//! The exchange of one request and its reply over one connection
//! ([`LocalClient`], whose documentation describes it).
//!
//! The framing is generic over the connection: a [`Connector`] opens a
//! [`HalfClose`] stream (bytes both ways and an end of the write half), so
//! a bridge to a socket the workstation cannot reach directly can be added
//! beside [`SocketPath`], the connection to a Unix socket path. How a
//! workstation reaches a socket inside a pod is not specified by any
//! document.
//!
//! Each call runs on a thread of its own, which connects, writes the
//! request line, closes its write half and reads the reply to the end of
//! the stream; the caller waits for it at most [`Timeouts::total`]. A
//! blocking connect has no timeout, so this thread may outlive the call: a
//! handshake (`phase`) makes sure it never writes a byte once the caller
//! has given up, so a call that ends before the request is written is
//! truly [`CallError::NotSent`].

use std::{
    fmt,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use super::{
    BootstrapRequest, Bootstrapped, CallError, ErrorCode, IssueChallengeRequest, Issued,
    MAX_REPLY_BYTES, NotSent, Op, Previewed, Reply, Request, RequestLine, ResponseRequest,
    Restored, Status, StatusRequest, UnknownOutcome, parse_reply, path::not_sent, wire::fits,
};
use crate::recovery::{Challenge, parse_challenge};

/// The default of [`Timeouts::total`]: 100 seconds, the longest an
/// accepted connection lasts on a server with the default settings (its
/// deadline, 30 seconds, its transaction timeout, 60, and its idle
/// timeout, 10; the service's `local_transport::Settings`).
pub const DEFAULT_TOTAL_WAIT: Duration = Duration::from_secs(100);

/// The default of [`Timeouts::idle`]: 10 seconds, the server's default
/// idle timeout, within which it writes its reply.
pub const DEFAULT_IDLE_WAIT: Duration = Duration::from_secs(10);

/// How long a call waits (see [`LocalClient`], "Time limits").
///
/// The defaults fit a server with the default settings only. The server's
/// deadline, transaction timeout and idle timeout are the deployment
/// operator's to tune (each up to about 24.8 days), and the transport has
/// no way to read them: a client of a server tuned otherwise sets its own
/// timeouts to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// The longest the call lasts, counted from the start of the connect:
    /// the connect, the write, and the wait for the reply and its end. It
    /// alone bounds the wait for the reply's first byte, during which the
    /// server legitimately stays silent (its deadline and its transaction).
    /// Over zero; default [`DEFAULT_TOTAL_WAIT`].
    pub total: Duration,
    /// The longest each write, and each read once the reply has begun, may
    /// block. Over zero; default [`DEFAULT_IDLE_WAIT`].
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            total: DEFAULT_TOTAL_WAIT,
            idle: DEFAULT_IDLE_WAIT,
        }
    }
}

/// A connected byte stream: reads, writes, and the end of its write half
/// alone, so that the peer reads the end of the stream while the reply can
/// still be read.
pub trait HalfClose: Read + Write {
    /// Ends the write half (`shutdown(SHUT_WR)` on a socket).
    ///
    /// # Errors
    ///
    /// The stream's error (on macOS, `ENOTCONN` once the peer has closed).
    /// The call reads on, and believes only a refusal, as after a failed
    /// write (see [`LocalClient`], "Exchange").
    fn close_write(&mut self) -> io::Result<()>;

    /// Bounds each later read: `None` blocks without a bound. A read past
    /// the bound fails with [`io::ErrorKind::WouldBlock`] or
    /// [`io::ErrorKind::TimedOut`].
    ///
    /// # Errors
    ///
    /// The stream's error: the wait cannot be kept, so the call ends, an
    /// unknown outcome once the request may have been written. A stream
    /// that needs no wait at that point (its peer gone, say) returns
    /// `Ok(())` itself: [`UnixStream`]'s does on macOS (see there).
    fn set_read_wait(&mut self, wait: Option<Duration>) -> io::Result<()>;

    /// Bounds each later write, as [`HalfClose::set_read_wait`] does reads.
    ///
    /// # Errors
    ///
    /// The stream's error, as for [`HalfClose::set_read_wait`]; before the
    /// first write the call ends [`NotSent::Setup`].
    fn set_write_wait(&mut self, wait: Option<Duration>) -> io::Result<()>;
}

/// A Unix socket. Its waits are its read and write timeouts, but for one
/// refusal: macOS's `EINVAL` once the peer has closed, passed over.
impl HalfClose for UnixStream {
    fn close_write(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }

    fn set_read_wait(&mut self, wait: Option<Duration>) -> io::Result<()> {
        unless_shut(self.set_read_timeout(wait))
    }

    fn set_write_wait(&mut self, wait: Option<Duration>) -> io::Result<()> {
        unless_shut(self.set_write_timeout(wait))
    }
}

/// The setting of a socket's timeout, but for the system's `EINVAL`
/// ([`io::ErrorKind::InvalidInput`] with an OS error code), which is passed
/// over: the socket keeps the timeout it had.
///
/// macOS refuses every option of a socket that can neither send nor
/// receive with `EINVAL`, and a socket is that as soon as its peer has
/// closed. Such a socket needs no wait: a read returns what is buffered,
/// then the end of the stream, and a write fails at once (a broken pipe).
/// Linux sets a timeout of any socket and refuses no wait asked for here.
/// `std`'s own refusal of a zero timeout, which has no OS error code, is not
/// passed over (no zero wait is asked for).
fn unless_shut(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(err) if err.kind() == io::ErrorKind::InvalidInput && err.raw_os_error().is_some() => {
            Ok(())
        }
        other => other,
    }
}

/// Opens one connection to the transport, once per call: a call never
/// connects twice.
pub trait Connector: Send + Sync + 'static {
    /// The stream a connection is.
    type Stream: HalfClose;

    /// Connects. It may block: the call stops waiting for it at
    /// [`Timeouts::total`], and the stream it gives afterwards is dropped
    /// unwritten.
    ///
    /// # Errors
    ///
    /// Why no connection was made: the call is then
    /// [`NotSent::Connect`] with the error's kind, or [`NotSent::Path`]
    /// for an error that carries a [`PathError`](super::PathError)
    /// ([`CheckedSocketPath`](super::CheckedSocketPath)'s refusals).
    fn connect(&self) -> io::Result<Self::Stream>;
}

/// The connection to the transport's Unix socket at a path, made as is:
/// the socket's owner, mode and directories are not checked here. A real
/// caller uses [`CheckedSocketPath`](super::CheckedSocketPath), through
/// [`LocalClient::new`], which checks them before every connect; this one,
/// through [`LocalClient::unchecked`], serves tests and bridges that check
/// otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketPath(PathBuf);

impl SocketPath {
    /// The socket at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The socket's path.
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Connector for SocketPath {
    type Stream = UnixStream;

    fn connect(&self) -> io::Result<UnixStream> {
        UnixStream::connect(&self.0)
    }
}

/// Whether to retry a call of an operation whose outcome is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Retry {
    /// A retry is safe: a `preview` or a `status` writes nothing.
    Safe,
    /// Reconcile an uncertain outcome first: the write may have committed
    /// or not, and a retry does not tell which. A retried `bootstrap` or
    /// `restore` is refused (`conflict`, `not_restorable`) once the first
    /// committed, but may succeed after a rollback if its preconditions
    /// still hold; a retried `issue_challenge` after a lost commit makes a
    /// second live challenge.
    ReconcileFirst,
}

impl Op {
    /// Whether to retry a call of this operation whose outcome is unknown
    /// ([`CallError::Unknown`]): only a `preview` or a `status` may be
    /// retried without reconciling. An `issue_challenge` stays
    /// [`Retry::ReconcileFirst`] (it writes a row and an audit event, so it
    /// is not safe to repeat blindly), though it cannot be reconciled (the
    /// client never received its operation ID): after an unknown outcome
    /// the operator issues again, and the first challenge, if it committed,
    /// expires unused (lead ruling, Q5). The client never retries on its
    /// own.
    pub const fn retry(self) -> Retry {
        match self {
            Self::Preview | Self::Status => Retry::Safe,
            Self::Bootstrap | Self::IssueChallenge | Self::Restore => Retry::ReconcileFirst,
        }
    }
}

/// The client of the deployment-local transport: one request per call,
/// one connection per request, never retried.
///
/// # Exchange
///
/// A call encodes the request (a line too large is not sent, and nothing
/// is connected), connects once ([`Connector`]; a Unix socket path checked
/// before the connect, [`CheckedSocketPath`](super::CheckedSocketPath), by
/// default), writes the line, closes its write half
/// ([`HalfClose`]), reads until the server closes the connection, at most
/// one byte past [`MAX_REPLY_BYTES`], and reads the reply with
/// [`parse_reply`].
///
/// The server may answer before it has read the whole request and close:
/// `forbidden` before any read, `invalid_request` at once for a line over
/// the limit or a byte after the newline. So a write or an end of the
/// write half that fails other than by running out of time (a broken
/// pipe, say) does not end the call: the
/// reply is still read. A read that fails with a reset (the server closed
/// with bytes of the request unread) ends the stream, and the bytes read
/// before it are kept. After either, the server did not read the whole
/// request, so only a refusal is believed; anything else, a success
/// included, is [`UnknownOutcome::ConnectionLost`]. (A write to a closed
/// socket raises `SIGPIPE`; Rust programs ignore it by default, and a
/// process that does not is killed by it.)
///
/// An end of the write half that fails after the line was written in full
/// counts as a failed write too: only a refusal is believed. On a socket it
/// fails only once the server has closed (macOS: `ENOTCONN`; Linux does not
/// fail it), and the server dispatches a request only once it has read the
/// end of the stream, which the failed end never sent: a server that
/// closed before it can have answered with a refusal, never a success.
///
/// The line is written in chunks of at most 4 KiB, one `write` each.
/// Before each, and before the flush, the wait is set again; after each
/// setting, and before the end of the write half, what is left of
/// [`Timeouts::total`] is checked: once the total has run out (the caller
/// has then given up), nothing more is sent. Until the first write may
/// start, the call is not sent: a total that runs out while connecting or
/// setting the first wait is [`NotSent::TimedOut`] for the caller and for
/// its thread alike.
/// (A socket's send timeout bounds each wait within a send, not the whole
/// send, on macOS and the BSDs: a large line offered at once to a slow
/// server could still be written long after the total.) A wait
/// the stream refuses ends the call: before the first write as
/// [`NotSent::Setup`], after it as [`UnknownOutcome::ConnectionLost`]. On
/// macOS a socket refuses every option once its peer has closed, a refusal
/// [`UnixStream`]'s [`HalfClose`] passes over (it needs no wait then), and
/// the reply is read as usual.
///
/// # Time limits
///
/// A call waits at most [`Timeouts::total`], counted from the start of the
/// connect; each write, and each read once the reply has begun, at most
/// [`Timeouts::idle`]. The default total, [`DEFAULT_TOTAL_WAIT`] (100
/// seconds), is how long an accepted connection lasts at most on a server
/// with the default settings: its deadline (30 seconds), its transaction
/// timeout (60) and its idle timeout (10), from the accept. Three limits
/// of the server's are outside what the client can know or bound:
///
/// - the server's settings are the deployment operator's to tune and are
///   not discoverable through the transport, so the defaults fit a default
///   server only;
/// - the wait in the socket's listen queue, before the server accepts, has
///   no bound on the server's side and is invisible to the client: the
///   connect and the write of a queued request succeed as if accepted;
/// - the server may still serve a request the client gave up on: once
///   written in full, a request is read and served when accepted, closed
///   client or not.
///
/// So a call that runs out of time once its first byte may have been
/// written is an unknown outcome ([`UnknownOutcome::TimedOut`]); one that
/// runs out while still connecting is [`NotSent::TimedOut`], and its
/// connection, if made later, is dropped unwritten.
///
/// # Outcomes
///
/// A success is a well-formed reply of the operation's own shape, read to
/// the end of the stream (for an issue, one whose members are its
/// challenge's). A refusal is a well-formed refusal of the closed set,
/// with one exception: a failed `COMMIT` is answered as a store failure,
/// `auth_unavailable` or `server_error`, whose outcome may be unknown, so
/// these two codes after a write (`bootstrap`, `issue_challenge`,
/// `restore`) are [`UnknownOutcome::UncertainCommit`], carrying the code;
/// after a `preview` or a `status` they stay refusals. Not sent means nothing was
/// written. Everything else is [`CallError::Unknown`]: **do not proceed;
/// reconcile first** ([`Op::retry`]). The client never retries on its
/// own.
///
/// To reconcile, read the state with [`LocalClient::status`] and decide by
/// [`RestoreVerdict`](super::RestoreVerdict) or
/// [`BootstrapVerdict`](super::BootstrapVerdict); the credentials a restore
/// revoked are read with [`LocalClient::revoked_credential_ids`] (see the
/// [module documentation](super), "Reconciling").
///
/// `Debug` shows the timeouts only.
pub struct LocalClient<C = super::CheckedSocketPath> {
    connector: Arc<C>,
    timeouts: Timeouts,
}

impl<C> fmt::Debug for LocalClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalClient")
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

impl LocalClient<SocketPath> {
    /// The client of the socket at `path`, connected to unchecked
    /// ([`SocketPath`]): for tests and bridges that check the socket
    /// otherwise. A real caller uses [`LocalClient::new`] instead.
    pub fn unchecked(path: impl Into<PathBuf>, timeouts: Timeouts) -> Self {
        Self::with_connector(SocketPath::new(path), timeouts)
    }
}

impl<C: Connector> LocalClient<C> {
    /// The client of the connections `connector` opens.
    pub fn with_connector(connector: C, timeouts: Timeouts) -> Self {
        Self {
            connector: Arc::new(connector),
            timeouts,
        }
    }

    /// The client's timeouts.
    pub const fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    /// Bootstraps the instance.
    ///
    /// # Errors
    ///
    /// See "Outcomes": a store failure (`auth_unavailable`,
    /// `server_error`) is [`UnknownOutcome::UncertainCommit`];
    /// [`Retry::ReconcileFirst`].
    pub fn bootstrap(&self, request: &BootstrapRequest) -> Result<Bootstrapped, CallError> {
        fits(request.encoded_len_lower_bound())?;
        match self.call(&Request::Bootstrap(request.clone()))? {
            Reply::Bootstrapped(reply) => Ok(reply),
            _ => Err(CallError::Unknown(UnknownOutcome::Malformed)),
        }
    }

    /// Issues a recovery challenge and reads its `M` with
    /// [`parse_challenge`]. The reply's `operation_id`, `expires_at` and
    /// `expected_revision` must be `M`'s; the challenge is still to be
    /// checked against the operator's expectations
    /// ([`check_challenge`](crate::recovery::check_challenge)).
    ///
    /// # Errors
    ///
    /// See "Outcomes": a store failure (`auth_unavailable`,
    /// `server_error`) is [`UnknownOutcome::UncertainCommit`]; a reply
    /// whose `M` [`parse_challenge`] refuses, or whose members are not
    /// `M`'s, is [`UnknownOutcome::ChallengeMismatch`];
    /// [`Retry::ReconcileFirst`].
    pub fn issue_challenge(&self, request: &IssueChallengeRequest) -> Result<Challenge, CallError> {
        self.issue_challenge_verbatim(request)
            .map(|issued| issued.challenge)
    }

    /// Issues a recovery challenge as [`LocalClient::issue_challenge`]
    /// does, and also gives the reply line exactly as the server sent it
    /// (lead ruling Q6, `docs/proposals/operator-cli-online.md`: the
    /// challenge artifact is the reply, verbatim). The line is given only
    /// with a success: once it was read in full, parsed as an issue's reply
    /// and its challenge checked, so it is the bytes [`parse_reply`] and
    /// [`parse_challenge`] accepted, its newline included.
    ///
    /// # Errors
    ///
    /// As [`LocalClient::issue_challenge`]: no line is given with an
    /// error.
    pub fn issue_challenge_verbatim(
        &self,
        request: &IssueChallengeRequest,
    ) -> Result<IssuedChallenge, CallError> {
        fits(request.encoded_len_lower_bound())?;
        match self.exchange(&Request::IssueChallenge(request.clone()))? {
            (Reply::Issued(reply), line) => Ok(IssuedChallenge {
                challenge: challenge_of(&reply)?,
                line,
            }),
            _ => Err(CallError::Unknown(UnknownOutcome::Malformed)),
        }
    }

    /// Previews what the signed response would restore.
    ///
    /// # Errors
    ///
    /// See "Outcomes": every refusal is [`CallError::Refused`];
    /// [`Retry::Safe`].
    pub fn preview(&self, response: &ResponseRequest) -> Result<Previewed, CallError> {
        fits(response.encoded_len_lower_bound())?;
        match self.call(&Request::Preview(response.clone()))? {
            Reply::Previewed(reply) => Ok(reply),
            _ => Err(CallError::Unknown(UnknownOutcome::Malformed)),
        }
    }

    /// Restores the operator the signed response authorizes.
    ///
    /// # Errors
    ///
    /// See "Outcomes": a store failure (`auth_unavailable`,
    /// `server_error`) is [`UnknownOutcome::UncertainCommit`];
    /// [`Retry::ReconcileFirst`].
    pub fn restore(&self, response: &ResponseRequest) -> Result<Restored, CallError> {
        fits(response.encoded_len_lower_bound())?;
        match self.call(&Request::Restore(response.clone()))? {
            Reply::Restored(reply) => Ok(reply),
            _ => Err(CallError::Unknown(UnknownOutcome::Malformed)),
        }
    }

    /// Reads the recovery state, the state of a recovery challenge and the
    /// enrollment of an mTLS key, as `request` asks ([`Status`]); changes
    /// no row. The reconcile step after a `bootstrap` or a `restore` of
    /// unknown outcome ([`StatusRequest::reconciling_bootstrap`],
    /// [`StatusRequest::reconciling_restore`]) and the page of a restore's
    /// revoked IDs after `revoked_after`
    /// ([`LocalClient::revoked_credential_ids`] walks them). The codec
    /// checks the reply's shape only, not how its members agree.
    ///
    /// # Errors
    ///
    /// See "Outcomes": every refusal is [`CallError::Refused`];
    /// [`Retry::Safe`].
    pub fn status(&self, request: &StatusRequest) -> Result<Status, CallError> {
        fits(request.encoded_len_lower_bound())?;
        match self.call(&Request::Status(request.clone()))? {
            Reply::Status(reply) => Ok(*reply),
            _ => Err(CallError::Unknown(UnknownOutcome::Malformed)),
        }
    }

    /// One exchange: the request line, the reply, its classification. The
    /// typed calls check [`fits`] first, so a value too large is refused
    /// before it is copied into `request`.
    fn call(&self, request: &Request) -> Result<Reply, CallError> {
        self.exchange(request).map(|(reply, _)| reply)
    }

    /// [`LocalClient::call`], with the reply line read: on a success, the
    /// bytes [`parse_reply`] accepted, which are one line and its newline
    /// and nothing after.
    fn exchange(&self, request: &Request) -> Result<(Reply, Vec<u8>), CallError> {
        let op = request.op();
        let line = request.encode()?;
        let Timeouts { total, idle } = self.timeouts;
        if total.is_zero() || idle.is_zero() {
            return Err(NotSent::InvalidTimeouts.into());
        }
        let deadline = Instant::now().checked_add(total);
        let phase = Arc::new(AtomicU8::new(UNSENT));
        let (sender, receiver) = mpsc::sync_channel(1);
        let connector = Arc::clone(&self.connector);
        let worker_phase = Arc::clone(&phase);
        thread::Builder::new()
            .name("skyoauth-local-exchange".into())
            .spawn(move || {
                let received = run(&*connector, &worker_phase, &line, deadline, idle);
                // The caller may have given up and gone.
                let _ = sender.send(received);
            })
            .map_err(|err| NotSent::Connect(err.kind()))?;
        let received = match deadline {
            Some(deadline) => {
                receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => receiver
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
        }
        // Out of time, or the thread ended without a result.
        .unwrap_or_else(|_| Err(give_up(&phase)))?;
        match parse_reply(op, &received.reply) {
            Err(CallError::Refused(code)) => Err(refusal(op, code)),
            // The server did not read the whole request: only a refusal is
            // believed.
            other => match received.lost {
                Some(kind) => Err(CallError::Unknown(UnknownOutcome::ConnectionLost(kind))),
                None => other.map(|reply| (reply, received.reply)),
            },
        }
    }
}

/// The success of [`LocalClient::issue_challenge_verbatim`]: the challenge
/// and the reply line it came in, exactly as the server sent it.
///
/// `Debug` prints `IssuedChallenge(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedChallenge {
    /// The reply's `M`, read with [`parse_challenge`], whose operation ID,
    /// expiry and expected revision are the reply's.
    pub challenge: Challenge,
    /// The reply line, its newline included: the bytes read, unchanged.
    pub line: Vec<u8>,
}

impl fmt::Debug for IssuedChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedChallenge(..)")
    }
}

/// The classification of a refusal with `code` of a request of `op` (lead
/// ruling).
///
/// A `COMMIT` that fails is answered as a store failure, `auth_unavailable`
/// or `server_error`, and its outcome may be unknown (the service's
/// "Transactions"). The three writes are listed: a `bootstrap` or a
/// `restore` may have committed what a retry cannot tell, and a retried
/// `issue_challenge` after a lost commit makes a second live challenge. So
/// these two codes are [`UnknownOutcome::UncertainCommit`], carrying the
/// code, after a write, and refusals after a `preview` or a `status`, which
/// change no row; every other code is a refusal after every operation. The
/// `writes` line alone decides which operations this applies to: a list of
/// the writes, so an operation added later is not taken as one.
const fn refusal(op: Op, code: ErrorCode) -> CallError {
    let writes = matches!(op, Op::Bootstrap | Op::IssueChallenge | Op::Restore);
    let store_failure = matches!(code, ErrorCode::AuthUnavailable | ErrorCode::ServerError);
    if writes && store_failure {
        CallError::Unknown(UnknownOutcome::UncertainCommit(code))
    } else {
        CallError::Refused(code)
    }
}

/// The challenge of an issue's reply: `M` as [`parse_challenge`] reads it,
/// whose operation ID, expiry and expected revision must be the reply's.
fn challenge_of(reply: &Issued) -> Result<Challenge, CallError> {
    let mismatch = CallError::Unknown(UnknownOutcome::ChallengeMismatch);
    let challenge = parse_challenge(&reply.challenge).map_err(|_| mismatch)?;
    if challenge.operation_id() == reply.operation_id
        && challenge.expires_at_micros() == reply.expires_at
        && challenge.expected_revision() == reply.expected_revision
    {
        Ok(challenge)
    } else {
        Err(mismatch)
    }
}

/// The phase of a call, shared by the caller and its thread: unsent (the
/// thread connects and sets the first write's wait; nothing written), then
/// either writing (the thread may write) or given up (the caller stopped
/// waiting; the thread must not write). Whichever leaves `UNSENT` first
/// decides, so the caller's not sent is never followed by a write.
const UNSENT: u8 = 0;
const WRITING: u8 = 1;
const GAVE_UP: u8 = 2;

/// The caller stops waiting: not sent while the thread has not started
/// writing, which it then never does; unknown once it may have written.
fn give_up(phase: &AtomicU8) -> CallError {
    match phase.compare_exchange(UNSENT, GAVE_UP, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => CallError::NotSent(NotSent::TimedOut),
        Err(_) => CallError::Unknown(UnknownOutcome::TimedOut),
    }
}

/// What a call's thread received: the bytes the server sent, and the kind
/// of the first failure of a write, of the end of the write half or of a
/// reset read, after which the server cannot have read the whole request.
struct Received {
    reply: Vec<u8>,
    lost: Option<io::ErrorKind>,
}

/// The thread of a call: connects and sets the wait of the first write,
/// then, unless the total has run out or the caller has given up meanwhile,
/// exchanges `line` for everything the server sends.
///
/// Nothing is written until then: a total run out, before or after the
/// setting (which may itself take time, on a bridge say), is
/// [`NotSent::TimedOut`], a wait the stream refuses [`NotSent::Setup`].
/// Only then does the phase turn to writing.
fn run<C: Connector>(
    connector: &C,
    phase: &AtomicU8,
    line: &RequestLine,
    deadline: Option<Instant>,
    idle: Duration,
) -> Result<Received, CallError> {
    let mut stream = connector.connect().map_err(|err| not_sent(&err))?;
    let first = wait(deadline, Some(idle)).map_err(|_| NotSent::TimedOut)?;
    stream
        .set_write_wait(first)
        .map_err(|err| NotSent::Setup(err.kind()))?;
    wait(deadline, None).map_err(|_| NotSent::TimedOut)?;
    if phase
        .compare_exchange(UNSENT, WRITING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // The caller has given up: the stream is dropped unwritten.
        return Err(NotSent::TimedOut.into());
    }
    sent(&mut stream, line.as_bytes(), deadline, idle).map_err(CallError::Unknown)
}

/// Writes `line`, ends the write half, then reads until the end of the
/// stream, or one byte past [`MAX_REPLY_BYTES`] and no further; the wait of
/// the first write is set ([`run`]).
///
/// A write or an end of the write half that fails other than by a timeout
/// does not stop the read (the server may have answered before reading the
/// whole request, and closed), and a reset ends the stream with what was
/// read: both are noted in [`Received::lost`]. Any other failure, a
/// timeout or a wait the stream refuses included, is an unknown outcome:
/// the line may have been written. The end of the write half is not sent
/// once the total has run out.
fn sent<S: HalfClose>(
    stream: &mut S,
    line: &[u8],
    deadline: Option<Instant>,
    idle: Duration,
) -> Result<Received, UnknownOutcome> {
    let lost = write_line(stream, line, deadline, idle)?;
    wait(deadline, None)?;
    let lost = note(stream.close_write(), lost)?;
    let mut reply = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        // Until the reply begins, the server may be silent for as long as
        // its deadline and transaction last: only the total bounds it.
        let bound = if reply.is_empty() { None } else { Some(idle) };
        stream
            .set_read_wait(wait(deadline, bound)?)
            .map_err(failed)?;
        // Never past the byte that shows the reply too large.
        let room = (MAX_REPLY_BYTES + 1 - reply.len()).min(chunk.len());
        match stream.read(&mut chunk[..room]) {
            Ok(0) => return Ok(Received { reply, lost }),
            Ok(read) => {
                reply.extend_from_slice(&chunk[..read]);
                if reply.len() > MAX_REPLY_BYTES {
                    // Too large already, whatever follows.
                    return Ok(Received { reply, lost });
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {
                let lost = lost.or(Some(err.kind()));
                return Ok(Received { reply, lost });
            }
            Err(err) => return Err(failed(err)),
        }
    }
}

/// The most one write offers the stream (see [`LocalClient`], "Exchange").
const WRITE_CHUNK: usize = 4096;

/// Writes `line` and flushes, one write of at most [`WRITE_CHUNK`] bytes at
/// a time, the wait of the first write already set: before each later
/// write, and before the flush, the wait is set again to what is left of
/// the total (at most the idle timeout), and the total checked once more
/// after the setting returns (it may take time), so that nothing is sent
/// once the total has run out and no write blocks past it. A write that takes nothing is a lost
/// connection ([`io::ErrorKind::WriteZero`]). The kind of a failure other
/// than a timeout is returned, and the writing stops (see [`note`]).
fn write_line<S: HalfClose>(
    stream: &mut S,
    line: &[u8],
    deadline: Option<Instant>,
    idle: Duration,
) -> Result<Option<io::ErrorKind>, UnknownOutcome> {
    let mut rest = line;
    loop {
        let chunk = rest.get(..WRITE_CHUNK).unwrap_or(rest);
        match stream.write(chunk) {
            Ok(0) => return note(Err(io::ErrorKind::WriteZero.into()), None),
            Ok(written) => rest = rest.get(written..).unwrap_or_default(),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return note(Err(err), None),
        }
        stream
            .set_write_wait(wait(deadline, Some(idle))?)
            .map_err(failed)?;
        wait(deadline, None)?;
        if rest.is_empty() {
            return note(stream.flush(), None);
        }
    }
}

/// The wait for the next read or write: what is left until `deadline`,
/// and at most `bound`.
///
/// # Errors
///
/// [`UnknownOutcome::TimedOut`] when nothing is left.
fn wait(
    deadline: Option<Instant>,
    bound: Option<Duration>,
) -> Result<Option<Duration>, UnknownOutcome> {
    let Some(deadline) = deadline else {
        return Ok(bound);
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(UnknownOutcome::TimedOut);
    }
    Ok(Some(bound.map_or(left, |bound| bound.min(left))))
}

/// Notes the failure of a write or of the end of the write half, after
/// `lost`: a wait that ran out is an unknown outcome; any other failure is
/// kept (the first one) and the call reads on.
fn note(
    result: io::Result<()>,
    lost: Option<io::ErrorKind>,
) -> Result<Option<io::ErrorKind>, UnknownOutcome> {
    match result {
        Ok(()) => Ok(lost),
        Err(err) if timed_out(&err) => Err(UnknownOutcome::TimedOut),
        Err(err) => Ok(lost.or(Some(err.kind()))),
    }
}

/// Whether `err` is a wait that ran out.
fn timed_out(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The unknown outcome of a read, or of the setting of a wait after the
/// first, that failed.
fn failed(err: io::Error) -> UnknownOutcome {
    if timed_out(&err) {
        UnknownOutcome::TimedOut
    } else {
        UnknownOutcome::ConnectionLost(err.kind())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// A stream that counts the bytes written to it, reads the end of the
    /// stream at once, and takes `setter` to set a write's wait (a slow
    /// bridge, say).
    struct Probe {
        written: Arc<AtomicUsize>,
        setter: Duration,
    }

    impl Read for Probe {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for Probe {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written.fetch_add(bytes.len(), Ordering::SeqCst);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl HalfClose for Probe {
        fn close_write(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn set_read_wait(&mut self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_wait(&mut self, _: Option<Duration>) -> io::Result<()> {
            // The setting itself takes this long: a slow call, not a wait
            // for another thread.
            thread::sleep(self.setter);
            Ok(())
        }
    }

    /// Connects a [`Probe`] at once.
    struct ProbeConnector {
        written: Arc<AtomicUsize>,
        setter: Duration,
    }

    impl Connector for ProbeConnector {
        type Stream = Probe;

        fn connect(&self) -> io::Result<Probe> {
            Ok(Probe {
                written: Arc::clone(&self.written),
                setter: self.setter,
            })
        }
    }

    /// [`run`] with the phase `phase`, a write's wait that takes `setter`
    /// to set, and `total` until the deadline: its result and the bytes
    /// written.
    fn probe(phase: u8, setter: Duration, total: Duration) -> (Result<(), CallError>, usize) {
        let written = Arc::new(AtomicUsize::new(0));
        let connector = ProbeConnector {
            written: Arc::clone(&written),
            setter,
        };
        let line = RequestLine(b"{}\n".to_vec());
        let phase = AtomicU8::new(phase);
        let result = run(
            &connector,
            &phase,
            &line,
            Instant::now().checked_add(total),
            Duration::from_secs(10),
        );
        (result.map(drop), written.load(Ordering::SeqCst))
    }

    /// The total runs out while the first write's wait is being set (it
    /// takes 150 ms of a 50 ms total): not sent, and nothing written.
    #[test]
    fn a_total_run_out_during_the_first_setting_writes_nothing() {
        let (result, written) = probe(
            UNSENT,
            Duration::from_millis(150),
            Duration::from_millis(50),
        );
        assert_eq!(result, Err(CallError::NotSent(NotSent::TimedOut)));
        assert_eq!(written, 0);
    }

    /// The caller has given up before the thread would write: not sent,
    /// and nothing written, however much of the total is left.
    #[test]
    fn a_call_given_up_before_the_write_writes_nothing() {
        let (result, written) = probe(GAVE_UP, Duration::ZERO, Duration::from_secs(10));
        assert_eq!(result, Err(CallError::NotSent(NotSent::TimedOut)));
        assert_eq!(written, 0);
    }

    /// Only the system's `EINVAL` is passed over; `std`'s own refusal and
    /// every other error are kept.
    #[test]
    fn only_the_systems_einval_is_passed_over() {
        let einval = io::Error::from_raw_os_error(22);
        assert_eq!(einval.kind(), io::ErrorKind::InvalidInput);
        assert!(unless_shut(Err(einval)).is_ok());
        assert!(unless_shut(Ok(())).is_ok());
        for kept in [
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot set a 0 duration timeout",
            ),
            io::Error::from(io::ErrorKind::InvalidInput),
            io::Error::from(io::ErrorKind::Other),
            io::Error::from_raw_os_error(9),
        ] {
            let kind = kept.kind();
            assert_eq!(unless_shut(Err(kept)).map_err(|err| err.kind()), Err(kind));
        }
    }

    /// A zero timeout of a real socket is `std`'s refusal, not passed
    /// over; a wait is set on a live socket.
    #[test]
    fn a_zero_timeout_of_a_socket_is_not_passed_over() {
        let (mut stream, _peer) = UnixStream::pair().unwrap();
        assert!(stream.set_read_wait(Some(Duration::from_secs(1))).is_ok());
        assert_eq!(
            stream
                .set_read_wait(Some(Duration::ZERO))
                .map_err(|err| err.kind()),
            Err(io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            stream
                .set_write_wait(Some(Duration::ZERO))
                .map_err(|err| err.kind()),
            Err(io::ErrorKind::InvalidInput)
        );
    }

    /// A store failure is an uncertain commit after each of the three
    /// writes, and a refusal after `preview` and `status`, which change no
    /// row; every other code is a refusal after every operation (mutant
    /// M9; `local_exchange` checks it through the typed calls too).
    #[test]
    fn only_the_three_writes_make_a_store_failure_uncertain() {
        for op in Op::ALL {
            let writes = matches!(op, Op::Bootstrap | Op::IssueChallenge | Op::Restore);
            for code in ErrorCode::ALL {
                let store_failure =
                    matches!(code, ErrorCode::AuthUnavailable | ErrorCode::ServerError);
                let expected = if writes && store_failure {
                    CallError::Unknown(UnknownOutcome::UncertainCommit(code))
                } else {
                    CallError::Refused(code)
                };
                assert_eq!(refusal(op, code), expected, "{op:?} {code:?}");
            }
        }
        assert_eq!(
            refusal(Op::Status, ErrorCode::AuthUnavailable),
            CallError::Refused(ErrorCode::AuthUnavailable)
        );
        assert_eq!(
            refusal(Op::Status, ErrorCode::ServerError),
            CallError::Refused(ErrorCode::ServerError)
        );
    }
}
