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
    Restored, UnknownOutcome, parse_reply,
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
    /// The stream's error.
    fn close_write(&mut self) -> io::Result<()>;

    /// Bounds each later read: `None` blocks without a bound. A read past
    /// the bound fails with [`io::ErrorKind::WouldBlock`] or
    /// [`io::ErrorKind::TimedOut`].
    ///
    /// # Errors
    ///
    /// The stream's error.
    fn set_read_wait(&mut self, wait: Option<Duration>) -> io::Result<()>;

    /// Bounds each later write, as [`HalfClose::set_read_wait`] does reads.
    ///
    /// # Errors
    ///
    /// The stream's error.
    fn set_write_wait(&mut self, wait: Option<Duration>) -> io::Result<()>;
}

impl HalfClose for UnixStream {
    fn close_write(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }

    fn set_read_wait(&mut self, wait: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(wait)
    }

    fn set_write_wait(&mut self, wait: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(wait)
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
    /// [`NotSent::Connect`] with the error's kind.
    fn connect(&self) -> io::Result<Self::Stream>;
}

/// The connection to the transport's Unix socket at a path, made as is:
/// the socket's owner, mode and directories are not checked here.
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
    /// A retry is safe: a `preview` writes nothing.
    Safe,
    /// Reconcile first: the write may have committed. A retried
    /// `bootstrap` or `restore` is refused (`conflict`, `not_restorable`)
    /// whether the first committed or not, so a retry cannot tell; a
    /// retried `issue_challenge` after a lost commit makes a second live
    /// challenge.
    ReconcileFirst,
}

impl Op {
    /// Whether to retry a call of this operation whose outcome is unknown
    /// ([`CallError::Unknown`]): only a `preview` may be retried without
    /// reconciling. The client never retries on its own.
    pub const fn retry(self) -> Retry {
        match self {
            Self::Preview => Retry::Safe,
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
/// is connected), connects once ([`Connector`]; a Unix socket path,
/// [`SocketPath`], by default), writes the line, closes its write half
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
/// after a `preview` they stay refusals. Not sent means nothing was
/// written. Everything else is [`CallError::Unknown`]: **do not proceed;
/// reconcile first** ([`Op::retry`]). The client never retries on its
/// own.
///
/// The transport has no operation that reads state, so this crate cannot
/// reconcile: the only readers are the admin HTTP API and the database
/// (open question Q18 of the T13.10 plan: a read operation on the socket,
/// or a reconcile through the admin API).
///
/// `Debug` shows the timeouts only.
pub struct LocalClient<C = SocketPath> {
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
    /// The client of the socket at `path`.
    pub fn new(path: impl Into<PathBuf>, timeouts: Timeouts) -> Self {
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
        match self.call(&Request::IssueChallenge(request.clone()))? {
            Reply::Issued(reply) => challenge_of(&reply),
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
        match self.call(&Request::Restore(response.clone()))? {
            Reply::Restored(reply) => Ok(reply),
            _ => Err(CallError::Unknown(UnknownOutcome::Malformed)),
        }
    }

    /// One exchange: the request line, the reply, its classification.
    fn call(&self, request: &Request) -> Result<Reply, CallError> {
        let op = request.op();
        let line = request.encode()?;
        let Timeouts { total, idle } = self.timeouts;
        if total.is_zero() || idle.is_zero() {
            return Err(NotSent::InvalidTimeouts.into());
        }
        let deadline = Instant::now().checked_add(total);
        let phase = Arc::new(AtomicU8::new(CONNECTING));
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
                None => other,
            },
        }
    }
}

/// The classification of a refusal with `code` of a request of `op` (lead
/// ruling).
///
/// A `COMMIT` that fails is answered as a store failure, `auth_unavailable`
/// or `server_error`, and its outcome may be unknown (the service's
/// "Transactions"). Every operation but `preview` writes: a `bootstrap` or
/// a `restore` may have committed what a retry cannot tell, and a retried
/// `issue_challenge` after a lost commit makes a second live challenge. So
/// these two codes are [`UnknownOutcome::UncertainCommit`], carrying the
/// code, after a write, and refusals after a `preview`; every other code is
/// a refusal after every operation. The `writes` line alone decides which
/// operations this applies to.
const fn refusal(op: Op, code: ErrorCode) -> CallError {
    let writes = !matches!(op, Op::Preview);
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

/// The phase of a call, shared by the caller and its thread: connecting
/// (nothing written), then either writing (the thread may write) or given
/// up (the caller stopped waiting; the thread must not write). Whichever
/// leaves `CONNECTING` first decides.
const CONNECTING: u8 = 0;
const WRITING: u8 = 1;
const GAVE_UP: u8 = 2;

/// The caller stops waiting: not sent while the thread is still
/// connecting, which it can then no longer write after; unknown once it
/// may have written.
fn give_up(phase: &AtomicU8) -> CallError {
    match phase.compare_exchange(CONNECTING, GAVE_UP, Ordering::AcqRel, Ordering::Acquire) {
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

/// The thread of a call: connects, then, unless the caller has given up,
/// exchanges `line` for everything the server sends.
fn run<C: Connector>(
    connector: &C,
    phase: &AtomicU8,
    line: &RequestLine,
    deadline: Option<Instant>,
    idle: Duration,
) -> Result<Received, CallError> {
    let mut stream = connector
        .connect()
        .map_err(|err| NotSent::Connect(err.kind()))?;
    if phase
        .compare_exchange(CONNECTING, WRITING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // The caller has given up: the stream is dropped unwritten.
        return Err(NotSent::TimedOut.into());
    }
    exchange(&mut stream, line.as_bytes(), deadline, idle).map_err(CallError::Unknown)
}

/// Writes `line`, ends the write half, then reads until the end of the
/// stream, or one byte past [`MAX_REPLY_BYTES`] and no further.
///
/// A write or an end of the write half that fails other than by a timeout
/// does not stop the read (the server may have answered before reading the
/// whole request, and closed), and a reset ends the stream with what was
/// read: both are noted in [`Received::lost`]. Any other failure, a
/// timeout included, is an unknown outcome: the line may have been
/// written.
fn exchange<S: HalfClose>(
    stream: &mut S,
    line: &[u8],
    deadline: Option<Instant>,
    idle: Duration,
) -> Result<Received, UnknownOutcome> {
    stream
        .set_write_wait(wait(deadline, Some(idle))?)
        .map_err(failed)?;
    let lost = note(stream.write_all(line).and_then(|()| stream.flush()), None)?;
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
        match stream.read(&mut chunk) {
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

/// The unknown outcome of a read, or of the setting of a wait, that
/// failed.
fn failed(err: io::Error) -> UnknownOutcome {
    if timed_out(&err) {
        UnknownOutcome::TimedOut
    } else {
        UnknownOutcome::ConnectionLost(err.kind())
    }
}
