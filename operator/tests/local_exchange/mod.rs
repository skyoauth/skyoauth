//! The deployment-local transport's exchange (`skyoauth_operator::local`,
//! [`LocalClient`]) against fake servers: `std` Unix listeners on threads,
//! each at a socket in a fresh directory of its own, that read the request
//! and answer as each test needs.
//!
//! - the request is exactly one line and then the end of the stream (the
//!   client closes its write half), and each golden success of the fixture
//!   is its operation's success;
//! - the refusals, by operation (lead ruling): `auth_unavailable` and
//!   `server_error` after a write (`bootstrap`, `issue_challenge`,
//!   `restore`) are unknown outcomes carrying the code, every other
//!   refusal, and these two after a `preview` or a `status`, are refused;
//! - an issued reply whose members are not its challenge's is unknown;
//! - after a failed write (a broken pipe), a failed end of the write half
//!   or a reset, the reply is still read and the bytes read are kept, but
//!   only a refusal is believed: a success the server sent without reading
//!   the request is unknown;
//! - a wait the stream refuses ends the call: not sent before the first
//!   write, unknown after it (the Unix socket's own refusal on macOS, once
//!   the server has closed, is passed over by its adapter, checked in the
//!   crate's unit tests);
//! - nothing is sent once the total has run out, and a reply over the cap
//!   is read one byte past it and no further (in-memory streams);
//! - everything else once the request may have been written is unknown,
//!   never refused and never a success: no reply, a partial reply, bytes
//!   after the newline, a reply over the cap, a server too slow for the
//!   total or idle timeout, a listener that accepts and never answers or
//!   never accepts;
//! - a connection that cannot be made is not sent, and a connect that
//!   returns after the caller gave up is dropped unwritten; a typed call
//!   with an oversized value is not sent (checked before its values are
//!   copied, which no test observes);
//! - every call connects once: the client never retries;
//! - the default timeouts are the server's default limits (the fixture's
//!   `default_limits`), and `Debug` and `Display` show no value.
//!
//! Unix only, like the module. Each wait of a test is bounded
//! ([`TEST_WAIT`]), the fake servers' accepts included
//! ([`accept_within`], the one poll); a fake server that must outlast the
//! call blocks until the call has returned. A lower bound on a call's
//! duration allows [`EARLY`]. What only Linux does is
//! checked on Linux alone: the kind of a lost connection, a reset when a
//! server closes with bytes unread (macOS reads the end of the stream
//! instead), and a queued connection still readable after its client has
//! gone.

use std::{
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use skyoauth_operator::{
    local::{
        BootstrapRequest, BootstrapVerdict, CallError, Connector, DEFAULT_IDLE_WAIT,
        DEFAULT_TOTAL_WAIT, ErrorCode, HalfClose, IssueChallengeRequest, Issued, LocalClient,
        MAX_REPLY_BYTES, MAX_REQUEST_BYTES, MAX_REVOKED_IDS_PER_REPLY, NotSent, Op, Reply, Request,
        ResponseRequest, RestoreVerdict, Restored, Retry, SocketPath, StatusRequest, Timeouts,
        UnknownOutcome, parse_reply,
    },
    recovery::RecoveryPublicKey,
};

use crate::local_wire::wire_fixture;
use crate::support::{list, text};

/// The longest a test waits for a fake server, a peer or a call that is
/// not meant to time out.
const TEST_WAIT: Duration = Duration::from_secs(10);

/// Timeouts no fake server that answers comes close to.
const PATIENT: Timeouts = Timeouts {
    total: TEST_WAIT,
    idle: TEST_WAIT,
};

/// A fresh directory under the system's temporary directory, created with
/// mode 0700, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "skyoauth-operator-exchange-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A connector that counts its connects, so a test sees that the client
/// connected once and never retried.
struct Counted {
    inner: SocketPath,
    connects: Arc<AtomicUsize>,
}

impl Connector for Counted {
    type Stream = UnixStream;

    fn connect(&self) -> io::Result<UnixStream> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        self.inner.connect()
    }
}

/// A client of the socket at `path` that counts its connects.
fn counted(path: &Path, timeouts: Timeouts) -> (LocalClient<Counted>, Arc<AtomicUsize>) {
    let connects = Arc::new(AtomicUsize::new(0));
    let client = LocalClient::with_connector(
        Counted {
            inner: SocketPath::new(path),
            connects: Arc::clone(&connects),
        },
        timeouts,
    );
    (client, connects)
}

/// Calls the operation of `request` through its typed method, as a
/// [`Reply`] (an issue's challenge back as its reply's members).
fn call<C: Connector>(client: &LocalClient<C>, request: &Request) -> Result<Reply, CallError> {
    match request {
        Request::Bootstrap(request) => client.bootstrap(request).map(Reply::Bootstrapped),
        Request::IssueChallenge(request) => client.issue_challenge(request).map(|challenge| {
            Reply::Issued(Issued {
                operation_id: challenge.operation_id().to_owned(),
                expires_at: challenge.expires_at_micros(),
                expected_revision: challenge.expected_revision(),
                challenge: challenge.message().to_vec(),
            })
        }),
        Request::Preview(response) => client.preview(response).map(Reply::Previewed),
        Request::Restore(response) => client.restore(response).map(Reply::Restored),
        Request::Status(request) => client
            .status(request)
            .map(|status| Reply::Status(Box::new(status))),
    }
}

fn key() -> RecoveryPublicKey {
    RecoveryPublicKey::from_hex("c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a")
        .unwrap()
}

/// A request of `op`, with values the fake servers do not read.
fn request(op: Op) -> Request {
    let response = ResponseRequest {
        operation_id: "SENTINEL-OPERATION".into(),
        signature: [0x5a; 64],
    };
    match op {
        Op::Bootstrap => Request::Bootstrap(BootstrapRequest {
            instance_id: "SENTINEL-INSTANCE".into(),
            credential_spki: vec![0xc7; 44],
            trust_anchor_ref: "SENTINEL-ANCHOR".into(),
            recovery_public_key: key(),
        }),
        Op::IssueChallenge => Request::IssueChallenge(IssueChallengeRequest {
            credential_spki: vec![0xc7; 44],
            trust_anchor_ref: "SENTINEL-ANCHOR".into(),
            new_recovery_public_key: key(),
        }),
        Op::Preview => Request::Preview(response),
        Op::Restore => Request::Restore(response),
        Op::Status => Request::Status(StatusRequest {
            operation_id: Some("SENTINEL-OPERATION".into()),
            credential_spki: Some(vec![0xc7; 44]),
            revoked_after: Some("SENTINEL-AFTER".into()),
        }),
    }
}

/// The golden reply line of the fixture's case `name`.
fn golden(name: &str) -> Vec<u8> {
    let fixture = wire_fixture();
    let case = list(&fixture, "golden_replies")
        .iter()
        .find(|case| text(case, "case") == name)
        .unwrap_or_else(|| panic!("no golden reply {name}"));
    text(case, "line").as_bytes().to_vec()
}

/// The golden success line of `op`.
fn golden_success(op: Op) -> Vec<u8> {
    golden(match op {
        Op::Bootstrap => "bootstrapped",
        Op::IssueChallenge => "issued",
        Op::Preview => "previewed",
        Op::Restore => "restored",
        Op::Status => "status_restored",
    })
}

/// Reads the request to the end of the stream, which only the client's
/// half-close gives within [`TEST_WAIT`] (the client still waits for the
/// reply): it must be exactly `expected`, one line.
fn read_request(stream: &mut UnixStream, expected: &[u8]) {
    let mut received = Vec::new();
    stream
        .read_to_end(&mut received)
        .expect("the end of the stream: the client closes its write half");
    assert_eq!(received, expected);
    assert_eq!(received.iter().filter(|byte| **byte == b'\n').count(), 1);
    assert_eq!(received.last(), Some(&b'\n'));
}

/// What a fake server is given: its one connection, the request line it
/// must read, and a receiver that ends when the call has returned.
struct Accepted {
    stream: UnixStream,
    line: Vec<u8>,
    returned: mpsc::Receiver<()>,
}

impl Accepted {
    fn read_request(&mut self) {
        read_request(&mut self.stream, &self.line);
    }

    /// Blocks until the call has returned (bounded by [`TEST_WAIT`]).
    fn wait_for_the_call(&self) {
        let _ = self.returned.recv_timeout(TEST_WAIT);
    }
}

/// The early end a timed wait may have (a socket timeout rounded down by
/// the system, say): a lower bound on how long a call took allows it.
const EARLY: Duration = Duration::from_millis(25);

/// Whether `took` is `bound` at least, but for [`EARLY`].
fn at_least(took: Duration, bound: Duration) -> bool {
    took + EARLY >= bound
}

/// The first connection to `listener`, accepted within [`TEST_WAIT`] or
/// the test fails: a client that never connects fails the test instead of
/// hanging it. The one poll of these tests: the listener does not block,
/// and is retried every millisecond until then. The connection returned
/// blocks.
fn accept_within(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + TEST_WAIT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Inherited from the listener on macOS, not on Linux.
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "no connection within the test wait"
                );
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => panic!("accept: {err}"),
        }
    }
}

/// Calls `request` with `timeouts` against a fake server that runs `serve`
/// on the first connection it accepts. Checks that the client connected
/// exactly once, joins the server (its failed assertions fail the test)
/// and returns the outcome and how long the call took.
fn against(
    request: &Request,
    timeouts: Timeouts,
    serve: impl FnOnce(Accepted) + Send + 'static,
) -> (Result<Reply, CallError>, Duration) {
    let dir = TempDir::new();
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let line = request.encode().unwrap().as_bytes().to_vec();
    let (done, returned) = mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let stream = accept_within(&listener);
        stream.set_read_timeout(Some(TEST_WAIT)).unwrap();
        stream.set_write_timeout(Some(TEST_WAIT)).unwrap();
        serve(Accepted {
            stream,
            line,
            returned,
        });
    });
    let (client, connects) = counted(&path, timeouts);
    let start = Instant::now();
    let outcome = call(&client, request);
    let took = start.elapsed();
    drop(done);
    server.join().expect("the fake server's checks");
    assert_eq!(
        connects.load(Ordering::SeqCst),
        1,
        "{request:?}: one connect"
    );
    (outcome, took)
}

/// Each golden success of the fixture, written after the server has read
/// exactly the request line and then the end of the stream, is its
/// operation's success: the values the codec reads from it, and for an
/// issue the challenge `M` whose members are the reply's.
#[test]
fn each_golden_success_is_its_operations_success() {
    for op in Op::ALL {
        let reply = golden_success(op);
        let expected = parse_reply(op, &reply).unwrap();
        let (outcome, _) = against(&request(op), PATIENT, move |mut accepted| {
            accepted.read_request();
            accepted.stream.write_all(&reply).unwrap();
        });
        assert_eq!(outcome, Ok(expected), "{op:?}");
    }
}

/// The refusal of `op` with the golden line of `code`, read in full.
fn refused(op: Op, code: ErrorCode) -> Result<Reply, CallError> {
    let line = golden(&format!("error_{}", code.as_str()));
    against(&request(op), PATIENT, move |mut accepted| {
        accepted.read_request();
        accepted.stream.write_all(&line).unwrap();
    })
    .0
}

/// The refusals, by operation and code (lead ruling): `auth_unavailable`
/// and `server_error`, which a failed `COMMIT` is also answered with, are
/// unknown outcomes carrying the code after every write (`bootstrap`,
/// `issue_challenge`, `restore`), and refusals after a `preview` or a
/// `status`, which change no row (mutant M9); every other code is a
/// refusal after every operation.
#[test]
fn store_failures_are_uncertain_commits_after_a_write() {
    for code in [ErrorCode::AuthUnavailable, ErrorCode::ServerError] {
        for op in [Op::Bootstrap, Op::IssueChallenge, Op::Restore] {
            assert_eq!(
                refused(op, code),
                Err(CallError::Unknown(UnknownOutcome::UncertainCommit(code))),
                "{op:?} {code:?}"
            );
        }
        for op in [Op::Preview, Op::Status] {
            assert_eq!(
                refused(op, code),
                Err(CallError::Refused(code)),
                "{op:?} {code:?}"
            );
        }
    }
    for code in [
        ErrorCode::Forbidden,
        ErrorCode::InvalidRequest,
        ErrorCode::Conflict,
        ErrorCode::NotRestorable,
    ] {
        for op in Op::ALL {
            assert_eq!(
                refused(op, code),
                Err(CallError::Refused(code)),
                "{op:?} {code:?}"
            );
        }
    }
}

/// The golden issued reply with one member changed: `M` with its first
/// byte changed (no longer a challenge), or the `operation_id`,
/// `expires_at` or `expected_revision` beside it not `M`'s. The codec
/// reads each as an issue's success; the client finds it does not match
/// its challenge: an unknown outcome.
#[test]
fn an_issued_reply_that_is_not_its_challenges_is_unknown() {
    let fixture = wire_fixture();
    let case = list(&fixture, "golden_replies")
        .iter()
        .find(|case| text(case, "case") == "issued")
        .unwrap();
    let values = &case["values"];
    let operation_id = text(values, "operation_id");
    let expires_at = values["expires_at"].as_i64().unwrap();
    let expected_revision = values["expected_revision"].as_i64().unwrap();
    let challenge = text(values, "challenge");
    let line = |operation_id: &str, expires_at: i64, expected_revision: i64, challenge: &str| {
        format!(
            "{{\"operation_id\":{},\"expires_at\":{expires_at},\"expected_revision\":{expected_revision},\"challenge\":\"{challenge}\"}}\n",
            Value::from(operation_id)
        )
        .into_bytes()
    };
    // The line rebuilt is the golden line.
    assert_eq!(
        line(operation_id, expires_at, expected_revision, challenge),
        golden("issued")
    );
    let other_first = if challenge.starts_with("00") {
        "01"
    } else {
        "00"
    };
    let variants = [
        line("other-operation", expires_at, expected_revision, challenge),
        line(operation_id, expires_at + 1, expected_revision, challenge),
        line(operation_id, expires_at, expected_revision + 1, challenge),
        line(
            operation_id,
            expires_at,
            expected_revision,
            &format!("{other_first}{}", &challenge[2..]),
        ),
    ];
    for variant in variants {
        assert!(
            matches!(
                parse_reply(Op::IssueChallenge, &variant),
                Ok(Reply::Issued(_))
            ),
            "the codec reads it"
        );
        let (outcome, _) = against(
            &request(Op::IssueChallenge),
            PATIENT,
            move |mut accepted| {
                accepted.read_request();
                accepted.stream.write_all(&variant).unwrap();
            },
        );
        assert_eq!(
            outcome,
            Err(CallError::Unknown(UnknownOutcome::ChallengeMismatch))
        );
    }
}

/// Replies the client cannot read exactly, each after the server read the
/// request: no reply at all, a partial reply, bytes after the newline, a
/// second line, an unknown code, another operation's success.
#[test]
fn a_reply_that_is_not_exact_is_unknown() {
    let success = golden_success(Op::Bootstrap);
    let half = success[..success.len() / 2].to_vec();
    let mut trailing = success.clone();
    trailing.push(b'x');
    let mut two_lines = success.clone();
    two_lines.extend_from_slice(&success);
    let cases: [(Vec<u8>, UnknownOutcome); 6] = [
        (Vec::new(), UnknownOutcome::Truncated),
        (half, UnknownOutcome::Truncated),
        (trailing, UnknownOutcome::TrailingBytes),
        (two_lines, UnknownOutcome::TrailingBytes),
        (
            b"{\"error\":\"nope\"}\n".to_vec(),
            UnknownOutcome::UnknownCode,
        ),
        (golden_success(Op::Restore), UnknownOutcome::Malformed),
    ];
    for (reply, expected) in cases {
        let (outcome, _) = against(&request(Op::Bootstrap), PATIENT, move |mut accepted| {
            accepted.read_request();
            accepted.stream.write_all(&reply).unwrap();
        });
        assert_eq!(outcome, Err(CallError::Unknown(expected)));
    }
}

/// Whether `outcome` is a connection lost, by `kind` on Linux (by any
/// kind on another system).
fn lost_by(outcome: &Result<Reply, CallError>, kind: io::ErrorKind) -> bool {
    match outcome {
        Err(CallError::Unknown(UnknownOutcome::ConnectionLost(got))) => {
            !cfg!(target_os = "linux") || *got == kind
        }
        _ => false,
    }
}

/// The server reads one byte of the request, maybe after it wrote its
/// reply, and closes with the rest unread: the client's read ends with a
/// reset. The bytes read before it are kept, and as the server did not
/// read the whole request, only a refusal is believed: `forbidden` and
/// `invalid_request` (which the server sends before reading the request in
/// full) are refusals, a store failure after a write is still an uncertain
/// commit, and nothing at all, a partial refusal or a success, a
/// well-formed one even, is an unknown outcome. That last part is Linux's
/// alone: macOS has no reset there, the client reads the end of the stream
/// and cannot tell this server from one that read the whole request, so
/// elsewhere these are only never refused and never not sent.
#[test]
fn a_reset_keeps_the_bytes_read_and_only_a_refusal_is_believed() {
    let forbidden = golden("error_forbidden");
    let cases: [(Op, Vec<u8>, Option<CallError>); 6] = [
        (
            Op::Restore,
            forbidden.clone(),
            Some(CallError::Refused(ErrorCode::Forbidden)),
        ),
        (
            Op::Bootstrap,
            golden("error_invalid_request"),
            Some(CallError::Refused(ErrorCode::InvalidRequest)),
        ),
        (
            Op::Restore,
            golden("error_auth_unavailable"),
            Some(CallError::Unknown(UnknownOutcome::UncertainCommit(
                ErrorCode::AuthUnavailable,
            ))),
        ),
        (Op::Bootstrap, golden_success(Op::Bootstrap), None),
        (Op::Preview, forbidden[..5].to_vec(), None),
        (Op::Preview, Vec::new(), None),
    ];
    for (op, reply, expected) in cases {
        for reply_first in [false, true] {
            let sent = reply.clone();
            let (outcome, _) = against(&request(op), PATIENT, move |mut accepted| {
                if reply_first {
                    accepted.stream.write_all(&sent).unwrap();
                }
                // One byte, then close with the rest of the line unread.
                let mut first = [0; 1];
                accepted.stream.read_exact(&mut first).unwrap();
                assert_eq!(first[0], b'{');
                if !reply_first {
                    accepted.stream.write_all(&sent).unwrap();
                }
            });
            let case = format!("{op:?}, {} bytes, first {reply_first}", reply.len());
            match &expected {
                Some(expected) => assert_eq!(outcome, Err(*expected), "{case}"),
                None if cfg!(target_os = "linux") => assert!(
                    lost_by(&outcome, io::ErrorKind::ConnectionReset),
                    "{case}: {outcome:?}"
                ),
                None => assert!(
                    !matches!(outcome, Err(CallError::Refused(_) | CallError::NotSent(_))),
                    "{case}: {outcome:?}"
                ),
            }
        }
    }
}

/// A connector that hands over its connection only once the server has
/// written its reply and closed, so that the client's write fails (a
/// broken pipe).
struct AfterClose {
    path: PathBuf,
    closed: Mutex<Option<mpsc::Receiver<()>>>,
    connects: Arc<AtomicUsize>,
}

impl Connector for AfterClose {
    type Stream = UnixStream;

    fn connect(&self) -> io::Result<UnixStream> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        let stream = UnixStream::connect(&self.path)?;
        let closed = self.closed.lock().unwrap().take().unwrap();
        closed.recv_timeout(TEST_WAIT).unwrap();
        Ok(stream)
    }
}

/// The server answers at once, without reading, and closes before the
/// client writes, as it does for `forbidden`: the write fails with a broken
/// pipe, and the client still reads the reply. A refusal is believed (a
/// store failure after a write is still an uncertain commit); nothing, or
/// a success, is an unknown outcome: the server did not read the request.
#[test]
fn a_failed_write_still_reads_the_reply() {
    let cases: [(Op, Vec<u8>, Option<CallError>); 6] = [
        (
            Op::Restore,
            golden("error_forbidden"),
            Some(CallError::Refused(ErrorCode::Forbidden)),
        ),
        (
            Op::IssueChallenge,
            golden("error_invalid_request"),
            Some(CallError::Refused(ErrorCode::InvalidRequest)),
        ),
        (
            Op::Preview,
            golden("error_server_error"),
            Some(CallError::Refused(ErrorCode::ServerError)),
        ),
        (
            Op::Bootstrap,
            golden("error_server_error"),
            Some(CallError::Unknown(UnknownOutcome::UncertainCommit(
                ErrorCode::ServerError,
            ))),
        ),
        (Op::Bootstrap, golden_success(Op::Bootstrap), None),
        (Op::Restore, Vec::new(), None),
    ];
    for (op, reply, expected) in cases {
        let dir = TempDir::new();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let (closed, closed_receiver) = mpsc::channel();
        let sent = reply.clone();
        let server = thread::spawn(move || {
            let mut stream = accept_within(&listener);
            stream.write_all(&sent).unwrap();
            drop(stream);
            closed.send(()).unwrap();
        });
        let connects = Arc::new(AtomicUsize::new(0));
        let client = LocalClient::with_connector(
            AfterClose {
                path,
                closed: Mutex::new(Some(closed_receiver)),
                connects: Arc::clone(&connects),
            },
            PATIENT,
        );
        let outcome = call(&client, &request(op));
        server.join().unwrap();
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        let case = format!("{op:?}, {} bytes", reply.len());
        match expected {
            Some(expected) => assert_eq!(outcome, Err(expected), "{case}"),
            None => assert!(
                lost_by(&outcome, io::ErrorKind::BrokenPipe),
                "{case}: {outcome:?}"
            ),
        }
    }
}

/// A reply over [`MAX_REPLY_BYTES`], from a server that never stops
/// writing and never closes: the client stops reading one past the cap
/// (long before its timeouts) and the outcome is unknown.
#[test]
fn a_reply_over_the_cap_is_unknown_and_not_read_further() {
    let (outcome, _) = against(&request(Op::Preview), PATIENT, |mut accepted| {
        accepted.read_request();
        let chunk = [b'a'; 4096];
        let mut written = 0;
        // Until the client closes its end.
        while accepted.stream.write_all(&chunk).is_ok() {
            written += chunk.len();
            assert!(written < 64 * MAX_REPLY_BYTES, "the client reads on");
        }
    });
    assert_eq!(outcome, Err(CallError::Unknown(UnknownOutcome::TooLarge)));
}

/// A server silent past the total, after it read the request: the outcome
/// is unknown, at the total and not at the (longer) idle timeout.
#[test]
fn a_reply_later_than_the_total_is_unknown() {
    let timeouts = Timeouts {
        total: Duration::from_millis(300),
        idle: TEST_WAIT,
    };
    let reply = golden_success(Op::Restore);
    let (outcome, took) = against(&request(Op::Restore), timeouts, move |mut accepted| {
        accepted.read_request();
        accepted.wait_for_the_call();
        let _ = accepted.stream.write_all(&reply);
    });
    assert_eq!(outcome, Err(CallError::Unknown(UnknownOutcome::TimedOut)));
    assert!(at_least(took, timeouts.total), "{took:?}");
    assert!(took < TEST_WAIT / 2, "{took:?}");
}

/// A reply that stops after its first bytes: the idle timeout ends the
/// call, long before the total, and the outcome is unknown.
#[test]
fn a_reply_that_stalls_is_unknown_at_the_idle_timeout() {
    let timeouts = Timeouts {
        total: TEST_WAIT,
        idle: Duration::from_millis(200),
    };
    let reply = golden_success(Op::Bootstrap);
    let (outcome, took) = against(&request(Op::Bootstrap), timeouts, move |mut accepted| {
        accepted.read_request();
        accepted.stream.write_all(&reply[..5]).unwrap();
        accepted.wait_for_the_call();
    });
    assert_eq!(outcome, Err(CallError::Unknown(UnknownOutcome::TimedOut)));
    assert!(at_least(took, timeouts.idle), "{took:?}");
    assert!(took < TEST_WAIT / 2, "{took:?}");
}

/// The wait for the reply's first byte is bounded by the total only: a
/// server silent for longer than the idle timeout (its transaction, say)
/// and then answering within the total is a success.
#[test]
fn the_first_byte_may_come_later_than_the_idle_timeout() {
    let timeouts = Timeouts {
        total: TEST_WAIT,
        idle: Duration::from_millis(100),
    };
    let reply = golden_success(Op::Preview);
    let expected = parse_reply(Op::Preview, &reply).unwrap();
    let (outcome, took) = against(&request(Op::Preview), timeouts, move |mut accepted| {
        accepted.read_request();
        thread::sleep(Duration::from_millis(500));
        accepted.stream.write_all(&reply).unwrap();
    });
    assert_eq!(outcome, Ok(expected));
    assert!(took >= Duration::from_millis(500), "{took:?}");
}

/// A server that accepts and never reads or answers: the request fits in
/// the socket's buffer, so it may be served later; unknown at the total.
#[test]
fn a_listener_that_accepts_and_never_answers_is_unknown() {
    let timeouts = Timeouts {
        total: Duration::from_millis(300),
        idle: TEST_WAIT,
    };
    let (outcome, took) = against(&request(Op::Restore), timeouts, |accepted| {
        accepted.wait_for_the_call();
    });
    assert_eq!(outcome, Err(CallError::Unknown(UnknownOutcome::TimedOut)));
    assert!(took < TEST_WAIT / 2, "{took:?}");
}

/// A listener that never accepts: the connect and the write of a request
/// still in the listen queue succeed, as if accepted, and the request may
/// be served once accepted; unknown at the total, never not sent.
#[test]
fn a_listener_that_never_accepts_is_unknown() {
    let dir = TempDir::new();
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let timeouts = Timeouts {
        total: Duration::from_millis(300),
        idle: TEST_WAIT,
    };
    let (client, connects) = counted(&path, timeouts);
    let start = Instant::now();
    let outcome = call(&client, &request(Op::Bootstrap));
    let took = start.elapsed();
    assert_eq!(outcome, Err(CallError::Unknown(UnknownOutcome::TimedOut)));
    assert!(
        at_least(took, timeouts.total) && took < TEST_WAIT / 2,
        "{took:?}"
    );
    assert_eq!(connects.load(Ordering::SeqCst), 1);
    // The queued connection holds the whole request line, then its end. On
    // Linux only: by now the call's thread may have dropped its end, and
    // macOS then refuses the options of the queued socket (`EINVAL`), and
    // may refuse its accept.
    if cfg!(target_os = "linux") {
        let mut queued = accept_within(&listener);
        queued.set_read_timeout(Some(TEST_WAIT)).unwrap();
        read_request(
            &mut queued,
            request(Op::Bootstrap).encode().unwrap().as_bytes(),
        );
    }
}

/// Paths no connection can be made to: missing, a regular file, a
/// directory, a socket file no listener holds, a path through a regular
/// file, a path too long for a socket address. Each is not sent, after one
/// connect.
#[test]
fn a_connection_that_cannot_be_made_is_not_sent() {
    let dir = TempDir::new();
    std::fs::write(dir.join("file"), b"").unwrap();
    std::fs::create_dir(dir.join("directory")).unwrap();
    drop(UnixListener::bind(dir.join("stale")).unwrap());
    assert!(dir.join("stale").exists());
    let long = dir.join(&"x".repeat(200));
    let cases = [
        (dir.join("missing"), io::ErrorKind::NotFound),
        (dir.join("file"), io::ErrorKind::ConnectionRefused),
        (dir.join("directory"), io::ErrorKind::ConnectionRefused),
        (dir.join("stale"), io::ErrorKind::ConnectionRefused),
        (dir.join("file").join("s"), io::ErrorKind::NotADirectory),
        (long, io::ErrorKind::InvalidInput),
    ];
    for (path, kind) in cases {
        for op in Op::ALL {
            let (client, connects) = counted(&path, PATIENT);
            let outcome = call(&client, &request(op));
            let Err(CallError::NotSent(NotSent::Connect(got))) = outcome else {
                panic!("{}: {outcome:?}", path.display());
            };
            if cfg!(target_os = "linux") {
                assert_eq!(got, kind, "{}", path.display());
            }
            assert_eq!(connects.load(Ordering::SeqCst), 1);
        }
    }
    // Through the unchecked connector too.
    let client = LocalClient::unchecked(dir.join("missing"), Timeouts::default());
    assert!(matches!(
        client.preview(&ResponseRequest {
            operation_id: "o".into(),
            signature: [1; 64],
        }),
        Err(CallError::NotSent(NotSent::Connect(_)))
    ));
}

/// A socket the caller may not write to (mode 000): permission denied,
/// not sent. Root is not refused by a mode, so as root only the connector's
/// error is checked.
#[test]
fn a_connection_without_permission_is_not_sent() {
    struct Denied;
    impl Connector for Denied {
        type Stream = UnixStream;
        fn connect(&self) -> io::Result<UnixStream> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    let client = LocalClient::with_connector(Denied, PATIENT);
    assert_eq!(
        call(&client, &request(Op::Restore)),
        Err(CallError::NotSent(NotSent::Connect(
            io::ErrorKind::PermissionDenied
        )))
    );

    let dir = TempDir::new();
    let path = dir.join("s");
    let _listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::metadata(&path).unwrap().uid() == 0 {
        eprintln!("NOTICE: running as root: the socket mode check was NOT run");
        return;
    }
    let (client, connects) = counted(&path, PATIENT);
    assert_eq!(
        call(&client, &request(Op::Restore)),
        Err(CallError::NotSent(NotSent::Connect(
            io::ErrorKind::PermissionDenied
        )))
    );
    assert_eq!(connects.load(Ordering::SeqCst), 1);
}

/// A stream, not a socket (a bridge, say), whose every write runs out of
/// time, and which would read a clean end of the stream.
struct Stalled;

impl io::Read for Stalled {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl io::Write for Stalled {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl HalfClose for Stalled {
    fn close_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn set_read_wait(&mut self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_wait(&mut self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

impl Connector for Stalled {
    type Stream = Self;

    fn connect(&self) -> io::Result<Self> {
        Ok(Self)
    }
}

/// A write that runs out of time (the server does not read, and the
/// buffers are full) ends the call as an unknown outcome: unlike a failed
/// write, it is not read on.
#[test]
fn a_write_that_times_out_is_unknown() {
    let client = LocalClient::with_connector(Stalled, PATIENT);
    for op in Op::ALL {
        let start = Instant::now();
        assert_eq!(
            call(&client, &request(op)),
            Err(CallError::Unknown(UnknownOutcome::TimedOut)),
            "{op:?}"
        );
        // At the stream's own timeout, not retried until the total.
        assert!(start.elapsed() < TEST_WAIT / 2, "{op:?}");
    }
}

/// What a [`Scripted`] stream saw: the bytes written to it and the length
/// of each write's offer, how many bytes were read from it and how many
/// reads, each wait set (read and write, failing or not), and whether it
/// was flushed and its write half ended (asked to, failing or not).
#[derive(Debug, Default, Clone)]
struct Seen {
    written: Vec<u8>,
    offers: Vec<usize>,
    read: usize,
    reads: usize,
    read_waits: Vec<Option<Duration>>,
    write_waits: Vec<Option<Duration>>,
    flushed: bool,
    closed: bool,
}

/// How a [`Scripted`] stream behaves.
#[derive(Clone)]
struct Plan {
    /// What it answers, at most `per_read` bytes per read, then the end of
    /// the stream.
    reply: Vec<u8>,
    per_read: usize,
    /// At most `per_write` bytes taken per write, each after `write_delay`.
    per_write: usize,
    write_delay: Duration,
    flush_delay: Duration,
    /// The failure of the end of its write half.
    close: Option<io::ErrorKind>,
    /// The failure of the setting of each read wait.
    read_waits: Option<io::ErrorKind>,
    /// The failure of the setting of the write wait, from the given one on
    /// (0: the first, before any write).
    write_waits: Option<(usize, io::ErrorKind)>,
    /// How long each setting of the write wait takes, from the given one on.
    write_wait_delay: Option<(usize, Duration)>,
}

impl Plan {
    /// Answers `reply`, a few bytes per read; takes whole writes at once;
    /// never fails.
    fn new(reply: &[u8]) -> Self {
        Self {
            reply: reply.to_vec(),
            per_read: 7,
            per_write: usize::MAX,
            write_delay: Duration::ZERO,
            flush_delay: Duration::ZERO,
            close: None,
            read_waits: None,
            write_waits: None,
            write_wait_delay: None,
        }
    }
}

/// A stream, not a socket, that behaves as its [`Plan`] says and records
/// what it [`Seen`]. Its `_gone` sender ends with it.
struct Scripted {
    plan: Plan,
    write_waits_set: usize,
    seen: Arc<Mutex<Seen>>,
    _gone: mpsc::Sender<()>,
}

fn fail(kind: Option<io::ErrorKind>) -> io::Result<()> {
    kind.map_or(Ok(()), |kind| Err(io::Error::from(kind)))
}

impl io::Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut seen = self.seen.lock().unwrap();
        let rest = &self.plan.reply[seen.read..];
        let read = rest.len().min(buf.len()).min(self.plan.per_read);
        buf[..read].copy_from_slice(&rest[..read]);
        seen.read += read;
        seen.reads += 1;
        Ok(read)
    }
}

impl io::Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        thread::sleep(self.plan.write_delay);
        let taken = buf.len().min(self.plan.per_write);
        let mut seen = self.seen.lock().unwrap();
        seen.offers.push(buf.len());
        seen.written.extend_from_slice(&buf[..taken]);
        Ok(taken)
    }

    fn flush(&mut self) -> io::Result<()> {
        thread::sleep(self.plan.flush_delay);
        self.seen.lock().unwrap().flushed = true;
        Ok(())
    }
}

impl HalfClose for Scripted {
    fn close_write(&mut self) -> io::Result<()> {
        self.seen.lock().unwrap().closed = true;
        fail(self.plan.close)
    }

    fn set_read_wait(&mut self, wait: Option<Duration>) -> io::Result<()> {
        self.seen.lock().unwrap().read_waits.push(wait);
        fail(self.plan.read_waits)
    }

    fn set_write_wait(&mut self, wait: Option<Duration>) -> io::Result<()> {
        let this = self.write_waits_set;
        self.write_waits_set += 1;
        if let Some((from, delay)) = self.plan.write_wait_delay
            && this >= from
        {
            thread::sleep(delay);
        }
        self.seen.lock().unwrap().write_waits.push(wait);
        fail(
            self.plan
                .write_waits
                .and_then(|(from, kind)| (this >= from).then_some(kind)),
        )
    }
}

/// The connector of one [`Scripted`] stream.
struct Script {
    plan: Plan,
    seen: Arc<Mutex<Seen>>,
    gone: Mutex<Option<mpsc::Sender<()>>>,
}

impl Connector for Script {
    type Stream = Scripted;

    fn connect(&self) -> io::Result<Scripted> {
        Ok(Scripted {
            plan: self.plan.clone(),
            write_waits_set: 0,
            seen: Arc::clone(&self.seen),
            _gone: self.gone.lock().unwrap().take().unwrap(),
        })
    }
}

/// Calls `op` over a [`Scripted`] stream of `plan` with `timeouts`: the
/// outcome and, once the call's thread has dropped the stream (bounded),
/// what the stream saw.
fn scripted_with(op: Op, plan: Plan, timeouts: Timeouts) -> (Result<Reply, CallError>, Seen) {
    scripted_request(&request(op), plan, timeouts)
}

/// [`scripted_with`], for `request`.
fn scripted_request(
    request: &Request,
    plan: Plan,
    timeouts: Timeouts,
) -> (Result<Reply, CallError>, Seen) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (gone, dropped) = mpsc::channel();
    let script = Script {
        plan,
        seen: Arc::clone(&seen),
        gone: Mutex::new(Some(gone)),
    };
    let outcome = call(&LocalClient::with_connector(script, timeouts), request);
    assert_eq!(
        dropped.recv_timeout(TEST_WAIT),
        Err(mpsc::RecvTimeoutError::Disconnected),
        "the call's thread ends"
    );
    let seen = seen.lock().unwrap().clone();
    (outcome, seen)
}

/// [`scripted_with`], with timeouts no stream here comes close to.
fn scripted(op: Op, plan: Plan) -> (Result<Reply, CallError>, Seen) {
    scripted_with(op, plan, PATIENT)
}

/// The most the client offers in one write: 4 KiB (`WRITE_CHUNK` of the
/// exchange).
const WRITE_CHUNK: usize = 4096;

/// A bootstrap whose line is about 20 KiB: five chunks.
fn long_bootstrap() -> Request {
    let Request::Bootstrap(mut bootstrap) = request(Op::Bootstrap) else {
        unreachable!()
    };
    bootstrap.credential_spki = vec![0xc7; 10_000];
    Request::Bootstrap(bootstrap)
}

/// A line longer than a chunk is offered a chunk at a time, each offer at
/// most [`WRITE_CHUNK`] bytes and each after its own wait is set, and the
/// flush after one more, whether the stream takes whole offers or part of
/// each; the whole line is written and the call succeeds.
#[test]
fn a_long_line_is_offered_a_chunk_at_a_time() {
    let long = long_bootstrap();
    let line = long.encode().unwrap();
    let line = line.as_bytes();
    assert!(line.len() > 4 * WRITE_CHUNK, "{}", line.len());
    let reply = golden_success(Op::Bootstrap);
    let expected = parse_reply(Op::Bootstrap, &reply).unwrap();
    for per_write in [usize::MAX, 1000] {
        let plan = Plan {
            per_write,
            ..Plan::new(&reply)
        };
        let (outcome, seen) = scripted_request(&long, plan, PATIENT);
        assert_eq!(outcome, Ok(expected.clone()), "{per_write}");
        assert_eq!(seen.written, line, "{per_write}");
        assert!(
            seen.offers.iter().all(|&offer| offer <= WRITE_CHUNK),
            "{per_write}: {:?}",
            seen.offers
        );
        assert!(
            seen.offers.len() >= line.len().div_ceil(WRITE_CHUNK),
            "{per_write}: {:?}",
            seen.offers
        );
        // One wait per write, and the flush's.
        assert_eq!(seen.write_waits.len(), seen.offers.len() + 1, "{per_write}");
        assert!(seen.flushed, "{per_write}");
    }
}

/// A setting of the write wait that returns after the total has run out
/// (a bridge, say) stops the writing before the next write. Before the
/// first write, nothing is written and the call is not sent, for the
/// caller as for its thread; before a later chunk, the call is unknown
/// (part of the line was written), and nothing more is written, flushed or
/// closed.
#[test]
fn a_wait_set_past_the_total_stops_the_writing() {
    let timeouts = Timeouts {
        total: Duration::from_millis(100),
        idle: TEST_WAIT,
    };
    let reply = golden_success(Op::Bootstrap);
    let slow = |from| Plan {
        write_wait_delay: Some((from, Duration::from_millis(300))),
        ..Plan::new(&reply)
    };
    let (outcome, seen) = scripted_request(&long_bootstrap(), slow(0), timeouts);
    assert_eq!(outcome, Err(CallError::NotSent(NotSent::TimedOut)));
    assert!(
        seen.offers.is_empty() && seen.written.is_empty(),
        "{seen:?}"
    );
    assert!(!seen.flushed && !seen.closed && seen.reads == 0, "{seen:?}");
    let (outcome, seen) = scripted_request(&long_bootstrap(), slow(1), timeouts);
    assert_eq!(outcome, Err(CallError::Unknown(UnknownOutcome::TimedOut)));
    assert_eq!(seen.offers, [WRITE_CHUNK], "{seen:?}");
    assert_eq!(seen.written.len(), WRITE_CHUNK);
    assert!(!seen.flushed && !seen.closed && seen.reads == 0, "{seen:?}");
}

/// The waits set: before each write, the idle timeout or what is left of
/// the total if less; before the first read, what is left of the total
/// alone (none without a total); before each later read, as before a
/// write (each chunk's). One wait per read.
#[test]
fn the_waits_set_are_the_idle_timeout_and_what_is_left_of_the_total() {
    let idle = Duration::from_secs(5);
    let near = |wait: &Option<Duration>, bound: Duration| {
        wait.is_some_and(|wait| wait <= bound && wait > bound - Duration::from_secs(1))
    };
    let reply = golden_success(Op::Restore);
    let expected = parse_reply(Op::Restore, &reply).unwrap();
    // A total longer than the idle timeout, and a line of several chunks.
    let total = Duration::from_secs(60);
    let bootstrapped = golden_success(Op::Bootstrap);
    let (outcome, seen) = scripted_request(
        &long_bootstrap(),
        Plan::new(&bootstrapped),
        Timeouts { total, idle },
    );
    assert_eq!(outcome, parse_reply(Op::Bootstrap, &bootstrapped));
    assert!(seen.write_waits.len() > 1, "{seen:?}");
    assert!(
        seen.write_waits.iter().all(|wait| near(wait, idle)),
        "{seen:?}"
    );
    assert!(near(&seen.read_waits[0], total), "{seen:?}");
    assert!(seen.read_waits.len() > 2, "{seen:?}");
    assert!(
        seen.read_waits[1..].iter().all(|wait| near(wait, idle)),
        "{seen:?}"
    );
    assert_eq!(seen.read_waits.len(), seen.reads, "{seen:?}");
    // A total shorter than the idle timeout bounds every wait.
    let total = Duration::from_secs(2);
    let (outcome, seen) = scripted_with(
        Op::Restore,
        Plan::new(&reply),
        Timeouts {
            total,
            idle: TEST_WAIT,
        },
    );
    assert_eq!(outcome, Ok(expected.clone()));
    for wait in seen.write_waits.iter().chain(&seen.read_waits) {
        assert!(near(wait, total), "{seen:?}");
    }
    // No total: the idle timeout, and no bound on the first read.
    let (outcome, seen) = scripted_with(
        Op::Restore,
        Plan::new(&reply),
        Timeouts {
            total: Duration::MAX,
            idle,
        },
    );
    assert_eq!(outcome, Ok(expected));
    assert!(seen.write_waits.iter().all(|wait| *wait == Some(idle)));
    assert_eq!(seen.read_waits[0], None);
    assert!(seen.read_waits[1..].iter().all(|wait| *wait == Some(idle)));
}

/// A write that takes nothing (`Ok(0)`) is a lost connection
/// ([`io::ErrorKind::WriteZero`]), not a write retried until the total: the
/// reply is still read, and a success is not believed.
#[test]
fn a_write_that_takes_nothing_is_a_lost_connection() {
    let timeouts = Timeouts {
        total: Duration::from_secs(1),
        idle: TEST_WAIT,
    };
    let reply = golden_success(Op::Restore);
    let plan = Plan {
        per_write: 0,
        ..Plan::new(&reply)
    };
    let (outcome, seen) = scripted_with(Op::Restore, plan, timeouts);
    assert_eq!(
        outcome,
        Err(CallError::Unknown(UnknownOutcome::ConnectionLost(
            io::ErrorKind::WriteZero
        )))
    );
    assert_eq!(seen.offers.len(), 1, "{seen:?}");
    assert!(seen.written.is_empty());
    assert!(seen.closed);
    assert_eq!(seen.read, reply.len());
}

/// An end of the write half that fails after the whole line was written
/// (`EINVAL` or, as macOS does once the server has closed, `ENOTCONN`):
/// the reply is still read, and as after a failed write only a refusal is
/// believed. A server dispatches a request only once it has read the end of
/// the stream, which this end never sent: a well-formed success, then, is
/// not one the server sent for this request, and is unknown.
#[test]
fn a_half_close_that_fails_after_the_whole_line_still_reads_the_reply() {
    for kind in [io::ErrorKind::InvalidInput, io::ErrorKind::NotConnected] {
        let mut cases = vec![
            (
                Op::Restore,
                golden("error_forbidden"),
                Err(CallError::Refused(ErrorCode::Forbidden)),
            ),
            (
                Op::Preview,
                golden("error_server_error"),
                Err(CallError::Refused(ErrorCode::ServerError)),
            ),
            (
                Op::Bootstrap,
                golden("error_auth_unavailable"),
                Err(CallError::Unknown(UnknownOutcome::UncertainCommit(
                    ErrorCode::AuthUnavailable,
                ))),
            ),
            (
                Op::IssueChallenge,
                Vec::new(),
                Err(CallError::Unknown(UnknownOutcome::ConnectionLost(kind))),
            ),
        ];
        for op in Op::ALL {
            cases.push((
                op,
                golden_success(op),
                Err(CallError::Unknown(UnknownOutcome::ConnectionLost(kind))),
            ));
        }
        for (op, reply, expected) in cases {
            let plan = Plan {
                close: Some(kind),
                ..Plan::new(&reply)
            };
            let (outcome, seen) = scripted(op, plan);
            let case = format!("{kind:?}, {op:?}, {} bytes", reply.len());
            assert_eq!(outcome, expected, "{case}");
            assert_eq!(
                seen.written,
                request(op).encode().unwrap().as_bytes(),
                "{case}: the whole line"
            );
            assert_eq!(seen.read, reply.len(), "{case}: the whole reply");
        }
    }
}

/// A wait the stream refuses ends the call, whatever the error (only the
/// Unix socket's own `HalfClose` passes over macOS's refusal of a closed
/// socket's options): before the first write it is not sent, nothing
/// written; after a write, a later write's or a read's, it is unknown.
#[test]
fn a_wait_the_stream_refuses_ends_the_call() {
    for kind in [
        io::ErrorKind::InvalidInput,
        io::ErrorKind::Unsupported,
        io::ErrorKind::Other,
    ] {
        for op in Op::ALL {
            let case = format!("{kind:?}, {op:?}");
            let plan = Plan {
                write_waits: Some((0, kind)),
                ..Plan::new(&golden_success(op))
            };
            let (outcome, seen) = scripted(op, plan);
            assert_eq!(
                outcome,
                Err(CallError::NotSent(NotSent::Setup(kind))),
                "{case}"
            );
            assert!(seen.written.is_empty(), "{case}");
            assert!(!seen.closed && seen.read == 0, "{case}");

            let plan = Plan {
                per_write: 5,
                write_waits: Some((1, kind)),
                ..Plan::new(&golden_success(op))
            };
            let (outcome, seen) = scripted(op, plan);
            assert_eq!(
                outcome,
                Err(CallError::Unknown(UnknownOutcome::ConnectionLost(kind))),
                "{case}: a later write"
            );
            assert_eq!(seen.written.len(), 5, "{case}: a later write");

            let plan = Plan {
                read_waits: Some(kind),
                ..Plan::new(&golden_success(op))
            };
            let (outcome, seen) = scripted(op, plan);
            assert_eq!(
                outcome,
                Err(CallError::Unknown(UnknownOutcome::ConnectionLost(kind))),
                "{case}: a read"
            );
            assert_eq!(
                seen.written,
                request(op).encode().unwrap().as_bytes(),
                "{case}: a read"
            );
        }
    }
}

/// Nothing is sent once the total has run out: not the rest of a line
/// written a byte at a time, each write well within the idle timeout but
/// all of them past the total; not the flush after a write that ended past
/// it; not the end of the write half after such a flush. The caller has
/// given up by then (unknown), and the call's thread stops.
#[test]
fn nothing_is_sent_once_the_total_has_run_out() {
    let timeouts = Timeouts {
        total: Duration::from_millis(100),
        idle: TEST_WAIT,
    };
    let line = request(Op::Bootstrap).encode().unwrap();
    let line = line.as_bytes();
    // Two milliseconds a byte: the line would take far longer than the
    // total.
    assert!(line.len() > 100, "{}", line.len());
    let slow_bytes = Plan {
        per_write: 1,
        write_delay: Duration::from_millis(2),
        ..Plan::new(&golden_success(Op::Bootstrap))
    };
    let slow_write = Plan {
        write_delay: Duration::from_millis(300),
        ..Plan::new(&golden_success(Op::Bootstrap))
    };
    let slow_flush = Plan {
        flush_delay: Duration::from_millis(300),
        ..Plan::new(&golden_success(Op::Bootstrap))
    };
    for (case, plan, whole, flushed) in [
        ("a byte at a time", slow_bytes, false, false),
        ("a slow write", slow_write, true, false),
        ("a slow flush", slow_flush, true, true),
    ] {
        let (outcome, seen) = scripted_with(Op::Bootstrap, plan, timeouts);
        assert_eq!(
            outcome,
            Err(CallError::Unknown(UnknownOutcome::TimedOut)),
            "{case}"
        );
        assert!(!seen.written.is_empty(), "{case}");
        assert_eq!(seen.written.len() == line.len(), whole, "{case}: {seen:?}");
        assert!(line.starts_with(&seen.written), "{case}");
        assert_eq!(seen.flushed, flushed, "{case}");
        assert!(!seen.closed, "{case}: the end of the write half");
        assert_eq!(seen.read, 0, "{case}");
    }
}

/// However large each read may be, the client reads one byte past
/// [`MAX_REPLY_BYTES`] and no further: the outcome is unknown, and the
/// stream has given exactly that many bytes.
#[test]
fn a_reply_over_the_cap_is_read_one_byte_past_it() {
    for extra in [1, 2, 8192, 3 * 8192 + 5] {
        let plan = Plan {
            per_read: usize::MAX,
            ..Plan::new(&vec![b'a'; MAX_REPLY_BYTES + extra])
        };
        let (outcome, seen) = scripted(Op::Preview, plan);
        assert_eq!(
            outcome,
            Err(CallError::Unknown(UnknownOutcome::TooLarge)),
            "{extra}"
        );
        assert_eq!(seen.read, MAX_REPLY_BYTES + 1, "{extra}");
    }
    // At the cap, the whole reply and its end are read.
    let plan = Plan {
        per_read: usize::MAX,
        ..Plan::new(&vec![b'a'; MAX_REPLY_BYTES])
    };
    let (outcome, seen) = scripted(Op::Preview, plan);
    assert_eq!(seen.read, MAX_REPLY_BYTES);
    assert!(
        matches!(outcome, Err(CallError::Unknown(UnknownOutcome::Truncated))),
        "{outcome:?}"
    );
}

/// A typed call whose values alone are longer than [`MAX_REQUEST_BYTES`]
/// (by a mebibyte, or by one byte) is not sent, and nothing is connected.
/// The typed calls check this before they copy the values into a
/// [`Request`]; that no copy is made is not observable here (no test
/// counts allocations).
#[test]
fn an_oversized_value_is_refused_before_it_is_copied() {
    let dir = TempDir::new();
    let (client, connects) = counted(&dir.join("s"), PATIENT);
    let too_large = Err(CallError::NotSent(NotSent::TooLarge));
    for len in [1024 * 1024, MAX_REQUEST_BYTES + 1] {
        let Request::Bootstrap(mut bootstrap) = request(Op::Bootstrap) else {
            unreachable!()
        };
        bootstrap.instance_id = String::new();
        bootstrap.credential_spki = Vec::new();
        bootstrap.trust_anchor_ref = "t".repeat(len);
        assert_eq!(client.bootstrap(&bootstrap).map(|_| ()), too_large, "{len}");
        let Request::IssueChallenge(mut issue) = request(Op::IssueChallenge) else {
            unreachable!()
        };
        issue.credential_spki = Vec::new();
        issue.trust_anchor_ref = "t".repeat(len);
        assert_eq!(
            client.issue_challenge(&issue).map(|_| ()),
            too_large,
            "{len}"
        );
        let Request::Restore(mut response) = request(Op::Restore) else {
            unreachable!()
        };
        response.operation_id = "o".repeat(len);
        assert_eq!(client.preview(&response).map(|_| ()), too_large, "{len}");
        assert_eq!(client.restore(&response).map(|_| ()), too_large, "{len}");
        for status in [
            StatusRequest {
                operation_id: Some("o".repeat(len)),
                ..StatusRequest::default()
            },
            StatusRequest {
                credential_spki: Some(vec![0xc7; len / 2 + 1]),
                ..StatusRequest::default()
            },
            StatusRequest {
                operation_id: Some("o".into()),
                revoked_after: Some("r".repeat(len)),
                ..StatusRequest::default()
            },
        ] {
            assert_eq!(client.status(&status).map(|_| ()), too_large, "{len}");
        }
    }
    assert_eq!(connects.load(Ordering::SeqCst), 0);
}

/// A connector whose connect blocks until the test hands it a stream.
struct Gate {
    stream: Mutex<Option<mpsc::Receiver<UnixStream>>>,
}

impl Connector for Gate {
    type Stream = UnixStream;

    fn connect(&self) -> io::Result<UnixStream> {
        let receiver = self.stream.lock().unwrap().take().unwrap();
        receiver
            .recv_timeout(TEST_WAIT)
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))
    }
}

/// A connect that outlasts the total: the call is not sent, and when the
/// connect returns afterwards, the connection is dropped with nothing
/// written to it (the handshake between the caller and its thread; the
/// thread's own deadline, past by then, would refuse the write too).
#[test]
fn a_connect_that_returns_after_the_caller_gave_up_is_never_written() {
    let (hand, stream) = mpsc::channel();
    let timeouts = Timeouts {
        total: Duration::from_millis(200),
        idle: TEST_WAIT,
    };
    let client = LocalClient::with_connector(
        Gate {
            stream: Mutex::new(Some(stream)),
        },
        timeouts,
    );
    let start = Instant::now();
    let outcome = call(&client, &request(Op::Restore));
    let took = start.elapsed();
    assert_eq!(outcome, Err(CallError::NotSent(NotSent::TimedOut)));
    assert!(
        at_least(took, timeouts.total) && took < TEST_WAIT / 2,
        "{took:?}"
    );
    // Now the connect returns; the peer reads the end of the stream, and
    // not one byte, once the call's thread has dropped its end.
    let (theirs, mut ours) = UnixStream::pair().unwrap();
    ours.set_read_timeout(Some(TEST_WAIT)).unwrap();
    hand.send(theirs).unwrap();
    let mut received = Vec::new();
    ours.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"");
}

/// Nothing is connected for a request that is not sent before the
/// connect: a line over the limit, or a zero timeout.
#[test]
fn a_request_not_sent_is_never_connected() {
    let dir = TempDir::new();
    let path = dir.join("s");
    let too_large = Request::Restore(ResponseRequest {
        operation_id: "x".repeat(64 * 1024),
        signature: [1; 64],
    });
    let (client, connects) = counted(&path, PATIENT);
    assert_eq!(
        call(&client, &too_large),
        Err(CallError::NotSent(NotSent::TooLarge))
    );
    for timeouts in [
        Timeouts {
            total: Duration::ZERO,
            idle: TEST_WAIT,
        },
        Timeouts {
            total: TEST_WAIT,
            idle: Duration::ZERO,
        },
    ] {
        let (zero, zero_connects) = counted(&path, timeouts);
        assert_eq!(
            call(&zero, &request(Op::Preview)),
            Err(CallError::NotSent(NotSent::InvalidTimeouts))
        );
        assert_eq!(zero_connects.load(Ordering::SeqCst), 0);
    }
    assert_eq!(connects.load(Ordering::SeqCst), 0);
}

/// A total too large for the clock (`Duration::MAX`) is no bound: the
/// call waits for the reply and succeeds; the idle timeout still applies.
#[test]
fn an_unbounded_total_still_exchanges() {
    let timeouts = Timeouts {
        total: Duration::MAX,
        idle: TEST_WAIT,
    };
    let reply = golden_success(Op::IssueChallenge);
    let expected = parse_reply(Op::IssueChallenge, &reply).unwrap();
    let (outcome, _) = against(
        &request(Op::IssueChallenge),
        timeouts,
        move |mut accepted| {
            accepted.read_request();
            accepted.stream.write_all(&reply).unwrap();
        },
    );
    assert_eq!(outcome, Ok(expected));
    // The idle timeout still bounds a reply that stalls.
    let timeouts = Timeouts {
        total: Duration::MAX,
        idle: Duration::from_millis(200),
    };
    let reply = golden_success(Op::Preview);
    let (outcome, took) = against(&request(Op::Preview), timeouts, move |mut accepted| {
        accepted.read_request();
        accepted.stream.write_all(&reply[..5]).unwrap();
        accepted.wait_for_the_call();
    });
    assert_eq!(outcome, Err(CallError::Unknown(UnknownOutcome::TimedOut)));
    assert!(took < TEST_WAIT / 2, "{took:?}");
}

/// The default total is the sum of the server's default deadline,
/// transaction timeout and idle timeout (the fixture's `default_limits`,
/// which the service's side checks against its `Settings::default()`), and
/// the default idle timeout the server's idle timeout. Which operations a
/// caller may retry after an unknown outcome.
#[test]
fn default_timeouts_are_the_servers_defaults() {
    let fixture = wire_fixture();
    let limits = &fixture["default_limits"];
    let seconds = |name: &str| Duration::from_secs(limits[name].as_u64().unwrap());
    assert_eq!(DEFAULT_TOTAL_WAIT, Duration::from_secs(100));
    assert_eq!(DEFAULT_TOTAL_WAIT, seconds("client_total_wait_seconds"));
    assert_eq!(
        DEFAULT_TOTAL_WAIT,
        seconds("deadline_seconds")
            + seconds("transaction_timeout_seconds")
            + seconds("idle_timeout_seconds")
    );
    assert_eq!(DEFAULT_IDLE_WAIT, seconds("idle_timeout_seconds"));
    assert_eq!(
        Timeouts::default(),
        Timeouts {
            total: DEFAULT_TOTAL_WAIT,
            idle: DEFAULT_IDLE_WAIT,
        }
    );
    let client = LocalClient::unchecked("/nonexistent", Timeouts::default());
    assert_eq!(client.timeouts(), Timeouts::default());
    assert_eq!(SocketPath::new("/a/b").path(), Path::new("/a/b"));
    let retry: Vec<(Op, Retry)> = Op::ALL.iter().map(|op| (*op, op.retry())).collect();
    assert_eq!(
        retry,
        [
            (Op::Bootstrap, Retry::ReconcileFirst),
            (Op::IssueChallenge, Retry::ReconcileFirst),
            (Op::Preview, Retry::Safe),
            (Op::Restore, Retry::ReconcileFirst),
            (Op::Status, Retry::Safe),
        ]
    );
}

/// No sentinel value of a request or of the socket's path is shown by
/// `Debug` (plain or alternate) or `Display` of the client, its timeouts or
/// any outcome of a call: `Debug` of the client shows its timeouts, every
/// error names its kind, `Display` is fixed text, distinct per outcome.
#[test]
fn debug_and_display_show_no_value() {
    const SENTINELS: [&str; 7] = [
        "SENTINEL",
        "5a5a",
        "5A5A",
        "90, 90",
        "c7c7",
        "199, 199",
        "skyoauth-operator-exchange",
    ];
    let dir = TempDir::new();
    let client = LocalClient::unchecked(dir.join("SENTINEL-PATH"), Timeouts::default());
    assert_eq!(
        format!("{client:?}"),
        "LocalClient { timeouts: Timeouts { total: 100s, idle: 10s }, .. }"
    );
    let mut shown = vec![
        format!("{client:?}"),
        format!("{client:#?}"),
        format!("{:?}", Timeouts::default()),
        format!("{:?}", request(Op::Restore)),
        format!(
            "{:?}",
            ResponseRequest {
                operation_id: "SENTINEL-OPERATION".into(),
                signature: [0x5a; 64],
            }
        ),
        format!("{:?}", Retry::ReconcileFirst),
    ];
    for op in Op::ALL {
        let outcome = call(&client, &request(op));
        assert!(
            matches!(outcome, Err(CallError::NotSent(NotSent::Connect(_)))),
            "{outcome:?}"
        );
        shown.push(format!("{outcome:?}"));
        shown.push(format!("{outcome:#?}"));
    }
    let mut errors = vec![
        CallError::NotSent(NotSent::TooLarge),
        CallError::NotSent(NotSent::InvalidTimeouts),
        CallError::NotSent(NotSent::Connect(io::ErrorKind::NotFound)),
        CallError::NotSent(NotSent::TimedOut),
        CallError::NotSent(NotSent::Setup(io::ErrorKind::Unsupported)),
        CallError::Unknown(UnknownOutcome::TimedOut),
        CallError::Unknown(UnknownOutcome::ConnectionLost(
            io::ErrorKind::ConnectionReset,
        )),
        CallError::Unknown(UnknownOutcome::ChallengeMismatch),
        CallError::Unknown(UnknownOutcome::PageMismatch),
    ];
    errors.push(CallError::Unknown(UnknownOutcome::UncertainCommit(
        ErrorCode::AuthUnavailable,
    )));
    // The code is in `Debug` only.
    let server_error = CallError::Unknown(UnknownOutcome::UncertainCommit(ErrorCode::ServerError));
    assert_eq!(
        format!("{server_error:?}"),
        "Unknown(UncertainCommit(ServerError))"
    );
    shown.push(server_error.to_string());
    let mut displays = std::collections::BTreeSet::new();
    for error in &errors {
        assert!(displays.insert(error.to_string()), "{error:?}");
        shown.extend([
            format!("{error:?}"),
            format!("{error:#?}"),
            error.to_string(),
        ]);
    }
    for shown in &shown {
        for sentinel in SENTINELS {
            assert!(!shown.contains(sentinel), "{shown}");
        }
    }
    // The advice of an unknown outcome.
    assert!(
        CallError::Unknown(UnknownOutcome::TimedOut)
            .to_string()
            .contains("reconcile")
    );
}

/// The operation ID of the page iterator's walks.
const WALKED: &str = "SENTINEL-WALKED";

/// The revoked credential IDs `range`, in byte order (zero-padded).
fn revoked(range: std::ops::Range<usize>) -> Vec<String> {
    range.map(|at| format!("cred_{at:05}")).collect()
}

/// The `status` request of a walk of [`WALKED`]: after `after`, or its
/// first page.
fn page_request(after: Option<&str>) -> StatusRequest {
    StatusRequest {
        operation_id: Some(WALKED.into()),
        credential_spki: None,
        revoked_after: after.map(str::to_owned),
    }
}

/// The page after the last of `held`.
fn after(held: usize) -> StatusRequest {
    page_request(Some(&revoked(0..held)[held - 1]))
}

/// A `status` reply line of a challenge in `state`, with `count` and the
/// page `ids` (`null` for both when `None`), as the service writes it.
fn status_line(state: &str, page: Option<(i64, &[String])>) -> Vec<u8> {
    let (count, ids) = page.map_or_else(
        || ("null".to_owned(), "null".to_owned()),
        |(count, ids)| (count.to_string(), Value::from(ids.to_vec()).to_string()),
    );
    format!(
        "{{\"server_time\":1,\"instance_id\":\"i\",\"recovery_key_epoch\":2,\
         \"recovery_state_revision\":2,\"recovery_public_key\":\"{}\",\
         \"operation_state\":\"{state}\",\"expires_at\":1,\"settles_at\":null,\
         \"restored_at\":1,\"admin_id\":\"a\",\"credential_id\":\"c\",\"binding_id\":\"b\",\
         \"revoked_credential_count\":{count},\"revoked_credential_ids\":{ids},\
         \"enrolled_state\":null,\"enrolled_admin_id\":null,\"enrolled_credential_id\":null,\
         \"enrolled_trust_anchor_sha256\":null}}\n",
        key().to_hex()
    )
    .into_bytes()
}

/// A `restored` `status` page: `count` and the IDs `range`.
fn page(count: i64, range: std::ops::Range<usize>) -> Vec<u8> {
    status_line("restored", Some((count, &revoked(range))))
}

/// A restore reply with `count` and the IDs `range`, as the codec gives it
/// (the walk's input; a list of any length).
fn restored(count: i64, range: std::ops::Range<usize>) -> Restored {
    Restored {
        admin_id: "a".into(),
        credential_id: "c".into(),
        binding_id: "b".into(),
        revoked_credential_count: count,
        revoked_credential_ids: revoked(range),
        recovery_key_epoch: 2,
        recovery_state_revision: 2,
    }
}

/// A fake server that answers one connection per step, in order, each
/// after it read exactly the step's request line and the end of the
/// stream; it accepts nothing after the last step (a connection more is
/// refused, or never answered). Returns its socket's directory and path,
/// and the server to join.
fn serve_in_order(steps: Vec<(Vec<u8>, Vec<u8>)>) -> (TempDir, PathBuf, thread::JoinHandle<()>) {
    let dir = TempDir::new();
    let path = dir.join("s");
    let listener = UnixListener::bind(&path).unwrap();
    let server = thread::spawn(move || {
        for (line, reply) in steps {
            let mut stream = accept_within(&listener);
            stream.set_read_timeout(Some(TEST_WAIT)).unwrap();
            stream.set_write_timeout(Some(TEST_WAIT)).unwrap();
            read_request(&mut stream, &line);
            stream.write_all(&reply).unwrap();
        }
    });
    (dir, path, server)
}

/// The page iterator's walk of [`WALKED`] after `restored`, or from
/// `status` alone, against a fake server of `steps`: each `status` request
/// the walk must send, in order, and the reply to it. Checks that the
/// walk made exactly these requests, one connection each.
fn walked(
    restored: Option<&Restored>,
    steps: Vec<(StatusRequest, Vec<u8>)>,
) -> Result<Vec<String>, CallError> {
    let expected = steps.len();
    let steps = steps
        .into_iter()
        .map(|(request, reply)| {
            let line = Request::Status(request).encode().unwrap();
            (line.as_bytes().to_vec(), reply)
        })
        .collect();
    let (_dir, path, server) = serve_in_order(steps);
    let (client, connects) = counted(&path, PATIENT);
    let outcome = client.revoked_credential_ids(WALKED, restored);
    server.join().expect("the fake server's checks");
    assert_eq!(
        connects.load(Ordering::SeqCst),
        expected,
        "one connect a page"
    );
    outcome
}

const PAGE_MISMATCH: Result<Vec<String>, CallError> =
    Err(CallError::Unknown(UnknownOutcome::PageMismatch));

/// After a restore reply, the walk reads the pages after its list with
/// `status`, `revoked_after` the last ID held, until the count is held,
/// each page `min(page size, count - held)` IDs: none for a complete list
/// (no count, a short count, exactly a page), then one more ID, a full
/// page and a part, two full pages.
#[test]
fn the_walk_reads_every_page_after_the_restore_reply() {
    assert_eq!(MAX_REVOKED_IDS_PER_REPLY, 1000);
    for count in [0, 3, 1000] {
        let held = usize::try_from(count).unwrap();
        assert_eq!(
            walked(Some(&restored(count, 0..held)), Vec::new()),
            Ok(revoked(0..held)),
            "{count}"
        );
    }
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![(after(1000), page(1001, 1000..1001))]
        ),
        Ok(revoked(0..1001))
    );
    assert_eq!(
        walked(
            Some(&restored(2500, 0..1000)),
            vec![
                (after(1000), page(2500, 1000..2000)),
                (after(2000), page(2500, 2000..2500)),
            ]
        ),
        Ok(revoked(0..2500))
    );
    assert_eq!(
        walked(
            Some(&restored(2000, 0..1000)),
            vec![(after(1000), page(2000, 1000..2000))]
        ),
        Ok(revoked(0..2000))
    );
}

/// Without a restore reply (a restore reconciled as committed), the walk
/// starts from `status` alone: its first page, then the rest as after a
/// restore reply.
#[test]
fn the_walk_from_status_alone_reads_every_page() {
    assert_eq!(
        walked(None, vec![(page_request(None), page(0, 0..0))]),
        Ok(Vec::new())
    );
    assert_eq!(
        walked(None, vec![(page_request(None), page(5, 0..5))]),
        Ok(revoked(0..5))
    );
    assert_eq!(
        walked(
            None,
            vec![
                (page_request(None), page(2001, 0..1000)),
                (after(1000), page(2001, 1000..2000)),
                (after(2000), page(2001, 2000..2001)),
            ]
        ),
        Ok(revoked(0..2001))
    );
}

/// A restore reply whose list is not `min(count, page size)` IDs, longer
/// or shorter (mutant M11), or whose count is negative, is unknown before
/// any `status` call.
#[test]
fn a_restore_reply_list_of_another_length_than_its_count_is_unknown() {
    for (count, range) in [
        (3, 0..4),
        (3, 0..2),
        (0, 0..1),
        (1, 0..0),
        (1500, 0..999),
        (1500, 0..1001),
        (1000, 0..999),
        (1000, 0..1001),
        (-1, 0..0),
    ] {
        assert_eq!(
            walked(Some(&restored(count, range.clone())), Vec::new()),
            PAGE_MISMATCH,
            "{count} {range:?}"
        );
    }
}

/// A `status` page shorter or longer than `min(page size, count - held)`
/// is unknown: the last page, a middle page, an empty page, and the first
/// page of a walk from `status` alone.
#[test]
fn a_status_page_of_another_length_is_unknown() {
    let cases = [
        (
            Some(restored(1500, 0..1000)),
            vec![(after(1000), page(1500, 1000..1499))],
        ),
        (
            Some(restored(1500, 0..1000)),
            vec![(after(1000), page(1500, 1000..1501))],
        ),
        (
            Some(restored(1001, 0..1000)),
            vec![(after(1000), page(1001, 1000..1000))],
        ),
        (
            Some(restored(2500, 0..1000)),
            vec![(after(1000), page(2500, 1000..1999))],
        ),
        (None, vec![(page_request(None), page(1500, 0..999))]),
        (None, vec![(page_request(None), page(5, 0..4))]),
        (None, vec![(page_request(None), page(5, 0..6))]),
        (None, vec![(page_request(None), page(-1, 0..0))]),
    ];
    for (at, (restored, steps)) in cases.into_iter().enumerate() {
        assert_eq!(walked(restored.as_ref(), steps), PAGE_MISMATCH, "case {at}");
    }
}

/// A `status` page whose IDs are not all after the `revoked_after` sent is
/// unknown: one that starts with it, one wholly before it; also with a
/// changed count, which is then no tie (checked first, no restart).
#[test]
fn an_id_not_after_revoked_after_is_unknown() {
    for count in [1002, 1003, 1001] {
        for ids in [revoked(999..1001), revoked(500..502)] {
            let reply = status_line("restored", Some((count, &ids)));
            assert_eq!(
                walked(Some(&restored(1002, 0..1000)), vec![(after(1000), reply)]),
                PAGE_MISMATCH,
                "{count} {ids:?}"
            );
        }
    }
    let reply = status_line("restored", Some((1501, &revoked(999..1001))));
    assert_eq!(
        walked(
            None,
            vec![
                (page_request(None), page(1500, 0..1000)),
                (after(1000), reply),
            ]
        ),
        PAGE_MISMATCH
    );
}

/// A `status` count above the restore reply's is the documented tie: the
/// walk restarts from `status` alone and lists what the service selects
/// then. One below it is unknown, with no restart.
#[test]
fn a_status_count_above_the_restore_replys_restarts_from_status_alone() {
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![
                (after(1000), page(1002, 1000..1002)),
                (page_request(None), page(1002, 0..1000)),
                (after(1000), page(1002, 1000..1002)),
            ]
        ),
        Ok(revoked(0..1002))
    );
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![(after(1000), page(1000, 1000..1000))]
        ),
        PAGE_MISMATCH
    );
}

/// A count that changes between `status` pages is the documented tie: the
/// walk restarts from `status` alone, once (up or down, after a restore
/// reply or from `status` alone), and its list must hold at least the
/// largest count seen; a second change, or a second count above the
/// restore reply's, is unknown.
#[test]
fn a_count_that_changes_between_status_pages_restarts_once_then_is_unknown() {
    // Restarted, then complete.
    assert_eq!(
        walked(
            Some(&restored(2500, 0..1000)),
            vec![
                (after(1000), page(2500, 1000..2000)),
                (after(2000), page(2501, 2000..2501)),
                (page_request(None), page(2501, 0..1000)),
                (after(1000), page(2501, 1000..2000)),
                (after(2000), page(2501, 2000..2501)),
            ]
        ),
        Ok(revoked(0..2501))
    );
    // Down, restarted, and back to the largest count seen: complete.
    assert_eq!(
        walked(
            None,
            vec![
                (page_request(None), page(1500, 0..1000)),
                (after(1000), page(1499, 1000..1499)),
                (page_request(None), page(1500, 0..1000)),
                (after(1000), page(1500, 1000..1500)),
            ]
        ),
        Ok(revoked(0..1500))
    );
    // Down, restarted, and the restarted walk below the largest count seen
    // (the restore reply's, or a `status` page's): a count never falls, so
    // unknown.
    assert_eq!(
        walked(
            Some(&restored(2500, 0..1000)),
            vec![
                (after(1000), page(2500, 1000..2000)),
                (after(2000), page(2499, 2000..2499)),
                (page_request(None), page(2499, 0..1000)),
                (after(1000), page(2499, 1000..2000)),
                (after(2000), page(2499, 2000..2499)),
            ]
        ),
        PAGE_MISMATCH
    );
    assert_eq!(
        walked(
            None,
            vec![
                (page_request(None), page(1500, 0..1000)),
                (after(1000), page(1499, 1000..1499)),
                (page_request(None), page(1499, 0..1000)),
                (after(1000), page(1499, 1000..1499)),
            ]
        ),
        PAGE_MISMATCH
    );
    // Restarted, then a second change: unknown, with no second restart.
    assert_eq!(
        walked(
            Some(&restored(2500, 0..1000)),
            vec![
                (after(1000), page(2500, 1000..2000)),
                (after(2000), page(2501, 2000..2501)),
                (page_request(None), page(2501, 0..1000)),
                (after(1000), page(2502, 1000..2000)),
            ]
        ),
        PAGE_MISMATCH
    );
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![
                (after(1000), page(1002, 1000..1002)),
                (page_request(None), page(1002, 0..1000)),
                (after(1000), page(1003, 1000..1003)),
            ]
        ),
        PAGE_MISMATCH
    );
    assert_eq!(
        walked(
            None,
            vec![
                (page_request(None), page(1500, 0..1000)),
                (after(1000), page(1501, 1000..1501)),
                (page_request(None), page(1501, 0..1000)),
                (after(1000), page(1500, 1000..1500)),
            ]
        ),
        PAGE_MISMATCH
    );
}

/// A restarted walk must hold at least the largest count seen in the
/// walk (the restore reply's included) and every ID of the restore
/// reply's list: a restart that reports fewer, or a list without the
/// restore reply's IDs, is unknown, not a shorter success.
#[test]
fn a_restarted_walk_below_the_largest_count_or_without_the_restore_ids_is_unknown() {
    // Restore 1001, a tie at 1002, then a restart that reports 5.
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![
                (after(1000), page(1002, 1000..1002)),
                (page_request(None), page(5, 0..5)),
            ]
        ),
        PAGE_MISMATCH
    );
    // Restore 1001, a tie at 1002, then a restart whose list holds none of
    // the restore reply's IDs.
    let last = revoked(10_000..11_000).pop().unwrap();
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![
                (after(1000), page(1002, 1000..1002)),
                (page_request(None), page(1002, 10_000..11_000)),
                (page_request(Some(&last)), page(1002, 11_000..11_002)),
            ]
        ),
        PAGE_MISMATCH
    );
    // Restore 1001, a tie at 1002, then a restart that holds every ID of
    // the restore reply but only 1001, below the 1002 seen.
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![
                (after(1000), page(1002, 1000..1002)),
                (page_request(None), page(1001, 0..1000)),
                (after(1000), page(1001, 1000..1001)),
            ]
        ),
        PAGE_MISMATCH
    );
    // From `status` alone: 1500, then 1499 (a tie), then a restart that
    // reports 3.
    assert_eq!(
        walked(
            None,
            vec![
                (page_request(None), page(1500, 0..1000)),
                (after(1000), page(1499, 1000..1499)),
                (page_request(None), page(3, 0..3)),
            ]
        ),
        PAGE_MISMATCH
    );
}

/// A `status` that does not report the restore (another state, or no
/// count or page) is unknown; a `status` call that fails ends the walk
/// with its own error (a refusal: `status` changes no row).
#[test]
fn a_status_that_does_not_report_the_restore_ends_the_walk() {
    assert_eq!(
        walked(
            None,
            vec![(page_request(None), status_line("issued", None))]
        ),
        PAGE_MISMATCH
    );
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![(after(1000), status_line("restored", None))]
        ),
        PAGE_MISMATCH
    );
    assert_eq!(
        walked(
            Some(&restored(1001, 0..1000)),
            vec![(
                after(1000),
                status_line("retired", Some((1001, &revoked(1000..1001))))
            )]
        ),
        PAGE_MISMATCH
    );
    for (restored, request, code) in [
        (
            Some(restored(1001, 0..1000)),
            after(1000),
            ErrorCode::AuthUnavailable,
        ),
        (None, page_request(None), ErrorCode::InvalidRequest),
        (None, page_request(None), ErrorCode::ServerError),
    ] {
        let reply = golden(&format!("error_{}", code.as_str()));
        assert_eq!(
            walked(restored.as_ref(), vec![(request, reply)]),
            Err(CallError::Refused(code)),
            "{code:?}"
        );
    }
}

/// The fixture's golden exchange, the bytes the real service sent, through
/// the client's typed calls: each request line is the golden one, each
/// outcome the golden reply's. Then the reconcile verdicts of its `status`
/// replies: before the bootstrap, repeat it; after it, its state matches,
/// enabled; after the restore, committed, and the walk holds the restore
/// reply's complete list without a `status` call, or reads it from
/// `status` alone with the golden `status` request of the operation. (The
/// service is checked against the same lines by
/// `tests/harness/local_transport_wire.rs`.)
#[test]
fn the_golden_exchange_through_the_client_reconciles() {
    let fixture = wire_fixture();
    let requests = list(&fixture, "golden_requests");
    let replies = list(&fixture, "golden_replies");
    let case = |cases: &[Value], name: &str| {
        cases
            .iter()
            .find(|case| text(case, "case") == name)
            .unwrap_or_else(|| panic!("no case {name}"))
            .clone()
    };
    let mut outcomes = Vec::new();
    for step in list(&fixture["exchange"], "steps") {
        let request_case = case(requests, text(step, "request"));
        let request = crate::local_wire::request_of(&request_case);
        let line = text(&request_case, "line").as_bytes().to_vec();
        assert_eq!(request.encode().unwrap().as_bytes(), line);
        let reply = text(&case(replies, text(step, "reply")), "line")
            .as_bytes()
            .to_vec();
        let expected = parse_reply(request.op(), &reply);
        let (outcome, _) = against(&request, PATIENT, move |mut accepted| {
            accepted.read_request();
            accepted.stream.write_all(&reply).unwrap();
        });
        assert_eq!(outcome, expected, "{}", text(step, "request"));
        outcomes.push((request, outcome));
    }
    let [
        (_, Ok(Reply::Status(nothing))),
        (Request::Bootstrap(bootstrap), Ok(Reply::Bootstrapped(_))),
        (Request::Status(asked_key), Ok(Reply::Status(enrolled))),
        _,
        _,
        (Request::Restore(restore), Ok(Reply::Restored(restored))),
        (Request::Status(asked_operation), Ok(Reply::Status(after_restore))),
        ..,
    ] = outcomes.as_slice()
    else {
        panic!("the steps: {outcomes:?}");
    };
    assert_eq!(
        BootstrapVerdict::of(bootstrap, nothing),
        BootstrapVerdict::RepeatBootstrap
    );
    assert!(*asked_key == StatusRequest::reconciling_bootstrap(bootstrap));
    assert_eq!(
        BootstrapVerdict::of(bootstrap, enrolled),
        BootstrapVerdict::Matches { enabled: true }
    );
    assert!(*asked_operation == StatusRequest::reconciling_restore(restore));
    assert_eq!(RestoreVerdict::of(after_restore), RestoreVerdict::Committed);
    // The restore reply's list is complete: no `status` call.
    let (_dir, path, server) = serve_in_order(Vec::new());
    let (client, connects) = counted(&path, PATIENT);
    assert_eq!(
        client.revoked_credential_ids(&restore.operation_id, Some(restored)),
        Ok(restored.revoked_credential_ids.clone())
    );
    server.join().unwrap();
    assert_eq!(connects.load(Ordering::SeqCst), 0);
    // From `status` alone: the golden request and reply of the operation.
    let request = text(&case(requests, "status_operation"), "line")
        .as_bytes()
        .to_vec();
    let reply = text(&case(replies, "status_restored"), "line")
        .as_bytes()
        .to_vec();
    let (_dir, path, server) = serve_in_order(vec![(request, reply)]);
    let (client, connects) = counted(&path, PATIENT);
    assert_eq!(
        client.revoked_credential_ids(&restore.operation_id, None),
        Ok(restored.revoked_credential_ids.clone())
    );
    server.join().unwrap();
    assert_eq!(connects.load(Ordering::SeqCst), 1);
}
