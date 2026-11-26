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
//!   refusal, and these two after a `preview`, are refused;
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
//! ([`TEST_WAIT`]); no test polls: a fake server that must outlast the
//! call blocks until the call has returned. What only Linux does is
//! checked on Linux alone: the kind of a lost connection, a reset when a
//! server closes with bytes unread (macOS reads the end of the stream
//! instead), and a queued connection still readable after its client has
//! gone.

use std::{
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{MetadataExt as _, PermissionsExt as _},
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
        BootstrapRequest, CallError, Connector, DEFAULT_IDLE_WAIT, DEFAULT_TOTAL_WAIT, ErrorCode,
        HalfClose, IssueChallengeRequest, Issued, LocalClient, MAX_REPLY_BYTES, MAX_REQUEST_BYTES,
        NotSent, Op, Reply, Request, ResponseRequest, Retry, SocketPath, Timeouts, UnknownOutcome,
        parse_reply,
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

/// A fresh directory under the system's temporary directory, removed when
/// dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "skyoauth-operator-exchange-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
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
        let (stream, _) = listener.accept().unwrap();
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
/// `issue_challenge`, `restore`), and refusals after a `preview`; every
/// other code is a refusal after every operation.
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
        assert_eq!(
            refused(Op::Preview, code),
            Err(CallError::Refused(code)),
            "{code:?}"
        );
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
            let (mut stream, _) = listener.accept().unwrap();
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
    assert!(took >= timeouts.total, "{took:?}");
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
    assert!(took >= timeouts.idle, "{took:?}");
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
    assert!(took >= timeouts.total && took < TEST_WAIT / 2, "{took:?}");
    assert_eq!(connects.load(Ordering::SeqCst), 1);
    // The queued connection holds the whole request line, then its end. On
    // Linux only: by now the call's thread may have dropped its end, and
    // macOS then refuses the options of the queued socket (`EINVAL`), and
    // may refuse its accept.
    if cfg!(target_os = "linux") {
        let (mut queued, _) = listener.accept().unwrap();
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
    // Through the default connector too.
    let client = LocalClient::new(dir.join("missing"), Timeouts::default());
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
        assert_eq!(
            call(&client, &request(op)),
            Err(CallError::Unknown(UnknownOutcome::TimedOut)),
            "{op:?}"
        );
    }
}

/// What a [`Scripted`] stream saw: the bytes written to it, how many bytes
/// were read from it, and whether it was flushed and its write half ended
/// (asked to, failing or not).
#[derive(Debug, Default, Clone)]
struct Seen {
    written: Vec<u8>,
    read: usize,
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
        Ok(read)
    }
}

impl io::Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        thread::sleep(self.plan.write_delay);
        let taken = buf.len().min(self.plan.per_write);
        self.seen
            .lock()
            .unwrap()
            .written
            .extend_from_slice(&buf[..taken]);
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

    fn set_read_wait(&mut self, _: Option<Duration>) -> io::Result<()> {
        fail(self.plan.read_waits)
    }

    fn set_write_wait(&mut self, _: Option<Duration>) -> io::Result<()> {
        let this = self.write_waits_set;
        self.write_waits_set += 1;
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
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (gone, dropped) = mpsc::channel();
    let script = Script {
        plan,
        seen: Arc::clone(&seen),
        gone: Mutex::new(Some(gone)),
    };
    let outcome = call(&LocalClient::with_connector(script, timeouts), &request(op));
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
    assert!(took >= timeouts.total && took < TEST_WAIT / 2, "{took:?}");
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
    let client = LocalClient::new("/nonexistent", Timeouts::default());
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
    let client = LocalClient::new(dir.join("SENTINEL-PATH"), Timeouts::default());
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
