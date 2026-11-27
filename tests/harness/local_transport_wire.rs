//! The deployment-local transport's wire fixture
//! `tests/conformance/fixtures/_wire/local_transport.v1.json` against the
//! service (`skyoauth_service::local_transport`), so that the operator's
//! codec (`skyoauth_operator::local`, which `operator/tests/local_wire`
//! checks against the same file) and the service cannot drift apart. They
//! test the fixture file, not a scenario: no name here matches `a\d\d_`,
//! and no stage of `tests/conformance/scenarios.toml` lists them (layout
//! §3).
//!
//! - the constants and the closed set of codes against the service's
//!   [`MAX_REQUEST_BYTES`], [`ErrorCode::ALL`], the default challenge
//!   TTL and the default time limits, whose sum is the operator client's
//!   default total wait (no server needed);
//! - every golden request line through a real transport whose store is
//!   unreachable: it passes the transport's parsing and value checks, so
//!   it reaches the store and is answered with the golden
//!   `auth_unavailable` line; the same line without its newline, without
//!   any one member, with an unknown member, with any member mistyped, or
//!   with another `op` is the golden `invalid_request` line, before the
//!   store (no database needed);
//! - the golden exchange on a database: the transport with the fixture's
//!   ID seed and clock answers each golden request line with exactly its
//!   golden reply line, byte for byte.
//!
//! The reply encoder of the service is private, so the success shapes and
//! the `conflict` and `not_restorable` lines are pinned through the
//! exchange; `forbidden` and `server_error` only by their codes.

use std::{
    io::{self, Read as _, Write as _},
    os::unix::{fs::PermissionsExt as _, net::UnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Map, Value};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    ids::test_support::SequentialIds,
    local_transport::{ErrorCode, LocalTransport, MAX_REQUEST_BYTES, Settings},
    operation::Clock,
    persistence::PgPool,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::{sync::oneshot, task::JoinHandle};

/// How long the client waits for a reply.
const CLIENT_WAIT: Duration = Duration::from_secs(20);

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/fixtures/_wire/local_transport.v1.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string in {value}"))
}

fn list<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    let list = value[name]
        .as_array()
        .unwrap_or_else(|| panic!("{name} is not an array in {value}"));
    assert!(!list.is_empty(), "{name} is empty");
    list
}

/// The case `name` of the list `cases`.
fn case<'a>(cases: &'a [Value], name: &str) -> &'a Value {
    cases
        .iter()
        .find(|case| text(case, "case") == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

/// The golden refusal line of `code`.
fn refusal_line(fixture: &Value, code: ErrorCode) -> String {
    text(
        case(
            list(fixture, "golden_replies"),
            &format!("error_{}", code.as_str()),
        ),
        "line",
    )
    .to_owned()
}

#[test]
fn local_wire_fixture_constants_are_the_services() {
    let fixture = fixture();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "local_transport_wire");
    assert_eq!(fixture["status"], "proposed");
    assert_eq!(fixture["op_member"], "op");
    assert_eq!(fixture["framing"]["line_end"], "\n");
    assert_eq!(
        fixture["framing"]["max_request_bytes"],
        u64::try_from(MAX_REQUEST_BYTES).unwrap()
    );
    // The client's own cap (the service sets none) holds every golden line.
    let max_reply = fixture["framing"]["max_reply_bytes"].as_u64().unwrap();
    for reply in list(&fixture, "golden_replies") {
        assert!(text(reply, "line").len() as u64 <= max_reply);
    }
    // The closed set, in the service's order.
    let listed: Vec<&str> = list(&fixture, "error_codes")
        .iter()
        .map(|entry| text(entry, "code"))
        .collect();
    let service: Vec<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
    assert_eq!(listed, service);
    // Each code's refusal is `{"error":"<code>"}` and its newline.
    for code in ErrorCode::ALL {
        assert_eq!(
            refusal_line(&fixture, code),
            format!("{{\"error\":\"{}\"}}\n", code.as_str())
        );
    }
    assert_eq!(
        fixture["exchange"]["challenge_ttl_seconds"],
        Settings::default().challenge_ttl.as_secs()
    );
    // The default time limits, and their sum: the operator client's
    // default total wait, which `operator/tests/local_exchange` pins to the
    // same member.
    let limits = &fixture["default_limits"];
    let seconds = |name: &str| Duration::from_secs(limits[name].as_u64().unwrap());
    let settings = Settings::default();
    assert_eq!(seconds("deadline_seconds"), settings.deadline);
    assert_eq!(
        seconds("transaction_timeout_seconds"),
        settings.transaction_timeout
    );
    assert_eq!(seconds("idle_timeout_seconds"), settings.idle_timeout);
    assert_eq!(
        seconds("client_total_wait_seconds"),
        settings.deadline + settings.transaction_timeout + settings.idle_timeout
    );
}

/// A clock that stays at one time.
struct FixedClock(SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// A pool that never connects (port 1), failing fast: a request that
/// reaches the store is answered `auth_unavailable`.
fn unreachable_pool() -> PgPool {
    let options = PgConnectOptions::new().host("127.0.0.1").port(1);
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(300))
        .connect_lazy_with(options)
}

/// A fresh directory under the system's temporary directory, removed when
/// dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "skyoauth-local-wire-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A transport served on its own task, at a socket in its own directory.
struct Server {
    path: PathBuf,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
    _dir: TempDir,
}

impl Server {
    /// Serves a transport on `pool` with the ID seed `seed` and a clock
    /// fixed at `now_micros`.
    async fn start(pool: &PgPool, seed: u64, now_micros: u64) -> Self {
        let dir = TempDir::new();
        let clock = FixedClock(UNIX_EPOCH + Duration::from_micros(now_micros));
        let transport = LocalTransport::new(
            pool.clone(),
            Arc::new(clock),
            Arc::new(SequentialIds::with_seed(seed)),
            None,
        );
        let listener = transport.bind(&dir.0.join("local.sock")).await.unwrap();
        let path = listener.path().to_path_buf();
        let (shutdown, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(listener.serve(async move {
            let _ = stopped.await;
        }));
        Self {
            path,
            shutdown,
            task,
            _dir: dir,
        }
    }

    /// Writes `bytes`, closes the write half, and returns everything the
    /// server sent back until it closed.
    async fn exchange(&self, bytes: Vec<u8>) -> Vec<u8> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || exchange(&path, &bytes))
            .await
            .unwrap()
            .unwrap()
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(30), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

/// Connects, writes `bytes` (a failed write is ignored: the server may
/// close before reading all of them), ends the stream and reads until the
/// server closes.
fn exchange(path: &Path, bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CLIENT_WAIT))?;
    stream.set_write_timeout(Some(CLIENT_WAIT))?;
    if stream.write_all(bytes).is_ok() {
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
    let mut received = Vec::new();
    match stream.read_to_end(&mut received) {
        Ok(_) => Ok(received),
        // The server closed with bytes of the request unread.
        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => Ok(received),
        Err(err) => Err(err),
    }
}

/// The request object of a golden request: `op` and its values.
fn request_object(fixture: &Value, case: &Value) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert(text(fixture, "op_member").to_owned(), case["op"].clone());
    for (name, value) in case["values"].as_object().unwrap() {
        object.insert(name.clone(), value.clone());
    }
    object
}

/// A request line of `object`.
fn line_of(object: &Map<String, Value>) -> Vec<u8> {
    let mut line = serde_json::to_vec(object).unwrap();
    line.push(b'\n');
    line
}

/// Each golden request passes the transport's checks and reaches the
/// (unreachable) store; every variant that drops, adds, retypes or
/// renames a member, or names another `op`, is refused before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn golden_requests_pass_the_transports_checks_and_variants_do_not() {
    let fixture = fixture();
    let unavailable = refusal_line(&fixture, ErrorCode::AuthUnavailable).into_bytes();
    let invalid = refusal_line(&fixture, ErrorCode::InvalidRequest).into_bytes();
    let server = Server::start(&unreachable_pool(), 1, 1_790_000_000_000_000).await;
    let ops = fixture["ops"].as_object().unwrap();
    let mut refused = 0;
    for case in list(&fixture, "golden_requests") {
        let name = text(case, "case");
        let op = text(case, "op");
        let line = text(case, "line").as_bytes().to_vec();
        // The golden line is the request object, members as the fixture
        // lists them for the op.
        let members: Vec<&str> = list(&fixture["ops"], op)
            .iter()
            .map(|member| member.as_str().unwrap())
            .collect();
        let object = request_object(&fixture, case);
        let mut names: Vec<&str> = object.keys().map(String::as_str).collect();
        names.sort_unstable();
        let mut expected = members.clone();
        expected.push(text(&fixture, "op_member"));
        expected.sort_unstable();
        assert_eq!(names, expected, "{name}");
        let parsed: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(parsed, Value::Object(object.clone()), "{name}");
        assert_eq!(server.exchange(line.clone()).await, unavailable, "{name}");

        let mut variants: Vec<(String, Vec<u8>)> = Vec::new();
        variants.push(("no newline".into(), line[..line.len() - 1].to_vec()));
        for member in &members {
            let mut without = object.clone();
            without.remove(*member);
            variants.push((format!("without {member}"), line_of(&without)));
            let mut retyped = object.clone();
            retyped.insert((*member).to_owned(), Value::from(1));
            variants.push((format!("{member} as an integer"), line_of(&retyped)));
            let mut renamed = without.clone();
            renamed.insert(member.to_uppercase(), object[*member].clone());
            variants.push((format!("{member} renamed"), line_of(&renamed)));
        }
        let mut extra = object.clone();
        extra.insert("extra".into(), Value::from("x"));
        variants.push(("an unknown member".into(), line_of(&extra)));
        for other in ops.keys().filter(|other| *other != op) {
            // Another op's name over this op's members (preview and
            // restore share theirs, so skip that pair).
            if names_of(&ops[other.as_str()]) == names_of(&ops[op]) {
                continue;
            }
            let mut renamed = object.clone();
            renamed.insert("op".into(), Value::from(other.as_str()));
            variants.push((format!("op {other}"), line_of(&renamed)));
        }
        let mut upper = object.clone();
        upper.insert("op".into(), Value::from(op.to_uppercase()));
        variants.push(("op in upper case".into(), line_of(&upper)));
        for (variant, bytes) in variants {
            assert_eq!(
                String::from_utf8(server.exchange(bytes).await).unwrap(),
                String::from_utf8(invalid.clone()).unwrap(),
                "{name}: {variant}"
            );
            refused += 1;
        }
    }
    assert!(refused > 30, "{refused}");
    server.stop().await;
}

fn names_of(members: &Value) -> Vec<&str> {
    members
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member.as_str().unwrap())
        .collect()
}

/// The golden exchange on a fresh database: each golden request line, in
/// the fixture's order, is answered with exactly its golden reply line,
/// by a transport with the fixture's ID seed and clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_golden_exchange_is_the_services() {
    let fixture = fixture();
    let exchange = &fixture["exchange"];
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let server = Server::start(
        &pool,
        exchange["id_seed"].as_u64().unwrap(),
        exchange["now_micros"].as_u64().unwrap(),
    )
    .await;
    let requests = list(&fixture, "golden_requests");
    let replies = list(&fixture, "golden_replies");
    for step in list(exchange, "steps") {
        let request = text(case(requests, text(step, "request")), "line");
        let reply = text(case(replies, text(step, "reply")), "line");
        let received = server.exchange(request.as_bytes().to_vec()).await;
        assert_eq!(String::from_utf8(received).unwrap(), reply, "{step}");
    }
    server.stop().await;
    db.drop([pool]).await;
}
