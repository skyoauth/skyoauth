//! The deployment-local bootstrap and recovery transport
//! (`crate::local_transport`; T13.4, T13.5, T13.6; OQ-TM-9) over a real
//! Unix socket in a temporary directory:
//!
//! - the socket file: owned by the service UID with mode 0600, no private
//!   directory left behind (a leftover one is cleaned), removed on
//!   shutdown, its lock file kept; another service UID (root only); an
//!   unsafe parent directory refuses to start; a path held by a file, a
//!   directory, a symbolic link, another UID's socket or a live listener
//!   refuses to start, and a stale socket of the service UID is replaced;
//!   simultaneous binds and an overlapping restart, serialized by the lock
//!   file; paths up to 107 bytes, 108 refused;
//! - the peer check: the process's own UID passes; another UID, run as a
//!   real second user through `runuser` and `python3`, is `forbidden`
//!   (before any read) when the service UID is a third one and passes when
//!   it is the service UID (only with `SKYOAUTH_IT_PEER_USER`, see
//!   [`a_peer_of_another_uid_is_refused`]);
//! - the protocol: one line and the end of the stream, however the bytes
//!   arrive; the 64 KiB limit, exactly; the idle timeout and the deadline
//!   close a silent or slow client without a response, and a silent client
//!   delays no other; connections past the limit wait; malformed, non-object
//!   and unknown-member requests are `invalid_request` before the store;
//! - the operations, on a database (`#[ignore]`d, `SKYOAUTH_IT_DATABASE_URL`,
//!   see `common/mod.rs`): bootstrap and its closure, durable across a new
//!   transport; concurrent bootstraps on two transports with exactly one
//!   winner; issue, preview, restore and a refused replay; an issue for a
//!   registered key; the trust anchor check against the database's; a
//!   wrong signature, an expired challenge, a missing store, a failed audit
//!   append, an ID generator failure and an unframed request, each writing
//!   nothing; a database whose default isolation is `SERIALIZABLE`;
//!   requests serialized per transport; the deadline covering the wait for
//!   a connection but not a transaction.
//!
//! The tests sign with fixed test keys, as `registry_recovery.rs` does, and
//! check `M` as the workstation would. No test name here may match the
//! scenario pattern `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`.

#![cfg(unix)]

mod common;

use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::{UnixListener as StdListener, UnixStream as StdStream},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use skyoauth_service::{
    identity::canonical_public_identity,
    ids::{IdGenerator, IdKind, test_support::SequentialIds},
    local_transport::{BindError, LocalListener, LocalTransport, MAX_REQUEST_BYTES, Settings},
    operation::Clock,
    persistence::{
        self, PgPool,
        registry::{
            AdminRole, ChainVerdict, OperatorRequest, OperatorScope, authorize_operator,
            get_recovery_state, verify_audit_chain,
        },
    },
};
use sqlx::{
    AssertSqlSafe, Connection, PgConnection,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tokio::{sync::oneshot, task::JoinHandle};

const INSTANCE: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
/// The seed of the bootstrap recovery key, a test key.
const SEED: [u8; 32] = [0x51; 32];
/// The seed of the key a restore rotates to.
const NEW_SEED: [u8; 32] = [0x52; 32];
/// The seed of a key that is never enrolled.
const THIRD_SEED: [u8; 32] = [0x53; 32];
/// The prefix of `M` (the recovery module, "What is signed").
const CHALLENGE_PREFIX: &str = "skyoauth.recovery_challenge.v1\n";
const ANCHOR: &str = "deployment/operator-ca";
/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo`.
const ED25519_SPKI_PREFIX: &str = "302a300506032b6570032100";
/// The client's wait for a response.
const CLIENT_WAIT: Duration = Duration::from_secs(20);
const T0: Duration = Duration::from_secs(1_790_000_000);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    SigningKey::from_bytes(seed)
        .sign(message)
        .to_bytes()
        .to_vec()
}

/// The hex DER `SubjectPublicKeyInfo` of the operator key numbered `n`
/// (an Ed25519 key of 32 bytes `n`: only its DER framing is checked).
fn spki(n: u8) -> String {
    format!("{ED25519_SPKI_PREFIX}{}", hex(&[n; 32]))
}

fn identity_of(n: u8) -> String {
    canonical_public_identity(&unhex(&spki(n))).unwrap()
}

/// A clock the tests move.
struct TestClock(Mutex<SystemTime>);

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(UNIX_EPOCH + T0)))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

/// The process's effective UID: the owner of a file it creates.
fn effective_uid(dir: &Path) -> u32 {
    let probe = dir.join("uid-probe");
    fs::write(&probe, b"").unwrap();
    let uid = fs::metadata(&probe).unwrap().uid();
    fs::remove_file(&probe).unwrap();
    uid
}

/// A fresh directory under the system's temporary directory, mode 0755 so
/// that another UID can reach a socket in it, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = env::temp_dir().join(format!(
            "skyoauth-local-transport-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }

    fn socket(&self) -> PathBuf {
        self.0.join("local.sock")
    }

    /// The names in the directory.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A pool that never connects (port 1), failing fast: the tests that use
/// it must not reach the store, or see `auth_unavailable` when they do.
fn unreachable_pool() -> PgPool {
    let options = PgConnectOptions::new().host("127.0.0.1").port(1);
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(300))
        .connect_lazy_with(options)
}

fn transport(pool: &PgPool, clock: Arc<TestClock>, seed: u64, uid: Option<u32>) -> LocalTransport {
    LocalTransport::new(
        pool.clone(),
        clock,
        Arc::new(SequentialIds::with_seed(seed)),
        uid,
    )
}

/// A transport being served on its own task.
struct Server {
    path: PathBuf,
    service_uid: u32,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Server {
    fn start(listener: LocalListener) -> Self {
        let path = listener.path().to_path_buf();
        let service_uid = listener.service_uid();
        let (shutdown, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(listener.serve(async move {
            let _ = stopped.await;
        }));
        Self {
            path,
            service_uid,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    async fn bind(transport: LocalTransport, path: &Path) -> Self {
        Self::start(transport.bind(path).await.unwrap())
    }

    async fn stop(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(30), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }

    /// Sends `bytes` and returns everything the server sent back.
    async fn raw(&self, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || exchange(&path, &bytes, false))
            .await
            .unwrap()
    }

    /// Sends `request` as one line and returns the response object.
    async fn call(&self, request: Value) -> Value {
        let mut line = serde_json::to_vec(&request).unwrap();
        line.push(b'\n');
        parse_reply(&self.raw(line).await.unwrap())
    }
}

/// Connects, writes `bytes` (a failed write is ignored: the server may
/// close before reading all of them), ends the stream unless `keep_open`,
/// and reads until the server closes.
fn exchange(path: &Path, bytes: &[u8], keep_open: bool) -> io::Result<Vec<u8>> {
    let mut stream = StdStream::connect(path)?;
    stream.set_read_timeout(Some(CLIENT_WAIT))?;
    stream.set_write_timeout(Some(CLIENT_WAIT))?;
    if stream.write_all(bytes).is_ok() && !keep_open {
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
    let mut received = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(received),
            Ok(read) => received.extend_from_slice(&chunk[..read]),
            // The server closed with bytes of the request unread.
            Err(err) if err.kind() == io::ErrorKind::ConnectionReset => return Ok(received),
            Err(err) => return Err(err),
        }
    }
}

/// One response line: the JSON object and its newline, nothing else.
fn parse_reply(bytes: &[u8]) -> Value {
    let text = std::str::from_utf8(bytes).unwrap();
    let body = text
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("no newline: {text:?}"));
    assert!(!body.contains('\n'), "{text:?}");
    serde_json::from_str(body).unwrap()
}

fn error(code: &str) -> Value {
    json!({ "error": code })
}

fn bootstrap_request(credential: u8, recovery_key: &[u8]) -> Value {
    json!({
        "op": "bootstrap",
        "instance_id": INSTANCE,
        "credential_spki": spki(credential),
        "trust_anchor_ref": ANCHOR,
        "recovery_public_key": hex(recovery_key),
    })
}

fn issue_request(credential: u8, new_key: &[u8]) -> Value {
    json!({
        "op": "issue_challenge",
        "credential_spki": spki(credential),
        "trust_anchor_ref": ANCHOR,
        "new_recovery_public_key": hex(new_key),
    })
}

fn signed(op: &str, operation_id: &str, signature: &[u8]) -> Value {
    json!({ "op": op, "operation_id": operation_id, "signature": hex(signature) })
}

/// The settings of the tests that do not test the limits.
fn settings() -> Settings {
    Settings {
        idle_timeout: Duration::from_secs(10),
        deadline: Duration::from_secs(30),
        statement_timeout: Duration::from_secs(10),
        ..Settings::default()
    }
}

// ---------------------------------------------------------------------------
// The socket file

#[tokio::test]
async fn the_socket_is_owned_by_the_service_uid_with_mode_0600() {
    let dir = TempDir::new();
    let uid = effective_uid(&dir.0);
    let path = dir.socket();
    // A private directory a killed bind left behind: removed under the lock.
    let leftover = dir.0.join(".local.sock.4194305.0.bind");
    fs::create_dir(&leftover).unwrap();
    fs::write(leftover.join("s"), b"").unwrap();
    let listener = transport(&unreachable_pool(), TestClock::new(), 1, None)
        .bind(&path)
        .await
        .unwrap();
    assert_eq!(listener.service_uid(), uid);
    assert_eq!(listener.path(), path);
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1, "the private directory's link is gone");
    // The socket and its lock file: the private directories are removed.
    assert_eq!(dir.entries(), ["local.sock", "local.sock.lock"]);
    let lock = fs::symlink_metadata(dir.0.join("local.sock.lock")).unwrap();
    assert!(lock.is_file());
    assert_eq!((lock.uid(), lock.mode() & 0o7777), (uid, 0o600));

    let server = Server::start(listener);
    // The process's own UID passes the peer check.
    assert_eq!(
        server.call(json!({"op": "nothing"})).await,
        error("invalid_request")
    );
    server.stop().await;
    // The lock file stays (see the module docs, "The socket file").
    assert_eq!(dir.entries(), ["local.sock.lock"]);

    // Dropped without serving, the listener removes its socket too.
    let listener = transport(&unreachable_pool(), TestClock::new(), 1, None)
        .bind(&path)
        .await
        .unwrap();
    drop(listener);
    assert_eq!(dir.entries(), ["local.sock.lock"]);

    // A path that is no longer its socket is left alone.
    let listener = transport(&unreachable_pool(), TestClock::new(), 1, None)
        .bind(&path)
        .await
        .unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replaced").unwrap();
    drop(listener);
    assert_eq!(fs::read(&path).unwrap(), b"replaced");
}

/// The UID of the local user `name`.
fn uid_of(name: &str) -> u32 {
    let output = Command::new("id").args(["-u", name]).output().unwrap();
    assert!(output.status.success(), "id -u {name}: {output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Another service UID: as root the socket and its lock file are given to
/// it; otherwise the socket's directory, the process's own, is not the
/// service UID's or root's, and nothing is created.
#[tokio::test]
async fn another_service_uid_needs_the_privilege_to_give_the_socket_away() {
    let dir = TempDir::new();
    let uid = effective_uid(&dir.0);
    let other = if uid == 0 { 65_534 } else { uid + 1 };
    let result = transport(&unreachable_pool(), TestClock::new(), 1, Some(other))
        .bind(&dir.socket())
        .await;
    if uid == 0 {
        let listener = result.unwrap();
        assert_eq!(listener.service_uid(), other);
        let metadata = fs::symlink_metadata(dir.socket()).unwrap();
        assert_eq!(metadata.uid(), other);
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        let lock = fs::symlink_metadata(dir.0.join("local.sock.lock")).unwrap();
        assert_eq!((lock.uid(), lock.mode() & 0o7777), (other, 0o600));
        drop(listener);
        assert_eq!(dir.entries(), ["local.sock.lock"]);
    } else {
        assert!(
            matches!(&result, Err(BindError::UnsafeDirectory)),
            "{result:?}"
        );
        assert!(dir.entries().is_empty(), "{:?}", dir.entries());
    }
}

/// The socket's directory: owned by the service UID or root, not a
/// symbolic link, and not writable by group or others unless sticky.
#[tokio::test]
async fn the_socket_directory_must_be_safe() {
    let dir = TempDir::new();
    let bind = |path: PathBuf| async move {
        transport(&unreachable_pool(), TestClock::new(), 1, None)
            .bind(&path)
            .await
    };
    let sub = dir.0.join("sub");
    fs::create_dir(&sub).unwrap();
    for mode in [0o775, 0o757, 0o777, 0o722] {
        fs::set_permissions(&sub, fs::Permissions::from_mode(mode)).unwrap();
        let result = bind(sub.join("a.sock")).await;
        assert!(
            matches!(result, Err(BindError::UnsafeDirectory)),
            "{mode:o}: {result:?}"
        );
        assert_eq!(fs::read_dir(&sub).unwrap().count(), 0, "{mode:o}");
    }
    for mode in [0o1777, 0o755, 0o700, 0o1775] {
        fs::set_permissions(&sub, fs::Permissions::from_mode(mode)).unwrap();
        drop(bind(sub.join("a.sock")).await.unwrap());
    }
    // A symbolic link as the directory.
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&sub, &link).unwrap();
    let result = bind(link.join("b.sock")).await;
    // `link/b.sock`'s parent is `link`, a symbolic link.
    assert!(
        matches!(result, Err(BindError::UnsafeDirectory)),
        "{result:?}"
    );
    assert!(!sub.join("b.sock.lock").exists());
    // Another owner (root only: the owner of a directory can be changed by
    // root alone).
    if effective_uid(&dir.0) == 0 {
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::lchown(&sub, Some(65_534), None).unwrap();
        let result = bind(sub.join("c.sock")).await;
        assert!(
            matches!(result, Err(BindError::UnsafeDirectory)),
            "{result:?}"
        );
    }
}

#[tokio::test]
async fn an_occupied_socket_path_refuses_to_start() {
    let dir = TempDir::new();
    let path = dir.socket();
    let bind = || {
        let path = path.clone();
        async move {
            transport(&unreachable_pool(), TestClock::new(), 1, None)
                .bind(&path)
                .await
        }
    };

    // A regular file, a directory, a symbolic link (to nothing, and to a
    // socket): left in place.
    fs::write(&path, b"data").unwrap();
    assert!(matches!(bind().await, Err(BindError::PathOccupied)));
    assert_eq!(fs::read(&path).unwrap(), b"data");
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(bind().await, Err(BindError::PathOccupied)));
    assert!(path.is_dir());
    fs::remove_dir(&path).unwrap();
    std::os::unix::fs::symlink(dir.0.join("nowhere"), &path).unwrap();
    assert!(matches!(bind().await, Err(BindError::PathOccupied)));
    let elsewhere = dir.0.join("elsewhere.sock");
    drop(StdListener::bind(&elsewhere).unwrap());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
    assert!(matches!(bind().await, Err(BindError::PathOccupied)));
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    fs::remove_file(&path).unwrap();
    fs::remove_file(&elsewhere).unwrap();

    // A live listener of the service UID that takes no lock file: in use,
    // left in place.
    let live = StdListener::bind(&path).unwrap();
    assert!(matches!(bind().await, Err(BindError::InUse)));
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    drop(live);

    // The same socket, now stale, owned by another UID (root only):
    // occupied, left in place.
    let stale = fs::symlink_metadata(&path).unwrap();
    assert!(stale.file_type().is_socket());
    if effective_uid(&dir.0) == 0 {
        std::os::unix::fs::lchown(&path, Some(65_534), None).unwrap();
        assert!(matches!(bind().await, Err(BindError::PathOccupied)));
        assert_eq!(fs::symlink_metadata(&path).unwrap().uid(), 65_534);
        std::os::unix::fs::lchown(&path, Some(0), None).unwrap();
    }

    // Stale and the service UID's: replaced.
    let listener = bind().await.unwrap();
    // (The inode number may be reused: the mode and a live listener show
    // the replacement.)
    assert_ne!(stale.mode() & 0o7777, 0o600);
    let bound = fs::symlink_metadata(&path).unwrap();
    assert_eq!(bound.mode() & 0o7777, 0o600);
    drop(StdStream::connect(&path).unwrap());
    // No private directory left by the refusals.
    assert_eq!(dir.entries(), ["local.sock", "local.sock.lock"]);
    // A second transport on the same path: in use (the lock).
    assert!(matches!(bind().await, Err(BindError::InUse)));
    drop(listener);
    assert_eq!(dir.entries(), ["local.sock.lock"]);

    // A lock path that is not a 0600 regular file of the service UID:
    // occupied, left in place, and nothing is bound.
    let lock = dir.0.join("local.sock.lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(bind().await, Err(BindError::PathOccupied)));
    assert_eq!(fs::symlink_metadata(&lock).unwrap().mode() & 0o7777, 0o644);
    fs::remove_file(&lock).unwrap();
    fs::create_dir(&lock).unwrap();
    assert!(matches!(bind().await, Err(BindError::PathOccupied)));
    fs::remove_dir(&lock).unwrap();
    let target = dir.0.join("target");
    fs::write(&target, b"").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, &lock).unwrap();
    assert!(matches!(bind().await, Err(BindError::PathOccupied)));
    assert!(
        fs::symlink_metadata(&lock)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!path.exists());
}

/// Binds of one stale path started together: exactly one wins, every other
/// is `InUse` (the lock file), and the winner's socket stays in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_binds_have_exactly_one_winner() {
    let dir = TempDir::new();
    let path = dir.socket();
    for round in 0..20 {
        drop(StdListener::bind(&path).unwrap());
        let start = Arc::new(tokio::sync::Barrier::new(8));
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let start = Arc::clone(&start);
                let path = path.clone();
                tokio::spawn(async move {
                    start.wait().await;
                    transport(&unreachable_pool(), TestClock::new(), 1, None)
                        .bind(&path)
                        .await
                })
            })
            .collect();
        let mut winners = Vec::new();
        for attempt in attempts {
            match attempt.await.unwrap() {
                Ok(listener) => winners.push(listener),
                Err(BindError::InUse) => {}
                Err(err) => panic!("round {round}: {err:?}"),
            }
        }
        assert_eq!(winners.len(), 1, "round {round}");
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600, "round {round}");
        drop(StdStream::connect(&path).unwrap());
        drop(winners);
        assert!(!path.exists(), "round {round}");
    }
}

/// A new transport started while the old one shuts down: it is `InUse`
/// until the old one has removed its socket, then binds, and its socket is
/// never removed by the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_overlapping_restart_keeps_the_new_socket() {
    let dir = TempDir::new();
    let path = dir.socket();
    let mut old = transport(&unreachable_pool(), TestClock::new(), 1, None)
        .bind(&path)
        .await
        .unwrap();
    for round in 0..20 {
        let dropping = tokio::task::spawn_blocking(move || drop(old));
        let started = Instant::now();
        let new = loop {
            match transport(&unreachable_pool(), TestClock::new(), 1, None)
                .bind(&path)
                .await
            {
                Ok(listener) => break listener,
                Err(BindError::InUse) => {
                    assert!(started.elapsed() < Duration::from_secs(10), "round {round}");
                    tokio::task::yield_now().await;
                }
                Err(err) => panic!("round {round}: {err:?}"),
            }
        };
        dropping.await.unwrap();
        // The old transport is gone; the new socket is in place and live.
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket(), "round {round}");
        drop(StdStream::connect(&path).unwrap());
        old = new;
    }
    drop(old);
    assert!(!path.exists());
}

/// A socket path that fits a Unix socket address works whatever its length
/// (the socket is bound through the private directory's descriptor, not at
/// a longer staging path); one that does not fit is `PathTooLong`.
#[tokio::test]
async fn a_socket_path_up_to_107_bytes_works() {
    let dir = TempDir::new();
    let base = dir.0.as_os_str().len() + 1;
    let path_of = |length: usize| {
        assert!(length > base + 8, "the temporary directory is too long");
        dir.0.join("p".repeat(length - base))
    };
    for length in [90, 100, 107] {
        let path = path_of(length);
        assert_eq!(path.as_os_str().len(), length);
        let server = Server::bind(
            transport(&unreachable_pool(), TestClock::new(), 1, None),
            &path,
        )
        .await;
        assert_eq!(
            server.call(json!({"op": "nothing"})).await,
            error("invalid_request"),
            "{length}"
        );
        server.stop().await;
        assert!(!path.exists());
    }
    let path = path_of(108);
    let result = transport(&unreachable_pool(), TestClock::new(), 1, None)
        .bind(&path)
        .await;
    assert!(matches!(result, Err(BindError::PathTooLong)), "{result:?}");
    assert_eq!(
        result.unwrap_err().to_string(),
        "the local socket path is too long for a Unix socket address (108 bytes on Linux, \
         104 on the BSDs and macOS, its terminating NUL included)"
    );
    // Nothing was created for it.
    let mut lock = path.into_os_string();
    lock.push(".lock");
    assert!(!Path::new(&lock).exists());
}

// ---------------------------------------------------------------------------
// The peer check

/// The variable that names a local user for the cross-UID peer test.
const PEER_USER_VAR: &str = "SKYOAUTH_IT_PEER_USER";

/// A client run as `user` (through `runuser` and `python3`): connects to
/// `path`, sends `line` and closes its write half (or, for `None`, sends
/// nothing and keeps the connection open), and prints what it receives, or
/// `connect-error <errno>`.
fn client_as(user: &str, path: &Path, line: Option<&str>) -> String {
    const CLIENT: &str = "import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print('connect-error', e.errno)
    sys.exit(0)
if sys.argv[2] == 'send':
    try:
        s.sendall(sys.argv[3].encode() + b'\\n')
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass
s.settimeout(20)
data = b''
while True:
    try:
        chunk = s.recv(4096)
    except ConnectionResetError:
        break
    if not chunk:
        break
    data += chunk
sys.stdout.write(data.decode())
";
    let mut command = Command::new("runuser");
    command
        .args(["-u", user, "--", "python3", "-I", "-c", CLIENT])
        .arg(path);
    match line {
        Some(line) => command.args(["send", line]),
        None => command.args(["silent", ""]),
    };
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// A peer whose UID is neither the service UID nor root is `forbidden`,
/// also once the socket's mode lets it connect, and at once, before any
/// read (a refused peer that sends nothing is answered well within the idle
/// timeout); with the service UID set to the peer's, it passes the check.
///
/// It needs a second local user and root (to run a client as that user
/// and to give the socket to another UID): set `SKYOAUTH_IT_PEER_USER` to
/// the user's name, and have `runuser` and `python3`. Without the variable
/// only the process's own UID is checked (by
/// `the_socket_is_owned_by_the_service_uid_with_mode_0600`, and, when the
/// tests do not run as root, by the unit test
/// `local_transport::connection::tests::a_refused_peer_is_answered_before_any_read`),
/// and this test prints a notice on stderr and passes; with it, a missing
/// prerequisite fails the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_of_another_uid_is_refused() {
    let Ok(user) = env::var(PEER_USER_VAR) else {
        eprintln!(
            "NOTICE: {PEER_USER_VAR} is not set: the cross-UID peer check was NOT run \
             (it needs root and a second local user; set {PEER_USER_VAR}=<user> to run it)"
        );
        return;
    };
    let dir = TempDir::new();
    assert_eq!(effective_uid(&dir.0), 0, "{PEER_USER_VAR} needs root");
    let peer = uid_of(&user);
    assert_ne!(peer, 0);
    let third = if peer == 65_534 { 65_533 } else { 65_534 };
    let malformed = r#"{"op":"nothing"}"#;

    // The service UID is a third UID: the file mode stops the peer at
    // `connect`; loosened, the peer check refuses it, before any read.
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, Some(third))
            .with_settings(Settings {
                idle_timeout: Duration::from_secs(10),
                ..settings()
            })
            .unwrap(),
        &dir.0.join("third.sock"),
    )
    .await;
    assert_eq!(server.service_uid, third);
    assert_eq!(
        client_as(&user, &server.path, Some(malformed)),
        "connect-error 13\n"
    );
    fs::set_permissions(&server.path, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        client_as(&user, &server.path, Some(malformed)),
        "{\"error\":\"forbidden\"}\n"
    );
    let started = Instant::now();
    assert_eq!(
        client_as(&user, &server.path, None),
        "{\"error\":\"forbidden\"}\n"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // Root passes whatever the service UID.
    assert_eq!(
        server.call(serde_json::from_str(malformed).unwrap()).await,
        error("invalid_request")
    );
    server.stop().await;

    // The service UID is the peer's: the socket is its, mode 0600, and the
    // peer passes the check (its malformed request is answered as such).
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, Some(peer)),
        &dir.0.join("peer.sock"),
    )
    .await;
    let metadata = fs::symlink_metadata(&server.path).unwrap();
    assert_eq!((metadata.uid(), metadata.mode() & 0o7777), (peer, 0o600));
    assert_eq!(
        client_as(&user, &server.path, Some(malformed)),
        "{\"error\":\"invalid_request\"}\n"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// The protocol

/// A valid `restore` request padded with leading spaces to `length` bytes,
/// its newline included.
fn padded_restore(length: usize) -> Vec<u8> {
    let request = format!(
        r#"{{"op":"restore","operation_id":"oper_1","signature":"{}"}}"#,
        hex(&[0; 64])
    );
    let mut line = vec![b' '; length - request.len() - 1];
    line.extend_from_slice(request.as_bytes());
    line.push(b'\n');
    line
}

/// A request line of exactly 64 KiB reaches the store (here, an
/// unreachable one: `auth_unavailable`); one byte more is `invalid_request`
/// before the store, as is a line that never ends.
#[tokio::test]
async fn the_request_size_limit_is_64_kib() {
    assert_eq!(MAX_REQUEST_BYTES, 65_536);
    let dir = TempDir::new();
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, None),
        &dir.socket(),
    )
    .await;
    let at_limit = padded_restore(MAX_REQUEST_BYTES);
    assert_eq!(at_limit.len(), MAX_REQUEST_BYTES);
    assert_eq!(
        parse_reply(&server.raw(at_limit).await.unwrap()),
        error("auth_unavailable")
    );
    for line in [
        padded_restore(MAX_REQUEST_BYTES + 1),
        vec![b' '; 4 * MAX_REQUEST_BYTES],
    ] {
        assert_eq!(
            parse_reply(&server.raw(line).await.unwrap()),
            error("invalid_request")
        );
    }
    server.stop().await;
}

/// A client that sends nothing is cut off after the idle timeout, one that
/// keeps sending without finishing a line after the deadline, both without
/// a response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_or_slow_client_is_closed_without_a_response() {
    let dir = TempDir::new();
    let limits = Settings {
        idle_timeout: Duration::from_millis(300),
        deadline: Duration::from_millis(1_500),
        statement_timeout: Duration::from_secs(1),
        ..settings()
    };
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, None)
            .with_settings(limits)
            .unwrap(),
        &dir.socket(),
    )
    .await;
    let path = server.path.clone();
    let (silent, slow) = tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let silent = exchange(&path, b"", true).unwrap();
        let silent = (silent, start.elapsed());
        let mut stream = StdStream::connect(&path).unwrap();
        stream.set_read_timeout(Some(CLIENT_WAIT)).unwrap();
        let start = Instant::now();
        let writer = stream.try_clone().unwrap();
        let drip = std::thread::spawn(move || {
            let mut writer = writer;
            // A byte every 100 ms, never a newline, for up to 10 s.
            for _ in 0..100 {
                if writer.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let mut received = Vec::new();
        let result = stream.read_to_end(&mut received);
        let elapsed = start.elapsed();
        drop(stream);
        drip.join().unwrap();
        (silent, (result.map(|_| received), elapsed))
    })
    .await
    .unwrap();
    assert_eq!(silent.0, b"");
    assert!(
        // Before the deadline: the idle timeout closed it.
        silent.1 >= Duration::from_millis(250) && silent.1 < Duration::from_millis(1_200),
        "{:?}",
        silent.1
    );
    let (received, elapsed) = slow;
    assert!(
        matches!(&received, Ok(bytes) if bytes.is_empty())
            || matches!(&received, Err(err) if err.kind() == io::ErrorKind::ConnectionReset),
        "{received:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(1_400) && elapsed < Duration::from_secs(5),
        "{elapsed:?}"
    );
    server.stop().await;
}

/// Malformed requests and values the transport's checks refuse are
/// `invalid_request` before the store is reached (the store here is
/// unreachable: reaching it would be `auth_unavailable`).
#[tokio::test]
async fn malformed_requests_are_refused_before_the_store() {
    let dir = TempDir::new();
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, None),
        &dir.socket(),
    )
    .await;
    let key = hex(&public_key(&SEED));
    let mut weak = [0; 32];
    weak[0] = 1;
    let mut lines: Vec<Vec<u8>> = [
        r#"{}"#.to_owned(),
        r#"{"op":"approve"}"#.to_owned(),
        r#"{"op":"restore","operation_id":"oper_1","signature":"00","extra":1}"#.to_owned(),
        r#"{"op":"restore","operation_id":"oper_1"}"#.to_owned(),
        r#"{"op":"restore","operation_id":"oper_1","signature":"0"}"#.to_owned(),
        r#"{"op":"restore","operation_id":"oper_1","signature":"AB"}"#.to_owned(),
        r#"{"op":"preview","operation_id":"oper\u0000","signature":"00"}"#.to_owned(),
        r#"[1]"#.to_owned(),
        // Positional (array) forms of valid requests, and roots that are not
        // objects: refused before the store.
        r#"["restore","oper_1","00"]"#.to_owned(),
        r#"  ["preview","oper_1","00"]"#.to_owned(),
        format!(
            r#"["bootstrap","{INSTANCE}","{}","{ANCHOR}","{key}"]"#,
            spki(1)
        ),
        r#"null"#.to_owned(),
        r#""restore""#.to_owned(),
        r#"1"#.to_owned(),
        r#"true"#.to_owned(),
    ]
    .map(String::into_bytes)
    .into();
    let mut bootstrap = |change: &dyn Fn(&mut Value)| {
        let mut request = bootstrap_request(1, &public_key(&SEED));
        change(&mut request);
        lines.push(serde_json::to_vec(&request).unwrap());
    };
    bootstrap(&|r| r["instance_id"] = json!("019A9F3C-5B2E-7C41-9D8E-0123456789AB"));
    bootstrap(&|r| r["instance_id"] = json!("019a9f3c-5b2e-4c41-9d8e-0123456789ab"));
    bootstrap(&|r| r["recovery_public_key"] = json!(key.to_uppercase()));
    bootstrap(&|r| r["recovery_public_key"] = json!(hex(&weak)));
    bootstrap(&|r| r["recovery_public_key"] = json!(hex(&[7; 32])));
    bootstrap(&|r| r["recovery_public_key"] = json!(hex(&[0x11; 31])));
    bootstrap(&|r| r["credential_spki"] = json!(identity_of(1)));
    bootstrap(&|r| r["credential_spki"] = json!(hex(b"not der")));
    bootstrap(&|r| r["trust_anchor_ref"] = json!("operator ca"));
    bootstrap(&|r| r["trust_anchor_ref"] = json!(""));
    bootstrap(&|r| r["trust_anchor_ref"] = json!("k".repeat(2049)));
    bootstrap(&|r| r["admin_id"] = json!("adm_chosen"));
    let mut issue = |change: &dyn Fn(&mut Value)| {
        let mut request = issue_request(2, &public_key(&NEW_SEED));
        change(&mut request);
        lines.push(serde_json::to_vec(&request).unwrap());
    };
    issue(&|r| r["new_recovery_public_key"] = json!(hex(&weak)));
    issue(&|r| r["trust_anchor_ref"] = json!("a\tb"));
    issue(&|r| r["trust_anchor_ref"] = json!("a\u{85}b"));
    issue(&|r| r["trust_anchor_ref"] = json!("a\u{9f}"));
    issue(&|r| r["credential_spki"] = json!(""));
    issue(&|r| r["ttl"] = json!(900));
    for mut line in lines {
        line.push(b'\n');
        let text = String::from_utf8_lossy(&line).into_owned();
        assert_eq!(
            parse_reply(&server.raw(line).await.unwrap()),
            error("invalid_request"),
            "{text}"
        );
    }
    for raw in [
        b"\xff\xfe\n".to_vec(),
        b"{\"op\":\"restore\"}\n{}\n".to_vec(),
        b"{\"op\":\"restore\",\"operation_id\":\"o\",\"signature\":\"00\"}".to_vec(),
        b"\n".to_vec(),
    ] {
        assert_eq!(
            parse_reply(&server.raw(raw).await.unwrap()),
            error("invalid_request")
        );
    }
    // The checks pass: the unreachable store answers.
    assert_eq!(
        server.call(bootstrap_request(1, &public_key(&SEED))).await,
        error("auth_unavailable")
    );
    server.stop().await;
}

/// Sends `pieces` with `pause` between them, then closes the write half
/// unless `keep_open`, and returns what the server sent back and when its
/// connection ended.
fn exchange_in_pieces(
    path: &Path,
    pieces: &[&[u8]],
    pause: Duration,
    keep_open: bool,
) -> (Vec<u8>, Duration) {
    let start = Instant::now();
    let mut stream = StdStream::connect(path).unwrap();
    stream.set_read_timeout(Some(CLIENT_WAIT)).unwrap();
    for (at, piece) in pieces.iter().enumerate() {
        if at > 0 {
            std::thread::sleep(pause);
        }
        if stream.write_all(piece).is_err() {
            break;
        }
    }
    if !keep_open {
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }
    let mut received = Vec::new();
    match stream.read_to_end(&mut received) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::ConnectionReset => {}
        Err(err) => panic!("{err}"),
    }
    (received, start.elapsed())
}

/// The request is the line and then the end of the stream, however the
/// bytes arrive: the same bytes in one write or in pieces with pauses give
/// the same answer; a byte after the newline, arriving late, is
/// `invalid_request`; a complete line whose client never closes its write
/// half is never dispatched (the store here is unreachable: a dispatched
/// request would be answered `auth_unavailable` in 300 ms).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_is_framed_by_the_end_of_the_stream() {
    let dir = TempDir::new();
    let limits = Settings {
        idle_timeout: Duration::from_millis(1_000),
        deadline: Duration::from_secs(10),
        statement_timeout: Duration::from_secs(5),
        ..settings()
    };
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, None)
            .with_settings(limits)
            .unwrap(),
        &dir.socket(),
    )
    .await;
    let path = server.path.clone();
    let results = tokio::task::spawn_blocking(move || {
        let valid: &[u8] = br#"{"op":"restore","operation_id":"oper_1","signature":"00"}"#;
        let line = [valid, b"\n"].concat();
        let pause = Duration::from_millis(150);
        let mut results = Vec::new();
        // The valid line: together, in two pieces, byte by byte in places.
        for pieces in [
            vec![&line[..]],
            vec![&line[..10], &line[10..]],
            vec![valid, b"\n"],
            vec![&line[..1], &line[1..30], &line[30..line.len() - 1], b"\n"],
        ] {
            results.push(("valid", exchange_in_pieces(&path, &pieces, pause, false)));
        }
        // Trailing bytes, late: after a pause, after the newline.
        for pieces in [
            vec![&line[..], b"x"],
            vec![&line[..], b"\n"],
            vec![&line[..], b" "],
            vec![valid, b"\n", b"{}"],
            vec![&line[..], &line[..]],
        ] {
            results.push(("trailing", exchange_in_pieces(&path, &pieces, pause, false)));
        }
        // A complete line, never followed by the end of the stream.
        results.push(("open", exchange_in_pieces(&path, &[&line], pause, true)));
        results
    })
    .await
    .unwrap();
    for (kind, (received, elapsed)) in results {
        match kind {
            "valid" => assert_eq!(parse_reply(&received), error("auth_unavailable")),
            "trailing" => assert_eq!(parse_reply(&received), error("invalid_request")),
            _ => {
                assert_eq!(received, b"", "dispatched without the end of the stream");
                assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
            }
        }
    }
    server.stop().await;
}

/// The request mutex is taken only once a request is read: a client that
/// sends nothing does not delay another one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_client_does_not_delay_another() {
    let dir = TempDir::new();
    let limits = Settings {
        idle_timeout: Duration::from_secs(8),
        ..settings()
    };
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, None)
            .with_settings(limits)
            .unwrap(),
        &dir.socket(),
    )
    .await;
    let silent = StdStream::connect(&server.path).unwrap();
    // Let the server accept it and start its read.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    // A valid request reaches the store (unreachable: 300 ms).
    let reply = server.call(signed("restore", "oper_1", &[0; 64])).await;
    assert_eq!(reply, error("auth_unavailable"));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    drop(silent);
    server.stop().await;
}

/// At most `max_connections` connections are served at once (default 32):
/// the next client waits, unaccepted, until one of them ends, and is then
/// served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_past_the_limit_wait() {
    assert_eq!(Settings::default().max_connections, 32);
    let dir = TempDir::new();
    let limits = Settings {
        idle_timeout: Duration::from_secs(3),
        ..settings()
    };
    let server = Server::bind(
        transport(&unreachable_pool(), TestClock::new(), 1, None)
            .with_settings(limits)
            .unwrap(),
        &dir.socket(),
    )
    .await;
    // 31 silent connections leave room for one more.
    let mut silent: Vec<StdStream> = (0..31)
        .map(|_| StdStream::connect(&server.path).unwrap())
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    assert_eq!(
        server.call(json!({"op": "nothing"})).await,
        error("invalid_request")
    );
    assert!(started.elapsed() < Duration::from_millis(1_000));
    // The 32nd silent one fills the limit: the 33rd waits for the idle
    // timeout (3 s) of the first ones.
    silent.push(StdStream::connect(&server.path).unwrap());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    assert_eq!(
        server.call(json!({"op": "nothing"})).await,
        error("invalid_request")
    );
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(1_500) && waited < Duration::from_secs(10),
        "{waited:?}"
    );
    drop(silent);
    server.stop().await;
}

// ---------------------------------------------------------------------------
// The operations, on a database

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// Every row of every table of the schema, as text, by table (as
/// `registry_recovery.rs`).
async fn snapshot(pool: &PgPool) -> BTreeMap<String, Vec<String>> {
    let mut connection = pool.acquire().await.unwrap();
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema() \
         AND tablename NOT LIKE '\\_sqlx%' ORDER BY 1",
    )
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    assert!(tables.len() > 20, "{tables:?}");
    let mut snapshot = BTreeMap::new();
    for table in tables {
        // The names come from the catalog.
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT t::text FROM \"{table}\" t ORDER BY t::text COLLATE \"C\""
        )))
        .fetch_all(&mut *connection)
        .await
        .unwrap();
        snapshot.insert(table, rows);
    }
    snapshot
}

async fn audit_events(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_event")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn verify(pool: &PgPool) -> ChainVerdict {
    verify_audit_chain(&mut pool.acquire().await.unwrap())
        .await
        .unwrap()
}

/// Whether the credential of operator key `n` authorizes an instance
/// `security_admin`.
async fn is_security_admin(pool: &PgPool, n: u8) -> bool {
    authorize_operator(
        pool,
        &OperatorRequest {
            public_identity: &identity_of(n),
            scope: OperatorScope::Instance,
            role: AdminRole::SecurityAdmin,
        },
    )
    .await
    .unwrap()
    .is_some()
}

/// The first IDs of `kind` that a transport with `seed` generates.
fn ids(seed: u64, kind: IdKind, count: usize) -> Vec<String> {
    let ids = SequentialIds::with_seed(seed);
    (0..count).map(|_| ids.new_id(kind).unwrap()).collect()
}

/// A transport on `pool` with `seed`, served at a fresh path in `dir`.
async fn serve(
    dir: &TempDir,
    name: &str,
    pool: &PgPool,
    clock: &Arc<TestClock>,
    seed: u64,
) -> Server {
    Server::bind(
        transport(pool, Arc::clone(clock), seed, None)
            .with_settings(settings())
            .unwrap(),
        &dir.0.join(name),
    )
    .await
}

/// Bootstrap is answered with what it wrote, closes for good, and stays
/// closed for a new transport on the same database.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bootstrap_closes_for_good_across_a_restart() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = serve(&dir, "a.sock", &pool, &clock, 1).await;
    // Nothing to issue before bootstrap.
    let before = snapshot(&pool).await;
    assert_eq!(
        server.call(issue_request(2, &public_key(&NEW_SEED))).await,
        error("conflict")
    );
    assert_eq!(snapshot(&pool).await, before);

    let reply = server.call(bootstrap_request(1, &public_key(&SEED))).await;
    // The refused issue took the first IDs of each kind.
    assert_eq!(
        reply,
        json!({
            "instance_id": INSTANCE,
            "admin_id": ids(1, IdKind::AdminIdentity, 2)[1],
            "credential_id": ids(1, IdKind::AdminCredential, 2)[1],
            "binding_id": ids(1, IdKind::AdminRoleBinding, 2)[1],
            "recovery_key_epoch": 1,
        })
    );
    assert!(is_security_admin(&pool, 1).await);
    let state = get_recovery_state(&pool).await.unwrap().unwrap();
    assert_eq!(state.recovery_public_key, public_key(&SEED));
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 1 }
    );
    let after = snapshot(&pool).await;

    // Closed, also for another key and instance ID.
    assert_eq!(
        server
            .call(bootstrap_request(3, &public_key(&THIRD_SEED)))
            .await,
        error("conflict")
    );
    server.stop().await;
    let server = serve(&dir, "a.sock", &pool, &clock, 2).await;
    for request in [bootstrap_request(4, &public_key(&THIRD_SEED)), {
        let mut other = bootstrap_request(5, &public_key(&THIRD_SEED));
        other["instance_id"] = json!("019a9f3c-5b2e-7c41-ad8e-ba9876543210");
        other
    }] {
        assert_eq!(server.call(request).await, error("conflict"));
    }
    assert_eq!(snapshot(&pool).await, after);
    assert!(!is_security_admin(&pool, 4).await);
    server.stop().await;
    db.drop([pool]).await;
}

/// Eight concurrent bootstraps, four on each of two transports on the same
/// database: exactly one succeeds, the others are `conflict`, and one
/// operator, one recovery state and one event exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_bootstraps_have_exactly_one_winner() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let servers = Arc::new([
        serve(&dir, "a.sock", &pool, &clock, 1).await,
        serve(&dir, "b.sock", &pool, &clock, 2).await,
    ]);
    let attempts: Vec<_> = (0..8_u8)
        .map(|n| {
            let servers = Arc::clone(&servers);
            tokio::spawn(async move {
                let server = &servers[usize::from(n % 2)];
                (
                    n,
                    server
                        .call(bootstrap_request(10 + n, &public_key(&SEED)))
                        .await,
                )
            })
        })
        .collect();
    let mut winners = Vec::new();
    for attempt in attempts {
        let (n, reply) = attempt.await.unwrap();
        if reply.get("error").is_some() {
            assert_eq!(reply, error("conflict"), "{n}");
        } else {
            assert_eq!(reply["instance_id"], INSTANCE, "{n}");
            winners.push(n);
        }
    }
    assert_eq!(winners.len(), 1, "{winners:?}");
    for n in 0..8 {
        assert_eq!(
            is_security_admin(&pool, 10 + n).await,
            winners == [n],
            "{n}"
        );
    }
    let count = |table: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    for table in [
        "recovery_state",
        "admin_identity",
        "admin_credential",
        "audit_event",
    ] {
        assert_eq!(count(table).await, 1, "{table}");
    }
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 1 }
    );
    let Ok(servers) = Arc::try_unwrap(servers) else {
        panic!("the attempts hold no server any more")
    };
    for server in servers {
        server.stop().await;
    }
    db.drop([pool]).await;
}

/// Bootstraps through `server` with the recovery key of [`SEED`] and the
/// operator key 1.
async fn bootstrap(server: &Server) {
    let reply = server.call(bootstrap_request(1, &public_key(&SEED))).await;
    assert_eq!(reply["recovery_key_epoch"], 1, "{reply}");
}

/// Issues a challenge for the replacement with operator key `credential`
/// and the recovery key of [`NEW_SEED`]; returns the operation ID and `M`.
async fn issue(server: &Server, credential: u8) -> (String, Vec<u8>) {
    let reply = server
        .call(issue_request(credential, &public_key(&NEW_SEED)))
        .await;
    let operation_id = reply["operation_id"].as_str().unwrap().to_owned();
    let challenge = unhex(reply["challenge"].as_str().unwrap());
    (operation_id, challenge)
}

/// The issue returns `M`, which the workstation checks and signs; the
/// preview and the restore answer with the replacement; a replay of the
/// signed response is refused and writes nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_is_issued_answered_and_consumed_once() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = serve(&dir, "a.sock", &pool, &clock, 1).await;
    bootstrap(&server).await;

    clock.advance(Duration::from_secs(1));
    let reply = server.call(issue_request(2, &public_key(&NEW_SEED))).await;
    let operation_id = ids(1, IdKind::AdministrativeOperation, 1).remove(0);
    let replacement = [
        ids(1, IdKind::AdminIdentity, 2).remove(1),
        ids(1, IdKind::AdminCredential, 2).remove(1),
        ids(1, IdKind::AdminRoleBinding, 2).remove(1),
    ];
    let issued_at = UNIX_EPOCH + T0 + Duration::from_secs(1);
    let expires_at = i64::try_from(
        (issued_at + Duration::from_secs(300))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    assert_eq!(reply["operation_id"], operation_id.as_str());
    assert_eq!(reply["expected_revision"], 1);
    assert_eq!(reply["expires_at"], expires_at);
    // `M`: the prefix and the canonical request, which binds the instance,
    // the epoch, the replacement, the new key, the revision and the expiry.
    let challenge = unhex(reply["challenge"].as_str().unwrap());
    let text = std::str::from_utf8(&challenge).unwrap();
    let canonical: Value =
        serde_json::from_str(text.strip_prefix(CHALLENGE_PREFIX).unwrap()).unwrap();
    assert_eq!(
        canonical,
        json!({
            "actor_id": "deployment_operator",
            "expected_revision": 1,
            "expires_at": expires_at,
            "id": operation_id,
            "kind": "operator_restoration",
            "plan": {
                "admin_id": replacement[0],
                "binding_id": replacement[2],
                "credential_id": replacement[1],
                "instance_id": INSTANCE,
                "new_recovery_public_key": hex(&public_key(&NEW_SEED)),
                "public_identity": identity_of(2),
                "recovery_key_epoch": 1,
                "trust_anchor_ref": ANCHOR,
            },
            "tenant_id": null,
        })
    );

    let signature = sign(&SEED, &challenge);
    clock.advance(Duration::from_secs(1));
    let before_preview = snapshot(&pool).await;
    assert_eq!(
        server
            .call(signed("preview", &operation_id, &signature))
            .await,
        json!({
            "admin_id": replacement[0],
            "credential_id": replacement[1],
            "binding_id": replacement[2],
            "new_recovery_key_epoch": 2,
            "expires_at": expires_at,
        })
    );
    assert_eq!(snapshot(&pool).await, before_preview);

    let reply = server
        .call(signed("restore", &operation_id, &signature))
        .await;
    assert_eq!(
        reply,
        json!({
            "admin_id": replacement[0],
            "credential_id": replacement[1],
            "binding_id": replacement[2],
            "revoked_credential_ids": [ids(1, IdKind::AdminCredential, 1)[0]],
            "recovery_key_epoch": 2,
            "recovery_state_revision": 2,
        })
    );
    assert!(is_security_admin(&pool, 2).await);
    assert!(!is_security_admin(&pool, 1).await);
    let state = get_recovery_state(&pool).await.unwrap().unwrap();
    assert_eq!(state.recovery_public_key, public_key(&NEW_SEED));
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 4 }
    );

    // The replay, and its preview: refused, nothing written.
    let after = snapshot(&pool).await;
    for op in ["restore", "preview"] {
        assert_eq!(
            server.call(signed(op, &operation_id, &signature)).await,
            error("not_restorable"),
            "{op}"
        );
    }
    assert_eq!(snapshot(&pool).await, after);
    server.stop().await;
    db.drop([pool]).await;
}

/// A signature by another key, over another message, malleated or of
/// another length is `not_restorable`: the database is unchanged, no audit
/// event is appended, and the challenge stays usable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_wrong_signature_writes_nothing() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = serve(&dir, "a.sock", &pool, &clock, 1).await;
    bootstrap(&server).await;
    let (operation_id, challenge) = issue(&server, 2).await;
    let good = sign(&SEED, &challenge);
    let mut flipped = good.clone();
    flipped[10] ^= 1;
    let before = snapshot(&pool).await;
    let events = audit_events(&pool).await;
    for (what, signature) in [
        ("another key", sign(&THIRD_SEED, &challenge)),
        ("the new key", sign(&NEW_SEED, &challenge)),
        ("another message", sign(&SEED, b"another message")),
        ("a flipped bit", flipped),
        ("63 bytes", good[..63].to_vec()),
        ("65 bytes", [&good[..], &[0]].concat()),
        ("empty", Vec::new()),
    ] {
        assert_eq!(
            server
                .call(signed("restore", &operation_id, &signature))
                .await,
            error("not_restorable"),
            "{what}"
        );
    }
    assert_eq!(
        server.call(signed("restore", "oper_unknown", &good)).await,
        error("not_restorable")
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(audit_events(&pool).await, events);
    // The challenge is still unconsumed.
    let reply = server.call(signed("restore", &operation_id, &good)).await;
    assert_eq!(reply["recovery_key_epoch"], 2, "{reply}");
    server.stop().await;
    db.drop([pool]).await;
}

/// A challenge expires after the transport's TTL by its clock, and a
/// restore after a restart of the transport still consumes an unexpired
/// one: the challenge is the row, not the transport's memory.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_outlives_a_restart_until_it_expires() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let short = Settings {
        challenge_ttl: Duration::from_secs(60),
        ..settings()
    };
    let start = |seed| {
        let pool = pool.clone();
        let clock = Arc::clone(&clock);
        let path = dir.0.join("a.sock");
        async move {
            Server::bind(
                transport(&pool, clock, seed, None)
                    .with_settings(short)
                    .unwrap(),
                &path,
            )
            .await
        }
    };
    let server = start(1).await;
    bootstrap(&server).await;
    let (expired, expired_m) = issue(&server, 2).await;
    clock.advance(Duration::from_secs(60));
    let before = snapshot(&pool).await;
    assert_eq!(
        server
            .call(signed("restore", &expired, &sign(&SEED, &expired_m)))
            .await,
        error("not_restorable")
    );
    assert_eq!(snapshot(&pool).await, before);

    let (operation_id, challenge) = issue(&server, 3).await;
    server.stop().await;
    let server = start(2).await;
    clock.advance(Duration::from_secs(59));
    let reply = server
        .call(signed("restore", &operation_id, &sign(&SEED, &challenge)))
        .await;
    assert_eq!(reply["recovery_key_epoch"], 2, "{reply}");
    assert!(is_security_admin(&pool, 3).await);
    server.stop().await;
    db.drop([pool]).await;
}

/// A transport whose pool is closed answers `auth_unavailable` and writes
/// nothing; bootstrap is then still open.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_missing_store_writes_nothing() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let closed = db.pool().await;
    closed.close().await;
    let server = serve(&dir, "closed.sock", &closed, &clock, 1).await;
    let before = snapshot(&pool).await;
    assert_eq!(
        server.call(bootstrap_request(1, &public_key(&SEED))).await,
        error("auth_unavailable")
    );
    assert_eq!(snapshot(&pool).await, before);
    server.stop().await;

    let server = serve(&dir, "open.sock", &pool, &clock, 2).await;
    bootstrap(&server).await;
    let (operation_id, challenge) = issue(&server, 2).await;
    server.stop().await;
    let server = serve(&dir, "closed.sock", &closed, &clock, 3).await;
    let before = snapshot(&pool).await;
    for request in [
        issue_request(3, &public_key(&NEW_SEED)),
        signed("restore", &operation_id, &sign(&SEED, &challenge)),
        signed("preview", &operation_id, &sign(&SEED, &challenge)),
    ] {
        assert_eq!(server.call(request).await, error("auth_unavailable"));
    }
    assert_eq!(snapshot(&pool).await, before);
    server.stop().await;
    db.drop([pool, closed]).await;
}

/// The audit chain head: its sequence and hash.
type Head = (i64, Option<Vec<u8>>);

async fn head(pool: &PgPool) -> Head {
    sqlx::query_as("SELECT sequence, head_hash FROM audit_chain_head")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Sets the audit chain head to `head`, past its trigger.
async fn set_head(pool: &PgPool, (sequence, hash): Head) {
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_chain_head SET sequence = $1, head_hash = $2")
        .bind(sequence)
        .bind(hash)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER audit_chain_head_advance")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// A head that leaves no sequence for another event: `2^53 - 1`.
fn full_head() -> Head {
    (9_007_199_254_740_991, Some(vec![0xcd; 32]))
}

/// An audit append that fails (a head at `2^53 - 1` leaves no sequence for
/// the event) fails the request with `server_error` and rolls everything
/// back: no bootstrap, no consumed challenge.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_audit_append_rolls_the_request_back() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = serve(&dir, "a.sock", &pool, &clock, 1).await;
    let empty = head(&pool).await;
    set_head(&pool, full_head()).await;
    let before = snapshot(&pool).await;
    assert_eq!(
        server.call(bootstrap_request(1, &public_key(&SEED))).await,
        error("server_error")
    );
    assert_eq!(snapshot(&pool).await, before);
    assert!(get_recovery_state(&pool).await.unwrap().is_none());
    set_head(&pool, empty).await;

    bootstrap(&server).await;
    let (operation_id, challenge) = issue(&server, 2).await;
    let signature = sign(&SEED, &challenge);
    let issued = head(&pool).await;
    set_head(&pool, full_head()).await;
    let before = snapshot(&pool).await;
    assert_eq!(
        server.call(issue_request(3, &public_key(&NEW_SEED))).await,
        error("server_error")
    );
    assert_eq!(
        server
            .call(signed("restore", &operation_id, &signature))
            .await,
        error("server_error")
    );
    assert_eq!(snapshot(&pool).await, before);
    set_head(&pool, issued).await;
    // The challenge was not consumed.
    let reply = server
        .call(signed("restore", &operation_id, &signature))
        .await;
    assert_eq!(reply["recovery_key_epoch"], 2, "{reply}");
    server.stop().await;
    db.drop([pool]).await;
}

/// An ID generator with no ID left answers `server_error` before the
/// transaction: nothing is written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_id_generator_failure_writes_nothing() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let exhausted = LocalTransport::new(
        pool.clone(),
        TestClock::new(),
        Arc::new(SequentialIds::with_last_count(IdKind::AuditEvent, u64::MAX)),
        None,
    );
    let server = Server::bind(exhausted, &dir.socket()).await;
    let before = snapshot(&pool).await;
    assert_eq!(
        server.call(bootstrap_request(1, &public_key(&SEED))).await,
        error("server_error")
    );
    assert_eq!(snapshot(&pool).await, before);
    server.stop().await;
    db.drop([pool]).await;
}

/// The transport runs at `READ COMMITTED` whatever the database's default:
/// a restore works on a database whose default isolation is
/// `SERIALIZABLE`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_runs_at_read_committed_whatever_the_default() {
    let (db, pool) = migrated().await;
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    // The name is the test database's, digits and underscores.
    sqlx::raw_sql(AssertSqlSafe(format!(
        "ALTER DATABASE {name} SET default_transaction_isolation = 'serializable'"
    )))
    .execute(&pool)
    .await
    .unwrap();
    let serializable = db.pool().await;
    let level: String = sqlx::query_scalar("SHOW default_transaction_isolation")
        .fetch_one(&serializable)
        .await
        .unwrap();
    assert_eq!(level, "serializable");
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = serve(&dir, "a.sock", &serializable, &clock, 1).await;
    bootstrap(&server).await;
    let (operation_id, challenge) = issue(&server, 2).await;
    let reply = server
        .call(signed("restore", &operation_id, &sign(&SEED, &challenge)))
        .await;
    assert_eq!(reply["recovery_key_epoch"], 2, "{reply}");
    server.stop().await;
    db.drop([pool, serializable]).await;
}

/// A lock held past the transport's statement timeout fails the request
/// with `auth_unavailable` (`lock_timeout`) and writes nothing; the
/// challenge stays usable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_held_lock_times_the_request_out() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let quick = Settings {
        statement_timeout: Duration::from_millis(300),
        ..settings()
    };
    let server = Server::bind(
        transport(&pool, Arc::clone(&clock), 1, None)
            .with_settings(quick)
            .unwrap(),
        &dir.socket(),
    )
    .await;
    bootstrap(&server).await;
    let (operation_id, challenge) = issue(&server, 2).await;
    let request = signed("restore", &operation_id, &sign(&SEED, &challenge));

    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT FROM recovery_state FOR UPDATE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let before = snapshot(&pool).await;
    let start = Instant::now();
    assert_eq!(
        server.call(request.clone()).await,
        error("auth_unavailable")
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(snapshot(&pool).await, before);
    lock.rollback().await.unwrap();
    let reply = server.call(request).await;
    assert_eq!(reply["recovery_key_epoch"], 2, "{reply}");
    server.stop().await;
    db.drop([pool]).await;
}

/// The deadline covers the wait for a pooled connection: with the pool's
/// only connection held elsewhere (and a pool acquire timeout far past the
/// deadline), a request is closed without a response at the deadline and
/// writes nothing; it is answered once the connection is free.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_deadline_covers_the_wait_for_a_connection() {
    let (db, pool) = migrated().await;
    let single = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let dir = TempDir::new();
    let limits = Settings {
        idle_timeout: Duration::from_secs(10),
        deadline: Duration::from_secs(1),
        statement_timeout: Duration::from_millis(500),
        ..Settings::default()
    };
    let server = Server::bind(
        transport(&single, TestClock::new(), 1, None)
            .with_settings(limits)
            .unwrap(),
        &dir.socket(),
    )
    .await;

    let held = single.acquire().await.unwrap();
    let before = snapshot(&pool).await;
    let mut line = serde_json::to_vec(&bootstrap_request(1, &public_key(&SEED))).unwrap();
    line.push(b'\n');
    let start = Instant::now();
    assert_eq!(server.raw(line).await.unwrap(), b"");
    let waited = start.elapsed();
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(5),
        "{waited:?}"
    );
    assert_eq!(snapshot(&pool).await, before);

    drop(held);
    bootstrap(&server).await;
    server.stop().await;
    single.close().await;
    db.drop([pool]).await;
}

/// One request at a time per transport: while a restore waits for a lock
/// another transaction holds, a preview (which takes no lock) waits for the
/// restore, and both are answered once the lock is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn requests_are_serialized_per_transport() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = Arc::new(serve(&dir, "a.sock", &pool, &clock, 1).await);
    bootstrap(&server).await;
    let (operation_id, challenge) = issue(&server, 2).await;
    let signature = sign(&SEED, &challenge);

    let mut holder = PgConnection::connect_with(&pool.connect_options())
        .await
        .unwrap();
    let mut lock = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM recovery_state FOR UPDATE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let restore = {
        let server = Arc::clone(&server);
        let request = signed("restore", &operation_id, &signature);
        tokio::spawn(async move { server.call(request).await })
    };
    // The restore is waiting for the lock.
    let waiting = "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
                   AND datname = current_database())";
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sqlx::query_scalar::<_, bool>(waiting)
        .fetch_one(&pool)
        .await
        .unwrap()
    {
        assert!(Instant::now() < deadline, "the restore never waited");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let preview = {
        let server = Arc::clone(&server);
        let request = signed("preview", &operation_id, &signature);
        tokio::spawn(async move { server.call(request).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !preview.is_finished(),
        "the preview did not wait for the restore"
    );
    assert!(!restore.is_finished());
    lock.rollback().await.unwrap();
    let restored = restore.await.unwrap();
    assert_eq!(restored["recovery_key_epoch"], 2, "{restored}");
    // Served after the restore: the challenge is consumed.
    assert_eq!(preview.await.unwrap(), error("not_restorable"));
    holder.close().await.unwrap();
    let Ok(server) = Arc::try_unwrap(server) else {
        panic!("the requests hold no server any more")
    };
    server.stop().await;
    db.drop([pool]).await;
}

/// An issue for a key that a credential already has, live or revoked, is
/// `conflict` before anything is written: the restore could never enroll
/// it (the credential key is unique).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_issue_for_a_registered_key_is_a_conflict() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = serve(&dir, "a.sock", &pool, &clock, 1).await;
    bootstrap(&server).await;
    // Key 1 is the bootstrap operator's, live.
    let before = snapshot(&pool).await;
    assert_eq!(
        server.call(issue_request(1, &public_key(&NEW_SEED))).await,
        error("conflict")
    );
    assert_eq!(snapshot(&pool).await, before);
    // A restore to key 2 revokes key 1.
    let (operation_id, challenge) = issue(&server, 2).await;
    let reply = server
        .call(signed("restore", &operation_id, &sign(&SEED, &challenge)))
        .await;
    assert_eq!(reply["recovery_key_epoch"], 2, "{reply}");
    assert!(!is_security_admin(&pool, 1).await);
    let before = snapshot(&pool).await;
    for (credential, what) in [(1, "revoked"), (2, "live")] {
        assert_eq!(
            server
                .call(issue_request(credential, &public_key(&THIRD_SEED)))
                .await,
            error("conflict"),
            "{what}"
        );
    }
    assert_eq!(snapshot(&pool).await, before);
    // A new key is issued.
    let reply = server
        .call(issue_request(3, &public_key(&THIRD_SEED)))
        .await;
    assert!(reply["challenge"].is_string(), "{reply}");
    server.stop().await;
    db.drop([pool]).await;
}

/// The transport refuses at the issue exactly the `trust_anchor_ref`
/// characters that the credential table's own check refuses (read from the
/// catalog and evaluated by the database): over U+0001 to U+00A1 and other
/// Unicode spaces, every value the transport accepts the database accepts,
/// and the other way round. U+0085 (a C1 control) is refused by both.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_trust_anchor_check_is_the_databases() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    // Not bootstrapped: a value the checks pass is a `conflict` (no
    // recovery state), one they refuse is `invalid_request`.
    let server = serve(&dir, "a.sock", &pool, &clock, 1).await;
    let definition: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
         WHERE conname = 'admin_credential_trust_anchor_ref_no_space_check'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let expression = definition
        .strip_prefix("CHECK ")
        .unwrap_or_else(|| panic!("{definition}"));
    assert_eq!(
        expression.matches("trust_anchor_ref").count(),
        1,
        "{expression}"
    );
    // The catalog's text, with the column replaced by the value.
    let evaluate = format!(
        "SELECT {}",
        expression.replace("trust_anchor_ref", "($1::text)")
    );
    let mut characters: Vec<char> = (1..=0xa1_u32).filter_map(char::from_u32).collect();
    characters.extend([
        '\u{1680}',
        '\u{2000}',
        '\u{200a}',
        '\u{200b}',
        '\u{2028}',
        '\u{2029}',
        '\u{202f}',
        '\u{205f}',
        '\u{3000}',
        '\u{feff}',
        '\u{fffd}',
        '\u{e9}',
        '\u{10ffff}',
    ]);
    let mut refused = Vec::new();
    for c in characters {
        let value = format!("a{c}b");
        let database: bool = sqlx::query_scalar(AssertSqlSafe(evaluate.clone()))
            .bind(&value)
            .fetch_one(&pool)
            .await
            .unwrap();
        let mut request = issue_request(2, &public_key(&NEW_SEED));
        request["trust_anchor_ref"] = json!(value);
        let reply = server.call(request).await;
        let transport = match reply["error"].as_str() {
            Some("conflict") => true,
            Some("invalid_request") => false,
            _ => panic!("U+{:04X}: {reply}", u32::from(c)),
        };
        assert_eq!(transport, database, "U+{:04X}", u32::from(c));
        if !database {
            refused.push(u32::from(c));
        }
    }
    let expected: Vec<u32> = (0x01..=0x20).chain(0x7f..=0x9f).collect();
    assert_eq!(refused, expected);
    assert!(refused.contains(&0x85));
    server.stop().await;
    db.drop([pool]).await;
}

/// A byte after the newline that arrives late, and a line whose client
/// never closes its write half, write nothing: the request is not
/// dispatched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_unframed_request_writes_nothing() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let server = Server::bind(
        transport(&pool, Arc::clone(&clock), 1, None)
            .with_settings(Settings {
                idle_timeout: Duration::from_millis(800),
                ..settings()
            })
            .unwrap(),
        &dir.socket(),
    )
    .await;
    let before = snapshot(&pool).await;
    let mut line = serde_json::to_vec(&bootstrap_request(1, &public_key(&SEED))).unwrap();
    line.push(b'\n');
    let path = server.path.clone();
    let (late, open) = tokio::task::spawn_blocking(move || {
        let pause = Duration::from_millis(300);
        (
            exchange_in_pieces(&path, &[&line, b"{}"], pause, false),
            exchange_in_pieces(&path, &[&line], pause, true),
        )
    })
    .await
    .unwrap();
    assert_eq!(parse_reply(&late.0), error("invalid_request"));
    assert_eq!(open.0, b"");
    assert_eq!(snapshot(&pool).await, before);
    assert!(get_recovery_state(&pool).await.unwrap().is_none());
    bootstrap(&server).await;
    server.stop().await;
    db.drop([pool]).await;
}

/// The deadline bounds the read, the mutex wait and the pool's acquire,
/// not the transaction: a restore whose request took most of the deadline
/// to arrive and then waited for a lock past the deadline still commits and
/// is answered, and the mutex is held until its transaction ends, so a
/// preview sent meanwhile is served after it (the challenge is consumed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_deadline_does_not_cut_a_transaction() {
    let (db, pool) = migrated().await;
    let dir = TempDir::new();
    let clock = TestClock::new();
    let limits = Settings {
        idle_timeout: Duration::from_secs(1),
        deadline: Duration::from_secs(2),
        statement_timeout: Duration::from_millis(1_800),
        ..settings()
    };
    let server = Arc::new(
        Server::bind(
            transport(&pool, Arc::clone(&clock), 1, None)
                .with_settings(limits)
                .unwrap(),
            &dir.socket(),
        )
        .await,
    );
    bootstrap(&server).await;
    let (operation_id, challenge) = issue(&server, 2).await;
    let signature = sign(&SEED, &challenge);

    let mut holder = PgConnection::connect_with(&pool.connect_options())
        .await
        .unwrap();
    let mut lock = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM recovery_state FOR UPDATE")
        .execute(&mut *lock)
        .await
        .unwrap();
    // The restore's request arrives over 1.2 s, then waits for the lock.
    let mut line = serde_json::to_vec(&signed("restore", &operation_id, &signature)).unwrap();
    line.push(b'\n');
    let path = server.path.clone();
    let started = Instant::now();
    let restore = tokio::task::spawn_blocking(move || {
        let pieces = [
            &line[..10],
            &line[10..11],
            &line[11..12],
            &line[12..13],
            &line[13..],
        ];
        exchange_in_pieces(&path, &pieces, Duration::from_millis(300), false)
    });
    // Past the restore's deadline, while its transaction waits.
    tokio::time::sleep_until((started + Duration::from_millis(2_100)).into()).await;
    let waiting: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
         AND datname = current_database())",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(waiting, "the restore is not waiting for the lock");
    let preview = {
        let server = Arc::clone(&server);
        let request = signed("preview", &operation_id, &signature);
        tokio::spawn(async move { server.call(request).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!preview.is_finished(), "the preview ran during the restore");
    lock.rollback().await.unwrap();
    let (received, elapsed) = restore.await.unwrap();
    assert!(elapsed > Duration::from_secs(2), "{elapsed:?}");
    let restored = parse_reply(&received);
    assert_eq!(restored["recovery_key_epoch"], 2, "{restored}");
    assert_eq!(preview.await.unwrap(), error("not_restorable"));
    holder.close().await.unwrap();
    let Ok(server) = Arc::try_unwrap(server) else {
        panic!("the requests hold no server any more")
    };
    server.stop().await;
    db.drop([pool]).await;
}
