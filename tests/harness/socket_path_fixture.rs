//! The socket path fixture `tests/conformance/fixtures/_wire/socket_path.v1.json`
//! against the service's own bind (`skyoauth_service::local_transport`,
//! [`LocalTransport::bind`]), so that the operator's checks of the socket
//! path (`skyoauth_operator::local::check_socket`, which
//! `operator/tests/local_path` runs on the same cases) and the service's
//! rules for its socket file cannot drift apart. They test the fixture
//! file, not a scenario: no name here matches `a\d\d_`, and no stage of
//! `tests/conformance/scenarios.toml` lists them (layout §3). No database
//! is needed: the transport's pool never connects.
//!
//! Each case's tree is built in a fresh case root, and the transport is
//! bound at the case's path: the bind's result must be the `bind` of the
//! case's outcome (`ok` for an accepted path, a stale socket of the service
//! UID with a wrong mode, an empty socket path and a sticky socket
//! directory the client alone refuses, `shared_directory`; `InvalidPath`,
//! `PathTooLong`, `UnsafeDirectory`, `UnsafeAncestor`, `PathOccupied`, or
//! `Io` with the error's kind: the case's `io_kind` for a failed lookup,
//! the outcome's `bind_io_kind`, `Other`, for too many symbolic links,
//! which the service's walk refuses itself), and a bound socket must be a
//! socket of the service UID with mode exactly 0600, the one the client
//! accepts.
//!
//! The binds run where the case's trust says the service runs them:
//!
//! - `service_or_root`, the bind of a service for its own UID: in this
//!   process when it is not root (the service UID is its own, so only the
//!   cases whose entries are all the service's can be built); as root, in a
//!   child process run as the local user `SKYOAUTH_IT_PEER_USER` names
//!   (the service UID; root gives the entries to it and to the other role
//!   first), a copy of this binary running
//!   [`socket_path_binds_as_the_service_uid`];
//! - `root_only`, root's bind for another service UID: in this process as
//!   root, for that user's UID (65534 without it).
//!
//! A case that cannot run (one that needs root, or as root the peer user)
//! is skipped with a printed NOTICE; the CI job runs as its runner's user,
//! so it binds the `service_or_root` cases whose entries are all its own.
//! A case whose bind is `ok` runs only where the service binds at all
//! ([`BINDS_SUPPORTED`]: Linux on x86_64, aarch64 and riscv64, where it
//! knows its `open` flags); elsewhere it is skipped with the NOTICE too.
//! The client's side of every case runs on every Unix target
//! (`operator/tests/local_path`).

use std::{
    env, fs,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use skyoauth_service::{
    ids::test_support::SequentialIds,
    local_transport::{BindError, LocalTransport, MAX_SOCKET_PATH_BYTES},
    operation::Clock,
    persistence::PgPool,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

/// The local user the `service_or_root` binds run as when this process is
/// root, as in `service/tests/local_transport.rs`.
const PEER_USER_VAR: &str = "SKYOAUTH_IT_PEER_USER";

/// The variable that hands the child process its binds: one line per bind,
/// the case's index, a tab and the absolute path.
const BINDS_VAR: &str = "SKYOAUTH_IT_SOCKET_PATH_BINDS";

/// The child's test, by its full name in this binary.
const CHILD_TEST: &str = "harness::socket_path_fixture::socket_path_binds_as_the_service_uid";

/// The start of each result line the child prints.
const RESULT_PREFIX: &str = "SOCKET-PATH-BIND";

/// The service UID of the `root_only` binds when no peer user is given.
const SERVICE_WITHOUT_PEER: u32 = 65_534;

/// The longest wait for the child process.
const CHILD_WAIT: Duration = Duration::from_secs(120);

/// Whether the service binds on this target: Linux on x86_64, aarch64 and
/// riscv64, the architectures whose `open` flags it knows (its
/// `OPEN_FLAGS`); elsewhere its bind stops at the lock file.
const BINDS_SUPPORTED: bool = cfg!(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
));

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/fixtures/_wire/socket_path.v1.json"
    );
    let text = fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string in {value}"))
}

fn list<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    value[name]
        .as_array()
        .unwrap_or_else(|| panic!("{name} is not an array in {value}"))
}

/// A clock that stays at one time.
struct FixedClock(SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// A pool that never connects (port 1): a bind never uses it.
fn unreachable_pool() -> PgPool {
    let options = PgConnectOptions::new().host("127.0.0.1").port(1);
    PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(300))
        .connect_lazy_with(options)
}

/// A fresh directory under the system's temporary directory, its symbolic
/// links resolved (the fixture's `case_root`), mode 0755, removed when
/// dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "skyoauth-socket-path-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
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

/// The UIDs of the fixture's roles for this process.
struct Roles {
    root: bool,
    service: u32,
    other: u32,
}

impl Roles {
    /// The UID of `role`, if this process can give an entry to it.
    fn uid(&self, role: &str) -> Option<u32> {
        match (role, self.root) {
            ("service", _) => Some(self.service),
            ("root", true) => Some(0),
            ("other", true) => Some(self.other),
            ("root" | "other", false) => None,
            _ => panic!("unknown role {role:?}"),
        }
    }
}

/// Where a case's bind runs.
enum Side {
    /// In this process, for the service UID given (`None`: its own).
    Here(Option<u32>),
    /// In the child process, as the service UID.
    Child,
    /// Not at all, for the reason given.
    Skipped(&'static str),
}

/// Where `case` binds (see the module docs).
fn side_of(case: &Value, roles: &Roles, peer: bool) -> Side {
    let own = list(case, "entries")
        .iter()
        .all(|entry| text(entry, "owner") == "service");
    match (text(case, "trust"), roles.root) {
        ("service_or_root", false) if own => Side::Here(None),
        ("service_or_root", false) => Side::Skipped("an entry of root or of another UID"),
        ("service_or_root", true) if peer => Side::Child,
        ("service_or_root", true) => Side::Skipped("as root, the peer user"),
        ("root_only", true) => Side::Here(Some(roles.service)),
        ("root_only", false) => Side::Skipped("root's bind for another UID"),
        (other, _) => panic!("unknown trust {other:?}"),
    }
}

/// The permission bits of an octal mode string, `"0755"` say.
fn mode_of(mode: &str) -> u32 {
    assert!(mode.starts_with('0'), "{mode:?}: an octal mode with its 0");
    u32::from_str_radix(mode, 8).unwrap_or_else(|err| panic!("{mode:?}: {err}"))
}

/// `rel` under `root`, its last component padded with `p` to the length
/// `pad` names when `rel` is the case's path (see the fixture's
/// `case_root`).
fn padded(root: &Path, case: &Value, rel: &str) -> PathBuf {
    let plain = root.join(rel);
    let Some(pad) = case.get("pad") else {
        return plain;
    };
    if rel != text(case, "path") {
        return plain;
    }
    let length = match pad.as_str() {
        Some("limit") => MAX_SOCKET_PATH_BYTES,
        Some("over_limit") => MAX_SOCKET_PATH_BYTES + 1,
        _ => panic!("unknown pad {pad}"),
    };
    let have = plain.as_os_str().len();
    assert!(
        have + 1 < length,
        "the temporary directory is too long for {case}"
    );
    let mut path = plain.into_os_string();
    path.push("p".repeat(length - have));
    PathBuf::from(path)
}

/// Gives `at` to `uid` (not followed) and, but for a symbolic link, sets
/// `mode`, in that order, so a set-ID bit survives the change of owner.
fn own_and_mode(at: &Path, uid: u32, mode: Option<u32>) {
    if fs::symlink_metadata(at).unwrap().uid() != uid {
        std::os::unix::fs::lchown(at, Some(uid), None).unwrap();
    }
    if let Some(mode) = mode {
        fs::set_permissions(at, fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// Builds the entries of `case` in `root` with the UIDs of `roles`, as the
/// fixture's `case_root` describes them.
fn build(root: &Path, case: &Value, roles: &Roles) {
    let root_text = root.to_str().expect("a UTF-8 temporary directory");
    for entry in list(case, "entries") {
        let rel = text(entry, "path");
        let at = padded(root, case, rel);
        let uid = roles
            .uid(text(entry, "owner"))
            .expect("a runnable case's owners");
        let target = || text(entry, "target").replace("$ROOT", root_text);
        match text(entry, "type") {
            "dir" => {
                fs::create_dir(&at).unwrap();
                own_and_mode(&at, uid, Some(mode_of(text(entry, "mode"))));
            }
            "file" => {
                fs::write(&at, b"").unwrap();
                own_and_mode(&at, uid, Some(mode_of(text(entry, "mode"))));
            }
            "socket" => {
                // A stale socket: its listener is closed at once.
                drop(UnixListener::bind(&at).unwrap());
                own_and_mode(&at, uid, Some(mode_of(text(entry, "mode"))));
            }
            "symlink" => {
                std::os::unix::fs::symlink(target(), &at).unwrap();
                own_and_mode(&at, uid, None);
            }
            "symlink_chain" => {
                let links = entry["links"].as_u64().expect("links is an integer");
                let name = |index: u64| {
                    if index == 0 {
                        rel.to_owned()
                    } else {
                        format!("{rel}.{index}")
                    }
                };
                for index in 0..links {
                    let to = if index + 1 == links {
                        target()
                    } else {
                        Path::new(&name(index + 1))
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned()
                    };
                    let link = root.join(name(index));
                    std::os::unix::fs::symlink(to, &link).unwrap();
                    own_and_mode(&link, uid, None);
                }
            }
            other => panic!("unknown entry type {other:?}"),
        }
    }
}

/// The bind result the fixture expects for `case`: its outcome's `bind`,
/// and for `Io` the error's kind, the case's `io_kind` or the outcome's
/// `bind_io_kind` (exactly one of them): never `Io` of any kind.
fn expected_bind(fixture: &Value, case: &Value) -> String {
    let expect = text(case, "expect");
    let outcome = list(fixture, "outcomes")
        .iter()
        .find(|outcome| text(outcome, "expect") == expect)
        .unwrap_or_else(|| panic!("no outcome {expect}"));
    let bind = text(outcome, "bind");
    match (case.get("io_kind"), outcome.get("bind_io_kind")) {
        (Some(kind), None) | (None, Some(kind)) => {
            assert_eq!(bind, "Io", "{case}");
            format!("Io:{}", kind.as_str().unwrap())
        }
        (None, None) => {
            assert_ne!(bind, "Io", "{case}: an Io bind without its kind");
            bind.to_owned()
        }
        (Some(_), Some(_)) => panic!("{case}: two kinds of its Io bind"),
    }
}

/// Binds the transport at `path` for `service` (`None`: this process's
/// UID) and names the result: `ok` when the socket bound is a socket of
/// the service UID with mode exactly 0600 (the listener is dropped, which
/// removes it), else what was found, or the error's variant (`Io` with its
/// kind).
async fn bind_outcome(path: &Path, service: Option<u32>) -> String {
    let transport = LocalTransport::new(
        unreachable_pool(),
        Arc::new(FixedClock(UNIX_EPOCH + Duration::from_secs(1_790_000_000))),
        Arc::new(SequentialIds::with_seed(1)),
        service,
    );
    match transport.bind(path).await {
        Ok(listener) => {
            let uid = listener.service_uid();
            let outcome = match fs::symlink_metadata(path) {
                Ok(found)
                    if found.file_type().is_socket()
                        && found.uid() == uid
                        && found.mode() & 0o7777 == 0o600 =>
                {
                    "ok".to_owned()
                }
                Ok(found) => format!("ok but owner {} mode {:o}", found.uid(), found.mode()),
                Err(err) => format!("ok but nothing at the path: {:?}", err.kind()),
            };
            drop(listener);
            outcome
        }
        Err(BindError::InvalidPath) => "InvalidPath".to_owned(),
        Err(BindError::PathTooLong) => "PathTooLong".to_owned(),
        Err(BindError::UnsafeDirectory) => "UnsafeDirectory".to_owned(),
        Err(BindError::UnsafeAncestor { .. }) => "UnsafeAncestor".to_owned(),
        Err(BindError::PathOccupied) => "PathOccupied".to_owned(),
        Err(BindError::Io(err)) => format!("Io:{:?}", err.kind()),
        Err(other) => format!("{other:?}"),
    }
}

/// Copies this test binary to `to`, mode 0755, for the child process: `cp`
/// writes the copy, so it is never open for writing in this process (see
/// `copy_of_this_binary` in `service/tests/local_transport.rs`). `to`'s
/// directory is root's.
fn copy_of_this_binary(to: &Path) {
    let status = Command::new("cp")
        .arg(env::current_exe().unwrap())
        .arg(to)
        .status()
        .unwrap();
    assert!(status.success(), "cp: {status}");
    fs::set_permissions(to, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Runs `binds` (case index and path) in a copy of this binary, in `dir`,
/// as `user`, and returns each index's result. The wait is bounded: past
/// [`CHILD_WAIT`] the child is killed and the test fails.
fn binds_as(user: &str, dir: &Path, binds: &[(usize, PathBuf)]) -> Vec<(usize, String)> {
    let binary = dir.join("tests");
    copy_of_this_binary(&binary);
    let lines: Vec<String> = binds
        .iter()
        .map(|(index, path)| format!("{index}\t{}", path.to_str().unwrap()))
        .collect();
    let child = Command::new("runuser")
        .args(["-u", user, "--", "env"])
        .arg(format!("{BINDS_VAR}={}", lines.join("\n")))
        .arg(&binary)
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    let Ok(output) = receiver.recv_timeout(CHILD_WAIT) else {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        panic!("the child binds did not end within {CHILD_WAIT:?}");
    };
    let output = output.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{output:?}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    stdout
        .lines()
        // libtest may print the test's name on the line of its first output.
        .filter_map(|line| line.split_once(RESULT_PREFIX).map(|(_, rest)| rest))
        .map(|line| {
            let mut parts = line.trim_start_matches('\t').splitn(2, '\t');
            let index = parts.next().unwrap().parse().unwrap();
            (index, parts.next().unwrap_or_default().to_owned())
        })
        .collect()
}

/// The child's binds: each line of `SKYOAUTH_IT_SOCKET_PATH_BINDS` bound
/// for this process's UID, its result printed. Without the variable it
/// does nothing (it runs as the service UID in a child process of
/// [`socket_path_fixture_cases_match_the_services_bind`]).
#[tokio::test]
async fn socket_path_binds_as_the_service_uid() {
    let Ok(binds) = env::var(BINDS_VAR) else {
        return;
    };
    for line in binds.lines() {
        let (index, path) = line.split_once('\t').expect("index and path");
        let outcome = bind_outcome(Path::new(path), None).await;
        println!("{RESULT_PREFIX}\t{index}\t{outcome}");
    }
}

#[test]
fn socket_path_fixture_constants_are_the_services() {
    let fixture = fixture();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "local_socket_path");
    assert_eq!(fixture["status"], "proposed");
    assert_eq!(text(&fixture, "socket_mode"), "0600");
    assert_eq!(fixture["max_symlinks"], 40);
    let platform = if cfg!(any(target_os = "linux", target_os = "android")) {
        "linux"
    } else {
        "other_unix"
    };
    assert_eq!(
        fixture["max_socket_path_bytes"][platform],
        u64::try_from(MAX_SOCKET_PATH_BYTES).unwrap()
    );
    // Every outcome's bind is a result `bind_outcome` names.
    for outcome in list(&fixture, "outcomes") {
        assert!(
            [
                "ok",
                "InvalidPath",
                "PathTooLong",
                "UnsafeDirectory",
                "UnsafeAncestor",
                "PathOccupied",
                "Io",
            ]
            .contains(&text(outcome, "bind")),
            "{outcome}"
        );
    }
}

/// Every case the process can run: its tree built, the transport bound at
/// its path, the result compared with the case's outcome.
#[test]
fn socket_path_fixture_cases_match_the_services_bind() {
    let fixture = fixture();
    let base = TempDir::new();
    let uid = fs::symlink_metadata(&base.0).unwrap().uid();
    let peer = if uid == 0 {
        env::var(PEER_USER_VAR).ok()
    } else {
        None
    };
    let service = match (&peer, uid) {
        (Some(user), 0) => uid_of(user),
        (None, 0) => SERVICE_WITHOUT_PEER,
        (_, own) => own,
    };
    // Root gives entries to it; it is neither root nor the service UID.
    let other = if service == 65_533 { 65_532 } else { 65_533 };
    let roles = Roles {
        root: uid == 0,
        service,
        other,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut ran = 0;
    let mut skipped: Vec<String> = Vec::new();
    let mut in_child: Vec<(usize, PathBuf)> = Vec::new();
    let cases = list(&fixture, "cases");
    for (index, case) in cases.iter().enumerate() {
        let name = text(case, "case");
        if !BINDS_SUPPORTED && expected_bind(&fixture, case) == "ok" {
            skipped.push(format!(
                "{name} (a successful bind, on a target the service does not bind on)"
            ));
            continue;
        }
        let side = side_of(case, &roles, peer.is_some());
        if let Side::Skipped(why) = side {
            skipped.push(format!("{name} ({why})"));
            continue;
        }
        let root = base.0.join(index.to_string());
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        build(&root, case, &roles);
        let path = padded(&root, case, text(case, "path"));
        match side {
            Side::Here(service) => {
                let got = runtime.block_on(bind_outcome(&path, service));
                let expected = expected_bind(&fixture, case);
                assert_eq!(got, expected, "{name}");
                ran += 1;
            }
            Side::Child => in_child.push((index, path)),
            Side::Skipped(_) => unreachable!(),
        }
    }
    if let Some(user) = &peer
        && !in_child.is_empty()
    {
        let results = binds_as(user, &base.0, &in_child);
        let indexes: Vec<usize> = results.iter().map(|(index, _)| *index).collect();
        let wanted: Vec<usize> = in_child.iter().map(|(index, _)| *index).collect();
        assert_eq!(indexes, wanted, "{results:?}");
        for (index, got) in results {
            let case = &cases[index];
            let expected = expected_bind(&fixture, case);
            assert_eq!(got, expected, "{} (as {user})", text(case, "case"));
            ran += 1;
        }
    }
    assert!(ran > 0, "no case ran");
    if !skipped.is_empty() {
        eprintln!(
            "NOTICE: {} of {} socket path cases were NOT bound by the service: {}",
            skipped.len(),
            cases.len(),
            skipped.join(", ")
        );
    }
}

/// Every case's bind is one the fixture's outcomes name, and each outcome
/// is used: a case or outcome no reader handles fails here.
#[test]
fn socket_path_fixture_outcomes_are_complete() {
    let fixture = fixture();
    let outcomes: Vec<&str> = list(&fixture, "outcomes")
        .iter()
        .map(|outcome| text(outcome, "expect"))
        .collect();
    let mut used = std::collections::BTreeSet::new();
    for case in list(&fixture, "cases") {
        expected_bind(&fixture, case);
        used.insert(text(case, "expect"));
    }
    assert_eq!(used, outcomes.into_iter().collect());
}
