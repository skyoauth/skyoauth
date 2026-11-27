//! The checks of the deployment-local transport's socket path
//! (`skyoauth_operator::local::check_socket`, [`CheckedSocketPath`],
//! [`LocalClient::new`]) against the shared fixture
//! `tests/conformance/fixtures/_wire/socket_path.v1.json`, whose trees the
//! `pg` target of `skyoauth-scenarios` binds the service's transport in
//! (`tests/harness/socket_path_fixture.rs`), so the client's copy of the
//! service's rules cannot drift from them.
//!
//! - every case of the fixture: its tree built in a fresh case root under
//!   the system's temporary directory, its path checked, the outcome
//!   compared; the cases a process that is not root cannot build (an entry
//!   of root or of another UID, or a `root_only` case decided by the case
//!   root's owner) are skipped with a printed NOTICE;
//! - the client with the checks connects to a safe socket, and does not
//!   connect at all to a refused one ([`NotSent::Path`]);
//! - the client's own rule for the socket's directory (no sticky
//!   exemption: a socket in the system's `/tmp` is refused), the owner
//!   check (as root), the trust sets, a relative path, and that no error
//!   shows the path.
//!
//! The comparison after the connect ([`PathProblem::Changed`]) is checked
//! by the module's own unit tests, which can act between the check and
//! the connect. Unix only, like the module; each wait is bounded and no
//! test polls.

use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{MetadataExt as _, PermissionsExt as _},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::Duration,
};

use serde_json::Value;
use skyoauth_operator::local::{
    AncestorTrust, CallError, CheckedSocketPath, Connector as _, ErrorCode, LocalClient,
    MAX_SOCKET_PATH_BYTES, MAX_SYMLINKS, NotSent, PathError, PathProblem, ResponseRequest,
    SOCKET_MODE, SocketExpectations, Timeouts, check_socket,
};

use crate::support::{fixtures_dir, list, text};

/// The fixture file under `_wire/`.
pub const SOCKET_PATH_FIXTURE: &str = "socket_path.v1.json";

/// The service UID of the cases when the test runs as root: any UID but
/// root's.
const SERVICE_AS_ROOT: u32 = 65_534;

/// The other UID of the cases when the test runs as root.
const OTHER_AS_ROOT: u32 = 65_533;

/// Timeouts no fake server that answers comes close to.
const PATIENT: Timeouts = Timeouts {
    total: Duration::from_secs(10),
    idle: Duration::from_secs(10),
};

/// Every outcome class of the fixture, with the problem it names (none
/// for `accept`).
const CLASSES: [&str; 12] = [
    "accept",
    "invalid_path",
    "too_long",
    "unsafe_directory",
    "shared_directory",
    "unsafe_ancestor",
    "too_many_symlinks",
    "lookup",
    "missing",
    "not_a_socket",
    "wrong_owner",
    "wrong_mode",
];

/// The outcomes a process that is not root can still compare in a
/// `root_only` case: decided before the walk reaches the case root, whose
/// owner it cannot make root.
const DECIDED_BEFORE_THE_WALK: [&str; 3] = ["invalid_path", "too_long", "unsafe_directory"];

/// The most symbolic links the kernel follows in one lookup: 40 on Linux,
/// as the fixture's (and the service's) walk; 32 on the BSDs and macOS
/// (`MAXSYMLINKS`), whose kernel fails a longer lookup itself.
#[cfg(any(target_os = "linux", target_os = "android"))]
const KERNEL_MAX_SYMLINKS: u64 = 40;
/// The most symbolic links the kernel follows in one lookup: 40 on Linux,
/// as the fixture's (and the service's) walk; 32 on the BSDs and macOS
/// (`MAXSYMLINKS`), whose kernel fails a longer lookup itself.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const KERNEL_MAX_SYMLINKS: u64 = 32;

/// The fixture, parsed.
pub fn socket_path_fixture() -> Value {
    let path = fixtures_dir().join("_wire").join(SOCKET_PATH_FIXTURE);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// A fresh directory under the system's temporary directory, its symbolic
/// links resolved (the fixture's `case_root`: macOS's lives under `/var`, a
/// link to `private/var`, which would add to a case's own links), mode
/// 0755, removed when dropped. Its name is short: macOS's temporary
/// directory is long and its socket paths end at 103 bytes.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "sko-path-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        Self(path)
    }

    /// The owner of the directory: the process's effective UID.
    fn uid(&self) -> u32 {
        fs::symlink_metadata(&self.0).unwrap().uid()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The UIDs of the fixture's roles for this process: as root, the service
/// and the other UID are given away with `lchown`; otherwise the service
/// is the process's own UID and no other role can be made.
struct Roles {
    root: bool,
    service: u32,
}

impl Roles {
    fn of(uid: u32) -> Self {
        if uid == 0 {
            Self {
                root: true,
                service: SERVICE_AS_ROOT,
            }
        } else {
            Self {
                root: false,
                service: uid,
            }
        }
    }

    /// The UID of `role`, if this process can give an entry to it.
    fn uid(&self, role: &str) -> Option<u32> {
        match (role, self.root) {
            ("service", _) => Some(self.service),
            ("root", true) => Some(0),
            ("other", true) => Some(OTHER_AS_ROOT),
            ("root" | "other", false) => None,
            _ => panic!("unknown role {role:?}"),
        }
    }

    /// Whether this process can build `case` as the fixture describes it
    /// (see the fixture's `case_root`).
    fn can_run(&self, case: &Value) -> bool {
        if self.root {
            return true;
        }
        let own = list(case, "entries")
            .iter()
            .all(|entry| text(entry, "owner") == "service");
        let trust_ok = match text(case, "trust") {
            "service_or_root" => true,
            "root_only" => DECIDED_BEFORE_THE_WALK.contains(&text(case, "expect")),
            other => panic!("unknown trust {other:?}"),
        };
        own && trust_ok
    }
}

/// The permission bits of an octal mode string, `"0755"` say.
fn mode_of(mode: &str) -> u32 {
    assert!(mode.starts_with('0'), "{mode:?}: an octal mode with its 0");
    u32::from_str_radix(mode, 8).unwrap_or_else(|err| panic!("{mode:?}: {err}"))
}

/// The trust of a case.
fn trust_of(case: &Value) -> AncestorTrust {
    match text(case, "trust") {
        "service_or_root" => AncestorTrust::ServiceOrRoot,
        "root_only" => AncestorTrust::RootOnly,
        other => panic!("unknown trust {other:?}"),
    }
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
    let path = PathBuf::from(path);
    assert_eq!(path.as_os_str().len(), length);
    path
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

/// Builds the entries of `case` in `root` with the UIDs of `roles`.
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
                assert!(links >= 1, "{entry}");
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
                        // The next link, by its name in the same directory.
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

/// The fixture class of a result of [`check_socket`], with the kind of a
/// lookup's error.
fn class(result: Result<(), PathError>) -> (&'static str, Option<io::ErrorKind>) {
    let Err(err) = result else {
        return ("accept", None);
    };
    let class = match err.problem() {
        PathProblem::InvalidPath => "invalid_path",
        PathProblem::TooLong => "too_long",
        PathProblem::UnsafeDirectory => "unsafe_directory",
        PathProblem::SharedDirectory => "shared_directory",
        PathProblem::UnsafeAncestor => "unsafe_ancestor",
        PathProblem::TooManySymlinks => "too_many_symlinks",
        PathProblem::Lookup(kind) => return ("lookup", Some(kind)),
        PathProblem::Missing => "missing",
        PathProblem::NotASocket => "not_a_socket",
        PathProblem::WrongOwner => "wrong_owner",
        PathProblem::WrongMode => "wrong_mode",
        other => panic!("check_socket never gives {other:?}"),
    };
    (class, None)
}

/// The kind of a lookup case's `io_kind`.
fn io_kind(case: &Value) -> io::ErrorKind {
    match text(case, "io_kind") {
        "NotFound" => io::ErrorKind::NotFound,
        "NotADirectory" => io::ErrorKind::NotADirectory,
        other => panic!("unknown io_kind {other:?}"),
    }
}

/// The links of the case's longest `symlink_chain`, 0 without one.
fn chain_links(case: &Value) -> u64 {
    list(case, "entries")
        .iter()
        .filter(|entry| text(entry, "type") == "symlink_chain")
        .map(|entry| entry["links"].as_u64().expect("links is an integer"))
        .max()
        .unwrap_or(0)
}

/// Runs every case this process can build, each in a fresh case root,
/// and returns the names of the cases run and of those skipped.
pub fn run_socket_path_cases(fixture: &Value) -> (BTreeSet<String>, BTreeSet<String>) {
    let probe = TempDir::new();
    let roles = Roles::of(probe.uid());
    drop(probe);
    let mut ran = BTreeSet::new();
    let mut skipped = BTreeSet::new();
    for case in list(fixture, "cases") {
        let name = text(case, "case").to_owned();
        if !roles.can_run(case) {
            skipped.insert(name);
            continue;
        }
        let root = TempDir::new();
        build(&root.0, case, &roles);
        let expectations = SocketExpectations {
            owner_uid: roles.service,
            ancestors: trust_of(case),
        };
        let path = padded(&root.0, case, text(case, "path"));
        let result = check_socket(&path, &expectations);
        if let Ok(checked) = &result {
            assert_eq!(checked.path(), path.as_path(), "{name}");
        }
        let (got, kind) = class(result.map(drop));
        let expect = text(case, "expect");
        if expect == "accept" && chain_links(case) > KERNEL_MAX_SYMLINKS {
            // The fixture's walk follows up to 40 links; a kernel that
            // follows fewer fails the lookup of the socket's directory
            // first (its error's kind is the platform's: not compared),
            // and could not connect either.
            eprintln!(
                "NOTICE: {name}: this kernel follows at most {KERNEL_MAX_SYMLINKS} symbolic \
                 links: expected refused as lookup, not accept"
            );
            assert_eq!(got, "lookup", "{name}");
            ran.insert(name);
            continue;
        }
        assert_eq!(
            got, expect,
            "{name}: (an accept case refused as unsafe_ancestor may mean that a directory above \
             the system's temporary directory is unsafe)"
        );
        if expect == "lookup" {
            assert_eq!(kind, Some(io_kind(case)), "{name}");
        } else {
            assert!(case.get("io_kind").is_none(), "{name}");
        }
        ran.insert(name);
    }
    (ran, skipped)
}

#[test]
fn socket_path_fixture_envelope_matches_the_crate() {
    let fixture = socket_path_fixture();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "local_socket_path");
    assert_eq!(fixture["status"], "proposed");
    assert_eq!(mode_of(text(&fixture, "socket_mode")), SOCKET_MODE);
    assert_eq!(SOCKET_MODE, 0o600);
    assert_eq!(fixture["max_symlinks"], u64::from(MAX_SYMLINKS));
    let limits = &fixture["max_socket_path_bytes"];
    assert_eq!(limits["linux"], 107);
    assert_eq!(limits["other_unix"], 103);
    let platform = if cfg!(any(target_os = "linux", target_os = "android")) {
        "linux"
    } else {
        "other_unix"
    };
    assert_eq!(
        limits[platform],
        u64::try_from(MAX_SOCKET_PATH_BYTES).unwrap()
    );
    // The outcomes, in the fixture's order, are exactly the classes here,
    // each with its service bind result.
    let outcomes: Vec<&str> = list(&fixture, "outcomes")
        .iter()
        .map(|outcome| text(outcome, "expect"))
        .collect();
    assert_eq!(outcomes, CLASSES);
}

#[test]
fn socket_path_cases_match_check_socket() {
    let fixture = socket_path_fixture();
    let (ran, skipped) = run_socket_path_cases(&fixture);
    assert!(!ran.is_empty());
    if !skipped.is_empty() {
        eprintln!(
            "NOTICE: {} of {} socket path cases were NOT run: they need root (an entry of root \
             or of another UID, or a root-owned case root): {}",
            skipped.len(),
            ran.len() + skipped.len(),
            skipped.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
}

/// The members of a JSON object.
fn members(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .map(String::as_str)
        .collect()
}

/// The fixture's members, outcomes, cases and entries are exactly what
/// this module reads, every outcome has a case, and every case is run or
/// skipped.
#[test]
fn every_socket_path_member_and_case_is_covered() {
    let fixture = socket_path_fixture();
    assert_eq!(
        members(&fixture),
        BTreeSet::from([
            "fixture_version",
            "kind",
            "status",
            "description",
            "socket_mode",
            "max_symlinks",
            "max_socket_path_bytes",
            "roles",
            "trust",
            "case_root",
            "outcomes",
            "cases",
        ])
    );
    assert_eq!(
        members(&fixture["max_socket_path_bytes"]),
        BTreeSet::from(["linux", "other_unix"])
    );
    assert_eq!(
        members(&fixture["roles"]),
        BTreeSet::from(["service", "root", "other"])
    );
    assert_eq!(
        members(&fixture["trust"]),
        BTreeSet::from(["service_or_root", "root_only"])
    );
    for outcome in list(&fixture, "outcomes") {
        // `bind_io_kind`, the service's error kind, is the harness's: here
        // only its place is checked.
        let mut allowed = BTreeSet::from(["expect", "bind", "applies_when"]);
        if outcome.get("bind_io_kind").is_some() {
            assert_eq!(text(outcome, "bind"), "Io", "{outcome}");
            allowed.insert("bind_io_kind");
        }
        assert_eq!(members(outcome), allowed, "{outcome}");
    }
    let cases = list(&fixture, "cases");
    let mut names = BTreeSet::new();
    let mut expected = BTreeSet::new();
    for case in cases {
        let name = text(case, "case");
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_')),
            "case name {name:?}"
        );
        assert!(names.insert(name.to_owned()), "{name} twice");
        let mut allowed = BTreeSet::from(["case", "trust", "entries", "path", "expect"]);
        for optional in ["pad", "io_kind"] {
            if case.get(optional).is_some() {
                allowed.insert(optional);
            }
        }
        assert_eq!(members(case), allowed, "{name}");
        assert_eq!(
            case.get("io_kind").is_some(),
            text(case, "expect") == "lookup"
        );
        trust_of(case);
        expected.insert(text(case, "expect"));
        for entry in list(case, "entries") {
            let shape: &[&str] = match text(entry, "type") {
                "dir" | "file" | "socket" => &["path", "type", "mode", "owner"],
                "symlink" => &["path", "type", "target", "owner"],
                "symlink_chain" => &["path", "type", "links", "target", "owner"],
                other => panic!("{name}: unknown entry type {other:?}"),
            };
            assert_eq!(
                members(entry),
                shape.iter().copied().collect::<BTreeSet<_>>(),
                "{name}"
            );
            assert!(
                ["service", "root", "other"].contains(&text(entry, "owner")),
                "{name}"
            );
        }
    }
    // Every class has a case, and no case another class.
    assert_eq!(expected, CLASSES.into_iter().collect::<BTreeSet<_>>());
    // Both trust sets accept something and refuse something.
    for trust in ["service_or_root", "root_only"] {
        let of = |accept: bool| {
            cases.iter().any(|case| {
                text(case, "trust") == trust && (text(case, "expect") == "accept") == accept
            })
        };
        assert!(of(true) && of(false), "{trust}");
    }
    let (ran, skipped) = run_socket_path_cases(&fixture);
    assert!(ran.is_disjoint(&skipped));
    assert_eq!(ran.union(&skipped).cloned().collect::<BTreeSet<_>>(), names);
}

/// A listening socket at `path`, mode 0600.
fn listen(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

/// A preview request with no meaning: the fake servers answer it with a
/// refusal.
fn response() -> ResponseRequest {
    ResponseRequest {
        operation_id: "op_1".to_owned(),
        signature: [7; 64],
    }
}

/// The client with the checks connects to a safe socket: the server reads
/// one line and the end of the stream, and its refusal comes back.
#[test]
fn the_checked_client_reaches_a_safe_socket() {
    let dir = TempDir::new();
    let path = dir.0.join("s");
    let listener = listen(&path);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(PATIENT.total)).unwrap();
        let mut request = Vec::new();
        let _ = stream.read_to_end(&mut request);
        let _ = stream.write_all(b"{\"error\":\"conflict\"}\n");
        request
    });
    let client = LocalClient::new(
        &path,
        SocketExpectations {
            owner_uid: dir.uid(),
            ancestors: AncestorTrust::ServiceOrRoot,
        },
        PATIENT,
    );
    let result = client.preview(&response());
    if result != Err(CallError::Refused(ErrorCode::Conflict)) {
        // Not connected: let the server's accept return before failing.
        drop(UnixStream::connect(&path));
    }
    let request = server.join().unwrap();
    assert_eq!(result.unwrap_err(), CallError::Refused(ErrorCode::Conflict));
    assert_eq!(request.iter().filter(|&&b| b == b'\n').count(), 1);
    assert!(request.ends_with(b"\n"));
}

/// A socket the checks refuse is never connected to: the call is not sent,
/// by the problem, and the listener has no connection waiting.
#[test]
fn a_refused_socket_is_never_connected() {
    let dir = TempDir::new();
    let path = dir.0.join("s");
    let listener = listen(&path);
    listener.set_nonblocking(true).unwrap();
    let own = dir.uid();
    // Another owner than the socket's is tried as root
    // (`the_socket_must_be_the_expected_owners`): here, a directory of the
    // process's own UID is not another owner's to trust.
    for (mode, problem) in [
        (0o644, PathProblem::WrongMode),
        (0o640, PathProblem::WrongMode),
    ] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let expectations = SocketExpectations {
            owner_uid: own,
            ancestors: AncestorTrust::ServiceOrRoot,
        };
        let client = LocalClient::new(&path, expectations, PATIENT);
        assert_eq!(
            client.preview(&response()).unwrap_err(),
            CallError::NotSent(NotSent::Path(problem)),
            "{problem:?}"
        );
        // The connector alone carries the problem in its error.
        let err = CheckedSocketPath::new(&path, expectations)
            .connect()
            .unwrap_err();
        let carried = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<PathError>())
            .expect("the error carries the problem");
        assert_eq!(carried.problem(), problem);
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            listener.accept().map(drop).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "{problem:?}: connected"
        );
    }
    // Nothing at the path: missing, and not connected either.
    fs::remove_file(&path).unwrap();
    let client = LocalClient::new(
        &path,
        SocketExpectations {
            owner_uid: own,
            ancestors: AncestorTrust::ServiceOrRoot,
        },
        PATIENT,
    );
    assert_eq!(
        client.preview(&response()).unwrap_err(),
        CallError::NotSent(NotSent::Path(PathProblem::Missing))
    );
}

/// A socket of the process's own UID directly in the system's `/tmp`
/// (root's, sticky and writable by all; resolved: macOS's `/tmp` is a
/// symbolic link, which the checks refuse as the socket's directory):
/// every check of the service passes, but the client requires a private
/// directory ([`PathProblem::SharedDirectory`]) and does not connect. The
/// socket is removed when the test ends: the guard is armed only once the
/// bind has made it, so an entry of another process at that name is never
/// removed.
#[test]
fn a_socket_in_the_systems_tmp_is_refused_as_shared() {
    let tmp = fs::canonicalize("/tmp").unwrap();
    let metadata = fs::symlink_metadata(&tmp).unwrap();
    if metadata.uid() != 0 || metadata.mode() & 0o1022 != 0o1022 {
        eprintln!(
            "NOTICE: {} is not root's, sticky and writable by all: the shared directory was NOT \
             tried in it",
            tmp.display()
        );
        return;
    }
    struct Removed(PathBuf);
    impl Drop for Removed {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let path = tmp.join(format!(
        "skyoauth-operator-shared-{}-{}.sock",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let listener = UnixListener::bind(&path).unwrap();
    // Made by this bind: ours to remove from here on.
    let socket = Removed(path);
    fs::set_permissions(&socket.0, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let expectations = SocketExpectations {
        owner_uid: fs::symlink_metadata(&socket.0).unwrap().uid(),
        ancestors: AncestorTrust::ServiceOrRoot,
    };
    assert_eq!(
        check_socket(&socket.0, &expectations)
            .map(drop)
            .unwrap_err()
            .problem(),
        PathProblem::SharedDirectory
    );
    assert_eq!(
        LocalClient::new(&socket.0, expectations, PATIENT)
            .preview(&response())
            .unwrap_err(),
        CallError::NotSent(NotSent::Path(PathProblem::SharedDirectory))
    );
    assert_eq!(
        listener.accept().map(drop).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "connected"
    );
}

/// A socket in a private directory of root, given to the service UID:
/// accepted for that owner, refused for any other expected owner, root
/// included, without a connection. Root only (a process that is not root
/// has no private directory of root to bind in), else a NOTICE.
#[test]
fn the_socket_must_be_the_expected_owners() {
    let dir = TempDir::new();
    if dir.uid() != 0 {
        eprintln!("NOTICE: the owner check needs root: it was NOT tried");
        return;
    }
    let path = dir.0.join("s");
    let listener = listen(&path);
    listener.set_nonblocking(true).unwrap();
    std::os::unix::fs::lchown(&path, Some(SERVICE_AS_ROOT), None).unwrap();
    let expectations = |owner_uid| SocketExpectations {
        owner_uid,
        ancestors: AncestorTrust::ServiceOrRoot,
    };
    for other in [0, OTHER_AS_ROOT, SERVICE_AS_ROOT + 1] {
        assert_eq!(
            LocalClient::new(&path, expectations(other), PATIENT)
                .preview(&response())
                .unwrap_err(),
            CallError::NotSent(NotSent::Path(PathProblem::WrongOwner)),
            "{other}"
        );
    }
    assert_eq!(
        listener.accept().map(drop).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "connected"
    );
    // For its owner: accepted.
    assert!(check_socket(&path, &expectations(SERVICE_AS_ROOT)).is_ok());
}

/// The service UID's own directory: trusted by
/// [`AncestorTrust::ServiceOrRoot`], refused by [`AncestorTrust::RootOnly`]
/// (as root, the directory and the socket are given to another UID first).
#[test]
fn root_only_refuses_a_directory_of_the_service() {
    let dir = TempDir::new();
    let sub = dir.0.join("d");
    fs::create_dir(&sub).unwrap();
    let path = sub.join("s");
    drop(UnixListener::bind(&path).unwrap());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut service = dir.uid();
    if service == 0 {
        service = SERVICE_AS_ROOT;
        std::os::unix::fs::lchown(&sub, Some(service), None).unwrap();
        std::os::unix::fs::lchown(&path, Some(service), None).unwrap();
    }
    let check = |ancestors| {
        check_socket(
            &path,
            &SocketExpectations {
                owner_uid: service,
                ancestors,
            },
        )
        .map(drop)
        .map_err(|err| err.problem())
    };
    assert_eq!(check(AncestorTrust::ServiceOrRoot), Ok(()));
    assert_eq!(
        check(AncestorTrust::RootOnly),
        Err(PathProblem::UnsafeDirectory)
    );
}

/// A relative path is checked as its absolute form, the working directory
/// joined to it, which must fit the limit too.
#[test]
fn a_relative_path_is_checked_as_its_absolute_form() {
    let cwd = std::env::current_dir().unwrap();
    let length = MAX_SOCKET_PATH_BYTES - 2;
    assert!(cwd.as_os_str().len() > 2);
    let relative = PathBuf::from(format!("x/{}", "p".repeat(length - 2)));
    assert_eq!(relative.as_os_str().len(), length);
    let expectations = SocketExpectations {
        owner_uid: 0,
        ancestors: AncestorTrust::RootOnly,
    };
    assert_eq!(
        check_socket(&relative, &expectations)
            .map(drop)
            .unwrap_err()
            .problem(),
        PathProblem::TooLong
    );
    // A name short enough once absolute is not refused for its length:
    // its directory's name is cut to what the working directory leaves.
    let room = MAX_SOCKET_PATH_BYTES.saturating_sub(cwd.as_os_str().len() + "/".len() + "/s".len());
    if room == 0 {
        eprintln!(
            "NOTICE: the working directory is too long for a relative socket path that fits \
             once absolute: that half was NOT tried"
        );
        return;
    }
    let name = &"x-skyoauth-operator-missing"[..room.min("x-skyoauth-operator-missing".len())];
    let short = PathBuf::from(format!("{name}/s"));
    assert!(cwd.join(&short).as_os_str().len() <= MAX_SOCKET_PATH_BYTES);
    let problem = check_socket(&short, &expectations)
        .map(drop)
        .unwrap_err()
        .problem();
    assert!(
        !matches!(problem, PathProblem::TooLong | PathProblem::InvalidPath),
        "{problem:?}"
    );
}

/// No error shows the path: `Display` is fixed text and `Debug` names the
/// problem only, also through [`NotSent`] and [`CallError`].
#[test]
fn errors_name_no_path() {
    let dir = TempDir::new();
    // Short names: the socket path must fit macOS's 103 bytes too.
    let sentinel = dir.0.join("SENTINEL-D");
    fs::create_dir(&sentinel).unwrap();
    let path = sentinel.join("SENTINEL-S");
    let listener = listen(&path);
    let expectations = SocketExpectations {
        owner_uid: dir.uid(),
        ancestors: AncestorTrust::ServiceOrRoot,
    };
    let checked = check_socket(&path, &expectations).unwrap();
    assert_eq!(format!("{checked:?}"), "CheckedSocket(..)");
    drop(listener);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let err = check_socket(&path, &expectations).unwrap_err();
    let connector = CheckedSocketPath::new(&path, expectations);
    let client = LocalClient::new(&path, expectations, PATIENT);
    let call = client.preview(&response()).unwrap_err();
    let problems = [
        PathProblem::InvalidPath,
        PathProblem::TooLong,
        PathProblem::UnsafeDirectory,
        PathProblem::SharedDirectory,
        PathProblem::UnsafeAncestor,
        PathProblem::TooManySymlinks,
        PathProblem::Lookup(io::ErrorKind::NotFound),
        PathProblem::Missing,
        PathProblem::NotASocket,
        PathProblem::WrongOwner,
        PathProblem::WrongMode,
        PathProblem::Changed,
    ];
    let mut shown = vec![
        err.to_string(),
        format!("{err:?}"),
        call.to_string(),
        format!("{call:?}"),
        format!("{client:?}"),
        format!("{connector:?}"),
        connector.connect().unwrap_err().to_string(),
    ];
    for problem in problems {
        shown.push(problem.to_string());
        shown.push(format!("{problem:?}"));
        shown.push(NotSent::Path(problem).to_string());
        shown.push(CallError::NotSent(NotSent::Path(problem)).to_string());
        assert!(!problem.to_string().is_empty());
    }
    for text in &shown {
        assert!(!text.contains("SENTINEL"), "{text}");
        assert!(!text.contains('/'), "{text}");
    }
    assert_eq!(format!("{err:?}"), "PathError(WrongMode)");
    assert_eq!(format!("{connector:?}"), "CheckedSocketPath(..)");
    assert_eq!(
        err.to_string(),
        "the local socket's permission bits are not exactly 0600"
    );
}
