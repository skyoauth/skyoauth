//! The checks of the transport's socket path before a connection: the
//! client's side of the service's rules for its socket file (the service's
//! `local_transport` module docs, "The socket file", steps 1, 2, 5 and 8,
//! and its `socket.rs`: `write_safe`, `check_directory`,
//! `check_ancestors`), so that the client gives its request, and the
//! signature it carries, only to a socket that the service UID owns with
//! mode 0600, in a directory and below directories that no other UID can
//! change.
//!
//! [`check_socket`] reads the path ([`CheckedSocketPath`] checks it before
//! every connection; [`LocalClient::new`] is the client
//! with these checks, the one a real caller uses). It mirrors the
//! service's bind decision by decision, with the same constants, and adds
//! one stricter rule (the socket's own directory may not be shared, even
//! sticky), so the two agree on every tree but where the fixture lists
//! otherwise (that rule's outcome, and its cases with a
//! `service_expected`): the shared fixture
//! `tests/conformance/fixtures/_wire/socket_path.v1.json` holds known
//! answers that this crate's `operator` target checks against
//! [`check_socket`] and the `pg` target of `skyoauth-scenarios`
//! (`tests/harness/socket_path_fixture.rs`) against the service's own
//! bind. [`check_socket`] lists the checks in the order they are made,
//! [`AncestorTrust`] whom they trust, and [`CheckedSocketPath`] what is
//! left between the check and the connect.
//!
//! `Debug` and `Display` of [`PathError`] and of [`PathProblem`] name the
//! problem only, never the path.
//!
//! The checks read owners and mode bits only: see [`check_socket`],
//! "Access control lists".

use std::{
    ffi::OsString,
    fmt, fs, io,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _},
        net::UnixStream,
    },
    path::{Component, Path, PathBuf},
};

use super::{Connector, LocalClient, NotSent, Timeouts};

/// The socket file's permission bits: exactly 0600 (the service's
/// `SOCKET_MODE`).
pub const SOCKET_MODE: u32 = 0o600;

/// The most symbolic links the walk of the socket's directory follows, as
/// the service's walk (and Linux's own lookup) does.
pub const MAX_SYMLINKS: u32 = 40;

/// The longest socket path, in bytes: one under the size of
/// `sockaddr_un.sun_path`, which also holds the terminating NUL (108 bytes
/// on Linux, so 107; the service's `MAX_SOCKET_PATH_BYTES`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub const MAX_SOCKET_PATH_BYTES: usize = 107;
/// The longest socket path, in bytes: one under the size of
/// `sockaddr_un.sun_path`, which also holds the terminating NUL (104 bytes
/// on the BSDs and macOS, so 103; the service's `MAX_SOCKET_PATH_BYTES`).
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub const MAX_SOCKET_PATH_BYTES: usize = 103;

/// The permission bits of a mode.
const PERMISSION_BITS: u32 = 0o7777;

/// The group and other write bits of a mode.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// The sticky bit of a mode.
const STICKY: u32 = 0o1000;

/// Which owners the client trusts with the directories on the way to the
/// socket.
///
/// The service trusts root and the service UID with the directories when
/// it binds as the service UID, and root alone when root binds for another
/// UID (its `check_ancestors`): the service UID could otherwise point the
/// path elsewhere while root gives the socket away. The client cannot
/// tell which way the socket was bound, so the caller picks.
/// [`AncestorTrust::ServiceOrRoot`], the usual case (a service that runs
/// as its own UID), is an inferred pick: no ruling fixes the client's trust
/// set. [`AncestorTrust::RootOnly`] is the stricter option, for a socket
/// root binds for the service UID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AncestorTrust {
    /// Root and the socket's expected owner, as the service trusts them
    /// when it binds as its own UID. An inferred pick: no ruling fixes the
    /// client's trust set.
    ServiceOrRoot,
    /// Root alone, as the service trusts it when root binds for another
    /// service UID: the stricter option.
    RootOnly,
}

/// What the client expects of the socket: its owner, and whom it trusts
/// with the directories on the way. The socket's permission bits are
/// always exactly [`SOCKET_MODE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketExpectations {
    /// The service UID, which must own the socket. The standard library
    /// cannot read the process's own UID, so the caller gives it.
    pub owner_uid: u32,
    /// Whom the client trusts with the directories.
    pub ancestors: AncestorTrust,
}

impl SocketExpectations {
    /// Whether `uid` may own a directory on the way, or a symbolic link in
    /// a sticky directory others may write.
    const fn trusts(&self, uid: u32) -> bool {
        match self.ancestors {
            AncestorTrust::ServiceOrRoot => uid == 0 || uid == self.owner_uid,
            AncestorTrust::RootOnly => uid == 0,
        }
    }
}

/// Why [`check_socket`] refused a socket path (see [`check_socket`] for
/// the order of the checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathProblem {
    /// The path ends in `/` or `/.`, or has no parent directory or no name.
    InvalidPath,
    /// The path is longer than [`MAX_SOCKET_PATH_BYTES`].
    TooLong,
    /// The socket's directory is a symbolic link or not a directory, has
    /// an owner the client does not trust, or is writable by group or
    /// others without the sticky bit; or the walk of its lookup did not end
    /// at it.
    UnsafeDirectory,
    /// The socket's own directory passed the service's checks but is
    /// writable by group or others, with the sticky bit (as `/tmp`): the
    /// client requires a private directory, where the service accepts a
    /// sticky one.
    SharedDirectory,
    /// A directory the lookup passes through has an owner the client does
    /// not trust or is writable by group or others without the sticky bit,
    /// or a symbolic link on the way, in a sticky directory others may
    /// write, has an owner the client does not trust.
    UnsafeAncestor,
    /// The lookup follows more than [`MAX_SYMLINKS`] symbolic links.
    TooManySymlinks,
    /// A lookup on the way failed, with the error's kind: of the socket's
    /// directory or of a directory above it (a missing entry, a file where
    /// a directory should be, a directory that may not be searched), of
    /// the socket path itself (anything but a missing entry, which is
    /// [`PathProblem::Missing`]), or of the working directory for a
    /// relative path.
    Lookup(io::ErrorKind),
    /// Nothing is at the socket path.
    Missing,
    /// The socket path holds something other than a socket: a file, a
    /// directory, a symbolic link.
    NotASocket,
    /// The socket's owner is not [`SocketExpectations::owner_uid`].
    WrongOwner,
    /// The socket's permission bits are not exactly [`SOCKET_MODE`].
    WrongMode,
    /// The socket path no longer held the checked socket after the
    /// connect; the connection was dropped before anything was written.
    Changed,
}

impl PathProblem {
    /// The fixed text of the problem.
    const fn text(self) -> &'static str {
        match self {
            Self::InvalidPath => {
                "the local socket path names a directory, or has no directory or name"
            }
            Self::TooLong => "the local socket path is too long for a Unix socket address",
            Self::UnsafeDirectory => {
                "the local socket's directory is a symbolic link, is not owned by a trusted UID, \
                 or is writable by group or others without the sticky bit"
            }
            Self::SharedDirectory => {
                "the local socket's directory is writable by group or others: the client \
                 requires a private directory"
            }
            Self::UnsafeAncestor => {
                "a directory above the local socket is not owned by a trusted UID or is writable \
                 by group or others without the sticky bit, or holds a symbolic link of another \
                 owner on the way"
            }
            Self::TooManySymlinks => {
                "the lookup of the local socket's directory follows too many symbolic links"
            }
            Self::Lookup(_) => "a lookup on the way to the local socket failed",
            Self::Missing => "nothing is at the local socket path",
            Self::NotASocket => "the local socket path holds something other than a socket",
            Self::WrongOwner => "the local socket is not owned by the service UID",
            Self::WrongMode => "the local socket's permission bits are not exactly 0600",
            Self::Changed => "the local socket path changed between its check and the connect",
        }
    }

    /// The kind of the [`io::Error`] that carries the problem out of a
    /// [`Connector`].
    const fn kind(self) -> io::ErrorKind {
        match self {
            Self::InvalidPath | Self::TooLong => io::ErrorKind::InvalidInput,
            Self::Lookup(kind) => kind,
            Self::Missing => io::ErrorKind::NotFound,
            Self::UnsafeDirectory
            | Self::SharedDirectory
            | Self::UnsafeAncestor
            | Self::TooManySymlinks
            | Self::NotASocket
            | Self::WrongOwner
            | Self::WrongMode
            | Self::Changed => io::ErrorKind::PermissionDenied,
        }
    }
}

impl fmt::Display for PathProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text())
    }
}

/// A socket path [`check_socket`] refused, by [`PathProblem`]. `Debug`
/// and `Display` name the problem only, never the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathError(PathProblem);

impl PathError {
    /// Why the path was refused.
    pub const fn problem(&self) -> PathProblem {
        self.0
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.text())
    }
}

impl std::error::Error for PathError {}

impl From<PathProblem> for PathError {
    fn from(problem: PathProblem) -> Self {
        Self(problem)
    }
}

/// A refusal of the lookup with the error's kind.
fn lookup(err: &io::Error) -> PathError {
    PathError(PathProblem::Lookup(err.kind()))
}

/// The socket [`check_socket`] accepted: its absolute path and what it was
/// when checked, to be compared after the connect.
///
/// `Debug` prints `CheckedSocket(..)`, not the path.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckedSocket {
    path: PathBuf,
    identity: Identity,
}

/// What the read of the socket path after the connect compares with the
/// checked socket (see [`CheckedSocketPath`], "Between the check and the
/// connect"): every field must be equal.
#[derive(Clone, Copy)]
struct Identity {
    socket: bool,
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    ctime: i64,
    ctime_nsec: i64,
}

impl Identity {
    /// The identity of `metadata`, of a path not followed.
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            socket: metadata.file_type().is_socket(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode() & PERMISSION_BITS,
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.socket == other.socket
            && self.dev == other.dev
            && self.ino == other.ino
            && self.uid == other.uid
            && self.mode == other.mode
            && self.ctime == other.ctime
            && self.ctime_nsec == other.ctime_nsec
    }
}

impl Eq for Identity {}

impl fmt::Debug for CheckedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckedSocket(..)")
    }
}

impl CheckedSocket {
    /// The absolute path that was checked, which the connect uses.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether `metadata`, of the socket path not followed, is still the
    /// checked socket: the same file type, device, inode, owner,
    /// permission bits and change time.
    fn is(&self, metadata: &fs::Metadata) -> bool {
        Identity::of(metadata) == self.identity
    }
}

/// Whether a directory's `mode` lets only its owner rename entries in it:
/// no group or other write bit, or the sticky bit (as `/tmp`).
const fn write_safe(mode: u32) -> bool {
    mode & GROUP_OTHER_WRITE == 0 || mode & STICKY != 0
}

/// Checks the socket at `path` against `expectations` and returns it, with
/// the absolute path to connect to. In the order they are made:
///
/// 1. a path that ends in `/` or `/.` names a directory, and one without a
///    parent or a name (`/`, `..` at its end) names no socket:
///    [`PathProblem::InvalidPath`];
/// 2. a path over [`MAX_SOCKET_PATH_BYTES`] (107 bytes on Linux, 103 on
///    the BSDs and macOS: `sockaddr_un.sun_path` less its NUL) fits no
///    Unix socket address: [`PathProblem::TooLong`];
/// 3. a relative path is joined to the working directory, read once, as
///    the service's bind does; the checks and the connect use that one
///    absolute path, which must fit the limit too (the service measures
///    the path as given; it reaches its socket through an open directory,
///    which a client without `unsafe` cannot);
/// 4. the socket's directory, looked up without following its own last
///    component, must be a directory (a symbolic link or a file there is
///    [`PathProblem::UnsafeDirectory`]), owned by a trusted UID
///    ([`AncestorTrust`]), and not writable by group or others unless
///    sticky (as `/tmp`);
/// 5. the lookup of the socket's directory is walked from the root
///    directory, entry by entry, following each symbolic link as the
///    kernel does (at most [`MAX_SYMLINKS`], 40, else
///    [`PathProblem::TooManySymlinks`]; `..` after a link is the link
///    target's parent, not the lexical one): every directory an entry or
///    `..` is looked up in, the root directory included, must be owned by
///    a trusted UID and not writable by group or others unless sticky, and
///    a symbolic link in a directory others may write (sticky) must be a
///    trusted UID's too, since its owner could replace it
///    ([`PathProblem::UnsafeAncestor`]). A lookup that fails on the way (a
///    missing entry, a file where a directory should be) is
///    [`PathProblem::Lookup`]. The walk must end at the directory of step
///    4 (same device and inode), else [`PathProblem::UnsafeDirectory`];
/// 6. stricter than the service: the socket's own directory must have no
///    group or other write bit at all, the sticky bit notwithstanding,
///    else [`PathProblem::SharedDirectory`] (the sticky bit's exemption
///    holds for the directories above it only). The service binds in a
///    sticky directory such as `/tmp`, where any UID may create an entry
///    at the socket's name while it is vacant; the client does not
///    connect there, so a deployment gives the socket a private directory
///    (owned by root or the service UID, mode 0755 or narrower). Decided
///    after the walk, so a path the service refuses is refused for the
///    service's reason;
/// 7. the socket path itself, not followed: nothing there is
///    [`PathProblem::Missing`]; anything but a socket (a file, a directory,
///    a symbolic link, to a socket or not) is [`PathProblem::NotASocket`];
///    a socket of another owner than [`SocketExpectations::owner_uid`] is
///    [`PathProblem::WrongOwner`]; and its permission bits (sticky, setuid
///    and setgid included) must be exactly [`SOCKET_MODE`], 0600, else
///    [`PathProblem::WrongMode`].
///
/// Where the service decides by the open directory (Linux), the client
/// decides by the path: on Linux the service refuses a socket directory it
/// cannot open without following a symbolic link, and walks the lookup
/// when the open fails, so a failed lookup of the directory is reported as
/// the walk reports it; the client does the same. The service's other
/// refusals (a lock file, a live listener, a bind for another UID by a
/// process that is not root) concern its bind only.
///
/// # Access control lists
///
/// The checks read owners and mode bits only. Linux shows a POSIX access
/// control list's grants in a file's group bits (the list's mask), so a
/// directory an ACL lets others write is refused like a group-writable
/// one. macOS does not: an ACL there can let another UID write to a
/// directory whose mode bits show no write bit, and the standard library
/// cannot read ACLs, so the checks cannot see that. macOS is a client and
/// test platform of the operator only; the service binds its socket on
/// Linux.
///
/// # Errors
///
/// [`PathError`], naming the first check that refused the path.
pub fn check_socket(
    path: &Path,
    expectations: &SocketExpectations,
) -> Result<CheckedSocket, PathError> {
    // A path that ends in `/` or `/.` names a directory, which the
    // accessors below would drop (`admin.sock/` has the name `admin.sock`).
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.ends_with(b"/") || bytes.ends_with(b"/.") {
        return Err(PathProblem::InvalidPath.into());
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(PathProblem::InvalidPath.into());
    };
    if path.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
        return Err(PathProblem::TooLong.into());
    }
    // One absolute path, the working directory joined to a relative one,
    // for the checks and the connect: the working directory is read once.
    let parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| lookup(&err))?
            .join(parent)
    };
    let socket = parent.join(name);
    if socket.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
        return Err(PathProblem::TooLong.into());
    }
    check_parent(&parent, expectations)?;
    let metadata = match fs::symlink_metadata(&socket) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(PathProblem::Missing.into());
        }
        // The socket path itself could not be read (not its directory).
        Err(err) => return Err(lookup(&err)),
    };
    if !metadata.file_type().is_socket() {
        return Err(PathProblem::NotASocket.into());
    }
    if metadata.uid() != expectations.owner_uid {
        return Err(PathProblem::WrongOwner.into());
    }
    if metadata.mode() & PERMISSION_BITS != SOCKET_MODE {
        return Err(PathProblem::WrongMode.into());
    }
    Ok(CheckedSocket {
        path: socket,
        identity: Identity::of(&metadata),
    })
}

/// Checks the socket's directory `parent`, an absolute path, as the
/// service's bind opens and checks it: the directory itself, not followed
/// ([`check_directory`]), then the walk of its lookup
/// ([`check_ancestors`]), which must end at it. A directory that cannot be
/// looked up is reported as the walk reports it, if the walk refuses it,
/// else by the lookup's error.
fn check_parent(parent: &Path, expectations: &SocketExpectations) -> Result<(), PathError> {
    let metadata = match fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(err) => {
            check_ancestors(parent, expectations)?;
            return Err(lookup(&err));
        }
    };
    check_directory(&metadata, expectations)?;
    let walked = check_ancestors(parent, expectations)?;
    if walked.dev() != metadata.dev() || walked.ino() != metadata.ino() {
        return Err(PathProblem::UnsafeDirectory.into());
    }
    // The client's own rule, stricter than the service's: no sticky
    // exemption for the socket's own directory.
    if metadata.mode() & GROUP_OTHER_WRITE != 0 {
        return Err(PathProblem::SharedDirectory.into());
    }
    Ok(())
}

/// Refuses a socket directory, `metadata` of its path not followed, that
/// is not a directory, has an owner the client does not trust, or that
/// another UID could write to ([`PathProblem::UnsafeDirectory`]).
fn check_directory(
    metadata: &fs::Metadata,
    expectations: &SocketExpectations,
) -> Result<(), PathError> {
    if !metadata.is_dir() || !expectations.trusts(metadata.uid()) || !write_safe(metadata.mode()) {
        return Err(PathProblem::UnsafeDirectory.into());
    }
    Ok(())
}

/// One step of the walk in [`check_ancestors`].
enum Step {
    /// Back to the root directory (an absolute path or link target).
    Root,
    /// `..`.
    Up,
    /// An entry of the current directory.
    Name(OsString),
}

/// Pushes the steps of `path` onto `steps`, a stack: the first step ends
/// on top.
fn push_steps(steps: &mut Vec<Step>, path: &Path) {
    let mut new: Vec<Step> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => new.push(Step::Root),
            Component::ParentDir => new.push(Step::Up),
            Component::Normal(name) => new.push(Step::Name(name.to_os_string())),
            Component::CurDir | Component::Prefix(_) => {}
        }
    }
    steps.extend(new.into_iter().rev());
}

/// Walks the lookup of `parent`, an absolute path, from the root
/// directory, entry by entry, following each symbolic link as the kernel
/// would, and checks every directory an entry, `..` included, is looked up
/// in, the root directory too: owned by a trusted UID and not writable by
/// group or others unless sticky. A symbolic link on the way in a
/// directory others may write (sticky) must be a trusted UID's too: its
/// owner could replace it. The socket's directory itself, where the walk
/// ends, is [`check_directory`]'s; the walk returns its metadata.
fn check_ancestors(
    parent: &Path,
    expectations: &SocketExpectations,
) -> Result<fs::Metadata, PathError> {
    // The directory `at` an entry, `..` included, is looked up in: `at` is
    // `/` and normal entries only, none of them a symbolic link.
    let check = |at: &Path| {
        let metadata = fs::symlink_metadata(at).map_err(|err| lookup(&err))?;
        if !metadata.is_dir()
            || !expectations.trusts(metadata.uid())
            || !write_safe(metadata.mode())
        {
            return Err(PathError(PathProblem::UnsafeAncestor));
        }
        Ok(metadata)
    };
    let mut steps = Vec::new();
    push_steps(&mut steps, parent);
    let mut at = PathBuf::from("/");
    let mut links = 0;
    while let Some(step) = steps.pop() {
        let name = match step {
            Step::Root => {
                at = PathBuf::from("/");
                continue;
            }
            // `..` is looked up in `at` too, whose owner could move it (to
            // point `..` elsewhere): checked like any other. `at` holds no
            // symbolic link, so its parent is the lexical one.
            Step::Up => {
                check(&at)?;
                at.pop();
                continue;
            }
            Step::Name(name) => name,
        };
        let metadata = check(&at)?;
        let next = at.join(&name);
        let found = fs::symlink_metadata(&next).map_err(|err| lookup(&err))?;
        if found.file_type().is_symlink() {
            // Sticky and writable by others (`write_safe` held): another
            // UID's link here could be replaced by its owner.
            if metadata.mode() & GROUP_OTHER_WRITE != 0 && !expectations.trusts(found.uid()) {
                return Err(PathProblem::UnsafeAncestor.into());
            }
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(PathProblem::TooManySymlinks.into());
            }
            push_steps(
                &mut steps,
                &fs::read_link(&next).map_err(|err| lookup(&err))?,
            );
        } else if found.is_dir() {
            at = next;
        } else {
            return Err(PathProblem::Lookup(io::ErrorKind::NotADirectory).into());
        }
    }
    fs::symlink_metadata(&at).map_err(|err| lookup(&err))
}

/// The connection to the transport's Unix socket at a path, checked before
/// every connect ([`check_socket`]) and compared after it: the connector a
/// real caller uses, through [`LocalClient::new`]. A
/// refused path is [`NotSent::Path`]: nothing was written.
///
/// # Between the check and the connect
///
/// The client has no `unsafe` code, no `libc` and no peer credentials of
/// the listener (`SO_PEERCRED`), and the standard library opens no
/// directory without following it, so it checks by path: it checks the
/// path, connects to the same absolute path, then reads the socket path
/// again (not followed) and refuses the connection, dropped before a byte
/// is written ([`NotSent::Path`]), unless it is still the checked socket:
/// the same file type, device, inode, owner, permission bits and change
/// time (`ctime`, seconds and nanoseconds). Only the socket path is read
/// again: the directories on the way are not walked again after the
/// connect.
///
/// What is left is a swap undone before that second read. The socket's own
/// directory is private ([`PathProblem::SharedDirectory`]) and every
/// directory above it is a trusted UID's and not writable by others (or
/// sticky, where only an entry's owner, a trusted UID, may rename the
/// directory on the way), so only root or the trusted service UID could
/// make one, and either could serve the socket anyway. That is why the
/// socket's own directory may not be sticky: in a sticky directory others
/// may write (as `/tmp`), any UID may create an entry at a vacant name.
/// While the service's socket is gone (a restart), another UID could bind
/// the name, take the connection, and remove its socket before the
/// service binds again, whose new socket may get the same inode number
/// (file systems such as ext4 reuse a freed one readily) and has the
/// service's owner and mode; the change time would tell the two apart
/// only when they fall in different ticks of the file system's clock.
/// Where access control lists are not shown in the mode bits (macOS, see
/// [`check_socket`]), a directory may still be writable by others. The
/// change time also changes in the service's own publish of a
/// new socket (a link, then the unlink of its staged name): a connect in
/// that window may be refused as [`PathProblem::Changed`], spuriously but
/// safely, since nothing was sent and the call can be retried.
///
/// `Debug` prints `CheckedSocketPath(..)`, not the path.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckedSocketPath {
    path: PathBuf,
    expectations: SocketExpectations,
}

impl fmt::Debug for CheckedSocketPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CheckedSocketPath(..)")
    }
}

impl CheckedSocketPath {
    /// The socket at `path`, expected as `expectations` says.
    pub fn new(path: impl Into<PathBuf>, expectations: SocketExpectations) -> Self {
        Self {
            path: path.into(),
            expectations,
        }
    }

    /// The socket's path, as given.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What the socket is expected to be.
    pub const fn expectations(&self) -> SocketExpectations {
        self.expectations
    }
}

impl Connector for CheckedSocketPath {
    type Stream = UnixStream;

    /// Checks, connects, and compares the socket path with the checked
    /// socket.
    ///
    /// # Errors
    ///
    /// A refused path is an [`io::Error`] that carries its [`PathError`]
    /// (the call is then [`NotSent::Path`]); a failed connect is the
    /// connect's error.
    fn connect(&self) -> io::Result<UnixStream> {
        connect_checked(&self.path, &self.expectations, |path| {
            UnixStream::connect(path)
        })
    }
}

/// [`check_socket`], then `connect` to the checked absolute path, then the
/// socket path read again: unless it is still the checked socket, the
/// stream is dropped, unwritten, and the path is refused
/// ([`PathProblem::Changed`]).
fn connect_checked<S>(
    path: &Path,
    expectations: &SocketExpectations,
    connect: impl FnOnce(&Path) -> io::Result<S>,
) -> io::Result<S> {
    let checked = check_socket(path, expectations).map_err(carried)?;
    let stream = connect(checked.path())?;
    match fs::symlink_metadata(checked.path()) {
        Ok(metadata) if checked.is(&metadata) => Ok(stream),
        // `stream` is dropped here, before anything is written to it.
        _ => Err(carried(PathError(PathProblem::Changed))),
    }
}

/// `err` as the [`io::Error`] a [`Connector`] returns, carrying it.
fn carried(err: PathError) -> io::Error {
    io::Error::new(err.problem().kind(), err)
}

/// Why a connect failed, as the call reports it: [`NotSent::Path`] for a
/// path [`CheckedSocketPath`] refused, [`NotSent::Connect`] with the
/// error's kind for anything else.
pub(super) fn not_sent(err: &io::Error) -> NotSent {
    match err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<PathError>())
    {
        Some(refused) => NotSent::Path(refused.problem()),
        None => NotSent::Connect(err.kind()),
    }
}

impl LocalClient<CheckedSocketPath> {
    /// The client of the socket at `path`, checked before every connect
    /// and compared after it ([`CheckedSocketPath`]): the client a real
    /// caller uses. [`LocalClient::unchecked`] connects to a path
    /// unchecked.
    pub fn new(
        path: impl Into<PathBuf>,
        expectations: SocketExpectations,
        timeouts: Timeouts,
    ) -> Self {
        Self::with_connector(CheckedSocketPath::new(path, expectations), timeouts)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::{fs::PermissionsExt as _, net::UnixListener},
        sync::atomic::{AtomicU32, Ordering},
        time::{Duration, Instant},
    };

    use super::*;

    /// A fresh directory under the system's temporary directory, mode
    /// 0700, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "skyoauth-operator-path-unit-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A listening socket at `path`, mode 0600.
    fn listen(path: &Path) -> UnixListener {
        let listener = UnixListener::bind(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }

    /// The expectations of a socket of `dir`'s owner.
    fn own(dir: &Path) -> SocketExpectations {
        SocketExpectations {
            owner_uid: fs::symlink_metadata(dir).unwrap().uid(),
            ancestors: AncestorTrust::ServiceOrRoot,
        }
    }

    #[test]
    fn an_unchanged_socket_is_connected() {
        let dir = Scratch::new();
        let path = dir.0.join("s");
        let _listener = listen(&path);
        let mut connected = None;
        let stream = connect_checked(&path, &own(&dir.0), |at| {
            connected = Some(at.to_path_buf());
            UnixStream::connect(at)
        });
        assert!(stream.is_ok(), "{stream:?}");
        assert_eq!(connected.as_deref(), Some(path.as_path()));
    }

    /// A change made to the socket at a path, which returns the listener of
    /// a replacement, if any.
    type Swap = dyn Fn(&Path) -> Option<UnixListener>;

    /// The socket replaced between the check and the connect (another
    /// inode, renamed over it while the first still exists, so its number
    /// cannot be reused), or given another mode, or removed, or changed in
    /// its change time alone (the same inode, owner and mode): the
    /// connection is dropped unwritten and the call is not sent, as
    /// [`NotSent::Path`].
    #[test]
    fn a_socket_changed_before_the_connect_is_refused() {
        let dir = Scratch::new();
        let path = dir.0.join("s");
        let expectations = own(&dir.0);
        let swaps: [&Swap; 4] = [
            &|at: &Path| {
                let other = at.with_file_name("s2");
                let listener = listen(&other);
                fs::rename(&other, at).unwrap();
                Some(listener)
            },
            &|at: &Path| {
                fs::set_permissions(at, fs::Permissions::from_mode(0o666)).unwrap();
                None
            },
            &|at: &Path| {
                fs::remove_file(at).unwrap();
                None
            },
            &|at: &Path| {
                // A mode changed and changed back, until the file system's
                // clock has ticked (bounded): only the change time moves.
                let before = fs::symlink_metadata(at).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    fs::set_permissions(at, fs::Permissions::from_mode(0o644)).unwrap();
                    fs::set_permissions(at, fs::Permissions::from_mode(0o600)).unwrap();
                    let now = fs::symlink_metadata(at).unwrap();
                    if (now.ctime(), now.ctime_nsec()) != (before.ctime(), before.ctime_nsec()) {
                        assert_eq!(now.ino(), before.ino());
                        assert_eq!(now.mode(), before.mode());
                        break;
                    }
                    assert!(Instant::now() < deadline, "the change time did not move");
                }
                None
            },
        ];
        for (index, swap) in swaps.into_iter().enumerate() {
            let listener = listen(&path);
            let mut replacement = None;
            let result = connect_checked(&path, &expectations, |at| {
                let stream = UnixStream::connect(at);
                replacement = swap(at);
                stream
            });
            let err = result.map(drop).unwrap_err();
            assert_eq!(
                not_sent(&err),
                NotSent::Path(PathProblem::Changed),
                "{index}"
            );
            // Dropped, not written: the server reads the end of the stream
            // at once.
            let (mut accepted, _) = listener.accept().unwrap();
            let mut read = Vec::new();
            io::Read::read_to_end(&mut accepted, &mut read).unwrap();
            assert!(read.is_empty(), "{index}");
            drop(replacement);
            let _ = fs::remove_file(&path);
        }
    }

    /// The read after the connect compares every field of the identity: a
    /// change in any one of them is another socket.
    #[test]
    fn the_recheck_compares_every_field() {
        let checked = Identity {
            socket: true,
            dev: 1,
            ino: 2,
            uid: 3,
            mode: SOCKET_MODE,
            ctime: 4,
            ctime_nsec: 5,
        };
        let same = checked;
        assert!(checked == same);
        let changes: [fn(&mut Identity); 7] = [
            |id| id.socket = false,
            |id| id.dev += 1,
            |id| id.ino += 1,
            |id| id.uid += 1,
            |id| id.mode = 0o644,
            |id| id.ctime += 1,
            |id| id.ctime_nsec += 1,
        ];
        for (index, change) in changes.into_iter().enumerate() {
            let mut found = checked;
            change(&mut found);
            assert!(checked != found, "{index}");
        }
    }

    #[test]
    fn a_failed_connect_keeps_its_kind_and_a_refusal_its_problem() {
        let err = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(
            not_sent(&err),
            NotSent::Connect(io::ErrorKind::ConnectionRefused)
        );
        for problem in [
            PathProblem::InvalidPath,
            PathProblem::Missing,
            PathProblem::Lookup(io::ErrorKind::NotADirectory),
            PathProblem::WrongMode,
        ] {
            let err = carried(PathError(problem));
            assert_eq!(not_sent(&err), NotSent::Path(problem));
            assert_eq!(err.kind(), problem.kind());
        }
        // Another error that carries a payload is a failed connect.
        let other = io::Error::other("elsewhere");
        assert_eq!(not_sent(&other), NotSent::Connect(io::ErrorKind::Other));
    }

    #[test]
    fn a_refused_path_is_never_connected() {
        let dir = Scratch::new();
        let path = dir.0.join("s");
        let _listener = listen(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let mut connects = 0;
        let result = connect_checked(&path, &own(&dir.0), |at| {
            connects += 1;
            UnixStream::connect(at)
        });
        let err = result.map(drop).unwrap_err();
        assert_eq!(not_sent(&err), NotSent::Path(PathProblem::WrongMode));
        assert_eq!(connects, 0);
    }
}
