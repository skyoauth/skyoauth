//! Creating the socket file: owned by the service UID, mode 0600, never
//! reachable by another UID in between, never in place of something else at
//! the path, and serialized across processes by a lock file (see the module
//! docs of [`crate::local_transport`], "The socket file").

use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io,
    os::unix::fs::{
        DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _,
        PermissionsExt as _,
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use tokio::net::{UnixListener, UnixStream};

/// The socket file's mode, and the lock file's.
pub(super) const SOCKET_MODE: u32 = 0o600;

/// The private directory's mode.
const PRIVATE_DIR_MODE: u32 = 0o700;

/// The permission bits of a mode.
const PERMISSION_BITS: u32 = 0o7777;

/// The group and other write bits of a mode.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// The sticky bit of a mode.
const STICKY: u32 = 0o1000;

/// The size of `sockaddr_un.sun_path`: 108 bytes on Linux, 104 on the BSDs
/// and macOS. A path must leave room for its terminating NUL.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) const SUN_PATH_BYTES: usize = 108;
/// The size of `sockaddr_un.sun_path`: 108 bytes on Linux, 104 on the BSDs
/// and macOS. A path must leave room for its terminating NUL.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) const SUN_PATH_BYTES: usize = 104;

/// The suffix of the lock file's name: `<name>.lock` next to the socket.
const LOCK_SUFFIX: &str = ".lock";

/// The suffix of a private directory's name, `.<name>.<pid>.<n>.bind`.
const PRIVATE_DIR_SUFFIX: &str = ".bind";

/// The socket's name inside the private directory.
const STAGED_NAME: &str = "s";

/// How many private directory names a bind tries before it gives up.
const PRIVATE_DIR_ATTEMPTS: u64 = 16;

/// Why [`bind`](super::LocalTransport::bind) did not start the transport.
/// Nothing is left at the socket path on any variant (a stale socket it
/// removed stays removed); the lock file may be (see the module docs, "The
/// socket file").
#[derive(Debug)]
pub enum BindError {
    /// The socket path has no parent directory or no file name.
    InvalidPath,
    /// The socket path does not fit a Unix socket address: it must be
    /// shorter than `sun_path` (108 bytes on Linux, 104 on the BSDs and
    /// macOS), so that a client can connect to it.
    PathTooLong,
    /// On a system without `/proc/self/fd` the socket is bound at its full
    /// staging path, `<directory>/.<name>.<pid>.<n>.bind/s`, which does not
    /// fit a Unix socket address: a shorter directory or name is needed.
    StagingPathTooLong,
    /// The socket's directory is not owned by the service UID or root, is a
    /// symbolic link, or is writable by its group or others without the
    /// sticky bit: another UID could replace the socket.
    UnsafeDirectory,
    /// Something is at the socket path that is not a socket owned by the
    /// service UID (a file, a directory, a symbolic link, another UID's
    /// socket), or at the lock path that is not a regular file owned by the
    /// service UID with mode 0600. It is left in place.
    PathOccupied,
    /// Another transport holds the lock file, or a process accepts
    /// connections on the socket at the path.
    InUse,
    /// The private directory, or the socket path after the bind, is not what
    /// the transport created: owned by the process (the directory) or the
    /// service UID (the socket), with mode 0700 or 0600.
    NotVerified,
    /// A file-system or socket call failed, a refused change of owner (the
    /// process may not give the socket to the service UID) included.
    Io(io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("the local socket path has no directory or name"),
            Self::PathTooLong => f.write_str(
                "the local socket path is too long for a Unix socket address (108 bytes on \
                 Linux, 104 on the BSDs and macOS, its terminating NUL included)",
            ),
            Self::StagingPathTooLong => f.write_str(
                "the local socket's staging path is too long for a Unix socket address and \
                 /proc/self/fd is not available: use a shorter directory or name",
            ),
            Self::UnsafeDirectory => f.write_str(
                "the local socket's directory must be owned by the service UID or root, not \
                 be a symbolic link, and not be writable by group or others unless sticky",
            ),
            Self::PathOccupied => f.write_str(
                "the local socket path holds something other than a socket owned by the \
                 service UID, or its lock path something other than its lock file",
            ),
            Self::InUse => f.write_str("another process holds or listens on the local socket"),
            Self::NotVerified => f.write_str(
                "the local socket is not owned by the service UID with mode 0600 after the bind",
            ),
            Self::Io(err) => write!(f, "the local socket could not be created: {err}"),
        }
    }
}

impl std::error::Error for BindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidPath
            | Self::PathTooLong
            | Self::StagingPathTooLong
            | Self::UnsafeDirectory
            | Self::PathOccupied
            | Self::InUse
            | Self::NotVerified => None,
        }
    }
}

impl From<io::Error> for BindError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// The socket file the transport created, identified by its inode, and
/// the lock it holds for the listener's life: dropping it removes the path
/// only while the path is still that socket, and only then releases the
/// lock.
#[derive(Debug)]
pub(super) struct SocketFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
    /// Locked (exclusive, `flock`) until dropped, after the path is
    /// removed: the field drops after [`Drop::drop`] has run.
    _lock: File,
}

impl SocketFile {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

/// Whether `metadata` is the socket `dev` and `ino`.
fn is_socket(metadata: &fs::Metadata, dev: u64, ino: u64) -> bool {
    metadata.file_type().is_socket() && metadata.dev() == dev && metadata.ino() == ino
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        // Under the lock: no other transport can have published a socket at
        // the path, and the inode check leaves anything else in place.
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| is_socket(&metadata, self.dev, self.ino))
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The private directory a bind creates next to the socket path, open, and
/// removed with what it holds when dropped.
struct PrivateDir {
    path: PathBuf,
    handle: File,
}

impl PrivateDir {
    /// Creates a new directory with mode 0700 in `parent`, under the name
    /// `.<name>.<pid>.<n>.bind`, opens it and checks that the open
    /// directory is the one at the path, owned by `effective_uid`, and that
    /// no one but its owner may enter it. `mkdir` never reuses an existing
    /// entry (a symbolic link included): a taken name is skipped.
    fn create(parent: &Path, name: &OsStr, effective_uid: u32) -> Result<Self, BindError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut last = None;
        for _ in 0..PRIVATE_DIR_ATTEMPTS {
            let mut entry = private_dir_prefix(name);
            entry.push(format!(
                "{}.{}{PRIVATE_DIR_SUFFIX}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let path = parent.join(entry);
            match fs::DirBuilder::new().mode(PRIVATE_DIR_MODE).create(&path) {
                Ok(()) => {
                    let handle = File::open(&path).map_err(|err| {
                        let _ = fs::remove_dir(&path);
                        BindError::Io(err)
                    })?;
                    let dir = Self { path, handle };
                    let opened = dir.handle.metadata()?;
                    let at_path = fs::symlink_metadata(&dir.path)?;
                    // The umask can only clear bits of 0700.
                    if !opened.is_dir()
                        || opened.dev() != at_path.dev()
                        || opened.ino() != at_path.ino()
                        || opened.uid() != effective_uid
                        || opened.mode() & 0o077 != 0
                    {
                        return Err(BindError::NotVerified);
                    }
                    return Ok(dir);
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => last = Some(err),
                Err(err) => return Err(err.into()),
            }
        }
        Err(last.map_or(BindError::PathOccupied, BindError::Io))
    }

    /// The address the socket is bound at inside the directory: through the
    /// open directory (`/proc/self/fd/<fd>/s`) where the system has
    /// `/proc/self/fd`, a short address whatever the directory's path;
    /// elsewhere the full path, which must fit a socket address.
    fn bind_address(&self) -> Result<PathBuf, BindError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd as _;
            let fd_dir = Path::new("/proc/self/fd");
            if fd_dir.is_dir() {
                return Ok(fd_dir
                    .join(self.handle.as_raw_fd().to_string())
                    .join(STAGED_NAME));
            }
        }
        let full = self.path.join(STAGED_NAME);
        if full.as_os_str().len() >= SUN_PATH_BYTES {
            return Err(BindError::StagingPathTooLong);
        }
        Ok(full)
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The start of a private directory's name for the socket name `name`.
fn private_dir_prefix(name: &OsStr) -> OsString {
    let mut prefix = OsString::from(".");
    prefix.push(name);
    prefix.push(".");
    prefix
}

/// Removes the private directories that a bind of `name` left in `parent`
/// when its process died: under the lock no other transport for `name`
/// has one, and every bind removes its own before it returns. Only
/// directories (never a symbolic link) owned by `effective_uid` whose name
/// is `.<name>.<digits>.<digits>.bind` are removed.
fn remove_stale_private_dirs(parent: &Path, name: &OsStr, effective_uid: u32) -> io::Result<()> {
    let prefix = private_dir_prefix(name);
    let prefix = prefix.as_encoded_bytes();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(middle) = file_name
            .as_encoded_bytes()
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(PRIVATE_DIR_SUFFIX.as_bytes()))
        else {
            continue;
        };
        let numeric = |part: Option<&[u8]>| {
            part.is_some_and(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
        };
        let mut parts = middle.split(|byte| *byte == b'.');
        if !(numeric(parts.next()) && numeric(parts.next()) && parts.next().is_none()) {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() && metadata.uid() == effective_uid {
            fs::remove_dir_all(&path)?;
        }
    }
    Ok(())
}

/// The process's effective UID, as the kernel reports it for a socket pair
/// the process creates (the credentials the peer check reads,
/// `SO_PEERCRED` on Linux): no file is created and no `unsafe` call made.
fn effective_uid() -> io::Result<u32> {
    let (one, _other) = UnixStream::pair()?;
    Ok(one.peer_cred()?.uid())
}

/// Refuses a socket directory another UID could write to (see
/// [`BindError::UnsafeDirectory`]).
fn check_directory(parent: &Path, service_uid: u32) -> Result<(), BindError> {
    let metadata = fs::symlink_metadata(parent)?;
    let mode = metadata.mode();
    let owner_ok = metadata.uid() == service_uid || metadata.uid() == 0;
    let write_ok = mode & GROUP_OTHER_WRITE == 0 || mode & STICKY != 0;
    if !metadata.is_dir() || !owner_ok || !write_ok {
        return Err(BindError::UnsafeDirectory);
    }
    Ok(())
}

/// Opens, or creates, the lock file at `lock_path` (a regular file owned by
/// `service_uid`, mode 0600) and locks it, exclusively and without waiting,
/// for the listener's life. A lock another open file holds is
/// [`BindError::InUse`]. The file is never removed: removing a lock file
/// while another process holds it open would let two processes lock two
/// files of the same name.
fn lock(lock_path: &Path, effective_uid: u32, service_uid: u32) -> Result<File, BindError> {
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(SOCKET_MODE)
        .open(lock_path)
    {
        Ok(file) => {
            if service_uid != effective_uid {
                std::os::unix::fs::fchown(&file, Some(service_uid), None)?;
            }
            // The umask may have cleared bits of 0600.
            file.set_permissions(fs::Permissions::from_mode(SOCKET_MODE))?;
            file
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            // Opened only when a regular file is at the path; the identity
            // check below catches a swap in between.
            if !fs::symlink_metadata(lock_path)?.is_file() {
                return Err(BindError::PathOccupied);
            }
            OpenOptions::new().read(true).write(true).open(lock_path)?
        }
        Err(err) => return Err(err.into()),
    };
    let opened = file.metadata()?;
    let at_path = fs::symlink_metadata(lock_path)?;
    if !opened.is_file()
        || opened.dev() != at_path.dev()
        || opened.ino() != at_path.ino()
        || opened.uid() != service_uid
        || opened.mode() & PERMISSION_BITS != SOCKET_MODE
    {
        return Err(BindError::PathOccupied);
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(BindError::InUse),
        Err(TryLockError::Error(err)) => Err(err.into()),
    }
}

/// What is at the socket path before the bind.
enum Existing {
    Nothing,
    /// A socket of the service UID that refused a connection: no one
    /// listens on it.
    Stale(fs::Metadata),
}

/// Refuses anything at `path` but nothing or a stale socket of
/// `service_uid` (see [`BindError::PathOccupied`] and
/// [`BindError::InUse`]).
async fn existing(path: &Path, service_uid: u32) -> Result<Existing, BindError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Existing::Nothing),
        Err(err) => return Err(err.into()),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != service_uid {
        return Err(BindError::PathOccupied);
    }
    // A non-blocking connect: accepted (or a full backlog, `WouldBlock`)
    // means a listener; only a refusal means none. Under the lock, a live
    // listener here is a process that does not take the lock file.
    match UnixStream::connect(path).await {
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => Ok(Existing::Stale(metadata)),
        Ok(_) => Err(BindError::InUse),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(BindError::InUse),
        Err(err) => Err(err.into()),
    }
}

/// Removes the stale socket `stale` at `path`, only while the path is still
/// that socket; anything else there is [`BindError::PathOccupied`] and left
/// in place.
fn remove_stale(path: &Path, stale: &fs::Metadata) -> Result<(), BindError> {
    let now = fs::symlink_metadata(path)?;
    if !is_socket(&now, stale.dev(), stale.ino()) {
        return Err(BindError::PathOccupied);
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Publishes the bound socket `staged` at `path` with `link`, which never
/// replaces an entry: one that is there is left in place
/// ([`BindError::PathOccupied`]).
fn publish(staged: &Path, path: &Path) -> Result<(), BindError> {
    fs::hard_link(staged, path).map_err(|err| match err.kind() {
        io::ErrorKind::AlreadyExists => BindError::PathOccupied,
        _ => BindError::Io(err),
    })
}

/// Binds the listener at `path` for `service_uid`, or for the process's
/// effective UID when `None`, and returns it with the socket file and the
/// service UID (see the module docs, "The socket file").
pub(super) async fn bind(
    path: &Path,
    service_uid: Option<u32>,
) -> Result<(UnixListener, SocketFile, u32), BindError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(BindError::InvalidPath);
    };
    if path.as_os_str().len() >= SUN_PATH_BYTES {
        return Err(BindError::PathTooLong);
    }
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let effective_uid = effective_uid()?;
    let service_uid = service_uid.unwrap_or(effective_uid);
    check_directory(parent, service_uid)?;

    // Everything below runs under the lock, held until the socket file is
    // dropped: two transports never replace or remove each other's socket.
    let mut lock_name = name.to_os_string();
    lock_name.push(LOCK_SUFFIX);
    let lock = lock(&parent.join(lock_name), effective_uid, service_uid)?;
    remove_stale_private_dirs(parent, name, effective_uid)?;
    let private = PrivateDir::create(parent, name, effective_uid)?;

    if let Existing::Stale(stale) = existing(path, service_uid).await? {
        remove_stale(path, &stale)?;
    }

    // Bound where no other UID can reach it: the mode the umask leaves does
    // not matter until the socket has its owner and mode 0600.
    let listener = UnixListener::bind(private.bind_address()?)?;
    let staged = private.path.join(STAGED_NAME);
    if service_uid != effective_uid {
        // `lchown`: never through a symbolic link.
        std::os::unix::fs::lchown(&staged, Some(service_uid), None)?;
    }
    fs::set_permissions(&staged, fs::Permissions::from_mode(SOCKET_MODE))?;
    let bound = fs::symlink_metadata(&staged)?;
    if !bound.file_type().is_socket() {
        return Err(BindError::NotVerified);
    }
    publish(&staged, path)?;
    let socket = SocketFile {
        path: path.to_path_buf(),
        dev: bound.dev(),
        ino: bound.ino(),
        _lock: lock,
    };
    drop(private);

    let metadata = fs::symlink_metadata(path)?;
    if !is_socket(&metadata, socket.dev, socket.ino)
        || metadata.uid() != service_uid
        || metadata.mode() & PERMISSION_BITS != SOCKET_MODE
    {
        return Err(BindError::NotVerified);
    }
    Ok((listener, socket, service_uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_errors_name_no_path() {
        for err in [
            BindError::InvalidPath,
            BindError::PathTooLong,
            BindError::StagingPathTooLong,
            BindError::UnsafeDirectory,
            BindError::PathOccupied,
            BindError::InUse,
            BindError::NotVerified,
        ] {
            let text = err.to_string();
            assert!(
                text.starts_with("the local socket") || text.starts_with("another"),
                "{text}"
            );
            assert!(
                !text.contains('/') || text.contains("/proc/self/fd"),
                "{text}"
            );
            assert!(std::error::Error::source(&err).is_none());
        }
        assert_eq!(
            BindError::PathTooLong.to_string(),
            "the local socket path is too long for a Unix socket address (108 bytes on Linux, \
             104 on the BSDs and macOS, its terminating NUL included)"
        );
        let io = BindError::from(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(std::error::Error::source(&io).is_some());
    }

    #[tokio::test]
    async fn a_path_without_a_name_is_invalid() {
        for path in ["/", ""] {
            assert!(
                matches!(
                    bind(Path::new(path), None).await,
                    Err(BindError::InvalidPath)
                ),
                "{path}"
            );
        }
    }

    /// A fresh directory for one test, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "skyoauth-socket-unit-{test}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// `link`, not `rename`: an entry that appeared at the path since the
    /// check is never replaced.
    #[test]
    fn publishing_never_replaces_an_entry() {
        let dir = Scratch::new("publish");
        let staged = dir.0.join("staged");
        let path = dir.0.join("public");
        fs::write(&staged, b"staged").unwrap();
        fs::write(&path, b"there first").unwrap();
        assert!(matches!(
            publish(&staged, &path),
            Err(BindError::PathOccupied)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"there first");
        assert_eq!(fs::read(&staged).unwrap(), b"staged");
        fs::remove_file(&path).unwrap();
        publish(&staged, &path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"staged");
    }

    /// The stale socket is removed only while it is still at the path: a
    /// socket or a file put there since the check is left in place.
    #[test]
    fn a_stale_socket_is_removed_only_while_it_is_there() {
        let dir = Scratch::new("stale");
        let path = dir.0.join("sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let stale = fs::symlink_metadata(&path).unwrap();
        // Replaced by another socket (a new inode: the stale one is kept
        // under another name, so its number is not reused).
        let moved = dir.0.join("moved");
        fs::rename(&path, &moved).unwrap();
        let other = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(matches!(
            remove_stale(&path, &stale),
            Err(BindError::PathOccupied)
        ));
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        drop(other);
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"file").unwrap();
        assert!(matches!(
            remove_stale(&path, &stale),
            Err(BindError::PathOccupied)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"file");
        // Still the stale socket: removed.
        fs::remove_file(&path).unwrap();
        fs::rename(&moved, &path).unwrap();
        remove_stale(&path, &stale).unwrap();
        assert!(fs::symlink_metadata(&path).is_err());
    }

    #[test]
    fn only_private_directories_of_the_name_are_cleaned() {
        let dir = Scratch::new("clean");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        let name = OsStr::new("local.sock");
        let stale = dir.0.join(".local.sock.123.4.bind");
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("s"), b"").unwrap();
        let kept = [
            ".local.sock.123.bind",
            ".local.sock.1.2.3.bind",
            ".local.sock.12a.4.bind",
            ".other.sock.123.4.bind",
            "local.sock.123.4.bind",
            ".local.sock..4.bind",
        ];
        for name in kept {
            fs::create_dir(dir.0.join(name)).unwrap();
        }
        // A symbolic link with a matching name is not a directory: left,
        // and so is what it points to.
        let target = dir.0.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"").unwrap();
        let link = dir.0.join(".local.sock.9.9.bind");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // A directory of another owner is left.
        remove_stale_private_dirs(&dir.0, name, uid.wrapping_add(1)).unwrap();
        assert!(stale.exists());
        remove_stale_private_dirs(&dir.0, name, uid).unwrap();
        assert!(!stale.exists());
        for name in kept {
            assert!(dir.0.join(name).is_dir(), "{name}");
        }
        assert!(target.join("keep").exists());
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[tokio::test]
    async fn the_effective_uid_is_the_owner_of_what_the_process_creates() {
        let dir = Scratch::new("euid");
        let owner = fs::symlink_metadata(&dir.0).unwrap().uid();
        assert_eq!(effective_uid().unwrap(), owner);
    }
}
