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

/// The new lock file's name inside its private directory.
const STAGED_LOCK_NAME: &str = "l";

/// How many times a bind opens or creates the lock file when other binds
/// keep creating it at the same time.
const LOCK_ATTEMPTS: u32 = 4;

/// How many private directory names a bind tries before it gives up.
const PRIVATE_DIR_ATTEMPTS: u64 = 16;

/// The most symbolic links the walk of the socket's directory follows
/// ([`check_ancestors`]), as Linux's own lookup does.
const MAX_SYMLINKS: u32 = 40;

/// Linux's `open` flags that differ by architecture: the crate does not
/// depend on `libc` (which this crate may not name without a new
/// dependency), so the values are Linux's own.
#[derive(Clone, Copy)]
#[cfg_attr(
    not(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "riscv64",
            target_arch = "aarch64"
        )
    )),
    allow(dead_code, reason = "constructed only where the flags are known")
)]
struct OpenFlags {
    /// `O_NOFOLLOW`.
    no_follow: i32,
    /// `O_DIRECTORY`.
    directory: i32,
}

/// `O_PATH`, 0o10000000 on x86_64, aarch64 and riscv64: a descriptor that
/// names a file (a directory the process may search but not list included)
/// without opening it for reading.
const O_PATH: i32 = 0o10_000_000;

/// `O_NONBLOCK`, 0o4000 on x86_64, aarch64 and riscv64.
const O_NONBLOCK: i32 = 0o4000;

/// The flags of [`OpenFlags`], by architecture, from Linux's
/// `asm-generic/fcntl.h` (`O_NOFOLLOW` 0o400000 and `O_DIRECTORY` 0o200000
/// on x86_64 and riscv64) and `arch/arm64/include/uapi/asm/fcntl.h`
/// (0o100000 and 0o40000 on aarch64). Elsewhere there are none: the
/// socket's directory is checked by its path, and [`bind`] refuses to start
/// when it opens the lock file ([`BindError::Io`] of kind
/// [`io::ErrorKind::Unsupported`]).
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
const OPEN_FLAGS: Option<OpenFlags> = Some(OpenFlags {
    no_follow: 0o400_000,
    directory: 0o200_000,
});
/// See the other architectures' definition.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const OPEN_FLAGS: Option<OpenFlags> = Some(OpenFlags {
    no_follow: 0o100_000,
    directory: 0o40_000,
});
/// See the Linux definitions: no flags known here.
#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    )
)))]
const OPEN_FLAGS: Option<OpenFlags> = None;

/// Why [`bind`](super::LocalTransport::bind) did not start the transport.
/// Nothing is left at the socket path on any variant (a stale socket it
/// removed stays removed); the lock file may be (see the module docs, "The
/// socket file").
#[derive(Debug)]
pub enum BindError {
    /// The socket path has no parent directory or no file name, or names a
    /// directory only: it ends in `/` or `/.` (which [`Path`]'s accessors
    /// drop, so `admin.sock/` would otherwise bind `admin.sock`).
    InvalidPath,
    /// The service UID is not the process's effective UID, and the process
    /// is not root: binding for another UID requires root; a service that
    /// is not root binds as its own UID. Refused before anything is
    /// created.
    NotRoot,
    /// The socket path does not fit a Unix socket address: it must be
    /// shorter than `sun_path` (108 bytes on Linux, 104 on the BSDs and
    /// macOS), so that a client can connect to it.
    PathTooLong,
    /// On a system without `/proc/self/fd` the socket is bound at its full
    /// staging path, `<directory>/.<name>.<pid>.<n>.bind/s`, which does not
    /// fit a Unix socket address: a shorter directory or name is needed.
    StagingPathTooLong,
    /// The socket's directory is a symbolic link, is writable by its group
    /// or others without the sticky bit, or has the wrong owner: the
    /// service UID or root when the service UID is the process's effective
    /// UID, else (root binding for another service UID) root, so the
    /// service UID cannot rename what the bind creates in it. Another UID
    /// could otherwise replace the socket. Also a directory
    /// that is not the one the check of its path reached (it was moved
    /// while the bind checked it).
    UnsafeDirectory,
    /// A directory the lookup of the socket's directory passes through (an
    /// ancestor, or one holding a symbolic link on the way) is writable by
    /// its group or others without the sticky bit, or has an owner the bind
    /// does not trust: root or the service UID when the service UID is the
    /// process's effective UID, else (root binding for another UID) root
    /// alone;
    /// or a symbolic link on the way, in such a directory that others may
    /// write (sticky), has an owner the bind does not trust. Another UID
    /// could rename the socket's directory, or the path to it. `depth`
    /// names the directory by its depth below the root directory (0 is the
    /// root directory itself), not by its path.
    UnsafeAncestor {
        /// The unsafe directory's depth below the root directory.
        depth: usize,
    },
    /// The service UID is not the process's effective UID, and the system
    /// has no `/proc/self/fd`: a bind for another UID reaches every entry it
    /// creates, opens or removes in the socket's directory through the open
    /// directory, never by a path looked up again, and refuses to start
    /// without it.
    NoDescriptorPaths,
    /// Something is at the socket path that is not a socket owned by the
    /// service UID (a file, a directory, a symbolic link, another UID's
    /// socket), or at the lock path that is not a regular file owned by the
    /// service UID with mode 0600. It is left in place.
    PathOccupied,
    /// Another transport holds the lock file, or a process accepts
    /// connections on the socket at the path (or other binds kept creating
    /// the lock file while this one tried to open it).
    InUse,
    /// The private directory, or the socket path after the bind, is not what
    /// the transport created: owned by the process (the directory) or the
    /// service UID (the socket), with mode 0700 or 0600.
    NotVerified,
    /// A file-system or socket call failed; also a lookup of the socket's directory through more than 40 symbolic
    /// links, and a target where the lock file cannot be opened without
    /// following a symbolic link (kind [`io::ErrorKind::Unsupported`]: not
    /// Linux on x86_64, aarch64 or riscv64).
    Io(io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str(
                "the local socket path has no directory or name, or names a directory (it ends \
                 in a slash, or in a slash and a dot)",
            ),
            Self::NotRoot => f.write_str(
                "the local socket can be bound for another service UID by root only; a service \
                 that is not root binds as its own UID",
            ),
            Self::PathTooLong => f.write_str(
                "the local socket path is too long for a Unix socket address (108 bytes on \
                 Linux, 104 on the BSDs and macOS, its terminating NUL included)",
            ),
            Self::StagingPathTooLong => f.write_str(
                "the local socket's staging path is too long for a Unix socket address and \
                 /proc/self/fd is not available: use a shorter directory or name",
            ),
            Self::UnsafeDirectory => f.write_str(
                "the local socket's directory must be owned by the service UID or root (by \
                 root when the service UID is not the process's), not be a symbolic link, \
                 and not be writable by group or others unless sticky",
            ),
            Self::UnsafeAncestor { depth } => write!(
                f,
                "the local socket's directory is reached through a directory {depth} levels \
                 below the root directory that is not owned by root (or by the service UID \
                 when it is the process's UID), is writable by group or others without the \
                 sticky bit, or holds a symbolic link on the way of another owner",
            ),
            Self::NoDescriptorPaths => f.write_str(
                "the local socket can be bound for another service UID only through \
                 /proc/self/fd, which is not available",
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
            | Self::NotRoot
            | Self::PathTooLong
            | Self::StagingPathTooLong
            | Self::UnsafeDirectory
            | Self::UnsafeAncestor { .. }
            | Self::NoDescriptorPaths
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
    /// The socket path as given.
    path: PathBuf,
    /// The socket's directory, open: the socket is removed through it.
    parent: ParentDir,
    /// The socket's name in `parent`.
    name: OsString,
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
        let entry = self.parent.entry(&self.name);
        if fs::symlink_metadata(&entry)
            .is_ok_and(|metadata| is_socket(&metadata, self.dev, self.ino))
        {
            let _ = fs::remove_file(&entry);
        }
    }
}

/// The open file `file` as a path, `/proc/self/fd/<fd>`, where the system
/// has `/proc/self/fd` and the path leads to `file` itself.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn descriptor_path(file: &File) -> Option<PathBuf> {
    use std::os::fd::AsRawFd as _;
    let path = Path::new("/proc/self/fd").join(file.as_raw_fd().to_string());
    let (Ok(at_path), Ok(opened)) = (fs::metadata(&path), file.metadata()) else {
        return None;
    };
    (at_path.dev() == opened.dev() && at_path.ino() == opened.ino()).then_some(path)
}

/// The open file as a path: none where the system has no `/proc/self/fd`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn descriptor_path(_file: &File) -> Option<PathBuf> {
    None
}

/// The socket's directory, opened once and checked: every entry the bind
/// creates, opens, links or removes in it (the lock file, the private
/// directories, the socket) is reached through the open directory,
/// `/proc/self/fd/<fd>/<entry>`, never through its path looked up again,
/// so a rename of the directory, or of one above it, after the check
/// redirects none of them. Where the system has no `/proc/self/fd`, the
/// entries are reached through the absolute path, and only a bind for the
/// process's own UID starts ([`BindError::NoDescriptorPaths`]).
#[derive(Debug)]
struct ParentDir {
    /// The directory's absolute path, as given (the working directory
    /// joined to a relative one).
    path: PathBuf,
    /// `/proc/self/fd/<fd>` of the open directory, where the system has it.
    fd_dir: Option<PathBuf>,
    /// The open directory (`O_PATH`: no read permission needed), kept open
    /// while `fd_dir` names it; `None` where [`OPEN_FLAGS`] are not known.
    _handle: Option<File>,
}

impl ParentDir {
    /// Opens the directory at `path`, an absolute path, never through a
    /// symbolic link at `path` itself (`O_NOFOLLOW`), and checks the open
    /// directory ([`check_directory`]), then the lookup of `path`
    /// ([`check_ancestors`]), which must end at the open directory, else
    /// [`BindError::UnsafeDirectory`] (it was moved in between). A symbolic
    /// link or another file at `path` is [`BindError::UnsafeDirectory`]; a
    /// failed open is reported as the walk reports it, when that refuses
    /// the path (an unsafe ancestor that the open could not pass, say).
    fn open(path: PathBuf, effective_uid: u32, service_uid: u32) -> Result<Self, BindError> {
        let handle = match OPEN_FLAGS {
            Some(flags) => {
                let opened = OpenOptions::new()
                    .read(true)
                    .custom_flags(O_PATH | flags.directory | flags.no_follow)
                    .open(&path);
                match opened {
                    Ok(handle) => Some(handle),
                    Err(err) => {
                        if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_dir()) {
                            return Err(BindError::UnsafeDirectory);
                        }
                        check_ancestors(&path, effective_uid, service_uid)?;
                        return Err(err.into());
                    }
                }
            }
            None => None,
        };
        let metadata = match &handle {
            Some(handle) => handle.metadata()?,
            None => fs::symlink_metadata(&path)?,
        };
        check_directory(&metadata, effective_uid, service_uid)?;
        let walked = check_ancestors(&path, effective_uid, service_uid)?;
        if walked.dev() != metadata.dev() || walked.ino() != metadata.ino() {
            return Err(BindError::UnsafeDirectory);
        }
        let fd_dir = handle.as_ref().and_then(descriptor_path);
        if fd_dir.is_none() && service_uid != effective_uid {
            return Err(BindError::NoDescriptorPaths);
        }
        Ok(Self {
            path,
            fd_dir,
            _handle: handle,
        })
    }

    /// The directory the entries are reached through: the open directory,
    /// else the path.
    fn dir(&self) -> &Path {
        self.fd_dir.as_deref().unwrap_or(&self.path)
    }

    /// The entry `name` of the directory, reached through [`Self::dir`].
    fn entry(&self, name: &OsStr) -> PathBuf {
        self.dir().join(name)
    }
}

/// The private directory a bind creates next to the socket path, open, and
/// cleared when dropped ([`clear_private_dir`]).
struct PrivateDir {
    /// The directory, reached through the socket's open directory
    /// ([`ParentDir::entry`]).
    path: PathBuf,
    handle: File,
    /// The UIDs whose staged entries clearing it unlinks: the process's
    /// and the service UID.
    owners: [u32; 2],
}

impl PrivateDir {
    /// Creates a new directory with mode 0700 in `parent`, under the name
    /// `.<name>.<pid>.<n>.bind`, opens it and checks that the open
    /// directory is the one at the path, owned by `effective_uid`, and that
    /// no one but its owner may enter it. `mkdir` never reuses an existing
    /// entry (a symbolic link included): a taken name is skipped. `None`
    /// when the new directory is gone before it is opened and checked:
    /// another bind, under the lock, cleared it as a leftover (an empty
    /// private directory of the process's UID), and the caller retries.
    fn create(
        parent: &ParentDir,
        name: &OsStr,
        effective_uid: u32,
        service_uid: u32,
    ) -> Result<Option<Self>, BindError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let gone = |err: &io::Error| err.kind() == io::ErrorKind::NotFound;
        let mut last = None;
        for _ in 0..PRIVATE_DIR_ATTEMPTS {
            let mut entry = private_dir_prefix(name);
            entry.push(format!(
                "{}.{}{PRIVATE_DIR_SUFFIX}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let path = parent.entry(&entry);
            match fs::DirBuilder::new().mode(PRIVATE_DIR_MODE).create(&path) {
                Ok(()) => {
                    #[cfg(test)]
                    create_hook(CreateStep::Made, &path);
                    let handle = match File::open(&path) {
                        Ok(handle) => handle,
                        Err(err) if gone(&err) => return Ok(None),
                        Err(err) => {
                            let _ = fs::remove_dir(&path);
                            return Err(err.into());
                        }
                    };
                    let dir = Self {
                        path,
                        handle,
                        owners: [effective_uid, service_uid],
                    };
                    let opened = dir.handle.metadata()?;
                    #[cfg(test)]
                    create_hook(CreateStep::Opened, &dir.path);
                    let at_path = match fs::symlink_metadata(&dir.path) {
                        Ok(at_path) => at_path,
                        Err(err) if gone(&err) => return Ok(None),
                        Err(err) => return Err(err.into()),
                    };
                    // The umask can only clear bits of 0700.
                    if !opened.is_dir()
                        || opened.dev() != at_path.dev()
                        || opened.ino() != at_path.ino()
                        || opened.uid() != effective_uid
                        || opened.mode() & 0o077 != 0
                    {
                        return Err(BindError::NotVerified);
                    }
                    return Ok(Some(dir));
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => last = Some(err),
                Err(err) => return Err(err.into()),
            }
        }
        Err(last.map_or(BindError::PathOccupied, BindError::Io))
    }

    /// The open directory as a path, `/proc/self/fd/<fd>`, where the system
    /// has `/proc/self/fd`.
    fn fd_dir(&self) -> Option<PathBuf> {
        descriptor_path(&self.handle)
    }

    /// The directory every staged entry is reached through: the open
    /// directory, `/proc/self/fd/<fd>`, where the system has it, so a
    /// rename of the directory's path changes nothing the bind does in it;
    /// else the path (see the module docs, "The socket file", on why that
    /// is safe too).
    fn entries(&self) -> PathBuf {
        self.fd_dir().unwrap_or_else(|| self.path.clone())
    }

    /// The address the socket is bound at, and every later call on the
    /// staged socket uses ([`staging_address`]).
    fn bind_address(&self) -> Result<PathBuf, BindError> {
        staging_address(&self.path, self.fd_dir())
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = clear_private_dir(&self.path, &self.entries(), self.owners);
    }
}

/// The steps of [`PrivateDir::create`] where a test's hook runs (tests
/// only).
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreateStep {
    /// After the `mkdir`, before the open.
    Made,
    /// After the open, before the check against the path.
    Opened,
}

/// A test's hook into [`PrivateDir::create`] (tests only).
#[cfg(test)]
type CreateHook = Box<dyn FnMut(CreateStep, &Path)>;

#[cfg(test)]
thread_local! {
    /// A test's hook into [`PrivateDir::create`] on this thread, called
    /// with the new directory's path at each [`CreateStep`], so that a test
    /// can take the directory away there, as another bind clearing it does
    /// (tests only).
    static CREATE_HOOK: std::cell::RefCell<Option<CreateHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs this thread's [`CREATE_HOOK`], if any (tests only).
#[cfg(test)]
fn create_hook(step: CreateStep, path: &Path) {
    CREATE_HOOK.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(step, path);
        }
    });
}

/// The address of the staged socket in the private directory at
/// `private`: through `fd_dir`, the open directory's `/proc/self/fd/<fd>`,
/// where the system has one, a short address whatever the directory's
/// path, and one a rename of the directory does not redirect; else the
/// full path, which must fit a socket address
/// ([`BindError::StagingPathTooLong`]; it is longer than the socket path,
/// so it may not fit when the socket path does).
fn staging_address(private: &Path, fd_dir: Option<PathBuf>) -> Result<PathBuf, BindError> {
    if let Some(fd_dir) = fd_dir {
        return Ok(fd_dir.join(STAGED_NAME));
    }
    let full = private.join(STAGED_NAME);
    if full.as_os_str().len() >= SUN_PATH_BYTES {
        return Err(BindError::StagingPathTooLong);
    }
    Ok(full)
}

/// Whether `metadata` is a private directory as a bind creates it: a
/// directory owned by `owner`, mode 0700 at most (the umask may clear
/// bits), so no group or other bits and no special bits.
fn is_private_dir(metadata: &fs::Metadata, owner: u32) -> bool {
    metadata.is_dir()
        && metadata.uid() == owner
        && metadata.mode() & PERMISSION_BITS & !PRIVATE_DIR_MODE == 0
}

/// Clears the private directory at `path`, one this process or a killed
/// bind created, reaching its entries through `entries` (the open
/// directory, or `path` itself). Nothing is unlinked or removed unless the
/// directory is private ([`is_private_dir`], owned by `owners[0]`, the
/// process's UID): a directory of that name with other bits is not one a
/// bind left, and is kept with what it holds. In a private one it unlinks
/// only the entries a bind puts there, each owned by one of `owners`: the
/// staged socket `s` (a socket) and the staged lock `l` as a bind leaves
/// it, an empty regular file with no permission bits beyond 0600. Then it
/// removes the directory at `path` only if it is empty (`rmdir`, never
/// recursively). Anything else in it is left (an `l` with data, say, which
/// no bind writes), and so is the directory.
fn clear_private_dir(path: &Path, entries: &Path, owners: [u32; 2]) -> io::Result<()> {
    // `fs::metadata`: the open directory's path is a link to it.
    if !fs::metadata(entries).is_ok_and(|metadata| is_private_dir(&metadata, owners[0])) {
        return Ok(());
    }
    for name in [STAGED_NAME, STAGED_LOCK_NAME] {
        // The staged socket is a socket, the staged lock an empty regular
        // file of mode 0600 at most (the umask may clear bits).
        let expected = |metadata: &fs::Metadata| {
            if name == STAGED_NAME {
                metadata.file_type().is_socket()
            } else {
                metadata.is_file()
                    && metadata.len() == 0
                    && metadata.mode() & PERMISSION_BITS & !SOCKET_MODE == 0
            }
        };
        let entry = entries.join(name);
        match fs::symlink_metadata(&entry) {
            Ok(metadata) if expected(&metadata) && owners.contains(&metadata.uid()) => {
                match fs::remove_file(&entry) {
                    Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
                    _ => {}
                }
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
    }
    match fs::remove_dir(path) {
        Err(err)
            if !matches!(
                err.kind(),
                io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::NotFound
            ) =>
        {
            Err(err)
        }
        _ => Ok(()),
    }
}

/// The start of a private directory's name for the socket name `name`.
fn private_dir_prefix(name: &OsStr) -> OsString {
    let mut prefix = OsString::from(".");
    prefix.push(name);
    prefix.push(".");
    prefix
}

/// The entries of the socket's directory to scan for leftovers, from
/// `read`, its `read_dir`: `None` when the process may not list it (a
/// sticky directory it may write but not read, mode 01733 say), where
/// nothing is scanned; any other failure is an error.
fn listing(read: io::Result<fs::ReadDir>) -> io::Result<Option<fs::ReadDir>> {
    match read {
        Ok(entries) => Ok(Some(entries)),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Ok(None),
        Err(err) => Err(err),
    }
}

/// Clears the private directories that a bind of `name` left in `parent`
/// when its process died ([`clear_private_dir`]): under the lock no other
/// transport for `name` serves from one, and every bind clears its own
/// before it returns (a bind still creating the lock file may lose its
/// directory to this, and then opens the lock file again). Only private
/// directories ([`is_private_dir`]: never a symbolic link, owned by
/// `effective_uid`, mode 0700 at most) whose name is
/// `.<name>.<digits>.<digits>.bind` are cleared, and only when `parent`
/// can be listed ([`listing`]); each is reached through the open `parent`.
fn remove_stale_private_dirs(
    parent: &ParentDir,
    name: &OsStr,
    effective_uid: u32,
    service_uid: u32,
) -> io::Result<()> {
    let prefix = private_dir_prefix(name);
    let prefix = prefix.as_encoded_bytes();
    let Some(entries) = listing(fs::read_dir(parent.dir()))? else {
        return Ok(());
    };
    for entry in entries {
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
        let path = parent.entry(&file_name);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if is_private_dir(&metadata, effective_uid) {
            clear_private_dir(&path, &path, [effective_uid, service_uid])?;
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

/// Whether a directory's `mode` lets only its owner rename entries in it:
/// no group or other write bit, or the sticky bit (as `/tmp`).
fn write_safe(mode: u32) -> bool {
    mode & GROUP_OTHER_WRITE == 0 || mode & STICKY != 0
}

/// Refuses a socket directory, `metadata` of the open directory (or of its
/// path, not followed), another UID could write to, or one whose owner
/// could rename what a bind for another service UID creates in it (see
/// [`BindError::UnsafeDirectory`]).
fn check_directory(
    metadata: &fs::Metadata,
    effective_uid: u32,
    service_uid: u32,
) -> Result<(), BindError> {
    let owner_ok = if effective_uid == service_uid {
        metadata.uid() == service_uid || metadata.uid() == 0
    } else {
        // A bind for another UID, which only root makes (`bind` refuses
        // any other process first): the directory must be the binding
        // UID's, root's, never the service UID's, which could swap the
        // private directory for one of its own while the bind changes the
        // socket's owner and mode.
        metadata.uid() == effective_uid
    };
    if !metadata.is_dir() || !owner_ok || !write_safe(metadata.mode()) {
        return Err(BindError::UnsafeDirectory);
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
    use std::path::Component;
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

/// Refuses a socket directory reached through a directory another UID
/// could change ([`BindError::UnsafeAncestor`]): it walks the lookup of
/// `parent`, an absolute path, from the root directory, entry by entry,
/// following each symbolic link as the kernel would, and checks every
/// directory it looks an entry up in, `..` included, and the root
/// directory: not writable by group or others unless sticky, and owned by
/// a trusted UID: root or `service_uid` when that is `effective_uid`; root
/// alone when the bind is for another UID (root's bind, the only one
/// [`bind`] lets through), which must trust no one but root with the path,
/// not the service UID, which would gain what the bind gives away. The
/// UIDs are arguments, so the rule holds for any pair. A symbolic link on the way in a directory
/// others may write (sticky) must be a trusted UID's too: its owner could
/// replace it. The socket's directory itself, where the walk ends, is
/// [`check_directory`]'s; the walk returns its metadata, to be compared
/// with the open directory.
fn check_ancestors(
    parent: &Path,
    effective_uid: u32,
    service_uid: u32,
) -> Result<fs::Metadata, BindError> {
    let trusted = |uid: u32| uid == 0 || (service_uid == effective_uid && uid == service_uid);
    // The directory `at` an entry, `..` included, is looked up in: `at` is
    // `/` and normal entries only, so its depth is its components'.
    let check = |at: &Path| {
        let metadata = fs::symlink_metadata(at)?;
        let depth = at.components().count() - 1;
        if !metadata.is_dir() || !trusted(metadata.uid()) || !write_safe(metadata.mode()) {
            return Err(BindError::UnsafeAncestor { depth });
        }
        Ok((metadata, depth))
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
            // `..` is looked up in `at` too, which its owner could move
            // (to point `..` elsewhere): checked like any other. `at` holds
            // no symbolic link: its parent is the lexical one.
            Step::Up => {
                check(&at)?;
                at.pop();
                continue;
            }
            Step::Name(name) => name,
        };
        let (metadata, depth) = check(&at)?;
        let next = at.join(&name);
        let found = fs::symlink_metadata(&next)?;
        if found.file_type().is_symlink() {
            // Sticky and writable by others (`write_safe` held): another
            // UID's link here could be replaced by its owner.
            if metadata.mode() & GROUP_OTHER_WRITE != 0 && !trusted(found.uid()) {
                return Err(BindError::UnsafeAncestor { depth });
            }
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(io::Error::other(
                    "the lookup of the local socket's directory follows too many symbolic links",
                )
                .into());
            }
            push_steps(&mut steps, &fs::read_link(&next)?);
        } else if found.is_dir() {
            at = next;
        } else {
            return Err(io::Error::from(io::ErrorKind::NotADirectory).into());
        }
    }
    Ok(fs::symlink_metadata(&at)?)
}

/// Opens, or creates, the lock file of `name` in `parent`, `<name>.lock`
/// (a regular file owned by `service_uid`, mode 0600), and locks it,
/// exclusively and without waiting, for the listener's life. A lock another
/// open file holds is [`BindError::InUse`]. The file is never removed:
/// removing a lock file while another process holds it open would let two
/// processes lock two files of the same name.
fn lock(
    parent: &ParentDir,
    name: &OsStr,
    effective_uid: u32,
    service_uid: u32,
) -> Result<File, BindError> {
    let mut lock_name = name.to_os_string();
    lock_name.push(LOCK_SUFFIX);
    let lock_path = parent.entry(&lock_name);
    for _ in 0..LOCK_ATTEMPTS {
        let opened = match open_lock(&lock_path)? {
            Some(file) => Some(file),
            None => create_lock(parent, name, &lock_path, effective_uid, service_uid)?,
        };
        // `None`: another bind published a lock file meanwhile, or cleared
        // this one's private directory (before it was opened, or after);
        // open what is there now.
        let Some(file) = opened else {
            continue;
        };
        // `fstat` of the open file: a regular file of the service UID, mode
        // 0600, and the one at the path, before it is locked or kept.
        let metadata = file.metadata()?;
        let at_path = fs::symlink_metadata(&lock_path)?;
        if !metadata.is_file()
            || metadata.dev() != at_path.dev()
            || metadata.ino() != at_path.ino()
            || metadata.uid() != service_uid
            || metadata.mode() & PERMISSION_BITS != SOCKET_MODE
        {
            return Err(BindError::PathOccupied);
        }
        return match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(BindError::InUse),
            Err(TryLockError::Error(err)) => Err(err.into()),
        };
    }
    Err(BindError::InUse)
}

/// The options the lock file is opened with: read and write, never
/// through a symbolic link at the path (`O_NOFOLLOW`: one fails with
/// `ELOOP`), and without blocking on a FIFO or a device (`O_NONBLOCK`).
/// [`io::ErrorKind::Unsupported`] where the flags are not known
/// ([`OPEN_FLAGS`]).
fn lock_options() -> io::Result<OpenOptions> {
    let Some(flags) = OPEN_FLAGS else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the local socket's lock file can be opened without following a symbolic link \
             only on Linux on x86_64, aarch64 and riscv64",
        ));
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(flags.no_follow | O_NONBLOCK);
    Ok(options)
}

/// The lock file at `lock_path`, opened ([`lock_options`]), or `None` when
/// there is none. Something at the path that is not a regular file (a
/// symbolic link, which the open refuses, a directory, a socket) is
/// [`BindError::PathOccupied`]; [`lock`] checks the open file, which
/// catches a FIFO or a device the open did not refuse, and a swap.
fn open_lock(lock_path: &Path) -> Result<Option<File>, BindError> {
    match lock_options()?.open(lock_path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => match fs::symlink_metadata(lock_path) {
            Ok(metadata) if !metadata.is_file() => Err(BindError::PathOccupied),
            _ => Err(err.into()),
        },
    }
}

/// Creates the lock file: a new private inode, `l` in a fresh private
/// directory (reached through the open directory, as the staged socket
/// is), mode 0600, given to `service_uid` on its open descriptor, and only
/// then hard-linked to `lock_path`, which never replaces an entry; the
/// private directory is cleared after. `None` when another bind
/// published a lock file first, or cleared the private directory, under
/// its lock, before the link (or before it was opened, [`PrivateDir::create`]):
/// the caller opens the lock file again. Killed
/// at any point, it leaves either no lock file or one owned by
/// `service_uid` with mode 0600, and at most a private directory, which
/// the next bind clears.
fn create_lock(
    parent: &ParentDir,
    name: &OsStr,
    lock_path: &Path,
    effective_uid: u32,
    service_uid: u32,
) -> Result<Option<File>, BindError> {
    let Some(private) = PrivateDir::create(parent, name, effective_uid, service_uid)? else {
        return Ok(None);
    };
    let staged = private.entries().join(STAGED_LOCK_NAME);
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(SOCKET_MODE)
        .open(&staged)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    // The umask may have cleared bits of 0600; then the owner (by root,
    // the only process that binds for another UID).
    file.set_permissions(fs::Permissions::from_mode(SOCKET_MODE))?;
    if service_uid != effective_uid {
        std::os::unix::fs::fchown(&file, Some(service_uid), None)?;
    }
    match fs::hard_link(&staged, lock_path) {
        Ok(()) => Ok(Some(file)),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::AlreadyExists | io::ErrorKind::NotFound
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

/// What is at the socket path before the bind.
enum Existing {
    Nothing,
    /// A socket of the service UID that refused a connection: no one
    /// listens on it.
    Stale(fs::Metadata),
}

/// Refuses anything at the socket path, `name` in `parent`, but nothing or
/// a stale socket of `service_uid` (see [`BindError::PathOccupied`] and
/// [`BindError::InUse`]). Through the open directory, the entry is opened
/// itself (`O_PATH`, never through a symbolic link), checked with `fstat`
/// and connected to through its own descriptor, `/proc/self/fd/<fd>`: the
/// inode checked, and an address that fits whatever the name's length.
/// Elsewhere the entry is checked with `lstat` and connected to by its
/// path.
async fn existing(
    parent: &ParentDir,
    name: &OsStr,
    service_uid: u32,
) -> Result<Existing, BindError> {
    let entry = parent.entry(name);
    let opened = match OPEN_FLAGS {
        Some(flags) if parent.fd_dir.is_some() => {
            let opened = OpenOptions::new()
                .read(true)
                .custom_flags(O_PATH | flags.no_follow)
                .open(&entry);
            match opened {
                Ok(file) => Some(file),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Ok(Existing::Nothing);
                }
                Err(err) => return Err(err.into()),
            }
        }
        _ => None,
    };
    let metadata = match &opened {
        Some(file) => file.metadata()?,
        None => match fs::symlink_metadata(&entry) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Existing::Nothing),
            Err(err) => return Err(err.into()),
        },
    };
    if !metadata.file_type().is_socket() || metadata.uid() != service_uid {
        return Err(BindError::PathOccupied);
    }
    let address = opened.as_ref().and_then(descriptor_path).unwrap_or(entry);
    // A non-blocking connect: accepted (or a full backlog, `WouldBlock`)
    // means a listener; only a refusal means none. Under the lock, a live
    // listener here is a process that does not take the lock file.
    match UnixStream::connect(&address).await {
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => Ok(Existing::Stale(metadata)),
        Ok(_) => Err(BindError::InUse),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(BindError::InUse),
        Err(err) => Err(err.into()),
    }
}

/// Removes the stale socket `stale` at the socket path, `name` in the open
/// `parent`, only while the path is still that socket; anything else there
/// is [`BindError::PathOccupied`] and left in place.
fn remove_stale(parent: &ParentDir, name: &OsStr, stale: &fs::Metadata) -> Result<(), BindError> {
    let entry = parent.entry(name);
    let now = fs::symlink_metadata(&entry)?;
    if !is_socket(&now, stale.dev(), stale.ino()) {
        return Err(BindError::PathOccupied);
    }
    fs::remove_file(&entry)?;
    Ok(())
}

/// Publishes the bound socket `staged` at the socket path, `name` in the
/// open `parent`, with `link`, which never replaces an entry: one that is
/// there is left in place ([`BindError::PathOccupied`]).
fn publish(staged: &Path, parent: &ParentDir, name: &OsStr) -> Result<(), BindError> {
    fs::hard_link(staged, parent.entry(name)).map_err(|err| match err.kind() {
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
    // A path that ends in `/` or `/.` names a directory, which the
    // accessors below would drop (`admin.sock/` has the file name
    // `admin.sock`).
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.ends_with(b"/") || bytes.ends_with(b"/.") {
        return Err(BindError::InvalidPath);
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(BindError::InvalidPath);
    };
    if path.as_os_str().len() >= SUN_PATH_BYTES {
        return Err(BindError::PathTooLong);
    }
    let effective_uid = effective_uid()?;
    let service_uid = service_uid.unwrap_or(effective_uid);
    // Binding for another UID requires root (see the module docs, "The
    // socket file"), refused before anything is created.
    if service_uid != effective_uid && effective_uid != 0 {
        return Err(BindError::NotRoot);
    }
    // One absolute path, the working directory joined to a relative one
    // (an empty one is the working directory), for the open and the walk
    // of its lookup: the working directory is read once.
    let parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };
    let parent = ParentDir::open(parent, effective_uid, service_uid)?;

    // Everything below runs under the lock, held until the socket file is
    // dropped: two transports never replace or remove each other's socket.
    // Every entry is reached through the open directory.
    let lock = lock(&parent, name, effective_uid, service_uid)?;
    remove_stale_private_dirs(&parent, name, effective_uid, service_uid)?;
    // `None` (cleared before it was checked) cannot happen under the lock.
    let private = PrivateDir::create(&parent, name, effective_uid, service_uid)?
        .ok_or(BindError::NotVerified)?;

    if let Existing::Stale(stale) = existing(&parent, name, service_uid).await? {
        remove_stale(&parent, name, &stale)?;
    }

    // Bound where no other UID can reach it: the mode the umask leaves does
    // not matter until the socket has its owner and mode 0600. One address,
    // through the open directory, for the bind and every call after it:
    // never the directory's path, which a rename could point elsewhere
    // between the calls (a `chmod` through a planted symbolic link).
    let staged = private.bind_address()?;
    let listener = UnixListener::bind(&staged)?;
    // The mode, then the owner (by root, as for the lock file).
    fs::set_permissions(&staged, fs::Permissions::from_mode(SOCKET_MODE))?;
    if service_uid != effective_uid {
        // `lchown`: never through a symbolic link.
        std::os::unix::fs::lchown(&staged, Some(service_uid), None)?;
    }
    let bound = fs::symlink_metadata(&staged)?;
    if !bound.file_type().is_socket() {
        return Err(BindError::NotVerified);
    }
    publish(&staged, &parent, name)?;
    let socket = SocketFile {
        path: path.to_path_buf(),
        parent,
        name: name.to_os_string(),
        dev: bound.dev(),
        ino: bound.ino(),
        _lock: lock,
    };
    drop(private);

    let metadata = fs::symlink_metadata(socket.parent.entry(&socket.name))?;
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
            BindError::NotRoot,
            BindError::PathTooLong,
            BindError::StagingPathTooLong,
            BindError::UnsafeDirectory,
            BindError::UnsafeAncestor { depth: 3 },
            BindError::NoDescriptorPaths,
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
        assert!(
            BindError::UnsafeAncestor { depth: 3 }
                .to_string()
                .contains(" 3 levels below the root directory ")
        );
        let io = BindError::from(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(std::error::Error::source(&io).is_some());
    }

    #[tokio::test]
    async fn a_path_without_a_name_is_invalid() {
        // Also a directory's spellings, which `Path`'s accessors drop.
        for path in [
            "/",
            "",
            ".",
            "a.sock/",
            "a.sock/.",
            "/tmp/a.sock//",
            "/tmp/a.sock/./",
        ] {
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

    /// `dir` opened as the socket's directory of a bind for the process's
    /// own UID (its owner).
    fn opened(dir: &Path) -> ParentDir {
        let uid = fs::symlink_metadata(dir).unwrap().uid();
        ParentDir::open(dir.to_path_buf(), uid, uid).unwrap()
    }

    /// A private directory as a bind creates it, mode 0700.
    fn private_dir_at(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// A staged lock as a bind leaves it: empty, mode 0600.
    fn staged_lock_at(path: &Path) {
        fs::write(path, b"").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// `link`, not `rename`: an entry that appeared at the path since the
    /// check is never replaced.
    #[test]
    fn publishing_never_replaces_an_entry() {
        let dir = Scratch::new("publish");
        let parent = opened(&dir.0);
        let staged = dir.0.join("staged");
        let path = dir.0.join("public");
        let name = OsStr::new("public");
        fs::write(&staged, b"staged").unwrap();
        fs::write(&path, b"there first").unwrap();
        assert!(matches!(
            publish(&staged, &parent, name),
            Err(BindError::PathOccupied)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"there first");
        assert_eq!(fs::read(&staged).unwrap(), b"staged");
        fs::remove_file(&path).unwrap();
        publish(&staged, &parent, name).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"staged");
    }

    /// The stale socket is removed only while it is still at the path: a
    /// socket or a file put there since the check is left in place.
    #[test]
    fn a_stale_socket_is_removed_only_while_it_is_there() {
        let dir = Scratch::new("stale");
        let parent = opened(&dir.0);
        let name = OsStr::new("sock");
        let path = dir.0.join("sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let stale = fs::symlink_metadata(&path).unwrap();
        // Replaced by another socket (a new inode: the stale one is kept
        // under another name, so its number is not reused).
        let moved = dir.0.join("moved");
        fs::rename(&path, &moved).unwrap();
        let other = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(matches!(
            remove_stale(&parent, name, &stale),
            Err(BindError::PathOccupied)
        ));
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        drop(other);
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"file").unwrap();
        assert!(matches!(
            remove_stale(&parent, name, &stale),
            Err(BindError::PathOccupied)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"file");
        // Still the stale socket: removed.
        fs::remove_file(&path).unwrap();
        fs::rename(&moved, &path).unwrap();
        remove_stale(&parent, name, &stale).unwrap();
        assert!(fs::symlink_metadata(&path).is_err());
    }

    #[test]
    fn only_private_directories_of_the_name_are_cleaned() {
        let dir = Scratch::new("clean");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        let name = OsStr::new("local.sock");
        let stale = dir.0.join(".local.sock.123.4.bind");
        private_dir_at(&stale);
        drop(std::os::unix::net::UnixListener::bind(stale.join("s")).unwrap());
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
        let other = uid.wrapping_add(1);
        let parent = opened(&dir.0);
        remove_stale_private_dirs(&parent, name, other, other).unwrap();
        assert!(stale.exists());
        remove_stale_private_dirs(&parent, name, uid, uid).unwrap();
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

    /// What a leftover private directory holds is unlinked only when a bind
    /// put it there (the staged socket `s`, the staged lock `l` as a bind
    /// leaves it, of the expected owners); anything else is kept, and so is
    /// the directory, which is removed only once empty (never recursively).
    /// A directory of that name that is not private is left untouched.
    #[test]
    fn a_leftover_directory_keeps_what_a_bind_did_not_put_there() {
        let dir = Scratch::new("leftover");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        let parent = opened(&dir.0);
        let name = OsStr::new("local.sock");
        let leftover = |n: u32| dir.0.join(format!(".local.sock.4194305.{n}.bind"));
        let socket_at = |path: PathBuf| drop(std::os::unix::net::UnixListener::bind(path).unwrap());

        // Empty: removed.
        private_dir_at(&leftover(0));
        // Only a stale staged socket: cleared.
        private_dir_at(&leftover(1));
        socket_at(leftover(1).join("s"));
        // Only a staged lock (a killed lock creation): cleared.
        private_dir_at(&leftover(2));
        staged_lock_at(&leftover(2).join("l"));
        // A staged socket and an unexpected file: the socket goes, the file
        // and the directory stay.
        private_dir_at(&leftover(3));
        socket_at(leftover(3).join("s"));
        fs::write(leftover(3).join("keep"), b"keep").unwrap();
        // An `s` that is not a socket and an `l` that is not a file: kept.
        private_dir_at(&leftover(4));
        fs::write(leftover(4).join("s"), b"not a socket").unwrap();
        fs::create_dir(leftover(4).join("l")).unwrap();
        fs::write(leftover(4).join("l").join("inner"), b"").unwrap();
        // A directory inside: kept with what it holds.
        private_dir_at(&leftover(5));
        fs::create_dir(leftover(5).join("sub")).unwrap();
        fs::write(leftover(5).join("sub").join("inner"), b"").unwrap();
        // An `l` no bind leaves: with data, with a wider mode, or in a
        // directory with group or other bits. Kept, and so is the
        // directory.
        private_dir_at(&leftover(7));
        staged_lock_at(&leftover(7).join("l"));
        fs::write(leftover(7).join("l"), b"data").unwrap();
        private_dir_at(&leftover(8));
        staged_lock_at(&leftover(8).join("l"));
        fs::set_permissions(leftover(8).join("l"), fs::Permissions::from_mode(0o644)).unwrap();
        private_dir_at(&leftover(9));
        staged_lock_at(&leftover(9).join("l"));
        fs::set_permissions(leftover(9), fs::Permissions::from_mode(0o750)).unwrap();
        // A directory of that name that is not private (mode 0755, or 0700
        // with a special bit) is no bind's: nothing in it is unlinked (a
        // live socket `s` included), and it is not removed, even empty.
        fs::create_dir(leftover(10)).unwrap();
        fs::set_permissions(leftover(10), fs::Permissions::from_mode(0o755)).unwrap();
        let live = std::os::unix::net::UnixListener::bind(leftover(10).join("s")).unwrap();
        for (n, mode) in [(11, 0o755), (12, 0o1700)] {
            fs::create_dir(leftover(n)).unwrap();
            fs::set_permissions(leftover(n), fs::Permissions::from_mode(mode)).unwrap();
        }

        remove_stale_private_dirs(&parent, name, uid, uid).unwrap();
        assert!(
            fs::symlink_metadata(leftover(10).join("s"))
                .unwrap()
                .file_type()
                .is_socket()
        );
        for n in [10, 11, 12] {
            assert!(leftover(n).is_dir(), "{n}");
        }
        // Nor when it is cleared directly (as the bind's own directory is).
        clear_private_dir(&leftover(10), &leftover(10), [uid, uid]).unwrap();
        clear_private_dir(&leftover(11), &leftover(11), [uid, uid]).unwrap();
        assert!(leftover(10).join("s").exists() && leftover(11).is_dir());
        drop(live);
        for n in [0, 1, 2] {
            assert!(fs::symlink_metadata(leftover(n)).is_err(), "{n}");
        }
        assert!(fs::symlink_metadata(leftover(3).join("s")).is_err());
        assert_eq!(fs::read(leftover(3).join("keep")).unwrap(), b"keep");
        assert_eq!(fs::read(leftover(4).join("s")).unwrap(), b"not a socket");
        assert!(leftover(4).join("l").join("inner").exists());
        assert!(leftover(5).join("sub").join("inner").exists());
        assert_eq!(fs::read(leftover(7).join("l")).unwrap(), b"data");
        for n in [8, 9] {
            assert!(leftover(n).join("l").is_file(), "{n}");
        }

        // Staged entries of another owner are kept (root only: others
        // cannot give a file away).
        if uid == 0 {
            let foreign = leftover(6);
            private_dir_at(&foreign);
            socket_at(foreign.join("s"));
            staged_lock_at(&foreign.join("l"));
            for entry in ["s", "l"] {
                std::os::unix::fs::lchown(foreign.join(entry), Some(4_194_305), None).unwrap();
            }
            remove_stale_private_dirs(&parent, name, uid, uid).unwrap();
            assert!(foreign.join("s").exists() && foreign.join("l").exists());
            // Of the service UID: cleared.
            remove_stale_private_dirs(&parent, name, uid, 4_194_305).unwrap();
            assert!(fs::symlink_metadata(&foreign).is_err());
        }
    }

    /// A private directory another bind clears (as a leftover, under its
    /// lock) between its `mkdir` and its open, or between its open and its
    /// check, as at a contended first start: [`PrivateDir::create`] gives
    /// `None`, and the creation of the lock file retries, in a new private
    /// directory. Deterministic: the test hook takes the directory away at
    /// that step, once.
    #[test]
    fn a_private_directory_cleared_before_its_check_is_retried() {
        use std::{cell::Cell, rc::Rc};
        for (n, step) in [CreateStep::Made, CreateStep::Opened]
            .into_iter()
            .enumerate()
        {
            let dir = Scratch::new(&format!("cleared-{n}"));
            let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
            let parent = opened(&dir.0);
            let name = OsStr::new("local.sock");
            // The steps reached so far; the directory is taken away at the
            // first only.
            let reached = Rc::new(Cell::new(0));
            let count = Rc::clone(&reached);
            CREATE_HOOK.set(Some(Box::new(move |at, path: &Path| {
                if at == step {
                    if count.get() == 0 {
                        fs::remove_dir(path).unwrap();
                    }
                    count.set(count.get() + 1);
                }
            })));
            // Cleared at the step: `None`, nothing left.
            assert!(matches!(
                PrivateDir::create(&parent, name, uid, uid),
                Ok(None)
            ));
            assert_eq!(reached.get(), 1, "{step:?}");
            assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0, "{step:?}");
            // Through the lock: the first private directory cleared, the
            // second used; the lock file made, no directory left.
            reached.set(0);
            drop(lock(&parent, name, uid, uid).unwrap());
            assert_eq!(reached.get(), 2, "{step:?}");
            let entries: Vec<_> = fs::read_dir(&dir.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(entries, [OsString::from("local.sock.lock")], "{step:?}");
            CREATE_HOOK.set(None);
        }
    }

    /// A directory put in the place of the new private directory between
    /// its `mkdir` and its open, which is not the verified private one:
    /// [`PrivateDir::create`] refuses it, whichever term of its check of
    /// the open directory it fails. Deterministic: the test hook swaps the
    /// directory at that step. Each swap passes every other term, so that
    /// removing one term (or the whole check) is caught here. The same
    /// swaps after the open (the open directory is then the verified one
    /// and the path is not) are refused by the comparison of the open
    /// directory with the path. Not covered: the device term, which alone
    /// refuses a link to another file system whose inode number equals the
    /// link's (fresh tmpfs instances, btrfs subvolumes); a unit test cannot
    /// set that up without mounts. The owner case needs root (others cannot
    /// give a directory away) and is skipped otherwise: CI's root step runs
    /// only `--test local_transport`, so it runs in a manual root run.
    #[test]
    fn a_directory_swapped_in_before_its_check_is_not_verified() {
        // Swaps: the directory at the path is renamed away and `put`
        // makes what is at the path instead.
        type Put = fn(&Path, &Path);
        let cases: [(&str, Put); 4] = [
            // Any other user may enter it: the mode term.
            ("open to all", |path, _| {
                fs::DirBuilder::new().mode(0o755).create(path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }),
            // A link to a private directory of the process's UID, which
            // is what the open reaches: a directory, owned, closed, but
            // not the entry at the path (the inode term).
            ("a link", |path, away| {
                let target = away.with_extension("target");
                fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
                std::os::unix::fs::symlink(&target, path).unwrap();
            }),
            // A file nobody else may enter: not a directory (the open of a
            // file succeeds), every other term holds.
            ("a file", |path, _| {
                fs::write(path, b"").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }),
            // A private directory of another user (root only: others
            // cannot give a directory away): the owner term.
            ("another owner", |path, _| {
                fs::DirBuilder::new().mode(0o700).create(path).unwrap();
                std::os::unix::fs::lchown(path, Some(4_194_305), None).unwrap();
            }),
        ];
        for (n, (what, put)) in cases.into_iter().enumerate() {
            for step in [CreateStep::Made, CreateStep::Opened] {
                let dir = Scratch::new(&format!("swapped-{n}-{step:?}"));
                let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
                if what == "another owner" && uid != 0 {
                    continue;
                }
                let parent = opened(&dir.0);
                let name = OsStr::new("local.sock");
                CREATE_HOOK.set(Some(Box::new(move |at, path: &Path| {
                    if at == step {
                        let away = path.with_extension("away");
                        fs::rename(path, &away).unwrap();
                        put(path, &away);
                    }
                })));
                let created = PrivateDir::create(&parent, name, uid, uid);
                CREATE_HOOK.set(None);
                assert!(
                    matches!(created, Err(BindError::NotVerified)),
                    "{what} at {step:?}: {:?}",
                    created.map(|dir| dir.map(|dir| dir.path.clone()))
                );
            }
        }
    }

    /// A directory the process may not list is not scanned; any other
    /// failure to list it is an error.
    #[test]
    fn a_directory_that_cannot_be_listed_is_not_scanned() {
        let denied = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(listing(denied).unwrap().is_none());
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::Other] {
            assert_eq!(
                listing(Err(io::Error::from(kind))).unwrap_err().kind(),
                kind
            );
        }
        let dir = Scratch::new("listing");
        fs::write(dir.0.join("entry"), b"").unwrap();
        let entries = listing(fs::read_dir(&dir.0)).unwrap().unwrap();
        assert_eq!(entries.count(), 1);
    }

    /// The platform's `sun_path` size: 108 bytes on Linux, 104 on the BSDs
    /// and macOS.
    #[test]
    fn the_path_limit_is_the_platforms() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(SUN_PATH_BYTES, 108);
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        assert_eq!(SUN_PATH_BYTES, 104);
    }

    /// The staging address: through the open directory when `/proc/self/fd`
    /// is there, whatever the directory's length; else the full staging
    /// path, refused when it does not fit, also when the socket path does.
    #[test]
    fn the_staging_address_fits_or_is_refused() {
        let fd_dir = PathBuf::from("/proc/self/fd/7");
        let long = PathBuf::from(format!("/{}", "d".repeat(200))).join(".local.sock.1.0.bind");
        assert_eq!(
            staging_address(&long, Some(fd_dir.clone())).unwrap(),
            fd_dir.join("s")
        );
        // Without it: the full path, up to one byte under `sun_path`.
        let fits = |length: usize| {
            // `<dir>/.x.sock.1.0.bind` and `/s`: `length` bytes in all.
            let tail = "/.x.sock.1.0.bind";
            let dir = "d".repeat(length - tail.len() - "/s".len() - 1);
            let private = PathBuf::from(format!("/{dir}{tail}"));
            assert_eq!(private.join("s").as_os_str().len(), length);
            staging_address(&private, None)
        };
        assert_eq!(
            fits(SUN_PATH_BYTES - 1).unwrap().as_os_str().len(),
            SUN_PATH_BYTES - 1
        );
        assert!(matches!(
            fits(SUN_PATH_BYTES),
            Err(BindError::StagingPathTooLong)
        ));
        // A socket path that fits, whose staging path does not.
        let socket = PathBuf::from(format!("/{}", "d".repeat(80))).join("x.sock");
        assert!(socket.as_os_str().len() < SUN_PATH_BYTES);
        let private = socket
            .parent()
            .unwrap()
            .join(".x.sock.4194305.18446744073709551615.bind");
        assert!(matches!(
            staging_address(&private, None),
            Err(BindError::StagingPathTooLong)
        ));
        assert!(staging_address(&private, Some(fd_dir)).is_ok());
    }

    /// Every staged entry is reached through the open private directory: a
    /// rename of its path, and another directory put at the path (with a
    /// symbolic link where the socket would be), changes nothing the bind
    /// does in it. Without `/proc/self/fd` it prints a notice and passes.
    #[test]
    fn the_staged_entries_are_reached_through_the_open_directory() {
        let dir = Scratch::new("staged");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        let parent = opened(&dir.0);
        let private = PrivateDir::create(&parent, OsStr::new("x.sock"), uid, uid)
            .unwrap()
            .unwrap();
        if private.fd_dir().is_none() {
            eprintln!("NOTICE: /proc/self/fd is missing: the staged entries were NOT tested");
            return;
        }
        let address = private.bind_address().unwrap();
        let lock = private.entries().join(STAGED_LOCK_NAME);
        let moved = dir.0.join("moved");
        fs::rename(&private.path, &moved).unwrap();
        fs::create_dir(&private.path).unwrap();
        let target = dir.0.join("target");
        fs::write(&target, b"").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target, private.path.join(STAGED_NAME)).unwrap();

        let listener = std::os::unix::net::UnixListener::bind(&address).unwrap();
        fs::set_permissions(&address, fs::Permissions::from_mode(SOCKET_MODE)).unwrap();
        assert!(
            fs::symlink_metadata(&address)
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert!(
            fs::symlink_metadata(moved.join(STAGED_NAME))
                .unwrap()
                .file_type()
                .is_socket()
        );
        assert_eq!(
            fs::symlink_metadata(&target).unwrap().mode() & PERMISSION_BITS,
            0o644
        );
        staged_lock_at(&lock);
        assert!(moved.join(STAGED_LOCK_NAME).is_file());
        assert!(!private.path.join(STAGED_LOCK_NAME).exists());
        drop(listener);
        // Cleared through the open directory too: the moved directory's
        // entries go; the one at the path keeps its link.
        let at_path = private.path.clone();
        drop(private);
        assert!(fs::read_dir(&moved).unwrap().next().is_none());
        assert!(
            fs::symlink_metadata(at_path.join(STAGED_NAME))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// The lock file is opened without following a symbolic link: a link at
    /// the lock path, to a file or to nothing, is occupied, and the file it
    /// points to is not opened. Where [`OPEN_FLAGS`] are known only: `ELOOP`
    /// is 40 there.
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "riscv64",
            target_arch = "aarch64"
        )
    ))]
    #[test]
    fn the_lock_file_is_never_opened_through_a_link() {
        let dir = Scratch::new("lock-link");
        let target = dir.0.join("target");
        fs::write(&target, b"").unwrap();
        let lock = dir.0.join("x.sock.lock");
        std::os::unix::fs::symlink(&target, &lock).unwrap();
        let err = lock_options().unwrap().open(&lock).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(40), "ELOOP: {err:?}");
        assert!(matches!(open_lock(&lock), Err(BindError::PathOccupied)));
        fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink(dir.0.join("nowhere"), &lock).unwrap();
        assert!(matches!(open_lock(&lock), Err(BindError::PathOccupied)));
        fs::remove_file(&lock).unwrap();
        fs::create_dir(&lock).unwrap();
        assert!(matches!(open_lock(&lock), Err(BindError::PathOccupied)));
        fs::remove_dir(&lock).unwrap();
        assert!(matches!(open_lock(&lock), Ok(None)));
        fs::write(&lock, b"").unwrap();
        assert!(matches!(open_lock(&lock), Ok(Some(_))));
    }

    /// The socket's directory: owned by the service UID or root when the
    /// process binds for itself; by the process's UID alone (root's, as
    /// only root binds for another UID) when it binds for another UID, so a
    /// directory of the service UID is refused then (it could rename what
    /// the bind gives away); never writable by group or others unless
    /// sticky; a directory. The UIDs are arguments, so the rules are
    /// checked whatever UID runs the test.
    #[test]
    fn the_socket_directory_has_a_trusted_owner() {
        let dir = Scratch::new("parent-owner");
        let metadata = fs::symlink_metadata(&dir.0).unwrap();
        let uid = metadata.uid();
        let other = uid.wrapping_add(1);
        check_directory(&metadata, uid, uid).unwrap();
        // Root's: trusted when the process binds for itself.
        check_directory(&fs::symlink_metadata("/").unwrap(), other, other).unwrap();
        // A bind for the owner from another UID: refused, root's included.
        assert!(matches!(
            check_directory(&metadata, other, uid),
            Err(BindError::UnsafeDirectory)
        ));
        // Another UID binding for itself: only root's directory is trusted.
        let result = check_directory(&metadata, other, other);
        if uid == 0 {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(BindError::UnsafeDirectory)),
                "{result:?}"
            );
        }
        // A bind for another UID: the process's own directory only.
        check_directory(&metadata, uid, other).unwrap();
        for mode in [0o775, 0o757] {
            fs::set_permissions(&dir.0, fs::Permissions::from_mode(mode)).unwrap();
            let metadata = fs::symlink_metadata(&dir.0).unwrap();
            assert!(matches!(
                check_directory(&metadata, uid, uid),
                Err(BindError::UnsafeDirectory)
            ));
        }
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o1777)).unwrap();
        check_directory(&fs::symlink_metadata(&dir.0).unwrap(), uid, uid).unwrap();
        let file = dir.0.join("file");
        fs::write(&file, b"").unwrap();
        assert!(matches!(
            check_directory(&fs::symlink_metadata(&file).unwrap(), uid, uid),
            Err(BindError::UnsafeDirectory)
        ));
    }

    /// Every directory the lookup of the socket's directory passes through
    /// is checked, not only the socket's directory's parent: a writable
    /// grandparent, a writable directory holding a symbolic link on the
    /// way, and one the link leads through, each refused by its depth.
    #[test]
    fn every_directory_on_the_way_is_checked() {
        let dir = Scratch::new("ancestors");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        let depth = dir.0.components().count() - 1;
        let grandparent = dir.0.join("g");
        let socket_dir = grandparent.join("p").join("s");
        fs::create_dir_all(&socket_dir).unwrap();
        for mode in [0o755, 0o700, 0o1777, 0o1775] {
            fs::set_permissions(&grandparent, fs::Permissions::from_mode(mode)).unwrap();
            check_ancestors(&socket_dir, uid, uid).unwrap();
        }
        for mode in [0o777, 0o775, 0o757] {
            fs::set_permissions(&grandparent, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(
                    check_ancestors(&socket_dir, uid, uid),
                    Err(BindError::UnsafeAncestor { depth: d }) if d == depth + 1
                ),
                "{mode:o}"
            );
        }
        fs::set_permissions(&grandparent, fs::Permissions::from_mode(0o755)).unwrap();
        // The directory that holds a link on the way.
        let open = dir.0.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&grandparent, open.join("link")).unwrap();
        assert!(matches!(
            check_ancestors(&open.join("link").join("p").join("s"), uid, uid),
            Err(BindError::UnsafeAncestor { depth: d }) if d == depth + 1
        ));
        // A safe link into a writable directory: the directory it leads
        // through is checked.
        let safe = dir.0.join("safe");
        fs::create_dir(&safe).unwrap();
        fs::create_dir_all(open.join("p").join("s")).unwrap();
        std::os::unix::fs::symlink(&open, safe.join("link")).unwrap();
        assert!(matches!(
            check_ancestors(&safe.join("link").join("p").join("s"), uid, uid),
            Err(BindError::UnsafeAncestor { depth: d }) if d == depth + 1
        ));
        // A safe link to a safe directory, and `..` after it.
        std::os::unix::fs::symlink(&grandparent, safe.join("good")).unwrap();
        check_ancestors(&safe.join("good").join("p").join("s"), uid, uid).unwrap();
        check_ancestors(&safe.join("good").join("p").join("..").join("p"), uid, uid).unwrap();
        // `..` is looked up in the directory before it, which is checked
        // too, though the path then leaves it: a writable one is refused.
        assert!(matches!(
            check_ancestors(&open.join("..").join("g").join("p").join("s"), uid, uid),
            Err(BindError::UnsafeAncestor { depth: d }) if d == depth + 1
        ));
        if uid == 0 {
            // And one of an untrusted owner in a sticky directory (whose
            // owner may move it, pointing its `..` elsewhere).
            let sticky = dir.0.join("t");
            let foreign = sticky.join("u");
            fs::create_dir_all(&foreign).unwrap();
            fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777)).unwrap();
            std::os::unix::fs::lchown(&foreign, Some(4_194_305), None).unwrap();
            let through = foreign.join("..").join("..").join("g").join("p").join("s");
            assert!(matches!(
                check_ancestors(&through, uid, uid),
                Err(BindError::UnsafeAncestor { depth: d }) if d == depth + 2
            ));
            check_ancestors(&through, 4_194_305, 4_194_305).unwrap();
        }
        // A loop of links.
        std::os::unix::fs::symlink(safe.join("loop"), safe.join("loop")).unwrap();
        assert!(matches!(
            check_ancestors(&safe.join("loop").join("s"), uid, uid),
            Err(BindError::Io(_))
        ));
        // A bind for another UID trusts root alone: the process's own
        // directories are refused unless it is root.
        let result = check_ancestors(&socket_dir, uid, uid.wrapping_add(1));
        if uid == 0 {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(BindError::UnsafeAncestor { .. })),
                "{result:?}"
            );
        }
        // Another owner (root only): refused unless it is the service UID
        // binding for itself; never for a bind for another UID, the owner
        // being the service UID or the binding process.
        if uid == 0 {
            std::os::unix::fs::lchown(&grandparent, Some(4_194_305), None).unwrap();
            for (effective, service) in [(uid, uid), (uid, 4_194_305), (4_194_305, uid)] {
                assert!(
                    matches!(
                        check_ancestors(&socket_dir, effective, service),
                        Err(BindError::UnsafeAncestor { depth: d }) if d == depth + 1
                    ),
                    "{effective} for {service}"
                );
            }
            check_ancestors(&socket_dir, 4_194_305, 4_194_305).unwrap();
        }
    }

    /// A symbolic link on the way in a sticky directory others may write
    /// (`/tmp`) is followed only when its owner is trusted: root, or the
    /// service UID when the process binds for itself; else the bind is
    /// refused at the link's directory. It needs a root-owned sticky
    /// `/tmp`; otherwise it prints a notice and passes.
    #[test]
    fn a_link_in_a_sticky_directory_needs_a_trusted_owner() {
        let shared = Path::new("/tmp");
        if !fs::symlink_metadata(shared)
            .is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o1002 == 0o1002)
        {
            eprintln!("NOTICE: no root-owned sticky /tmp: links in it were NOT tested");
            return;
        }
        let dir = Scratch::new("sticky-link");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        fs::create_dir(dir.0.join("sub")).unwrap();
        struct Unlink(PathBuf);
        impl Drop for Unlink {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let link = Unlink(shared.join(format!("skyoauth-socket-unit-link-{}", std::process::id())));
        let _ = fs::remove_file(&link.0);
        std::os::unix::fs::symlink(&dir.0, &link.0).unwrap();
        let through = link.0.join("sub");
        // The process's own link, for its own bind: followed.
        assert_eq!(
            check_ancestors(&through, uid, uid).unwrap().ino(),
            fs::metadata(dir.0.join("sub")).unwrap().ino()
        );
        // For another UID (root alone is trusted): refused at `/tmp`,
        // unless the process is root.
        let result = check_ancestors(&through, uid, uid.wrapping_add(1));
        if uid == 0 {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(BindError::UnsafeAncestor { depth: 1 })),
                "{result:?}"
            );
        }
        if uid == 0 {
            // Another UID's link: refused, unless that UID binds for
            // itself.
            std::os::unix::fs::lchown(&link.0, Some(4_194_305), None).unwrap();
            for (effective, service) in [(0, 0), (0, 4_194_305)] {
                let result = check_ancestors(&through, effective, service);
                assert!(
                    matches!(result, Err(BindError::UnsafeAncestor { depth: 1 })),
                    "{effective} for {service}: {result:?}"
                );
            }
            check_ancestors(&through, 4_194_305, 4_194_305).unwrap();
            // In a directory others may not write, the owner of a link does
            // not matter: only the directory's owner can replace it.
            let safe = dir.0.join("safe");
            fs::create_dir(&safe).unwrap();
            let inner = safe.join("link");
            std::os::unix::fs::symlink(dir.0.join("sub"), &inner).unwrap();
            std::os::unix::fs::lchown(&inner, Some(4_194_305), None).unwrap();
            check_ancestors(&inner, 0, 0).unwrap();
        }
    }

    /// Every entry of the socket's directory is reached through the open
    /// directory: with the directory renamed after it was opened, and
    /// another one put at its path holding the same names (a leftover
    /// private directory, a live socket), the lock file, the scan for
    /// leftovers, the private directory, the stale socket's check and
    /// removal, the publication and the socket's removal all act on the
    /// moved directory, and the one at the path is left as it was. Without
    /// `/proc/self/fd` it prints a notice and passes.
    #[tokio::test]
    async fn the_socket_directory_is_reached_through_its_descriptor() {
        let dir = Scratch::new("parent-fd");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        let socket_dir = dir.0.join("s");
        fs::create_dir(&socket_dir).unwrap();
        let parent = opened(&socket_dir);
        if parent.fd_dir.is_none() {
            eprintln!("NOTICE: /proc/self/fd is missing: the open directory was NOT tested");
            return;
        }
        let moved = dir.0.join("moved");
        fs::rename(&socket_dir, &moved).unwrap();
        fs::create_dir(&socket_dir).unwrap();
        let name = OsStr::new("local.sock");
        let leftover = ".local.sock.4194305.1.bind";
        for at in [&moved, &socket_dir] {
            private_dir_at(&at.join(leftover));
            staged_lock_at(&at.join(leftover).join("l"));
        }
        // A stale socket in the moved directory, a live one at the path: a
        // check by the path would find it in use.
        drop(std::os::unix::net::UnixListener::bind(moved.join("local.sock")).unwrap());
        let live = std::os::unix::net::UnixListener::bind(socket_dir.join("local.sock")).unwrap();
        let decoy_socket = fs::symlink_metadata(socket_dir.join("local.sock"))
            .unwrap()
            .ino();
        let names = |at: &Path| {
            let mut names: Vec<String> = fs::read_dir(at)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        let decoy = names(&socket_dir);
        assert_eq!(decoy, [leftover, "local.sock"]);
        let decoy_unchanged = || {
            assert_eq!(names(&socket_dir), decoy);
            assert!(socket_dir.join(leftover).join("l").is_file());
            assert_eq!(
                fs::symlink_metadata(socket_dir.join("local.sock"))
                    .unwrap()
                    .ino(),
                decoy_socket
            );
        };

        let lock = lock(&parent, name, uid, uid).unwrap();
        remove_stale_private_dirs(&parent, name, uid, uid).unwrap();
        let private = PrivateDir::create(&parent, name, uid, uid)
            .unwrap()
            .unwrap();
        decoy_unchanged();
        let Existing::Stale(stale) = existing(&parent, name, uid).await.unwrap() else {
            panic!("the moved directory's stale socket was not found");
        };
        remove_stale(&parent, name, &stale).unwrap();
        let staged = private.bind_address().unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&staged).unwrap();
        publish(&staged, &parent, name).unwrap();
        let bound = fs::symlink_metadata(&staged).unwrap();
        decoy_unchanged();
        drop(private);
        assert_eq!(names(&moved), ["local.sock", "local.sock.lock"]);
        assert_eq!(
            fs::symlink_metadata(moved.join("local.sock"))
                .unwrap()
                .ino(),
            bound.ino()
        );
        decoy_unchanged();
        let socket = SocketFile {
            path: socket_dir.join("local.sock"),
            parent,
            name: name.to_os_string(),
            dev: bound.dev(),
            ino: bound.ino(),
            _lock: lock,
        };
        drop(socket);
        assert_eq!(names(&moved), ["local.sock.lock"]);
        decoy_unchanged();
        drop((listener, live));
    }

    #[tokio::test]
    async fn the_effective_uid_is_the_owner_of_what_the_process_creates() {
        let dir = Scratch::new("euid");
        let owner = fs::symlink_metadata(&dir.0).unwrap().uid();
        assert_eq!(effective_uid().unwrap(), owner);
    }
}
