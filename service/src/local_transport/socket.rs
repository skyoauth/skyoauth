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

/// `O_NOFOLLOW | O_NONBLOCK` for opening the lock file, by architecture:
/// the crate does not depend on `libc` (which this crate may not name
/// without a new dependency), so the values are Linux's own, from its
/// `asm-generic/fcntl.h` (`O_NOFOLLOW` 0o400000 on x86_64 and riscv64) and
/// `arch/arm64/include/uapi/asm/fcntl.h` (0o100000 on aarch64), and
/// `O_NONBLOCK` 0o4000 on all three. Elsewhere there is none, and
/// [`bind`] refuses to start ([`BindError::Io`] of kind
/// [`io::ErrorKind::Unsupported`]).
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "riscv64")
))]
const LOCK_OPEN_FLAGS: Option<i32> = Some(0o400_000 | 0o4000);
/// See the other architectures' definition.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const LOCK_OPEN_FLAGS: Option<i32> = Some(0o100_000 | 0o4000);
/// See the Linux definitions: no flags known here.
#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "riscv64",
        target_arch = "aarch64"
    )
)))]
const LOCK_OPEN_FLAGS: Option<i32> = None;

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
    /// The socket's directory is a symbolic link, is writable by its group
    /// or others without the sticky bit, or has the wrong owner: the
    /// service UID or root when the service UID is the process's effective
    /// UID, else (root binding for another service UID) the effective UID
    /// itself, so the service UID cannot rename what the bind creates in
    /// it. Another UID could otherwise replace the socket.
    UnsafeDirectory,
    /// A directory the lookup of the socket's directory passes through (an
    /// ancestor, or one holding a symbolic link on the way) is not owned by
    /// root, the service UID or the process's effective UID, or is writable
    /// by its group or others without the sticky bit: another UID could rename the socket's
    /// directory, or the path to it. `depth` names the directory by its
    /// depth below the root directory (0 is the root directory itself), not
    /// by its path.
    UnsafeAncestor {
        /// The unsafe directory's depth below the root directory.
        depth: usize,
    },
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
    /// A file-system or socket call failed, a refused change of owner (the
    /// process may not give the socket to the service UID) included; also
    /// a lookup of the socket's directory through more than 40 symbolic
    /// links, and a target where the lock file cannot be opened without
    /// following a symbolic link (kind [`io::ErrorKind::Unsupported`]: not
    /// Linux on x86_64, aarch64 or riscv64).
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
                "the local socket's directory must be owned by the service UID or root (by \
                 the process's UID when the service UID is another), not be a symbolic link, \
                 and not be writable by group or others unless sticky",
            ),
            Self::UnsafeAncestor { depth } => write!(
                f,
                "the local socket's directory is reached through a directory {depth} levels \
                 below the root directory that is not owned by root, the service UID or the \
                 process's UID, or is writable by group or others without the sticky bit",
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
            | Self::UnsafeAncestor { .. }
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
/// cleared when dropped ([`clear_private_dir`]).
struct PrivateDir {
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
    /// entry (a symbolic link included): a taken name is skipped.
    fn create(
        parent: &Path,
        name: &OsStr,
        effective_uid: u32,
        service_uid: u32,
    ) -> Result<Self, BindError> {
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
                    let dir = Self {
                        path,
                        handle,
                        owners: [effective_uid, service_uid],
                    };
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

    /// The open directory as a path, `/proc/self/fd/<fd>`, where the system
    /// has `/proc/self/fd`.
    fn fd_dir(&self) -> Option<PathBuf> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd as _;
            let fd_dir = Path::new("/proc/self/fd");
            if fd_dir.is_dir() {
                return Some(fd_dir.join(self.handle.as_raw_fd().to_string()));
            }
        }
        None
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

/// Clears the private directory at `path`, one this process or a killed
/// bind created, reaching its entries through `entries` (the open
/// directory, or `path` itself): it unlinks only the entries a bind puts
/// there, the staged socket `s` (a socket) and the staged lock `l` (a
/// regular file), each owned by one of `owners`, and then removes the
/// directory at `path` only if it is empty (`rmdir`, never recursively).
/// Anything else in it is left, and so is the directory.
fn clear_private_dir(path: &Path, entries: &Path, owners: [u32; 2]) -> io::Result<()> {
    for name in [STAGED_NAME, STAGED_LOCK_NAME] {
        // The staged socket is a socket, the staged lock a regular file.
        let expected = |metadata: &fs::Metadata| {
            if name == STAGED_NAME {
                metadata.file_type().is_socket()
            } else {
                metadata.is_file()
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
/// directory to this, and then opens the lock file again). Only
/// directories (never a symbolic link) owned by `effective_uid` whose name
/// is `.<name>.<digits>.<digits>.bind` are cleared, and only when `parent`
/// can be listed ([`listing`]).
fn remove_stale_private_dirs(
    parent: &Path,
    name: &OsStr,
    effective_uid: u32,
    service_uid: u32,
) -> io::Result<()> {
    let prefix = private_dir_prefix(name);
    let prefix = prefix.as_encoded_bytes();
    let Some(entries) = listing(fs::read_dir(parent))? else {
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
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() && metadata.uid() == effective_uid {
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

/// Refuses a socket directory another UID could write to, or one whose
/// owner could rename what a bind for another service UID creates in it
/// (see [`BindError::UnsafeDirectory`]).
fn check_directory(parent: &Path, effective_uid: u32, service_uid: u32) -> Result<(), BindError> {
    let metadata = fs::symlink_metadata(parent)?;
    let owner_ok = if effective_uid == service_uid {
        metadata.uid() == service_uid || metadata.uid() == 0
    } else {
        // Root binding for another UID: the service UID must not own the
        // directory, or it could swap the private directory for one of its
        // own while the bind changes the socket's owner and mode.
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
/// `parent` from the root directory (from the working directory when
/// `parent` is relative), entry by entry, following each symbolic link as
/// the kernel would, and checks every directory it looks an entry up in,
/// the root directory included: owned by root, `service_uid` or
/// `effective_uid` (the process binding, which a bind for another UID
/// trusts already: it is root, or it cannot give the files away), and not
/// writable by group or others unless sticky. The socket's directory
/// itself, where the walk ends, is [`check_directory`]'s.
fn check_ancestors(parent: &Path, effective_uid: u32, service_uid: u32) -> Result<(), BindError> {
    let mut steps = Vec::new();
    if parent.is_relative() {
        // The working directory as the kernel resolved it: no link in it.
        push_steps(&mut steps, &std::env::current_dir()?);
    }
    push_steps(&mut steps, parent);
    let mut at = PathBuf::from("/");
    let mut links = 0;
    while let Some(step) = steps.pop() {
        let name = match step {
            Step::Root => {
                at = PathBuf::from("/");
                continue;
            }
            // `at` holds no symbolic link: its parent is the lexical one.
            Step::Up => {
                at.pop();
                continue;
            }
            Step::Name(name) => name,
        };
        let metadata = fs::symlink_metadata(&at)?;
        if !metadata.is_dir()
            || ![0, service_uid, effective_uid].contains(&metadata.uid())
            || !write_safe(metadata.mode())
        {
            // `at` is `/` and normal entries only.
            let depth = at.components().count() - 1;
            return Err(BindError::UnsafeAncestor { depth });
        }
        let next = at.join(&name);
        let found = fs::symlink_metadata(&next)?;
        if found.file_type().is_symlink() {
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
    Ok(())
}

/// Opens, or creates, the lock file of `name` in `parent`, `<name>.lock`
/// (a regular file owned by `service_uid`, mode 0600), and locks it,
/// exclusively and without waiting, for the listener's life. A lock another
/// open file holds is [`BindError::InUse`]. The file is never removed:
/// removing a lock file while another process holds it open would let two
/// processes lock two files of the same name.
fn lock(
    parent: &Path,
    name: &OsStr,
    effective_uid: u32,
    service_uid: u32,
) -> Result<File, BindError> {
    let mut lock_name = name.to_os_string();
    lock_name.push(LOCK_SUFFIX);
    let lock_path = parent.join(lock_name);
    for _ in 0..LOCK_ATTEMPTS {
        let opened = match open_lock(&lock_path)? {
            Some(file) => Some(file),
            None => create_lock(parent, name, &lock_path, effective_uid, service_uid)?,
        };
        // `None`: another bind published a lock file meanwhile, or cleared
        // this one's private directory; open what is there now.
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
/// ([`LOCK_OPEN_FLAGS`]).
fn lock_options() -> io::Result<OpenOptions> {
    let Some(flags) = LOCK_OPEN_FLAGS else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the local socket's lock file can be opened without following a symbolic link \
             only on Linux on x86_64, aarch64 and riscv64",
        ));
    };
    let mut options = OpenOptions::new();
    options.read(true).write(true).custom_flags(flags);
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
/// its lock, before the link: the caller opens the lock file again. Killed
/// at any point, it leaves either no lock file or one owned by
/// `service_uid` with mode 0600, and at most a private directory, which
/// the next bind clears.
fn create_lock(
    parent: &Path,
    name: &OsStr,
    lock_path: &Path,
    effective_uid: u32,
    service_uid: u32,
) -> Result<Option<File>, BindError> {
    let private = PrivateDir::create(parent, name, effective_uid, service_uid)?;
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
    if service_uid != effective_uid {
        std::os::unix::fs::fchown(&file, Some(service_uid), None)?;
    }
    // The umask may have cleared bits of 0600.
    file.set_permissions(fs::Permissions::from_mode(SOCKET_MODE))?;
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
    check_directory(parent, effective_uid, service_uid)?;
    check_ancestors(parent, effective_uid, service_uid)?;

    // Everything below runs under the lock, held until the socket file is
    // dropped: two transports never replace or remove each other's socket.
    let lock = lock(parent, name, effective_uid, service_uid)?;
    remove_stale_private_dirs(parent, name, effective_uid, service_uid)?;
    let private = PrivateDir::create(parent, name, effective_uid, service_uid)?;

    if let Existing::Stale(stale) = existing(path, service_uid).await? {
        remove_stale(path, &stale)?;
    }

    // Bound where no other UID can reach it: the mode the umask leaves does
    // not matter until the socket has its owner and mode 0600. One address,
    // through the open directory, for the bind and every call after it:
    // never the directory's path, which a rename could point elsewhere
    // between the calls (a `chmod` through a planted symbolic link).
    let staged = private.bind_address()?;
    let listener = UnixListener::bind(&staged)?;
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
            BindError::UnsafeAncestor { depth: 3 },
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
        remove_stale_private_dirs(&dir.0, name, other, other).unwrap();
        assert!(stale.exists());
        remove_stale_private_dirs(&dir.0, name, uid, uid).unwrap();
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
    /// put it there (the staged socket `s`, the staged lock `l`, of the
    /// expected owners); anything else is kept, and so is the directory,
    /// which is removed only once empty (never recursively).
    #[test]
    fn a_leftover_directory_keeps_what_a_bind_did_not_put_there() {
        let dir = Scratch::new("leftover");
        let uid = fs::symlink_metadata(&dir.0).unwrap().uid();
        let name = OsStr::new("local.sock");
        let leftover = |n: u32| dir.0.join(format!(".local.sock.4194305.{n}.bind"));
        let socket_at = |path: PathBuf| drop(std::os::unix::net::UnixListener::bind(path).unwrap());

        // Empty: removed.
        fs::create_dir(leftover(0)).unwrap();
        // Only a stale staged socket: cleared.
        fs::create_dir(leftover(1)).unwrap();
        socket_at(leftover(1).join("s"));
        // Only a staged lock (a killed lock creation): cleared.
        fs::create_dir(leftover(2)).unwrap();
        fs::write(leftover(2).join("l"), b"").unwrap();
        // A staged socket and an unexpected file: the socket goes, the file
        // and the directory stay.
        fs::create_dir(leftover(3)).unwrap();
        socket_at(leftover(3).join("s"));
        fs::write(leftover(3).join("keep"), b"keep").unwrap();
        // An `s` that is not a socket and an `l` that is not a file: kept.
        fs::create_dir(leftover(4)).unwrap();
        fs::write(leftover(4).join("s"), b"not a socket").unwrap();
        fs::create_dir(leftover(4).join("l")).unwrap();
        fs::write(leftover(4).join("l").join("inner"), b"").unwrap();
        // A directory inside: kept with what it holds.
        fs::create_dir(leftover(5)).unwrap();
        fs::create_dir(leftover(5).join("sub")).unwrap();
        fs::write(leftover(5).join("sub").join("inner"), b"").unwrap();

        remove_stale_private_dirs(&dir.0, name, uid, uid).unwrap();
        for n in [0, 1, 2] {
            assert!(fs::symlink_metadata(leftover(n)).is_err(), "{n}");
        }
        assert!(fs::symlink_metadata(leftover(3).join("s")).is_err());
        assert_eq!(fs::read(leftover(3).join("keep")).unwrap(), b"keep");
        assert_eq!(fs::read(leftover(4).join("s")).unwrap(), b"not a socket");
        assert!(leftover(4).join("l").join("inner").exists());
        assert!(leftover(5).join("sub").join("inner").exists());

        // Staged entries of another owner are kept (root only: others
        // cannot give a file away).
        if uid == 0 {
            let foreign = leftover(6);
            fs::create_dir(&foreign).unwrap();
            socket_at(foreign.join("s"));
            fs::write(foreign.join("l"), b"").unwrap();
            for entry in ["s", "l"] {
                std::os::unix::fs::lchown(foreign.join(entry), Some(4_194_305), None).unwrap();
            }
            remove_stale_private_dirs(&dir.0, name, uid, uid).unwrap();
            assert!(foreign.join("s").exists() && foreign.join("l").exists());
            // Of the service UID: cleared.
            remove_stale_private_dirs(&dir.0, name, uid, 4_194_305).unwrap();
            assert!(fs::symlink_metadata(&foreign).is_err());
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
        let private = PrivateDir::create(&dir.0, OsStr::new("x.sock"), uid, uid).unwrap();
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
        fs::write(&lock, b"").unwrap();
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
    /// points to is not opened.
    #[cfg(target_os = "linux")]
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
        // A loop of links.
        std::os::unix::fs::symlink(safe.join("loop"), safe.join("loop")).unwrap();
        assert!(matches!(
            check_ancestors(&safe.join("loop").join("s"), uid, uid),
            Err(BindError::Io(_))
        ));
        // The process's own directories, when it binds for another UID.
        check_ancestors(&socket_dir, uid, uid.wrapping_add(1)).unwrap();
        // Another owner (root only): refused unless it is the service UID
        // or the effective UID.
        if uid == 0 {
            std::os::unix::fs::lchown(&grandparent, Some(4_194_305), None).unwrap();
            assert!(matches!(
                check_ancestors(&socket_dir, uid, uid),
                Err(BindError::UnsafeAncestor { depth: d }) if d == depth + 1
            ));
            check_ancestors(&socket_dir, uid, 4_194_305).unwrap();
            // Or the effective UID (another process binding for root).
            check_ancestors(&socket_dir, 4_194_305, uid).unwrap();
        }
    }

    #[tokio::test]
    async fn the_effective_uid_is_the_owner_of_what_the_process_creates() {
        let dir = Scratch::new("euid");
        let owner = fs::symlink_metadata(&dir.0).unwrap().uid();
        assert_eq!(effective_uid().unwrap(), owner);
    }
}
