//! Creating the socket file: owned by the service UID, mode 0600, never
//! reachable by another UID in between, and never in place of something
//! else at the path (see the module docs of [`crate::local_transport`],
//! "The socket file").

use std::{
    fmt, fs, io,
    os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use tokio::net::{UnixListener, UnixStream};

/// The socket file's mode.
pub(super) const SOCKET_MODE: u32 = 0o600;

/// The private directory's mode.
const PRIVATE_DIR_MODE: u32 = 0o700;

/// The permission bits of a mode.
const PERMISSION_BITS: u32 = 0o7777;

/// How many private directory names a bind tries before it gives up (a name
/// is taken only when a directory of a crashed process with the same PID
/// was left behind).
const PRIVATE_DIR_ATTEMPTS: u64 = 16;

/// Why [`bind`](super::LocalTransport::bind) did not start the transport.
/// Nothing is left at the socket path on any variant (a stale socket it
/// removed stays removed).
#[derive(Debug)]
pub enum BindError {
    /// The socket path has no parent directory or no file name.
    InvalidPath,
    /// Something is at the socket path that is not a socket owned by the
    /// service UID: a file, a directory, a symbolic link, another UID's
    /// socket. It is left in place.
    PathOccupied,
    /// A process accepts connections on the socket at the path.
    InUse,
    /// After the bind, the socket path is not the socket the transport
    /// bound with the service UID as owner and mode 0600.
    NotVerified,
    /// A file-system or socket call failed, a refused change of owner (the
    /// process may not give the socket to the service UID) included.
    Io(io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("the local socket path has no directory or name"),
            Self::PathOccupied => f.write_str(
                "the local socket path holds something other than a socket owned by the \
                 service UID",
            ),
            Self::InUse => f.write_str("another process listens on the local socket"),
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
            Self::InvalidPath | Self::PathOccupied | Self::InUse | Self::NotVerified => None,
        }
    }
}

impl From<io::Error> for BindError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// The socket file the transport created, identified by its inode: dropping
/// it removes the path only while the path is still that socket.
#[derive(Debug)]
pub(super) struct SocketFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl SocketFile {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Whether `metadata` is this socket.
    fn is(&self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_socket() && metadata.dev() == self.dev && metadata.ino() == self.ino
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| self.is(&metadata)) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The private directory a bind creates next to the socket path, removed
/// with what it holds when dropped.
struct PrivateDir {
    path: PathBuf,
}

impl PrivateDir {
    /// Creates a new directory with mode 0700 in `parent`, under a name
    /// derived from `name`, the process ID and a counter, and checks that
    /// no one but its owner may enter it. `mkdir` never reuses an existing
    /// entry (a symbolic link included): a taken name is skipped.
    fn create(parent: &Path, name: &std::ffi::OsStr) -> Result<(Self, fs::Metadata), BindError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut last = None;
        for _ in 0..PRIVATE_DIR_ATTEMPTS {
            let mut entry = std::ffi::OsString::from(".");
            entry.push(name);
            entry.push(format!(
                ".{}.{}.bind",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let path = parent.join(entry);
            match fs::DirBuilder::new().mode(PRIVATE_DIR_MODE).create(&path) {
                Ok(()) => {
                    let dir = Self { path };
                    let metadata = fs::symlink_metadata(&dir.path)?;
                    // The umask can only clear bits of 0700.
                    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
                        return Err(BindError::NotVerified);
                    }
                    return Ok((dir, metadata));
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => last = Some(err),
                Err(err) => return Err(err.into()),
            }
        }
        Err(last.map_or(BindError::PathOccupied, BindError::Io))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
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
    // means a listener; only a refusal means none.
    match UnixStream::connect(path).await {
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => Ok(Existing::Stale(metadata)),
        Ok(_) => Err(BindError::InUse),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(BindError::InUse),
        Err(err) => Err(err.into()),
    }
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
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    // The directory's owner is the process's effective (file-system) UID.
    let (private, private_metadata) = PrivateDir::create(parent, name)?;
    let effective_uid = private_metadata.uid();
    let service_uid = service_uid.unwrap_or(effective_uid);

    if let Existing::Stale(stale) = existing(path, service_uid).await? {
        // Still the socket that refused the connection.
        let now = fs::symlink_metadata(path)?;
        if now.dev() != stale.dev() || now.ino() != stale.ino() {
            return Err(BindError::PathOccupied);
        }
        fs::remove_file(path)?;
    }

    // Bound where no other UID can reach it: the mode the umask leaves does
    // not matter until the socket has its owner and mode 0600.
    let temporary = private.path.join("socket");
    let listener = UnixListener::bind(&temporary)?;
    if service_uid != effective_uid {
        std::os::unix::fs::chown(&temporary, Some(service_uid), None)?;
    }
    fs::set_permissions(&temporary, fs::Permissions::from_mode(SOCKET_MODE))?;
    let bound = fs::symlink_metadata(&temporary)?;
    // `link` never replaces an entry: one that appeared since the check is
    // left in place.
    fs::hard_link(&temporary, path).map_err(|err| match err.kind() {
        io::ErrorKind::AlreadyExists => BindError::PathOccupied,
        _ => BindError::Io(err),
    })?;
    let socket = SocketFile {
        path: path.to_path_buf(),
        dev: bound.dev(),
        ino: bound.ino(),
    };
    drop(private);

    let metadata = fs::symlink_metadata(path)?;
    if !socket.is(&metadata)
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
        for (err, text) in [
            (
                BindError::InvalidPath,
                "the local socket path has no directory or name",
            ),
            (
                BindError::PathOccupied,
                "the local socket path holds something other than a socket owned by the \
                 service UID",
            ),
            (
                BindError::InUse,
                "another process listens on the local socket",
            ),
            (
                BindError::NotVerified,
                "the local socket is not owned by the service UID with mode 0600 after the bind",
            ),
        ] {
            assert_eq!(err.to_string(), text);
            assert!(std::error::Error::source(&err).is_none());
        }
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
}
