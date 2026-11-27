//! The output file of `sign` and `issue-challenge` (`--out`): a new file,
//! never an existing one. `sign` creates and writes it at once
//! ([`write_new`]); `issue-challenge` creates it before its request is sent
//! ([`create_new`]) and writes it only after the challenge was issued
//! ([`write()`]), so an existing `--out` sends nothing, and a request that
//! does not succeed leaves the file empty.
//!
//! The file is created with `create_new` (`O_CREAT | O_EXCL` on Unix,
//! `CREATE_NEW` on Windows), so an existing file, or a symbolic link
//! (even a dangling one), is never followed, truncated or overwritten; on
//! Unix it is created with mode 0600 (less if the umask removes an owner
//! bit). The bytes are written and synchronized to the disk (`sync_all`)
//! before success is reported. A write or synchronization that fails after
//! the file was created may leave a partial or empty file: such a file is
//! not a response artifact and is refused as one. Under a file-size limit
//! (`RLIMIT_FSIZE`) a write over it raises `SIGXFSZ`, whose default action
//! kills the process before the write returns: no exit code, and the file
//! is partial or empty too. No signal is handled here (that would take an
//! `unsafe` call or a dependency), so the exit code 3 for such a write
//! holds only where the signal is ignored.
//!
//! No access control list is set or read: on macOS the new file inherits
//! the ACL entries of its directory, which its mode does not show, so the
//! help tells the operator to remove the ACLs of the `--out` directory.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write as _},
    path::Path,
};

use crate::Failure;

/// The flag that names the file, in every message.
const FLAG: &str = "--out";

/// Writes `bytes` to a new file at `path`.
///
/// # Errors
///
/// [`Failure::Io`] when the file exists or cannot be created, written or
/// synchronized.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = create_new(path)?;
    write(&mut file, bytes)
        .map_err(|kind| Failure::Io(format!("{FLAG}: the file cannot be written ({kind})")))
}

/// Creates a new, empty file at `path` (mode 0600 on Unix).
///
/// # Errors
///
/// [`Failure::Io`] when the file exists or cannot be created.
pub fn create_new(path: &Path) -> Result<File, Failure> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|err| {
        Failure::Io(if err.kind() == io::ErrorKind::AlreadyExists {
            format!("{FLAG}: the file already exists; it is never overwritten")
        } else {
            format!("{FLAG}: the file cannot be created ({})", err.kind())
        })
    })
}

/// Writes `bytes` to `file` and synchronizes it to the disk.
///
/// # Errors
///
/// The kind of the error of the write or the synchronization that failed.
pub fn write(file: &mut File, bytes: &[u8]) -> Result<(), io::ErrorKind> {
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| err.kind())
}
