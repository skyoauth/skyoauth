//! The output file of `sign` (`--out`): a new file, never an existing one.
//!
//! The file is created with `create_new` (`O_CREAT | O_EXCL` on Unix,
//! `CREATE_NEW` on Windows), so an existing file, or a symbolic link
//! (even a dangling one), is never followed, truncated or overwritten; on
//! Unix it is created with mode 0600 (less if the umask removes an owner
//! bit). The bytes are written and synchronized to the disk (`sync_all`)
//! before success is reported. A write or synchronization that fails after
//! the file was created may leave a partial or empty file: such a file is
//! not a response artifact and is refused as one.

use std::{fs::OpenOptions, io::Write as _, path::Path};

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
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|err| {
        Failure::Io(if err.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{FLAG}: the file already exists; it is never overwritten")
        } else {
            format!("{FLAG}: the file cannot be created ({})", err.kind())
        })
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| {
            Failure::Io(format!(
                "{FLAG}: the file cannot be written ({})",
                err.kind()
            ))
        })
}
