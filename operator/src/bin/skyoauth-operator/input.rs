//! Reading an artifact file: a regular file of at most a given size, read
//! whole. Errors name the flag that gave the file and the kind of the
//! failure, not the path or the operating system's text, so they are the
//! same on every platform.

use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use crate::Failure;

/// The bytes of the regular file at `path`, given by `flag`, at most `cap`
/// bytes.
///
/// The path is checked before it is opened, so a directory, a device or a
/// named pipe is refused without being opened (opening a named pipe could
/// block), and the opened file is checked again. A file that grows past
/// `cap` while it is read is refused all the same: at most `cap + 1`
/// bytes are read.
///
/// # Errors
///
/// [`Failure::Io`] when the file cannot be read, is not a regular file or
/// is larger than `cap`.
pub fn read_file(flag: &str, path: &Path, cap: usize) -> Result<Vec<u8>, Failure> {
    let unreadable = |err: std::io::Error| {
        Failure::Io(format!("{flag}: the file cannot be read ({})", err.kind()))
    };
    let not_regular = || Failure::Io(format!("{flag}: not a regular file"));
    let too_large = || Failure::Io(format!("{flag}: the file is larger than {cap} bytes"));
    let limit = u64::try_from(cap).unwrap_or(u64::MAX);

    let metadata = fs::metadata(path).map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    if metadata.len() > limit {
        return Err(too_large());
    }
    let file = File::open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    if metadata.len() > limit {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > cap {
        return Err(too_large());
    }
    Ok(bytes)
}
