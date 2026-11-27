//! The seed file of `sign` (`docs/proposals/operator-cli-artifacts.md`,
//! "The seed file"): the 32-byte Ed25519 seed (RFC 8032) as 64 lowercase
//! hexadecimal digits, optionally followed by one newline, and nothing
//! else.
//!
//! - The file must be a regular file, not a symbolic link: its path is
//!   checked with `symlink_metadata` before it is opened, so a link, a
//!   directory, a device or a named pipe is refused without being opened,
//!   and the opened file is checked again.
//! - On Unix it must be owned by the process's effective user and of mode
//!   0600 exactly, checked on the path and again on the opened file, which
//!   must be the same file (device and inode) as the path checked. On
//!   other platforms (Windows) its protection is not checked: the operator
//!   must protect it by other means.
//! - No access control list is read (the standard library cannot), as in
//!   the client's socket path check (`check_socket`, "Access control
//!   lists"). Linux shows a POSIX ACL's grants in the group bits (its
//!   mask), so a file an ACL lets others read is not of mode 0600; macOS
//!   does not, so there an ACL can let others read a file of mode 0600:
//!   the help tells the operator to remove the ACLs of the seed file and
//!   of the `--out` directory.
//! - A file of more than 128 bytes is refused as too large; at most 129
//!   bytes are read, into a fixed buffer, so a file that grows while it is
//!   read is refused all the same. Within the cap, the bytes must decode as
//!   a seed (at most 65 bytes): any other content, a carriage return, a
//!   byte order mark, a prefix, a second newline or a trailing space, is
//!   one refusal, "not a seed".
//!
//! No message holds the path, the file's bytes or the seed: a failure is
//! named by the flag and its kind. Nothing here derives or implements
//! `Debug`. The seed is not wiped from memory: neither this binary nor the
//! library's software signer (built without `zeroize`) wipes it.

use std::{
    fs::{self, File, Metadata},
    io::{self, Read},
    path::Path,
};

use crate::Failure;

/// The flag that names the file, in every message.
const FLAG: &str = "--seed-file";

/// The seed's length, in bytes.
const SEED_BYTES: usize = 32;

/// The largest seed file read: more is refused as too large, not read.
/// Larger than a seed (64 digits and a newline), so a file with a few bytes
/// too many is refused as what it is, not a seed.
const MAX_SEED_FILE_BYTES: usize = 128;

/// The required mode of the file on Unix: read and write for its owner,
/// nothing else (no special bit either).
#[cfg(unix)]
const SEED_FILE_MODE: u32 = 0o600;

/// A file failure of the seed file, exit 3.
fn io_failure(what: &str) -> Failure {
    Failure::Io(format!("{FLAG}: {what}"))
}

fn unreadable(err: &io::Error) -> Failure {
    Failure::Io(format!("{FLAG}: the file cannot be read ({})", err.kind()))
}

fn too_large() -> Failure {
    io_failure(&format!(
        "the file is larger than {MAX_SEED_FILE_BYTES} bytes"
    ))
}

/// The seed of the seed file at `path`.
///
/// # Errors
///
/// [`Failure::Io`] when the file cannot be read, is a symbolic link or not
/// a regular file, is not protected (Unix: owned by another user, or of
/// another mode than 0600), changed between its check and its opening, or
/// is larger than 128 bytes; [`Failure::Refused`] when its bytes are not
/// a seed.
pub fn read(path: &Path) -> Result<[u8; SEED_BYTES], Failure> {
    let owner = effective_owner()?;
    let checked = fs::symlink_metadata(path).map_err(|err| unreadable(&err))?;
    if checked.file_type().is_symlink() {
        return Err(io_failure("a symbolic link, not the file itself"));
    }
    check(&checked, &owner)?;
    let mut file = File::open(path).map_err(|err| unreadable(&err))?;
    let opened = file.metadata().map_err(|err| unreadable(&err))?;
    check(&opened, &owner)?;
    if !same_file(&checked, &opened) {
        return Err(io_failure(
            "the file changed between its check and its opening",
        ));
    }
    let mut buffer = [0_u8; MAX_SEED_FILE_BYTES + 1];
    let mut length = 0;
    while length < buffer.len() {
        match file.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(unreadable(&err)),
        }
    }
    if length > MAX_SEED_FILE_BYTES {
        return Err(too_large());
    }
    decode(&buffer[..length]).ok_or_else(|| {
        Failure::Refused(format!(
            "{FLAG}: the file is not a seed: 64 lowercase hexadecimal digits, optionally \
             followed by one newline"
        ))
    })
}

/// The checks of the file's metadata, on its path and again once opened: a
/// regular file, protected, of at most [`MAX_SEED_FILE_BYTES`].
fn check(metadata: &Metadata, owner: &Owner) -> Result<(), Failure> {
    if !metadata.is_file() {
        return Err(io_failure("not a regular file"));
    }
    protected(metadata, owner)?;
    if usize::try_from(metadata.len()).map_or(true, |len| len > MAX_SEED_FILE_BYTES) {
        return Err(too_large());
    }
    Ok(())
}

/// The seed of `bytes`: 64 lowercase hexadecimal digits and an optional
/// newline.
fn decode(bytes: &[u8]) -> Option<[u8; SEED_BYTES]> {
    let digits = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let (pairs, rest) = digits.as_chunks::<2>();
    if pairs.len() != SEED_BYTES || !rest.is_empty() {
        return None;
    }
    let mut seed = [0_u8; SEED_BYTES];
    for (byte, [high, low]) in seed.iter_mut().zip(pairs) {
        *byte = (hex_digit(*high)? << 4) | hex_digit(*low)?;
    }
    Some(seed)
}

/// The value of one lowercase hexadecimal digit.
const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The user that must own the seed file: the process's effective user on
/// Unix.
#[cfg(unix)]
type Owner = u32;

/// No owner is checked on other platforms.
#[cfg(not(unix))]
struct Owner;

/// The process's effective UID, as the kernel reports it for a pipe the
/// process creates (the owner of a new pipe: the effective UID on Linux,
/// where it is the file-system UID, which follows it, and on macOS and the
/// BSDs): no file is created and no `unsafe` call made.
#[cfg(unix)]
fn effective_owner() -> Result<Owner, Failure> {
    use std::os::{fd::OwnedFd, unix::fs::MetadataExt as _};
    let cannot = |err: io::Error| {
        Failure::Io(format!(
            "the effective user cannot be read ({})",
            err.kind()
        ))
    };
    let (reader, _writer) = io::pipe().map_err(cannot)?;
    let pipe = File::from(OwnedFd::from(reader));
    Ok(pipe.metadata().map_err(cannot)?.uid())
}

#[cfg(not(unix))]
const fn effective_owner() -> Result<Owner, Failure> {
    Ok(Owner)
}

/// Unix: owned by `owner`, of mode 0600 exactly.
#[cfg(unix)]
fn protected(metadata: &Metadata, owner: &Owner) -> Result<(), Failure> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.uid() != *owner {
        return Err(io_failure("the file is not owned by the effective user"));
    }
    if metadata.mode() & 0o7777 != SEED_FILE_MODE {
        return Err(io_failure("the file's mode is not exactly 0600"));
    }
    Ok(())
}

/// Not checked on other platforms (Windows): a documented residual.
#[cfg(not(unix))]
const fn protected(_metadata: &Metadata, _owner: &Owner) -> Result<(), Failure> {
    Ok(())
}

/// Unix: the same device and inode.
#[cfg(unix)]
fn same_file(checked: &Metadata, opened: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    checked.dev() == opened.dev() && checked.ino() == opened.ino()
}

/// Not comparable with `std` on other platforms.
#[cfg(not(unix))]
const fn same_file(_checked: &Metadata, _opened: &Metadata) -> bool {
    true
}
