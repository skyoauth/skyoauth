//! The canonical public identity of an mTLS public key, as the service
//! derives it (`skyoauth_service::identity`; identity-registry section 5.2;
//! lead decision, 2026-11-24): [`PUBLIC_IDENTITY_PREFIX`] followed by the 64
//! lowercase hexadecimal digits of the SHA-256 digest of the key's DER
//! `SubjectPublicKeyInfo`.
//!
//! Only the bounds and the digest are reimplemented here. The service also
//! checks that the bytes are a strict DER `SubjectPublicKeyInfo` and refuses
//! them otherwise; this function does not, so it gives an identity for bytes
//! the service refuses. Which key algorithms and forms are accepted is not
//! decided yet, and the service, which derives the identity it stores from
//! the DER bytes it is given, stays the authority. The operator shows this
//! identity to check what the service reports, never to replace the service's
//! derivation.
//!
//! The fixture `tests/conformance/fixtures/_recovery/public_identity.v1.json`
//! holds the known answers both sides check.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::text::encode_hex;

/// The prefix of a canonical public identity.
pub const PUBLIC_IDENTITY_PREFIX: &str = "spki-sha256:";

/// The largest DER `SubjectPublicKeyInfo` the service accepts, in bytes.
pub const MAX_SPKI_DER_BYTES: usize = 4096;

/// Why no identity is given. Carries no input byte: `Debug` names the
/// variant only, `Display` is the service's fixed text for the same case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// No bytes.
    Empty,
    /// More than [`MAX_SPKI_DER_BYTES`] bytes.
    TooLarge,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the public key is empty",
            Self::TooLarge => "the public key is too large",
        })
    }
}

impl std::error::Error for IdentityError {}

/// The canonical public identity of the key whose DER
/// `SubjectPublicKeyInfo` is `spki_der`: 1 to [`MAX_SPKI_DER_BYTES`] bytes,
/// whose structure is not checked (see the module documentation).
///
/// # Errors
///
/// [`IdentityError::Empty`] for no bytes, [`IdentityError::TooLarge`] for
/// more than [`MAX_SPKI_DER_BYTES`].
pub fn public_identity_of_spki(spki_der: &[u8]) -> Result<String, IdentityError> {
    if spki_der.is_empty() {
        return Err(IdentityError::Empty);
    }
    if spki_der.len() > MAX_SPKI_DER_BYTES {
        return Err(IdentityError::TooLarge);
    }
    let digest = encode_hex(&Sha256::digest(spki_der));
    let mut identity = String::with_capacity(PUBLIC_IDENTITY_PREFIX.len() + digest.len());
    identity.push_str(PUBLIC_IDENTITY_PREFIX);
    identity.push_str(&digest);
    Ok(identity)
}
