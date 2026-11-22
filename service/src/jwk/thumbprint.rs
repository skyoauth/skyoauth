//! RFC 7638 JWK thumbprints with SHA-256.
//!
//! The hash input is the JSON object of the key type's required members
//! only, in lexicographic member order, with no whitespace (RFC 7638
//! section 3.2): `{"e":…,"kty":"RSA","n":…}`,
//! `{"crv":…,"kty":"EC","x":…,"y":…}` and `{"crv":…,"kty":"OKP","x":…}`
//! (RFC 8037 section 2). The member values are the canonical unpadded
//! base64url of the validated octets, which equal the uploaded text since
//! only canonical text is accepted; every value is plain ASCII with nothing
//! to escape. The thumbprint is the unpadded base64url of the digest.

use std::fmt;

use sha2::{Digest, Sha256};

use super::base64url::encode;
use super::key::PublicKey;

/// An RFC 7638 SHA-256 JWK thumbprint, as unpadded base64url (43
/// characters). A digest of public key material, not the material itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Thumbprint(String);

impl Thumbprint {
    /// The base64url text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The RFC 7638 hash input of `key` (see the module docs).
pub(crate) fn thumbprint_input(key: &PublicKey) -> String {
    match key {
        PublicKey::Rsa { n, e } => {
            format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, encode(e), encode(n))
        }
        PublicKey::Ec { curve, x, y } => format!(
            r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
            curve.name(),
            encode(x),
            encode(y)
        ),
        PublicKey::Okp { curve, x } => format!(
            r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
            curve.name(),
            encode(x)
        ),
    }
}

/// The RFC 7638 SHA-256 thumbprint of `key`.
pub(crate) fn thumbprint(key: &PublicKey) -> Thumbprint {
    Thumbprint(encode(&Sha256::digest(thumbprint_input(key).as_bytes())))
}
