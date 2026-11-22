//! The canonical public projection of a validated set (the JSON text to
//! store), its fingerprint, and the parse of a stored projection (see
//! "Projection, fingerprint and stored sets" in the module docs of
//! [`crate::jwk`]).
//!
//! The projection of a key is a JSON object of these members, in
//! lexicographic member order, with no whitespace: `alg` (only when the
//! upload had it), then `e`, `kid`, `kty`, `n` for `RSA`; `crv`, `kid`,
//! `kty`, `x`, `y` for `EC`; `crv`, `kid`, `kty`, `x` for `OKP`. The set is
//! `{"keys":[…]}`, its keys in set order, joined by `,`. The key values are
//! the canonical unpadded base64url of the validated octets and the `kid`
//! is validated text (`A`-`Z`, `a`-`z`, `0`-`9`, `-._~:+/=`): plain ASCII
//! with nothing to escape, as in the `thumbprint` submodule.

use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::base64url::encode;
use super::key::{Algorithm, KNOWN_ALGORITHMS, Points, PublicJwk, PublicKey};
use super::set::{JwkSet, JwkSetError, parse_jwk_set, parse_keys};

/// The canonical projection of one key (see the submodule docs).
fn key_json(jwk: &PublicJwk) -> String {
    let alg = jwk
        .alg()
        .map(|alg| format!(r#""alg":"{}","#, alg.name()))
        .unwrap_or_default();
    let kid = jwk.kid().as_str();
    match jwk.key() {
        PublicKey::Rsa { n, e } => format!(
            r#"{{{alg}"e":"{}","kid":"{kid}","kty":"RSA","n":"{}"}}"#,
            encode(e),
            encode(n)
        ),
        PublicKey::Ec { curve, x, y } => format!(
            r#"{{{alg}"crv":"{}","kid":"{kid}","kty":"EC","x":"{}","y":"{}"}}"#,
            curve.name(),
            encode(x),
            encode(y)
        ),
        PublicKey::Okp { curve, x } => format!(
            r#"{{{alg}"crv":"{}","kid":"{kid}","kty":"OKP","x":"{}"}}"#,
            curve.name(),
            encode(x)
        ),
    }
}

/// The canonical projection of a set of `keys` (see the submodule docs).
pub(crate) fn public_json(keys: &[PublicJwk]) -> String {
    let keys: Vec<String> = keys.iter().map(key_json).collect();
    format!(r#"{{"keys":[{}]}}"#, keys.join(","))
}

/// The fingerprint of a set's canonical projection (inferred): the unpadded
/// base64url of the SHA-256 digest of the projection's bytes, 43
/// characters. A digest of public key material, not the material itself.
///
/// Its use is open: the design section 5.7 export gives a version only
/// `id` and `public_jwks_ref` (OQ-IR-6, open), and whether the version's
/// `fingerprint` column holds this value is the wiring's decision (T11.9).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeysetFingerprint(String);

impl KeysetFingerprint {
    /// The fingerprint of the projection text `public_json`.
    fn of(public_json: &str) -> Self {
        Self(encode(&Sha256::digest(public_json.as_bytes())))
    }

    /// The base64url text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeysetFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An uploaded set that passed every check of [`parse_jwk_set`], with its
/// canonical public projection and fingerprint: what the keyset write path
/// stores. Built only by [`validate_keyset`]. `Debug` prints the keys (as
/// [`PublicJwk`] does, without key octets) and the fingerprint, never the
/// projection, which holds the key octets.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedKeyset {
    set: JwkSet,
    public_json: String,
    fingerprint: KeysetFingerprint,
}

impl ValidatedKeyset {
    /// The validated set.
    pub fn set(&self) -> &JwkSet {
        &self.set
    }

    /// The keys, in upload order.
    pub fn keys(&self) -> &[PublicJwk] {
        self.set.keys()
    }

    /// The canonical public projection, the JSON text to store (equal to
    /// [`JwkSet::to_public_json`]). It never holds an uploaded member
    /// outside the projection, the private members included (an upload
    /// with one is refused anyway).
    pub fn public_json(&self) -> &str {
        &self.public_json
    }

    /// The fingerprint of [`public_json`](Self::public_json) (inferred).
    pub fn fingerprint(&self) -> &KeysetFingerprint {
        &self.fingerprint
    }
}

impl fmt::Debug for ValidatedKeyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedKeyset")
            .field("keys", &self.set.keys())
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Validates an uploaded JWK Set as [`parse_jwk_set`] does, every check
/// included, and returns it with its canonical public projection and
/// fingerprint.
pub fn validate_keyset(
    value: &Value,
    allowed: &[Algorithm],
) -> Result<ValidatedKeyset, JwkSetError> {
    let set = parse_jwk_set(value, allowed)?;
    let public_json = set.to_public_json();
    let fingerprint = KeysetFingerprint::of(&public_json);
    Ok(ValidatedKeyset {
        set,
        public_json,
        fingerprint,
    })
}

/// A set read back from the database by [`parse_stored`]: every rule of
/// [`parse_jwk_set`] but the point checks, so its keys are not
/// point-checked here. Built only by [`parse_stored`]. `Debug` prints the
/// keys (without key octets) and the fingerprint, never the projection.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredKeyset {
    keys: Vec<PublicJwk>,
    public_json: String,
    fingerprint: KeysetFingerprint,
}

impl StoredKeyset {
    /// The keys, in stored order.
    pub fn keys(&self) -> &[PublicJwk] {
        &self.keys
    }

    /// The key whose `kid` is exactly `kid`.
    pub fn get(&self, kid: &str) -> Option<&PublicJwk> {
        self.keys.iter().find(|key| key.kid().as_str() == kid)
    }

    /// The canonical public projection of the parsed keys, recomputed: it
    /// does not depend on the stored text's member order or whitespace
    /// (`jsonb` reorders members and its text output adds spaces).
    pub fn public_json(&self) -> &str {
        &self.public_json
    }

    /// The fingerprint of [`public_json`](Self::public_json) (inferred).
    pub fn fingerprint(&self) -> &KeysetFingerprint {
        &self.fingerprint
    }
}

impl fmt::Debug for StoredKeyset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredKeyset")
            .field("keys", &self.keys)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Parses a JWK Set read back from the database (a version's
/// `public_jwks`), as JSON text or bytes.
///
/// It applies the shape, size and per-key rules of [`parse_jwk_set`]
/// (members and allowlist, `kid`, encodings and lengths, RSA bounds, `alg`
/// rules, unique `kid`s and keys) but **no point arithmetic**: no EC
/// on-curve or range check and no Ed25519 canonical, decoding or
/// small-order check (provisional lead pick, 2026-11-22: they cost about
/// 8.8 ms per Ed25519 key, too much per read). So a key that is not a point
/// of its curve is accepted here and refused by [`parse_jwk_set`].
///
/// The `alg` rules run with [`KNOWN_ALGORITHMS`] as the allowed set
/// (inferred): the allowed set was applied at write, and the algorithm a
/// token may use is chosen at verification against the source's
/// `algorithms` and the allowed set (T11.7, OQ-TP-3), so narrowing the
/// allowed set later does not make every stored set unreadable. An RSA key
/// without `alg` is still refused. The size bound is measured on the parsed
/// value, as for an upload; the raw input is parsed whole first.
///
/// # Trust
///
/// The stored value is trusted to have been validated at write by
/// [`validate_keyset`] (or [`parse_jwk_set`]), with every point check. The
/// database `CHECK` floor (`0004`: a nonempty `keys` array of objects, no
/// private or symmetric member) does not make that true by itself: a row
/// written by any other path passes it with an off-curve key. Runtime
/// verification (T11.7) must select from stored keys that were validated
/// at write, read through this function, and not re-run the full parse per
/// request.
pub fn parse_stored(stored: impl AsRef<[u8]>) -> Result<StoredKeyset, JwkSetError> {
    let value: Value = serde_json::from_slice(stored.as_ref()).map_err(|_| JwkSetError::NotJson)?;
    let keys = parse_keys(&value, &KNOWN_ALGORITHMS, Points::Skip)?;
    let public_json = public_json(&keys);
    let fingerprint = KeysetFingerprint::of(&public_json);
    Ok(StoredKeyset {
        keys,
        public_json,
        fingerprint,
    })
}
