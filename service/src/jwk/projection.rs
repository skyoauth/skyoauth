//! The canonical public projection of a validated set (the JSON text to
//! store), its fingerprint, and the parse of a stored projection (see
//! "Projection, fingerprint and stored sets" in the module docs of
//! [`crate::jwk`]).
//!
//! The projection of a key is a JSON object of these members, in
//! lexicographic member order, with no whitespace: `alg` (only when the
//! upload had it), then `e`, `kid`, `kty`, `n` for `RSA`; `crv`, `kid`,
//! `kty`, `x`, `y` for `EC`; `crv`, `kid`, `kty`, `x` for `OKP`. The set is
//! `{"keys":[…]}`, its keys sorted by `kid` (byte order; the `kid`s are
//! unique ASCII, and the set parse already returns them in that order),
//! joined by `,`. So the same keys in any upload order give the same bytes
//! and fingerprint (provisional lead pick, 2026-11-22). The key values are
//! the canonical unpadded base64url of the validated octets and the `kid`
//! is validated text (`A`-`Z`, `a`-`z`, `0`-`9`, `-._~:+/=`): plain ASCII
//! with nothing to escape, as in the `thumbprint` submodule.

use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::base64url::encode;
use super::key::{Algorithm, KNOWN_ALGORITHMS, Points, PublicJwk, PublicKey};
use super::set::{JwkSet, JwkSetError, MAX_SET_BYTES, parse_jwk_set, parse_keys};

/// The longest input [`parse_stored`] parses, in bytes: 4 ×
/// [`MAX_SET_BYTES`], checked on the raw input before the JSON parse, room
/// for the spaces and reordering of `jsonb` text output (provisional lead
/// pick, 2026-11-22). The compact size rule of [`MAX_SET_BYTES`] still
/// applies to the parsed value.
pub const MAX_STORED_BYTES: usize = 4 * MAX_SET_BYTES;

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

/// The canonical projection of a set of `keys`, which the set parse has
/// sorted by `kid` (see the submodule docs).
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
/// stores. Built only by [`validate_keyset`]. The registry write API must
/// take a `&ValidatedKeyset`, never a [`StoredKeyset`] or a bare `&str`:
/// [`StoredKeyset::public_json`] returns the same `&str`, so a copy or
/// restore path could otherwise store keys whose points were never checked.
/// `Debug` prints the keys (as
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

    /// The keys, sorted by `kid` (the projection's order).
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
/// [`parse_jwk_set`] but the point checks, and with [`KNOWN_ALGORITHMS`] in
/// place of the allowed set, so its keys are not point-checked here. Built
/// only by [`parse_stored`]. Its keys are **not verifier-ready**: no point
/// checks ran, so the verifier never takes them (provisional lead pick,
/// 2026-11-22; see [`parse_stored`]). Never pass it, or its
/// [`public_json`](Self::public_json), to a write: writes take a
/// [`ValidatedKeyset`]. `Debug` prints the keys (without key octets) and
/// the fingerprint, never the projection.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredKeyset {
    keys: Vec<PublicJwk>,
    public_json: String,
    fingerprint: KeysetFingerprint,
}

impl StoredKeyset {
    /// The keys, sorted by `kid` (the projection's order), whatever the
    /// stored order.
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
/// value, as for an upload; before that, input longer than
/// [`MAX_STORED_BYTES`] is refused with [`JwkSetError::TooLarge`] without
/// being parsed (provisional lead pick, 2026-11-22).
///
/// # Trust
///
/// The stored value is trusted to have been validated at write by
/// [`validate_keyset`] (or [`parse_jwk_set`]), with every point check. The
/// database `CHECK` floor (`0004`: a nonempty `keys` array of objects, no
/// private or symmetric member) does not make that true by itself: a row
/// written by any other path passes it with an off-curve key.
///
/// The keys are **not verifier-ready**: no point checks ran (provisional
/// lead pick, 2026-11-22). The verifier's key cache (T11.7) is built from a
/// full [`validate_keyset`] pass per version, once, never from this
/// function; this function is for reading a stored set back where no key
/// is used to verify (for example its projection or fingerprint).
///
/// # Errors
///
/// A [`JwkSetError`] here is a data-integrity error (a stored row that
/// breaks the rules it was written under), not a client error: a future
/// HTTP mapping must not reuse the upload mapping for it.
pub fn parse_stored(stored: impl AsRef<[u8]>) -> Result<StoredKeyset, JwkSetError> {
    let stored = stored.as_ref();
    if stored.len() > MAX_STORED_BYTES {
        return Err(JwkSetError::TooLarge);
    }
    let value: Value = serde_json::from_slice(stored).map_err(|_| JwkSetError::NotJson)?;
    let keys = parse_keys(&value, &KNOWN_ALGORITHMS, Points::Skip)?;
    let public_json = public_json(&keys);
    let fingerprint = KeysetFingerprint::of(&public_json);
    Ok(StoredKeyset {
        keys,
        public_json,
        fingerprint,
    })
}
