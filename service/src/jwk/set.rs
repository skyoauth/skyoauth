//! One uploaded JWK Set (RFC 7517 section 5): its shape, bounds and the
//! uniqueness of `kid` and key within it.

use std::{fmt, io};

use serde_json::Value;

use super::key::{Algorithm, JwkError, Kid, Points, PublicJwk, parse_jwk};
use super::projection;

/// The most keys one set may hold (inferred).
pub const MAX_KEYS: usize = 20;

/// The largest set, in bytes of its compact JSON serialization (inferred:
/// 64 KiB).
pub const MAX_SET_BYTES: usize = 64 * 1024;

/// A validated JWK Set: at most [`MAX_KEYS`] public keys with distinct
/// `kid`s and distinct thumbprints, sorted by `kid` (byte order, the
/// projection's order). Built only by [`parse_jwk_set`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<PublicJwk>,
}

impl JwkSet {
    /// The keys, sorted by `kid` (byte order).
    pub fn keys(&self) -> &[PublicJwk] {
        &self.keys
    }

    /// The key whose `kid` is exactly `kid`.
    pub fn get(&self, kid: &str) -> Option<&PublicJwk> {
        self.keys.iter().find(|key| key.kid().as_str() == kid)
    }

    /// The canonical public projection of the set, the JSON text to store
    /// (see "Projection, fingerprint and stored sets" in the module docs of
    /// [`crate::jwk`]): only `alg`, `kty`, `kid` and the key members;
    /// members sorted, keys sorted by `kid`, no whitespace. [`validate_keyset`](super::validate_keyset)
    /// returns it with the set.
    pub fn to_public_json(&self) -> String {
        projection::public_json(&self.keys)
    }
}

/// Why a JWK Set is refused. A key is named by its index in `keys` and,
/// once validated, its `kid`; no variant holds key material.
///
/// From [`parse_jwk_set`] or [`validate_keyset`](super::validate_keyset)
/// it is a client error (the upload is refused). From
/// [`parse_stored`](super::parse_stored) it is a data-integrity error (a
/// stored row breaks the rules it was written under), not a client error:
/// a future HTTP mapping must not reuse the upload mapping for it.
///
/// The enum is `#[non_exhaustive]`: a later task may add a variant, so a
/// `match` outside this crate needs a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwkSetError {
    /// The stored value is not JSON text. Only
    /// [`parse_stored`](super::parse_stored) returns it; the parser's
    /// message is dropped, so no input text is echoed.
    NotJson,
    /// The compact serialization is longer than [`MAX_SET_BYTES`], or
    /// (only from [`parse_stored`](super::parse_stored)) the raw stored
    /// input is longer than [`MAX_STORED_BYTES`](super::MAX_STORED_BYTES)
    /// and was not parsed.
    TooLarge,
    /// The set is not a JSON object.
    NotAnObject,
    /// The set has no `keys` member.
    MissingKeys,
    /// The set has a member other than `keys` (inferred). The member is
    /// not named: its name is uploaded text.
    UnexpectedMember,
    /// `keys` is not an array.
    KeysNotArray,
    /// `keys` is empty.
    NoKeys,
    /// `keys` holds more than [`MAX_KEYS`] entries.
    TooManyKeys { count: usize },
    /// An entry of `keys` is not a JSON object.
    KeyNotObject { index: usize },
    /// An entry of `keys` is refused.
    Key { index: usize, error: JwkError },
    /// Two keys share a `kid`.
    DuplicateKid {
        kid: Kid,
        first: usize,
        second: usize,
    },
    /// Two keys with different `kid`s are the same key (same thumbprint).
    DuplicateKey { first_kid: Kid, second_kid: Kid },
}

impl fmt::Display for JwkSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotJson => f.write_str("stored JWK set is not JSON"),
            Self::TooLarge => write!(f, "JWK set is larger than {MAX_SET_BYTES} bytes"),
            Self::NotAnObject => f.write_str("JWK set is not a JSON object"),
            Self::MissingKeys => f.write_str("JWK set has no \"keys\" member"),
            Self::UnexpectedMember => f.write_str("JWK set has a member other than \"keys\""),
            Self::KeysNotArray => f.write_str("JWK set \"keys\" is not an array"),
            Self::NoKeys => f.write_str("JWK set \"keys\" is empty"),
            Self::TooManyKeys { count } => {
                write!(f, "JWK set has {count} keys, more than {MAX_KEYS}")
            }
            Self::KeyNotObject { index } => write!(f, "JWK set key {index} is not an object"),
            Self::Key { index, error } => write!(f, "JWK set key {index}: {error}"),
            Self::DuplicateKid { kid, first, second } => {
                write!(f, "JWK set keys {first} and {second} share kid \"{kid}\"")
            }
            Self::DuplicateKey {
                first_kid,
                second_kid,
            } => write!(
                f,
                "JWK set kids \"{first_kid}\" and \"{second_kid}\" name the same key"
            ),
        }
    }
}

impl std::error::Error for JwkSetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Counts written bytes and fails once they pass `max`, so measuring an
/// oversized value stops early.
struct Bounded {
    written: usize,
    max: usize,
}

impl io::Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written = self.written.saturating_add(buf.len());
        if self.written > self.max {
            return Err(io::Error::other("over the bound"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Whether the compact JSON serialization of `value` is at most `max`
/// bytes.
fn within_size(value: &Value, max: usize) -> bool {
    serde_json::to_writer(&mut Bounded { written: 0, max }, value).is_ok()
}

/// Validates an uploaded JWK Set against the rules of the module docs of
/// [`crate::jwk`]; `allowed` is the allowed algorithm set, normally
/// [`DEFAULT_ALLOWED_ALGORITHMS`](super::DEFAULT_ALLOWED_ALGORITHMS).
/// The first refusal found is returned.
pub fn parse_jwk_set(value: &Value, allowed: &[Algorithm]) -> Result<JwkSet, JwkSetError> {
    parse_keys(value, allowed, Points::Check).map(|keys| JwkSet { keys })
}

/// The set rules of [`parse_jwk_set`], with the point checks run or
/// skipped as `points` says; the keys sorted by `kid` (byte order). Error
/// indexes are positions in the input `keys`.
pub(crate) fn parse_keys(
    value: &Value,
    allowed: &[Algorithm],
    points: Points,
) -> Result<Vec<PublicJwk>, JwkSetError> {
    if !within_size(value, MAX_SET_BYTES) {
        return Err(JwkSetError::TooLarge);
    }
    let set = value.as_object().ok_or(JwkSetError::NotAnObject)?;
    let entries = match set.get("keys") {
        None => return Err(JwkSetError::MissingKeys),
        Some(Value::Array(entries)) => entries,
        Some(_) => return Err(JwkSetError::KeysNotArray),
    };
    if set.len() != 1 {
        return Err(JwkSetError::UnexpectedMember);
    }
    if entries.is_empty() {
        return Err(JwkSetError::NoKeys);
    }
    if entries.len() > MAX_KEYS {
        return Err(JwkSetError::TooManyKeys {
            count: entries.len(),
        });
    }
    let mut keys: Vec<PublicJwk> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let jwk = entry
            .as_object()
            .ok_or(JwkSetError::KeyNotObject { index })?;
        let key =
            parse_jwk(jwk, allowed, points).map_err(|error| JwkSetError::Key { index, error })?;
        if let Some(first) = keys.iter().position(|other| other.kid() == key.kid()) {
            return Err(JwkSetError::DuplicateKid {
                kid: key.kid().clone(),
                first,
                second: index,
            });
        }
        if let Some(other) = keys
            .iter()
            .find(|other| other.thumbprint() == key.thumbprint())
        {
            return Err(JwkSetError::DuplicateKey {
                first_kid: other.kid().clone(),
                second_kid: key.kid().clone(),
            });
        }
        keys.push(key);
    }
    // The projection's order (provisional lead pick, 2026-11-22): the same
    // keys in any input order give the same bytes and fingerprint.
    keys.sort_by(|a, b| a.kid().cmp(b.kid()));
    Ok(keys)
}
