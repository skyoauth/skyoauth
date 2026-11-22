//! One uploaded JWK Set (RFC 7517 section 5): its shape, bounds and the
//! uniqueness of `kid` and key within it.

use std::{fmt, io};

use serde_json::Value;

use super::key::{Algorithm, JwkError, Kid, PublicJwk, parse_jwk};

/// The most keys one set may hold (inferred).
pub const MAX_KEYS: usize = 20;

/// The largest set, in bytes of its compact JSON serialization (inferred:
/// 64 KiB).
pub const MAX_SET_BYTES: usize = 64 * 1024;

/// A validated JWK Set: at most [`MAX_KEYS`] public keys with distinct
/// `kid`s and distinct thumbprints, in upload order. Built only by
/// [`parse_jwk_set`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<PublicJwk>,
}

impl JwkSet {
    /// The keys, in upload order.
    pub fn keys(&self) -> &[PublicJwk] {
        &self.keys
    }

    /// The key whose `kid` is exactly `kid`.
    pub fn get(&self, kid: &str) -> Option<&PublicJwk> {
        self.keys.iter().find(|key| key.kid().as_str() == kid)
    }
}

/// Why a JWK Set is refused. A key is named by its index in `keys` and,
/// once validated, its `kid`; no variant holds key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwkSetError {
    /// The compact serialization is longer than [`MAX_SET_BYTES`].
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
        let key = parse_jwk(jwk, allowed).map_err(|error| JwkSetError::Key { index, error })?;
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
    Ok(JwkSet { keys })
}
