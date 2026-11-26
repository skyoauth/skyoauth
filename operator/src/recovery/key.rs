//! [`RecoveryPublicKey`] and its checks.

use std::fmt;

use ed25519_dalek::VerifyingKey;

use super::RECOVERY_PUBLIC_KEY_LENGTH;
use crate::text::{decode_hex, encode_hex};

/// Why bytes or text are not a usable recovery public key. Carries no input
/// byte: `Debug` names the variant only, `Display` is fixed text.
///
/// The byte checks run in the service's order, and each `Display` is the
/// service's message for it: [`KeyError::Length`], then
/// [`KeyError::Undecodable`], [`KeyError::NotCanonical`] and
/// [`KeyError::SmallOrder`]. So a non-canonical encoding of a small-order
/// point is [`KeyError::NotCanonical`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The text is not exactly 64 lowercase hexadecimal digits (only from
    /// [`RecoveryPublicKey::from_hex`]). The service's restoration plan
    /// refuses the same text before its byte checks.
    NotHex,
    /// Not 32 bytes.
    Length,
    /// 32 bytes that decode to no curve point.
    Undecodable,
    /// A point whose encoding is not its canonical one.
    NotCanonical,
    /// A point of small order (a weak key).
    SmallOrder,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotHex => "recovery public key is not 64 lowercase hexadecimal digits",
            Self::Length => "recovery public key is not a 32-byte Ed25519 key",
            Self::Undecodable => "recovery public key is not an Ed25519 point",
            Self::NotCanonical => "recovery public key is not canonically encoded",
            Self::SmallOrder => "recovery public key is a small-order Ed25519 point",
        })
    }
}

impl std::error::Error for KeyError {}

/// A raw 32-byte Ed25519 recovery public key that passed the service's
/// checks: a canonically encoded curve point not of small order.
///
/// A public key is not secret, but `Debug` prints no byte of it, like the
/// service's types that carry key material; [`RecoveryPublicKey::to_hex`]
/// is the explicit way to show it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryPublicKey([u8; RECOVERY_PUBLIC_KEY_LENGTH]);

impl fmt::Debug for RecoveryPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryPublicKey(..)")
    }
}

impl RecoveryPublicKey {
    /// The key in `bytes`, checked as the service checks it.
    ///
    /// # Errors
    ///
    /// The first check `bytes` fails, in this order:
    /// [`KeyError::Length`], [`KeyError::Undecodable`],
    /// [`KeyError::NotCanonical`], [`KeyError::SmallOrder`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        let bytes: &[u8; RECOVERY_PUBLIC_KEY_LENGTH] =
            bytes.try_into().map_err(|_| KeyError::Length)?;
        // ZIP-215 decoding: accepts a `y` at or above the field prime and a
        // negative zero `x`, so the re-encoding below is the canonical check.
        let key = VerifyingKey::from_bytes(bytes).map_err(|_| KeyError::Undecodable)?;
        if key.to_edwards().compress().as_bytes() != bytes {
            return Err(KeyError::NotCanonical);
        }
        if key.is_weak() {
            return Err(KeyError::SmallOrder);
        }
        Ok(Self(*bytes))
    }

    /// The key in `text`, 64 lowercase hexadecimal digits (the form of the
    /// restoration plan and of the deployment-local transport), checked as
    /// [`RecoveryPublicKey::from_bytes`] checks its bytes.
    ///
    /// # Errors
    ///
    /// [`KeyError::NotHex`] for text of another length (in bytes) or with a
    /// character that is not a lowercase hexadecimal digit; otherwise the
    /// errors of [`RecoveryPublicKey::from_bytes`].
    pub fn from_hex(text: &str) -> Result<Self, KeyError> {
        if text.len() != 2 * RECOVERY_PUBLIC_KEY_LENGTH {
            return Err(KeyError::NotHex);
        }
        let bytes = decode_hex(text).ok_or(KeyError::NotHex)?;
        Self::from_bytes(&bytes)
    }

    /// The 32 bytes of the key.
    pub const fn as_bytes(&self) -> &[u8; RECOVERY_PUBLIC_KEY_LENGTH] {
        &self.0
    }

    /// The key as 64 lowercase hexadecimal digits.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}
