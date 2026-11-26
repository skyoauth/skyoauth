//! The offline recovery formats (ADR-013 items 7 and 8;
//! docs/proposals/recovery-verified-response.md, section 4).
//!
//! This part holds the recovery public key, [`RecoveryPublicKey`]: the raw
//! 32-byte Ed25519 public key, and in text 64 lowercase hexadecimal digits.
//! The service refuses a key that is small-order, non-canonically encoded or
//! undecodable at every enrollment point (the bootstrap key, the plan's new
//! key at the issue and again at the restore; user ruling, 2026-11-24), so
//! the workstation runs the same checks in the same order before it hands
//! a key over.
//!
//! The fixture `tests/conformance/fixtures/_recovery/key.v1.json` holds the
//! known answers both sides check.

mod key;

pub use key::{KeyError, RecoveryPublicKey};

/// The length of a recovery public key, in bytes (the service's
/// `RECOVERY_PUBLIC_KEY_LENGTH`).
pub const RECOVERY_PUBLIC_KEY_LENGTH: usize = 32;
