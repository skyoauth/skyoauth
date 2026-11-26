//! The offline recovery formats (ADR-013 items 7 and 8;
//! docs/proposals/recovery-verified-response.md, section 4).
//!
//! # Keys
//!
//! The recovery public key, [`RecoveryPublicKey`], is the raw 32-byte
//! Ed25519 public key, and in text 64 lowercase hexadecimal digits. The
//! service refuses a key that is small-order, non-canonically encoded or
//! undecodable at every enrollment point (the bootstrap key, the plan's new
//! key at the issue and again at the restore; user ruling, 2026-11-24), so
//! the workstation runs the same checks in the same order before it hands
//! a key over.
//!
//! # What is signed
//!
//! The service issues a challenge as the bytes `M`, which the recovery key
//! signs (`skyoauth_service::persistence::registry::recovery`, module docs
//! "What is signed"):
//!
//! ```text
//! C = canonical JSON of {"actor_id": "deployment_operator",
//!       "expected_revision", "expires_at" (µs), "id",
//!       "kind": "operator_restoration", "plan", "tenant_id": null}
//! M = "skyoauth.recovery_challenge.v1\n" || C
//! ```
//!
//! `C` has its members sorted byte-wise at both levels, no whitespace,
//! integers (`i64` only) in decimal and strings escaped as the service
//! escapes them. The plan is closed: exactly the eight members
//! [`PLAN_INSTANCE_ID`], [`PLAN_RECOVERY_KEY_EPOCH`] (an integer),
//! [`PLAN_ADMIN_ID`], [`PLAN_CREDENTIAL_ID`], [`PLAN_BINDING_ID`],
//! [`PLAN_PUBLIC_IDENTITY`], [`PLAN_TRUST_ANCHOR_REF`] and
//! [`PLAN_NEW_RECOVERY_PUBLIC_KEY`] (the others strings).
//!
//! [`parse_challenge`] reads `M` strictly, then re-encodes what it read
//! with [`canonical_json`] and requires the same bytes, so a non-canonical
//! or extended `C` is never accepted (provisional lead pick, 2026-11-24).
//! It refuses an `M` over [`MAX_CHALLENGE_BYTES`] before reading it, and
//! reads the rest in time linear in its length.
//! [`check_challenge`] then checks the challenge against what the operator
//! expects ([`Expectations`]) and the operator's clock; only its result, a
//! [`VerifiedChallenge`], is meant to be signed.
//!
//! The fixtures `tests/conformance/fixtures/_recovery/key.v1.json` and
//! `challenge.v1.json` hold the known answers both sides check.
//!
//! No I/O, clock or random source is used: the time is the caller's.

mod canonical;
mod challenge;
mod key;

use std::time::Duration;

pub use canonical::{canonical_json, challenge_message};
pub use challenge::{
    Challenge, ChallengeError, Expectations, Refusal, RestorationPlan, VerifiedChallenge,
    check_challenge, parse_challenge,
};
pub use key::{KeyError, RecoveryPublicKey};

/// The length of a recovery public key, in bytes (the service's
/// `RECOVERY_PUBLIC_KEY_LENGTH`).
pub const RECOVERY_PUBLIC_KEY_LENGTH: usize = 32;

/// The domain-separation prefix of `M`, with its newline (the service's
/// `CHALLENGE_PREFIX`).
pub const CHALLENGE_PREFIX: &[u8] = b"skyoauth.recovery_challenge.v1\n";

/// The one challenge kind, `C`'s `kind` (the service's
/// `OPERATOR_RESTORATION`).
pub const OPERATOR_RESTORATION: &str = "operator_restoration";

/// The actor that records a challenge, `C`'s `actor_id` (the service's
/// `DEPLOYMENT_OPERATOR_ACTOR`).
pub const DEPLOYMENT_OPERATOR_ACTOR: &str = "deployment_operator";

/// The shortest TTL the service gives a challenge: 1 second.
pub const MIN_CHALLENGE_TTL: Duration = Duration::from_secs(1);

/// The TTL the service gives a challenge when its caller has no other: 5
/// minutes.
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// The longest TTL the service gives a challenge: 15 minutes. Also the
/// furthest ahead of the operator's clock that [`check_challenge`] accepts
/// an expiry.
pub const MAX_CHALLENGE_TTL: Duration = Duration::from_secs(15 * 60);

/// The largest `M` [`parse_challenge`] reads, in bytes: 64 KiB, the
/// deployment-local transport's largest request line (the service's
/// `MAX_REQUEST_BYTES`). An `M` the service issues is far smaller: the
/// plan's `public_identity` and `trust_anchor_ref` are at most 2048 bytes
/// each, and its other strings are identifiers (inferred bound).
pub const MAX_CHALLENGE_BYTES: usize = 64 * 1024;

/// The plan member that names the instance.
pub const PLAN_INSTANCE_ID: &str = "instance_id";

/// The plan member that names the epoch of the key that must sign.
pub const PLAN_RECOVERY_KEY_EPOCH: &str = "recovery_key_epoch";

/// The plan member that names the replacement operator.
pub const PLAN_ADMIN_ID: &str = "admin_id";

/// The plan member that names the replacement's credential.
pub const PLAN_CREDENTIAL_ID: &str = "credential_id";

/// The plan member that names the replacement's role binding.
pub const PLAN_BINDING_ID: &str = "binding_id";

/// The plan member that holds the replacement credential's public identity.
pub const PLAN_PUBLIC_IDENTITY: &str = "public_identity";

/// The plan member that holds the replacement credential's trust anchor
/// reference.
pub const PLAN_TRUST_ANCHOR_REF: &str = "trust_anchor_ref";

/// The plan member that holds the new recovery public key, 64 lowercase
/// hexadecimal digits.
pub const PLAN_NEW_RECOVERY_PUBLIC_KEY: &str = "new_recovery_public_key";
