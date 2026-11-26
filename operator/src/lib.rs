//! The skyoauth workstation operator library (`skyoauth-operator`; ADR-013
//! item 6, ADR-017 item 7, tasks T13.10).
//!
//! This first part holds the formats the workstation shares with the
//! service:
//!
//! - [`recovery::RecoveryPublicKey`]: the raw 32-byte Ed25519 recovery
//!   public key, with the service's checks in the service's order (32
//!   bytes, decodable, canonically encoded, not of small order) and its
//!   messages;
//! - [`recovery::parse_challenge`] and [`recovery::check_challenge`]: the
//!   recovery challenge `M` the service issues, read strictly and compared
//!   byte for byte with its canonical re-encoding, then checked against
//!   the operator's expectations and clock;
//! - [`identity::public_identity_of_spki`]: the canonical public identity
//!   `spki-sha256:<hex>` of a DER `SubjectPublicKeyInfo`;
//! - `local` (Unix only): the wire codec of the service's deployment-local
//!   transport, its request lines and its replies, pinned by
//!   `tests/conformance/fixtures/_wire/local_transport.v1.json`.
//!
//! The crate does not depend on `skyoauth-service`: it builds and tests on
//! Linux, macOS and Windows without a server or a database (ADR-017 item
//! 15). Each format is reimplemented here and pinned, on both sides, by the
//! fixture files under `tests/conformance/fixtures/_recovery/`: this crate's
//! `operator` test target checks every case, and the `pg` target of
//! `skyoauth-scenarios` feeds the same cases to the service.
//!
//! No I/O, clock or random source is used: a time is always the caller's.

#![forbid(unsafe_code)]

pub mod identity;
#[cfg(unix)]
pub mod local;
pub mod recovery;
mod text;
