//! Service-layer rules of trust keysets and trust sources that the
//! registry does not hold.
//!
//! - **Trust keyset versions** (T11.3, T11.9): [`create_version`],
//!   [`enable_version`] and [`disable_version`] are the audited write path
//!   of a trust keyset version: they authorize the operator, check the
//!   overlap of the keyset's enabled versions, write the row and append its
//!   audit event, in the caller's transaction, after [`validate_upload`] has
//!   validated the upload outside it. See the [`keyset`] module for the
//!   rules, the lock order and what is not done here.
//! - **Trust sources** (T11.2; identity-registry IR-152): [`create_source`]
//!   and [`update_source`] are the audited write path of a trust source:
//!   they authorize the operator, check the source's egress destinations
//!   against the egress allowlist, write the row and append its audit event,
//!   in the caller's transaction. See the [`source`] module for the rules,
//!   the lock order and what is not done here.
//!
//! The module is library-level only: no endpoint calls it yet, and nothing
//! wires it at startup (provisional lead pick, 2026-11-22).

pub mod keyset;
pub mod source;

pub use keyset::{
    KeysetAudit, KeysetWriteError, MAX_ENABLED_VERSIONS_PER_KEYSET, NewKeysetVersion,
    VALIDATION_WORKERS, create_version, disable_version, enable_version, validate_upload,
};
pub use source::{
    DISCOVERY_URL, SourceAudit, SourceWriteError, TOKEN_REVIEW_ENDPOINT, create_source,
    update_source,
};
