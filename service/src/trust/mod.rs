//! Service-layer rules of trust keysets and trust sources that the
//! registry does not hold.
//!
//! - **Trust keyset versions** (T11.3, T11.9): [`submit_create_version`]
//!   and [`submit_enable_version`] are the audited write path of a keyset
//!   version create and enable, through the second-approver gate
//!   ([`crate::operation`]): applied at once, or a pending operation for a
//!   second approver. [`disable_version`] is the audited disable, never
//!   gated (a disable is not widening). Each authorizes the operator and,
//!   when the write is applied, checks the overlap of the keyset's enabled
//!   versions where a version becomes enabled, writes the row and appends
//!   its audit event, in the caller's transaction, after
//!   [`validate_upload`] has validated the upload outside it. See the [`keyset`] module for the rules, the lock
//!   order and what is not done here.
//! - **Trust sources** (T11.2; identity-registry IR-152):
//!   [`submit_create_source`] and [`submit_update_source`] are the audited
//!   write path of a trust source, through the second-approver gate: a
//!   create and a widening update applied at once or pending, a
//!   disable-only update applied at once as not widening. Each authorizes
//!   the operator, checks the source's egress destinations against the
//!   egress allowlist and, when the write is applied, writes the row and
//!   appends its audit event, in the caller's transaction. See the [`source`] module for the rules, the
//!   lock order and what is not done here.
//!
//! The ungated create and enable of a keyset version and create and update
//! of a trust source (`create_version`, `enable_version`, `create_source`,
//! `update_source`) apply a widening write on one operator's authority, so
//! they are crate-private (second-approver proposal, PR 7). This package's
//! integration tests reach them through a `#[doc(hidden)]` module compiled
//! only with the `test-support` feature, which a normal build leaves off.
//!
//! The module is library-level only: no endpoint calls it yet, and nothing
//! wires it at startup (provisional lead pick, 2026-11-22).

pub mod keyset;
pub mod source;
// The ungated writes for this package's integration tests (see the module
// docs). Absent from a normal build; `service/tests/ungated_writes_private.rs`
// checks that such a build exposes none of them.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;
pub(crate) mod write;

pub use keyset::{
    IN_TRANSACTION_WAIT, IN_TRANSACTION_WORKERS, KeysetAudit, KeysetWriteError,
    MAX_ENABLED_VERSIONS_PER_KEYSET, NewKeysetVersion, VALIDATION_WORKERS, disable_version,
    submit_create_version, submit_enable_version, validate_upload,
};
pub use source::{
    DISCOVERY_URL, SourceAudit, SourceWriteError, TOKEN_REVIEW_ENDPOINT, submit_create_source,
    submit_update_source,
};
