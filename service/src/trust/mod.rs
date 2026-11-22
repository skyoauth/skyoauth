//! Service-layer rules of trust sources that the registry does not hold
//! (T11.2; identity-registry IR-152). [`create_source`] and
//! [`update_source`] are the audited write path of a trust source: they
//! authorize the operator, check the source's egress destinations against
//! the egress allowlist, write the row and append its audit event, in the
//! caller's transaction. See the [`source`] module for the rules, the lock
//! order and what is not done here.
//!
//! The module is library-level only: no endpoint calls it yet, and nothing
//! wires it at startup (provisional lead pick, 2026-11-22).

pub mod source;

pub use source::{
    DISCOVERY_URL, SourceAudit, SourceWriteError, TOKEN_REVIEW_ENDPOINT, create_source,
    update_source,
};
