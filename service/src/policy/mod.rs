//! Pure policy decisions of the workload exchange: scope resolution
//! ([`resolve_scopes`]) and binding matching ([`match_binding`]); see
//! their modules.
//!
//! Nothing here reads or writes the database. The loaders that feed these
//! functions, `load_scope_ceilings` and `select_grant`, stay in
//! `persistence::registry`, which depends on this module and never the
//! reverse (lead ruling, 2026-11-21).

mod matching;
mod scope;

pub use matching::{EligibleBinding, Evidence, match_binding};
pub use scope::{ScopeCeilings, ScopeError, ScopeRequest, resolve_scopes};
