//! The ungated trust writes, for this package's integration tests only.
//!
//! `create_version`, `enable_version`, `create_source` and `update_source`
//! apply a widening write at once on one operator's authority, without the
//! second approver that `widening_second_approver` asks for, so they are
//! crate-private (second-approver proposal, PR 7). The integration tests
//! under `service/tests` are crates of their own and test those writes
//! directly, so this module, compiled only with the `test-support` feature,
//! exposes each through a wrapper of the same name and signature (a
//! crate-private function cannot be re-exported). The feature is off in a
//! normal build; this package's dev-dependency on itself turns it on for
//! its test targets only (inferred: the mechanism; the proposal's "PR 7 as
//! implemented"). Nothing outside tests may enable it, and no endpoint may
//! call this module: an endpoint calls the gated `submit_*` writes of
//! [`super::keyset`] and [`super::source`].
//!
//! `disable_version` is not here: a disable is not widening, is never
//! gated, and stays public in [`super::keyset`].

use sqlx::{Postgres, Transaction};

use super::keyset::{self, KeysetAudit, KeysetWriteError, NewKeysetVersion};
use super::source::{self, SourceAudit, SourceWriteError};
use crate::persistence::registry::{
    NewTrustSource, TrustKeysetVersion, TrustSource, TrustSourceChanges,
};

/// The crate-private `trust::keyset::create_version`: the ungated keyset
/// version create. Tests only.
pub async fn create_version(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewKeysetVersion<'_>,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    keyset::create_version(transaction, public_identity, new, audit).await
}

/// The crate-private `trust::keyset::enable_version`: the ungated keyset
/// version enable. Tests only.
pub async fn enable_version(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    keyset::enable_version(
        transaction,
        public_identity,
        tenant_id,
        id,
        expected_revision,
        audit,
    )
    .await
}

/// The crate-private `trust::source::create_source`: the ungated trust
/// source create. Tests only.
pub async fn create_source(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewTrustSource,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    source::create_source(transaction, public_identity, new, audit).await
}

/// The crate-private `trust::source::update_source`: the ungated trust
/// source update. Tests only.
pub async fn update_source(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustSourceChanges,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    source::update_source(
        transaction,
        public_identity,
        tenant_id,
        id,
        expected_revision,
        changes,
        audit,
    )
    .await
}
