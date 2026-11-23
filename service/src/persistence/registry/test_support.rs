//! The bare registry trust writers, for tests only.
//!
//! [`create_trust_keyset_version`], [`update_trust_keyset_version`],
//! [`create_trust_source`] and [`update_trust_source`] write a keyset
//! version or a trust source with no authorization, no second-approver
//! gate, no audit event and, for a keyset version, no JWK rule and no
//! overlap check: only the database's checks apply. So they are
//! crate-private (`pub(crate)`; second-approver proposal, PR 9), and within
//! the crate only [`crate::trust::keyset`] and [`crate::trust::source`]
//! call them, from the steps that authorize, gate and audit the write. The
//! integration tests under `service/tests` and the scenario tests of
//! `skyoauth-scenarios` (`tests/`) are crates of their own and use these
//! writers to set up rows and to test the registry floor itself, so this
//! module, compiled only with the `test-support` feature, exposes each
//! through a wrapper of the same name and signature (a crate-private
//! function cannot be re-exported). The feature is off in a normal build;
//! this package's dev-dependency on itself and the scenario package's
//! dev-dependency on this package turn it on for test targets only
//! (inferred: the mechanism, as in `trust::test_support`; the proposal's
//! "PR 9 as implemented"). Nothing outside tests may enable it, and no
//! endpoint may call this module: an endpoint calls the gated `submit_*`
//! writes of [`crate::trust::keyset`] and [`crate::trust::source`].

use sqlx::PgExecutor;

use super::{
    NewTrustKeysetVersion, NewTrustSource, RegistryError, Status, TrustKeysetVersion, TrustSource,
    TrustSourceChanges, trust,
};

/// The `pub(crate)` registry `create_trust_keyset_version`: the unchecked
/// keyset version create. Tests only.
pub async fn create_trust_keyset_version<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTrustKeysetVersion,
) -> Result<TrustKeysetVersion, RegistryError> {
    trust::create_trust_keyset_version(executor, new).await
}

/// The `pub(crate)` registry `update_trust_keyset_version`: the unchecked
/// keyset version status change. Tests only.
pub async fn update_trust_keyset_version<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    status: Status,
) -> Result<TrustKeysetVersion, RegistryError> {
    trust::update_trust_keyset_version(executor, tenant_id, id, expected_revision, status).await
}

/// The `pub(crate)` registry `create_trust_source`: the unchecked trust
/// source create. Tests only.
pub async fn create_trust_source<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTrustSource,
) -> Result<TrustSource, RegistryError> {
    trust::create_trust_source(executor, new).await
}

/// The `pub(crate)` registry `update_trust_source`: the unchecked trust
/// source update. Tests only.
pub async fn update_trust_source<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustSourceChanges,
) -> Result<TrustSource, RegistryError> {
    trust::update_trust_source(executor, tenant_id, id, expected_revision, changes).await
}
