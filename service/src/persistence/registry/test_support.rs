//! The bare registry writers that a normal build keeps crate-private, for
//! tests only.
//!
//! [`create_trust_keyset_version`], [`update_trust_keyset_version`],
//! [`create_trust_source`] and [`update_trust_source`] write a keyset
//! version or a trust source with no authorization, no second-approver
//! gate, no audit event and, for a keyset version, no JWK rule and no
//! overlap check: only the database's checks apply. So they are
//! crate-private (`pub(crate)`; second-approver proposal, PR 9), and within
//! the crate only [`crate::trust::keyset`] and [`crate::trust::source`]
//! call them, from the steps that authorize, gate and audit the write.
//!
//! The operator writers [`create_admin_identity`],
//! [`create_admin_credential`], [`create_admin_role_binding`] and
//! [`update_admin_role_binding`] enroll an operator, `security_admin`
//! included, or re-enable a role binding, with no authorization and no
//! audit event; [`append_audit_event`] appends a well-chained event of the
//! caller's choosing; and [`insert_administrative_operation`],
//! [`consume_administrative_operation`] and
//! [`revoke_administrative_operation`] write the second-approver gate's own
//! operation rows unchecked. So they are crate-private too (PR 10): the
//! three operator creates are visible only within the registry
//! (`pub(super)`), where `bootstrap_instance` and `restore_operator` call
//! them; `update_admin_role_binding` likewise, with no caller in the crate,
//! so it is dead code without the `test-support` feature, which its
//! `expect(dead_code)` states; and the audit append and the operation-row
//! writers are `pub(crate)`, called by the audited writes of the registry,
//! [`crate::trust`] and [`crate::operation`]. Making the operator creates
//! crate-private does not by itself keep another crate from enrolling a
//! `security_admin`: `bootstrap_instance`, `issue_recovery_challenge` and
//! `restore_operator` stay public (the proposal, "Still open").
//!
//! The integration tests under `service/tests` and the scenario tests of
//! `skyoauth-scenarios` (`tests/`) are crates of their own and use these
//! writers to set up rows and to test the registry floor itself, so this
//! module, compiled only with the `test-support` feature, exposes each
//! through a wrapper of the same name and signature (a crate-private
//! function cannot be re-exported). The feature is off in a normal build;
//! this package's dev-dependency on itself and the scenario package's
//! dev-dependency on this package turn it on for test targets only
//! (inferred: the mechanism, as in `trust::test_support`; the proposal's
//! "PR 9 as implemented" and "PR 10 as implemented"). Nothing outside tests
//! may enable it, and no endpoint may call this module: an endpoint calls
//! the gated `submit_*` writes of [`crate::trust::keyset`] and
//! [`crate::trust::source`], and the approval of [`crate::operation`].

use std::time::SystemTime;

use sqlx::{PgExecutor, Postgres, Transaction};

use super::{
    AdminCredential, AdminIdentity, AdminRoleBinding, AdminRoleBindingChanges,
    AdministrativeOperation, AuditEvent, NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding,
    NewAdministrativeOperation, NewAuditEvent, NewTrustKeysetVersion, NewTrustSource,
    RegistryError, Status, TrustKeysetVersion, TrustSource, TrustSourceChanges, events, operation,
    operator, trust,
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

/// The registry's `create_admin_identity` (`pub(super)`): an operator
/// identity, unauthorized and unaudited. Tests only.
pub async fn create_admin_identity<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAdminIdentity,
) -> Result<AdminIdentity, RegistryError> {
    operator::create_admin_identity(executor, new).await
}

/// The registry's `create_admin_credential` (`pub(super)`): an operator
/// credential, unauthorized and unaudited. Tests only.
pub async fn create_admin_credential<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAdminCredential,
) -> Result<AdminCredential, RegistryError> {
    operator::create_admin_credential(executor, new).await
}

/// The registry's `create_admin_role_binding` (`pub(super)`): an operator
/// role binding, `security_admin` included, unauthorized and unaudited.
/// Tests only.
pub async fn create_admin_role_binding<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAdminRoleBinding,
) -> Result<AdminRoleBinding, RegistryError> {
    operator::create_admin_role_binding(executor, new).await
}

/// The registry's `update_admin_role_binding` (`pub(super)`, no caller in
/// the crate): a role binding's status change, a re-enable included,
/// unauthorized and unaudited. Tests only.
pub async fn update_admin_role_binding<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &AdminRoleBindingChanges,
) -> Result<AdminRoleBinding, RegistryError> {
    operator::update_admin_role_binding(executor, id, expected_revision, changes).await
}

/// The `pub(crate)` registry `append_audit_event`: one chained audit event
/// of the caller's choosing. Tests only.
pub async fn append_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    event: &NewAuditEvent,
) -> Result<AuditEvent, RegistryError> {
    events::append_audit_event(transaction, event).await
}

/// The `pub(crate)` registry `insert_administrative_operation`: an
/// operation row, unchecked. Tests only.
pub async fn insert_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    new: &NewAdministrativeOperation,
) -> Result<AdministrativeOperation, RegistryError> {
    operation::insert_administrative_operation(transaction, new).await
}

/// The `pub(crate)` registry `consume_administrative_operation`: an
/// operation consumed, unchecked. Tests only.
pub async fn consume_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<i64, RegistryError> {
    operation::consume_administrative_operation(transaction, id, now, outcome).await
}

/// The `pub(crate)` registry `revoke_administrative_operation`: an
/// operation revoked, unchecked. Tests only.
pub async fn revoke_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    revoking_operation_id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<i64, RegistryError> {
    operation::revoke_administrative_operation(transaction, id, revoking_operation_id, now, outcome)
        .await
}
