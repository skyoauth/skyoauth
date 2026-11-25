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
//! `security_admin`: `bootstrap_instance` stays public (the proposal,
//! "Still open"), before the instance is bootstrapped. `restore_operator`
//! stays public too but verifies the recovery key's signature itself
//! before it enrolls anyone, and `issue_recovery_challenge` enrolls no one
//! (`docs/proposals/recovery-verified-response.md`).
//!
//! The checker writers [`create_resource_server_checker`],
//! [`update_resource_server_checker`],
//! [`add_resource_server_checker_tenant`] and
//! [`remove_resource_server_checker_tenant`], the action writers
//! [`create_resource_action`] and [`update_resource_action`], the resource
//! server writers [`create_resource_server`] and [`update_resource_server`],
//! the assignment writers [`create_audience_tenant_assignment`] and
//! [`update_audience_tenant_assignment`], and [`create_tenant`],
//! [`update_tenant`], [`create_principal`] and [`update_principal`] create
//! an audience, admit a tenant to an audience or a checker, define what an
//! action requires, or create, rename or re-enable a tenant or a principal,
//! with no authorization and no audit event. So they are crate-private too
//! (the survey under "Still open after PRs 7, 9 and 10" of the same
//! proposal, and its follow-up): `pub(crate)`, because the audited,
//! authorized writes of [`crate::admin`] call them, and nothing else in the
//! crate does (inferred: the narrowest visibility that caller allows).
//! [`create_egress_allowlist_entry`] and [`update_egress_allowlist_entry`]
//! add, re-enable or disable an instance egress destination with no
//! authorization, no destination syntax check and no audit event, so they
//! are `pub(crate)` for the same reason: the audited, authorized writes of
//! [`crate::admin::egress`] call them, and nothing else in the crate does.
//!
//! The remaining writers of the principal binding, service identity, grant
//! and trust keyset tables ([`create_principal_binding`] to
//! [`remove_service_grant_resource_server`], [`create_trust_keyset`] and
//! [`update_trust_keyset`] below) write those rows, a re-enable or a
//! widened list set included, with no authorization and no audit event.
//! Nothing in the crate calls them, so they are `pub(super)` with the
//! same `expect(dead_code)` as `update_admin_role_binding`, and the
//! scenario tests under `tests/security` reach them here too (the
//! follow-up of the same survey).
//! [`consume_assertion`](super::consume_assertion) and
//! [`consume_assertion_set`](super::consume_assertion_set) stay public: they
//! only insert replay records.
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
    AdministrativeOperation, AudienceTenantAssignment, AudienceTenantAssignmentChanges, AuditEvent,
    EgressAllowlistEntry, NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding,
    NewAdministrativeOperation, NewAudienceTenantAssignment, NewAuditEvent,
    NewEgressAllowlistEntry, NewPrincipal, NewPrincipalBinding, NewResourceAction,
    NewResourceServer, NewResourceServerChecker, NewServiceGrant, NewServiceIdentity, NewTenant,
    NewTrustKeyset, NewTrustKeysetVersion, NewTrustSource, Principal, PrincipalBinding,
    PrincipalBindingChanges, PrincipalPatch, RegistryError, ResourceAction, ResourceActionChanges,
    ResourceServer, ResourceServerChanges, ResourceServerChecker, ResourceServerCheckerChanges,
    ServiceGrant, ServiceGrantChanges, ServiceIdentity, ServiceIdentityChanges, Status, Tenant,
    TenantPatch, TrustKeyset, TrustKeysetChanges, TrustKeysetVersion, TrustSource,
    TrustSourceChanges, audience, events, grant, instance, operation, operator, tenant, trust,
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

/// The registry's `create_resource_server_checker` (`pub(crate)`,
/// called by `crate::admin`): a checker, unauthorized and unaudited.
/// Tests only.
pub async fn create_resource_server_checker<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewResourceServerChecker,
) -> Result<ResourceServerChecker, RegistryError> {
    audience::create_resource_server_checker(executor, new).await
}

/// The registry's `update_resource_server_checker` (`pub(crate)`,
/// called by `crate::admin`): a checker's identity or status, a re-enable
/// included, unauthorized and unaudited. Tests only.
pub async fn update_resource_server_checker<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceServerCheckerChanges,
) -> Result<ResourceServerChecker, RegistryError> {
    audience::update_resource_server_checker(executor, id, expected_revision, changes).await
}

/// The registry's `add_resource_server_checker_tenant` (`pub(crate)`,
/// called by `crate::admin`): a tenant admitted to a checker,
/// unauthorized and unaudited. Tests only.
pub async fn add_resource_server_checker_tenant<'e>(
    executor: impl PgExecutor<'e>,
    checker_id: &str,
    expected_revision: i64,
    tenant_id: &str,
) -> Result<i64, RegistryError> {
    audience::add_resource_server_checker_tenant(executor, checker_id, expected_revision, tenant_id)
        .await
}

/// The registry's `remove_resource_server_checker_tenant` (`pub(crate)`,
/// called by `crate::admin`): a tenant removed from a checker, unauthorized
/// and unaudited. Tests only.
pub async fn remove_resource_server_checker_tenant<'e>(
    executor: impl PgExecutor<'e>,
    checker_id: &str,
    expected_revision: i64,
    tenant_id: &str,
) -> Result<i64, RegistryError> {
    audience::remove_resource_server_checker_tenant(
        executor,
        checker_id,
        expected_revision,
        tenant_id,
    )
    .await
}

/// The registry's `create_resource_action` (`pub(crate)`, called by
/// `crate::admin`): an action rule, unauthorized and unaudited. Tests only.
pub async fn create_resource_action<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewResourceAction,
) -> Result<ResourceAction, RegistryError> {
    audience::create_resource_action(executor, new).await
}

/// The registry's `update_resource_action` (`pub(crate)`, called by
/// `crate::admin`): an action rule's mutable columns, a re-enable included,
/// unauthorized and unaudited. Tests only.
pub async fn update_resource_action<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceActionChanges,
) -> Result<ResourceAction, RegistryError> {
    audience::update_resource_action(executor, id, expected_revision, changes).await
}

/// The registry's `update_tenant` (`pub(crate)`, called by `crate::admin`): a
/// tenant's name or status, a re-enable included, unauthorized and
/// unaudited. Tests only.
pub async fn update_tenant<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    patch: &TenantPatch,
) -> Result<Tenant, RegistryError> {
    tenant::update_tenant(executor, id, expected_revision, patch).await
}

/// The registry's `update_principal` (`pub(crate)`, called by
/// `crate::admin`): a principal's name or status, a re-enable included,
/// unauthorized and unaudited. Tests only.
pub async fn update_principal<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    patch: &PrincipalPatch,
) -> Result<Principal, RegistryError> {
    tenant::update_principal(executor, tenant_id, id, expected_revision, patch).await
}

/// The registry's `create_resource_server` (`pub(crate)`, called by
/// `crate::admin`): a resource server (an audience), unauthorized and
/// unaudited. Tests only.
pub async fn create_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewResourceServer,
) -> Result<ResourceServer, RegistryError> {
    audience::create_resource_server(executor, new).await
}

/// The registry's `update_resource_server` (`pub(crate)`, called by
/// `crate::admin`): a resource server's mutable columns, a re-enable
/// included, unauthorized and unaudited. Tests only.
pub async fn update_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceServerChanges,
) -> Result<ResourceServer, RegistryError> {
    audience::update_resource_server(executor, id, expected_revision, changes).await
}

/// The registry's `create_audience_tenant_assignment` (`pub(crate)`,
/// called by `crate::admin`): a tenant's assignment to an audience,
/// unauthorized and unaudited. Tests only.
pub async fn create_audience_tenant_assignment<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAudienceTenantAssignment,
) -> Result<AudienceTenantAssignment, RegistryError> {
    audience::create_audience_tenant_assignment(executor, new).await
}

/// The registry's `update_audience_tenant_assignment` (`pub(crate)`,
/// called by `crate::admin`): an assignment's mutable columns, a re-enable
/// included, unauthorized and unaudited. Tests only.
pub async fn update_audience_tenant_assignment<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &AudienceTenantAssignmentChanges,
) -> Result<AudienceTenantAssignment, RegistryError> {
    audience::update_audience_tenant_assignment(executor, id, expected_revision, changes).await
}

/// The registry's `create_principal_binding` (`pub(super)`, no caller in
/// the crate): a principal binding, the claims of a trust source that map
/// to a workload principal, unauthorized and unaudited. Tests only.
pub async fn create_principal_binding<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewPrincipalBinding,
) -> Result<PrincipalBinding, RegistryError> {
    grant::create_principal_binding(executor, new).await
}

/// The registry's `update_principal_binding` (`pub(super)`, no caller in
/// the crate): a binding's mutable columns, a re-enable included,
/// unauthorized and unaudited. Tests only.
pub async fn update_principal_binding<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &PrincipalBindingChanges,
) -> Result<PrincipalBinding, RegistryError> {
    grant::update_principal_binding(executor, tenant_id, id, expected_revision, changes).await
}

/// The registry's `create_service_identity` (`pub(super)`, no caller in the
/// crate): a service identity with its audiences, unauthorized and
/// unaudited. Tests only.
pub async fn create_service_identity<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewServiceIdentity,
) -> Result<ServiceIdentity, RegistryError> {
    grant::create_service_identity(executor, new).await
}

/// The registry's `update_service_identity` (`pub(super)`, no caller in the
/// crate): a service identity's mutable columns, a re-enable included,
/// unauthorized and unaudited. Tests only.
pub async fn update_service_identity<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &ServiceIdentityChanges,
) -> Result<ServiceIdentity, RegistryError> {
    grant::update_service_identity(executor, tenant_id, id, expected_revision, changes).await
}

/// The registry's `add_service_identity_resource_server` (`pub(super)`, no
/// caller in the crate): an audience added to a service identity,
/// unauthorized and unaudited. Tests only.
pub async fn add_service_identity_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    service_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    grant::add_service_identity_resource_server(
        executor,
        tenant_id,
        service_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

/// The registry's `remove_service_identity_resource_server` (`pub(super)`,
/// no caller in the crate): an audience removed from a service identity,
/// unauthorized and unaudited. Tests only.
pub async fn remove_service_identity_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    service_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    grant::remove_service_identity_resource_server(
        executor,
        tenant_id,
        service_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

/// The registry's `create_service_grant` (`pub(super)`, no caller in the
/// crate): a service grant with its bindings and audiences, unauthorized
/// and unaudited. Tests only.
pub async fn create_service_grant<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewServiceGrant,
) -> Result<ServiceGrant, RegistryError> {
    grant::create_service_grant(executor, new).await
}

/// The registry's `update_service_grant` (`pub(super)`, no caller in the
/// crate): a grant's mutable columns, a re-enable included, unauthorized
/// and unaudited. Tests only.
pub async fn update_service_grant<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &ServiceGrantChanges,
) -> Result<ServiceGrant, RegistryError> {
    grant::update_service_grant(executor, tenant_id, id, expected_revision, changes).await
}

/// The registry's `add_service_grant_binding` (`pub(super)`, no caller in
/// the crate): a binding added to a grant, unauthorized and unaudited.
/// Tests only.
pub async fn add_service_grant_binding<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    binding_id: &str,
) -> Result<i64, RegistryError> {
    grant::add_service_grant_binding(executor, tenant_id, grant_id, expected_revision, binding_id)
        .await
}

/// The registry's `remove_service_grant_binding` (`pub(super)`, no caller
/// in the crate): a binding removed from a grant, unauthorized and
/// unaudited. Tests only.
pub async fn remove_service_grant_binding<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    binding_id: &str,
) -> Result<i64, RegistryError> {
    grant::remove_service_grant_binding(
        executor,
        tenant_id,
        grant_id,
        expected_revision,
        binding_id,
    )
    .await
}

/// The registry's `add_service_grant_resource_server` (`pub(super)`, no
/// caller in the crate): an audience added to a grant, unauthorized and
/// unaudited. Tests only.
pub async fn add_service_grant_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    grant::add_service_grant_resource_server(
        executor,
        tenant_id,
        grant_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

/// The registry's `remove_service_grant_resource_server` (`pub(super)`, no
/// caller in the crate): an audience removed from a grant, unauthorized and
/// unaudited. Tests only.
pub async fn remove_service_grant_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    grant::remove_service_grant_resource_server(
        executor,
        tenant_id,
        grant_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

/// The registry's `create_tenant` (`pub(crate)`, called by `crate::admin`):
/// a tenant with its secret namespace, unauthorized and unaudited. Tests
/// only.
pub async fn create_tenant<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTenant,
) -> Result<Tenant, RegistryError> {
    tenant::create_tenant(executor, new).await
}

/// The registry's `create_principal` (`pub(crate)`, called by
/// `crate::admin`): a principal of a tenant, unauthorized and unaudited.
/// Tests only.
pub async fn create_principal<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewPrincipal,
) -> Result<Principal, RegistryError> {
    tenant::create_principal(executor, new).await
}

/// The registry's `create_trust_keyset` (`pub(super)`, no caller in the
/// crate): a trust keyset, unauthorized and unaudited. Tests only.
pub async fn create_trust_keyset<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTrustKeyset,
) -> Result<TrustKeyset, RegistryError> {
    trust::create_trust_keyset(executor, new).await
}

/// The registry's `update_trust_keyset` (`pub(super)`, no caller in the
/// crate): a keyset's name or status, a re-enable included, unauthorized
/// and unaudited. Tests only.
pub async fn update_trust_keyset<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustKeysetChanges,
) -> Result<TrustKeyset, RegistryError> {
    trust::update_trust_keyset(executor, tenant_id, id, expected_revision, changes).await
}

/// The registry's `create_egress_allowlist_entry` (`pub(crate)`, called by
/// `crate::admin::egress`): an egress allowlist entry, enabled or not, with
/// no destination syntax check, unauthorized and unaudited. Tests only.
pub async fn create_egress_allowlist_entry<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewEgressAllowlistEntry,
) -> Result<EgressAllowlistEntry, RegistryError> {
    instance::create_egress_allowlist_entry(executor, new).await
}

/// The registry's `update_egress_allowlist_entry` (`pub(crate)`, called by
/// `crate::admin::egress`): an entry's status, a re-enable included,
/// unauthorized and unaudited. Tests only.
pub async fn update_egress_allowlist_entry<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    status: Status,
) -> Result<EgressAllowlistEntry, RegistryError> {
    instance::update_egress_allowlist_entry(executor, id, expected_revision, status).await
}
