//! Principal bindings, service identities with their audience rows, and
//! service grants with their binding and audience rows (`0004`). All are
//! tenant-owned, so every read, update and list-set change names the
//! tenant.

use sqlx::{PgExecutor, types::Json};

use super::{
    NewPrincipalBinding, NewServiceGrant, NewServiceIdentity, Page, PrincipalBinding,
    PrincipalBindingChanges, RegistryError, ServiceGrant, ServiceGrantChanges, ServiceIdentity,
    ServiceIdentityChanges, list_change, micros, model::optional_since_epoch,
    tenant_compare_and_set, tenant_list_page, updated, validate_claim_match_policy,
};

macro_rules! binding_columns {
    () => {
        "id, tenant_id, name, trust_source_id, profile, claim_match_policy, \
         workload_principal_id, status, revision"
    };
}

macro_rules! service_base_columns {
    () => {
        "id, tenant_id, name, max_scopes, max_resource_constraints, status, revision"
    };
}

/// `resource_server_ids` is derived from the identity's rows; the subquery
/// names the table, not an alias, so the list serves `SELECT` and
/// `RETURNING`, as for checkers.
macro_rules! service_columns {
    () => {
        concat!(
            service_base_columns!(),
            ", ARRAY(SELECT r.resource_server_id FROM service_identity_resource_server r \
             WHERE r.service_id = service_identity.id \
             ORDER BY r.resource_server_id COLLATE \"C\") AS resource_server_ids"
        )
    };
}

macro_rules! grant_base_columns {
    () => {
        concat!(
            "id, tenant_id, name, actor_principal_id, target_service_id, mode, scopes, \
             default_scopes, resource_constraints, max_ttl, ",
            micros!("valid_until"),
            ", status, activation_state, revision"
        )
    };
}
pub(super) use grant_base_columns;

/// `allowed_binding_ids` and `resource_server_ids` are derived from the
/// grant's rows, as for service identities.
macro_rules! grant_columns {
    () => {
        concat!(
            grant_base_columns!(),
            ", ARRAY(SELECT b.binding_id FROM service_grant_binding b \
             WHERE b.grant_id = service_grant.id \
             ORDER BY b.binding_id COLLATE \"C\") AS allowed_binding_ids, \
             ARRAY(SELECT r.resource_server_id FROM service_grant_resource_server r \
             WHERE r.grant_id = service_grant.id \
             ORDER BY r.resource_server_id COLLATE \"C\") AS resource_server_ids"
        )
    };
}
pub(super) use grant_columns;

/// Adds the row `$4` to a list set of the `$owner` row `$1` of tenant `$3`
/// at revision `$2`, advancing the owner's revision in the same statement.
/// The row copies `tenant_id` and the `$carried` owner columns. The owner's
/// revision moves to `revision + 1`, not `$2 + 1`, for the reason given at
/// `compare_and_set!`. The result is read by [`list_change`].
macro_rules! list_add {
    ($owner:literal, $list:literal, $owner_column:literal, $item:literal, $carried:literal) => {
        concat!(
            "WITH bumped AS (UPDATE ",
            $owner,
            " SET revision = revision + 1 WHERE id = $1 AND tenant_id = $3 AND revision = $2 \
             RETURNING id, tenant_id",
            $carried,
            ", revision), added AS (INSERT INTO ",
            $list,
            " (",
            $owner_column,
            ", tenant_id",
            $carried,
            ", ",
            $item,
            ") SELECT id, tenant_id",
            $carried,
            ", $4 FROM bumped) SELECT (SELECT revision FROM bumped) AS revision, \
             (SELECT revision FROM ",
            $owner,
            " WHERE id = $1 AND tenant_id = $3) AS current_revision, true AS listed"
        )
    };
}

/// Removes the row `$4` from a list set of the `$owner` row `$1` of tenant
/// `$3` at revision `$2`, advancing the owner's revision in the same
/// statement. The owner row is locked before the list row is deleted, so
/// two changes from one revision serialize on it. The owner's revision
/// moves as in [`list_add!`]. The result is read by [`list_change`].
macro_rules! list_remove {
    ($owner:literal, $list:literal, $owner_column:literal, $item:literal) => {
        concat!(
            "WITH bumped AS (UPDATE ",
            $owner,
            " SET revision = revision + 1 WHERE id = $1 AND tenant_id = $3 AND revision = $2 \
             AND EXISTS (SELECT FROM ",
            $list,
            " WHERE ",
            $owner_column,
            " = $1 AND ",
            $item,
            " = $4) RETURNING id, revision), removed AS (DELETE FROM ",
            $list,
            " WHERE ",
            $owner_column,
            " IN (SELECT id FROM bumped) AND ",
            $item,
            " = $4) SELECT (SELECT revision FROM bumped) AS revision, (SELECT revision FROM ",
            $owner,
            " WHERE id = $1 AND tenant_id = $3) AS current_revision, EXISTS (SELECT FROM ",
            $list,
            " WHERE ",
            $owner_column,
            " = $1 AND ",
            $item,
            " = $4) AS listed"
        )
    };
}

/// Runs a [`list_add!`] or [`list_remove!`] statement.
async fn change_list<'e>(
    executor: impl PgExecutor<'e>,
    sql: &'static str,
    tenant_id: &str,
    owner_id: &str,
    expected_revision: i64,
    item: &str,
) -> Result<i64, RegistryError> {
    let row = sqlx::query(sql)
        .bind(owner_id)
        .bind(expected_revision)
        .bind(tenant_id)
        .bind(item)
        .fetch_one(executor)
        .await?;
    list_change(&row, expected_revision)
}

/// Creates a binding at revision 1. Its source and its workload principal
/// must be of the same tenant, and the principal a workload. Its
/// `claim_match_policy` must have every predicate its profile requires
/// ([`validate_claim_match_policy`], checked before the statement; an unmet
/// one is [`RegistryError::RequiredPredicate`]).
pub async fn create_principal_binding<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewPrincipalBinding,
) -> Result<PrincipalBinding, RegistryError> {
    validate_claim_match_policy(new.profile, &new.claim_match_policy)?;
    Ok(sqlx::query_as(concat!(
        "INSERT INTO principal_binding \
         (id, tenant_id, name, trust_source_id, profile, claim_match_policy, \
         workload_principal_id, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING ",
        binding_columns!()
    ))
    .bind(&new.id)
    .bind(&new.tenant_id)
    .bind(&new.name)
    .bind(&new.trust_source_id)
    .bind(new.profile.as_str())
    .bind(Json(&new.claim_match_policy))
    .bind(&new.workload_principal_id)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a binding of `tenant_id` by ID.
pub async fn get_principal_binding<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
) -> Result<PrincipalBinding, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        binding_columns!(),
        " FROM principal_binding WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists the bindings of `tenant_id` by ID.
pub async fn list_principal_bindings<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    page: Page<'_>,
) -> Result<Vec<PrincipalBinding>, RegistryError> {
    Ok(
        sqlx::query_as(tenant_list_page!("principal_binding", binding_columns!()))
            .bind(tenant_id)
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of a binding of `tenant_id` at
/// `expected_revision` and advances its revision by one. The new
/// `claim_match_policy` must have every predicate the new profile requires
/// ([`validate_claim_match_policy`], checked before the statement, so a
/// rejected policy is [`RegistryError::RequiredPredicate`] whether or not
/// the binding exists).
/// Removing an optional predicate widens the binding; reviewing that stays
/// with the service (ADR-016 item 2).
pub async fn update_principal_binding<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &PrincipalBindingChanges,
) -> Result<PrincipalBinding, RegistryError> {
    validate_claim_match_policy(changes.profile, &changes.claim_match_policy)?;
    let row = sqlx::query(tenant_compare_and_set!(
        "principal_binding",
        "name = $4, profile = $5, claim_match_policy = $6, status = $7",
        binding_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(tenant_id)
    .bind(&changes.name)
    .bind(changes.profile.as_str())
    .bind(Json(&changes.claim_match_policy))
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Creates a service identity at revision 1 with its initial audiences, in
/// one statement. Its ID must be that of a same-tenant service principal,
/// created first (in the caller's transaction, identity-registry section
/// 5.1), and each audience must be assigned to the tenant
/// (`service_identity_resource_server_assignment_fkey`) by an enabled
/// assignment: since `0010` one that is disabled is
/// [`RegistryError::Invariant`] with [`InvariantKind::AssignmentActive`] and
/// `service_identity_resource_server_assignment_active`, and nothing is
/// written. The guard locks each assignment `FOR SHARE` until the caller's
/// transaction ends (migrations README, "What 0010 adds", for the lock
/// order).
///
/// [`InvariantKind::AssignmentActive`]: super::InvariantKind::AssignmentActive
pub async fn create_service_identity<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewServiceIdentity,
) -> Result<ServiceIdentity, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "WITH created AS (INSERT INTO service_identity \
         (id, tenant_id, name, max_scopes, max_resource_constraints, status) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING ",
        service_base_columns!(),
        "), listed AS (INSERT INTO service_identity_resource_server \
         (service_id, tenant_id, resource_server_id) \
         SELECT created.id, created.tenant_id, u.item FROM created, unnest($7::text[]) AS u(item) \
         RETURNING resource_server_id) \
         SELECT created.*, ARRAY(SELECT resource_server_id FROM listed \
         ORDER BY resource_server_id COLLATE \"C\") AS resource_server_ids FROM created"
    ))
    .bind(&new.id)
    .bind(&new.tenant_id)
    .bind(&new.name)
    .bind(Json(&new.max_scopes))
    .bind(Json(&new.max_resource_constraints))
    .bind(new.status.as_str())
    .bind(&new.resource_server_ids)
    .fetch_one(executor)
    .await?)
}

/// Reads a service identity of `tenant_id`, with its audiences, by ID.
pub async fn get_service_identity<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
) -> Result<ServiceIdentity, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        service_columns!(),
        " FROM service_identity WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists the service identities of `tenant_id`, with their audiences, by
/// ID.
pub async fn list_service_identities<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    page: Page<'_>,
) -> Result<Vec<ServiceIdentity>, RegistryError> {
    Ok(
        sqlx::query_as(tenant_list_page!("service_identity", service_columns!()))
            .bind(tenant_id)
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of a service identity of `tenant_id` at
/// `expected_revision` and advances its revision by one. Its audiences are
/// unchanged.
pub async fn update_service_identity<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &ServiceIdentityChanges,
) -> Result<ServiceIdentity, RegistryError> {
    let row = sqlx::query(tenant_compare_and_set!(
        "service_identity",
        "name = $4, max_scopes = $5, max_resource_constraints = $6, status = $7",
        service_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(tenant_id)
    .bind(&changes.name)
    .bind(Json(&changes.max_scopes))
    .bind(Json(&changes.max_resource_constraints))
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Adds `resource_server_id` to the audiences of the service identity of
/// `tenant_id` at `expected_revision` and advances its revision by one,
/// returning the new revision. The audience must be assigned to the tenant:
/// otherwise [`RegistryError::Invariant`] with
/// `service_identity_resource_server_assignment_fkey`. Since `0010` the
/// assignment must also be enabled: otherwise [`RegistryError::Invariant`]
/// with [`InvariantKind::AssignmentActive`] and
/// `service_identity_resource_server_assignment_active`. One already listed
/// is [`RegistryError::AlreadyExists`] with
/// `service_identity_resource_server_pkey`. No error changes the revision.
/// The statement locks the identity row, then the guard locks the
/// assignment `FOR SHARE`; a caller that audits the write appends its event
/// after this call (migrations README, "What 0010 adds").
///
/// [`InvariantKind::AssignmentActive`]: super::InvariantKind::AssignmentActive
pub async fn add_service_identity_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    service_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    change_list(
        executor,
        list_add!(
            "service_identity",
            "service_identity_resource_server",
            "service_id",
            "resource_server_id",
            ""
        ),
        tenant_id,
        service_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

/// Removes `resource_server_id` from the audiences of the service identity
/// of `tenant_id` at `expected_revision` and advances its revision by one,
/// returning the new revision. An audience not listed is
/// [`RegistryError::NotFound`] and changes nothing.
pub async fn remove_service_identity_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    service_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    change_list(
        executor,
        list_remove!(
            "service_identity",
            "service_identity_resource_server",
            "service_id",
            "resource_server_id"
        ),
        tenant_id,
        service_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

/// Creates a grant at revision 1 with its initial bindings and audiences,
/// in one statement, so a grant created with at least one binding passes
/// the commit-time binding check on any executor. With no binding, the
/// call fails with [`RegistryError::Guard`] on an executor that commits at
/// once; inside a caller transaction the commit fails the same way unless
/// [`add_service_grant_binding`] runs first. Each binding must be a
/// same-tenant binding of the grant's actor
/// (`service_grant_binding_binding_id_fkey`), and each audience assigned to
/// the tenant (`service_grant_resource_server_assignment_fkey`) by an
/// enabled assignment: since `0010` one that is disabled is
/// [`RegistryError::Invariant`] with [`InvariantKind::AssignmentActive`] and
/// `service_grant_resource_server_assignment_active`. A disabled resource
/// server behind an enabled assignment is accepted as a dormant reference
/// (the live check denies it, IR-081).
///
/// An impersonation grant must be created with all its bindings and
/// audiences in this call. Since `0009` it never changes afterwards:
/// [`add_service_grant_binding`] and the other list-set changes first
/// advance the grant's revision with an `UPDATE`, which the guard refuses,
/// so they fail with [`RegistryError::Guard`] even inside the creating
/// transaction.
///
/// [`InvariantKind::AssignmentActive`]: super::InvariantKind::AssignmentActive
pub async fn create_service_grant<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewServiceGrant,
) -> Result<ServiceGrant, RegistryError> {
    let valid_until = optional_since_epoch(new.valid_until)?;
    Ok(sqlx::query_as(concat!(
        "WITH created AS (INSERT INTO service_grant \
         (id, tenant_id, name, actor_principal_id, target_service_id, mode, scopes, \
         default_scopes, resource_constraints, max_ttl, valid_until, status, activation_state) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, timestamptz 'epoch' + $11::interval, \
         $12, $13) RETURNING ",
        grant_base_columns!(),
        "), bound AS (INSERT INTO service_grant_binding \
         (grant_id, binding_id, tenant_id, actor_principal_id) \
         SELECT created.id, u.item, created.tenant_id, created.actor_principal_id \
         FROM created, unnest($14::text[]) AS u(item) RETURNING binding_id), \
         audiences AS (INSERT INTO service_grant_resource_server \
         (grant_id, tenant_id, resource_server_id) \
         SELECT created.id, created.tenant_id, u.item FROM created, unnest($15::text[]) AS u(item) \
         RETURNING resource_server_id) \
         SELECT created.*, \
         ARRAY(SELECT binding_id FROM bound ORDER BY binding_id COLLATE \"C\") \
         AS allowed_binding_ids, \
         ARRAY(SELECT resource_server_id FROM audiences ORDER BY resource_server_id COLLATE \"C\") \
         AS resource_server_ids FROM created"
    ))
    .bind(&new.id)
    .bind(&new.tenant_id)
    .bind(&new.name)
    .bind(&new.actor_principal_id)
    .bind(&new.target_service_id)
    .bind(new.mode.as_str())
    .bind(Json(&new.scopes))
    .bind(new.default_scopes.as_ref().map(Json))
    .bind(Json(&new.resource_constraints))
    .bind(new.max_ttl)
    .bind(valid_until)
    .bind(new.status.as_str())
    .bind(new.activation_state.as_str())
    .bind(&new.allowed_binding_ids)
    .bind(&new.resource_server_ids)
    .fetch_one(executor)
    .await?)
}

/// Reads a grant of `tenant_id`, with its bindings and audiences, by ID.
pub async fn get_service_grant<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
) -> Result<ServiceGrant, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        grant_columns!(),
        " FROM service_grant WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists the grants of `tenant_id`, with their bindings and audiences, by
/// ID.
pub async fn list_service_grants<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    page: Page<'_>,
) -> Result<Vec<ServiceGrant>, RegistryError> {
    Ok(
        sqlx::query_as(tenant_list_page!("service_grant", grant_columns!()))
            .bind(tenant_id)
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of a grant of `tenant_id` at
/// `expected_revision` and advances its revision by one. Its actor, target,
/// mode, bindings and audiences are unchanged.
pub async fn update_service_grant<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &ServiceGrantChanges,
) -> Result<ServiceGrant, RegistryError> {
    let valid_until = optional_since_epoch(changes.valid_until)?;
    let row = sqlx::query(tenant_compare_and_set!(
        "service_grant",
        "name = $4, scopes = $5, default_scopes = $6, resource_constraints = $7, max_ttl = $8, \
         valid_until = timestamptz 'epoch' + $9::interval, status = $10, activation_state = $11",
        grant_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(tenant_id)
    .bind(&changes.name)
    .bind(Json(&changes.scopes))
    .bind(changes.default_scopes.as_ref().map(Json))
    .bind(Json(&changes.resource_constraints))
    .bind(changes.max_ttl)
    .bind(valid_until)
    .bind(changes.status.as_str())
    .bind(changes.activation_state.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Adds `binding_id` to the allowed bindings of the grant of `tenant_id` at
/// `expected_revision` and advances its revision by one, returning the new
/// revision. The binding must be a same-tenant binding of the grant's
/// actor: otherwise [`RegistryError::Invariant`] with
/// `service_grant_binding_binding_id_fkey`. One already listed is
/// [`RegistryError::AlreadyExists`] with `service_grant_binding_pkey`.
/// Neither error changes the revision.
pub async fn add_service_grant_binding<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    binding_id: &str,
) -> Result<i64, RegistryError> {
    change_list(
        executor,
        list_add!(
            "service_grant",
            "service_grant_binding",
            "grant_id",
            "binding_id",
            ", actor_principal_id"
        ),
        tenant_id,
        grant_id,
        expected_revision,
        binding_id,
    )
    .await
}

/// Removes `binding_id` from the allowed bindings of the grant of
/// `tenant_id` at `expected_revision` and advances its revision by one,
/// returning the new revision. A binding not listed is
/// [`RegistryError::NotFound`] and changes nothing.
///
/// Removing the grant's last binding fails at commit with `SK001`
/// ([`RegistryError::Guard`]): at once on an executor that commits at once,
/// at the caller's commit inside a transaction, unless a binding is added
/// before it.
pub async fn remove_service_grant_binding<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    binding_id: &str,
) -> Result<i64, RegistryError> {
    change_list(
        executor,
        list_remove!(
            "service_grant",
            "service_grant_binding",
            "grant_id",
            "binding_id"
        ),
        tenant_id,
        grant_id,
        expected_revision,
        binding_id,
    )
    .await
}

/// Adds `resource_server_id` to the audiences of the grant of `tenant_id`
/// at `expected_revision` and advances its revision by one, returning the
/// new revision. The audience must be assigned to the tenant: otherwise
/// [`RegistryError::Invariant`] with
/// `service_grant_resource_server_assignment_fkey`. Since `0010` the
/// assignment must also be enabled: otherwise [`RegistryError::Invariant`]
/// with [`InvariantKind::AssignmentActive`] and
/// `service_grant_resource_server_assignment_active`. One already listed is
/// [`RegistryError::AlreadyExists`] with `service_grant_resource_server_pkey`.
/// The lock order is that of [`add_service_identity_resource_server`]: the
/// grant row, then the assignment `FOR SHARE`, then the caller's audit
/// event.
///
/// [`InvariantKind::AssignmentActive`]: super::InvariantKind::AssignmentActive
pub async fn add_service_grant_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    change_list(
        executor,
        list_add!(
            "service_grant",
            "service_grant_resource_server",
            "grant_id",
            "resource_server_id",
            ""
        ),
        tenant_id,
        grant_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

/// Removes `resource_server_id` from the audiences of the grant of
/// `tenant_id` at `expected_revision` and advances its revision by one,
/// returning the new revision. An audience not listed is
/// [`RegistryError::NotFound`] and changes nothing.
pub async fn remove_service_grant_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    expected_revision: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    change_list(
        executor,
        list_remove!(
            "service_grant",
            "service_grant_resource_server",
            "grant_id",
            "resource_server_id"
        ),
        tenant_id,
        grant_id,
        expected_revision,
        resource_server_id,
    )
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn list_add_bumps_the_owner_revision_and_copies_its_columns() {
        assert_eq!(
            list_add!(
                "service_grant",
                "service_grant_binding",
                "grant_id",
                "binding_id",
                ", actor_principal_id"
            ),
            "WITH bumped AS (UPDATE service_grant SET revision = revision + 1 \
             WHERE id = $1 AND tenant_id = $3 AND revision = $2 \
             RETURNING id, tenant_id, actor_principal_id, revision), \
             added AS (INSERT INTO service_grant_binding \
             (grant_id, tenant_id, actor_principal_id, binding_id) \
             SELECT id, tenant_id, actor_principal_id, $4 FROM bumped) \
             SELECT (SELECT revision FROM bumped) AS revision, \
             (SELECT revision FROM service_grant WHERE id = $1 AND tenant_id = $3) \
             AS current_revision, true AS listed"
        );
    }

    #[test]
    fn list_remove_deletes_only_after_the_owner_revision_moved() {
        assert_eq!(
            list_remove!(
                "service_identity",
                "service_identity_resource_server",
                "service_id",
                "resource_server_id"
            ),
            "WITH bumped AS (UPDATE service_identity SET revision = revision + 1 \
             WHERE id = $1 AND tenant_id = $3 AND revision = $2 \
             AND EXISTS (SELECT FROM service_identity_resource_server \
             WHERE service_id = $1 AND resource_server_id = $4) RETURNING id, revision), \
             removed AS (DELETE FROM service_identity_resource_server \
             WHERE service_id IN (SELECT id FROM bumped) AND resource_server_id = $4) \
             SELECT (SELECT revision FROM bumped) AS revision, \
             (SELECT revision FROM service_identity WHERE id = $1 AND tenant_id = $3) \
             AS current_revision, EXISTS (SELECT FROM service_identity_resource_server \
             WHERE service_id = $1 AND resource_server_id = $4) AS listed"
        );
    }
}
