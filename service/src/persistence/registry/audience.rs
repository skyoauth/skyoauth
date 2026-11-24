//! Resource servers, audience tenant assignments, checkers with their
//! tenant rows, and resource actions (`0003`).

use sqlx::{PgExecutor, types::Json};

use super::{
    AudienceTenantAssignment, AudienceTenantAssignmentChanges, NewAudienceTenantAssignment,
    NewResourceAction, NewResourceServer, NewResourceServerChecker, Page, RegistryError,
    ResourceAction, ResourceActionChanges, ResourceServer, ResourceServerChanges,
    ResourceServerChecker, ResourceServerCheckerChanges, compare_and_set, list_change, list_page,
    updated,
};

macro_rules! resource_server_columns {
    () => {
        "id, audience, name, allowed_profiles, scopes, constraint_versions, status, revision"
    };
}

macro_rules! assignment_columns {
    () => {
        "id, resource_server_id, tenant_id, allowed_profiles, allowed_scopes, \
         constraint_versions, status, revision"
    };
}

/// `allowed_tenant_ids` is derived from the checker's tenant rows. The
/// subquery names the table, not an alias, so the same list serves
/// `SELECT … FROM resource_server_checker` and `RETURNING`.
macro_rules! checker_columns {
    () => {
        "id, resource_server_id, public_mtls_identity, status, revision, \
         ARRAY(SELECT t.tenant_id FROM resource_server_checker_tenant t \
         WHERE t.checker_id = resource_server_checker.id \
         ORDER BY t.tenant_id COLLATE \"C\") AS allowed_tenant_ids"
    };
}

macro_rules! action_columns {
    () => {
        "id, resource_server_id, action_name, required_scopes, accepted_profiles, \
         required_resource_dimensions, live_check_required, status, revision"
    };
}

/// Creates a resource server at revision 1.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn create_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewResourceServer,
) -> Result<ResourceServer, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO resource_server \
         (id, audience, name, allowed_profiles, scopes, constraint_versions, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING ",
        resource_server_columns!()
    ))
    .bind(&new.id)
    .bind(&new.audience)
    .bind(&new.name)
    .bind(Json(&new.allowed_profiles))
    .bind(Json(&new.scopes))
    .bind(Json(&new.constraint_versions))
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a resource server by ID.
pub async fn get_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<ResourceServer, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        resource_server_columns!(),
        " FROM resource_server WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists resource servers by ID.
pub async fn list_resource_servers<'e>(
    executor: impl PgExecutor<'e>,
    page: Page<'_>,
) -> Result<Vec<ResourceServer>, RegistryError> {
    Ok(
        sqlx::query_as(list_page!("resource_server", resource_server_columns!()))
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of a resource server at
/// `expected_revision` and advances its revision by one.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn update_resource_server<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceServerChanges,
) -> Result<ResourceServer, RegistryError> {
    let row = sqlx::query(compare_and_set!(
        "resource_server",
        "name = $3, allowed_profiles = $4, scopes = $5, constraint_versions = $6, status = $7",
        resource_server_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(&changes.name)
    .bind(Json(&changes.allowed_profiles))
    .bind(Json(&changes.scopes))
    .bind(Json(&changes.constraint_versions))
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Creates an audience assignment of a tenant at revision 1.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn create_audience_tenant_assignment<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAudienceTenantAssignment,
) -> Result<AudienceTenantAssignment, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO audience_tenant_assignment \
         (id, resource_server_id, tenant_id, allowed_profiles, allowed_scopes, \
         constraint_versions, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING ",
        assignment_columns!()
    ))
    .bind(&new.id)
    .bind(&new.resource_server_id)
    .bind(&new.tenant_id)
    .bind(Json(&new.allowed_profiles))
    .bind(Json(&new.allowed_scopes))
    .bind(Json(&new.constraint_versions))
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads an assignment by ID.
pub async fn get_audience_tenant_assignment<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<AudienceTenantAssignment, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        assignment_columns!(),
        " FROM audience_tenant_assignment WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists assignments by ID.
pub async fn list_audience_tenant_assignments<'e>(
    executor: impl PgExecutor<'e>,
    page: Page<'_>,
) -> Result<Vec<AudienceTenantAssignment>, RegistryError> {
    Ok(sqlx::query_as(list_page!(
        "audience_tenant_assignment",
        assignment_columns!()
    ))
    .bind(page.after_id())
    .bind(i64::from(page.limit()))
    .fetch_all(executor)
    .await?)
}

/// Replaces the mutable columns of an assignment at `expected_revision` and
/// advances its revision by one.
///
/// Since `0010` a service identity's or grant's audience insert locks the
/// assignment `FOR SHARE` until its transaction ends, so this update, a
/// disable included, waits for such an insert to commit or roll back, and
/// an insert waits for this update. Disabling an assignment that rows
/// already reference is not refused (lead ruling, 2026-11-21, decision 4 of
/// docs/proposals/ir-080-assignment-write-guard.md: the live check denies
/// them), and enabling one revalidates nothing. A caller
/// that audits the update appends its event after this call, so it locks
/// the assignment before the audit head (migrations README, "What 0010
/// adds").
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn update_audience_tenant_assignment<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &AudienceTenantAssignmentChanges,
) -> Result<AudienceTenantAssignment, RegistryError> {
    let row = sqlx::query(compare_and_set!(
        "audience_tenant_assignment",
        "allowed_profiles = $3, allowed_scopes = $4, constraint_versions = $5, status = $6",
        assignment_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(Json(&changes.allowed_profiles))
    .bind(Json(&changes.allowed_scopes))
    .bind(Json(&changes.constraint_versions))
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Creates a checker at revision 1, with no tenants.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn create_resource_server_checker<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewResourceServerChecker,
) -> Result<ResourceServerChecker, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO resource_server_checker \
         (id, resource_server_id, public_mtls_identity, status) VALUES ($1, $2, $3, $4) \
         RETURNING ",
        checker_columns!()
    ))
    .bind(&new.id)
    .bind(&new.resource_server_id)
    .bind(&new.public_mtls_identity)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a checker, with its tenant set, by ID.
pub async fn get_resource_server_checker<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<ResourceServerChecker, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        checker_columns!(),
        " FROM resource_server_checker WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists checkers, with their tenant sets, by ID.
pub async fn list_resource_server_checkers<'e>(
    executor: impl PgExecutor<'e>,
    page: Page<'_>,
) -> Result<Vec<ResourceServerChecker>, RegistryError> {
    Ok(
        sqlx::query_as(list_page!("resource_server_checker", checker_columns!()))
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of a checker at `expected_revision` and
/// advances its revision by one. Its tenant set is unchanged.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn update_resource_server_checker<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceServerCheckerChanges,
) -> Result<ResourceServerChecker, RegistryError> {
    let row = sqlx::query(compare_and_set!(
        "resource_server_checker",
        "public_mtls_identity = $3, status = $4",
        checker_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(&changes.public_mtls_identity)
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Adds `tenant_id` to the tenant set of the checker at `expected_revision`
/// and advances the checker's revision by one, returning the new revision.
///
/// The tenant must have an assignment of the checker's resource server,
/// whatever its status: otherwise [`RegistryError::Invariant`] with
/// `resource_server_checker_tenant_assignment_fkey`. A tenant already in the
/// set is [`RegistryError::AlreadyExists`] with
/// `resource_server_checker_tenant_pkey`. Neither error changes the
/// revision.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn add_resource_server_checker_tenant<'e>(
    executor: impl PgExecutor<'e>,
    checker_id: &str,
    expected_revision: i64,
    tenant_id: &str,
) -> Result<i64, RegistryError> {
    let row = sqlx::query(
        "WITH bumped AS (
             UPDATE resource_server_checker SET revision = revision + 1
             WHERE id = $1 AND revision = $2
             RETURNING id, resource_server_id, revision
         ), added AS (
             INSERT INTO resource_server_checker_tenant (checker_id, resource_server_id, tenant_id)
             SELECT id, resource_server_id, $3 FROM bumped
         )
         SELECT (SELECT revision FROM bumped) AS revision,
                (SELECT revision FROM resource_server_checker WHERE id = $1) AS current_revision,
                true AS listed",
    )
    .bind(checker_id)
    .bind(expected_revision)
    .bind(tenant_id)
    .fetch_one(executor)
    .await?;
    list_change(&row, expected_revision)
}

/// Removes `tenant_id` from the tenant set of the checker at
/// `expected_revision` and advances the checker's revision by one, returning
/// the new revision. A tenant not in the set is [`RegistryError::NotFound`]
/// and changes nothing.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn remove_resource_server_checker_tenant<'e>(
    executor: impl PgExecutor<'e>,
    checker_id: &str,
    expected_revision: i64,
    tenant_id: &str,
) -> Result<i64, RegistryError> {
    // The checker row is locked before the tenant row is deleted, so two
    // set changes from one revision serialize on it and the second finds the
    // revision moved.
    let row = sqlx::query(
        "WITH bumped AS (
             UPDATE resource_server_checker SET revision = revision + 1
             WHERE id = $1 AND revision = $2 AND EXISTS (
                 SELECT FROM resource_server_checker_tenant
                 WHERE checker_id = $1 AND tenant_id = $3)
             RETURNING id, revision
         ), removed AS (
             DELETE FROM resource_server_checker_tenant
             WHERE checker_id IN (SELECT id FROM bumped) AND tenant_id = $3
         )
         SELECT (SELECT revision FROM bumped) AS revision,
                (SELECT revision FROM resource_server_checker WHERE id = $1) AS current_revision,
                EXISTS (SELECT FROM resource_server_checker_tenant
                        WHERE checker_id = $1 AND tenant_id = $3) AS listed",
    )
    .bind(checker_id)
    .bind(expected_revision)
    .bind(tenant_id)
    .fetch_one(executor)
    .await?;
    list_change(&row, expected_revision)
}

/// Creates an action rule at revision 1.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn create_resource_action<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewResourceAction,
) -> Result<ResourceAction, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO resource_action \
         (id, resource_server_id, action_name, required_scopes, accepted_profiles, \
         required_resource_dimensions, live_check_required, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING ",
        action_columns!()
    ))
    .bind(&new.id)
    .bind(&new.resource_server_id)
    .bind(&new.action_name)
    .bind(Json(&new.required_scopes))
    .bind(Json(&new.accepted_profiles))
    .bind(Json(&new.required_resource_dimensions))
    .bind(new.live_check_required)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads an action rule by ID.
pub async fn get_resource_action<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<ResourceAction, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        action_columns!(),
        " FROM resource_action WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists action rules by ID.
pub async fn list_resource_actions<'e>(
    executor: impl PgExecutor<'e>,
    page: Page<'_>,
) -> Result<Vec<ResourceAction>, RegistryError> {
    Ok(
        sqlx::query_as(list_page!("resource_action", action_columns!()))
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of an action rule at `expected_revision`
/// and advances its revision by one.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn update_resource_action<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceActionChanges,
) -> Result<ResourceAction, RegistryError> {
    let row = sqlx::query(compare_and_set!(
        "resource_action",
        "required_scopes = $3, accepted_profiles = $4, required_resource_dimensions = $5, \
         live_check_required = $6, status = $7",
        action_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(Json(&changes.required_scopes))
    .bind(Json(&changes.accepted_profiles))
    .bind(Json(&changes.required_resource_dimensions))
    .bind(changes.live_check_required)
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}
