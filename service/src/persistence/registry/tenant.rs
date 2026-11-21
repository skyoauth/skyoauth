//! Tenants and principals (`0002`), with the revisions `0007` adds.

use sqlx::PgExecutor;

use super::{
    NewPrincipal, NewTenant, Page, Principal, PrincipalPatch, RegistryError, Status, Tenant,
    TenantPatch, compare_and_set, list_page, micros, tenant_compare_and_set, updated,
};

macro_rules! tenant_columns {
    () => {
        concat!(
            "id, name, secret_namespace, status, ",
            micros!("created_at"),
            ", revision"
        )
    };
}

macro_rules! principal_columns {
    () => {
        concat!(
            "id, tenant_id, kind, name, status, ",
            micros!("created_at"),
            ", revision"
        )
    };
}

/// The error of an update with an empty patch: an encode error, mapped to
/// [`RegistryError::Other`] like an out-of-range time, returned before any
/// statement runs (lead ruling, 2026-11-21).
fn empty_patch() -> RegistryError {
    sqlx::Error::Encode("empty patch".into()).into()
}

/// Creates a tenant with the caller's ID and secret namespace.
pub async fn create_tenant<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTenant,
) -> Result<Tenant, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO tenant (id, name, secret_namespace, status) VALUES ($1, $2, $3, $4) \
         RETURNING ",
        tenant_columns!()
    ))
    .bind(&new.id)
    .bind(&new.name)
    .bind(&new.secret_namespace)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a tenant by ID.
pub async fn get_tenant<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<Tenant, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        tenant_columns!(),
        " FROM tenant WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists tenants by ID.
pub async fn list_tenants<'e>(
    executor: impl PgExecutor<'e>,
    page: Page<'_>,
) -> Result<Vec<Tenant>, RegistryError> {
    Ok(sqlx::query_as(list_page!("tenant", tenant_columns!()))
        .bind(page.after_id())
        .bind(i64::from(page.limit()))
        .fetch_all(executor)
        .await?)
}

/// Changes the columns set in `patch` of the tenant `id` at
/// `expected_revision` and advances its revision by one. `id`,
/// `secret_namespace` and `created_at` keep their values.
///
/// A name need not be unique: `0002` has no unique constraint on it. An
/// empty patch is an encode error, [`RegistryError::Other`], before any
/// statement runs. Re-enabling a disabled tenant is a plain status change
/// here; whether it needs an approval, and any other widening rule, belongs
/// to the service layer (provisional lead pick, 2026-11-21).
pub async fn update_tenant<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    patch: &TenantPatch,
) -> Result<Tenant, RegistryError> {
    if patch.is_empty() {
        return Err(empty_patch());
    }
    let row = sqlx::query(compare_and_set!(
        "tenant",
        "name = coalesce($3, name), status = coalesce($4, status)",
        tenant_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(patch.name.as_deref())
    .bind(patch.status.map(Status::as_str))
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Creates a principal in its tenant.
pub async fn create_principal<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewPrincipal,
) -> Result<Principal, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO principal (id, tenant_id, kind, name, status) \
         VALUES ($1, $2, $3, $4, $5) RETURNING ",
        principal_columns!()
    ))
    .bind(&new.id)
    .bind(&new.tenant_id)
    .bind(new.kind.as_str())
    .bind(&new.name)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a principal of `tenant_id` by ID; one of another tenant is
/// [`RegistryError::NotFound`].
pub async fn get_principal<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
) -> Result<Principal, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        principal_columns!(),
        " FROM principal WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Changes the columns set in `patch` of the principal `id` of `tenant_id`
/// at `expected_revision` and advances its revision by one. `id`,
/// `tenant_id`, `kind` and `created_at` keep their values. A principal of
/// another tenant is [`RegistryError::NotFound`], whatever its revision.
///
/// The update is kind-agnostic: the rule that only workload and service
/// principals change through this path belongs to the service handler
/// (lead ruling, 2026-11-21). A name need not be unique: `0002` has no
/// unique constraint on it. An empty patch is an encode error,
/// [`RegistryError::Other`], before any statement runs. Re-enabling a
/// disabled principal is a plain status change here; whether it needs an
/// approval, and any other widening rule, belongs to the service layer
/// (provisional lead pick, 2026-11-21).
pub async fn update_principal<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    patch: &PrincipalPatch,
) -> Result<Principal, RegistryError> {
    if patch.is_empty() {
        return Err(empty_patch());
    }
    let row = sqlx::query(tenant_compare_and_set!(
        "principal",
        "name = coalesce($4, name), status = coalesce($5, status)",
        principal_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(tenant_id)
    .bind(patch.name.as_deref())
    .bind(patch.status.map(Status::as_str))
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Lists the principals of `tenant_id` by ID.
pub async fn list_principals<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    page: Page<'_>,
) -> Result<Vec<Principal>, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        principal_columns!(),
        " FROM principal WHERE tenant_id = $1 AND ($2::text IS NULL OR id > $2 COLLATE \"C\") \
         ORDER BY id COLLATE \"C\" LIMIT $3"
    ))
    .bind(tenant_id)
    .bind(page.after_id())
    .bind(i64::from(page.limit()))
    .fetch_all(executor)
    .await?)
}
