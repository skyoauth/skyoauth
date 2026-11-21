//! Tenants and principals (`0002`). Neither has a revision column yet, so
//! both are create-only here.

use sqlx::PgExecutor;

use super::{NewPrincipal, NewTenant, Page, Principal, RegistryError, Tenant, list_page};

macro_rules! tenant_columns {
    () => {
        "id, name, secret_namespace, status, \
         (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us"
    };
}

macro_rules! principal_columns {
    () => {
        "id, tenant_id, kind, name, status, \
         (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us"
    };
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
