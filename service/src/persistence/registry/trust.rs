//! Trust keysets, their versions and trust sources (`0004`). All three are
//! tenant-owned, so every read and update names the tenant.

use sqlx::{PgExecutor, types::Json};

use super::{
    NewTrustKeyset, NewTrustKeysetVersion, NewTrustSource, Page, RegistryError, Status,
    TrustKeyset, TrustKeysetChanges, TrustKeysetVersion, TrustSource, TrustSourceChanges, micros,
    model::{optional_since_epoch, since_epoch},
    tenant_compare_and_set, tenant_list_page, updated,
};

macro_rules! keyset_columns {
    () => {
        "id, tenant_id, name, status, revision"
    };
}

macro_rules! version_columns {
    () => {
        concat!(
            "id, tenant_id, keyset_id, public_jwks, fingerprint, ",
            micros!("effective_at"),
            ", ",
            micros!("expires_at"),
            ", status, provenance, revision"
        )
    };
}

macro_rules! source_columns {
    () => {
        "id, tenant_id, name, kind, exact_issuer, discovery_url, jwks_keyset_id, cluster_id, \
         token_review_endpoint, ca_bundle_ref, ca_fingerprint, reviewer_credential_ref, \
         review_timeout_ms, audiences, algorithms, proof_bounds, assertion_profile, \
         stale_revocation_acknowledged, replay_mode, status, revision"
    };
}

/// Creates a keyset at revision 1.
pub async fn create_trust_keyset<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTrustKeyset,
) -> Result<TrustKeyset, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO trust_keyset (id, tenant_id, name, status) VALUES ($1, $2, $3, $4) \
         RETURNING ",
        keyset_columns!()
    ))
    .bind(&new.id)
    .bind(&new.tenant_id)
    .bind(&new.name)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a keyset of `tenant_id` by ID.
pub async fn get_trust_keyset<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
) -> Result<TrustKeyset, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        keyset_columns!(),
        " FROM trust_keyset WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists the keysets of `tenant_id` by ID.
pub async fn list_trust_keysets<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    page: Page<'_>,
) -> Result<Vec<TrustKeyset>, RegistryError> {
    Ok(
        sqlx::query_as(tenant_list_page!("trust_keyset", keyset_columns!()))
            .bind(tenant_id)
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of a keyset of `tenant_id` at
/// `expected_revision` and advances its revision by one.
pub async fn update_trust_keyset<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustKeysetChanges,
) -> Result<TrustKeyset, RegistryError> {
    let row = sqlx::query(tenant_compare_and_set!(
        "trust_keyset",
        "name = $4, status = $5",
        keyset_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(tenant_id)
    .bind(&changes.name)
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Creates a version of a same-tenant keyset at revision 1. Versions are
/// immutable but for `status`, which [`update_trust_keyset_version`]
/// changes.
pub async fn create_trust_keyset_version<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTrustKeysetVersion,
) -> Result<TrustKeysetVersion, RegistryError> {
    let effective_at = since_epoch(new.effective_at)?;
    let expires_at = optional_since_epoch(new.expires_at)?;
    Ok(sqlx::query_as(concat!(
        "INSERT INTO trust_keyset_version \
         (id, tenant_id, keyset_id, public_jwks, fingerprint, effective_at, expires_at, status, \
         provenance) VALUES ($1, $2, $3, $4, $5, timestamptz 'epoch' + $6::interval, \
         timestamptz 'epoch' + $7::interval, $8, $9) RETURNING ",
        version_columns!()
    ))
    .bind(&new.id)
    .bind(&new.tenant_id)
    .bind(&new.keyset_id)
    .bind(Json(&new.public_jwks))
    .bind(&new.fingerprint)
    .bind(effective_at)
    .bind(expires_at)
    .bind(new.status.as_str())
    .bind(Json(&new.provenance))
    .fetch_one(executor)
    .await?)
}

/// Reads a keyset version of `tenant_id` by ID.
pub async fn get_trust_keyset_version<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
) -> Result<TrustKeysetVersion, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        version_columns!(),
        " FROM trust_keyset_version WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists the versions of the keyset `keyset_id` of `tenant_id` by ID
/// (inferred: per keyset, the set a verifier reads).
pub async fn list_trust_keyset_versions<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    keyset_id: &str,
    page: Page<'_>,
) -> Result<Vec<TrustKeysetVersion>, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "SELECT ",
        version_columns!(),
        " FROM trust_keyset_version WHERE tenant_id = $1 AND keyset_id = $2 \
         AND ($3::text IS NULL OR id > $3 COLLATE \"C\") ORDER BY id COLLATE \"C\" LIMIT $4"
    ))
    .bind(tenant_id)
    .bind(keyset_id)
    .bind(page.after_id())
    .bind(i64::from(page.limit()))
    .fetch_all(executor)
    .await?)
}

/// Sets the `status` of the keyset version `id` of `tenant_id` at
/// `expected_revision` and advances the version's own revision by one, with
/// no tie to the keyset's revision (lead decision, 2026-11-21). Every other
/// column keeps its value. A version of another tenant is
/// [`RegistryError::NotFound`], whatever its revision.
///
/// Re-enabling a disabled version is a plain status change here; whether it
/// needs an approval, and any other widening rule, belongs to the service
/// layer (provisional lead pick, 2026-11-21).
pub async fn update_trust_keyset_version<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    status: Status,
) -> Result<TrustKeysetVersion, RegistryError> {
    let row = sqlx::query(tenant_compare_and_set!(
        "trust_keyset_version",
        "status = $4",
        version_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(tenant_id)
    .bind(status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}

/// Creates a trust source at revision 1. The database checks that the
/// kind-specific fields match `kind` (the `trust_source_*_kind_check`
/// constraints).
pub async fn create_trust_source<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewTrustSource,
) -> Result<TrustSource, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO trust_source \
         (id, tenant_id, name, kind, exact_issuer, discovery_url, jwks_keyset_id, cluster_id, \
         token_review_endpoint, ca_bundle_ref, ca_fingerprint, reviewer_credential_ref, \
         review_timeout_ms, audiences, algorithms, proof_bounds, assertion_profile, \
         stale_revocation_acknowledged, replay_mode, status) VALUES ($1, $2, $3, $4, $5, $6, \
         $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20) RETURNING ",
        source_columns!()
    ))
    .bind(&new.id)
    .bind(&new.tenant_id)
    .bind(&new.name)
    .bind(new.kind.as_str())
    .bind(&new.exact_issuer)
    .bind(&new.discovery_url)
    .bind(&new.jwks_keyset_id)
    .bind(&new.cluster_id)
    .bind(&new.token_review_endpoint)
    .bind(&new.ca_bundle_ref)
    .bind(&new.ca_fingerprint)
    .bind(&new.reviewer_credential_ref)
    .bind(new.review_timeout_ms)
    .bind(Json(&new.audiences))
    .bind(new.algorithms.as_ref().map(Json))
    .bind(Json(&new.proof_bounds))
    .bind(new.assertion_profile.as_str())
    .bind(new.stale_revocation_acknowledged)
    .bind(new.replay_mode.as_str())
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a trust source of `tenant_id` by ID.
pub async fn get_trust_source<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
) -> Result<TrustSource, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        source_columns!(),
        " FROM trust_source WHERE tenant_id = $1 AND id = $2"
    ))
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists the trust sources of `tenant_id` by ID.
pub async fn list_trust_sources<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    page: Page<'_>,
) -> Result<Vec<TrustSource>, RegistryError> {
    Ok(
        sqlx::query_as(tenant_list_page!("trust_source", source_columns!()))
            .bind(tenant_id)
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Replaces the mutable columns of a trust source of `tenant_id` at
/// `expected_revision` and advances its revision by one. `kind`,
/// `cluster_id` and `jwks_keyset_id` keep their values.
pub async fn update_trust_source<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustSourceChanges,
) -> Result<TrustSource, RegistryError> {
    let row = sqlx::query(tenant_compare_and_set!(
        "trust_source",
        "name = $4, exact_issuer = $5, discovery_url = $6, token_review_endpoint = $7, \
         ca_bundle_ref = $8, ca_fingerprint = $9, reviewer_credential_ref = $10, \
         review_timeout_ms = $11, audiences = $12, algorithms = $13, proof_bounds = $14, \
         assertion_profile = $15, stale_revocation_acknowledged = $16, replay_mode = $17, \
         status = $18",
        source_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(tenant_id)
    .bind(&changes.name)
    .bind(&changes.exact_issuer)
    .bind(&changes.discovery_url)
    .bind(&changes.token_review_endpoint)
    .bind(&changes.ca_bundle_ref)
    .bind(&changes.ca_fingerprint)
    .bind(&changes.reviewer_credential_ref)
    .bind(changes.review_timeout_ms)
    .bind(Json(&changes.audiences))
    .bind(changes.algorithms.as_ref().map(Json))
    .bind(Json(&changes.proof_bounds))
    .bind(changes.assertion_profile.as_str())
    .bind(changes.stale_revocation_acknowledged)
    .bind(changes.replay_mode.as_str())
    .bind(changes.status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}
