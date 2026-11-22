//! Trust keysets, their versions and trust sources (`0004`). All three are
//! tenant-owned, so every read and update names the tenant.

use std::time::SystemTime;

use sqlx::{FromRow, PgExecutor, Row, postgres::PgRow, types::Json};

use super::{
    NewTrustKeyset, NewTrustKeysetVersion, NewTrustSource, Page, RegistryError, Status,
    TrustKeyset, TrustKeysetChanges, TrustKeysetVersion, TrustSource, TrustSourceChanges, micros,
    model::{Origin, optional_since_epoch, required_timestamp, since_epoch, text, timestamp},
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
pub(super) use source_columns;

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
///
/// **Test-only: the unchecked floor.** This writer stores whatever
/// `public_jwks` and `fingerprint` it is given: no JWK rule, no point
/// check, no overlap check, no authorization and no audit event; only the
/// `0004` `CHECK`s apply. It stays public for the integration and scenario
/// tests (provisional lead pick, 2026-11-22: they call it from other
/// crates, so it cannot be crate-private), and it must stay unreachable
/// from any endpoint. The write path is
/// [`trust::keyset::create_version`](crate::trust::keyset::create_version),
/// which validates the upload, stores its canonical projection and
/// fingerprint, checks the overlap and appends the audit event; it must be
/// the only path that writes a keyset version outside tests.
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

/// One version of a keyset as the keyset write path
/// ([`crate::trust::keyset`]) reads it: its `public_jwks` as the text
/// PostgreSQL prints, not parsed, so the write path can bound it before
/// any parse.
pub(crate) struct KeysetVersionText {
    pub(crate) id: String,
    pub(crate) public_jwks: String,
    pub(crate) effective_at: SystemTime,
    pub(crate) expires_at: Option<SystemTime>,
    pub(crate) status: Status,
    pub(crate) revision: i64,
}

impl FromRow<'_, PgRow> for KeysetVersionText {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("trust_keyset_version");
        Ok(Self {
            id: row.try_get("id")?,
            public_jwks: row.try_get("public_jwks")?,
            effective_at: required_timestamp(row, ORIGIN, "effective_at")?,
            expires_at: timestamp(row, ORIGIN, "expires_at")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// Every version of the keyset `keyset_id` of `tenant_id`, by ID, for the
/// keyset write path, which holds the parent keyset row locked while it
/// reads them. Takes no lock of its own.
pub(crate) async fn read_keyset_versions<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    keyset_id: &str,
) -> Result<Vec<KeysetVersionText>, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "SELECT id, public_jwks::text AS public_jwks, ",
        micros!("effective_at"),
        ", ",
        micros!("expires_at"),
        ", status, revision FROM trust_keyset_version WHERE tenant_id = $1 AND keyset_id = $2 \
         ORDER BY id COLLATE \"C\""
    ))
    .bind(tenant_id)
    .bind(keyset_id)
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
///
/// A row holding a time outside the `0007` range checks fails the update
/// with `23514` while the checks are in force; with them dropped, the write
/// applies and the call returns [`RegistryError::UnreadableTimestamp`] (see
/// the module documentation, "Timestamps").
///
/// **Test-only: the unchecked floor**, like
/// [`create_trust_keyset_version`]: a re-enable here runs no overlap check,
/// no authorization and no audit event. It stays public for the tests and
/// must stay unreachable from any endpoint; the write path is
/// [`trust::keyset::enable_version`](crate::trust::keyset::enable_version)
/// and [`trust::keyset::disable_version`](crate::trust::keyset::disable_version)
/// (provisional lead pick, 2026-11-22).
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
