//! Egress allowlist fixtures for trust sources written through the bare
//! registry writers.
//!
//! Since migration `0011` (service/migrations/README.md, "What 0011 adds";
//! provisional lead pick, 2026-11-22) the database refuses a trust source
//! whose `discovery_url` or `token_review_endpoint` has no enabled egress
//! allowlist entry of its purpose with exactly that value (`23514`,
//! `trust_source_discovery_url_egress_enabled` or
//! `trust_source_token_review_endpoint_egress_enabled`). A scenario that
//! creates sources with `registry::create_trust_source` first allows their
//! destinations with [`allow_destinations`].

use skyoauth_service::persistence::{PgPool, registry::NewTrustSource};

/// Inserts an enabled egress allowlist entry for each destination `source`
/// sets: `discovery_url` with purpose `oidc_discovery` and
/// `token_review_endpoint` with purpose `token_review`. An entry that
/// exists for the purpose and destination is left as it is, so sources that
/// share a destination may each call this. The entry ID is derived from the
/// purpose and the destination.
///
/// # Panics
///
/// When the insert fails.
pub async fn allow_destinations(pool: &PgPool, source: &NewTrustSource) {
    for (purpose, destination) in [
        ("oidc_discovery", source.discovery_url.as_deref()),
        ("token_review", source.token_review_endpoint.as_deref()),
    ] {
        let Some(destination) = destination else {
            continue;
        };
        sqlx::query(
            "INSERT INTO egress_allowlist_entry (id, purpose, exact_destination, status) \
             VALUES ('egr_' || md5($1 || ' ' || $2), $1, $2, 'enabled') ON CONFLICT DO NOTHING",
        )
        .bind(purpose)
        .bind(destination)
        .execute(pool)
        .await
        .unwrap_or_else(|err| panic!("egress entry for a {purpose} destination: {err}"));
    }
}
