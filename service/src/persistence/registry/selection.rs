//! Grant selection for the workload exchange (ADR-015 item 4 steps 1, 3
//! and 4; design section 5.7; T12.3; groundwork for T12.7 and T21.4;
//! conformance A25 and A50).
//!
//! [`select_grant`] is step 1 with the loading half of step 3: in one
//! statement it loads the selected grant and source as untrusted candidates
//! and the grant's eligible bindings.
//! [`match_binding`](crate::policy::match_binding) is the matching half of
//! step 3 and step 4: it picks the one eligible binding that the verified
//! evidence matches (see its module, `policy`, for the matching rules).
//! Between the two, the caller verifies the proof at the selected source
//! (step 2); selection does not.
//!
//! # Selection
//!
//! A grant is selected by tenant, grant ID, source ID and the mode the
//! request expects. The grant must be of that tenant and mode and enabled,
//! and the source of that tenant and enabled. Its eligible bindings are the
//! rows of its allowed bindings (`service_grant_binding`) whose binding is
//! of the grant's tenant, verifies at the selected source, maps to the
//! grant's actor and is enabled, sorted by ID byte-wise. Bindings of other
//! actors, of other sources, disabled ones and ones the grant does not list
//! are never loaded. The `0004` foreign keys already keep a listed binding
//! in the grant's tenant and on the grant's actor (ADR-022 item 13), and a
//! binding's source in the binding's tenant; the statement checks the
//! tenant of the grant, the source and the binding, and the actor, again
//! rather than rely on them.
//!
//! The grant and source are enabled at selection time; step 5 re-checks
//! their current status later (see "Not done here"). They are filtered
//! here as well for two reasons (inferred): a disabled grant or source and
//! a miss map to the same wire error (`invalid_grant`, ERR-020), so the
//! filter does not change what a client sees; and the caller must not call
//! a disabled source's discovery, JWKS or TokenReview endpoint to verify
//! the proof (step 2) before it can deny, which it can only avoid if a
//! disabled source is not selected. The dormant impersonation grant is
//! covered by the same filter: the schema keeps an impersonation grant
//! disabled (`service_grant_impersonation_disabled_check`, `0004`), so no
//! `activation_state` filter is needed for it.
//!
//! The grant's actor and target are candidates: an ID is not proof of the
//! actor (design section 5.7 step 2). Only a binding that matches evidence
//! verified at the selected source ties the request to the actor.
//!
//! The tenant is an argument, while IR-033 and API-015 say the tenant of a
//! workload request comes from the selected source and grant, and a request
//! carries no tenant override. How the T21 caller gets the tenant is an
//! open design question, not settled here: a global source lookup before
//! [`select_grant`] (a miss there ending in the same `NotSelectable` and
//! `invalid_grant`), or a variant of [`select_grant`] that takes the tenant
//! from the source.
//!
//! # One outcome for every miss
//!
//! A wrong tenant, an unknown grant, a disabled grant, a mode mismatch, an
//! unknown source, a disabled source or one of another tenant, and a grant
//! with no eligible binding for the source all give the same value,
//! [`SelectionError::NotSelectable`], which carries no detail (ERR-020;
//! design section 5.7 step 1). Every miss runs the same statement, which
//! then returns no row, and the same Rust path after it.
//!
//! The statement's `WHERE EXISTS` gate is what makes a miss return no row,
//! and it is required: without it, a miss that finds the grant (a grant
//! with no eligible binding, or a source of another tenant) would still
//! return the grant row, and decoding a corrupt grant row could give
//! [`SelectionError::Store`] instead of `NotSelectable`, so the outcome of
//! a miss would depend on which selector missed. The Rust check that the
//! eligible bindings are not empty is defense in depth; if either ever
//! goes, it is the one to drop.
//!
//! What is claimed is only that: one error value, with no field and the
//! same `Display` and `Debug` text, for every miss. The database does
//! different work for different misses (an index lookup that finds a row
//! or does not), so no claim is made that a miss takes the same time
//! whatever its cause (inferred: timing is not addressed here).
//!
//! A store failure is [`SelectionError::Store`], with the
//! [`RegistryError`] of the statement or of decoding a row, so a caller can
//! tell "retry" from "deny" and still deny on both. A statement failure
//! does not depend on which selector missed: the statement is the same for
//! every input. A decode failure can only follow a hit, since a miss
//! returns no row, and needs a corrupt row (for example a `valid_until` the
//! registry cannot read). A NUL character in an argument fails the
//! statement with `22021` (`Store`), as everywhere in the registry; the
//! request layer must reject it first (T14.1, T21.1).
//!
//! # Not done here
//!
//! - Verifying the proof (step 2) is the verifier's (T11.x, T22.2, T23.3).
//!   [`Evidence`](crate::policy::Evidence) is the verified claims it will
//!   hand over; nothing here decodes or checks a token.
//! - Step 5 is not done: the current status of the tenant, the actor and
//!   target principals, the source, the grant and the target service (the
//!   status checks of T12.6, T12.7 and T14.2; the grant and source are
//!   enabled when selected, and step 5 checks them again); the grant's
//!   `activation_state` and `valid_until`; the registered audience
//!   assignment; the scope and resource ceilings; and the snapshot of the
//!   policy revision with the selected binding and the other decision
//!   dependencies (T12.6). Wiring all of it into the exchange is M2's
//!   (T21.4, T21.5).
//! - Whether the binding's profile template fits the source (ADR-016
//!   item 4), audit (T20.6) and the mapping of a miss to `invalid_grant`
//!   (ERR-020, the token endpoint's).

use std::{collections::BTreeMap, fmt};

use sqlx::{FromRow, PgExecutor, Row, types::Json};

use crate::policy::EligibleBinding;

use super::{
    GrantMode, RegistryError, ServiceGrant, TrustSource,
    grant::{grant_base_columns, grant_columns},
    micros,
    trust::source_columns,
};

/// The selection statement. `$1` is the tenant, `$2` the grant, `$3` the
/// source and `$4` the expected mode. It returns the grant (`row_kind` 0),
/// the source (1) and each eligible binding (2) as rows of one shape, the
/// columns of the other kinds `NULL`, so the grant and source rows decode
/// with the same code as [`get_service_grant`](super::get_service_grant)
/// and [`get_trust_source`](super::get_trust_source). The grant and the
/// source must be enabled. The final `WHERE EXISTS` gate returns every row
/// only when at least one binding is eligible, and that needs the grant and
/// the source, so every miss returns no row and decodes nothing. The gate
/// is required (see the module docs, "One outcome for every miss").
const SELECT_GRANT: &str = concat!(
    "WITH grant_row AS (SELECT ",
    grant_columns!(),
    " FROM service_grant WHERE tenant_id = $1 AND id = $2 AND mode = $4 AND status = 'enabled'), \
     source_row AS (SELECT ",
    source_columns!(),
    " FROM trust_source WHERE tenant_id = $1 AND id = $3 AND status = 'enabled'), \
     eligible AS (SELECT b.id, b.claim_match_policy, b.revision \
         FROM grant_row g \
         JOIN service_grant_binding l ON l.grant_id = g.id AND l.tenant_id = g.tenant_id \
         JOIN principal_binding b ON b.id = l.binding_id \
         JOIN source_row s ON s.id = b.trust_source_id \
         WHERE b.tenant_id = g.tenant_id \
           AND b.workload_principal_id = g.actor_principal_id \
           AND b.status = 'enabled'), \
     selected AS (\
         SELECT 0 AS row_kind, id, tenant_id, name, status, revision, \
             actor_principal_id, target_service_id, mode, scopes, default_scopes, \
             resource_constraints, max_ttl, valid_until_us, activation_state, \
             allowed_binding_ids, resource_server_ids, \
             NULL::text AS kind, NULL::text AS exact_issuer, NULL::text AS discovery_url, \
             NULL::text AS jwks_keyset_id, NULL::text AS cluster_id, \
             NULL::text AS token_review_endpoint, NULL::text AS ca_bundle_ref, \
             NULL::text AS ca_fingerprint, NULL::text AS reviewer_credential_ref, \
             NULL::integer AS review_timeout_ms, NULL::jsonb AS audiences, \
             NULL::jsonb AS algorithms, NULL::jsonb AS proof_bounds, \
             NULL::text AS assertion_profile, NULL::boolean AS stale_revocation_acknowledged, \
             NULL::text AS replay_mode, NULL::jsonb AS claim_match_policy \
         FROM grant_row \
         UNION ALL \
         SELECT 1, id, tenant_id, name, status, revision, \
             NULL::text, NULL::text, NULL::text, NULL::jsonb, NULL::jsonb, \
             NULL::jsonb, NULL::integer, NULL::bigint, NULL::text, \
             NULL::text[], NULL::text[], \
             kind, exact_issuer, discovery_url, jwks_keyset_id, cluster_id, \
             token_review_endpoint, ca_bundle_ref, ca_fingerprint, reviewer_credential_ref, \
             review_timeout_ms, audiences, algorithms, proof_bounds, \
             assertion_profile, stale_revocation_acknowledged, replay_mode, NULL::jsonb \
         FROM source_row \
         UNION ALL \
         SELECT 2, id, NULL::text, NULL::text, NULL::text, revision, \
             NULL::text, NULL::text, NULL::text, NULL::jsonb, NULL::jsonb, \
             NULL::jsonb, NULL::integer, NULL::bigint, NULL::text, \
             NULL::text[], NULL::text[], \
             NULL::text, NULL::text, NULL::text, NULL::text, NULL::text, \
             NULL::text, NULL::text, NULL::text, NULL::text, \
             NULL::integer, NULL::jsonb, NULL::jsonb, NULL::jsonb, \
             NULL::text, NULL::boolean, NULL::text, claim_match_policy \
         FROM eligible) \
     SELECT * FROM selected WHERE EXISTS (SELECT FROM eligible) \
     ORDER BY row_kind, id COLLATE \"C\""
);

/// A grant selected by [`select_grant`], with the source and the grant's
/// eligible bindings. The grant and source are untrusted candidates,
/// enabled when selected: every step 5 check, their current status
/// included, is still to be done.
#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    /// The grant, of the selector's tenant and the expected mode, with its
    /// allowed bindings and audiences, enabled when selected.
    pub grant: ServiceGrant,
    /// The source, of the grant's tenant, enabled when selected.
    pub source: TrustSource,
    /// The grant's eligible bindings for the source, sorted by ID
    /// byte-wise; never empty.
    pub eligible_bindings: Vec<EligibleBinding>,
}

/// Why [`select_grant`] selected nothing.
#[derive(Debug)]
pub enum SelectionError {
    /// No grant can be selected with these selectors, whatever the reason;
    /// one value with no detail (ERR-020).
    NotSelectable,
    /// The statement failed: [`RegistryError::Retry`] means retry the whole
    /// transaction, anything else is a store failure. Either way nothing
    /// was selected.
    Store(RegistryError),
}

/// `NotSelectable` equals itself. A `Store` error equals nothing, itself
/// included, since a database error has no equality.
impl PartialEq for SelectionError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Self::NotSelectable, Self::NotSelectable))
    }
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSelectable => f.write_str("no grant can be selected"),
            Self::Store(err) => write!(f, "grant selection failed: {err}"),
        }
    }
}

impl std::error::Error for SelectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotSelectable => None,
            Self::Store(err) => Some(err),
        }
    }
}

impl From<RegistryError> for SelectionError {
    fn from(err: RegistryError) -> Self {
        Self::Store(err)
    }
}

impl From<sqlx::Error> for SelectionError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

/// Selects grant `grant_id` of `tenant_id` in `expected_mode` for source
/// `source_id`, with the grant's eligible bindings, in one statement (see
/// the module docs). Every miss is [`SelectionError::NotSelectable`].
pub async fn select_grant<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    source_id: &str,
    expected_mode: GrantMode,
) -> Result<Selection, SelectionError> {
    let rows = sqlx::query(SELECT_GRANT)
        .bind(tenant_id)
        .bind(grant_id)
        .bind(source_id)
        .bind(expected_mode.as_str())
        .fetch_all(executor)
        .await?;
    let mut grant = None;
    let mut source = None;
    let mut eligible_bindings = Vec::new();
    for row in &rows {
        match row.try_get::<i32, _>("row_kind")? {
            0 => grant = Some(ServiceGrant::from_row(row)?),
            1 => source = Some(TrustSource::from_row(row)?),
            _ => eligible_bindings.push(EligibleBinding {
                id: row.try_get("id")?,
                claim_match_policy: row
                    .try_get::<Json<BTreeMap<String, String>>, _>("claim_match_policy")?
                    .0,
                revision: row.try_get("revision")?,
            }),
        }
    }
    // The statement's `WHERE EXISTS` gate already returns no row unless a
    // binding is eligible, and it is the required check (a miss must decode
    // nothing). This guard is defense in depth: the one to drop if either
    // ever goes.
    match (grant, source) {
        (Some(grant), Some(source)) if !eligible_bindings.is_empty() => Ok(Selection {
            grant,
            source,
            eligible_bindings,
        }),
        _ => Err(SelectionError::NotSelectable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_selectable_has_one_text_and_equals_only_itself() {
        let err = SelectionError::NotSelectable;
        assert_eq!(err, SelectionError::NotSelectable);
        assert_eq!(err.to_string(), "no grant can be selected");
        assert_eq!(format!("{err:?}"), "NotSelectable");
        let store = SelectionError::from(sqlx::Error::RowNotFound);
        assert_ne!(store, SelectionError::NotSelectable);
        assert_ne!(store, SelectionError::from(sqlx::Error::RowNotFound));
    }
}
