//! Shared fixture of the service-grant lifecycle scenarios A38 and A53: one
//! tenant with a grant's references, grant records built from a mode,
//! status and activation state, and the assertions both scenarios make
//! through the typed registry API (`skyoauth_service::persistence::registry`).
//! Not a scenario: it holds no test.
//!
//! The refusal cases are listed once, in [`CREATE_REFUSALS`] and
//! [`UPDATE_REFUSALS`], with the `0004` check that reports each. A write
//! that breaks both checks is reported by
//! `service_grant_activation_mode_check`: PostgreSQL tests a table's
//! `CHECK` constraints in alphabetical order by name (documented under
//! `CREATE TABLE` since 9.5) and reports the first one that fails.

use std::fmt::Debug;

use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, ActivationState, AssertionProfile, BindingProfile, GrantMode, InvariantKind,
        JsonObject, MAX_PAGE_SIZE, NewPrincipal, NewPrincipalBinding, NewServiceGrant,
        NewServiceIdentity, NewTenant, NewTrustSource, Page, PrincipalKind, RegistryError,
        ReplayMode, ServiceGrant, ServiceGrantChanges, Status, TrustSourceKind,
    },
};

pub(super) const TENANT: &str = "ten_a";
/// The grant's workload actor.
const ACTOR: &str = "wld_a";
/// The actor's binding, the grant's one allowed binding.
const BINDING: &str = "bnd_a";
/// The service principal and identity a delegation or impersonation grant
/// targets.
const SERVICE: &str = "svc_a";

/// Allows impersonation only while disabled: `CHECK (mode <> 'impersonation'
/// OR status = 'disabled')`.
pub(super) const IMPERSONATION_DISABLED: &str = "service_grant_impersonation_disabled_check";
/// Ties `requires_reapproval` to impersonation, both ways: `CHECK
/// ((activation_state = 'requires_reapproval') = (mode = 'impersonation'))`.
pub(super) const ACTIVATION_MODE: &str = "service_grant_activation_mode_check";

/// Impersonation creates refused: (status, activation state, the check that
/// reports it). "Approved" is `not_required` (inferred, see the A53 module).
pub(super) const CREATE_REFUSALS: [(Status, ActivationState, &str); 3] = [
    // Enabled.
    (
        Status::Enabled,
        ActivationState::RequiresReapproval,
        IMPERSONATION_DISABLED,
    ),
    // Approved.
    (
        Status::Disabled,
        ActivationState::NotRequired,
        ACTIVATION_MODE,
    ),
    // Enabled and approved: both checks fail; the first by name is reported.
    (
        Status::Enabled,
        ActivationState::NotRequired,
        ACTIVATION_MODE,
    ),
];

/// Updates of a dormant impersonation grant refused, in the same form.
pub(super) const UPDATE_REFUSALS: [(Status, ActivationState, &str); 3] = [
    // Enabling, reapproval marker kept.
    (
        Status::Enabled,
        ActivationState::RequiresReapproval,
        IMPERSONATION_DISABLED,
    ),
    // Clearing the reapproval marker, still disabled.
    (
        Status::Disabled,
        ActivationState::NotRequired,
        ACTIVATION_MODE,
    ),
    // Both: the first failing check by name is reported.
    (
        Status::Enabled,
        ActivationState::NotRequired,
        ACTIVATION_MODE,
    ),
];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// A fresh database with one tenant holding a workload actor with a
/// binding (on a GitHub source) and a service principal with a service
/// identity: everything a grant of any mode refers to.
pub(super) async fn tenant() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    registry::create_tenant(
        &pool,
        &NewTenant {
            id: TENANT.into(),
            name: "Example".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (id, kind, name) in [
        (ACTOR, PrincipalKind::Workload, "ci"),
        (SERVICE, PrincipalKind::Service, "deploy-api"),
    ] {
        registry::create_principal(
            &pool,
            &NewPrincipal {
                id: id.into(),
                tenant_id: TENANT.into(),
                kind,
                name: name.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    let issuer = "https://token.actions.githubusercontent.com";
    registry::create_trust_source(
        &pool,
        &NewTrustSource {
            id: "src_a".into(),
            tenant_id: TENANT.into(),
            name: "github".into(),
            kind: TrustSourceKind::OidcDiscovery,
            exact_issuer: issuer.into(),
            discovery_url: Some(format!("{issuer}/.well-known/openid-configuration")),
            jwks_keyset_id: None,
            cluster_id: None,
            token_review_endpoint: None,
            ca_bundle_ref: None,
            ca_fingerprint: None,
            reviewer_credential_ref: None,
            review_timeout_ms: None,
            audiences: strings(&["https://skyoauth.example"]),
            algorithms: Some(strings(&["RS256"])),
            proof_bounds: JsonObject::new(),
            assertion_profile: AssertionProfile::ReusableJwt,
            stale_revocation_acknowledged: None,
            replay_mode: ReplayMode::Reusable,
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::create_principal_binding(
        &pool,
        &NewPrincipalBinding {
            id: BINDING.into(),
            tenant_id: TENANT.into(),
            name: "release".into(),
            trust_source_id: "src_a".into(),
            profile: BindingProfile::GithubProduction,
            claim_match_policy: [("repository".to_string(), "example/release".to_string())].into(),
            workload_principal_id: ACTOR.into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::create_service_identity(
        &pool,
        &NewServiceIdentity {
            id: SERVICE.into(),
            tenant_id: TENANT.into(),
            name: "deploy-api".into(),
            max_scopes: strings(&["read"]),
            max_resource_constraints: JsonObject::new(),
            resource_server_ids: vec![],
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    (db, pool)
}

/// A grant `id` of the fixture's actor with its one binding; a delegation
/// or impersonation grant targets the fixture's service.
pub(super) fn grant(
    id: &str,
    mode: GrantMode,
    status: Status,
    activation_state: ActivationState,
) -> NewServiceGrant {
    NewServiceGrant {
        id: id.into(),
        tenant_id: TENANT.into(),
        name: id.into(),
        actor_principal_id: ACTOR.into(),
        target_service_id: (mode != GrantMode::Direct).then(|| SERVICE.into()),
        mode,
        scopes: strings(&["read"]),
        default_scopes: Some(strings(&["read"])),
        resource_constraints: JsonObject::new(),
        max_ttl: 300,
        valid_until: None,
        status,
        activation_state,
        allowed_binding_ids: vec![BINDING.into()],
        resource_server_ids: vec![],
    }
}

/// The dormant impersonation record: disabled and requiring reapproval.
pub(super) fn dormant(id: &str) -> NewServiceGrant {
    grant(
        id,
        GrantMode::Impersonation,
        Status::Disabled,
        ActivationState::RequiresReapproval,
    )
}

/// The record `new` describes, at `revision`.
fn record(new: &NewServiceGrant, revision: i64) -> ServiceGrant {
    ServiceGrant {
        id: new.id.clone(),
        tenant_id: new.tenant_id.clone(),
        name: new.name.clone(),
        actor_principal_id: new.actor_principal_id.clone(),
        target_service_id: new.target_service_id.clone(),
        mode: new.mode,
        scopes: new.scopes.clone(),
        default_scopes: new.default_scopes.clone(),
        resource_constraints: new.resource_constraints.clone(),
        max_ttl: new.max_ttl,
        valid_until: new.valid_until,
        status: new.status,
        activation_state: new.activation_state,
        allowed_binding_ids: new.allowed_binding_ids.clone(),
        resource_server_ids: new.resource_server_ids.clone(),
        revision,
    }
}

/// The mutable columns of `grant` as they are, with `status` and
/// `activation_state` replaced.
pub(super) fn changes(
    grant: &ServiceGrant,
    status: Status,
    activation_state: ActivationState,
) -> ServiceGrantChanges {
    ServiceGrantChanges {
        name: grant.name.clone(),
        scopes: grant.scopes.clone(),
        default_scopes: grant.default_scopes.clone(),
        resource_constraints: grant.resource_constraints.clone(),
        max_ttl: grant.max_ttl,
        valid_until: grant.valid_until,
        status,
        activation_state,
    }
}

/// The tenant's grant `id` as listed, if it is.
async fn listed(pool: &PgPool, id: &str) -> Option<ServiceGrant> {
    registry::list_service_grants(pool, TENANT, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap()
        .into_iter()
        .find(|grant| grant.id == id)
}

/// Creates `new` and checks that the registry stored exactly it at
/// revision 1: the created record, the read and the listed one all equal
/// the record `new` describes.
pub(super) async fn assert_stored(pool: &PgPool, new: &NewServiceGrant) -> ServiceGrant {
    let want = record(new, 1);
    let created = registry::create_service_grant(pool, new).await.unwrap();
    assert_eq!(created, want);
    assert_eq!(created.revision, 1);
    assert_eq!(
        registry::get_service_grant(pool, TENANT, &new.id)
            .await
            .unwrap(),
        want
    );
    assert_eq!(listed(pool, &new.id).await, Some(want.clone()));
    want
}

/// The refusal of a `0004` table check named `constraint`.
#[track_caller]
pub(super) fn assert_check<T: Debug>(result: Result<T, RegistryError>, constraint: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::Check,
            constraint: Some(actual),
        }) => assert_eq!(actual, constraint),
        other => panic!("expected Invariant {{ Check, {constraint} }}: {other:?}"),
    }
}

/// Creating `new` is refused by `constraint`, and nothing is stored: the
/// grant is neither found nor listed.
pub(super) async fn assert_create_refused(pool: &PgPool, new: &NewServiceGrant, constraint: &str) {
    assert_check(registry::create_service_grant(pool, new).await, constraint);
    let read = registry::get_service_grant(pool, TENANT, &new.id).await;
    assert!(matches!(read, Err(RegistryError::NotFound)), "{read:?}");
    assert_eq!(listed(pool, &new.id).await, None);
}

/// Updating `grant` at its revision to `status` and `activation_state` is
/// refused by `constraint`, and the stored record, revision included, is
/// still exactly `grant`.
pub(super) async fn assert_update_refused(
    pool: &PgPool,
    grant: &ServiceGrant,
    status: Status,
    activation_state: ActivationState,
    constraint: &str,
) {
    assert_check(
        registry::update_service_grant(
            pool,
            TENANT,
            &grant.id,
            grant.revision,
            &changes(grant, status, activation_state),
        )
        .await,
        constraint,
    );
    assert_unchanged(pool, grant).await;
}

/// The stored record is still exactly `grant`, at its revision.
pub(super) async fn assert_unchanged(pool: &PgPool, grant: &ServiceGrant) {
    let read = registry::get_service_grant(pool, TENANT, &grant.id)
        .await
        .unwrap();
    assert_eq!(read.revision, grant.revision);
    assert_eq!(&read, grant);
}
