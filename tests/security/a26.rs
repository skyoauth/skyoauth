//! A26: scope omitted with or without defaults, empty or excessive scopes.
//! Expected: narrow explicit defaults or `invalid_scope`, never the full
//! ceiling by omission (tasks §8; T12.8, T21.5; identity-registry IR-062,
//! IR-063, IR-066; ADR-015 items 7 and 9; errors-retry ERR-024; design
//! §5.7).
//!
//! **A26 partial: the registry and policy slice only; A26 M1a stays
//! planned (scope "policy").** These tests are registered on A26's planned
//! M1a stage, so they are no evidence for it: the reporter lists their
//! results as not counted, and they are no claim. They run through the
//! public API of `skyoauth_service` against a real PostgreSQL, one fresh
//! database per test, with no SQL of their own: the registry writes and
//! reads (`skyoauth_service::persistence::registry`; the trust source
//! setup goes through its `#[doc(hidden)]` `test_support` module, which
//! only the `test-support` feature compiles and this package's test
//! targets turn on), the ceiling loader
//! [`load_scope_ceilings`] and the pure scope decision
//! [`resolve_scopes`] (`skyoauth_service::policy`), which the loader feeds
//! through [`LoadedCeilings::default_scopes`] and
//! [`LoadedCeilings::scope_ceilings`]. A [`ScopeError::Invalid`] is what
//! the token endpoint is to map to `invalid_scope`; no test here sees that
//! wire code.
//!
//! The fixture is local ([`fixture`]): tenants `ten_a` and `ten_b` share
//! one resource server, `rs_api`, each by its own assignment with its own
//! scope ceiling. Each of `admin`, `audit`, `logs:read` and `deploy:write`
//! lies outside exactly one ceiling of `grt_direct` and `grt_dlg`
//! (`deploy:write` for the delegation only), so a check that skipped any
//! one ceiling lets one of them through:
//!
//! | scope          | `rs_api` | `ata_a` | `ata_b` | grants of `ten_a` | `svc_a` |
//! | -------------- | -------- | ------- | ------- | ----------------- | ------- |
//! | `read`         | yes      | yes     | yes     | yes               | yes     |
//! | `deploy:write` | yes      | yes     | no      | yes               | **no**  |
//! | `admin`        | yes      | **no**  | yes     | yes               | yes     |
//! | `audit`        | **no**   | yes     | no      | yes               | yes     |
//! | `logs:read`    | yes      | yes     | no      | **no**            | yes     |
//!
//! `ten_a`'s grants (`grt_direct`, `grt_dlg` with the target service
//! `svc_a`, both with the defaults `read`) can therefore carry `read` and
//! `deploy:write` directly and only `read` by delegation. `grt_none`
//! (`read`, `deploy:write`) has no defaults. `ten_b`'s grant `grt_b`
//! (`read`, `admin`; defaults `admin`) can carry `admin`, which `ten_a`'s
//! assignment does not allow.
//!
//! - **Positive.** An omitted scope resolves to exactly the grant's stored
//!   explicit defaults, sorted byte-wise, and not to the wider ceiling that
//!   an explicit request may still reach; the loaded ceilings are exactly
//!   the registry's rows (the grant, the resource server, the tenant's own
//!   assignment and, for the delegation only, the target service, each
//!   with its ID, status and revision); defaults changed through
//!   `update_service_grant` apply from the next load, in both tenants
//!   (`a26_pos_omitted_scope_resolves_to_the_stored_explicit_defaults`).
//! - **Negative, no defaults.** A grant stored without defaults, or whose
//!   defaults were cleared, resolves an omitted scope to
//!   [`ScopeError::Invalid`], although its own scopes and the intersection
//!   of its ceilings would resolve if asked for: neither is a fallback
//!   (`a26_neg_omitted_scope_without_defaults_is_invalid_scope`).
//! - **Negative, refused at write.** The registry refuses empty defaults
//!   and defaults outside the grant's own `scopes`, on create and on
//!   update, and a `scopes` update that leaves a default outside, each by
//!   `Invariant { Check, service_grant_default_scopes_check }`; malformed
//!   tokens by `Invariant { Check, skyoauth_scope_list_check }`. Compared
//!   by variant, kind and constraint, never by message text. Each refusal
//!   writes nothing (`a26_neg_empty_or_out_of_grant_defaults_are_refused_at_write`).
//! - **Negative, explicit scope.** An explicit empty list (also for a grant
//!   with defaults), a scope outside each ceiling in turn, alone or next to
//!   an allowed one (denied, not trimmed), an unknown scope and a case or
//!   lookalike variant of an allowed one each resolve to
//!   [`ScopeError::Invalid`]; the target service's `max_scopes` bounds the
//!   delegation only. Tokens outside the RFC 6749 `scope-token` grammar
//!   resolve to it too, but only because no ceiling contains them:
//!   `skyoauth_scope_list_check` keeps them out of every stored ceiling, so
//!   these tests cannot tell the policy's grammar check from its ceiling
//!   check. The grammar check itself is pinned only by the unit tests of
//!   `policy::scope`
//!   (`a26_neg_explicit_empty_or_excessive_scope_is_invalid_scope`).
//! - **Negative, shrunken ceiling.** Defaults that a ceiling other than
//!   the grant's own no longer contains (the assignment, the resource
//!   server, the target service, each narrowed through its registry
//!   update) resolve to [`ScopeError::Invalid`], not to what is left of
//!   them; restoring the ceiling restores them. The registry stores
//!   defaults outside those ceilings, since it checks only the grant's own
//!   `scopes` (`0004`: "the other ceilings can change later, so the service
//!   checks them"); such a grant's omitted scope is then invalid from the
//!   start (`a26_neg_defaults_outside_a_narrowed_ceiling_are_invalid_not_trimmed`).
//! - **Negative, tenants.** The other tenant's assignment of the same
//!   audience never applies: `ten_a`'s grant cannot carry `admin`, which
//!   only `ten_b`'s assignment allows, a grant loads under its own tenant
//!   only, and widening `ten_b`'s assignment leaves `ten_a`'s loaded
//!   ceilings and decisions unchanged, and narrowing `ten_a`'s leaves
//!   `ten_b`'s (`a26_neg_other_tenants_ceilings_never_apply`).
//! - **Negative, uncommitted writes.** Inside a transaction, a widened
//!   assignment and widened defaults resolve for that transaction only;
//!   outside it, and after its rollback, the committed ceilings and
//!   defaults apply unchanged. A narrowing applies only once committed
//!   (`a26_neg_uncommitted_ceiling_changes_never_apply`). The loader takes
//!   no lock, so nothing here waits; each load outside the transaction is
//!   bounded by a 10 s deadline, so a loader that took a lock fails the
//!   test instead of hanging it.
//!
//! # Spec and registry picks
//!
//! The spec's rules these tests pin: an omitted WIF scope uses only the
//! grant's explicit nonempty `default_scopes`, a subset of every applicable
//! ceiling, otherwise `invalid_scope`; explicit empty or excessive scopes
//! are denied, not trimmed or widened (IR-063; ADR-015 item 7; design
//! §5.7; T12.8); the ceilings of a direct grant are the resource server's
//! `scopes`, the assignment's `allowed_scopes` and the grant's `scopes`,
//! and a delegation adds the target service's `max_scopes` (IR-062); and
//! scope tokens are case-sensitive (IR-066). IR-066's `scope-token` grammar
//! is pinned here only at write, where the registry refuses a malformed
//! default (`skyoauth_scope_list_check`); a malformed request token is
//! refused by the ceilings too (see the explicit-scope negative).
//!
//! Defaults equal to the whole ceiling intersection are accepted and
//! resolve (the delegation's `read`): IR-063 requires defaults that are
//! explicit, nonempty and within every ceiling, and tasks §8's "narrow" is
//! read as "never the full ceiling by omission", not "strictly narrower".
//! Provisional.
//!
//! These are the registry's or the policy module's behaviour, not the
//! spec's, where the spec does not define them: that the result is sorted
//! byte-wise (IR-060's canonical order, inferred for this surface in
//! `policy::scope`); that every scope failure is the one
//! [`ScopeError::Invalid`] with no detail; that the registry refuses empty
//! defaults and defaults outside the grant's own `scopes` at write
//! (`service_grant_default_scopes_check`, `0004`), while the spec requires
//! the subset only at issuance; and that it accepts defaults outside the
//! other ceilings. That last pick is provisional:
//! `service/migrations/README.md` ("What 0004 adds", the list "The database
//! does not enforce these rules; the service must", line 579 at this
//! commit) leaves keeping `default_scopes` and `scopes` within every other
//! ceiling to the service. A later write-time check in the registry, or a
//! typed refusal, would change the last block of
//! `a26_neg_defaults_outside_a_narrowed_ceiling_are_invalid_not_trimmed`;
//! a check above the registry would not turn it red, since the test calls
//! the registry directly.
//!
//! **Missing, so not a claim.** A26 M1a needs its row through the
//! in-process service (UC); these tests reach only the registry and the
//! pure policy function below it. Still needed, with the owner of each
//! part:
//!
//! - The token endpoint calling the loader and [`resolve_scopes`] for a
//!   WIF exchange, and mapping [`ScopeError::Invalid`] to the wire
//!   `invalid_scope`, after `invalid_request`, `invalid_grant` and an
//!   audience `invalid_target` (ERR-024; ADR-015 item 9; the scope check
//!   after the audience check is inferred: the ceilings need the audience's
//!   resource server): A26's M2 stage, "exchange" (T21.5; T21.2 for the
//!   OAuth-shaped error).
//! - The issued credential carrying exactly the resolved, explicit scope
//!   (IR-061): A26's M2 stage.
//! - The request layer that turns the `scope` parameter into tokens: an
//!   absent parameter versus an empty one (T21.1, A26's M2 stage), and
//!   repeated tokens inside one `scope` value, which [`resolve_scopes`]
//!   tolerates following a lead lean on OQ-IR-11 (open; not pinned here).
//! - The wire code for a request token outside the `scope-token` grammar
//!   is undecided: `invalid_request` (malformed input) or `invalid_scope`
//!   (T21.1).
//! - In the tasks only, not in A26's row: the decision recording the
//!   ceilings' revisions (T12.6, T21.5) and a duplicated `scope` parameter
//!   (T21.1).
//! - The rest of the row's negative, tagged M2 in the registry: any
//!   `resource` parameter and an audience not in the grant's set or not
//!   assigned give `invalid_target` (the loader's `None`; the service
//!   tests pin it at the registry level), and an unsupported
//!   `requested_token_type` gives `invalid_request`: A26's M2 stage (T21.1,
//!   T21.5).
//! - The status part of design §5.7 step 5: the loader returns disabled
//!   records and [`LoadedCeilings::all_enabled`] reports them, but which
//!   status denies, and the tenant's status, the grant's
//!   `activation_state` and `valid_until` (not loaded), belong to T12.6,
//!   T12.7 and T14.2, wired into the exchange in M2 (T21.4, T21.5); a
//!   disable with outstanding credentials is A21.
//! - T12.8's "profile/mode mismatch denies" is not a scope ceiling and is
//!   credited elsewhere. A grant of the wrong mode is A25's (T12.3, T12.8):
//!   `select_grant` with the request's expected mode gives
//!   `NotSelectable`, the uniform `invalid_grant` at A25's M2 stage
//!   (ADR-006; OQ-ERR-3). Proof parameters that do not fit the grant type
//!   are request shape, `invalid_request`, checked before the grant is
//!   loaded (ADR-015 item 9.2; T21.1). Reading "profile" as the `wif`
//!   credential profile is the `allowed_profiles` question below. "Direct
//!   grants have no service target" is the `0004` check
//!   `service_grant_target_mode_check`, pinned by the service tests, and
//!   here only as a direct grant loading no target service.
//!
//! Not A26's: resource constraint ceilings (IR-123) and TTL caps, which
//! the loader does not load; human scopes and native refresh (IR-062's
//! human rows, IR-064); the fuzzing of T21.7.
//!
//! Not A26's; owner to be ruled: the `wif` profile in the resource
//! server's and the assignment's `allowed_profiles`, which
//! `load_scope_ceilings` does not load and nothing checks. Provisional
//! assignment: issuance-time enforcement at T21.5 (design §5.7 step 5),
//! T14.2 for the assignment; no registry row yet.
//!
//! # Overlap
//!
//! `service/tests/registry_ceilings.rs` covers the loader against a seed
//! written in SQL: the loaded values against the getters, every miss as the
//! same `None` (including an audience the target service does not list,
//! IR-083), the statement's re-check of what the foreign keys guarantee,
//! disabled records and `all_enabled`, and the A26 cases on loaded
//! ceilings, with ceilings shrunk by SQL `UPDATE`s. The unit tests of
//! `policy::scope` cover [`resolve_scopes`] on built ceilings, the token
//! grammar and the no-detail error text. The schema and registry service
//! tests (`schema_trust_binding_grant.rs`, `registry_trust.rs`) cover the
//! default-scope and scope-list checks. This module adds the same policy
//! through registry writes only, both tenants on one audience, the
//! registry's refusals next to the policy's, and transactions.

use std::{fmt::Debug, time::Duration};

use skyoauth_scenarios::{egress, pg::TestDb};
use skyoauth_service::{
    persistence::{
        PgPool,
        registry::{
            self, ActivationState, AssertionProfile, AudienceTenantAssignmentChanges,
            BindingProfile, CeilingRecord, GrantMode, InvariantKind, JsonObject, LoadedCeilings,
            MAX_PAGE_SIZE, NewAudienceTenantAssignment, NewPrincipal, NewPrincipalBinding,
            NewResourceServer, NewServiceGrant, NewServiceIdentity, NewTenant, NewTrustSource,
            Page, PrincipalKind, Profile, RegistryError, ReplayMode, ResourceServerChanges,
            ServiceGrant, ServiceGrantChanges, ServiceIdentityChanges, Status, TrustSourceKind,
            load_scope_ceilings,
        },
    },
    policy::{ScopeError, ScopeRequest, resolve_scopes},
};
use sqlx::PgExecutor;

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

const TEN_A: &str = "ten_a";
const TEN_B: &str = "ten_b";

/// The resource server both tenants are assigned.
const RS: &str = "rs_api";
const AUDIENCE: &str = "https://api.example";
const RS_SCOPES: [&str; 4] = ["read", "deploy:write", "admin", "logs:read"];

/// `ten_a`'s assignment of [`RS`]: no `admin`.
const ATA_A: &str = "ata_a";
const ATA_A_SCOPES: [&str; 4] = ["read", "deploy:write", "audit", "logs:read"];
/// `ten_b`'s assignment of [`RS`]: `admin`.
const ATA_B: &str = "ata_b";
const ATA_B_SCOPES: [&str; 2] = ["read", "admin"];

/// `ten_a`'s service identity, the target of [`DLG`]: no `deploy:write`.
const SVC_A: &str = "svc_a";
const SVC_A_SCOPES: [&str; 4] = ["read", "admin", "audit", "logs:read"];

/// The scopes of `ten_a`'s grants with defaults: no `logs:read`.
const GRANT_SCOPES: [&str; 4] = ["read", "deploy:write", "admin", "audit"];
/// `ten_a`'s direct grant, defaults `read`.
const DIRECT: &str = "grt_direct";
/// `ten_a`'s delegation to [`SVC_A`], defaults `read`.
const DLG: &str = "grt_dlg";
/// `ten_a`'s direct grant without defaults, with the scopes `read` and
/// `deploy:write`: exactly the intersection of its ceilings.
const NONE: &str = "grt_none";
/// `ten_b`'s direct grant, scopes `read` and `admin`, defaults `admin`.
const GRT_B: &str = "grt_b";

/// Each scope outside exactly one ceiling of [`DIRECT`] and [`DLG`]
/// (module docs), with whether it is outside for the direct grant too:
/// only the target service's `max_scopes` is a delegation-only ceiling.
const EXCESSIVE: [(&str, &str, bool); 4] = [
    ("admin", "the assignment", true),
    ("audit", "the resource server", true),
    ("logs:read", "the grant", true),
    ("deploy:write", "the target service", false),
];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn explicit(values: &[&str]) -> ScopeRequest {
    ScopeRequest::Explicit(strings(values))
}

fn tenant(id: &str, namespace: &str) -> NewTenant {
    NewTenant {
        id: id.into(),
        name: "Example".into(),
        secret_namespace: namespace.into(),
        status: Status::Enabled,
    }
}

fn principal(tenant: &str, id: &str, kind: PrincipalKind, name: &str) -> NewPrincipal {
    NewPrincipal {
        id: id.into(),
        tenant_id: tenant.into(),
        kind,
        name: name.into(),
        status: Status::Enabled,
    }
}

fn github_source(tenant: &str, id: &str) -> NewTrustSource {
    NewTrustSource {
        id: id.into(),
        tenant_id: tenant.into(),
        name: "github".into(),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: GITHUB_ISSUER.into(),
        discovery_url: Some(format!("{GITHUB_ISSUER}/.well-known/openid-configuration")),
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
    }
}

fn binding(tenant: &str, id: &str, source: &str, workload: &str) -> NewPrincipalBinding {
    NewPrincipalBinding {
        id: id.into(),
        tenant_id: tenant.into(),
        name: "release".into(),
        trust_source_id: source.into(),
        profile: BindingProfile::GithubProduction,
        claim_match_policy: super::grant_fixture::github_policy(),
        workload_principal_id: workload.into(),
        status: Status::Enabled,
    }
}

fn assignment(id: &str, tenant: &str, scopes: &[&str]) -> NewAudienceTenantAssignment {
    NewAudienceTenantAssignment {
        id: id.into(),
        resource_server_id: RS.into(),
        tenant_id: tenant.into(),
        allowed_profiles: vec![Profile::Wif],
        allowed_scopes: strings(scopes),
        constraint_versions: vec![],
        status: Status::Enabled,
    }
}

/// A grant of `ten_a`'s workload on [`RS`]: a delegation to [`SVC_A`] when
/// `delegation`, otherwise direct.
fn grant_a(
    id: &str,
    delegation: bool,
    scopes: &[&str],
    defaults: Option<&[&str]>,
) -> NewServiceGrant {
    NewServiceGrant {
        id: id.into(),
        tenant_id: TEN_A.into(),
        name: id.into(),
        actor_principal_id: "wld_a".into(),
        target_service_id: delegation.then(|| SVC_A.into()),
        mode: if delegation {
            GrantMode::Delegation
        } else {
            GrantMode::Direct
        },
        scopes: strings(scopes),
        default_scopes: defaults.map(strings),
        resource_constraints: JsonObject::new(),
        max_ttl: 300,
        valid_until: None,
        status: Status::Enabled,
        activation_state: ActivationState::NotRequired,
        allowed_binding_ids: strings(&["bnd_a"]),
        resource_server_ids: strings(&[RS]),
    }
}

/// The fixture of the module docs, written through the registry API only.
async fn fixture() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for (id, namespace) in [(TEN_A, "ns_a"), (TEN_B, "ns_b")] {
        registry::create_tenant(&pool, &tenant(id, namespace))
            .await
            .unwrap();
    }
    for (tenant, id, kind, name) in [
        (TEN_A, "wld_a", PrincipalKind::Workload, "ci"),
        (TEN_A, SVC_A, PrincipalKind::Service, "deploy-api"),
        (TEN_B, "wld_b", PrincipalKind::Workload, "ci"),
    ] {
        registry::create_principal(&pool, &principal(tenant, id, kind, name))
            .await
            .unwrap();
    }
    for (tenant, source, binding_id, workload) in [
        (TEN_A, "src_a", "bnd_a", "wld_a"),
        (TEN_B, "src_b", "bnd_b", "wld_b"),
    ] {
        let new = github_source(tenant, source);
        egress::allow_destinations(&pool, &new).await;
        registry::test_support::create_trust_source(&pool, &new)
            .await
            .unwrap();
        registry::create_principal_binding(&pool, &binding(tenant, binding_id, source, workload))
            .await
            .unwrap();
    }
    registry::create_resource_server(
        &pool,
        &NewResourceServer {
            id: RS.into(),
            audience: AUDIENCE.into(),
            name: "API".into(),
            allowed_profiles: vec![Profile::Wif],
            scopes: strings(&RS_SCOPES),
            constraint_versions: vec![],
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for new in [
        assignment(ATA_A, TEN_A, &ATA_A_SCOPES),
        assignment(ATA_B, TEN_B, &ATA_B_SCOPES),
    ] {
        registry::create_audience_tenant_assignment(&pool, &new)
            .await
            .unwrap();
    }
    registry::create_service_identity(
        &pool,
        &NewServiceIdentity {
            id: SVC_A.into(),
            tenant_id: TEN_A.into(),
            name: "deploy-api".into(),
            max_scopes: strings(&SVC_A_SCOPES),
            max_resource_constraints: JsonObject::new(),
            resource_server_ids: strings(&[RS]),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for new in [
        grant_a(DIRECT, false, &GRANT_SCOPES, Some(&["read"])),
        grant_a(DLG, true, &GRANT_SCOPES, Some(&["read"])),
        grant_a(NONE, false, &["read", "deploy:write"], None),
        NewServiceGrant {
            id: GRT_B.into(),
            tenant_id: TEN_B.into(),
            actor_principal_id: "wld_b".into(),
            scopes: strings(&["read", "admin"]),
            default_scopes: Some(strings(&["admin"])),
            allowed_binding_ids: strings(&["bnd_b"]),
            ..grant_a(GRT_B, false, &[], None)
        },
    ] {
        registry::create_service_grant(&pool, &new).await.unwrap();
    }
    (db, pool)
}

/// The tenant's assignment of [`RS`].
fn own_assignment(tenant: &str) -> &'static str {
    match tenant {
        TEN_A => ATA_A,
        TEN_B => ATA_B,
        other => panic!("no assignment for {other}"),
    }
}

/// The ceilings of `grant` of `tenant` for [`AUDIENCE`], which must load.
async fn load<'e>(executor: impl PgExecutor<'e>, tenant: &str, grant: &str) -> LoadedCeilings {
    load_scope_ceilings(executor, tenant, grant, AUDIENCE)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no ceilings for {tenant} {grant}"))
}

/// How long a load outside a transaction that holds uncommitted writes may
/// take. The loader takes no lock, so it never waits for that transaction;
/// one that did would hang the test without this bound.
const OUTSIDE_DEADLINE: Duration = Duration::from_secs(10);

/// [`load`] of `ten_a`'s `grant` through `pool`, bounded by
/// [`OUTSIDE_DEADLINE`].
async fn load_outside(pool: &PgPool, grant: &str) -> LoadedCeilings {
    tokio::time::timeout(OUTSIDE_DEADLINE, load(pool, TEN_A, grant))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "loading {grant} outside the transaction waited {OUTSIDE_DEADLINE:?} for its \
                 uncommitted writes: the loader must take no lock"
            )
        })
}

/// The decision for `request` on `loaded`.
fn decide(loaded: &LoadedCeilings, request: &ScopeRequest) -> Result<Vec<String>, ScopeError> {
    resolve_scopes(request, loaded.default_scopes(), &loaded.scope_ceilings())
}

/// The decision for `request` on the ceilings of `grant` of `tenant` as
/// committed now.
async fn resolve(
    pool: &PgPool,
    tenant: &str,
    grant: &str,
    request: &ScopeRequest,
) -> Result<Vec<String>, ScopeError> {
    decide(&load(pool, tenant, grant).await, request)
}

/// The ceilings the registry's getters give for `grant` of `tenant`: the
/// grant, [`RS`], the tenant's own assignment and, for a delegation or
/// impersonation grant, its target service.
async fn from_getters(pool: &PgPool, tenant: &str, grant: &str) -> LoadedCeilings {
    let grant = registry::get_service_grant(pool, tenant, grant)
        .await
        .unwrap();
    let server = registry::get_resource_server(pool, RS).await.unwrap();
    let assignment = registry::get_audience_tenant_assignment(pool, own_assignment(tenant))
        .await
        .unwrap();
    assert_eq!(assignment.tenant_id, tenant);
    // The target service is keyed off the grant's mode, as the loader keys
    // it: only a delegation or impersonation grant has one, and a direct
    // grant has none whatever `target_service_id` holds.
    let target_service = match grant.mode {
        GrantMode::Delegation | GrantMode::Impersonation => {
            let id = grant
                .target_service_id
                .as_deref()
                .expect("a delegation or impersonation grant names its target (`0004`)");
            let service = registry::get_service_identity(pool, tenant, id)
                .await
                .unwrap();
            Some(CeilingRecord {
                id: service.id,
                status: service.status,
                revision: service.revision,
                scopes: service.max_scopes,
            })
        }
        GrantMode::Direct => None,
    };
    LoadedCeilings {
        grant: CeilingRecord {
            id: grant.id,
            status: grant.status,
            revision: grant.revision,
            scopes: grant.scopes,
        },
        grant_mode: grant.mode,
        grant_default_scopes: grant.default_scopes,
        resource_server: CeilingRecord {
            id: server.id,
            status: server.status,
            revision: server.revision,
            scopes: server.scopes,
        },
        assignment: CeilingRecord {
            id: assignment.id,
            status: assignment.status,
            revision: assignment.revision,
            scopes: assignment.allowed_scopes,
        },
        target_service,
    }
}

/// Loads `grant` of `tenant` and checks that it is exactly what the
/// getters give.
async fn assert_loaded_exactly(pool: &PgPool, tenant: &str, grant: &str) -> LoadedCeilings {
    let loaded = load(pool, tenant, grant).await;
    assert_eq!(
        loaded,
        from_getters(pool, tenant, grant).await,
        "{tenant} {grant}"
    );
    loaded
}

/// The mutable columns of `grant` as they are.
fn grant_changes(grant: &ServiceGrant) -> ServiceGrantChanges {
    ServiceGrantChanges {
        name: grant.name.clone(),
        scopes: grant.scopes.clone(),
        default_scopes: grant.default_scopes.clone(),
        resource_constraints: grant.resource_constraints.clone(),
        max_ttl: grant.max_ttl,
        valid_until: grant.valid_until,
        status: grant.status,
        activation_state: grant.activation_state,
    }
}

/// Replaces the defaults of `current` at its revision through `executor`,
/// and checks that the update stored them and advanced the revision by one.
async fn set_defaults<'e>(
    executor: impl PgExecutor<'e>,
    current: &ServiceGrant,
    defaults: Option<&[&str]>,
) -> ServiceGrant {
    let changes = ServiceGrantChanges {
        default_scopes: defaults.map(strings),
        ..grant_changes(current)
    };
    let updated = registry::update_service_grant(
        executor,
        &current.tenant_id,
        &current.id,
        current.revision,
        &changes,
    )
    .await
    .unwrap();
    assert_eq!(updated.revision, current.revision + 1);
    assert_eq!(updated.default_scopes, changes.default_scopes);
    updated
}

/// Every grant of `ten_a`, as listed.
async fn all_grants(pool: &PgPool) -> Vec<ServiceGrant> {
    registry::list_service_grants(pool, TEN_A, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap()
}

async fn get_grant(pool: &PgPool, tenant: &str, grant: &str) -> ServiceGrant {
    registry::get_service_grant(pool, tenant, grant)
        .await
        .unwrap()
}

/// Replaces the `allowed_scopes` of assignment `id` at its current
/// revision, keeping its other columns.
async fn set_assignment_scopes<'e>(
    executor: impl PgExecutor<'e>,
    pool: &PgPool,
    id: &str,
    scopes: &[&str],
) -> i64 {
    let current = registry::get_audience_tenant_assignment(pool, id)
        .await
        .unwrap();
    let updated = registry::update_audience_tenant_assignment(
        executor,
        id,
        current.revision,
        &AudienceTenantAssignmentChanges {
            allowed_profiles: current.allowed_profiles,
            allowed_scopes: strings(scopes),
            constraint_versions: current.constraint_versions,
            status: current.status,
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.allowed_scopes, strings(scopes));
    updated.revision
}

async fn set_server_scopes(pool: &PgPool, scopes: &[&str]) -> i64 {
    let current = registry::get_resource_server(pool, RS).await.unwrap();
    let updated = registry::update_resource_server(
        pool,
        RS,
        current.revision,
        &ResourceServerChanges {
            name: current.name,
            allowed_profiles: current.allowed_profiles,
            scopes: strings(scopes),
            constraint_versions: current.constraint_versions,
            status: current.status,
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.scopes, strings(scopes));
    updated.revision
}

async fn set_service_scopes(pool: &PgPool, scopes: &[&str]) -> i64 {
    let current = registry::get_service_identity(pool, TEN_A, SVC_A)
        .await
        .unwrap();
    let updated = registry::update_service_identity(
        pool,
        TEN_A,
        SVC_A,
        current.revision,
        &ServiceIdentityChanges {
            name: current.name,
            max_scopes: strings(scopes),
            max_resource_constraints: current.max_resource_constraints,
            status: current.status,
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.max_scopes, strings(scopes));
    updated.revision
}

/// The refusal of a check constraint named `constraint`, by variant, kind
/// and name.
#[track_caller]
fn assert_check<T: Debug>(result: Result<T, RegistryError>, constraint: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::Check,
            constraint: Some(actual),
        }) => assert_eq!(actual, constraint),
        other => panic!("expected Invariant {{ Check, {constraint} }}: {other:?}"),
    }
}

#[track_caller]
fn assert_invalid(result: Result<Vec<String>, ScopeError>, case: &str) {
    assert_eq!(result, Err(ScopeError::Invalid), "{case}");
}

const DEFAULTS_CHECK: &str = "service_grant_default_scopes_check";
const SCOPE_LIST_CHECK: &str = "skyoauth_scope_list_check";

#[tokio::test]
async fn a26_pos_omitted_scope_resolves_to_the_stored_explicit_defaults() {
    let (db, pool) = fixture().await;

    // The loaded ceilings are the registry's rows: the tenant's own
    // assignment, and the target service for the delegation only.
    let direct = assert_loaded_exactly(&pool, TEN_A, DIRECT).await;
    assert_eq!(direct.grant_mode, GrantMode::Direct);
    assert_eq!(direct.assignment.id, ATA_A);
    assert_eq!(direct.target_service, None);
    assert_eq!(direct.scope_ceilings().target_service, None);
    assert_eq!(direct.default_scopes(), Some(&strings(&["read"])[..]));
    let delegation = assert_loaded_exactly(&pool, TEN_A, DLG).await;
    assert_eq!(delegation.grant_mode, GrantMode::Delegation);
    assert_eq!(
        delegation
            .target_service
            .as_ref()
            .map(|s| (s.id.as_str(), &s.scopes)),
        Some((SVC_A, &strings(&SVC_A_SCOPES)))
    );
    assert_eq!(
        delegation.scope_ceilings().target_service,
        Some(strings(&SVC_A_SCOPES))
    );
    let other = assert_loaded_exactly(&pool, TEN_B, GRT_B).await;
    assert_eq!(other.assignment.id, ATA_B);

    // Omitted: exactly the defaults, though the direct grant's ceilings
    // allow deploy:write too when it is asked for.
    for grant in [DIRECT, DLG] {
        assert_eq!(
            resolve(&pool, TEN_A, grant, &ScopeRequest::Omitted).await,
            Ok(strings(&["read"])),
            "{grant}"
        );
    }
    assert_eq!(
        resolve(&pool, TEN_A, DIRECT, &explicit(&["read", "deploy:write"])).await,
        Ok(strings(&["deploy:write", "read"]))
    );
    assert_eq!(
        resolve(&pool, TEN_B, GRT_B, &ScopeRequest::Omitted).await,
        Ok(strings(&["admin"]))
    );

    // Defaults changed through the registry apply from the next load,
    // stored in the order written and resolved sorted byte-wise.
    let grant = get_grant(&pool, TEN_A, DIRECT).await;
    let grant = set_defaults(&pool, &grant, Some(&["read", "deploy:write"])).await;
    let loaded = assert_loaded_exactly(&pool, TEN_A, DIRECT).await;
    assert_eq!(loaded.grant.revision, 2);
    assert_eq!(
        loaded.default_scopes(),
        Some(&strings(&["read", "deploy:write"])[..])
    );
    assert_eq!(
        decide(&loaded, &ScopeRequest::Omitted),
        Ok(strings(&["deploy:write", "read"]))
    );
    set_defaults(&pool, &grant, Some(&["deploy:write"])).await;
    let loaded = assert_loaded_exactly(&pool, TEN_A, DIRECT).await;
    assert_eq!(loaded.grant.revision, 3);
    assert_eq!(
        decide(&loaded, &ScopeRequest::Omitted),
        Ok(strings(&["deploy:write"]))
    );
    // The delegation's defaults are untouched by the direct grant's.
    assert_eq!(
        resolve(&pool, TEN_A, DLG, &ScopeRequest::Omitted).await,
        Ok(strings(&["read"]))
    );
    let grant_b = get_grant(&pool, TEN_B, GRT_B).await;
    set_defaults(&pool, &grant_b, Some(&["read", "admin"])).await;
    assert_eq!(
        resolve(&pool, TEN_B, GRT_B, &ScopeRequest::Omitted).await,
        Ok(strings(&["admin", "read"]))
    );
    db.drop([pool]).await;
}

#[tokio::test]
async fn a26_neg_omitted_scope_without_defaults_is_invalid_scope() {
    let (db, pool) = fixture().await;

    // Stored without defaults. Its own scopes are exactly the intersection
    // of its ceilings, so a fallback to either would resolve; none does.
    let loaded = assert_loaded_exactly(&pool, TEN_A, NONE).await;
    assert_eq!(get_grant(&pool, TEN_A, NONE).await.default_scopes, None);
    assert_eq!(loaded.default_scopes(), None);
    assert_invalid(decide(&loaded, &ScopeRequest::Omitted), "no defaults");
    assert_eq!(
        decide(&loaded, &explicit(&["read", "deploy:write"])),
        Ok(strings(&["deploy:write", "read"]))
    );

    // Defaults cleared through the registry: omission is invalid from the
    // next load on; an explicit request inside the ceilings still resolves.
    for (tenant, grant, allowed) in [
        (TEN_A, DIRECT, "read"),
        (TEN_A, DLG, "read"),
        (TEN_B, GRT_B, "admin"),
    ] {
        let current = get_grant(&pool, tenant, grant).await;
        set_defaults(&pool, &current, None).await;
        let loaded = assert_loaded_exactly(&pool, tenant, grant).await;
        assert_eq!(loaded.default_scopes(), None, "{grant}");
        assert_invalid(decide(&loaded, &ScopeRequest::Omitted), grant);
        assert_eq!(
            decide(&loaded, &explicit(&[allowed])),
            Ok(strings(&[allowed])),
            "{grant}"
        );
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a26_neg_empty_or_out_of_grant_defaults_are_refused_at_write() {
    let (db, pool) = fixture().await;
    let before = get_grant(&pool, TEN_A, DIRECT).await;
    let grants_before = all_grants(&pool).await;

    // Create: empty defaults, defaults outside the grant's own scopes
    // (logs:read; a case variant of read), and malformed tokens.
    let refusals: [(&str, &[&str], &str); 6] = [
        ("empty", &[], DEFAULTS_CHECK),
        ("outside the grant", &["read", "logs:read"], DEFAULTS_CHECK),
        ("case variant", &["READ"], DEFAULTS_CHECK),
        ("space in a token", &["read write"], SCOPE_LIST_CHECK),
        ("empty token", &[""], SCOPE_LIST_CHECK),
        ("backslash", &["re\\ad"], SCOPE_LIST_CHECK),
    ];
    for (case, defaults, constraint) in refusals {
        for delegation in [false, true] {
            let new = grant_a("grt_new", delegation, &GRANT_SCOPES, Some(defaults));
            assert_check(
                registry::create_service_grant(&pool, &new).await,
                constraint,
            );
            let read = registry::get_service_grant(&pool, TEN_A, "grt_new").await;
            assert!(
                matches!(read, Err(RegistryError::NotFound)),
                "{case}: {read:?}"
            );
        }
    }

    // Update: the same defaults, and scopes that leave a default outside.
    for (case, defaults, constraint) in refusals {
        let changes = ServiceGrantChanges {
            default_scopes: Some(strings(defaults)),
            ..grant_changes(&before)
        };
        assert_check(
            registry::update_service_grant(&pool, TEN_A, DIRECT, before.revision, &changes).await,
            constraint,
        );
        assert_eq!(get_grant(&pool, TEN_A, DIRECT).await, before, "{case}");
    }
    let narrowed = ServiceGrantChanges {
        scopes: strings(&["deploy:write", "admin", "audit"]),
        ..grant_changes(&before)
    };
    assert_check(
        registry::update_service_grant(&pool, TEN_A, DIRECT, before.revision, &narrowed).await,
        DEFAULTS_CHECK,
    );

    // Nothing was written, and the stored defaults still decide.
    assert_eq!(all_grants(&pool).await, grants_before);
    assert_eq!(
        resolve(&pool, TEN_A, DIRECT, &ScopeRequest::Omitted).await,
        Ok(strings(&["read"]))
    );
    db.drop([pool]).await;
}

#[tokio::test]
async fn a26_neg_explicit_empty_or_excessive_scope_is_invalid_scope() {
    let (db, pool) = fixture().await;
    let direct = load(&pool, TEN_A, DIRECT).await;
    let delegation = load(&pool, TEN_A, DLG).await;
    let none = load(&pool, TEN_A, NONE).await;

    // Controls: read is in every ceiling; deploy:write in every ceiling of
    // the direct grant.
    for loaded in [&direct, &delegation, &none] {
        assert_eq!(decide(loaded, &explicit(&["read"])), Ok(strings(&["read"])));
    }
    assert_eq!(
        decide(&direct, &explicit(&["deploy:write"])),
        Ok(strings(&["deploy:write"]))
    );

    // An explicit empty list is not an omission, also where defaults
    // exist.
    for (grant, loaded) in [(DIRECT, &direct), (DLG, &delegation), (NONE, &none)] {
        assert_invalid(decide(loaded, &explicit(&[])), grant);
    }

    // Outside one ceiling: denied alone, and next to an allowed scope
    // (not trimmed), in either order.
    for (scope, ceiling, direct_too) in EXCESSIVE {
        for request in [
            explicit(&[scope]),
            explicit(&["read", scope]),
            explicit(&[scope, "read"]),
        ] {
            let case = format!("{request:?} outside {ceiling}");
            assert_invalid(decide(&delegation, &request), &case);
            if direct_too {
                assert_invalid(decide(&direct, &request), &case);
            } else {
                assert_eq!(
                    decide(&direct, &request).map(|scopes| scopes.contains(&scope.to_string())),
                    Ok(true),
                    "{case}: the direct grant has no target service"
                );
            }
        }
    }

    // Unknown, case or lookalike variants of read; then tokens outside the
    // scope-token grammar, refused here only because no ceiling contains
    // them (skyoauth_scope_list_check keeps them out of every ceiling). They
    // do not pin the grammar check itself: only the policy::scope unit tests
    // do.
    for scope in [
        "unknown",
        "write",
        "READ",
        "Read",
        "read:",
        "re\u{0430}d",
        "read write",
        "",
        "re\"ad",
        "re\\ad",
        "r\u{e9}ad",
        "read\t",
    ] {
        for (grant, loaded) in [(DIRECT, &direct), (DLG, &delegation)] {
            assert_invalid(
                decide(loaded, &explicit(&[scope])),
                &format!("{grant} {scope:?}"),
            );
            assert_invalid(
                decide(loaded, &explicit(&["read", scope])),
                &format!("{grant} read+{scope:?}"),
            );
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a26_neg_defaults_outside_a_narrowed_ceiling_are_invalid_not_trimmed() {
    let (db, pool) = fixture().await;
    let grant = get_grant(&pool, TEN_A, DIRECT).await;
    set_defaults(&pool, &grant, Some(&["read", "deploy:write"])).await;
    let both = Ok(strings(&["deploy:write", "read"]));
    assert_eq!(
        resolve(&pool, TEN_A, DIRECT, &ScopeRequest::Omitted).await,
        both
    );

    // The assignment, then the resource server, loses deploy:write: the
    // defaults fail whole, read alone still resolves when asked for, and
    // the restored ceiling restores the defaults. Each loaded ceiling is
    // the row at its new revision.
    let narrower_assignment: Vec<&str> = ATA_A_SCOPES
        .into_iter()
        .filter(|scope| *scope != "deploy:write")
        .collect();
    let revision = set_assignment_scopes(&pool, &pool, ATA_A, &narrower_assignment).await;
    let loaded = assert_loaded_exactly(&pool, TEN_A, DIRECT).await;
    assert_eq!(loaded.assignment.revision, revision);
    assert_invalid(
        decide(&loaded, &ScopeRequest::Omitted),
        "assignment narrowed",
    );
    assert_eq!(
        decide(&loaded, &explicit(&["read"])),
        Ok(strings(&["read"]))
    );
    set_assignment_scopes(&pool, &pool, ATA_A, &ATA_A_SCOPES).await;
    assert_eq!(
        resolve(&pool, TEN_A, DIRECT, &ScopeRequest::Omitted).await,
        both
    );

    let narrower_server: Vec<&str> = RS_SCOPES
        .into_iter()
        .filter(|scope| *scope != "deploy:write")
        .collect();
    let revision = set_server_scopes(&pool, &narrower_server).await;
    let loaded = assert_loaded_exactly(&pool, TEN_A, DIRECT).await;
    assert_eq!(loaded.resource_server.revision, revision);
    assert_invalid(
        decide(&loaded, &ScopeRequest::Omitted),
        "resource server narrowed",
    );
    assert_eq!(
        decide(&loaded, &explicit(&["read"])),
        Ok(strings(&["read"]))
    );
    set_server_scopes(&pool, &RS_SCOPES).await;
    assert_eq!(
        resolve(&pool, TEN_A, DIRECT, &ScopeRequest::Omitted).await,
        both
    );

    // The target service loses read: the delegation's defaults fail; the
    // direct grant, with no target, is not bounded by it.
    let revision = set_service_scopes(&pool, &["admin", "audit"]).await;
    let loaded = assert_loaded_exactly(&pool, TEN_A, DLG).await;
    assert_eq!(
        loaded.target_service.as_ref().map(|s| s.revision),
        Some(revision)
    );
    assert_invalid(
        decide(&loaded, &ScopeRequest::Omitted),
        "target service narrowed",
    );
    assert_eq!(
        resolve(&pool, TEN_A, DIRECT, &ScopeRequest::Omitted).await,
        both
    );
    set_service_scopes(&pool, &SVC_A_SCOPES).await;
    assert_eq!(
        resolve(&pool, TEN_A, DLG, &ScopeRequest::Omitted).await,
        Ok(strings(&["read"]))
    );

    // The registry stores defaults inside the grant's own scopes but
    // outside another ceiling: admin (not in the assignment) and, for a
    // delegation, deploy:write (not in the target service). Omission is
    // invalid from the start, not trimmed to read.
    for (id, delegation, outside) in [
        ("grt_admin", false, "admin"),
        ("grt_dlg_deploy", true, "deploy:write"),
    ] {
        let new = grant_a(id, delegation, &GRANT_SCOPES, Some(&["read", outside]));
        let stored = registry::create_service_grant(&pool, &new).await.unwrap();
        assert_eq!(stored.default_scopes, new.default_scopes);
        let loaded = assert_loaded_exactly(&pool, TEN_A, id).await;
        assert_invalid(decide(&loaded, &ScopeRequest::Omitted), id);
        assert_eq!(
            decide(&loaded, &explicit(&["read"])),
            Ok(strings(&["read"]))
        );
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a26_neg_other_tenants_ceilings_never_apply() {
    let (db, pool) = fixture().await;

    // admin: ten_b's assignment allows it, ten_a's does not.
    assert_invalid(
        resolve(&pool, TEN_A, DIRECT, &explicit(&["admin"])).await,
        "ten_a admin",
    );
    assert_eq!(
        resolve(&pool, TEN_B, GRT_B, &explicit(&["admin"])).await,
        Ok(strings(&["admin"]))
    );

    // A grant loads under its own tenant only.
    for (tenant, grant) in [(TEN_B, DIRECT), (TEN_B, DLG), (TEN_B, NONE), (TEN_A, GRT_B)] {
        assert_eq!(
            load_scope_ceilings(&pool, tenant, grant, AUDIENCE)
                .await
                .unwrap(),
            None,
            "{tenant} {grant}"
        );
    }

    // Widening ten_b's assignment to every scope changes nothing for
    // ten_a's grants.
    let before_a: Vec<LoadedCeilings> = {
        let mut loaded = vec![];
        for grant in [DIRECT, DLG, NONE] {
            loaded.push(load(&pool, TEN_A, grant).await);
        }
        loaded
    };
    set_assignment_scopes(
        &pool,
        &pool,
        ATA_B,
        &["read", "deploy:write", "admin", "audit", "logs:read"],
    )
    .await;
    for (grant, before) in [DIRECT, DLG, NONE].into_iter().zip(&before_a) {
        assert_eq!(&load(&pool, TEN_A, grant).await, before, "{grant}");
    }
    for (scope, _, _) in EXCESSIVE {
        if scope != "deploy:write" {
            assert_invalid(
                resolve(&pool, TEN_A, DIRECT, &explicit(&[scope])).await,
                &format!("ten_a {scope} after ten_b widened"),
            );
        }
    }
    assert_eq!(
        resolve(&pool, TEN_A, DIRECT, &ScopeRequest::Omitted).await,
        Ok(strings(&["read"]))
    );

    // Narrowing ten_a's assignment to nothing changes nothing for ten_b's.
    let before_b = load(&pool, TEN_B, GRT_B).await;
    set_assignment_scopes(&pool, &pool, ATA_A, &[]).await;
    assert_invalid(
        resolve(&pool, TEN_A, DIRECT, &ScopeRequest::Omitted).await,
        "ten_a narrowed",
    );
    assert_eq!(load(&pool, TEN_B, GRT_B).await, before_b);
    assert_eq!(
        resolve(&pool, TEN_B, GRT_B, &ScopeRequest::Omitted).await,
        Ok(strings(&["admin"]))
    );
    db.drop([pool]).await;
}

#[tokio::test]
async fn a26_neg_uncommitted_ceiling_changes_never_apply() {
    let (db, pool) = fixture().await;
    let before = load(&pool, TEN_A, DIRECT).await;

    // Widened assignment and defaults, then rolled back.
    let mut tx = pool.begin().await.unwrap();
    let mut widened: Vec<&str> = ATA_A_SCOPES.to_vec();
    widened.push("admin");
    set_assignment_scopes(&mut *tx, &pool, ATA_A, &widened).await;
    let grant = get_grant(&pool, TEN_A, DIRECT).await;
    set_defaults(&mut *tx, &grant, Some(&["read", "admin"])).await;
    let inside = load(&mut *tx, TEN_A, DIRECT).await;
    assert_eq!(
        decide(&inside, &ScopeRequest::Omitted),
        Ok(strings(&["admin", "read"]))
    );
    // Outside the transaction, the committed rows decide.
    let outside = load_outside(&pool, DIRECT).await;
    assert_eq!(outside, before);
    assert_eq!(
        decide(&outside, &ScopeRequest::Omitted),
        Ok(strings(&["read"]))
    );
    assert_invalid(
        decide(&outside, &explicit(&["admin"])),
        "uncommitted widening",
    );
    tx.rollback().await.unwrap();
    assert_eq!(load(&pool, TEN_A, DIRECT).await, before);
    assert_invalid(
        resolve(&pool, TEN_A, DIRECT, &explicit(&["admin"])).await,
        "rolled-back widening",
    );

    // A narrowing applies once committed, not before.
    let mut tx = pool.begin().await.unwrap();
    set_assignment_scopes(&mut *tx, &pool, ATA_A, &["deploy:write"]).await;
    assert_invalid(
        decide(&load(&mut *tx, TEN_A, DIRECT).await, &ScopeRequest::Omitted),
        "inside the narrowing",
    );
    assert_eq!(
        decide(&load_outside(&pool, DIRECT).await, &ScopeRequest::Omitted),
        Ok(strings(&["read"]))
    );
    tx.commit().await.unwrap();
    let after = assert_loaded_exactly(&pool, TEN_A, DIRECT).await;
    assert_eq!(after.assignment.revision, before.assignment.revision + 1);
    assert_invalid(
        decide(&after, &ScopeRequest::Omitted),
        "committed narrowing",
    );
    db.drop([pool]).await;
}
