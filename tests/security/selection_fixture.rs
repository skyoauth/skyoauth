//! Shared fixture of the grant-selection scenarios A25 (and later A50): two
//! tenants with the same object graph, created through the typed registry
//! API (`skyoauth_service::persistence::registry`), the grants, sources and
//! bindings the scenarios select and match, and evidence that every binding
//! of a source fits. Not a scenario: it holds no test.
//!
//! Every ID carries its tenant's suffix, because IDs are global (as in
//! A29): `wld_a_b` is workload `wld_a` of tenant `ten_b`. Names are the same
//! in both tenants. Per tenant:
//!
//! - workloads `wld_a` and `wld_b`; services `svc_1` and `svc_2`, each with
//!   its service identity; one resource server (`rs`) assigned to the
//!   tenant, the audience of every grant and of both identities;
//! - sources: `src_gh` and `src_alt` on the GitHub Actions issuer (both
//!   `oidc_discovery`), and `src_gen` on a non-GitHub issuer;
//! - four grants with the same audience ([`GRANTS`]): direct of `wld_a`,
//!   delegation of `wld_a` to `svc_1`, delegation of `wld_a` to `svc_2`, and
//!   delegation of `wld_b` to `svc_1`;
//! - bindings, every one enabled unless said otherwise. On `src_gh`, each
//!   grant has its own eligible `github_production` binding
//!   (`bnd_a_direct`, `bnd_a_svc1`, `bnd_a_svc2`, `bnd_b_svc1`). On
//!   `src_gen`, each actor has one `generic_production` binding (`bnd_g_a`,
//!   `bnd_g_b`) that every grant of that actor lists. For each actor `x`,
//!   three `github_production` bindings that are never eligible on
//!   `src_gh`: `bnd_0_free_x` (on `src_gh`, listed by no grant),
//!   `bnd_0_off_x` (on `src_gh`, disabled, listed by every grant of `x`)
//!   and `bnd_0_alt_x` (on `src_alt`, listed by every grant of `x`, so
//!   eligible there and only there).
//!
//! Every `github_production` binding has the same policy
//! ([`github_policy`](super::grant_fixture::github_policy)) and every
//! `generic_production` binding the same `sub`, so the evidence of a source
//! ([`Source::evidence`]) fits every binding on it, of both actors. On
//! `src_gh`, the IDs of the ineligible and other-actor bindings sort lowest
//! byte-wise (`bnd_0_…` before `bnd_a_…` before `bnd_b_…`), so a selection
//! that loaded one would have
//! [`match_binding`](skyoauth_service::policy::match_binding)
//! pick it over the grant's own. On `src_alt` and `src_gen` that holds for
//! the grant of `wld_b` only: the bindings of `wld_a` sort first there.
//!
//! Each binding profile is on a source of its kind: `github_production`
//! only on the GitHub issuer, `generic_production` only on `src_gen`. The
//! check that a binding's template fits its source (ADR-016 item 4) is not
//! built; once it is, it may refuse a `generic_production` template on a
//! GitHub source, so a scenario that adds bindings here should keep this
//! pairing.
//!
//! **The A50 additions.** [`two_tenants_with_matching`] seeds the same two
//! tenants plus, per tenant, the records of A50 only, so A25's database and
//! its expected eligible bindings stay as above. All are
//! `generic_production` bindings on the partner CI's issuer, a
//! repository-wide policy being `sub` and `repository_id`
//! ([`repo_wide_policy`]) and a deployment policy adding `environment`
//! ([`deployment_policy`]):
//!
//! - a second source on that issuer, `src_gen2` ([`SECOND_GENERIC`]);
//! - bindings of `wld_a`: on `src_gen`, the repository-wide `bnd_m1` and
//!   the deployment binding `bnd_m2`, both enabled, whose neutral names
//!   differ only in byte order (A50 tests the ID order, not specificity),
//!   and
//!   three deployment bindings that sort lowest and are never eligible on
//!   `src_gen`: `bnd_0_gen_off` (disabled, listed), `bnd_0_gen_free`
//!   (enabled, listed by no grant) and `bnd_0_gen2` (on `src_gen2`,
//!   listed, so eligible there and only there);
//! - bindings of `wld_b` on `src_gen`: the repository-wide `bnd_0_repo` of
//!   the same repository, which sorts before the eligible bindings of
//!   `wld_a` there (`bnd_m1`, `bnd_m2`),
//!   and the repository-wide `bnd_b_other` of another repository;
//! - three direct grants ([`MATCHING_GRANTS`]): `grt_a_match` of `wld_a`
//!   (listing `bnd_m2`, `bnd_0_gen_off` and `bnd_0_gen2`),
//!   `grt_a_multi` of `wld_a` (listing `bnd_m1` and `bnd_m2`) and
//!   `grt_b_match` of `wld_b` (listing `bnd_0_repo` and `bnd_b_other`).
//!
//! [`deployment_evidence`] fits every one of these bindings but
//! `bnd_b_other`; [`other_repository_evidence`] fits `bnd_b_other` only.
//! `generic_production` bindings stay on non-GitHub sources, as above.

use std::collections::BTreeMap;

use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    persistence::{
        PgPool,
        registry::{
            self, ActivationState, AssertionProfile, BindingProfile, GrantMode, JsonObject,
            NewAudienceTenantAssignment, NewPrincipal, NewPrincipalBinding, NewResourceServer,
            NewServiceGrant, NewServiceIdentity, NewTenant, NewTrustSource, PrincipalKind, Profile,
            ReplayMode, Status, TrustSourceKind,
        },
    },
    policy::Evidence,
};

use super::grant_fixture::github_policy;

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GENERIC_ISSUER: &str = "https://ci.partner.example";
/// The `sub` every `generic_production` binding names.
const GENERIC_SUB: &str = "pipeline:example/release:production";

/// One of the two tenants. Every ID carries the tenant's suffix.
#[derive(Clone, Copy, Debug)]
pub(super) struct Side {
    pub(super) tenant: &'static str,
    suffix: &'static str,
}

pub(super) const A: Side = Side {
    tenant: "ten_a",
    suffix: "a",
};
pub(super) const B: Side = Side {
    tenant: "ten_b",
    suffix: "b",
};

/// (owner, other): the other tenant names the owner's records.
pub(super) const DIRECTIONS: [(Side, Side); 2] = [(A, B), (B, A)];

impl Side {
    /// The ID of record `base` in this tenant.
    pub(super) fn id(self, base: &str) -> String {
        format!("{base}_{}", self.suffix)
    }

    /// The tenant's one resource server, every grant's audience.
    pub(super) fn audience(self) -> String {
        self.id("rs")
    }
}

/// The tenant's sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Source {
    /// `src_gh`: GitHub Actions, the source of each grant's own binding.
    Github,
    /// `src_alt`: a second source on the GitHub issuer.
    Alt,
    /// `src_gen`: a non-GitHub issuer, with `generic_production` bindings.
    Generic,
}

pub(super) const SOURCES: [Source; 3] = [Source::Github, Source::Alt, Source::Generic];

impl Source {
    fn base(self) -> &'static str {
        match self {
            Self::Github => "src_gh",
            Self::Alt => "src_alt",
            Self::Generic => "src_gen",
        }
    }

    /// The source's ID in `side`.
    pub(super) fn id(self, side: Side) -> String {
        side.id(self.base())
    }

    /// Evidence that fits every binding on this source, of either actor:
    /// every predicate, plus claims no predicate names.
    pub(super) fn evidence(self) -> Evidence {
        match self {
            Self::Github | Self::Alt => github_evidence(),
            Self::Generic => generic_evidence(),
        }
    }
}

/// Verified claims of a push to `main` of `example/release` in the
/// `production` environment: every predicate of
/// [`github_policy`](super::grant_fixture::github_policy), plus `sub` and
/// `actor`, which no binding names.
pub(super) fn github_evidence() -> Evidence {
    let mut claims = github_policy();
    claims.insert(
        "sub".into(),
        "repo:example/release:environment:production".into(),
    );
    claims.insert("actor".into(), "octocat".into());
    Evidence::new(claims)
}

/// Verified claims of the partner CI's production pipeline: the `sub` of
/// every `generic_production` binding, plus a claim no binding names.
pub(super) fn generic_evidence() -> Evidence {
    [("sub", GENERIC_SUB), ("pipeline_run", "4711")]
        .into_iter()
        .collect()
}

/// One of the four same-audience grants of a tenant. Every field but
/// `name` and `mode` is an ID base ([`Side::id`]).
#[derive(Clone, Copy, Debug)]
pub(super) struct Grant {
    pub(super) id: &'static str,
    /// The tenant-local name.
    pub(super) name: &'static str,
    pub(super) mode: GrantMode,
    pub(super) actor: &'static str,
    /// `None` for the direct grant.
    pub(super) target: Option<&'static str>,
    /// The grant's own binding on `src_gh`.
    binding: &'static str,
    /// The actor's binding on `src_gen` (every grant of the actor lists it).
    generic: &'static str,
    /// The actor's binding on `src_alt` (every grant of the actor lists it).
    alt: &'static str,
}

impl Grant {
    /// The ID base of the one binding of this grant that is eligible on
    /// `source`.
    pub(super) fn eligible_on(self, source: Source) -> &'static str {
        match source {
            Source::Github => self.binding,
            Source::Alt => self.alt,
            Source::Generic => self.generic,
        }
    }
}

/// The four same-audience grants: three of `wld_a` that differ in mode and
/// target, and one of `wld_b` with the same target as one of them.
pub(super) const GRANTS: [Grant; 4] = [
    Grant {
        id: "grt_a_direct",
        name: "a-direct",
        mode: GrantMode::Direct,
        actor: "wld_a",
        target: None,
        binding: "bnd_a_direct",
        generic: "bnd_g_a",
        alt: "bnd_0_alt_a",
    },
    Grant {
        id: "grt_a_svc1",
        name: "a-to-svc1",
        mode: GrantMode::Delegation,
        actor: "wld_a",
        target: Some("svc_1"),
        binding: "bnd_a_svc1",
        generic: "bnd_g_a",
        alt: "bnd_0_alt_a",
    },
    Grant {
        id: "grt_a_svc2",
        name: "a-to-svc2",
        mode: GrantMode::Delegation,
        actor: "wld_a",
        target: Some("svc_2"),
        binding: "bnd_a_svc2",
        generic: "bnd_g_a",
        alt: "bnd_0_alt_a",
    },
    Grant {
        id: "grt_b_svc1",
        name: "b-to-svc1",
        mode: GrantMode::Delegation,
        actor: "wld_b",
        target: Some("svc_1"),
        binding: "bnd_b_svc1",
        generic: "bnd_g_b",
        alt: "bnd_0_alt_b",
    },
];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// Source `on` of `side`: `src_gh` and `src_alt` on the GitHub issuer,
/// `src_gen` on the partner CI's issuer.
fn source(side: Side, on: Source) -> NewTrustSource {
    let (name, issuer) = match on {
        Source::Github => ("github", GITHUB_ISSUER),
        Source::Alt => ("github-alt", GITHUB_ISSUER),
        Source::Generic => ("partner-ci", GENERIC_ISSUER),
    };
    NewTrustSource {
        id: on.id(side),
        tenant_id: side.tenant.into(),
        name: name.into(),
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
    }
}

/// Binding `base` of workload `actor` on `source`: `github_production` on a
/// GitHub source, `generic_production` on `src_gen`. Its name is its ID
/// base with dashes.
fn binding(side: Side, base: &str, actor: &str, on: Source, status: Status) -> NewPrincipalBinding {
    let (profile, claim_match_policy) = match on {
        Source::Github | Source::Alt => (BindingProfile::GithubProduction, github_policy()),
        Source::Generic => (
            BindingProfile::GenericProduction,
            BTreeMap::from([("sub".to_string(), GENERIC_SUB.to_string())]),
        ),
    };
    NewPrincipalBinding {
        id: side.id(base),
        tenant_id: side.tenant.into(),
        name: base.replace('_', "-"),
        trust_source_id: on.id(side),
        profile,
        claim_match_policy,
        workload_principal_id: side.id(actor),
        status,
    }
}

/// The bindings of `side`: (ID base, actor, source, status).
const BINDINGS: [(&str, &str, Source, Status); 12] = [
    // Each grant's own eligible binding on src_gh.
    ("bnd_a_direct", "wld_a", Source::Github, Status::Enabled),
    ("bnd_a_svc1", "wld_a", Source::Github, Status::Enabled),
    ("bnd_a_svc2", "wld_a", Source::Github, Status::Enabled),
    ("bnd_b_svc1", "wld_b", Source::Github, Status::Enabled),
    // Each actor's binding on src_gen.
    ("bnd_g_a", "wld_a", Source::Generic, Status::Enabled),
    ("bnd_g_b", "wld_b", Source::Generic, Status::Enabled),
    // Never eligible on src_gh, and sorting lowest: unlisted, disabled, on
    // the other source.
    ("bnd_0_free_a", "wld_a", Source::Github, Status::Enabled),
    ("bnd_0_free_b", "wld_b", Source::Github, Status::Enabled),
    ("bnd_0_off_a", "wld_a", Source::Github, Status::Disabled),
    ("bnd_0_off_b", "wld_b", Source::Github, Status::Disabled),
    ("bnd_0_alt_a", "wld_a", Source::Alt, Status::Enabled),
    ("bnd_0_alt_b", "wld_b", Source::Alt, Status::Enabled),
];

/// The record of grant `grant` in `side`: its own binding, its actor's
/// `src_gen` and `src_alt` bindings and disabled `bnd_0_off` binding, and
/// the tenant's audience.
fn grant(side: Side, grant: Grant) -> NewServiceGrant {
    let actor_suffix = &grant.actor["wld_".len()..];
    NewServiceGrant {
        id: side.id(grant.id),
        tenant_id: side.tenant.into(),
        name: grant.name.into(),
        actor_principal_id: side.id(grant.actor),
        target_service_id: grant.target.map(|target| side.id(target)),
        mode: grant.mode,
        scopes: strings(&["read"]),
        default_scopes: Some(strings(&["read"])),
        resource_constraints: JsonObject::new(),
        max_ttl: 300,
        valid_until: None,
        status: Status::Enabled,
        activation_state: ActivationState::NotRequired,
        allowed_binding_ids: vec![
            side.id(grant.binding),
            side.id(grant.generic),
            side.id(grant.alt),
            side.id(&format!("bnd_0_off_{actor_suffix}")),
        ],
        resource_server_ids: vec![side.audience()],
    }
}

/// Creates the records of `side` described in the module docs.
async fn seed(pool: &PgPool, side: Side) {
    registry::create_tenant(
        pool,
        &NewTenant {
            id: side.tenant.into(),
            name: "Example".into(),
            secret_namespace: side.id("ns"),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (base, kind, name) in [
        ("wld_a", PrincipalKind::Workload, "ci-a"),
        ("wld_b", PrincipalKind::Workload, "ci-b"),
        ("svc_1", PrincipalKind::Service, "deploy-api"),
        ("svc_2", PrincipalKind::Service, "audit-api"),
    ] {
        registry::create_principal(
            pool,
            &NewPrincipal {
                id: side.id(base),
                tenant_id: side.tenant.into(),
                kind,
                name: name.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    registry::create_resource_server(
        pool,
        &NewResourceServer {
            id: side.audience(),
            audience: format!("https://api-{}.example", side.suffix),
            name: format!("API-{}", side.suffix),
            allowed_profiles: vec![Profile::Wif],
            scopes: strings(&["read"]),
            constraint_versions: vec![],
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::create_audience_tenant_assignment(
        pool,
        &NewAudienceTenantAssignment {
            id: side.id("ata"),
            resource_server_id: side.audience(),
            tenant_id: side.tenant.into(),
            allowed_profiles: vec![Profile::Wif],
            allowed_scopes: strings(&["read"]),
            constraint_versions: vec![],
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (base, name) in [("svc_1", "deploy-api"), ("svc_2", "audit-api")] {
        registry::create_service_identity(
            pool,
            &NewServiceIdentity {
                id: side.id(base),
                tenant_id: side.tenant.into(),
                name: name.into(),
                max_scopes: strings(&["read"]),
                max_resource_constraints: JsonObject::new(),
                resource_server_ids: vec![side.audience()],
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    for on in SOURCES {
        registry::create_trust_source(pool, &source(side, on))
            .await
            .unwrap();
    }
    for (base, actor, on, status) in BINDINGS {
        registry::create_principal_binding(pool, &binding(side, base, actor, on, status))
            .await
            .unwrap();
    }
    for g in GRANTS {
        registry::create_service_grant(pool, &grant(side, g))
            .await
            .unwrap();
    }
}

/// A fresh database holding both tenants, `ten_a` and `ten_b`, each with
/// the records described in the module docs.
pub(super) async fn two_tenants() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for side in [A, B] {
        seed(&pool, side).await;
    }
    (db, pool)
}

/// The `sub` of every A50 binding.
const MATCHING_SUB: &str = "pipeline:example/release";
/// The repository of every A50 binding but `bnd_b_other`.
pub(super) const REPOSITORY_ID: &str = "987654";
/// The repository of `bnd_b_other`.
pub(super) const OTHER_REPOSITORY_ID: &str = "246810";

/// The ID base of `src_gen2`, the second source on the partner CI's issuer
/// (A50 only).
pub(super) const SECOND_GENERIC: &str = "src_gen2";

/// A repository-wide policy: the pipeline's `sub` and the repository.
pub(super) fn repo_wide_policy(repository_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("sub".to_string(), MATCHING_SUB.to_string()),
        ("repository_id".to_string(), repository_id.to_string()),
    ])
}

/// A deployment policy: the repository-wide policy of [`REPOSITORY_ID`]
/// and the `production` environment.
pub(super) fn deployment_policy() -> BTreeMap<String, String> {
    let mut policy = repo_wide_policy(REPOSITORY_ID);
    policy.insert("environment".into(), "production".into());
    policy
}

/// Verified claims of a `production` deployment of [`REPOSITORY_ID`]: every
/// predicate of [`deployment_policy`], plus a claim no binding names. It
/// fits every A50 binding but `bnd_b_other`.
pub(super) fn deployment_evidence() -> Evidence {
    let mut claims = deployment_policy();
    claims.insert("pipeline_run".into(), "4711".into());
    Evidence::new(claims)
}

/// [`deployment_evidence`] of [`OTHER_REPOSITORY_ID`]: it fits
/// `bnd_b_other` (of `wld_b`) and no other binding.
pub(super) fn other_repository_evidence() -> Evidence {
    let mut claims = deployment_policy();
    claims.insert("repository_id".into(), OTHER_REPOSITORY_ID.into());
    claims.insert("pipeline_run".into(), "4711".into());
    Evidence::new(claims)
}

/// The A50 bindings of a tenant: (ID base, actor, source ID base, status,
/// `Some(repository)` for a repository-wide policy or `None` for the
/// deployment policy).
const MATCHING_BINDINGS: [(&str, &str, &str, Status, Option<&str>); 7] = [
    ("bnd_m2", "wld_a", "src_gen", Status::Enabled, None),
    (
        "bnd_m1",
        "wld_a",
        "src_gen",
        Status::Enabled,
        Some(REPOSITORY_ID),
    ),
    ("bnd_0_gen_off", "wld_a", "src_gen", Status::Disabled, None),
    ("bnd_0_gen_free", "wld_a", "src_gen", Status::Enabled, None),
    ("bnd_0_gen2", "wld_a", SECOND_GENERIC, Status::Enabled, None),
    (
        "bnd_0_repo",
        "wld_b",
        "src_gen",
        Status::Enabled,
        Some(REPOSITORY_ID),
    ),
    (
        "bnd_b_other",
        "wld_b",
        "src_gen",
        Status::Enabled,
        Some(OTHER_REPOSITORY_ID),
    ),
];

/// One of the A50 grants of a tenant: a direct grant of the tenant's
/// audience. `id`, `actor` and `listed` are ID bases ([`Side::id`]).
#[derive(Clone, Copy, Debug)]
pub(super) struct MatchingGrant {
    pub(super) id: &'static str,
    name: &'static str,
    pub(super) actor: &'static str,
    /// The bindings the grant lists, its `allowed_binding_ids`.
    pub(super) listed: &'static [&'static str],
}

/// `grt_a_match`: the deployment binding of `wld_a`, and its disabled and
/// other-source bindings.
pub(super) const GRANT_A_MATCH: MatchingGrant = MatchingGrant {
    id: "grt_a_match",
    name: "a-match",
    actor: "wld_a",
    listed: &["bnd_m2", "bnd_0_gen_off", "bnd_0_gen2"],
};
/// `grt_a_multi`: two bindings of `wld_a` that the same evidence can fit.
pub(super) const GRANT_A_MULTI: MatchingGrant = MatchingGrant {
    id: "grt_a_multi",
    name: "a-multi",
    actor: "wld_a",
    listed: &["bnd_m1", "bnd_m2"],
};
/// `grt_b_match`: the two repository-wide bindings of `wld_b`.
pub(super) const GRANT_B_MATCH: MatchingGrant = MatchingGrant {
    id: "grt_b_match",
    name: "b-match",
    actor: "wld_b",
    listed: &["bnd_0_repo", "bnd_b_other"],
};
pub(super) const MATCHING_GRANTS: [MatchingGrant; 3] =
    [GRANT_A_MATCH, GRANT_A_MULTI, GRANT_B_MATCH];

/// Creates the A50 records of `side` (module docs, "The A50 additions").
async fn seed_matching(pool: &PgPool, side: Side) {
    registry::create_trust_source(
        pool,
        &NewTrustSource {
            id: side.id(SECOND_GENERIC),
            name: "partner-ci-2".into(),
            ..source(side, Source::Generic)
        },
    )
    .await
    .unwrap();
    for (base, actor, on, status, repository) in MATCHING_BINDINGS {
        let claim_match_policy = match repository {
            Some(repository_id) => repo_wide_policy(repository_id),
            None => deployment_policy(),
        };
        registry::create_principal_binding(
            pool,
            &NewPrincipalBinding {
                trust_source_id: side.id(on),
                claim_match_policy,
                ..binding(side, base, actor, Source::Generic, status)
            },
        )
        .await
        .unwrap();
    }
    for g in MATCHING_GRANTS {
        registry::create_service_grant(
            pool,
            &NewServiceGrant {
                id: side.id(g.id),
                name: g.name.into(),
                actor_principal_id: side.id(g.actor),
                allowed_binding_ids: g.listed.iter().map(|base| side.id(base)).collect(),
                // The direct grant's target, mode, scopes and audience.
                ..grant(side, GRANTS[0])
            },
        )
        .await
        .unwrap();
    }
}

/// [`two_tenants`] with the A50 records of each tenant (module docs, "The
/// A50 additions").
pub(super) async fn two_tenants_with_matching() -> (TestDb, PgPool) {
    let (db, pool) = two_tenants().await;
    for side in [A, B] {
        seed_matching(&pool, side).await;
    }
    (db, pool)
}
