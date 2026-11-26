//! A37: production predicate omitted or optional predicate removed.
//! Expected: required omissions reject; optional omission semantics
//! explicit, removal reviewed as widening (tasks §8; T00.12, T12.2;
//! ADR-016 items 1 to 4).
//!
//! **A37 partial: only "removal reviewed as widening" is uncovered, and it
//! has no code, so A37 M1a stays planned (scope "full row").** These tests
//! are registered on A37's planned M1a stage, so they are no evidence for
//! it: the reporter lists their results as not counted. They run through
//! the typed registry API (`skyoauth_service::persistence::registry`), with
//! binding matching from `skyoauth_service::policy`, against a real
//! PostgreSQL, one fresh database per test, except
//! `a37_neg_store_refuses_incomplete_policy`, which writes with plain SQL
//! past the registry. The fixture is local: one tenant, one workload
//! principal, a GitHub source and a generic OIDC source.
//!
//! - **Positive.** A binding of each profile template with exactly the
//!   required set is stored and read back unchanged
//!   (`a37_pos_complete_policy_stored_per_profile`). A `github_production`
//!   binding that omits the optional `repository` and `job_workflow_ref`
//!   is selected for its grant (`registry::select_grant`) and matched
//!   (`policy::match_binding`) by evidence carrying either of two different
//!   `repository` values, or none; `job_workflow_ref` is absent or equal to
//!   `workflow_ref` (no reusable workflow), and a required predicate still
//!   constrains (`a37_pos_optional_predicate_omitted_is_unconstrained`).
//! - **Negative.** For every profile and every required claim, enabled or
//!   disabled: a create without it
//!   (`a37_neg_required_predicate_missing_refused`) or with it empty
//!   (`a37_neg_required_predicate_empty_refused`) is refused and writes
//!   nothing; an update that drops or empties it is
//!   refused and changes nothing
//!   (`a37_neg_required_predicate_removed_by_update_refused`); a
//!   `generic_production` binding of only `sub` moved to another profile
//!   without that profile's set is refused
//!   (`a37_neg_profile_change_needs_new_required_set`); and a write past
//!   the registry is refused by the profile's `0008` check
//!   (`a37_neg_store_refuses_incomplete_policy`).
//!
//! **The required sets are written out here** ([`TEMPLATES`]), from the
//! spec, and never read from `registry::required_claims`: a change to the
//! service's table (a claim dropped, an optional one made required) must
//! fail these tests rather than move them along with it. Sources:
//! `github_production` is the ADR-016 item 3 set as the keys of the design
//! §5.7 example (immutable owner and repository IDs, `event_name`, `ref`,
//! `environment`, `workflow_ref`); `kubernetes_production` is namespace,
//! service-account name and UID (ADR-016 item 4), and their flat claim
//! names are **inferred** (no spec names the keys; they are the names
//! `0008` checks); `generic_production` is `sub` (ADR-016 item 4).
//! `repository` and the reusable-workflow identity `job_workflow_ref` are
//! optional: ADR-016 item 3 requires the latter only "when used", and that
//! it is optional in the registry, and its claim name, are **inferred**.
//!
//! **The refusal.** The registry refuses before its statement with
//! `RegistryError::RequiredPredicate { claim, problem }`: the claim name
//! and `PredicateProblem::Missing` or `PredicateProblem::Empty`. The tests
//! assert that variant, its fields, and that its `Display` text names the
//! claim and the problem as whole words; the profile is not in the error
//! (the caller passed it).
//!
//! **Not covered: removal reviewed as widening.** ADR-016 item 2 makes
//! deleting a predicate privilege widening that needs review, approved as
//! in ADR-008 item 12. No code does that yet: the registry accepts an
//! update that removes an optional predicate with no approval, and cannot
//! tell a reviewed update from another; the review needs the operator API
//! of ADR-008 item 12, which does not exist. Its future tests,
//! `a37_neg_optional_predicate_removal_without_widening_approval_refused`
//! and `a37_pos_optional_predicate_removal_with_widening_approval_applies`,
//! are not written or registered, and A37 M1a cannot be implemented
//! without them (a stage cannot be split inside one milestone).
//!
//! **Known gaps, asserted by no test.**
//!
//! - A profile change can drop predicates: moving a `github_production`
//!   binding to `generic_production` with a policy of only `sub` meets the
//!   new set and is accepted, although every GitHub predicate is gone. Its
//!   stops would be the widening review (ADR-016 item 2; ADR-008 items 12,
//!   13) and the enrollment fit check (ADR-016 item 4); neither is built.
//!   The spec does not settle whether the fit check would reject
//!   `generic_production` on a GitHub `oidc_discovery` source.
//! - A token whose `job_workflow_ref` differs from its `workflow_ref`
//!   matches a binding that does not pin it (ADR-016 item 3; predicate.rs
//!   `GITHUB_JOB_WORKFLOW_REF`; T22.2).
//!
//! No test here pins either acceptance as correct.
//!
//! Not covered here either: the defensive matrices of
//! `service/tests/registry_predicates.rs` (whitespace-only values,
//! non-string JSON values, the catalog of the checks, the `0007` upgrade
//! precondition); near-miss claim names, which only the Rust-side unit test
//! `claim_names_match_exactly` in
//! `service/src/persistence/registry/predicate.rs` covers (no
//! database-side matrix of them exists); and empty or whitespace-only
//! values of optional predicates, whose meaning the spec does not settle.

use std::{collections::BTreeMap, fmt::Debug};

use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    persistence::{
        PgPool,
        registry::{
            self, ActivationState, AssertionProfile, BindingProfile, GrantMode, InvariantKind,
            JsonObject, MAX_PAGE_SIZE, NewPrincipal, NewPrincipalBinding, NewServiceGrant,
            NewTenant, NewTrustSource, Page, PrincipalBinding, PrincipalBindingChanges,
            PrincipalKind, RegistryError, ReplayMode, Status, TrustSourceKind, select_grant,
        },
    },
    policy::{Evidence, match_binding},
};

use super::egress_fixture::Egress;

const TENANT: &str = "ten_a";
/// The workload principal every binding maps to.
const ACTOR: &str = "wld_a";
/// The GitHub Actions source of the `github_production` bindings.
const GITHUB_SOURCE: &str = "src_github";
/// A generic OIDC source, of the `kubernetes_production` and
/// `generic_production` bindings. The schema does not tie a template to a
/// source kind (that enrollment check of ADR-016 item 4 is not built), so
/// no Kubernetes source is needed.
const GENERIC_SOURCE: &str = "src_generic";

/// A binding profile template with the predicates the spec requires of it,
/// each with a sample value.
#[derive(Clone, Copy)]
struct Template {
    profile: BindingProfile,
    /// The profile as stored. The refusal does not name it
    /// (`RequiredPredicate` carries the claim and the problem only); the
    /// tests use it in their failure messages.
    name: &'static str,
    /// The `0008` check of the profile.
    check: &'static str,
    source: &'static str,
    /// (claim, sample value): exactly the required set.
    required: &'static [(&'static str, &'static str)],
}

const GITHUB: Template = Template {
    profile: BindingProfile::GithubProduction,
    name: "github_production",
    check: "principal_binding_github_production_predicates_check",
    source: GITHUB_SOURCE,
    // ADR-016 item 3; the keys and values of the design §5.7 example.
    required: &[
        ("repository_owner_id", "123456"),
        ("repository_id", "456789"),
        ("event_name", "push"),
        ("ref", "refs/heads/main"),
        ("environment", "production"),
        (
            "workflow_ref",
            "acme/platform/.github/workflows/deploy.yml@refs/heads/main",
        ),
    ],
};

const KUBERNETES: Template = Template {
    profile: BindingProfile::KubernetesProduction,
    name: "kubernetes_production",
    check: "principal_binding_kubernetes_production_predicates_check",
    source: GENERIC_SOURCE,
    // ADR-016 item 4: namespace, service-account name and UID. The flat
    // claim names are inferred, as in `0008`.
    required: &[
        ("kubernetes.io/serviceaccount/namespace", "ci"),
        (
            "kubernetes.io/serviceaccount/service-account.name",
            "release",
        ),
        (
            "kubernetes.io/serviceaccount/service-account.uid",
            "6c1a2f0e-3b5d-4e7a-9f2c-1d8e4b6a0c35",
        ),
    ],
};

const GENERIC: Template = Template {
    profile: BindingProfile::GenericProduction,
    name: "generic_production",
    check: "principal_binding_generic_production_predicates_check",
    source: GENERIC_SOURCE,
    // ADR-016 item 4: an exact `sub`.
    required: &[("sub", "release-pipeline")],
};

const TEMPLATES: [Template; 3] = [GITHUB, KUBERNETES, GENERIC];

/// Optional `github_production` predicates (inferred; see the module
/// docs): never required, so a binding may omit them.
const REPOSITORY: &str = "repository";
const JOB_WORKFLOW_REF: &str = "job_workflow_ref";

impl Template {
    /// Exactly the required predicates, with their sample values.
    fn complete(self) -> BTreeMap<String, String> {
        self.required
            .iter()
            .map(|(claim, value)| ((*claim).to_string(), (*value).to_string()))
            .collect()
    }

    /// The complete policy without `claim`.
    fn without(self, claim: &str) -> BTreeMap<String, String> {
        let mut policy = self.complete();
        assert!(policy.remove(claim).is_some(), "{claim} is not required");
        policy
    }

    /// The complete policy with `claim` empty.
    fn emptied(self, claim: &str) -> BTreeMap<String, String> {
        let mut policy = self.complete();
        assert!(
            policy.insert(claim.into(), String::new()).is_some(),
            "{claim} is not required"
        );
        policy
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// A fresh database with the tenant, its workload principal and the two
/// sources, whose destinations the egress fixture allows on the instance
/// it bootstraps.
async fn fixture() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let egress = Egress::bootstrap(&pool).await;
    registry::test_support::create_tenant(
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
    registry::test_support::create_principal(
        &pool,
        &NewPrincipal {
            id: ACTOR.into(),
            tenant_id: TENANT.into(),
            kind: PrincipalKind::Workload,
            name: "release".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (id, name, issuer) in [
        (
            GITHUB_SOURCE,
            "github",
            "https://token.actions.githubusercontent.com",
        ),
        (GENERIC_SOURCE, "generic", "https://idp.example"),
    ] {
        let new = NewTrustSource {
            id: id.into(),
            tenant_id: TENANT.into(),
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
        };
        egress.allow_destinations(&pool, &new).await;
        registry::test_support::create_trust_source(&pool, &new)
            .await
            .unwrap();
    }
    (db, pool)
}

/// A binding `id` of `template` on its source, mapping to the fixture's
/// actor.
fn binding(
    id: &str,
    template: Template,
    policy: BTreeMap<String, String>,
    status: Status,
) -> NewPrincipalBinding {
    NewPrincipalBinding {
        id: id.into(),
        tenant_id: TENANT.into(),
        name: id.into(),
        trust_source_id: template.source.into(),
        profile: template.profile,
        claim_match_policy: policy,
        workload_principal_id: ACTOR.into(),
        status,
    }
}

/// The record `new` describes, at `revision`.
fn record(new: &NewPrincipalBinding, revision: i64) -> PrincipalBinding {
    PrincipalBinding {
        id: new.id.clone(),
        tenant_id: new.tenant_id.clone(),
        name: new.name.clone(),
        trust_source_id: new.trust_source_id.clone(),
        profile: new.profile,
        claim_match_policy: new.claim_match_policy.clone(),
        workload_principal_id: new.workload_principal_id.clone(),
        status: new.status,
        revision,
    }
}

/// Every binding of the tenant, as listed.
async fn listed(pool: &PgPool) -> Vec<PrincipalBinding> {
    registry::list_principal_bindings(pool, TENANT, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap()
}

/// Creates `new` and checks that the registry stored exactly it at
/// revision 1: the created record, the read and the listed one all equal
/// the record `new` describes.
async fn assert_stored(pool: &PgPool, new: &NewPrincipalBinding) -> PrincipalBinding {
    let want = record(new, 1);
    let created = registry::test_support::create_principal_binding(pool, new)
        .await
        .unwrap();
    assert_eq!(created, want);
    assert_eq!(
        registry::get_principal_binding(pool, TENANT, &new.id)
            .await
            .unwrap(),
        want
    );
    assert_eq!(
        listed(pool).await.into_iter().find(|b| b.id == new.id),
        Some(want.clone())
    );
    want
}

/// Binding `id` is neither found nor listed.
async fn assert_absent(pool: &PgPool, id: &str) {
    let read = registry::get_principal_binding(pool, TENANT, id).await;
    assert!(matches!(read, Err(RegistryError::NotFound)), "{read:?}");
    assert!(listed(pool).await.iter().all(|b| b.id != id));
}

/// The stored binding is still exactly `binding`, at its revision, read and
/// listed.
async fn assert_unchanged(pool: &PgPool, binding: &PrincipalBinding) {
    let read = registry::get_principal_binding(pool, TENANT, &binding.id)
        .await
        .unwrap();
    assert_eq!(read.revision, binding.revision);
    assert_eq!(&read, binding);
    assert_eq!(
        listed(pool).await.into_iter().find(|b| b.id == binding.id),
        Some(binding.clone())
    );
}

/// The registry's refusal of a policy that lacks a required predicate of
/// `profile`: `RequiredPredicate`, whose `claim` is one of `claims` and
/// whose `problem` displays as `problem` ("missing" or "empty"), and whose
/// `Display` text names both as whole words (see the module docs, "The
/// refusal").
#[track_caller]
fn assert_refused<T: Debug>(
    result: Result<T, RegistryError>,
    claims: &[&str],
    profile: &str,
    problem: &str,
) {
    let err = match result {
        Err(err @ RegistryError::RequiredPredicate { .. }) => err,
        other => panic!("expected the refusal of {claims:?} of {profile}: {other:?}"),
    };
    let RegistryError::RequiredPredicate {
        claim,
        problem: found,
    } = err
    else {
        unreachable!()
    };
    assert!(
        claims.contains(&claim),
        "{profile}: {claim} is none of {claims:?}"
    );
    assert_eq!(found.to_string(), problem, "{profile}: {claim}");
    let words = format!(" {err} ");
    let names = |word: &str| words.contains(&format!(" {word} "));
    assert!(names(claim), "{err} does not name {claim}");
    assert!(names(problem), "{err} does not say {problem}");
}

/// A refusal of the `0008` check named `check`.
#[track_caller]
fn assert_check(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>, check: &str) {
    match result.map_err(RegistryError::from) {
        Err(RegistryError::Invariant {
            kind: InvariantKind::Check,
            constraint: Some(actual),
        }) => assert_eq!(actual, check),
        other => panic!("expected Invariant {{ Check, {check} }}: {other:?}"),
    }
}

#[tokio::test]
async fn a37_pos_complete_policy_stored_per_profile() {
    let (db, pool) = fixture().await;
    for template in TEMPLATES {
        let new = binding(
            &format!("bnd_{}", template.name),
            template,
            template.complete(),
            Status::Enabled,
        );
        let stored = assert_stored(&pool, &new).await;
        assert_eq!(stored.profile.as_str(), template.name);
        // Exactly the spec's set: no claim added or lost on the way.
        let mut want: Vec<&str> = template.required.iter().map(|(claim, _)| *claim).collect();
        want.sort_unstable();
        let keys: Vec<&str> = stored
            .claim_match_policy
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, want);
    }
    assert_eq!(listed(&pool).await.len(), TEMPLATES.len());
    db.drop([pool]).await;
}

#[tokio::test]
async fn a37_pos_optional_predicate_omitted_is_unconstrained() {
    let (db, pool) = fixture().await;
    let new = binding("bnd_release", GITHUB, GITHUB.complete(), Status::Enabled);
    for optional in [REPOSITORY, JOB_WORKFLOW_REF] {
        assert!(!new.claim_match_policy.contains_key(optional));
    }
    assert_stored(&pool, &new).await;
    registry::test_support::create_service_grant(
        &pool,
        &NewServiceGrant {
            id: "grt_release".into(),
            tenant_id: TENANT.into(),
            name: "release".into(),
            actor_principal_id: ACTOR.into(),
            target_service_id: None,
            mode: GrantMode::Direct,
            scopes: strings(&["deploy"]),
            default_scopes: None,
            resource_constraints: JsonObject::new(),
            max_ttl: 300,
            valid_until: None,
            status: Status::Enabled,
            activation_state: ActivationState::NotRequired,
            allowed_binding_ids: vec![new.id.clone()],
            resource_server_ids: vec![],
        },
    )
    .await
    .unwrap();
    let selection = select_grant(
        &pool,
        TENANT,
        "grt_release",
        GITHUB_SOURCE,
        GrantMode::Direct,
    )
    .await
    .unwrap();
    let [eligible] = selection.eligible_bindings.as_slice() else {
        panic!("{:?}", selection.eligible_bindings);
    };
    assert_eq!(
        (eligible.id.as_str(), eligible.revision),
        ("bnd_release", 1)
    );
    assert_eq!(eligible.claim_match_policy, GITHUB.complete());

    // The verified claims: the required ones with the binding's values,
    // GitHub's `sub` and `actor`, and the optional ones as given.
    let evidence = |optional: &[(&str, &str)]| {
        let mut claims = GITHUB.complete();
        claims.insert(
            "sub".into(),
            "repo:acme/platform:environment:production".into(),
        );
        claims.insert("actor".into(), "octocat".into());
        for (claim, value) in optional {
            claims.insert((*claim).into(), (*value).into());
        }
        Evidence::new(claims)
    };
    // Only `repository` varies. `job_workflow_ref` is absent or equal to
    // `workflow_ref`, so no reusable workflow runs: a token whose
    // `job_workflow_ref` differs is the known gap of the module docs, and
    // no case here has one.
    let workflow_ref = GITHUB.complete()["workflow_ref"].clone();
    for optional in [
        &[
            (REPOSITORY, "acme/platform"),
            (JOB_WORKFLOW_REF, workflow_ref.as_str()),
        ][..],
        &[
            (REPOSITORY, "acme/renamed"),
            (JOB_WORKFLOW_REF, workflow_ref.as_str()),
        ],
        &[(REPOSITORY, "acme/renamed")],
        &[],
    ] {
        let matched = match_binding(&selection.eligible_bindings, &evidence(optional));
        assert_eq!(
            matched.map(|b| (b.id.as_str(), b.revision)),
            Some(("bnd_release", 1)),
            "{optional:?}"
        );
    }
    // A required predicate still constrains: another ref matches nothing.
    let mut other_ref = GITHUB.complete();
    other_ref.insert("ref".into(), "refs/heads/feature".into());
    assert_eq!(
        match_binding(&selection.eligible_bindings, &Evidence::new(other_ref)),
        None
    );
    db.drop([pool]).await;
}

#[tokio::test]
async fn a37_neg_required_predicate_missing_refused() {
    let (db, pool) = fixture().await;
    for template in TEMPLATES {
        let id = format!("bnd_{}", template.name);
        for (claim, _) in template.required {
            for status in [Status::Enabled, Status::Disabled] {
                let new = binding(&id, template, template.without(claim), status);
                assert_refused(
                    registry::test_support::create_principal_binding(&pool, &new).await,
                    &[claim],
                    template.name,
                    "missing",
                );
                assert_absent(&pool, &id).await;
            }
        }
    }
    assert_eq!(listed(&pool).await, []);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a37_neg_required_predicate_empty_refused() {
    let (db, pool) = fixture().await;
    for template in TEMPLATES {
        let id = format!("bnd_{}", template.name);
        for (claim, _) in template.required {
            for status in [Status::Enabled, Status::Disabled] {
                let new = binding(&id, template, template.emptied(claim), status);
                assert_refused(
                    registry::test_support::create_principal_binding(&pool, &new).await,
                    &[claim],
                    template.name,
                    "empty",
                );
                assert_absent(&pool, &id).await;
            }
        }
    }
    assert_eq!(listed(&pool).await, []);
    db.drop([pool]).await;
}

/// Dropping or emptying each required claim of a stored binding, enabled
/// or disabled, and whether the update keeps or flips its status.
#[tokio::test]
async fn a37_neg_required_predicate_removed_by_update_refused() {
    let (db, pool) = fixture().await;
    for template in TEMPLATES {
        for stored_status in [Status::Enabled, Status::Disabled] {
            let new = binding(
                &format!("bnd_{}_{stored_status}", template.name),
                template,
                template.complete(),
                stored_status,
            );
            let stored = assert_stored(&pool, &new).await;
            for (claim, _) in template.required {
                for (policy, problem) in [
                    (template.without(claim), "missing"),
                    (template.emptied(claim), "empty"),
                ] {
                    for status in [Status::Enabled, Status::Disabled] {
                        let changes = PrincipalBindingChanges {
                            name: stored.name.clone(),
                            profile: stored.profile,
                            claim_match_policy: policy.clone(),
                            status,
                        };
                        assert_refused(
                            registry::test_support::update_principal_binding(
                                &pool,
                                TENANT,
                                &stored.id,
                                stored.revision,
                                &changes,
                            )
                            .await,
                            &[claim],
                            template.name,
                            problem,
                        );
                        assert_unchanged(&pool, &stored).await;
                    }
                }
            }
        }
    }
    db.drop([pool]).await;
}

/// A `generic_production` binding of only `sub` moved to
/// `github_production` or `kubernetes_production`: with `sub` alone, and
/// with the new set less one claim each, enabled or disabled.
#[tokio::test]
async fn a37_neg_profile_change_needs_new_required_set() {
    let (db, pool) = fixture().await;
    let new = binding("bnd_generic", GENERIC, GENERIC.complete(), Status::Enabled);
    let stored = assert_stored(&pool, &new).await;
    assert_eq!(stored.claim_match_policy.len(), 1);
    for target in [GITHUB, KUBERNETES] {
        let target_claims: Vec<&str> = target.required.iter().map(|(claim, _)| *claim).collect();
        let mut attempts = vec![(GENERIC.complete(), target_claims.clone())];
        for claim in &target_claims {
            let mut policy = target.without(claim);
            policy.extend(GENERIC.complete());
            attempts.push((policy, vec![*claim]));
        }
        for (policy, claims) in attempts {
            for status in [Status::Enabled, Status::Disabled] {
                let changes = PrincipalBindingChanges {
                    name: stored.name.clone(),
                    profile: target.profile,
                    claim_match_policy: policy.clone(),
                    status,
                };
                assert_refused(
                    registry::test_support::update_principal_binding(
                        &pool,
                        TENANT,
                        &stored.id,
                        stored.revision,
                        &changes,
                    )
                    .await,
                    &claims,
                    target.name,
                    "missing",
                );
                assert_unchanged(&pool, &stored).await;
            }
        }
    }
    db.drop([pool]).await;
}

const RAW_INSERT: &str = "INSERT INTO principal_binding \
     (id, tenant_id, name, trust_source_id, profile, claim_match_policy, \
     workload_principal_id, status) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)";
const RAW_UPDATE: &str = "UPDATE principal_binding \
     SET profile = $1, claim_match_policy = $2::jsonb, revision = revision + 1 \
     WHERE tenant_id = $3 AND id = $4";

/// `policy` as JSON, with an optional predicate added, so that it is never
/// empty: an empty policy (`generic_production` without `sub`) would fail
/// the `0004` check `principal_binding_claim_match_policy_check` too, which
/// PostgreSQL tests first (checks run in name order), and hide the `0008`
/// one.
fn json(policy: &BTreeMap<String, String>) -> String {
    let mut policy = policy.clone();
    policy.insert("actor".into(), "octocat".into());
    serde_json::to_string(&policy).unwrap()
}

/// Writes past the registry, as an operator with SQL access or a bug in a
/// future writer would: each is refused by the `0008` check of the row's
/// profile, mapped to `Invariant { Check, <check> }`, and changes nothing.
#[tokio::test]
async fn a37_neg_store_refuses_incomplete_policy() {
    let (db, pool) = fixture().await;
    let mut stored = Vec::new();
    for template in TEMPLATES {
        for status in [Status::Enabled, Status::Disabled] {
            let new = binding(
                &format!("bnd_{}_{status}", template.name),
                template,
                template.complete(),
                status,
            );
            stored.push((template, assert_stored(&pool, &new).await));
        }
    }
    for (template, row) in &stored {
        for (claim, _) in template.required {
            for policy in [template.without(claim), template.emptied(claim)] {
                for status in [Status::Enabled, Status::Disabled] {
                    assert_check(
                        sqlx::query(RAW_INSERT)
                            .bind("bnd_raw")
                            .bind(TENANT)
                            .bind("raw")
                            .bind(template.source)
                            .bind(template.name)
                            .bind(json(&policy))
                            .bind(ACTOR)
                            .bind(status.as_str())
                            .execute(&pool)
                            .await,
                        template.check,
                    );
                    assert_absent(&pool, "bnd_raw").await;
                }
                assert_check(
                    sqlx::query(RAW_UPDATE)
                        .bind(template.name)
                        .bind(json(&policy))
                        .bind(TENANT)
                        .bind(&row.id)
                        .execute(&pool)
                        .await,
                    template.check,
                );
                assert_unchanged(&pool, row).await;
            }
        }
    }
    // A `generic_production` row moved to another profile with only `sub`.
    for (template, row) in &stored {
        if template.name != GENERIC.name {
            continue;
        }
        for target in [GITHUB, KUBERNETES] {
            assert_check(
                sqlx::query(RAW_UPDATE)
                    .bind(target.name)
                    .bind(json(&GENERIC.complete()))
                    .bind(TENANT)
                    .bind(&row.id)
                    .execute(&pool)
                    .await,
                target.check,
            );
            assert_unchanged(&pool, row).await;
        }
    }
    db.drop([pool]).await;
}
