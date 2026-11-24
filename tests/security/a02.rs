//! A02: GitHub event-context escalation. Expected: an otherwise-matching
//! non-push or missing event, and a wrong owner, repository, ref,
//! environment or workflow, are denied; a production binding cannot be
//! satisfied by pull request, dispatch, comment or `workflow_run` context
//! (tasks §8; T12.2, T12.7, T22.5, T52.2).
//!
//! **A02 partial: these tests are registered on A02's planned M1a stage
//! ("policy on verified-claim fixtures"), so they are no evidence for it:
//! the reporter lists their results as not counted, and the stage stays
//! `planned` with no stamp.** They test the policy half of the stage only:
//! `registry::select_grant`, then `policy::match_binding` (ADR-015 item 4
//! steps 1, 3 and 4; design section 5.3 and section 5.7; ADR-016 item 1)
//! against a real PostgreSQL, one fresh database per test, seeded through
//! the typed registry API by the shared fixture
//! (`tests/security/selection_fixture.rs`). Every test runs in both
//! tenants, for each of the four grants of a tenant, on both GitHub-issuer
//! sources (`src_gh` and `src_alt`), where each grant has exactly one
//! eligible `github_production` binding.
//!
//! **The evidence is an inferred shape, and nothing verifies it.**
//! `policy::Evidence` is a map of claim name to string value, which
//! `service/src/policy/matching.rs` marks inferred: "the verifier, T11.x,
//! does not exist yet, so this is the smallest shape matching needs". The
//! GitHub verifier (T22.2: issuer, signature, audience and time; immutable
//! owner and repository IDs; explicit event, ref, environment, workflow and
//! reusable-workflow context) does not exist, so the claim sets here are
//! written by hand as the verified claims it is expected to hand over, not
//! decoded from any token. A real token's claim names, value spellings and
//! types (a number-valued ID, for instance) may differ from these strings;
//! when the verifier lands, these tables must be rebuilt from its output.
//!
//! **The claim-mutation table.** The push claim set ([`PUSH_CLAIMS`]) is
//! the binding's policy, written out here and pinned against the stored
//! binding, so a fixture change fails these tests rather than move them:
//! a push to `refs/heads/main` of `example/release` (owner ID `123456`,
//! repository ID `987654`) in the `production` environment, by the
//! `deploy.yml` workflow at `refs/heads/main`. Each case changes or removes
//! only the claims it names and keeps every other claim equal, so each
//! negative is "otherwise matching" (T22.5): a real `pull_request` token
//! would also carry another `ref` and `sub`, but then the `ref` predicate
//! alone would deny it and the `event_name` predicate would go untested.
//! Every case runs on two bases: exactly the push claim set, and the same
//! with claims no predicate names ([`UNNAMED_CLAIMS`]), as a real token
//! has. Each test first matches the unchanged base (the in-test control),
//! so a no-match can only come from the change.
//!
//! - **Positive.** The exact push claim set, and the same with unnamed
//!   claims, match the grant's own binding, as stored (ID, policy and
//!   revision) (`a02_pos_push_claims_match_the_push_binding`).
//! - **Negative.** Each gives no binding, `None`, while the selection still
//!   succeeds with the same one eligible binding: `event_name` set to
//!   `pull_request` (`a02_neg_pull_request_against_push_binding`),
//!   `pull_request_target`
//!   (`a02_neg_pull_request_target_against_push_binding`),
//!   `workflow_dispatch` (`a02_neg_workflow_dispatch_against_push_binding`),
//!   `issue_comment` (`a02_neg_issue_comment_against_push_binding`) or
//!   `workflow_run` (`a02_neg_workflow_run_against_push_binding`);
//!   `event_name` absent or empty
//!   (`a02_neg_missing_event_name_against_push_binding`); a wrong or absent
//!   owner ID, another owner in `repository`, or a same-named repository of
//!   another owner (`a02_neg_wrong_owner_against_push_binding`); a wrong or
//!   absent repository ID, another repository name of the same owner, or a
//!   sibling repository (`a02_neg_wrong_repo_against_push_binding`); another
//!   branch, a tag (`event_name` still `push`), a pull request merge ref,
//!   the short `main`, or no `ref` (`a02_neg_wrong_ref_against_push_binding`);
//!   another, a case-variant or no environment
//!   (`a02_neg_wrong_environment_against_push_binding`); and another
//!   workflow file, the same file at another ref or in another repository,
//!   or no `workflow_ref` (`a02_neg_wrong_workflow_against_push_binding`).
//!
//! Byte-wise exact comparison (the case-variant environment, the short
//! `main`) is ADR-016 item 1 and design section 5.3: no case folding,
//! prefix or wildcard. The generic near-miss matrices (case, trailing
//! space, near-miss claim names) are A50's and the service tests'
//! (`service/tests/registry_selection.rs`); that a `github_production`
//! binding cannot omit any of these predicates is A37's.
//!
//! **What remains of A02 M1a** before it can be implemented and stamped:
//!
//! - the GitHub verifier (T22.2) that turns a token into verified claims,
//!   and with it the final shape of `Evidence`, which may move these
//!   tables;
//! - the GH harness component (mock GitHub OIDC) and the "verified-claim
//!   fixtures" the stage's scope names: tokens of each event, verified at
//!   the selected source, so the cases come from the verifier rather than
//!   from hand-written maps (as shared fixtures, `tests/conformance/
//!   fixtures/a02/`, if the stage takes FX fixtures; layout §1.3);
//! - the reusable-workflow identity (`job_workflow_ref`; ADR-016 item 3,
//!   T22.2), which no `github_production` binding in the fixture names, so
//!   no case here changes it, and the fork and pull-request context of
//!   T22.5 beyond `event_name`;
//! - a review of the stage against its §8 row once the verifier exists
//!   (the lead's ruling: no stamp and no row edit until then).
//!
//! Not A02 M1a's: the exchange and its wire denial (`invalid_grant`), and
//! the live negative, the real token of a `schedule` or
//! `workflow_dispatch` run denied by the push-only binding in
//! `live-wif-negative`, which are A02's M2 stage.

use std::collections::BTreeMap;

use skyoauth_service::{
    persistence::{
        PgPool,
        registry::{self, BindingProfile, Selection, Status, select_grant},
    },
    policy::{EligibleBinding, Evidence, match_binding},
};

use super::selection_fixture::{A, B, GRANTS, Grant, Side, Source, two_tenants};

/// The push claim set: the predicates of every `github_production` binding
/// of the fixture, a push to `main` of `example/release` in `production`.
/// Written out here, not read from the fixture.
const PUSH_CLAIMS: [(&str, &str); 7] = [
    ("repository_owner_id", "123456"),
    ("repository_id", "987654"),
    ("repository", "example/release"),
    ("event_name", "push"),
    ("ref", "refs/heads/main"),
    ("environment", "production"),
    (
        "workflow_ref",
        "example/release/.github/workflows/deploy.yml@refs/heads/main",
    ),
];

/// Claims of a push token that no predicate names.
const UNNAMED_CLAIMS: [(&str, &str); 3] = [
    ("sub", "repo:example/release:environment:production"),
    ("actor", "octocat"),
    ("run_id", "4711"),
];

/// The GitHub-issuer sources, each with one eligible `github_production`
/// binding per grant.
const GITHUB_SOURCES: [Source; 2] = [Source::Github, Source::Alt];

fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(claim, value)| (claim.to_string(), value.to_string()))
        .collect()
}

/// The bases every case is applied to: (name, claims).
fn bases() -> [(&'static str, BTreeMap<String, String>); 2] {
    let mut with_unnamed = claims(&PUSH_CLAIMS);
    with_unnamed.extend(claims(&UNNAMED_CLAIMS));
    [
        ("exact push claims", claims(&PUSH_CLAIMS)),
        ("push claims with unnamed claims", with_unnamed),
    ]
}

/// One change to a claim set.
#[derive(Clone, Copy, Debug)]
enum Change {
    /// Set the claim to this value.
    Set(&'static str, &'static str),
    /// Remove the claim.
    Remove(&'static str),
}

impl Change {
    fn claim(self) -> &'static str {
        match self {
            Self::Set(claim, _) | Self::Remove(claim) => claim,
        }
    }
}

/// A row of the claim-mutation table: a name and its changes.
type Case = (&'static str, &'static [Change]);

/// `base` with `changes` applied.
fn mutated(base: &BTreeMap<String, String>, changes: &[Change]) -> BTreeMap<String, String> {
    let mut claims = base.clone();
    for change in changes {
        match *change {
            Change::Set(claim, value) => {
                claims.insert(claim.into(), value.into());
            }
            Change::Remove(claim) => {
                claims.remove(claim);
            }
        }
    }
    claims
}

/// The claims whose value differs between `a` and `b`, present in one only
/// included.
fn differing(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> Vec<String> {
    let mut names: Vec<String> = a
        .keys()
        .chain(b.keys())
        .filter(|claim| a.get(*claim) != b.get(*claim))
        .cloned()
        .collect();
    names.sort();
    names.dedup();
    names
}

/// A grant of the fixture selected on a GitHub-issuer source, with the
/// stored binding it must match.
struct Target {
    /// Tenant, grant and source, for messages.
    label: String,
    selection: Selection,
    /// The stored binding as an eligible binding carries it.
    binding: EligibleBinding,
}

/// Selects `grant` of `side` on `source` and checks the fixture's
/// preconditions: the selection succeeds with exactly one eligible binding,
/// the grant's own, a stored, enabled `github_production` binding of the
/// grant's actor whose policy is exactly [`PUSH_CLAIMS`].
async fn target(pool: &PgPool, side: Side, grant: Grant, source: Source) -> Target {
    let label = format!("{} {} {}", side.tenant, side.id(grant.id), source.id(side));
    let selection = select_grant(
        pool,
        side.tenant,
        &side.id(grant.id),
        &source.id(side),
        grant.mode,
    )
    .await
    .unwrap_or_else(|err| panic!("{label}: {err:?}"));
    let stored =
        registry::get_principal_binding(pool, side.tenant, &side.id(grant.eligible_on(source)))
            .await
            .unwrap();
    assert_eq!(stored.profile, BindingProfile::GithubProduction, "{label}");
    assert_eq!(stored.status, Status::Enabled, "{label}");
    assert_eq!(
        stored.workload_principal_id,
        side.id(grant.actor),
        "{label}"
    );
    assert_eq!(stored.trust_source_id, source.id(side), "{label}");
    assert_eq!(stored.claim_match_policy, claims(&PUSH_CLAIMS), "{label}");
    assert_eq!(stored.claim_match_policy["event_name"], "push", "{label}");
    let binding = EligibleBinding {
        id: stored.id,
        claim_match_policy: stored.claim_match_policy,
        revision: stored.revision,
    };
    assert_eq!(
        selection.eligible_bindings,
        std::slice::from_ref(&binding),
        "{label}"
    );
    Target {
        label,
        selection,
        binding,
    }
}

/// Every grant of both tenants on both GitHub-issuer sources.
async fn targets(pool: &PgPool) -> Vec<Target> {
    let mut targets = Vec::new();
    for side in [A, B] {
        for grant in GRANTS {
            for source in GITHUB_SOURCES {
                targets.push(target(pool, side, grant, source).await);
            }
        }
    }
    targets
}

/// For every target and base: the unchanged base matches the target's
/// binding (the control), and each case, which differs from the base in
/// exactly the claims it names, matches nothing.
async fn assert_every_case_matches_nothing(cases: &[Case]) {
    let (db, pool) = two_tenants().await;
    let targets = targets(&pool).await;
    assert_eq!(targets.len(), 16);
    for target in &targets {
        let eligible = &target.selection.eligible_bindings;
        for (base_name, base) in bases() {
            let label = format!("{} {base_name}", target.label);
            assert_eq!(
                match_binding(eligible, &Evidence::new(base.clone())),
                Some(&target.binding),
                "{label}: control"
            );
            for (name, changes) in cases {
                let changed = mutated(&base, changes);
                let mut named: Vec<String> = changes
                    .iter()
                    .map(|change| change.claim().to_string())
                    .collect();
                named.sort();
                named.dedup();
                assert_eq!(differing(&base, &changed), named, "{label} {name}");
                assert_eq!(
                    match_binding(eligible, &Evidence::new(changed)),
                    None,
                    "{label} {name}"
                );
            }
        }
    }
    db.drop([pool]).await;
}

/// The exact push claim set, and the same with claims no predicate names,
/// match the grant's own push binding, as stored, for every grant of both
/// tenants on both GitHub-issuer sources.
#[tokio::test]
async fn a02_pos_push_claims_match_the_push_binding() {
    let (db, pool) = two_tenants().await;
    let targets = targets(&pool).await;
    assert_eq!(targets.len(), 16);
    for target in &targets {
        for (base_name, base) in bases() {
            assert_eq!(base["event_name"], "push");
            assert_eq!(
                match_binding(&target.selection.eligible_bindings, &Evidence::new(base)),
                Some(&target.binding),
                "{} {base_name}",
                target.label
            );
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a02_neg_pull_request_against_push_binding() {
    assert_every_case_matches_nothing(&[(
        "pull_request",
        &[Change::Set("event_name", "pull_request")],
    )])
    .await;
}

#[tokio::test]
async fn a02_neg_pull_request_target_against_push_binding() {
    assert_every_case_matches_nothing(&[(
        "pull_request_target",
        &[Change::Set("event_name", "pull_request_target")],
    )])
    .await;
}

#[tokio::test]
async fn a02_neg_workflow_dispatch_against_push_binding() {
    assert_every_case_matches_nothing(&[(
        "workflow_dispatch",
        &[Change::Set("event_name", "workflow_dispatch")],
    )])
    .await;
}

#[tokio::test]
async fn a02_neg_issue_comment_against_push_binding() {
    assert_every_case_matches_nothing(&[(
        "issue_comment",
        &[Change::Set("event_name", "issue_comment")],
    )])
    .await;
}

#[tokio::test]
async fn a02_neg_workflow_run_against_push_binding() {
    assert_every_case_matches_nothing(&[(
        "workflow_run",
        &[Change::Set("event_name", "workflow_run")],
    )])
    .await;
}

#[tokio::test]
async fn a02_neg_missing_event_name_against_push_binding() {
    assert_every_case_matches_nothing(&[
        ("event_name absent", &[Change::Remove("event_name")]),
        ("event_name empty", &[Change::Set("event_name", "")]),
    ])
    .await;
}

#[tokio::test]
async fn a02_neg_wrong_owner_against_push_binding() {
    assert_every_case_matches_nothing(&[
        (
            "other owner ID",
            &[Change::Set("repository_owner_id", "654321")],
        ),
        ("owner ID absent", &[Change::Remove("repository_owner_id")]),
        (
            "other owner in repository",
            &[Change::Set("repository", "attacker/release")],
        ),
        (
            "same-named repository of another owner",
            &[
                Change::Set("repository_owner_id", "654321"),
                Change::Set("repository_id", "135791"),
                Change::Set("repository", "attacker/release"),
                Change::Set(
                    "workflow_ref",
                    "attacker/release/.github/workflows/deploy.yml@refs/heads/main",
                ),
            ],
        ),
    ])
    .await;
}

#[tokio::test]
async fn a02_neg_wrong_repo_against_push_binding() {
    assert_every_case_matches_nothing(&[
        (
            "other repository ID",
            &[Change::Set("repository_id", "987655")],
        ),
        ("repository ID absent", &[Change::Remove("repository_id")]),
        (
            "other repository name",
            &[Change::Set("repository", "example/release-fork")],
        ),
        (
            "sibling repository of the same owner",
            &[
                Change::Set("repository_id", "975318"),
                Change::Set("repository", "example/tools"),
                Change::Set(
                    "workflow_ref",
                    "example/tools/.github/workflows/deploy.yml@refs/heads/main",
                ),
            ],
        ),
    ])
    .await;
}

#[tokio::test]
async fn a02_neg_wrong_ref_against_push_binding() {
    assert_every_case_matches_nothing(&[
        ("other branch", &[Change::Set("ref", "refs/heads/dev")]),
        ("tag push", &[Change::Set("ref", "refs/tags/v1.0.0")]),
        (
            "pull request merge ref",
            &[Change::Set("ref", "refs/pull/1/merge")],
        ),
        ("short branch name", &[Change::Set("ref", "main")]),
        ("ref absent", &[Change::Remove("ref")]),
    ])
    .await;
}

#[tokio::test]
async fn a02_neg_wrong_environment_against_push_binding() {
    assert_every_case_matches_nothing(&[
        (
            "other environment",
            &[Change::Set("environment", "staging")],
        ),
        (
            "case-variant environment",
            &[Change::Set("environment", "Production")],
        ),
        ("environment absent", &[Change::Remove("environment")]),
    ])
    .await;
}

#[tokio::test]
async fn a02_neg_wrong_workflow_against_push_binding() {
    assert_every_case_matches_nothing(&[
        (
            "other workflow file",
            &[Change::Set(
                "workflow_ref",
                "example/release/.github/workflows/other.yml@refs/heads/main",
            )],
        ),
        (
            "same workflow at another ref",
            &[Change::Set(
                "workflow_ref",
                "example/release/.github/workflows/deploy.yml@refs/heads/dev",
            )],
        ),
        (
            "same workflow path in another repository",
            &[Change::Set(
                "workflow_ref",
                "example/tools/.github/workflows/deploy.yml@refs/heads/main",
            )],
        ),
        ("workflow_ref absent", &[Change::Remove("workflow_ref")]),
    ])
    .await;
}
