//! A50: repo-wide and deployment binding map different actors; selected
//! grant owns one. Expected: the matching eligible binding of the grant's
//! actor succeeds and another actor's overlap is irrelevant; no eligible
//! match denies; several same-actor matches are deterministic, with no
//! union (tasks §8; T12.3, T21.4, T21.7).
//!
//! Stage M1a, "binding matching: the grant actor's eligible binding matches
//! despite another actor's overlap; an other-actor-only, ineligible or
//! absent match selects none; several same-actor matches select the
//! byte-wise lowest ID, one binding, never a union (registry API)":
//! `registry::select_grant`, then `policy::match_binding` (ADR-015 item 4
//! steps 1, 3 and 4; design section 5.7 and section 5.3; ADR-016 item 1)
//! against a real PostgreSQL, one fresh database per test, seeded through
//! the typed registry API by the shared fixture
//! (`tests/security/selection_fixture.rs`, "The A50 additions"). Every test
//! runs in both tenants.
//!
//! The overlap is built on the partner CI's source, `src_gen`, with
//! `generic_production` bindings: the repository-wide binding `bnd_0_repo`
//! of `wld_b` (`sub` and `repository_id`) and the deployment binding
//! `bnd_m2` of `wld_a` (the same and `environment`), so evidence of a
//! production deployment fits both, and `wld_b`'s sorts first. A
//! `github_production` binding cannot express a repository-wide binding:
//! its template requires `ref`, `environment` and `workflow_ref` (ADR-016
//! item 3). The ADR-016 item 4 check that a binding's template fits its
//! source and its `assertion_profile` is not built; once it is, it may
//! refuse this pairing of `generic_production` bindings with a
//! `reusable_jwt` OIDC source, and this overlap would have to be rebuilt
//! on whatever pairing it accepts. The fixture keeps its rule:
//! `github_production` only on GitHub-issuer sources, `generic_production`
//! only on non-GitHub ones.
//!
//! - **Positive.** Evidence that fits the deployment binding of `wld_a` and
//!   the repository-wide binding of `wld_b`, whose ID sorts first, gives
//!   each actor's grant its own actor's binding, as stored, and neither is
//!   an error (`a50_pos_grant_actors_binding_matches_despite_other_actors_overlap`).
//! - **Negative.** Evidence that only `wld_b`'s binding fits gives no
//!   binding for the grants of `wld_a`, with no fallback to it
//!   (`a50_neg_only_other_actors_binding_matches_gives_none`). Evidence
//!   with a differing value, a missing claim, or a value that differs only
//!   in case or by a trailing space gives no binding, and a grant whose
//!   actor has no eligible binding on the source selects nothing
//!   (`a50_neg_no_eligible_match`). Bindings of the grant's actor that fit
//!   the evidence and sort first but are disabled, not listed by the grant,
//!   or on another source are never returned
//!   (`a50_neg_ineligible_bindings_never_match`). Two matching bindings of
//!   one actor give the one with the byte-wise lowest ID, with its own
//!   stored policy and current revision, never a merge of the two, in every
//!   input order and on every selection
//!   (`a50_neg_several_same_actor_matches_give_one_stable_id_no_union`).
//!
//! **Precedence.** Design section 5.7 item 4 says that several eligible
//! bindings of the same actor are ordered by "stable ID ordering" without
//! defining it. "Lowest ID wins", in ascending byte order of the binding ID
//! as `service/src/policy/matching.rs` builds it, is the lead's reading
//! (provisional), and it is the only precedence tested.
//! Specificity is deliberately not tested: the spec says nothing about it.
//! The two same-actor bindings that the same evidence fits therefore have
//! neutral names, `bnd_m1` and `bnd_m2`, that differ only in byte order and
//! say nothing about either policy, and they are equally specific and not
//! comparable: `bnd_m1` names `sub`, `repository_id` and `ref`, `bnd_m2`
//! names `sub`, `repository_id` and `environment`, so neither is a subset
//! of the other. No ordering by specificity can tell them apart, and a rule
//! that ranks specificity first and breaks ties by ID passes these tests as
//! well as plain ID order does. The tests also cannot tell byte order from
//! a case-insensitive order: on every pair of binding IDs they compare, the
//! two orders agree. This is deliberate: they do not lock the provisional
//! reading in any further than "the lowest ID wins".
//!
//! Not covered here: the matching matrices of the service tests
//! (`service/tests/registry_selection.rs`: every predicate present and
//! equal, near-miss claim names and values, an empty policy, and
//! permutations of hand-built binding lists;
//! `service/tests/registry_predicates.rs`: required predicates, empty and
//! whitespace-only values), and a listed binding of another actor, which
//! the `0004` foreign keys refuse (ADR-022 item 13), so the statement's
//! actor recheck is observable only with the keys dropped
//! (`selection_rechecks_the_tenant_and_actor_the_foreign_keys_guarantee`).
//! The M2 stage: the denial on the wire, the selected binding and its
//! revision recorded in the policy revision and audit, and that the issued
//! permissions are the grant's, never a union over bindings.

use std::collections::BTreeMap;

use skyoauth_service::{
    persistence::{
        PgPool,
        registry::{
            self, BindingProfile, GrantMode, Page, PrincipalBinding, PrincipalBindingChanges,
            Selection, SelectionError, Status, select_grant,
        },
    },
    policy::{EligibleBinding, Evidence, match_binding},
};

use super::selection_fixture::{
    A, B, GRANT_A_MATCH, GRANT_A_MULTI, GRANT_B_MATCH, MATCHING_GRANTS, MatchingGrant,
    OTHER_REPOSITORY_ID, REPOSITORY_ID, SECOND_GENERIC, Side, deployment_claims,
    deployment_evidence, other_repository_evidence, two_tenants_with_matching,
};

/// The ID base of the partner CI's first source.
const GENERIC: &str = "src_gen";

async fn select(
    pool: &PgPool,
    side: Side,
    grant: MatchingGrant,
    source: &str,
) -> Result<Selection, SelectionError> {
    select_grant(
        pool,
        side.tenant,
        &side.id(grant.id),
        &side.id(source),
        GrantMode::Direct,
    )
    .await
}

/// `grant` of `side` on `source` of `side`: selected.
async fn select_own(pool: &PgPool, side: Side, grant: MatchingGrant, source: &str) -> Selection {
    select(pool, side, grant, source)
        .await
        .unwrap_or_else(|err| panic!("{} {} {source}: {err:?}", side.tenant, grant.id))
}

/// The IDs of a selection's eligible bindings, in their order.
fn ids(selection: &Selection) -> Vec<&str> {
    selection
        .eligible_bindings
        .iter()
        .map(|binding| binding.id.as_str())
        .collect()
}

/// A stored binding as an eligible binding carries it.
fn eligible(binding: &PrincipalBinding) -> EligibleBinding {
    EligibleBinding {
        id: binding.id.clone(),
        claim_match_policy: binding.claim_match_policy.clone(),
        revision: binding.revision,
    }
}

/// Whether `evidence` has every predicate of `binding`'s stored policy with
/// exactly its value: the matching rule, restated here so that the
/// fixture's preconditions do not rest on the code under test.
fn fits(binding: &PrincipalBinding, evidence: &Evidence) -> bool {
    policy_fits(&binding.claim_match_policy, evidence)
}

/// [`fits`] for a policy on its own.
fn policy_fits(policy: &BTreeMap<String, String>, evidence: &Evidence) -> bool {
    !policy.is_empty()
        && policy
            .iter()
            .all(|(claim, value)| evidence.get(claim) == Some(value.as_str()))
}

async fn stored(pool: &PgPool, side: Side, base: &str) -> PrincipalBinding {
    registry::get_principal_binding(pool, side.tenant, &side.id(base))
        .await
        .unwrap()
}

/// Every binding of `side`, enabled or not, listed or not.
async fn all_bindings(pool: &PgPool, side: Side) -> Vec<PrincipalBinding> {
    registry::list_principal_bindings(pool, side.tenant, Page::first(registry::MAX_PAGE_SIZE))
        .await
        .unwrap()
}

/// `matched` is the stored binding `base` of `side`, of workload `actor`,
/// with its stored policy and revision.
async fn assert_is_stored(
    pool: &PgPool,
    side: Side,
    matched: Option<&EligibleBinding>,
    base: &str,
    actor: &str,
    case: &str,
) {
    let own = stored(pool, side, base).await;
    assert_eq!(own.workload_principal_id, side.id(actor), "{case}");
    assert_eq!(matched, Some(&eligible(&own)), "{case}");
}

/// The evidence of a production deployment of the repository fits the
/// deployment binding of `wld_a` (`bnd_m2`) and the repository-wide
/// binding of `wld_b` (`bnd_0_repo`), whose ID sorts first. Each grant gets
/// its own actor's binding.
#[tokio::test]
async fn a50_pos_grant_actors_binding_matches_despite_other_actors_overlap() {
    let (db, pool) = two_tenants_with_matching().await;
    let evidence = deployment_evidence();
    for side in [A, B] {
        let t = side.tenant;
        // The overlap: both bindings fit, on the same source, and the other
        // actor's sorts first.
        let (of_a, of_b) = (
            stored(&pool, side, "bnd_m2").await,
            stored(&pool, side, "bnd_0_repo").await,
        );
        assert_eq!(
            (of_a.trust_source_id.as_str(), of_b.trust_source_id.as_str()),
            (side.id(GENERIC).as_str(), side.id(GENERIC).as_str()),
            "{t}"
        );
        assert_eq!(of_a.profile, BindingProfile::GenericProduction, "{t}");
        assert_eq!(of_b.profile, BindingProfile::GenericProduction, "{t}");
        assert!(fits(&of_a, &evidence), "{t}");
        assert!(fits(&of_b, &evidence), "{t}");
        assert!(of_b.id.as_bytes() < of_a.id.as_bytes(), "{t}");
        // The repository-wide binding names a subset of the deployment's
        // predicates.
        assert!(
            of_b.claim_match_policy
                .iter()
                .all(|(claim, value)| of_a.claim_match_policy.get(claim) == Some(value))
                && of_b.claim_match_policy.len() < of_a.claim_match_policy.len(),
            "{t}"
        );

        let grant_a = select_own(&pool, side, GRANT_A_MATCH, GENERIC).await;
        let grant_b = select_own(&pool, side, GRANT_B_MATCH, GENERIC).await;
        assert_eq!(grant_a.grant.actor_principal_id, side.id("wld_a"), "{t}");
        assert_eq!(grant_b.grant.actor_principal_id, side.id("wld_b"), "{t}");
        let case = format!("{t} {}", side.id(GRANT_A_MATCH.id));
        assert_is_stored(
            &pool,
            side,
            match_binding(&grant_a.eligible_bindings, &evidence),
            "bnd_m2",
            "wld_a",
            &case,
        )
        .await;
        let case = format!("{t} {}", side.id(GRANT_B_MATCH.id));
        assert_is_stored(
            &pool,
            side,
            match_binding(&grant_b.eligible_bindings, &evidence),
            "bnd_0_repo",
            "wld_b",
            &case,
        )
        .await;
        // Over both grants' bindings at once, the lowest fitting ID is the
        // other actor's, so a matcher that ignored the actor would choose
        // it for wld_a: the overlap is real. Computed here, not by
        // `match_binding`, so that this precondition takes no side on how
        // a binding with fewer predicates ranks against one with more.
        let lowest_fitting = grant_a
            .eligible_bindings
            .iter()
            .chain(&grant_b.eligible_bindings)
            .filter(|binding| policy_fits(&binding.claim_match_policy, &evidence))
            .map(|binding| binding.id.as_str())
            .min_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(lowest_fitting, Some(of_b.id.as_str()), "{t}");
    }
    db.drop([pool]).await;
}

/// Evidence of another repository fits `wld_b`'s `bnd_b_other` and no
/// binding of `wld_a`: the grants of `wld_a` are selected, but match
/// nothing, and do not fall back to `wld_b`'s binding.
#[tokio::test]
async fn a50_neg_only_other_actors_binding_matches_gives_none() {
    let (db, pool) = two_tenants_with_matching().await;
    let evidence = other_repository_evidence();
    for side in [A, B] {
        let t = side.tenant;
        // Of every binding of the tenant, enabled or not, listed or not,
        // only wld_b's bnd_b_other fits.
        let fitting: Vec<(String, String)> = all_bindings(&pool, side)
            .await
            .iter()
            .filter(|binding| fits(binding, &evidence))
            .map(|binding| (binding.id.clone(), binding.workload_principal_id.clone()))
            .collect();
        assert_eq!(fitting, [(side.id("bnd_b_other"), side.id("wld_b"))], "{t}");
        assert_eq!(
            stored(&pool, side, "bnd_b_other").await.claim_match_policy["repository_id"],
            OTHER_REPOSITORY_ID,
            "{t}"
        );
        for grant in [GRANT_A_MATCH, GRANT_A_MULTI] {
            let selected = select_own(&pool, side, grant, GENERIC).await;
            let case = format!("{t} {}", side.id(grant.id));
            assert_eq!(
                match_binding(&selected.eligible_bindings, &evidence),
                None,
                "{case}"
            );
            // The same grant matches the evidence of its own repository.
            assert!(
                match_binding(&selected.eligible_bindings, &deployment_evidence()).is_some(),
                "{case}"
            );
        }
        let grant_b = select_own(&pool, side, GRANT_B_MATCH, GENERIC).await;
        assert_is_stored(
            &pool,
            side,
            match_binding(&grant_b.eligible_bindings, &evidence),
            "bnd_b_other",
            "wld_b",
            &format!("{t} {}", side.id(GRANT_B_MATCH.id)),
        )
        .await;
    }
    db.drop([pool]).await;
}

/// `deployment_evidence` with `claim` set to `value`, or removed.
fn deployment_evidence_with(claim: &str, value: Option<&str>) -> Evidence {
    let mut claims = deployment_claims();
    match value {
        Some(value) => claims.insert(claim.into(), value.into()),
        None => claims.remove(claim),
    };
    Evidence::new(claims)
}

/// `grt_a_match` has one eligible binding on `src_gen`, the deployment
/// binding. Evidence with a differing value, a missing claim, or a value
/// that differs only in case or by a trailing space matches nothing. On
/// `src_gen2`, where only `wld_a` has a binding, the grant of `wld_b`
/// selects nothing.
#[tokio::test]
async fn a50_neg_no_eligible_match() {
    let (db, pool) = two_tenants_with_matching().await;
    for side in [A, B] {
        let t = side.tenant;
        let selected = select_own(&pool, side, GRANT_A_MATCH, GENERIC).await;
        assert_eq!(ids(&selected), [side.id("bnd_m2")], "{t}");
        // The unchanged evidence matches.
        assert_eq!(
            deployment_evidence_with("pipeline_run", Some("4711")),
            deployment_evidence()
        );
        assert_is_stored(
            &pool,
            side,
            match_binding(&selected.eligible_bindings, &deployment_evidence()),
            "bnd_m2",
            "wld_a",
            t,
        )
        .await;
        for (claim, value) in [
            // A differing value of each predicate.
            ("sub", Some("pipeline:example/other")),
            ("repository_id", Some(OTHER_REPOSITORY_ID)),
            ("environment", Some("staging")),
            // Each predicate's claim missing.
            ("sub", None),
            ("repository_id", None),
            ("environment", None),
            // A value differing only in case, or by a trailing space.
            ("environment", Some("Production")),
            ("environment", Some("production ")),
        ] {
            let evidence = deployment_evidence_with(claim, value);
            assert_eq!(
                match_binding(&selected.eligible_bindings, &evidence),
                None,
                "{t} {claim} {value:?}"
            );
        }

        // On src_gen2, wld_a's bnd_0_gen2 fits the evidence and is eligible
        // for grt_a_match; wld_b has no binding there, so its grant selects
        // nothing.
        let second = stored(&pool, side, "bnd_0_gen2").await;
        assert_eq!(second.trust_source_id, side.id(SECOND_GENERIC), "{t}");
        assert!(fits(&second, &deployment_evidence()), "{t}");
        assert!(
            all_bindings(&pool, side)
                .await
                .iter()
                .filter(|binding| binding.trust_source_id == side.id(SECOND_GENERIC))
                .all(|binding| binding.workload_principal_id == side.id("wld_a")),
            "{t}"
        );
        assert_eq!(
            ids(&select_own(&pool, side, GRANT_A_MATCH, SECOND_GENERIC).await),
            [second.id.as_str()],
            "{t}"
        );
        match select(&pool, side, GRANT_B_MATCH, SECOND_GENERIC).await {
            Err(SelectionError::NotSelectable) => {}
            other => panic!(
                "{t} {}: expected NotSelectable: {other:?}",
                GRANT_B_MATCH.id
            ),
        }
    }
    db.drop([pool]).await;
}

/// Bindings of `wld_a` that fit the evidence and sort before its eligible
/// one, but are disabled (listed), not listed (enabled), or on another
/// source (listed, enabled), are never loaded, so never returned.
#[tokio::test]
async fn a50_neg_ineligible_bindings_never_match() {
    let (db, pool) = two_tenants_with_matching().await;
    let evidence = deployment_evidence();
    for side in [A, B] {
        let t = side.tenant;
        let grant = registry::get_service_grant(&pool, t, &side.id(GRANT_A_MATCH.id))
            .await
            .unwrap();
        let own = stored(&pool, side, "bnd_m2").await;
        for (base, status, listed, source) in [
            ("bnd_0_gen_off", Status::Disabled, true, GENERIC),
            ("bnd_0_gen_free", Status::Enabled, false, GENERIC),
            ("bnd_0_gen2", Status::Enabled, true, SECOND_GENERIC),
        ] {
            let other = stored(&pool, side, base).await;
            let case = format!("{t} {base}");
            assert_eq!(
                (
                    other.workload_principal_id.as_str(),
                    other.status,
                    grant.allowed_binding_ids.contains(&other.id),
                    other.trust_source_id.as_str(),
                ),
                (
                    side.id("wld_a").as_str(),
                    status,
                    listed,
                    side.id(source).as_str()
                ),
                "{case}"
            );
            assert!(fits(&other, &evidence), "{case}");
            assert!(other.id.as_bytes() < own.id.as_bytes(), "{case}");
        }
        let selected = select_own(&pool, side, GRANT_A_MATCH, GENERIC).await;
        assert_eq!(ids(&selected), [own.id.as_str()], "{t}");
        assert_eq!(
            match_binding(&selected.eligible_bindings, &evidence),
            Some(&eligible(&own)),
            "{t}"
        );
    }
    db.drop([pool]).await;
}

/// `grt_a_multi` lists two bindings of `wld_a` that the evidence fits:
/// `bnd_m1` (branch) and `bnd_m2` (deployment), equally specific and not
/// comparable, whose names differ only by byte order. The match is
/// `bnd_m1`, the lowest ID, alone, with its own stored policy and current
/// revision, in every order of the input and on every selection.
#[tokio::test]
async fn a50_neg_several_same_actor_matches_give_one_stable_id_no_union() {
    let (db, pool) = two_tenants_with_matching().await;
    let evidence = deployment_evidence();
    // Every A50 grant lists bindings of its own actor only.
    for side in [A, B] {
        for grant in MATCHING_GRANTS {
            for base in grant.listed {
                assert_eq!(
                    stored(&pool, side, base).await.workload_principal_id,
                    side.id(grant.actor)
                );
            }
        }
    }
    for side in [A, B] {
        let t = side.tenant;
        let (lowest, higher) = (
            stored(&pool, side, "bnd_m1").await,
            stored(&pool, side, "bnd_m2").await,
        );
        assert!(lowest.id.as_bytes() < higher.id.as_bytes(), "{t}");
        assert_eq!(
            lowest.claim_match_policy["repository_id"], REPOSITORY_ID,
            "{t}"
        );
        // Equally specific and not comparable: as many predicates, and
        // neither a subset of the other. So a merge of them differs from
        // each, and no ranking by specificity decides between them.
        let subset = |a: &PrincipalBinding, b: &PrincipalBinding| {
            a.claim_match_policy
                .iter()
                .all(|(claim, value)| b.claim_match_policy.get(claim) == Some(value))
        };
        assert_eq!(
            lowest.claim_match_policy.len(),
            higher.claim_match_policy.len(),
            "{t}"
        );
        assert!(
            !subset(&lowest, &higher) && !subset(&higher, &lowest),
            "{t}"
        );

        let selected = select_own(&pool, side, GRANT_A_MULTI, GENERIC).await;
        assert_eq!(
            selected.eligible_bindings,
            [eligible(&lowest), eligible(&higher)],
            "{t}"
        );
        assert!(fits(&lowest, &evidence) && fits(&higher, &evidence), "{t}");
        // Every order of the input gives the same binding, as stored: the
        // lowest ID, with its own policy and revision only.
        let mut reversed = selected.eligible_bindings.clone();
        reversed.reverse();
        for order in [&selected.eligible_bindings, &reversed] {
            assert_eq!(
                match_binding(order, &evidence),
                Some(&eligible(&lowest)),
                "{t}"
            );
        }
        // So does every new selection.
        for _ in 0..3 {
            let again = select_own(&pool, side, GRANT_A_MULTI, GENERIC).await;
            assert_eq!(again, selected, "{t}");
            assert_eq!(
                match_binding(&again.eligible_bindings, &evidence),
                Some(&eligible(&lowest)),
                "{t}"
            );
        }

        // An update of the other binding moves its revision, not the
        // selected one's; an update of the selected binding moves its own.
        for (updated, base) in [(&higher, "bnd_m2"), (&lowest, "bnd_m1")] {
            registry::test_support::update_principal_binding(
                &pool,
                t,
                &updated.id,
                updated.revision,
                &PrincipalBindingChanges {
                    name: format!("{}-renamed", updated.name),
                    profile: updated.profile,
                    claim_match_policy: updated.claim_match_policy.clone(),
                    status: Status::Enabled,
                },
            )
            .await
            .unwrap();
            let current = stored(&pool, side, "bnd_m1").await;
            let again = select_own(&pool, side, GRANT_A_MULTI, GENERIC).await;
            assert_eq!(
                again.eligible_bindings,
                [
                    eligible(&current),
                    eligible(&stored(&pool, side, "bnd_m2").await)
                ],
                "{t} after {base}"
            );
            assert_eq!(
                match_binding(&again.eligible_bindings, &evidence),
                Some(&eligible(&current)),
                "{t} after {base}"
            );
        }
        let current = stored(&pool, side, "bnd_m1").await;
        assert_eq!(
            (
                current.revision,
                stored(&pool, side, "bnd_m2").await.revision
            ),
            (lowest.revision + 1, higher.revision + 1),
            "{t}"
        );
    }
    db.drop([pool]).await;
}
