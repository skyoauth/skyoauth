//! The required predicates of each binding profile template (ADR-016
//! items 2 to 4; design section 5.3; T12.2; conformance A37), the one table
//! of them in the service. `0008` checks the same sets in the database, one
//! named check per profile; changing a set needs a new migration as well as
//! a change here.
//!
//! A required predicate is present when its claim name is a key of the
//! binding's `claim_match_policy` and its value is not empty. A
//! whitespace-only value is not empty: it is accepted, and matches only a
//! token carrying exactly that value (exact match, design section 5.3).
//! Predicates outside the required set are optional: omitted, they are
//! unconstrained (ADR-016 item 1); [`GITHUB_JOB_WORKFLOW_REF`] is one. The
//! values of `claim_match_policy` are strings in the registry's types, and
//! `0004` rejects a stored value that is not one.
//!
//! [`create_principal_binding`](super::grant::create_principal_binding) and
//! [`update_principal_binding`](super::grant::update_principal_binding) call
//! [`validate_claim_match_policy`] before their statement; an unmet required
//! predicate is [`RegistryError::RequiredPredicate`], naming the claim and
//! whether it is [`PredicateProblem::Missing`] or [`PredicateProblem::Empty`],
//! never a value. Removing an optional predicate widens the binding and needs
//! review (ADR-016 item 2; ADR-008 items 12 and 13), which stays with the
//! service: the registry cannot tell a reviewed update from another.
//!
//! A profile change that drops a predicate is such a removal too: moving a
//! binding from `github_production` to `generic_production` with a policy
//! of only `sub` meets the new set, and this check passes it, although every
//! GitHub predicate is gone. The check that the template fits the source
//! and its `assertion_profile` (ADR-016 item 4) is the only stop on that
//! downgrade, and it is not built: no task in the task list names it, so it
//! is an open follow-up, closest to T12.2.

use std::collections::BTreeMap;

use super::{BindingProfile, PredicateProblem, RegistryError};

/// `github_production`: the ADR-016 item 3 set, as the keys of the design
/// section 5.7 example: immutable owner and repository IDs, explicit event,
/// ref, environment and workflow identity. The reusable-workflow identity
/// that item 3 requires "when used" (`job_workflow_ref`, inferred) is
/// optional here, since a policy does not show whether the job uses one.
const GITHUB_PRODUCTION: [&str; 6] = [
    "repository_owner_id",
    "repository_id",
    "event_name",
    "ref",
    "environment",
    "workflow_ref",
];

/// The reusable-workflow identity of a GitHub job, which ADR-016 item 3
/// requires "when used" (inferred: the claim name, and that it is
/// optional). It is not in [`required_claims`]: a policy does not show
/// whether the job uses a reusable workflow. When the token's
/// `job_workflow_ref` differs from its `workflow_ref`, the job runs one, and
/// matching (T22.2) should match it only to a binding that pins this
/// predicate (inferred); that check is not built here.
pub const GITHUB_JOB_WORKFLOW_REF: &str = "job_workflow_ref";

/// `kubernetes_production`: namespace, service-account name and
/// service-account UID (ADR-016 item 4). The flat claim names are
/// (inferred): no source names the keys. They are the normalized evidence
/// keys the Kubernetes adapters (T23.3, T23.6) must produce from the
/// service-account identity they verify; changing one needs a new
/// migration and rewriting every `kubernetes_production` binding.
const KUBERNETES_PRODUCTION: [&str; 3] = [
    "kubernetes.io/serviceaccount/namespace",
    "kubernetes.io/serviceaccount/service-account.name",
    "kubernetes.io/serviceaccount/service-account.uid",
];

/// `generic_production`: an exact `sub` (ADR-016 item 4).
const GENERIC_PRODUCTION: [&str; 1] = ["sub"];

/// The claim names `profile` requires in a binding's `claim_match_policy`,
/// in the order [`validate_claim_match_policy`] checks them.
pub fn required_claims(profile: BindingProfile) -> &'static [&'static str] {
    match profile {
        BindingProfile::GithubProduction => &GITHUB_PRODUCTION,
        BindingProfile::KubernetesProduction => &KUBERNETES_PRODUCTION,
        BindingProfile::GenericProduction => &GENERIC_PRODUCTION,
    }
}

/// Checks that `policy` has every predicate `profile` requires, each with a
/// non-empty value. The first one missing or empty, in the order of
/// [`required_claims`], is [`RegistryError::RequiredPredicate`] with its
/// claim name and [`PredicateProblem::Missing`] (no such key, byte-wise) or
/// [`PredicateProblem::Empty`] (the empty string); the error carries no
/// value of the policy. Keys outside the required set are not checked.
pub fn validate_claim_match_policy(
    profile: BindingProfile,
    policy: &BTreeMap<String, String>,
) -> Result<(), RegistryError> {
    for claim in required_claims(profile) {
        let problem = match policy.get(*claim) {
            Some(value) if !value.is_empty() => continue,
            Some(_) => PredicateProblem::Empty,
            None => PredicateProblem::Missing,
        };
        return Err(RegistryError::RequiredPredicate { claim, problem });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILES: [BindingProfile; 3] = [
        BindingProfile::GithubProduction,
        BindingProfile::KubernetesProduction,
        BindingProfile::GenericProduction,
    ];

    /// Exactly the required predicates of `profile`, each with a value.
    fn complete(profile: BindingProfile) -> BTreeMap<String, String> {
        required_claims(profile)
            .iter()
            .map(|claim| ((*claim).to_string(), format!("value of {claim}")))
            .collect()
    }

    #[track_caller]
    fn assert_rejected(
        profile: BindingProfile,
        policy: &BTreeMap<String, String>,
        claim: &str,
        problem: PredicateProblem,
    ) {
        match validate_claim_match_policy(profile, policy) {
            Err(RegistryError::RequiredPredicate {
                claim: named,
                problem: found,
            }) => {
                assert_eq!((named, found), (claim, problem), "{profile}");
            }
            other => panic!("{profile}: expected {claim} {problem}: {other:?}"),
        }
    }

    #[test]
    fn the_required_sets_are_the_adr_016_sets() {
        assert_eq!(
            required_claims(BindingProfile::GithubProduction),
            [
                "repository_owner_id",
                "repository_id",
                "event_name",
                "ref",
                "environment",
                "workflow_ref",
            ]
        );
        assert_eq!(
            required_claims(BindingProfile::KubernetesProduction),
            [
                "kubernetes.io/serviceaccount/namespace",
                "kubernetes.io/serviceaccount/service-account.name",
                "kubernetes.io/serviceaccount/service-account.uid",
            ]
        );
        assert_eq!(required_claims(BindingProfile::GenericProduction), ["sub"]);
        // The reusable-workflow identity is optional in every profile.
        assert_eq!(GITHUB_JOB_WORKFLOW_REF, "job_workflow_ref");
        for profile in PROFILES {
            assert!(!required_claims(profile).contains(&GITHUB_JOB_WORKFLOW_REF));
        }
    }

    #[test]
    fn a_whitespace_only_value_is_not_empty() {
        for profile in PROFILES {
            for value in [" ", "\t", " \n "] {
                let policy = required_claims(profile)
                    .iter()
                    .map(|claim| ((*claim).to_string(), value.to_string()))
                    .collect();
                assert!(validate_claim_match_policy(profile, &policy).is_ok());
            }
        }
    }

    #[test]
    fn a_complete_policy_passes_with_or_without_optional_predicates() {
        for profile in PROFILES {
            let mut policy = complete(profile);
            assert!(validate_claim_match_policy(profile, &policy).is_ok());
            // Optional predicates, among them the reusable-workflow one and
            // the required claims of the other profiles.
            policy.insert(
                GITHUB_JOB_WORKFLOW_REF.into(),
                "org/repo/.github/workflows/w.yml@v1".into(),
            );
            policy.insert("actor".into(), String::new());
            for other in PROFILES {
                for claim in required_claims(other) {
                    policy
                        .entry((*claim).to_string())
                        .or_insert_with(|| "x".into());
                }
            }
            assert!(validate_claim_match_policy(profile, &policy).is_ok());
        }
    }

    #[test]
    fn each_required_predicate_missing_or_empty_is_rejected() {
        for profile in PROFILES {
            for claim in required_claims(profile) {
                let mut missing = complete(profile);
                missing.remove(*claim);
                assert_rejected(profile, &missing, claim, PredicateProblem::Missing);
                let mut empty = complete(profile);
                empty.insert((*claim).to_string(), String::new());
                assert_rejected(profile, &empty, claim, PredicateProblem::Empty);
            }
        }
    }

    #[test]
    fn the_first_unmet_predicate_in_table_order_is_named() {
        assert_rejected(
            BindingProfile::GithubProduction,
            &BTreeMap::new(),
            "repository_owner_id",
            PredicateProblem::Missing,
        );
        let mut policy = complete(BindingProfile::GithubProduction);
        policy.remove("workflow_ref");
        policy.insert("event_name".into(), String::new());
        assert_rejected(
            BindingProfile::GithubProduction,
            &policy,
            "event_name",
            PredicateProblem::Empty,
        );
        // Every profile names its first claim for an empty policy, and the
        // first claim when every value is empty.
        for profile in PROFILES {
            let first = required_claims(profile)[0];
            assert_rejected(profile, &BTreeMap::new(), first, PredicateProblem::Missing);
            let empty = required_claims(profile)
                .iter()
                .map(|claim| ((*claim).to_string(), String::new()))
                .collect();
            assert_rejected(profile, &empty, first, PredicateProblem::Empty);
        }
    }

    /// A claim name that differs from a required one in any byte (case, a
    /// trailing space, the nested form of a Kubernetes claim) does not
    /// stand in for it.
    #[test]
    fn claim_names_match_exactly() {
        for (profile, claim, near) in [
            (BindingProfile::GenericProduction, "sub", "Sub"),
            (BindingProfile::GenericProduction, "sub", "sub "),
            (BindingProfile::GithubProduction, "ref", "Ref"),
            (
                BindingProfile::KubernetesProduction,
                "kubernetes.io/serviceaccount/namespace",
                "kubernetes.io/namespace",
            ),
        ] {
            let mut policy = complete(profile);
            let value = policy.remove(claim).unwrap();
            policy.insert(near.into(), value);
            assert_rejected(profile, &policy, claim, PredicateProblem::Missing);
        }
    }

    /// The claim of the error is the `'static` name from the table of the
    /// profile, for every profile and both problems, and its `Display`
    /// names that claim and the problem.
    #[test]
    fn the_variant_carries_the_table_claim_and_the_problem() {
        for profile in PROFILES {
            for (index, claim) in required_claims(profile).iter().enumerate() {
                for problem in [PredicateProblem::Missing, PredicateProblem::Empty] {
                    let mut policy = complete(profile);
                    match problem {
                        PredicateProblem::Missing => policy.remove(*claim),
                        PredicateProblem::Empty => {
                            policy.insert((*claim).to_string(), String::new())
                        }
                    };
                    let err = validate_claim_match_policy(profile, &policy).unwrap_err();
                    let RegistryError::RequiredPredicate {
                        claim: named,
                        problem: found,
                    } = err
                    else {
                        panic!("{profile} {claim}: {err:?}");
                    };
                    assert!(std::ptr::eq(named, required_claims(profile)[index]));
                    assert_eq!(found, problem);
                    assert_eq!(
                        err.to_string(),
                        format!("registry binding's required predicate {claim} is {problem}")
                    );
                    assert!(std::error::Error::source(&err).is_none());
                }
            }
        }
    }

    /// The error names the claim, never a value.
    #[test]
    fn the_error_carries_no_value() {
        let mut policy = complete(BindingProfile::GenericProduction);
        policy.insert("sub".into(), String::new());
        policy.insert("secret-looking".into(), "s3cr3t".into());
        let err =
            validate_claim_match_policy(BindingProfile::GenericProduction, &policy).unwrap_err();
        assert!(!format!("{err:?} {err}").contains("s3cr3t"));
    }
}
