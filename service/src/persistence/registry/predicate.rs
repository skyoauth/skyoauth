//! The required predicates of each binding profile template (ADR-016
//! items 2 to 4; design section 5.3; T12.2; conformance A37), the one table
//! of them in the service. `0008` checks the same sets in the database, one
//! named check per profile; changing a set needs a new migration as well as
//! a change here.
//!
//! A required predicate is present when its claim name is a key of the
//! binding's `claim_match_policy` and its value is not empty. Predicates
//! outside the required set are optional: omitted, they are unconstrained
//! (ADR-016 item 1). The values of `claim_match_policy` are strings in the
//! registry's types, and `0004` rejects a stored value that is not one.
//!
//! [`create_principal_binding`](super::create_principal_binding) and
//! [`update_principal_binding`](super::update_principal_binding) call
//! [`validate_claim_match_policy`] before their statement. Removing an
//! optional predicate widens the binding and needs review (ADR-016 item 2;
//! ADR-008), which stays with the service: the registry cannot tell a
//! reviewed update from another.

use std::collections::BTreeMap;

use super::{BindingProfile, RegistryError};

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

/// `kubernetes_production`: namespace, service-account name and
/// service-account UID (ADR-016 item 4). The flat claim names are
/// (inferred): no source names the keys.
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
/// [`required_claims`], is an encode error, [`RegistryError::Other`], as for
/// the other rejections the registry makes before a statement (an empty
/// patch, an empty assertion set). Its message names the claim and the
/// profile, never a value. Keys outside the required set are not checked.
pub fn validate_claim_match_policy(
    profile: BindingProfile,
    policy: &BTreeMap<String, String>,
) -> Result<(), RegistryError> {
    for claim in required_claims(profile) {
        let problem = match policy.get(*claim) {
            Some(value) if !value.is_empty() => continue,
            Some(_) => "is empty",
            None => "is missing",
        };
        return Err(sqlx::Error::Encode(
            format!("the required predicate {claim} of {profile} {problem}").into(),
        )
        .into());
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
    fn assert_rejected(profile: BindingProfile, policy: &BTreeMap<String, String>, message: &str) {
        match validate_claim_match_policy(profile, policy) {
            Err(RegistryError::Other(sqlx::Error::Encode(err))) => {
                assert_eq!(err.to_string(), message);
            }
            other => panic!("expected {message:?}: {other:?}"),
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
    }

    #[test]
    fn a_complete_policy_passes_with_or_without_optional_predicates() {
        for profile in PROFILES {
            let mut policy = complete(profile);
            assert!(validate_claim_match_policy(profile, &policy).is_ok());
            // Optional predicates, among them the reusable-workflow one and
            // the required claims of the other profiles.
            policy.insert(
                "job_workflow_ref".into(),
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
                assert_rejected(
                    profile,
                    &missing,
                    &format!("the required predicate {claim} of {profile} is missing"),
                );
                let mut empty = complete(profile);
                empty.insert((*claim).to_string(), String::new());
                assert_rejected(
                    profile,
                    &empty,
                    &format!("the required predicate {claim} of {profile} is empty"),
                );
            }
        }
    }

    #[test]
    fn the_first_unmet_predicate_in_table_order_is_named() {
        assert_rejected(
            BindingProfile::GithubProduction,
            &BTreeMap::new(),
            "the required predicate repository_owner_id of github_production is missing",
        );
        let mut policy = complete(BindingProfile::GithubProduction);
        policy.remove("workflow_ref");
        policy.insert("event_name".into(), String::new());
        assert_rejected(
            BindingProfile::GithubProduction,
            &policy,
            "the required predicate event_name of github_production is empty",
        );
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
            assert_rejected(
                profile,
                &policy,
                &format!("the required predicate {claim} of {profile} is missing"),
            );
        }
    }

    /// The message names the claim and the profile, never a value.
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
