//! Binding matching for the workload exchange (ADR-015 item 4 steps 3 and
//! 4; design section 5.7; T12.3; groundwork for T12.7 and T21.4;
//! conformance A25 and A50): the matching half of step 3, and step 4.
//! `select_grant` (in `persistence::registry`) loads a grant's eligible
//! bindings; [`match_binding`] picks the one that the verified evidence
//! matches.
//!
//! This module is pure: it reads nothing and writes nothing.
//!
//! # Matching
//!
//! A binding matches when every predicate of its `claim_match_policy` is a
//! claim of the evidence with exactly the same string: predicates are
//! ANDed, a configured claim absent from the evidence is a non-match, and
//! strings compare byte for byte, with no regex, wildcard, case folding,
//! trimming or Unicode normalization (ADR-016 item 1; design section 5.3).
//! Claims of the evidence that no predicate names are ignored. A binding
//! with an empty policy matches nothing (inferred: the schema forbids an
//! empty policy since `0004`, and matching fails closed if one is loaded).
//!
//! Among the matching eligible bindings, the one with the byte-wise lowest
//! ID is selected, for provenance (step 4; inferred: "stable ID ordering"
//! taken as ascending byte order, the order the registry lists IDs in).
//! [`match_binding`] picks that minimum itself, so for bindings with
//! unique IDs it does not rely on the order of its input; the eligible
//! bindings of a `Selection` have unique IDs (one grant, and its list
//! has one row per binding: `PRIMARY KEY (grant_id, binding_id)`). Only that binding is returned: the predicates or permissions of
//! the others are never unioned with it, and when none matches there is no
//! fallback to any other binding. The returned binding carries its ID and
//! revision, which the caller records as the selected binding of the
//! decision.

use std::{collections::BTreeMap, fmt};

/// A binding eligible for a selected grant: listed by it, of its tenant
/// and actor, on the selected source and enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibleBinding {
    pub id: String,
    /// ANDed exact-string predicates, claim name to value.
    pub claim_match_policy: BTreeMap<String, String>,
    /// The binding's revision, for the decision's provenance.
    pub revision: i64,
}

impl EligibleBinding {
    /// Whether `evidence` has every predicate of the policy with exactly
    /// its value. An empty policy matches nothing (inferred).
    pub fn matches(&self, evidence: &Evidence) -> bool {
        !self.claim_match_policy.is_empty()
            && self
                .claim_match_policy
                .iter()
                .all(|(claim, value)| evidence.get(claim) == Some(value.as_str()))
    }
}

/// The claims of a proof verified at the selected source, claim name to
/// string value (inferred: the verifier, T11.x, does not exist yet, so this
/// is the smallest shape matching needs). Its `Debug` text lists the claim
/// names, never their values.
///
/// A map keeps one value per claim name, so the verifier (T11.x) must
/// reject a proof with a duplicate claim name before it builds `Evidence`;
/// that is the verifier task's responsibility, not this type's.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    claims: BTreeMap<String, String>,
}

impl Evidence {
    /// Evidence of exactly `claims`.
    pub fn new(claims: BTreeMap<String, String>) -> Self {
        Self { claims }
    }

    /// The value of `claim`, if the evidence has it.
    pub fn get(&self, claim: &str) -> Option<&str> {
        self.claims.get(claim).map(String::as_str)
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Evidence {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        Self::new(
            iter.into_iter()
                .map(|(claim, value)| (claim.into(), value.into()))
                .collect(),
        )
    }
}

impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Evidence")
            .field("claims", &self.claims.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The eligible binding that `evidence` matches, the one with the
/// byte-wise lowest ID when several do, or `None` when none does (see the
/// module docs). For unique IDs it does not rely on the order of
/// `eligible`; the eligible bindings of a `Selection` have unique IDs.
pub fn match_binding<'a>(
    eligible: &'a [EligibleBinding],
    evidence: &Evidence,
) -> Option<&'a EligibleBinding> {
    eligible
        .iter()
        .filter(|binding| binding.matches(evidence))
        .min_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_debug_lists_claim_names_only() {
        let evidence: Evidence = [("sub", "repo:acme/secret-name")].into_iter().collect();
        assert_eq!(format!("{evidence:?}"), r#"Evidence { claims: ["sub"] }"#);
    }
}
