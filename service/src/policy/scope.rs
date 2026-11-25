//! Scope resolution for the workload exchange: which scopes a `wif`
//! credential carries, from the request's `scope` and the grant's
//! `default_scopes`, within every applicable ceiling (IR-062, IR-063,
//! IR-066; ADR-015 items 7 and 9; errors-retry ERR-024; design section
//! 5.7; T12.8; groundwork for T21.5; conformance A26, M1a "scope policy ... (registry API)").
//!
//! This module is pure: it reads nothing and writes nothing.
//! `load_scope_ceilings` (in `persistence::registry`) loads the ceilings
//! it needs. It lives in `policy`, apart from that loader, because it does
//! not depend on the database (lead ruling, 2026-11-21).
//!
//! # Rules
//!
//! - **Ceilings** (IR-062). Every scope must lie in the resource server's
//!   `scopes`, the tenant's assignment `allowed_scopes` and the grant's
//!   `scopes`, and, for a delegation or impersonation grant, in its target
//!   service's `max_scopes`. A scope matches a ceiling entry only when the
//!   two are the same string, byte for byte (IR-066: scope tokens are
//!   case-sensitive).
//! - **Omitted scope** (IR-063; ADR-015 item 7). Only the grant's explicit
//!   nonempty `default_scopes` are used. No defaults is an error; the full
//!   ceiling is never a fallback. The defaults are checked against every
//!   ceiling again on each call, since a ceiling can shrink after the grant
//!   was written; a default outside one is an error, never trimmed.
//! - **Explicit scope** (IR-063). An empty list is an error. A nonempty
//!   list must lie in every ceiling; a scope outside one (unknown or
//!   excessive) is an error, never trimmed or widened.
//! - **Tokens** (IR-066). Every scope must match the RFC 6749 section 3.3
//!   `scope-token` grammar `1*( %x21 / %x23-5B / %x5D-7E )`, the rule of
//!   the `skyoauth_scope_list` domain of `0003`: not empty, printable
//!   ASCII, no space, `"` or `\`. Anything else is an error.
//! - **Repeated tokens** are tolerated, following the lead lean on OQ-IR-11
//!   (identity-registry: "keep duplicate scope tokens tolerated outside
//!   comparison v1 unless a source says otherwise"; not decided). The
//!   result is the scopes deduplicated and sorted byte-wise, the canonical
//!   order of IR-060 (inferred for this surface).
//!
//! # Errors
//!
//! Every failure is the single [`ScopeError::Invalid`], which the token
//! endpoint maps to `invalid_scope` (ERR-024 (3); ADR-015 item 9.4). It carries no detail: its
//! `Display` and `Debug` text name no scope, no ceiling and which rule
//! failed, so a response built from it cannot reveal a ceiling's contents
//! or which ceiling refused.
//!
//! # Not done here
//!
//! The current status of the tenant, grant, resource server, assignment and
//! target service (design section 5.7 step 5: the status checks of T12.6,
//! T12.7 and T14.2, wired into the exchange in M2, T21.4 and T21.5); the
//! mapping of errors to OAuth codes and their order (ERR-024; M2); the
//! audience checks that give `invalid_target`; resource constraint ceilings
//! (IR-123); and TTL caps.

use std::fmt;

/// The request's `scope`, already split into tokens by the request layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRequest {
    /// No `scope` parameter.
    Omitted,
    /// The tokens of the `scope` parameter, in request order, repeats
    /// included. An empty list is a `scope` parameter with no token.
    Explicit(Vec<String>),
}

/// The ceilings a `wif` credential's scopes must all lie in (IR-062).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCeilings {
    /// `ResourceServer.scopes` of the requested audience.
    pub resource_server: Vec<String>,
    /// `AudienceTenantAssignment.allowed_scopes` of the tenant for it.
    pub assignment: Vec<String>,
    /// `ServiceGrant.scopes`.
    pub grant: Vec<String>,
    /// The target `ServiceIdentity.max_scopes`: `Some` for a delegation or
    /// impersonation grant (IR-062), `None` for a direct grant.
    pub target_service: Option<Vec<String>>,
}

impl ScopeCeilings {
    /// Whether `scope` is in every ceiling.
    fn allow(&self, scope: &str) -> bool {
        let within = |ceiling: &[String]| ceiling.iter().any(|entry| entry == scope);
        within(&self.resource_server)
            && within(&self.assignment)
            && within(&self.grant)
            && self.target_service.as_deref().is_none_or(within)
    }
}

/// Why no scopes resolve. One value with no detail (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    /// The scope is invalid for this grant and audience: `invalid_scope`.
    Invalid,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid scope")
    }
}

impl std::error::Error for ScopeError {}

/// Whether `token` matches the RFC 6749 section 3.3 `scope-token` grammar
/// (IR-066), the rule of the `skyoauth_scope_list` domain.
fn is_scope_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// The scopes a credential carries for `request`, deduplicated and sorted
/// byte-wise, or [`ScopeError::Invalid`] (see the module docs).
/// `grant_default_scopes` is the grant's `default_scopes`.
pub fn resolve_scopes(
    request: &ScopeRequest,
    grant_default_scopes: Option<&[String]>,
    ceilings: &ScopeCeilings,
) -> Result<Vec<String>, ScopeError> {
    let scopes = match request {
        ScopeRequest::Omitted => match grant_default_scopes {
            Some(defaults) if !defaults.is_empty() => defaults,
            _ => return Err(ScopeError::Invalid),
        },
        ScopeRequest::Explicit(requested) if requested.is_empty() => {
            return Err(ScopeError::Invalid);
        }
        ScopeRequest::Explicit(requested) => requested.as_slice(),
    };
    if !scopes
        .iter()
        .all(|scope| is_scope_token(scope) && ceilings.allow(scope))
    {
        return Err(ScopeError::Invalid);
    }
    let mut resolved = scopes.to_vec();
    resolved.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    resolved.dedup();
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn explicit(values: &[&str]) -> ScopeRequest {
        ScopeRequest::Explicit(strings(values))
    }

    /// Each ceiling has one scope the others lack, so a scope beyond each
    /// one in turn can be named. `read` and `deploy:write` are in all.
    fn delegation() -> ScopeCeilings {
        ScopeCeilings {
            resource_server: strings(&["read", "deploy:write", "admin", "not-assigned"]),
            assignment: strings(&["read", "deploy:write", "admin", "not-granted"]),
            grant: strings(&["read", "deploy:write", "admin", "not-for-service"]),
            target_service: Some(strings(&["read", "deploy:write", "not-on-server"])),
        }
    }

    fn direct() -> ScopeCeilings {
        ScopeCeilings {
            target_service: None,
            ..delegation()
        }
    }

    #[track_caller]
    fn assert_invalid(result: Result<Vec<String>, ScopeError>) {
        assert_eq!(result, Err(ScopeError::Invalid));
    }

    #[test]
    fn omitted_scope_is_exactly_the_grant_defaults() {
        let defaults = strings(&["read"]);
        assert_eq!(
            resolve_scopes(&ScopeRequest::Omitted, Some(&defaults), &delegation()),
            Ok(strings(&["read"]))
        );
        let defaults = strings(&["deploy:write", "read"]);
        assert_eq!(
            resolve_scopes(&ScopeRequest::Omitted, Some(&defaults), &direct()),
            Ok(strings(&["deploy:write", "read"]))
        );
    }

    #[test]
    fn omitted_scope_without_defaults_is_invalid() {
        // Every ceiling is the same, so a fallback to any one of them, or to
        // their intersection, would resolve; none may.
        let same = ScopeCeilings {
            resource_server: strings(&["read"]),
            assignment: strings(&["read"]),
            grant: strings(&["read"]),
            target_service: Some(strings(&["read"])),
        };
        let same_direct = ScopeCeilings {
            target_service: None,
            ..same.clone()
        };
        for ceilings in [&same, &same_direct] {
            assert_invalid(resolve_scopes(&ScopeRequest::Omitted, None, ceilings));
            // An empty list is not explicit defaults (the schema forbids
            // one).
            assert_invalid(resolve_scopes(&ScopeRequest::Omitted, Some(&[]), ceilings));
        }
    }

    #[test]
    fn defaults_outside_a_shrunken_ceiling_are_invalid_not_trimmed() {
        let defaults = strings(&["read", "deploy:write"]);
        assert!(resolve_scopes(&ScopeRequest::Omitted, Some(&defaults), &delegation()).is_ok());
        let mut shrunk = [delegation(), delegation(), delegation(), delegation()];
        shrunk[0].resource_server = strings(&["read"]);
        shrunk[1].assignment = strings(&["read"]);
        shrunk[2].grant = strings(&["read"]);
        shrunk[3].target_service = Some(strings(&["read"]));
        for ceilings in &shrunk {
            assert_invalid(resolve_scopes(
                &ScopeRequest::Omitted,
                Some(&defaults),
                ceilings,
            ));
        }
        // Malformed defaults are invalid too.
        assert_invalid(resolve_scopes(
            &ScopeRequest::Omitted,
            Some(&strings(&["read", "bad scope"])),
            &delegation(),
        ));
    }

    #[test]
    fn explicit_empty_scope_is_invalid() {
        let defaults = strings(&["read"]);
        assert_invalid(resolve_scopes(&explicit(&[]), Some(&defaults), &direct()));
    }

    #[test]
    fn a_scope_beyond_any_one_ceiling_is_invalid() {
        // Beyond the resource server, the assignment, the grant and the
        // target service, in turn; each is in every other ceiling.
        for beyond in [
            "not-on-server",
            "not-assigned",
            "not-granted",
            "not-for-service",
        ] {
            assert_invalid(resolve_scopes(
                &explicit(&["read", beyond]),
                None,
                &delegation(),
            ));
        }
        // Unknown everywhere, and unknown only by case.
        assert_invalid(resolve_scopes(&explicit(&["unknown"]), None, &direct()));
        assert_invalid(resolve_scopes(&explicit(&["READ"]), None, &direct()));
    }

    #[test]
    fn the_target_service_ceiling_applies_exactly_when_present() {
        // "admin" is in the resource server, assignment and grant, but not
        // in the target service's max_scopes.
        assert_eq!(
            resolve_scopes(&explicit(&["admin"]), None, &direct()),
            Ok(strings(&["admin"]))
        );
        assert_invalid(resolve_scopes(&explicit(&["admin"]), None, &delegation()));
        // An empty target ceiling allows nothing.
        let empty_target = ScopeCeilings {
            target_service: Some(vec![]),
            ..delegation()
        };
        assert_invalid(resolve_scopes(&explicit(&["read"]), None, &empty_target));
    }

    #[test]
    fn a_subset_of_every_ceiling_resolves_deduplicated_and_sorted() {
        assert_eq!(
            resolve_scopes(
                &explicit(&["read", "deploy:write", "read"]),
                None,
                &delegation()
            ),
            Ok(strings(&["deploy:write", "read"]))
        );
        // Byte-wise: upper case before lower case.
        let ceilings = ScopeCeilings {
            resource_server: strings(&["b", "B", "a"]),
            assignment: strings(&["a", "B", "b"]),
            grant: strings(&["B", "b", "a"]),
            target_service: None,
        };
        assert_eq!(
            resolve_scopes(&explicit(&["b", "a", "B", "a"]), None, &ceilings),
            Ok(strings(&["B", "a", "b"]))
        );
        let defaults = strings(&["b", "B", "b"]);
        assert_eq!(
            resolve_scopes(&ScopeRequest::Omitted, Some(&defaults), &ceilings),
            Ok(strings(&["B", "b"]))
        );
    }

    #[test]
    fn malformed_tokens_are_invalid_even_when_a_ceiling_lists_them() {
        for token in [
            "",
            " ",
            "read write",
            " read",
            "read\t",
            "read\n",
            "a\u{7f}",
            "a\"b",
            "a\\b",
            "r\u{e9}ad",
            "\u{0}",
        ] {
            let ceilings = ScopeCeilings {
                resource_server: strings(&[token]),
                assignment: strings(&[token]),
                grant: strings(&[token]),
                target_service: None,
            };
            assert_invalid(resolve_scopes(&explicit(&[token]), None, &ceilings));
            assert_invalid(resolve_scopes(
                &ScopeRequest::Omitted,
                Some(&strings(&[token])),
                &ceilings,
            ));
        }
        // The edges of the grammar are valid.
        let edges = "!#[]^~";
        let ceilings = ScopeCeilings {
            resource_server: strings(&[edges]),
            assignment: strings(&[edges]),
            grant: strings(&[edges]),
            target_service: None,
        };
        assert_eq!(
            resolve_scopes(&explicit(&[edges]), None, &ceilings),
            Ok(strings(&[edges]))
        );
    }

    #[test]
    fn the_error_names_no_scope_or_ceiling() {
        let err =
            resolve_scopes(&explicit(&["read", "not-assigned"]), None, &delegation()).unwrap_err();
        assert_eq!(err.to_string(), "invalid scope");
        assert_eq!(format!("{err:?}"), "Invalid");
    }
}
