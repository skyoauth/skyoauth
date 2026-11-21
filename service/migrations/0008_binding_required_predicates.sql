-- The required predicates of each binding profile template (ADR-016 items 2
-- to 4; design section 5.3; T12.2; conformance A37): a principal_binding
-- whose claim_match_policy lacks a predicate its profile requires is
-- rejected. The conventions of 0002 to 0007 apply. "(inferred)" marks a
-- choice the specifications and lead decisions do not dictate; README.md
-- "What 0008 adds" has the upgrade precondition.
--
-- A required predicate is present when its claim name is a key of
-- claim_match_policy and its value is a non-empty JSON string. Optional
-- predicates, the keys outside the required set, stay as before: omitted is
-- unconstrained (ADR-016 item 1). The sets:
--
-- - github_production: repository_owner_id, repository_id, event_name, ref,
--   environment and workflow_ref, the ADR-016 item 3 set as the keys of the
--   design section 5.7 example. The reusable-workflow identity that item 3
--   requires "when used" (job_workflow_ref, inferred) is not checked here:
--   whether a binding uses one is not visible in the row.
-- - kubernetes_production: namespace, service-account name and
--   service-account UID, as the flat claim names
--   kubernetes.io/serviceaccount/namespace,
--   kubernetes.io/serviceaccount/service-account.name and
--   kubernetes.io/serviceaccount/service-account.uid (inferred: no source
--   names the keys).
-- - generic_production: sub.
--
-- The registry checks the same sets before its statement
-- (service/src/persistence/registry/predicate.rs). A set is fixed by the
-- check below: changing one needs a new migration that replaces the check,
-- and the registry table changes with it.
--
-- One named check per profile (inferred), so a rejection names the profile
-- whose set is not met, and each check reads alone in the catalog, with no
-- shared function, as the range checks of 0007. Each check holds for every
-- row of another profile. The checks use only immutable built-ins: ?&
-- (every key present), -> with jsonb_typeof, and ->>. The key set is never
-- NULL (claim_match_policy and profile are NOT NULL, and ?& of a present
-- object is true or false), so a missing key makes the check false, not
-- NULL. The empty-string comparison is under COLLATE "C", byte-wise.
--
-- The checks apply to every row, a disabled binding included (inferred): an
-- update replaces the whole row, so re-enabling one could not keep an
-- incomplete policy anyway. Adding the constraint validates every existing
-- row: a row that fails makes the migration fail with 23514 and roll back
-- (README.md "What 0008 adds", "Upgrade precondition").

ALTER TABLE principal_binding
    ADD CONSTRAINT principal_binding_github_production_predicates_check
        CHECK (profile <> 'github_production'
            OR (claim_match_policy ?& ARRAY['repository_owner_id', 'repository_id', 'event_name',
                                            'ref', 'environment', 'workflow_ref']
                AND jsonb_typeof(claim_match_policy -> 'repository_owner_id') = 'string'
                AND (claim_match_policy ->> 'repository_owner_id') COLLATE "C" <> ''
                AND jsonb_typeof(claim_match_policy -> 'repository_id') = 'string'
                AND (claim_match_policy ->> 'repository_id') COLLATE "C" <> ''
                AND jsonb_typeof(claim_match_policy -> 'event_name') = 'string'
                AND (claim_match_policy ->> 'event_name') COLLATE "C" <> ''
                AND jsonb_typeof(claim_match_policy -> 'ref') = 'string'
                AND (claim_match_policy ->> 'ref') COLLATE "C" <> ''
                AND jsonb_typeof(claim_match_policy -> 'environment') = 'string'
                AND (claim_match_policy ->> 'environment') COLLATE "C" <> ''
                AND jsonb_typeof(claim_match_policy -> 'workflow_ref') = 'string'
                AND (claim_match_policy ->> 'workflow_ref') COLLATE "C" <> '')),
    ADD CONSTRAINT principal_binding_kubernetes_production_predicates_check
        CHECK (profile <> 'kubernetes_production'
            OR (claim_match_policy ?& ARRAY['kubernetes.io/serviceaccount/namespace',
                                            'kubernetes.io/serviceaccount/service-account.name',
                                            'kubernetes.io/serviceaccount/service-account.uid']
                AND jsonb_typeof(claim_match_policy -> 'kubernetes.io/serviceaccount/namespace')
                    = 'string'
                AND (claim_match_policy ->> 'kubernetes.io/serviceaccount/namespace')
                    COLLATE "C" <> ''
                AND jsonb_typeof(
                        claim_match_policy -> 'kubernetes.io/serviceaccount/service-account.name')
                    = 'string'
                AND (claim_match_policy ->> 'kubernetes.io/serviceaccount/service-account.name')
                    COLLATE "C" <> ''
                AND jsonb_typeof(
                        claim_match_policy -> 'kubernetes.io/serviceaccount/service-account.uid')
                    = 'string'
                AND (claim_match_policy ->> 'kubernetes.io/serviceaccount/service-account.uid')
                    COLLATE "C" <> '')),
    ADD CONSTRAINT principal_binding_generic_production_predicates_check
        CHECK (profile <> 'generic_production'
            OR (claim_match_policy ? 'sub'
                AND jsonb_typeof(claim_match_policy -> 'sub') = 'string'
                AND (claim_match_policy ->> 'sub') COLLATE "C" <> ''));
