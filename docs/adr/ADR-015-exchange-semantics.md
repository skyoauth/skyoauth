# ADR-015: Exchange semantics

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.9. Implementation: T12.3, T12.7, T12.8,
  T21.1–T21.7.
- **Baseline (tasks §11):** "RFC direct subject exchange versus private actor
  mapping; explicit generated selectors and grant-directed bindings".
- **Contracts:** [public-api.md](../contracts/public-api.md) §2.1,
  [identity-registry.md](../contracts/identity-registry.md) §6, §10, §11,
  [errors-retry.md](../contracts/errors-retry.md) §3,
  [token-profiles.md](../contracts/token-profiles.md) §5.

## Context

T00.9 asks M0 to "specify RFC 8693 direct subject exchange versus private
service-delegation actor grant, selector/proof roles, grant-directed binding
evaluation, narrow scope defaults, errors and unsupported two-token
delegation. Private grant URI is not claimed IANA-registered." Design §5.7 and
tasks §2 "Exchange selection and scope" define the behavior. The grant modes
themselves (direct, delegation, dormant impersonation) are ADR-006.

A tenant may have several grants for one audience, and repo-wide and
deployment-specific bindings may overlap for different actors (A25, A50).
Selection must neither deny such configurations by accident nor let an
unauthorized actor fall back onto another grant (design §5.7).

## Decision

1. **Two form-encoded profiles at `/oauth/token`** (design §5.7 table):

   | Profile    | `grant_type`                                              | Input proof                                                  | Output identity                                                       |
   | ---------- | --------------------------------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------- |
   | Direct     | `urn:ietf:params:oauth:grant-type:token-exchange`         | `subject_token`, type `urn:ietf:params:oauth:token-type:jwt` | Verified workload `sub`; no `actor_token` accepted                    |
   | Delegation | `urn:skyoauth:params:oauth:grant-type:service-delegation` | `actor_token`, type `urn:ietf:params:oauth:token-type:jwt`   | Grant's service `sub` and workload `act`; no `subject_token` accepted |

2. **Proof roles.** RFC 8693 distinguishes subject and actor proofs. A single
   workload assertion is not a service subject token, so delegation carries it
   as `actor_token`. The private extension is not advertised as standard
   two-token delegation or as an IANA-registered grant (design §5.7).
3. **Explicit generated selectors.** Both profiles require exactly one
   `skyoauth_trust_source`, exactly one `skyoauth_grant_id` and exactly one
   API `audience`, with optional `scope`. The selectors are nonsecret SkyOAuth
   extensions containing generated immutable IDs, never tenant-local display
   names (design §5.7, §7.4).
4. **Evaluation order** (design §5.7 steps 1–5; tasks §2):
   1. Load the selected source and grant as untrusted candidates; require the
      same tenant and the expected grant mode; reveal no cross-tenant
      existence details on failure.
   2. Verify the assertion only at that source. The grant determines the
      candidate actor and target; an ID does not prove that actor.
   3. Evaluate enabled bindings for that source that map to the selected
      grant's actor and are in its nonempty `allowed_binding_ids`. At least
      one must match the verified evidence. Matching bindings for other actors
      neither make the request ambiguous nor authorize it.
   4. Bindings are identity predicates in v0.1, not resource grants. Several
      eligible matches for the same actor select one by stable ID order for
      provenance; permissions are never unioned.
   5. Validate current tenant, principal, source, binding, grant and service
      status, the registered audience assignment and all ceilings. Record the
      selected binding and the complete immutable decision dependencies in the
      policy revision and audit.
5. **Configuration checks.** Configuration rejects cross-actor and
   cross-tenant binding references (tasks §2; T12.7).
6. **No overrides.** There is no requested subject, target, tenant or mode
   override and no dynamic verifier selection (design §5.7; tasks §2).
7. **Narrow scope defaults.** Omitted scope uses only the grant's explicit
   nonempty `default_scopes`, a subset of all applicable ceilings; otherwise
   `invalid_scope`. Explicit empty or excessive scopes deny rather than being
   trimmed or broadened (design §5.7; T12.8).
8. **Other denials.** Duplicate parameters, missing selectors, profile
   mismatch, unsupported `resource` or requested token type deny. One exact
   registered API audience per credential (design §5.7; T21.1). `resource` is
   always rejected; `requested_token_type` is accepted only when absent or
   exactly `urn:ietf:params:oauth:token-type:access_token` (OQ-ADR015-1).
9. **Error codes** (OQ-ERR-3, lead decision):
   - `invalid_request` for malformed input, duplicate parameters, missing
     selectors, unsupported parameters and profile mismatch;
   - one uniform `invalid_grant` for any source, grant, binding or proof
     failure, revealing no detail about which one failed (ERR-020);
   - `invalid_target` for an `audience` not in the grant's set or not
     assigned to the tenant;
   - `invalid_scope` and `unsupported_grant_type` keep their existing
     meaning.
10. **Response.** Success returns `access_token`, `token_type=Bearer`,
    `expires_in`, explicit `scope` and
    `issued_token_type=urn:ietf:params:oauth:token-type:access_token`, with
    no-store and never a WIF refresh token (design §5.7). Errors are
    OAuth-shaped, with no redirects, and the private grant is clearly labeled
    (T21.2).
11. **Post-create IDs.** Job and client configuration uses the IDs returned by
    creation or export, not operator-chosen global identifiers (design §5.7,
    §7.4; tasks §2).
12. **Separate upstream exchange.** The upstream-provider exchange adapter is
    separate from these profiles (design §5.5, §5.7; ADR-009).

## Consequences and requirements

- Contract requirements: API-010 to API-015, API-017, API-018 (the WIF
  exchange), IR-062 and IR-063 (scope ceilings and defaults; IR-063 is
  canonical for scope omission), IR-083 (one audience per exchange from the
  grant's set), IR-021 (names are never selectors), the `allowed_binding_ids`
  row in identity-registry §10, IR-160 (parameter namespace), ERR-020
  (non-enumerating failures) and the errors-retry §3 table, TP-040 and TP-044
  (issued `wif` claims; no refresh credential), TP-033 (each issuance gets a
  new `jti`).
- Repo-wide and deployment-specific bindings for different actors can coexist
  without accidental denial or unauthorized fallback (design §5.7).
- Conformance rows: A01, A02, A03, A25, A26, A49, A50.

## Alternatives considered

- **Standard RFC 8693 two-token delegation.** Unsupported in v0.1 (T00.9;
  design §5.7).
- **Selecting a verifier, subject, target or mode from the request or token.**
  Rejected (design §3.1, §5.7).
- **Name-based selectors.** Rejected; names are tenant-local labels (design
  §7.4; A49).
- **Unioning binding permissions or first-global-match selection.** Rejected
  (design §5.7; T12.3).
- **Denying on overlap with another actor's binding.** Rejected; other actors'
  bindings are ignored (design §5.7; T12.7).
- **Issuing the full ceiling when scope is omitted.** Rejected (design §5.7;
  A26).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-ERR-3** — OAuth `error` values for the denials other than
  `invalid_scope`. Decided for `/oauth/token` (lead decision, 2026-11-19): the
  mapping in item 9. The errors-retry contract entry for OQ-ERR-3 still reads
  open and needs a follow-up amendment; this ADR does not edit the contract.
- **OQ-ERR-7** — HTTP status and OAuth error for an unavailable replay store at
  `/oauth/token` (open).
- **OQ-API-8** — whether the private grant appears in the metadata's
  `grant_types_supported` (open).
- **OQ-IR-6** — export field names for grants and bindings (open).
- **OQ-IR-7** — grants with several audiences. Decided (lead decision,
  2026-11-19): each request selects one through `audience` (IR-083).
- **OQ-IR-11** — whether a `scope` parameter repeating a token is rejected
  outside comparison v1 (open; lead lean recorded).

New questions raised by this ADR:

- **OQ-ADR015-1 — `resource` and `requested_token_type`.** Decided (lead
  decision, 2026-11-19): `resource` is always rejected; `requested_token_type`
  is accepted only when absent or exactly
  `urn:ietf:params:oauth:token-type:access_token` (item 8). Original
  question: design §5.7 denies
  an "unsupported resource or requested token type", and T21.1 rejects
  "unsupported target/subject/resource parameters". The sources did not say
  whether any `resource` value is supported, or whether `requested_token_type`
  is accepted when it names
  `urn:ietf:params:oauth:token-type:access_token` or must be absent.

## Tests

- A01 — valid GitHub push with required claims and the selected grant/binding
  gets the scoped `wif` profile.
- A02, A03 — non-matching context or proof mismatch denies.
- A25 — several same-audience grants; the generated grant selector chooses the
  actor and target; override, wrong tenant or mode denies.
- A26 — scope omitted with and without defaults, empty and excessive scopes.
- A49 — exchange with names instead of IDs rejects.
- A50 — overlapping bindings for different actors; only the grant actor's
  eligible bindings count; no union.
- Task tests: T21.7 (parser/selector fuzzing, overlapping bindings, scope
  defaults, non-enumerating errors), T52.2, T52.7.
