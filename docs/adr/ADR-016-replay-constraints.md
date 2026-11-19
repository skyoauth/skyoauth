# ADR-016: Replay and constraints

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.12. Implementation: T11.11, T12.2, T12.6,
  T12.9, T21.5, T21.6, T21.8, T22.7, T23.5, T23.6.
- **Baseline (tasks §11):** "Reusable default/projected tokens; single-use
  only verified on-demand capability; profile-specific signed
  constraints/revisions".
- **Contracts:** [identity-registry.md](../contracts/identity-registry.md)
  §8, §10, §12, [token-profiles.md](../contracts/token-profiles.md) §4, §5,
  §8, [errors-retry.md](../contracts/errors-retry.md) §3,
  [lifetimes.md](../contracts/lifetimes.md) §9, §11.

## Context

T00.12 asks M0 to "define matcher omission and source-capability replay
semantics: required production claims cannot be omitted; reusable default;
single-use only verified on-demand JWTs, never projected Kubernetes/TokenReview
sources." Design §9 lists assertion theft and replay as threats. Not every
source can supply a fresh verified `jti` per exchange: TokenReview returns
authenticated user and audience evidence, not a claim set (design §5.4), and
rereading a projected file does not promise a fresh token (design §5.3).

The issued credential carries signed constraints and a policy revision, so
that verifiers and live checks know exactly which policy authorized it
(design §6, §6.1).

## Decision

### Matcher semantics

1. Binding matcher predicates are ANDed. A configured claim absent from
   verified evidence is a non-match. Omitted optional predicates are
   unconstrained. Strings match exactly, with no implicit regex or wildcard
   (design §5.3; T12.2).
2. Required production predicates cannot be omitted, and deleting a predicate
   is explicit privilege widening that needs review (design §5.3; T12.2;
   A37).
3. For GitHub, production bindings require immutable owner and repository
   IDs, explicit `event_name`, ref, environment and workflow identity, plus
   reusable-workflow identity when used. A default-branch ref or workflow
   does not establish a safe event; the design example is push-only. GitHub's
   human `actor` is audit provenance, not a human SkyOAuth login (design
   §5.3; T22.2). SkyOAuth does not rely on GitHub environment or branch
   protection: `environment` is an additional ANDed predicate, and
   self-hosted runners shared across trust domains are out of scope and
   residual risk ([threat model](../threat-model.md) OQ-TM-2).
4. **Required predicates per binding profile template.** The required
   predicate set is keyed on the binding `profile` template (a fixed enum,
   for example `github_production`, `kubernetes_production` and
   `generic_production`), not on the source kind: GitHub is an
   `oidc_discovery` source, and Kubernetes local JWT validation uses an
   `uploaded_jwks` or `oidc_discovery` source (OQ-ADR005-1). Enrollment
   checks that the template fits the source and its `assertion_profile`.
   - `github_production` requires the item 3 set.
   - `kubernetes_production` requires namespace, service-account name and
     service-account UID.
   - `generic_production` requires an exact `sub`.

   The binding `profile` is a template name separate from the source's
   `assertion_profile` (OQ-ADR005-2; OQ-ADR016-1).

### Replay is a source capability

5. **Reusable (default).** Another otherwise-valid exchange of the same proof
   inside its lifetime is permitted only after fresh policy evaluation and
   rate limits, and produces a new output `jti` (design §5.3).
6. **Single-use (opt-in, eligible sources only).** Permitted only for locally
   signature-verified `oidc_discovery` or `uploaded_jwks` sources enrolled
   with an on-demand assertion profile and a client and issuer able to obtain
   a fresh signed nonempty `jti` per exchange. SkyOAuth atomically consumes a
   keyed digest of `(tenant, source_id, exact_issuer, verified_jti)` across
   replicas and grants; exactly one attempt may issue. A missing `jti`, a
   store failure or a replay denies; a crash may burn the proof, and a retry
   needs a fresh assertion (design §5.3; T21.6).
7. **Retention.** Consumption is retained through proof `exp` plus skew and
   across digest-key rotation; provider switch, rollback, failover and restore
   never reset it (design §5.3; T21.8).
8. **Projected tokens are reusable only.** Kubernetes projected tokens,
   including TokenReview sources, use `reusable` in v0.1. Enrollment and
   import reject `single_use` for `kubernetes_token_review` or any
   projected-service-account assertion profile, even when keys could be
   verified locally. A `jti` is never invented from decoded input for replay
   enforcement (design §5.3, §5.4; T11.11, T23.6).
9. **Generic JWT sources** require an explicit tested renewal capability
   before opting into single-use (design §5.3; T11.11).

### Profile-specific signed constraints and revisions

10. Every credential carries signed `skyoauth_constraints` and
    `skyoauth_policy_revision` (design §6).
11. **`wif`** uses `authorization: allowlist`: values within a dimension are
    alternatives; different dimensions are ANDed with tenant, audience, scope
    and RBAC. Missing or empty required dimensions deny; a grant ID alone is
    insufficient. The issued constraints are the profile-appropriate narrowed
    constraints within the grant (and, for delegation, the service) ceilings
    (design §6; T21.5).
12. **Human profiles** use exactly `{"version":1,"authorization":"backend_rbac"}`,
    with no membership claim; the backend's RBAC decides. The WIF profile
    cannot use `backend_rbac` or omit allowlists (design §6).
13. Unknown constraint fields or versions and the wrong authorization mode
    deny (design §6; A30).
14. **Policy revisions** are immutable typed dependency sets: WIF snapshots
    the tenant/resource assignment, chosen source and binding, grant and
    optional service. Live checks deny superseded or invalidated revisions and
    never reinterpret an old token under broader policy. Staging, observation
    sequence, operational limits and bundle-only pointer changes are not
    authorization dependencies (design §6.1; tasks §3 "Policy revisions";
    T12.6).

## Consequences and requirements

- Contract requirements: IR-120 to IR-123 (allowlists), IR-130, IR-131
  (`backend_rbac`), IR-140, IR-141 (unknown means deny; per-resource-server
  constraint schema), IR-150 (backend order), the `PrincipalBinding` row in
  identity-registry §10 and the "configured binding predicate absent" row in
  §12; TP-033 (new output `jti`), TP-035 (`PolicyRevision` ID), TP-040,
  TP-042, TP-045, TP-070 (`jti` is not a verifier replay key), TP-072, TP-080;
  ERR-023 (single-use replay, missing `jti` or store failure denies); the
  lifetimes §9 retention table, LT-100, LT-101 (restore never revives consumed
  state).
- A canceled job can leave an issued bearer credential valid until expiry;
  critical operations use live checks (design §5.3, §6.1).
- Conformance rows: A02, A16, A21, A23, A24, A30, A35, A37, A54.

## Alternatives considered

- **A universal replay toggle.** Rejected: replay policy is a source
  capability (design §5.3).
- **Single-use for projected or TokenReview tokens.** Rejected (design §5.3;
  A54).
- **Inventing a `jti` from decoded TokenReview input.** Rejected (design
  §5.4).
- **Regex or wildcard matching.** Rejected (design §5.3).
- **A human subject-prefix exemption from constraints.** Rejected (design §6;
  A30).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-IR-1** — constraint dimension catalogue. Decided (lead decision,
  2026-11-19): a versioned per-resource-server schema (IR-141).
- **OQ-IR-10** — whether action `required_resource_dimensions` apply to human
  profiles (open).
- **OQ-TP-7** — whether `skyoauth_profile_version` and the constraints
  `version` version independently (open).
- **OQ-ERR-7** — status and OAuth error for an unavailable replay store (open).
- **OQ-LT-13** — restore quarantine. Decided (lead decision, 2026-11-19):
  default 15 min, ceiling 60 min; consumed state is preserved or the affected
  credentials are revoked (LT-100, LT-106).
- **OQ-ADR005-2** — the assertion-profile value set this ADR's eligibility
  rule depends on. Decided (lead decision, 2026-11-19; raised by ADR-005):
  `on_demand_jwt`, `reusable_jwt` and `projected_service_account`;
  `single_use` only with `on_demand_jwt` on an `oidc_discovery` or
  `uploaded_jwks` source (item 6).
- **OQ-TM-2** ([threat model](../threat-model.md) §6) — GitHub-side
  preconditions. Decided (lead decision, 2026-11-19): no reliance on GitHub
  environment or branch protection; bindings pin event, ref and workflow,
  `environment` is an additional ANDed predicate, and shared self-hosted
  runners are residual risk (item 3).

New questions raised by this ADR:

- **OQ-ADR016-1 — Required production predicates outside GitHub.** Decided
  (lead decision, 2026-11-19): required predicate sets are keyed on the
  binding `profile` template (for example `github_production`,
  `kubernetes_production`, `generic_production`), and enrollment checks that
  the template fits the source and its `assertion_profile`. Kubernetes
  requires namespace, service-account name and UID; generic requires an exact
  `sub`; GitHub keeps the item 3 set (item 4). Original question: the
  required set is given only for GitHub (design §5.3; T12.2). For
  `uploaded_jwks`, other `oidc_discovery` and Kubernetes bindings, the sources
  do not say which predicates are required, or how a binding is designated
  "production" (the design §5.7 example uses `profile: github_production`).
- **OQ-ADR016-2 — Widening approval.** Deleting a predicate is "explicit
  privilege widening" (design §5.3), and the trust-source, keyset, binding and
  grant endpoints require "explicit widening approval" (tasks §2 "Endpoint
  matrix"; ADR-008 baseline), but the approving role, the operation and its
  record are not defined. Open here: it is decided in ADR-008 (next ADR PR).

## Tests

- A02 — otherwise-matching non-push or wrong-context proof denied; production
  binding not satisfied by PR, dispatch, comment or `workflow_run`.
- A23 — reusable proof replay issues a new output `jti` after fresh
  evaluation.
- A24 — eligible on-demand single-use proof replay across replicas and grants:
  exactly one issuance; missing `jti`, replay or store failure denied.
- A35 — consumed stays consumed through provider switch/restore and
  digest-key changes.
- A37 — required omissions reject; optional omission explicit; removal
  reviewed as widening.
- A54 — projected-token reuse works; `single_use` enrollment denied.
- A30 — absent, unknown or contradictory profile claims and WIF constraints
  fail closed.
- A16, A21 — constraints and revisions preserved; residual TTL explicit.
- Task tests: T12.9, T21.6, T21.8, T22.7, T23.5, T52.2.
