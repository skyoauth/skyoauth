# ADR-012: Human-provider migration

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.16 (exclusive provider semantic transitions,
  enrollment hold) (inferred: tasks §2 names no ADR in T00.16). Implementation:
  T13.9, T51.1–T51.11, T41.5.
- **Baseline (tasks §11):** "Sole provider transition with monotonic auth
  invalidation; WIF/audience/client/operator state preserved"
- **Contracts:** [lifetimes.md](../contracts/lifetimes.md) §4, §11;
  [public-api.md](../contracts/public-api.md) §7.2;
  [identity-registry.md](../contracts/identity-registry.md) §2, §4, §5.1.

## Context

Replacing the human IdP (for example Zitadel with another OIDC provider) is a
goal the stable contract is built around: human migration may invalidate human
authentication state but requires no client or backend redeployment or
reconfiguration (design §2 C04). WIF sources, bindings, grants, audiences,
clients, origins and operator authority must survive unchanged (design §2
C05–C07, C10). Design §8 gives a seven-step runbook. This ADR fixes the
transition's effect on state; the write boundary that makes the transition the
only writer is ADR-021, and the enrollment hold it sets is ADR-023.

## Decision

### One transition

1. **Sole transition.** `TenantLoginState.active_provider_id` changes only
   through the authorized plan and commit of the provider transition, which
   covers initial activation from null, switch, disable and rollback. There is
   no alternate pointer writer; migration tooling (T51) is built on the M1b
   primitive (T13.9), not beside it (design §7.3; T13.9, T51.1).
2. **Immutable plan.** The dry-run plan is immutable and bound to expected login
   and configuration revisions; concurrent relevant changes require a replan. A
   plan that attempts any WIF, audience, client, origin, operator, gateway or
   signer mutation is rejected (design §8 step 3; T51.3).
3. **Operator independence.** Operators authenticate independently of the
   upstream provider; a switch or rollback works during an IdP outage through
   the portable operator client and the local recovery verifier, with no
   upstream-admin link (design §7.2, §8 step 2; T51.11). Under OQ-TM-7 a switch
   or rollback commit needs a distinct second `adm_*` approver; a switch signed
   with the recovery key through the local recovery verifier counts as its own
   approval, the recovery key acting as the second factor, and is audited (lead
   decision, 2026-11-19; OQ-TM-7, OQ-TM-8).

### Monotonic auth invalidation

4. **Atomic commit.** The commit updates only provider login and mapping
   configuration and advances fresh human authentication epochs atomically. It
   invalidates affected browser and native flow bindings, sessions and
   authentication contexts, pending requests and codes, required refresh
   families and dependent continuations, and sets the enrollment hold (design §8
   step 4; T51.4; ADR-023; for disable and activation from null see ADR-023
   items 7 and 10).
5. **Residuals.** Offline human JWTs keep only their documented short TTL (at
   most 300 seconds); live checks reject invalidated contexts; existing stream
   leases expire within their approved remaining window (design §8 step 4;
   T51.4; ADR-010).
6. **Rollback.** Rollback uses the same guarded transaction with fresh monotonic
   epochs; generations never reset. It is never a whole-database restore over
   independent policy changes and never resurrects consumed human or proof state
   (design §7.3, §8 step 7; T51.8).

### Preserved state

7. **WIF.** All external source configurations (IDs, exact issuer, discovery,
   uploaded keysets, TokenReview endpoints, CA and reviewer references,
   audiences, replay policy), bindings, direct and delegation grants, ceilings,
   defaults, constraints and dormant impersonation records survive unchanged;
   consumed-proof state is not reset (design §2 C05–C07; T51.6, T51.7).
8. **Audience, client and origin.** Audience registrations, assignments, actions
   and checker identities, OAuth clients, origins, routes and bundle versions
   and human access policies stay stable (design §2 C03, C04, §7.1).
9. **Operator.** Operator identities, roles and recovery keys are independent of
   the provider (design §2 C10, §7.2).
10. **Issuer and keys.** The issuer does not change and signing keys are not
    rotated for a provider change (design §6; T51.10).
11. **Clients.** Prebuilt TypeScript SPA and Rust CLI artifacts are reused with
    recorded hashes; no rebuild, package upgrade, YAML, callback or client
    registration change (design §8 step 6; T51.5).

### Reauthentication

12. Humans reauthenticate; stable principal and RBAC mappings carry over only
    where a verified link exists. Unmatched users stay blocked under the
    enrollment hold until verified linking or an explicit resume. Equal emails
    do not prove identity continuity (design §2, §8 step 5; ADR-023).

## Consequences and requirements

- Contract requirements: LT-030 (fresh epochs on rollback), LT-101 (no revival),
  IR-012 (no issuer or key change), API-148, API-149 (transition and
  credential-only rotation boundaries), API-150 (enrollment resume).
- Every human must log in again after a switch; native refresh families end
  (design §8; T51.6).
- A human-provider outage blocks fresh human login but not valid WIF or operator
  recovery (design §8; A20).
- Conformance rows: A14, A15, A16, A17, A20, A34, A35, A42, A47, A63.

## Alternatives considered

- **Generic PATCH, import, reload or delete of the active provider.** Rejected
  (design §7.3, §8 step 3).
- **Whole-database rollback.** Rejected (design §8 step 7).
- **Email-based continuity.** Rejected (design §2).
- **Rotating issuer or signing keys with the provider.** Rejected (T51.10).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-LT-13** — restore quarantine duration. Decided (lead decision,
  2026-11-19): default 15 min, ceiling 60 min; longer-lived state relies on
  preserved consumed state or revocation. Applies to restore, not to a provider
  rollback (inferred).
- **OQ-TM-6** — verified linking ceremony. Decided (lead decision, 2026-11-19):
  operator enrollment of a new principal is operator-asserted and audited;
  linking to an existing principal uses a browser-bound transaction proving both
  identities, and if the old IdP is unavailable during migration an
  operator-asserted link is allowed with OQ-TM-7 approval and user notification.
- **OQ-TM-7** — separation of duty. Decided (lead decision, 2026-11-19): the
  switch, rollback and initial-activation commits (initial activation goes
  through the switch commit) and links to existing principals need a distinct
  second `adm_*` approver, unless an explicit audited instance policy allows
  single-actor mode. Disabling the active provider is fail-safe and does not
  need one (lead decision, 2026-11-19).
- **OQ-TM-8** — recovery scope and key lifecycle. Decided (lead decision,
  2026-11-19): recovery restores operators only by enrolling a replacement
  `security_admin` credential and revoking operator credentials; a single
  recovery key in v0.1. A switch signed with the recovery key counts as its own
  approval and is audited (lead decision, 2026-11-19; item 3).
- **OQ-TM-12** — audit sink. Decided (lead decision, 2026-11-19): provider
  switches are also emitted to an append-only external sink.
- **OQ-TM-14** — bulk session revocation. Decided (lead decision, 2026-11-19): a
  revision-checked, audited operation advances the tenant's `auth_generation`
  without a provider change; to be specified before M1b and M3. It is the
  audited compromise transition, the only epoch-advancing path besides the
  provider transition: tenant `provider_admin` per tenant, no single-origin
  variant; the instance-wide response runs it for every tenant (ADR-021).

New questions raised by this ADR:

- **OQ-ADR012-1 — Old-provider links after a switch.** The sources say existing
  verified links continue after reauthentication, but not what happens to
  `HumanSubjectLink` records for the previous provider after a switch: whether
  they stay active, are disabled, or become usable again on rollback without a
  new link. Open; to be decided before M1b/M3 (lead decision, 2026-11-19).
- **OQ-ADR012-2 — Dry-run output.** Design §8 step 7 compares pre and post
  allowed and denied decisions, but the content of the dry-run plan (affected
  session and family counts, the fixtures it evaluates) is not specified. Open;
  to be decided before M1b/M3 (lead decision, 2026-11-19).

## Tests

- A14, A42 — unchanged TypeScript and Rust artifacts through switch and
  rollback.
- A15, A16 — all source kinds, bindings, grants and dormant impersonation
  preserved.
- A17 — rollback after independent policy changes.
- A20 — IdP unavailable.
- A34, A35 — native and proof state across switch and rollback.
- A47, A63 — generic writes rejected; credential-only rotation keeps epochs.
- Task tests: T51.3, T51.5–T51.9, T51.11.
