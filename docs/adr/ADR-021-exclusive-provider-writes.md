# ADR-021: Exclusive provider writes and credential-only rotation

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.16 ("exclusive provider semantic transitions
  versus credential-only rotation") (inferred: tasks §2 names no ADR in T00.16).
  Implementation: T13.9, T30.9, T10.7, T51.1, T51.11.
- **Baseline (tasks §11):** "Read-only active observations, generic
  mutation/import rejection, sole epoch-advancing semantic transition M1b;
  separate audited credential-only rotation preserves epochs"
- **Contracts:** [public-api.md](../contracts/public-api.md) §7, §7.2;
  [lifetimes.md](../contracts/lifetimes.md) §4.

## Context

Which human provider a tenant trusts is an authentication-critical choice. If an
ordinary PATCH, an import, a config reload or deleting the active provider could
change it, a write meant as policy administration would silently change who can
log in and would bypass epoch invalidation (design §7.3; design §2 C10; T00.7
"generic-provider-write bypass"). At the same time, upstream client secrets and
keys must rotate routinely, and doing that through a provider switch would log
every user out (design §7.3). This ADR fixes the write boundary; the
transition's effect on state is ADR-012.

## Decision

### Read-only active observations

1. `TenantLoginState.active_provider_id` is the sole active-provider pointer;
   `HumanProvider` has no independently writable active flag. All GET and export
   representations of active state are read-only observations (design §7.3).

### Generic mutation and import rejection

2. Ordinary provider PATCH, deletion or disable of the active provider, GitOps
   imports and config reloads reject any attempt to change the pointer,
   authentication epochs or the active provider's issuer, client, callbacks or
   authentication semantics. Creating and testing inactive candidates is
   permitted (design §7.3; T13.9).
3. No import replaces the transition, including one submitted by an operator
   holding every role; a proposed active-state change is always rejected in an
   ordinary import (design §7.3; ADR-008).
4. A rejected generic write leaves epochs unchanged (tasks §8 A47).

### Sole epoch-advancing semantic transition (M1b)

5. One M1b primitive covers authentication-critical changes, initial activation
   from null, switch, disable and rollback: an immutable plan, dry-run and
   commit against expected login and configuration revisions; only its
   authorized commit updates login state and advances epochs atomically, with
   the enrollment hold and audit (design §7.3; T13.9).
6. M5 migration tooling (T51) orchestrates this primitive and is not an
   alternate writer; break-glass recovery may run the same validated transition
   only (design §7.2; T51.1).
7. Rollback uses the same transaction with fresh monotonic epochs (design §7.3;
   ADR-012).

### Separate audited credential-only rotation

8. A dedicated, audited `provider_admin` operation may replace the versioned
   secret or key reference for the same issuer, upstream `client_id`,
   client-authentication method, callbacks and identity and authentication
   semantics, including on the active provider (design §7.3; T30.9).
9. It compares expected provider and credential revisions, validates the
   unchanged semantic tuple and advances only administrative and credential
   revisions. Provider `auth_epoch` and tenant `auth_generation` do not change;
   sessions, native refresh families and pending transcripts keep their identity
   binding (design §7.3).
10. Only explicitly configured versions are used for bounded provider-supported
    overlap; there is no arbitrary secret or key fallback. Lack of upstream
    overlap may fail an in-flight code exchange but does not log out existing
    sessions (design §7.3).
11. Requests that also change issuer, `client_id`, auth method, callbacks or
    assurance are rejected by this endpoint and need the transition plan. GitOps
    uses an explicitly typed credential-only operation with identical validation
    (design §7.3).
12. Secret bytes never appear in configuration exports or logs (design §7.3).
13. A compromised credential can separately trigger a deliberate
    epoch-invalidating transition (design §7.3; T30.9).

## Consequences and requirements

- Contract requirements: API-148 (transition only through plan and commit),
  API-149 (credential-only rotation boundary), API-121 (no active-provider write
  through import), LT-030 (fresh epochs on rollback).
- Routine upstream credential rotation is invisible to users; provider changes
  always force reauthentication (design §7.3).
- A GitOps pipeline cannot express an active-provider change (design §7.3).
- Conformance rows: A47, A63; A17 for rollback.

## Alternatives considered

- **An active flag on `HumanProvider`.** Rejected (design §7.3).
- **Provider changes through PATCH, import or reload.** Rejected (design §7.3).
- **Rotating credentials through a provider switch.** Rejected; it would
  invalidate all sessions (design §7.3).
- **Arbitrary secret or key fallback during rotation.** Rejected (design §7.3).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-API-7** — the roles that may read login state are not named (open).
- **OQ-API-11** — grouped-path shorthand (open; lead lean recorded).
- **OQ-TM-7** — separation of duty. Decided (lead decision, 2026-11-19): switch
  and rollback commit need a distinct second `adm_*` approver unless an explicit
  audited instance policy allows single-actor mode.
- **OQ-TM-12** — audit sink. Decided (lead decision, 2026-11-19): provider
  switches are also emitted to an append-only external sink.
- **OQ-TM-13** — secret references. Decided (lead decision, 2026-11-19): a
  provider `credential_ref` resolves only within the tenant's provisioned secret
  namespace.
- **OQ-TM-14** — bulk session revocation. Decided (lead decision, 2026-11-19): a
  revision-checked, audited operation advances the tenant's `auth_generation`
  without a provider change; to be specified before M1b and M3.

New questions raised by this ADR:

- **OQ-ADR021-1 — Second epoch-advancing path.** The baseline makes the provider
  transition the "sole epoch-advancing semantic transition", while the OQ-TM-14
  decision adds an operation that advances `auth_generation` without a provider
  change. The sources do not say whether that operation is a mode of the
  transition primitive or a separate path, which endpoint and role own it, or
  whether compromise-triggered invalidation (T30.9) uses it or a full
  transition.
- **OQ-ADR021-2 — Rotation overlap bound.** T30.9 requires a "bounded configured
  overlap" for credential-only rotation, but no default, maximum or field for it
  is given.

## Tests

- A47 — PATCH, import, reload, delete and authentication-critical edits reject
  atomically with epochs unchanged; initial activation, switch and rollback via
  the plan.
- A63 — credential-only rotation preserves epochs, sessions and refresh; mixed
  semantic changes require the transition.
- A17 — rollback after independent policy changes.
- Task tests: T51.3, T51.11.
