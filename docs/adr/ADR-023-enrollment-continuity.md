# ADR-023: Human enrollment and migration continuity

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.16 ("enrollment policy/hold") (inferred: tasks §2
  names no ADR in T00.16). Implementation: T30.4, T30.8, T13.8, T13.9, T51.4,
  T51.11.
- **Baseline (tasks §11):** "preprovisioned default, explicit zero-privilege
  auto-create; switch/rollback hold and deliberate generation-bound resume"
- **Contracts:** [identity-registry.md](../contracts/identity-registry.md) §5.1;
  [public-api.md](../contracts/public-api.md) §3, §7, §7.2;
  [errors-retry.md](../contracts/errors-retry.md) §5.

## Context

An upstream login proves an issuer and subject, not a SkyOAuth principal. On a
first login there may be no verified link, and after a provider switch every
user arrives from a new issuer with new subjects (design §5.1.1, §8). Creating
principals automatically would be convenient for opted-in public apps, but
during migration it would silently give returning users new, empty identities
and detach them from their backend RBAC; matching by email would let one
provider's account claim another's identity (design §2, §5.1.1; T00.7
"identity-linking confusion"). This ADR fixes when a login may create a
principal and how migration blocks that until operators have reconciled links.

## Decision

### Enrollment policy

1. **Versioned tenant policy.** A versioned `HumanEnrollmentPolicy` per tenant
   applies to both browser and native login, so the SPA and the CLI behave the
   same on first login (design §5.1.1; T30.4, T30.8).
2. **`preprovisioned` (default).** An authenticated but unlinked subject is
   denied with a non-enumerating `enrollment_required` result (design §5.1.1).
3. **`auto_create` (explicit opt-in).** After the same full OIDC and browser
   checks, a fresh `usr_*` principal and verified link are created atomically
   for the exact active provider, issuer and subject. Concurrent first logins
   converge on one principal through a unique tenant, provider, issuer and
   subject constraint (design §5.1.1; T30.4).
4. **Zero privilege.** New principals start with no backend resource privileges;
   application onboarding and RBAC are separate. Auto-create never matches by
   email, copies another user's membership or creates operator authority (design
   §5.1.1).
5. **Disabled identities.** Existing disabled links or principals deny rather
   than triggering a replacement create (design §5.1.1).
6. **Verified links.** Resolution uses tenant, provider, exact issuer and
   subject. Email equality never links identities (design §2; IR-041).

### Switch and rollback hold

7. **Hold set atomically.** `TenantLoginState.enrollment_hold` is set by a
   provider switch or rollback in the same transaction as epoch invalidation,
   and overrides `auto_create` (design §5.1.1; ADR-012).
8. **Rechecked on every callback.** Every callback rechecks the current hold,
   policy and generation before creating any principal; there is no auto-create
   across a concurrent switch or rollback (design §5.1.1; T30.8).
9. **Effect.** Unmatched replacement-provider subjects are denied while the hold
   is set, not assigned new IDs. Existing verified links continue normally after
   reauthentication (design §5.1.1).
10. **Initial activation.** Activation from a null provider may explicitly
    enable `auto_create` only as an approved fresh-install choice in its plan
    (design §5.1.1).

### Deliberate generation-bound resume

11. **Explicit operation.** After link reconciliation, `provider_admin` may
    resume enrollment through
    `POST /admin/v1/tenants/{tenant}/human-enrollment-policy/resume`, a
    revision-checked, audited reconciliation acknowledgement bound to the
    expected current provider, login generation and revision; it clears the hold
    only for current state (design §5.1.1; tasks §2 "Endpoint matrix").
12. **Nothing else clears it.** Elapsed time, import, a policy edit, restart or
    rollback never clears the hold; the enrollment-policy PATCH cannot clear it
    (design §5.1.1; tasks §2 "Endpoint matrix").
13. **Warning.** The confirmation warns that resuming lets genuinely unlinked
    subjects become new users, not inherit old identities. Existing-user
    continuity must be verified before resuming; equivalence cannot be inferred
    from claims (design §5.1.1).
14. **No side effects.** Changing policy or hold never changes WIF or role
    assignments (design §5.1.1).

## Consequences and requirements

- Contract requirements: IR-041 (exact issuer and subject, no email linking),
  IR-042 (zero-privilege new principals), API-150 (resume boundary).
- After a switch, unlinked users are blocked until operators link them or resume
  enrollment; resuming early can create duplicate identities for returning users
  (design §5.1.1).
- Invitation workflows are deferred; operators preprovision through the
  verified-enrollment path (design §5.1.1).
- Conformance rows: A22, A47, A60.

## Alternatives considered

- **Auto-create by default.** Rejected; `preprovisioned` is the default (design
  §5.1.1).
- **Email-based linking or merging.** Rejected (design §2, §5.1.1).
- **Clearing the hold on a timer, import or policy edit.** Rejected (design
  §5.1.1).
- **Mandatory per-user mTLS enrollment.** Avoided for opted-in public apps
  (design §5.1.1).
- **Invitation workflows.** Deferred (design §5.1.1).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-ERR-6** — the HTTP status and rendering of `enrollment_required` (open).
- **OQ-API-7** — the roles that may read login state, including the hold (open).
- **OQ-TM-6** — verified linking ceremony. Decided (lead decision, 2026-11-19):
  enrollment of a new principal is operator-asserted and audited; a link to an
  existing principal uses a browser-bound transaction proving both identities,
  and if the old IdP is unavailable during migration an operator-asserted link
  is allowed with OQ-TM-7 approval and user notification.
- **OQ-TM-7** — separation of duty. Decided (lead decision, 2026-11-19): links
  to existing principals need a distinct second `adm_*` approver; enrollment
  resume creates only zero-privilege principals and may be performed by a single
  actor.

New questions raised by this ADR:

- **OQ-ADR023-1 — Hold on initial activation.** Design §5.1.1 says a switch or
  rollback sets the hold and that activation from null may enable `auto_create`
  in its plan. Whether initial activation from null sets `enrollment_hold`,
  leaving a fresh install with `auto_create` blocked until a resume, is not
  stated.
- **OQ-ADR023-2 — Disable of the active provider.** The transition primitive
  covers "switch/disable/rollback" (T13.9), but whether disabling the active
  provider without a replacement sets the hold, and what `enrollment_required`
  callers see while no provider is active, is not stated.

## Tests

- A60 — first browser and native login in default and auto-create mode,
  concurrent callbacks, disabled user, switch and rollback hold.
- A22 — email-only link or upstream admin-role claim.
- A47 — generic writes cannot move the provider or clear state.
- Task tests: T30.7, T30.8, T51.11.
