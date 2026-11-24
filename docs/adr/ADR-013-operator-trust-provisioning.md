# ADR-013: Operator trust and provisioning

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.10. Implementation: T13.1–T13.10, T14.9 (route
  preparation and approval contracts), T51.11, T52.5, T52.8.
- **Baseline (tasks §11):** "Independent keys/local roles, M1a workstation
  operator/local verifier and M1b human contracts. client_admin requests
  immutable preparation; the M3 scoped worker finalizes the version before
  security_admin approval. Approval binds all affected security revisions and
  explicit reenable_targets; activation clears only named current vetoes. No
  implicit role inheritance, generic enable PATCH or stale-plan recovery."
- **Contracts:** [public-api.md](../contracts/public-api.md) §1, §7,
  [identity-registry.md](../contracts/identity-registry.md) §5.2,
  [gateway-containment.md](../contracts/gateway-containment.md) §7, §11.3,
  §14, [lifetimes.md](../contracts/lifetimes.md) §11.

## Context

T00.10 asks M0 to "ratify independent adm identities, local roles, portable
M1a workstation client, deployment-local verifier and offline-key custody.
Split workload provisioning M1a from human provisioning M1b; upstream claims
cannot assign operator rights." Operator authority must not depend on the
replaceable human IdP: a provider switch or rollback must remain possible
while that IdP is down or account linking is broken (design §2 C10, §7.2, §8).
Design §3.1 boundary 2 states that independent `adm_*` identities cannot be
acquired through OIDC claims or WIF. Route-bundle deployment needs separate
tenant preparation and instance approval (design §4.2).

## Decision

### Identities and roles

1. **Independent identities.** Operators authenticate with independent
   `adm_*` identities and registered mTLS public credentials rooted in
   deployment trust. The active local credential and role are checked on every
   call; a certificate alone is insufficient. OIDC roles, groups or emails,
   human sessions and WIF credentials never grant operator authority. Operator
   keys are operational trust anchors, not application API secrets (design
   §7.2; T13.1).
2. **Local roles.** Instance `security_admin` and tenant `trust_admin`,
   `client_admin`, `provider_admin` and `auditor`, with the explicit rights in
   design §7.2. Roles do not inherit one another; one operator may hold
   several roles only by explicit assignment (design §7.2; T13.2).
3. **Per-field authority.** Resource scope and per-field authority are
   enforced on reads, writes and imports. Every write uses validation, an
   optimistic revision check and audit (tasks §2 note under the endpoint
   matrix; T13.2, T13.3).
4. **Imports.** GitOps documents are role-scoped. A combined bundle is
   accepted only if the actor holds every role needed for every mutation;
   otherwise the whole bundle is rejected, never partially applied. Active
   provider state is never writable through import (design §7.3; T10.7).

### Bootstrap, workstation client and recovery

5. **Bootstrap.** Bootstrap is a deployment-local command or Unix-socket
   operation, never public enrollment. It atomically enrolls an initial
   `security_admin` public credential and a separate offline recovery public
   key, audits, and durably closes bootstrap. Restart or an empty
   configuration cannot reopen it (design §7.2; T13.4).
6. **Portable workstation operator (M1a).** `skyoauth-operator` at `operator/`
   is a Linux, macOS and Windows private mTLS client and local recovery
   challenge signer, with no server, database or M4 native-OAuth dependency.
   Operator and recovery private keys stay on the workstation or hardware
   signer, never copied into a pod. Supported TLS client-key and hardware/OS
   signer adapters are documented and tested per platform; unsupported
   combinations fail explicitly and never export a key as a fallback (design
   §7.2, §10.1; tasks §1; T13.3, T13.7, T13.10).
7. **Deployment-local verifier.** The recovery signature is verified by the
   library inside `restore_operator` (a combined verify-and-restore step;
   Ed25519 via `ed25519-dalek`; weak and non-canonical keys are refused at
   verify and at every enrollment point; user ruling, 2026-11-24). The
   service binary keeps only the deployment-local bootstrap and the recovery
   transport (design §7.2; tasks §1; docs/proposals/recovery-verified-response.md).
   Accepted residual (user, 2026-11-23, Q7 of the second-approver proposal):
   while the second-approver toggle is on, one `security_admin` can enrol a
   second identity, grant it `security_admin` and approve through it, until
   gating `security_admin` grants is added.
8. **Break-glass recovery.** The restricted local service emits a
   short-lived, single-use challenge with the instance identity, the
   operation/arguments digest and the expected revision. The workstation
   verifies and displays that context and signs it with the offline recovery
   key; only the signed response crosses the separately authorized
   deployment-local channel. Recovery permits bounded operator restoration
   (M1a) or the same validated provider switch or rollback (M1b) only, never
   arbitrary WIF edits, audience reassignment or token minting. Challenges are
   consumed durably, audited and alerted, and recovery keys are rotated after
   use. Recovery is rehearsed with the human IdP down (design §7.2; T13.5,
   T13.7).
   - Operator restoration only enrolls a replacement `security_admin`
     credential and revokes operator credentials (OQ-TM-8).
   - The same signed recovery transaction enrolls the replacement recovery
     public key. No online path, including an online `security_admin`, can
     replace or rotate it (OQ-TM-8, OQ-TM-15).
   - v0.1 has a single recovery key; a quorum is deferred (OQ-TM-8).
   - The recovery socket is owned by the service UID with mode 0600;
     `pods/exec` on the SkyOAuth namespace equals channel access (OQ-TM-9).

### Provisioning split

9. **M1a workload provisioning.** `security_admin` creates tenants, the
   audience, checker identities, actions and explicit roles; `trust_admin`
   creates workload and service principals, sources, bindings and grants.
   This chain works without SQL edits and without human tables (T13.8; tasks
   §9 "Slice assignment"). Secret references that `trust_admin` (and, in
   M1b, `provider_admin`) configure resolve only within a per-tenant
   provisioned secret namespace, and discovery, JWKS and TokenReview egress
   destinations come from an allowlist approved by instance `security_admin`;
   tenant operators only choose from it (OQ-TM-13).
10. **M1b human provisioning.** M1b adds origin, route and bundle versions,
    scoped controller enrollment and deployment approval, separate capacity
    policy, client and human policy, enrollment, provider and link
    provisioning and initial provider activation (from a null pointer, through
    the switch operation) to the same operator client before M3 (design §7.2;
    T13.8, T13.9). One explicitly scoped operator and tenant is a valid small
    deployment, not an implicit-tenant protocol (design §1.3, §7.2), but only
    under the explicit audited single-actor instance policy; otherwise every
    plan commit except a disable-only commit, and links to existing
    principals, need a distinct second `adm_*` approver (OQ-TM-7).
    Provisioning a link to an existing principal uses a browser-bound
    transaction that proves both identities, or, when the old IdP is
    unavailable during migration, an operator-asserted link with OQ-TM-7
    approval and user notification; operator enrollment of a new principal is
    operator-asserted and audited (OQ-TM-6).

### Route preparation and approval

11. **Preparation.** Tenant `client_admin` requests an immutable
    `route_bundle_prepare` operation with the input snapshot, expected active
    generation, affected-parent security revisions, required
    `activation_mode` and explicit recovery intent. M1b persists these
    contracts; the M3 isolated scoped worker runs the pinned translator and
    submits its bound result, and only then does the service finalize a
    completed `RouteBundleVersion`. Pending or failed preparations and
    caller-supplied digests are not approvable (design §4.2; tasks §3 "Route
    preparation, approval and recovery"; T14.9).
12. **Approval.** Instance `security_admin` approves only a completed prepared
    version. The expiring approval binds the plan digest, active generation,
    every affected parent `security_revision`, explicit `reenable_targets`,
    scopes, adapter inputs, `activation_mode` and the exact abort plan; a
    `gateway_apply` approval also binds the apply timeout and a finite
    `abort_until` (tasks §2 "Endpoint matrix"; design §4.2).
13. **Activation clears only named vetoes.** Activation clears only the
    explicitly approved `reenable_targets` that are still current and advances
    their revisions atomically with the pin change; all other parents keep
    their status. No PATCH or import can clear a security veto (tasks §3
    "Route preparation, approval and recovery").
14. **No stale-plan recovery.** A disable after approval advances the
    parent's `security_revision` and invalidates the forward approval (the
    09:00 approval, 09:20 disable, 09:30 activation case); recovery needs a new
    preparation and approval (tasks §3; T14.9).
15. **Controller credentials** never substitute for the preparer or approver
    role (design §4.2). Detailed transition, cancel, revoke, abort and
    supersession rules are the T00.5 contract and ADR-020.

## Consequences and requirements

- Contract requirements: API-002 (local credential and role on every call;
  no upstream or WIF authority), API-003 (validated, revision-checked,
  audited writes), API-120 (no role inheritance), API-121 (whole-plan import
  authorization), API-122, API-123, the approval-boundary table API-140 to
  API-155 (including API-152, break-glass limits), the operator endpoint and
  local/workstation interface tables in public-api §7.1, the role table in
  identity-registry §5.2, GW-070 to GW-076 (preparation), GW-130 to GW-137
  (roles, cancel, revoke), GW-230 to GW-236 (security-revision-bound
  recovery and first enablement), LT-100 and LT-107 (restore and recovery challenge).
- Zero static application secrets does not mean zero privileged keys:
  operator and recovery keys need protection (design §9). A compromised human
  IdP cannot rewrite operator authority (design §9).
- Conformance rows: A20, A22, A32, A47, A48, A58, A64.

## Alternatives considered

- **Operator rights from upstream OIDC roles, groups or email.** Rejected
  (design §3.1, §7.2; A22).
- **Public enrollment or public recovery.** Rejected; bootstrap and recovery
  are deployment-local only (design §7.2; tasks §2 "Endpoint matrix").
- **Running the remote client inside the cluster or copying keys into a
  pod.** Rejected (design §7.2; T13.7).
- **SPIRE, sidecar or cloud STS dependency for operator trust.** Not required
  (tasks §0).
- **A generic enable PATCH or import to clear vetoes.** Rejected (tasks §3).
- **Admin UI and self-service tenant onboarding.** Deferred (design §1.3;
  tasks §9).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-API-2** — no operator endpoint revokes a human session, native refresh
  family or authentication context (open). Related: OQ-TM-14 decides a
  revision-checked, audited operation that advances a tenant's
  `auth_generation` without a provider change, revoking the tenant's sessions
  in bulk; per-session and per-family revocation stay open.
- **OQ-API-3** — no operator endpoint administers public issuer keys.
  Decided (lead decision, 2026-11-19) by OQ-TM-10: an admin endpoint for
  public-key emergency disable and rotation is added (ADR-002 item 4). The
  public-api contract now decides it: `/admin/v1/issuer-keys` (API-153), with
  API-042 and API-043 for the JWKS bounds.
- **OQ-API-6** — who may security-disable. Decided (lead decision,
  2026-11-19): tenant `client_admin` only (API-145).
- **OQ-API-7** — roles that may read login state (open).
- **OQ-API-11** — grouped-path shorthand in the endpoint matrix (open; lead
  lean recorded).
- **OQ-GW-9** — authority required for compensation. Decided (lead decision,
  2026-11-19): unrevoked approval and current controller scope; disabling the
  preparer or approver does not stop compensation.
- **OQ-GW-10** — cancel outside `applying`. Decided (lead decision,
  2026-11-19): rejects with no state change (GW-137).
- **OQ-LT-4**, **OQ-LT-5** — instance maximum for `abort_until` and the
  forward approval expiry are not given (open).
- **OQ-LT-13** — restore quarantine. Decided (lead decision, 2026-11-19):
  default 15 min, ceiling 60 min.
- **OQ-LT-17** — recovery challenge TTL. Decided (lead decision, 2026-11-19):
  default 5 min, maximum 15 min (LT-107).

Threat-model decisions ([threat model](../threat-model.md) §6) that bind
this ADR, each Decided (lead decision, 2026-11-19):

- **OQ-TM-6** — verified linking ceremony: operator enrollment of a new
  principal is operator-asserted and audited; a link to an existing principal
  uses a browser-bound transaction proving both identities, or an
  operator-asserted link with OQ-TM-7 approval and user notification when the
  old IdP is unavailable during migration (item 10).
- **OQ-TM-7** — separation of duty: every plan commit except a disable-only
  commit (authentication-critical changes to the active provider, activation
  from null, switch and rollback), and every link to an existing principal,
  needs a distinct second `adm_*` approver (`security_admin` or another
  `provider_admin`); single-actor mode only through an explicit audited
  instance policy for small installations; a disable-only commit fails safe;
  zero-privilege enrollment resume may be single-actor (item 10).
- **OQ-TM-8** — recovery scope and key lifecycle: operator restoration only
  enrolls a replacement `security_admin` credential and revokes operator
  credentials; the challenge TTL defaults to 5 min with a 15 min maximum
  (LT-107); every break-glass transaction (operator restoration or provider
  switch or rollback) enrolls a replacement recovery public key in the same
  signed transaction and retires the used key; one recovery key in v0.1,
  quorum deferred (item 8).
- **OQ-TM-9** — local recovery channel access: socket owned by the service
  UID, mode 0600; `pods/exec` on the SkyOAuth namespace limited to trusted
  infrastructure administrators (item 8).
- **OQ-TM-12** — operator writes, recovery, key operations and provider
  switches are also emitted to an append-only external sink; the database
  audit stays authoritative.
- **OQ-TM-13** — per-tenant secret namespaces and a `security_admin`-approved
  egress allowlist (item 9).
- **OQ-TM-14** — bulk session revocation by advancing a tenant's
  `auth_generation` (see OQ-API-2).
- **OQ-TM-15** — no online path replaces the recovery key; only the signed
  recovery transaction over the deployment-local channel does (item 8).

New questions raised by this ADR:

- **OQ-ADR013-1 — Recovery key rotation path.** Decided (lead decision,
  2026-11-19) by OQ-TM-8 and OQ-TM-15: the same signed local recovery
  transaction enrolls the replacement recovery public key, and no online path
  can replace it. Original question: design §7.2 requires rotating
  recovery keys after use, and `RecoveryState` holds `recovery_public_key` and
  `recovery_key_epoch` (tasks §3). Neither the endpoint matrix nor the local
  interface names the operation, channel or role that enrolls the
  replacement recovery public key.
- **OQ-ADR013-2 — Scope of "bounded operator restoration".** Decided (lead
  decision, 2026-11-19) by OQ-TM-8: restoration only enrolls a replacement
  `security_admin` credential and revokes operator credentials; v0.1 has one
  recovery key. Original question: design §7.2 and T13.5 permit break-glass
  "operator restoration" and A32 requires "audited independent restoration",
  but the permitted operations (for example re-enrolling a `security_admin`
  credential, revoking a compromised operator, restoring role bindings) are not
  enumerated.
- **OQ-ADR013-3 — Instance audit reader.** Decided (lead decision,
  2026-11-19): instance audit events are readable only through an explicit
  instance-scoped `auditor` assignment; no role inherits it. Original
  question: design §7.2 grants tenant
  `auditor` tenant reads and "separate instance audit authority where
  explicitly granted", and the endpoint matrix says "instance events
  separately authorized", but no role or endpoint for reading instance audit
  events is defined.

## Tests

- A32 — concurrent or reopened bootstrap, forged IdP admin, revoked operator
  and replayed recovery: one enrollment only, no elevation or replay, audited
  restoration.
- A48 — empty installation to a working workload chain (M1a) and human chain
  (M1b) through the operator tools, with no SQL or M4 dependency.
- A64 — macOS, Windows and Linux workstation operator and offline recovery
  against a Linux service; keys never leave the workstation.
- A22 — upstream admin-role claim gives no operator elevation.
- A20 — operator recovery works with the human IdP unavailable.
- A47 — generic writes cannot change the active provider.
- A58 — preparation, mode-bound approval, 09:00/09:20/09:30 stale approval,
  named `reenable_targets` only.
- Task tests: T13.6, T13.7, T13.10, T14.9, T51.11, T52.5, T52.8.
