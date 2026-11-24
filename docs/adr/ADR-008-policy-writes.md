# ADR-008: Policy writes, imports and approval

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The direction is accepted; lead decisions, text marked "(inferred)" and provisional lead picks stay implementation choices that ordinary review can change, while a change to a user ruling goes back to the user (design §12; [status values](README.md#status-values)). Questions still marked open under Open questions stay open: ratification closes none of them.
- **Tasks:** ratified with T00.10 (independent identities and roles behind every
  write) (inferred: tasks §2 names no ADR in T00.10; the README index pairs
  ADR-008 with it). Implementation: T10.4, T10.5, T10.7, T12.2, T13.2, T13.3,
  T13.8.
- **Baseline (tasks §11):** "Revisioned role-scoped DB/GitOps, full-plan
  authorization and explicit widening/deletion approval"
- **Contracts:** [public-api.md](../contracts/public-api.md) §1, §7, §7.2;
  [identity-registry.md](../contracts/identity-registry.md) §3, §5.2, §8;
  [gateway-containment.md](../contracts/gateway-containment.md) §5.

## Context

PostgreSQL is authoritative for all stable authority and one-time state (design
§7). Configuration arrives two ways: the private operator API and GitOps
documents applied through the imports endpoint (design §7.3; tasks §2 "Endpoint
matrix"). Both must be checked against the same independent operator roles,
which never inherit one another (design §7.2), and neither may become a way
around the guarded provider transition (ADR-021) or the gateway sole-writer path
(ADR-020). Matcher semantics make deleting a predicate a privilege increase, so
removal cannot be treated as a harmless edit (design §5.3). This ADR fixes how
writes are versioned, authorized and approved; which role owns which object is
design §7.2 and identity-registry §5.2.

## Decision

### Revisioned writes

1. **Optimistic revisions and audit.** Every write uses validation, an
   optimistic revision check (an expected revision, or the epoch, sequence and
   generation counters the endpoint defines) and an atomic audit record. Updates
   name the existing generated ID and expected revision within the authorized
   tenant (design §7, §7.4; T10.4).
2. **Immutable history.** Typed policy dependencies are immutable sets of
   entity-kind, ID and revision references; issued credentials are never
   reinterpreted through a mutable record. Origin, route and bundle versions are
   append-only; runtime observations and capacity policies have separate storage
   and revision rules (tasks §3 "Policy revisions"; T10.1, T10.4).
3. **Soft disable.** Records are disabled, not cascade-deleted; WIF, audience,
   client, origin and operator records cannot cascade-delete through
   `HumanProvider` (design §7; T10.1). Removal of anything referenced or
   enabled is soft disable only (OQ-ADR008-2). A binding may be hard-deleted by
   an audited admin write only when it is disabled and no grant, approval or
   audit-required record references it; a disabled, unreferenced grant follows
   the same rule. Soft disable of a binding or grant is fail-safe and is not
   widening, so it needs no second approver even when
   `widening_second_approver` is on; deleting a whole binding or grant is
   still widening-class and is approved as in item 12. Decided (lead
   decision, 2026-11-19; reconciles OQ-ADR008-2 with OQ-ADR022-1).
4. **Fail closed.** Store failures never expand privilege, and conservative
   cache invalidation applies (design §7).

### Role-scoped DB and GitOps

5. **Same roles on both paths.** API writes and GitOps documents are checked
   against explicit operator roles with resource scope and per-field authority;
   roles do not inherit one another (design §7.2; T13.2).
6. **Role-scoped documents.** GitOps documents are role-scoped; separate
   provider, client and WIF documents are recommended (design §7.3).
7. **Redacted export and import.** Versioned export and import cover every
   source kind, keysets, audience, action and checker public metadata, client,
   origin, route and bundle configuration versions, separate capacity policies,
   human policy, grants and activation state and operator public metadata, with
   semantic diff, preconditions and approval. Secret and live credential
   material and restorable active route observations are excluded (design §7;
   T10.5).
8. **Reconciliation, not wipe.** Reapplying is tenant-local reconciliation; an
   import never wipes objects it omits (design §7.4; T10.7). For GitOps
   precedence, API writes win: GitOps reports drift from its documents and never
   reverts automatically (lead decision, 2026-11-19, OQ-ADR008-1).
9. **Not ordinary writable configuration.** Active-provider state and
   route-runtime pointers and observations are read-only through PATCH and
   import (ADR-021). Protected gateway resources are applied only by the
   approved controller path, not directly by Helm, Argo CD or Flux (design §4.2;
   T10.7; ADR-020).

### Full-plan authorization

10. **Every role for every mutation.** A combined bundle is accepted only when
    the actor holds every role needed for every mutation and the plan passes the
    same validation; otherwise the whole bundle is rejected. Unauthorized
    sections are never partially applied or ignored (design §7.3; T10.7).
11. **Whole-plan validation.** The imports endpoint performs whole-plan role
    validation and rejects unauthorized sections and active-pointer mutation
    with no partial apply (tasks §2 "Endpoint matrix").

### Explicit widening and deletion approval

12. **Widening is explicit.** Trust-source, keyset, binding and grant writes
    require explicit widening approval (tasks §2 "Endpoint matrix"). Lead
    decision on OQ-ADR016-2 (2026-11-19): a write that widens access carries an
    explicit widening flag and the expected revision of the object it widens,
    and is recorded in the atomic audit record. The server detects whether a
    write widens access; the flag only acknowledges that detection, and a write
    the server detects as widening without the flag is rejected (lead decision,
    2026-11-19, OQ-ADR008-3). A distinct second `adm_*` approver, as OQ-TM-7
    requires for every provider plan commit except a disable-only commit, is
    optional and off by default. It is the instance policy setting
    `widening_second_approver`; turning it on or off is itself an audited write
    that needs a distinct second `security_admin` approver, or one actor when
    the audited single-actor instance policy `single_actor_mode` is on.
    Turning `widening_second_approver` off is a widening write: without the
    widening flag it is rejected like every other widening write (the user's
    ruling, 2026-11-24; the library implements it in `skyoauth_service::operation` (#136), and T13.3 wires the endpoint). `single_actor_mode` (default
    false) is deployment configuration, set at install, so no online admin
    can enable it alone; the database mirrors it read-only, with
    an audit event on change. Whether the local signed recovery transaction can
    also set it was open (identity-registry OQ-IR-13); the interim reading is confirmed (the user, 2026-11-24, relayed by the lead):
    `single_actor_mode` changes only by deployment configuration applied at restart and audited at startup.
    An approval is a second `AdministrativeOperation` of kind `approve` by a
    different actor, who holds `security_admin` for widening writes and
    security-domain toggles (tasks §3 `InstanceSecurityPolicy`; Decided (lead
    decision, 2026-11-19), OQ-ADR008-3). Adding or re-enabling an
    `EgressAllowlistEntry` is also widening-class; disabling one is not
    (Decided (lead decision, 2026-11-20), identity-registry OQ-IR-12).
13. **Deleting a predicate is widening.** Matcher predicates are ANDed; omitted
    optional predicates are unconstrained; the required predicates of the
    binding `profile` template (ADR-016 item 4) cannot be omitted; deleting a
    predicate is explicit privilege widening and is reviewed as such (design
    §5.3; T12.2).
14. **Ceilings.** Writes stay within instance audience assignments and other
    ceilings; a tenant cannot self-assign an audience (design §7.1; ADR-018).

### Separate approval paths

15. Some writes have their own approval boundary and are not governed by
    ordinary policy writes: gateway deployment approval by `security_admin`
    (ADR-020), the provider transition plan and commit (ADR-012, ADR-021),
    security-disable and its explicit re-enable (ADR-020) and enrollment resume
    (ADR-023) (design §4.2, §7.3; public-api §7.2).

## Consequences and requirements

- Contract requirements: API-003 (validation, optimistic revision, audit),
  API-120 (no role inheritance), API-121 (whole-import role check), API-140 to
  API-152 (approval boundaries), IR-022 (expected revision on update), GW-057
  (GitOps tools do not apply managed objects).
- A small installation may give one operator several roles, but only by explicit
  assignment (design §7.2).
- A GitOps pipeline that mixes WIF, client and provider sections must run as an
  actor holding all three roles, or split its documents (design §7.3).
- Conformance rows: A37 (predicate removal reviewed as widening), A47 (generic
  writes cannot move the active provider), A48 (staged operator provisioning
  without SQL), A49 (create, export and reapply), A17 (rollback leaves
  independent policy changes untouched).

## Alternatives considered

- **Partial apply or ignoring unauthorized sections.** Rejected (design §7.3).
- **Wiping objects omitted from an import.** Rejected (T10.7).
- **Direct Helm, Argo CD or Flux apply of protected gateway resources.**
  Rejected (design §4.2; T10.7).
- **Implicit role inheritance.** Rejected (design §7.2).
- **Treating predicate deletion as an ordinary edit.** Rejected (design §5.3).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-IR-6** — export field names differ from the logical model, and which
  names are frozen is not stated (open).
- **OQ-API-11** — the grouped-path shorthand of the endpoint matrix needs two
  readings (open; lead lean recorded).
- **OQ-ADR016-2** — widening approval. Decided (lead decision, 2026-11-19): an
  explicit widening flag, the expected revision and an audit record; an
  OQ-TM-7-style second approver is optional. Recorded in Decision item 12.
- **OQ-TM-7** — separation of duty for identity-critical writes. Decided (lead
  decision, 2026-11-19): every plan commit except a disable-only commit
  (authentication-critical changes to the active provider, activation from
  null, switch and rollback) and links to existing principals need a distinct
  second `adm_*` approver unless an explicit audited instance policy allows
  single-actor mode; a disable-only commit and enrollment resume may be
  single-actor.
- **OQ-TM-12** — audit sink independence. Decided (lead decision, 2026-11-19):
  operator writes and other security events are also emitted to an append-only
  external sink; the database audit stays authoritative. The sink is decided
  (lead decision, 2026-11-19): an operator-configured append-only,
  hash-chained JSONL stream forwarded to a syslog-over-TLS or OTLP-logs
  endpoint, set in deployment configuration (tasks Gate M1a and §3; ADR-002
  item 4).
- **OQ-TM-13** — external secret references and egress approval. Decided (lead
  decision, 2026-11-19): secret references written in source and provider
  records resolve only within a per-tenant provisioned secret namespace;
  discovery, JWKS and TokenReview egress destinations come from a
  `security_admin`-approved allowlist that tenant operators only choose from.

New questions raised by this ADR:

- **OQ-ADR008-1 — GitOps precedence.** Decided (lead decision, 2026-11-19): API
  writes win; GitOps reports drift and never reverts automatically (item 8).
  Original question: T10.7 requires "GitOps precedence" but no source says which
  of a GitOps document and a later API write wins for the same object, or how
  drift between them is reported.
- **OQ-ADR008-2 — Deletion versus disable.** Decided (lead decision,
  2026-11-19): soft disable only for anything referenced or enabled; a binding
  or grant may be hard-deleted by an audited admin write only when it is
  disabled and no grant, approval or audit-required record references it; soft
  disable is fail-safe and not widening; deleting a whole binding or grant
  counts as widening (item 3; consistent with OQ-ADR022-1). Original question:
  The baseline names "deletion approval", while design §7 and T10.1 describe
  soft disable and immutable revisions. Which objects, if any, can be
  hard-deleted, and whether deleting a whole binding or grant (not only a
  predicate) needs the same approval, is not stated.
- **OQ-ADR008-3 — Widening classification and the optional second approver.**
  Decided (lead decision, 2026-11-19): the server detects widening; the flag
  only acknowledges it (item 12). The optional second approver is the instance
  policy setting `widening_second_approver`, off by default; turning it on or
  off is an audited write that needs a distinct second `security_admin`
  approver, or one actor when `single_actor_mode` is on. `single_actor_mode`
  (default false) is the audited single-actor instance policy: deployment
  configuration set at install, mirrored read-only in the database with an
  audit event on change (lead decision, 2026-11-19; item 12); whether the
  local signed recovery transaction can also set it was open
  (identity-registry OQ-IR-13); the interim reading is confirmed (the user, 2026-11-24, relayed by the lead): it changes only by deployment configuration at restart. Both are in the tasks §3 schema with the M1a
  spec amendments. Contracts: identity-registry IR-052 (the setting and its
  effect) and IR-054 (second-approver approvals), public-api API-156 and the
  `/approve` operation endpoints (OQ-API-13). Ruled by the user, 2026-11-22,
  relayed by the lead: a trust keyset version write (a create, an enable, a
  re-enable) and a trust source write count as widening, so while
  `widening_second_approver` is on they need an IR-054 approval by a second
  approver; the second-approver flow was accepted by the user on 2026-11-23 and is
  implemented in `skyoauth_service::operation` (PRs #111, #114-#123;
  nearest task owners T13.3, T13.2, T13.8, T11.6, T10.4 and T10.2; design and
  rulings in docs/proposals/second-approver-gated-writes.md). No endpoint is
  wired before the request layer. Ruled by the user with it (2026-11-23, Q1 to
  Q7 of the proposal; see "Ruled by the user, 2026-11-23" there): Q1 a fixed
  24h `expires_at` and read endpoints that return the digest and the whole
  envelope (OQ-API-14); Q2 a disable-only trust source update is not widening,
  like a soft disable of a binding or grant; Q3 a disabled keyset version
  create is widening; Q4 under `single_actor_mode` the one actor must also hold
  `security_admin`; Q5 the requester is checked again at approve; Q6 no
  fingerprint in the audit event for now (a `request_digest` member is the
  better ADR follow-up than the fingerprint); Q7 gating `security_admin` grants while the toggle is on is a
  follow-up, and until then the residual risk (one `security_admin` can enrol a
  second identity, grant it `security_admin` and approve through it) is
  accepted. Every request that sets `widening_second_approver` to false, a
  false to false write included, needs the widening flag like every other
  widening write (the user, 2026-11-24, relayed by the lead; item 12;
  implemented in the library, `skyoauth_service::operation` (#136); T13.3 wires the endpoint; see the second-approver proposal). Still open: the audit sink TLS
  trust settings and alert routing (OQ-TM-12). Original question: The OQ-ADR016-2 decision
  requires a widening flag, but the sources do not list which changes count as
  widening beyond predicate deletion (for example a wider audience ceiling, a
  new keyset version or an added allowed binding), whether the server detects
  widening itself or relies on the flag, or how an installation turns on the
  optional second approver.

## Tests

- A37 — required predicate omission rejects; optional predicate removal is
  detected as widening, and the expected result is the widening flag plus the
  expected revision plus the audit record; without the flag it rejects.
- A47 — PATCH, import, reload, delete and authentication-critical edits cannot
  move the active provider; epochs are unchanged on denial.
- A48 — empty installation provisioned by staged operator tools; missing roles
  deny.
- A49 — identical labels in two tenants; create, export and reapply.
- A17 — rollback after independent policy and audience changes leaves them
  untouched.
- Task tests: T10.8, T13.6, T52.7 (import parser fuzzing).

## Errata

- 2026-11-21: item 3 allows hard delete of a disabled, unreferenced grant,
  except an impersonation grant, which is never hard-deleted (disabled only):
  deleting and recreating a dormant impersonation grant under
  caller-supplied IDs would revive it. Registry guard: migration `0006`.
