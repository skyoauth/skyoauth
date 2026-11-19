# ADR-008: Policy writes, imports and approval

- **Status:** Proposed, M0 — ratification pending maintainer review.
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
   `HumanProvider` (design §7; T10.1).
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
   import never wipes objects it omits (design §7.4; T10.7).
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
    and is recorded in the atomic audit record. A widening write without the
    flag is rejected (inferred: the decision names the flag as required). A
    distinct second `adm_*` approver, as OQ-TM-7 requires for provider switch
    commits, is optional and not required by default.
13. **Deleting a predicate is widening.** Matcher predicates are ANDed; omitted
    optional predicates are unconstrained; required production GitHub predicates
    cannot be omitted; deleting a predicate is explicit privilege widening and
    is reviewed as such (design §5.3; T12.2).
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
  decision, 2026-11-19): switch and rollback commit and links to existing
  principals need a distinct second `adm_*` approver unless an explicit audited
  instance policy allows single-actor mode; enrollment resume may be
  single-actor.
- **OQ-TM-12** — audit sink independence. Decided (lead decision, 2026-11-19):
  operator writes and other security events are also emitted to an append-only
  external sink, at minimum structured logs; the database audit stays
  authoritative. The sink is chosen by M1a.
- **OQ-TM-13** — external secret references and egress approval. Decided (lead
  decision, 2026-11-19): secret references written in source and provider
  records resolve only within a per-tenant provisioned secret namespace;
  discovery, JWKS and TokenReview egress destinations come from a
  `security_admin`-approved allowlist that tenant operators only choose from.

New questions raised by this ADR:

- **OQ-ADR008-1 — GitOps precedence.** T10.7 requires "GitOps precedence" but no
  source says which of a GitOps document and a later API write wins for the same
  object, or how drift between them is reported.
- **OQ-ADR008-2 — Deletion versus disable.** The baseline names "deletion
  approval", while design §7 and T10.1 describe soft disable and immutable
  revisions. Which objects, if any, can be hard-deleted, and whether deleting a
  whole binding or grant (not only a predicate) needs the same approval, is not
  stated.
- **OQ-ADR008-3 — Widening classification and the optional second approver.**
  The OQ-ADR016-2 decision requires a widening flag, but the sources do not list
  which changes count as widening beyond predicate deletion (for example a wider
  audience ceiling, a new keyset version or an added allowed binding), whether
  the server detects widening itself or relies on the flag, or how an
  installation turns on the optional second approver.

## Tests

- A37 — required predicate omission rejects; optional removal is reviewed
  widening.
- A47 — PATCH, import, reload, delete and authentication-critical edits cannot
  move the active provider; epochs are unchanged on denial.
- A48 — empty installation provisioned by staged operator tools; missing roles
  deny.
- A49 — identical labels in two tenants; create, export and reapply.
- A17 — rollback after independent policy and audience changes leaves them
  untouched.
- Task tests: T10.8, T13.6, T52.7 (import parser fuzzing).
