# ADR-022: Identifier and binding lifecycle

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The
  direction is accepted; the details, including lead decisions and text marked
  "(inferred)", are implementation choices that ordinary review can change
  (design §12; [status values](README.md#status-values)). Questions still
  marked open under Open questions stay open: ratification closes none of
  them.
- **Tasks:** ratified with T00.16 ("generated-ID lifecycle") and T00.9 (selector
  and proof roles, grant-directed binding evaluation) (inferred: tasks §2 names
  no ADR in these tasks). Implementation: T10.2, T12.3, T12.7, T14.8, T10.8.
- **Baseline (tasks §11):** "Generated opaque IDs + tenant-local
  names/create-reference mapping; selected grant's actor/approved binding set
  filters evidence"
- **Contracts:** [identity-registry.md](../contracts/identity-registry.md) §3,
  §4; [public-api.md](../contracts/public-api.md) §2.1, §7.

## Context

WIF callers and clients name the source and grant they use in every exchange,
and SPAs and CLIs carry their client and origin configuration across provider
migrations (design §2 C02, §5.7). If those selectors were user-chosen names or
global IDs, two tenants could collide, an import could probe or claim another
tenant's object, and a rename could break a deployed job (design §7.4; A49).
Bindings, in turn, are identity predicates that can overlap: a repository-wide
binding and a deployment-specific binding may both match one proof for different
actors (design §5.7; A50). The exchange algorithm itself is ADR-015; this ADR
fixes how identifiers are created, referenced, exported and preserved, and how
the selected grant scopes binding evaluation over their lifetime.

## Decision

### Generated opaque IDs and tenant-local names

1. **Server-generated.** All object IDs and public OAuth `client_id` values are
   server-generated opaque random identifiers. A client cannot choose a global
   ID on initial create (design §7.4; T10.2).
2. **Opaque.** IDs are compared exactly; type prefixes in examples indicate
   type, not authority, and prefix and length are not a frozen format (design
   §7.4; lead decision OQ-IR-4).
3. **Tenant-local names.** `name` is a human label unique only within its entity
   type and tenant, never an exchange selector and never globally reserved. Two
   tenants' identically named sources get different IDs without collision
   (design §7.4).

### Create-then-reference mapping

4. **Create.** Creation omits the ID and supplies a tenant-scoped name; the
   authorized API returns the generated ID and revision (design §7.4; T10.2).
5. **Dependency order or mapping import.** Provision in dependency order (tenant
   and audience assignment, principals, source and keyset, binding, grant and
   client policy), or use a validated importer with tenant-local manifest
   references that resolves to generated IDs and returns a persistent mapping.
   Export that mapping and place the returned source and grant IDs in job and
   client configuration (design §7.4; T14.8).
6. **Update.** Updates name the existing ID and expected revision within the
   authorized tenant (design §7.4; ADR-008).
7. **Export and restore.** Redacted exports preserve IDs for same-instance
   reconciliation; privileged full restore preserves them only into the intended
   empty or restored authority after ownership and provenance validation.
   Ordinary tenant import cannot claim an arbitrary missing global ID or rebind
   it; reapplication is tenant-local reconciliation, not recreation (design
   §7.4).
8. **Stable through migration.** Once deployed, clients and callers keep their
   IDs across provider migration; the one-time create-then-reference step does
   not violate the zero-reconfiguration goal (design §7.4, §2 C02, C05, C06).
9. **Composite tenant references.** Composite tenant and object foreign keys
   prevent cross-tenant references (design §7.1).

### Selected grant filters binding evidence

10. **Grant-directed.** The selected grant determines the candidate actor and
    target. Only enabled bindings for the selected source that map to that
    grant's actor and appear in its approved `allowed_binding_ids` are
    evaluated; at least one must match the verified evidence (design §5.7;
    T12.3; ADR-015). A disabled binding may stay in `allowed_binding_ids` but
    never matches; a grant with no enabled allowed binding denies; a binding is
    never hard-deleted while referenced (lead decision, 2026-11-19,
    OQ-ADR022-1). A binding may be hard-deleted only when it is disabled and
    unreferenced by any grant, approval or audit-required record, through an
    audited widening-class admin write; disabled, unreferenced grants follow the
    same rule (ADR-008 item 3).
11. **Other actors are irrelevant.** A matching binding for another actor
    neither authorizes nor makes the request ambiguous (design §5.7; T12.7).
12. **No union.** Several matching same-actor bindings select one by stable ID
    order for provenance; their permissions are never unioned (design §5.7).
13. **Configuration-time checks.** Configuration with cross-actor or
    cross-tenant allowed binding references is rejected (design §5.7; T12.7).
14. **Provenance.** The selected binding and complete immutable decision
    dependencies are emitted in the policy revision and audit (design §5.7).

## Consequences and requirements

- Contract requirements: IR-020 to IR-024 (identifiers and names), IR-033
  (tenant resolution), API-010 to API-014 (token endpoint selectors) (inferred
  mapping to the issuer contract's exchange rows).
- A new workload caller needs a create step and then its generated IDs in
  configuration; names cannot be used in exchange (design §7.4).
- Splitting a repository-wide binding into deployment bindings needs no grant
  changes beyond `allowed_binding_ids` (design §5.7) (inferred).
- Conformance rows: A25, A29, A49, A50.

## Alternatives considered

- **User-chosen global IDs or name selectors.** Rejected (design §7.4).
- **Permission union across bindings or first-global-match.** Rejected (design
  §5.7; T12.3).
- **Denying on another actor's overlapping binding.** Rejected (design §5.7).
- **Recreation on reapplication.** Rejected; reconciliation keeps IDs (design
  §7.4).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-IR-4** — normative ID format. Decided (lead decision, 2026-11-19): opaque
  strings compared exactly; prefix and length not frozen.
- **OQ-IR-5** — `Principal.kind` literal values are not given (open).
- **OQ-IR-6** — export field names differ from the logical model (open).
- **OQ-API-11** — grouped-path shorthand (open; lead lean recorded).
- **OQ-TM-2** — GitHub-side preconditions. Decided (lead decision, 2026-11-19):
  bindings pin event, ref and workflow and do not rely on GitHub environment or
  branch protection; `environment` is an additional ANDed predicate.

New questions raised by this ADR:

- **OQ-ADR022-1 — Disabled or deleted bindings in `allowed_binding_ids`.**
  Decided (lead decision, 2026-11-19): disabled bindings may stay in the list
  but never match; a grant with no enabled binding denies; no hard delete while
  referenced (item 10). Original question: Configuration rejects cross-actor
  references, but the sources do not say whether a grant may keep a disabled
  binding in `allowed_binding_ids`, what happens to a grant whose every allowed
  binding is disabled, or whether a binding can ever be hard-deleted while
  referenced.
- **OQ-ADR022-2 — Manifest references and mapping format.** The importer
  resolves "tenant-local manifest references" and returns "a persistent mapping"
  (design §7.4), but the reference syntax in import documents and the mapping's
  format and storage are not specified. Open; to be resolved in T10.7 (lead
  decision, 2026-11-19).

## Tests

- A49 — identical operator labels in two tenants; create, export and reapply;
  names instead of IDs reject.
- A50 — repo-wide and deployment bindings for different actors; selected grant
  owns one.
- A25 — several same-audience grants and target services.
- A29 — shared issuer and object names; crossed references.
- Task tests: T10.8, T12.7, T14.8.
