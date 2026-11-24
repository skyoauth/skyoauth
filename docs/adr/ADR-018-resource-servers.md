# ADR-018: Resource servers, audience assignments and checkers

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The
  direction is accepted; the details, including lead decisions and text marked
  "(inferred)", are implementation choices that ordinary review can change
  (design §12; [status values](README.md#status-values)). Questions still
  marked open under Open questions stay open: ratification closes none of
  them.
- **Tasks:** ratified with T00.15 (ResourceServer, AudienceTenantAssignment,
  ResourceAction and checker ownership) and T00.4 (audience registry and
  persisted action rules) (inferred: tasks §2 names no ADR in these tasks).
  Implementation: T14.1–T14.4, T26.1–T26.5.
- **Baseline (tasks §11):** "Instance audience registry/tenant assignments,
  separate receiver checker identities and persisted action rules"
- **Contracts:** [identity-registry.md](../contracts/identity-registry.md) §7
  (7.1–7.5), §9; [public-api.md](../contracts/public-api.md) §5, §7.2.

## Context

Tenants are administrative partitions, but an audience names an API that may
serve several tenants (design §7.1). If audience strings were tenant-controlled
free text, a tenant administrator could mint credentials for another tenant's
API merely by spelling its audience or project name (design §7.1; A43). The
token's subject (a workload or `ServiceIdentity`) is also distinct from the API
that receives it: several actors can call the same resource server without
becoming its authority for live checks (design §7.1). T00.15 asks to ratify
"ResourceServer/AudienceTenantAssignment/ResourceAction/checker ownership ... no
free-string self-assignment or subject-prefix exemption"; T00.4 asks to "persist
action-to-scope/profile/resource rules".

## Decision

### Instance audience registry

1. **Instance-owned.** Only instance `security_admin` creates a
   `ResourceServer`, with one globally unique exact audience. Tenants cannot
   self-assign an existing audience or create a competing registration (design
   §7.1; T14.1).
2. **Exactly one audience per credential.** Issued credentials carry exactly one
   registered API audience (design §5.7, §6).

### Tenant assignments

3. **Explicit assignment.** `security_admin` grants a tenant access through an
   `AudienceTenantAssignment` specifying allowed profiles, scopes and constraint
   schema versions (design §7.1; T14.1).
4. **References need an assignment.** Service ceilings, WIF grants, OAuth
   clients, application origins and `HumanAccessPolicy` records reference
   registered audience IDs and are refused at write and at issuance without an
   active same-tenant assignment; the assignment is rechecked on every live
   check (design §7.1; T14.2). Disabling a resource server denies its live
   checks and new issuance for its audience; dependent records stay (lead
   decision, 2026-11-19, OQ-ADR018-2).
5. **Defense in depth, not ownership.** For a shared multi-tenant audience, the
   backend maps every resource to a canonical SkyOAuth tenant and compares it
   with the signed tenant before scopes, resources and RBAC; a missing mapping
   denies. An assignment never replaces that check (design §7.1; design §2 C09;
   T14.2).

### Separate receiver checker identities

6. **Receiver, not subject.** `ResourceServerChecker` identities are registered
   mTLS public identities bound to one resource server and an explicit
   `allowed_tenant_ids` set, registered by `security_admin` through
   instance-scoped endpoints. A `ServiceIdentity` is a possible token subject,
   never checker authority, whatever its allowed audiences; a resource server
   cannot use another audience's checker identity (design §7.1, §6.1; T14.3).
   The checker's tenant set must be a subset of the resource server's active
   tenant assignments. While an assignment is disabled its tenant is excluded
   from the checker's effective set, with no edit to the stored set, so
   re-enabling the assignment restores it (lead decision, 2026-11-19,
   OQ-ADR018-1).
7. **Direct grants work.** Direct workload credentials with no target service
   are fully supported by the live check (design §6.1; T14.3).

### Persisted action rules

8. **Per resource server.** `ResourceAction` rules are persisted per resource
   server and administered only by `security_admin`: required scopes (all
   required, OQ-IR-2), accepted profiles, required resource dimensions and
   whether live checking is mandatory (M1a), plus stream capability, duration,
   `stream_class` and `max_session_lease_seconds` (M1b) (design §6.1, §7.1;
   T14.4).
9. **Ceilings.** Lease defaults and the critical cap are 15 seconds or less;
   `security_admin` may explicitly allow noncritical read-only leases up to 300
   seconds. Tenant route editors cannot exceed receiver ceilings (design §6.1.1;
   T14.4; ADR-010).
10. **Unknown denies.** Unknown action, resource or caller, wrong tenant or
    audience, and unknown or contradictory rules deny or are rejected, never
    silently widened (design §6.1; T14.4).
11. **Stable through migration.** Audience assignments, actions and checker
    identities are stable through a human provider switch and included in
    snapshots (design §7.1; ADR-012).

## Consequences and requirements

- Contract requirements: IR-070 to IR-072 (resource servers), IR-080 to IR-083
  (tenant assignments), IR-090 (checkers), IR-100 to IR-104 (action rules),
  IR-110 (profile acceptance), API-070 to API-075 (live check authentication),
  API-147 (audience administration is instance-only).
- A tenant needs a `security_admin` assignment before it can reference any API
  audience; there is no tenant self-service path (design §7.1).
- A backend serving several tenants must keep its own canonical
  resource-to-tenant mapping (design §7.1).
- Conformance rows: A13, A29, A31, A43, A45.

## Alternatives considered

- **Tenant-controlled audience strings.** Rejected (design §7.1).
- **Using the token subject or a delegated `ServiceIdentity` as checker
  authority.** Rejected (design §6.1, §7.1).
- **Subject-prefix exemptions for profiles.** Rejected (T00.15; ADR-019).
- **Assignment as a substitute for backend tenant verification.** Rejected
  (design §7.1).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-IR-1** — constraint dimensions. Decided (lead decision, 2026-11-19): each
  resource server has a versioned constraint schema that defines its dimensions;
  the v1 envelope is fixed.
- **OQ-IR-2** — `required_scopes`. Decided (lead decision, 2026-11-19): all are
  required.
- **OQ-IR-7** — grants with several audiences. Decided (lead decision,
  2026-11-19): a grant may hold several resource servers; each request selects
  one.
- **OQ-IR-8** — no field classifies actions as critical, mutating or noncritical
  read-only, and `stream_class` values are undefined (open).
- **OQ-IR-9** — audience string syntax and comparison rules (open).
- **OQ-IR-10** — whether required resource dimensions apply to human profiles
  (open).
- **OQ-API-5** — private endpoint wire schemas (open).
- **OQ-API-12** — whether every backend that verifies assertions must hold a
  checker identity to fetch `/internal/v1/assertion-jwks` (open; lead lean
  recorded).

New questions raised by this ADR:

- **OQ-ADR018-1 — Checker tenant set versus assignments.** Decided (lead
  decision, 2026-11-19): the checker tenant set must be a subset of active
  assignments; while an assignment is disabled its tenant is excluded without
  editing the stored set, so re-enabling restores it (item 6).
  Original question: A checker's `allowed_tenant_ids` and the resource server's
  `AudienceTenantAssignment` records are separate. Whether the checker tenant
  set must be a subset of the currently assigned tenants, and what happens to a
  checker's tenant entry when an assignment is disabled, is not stated.
- **OQ-ADR018-2 — Disabling a resource server.** Decided (lead decision,
  2026-11-19): disabling a resource server denies live checks and new issuance;
  dependent records stay (item 4). Original question: `ResourceServer` has a
  `status`, but the effect of disabling one on outstanding credentials,
  continuations and dependent grants, clients and origins is not stated beyond
  live checks denying invalid authority (inferred).

## Tests

- A43 — another tenant's audience or project name; shared audience on another
  tenant's resource.
- A45 — direct grant with no target service; delegated subject is not checker
  authority.
- A31 — wrong checker, audience, tenant or action; unavailable checker.
- A13, A29 — canonical tenant mismatch; same issuer or names across tenants.
- Task tests: T14.1–T14.4, T26.5.
