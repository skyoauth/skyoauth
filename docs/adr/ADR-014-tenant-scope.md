# ADR-014: Tenant scope

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The
  direction is accepted; the details, including lead decisions and text marked
  "(inferred)", are implementation choices that ordinary review can change
  (design §12; [status values](README.md#status-values)). Questions still
  marked open under Open questions stay open: ratification closes none of
  them.
- **Tasks:** ratified with T00.11. Implementation: T10.1, T10.8, T14.1, T14.2,
  T14.5, T14.7, T14.8, T52.6.
- **Baseline (tasks §11):** "Composite references, instance audience/origin
  assignment, same-tenant trust/grants and mandatory backend resource
  mapping".
- **Contracts:** [identity-registry.md](../contracts/identity-registry.md)
  §1, §4, §7, §9, [public-api.md](../contracts/public-api.md) §2.1, §3, §7.2,
  [token-profiles.md](../contracts/token-profiles.md) §8.

## Context

T00.11 asks M0 to "define tenant ownership/composite references, instance
audience assignment and canonical-origin ownership, nonunique issuer strings
and same-issuer cross-tenant/cluster fixtures". Design §9 lists cross-tenant
audience issuance as a threat. Design §2 C09 requires that credential validity
never bypasses canonical tenant checks or backend RBAC, and that a matching
project name, scope or audience alone is insufficient. Tenant checks apply
even to a single-tenant installation (design §1.3).

## Decision

1. **Tenant partition.** `Tenant` is the administrative policy partition,
   explicitly mapped to application organization and resource ownership.
   Every installation has explicit tenants; tenant IDs, audience ownership and
   isolation checks apply even with one tenant (design §1.3, §7.1).
2. **Composite references.** Stable generated IDs are globally unique, and
   composite tenant/object foreign keys prevent cross-tenant references.
   Sources, keysets, bindings, services, grants, clients, origins and human
   policies are tenant-owned, and the protection extends to their immutable
   versions (design §7.1; tasks §3 "Ownership"; T10.1).
3. **Instance audience assignment.** Audience strings are not tenant
   namespaces. Instance `security_admin` creates a `ResourceServer` with one
   globally unique exact audience and grants tenants access through
   `AudienceTenantAssignment` records with allowed profiles, scopes and
   constraint schema. Tenants cannot self-assign an existing audience or
   create a competing registration. Service ceilings, WIF grants, OAuth
   clients, application origins and `HumanAccessPolicy` records reference
   registered audience IDs and are refused without an active same-tenant
   assignment, which is rechecked at issuance and at every live policy check
   (design §7.1; T14.1, T14.2).
4. **Canonical-origin ownership.** `ApplicationOrigin` binds one globally
   unique canonical HTTPS origin to one tenant. Instance `security_admin`
   enrolls that ownership; a tenant cannot claim another tenant's host, and a
   scoped `client_admin` can narrow routes and audiences but cannot reassign
   host or tenant. v0.1 does not multiplex tenants on one origin (design §4;
   tasks §3 "Ownership"; T14.5).
5. **Tenant resolution.** A browser request's tenant comes from the registered
   origin, a native request's from the globally unique generated `client_id`,
   and a WIF request's from the selected source and grant, which must belong
   to the same tenant. A free `tenant` query or an untrusted forwarded header
   never selects a tenant (design §4, §5.2, §5.7; T14.7).
6. **Same-tenant trust and grants.** The exchange loads the selected source
   and grant as untrusted candidates, requires the same tenant and reveals no
   cross-tenant existence details on failure. Configuration rejects
   cross-tenant and cross-actor binding references (design §5.7; tasks §2
   "Exchange selection and scope").
7. **Nonunique issuer strings.** External issuer strings are not unique:
   different tenants can register GitHub, and independently keyed clusters can
   share one issuer. A source selector chooses only a candidate verifier;
   verified evidence plus the selected same-tenant grant establishes authority
   (design §7.1). Cluster disambiguation is ADR-011.
8. **Mandatory backend resource mapping.** For a shared multi-tenant audience
   every backend resource is mapped to a canonical SkyOAuth tenant. The
   backend compares that owner with the signed `skyoauth_tenant` before
   scopes, resources and RBAC; a missing mapping denies. Instance assignment
   is defense in depth, not permission to omit tenant verification (design
   §7.1; T14.2).
9. **Names are tenant-local.** Tenant-local names are labels, unique only per
   entity type and tenant; two tenants' identically named objects get
   different generated IDs with no global-name collision or probe (design
   §7.4; T14.8).
10. **Per-tenant secrets and egress.** Secret references configured by a
    tenant operator resolve only within that tenant's provisioned secret
    namespace, so a reference cannot name a secret provisioned for another
    tenant. Discovery, JWKS and TokenReview egress destinations come from an
    allowlist approved by instance `security_admin` (OQ-TM-13).
11. **Tenant disable.** A disabled tenant denies issuance, live checks,
    admission and refresh, and its `auth_generation` is advanced
    (OQ-ADR014-1).
12. **Multi-tenant applications** may serve several application organizations
    inside their one explicitly mapped SkyOAuth tenant; any different mapping
    needs a separate reviewed protocol (design §4).

## Consequences and requirements

- Contract requirements: IR-030, IR-031, IR-032, IR-033 (tenants), IR-070,
  IR-071, IR-072, IR-080, IR-081, IR-082, IR-083 (audience registry and
  assignments), IR-090 (checker tenant set), IR-020, IR-021 (generated IDs,
  tenant-local names), IR-150 (backend authorization order), API-012 (no
  cross-tenant existence detail), API-050 (origin and tenant resolution),
  API-146, API-147 (instance-only ownership and registration), ERR-020
  (non-enumerating token endpoint failures), TP-073 (backend tenant check
  after profile validation).
- A small installation still provisions one explicit tenant and assigns
  scoped roles explicitly (design §1.3, §7.2).
- Conformance rows: A13, A29, A31, A43, A45, A46, A49.

## Alternatives considered

- **Tenant-controlled free audience namespaces.** Rejected (design §7.1).
- **Tenant selection by query parameter or forwarded header.** Rejected
  (design §4).
- **Multiplexing tenants on one origin.** Not in v0.1; a different mapping
  needs a separate reviewed protocol (design §4).
- **A single-tenant-only distribution** that omits tenant checks. Any such
  distribution is a separate reviewed scope choice, not a reason to omit
  tenant checks from credentials that already carry them (design §1.3).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-IR-6** — whether exports carry audience strings or `ResourceServer`
  IDs (the design §5.7 export shows `audience: control-plane-api`) (open).
- **OQ-IR-7** — grants with several audiences. Decided (lead decision,
  2026-11-19): a grant may hold several resource servers; each request selects
  one (IR-083).
- **OQ-IR-9** — audience string syntax and comparison rules (open).
- **OQ-TM-13** ([threat model](../threat-model.md) §6) — external secret
  references and egress approval. Decided (lead decision, 2026-11-19):
  per-tenant secret namespaces and a `security_admin`-approved egress
  allowlist (item 10).

New questions raised by this ADR:

- **OQ-ADR014-1 — Effect of tenant disable.** Decided (lead decision,
  2026-11-19): a disabled tenant denies issuance, live checks, admission and
  refresh, and advances the tenant's `auth_generation` (item
  11). Original question: `/admin/v1/tenants` lets
  instance `security_admin` disable a tenant (tasks §2 "Endpoint matrix"), and
  the exchange validates current tenant status (design §5.7 step 5). The live
  check (design §6.1) and the human issuance paths do not name tenant status,
  and the sources do not say whether disabling a tenant revokes its sessions,
  native refresh families and continuations or only blocks new issuance.

## Tests

- A13 — a valid credential outside the canonical resource tenant is denied by
  the backend.
- A29 — tenants sharing a GitHub issuer or object names coexist; crossed
  references deny.
- A43 — tenant B cannot register or grant tenant A's audience; backend tenant
  mismatch denies even when audience, scope or name match.
- A46 — two origins and tenants with different providers; spoofed Host,
  Forwarded or tenant query denies before redirect.
- A49 — identical labels in two tenants get distinct generated IDs.
- A31, A45 — checker bound to its audience and tenant set.
- The same-issuer cross-tenant and cluster fixtures that T00.11 asks for are
  the A28 and A29 rows of the
  [conformance layout scenario map](../testing/conformance-layout.md#2-scenario-map).
- Task tests: T10.8 (cross-tenant property tests), T14.2, T14.8, T52.6.
