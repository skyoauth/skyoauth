# ADR-019: Human credential profiles and private JWT types

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The direction is accepted; lead decisions, text marked "(inferred)" and provisional lead picks stay implementation choices that ordinary review can change, while a change to a user ruling goes back to the user (design §12; [status values](README.md#status-values)). Questions still marked open under Open questions stay open: ratification closes none of them.
- **Tasks:** ratified with T00.3 (private types and profile claim sets) and
  T00.15 (explicit HumanAccessPolicy and credential profile sources) (inferred:
  tasks §2 names no ADR in these tasks). Implementation: T20.1–T20.4, T20.8,
  T32.2, T32.5, T40.13, T12.9.
- **Baseline (tasks §11):** "Explicit human_cli/human_session versus WIF;
  complete human policy provenance/backend_rbac mode, private JWT types rather
  than partial RFC 9068"
- **Contracts:** [token-profiles.md](../contracts/token-profiles.md) §1–§9;
  [identity-registry.md](../contracts/identity-registry.md) §8, §11.

## Context

One issuer signs credentials for workloads (WIF), native CLIs and browser
sessions. If a verifier could infer which rules apply from a `usr_` prefix, a
missing grant or the presence of `act`, a human token could pass as delegated
WIF, or a WIF token could skip human RBAC (design §6; A30, A44). RFC 9068
defines `at+jwt` access tokens, but it requires `client_id`, which WIF does not
have and must not invent from a source ID (design §6). Human tokens carry no
project or environment allowlist, so their authorization must be stated
explicitly rather than left as an omitted claim (design §6). T00.3 asks to
specify "exact protected types `skyoauth-access+jwt` and
`skyoauth-internal+jwt`, signed profile/version and required
WIF/human_cli/human_session claim sets".

## Decision

### Private JWT types

1. Access JWTs use protected `typ=skyoauth-access+jwt`; internal gateway
   assertions use `typ=skyoauth-internal+jwt`. These are proposed private
   identifiers, not registered media types (design §6; T00.3).
2. SkyOAuth does not emit or accept `at+jwt` as a SkyOAuth profile and does not
   advertise RFC 9068 compliance; any future RFC 9068 support needs a separate
   complete conformance profile. OIDC ID tokens, including upstream ones, are
   rejected (design §6; T20.8).
3. Access tokens verify only against the public issuer JWKS; internal assertions
   only against the private internal set. The verifier selects the trust set
   from ingress and profile before `kid` lookup, so changing `typ` cannot cross
   key purposes (design §6, §6.2).

### Explicit profiles

4. **Three profiles.** `wif` (access type, bearer path), `human_cli` (access
   type, bearer path) and `human_session` (internal type, authenticated
   gateway-only assertion header). The protected `typ`, signed
   `skyoauth_profile` with `skyoauth_profile_version=1` and expected ingress
   route jointly select validation rules (design §6).
5. **No inference.** A profile is never inferred from a `usr_` prefix, a missing
   grant, the presence of `act` or an untrusted request header. Unknown
   versions, contradictory claim sets and profiles not allowed by the
   resource-server registration or route are rejected (design §6; T20.3).
6. **Common claims.** Every profile requires signature, allowed algorithm and
   `kid`, exact issuer, one registered audience, `iat`, `nbf`, `exp` with
   bounded TTL and skew, unique `jti`, explicit `scope`, signed
   `skyoauth_tenant`, profile and version, `skyoauth_policy_revision` and
   `skyoauth_constraints` (design §6).
7. **WIF.** Workload or delegated service `sub`, grant ID, direct or delegation
   mode, binding-backed policy revision and `authorization: allowlist`
   constraints; delegation adds workload `act`. WIF cannot use `backend_rbac` or
   omit allowlists and receives no refresh credential (design §6; T20.3, T20.5).
8. **`human_cli`.** Human `sub`, the actual registered OAuth `client_id`, opaque
   `skyoauth_authentication`, `auth_time`, the human policy revision and
   `backend_rbac` constraints; no WIF grant, mode or `act`; access lifetime at
   most 300 seconds (design §6; T40.13).
9. **`human_session`.** Human `sub`, application-origin ID, opaque
   authentication and session references (never cookie hashes or tickets),
   `auth_time`, policy revision, `backend_rbac` constraints, route and route
   version, and the request-binding tuple; no WIF claims and no invented
   `client_id`; at most 30 seconds; minted only after the live session, Origin
   and CSRF check and never returned to SPA JavaScript (design §6; T32.2;
   ADR-007).

### Complete human policy provenance

10. `HumanAccessPolicy` is a tenant- and audience-scoped, provider-independent
    record for exactly one OAuth client or `ApplicationOrigin`, with scope, TTL
    and authentication ceilings set by `client_admin` within the instance
    audience assignment. Issuance snapshots it with the client or origin
    registration and relevant revisions; a `HumanAuthentication` record links
    the login to provider and epoch without clients knowing a provider ID
    (design §6).
11. CLI scopes are the intersection of approved requested scopes, client policy
    and audience assignment. Browser scopes derive from the registered origin's
    policy and the route-selected audience, never from browser-supplied headers.
    The human-session snapshot includes the active pinned origin and route
    version IDs, not staged versions or capacity revisions (design §6, §4.1).

### backend_rbac mode

12. Human profiles carry `{"version":1,"authorization":"backend_rbac"}` and make
    no project or environment membership claim. The backend resolves the
    resource's canonical tenant, matches signed tenant and audience, checks
    scope and then evaluates its current human RBAC; no membership or missing
    tenant mapping denies. This is explicit authorization by the backend, not an
    exemption or an automatic allow (design §6; T32.5).
13. For WIF allowlists, values within a dimension are alternatives and
    dimensions are ANDed with tenant, audience, scope and RBAC; missing or empty
    required dimensions, unknown constraint fields or versions or the wrong mode
    deny (design §6).

## Consequences and requirements

- Contract requirements: TP-001 to TP-004 (types and version), TP-010 to TP-015
  (protected header and trust sets), TP-020, TP-021, TP-023 (profile selection),
  TP-030 to TP-035 (common claims), TP-040 to TP-047 (profile-specific claims),
  TP-070 to TP-073, TP-080 to TP-082 (verifier and live-check obligations),
  IR-130, IR-131, IR-140 (constraint modes).
- Off-the-shelf RFC 9068 validators do not accept SkyOAuth tokens; verifiers use
  the published private-profile rules (T20.8).
- Every backend that accepts human profiles must implement canonical tenant
  mapping and RBAC (design §6).
- Conformance rows: A10, A13, A30, A44, A55.

## Alternatives considered

- **RFC 9068 `at+jwt`.** Rejected for v0.1; it would need `client_id` WIF does
  not have and a complete conformance profile (design §6).
- **Profile inference from subject prefix, missing grant or `act`.** Rejected
  (design §6).
- **Omitted constraints as the human authorization model.** Rejected;
  `backend_rbac` is explicit (design §6).
- **Shared key set for access and internal evidence.** Rejected (design §6.2;
  ADR-002).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-TP-1** — route revision claim. Decided (lead decision, 2026-11-19):
  separate `skyoauth_route_version`.
- **OQ-TP-2** — internal `iss`. Decided (lead decision, 2026-11-19): the
  canonical issuer.
- **OQ-TP-3** — the allowed JWS algorithm set is not fixed (open).
- **OQ-TP-4** — `aud` encoding. Decided (lead decision, 2026-11-19): a JSON
  string only.
- **OQ-TP-5** — `act.iss`. Decided (lead decision, 2026-11-19): required and
  equal to the canonical issuer.
- **OQ-TP-6** — unexpected claims. Decided (lead decision, 2026-11-19): exact
  claim sets; extras rejected.
- **OQ-TP-7** — whether profile, constraints and request versions move
  independently (open).
- **OQ-TP-8** — scope ordering. Decided (lead decision, 2026-11-19): canonical
  sorted unique string; verifiers treat it as a set.
- **OQ-TP-9** — human `skyoauth_policy_revision`. Decided (lead decision,
  2026-11-19): the `PolicyRevision` ID for every profile.
- **OQ-TP-10** — clock skew. Decided (lead decision, 2026-11-19): default 60 s,
  ceiling 120 s.
- **OQ-TP-11** — assertion header. Decided (lead decision, 2026-11-19):
  `X-SkyOAuth-Assertion`.
- **OQ-TP-12** — well-formed `jti`. Decided (lead decision, 2026-11-19): a JSON
  string, checked for presence.
- **OQ-IR-10** — whether required resource dimensions apply to human profiles
  (open).
- **OQ-TM-3** — reuse of internal assertions. Decided (lead decision,
  2026-11-19): verifiers do not reject a repeated `jti`; reuse within 30 s is
  residual risk.
- **OQ-TM-10** — public signer isolation. Decided (lead decision, 2026-11-19):
  processes that serve Check or hold internal keys get no public-signing
  permission.
- **OQ-TM-16** — signer re-check. Decided (lead decision, 2026-11-19): the
  public signer enforces structural limits (`typ` and profile, `iss`, a
  registered audience, `exp` − `iat` ≤ 300 s) but not issuance policy, and logs
  every signature to the external sink.

New questions raised by this ADR:

- **OQ-ADR019-1 — Bearer route profile source.** TP-071 rejects a profile the
  ingress route does not allow, and `ApplicationRouteVersion.allowed_profiles`
  records this for routes in a route bundle. For M2 bearer routes on a host that
  is not enrolled in a bundle, the sources do not say where the accepted
  profiles (`wif` and `human_cli`) of the ingress route are recorded. Open; to
  be decided before M2 (lead decision, 2026-11-19).
- **OQ-ADR019-2 — Publishing the private profile.** T20.1 and T20.8 require
  "explicit private token-profile metadata" and published validation rules, but
  not whether the profile is advertised in discovery metadata, a separate
  document or only the contract (related: OQ-API-8). Open; deferred (lead
  decision, 2026-11-19).

## Tests

- A30 — required claims absent, unknown or contradictory; no human
  subject-prefix exemption.
- A44 — valid human profiles without a WIF grant; WIF forged into human shape.
- A55 — private types versus `at+jwt`, ID tokens and profile confusion.
- A10, A13 — human-session evidence and canonical tenant mismatch.
- Task tests: T20.4, T20.8, T12.9.
