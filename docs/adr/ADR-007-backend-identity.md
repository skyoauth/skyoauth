# ADR-007: Backend identity and credential containment

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.5 (inferred: tasks §2 names no ADR in T00.5;
  design §4.1 names ADR-007 for the deferred per-route metadata alternative).
  Implementation: T25.1–T25.4, T32.1, T32.2, T32.4, T32.5, T32.13, T50.4, T52.4.
- **Baseline (tasks §11):** "Original bearer or purpose-signed human evidence;
  unconditional route-stage Cookie/CSRF removal and whole Set-Cookie response
  removal on every non-SkyOAuth route, including no-auth static paths. Exact
  identity-bound exemptions, not selective-cookie parsing. Fixed target
  digest/no rewrites; actual pinned/security dependencies govern invalidation,
  not staging/polling/capacity or an unrelated bundle-pointer change.
  Gateway-metadata-only routing remains deferred."
- **Contracts:** [gateway-containment.md](../contracts/gateway-containment.md)
  §2.1, §3, §4, §13; [public-api.md](../contracts/public-api.md) §4;
  [token-profiles.md](../contracts/token-profiles.md) §3, §6;
  [lifetimes.md](../contracts/lifetimes.md) §10.

## Context

Envoy carries application bytes directly to the backend; SkyOAuth sees only
bounded metadata (design §1, §4). The backend must learn who is calling without
receiving a reusable browser credential: a billing or static-file backend must
not obtain a session cookie usable against another audience (design §4). Cookie
leakage to backends and header spoofing are named threats (design §9; T00.7).
T00.5 asks M0 to freeze "exact digest binding and all-route credential
containment" and the exact identity-bound exemptions. The gateway deployment and
admission procedure that enforces these rules is ADR-020.

## Decision

### What the backend receives

1. **Bearer calls** carry their original SkyOAuth access JWT. **Cookie calls**
   cause SkyOAuth to return a short-lived, purpose-signed internal
   `human_session` assertion to Envoy for a private, overwritten backend header
   (`X-SkyOAuth-Assertion`, lead decision OQ-API-10). Both internal links are
   authenticated and the backend rejects mixed credentials (design §4, §6).
2. RPC failures are typed errors, never an IdP HTML redirect: 401, 403, the
   capacity results and 503 for unavailable infrastructure (design §4; ADR-010).
3. An alternative header adapter must preserve the same typed identity semantics
   and authenticated transport and must not infer profiles from a subject prefix
   (design §4).

### Containment on every enrolled-host route

4. **Request removal.** On an enrolled host, including the issuer host, every
   route except the exact exemptions of item 7 removes all `Cookie` fields and
   `X-SkyOAuth-CSRF` before forwarding, whatever its authentication class and
   whether or not ext_authz runs. This covers the SPA shell, assets, public and
   health endpoints, bearer routes and every non-exempt SkyOAuth endpoint,
   including `/oauth/token`, `/oauth/revoke`, `/.well-known/*` and
   `/_skyoauth/oidc/backchannel-logout` (GW-020, GW-033, GW-035; lead decision,
   OQ-GW-3, OQ-GW-12). HTTPRoute
   `RequestHeaderModifier.remove: [cookie, x-skyoauth-csrf]` produces Envoy
   route-level `request_headers_to_remove`; the removal is not conditional on an
   auth-service response (design §4; T32.4).
5. **Stage.** On protected routes SkyOAuth first receives the original bounded
   metadata for session, Origin and CSRF validation and mixed-credential
   rejection; removal uses the ordinary upstream stage, not early removal before
   ext_authz. The gRPC `headers_to_remove` remains defense in depth only (design
   §4; T32.4).
6. **Response removal.** The same routes, with the same exact exemptions (item
   7), also remove every `Set-Cookie` response field
   (`ResponseHeaderModifier.remove: [set-cookie]`), including duplicate and
   nonreserved cookies, not a selective parse of reserved names. Non-exempt
   SkyOAuth endpoints, issuer-host routes among them, set no cookies.
   Application responses cannot set cookies in v0.1 (design §4; GW-027, GW-033,
   GW-035; lead decision, OQ-GW-3, OQ-GW-12).
7. **Exact identity-bound exemptions.** Only the fixed SkyOAuth authentication
   and session endpoints routed to the independently verified SkyOAuth backend
   identity may consume or issue their cookies. A path prefix, caller header or
   tenant-supplied flag cannot grant an exemption (design §4). One exception
   list scopes both the request removal (item 4) and the response removal (item
   6): the seven fixed endpoints of gateway-containment §4.1 (app-origin
   `/_skyoauth/login`, `/_skyoauth/callback`, `/_skyoauth/session`,
   `/_skyoauth/logout`; issuer `/oauth/authorize`, `/oauth/callback`,
   `/oauth/confirm`; lead decision, OQ-GW-3), plus each exact registered
   per-provider issuer callback path `/oauth/callback/{provider_id}`. Such a
   path is server-generated for a provider without RFC 9207 `iss`, is exempt in
   the same way as `/oauth/callback`, is listed by exact path in the approved
   issuer projection and routes to the verified SkyOAuth backend; no prefix or
   pattern exemption covers these paths (OQ-TM-4; T00.5, T32.4, T40.12; spec
   amendment pending, threat-model §6.1).
8. **Projected and tested.** Both removals, their stage and order, and the exact
   exemptions are part of the approved semantic projection; a missing removal or
   unauthorized exemption rejects preparation or activation. Tests check actual
   filter order and upstream bytes, including retries and mirrors; cookies and
   CSRF are never copied into other forwarded metadata and are redacted in
   gateway logs (design §4, §4.2; T32.4).
9. **Duplicate cookies.** Authentication rejects duplicate or ambiguous SkyOAuth
   cookies rather than choosing a copy (design §4).
10. **Not JavaScript isolation.** This is credential containment, not isolation
    from malicious JavaScript on the same trusted origin (design §4).

### Request binding and no rewrites

11. **Fixed target digest.** The assertion carries `skyoauth_route` and its
    version and
    `skyoauth_request={version:1,method,scheme,authority,target_sha256}`,
    describing the request after ingress validation and before ext_authz.
    `target_sha256` is the unpadded base64url SHA-256 of the exact ASCII
    origin-form target (43 characters); query order, duplicates, escape spelling
    and absent versus empty query are significant. The raw path and query are
    never in the assertion (design §4.1; T32.13).
12. **Backend comparison.** The backend recomputes the digest from its received
    raw target and compares method, scheme, authority and digest before its
    single URL-decoding pass (design §4.1).
13. **No rewrites.** Routes accepting `human_session` forbid path, host or query
    rewrites, post-auth routing-input mutation and route-cache rematching;
    client-supplied `X-Original-*` is never trusted. Backends without the raw
    target cannot use this adapter (design §4.1).

### What invalidates evidence

14. Activation supersedes only credentials and contexts whose actual pinned
    origin or route versions or security dependencies changed. Staging,
    observation polling, operational capacity edits and a bundle pointer advance
    that leaves a route's dependencies unchanged are not authorization changes
    (design §4.2; tasks §3 "Policy revisions"; T10.4).

### Deferred

15. Trusted per-route audience metadata carried by the gateway
    ("gateway-metadata-only routing") remains a future alternative under ADR-007
    and ADR-020, not a caller-header fallback (design §4.1; tasks §11).

## Consequences and requirements

- Contract requirements: GW-001 to GW-006 (request target digest), GW-020 to
  GW-029 (all-route containment), GW-030 to GW-035 (exemptions and the issuer
  host), GW-040 (filter-order tests), GW-227 and LT-094 (only changed
  dependencies are superseded), API-061 to API-063 (backend transport, mixed
  credentials, removal), TP-047, TP-050 to TP-054 (route and request binding),
  API-056 and GW-024 (duplicate cookies).
- Static and public backends on an enrolled host never see session or flow
  cookies and cannot set cookies; applications that need their own cookies are
  unsupported in v0.1 (design §4).
- Backends that need path rewrites or lack the raw target cannot accept
  `human_session` (design §4.1).
- Conformance rows: A08, A10, A18, A36, A44, A61; the containment and digest
  parts of A58.

## Alternatives considered

- **Selective cookie-name filtering (Lua, Wasm or ext_proc).** Not required by
  the baseline; whole-header removal instead (design §4).
- **Early removal before ext_authz.** Rejected; protected routes must
  authenticate the original metadata first (design §4).
- **gRPC `headers_to_remove` as the only mechanism.** Rejected; defense in depth
  only (T32.4).
- **Exemptions by path prefix, caller header or tenant flag.** Rejected (design
  §4).
- **Rewrites with relaxed equality.** Rejected; supporting rewrites later needs
  a separate authenticated original/effective-target profile (design §4.1).
- **Gateway-metadata-only routing.** Deferred (design §4.1; tasks §11).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-GW-3** — exact exemption list. Decided (lead decision, 2026-11-19): only
  the seven cookie endpoints are exempt; the issuer host is not an
  `ApplicationOrigin`. Still open: per exempt endpoint, which cookies and
  headers are retained beyond those named.
- **OQ-GW-4** — how the verified SkyOAuth backend identity is expressed and
  verified. Deferred (lead decision, 2026-11-19) to T32.4.
- **OQ-GW-5** — the pinned adapter's literal per-route filter list and the stage
  at which client-supplied identity and assertion headers are removed (open).
- **OQ-GW-12** — enrolled host. Decided (lead decision, 2026-11-19) in part: the
  issuer host is enrolled for containment. Still open: which bundle carries the
  issuer host's scope, and whether containment applies to an origin registered
  before a protected scope is enrolled.
- **OQ-API-10 / OQ-TP-11** — assertion header. Decided (lead decision,
  2026-11-19): `X-SkyOAuth-Assertion`.
- **OQ-TP-1** — route revision claim. Decided (lead decision, 2026-11-19):
  separate `skyoauth_route_version`.
- **OQ-TP-7** — whether `skyoauth_request.version` ties to the profile or
  constraints version (open).
- **OQ-TM-3** — reuse of internal assertions. Decided (lead decision,
  2026-11-19): verifiers do not reject a repeated `jti`; reuse within 30 s is
  residual risk.

New questions raised by this ADR:

- **OQ-ADR007-1 — Meaning of "gateway-metadata-only routing".** The tasks §11
  baseline defers "gateway-metadata-only routing"; design §4.1 defers "trusted
  per-route audience metadata ... under ADR-007/ADR-020". The sources do not
  define either term or say whether they are the same alternative, nor which of
  the two ADRs would own its future decision.
- **OQ-ADR007-2 — Applications that need cookies.** Application responses cannot
  set cookies in v0.1 (design §4). The sources do not say whether this is a
  permanent product boundary or a v0.1 limit, nor what an application on an
  enrolled host that relies on its own cookies is expected to do.

## Tests

- A18 — public, health, static and bearer backends receive no Cookie or
  `X-SkyOAuth-CSRF` and cannot set cookies, with no Check call; projected
  removals and exemptions; genuine SkyOAuth flows still work, including the
  native flow through `/oauth/callback/{provider_id}`.
- A18 (non-exempt issuer route) — on the issuer host, `/oauth/token`,
  `/oauth/revoke` and `/.well-known/*` receive no Cookie or `X-SkyOAuth-CSRF`
  upstream and their `Set-Cookie` fields are removed; an unregistered
  `/oauth/callback/{provider_id}`-shaped path or a path prefix gets no exemption
  (GW-020, GW-027, GW-033, GW-035).
- A61 — raw-target variants, 4 KiB query, digest tampering, rewrites and
  rematching.
- A08, A10, A44 — typed human-session evidence, mixed-credential denial, profile
  and route checks.
- A36 — spoofed headers and direct-backend attacks on the M2 bearer path.
- Task tests: T32.4, T32.13, T50.4, T52.4.
