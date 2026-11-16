# SkyOAuth — Architecture, security model, and roadmap

> **Status:** proposed design for review (2026-11-15). This document is normative for project goals, not evidence that an implementation exists. See [skyoauth-tasks.md](skyoauth-tasks.md) for detailed interfaces, dependencies, milestones, and acceptance tests.

## 1. Executive summary

SkyOAuth is a small, self-hostable **identity bridge** for public-facing applications and private APIs. It eliminates application-managed, long-lived client credentials by accepting *existing* human and workload identities, applying administrator-owned trust and authorization policies, and presenting stable SkyOAuth credentials to protected services.

SkyOAuth is **not** a substitute for an upstream human identity provider, a service mesh, or an application traffic proxy:

- **Browser:** OIDC SSO with Zitadel (or another upstream provider) establishes an opaque, Secure/HttpOnly, server-side session. The browser never receives OAuth access or refresh tokens.
- **CLI:** a stable SkyOAuth native OAuth interface brokers interactive upstream OIDC sign-in (Authorization Code + PKCE; device flow if implemented). CLIs receive short-lived SkyOAuth API access tokens rather than upstream-provider-specific credentials.
- **Workloads:** GitHub Actions OIDC, Kubernetes projected service-account tokens, and registered third-party OIDC/JWT issuers can be verified and exchanged into short-lived, audience-bound SkyOAuth access tokens using RFC 8693. **GitHub Actions → our k3s APIs is a first-class, mandatory use case.**
- **Gateway:** Envoy Gateway queries SkyOAuth's out-of-band gRPC `ext_authz` implementation for opaque browser sessions and, initially, bearer tokens. Envoy routes ConnectRPC calls, streams, and large downloads **directly** to the application; SkyOAuth never proxies their bodies. HTTP ForwardAuth adapters can support other gateways.
- **Backend:** protected APIs enforce tenant/project/workflow permissions and operation-specific authorization; the identity bridge only establishes principal identity and scoped grants.

**Non-negotiable compatibility goal:** replacing Zitadel or any other *upstream human IdP* must require **zero changes, rebuilds, reconfiguration, or redeployments of browser/CLI/agent clients or protected services**. Reauthentication of human users is acceptable. The migration must **also leave all WIF issuer registrations (discovery URLs or uploaded JWKS), external-claim → principal mappings, service impersonation/delegation grants, audiences/scopes, and policy decisions intact**, without administrators resetting them.

The public SkyOAuth issuer and its signing keys, trust registry, internal principals, and policy database are **SkyOAuth-owned**, not upstream-IdP-owned.

### 1.1 Goals

1. Remove static API keys, personal access tokens, and secret bootstrap credentials from browser frontends, CI jobs, and workload/agent applications.
2. Provide a stable, standards-oriented HTTP/OAuth contract and small client SDKs across upstream human IdP changes.
3. Support GitHub Actions OIDC → scoped access to user-owned cluster backends, without cloud STS, SPIRE, sidecars, or an application-layer reverse proxy.
4. Maintain persistent administrator-managed issuer URL/JWKS trust sources, subject bindings, impersonation/delegation and service policy mappings, regardless of human IdP migration or normal application upgrades.
5. Be usable with k3s/Kubernetes, Envoy Gateway, Cloudflare Tunnel, ConnectRPC, and optional alternate gateways.
6. Keep a narrow, auditable Rust service and an explicit separation between authentication, token issuance, and resource authorization.

### 1.2 Non-goals

- Directory/user provisioning, MFA, passwords, consent UI, organizational identity governance (upstream IdP responsibilities).
- SPIRE/SPIFFE or a mandatory cluster agent/sidecar; support direct Kubernetes service-account federation.
- Proxying ConnectRPC requests, downloads, SSE, or streaming payloads.
- General AWS/GCP/Azure credential brokerage or cloud role assumption in the initial release. **WIF for authenticating to SkyOAuth-protected APIs is required**, independently of cloud WIF.
- A universal ABAC engine for application resources, Temporal operations, or cloud permissions.
- Converting arbitrary external tokens into an upstream provider's administrator tokens or allowing public impersonation of its users.
- A general-purpose user-configurable URL/JWKS fetcher; external trust is administrator-controlled.

## 2. Stable compatibility contract (MUST)

These are versioned public/project contracts; provider-specific details MUST NOT leak across them.

| ID | Invariant |
| --- | --- |
| C01 | Stable SkyOAuth issuer URL, discovery/JWKS endpoints and published signing-key rotation contract. |
| C02 | Stable native-client authorization/token endpoints, exchange endpoint, browser-session endpoints and client SDK APIs. |
| C03 | Stable API audiences, normalized principal IDs, token semantics, gateway/authentication contracts, and ConnectRPC caller identity contract. |
| C04 | Human IdP changes may invalidate human browser/CLI sessions but require no client or backend redeployment/configuration changes. |
| C05 | External issuer registrations (exact `iss`, discovery URL **or** uploaded public JWKS, accepted `aud`/algorithms and lifecycle metadata) survive human IdP migration unchanged. |
| C06 | External subject/claim → workload principal bindings and service `act_as`/impersonation/delegation grants, scope/audience ceilings, tenant/resource constraints and policy IDs survive unchanged. |
| C07 | Already permitted WIF sources continue to exchange tokens with identical effective policy outcomes, apart from independently triggered trust or policy changes. |
| C08 | SkyOAuth-issued credentials have an issuer distinct from upstream human IdPs; backends do not need to trust Zitadel, GitHub, or other upstream issuers directly. |
| C09 | Authentication never bypasses application-level resource authorization. Cookie or JWT proof alone never implies permission to operate on a project, Temporal workflow, tenant, or cloud account. |
| C10 | Policy changes and upstream migrations are separate, explicit administrative operations with audit, dry-run, and rollback. |

**Scope of guarantee:** a human IdP migration is not an external issuer's own key compromise/rotation, its protocol outage, or a requested WIF-policy change. Those events may legitimately require explicit administrator action. It is also not a promise that every provider supports identical MFA or user claims. Identity linking must be explicitly verified; equal email addresses do not prove account continuity.

## 3. Logical architecture and trust boundaries

~~~mermaid
flowchart TB
  subgraph Clients
    B[Browser / React + Vite]
    C[CLI / human]
    G[GitHub Actions / CI]
    K[Kubernetes or external agent]
  end
  subgraph Identity["SkyOAuth identity control plane — Rust"]
    PUB[Public OIDC / OAuth / session endpoints]
    EXT[gRPC ext_authz / HTTP ForwardAuth]
    EX[Policy-aware exchange + local JWT issuer]
    DB[(PostgreSQL: sessions, trust, grants, keys metadata)]
  end
  U[Upstream human OIDC: Zitadel or replacement]
  J[Configured external issuers and Kubernetes TokenReview]
  EDGE[Cloudflare Tunnel optional -> Envoy Gateway]
  API[ConnectRPC / REST control-plane API]
  TP[Temporal / cloud execution backends]
  B --> EDGE
  C --> PUB
  G --> EX
  K --> EX
  PUB <--> U
  EX <--> J
  PUB --> DB
  EX --> DB
  EDGE -. auth check only .-> EXT
  EXT --> DB
  EDGE -->|authorized request / response bytes| API
  API --> TP
~~~

The diagram separates *logical* control-plane calls; browser login/session paths are routed by Envoy to SkyOAuth on the **same application origin**, while API traffic goes from Envoy directly to the backend. External clients can reach the public token exchange endpoint but **not** the private ext_authz listener.

### 3.1 Four security boundaries

1. **External issuers are untrusted until explicitly registered.** A JWT is not authoritative because it has an `iss` or `kid` claim; the configured source fixes issuer, key source, algorithm, audience, maximum age, and claim policy.
2. **SkyOAuth owns session and token authority.** Stable internal principal IDs (`usr_*`, `wld_*`, `svc_*`) are independent of upstream subject IDs. SkyOAuth signing keys are not Zitadel keys.
3. **Envoy is the transport gate, not application policy.** A protected route must have a fail-closed SecurityPolicy; a backend must never trust arbitrary user identity headers supplied by a public client.
4. **Application/resource authorization remains in the API.** The API validates an authenticated principal and grant constraints before workflow start/cancel/terminate, cloud mutation, and artifact access.

The token-signing function is privileged. Separate its key material/permissions from public session handling, and make the issuer signing component independently deployable if the operational threat model demands it.

## 4. Deployment and traffic paths

Recommended deployment: Rust/Axum + Tokio service with a public HTTP listener (via Envoy) and a separate private gRPC `envoy.service.auth.v3.Authorization/Check` listener; PostgreSQL authoritative store; 2+ stateless SkyOAuth replicas; Envoy Gateway data plane and Gateway API HTTPRoutes; Cloudflare Tunnel optional. Valkey is an *optional* bounded-lifetime cache, not a required security dependency.

Example origin layout (deployment-specific hostnames, stable to clients):

| Entry point | Example | Access |
| --- | --- | --- |
| SkyOAuth issuer/exchange | `https://identity.example.com/oauth/token` and `/.well-known/jwks.json` | Public, strongly rate limited |
| Same-origin browser auth | `https://app.example.com/_skyoauth/login`, `/callback`, `/session`, `/logout` | Public; route to SkyOAuth |
| App RPC | `https://app.example.com/rpc/...` | Envoy -> ext_authz -> API |
| Downloads/events | `https://app.example.com/downloads/...`, `/events/...` | Envoy -> ext_authz -> API, no auth-service data hop |
| Private auth checks | gRPC ext_authz port inside cluster | Gateway only, authenticated transport |

For browser cookies use a host-only `__Host-` cookie per application origin. The gateway routes the auth endpoints on the application host; do not broaden cookie scope to `.example.com` for convenience. The stable issuer may be a separate hostname: this does **not** imply sharing that hostname's cookies with the SPA.

**Envoy integration:** gRPC ext_authz sees a minimal header/method/authority/path context (never upload bodies); returns Allow/Deny and narrowly defined verified identity material. Enforce header sanitization, gateway-to-backend network restriction, and TLS/mTLS or an audience-bound, signed internal identity assertion. Return 401 for RPC auth failures (not OIDC HTML redirects); browser SDK initiates top-level login navigation. Fail closed on auth-service/database outages. Explicitly reject ambiguous requests carrying a session cookie and a bearer credential.

**Cloudflare:** Tunnel provides origin connectivity, not a substitute for per-route authentication; WAF/rate-limit/Access features must be configured separately. Avoid trusting arbitrary `CF-*` or `X-Forwarded-*` headers outside a trusted proxy chain. Layered rate limits should work without moving application bytes through SkyOAuth.

## 5. Identity and credential flows

### 5.1 Browser: opaque server-side session

1. Unauthenticated navigation follows a SkyOAuth-managed login entrypoint on the app origin with a validated relative return location.
2. SkyOAuth starts upstream OIDC Authorization Code + PKCE S256, per-transaction state/nonce, strict callback URI and issuer binding; all remote discovery HTTP must enforce SSRF-safe egress restrictions.
3. On callback, verify issuer, ID token signature, audience, nonce, expiry, and appropriate `auth_time`/MFA requirements; look up a stable human principal through a verified provider-subject binding.
4. Generate a new CSPRNG session ticket, store only its keyed hash, principal reference, upstream authentication metadata, idle/absolute expiry, revocation state, and a CSRF verifier in PostgreSQL.
5. Set `__Host-skyoauth_session` with `Secure; HttpOnly; Path=/; SameSite=Lax` and no Domain; this is **not** an OAuth token cookie. Local logout revokes the session. Upstream logout notifications may revoke mapped sessions after fully verifying the logout token.
6. `GET /_skyoauth/session` returns only browser-safe principal/session and a session-bound CSRF token with `Cache-Control: no-store`. Unsafe cookie-authenticated calls must pass exact-origin and CSRF checks; SameSite alone is not the defense.
7. For multi-org products, the API resolves and authorizes actual organization/project membership; any UI-selected org is an untrusted request parameter.

**Default**: discard upstream access/refresh tokens after authentication. When Zitadel RFC 8693 delegation or an upstream API call is required, encrypted, server-side retention becomes an explicit opt-in credential vault feature. Reauthentication after human IdP migration is permitted. Sessions should not be coupled to upstream token rotation or force browser cookie rotation on every ext_authz check.

### 5.2 CLI: brokered OAuth, not provider-specific URLs

The CLI is an OAuth public client of **SkyOAuth** using a stable bridge-owned `/oauth/authorize` and `/oauth/token` contract, Authorization Code + PKCE, loopback redirect URI per native-app guidance; device authorization is an additional profile for headless environments. SkyOAuth forwards the *human authentication step* to the currently active upstream IdP, then issues short-lived SkyOAuth API tokens. Changing Zitadel does not change CLI configuration. Never put upstream refresh tokens on the CLI. Persistent CLI login is an explicit product decision: either interactive reauth or a revocable SkyOAuth refresh credential in OS keychain, not a static API key.

Implementing a public-client OAuth frontend is a real authorization-server obligation: transactional authorization codes, registered client IDs and redirects, PKCE, token response semantics, issuer metadata, throttling, revocation, and replay prevention. Do **not** claim CLI compatibility until this profile passes conformance tests.

### 5.3 GitHub Actions WIF (required)

1. GitHub Actions job has `permissions: id-token: write` and asks GitHub's OIDC service for a JWT with the administrator-configured SkyOAuth exchange audience.
2. Client posts an RFC 8693 token-exchange request to SkyOAuth `/oauth/token` (grant `urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`), over TLS.
3. SkyOAuth identifies a **registered** source, verifies GitHub issuer/signature/exact audience/time claims against discovery/JWKS, and matches immutable repo owner/repo IDs plus configured event, branch/environment, workflow/job-workflow identity constraints.
4. It resolves the **stable internal workload principal**, evaluates the immutable-versioned delegation/impersonation grant, and issues a short-lived SkyOAuth access JWT for an explicitly approved API audience, scope set, and resource constraints. The actor and verified GitHub run provenance are retained for auditing.
5. The client calls ConnectRPC via Envoy using `Authorization: Bearer ...`. The protected API checks issuer/audience/scopes and operation-specific resource permissions. The SDK reacquires a GitHub assertion and exchanges again on expiry; never logs or persists the tokens.

A successful GitHub JWT does **not** grant any operation by itself. Production grants must not be satisfied by arbitrary PR code or untrusted `pull_request_target` execution. Match appropriate immutable claims (e.g. `repository_id` / `repository_owner_id`), workflow identity, and GitHub environment protections.

**Token replay:** an incoming CI assertion is a bearer proof within its validity window. Rate-limit exchanges, bind audience, bound token lifetime, and optionally enforce `jti` single-use for high-assurance policies. A cancelled job may leave an issued short-lived JWT usable until expiration; sensitive APIs may require a live policy check or session/issuance epoch.

### 5.4 Kubernetes and generic external WIF

For k3s, use projected, rotated, *audience-bound* service-account tokens, re-reading the token file. Prefer Kubernetes TokenReview (issuer/cluster allowlist, intended audience, SA/namespace and bound Pod identity) for live validation; do not let request content choose arbitrary Kubernetes API URLs. No SPIRE, sidecar, or node agent required.

A generic WIF trust source supports either:

- **Discovery mode:** an explicitly approved exact issuer and OIDC discovery/JWKS URL, pinned accepted algorithms/audiences and bound refresh/stale-cache rules; or
- **Uploaded-JWKS mode:** explicit exact expected `iss`, accepted audiences and algorithms, administrator-uploaded **public** JWK set versions and rotation overlap; never infer trust solely from possession of a key.

Disallow unregistered issuers, remote `jku`/`x5u` header-driven key resolution, `alg=none`, weak algorithm substitution, private JWK upload, and implicit trust of arbitrary URL redirects. Bound token size, claim complexity, clocks, and public-key refresh. A trust-source change is **not** part of a human IdP migration.

### 5.5 Upstream RFC 8693 delegation to Zitadel

Zitadel is the first *human IdP adapter*, not the canonical issuer of our APIs. Where Zitadel supports a compatible exchange of **Zitadel-issued** tokens, SkyOAuth may delegate the upstream exchange after verifying the grant and available audiences/scopes. Zitadel's implementation constrains exchange to existing audiences and restricts impersonated tokens for Zitadel's own APIs; do not assume arbitrary GitHub assertion → Zitadel token exchange works.

**Always normalize the downstream API credential to SkyOAuth's public contract.** Zitadel token pass-through directly to protected APIs is **not** the default; it would break the zero-client/backend-change migration goal. An upstream exchange result may be retained server-side for an explicitly approved provider operation, or be validated and converted to a bounded SkyOAuth JWT.

Zitadel administrative operations must use a separately isolated, restricted server-side service identity/adapter, with per-operation authorization and audit. Never let GitHub `act_as` grants mint arbitrary upstream Zitadel administrator credentials or impersonated tokens.

### 5.6 Delegation versus impersonation

Federation trust maps *verified source claims* to a stable actor (`wld_*`). A **ServiceGrant** may permit that actor to operate as a configured service (`svc_*`), bounded by audience, scopes, tenant/project/environment and expiration:

- **Delegation (default):** token `sub` represents the approved service, `act` (RFC 8693) records the original workload actor; include grant/policy provenance and log the verified GitHub job/run. Services must not drop attribution in audit.
- **True impersonation:** an explicitly different, high-risk policy mode that can omit actor identity in the target-visible token. Disabled by default; admin approval, strict bound targets and issuance auditing required. Prefer forbidding it for privileged targets in v0.1.
- **Direct workload token:** `sub` is the stable workload principal if no service mapping is required.

Effective access is the **intersection** of verified identity binding, the actor's allowed grant, target service ceiling, requested audience/scopes and resource constraints. Missing fields deny rather than silently widen. GitHub's human `actor` claim is audit context, not proof of a human SkyOAuth session.

Example proposed policy (not yet a released configuration schema):

~~~yaml
issuer:
  url: https://identity.example.com
human_providers:
  active: zitadel
  entries:
    zitadel:
      issuer: https://zitadel.example.com
federation:
  trust_sources:
    - id: trust_github
      kind: oidc_discovery
      issuer: https://token.actions.githubusercontent.com
      audiences: [https://identity.example.com]
      allowed_algs: [RS256]
    - id: trust_partner
      kind: uploaded_jwks
      issuer: https://ci.partner.example
      keyset_id: partner-production
      audiences: [https://identity.example.com]
      allowed_algs: [ES256]
  bindings:
    - id: binding_release_pipeline
      source: trust_github
      match:
        repository_owner_id: "123456"
        repository_id: "456789"
        ref: refs/heads/main
        environment: production
        workflow_ref: acme/platform/.github/workflows/deploy.yml@refs/heads/main
      principal: wld_release_pipeline
  grants:
    - id: grant_release
      actor: wld_release_pipeline
      act_as: svc_deployment_controller
      mode: delegation
      audience: control-plane-api
      scopes: [deployments.create, workflows.read]
      constraints:
        projects: [platform-production]
        environments: [production]
      max_lifetime_seconds: 300
~~~

The schema is declarative **and** backed by persistent stable IDs; external URLs are exact-match verification attributes, not foreign keys to upstream human providers. A GitOps importer must refuse accidental deletes or privilege widening without explicit approval.

## 6. Token contract and verification

SkyOAuth-issued API JWTs use a dedicated stable issuer `iss`, stable API `aud` values, immutable local principal `sub`, bounded `iat/nbf/exp`, unique `jti`, scoped grants and (for delegation) RFC 8693 `act`. Protected services must check token type, issuer, audience, signature, time limits and policy-relevant claims; they must not accept arbitrary ID tokens as API tokens. Do not use untrusted claim keys as authorization headers.

A conceptual delegated access JWT:

~~~json
{
  "iss": "https://identity.example.com",
  "sub": "svc_deployment_controller",
  "act": {
    "iss": "https://identity.example.com",
    "sub": "wld_release_pipeline"
  },
  "aud": "control-plane-api",
  "scope": "deployments.create workflows.read",
  "skyoauth_grant": "grant_release",
  "exp": 1794780300,
  "jti": "token-instance-id"
}
~~~

Keys: asymmetric signer, bridge-owned JWKS with `kid`, versioned/overlapping rotation and private material outside source control. Prefer KMS/HSM support or encrypted-at-rest private keys with isolated access; never use an upstream IdP's signing keys. Retain retired public keys for maximum issued lifetime plus clock skew. Signer key rotation is independent of human IdP changes.

**Revocation tradeoff:** short-lived local JWTs verify without DB lookup, so revoking a WIF grant does not retroactively invalidate already-issued JWTs until expiration. Use a short default (e.g. <= 5 minutes), and consider an explicit online-policy gate for highly destructive endpoints. Browser cookies are server-revocable immediately. Never pretend that all paths have identical revocation semantics.

## 7. Persistent data ownership and policy

PostgreSQL is authoritative for:

| Aggregate | Stable ownership |
| --- | --- |
| `human_provider` / `external_subject_link` | Replaceable upstream human connections and verified user mappings |
| `principal` / `service_identity` | Stable SkyOAuth human, workload, and service IDs |
| `session` / `oidc_transaction` | Opaque browser sessions, revocation, PKCE/state/nonce transactions |
| `trust_source` / `trust_keyset_version` | Registered external issuers, discovery metadata, uploaded public JWKS |
| `principal_binding` | Immutable-approved external claim patterns → internal workload IDs |
| `service_grant` / `policy_revision` | Versioned delegate/impersonate, scope/audience/resource constraints |
| `signing_key_version` | Bridge-owned issuer key metadata/rotation state |
| `audit_event` | Policy changes, token issuance decisions, upstream migrations, sessions and grants |

No WIF object may depend through a cascading foreign key on `human_provider`. Policy writes need optimistic version checks, validation, immutable history and auditable actor identity. Exports/backups must include trust sources, uploaded JWKS and their provenance, service grants, and signing-key recovery strategy; **never export active private signing keys as ordinary plaintext YAML**.

Auth checks must fail closed on store failure. Favor simple PostgreSQL first; only introduce an optional cache with explicit revocation bounds and no privilege-expanding fallback.

## 8. Migration contract and runbook

Human provider swap is a *targeted, reversible* administrative operation, not a recreation of SkyOAuth:

1. Export/snapshot stable SkyOAuth public metadata, WIF registry IDs, keyset fingerprints/versions, workload bindings, service grants, effective policy decision fixtures, signing-key metadata and audit revision.
2. Register/test replacement human IdP with fixed issuer/client/callback configuration on the server. Validate claims needed for human login; prepare verified account linkage (manual/admin-approved mappings, never email matching alone).
3. Dry-run the provider switch. Assert **no WIF trust sources, uploaded public JWKS, bindings, grant IDs, grant contents, API audiences, signing keys, or gateway policies are mutated**. Reject a migration plan that attempts those changes.
4. Atomically switch only active human login provider and associated human mapping configuration; invalidate affected human sessions/CLI credentials, with rollback controls.
5. Reauthenticate humans. Verify stable internal user IDs and unchanged application RBAC where explicit linkage exists; unmatched users require controlled enrollment.
6. Re-run GitHub WIF and uploaded-JWKS exchanges and negative tests **without changing job YAML, client packages/binaries, secrets, API settings, or service deployments**.
7. Compare pre/post policy decisions and audit invariants. Roll back the human provider pointer independently of the WIF registry if needed.

Repeat migration conformance tests after DB schema, chart, protocol, and SDK upgrades—not just after IdP switches. Human-provider downtime may affect human reauthentication but must not block already valid GitHub/Kubernetes WIF exchanges except where the shared SkyOAuth service itself is unavailable.

## 9. Security and abuse model

Main threats: malicious or compromised CI workflows; forgery/issuer confusion; uploaded-JWKS misconfiguration; token exchange replay; policy privilege escalation; signer compromise; cookie theft or session fixation; CSRF/XSS; unauthenticated gateway route; header spoofing; SSRF in issuer discovery; cross-tenant resource authorization failures; migrations that orphan/recreate trust objects; stale grants and long-lived streams; compromised credentials on GitHub runners.

Baseline mitigations:

- Deny-by-default for issuer/source/binding/service grant; exact allowlisted issuer, audience, algorithm and claims; admin-approved import and rotation with dry-run/diff.
- Short-lived JWTs; token and request size limits; rate limiting; audit redaction; deterministic source-policy matching; explicit policy revisions; no arbitrary requested `sub` accepted.
- Gateway ext_authz fail-closed, mTLS or signed assertions internally, sanitize client identity headers; no direct API network access from untrusted clients.
- PKCE/state/nonce, narrow callback URIs, login CSRF defense; host-only cookies, server-side session revocation, CSRF, CSP for frontend; sessions never exposed to JS.
- Distinct browser cookie and bearer authentication profiles; reject dual credentials; treat origin/CSRF semantics separately from machine JWT calls.
- Strict outbound allowlists/timeouts for OIDC discovery and JWKS; never trust JWT-supplied `jku`/`x5u` or fetch arbitrary internal URLs.
- No unbounded stream authorization assumption: establish policy for stream max duration, periodic reauthorization or server-side cancellation; backend enforces each artifact/workflow resource permission.
- Audit all source verification, exchange allow/deny, service impersonation, policy edits, and migration steps without logging tokens, raw cookies or private keys.

**Residual limits:** zero *client-side static secrets* does not mean zero trust anchors. SkyOAuth holds privileged signing keys; upstream OIDC may require server-side confidential client credentials; Kubernetes TokenReview requires narrowly scoped cluster access; identity can be stolen during a valid job/session. Security depends on those protections and backend RBAC.

## 10. SDKs and developer experience

- `@skyoauth/browser`: same-origin session fetch, top-level login/logout, CSRF token retrieval, browser-safe principal, no access-token getter, no persistent JS token storage.
- `@skyoauth/react`: small React provider/hook; loading/unauthenticated/authenticated states, stable across IdP migration.
- `@skyoauth/connect`: ConnectRPC interceptor attaches CSRF for cookie sessions, handles gateway 401 vs Connect Unauthenticated, never auto-replays non-idempotent mutations, handles stream errors.
- `skyoauth-cli` / Rust SDK: stable SkyOAuth authorization/PKCE and WIF exchange client with in-memory bearer-token caching; GitHub runner obtains OIDC via supported runner interface; K8s provider rereads projected token file. Avoid writing exchanged machine tokens to disk or logs.
- Gateway integration examples: Envoy Gateway SecurityPolicy for gRPC ext_authz and protected routes, Traefik ForwardAuth adapter, k3s Helm chart, optional Cloudflare Tunnel topology.

API clients and server policy configurations must be defined in terms of **SkyOAuth** issuer/audience/subject and stable trust/grant IDs, not Zitadel identities.

## 11. Milestone roadmap

| Stage | Deliverable | Release gate |
| --- | --- | --- |
| **M0 — Specification and threat model** | Public contract, trust/policy semantics, security ADRs, tests | Reviewable protocol/spec examples and threat matrix |
| **M1 — Persistent identity core** | Postgres schema, stable principals, issuer/JWKS registry, bindings/grants, signer/JWKS, policy evaluator | No human-IdP foreign-key coupling; migrations/backups proven |
| **M2 — Mandatory WIF** | GitHub Actions OIDC, K8s TokenReview, generic discovered/uploaded-JWKS sources, RFC 8693 endpoint, scoped JWTs, workload client | GitHub Actions → protected API works with no static secret; deny/replay tests |
| **M3 — Human auth and gateways** | Zitadel OIDC, opaque browser sessions, Envoy gRPC ext_authz, same-origin routes, CSRF, browser/React/Connect libraries | Authenticated ConnectRPC unary/stream/download with no payload proxying |
| **M4 — Stable CLI and provider delegation** | Bridge-owned public-client PKCE auth, CLI SDK, provider adapter, compatible Zitadel exchange | Existing CLI survives upstream provider swap after reauth |
| **M5 — Migration and hardening** | Provider-switch runbook/tooling, WIF invariance tests, telemetry, K8s deployment/security and OSS release process | **No client change AND no WIF policy/trust reset**, same effective grants |
| **v0.1 release** | M0–M5 complete with security test gates | Versioned contract and published conformance suite |
| **Later** | Device flow, other CI issuers/gateways, expanded admin UI, optional token-binding/online revocation, cloud STS adapters | Separately scoped; not substitutes for mandatory WIF |

Detailed tasks, API shapes, state machines, dependencies, and acceptance criteria are in [skyoauth-tasks.md](skyoauth-tasks.md).

## 12. Open design decisions

Record decisions as ADRs before implementation: bridge-native CLI authorization-code implementation and whether to ship device flow in v0.1; session token retention for delegated Zitadel operations; precise authentication header transport and backend validation; ES256/RS256 signer and key-management backend; first-class admin configuration API vs GitOps-only initial writes; online WIF revocation needs for destructive APIs; whether true impersonation is supported at all before v1; resource-constraint encoding and schema versioning.

Security-critical behavior must be **explicit and tested**, not inferred from framework defaults.

## 13. References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html) (delegation and `act` claim)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 8252 — OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [Zitadel token exchange guide](https://zitadel.com/docs/guides/integrate/token-exchange) (current provider-specific restrictions)
- [GitHub Actions OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) and [reusable workflow identity](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)
- [Envoy Gateway external authorization](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
- [Kubernetes projected service-account tokens](https://kubernetes.io/docs/concepts/security/service-accounts/) and [TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
