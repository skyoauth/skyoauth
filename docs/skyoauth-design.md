# SkyOAuth — Architecture, security model, and roadmap

> **Status:** proposed design for review (2026-11-15; revised for PR #1 review). This document is normative for project goals, not evidence that an implementation exists. See [skyoauth-tasks.md](skyoauth-tasks.md) for detailed interfaces, dependencies, milestones, and acceptance tests.

## 1. Executive summary

SkyOAuth is a small, self-hostable **identity bridge** for public-facing applications and private APIs. It eliminates application-managed, long-lived client credentials by accepting *existing* human and workload identities, applying administrator-owned trust and authorization policies, and presenting stable SkyOAuth credentials to protected services.

SkyOAuth is **not** a substitute for an upstream human identity provider, a service mesh, or an application traffic proxy:

- **Browser:** OIDC SSO with Zitadel (or another upstream provider) establishes an opaque, Secure/HttpOnly, server-side session. The browser never receives OAuth access or refresh tokens.
- **CLI:** a stable SkyOAuth native OAuth interface brokers interactive upstream OIDC sign-in (Authorization Code + PKCE; device flow if implemented). CLIs receive short-lived SkyOAuth API access tokens rather than upstream-provider-specific credentials. SkyOAuth requires its own transaction-bound native-client confirmation.
- **Workloads:** GitHub Actions OIDC, Kubernetes projected service-account tokens, and registered third-party OIDC/JWT issuers can be verified and exchanged into short-lived, audience-bound SkyOAuth access tokens. Direct workload exchange uses RFC 8693; policy-mapped service delegation uses an explicitly separate SkyOAuth extension (§5.7). **GitHub Actions → our k3s APIs is a first-class, mandatory use case.**
- **Gateway:** Envoy Gateway queries SkyOAuth's out-of-band gRPC `ext_authz` implementation for opaque browser sessions and, initially, bearer tokens. The minimal bearer path ships in M2; browser support extends it in M3. Envoy routes ConnectRPC calls, streams, and large downloads **directly** to the application; SkyOAuth never proxies their bodies. HTTP ForwardAuth adapters can support other gateways.
- **Backend:** protected APIs enforce tenant/project/workflow permissions and operation-specific authorization; the identity bridge only establishes principal identity and scoped grants.

**Non-negotiable compatibility goal:** replacing Zitadel or any other *upstream human IdP* must require **zero changes, rebuilds, reconfiguration, or redeployments of browser/CLI/agent clients or protected services**. Reauthentication of human users is acceptable. The migration must **also leave all WIF registrations (discovery URLs, uploaded JWKS, or per-cluster TokenReview configuration), external-claim → principal mappings, supported service grants, audiences/scopes, and policy decisions intact**, without administrators resetting them. Stored impersonation policy must also survive without being implicitly enabled, even when that mode is not shipped.

The public SkyOAuth issuer and its signing keys, trust registry, internal principals, administrator authority, and policy database are **SkyOAuth-owned**, not upstream-IdP-owned.

### 1.1 Goals

1. Remove static API keys, personal access tokens, and secret bootstrap credentials from browser frontends, CI jobs, and workload/agent applications.
2. Provide a stable, standards-oriented HTTP/OAuth contract and small client SDKs across upstream human IdP changes; explicitly identify project-specific extensions.
3. Support GitHub Actions OIDC → scoped access to user-owned cluster backends, without cloud STS, SPIRE, sidecars, or an application-layer reverse proxy.
4. Maintain persistent administrator-managed discovery/JWKS/TokenReview trust sources, subject bindings, and service policy mappings, regardless of human IdP migration or normal application upgrades.
5. Be usable with k3s/Kubernetes, Envoy Gateway, Cloudflare Tunnel, ConnectRPC, and optional alternate gateways.
6. Keep a narrow, auditable Rust service and an explicit separation between authentication, token issuance, and resource authorization.

### 1.2 Non-goals

- Directory/user provisioning, end-user MFA/password management, upstream consent management, and organizational identity governance (upstream IdP responsibilities). **SkyOAuth's own minimal native-client confirmation is in scope**; a device user-code verification/confirmation page is required if device flow ships. Independent operator credentials (§7.2) are also in scope.
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
| C02 | Stable native-client authorization/token endpoints, exchange profiles including source/grant selectors, browser-session endpoints and client SDK APIs. |
| C03 | Stable API audiences, normalized principal IDs, versioned token/constraint semantics, gateway/authentication contracts, and ConnectRPC caller identity contract. |
| C04 | Human IdP changes may invalidate human browser/CLI sessions but require no client or backend redeployment/configuration changes. Registered SkyOAuth OAuth clients remain unchanged. |
| C05 | Tenant-owned external registrations survive unchanged: stable source ID, exact `iss`, discovery URL or uploaded public JWKS/keyset versions or TokenReview cluster ID/endpoint/CA/reviewer-credential reference, accepted audiences, verification/replay policy and lifecycle metadata. |
| C06 | External subject/claim → workload principal bindings and service grants, scope/audience ceilings, tenant/resource constraints, modes and policy IDs survive unchanged. Unsupported impersonation records remain inactive, not deleted or activated. |
| C07 | Already permitted WIF sources continue to exchange tokens with identical effective policy outcomes, apart from independently triggered trust or policy changes. Replay-consumption state is not reset. |
| C08 | SkyOAuth-issued credentials have an issuer distinct from upstream human IdPs; backends do not need to trust Zitadel, GitHub, or other upstream issuers directly. |
| C09 | Authentication never bypasses application-level resource authorization. Cookie or JWT proof alone never implies permission to operate on a project, Temporal workflow, tenant, or cloud account. |
| C10 | Policy changes and upstream migrations are separate, explicit administrative operations with audit, dry-run, and rollback. Administrator authority/recovery is independent of the active human IdP. |

**Scope of guarantee:** a human IdP migration is not an external issuer's own key compromise/rotation, its protocol outage, or a requested WIF-policy change. Those events may legitimately require explicit administrator action. It is also not a promise that every provider supports identical MFA or user claims. Identity linking must be explicitly verified; equal email addresses do not prove account continuity. Normal independent TokenReview reviewer-credential rotation remains possible; a human provider switch neither rotates it nor rewrites its reference.

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
    PUB[Public OAuth / OIDC broker / session endpoints]
    EXT[gRPC ext_authz / HTTP ForwardAuth]
    EX[Policy-aware exchange + local JWT issuer]
    ADM[Private operator API / recovery]
    DB[(PostgreSQL: sessions, trust, grants, keys metadata)]
  end
  U[Upstream human OIDC: Zitadel or replacement]
  J[Configured external issuers and Kubernetes TokenReview]
  O[Independent operator credentials]
  EDGE[Cloudflare Tunnel optional -> Envoy Gateway]
  API[ConnectRPC / REST control-plane API]
  TP[Temporal / cloud execution backends]
  B --> EDGE
  C --> PUB
  G --> EX
  K --> EX
  O --> ADM
  ADM --> DB
  PUB <--> U
  EX <--> J
  PUB --> DB
  EX --> DB
  EDGE -. auth check only .-> EXT
  EXT --> DB
  EDGE -->|authorized request / response bytes| API
  API -. private live grant check .-> EX
  API --> TP
~~~

The diagram separates *logical* control-plane calls; browser login/session paths are routed by Envoy to SkyOAuth on the **same application origin**, while API traffic goes from Envoy directly to the backend. External clients can reach the public token endpoint but **not** the private ext_authz, policy-check, or operator listeners.

### 3.1 Four security boundaries

1. **External issuers are untrusted until explicitly registered.** A JWT is not authoritative because it has an `iss` or `kid` claim; a selected registered source fixes issuer, verifier, audience, maximum age, and claim policy. Request selectors are not credentials.
2. **SkyOAuth owns session, token, and administrative authority.** Stable internal principal IDs (`usr_*`, `wld_*`, `svc_*`) are independent of upstream subject IDs. Separate `adm_*` operator identities cannot be obtained through upstream roles, email, or WIF. SkyOAuth signing keys are not Zitadel keys.
3. **Envoy is the transport gate, not application policy.** A protected route must have a fail-closed SecurityPolicy; a backend must never trust arbitrary user identity headers supplied by a public client.
4. **Application/resource authorization remains in the API.** The API validates an authenticated principal and signed grant constraints before workflow start/cancel/terminate, cloud mutation, and artifact access. A live grant check does not replace backend RBAC.

The token-signing function is privileged. Separate its key material/permissions from public session handling, and make the issuer signing component independently deployable if the operational threat model demands it.

## 4. Deployment and traffic paths

Recommended deployment: Rust/Axum + Tokio service with a public HTTP listener (via Envoy), a separate private gRPC `envoy.service.auth.v3.Authorization/Check` listener, and authenticated private control-plane listeners; PostgreSQL authoritative store; 2+ stateless SkyOAuth replicas; Envoy Gateway data plane and Gateway API HTTPRoutes; Cloudflare Tunnel optional. Valkey is an *optional* bounded-lifetime cache, not a required security dependency.

Example origin layout (deployment-specific hostnames, stable to clients):

| Entry point | Example | Access |
| --- | --- | --- |
| SkyOAuth issuer/exchange | `https://identity.example.com/oauth/token` and `/.well-known/jwks.json` | Public, strongly rate limited |
| Same-origin browser auth | `https://app.example.com/_skyoauth/login`, `/callback`, `/session`, `/logout` | Public; route to SkyOAuth |
| App RPC | `https://app.example.com/rpc/...` | Envoy -> ext_authz -> API |
| Downloads/events | `https://app.example.com/downloads/...`, `/events/...` | Envoy -> ext_authz -> API, no auth-service data hop |
| Private auth checks | gRPC ext_authz port inside cluster | Gateway only, authenticated transport |
| Live grant check | `POST /internal/v1/policy/check` on private listener | Authenticated, audience-authorized backend only |
| Operator API | `/admin/v1/...` on separate private listener | Independent operator mTLS identity + local role check |

For browser cookies use a host-only `__Host-` cookie per application origin. The gateway routes the auth endpoints on the application host; do not broaden cookie scope to `.example.com` for convenience. The stable issuer may be a separate hostname: this does **not** imply sharing that hostname's cookies with the SPA.

**Envoy integration:** gRPC ext_authz sees a minimal header/method/authority/path context (never upload bodies); returns Allow/Deny and narrowly defined verified identity material. Enforce header sanitization, gateway-to-backend network restriction, and TLS/mTLS or an audience-bound, signed internal identity assertion. Preserve the entire verified constraint envelope, not just `sub`/scope. Return 401 for RPC auth failures (not OIDC HTML redirects); browser SDK initiates top-level login navigation. Fail closed on auth-service/database outages. Explicitly reject ambiguous requests carrying a session cookie and a bearer credential.

**Cloudflare:** Tunnel provides origin connectivity, not a substitute for per-route authentication; WAF/rate-limit/Access features must be configured separately. Avoid trusting arbitrary `CF-*` or `X-Forwarded-*` headers outside a trusted proxy chain. Layered rate limits should work without moving application bytes through SkyOAuth.

## 5. Identity and credential flows

### 5.1 Browser: opaque server-side session

1. Unauthenticated navigation follows a SkyOAuth-managed login entrypoint on the app origin with a validated relative return location.
2. SkyOAuth starts upstream OIDC Authorization Code + PKCE S256, per-transaction state/nonce, strict callback URI and issuer binding; all remote discovery HTTP must enforce SSRF-safe egress restrictions.
3. On callback, verify issuer, ID token signature, audience, nonce, expiry, and appropriate `auth_time`/MFA requirements; look up a stable human principal through a verified provider-subject binding.
4. Generate a new CSPRNG session ticket. Store only its keyed hash plus tenant/principal, provider ID/subject and optional upstream `sid`, provider authentication epoch, creation/last-seen timestamps, separate idle/absolute deadlines, revocation state, and a CSRF verifier in PostgreSQL. Index provider/session selectors for provider switches and verified back-channel logout.
5. Set `__Host-skyoauth_session` with `Secure; HttpOnly; Path=/; SameSite=Lax` and no Domain; this is **not** an OAuth token cookie. Local logout revokes the session. Upstream logout notifications may revoke mapped sessions after fully verifying the logout token.
6. `GET /_skyoauth/session` returns only browser-safe principal/session and a session-bound CSRF token with `Cache-Control: no-store`. Unsafe cookie-authenticated calls must pass exact-origin and CSRF checks; SameSite alone is not the defense.
7. For multi-org products, the API resolves and authorizes actual organization/project membership; any UI-selected org is an untrusted request parameter.

A session is usable only before **both** deadlines and while its provider epoch is current. Throttled last-seen writes must be conservative across replicas: never revive an idle-expired session or extend the absolute deadline. The maximum early idle expiry caused by write coalescing must be documented and tested.

**Default**: discard upstream access/refresh tokens after authentication. When Zitadel RFC 8693 delegation or an upstream API call is required, encrypted, server-side retention becomes an explicit opt-in credential vault feature. Reauthentication after human IdP migration is permitted. Sessions should not be coupled to upstream token rotation or force browser cookie rotation on every ext_authz check.

### 5.2 CLI: brokered OAuth, not provider-specific URLs

The CLI is an OAuth public client of **SkyOAuth** using a stable bridge-owned `/oauth/authorize` and `/oauth/token` contract, Authorization Code + PKCE, loopback redirect URI per native-app guidance; device authorization is an additional profile for headless environments. SkyOAuth forwards the *human authentication step* to the currently active upstream IdP, then issues short-lived SkyOAuth API tokens. Changing Zitadel does not change CLI configuration. Never put upstream refresh tokens on the CLI. Persistent CLI login is an explicit product decision: either interactive reauth or a revocable SkyOAuth refresh credential in OS keychain, not a static API key.

**Native-client confirmation is mandatory for every new loopback authorization transaction.** After upstream authentication, SkyOAuth displays the registered client name, signed-in account, requested audience/scopes and loopback destination, with explicit approve/deny controls. State plainly that a public client ID does not authenticate the local program. Bind approval to the exact client, redirect, PKCE challenge, audience/scopes, principal and expiring single-use transaction; CSRF-protect the confirmation POST and prohibit framing. Existing SSO or an earlier approval for the same client ID must not auto-approve a new transaction. Denial/expiry produces no code. This is SkyOAuth authorization, not the upstream IdP's consent to SkyOAuth's confidential client; see RFC 8252 §8.6. It reduces silent local-client impersonation, not all social engineering.

If device flow ships, its user-code verification and confirmation pages must provide equivalent account/client/scope disclosure, explicit approval, expiry and polling/abuse controls. It is not an automatic fallback that bypasses confirmation.

Implementing a public-client OAuth frontend is a real authorization-server obligation: transactional authorization codes shared across replicas, registered client IDs and redirects, PKCE, token response semantics, issuer metadata, throttling, revocation, and replay prevention. Do **not** claim CLI compatibility until this profile passes conformance tests.

### 5.3 GitHub Actions WIF (required)

1. GitHub Actions job has `permissions: id-token: write` and asks GitHub's OIDC service for a JWT with the administrator-configured SkyOAuth exchange audience.
2. Client posts to SkyOAuth `/oauth/token` over TLS with stable source/grant selectors and one explicit API audience. Use the RFC 8693 direct-workload profile or the service-delegation extension in §5.7; do not silently reinterpret one as the other.
3. SkyOAuth selects a **registered** source, verifies GitHub issuer/signature/exact audience/time claims against discovery/JWKS, and matches immutable repo owner/repo IDs plus event, branch/environment, workflow/job-workflow identity constraints.
4. It resolves the **stable internal workload principal**, checks the specifically selected immutable-versioned grant, and issues a short-lived SkyOAuth access JWT containing approved audience, scopes, tenant/resource constraints, policy revision and actor attribution. Verified GitHub run provenance is retained for auditing.
5. The client calls ConnectRPC via Envoy using `Authorization: Bearer ...`. The protected API checks the full token/constraint profile and operation-specific resource permissions. The SDK reacquires a GitHub assertion and exchanges again on expiry; never logs or persists the tokens.

A successful GitHub JWT does **not** grant any operation by itself. Production grants must not be satisfied by arbitrary PR code or untrusted `pull_request_target` execution. `ref` and workflow context are not substitutes for an explicit `event_name` restriction. The production GitHub binding profile requires nonempty exact owner/repository IDs, event allowlist, ref, environment and workflow identity (plus reusable-workflow identity when used); reject incomplete configurations before activation. The example below permits **push only**.

**Matcher semantics:** listed predicates are ANDed; a configured claim missing from the verified token is a non-match. An omitted optional predicate means **unconstrained for that claim**, not implicit denial. Therefore security-required predicates cannot be omitted, and deleting a predicate is privilege widening subject to explicit approval. No automatic wildcard or regex matching is implied by a string.

**Token replay:** the source's `replay_mode` is explicit. Default `reusable` accepts an otherwise valid assertion again within its validity window, after fresh policy evaluation/rate limits, and issues a new token with a new `jti`; there is no idempotent-response guarantee. High-assurance sources may select `single_use`: require a verified nonempty source `jti` and atomically consume `(tenant, trust_source_id, exact_issuer, jti)` across all replicas and grants before issuance. Exactly one concurrent exchange may succeed; subsequent attempts deny. Persist only a keyed digest of this replay key until source `exp` plus allowed skew; missing `jti` or store failure denies. A crash after consumption may burn the assertion, so retry with a fresh one. Provider switches/rollback never clear this state. A cancelled job may leave an issued JWT usable until expiration; critical APIs use §6.1.

### 5.4 Kubernetes and generic external WIF

For k3s, use projected, rotated, *audience-bound* service-account tokens, re-reading the token file. The default Kubernetes adapter is **`kubernetes_token_review`**, not OIDC discovery disguised as a cluster verifier. Each administrator-approved source persists a stable cluster ID, exact expected issuer, fixed HTTPS API server endpoint, trusted CA bundle/fingerprint, reviewer-credential reference, intended review audiences, timeouts, status and revision. Reviewer credentials are narrowly scoped to TokenReview creation and stored/rotated outside ordinary exports. No SPIRE, sidecar, or node agent is required.

The request's required `skyoauth_trust_source` selects one preconfigured source ID; its tenant and verifier configuration come from the registry. It is an untrusted routing selector, never proof of cluster identity. Multiple clusters may share the same `iss`, so **issuer is not a unique registry key**. Never probe every cluster until one accepts, infer a cluster from an unverified claim, or let request content supply an API URL/CA/credential. Verify only at the selected endpoint and deny on failure. Shared signing authorities can defeat cluster separation; do not claim isolation between clusters intentionally sharing token trust.

Set TokenReview `spec.audiences` explicitly; require `status.authenticated=true`, no error, and a compatible nonempty `status.audiences`. Bind the returned authenticated SA name/UID and required bound-Pod identity to that source/cluster. Test identical issuer strings across two independently keyed clusters. Private cluster endpoints are allowed only through the preapproved TokenReview egress profile with TLS CA/hostname validation, no redirects and bounded requests, not the public discovery fetcher.

Other source kinds are:

- **`oidc_discovery`:** explicitly approved exact issuer and OIDC discovery/JWKS URL, pinned accepted algorithms/audiences and bounded refresh/stale-cache rules.
- **`uploaded_jwks`:** exact expected issuer, accepted audiences/algorithms, a stable `TrustKeyset` parent and administrator-uploaded **public** keyset versions with explicit rotation overlap. Versions attach to the keyset, not circularly back to a source pointer. Several versions may be active simultaneously.

Local JWT verification for Kubernetes is a separately configured discovery/uploaded-JWKS source with a documented stale-revocation tradeoff, never an automatic fallback from failed TokenReview. Disallow unregistered sources, remote `jku`/`x5u` header-driven key resolution, `alg=none`, weak algorithm substitution, private JWK upload and implicit trust of arbitrary URL redirects. Bound token size, claim complexity, clocks and public-key refresh. A trust-source change is **not** part of a human IdP migration.

### 5.5 Upstream RFC 8693 delegation to Zitadel

Zitadel is the first *human IdP adapter*, not the canonical issuer of our APIs. Where Zitadel supports a compatible exchange of **Zitadel-issued** tokens, SkyOAuth may delegate the upstream exchange after verifying the grant and available audiences/scopes. Provider-specific capabilities/restrictions must be verified against the deployed version; do not assume arbitrary GitHub assertion → Zitadel token exchange or access to Zitadel's own administrative APIs works.

**Always normalize the downstream API credential to SkyOAuth's public contract.** Zitadel token pass-through directly to protected APIs is **not** the default; it would break the zero-client/backend-change migration goal. An upstream exchange result may be retained server-side for an explicitly approved provider operation, or be validated and converted to a bounded SkyOAuth JWT.

Zitadel administrative operations must use a separately isolated, restricted server-side service identity/adapter, with audit and no client exposure. This identity is not SkyOAuth's operator authority, and neither public WIF profile may mint its credentials.

### 5.6 Delegation versus impersonation

Federation trust maps *verified source claims* to a stable actor (`wld_*`). A **ServiceGrant** explicitly chooses one mode:

- **Delegation (required):** `sub` represents the approved service (`svc_*`), while the RFC 8693 `act` claim records the original workload actor. Include grant/policy provenance and retain verified source run/job attribution in audit. The policy-mapped request is the extension defined in §5.7, not generic RFC 8693 delegation.
- **Direct workload (required):** `sub` is the stable workload principal; the selected grant has no target service and still supplies explicit audience/scope/resource ceilings.
- **True impersonation (conditional):** distinct high-risk mode that can omit target-visible actor identity. Disabled by default and **not required for v0.1**; ADR-006 must explicitly include it before implementation/activation. If included, separate approval, strict target ceilings, issuance attribution and tests are mandatory. Unsupported stored records remain inert through migrations; they never degrade into delegation or direct access.

Effective access is the **intersection** of verified identity binding, selected actor grant, target service ceiling (when applicable), requested audience/scopes and resource constraints. Missing required identity/policy fields deny rather than widen. Optional scope omission has the explicit narrow rule in §5.7. GitHub's human `actor` claim is audit context, not proof of a human SkyOAuth session.

Example proposed policy (not yet a released configuration schema; referenced principals/services belong to this tenant):

~~~yaml
tenant_id: tenant_platform
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
      replay_mode: single_use
    - id: trust_partner
      kind: uploaded_jwks
      issuer: https://ci.partner.example
      keyset_id: partner-production
      audiences: [https://identity.example.com]
      allowed_algs: [ES256]
      replay_mode: reusable
    - id: trust_k3s_production
      kind: kubernetes_token_review
      issuer: https://kubernetes.default.svc.cluster.local
      cluster_id: cluster_production
      api_server: https://k3s-api.internal.example:6443
      ca_bundle_ref: ca_k3s_production
      reviewer_credential_ref: secretref_k3s_reviewer
      audiences: [https://identity.example.com]
      replay_mode: reusable
  keysets:
    - id: partner-production
      versions:
        - id: partner-v1
          public_jwks_ref: public-jwks/partner-v1.json
  bindings:
    - id: binding_release_pipeline
      source: trust_github
      profile: github_production
      match:
        repository_owner_id: "123456"
        repository_id: "456789"
        event_name: push
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
      default_scopes: [workflows.read]
      constraints:
        projects: [platform-production]
        environments: [production]
      max_lifetime_seconds: 300
~~~

The schema is declarative **and** backed by persistent stable IDs. Public-JWKS/CA references in this illustration must resolve to validated, versioned contents during enrollment; clients cannot supply them. External URLs are verification attributes, not foreign keys to upstream human providers. A GitOps importer must refuse accidental deletes or privilege widening without explicit approval.

### 5.7 Exchange request profile and grant selection

Both profiles use form-encoded `POST /oauth/token`, require exactly one `audience`, `skyoauth_trust_source` and `skyoauth_grant_id`, and accept optional `scope`. The two `skyoauth_*` parameters are **nonsecret SkyOAuth extensions**, not standard RFC parameters. Resolve the selected source, verify its proof, resolve its binding, then require that the selected grant belongs to the same tenant and verified actor. A grant ID selects its preapproved mode/target; it grants no authority by itself. Never choose the first matching grant or accept arbitrary requested `sub`, `act_as`, tenant, mode or target-service overrides. Different grants for the same audience are therefore unambiguous.

| Profile | Grant type | Proof parameters | Issued identity |
| --- | --- | --- | --- |
| Direct workload | `urn:ietf:params:oauth:grant-type:token-exchange` | External assertion in `subject_token`; `subject_token_type=urn:ietf:params:oauth:token-type:jwt` | Verified workload mapped to stable `sub`; selected grant must be `direct` |
| Service delegation | `urn:skyoauth:params:oauth:grant-type:service-delegation` (proposed private extension) | External assertion in `actor_token`; `actor_token_type=urn:ietf:params:oauth:token-type:jwt` | Grant's service as `sub`, verified workload as `act.sub`; selected grant must be `delegation` |

RFC 8693 distinguishes the subject represented by `subject_token` from the acting party represented by `actor_token` (§2.1 and Appendix A). A workload assertion alone is not a target-service subject token. SkyOAuth therefore **does not advertise the single-proof service-mapping operation as standard RFC 8693 delegation** or silently move an RFC subject into `act`. The private extension uses administrator-owned target authorization instead of a subject token. Its URI is a proposed project identifier, not an IANA-registered grant. Generic two-token RFC delegation is outside v0.1; the upstream Zitadel adapter remains separate. T00.9 must freeze/document these interoperability limits before publishing SDKs.

`scope` omission uses only the selected grant's explicit, nonempty `default_scopes`, which must be a subset of its allowed scopes and all current ceilings. Without such defaults, return `invalid_scope`; never infer all allowed scopes. An explicitly empty or excessive scope request is rejected, not silently widened. Requesting any unapproved scope denies the request. Missing required selectors, duplicate parameters, unsupported proof combinations, or grant/profile mismatch deny. The direct profile rejects `actor_token`; the extension rejects `subject_token`. Only one target audience is supported initially; unsupported `resource` or requested token types are rejected rather than ignored.

A conceptual delegation request (displayed decoded; the client form-encodes values):

~~~text
grant_type=urn:skyoauth:params:oauth:grant-type:service-delegation
actor_token=<fresh GitHub assertion>
actor_token_type=urn:ietf:params:oauth:token-type:jwt
skyoauth_trust_source=trust_github
skyoauth_grant_id=grant_release
audience=control-plane-api
scope=deployments.create workflows.read
~~~

Success uses an OAuth token response with `access_token`, `token_type=Bearer`, `expires_in`, explicit granted `scope`, and `issued_token_type=urn:ietf:params:oauth:token-type:access_token`; no WIF refresh token. Use standard OAuth errors, non-enumerating authorization failures, no redirects and `Cache-Control: no-store`. The extension's response intentionally follows this shape without claiming the grant itself is standard.

## 6. Token contract and verification

SkyOAuth-issued API JWTs use a dedicated stable `iss`, stable API `aud`, immutable local `sub`, bounded `iat/nbf/exp`, unique `jti`, explicit token type (`typ=at+jwt` in the protected header), and (for delegation) RFC 8693 `act`. Protected services must check the complete profile, not accept arbitrary ID tokens as API tokens or turn untrusted claim keys into authorization headers.

The **WIF profile requires** a signed tenant ID, grant ID, immutable effective-policy revision and versioned resource constraints. `skyoauth_policy_revision` identifies the decision snapshot covering source, binding, grant and target-service ceilings; it is not merely the mutable grant's name. Resource restrictions are carried **in the token**, so offline verifiers do not need a grant lookup to discover them. For a gateway-generated internal assertion, preserve the same effective constraints and cap its lifetime to the original credential.

A conceptual delegated access JWT (matching the explicit scope request above):

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
  "skyoauth_tenant": "tenant_platform",
  "skyoauth_grant": "grant_release",
  "skyoauth_policy_revision": "policy_release_7",
  "skyoauth_constraints": {
    "version": 1,
    "projects": ["platform-production"],
    "environments": ["production"]
  },
  "iat": 1794780000,
  "nbf": 1794780000,
  "exp": 1794780300,
  "jti": "token-instance-id"
}
~~~

Constraint version 1 uses exact identifier allowlists. Values within a list are alternatives; different dimensions are ANDed with tenant, audience, scope and backend RBAC. Missing/empty required dimensions, unknown constraint fields or unsupported schema versions fail closed; omission is never `*`. The API resolves canonical tenant/project/environment from its own resource state, not from caller headers, and rejects resources outside the signed envelope. T00.4 freezes this schema and operation-to-required-dimension mapping before clients/backends ship. A token containing only a grant ID is insufficient.

Keys: asymmetric signer, bridge-owned JWKS with `kid`, versioned/overlapping rotation and private material outside source control. Prefer KMS/HSM support or encrypted-at-rest private keys with isolated access; never use an upstream IdP's signing keys. Retain retired public keys for maximum issued lifetime plus clock skew. Signer key rotation is independent of human IdP changes. Signer and JWKS implementation are **M2 / T20**; M1 only defines their persistence model.

### 6.1 Revocation and private live grant check

Short-lived local JWTs can verify without DB lookup, so disabling a WIF grant does not invalidate an already-issued token on an **offline** path before expiry. Use a short default (e.g. at most five minutes). Browser cookies are server-revocable. Do not claim uniform revocation semantics or guaranteed instantaneous Kubernetes object revocation beyond the selected verifier's documented behavior.

The mandatory M2 / T26 private `POST /internal/v1/policy/check` supports critical operations. An mTLS-authenticated backend, authorized for the token's audience/tenant, sends the presented access token plus the canonical action and resource coordinates it has resolved. SkyOAuth verifies the token, current principal/source/binding/grant/service status, applicable expirations, the effective policy revision, and the action's scope/resource ceilings. Any invalidated or superseded revision denies and requires a new token; it must not silently reinterpret an old token under broader policy. Return a request-bound allow/deny, checked revision and decision ID with no-store. Do not return a new token or a blanket authorization capability.

The backend must still perform its own resource RBAC and use the result only for the exact operation just checked; no positive caching for critical calls. Unknown caller/action/resource, database failure or unavailable checker fails closed. Revocation blocks checks started after the committed revocation, but cannot undo an already authorized operation; long-lived streams need bounded duration or rechecks/cancellation. No application payload crosses this endpoint. The task plan defines authentication, schema, endpoint, implementation and release tests rather than deferring this to an unspecified future introspection feature.

## 7. Persistent data ownership and policy

PostgreSQL is authoritative for:

| Aggregate | Stable ownership |
| --- | --- |
| `tenant` / `principal` / `service_identity` | Policy ownership boundary and stable human/workload/service IDs |
| `human_provider` / `human_subject_link` | Replaceable human connections, monotonic auth epoch and verified user mappings |
| `session` / `oidc_transaction` | Provider-indexed sessions, separate idle/absolute deadlines, revocation and one-time login state |
| `oauth_client` / `oauth_authorization_request` / `oauth_authorization_code` | Stable client registration, transaction-bound confirmation, single-use codes |
| `cli_refresh_credential` | Optional rotating, hashed refresh families and provider-epoch revocation |
| `trust_source` / `trust_keyset` / `trust_keyset_version` | Three verifier kinds, per-cluster configuration and owned public-JWKS versions |
| `principal_binding` / `service_grant` / `policy_revision` | Source-bound identities, mode/target/scope/resource ceilings, immutable effective decisions |
| `consumed_assertion` | Durable source-scoped single-use proof consumption across replicas |
| `admin_identity` / `admin_credential` / `admin_role_binding` / `recovery_state` | Independent operator trust, tenant-scoped roles, bootstrap/recovery lifecycle |
| `signing_key_version` / `audit_event` | Bridge-owned signing metadata, issuance/policy/migration/administrative audit |

No WIF or administrator object may depend through a cascading foreign key on `human_provider`. Policy writes need optimistic version checks, validation, immutable history and auditable actor identity. Exports/backups include all three source kinds, uploaded public JWKS and provenance, grants, client registrations, operator public trust metadata and signing-key recovery strategy; **never export private signing keys, operator keys, reviewer secrets, tokens or live session material as ordinary plaintext YAML**. Encrypted database backups have separate access/recovery controls.

Auth checks must fail closed on store failure. Favor simple PostgreSQL first; only introduce an optional cache with explicit revocation bounds and no privilege-expanding fallback.

### 7.1 Tenant ownership and source uniqueness

A `Tenant` is SkyOAuth's administrative policy partition; its relationship to application organizations is explicit, not inferred from an upstream email domain. Human providers/links, principals, clients, sessions, trust sources, keysets, bindings, services, grants and policy revisions carry `tenant_id`. Globally unique opaque object IDs enable lookup, but composite tenant/object foreign keys enforce **same-tenant** relationships. Cross-tenant bindings, grants and keyset references are forbidden in v0.1. The bridge issuer/signing keys are instance-owned; admin role bindings specify tenant scope or explicit instance scope.

`exact_issuer` is a verification attribute, **not globally or tenant-wide unique**. Two tenants may register GitHub independently; one tenant may register multiple Kubernetes clusters with an identical issuer. Sources have unique stable IDs and tenant-local names; keyset ownership and cluster IDs are explicit. The source selector determines the candidate tenant/verifier, then the verified source and same-tenant binding/grant determine authority. Neither an untrusted tenant claim nor a request parameter can switch this boundary. Audit, exports and operator reads/writes enforce the same ownership.

### 7.2 Administrator authentication, bootstrap and recovery

The v0.1 baseline is a **private operator API/CLI**, not an end-user admin role automatically imported from OIDC. Independent `adm_*` identities authenticate with registered operator public-key credentials over mTLS, rooted in deployment-owned trust and checked against local credential status on each request. A valid certificate alone is insufficient without an enabled local identity/role binding. Upstream roles, group claims, email and application/WIF access tokens never confer operator rights. Operator private keys (preferably hardware-backed) are privileged operational trust anchors, not static application API secrets.

Roles are explicit: tenant-scoped `trust_admin` manages sources/keysets/bindings/services/grants; `provider_admin` manages human connections, verified links and provider switch/rollback; `auditor` reads redacted configuration/audit; instance `security_admin` manages operator enrollment/roles, issuer-key administration and recovery controls. Roles do not implicitly include one another. A provider administrator cannot mutate WIF policy, and no IdP-controlled enrollment flow can assign an operator role. GitOps import uses an independently authenticated, scoped operator identity with the same validation/approval rules.

Initial bootstrap runs only through a deployment-local, access-controlled command/Unix socket, never a public HTTP enrollment route. An atomic, durable bootstrap transaction enrolls the initial operator public credential and a separately held offline recovery public key, records audit, and irreversibly closes normal bootstrap mode. Restarts and an empty-looking config file must not reopen it. Public credentials/role state and the bootstrap-closed marker are included in protected restore procedures; private keys are not ordinary exports.

Break-glass also uses the restricted local command/socket and possession of the pre-enrolled **independent recovery key**, with a short-lived single-use challenge bound to operation, arguments and expected revision. Permit only bounded recovery operations: restore an operator credential/role or execute a validated human-provider switch/rollback. No generic WIF grant editing, token minting or policy-check bypass. Consume challenges durably, audit and alert on use, rotate recovery material after use, and rehearse recovery while the human IdP is unavailable or its administrator mappings are broken. This cannot recover an unavailable database/signing subsystem without their separate disaster-recovery process.

Operator endpoints are private, tenant-scoped and revision-checked. They cover trust/keyset/binding/service/grant CRUD, validated GitOps import, human-provider configuration/linking and distinct `human-provider-switches` dry-run/commit/rollback operations. Provider switches have a database write boundary excluding WIF/operator objects. ADR-013 and T00.10/T13 must approve and implement these controls before WIF configuration or migration tooling ships; expanding an admin UI does not defer authentication/recovery.

## 8. Migration contract and runbook

Human provider swap is a *targeted, reversible* administrative operation, not a recreation of SkyOAuth:

1. Using independent operator authority, snapshot stable public metadata, tenant/source IDs, all three verifier configurations, keyset versions/fingerprints, workload bindings, grants/modes/default scopes/constraints, effective policy fixtures, client registrations, signing/operator public metadata and audit revision. Record replay-state invariants without exporting proof/token material.
2. Register/test the replacement human IdP with fixed issuer/client/callback configuration on the server. Prepare verified human linkage (never email matching alone). Confirm the independent operator/recovery path still works; it does not depend on linking an upstream admin account.
3. Dry-run the switch. Assert **no WIF source, TokenReview config, public JWKS, binding, grant, API audience, OAuth client registration, signing key, operator role or gateway policy is mutated**. Reject a plan attempting those changes.
4. Atomically switch the tenant's active human provider/mapping configuration and advance the affected provider authentication epochs. Invalidate affected human sessions, pending OIDC/native authorization transactions, unredeemed authorization codes and optional CLI refresh families. Do not alter WIF principals, policy or consumed assertions. Already-issued offline human JWTs retain only their documented short lifetime; never claim they were retroactively erased.
5. Reauthenticate humans. Verify stable internal user IDs and unchanged application RBAC where explicit linkage exists; unmatched users require controlled enrollment.
6. Re-run GitHub, **both shared-issuer Kubernetes cluster fixtures**, and uploaded-JWKS exchanges and negative tests **without changing job YAML, client packages/binaries, secrets, API settings or service deployments**. Exercise direct and delegated profiles and both replay modes.
7. Compare pre/post policy decisions and audit invariants. Roll back only human configuration when needed, with fresh epoch invalidation; do not restore a whole database snapshot over independently changed WIF policy or resurrect consumed codes/refresh tokens/assertions. Epochs are monotonic even on rollback.

Repeat migration conformance tests after DB schema, chart, protocol and SDK upgrades—not just IdP switches. Human-provider downtime may affect human reauthentication but must not block valid WIF exchanges or independent operator recovery except where the shared SkyOAuth infrastructure is unavailable. Valid single-use tests obtain fresh assertions; invariance does not require a consumed assertion to become reusable.

## 9. Security and abuse model

Main threats: compromised CI workflows; forgery/issuer or cluster confusion; JWKS misconfiguration; token replay; policy escalation; signer/operator compromise; session fixation; CSRF/XSS; silent native-client impersonation; unauthenticated gateway/admin routes; header spoofing; discovery SSRF; cross-tenant configuration/resource access; migrations that orphan trust or revive credentials; stale grants and long-lived streams; stolen runner credentials.

Baseline mitigations:

- Deny-by-default for source/binding/selected grant; exact issuer/audience/algorithm and required claims; explicit GitHub event; tenant-safe references and independent admin approval.
- Short-lived typed JWTs with signed versioned constraints; bounded input; source-scoped replay policy; deterministic revisions and no arbitrary requested `sub`.
- Fail-closed ext_authz, authenticated internal transport, sanitized identity headers and blocked direct API access; private audience-authorized live grant checks for critical operations.
- PKCE/state/nonce and narrow callback URIs; per-transaction native confirmation; host-only sessions, separate idle/absolute deadlines, CSRF and CSP; no browser token exposure.
- Distinct cookie and bearer profiles, rejecting dual credentials; no cookie/Origin assumptions in machine JWT validation.
- SSRF-safe discovery; explicitly configured TokenReview egress/CA/credential; never trust JWT-controlled key URLs or select clusters by issuer alone.
- Bounded stream authorization, rechecks/cancellation and backend resource permission checks for every operation.
- Auditable, revision-checked policy/provider changes and isolated operator recovery; no IdP role promotion; no tokens, raw cookies or private keys in logs.

**Residual limits:** zero *client-side static application secrets* does not mean zero trust anchors. SkyOAuth holds signing keys and independent operator/recovery trust; upstream OIDC may require confidential client credentials; TokenReview requires narrowly scoped cluster access; identity can be stolen during a valid job/session. A compromised human IdP can still impersonate mapped application users; it must not thereby gain authority to rewrite WIF or operator policy. Runtime/database/operator compromise remains a separate high-impact threat.

## 10. SDKs and developer experience

- `@skyoauth/browser`: same-origin session fetch, top-level login/logout, CSRF retrieval, browser-safe principal, no access-token getter or persistent JS token storage.
- `@skyoauth/react`: small React provider/hook with explicit loading/unauthenticated/authenticated states, stable across IdP migration.
- `@skyoauth/connect`: browser ConnectRPC interceptor for CSRF and auth errors; never auto-replay non-idempotent mutations.
- **Required Rust `skyoauth-client` in `crates/client`:** shared typed source/grant selectors, direct/delegated exchange, in-memory bearer caching, GitHub runner OIDC and Kubernetes projected-file providers (M2); native PKCE/confirmation flow and optional keychain refresh support (M4).
- **Required reference `skyoauth-cli` in `crates/cli`:** exercises the Rust client against stable SkyOAuth endpoints; distinguishes application login from separately authenticated operator commands. CLI auth is not an optional TypeScript package.
- `packages/agent`: optional additional TypeScript workload bindings; not a substitute for the required Rust client/CLI deliverables.
- Gateway examples: Envoy SecurityPolicy and protected routes (minimal bearer M2; browser/streams M3), optional ForwardAuth, k3s chart and Cloudflare topology.

Clients and policy configurations reference **SkyOAuth** issuer/audience/subject and stable source/grant IDs, not Zitadel identities. A provider migration does not change those selectors or published client registrations.

## 11. Milestone roadmap

| Stage | Deliverable | Release gate |
| --- | --- | --- |
| **M0 — Specification and threat model** | Public profiles, tenant/source/grant semantics, confirmation/admin/recovery ADRs, tests | Reviewable protocol/schema examples and threat matrix |
| **M1 — Persistent identity core** | Schema including later CLI/replay state, tenant ownership, trust/keyset/cluster registry, bindings/grants, policy evaluator, independent operator API/bootstrap/recovery | No human-IdP coupling; restores preserve IDs and consumption state; operator isolation proven |
| **M2 — Mandatory WIF and bearer gateway** | Signer/JWKS (T20), exchange profiles, GitHub/K8s/generic WIF, Rust workload client, minimal bearer ext_authz (T25), live grant check (T26) | GitHub/k3s → Envoy → ConnectRPC without static application secrets or human IdP; reusable replay accepted when valid, single-use replay denied |
| **M3 — Human auth and browser gateway** | Zitadel OIDC, opaque sessions, cookie/CSRF extension to M2 gateway, same-origin routes, browser/React/Connect libraries | Unary/stream/download works with no SkyOAuth payload proxying |
| **M4 — Stable CLI and provider delegation** | Bridge public-client PKCE + explicit confirmation, Rust native client/CLI, optional compatible upstream exchange | Existing CLI survives provider swap after reauth; silent authorization denied |
| **M5 — Migration and hardening** | Switch/runbook tooling, all-source WIF invariance, operator outage recovery, telemetry, K8s packaging and release process | **No client change AND no WIF trust/policy reset**, same effective grants |
| **v0.1 release** | M0–M5 and mandatory direct/delegation gates; conditional modes only if explicitly included | Versioned contract and published conformance suite |
| **Later / conditional** | Device flow, true impersonation, other issuers/gateways, expanded admin UI, token binding, cloud STS | Separately scoped; not substitutes for required WIF, confirmation or operator controls |

Detailed tasks, API shapes, state machines, dependencies, and acceptance criteria are in [skyoauth-tasks.md](skyoauth-tasks.md).

## 12. Open design decisions

ADRs must ratify the proposed defaults before implementation: exact native authorization implementation and optional device/refresh scope; upstream token-vault retention; header/assertion transport; signing algorithm/key-management backend; private admin credential tooling/recovery ceremonies; source/grant extension identifiers and errors; exact constraint schema/action registry; and whether true impersonation is included at all. The proposed baseline already requires per-transaction native confirmation, independent operator authority, a private live grant checker, explicit tenancy/source selection and signed resource constraints; these are not optional gaps to defer to a later UI.

Security-critical behavior must be **explicit and tested**, not inferred from framework defaults. A change to these defaults requires a reviewed ADR plus synchronized examples, tasks and release gates.

## 13. References

- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html) (§2.1 and Appendix A: subject/actor request semantics; §4.1: `act`)
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 8252 — OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252.html) (§8.6: client impersonation and interaction)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [Zitadel token exchange guide](https://zitadel.com/docs/guides/integrate/token-exchange) (verify provider/version-specific capabilities)
- [GitHub Actions OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) and [reusable workflow identity](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)
- [Envoy Gateway external authorization](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
- [Kubernetes projected service-account tokens](https://kubernetes.io/docs/concepts/security/service-accounts/) and [TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
