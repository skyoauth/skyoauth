# SkyOAuth — Architecture, security model, and roadmap

> **Status:** proposed design for review (2026-11-15; revised for both PR #1 review rounds and the PR #2 repository bootstrap). This document specifies project requirements, not implemented authentication. The bootstrap supplies a Rust service and a TypeScript health client. See [skyoauth-tasks.md](skyoauth-tasks.md) for interfaces, schema, milestones and release tests.

## 1. Executive summary

SkyOAuth is a small, self-hostable **identity bridge** for public-facing applications and private APIs. It accepts existing human and workload identities, applies administrator-owned trust and authorization policies, and presents stable SkyOAuth credentials to protected services without application-managed static API secrets.

SkyOAuth is not an upstream human identity provider, service mesh or application traffic proxy:

- **Browser:** upstream OIDC establishes an opaque, Secure/HttpOnly server-side session. A required **TypeScript SPA library** manages browser-safe session state and CSRF; JavaScript never receives OAuth access or refresh tokens.
- **CLI:** a required, reusable **Rust client crate** uses SkyOAuth's stable public-client Authorization Code + PKCE interface and transaction-specific confirmation. It receives short-lived SkyOAuth API credentials, not upstream-provider tokens. A reference CLI consumes this library rather than implementing a second protocol stack.
- **Workloads:** GitHub Actions OIDC, projected Kubernetes service-account tokens and registered external JWTs become scoped SkyOAuth access tokens. Direct exchange uses RFC 8693; single-proof service delegation is an explicitly separate extension (§5.7). **GitHub Actions → our k3s APIs is mandatory.**
- **Gateway:** Envoy Gateway calls a private, out-of-band gRPC `ext_authz` service. Minimal bearer support ships in M2; cookie/session support in M3. ConnectRPC calls, streams and downloads flow **directly from Envoy to the application**, never through SkyOAuth.
- **Backend:** the application remains authoritative for resource RBAC. It validates the signed credential profile, its own registered audience, canonical tenant/resource ownership and operation permissions. Audience registration and service identity are different objects.

**Non-negotiable migration goal:** replacing the upstream human IdP requires **zero changes, rebuilds, reconfiguration or redeployments of browser/CLI/agent clients or protected services**. Human reauthentication is acceptable. WIF registrations, discovery URLs, uploaded JWKS, per-cluster TokenReview configuration, subject bindings, supported service grants, audiences/scopes, resource constraints and effective policy decisions survive without administrative reset. Unsupported impersonation policy remains disabled, including after a capability upgrade.

SkyOAuth owns its public issuer/signing keys, tenants, audience authority, clients/application origins, principals, trust/policy database and independent operator authority. These are not owned by the replaceable human IdP.

### 1.1 Goals

1. Remove static application API keys/PATs/bootstrap secrets from SPAs, CLI applications, CI jobs and workload agents.
2. Provide **both** a TypeScript SPA library and a reusable Rust CLI library with stable, versioned contracts across human IdP migration. Their credential APIs are intentionally different.
3. Support GitHub Actions → protected cluster APIs without cloud STS, SPIRE, sidecars or an auth-service data-plane hop.
4. Preserve independently administered WIF sources, keysets, bindings, service policies, audience assignments and client registrations across migrations/upgrades.
5. Work with k3s/Kubernetes, Envoy Gateway, ConnectRPC and optional Cloudflare Tunnel/alternate gateways.
6. Keep the Rust service narrow and auditable; separate authentication, issuance, independent operator authority and application resource authorization.

### 1.2 Non-goals

- Passwords, end-user MFA, directory provisioning, upstream consent management and organizational identity governance. **SkyOAuth's native-client confirmation and independent operator credentials are in scope.** Device verification/confirmation is required if that optional flow ships.
- A mandatory service mesh, SPIRE/SPIFFE, cluster sidecar or node agent.
- Proxying application bodies, streaming payloads, downloads or SSE through SkyOAuth.
- General cloud credential brokerage in v0.1; this does not make WIF for SkyOAuth-protected APIs optional.
- Replacing backend resource RBAC with a universal application ABAC engine.
- Public access to upstream administrator tokens, arbitrary impersonation, or token-controlled URL/JWKS discovery.
- Identical secret-handling APIs across browsers and native apps; a Node-only client or reference executable alone does not satisfy the two library requirements.

## 2. Stable compatibility contract (MUST)

| ID | Invariant |
| --- | --- |
| C01 | Stable SkyOAuth issuer, discovery/JWKS and signing-key rotation contract. |
| C02 | Stable native OAuth, WIF exchange, browser-session and TypeScript SPA/Rust CLI library interfaces, including generated source/grant selectors. |
| C03 | Stable audience registrations, tenant/principal IDs, credential profiles, constraint semantics and gateway/backend identity contract. |
| C04 | Human migration may invalidate human auth state, but requires no client/backend redeployment or reconfiguration. OAuth clients, application origins and human access policies remain stable. |
| C05 | All external source configurations survive: IDs, exact issuer, discovery or uploaded keysets or TokenReview endpoint/cluster/CA/reviewer references, audiences, verifier/replay policy and lifecycle metadata. |
| C06 | Bindings, direct/delegation grants, target/service ceilings, approved binding sets, scopes/defaults and resource constraints survive. Unsupported impersonation records remain unchanged and inactive. |
| C07 | Valid WIF exchanges retain identical effective policy outcomes unless an independent trust/policy change occurs. Consumed-proof state is not reset. |
| C08 | SkyOAuth's issuer is distinct from upstream IdPs; protected services need not trust GitHub, Kubernetes or Zitadel directly. |
| C09 | Credential validity never bypasses canonical tenant checks or backend RBAC. A matching project name, scope or audience alone is insufficient. |
| C10 | Provider switch/rollback and policy administration are separate audited operations. Only the switch transaction changes the active-provider pointer; authority/recovery is independent of the human IdP. |

A human migration is not an external issuer's compromise/rotation/outage or a requested WIF-policy change. Those can require independent operator action. Equal emails do not prove identity continuity. The replacement provider must meet the configured human-authentication requirements. TokenReview reviewer rotation, audience administration and signer rotation remain independent operations, never implicit migration side effects.

## 3. Architecture and trust boundaries

~~~mermaid
flowchart TB
  subgraph Clients
    B[Browser / TypeScript SPA library]
    C[CLI / Rust client crate]
    G[GitHub Actions / CI]
    K[Kubernetes / external agent]
  end
  subgraph Identity["SkyOAuth identity control plane — Rust"]
    PUB[Public OAuth / OIDC broker / session endpoints]
    EXT[Private gRPC ext_authz]
    EX[Exchange / policy checks / local issuer]
    ADM[Independent operator API / recovery]
    DB[(PostgreSQL: identity, audiences, trust, policy, transactions)]
  end
  U[Replaceable human OIDC provider]
  J[Registered external verifiers / TokenReview]
  O[Independent operator keys]
  EDGE[Optional Cloudflare Tunnel -> Envoy]
  API[Registered resource server / ConnectRPC API]
  B --> EDGE
  C --> PUB
  G --> EX
  K --> EX
  O --> ADM
  ADM --> DB
  PUB <--> U
  PUB --> DB
  EX <--> J
  EX --> DB
  EDGE -. metadata-only auth check .-> EXT
  EXT --> DB
  EDGE -->|application request and response bytes| API
  API -. private operation check .-> EX
~~~

Browser auth routes are served on the registered application origin. Native authorization and its upstream callback are on the canonical issuer origin. External clients cannot reach private authorization, live-policy or operator listeners.

### 3.1 Four boundaries

1. **External proof is untrusted until verified by the selected registered source.** An `iss`, `kid`, source ID or grant ID is not authority to choose a verifier URL, tenant or subject.
2. **SkyOAuth owns issuance and administrative trust.** Stable local human/workload/service principals are distinct from upstream subjects. Independent `adm_*` identities cannot be acquired through OIDC claims or WIF. Instance-owned audience assignments bound tenant issuance.
3. **Envoy authenticates transport, not application permissions.** Protected routes fail closed; client identity headers are stripped; the backend is not directly accessible to untrusted callers.
4. **The API checks the exact credential profile and canonical resource tenant, then RBAC.** An explicit human `backend_rbac` constraint mode is not a WIF exemption or an automatic allow.

Isolate signer keys/permissions from public handlers and operator/reviewer credentials. The signer can be separately deployed when required by the threat model. No client library replaces server-side enforcement.

## 4. Deployment, origins and traffic paths

Baseline: Rust/Axum + Tokio, PostgreSQL, two or more stateless replicas, public HTTP via Envoy, separate authenticated private gateway/policy/operator listeners. Valkey is an optional bounded cache, not a required security dependency. Gateway API HTTPRoutes and SecurityPolicy protect every sensitive route.

| Entry point | Example | Boundary |
| --- | --- | --- |
| Issuer/token/JWKS | `https://identity.example.com/oauth/token`, `/.well-known/jwks.json` | Public, TLS, rate limited |
| App auth | `https://app.example.com/_skyoauth/login`, `/callback`, `/session`, `/logout` | Registered ApplicationOrigin; app-local cookie |
| Native flow | Issuer `/oauth/authorize`, `/oauth/callback`, `/oauth/confirm` | Issuer-local transaction cookie; no app-cookie sharing |
| App RPC/streams/downloads | App `/rpc/...`, `/events/...`, `/downloads/...` | Envoy -> backend, no SkyOAuth payload hop |
| Auth checks | `envoy.service.auth.v3.Authorization/Check` | Authenticated private Envoy caller |
| Live policy check | `POST /internal/v1/policy/check` | Registered resource-server checker identity |
| Operator API | `/admin/v1/...` | Separate private mTLS authority and local roles |

`ApplicationOrigin` binds one canonical HTTPS origin to one tenant, callback URI, allowed relative return paths and approved API audience IDs. Its global origin ownership is enrolled by instance `security_admin`; a tenant cannot claim another tenant's host. A scoped `client_admin` can narrow permitted routes/audiences but cannot reassign the host/tenant. v0.1 does not implicitly multiplex tenants on the same origin. Multi-tenant applications may serve multiple application organizations inside their one explicitly mapped SkyOAuth tenant; any different mapping needs a separate reviewed protocol.

Resolve browser tenant/provider from the registered origin and `TenantLoginState`, **not** a free `tenant` query or an untrusted forwarded header. At the public ingress, require an allowlisted authority/SNI/route match; SkyOAuth accepts canonical authority only from its authenticated trusted gateway chain. Unknown/ambiguous origin, spoofed Host/Forwarded values or disabled origin denies before redirect. Return locations are normalized same-origin relative paths validated against the stored allowlist; reject protocol-relative URLs, backslashes, traversal and prefix-confusion tricks.

Use host-only `__Host-` cookies with Secure, HttpOnly and Path=/; do not broaden Domain for convenience. An issuer host distinct from the app host does not imply sharing their cookies. The active-provider switch preserves origin and callback registrations.

**Backend identity transport:** bearer calls carry their original SkyOAuth access JWT; cookie calls cause SkyOAuth to return a short-lived signed internal human-session assertion to Envoy for a private, overwritten backend header (§6). Both internal links are authenticated and the backend rejects mixed credentials. RPC failures return structured 401/403, never an IdP HTML redirect; the SPA explicitly navigates to login. An alternative header adapter must preserve the same typed identity semantics and authenticated transport, not infer profiles from a subject prefix.

Cloudflare Tunnel supplies connectivity, not per-route authorization. WAF, rate limits and Cloudflare Access remain separately configured. Do not trust arbitrary `CF-*` or `X-Forwarded-*` outside the configured proxy chain.

## 5. Identity and credential flows

### 5.1 Browser login, login CSRF and opaque session

1. Resolve the registered `ApplicationOrigin`, its tenant and active provider. Validate the relative return location from that registration.
2. Generate state, nonce, PKCE S256 and a server-generated browser-flow secret. Set short-lived `__Host-skyoauth_login` (Secure; HttpOnly; Path=/; SameSite=Lax; no Domain); store only its keyed hash in a `BrowserFlowBinding`. Bind the OIDC transaction to that hash, flow kind, origin, tenant, provider/epoch, exact callback and return path.
3. Redirect to the fixed upstream authorization endpoint. The baseline uses a top-level GET/query callback; a provider requiring another response mode needs an explicit tested profile, not a weaker cookie fallback.
4. At `/_skyoauth/callback`, require **both** correct one-time state and the initiating browser's matching flow cookie, exact registered origin/callback, provider epoch, PKCE and verified ID-token issuer/audience/signature/nonce/time/authentication requirements. A state or transaction ID alone is not browser authentication. Wrong or missing browser binding denies without creating, replacing or linking a session.
5. Resolve a verified provider-subject link to a stable local human principal. Create a `HumanAuthentication` record and a fresh CSPRNG opaque session ticket; persist only its keyed hash, origin/tenant/principal/authentication reference, provider/subject/optional sid, idle/absolute expiry and CSRF verifier. Atomically consume the login transaction and expire its flow binding. Starting a new flow for the same flow-cookie slot invalidates the old one; stale tabs restart rather than bypass binding.
6. Set `__Host-skyoauth_session` with Secure; HttpOnly; Path=/; SameSite=Lax, no Domain. It is not an OAuth token. `GET /_skyoauth/session` returns only safe principal/session metadata and a session-bound CSRF token with no-store.
7. Unsafe cookie calls, including Connect unary POST and logout, require exact Origin plus CSRF. Local logout revokes the session/authentication context. Optional back-channel logout verifies signature/issuer/audience/events/time/replay and uses indexed provider/subject/sid selectors.

A session is usable only before **both** idle and absolute deadlines, on its registered origin/tenant, with live principal/authentication/provider epoch. Throttled last-seen writes must not revive an expired session or extend absolute lifetime; document bounded early idle expiry from coalescing. Verified account linking also requires an initiating-browser-bound transaction and explicit proof/approval; never email-only merging or attacker-supplied callback account reassignment.

Login CSRF, callback injection, redirect URI confusion, OIDC mix-up, session fixation and identity-linking confusion are explicit release threats/tests. PKCE/state/nonce are not sufficient when their transaction is not bound to the initiating browser; see RFC 9700 §§2.1 and 4.7.

Default: discard upstream access/refresh tokens after login. An encrypted server-side provider-token vault is an explicit opt-in for authorized upstream operations; tokens never reach SPA JavaScript. Do not rotate the browser cookie on every ext_authz check or couple normal session lifetime to upstream token rotation.

### 5.2 Native OAuth and issuer-origin confirmation

The Rust CLI is a public client of SkyOAuth, not Zitadel. It uses stable issuer `/oauth/authorize` and `/oauth/token`, a registered generated `client_id`, S256 PKCE and an IP-loopback redirect. Client ID identifies configuration/tenant but does not authenticate a local process. Persistent login is either interactive reauth or an explicitly supported rotating SkyOAuth refresh credential in an OS keychain, never an upstream refresh token or static API key.

**Issuer-origin browser flow:** `/oauth/authorize` resolves the globally unique registered client and its tenant, validates redirect/audience/scopes against registration and audience assignment, creates `OAuthAuthorizationRequest`, and sets `__Host-skyoauth_native` on the **issuer origin** with the same secure host-only attributes and a short transaction lifetime. Its keyed hash binds the native request and upstream OIDC transaction. Upstream authentication returns to the fixed **issuer `/oauth/callback`**, registered on that tenant's HumanProvider, not the app-origin callback. Native and app flow cookies/transaction kinds are never interchangeable.

The issuer callback checks state, the native flow cookie, expected issuer/client/callback, PKCE/nonce, epoch and ID token before storing the verified human principal/authentication on the native request. Rotate the issuer-local flow secret and bind the replacement to that request before confirmation. `/oauth/confirm` requires this bound cookie and completed server-side authentication; a transaction ID, app cookie, URL principal or live upstream SSO alone cannot approve a request. A new native start invalidates the previous native cookie slot; stale/conflicting tabs fail closed and restart.

**Every new loopback authorization requires explicit SkyOAuth approval.** Show the registered client name, account, audience/scopes and exact loopback destination, with approve/deny and a warning that the public client ID does not prove the local program's identity. The confirmation POST requires exact issuer Origin, CSRF, anti-framing, matching rotated flow binding, request digest, principal and unexpired provider epoch. Bind the resulting one-time code to the exact client/redirect/PKCE/audience/scopes/authentication. Only after approval redirect that SkyOAuth code to the loopback listener. Denial/expiry creates no code; consume confirmation state and clear its cookie. Prior consent or existing SSO never auto-approves a new request (RFC 8252 §8.6).

The native client separately checks its own OAuth state and exact callback path, redeems using its PKCE verifier, and closes the loopback listener after success/cancellation/timeout. Codes are transactional and single-use across replicas. Device flow is conditional and requires user-code verification plus equivalent explicit approval/abuse controls; it cannot bypass this interaction. Do not claim native compatibility until conformance passes.

### 5.3 GitHub WIF and proof replay

A GitHub Actions job with `permissions: id-token: write` requests the configured exchange audience, then uses the stable generated source/grant IDs at `/oauth/token`. SkyOAuth verifies that selected source, evaluates the selected grant's eligible bindings, and issues only its bounded direct or delegated credential. The Rust workload provider renews with a fresh assertion; it never logs/persists workload tokens or receives WIF refresh credentials.

Production bindings require immutable owner/repository IDs, explicit `event_name`, ref, environment and workflow identity, plus reusable-workflow identity when used. A default-branch ref/workflow does not establish a safe event. The example is **push-only**, rejecting otherwise-matching `pull_request_target`, `workflow_dispatch`, `issue_comment` and `workflow_run` assertions. GitHub's human `actor` is audit provenance, not a human SkyOAuth login.

Matcher predicates are ANDed. A configured claim absent from verified evidence is a non-match. Omitted optional predicates are unconstrained; required production predicates cannot be omitted, and deleting a predicate is explicit privilege widening. Strings are exact matches, not implicit regex/wildcards.

**Replay policy is a source capability, not a universal toggle.** Default `reusable` permits another otherwise-valid proof exchange inside its lifetime only after fresh policy evaluation/rate limits, producing a new output `jti`. `single_use` is permitted only for locally signature-verified discovery/uploaded-JWKS sources enrolled with an **on-demand assertion** profile and a client/issuer capable of obtaining a fresh signed nonempty `jti` per exchange. Consume a keyed digest of `(tenant, source_id, exact_issuer, verified_jti)` atomically across replicas/grants; exactly one attempt may issue. Missing jti/store failure/replay denies, and a crash may burn the proof. Retain consumption through exp plus skew and digest-key rotation; provider switch/rollback never resets it.

**Kubernetes projected tokens, including TokenReview sources, must use `reusable` in v0.1.** Enrollment/import rejects `single_use` for `kubernetes_token_review` or any projected-service-account assertion profile, even when keys could also be verified locally. Rereading a projected file does not promise a fresh token/JTI on demand; do not force an agent to wait for kubelet rotation after its short-lived SkyOAuth token expires. Generic JWT sources require an explicit tested renewal capability before opting into single-use. A canceled job can leave an issued bearer credential valid until expiry; critical operations use §6.1.

### 5.4 Kubernetes and generic external sources

Use rotated, audience-bound projected service-account tokens, rereading the file on renewal. A `kubernetes_token_review` source stores a stable cluster ID, configured expected issuer metadata, fixed HTTPS API endpoint, versioned CA/fingerprint, narrowly scoped reviewer-credential reference, requested audiences and timeout. Reviewer secrets are externally managed, not plaintext exports. Its fixed private-egress profile permits only the approved endpoint with TLS hostname/CA verification and no redirects.

The required source ID selects exactly one registered verifier. It is not proof of a tenant or cluster. Multiple clusters may share an issuer, so issuer is not a unique lookup key; do not probe clusters until one accepts, use unverified claims to select a server or accept client-supplied endpoint/CA/credentials. Shared signing authorities cannot provide independent cluster isolation.

TokenReview sends explicit `spec.audiences` and requires authenticated success, no error and compatible nonempty returned audiences. Bind returned SA identity/UID and supported bound-Pod evidence to the selected cluster/source. TokenReview returns authenticated user/audience evidence, **not a general claim set or guaranteed verified jti**. Never invent a jti from decoded input for replay enforcement. Policies requiring evidence the adapter cannot attest are rejected; parsed token fields can narrow checks but cannot supply missing positive authorization evidence. Document the supported cluster's time/object-revocation behavior rather than claiming instantaneous revocation. Tests must renew using the same still-valid projected token before rotation, then the rotated token.

Other source kinds:

- `oidc_discovery`: exact issuer, explicitly approved discovery/JWKS egress, algorithm/audience allowlists, bounded refresh/cache/staleness.
- `uploaded_jwks`: exact issuer/audiences/algorithms and a stable tenant-owned `TrustKeyset` parent with public-only versioned keysets and explicit overlap. Multiple versions may be active; conflicting live kid/key combinations deny.

Kubernetes local JWT validation is a separately enrolled mode with explicit stale-object-revocation limits, not fallback from failed TokenReview. Reject unregistered sources, token `jku`/`x5u`/embedded-key trust, `alg=none`, weak substitution, private-key uploads and arbitrary redirects. Bound input sizes, claim complexity, clocks and key refresh. None of these source configurations belongs to a human provider switch.

### 5.5 Upstream provider exchange

Zitadel is the first human adapter, not the canonical API issuer. Compatible, authorized exchange of Zitadel-issued tokens may run server-side after checking actual deployed provider capabilities and subject/actor/audience/scope restrictions. Do not assume arbitrary GitHub/K8s assertions can be exchanged into Zitadel administrator credentials.

Normalize downstream credentials to SkyOAuth's public profile. An upstream token may be retained in the explicit encrypted vault for an approved upstream operation, never passed through as the default application credential. Upstream administration uses a separately isolated, restricted service adapter; it is neither SkyOAuth operator authority nor a target of public WIF delegation.

### 5.6 Grant modes and dormant impersonation

- **Direct workload (required):** the grant's workload actor becomes `sub`; target service is null; audience/scope/resource ceilings still apply.
- **Delegation (required):** the preapproved service becomes `sub`, workload becomes RFC 8693 `act.sub`; retain source/run provenance and effective revision in audit. The single-proof request is the explicit extension in §5.7.
- **True impersonation (conditional):** high-risk mode omitting target-visible actor; not required for v0.1 and never a fallback for another mode.

An unsupported impersonation grant has a defined write path: authorized create/import accepts it **only with `status: disabled` and `activation_state: requires_reapproval`**. Reject an enabled/approved unsupported record rather than silently activating or pretending it is delegation. This permits preservation tests through normal APIs, not direct database inserts. Store its full desired constraints/provenance. A release gaining the capability leaves that record disabled and requiring approval; feature availability, import, ordinary PATCH or provider migration cannot enable it.

Activation, only after ADR-006 includes the mode, is a dedicated operation requiring enabled capability, a separate instance-security approval bound to the exact grant revision/target/ceilings, and a tenant `trust_admin` activation commit. The approving operator must differ from the activating operator. Edits invalidate approval; upgrades/downgrades cannot reuse an approval for a different capability/policy revision. An unsupported binary must refuse active impersonation configuration at deployment preflight until an explicit disable operation has occurred. No migration changes dormant records.

### 5.7 Exchange selection, overlapping bindings and scope

Both form-encoded profiles require exactly one `skyoauth_trust_source`, `skyoauth_grant_id` and API `audience`, with optional `scope`. The two selectors are nonsecret SkyOAuth extensions containing **generated immutable IDs**, never tenant-local display names (§7.4).

1. Load the selected source and grant as untrusted candidate records, require the same tenant and expected grant mode; reveal no cross-tenant existence details on failure.
2. Verify the assertion only at that source. The grant determines the candidate actor/target, but an ID does not prove that actor.
3. Evaluate enabled bindings for that source **that map to the selected grant's actor and are explicitly in its `allowed_binding_ids`**. At least one must match verified evidence. Matching bindings for other actors do not make the request ambiguous or authorize this grant.
4. Bindings in v0.1 are identity predicates, not independent resource grants. If several eligible bindings match the same actor, use stable ID ordering to select one for provenance; their permissions are not unioned. Invalid cross-actor references are rejected at configuration time. The grant, target ceiling, audience assignment and requested scope/resources determine authorization.
5. Validate current tenant/principal/source/binding/grant/service status, registered audience assignment and all ceilings. Emit the selected binding and complete immutable decision dependencies in the policy revision/audit.

This permits repo-wide and deployment-specific bindings to coexist without an accidental denial or an unauthorized actor fallback. Grant selection never accepts arbitrary subject, target, tenant or mode overrides.

| Profile | Grant type | Input proof | Output identity |
| --- | --- | --- | --- |
| Direct | `urn:ietf:params:oauth:grant-type:token-exchange` | `subject_token`, type `urn:ietf:params:oauth:token-type:jwt` | Verified workload `sub`; no `actor_token` accepted |
| Delegation | `urn:skyoauth:params:oauth:grant-type:service-delegation` | `actor_token`, type `urn:ietf:params:oauth:token-type:jwt` | Grant's service `sub` and workload `act`; no `subject_token` accepted |

RFC 8693 distinguishes subject and actor proofs (§2.1/Appendix A). A single workload assertion is not a service subject token. The private extension uses administrator-owned target authorization and is **not advertised as standard two-token delegation** or an IANA-registered grant. The upstream exchange adapter is separate.

Omitted scope uses only the grant's explicit nonempty `default_scopes`, a subset of all applicable ceilings; otherwise `invalid_scope`. Explicit empty/excessive scopes deny rather than silently broaden or trim. Duplicate parameters, missing selectors, profile mismatch, unsupported resource or requested token type deny. Initially support one exact registered API audience per credential. Success returns access_token, Bearer token_type, expires_in, explicit scope and `issued_token_type=urn:ietf:params:oauth:token-type:access_token`, no-store and no WIF refresh token.

The following is a **post-create export fragment**, not initial create input. IDs illustrate generated persisted values; readable names are tenant-local labels. The referenced tenant, audience assignment, workload and service already exist. Provider state is deliberately absent: this is a WIF-role document, not a combined provider/WIF import.

~~~yaml
tenant_id: ten_018f31a6d2094aa4b28c119be13b0472
trust_sources:
  - id: trust_81dbec63208c4a88aef72b5c05d68419
    name: github-production
    kind: oidc_discovery
    issuer: https://token.actions.githubusercontent.com
    audiences: [https://identity.example.com]
    allowed_algs: [RS256]
    assertion_profile: on_demand_jwt
    replay_mode: single_use
  - id: trust_39e7e4e62011420cab93e513277cae9b
    name: partner-production
    kind: uploaded_jwks
    issuer: https://ci.partner.example
    keyset_id: keyset_18a134a4f12047d8ba5d27914b2406dc
    audiences: [https://identity.example.com]
    allowed_algs: [ES256]
    assertion_profile: reusable_jwt
    replay_mode: reusable
  - id: trust_53ca1d3069b64d10b4e247591fa72163
    name: k3s-production
    kind: kubernetes_token_review
    issuer: https://kubernetes.default.svc.cluster.local
    cluster_id: cluster_40ef5317f4b74fa3bd25763b9d90a8c1
    api_server: https://k3s-api.internal.example:6443
    ca_bundle_ref: ca_k3s_production
    reviewer_credential_ref: secretref_k3s_reviewer
    audiences: [https://identity.example.com]
    assertion_profile: projected_service_account
    replay_mode: reusable
keysets:
  - id: keyset_18a134a4f12047d8ba5d27914b2406dc
    name: partner-production
    versions:
      - id: keyver_5101ab993e8c439dbfca9456bd9053b2
        public_jwks_ref: public-jwks/partner-v1.json
bindings:
  - id: binding_a89023ed51e549c99928b83663528e52
    name: release-pipeline
    source_id: trust_81dbec63208c4a88aef72b5c05d68419
    profile: github_production
    match:
      repository_owner_id: "123456"
      repository_id: "456789"
      event_name: push
      ref: refs/heads/main
      environment: production
      workflow_ref: acme/platform/.github/workflows/deploy.yml@refs/heads/main
    principal_id: wld_206f380172eb482783d6dfbe9c0ae418
grants:
  - id: grant_d50e0a3bd52e4f26a3ad452017d64f09
    name: release
    actor: wld_206f380172eb482783d6dfbe9c0ae418
    allowed_binding_ids: [binding_a89023ed51e549c99928b83663528e52]
    act_as: svc_43738ce105c748278cd73d1b30617fc8
    mode: delegation
    audience: control-plane-api
    scopes: [deployments.create, workflows.read]
    default_scopes: [workflows.read]
    constraints:
      version: 1
      authorization: allowlist
      projects: [platform-production]
      environments: [production]
    max_lifetime_seconds: 300
~~~

Public-JWKS/CA references resolve to validated versioned contents at enrollment, never client-selected fetches. The instance resource-server registry must already authorize this tenant for `control-plane-api`. The wire request uses the IDs returned by creation/export, form-encoded (shown decoded here):

~~~text
grant_type=urn:skyoauth:params:oauth:grant-type:service-delegation
actor_token=<fresh GitHub assertion>
actor_token_type=urn:ietf:params:oauth:token-type:jwt
skyoauth_trust_source=trust_81dbec63208c4a88aef72b5c05d68419
skyoauth_grant_id=grant_d50e0a3bd52e4f26a3ad452017d64f09
audience=control-plane-api
scope=deployments.create workflows.read
~~~

## 6. Explicit credential profiles and backend verification

SkyOAuth uses a **private, versioned JWT profile**, not an incomplete RFC 9068 claim. Access JWTs have protected header `typ=skyoauth-access+jwt`; internal gateway assertions use `typ=skyoauth-internal+jwt`. These are proposed private identifiers, not registered media types. Do not emit/accept `at+jwt` as a SkyOAuth profile: RFC 9068 requires, among other fields, client_id, which WIF does not invent from a source ID. Native tokens do carry their actual registered client_id for local attribution. Any future RFC 9068 support needs a separate complete conformance profile.

All credentials require a verified signature/allowed algorithm/kid, exact issuer and **one registered audience**, iat/nbf/exp with bounded TTL/skew, unique jti, explicit scope, signed `skyoauth_tenant`, `skyoauth_profile`, `skyoauth_profile_version=1`, `skyoauth_policy_revision` and `skyoauth_constraints`. The protected typ, signed profile and expected ingress route jointly select validation rules. Never infer a profile from a `usr_` prefix, missing grant, presence of `act` or an untrusted request header. Reject unknown versions, contradictory claim sets and a profile not allowed by the resource-server registration.

| Signed profile | Protected typ / ingress | Required identity and authorization evidence |
| --- | --- | --- |
| `wif` | `skyoauth-access+jwt`, bearer path | Workload or delegated service sub, grant ID, direct/delegation mode, binding-backed policy revision, `authorization: allowlist` constraints; delegation additionally requires workload act |
| `human_cli` | `skyoauth-access+jwt`, bearer path | Human sub, actual OAuth client_id, opaque `skyoauth_authentication` reference, auth_time, HumanAccessPolicy revision and explicit `authorization: backend_rbac` constraints; no WIF grant/mode/act |
| `human_session` | `skyoauth-internal+jwt`, authenticated gateway-only assertion header | Human sub, application-origin ID, opaque authentication and session references, auth_time, HumanAccessPolicy revision and `authorization: backend_rbac` constraints; request binding; no WIF grant/mode/act or invented client_id |

`HumanAccessPolicy` is a tenant/audience-scoped, provider-independent record for exactly one OAuth client or ApplicationOrigin. A scoped `client_admin` sets its scope/TTL/authentication ceilings within the instance audience assignment. Issuance snapshots those records plus client/origin registration and relevant revisions; a `HumanAuthentication` record links the verified login to provider/epoch without requiring clients to know a provider ID. CLI scopes intersect approved requested scopes, client policy and audience assignment. Browser scopes derive from the registered origin's policy and selected route audience, never browser-supplied identity/scope headers.

**Human resource authorization is explicit, not an omitted claim.** Human profiles carry `{"version":1,"authorization":"backend_rbac"}`; they make no project/environment membership claim. The backend must resolve the resource's SkyOAuth tenant, match signed tenant/audience, check scope, then evaluate its current human membership/RBAC. No membership or missing tenant mapping denies. These profiles are accepted only on routes registered to support them. The WIF profile cannot use backend_rbac mode or omit allowlists; a human token cannot masquerade as delegated WIF.

A conceptual delegated WIF payload, with protected `typ=skyoauth-access+jwt`:

~~~json
{
  "iss": "https://identity.example.com",
  "sub": "svc_43738ce105c748278cd73d1b30617fc8",
  "act": {"iss": "https://identity.example.com", "sub": "wld_206f380172eb482783d6dfbe9c0ae418"},
  "aud": "control-plane-api",
  "scope": "deployments.create workflows.read",
  "skyoauth_tenant": "ten_018f31a6d2094aa4b28c119be13b0472",
  "skyoauth_profile": "wif",
  "skyoauth_profile_version": 1,
  "skyoauth_mode": "delegation",
  "skyoauth_grant": "grant_d50e0a3bd52e4f26a3ad452017d64f09",
  "skyoauth_policy_revision": "polrev_8526ec2d468e4adc94c9343608ee873f",
  "skyoauth_constraints": {"version": 1, "authorization": "allowlist", "projects": ["platform-production"], "environments": ["production"]},
  "iat": 1794780000,
  "nbf": 1794780000,
  "exp": 1794780300,
  "jti": "jti_d8139a27124d4ea3a4835a4cd30a09de"
}
~~~

A conceptual CLI human payload with the same private access typ, but a different mandatory profile:

~~~json
{
  "iss": "https://identity.example.com",
  "sub": "usr_f81b224cda9548b382541b16f823ac5e",
  "aud": "control-plane-api",
  "client_id": "client_6e94e21f46ba4eb1b8bd5bec24070f14",
  "scope": "workflows.read",
  "skyoauth_tenant": "ten_018f31a6d2094aa4b28c119be13b0472",
  "skyoauth_profile": "human_cli",
  "skyoauth_profile_version": 1,
  "skyoauth_authentication": "hauth_594948a2cc4b4ca19c5ca2d52bc7536d",
  "skyoauth_policy_revision": "polrev_97fc45cb6fe84d9d8df13c2981f9ca3e",
  "skyoauth_constraints": {"version": 1, "authorization": "backend_rbac"},
  "auth_time": 1794780000,
  "iat": 1794780000,
  "nbf": 1794780000,
  "exp": 1794780300,
  "jti": "jti_43ff5f1289c94db49dcb50d0e7a53375"
}
~~~

A human-session assertion has the common claims and human constraints above, `skyoauth_profile=human_session`, `skyoauth_application_origin`, `skyoauth_authentication`, `skyoauth_session` (opaque internal references, never cookie hashes/tickets), and `skyoauth_request` binding method, canonical authority and normalized path/query. It omits client_id and is minted only by SkyOAuth after the live session/Origin/CSRF check. TTL is at most 30 seconds and cannot exceed session/authentication deadlines. Envoy removes client-supplied assertion headers; the backend accepts it only on the authenticated gateway channel for the bound request. Public bearer ingress rejects internal assertions. This is not a signature over the application body and does not remove backend operation/resource validation. The assertion is never returned to SPA JavaScript.

For WIF allowlists, values within a dimension are alternatives and different dimensions are ANDed with tenant/audience/scope/RBAC. Missing/empty required dimensions, unknown constraint fields/versions or wrong authorization mode deny. A grant ID alone is insufficient. Human backends use the explicitly different schema above, not an undocumented exemption from A30.

Signing keys are asymmetric, bridge-owned, isolated and versioned with kid/overlap. Retain retired public keys through maximum issued TTL plus skew; no upstream signing keys and no plaintext key export. M1 defines metadata, **M2/T20 implements signer/JWKS**. Provider migration does not rotate keys.

### 6.1 Revocation and private live operation check

Offline short-lived access JWTs retain residual validity until expiry after a grant/policy/session change; default maximum access TTL is five minutes. Browser authentication is checked live at the gateway; an already-issued internal assertion has only its bounded residual lifetime. Do not promise cancellation of previously authorized operations or instantaneous Kubernetes object revocation.

`POST /internal/v1/policy/check` is private. Authenticate the caller against **ResourceServerChecker**, bound to the registered resource-server audience and explicit tenant set, not against the token's delegated subject/service. Direct workload credentials with no target service are fully supported. The caller sends exactly one access JWT or internal assertion plus canonical action/resource coordinates; request binding is retained for internal assertions. Input is bounded and never logged as token material or application payload.

Look up the persisted `ResourceAction` for that resource server: required scopes, supported profiles, required resource dimensions and whether live checking is mandatory. Verify the complete profile, audience/tenant assignment, current principal and immutable decision dependencies. WIF checks source, chosen binding, grant and optional target service; human checks HumanAccessPolicy, client/origin, authentication/provider epoch and session where applicable. Superseded/invalidated authorization revisions deny and require renewed credentials; never reinterpret an old token under broader policy. Unknown action/resource/caller, wrong tenant/audience or store/checker outage denies. A resource server cannot use another audience's checker identity.

Return request-bound allow/deny, checked revision and decision ID with no-store, not a new token or reusable blanket permission. The backend still applies canonical resource ownership and RBAC, with no positive caching for critical calls. Checks begun after committed revocation deny; a subsequent revocation cannot undo already-authorized work. Streams require bounded duration, periodic checks or cancellation. M2/T26 delivers WIF support; M3 adds human-session checks and M4 human CLI checks before those profiles ship.

## 7. Persistence, ownership and administrative writes

PostgreSQL is authoritative for all stable authority and one-time state. WIF, audience, client/origin and operator records cannot cascade-delete through HumanProvider. Use immutable history, optimistic concurrency, atomic audit and conservative cache invalidation. Store failures never expand privilege. Encrypted database backups differ from redacted configuration exports; neither ordinary YAML nor logs may expose private keys, reviewer/operator secrets, cookies, proof tokens or refresh credentials.

### 7.1 Tenant partition and instance-owned audience authority

`Tenant` is the administrative policy partition, explicitly mapped to application organization/resource ownership. Stable generated IDs are globally unique; composite tenant/object foreign keys prevent cross-tenant references. Sources/keysets/bindings/services/grants/clients/origins/human policies are tenant-owned. External issuer strings are not unique: different tenants can register GitHub, and independently keyed clusters can share one issuer. A source selector chooses only a candidate verifier; verified evidence plus the selected same-tenant grant establishes authority.

**Audience strings are not tenant-controlled free namespaces.** Instance `security_admin` creates a `ResourceServer` with one globally unique exact audience and explicitly grants tenants access through `AudienceTenantAssignment` records specifying allowed profiles/scopes and constraint schema. Tenants may not self-assign an existing audience or create a competing registration. Service ceilings, WIF grants, OAuth clients, ApplicationOrigins and HumanAccessPolicies reference registered audience IDs and are refused if no active same-tenant assignment exists. Recheck at issuance and live policy checks; a tenant admin cannot mint for another tenant's API merely by spelling its audience/project name.

The resource server separately owns checker identities and action-to-scope/resource/profile mappings, administered through instance-scoped endpoints. `ServiceIdentity` is a possible **token subject**, not the API receiver. Multiple actors or direct-mode tokens can call the same resource server without becoming its checker authority.

For a shared multi-tenant audience, every backend resource is mapped to a canonical SkyOAuth tenant. The backend must compare that owner with the signed tenant before scopes/resources/RBAC; missing mapping denies. Instance assignment is defense in depth, not permission to omit tenant verification. Audience assignments/actions/checker identities and client/origin policy are stable through a human provider switch and included in snapshots.

### 7.2 Independent operator roles, provisioning and recovery

Operator authentication uses independent `adm_*` identities and registered mTLS public credentials rooted in deployment trust. Check the active local credential and role on every call; a certificate alone is insufficient. OIDC roles/groups/emails, human sessions and WIF credentials never grant operator authority. Operator keys are operational trust anchors, not application API secrets.

| Role | Explicit rights |
| --- | --- |
| Instance `security_admin` | Create/disable tenants; enroll operators and scoped roles; register/assign resource-server audiences, checker identities/action registries and canonical application-origin ownership; manage signer/recovery policy; approve conditional high-risk activation. No implicit tenant role inheritance. |
| Tenant `trust_admin` | Create workload/service principals and service identities atomically; manage source/keyset/binding/grant policy within instance audience ceilings; activate an approved supported grant. Cannot create human principals or self-assign API audiences. |
| Tenant `client_admin` | Create/update registered public OAuth clients, assigned-origin return/audience configuration and HumanAccessPolicies within assignments. Cannot reassign origin ownership or change active providers/WIF grants. |
| Tenant `provider_admin` | Configure/test inactive human providers; controlled human enrollment/verified subject links; switch/rollback plans. Cannot edit WIF, audience assignments, clients or operator roles. |
| Tenant `auditor` | Redacted tenant configuration/audit reads; separate instance audit authority where explicitly granted. |

Bootstrap is a deployment-local command/Unix socket operation, never public enrollment. Atomically enroll an initial security_admin public credential and separate offline recovery public key, audit, then durably close bootstrap. Restart or an empty config cannot reopen it. M1 commands live under the existing **service binary's operator/bootstrap subcommands**, independent of the M4 application CLI; an authenticated private operator client can perform configuration writes without native human OAuth.

The first operator can then create a tenant, enroll/assign its scoped operators, register an API audience and tenant assignment, create/assign an application origin, register a CLI client and human policy, create workload/service principals, and configure providers/sources/bindings/grants. A single operator may hold multiple explicitly assigned roles for a small deployment, but no role implicitly inherits another. Initial human-provider activation uses the same switch operation from a null pointer. This provides a complete post-bootstrap write path with no manual database inserts.

Break-glass uses the restricted local interface plus the independent recovery key over a short-lived, single-use challenge bound to operation/arguments/expected revision. Permit bounded operator restoration or the same validated provider-switch/rollback operation only, not arbitrary WIF edits, audience reassignment or token minting. Consume challenges durably, audit/alert and rotate recovery keys after use. Rehearse while the human IdP is down or account linking is broken. Database/signer disaster recovery remains separate. Restore procedures preserve bootstrap-closed and consumed state or quarantine issuance until outstanding state can no longer be replayed.

### 7.3 Provider changes cannot bypass the switch transaction

`TenantLoginState.active_provider_id` is the sole active-provider pointer. HumanProvider has no independently writable active flag. All GET/export representations of active state are **read-only observations**. Ordinary provider PATCH, deletion/disable of the active provider, GitOps imports and config reloads must reject attempts to change the pointer, auth epochs or active-provider issuer/client/callback/authentication semantics. Creating/testing inactive candidates is permitted. A plan may cover such authentication-critical changes, activation from null, switch, disable or rollback; only its authorized commit transaction updates login state and advances epochs atomically.

Rollback uses the same guarded transaction with fresh monotonic epochs. No import, including one submitted by an operator holding every role, can replace it. Auth state is never retained accidentally because a generic active flag changed.

GitOps documents are role-scoped. A combined bundle is accepted only when the actor has **every** role needed for every mutation and its plan passes the same validation; otherwise reject the whole bundle, never partially apply or ignore unauthorized sections. Active-provider observations are not writable fields and a proposed change is always rejected in an ordinary import. Separate provider, client and WIF documents are recommended; the example in §5.7 is WIF-only.

### 7.4 Generated selectors and create-then-reference workflow

All object IDs and public OAuth client IDs are server-generated opaque random identifiers. Tenant-local `name` is a human label unique only within its entity type/tenant, never an exchange selector or globally reserved name. The prefixes in examples indicate type, not authority. A client cannot choose a global ID on initial create or probe another tenant through an import collision.

Creation omits ID and supplies a tenant-scoped name; the authorized API returns the generated ID/revision. Provision in dependency order (tenant/audience assignment, principals/source/keyset, binding, grant/client policy), or use a validated importer with tenant-local manifest references that resolves to generated IDs and returns a persistent mapping. Export that mapping and place returned source/grant IDs in job/client configuration. Creating two tenants' `github-production` sources yields different IDs without name collision.

Updates specify the existing ID and expected revision within the authorized tenant. Redacted exports preserve IDs on same-instance reconciliation; privileged full restore preserves them only into the intended empty/restored authority after ownership/provenance validation. Ordinary tenant import cannot claim an arbitrary missing global ID or rebind it. Reapplication is tenant-local reconciliation, not recreation. Once deployed, clients retain their IDs across provider migration; the one-time create-then-reference step does not violate the zero-reconfiguration goal.

## 8. Human-provider migration runbook

1. Authenticate independently. Snapshot issuer metadata, tenant/resource-server/audience assignments/actions/checker identities, client/origin/human-policy registrations, all verifier configurations/keysets, principals/bindings/grants/activation state, policy decision fixtures, public key metadata and replay invariants. Do not export proof/secret material.
2. Register/test an inactive replacement provider with fixed app and issuer-native callbacks; prepare verified account linkage and prove operator/recovery availability independently of upstream admin accounts.
3. Create an immutable provider-switch dry-run plan against expected login/config revisions. Reject any attempted WIF/audience/client/origin/operator/gateway/signer mutation; concurrent relevant changes require replan. A generic PATCH/import is not an alternate route.
4. Commit only provider login/mapping configuration and fresh human auth epochs atomically. Invalidate affected browser/native flow bindings, sessions/authentication contexts, pending requests/codes and optional refresh families. Preserve WIF configuration and consumed assertions. Offline human JWTs retain only their documented short TTL; live checks reject invalidated contexts.
5. Reauthenticate humans with stable principal/RBAC mappings where explicitly verified; unmatched users require controlled enrollment. Existing client_id, origin, audience and library configuration remain unchanged.
6. Reuse prebuilt **TypeScript SPA and independent Rust CLI artifacts** (record hashes), existing GitHub job, uploaded-JWKS workload and two independently keyed shared-issuer Kubernetes clusters. No rebuild/package upgrade/YAML/CA/reviewer/source/grant/audience change. Exercise direct/delegated profiles, human profile verification and both supported replay modes; projected Kubernetes renewal stays reusable.
7. Compare pre/post allowed and denied decisions, IDs/revisions and audit. Roll back through the guarded plan with fresh epochs, never whole-DB rollback over independent policy changes or resurrection of consumed credentials. Unsupported impersonation stays disabled; single-use tests obtain fresh proofs, never require a consumed one to become valid.

Repeat conformance after schema/chart/protocol/SDK upgrades. Human-provider downtime can block fresh human login but not valid independent WIF or operator recovery, except where shared SkyOAuth infrastructure is unavailable.

## 9. Security and abuse model

Threats include compromised workflows/runners, issuer/key/cluster confusion, assertion theft/replay, cross-tenant audience issuance, subject-versus-resource-server confusion, profile substitution, signer/operator compromise, login CSRF and callback injection, OIDC mix-up, redirect URI confusion, identity-linking confusion, native-client impersonation, session fixation, CSRF/XSS, unprotected routes, header spoofing, SSRF, generic-provider-write bypass, credential resurrection and stale streams.

Mitigations are explicit: instance audience assignments plus canonical backend tenant/RBAC checks; typed signed profiles with distinct human/WIF schemas; grant-directed source-bound evidence; restricted verifier egress; browser-bound state/nonce/PKCE and separate issuer-native confirmation cookies; one-time codes/consumption across replicas; scoped independent operator writes and exclusive switch commits; no token logging; fail-closed stores/private endpoints; short TTLs with critical live action checks and bounded streams. Every claim has positive and negative release fixtures in the task plan.

Residual limits: zero static application secrets does not mean zero privileged keys. SkyOAuth signer/operator/recovery trust and reviewer/upstream service credentials need protection. Compromised human IdPs can impersonate mapped application users, but not independently rewrite WIF/operator/audience authority. HttpOnly limits token extraction, not authenticated actions by same-origin malicious JavaScript. Root/runtime/database compromise remains separate high-impact risk. Authorization cannot retroactively undo an already accepted operation.

## 10. Required clients and repository layout

### 10.1 Two first-class libraries

| Deliverable | Package / home | Primary consumer | Gate |
| --- | --- | --- | --- |
| TypeScript SPA library | npm `@skyoauth/client`, `clients/typescript/` | Framework-neutral SPAs; React/Connect adapters | M3 |
| Rust client library | Cargo `skyoauth-client`, Rust import `skyoauth_client`, `clients/rust/` | User-owned CLIs; workload tooling | WIF M2; native M4 |
| Reference Rust CLI | `skyoauth-cli`, `cli/` | Thin consumer of the Rust library | Native M4 |
| Deployment operator commands | Existing `skyoauth-service` binary subcommands | Local bootstrap/recovery and private operator configuration | M1, no M4 dependency |

The similarly named npm and Cargo libraries are intentional language-specific distributions in separate registries, not competing packages or interchangeable imports. Both are required. Browser code never gets a token getter, native listener or operator key. Rust consumers do not depend on React, a JS runtime, frontend assets, service internals or PostgreSQL.

### 10.2 TypeScript: SPA-first

Evolve the existing package instead of adding a second browser core. Provide session/principal state, top-level login, CSRF-protected logout, cancellation and authenticated transport. `@skyoauth/client/react` and `/connect` are explicit entry points with optional peer dependencies excluded from the framework-neutral core. Runtime/type exports agree; the core bundles without Node built-ins/polyfills.

Authenticated targets are configured same-application-origin HTTPS routes with no URL userinfo. Validate before attaching CSRF; use Fetch same-origin mode/credentials and reject redirects for authenticated API fetches. Caller options cannot override these boundaries or add bearer authentication. Only explicit top-level login follows server-managed upstream redirects. Narrow explicit loopback development settings must not weaken production. Injected fetch is trusted integration code, not permission to bypass URL/header checks.

Keep CSRF/session metadata in bounded memory, clear on logout/account change/invalidation, and send only credential-free cross-tab invalidation signals. No access/refresh tokens in localStorage, sessionStorage or IndexedDB. Distinguish unavailable/cancelled/forbidden from unauthenticated; no automatic mutation replay on 401 or after login. Streaming/download cancellation remains end-to-end without SkyOAuth buffering bodies.

The bootstrap arbitrary-baseUrl `health()` helper is unauthenticated utility code, not permission to attach session capabilities to that URL. Test that an off-origin health base cannot become an authenticated target. Future TypeScript workload support is a separate nonbrowser surface and not a substitute for the SPA library. Validate packed npm artifacts in an actual browser, not only Node fetch mocks.

### 10.3 Rust: reusable CLI library

`clients/rust` is a planned Cargo member publishing `skyoauth-client`, consumed by `cli/` and an independent example. Expose typed configuration/errors, redacted credential wrappers, cancellation/timeouts and provider traits. Document feature boundaries for native OAuth, system-browser launch, loopback, optional keychain and GitHub/Kubernetes integration; test minimal/default feature sets, not just all-features.

Use an external system browser, S256 PKCE/state and §5.2 confirmation. Bind an ephemeral listener only to an IP loopback address; choose the port before authorization and match the exact chosen redirect on redemption. Bound callback lifetime/path, reject wrong state and clean up on cancel/timeout. No embedded login webview, password or static-client-secret fallback.

Attach credentials only to configured HTTPS API origins/audiences; never log or forward them across origin redirects. Access-token cache is memory-only. Optional rotating refresh uses the OS credential store; unavailable secure storage cannot silently fall back to plaintext. Workload renewal reacquires fresh on-demand proofs or rereads reusable projected tokens and never gets WIF refresh credentials. Library owns protocol; CLI owns terminal UX/exit codes.

Test the native crate/consumer on Linux, macOS and Windows, including loopback/cancellation and supported keychain adapters where included. Publish MSRV, TLS/runtime/features/platform policy separately from Linux server deployment support. Package and compile an independent consumer without private workspace-path assumptions.

### 10.4 Preserve the landed bootstrap

PR #2 at `8f81df23efd4c4a0cfe522f711a9ca56f294aab1` established `service/`, the root Cargo workspace, `clients/typescript/` and CI. Retain them. Add `clients/rust`/`cli` when implemented; start server trust/policy/issuer/etc. as modules under `service/src`, extracting `crates/` only for justified reuse/isolation. Do not duplicate a service under `crates/server` or keep stale `packages/*` paths as another authoritative layout.

Preserve bootstrap tests/coverage and docs-only behavior. Each implementation adding/moving a member, entry point or package updates manifests, exports, lockfiles, CI paths/jobs, packed-consumer tests and README together. This docs-only PR neither moves bootstrap code nor claims empty crates/auth handlers exist. M1 operator subcommands do not require M4 native auth. Versioned profile fixtures and unchanged prebuilt SPA/Rust consumers prove migration compatibility without conflating credential models.

## 11. Roadmap

| Stage | Deliverable | Gate |
| --- | --- | --- |
| Bootstrap, landed separately | Rust service, TypeScript health helper, workspace/CI | Foundation, not authentication completion |
| M0 — Contracts | Profiles, audience/origin/admin ownership, source/grant/ID semantics, client ADRs, threat/test matrix | No unresolved security semantics in examples |
| M1 — Persistent authority | Full schema, resource-server/action/tenant assignments, client/origin provisioning, trust/grants, independent operator writes/bootstrap/recovery | Complete authorized create path, ownership and restore/one-time-state tests |
| M2 — WIF/bearer | Signer/JWKS, direct/delegated exchange, Rust workload library, bearer Envoy, WIF live action checks | GitHub/k3s → Envoy → API without human IdP/static app secrets; fixed replay outcomes |
| M3 — Browser | Origin-resolved browser-bound OIDC, sessions/internal human profile, human-session live checks, required TypeScript SPA/adapters | Packed browser library, login-CSRF/profile/transport tests, no payload hop |
| M4 — Native | Issuer-local callback/confirmation, reusable Rust native crate/reference CLI, human CLI profile/live checks, optional upstream exchange | Independent native consumers/platforms; no silent approval, stable migration |
| M5 — Migration/hardening | Exclusive switch tooling, all-source invariance, unchanged client artifacts, recovery/deployment/release process | No client change and no WIF/audience/client reset; all mandatory tests |
| v0.1 | M0–M5 and both client libraries, direct and attributed delegation | Versioned contracts and conformance suite |
| Conditional/later | Device/refresh options, true impersonation, other gateways/issuers, expanded admin UI, cloud STS, TypeScript workload helpers | Separately approved; not substitutes for required controls |

## 12. Decisions requiring ADR ratification

The proposed defaults now explicitly specify audience authority/resource-server identity, human versus WIF profiles/private token typing, application-origin routing, browser-bound native callbacks, exclusive provider-switch writes, complete operator provisioning, generated-ID lifecycle, grant-directed binding selection, dormant impersonation activation and source-capability replay restrictions. ADRs also ratify signer/backend transport details, optional device/refresh/vault support and exact packaged client feature matrices. Changing a decision requires synchronized schema/examples/tasks/tests, not an implementation shortcut.

## 13. References

- [Architecture tasks and release gates](skyoauth-tasks.md)
- [Bootstrap PR #2](https://github.com/skyoauth/skyoauth/pull/2) and [landed tree](https://github.com/skyoauth/skyoauth/tree/8f81df23efd4c4a0cfe522f711a9ca56f294aab1)
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html): subject/actor exchange semantics and act claim
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): OAuth security, browser-bound transactions, mix-up/redirect/CSRF defenses
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html): external browser, loopback and native-client interaction
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html): explicit JWT typing and validation separation
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html): at+jwt/client_id requirements; SkyOAuth instead specifies a private profile above
- [Fetch Standard](https://fetch.spec.whatwg.org/): mode, credentials and redirects; SPA policy applies stricter target/header rules
- [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) and [reusable workflow identity](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)
- [Kubernetes TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) and [projected service-account rotation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Envoy Gateway external authorization](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
- [Zitadel token exchange](https://zitadel.com/docs/guides/integrate/token-exchange): verify deployed provider/version capabilities
