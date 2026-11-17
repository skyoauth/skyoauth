# SkyOAuth — Architecture, security model, and roadmap

> **Status:** proposed design for review. This document specifies project requirements, not implemented authentication. The bootstrap supplies a Rust service and a TypeScript health client. See [skyoauth-tasks.md](skyoauth-tasks.md) for interfaces, schema, milestones and release tests.

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

### 1.3 Bounded release scope and workload-first delivery

v0.1 still requires direct/delegated WIF, opaque SPA sessions, both client libraries, usable native login/renewal and zero-reset human-provider migration. It does **not** require active true impersonation, device flow, an admin UI, cloud STS, alternate gateways, provider-token exchange or a general enrollment/invitation product. Dormant impersonation storage is a preservation rule, not an activation subsystem (§5.6).

The logical schema is specified together, but implementation is split: **M1a** delivers workload principals/trust/grants, tenant/audience/checker authority, independent operator/bootstrap/recovery and durable replay; **M2 can ship its usable WIF slice after M1a**. **M1b**, completed before M3, adds human providers/enrollment, origin/routes/client policy, browser/native/refresh state and the sole provider-transition primitive. M1b can run alongside M2; human tables, native approval UX and optional features do not block the first workload token. Tasks §9 assigns the boundary explicitly.

A small installation provisions one explicit tenant and may assign several scoped roles to one operator. Tenant IDs, audience ownership and isolation checks apply even to a single-tenant installation. Tenant-management UI and self-service tenant creation are not required. Any future single-tenant-only distribution is a separate reviewed scope choice, not a reason to omit tenant checks from credentials that already carry them. Full v0.1 acceptance remains stronger than the earlier usable M2 milestone.

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
  C -->|bearer API call| EDGE
  G -->|bearer API call| EDGE
  K -->|bearer API call| EDGE
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

Isolate **public access-token** signer keys/permissions from public handlers and operator/reviewer credentials. That signer can be separately deployed or use KMS/HSM. The gateway's internal assertions instead use a distinct local signing key and private verifier set (§6.2), never the public issuer key. No client library replaces server-side enforcement.

## 4. Deployment, origins and traffic paths

Baseline: Rust/Axum + Tokio, PostgreSQL, two or more stateless replicas, public HTTP via Envoy, separate authenticated private gateway/policy/operator listeners. Valkey is an optional bounded cache, not a required security dependency. Gateway API HTTPRoutes and SecurityPolicy protect every sensitive route.

| Entry point | Example | Boundary |
| --- | --- | --- |
| Issuer/token/JWKS | `https://identity.example.com/oauth/token`, `/.well-known/jwks.json` | Public, TLS, rate limited |
| App auth | `https://app.example.com/_skyoauth/login`, `/callback`, `/session`, `/logout` | Registered ApplicationOrigin; app-local cookie |
| Native flow | Issuer `/oauth/authorize`, `/oauth/callback`, `/oauth/confirm` | Issuer-local transaction cookie; no app-cookie sharing |
| App RPC/streams/downloads | App `/rpc/...`, `/events/...`, `/downloads/...` | Envoy -> backend, no SkyOAuth payload hop |
| Auth checks | `envoy.service.auth.v3.Authorization/Check` | Authenticated private Envoy caller |
| Live policy check | `POST /internal/v1/policy/check`; `/internal/v1/policy/recheck-session`; `/internal/v1/policy/close-session` | Registered checker; admission, renewal and idempotent release of its own stream context |
| Internal assertion keys | `GET /internal/v1/assertion-jwks` | Private authenticated checker/gateway trust distribution, never public issuer JWKS |
| Operator API | `/admin/v1/...` | Separate private mTLS authority and local roles |

`ApplicationOrigin` binds one canonical HTTPS origin to one tenant, callback URI, allowed relative return paths and approved API audience IDs. Its global origin ownership is enrolled by instance `security_admin`; a tenant cannot claim another tenant's host. A scoped `client_admin` can narrow permitted routes/audiences but cannot reassign the host/tenant. v0.1 does not implicitly multiplex tenants on the same origin. Multi-tenant applications may serve multiple application organizations inside their one explicitly mapped SkyOAuth tenant; any different mapping needs a separate reviewed protocol.

Resolve browser tenant/provider from the registered origin and `TenantLoginState`, **not** a free `tenant` query or an untrusted forwarded header. At the public ingress, require an allowlisted authority/SNI/route match; SkyOAuth accepts canonical authority only from its authenticated trusted gateway chain. Unknown/ambiguous origin, spoofed Host/Forwarded values or disabled origin denies before redirect. Return locations are normalized same-origin relative paths validated against the stored allowlist; reject protocol-relative URLs, backslashes, traversal and prefix-confusion tricks.

Use host-only `__Host-` cookies with Secure, HttpOnly and Path=/; do not broaden Domain for convenience. An issuer host distinct from the app host does not imply sharing their cookies. The active-provider switch preserves origin and callback registrations.

**Backend identity transport:** bearer calls carry their original SkyOAuth access JWT; cookie calls cause SkyOAuth to return a short-lived signed internal human-session assertion to Envoy for a private, overwritten backend header (§6). Both internal links are authenticated and the backend rejects mixed credentials. RPC failures return typed errors, never an IdP HTML redirect: 401 for missing/invalid authentication, 403 for definitive authorization denial, the distinct capacity results in §6.1.1, and 503 for unavailable route/auth infrastructure (§4.2). The SPA explicitly navigates to login only for an authentication result. An alternative header adapter must preserve the same typed identity semantics and authenticated transport, not infer profiles from a subject prefix.

**Consume browser credentials on every non-SkyOAuth route.** On an enrolled host, every route to an application backend removes **all Cookie fields** and `X-SkyOAuth-CSRF` before forwarding, regardless of authentication class or whether ext_authz runs. This includes the SPA shell, assets, public/health endpoints and bearer routes. Configure HTTPRoute `RequestHeaderModifier.remove: [cookie, x-skyoauth-csrf]`, producing Envoy route-level `request_headers_to_remove`; the rule is not conditional on an auth-service response. On protected routes, SkyOAuth must first receive the original bounded metadata for session/Origin/CSRF validation and mixed-credential rejection. Use ordinary upstream-stage removal, not early removal before ext_authz. The gRPC `OkHttpResponse.headers_to_remove` remains defense in depth, with non-appending assertion replacement. Authentication rejects duplicate/ambiguous SkyOAuth cookies rather than choosing a copy. Never copy cookies/CSRF into alternative forwarded metadata; redact them in gateway logs/traces as well as application logs. Test actual filter ordering and upstream bytes, including retries and mirrors; prohibit configurations that restore or expose the credentials.

**Application responses cannot set cookies in v0.1.** Every non-SkyOAuth route also configures HTTPRoute `ResponseHeaderModifier.remove: [set-cookie]` / Envoy `response_headers_to_remove: [set-cookie]`, removing every Set-Cookie field, not selectively parsing reserved names. No Lua/Wasm/ext_proc cookie-name filter is required by this baseline. Only the fixed SkyOAuth authentication/session endpoints routed to the independently verified SkyOAuth backend identity are exempt consumers/issuers of their required cookies; a path prefix, caller header or tenant-supplied flag alone cannot grant an exemption. Include both removals, their stage/order and the exact exemptions in the approved semantic projection. Missing removal or an unauthorized exemption rejects preparation/activation. Public-route tests run with no ext_authz call and still prove that static servers receive no session/flow cookies and cannot set them. Genuine SkyOAuth login/callback/session/logout/native flows must continue to work. A billing or static-file backend receives no reusable session credential usable against another audience. This is credential containment, not isolation from malicious JavaScript served on the same trusted application origin.

Cloudflare Tunnel supplies connectivity, not per-route authorization. WAF, rate limits and Cloudflare Access remain separately configured. Do not trust arbitrary `CF-*` or `X-Forwarded-*` outside the configured proxy chain.

### 4.1 Cookie route selection and request binding v1

`ApplicationRoute` is a tenant-owned child of `ApplicationOrigin`, administered by `client_admin` within that origin's audience assignments. Its immutable configuration version records an exact or segment-prefix path, nonempty method allowlist, exactly one resource-server ID, accepted credential profiles, session lease duration and maximum stream duration. For cookie requests, SkyOAuth resolves **only the origin/route versions pinned by the active RouteBundleVersion** (§4.2), then selects that origin's `HumanAccessPolicy` for the route's audience. `/rpc/billing` and `/rpc/deploy` can therefore issue different audiences/scopes on the same host. Request headers, cookies, query parameters and JSON bodies cannot select an audience or policy. A staged PATCH is not a live authorization change.

For a method, exact path beats prefix; otherwise choose the longest matching **segment** prefix (`/rpc/billing` matches itself or `/rpc/billing/...`, never `/rpc/billing-admin`). Reject equal-precedence conflicts on writes. Select before checking status: a disabled winning route denies rather than falling back to a broader route. Unknown routes/methods, missing policy/assignment or unsupported profiles deny. Gateway routing and this registry must select the same receiver; the mandatory admission procedure below applies to every change, not just initial deployment. M2 bearer routes already pin an expected audience in gateway/backend configuration; this additional cookie mapping ships in M3. Bearer validation never chooses the expected audience from the token itself.

**Routing-agreement admission is mandatory on every change** to either ApplicationRoute or gateway routes, precedence, receiver destinations, authentication policy, rewrites or route-cache behavior. A revision-checked deployment plan validates the prospective pair for method/path/host selection, exact audience/receiver, supported profiles and no-rewrite rules. Generate both representations from one reviewed route bundle where practical; direct registry PATCH/import or an out-of-band gateway edit cannot activate an unchecked mapping. Restrict gateway mutation to the admission-controlled deployment path; a CI smoke test alone is not enforcement. Registry and gateway administrators retain their respective authority; neither role silently acquires the other's rights. Section 4.2 defines the enforcers and persisted evidence.

There is no distributed atomic-write claim: staging leaves the old pinned pair live. A real gateway change closes the entire affected origin bundle to new cookie-authenticated application requests for its apply-and-observe cycle, not merely the edited path. Unchanged contexts may retain only their existing leases during that window (§4.2); operators must account for possible stream interruption. Independently classified public routes and fixed SkyOAuth cleanup endpoints are not implicitly cookie-gated. A strictly registry-only activation may instead switch pins atomically under the unchanged deployment evidence without closing the gate, subject to §4.2's exact equivalence and freshness checks. Known mismatch stays closed; transient observation loss uses only the bounded last-verified-state rule. Rollback is another validated activation, not restoration of an old active flag or security state. Unaffected bundles need not stop. The coordination cost and possible denial are explicit; trusted per-route audience metadata remains a future alternative under ADR-007/ADR-020, not a caller-header fallback.

The internal assertion carries `skyoauth_route` and its revision, plus `skyoauth_request={version:1,method,scheme,authority,target_sha256}`. The v1 tuple is the request **after ingress validation/normalization and before ext_authz**, and must be identical at the backend before framework URL decoding. `scheme` is `https`; `method` is the exact uppercase registered method. `authority` is the registered lowercase ASCII/IDNA host with a non-default port if present (443 omitted); userinfo, trailing-dot aliases and conflicting Host/:authority are rejected. The internal TLS hop does not redefine the external scheme/origin.

`target` is the exact ASCII origin-form path plus optional `?query`. Query ordering, duplicate parameters, percent-escape spelling, `+` versus `%20`, and absent versus empty query are preserved; neither signer nor verifier parses/reorders the query or decodes the bound target. Ingress rejects fragments, controls, literal backslashes, malformed escapes, encoded path separators, dot/traversal segments (including percent-encoded dots) and repeated path slashes; non-ASCII path data must be percent-encoded. Canonical authority validation occurs once before route selection. These are required deployment/parser rules, not assumed Envoy defaults. The backend compares method/scheme/authority and the raw-target digest before applying its documented single URL-decoding pass for resource routing; configurations needing double-decoding are unsupported.

`target_sha256` is the unpadded base64url encoding of the full 32-byte SHA-256 digest of the exact ASCII `target` bytes defined above (43 characters). Do not include the raw path/query in the assertion or its stored continuation binding. The backend recomputes that digest from its received raw target; it does not hash a parsed/reconstructed URL. This keeps the binding fixed-size without changing exact-match semantics. Hashes are not encryption or anonymization: low-entropy targets can be guessed, so redact assertions/digests and sensitive request queries from logs. Input target/header size limits still apply.

Request-binding fixture: target `/rpc/billing?item=1&item=2&q=a%20b` has `target_sha256=EqNKWsbu3kU-OFps9t2Cn28dZrhJcWZ1ApnVNevplu8`. Test that query order, duplicate values, escape spelling and absent versus empty query produce different bindings; a 4 KiB query must not enlarge the assertion's target claim.

**v0.1 routes accepting `human_session` forbid path/host/query rewrites, post-auth routing-input mutations and route-cache rematching.** No URLRewrite prefix replacement, automatic host rewrite or trust in client-supplied `X-Original-*` is a workaround. Configuration admission/smoke tests reject such routes; unexpected mismatch fails closed at runtime. Backends without access to the raw target cannot use this assertion adapter. Supporting rewrites later requires a separately specified authenticated original/effective-target profile, not relaxed equality. The assertion binds request metadata, not the body; backend resource/RBAC checks remain necessary.

### 4.2 Route admission enforcer and runtime observations

**Protected scope, not opt-in labels.** Instance `security_admin` enrolls the protected set by cluster, Gateway UID, listener and hostname intersection in the approved bundle. A ValidatingAdmissionPolicy/binding (`failurePolicy: Fail`, `validationActions: [Deny]`) plus RBAC restrict configuration writes affecting that set to the dedicated route-controller service account. Guard create/update/delete of every route that could attach to a protected listener/host, including new or unlabeled routes, omitted/wildcard hostnames, more-specific shadow routes, old and new parentRefs, cross-namespace attachments and changes to allowedRoutes/namespace selectors. Non-cookie bearer, public auth and health paths on a protected host are managed resources in the same bundle with their own explicit authentication class; they do not acquire cookie authorization. M2-only routes on a distinct unenrolled host/listener stay outside this mechanism until that scope is enrolled. Shared Gateway-wide policy or listener changes require approval of all affected bundles or are rejected, not declared unrelated because the edited object lacks a bundle label.

The adapter's guarded inventory includes Gateway/HTTPRoute/SecurityPolicy, reference permissions, supported security/traffic extensions and backend identity/routing configuration that can affect the protected set. Where an indirect dependency cannot be safely narrowed by the supported admission predicates, guard that entire dependency scope or reject the attachment/extension; do not assume CEL can dynamically traverse arbitrary Kubernetes objects. Pin this inventory and parameterized host/listener rules with tests in T00.5/T50.4. Only narrow status-only updates by the existing gateway controller are exempt. Guard selector/parameter changes themselves under infrastructure administration, and verify installation before enabling traffic. Ordinary direct edits and new shadow routes are rejected at admission, not merely discovered later. Cluster administrators who can remove these guards remain trusted infrastructure principals.

**Explicit authority and preparation.** The separately deployed **SkyOAuth route controller** (`service/src/route_control`, `skyoauth-service route-control`, M3) is the sole writer for this protected resource set, not for all gateways in the cluster. A tenant `client_admin` creates a bundle parent, then requests preparation at `POST /admin/v1/tenants/{tenant}/route-bundles/{id}/preparations`. This stores an immutable `AdministrativeOperation(kind=route_bundle_prepare)` input snapshot and digest, expected active generation, origin/route versions, security preconditions and any explicit recovery intent; it is not an approved deployment or a RouteBundleVersion with a caller-chosen expected digest. The M3 controller's preparation worker runs the pinned translator before approval, then submits its scoped result at `POST /internal/v1/route-bundles/{id}/preparations/{operation}/result`. The service validates operation/input identity, controller scope and current preconditions, and atomically finalizes one immutable RouteBundleVersion containing the expected gateway digest and a server-computed complete plan digest. An exact duplicate result returns the same version; a contradictory result or changed precondition requires rejection/re-preparation. Failed or pending preparation cannot be approved. M1b supplies the schema and draft/result/approval contracts; real translation and executable preparation are M3 deliverables, not an M2 prerequisite.

**Instance `security_admin` approves only a completed prepared version** through `POST /admin/v1/tenants/{tenant}/route-bundles/{id}/versions/{version}/approve`. Its expiring `AdministrativeOperation(kind=route_bundle_approval)` binds the complete plan digest, exact version, expected active generation, protected scopes, adapter/translator inputs, every affected stable parent's `security_revision`, and the exact `reenable_targets`. Recheck enabled preparer/approver authority, approval validity and all preconditions before begin and again atomically at activation. A later disable, changed input, expired/revoked approval or intervening activation invalidates the pending operation; a controller credential cannot substitute for either role. A person may hold both roles only by explicit assignment. Approval authorizes that exact plan and recovery list, never arbitrary manifests or a blanket active flag.

Registered controller mTLS identities have explicit gateway/origin scope and no signer, WIF or human authority. Bounded, cursor-paginated private `GET /internal/v1/route-bundles` discovers only that identity's pending preparations and prepared/approved/active work; cursor/filter input cannot broaden scope. Private `GET /internal/v1/route-bundles/{id}` returns scoped preparation inputs, prepared plans and durable active/applying/deployment generations, epoch and sequence. No generated bundle ID needs to be baked into the controller deployment. Controller-only `POST .../{id}/claim` allocates a durable ownership epoch/lease; `POST .../{id}/transitions` supports service-validated begin/activate/abort and the registry-only operation below; `POST .../{id}/observations` records evidence under that epoch and increasing sequence. For a gateway change, begin closes before any apply and activation requires a complete matching observation set. Reconciliation uses leader election and Kubernetes resourceVersion preconditions; uncertain/incomplete writes during handoff keep the gate closed until the new owner reconciles and re-observes. Old epochs/replayed reports cannot reopen it. Deploy at least two controller replicas with disruption/placement controls; failover never resets sequences or observation ages.

Helm, Argo CD and Flux may render/submit approved bundle inputs, but cannot directly apply managed objects while this sole-writer guard is installed. The SkyOAuth approval/controller path is therefore a deliberate deployment dependency, recorded in ADR-020. Unenrolled scopes remain independently managed. A future design that admits existing deployers' writes against approved object digests is an alternative, not an undocumented second writer.

**Immutable configuration versus live state.** Stable `ApplicationOrigin` and `ApplicationRoute` parents retain identity/ownership plus immediate `security_status` and monotonic `security_revision`. Append-only origin/route versions contain planned configuration; PATCH/import stages and never changes active pins. A completed RouteBundleVersion pins the complete origin/route version set, gateway plan, projection/adapter versions, expected digest, `security_preconditions` and `reenable_targets`. RouteBundleRuntime separates active registry pins from `deployment_version_id`, the approved version whose unchanged gateway configuration is backed by observations. Per-proxy RouteBundleObservation samples bind that deployment version, serving-set generation, epoch and sequence. Polling does not revise authorization or create policy-change audit events. Activation supersedes only credentials/contexts whose actual origin/route or security dependencies changed; an unchanged route is not revoked solely because the bundle ID/version pointer advanced. Capacity records remain independent operational state.

**Incident disable and explicit recovery.** A disable atomically sets the parent's security_status to disabled, advances security_revision and invalidates pending plans that captured the prior revision. Security preconditions cover the origin and all pinned or otherwise affected route parents, including a removed/replaced route; they are execution preconditions, not a continuously enforced equality that disables unrelated live routes. The 09:00 approval cannot activate after a 09:20 disable without re-preparation and fresh approval. If disable races activation, the shared transaction/CAS order either rejects stale activation or applies the later disable; it never clears the incident accidentally. A new plan may preserve a disabled parent, or name it explicitly in `reenable_targets` with its current disabled revision and recovery reason. Successful activation clears only those named parents and advances their security revisions in the same transaction as the pin change. Omitted targets keep their security state. Unpinning/replacing a security-disabled route requires explicit recovery intent for that parent rather than an overlapping new-ID bypass. Re-enablement cannot resurrect invalidated credentials or closed continuations; new evidence snapshots current security revisions. Rollback follows the same rule, not historical security-status restoration.

A route is usable only when the origin and route parents are security-enabled, the pinned ApplicationRouteVersion has `configured_status=enabled`, and the ordinary gate/policy checks pass. Configured disabling is a planned version change; security disabling is an immediate independent veto. Clearing one does not clear the other. Select the winning route before checking either status; neither disabled form permits broader fallback.

**Registry-only activation.** `activate_registry_only` on the existing transitions endpoint may switch active registry pins without begin, gateway writes or gate closure only when the service verifies unchanged managed gateway resource contents, relevant dependency identities, protected scopes, adapter/bootstrap/projection versions, expected gateway digest and serving-set generation. The current gate must be eligible with complete fresh observations (within 30 seconds), all approval/security preconditions must still hold, and reenable_targets must be empty; incident recovery uses ordinary reviewed activation. Compare the approved artifacts themselves, not just equal resource names or a caller's no-op flag. Atomically advance active registry pins/generation and supersede only changed authorization dependencies, retaining deployment_version_id and the original observation samples, collection times and deadlines. No copied sample gets a new age or extra tolerance. A failed fast-path check leaves the old pair unchanged; it does not silently fall back into a disruptive apply. The caller may prepare/approve the ordinary path separately. Changing only one route's lease therefore need not interrupt unrelated routes, but the changed route's existing contexts still require fresh admission.

**Actual observation mechanism.** Envoy's admin interface is not assumed to provide remote authenticated read-only access; Envoy Gateway normally exposes it only on pod loopback. The supported adapter adds a **separate static management listener through EnvoyProxy bootstrap customization**, not a public HTTPRoute and not a sidecar. It requires mTLS for the enrolled controller, network access restricted to that controller, and an exact allowlist of GET requests to fixed, adapter-owned `/config_dump?resource=...&mask=...` targets forwarded to the fixed loopback admin cluster. Freeze the literal targets/masks and size/time bounds for each supported adapter in T00.5. Reject caller-supplied query variations, arbitrary paths/methods, bodies, upgrades, CONNECT, redirects and generic admin proxying; never expose secrets dumps or `/quitquitquit`, `/drain_listeners` or `/runtime_modify`. The controller receives no pods/exec or pods/portforward permission. The raw admin port stays loopback-only. Validate the listener and its isolation before admitting protected traffic; deployments unable to enforce this adapter do not silently open the full admin surface.

**Translator ownership.** The M3 route-control preparation worker, not the public auth service or tenant caller, runs the same pinned Envoy Gateway translator build through `egctl x translate --from gateway-api --to xds` before a version can be approved. Execute it as an isolated, resource/time/output-bounded helper on the validated complete input snapshot and explicit bootstrap inputs: fixed binary/arguments, no shell, tenant-selected executable, network fetch or missing-resource synthesis, and no auth, signing, reviewer or operator credentials. The public auth-serving image need not contain egctl. The service authenticates/binds the worker result to its pending operation; the scoped worker is an explicit trusted preparation component, not proof that a caller-supplied hash is correct. Do not reimplement Envoy Gateway translation or derive the expected digest from a running proxy. Pin Gateway/egctl/Envoy/bootstrap artifacts together and rerun projection fixtures plus real gateway tests on patch upgrades; this specifies a mechanism, not a tested version pair.

**Protected-scope projection.** Compute the same versioned `P(configuration, protected_scope)` on prepared xDS and observed active configuration. Include filter chains and virtual-host selection capable of serving the protected listener/SNI/authority, including intersecting exact/wildcard/catch-all candidates and their relevant precedence. Include all routes/authentication classes on the protected host, their reachable clusters/discovery selectors/peer identities, and shared listener/HCM/TLS/filter/normalization settings on which they depend. Request Cookie/CSRF removal, response Set-Cookie removal, auth exemptions and filter ordering are security-relevant. Exclude only provably disjoint virtual hosts/routes/clusters and documented nonsemantic noise; do not hash the entire shared RouteConfiguration simply because it contains the protected host. A route change solely for an unenrolled b.example.com on that listener must leave app.example.com's projection and active evidence eligibility unchanged. A wildcard overlap, protected receiver/auth change or shared listener security change must change the projection or reject preparation. Ambiguous/unsupported dependency reachability fails closed, never silently disappears from the digest. Disjoint edits do not by themselves change the protected serving-set generation or expire its observations. An Accepted condition, manifest hash or caller-selected dump is not deployed evidence.

**Observation loss is not an observed mismatch.** Watch configuration/proxy membership and poll each traffic-eligible proxy at least every 10 seconds. Mark observations stale and alert after **30 seconds**, but retain a fully verified deployment for at most **300 seconds from sample collection start** while deployment_version_id and the protected serving-set generation are unchanged, the current registry version is verified deployment-equivalent, no gateway apply or known mismatch exists, and independent session/policy checks pass. Registry-only activation preserves rather than resets these deadlines. This is not a session, policy or database fail-open rule. Network delay, controller restart and failed polls never advance sample ages. New proxies have no last-known-good allowance and stay outside protected readiness until verified. One unobservable serving proxy eventually gates its affected bundles; removing it from the required set needs verified withdrawal/draining followed by verification of the remainder. A 40-second controller reschedule can preserve an unchanged deployment, but five minutes of unobservability cannot.

**During gateway apply.** Begin closes the entire affected origin bundle to new cookie-authenticated application requests and continuation admissions; return **503 `route_configuration_unavailable` with bounded Retry-After** (Connect `unavailable`) throughout apply, as for an exhausted observation budget or no verified deployment. This is not 401/403 or a login redirect. An established context whose pinned origin/route versions and authorization/security dependencies are unchanged in the applying version receives temporary `unavailable`, not terminal denial: no renewal and no closed_at, with retries allowed only until its existing lease deadline. A changed/removed dependency, security disable or other revocation is terminal; abort or re-enable cannot resurrect it. Differences expected while installing the approved plan are transitional, not unsolicited drift; out-of-plan mismatch remains terminal. Registry-only activation follows its separate no-write path above. A real gateway apply can therefore interrupt every cookie stream on the origin if the apply-and-observe cycle exceeds its lease, even for an unchanged route; schedule accordingly.

Transient observation/store/transport failure likewise grants no new lease and leaves the existing cutoff unchanged; auth-service transport failures map explicitly to fail-closed 503. Reopening after a real apply requires fresh complete evidence. Assertions and leases are capped by remaining observation validity and all session/policy bounds, never another stacked window. Fixed `/_skyoauth/session` and `/_skyoauth/logout` routing, native `/oauth/revoke`, verified back-channel logout and independent session-revocation/security-disable operations do not depend on the application route gate. They retain their own origin, credential, CSRF/signature and store checks; the session endpoint may supply only browser-safe metadata/CSRF needed for cleanup, never forwarding authority. The controller must preserve those fixed SkyOAuth routes during an application apply. Gate bypass for cleanup is not permission to mint an application assertion or ignore infrastructure failure. No instantaneous detection or uninterrupted-availability guarantee is made.

T14.9 owns M1b versioned schema, pending-preparation/result/approval/list/read contracts and service-validated state transitions. T32.3 delivers M3 isolated translator preparation before approval, controller/listener enforcement, scoped observation and both activation paths; M1b must not claim a deployable translated plan without that worker. T50.4 packages/audits the actual mechanism and tests shared-listener isolation, incident recovery, preparation failures, registry-only activation and full-apply interruption. Kubernetes/Envoy administrators able to replace the data plane or remove guards are outside this guarantee. Every alternate gateway adapter, including ForwardAuth on Kubernetes, needs its own equivalent reviewed deployment/observation and all-route credential-removal contract; platform location does not imply Envoy support.

## 5. Identity and credential flows

### 5.1 Browser login, login CSRF and opaque session

1. Resolve the registered `ApplicationOrigin`, its tenant and active provider. Validate the relative return location from that registration.
2. Generate state, nonce, PKCE S256 and a server-generated browser-flow secret. Set short-lived `__Host-skyoauth_login` (Secure; HttpOnly; Path=/; SameSite=Lax; no Domain); store only its keyed hash in a `BrowserFlowBinding`. Bind the OIDC transaction to that hash, flow kind, origin, tenant, provider/epoch, exact callback and return path.
3. Redirect to the fixed upstream authorization endpoint. The baseline uses a top-level GET/query callback; a provider requiring another response mode needs an explicit tested profile, not a weaker cookie fallback.
4. At `/_skyoauth/callback`, require **both** correct one-time state and the initiating browser's matching flow cookie, exact registered origin/callback, provider epoch, PKCE and verified ID-token issuer/audience/signature/nonce/time/authentication requirements. A state or transaction ID alone is not browser authentication. Wrong or missing browser binding denies without creating, replacing or linking a session.
5. Resolve the verified provider-subject link, applying §5.1.1 when none exists; never silently create a replacement for an unlinked migrated account. Create a `HumanAuthentication` record and a fresh CSPRNG opaque session ticket; persist only its keyed hash, origin/tenant/principal/authentication reference, provider/subject/optional sid, idle/absolute expiry and CSRF verifier. Atomically consume the login transaction and expire its flow binding. Starting a new flow for the same flow-cookie slot invalidates the old one; stale tabs restart rather than bypass binding.
6. Set `__Host-skyoauth_session` with Secure; HttpOnly; Path=/; SameSite=Lax, no Domain. It is not an OAuth token. `GET /_skyoauth/session` returns only safe principal/session metadata and a session-bound CSRF token with no-store.
7. Unsafe cookie calls, including Connect unary POST and logout, require exact Origin plus CSRF in `X-SkyOAuth-CSRF`. Local logout revokes the session/authentication context. Optional back-channel logout verifies signature/issuer/audience/events/time/replay and uses indexed provider/subject/sid selectors. The gateway consumes browser credentials before application forwarding as specified in §4.

A session is usable only before **both** idle and absolute deadlines, on its registered origin/tenant, with live principal/authentication/provider epoch. Throttled last-seen writes must not revive an expired session or extend absolute lifetime; document bounded early idle expiry from coalescing. Verified account linking also requires an initiating-browser-bound transaction and explicit proof/approval; never email-only merging or attacker-supplied callback account reassignment.

Login CSRF, callback injection, redirect URI confusion, OIDC mix-up, session fixation and identity-linking confusion are explicit release threats/tests. PKCE/state/nonce are not sufficient when their transaction is not bound to the initiating browser; see RFC 9700 §§2.1 and 4.7.

Default: discard upstream access/refresh tokens after login. An encrypted server-side provider-token vault is an explicit opt-in for authorized upstream operations; tokens never reach SPA JavaScript. Do not rotate the browser cookie on every ext_authz check or couple normal session lifetime to upstream token rotation.

### 5.1.1 First login and migration enrollment hold

A versioned tenant `HumanEnrollmentPolicy` has two v0.1 modes: **`preprovisioned` (default)** denies an authenticated but unlinked subject with a non-enumerating `enrollment_required` result; **`auto_create` (explicit operator opt-in)** atomically creates a fresh `usr_*` principal and verified link for the exact active provider/issuer/subject after the same full OIDC/browser checks. Concurrent first logins use a unique tenant/provider/issuer/subject constraint and converge on one principal. This policy applies to both browser and native login. It never matches by email, copies another user's membership, or creates operator authority. New principals start with **no backend resource privileges**; application onboarding/RBAC is separate. Existing disabled links/principals deny rather than triggering a replacement create. Invitation workflows are deferred; operators can preprovision through the existing verified-enrollment path.

`TenantLoginState.enrollment_hold` overrides auto_create. A provider switch or rollback sets the hold atomically with epoch invalidation; every callback rechecks the current hold/policy/generation before creating any principal. Unmatched replacement-provider subjects are denied while the hold is set, not silently assigned new IDs. Existing verified links continue normally after reauthentication. Initial activation from null may explicitly enable auto_create only as an approved fresh-install choice in its plan.

After linkage reconciliation, `provider_admin` may explicitly resume enrollment through a revision-checked, audited operation bound to the current provider and login generation; neither elapsed time, import, policy edit, restart nor rollback clears the hold. The confirmation warns that resuming permits genuinely unlinked subjects to become **new** users, not to inherit old identities. Existing-user continuity must be verified before resuming; unknown equivalence cannot be inferred from claims. Changing policy/hold never changes WIF or role assignments. This avoids mandatory per-user mTLS enrollment for opted-in public apps without guessing account continuity during migration.

### 5.2 Native OAuth and issuer-origin confirmation

The Rust CLI is a public client of SkyOAuth, not Zitadel. It uses stable issuer `/oauth/authorize` and `/oauth/token`, a registered generated `client_id`, S256 PKCE and an IP-loopback redirect. Client ID identifies configuration/tenant but does not authenticate a local process. **Bounded rotating SkyOAuth refresh credentials are required in M4**, so normal commands renew short-lived access without repeated browser approval; they are never upstream refresh tokens or static API keys (§5.2.2).

**Issuer-origin browser flow:** `/oauth/authorize` resolves the globally unique registered client and its tenant, validates redirect/audience/scopes against registration and audience assignment, creates `OAuthAuthorizationRequest`, and sets `__Host-skyoauth_native` on the **issuer origin** with the same secure host-only attributes and a short transaction lifetime. Its keyed hash binds the native request and upstream OIDC transaction. Upstream authentication returns to the fixed **issuer `/oauth/callback`**, registered on that tenant's HumanProvider, not the app-origin callback. Native and app flow cookies/transaction kinds are never interchangeable.

The issuer callback checks state, the native flow cookie, expected issuer/client/callback, PKCE/nonce, epoch and ID token before storing the verified human principal/authentication on the native request. Rotate the issuer-local flow secret and bind the replacement to that request before confirmation. `/oauth/confirm` requires this bound cookie and completed server-side authentication; a transaction ID, app cookie, URL principal or live upstream SSO alone cannot approve a request. A new native start invalidates the previous native cookie slot; stale/conflicting tabs show an explicit superseded-login error and require a deliberate restart. They must not silently approve or redirect to the replacement flow. The comparison value below lets the user distinguish concurrent requests.

**Every new loopback authorization requires explicit SkyOAuth approval.** Show the registered client name, account, audience/scopes, approved native-session duration, exact loopback destination and §5.2.1 comparison value, with approve/deny and a warning that the public client ID does not prove the local program's identity. The confirmation POST requires exact issuer Origin, CSRF, anti-framing, matching rotated flow binding, request digest, principal and unexpired provider epoch. Bind the resulting one-time code to the exact client/redirect/PKCE/audience/scopes/authentication. Only after approval redirect that SkyOAuth code to the loopback listener. Denial/expiry creates no code; consume confirmation state and clear its cookie. Prior consent or existing SSO never auto-approves a new request (RFC 8252 §8.6).

The native client separately checks its own OAuth state and exact callback path, redeems using its PKCE verifier, and closes the loopback listener after success/cancellation/timeout. Codes are transactional and single-use across replicas. Device flow is conditional and requires user-code verification plus equivalent explicit approval/abuse controls; it cannot bypass this interaction. Do not claim native compatibility until conformance passes.

### 5.2.1 Match the browser approval to the initiating CLI

Before opening the system browser, the Rust crate exposes an immutable confirmation descriptor; the reference CLI prints its exact loopback URI/port and a grouped comparison value and instructs the user to compare **both** with the SkyOAuth page. Library consumers must display the descriptor through their own trusted UI. The page derives the value from its stored validated transaction; it does not echo a caller-supplied display-code parameter. Approval requires an explicit “matches my CLI” acknowledgement in addition to the normal CSRF-protected action. A mismatching/superseded request must be denied and restarted, not worked around by approving another tab.

Comparison v1 is display-only, not a credential or proof of client identity: SHA-256 over the ordered UTF-8 fields `skyoauth-native-confirm-v1`, client_id, exact redirect_uri, code_challenge, `S256`, exact audience, canonical scope string, and client state. Prefix **each field** with its four-byte unsigned big-endian byte length. Scope is the space-joined, bytewise ASCII-sorted unique scope tokens; reject duplicates/invalid tokens. State is an independent CSPRNG value with at least 128 bits of entropy. Display the first 10 digest bytes as unpadded uppercase RFC 4648 Base32, grouped 4-4-4-4. Both implementations use shared test vectors. The random PKCE verifier stays secret and is never displayed, transmitted in the authorization URL or used as the display value itself.

The following literal test vector fixes field framing and display encoding; its state is a fixture, not a production random value:

~~~json
{
  "fields_in_order": [
    "skyoauth-native-confirm-v1",
    "client_6e94e21f46ba4eb1b8bd5bec24070f14",
    "http://127.0.0.1:49152/callback",
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "S256",
    "control-plane-api",
    "deployments.create workflows.read",
    "nY0vZ8s1B2c3D4e5F6g7H8i9J0k1L2m3"
  ],
  "sha256_hex": "563fd9668fde2a4aa01b611c170b437bbfa0f9c7f29a8e13c1f979cbef33acce",
  "comparison": "KY75-SZUP-3YVE-VIA3"
}
~~~

A malicious concurrent request with a different redirect/challenge/state changes the descriptor; copying a legitimate challenge still does not supply its verifier. This is a user-assisted correlation defense, not phishing resistance, a second factor, or protection from a local attacker able to read the CLI's secrets or alter its terminal. Missing comparison, social engineering or compromised same-origin UI remain residual risks; PKCE/state and all browser-binding checks are still mandatory.

### 5.2.2 Required native renewal, not long-lived access JWTs

A successful approved native code exchange issues an access JWT capped at **300 seconds** and a rotating SkyOAuth refresh credential tied to one `CLIRefreshFamily`: tenant, actual OAuth client, principal, HumanAuthentication/provider epochs, one audience and the approved scope ceiling. Default family limits remain **12 hours absolute and 1 hour idle**. An audited `client_admin` HumanAccessPolicy change may opt into at most **7 days absolute and 24 hours idle**, within any stricter instance/assurance limits; require positive durations and idle <= absolute. These are proposed product limits, not OAuth-mandated durations. Snapshot both limits at explicit browser approval: increases apply only to newly approved families, never to an existing family or HumanAuthentication. A tightening transaction permanently narrows affected family limits or revokes affected families; the next refresh/live check enforces it. Elapsed or revoked state is never resurrected by a later increase. Neither rotation nor refresh resets the absolute deadline or auth_time. The native HumanAuthentication lifetime is capped by that family and any stricter authentication requirement, not by the first access JWT's 300-second expiry. There is at most one family per native authentication/client/audience tuple; live checks resolve that unique family from the signed authentication reference, actual client_id and audience, and deny if it is absent or revoked. The browser displays these limits at initial approval. Refresh continues that approved authorization and is not a new loopback transaction needing confirmation.

The form request uses standard `grant_type=refresh_token`, `refresh_token`, `client_id` and optional narrowing `scope` at the stable `/oauth/token`. Project-specific **`skyoauth_refresh_request_id` is optional** and enables only bounded retry recovery. When present it must be an independent 256-bit CSPRNG value encoded as unpadded base64url; empty, malformed or duplicate values are `invalid_request`, not silent opt-out. It is retry correlation, not client authentication or a standard OAuth parameter. Reject audience/resource/subject overrides, duplicate parameters and unknown clients. Each successful refresh atomically consumes the old credential and returns one successor plus a fresh bounded access token. Recheck current client, audience assignment, principal, HumanAccessPolicy, authentication/epochs and family deadlines/revocation; never exceed original approved scopes. Omitted scope retains the previous scope set only if still allowed; explicit narrowing can succeed, but changed authentication requirements or invalid/revoked state requires reauthentication. No refresh extends upstream identity assurance indefinitely. See RFC 6749 §6 and RFC 9700 §4.14.

**Standard-client path:** without the request ID, perform ordinary one-time rotation with no retry receipt or response envelope. Reuse of that consumed credential revokes the family, including a retry that adds an ID after the fact. A lost response can therefore require a new interactive authorization. Generic OAuth refresh clients need no private parameter to renew, but receive no idempotent-retry guarantee. Supplying an ID selects the extension for that attempt; omitting/changing it on replay cannot downgrade an extension attempt into a fresh plain rotation.

**Bounded exact retry:** when an ID is supplied, the first successful refresh atomically consumes the old credential, creates exactly one successor and stores a retry receipt on that consumed credential. The receipt binds keyed hashes of the request ID and canonical request (actual client, parent generation and requested scope, distinguishing omission from an explicit set), the issued policy revision, successor generation, and a non-sliding **30-second** deadline from commit. Store the already-issued access/refresh credential values only in a short-lived authenticated-encrypted response envelope, with associated data binding that receipt and a separate protected encryption-key reference. Keep the key outside the database and separate from signing keys; no plaintext response cache, token logs or ordinary export. Purge the envelope at expiry; retain consumed-token/replay metadata for the family's remaining lifetime. This is a narrow M4 retry record, not a general upstream-token vault.

Within that window an exact same-token/request-ID/payload retry may return the **same credential values** only while the successor is still current and unconsumed, the family/epoch/assurance and issued policy revision remain valid, and the cached access token is unexpired. Recompute expires_in from its remaining lifetime; do not re-sign, rotate again, advance idle/auth_time/absolute deadlines, or replay a response after logout/switch/revocation. Concurrent identical retries converge on the one committed result across replicas. A different request ID or payload on a known consumed token remains replay and revokes the family. An exact retry whose successor was already consumed returns invalid_grant without returning old credentials or revoking a healthy newer generation while its receipt remains recognizable. After the 30-second window ordinary consumed-token replay handling applies; the client must stop recovery and reauthenticate instead. Missing/decryption-failed receipt for an extension attempt or unavailable store fails closed, never creates a second successor or falls back to plain rotation. A stolen token **and** its matching request ID can recover that same result during the window: this explicit bounded replay trade-off is not sender constraint.

The Rust client **always sends the extension ID**, serializes refresh across processes, writes the pending token/request-ID/exact payload to secure storage (or the explicitly memory-only session) before sending, and atomically replaces it with the successor after success. It does not retry without the ID after an extension failure. A lost response permits only bounded exact retries with backoff, conservatively stopping by 30 seconds from the first client send (never later than the server receipt deadline); never generate a new nonce or blindly retry the API mutation. A crash after that window or loss of secure pending state can still require reauthentication. `/oauth/revoke` remains required, checks token/client binding and revokes the family plus associated authentication with a non-enumerating response. Offline access retains at most 300 seconds residual validity; live checks include family status.

Access tokens remain memory-only. The reference CLI persists refresh credentials only in an available supported OS credential store, with an explicitly selected memory-only session when secure persistence is unavailable; never silently write plaintext. A minimal crate can omit platform storage but still implements in-memory refresh. Ten-minute commands and later commands within the family lifetime renew without opening a browser. Refresh never automatically retries the original non-idempotent API operation. WIF and SPA JavaScript still receive **no** refresh credential.

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

**v0.1 does not implement impersonation activation.** Retain only the existing grant's disabled state, desired policy/provenance and requires_reapproval marker, because preserving stored WIF policy is an explicit compatibility requirement. There is no v0.1 GrantActivationApproval table, activation endpoint, two-person ceremony implementation or active-impersonation release gate. All attempts to enable or issue this mode deny. Startup/import validation rejects active unsupported records without silently rewriting or deleting them.

A later feature-specific ADR must specify fresh revision-bound approval/activation and its tests before the mode can ship; simply upgrading capability cannot activate preserved records. This defers the active subsystem rather than removing the established no-reset guarantee. No provider migration changes dormant records.

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

`HumanAccessPolicy` is a tenant/audience-scoped, provider-independent record for exactly one OAuth client or ApplicationOrigin. A scoped `client_admin` sets its scope/TTL/authentication ceilings within the instance audience assignment. Issuance snapshots those records plus client/origin registration and relevant revisions; a `HumanAuthentication` record links the verified login to provider/epoch without requiring clients to know a provider ID. CLI scopes intersect approved requested scopes, client policy and audience assignment. Browser scopes derive from the registered origin's policy and the ApplicationRoute-selected audience (§4.1), never browser-supplied identity/scope headers. The immutable human-session policy snapshot includes the active pinned origin/route version IDs, not newer staged versions or operational capacity revisions.

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

A human-session assertion has the common claims and human constraints above, `skyoauth_profile=human_session`, `skyoauth_application_origin`, `skyoauth_authentication`, `skyoauth_session` (opaque internal references, never cookie hashes/tickets), `skyoauth_route`/route revision, and the exact `skyoauth_request` v1 tuple with target_sha256 defined in §4.1. It omits client_id and is minted only by SkyOAuth with the dedicated internal key (§6.2) after the live session/Origin/CSRF check. TTL is at most 30 seconds and cannot exceed session/authentication or applicable observation deadlines. Envoy removes client-supplied assertion headers and consumes cookies/CSRF before application forwarding (§4); the backend accepts only the resulting assertion on the authenticated gateway channel for the bound request. Public bearer ingress rejects internal assertions. This is not a signature over the application body and does not remove backend operation/resource validation. The assertion is never returned to SPA JavaScript.

For WIF allowlists, values within a dimension are alternatives and different dimensions are ANDed with tenant/audience/scope/RBAC. Missing/empty required dimensions, unknown constraint fields/versions or wrong authorization mode deny. A grant ID alone is insufficient. Human backends use the explicitly different schema above, not an undocumented exemption from A30.

Signing keys are asymmetric, bridge-owned, isolated and versioned with kid/overlap. Retain retired public keys through maximum issued TTL plus skew; no upstream signing keys and no plaintext key export. M1a defines public-key metadata, **M2/T20 implements public signer/JWKS**; M3/T32.14 implements the separate internal signer. Provider migration does not rotate keys.

### 6.1 Revocation and private live operation check

Offline short-lived access JWTs retain residual validity until expiry after a grant/policy/session change; the v0.1 access TTL ceiling is 300 seconds (policies may shorten it). Browser authentication is checked live at the gateway; an already-issued internal assertion has only its bounded residual lifetime. Do not promise cancellation of previously authorized operations or instantaneous Kubernetes object revocation.

`POST /internal/v1/policy/check` is private. Authenticate the caller against **ResourceServerChecker**, bound to the registered resource-server audience and explicit tenant set, not against the token's delegated subject/service. Direct workload credentials with no target service are fully supported. The caller sends exactly one access JWT or internal assertion plus canonical action/resource coordinates; request binding is retained for internal assertions. Input is bounded and never logged as token material or application payload.

Look up the persisted `ResourceAction` for that resource server: required scopes, supported profiles, required resource dimensions and whether live checking is mandatory. Verify the complete profile, audience/tenant assignment, current principal and immutable decision dependencies. WIF checks source, chosen binding, grant and optional target service; human checks HumanAccessPolicy, active pinned client/origin/route configuration, authentication/provider epoch and session or native refresh family as applicable. Superseded/invalidated authorization revisions deny and require renewed credentials; never reinterpret an old token under broader policy. Unknown action/resource/caller or wrong tenant/audience denies. Store/checker or transient route-observation failure returns typed unavailable without an allow; it is not an authentication failure. A resource server cannot use another audience's checker identity.

Return request-bound allow/deny/unavailable, checked revision when available and decision ID with no-store, not a new token or reusable blanket permission. The backend still applies canonical resource ownership and RBAC, with no positive caching for critical calls. Checks begun after committed revocation deny; a subsequent revocation cannot undo already-authorized work. Browser streams/downloads that outlast initial evidence use the bounded continuation below; expired assertions are never accepted as fresh evidence. **Bearer server-streaming responses (`wif` and `human_cli`) end no later than the original access JWT expiry**, hence at most its remaining 300-second lifetime, and sooner on a required live denial. v0.1 has no in-band token replacement or bearer continuation: the Rust consumer obtains a fresh credential and explicitly opens a new read-only subscription/download request. Native refresh or WIF reacquisition does not extend the old response. Resume cursors/event IDs/ranges are application-owned positions, never authorization; every new request repeats tenant/scope/resource/RBAC checks. A ten-minute log tail therefore reconnects across token lifetimes without restarting the deployment it observes. Deduplication/gaps are an application contract, not an exactly-once promise. Generalized bearer continuation is deferred under ADR-010 to avoid extending external-proof authority implicitly. M2/T26 delivers WIF support; M3 adds human-session checks and M4 human CLI checks before those profiles ship.

### 6.1.1 Established browser-stream continuation

For an action registered as stream-capable, the backend first calls `/internal/v1/policy/check` with the **unexpired** human_session assertion, canonical action/resource coordinates and a fresh backend stream-instance nonce, requesting a session continuation. Before sending protected bytes it verifies the ordinary allow and its own current RBAC. SkyOAuth atomically records a `SessionContinuation` and returns an opaque continuation ID plus `authorized_until`; this is a narrow exception to the ordinary check response, not a new bearer credential. Session/authentication references alone, or an already-expired assertion, cannot open one. An assertion jti can initialize at most one continuation; replay with different nonce/context denies. An exact retry by the same checker may recover the same ID but never extends its lease without a recheck.

Bind the continuation to the authenticated checker identity, tenant/audience, principal, session/authentication refs, origin/route and policy revision, exact action/resource coordinates, request tuple and stream nonce. It authorizes continuation of **that already-established response**, not a new request, new resource, new mutation or wider scope. It is private server-to-server state, never exposed to browser code or accepted on a public bearer path.

`POST /internal/v1/policy/recheck-session` accepts the continuation ID and bound nonce/context from the same registered mTLS checker, using stored verified references rather than an expired JWT. Check session/authentication deadlines, principal/provider/tenant epochs, pinned origin/route versions, current parent security revisions/status, assignment/policy/action dependencies and §4.2 runtime state; the backend rechecks canonical ownership/RBAC. Revocation, changed dependencies or an unauthorized caller denies and closes. During a planned gateway apply, unchanged pinned dependencies yield unavailable with no renewal or closed_at; changed/removed dependencies or security disable are terminal. Temporary store/observation/transport unavailability likewise permits retry only inside the previous lease. Staging, operational cap edits and a registry-only pointer advance with unchanged actual dependencies are not authorization mismatches. A changed version or security revision requires fresh admission; re-enabling never resurrects an invalidated context.

Each allow returns `lease_seconds` and `authorized_until`. The route's `session_lease_seconds` defaults to **15 seconds** and is bounded by the instance-administered ResourceAction `max_session_lease_seconds`. The action ceiling defaults to 15; only an explicitly classified **noncritical read-only** action may opt into a ceiling above 15, with an absolute maximum of **300 seconds**. Critical or mutating actions stay at <=15 seconds; per-operation live checks are still required where registered. Reject out-of-range or contradictory configuration rather than silently widening. The effective lease is the shortest of route/action limits, current session/authentication expiry, the applicable route-observation deadline and an immutable continuation deadline of at most **1 hour** from creation (route/action policy may shorten it). Authorization revisions bind these choices; activation of changed policy requires fresh admission, not reinterpretation of an old context.

Recheck before authorized_until; renewal after it or the absolute deadline denies even when the session remains live. Stop protected transmission immediately on terminal denial, or by the last successful deadline when the checker/store is unavailable. Neither stream traffic nor rechecks extend session idle/absolute expiry. Revocation after an allow has at most the **selected remaining lease** (default 15 seconds, explicitly opted-in noncritical maximum 300 seconds), not instantaneous cancellation. Set a monotonic local deadline no later than recheck request-start plus returned lease_seconds, subtract a safety margin and honor earlier server/session/context/observation bounds; network delay never extends it. No fail-open stream grace. A 20-second auth-checker/store outage will terminate default-lease streams whose last deadline passes; route-observer loss alone follows §4.2's separate bounded observation tolerance. Longer leases trade slower revocation for less polling and more outage tolerance, not guaranteed availability.

**Explicit release:** after completion, cancellation, disconnect, terminal denial or graceful backend draining, the backend stops local transmission and sends `POST /internal/v1/policy/close-session` with the continuation ID and its bound nonce/context. Require the same currently authorized mTLS checker; do not require an unexpired assertion, live end-user session or unexpired lease to release the checker's own context. Atomically set closed_at and release its quota occupancy exactly once, serialized with admission/recheck. A matching repeat returns success without another decrement; close wins permanently over later rechecks. Unknown IDs or mismatched checker/nonce/context receive the same non-enumerating not-found result and cannot release another stream. Do not expose the handle or release endpoint to SPA code.

Release may be retried with bounded backoff by that backend, but loss of the close request or a backend crash can leave an orphan until its last lease expires. No availability guarantee bypasses the cap in that case. Retain closed-context identity long enough for bounded idempotent retries, and an admission-jti tombstone at least through assertion expiry plus skew; closing or garbage collection never permits a second admission with the same assertion. Expired contexts cease counting without waiting for a cleanup job. Process restart or a new connection always requires fresh admission, not reuse of an orphan's handle.

The one-hour cap deliberately interrupts an unfinished download. APIs serving resumable artifacts must support range/resume against a stable object version/ETag, with If-Range or equivalent integrity checks; on version change or unsupported resume restart safely, never concatenate unrelated versions. SSE/RPC reconnection uses validated application cursors. Both client libraries provide opt-in read-only reconnect with capped exponential backoff and full jitter, honor Retry-After, and stop on cancellation or definitive authorization denial; do not reconnect all clients immediately, follow cross-origin credential redirects or replay mutations. Recovery always obtains fresh admission and backend RBAC. Payloads still flow directly through Envoy.

**Bounded load:** the recheck endpoint accepts either one item or a batch of at most **100 items / 64 KiB**, under one registered checker identity. Each item retains its continuation ID, nonce/context and correlation ID and receives an independent allow/deny/unavailable/deadline; no batch-wide allow exists. Reject duplicate IDs or malformed/oversized envelopes before writes; deny a wrong-checker/tenant item without exposing its state. Missing/late/unavailable results never extend its previous lease. Implement set-based reads/writes where safe, retaining each context's atomic no-post-expiry renewal and current-policy checks. Batching reduces network overhead, **not** the number of logical decisions or required row updates. Schedule jittered renewals before each earliest deadline, never delay to fill a batch. The close endpoint uses the same single/batch bounds and per-item identity checks, but only closes contexts and never returns an authorization lease.

Admission enforces an atomic cross-replica per-session cap using **OriginCapacityPolicy**, a separately revisioned operational record keyed by origin, default **8**, editable by that tenant's client_admin. **InstanceCapacityPolicy**, controlled by security_admin, stores the per-session ceiling (1–64) and explicit finite tenant/checker/global quotas and rate limits. The effective session cap is always the lower of the current origin setting and instance ceiling, including after the latter is lowered. Reject new origin settings above the ceiling; an existing higher value is bounded by the new ceiling until reconciled. These operational revisions are **excluded from route-bundle pins and HumanAccessPolicy/credential authorization snapshots**. Lowering limits blocks new admissions until occupancy falls below them; it does not close existing streams, change their authorization revisions or require redeployment. A session is origin-bound and occupancy counts unclosed unexpired leases across all its routes/checkers, not per API connection pool. Admission and limit updates serialize; expiry releases occupancy without waiting for cleanup.

Capacity failures have distinct safe wire reasons after authentication/authorization: **`too_many_open_streams`** is only the per-session cap (HTTP 429 / Connect `resource_exhausted`); **`stream_capacity_unavailable`** is shared tenant/checker/global exhaustion (HTTP 503 / Connect `unavailable`), without exposing other tenants' counters; request-rate limiting remains `rate_limited` (429). All may include a bounded Retry-After, not a guarantee that capacity will be free. For an opted-in resumable read-only reconnect, the TypeScript library may make **one delayed per-session-cap retry** at a valid Retry-After no greater than 300 seconds, plus bounded positive jitter, then surface the capacity error if still capped. Missing/invalid hints surface immediately. Preserve that one-retry budget across intervening transient failures; it resets only after a successfully established stream or an explicit new application/user operation, not each 429. Shared-capacity and infrastructure unavailability instead use cancellable jittered backoff with finite attempt/elapsed budgets and no login prompt. No automatic mutation replay. This permits orphan-expiry recovery after a crashed five-stream backend without creating a permanent reconnect loop. Close/expiry still preserves admission tombstones; client code never receives continuation handles. T32.14 measures actual load: ten thousand streams at 15-second intervals imply about 667 decisions/updates per second before safety margins, regardless of RPC batching.

### 6.2 Separate internal assertion signing and cost

Public access-token keys and internal assertion keys are distinct key pairs with disjoint kid namespaces and **non-interchangeable trust sets**. The v0.1 internal model is **one versioned key per deployment signer group, shared only by that group's authorized auth replicas**, not a freshly generated key per replica. Scale-out loads an already-published active key/kid from protected deployment secret storage or startup unwrapping into local protected memory; it does not enroll a new trust identity. Replicas have no public access-signing permission. Shared compromise affects the whole signer group; per-replica keys remain an alternative requiring a separate enrollment design, not an ambiguous second baseline.

Only instance `security_admin` through audited key administration enrolls/rotates/disables group keys and authorizes private-key distribution; public clients and auth replicas cannot self-register a kid/key. Backends/live checkers obtain the internal public set from authenticated private `/internal/v1/assertion-jwks`, rooted in deployment trust. It has a version/ETag and a maximum **60-second** verification-cache freshness, without stale-on-error extension. Unknown kid may trigger one bounded, rate-limited single-flight refetch of this fixed endpoint, with negative caching; it never authorizes a token-selected URL or key. Failure or still-unknown/disabled key denies. Profile/ingress selects the trust set before kid lookup, so changing typ cannot cross key purposes.

For a new group or key version, publish its public key before setting activate_after, at least the maximum verifier cache interval plus allowed clock skew later. Readiness requires the replica to load a registered key, confirm the published set/version and wait until activate_after; new verifier processes fetch the current set before readiness. Ordinary scale-out of an active group needs no new-key delay. Rotation retains the prior signer through overlap until the new key is eligible; a failed publication prevents activation, not verification bypass. Rollout/scale-out tests include cached old sets, unknown-kid floods, private key-service outage and missing/wrong group secrets.

**Emergency standby:** production commissioning and planned-rotation completion require one active version plus at least one prepublished, unexpired standby per signer group, already past activate_after. Standby public material is already verification-eligible in the private set; `signing_state=standby` is a control-plane prohibition on issuing with it, distinct from verification eligibility. Promotion therefore does not require every verifier to refresh an active-status flag. Keep the standby private key in separately access-controlled encrypted custody: ordinary auth replicas cannot mount, unwrap or read it before promotion. A standby secret already exposed to the compromised process is not a clean recovery key.

**Standby-use tripwire:** after verifying the signature, live policy checks, continuation admission and rechecks consult authoritative key state and deny evidence whose admitting key is still unpromoted/standby, with a rate-bounded compromise alert containing key/decision identifiers, never token bytes. Merely naming a standby kid in an invalid signature must not trigger a verified-compromise alert. Promotion is required before legitimate issuance. Previously promoted keys in normal retirement continue under the existing overlap/provenance rules; retirement is not standby. Offline signature verification alone cannot enforce this live-state tripwire because standby public keys are intentionally prepublished; do not claim otherwise.

On compromise, instance security_admin disables the affected version and promotes an eligible unaffected standby through an audited revision-checked key operation, then distributes it only to isolated/rebuilt or otherwise verified-clean replicas. Do not leave a compromised key enabled during propagation and do not waive activate_after for a newly enrolled key. This removes the mandatory publication wait, not the time needed for containment, key delivery or replica recovery. Promotion may operate in an alerted **degraded-redundancy** state while a new standby is enrolled and matures; lack of a replacement standby must not block use of the promoted clean signer. If no trusted eligible standby remains, fail closed until recovery rather than using compromised material. Existing offline-cache and continuation-lease revocation bounds still apply; standby promotion cannot resurrect contexts admitted under a disabled key.

Internal-key rotation/disable is independent of public JWKS and provider changes. Retain retired verification keys for the 30-second assertion lifetime plus skew, but reject compromised/disabled keys under the bounded cache/live-check rules above. Retain key status/provenance records through all dependent continuation deadlines even after public key bytes retire; retirement alone does not revoke admitted streams, whereas compromise/disable does. Continuations retain the admitting internal-key ID and deny on its compromise/disable; they do not rely on retaining an expired assertion or old key for the stream's lifetime. Key disable does not instantaneously update an offline verifier cache: its remaining freshness is at most 60 seconds; live admission/rechecks consult authoritative status, and previously granted stream leases retain only their stated bound. A compromised internal signer can forge internal evidence within its trusted boundary and is still high-impact, but cannot mint public access tokens; live checks additionally compare identity fields to the actual session/authentication records.

Expected cookie-path work is bounded metadata parsing, a live session/policy read (batched where possible), **one local asymmetric signature** and backend signature verification. There is no per-request KMS/HSM/network signing round trip in the baseline, no body processing and no cached reusable request assertion. A separately mandated remote internal signer is an explicit deployment variant whose availability/latency must be measured; failure denies. T32.14 benchmarks signing CPU, store reads/writes, p50/p95/p99 check latency and throughput, including continuation batches, per-session cap abuse and 10,000 idle open streams at several lease sizes on stated representative hardware. Set and publish the deployment's latency budget from those measurements; no unmeasured numeric performance claim or cache that weakens revocation is implied.

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
| Instance `security_admin` | Create/disable tenants; enroll operators and scoped roles; register/assign resource-server audiences, checker identities/action registries and canonical application-origin ownership; manage signer/recovery policy, InstanceCapacityPolicy and scoped route-controller identities. Approve exact route-bundle deployment operations/protected scopes under §4.2, not arbitrary tenant edits. Future high-risk activation is outside v0.1. No implicit tenant role inheritance. |
| Tenant `trust_admin` | Create workload/service principals and service identities atomically; manage source/keyset/binding/grant policy within instance audience ceilings; enable supported direct/delegation grants; no impersonation activation in v0.1. Cannot create human principals or self-assign API audiences. |
| Tenant `client_admin` | Create/update registered public OAuth clients, stage assigned-origin/route versions and route bundles, manage HumanAccessPolicies and separate OriginCapacityPolicy within instance ceilings. Cannot approve gateway deployment, activate unobserved routes, reassign origin ownership or change active providers/WIF grants. |
| Tenant `provider_admin` | Configure/test inactive human providers; human enrollment policy/hold and verified subject links; credential-only rotation and switch/rollback plans. Cannot edit WIF, audience assignments, clients or operator roles. |
| Tenant `auditor` | Redacted tenant configuration/audit reads; separate instance audit authority where explicitly granted. |

Bootstrap is a deployment-local command/Unix socket operation, never public enrollment. Atomically enroll an initial security_admin public credential and separate offline recovery public key, audit, then durably close bootstrap. Restart or an empty config cannot reopen it. The service binary retains only the deployment-local bootstrap/recovery verifier. **M1a provides a separate `skyoauth-operator` workstation binary at `operator/`, tested on Linux, macOS and Windows**, for remote private mTLS configuration and local signing of recovery challenges. It has no server/database or M4 native-OAuth dependency. Operator keys remain on the operator workstation/hardware signer, never copied into a pod to run a remote client.

Document and test the supported TLS client-key and hardware/OS signer adapters per platform; unsupported hardware/provider combinations fail explicitly, never export a key as fallback. For break-glass, the restricted local service emits a short-lived challenge including instance identity, operation/arguments digest and expected revision. The workstation verifies/displays that context and signs it with the offline recovery key; only the signed response crosses the separately authorized deployment-local channel. Offline key custody is not relaxed by the existence of a portable client. M1b adds the human configuration commands to the same operator binary before M3.

The first operator can then create a tenant, enroll/assign its scoped operators, register an API audience and tenant assignment, create/assign an application origin, register a CLI client and human policy, create workload/service principals, and configure providers/sources/bindings/grants. A single operator may hold multiple explicitly assigned roles for a small deployment, but no role implicitly inherits another. Initial human-provider activation uses the same switch operation from a null pointer. This provides a complete post-bootstrap write path with no manual database inserts.

Break-glass uses the restricted local interface plus the independent recovery key over a short-lived, single-use challenge bound to operation/arguments/expected revision. Permit bounded operator restoration or the same validated provider-switch/rollback operation only, not arbitrary WIF edits, audience reassignment or token minting. Consume challenges durably, audit/alert and rotate recovery keys after use. Rehearse while the human IdP is down or account linking is broken. Database/signer disaster recovery remains separate. Restore procedures preserve bootstrap-closed and consumed state or quarantine issuance until outstanding state can no longer be replayed.

### 7.3 Provider changes cannot bypass the switch transaction

`TenantLoginState.active_provider_id` is the sole active-provider pointer. HumanProvider has no independently writable active flag. All GET/export representations of active state are **read-only observations**. Ordinary provider PATCH, deletion/disable of the active provider, GitOps imports and config reloads must reject attempts to change the pointer, auth epochs or active-provider issuer/client/callback/authentication semantics. Creating/testing inactive candidates is permitted. A plan may cover such authentication-critical changes, activation from null, switch, disable or rollback; only its authorized commit transaction updates login state and advances epochs atomically.

**Credential-only rotation is not a provider switch.** A dedicated, audited `provider_admin` credential-rotation operation may replace the versioned secret/key reference for the **same issuer, upstream client_id, client-authentication method, callbacks and identity/authentication semantics**, including an active provider. Compare expected provider/credential revisions, validate the unchanged semantic tuple, and advance only administrative/credential revisions; provider auth_epoch and tenant auth_generation do not change. Existing sessions, native refresh families and pending transcripts retain their identity binding. Never expose secret bytes in configuration exports or logs.

Use only explicitly configured versions for bounded provider-supported overlap; no arbitrary secret/key fallback. Lack of upstream overlap may fail an in-flight code exchange and require that login to restart, but does not itself log out existing sessions. A compromised credential can separately trigger an intentional epoch-invalidating transition. Requests that also alter issuer/client_id/auth method/callbacks/assurance are rejected by this endpoint and require the ordinary switch plan. GitOps uses an explicitly typed credential-only operation with identical validation, not a generic way to bypass active-state protection.

Rollback uses the same guarded transaction with fresh monotonic epochs. No import, including one submitted by an operator holding every role, can replace it. Auth state is never retained accidentally because a generic active flag changed.

GitOps documents are role-scoped. A combined bundle is accepted only when the actor has **every** role needed for every mutation and its plan passes the same validation; otherwise reject the whole bundle, never partially apply or ignore unauthorized sections. Active-provider observations are not writable fields and a proposed change is always rejected in an ordinary import. Separate provider, client and WIF documents are recommended; the example in §5.7 is WIF-only.

### 7.4 Generated selectors and create-then-reference workflow

All object IDs and public OAuth client IDs are server-generated opaque random identifiers. Tenant-local `name` is a human label unique only within its entity type/tenant, never an exchange selector or globally reserved name. The prefixes in examples indicate type, not authority. A client cannot choose a global ID on initial create or probe another tenant through an import collision.

Creation omits ID and supplies a tenant-scoped name; the authorized API returns the generated ID/revision. Provision in dependency order (tenant/audience assignment, principals/source/keyset, binding, grant/client policy), or use a validated importer with tenant-local manifest references that resolves to generated IDs and returns a persistent mapping. Export that mapping and place returned source/grant IDs in job/client configuration. Creating two tenants' identically named sources yields different IDs without name collision.

Updates specify the existing ID and expected revision within the authorized tenant. Redacted exports preserve IDs on same-instance reconciliation; privileged full restore preserves them only into the intended empty/restored authority after ownership/provenance validation. Ordinary tenant import cannot claim an arbitrary missing global ID or rebind it. Reapplication is tenant-local reconciliation, not recreation. Once deployed, clients retain their IDs across provider migration; the one-time create-then-reference step does not violate the zero-reconfiguration goal.

## 8. Human-provider migration runbook

1. Authenticate independently. Snapshot issuer metadata, tenant/resource-server/audience assignments/actions/checker identities, client/origin/route/bundle versions and separate capacity policies, human-policy/enrollment registrations and current hold, all verifier configurations/keysets, principals/bindings/grants/activation state, policy decision fixtures, public key metadata and replay invariants. Do not export proof/secret material; fresh route observations are runtime evidence, not restorable permission.
2. Register/test an inactive replacement provider with fixed app and issuer-native callbacks; prepare verified account linkage and prove operator/recovery availability independently of upstream admin accounts.
3. Create an immutable provider-switch dry-run plan against expected login/config revisions. Reject any attempted WIF/audience/client/origin/operator/gateway/signer mutation; concurrent relevant changes require replan. A generic PATCH/import is not an alternate route.
4. Commit only provider login/mapping configuration and fresh human auth epochs atomically. Invalidate affected browser/native flow bindings, sessions/authentication contexts, pending requests/codes and required refresh families; set the enrollment hold (§5.1.1). Preserve WIF configuration and consumed assertions. Offline human JWTs retain only their documented short TTL; live checks reject invalidated contexts.
5. Reauthenticate humans with stable principal/RBAC mappings where explicitly verified; unmatched users remain blocked under the enrollment hold until verified linking or an explicit enrollment-resume decision. Existing client_id, origin, audience and library configuration remain unchanged.
6. Reuse prebuilt **TypeScript SPA and independent Rust CLI artifacts** (record hashes), existing GitHub job, uploaded-JWKS workload and two independently keyed shared-issuer Kubernetes clusters. No rebuild/package upgrade/YAML/CA/reviewer/source/grant/audience change. Exercise direct/delegated profiles, human profile verification and both supported replay modes; projected Kubernetes renewal stays reusable.
7. Compare pre/post allowed and denied decisions, IDs/revisions and audit. Roll back through the guarded plan with fresh epochs, never whole-DB rollback over independent policy changes or resurrection of consumed human/proof state. Unsupported impersonation stays disabled; single-use tests obtain fresh proofs, never require a consumed one to become valid.

Repeat conformance after schema/chart/protocol/SDK upgrades. Human-provider downtime can block fresh human login but not valid independent WIF or operator recovery, except where shared SkyOAuth infrastructure is unavailable.

## 9. Security and abuse model

Threats include compromised workflows/runners, issuer/key/cluster confusion, assertion theft/replay, cross-tenant audience issuance, subject-versus-resource-server confusion, profile substitution, signer/operator compromise, login CSRF and callback injection, OIDC mix-up, redirect URI confusion, identity-linking confusion, native-client impersonation, session fixation, CSRF/XSS, unprotected routes, header spoofing, SSRF, generic-provider-write bypass, credential resurrection and stale streams.

Mitigations are explicit: instance audience assignments plus canonical backend tenant/RBAC checks; typed signed profiles with distinct human/WIF schemas; grant-directed source-bound evidence; restricted verifier egress; browser-bound state/nonce/PKCE and separate issuer-native confirmation cookies; one-time codes/consumption across replicas; scoped independent operator writes and exclusive switch commits; cookie/CSRF consumption before backend forwarding; no token logging; fail-closed stores/private endpoints; short TTLs with critical live action checks and bounded streams. Every claim has positive and negative release fixtures in the task plan.

Residual limits: zero static application secrets does not mean zero privileged keys. SkyOAuth signer/operator/recovery trust and reviewer/upstream service credentials need protection. Compromised human IdPs can impersonate mapped application users, but not independently rewrite WIF/operator/audience authority. HttpOnly limits token extraction, not authenticated actions by same-origin malicious JavaScript. Root/runtime/database compromise remains separate high-impact risk. Authorization cannot retroactively undo an already accepted operation.

## 10. Required clients and repository layout

### 10.1 Two first-class libraries

| Deliverable | Package / home | Primary consumer | Gate |
| --- | --- | --- | --- |
| TypeScript SPA library | npm `@skyoauth/client`, `clients/typescript/` | Framework-neutral SPAs; React/Connect adapters | M3 |
| Rust client library | Cargo `skyoauth-client`, Rust import `skyoauth_client`, `clients/rust/` | User-owned CLIs; workload tooling | WIF M2; native M4 |
| Reference Rust CLI | `skyoauth-cli`, `cli/` | Thin consumer of the Rust library | Native M4 |
| Workstation operator client | `skyoauth-operator`, `operator/` | Private mTLS administration and offline recovery signing; Linux/macOS/Windows | M1a; human commands M1b |
| Local bootstrap/recovery verifier | Existing `skyoauth-service` subcommands | Deployment-local challenge/verification, no workstation private keys | M1a; provider transition M1b |

The similarly named npm and Cargo libraries are intentional language-specific distributions in separate registries, not competing packages or interchangeable imports. Both are required. Browser code never gets a token getter, native listener or operator key. Rust consumers do not depend on React, a JS runtime, frontend assets, service internals or PostgreSQL.

### 10.2 TypeScript: SPA-first

Evolve the existing package instead of adding a second browser core. Provide session/principal state, top-level login, CSRF-protected logout, cancellation and authenticated transport. `@skyoauth/client/react` and `/connect` are explicit entry points with optional peer dependencies excluded from the framework-neutral core. Runtime/type exports agree; the core bundles without Node built-ins/polyfills.

Authenticated targets are configured same-application-origin HTTPS routes with no URL userinfo. Validate before attaching CSRF; use Fetch same-origin mode/credentials and reject redirects for authenticated API fetches. Caller options cannot override these boundaries or add bearer authentication. Only explicit top-level login follows server-managed upstream redirects. Narrow explicit loopback development settings must not weaken production. Injected fetch is trusted integration code, not permission to bypass URL/header checks.

Keep CSRF/session metadata in bounded memory, clear on logout/account change/invalidation, and send only credential-free cross-tab invalidation signals. No access/refresh tokens in localStorage, sessionStorage or IndexedDB. Distinguish unavailable/cancelled/forbidden from unauthenticated; no automatic mutation replay on 401 or after login. Streaming/download cancellation remains end-to-end without SkyOAuth buffering bodies. Opt-in resumable read-only reconnect follows §6.1.1 backoff/jitter, range/version and fresh-authorization rules; authorization failures never become infinite reconnect loops. Expose per-session too_many_open_streams separately from retryable shared-capacity/infrastructure errors. Permit only the specified one delayed per-session recovery retry, then surface it; never turn 503 into login. The backend, not browser code, releases continuation slots on cancellation.

The bootstrap arbitrary-baseUrl `health()` helper is unauthenticated utility code, not permission to attach session capabilities to that URL. Test that an off-origin health base cannot become an authenticated target. Future TypeScript workload support is a separate nonbrowser surface and not a substitute for the SPA library. Validate packed npm artifacts in an actual browser, not only Node fetch mocks.

### 10.3 Rust: reusable CLI library

`clients/rust` is a planned Cargo member publishing `skyoauth-client`, consumed by `cli/` and an independent example. Expose typed configuration/errors, redacted credential wrappers, cancellation/timeouts and provider traits. Document feature boundaries for native OAuth, system-browser launch, loopback, required refresh protocol with optional platform-storage features, and GitHub/Kubernetes integration; test minimal/default feature sets, not just all-features.

Use an external system browser, S256 PKCE/state and §5.2 confirmation. Bind an ephemeral listener only to an IP loopback address; choose the port before authorization and match the exact chosen redirect on redemption. Bound callback lifetime/path, reject wrong state and clean up on cancel/timeout. No embedded login webview, password or static-client-secret fallback.

Attach credentials only to configured HTTPS API origins/audiences; never log or forward them across origin redirects. Access-token cache is memory-only. Required rotating refresh uses the OS credential store for persistence; a deliberately selected in-memory session works without it, and unavailable secure storage cannot silently fall back to plaintext. Workload renewal reacquires fresh on-demand proofs or rereads reusable projected tokens and never gets WIF refresh credentials. Bearer streams use explicit fresh-token reconnect at expiry (§6.1), with application cursors/ranges and no restarted mutation; background jobs are distinct from their observation streams. Library owns protocol; CLI owns terminal UX/exit codes.

Test the native crate/consumer on Linux, macOS and Windows, including loopback/cancellation and supported keychain adapters where included. Publish MSRV, TLS/runtime/features/platform policy separately from Linux server deployment support. Package and compile an independent consumer without private workspace-path assumptions.

### 10.4 Preserve the landed bootstrap

PR #2 at `8f81df23efd4c4a0cfe522f711a9ca56f294aab1` established `service/`, the root Cargo workspace, `clients/typescript/` and CI. Retain them. Add `operator` in M1a and `clients/rust`/`cli` when implemented; start server trust/policy/issuer/etc. as modules under `service/src`, extracting `crates/` only for justified reuse/isolation. Do not duplicate a service under `crates/server` or keep stale `packages/*` paths as another authoritative layout. The M3 route-control subcommand uses the service's route_control module in a separate least-privilege deployment; it is not part of either client library.

Preserve bootstrap tests/coverage and docs-only behavior. Each implementation adding/moving a member, entry point or package updates manifests, exports, lockfiles, CI paths/jobs, packed-consumer tests and README together. Planned modules and auth handlers are not implied to exist in the scaffold. The M1a operator client and local verifier do not require M4 native auth. Versioned profile fixtures and unchanged prebuilt SPA/Rust consumers prove migration compatibility without conflating credential models.

## 11. Roadmap

| Stage | Deliverable | Gate |
| --- | --- | --- |
| Bootstrap, landed separately | Rust service, TypeScript health helper, workspace/CI | Foundation, not authentication completion |
| M0 — Contracts | Profiles, audience/origin/admin ownership, source/grant/ID semantics, client ADRs, threat/test matrix | No unresolved security semantics in examples |
| M1a — Workload authority | WIF/tenant/audience/checker schema, trust/grants/replay, portable operator client and local bootstrap/recovery | Workload provisioning/restore/isolation gates; sufficient prerequisite for M2 |
| M1b — Human authority | Human enrollment/hold, origin/route/bundle/client policy, login/native/refresh state and sole provider transition | Complete human provisioning/state before M3; can run alongside M2 |
| M2 — WIF/bearer | Signer/JWKS, direct/delegated exchange, Rust workload library, bearer Envoy, WIF live action checks | GitHub/k3s → Envoy → API without human IdP/static app secrets; fixed replay outcomes |
| M3 — Browser | Origin-resolved browser-bound OIDC, sessions/internal human profile, continuation release/rechecks, approved route controller/isolated observer and admission guards, local assertion signer with standby, required TypeScript SPA/adapters | Packed browser library, cookie-isolation/profile/transport and deployment-enforcement tests, no payload hop |
| M4 — Native | Issuer-local callback/confirmation, reusable Rust native crate/reference CLI, human CLI profile/live checks and required bounded rotating refresh | Independent native consumers/platforms; standard refresh and optional retry extension; no silent approval, stable migration |
| M5 — Migration/hardening | Exclusive switch tooling, all-source invariance, unchanged client artifacts, recovery/deployment/release process | No client change and no WIF/audience/client reset; all mandatory tests |
| v0.1 | M0, M1a/M1b and M2–M5 and both client libraries, direct and attributed delegation | Versioned contracts and conformance suite |
| Conditional/later | Device flow, active true impersonation, upstream exchange/vault, other gateways/issuers, expanded admin UI, cloud STS, TypeScript workload helpers | Separately approved; not substitutes for required controls |

## 12. Decisions requiring ADR ratification

The proposed baselines and their trade-offs are indexed in the tasks document's ADR table. They cover audience/tenant authority, credential profiles, route enforcement, signer custody/recovery, native confirmation/renewal, browser sessions/continuations, enrollment, operator authority, provider migration and client packaging. Numeric lease, cache and refresh limits are product-policy proposals, not unmeasured availability promises or standards-mandated values. Ratification or a changed decision must update the applicable schema, examples, implementation tasks and acceptance cases together; protocol behavior must not depend on PR discussion history.

## 13. References

- [Architecture tasks and release gates](skyoauth-tasks.md)
- [Bootstrap PR #2](https://github.com/skyoauth/skyoauth/pull/2) and [landed tree](https://github.com/skyoauth/skyoauth/tree/8f81df23efd4c4a0cfe522f711a9ca56f294aab1)
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html): subject/actor exchange semantics and act claim
- [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) and [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html): refresh and revocation
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html): comparison display Base32 encoding (the comparison protocol itself is project-specific)
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): OAuth security, refresh rotation, browser-bound transactions, mix-up/redirect/CSRF defenses
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html): external browser, loopback and native interaction
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html): explicit JWT typing and validation separation
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html): at+jwt/client_id requirements; SkyOAuth instead specifies a private profile above
- [Fetch Standard](https://fetch.spec.whatwg.org/): mode, credentials and redirects; SPA policy applies stricter target/header rules
- [GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) and [reusable workflow identity](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows)
- [Kubernetes TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) and [projected service-account rotation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Envoy Gateway external authorization](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
- [Zitadel token exchange](https://zitadel.com/docs/guides/integrate/token-exchange): verify deployed provider/version capabilities
- [Envoy route components](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto) and [ext_authz configuration](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto): rewrites and route-cache mutation require explicit deployment restrictions
- [Envoy Authorization service](https://www.envoyproxy.io/docs/envoy/v1.40.1/api-v3/service/auth/v3/external_auth.proto): header consumption/overrides and explicit denial status; deployment must pin and test its own supported version pair
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/): API-server enforcement with fail-closed policy/binding; cluster administrators remain trusted
- [Envoy administration interface](https://www.envoyproxy.io/docs/envoy/latest/operations/admin.html) and [Envoy Gateway admin access](https://gateway.envoyproxy.io/docs/troubleshooting/envoy-proxy-admin-interface/): loopback admin and the need for a separately protected observer surface
- [EnvoyProxy bootstrap customization](https://gateway.envoyproxy.io/v1.10/tasks/operations/customize-envoyproxy/) and [egctl translation](https://gateway.envoyproxy.io/v1.10/tasks/operations/egctl/): mechanisms for the proposed management listener and pinned translator; not evidence of deployed SkyOAuth interoperability
- [Envoy Gateway request header removal](https://gateway.envoyproxy.io/docs/tasks/traffic/http-request-headers/) and [response header removal](https://gateway.envoyproxy.io/docs/tasks/traffic/http-response-headers/): route-level whole-header removal independent of ext_authz; validate the pinned adapter and normal-versus-early filter ordering
