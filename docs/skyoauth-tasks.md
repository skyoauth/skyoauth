# SkyOAuth — Detailed design, implementation tasks, and release gates

> **Status:** proposed implementation plan, 2026-11-15. Paired with [skyoauth-design.md](skyoauth-design.md). Checkboxes are **not yet completed**. All code/configuration snippets are proposed interfaces, not deployed implementations.

## 0. Delivery principles

**The two central outcomes are (1) secretless GitHub Actions → protected cluster API access via WIF and (2) a zero-client-change / zero-WIF-reset upstream human IdP migration.** Browser sessions, CLI auth, and gateway integration are equally required before v0.1 is declared feature complete.

- A migration from Zitadel to another human OIDC provider MAY require humans to reauthenticate. It MUST NOT require changes, configuration updates, recompiles, restarts, or redeployments of browser/CLI/agent/API clients; nor any reset of trusted external issuer discovery URLs, uploaded JWKS, subject bindings, service impersonation/delegation grants, or resource scope constraints.
- No application response body is proxied through SkyOAuth. Envoy (or another gateway) remains the transport data plane for large downloads and ConnectRPC streams.
- The stable SkyOAuth public issuer and JWKS are independent of the active upstream human IdP. Locally issued API tokens, not Zitadel/GitHub tokens, are the default backend credential.
- WIF trust, principal binding, and service grant policy are independently persistent/versioned database resources; upstream human IdP changes can touch only their own logical domain.
- Policy is deny-by-default; delegate by least privilege; preserve original actor attribution; privileged impersonation requires a distinct explicit opt-in.
- No SPIRE, service mesh, sidecar, or Cloud STS dependency is required to use WIF for GitHub Actions or k3s agents.
- Each security assertion is backed by an automated positive **and negative** test. Do not represent outline snippets as production-ready API manifests.

## 1. Proposed repository layout

~~~text
crates/
  core/               Stable Principal, Actor, ServiceGrant, Decision types
  config/             Bootstrap settings, schema, validated reloads
  persistence/        SQL migrations, repository interfaces, PostgreSQL
  oidc/               Human upstream adapters, OIDC flow/transcript
  session/            Opaque browser sessions, CSRF, logout
  trust/              External issuer/JWKS registry and verifier
  federation/         GitHub, Kubernetes TokenReview, generic JWT verification
  policy/             Claim bindings, delegation/impersonation, constraints
  exchange/           RFC 8693 endpoint, access-token grants and issuance
  issuer/             Bridge issuer discovery, JWKS, key lifecycle
  gateway/            Envoy ext_authz and HTTP ForwardAuth adapters
  server/             Axum listeners, wiring, health/metrics
packages/
  browser/            Framework-neutral TypeScript session SDK
  react/              AuthProvider/useAuth bindings
  connect/            ConnectRPC browser interceptor
  agent/              TypeScript GitHub/K8s credential provider
  cli/                Optional CLI-facing SDK
deploy/
  helm/skyoauth/      K8s chart, probes, security context, network policies
  examples/envoy/     Envoy Gateway HTTPRoute and SecurityPolicy
  examples/k3s/       k3s projected-token + TokenReview RBAC
  examples/github/    Zero-static-secret GitHub Actions caller
  examples/traefik/   HTTP ForwardAuth compatibility
tests/
  conformance/        Stable public protocol, migration and policy invariance
  security/           JWT/OIDC/CSRF/forgery/replay/gateway tests
  integration/        PostgreSQL, mock OIDC, Envoy, ConnectRPC
docs/
  skyoauth-design.md
  skyoauth-tasks.md
~~~

Exact crate boundaries can evolve; keep trust/policy/issuer as core separable modules and avoid circular dependencies.

## 2. Stable public contract — specification tasks

### T00 — Protocol and threat model (M0, blocker for implementation)

- [ ] **T00.1** Freeze the origin/URL strategy for public SkyOAuth issuer, app-origin browser endpoints, OAuth native-client endpoints, JWKS, RFC 8693 exchange, private ext_authz check.
- [ ] **T00.2** Define versioned API error schema, 401/403/429/503 distinction, HTTP caching, retry guidance, and backwards-compatibility policy.
- [ ] **T00.3** Define token profiles: human browser session, CLI SkyOAuth access JWT, WIF SkyOAuth access JWT, short-lived internal backend assertion if selected; forbid using ID tokens as API credentials.
- [ ] **T00.4** Specify a single stable `iss`, allowed API `aud` registry, normalized human/workload/service subjects, `act` semantics, `scope` format, and claims namespace/schema version.
- [ ] **T00.5** Document gateway/client header contract: no client-supplied identity headers, explicit handling when Cookie and Authorization are both present, explicit Origin/CSRF semantics, backend verification requirements.
- [ ] **T00.6** Specify session idle/absolute expiry, login transaction lifetime, token exchange lifetime caps, clock skew, logout and key rotation.
- [ ] **T00.7** Threat model (STRIDE-style): malicious workflow, JWT issuer/key confusion, token theft/replay, forged/mutating browser requests, OIDC callback abuse, JWKS SSRF, privilege escalation, unauthorized gateway paths, stale policy, identity-linking confusion, signing-key compromise, compromised CI job.
- [ ] **T00.8** Create ADRs for signer (e.g. ES256), storage/key encryption, provider delegation, CLI authorization-server obligations, backend identity propagation, and impersonation policy.
- [ ] **T00.9** Document explicitly which behavior is RFC standard and which is SkyOAuth-specific; include code examples for all client profiles.

**Gate M0:** reviewed interface/schema fixture examples; signed-off threat matrix and deployment trust boundaries. No public client must need to know an upstream Zitadel issuer URL.

### Proposed endpoint matrix

| Method / transport | Endpoint | Caller | Required behavior |
| --- | --- | --- | --- |
| GET | `/_skyoauth/login` | Browser | Start upstream auth, validated relative return; no arbitrary redirects |
| GET | `/_skyoauth/callback` | Upstream redirect via browser | Validate state, nonce, PKCE, provider, single-use transaction |
| GET | `/_skyoauth/session` | Browser | Auth status, browser-safe principal and session-bound CSRF token; no-store |
| POST | `/_skyoauth/logout` | Browser | CSRF validated; revoke opaque session; expire cookie |
| GET | `/.well-known/oauth-authorization-server` | OAuth clients | Stable bridge-owned issuer/metadata once CLI profile ships |
| GET | `/.well-known/jwks.json` | Gateway/backend | Public SkyOAuth signing keys; rotation overlap |
| GET | `/oauth/authorize` | CLI public client | SkyOAuth Authorization Code + PKCE broker; not direct Zitadel URI |
| POST | `/oauth/token` | CLI, WIF agents | Supported grants, including RFC 8693; policy-bound token response |
| POST | `/oauth/revoke` | CLI if refresh supported | Revoke a SkyOAuth credential/session as specified |
| gRPC | `envoy.service.auth.v3.Authorization/Check` | Private Envoy | Fail-closed authentication decision + header/assertion contract |
| GET | `/internal/auth/check` | Trusted HTTP ForwardAuth caller | Gateway-agnostic HTTP check, private listener |
| POST | `/_skyoauth/oidc/backchannel-logout` | Configured upstream IdP | Validate signed logout token; bounded logout state |

Path strategy is proposed and should be frozen before SDK publication; keep app-origin paths and issuer-origin metadata distinct where required.

## 3. Data model and persistence (M1)

The following object model MUST survive human IdP migration independently.

~~~text
Principal(id, kind, status, created_at)
HumanProvider(id, issuer, metadata, active, revision)
HumanSubjectLink(provider_id, issuer, upstream_sub, principal_id, verified_by)
Session(id_hash, principal_id, auth_context, expires, revoked_at, csrf_verifier)
OIDCTransaction(state_hash, nonce_hash, pkce_context, provider_id, redirect, expires)
TrustSource(id, kind, exact_issuer, discovery_url?, jwks_keyset_id?, audiences, algorithms, status, revision)
TrustKeysetVersion(id, trust_source_id, public_jwks, fingerprint, effective_at, expires_at)
PrincipalBinding(id, trust_source_id, claim_match_policy, workload_principal_id, status, revision)
ServiceIdentity(id, name, allowed_audiences, max_scopes, status)
ServiceGrant(id, actor_principal_id, target_service_id, mode, audiences, scopes,
             resource_constraints, max_ttl, status, revision)
IssuerKeyVersion(kid, algorithm, public_key, signing_key_reference, validity)
AuditEvent(id, timestamp, actor, action, object_id, previous_revision, new_revision, outcome)
~~~

### T10 — Schema and migration safety

- [ ] **T10.1** Design PostgreSQL migrations, indexes, strict uniqueness, foreign-key policies, and soft-disable/revision model. In particular, **do not cascade-delete TrustSource/Binding/ServiceGrant on HumanProvider deletion/change**.
- [ ] **T10.2** Generate stable opaque IDs for all principals, trust objects, bindings and grants; preserve IDs across import/export and upgrades.
- [ ] **T10.3** Store only keyed hash of random browser session tickets; protect per-session CSRF verifier; normalize/timestamp all expiry and revocation decisions.
- [ ] **T10.4** Implement immutable revision history for WIF policies, auditable actor metadata and optimistic concurrency/ETag (no silent lost updates).
- [ ] **T10.5** Implement versioned export/import (including *public* JWKS and policy metadata, not plaintext private signing keys) with semantic diff, dry-run, precondition checks and backup restore tests.
- [ ] **T10.6** Make secrets/cryptographic keys external to normal config exports; specify key recovery and disaster recovery runbooks.
- [ ] **T10.7** Define policy-source precedence for declarative GitOps vs DB admin changes; missing config MUST NOT result in wiping live trust objects.
- [ ] **T10.8** Add integrity checks and unit/property tests for tenant ownership of configs, deterministic ID resolution, rejected cyclic impersonation grants, and privilege ceilings.

### T11 — Trust source registry and JWK lifecycle

- [ ] **T11.1** Register trusted exact issuer plus kind (`oidc_discovery` or `uploaded_jwks`), accepted algorithms, audiences, maximum proof lifetime, status/revision.
- [ ] **T11.2** In discovery mode, pin allowlisted HTTPS host and exact issuer, resolve safe metadata/JWKS URLs, prevent SSRF/redirect-to-private-address and key-confusion.
- [ ] **T11.3** In upload mode, validate public-only JWK types, algorithm, unique `kid`, key strength, set-size and key overlap. Reject private JWK parameters.
- [ ] **T11.4** Add key-refresh strategy with bounded cache, expiration, rotation overlap, health alarms, and no permissive fallback when valid keys unavailable.
- [ ] **T11.5** Prevent token headers (`jku`, `x5u`, embedded `jwk`, unrecognized `kid`) from altering configured source trust.
- [ ] **T11.6** Implement audit, disable/re-enable, and independent trust-source rotation without recreating principal bindings or service grants.
- [ ] **T11.7** Verify source cannot be inferred merely by reusing a `kid`; match registered issuer + audience + algorithm + keyset.

### T12 — Internal principal and policy engine

- [ ] **T12.1** Normalize (`issuer`, `subject`) for humans, and (TrustSource ID, verified subject/claims) for workloads to independent stable principal IDs.
- [ ] **T12.2** Implement compiled, deterministic, deny-by-default claim matching; GitHub binding uses owner/repository immutable IDs and configured workflow/environment/ref/event context.
- [ ] **T12.3** Resolve delegation grants actor -> service with strict requested-audience/scope/resource intersections and maximum TTL.
- [ ] **T12.4** Implement RFC 8693 `act` attribution for delegated service tokens; retained original actor and source run/job provenance in audit. Do not treat GitHub `actor` as SkyOAuth human identity.
- [ ] **T12.5** True impersonation distinct from delegation, disabled by default. If enabled, separate approval, target ceiling, logging and tests; no arbitrary requested `sub`.
- [ ] **T12.6** Define policy revision snapshots for deterministic token issuance and audit. Explicit online reauthorization for critical actions if immediate policy revocation required.
- [ ] **T12.7** Negative tests: subject mismatch, wrong repo/owner, workflow path mismatch, missing environment, wrong audience, disabled source/grant, service grant escalation, ambiguous policy or duplicated mapping.

**Gate M1:** database restore retains all trust/grant IDs; disabling or replacing a human provider cannot delete/modify them. Policy decisions deterministic, privilege escalation denied.

## 4. WIF and token issuance — required (M2)

### T20 — SkyOAuth JWT issuer

- [ ] **T20.1** Publish stable SkyOAuth issuer URL, supported token profile and JWKS endpoint; bridge-issued tokens never pretend to be Zitadel-issued.
- [ ] **T20.2** Implement asymmetric signer with explicit algorithm allowlist, `kid`, rotation overlap, protected signing key, bounded `iat/nbf/exp`, unique `jti`.
- [ ] **T20.3** Use narrow API audiences and allowlist scope/constraints; distinguish access JWT from ID token using token typing and verifier profile.
- [ ] **T20.4** Implement gateway/backend verification fixtures for good/bad issuer, audience, expired/not-before, wrong signature, retired keys and token type.
- [ ] **T20.5** Define refresh/reissue semantics: WIF clients never receive long-lived refresh tokens; obtain a fresh source assertion on next exchange.
- [ ] **T20.6** Log issuance metadata (source/grant/run/audience/decision) but never JWTs or signing key bytes; expose safe metrics.
- [ ] **T20.7** Document residual bearer-token revocation window and strong-auth alternative for destructive calls.

### T21 — RFC 8693 exchange endpoint

- [ ] **T21.1** Parse form-encoded token-exchange grant (`grant_type`, `subject_token`, `subject_token_type`, `audience`, optional `scope`); enforce strict size and parameter multiplicity limits.
- [ ] **T21.2** Implement standard success/error response encoding, Cache-Control no-store, HTTP status, no redirect, TLS and rate-limit requirements.
- [ ] **T21.3** Verify source using only configured issuer/TokenReview adapters; reject unregistered issuer and unsupported grant/token types.
- [ ] **T21.4** Resolve stable actor and binding/grant policy before issuing; no requested `sub` or arbitrary `act_as` accepted.
- [ ] **T21.5** Compare requested vs allowed audience/scopes and reject escalation; preserve resource-constraint provenance.
- [ ] **T21.6** Add idempotency/replay policy for input JWT/JTI; single-use assertion support for selected high-risk federation policies.
- [ ] **T21.7** Cross-provider conformance tests and adversarial fuzz targets for parsing and verifier selection.

### T22 — GitHub Actions OIDC integration (mandatory)

- [ ] **T22.1** Register GitHub's issuer `https://token.actions.githubusercontent.com` with pinned discovery/JWKS, accepted audience and explicit claim schema.
- [ ] **T22.2** Implement strict checks for issuer, audience, signature, `iat/nbf/exp`, issuer key refresh, repository_owner_id, repository_id, ref/environment/event and workflow/job_workflow_ref where applicable.
- [ ] **T22.3** Detect GitHub runner OIDC environment via documented Actions interface; request custom-audience token without static secrets, do not log runner request token.
- [ ] **T22.4** Provide minimal reusable action/example using `permissions: id-token: write` and no configured repository secrets; avoid printing exchanged tokens.
- [ ] **T22.5** Add negative tests for fork/PR threats, untrusted `pull_request_target` patterns, other repository/owner, wrong branch, mismatched workflow, misbound environment, wrong custom audience, missing permission.
- [ ] **T22.6** Demonstrate real GitHub OIDC -> exchange -> Envoy -> ConnectRPC authorization in a disposable test environment; preserve run ID/attempt in audit.
- [ ] **T22.7** Demonstrate TTL renewal obtains new GitHub source assertion; bridge API token never written to disk in job.

### T23 — Kubernetes/k3s federation (mandatory)

- [ ] **T23.1** Document workload pod with projected `serviceAccountToken` audience restricted to SkyOAuth, short expiry and kubelet token-file rotation.
- [ ] **T23.2** Integrate TokenReview for each administrator-approved Kubernetes cluster, with minimal reviewer credential and bounded timeout.
- [ ] **T23.3** Match verified cluster, namespace, SA and where required Pod binding; do not let assertion choose an arbitrary TokenReview server.
- [ ] **T23.4** Deny deleted pod/revoked SA, wrong audience/cluster, expired token, malicious namespace and wrong workload identity.
- [ ] **T23.5** Agent SDK re-reads projected token file per renewal and caches only issued short-lived API credential in memory.
- [ ] **T23.6** Document local JWT verification as a distinct optional mode with explicit stale revocation tradeoff; TokenReview default where practical.

### T24 — Generic WIF issuer and uploaded JWKS

- [ ] **T24.1** Support configured OIDC discovery issuer and uploaded public JWKS trusted sources with the *same* policy engine.
- [ ] **T24.2** Test overlapping key rotation without deleting trust source ID, binding, or service grant.
- [ ] **T24.3** Test arbitrary/disallowed issuer, fake keys, wrong alg, duplicate `kid` and unsafe remote discovery URLs.
- [ ] **T24.4** Provide operator documentation for public-JWKS enrollment, rotations, disabling trust, and durable exports.

**Gate M2:** GitHub Actions and k3s agents call SkyOAuth-protected ConnectRPC APIs without static client secrets or upstream human IdP; policy grants bound target scopes and deny disallowed workflows.

## 5. Human OIDC, sessions, and gateway (M3)

### T30 — Upstream human OIDC adapter

- [ ] **T30.1** Implement Zitadel via standards-based OIDC discovery; configurable upstream adapter with fixed callback and validated issuer/ID-token verification.
- [ ] **T30.2** Authorization Code + PKCE S256, per-login `state` + `nonce`, one-time transaction persistence, strict return-location allowlist, no open redirect.
- [ ] **T30.3** SSRF-safe metadata/JWKS fetching, timeouts, provider outage behavior, no token logging.
- [ ] **T30.4** Verified upstream (issuer, `sub`) -> stable SkyOAuth human ID mapping; no email-only linking. Provide controlled new-user enrollment.
- [ ] **T30.5** Optional server-side provider token vault behind feature flag for delegated provider exchanges. Default discard upstream OAuth tokens.
- [ ] **T30.6** Optional signed back-channel logout: verify issuer/audience/signature/events/sub-or-sid and map to sessions; test replay.

### T31 — Browser opaque sessions

- [ ] **T31.1** Generate CSPRNG opaque session tickets; store keyed hashes and minimal session context in PostgreSQL; host-only `__Host-` Secure HttpOnly SameSite cookie; no JS token exposure.
- [ ] **T31.2** Expire by idle and absolute lifetimes, revoke immediately on logout; throttle last-seen writes without losing timeout guarantees.
- [ ] **T31.3** Same-origin session endpoint with no-store, browser-safe principal and session-bound CSRF token; no OAuth tokens, upstream roles or secrets.
- [ ] **T31.4** Enforce Origin/CSRF for unsafe cookie-authenticated requests (including Connect unary POST), block cookie+bearer ambiguity.
- [ ] **T31.5** Test callback replay/session fixation/cookie confusion/cross-origin CSRF/expired or revoked cookies/multi-replica sessions/DB outage.
- [ ] **T31.6** State logout vs upstream SSO logout semantics; no claim that browser token revocation automatically ends IdP SSO.

### T32 — Envoy gateway + ConnectRPC interoperability

- [ ] **T32.1** Implement Envoy gRPC Authorization Check v3 using generated protobuf and version-pinned protocol compatibility.
- [ ] **T32.2** Inspect only bounded request metadata; never inspect full uploads/downloads. Return 200/deny 401/403 with controlled identity metadata; fail closed on internal exceptions.
- [ ] **T32.3** Provide SecurityPolicy, HTTPRoute for public login endpoints, protected RPC, events, downloads, and private gRPC service; apply failClosed semantics.
- [ ] **T32.4** Test gateway removal/spoofing of identity headers; restrict direct API network access; authenticated SkyOAuth->Envoy and Envoy->backend channels.
- [ ] **T32.5** Define JWT verifier/backend path: initial ext_authz supports cookies and bearer tokens; optional native Envoy JWT bypass optimization must be security-equivalent.
- [ ] **T32.6** Ensure expired RPC auth gets structured 401, not HTML OIDC redirect. Browser SDK triggers top-level navigation.
- [ ] **T32.7** Verify Connect unary and server streaming, SSE and multi-GB artifact download through Envoy with **no SkyOAuth data-plane hop**; test cancellation/reconnect/idle timeouts.
- [ ] **T32.8** Enforce backend resource permission for every workflow operation; handle long-lived stream revocation by bounded lifetime/recheck strategy.
- [ ] **T32.9** Add HTTP ForwardAuth adapter with the same decision semantics for Traefik/NGINX. Verify trusted forwarded headers; never expose on public listener.
- [ ] **T32.10** Document Cloudflare Tunnel placement and separation from Cloudflare Access/WAF/rate-limit functions.

### T33 — Frontend libraries

- [ ] **T33.1** `@skyoauth/browser`: session state, login/logout, CSRF token, bounded session cache and invalidation, same-origin-only, no localStorage token.
- [ ] **T33.2** `@skyoauth/react`: React AuthProvider/useAuth, correct loading/unauthenticated/authenticated transitions, route integration examples.
- [ ] **T33.3** `@skyoauth/connect`: attach CSRF, handle Envoy 401 vs Connect Unauthenticated and stream errors; no automatic replay of mutations.
- [ ] **T33.4** Version JS package API and contract tests against stable SkyOAuth URLs; no direct Zitadel endpoint/import/configuration.
- [ ] **T33.5** Playwright E2E for login, logout, reload, session expiry, cross-tab logout behavior, CSRF, and protected ConnectRPC.

**Gate M3:** a browser authenticates with Zitadel and calls a protected multi-tenant ConnectRPC API using only opaque session cookie + CSRF; long streams/downloads bypass SkyOAuth. Negative authorization and gateway bypass tests pass.

## 6. CLI interface and upstream token delegation (M4)

### T40 — SkyOAuth native-client public OAuth profile

- [ ] **T40.1** Publish bridge-owned OAuth authorization metadata, `/oauth/authorize` and `/oauth/token`; define stable CLI client registration and allowed loopback redirects.
- [ ] **T40.2** Broker authentication to active upstream provider, then issue **SkyOAuth** authorization code tied to local public client, redirect, code challenge, scope and login principal.
- [ ] **T40.3** Require S256 PKCE; one-time authorization codes, expiration and replay tests, redirect URI equality, state handling on client.
- [ ] **T40.4** Issue only scoped bridge API access tokens, never upstream provider tokens to CLI.
- [ ] **T40.5** Decide interactive-only reauth vs rotating, revocable SkyOAuth refresh credentials stored by SDK in OS keychain; do not call keychain refresh credentials “secretless”.
- [ ] **T40.6** Device authorization (RFC 8628) only if consciously included in release scope; document CLI fallback and polling controls.
- [ ] **T40.7** CLI SDK and Connect client examples stay unchanged during IdP migration; reauth is acceptable.

### T41 — Provider adapter and Zitadel RFC 8693 support

- [ ] **T41.1** Define trait for upstream human login and optional provider token-exchange capabilities, with explicit capability detection/configuration.
- [ ] **T41.2** When Zitadel-issued source token and intended audiences/scopes are compatible, allow authorized delegated RFC 8693 exchange server-side; normalize any downstream API token to SkyOAuth's issuer.
- [ ] **T41.3** Document that Zitadel cannot be assumed to exchange GitHub/K8s assertions or mint new privileged audiences; local WIF path is independent and remains required.
- [ ] **T41.4** Block upstream administrative API tokens from being returned to clients or issued via generalized `act_as`. Use a separate restricted service-side adapter for privileged provider administration if needed.
- [ ] **T41.5** Test with Zitadel mock/instance and replacement OIDC provider; no breaking change in CLI SDK, public metadata, API JWT, or gateway headers.

**Gate M4:** CLI user authenticates via active human IdP but only sees stable SkyOAuth issuer/endpoints. Swapping provider requires reauth but no CLI reconfiguration.

## 7. Operational safety, deployment, and migration (M5)

### T50 — Kubernetes packaging and readiness

- [ ] **T50.1** Helm chart with public and private listeners, probes, securityContext (non-root/read-only FS), service accounts, resource limits, NetworkPolicies and pod disruption settings.
- [ ] **T50.2** PostgreSQL schema migrate/backup/restore and rollback instructions; 2+ replica support.
- [ ] **T50.3** Isolation for token-signing privileges and upstream admin API adapter; signing-key recovery/rotation documentation.
- [ ] **T50.4** Gateway policy smoke tests reject unprotected newly added sensitive routes; no hardcoded bypass on callback/session endpoints.
- [ ] **T50.5** Rate limits for exchange/login/issuer discovery/cache churn and admin operations; bound memory, JWT size, claim depth and HTTP request body.
- [ ] **T50.6** Observability: authz latency p50/p95/p99, session lookup, token issuance/denial metrics, JWKS refresh failures, source/grant change audit; no PII/token labels.
- [ ] **T50.7** SBOM, dependency scanning, hardened build provenance, vulnerability disclosure, release/patch policy and docs.

### T51 — Human IdP migration *without WIF reconfiguration*

- [ ] **T51.1** Provide explicit `human_provider_switch` administrative operation distinct from `trust_source_update`, `binding_update`, `grant_update`.
- [ ] **T51.2** Snapshot WIF registry and authorization fixtures (source IDs/issuers, discovery metadata, uploaded JWKS fingerprints/versions, bindings, service grants, scope/resource constraints, signing-key metadata).
- [ ] **T51.3** Prepare replacement IdP and verified human-account linking; dry-run effect and forbid touching any WIF objects or stable issuer/token API contract.
- [ ] **T51.4** Switch only active human IdP config; revoke affected human sessions/CLI credentials as defined; preserve all actor/service ID mappings and bridge signing keys.
- [ ] **T51.5** Run previously built browser/CLI apps after reauth with **no binaries, env vars, redirect URI client config, or deployment change**.
- [ ] **T51.6** Run existing GitHub Actions job and uploaded-JWKS workload after provider switch with **no YAML, WIF trust setting, JWKS upload, mapped subject, impersonation/service grant, or audience change**.
- [ ] **T51.7** Compare effective policy decisions and audit provenance pre/post, including allow and deny cases; fail release if WIF behavior changes.
- [ ] **T51.8** Test rollback of human IdP pointer without rolling back/overwriting independently changed WIF policy.
- [ ] **T51.9** Test schema migrations and backup/restore across bridge version upgrades preserving WIF object IDs and grants.
- [ ] **T51.10** Prove no client or gateway/backend redeploy on replacement provider and no certificate/signing-key rotation required merely by upstream migration.

### T52 — Security conformance and hardening

- [ ] **T52.1** Corpus of malformed JWT headers/claims, signature algorithm confusion, issuer mismatch, malicious `jku`, private-JWK upload, duplicate `kid`, key rollover.
- [ ] **T52.2** Negative WIF claims: GitHub fork, owner ID mismatch, wrong job reusable workflow, wrong event/ref/env, disallowed service, denied scope/resource, replay attempts.
- [ ] **T52.3** Test OIDC mix-up, callback replay, failed nonce/state/PKCE, login CSRF, redirect URI confusion, cookie fixation, CSRF, XSS-resilient cookie properties.
- [ ] **T52.4** Test header spoof, direct-backend bypass, ext_authz failure fail-closed, oversized auth headers, request smuggling/proxy normalization.
- [ ] **T52.5** Test signer key compromise drill, retired key overlap, suspicious issuance alerts, audit immutability and log redaction.
- [ ] **T52.6** Test backend tenant isolation, workflow cancellation/termination authorization, artifact access, stream revocation and critical-operation online policy checks.
- [ ] **T52.7** Fuzz untrusted token, policy and metadata parsers; run end-to-end and load/latency benchmarks on k3s/Envoy.
- [ ] **T52.8** Independent security review before stable release.

**Gate M5 / v0.1:** all C01–C10 compatibility invariants hold; actual GitHub Actions secretless WIF works; baseline k3s GitHub/Pod workloads, browser and CLI work; cross-provider migration changes neither clients nor WIF registrations/policies; all negative security tests pass.

## 8. Conformance matrix — automated release blocking

| ID | Scenario | Expected result |
| --- | --- | --- |
| A01 | Valid GitHub token, repository owner/repo and production job match | Scoped bridge token issued; API call authorized only within grant |
| A02 | Same job but wrong owner/repo, branch/environment, event or reusable workflow | Denied, no token |
| A03 | Token issuer/JWKS/audience mismatch | Denied; no dynamic key-source fallback |
| A04 | Uploaded public JWKS rotates with overlap | TrustSource ID, bindings, grants remain; valid old/new tokens per time policy |
| A05 | Attempt to upload private JWK or use token `jku` | Rejected |
| A06 | Kubernetes TokenReview validates bound SA and intended audience | Scoped token issued |
| A07 | Deleted Pod, wrong audience/cluster/SA | Denied |
| A08 | Browser session cookie only, CSRF valid | Allowed at edge; backend RBAC still enforced |
| A09 | Unsafe browser request without CSRF or wrong Origin | Denied |
| A10 | Cookie + bearer token in same request | Denied ambiguity |
| A11 | Expired/revoked browser session or database unavailable | Denied / appropriate 401 or 503; no fail-open |
| A12 | ConnectRPC streaming and artifact download | Data bypasses SkyOAuth; authorization before stream; reauth strategy defined |
| A13 | Unauthorized cross-tenant workflow operation with valid session/JWT | Backend denies |
| A14 | Zitadel -> mock alternative upstream human IdP; existing browser and CLI packages | Same endpoints/config; reauthentication only |
| **A15** | **Same migration with existing GitHub discovery source and uploaded-JWKS trust** | **No reset/metadata change or policy diff; successful exchanges** |
| **A16** | **Same migration with subject bindings, service `act_as` and impersonation grants** | **Same object IDs, scopes, resource constraints, effective allow/deny results** |
| A17 | Migration rollback | WIF changes untouched; provider pointer rolled back only |
| A18 | Gateway receives client-spoofed identity headers | Removed/overwritten; no privilege escalation |
| A19 | Rotate SkyOAuth issuer signing key independently of IdP | Clients/backend verify during overlap without configuration change |
| A20 | Upstream human provider unavailable | WIF continues independently while human fresh login fails closed |
| A21 | Revoke WIF grant while short-lived JWT outstanding | No further issuance; documented remaining offline token validity or online enforcement |
| A22 | Human account linking tries email-only match | Explicit verification required, no automatic ID reassignment |

## 9. Recommended delivery order and issue breakdown

The tasks are ordered by security dependencies, not by UI visibility.

| Order | Block | Prerequisites | Output |
| --- | --- | --- | --- |
| 1 | M0 / T00 | None | Public contract and threat model |
| 2 | M1 / T10–T12 | M0 | DB, trust registry, stable principal/grant evaluator |
| 3 | M2 / T20–T24 | M1 | GitHub/K8s WIF, issuer/JWKS, exchange, SDK examples |
| 4 | M3 / T30–T33 | M1 and token/identity contract | Zitadel browser OIDC, opaque sessions, Envoy, frontend SDK |
| 5 | M4 / T40–T41 | M2, M3 | CLI OAuth + provider delegation |
| 6 | M5 / T50–T52 | All above | Cluster hardening, zero-reset IdP migration and conformance |

Suggested small, reviewable PR boundaries: schema and models; registry/verifier; grants/evaluator; signer/JWKS; exchange/GitHub; TokenReview; OIDC/session; Envoy ext_authz; browser SDK; CLI; provider adapters; Helm/observability; migration testing. Keep implementation and docs-only PRs distinct.

## 10. Definitions of done

**Protocol DoD:** published, versioned specifications and examples describe all supported clients and trusted downstream services; no upstream human-provider identifier is required by any released client.

**WIF DoD:** users can configure an issuer via discovery URL or uploaded public JWKS, bind verified subjects/claims to stable workloads, and grant controlled delegation/impersonation to stable service identities. GitHub Actions and Kubernetes agents authenticate to their own cluster APIs without static application API secrets.

**Gateway DoD:** streaming events and downloads go Envoy -> backend directly; SkyOAuth sees authorization metadata only, returns clear denial; private auth endpoint and backend network boundaries are enforced.

**Migration DoD:** swapping Zitadel -> another OIDC provider with only human reauth never changes client binaries/config, gateway settings, trust source/JWKS records, subject and service-policy bindings, bridge keys, audiences, or effective WIF allow/deny decisions. Automated A14–A17 and A20 are release-blocking.

**Security DoD:** security reviewer can trace each issued principal to verified source + binding + grant, find actor provenance in audit, and demonstrate deny-by-default, revocation limits, tenant checks, constrained signing keys, and failures on malicious/token-mixed requests.

## 11. Open ADR decisions for maintainers

| ADR | Decision to make | Recommended starting direction |
| --- | --- | --- |
| ADR-001 | Issuer URL and discovery metadata profile | Single stable canonical HTTPS issuer, independent of upstream |
| ADR-002 | Signing keys and backup | Asymmetric, versioned `kid`, isolated key reference, overlapping JWKS |
| ADR-003 | Human sessions and store | PostgreSQL, opaque host-only cookie, keyed hash, no upstream tokens by default |
| ADR-004 | CLI public OAuth surface | Bridge-owned PKCE loopback flow; device flow later |
| ADR-005 | WIF source validation | GitHub discovery/JWKS, K8s TokenReview, uploaded public JWKS |
| ADR-006 | Delegation versus impersonation | RFC 8693 `act` delegation default; impersonation disabled by default |
| ADR-007 | Header identity propagation | mTLS-restricted headers or signed internal assertion; no browser assertion |
| ADR-008 | Source of policy truth | PostgreSQL with revisioned GitOps import, explicit deletion approval |
| ADR-009 | Upstream Zitadel token delegation | Optional server-side exchange only; always normalize downstream API tokens |
| ADR-010 | Immediate revocation for critical operations | Short JWTs and backend online recheck for destructive operations |
| ADR-011 | Multi-cluster signing/issuer model | One logical issuer, recoverable secure signer; separate authorities only if intentional |
| ADR-012 | Migration semantics | Human-provider-only pointer change, WIF immutability invariants |

## 12. Normative references

- [Architecture and roadmap](skyoauth-design.md)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [RFC 9700 — OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 8252 — OAuth for native applications](https://www.rfc-editor.org/rfc/rfc8252.html)
- [RFC 8725 — JWT best current practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [GitHub OIDC docs](https://docs.github.com/en/actions/reference/security/oidc)
- [Kubernetes TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
- [Envoy Gateway extAuth](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
