# SkyOAuth — Detailed design, implementation tasks, and release gates

> **Status:** proposed implementation plan, 2026-11-15; revised for PR #1 review. Paired with [skyoauth-design.md](skyoauth-design.md). Checkboxes are **not yet completed**. All code/configuration snippets are proposed interfaces, not deployed implementations.

## 0. Delivery principles

**The two central outcomes are (1) secretless GitHub Actions → protected cluster API access via WIF and (2) a zero-client-change / zero-WIF-reset upstream human IdP migration.** Browser sessions, CLI auth and gateway integration are equally required before v0.1 is declared feature complete.

- A human IdP migration MAY require human reauthentication. It MUST NOT require client/backend configuration updates, recompiles, restarts or redeployments; nor any reset of registered discovery URLs, uploaded JWKS, per-cluster TokenReview configuration, subject bindings, supported service grants or resource constraints.
- No application response body is proxied through SkyOAuth. Envoy remains the transport data plane for downloads and ConnectRPC streams; minimal bearer ext_authz is an M2 prerequisite, not deferred to M3.
- The stable SkyOAuth public issuer/JWKS are independent of the human IdP. Locally issued, typed API tokens with signed tenant/resource constraints are the default backend credential.
- Tenant-owned WIF trust, bindings, grants, client registrations and independent operator authority persist separately from human-provider configuration. A switch invalidates affected human authentication state, not WIF replay state or policy.
- Direct workload access and actor-attributed service delegation are required. True impersonation is disabled by default and conditional on ADR-006 explicitly including it; unsupported stored records stay inactive and survive migrations.
- Standard RFC 8693 subject/actor semantics must not be silently redefined. The direct exchange and SkyOAuth-specific service-delegation extension are documented separately.
- No SPIRE, service mesh, sidecar or cloud STS dependency is required. Independent operator/recovery keys and narrowly scoped TokenReview reviewer credentials remain privileged operational trust anchors, not application API secrets.
- Each security assertion needs automated positive **and negative** tests. These are design requirements, not claims that tests or implementations already exist.

## 1. Proposed repository layout

~~~text
crates/
  core/               Tenant, Principal, Actor, ServiceGrant, Decision types
  config/             Bootstrap settings, schemas, validated reloads
  persistence/        SQL migrations, repositories, PostgreSQL transactions
  admin/              Independent operator auth, scoped roles, bootstrap/recovery
  oidc/               Human upstream adapters, OIDC flow/transcript
  session/            Opaque browser sessions, CSRF, logout
  trust/              Three-kind source registry, public keyset lifecycle
  federation/         GitHub, Kubernetes TokenReview, generic JWT verification
  policy/             Claim bindings, selected grants, signed constraints
  exchange/           RFC 8693 direct exchange + service-delegation extension
  issuer/             Bridge issuer discovery, JWKS, key lifecycle
  gateway/            Envoy ext_authz and HTTP ForwardAuth adapters
  client/             Required Rust skyoauth-client: WIF (M2), native PKCE (M4)
  cli/                Required Rust skyoauth-cli reference executable (M4)
  server/             Public/private Axum listeners, wiring, health/metrics
packages/
  browser/            Framework-neutral TypeScript session SDK
  react/              AuthProvider/useAuth bindings
  connect/            ConnectRPC browser interceptor
  agent/              Optional additional TypeScript workload client
deploy/
  helm/skyoauth/      K8s chart, probes, security context, network policies
  examples/envoy/     M2 bearer and M3 browser HTTPRoute/SecurityPolicy
  examples/k3s/       Projected tokens, per-cluster TokenReview RBAC
  examples/github/    Zero-static-secret GitHub Actions caller
tests/
  conformance/        Public profiles, migration and policy invariance
  security/           JWT/OIDC/CSRF/replay/admin/tenant/gateway tests
  integration/        PostgreSQL, mock OIDC, two K8s clusters, Envoy, ConnectRPC
docs/
  skyoauth-design.md
  skyoauth-tasks.md
~~~

Crate boundaries can evolve, but the required Rust client/CLI and TypeScript browser packages have agreed homes. Optional TypeScript workload bindings do not replace Rust native authentication. Keep trust/policy/issuer separable and avoid circular dependencies.

## 2. Stable public contract — specification tasks

### T00 — Protocol and threat model (M0, blocker for implementation)

- [ ] **T00.1** Freeze canonical issuer, app-origin browser paths, native OAuth endpoints, JWKS, both exchange profiles, private ext_authz, live grant check and operator API boundaries.
- [ ] **T00.2** Define versioned errors, 401/403/429/503 semantics, no-store/caching, bounded retries, non-enumerating failures and compatibility policy.
- [ ] **T00.3** Define browser session, human CLI access JWT, WIF access JWT and optional internal assertion profiles. Require `typ=at+jwt` for API access JWTs; reject ID tokens as API credentials.
- [ ] **T00.4** Freeze stable `iss`, allowed audiences, principal kinds, `act`, scopes and signed claim namespace. Specify constraint version 1: tenant plus exact project/environment allowlists, AND across dimensions, OR within each list; missing/empty required dimensions and unknown fields/versions deny. Define each API operation's required dimensions and scope.
- [ ] **T00.5** Freeze gateway/backend identity transport, full constraint propagation, header sanitization, cookie+bearer rejection and separate Origin/CSRF rules.
- [ ] **T00.6** Specify separate session idle/absolute deadlines, conservative last-seen coalescing, login/code lifetimes, provider epochs, JWT caps/skew, logout and signing-key rotation.
- [ ] **T00.7** Threat model malicious workflows, issuer/cluster confusion, proof replay, cross-tenant config/resource access, native-client impersonation, forged browser calls, discovery SSRF, stale policy, operator recovery and signer/runtime/database compromise.
- [ ] **T00.8** Approve ADRs for signer/key storage, provider delegation, native-client confirmation, backend propagation and conditional impersonation. Device flow and CLI refresh support require explicit scope decisions.
- [ ] **T00.9** Specify RFC 8693 **direct** exchange separately from the proposed `urn:skyoauth:params:oauth:grant-type:service-delegation` extension. Document proof roles, required `skyoauth_trust_source`/`skyoauth_grant_id`, grant-derived target/mode, exact audience, narrow omitted-scope defaults, errors and unsupported generic two-token delegation; provide examples for both profiles. The private grant URI is not claimed to be IANA-registered.
- [ ] **T00.10** ADR-013: approve independent `adm_*` identities, mTLS public-key registration, local roles, private endpoints, one-time local bootstrap, separate offline recovery key, recovery allowlist/audit and the IdP-outage/compromised-IdP threat model. No upstream identity claim may assign operator authority.
- [ ] **T00.11** ADR-014: specify tenant ownership, composite same-tenant references, nonunique issuer strings, stable source selection and duplicate-issuer cluster/tenant fixtures.
- [ ] **T00.12** Specify matcher omission and replay semantics: absent configured claim denies; omitted optional predicate is unconstrained; required production predicates cannot be omitted. Default source replay is reusable; single-use requires verified `jti` and durable source-scoped consumption.

**Gate M0:** reviewed protocol/schema/examples, security ADRs and threat matrix; no client needs an upstream issuer URL. RFC versus extension behavior, admin trust, tenant scope, native interaction, scope omission and replay outcomes are not left implicit.

### Proposed endpoint matrix

| Method / transport | Endpoint | Caller | Required behavior |
| --- | --- | --- | --- |
| GET | `/_skyoauth/login` | Browser | Start upstream auth, validated relative return |
| GET | `/_skyoauth/callback` | Upstream redirect via browser | State/nonce/PKCE/provider binding, one-time transaction |
| GET | `/_skyoauth/session` | Browser | Safe principal/session + CSRF, no-store |
| POST | `/_skyoauth/logout` | Browser | CSRF check, revoke session, expire cookie |
| GET | `/.well-known/oauth-authorization-server` | OAuth clients | Stable metadata; advertise only implemented profiles |
| GET | `/.well-known/jwks.json` | Gateway/backend | Public SkyOAuth signing keys and rotation overlap (M2) |
| GET | `/oauth/authorize` | Native public client | Registered client/redirect, S256 PKCE, upstream authentication |
| GET / POST | `/oauth/confirm` | Authenticated browser | Show exact native transaction; explicit approve/deny, CSRF and anti-framing; never silent SSO approval |
| POST | `/oauth/token` | CLI, WIF agents | Supported OAuth grants and explicit service-delegation extension; no arbitrary subject/target |
| POST | `/oauth/revoke` | CLI if refresh ships | Revoke SkyOAuth refresh credential/family as specified |
| gRPC | `envoy.service.auth.v3.Authorization/Check` | Private authenticated Envoy | M2 bearer; M3 cookie/CSRF; fail closed |
| GET | `/internal/auth/check` | Trusted ForwardAuth caller | Optional private adapter with equivalent decision semantics |
| POST | `/internal/v1/policy/check` | Private authenticated backend | Audience/tenant-bound live grant check for exact token/action/resource (T26) |
| POST | `/_skyoauth/oidc/backchannel-logout` | Configured upstream IdP | Optional signed logout verification and bounded replay state |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/trust-sources`, `/keysets`, `/bindings`, `/services`, `/grants` | Independent `trust_admin` | Tenant-bound CRUD/disable and keyset versions; revision preconditions, dry-run/diff/audit |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/human-providers`, `/human-links` | Independent `provider_admin` | Verified provider/link configuration; no WIF mutations |
| POST | `/admin/v1/tenants/{tenant}/human-provider-switches` | Independent `provider_admin` | Create immutable dry-run plan; separate `/{plan}/commit` and `/{plan}/rollback` actions, expected revision (T51) |
| POST | `/admin/v1/tenants/{tenant}/imports` | Appropriately scoped operator | Validated GitOps plan; explicit deletion/widening approval; no cross-role import bypass |
| GET / POST / PATCH | `/admin/v1/operators`, `/operator-roles` | Instance `security_admin` | Credential enrollment/disable and explicit local roles |
| GET | `/admin/v1/tenants/{tenant}/audit` | Independent `auditor` | Tenant-scoped redacted events; no secret material |
| Local command / Unix socket | Bootstrap and break-glass | Deployment operator + independent credential proof | No public enrollment/recovery route; durable one-time challenge and audit |

Admin path alternatives above share the full `/admin/v1/tenants/{tenant}` prefix; instance operator paths are separate. Private listeners are not exposed through public Gateway routes. Device endpoints/pages are specified only if the optional device profile is approved; they cannot bypass confirmation. Freeze paths before SDK publication.

### Exchange selection and scope rules

For both WIF profiles require one stable `skyoauth_trust_source`, one `skyoauth_grant_id` and one API `audience`; `scope` is optional. Select only the registered source, verify its proof, resolve a same-tenant binding, then verify that the selected grant is enabled and belongs to that actor/tenant. IDs are selectors, not credentials. The grant determines mode and target; the request cannot override either. Multiple grants for the same audience are valid and selected explicitly.

- RFC 8693 direct grant: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, external `subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`; require a direct grant, output workload `sub`, reject `actor_token`.
- Service-delegation extension: `grant_type=urn:skyoauth:params:oauth:grant-type:service-delegation`, external `actor_token`, `actor_token_type=urn:ietf:params:oauth:token-type:jwt`; require a delegation grant, output configured service `sub` and verified workload `act.sub`, reject `subject_token`. This single-proof policy mapping is **not** generic RFC 8693 delegation.
- Omitted scope uses only an explicit nonempty `default_scopes` subset on the selected grant. No defaults means `invalid_scope`. Explicit empty/excessive scopes deny; never infer all allowed scopes. Unsupported `resource`, token types, duplicate parameters, missing selectors and grant/profile mismatches deny rather than being ignored.

Return `access_token`, `token_type=Bearer`, `expires_in`, granted `scope` and `issued_token_type=urn:ietf:params:oauth:token-type:access_token`, with no-store and no WIF refresh token. The extension deliberately shares this response shape without claiming its grant semantics are RFC-standard. See design §5.7 for the wire example and rationale.

## 3. Data model and persistence (M1)

Define the full logical schema in M1 even when native OAuth handlers ship in M4. Stable configuration survives provider switches; affected human authentication state is deliberately invalidated. Encrypted database backups and redacted configuration exports are distinct artifacts.

~~~text
Tenant(id, name, status, created_at)
Principal(id, tenant_id, kind, status, created_at)
HumanProvider(id, tenant_id, issuer, metadata, active, auth_epoch, revision)
HumanSubjectLink(tenant_id, provider_id, issuer, upstream_sub, principal_id, verified_by)
Session(id_hash, tenant_id, principal_id, provider_id, upstream_sub, upstream_sid?,
        provider_auth_epoch, auth_context, created_at, last_seen_at,
        idle_timeout_seconds, idle_expires_at, absolute_expires_at,
        revoked_at?, csrf_verifier)
OIDCTransaction(state_hash, tenant_id, provider_id, provider_auth_epoch,
                expected_issuer, nonce_hash, protected_pkce_context, redirect,
                native_request_id?, expires_at, consumed_at?)
OAuthClient(id, tenant_id, client_id, display_name, redirect_rules,
            allowed_audiences, allowed_scopes, status, revision)
OAuthAuthorizationRequest(id_hash, tenant_id, client_id, principal_id?,
                          provider_id?, provider_auth_epoch?, redirect_uri,
                          pkce_challenge, pkce_method, audience, scopes,
                          protected_client_state, csrf_verifier,
                          confirmation_status, approved_at?, expires_at, consumed_at?)
OAuthAuthorizationCode(code_hash, tenant_id, request_id, client_id, principal_id,
                       provider_id, provider_auth_epoch, redirect_uri,
                       pkce_challenge, pkce_method, audience, scopes,
                       issued_at, expires_at, consumed_at?)
CLIRefreshCredential(token_hash, tenant_id, family_id, parent_id?, client_id,
                     principal_id, provider_id, provider_auth_epoch, audience,
                     scopes, issued_at, expires_at, consumed_at?, revoked_at?)
TrustSource(id, tenant_id, name, kind, exact_issuer, discovery_url?, jwks_keyset_id?,
            cluster_id?, token_review_endpoint?, ca_bundle_ref?, ca_fingerprint?,
            reviewer_credential_ref?, review_timeout_ms?, audiences, algorithms?,
            max_proof_lifetime, replay_mode, status, revision)
TrustKeyset(id, tenant_id, name, status, revision)
TrustKeysetVersion(id, tenant_id, keyset_id, public_jwks, fingerprint,
                   effective_at, expires_at?, status, provenance)
PrincipalBinding(id, tenant_id, trust_source_id, profile, claim_match_policy,
                 workload_principal_id, status, revision)
ServiceIdentity(id, tenant_id, name, allowed_audiences, max_scopes,
                max_resource_constraints, policy_check_mtls_identities,
                status, revision)
ServiceGrant(id, tenant_id, actor_principal_id, target_service_id?, mode,
             audiences, scopes, default_scopes?, resource_constraints,
             max_ttl, valid_until?, status, revision)
PolicyRevision(id, tenant_id, source_id, binding_id, grant_id, target_service_id?,
               source_revision, binding_revision, grant_revision, service_revision?,
               effective_constraints, created_at, invalidated_at?)
ConsumedAssertion(tenant_id, trust_source_id, replay_key_digest, digest_key_version,
                   consumed_at, retain_until)
AdminIdentity(id, status, created_at)
AdminCredential(id, admin_id, public_identity, trust_anchor_ref, status, revoked_at?)
AdminRoleBinding(id, admin_id, role, tenant_id?, status, revision)
RecoveryState(instance_id, bootstrap_closed, recovery_public_key,
               recovery_key_epoch, revision)
AdministrativeOperation(id, tenant_id?, actor_id, kind, request_digest,
                        expected_revision, challenge_hash?, expires_at?,
                        consumed_at?, outcome, audit_id)
IssuerKeyVersion(kid, algorithm, public_key, signing_key_reference, validity)
AuditEvent(id, tenant_id?, timestamp, actor, action, object_id,
           previous_revision, new_revision, outcome)
~~~

**Ownership/uniqueness:** globally unique stable IDs permit lookup; composite `(tenant_id, id)` references enforce same-tenant relationships. Sources have tenant-local unique names, **not unique issuer strings**. Two tenants can independently register GitHub, and one tenant can register two separately keyed Kubernetes clusters sharing an issuer. A source selector resolves exactly one candidate verifier; never trial other sources after rejection. `ServiceIdentity.id` references a same-tenant `svc_*` principal; direct grants require a null target, delegated grants a same-tenant service. Human mappings key on provider plus exact issuer/subject within tenant. Cross-tenant grants/bindings/keysets are forbidden in v0.1.

**Verifier union:** `oidc_discovery` requires discovery configuration; `uploaded_jwks` requires a same-tenant `TrustKeyset`; `kubernetes_token_review` requires stable cluster identity, fixed API endpoint, versioned CA and reviewer-credential reference plus audiences/timeouts. Reject irrelevant or contradictory verifier fields. Multiple live `TrustKeysetVersion` rows attach to the stable parent; a source does not point at one arbitrarily current version. Duplicate live `kid` values with conflicting keys are rejected. Secrets are external references, never ordinary config-export values.

**Ephemeral state:** native transactions/codes and optional refresh families carry provider ID/auth epoch for targeted invalidation. Session logout indexes include tenant/provider/subject and optional upstream `sid`. Replay uniqueness is the keyed digest of `(tenant, source_id, exact_issuer, verified_jti)` across all grants; preserve the digest-key strategy through its retention window so key rotation cannot bypass consumption. Consumed rows live until proof `exp` plus allowed skew. Provider rollback never resets epochs or resurrects consumed state. An encrypted DB restore must preserve consumption, or wait out outstanding credential/proof lifetimes before reopening issuance; redacted configuration import is not a replay-state restore.

**Instance-owned state:** issuer keys, operator identities/credentials and recovery anchors are not human-provider children. Role bindings are tenant-scoped except explicitly instance-scoped `security_admin`. Tenant audit rows and instance audit rows have distinct access checks. The backend live-check caller's registered mTLS identity is bound to a local service/tenant and its allowed audiences; a public application token is not a policy-check client credential.

### T10 — Schema and migration safety

- [ ] **T10.1** Implement migrations/indexes, strict tenant-safe references, typed verifier fields, soft disable/revisions and one active human provider per tenant. No cascading human-provider deletion into WIF/operator objects.
- [ ] **T10.2** Generate stable opaque tenant/principal/source/keyset/binding/grant/client IDs; preserve IDs through import/export and upgrades.
- [ ] **T10.3** Store keyed hashes of browser tickets, codes and refresh credentials, protect CSRF/PKCE state, and normalize timestamps/revocation. Never store raw replay proofs.
- [ ] **T10.4** Immutable policy snapshots, operator audit and optimistic concurrency/ETag; no silent lost updates or mutable interpretation of an old issued revision.
- [ ] **T10.5** Versioned redacted export/import covers all verifier kinds, keyset parents/versions, grants/default scopes, tenant ownership, stable OAuth clients and public operator metadata. Add semantic diff, dry-run, approval/preconditions and restore tests; exclude private keys, reviewer secrets and live credentials.
- [ ] **T10.6** Separate secret/key recovery and encrypted DB disaster recovery, including replay/one-time-state retention, bootstrap-closed state and rollback that cannot revive invalidated credentials.
- [ ] **T10.7** Define GitOps versus DB write precedence; missing imported config must not wipe live objects. Enforce the same operator roles as API writes.
- [ ] **T10.8** Property/integrity tests: two tenants sharing GitHub issuer, two clusters sharing issuer, cross-tenant references denied, stable selector resolution, no cyclic delegation and privilege ceilings.
- [ ] **T10.9** Reserve/implement durable OAuth client/request/code, optional refresh-family and consumed-assertion tables in M1; atomic one-time consumption/uniqueness shared across replicas. Handlers ship in M2/M4 without inventing migration-exempt state.
- [ ] **T10.10** Implement provider-indexed session deadlines and monotonic auth epochs; test coalesced last-seen writes, absolute caps, verified `sid` logout and switch/rollback targeting.

### T11 — Trust source registry and key lifecycle

- [ ] **T11.1** Register three kinds: `oidc_discovery`, `uploaded_jwks`, `kubernetes_token_review`; persist tenant, exact issuer, verifier config, audiences, proof limits, replay mode, status/revision. Issuer is not a uniqueness key.
- [ ] **T11.2** Discovery mode: exact issuer and approved HTTPS egress, SSRF-safe metadata/JWKS, bounded redirects/cache/refresh and key-confusion defense.
- [ ] **T11.3** Upload mode: public-only JWK types/algorithms/strength, bounded set size, unique nonconflicting active `kid`, explicit rotation overlap; reject private parameters.
- [ ] **T11.4** Bounded key caches, expiry/rotation health and no permissive fallback when verification keys are unavailable.
- [ ] **T11.5** Token `jku`, `x5u`, embedded `jwk` or unknown `kid` cannot alter configured trust.
- [ ] **T11.6** Audited disable/re-enable/rotation preserves source/binding/grant IDs and is independent of human-provider changes.
- [ ] **T11.7** Select one stable source ID, then validate that source's exact issuer/audience/algorithm/verifier; never infer trust by `kid` or search alternate sources on failure.
- [ ] **T11.8** TokenReview enrollment validates stable cluster ID, fixed endpoint, CA content/fingerprint, external reviewer-credential reference, review audiences/timeouts and explicit private egress. No request-supplied endpoints/credentials or silent local-JWT fallback.
- [ ] **T11.9** Implement `TrustKeyset` parent and version lifecycle with same-tenant ownership and overlapping active versions, no circular source/version reference.
- [ ] **T11.10** Test duplicate issuer registrations across tenants/clusters, invalid kind-specific fields, untrusted selectors and migration preservation of TokenReview CA/reviewer references.

### T12 — Internal principal and policy engine

- [ ] **T12.1** Resolve humans by tenant/provider/exact issuer/subject and workloads by tenant/source/verified claims to stable local principals; never use email or unverified tenant claims as authority.
- [ ] **T12.2** Deterministic AND matcher: configured missing claim denies; omitted optional predicate is unconstrained. Production GitHub profile requires exact immutable owner/repo IDs, explicit `event_name`, ref, environment and workflow identity; reusable-workflow identity when applicable. Reject incomplete configs and require approval for predicate removal.
- [ ] **T12.3** Resolve the explicitly selected grant, verify actor/tenant/status, derive its target/mode and apply audience/scope/resource/TTL ceilings. Two grants for one audience are not ambiguous when an ID is supplied.
- [ ] **T12.4** Delegated JWT `act` identifies the workload, `sub` the approved service; retain verified source run/job in audit. GitHub's human `actor` is not an authenticated SkyOAuth user.
- [ ] **T12.5** Direct and delegation modes mandatory; true impersonation disabled and conditional on ADR-006. Unsupported impersonation records remain inert and unchanged through export/migration; no fallback to another mode.
- [ ] **T12.6** Immutable effective `PolicyRevision` covers source/binding/grant/service ceilings. Link signed constraints to that revision and support current-status/revision rechecks in T26.
- [ ] **T12.7** Deny wrong subject/repo/owner/event/workflow/environment, absent required claims, disabled source/grant, wrong tenant/target, ambiguous bindings and escalation. Unselected grants never broaden a selected grant.
- [ ] **T12.8** Optional request scope uses only explicit nonempty grant defaults; reject absent defaults, empty/extra scopes, invalid defaults and mode/profile mismatch. Direct grants have no service target.
- [ ] **T12.9** Freeze constraint schema and action mapping with verifier fixtures: unknown fields/version or missing required resource dimension deny; backend canonical resource IDs are authoritative.

### T13 — Independent operator authority and recovery

- [ ] **T13.1** Implement separate `adm_*` identities and registered mTLS public-key credentials; local active credential/role checks on every request. No OIDC claims, WIF token, app session or email-based operator promotion.
- [ ] **T13.2** Tenant-scoped `trust_admin`, `provider_admin`, `auditor` and explicit instance `security_admin`; no implicit role inheritance. Enforce reads, writes, imports and credential/role changes at the same boundary.
- [ ] **T13.3** Private operator listener/API and local CLI plumbing with exact tenant scope, expected revisions, dry-run/diff, immutable audit and explicit disable/delete/widening approval. Separate provider mutations from WIF writes.
- [ ] **T13.4** One-time deployment-local bootstrap enrolls initial operator public credential and separate offline recovery public key atomically, records audit and durably closes bootstrap. Restart/config omission cannot reopen enrollment.
- [ ] **T13.5** Break-glass local command/socket verifies recovery-key proof over expiring one-time operation/arguments/revision challenge. Allow bounded operator restoration or validated provider switch/rollback only; no arbitrary WIF edit or token minting. Audit/alert, consume challenges durably and rotate recovery keys after use.
- [ ] **T13.6** Tests for forged upstream admin roles, compromised-IdP sessions, tenant role crossover, disabled operator keys, replayed recovery challenges, concurrent bootstrap and missing audit/store. All deny without independent authorization.
- [ ] **T13.7** Exercise operator restoration with human IdP unavailable; reserve switch/rollback recovery integration for T51.11. Document hardware-backed/offline key custody and separate DB/signer recovery limitations.

**Gate M1:** schema and protected restore preserve tenant/source/keyset/grant/client IDs and one-time/replay invariants. Policies are deterministic and tenant-safe; human-provider operations cannot mutate WIF/operator authority. Independent scoped configuration writes, one-time bootstrap and operator recovery work. Signer/JWKS implementation remains M2 / T20.

## 4. WIF, issuer and minimal bearer gateway — required (M2)

### T20 — SkyOAuth JWT issuer

- [ ] **T20.1** Publish stable issuer/token profile and JWKS; never pretend bridge tokens are upstream-issued. M1 defines persistence, M2 implements signer/JWKS.
- [ ] **T20.2** Asymmetric signer with explicit algorithm/kid, protected key, overlap, bounded `iat/nbf/exp`, `typ=at+jwt` and unique `jti`.
- [ ] **T20.3** Issue explicit audience/scope and signed tenant, grant, immutable effective policy revision and versioned constraints. Include workload `act` for delegation; no grant-ID-only authorization contract.
- [ ] **T20.4** Gateway/backend verification fixtures for issuer/audience/type/signature/time/key errors, missing constraints, unsupported versions and resource outside signed allowlists.
- [ ] **T20.5** WIF has no refresh credentials; clients reacquire source assertions and re-evaluate selected grants on renewal.
- [ ] **T20.6** Audit source/binding/grant/revision/run/audience decisions without JWT/key bytes; bounded non-sensitive metrics.
- [ ] **T20.7** Document offline bearer revocation window, Kubernetes verifier propagation limits and required T26 live checks for critical actions; no claim of instantaneous cancellation of in-flight work.

### T21 — Direct exchange and service-delegation extension

- [ ] **T21.1** Parse both form-encoded profiles from §2 with required source/grant selectors, exactly one audience and optional scope. Reject missing/duplicate/oversized parameters, unsupported proof combinations, requested subject/target overrides and unsupported resource/token types.
- [ ] **T21.2** Standard OAuth-shaped token/error responses, explicit granted scope/issued token type, no-store, no redirects, TLS and rate limits; clearly label the private grant extension.
- [ ] **T21.3** Select only the registered source adapter and validate the proof there; source selector itself grants no tenant/workload authority. No dynamic verifier endpoint or fallback to another cluster.
- [ ] **T21.4** Bind the verified workload to the selected same-tenant grant. Direct `subject_token` becomes workload `sub`; extension `actor_token` becomes `act.sub` and its grant supplies service `sub`.
- [ ] **T21.5** Explicit scopes must all fit current ceilings; omission uses only valid nonempty defaults or returns `invalid_scope`. Encode narrowed resources in the signed token, not just audit.
- [ ] **T21.6** Implement explicit source replay modes: default `reusable` accepts repeat valid proofs after fresh evaluation and returns a new JWT/JTI; `single_use` requires verified `jti` and atomically consumes its source-scoped digest across replicas/grants before issuance. Second concurrent attempt/missing JTI/store failure denies; crash may burn proof, so retry with a fresh proof. No cached-token idempotency promise.
- [ ] **T21.7** Fuzz parsing/selection and test direct versus delegation proof roles, two same-audience grants, missing/default/excessive scope and non-enumerating denial.
- [ ] **T21.8** Preserve consumed-proof uniqueness through digest-key rotation, human switch/rollback, replica failover and protected restore; purge only after proof expiry plus skew.

### T22 — GitHub Actions OIDC integration (mandatory)

- [ ] **T22.1** Register GitHub issuer `https://token.actions.githubusercontent.com` as a tenant-owned discovery source with fixed accepted audience/algorithms and explicit replay policy.
- [ ] **T22.2** Validate issuer/signature/audience/time, immutable repository owner/repo IDs, explicit `event_name`, ref/environment and workflow/job-workflow context required by the binding profile.
- [ ] **T22.3** Rust `skyoauth-client` obtains custom-audience GitHub OIDC through the documented runner interface, without static secrets or logging runner credentials.
- [ ] **T22.4** Minimal example uses `permissions: id-token: write`, stable source/grant IDs and the intended direct/delegation profile. Production example permits `event_name: push`, not unspecified events.
- [ ] **T22.5** Deny fork/PR threats, `pull_request_target`, `workflow_dispatch`, `issue_comment` and `workflow_run` against the push-only binding even when repo/ref/environment/workflow claims otherwise match; also test wrong owner/repo/branch/workflow/audience and absent required claims.
- [ ] **T22.6** Real GitHub OIDC -> exchange -> **M2/T25 Envoy bearer ext_authz** -> ConnectRPC authorization in a disposable environment; preserve run/attempt provenance in audit.
- [ ] **T22.7** Renewal obtains fresh source assertion; workload tokens are memory-only. Test reusable and single-use source behavior separately, including concurrent replay across replicas.

### T23 — Kubernetes/k3s federation (mandatory)

- [ ] **T23.1** Document projected service-account token with intended SkyOAuth audience, bounded lifetime and file rotation; clients re-read on renewal.
- [ ] **T23.2** Implement `kubernetes_token_review` using only the selected source's fixed endpoint/CA/reviewer reference; least-privilege TokenReview create permission, bounded request/timeout and explicit private egress.
- [ ] **T23.3** Set review audiences and require authenticated success, no error and compatible nonempty returned audiences. Validate expected issuer/time and returned SA name/UID plus required Pod identity; bind all to configured cluster/source.
- [ ] **T23.4** Deny wrong audience/cluster/SA, expired token and deleted-bound-object cases within the supported Kubernetes validation semantics. Test two independently keyed clusters with identical `iss`: selecting the other source must fail, never fall back.
- [ ] **T23.5** Rust provider re-reads projected file each renewal and caches only short-lived bridge credential in memory; no static app secret.
- [ ] **T23.6** Local JWT verification is a separately enrolled discovery/upload source with explicit stale-revocation limits, never a fallback when TokenReview fails.
- [ ] **T23.7** Preserve cluster IDs, endpoints, CA versions/fingerprints, reviewer references and claim bindings through human-provider switch/rollback; independent reviewer rotation does not recreate the source.

### T24 — Generic WIF issuer and uploaded JWKS

- [ ] **T24.1** Discovery and uploaded-public-JWKS sources share tenant/source/grant selection and policy semantics with other WIF adapters.
- [ ] **T24.2** Overlapping key rotation preserves `TrustKeyset`, source, binding and grant IDs; both versions valid only under their explicit time policy.
- [ ] **T24.3** Deny arbitrary issuer/fake keys/wrong algorithm/conflicting live `kid`, private-key upload and unsafe URLs; never cross tenant keyset ownership.
- [ ] **T24.4** Operator enrollment, rotation, disable and redacted export documentation includes stable parent/version relationships and secret exclusions.

### T25 — Minimal bearer-only Envoy path (M2, not M3)

- [ ] **T25.1** Implement generated Envoy Authorization Check v3 service on authenticated private listener; validate SkyOAuth bearer profile and preserve complete signed constraints.
- [ ] **T25.2** Bounded metadata only; no body buffering/proxying, no cookie authorization yet, reject dual cookie/bearer credentials, structured deny and fail closed on exception/store failure.
- [ ] **T25.3** Minimal SecurityPolicy/HTTPRoute protects the ConnectRPC test API; public exchange/discovery routing is separate and the auth listener is never public.
- [ ] **T25.4** Strip/overwrite client identity headers, authenticate internal channels, restrict direct backend access and prove backend verifies issuer/audience/constraints plus resource RBAC.
- [ ] **T25.5** Integration tests for GitHub/k3s bearer call, expired/forged token, wrong resource, spoofed headers, unprotected route, private-listener access and auth-service outage; these satisfy T22.6 without waiting for M3.

### T26 — Private live grant check (M2)

- [ ] **T26.1** Implement `POST /internal/v1/policy/check` on private listener. Authenticate backend mTLS against registered local service identity and allowed tenant/audiences; public app/WIF credentials alone cannot call it.
- [ ] **T26.2** Request contains access token plus backend-resolved canonical action and tenant/project/environment coordinates. Bound all input; no application payload, no token logging and no caller-asserted grant replacement.
- [ ] **T26.3** Verify full token and immutable snapshot, current principal/source/binding/grant/service status and time limits; deny superseded/invalidated effective revision. Enforce action scope and signed/current resource ceilings without broadening old tokens.
- [ ] **T26.4** Return request-bound allow/deny, checked revision and decision ID with no-store. Backend still checks RBAC; use only for that exact action/resource, no positive caching on critical operations and no reusable authorization capability.
- [ ] **T26.5** Test immediate denial for checks started after committed revocation, wrong backend audience/tenant, changed revision, unknown action/resource and DB/checker outage; demonstrate documented offline residual validity separately.
- [ ] **T26.6** Publish backend integration for destructive operations and bounded stream rechecks. Document race boundary: already-authorized work cannot be retroactively undone by a later revocation.

**Gate M2:** GitHub and k3s workloads call protected ConnectRPC **through Envoy/T25** without static application secrets or the human IdP. Signer/JWKS, both required exchange profiles, Rust WIF client, signed constraints and T26 live checks work. Push-only event negatives deny. Reusable replay succeeds only while otherwise valid; single-use replay has exactly one winner. All dependencies are in M0–M2.

## 5. Human OIDC, sessions and browser gateway (M3)

### T30 — Upstream human OIDC adapter

- [ ] **T30.1** Zitadel standards-based discovery with fixed callback, configurable provider adapter and issuer/ID-token verification.
- [ ] **T30.2** Authorization Code + PKCE S256, one-time state/nonce transaction bound to provider epoch and strict return-location allowlist.
- [ ] **T30.3** SSRF-safe metadata/JWKS, bounded timeouts, fail-closed outage handling and no token logging.
- [ ] **T30.4** Verified tenant/provider/issuer/subject -> stable human mapping; no email-only linking or upstream claim -> operator role promotion.
- [ ] **T30.5** Optional encrypted provider-token vault behind explicit feature flag; otherwise discard upstream OAuth tokens.
- [ ] **T30.6** Optional signed back-channel logout verifies issuer/audience/signature/events/sub-or-sid and replay; uses indexed provider/subject/sid session selectors, never free-form auth-context search.

### T31 — Browser opaque sessions

- [ ] **T31.1** CSPRNG tickets, keyed hashes, provider/epoch metadata and CSRF verifier in PostgreSQL; host-only `__Host-` Secure/HttpOnly/SameSite cookie, no JS token exposure.
- [ ] **T31.2** Require both idle and absolute deadlines plus live provider epoch; conservative throttled last-seen writes across replicas cannot revive an expired session or extend absolute lifetime. Document bounded early idle expiry due to coalescing.
- [ ] **T31.3** Same-origin no-store session endpoint returns browser-safe principal and CSRF only, no upstream roles or secrets.
- [ ] **T31.4** Origin/CSRF for unsafe cookie requests including Connect unary POST; reject cookie+bearer ambiguity.
- [ ] **T31.5** Tests for fixation/callback replay/CSRF/cookie confusion, each expiry independently, concurrent last-seen updates, revocation, provider switch and DB outage.
- [ ] **T31.6** Distinguish local logout from upstream SSO logout; use provider/sid targeting only after verified logout evidence.

### T32 — Browser extension to M2 gateway + ConnectRPC

- [ ] **T32.1** Extend the **existing T25** Authorization Check service with opaque-session support; do not defer the bearer implementation to this milestone.
- [ ] **T32.2** Apply cookie/Origin/CSRF semantics while preserving bounded metadata-only checks, full identity constraints, controlled headers and fail-closed behavior.
- [ ] **T32.3** Extend M2 routes for public login/session callbacks and protected browser RPC/events/downloads; no accidental bypass for newly added sensitive routes.
- [ ] **T32.4** Re-run header spoof/direct-backend/private-listener tests for browser as well as bearer; authenticated internal channels remain mandatory.
- [ ] **T32.5** Both cookie and bearer profiles now supported. Any optional native Envoy JWT optimization must preserve constraints, policy/revocation requirements and equivalent fail-closed behavior.
- [ ] **T32.6** Structured 401 for expired RPC auth, not HTML redirects; browser library performs top-level navigation.
- [ ] **T32.7** Connect unary/server-streaming, SSE and large artifact download pass directly Envoy -> backend; test cancellation/reconnect/idle limits and no SkyOAuth payload hop.
- [ ] **T32.8** Backend authorizes each workflow/artifact resource; bounded stream duration/rechecks/cancellation and T26 integration for designated critical bearer operations.
- [ ] **T32.9** Optional HTTP ForwardAuth adapter reuses decision semantics; trusted forwarded headers, private listener and equivalent tests.
- [ ] **T32.10** Document Cloudflare Tunnel placement separately from Access/WAF/rate-limit functions.

### T33 — Frontend libraries

- [ ] **T33.1** `@skyoauth/browser`: same-origin session/login/logout/CSRF, bounded session cache, no localStorage tokens.
- [ ] **T33.2** `@skyoauth/react`: explicit loading/unauthenticated/authenticated states and route examples.
- [ ] **T33.3** `@skyoauth/connect`: CSRF, gateway 401 versus Connect Unauthenticated/stream errors; no automatic mutation replay.
- [ ] **T33.4** Versioned JS APIs and stable SkyOAuth URL tests; no Zitadel imports/endpoints/config.
- [ ] **T33.5** Browser E2E for login/logout/reload/expiry/cross-tab state, CSRF and protected ConnectRPC.

**Gate M3:** browser uses only opaque session plus CSRF for protected multi-tenant APIs. Negative resource/gateway tests pass; streaming/download data bypasses SkyOAuth. M2 bearer behavior is unchanged.

## 6. CLI interface and upstream token delegation (M4)

### T40 — SkyOAuth native-client public OAuth profile

- [ ] **T40.1** Implement stable authorization metadata/endpoints and registered public clients using M1 schema; exact loopback rules and supported grant list.
- [ ] **T40.2** Broker upstream authentication, then require **fresh transaction-specific SkyOAuth confirmation** showing registered client, account, audience/scopes and loopback destination. Warn that public client ID does not authenticate the local program. Existing SSO or prior client consent cannot auto-approve a new request.
- [ ] **T40.3** Bind explicit approval/code to client, exact redirect, S256 challenge, audience/scopes, principal/provider epoch and expiry. CSRF/anti-framing on confirmation, one-time code redemption across replicas, native state checks and denial/expiry with no code.
- [ ] **T40.4** Issue scoped SkyOAuth API tokens only; no upstream tokens on CLI. A malicious local process with its own PKCE verifier and loopback port must not silently receive a code from an existing SSO session.
- [ ] **T40.5** Decide interactive-only versus optional rotating hashed refresh families in OS keychain. If included, bind provider epoch, detect family reuse and support revoke/switch invalidation. Do not call persistent refresh credentials secretless.
- [ ] **T40.6** Device flow only if explicitly scoped: user-code verification and equivalent explicit confirmation pages, expiring one-time approval, bounded polling and abuse tests. No interaction-bypassing fallback.
- [ ] **T40.7** Required Rust `crates/client` native API and `crates/cli` reference executable; existing client/Connect examples remain unchanged through provider migration after reauth.
- [ ] **T40.8** Tests for silent SSO, changed confirmation parameters, user denial, expired approval, concurrent code redemption across replicas and stale-provider transactions/codes/refresh families after switch/rollback.

### T41 — Provider adapter and Zitadel RFC 8693 support

- [ ] **T41.1** Human login/provider exchange trait with explicit capability detection and version-specific configuration; operator authority is a separate subsystem.
- [ ] **T41.2** Compatible authorized exchange of Zitadel-issued tokens can run server-side; respect real subject/actor semantics and normalize any downstream API token to SkyOAuth issuer/constraints.
- [ ] **T41.3** Verify deployed provider restrictions; never assume exchange of arbitrary GitHub/K8s assertions or new administrative audiences. Local WIF remains independent and required.
- [ ] **T41.4** No upstream administrative token returned through public exchange/delegation; separately restricted service-side adapter for provider administration when needed.
- [ ] **T41.5** Zitadel and replacement-provider tests show unchanged Rust client/CLI, metadata, API JWT/constraint profile and gateway contract.

**Gate M4:** CLI sees stable SkyOAuth issuer/endpoints, explicitly confirms each new authorization, and survives provider swap after reauth without reconfiguration. Native/code/optional refresh state uses M1 durability and epoch rules.

## 7. Operational safety, deployment and migration (M5)

### T50 — Kubernetes packaging and readiness

- [ ] **T50.1** Chart separates public, private gateway/policy and operator listeners; probes, non-root/read-only security context, resource limits, service accounts, NetworkPolicies and disruption settings.
- [ ] **T50.2** PostgreSQL migrate/backup/restore, two-plus replicas, one-time-state safety and rollback documentation.
- [ ] **T50.3** Isolate signer, reviewer credentials, operator/recovery keys and upstream admin adapter; documented recovery/rotation boundaries.
- [ ] **T50.4** Route policy smoke tests reject newly exposed sensitive paths and public access to internal/admin endpoints.
- [ ] **T50.5** Bounded requests, token/claim sizes, rate limits for exchange/login/discovery/native confirmation/admin and no sensitive cache fallback.
- [ ] **T50.6** Safe latency/denial/refresh/audit metrics; no PII/token labels or secret-bearing logs.
- [ ] **T50.7** SBOM, dependency/provenance scanning, vulnerability disclosure, patch policy and release docs.

### T51 — Human IdP migration *without WIF reconfiguration*

- [ ] **T51.1** Implement distinct independently authorized `human_provider_switch` plan/dry-run/commit/rollback, separate from source/binding/grant updates; expected revisions and audited provider-only write boundary.
- [ ] **T51.2** Snapshot stable tenant/principal/source IDs, **all three verifier configs**, TokenReview cluster/endpoint/CA/reviewer references, keyset parents/versions/fingerprints, bindings, grant modes/default scopes/constraints, policy fixtures, OAuth client registrations and issuer/operator public metadata. Record replay-state preservation without exposing proofs. Separately enumerate affected human transactions/codes/sessions/refresh families for invalidation, not equality.
- [ ] **T51.3** Prepare replacement provider/verified human links; dry-run rejects any WIF/operator/client-registration/gateway/signing-contract change. Operator access must not depend on linked upstream admins.
- [ ] **T51.4** Atomically switch only tenant human configuration and advance relevant auth epochs; invalidate affected sessions, pending login/native requests, unredeemed codes and optional refresh families. Preserve WIF policy/consumption and stable clients; document remaining lifetime of already-issued offline human JWTs.
- [ ] **T51.5** Previously built browser and required Rust CLI work after reauth with no binaries, environment variables, callback/client registration or deployment changes.
- [ ] **T51.6** Existing GitHub job, uploaded-JWKS workload and **two shared-issuer Kubernetes cluster fixtures** work without YAML/source/CA/reviewer/key upload/binding/grant/audience change. Exercise direct and delegated grants; impersonation only if included by ADR-006.
- [ ] **T51.7** Compare effective pre/post allow/deny fixtures, IDs/revisions and audit provenance. Single-use tests use fresh valid proofs; previously consumed proofs must remain denied.
- [ ] **T51.8** Roll back human configuration only with fresh monotonic epoch invalidation, never restore an entire DB snapshot over independent WIF changes or resurrect consumed codes/proofs/refresh credentials.
- [ ] **T51.9** Schema upgrades/protected restore preserve full stable and one-time-state models, including later CLI entities and keyset ownership.
- [ ] **T51.10** Prove no client/gateway/backend redeployment or certificate/signing-key rotation merely because the human provider changed.
- [ ] **T51.11** Rehearse switch and rollback with human IdP unavailable/unlinked admin accounts using T13 independent credentials; separately exercise audited break-glass recovery. Forged upstream admin roles cannot alter WIF or operator policy.

### T52 — Security conformance and hardening

- [ ] **T52.1** Malformed JWT/key corpus, algorithm/issuer confusion, malicious key URLs, private-JWK upload and overlapping-key lifecycle.
- [ ] **T52.2** Negative WIF owner/repo/event/ref/environment/workflow/cluster/tenant/grant/scope/resource fixtures; explicitly assert each replay mode's expected outcome.
- [ ] **T52.3** OIDC mix-up, nonce/state/PKCE and callback/code replay, native silent-SSO/confirmation attack, CSRF/fixation and provider-epoch rollback tests.
- [ ] **T52.4** Header spoof/direct-backend/private-listener access, fail-closed ext_authz, oversized headers and proxy-normalization/smuggling tests.
- [ ] **T52.5** Signer/operator/recovery compromise drills, overlapping/retired keys, suspicious issuance, audit integrity and redaction.
- [ ] **T52.6** Backend tenant/resource isolation, workflow termination/cancellation, artifact/stream controls and implemented **T26** online checks versus documented offline revocation limits.
- [ ] **T52.7** Fuzz token/policy/metadata/confirmation parsers; load tests on k3s/Envoy with concurrent code and proof consumption.
- [ ] **T52.8** Independent security review before stable release, including operator isolation and standard-versus-extension interoperability claims.

**Gate M5 / v0.1:** C01–C10 hold; real GitHub/k3s WIF, browser and required Rust CLI work; migration changes neither clients nor WIF trust/policy and cannot elevate IdP-controlled admins. Mandatory conformance tests pass; optional profile tests are conditional only where explicitly stated below.

## 8. Conformance matrix — automated release blocking

| ID | Scenario | Expected result |
| --- | --- | --- |
| A01 | Valid GitHub push with required repo/owner/ref/environment/workflow and selected grant | Scoped bridge JWT; only signed resource envelope authorized |
| A02 | Otherwise matching token but wrong/missing event, including `pull_request_target`, `workflow_dispatch`, `issue_comment`, `workflow_run`; or wrong owner/repo/ref/environment/workflow | Denied; push-only example cannot be satisfied by another event |
| A03 | Selected source issuer/JWKS/audience mismatch | Denied, no alternate verifier/key-source fallback |
| A04 | Uploaded keyset rotates with overlapping versions | Stable keyset/source/binding/grant IDs; old/new keys valid only under time policy |
| A05 | Private-JWK upload or token-controlled key URL | Rejected |
| A06 | Configured TokenReview accepts bound SA/Pod and intended audience | Scoped token for that source's tenant/cluster |
| A07 | Wrong cluster/SA/audience, expired proof or deleted bound object | Denied under documented TokenReview semantics, never local-JWT fallback |
| A08 | Browser cookie with valid CSRF/Origin | Edge permits; backend resource RBAC still required |
| A09 | Unsafe cookie call lacks CSRF or correct Origin | Denied |
| A10 | Cookie plus bearer in one request | Denied ambiguity |
| A11 | Revoked/expired browser session or unavailable store | Appropriate 401/503, never fail-open |
| A12 | ConnectRPC stream/artifact download | Direct Envoy -> backend data; bounded authorization lifetime/recheck |
| A13 | Valid token/session used outside tenant/project/environment | Backend denies from signed envelope plus resource RBAC |
| A14 | Zitadel -> replacement provider with existing browser and Rust CLI | Same endpoints/config/packages; human reauth only |
| **A15** | **Migration with discovery, uploaded-JWKS and two shared-issuer TokenReview sources** | **Stable configs/CA/reviewer refs/keysets/IDs; unchanged allow/deny behavior and existing workload configs** |
| **A16** | **Migration with workload bindings, direct and service-delegation grants** | **Same IDs/modes/default scopes/constraints/revisions and decisions. Active impersonation tests conditional on ADR-006; unsupported stored records remain unchanged/inactive.** |
| A17 | Human provider rollback after independent WIF change | WIF untouched; epochs advance; consumed/auth-invalidated state not resurrected |
| A18 | Client-spoofed gateway identity headers | Removed/overwritten; no privilege escalation or lost constraints |
| A19 | Independent bridge signing-key rotation | Clients/backend verify during overlap, no config change |
| A20 | Human provider unavailable | Valid WIF and independent operator recovery still work; fresh human login fails closed |
| A21 | Disable grant while issued JWT exists | New issuance denied; offline JWT has documented residual TTL; T26 checks after commit deny |
| A22 | Email-only human linking or upstream admin-role claim | No automatic user linking or operator elevation |
| A23 | Replay same valid proof on default reusable source | Re-evaluate policy; may issue new token/JTI within validity, never bypass revocation |
| A24 | Replay/concurrent exchange on single-use source, including other grant and replica | Exactly one issuance; later attempts, missing JTI or unavailable replay store deny |
| A25 | Two grants share audience, e.g. direct versus delegation/two target services | Explicit grant selector chooses one; wrong actor/tenant/profile/target override denies |
| A26 | Omitted scope with/without explicit grant defaults; empty/excessive scope | Narrow defaults only; otherwise `invalid_scope`, never all allowed scopes |
| A27 | Live SSO plus malicious local public-client request with own PKCE/loopback | SkyOAuth confirmation required; no silent code; denial/expiry yields no code |
| A28 | Two clusters share exact issuer but independent signing trust | Selected cluster validates its own proof; wrong selection denies, no probing/fallback |
| A29 | Two tenants independently register GitHub; cross-tenant keyset/binding/grant attempt | Registrations coexist; ownership crossover denied |
| A30 | Token omits constraints/revision or uses unknown constraint schema/field | Backend fails closed; grant ID alone insufficient |
| A31 | Policy check wrong backend identity/audience/tenant/action, superseded revision or outage | Denied; no cached allow or RBAC replacement |
| A32 | Bootstrap races, restart, forged IdP admin, revoked operator, replayed recovery proof | One enrollment only; no reopened bootstrap/elevation/replay; audited independent recovery |
| A33 | Session idle/absolute expiry, coalesced writes and provider/sid targeting | Either deadline denies; no revival/absolute extension; only correctly selected sessions revoked |
| A34 | Concurrent native code redemption, optional refresh reuse, human switch/rollback | One-time semantics across replicas; affected auth state invalid; OAuth clients unchanged |
| A35 | Provider switch/rollback or protected restore after proof consumption | Consumed assertions remain denied; no reset through epoch/config import or digest-key rotation |
| A36 | Real GitHub/k3s -> M2 Envoy -> ConnectRPC; spoof/outage/direct-backend attempts | Positive bearer path works in M2; all bypass/fail-open cases deny before M3 |
| A37 | Production binding omits event/required predicate; optional predicate omitted | Incomplete production config rejected; generic optional omission explicitly unconstrained and deletion treated as widening |
| A38 | Device flow or true impersonation not included in release | Not advertised/accepted; stored unsupported policy inert. If included, its full security/confirmation/migration tests become blocking. |

All unconditional rows are release-blocking. Optional refresh/device/active-impersonation subcases are conditional on the reviewed release scope; unsupported-path rejection and preservation of inert stored policy are unconditional. This does not make required direct delegation, native confirmation, operator recovery or live checks optional.

## 9. Recommended delivery order and issue breakdown

| Order | Block | Prerequisites | Output |
| --- | --- | --- | --- |
| 1 | M0 / T00 | None | Reviewed profiles, tenant/admin/confirmation/replay decisions and threat matrix |
| 2 | M1 / T10–T13 | M0 | Full schema, three-kind registry/keysets, principals/policy, scoped operator bootstrap/recovery |
| 3 | M2 / T20–T26 | M1 | Signer/JWKS, WIF profiles, Rust workload client, bearer Envoy path and live grant checker |
| 4 | M3 / T30–T33 | M1 and M2 bearer/identity contract | Human OIDC/sessions, browser extension to gateway, frontend SDKs |
| 5 | M4 / T40–T41 | M2, M3 and M1 OAuth state | Native confirmation/code flow, required Rust client/CLI, optional upstream delegation |
| 6 | M5 / T50–T52 | All above | Packaging, operator-outage recovery, zero-reset migration and conformance |

Suggested reviewable implementation boundaries: schema/models; operator/bootstrap; registry/keysets; grants/evaluator; signer/JWKS; exchange/GitHub; TokenReview; **bearer ext_authz and live check before M2 close**; OIDC/session/browser gateway; browser SDK; native confirmation/Rust CLI; provider adapter; deployment; migration/security tests. Keep implementation and docs-only PRs distinct.

## 10. Definitions of done

**Protocol DoD:** versioned specs/examples distinguish RFC direct exchange from the service-delegation extension, define selectors/default scopes/constraints/replay and expose no upstream human-provider identifier to clients.

**WIF DoD:** administrators independently configure discovery, uploaded public JWKS with stable keyset versions, or per-cluster TokenReview; bind verified claims to workloads and grant required direct/delegated service access. GitHub and Kubernetes clients use no static application API secrets. True impersonation is conditional, not a prerequisite for declaring required delegation complete.

**Gateway DoD:** M2 bearer calls pass through authenticated, fail-closed Envoy ext_authz; M3 adds cookie/CSRF. Data goes directly Envoy -> backend, signed constraints are preserved and private endpoints/direct-backend access are restricted.

**CLI DoD:** required Rust client and reference CLI use stable SkyOAuth endpoints, S256 PKCE and fresh transaction-specific user confirmation; multi-replica one-time codes and optional refresh revocation work without provider-specific client configuration.

**Administration DoD:** private operator authority is independent of upstream human authentication; local scoped roles, closed bootstrap, separate recovery key and audited break-glass work during provider outage without granting general WIF-policy bypass.

**Migration DoD:** only affected human configuration/authentication state changes. Clients, gateways, all source kinds/CA/reviewer references, keysets, bindings/grants, issuer keys, OAuth registrations and effective WIF decisions remain stable; consumed WIF proofs remain consumed. No admin reset or upstream account link is needed for operator recovery.

**Security DoD:** every issued WIF identity traces to source + binding + selected grant/revision and signed resource constraints; backend RBAC remains authoritative, live checks have implemented fail-closed behavior, and all unconditional A01–A38 scenarios are demonstrable.

## 11. ADR decisions for maintainers

These directions synchronize the proposed design and implementation plan. Ratify before implementation; a changed decision must update both documents and its tests.

| ADR | Decision | Proposed starting direction |
| --- | --- | --- |
| ADR-001 | Issuer/discovery | One canonical stable HTTPS issuer, independent of human providers |
| ADR-002 | Signing keys/backup | Asymmetric kid/overlap, isolated key references; implementation M2/T20 |
| ADR-003 | Session/store | PostgreSQL keyed-hash tickets, explicit idle/absolute/provider epoch fields |
| ADR-004 | Native public OAuth | Required Rust PKCE loopback + fresh SkyOAuth confirmation; optional refresh/device explicitly scoped |
| ADR-005 | WIF verification | Three source kinds; stable source selector, per-cluster TokenReview config, stable keyset parent |
| ADR-006 | Delegation/impersonation | Direct and actor-attributed delegation required; true impersonation disabled/conditional, stored policy preserved inert |
| ADR-007 | Identity propagation | Authenticated internal channels, complete constraint envelope, no client identity headers |
| ADR-008 | Policy writes | PostgreSQL + revisioned scoped GitOps; independent operator auth and explicit widening/deletion approval |
| ADR-009 | Zitadel exchange | Optional compatible upstream exchange; always normalize downstream API credential |
| ADR-010 | Critical-operation revocation | Short offline JWTs plus mandatory M2/T26 private, backend-authenticated live check |
| ADR-011 | Multi-cluster issuer | One bridge authority; source IDs disambiguate Kubernetes clusters, never issuer alone |
| ADR-012 | Migration | Provider-only config + monotonic human auth invalidation; all WIF/client/operator invariants retained |
| ADR-013 | Administrator trust/recovery | Independent registered operator keys, local scoped roles, closed local bootstrap, separate offline recovery |
| ADR-014 | Tenant ownership | Tenant fields/composite references, nonunique external issuer, same-tenant keyset/binding/grant |
| ADR-015 | Exchange interoperability | RFC 8693 direct subject exchange versus explicit private actor-based service mapping; source/grant selectors and narrow scope defaults |
| ADR-016 | Replay/constraints | Reusable default versus atomic source-scoped single-use; signed versioned constraints and effective revision |

## 12. Normative references

- [Architecture and roadmap](skyoauth-design.md)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html) (§2.1 / Appendix A subject and actor semantics; §4.1 `act`)
- [RFC 9700 — OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 8252 — OAuth for native applications](https://www.rfc-editor.org/rfc/rfc8252.html) (§8.6 native-client impersonation)
- [RFC 8725 — JWT best current practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [GitHub OIDC docs](https://docs.github.com/en/actions/reference/security/oidc)
- [Kubernetes TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
- [Envoy Gateway extAuth](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
