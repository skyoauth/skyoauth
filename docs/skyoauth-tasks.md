# SkyOAuth — Detailed design, implementation tasks, and release gates

> **Status:** proposed implementation plan. Paired with [skyoauth-design.md](skyoauth-design.md). All authentication checkboxes remain **unchecked**. The landed service/health-client scaffold is not an implementation of these security contracts.

## 0. Delivery principles

The central outcomes are **secretless GitHub Actions → protected cluster API WIF** and **zero-client-change / zero-WIF-reset human IdP migration**. Browser sessions, gateway integration, a **TypeScript library for SPAs** and a **reusable Rust client crate for CLI applications** are all required before v0.1. A Node-only library or a repository-local Rust executable alone does not satisfy the client requirements.

- Human migration may require reauthentication, not changes to client/backend binaries, packages, settings or deployments. Preserve every source kind, keyset, binding, grant, audience assignment, client/origin registration and effective WIF decision.
- Envoy is the application data plane. SkyOAuth processes bounded authentication/authorization metadata, never uploads, downloads or stream bodies.
- The stable issuer and signing keys are independent of the human IdP. Explicit private credential profiles separate WIF access, human CLI access and gateway-only human-session assertions.
- Instance-owned resource-server/audience authority bounds tenant policy; services a workload acts as are not resource servers or policy-check callers. Canonical backend tenant mapping and RBAC remain mandatory.
- Direct workload and attributed service delegation are required. Active true impersonation is outside v0.1; retain only disabled/reapproval-required policy preservation. Its future activation subsystem is deferred, not a release prerequisite.
- Standard RFC 8693 direct exchange and the single-proof service-delegation extension are distinguished. No incomplete RFC 9068 `at+jwt` claim: use the private types defined in design §6.
- The only active-provider write path is an authorized switch transaction with epoch invalidation. PATCH/import/config reload cannot bypass it.
- Operator/recovery/reviewer keys are privileged operational trust anchors, not static application API secrets. No SPIRE/sidecar/cloud STS dependency is required.
- Both client profiles have package, real-runtime and migration tests. Share wire/error fixtures, not browser-unsafe token APIs or server dependencies.
- Required M4 native refresh keeps access credentials at a maximum 300-second lifetime without a browser prompt on every renewal; persistent refresh remains a sensitive revocable credential, not a static API key.
- Every security requirement needs positive and negative tests; the tasks below do not claim they are already implemented.

**Workload-first sequence:** specify the complete logical model in M0, implement workload authority in **M1a**, and let **M2 WIF proceed after M1a**. Human authority/state is **M1b**, parallelizable with M2 but required before M3. Do not require human tables, browser/native UX or a tenant-management UI before the first usable workload slice. Full v0.1 still requires both libraries, human migration and all applicable security gates; explicit tenant/audience isolation is retained. Design §1.3 records this scope decision.

## 1. Repository layout and bootstrap integration

PR #2 landed in `main` at `8f81df23efd4c4a0cfe522f711a9ca56f294aab1`, establishing `service/`, a Cargo workspace, `clients/typescript/` and CI. Retain these homes. The following is a target layout; most auth modules are planned, not present. Add members with their implementations, not empty scaffolding that implies authentication support.

~~~text
Cargo.toml            Existing service member; add operator, clients/rust, cli with code
service/              Existing skyoauth-service (Axum/Tokio)
  src/main.rs         Process/listener wiring; M1a local bootstrap/recovery verifier
  src/lib.rs          Service composition
  src/core/           Proposed tenant/principal/profile/decision types
  src/config/         Validated configuration and reloads
  src/persistence/    PostgreSQL repositories, revisions and transactions
  src/admin/          Independent operator roles, bootstrap and recovery
  src/registry/       Resource servers, audiences/actions, clients and origins
  src/route_control/  M3 separately deployed route-control subcommand and observers
  src/oidc/           Upstream human adapter and browser-bound transcripts
  src/session/        Opaque sessions, CSRF and logout
  src/trust/          Source/keyset registry and verifier lifecycle
  src/federation/     GitHub, TokenReview and generic verification
  src/policy/         Grant-directed bindings, human policy, constraints
  src/exchange/       Direct RFC exchange and service-delegation extension
  src/issuer/         Private token profiles, signer/JWKS lifecycle
  src/gateway/        Envoy and optional ForwardAuth decision adapters
clients/
  typescript/         Existing npm @skyoauth/client; required SPA library M3
    src/              Framework-neutral session/transport core
    src/react/        Planned @skyoauth/client/react optional-peer entry
    src/connect/      Planned @skyoauth/client/connect optional-peer entry
    test/             Unit/type/package and real-browser tests
  rust/               Planned Cargo skyoauth-client reusable library
    src/              WIF M2; native PKCE M4; redacted credential/provider APIs
    tests/            Protocol, feature, transport and native-platform tests
operator/             M1a skyoauth-operator workstation client; Linux/macOS/Windows
cli/                  Planned skyoauth-cli: thin application-library consumer M4
crates/               Only extracted shared/server libraries when justified
examples/
  spa/                Consumer of packed npm artifact
  rust-cli/           Independent consumer of packaged Rust crate
deploy/
  helm/skyoauth/      Probes, security context, NetworkPolicies, chart
  examples/envoy/     M2 bearer and M3 session route/security policies
  examples/k3s/       Projected tokens and per-cluster TokenReview RBAC
  examples/github/    No-static-secret caller with generated source/grant IDs
tests/
  conformance/        Versioned wire/profile and migration fixtures
  security/           JWT/OIDC/CSRF/admin/tenant/audience/replay/gateway tests
  integration/        PostgreSQL, mock OIDC, two clusters, Envoy and ConnectRPC
scripts/ci/           Existing docs-only detection; expand checks with new code
docs/
  skyoauth-design.md
  skyoauth-tasks.md
~~~

Server boundaries can start as modules; extract crates for dependency isolation or reuse, not directory count. The Rust client must not depend on the service, PostgreSQL, operator internals or frontend assets. npm `@skyoauth/client` and Cargo `skyoauth-client` are intentionally parallel names in different registries; Rust imports `skyoauth_client`. Documentation and examples identify the language/distribution explicitly.

**M1a `operator/` publishes `skyoauth-operator`**, a portable Linux/macOS/Windows private mTLS client and recovery-challenge signer, independent of server/database dependencies and M4 native OAuth. The existing service binary retains only the deployment-local bootstrap/recovery verifier. Recovery challenges cross an independently authorized local channel; private operator/recovery keys remain on the workstation or hardware signer, never copied into a pod. M1b adds human provisioning/transition commands to the same operator client. `cli/` remains the separate M4 application/reference consumer.

The existing TypeScript arbitrary-baseUrl `health()` helper is unauthenticated bootstrap functionality. It cannot define the future authenticated session transport's origin boundary. Keep `@skyoauth/client` as the browser core rather than creating competing `packages/browser` or `crates/client` homes. Future TypeScript workload helpers are additional nonbrowser surfaces. The M3 `skyoauth-service route-control` process is a separate least-privilege deployment of the route_control module, not part of either client library.

Implementation PRs adding/moving modules, workspace members or package entry points update manifests/exports, lockfiles, CI paths/build/test/coverage, package-consumer examples and README together. Preserve the bootstrap's docs-only skip behavior; a skipped job is not a passed runtime test.

## 2. Public and operator contract — specification tasks

### T00 — Protocol and threat model (M0)

- [ ] **T00.1** Freeze public issuer/token/JWKS, app-origin auth, issuer-native callback/confirmation/refresh/revoke, private gateway/live-check/session-recheck/session-close/internal-key, scoped route preparation/result/list/read/claim/transition/observation and operator approval boundaries. Cleanup/revocation must not depend on the application route gate.
- [ ] **T00.2** Version errors, no-store, cancellation and non-enumerating failures. Separate 401 authentication, 403 authorization, 429 per-session too_many_open_streams/rate_limited and 503 shared stream_capacity_unavailable/route_configuration_unavailable (Connect unavailable). Define finite retry budgets and the one delayed per-session recovery retry; never a login prompt for infrastructure/capacity or mutation replay.
- [ ] **T00.3** Specify exact protected types `skyoauth-access+jwt` and `skyoauth-internal+jwt`, signed profile/version and required WIF/human_cli/human_session claim sets. Reject profile/ingress mismatches and ID tokens; do not advertise RFC 9068 compliance or emit `at+jwt`.
- [ ] **T00.4** Freeze issuer, audience registry, principal kinds, scopes, claim namespace and constraints. WIF uses explicit allowlists; human profiles explicitly use backend_rbac mode with mandatory canonical tenant/scope/RBAC checks. Persist action-to-scope/profile/resource rules; unknown modes/fields/versions deny.
- [ ] **T00.5** Freeze exact digest binding and all-route credential containment: ordinary HTTPRoute RequestHeaderModifier removes Cookie/X-SkyOAuth-CSRF after any required auth; ResponseHeaderModifier removes every Set-Cookie on non-SkyOAuth routes, including public/health/static routes with no Check. Pin exact backend-identity-bound auth exemptions and actual filter order, not an unspecified selective-cookie filter. Define security-revision-bound recovery, mode-bound registry-only versus gateway activation and exact bounded abort authority, and protected-scope projection including shared listener dependencies but excluding disjoint virtual hosts and only proven-inert filters. Include controller-token/mTLS-key sandbox denial tests and effective-filter override/order fixtures. M3 isolated controller preparation computes expected xDS before approval; M1b only supplies pending/result contracts. Pin EG/egctl/Envoy/bootstrap, complete inputs, management GET masks and adapter fixtures; no caller hash or whole-shared-dump shortcut.
- [ ] **T00.6** Specify session/flow/code/epoch/restore lifetimes, access <=300s/internal evidence <=30s and refresh defaults 12h/1h with explicit 7d/24h ceilings and no existing-family extension. Browser leases default/critical <=15s, opted-in noncritical <=300s/context <=1h. Route polling <=10s, stale alert 30s, equivalent verified deployment evidence <=300s from collection start; gateway apply/mismatch has no allowance. Registry-only activation preserves sample ages and cannot extend the deadline. Planned apply returns unavailable for unchanged contexts with no lease extension; changed dependencies deny. Record full-origin apply interruption and cleanup independence in ADR-010/ADR-020. Forward approval expiry and a separately approved finite abort_until have distinct execution meanings; neither stale evidence nor compensation extends a stream lease.
- [ ] **T00.7** Threat model malicious CI, issuer/cluster/key confusion, audience/tenant escalation, subject/resource-server confusion, profile substitution, replay, **login CSRF, OIDC callback abuse, redirect URI confusion, identity-linking confusion**, native-client impersonation, generic-provider-write bypass, cookie leakage to backends, shadow routes, operator recovery and runtime/database compromise.
- [ ] **T00.8** Ratify distinct public/internal signer isolation and separately held eligible standby, live standby-use tripwire with explicit offline limitation, native comparison/required refresh, signed internal evidence and minimal dormant-policy preservation. Device flow, provider vault/exchange and active impersonation remain separately scoped future features.
- [ ] **T00.9** Specify RFC 8693 direct subject exchange versus private service-delegation actor grant, selector/proof roles, grant-directed binding evaluation, narrow scope defaults, errors and unsupported two-token delegation. Private grant URI is not claimed IANA-registered.
- [ ] **T00.10** Ratify independent adm identities, local roles, portable M1a workstation client, deployment-local verifier and offline-key custody. Split workload provisioning M1a from human provisioning M1b; upstream claims cannot assign operator rights.
- [ ] **T00.11** Define tenant ownership/composite references, instance audience assignment and canonical-origin ownership, nonunique issuer strings and same-issuer cross-tenant/cluster fixtures.
- [ ] **T00.12** Define matcher omission and source-capability replay semantics: required production claims cannot be omitted; reusable default; single-use only verified on-demand JWTs, never projected Kubernetes/TokenReview sources.
- [ ] **T00.13** ADR-017: both client library contracts, package/crate identities, supported browser/native environments, typed errors and migration fixtures; no SPA OAuth-token API or required server dependency in the Rust crate.
- [ ] **T00.14** Adopt the bootstrap-aware layout in §1, distinguish existing health scaffold from proposed auth, and specify manifest/CI/packaged-consumer gates.
- [ ] **T00.15** Ratify ResourceServer/AudienceTenantAssignment/ResourceAction/checker ownership and explicit HumanAccessPolicy/credential profile sources; no free-string self-assignment or subject-prefix exemption.
- [ ] **T00.16** Freeze origin/route tenant-audience resolution, app/native flow cookies, enrollment policy/hold, exclusive provider semantic transitions versus credential-only rotation, generated-ID lifecycle and disabled-only impersonation preservation. Keep operational capacity revisions out of pinned authorization versions.
- [ ] **T00.17** Freeze request-comparison vectors, plain OAuth refresh versus optional retry-extension semantics, continuation close/recheck/admission races and M1a/M1b dependencies. Rust always uses the retry ID, but standard clients may omit it. Preserve security invariants while deferring active impersonation and optional UX/subsystems.

**Gate M0:** reviewed schema/profile/wire examples and threat matrix; no client requires an upstream issuer. Both client profiles, browser binding, audience authority, admin writes, scope omission, binding overlap and replay behavior have fixed expected results.

### Endpoint matrix

| Method / transport | Endpoint | Caller / role | Required behavior |
| --- | --- | --- | --- |
| GET | App `/_skyoauth/login` | Browser on registered origin | Resolve tenant/provider from active pinned ApplicationOriginVersion; create browser-bound transaction and validated return |
| GET | App `/_skyoauth/callback` | Upstream via initiating browser | Require app flow cookie plus state/nonce/PKCE/provider/epoch/origin; one-time consume |
| GET | App `/_skyoauth/session` | Browser | Safe session/principal + CSRF only; no-store |
| POST | App `/_skyoauth/logout` | Browser | Origin/CSRF, revoke session/context, expire cookie |
| GET | Issuer `/.well-known/oauth-authorization-server` | OAuth clients | Stable metadata; advertise implemented grants/profiles only |
| GET | Issuer `/.well-known/jwks.json` | Verifiers | Public signer overlap, M2 |
| GET | Issuer `/oauth/authorize` | Native public client via browser | Resolve registered client/tenant, validate redirect/PKCE/audience/scopes; set issuer-native flow cookie |
| GET | Issuer `/oauth/callback` | Upstream via initiating native-flow browser | Require native flow cookie + state/transcript; bind verified human and rotate cookie before confirmation |
| GET / POST | Issuer `/oauth/confirm` | Browser with completed native transaction and rotated issuer cookie | Show server-derived CLI comparison/port/session duration; explicit match/approve/deny, exact Origin/CSRF/anti-framing; transaction ID/app cookie alone insufficient |
| POST | Issuer `/oauth/token` | CLI/WIF | Supported grants/proof roles, registered audience assignment, profile-specific credentials; native refresh works without private retry ID |
| POST | Issuer `/oauth/revoke` | Registered native client with its refresh credential | Required M4; revoke matching local family, non-enumerating response |
| gRPC | `envoy.service.auth.v3.Authorization/Check` | Private authenticated Envoy | M2 bearer; M3 session/CSRF and internal assertion, consume browser cookies/CSRF before backend; explicit fail-closed 503 mapping |
| GET | Private `/internal/auth/check` | Trusted ForwardAuth | Optional equivalent typed decision adapter with reviewed deployment enforcement; never public |
| POST | Private `/internal/v1/policy/check` | Registered resource-server checker | Exact profile/action/resource checks; optional stream admission only from unexpired human_session evidence; distinguish deny/unavailable |
| POST | Private `/internal/v1/policy/recheck-session` | Same registered checker as established stream | Single item or <=100-item/64 KiB batch, bound per-item allow/deny/unavailable/deadline; unavailable grants no lease and is not terminal |
| POST | Private `/internal/v1/policy/close-session` | Same currently authorized checker, bound nonce/context | Idempotent single/batch release; atomic closed_at/quota update, no live user session or assertion required, no authorization lease |
| GET | Private `/internal/v1/assertion-jwks` | Authenticated checker/gateway trust consumer | Versioned signer-group public set, <=60s freshness/readiness rules; eligible standby already present, separate from issuer JWKS |
| GET / POST / PATCH | `/admin/v1/internal-assertion-keys` | Instance security_admin | Audited group-key enrollment/rotation/disable and eligible-standby promotion; protected key references only, separate standby custody |
| POST | App `/_skyoauth/oidc/backchannel-logout` | Configured upstream IdP | Optional signed logout/replay verification and indexed session targeting |
| GET / POST / PATCH | `/admin/v1/tenants` | Instance security_admin | Create/disable tenants, generated IDs, no implicit role inheritance |
| GET / POST / PATCH | `/admin/v1/resource-servers` | Instance security_admin | Globally unique exact audience and allowed profile/scope/schema registry |
| GET / POST / PATCH | `/admin/v1/resource-servers/{id}/tenant-assignments`, `/checker-identities`, `/actions` | Instance security_admin | Assign tenants/ceilings; register receiver mTLS identities and action rules, never token-subject credentials |
| POST / PATCH | `/admin/v1/application-origin-registrations` | Instance security_admin | Enroll canonical HTTPS origin and tenant ownership; validate ingress/callback mapping, reject collisions |
| GET / POST / PATCH | `/admin/v1/route-controller-identities` | Instance security_admin | Register independent controller mTLS identity and gateway/origin scope; no signer, WIF or human authority |
| GET / PATCH | `/admin/v1/instance-capacity-policy` | Instance security_admin | Independent operational revision, session ceiling 1–64 and finite shared quotas/rates; no credential or bundle invalidation |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/principals`, `/services` | Tenant trust_admin | Workload/service principal creation only; service and svc principal atomic; no human/operator escalation |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/trust-sources`, `/keysets`, `/bindings`, `/grants` | Tenant trust_admin | Same-tenant IDs, registered audience ceilings, typed verifiers, disable/revisions and explicit widening approval |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/oauth-clients`, `/human-access-policies` | Tenant client_admin | Registered native clients/generated client IDs and bounded human issuance policy |
| GET / PATCH | `/admin/v1/tenants/{tenant}/application-origins/{id}` | Tenant client_admin | Read active/staged versions; configuration PATCH appends an unpinned version, cannot change origin ownership or active values |
| GET / PATCH | `/admin/v1/tenants/{tenant}/application-origins/{id}/capacity-policy` | Tenant client_admin | Separately revisioned per-session cap, default 8 within current instance ceiling; lower only new admissions |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/application-origins/{id}/routes` | Tenant client_admin | Append staged immutable route versions; deterministic mapping/precedence, no automatic activation |
| POST | `/admin/v1/tenants/{tenant}/application-origins/{id}/disable`, `/routes/{route}/disable` | Tenant client_admin; ownership administration remains instance-scoped | Immediately set disabled and advance security_revision; invalidate captured pending-plan preconditions. Only explicit reenable_targets in freshly reviewed activation may clear named statuses; no generic PATCH/import clear |
| GET / POST | `/admin/v1/tenants/{tenant}/route-bundles` | Tenant client_admin | Create/read stable bundle parents and inspect pending/prepared versions; cannot supply trusted expected digests or deployment approval |
| POST | `/admin/v1/tenants/{tenant}/route-bundles/{id}/preparations` | Tenant client_admin | Store immutable route_bundle_prepare AdministrativeOperation with input snapshot/digest, active-generation/security preconditions, activation_mode and explicit recovery intent; no deployable version until trusted preparation completes |
| POST | `/admin/v1/tenants/{tenant}/route-bundles/{id}/versions/{version}/approve` | Instance security_admin | Approve completed prepared version only; expiring operation binds full plan digest, active generation, all affected parent security revisions, reenable_targets, scopes, adapter inputs, activation_mode and exact abort_plan; gateway_apply also binds finite abort_until separate from forward expires_at. Show interruption/recovery scope; recheck before mode-matched execution |
| GET | Private `/internal/v1/route-bundles` | Registered scoped controller mTLS identity | Bounded cursor-paginated discovery of pending preparations and prepared/approved/active work within enrolled scope; filters/cursors cannot broaden access |
| GET | Private `/internal/v1/route-bundles/{id}` | Registered scoped controller mTLS identity | Read scoped preparation input/prepared plan and durable active/applying/deployment generation, epoch/sequence; no arbitrary tenant data |
| POST | Private `/internal/v1/route-bundles/{id}/preparations/{operation}/result` | Registered scoped controller preparation worker | Bind result to exact pending input/preconditions; finalize one immutable version and server plan digest. Exact repeats converge, conflicting/stale results reject; no gateway writes or deployment approval |
| POST | Private `/internal/v1/route-bundles/{id}/claim` | Registered scoped controller mTLS identity | Allocate durable fenced ownership epoch/lease; no approval or observation-age reset |
| POST | Private `/internal/v1/route-bundles/{id}/transitions` | Current scoped controller owner | Mode/approval/security-CAS begin/activate only for gateway_apply; activate_registry_only only for registry_only with identical deployment inputs/fresh evidence/no recovery targets. abort/complete_abort compensate a begun attempt using only its exact retained abort_plan, unrevoked authority and abort_until; preserve newer vetoes and reobserve before reopening. Full apply closes gate; final activation atomically selects pins and clears only approved recovery targets |
| POST | Private `/internal/v1/route-bundles/{id}/observations` | Current scoped controller owner | Per-proxy evidence bound to deployment_version_id, serving generation, epoch and increasing sequence; registry-only pin switches retain sample identity and age; polling changes no authorization revision |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/human-providers`, `/human-links` | Tenant provider_admin | Inactive provider configuration/testing and controlled verified human enrollment/linking; active-state writes rejected |
| GET | `/admin/v1/tenants/{tenant}/login-state` | Authorized scoped operator | Read-only active provider/generation/enrollment hold/revision |
| GET / PATCH | `/admin/v1/tenants/{tenant}/human-enrollment-policy` | Tenant provider_admin | preprovisioned default or explicit auto_create; cannot clear migration hold |
| POST | `/admin/v1/tenants/{tenant}/human-enrollment-policy/resume` | Tenant provider_admin | Explicit audited reconciliation acknowledgement, expected provider/generation/revision; clear hold only for current state |
| POST | `/admin/v1/tenants/{tenant}/human-providers/{id}/credential-rotations` | Tenant provider_admin | Same issuer/client_id/auth method/callback/assurance; versioned credential reference only, no epoch advance |
| POST | `/admin/v1/tenants/{tenant}/human-provider-switches` and `/{plan}/commit`, `/{plan}/rollback` | Tenant provider_admin | Exclusive plan/dry-run/commit transition, including initial activation; epoch invalidation and expected revisions |
| POST | `/admin/v1/tenants/{tenant}/imports` | Every role required by all included sections | Whole-plan role validation; reject unauthorized sections/active-pointer mutation, no partial apply |
| GET / POST / PATCH | `/admin/v1/operators`, `/operator-roles` | Instance security_admin | Independent operator enrollment/disable and explicit scoped roles |
| GET | `/admin/v1/tenants/{tenant}/audit` | Tenant auditor | Redacted scoped audit; instance events separately authorized |
| Local command / Unix socket | Service bootstrap/recovery verifier | Deployment operator + independent signed proof | M1a; challenge bound to instance/operation/revision, no public recovery or private keys in pod |
| Workstation command | `skyoauth-operator` | Independent operator/recovery key | M1a three-platform mTLS client/offline signer; human commands M1b; no native OAuth dependency |

Grouped sibling paths share the full prefix preceding them. Private listeners are never public gateway routes. All writes use validation, optimistic revision checks and audit; high-frequency observation refreshes are operational telemetry, not new policy-change events. Device and impersonation-activation endpoints are absent in v0.1; adding them requires a later reviewed feature contract. Native upstream callbacks are not app callbacks or loopback callbacks: the browser returns upstream -> issuer, confirms there, then receives a SkyOAuth code at its CLI loopback.

### Exchange selection and scope

Require one generated source ID, generated grant ID and exact registered audience. Load source/grant only as candidates; require same tenant, then verify the proof at that source. Filter matching bindings by **the selected grant's actor and nonempty allowed_binding_ids**. At least one eligible enabled binding must match. Bindings for other actors do not cause ambiguity or confer access. Bindings are identity-only in v0.1; multiple eligible matches choose a stable ID for provenance, never union permissions. Configuration rejects cross-actor/cross-tenant binding references.

Direct RFC exchange accepts subject_token/type=jwt and a direct grant, returns workload sub, rejects actor_token. The private service-delegation grant accepts actor_token/type=jwt and a delegated grant, returns configured service sub plus workload act, rejects subject_token. No requested subject/target/mode override or dynamic verifier selection.

Omitted scope uses only explicit nonempty allowed default_scopes; otherwise invalid_scope. Explicit empty/excessive scopes, unsupported resource/requested token types, duplicates or profile mismatch deny. Return access_token, Bearer token_type, expires_in, explicit scope and `issued_token_type=urn:ietf:params:oauth:token-type:access_token`, no-store, never WIF refresh. The design's exported example uses **post-create generated IDs**, not operator-chosen global identifiers.

## 3. Logical data model and staged persistence (M1a/M1b)

Approve the complete logical model in M0, but implement tables/handlers in their dependency slice. **M1a** includes workload Tenant/Principal, resource-server/assignment/checker/action authority, trust/keyset/binding/service/grant/policy, replay, operator/recovery/audit and public signing metadata. **M1b** includes versioned origin/route/bundle/controller and separate capacity policy, client/human policy, provider/login/enrollment/link state, browser/native/authentication/session/continuation/refresh state and internal-key metadata, before M3. Optional/future feature tables are not a prerequisite. Stable authority survives provider changes; affected human flow/auth state is invalidated. Instance versus tenant authority and redacted export versus encrypted backup remain distinct.

~~~text
Tenant(id, name, status, created_at)
Principal(id, tenant_id, kind, name, status, created_at)
ResourceServer(id, audience, name, allowed_profiles, scopes, constraint_versions,
               status, revision)
AudienceTenantAssignment(id, resource_server_id, tenant_id, allowed_profiles,
                         allowed_scopes, constraint_versions, status, revision)
ResourceServerChecker(id, resource_server_id, public_mtls_identity,
                      allowed_tenant_ids, status, revision)
ResourceAction(id, resource_server_id, action_name, required_scopes,
               accepted_profiles, required_resource_dimensions,
               live_check_required, stream_capable, max_stream_duration_seconds?,
               stream_class, max_session_lease_seconds, status, revision)
ApplicationOrigin(id, tenant_id, canonical_origin, security_status,
                  security_revision, created_at)
ApplicationOriginVersion(id, tenant_id, application_origin_id, revision,
                         callback_uri, allowed_return_paths, resource_server_ids,
                         created_by, created_at)
ApplicationRoute(id, tenant_id, application_origin_id, route_bundle_id,
                 security_status, security_revision, created_at)
ApplicationRouteVersion(id, tenant_id, application_route_id, revision,
                        match_kind, path, methods, resource_server_id,
                        allowed_profiles, max_stream_duration_seconds,
                        session_lease_seconds, configured_status, created_at)
OriginCapacityPolicy(application_origin_id, tenant_id,
                     max_session_continuations, revision)
InstanceCapacityPolicy(instance_id, max_session_continuations_ceiling,
                       tenant_context_limits, checker_context_limits,
                       global_context_limit, request_rate_limits, revision)
RouteControllerIdentity(id, public_mtls_identity, gateway_deployment_refs,
                        allowed_application_origin_ids, status, revision)
RouteBundle(id, tenant_id, application_origin_id, controller_id, status, revision)
RouteBundleVersion(id, tenant_id, bundle_id, version, activation_mode,
                   origin_version_id,
                   route_version_ids, managed_gateway_resource_refs,
                   protected_gateway_listener_host_scopes,
                   adapter_artifact_digests, translator_input_digest,
                   canonicalization_version, expected_gateway_digest,
                   security_preconditions, reenable_targets, abort_plan?,
                   plan_digest, prepared_operation_id, created_at)
RouteBundleRuntime(bundle_id, active_version_id?, deployment_version_id?,
                   applying_version_id?, applying_approval_id?, apply_phase,
                   abort_source_active_version_id?, abort_source_deployment_version_id?,
                   write_journal,
                   active_generation, traffic_gate, gate_reason,
                   controller_epoch, owner_id?, owner_lease_until?,
                   last_observation_sequence, serving_set_generation)
RouteBundleObservation(bundle_id, deployment_version_id, proxy_uid,
                       serving_set_generation, controller_epoch, sequence,
                       observed_gateway_digest, collection_started_at,
                       fresh_until, valid_until, result)
OAuthClient(id, tenant_id, client_id, name, display_name, redirect_rules,
            resource_server_ids, allowed_scopes, status, revision)
HumanAccessPolicy(id, tenant_id, resource_server_id, oauth_client_id?,
                  application_origin_id?, allowed_scopes, max_ttl,
                  required_authentication, refresh_absolute_limit_seconds?,
                  refresh_idle_timeout_seconds?, status, revision)
HumanProvider(id, tenant_id, name, issuer, upstream_client_id, client_auth_method,
              credential_ref, credential_revision, metadata, app_callback_config,
              native_callback_uri, auth_epoch, status, revision)
TenantLoginState(tenant_id, active_provider_id?, auth_generation, enrollment_hold,
                 revision)
HumanEnrollmentPolicy(tenant_id, mode, revision)
HumanSubjectLink(tenant_id, provider_id, issuer, upstream_sub, principal_id,
                 verified_by, verification_operation_id, status, revision)
BrowserFlowBinding(id_hash, tenant_id, flow_kind, canonical_origin,
                   application_origin_id?, created_at, expires_at, consumed_at?)
HumanAuthentication(id, tenant_id, principal_id, provider_id,
                    provider_auth_epoch, tenant_auth_generation,
                    auth_time, verified_auth_context, expires_at, revoked_at?)
Session(id_hash, internal_ref, tenant_id, application_origin_id, principal_id,
        human_authentication_id, provider_id, upstream_sub, upstream_sid?,
        created_at, last_seen_at, idle_timeout_seconds, idle_expires_at,
        absolute_expires_at, revoked_at?, csrf_verifier)
SessionContinuation(id, checker_id, tenant_id, resource_server_id, principal_id,
                    session_ref, human_authentication_id, application_origin_id,
                    origin_version_id, application_route_id, route_version_id,
                    policy_revision_id, action_id, action_revision,
                    canonical_resource, request_binding, stream_nonce,
                    admitting_assertion_jti_digest, admitting_internal_kid,
                    created_at, absolute_expires_at, authorized_until, closed_at?)
OIDCTransaction(state_hash, tenant_id, flow_kind, browser_flow_hash,
                provider_id, provider_auth_epoch, tenant_auth_generation,
                expected_issuer, expected_callback_uri, application_origin_id?,
                nonce_hash, protected_pkce_context, validated_return_path?,
                native_request_id?, expires_at, consumed_at?)
OAuthAuthorizationRequest(id_hash, tenant_id, oauth_client_id, browser_flow_hash,
                          principal_id?, human_authentication_id?, provider_id,
                          provider_auth_epoch, tenant_auth_generation,
                          redirect_uri, pkce_challenge, pkce_method,
                          resource_server_id, scopes, protected_client_state,
                          request_digest, csrf_verifier, confirmation_status,
                          approved_at?, expires_at, consumed_at?)
OAuthAuthorizationCode(code_hash, tenant_id, request_id, oauth_client_id,
                       principal_id, human_authentication_id, redirect_uri,
                       pkce_challenge, pkce_method, resource_server_id, scopes,
                       human_access_policy_id, issued_at, expires_at, consumed_at?)
CLIRefreshFamily(id, tenant_id, oauth_client_id, principal_id,
                 human_authentication_id, resource_server_id, approved_scopes,
                 created_at, absolute_expires_at, idle_timeout_seconds,
                 idle_expires_at, current_generation, revoked_at?)
CLIRefreshCredential(token_hash, tenant_id, family_id, generation, parent_id?,
                     scopes, issued_at, expires_at, consumed_at?,
                     retry_request_id_hash?, retry_payload_hash?, retry_until?,
                     retry_successor_generation?, retry_policy_revision?,
                     encrypted_retry_response?, retry_encryption_key_ref?)
TrustSource(id, tenant_id, name, kind, exact_issuer, discovery_url?, jwks_keyset_id?,
            cluster_id?, token_review_endpoint?, ca_bundle_ref?, ca_fingerprint?,
            reviewer_credential_ref?, review_timeout_ms?, audiences, algorithms?,
            proof_bounds, assertion_profile, replay_mode, status, revision)
TrustKeyset(id, tenant_id, name, status, revision)
TrustKeysetVersion(id, tenant_id, keyset_id, public_jwks, fingerprint,
                   effective_at, expires_at?, status, provenance)
PrincipalBinding(id, tenant_id, name, trust_source_id, profile, claim_match_policy,
                 workload_principal_id, status, revision)
ServiceIdentity(id, tenant_id, name, resource_server_ids, max_scopes,
                max_resource_constraints, status, revision)
ServiceGrant(id, tenant_id, name, actor_principal_id, allowed_binding_ids,
             target_service_id?, mode, resource_server_ids, scopes,
             default_scopes?, resource_constraints, max_ttl, valid_until?,
             status, activation_state, revision)
PolicyRevision(id, tenant_id, profile, resource_server_id, dependency_revisions,
               selected_binding_id?, grant_id?, human_access_policy_id?,
               effective_scopes, effective_constraints, created_at, invalidated_at?)
ConsumedAssertion(tenant_id, trust_source_id, replay_key_digest,
                   digest_key_version, consumed_at, retain_until)
AdminIdentity(id, status, created_at)
AdminCredential(id, admin_id, public_identity, trust_anchor_ref, status, revoked_at?)
AdminRoleBinding(id, admin_id, role, tenant_id?, status, revision)
RecoveryState(instance_id, bootstrap_closed, recovery_public_key,
               recovery_key_epoch, revision)
AdministrativeOperation(id, tenant_id?, actor_id, kind, request_digest,
                        expected_revision, immutable_plan, challenge_hash?,
                        expires_at?, consumed_at?, outcome, audit_id)
IssuerKeyVersion(kid, algorithm, public_key, signing_key_reference, validity)
InternalAssertionKeyVersion(kid, signer_group_id, algorithm, public_key,
                            internal_key_reference, published_at, activate_after,
                            signing_state, validity, status, revision)
AuditEvent(id, tenant_id?, timestamp, actor, action, object_id,
           previous_revision, new_revision, outcome)
~~~

**Ownership:** ResourceServer/audience namespace, ResourceServerChecker/Action and origin ownership enrollment are instance authority; AudienceTenantAssignment grants named tenants bounded issuance rights. Composite same-tenant references protect all tenant-owned objects and their immutable versions. ServiceIdentity.id references a svc principal and contains no checker credentials. Direct grants require null target; delegated grants require a same-tenant service. ApplicationOrigin has globally unique canonical origin, assigned rather than claimed by tenant admins. OAuth client_id is globally unique and generated, so issuer-native authorization deterministically resolves its tenant. HumanAccessPolicy has exactly one client/origin consumer and one registered audience, unique per consumer/audience. The active bundle pins the origin/route versions used to resolve a cookie request; exact paths beat longest segment-prefix paths for the method, ties reject and disabled winners deny rather than falling back. Canonical request/route matching and no-rewrite rules are normative in design §4.1.

**Route preparation, approval and recovery:** origin/route/bundle versions are immutable; active_version_id alone selects live registry pins. client_admin requests a route_bundle_prepare AdministrativeOperation containing the immutable source snapshot/input digest, expected active generation, affected-parent security revisions, required activation_mode (registry_only or gateway_apply) and explicit recovery intent. M1b persists these contracts; M3's isolated controller worker runs the pinned translator and submits its authenticated bound result before the service creates a completed RouteBundleVersion. Pending/failed operations and caller digests are not approvable. Instance security_admin's separate expiring route_bundle_approval binds the finalized plan, activation_mode and security_preconditions/reenable_targets. Finalization checks registry_only equivalence to the captured deployment_version_id; mode changes require a new preparation and approval. A gateway_apply version retains an exact abort_plan of prior registry/deployment pins and scoped prior resource values/absence. Its approval immutable_plan includes a finite abort_until later than the forward expires_at within an instance maximum; both are displayed, never inferred by the controller. Preparation-result, begin and final activation recheck relevant preconditions; all role/approval/security checks at activation share the pin-change transaction. Exact result retries are idempotent, contradictory results reject.

security_preconditions maps every pinned/affected stable origin/route parent to its captured security_revision; reenable_targets explicitly lists typed parent IDs, expected disabled revisions and recovery reasons. A later disable advances the revision and invalidates its forward authorization (not already-approved bounded compensation of a begun attempt), including the 09:00 approval / 09:20 disable / 09:30 apply case. Activation may clear only explicitly approved targets and increments their revisions atomically; all others retain their status. configured_status=enabled in a pinned route version is insufficient while either parent is security-disabled, and clearing the security veto cannot override configured_status=disabled. No fallback, replacement-ID/unpin bypass or rollback restoration of newer security state. Security revisions are execution preconditions and current credential dependencies, not a bundle-wide runtime equality that revokes unrelated routes. No direct PATCH/import can clear a veto or write runtime eligibility.

**Unfinished-apply compensation:** apply_phase distinguishes applying, abort_required and aborting from idle. A newer disable or failed forward precondition after begin marks abort_required, stops forward writes and keeps the gate closed. The existing approval permits only its exact abort_plan until abort_until with current enabled authority; forward expiry/newer disables do not cancel this narrow compensation, but approval/authority revocation does. Runtime source IDs and a durable bounded per-object UID/resourceVersion/write journal support idempotent abort and fenced takeover; settle outstanding writes and restore only approved resources, deleting only matching attempt-owned creations. Abort calls are bound to the current attempt/approval/digest/epoch; complete_abort requires phase=aborting and fresh complete restored-deployment observations before ending the attempt and reopening old unaffected pins. Advance the runtime generation, retain all newer security revisions/vetoes and invalidations, and never revive closed contexts. A no-prior-pair enrollment abort remains unconfigured/closed. Failed/expired/revoked/ambiguous compensation stays closed for new authorized recovery. Design §4.2 is normative; this is not arbitrary rollback authority.

**Route runtime state:** active_version_id selects registry configuration; deployment_version_id names the approved gateway deployment against which per-proxy observations were collected. A real apply moves both only after matching evidence; activate_registry_only may change the former while retaining the latter, samples and original ages. It requires an already eligible gate, complete <=30s-fresh samples and exact equivalence of managed resource contents/relevant dependencies, scopes, adapter/bootstrap/projection versions, expected gateway digest and serving generation, plus current approval/security preconditions and no reenable_targets. No gateway writes, begin or gate closure occurs. Mode checks precede all transitions: begin/activate reject registry_only and activate_registry_only rejects gateway_apply. A failed fast-path check leaves old state unchanged; retry freshness only in the approved mode, never reuse its approval for begin. Supersede only changed authorization dependencies, not unchanged routes just because a bundle pointer advanced. Scoped list/read discovers preparation and approved work; durable epoch/sequence, leader election and resourceVersion preconditions govern reconciliation. Uncertain partial writes stay closed through failover; a failed begun attempt uses its bounded abort/complete_abort and journal, not an undefined gate reset. Polling is telemetry, not configuration audit churn; restore cannot restore observation eligibility.

**Route observation bounds and apply outcomes:** poll <=10s, stale alert at 30s, unchanged deployment evidence usable at most 300s from original collection start with equivalent active registry configuration, unchanged protected serving generation, no gateway apply/mismatch and valid independent auth. Registry-only activation cannot refresh that age. A new proxy has no grace. Full begin gates all new cookie application requests/admissions on the origin with 503 route_configuration_unavailable throughout apply. Existing unchanged pinned authorization dependencies return unavailable without renewal/closed_at, while changed/removed dependencies, security disable or out-of-plan drift deny terminally. Only journaled approved apply/abort transformations under a closed gate are transitional. Recording an authenticated current out-of-plan mismatch immediately closes the gate, alerts, gives new calls 503 and rechecks terminal deny/closed_at; the 300s allowance never applies. Old matching reports cannot reopen; fresh complete evidence after approved reconciliation is required, without resurrecting closed contexts. Stop at the previous lease; real apply, incident recovery and compensating abort can interrupt the entire origin's cookie traffic. Fixed session/CSRF/logout, native revoke and verified revocation/disable endpoints remain gate-independent with their own checks, never application-assertion issuance. T14.9 defines persistence/contracts; T32.3 implements isolated preparation, scoped projection and activation in M3; T50.4 tests actual deployment behavior. Other adapters need equivalent enforcement.

**Operational capacity:** OriginCapacityPolicy and InstanceCapacityPolicy have independent optimistic revisions/audit. They are absent from origin/route version pins and PolicyRevision dependencies. Current effective session limit is min(origin setting, instance ceiling), including after a ceiling decrease; session occupancy spans all routes/checkers. Quota/rate maps must have finite validated entries/defaults, never absent-as-unlimited. Limit changes serialize with admission but neither supersede existing authorization nor evict streams. Per-session excess is too_many_open_streams; shared quota excess is stream_capacity_unavailable; rate limits are separate. §6.1.1 in the design fixes wire/retry behavior.

**IDs/names:** server-generated opaque IDs, including client_id, are immutable selectors; names are tenant-local labels, not exchange identifiers. Initial create omits ID and returns it. GitOps may use tenant-local typed manifest references, resolved by an authorized plan that returns a persistent ID mapping. Updates require ID/tenant/revision; ordinary tenant imports cannot claim missing global IDs. Privileged restore preserves IDs only into the intended restored authority with ownership/provenance validation. Two tenants' identically named sources/clients/grants coexist without global-name probing.

**Verifier union:** discovery requires approved metadata; upload requires same-tenant keyset; TokenReview requires cluster/endpoint/CA/reviewer/audience/timeout and reusable replay. Reject contradictory fields and unsupported evidence requirements. Keyset versions reference a stable parent; overlapping keys have explicit validity and no conflicting live kid/key pair. Single-use additionally requires locally verified on-demand JWT evidence and fresh-assertion capability; reject it for projected-service-account profiles even with local verification.

**Policy revisions:** dependency_revisions is a typed immutable set of entity-kind/ID/revision references. WIF snapshots tenant/resource assignment, chosen source/binding, grant and optional service. Human snapshots assignment, HumanAccessPolicy and client or active pinned origin configuration; human_session additionally snapshots its route version and current stable origin/route security revisions. A disable/re-enable cycle cannot revive old evidence. Staging, observation sequence, operational limits and a bundle-only pointer change are not authorization dependencies. Activation supersedes only dependencies actually changed; unchanged route contexts remain valid subject to the runtime gate. Current action rules, provider/authentication epochs, session or native-family validity remain live checks. No fake WIF grant or missing/contradictory dependency/profile exemption.

**One-time state:** store keyed hashes of flow cookies/session tickets/codes/refresh tokens, not plaintext secrets. Only an attempt opting into skyoauth_refresh_request_id stores an authenticated-encrypted issued-response envelope for <=30 seconds under a separate protected key, excluded from exports/logs. Plain refresh has all retry fields null and ordinary consumed-token replay revocation. An extension attempt retains its correlation/deadline metadata after envelope purge; receipt loss must not look like plain rotation. Invalid supplied IDs are rejected, not silently omitted, and replay cannot add/remove an ID to switch paths. Distinct app/native bindings include origin and flow kind; HumanAuthentication links credentials to monotonic provider/tenant epochs. A native authentication/client/audience tuple has at most one refresh family, resolved by live check from signed authentication/client_id/audience and required to be live. HumanAccessPolicy refresh fields apply only to native clients: defaults 12h/1h, explicit maxima 7d/24h within stricter assurance/instance limits. Snapshot approved absolute/idle limits; increases require a new browser-approved family and cannot extend existing state, while tightening permanently narrows/revokes affected families and is enforced on refresh/live checks. Required refresh families have immutable absolute and bounded idle deadlines, unique generation/hash, atomic consume/replace and whole-family replay revocation except opted-in bounded exact retries under design §5.2.2; HumanAuthentication expires at the approved assurance/family bound, not the access token's 300-second bound. No rotation extends auth_time/absolute lifetime. Replay uniqueness spans grants/replicas through exp plus skew and digest-key rotation. Restore preserves consumption or quarantines issuance; config import does not restore it.

**Provider pointer/enrollment:** TenantLoginState is authoritative; HumanProvider has no writable active flag. M1b's guarded transition is the sole pointer/epoch writer and atomically sets enrollment_hold for switch/rollback. A callback rechecks generation, hold and HumanEnrollmentPolicy in the principal/link transaction. preprovisioned is default; explicit auto_create creates one new zero-privilege principal/link for a previously unseen exact subject, never email-merges or replaces disabled identities. Only explicit provider/generation/revision-bound enrollment-resume clears a migration hold. Credential-only rotation of the unchanged semantic provider/client tuple has a separate revision-checked path and does not advance auth epochs.

**Stream state:** SessionContinuation is created only from a still-valid internal assertion for a stream-capable action. Uniqueness of admitting assertion jti prevents multiple contexts; exact same-checker retry can return the existing context without lease extension. It binds all fields listed above and active origin/route/policy/action versions; it is not a bearer capability. Rechecks require the same authenticated checker and exact context/nonce, current session/epochs/authorization, route-runtime eligibility and backend RBAC. A renewal after the last authorized_until denies, even if the session remains live. A successful lease follows route/action limits: default/critical <=15 seconds; explicit noncritical read-only ceiling <=300 seconds, within one-hour context, session/authentication and applicable observation deadlines. Temporary unavailable grants no new lease and does not close state; terminal denial does. Same-checker batches preserve per-item atomic renewals, not batch-wide authorization. Origin/instance capacity policies govern only admission; lowering them leaves existing live contexts valid. No idle touch, new request, resource change or post-expiry resurrection. close-session atomically sets closed_at/releases occupancy exactly once without requiring live user evidence; matching retries succeed and closed contexts never renew. Unknown/wrong-checker/nonce/context close does not mutate another stream. Crash or lost close retains occupancy only until last lease expiry, independent of cleanup scheduling. Retain bounded close-retry identity and admission-jti tombstones through assertion expiry plus skew; restart requires fresh admission. Internal key disable or verified unpromoted-standby use denies. Capacity wire distinctions and bounded retry budgets follow design §6.1.1.

**Key separation:** public access keys and internal assertion keys have disjoint kid namespaces/trust sets. Internal keys belong to deployment signer groups and are shared only by authorized replicas in that group, not generated per replica. Instance security_admin enrolls/distributes them; replicas cannot self-register. Publish before use, cache freshness <=60s with no stale-on-error, activate_after >= publication + maximum cache window + skew, and readiness gates key loading/publication/activation. New group replicas reuse an active kid; unknown kid gets bounded single-flight fixed-endpoint refetch, then deny. signing_state distinguishes active/standby/retired issuance roles from verification status: standby public material is prepublished, but private material is unavailable to normal auth replicas until audited promotion. Live checks/admission/rechecks reject cryptographically valid evidence from an unpromoted standby and raise a bounded alert; offline verification alone cannot enforce that authoritative-state tripwire. Normal retirement of a previously promoted key retains its documented overlap. Production commissioning/rotation completion requires active plus eligible standby; emergency clean promotion may run in alerted degraded redundancy while replenishing. No eligible unaffected standby means fail closed, not maturity waiver or compromised fallback. Keep key status/provenance through dependent continuation deadlines. Design §6.2 is the key lifecycle contract.

### T10 — Schema and migration safety

- [ ] **T10.1** Implement staged migrations/indexes from the approved logical schema: workload M1a, human M1b before handlers. Generated IDs, typed unions, tenant references, soft disable/immutable revisions; no provider cascade into WIF/audience/client/operator authority. Origin/route/bundle versions are append-only; runtime observations and capacity policies have separate storage/revision rules.
- [ ] **T10.2** Implement server-generated opaque create IDs/client_id and tenant-local name uniqueness; create responses return IDs/revisions, and exports retain them. No user-chosen global ID on normal create.
- [ ] **T10.3** Hash browser-flow/session/code/refresh secrets; protect CSRF/PKCE and normalize expiry/revocation. Do not store raw replay assertions or expose cookie hashes as backend session references. The opted-in <=30s encrypted refresh-retry envelope is the explicit design §5.2.2 exception, never plaintext.
- [ ] **T10.4** Complete immutable typed policy dependencies, pinned active versions and atomic audit/optimistic concurrency. Staged config, sample refresh and capacity-only changes cannot supersede live authorization; committed security disable/activation can. No mutable reinterpretation of issued credentials.
- [ ] **T10.5** Redacted versioned export/import includes every source kind, keysets, audience/actions/checker public metadata, clients/origin/route/bundle configuration versions, separate capacity policies, human policy, grants/activation state and operator public metadata. Semantic diff/preconditions/approval; exclude secret/live credential material and restorable active route observations.
- [ ] **T10.6** Separate encrypted DB/key disaster recovery; preserve bootstrap-closed and one-time/replay state or quarantine. Rollback never revives credentials or resets monotonic generations; restored route bundles need fresh observation before activation.
- [ ] **T10.7** GitOps precedence and full-plan role checks; no wiping omitted objects or partially applying unauthorized sections. Active-provider state and route-runtime pointers/observations are not ordinary writable configuration. Protected gateway resources are applied by the approved controller path, not directly by Helm/Argo/Flux.
- [ ] **T10.8** Property tests for same-name tenants/sources, same-issuer clusters, cross-tenant object/audience/origin references, deterministic generated-ID resolution, grant-bound matching and privilege ceilings.
- [ ] **T10.9** M1a delivers durable WIF replay/operator one-time state. M1b delivers OAuth/client/code/browser-flow/authentication/required refresh-family, versioned route/controller/runtime/capacity and continuation state before M3/M4 handlers. Atomic consumption across replicas; human tables are not M2 prerequisites.
- [ ] **T10.10** Session idle/absolute and authentication epoch relationships; coalesced writes cannot revive/extend expired sessions. Index verified provider/subject/sid logout and switch invalidation.
- [ ] **T10.11** Store dormant impersonation only disabled/reapproval-required in the existing grant record and preserve it unchanged. No v0.1 activation-approval entity/endpoints; reject enablement, issuance and active unsupported import/startup without silent data deletion.

### T11 — Trust registry and key lifecycle

- [ ] **T11.1** Three verifier kinds with tenant/source IDs, exact issuer metadata, audiences/evidence bounds/assertion profile/replay/status/revision; issuer is not unique.
- [ ] **T11.2** Discovery exact issuer/approved HTTPS egress, SSRF-safe metadata/JWKS, bounded cache/redirect/refresh and key-confusion defenses.
- [ ] **T11.3** Uploaded public-only keys, algorithms/strength/size, explicit overlap, unique nonconflicting live kid; reject private parameters.
- [ ] **T11.4** Bounded key cache/expiry/rotation alarms; no permissive fallback when valid keys unavailable.
- [ ] **T11.5** JWT jku/x5u/embedded jwk/unknown kid cannot change configured trust.
- [ ] **T11.6** Audited disable/rotation preserves source/binding/grant IDs independently of human-provider changes.
- [ ] **T11.7** Verify only the explicitly selected registered source; never infer authority by kid/issuer or search alternate clusters after denial.
- [ ] **T11.8** TokenReview enrollment validates fixed endpoint, versioned CA, reviewer reference, explicit audience/timeout/private egress and reusable replay; no request-selected endpoint or local-JWT fallback.
- [ ] **T11.9** Implement stable TrustKeyset parent/version lifecycle and tenant ownership; overlapping versions do not create circular current-version references.
- [ ] **T11.10** Test duplicate issuers across tenants/clusters, conflicting kind fields, arbitrary selectors and migration preservation of reviewer/CA references.
- [ ] **T11.11** Reject single_use for TokenReview/projected-service-account profiles; require verifiable signed jti and tested on-demand renewal for other single-use sources. Missing adapter evidence cannot be synthesized from untrusted JWT parsing.

### T12 — Principals, selected bindings and policy

- [ ] **T12.1** Human resolution is tenant/provider/exact issuer/subject; workload evidence is tenant/source/verified claims. No email or unverified tenant authority.
- [ ] **T12.2** AND predicates; configured missing claims deny, optional omitted predicates are unconstrained. Required production GitHub owner/repo/event/ref/environment/workflow fields cannot be omitted; deleting one is reviewed widening.
- [ ] **T12.3** Load selected grant, verify proof at selected same-tenant source, then filter matching bindings by grant actor and allowed_binding_ids. Require a match; other actors' overlaps do not deny or authorize. Deterministic matching evidence, no permission union or first-global-match fallback.
- [ ] **T12.4** Direct workload sub versus delegated service sub/workload act; audit source/run provenance without treating GitHub actor as human authentication.
- [ ] **T12.5** Required direct/delegation remain distinct. Active impersonation is excluded from v0.1; unsupported-mode issuance never falls back, minimal disabled-policy preservation follows design §5.6.
- [ ] **T12.6** Snapshot full WIF or human policy dependencies; include resource-server assignment and active pinned client/origin/route policy as appropriate. Live checks deny invalidated/superseded revisions without broadening old credentials; staging or operational cap edits cannot invalidate them.
- [ ] **T12.7** Deny wrong owner/repo/subject/event/workflow, no eligible binding, wrong actor/tenant/audience assignment, disabled records and escalation. A matching binding for another actor is ignored, not an ambiguity denial; configuration with cross-actor allowed binding references rejects.
- [ ] **T12.8** Scope omission uses explicit nonempty defaults only. Validate defaults/requests against all ceilings; direct grants have no service target, profile/mode mismatch denies.
- [ ] **T12.9** WIF allowlists and explicit human backend_rbac schema, action/profile mapping and canonical tenant requirements have verifier fixtures; missing required/unknown fields fail closed by profile.
- [ ] **T12.10** Test disabled-only impersonation create/import/export and attempted enablement denial using normal APIs. Defer active approval/activation machinery and its feature-specific tests to a later ADR; do not make future activation a v0.1 prerequisite.

### T13 — Independent operator authority, provisioning and recovery

- [ ] **T13.1** Independent adm identities, registered mTLS public keys and active local credential/role check on every request; no OIDC/session/WIF/email promotion.
- [ ] **T13.2** Implement explicit instance security_admin and tenant trust_admin/client_admin/provider_admin/auditor roles. No inheritance; all reads/writes/imports enforce resource scope and per-field authority. security_admin approves exact gateway deployment plans and instance limits; client_admin prepares tenant versions and origin limits but cannot approve deployment.
- [ ] **T13.3** M1a private operator API, portable operator/ workstation binary and service-local bootstrap/recovery verifier, with revisions/diff/dry-run/audit. M1b adds human commands. Neither remote client nor local verifier depends on M4 native OAuth or copying private operator keys into pods.
- [ ] **T13.4** Atomic one-time local bootstrap enrolls security_admin public credential and separate offline recovery key, audits and durably closes enrollment; restart/config omission cannot reopen it.
- [ ] **T13.5** Local recovery verifier emits an expiring challenge bound to instance/operation/arguments/revision; portable workstation signs with independent offline key. Only signed responses cross the separately authorized deployment-local channel. M1a permits operator restoration; M1b also permits guarded provider transitions. No arbitrary WIF/audience edits or token minting; consume/audit/alert and rotate recovery material.
- [ ] **T13.6** Deny forged upstream roles, compromised-IdP sessions, scope crossover, revoked keys, replayed recovery, concurrent bootstrap and missing store/audit.
- [ ] **T13.7** Rehearse workstation-held operator/recovery credentials with IdP unavailable on Linux/macOS/Windows; document/test TLS-key and hardware/OS signer support per platform. Unsupported adapters fail explicitly, no key-export fallback or requirement to run the remote client inside the cluster.
- [ ] **T13.8** M1a provisioning: security_admin tenant/audience/checker/actions/explicit roles, trust_admin workload/service/source/binding/grant. M1b adds origin/route/bundle versions, scoped controller enrollment and deployment approval, separate capacity policy, client/human policy/enrollment/provider/link provisioning and initial activation. Each slice works without SQL edits; one explicitly scoped operator/tenant is valid, not an implicit-tenant protocol.
- [ ] **T13.9** M1b sole provider-transition primitive: immutable plan/dry-run/commit, expected login/config revisions, initial activation, switch/disable/rollback, atomic epoch advance/enrollment hold and audit. Generic pointer/auth-semantic mutation rejects. Credential-only rotation is separately constrained by T30.9. T51 builds orchestration, not an alternate writer.
- [ ] **T13.10** Package/build/test skyoauth-operator independently of server/DB and native application SDK on Linux/macOS/Windows in M1a. Test remote mTLS configuration and offline challenge signing/verification, instance binding and redaction; operator key remains outside the pod.

### T14 — Resource servers, audience assignments and application registrations

- [ ] **T14.1** Instance-owned globally unique exact audience registry and explicit tenant/profile/scope/schema assignments; scoped tenant admins cannot self-assign or shadow another audience.
- [ ] **T14.2** Refuse service/grant/client/origin/human-policy references outside active same-tenant assignment at write and issuance; recheck on live authorization. Backends map canonical resource ownership to signed SkyOAuth tenant and deny absent/mismatched mappings.
- [ ] **T14.3** Register resource-server mTLS checker identities with explicit audience/tenant scope independently of ServiceIdentity/token subjects. Direct grants with null target work; a delegated service principal cannot become a checker by allowed_audiences alone.
- [ ] **T14.4** Persist action scopes/profiles/resource dimensions/live-check rules in M1a. M1b adds stream capability, duration, stream_class and max_session_lease_seconds. Defaults/critical cap <=15s; instance security_admin may explicitly allow noncritical read-only leases up to 300s. Tenant route editors cannot exceed receiver ceilings; unknown/contradictory rules deny.
- [ ] **T14.5** M1b canonical origin ownership plus append-only origin/route configuration versions; pin callbacks, trusted ingress and return rules. Separately implement OriginCapacityPolicy (client_admin, default 8) and InstanceCapacityPolicy (security_admin, ceiling <=64 and finite shared quotas/rates). Admission uses current minimum even after ceiling reduction; cap changes do not alter route pins, credentials or live streams. Test lower-with-occupancy, raised cap and attempted ceiling escape.
- [ ] **T14.6** M1b HumanAccessPolicy for one client/origin per audience, within assignment scope/TTL/assurance ceilings; native refresh defaults/caps and no auto-granted backend membership. Provider-independent configuration remains stable through migration.
- [ ] **T14.7** M1b deterministic client_id -> tenant and authority -> origin/tenant; active-pinned cookie ApplicationRouteVersion -> one resource server/HumanAccessPolicy. Deny unknown/spoofed authority or client-selected tenant/audience before authorization; staged versions are never consulted for live selection.
- [ ] **T14.8** Document create-then-reference and authorized import manifest references, return/generated ID mapping and same-instance reconciliation. Test identical labels in different tenants, unauthorized IDs and restore provenance; public exchange accepts generated IDs only.
- [ ] **T14.9** M1b implements immutable route preparation operations/result contracts and completed-version/approval schema, separate Runtime/Observation state, scoped list/read and fenced transitions. No expected digest is trusted from a tenant; T32.3's M3 worker finalizes prepared versions before approval. Bind every affected parent security_revision and explicit reenable_targets into plan/approval; atomic activation clears only named current targets and advances revisions. Test 09:00 approval/09:20 disable/09:30 activation, disable-after-begin and forward-expiry cases that abort/reobserve/reopen the prior unaffected routes while preserving newer vetoes, omitted/foreign targets, configured-disabled versus security-disabled, rollback/replacement bypass and no evidence resurrection. Model registry-only equivalence/freshness checks and retained deployment_version_id/sample ages separately from full begin/apply/observe. Four-hour staging remains harmless; invalid/stale approval or result rejects without config churn. Test required activation_mode in input/version/digest/approval, registry-only finalization equivalence, wrong-mode transitions and 31s-old evidence retry without begin. Cover retained abort_plan/artifacts, separate deadlines, revoked/exhausted compensation, no-prior-pair cleanup, journal/CAS takeover and no old security-state restoration.

**Gate M1a (M2 prerequisite):** workload tenant/audience/checker/action/principal/trust/grant provisioning, portable operator/local recovery, replay/restore/isolation and public-key metadata pass without human tables, M4 or manual SQL. Tenant/audience checks are not deferred. Signer/public JWKS is M2.

**Gate M1b (M3 prerequisite; may run alongside M2):** human origin/route versions, draft bundle-preparation and approval/result persistence, client/enrollment/provider provisioning, independent limits, browser/native/refresh/continuation state and guarded provider transition are ready before handlers. Isolation, one-time/restore and security-revision recovery contracts pass. This gate does not claim a deployable translated bundle: the isolated preparation worker, internal signer and real controller/observation/activation enforcement are M3. M2 remains independent of these human components.

## 4. WIF, issuer and bearer gateway (M2)

### T20 — JWT issuer and profile verification

- [ ] **T20.1** Stable issuer/JWKS and explicit private token-profile metadata; no upstream-issued pretense or implicit RFC 9068 claim.
- [ ] **T20.2** M2 public asymmetric signer/JWKS uses protected public-access key/kid/overlap, access TTL <=300 seconds and unique jti/private type. M3 internal assertions use a different locally held key and private verification set (T32.14), never the public issuer key.
- [ ] **T20.3** WIF requires signed tenant, profile/version/mode, grant, complete effective policy revision and allowlist constraints; delegation requires act. Standard core claims and profile selection are shared, not subject-prefix heuristics.
- [ ] **T20.4** Verifier fixtures for issuer/audience/assignment/type/signature/time/key/profile errors, unknown schemas, missing WIF allowlists, contradictory human/WIF claims and canonical resource tenant mismatch.
- [ ] **T20.5** WIF receives no refresh credential; provider renewal gets fresh on-demand assertion or reuses a valid projected token according to source capabilities.
- [ ] **T20.6** Audit source/binding/grant/revision/run/audience decisions with safe metrics, never JWT/key bytes.
- [ ] **T20.7** Document 300-second offline access cap, 30-second internal evidence lifetime, separate bounded session-stream leases and TokenReview propagation. No claim that old credentials/continuations authorize new requests or can undo in-flight work.
- [ ] **T20.8** Publish private-profile validation rules and reject at+jwt/ID-token/internal-header substitution. Native client_id is actual registration; WIF does not invent an OAuth client ID from a source/actor. Cite RFC 9068 to explain the distinction.

### T21 — Exchange and reusable Rust workload library

- [ ] **T21.1** Strict bounded form parser for required generated source/grant selectors, one registered audience, optional scope and supported proof combinations. Reject duplicates/missing/oversized/unsupported target/subject/resource parameters.
- [ ] **T21.2** OAuth-shaped success/errors, explicit scope/issued type, no-store, no redirects, TLS/rate limits and clearly labeled private grant extension.
- [ ] **T21.3** Only selected registered verifier; selector itself gives no tenant/actor authority and no alternate cluster/key-source fallback.
- [ ] **T21.4** Selected grant's actor and approved binding set filter verified evidence before authorization; support overlapping other-actor bindings. Direct proof becomes workload sub; delegated proof becomes act with preapproved service sub.
- [ ] **T21.5** Requested/default scopes fit assignment/grant/service ceilings; encode profile-appropriate narrowed constraints and full revision, not just an audit ID.
- [ ] **T21.6** Reusable accepts otherwise valid repeat proof after fresh evaluation/new output jti. Eligible on-demand single-use atomically consumes source-scoped verified-jti digest; replay/missing jti/store failure denies, crash may burn proof, retry needs fresh assertion. Reject single-use on projected/TokenReview sources at enrollment and request validation.
- [ ] **T21.7** Fuzz parser/selector/profile roles; test two same-audience grants, overlapping bindings to different actors, multiple eligible same-actor bindings, no-match, scope defaults/escalation and non-enumerating errors.
- [ ] **T21.8** Consumption survives digest-key rotation, provider switch/rollback, failover/restore and all grant choices until proof exp plus skew; no cached-token idempotency claim.
- [ ] **T21.9** Add clients/rust Cargo library with typed exchange/profile/selector config, redacted credentials, memory cache and bounded/cancellable transport. No service/DB dependency, off-origin credential forwarding or mutation replay. Package/test independently of reference CLI.

### T22 — Mandatory GitHub Actions

- [ ] **T22.1** Tenant-owned GitHub discovery source with explicit audience/algorithms/assertion profile/replay capability; instance audience assignment governs output separately from proof audience.
- [ ] **T22.2** Verify issuer/signature/audience/time, immutable owner/repo IDs, explicit event/ref/environment/workflow/reusable-workflow context.
- [ ] **T22.3** Rust provider obtains custom-audience assertions through documented runner interface, no static secrets/logging; provider feature optional for ordinary native consumer.
- [ ] **T22.4** Example uses id-token:write, returned generated source/grant IDs and correct profile. Production binding permits push only; provisioning emits IDs before workflow configuration.
- [ ] **T22.5** Deny fork/PR and otherwise-matching pull_request_target/workflow_dispatch/issue_comment/workflow_run against push-only binding, wrong claims/audience and absent permission/evidence.
- [ ] **T22.6** Real GitHub -> exchange -> **T25 M2 bearer Envoy** -> ConnectRPC, with run/attempt audit and backend tenant/profile/resource verification.
- [ ] **T22.7** Renew with fresh assertion; memory-only API tokens. Test reusable and eligible single-use concurrency separately.

### T23 — Mandatory Kubernetes/k3s

- [ ] **T23.1** Projected audience-bound short-lived tokens and kubelet rotation; document that rereading before rotation may return the same token.
- [ ] **T23.2** Selected source's fixed TokenReview endpoint/CA/reviewer, least-privilege review-create access, bounded timeout/private egress and no fallback.
- [ ] **T23.3** Explicit requested/returned compatible audiences, authenticated success/no error, returned SA name/UID and supported Pod evidence bound to cluster/source. No assumption that TokenReview returns arbitrary verified JWT claims/jti; reject policies demanding unavailable evidence.
- [ ] **T23.4** Deny wrong cluster/SA/audience, expired proof/deleted-bound-object under documented semantics. Independently keyed shared-issuer clusters cannot be selected interchangeably.
- [ ] **T23.5** Rust provider rereads file and caches only bridge token in memory. **Renew using the same valid projected token before kubelet rotation**, then use rotated token; reusable mode required, no new client secret.
- [ ] **T23.6** Separate local-JWT enrollment states stale object-revocation tradeoff; projected-token profile still rejects single-use. Never degrade from failed review to local validation.
- [ ] **T23.7** Provider switch preserves cluster/endpoint/CA/reviewer references, binding IDs and reusable behavior; independent reviewer rotation is not a new source.

### T24 — Generic issuer and uploaded keysets

- [ ] **T24.1** Discovery/uploaded-key sources share tenant/generated-selector/grant-bound policy semantics and capability-validated replay.
- [ ] **T24.2** Rotation overlap preserves parent/source/binding/grant IDs and explicit validity windows.
- [ ] **T24.3** Reject disallowed issuer/fake keys/alg/conflicting kid/private keys/unsafe URLs/cross-tenant keysets.
- [ ] **T24.4** Document generated-ID enrollment/export, public-only provenance, rotation/disable and secret exclusions.

### T25 — Minimal bearer-only Envoy path

- [ ] **T25.1** Generated Authorization Check v3 on authenticated private listener; verify WIF private access profile and preserve original signed credential/constraints.
- [ ] **T25.2** Bounded metadata only, no body buffering, no cookie authorization until M3; reject mixed credentials/internal assertions on public bearer ingress and fail closed.
- [ ] **T25.3** Protected ConnectRPC route plus separate public exchange/JWKS routes; private auth/policy/operator endpoints never exposed.
- [ ] **T25.4** Sanitize identity/assertion headers, authenticate internal channels, restrict direct API access and verify backend's registered audience, canonical tenant, profile, constraints and RBAC.
- [ ] **T25.5** GitHub/k3s positives and forged/expired/wrong-tenant/wrong-resource/header-spoof/unprotected-route/private-access/outage negatives satisfy T22.6 in M2.

### T26 — Private live operation check

- [ ] **T26.1** Private POST /internal/v1/policy/check authenticates **ResourceServerChecker**, not delegated ServiceIdentity; bind exact resource-server audience and permitted tenant set. A public app/WIF credential is not checker-client authentication.
- [ ] **T26.2** Ordinary check takes one access JWT/internal assertion plus canonical action/resource and retained request binding. M3 may additionally request stream admission with fresh backend nonce using unexpired human_session evidence; expired JWTs/session refs alone cannot open a continuation. Bound metadata, no bodies/token logs.
- [ ] **T26.3** Validate full profile/current typed policy dependencies and registered action required scopes/profiles/dimensions. WIF checks chosen binding/grant/source/optional service; direct null service valid. Human branches later check HumanAccessPolicy, active pinned client/origin/route policy, authentication/session/provider epochs. Superseded authorization denies, staged or capacity-only changes do not.
- [ ] **T26.4** Ordinary response is exact-request allow/deny/unavailable with revision when available and decision ID, no-store, no blanket capability or critical positive cache. M3 stream admission is the narrow T32.12 exception returning an opaque checker-bound continuation/lease. Unavailability grants no permission; backend always enforces canonical ownership/RBAC.
- [ ] **T26.5** Deny checks started after committed revocation, unknown actions/callers/resources, wrong audience/tenant or superseded authorization; store/route-observation outage returns typed unavailable without allow. Test direct/delegated access through one registered receiver and no positive cache.
- [ ] **T26.6** M2 WIF and M4 human_cli server-streaming responses close by the original access-token expiry (remaining TTL <=300s), with no in-band token replacement or bearer continuation. Rust read-only consumers obtain a fresh token and reconnect using application cursors/ranges; ten-minute tails must not restart observed jobs. M3/T32.11–T32.12 alone uses live session continuations; no expired assertion accepted.

**Gate M2:** actual GitHub/k3s calls pass through Envoy to registered APIs without human IdP/static application secrets. Signer/JWKS, both exchange profiles, independently consumable Rust WIF crate, signed WIF constraints, audience assignments and receiver-authorized action checks work. Fixed replay tests include reusable projected-token renewal and atomic on-demand single-use. Dependencies are M0 + M1a + M2, not M1b/M3/M4.

## 5. Human OIDC, sessions and TypeScript SPA (M3)

### T30 — Upstream human login and browser binding

- [ ] **T30.1** Standards-based Zitadel adapter with fixed registered app/native callbacks, expected issuer/client configuration and complete ID-token verification; capabilities explicit.
- [ ] **T30.2** Resolve app tenant/provider from active pinned canonical origin configuration; create app flow cookie and BrowserFlowBinding, state/nonce/S256 transaction with exact origin/callback/provider/epoch/validated return. State alone is insufficient; staging cannot change an in-flight callback's live origin policy.
- [ ] **T30.3** SSRF-safe discovery, bounded timeouts/no token logging, provider outage fails closed. Ingress authority/forwarded metadata must come from trusted route/transport.
- [ ] **T30.4** Use exact verified subject links and shared browser/native HumanEnrollmentPolicy. preprovisioned default denies unlinked subjects; explicit auto_create creates a fresh zero-backend-privilege principal/link atomically. Existing disabled identities deny, no email-link/role promotion; migration enrollment hold always overrides auto-create. Linking remains browser-bound with explicit proof.
- [ ] **T30.5** Optional encrypted provider-token vault only behind explicit feature; default discard upstream tokens.
- [ ] **T30.6** Optional back-channel logout verifies issuer/audience/signature/events/time/replay then indexes provider/subject/sid; no arbitrary claim/context lookup.
- [ ] **T30.7** Test login-CSRF/callback-injection/mix-up/redirect-confusion/linking attacks: attacker callback loaded in victim browser, missing/wrong cookie, other origin/tenant/provider/flow kind, tampered return path and stale concurrent tab all deny without replacing victim session. Baseline top-level GET/query callback; alternative response mode needs reviewed cookie policy.
- [ ] **T30.8** Implement enrollment hold/resume and concurrency tests: unique subject tuple, no duplicate principals, no auto-create across concurrent provider switch/rollback, no hold clearing by import/restart/policy edit. Reconciliation acknowledgement/resume binds current provider/generation/revision. Test native and SPA first-login parity.
- [ ] **T30.9** Implement audited versioned credential-only rotation for unchanged issuer/upstream client_id/auth method/callback/assurance; advance credential/admin revisions, not auth epochs. Bounded configured overlap; existing session/refresh/identity transcripts survive. Reject mixed semantic edits; compromise-triggered epoch invalidation remains a separate deliberate transition.

### T31 — Opaque sessions and human authentication context

- [ ] **T31.1** Fresh CSPRNG session ticket/keyed hash, app-origin/tenant binding, human auth reference, provider/subject/sid indexes and CSRF; secure host-only cookie, no JS OAuth tokens.
- [ ] **T31.2** Both idle/absolute deadlines and current human auth/provider/tenant generation required. Conservative coalesced last-seen never revives or extends absolute lifetime; document possible bounded early idle expiry.
- [ ] **T31.3** No-store safe session/principal/CSRF response, no upstream credentials/admin roles/internal assertion.
- [ ] **T31.4** Exact Origin and X-SkyOAuth-CSRF on unsafe calls including Connect POST; reject bearer+cookie ambiguity before credential consumption. T32.4 strips browser credentials before application forwarding, not on SkyOAuth auth endpoints.
- [ ] **T31.5** Fixation/login callback replay/cookie confusion/CSRF, independent expiry, concurrent updates, revocation/switch/store outage and session-origin crossover tests.
- [ ] **T31.6** Distinguish local/upstream logout and verified sid selection. M3 fixed session/CSRF/logout and verified revocation/security-disable paths remain reachable independently of an application route gate, including planned apply or exhausted observation budget. Preserve their own Origin/CSRF/credential/signature/store checks; test cleanup without minting forwarding evidence or clearing unrelated security vetoes. Native /oauth/revoke and its gate-independent test are M4/T40.15, not an M3 prerequisite.
- [ ] **T31.7** Session consumers use active pinned origin/route versions and their HumanAccessPolicy/audience, never newest staged versions or browser scope/tenant headers. Live security disable and runtime bundle gate still apply; capacity-only edits do not supersede authorization. Missing canonical tenant or RBAC denies.

### T32 — Browser gateway and explicit human-session profile

- [ ] **T32.1** Extend existing T25 with session support, not defer bearer implementation. Live validate session/auth context/provider epoch/origin and route-bundle deployment validity before minting internal evidence.
- [ ] **T32.2** Emit signer-group-key-signed skyoauth-internal+jwt/human_session/version with human sub, tenant/audience/scope/policy, backend_rbac, auth_time, opaque origin/auth/session refs, active pinned route revision and request-binding v1 method/scheme/authority/target_sha256. No raw path/query claim; TTL <=30s/session/applicable observation deadline, no fake WIF grant/client_id or prefix exemption.
- [ ] **T32.3** Deliver M3 controller preparation/apply/observation with >=2 replicas, durable ownership/sequence and resourceVersion-aware reconciliation. Scoped list/read discovers pending input operations; an isolated bounded fixed-argument EG/egctl helper prepares expected xDS before service-finalized immutable versions and security_admin approval, never inside the public auth-serving process or from a tenant digest. Test failed/incomplete translation, duplicate/conflicting result and security revision changes during preparation. Install existing host/listener VAP/RBAC guards and fixed mTLS GET-only management listener. Apply the same protected-scope projection to desired/observed config, excluding disjoint virtual hosts but retaining shared listener/security dependencies and ordered effective filters; omit only adapter-proven inert filters across all protected paths/overrides. Deny helper access to controller Kubernetes tokens/mTLS keys, inherited secrets and privileged sockets; test the sandbox, not just arguments. Implement strict registry-only activation with fresh evidence and unchanged sample ages; full begin gates the origin, unchanged contexts get unavailable/no renewal, changed dependencies deny. Poll <=10s/stale30s/max300s; new proxies have no grace. Test mode-matched transitions with no fallback, old epochs, partial apply and disable/forward-expiry after begin: compensate exact prior resources under abort_until, reobserve and reopen unaffected routes without clearing vetoes. Test failed/revoked/exhausted compensation remaining closed, fenced journal replay, cleanup during gating, 40s failover, hung proxy/withdrawal and observation cutoff. T50.4 audits the deployed mechanism, not its first implementation. Inject a known out-of-plan digest mismatch while prior evidence is fresh: immediate gate closure/new-call503 and terminal recheck, no 300s allowance; late matching reports cannot reopen and invalid/unapproved/mode-mismatched plans cannot activate.
- [ ] **T32.4** Enforce ordinary upstream-stage RequestHeaderModifier removal of every Cookie and X-SkyOAuth-CSRF field on every non-SkyOAuth route, including public SPA/assets/health/bearer paths with no ext_authz call. On protected routes authenticate original metadata first; retain gRPC removal only as redundant defense, not the sole mechanism. ResponseHeaderModifier removes all Set-Cookie fields on application responses, including duplicate/nonreserved cookies; no selective parser assumed. Only exact fixed SkyOAuth routes plus verified backend identity are exempt. Project removals/order/exemptions into the digest and reject absent rules. Test no-Check static requests, raw upstream/logs/retries/mirrors, whole-header response removal and genuine auth flows. Retain duplicate-auth-cookie, spoofed assertion/direct-backend/profile/cross-audience negatives; no credential copies/restoration and no claim of same-origin JS isolation.
- [ ] **T32.5** Validate profile-specific claim schemas and backend canonical tenant/RBAC, preserving bearer behavior. Any future gateway JWT optimization must preserve all profile/assignment/revocation controls.
- [ ] **T32.6** Map 401 authentication, 403 definitive authorization, 429 too_many_open_streams/rate_limited and 503 stream_capacity_unavailable/route_configuration_unavailable to typed HTTP/Connect results with bounded Retry-After. Full planned apply yields 503 for new cookie application calls; an unchanged established context gets unavailable with no renewed lease or closed_at, not terminal 403. Changed dependencies/revocation still deny. Configure transport failure as fail-closed 503. No availability/capacity login prompt, automatic logout, mutation replay or RPC HTML redirect.
- [ ] **T32.7** Unary/server streams/SSE/large downloads go Envoy -> backend; cancellation/reconnect/idle/body-nonbuffering and backend release-on-disconnect tests.
- [ ] **T32.8** Authorize workflow/artifact resources and long-response transmission via T32.12 admission/recheck leases, including download/SSE/RPC cancellation. Recheck backend RBAC; expired evidence cannot authorize a new request or continue past the last lease.
- [ ] **T32.9** Optional private ForwardAuth preserves typed evidence, cookie consumption, trusted forwarded chain and decision/error semantics, never plain public-client identity headers. Require a reviewed equivalent deployment enforcer for each gateway even when hosted on Kubernetes; Envoy observer assumptions are not inherited automatically.
- [ ] **T32.10** Cloudflare Tunnel versus Access/WAF/rate limits documented separately.
- [ ] **T32.11** Human_session live checks use actual pinned origin/route and parent security revisions/status, HumanAccessPolicy, session/authentication/epochs, action rules and deployment gate. Re-enable does not resurrect older evidence; unchanged route dependencies survive a registry-only bundle-pointer advance, while staged/capacity changes remain irrelevant. Apply-specific unavailable versus terminal denial follows §4.2. Verify key state after signature, including standby misuse; backend tenant/RBAC remains required and no WIF grant is fabricated.
- [ ] **T32.12** Implement §6.1.1 admission/close/tombstone/binding and <=100-item/64 KiB per-item rechecks. Leases default/critical <=15s, noncritical <=300s/context <=1h and session/auth/original observation deadlines; no grace/idle extension/resurrection. During full apply or its bounded compensation, unchanged pinned dependencies get unavailable/no renewal/no closed_at; changed/removed/security-disabled dependencies terminate. Registry-only activation retains unchanged contexts without resetting sample ages. Keep owner-only idempotent close, expiry-based orphan release, separate current capacity limits and per-session429/shared503 semantics. Test navigation/double-close races, five-orphan reconnects, cap lowering, mixed unavailable batches, planned-apply/abort recovery before versus after lease cutoff, immediate terminal denial on known out-of-plan mismatch versus unavailable without drift, changed-route re-admission and cleanup while gated. No mutation replay, queue or eviction; batching still costs store work.
- [ ] **T32.13** Implement shared digest-binding vectors: unpadded base64url SHA-256 of exact ASCII raw target, retaining query order/duplicates/escape spelling and absent/empty query distinctions. Compare before URL decoding; no raw target in assertion/continuation binding. Test 4 KiB query fixed-size binding, logging redaction and modified target denial. Keep method/HTTPS/registered authority validation, path-ambiguity rejection and actual Envoy rewrite/rematch rejection; no X-Original-header bypass.
- [ ] **T32.14** Implement signer-group keys, disjoint trust/permissions, publication/readiness, <=60s cache and bounded refetch under §6.2. Production active plus eligible separately held standby; audited promotion to clean replicas, degraded replenishment and no maturity waiver/compromised fallback. Add live tripwire: valid signature under unpromoted standby denies/alerts at check/admission/recheck; invalid-signature kid spoof cannot raise verified-compromise alerts; promoted/retired normal overlap still works, offline limitation explicit. Explicitly test a disabled active key with no eligible unaffected standby: fail closed, never use an immature/compromised key or waive readiness. Retain scale-out/cache/outage/flood/provenance tests. Benchmark signing and 10,000 idle continuations across lease/batch sizes, actual reads/writes, latency/CPU, release churn, quotas and mass reconnect; no unmeasured promise.

### T33 — Required TypeScript SPA library

- [ ] **T33.1** Evolve clients/typescript / @skyoauth/client: framework-neutral session/principal, login/logout/CSRF, bounded memory/cancellation, no token getter/persistent credential storage. Unauthenticated health helper remains separate.
- [ ] **T33.2** /react entry point has explicit loading/authenticated/unauthenticated/unavailable states; React optional peer excluded from core.
- [ ] **T33.3** Connect adapter's opt-in read-only reconnect uses finite jittered backoff/Retry-After/cancellation for shared-capacity or infrastructure503, not login. Per-session too_many_open_streams allows only one delayed retry at a valid <=300s hint plus bounded jitter, then surfaces capacity; budget persists across transient attempts and resets only after an established stream or explicit new user/app operation. Missing hint surfaces immediately; definitive auth denial stops. Test five-orphan recovery, persistent/shared exhaustion, invalid hints and no retry-loop reset. Backend releases on navigation/cancel; browser never sees handles. Fresh auth/RBAC, application cursors, ETag/If-Range safe resume and one-hour cap remain; no mutation replay/off-origin forwarding or framework peers in core.
- [ ] **T33.4** Runtime/declaration exports and versioned wire/errors align, no upstream-specific imports/config, no Node built-ins/polyfills in browser core; tested browser support documented.
- [ ] **T33.5** Real-browser E2E login/logout/reload/expiry/cross-tab invalidation, CSRF, ConnectRPC/cancel/unavailable/capacity states and browser-bound callback attacks; Node mocks alone insufficient.
- [ ] **T33.6** Same-origin HTTPS/no-userinfo targets, Fetch same-origin mode/credentials, X-SkyOAuth-CSRF header and API redirect rejection; forbid caller overrides or bearer mixing. Explicit top-level login follows OIDC; loopback development mode narrowly scoped.
- [ ] **T33.7** Negative off-origin health/auth reuse, Request/options/redirect/downgrade manipulation, CSRF leakage, logout/account cache and credential-free cross-tab signals. Injected fetch is trusted code, not exemption from URL/header checks.
- [ ] **T33.8** Pack npm artifact and install in independent examples/spa; verify declarations/exports/browser bundle without Node/React/Connect in core, adapter peers separately. Add CI package/browser checks when code lands.

**Gate M3:** the packed TypeScript library works in a real SPA with opaque cookie/CSRF only; no browser credential reaches application backends. Login-CSRF and explicit human-session policy/RBAC checks hold. Pinned routing/approval/guarded observer, stale-versus-mismatch behavior, close/capacity/retry, enrollment hold and standby tripwire tests pass. No Node/framework dependencies in core, no payload proxying and no bearer regression.

## 6. Native OAuth and reusable Rust CLI library (M4)

### T40 — Native server flow and client crate

- [ ] **T40.1** Stable metadata/endpoints and registered generated OAuth client IDs; client_admin provisioning and instance audience assignment precede auth. Exact IP-loopback redirect rules and supported grants.
- [ ] **T40.2** Fresh confirmation shows client/account/audience/scopes/session duration, exact loopback URI/port and server-derived comparison value. Rust caller displays descriptor before browser launch; user explicitly confirms it matches their CLI. Prior SSO/consent never auto-approves, conflicting tabs show superseded-login rather than redirecting to a replacement.
- [ ] **T40.3** Bind approval/code to client, redirect, S256 challenge, audience/scopes, verified human authentication, browser flow and epoch. Exact-Origin/CSRF/anti-framing POST, one-time cross-replica code use, native state validation; denial/expiry yields no code.
- [ ] **T40.4** Only scoped SkyOAuth credentials to CLI; no upstream tokens. Malicious local process with its own PKCE/loopback cannot silently receive a code via existing SSO.
- [ ] **T40.5** Required rotating refresh retains access <=300s, 12h/1h family defaults and audited opt-in maxima 7d/24h within stricter limits; no existing-family/auth_time extension. skyoauth_refresh_request_id is optional on the wire: no ID means plain one-time rotation, no receipt and normal replay revocation; invalid supplied ID is invalid_request. With ID, the <=30s authenticated-encrypted receipt recovers only the same committed values for exact token/ID/payload/current authorization, with no extra issuance/deadline. Replay cannot add/remove ID to switch paths. Rust always supplies ID and never silently downgrades after failure. Keep revoke, secure OS or explicit memory-only storage; no plaintext fallback.
- [ ] **T40.6** Device flow conditional: user-code verification/explicit approval pages, expiry/polling/abuse tests, no interaction bypass.
- [ ] **T40.7** Reusable clients/rust native API, thin cli/ reference and independent examples/rust-cli package consumer. Protocol logic in crate, terminal UX in executable; no server/DB/frontend dependency.
- [ ] **T40.8** Silent SSO, altered confirmation, denial/expiry/concurrent code redemption, stale-provider requests/codes/refresh and browser-cookie transplantation tests.
- [ ] **T40.9** External system browser, ephemeral IP-loopback-only listener, bounded callback path/state/lifetime and exact chosen redirect at redemption. Invalid callback/cancel/timeout cleanup; no login webview/password/secret fallback.
- [ ] **T40.10** Publish/test MSRV/TLS/runtime/features and Linux/macOS/Windows native support, minimal/default builds, required refresh protocol and optional OS-storage/GitHub/K8s adapters. Reference CLI persistence uses supported secure storage; minimal library can explicitly use memory-only refresh.
- [ ] **T40.11** Redacted credentials/errors, memory cache, explicitly scoped HTTPS origin/audience transport; no cross-origin forwarding or automatic mutation replay. Package and compile independent consumer without private workspace paths.
- [ ] **T40.12** Implement issuer /oauth/callback and __Host-skyoauth_native cookie distinct from app flow. Authorize creates browser-bound request; callback verifies full transcript/cookie/epoch, records human and rotates cookie; confirm requires rotated binding plus CSRF. App cookie/transaction ID alone never authenticates confirmation. Expire/consume on completion, denial or new conflicting flow.
- [ ] **T40.13** Issue private human_cli access with actual client_id, human sub, tenant/audience/scope, auth_time, opaque authentication ref, HumanAccessPolicy revision and backend_rbac constraints. Required refresh family links that authentication/context; T26 checks its revocation/epochs alongside client/policy. No WIF grant/act or access lifetime above 300s.
- [ ] **T40.14** Implement design §5.2.1 length-prefixed SHA-256/80-bit Base32 comparison v1 with shared server/Rust vectors; expose descriptor before launch, never PKCE verifier. Test changes to client/redirect/challenge/audience/scopes/state, concurrent local authorization, copied challenge, acknowledgement tampering and superseded cookie slots. State user-assisted/social-engineering limits, not phishing resistance.
- [ ] **T40.15** Test independent generic OAuth refresh without private fields: success/no receipt, plain lost response/replay revocation and added-ID replay denial. Test malformed/empty/duplicate ID and missing-ID replay of an extension attempt. Rust persists pending token/ID/payload securely, exact retries converge on one successor and remaining expires_in; cover consumed successor, receipt expiry/decryption/store failure, policy/logout/switch during retry and crash recovery without downgrade. Ten-minute command/tail reconnect must not restart mutations. Test default versus opted-in >70min idle, maxima rejection, no old-family extension or resurrection after changes. Credential-only rotation preserves family; WIF gets no refresh. In M4, test native /oauth/revoke during application apply/abort or observation-gate closure; client/token/store checks and non-enumerating family revocation remain mandatory, with no application gate dependency.

### T41 — Upstream adapter/exchange

- [ ] **T41.1** Human-login/optional-provider-exchange trait with explicit deployed capability checks, independent of operator authority.
- [ ] **T41.2** Authorized compatible Zitadel-issued exchange stays server-side, respecting real subject/actor semantics and normalizing downstream credential/profile.
- [ ] **T41.3** Do not assume arbitrary GitHub/K8s exchange or administrative audiences; local WIF required independently.
- [ ] **T41.4** Never return upstream admin token through generalized delegation; separate restricted adapter if needed.
- [ ] **T41.5** Replacement-provider tests preserve TypeScript/Rust contracts, metadata/profile/constraints/gateway transport and registered clients/origins.

**Gate M4:** an independent CLI uses the packaged Rust crate, issuer-local confirmation/comparison and required rotating refresh. Generic refresh works without private parameters; the Rust client uses bounded exact-retry recovery. A ten-minute session renews 300-second access without another browser prompt; expiry/revocation and non-idempotent replay require reauth. Human_cli verifies without WIF claims; platform/feature/storage/transport tests pass. Migration requires reauth only. A repository-local executable alone does not satisfy the gate.

## 7. Operational safety, deployment and migration (M5)

### T50 — Packaging and readiness

- [ ] **T50.1** Chart public/private gateway-policy/operator listeners, non-root/read-only context, service accounts, probes/resources/NetworkPolicies/disruption settings.
- [ ] **T50.2** PostgreSQL migrations/backup/restore, multi-replica atomic state and quarantine/rollback instructions.
- [ ] **T50.3** Isolate public/internal signers, reviewer/upstream service credentials and workstation operator/recovery keys. Provision eligible standby in separate custody, audited clean promotion and replenishment; test the live standby-use tripwire and honest cache/lease/containment bounds. No unmeasured signing-cost claim.
- [ ] **T50.4** Package/audit >=2-controller preparation/apply/observation, durable failover, VAP/RBAC host/listener scope and exact mTLS GET-only management listener; no broad admin/exec/portforward. Verify translator/helper isolation including denied access to controller Kubernetes service-account token, mTLS key, inherited secret FDs/mounts and privileged sockets and pinned artifact upgrades with complete-input/projection fixtures and actual proxy checks. Test public SPA/asset/health cookie and whole-Set-Cookie removal with no Check; unchanged digest/traffic after a disjoint b.example.com route edit or SecurityPolicy addition/removal whose filter is proven inert on every app.example.com path/override on the shared listener. Enabling that filter on a protected route, changing effective-filter order or shared auth/TLS must be rejected or change the digest. Separate observer eligibility from possible Envoy connection draining; test ordinary reconnect rather than promise transport continuity. Keep shadow-route/dependency/selector/namespace negatives. Exercise registry-only activation without gateway writes/gate closure/sample-age refresh; document/test origin-wide real-apply and incident-reenable interruption even with unchanged gateway contents, bounded abort/reobserve recovery after disable/forward expiry, wrong-mode/no-fallback rejection, unchanged stream lease cutoff, changed-context denial and gate-independent logout. Retain 40s failover/max300s/hung-proxy/readiness/replay cases and Helm/Argo/Flux submit-not-apply workflow; alternate gateways need equivalent enforcement. Inject fresh out-of-plan mismatch: close immediately, new-call503, terminal stream recheck, no stale-evidence allowance or reopening from old reports. Keep missing/expired/revoked/stale/mode-mismatched approval rejection explicit.
- [ ] **T50.5** Bound requests/token/claim sizes and cache churn; rate-limit exchange/login/native confirmation/discovery/admin with no privilege-expanding fallback.
- [ ] **T50.6** Safe latency/denial/audit metrics, no PII/token labels or secret-bearing logs. Redact cookies/CSRF/assertions and management dumps; observation heartbeats do not generate configuration-change audit churn. Alert stale evidence, known drift, exhausted budgets and verified standby misuse distinctly.
- [ ] **T50.7** SBOM/dependency/provenance review, vulnerability disclosure/patch/release docs for service and both clients.
- [ ] **T50.8** Audit bootstrap-preserving CI: fmt/lint/type/test/coverage, docs-only detection, all new workspace/package paths and packed consumers/browser/native jobs. Checks land with T21/T33/T40 implementations; M5 verifies coverage, not invents it late. README/manifests/lockfiles stay synchronized; skip != execution.

### T51 — Exclusive provider migration without resets

- [ ] **T51.1** Build full migration operator tooling/runbook on **T13.9's M1b sole transition primitive**. Immutable plan/dry-run/commit/rollback, expected login/config revisions and audited provider-only write boundary; no new alternate pointer writer.
- [ ] **T51.2** Snapshot stable tenants/principals/audience registrations/assignments/actions/checker public metadata, origin/route/bundle versions and separate capacity policies, clients/human policies/enrollment config and hold, all source/cluster/CA/reviewer/keyset configs, bindings/grants/defaults/activation state and issuer/operator metadata. Record replay preservation without exposing proof secrets. Enumerate human flow/auth/session/code/refresh state for invalidation, not equality; runtime route observations are not restorable permission.
- [ ] **T51.3** Test inactive replacement and verified links; plan rejects WIF/audience/client/origin/operator/gateway/signer mutation. Independent operator access requires no upstream-admin linking. Concurrent relevant configuration changes require replan.
- [ ] **T51.4** Atomically update human login/mapping state and monotonic epochs; set enrollment hold, invalidate app/native flows/authentication/sessions/pending codes/required refresh families and dependent continuations. Preserve WIF/registrations. Offline access residual <=300s, live checks deny and existing stream leases expire within their approved remaining window (default/critical <=15s; opted-in noncritical <=300s); no claim of instantaneous in-flight cancellation.
- [ ] **T51.5** Reuse prebuilt TypeScript SPA and independent Rust CLI with recorded artifact hashes after reauth; no SDK upgrade/rebuild/env/callback/client registration/deployment change.
- [ ] **T51.6** Unchanged GitHub/uploaded-key/two shared-issuer K8s callers, direct/delegated profiles and human clients. Dormant impersonation remains disabled; active impersonation is not a v0.1 subcase. Include required native refresh reauth after switch and browser continuation denial; no source/CA/reviewer/grant/audience edits.
- [ ] **T51.7** Compare pre/post allowed/denied policy fixtures and revisions. Single-use uses fresh proofs and consumed ones remain denied; projected Kubernetes proves reusable renewal. Both library wire/error fixtures stay compatible.
- [ ] **T51.8** Rollback through the same primitive with fresh epochs, never whole-DB restore over independent WIF/audience changes or resurrection of consumed human/proof state.
- [ ] **T51.9** Schema/restore preserves stable IDs, one-time state and disabled-policy markers; ordinary import is not a replay restore. Continuations are not restored as live streams; reconnect requires fresh admission. Required refresh consumed/revoked state cannot resurrect; route-runtime validity requires fresh observation.
- [ ] **T51.10** No client/gateway/backend redeploy or issuer/certificate rotation solely for a human provider change.
- [ ] **T51.11** Switch/rollback during IdP outage using portable independent operator and local recovery verifier; no upstream-admin link. Generic pointer/semantic writes deny; credential-only rotation keeps epochs; enrollment hold prevents accidental migrated-user recreation until explicit reconciliation/resume.

### T52 — Security conformance

- [ ] **T52.1** Malformed JWT/header/claim/key corpus, profile/type substitution, issuer/algorithm confusion, key URLs/private upload and rollover.
- [ ] **T52.2** WIF owner/repo/event/ref/env/workflow/cluster/tenant/audience/actor/binding/grant/scope/resource negatives and fixed capability/replay outcomes.
- [ ] **T52.3** **Login CSRF, OIDC callback abuse, redirect URI confusion, identity-linking confusion**, mix-up/state/nonce/PKCE/code replay, app/native flow-cookie crossover, silent SSO/confirmation attack, fixation and epoch rollback tests. Victim browser cannot acquire attacker's session by loading an attacker-initiated callback.
- [ ] **T52.4** Spoofed identity/route/assertion/original-target headers, backend cookie/CSRF leakage and reserved Set-Cookie attacks, direct backend/private/admin listeners, exact digest binding, disabled-route fallback and forbidden rewrites/rematching. Test actual raw upstream bytes, shadow-route admission and supported/rejected management-listener configurations, not only registry simulations.
- [ ] **T52.5** Public/internal signer separation, rotation/disable/standby misuse and continuation provenance; workstation/hardware recovery drills, provider credential-only rotation versus semantic transition, suspicious issuance, safe audit/redaction.
- [ ] **T52.6** Canonical tenant/resources, human RBAC versus WIF allowlists, destructive workflows and >30-second streams/downloads through actual T26/T32.12. Test lease cutoff on unavailable versus terminal denial, no idle extension/reuse, separate cap reductions without eviction, bounded orphan retry and observation deadline, alongside offline access TTL.
- [ ] **T52.7** Fuzz token/policy/metadata/confirmation/import parsers; k3s/Envoy load tests with concurrent login/code/proof consumption and revision changes.
- [ ] **T52.8** Independent review of staged provisioning/isolation, audience/routes/checkers, immutable active pins versus capacity/runtime state, approved controller/observer boundaries, enrollment/identity continuity, native comparison/refresh, separate signers and minimal dormant preservation. Deferred activation machinery or an admin UI is not implemented scope.

**Gate M5 / v0.1:** C01–C10, real WIF, both required libraries and every unconditional conformance row pass. Migration changes neither client artifacts nor WIF/audience/client authority, cannot bypass human invalidation and cannot promote upstream identities to operators. Optional subcases are conditional only where explicitly stated.

## 8. Conformance matrix — automated release blocking

| ID | Scenario | Expected result |
| --- | --- | --- |
| A01 | Valid GitHub push, required claims and selected approved grant/binding | Scoped WIF profile; only signed tenant/resource envelope plus RBAC permitted |
| A02 | Otherwise-matching non-push/missing event, wrong owner/repo/ref/environment/workflow | Denied; production binding cannot be satisfied by PR/dispatch/comment/workflow_run context |
| A03 | Selected source proof issuer/key/audience mismatch | Denied, no alternate verifier/key source |
| A04 | Public keyset overlapping rotation | Parent/source/binding/grant IDs stable; explicit old/new validity windows |
| A05 | Private-key upload or token-directed key URL | Rejected |
| A06 | Configured TokenReview authenticates SA/Pod and intended returned audience | Scoped token for selected tenant/cluster; no invented claim evidence |
| A07 | Wrong cluster/SA/audience, expired proof/deleted object | Denied under documented verifier semantics, no fallback |
| A08 | Browser cookie with valid CSRF/Origin | Typed human-session evidence at edge; canonical tenant and backend RBAC still required |
| A09 | Unsafe cookie call lacks correct Origin/CSRF | Denied |
| A10 | Cookie + bearer or bearer + internal assertion | Denied mixed profiles/credentials |
| A11 | Revoked/expired session or unavailable store | Appropriate 401/503, no fail-open |
| A12 | Browser and bearer streams/downloads beyond credential/context lifetime | Direct Envoy bytes; bearer closes by original exp and explicitly reconnects with fresh token, browser follows leases/1h cap; backoff/jitter and version-safe resume, no restarted mutation |
| A13 | Valid credential outside canonical resource tenant or WIF allowlist/human RBAC | Backend denies; names alone do not identify tenant ownership |
| A14 | Provider change with existing TypeScript SPA and independent Rust CLI | Same artifact hashes/endpoints/config, human reauth only |
| A15 | Migration with discovery/uploaded keys/two shared-issuer TokenReview clusters | Stable configs/CA/reviewer/keyset IDs and effective decisions |
| A16 | Migration with direct/delegation bindings/grants and dormant impersonation | IDs/modes/defaults/constraints/revisions preserved; dormant remains disabled. No active-impersonation gate in v0.1. |
| A17 | Rollback after independent policy/audience change | Those changes untouched; fresh human epochs, no resurrected state |
| A18 | Spoofed identity; billing/deploy and public SPA/assets/health backends capture request/response metadata, including no-Check routes | All non-SkyOAuth routes remove every Cookie/X-SkyOAuth-CSRF upstream and every Set-Cookie response field independent of ext_authz; removals/order/identity-bound exemptions are projected and missing rules reject. No copies in logs/retries/mirrors, mixed/duplicate auth ambiguity denies, protected assertion cannot cross audience; genuine fixed SkyOAuth cookie flows still work |
| A19 | Independent issuer-key rotation | Verification through overlap without client/backend config change |
| A20 | Human IdP unavailable | Valid WIF and independent operator recovery work; fresh human login fails closed |
| A21 | Disable grant/assignment/policy with outstanding JWT | No new issuance; offline residual TTL explicit; committed-revocation live checks deny |
| A22 | Email-only link or upstream admin-role claim | No automatic linking/operator elevation |
| A23 | Valid proof replay on reusable source | Fresh evaluation may issue new output jti; revocation still enforced |
| A24 | Eligible on-demand single-use proof replay across replicas/grants | Exactly one issuance, missing jti/replay/store failure denied |
| A25 | Multiple same-audience grants/direct or different target services | Generated grant selector chooses authorized actor/target; override/wrong tenant/mode denies |
| A26 | Scope omitted with/without defaults, empty/excessive scopes | Narrow explicit defaults or invalid_scope, never full ceiling by omission |
| A27 | Live SSO and malicious local public-client PKCE/loopback | Explicit confirmation always; deny/expiry no code |
| A28 | Independently keyed clusters share issuer | Only selected cluster validates its proof; no cross-cluster probing/fallback |
| A29 | Tenants share GitHub issuer or object names; crossed references | Registrations coexist, ownership crossover denied |
| A30 | Profile-required claims absent/unknown/contradictory, including WIF constraints/revision | Fail closed by explicit profile; no human subject-prefix exemption |
| A31 | Wrong checker/audience/tenant/action, superseded authorization or unavailable checker | Invalid authority denies; unavailable returns no allow and no positive cache/RBAC replacement, no authentication redirect |
| A32 | Concurrent/reopened bootstrap, forged IdP admin, revoked operator/replayed recovery | One enrollment only, no elevation/replay, audited independent restoration |
| A33 | Idle/absolute/session-origin and provider/sid targeting | Either expiry denies; no revival/absolute extension; only correctly selected sessions revoked |
| A34 | Concurrent native code/refresh reuse and human switch/rollback | Single code consumption/refresh successor across replicas; plain consumed-token replay revokes, only opted-in bounded exact receipt retry is idempotent, no add/remove-ID replay; affected human state invalid, registrations stable |
| A35 | Provider switch/restore after proof consumption | Consumed stays consumed through config/digest-key changes or quarantine |
| A36 | Real GitHub/k3s -> M2 Envoy -> API; spoof/outage/direct-backend attacks | Positive bearer path works before M3, bypasses deny |
| A37 | Production predicate omitted or optional predicate removed | Required omissions reject; optional omission semantics explicit, removal reviewed as widening |
| A38 | Device/impersonation not shipped | Not advertised/accepted for issuance; dormant impersonation API storage allowed only disabled; capability gain does not activate |
| A39 | Packed TypeScript core and separately imported adapters | Framework-free browser/types work, no Node built-ins/polyfills or peer frameworks in core |
| A40 | SPA foreign-origin/userinfo/HTTP/redirect/options attack, off-origin health base reused | Reject before CSRF/credential forwarding, no token API/storage/mixed auth or silent mutation replay |
| A41 | Packaged Rust crate in independent Linux/macOS/Windows CLI, default/minimal features | PKCE/loopback/cancel works without server/DB/frontend deps; redaction/origin bounds, no plaintext keychain fallback |
| A42 | Both client profile fixtures and prebuilt consumers through switch/rollback | Stable per-profile wire/error contract and unchanged artifacts; distinct credential models |
| A43 | Tenant B registers/grants tenant A's audience/project name, or uses shared audience on A-owned resource | Write/issuance outside instance assignment denied; backend canonical tenant mismatch denies even if audience/scope/name matches |
| A44 | Valid human_cli or human_session without WIF grant; WIF forged into human shape | Legitimate explicit human profile accepted only with complete human policy/evidence and RBAC; missing discriminator/contradictory claims or wrong route denies |
| A45 | Direct grant with no target service and registered backend checker/action | Live check works; delegated subject is not checker authority; unknown action or another audience's checker denies |
| A46 | Two registered origins/tenants with different human providers; spoofed Host/Forwarded or tenant query | Correct provider/session tenant per registered trusted origin; unknown/crossed/spoofed origins deny before redirect |
| A47 | Active provider changed by PATCH/import/reload/delete/auth-critical edit; initial activation/switch/rollback via plan | Generic writes reject atomically, epochs unchanged on denial; only guarded commit advances pointer and epochs |
| A48 | Empty installation -> tenant/audience/origin/client/principal/source/grant and initial provider via staged operator tools | Workload chain M1a, human chain M1b; portable operator/local verifier, no SQL or M4 dependency; missing roles deny |
| A49 | Identical operator labels in two tenants and create/export/reapply | Distinct generated IDs, deterministic authorized mapping, no global-name collision/probe; exchange names instead of IDs reject |
| A50 | Repo-wide and deployment binding map different actors; selected grant owns one | Matching eligible binding for grant actor succeeds; other actor overlap irrelevant. No eligible match denies; multiple same-actor matches deterministic with no union. |
| A51 | Attacker-initiated app login callback loaded by victim; redirect/linking/mix-up attacks | Missing/wrong browser flow binding denies without creating/replacing/linking victim session; PKCE/state/nonce plus exact transcript enforced |
| A52 | Native issuer callback/confirm with no app cookie, correct native binding; stolen transaction ID/wrong cookie | Correct issuer flow succeeds with explicit approval; transaction ID/app cookie/foreign browser alone denies; rotated binding consumed |
| A53 | Unsupported impersonation create/import, then capability upgrade and activation attempts | Disabled/reapproval record round-trips normally; enabled unsupported input rejects; upgrade/PATCH/import cannot activate, future reviewed activation required; no activation operation ships in v0.1 |
| A54 | TokenReview/projected token reused before rotation, then rotated; single_use configuration requested | Reusable renewal works both times with fresh validation; single_use enrollment/import denied even with local keys; no verified-jti assumption |
| A55 | Private access/internal types versus at+jwt/ID token/profile confusion | Only exact implemented private type/profile/ingress pairs accepted; WIF does not invent client_id; actual CLI client_id required |
| A56 | Stream page navigation/close races, five orphans and reconnects, shared quotas, origin/instance cap changes and unavailable batches | Owner close releases once, foreign/replay cannot reopen, orphans count only to lease. Current min(origin cap, instance ceiling) affects new admission only, no auth/pin change or eviction. Per-session429 gets at most one hinted delayed read-only retry; shared503 gets finite jittered retries, not login; retry budget cannot reset in a loop. Last lease/<=1h/session/observation bounds remain, unavailable never renews or terminally closes; known denial does |
| A57 | Generic refresh without ID, optional-extension replay/lost reply, family policy/expiry/switch | Plain rotation succeeds without receipt; plain consumed replay revokes even with added ID. Malformed/duplicate supplied ID rejects; extension cannot downgrade. Rust always sends ID; <=30s exact retry returns one committed successor/remaining TTL without widening. Keep 7d/24h maxima, current authorization and no plaintext fallback |
| A58 | Billing/deploy selection; pending preparation, incident-disable recovery, protected-scope digest, registry-only versus full activation and failover | Correct audience/policy and exact-before-segment-prefix precedence; ties, wrong/missing methods, absent routes and disabled winners deny without broader fallback. Only the exact mode-bound security_admin-approved plan may activate; missing/expired/revoked/stale/wrong-mode approval denies without a fallback. Staging harmless; M3 scoped worker finalizes expected digest before approval, pending/caller/conflicting/stale results reject and list/read cannot cross scope. 09:20 disable invalidates the 09:00 forward approval; disable or forward expiry after begin triggers exact preapproved abort until abort_until, reobserve and reopen only prior unaffected routes, preserving new vetoes; failed/revoked/exhausted compensation stays closed; activation clears only fresh explicit targets with atomic revision checks, configured-disabled still denies, rollback/replacement cannot bypass or resurrect evidence. Disjoint same-listener vhost edits and other-host policies adding only proven-inert filters leave digest/eligibility unchanged; enabling overrides/effective-filter order changes do not; overlaps/shared security changes do not. Registry-only activation retains fresh deployment evidence/original ages, no writes/closure and unchanged routes survive. Registry-only approval cannot begin after a freshness failure; mode change needs reapproval. Full apply, incident reenable and abort give origin-wide new-call 503, unchanged contexts unavailable only to last lease, changed dependencies terminal; logout/revoke remain usable. A fresh out-of-plan mismatch closes the gate immediately, new calls get503 and rechecks terminally close contexts without the 300s allowance; old matching reports cannot reopen, recovery requires approved reconciliation/fresh complete evidence and no context resurrection. Retain new unlabeled/wildcard/omitted-host and cross-namespace shadow-route guards, management isolation, 40s failover/stale30s/max300s, new-proxy readiness, epoch replay and restore/reobserve tests |
| A59 | Legitimate CLI plus concurrent malicious native request; comparison-field changes and superseded tab | Server/Rust v1 descriptor agrees only for exact request; CLI displays port/code, page requires matching acknowledgement; no silent replacement; PKCE/state remain required |
| A60 | First browser/native login in default/auto-create mode, concurrent callback, disabled user, switch/rollback hold | Default denies; opt-in creates one zero-privilege exact-subject principal; no email merge or disabled replacement; migration hold prevents recreation until explicit reconciliation/resume |
| A61 | Raw-target variants and 4 KiB query, digest tampering, rewrites/rematching | Fixed 43-character SHA-256 binding of exact bytes, no raw-query duplication; order/duplicates/escape spelling/empty query significant; mismatch or unsupported configuration denies, logs redact |
| A62 | Signer scale-out/rotation, compromise/standby promotion, valid standby signature before promotion and invalid-signature kid spoof | Eligible standby prepublished but private custody separate; audited clean promotion avoids publication wait, not containment. Live check/admission/recheck denies and alerts valid unpromoted-standby evidence; invalid signature cannot trigger verified alert. Offline key-set limitation explicit; previously promoted retired overlap remains. Disabled active key with no eligible unaffected standby fails closed; no immature/compromised fallback or readiness waiver; degraded promotion alerts/replenishes, purpose/cache/continuation bounds and measured load remain |
| A63 | Active provider secret/key-reference rotation versus changed issuer/client_id/auth method/callback/assurance | Credential-only audited revision advances preserve epochs/session/refresh; mixed semantic changes require guarded transition; no arbitrary fallback or exported secret |
| A64 | macOS/Windows/Linux workstation operator and offline recovery against Linux service | Private keys remain on workstation/hardware; scoped remote writes and instance-bound challenge response work without server/DB/M4 dependency or key export into pod |

All unconditional rows block full v0.1. Optional device-flow subcases apply only to a later explicitly included profile; unsupported device issuance and disabled-only impersonation preservation/rejection remain unconditional. Native refresh and server support for its optional retry extension are required; clients may omit the extension, while the Rust library uses it. Active impersonation, approval tables/endpoints and two-person activation tests are deferred to its future ADR. Neither client library, direct/delegated WIF, native confirmation, operator recovery nor profile-appropriate live checking is optional. M2 is an earlier usable milestone, not a claim that the full v0.1 suite has run.

## 9. Delivery dependencies and issue boundaries

| Order | Block | Prerequisites | Output |
| --- | --- | --- | --- |
| 0 | Bootstrap PR #2, landed | None | Service, TypeScript health helper, workspace/CI only |
| 1 | M0 / T00 | Inspect bootstrap | Reviewed public/operator/client/security contracts |
| 2a | M1a / workload parts of T10–T14 | M0 | Workload authority/replay, tenant/audience/checker/actions, portable operator and local bootstrap/recovery |
| 2b | M1b / human parts of T10–T14 | M1a; parallel with M2 | Versioned origin/routes/bundles/controller and operational limits, enrollment/client/provider policy, browser/native/refresh/continuation state and sole provider transition |
| 3 | M2 / T20–T26 | M1a, not M1b | Signer/JWKS/WIF, Rust workload library, bearer Envoy and receiver-authorized WIF action checks |
| 4 | M3 / T30–T33 | M1b, M2 | Enrollment-safe OIDC, approved controller/scoped observer/guard enforcement, cookie consumption, private signer/standby, stream lifecycle and TypeScript SPA |
| 5 | M4 / T40–T41 | M2, M3, M1b OAuth state | Native callback/comparison/confirmation, standard rotating refresh with optional retry extension, reusable Rust library/reference CLI |
| 6 | M5 / T50–T52 | Above | Deployment/CI audit, full switch runbook/invariance/recovery and unchanged-artifact conformance |

**Slice assignment:** T10/T12 are implemented first for workload authority/replay in M1a, then for human state/policy in M1b; logical type definitions are reviewed together. T13.1–T13.7/T13.10 provide operator/local recovery in M1a, T13.8 splits provisioning and T13.9 is M1b. T14.1–T14.4 provide audience/checker/WIF action authority in M1a (human/stream fields before M3); T14.5–T14.7/T14.9 are M1b; T14.8 applies to each slice's objects. T32.3 implements and deploys route enforcement in M3; T50.4 audits/packages that existing mechanism. M2 needs no browser/provider/refresh/continuation/controller handlers or tables. Model/restore invariants become blocking when their slice first lands; all are exercised before full v0.1.

Reviewable implementation slices: workload schema/operator/trust/policy; signer/exchange/Rust WIF; TokenReview/bearer gateway/live checks; parallel human registry/state; browser-bound OIDC/enrollment/route enforcement/assertions/stream continuation and TypeScript package; native comparison/refresh/Rust library; deployment/migration. Keep tenant/isolation tests and independent audience authority even in one-tenant deployments. Defer admin UI, self-service tenant onboarding, invitations, device flow, vault/provider exchange, alternate gateways and active impersonation. New package CI/consumer tests land with code.

## 10. Definitions of done

**Protocol:** explicit standard/private grant distinction and private credential typing, selectors/defaults/binding selection/replay/constraints; profile-specific verification without upstream-provider configuration or subject-prefix exemptions.

**WIF:** authorized discovery/uploaded-key/TokenReview enrollment, generated stable selectors and direct/delegated service access within instance audience assignments. Secretless GitHub/K8s API calls and correct renewal modes; impersonation not required.

**Gateway:** fail-closed bearer M2; M3 consumes browser credentials, binds exact request/audience and uses active immutable route pins. Named approval/scoped admission/controller/isolated observer enforce deployment, with distinct bounded stale-observation and known-mismatch behavior. Local internal signer/standby tripwire, bounded stream lifecycle and explicit release; no rewrites/rematching, body proxy or backend-RBAC bypass.

**TypeScript SPA:** packaged @skyoauth/client is browser/framework-neutral, not Node health/workload code; memory-only session/CSRF, strict same-origin transport, no OAuth-token getter and no Node/framework core dependencies. Real-browser/package/type/adapter tests include distinct capacity/infrastructure errors, one bounded orphan-recovery retry versus finite shared retries, no login on503, and backend slot release on cancellation.

**Rust CLI:** reusable packaged skyoauth-client works in an independent CLI with PKCE/system browser/loopback, request comparison/explicit approval and required rotating refresh under the 300-second access cap. It always sends the optional retry ID, while generic OAuth clients can refresh without it. Test renewal/replay/revocation and secure persistent or explicit memory-only storage. Thin executable, no server/database dependency or unsafe fallback.

**Administration:** M1a workload provisioning via portable workstation operator/local verifier precedes M2; M1b human provisioning/transition precedes M3. Independent key custody/roles/recovery, exclusive semantic transitions, safe credential rotation, exact deployment approval and enrollment holds cannot be bypassed by upstream identities/imports. Staging, polling and capacity-only changes do not mutate active authorization. Disabled-only impersonation preservation needs no active-mode machinery.

**Migration:** only affected human configuration/authentication state changes through guarded commits. Prebuilt artifacts, audiences/actions/checkers, origin/route/bundle versions and capacity policies, clients/human policies, WIF sources/keysets/bindings/grants/dormant status, issuer keys and effective WIF decisions stay stable; consumed state never revives. Runtime observations refresh independently and cannot be restored as permission.

**Security:** every credential traces to an explicit verified profile and complete policy/authentication provenance, canonical resource tenant and backend RBAC. Revocation/race limits are honest. All unconditional A01–A64 are demonstrable, including login-CSRF/redirect/linking defenses.

## 11. ADR decisions to ratify

These are proposed starting decisions, not claims of implementation or automatic maintainer approval. A changed decision updates both docs and affected tests. Implementation reviews validate the linked acceptance cases and publish measured capacity/outage behavior.

| ADR | Decision | Proposed baseline |
| --- | --- | --- |
| ADR-001 | Issuer/discovery | One stable canonical HTTPS issuer independent of human providers |
| ADR-002 | Signer/recovery | Public signer/JWKS M2; shared internal signer-group keys/private set M3 with publication/cache/readiness bounds and measured cost. Active plus separately held eligible standby, audited clean promotion/degraded replenishment. Live verified-standby-use tripwire denies/alerts; offline prepublished key sets cannot enforce instantaneous state. Per-replica enrollment remains a future alternative. |
| ADR-003 | Sessions/state | PostgreSQL keyed hashes, explicit deadlines/origin/authentication epochs and browser flow bindings |
| ADR-004 | Native OAuth | Rust PKCE/system browser/issuer cookie/comparison/fresh approval and required rotating refresh. Plain standard refresh works without ID; optional 30s encrypted exact-retry extension used by Rust, not sender constraint. Defaults 12h/1h, opt-in maxima 7d/24h within stricter limits, no old-family extension. Sender-constrained retry and device flow deferred. |
| ADR-005 | WIF adapters | Three source kinds, fixed source selector/cluster config and keyset parent; reusable projected tokens |
| ADR-006 | Modes | Required direct/delegation; retain disabled impersonation policy only, active subsystem/approval machinery deferred |
| ADR-007 | Backend identity | Original bearer or purpose-signed human evidence; unconditional route-stage Cookie/CSRF removal and whole Set-Cookie response removal on every non-SkyOAuth route, including no-auth static paths. Exact identity-bound exemptions, not selective-cookie parsing. Fixed target digest/no rewrites; actual pinned/security dependencies govern invalidation, not staging/polling/capacity or an unrelated bundle-pointer change. Gateway-metadata-only routing remains deferred. |
| ADR-008 | Policy writes | Revisioned role-scoped DB/GitOps, full-plan authorization and explicit widening/deletion approval |
| ADR-009 | Upstream exchange | Optional compatible provider operation server-side, normalize downstream credential |
| ADR-010 | Live revocation | Access <=300s/internal evidence <=30s; browser leases default/critical <=15s, noncritical <=300s/context <=1h plus observation bounds. Temporary unavailable grants no renewal, terminal deny closes. Separate operational quotas, idempotent release and distinct per-session/shared errors; one hinted orphan retry versus finite jittered shared retry. Bearer reconnect/range resume stays; no general bearer continuation or mutation replay. |
| ADR-011 | Cluster/authority | One bridge issuer, registered source IDs disambiguate clusters, not issuer alone |
| ADR-012 | Migration | Sole provider transition with monotonic auth invalidation; WIF/audience/client/operator state preserved |
| ADR-013 | Operator trust/provisioning | Independent keys/local roles, M1a workstation operator/local verifier and M1b human contracts. client_admin requests immutable preparation; the M3 scoped worker finalizes the version before security_admin approval. Approval binds all affected security revisions and explicit reenable_targets; activation clears only named current vetoes. No implicit role inheritance, generic enable PATCH or stale-plan recovery. |
| ADR-014 | Tenant scope | Composite references, instance audience/origin assignment, same-tenant trust/grants and mandatory backend resource mapping |
| ADR-015 | Exchange semantics | RFC direct subject exchange versus private actor mapping; explicit generated selectors and grant-directed bindings |
| ADR-016 | Replay/constraints | Reusable default/projected tokens; single-use only verified on-demand capability; profile-specific signed constraints/revisions |
| ADR-017 | Clients/layout | Preserve service/TypeScript bootstrap; mandatory SPA npm package and reusable clients/rust crate, thin native cli/; artifact/platform gates |
| ADR-018 | Resource servers | Instance audience registry/tenant assignments, separate receiver checker identities and persisted action rules |
| ADR-019 | Human credentials/private types | Explicit human_cli/human_session versus WIF; complete human policy provenance/backend_rbac mode, private JWT types rather than partial RFC 9068 |
| ADR-020 | Browser routing/binding | Assigned origin/distinct app-native bindings and guarded Gateway/listener/host scope. M3 isolated pinned translation precedes approval; scoped list/result APIs discover/finalize work. Project protected vhosts and ordered effective filters/shared dependencies, excluding only proven-inert other-host filters; HCM changes may still drain connections. Sandbox the translator away from controller credentials. Mode is immutable preparation/approval input; wrong-mode execution and fallback deny. Registry-only activation reuses unchanged fresh deployment evidence without refreshing its age or closing the gate; real gateway apply interrupts origin cookie traffic, unchanged contexts get unavailable only to their lease, cleanup stays independent. Gateway approval preauthorizes only exact bounded compensation to the captured prior pair; a newer disable/forward expiry after begin triggers abort/reobserve, never restoring security state. Known out-of-plan mismatch closes immediately with terminal rechecks and no stale allowance. Sole-writer GitOps cost, >=2 fenced controllers, fixed mTLS observer, poll<=10s/stale30s/max300s and cluster-admin boundary remain explicit. |
| ADR-021 | Exclusive provider writes | Read-only active observations, generic mutation/import rejection, sole epoch-advancing semantic transition M1b; separate audited credential-only rotation preserves epochs |
| ADR-022 | Identifier and binding lifecycle | Generated opaque IDs + tenant-local names/create-reference mapping; selected grant's actor/approved binding set filters evidence |
| ADR-023 | Enrollment and continuity | preprovisioned default, explicit zero-privilege auto-create; switch/rollback hold and deliberate generation-bound resume |
| ADR-024 | Delivery scope | M1a -> usable M2; parallel M1b before M3; full v0.1 still both clients/migration/isolation, active impersonation machinery deferred |

## 12. References

- [Architecture and roadmap](skyoauth-design.md)
- [Bootstrap PR #2](https://github.com/skyoauth/skyoauth/pull/2) and [landed tree](https://github.com/skyoauth/skyoauth/tree/8f81df23efd4c4a0cfe522f711a9ca56f294aab1)
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html): subject/actor roles and act
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): browser-bound OAuth transactions, CSRF/redirect/mix-up protection
- [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) and [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html): native refresh/revocation
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html): Base32 comparison-display encoding; correlation protocol is project-specific
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html): external browser, loopback and native interaction
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html): JWT profile separation
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html): at+jwt/client_id requirements, contrasted with the chosen private profile
- [Fetch Standard](https://fetch.spec.whatwg.org/): same-origin credentials/mode/redirect controls
- [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc)
- [Kubernetes TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) and [projected token rotation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Envoy Gateway extAuth](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
- [Envoy route configuration](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto) and [ext_authz filter](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto): verify deployed route normalization/mutation behavior
- [Envoy Authorization service](https://www.envoyproxy.io/docs/envoy/v1.40.1/api-v3/service/auth/v3/external_auth.proto): header removal and explicit denial status; test the selected deployment version
- [Kubernetes ValidatingAdmissionPolicy](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/): fail-closed API-server admission and deployment trust boundary
- [Envoy administration interface](https://www.envoyproxy.io/docs/envoy/latest/operations/admin.html) and [Envoy Gateway admin access](https://gateway.envoyproxy.io/docs/troubleshooting/envoy-proxy-admin-interface/): loopback admin is not an authenticated remote observer
- [EnvoyProxy customization](https://gateway.envoyproxy.io/v1.10/tasks/operations/customize-envoyproxy/) and [egctl translation](https://gateway.envoyproxy.io/v1.10/tasks/operations/egctl/): proposed static management listener and pinned translator adapter; actual integration tests remain required
- [Envoy Gateway request header removal](https://gateway.envoyproxy.io/docs/tasks/traffic/http-request-headers/) and [response header removal](https://gateway.envoyproxy.io/docs/tasks/traffic/http-response-headers/): route-level whole-header removal independent of ext_authz; validate the pinned adapter and normal-versus-early filter ordering
- [Envoy HTTP filter ordering and route-based enablement](https://www.envoyproxy.io/docs/envoy/v1.40.1/intro/arch_overview/http/http_filters): resolve effective per-route filters and overrides; global HCM filter additions may drain connections even when protected-route authorization is unchanged. The selected Gateway/Envoy adapter still requires integration tests.
