# SkyOAuth — Detailed design, implementation tasks, and release gates

> **Status:** proposed implementation plan, 2026-11-15; revised for both PR #1 review rounds and PR #2 bootstrap. Paired with [skyoauth-design.md](skyoauth-design.md). All authentication checkboxes remain **unchecked**. The landed service/health-client scaffold is not an implementation of these security contracts.

## 0. Delivery principles

The central outcomes are **secretless GitHub Actions → protected cluster API WIF** and **zero-client-change / zero-WIF-reset human IdP migration**. Browser sessions, gateway integration, a **TypeScript library for SPAs** and a **reusable Rust client crate for CLI applications** are all required before v0.1. A Node-only library or a repository-local Rust executable alone does not satisfy the client requirements.

- Human migration may require reauthentication, not changes to client/backend binaries, packages, settings or deployments. Preserve every source kind, keyset, binding, grant, audience assignment, client/origin registration and effective WIF decision.
- Envoy is the application data plane. SkyOAuth processes bounded authentication/authorization metadata, never uploads, downloads or stream bodies.
- The stable issuer and signing keys are independent of the human IdP. Explicit private credential profiles separate WIF access, human CLI access and gateway-only human-session assertions.
- Instance-owned resource-server/audience authority bounds tenant policy; services a workload acts as are not resource servers or policy-check callers. Canonical backend tenant mapping and RBAC remain mandatory.
- Direct workload and attributed service delegation are required. True impersonation is conditional; unsupported records are accepted only disabled and require fresh explicit approval if support later ships.
- Standard RFC 8693 direct exchange and the single-proof service-delegation extension are distinguished. No incomplete RFC 9068 `at+jwt` claim: use the private types defined in design §6.
- The only active-provider write path is an authorized switch transaction with epoch invalidation. PATCH/import/config reload cannot bypass it.
- Operator/recovery/reviewer keys are privileged operational trust anchors, not static application API secrets. No SPIRE/sidecar/cloud STS dependency is required.
- Both client profiles have package, real-runtime and migration tests. Share wire/error fixtures, not browser-unsafe token APIs or server dependencies.
- Every security requirement needs positive and negative tests; the tasks below do not claim they are already implemented.

## 1. Repository layout and bootstrap integration

PR #2 landed in `main` at `8f81df23efd4c4a0cfe522f711a9ca56f294aab1`, establishing `service/`, a Cargo workspace, `clients/typescript/` and CI. Retain these homes. This documentation-only PR neither moves bootstrap files nor creates empty crates. The following is a target layout; most auth modules are planned, not present.

~~~text
Cargo.toml            Existing service member; add clients/rust and cli with code
service/              Existing skyoauth-service (Axum/Tokio)
  src/main.rs         Process/listener wiring; M1 local operator subcommands
  src/lib.rs          Service composition
  src/core/           Proposed tenant/principal/profile/decision types
  src/config/         Validated configuration and reloads
  src/persistence/    PostgreSQL repositories, revisions and transactions
  src/admin/          Independent operator roles, bootstrap and recovery
  src/registry/       Resource servers, audiences/actions, clients and origins
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

M1 operator commands live in **the existing service binary's operator/bootstrap subcommands**, including local recovery and private operator-client plumbing. They do not depend on the M4 native OAuth library/CLI. `cli/` is the later application/reference consumer, not the bootstrap prerequisite. T13 supplies a complete operator write path before M2.

The existing TypeScript arbitrary-baseUrl `health()` helper is unauthenticated bootstrap functionality. It cannot define the future authenticated session transport's origin boundary. Keep `@skyoauth/client` as the browser core rather than creating competing `packages/browser` or `crates/client` homes. Future TypeScript workload helpers are additional nonbrowser surfaces.

Implementation PRs adding/moving modules, workspace members or package entry points update manifests/exports, lockfiles, CI paths/build/test/coverage, package-consumer examples and README together. Preserve the bootstrap's docs-only skip behavior; a skipped job is not a passed runtime test.

## 2. Public and operator contract — specification tasks

### T00 — Protocol and threat model (M0)

- [ ] **T00.1** Freeze public issuer/token/JWKS, app-origin auth routes, issuer-native callback/confirmation, private gateway/live-check and operator boundaries.
- [ ] **T00.2** Version errors, 401/403/429/503 semantics, no-store/caching, cancellation, bounded retries and non-enumerating failures. No automatic replay of mutations.
- [ ] **T00.3** Specify exact protected types `skyoauth-access+jwt` and `skyoauth-internal+jwt`, signed profile/version and required WIF/human_cli/human_session claim sets. Reject profile/ingress mismatches and ID tokens; do not advertise RFC 9068 compliance or emit `at+jwt`.
- [ ] **T00.4** Freeze issuer, audience registry, principal kinds, scopes, claim namespace and constraints. WIF uses explicit allowlists; human profiles explicitly use backend_rbac mode with mandatory canonical tenant/scope/RBAC checks. Persist action-to-scope/profile/resource rules; unknown modes/fields/versions deny.
- [ ] **T00.5** Specify original bearer versus gateway-only signed human assertion transport, request binding, header sanitization, no dual credentials and separate cookie Origin/CSRF semantics.
- [ ] **T00.6** Specify session idle/absolute expiry, conservative coalescing, flow-cookie/code lifetimes, auth epochs, JWT/skew caps, logout, rotation and restore quarantine.
- [ ] **T00.7** Threat model malicious CI, issuer/cluster/key confusion, audience/tenant escalation, subject/resource-server confusion, profile substitution, replay, **login CSRF, OIDC callback abuse, redirect URI confusion, identity-linking confusion**, native-client impersonation, generic-provider-write bypass, operator recovery and runtime/database compromise.
- [ ] **T00.8** Ratify signer/key isolation, provider vault/delegation, native confirmation, signed internal assertion and conditional impersonation ADRs. Explicitly scope device/refresh features.
- [ ] **T00.9** Specify RFC 8693 direct subject exchange versus private service-delegation actor grant, selector/proof roles, grant-directed binding evaluation, narrow scope defaults, errors and unsupported two-token delegation. Private grant URI is not claimed IANA-registered.
- [ ] **T00.10** Ratify independent adm identities, mTLS registration/local role checks, complete tenant/client/principal provisioning, private endpoints, local bootstrap and bounded offline recovery. Upstream claims cannot assign operator rights.
- [ ] **T00.11** Define tenant ownership/composite references, instance audience assignment and canonical-origin ownership, nonunique issuer strings and same-issuer cross-tenant/cluster fixtures.
- [ ] **T00.12** Define matcher omission and source-capability replay semantics: required production claims cannot be omitted; reusable default; single-use only verified on-demand JWTs, never projected Kubernetes/TokenReview sources.
- [ ] **T00.13** ADR-017: both client library contracts, package/crate identities, supported browser/native environments, typed errors and migration fixtures; no SPA OAuth-token API or required server dependency in the Rust crate.
- [ ] **T00.14** Adopt the bootstrap-aware layout in §1, distinguish existing health scaffold from proposed auth, and specify manifest/CI/packaged-consumer gates.
- [ ] **T00.15** Ratify ResourceServer/AudienceTenantAssignment/ResourceAction/checker ownership and explicit HumanAccessPolicy/credential profile sources; no free-string self-assignment or subject-prefix exemption.
- [ ] **T00.16** Freeze registered-origin tenant resolution, app versus issuer-native flow cookies/callbacks, exclusive provider transition primitive, generated-ID create/reference lifecycle and dormant-mode activation approval.

**Gate M0:** reviewed schema/profile/wire examples and threat matrix; no client requires an upstream issuer. Both client profiles, browser binding, audience authority, admin writes, scope omission, binding overlap and replay behavior have fixed expected results.

### Endpoint matrix

| Method / transport | Endpoint | Caller / role | Required behavior |
| --- | --- | --- | --- |
| GET | App `/_skyoauth/login` | Browser on registered origin | Resolve tenant/provider from ApplicationOrigin; create browser-bound transaction and validated return |
| GET | App `/_skyoauth/callback` | Upstream via initiating browser | Require app flow cookie plus state/nonce/PKCE/provider/epoch/origin; one-time consume |
| GET | App `/_skyoauth/session` | Browser | Safe session/principal + CSRF only; no-store |
| POST | App `/_skyoauth/logout` | Browser | Origin/CSRF, revoke session/context, expire cookie |
| GET | Issuer `/.well-known/oauth-authorization-server` | OAuth clients | Stable metadata; advertise implemented grants/profiles only |
| GET | Issuer `/.well-known/jwks.json` | Verifiers | Public signer overlap, M2 |
| GET | Issuer `/oauth/authorize` | Native public client via browser | Resolve registered client/tenant, validate redirect/PKCE/audience/scopes; set issuer-native flow cookie |
| GET | Issuer `/oauth/callback` | Upstream via initiating native-flow browser | Require native flow cookie + state/transcript; bind verified human and rotate cookie before confirmation |
| GET / POST | Issuer `/oauth/confirm` | Browser with completed native transaction and rotated issuer cookie | Explicit approve/deny, exact Origin/CSRF/anti-framing; transaction ID or app cookie alone insufficient |
| POST | Issuer `/oauth/token` | CLI/WIF | Supported grants/proof roles, registered audience assignment, profile-specific credentials |
| POST | Issuer `/oauth/revoke` | CLI if refresh supported | Revoke local credential/family per profile |
| gRPC | `envoy.service.auth.v3.Authorization/Check` | Private authenticated Envoy | M2 bearer; M3 session/CSRF and internal assertion; fail closed |
| GET | Private `/internal/auth/check` | Trusted ForwardAuth | Optional equivalent typed decision adapter, never public |
| POST | Private `/internal/v1/policy/check` | Registered resource-server checker | Exact audience/tenant/action/profile/resource checks, independent of token subject |
| POST | App `/_skyoauth/oidc/backchannel-logout` | Configured upstream IdP | Optional signed logout/replay verification and indexed session targeting |
| GET / POST / PATCH | `/admin/v1/tenants` | Instance security_admin | Create/disable tenants, generated IDs, no implicit role inheritance |
| GET / POST / PATCH | `/admin/v1/resource-servers` | Instance security_admin | Globally unique exact audience and allowed profile/scope/schema registry |
| GET / POST / PATCH | `/admin/v1/resource-servers/{id}/tenant-assignments`, `/checker-identities`, `/actions` | Instance security_admin | Assign tenants/ceilings; register receiver mTLS identities and action rules, never token-subject credentials |
| POST / PATCH | `/admin/v1/application-origin-registrations` | Instance security_admin | Enroll canonical HTTPS origin and tenant ownership; validate ingress/callback mapping, reject collisions |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/principals`, `/services` | Tenant trust_admin | Workload/service principal creation only; service and svc principal atomic; no human/operator escalation |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/trust-sources`, `/keysets`, `/bindings`, `/grants` | Tenant trust_admin | Same-tenant IDs, registered audience ceilings, typed verifiers, disable/revisions and explicit widening approval |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/oauth-clients`, `/human-access-policies` | Tenant client_admin | Registered native clients/generated client IDs and bounded human issuance policy |
| GET / PATCH | `/admin/v1/tenants/{tenant}/application-origins/{id}` | Tenant client_admin | Configure assigned-origin return paths/audience references; cannot change canonical origin/tenant |
| GET / POST / PATCH | `/admin/v1/tenants/{tenant}/human-providers`, `/human-links` | Tenant provider_admin | Inactive provider configuration/testing and controlled verified human enrollment/linking; active-state writes rejected |
| GET | `/admin/v1/tenants/{tenant}/login-state` | Authorized scoped operator | Read-only active provider/generation/revision |
| POST | `/admin/v1/tenants/{tenant}/human-provider-switches` and `/{plan}/commit`, `/{plan}/rollback` | Tenant provider_admin | Exclusive plan/dry-run/commit transition, including initial activation; epoch invalidation and expected revisions |
| POST | `/admin/v1/tenants/{tenant}/imports` | Every role required by all included sections | Whole-plan role validation; reject unauthorized sections/active-pointer mutation, no partial apply |
| POST | `/admin/v1/grant-activation-approvals` | Instance security_admin | Conditional high-risk approval bound to exact grant/capability revision, separate from scoped activator |
| POST | `/admin/v1/tenants/{tenant}/grants/{id}/activate` | Tenant trust_admin | Supported mode, valid separate approval where required; generic PATCH cannot activate dormant impersonation |
| GET / POST / PATCH | `/admin/v1/operators`, `/operator-roles` | Instance security_admin | Independent operator enrollment/disable and explicit scoped roles |
| GET | `/admin/v1/tenants/{tenant}/audit` | Tenant auditor | Redacted scoped audit; instance events separately authorized |
| Local command / Unix socket | Service operator/bootstrap/recovery subcommands | Deployment operator + independent proof | M1; no public enrollment/recovery; durable challenge/audit; no native M4 dependency |

Grouped sibling paths share the full prefix preceding them. Private listeners are never public gateway routes. All writes use validation, optimistic revision checks and audit. Device endpoints are added only if the explicitly reviewed profile ships. Native upstream callbacks are not app callbacks or loopback callbacks: the browser returns upstream -> issuer, confirms there, then receives a SkyOAuth code at its CLI loopback.

### Exchange selection and scope

Require one generated source ID, generated grant ID and exact registered audience. Load source/grant only as candidates; require same tenant, then verify the proof at that source. Filter matching bindings by **the selected grant's actor and nonempty allowed_binding_ids**. At least one eligible enabled binding must match. Bindings for other actors do not cause ambiguity or confer access. Bindings are identity-only in v0.1; multiple eligible matches choose a stable ID for provenance, never union permissions. Configuration rejects cross-actor/cross-tenant binding references.

Direct RFC exchange accepts subject_token/type=jwt and a direct grant, returns workload sub, rejects actor_token. The private service-delegation grant accepts actor_token/type=jwt and a delegated grant, returns configured service sub plus workload act, rejects subject_token. No requested subject/target/mode override or dynamic verifier selection.

Omitted scope uses only explicit nonempty allowed default_scopes; otherwise invalid_scope. Explicit empty/excessive scopes, unsupported resource/requested token types, duplicates or profile mismatch deny. Return access_token, Bearer token_type, expires_in, explicit scope and issued_token_type=access_token, no-store, never WIF refresh. The design's exported example uses **post-create generated IDs**, not operator-chosen global identifiers.

## 3. Data model and persistence (M1)

Define the complete logical schema before later handlers. Stable authority survives provider changes; affected human flow/auth state is invalidated. Instance-owned registration and tenant-owned configuration are distinct; redacted exports and encrypted database backups are different artifacts.

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
               live_check_required, status, revision)
ApplicationOrigin(id, tenant_id, canonical_origin, callback_uri,
                  allowed_return_paths, resource_server_ids, status, revision)
OAuthClient(id, tenant_id, client_id, name, display_name, redirect_rules,
            resource_server_ids, allowed_scopes, status, revision)
HumanAccessPolicy(id, tenant_id, resource_server_id, oauth_client_id?,
                  application_origin_id?, allowed_scopes, max_ttl,
                  required_authentication, status, revision)
HumanProvider(id, tenant_id, name, issuer, metadata, app_callback_config,
              native_callback_uri, auth_epoch, status, revision)
TenantLoginState(tenant_id, active_provider_id?, auth_generation, revision)
HumanSubjectLink(tenant_id, provider_id, issuer, upstream_sub, principal_id,
                 verified_by, verification_operation_id)
BrowserFlowBinding(id_hash, tenant_id, flow_kind, canonical_origin,
                   application_origin_id?, created_at, expires_at, consumed_at?)
HumanAuthentication(id, tenant_id, principal_id, provider_id,
                    provider_auth_epoch, tenant_auth_generation,
                    auth_time, verified_auth_context, expires_at, revoked_at?)
Session(id_hash, internal_ref, tenant_id, application_origin_id, principal_id,
        human_authentication_id, provider_id, upstream_sub, upstream_sid?,
        created_at, last_seen_at, idle_timeout_seconds, idle_expires_at,
        absolute_expires_at, revoked_at?, csrf_verifier)
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
CLIRefreshCredential(token_hash, tenant_id, family_id, parent_id?, oauth_client_id,
                     principal_id, human_authentication_id, resource_server_id,
                     scopes, issued_at, expires_at, consumed_at?, revoked_at?)
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
             status, activation_state, activation_approval_id?, revision)
GrantActivationApproval(id, tenant_id, grant_id, grant_revision,
                        capability_revision, approved_by, expires_at,
                        consumed_at?, audit_id)
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
AuditEvent(id, tenant_id?, timestamp, actor, action, object_id,
           previous_revision, new_revision, outcome)
~~~

**Ownership:** ResourceServer/audience namespace, ResourceServerChecker/Action and origin ownership enrollment are instance authority; AudienceTenantAssignment grants named tenants bounded issuance rights. Composite same-tenant references protect all tenant-owned objects. ServiceIdentity.id references a svc principal and contains no checker credentials. Direct grants require null target; delegated grants require a same-tenant service. ApplicationOrigin has globally unique canonical origin, assigned rather than claimed by tenant admins. OAuth client_id is globally unique and generated, so issuer-native authorization deterministically resolves its tenant. HumanAccessPolicy has exactly one client/origin consumer and one registered audience, unique per consumer/audience.

**IDs/names:** server-generated opaque IDs, including client_id, are immutable selectors; names are tenant-local labels, not exchange identifiers. Initial create omits ID and returns it. GitOps may use tenant-local typed manifest references, resolved by an authorized plan that returns a persistent ID mapping. Updates require ID/tenant/revision; ordinary tenant imports cannot claim missing global IDs. Privileged restore preserves IDs only into the intended restored authority with ownership/provenance validation. Two tenants' identically named sources/clients/grants coexist without global-name probing.

**Verifier union:** discovery requires approved metadata; upload requires same-tenant keyset; TokenReview requires cluster/endpoint/CA/reviewer/audience/timeout and reusable replay. Reject contradictory fields and unsupported evidence requirements. Keyset versions reference a stable parent; overlapping keys have explicit validity and no conflicting live kid/key pair. Single-use additionally requires locally verified on-demand JWT evidence and fresh-assertion capability; reject it for projected-service-account profiles even with local verification.

**Policy revisions:** dependency_revisions is a typed immutable set of entity-kind/ID/revision references. WIF snapshots tenant/resource registration/assignment, chosen source/binding, grant and optional target service. Human snapshots tenant/resource assignment, HumanAccessPolicy and client/origin registration. Current action rules are evaluated at live check. Human authentication/provider epochs and session validity are separately checked live; no fake WIF grant for a human. Missing/contradictory dependency/profile fields deny.

**One-time state:** store keyed hashes of flow cookies/session tickets/codes/refresh tokens, not secrets. Distinct app/native browser bindings include exact origin and flow kind. Indexed session provider/subject/sid supports verified logout. HumanAuthentication links pending native codes/refresh and sessions to monotonic provider/tenant epochs. Replay key uniqueness spans grants/replicas through exp plus skew and digest-key rotation. Restore must preserve consumed state or quarantine issuance until outstanding lifetimes expire; config import does not restore consumption.

**Provider pointer:** only TenantLoginState is authoritative; HumanProvider has no writable active flag. A restricted provider-transition command is the sole pointer/epoch writer. Generic CRUD/import rejects active-pointer or active-authentication-semantics changes. Initial activation uses the same command from null. M1 implements this primitive; M5 adds full migration tooling/exercises, avoiding a dependency from M3 initial login on unfinished M5 work.

### T10 — Schema and migration safety

- [ ] **T10.1** Implement migrations/indexes, generated IDs, typed unions, composite tenant references, soft disable and immutable revisions. No cascading provider deletion into WIF/audience/client/operator objects; one TenantLoginState per tenant.
- [ ] **T10.2** Implement server-generated opaque create IDs/client_id and tenant-local name uniqueness; create responses return IDs/revisions, and exports retain them. No user-chosen global ID on normal create.
- [ ] **T10.3** Hash browser-flow/session/code/refresh secrets; protect CSRF/PKCE and normalize expiry/revocation. Do not store raw replay assertions or expose cookie hashes as backend session references.
- [ ] **T10.4** Complete immutable typed policy dependencies and atomic audit/optimistic concurrency; no mutable reinterpretation of issued credentials.
- [ ] **T10.5** Redacted versioned export/import includes every source kind, keysets, audience/actions/checker public metadata, clients/origins/human policy, grants/activation state and operator public metadata. Semantic diff/preconditions/approval; exclude secret/live credential material.
- [ ] **T10.6** Separate encrypted DB/key disaster recovery; preserve bootstrap-closed and one-time/replay state or quarantine. Rollback never revives credentials or resets monotonic generations.
- [ ] **T10.7** GitOps precedence and full-plan role checks; no wiping omitted objects or partially applying unauthorized sections. Active-provider state is observation-only and proposed mutation rejects.
- [ ] **T10.8** Property tests for same-name tenants/sources, same-issuer clusters, cross-tenant object/audience/origin references, deterministic generated-ID resolution, grant-bound matching and privilege ceilings.
- [ ] **T10.9** M1 durable OAuth client/request/code, browser-flow, HumanAuthentication, optional refresh-family and replay tables; atomic consumption across replicas before later handlers ship.
- [ ] **T10.10** Session idle/absolute and authentication epoch relationships; coalesced writes cannot revive/extend expired sessions. Index verified provider/subject/sid logout and switch invalidation.
- [ ] **T10.11** Persist dormant impersonation only disabled/reapproval-required through public operator API; approval/activation history is durable, capability upgrades do not change status.

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
- [ ] **T12.5** Required direct/delegation and conditional impersonation remain distinct; no unsupported-mode fallback. Apply §5.6 design dormant write/activation lifecycle.
- [ ] **T12.6** Snapshot full WIF or human policy dependencies; include resource-server assignment and client/origin policy as appropriate. Live checks deny invalidated/superseded revisions without broadening old credentials.
- [ ] **T12.7** Deny wrong owner/repo/subject/event/workflow, no eligible binding, wrong actor/tenant/audience assignment, disabled records and escalation. A matching binding for another actor is ignored, not an ambiguity denial; configuration with cross-actor allowed binding references rejects.
- [ ] **T12.8** Scope omission uses explicit nonempty defaults only. Validate defaults/requests against all ceilings; direct grants have no service target, profile/mode mismatch denies.
- [ ] **T12.9** WIF allowlists and explicit human backend_rbac schema, action/profile mapping and canonical tenant requirements have verifier fixtures; missing required/unknown fields fail closed by profile.
- [ ] **T12.10** Accept unsupported impersonation create/import only disabled with requires_reapproval; reject enabled input. Supported activation needs separate security-admin approval bound to revision/capability and a distinct scoped activator. Generic PATCH/import/upgrade cannot activate; edits invalidate approval.

### T13 — Independent operator authority, provisioning and recovery

- [ ] **T13.1** Independent adm identities, registered mTLS public keys and active local credential/role check on every request; no OIDC/session/WIF/email promotion.
- [ ] **T13.2** Implement explicit instance security_admin and tenant trust_admin/client_admin/provider_admin/auditor roles. No inheritance; all reads/writes/imports enforce resource scope and per-field authority.
- [ ] **T13.3** Private operator API and **M1 service operator subcommands** for configuration/bootstrap/recovery, revisions, diff/dry-run and audit. Native application CLI is M4 and not a dependency.
- [ ] **T13.4** Atomic one-time local bootstrap enrolls security_admin public credential and separate offline recovery key, audits and durably closes enrollment; restart/config omission cannot reopen it.
- [ ] **T13.5** Local recovery verifies expiring one-time operation/arguments/revision challenge, allows bounded operator restoration or the guarded provider transition, never arbitrary WIF/audience edits or token minting. Consume, audit/alert and rotate recovery key after use.
- [ ] **T13.6** Deny forged upstream roles, compromised-IdP sessions, scope crossover, revoked keys, replayed recovery, concurrent bootstrap and missing store/audit.
- [ ] **T13.7** Rehearse operator restoration without human IdP; hardware/offline custody and independent database/signer recovery limitations documented.
- [ ] **T13.8** Complete provisioning chain: security_admin creates tenant/audience assignment/origin ownership and explicit scoped roles; trust_admin creates workload/service principals; client_admin creates OAuth clients/human policies; provider_admin performs controlled human enrollment/links. Test from an empty installation without SQL edits.
- [ ] **T13.9** Implement the exclusive provider-transition primitive in M1: plan/dry-run/commit with expected login/config revisions, initial null activation, switch/disable/rollback, atomic epoch advance and audit. Generic PATCH/import/reload, active-provider delete/disable and auth-critical issuer/client/callback changes outside this primitive reject. T51 builds full migration orchestration on it.

### T14 — Resource servers, audience assignments and application registrations

- [ ] **T14.1** Instance-owned globally unique exact audience registry and explicit tenant/profile/scope/schema assignments; scoped tenant admins cannot self-assign or shadow another audience.
- [ ] **T14.2** Refuse service/grant/client/origin/human-policy references outside active same-tenant assignment at write and issuance; recheck on live authorization. Backends map canonical resource ownership to signed SkyOAuth tenant and deny absent/mismatched mappings.
- [ ] **T14.3** Register resource-server mTLS checker identities with explicit audience/tenant scope independently of ServiceIdentity/token subjects. Direct grants with null target work; a delegated service principal cannot become a checker by allowed_audiences alone.
- [ ] **T14.4** Persist action registry: required scopes, accepted credential profiles, canonical resource dimensions and live-check requirement. Unknown action denies; tenant grant editors cannot weaken action rules.
- [ ] **T14.5** Enroll globally unique canonical ApplicationOrigin under instance ownership; client_admin may configure permitted return paths/audiences without reassigning origin/tenant. Pin callbacks, trusted ingress authority and exact normalized return-path rules.
- [ ] **T14.6** HumanAccessPolicy for exactly one registered OAuth client or application origin per audience; scope/TTL/authentication ceilings bounded by assignment, provider-independent and stable through migration.
- [ ] **T14.7** Deterministic issuer-native client_id -> tenant and app authority -> origin/tenant routing; deny unknown/spoofed/ambiguous authority before redirects. Do not use free tenant query/forwarded header to select a provider.
- [ ] **T14.8** Document create-then-reference and authorized import manifest references, return/generated ID mapping and same-instance reconciliation. Test identical labels in different tenants, unauthorized IDs and restore provenance; public exchange accepts generated IDs only.

**Gate M1:** complete authorized provisioning from bootstrap through tenant/audience/client/origin/principal/trust/grant creation and initial provider activation, without M4 or manual DB insertion. Typed schemas, scoped writes, protected restore, policy ownership and one-time-state invariants pass. Human-provider operations cannot mutate WIF/audience/client/operator authority. Signer/JWKS remains M2.

## 4. WIF, issuer and bearer gateway (M2)

### T20 — JWT issuer and profile verification

- [ ] **T20.1** Stable issuer/JWKS and explicit private token-profile metadata; no upstream-issued pretense or implicit RFC 9068 claim.
- [ ] **T20.2** Asymmetric protected signer/kid/overlap, bounded iat/nbf/exp, unique jti and exact private access/internal types. M2 issues WIF access; human issuers arrive with M3/M4.
- [ ] **T20.3** WIF requires signed tenant, profile/version/mode, grant, complete effective policy revision and allowlist constraints; delegation requires act. Standard core claims and profile selection are shared, not subject-prefix heuristics.
- [ ] **T20.4** Verifier fixtures for issuer/audience/assignment/type/signature/time/key/profile errors, unknown schemas, missing WIF allowlists, contradictory human/WIF claims and canonical resource tenant mismatch.
- [ ] **T20.5** WIF receives no refresh credential; provider renewal gets fresh on-demand assertion or reuses a valid projected token according to source capabilities.
- [ ] **T20.6** Audit source/binding/grant/revision/run/audience decisions with safe metrics, never JWT/key bytes.
- [ ] **T20.7** Document offline residual TTL, bounded internal assertion lifetime, TokenReview propagation and critical live checks; no promise of undoing in-flight work.
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
- [ ] **T26.2** Request has exactly one access credential or internal assertion plus canonical action and resource coordinates; bounded metadata, no bodies/token logs, no caller-supplied replacement grant/profile.
- [ ] **T26.3** Validate full profile/current typed policy dependencies and registered action required scopes/profiles/dimensions. WIF checks chosen binding/grant/source/optional service; direct null service valid. Human branches later check HumanAccessPolicy/client-or-origin/authentication/session/provider epochs. Superseded revision denies.
- [ ] **T26.4** Return exact-request allow/deny/revision/decision ID, no-store; no reusable capability or positive cache for critical calls. Backend still checks canonical ownership and RBAC.
- [ ] **T26.5** Deny checks started after committed revocation, unknown actions/callers/resources, wrong audience/tenant, changed assignment/revision and store outage. Test direct and delegated access through the same registered receiver identity.
- [ ] **T26.6** Backend integration for destructive calls and bounded streams; race boundary documented. M2 delivers WIF; M3/T32.11 adds human-session and M4/T40.13 human-CLI checks before those profiles ship.

**Gate M2:** actual GitHub/k3s calls pass through Envoy to registered APIs without human IdP/static application secrets. Signer/JWKS, both exchange profiles, independently consumable Rust WIF crate, signed WIF constraints, audience assignments and receiver-authorized action checks work. Fixed replay tests include reusable projected-token renewal and atomic on-demand single-use. Dependencies are M0–M2, not M3/M4.

## 5. Human OIDC, sessions and TypeScript SPA (M3)

### T30 — Upstream human login and browser binding

- [ ] **T30.1** Standards-based Zitadel adapter with fixed registered app/native callbacks, expected issuer/client configuration and complete ID-token verification; capabilities explicit.
- [ ] **T30.2** Resolve app tenant/provider from registered canonical origin; create app flow cookie and BrowserFlowBinding, state/nonce/S256 transaction with exact origin/callback/provider/epoch/validated return. State alone is insufficient.
- [ ] **T30.3** SSRF-safe discovery, bounded timeouts/no token logging, provider outage fails closed. Ingress authority/forwarded metadata must come from trusted route/transport.
- [ ] **T30.4** Verified subject -> stable human principal/HumanAuthentication, controlled enrollment/explicit linking; no email-only link or operator promotion. Link requests also bind initiating browser and require appropriate current/fresh identity proof.
- [ ] **T30.5** Optional encrypted provider-token vault only behind explicit feature; default discard upstream tokens.
- [ ] **T30.6** Optional back-channel logout verifies issuer/audience/signature/events/time/replay then indexes provider/subject/sid; no arbitrary claim/context lookup.
- [ ] **T30.7** Restore explicit login-CSRF/callback-injection/mix-up/redirect-confusion/linking tests: attacker callback loaded in victim browser, missing/wrong cookie, other origin/tenant/provider/flow kind, tampered return path and stale concurrent tab all deny without replacing victim session. Baseline top-level GET/query callback; alternative response mode needs reviewed cookie policy.

### T31 — Opaque sessions and human authentication context

- [ ] **T31.1** Fresh CSPRNG session ticket/keyed hash, app-origin/tenant binding, human auth reference, provider/subject/sid indexes and CSRF; secure host-only cookie, no JS OAuth tokens.
- [ ] **T31.2** Both idle/absolute deadlines and current human auth/provider/tenant generation required. Conservative coalesced last-seen never revives or extends absolute lifetime; document possible bounded early idle expiry.
- [ ] **T31.3** No-store safe session/principal/CSRF response, no upstream credentials/admin roles/internal assertion.
- [ ] **T31.4** Exact Origin/CSRF on unsafe calls including Connect POST; no bearer+cookie ambiguity.
- [ ] **T31.5** Fixation/login callback replay/cookie confusion/CSRF, independent expiry, concurrent updates, revocation/switch/store outage and session-origin crossover tests.
- [ ] **T31.6** Local versus upstream logout distinguished; human auth context/session revocation and verified sid selection are explicit.
- [ ] **T31.7** Session consumers use approved ApplicationOrigin/HumanAccessPolicy/audience mapping, not browser scope/tenant headers; missing canonical backend tenant/RBAC membership denies.

### T32 — Browser gateway and explicit human-session profile

- [ ] **T32.1** Extend existing T25 with session support, not defer bearer implementation. Live validate session/auth context/provider epoch/origin before minting internal evidence.
- [ ] **T32.2** Emit private signed `skyoauth-internal+jwt` + human_session/version profile, human sub, signed tenant/audience/scope/policy revision, explicit backend_rbac constraints, auth_time, opaque origin/authentication/session refs and method/authority/path-query binding. No WIF grant, invented client_id or subject-prefix exemption; TTL <=30s and session deadline.
- [ ] **T32.3** Route app login/callback/session and protected browser RPC/events/downloads with registered-origin enforcement; no sensitive-route bypass.
- [ ] **T32.4** Strip client assertion/identity headers; backend accepts internal assertion only from authenticated gateway on bound request, never public bearer. Re-run header-spoof/direct-backend/profile-substitution tests.
- [ ] **T32.5** Validate profile-specific claim schemas and backend canonical tenant/RBAC, preserving bearer behavior. Any future gateway JWT optimization must preserve all profile/assignment/revocation controls.
- [ ] **T32.6** Structured 401/403, no HTML redirects for RPC; TypeScript initiates explicit top-level login.
- [ ] **T32.7** Unary/server streams/SSE/large downloads go Envoy -> backend; cancellation/reconnect/idle/body-nonbuffering tests.
- [ ] **T32.8** Resource authorization per workflow/artifact; bounded stream duration/rechecks/cancellation and critical operation policy checks.
- [ ] **T32.9** Optional private ForwardAuth preserves typed evidence, trusted forwarded chain and decision semantics, never plain public-client identity headers.
- [ ] **T32.10** Cloudflare Tunnel versus Access/WAF/rate limits documented separately.
- [ ] **T32.11** Extend T26 for human_session: check HumanAccessPolicy, origin, current HumanAuthentication/session/epochs and action registry, with canonical resource tenant and backend RBAC still mandatory. Token has no WIF grant and is not rejected merely for that absence.

### T33 — Required TypeScript SPA library

- [ ] **T33.1** Evolve clients/typescript / @skyoauth/client: framework-neutral session/principal, login/logout/CSRF, bounded memory/cancellation, no token getter/persistent credential storage. Unauthenticated health helper remains separate.
- [ ] **T33.2** /react entry point has explicit loading/authenticated/unauthenticated/unavailable states; React optional peer excluded from core.
- [ ] **T33.3** /connect entry point handles CSRF, gateway versus Connect auth/stream errors and cancellation; optional peers excluded from core, no mutation auto-replay.
- [ ] **T33.4** Runtime/declaration exports and versioned wire/errors align, no upstream-specific imports/config, no Node built-ins/polyfills in browser core; tested browser support documented.
- [ ] **T33.5** Real-browser E2E login/logout/reload/expiry/cross-tab invalidation, CSRF, ConnectRPC/cancel/unavailable states and browser-bound callback attacks; Node mocks alone insufficient.
- [ ] **T33.6** Same-origin HTTPS/no-userinfo targets, Fetch same-origin mode/credentials, API redirect rejection; forbid caller overrides or bearer mixing. Explicit top-level login follows OIDC; loopback development mode narrowly scoped.
- [ ] **T33.7** Negative off-origin health/auth reuse, Request/options/redirect/downgrade manipulation, CSRF leakage, logout/account cache and credential-free cross-tab signals. Injected fetch is trusted code, not exemption from URL/header checks.
- [ ] **T33.8** Pack npm artifact and install in independent examples/spa; verify declarations/exports/browser bundle without Node/React/Connect in core, adapter peers separately. Add CI package/browser checks when code lands.

**Gate M3:** the packed TypeScript library works in a real SPA with opaque cookie/CSRF only; registered origin resolves tenant/provider, login-CSRF defenses hold, explicit human_session profile passes correct backend/live checks without WIF exemptions. No Node/framework dependencies in core, no payload proxying and no bearer regression.

## 6. Native OAuth and reusable Rust CLI library (M4)

### T40 — Native server flow and client crate

- [ ] **T40.1** Stable metadata/endpoints and registered generated OAuth client IDs; client_admin provisioning and instance audience assignment precede auth. Exact IP-loopback redirect rules and supported grants.
- [ ] **T40.2** Fresh SkyOAuth confirmation for each transaction showing client/account/audience/scopes/loopback and public-client identity caveat; SSO/prior consent cannot auto-approve.
- [ ] **T40.3** Bind approval/code to client, redirect, S256 challenge, audience/scopes, verified human authentication, browser flow and epoch. Exact-Origin/CSRF/anti-framing POST, one-time cross-replica code use, native state validation; denial/expiry yields no code.
- [ ] **T40.4** Only scoped SkyOAuth credentials to CLI; no upstream tokens. Malicious local process with its own PKCE/loopback cannot silently receive a code via existing SSO.
- [ ] **T40.5** Interactive-only or explicitly included rotating hashed refresh families in OS keychain, auth epoch/reuse detection/revocation; never call persistent refresh secretless or silently fall back to plaintext files.
- [ ] **T40.6** Device flow conditional: user-code verification/explicit approval pages, expiry/polling/abuse tests, no interaction bypass.
- [ ] **T40.7** Reusable clients/rust native API, thin cli/ reference and independent examples/rust-cli package consumer. Protocol logic in crate, terminal UX in executable; no server/DB/frontend dependency.
- [ ] **T40.8** Silent SSO, altered confirmation, denial/expiry/concurrent code redemption, stale-provider requests/codes/refresh and browser-cookie transplantation tests.
- [ ] **T40.9** External system browser, ephemeral IP-loopback-only listener, bounded callback path/state/lifetime and exact chosen redirect at redemption. Invalid callback/cancel/timeout cleanup; no login webview/password/secret fallback.
- [ ] **T40.10** Publish/test MSRV/TLS/runtime/features and Linux/macOS/Windows support, minimal/default builds and optional keychain/GitHub/K8s adapters separately, not all-features alone.
- [ ] **T40.11** Redacted credentials/errors, memory cache, explicitly scoped HTTPS origin/audience transport; no cross-origin forwarding or automatic mutation replay. Package and compile independent consumer without private workspace paths.
- [ ] **T40.12** Implement issuer /oauth/callback and __Host-skyoauth_native cookie distinct from app flow. Authorize creates browser-bound request; callback verifies full transcript/cookie/epoch, records human and rotates cookie; confirm requires rotated binding plus CSRF. App cookie/transaction ID alone never authenticates confirmation. Expire/consume on completion, denial or new conflicting flow.
- [ ] **T40.13** Issue `skyoauth-access+jwt` / human_cli with actual client_id, human sub, tenant/audience/scope, auth_time, opaque authentication ref, HumanAccessPolicy revision and explicit backend_rbac constraints. No WIF grant/act. Extend T26 with human auth/epoch/client/policy checks and profile-specific backend fixtures before shipping.

### T41 — Upstream adapter/exchange

- [ ] **T41.1** Human-login/optional-provider-exchange trait with explicit deployed capability checks, independent of operator authority.
- [ ] **T41.2** Authorized compatible Zitadel-issued exchange stays server-side, respecting real subject/actor semantics and normalizing downstream credential/profile.
- [ ] **T41.3** Do not assume arbitrary GitHub/K8s exchange or administrative audiences; local WIF required independently.
- [ ] **T41.4** Never return upstream admin token through generalized delegation; separate restricted adapter if needed.
- [ ] **T41.5** Replacement-provider tests preserve TypeScript/Rust contracts, metadata/profile/constraints/gateway transport and registered clients/origins.

**Gate M4:** an independent CLI uses the packaged Rust crate and issuer-local browser-confirmed OAuth flow. Human_cli is explicitly verifiable without WIF claims; native feature/platform/transport tests pass. Provider migration requires reauth only. A working repository-local executable alone does not satisfy the gate.

## 7. Operational safety, deployment and migration (M5)

### T50 — Packaging and readiness

- [ ] **T50.1** Chart public/private gateway-policy/operator listeners, non-root/read-only context, service accounts, probes/resources/NetworkPolicies/disruption settings.
- [ ] **T50.2** PostgreSQL migrations/backup/restore, multi-replica atomic state and quarantine/rollback instructions.
- [ ] **T50.3** Isolate signer/reviewer/operator/recovery/upstream-admin credentials; independent recovery/rotation boundaries.
- [ ] **T50.4** Route smoke tests reject newly exposed sensitive routes, spoofed origin and public internal/operator endpoints.
- [ ] **T50.5** Bound requests/token/claim sizes and cache churn; rate-limit exchange/login/native confirmation/discovery/admin with no privilege-expanding fallback.
- [ ] **T50.6** Safe latency/denial/audit metrics, no PII/token labels or secret-bearing logs.
- [ ] **T50.7** SBOM/dependency/provenance review, vulnerability disclosure/patch/release docs for service and both clients.
- [ ] **T50.8** Audit bootstrap-preserving CI: fmt/lint/type/test/coverage, docs-only detection, all new workspace/package paths and packed consumers/browser/native jobs. Checks land with T21/T33/T40 implementations; M5 verifies coverage, not invents it late. README/manifests/lockfiles stay synchronized; skip != execution.

### T51 — Exclusive provider migration without resets

- [ ] **T51.1** Build full migration operator tooling/runbook on **T13.9's M1 sole transition primitive**. Immutable plan/dry-run/commit/rollback, expected login/config revisions and audited provider-only write boundary; no new alternate pointer writer.
- [ ] **T51.2** Snapshot stable tenants/principals/audience registrations/assignments/actions/checker public metadata, origins/clients/human policies, all source/cluster/CA/reviewer/keyset configs, bindings/grants/defaults/activation state and issuer/operator metadata. Record replay preservation without exposing proof secrets. Enumerate human flow/auth/session/code/refresh state for invalidation, not equality.
- [ ] **T51.3** Test inactive replacement and verified links; plan rejects WIF/audience/client/origin/operator/gateway/signer mutation. Independent operator access requires no upstream-admin linking. Concurrent relevant configuration changes require replan.
- [ ] **T51.4** Atomically change only human login/mapping state and advance monotonic generations/epochs. Invalidate affected app/native flow bindings, HumanAuthentication/sessions, pending requests/codes and optional refresh families. Preserve WIF consumption and registration; document residual offline human JWT TTL and immediate live-check denial.
- [ ] **T51.5** Reuse prebuilt TypeScript SPA and independent Rust CLI with recorded artifact hashes after reauth; no SDK upgrade/rebuild/env/callback/client registration/deployment change.
- [ ] **T51.6** Existing GitHub, uploaded-key workload and two independently keyed shared-issuer K8s clusters work with unchanged workflow/source/CA/reviewer/grant/audience config. Direct/delegated and human profiles remain correct; active impersonation only if included, dormant records always unchanged.
- [ ] **T51.7** Compare pre/post allowed/denied policy fixtures and revisions. Single-use uses fresh proofs and consumed ones remain denied; projected Kubernetes proves reusable renewal. Both library wire/error fixtures stay compatible.
- [ ] **T51.8** Rollback through the same primitive with fresh epochs, never whole-DB restore over independent WIF/audience changes or resurrection of consumed human/proof state.
- [ ] **T51.9** Schema upgrade/restore preserves full stable/one-time models and dormant-mode activation guard; ordinary config import never substitutes for authoritative replay restore.
- [ ] **T51.10** No client/gateway/backend redeploy or issuer/certificate rotation solely for a human provider change.
- [ ] **T51.11** Switch/rollback with IdP unavailable/unlinked admin using independent credentials and separately exercised audited recovery. Forged upstream admin roles cannot edit policy/registrations; generic PATCH/import/reload pointer attempts deny without partial effects.

### T52 — Security conformance

- [ ] **T52.1** Malformed JWT/header/claim/key corpus, profile/type substitution, issuer/algorithm confusion, key URLs/private upload and rollover.
- [ ] **T52.2** WIF owner/repo/event/ref/env/workflow/cluster/tenant/audience/actor/binding/grant/scope/resource negatives and fixed capability/replay outcomes.
- [ ] **T52.3** **Login CSRF, OIDC callback abuse, redirect URI confusion, identity-linking confusion**, mix-up/state/nonce/PKCE/code replay, app/native flow-cookie crossover, silent SSO/confirmation attack, fixation and epoch rollback tests. Victim browser cannot acquire attacker's session by loading an attacker-initiated callback.
- [ ] **T52.4** Header/assertion spoofing, direct backend/private listener, fail-closed auth, oversized headers and proxy normalization/smuggling/origin routing.
- [ ] **T52.5** Signer/operator/recovery compromise drills, retired key overlap, suspicious issuance, audit integrity/redaction and exclusive provider-write authorization.
- [ ] **T52.6** Backend canonical tenant/resource isolation, human RBAC versus WIF allowlists, destructive workflows/artifacts/streams and implemented profile-specific T26 checks versus offline TTL.
- [ ] **T52.7** Fuzz token/policy/metadata/confirmation/import parsers; k3s/Envoy load tests with concurrent login/code/proof consumption and revision changes.
- [ ] **T52.8** Independent security review including complete provisioning, audience/checker/action boundary, browser/native transports, dormant activation and honest RFC-versus-private profile claims.

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
| A12 | Stream/download | Direct Envoy -> backend bytes, bounded auth lifetime/recheck |
| A13 | Valid credential outside canonical resource tenant or WIF allowlist/human RBAC | Backend denies; names alone do not identify tenant ownership |
| A14 | Provider change with existing TypeScript SPA and independent Rust CLI | Same artifact hashes/endpoints/config, human reauth only |
| A15 | Migration with discovery/uploaded keys/two shared-issuer TokenReview clusters | Stable configs/CA/reviewer/keyset IDs and effective decisions |
| A16 | Migration with direct/delegation bindings/grants and dormant impersonation | IDs/modes/defaults/constraints/revisions preserved; dormant remains disabled. Active impersonation subcases conditional on supported mode. |
| A17 | Rollback after independent policy/audience change | Those changes untouched; fresh human epochs, no resurrected state |
| A18 | Spoofed identity/assertion headers | Removed/overwritten, no profile substitution or lost constraints |
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
| A31 | Wrong checker/audience/tenant/action, superseded revision or checker outage | Denied, no positive cache or RBAC replacement |
| A32 | Concurrent/reopened bootstrap, forged IdP admin, revoked operator/replayed recovery | One enrollment only, no elevation/replay, audited independent restoration |
| A33 | Idle/absolute/session-origin and provider/sid targeting | Either expiry denies; no revival/absolute extension; only correctly selected sessions revoked |
| A34 | Concurrent native code/optional refresh reuse and human switch/rollback | One-time across replicas; affected human state invalid, registrations unchanged |
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
| A48 | Empty installation -> tenant/audience/origin/client/principal/source/grant and initial provider via M1 operator tools | Complete independently authorized path without SQL edits or M4 native CLI; missing roles deny |
| A49 | Identical operator labels in two tenants and create/export/reapply | Distinct generated IDs, deterministic authorized mapping, no global-name collision/probe; exchange names instead of IDs reject |
| A50 | Repo-wide and deployment binding map different actors; selected grant owns one | Matching eligible binding for grant actor succeeds; other actor overlap irrelevant. No eligible match denies; multiple same-actor matches deterministic with no union. |
| A51 | Attacker-initiated app login callback loaded by victim; redirect/linking/mix-up attacks | Missing/wrong browser flow binding denies without creating/replacing/linking victim session; PKCE/state/nonce plus exact transcript enforced |
| A52 | Native issuer callback/confirm with no app cookie, correct native binding; stolen transaction ID/wrong cookie | Correct issuer flow succeeds with explicit approval; transaction ID/app cookie/foreign browser alone denies; rotated binding consumed |
| A53 | Unsupported impersonation create/import, then capability upgrade and activation attempts | Disabled/reapproval record round-trips normally; enabled unsupported input rejects; upgrade/PATCH/import cannot activate, dedicated fresh approved commit required |
| A54 | TokenReview/projected token reused before rotation, then rotated; single_use configuration requested | Reusable renewal works both times with fresh validation; single_use enrollment/import denied even with local keys; no verified-jti assumption |
| A55 | Private access/internal types versus at+jwt/ID token/profile confusion | Only exact implemented private type/profile/ingress pairs accepted; WIF does not invent client_id; actual CLI client_id required |

All unconditional rows block release. Optional refresh/device/active-impersonation subcases are conditional on reviewed feature scope; rejection of unsupported issuance and normal disabled-policy storage/preservation are unconditional. Neither client library, direct/delegated WIF, native confirmation, operator recovery nor profile-appropriate live checking is optional.

## 9. Delivery dependencies and issue boundaries

| Order | Block | Prerequisites | Output |
| --- | --- | --- | --- |
| 0 | Bootstrap PR #2, landed | None | Service, TypeScript health helper, workspace/CI only |
| 1 | M0 / T00 | Inspect bootstrap | Reviewed public/operator/client/security contracts |
| 2 | M1 / T10–T14 | M0 | Full authority/state schema, audience/origin/client provisioning, trust/policy, local operator recovery and sole provider-transition primitive |
| 3 | M2 / T20–T26 | M1 | Signer/JWKS/WIF, Rust workload library, bearer Envoy and receiver-authorized WIF action checks |
| 4 | M3 / T30–T33 | M1, M2 | Browser-bound human OIDC/session/internal profile, human-session checks and TypeScript SPA package |
| 5 | M4 / T40–T41 | M2, M3, M1 OAuth state | Issuer-native callback/confirmation, human CLI profile/checks, reusable Rust native library/reference CLI |
| 6 | M5 / T50–T52 | Above | Deployment/CI audit, full switch runbook/invariance/recovery and unchanged-artifact conformance |

Reviewable implementation slices: schema/registry; independent operator and complete provisioning; verifiers/keysets; selected-grant policy; signer/profile verifiers; exchange/Rust WIF/GitHub; TokenReview; bearer ext_authz/live check; browser-bound OIDC/session/origin routing; human internal assertion and TypeScript package; issuer-native server flow/Rust library; provider adapter; deployment/migration/security tests. Include each new package's CI/consumer tests with its implementation, not as a later optional step. Docs-only and runtime PRs remain separate.

## 10. Definitions of done

**Protocol:** explicit standard/private grant distinction and private credential typing, selectors/defaults/binding selection/replay/constraints; profile-specific verification without upstream-provider configuration or subject-prefix exemptions.

**WIF:** authorized discovery/uploaded-key/TokenReview enrollment, generated stable selectors and direct/delegated service access within instance audience assignments. Secretless GitHub/K8s API calls and correct renewal modes; impersonation not required.

**Gateway:** authenticated fail-closed bearer path in M2; origin/session/CSRF plus signed private human evidence in M3. Bytes go directly to backend, which verifies profile/audience/canonical tenant/RBAC; no public internal endpoint or spoofed identity.

**TypeScript SPA:** packaged @skyoauth/client is browser/framework-neutral, not just Node health/workload code; memory-only session/CSRF and strict same-origin transport, no OAuth-token getter, core without Node/framework dependencies, real-browser/package/type/adapter tests.

**Rust CLI:** packaged reusable skyoauth-client works in an independent CLI with PKCE/external browser/loopback/explicit confirmation, typed/redacted transport and tested native features/platforms. Reference executable uses that API; no service/database dependency or unsafe storage fallback.

**Administration:** bootstrap to tenant/audience/origin/client/principal/policy registration is completely authorized and executable in M1. Independent roles/recovery, read-only generic active state, exclusive transition commit and dormant-mode approval cannot be bypassed by upstream identities/imports.

**Migration:** only affected human configuration/authentication state changes through guarded commits. Prebuilt client artifacts, audiences/actions/checkers, origins/clients/human policies, all WIF sources/keysets/bindings/grants/dormant status, issuer keys and effective WIF decisions stay stable; consumed state never revives.

**Security:** every credential traces to an explicit verified profile and complete policy/authentication provenance, canonical resource tenant and backend RBAC. Revocation/race limits are honest. All unconditional A01–A55 are demonstrable, including restoration of login-CSRF/redirect/linking defenses.

## 11. ADR decisions to ratify

These are proposed starting decisions, not claims of implementation or automatic maintainer approval. A changed decision updates both docs and affected tests.

| ADR | Decision | Proposed baseline |
| --- | --- | --- |
| ADR-001 | Issuer/discovery | One stable canonical HTTPS issuer independent of human providers |
| ADR-002 | Signer/recovery | Asymmetric isolated kid/overlap; implementation M2 |
| ADR-003 | Sessions/state | PostgreSQL keyed hashes, explicit deadlines/origin/authentication epochs and browser flow bindings |
| ADR-004 | Native OAuth | Reusable Rust PKCE, external browser, issuer-local callback/cookie and fresh confirmation; optional refresh/device scoped |
| ADR-005 | WIF adapters | Three source kinds, fixed source selector/cluster config and keyset parent; reusable projected tokens |
| ADR-006 | Modes | Required direct/delegation; unsupported impersonation stored disabled, capability-independent fresh activation approval |
| ADR-007 | Backend identity | Original typed bearer or signed gateway-only human assertion; authenticated channels and canonical tenant checks |
| ADR-008 | Policy writes | Revisioned role-scoped DB/GitOps, full-plan authorization and explicit widening/deletion approval |
| ADR-009 | Upstream exchange | Optional compatible provider operation server-side, normalize downstream credential |
| ADR-010 | Live revocation | Short offline TTL plus resource-server-authenticated action check; WIF M2/human M3–M4 |
| ADR-011 | Cluster/authority | One bridge issuer, registered source IDs disambiguate clusters, not issuer alone |
| ADR-012 | Migration | Sole provider transition with monotonic auth invalidation; WIF/audience/client/operator state preserved |
| ADR-013 | Operator trust/provisioning | Independent keys/local roles, complete tenant/client/principal endpoints, M1 service operator subcommands and offline recovery |
| ADR-014 | Tenant scope | Composite references, instance audience/origin assignment, same-tenant trust/grants and mandatory backend resource mapping |
| ADR-015 | Exchange semantics | RFC direct subject exchange versus private actor mapping; explicit generated selectors and grant-directed bindings |
| ADR-016 | Replay/constraints | Reusable default/projected tokens; single-use only verified on-demand capability; profile-specific signed constraints/revisions |
| ADR-017 | Clients/layout | Preserve service/TypeScript bootstrap; mandatory SPA npm package and reusable clients/rust crate, thin native cli/; artifact/platform gates |
| ADR-018 | Resource servers | Instance audience registry/tenant assignments, separate receiver checker identities and persisted action rules |
| ADR-019 | Human credentials/private types | Explicit human_cli/human_session versus WIF; complete human policy provenance/backend_rbac mode, private JWT types rather than partial RFC 9068 |
| ADR-020 | Browser routing/binding | Globally assigned origin -> tenant/provider, distinct app/native flow cookies/callbacks, no transaction-ID-only authentication |
| ADR-021 | Exclusive provider writes | Read-only active observations, generic mutation/import rejection, sole revision-checked epoch-advancing commit primitive in M1 |
| ADR-022 | Identifier and binding lifecycle | Generated opaque IDs + tenant-local names/create-reference mapping; selected grant's actor/approved binding set filters evidence |

## 12. References

- [Architecture and roadmap](skyoauth-design.md)
- [Bootstrap PR #2](https://github.com/skyoauth/skyoauth/pull/2) and [landed tree](https://github.com/skyoauth/skyoauth/tree/8f81df23efd4c4a0cfe522f711a9ca56f294aab1)
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html): subject/actor roles and act
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): browser-bound OAuth transactions, CSRF/redirect/mix-up protection
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html): external browser, loopback and native interaction
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html): JWT profile separation
- [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html): at+jwt/client_id requirements, contrasted with the chosen private profile
- [Fetch Standard](https://fetch.spec.whatwg.org/): same-origin credentials/mode/redirect controls
- [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc)
- [Kubernetes TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) and [projected token rotation](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Envoy Gateway extAuth](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)
