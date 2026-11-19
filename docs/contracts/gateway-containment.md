# Gateway credential containment and route admission

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Tasks covered:** T00.5.
- **Derived from:** [design](../skyoauth-design.md) §3.1, §4, §4.1, §4.2,
  §6, §6.1.1, §7.2, §13; [tasks](../skyoauth-tasks.md) §2 "Endpoint matrix",
  §3 ("Route preparation, approval and recovery", "Unfinished-apply
  compensation", "Recovery supersession", "Secret dependencies and sanitized
  preparation", "Protected-listener TLS renewal", "cert-manager temporary-key
  class", "TLS recovery under the approved contract", "Exact-mode rotation",
  "Credential hold and deletion protection", "Guard boundary and writer
  entries", "Administrative runtime reads", "Route runtime state", "Route
  observation bounds and apply outcomes"), T14.9, T32.3, T32.4, T32.13, T50.4,
  T52.4, §8 (A18, A58, A61), §9, §11 (ADR-007, ADR-020).
- **Related contracts:** [public-api.md](public-api.md) (endpoints and
  callers), [errors-retry.md](errors-retry.md) (wire results),
  [token-profiles.md](token-profiles.md) (assertion claims),
  [lifetimes.md](lifetimes.md) (every numeric time bound used here).

This document freezes how the Envoy Gateway adapter keeps browser credentials
away from application backends, how the request digest and the gateway
configuration digests are bound, and who may prepare, approve, activate,
cancel, revoke, abort and supersede a route-bundle deployment. It restates
the design and the tasks plan and adds no new behavior. Where the sources
leave a detail open, it is listed under [Open questions](#open-questions) and
is not decided here.

The contract covers the Envoy Gateway adapter only. Every alternate gateway
adapter, including ForwardAuth on Kubernetes, needs its own reviewed
equivalent deployment, observation and all-route credential-removal contract.
(design §4.2; tasks T32.9)

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119,
RFC 8174) when they appear in capitals. Requirement IDs use `GW-nnn`.

## 1. Terms

| Term               | Meaning in this contract                                                                                                                                        | Source                |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| Enrolled host      | A host whose routes are in the protected set that instance `security_admin` enrolled by cluster, Gateway UID, listener and hostname intersection (see OQ-GW-12) | design §4, §4.2       |
| SkyOAuth route     | A fixed SkyOAuth authentication or session endpoint routed to the independently verified SkyOAuth backend identity                                              | design §4             |
| Non-SkyOAuth route | Every other route on an enrolled host: SPA shell, assets, public, health, bearer and cookie-protected application routes                                        | design §4             |
| Protected scope    | The enrolled cluster, Gateway UID, listener and hostname set of an approved bundle                                                                              | design §4.2           |
| Route bundle       | Tenant-owned parent whose immutable versions pin one origin version, route versions, gateway plan, `activation_mode`, optional `abort_plan` and digests         | design §4.2; tasks §3 |
| Attempt            | Durable `RouteBundleAttempt` of one approved `gateway_apply` version, with its deadlines, reason and write journal                                              | design §4.2; tasks §3 |
| Traffic gate       | Runtime eligibility of the bundle for new cookie-authenticated application requests and continuation admissions                                                 | design §4.2           |
| Projection `P`     | Versioned `P(configuration, protected_scope)` computed on prepared xDS and on observed active configuration                                                     | design §4.2           |
| Deployment version | `deployment_version_id`: the approved version whose unchanged gateway configuration is backed by observations, distinct from the active registry pins           | design §4.2           |

## 2. Digest binding

### 2.1 Request target digest

The `human_session` assertion binds the request through the
`skyoauth_request` v1 tuple. Its claim shape and fixture are frozen in
[token-profiles.md §6](token-profiles.md#6-request-binding-human_session-only).
This section adds the gateway and backend obligations.

- **GW-001** The bound tuple MUST be the request after ingress validation and
  normalization and before ext_authz, and MUST be identical at the backend
  before framework URL decoding. (design §4.1)
- **GW-002** Ingress MUST reject fragments, control characters, literal
  backslashes, malformed escapes, encoded path separators, dot and traversal
  segments (including percent-encoded dots) and repeated path slashes.
  Non-ASCII path data MUST be percent-encoded. These are required deployment
  and parser rules, not assumed Envoy defaults. (design §4.1)
- **GW-003** Canonical authority validation MUST occur once, before route
  selection. Userinfo, trailing-dot aliases and conflicting Host and
  `:authority` values MUST be rejected. (design §4.1)
- **GW-004** The backend MUST recompute `target_sha256` from its received raw
  target and compare method, scheme, authority and digest before its single
  documented URL-decoding pass. It MUST NOT hash a parsed or reconstructed URL.
  Configurations needing double decoding are unsupported. (design §4.1; tasks
  T32.13)
- **GW-005** Routes accepting `human_session` MUST NOT use path, host or query
  rewrites, post-auth routing-input mutation or route-cache rematching.
  URLRewrite prefix replacement, automatic host rewrite and client-supplied
  `X-Original-*` headers are not workarounds. Admission and smoke tests MUST
  reject such routes; unexpected mismatch MUST fail closed. (design §4.1;
  tasks T32.13, A61)
- **GW-006** Assertions, digests and sensitive request queries MUST be redacted
  from logs. The digest is not encryption: low-entropy targets can be guessed.
  (design §4.1)

### 2.2 Configuration digests

| Digest or version field      | Binds                                                                                                              | Computed by                                                                       | Source                |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- | --------------------- |
| Preparation input digest     | Immutable input snapshot of the `route_bundle_prepare` operation                                                   | Service, at the preparation request                                               | design §4.2           |
| `translator_input_digest`    | Validated complete input snapshot, explicit bootstrap inputs and the Secret substitution profile                   | Preparation worker; bound by the service to the pending operation                 | design §4.2; tasks §3 |
| `adapter_artifact_digests`   | Pinned Envoy Gateway, egctl, Envoy and bootstrap artifacts                                                         | Preparation worker; recorded in the version                                       | design §4.2; tasks §3 |
| `canonicalization_version`   | Version of the projection `P` and its canonical form                                                               | Adapter                                                                           | design §4.2; tasks §3 |
| `expected_gateway_digest`    | `P` of the translated xDS for the protected scope                                                                  | Preparation worker running the pinned translator; never a caller or running proxy | design §4.2           |
| `plan_digest`                | Complete plan, including `activation_mode`, `abort_plan`, `security_preconditions`, `reenable_targets` and timeout | Service, at finalization                                                          | design §4.2           |
| `observed_gateway_digest`    | `P` of one proxy's observed active configuration                                                                   | Controller from the management listener; recorded per proxy                       | design §4.2; tasks §3 |
| `recovery_snapshot_digest`   | Failed attempt revision and journal digest, recovery inventory, last completed pair and unresolved obligations     | Preparation for a supersession                                                    | design §4.2           |
| `dependency_contract_digest` | Stable TLS dependency contract: reference, UID, profile and writers                                                | Service                                                                           | design §4.2           |
| `dependency_evidence_digest` | Fresh supervisor verification of real Secret dependencies for one observation                                      | Controller supervisor                                                             | design §4.2           |

- **GW-010** The service MUST NOT trust a caller-supplied expected digest. A
  tenant cannot supply a trusted expected digest, and a scoped worker result is
  an explicit trusted preparation component, not proof that a caller hash is
  correct. (design §4.2; tasks T14.9)
- **GW-011** The expected gateway digest MUST NOT be derived from a running
  proxy, and SkyOAuth MUST NOT reimplement Envoy Gateway translation. (design
  §4.2)
- **GW-012** `activation_mode` MUST be included in both the input and plan
  digests. (design §4.2)
- **GW-013** Approval MUST bind the complete plan digest and exact version.
  (design §4.2)
- **GW-014** Input and plan digests, approval preconditions, registry-only
  equivalence, `recovery_snapshot_digest` and `restore_pair` MUST compare the
  stable TLS dependency contract and revalidate current allowed material, not a
  historical leaf certificate or resourceVersion. Exact-mode dependencies
  additionally bind their material pins. (design §4.2)

The hash algorithm and canonical serialization of these digests are not
specified (OQ-GW-7).

## 3. All-route credential containment

| Rule                              | Applies to                                   | Mechanism                                                                                               | Stage                                                         | Source                 |
| --------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------- |
| Remove every `Cookie` field       | Every non-SkyOAuth route on an enrolled host | HTTPRoute `RequestHeaderModifier.remove: [cookie, x-skyoauth-csrf]` → route `request_headers_to_remove` | Ordinary upstream stage; after ext_authz where ext_authz runs | design §4; tasks T32.4 |
| Remove `X-SkyOAuth-CSRF`          | Every non-SkyOAuth route on an enrolled host | Same modifier                                                                                           | Same                                                          | design §4; tasks T32.4 |
| Remove every `Set-Cookie` field   | Every non-SkyOAuth route on an enrolled host | HTTPRoute `ResponseHeaderModifier.remove: [set-cookie]` → `response_headers_to_remove: [set-cookie]`    | Response                                                      | design §4; tasks T32.4 |
| ext_authz `headers_to_remove`     | Protected cookie routes                      | gRPC `OkHttpResponse.headers_to_remove`                                                                 | Defense in depth only                                         | design §4; tasks T32.4 |
| Assertion header replacement      | Protected cookie routes                      | Non-appending replacement of the private backend header                                                 | After a successful Check                                      | design §4, §6          |
| Client-supplied assertion headers | All routes                                   | Removed by Envoy                                                                                        | Not specified (OQ-GW-5)                                       | design §3.1, §6        |

- **GW-020** On an enrolled host, every route to an application backend MUST
  remove all `Cookie` fields and `X-SkyOAuth-CSRF` before forwarding,
  regardless of authentication class or whether ext_authz runs. This includes
  the SPA shell, assets, public and health endpoints and bearer routes.
  (design §4; tasks T32.4, A18)
- **GW-021** The removal MUST NOT be conditional on an auth-service response.
  (design §4)
- **GW-022** On protected routes SkyOAuth MUST first receive the original
  bounded metadata for session, Origin and CSRF validation and mixed-credential
  rejection. Removal MUST use ordinary upstream-stage removal, not early
  removal before ext_authz. (design §4; tasks T32.4)
- **GW-023** The gRPC `headers_to_remove` MUST NOT be the sole removal
  mechanism. (tasks T32.4)
- **GW-024** Authentication MUST reject duplicate or ambiguous SkyOAuth cookies
  rather than choose a copy. (design §4; tasks T32.4, A18)
- **GW-025** Cookies and CSRF tokens MUST NOT be copied into alternative
  forwarded metadata, and MUST be redacted in gateway logs and traces as well
  as application logs. (design §4; tasks T50.6)
- **GW-026** Configurations that restore or expose the removed credentials MUST
  be prohibited, including through retries and mirrors. (design §4; tasks
  T32.4, A18)
- **GW-027** Every non-SkyOAuth route MUST remove every `Set-Cookie` response
  field, including duplicate and nonreserved cookies, without parsing cookie
  names. No Lua, Wasm or ext_proc cookie-name filter is required or relied on.
  (design §4; tasks T32.4)
- **GW-028** Both removals, their stage and order, and the exact exemptions
  MUST be included in the approved projection. Missing removal or an
  unauthorized exemption MUST reject preparation and activation. (design §4,
  §4.2; tasks T32.4)
- **GW-029** Containment is not isolation from malicious JavaScript served on
  the same trusted application origin and MUST NOT be claimed as such. (design
  §4, §9; tasks T32.4)

Routes only on a distinct unenrolled host or listener stay outside this
mechanism until that scope is enrolled (design §4.2).

## 4. Exemptions and filter order

### 4.1 Exemptions

Only fixed SkyOAuth authentication and session endpoints that route to the
independently verified SkyOAuth backend identity may consume or issue their
required cookies (design §4). The cookie-bearing endpoints named by the
sources are:

| Host               | Path                  | Cookies the endpoint consumes or issues                                                           | Source                |
| ------------------ | --------------------- | ------------------------------------------------------------------------------------------------- | --------------------- |
| Application origin | `/_skyoauth/login`    | Issues `__Host-skyoauth_login`                                                                    | design §4, §5.1       |
| Application origin | `/_skyoauth/callback` | Consumes `__Host-skyoauth_login`; issues `__Host-skyoauth_session`                                | design §5.1           |
| Application origin | `/_skyoauth/session`  | Consumes `__Host-skyoauth_session`                                                                | design §5.1           |
| Application origin | `/_skyoauth/logout`   | Consumes `__Host-skyoauth_session` and `X-SkyOAuth-CSRF`; expires the session cookie              | design §5.1; tasks §2 |
| Issuer origin      | `/oauth/authorize`    | Issues `__Host-skyoauth_native`                                                                   | design §5.2           |
| Issuer origin      | `/oauth/callback`     | Consumes and rotates `__Host-skyoauth_native`                                                     | design §5.2           |
| Issuer origin      | `/oauth/confirm`      | Consumes the rotated `__Host-skyoauth_native` and CSRF; clears it on completion, denial or expiry | design §5.2           |

Whether the issuer host is an enrolled host, and whether non-cookie SkyOAuth
endpoints (`/oauth/token`, `/oauth/revoke`, `/.well-known/*`,
`/_skyoauth/oidc/backchannel-logout`) are exempt, are open (OQ-GW-3).

- **GW-030** An exemption MUST require both the exact fixed path and routing
  to the independently verified SkyOAuth backend identity. A path prefix, a
  caller header or a tenant-supplied flag alone MUST NOT grant an exemption.
  (design §4; tasks T32.4)
- **GW-031** Genuine SkyOAuth login, callback, session, logout and native flows
  MUST continue to work under containment. (design §4; tasks A18)
- **GW-032** The route controller MUST preserve the fixed SkyOAuth routes during
  an application apply, and a `cleanup_to_closed` target MUST preserve fixed
  SkyOAuth cleanup endpoints. (design §4.2; see also
  [public-api.md §8](public-api.md#8-independence-from-the-application-route-gate))

### 4.2 Filter order

The sources fix the following ordering constraints. The literal per-route
Envoy filter chain of the pinned adapter is an adapter fixture (OQ-GW-5).

| Constraint                                                                                                                                        | Source                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| Canonical authority validation happens once, before route selection                                                                               | design §4.1              |
| The request tuple is taken after ingress validation and normalization, before ext_authz                                                           | design §4.1              |
| On protected routes ext_authz receives the original Cookie, Origin and CSRF metadata                                                              | design §4                |
| Cookie and CSRF removal runs at the ordinary upstream stage, after any required authentication                                                    | design §4; tasks T00.5   |
| No routing-input mutation or route-cache rematching after authentication on `human_session` routes                                                | design §4.1              |
| The ordered effective filter chain and resolved configuration of each protected route is projected; an order change changes the digest or rejects | design §4.2; tasks T50.4 |
| Disabling a previously effective mandatory auth filter changes the projection; it is not an inert-filter exclusion                                | design §4.2              |

- **GW-040** Tests MUST verify the actual filter ordering and the bytes the
  upstream receives, not only registry simulations. (design §4; tasks T52.4)

## 5. Protected scope and admission guard

- **GW-050** Instance `security_admin` MUST enroll the protected set by
  cluster, Gateway UID, listener and hostname intersection. (design §4.2)
- **GW-051** A ValidatingAdmissionPolicy and binding with
  `failurePolicy: Fail` and `validationActions: [Deny]`, plus RBAC, MUST
  restrict configuration writes affecting the protected set to the dedicated
  route-controller service account. (design §4.2)
- **GW-052** The guard MUST cover create, update and delete of every route that
  could attach to a protected listener or host, including new or unlabeled
  routes, omitted and wildcard hostnames, more-specific shadow routes, old and
  new `parentRefs`, cross-namespace attachments and changes to
  `allowedRoutes` and namespace selectors. (design §4.2; tasks A58)
- **GW-053** The guarded inventory MUST include Gateway, HTTPRoute,
  SecurityPolicy, reference permissions, supported security and traffic
  extensions and backend identity and routing configuration that can affect
  the protected set. Where an indirect dependency cannot be narrowed safely by
  the supported admission predicates, the whole dependency scope MUST be
  guarded or the attachment rejected. (design §4.2; see OQ-GW-6)
- **GW-054** Non-cookie bearer, public, auth and health paths on a protected
  host MUST be managed resources in the same bundle with an explicit
  authentication class. They do not acquire cookie authorization. (design
  §4.2)
- **GW-055** Shared Gateway-wide policy or listener changes MUST require
  approval of all affected bundles or be rejected. (design §4.2)
- **GW-056** Admission exceptions are limited to narrow status-only updates by
  the existing gateway controller, the scoped TLS-renewer update (§12.4), the
  cert-manager temporary-key class (§12.4) and sealed, acknowledged
  credential-retirement DELETE (§12.6). (design §4.2; see OQ-GW-14)
- **GW-057** Helm, Argo CD and Flux MAY render and submit approved bundle
  inputs but MUST NOT directly apply managed objects while the sole-writer
  guard is installed. (design §4.2; tasks T10.7; ADR-020)
- **GW-058** Installation MUST be verified before protected traffic is enabled.
  Ordinary direct edits and new shadow routes MUST be rejected at admission,
  not only discovered later. (design §4.2)

Cluster administrators who can remove these guards remain trusted
infrastructure principals and are outside this guarantee (design §4.2).

## 6. Protected-scope projection

| Included in `P`                                                                                      | Excluded from `P`                                                                                         | Source      |
| ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ----------- |
| Filter chains and virtual-host selection capable of serving the protected listener, SNI or authority | Provably disjoint virtual hosts, routes and clusters                                                      | design §4.2 |
| Intersecting exact, wildcard and catch-all candidates and their relevant precedence                  | Documented nonsemantic noise (OQ-GW-7)                                                                    | design §4.2 |
| All routes and authentication classes on the protected host                                          | Filters proven inert on every protected request path, and only their exclusively unreachable dependencies | design §4.2 |
| Reachable clusters, discovery selectors and peer identities                                          | Secret payloads                                                                                           | design §4.2 |
| Shared listener, HCM, TLS and normalization settings the protected routes depend on                  |                                                                                                           | design §4.2 |
| Ordered effective filter chain and resolved configuration per protected route                        |                                                                                                           | design §4.2 |
| Request Cookie and CSRF removal, response Set-Cookie removal, auth exemptions and filter ordering    |                                                                                                           | design §4.2 |
| Secret references (SDS names) and all public security semantics                                      |                                                                                                           | design §4.2 |

- **GW-060** The same versioned `P` MUST be computed on prepared xDS and on
  observed active configuration. (design §4.2)
- **GW-061** `P` MUST NOT be the hash of the whole shared RouteConfiguration
  merely because it contains the protected host. An Accepted condition, a
  manifest hash or a caller-selected dump is not deployed evidence. (design
  §4.2)
- **GW-062** A filter introduced for an unenrolled host MAY be excluded only
  when the pinned adapter has explicit, tested semantics proving it disabled
  or inert on every protected request path, including public, auth and
  fallback routes, after resolving default disabling and every supported
  RouteConfiguration, virtual-host, route and backend override and
  request-dependent enablement. A default disabled flag alone is insufficient.
  (design §4.2)
- **GW-063** Unknown or custom filters, ambiguous overrides, global security
  effects and unprovable request-dependent activation MUST remain protected
  dependencies or be rejected before apply. Ambiguous dependency reachability
  fails closed. (design §4.2)
- **GW-064** A route change solely for an unenrolled host on the shared
  listener, or a SecurityPolicy addition or removal for that host whose filter
  is proven inert on every protected path, MUST leave the protected projection
  and evidence eligibility unchanged. A wildcard overlap, a protected receiver
  or auth change, an override enabling the filter on a protected route, an
  effective-filter order change or a shared listener security change MUST
  change the projection or be rejected. (design §4.2; tasks T50.4, A58)
- **GW-065** Disjoint edits MUST NOT by themselves change the protected
  serving-set generation or expire its observations. (design §4.2)

Projection eligibility does not promise transport continuity: a listener or
HCM update can still drain Envoy connections, so ordinary bounded reconnect
remains necessary (design §4.2; tasks T50.4).

## 7. Preparation: M1b contracts and M3 isolated translation

| Milestone | Delivers                                                                                                                                   | Must not claim               | Source                       |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------- | ---------------------------- |
| M1b       | Versioned schema; pending-preparation, result, approval, list and read contracts; service-validated state transitions (T14.9)              | A deployable translated plan | design §4.2; tasks T14.9, §9 |
| M3        | Isolated translator preparation before approval, controller and listener enforcement, scoped observation and both activation paths (T32.3) |                              | design §4.2; tasks T32.3     |
| M5        | Packaging and audit of the actual mechanism (T50.4)                                                                                        | Inventing the mechanism late | design §4.2; tasks T50.4, §9 |

- **GW-070** A preparation request at
  `POST /admin/v1/tenants/{tenant}/route-bundles/{id}/preparations` MUST store
  an immutable `route_bundle_prepare` operation with the input snapshot and
  digest, expected active generation, origin and route versions, security
  preconditions, required `activation_mode`, gateway-apply timeout and any
  explicit recovery intent including `supersedes_attempt_id`. It is not an
  approved deployment or a version with a caller-chosen digest. (design §4.2)
- **GW-071** The M3 preparation worker MUST run the pinned translator
  (`egctl x translate --from gateway-api --to xds`) before approval and submit
  its scoped result at
  `POST /internal/v1/route-bundles/{id}/preparations/{operation}/result`.
  (design §4.2)
- **GW-072** The service MUST validate operation and input identity,
  controller scope and current preconditions, then atomically finalize one
  immutable `RouteBundleVersion` with the expected gateway digest and a
  server-computed plan digest. An exact duplicate result MUST return the same
  version; a contradictory result or changed precondition MUST be rejected and
  require re-preparation. (design §4.2; tasks T14.9)
- **GW-073** Pending and failed preparations MUST NOT be approvable. (design
  §4.2)
- **GW-074** Finalization MUST reject a `registry_only` plan that is not
  deployment-equivalent to the captured `deployment_version_id` or that has
  recovery targets. (design §4.2)
- **GW-075** A `gateway_apply` version MUST contain an immutable `abort_plan`
  (§11.4). (design §4.2)
- **GW-076** The public auth-serving image need not contain egctl. Preparation
  MUST NOT run inside the public auth-serving process. (design §4.2; tasks
  T32.3)

## 8. Translator sandbox

- **GW-080** The helper MUST be an isolated, resource-, time- and
  output-bounded process with a fixed binary and arguments, no shell, no
  tenant-selected executable and no network fetch. (design §4.2; numeric bounds
  are OQ-GW-11)
- **GW-081** egctl `--add-missing-resources` MUST stay disabled. The only
  permitted substitution is the supervisor's placeholder Secret (§12.1).
  (design §4.2)
- **GW-082** The helper MUST NOT have access to real auth, signing, reviewer or
  operator credentials, the controller's Kubernetes service-account token,
  mTLS private key, kubeconfig, secret mounts or environment, inherited
  credential file descriptors, or authenticated API or proxy sockets. It
  receives only bounded sanitized input and returns bounded output through
  dedicated pipes. (design §4.2; tasks T32.3, T50.4)
- **GW-083** Isolation MUST be an enforced process or container sandbox with no
  shared credential mounts and no service-account automount, not a promise
  that the child will not read inherited secrets. (design §4.2)
- **GW-084** A credentialed supervisor, outside the helper, MUST perform scoped
  API calls. (design §4.2)
- **GW-085** Tests MUST attempt access to each denied credential and attempt
  network and API use, and MUST show that sentinel production secrets never
  reach helper input, logs, plans or results. (design §4.2; tasks T32.3, T50.4)

## 9. Pinned adapter inputs

| Input                                                    | Requirement                                            | Named in sources                                                        | Source           |
| -------------------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------- | ---------------- |
| Envoy Gateway controller and egctl                       | Same pinned translator build as the deployed gateway   | v1.10 documentation and v1.10.0 source as references, not a tested pair | design §4.2, §13 |
| Envoy proxy                                              | Pinned with the gateway and bootstrap                  | v1.40.1 documentation as reference                                      | design §4.2, §13 |
| EnvoyProxy bootstrap customization                       | Pinned; adds the static management listener            | Not versioned                                                           | design §4.2      |
| Management listener targets, masks, size and time bounds | Literal values frozen per adapter                      | Not given (OQ-GW-1)                                                     | design §4.2      |
| Projection canonicalization                              | `canonicalization_version` bound into the version      | Not given                                                               | tasks §3         |
| Placeholder Secret fixtures                              | Adapter-versioned, deterministic, public test data     | Not given                                                               | design §4.2      |
| cert-manager key manager                                 | Pinned version whose temporary-key lifecycle is tested | v1.20.0 source as reference                                             | design §4.2, §13 |

- **GW-090** Gateway, egctl, Envoy and bootstrap artifacts MUST be pinned
  together, and projection fixtures plus real gateway tests MUST be rerun on
  patch upgrades. The sources specify a mechanism, not a tested version pair.
  (design §4.2; see OQ-GW-2)
- **GW-091** Translation MUST run on a validated complete input snapshot with
  explicit bootstrap inputs. Unspecified missing-resource synthesis is
  forbidden. (design §4.2)

## 10. Management listener

- **GW-100** The supported adapter MUST add a separate static management
  listener through EnvoyProxy bootstrap customization, not a public HTTPRoute
  and not a sidecar. (design §4.2)
- **GW-101** The listener MUST require mTLS for the enrolled controller and
  restrict network access to that controller. (design §4.2)
- **GW-102** The listener MUST forward only an exact allowlist of GET requests
  to fixed, adapter-owned `/config_dump?resource=...&mask=...` targets on the
  fixed loopback admin cluster. It MUST reject caller-supplied query
  variations, arbitrary paths or methods, bodies, upgrades, CONNECT, redirects
  and generic admin proxying. (design §4.2)
- **GW-103** It MUST NOT expose secrets dumps, `/quitquitquit`,
  `/drain_listeners` or `/runtime_modify`. The raw admin port MUST stay
  loopback-only. (design §4.2)
- **GW-104** The controller MUST NOT receive `pods/exec` or `pods/portforward`
  permission. (design §4.2; tasks T50.4)
- **GW-105** The listener and its isolation MUST be validated before protected
  traffic is admitted. A deployment that cannot enforce this adapter MUST NOT
  silently open the full admin surface. (design §4.2)

## 11. Activation, apply and recovery

### 11.1 Activation modes

| Property                       | `registry_only`                                                                                        | `gateway_apply`                                                                      | Source      |
| ------------------------------ | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ | ----------- |
| Transition used                | `activate_registry_only`                                                                               | `begin`, then `activate`                                                             | design §4.2 |
| Gateway writes                 | None                                                                                                   | Scoped controller writes under the write journal                                     | design §4.2 |
| Gate                           | Stays open; current gate must already be eligible                                                      | Closed at `begin` for the affected origin bundle until verified activation (OQ-GW-8) | design §4.2 |
| Evidence                       | Complete observations fresh within 30 s; original samples, ages and deadlines retained                 | Complete fresh matching observation set before `activate`                            | design §4.2 |
| `deployment_version_id`        | Retained                                                                                               | Advanced on activation                                                               | design §4.2 |
| `reenable_targets`             | MUST be empty                                                                                          | Allowed; cleared atomically on activation                                            | design §4.2 |
| Supersession of failed attempt | Not allowed                                                                                            | Allowed with fresh approval                                                          | design §4.2 |
| `abort_plan`, `abort_until`    | None; no compensation authority                                                                        | Required                                                                             | design §4.2 |
| `apply_timeout_seconds`        | Not applicable                                                                                         | Bound into preparation, version and approval                                         | design §4.2 |
| Failed check                   | Old pair unchanged; MAY retry freshness in the same mode while approval is valid; no fallback to apply | Abort path (§11.4)                                                                   | design §4.2 |

- **GW-110** Mode MUST be immutable from preparation onward. There is no
  automatic mode, and neither the controller nor an approval retry can change
  it. (design §4.2)
- **GW-111** `begin` and `activate` MUST reject a `registry_only` approval, and
  `activate_registry_only` MUST reject a `gateway_apply` approval, without
  changing the gate or performing writes. `begin` MUST reject a
  `registry_only` approval even when its samples have become stale. (design
  §4.2; tasks §3)
- **GW-112** `activate_registry_only` MUST verify unchanged managed gateway
  resource contents, relevant dependency identities, protected scopes,
  adapter, bootstrap and projection versions, expected gateway digest and
  serving-set generation by comparing the approved artifacts, not resource
  names or a caller's no-op flag. (design §4.2)
- **GW-113** Registry-only activation MUST atomically advance registry pins and
  generation and supersede only changed authorization dependencies; it MUST
  NOT give a copied sample a new age or extra tolerance. (design §4.2)
- **GW-114** Incident re-enable MUST use `gateway_apply`, even when gateway
  contents are unchanged. (design §4.2)

### 11.2 Apply phases

| `apply_phase`       | Entered by                                                                                                                                        | Gate                             | Writes allowed                                             | Source      |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ---------------------------------------------------------- | ----------- |
| `idle`              | No current attempt; successful activation; successful `complete_abort`                                                                            | Per observations and other holds | None                                                       | design §4.2 |
| `applying`          | `begin`                                                                                                                                           | Closed                           | Forward writes until `apply_deadline`                      | design §4.2 |
| `abort_required`    | Cancel, newer disable, failed forward precondition (including forward expiry), nonretryable apply failure, apply deadline                         | Closed                           | None until `abort`                                         | design §4.2 |
| `aborting`          | `abort` from `applying` (recorded nonretryable failure or deadline) or from `abort_required`                                                      | Closed                           | Compensation to the exact `abort_plan` until `abort_until` | design §4.2 |
| `recovery_required` | Approval or required authority revoked, nonretryable compensation failure, missing artifacts, unresolved conflicting writes, `now >= abort_until` | Closed                           | None under old authority                                   | design §4.2 |

- **GW-120** `begin` MUST require `idle`, except a freshly approved
  supersession of the exact `recovery_required` attempt (§11.5). `begin` MUST
  close the gate before any apply and record the abort source and a durable
  per-object write journal. (design §4.2)
- **GW-121** `begin` MUST persist
  `apply_deadline = min(begun_at + apply_timeout_seconds, approval.expires_at)`.
  Before it, the controller MAY retry transient failures. `activate` at or
  after the deadline MUST reject even if the reconciler has not run. (design
  §4.2; bounds in [lifetimes.md](lifetimes.md))
- **GW-122** The owning controller MAY call `abort` directly from `applying` for
  a recorded nonretryable failure or elapsed deadline; the service records the
  reason and phase change atomically. A durable service reconciler MUST check
  deadlines at least every 10 seconds, and every transition MUST enforce them
  independently. (design §4.2)
- **GW-123** Ownership transfer, claim and restart MUST NOT reset deadlines,
  give another apply interval or lose unresolved writes. (design §4.2)
- **GW-124** If no controller can compensate, the gate MUST stay closed. No
  service-side timer performs Kubernetes writes. (design §4.2)
- **GW-125** Every forward or compensating write MUST pass ownership checks and
  UID and resourceVersion preconditions. Uncertain or incomplete writes during
  handoff keep the gate closed until the new owner reconciles and
  re-observes. Old epochs and replayed reports MUST NOT reopen the gate.
  (design §4.2)
- **GW-126** At least two controller replicas MUST be deployed with leader
  election, disruption and placement controls; failover MUST NOT reset
  sequences or observation ages. (design §4.2; tasks T32.3)

Gate outcomes while a phase other than `idle` is current are in §13; wire
results are frozen in
[errors-retry.md §2](errors-retry.md#2-status-classes) and
[§4](errors-retry.md#4-policy-check-recheck-and-close-results).

### 11.3 Roles

| Operation                                    | Who                                                                           | Must not                                                                                                     | Source                       |
| -------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------- |
| Request preparation (including supersession) | Tenant `client_admin`                                                         | Supply a trusted digest; create an approvable version before the worker result                               | design §4.2                  |
| Submit preparation result                    | Scoped M3 preparation worker                                                  | Write to the gateway or approve                                                                              | design §4.2; tasks §2 matrix |
| Approve a prepared version                   | Instance `security_admin`                                                     | Approve a pending or failed preparation; change mode; authorize arbitrary manifests or a blanket active flag | design §4.2                  |
| `claim`, transitions, observations           | Current scoped controller owner                                               | Substitute for the preparer or approver role                                                                 | design §4.2                  |
| Cancel an applying attempt                   | Tenant `client_admin` within the bundle's scope, or instance `security_admin` | Write to the gateway; change deadlines; cancel a successor                                                   | design §4.2; tasks §2 matrix |
| Revoke an approval                           | Instance `security_admin` only                                                | Change the immutable plan; roll back a completed deployment                                                  | design §4.2; tasks §2 matrix |
| Read bundle runtime and current attempt      | Tenant `client_admin` within scope, or instance `security_admin`              | Grant write authority; expose journal, manifests, xDS, worker inputs or Secret material                      | design §4.2; tasks §3        |

- **GW-130** Preparer and approver authority, approval validity and all
  preconditions MUST be rechecked before `begin` and again atomically at
  activation. (design §4.2)
- **GW-131** One person MAY hold both roles only by explicit assignment.
  (design §4.2, §7.2)
- **GW-132** Cancel MUST record an audited `route_bundle_cancel` operation with
  reason and expected attempt revision, atomically mark the current applying
  attempt `abort_required` and retain its approved compensation authority. A
  cancel of the same `abort_required` or `aborting` attempt MUST be idempotent
  and change neither deadline. A stale attempt ID MUST NOT cancel a successor.
  (design §4.2)
- **GW-133** Revoke MUST record a revision-checked
  `route_bundle_approval_revoke` operation and monotonic
  `revoked_at`/`revocation_operation_id`. It MUST reject unbegun execution and
  stop both forward and compensating writes of a current unfinished attempt,
  which becomes `recovery_required` with the gate closed. (design §4.2)
- **GW-134** Revocation after a completed activation MUST NOT undo that
  deployment; incident denial uses the independent security-disable
  operations. Neither cancel nor revoke can clear security vetoes or grant
  replacement authority. (design §4.2)
- **GW-135** Exact retries MUST return the recorded result, and activation,
  cancel and revoke races MUST serialize with the attempt and approval checks.
  (design §4.2; tasks §3)
- **GW-136** The operator MUST read the attempt ID and revision before cancel or
  supplying `supersedes_attempt_id`; a racing phase or revision change MUST
  reject the stale write rather than act on a newer attempt. (design §4.2)

### 11.4 Abort of an unfinished apply

| `abort_plan.target_kind` | Used for                                                                                             | Content                                                                                                                                               | Completion effect                                                                                    | Source      |
| ------------------------ | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ----------- |
| `restore_pair`           | Normal case; recovery when the last completed pair's artifacts revalidate under current dependencies | Captured prior active registry and deployment version IDs (which may differ), exact prior protected resource contents or absence, expected projection | Reopens the prior pair after fresh complete evidence of the restored projection; advances generation | design §4.2 |
| `cleanup_to_closed`      | Initial enrollment; recovery when restore artifacts are unavailable or unusable                      | Complete non-serving configuration and exact owned-resource cleanup list                                                                              | Clears live pins to unconfigured, ends the attempt, advances generation; gate stays closed           | design §4.2 |

- **GW-140** Compensation MUST be limited to the approval's exact `abort_plan`,
  not arbitrary historical versions. Abort calls MUST bind approval and attempt
  ID, plan digest and current controller epoch. (design §4.2)
- **GW-141** Compensation MUST require current controller scope, enabled
  required operator authority (OQ-GW-9), an unrevoked approval and
  `now < abort_until`. A newer parent disable or an elapsed forward
  `expires_at` MUST NOT reject already-approved compensating writes. (design
  §4.2)
- **GW-142** The controller MUST stop forward work, fence prior owners and
  outstanding writes, and restore only approved protected resource values. It
  MAY delete an attempt-created object only with the journaled matching UID and
  ownership. Unrelated host resources MUST NOT be overwritten. (design §4.2)
- **GW-143** `complete_abort` MUST be valid only for the current `aborting`
  attempt and only after all writes have settled and a complete fresh
  observation set proves the exact target. An exact completion retry MUST
  return the recorded result without new writes; replay after a newer attempt
  MUST NOT restore older pins. (design §4.2)
- **GW-144** `complete_abort` MUST NOT restore any `security_status`,
  `security_revision`, role, policy invalidation, session or continuation.
  (design §4.2)
- **GW-145** Transient compensation failures MAY be retried only within the
  original abort window. Aborting is idempotent and bounded, not a general
  rollback API. (design §4.2)

### 11.5 Superseding a failed attempt

- **GW-150** Recovery from `recovery_required` MUST use a new `gateway_apply`
  preparation naming `supersedes_attempt_id`, and a fresh instance
  `security_admin` approval of the supersession, exact forward and cleanup
  scope and abort target, with currently enabled preparer, controller and
  approver authority. A revoked old approval grants none of this. (design §4.2)
- **GW-151** Before finalization a current scoped owner MUST fence and quiesce
  the old writer and settle every outstanding request. An unaccounted in-flight
  write or unknown ownership MUST block finalization, never license a forced
  overwrite. (design §4.2)
- **GW-152** The recovery snapshot MUST capture actual mixed resources, the
  failed attempt's revision and journal digest, the last completed pair, all
  unresolved writes and cleanup obligations into `recovery_snapshot_digest`.
  It is not an approved deployment. (design §4.2)
- **GW-153** Only that approved recovery `begin` MAY replace a
  `recovery_required` attempt. It MUST atomically compare the failed attempt
  ID, revision, journal digest, recovery inventory and active generation, mark
  the old attempt superseded and inherit every unresolved journal entry and
  cleanup obligation, including earlier creations absent from the new plan.
  Changed inventory requires re-preparation. (design §4.2)
- **GW-154** The recovery `abort_plan` MUST NOT restore the captured mixed
  state. It MUST be a revalidated `restore_pair` or an explicit
  `cleanup_to_closed`. (design §4.2)
- **GW-155** Successful recovery activation and either abort completion MUST
  reconcile every inherited journal obligation. Another failure or an expired
  or revoked recovery approval returns to `recovery_required` and MAY be
  superseded again, never by extending old authority or inventing evidence.
  (design §4.2)

## 12. Secret dependencies and TLS profiles

### 12.1 Sanitized substitution

- **GW-160** The supervisor MUST resolve every Secret reference with scoped
  reads and verify existence, reference permissions, supported type, required
  keys and material validity; for TLS it MUST verify the real key and
  certificate match, validity and required host identity. (design §4.2)
- **GW-161** It MUST record nonsecret `secret_dependencies`: kind, namespace,
  name, expected UID, usage and `validation_mode`, and for exact mode the
  resourceVersion and approved public fingerprints. (design §4.2; tasks §3)
- **GW-162** It MUST substitute an adapter-versioned deterministic
  nonproduction placeholder Secret of the same reference, type and key shape.
  A placeholder MUST NOT stand in for a missing or invalid real dependency, and
  no real Secret may be restored from a placeholder. (design §4.2)
- **GW-163** Real private keys, passwords and tokens MUST NOT enter helper
  input, logs, plans, results or observation dumps. Inline secret material and
  Secret usages without an explicit validated adapter profile MUST be
  rejected. (design §4.2)
- **GW-164** The adapter MUST prove on fixtures that substitution preserves the
  projected routing, filter and TLS structure and SDS references for each
  supported use. A policy or backend that parses credential bytes without that
  proof MUST be rejected at preparation. (design §4.2; see OQ-GW-13)
- **GW-165** Runtime `secret_dependencies` MUST include only references
  reachable from effective protected configuration. Proven disjoint or inert
  translation-only references are validated for preparation but excluded from
  protected evidence; unknown reachability stays protected or rejects. (design
  §4.2)
- **GW-166** Missing or invalid proposed dependencies MUST reject preparation
  or execution without altering the old live pair. A known violation of a
  deployed dependency's approved contract closes the gate as drift. (design
  §4.2)

### 12.2 Validation modes

| `validation_mode` | Used for                                                | Immutable contract                                                                                    | Observed, not pinned              | Material change                                                                     | Source                |
| ----------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------- | ----------------------------------------------------------------------------------- | --------------------- |
| `exact`           | Supported policy and backend credentials                | Reference, UID, type, usage, resourceVersion, approved public fingerprints                            | Nothing                           | Staged new reference and approved `gateway_apply` (§12.5); in-place change is drift | design §4.2; tasks §3 |
| `tls_renewal`     | Supported renewable downstream TLS listeners (baseline) | Reference, UID, type, protected listener and SNI, validation-profile digest, enrolled renewal writers | Leaf fingerprint, resourceVersion | In-profile same-UID renewal without new approval (§12.3)                            | design §4.2; tasks §3 |

- **GW-170** A renewable downstream listener without a proven `tls_renewal`
  profile MUST be rejected at enrollment; it MUST NOT silently fall back to
  leaf pinning. (design §4.2)

### 12.3 Renewable TLS profile

The `tls_renewal` profile pins: independent trust anchors and any issuer or
SPKI restrictions (not an issuer name or the Secret's own `ca.crt`), required
hostnames and allowed SANs, serverAuth and key usages, permitted key and
signature algorithms and strength, current validity and revocation checks,
minimum remaining validity and `renewal_overlap_seconds`. (design §4.2; tasks
§3)

- **GW-180** The profile, trust anchors, reference and UID MUST NOT be widened
  or replaced by renewal; such changes are newly prepared and approved
  configuration. (design §4.2)
- **GW-181** A valid same-UID renewal between preparation, approval and `begin`
  MUST NOT invalidate the plan solely because material changed; each execution
  still needs valid current dependency evidence. (design §4.2)
- **GW-182** Overlap and convergence follow design §4.2 "Bounded SDS
  propagation": at most a current and a previous validated public candidate,
  monotonic `material_sequence`, and `overlap_until` fixed at first sight of a
  new valid leaf. Numeric bounds are in [lifetimes.md](lifetimes.md). (design
  §4.2; tasks §3)
- **GW-183** Invalid material MUST NOT occupy a candidate slot. A third distinct
  valid leaf during incomplete propagation MUST NOT enlarge the set or start
  another overlap; it closes admission as `awaiting_evidence`. (design §4.2)
- **GW-184** Ordinary convergence and recovery MUST use the same CAS
  single-candidate transition on `POST /internal/v1/route-bundles/{id}/observations`:
  validate the current actual Secret under the unchanged contract, obtain
  complete evidence fresh within 30 s from every traffic-eligible proxy,
  advance `material_sequence`, retain only that candidate, clear
  previous/overlap state and the TLS failure, and set `stable`. It needs no new
  preparation, approval or `gateway_apply`, and clears only the TLS blocker.
  (design §4.2)
- **GW-185** After convergence the retired candidate MUST NOT be authorized: a
  fresh served regression to it is `material_mismatch`. Stale pre-convergence
  reports MUST fail sequence checks without changing eligibility. (design
  §4.2; tasks T32.3)
- **GW-186** A successful permitted renewal MUST NOT change
  `expected_gateway_digest` or revoke contexts, and compensation MUST NOT write
  an expired certificate back. (design §4.2)

### 12.4 Writer exceptions

| Writer                                          | Permitted                                                                                                                                                                                      | Forbidden                                                                                                                             | Source                |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| Enrolled TLS renewer (for example cert-manager) | UPDATE of `tls.crt`, `tls.key`, optional `ca.crt` and enumerated nonsecurity metadata of the exact existing Secret                                                                             | Delete or recreate; change reference, type or ownership; widen trust or profile; write another dependency; mutate routes or listeners | design §4.2; tasks §3 |
| cert-manager temporary-key class                | CREATE of key-only Secrets carrying the reserved `cert-manager.io/next-private-key="true"` marker, pinned controller marker, owner reference and name prefix; DELETE by the enrolled principal | Any UPDATE adding or removing the marker or changing identity, owner or class; any use as a credential, hold or abort source          | design §4.2; tasks §3 |
| Credential provisioner                          | Create-only staging in an isolated scope; DELETE only of a sealed UID with UID and resourceVersion preconditions after acknowledgement                                                         | UPDATE or DELETE of active or retained dependencies; deletion by name alone                                                           | design §4.2; tasks §3 |

- **GW-190** The supervisor, not CEL or a cert-manager Ready condition, MUST
  verify the real certificate pair, chain and profile before accepting
  material evidence. (design §4.2)
- **GW-191** The Secret guard MUST deny UPDATE and DELETE of every Secret in the
  exact dedicated credential namespaces, tracked or untracked, except the
  exceptions in this table. Missing or invalid guard parameters MUST deny.
  (design §4.2)

### 12.5 Exact-mode reference rotation

1. An independent credential provisioner stages a new unreferenced, frozen
   Secret S2 (data and metadata/resourceVersion) while S1 stays live.
2. Tenant `client_admin` prepares a `gateway_apply` version changing the
   reference from S1 to S2. The supervisor verifies S2's real material and
   binds its exact reference, UID, resourceVersion and evidence.
3. Instance `security_admin` approves it with the credential-reference
   rotation and the origin-wide cookie and stream interruption displayed.
4. The controller applies only gateway references and activates on fresh
   complete gateway and material evidence.
5. On failure, compensation restores the approved S1 reference only if S1
   still validates; otherwise the bundle stays closed for fresh authorized
   recovery.
6. S1 is retired only after every hold releases, through the sealed retirement
   protocol (§12.6).

(design §4.2; tasks §3 "Exact-mode rotation")

- **GW-200** `registry_only` or `tls_renewal` MUST NOT substitute for this flow,
  and in-place automatic renewal of an exact target MUST be denied. (design
  §4.2)
- **GW-201** Missing or invalid S2 MUST be rejected before `begin` without
  disturbing S1. S1 MUST remain unchanged, unrevoked, usable and protected
  for every outstanding abort or restore obligation. (design §4.2)

### 12.6 Credential holds and deletion protection

The hold ledger, protection-scope registry, retained guard proofs and
retirement protocol are specified in design §4.2 and tasks §3 ("Credential
hold and deletion protection" through "Unreferenced staging cleanup"). This
contract freezes only the invariants the gateway path depends on.

- **GW-210** Holds MUST be service state keyed by Secret UID across all
  bundles (`active_registry`, `active_deployment`, `applying_forward`,
  `abort_source`, `inherited_recovery`, `approved_pending`), acquired or
  transferred before predecessors are released. `abort_until` alone is not a
  release. (design §4.2)
- **GW-211** New credential adoption MUST require service-acquired holds and
  confirmed installed protection before an approval becomes executable or a
  forward `begin` succeeds. (design §4.2)
- **GW-212** Abort, `complete_abort`, already-begun activation and supersession
  inheritance MAY carry a retained guard proof while the same UID, consumer and
  contract stay continuously held; a zero-hold gap, new UID or consumer,
  widened contract or known protection loss requires fresh adoption. (design
  §4.2; tasks T32.3)
- **GW-213** Deletion MUST require a zero-hold `credential_retirement` seal, a
  matching `release_ack`/`delete_authorized` for the exact UID,
  resourceVersion and principal, and DELETE with UID and resourceVersion
  preconditions. A held, retiring, stale or unknown UID MUST NOT be deleted.
  (design §4.2)

## 13. Observation and gate outcomes

- **GW-220** Observations MUST be per proxy, bound to deployment version,
  attempt ID and target kind where applicable, serving-set generation,
  controller epoch, increasing sequence and `dependency_evidence_digest`.
  (design §4.2; tasks §2 matrix)
- **GW-221** Polling is operational telemetry and MUST NOT revise
  authorization or create policy-change audit events. (design §4.2)
- **GW-222** Cleanup evidence has no serving deployment version and MUST NOT
  enable traffic. (design §4.2)
- **GW-223** New proxies MUST stay outside protected readiness until verified.
  Removing an unobservable proxy from the required set needs verified
  withdrawal or draining followed by verification of the remainder. (design
  §4.2)

| Condition                                                            | New cookie application requests and admissions | Existing continuation recheck                                                                              | Source                    |
| -------------------------------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------- |
| Verified deployment, evidence within its bound, no other hold        | Eligible                                       | Ordinary                                                                                                   | design §4.2               |
| Observation loss within the last-known-good bound                    | Eligible                                       | Ordinary, leases capped by remaining observation validity                                                  | design §4.2               |
| Observation bound exhausted or no verified deployment                | 503 `route_configuration_unavailable`          | Unavailable; no renewal, no `closed_at`                                                                    | design §4.2               |
| `applying`, `abort_required`, `aborting`, `recovery_required`        | 503 `route_configuration_unavailable`          | Unchanged dependencies: unavailable to the existing lease; changed, removed or security-disabled: terminal | design §4.2; tasks T32.12 |
| Fresh authenticated out-of-plan digest mismatch                      | 503 immediately; no 30 s or 300 s allowance    | Terminal deny and `closed_at`                                                                              | design §4.2; tasks A58    |
| TLS nonconvergence at the overlap cutoff, no established violation   | 503 (`awaiting_evidence`)                      | Unavailable; no renewal, no `closed_at`                                                                    | design §4.2               |
| Confirmed invalid, revoked, expired, foreign or unaccounted material | 503 (`material_mismatch`)                      | Terminal deny and `closed_at`                                                                              | design §4.2               |

- **GW-224** Only differences accounted for by the approved forward or abort
  plan and write journal under a closed gate are transitional; out-of-plan
  mismatch is terminal. Late or replayed matching samples MUST NOT reopen a
  gate closed for mismatch. (design §4.2)
- **GW-225** Observation alone MUST NOT activate an unapproved version or one
  with wrong-mode, expired, revoked or stale approval. (design §4.2)
- **GW-226** Fixed `/_skyoauth/session` and `/_skyoauth/logout`, native
  `/oauth/revoke`, verified back-channel logout and independent revocation and
  security-disable operations MUST NOT depend on the application route gate
  and MUST NOT mint application assertions (see
  [public-api.md §8](public-api.md#8-independence-from-the-application-route-gate)).
  (design §4.2)

## 14. Security-revision-bound recovery

- **GW-230** `security_preconditions` MUST map every pinned or otherwise
  affected origin and route parent, including removed or replaced routes, to
  its captured `security_revision`. They are execution preconditions, not a
  continuous equality that disables unrelated live routes. (design §4.2;
  tasks §3)
- **GW-231** A disable MUST atomically set `security_status=disabled`, advance
  `security_revision` and invalidate forward execution of plans that captured
  the prior revision. If the current attempt is `applying`, the same
  transaction MUST mark it `abort_required`. Existing `abort_required` or
  `aborting` compensation keeps its phase and deadlines, and disable MUST NOT
  clear `recovery_required`. (design §4.2)
- **GW-232** `reenable_targets` MUST list typed parent IDs, expected disabled
  revisions and recovery reasons. Successful activation MUST clear only those
  parents and advance their revisions in the same transaction as the pin
  change; omitted parents keep their state. No PATCH or import can clear a
  veto. (design §4.2; tasks §3)
- **GW-233** Unpinning or replacing a security-disabled route MUST require
  explicit recovery intent for that parent, not an overlapping new-ID bypass.
  (design §4.2)
- **GW-234** A route MUST be usable only when the origin and route parents are
  security-enabled, the pinned route version has `configured_status=enabled`
  and the gate and policy checks pass. The winning route is selected before
  either status is checked, and a disabled winner MUST NOT fall back to a
  broader route. (design §4.1, §4.2)
- **GW-235** Re-enable, rollback and abort completion MUST NOT resurrect
  invalidated credentials or closed continuations, or restore historical
  security state. (design §4.2)

Fixture (tasks T14.9, A58): an approval at 09:00, a disable at 09:20 and an
activation attempt at 09:30 MUST reject without re-preparation and fresh
approval. A disable after `begin` aborts, restores and re-observes; the old
unaffected routes reopen while the disabled route stays disabled at its newer
revision.

## 15. Test and fixture requirements

| Area                          | Must show                                                                                                                                                                          | Tasks                    |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| Containment without Check     | Public SPA, asset and health requests with no ext_authz call deliver no session or flow cookie or CSRF upstream and cannot set cookies                                             | T32.4, T50.4, A18        |
| Raw upstream bytes            | Billing, deploy and static backends capture request and response metadata; retries and mirrors carry no credential copies; logs redact                                             | T32.4, T52.4, A18        |
| Response removal              | Whole-field Set-Cookie removal, including duplicate and nonreserved names                                                                                                          | T32.4                    |
| Exemptions                    | Genuine login, callback, session, logout and native flows work; prefix-only, header-only or flag-only exemptions reject                                                            | T32.4, A18               |
| Filter order                  | Actual ordering: Check sees original metadata; removal at upstream stage; order change changes digest or rejects                                                                   | T32.4, T50.4             |
| Request digest                | Shared vectors; order, duplicates, escapes and empty versus absent query significant; 4 KiB query fixed size; rewrites and rematching rejected                                     | T32.13, A61              |
| Projection                    | b.example.com route edit and inert SecurityPolicy leave app.example.com digest unchanged; enabling override, order change, shared auth or TLS change does not                      | T32.3, T50.4, A58        |
| Admission                     | New unlabeled, wildcard, omitted-host and cross-namespace shadow routes rejected                                                                                                   | T32.3, T50.4, A58        |
| Sandbox                       | Denied access to controller token, mTLS key, inherited FDs, mounts and privileged sockets; secret sentinels absent from output                                                     | T32.3, T50.4             |
| Management listener           | Supported and rejected listener configurations; GET-only fixed targets                                                                                                             | T32.3, T50.4, T52.4      |
| Preparation                   | Failed or incomplete translation, duplicate and conflicting results, security revision change during preparation                                                                   | T14.9, T32.3             |
| Modes                         | Wrong-mode transitions reject; registry-only keeps sample ages; 31 s-old evidence retry without `begin`                                                                            | T14.9, T32.3, A58        |
| Apply deadline                | 09:28 `begin`, 120 s timeout, approval to 11:00: deadline 09:30; activate at or after rejects; takeover cannot reset                                                               | T14.9, T50.4             |
| Cancel and revoke             | Roles, revisions, idempotency, races, stale IDs                                                                                                                                    | T14.9, T32.3, T50.4      |
| Compensation and supersession | Restore and re-observe; revoked or exhausted compensation stays closed; supersession with inherited orphan cleanup; `restore_pair` versus `cleanup_to_closed`; repeated failure    | T14.9, T32.3, T50.4, A58 |
| Secrets                       | Placeholder only after real validation; missing, invalid or replaced Secrets deny; byte-sensitive unsupported uses reject                                                          | T32.3, T50.4             |
| TLS renewal                   | Mixed old and new SDS; 10:00 B, 10:02 deadline, 10:03 late convergence; invalid B then valid C; 10:00:30–10:02:30 gap; 10:01 convergence then 10:01:30 regression to A is terminal | T32.3, T50.4, A58        |
| Exact rotation                | S1 to staged S2; bad staging harmless; retained S1 rollback and retirement; expired S1 recovery                                                                                    | T32.3, T50.4, A58        |
| Holds and scopes              | Held S1 retirement denied while `abort_required`, `recovery_required` or approved-pending; pending and committed scope PATCH with reconciler outage (T32.3 10:00–10:31 timeline)   | T32.3, T50.4, A58        |
| Mismatch                      | Fresh out-of-plan mismatch closes immediately; terminal recheck; old reports cannot reopen                                                                                         | T32.3, T50.4, A58        |

## Open questions

These are gaps, ambiguities or contradictions in the design and tasks
documents. This contract does not resolve them. Entries marked
"(contradiction)" are places where the sources disagree.

- **OQ-GW-1 — Management listener literals.** Design §4.2 requires T00.5 to
  "freeze the literal targets/masks and size/time bounds for each supported
  adapter". The sources give no literal `/config_dump` `resource` or `mask`
  values, response size limit or request timeout.
- **OQ-GW-2 — Pinned versions.** The sources cite Envoy Gateway v1.10 and
  v1.10.0, Envoy v1.40.1 and cert-manager v1.20.0 as references but state that
  they specify "a mechanism, not a tested version pair". No pinned
  Envoy Gateway, egctl, Envoy, bootstrap or cert-manager version or artifact
  digest is chosen.
- **OQ-GW-3 — Exact exemption list.** Design §4 exempts "fixed SkyOAuth
  authentication/session endpoints" without listing them. Open: whether the
  issuer host is an enrolled host subject to containment; whether
  `/_skyoauth/oidc/backchannel-logout`, `/oauth/token`, `/oauth/revoke` and
  `/.well-known/*` are exempt or keep Cookie and Set-Cookie removal; and,
  per exempt endpoint, which cookies and headers are retained.
- **OQ-GW-4 — Verified SkyOAuth backend identity.** The exemption requires
  routing to the "independently verified SkyOAuth backend identity", but how
  that identity is expressed and verified (Service and namespace, UID, peer
  certificate identity or cluster) is not specified.
- **OQ-GW-5 — Literal filter chain and assertion-header stripping.** The
  sources fix ordering constraints but not the pinned adapter's per-route
  filter list, or at which stage client-supplied identity and assertion
  headers are removed relative to ext_authz. The assertion header name is also
  open (OQ-API-10, OQ-TP-11).
- **OQ-GW-6 — Guarded inventory kinds.** "Supported security/traffic
  extensions" and "backend identity/routing configuration" are not enumerated
  as Kubernetes kinds for the admission guard.
- **OQ-GW-7 — Digest algorithm and canonical form.** Only `target_sha256` has a
  defined algorithm and encoding. The hash, encoding and canonical
  serialization of input, plan, expected and observed gateway, recovery,
  dependency-contract and dependency-evidence digests, and the list of
  "documented nonsemantic noise", are not specified.
- **OQ-GW-8 — Gate scope: bundle or origin (contradiction).** `ApplicationRoute` has a
  `route_bundle_id` and `RouteBundle` has one `application_origin_id`, so an
  origin may have several bundles. Design §4.1 and §4.2 say `begin` closes
  "the entire affected origin bundle" and "unaffected bundles need not stop",
  while design §4.2, ADR-020 and T00.6 describe the interruption as
  origin-wide ("every cookie stream on the origin"). Whether one bundle's apply
  closes another bundle on the same origin is unresolved.
- **OQ-GW-9 — Required authority for compensation.** Compensation needs
  "enabled required operator authority", but the sources do not say whether
  this is the preparer, the approver or both, or what happens if the preparing
  `client_admin` is disabled during `aborting`.
- **OQ-GW-10 — Cancel outside `applying`.** Cancel is defined for an
  `applying` attempt and is idempotent for `abort_required` or `aborting`. Its
  result for `recovery_required` or `idle` is not stated.
- **OQ-GW-11 — Helper bounds.** The helper's resource, time and output limits
  are required but not given numerically.
- **OQ-GW-12 — "Enrolled host".** Design §4 scopes containment to "an enrolled
  host" while design §4 and §4.2 describe two enrollments: `ApplicationOrigin`
  ownership and protected-scope enrollment. Whether an origin can be
  registered without an enrolled protected scope (for example before the M3
  controller is installed), and whether containment applies then, is not
  stated.
- **OQ-GW-13 — Supported exact-mode usages.** The sources require exact mode
  for "supported policy/backend" credentials but do not enumerate which
  policy or backend Secret usages v0.1 supports.

- **OQ-GW-14 — Admission exception list (contradiction).** Design §4.2
  "Protected scope" says that besides the TLS-renewer update and sealed
  retirement DELETE, "only narrow status-only updates by the existing gateway
  controller are exempt". Design §4.2 "Guard coverage" and tasks §3 also allow
  the cert-manager temporary-key CREATE/DELETE class. GW-056 lists all four;
  the earlier "only" sentence should be reconciled.
