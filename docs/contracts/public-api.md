# Public, private and operator API boundaries

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Tasks covered:** T00.1.
- **Derived from:** [design](../skyoauth-design.md) §1, §3, §4, §4.1, §4.2,
  §5.1, §5.1.1, §5.2, §5.2.1, §5.2.2, §5.6, §5.7, §6, §6.1, §6.1.1, §6.2,
  §7.1, §7.2, §7.3, §7.4; [tasks](../skyoauth-tasks.md) §2 "Endpoint matrix",
  §2 "Exchange selection and scope", §3, §11 (ADR-001, ADR-004, ADR-007,
  ADR-010, ADR-013, ADR-020).
- **Related contracts:** [errors-retry.md](errors-retry.md),
  [token-profiles.md](token-profiles.md),
  [identity-registry.md](identity-registry.md).

This document freezes which endpoints exist, who may call them, on which
listener, and what each one must and must not do. It restates the design and
the tasks endpoint matrix; it adds no new behavior. Where the sources leave a
detail open, the detail is listed under [Open questions](#open-questions) and
is not decided here.

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119,
RFC 8174) when they appear in capitals. Each normative requirement has an ID
(`API-nnn`) so that tests can cite it.

## 1. Listener classes

Every endpoint belongs to exactly one listener class.

| Class           | Reached by                                                                            | Authentication of caller                                         | Source                  |
| --------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ----------------------- |
| Public issuer   | Any client over TLS on the canonical issuer origin                                    | Endpoint-specific (proof, PKCE, refresh credential, flow cookie) | design §4, §5.2, §5.7   |
| App origin      | Browser on a registered `ApplicationOrigin`, via Envoy                                | Endpoint-specific (flow cookie, session cookie, Origin, CSRF)    | design §4, §5.1         |
| Private gateway | Authenticated Envoy (or reviewed ForwardAuth adapter)                                 | Authenticated private channel                                    | design §4, §6; tasks §2 |
| Private policy  | Registered `ResourceServerChecker`                                                    | mTLS identity bound to one resource server and a tenant set      | design §6.1, §6.1.1     |
| Private trust   | Authenticated checker or gateway trust consumer                                       | Authenticated private channel rooted in deployment trust         | design §6.2             |
| Private control | Registered route-controller, credential-provisioner or protection-controller identity | mTLS identity with explicit scope                                | design §4.2             |
| Operator        | Independent operator (`adm_*`)                                                        | Registered mTLS credential plus active local role, on every call | design §7.2             |
| Local           | Deployment operator on the service host                                               | Local command or Unix socket plus independent signed proof       | design §7.2             |

- **API-001** Private gateway, policy, trust, control and operator listeners
  MUST NOT be exposed as public gateway routes. External clients MUST NOT be
  able to reach them. (design §3, §4; tasks §2 note under the endpoint matrix)
- **API-002** Operator endpoints MUST check the active local credential and
  role on every call. A certificate alone, OIDC roles, groups, emails, human
  sessions and WIF credentials MUST NOT grant operator authority. (design §7.2)
- **API-003** Every write on the operator API MUST use validation, an optimistic
  revision check and an audit record. High-frequency observation refreshes are
  operational telemetry and MUST NOT create policy-change audit events.
  (tasks §2 note under the endpoint matrix; design §4.2)
- **API-004** Grouped sibling paths in the tables below share the full prefix
  that precedes them, as in the tasks endpoint matrix. (tasks §2)
- **API-005** No endpoint in this document proxies application request or
  response bodies. ConnectRPC calls, streams and downloads MUST flow from Envoy
  directly to the application. (design §1, §4)

## 2. Public issuer endpoints

All paths are on the canonical issuer origin (for example
`https://identity.example.com`). See
[identity-registry.md §2](identity-registry.md#2-issuer) for the issuer.

| Method    | Path                                      | Caller                                                                   | Milestone             | Required behavior                                                                                                                                    | Source                               |
| --------- | ----------------------------------------- | ------------------------------------------------------------------------ | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| GET       | `/.well-known/oauth-authorization-server` | OAuth clients                                                            | M2                    | Stable metadata; advertise implemented grants and profiles only                                                                                      | tasks §2 matrix; design §2 C01       |
| GET       | `/.well-known/jwks.json`                  | Verifiers                                                                | M2                    | Public access-token signer keys with rotation overlap; never internal assertion keys                                                                 | design §4, §6, §6.2; tasks §2 matrix |
| GET       | `/oauth/authorize`                        | Native public client, through the system browser                         | M4                    | Resolve registered client and tenant; validate redirect, PKCE, audience and scopes; create `OAuthAuthorizationRequest`; set `__Host-skyoauth_native` | design §5.2; tasks §2 matrix         |
| GET       | `/oauth/callback`                         | Upstream provider, through the initiating native-flow browser            | M4                    | Require native flow cookie plus state and transcript; bind verified human; rotate the flow cookie before confirmation                                | design §5.2; tasks §2 matrix         |
| GET, POST | `/oauth/confirm`                          | Browser holding a completed native transaction and rotated issuer cookie | M4                    | Show server-derived comparison, loopback URI and port, session duration; explicit match acknowledgement and approve or deny                          | design §5.2, §5.2.1; tasks §2 matrix |
| POST      | `/oauth/token`                            | Rust CLI, generic OAuth clients, WIF callers                             | M2 (WIF), M4 (native) | Supported grants and proof roles only (§2.1); registered audience assignment; profile-specific credentials                                           | design §5.2.2, §5.7; tasks §2 matrix |
| POST      | `/oauth/revoke`                           | Registered native client with its refresh credential                     | M4                    | Revoke the matching refresh family and associated authentication; non-enumerating response                                                           | design §5.2.2; tasks §2 matrix       |

### 2.1 Token endpoint grant profiles

| Profile                                    | `grant_type`                                              | Proof parameters                                                                                 | Rejected parameters                                             | Output                                                                      | Source              |
| ------------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------- |
| WIF direct (RFC 8693)                      | `urn:ietf:params:oauth:grant-type:token-exchange`         | `subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`                       | `actor_token`                                                   | `wif` access token; `sub` is the verified workload; no `act`                | design §5.6, §5.7   |
| WIF service delegation (private extension) | `urn:skyoauth:params:oauth:grant-type:service-delegation` | `actor_token`, `actor_token_type=urn:ietf:params:oauth:token-type:jwt`                           | `subject_token`                                                 | `wif` access token; `sub` is the grant's service; `act.sub` is the workload | design §5.6, §5.7   |
| Native authorization code                  | `authorization_code`                                      | One-time SkyOAuth code, PKCE verifier, exact redirect URI, `client_id`                           | See OQ-API-4                                                    | `human_cli` access token (<= 300 s) and one rotating refresh credential     | design §5.2, §5.2.2 |
| Native refresh                             | `refresh_token`                                           | `refresh_token`, `client_id`, optional narrowing `scope`, optional `skyoauth_refresh_request_id` | `audience`, `resource`, subject overrides; duplicate parameters | Successor refresh credential and fresh `human_cli` access token             | design §5.2.2       |

WIF exchange requirements (design §5.7; tasks §2 "Exchange selection and
scope"):

- **API-010** Both WIF profiles MUST require exactly one
  `skyoauth_trust_source`, exactly one `skyoauth_grant_id` and exactly one API
  `audience`, with optional `scope`. Requests MUST be form-encoded.
- **API-011** `skyoauth_trust_source` and `skyoauth_grant_id` MUST be generated
  immutable IDs. Tenant-local display names MUST be rejected as selectors.
  (design §5.7, §7.4; tasks A49)
- **API-012** The service MUST load the selected source and grant only as
  untrusted candidates, require the same tenant and the expected grant mode,
  and MUST NOT reveal cross-tenant existence on failure.
- **API-013** The assertion MUST be verified only at the selected source. The
  service MUST NOT select a verifier by `iss`, `kid` or other token content and
  MUST NOT try another source, cluster or key set after a failure. (design §3.1,
  §5.4; tasks T11.7)
- **API-014** Only enabled bindings for the selected source that map to the
  grant's actor and appear in the grant's `allowed_binding_ids` are evaluated.
  At least one MUST match. Matching bindings for other actors MUST NOT deny or
  authorize the request. Several eligible matches MUST select one by stable ID
  order for provenance and MUST NOT union permissions.
- **API-015** Requests MUST NOT carry subject, target, tenant or mode
  overrides. Duplicate parameters, missing selectors, profile mismatch,
  unsupported `resource` and unsupported requested token type MUST be denied.
- **API-016** Omitted `scope` MUST use only the grant's explicit nonempty
  `default_scopes`; otherwise the request fails with `invalid_scope`. An
  explicit empty or excessive scope MUST be denied, not trimmed or widened.
- **API-017** Success MUST return `access_token`, `token_type=Bearer`,
  `expires_in`, an explicit `scope` and
  `issued_token_type=urn:ietf:params:oauth:token-type:access_token`, with
  `Cache-Control: no-store`. WIF responses MUST NOT include a refresh token.
- **API-018** The service-delegation grant MUST NOT be advertised as standard
  RFC 8693 two-token delegation or as an IANA-registered grant. (design §5.7;
  tasks T00.9)

Native token requirements (design §5.2, §5.2.2):

- **API-020** Authorization codes MUST be single-use across replicas and bound
  to the exact client, redirect URI, PKCE challenge, audience, scopes and
  verified authentication. Redemption MUST match the exact redirect URI chosen
  before authorization.
- **API-021** A successful code exchange MUST issue an access token capped at
  300 seconds and exactly one refresh credential belonging to one
  `CLIRefreshFamily`. Refresh credentials MUST NOT be upstream refresh tokens.
- **API-022** Refresh MUST work without `skyoauth_refresh_request_id`. Without
  it, the service performs plain one-time rotation; reuse of a consumed
  credential revokes the family.
- **API-023** When `skyoauth_refresh_request_id` is present it MUST be an
  unpadded base64url encoding of 256 random bits. Empty, malformed or duplicate
  values MUST fail with `invalid_request`, not be ignored.
- **API-024** Refresh MUST recheck the client, audience assignment, principal,
  `HumanAccessPolicy`, authentication, epochs and family deadlines, and MUST
  NOT exceed the originally approved scopes. Refresh MUST NOT reset the
  family's absolute deadline or `auth_time`.
- **API-025** Bounded exact-retry behavior follows design §5.2.2 and is frozen
  in [errors-retry.md §6](errors-retry.md#6-retry-budgets-and-client-behavior).

Native authorization and confirmation requirements (design §5.2, §5.2.1):

- **API-030** `/oauth/authorize` MUST resolve the tenant only from the globally
  unique registered `client_id`, and MUST validate the redirect, audience and
  scopes against the client registration and the audience assignment.
- **API-031** Redirect URIs MUST be IP-loopback redirects registered for the
  client. (design §5.2, §10.3; tasks T40.1)
- **API-032** `/oauth/callback` on the issuer is the only upstream callback for
  native flows. App-origin and native flow cookies and transaction kinds MUST
  NOT be interchangeable.
- **API-033** `/oauth/confirm` MUST require the rotated native flow cookie and a
  completed server-side authentication. A transaction ID, an app cookie, a
  principal in the URL or a live upstream SSO session alone MUST NOT approve a
  request.
- **API-034** The confirmation POST MUST require the exact issuer `Origin`,
  CSRF, anti-framing, the matching rotated flow binding, the request digest,
  the principal and an unexpired provider epoch, plus the explicit "matches my
  CLI" acknowledgement.
- **API-035** Every new loopback authorization MUST require explicit approval.
  Prior consent or existing SSO MUST NOT auto-approve. Denial or expiry MUST
  create no code.
- **API-036** A new native start MUST invalidate the previous native cookie
  slot. A stale or conflicting tab MUST show a superseded-login error and MUST
  NOT approve or redirect to the replacement flow.
- **API-037** The comparison value MUST be derived from the stored validated
  transaction (comparison v1, design §5.2.1), never echoed from a request
  parameter.

Revocation (design §5.2.2; tasks T40.15):

- **API-040** `/oauth/revoke` MUST check the token-to-client binding, revoke the
  refresh family and its associated authentication, and return a
  non-enumerating response.
- **API-041** `/oauth/revoke` MUST NOT depend on the application route gate
  (§8). Its client, token and store checks remain mandatory.

## 3. Application-origin endpoints

All paths are served on each registered `ApplicationOrigin` (for example
`https://app.example.com`). They are fixed SkyOAuth routes, routed to the
verified SkyOAuth backend identity.

| Method | Path                                 | Caller                                   | Milestone | Required behavior                                                                                                                         | Source                       |
| ------ | ------------------------------------ | ---------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| GET    | `/_skyoauth/login`                   | Browser on registered origin             | M3        | Resolve tenant and provider from the active pinned `ApplicationOriginVersion`; create browser-bound transaction and validated return path | design §5.1; tasks §2 matrix |
| GET    | `/_skyoauth/callback`                | Upstream, through the initiating browser | M3        | Require app flow cookie plus state, nonce, PKCE, provider, epoch and origin; consume once                                                 | design §5.1; tasks §2 matrix |
| GET    | `/_skyoauth/session`                 | Browser                                  | M3        | Safe session and principal metadata plus session-bound CSRF token only; `no-store`                                                        | design §5.1; tasks §2 matrix |
| POST   | `/_skyoauth/logout`                  | Browser                                  | M3        | Exact `Origin` and CSRF; revoke session and authentication context; expire cookie                                                         | design §5.1; tasks §2 matrix |
| POST   | `/_skyoauth/oidc/backchannel-logout` | Configured upstream IdP                  | Optional  | Verify signature, issuer, audience, events, time and replay; target sessions by indexed provider, subject and sid                         | design §5.1; tasks §2 matrix |

| Cookie                    | Set by                             | Attributes                                                     | Purpose                                   | Source      |
| ------------------------- | ---------------------------------- | -------------------------------------------------------------- | ----------------------------------------- | ----------- |
| `__Host-skyoauth_login`   | `/_skyoauth/login` (app origin)    | Secure; HttpOnly; Path=/; SameSite=Lax; no Domain; short-lived | Browser flow binding for app login        | design §5.1 |
| `__Host-skyoauth_session` | `/_skyoauth/callback` (app origin) | Secure; HttpOnly; Path=/; SameSite=Lax; no Domain              | Opaque session ticket; not an OAuth token | design §5.1 |
| `__Host-skyoauth_native`  | `/oauth/authorize` (issuer origin) | Same secure host-only attributes; short transaction lifetime   | Native flow binding; rotated at callback  | design §5.2 |

- **API-050** The app origin, tenant and provider MUST be resolved from the
  registered origin and `TenantLoginState`, never from a `tenant` query
  parameter or an untrusted forwarded header. Unknown, ambiguous, spoofed or
  disabled origins MUST be denied before any redirect. (design §4)
- **API-051** Return locations MUST be normalized same-origin relative paths
  validated against the stored allowlist. Protocol-relative URLs, backslashes,
  traversal and prefix-confusion forms MUST be rejected. (design §4)
- **API-052** The callback MUST require both the one-time state and the
  initiating browser's matching flow cookie. Wrong or missing browser binding
  MUST deny without creating, replacing or linking a session. (design §5.1)
- **API-053** Unsafe cookie-authenticated calls, including Connect unary POST
  and logout, MUST require the exact `Origin` and the CSRF token in
  `X-SkyOAuth-CSRF`. (design §5.1)
- **API-054** `GET /_skyoauth/session` MUST NOT return upstream credentials,
  OAuth tokens, operator roles or internal assertions. (design §5.1; tasks T31.3)
- **API-055** Cookies MUST use host-only `__Host-` names with Secure, HttpOnly
  and Path=/, and MUST NOT broaden Domain. An issuer host distinct from the app
  host MUST NOT share cookies with it. (design §4)
- **API-056** Duplicate or ambiguous SkyOAuth cookies MUST be rejected, not
  resolved by choosing a copy. (design §4)

## 4. Private gateway endpoints

| Transport | Endpoint                                    | Caller                      | Milestone             | Required behavior                                                                                                                                          | Source                         |
| --------- | ------------------------------------------- | --------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| gRPC      | `envoy.service.auth.v3.Authorization/Check` | Authenticated private Envoy | M2 bearer, M3 session | Bearer: verify and keep the original access JWT. Session: validate cookie, Origin and CSRF, then return a `human_session` internal assertion. Fail closed. | design §4, §6; tasks §2 matrix |
| GET       | `/internal/auth/check`                      | Trusted ForwardAuth adapter | Optional              | Equivalent typed decision adapter with reviewed deployment enforcement; never public                                                                       | tasks §2 matrix, T32.9         |

- **API-060** The Check service MUST receive only bounded request metadata,
  never bodies. (design §1, §4; tasks T25.2)
- **API-061** Bearer calls MUST carry their original SkyOAuth access JWT to the
  backend. Cookie calls MUST cause SkyOAuth to return a short-lived signed
  internal `human_session` assertion for a private, overwritten backend header.
  (design §4)
- **API-062** Public bearer ingress MUST reject internal assertions. Mixed
  credentials (cookie plus bearer, bearer plus internal assertion) MUST be
  denied. (design §4, §6; tasks A10)
- **API-063** Every non-SkyOAuth route on an enrolled host MUST remove all
  `Cookie` fields and `X-SkyOAuth-CSRF` before forwarding and all
  `Set-Cookie` response fields, independently of whether Check runs. The
  detailed containment contract is T00.5 and is out of scope here. (design §4)
- **API-064** Auth-service transport failure MUST map to a fail-closed 503, not
  an allow. (design §4.2; tasks T32.6)
- **API-065** RPC failures MUST be typed errors, never an IdP HTML redirect.
  Status mapping is frozen in
  [errors-retry.md §2](errors-retry.md#2-status-classes). (design §4)

## 5. Private policy and trust endpoints

| Method | Path                                  | Caller                                                              | Milestone                        | Required behavior                                                                                                                                         | Source                               |
| ------ | ------------------------------------- | ------------------------------------------------------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| POST   | `/internal/v1/policy/check`           | Registered `ResourceServerChecker`                                  | M2 (WIF), M3 (session), M4 (CLI) | Exact profile, action and resource checks; returns allow, deny or unavailable; optional stream admission from an unexpired `human_session` assertion only | design §6.1, §6.1.1; tasks §2 matrix |
| POST   | `/internal/v1/policy/recheck-session` | The same checker that established the stream                        | M3                               | One item or a batch of at most 100 items and 64 KiB; independent per-item allow, deny or unavailable and deadline                                         | design §6.1.1; tasks §2 matrix       |
| POST   | `/internal/v1/policy/close-session`   | The same currently authorized checker, with bound nonce and context | M3                               | Idempotent single or batch release; atomic `closed_at` and quota release; no live session, assertion or lease required; returns no lease                  | design §6.1.1; tasks §2 matrix       |
| GET    | `/internal/v1/assertion-jwks`         | Authenticated checker or gateway trust consumer                     | M3                               | Versioned signer-group public key set with version or ETag; eligible standby keys already present; separate from the issuer JWKS                          | design §6.2; tasks §2 matrix         |

Policy check (design §6.1):

- **API-070** The caller MUST be authenticated as a `ResourceServerChecker`
  bound to one registered resource-server audience and an explicit tenant set,
  not as the token's subject or delegated service. A checker MUST NOT act for
  another audience.
- **API-071** A check request MUST carry exactly one access JWT or internal
  assertion plus canonical action and resource coordinates. Request binding is
  retained for internal assertions. Input MUST be bounded and MUST NOT be
  logged as token material or application payload.
- **API-072** The service MUST look up the persisted `ResourceAction` for the
  resource server. Unknown action, resource or caller, and wrong tenant or
  audience MUST deny.
- **API-073** The response MUST be a request-bound allow, deny or unavailable,
  with the checked revision when available and a decision ID, served
  `no-store`. It MUST NOT be a new token or a reusable blanket permission.
- **API-074** Store, checker or transient route-observation failure MUST return
  typed unavailable without an allow. Unavailable is not an authentication
  failure.
- **API-075** Direct workload credentials with no target service MUST be fully
  supported. (design §6.1; tasks A45)

Stream continuation (design §6.1.1):

- **API-080** Stream admission MUST require an unexpired `human_session`
  assertion, a stream-capable action and a fresh backend stream-instance nonce.
  Session references alone or an expired assertion MUST NOT open a
  continuation. One assertion `jti` MUST initialize at most one continuation.
- **API-081** Admission returns an opaque continuation ID, `lease_seconds` and
  `authorized_until`. The continuation ID MUST NOT be exposed to browser code
  or accepted on a public bearer path.
- **API-082** Recheck MUST accept the continuation ID and bound nonce and
  context from the same registered mTLS checker. Renewal after
  `authorized_until` or the absolute deadline MUST deny.
- **API-083** Recheck and close batches MUST be at most 100 items and 64 KiB,
  under one checker identity. Duplicate IDs and malformed or oversized
  envelopes MUST be rejected before any write. Each item gets an independent
  result; no batch-wide allow exists.
- **API-084** Close MUST set `closed_at` and release quota exactly once. A
  matching repeat MUST succeed without another decrement. Unknown IDs and
  mismatched checker, nonce or context MUST receive the same non-enumerating
  not-found result.

Internal assertion keys (design §6.2):

- **API-090** `/internal/v1/assertion-jwks` MUST serve only internal assertion
  public keys, with a disjoint kid namespace from the issuer JWKS. Verifiers
  MUST NOT cache it longer than 60 seconds and MUST NOT extend freshness on
  error.
- **API-091** An unknown kid MAY trigger one bounded, rate-limited,
  single-flight refetch of this fixed endpoint, with negative caching. A
  token-selected URL or key MUST NOT be used.

## 6. Private route-control and credential endpoints

All callers are registered mTLS identities with explicit gateway, origin or
Secret scope. Filters and cursors MUST NOT broaden scope (**API-100**). None of
these identities has signer, WIF or human authority (**API-101**). (design
§4.2; tasks §2 matrix)

| Method | Path                                                              | Caller                                                            | Required behavior                                                                                                                                                             | Source                       |
| ------ | ----------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| GET    | `/internal/v1/route-bundles`                                      | Scoped route controller                                           | Bounded cursor-paginated discovery of pending preparations and prepared, approved and active work                                                                             | design §4.2; tasks §2 matrix |
| GET    | `/internal/v1/route-bundles/{id}`                                 | Scoped route controller                                           | Scoped preparation input, prepared plan, durable generations, current attempt, deadline, reason, journal revision, recovery inventory, epoch and sequence; no Secret payloads | design §4.2; tasks §2 matrix |
| POST   | `/internal/v1/route-bundles/{id}/preparations/{operation}/result` | Scoped preparation worker                                         | Bind the result to the exact pending input and preconditions; finalize one immutable version and server plan digest; no gateway writes or approval                            | design §4.2; tasks §2 matrix |
| POST   | `/internal/v1/route-bundles/{id}/claim`                           | Scoped route controller                                           | Allocate a durable fenced ownership epoch and lease; no approval and no observation-age reset                                                                                 | design §4.2; tasks §2 matrix |
| POST   | `/internal/v1/route-bundles/{id}/transitions`                     | Current scoped owner                                              | Mode-, approval- and security-checked transitions (table below)                                                                                                               | design §4.2; tasks §2 matrix |
| POST   | `/internal/v1/route-bundles/{id}/observations`                    | Current scoped owner                                              | Per-proxy evidence bound to deployment version, attempt and target kind, serving generation, epoch and increasing sequence                                                    | design §4.2; tasks §2 matrix |
| GET    | `/internal/v1/credential-dependencies`, `/{dependency}`           | Scoped credential provisioner or designated protection reconciler | Bounded nonsecret hold, lifecycle, guard and retirement status; foreign holds opaque but counted                                                                              | design §4.2; tasks §2 matrix |
| POST   | `/internal/v1/credential-dependencies`                            | Scoped credential provisioner                                     | Register actual object metadata for cleanup; existing held, retiring or retired state returned unchanged; grants no use authority                                             | design §4.2; tasks §2 matrix |
| POST   | `/internal/v1/credential-dependencies/{dependency}/retirements`   | Scoped credential provisioner                                     | Zero-hold check under row lock; record `credential_retirement` and seal the UID; no deletion before exact guard acknowledgement                                               | design §4.2; tasks §2 matrix |
| GET    | `/internal/v1/credential-protection-scopes`, `/{scope}`           | Designated protection-controller identity                         | Discover current and pending verification, protection, maintenance and decommission work                                                                                      | design §4.2; tasks §2 matrix |
| POST   | `/internal/v1/credential-protection-scopes/{scope}/transitions`   | Designated protection-controller identity                         | `claim`, `verify_scope`, `protect_ack`, `release_ack`, `delete_observed`, `decommission_observed` bound to verified registration, epoch, sequence and object identity         | design §4.2; tasks §2 matrix |

Route-bundle transitions (design §4.2; tasks §3 "Route preparation, approval
and recovery"):

| Transition               | Allowed from                                                                                  | Approval mode required | Effect                                                                                                                               | Source      |
| ------------------------ | --------------------------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ----------- |
| `begin`                  | `idle`; or `recovery_required` only for a freshly approved supersession of that exact attempt | `gateway_apply`        | Closes the origin gate before any apply; persists `apply_deadline`, abort source and write journal                                   | design §4.2 |
| `activate`               | `applying` (current forward attempt)                                                          | `gateway_apply`        | Requires complete matching observations before `apply_deadline`; atomically selects pins and clears only approved `reenable_targets` | design §4.2 |
| `activate_registry_only` | Eligible gate with complete observations no older than 30 s                                   | `registry_only`        | Switches registry pins without writes or gate closure; keeps `deployment_version_id` and original sample ages                        | design §4.2 |
| `abort`                  | `applying` (recorded nonretryable failure or deadline) or `abort_required`                    | `gateway_apply`        | Moves to `aborting`; compensation limited to the exact `abort_plan` until `abort_until`                                              | design §4.2 |
| `complete_abort`         | `aborting`                                                                                    | `gateway_apply`        | Requires settled writes and fresh complete evidence of the exact target; `cleanup_to_closed` never opens the gate                    | design §4.2 |

- **API-110** A transition called with the wrong approval mode MUST reject
  without changing the gate or performing writes. (design §4.2)
- **API-111** Old epochs and replayed reports MUST NOT reopen a gate. Exact
  result and completion retries MUST return the recorded result. (design §4.2)
- **API-112** A preparation result MUST be bound to its pending operation;
  contradictory or stale results MUST reject. A caller-supplied digest MUST
  NOT be trusted. (design §4.2; tasks T14.9)

## 7. Operator API and approval boundaries

### 7.1 Endpoints

All paths are under the private operator listener. Roles are defined in
[identity-registry.md §5.2](identity-registry.md#52-operator-identities-and-roles).

| Methods          | Path                                                                                       | Role                                                                   | Source                         |
| ---------------- | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------ |
| GET, POST, PATCH | `/admin/v1/tenants`                                                                        | Instance `security_admin`                                              | tasks §2 matrix; design §7.2   |
| GET, POST, PATCH | `/admin/v1/operators`, `/admin/v1/operator-roles`                                          | Instance `security_admin`                                              | tasks §2 matrix                |
| GET, POST, PATCH | `/admin/v1/resource-servers`                                                               | Instance `security_admin`                                              | tasks §2 matrix; design §7.1   |
| GET, POST, PATCH | `/admin/v1/resource-servers/{id}/tenant-assignments`, `/checker-identities`, `/actions`    | Instance `security_admin`                                              | tasks §2 matrix; design §7.1   |
| POST, PATCH      | `/admin/v1/application-origin-registrations`                                               | Instance `security_admin`                                              | tasks §2 matrix; design §4     |
| GET, POST, PATCH | `/admin/v1/route-controller-identities`                                                    | Instance `security_admin`                                              | tasks §2 matrix                |
| GET, POST, PATCH | `/admin/v1/credential-provisioners`                                                        | Instance `security_admin`                                              | tasks §2 matrix                |
| GET, POST, PATCH | `/admin/v1/credential-protection-scopes`                                                   | Instance `security_admin`                                              | tasks §2 matrix                |
| GET, PATCH       | `/admin/v1/instance-capacity-policy`                                                       | Instance `security_admin`                                              | tasks §2 matrix; design §6.1.1 |
| GET, POST, PATCH | `/admin/v1/internal-assertion-keys`                                                        | Instance `security_admin`                                              | tasks §2 matrix; design §6.2   |
| GET, POST, PATCH | `/admin/v1/tenants/{tenant}/principals`, `/services`                                       | Tenant `trust_admin`                                                   | tasks §2 matrix                |
| GET, POST, PATCH | `/admin/v1/tenants/{tenant}/trust-sources`, `/keysets`, `/bindings`, `/grants`             | Tenant `trust_admin`                                                   | tasks §2 matrix                |
| GET, POST, PATCH | `/admin/v1/tenants/{tenant}/oauth-clients`, `/human-access-policies`                       | Tenant `client_admin`                                                  | tasks §2 matrix                |
| GET, PATCH       | `/admin/v1/tenants/{tenant}/application-origins/{id}`                                      | Tenant `client_admin`                                                  | tasks §2 matrix                |
| GET, PATCH       | `/admin/v1/tenants/{tenant}/application-origins/{id}/capacity-policy`                      | Tenant `client_admin`                                                  | tasks §2 matrix                |
| GET, POST, PATCH | `/admin/v1/tenants/{tenant}/application-origins/{id}/routes`                               | Tenant `client_admin`                                                  | tasks §2 matrix                |
| POST             | `/admin/v1/tenants/{tenant}/application-origins/{id}/disable`, `/routes/{route}/disable`   | Tenant `client_admin` (see OQ-API-6)                                   | tasks §2 matrix; design §4.2   |
| GET, POST        | `/admin/v1/tenants/{tenant}/route-bundles`                                                 | Tenant `client_admin`; instance `security_admin` may read              | tasks §2 matrix                |
| GET              | `/admin/v1/tenants/{tenant}/route-bundles/{id}`                                            | Tenant `client_admin` within bundle scope or instance `security_admin` | tasks §2 matrix; design §4.2   |
| POST             | `/admin/v1/tenants/{tenant}/route-bundles/{id}/preparations`                               | Tenant `client_admin`                                                  | tasks §2 matrix; design §4.2   |
| POST             | `/admin/v1/tenants/{tenant}/route-bundles/{id}/versions/{version}/approve`                 | Instance `security_admin`                                              | tasks §2 matrix; design §4.2   |
| POST             | `/admin/v1/tenants/{tenant}/route-bundles/{id}/attempts/{attempt}/cancel`                  | Tenant `client_admin` within scope or instance `security_admin`        | tasks §2 matrix; design §4.2   |
| POST             | `/admin/v1/tenants/{tenant}/route-bundles/{id}/approvals/{approval}/revoke`                | Instance `security_admin` only                                         | tasks §2 matrix; design §4.2   |
| GET, POST, PATCH | `/admin/v1/tenants/{tenant}/human-providers`, `/human-links`                               | Tenant `provider_admin`                                                | tasks §2 matrix                |
| GET              | `/admin/v1/tenants/{tenant}/login-state`                                                   | Authorized scoped operator (see OQ-API-7)                              | tasks §2 matrix                |
| GET, PATCH       | `/admin/v1/tenants/{tenant}/human-enrollment-policy`                                       | Tenant `provider_admin`                                                | tasks §2 matrix; design §5.1.1 |
| POST             | `/admin/v1/tenants/{tenant}/human-enrollment-policy/resume`                                | Tenant `provider_admin`                                                | tasks §2 matrix; design §5.1.1 |
| POST             | `/admin/v1/tenants/{tenant}/human-providers/{id}/credential-rotations`                     | Tenant `provider_admin`                                                | tasks §2 matrix; design §7.3   |
| POST             | `/admin/v1/tenants/{tenant}/human-provider-switches`, `/{plan}/commit`, `/{plan}/rollback` | Tenant `provider_admin`                                                | tasks §2 matrix; design §7.3   |
| POST             | `/admin/v1/tenants/{tenant}/imports`                                                       | Every role required by every included section                          | tasks §2 matrix; design §7.3   |
| GET              | `/admin/v1/tenants/{tenant}/audit`                                                         | Tenant `auditor`                                                       | tasks §2 matrix                |

| Interface                                   | Caller                                            | Required behavior                                                                               | Source                       |
| ------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------- |
| Local command or Unix socket on the service | Deployment operator plus independent signed proof | Bootstrap and recovery verifier; challenge bound to instance, operation, arguments and revision | design §7.2; tasks §2 matrix |
| `skyoauth-operator` workstation command     | Independent operator or recovery key holder       | Private mTLS client and offline recovery signer; private keys never copied into a pod           | design §7.2; tasks §2 matrix |

### 7.2 Approval boundaries

| Operation                                                  | Who may perform it                                            | What it MUST NOT do                                                                                                         | Source                       |
| ---------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| Stage origin or route configuration (PATCH, import)        | Tenant `client_admin`                                         | Change active pins, origin ownership or active values                                                                       | design §4.2; tasks §2 matrix |
| Request route-bundle preparation                           | Tenant `client_admin`                                         | Supply a trusted expected digest; create an approvable version before the scoped worker finalizes it                        | design §4.2                  |
| Approve a prepared route-bundle version                    | Instance `security_admin`                                     | Approve a pending or failed preparation; change the activation mode; authorize arbitrary manifests or a blanket active flag | design §4.2                  |
| Cancel an applying attempt                                 | Tenant `client_admin` in scope or instance `security_admin`   | Write to the gateway; extend deadlines; cancel a successor attempt                                                          | design §4.2                  |
| Revoke a route-bundle approval                             | Instance `security_admin` only                                | Change the immutable plan; roll back a completed activation                                                                 | design §4.2                  |
| Security-disable an origin or route                        | Tenant `client_admin` per tasks matrix                        | Be cleared by PATCH or import; only explicit `reenable_targets` in a freshly approved activation clear it                   | design §4.2; tasks §2 matrix |
| Enroll application-origin ownership                        | Instance `security_admin`                                     | Be claimed or reassigned by a tenant administrator                                                                          | design §4                    |
| Register audiences, assignments, checkers, actions         | Instance `security_admin`                                     | Be self-assigned by tenants                                                                                                 | design §7.1                  |
| Switch, roll back or initially activate the human provider | Tenant `provider_admin` through the plan and commit operation | Be performed by PATCH, import, reload or delete                                                                             | design §7.3                  |
| Rotate a provider credential only                          | Tenant `provider_admin`                                       | Change issuer, upstream `client_id`, auth method, callbacks or assurance; advance auth epochs                               | design §7.3                  |
| Resume human enrollment after a switch                     | Tenant `provider_admin`                                       | Be cleared by elapsed time, import, policy edit, restart or rollback                                                        | design §5.1.1                |
| Enroll or rotate internal assertion keys                   | Instance `security_admin`                                     | Be self-registered by replicas or public clients                                                                            | design §6.2                  |
| Break-glass recovery                                       | Local verifier plus independent offline recovery key          | Edit WIF policy, reassign audiences or mint tokens                                                                          | design §7.2                  |

- **API-120** Roles MUST NOT inherit one another. One operator MAY hold several
  roles only by explicit assignment. (design §7.2)
- **API-121** A combined import MUST be accepted only if the actor holds every
  role required by every mutation; otherwise the whole import MUST be rejected.
  Active-provider state MUST NOT be writable through import. (design §7.3)
- **API-122** A controller credential MUST NOT substitute for the preparer or
  approver role. (design §4.2)
- **API-123** Route-bundle admin reads MUST expose no write journal, manifests,
  xDS, private worker inputs or Secret material, and MUST grant no write
  authority. (design §4.2)
- **API-124** Device-flow and impersonation-activation endpoints MUST be absent
  in v0.1. Adding them requires a later reviewed feature contract. (tasks §2
  note under the endpoint matrix; design §5.6)

## 8. Independence from the application route gate

The application route gate closes new cookie-authenticated application
requests and continuation admissions during gateway apply, compensation,
recovery, known mismatch or exhausted observation budget (design §4.2). The
following MUST remain available while the gate is closed (**API-130**). Each
keeps its own origin, credential, CSRF, signature and store checks.

| Endpoint or operation                                                           | Source                                              |
| ------------------------------------------------------------------------------- | --------------------------------------------------- |
| `GET /_skyoauth/session` (browser-safe metadata and CSRF for cleanup only)      | design §4.2; tasks T31.6                            |
| `POST /_skyoauth/logout`                                                        | design §4.2; tasks T31.6                            |
| `POST /oauth/revoke`                                                            | design §4.2; tasks T40.15                           |
| Verified back-channel logout                                                    | design §4.2                                         |
| Independent session-revocation and security-disable operations                  | design §4.2; tasks T31.6 (see OQ-API-2)             |
| `POST /internal/v1/policy/close-session`                                        | design §6.1.1; tasks T32.12 ("cleanup while gated") |
| Operator route-bundle list and detail reads, cancel and preparation of recovery | design §4.2; tasks T50.4                            |
| Credential-dependency status reads                                              | design §4.2                                         |

- **API-131** Gate independence MUST NOT allow minting an application
  assertion or forwarding authority. The session endpoint MAY supply only
  browser-safe metadata and CSRF needed for cleanup. (design §4.2)
- **API-132** The route controller MUST preserve the fixed SkyOAuth routes
  during an application apply. A `cleanup_to_closed` abort target MUST keep
  fixed SkyOAuth cleanup endpoints. (design §4.2)
- **API-133** Independently classified public routes and fixed SkyOAuth cleanup
  endpoints MUST NOT be implicitly cookie-gated. (design §4.1)

## Open questions

These are gaps or ambiguities in the design and tasks documents. This contract
does not resolve them.

- **OQ-API-1 — Login and callback during a closed gate.** Design §4.2 lists
  session, logout, native revoke, back-channel logout and security-disable as
  gate-independent, but not `/_skyoauth/login` or `/_skyoauth/callback`. Login
  resolves the tenant from the active pinned `ApplicationOriginVersion`, which
  does not exist for an unconfigured or `cleanup_to_closed` origin. Whether
  login and callback are available while the gate is closed is not stated.
- **OQ-API-2 — No operator session-revocation endpoint.** Design §4.2 and tasks
  T31.6 refer to "independent session-revocation operations", but the endpoint
  matrix has no operator endpoint for revoking a human session, native refresh
  family or authentication context.
- **OQ-API-3 — No public issuer key administration endpoint.** Design §7.2
  gives instance `security_admin` signer management and A19 requires
  independent issuer-key rotation, but the matrix has an admin endpoint only
  for internal assertion keys (`/admin/v1/internal-assertion-keys`), not for
  public access-token keys.
- **OQ-API-4 — Native authorize and code-redemption parameters.** The design
  says `/oauth/authorize` validates "redirect/audience/scopes" and comparison
  v1 includes the exact audience, but the request parameter carrying the
  audience (`audience`, `resource` or another name) is not named. The full
  parameter lists for the authorize request and for
  `grant_type=authorization_code` redemption are not enumerated.
- **OQ-API-5 — Private endpoint wire schemas.** The policy check, recheck,
  close, route-control and credential endpoints define semantics and some
  field names (`lease_seconds`, `authorized_until`, `current_attempt`), but
  not the media type, complete request and response field names, or the HTTP
  status codes that carry allow, deny, unavailable and not-found.
- **OQ-API-6 — Who may security-disable.** The tasks matrix grants origin and
  route `disable` to tenant `client_admin`. Design §4.2 describes incident
  disable without naming a role, and the design §7.2 role table does not list
  disable for either `client_admin` or `security_admin`. Whether instance
  `security_admin` may disable a tenant's origin or route is not stated.
- **OQ-API-7 — Login-state readers.** `GET /admin/v1/tenants/{tenant}/login-state`
  is open to an "authorized scoped operator" without naming roles.
- **OQ-API-8 — Metadata content.** The tasks matrix requires the metadata
  document to "advertise implemented grants/profiles only", and design §5.7
  forbids advertising the private grant as standard two-token delegation. The
  metadata fields, and whether the private grant URI appears in
  `grant_types_supported`, are not specified.
- **OQ-API-9 — Revocation of access tokens.** `/oauth/revoke` is specified for
  refresh credentials. Whether it accepts access tokens or a
  `token_type_hint` (RFC 7009) is not stated.
- **OQ-API-10 — Internal assertion header name.** Design §4 and §6 refer to a
  "private, overwritten backend header" for the `human_session` assertion
  without naming it.
