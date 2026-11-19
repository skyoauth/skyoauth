# Errors, no-store, cancellation and retry

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Tasks covered:** T00.2.
- **Derived from:** [design](../skyoauth-design.md) §4, §4.2, §5.1, §5.1.1,
  §5.2, §5.2.2, §5.3, §5.7, §6.1, §6.1.1, §6.2, §10.2, §10.3;
  [tasks](../skyoauth-tasks.md) §2 "Endpoint matrix", §2 "Exchange selection
  and scope", §3 ("Operational capacity", "Stream state", "One-time state"),
  T32.6, T33.3, T40.5, T40.15, §8 (A11, A26, A31, A56, A57), §11 (ADR-004,
  ADR-010, ADR-020).
- **Related contracts:** [public-api.md](public-api.md),
  [token-profiles.md](token-profiles.md).

This document freezes the error classes, reason strings, cache rules,
cancellation behavior and retry budgets that the sources define. It does not
invent wire fields the sources leave open; those are listed under
[Open questions](#open-questions).

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119,
RFC 8174) when they appear in capitals. Requirement IDs use `ERR-nnn`.

## 1. Principles

- **ERR-001** Authentication failure, authorization denial, capacity
  exhaustion and infrastructure unavailability MUST be distinct results. A
  capacity or infrastructure result MUST NOT be reported as an authentication
  failure. (design §4, §6.1.1; tasks T00.2, T32.6)
- **ERR-002** Client libraries and server responses MUST NOT turn a capacity or
  infrastructure result into a login prompt or an automatic logout. (design
  §6.1.1, §10.2; tasks T32.6)
- **ERR-003** Client libraries MUST NOT automatically replay a mutation after
  any error, after login or after refresh. (design §5.2.2, §6.1.1, §10.2,
  §10.3)
- **ERR-004** RPC failures on application routes MUST be typed errors, never an
  IdP HTML redirect. (design §4)
- **ERR-005** Store, checker, observation and transport failures MUST fail
  closed. They MUST NOT expand privilege or produce an allow. (design §4.2,
  §6.1, §7)

## 2. Status classes

Application-route and gateway results:

| HTTP | Connect code             | Wire reason                       | Meaning                                                                                                                                              | SPA login?                    | Source                            |
| ---- | ------------------------ | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | --------------------------------- |
| 401  | Not specified (OQ-ERR-2) | Not specified (OQ-ERR-1)          | Missing or invalid authentication (for example revoked or expired session)                                                                           | Yes, explicit navigation only | design §4; tasks T32.6, A11       |
| 403  | Not specified (OQ-ERR-2) | Not specified (OQ-ERR-1)          | Definitive authorization denial                                                                                                                      | No                            | design §4; tasks T32.6            |
| 429  | `resource_exhausted`     | `too_many_open_streams`           | Per-session continuation cap only, after authentication and authorization                                                                            | No                            | design §6.1.1; tasks T00.2        |
| 429  | Not specified (OQ-ERR-2) | `rate_limited`                    | Request-rate limiting                                                                                                                                | No                            | design §6.1.1; tasks T00.2        |
| 503  | `unavailable`            | `stream_capacity_unavailable`     | Shared tenant, checker or global continuation capacity exhausted                                                                                     | No                            | design §6.1.1; tasks T00.2        |
| 503  | `unavailable`            | `route_configuration_unavailable` | Route gate closed: gateway apply, compensation, recovery, no verified deployment, exhausted observation budget, known mismatch, TLS evidence failure | No                            | design §4.2; tasks T00.2          |
| 503  | `unavailable`            | Not specified (OQ-ERR-1)          | Other route or auth infrastructure unavailable, including auth-service transport failure and store outage                                            | No                            | design §4, §4.2; tasks T32.6, A11 |

- **ERR-010** 401 MUST be used only for missing or invalid authentication.
  (design §4)
- **ERR-011** 403 MUST be used only for a definitive authorization denial.
  (design §4)
- **ERR-012** `too_many_open_streams` MUST be used only for the per-session cap.
  Shared-capacity exhaustion MUST use `stream_capacity_unavailable` and MUST
  NOT expose other tenants' counters. (design §6.1.1)
- **ERR-013** Capacity results MUST be evaluated only after authentication and
  authorization. (design §6.1.1)
- **ERR-014** 429 and 503 results MAY include a bounded `Retry-After`. It is a
  hint, not a promise that capacity will be free. (design §4.2, §6.1.1)
- **ERR-015** A gate closed for gateway apply, compensation or recovery MUST NOT
  return 401 or 403 and MUST NOT redirect to login. (design §4.2)
- **ERR-016** Auth-service transport failure MUST be configured as a
  fail-closed 503. (design §4.2; tasks T32.6)

## 3. OAuth endpoint errors

Errors on `/oauth/token` and `/oauth/revoke` are OAuth-shaped (tasks T21.2).
Only the codes below are fixed by the sources; see OQ-ERR-3 for the rest.

| Condition                                                                                                 | Error                                                                          | Source                     |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------- |
| WIF `scope` omitted and the grant has no explicit nonempty `default_scopes`                               | `invalid_scope`                                                                | design §5.7; tasks A26     |
| WIF `scope` explicitly empty or excessive                                                                 | Denied (code not specified)                                                    | design §5.7                |
| `skyoauth_refresh_request_id` empty, malformed or duplicated                                              | `invalid_request`                                                              | design §5.2.2; tasks T40.5 |
| Exact refresh retry whose successor was already consumed (inside the 30 s window)                         | `invalid_grant`; no credentials returned; healthy newer generation not revoked | design §5.2.2              |
| Duplicate parameters, missing selectors, profile mismatch, unsupported `resource` or requested token type | Denied (code not specified)                                                    | design §5.7                |
| Refresh with `audience`, `resource` or subject override, duplicate parameters or unknown client           | Rejected (code not specified)                                                  | design §5.2.2              |
| Selected source, grant or tenant mismatch                                                                 | Denied without cross-tenant existence detail                                   | design §5.7                |
| Revoke request for any token or client                                                                    | Non-enumerating response                                                       | design §5.2.2              |

- **ERR-020** Token endpoint failures MUST NOT reveal whether a source, grant,
  client or token exists in another tenant. (design §5.7)
- **ERR-021** Reuse of a consumed refresh credential outside an opted-in exact
  retry MUST revoke the whole family, including a replay that adds a request ID
  after the fact. (design §5.2.2)
- **ERR-022** A missing or undecryptable retry receipt, or an unavailable store,
  for an extension attempt MUST fail closed. It MUST NOT create a second
  successor or fall back to plain rotation. (design §5.2.2)
- **ERR-023** Single-use proof replay, a missing `jti` or a replay-store failure
  MUST deny. (design §5.3)

## 4. Policy check, recheck and close results

| Endpoint                              | Result          | Meaning                                                                                                                                                                         | Effect on continuation                                                   | Source              |
| ------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------- |
| `/internal/v1/policy/check`           | allow           | Request-bound allow, with checked revision when available and a decision ID                                                                                                     | Admission (if requested) returns ID, `lease_seconds`, `authorized_until` | design §6.1, §6.1.1 |
| `/internal/v1/policy/check`           | deny            | Unknown action, resource or caller; wrong tenant or audience; superseded authorization; revocation                                                                              | None created                                                             | design §6.1         |
| `/internal/v1/policy/check`           | unavailable     | Store, checker or transient route-observation failure                                                                                                                           | None created; not an authentication failure                              | design §6.1         |
| `/internal/v1/policy/recheck-session` | allow           | Renewed lease                                                                                                                                                                   | New `authorized_until`                                                   | design §6.1.1       |
| `/internal/v1/policy/recheck-session` | unavailable     | Temporary store, observation or transport loss; planned gateway apply with unchanged pinned dependencies; TLS evidence missing or late                                          | No renewal, no `closed_at`; usable only until the previous lease         | design §4.2, §6.1.1 |
| `/internal/v1/policy/recheck-session` | deny (terminal) | Revocation, changed or removed dependency, security disable, known out-of-plan mismatch, confirmed TLS material mismatch, unauthorized caller, renewal after `authorized_until` | `closed_at` set; never revived                                           | design §4.2, §6.1.1 |
| `/internal/v1/policy/close-session`   | success         | Context closed now, or already closed by the same checker and binding                                                                                                           | Quota released exactly once                                              | design §6.1.1       |
| `/internal/v1/policy/close-session`   | not found       | Unknown ID, or mismatched checker, nonce or context                                                                                                                             | No change; same result for every such case                               | design §6.1.1       |

- **ERR-030** Unavailable MUST NOT grant a new lease and MUST NOT close the
  context. Terminal deny MUST close it. (design §6.1.1; tasks ADR-010)
- **ERR-031** Each batch item MUST receive its own result. A missing, late or
  unavailable result MUST NOT extend that item's previous lease. (design
  §6.1.1)
- **ERR-032** A wrong-checker or wrong-tenant batch item MUST be denied without
  exposing its state. (design §6.1.1)
- **ERR-033** On terminal deny the backend MUST stop protected transmission
  immediately; on unavailable it MUST stop by the last successful deadline.
  (design §6.1.1)
- **ERR-034** Positive check results MUST NOT be cached for critical calls.
  (design §6.1)

## 5. Browser and native flow errors

| Situation                                                                              | Result                                                                                     | Source        |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------- |
| Authenticated but unlinked subject under `preprovisioned`, or under an enrollment hold | Non-enumerating `enrollment_required`; no principal created                                | design §5.1.1 |
| Unknown, ambiguous, spoofed or disabled origin                                         | Deny before redirect                                                                       | design §4     |
| App callback with wrong or missing browser binding                                     | Deny without creating, replacing or linking a session                                      | design §5.1   |
| Native confirmation from a stale or conflicting tab                                    | Explicit superseded-login error; restart required; no approval or redirect to the new flow | design §5.2   |
| Native confirmation denied or expired                                                  | No code issued; confirmation state consumed; cookie cleared                                | design §5.2   |

## 6. Retry budgets and client behavior

| Situation                                                           | Who                     | Allowed retry                                                                                                                                                                                  | Source                     |
| ------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| 401 on an application call                                          | SPA                     | None automatically. Explicit navigation to login only; no replay after login                                                                                                                   | design §4, §10.2           |
| 403 or definitive denial                                            | Both libraries          | None. Reconnect loops MUST stop                                                                                                                                                                | design §6.1.1, §10.2       |
| 429 `too_many_open_streams`, opted-in resumable read-only reconnect | TypeScript              | One delayed retry at a valid `Retry-After` of at most 300 s plus bounded positive jitter, then surface the error. Missing or invalid hint: surface immediately                                 | design §6.1.1; tasks T33.3 |
| 503 `stream_capacity_unavailable` or infrastructure 503             | Both libraries          | Cancellable jittered backoff with finite attempt and elapsed budgets; no login prompt                                                                                                          | design §6.1.1; tasks T33.3 |
| Read-only stream or download reconnect                              | Both libraries (opt-in) | Capped exponential backoff with full jitter; honor `Retry-After`; stop on cancellation or definitive denial; fresh admission and backend RBAC every time; no cross-origin credential redirects | design §6.1.1              |
| Bearer stream reaching access-token expiry                          | Rust                    | Obtain a fresh credential and open a new read-only request with an application cursor or range; never restart the observed mutation                                                            | design §6.1; tasks T26.6   |
| Lost response to a refresh with `skyoauth_refresh_request_id`       | Rust                    | Bounded exact retries with backoff of the same token, ID and payload, stopping by 30 s from the first send; never a new ID; never a retry without the ID                                       | design §5.2.2              |
| Lost response to a plain refresh                                    | Generic OAuth client    | None guaranteed. Replay revokes the family; reauthentication may be needed                                                                                                                     | design §5.2.2              |
| Single-use WIF proof consumed or burned                             | Rust workload provider  | Obtain a fresh assertion; never reuse the consumed proof                                                                                                                                       | design §5.3; tasks T21.6   |
| Lost `close-session` response                                       | Backend                 | Bounded backoff retries of the same close                                                                                                                                                      | design §6.1.1              |

- **ERR-040** The per-session one-retry budget MUST persist across intervening
  transient failures. It MUST reset only after a successfully established
  stream or an explicit new application or user operation, never on each 429.
  (design §6.1.1; tasks T33.3)
- **ERR-041** Shared-capacity and infrastructure retries MUST have finite
  attempt and elapsed budgets and MUST be cancellable. (design §6.1.1)
- **ERR-042** The Rust client MUST always send `skyoauth_refresh_request_id`,
  MUST write the pending token, request ID and exact payload to secure storage
  (or the explicit memory-only session) before sending, and MUST NOT retry
  without the ID after an extension failure. (design §5.2.2; tasks T40.5)
- **ERR-043** An exact refresh retry within the 30-second window MAY return the
  same credential values only while the successor is current and unconsumed,
  the family, epoch, assurance and policy revision are valid and the cached
  access token is unexpired. `expires_in` MUST be recomputed from the remaining
  lifetime; nothing is re-signed, rotated again or extended. (design §5.2.2)
- **ERR-044** Retries MUST NOT renew a continuation lease from uncertainty, and
  clients MUST NOT reconnect all streams immediately. (design §6.1.1)
- **ERR-045** Refresh MUST NOT automatically retry the original API operation.
  (design §5.2.2)

## 7. Cache control

| Response                                | Requirement                                            | Source                                               |
| --------------------------------------- | ------------------------------------------------------ | ---------------------------------------------------- |
| `/oauth/token` success (WIF and native) | MUST be `no-store`                                     | design §5.7; tasks §2 "Exchange selection and scope" |
| `GET /_skyoauth/session`                | MUST be `no-store`                                     | design §5.1; tasks §2 matrix                         |
| `/internal/v1/policy/check` result      | MUST be `no-store`                                     | design §6.1; tasks T26.4                             |
| Refresh retry envelope                  | MUST NOT be a plaintext response cache; purged at 30 s | design §5.2.2                                        |

- **ERR-050** Token material, cookies, CSRF tokens, assertions and digests MUST
  NOT appear in logs or traces. (design §4, §4.1, §6.1)

## 8. Cancellation

- **ERR-060** Client libraries MUST report cancellation as a distinct result
  from unauthenticated, forbidden and unavailable. (design §10.2)
- **ERR-061** Streaming and download cancellation MUST remain end-to-end
  without SkyOAuth buffering bodies. (design §10.2; tasks T32.7)
- **ERR-062** After completion, cancellation, disconnect, terminal denial or
  graceful drain, the backend — not browser code — MUST stop transmission and
  call `close-session`. Loss of that call leaves an orphan only until its last
  lease expires. (design §6.1.1)
- **ERR-063** Cancelling a native login MUST close the loopback listener; no
  code is produced. (design §5.2, §10.3)

## 9. Versioning

- **ERR-070** The reason strings in §2 (`too_many_open_streams`, `rate_limited`,
  `stream_capacity_unavailable`, `route_configuration_unavailable`) and
  `enrollment_required` are frozen by this contract. Renaming one is a
  breaking change and MUST update design, tasks, both libraries' shared
  fixtures and tests together. (design §12; tasks §0 "share wire/error
  fixtures")
- **ERR-071** Both client libraries MUST share wire and error fixtures. (tasks
  §0; A42)

## Open questions

- **OQ-ERR-1 — Error envelope and version.** T00.2 asks to "version errors",
  but the sources define no error body schema, no version discriminator and no
  reason strings for 401, 403 or generic infrastructure 503.
- **OQ-ERR-2 — Connect codes.** The sources give Connect codes only for
  `too_many_open_streams` (`resource_exhausted`) and the 503 results
  (`unavailable`). Connect codes for 401, 403 and `rate_limited` are not
  stated.
- **OQ-ERR-3 — OAuth error codes for denials.** The token endpoint must deny
  duplicate parameters, missing selectors, profile mismatch, unsupported
  `resource` or requested token type, explicit empty or excessive scope, refresh
  overrides, unknown clients and revoked or expired families, but the OAuth
  `error` values (for example `invalid_request`, `invalid_target`,
  `invalid_grant`, `invalid_client`, `unsupported_grant_type`) are not
  assigned.
- **OQ-ERR-4 — Numeric retry budgets.** "Finite attempt/elapsed budgets", the
  "bounded positive jitter" added to the one per-session retry, the backoff
  base and cap, and the bound on `Retry-After` for 503 results are not given
  numerically.
- **OQ-ERR-5 — `rate_limited` client behavior.** The sources define retry
  rules for the per-session cap and for shared or infrastructure 503, but not
  for 429 `rate_limited`.
- **OQ-ERR-6 — Status of flow errors.** The HTTP status and rendering of
  `enrollment_required`, the native superseded-login error and the denied
  origin result are not specified.
- **OQ-ERR-7 — Token endpoint unavailability.** Replay-store or retry-store
  failure "fails closed", but the HTTP status and OAuth error for an
  unavailable store at `/oauth/token` are not specified.
- **OQ-ERR-8 — `no-store` on errors.** `no-store` is required for successful
  token responses, the session response and policy decisions. Whether error
  responses on those endpoints must also be `no-store` is not stated.
- **OQ-ERR-9 — Bearer stream end.** Bearer server streams end no later than
  the access token's `exp`, but the status or stream error the client receives
  at that point is not specified.
