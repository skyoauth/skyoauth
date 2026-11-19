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
[Open questions](#open-questions). Items marked **Decided** there record lead
decisions that the normative text below already reflects. Text marked
"(inferred)" is this contract's reading of the sources, not a statement they
make directly.

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
  IdP HTML redirect. This requirement is canonical; public-api API-065 refers
  to it. (design §4)
- **ERR-005** Store, checker, observation and transport failures MUST fail
  closed. They MUST NOT expand privilege or produce an allow. (design §4.2,
  §6.1, §7)

## 2. Status classes

Application-route and gateway results:

| HTTP | Connect code                             | Wire reason                       | Meaning                                                                                                                                                         | SPA login?                    | Source                                           |
| ---- | ---------------------------------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------ |
| 401  | `unauthenticated` (decided, OQ-ERR-2)    | `unauthenticated` (OQ-ERR-1)      | Missing or invalid authentication (for example revoked or expired session)                                                                                      | Yes, explicit navigation only | design §4; tasks T32.6, A11; lead decision       |
| 403  | `permission_denied` (decided, OQ-ERR-2)  | `forbidden` (OQ-ERR-1)            | Definitive authorization denial                                                                                                                                 | No                            | design §4; tasks T32.6; lead decision            |
| 429  | `resource_exhausted`                     | `too_many_open_streams`           | Per-session continuation cap only, after authentication and authorization                                                                                       | No                            | design §6.1.1; tasks T00.2                       |
| 429  | `resource_exhausted` (decided, OQ-ERR-2) | `rate_limited`                    | Request-rate limiting                                                                                                                                           | No                            | design §6.1.1; tasks T00.2; lead decision        |
| 503  | `unavailable`                            | `stream_capacity_unavailable`     | Shared tenant, checker or global continuation capacity exhausted                                                                                                | No                            | design §6.1.1; tasks T00.2                       |
| 503  | `unavailable`                            | `route_configuration_unavailable` | Route gate closed: gateway apply, compensation, recovery, no verified deployment, exhausted observation budget, known mismatch, TLS evidence failure (inferred) | No                            | design §4.2; tasks T00.2                         |
| 503  | `unavailable`                            | `auth_unavailable` (OQ-ERR-1)     | Other route or auth infrastructure unavailable, including auth-service transport failure and store outage                                                       | No                            | design §4, §4.2; tasks T32.6, A11; lead decision |

The TLS row is inferred: design §4.2 says TLS nonconvergence and material
mismatch close new requests "with 503" but does not name the reason string.
The Connect codes for 401, 403 and `rate_limited` are a lead decision that has
not been verified against the Connect protocol documentation.

- **ERR-010** 401 MUST be used only for missing or invalid authentication.
  (design §4)
- **ERR-011** 403 MUST be used only for a definitive authorization denial.
  (design §4)
- **ERR-012** `too_many_open_streams` MUST be used only for the per-session cap.
  Shared-capacity exhaustion MUST use `stream_capacity_unavailable` and MUST
  NOT expose other tenants' counters. (design §6.1.1)
- **ERR-013** Capacity results MUST be evaluated only after authentication and
  authorization. (design §6.1.1)
- **ERR-014** A 503 `route_configuration_unavailable` response MUST include a
  bounded `Retry-After`. Capacity and rate results (`too_many_open_streams`,
  `stream_capacity_unavailable`, `rate_limited`) MAY include a bounded
  `Retry-After`; it is not required. When a `stream_capacity_unavailable` or
  `rate_limited` response has no `Retry-After`, the client falls back to the
  ERR-046 backoff; an invalid hint or one over 300 s is surfaced as the error
  (ERR-047, ERR-049). A `too_many_open_streams` response without a valid hint
  is surfaced immediately (§6). A `Retry-After` is a
  hint, not a promise that capacity or configuration will be available.
  Whether generic `auth_unavailable` carries `Retry-After` is not specified.
  (design §4.2, §6.1.1; tasks T32.6; MUST versus MAY: lead decision,
  OQ-ERR-10)
- **ERR-015** While the application route gate is closed, the closure MUST be
  reported only as 503 `route_configuration_unavailable`, never as 401 or 403
  and never as a login redirect. Which result wins when a request also fails
  authentication is OQ-ERR-11. (design §4.2; tasks T32.6)
- **ERR-016** Auth-service transport failure MUST be configured as a
  fail-closed 503. This requirement is canonical; public-api API-064 refers to
  it. (design §4.2; tasks T32.6)

## 3. OAuth endpoint errors

Errors on `/oauth/token` and `/oauth/revoke` are OAuth-shaped (tasks T21.2).
Only the codes below are fixed, by the sources or, for the WIF exchange
profiles, by the OQ-ERR-3 decision; see OQ-ERR-3 for the rest.

| Condition                                                                                                                                                                    | Error                                                                          | Source                                           |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------ |
| WIF `scope` absent and the grant has no explicit nonempty `default_scopes`                                                                                                   | `invalid_scope`                                                                | design §5.7; tasks A26                           |
| WIF `scope` absent and the grant has explicit nonempty `default_scopes`                                                                                                      | Not an error: those `default_scopes` apply                                     | design §5.7                                      |
| WIF `scope` explicitly empty                                                                                                                                                 | `invalid_scope` (ERR-024)                                                      | design §5.7; tasks A26; lead decision (OQ-ERR-3) |
| WIF `scope` unknown or excessive                                                                                                                                             | `invalid_scope` (ERR-024)                                                      | design §5.7; lead decision (OQ-ERR-3)            |
| `skyoauth_refresh_request_id` empty, malformed or duplicated                                                                                                                 | `invalid_request`                                                              | design §5.2.2; tasks T40.5                       |
| Exact refresh retry whose successor was already consumed (inside the 30 s window)                                                                                            | `invalid_grant`; no credentials returned; healthy newer generation not revoked | design §5.2.2                                    |
| WIF exchange: malformed request, duplicate parameters, missing selectors, unsupported parameters other than `resource`, unsupported requested token type or profile mismatch | `invalid_request` (ERR-024)                                                    | design §5.7; lead decision (OQ-ERR-3)            |
| WIF exchange: any `resource` parameter, which is never supported (an explicit exception to the `invalid_request` rule for unsupported parameters; RFC 8693 §2.2.2, RFC 8707) | `invalid_target` (ERR-024)                                                     | design §5.7; lead decision (OQ-ERR-3)            |
| WIF exchange: audience not in the grant's audience set or not assigned                                                                                                       | `invalid_target` (ERR-024)                                                     | design §5.7; lead decision (OQ-ERR-3)            |
| Unsupported `grant_type`                                                                                                                                                     | `unsupported_grant_type`                                                       | lead decision (OQ-ERR-3)                         |
| Refresh with `audience`, `resource` or subject override, duplicate parameters or unknown client                                                                              | Rejected (code not specified)                                                  | design §5.2.2                                    |
| WIF exchange: any source, grant, binding or proof failure, including source, grant or tenant mismatch                                                                        | Uniform `invalid_grant`, without cross-tenant existence detail (ERR-024)       | design §5.7; lead decision (OQ-ERR-3)            |
| Revoke request for any token or client                                                                                                                                       | Non-enumerating response                                                       | design §5.2.2                                    |

- **ERR-020** Token endpoint failures MUST NOT reveal whether a source, grant,
  client or token exists in another tenant. (design §5.7 for sources and
  grants; clients and tokens inferred from the non-enumerating revoke response
  in design §5.2.2)
- **ERR-021** Reuse of a consumed refresh credential outside an opted-in exact
  retry MUST revoke the whole family, including a replay that adds a request ID
  after the fact. (design §5.2.2)
- **ERR-022** A missing or undecryptable retry receipt, or an unavailable store,
  for an extension attempt MUST fail closed. It MUST NOT create a second
  successor or fall back to plain rotation. (design §5.2.2)
- **ERR-023** For `single_use` sources, single-use proof replay, a missing
  `jti` or a replay-store failure MUST deny. (design §5.3)
- **ERR-024** For the WIF exchange profiles, every source, grant, binding or
  proof failure MUST return the same `invalid_grant` response, so the response
  does not reveal which check failed or whether the object exists in another
  tenant (ERR-020). An absent `scope` means the grant's explicit
  nonempty `default_scopes` apply, and MUST return `invalid_scope` if the
  grant has none. An explicitly empty `scope` MUST be denied with
  `invalid_scope` (identity-registry IR-063). An unknown or excessive `scope`
  MUST return `invalid_scope`. A `resource` parameter is never supported and
  MUST always return `invalid_target`, an explicit exception to the
  `invalid_request` rule for unsupported parameters (RFC 8693 §2.2.2,
  RFC 8707). An audience that is not in the grant's audience set or is not
  assigned MUST return `invalid_target`. An unsupported requested token type
  MUST return `invalid_request` (public-api API-015). (lead decision,
  OQ-ERR-3)

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

| Situation                                                   | Result                                                                                                      | Source        |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------- |
| Authenticated but unlinked subject under `preprovisioned`   | Non-enumerating `enrollment_required`; no principal created                                                 | design §5.1.1 |
| Authenticated but unlinked subject under an enrollment hold | Denied; no principal created. Reporting it as `enrollment_required` is inferred: the design names no result | design §5.1.1 |
| Unknown, ambiguous, spoofed or disabled origin              | Deny before redirect                                                                                        | design §4     |
| App callback with wrong or missing browser binding          | Deny without creating, replacing or linking a session                                                       | design §5.1   |
| Native confirmation from a stale or conflicting tab         | Explicit superseded-login error; restart required; no approval or redirect to the new flow                  | design §5.2   |
| Native confirmation denied or expired                       | No code issued; confirmation state consumed; cookie cleared                                                 | design §5.2   |

## 6. Retry budgets and client behavior

| Situation                                                           | Who                     | Allowed retry                                                                                                                                                                                            | Source                                    |
| ------------------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| 401 on an application call                                          | SPA                     | None automatically. Explicit navigation to login only; no replay after login                                                                                                                             | design §4, §10.2                          |
| 403 or definitive denial                                            | Both libraries          | None. Reconnect loops MUST stop                                                                                                                                                                          | design §6.1.1, §10.2                      |
| 429 `too_many_open_streams`, opted-in resumable read-only reconnect | TypeScript              | One delayed retry at a valid `Retry-After` of at most 300 s plus jitter (ERR-048), then surface the error. Missing or invalid hint: surface immediately                                                  | design §6.1.1; tasks T33.3; lead decision |
| 503 `stream_capacity_unavailable` or infrastructure 503             | Both libraries          | Cancellable backoff under the shared budget (ERR-046, ERR-047); no login prompt                                                                                                                          | design §6.1.1; tasks T33.3; lead decision |
| 429 `rate_limited`                                                  | Both libraries          | Same shared budget as `stream_capacity_unavailable` (ERR-049); no login prompt                                                                                                                           | lead decision (OQ-ERR-5)                  |
| Read-only stream or download reconnect                              | Both libraries (opt-in) | Capped exponential backoff with full jitter (ERR-046); honor `Retry-After`; stop on cancellation or definitive denial; fresh admission and backend RBAC every time; no cross-origin credential redirects | design §6.1.1; lead decision              |
| Bearer stream reaching access-token expiry                          | Rust                    | Obtain a fresh credential and open a new read-only request with an application cursor or range; never restart the observed mutation                                                                      | design §6.1; tasks T26.6                  |
| Lost response to a refresh with `skyoauth_refresh_request_id`       | Rust                    | Bounded exact retries with backoff of the same token, ID and payload, stopping by 30 s from the first send; never a new ID; never a retry without the ID                                                 | design §5.2.2                             |
| Lost response to a plain refresh                                    | Generic OAuth client    | None guaranteed. Replay revokes the family; reauthentication may be needed                                                                                                                               | design §5.2.2                             |
| Single-use WIF proof consumed or burned                             | Rust workload provider  | Obtain a fresh assertion; never reuse the consumed proof                                                                                                                                                 | design §5.3; tasks T21.6                  |
| Lost `close-session` response                                       | Backend                 | Bounded backoff retries of the same close                                                                                                                                                                | design §6.1.1                             |

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
- **ERR-046** Automatic retries for shared capacity, infrastructure 503 and
  read-only reconnect MUST use exponential backoff with base 1 s, factor 2,
  cap 30 s and full jitter (each delay uniform between 0 and the capped
  exponential value). They MUST stop after 5 retries or 120 s of accumulated
  backoff waiting, whichever comes first, and then surface the error. The 5
  retries are counted after the first failure: at most 6 requests in total,
  the initial request plus 5 retries. The 120 s counts only backoff waits;
  time spent waiting for a valid `Retry-After` (ERR-047) is excluded from that
  clock, while each such retry still counts toward the maximum of 5. A backoff
  wait that would take the accumulated backoff waiting past 120 s MUST NOT be
  started: the retries end there and the error is surfaced; the wait is not
  shortened to fit the budget. The whole retry sequence, including
  `Retry-After` waits, is therefore bounded by the 5-retry maximum and stays
  cancellable at any point (ERR-041). (lead decision, OQ-ERR-4, OQ-ERR-12;
  design §6.1.1)
- **ERR-047** Client libraries MUST honor a valid 503 `Retry-After` of at most
  300 s as the earliest time of the next attempt. The client waits that long;
  that wait is excluded from the ERR-046 120 s backoff clock, and the retry
  still counts toward the ERR-046 maximum of 5 retries. A missing
  `Retry-After` falls back to the ERR-046 schedule. An invalid `Retry-After`,
  or one larger than 300 s, MUST end the automatic retries and surface the
  error: the client MUST NOT retry on the ERR-046 schedule, about 1 s later,
  after the server asked for a longer wait. (lead decision, OQ-ERR-4,
  OQ-ERR-12)
- **ERR-048** The single delayed per-session retry (`too_many_open_streams`)
  MUST wait the valid `Retry-After` plus a jitter drawn uniformly from 0 to
  min(5 s, 10% of the hint). (lead decision, OQ-ERR-4; design §6.1.1)
- **ERR-049** 429 `rate_limited` MUST be retried, if at all, only as an
  automatic read-only retry under the same budget and `Retry-After` rules as
  `stream_capacity_unavailable` (ERR-046, ERR-047). It never triggers a login
  prompt or a mutation replay. (lead decision, OQ-ERR-5)

## 7. Cache control

| ID      | Response                                                     | Requirement                                            | Source                                                                 |
| ------- | ------------------------------------------------------------ | ------------------------------------------------------ | ---------------------------------------------------------------------- |
| ERR-051 | Every `/oauth/token` response (WIF and native), incl. errors | MUST be `no-store`                                     | design §5.7; tasks §2 "Exchange selection and scope"; errors: OQ-ERR-8 |
| ERR-052 | Every `GET /_skyoauth/session` response, incl. errors        | MUST be `no-store`                                     | design §5.1; tasks §2 matrix; errors: OQ-ERR-8                         |
| ERR-053 | Every `/internal/v1/policy/check` response, incl. errors     | MUST be `no-store`                                     | design §6.1; tasks T26.4; errors: OQ-ERR-8                             |
| ERR-054 | Refresh retry envelope                                       | MUST NOT be a plaintext response cache; purged at 30 s | design §5.2.2                                                          |

- **ERR-050** Token material, cookies, CSRF tokens, assertions and digests MUST
  NOT appear in logs or traces. (design §4, §4.1, §6.1)

## 8. Cancellation

- **ERR-060** Client libraries MUST report cancellation as a distinct result
  from unauthenticated, forbidden and unavailable. (design §10.2 distinguishes
  cancelled from unauthenticated; distinctness from forbidden and unavailable
  is inferred)
- **ERR-061** Streaming and download cancellation MUST remain end-to-end
  without SkyOAuth buffering bodies. (design §10.2; tasks T32.7)
- **ERR-062** After completion, cancellation, disconnect, terminal denial or
  graceful drain, the backend — not browser code — MUST stop transmission and
  call `close-session`. Loss of that call leaves an orphan only until its last
  lease expires. (design §6.1.1)
- **ERR-063** Cancelling a native login MUST close the loopback listener; no
  code is produced. (design §5.2, §10.3)

## 9. Versioning

- **ERR-070** The reason strings in §2 (`unauthenticated`, `forbidden`,
  `too_many_open_streams`, `rate_limited`, `stream_capacity_unavailable`,
  `route_configuration_unavailable`, `auth_unavailable`) and
  `enrollment_required` are frozen by this contract. Renaming one is a
  breaking change and MUST update design, tasks, both libraries' shared
  fixtures and tests together. (design §12; tasks §0 "share wire/error
  fixtures"; `unauthenticated`, `forbidden` and `auth_unavailable`: lead
  decision, OQ-ERR-1)
- **ERR-071** Both client libraries MUST share wire and error fixtures. The
  shared error fixture set is versioned; that version, not a field in the
  error body, is how errors are versioned. (tasks §0; A42; versioning: lead
  decision, OQ-ERR-1)
- **ERR-072** Error bodies MUST NOT carry a version field in v0.1. (lead
  decision, OQ-ERR-1)

## Open questions

Items marked **Decided** record a lead decision; the normative text above
already reflects it, and the design and tasks documents still need the
follow-up. All other items are not resolved by this contract.

- **OQ-ERR-1 — Error envelope and version.** **Decided** (lead decision,
  2026-11-19), minimal form: errors are versioned through the versioned shared
  error fixture set (ERR-070, ERR-071); v0.1 error bodies carry no version
  field (ERR-072). The reasons for 401, 403 and generic infrastructure 503 are
  frozen as `unauthenticated`, `forbidden` and `auth_unavailable`. The rest of
  the body schema stays unspecified. Original question: T00.2 asks to "version
  errors", but the sources define no error body schema, no version
  discriminator and no reason strings for 401, 403 or generic infrastructure 503.
- **OQ-ERR-2 — Connect codes.** **Decided** (lead decision, 2026-11-19): 401
  maps to `unauthenticated`, 403 to `permission_denied` and 429 `rate_limited`
  to `resource_exhausted`. Unverified against the Connect protocol
  documentation. Original question: the sources give Connect codes only for
  `too_many_open_streams` (`resource_exhausted`) and the 503 results
  (`unavailable`).
- **OQ-ERR-3 — OAuth error codes for denials.** **Decided** (lead decision,
  2026-11-19) in part, for the WIF exchange profiles (§3 table, ERR-024):
  `invalid_request` for malformed requests, duplicate parameters, missing
  selectors, unsupported parameters other than `resource`, an unsupported
  requested token type and profile mismatch; uniform `invalid_grant` for any
  source, grant, binding or proof failure (ERR-020); `invalid_target` for any
  `resource` parameter, which is never supported (an explicit exception to the
  `invalid_request` rule; RFC 8693 §2.2.2, RFC 8707), and for an audience not
  in the grant's audience set or not assigned; `invalid_scope`
  and `unsupported_grant_type` keep their meanings. Scope is also **Decided**
  (lead decision, 2026-11-19): an absent scope uses the grant's
  `default_scopes`, or is `invalid_scope` if there are none; an explicitly
  empty, unknown or excessive scope is `invalid_scope` (ERR-024, IR-063).
  Still open: the codes for the other
  `/oauth/token` denials (refresh overrides, unknown clients, revoked or
  expired families). Original question:
  the token endpoint must deny duplicate parameters, missing selectors, profile mismatch, unsupported
  `resource` or requested token type, explicit empty or excessive scope, refresh
  overrides, unknown clients and revoked or expired families, but the OAuth
  `error` values (for example `invalid_request`, `invalid_target`,
  `invalid_grant`, `invalid_client`, `unsupported_grant_type`) are not
  assigned.
- **OQ-ERR-4 — Numeric retry budgets.** **Decided** (lead decision, 2026-11-19):
  base 1 s, factor 2, cap 30 s, full jitter, at most 5 retries or 120 s
  (ERR-046); 503 `Retry-After` honored up to 300 s (ERR-047); the one delayed
  per-session retry adds jitter uniform in 0 to min(5 s, 10% of the hint)
  (ERR-048). Also decided (lead decision, 2026-11-19): ERR-046 means 5 retries
  after the first failure, that is at most 6 requests in total, and 120 s of
  accumulated backoff waiting; a backoff wait that would cross 120 s is not
  started, and the retries end. For ERR-047, a missing `Retry-After` falls
  back to the ERR-046 backoff, while an invalid or over-300 s `Retry-After`
  surfaces the error instead of retrying about 1 s after an explicit longer
  server hint. This replaces the earlier reading, first recorded as inferred,
  that an invalid or over-300 s hint falls back to backoff. Original question:
  the finite attempt and elapsed budgets, the jitter on the per-session retry,
  the backoff base and cap and the bound on `Retry-After` for 503 results were
  not given numerically.
- **OQ-ERR-5 — `rate_limited` client behavior.** **Decided** (lead decision,
  2026-11-19): `rate_limited` uses the shared-capacity budget (ERR-049).
  Original question: the sources define retry rules for the per-session cap
  and for shared or infrastructure 503, but not for 429 `rate_limited`.
- **OQ-ERR-6 — Status of flow errors.** The HTTP status and rendering of
  `enrollment_required`, the native superseded-login error and the denied
  origin result are not specified.
- **OQ-ERR-7 — Token endpoint unavailability.** Replay-store or retry-store
  failure "fails closed", but the HTTP status and OAuth error for an
  unavailable store at `/oauth/token` are not specified.
- **OQ-ERR-8 — `no-store` on errors.** **Decided** (lead decision,
  2026-11-19): every response of `/oauth/token`, `GET /_skyoauth/session` and
  `/internal/v1/policy/check`, including errors, is `no-store` (ERR-051 to
  ERR-053). Original question: `no-store` was required only for successful
  token responses, the session response and policy decisions.
- **OQ-ERR-9 — Bearer stream end.** Bearer server streams end no later than
  the access token's `exp`, but the status or stream error the client receives
  at that point is not specified.
- **OQ-ERR-10 — `Retry-After` MAY versus MUST.** **Decided** (lead decision,
  2026-11-19): `route_configuration_unavailable` MUST carry a bounded
  `Retry-After`; capacity and `rate_limited` responses MAY carry one, and
  without a `Retry-After` the client falls back to backoff, while an invalid or
  over-300 s hint surfaces the error (ERR-014, ERR-047). The
  decision does not cover generic `auth_unavailable`, which stays unspecified.
  Follow-up: tasks T32.6 reads as requiring `Retry-After` on every capacity and
  rate result and needs to say MAY. Original question: design §4.2 requires a
  bounded `Retry-After` on `route_configuration_unavailable`, and tasks T32.6
  maps all of 429 `too_many_open_streams`/`rate_limited` and 503
  `stream_capacity_unavailable`/`route_configuration_unavailable` "to typed
  HTTP/Connect results with bounded Retry-After", which reads as required.
  Design §6.1.1 says the capacity results and `rate_limited` "may include a
  bounded Retry-After". Whether `Retry-After` is required on the capacity and
  rate results, and on generic `auth_unavailable`, is not settled.
- **OQ-ERR-11 — 401 versus 503 precedence.** Design §4.2 forbids reporting a
  closed gate as 401, and ERR-013 orders capacity checks after authentication,
  but the sources do not say which result a request gets when the gate is
  closed and its session is also missing, expired or revoked: 503
  `route_configuration_unavailable` (gate first) or 401 (authentication
  first). The order also decides whether an unauthenticated caller can observe
  the gate state.

  Lead lean (not decided): the gate-closure 503 wins over 401 only when the
  gate is closed for that route; otherwise the request gets the normal 401.
  (triage: spec-amendments PR)

- **OQ-ERR-12 — `Retry-After` beyond the elapsed budget.** **Decided** (lead
  decision, 2026-11-19): the 120 s budget caps backoff-driven retries only. When
  the server sends a valid `Retry-After` of at most 300 s, the client waits that
  long; that wait is excluded from the 120 s elapsed clock, which counts only
  backoff waits, and the retry still counts toward the maximum of 5 retries
  (ERR-046, ERR-047). Original question: the OQ-ERR-4
  decision accepts a 503 `Retry-After` of up to 300 s but also caps automatic
  retries at 120 s. Whether a valid hint longer than the remaining elapsed
  budget ends the retries, or whether the wait it asks for is outside that
  budget, is not decided.
