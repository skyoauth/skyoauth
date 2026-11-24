# ADR-010: Live revocation, leases and stream continuation

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The
  direction is accepted; the details, including lead decisions and text marked
  "(inferred)", are implementation choices that ordinary review can change
  (design §12; [status values](README.md#status-values)). Questions still
  marked open under Open questions stay open: ratification closes none of
  them.
- **Tasks:** ratified with T00.6 (lifetimes and leases; it names ADR-010 for the
  full-origin apply interruption and cleanup independence) and T00.2 (errors,
  capacity results and retry budgets). Implementation: T26.1–T26.6, T31.6,
  T32.6–T32.8, T32.11, T32.12, T32.14, T33.3, T40.10.
- **Baseline (tasks §11):** "Access <=300s/internal evidence <=30s; browser
  leases default/critical <=15s, noncritical <=300s/context <=1h plus
  observation bounds. Temporary unavailable grants no renewal, terminal deny
  closes. Separate operational quotas, idempotent release and distinct
  per-session/shared errors; one hinted orphan retry versus finite jittered
  shared retry. Bearer reconnect/range resume stays; no general bearer
  continuation or mutation replay."
- **Contracts:** [lifetimes.md](../contracts/lifetimes.md) §1, §2, §5, §10;
  [errors-retry.md](../contracts/errors-retry.md) §2, §4, §6;
  [public-api.md](../contracts/public-api.md) §5, §8;
  [token-profiles.md](../contracts/token-profiles.md) §7;
  [identity-registry.md](../contracts/identity-registry.md) §7.4.

## Context

SkyOAuth issues offline-verifiable JWTs, so a revocation cannot reach a
credential already in a backend's hands except through its expiry or a live
check (design §6.1). Payloads stream from Envoy directly to the backend;
SkyOAuth never sees them (design §1, §4). A browser stream or download can
outlive the 30-second internal assertion that admitted it, and a ten-minute log
tail outlives a 300-second bearer token (design §6.1, §6.1.1). The design needs
a bound on how long revoked authority keeps working, a way for long browser
responses to continue under that bound, and capacity and error rules that never
turn infrastructure trouble into a login prompt or a mutation replay. The
gateway route gate that can close application traffic is ADR-020; this ADR
records how leases and cleanup behave under it.

## Decision

### Credential lifetimes and offline residual

1. Access JWTs are capped at 300 seconds; internal `human_session` assertions at
   30 seconds. Policies may shorten both. After a grant, policy or session
   change an offline credential keeps only its residual validity; there is no
   promise of cancelling previously authorized operations (design §6.1; LT-013).
2. Expired assertions are never accepted as fresh evidence, including for stream
   admission (design §6.1, §6.1.1).

### Private live check

3. `POST /internal/v1/policy/check` authenticates the caller as a
   `ResourceServerChecker` bound to the registered audience and an explicit
   tenant set, not as the token's subject or service. It takes exactly one
   access JWT or internal assertion plus canonical action and resource
   coordinates, looks up the persisted `ResourceAction`, verifies the complete
   profile and immutable decision dependencies and returns a request-bound
   allow, deny or unavailable with a decision ID, served `no-store` (design
   §6.1; T26.1–T26.4; ADR-018).
4. Checks begun after a committed revocation deny; superseded or invalidated
   authorization revisions deny and require renewed credentials. Store, checker
   or transient route-observation failure returns typed unavailable, never an
   allow and never an authentication failure. No positive caching for critical
   calls (design §6.1; T26.5).

### Browser-stream continuation

5. **Admission.** For a stream-capable action, the backend presents an unexpired
   `human_session` assertion, canonical coordinates and a fresh stream-instance
   nonce; SkyOAuth records a `SessionContinuation` bound to the checker, tenant
   and audience, principal, session and authentication, origin and route, policy
   revision, exact coordinates, request tuple and nonce. One assertion `jti`
   admits at most one continuation. It continues that already-established
   response only, never a new request, resource, mutation or wider scope, and is
   never exposed to browser code (design §6.1.1; T32.12).
6. **Leases.** Each allow returns `lease_seconds` and `authorized_until`. Route
   `session_lease_seconds` defaults to 15 seconds within the action's
   `max_session_lease_seconds`; the action ceiling defaults to 15, and only an
   explicitly classified noncritical read-only action may opt into a ceiling
   above 15, at most 300 seconds. Critical or mutating actions stay at 15
   seconds or less. Out-of-range or contradictory configuration is rejected
   (design §6.1.1; T14.4).
7. **Composition.** The effective lease is the earliest of route and action
   limits, current session and authentication expiry, the applicable
   route-observation deadline and an immutable continuation deadline of at most
   1 hour from creation. Bounds never stack (design §6.1.1, §4.2; LT-001).
8. **Recheck.** `POST /internal/v1/policy/recheck-session` from the same mTLS
   checker rechecks deadlines, epochs, pinned versions, parent security
   revisions, dependencies and runtime state. Renewal after `authorized_until`
   or the absolute deadline denies. Neither stream traffic nor rechecks extend
   session idle or absolute expiry (design §6.1.1).
9. **Unavailable versus terminal.** Temporary store, observation or transport
   unavailability grants no renewal and does not close the context; the backend
   stops by the last successful deadline. Terminal deny closes the context and
   stops transmission immediately. Missing, late or unavailable batch items
   never extend their lease. There is no fail-open stream grace (design §6.1.1;
   LT-002).
10. **Local deadline.** The backend sets a monotonic deadline no later than
    recheck request start plus `lease_seconds`, minus a safety margin, honoring
    earlier bounds; network delay never extends it (design §6.1.1).
11. **Revocation bound.** Revocation after an allow has at most the selected
    remaining lease (default 15 seconds, opted-in noncritical maximum 300
    seconds). Longer leases trade slower revocation for less polling, not
    guaranteed availability (design §6.1.1).
12. **Batches.** Recheck and close accept one item or at most 100 items and 64
    KiB under one checker identity, each with an independent result; no
    batch-wide allow. Renewals are jittered before each earliest deadline and
    never delayed to fill a batch (design §6.1.1).

### Release, quotas and errors

13. **Idempotent release.** `POST /internal/v1/policy/close-session` from the
    same checker sets `closed_at` and releases occupancy exactly once; a
    matching repeat succeeds without another decrement; close wins permanently
    over later rechecks; unknown or mismatched handles get the same
    non-enumerating not-found. An admission-`jti` tombstone outlives the
    assertion, so close or garbage collection never permits a second admission.
    A crash can leave an orphan until its last lease expires (design §6.1.1).
14. **Separate operational quotas.** `OriginCapacityPolicy` (per origin, default
    8, tenant `client_admin`) and `InstanceCapacityPolicy` (security_admin:
    per-session ceiling 1–64 and finite tenant, checker and global quotas and
    rate limits) are operational records excluded from route-bundle pins and
    authorization snapshots. The instance quotas and rate limits are explicit
    values required at installation, with no implicit defaults (lead decision,
    2026-11-19, OQ-ADR010-1). The effective session cap is the lower of the two;
    lowering it blocks new admissions only and never closes streams or changes
    authorization (design §6.1.1; T10.4).
15. **Distinct errors.** 401 is authentication only and 403 a definitive denial.
    `too_many_open_streams` (429) is only the per-session cap;
    `stream_capacity_unavailable` (503) is shared exhaustion and exposes no
    other tenant's counters; `rate_limited` (429) is request-rate limiting;
    `route_configuration_unavailable` (503) is the closed route gate. Capacity
    results come after authentication and authorization (design §6.1.1, §4.2;
    T00.2, T32.6).
16. **Retries.** For an opted-in resumable read-only reconnect, the TypeScript
    library makes one delayed per-session retry at a valid `Retry-After` of at
    most 300 seconds plus bounded jitter, preserving that budget across
    transient failures; missing or invalid hints surface immediately.
    Shared-capacity and infrastructure unavailability use cancellable jittered
    backoff with finite attempt and elapsed budgets. Neither path prompts for
    login or replays a mutation (design §6.1.1; T33.3).

### Bearer streams

17. Bearer server-streaming responses (`wif` and `human_cli`) end no later than
    the original access token's expiry, sooner on a required live denial. There
    is no in-band token replacement and no general bearer continuation; native
    refresh or WIF reacquisition does not extend the old response. The Rust
    consumer obtains a fresh credential and opens a new read-only request using
    an application cursor or range; every new request repeats tenant, scope,
    resource and RBAC checks (design §6.1; T26.6, T40.10).
18. Range resume uses a stable object version or ETag with `If-Range` or an
    equivalent integrity check; otherwise restart safely. The one-hour browser
    cap deliberately interrupts unfinished downloads (design §6.1.1).

### Route gate and cleanup

19. The route-gate clause (lead decision OQ-LT-14, 2026-11-19): "Real gateway
    apply/compensation closes origin cookie admissions; unchanged contexts get
    unavailable only to their existing lease; fixed
    session/logout/revoke/back-channel/security-disable cleanup stays
    independent of the route gate"
20. Changed or removed dependencies or a security disable are terminal. Staging,
    polling, operational capacity edits and a registry-only pointer advance with
    unchanged actual dependencies are not authorization mismatches. Re-enabling
    never resurrects an invalidated context (design §6.1.1, §4.2; ADR-020).

### Internal key state

21. Live checks, continuation admission and rechecks deny evidence admitted by a
    still-unpromoted standby or a compromised or disabled internal key;
    continuations keep the admitting key ID. The internal JWKS verification
    cache is at most 60 seconds with no stale-on-error extension (design §6.2;
    ADR-002).

## Consequences and requirements

- Contract requirements: LT-001 to LT-004 (composition, unavailable, monotonic
  deadlines), LT-013, LT-014 (offline residual, bearer streams), LT-040 to
  LT-045 (continuation leases), LT-051, LT-055 (observation caps), LT-090 to
  LT-094 (gate outcomes over time), ERR-010 to ERR-016 (status classes), ERR-030
  to ERR-034 (check, recheck and close results), ERR-040 to ERR-049 (retry
  budgets), API-070 to API-075 (live check), API-080 to API-084 (continuation),
  API-130 to API-134 (independence from the route gate), TP-062 (no expired
  evidence), IR-101, IR-102 (lease ceilings).
- A checker or store outage longer than the remaining lease terminates
  default-lease streams (design §6.1.1).
- Ten thousand streams at 15-second leases imply about 667 decisions per second
  before margins, whatever the batching; T32.14 measures it (design §6.1.1).
- A real gateway apply can interrupt every cookie stream on the origin
  (lifetimes §10).
- Conformance rows: A11, A12, A21, A31, A56; the gate-outcome parts of A58.

## Alternatives considered

- **Longer access TTLs.** Rejected; 300 seconds is the v0.1 ceiling (design
  §6.1).
- **Fail-open stream grace on checker or store outage.** Rejected (design
  §6.1.1).
- **General bearer continuation or in-band token replacement.** Deferred under
  this ADR, to avoid extending external-proof authority implicitly (design
  §6.1).
- **Positive caching of critical decisions or a reusable blanket permission.**
  Rejected (design §6.1).
- **Capacity limits inside authorization snapshots.** Rejected; they are
  operational revisions (design §6.1.1).
- **Per-replica internal keys.** An alternative needing a separate enrollment
  design (design §6.2; ADR-002).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-LT-14** — ADR-010 record. Decided (lead decision, 2026-11-19); the clause
  is recorded in Decision item 19.
- **OQ-LT-10** — closed-context retention has no value (open).
- **OQ-LT-12** — the size of the local lease safety margin (open).
- **OQ-ERR-4** — numeric retry budgets. Decided (lead decision, 2026-11-19):
  base 1 s, factor 2, cap 30 s, full jitter, at most 5 retries or 120 s.
- **OQ-ERR-5** — `rate_limited` behavior. Decided (lead decision, 2026-11-19):
  it uses the shared-capacity budget.
- **OQ-ERR-9** — the status or stream error a client receives at bearer stream
  end (open).
- **OQ-ERR-10** — `Retry-After`. Decided (lead decision, 2026-11-19): required
  on `route_configuration_unavailable`, optional on capacity and rate results;
  generic `auth_unavailable` stays unspecified.
- **OQ-ERR-11** — 401 versus 503 precedence when the gate is closed and the
  session is invalid (open; lead lean recorded).
- **OQ-ERR-12** — `Retry-After` beyond the elapsed budget. Decided (lead
  decision, 2026-11-19): a valid hint is waited and excluded from the 120 s
  clock.
- **OQ-IR-8** — no field classifies an action as critical, mutating or
  noncritical read-only, and `stream_class` values are undefined (open).
- **OQ-API-2** — no operator endpoint revokes a human session, refresh family or
  authentication context (open).
- **OQ-API-5** — private endpoint wire schemas and status codes (open).
- **OQ-GW-8** — gate scope. Decided (lead decision, 2026-11-19): one
  `RouteBundle` per `ApplicationOrigin`, so the gate is origin-wide.
- **OQ-TM-3** — reuse of internal assertions. Decided (lead decision,
  2026-11-19): no `jti` rejection for ordinary requests; continuation admission
  stays one per `jti`.
- **OQ-TM-14** — bulk invalidation through `auth_generation`. Decided (lead
  decision, 2026-11-19) in the threat model; the audited compromise transition
  of ADR-021 owns it (tenant `provider_admin` per tenant, no single-origin
  variant; the instance-wide response runs it for every tenant).

New questions raised by this ADR:

- **OQ-ADR010-1 — Default quotas.** Decided (lead decision, 2026-11-19):
  explicit quotas are required at installation; there are no implicit defaults
  (item 14). Original question: `InstanceCapacityPolicy` stores "explicit finite
  tenant/checker/global quotas and rate limits" (design §6.1.1), but no default
  values or installation-time requirement for them are given.
- **OQ-ADR010-2 — Shortening the one-hour cap.** The continuation deadline is
  "at most 1 hour from creation (route/action policy may shorten it)" (design
  §6.1.1). Whether `max_stream_duration_seconds` on `ResourceAction` and
  `ApplicationRouteVersion` is the field that shortens it is not stated
  (inferred reading). Open; to be decided before M1b/M3 (lead decision,
  2026-11-19).
- **OQ-ADR010-3 — Rust bearer reconnect policy.** Answered by ERR-046: the
  errors-retry §6 row for read-only stream or download reconnect applies to both
  libraries (opt-in) with ERR-046 backoff, so the Rust crate's bearer reconnect
  uses the same budget. Original question: Design §6.1.1 says "both client
  libraries provide opt-in read-only reconnect" with backoff and `Retry-After`;
  the one delayed per-session retry is stated only for the TypeScript library.
  Whether the Rust crate's bearer reconnect uses the same ERR-046 budget is not
  stated.

## Tests

- A11 — revoked or expired session and unavailable store give 401 or 503, never
  fail-open.
- A12 — browser and bearer streams beyond credential and context lifetime;
  reconnect, backoff and range resume without restarted mutation.
- A21 — disabled grant, assignment or policy with an outstanding JWT.
- A31 — wrong checker, audience, tenant or action; unavailable checker.
- A56 — close races, orphans, shared quotas, cap changes, retry budgets and
  unavailable batches.
- A58 — unchanged contexts get unavailable during apply; changed dependencies
  deny.
- Task tests: T26.5, T26.6, T32.7, T32.8, T32.12, T32.14, T33.5.
