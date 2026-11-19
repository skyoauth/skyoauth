# Lifetimes, deadlines and recovery bounds

- **Status:** proposed, M0. Not implemented; not yet reviewed or ratified.
- **Tasks covered:** T00.6.
- **Derived from:** [design](../skyoauth-design.md) §4.1, §4.2, §5.1, §5.2,
  §5.2.2, §5.3, §6, §6.1, §6.1.1, §6.2, §7.2, §12; [tasks](../skyoauth-tasks.md)
  §0, §3 ("Route preparation, approval and recovery", "Unfinished-apply
  compensation", "Protected-listener TLS renewal", "TLS recovery under the
  approved contract", "Route runtime state", "Route observation bounds and
  apply outcomes", "Operational capacity", "One-time state", "Stream state",
  "Key separation"), T10.6, T14.9, T20.7, T26.6, T31.2, T32.3, T32.12,
  T33.3, T40.5, T40.15, T51.4, T51.9, §8 (A12, A33, A56, A57, A58), §11
  (ADR-004, ADR-010, ADR-020).
- **Related contracts:** [token-profiles.md](token-profiles.md) (credential
  lifetimes), [errors-retry.md](errors-retry.md) (retry budgets and wire
  results), [gateway-containment.md](gateway-containment.md) (apply, abort and
  observation mechanics).

This document collects every lifetime, default, ceiling and deadline the
sources define, and the rules for combining, renewing and recovering them. It
restates the design and the tasks plan and adds no new values, except values
cited as "lead decision": those come from an open question marked
**Decided**, whose design and tasks amendment is a pending follow-up. Where the
sources require a bound but give no number and no decision exists, the table
says "Not specified" and the gap is listed under
[Open questions](#open-questions).

These are proposed product limits, not OAuth-mandated values or availability
promises (design §5.2.2, §12).

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119,
RFC 8174) when they appear in capitals. Requirement IDs use `LT-nnn`.

Terms used in the tables:

- **Default:** the value used when configuration does not set one.
- **Ceiling:** the largest value configuration may set.
- **Maximum:** a fixed upper bound that no configuration can exceed.
- **Skew:** the bounded clock skew: default 60 s, instance-configurable up to
  a ceiling of 120 s (lead decision, OQ-LT-16; the same decision answers
  OQ-TP-10 in [token-profiles.md](token-profiles.md#open-questions)).

## 1. Composition rules

- **LT-001** Every effective deadline MUST be the earliest of all bounds that
  apply to it. Bounds MUST NOT stack into a longer window. (design §4.2,
  §6.1.1; tasks §3 "Stream state")
- **LT-002** Temporary unavailability (store, checker, observation or
  transport) MUST NOT grant a new lease, extend a deadline or close state. It
  permits retry only until the previous deadline. (design §4.2, §6.1.1;
  ADR-010)
- **LT-003** Controller takeover, restart, claim, failed polls, network delay,
  metadata rereads and registry-only activation MUST NOT reset or advance a
  sample age, apply deadline, abort deadline, overlap deadline or lease.
  (design §4.2; tasks §3; T00.6)
- **LT-004** Local deadlines MUST use a monotonic clock set no later than the
  request start plus the returned lease, less a safety margin. Network delay
  MUST NOT extend them. (design §6.1.1; margin is OQ-LT-12)
- **LT-005** Increasing a native refresh-family absolute or idle limit (the
  native refresh fields of `HumanAccessPolicy`, tasks §3) MUST NOT extend an
  existing family or `HumanAuthentication`; it applies only to newly approved
  families. Tightening such a limit MUST permanently narrow the limits of
  affected families or revoke them, enforced at the next refresh or live
  check. Elapsed or revoked state is never resurrected by a later increase.
  LT-005 does not govern route-bundle approval deadlines: `expires_at`,
  `apply_deadline` and `abort_until` are bound into the approval and attempt
  (§6), and no limit change shortens an approved `abort_until` (inferred from
  the explicit approved `abort_until`, design §4.2). Capacity limits follow
  LT-007. (design §5.2.2; tasks §3 "One-time state", T40.5)
- **LT-006** Configuration MUST reject out-of-range or contradictory values
  rather than silently widen them. Durations MUST be positive. (design §5.2.2,
  §6.1.1)
- **LT-007** Origin and instance capacity limits govern only new admissions.
  Lowering one MUST block new admissions until occupancy falls below the
  effective limit and MUST NOT close, evict or revoke existing live
  continuations. Changing one MUST NOT alter route pins, credentials,
  authorization revisions or existing lease deadlines. (design §6.1.1; tasks
  §3 "Operational capacity", T14.5)

## 2. Credentials

| Item                               | Default              | Ceiling or maximum                                          | Also bounded by                                                 | Source                                   |
| ---------------------------------- | -------------------- | ----------------------------------------------------------- | --------------------------------------------------------------- | ---------------------------------------- |
| `wif` access token                 | Not specified        | Maximum 300 s                                               | Grant maximum TTL                                               | design §5.7, §6.1; tasks T20.2           |
| `human_cli` access token           | Not specified        | Maximum 300 s                                               | `HumanAccessPolicy` TTL, refresh family, authentication         | design §5.2.2, §6.1; tasks T40.5         |
| `human_session` internal assertion | Not specified        | Maximum 30 s                                                | Session, authentication and applicable observation deadlines    | design §6, §6.1; tasks T32.2             |
| Native refresh family, absolute    | 12 h                 | Ceiling 7 d (`client_admin` opt-in)                         | Stricter instance and assurance limits; snapshotted at approval | design §5.2.2; tasks T40.5, ADR-004      |
| Native refresh family, idle        | 1 h                  | Ceiling 24 h (`client_admin` opt-in)                        | MUST be ≤ absolute; stricter instance and assurance limits      | design §5.2.2; tasks T40.5, ADR-004      |
| Refresh retry receipt and envelope | 30 s from commit     | Maximum 30 s, non-sliding                                   | Successor current and unconsumed, cached access token unexpired | design §5.2.2; tasks §3 "One-time state" |
| Rust client exact-retry window     | 30 s from first send | Never later than the server receipt deadline                | —                                                               | design §5.2.2; tasks T40.5               |
| WIF refresh credential             | None issued          | —                                                           | —                                                               | design §5.3, §5.7                        |
| Bearer server-streaming response   | —                    | Ends by the original access token `exp` (≤ 300 s remaining) | Earlier required live denial                                    | design §6.1; tasks T26.6                 |

- **LT-010** Refresh family limits MUST be snapshotted at explicit browser
  approval. Increases MUST apply only to newly approved families, never to an
  existing family or `HumanAuthentication`. (design §5.2.2)
- **LT-011** Rotation and refresh MUST NOT reset the absolute deadline or
  `auth_time`. An exact retry MUST NOT advance the idle, `auth_time` or
  absolute deadlines and MUST recompute `expires_in` from the remaining
  lifetime. (design §5.2.2)
- **LT-012** After the 30-second retry window, ordinary consumed-token replay
  handling MUST apply. (design §5.2.2)
- **LT-013** Offline access tokens retain residual validity until expiry, at
  most 300 seconds. Already-issued internal assertions retain only their
  residual lifetime. No instantaneous cancellation is promised. (design §6.1;
  tasks T20.7, A21)
- **LT-014** Bearer streams MUST NOT be extended by refresh or WIF
  reacquisition. The client reconnects with a fresh credential and an
  application cursor or range. (design §6.1; tasks T26.6, A12)

## 3. Browser and native flow state

| Item                                                     | Lifetime                                           | Rules                                                                                                                                                             | Source                                                    |
| -------------------------------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `__Host-skyoauth_login` and `BrowserFlowBinding`         | Default 10 min; ceiling 15 min                     | Consumed at callback; a new flow in the same slot invalidates the old one                                                                                         | design §5.1; lead decision (OQ-LT-1)                      |
| `OIDCTransaction`                                        | Default 10 min; ceiling 15 min (`expires_at`)      | One-time; consumed atomically with session creation                                                                                                               | design §5.1; tasks §3; lead decision (OQ-LT-1)            |
| `__Host-skyoauth_native` and `OAuthAuthorizationRequest` | Default 10 min; ceiling 15 min (`expires_at`)      | Rotated at issuer callback with the original `expires_at` kept (LT-024); consumed at approval, denial or expiry; a new native start invalidates the previous slot | design §5.2; tasks T40.12; lead decision (OQ-LT-1)        |
| `OAuthAuthorizationCode`                                 | Default 60 s; ceiling 5 min (`expires_at`)         | Single use across replicas                                                                                                                                        | design §5.2; tasks §3; lead decision (OQ-LT-1)            |
| Native loopback listener                                 | Bounded; not specified                             | Closed after success, cancellation or timeout                                                                                                                     | design §5.2, §10.3; tasks T40.9                           |
| `Session` idle                                           | Default 8 h; ceiling 24 h (`idle_timeout_seconds`) | Coalesced last-seen writes MUST NOT revive an expired session; bounded early idle expiry from coalescing is documented                                            | design §5.1; tasks T10.10, T31.2; lead decision (OQ-LT-2) |
| `Session` absolute                                       | Default 24 h; ceiling 7 d (`absolute_expires_at`)  | Never extended by activity, streams or rechecks                                                                                                                   | design §5.1, §6.1.1; tasks T31.2; lead decision (OQ-LT-2) |
| Browser `HumanAuthentication`                            | Not specified (`expires_at`)                       | Bound to provider and tenant epochs                                                                                                                               | design §5.1; tasks §3                                     |
| Native `HumanAuthentication`                             | Refresh family and stricter authentication bound   | Not capped by the first access token's 300 s                                                                                                                      | design §5.2.2; tasks §3 "One-time state"                  |
| Session CSRF token                                       | Session lifetime                                   | Session-bound                                                                                                                                                     | design §5.1                                               |

- **LT-020** A session MUST be usable only before both its idle and absolute
  deadlines, on its registered origin and tenant, with live principal,
  authentication and provider epoch. (design §5.1; tasks A33)
- **LT-021** Stream traffic and continuation rechecks MUST NOT extend session
  idle or absolute expiry. (design §6.1.1)
- **LT-022** Native confirmation denial or expiry MUST create no code, consume
  the confirmation state and clear its cookie. (design §5.2)
- **LT-023** The login flow, `OIDCTransaction`, native authorization request
  (`__Host-skyoauth_native` and `OAuthAuthorizationRequest`), authorization
  code and session lifetimes in the table above MUST be instance-configurable
  within their ceilings; LT-006 applies to out-of-range values. (lead decision,
  OQ-LT-1, OQ-LT-2; native authorization request: Decided (lead decision,
  2026-11-19))
- **LT-024** Rotating `__Host-skyoauth_native` at the issuer callback MUST
  keep the original `expires_at` of the native authorization request. Rotation
  MUST NOT reset, restart or extend its lifetime (default 10 min, ceiling
  15 min), consistent with the no-extension rule (LT-001). (OQ-LT-1:
  Decided (lead decision, 2026-11-19))

## 4. Epochs, revisions and generations

These values have no lifetime. They are monotonic and are never reset.

| Value                                                      | Advances on                                                                                                                                                                     | Never                                                                                                         | Source                                                         |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `HumanProvider.auth_epoch`                                 | Provider switch, rollback, initial activation                                                                                                                                   | Advanced by credential-only rotation or by the deliberate compromise transition; reset by rollback or restore | design §5.1.1, §7.3; tasks §3                                  |
| `TenantLoginState.auth_generation`                         | Provider switch, rollback, initial activation; the deliberate compromise transition, which advances only this value, per tenant, without a provider change (public-api API-154) | Advanced by credential-only rotation; reset by rollback or restore                                            | design §5.1.1, §7.3; tasks §3, T13.9; lead decision (OQ-TM-14) |
| Parent `security_revision`                                 | Security disable; re-enable through `reenable_targets`                                                                                                                          | Restored by rollback or abort                                                                                 | design §4.2                                                    |
| Runtime `active_generation`                                | Activation, `complete_abort`                                                                                                                                                    | Reset by restore                                                                                              | design §4.2                                                    |
| Controller and scope `owner_epoch`, observation `sequence` | Claim; each report                                                                                                                                                              | Reset by failover                                                                                             | design §4.2                                                    |
| TLS `material_sequence`                                    | Single-candidate convergence or recovery                                                                                                                                        | Reset by plan or pin change                                                                                   | design §4.2                                                    |
| `hold_generation`, guard `generation`                      | Hold and guard changes                                                                                                                                                          | Lowered; equal counters with a different spec are rejected                                                    | design §4.2                                                    |

- **LT-030** Rollback MUST use fresh monotonic epochs and MUST NOT reset
  generations. (design §7.3; tasks T10.6, T51.8)

## 5. Stream continuation leases

| Item                                      | Default       | Ceiling or maximum                                                                                                    | Who sets                                     | Source                              |
| ----------------------------------------- | ------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ----------------------------------- |
| Route `session_lease_seconds`             | 15 s          | Bounded by the action's `max_session_lease_seconds`                                                                   | Tenant `client_admin` (route version)        | design §6.1.1; tasks T14.4          |
| Action `max_session_lease_seconds`        | 15 s          | 15 s for critical or mutating actions; up to 300 s only for explicitly classified noncritical read-only actions       | Instance `security_admin` (`ResourceAction`) | design §6.1.1; tasks T14.4, ADR-010 |
| Continuation absolute deadline            | —             | Maximum 1 h from creation; route or action policy may shorten                                                         | Route and action                             | design §6.1.1; tasks T32.12         |
| Effective lease                           | —             | Minimum of route and action limits, session and authentication expiry, observation deadline and continuation deadline | Computed                                     | design §6.1.1                       |
| Revocation residual after an allow        | —             | The selected remaining lease (15 s default; 300 s opted-in maximum)                                                   | —                                            | design §6.1.1; tasks T51.4          |
| Admission-`jti` tombstone                 | —             | At least through assertion expiry plus skew                                                                           | —                                            | design §6.1.1                       |
| Closed-context identity for close retries | Not specified | "Long enough for bounded idempotent retries"                                                                          | —                                            | design §6.1.1                       |
| Orphan occupancy after a lost close       | —             | Until its last lease expires                                                                                          | —                                            | design §6.1.1; tasks A56            |

- **LT-040** Renewal after `authorized_until` or after the continuation's
  absolute deadline MUST deny, even when the session remains live. (design
  §6.1.1; tasks §3 "Stream state")
- **LT-041** On terminal denial the backend MUST stop protected transmission
  immediately; when the checker or store is unavailable it MUST stop by the
  last successful deadline. No fail-open stream grace exists. (design §6.1.1)
- **LT-042** A missing, late or unavailable batch item MUST NOT extend that
  item's previous lease. (design §6.1.1)
- **LT-043** Expired contexts MUST stop counting toward capacity without waiting
  for a cleanup job. (design §6.1.1)
- **LT-044** Renewals MUST be scheduled with jitter before each earliest
  deadline and MUST NOT be delayed to fill a batch. (design §6.1.1)
- **LT-045** The one-hour cap deliberately interrupts unfinished downloads;
  resumable APIs use stable object versions and ranges. (design §6.1.1; tasks
  A12)

## 6. Route observation and activation

| Item                                 | Value                                                        | Rules                                                                                                                           | Source                   |
| ------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| Proxy poll interval                  | At least every 10 s                                          | Per traffic-eligible proxy, plus configuration and membership watch                                                             | design §4.2; tasks T00.6 |
| Stale mark and alert                 | 30 s from sample collection start                            | Same reference point as the 300 s bound (lead decision, OQ-LT-9)                                                                | design §4.2              |
| Last-known-good deployment evidence  | Maximum 300 s from sample collection start                   | Only with unchanged `deployment_version_id` and serving-set generation, equivalent registry version, no apply or known mismatch | design §4.2; tasks T00.6 |
| Registry-only activation freshness   | Complete observations no older than 30 s                     | Retains original sample ages; cannot extend the 300 s bound                                                                     | design §4.2; tasks T14.9 |
| TLS recovery evidence freshness      | Complete evidence no older than 30 s                         | Original sample collection times unchanged                                                                                      | design §4.2              |
| New proxy grace                      | None                                                         | Outside readiness until verified                                                                                                | design §4.2              |
| Known out-of-plan mismatch allowance | None                                                         | Immediate closure; no 30 s or 300 s allowance                                                                                   | design §4.2; tasks A58   |
| Gateway apply allowance              | None                                                         | Gate closed from `begin`                                                                                                        | design §4.2; tasks T00.6 |
| `apply_timeout_seconds`              | Default 120 s                                                | Positive; at most the instance ceiling, which is instance-configurable and hard-capped at 300 s (lead decision, OQ-LT-6)        | design §4.2; tasks §3    |
| `apply_deadline`                     | `min(begun_at + apply_timeout_seconds, approval.expires_at)` | Persisted at `begin`; survives takeover                                                                                         | design §4.2; tasks §3    |
| Service deadline reconciler          | At least every 10 s                                          | Every transition also enforces deadlines                                                                                        | design §4.2              |
| Forward approval `expires_at`        | Not specified                                                | Bounds forward execution only                                                                                                   | design §4.2              |
| `abort_until`                        | Explicit, finite, later than `expires_at`                    | At most a documented instance maximum, not specified (OQ-LT-4)                                                                  | design §4.2; tasks §3    |
| Controller ownership lease           | Not specified                                                | Fenced epoch; no observation-age reset                                                                                          | design §4.2              |

- **LT-050** Sample age MUST be measured from collection start. Network delay,
  controller restart and failed polls MUST NOT advance it, and a 40-second
  controller reschedule MAY preserve an unchanged deployment while five
  minutes of unobservability MUST NOT. (design §4.2)
- **LT-051** Assertions and leases MUST be capped by the remaining observation
  validity and all session and policy bounds. (design §4.2)
- **LT-052** `activate` at or after `apply_deadline` MUST reject even if the
  reconciler has not run. A proxy that never produces the matching digest
  MUST trigger abort at the apply deadline, not when the approval expires.
  (design §4.2)
- **LT-053** `apply_timeout_seconds`, forward `expires_at` and `abort_until`
  MUST have distinct meanings: the first two bound forward execution, the last
  bounds compensation only. All three MUST survive takeover. Forward expiry
  alone MUST NOT stop compensation; revocation of the approval or loss of
  controller scope does, and disabling the preparer or the approving
  `security_admin` does not
  ([gateway-containment.md GW-141, GW-146](gateway-containment.md#114-abort-of-an-unfinished-apply)).
  (design §4.2; tasks T00.6; lead decision, OQ-GW-9; approver: Decided (lead
  decision, 2026-11-19))
- **LT-054** Transient compensation failures MAY retry only within the original
  abort window. At `now >= abort_until` an unfinished attempt MUST become
  `recovery_required`. `abort_until` is not a release of credential holds.
  (design §4.2)
- **LT-055** Stale evidence and compensation MUST NOT extend a stream lease.
  (tasks T00.6)

## 7. TLS renewal

| Item                               | Value                                                                                                                                   | Source                |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `renewal_overlap_seconds`          | Default 120 s; positive; at most the instance ceiling, which is instance-configurable and hard-capped at 300 s (lead decision, OQ-LT-6) | design §4.2; tasks §3 |
| `overlap_until`                    | `min(first_new_seen_at + renewal_overlap_seconds, old certificate's profile-validity cutoff)`                                           | design §4.2; tasks §3 |
| Profile minimum remaining validity | Set by the approved profile; no default given (OQ-LT-15)                                                                                | design §4.2           |
| Accepted candidates                | At most two: current and previous                                                                                                       | design §4.2           |

- **LT-060** `overlap_until` MUST be fixed when a different valid leaf is first
  seen. Same-leaf rewrites, metadata rereads, ownership transfer, other Secret
  writes and plan or pin changes MUST NOT reset it. (design §4.2)
- **LT-061** Overlap MUST NOT reset the observation or lease cutoffs, refresh
  an old sample or extend the 300-second observation bound. (design §4.2;
  tasks T00.6)
- **LT-062** At `overlap_until` without complete convergence, new requests and
  admissions MUST get 503 and existing contexts MUST get unavailable, with no
  renewed lease and no `closed_at`. The deadline MUST NOT be extended.
  (design §4.2)
- **LT-063** Full-convergence recovery MAY reset candidate state only with new
  complete fresh proof under the unchanged contract. It MUST NOT extend an
  expired overlap, make an old sample fresh or revive a closed or expired
  context. (design §4.2; tasks T00.6)

## 8. Keys and verifier caches

| Item                                            | Value                                                         | Source                          |
| ----------------------------------------------- | ------------------------------------------------------------- | ------------------------------- |
| Retired public signing key retention            | Through maximum issued TTL plus skew                          | design §6                       |
| Retired internal assertion key retention        | 30 s assertion lifetime plus skew                             | design §6.2                     |
| Internal key status and provenance records      | Through all dependent continuation deadlines                  | design §6.2; tasks §3           |
| `/internal/v1/assertion-jwks` verifier cache    | Maximum 60 s freshness; no stale-on-error extension           | design §6.2; tasks §3           |
| New internal key `activate_after`               | At least publication + maximum verifier cache interval + skew | design §6.2; tasks §3           |
| Offline verifier lag after internal key disable | At most the remaining cache freshness (≤ 60 s)                | design §6.2                     |
| Unknown-`kid` refetch and negative cache        | Bounded, rate-limited, single-flight; values not specified    | design §6.2                     |
| `oidc_discovery` metadata and JWKS cache        | Bounded refresh, cache and staleness; values not specified    | design §5.4; tasks T11.2, T11.4 |
| TokenReview `review_timeout_ms`                 | Configured per source; no default given                       | design §5.4; tasks §3           |

- **LT-070** Ordinary scale-out of an active signer group MUST NOT need a
  new-key delay; a newly enrolled key's `activate_after` MUST NOT be waived,
  including during compromise recovery. (design §6.2)
- **LT-071** Live admission and rechecks MUST consult authoritative key state;
  continuations admitted under a disabled or compromised key MUST be denied.
  (design §6.2)

## 9. Replay and one-time state retention

| State                                       | Retained                                                              | Source                                 |
| ------------------------------------------- | --------------------------------------------------------------------- | -------------------------------------- |
| Consumed single-use WIF proof               | Through proof `exp` plus skew, across digest-key rotation             | design §5.3; tasks §3 "One-time state" |
| Consumed refresh credential replay metadata | For the family's remaining lifetime                                   | design §5.2.2                          |
| Refresh retry response envelope             | Purged at the 30 s receipt deadline                                   | design §5.2.2; tasks T10.3             |
| Retry correlation metadata                  | After envelope purge, so receipt loss cannot look like plain rotation | tasks §3 "One-time state"              |
| Admission-`jti` tombstone                   | At least through assertion expiry plus skew                           | design §6.1.1                          |
| Credential UID retirement tombstones        | Persist                                                               | design §4.2                            |

- **LT-080** Closing or garbage collection MUST NOT permit a second admission
  with the same assertion. (design §6.1.1)

## 10. Gate outcomes over time

- **LT-090** A real gateway apply, incident re-enable or compensating abort
  MUST close the affected origin's cookie application traffic for the whole
  apply-and-observe cycle; with exactly one route bundle per origin in v0.1,
  this is the bundle's whole origin
  ([gateway-containment.md GW-115](gateway-containment.md#111-activation-modes)).
  Unchanged contexts receive unavailable with no lease extension and stop at
  their existing lease; changed or removed dependencies and security disable
  deny terminally. (design §4.1, §4.2; tasks T00.6, T32.12, ADR-020; lead
  decision, OQ-GW-8)
- **LT-091** Because an apply can take up to the apply timeout while default
  leases are 15 seconds, an apply can interrupt every cookie stream on the
  origin, including unchanged routes. Operators MUST schedule accordingly; no
  uninterrupted-availability guarantee is made. (design §4.2)
- **LT-092** Fixed session and logout routes, native `/oauth/revoke`, verified
  back-channel logout and independent revocation and security-disable
  operations MUST NOT depend on the application route gate. (design §4.2;
  tasks T31.6, T40.15)
- **LT-093** A checker or store outage terminates default-lease streams whose
  last deadline passes; route-observer loss alone follows the separate
  observation bound in §6. (design §6.1.1)
- **LT-094** Activation in either mode and `complete_abort` MUST supersede only
  credentials and contexts whose actual origin or route versions or security
  dependencies changed. An unchanged route MUST NOT be revoked solely because
  the bundle ID or version pointer advanced; its contexts keep only their
  existing lease under LT-090
  ([gateway-containment.md GW-227](gateway-containment.md#13-observation-and-gate-outcomes)).
  (design §4.2 "Immutable configuration versus live state"; tasks §3 "Policy
  revisions"; ADR-007)

## 11. Restore, rollback and break-glass recovery

| Item                               | Value                                                 | Source                                |
| ---------------------------------- | ----------------------------------------------------- | ------------------------------------- |
| Restore issuance quarantine        | Default 15 min; ceiling 60 min; instance-configurable | design §7.2; lead decision (OQ-LT-13) |
| Break-glass recovery challenge TTL | Default 5 min; maximum 15 min; single use             | design §7.2; lead decision (OQ-LT-17) |

- **LT-100** Restore MUST preserve bootstrap-closed and consumed state, or
  quarantine issuance (bounded by the table above) until outstanding state can
  no longer be replayed, or, where consumed state is not preserved and the
  quarantine cannot cover the outstanding state, revoke the affected
  credentials (LT-106). (design §7.2; tasks T10.6, A35; revocation
  alternative: Decided (lead decision, 2026-11-19))
- **LT-101** Rollback and restore MUST NOT revive credentials, consumed proofs,
  refresh state, sessions or continuations, or reset monotonic generations.
  (design §7.2, §8; tasks T10.6, T51.8, T51.9)
- **LT-102** Continuations MUST NOT be restored as live streams; reconnect
  requires fresh admission. (tasks T51.9)
- **LT-103** Route observations are runtime evidence, not restorable
  permission. Restored route bundles MUST be freshly observed before
  activation or eligibility. (design §8; tasks T10.6, T51.9)
- **LT-104** After restore, credential holds, retirement seals and installed
  guards MUST be reconciled before dependency readiness; unresolved fence
  history MUST stay quarantined. (design §4.2; tasks T50.2)
- **LT-105** Abort completion and deliberate rollback MUST NOT restore
  historical security state. (design §4.1, §4.2)
- **LT-106** The restore issuance quarantine is bounded by the table above.
  Outstanding state that could still be replayed after the quarantine ends
  MUST be covered by preserved bootstrap-closed and consumed state (LT-100,
  LT-101), or, where consumed state is not preserved, by revoking the affected
  credentials (LT-101), not by the quarantine alone. (lead decision,
  OQ-LT-13; the second sentence is inferred from LT-100; the revocation
  alternative: Decided (lead decision, 2026-11-19))

  Note: the 60 min quarantine ceiling cannot cover native refresh families,
  whose absolute lifetime can reach 7 d (§2). Outstanding refresh state after
  a restore is therefore covered only by preserved consumed state or by
  revocation of the affected families, never by the quarantine.

- **LT-107** A break-glass recovery challenge MUST expire within its TTL and
  MUST be consumed durably on first use; an expired or consumed challenge
  MUST NOT authorize an operation. (design §7.2; TTL values: lead decision, OQ-LT-17)

## 12. Worked timelines

| Case                            | Inputs                                                                 | Required outcome                                                                                                             | Source                   |
| ------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| Apply deadline                  | Approval `expires_at` 11:00; `begin` 09:28; timeout 120 s              | `apply_deadline` 09:30; activate at or after 09:30 rejects; next ≤ 10 s scan records `abort_required`; takeover cannot reset | tasks T14.9              |
| Disable before activation       | Approval 09:00; disable 09:20; activation 09:30                        | Activation rejects; re-preparation and fresh approval required                                                               | design §4.2; tasks T14.9 |
| Controller reschedule           | 40 s unobservability, unchanged deployment                             | Deployment MAY stay eligible                                                                                                 | design §4.2              |
| Long unobservability            | 5 min unobservability                                                  | Gate closes; contexts get unavailable                                                                                        | design §4.2              |
| Checker outage                  | 20 s outage, 15 s leases                                               | Streams stop at their last deadline                                                                                          | design §6.1.1            |
| TLS late convergence            | New leaf B at 10:00; `overlap_until` 10:02; full convergence 10:03     | 10:02 unavailable (not terminal); 10:03 reopens on fresh complete proof; no revival of closed contexts                       | design §4.2; tasks §3    |
| TLS in-window convergence       | B at 10:00; deadline 10:02; convergence 10:01; served A at 10:01:30    | Previous candidate and timers cleared at 10:01; regression to A terminal                                                     | tasks T32.3              |
| TLS observation gap             | No evidence 10:00:30–10:02:30                                          | Unavailable at the earlier cutoff; never terminal from the gap alone                                                         | design §4.2; tasks §3    |
| Exact rotation with scope PATCH | `begin` 10:00, timeout 300 s, `abort_until` 10:30, apply failure 10:03 | Abort and `complete_abort` before 10:30 with retained S1 proof                                                               | tasks T32.3              |
| Native idle                     | > 70 min without refresh, default versus opted-in idle                 | Default family expires; opted-in family within its idle ceiling continues                                                    | tasks T40.15             |

## 13. Related non-time bounds (informative)

| Item                                    | Value                                                 | Source                     |
| --------------------------------------- | ----------------------------------------------------- | -------------------------- |
| Per-session continuation cap            | Default 8; instance ceiling range 1–64; effective min | design §6.1.1; tasks T14.5 |
| Recheck and close batch                 | At most 100 items and 64 KiB                          | design §6.1.1              |
| Per-session `Retry-After` for one retry | At most 300 s, plus bounded positive jitter           | design §6.1.1; tasks T33.3 |
| Accepted TLS candidates                 | At most 2                                             | design §4.2                |

## Open questions

These are gaps, ambiguities or contradictions in the design and tasks
documents. Entries marked "(contradiction)" are places where the sources
disagree.

Items marked **Decided** record a lead decision; the normative text above
already reflects it, and the design and tasks documents still need the
follow-up amendment. A decision is revisited through an ADR if implementation
shows problems. All other items are not resolved by this contract.

- **OQ-LT-1 — Flow, transaction and code lifetimes.** **Decided** (lead
  decision, 2026-11-19): the OIDC login flow (`__Host-skyoauth_login`,
  `BrowserFlowBinding`, `OIDCTransaction`) defaults to 10 min with a 15 min
  ceiling; the issuer-native authorization code defaults to 60 s with a 5 min
  ceiling and is single use; all are instance-configurable within the
  ceilings (§3, LT-023). The native authorization request
  (`__Host-skyoauth_native` and `OAuthAuthorizationRequest`) is Decided (lead
  decision, 2026-11-19): it uses the same default of 10 min and ceiling of
  15 min, instance-configurable within the ceiling (§3, LT-023). Whether
  rotating `__Host-skyoauth_native` at the issuer callback resets the 10/15 min
  clock is Decided (lead decision, 2026-11-19): rotation keeps the original
  `expires_at`, with no reset and no extension, consistent with the
  no-extension rule (§3, LT-024). No part of this item remains open.
  Original question: T00.6 asks to specify flow and code lifetimes; the
  sources call the login flow cookie and native transaction "short-lived" and
  give `expires_at` fields for `BrowserFlowBinding`, `OIDCTransaction`,
  `OAuthAuthorizationRequest` and `OAuthAuthorizationCode`, but no numbers or
  ceilings.
- **OQ-LT-2 — Session lifetimes.** **Decided** (lead decision, 2026-11-19) in
  part: browser session idle defaults to 8 h (ceiling 24 h) and absolute to
  24 h (ceiling 7 d), instance-configurable within the ceilings (§3, LT-023).
  Still open: the browser `HumanAuthentication` lifetime and the last-seen
  coalescing interval that bounds early idle expiry. Original question: no
  default or ceiling was given for session idle or absolute lifetime.
- **OQ-LT-3 — Refresh idle reset.** The sources define a 1 h default idle
  limit but do not say which events advance `idle_expires_at` (successful
  refresh only, or also live checks).
- **OQ-LT-4 — `abort_until` instance maximum.** Design §4.2 requires
  `abort_until` to be "within a documented instance maximum"; the value and
  where it is configured are not given.
- **OQ-LT-5 — Forward approval expiry.** No default or maximum is given for a
  route-bundle approval's forward `expires_at`.
- **OQ-LT-6 — Ceiling semantics.** **Decided** (lead decision, 2026-11-19):
  the ceiling is instance-configurable and hard-capped at 300 s (§6, §7).
  Still open: where the ceiling is configured. Original question: for
  `apply_timeout_seconds` and `renewal_overlap_seconds` the sources say "at
  most the instance ceiling of 300 seconds", without saying whether 300 s is
  a fixed maximum or an instance-configurable ceiling capped at 300 s.
- **OQ-LT-7 — Instance refresh limits.** Refresh limits are "within any
  stricter instance/assurance limits", but no instance-level refresh limit
  field exists in the logical model.
- **OQ-LT-8 — Controller and scope ownership leases.** Route-bundle
  `owner_lease_until` and protection-scope `owner_lease_until` have no
  duration.
- **OQ-LT-9 — Stale reference point and observation fields.** **Decided**
  (lead decision, 2026-11-19) in part: the 30 s stale threshold is measured
  from sample collection start, like the 300 s bound (§6). Still open:
  `RouteBundleObservation.fresh_until` and `valid_until` are not defined.
  Original question: the 30 s stale threshold had no stated reference point.
- **OQ-LT-10 — Closed-context retention.** Closed-context identity is kept
  "long enough for bounded idempotent retries" without a value.
- **OQ-LT-11 — Cache values.** Unknown-`kid` refetch rate limit and negative
  cache duration, and `oidc_discovery` refresh and staleness bounds, are not
  given.
- **OQ-LT-12 — Lease safety margin.** Local continuation deadlines subtract a
  "safety margin" whose size is not specified.
- **OQ-LT-13 — Restore quarantine duration.** **Decided** (lead decision,
  2026-11-19): default 15 min, ceiling 60 min (§11, LT-106). Because refresh
  families can last up to 7 days, longer-lived outstanding state relies on
  preserved consumed state or, where that is not preserved, on revoking the
  affected credentials, rather than on the quarantine (LT-100, LT-106).
  Original question: restore must quarantine issuance "until outstanding
  state can no longer be replayed"; the quarantine length and how it is
  computed were not stated.
- **OQ-LT-14 — ADR-010 record (contradiction).** **Decided** (lead decision,
  2026-11-19) and resolved: ADR-010, published in `docs/adr` (item 19), carries
  the clause "Real gateway
  apply/compensation closes origin cookie admissions; unchanged contexts get
  unavailable only to their existing lease; fixed
  session/logout/revoke/back-channel/security-disable cleanup stays
  independent of the route gate." Original question: T00.6 requires the full-origin apply
  interruption and cleanup independence to be recorded in ADR-010 and
  ADR-020; ADR-020 in tasks §11 records both, ADR-010 records neither. The ADR
  table is outside this contract and was not changed.
- **OQ-LT-15 — TLS minimum remaining validity.** The `tls_renewal` profile
  pins a minimum remaining validity, but no default or floor is given.
- **OQ-LT-16 — Clock skew and `Retry-After` bounds.** **Decided** (lead
  decision, 2026-11-19) for skew: default 60 s, ceiling 120 s (Terms; same
  decision as OQ-TP-10). The bound on `Retry-After` for 503 results is
  Decided (lead decision, 2026-11-19) in the related contract: clients honor
  a valid 503 `Retry-After` of at most 300 s (ERR-047, OQ-ERR-4 in
  [errors-retry.md](errors-retry.md#open-questions)). No part of this item
  remains open. Original question: the
  maximum skew and the `Retry-After` bound were open and affect every
  retention row above that adds skew.
- **OQ-LT-17 — Break-glass recovery challenge TTL.** **Decided** (lead
  decision, 2026-11-19): default 5 min, maximum 15 min (§11, LT-107).
  Follow-up: add the values to design §7.2. Original question: design §7.2
  calls the recovery challenge "short-lived" and single use without a
  number.
