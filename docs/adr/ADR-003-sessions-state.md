# ADR-003: Sessions and one-time state

- **Status:** Proposed, M0 — ratification pending maintainer review.
- **Tasks:** ratified with T00.6 (session, flow, code and epoch lifetimes) and
  the flow-cookie part of T00.16 (inferred: tasks §2 names no ADR in these tasks
  for this decision). Implementation: T10.3, T10.6, T10.9, T10.10, T30.2, T30.6,
  T31.1–T31.7, T40.12, T51.4.
- **Baseline (tasks §11):** "PostgreSQL keyed hashes, explicit
  deadlines/origin/authentication epochs and browser flow bindings"
- **Contracts:** [lifetimes.md](../contracts/lifetimes.md) §3, §4, §11;
  [public-api.md](../contracts/public-api.md) §3, §8;
  [errors-retry.md](../contracts/errors-retry.md) §2, §7;
  [token-profiles.md](../contracts/token-profiles.md) §5.

## Context

The browser path gives JavaScript no OAuth access or refresh token: upstream
OIDC establishes an opaque, Secure/HttpOnly server-side session on the
registered application origin (design §1, §5.1). Native login keeps its own
transaction on the issuer origin (design §5.2; ADR-004). Login CSRF, OIDC
callback injection, mix-up, redirect confusion, session fixation and
identity-linking confusion are named release threats; PKCE, state and nonce do
not help when the transaction is not bound to the initiating browser (design
§5.1, §9; RFC 9700 §§2.1 and 4.7).

T00.6 asks M0 to specify "session/flow/code/epoch/restore lifetimes", and T00.16
to freeze "app/native flow cookies". The logical model holds this state in
`BrowserFlowBinding`, `OIDCTransaction`, `HumanAuthentication`, `Session`,
`OAuthAuthorizationRequest`, `OAuthAuthorizationCode` and the refresh tables
(tasks §3). This ADR records how that state is stored, bound and expired. Native
refresh semantics are ADR-004; provider epochs, their sole routine writer and
the audited compromise transition are ADR-012 and ADR-021; stream continuations
are ADR-010.

## Decision

### Storage

1. **PostgreSQL is authoritative** for all stable authority and one-time state.
   Store failures never expand privilege. Valkey is an optional bounded cache,
   not a required security dependency (design §4, §7).
2. **Keyed hashes, not secrets.** SkyOAuth stores keyed hashes of flow cookies,
   session tickets, authorization codes and refresh tokens, never the plaintext
   values. CSRF verifiers and PKCE context are protected. Raw replay assertions
   are not stored, and cookie hashes are never exposed as backend session
   references (tasks §3 "One-time state"; T10.3). The `human_session` assertion
   carries opaque internal references, never cookie hashes or tickets (design
   §6). The only stored credential values are the opted-in, at most 30-second,
   authenticated-encrypted refresh-retry envelope of ADR-004 (design §5.2.2;
   T10.3). One versioned keyed-hash key, held outside the database, computes
   these hashes; old key versions are kept for lookup until the state that
   depends on them expires (lead decision, 2026-11-19, OQ-ADR003-1).
3. **Backups versus exports.** Encrypted database backups differ from redacted
   configuration exports; neither ordinary YAML nor logs expose cookies, proof
   tokens or refresh credentials (design §7).

### Browser flow bindings

4. **Login transaction.** `/_skyoauth/login` resolves the registered
   `ApplicationOrigin`, its tenant and active provider from the active pinned
   origin configuration, and validates the relative return location (design §5.1
   step 1; T30.2). It generates state, nonce, PKCE S256 and a server-generated
   browser-flow secret, sets the short-lived `__Host-skyoauth_login` cookie
   (Secure; HttpOnly; Path=/; SameSite=Lax; no Domain) and stores only its keyed
   hash in a `BrowserFlowBinding`. The OIDC transaction binds that hash, flow
   kind, origin, tenant, provider and epoch, exact callback and return path
   (design §5.1 step 2).
5. **Callback.** `/_skyoauth/callback` requires both the correct one-time state
   and the initiating browser's matching flow cookie, the exact registered
   origin and callback, the provider epoch, PKCE and a verified ID token. A
   state or transaction ID alone is not browser authentication. A wrong or
   missing browser binding denies without creating, replacing or linking a
   session (design §5.1 step 4; T30.7).
6. **Distinct app and native bindings.** Bindings include origin and flow kind;
   the app-origin `__Host-skyoauth_login` and the issuer-origin
   `__Host-skyoauth_native` cookies and transaction kinds are never
   interchangeable (design §5.2; tasks §3 "One-time state"; T40.12).
7. **One slot, one flow.** Starting a new flow in the same flow-cookie slot
   invalidates the old one; stale tabs restart rather than bypass the binding
   (design §5.1 step 5).
8. **Atomic consumption.** Session creation atomically consumes the login
   transaction and expires its flow binding (design §5.1 step 5).

### Sessions

9. **Opaque ticket.** A fresh CSPRNG session ticket is set as
   `__Host-skyoauth_session` (Secure; HttpOnly; Path=/; SameSite=Lax; no
   Domain). The session row stores its keyed hash, origin, tenant, principal and
   `HumanAuthentication` reference, provider, subject and optional `sid`, idle
   and absolute deadlines and the CSRF verifier (design §5.1 steps 5–6; T31.1).
10. **Both deadlines.** A session is usable only before both its idle and
    absolute deadlines, on its registered origin and tenant, with live
    principal, authentication and provider epoch. Throttled last-seen writes
    never revive an expired session or extend the absolute lifetime; bounded
    early idle expiry from coalescing is documented (design §5.1; T10.10,
    T31.2). Stream traffic and rechecks do not extend either deadline (design
    §6.1.1).
11. **Safe session read.** `GET /_skyoauth/session` returns only safe principal
    and session metadata and a session-bound CSRF token, with no-store (design
    §5.1 step 6; T31.3).
12. **Unsafe calls.** Unsafe cookie calls, including Connect unary POST and
    logout, require the exact `Origin` and `X-SkyOAuth-CSRF` (design §5.1 step
    7; T31.4).
13. **No coupling to upstream tokens.** The browser cookie is not rotated on
    every ext_authz check, and the session lifetime is not coupled to upstream
    token rotation. Upstream access and refresh tokens are discarded after login
    by default (design §5.1).

### Authentication epochs

14. **HumanAuthentication.** Each verified login creates a `HumanAuthentication`
    that links the session (or native refresh family) to the monotonic provider
    `auth_epoch` and tenant `auth_generation` (design §5.1 step 5; tasks §3
    "One-time state").
15. **Invalidation by epoch.** Provider switch and rollback advance the epochs
    atomically and invalidate affected flow bindings, authentication contexts,
    sessions, pending requests and codes, refresh families and dependent
    continuations (design §8 step 4; T51.4). Credential-only rotation keeps the
    epochs (design §7.3; ADR-021). The audited compromise transition advances
    the tenant `auth_generation` without a provider change (OQ-TM-14; ADR-021).
    Rollback uses fresh monotonic epochs and never resets generations (design
    §7.3; T10.6).
16. **Logout targeting.** Local logout revokes the session and authentication
    context. Optional back-channel logout verifies signature, issuer, audience,
    events, time and replay and selects sessions only through indexed provider,
    subject and `sid` selectors (design §5.1 step 7; T10.10, T30.6, T31.6).

### Deadlines and recovery

17. **Explicit deadlines.** Every one-time record carries its own `expires_at`;
    lifetimes and ceilings follow lifetimes §3 (login flow and native request
    default 10 min, ceiling 15 min; code default 60 s, ceiling 5 min; session
    idle default 8 h, ceiling 24 h; absolute default 24 h, ceiling 7 d; lead
    decisions OQ-LT-1, OQ-LT-2).
18. **Restore.** Restore preserves bootstrap-closed and consumed one-time state,
    or quarantines issuance (default 15 min, ceiling 60 min) until outstanding
    state can no longer be replayed. Where consumed state is not preserved and
    the quarantine cannot cover the outstanding state, the affected credentials
    are revoked: the quarantine alone never covers state that outlives it, such
    as native refresh families with an absolute lifetime up to 7 d (LT-100,
    LT-106; revocation alternative: Decided (lead decision, 2026-11-19)).
    Rollback and restore never revive credentials, sessions or refresh state or
    reset monotonic generations (LT-101; T10.6; design §7.2).
19. **Gate independence.** The session and logout routes do not depend on the
    application route gate; they keep their own Origin, CSRF and store checks
    (design §4.2; ADR-010, ADR-020).

## Consequences and requirements

- Contract requirements: API-050 to API-056 (origin resolution, return paths,
  callback binding, Origin and CSRF, safe session read, cookie attributes,
  duplicate cookies), LT-020, LT-021, LT-023, LT-024 (session and flow
  deadlines), LT-030 (fresh epochs on rollback), LT-100, LT-101, LT-106
  (restore), ERR-052 (no-store session read), GW-024 (duplicate cookies reject),
  IR-033 (tenant from the registered origin), TP-041 (human credentials carry no
  WIF claims).
- A database read exposes only keyed hashes, not usable tickets or codes
  (inferred). HttpOnly limits token extraction, not authenticated actions by
  same-origin malicious JavaScript (design §9).
- An idle session may end slightly early because last-seen writes are coalesced
  (design §5.1).
- Conformance rows: A08, A09, A11, A33, A34, A46, A51, A52.

## Alternatives considered

- **State or transaction ID as browser authentication.** Rejected (design §5.1,
  §5.2).
- **Rotating the cookie on every ext_authz check or coupling session lifetime to
  upstream token rotation.** Rejected (design §5.1).
- **Valkey or another cache as a required security dependency.** Rejected; it is
  an optional bounded cache (design §4).
- **Broadening cookie Domain or sharing issuer and app cookies.** Rejected
  (design §4).
- **A non-GET callback response mode.** Needs an explicit tested profile, not a
  weaker cookie fallback (design §5.1 step 3; T30.7).
- **Keeping upstream provider tokens by default.** Rejected; an encrypted
  provider-token vault is an explicit opt-in (design §5.1; ADR-009).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-LT-1** — flow, transaction and code lifetimes. Decided (lead decision,
  2026-11-19): login flow and native request 10 min, ceiling 15 min; code 60 s,
  ceiling 5 min; native cookie rotation keeps the original `expires_at`.
- **OQ-LT-2** — session lifetimes. Decided (lead decision, 2026-11-19) in part:
  idle 8 h (ceiling 24 h), absolute 24 h (ceiling 7 d). Still open: the browser
  `HumanAuthentication` lifetime and the last-seen coalescing interval.
- **OQ-LT-13** — restore quarantine. Decided (lead decision, 2026-11-19):
  default 15 min, ceiling 60 min.
- **OQ-API-1** — login and callback during a closed gate. Decided (lead
  decision, 2026-11-19): not gated; allowed only with an active pinned origin
  version and a security-enabled origin.
- **OQ-API-2** — no operator endpoint revokes a human session, refresh family or
  authentication context (open).
- **OQ-ERR-6** — HTTP status and rendering of `enrollment_required`, the
  superseded-login error and the denied-origin result (open).
- **OQ-TM-4** — mix-up defense. Decided (lead decision, 2026-11-19): RFC 9207
  `iss` check where the provider advertises it, otherwise per-provider callback
  paths.
- **OQ-TM-14** — bulk session revocation. Decided (lead decision, 2026-11-19): a
  revision-checked, audited operation advances the tenant's `auth_generation`
  without a provider change; to be specified before M1b and M3. It is the
  audited compromise transition of ADR-021: tenant `provider_admin` per tenant,
  no single-origin variant; the instance-wide response runs it for every tenant.

New questions raised by this ADR:

- **OQ-ADR003-1 — Hashing key.** Decided (lead decision, 2026-11-19): one
  versioned keyed-hash key outside the database; old versions are kept for
  lookup until dependent state expires (item 2). Original question: The sources
  require keyed hashes for flow cookies, session tickets, codes and refresh
  tokens (tasks §3 "One-time state"; T10.3), and require replay digests to
  survive digest-key rotation (design §5.3; T21.8). They do not say which key
  computes the session, flow, code and refresh hashes, where it is held, or how
  a rotation keeps live sessions and refresh families resolvable.
- **OQ-ADR003-2 — Back-channel logout without `sid`.** Back-channel logout
  selects sessions by "indexed provider/subject/sid selectors" (design §5.1 step
  7; T30.6). Whether a verified logout token that carries `sub` but no `sid`
  revokes every session of that subject for the provider, or is rejected, is not
  stated. Open; to be decided before M1b/M3 (lead decision, 2026-11-19).

## Tests

- A08, A09 — cookie with valid Origin and CSRF gets typed human-session
  evidence; missing Origin or CSRF denies.
- A11 — revoked or expired session, or unavailable store: 401 or 503, no
  fail-open.
- A33 — idle and absolute expiry, session-origin crossover and provider/`sid`
  targeting.
- A34 — switch and rollback invalidate affected human state.
- A35 — restore after proof consumption: consumed stays consumed, or issuance is
  quarantined; where neither covers outstanding state (such as a native refresh
  family), the affected credentials are revoked (LT-100, LT-106).
- A46 — origin-resolved tenant and provider; spoofed Host, Forwarded or tenant
  query denies before redirect.
- A51, A52 — attacker-initiated callbacks and app/native flow-cookie crossover
  deny without creating, replacing or linking a session.
- Task tests: T30.7, T31.5, T31.6, T10.10, T52.3.
