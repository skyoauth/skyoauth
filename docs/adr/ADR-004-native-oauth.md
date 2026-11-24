# ADR-004: Native OAuth and required refresh

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The direction is accepted; lead decisions, text marked "(inferred)" and provisional lead picks stay implementation choices that ordinary review can change, while a change to a user ruling goes back to the user (design §12; [status values](README.md#status-values)). Questions still marked open under Open questions stay open: ratification closes none of them.
- **Tasks:** ratified with T00.8 (native comparison and required refresh) and
  T00.17 (request-comparison vectors, plain refresh versus the optional retry
  extension) (inferred: tasks §2 names no ADR in these tasks). Implementation:
  T40.1–T40.15, T26.6 (native), T51.5.
- **Baseline (tasks §11):** "Rust PKCE/system browser/issuer
  cookie/comparison/fresh approval and required rotating refresh. Plain standard
  refresh works without ID; optional 30s encrypted exact-retry extension used by
  Rust, not sender constraint. Defaults 12h/1h, opt-in maxima 7d/24h within
  stricter limits, no old-family extension. Sender-constrained retry and device
  flow deferred."
- **Contracts:** [public-api.md](../contracts/public-api.md) §2, §2.1, §8;
  [errors-retry.md](../contracts/errors-retry.md) §3, §6, §8;
  [lifetimes.md](../contracts/lifetimes.md) §2, §3;
  [token-profiles.md](../contracts/token-profiles.md) §5, §8;
  [identity-registry.md](../contracts/identity-registry.md) §6.

## Context

The Rust CLI is a public client of SkyOAuth, not of the upstream human provider.
It uses the stable issuer `/oauth/authorize` and `/oauth/token`, a registered
generated `client_id`, S256 PKCE and an IP-loopback redirect (design §5.2). A
`client_id` identifies configuration and tenant but does not authenticate a
local process, so a malicious local program can start its own PKCE flow and
loopback listener (design §5.2, §9; A27). Access tokens are capped at 300
seconds, so a usable CLI needs renewal without a browser prompt on every renewal
(tasks §0; design §5.2.2).

T00.8 asks M0 to ratify "native comparison/required refresh"; T00.17 asks it to
"freeze request-comparison vectors, plain OAuth refresh versus optional
retry-extension semantics ... Rust always uses the retry ID, but standard
clients may omit it." The native browser state itself (flow cookie, transaction,
code) is stored as in ADR-003; the `human_cli` profile is ADR-019.

## Decision

### Issuer-origin flow

1. **Authorize.** `/oauth/authorize` resolves the globally unique registered
   client and its tenant, validates redirect, audience and scopes against the
   registration and the instance audience assignment, creates an
   `OAuthAuthorizationRequest`, and sets `__Host-skyoauth_native` on the issuer
   origin with the same secure host-only attributes and a short transaction
   lifetime (design §5.2; T40.1, T40.12).
2. **Issuer callback.** Upstream authentication returns to an issuer callback
   registered on the tenant's `HumanProvider`, never the app-origin callback.
   Which callback depends on the provider (OQ-TM-4; T30.1, T40.12):
   - **Provider advertises RFC 9207.** It returns to the fixed issuer
     `/oauth/callback`, and the callback checks the authorization-response `iss`
     against that provider's expected issuer before any code exchange; a
     mismatched `iss` denies, and so does a missing one (inferred, RFC 9207
     §2.4).
   - **Provider does not advertise RFC 9207.** It returns to its own
     per-provider issuer callback path, server-generated in the reserved form
     `/oauth/callback/{provider_id}` and never tenant-supplied. The validator
     rejects a collision with another SkyOAuth endpoint or provider path. The
     path is an exact registered issuer route with the same cookie exemption and
     checks as `/oauth/callback` (ADR-007 item 7). The callback denies, before
     any code exchange, a response that arrives on a path other than the one
     registered for the transaction's provider (inferred). Adding the path is a
     system-bundle apply that must finish before the provider is tested or used
     for native login.

   Either callback checks state, the native flow cookie, expected issuer, client
   and callback, PKCE, nonce, epoch and ID token, stores the verified human on
   the request, and rotates the issuer-local flow secret before confirmation.
   Native and app flow cookies are never interchangeable (design §5.2; T40.12).
   Decided (lead decision, 2026-11-19, OQ-TM-4; design §5.2 and the tasks are
   amended; only the API-032 contract amendment is still pending).

3. **Fresh explicit approval.** Every new loopback authorization requires
   explicit SkyOAuth approval at `/oauth/confirm`, showing the registered client
   name, account, audience and scopes, approved native-session duration, exact
   loopback destination and the comparison value, with a warning that the public
   client ID does not prove the local program's identity. The POST requires the
   exact issuer Origin, CSRF, anti-framing, the matching rotated flow binding,
   request digest, principal and unexpired provider epoch. Prior consent or
   existing SSO never auto-approves (design §5.2; RFC 8252 §8.6; T40.2, T40.3).
4. **Superseded tabs.** A new native start invalidates the previous cookie slot;
   stale or conflicting tabs show an explicit superseded-login error and require
   a deliberate restart, never silent approval or a redirect to the replacement
   flow (design §5.2).
5. **Code.** Approval binds a one-time code to the exact client, redirect, PKCE
   challenge, audience, scopes and authentication; only then is it redirected to
   the loopback listener. Denial or expiry creates no code. Codes are single use
   across replicas (design §5.2; T40.3).
6. **Client side.** The Rust crate uses an external system browser and an
   ephemeral listener bound only to an IP loopback address, chooses the port
   before authorization, matches the exact chosen redirect at redemption, checks
   its own state and callback path, and closes the listener on success,
   cancellation or timeout. No embedded webview, password or static client
   secret fallback (design §5.2, §10.3; T40.9).

### Comparison v1

7. Before opening the browser, the crate exposes an immutable confirmation
   descriptor; the reference CLI prints the exact loopback URI and port and a
   grouped comparison value. The page derives the value from its stored
   validated transaction, never from a caller-supplied display parameter, and
   approval requires an explicit "matches my CLI" acknowledgement (design
   §5.2.1; T40.2, T40.14).
8. The value is SHA-256 over the length-prefixed (four-byte big-endian) UTF-8
   fields `skyoauth-native-confirm-v1`, `client_id`, exact `redirect_uri`,
   `code_challenge`, `S256`, exact audience, canonical scope string and client
   state; the first 10 digest bytes are shown as unpadded uppercase RFC 4648
   Base32 grouped 4-4-4-4. The design §5.2.1 literal vector
   (`KY75-SZUP-3YVE-VIA3`) is shared by server and Rust tests. The PKCE verifier
   is never displayed or transmitted (design §5.2.1).
9. This is a user-assisted correlation defense, not phishing resistance, a
   second factor or protection from a local attacker that can read the CLI's
   secrets (design §5.2.1).

### Required rotating refresh

10. **Family.** A successful code exchange issues an access JWT capped at 300
    seconds and a rotating SkyOAuth refresh credential in one
    `CLIRefreshFamily`: tenant, actual client, principal, `HumanAuthentication`
    and provider epochs, one audience and the approved scope ceiling. There is
    at most one family per native authentication, client and audience tuple
    (design §5.2.2; T40.5).
11. **Limits.** Defaults are 12 hours absolute and 1 hour idle. An audited
    `client_admin` `HumanAccessPolicy` change may opt into at most 7 days
    absolute and 24 hours idle, within any stricter instance or assurance limit;
    durations are positive and idle is at most absolute. These are product
    limits, not OAuth-mandated values (design §5.2.2).
12. **No old-family extension.** Limits are snapshotted at browser approval.
    Increases apply only to newly approved families; tightening permanently
    narrows or revokes affected families. Neither rotation nor refresh resets
    the absolute deadline or `auth_time`; elapsed or revoked state is never
    resurrected (design §5.2.2; T40.5).
13. **Plain standard refresh.** `grant_type=refresh_token` with `refresh_token`,
    `client_id` and optional narrowing `scope` works without any private
    parameter: ordinary one-time rotation, no retry receipt, and reuse of a
    consumed credential revokes the family, including a retry that adds an ID
    afterwards. A lost response may require new interactive authorization
    (design §5.2.2).
14. **Optional exact-retry extension.** `skyoauth_refresh_request_id`, when
    present, is an independent 256-bit CSPRNG value as unpadded base64url;
    empty, malformed or duplicate values are `invalid_request`. The first
    success stores a receipt with a non-sliding 30-second deadline and the
    already-issued values in an authenticated-encrypted envelope under a
    separate protected key outside the database. An exact same-token, same-ID,
    same-payload retry returns the same values with recomputed `expires_in` only
    while the successor is current and unconsumed and authorization remains
    valid. A different ID or payload is replay; a missing or undecryptable
    receipt or unavailable store fails closed; omitting or changing the ID
    cannot downgrade an extension attempt (design §5.2.2; T40.5).
15. **Not sender constraint.** A stolen token together with its request ID can
    recover the same result within the window; this bounded replay trade-off is
    stated, not hidden (design §5.2.2).
16. **Rust behavior.** The Rust client always sends the ID, serializes refresh
    across processes, persists the pending token, ID and exact payload securely
    (or in an explicitly memory-only session) before sending, never retries
    without the ID after an extension failure, and stops recovery within 30
    seconds of the first send. Persistence uses a supported OS credential store
    or explicit memory-only storage, never plaintext (design §5.2.2; T40.5,
    T40.10).
17. **Live state.** Each refresh rechecks client, audience assignment,
    principal, `HumanAccessPolicy`, authentication, epochs and family deadlines
    and never exceeds the approved scopes. Live checks resolve the unique family
    from the signed authentication reference, actual `client_id` and audience
    and deny if it is absent or revoked (design §5.2.2, §6.1).
18. **Revoke.** `/oauth/revoke` is required in M4, checks the token-to-client
    binding and revokes the family and associated authentication with a
    non-enumerating response, independently of the application route gate
    (design §5.2.2, §4.2; T40.15).
19. **No mutation replay.** Refresh never retries the original API operation;
    WIF and SPA JavaScript receive no refresh credential (design §5.2.2;
    ADR-016, ADR-017).

### Deferred

20. Sender-constrained retry and the device flow are deferred. The device flow
    is conditional and would need user-code verification and equivalent explicit
    approval; its endpoints are absent in v0.1 (design §5.2; tasks §2 "Endpoint
    matrix"; T40.6).

## Consequences and requirements

- Contract requirements: API-020 to API-025 (codes and refresh), API-030 to
  API-038 (authorize, callback, confirmation), API-040, API-041 (revoke),
  ERR-021, ERR-022 (replay revocation and fail-closed receipts), ERR-042,
  ERR-043 (Rust and exact retry), ERR-045 (no API-operation retry), ERR-051
  (no-store), ERR-063 (cancel closes the listener), LT-005, LT-010 to LT-012
  (family limits and retry window), LT-022 to LT-024 (confirmation and native
  request lifetimes), TP-081 (family resolution in live checks), IR-064 (omitted
  scope on refresh).
- A ten-minute command renews 300-second access without another browser prompt;
  expiry, revocation and non-idempotent replay require reauthentication (tasks
  Gate M4).
- Generic OAuth clients can refresh but get no idempotent-retry guarantee
  (design §5.2.2).
- Conformance rows: A27, A34, A41, A52, A57, A59; with migration, A14 and A42.

## Alternatives considered

- **Long-lived access JWTs.** Rejected; access stays at most 300 seconds (design
  §5.2.2).
- **Mandatory private retry parameter for all clients.** Rejected; plain
  standard refresh works without it (design §5.2.2; T00.17).
- **Sender-constrained retry.** Deferred (tasks §11).
- **Device flow.** Conditional and deferred (design §5.2; T40.6).
- **Embedded webview, password or static client secret.** Rejected (design
  §10.3; T40.9).
- **Auto-approval from prior consent or live SSO.** Rejected (design §5.2; A27).
- **Plaintext refresh storage fallback.** Rejected (design §5.2.2; T40.5).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-API-4** — the authorize audience parameter name and the full authorize
  and code-redemption parameter lists (open).
- **OQ-API-8** — metadata content and advertised grants (open).
- **OQ-API-9** — whether `/oauth/revoke` accepts access tokens or a
  `token_type_hint` (open).
- **OQ-ERR-3** — OAuth `error` values. Decided (lead decision, 2026-11-19) for
  the WIF exchange profiles only (ADR-015); the values for refresh overrides,
  unknown clients and revoked or expired families remain open.
- **OQ-ERR-6** — status of the superseded-login error (open).
- **OQ-ERR-7** — HTTP status and OAuth error when the retry store is unavailable
  (open).
- **OQ-LT-1** — native request and code lifetimes. Decided (lead decision,
  2026-11-19): request 10 min (ceiling 15 min), code 60 s (ceiling 5 min);
  rotation keeps the original `expires_at`.
- **OQ-LT-3** — which events advance a refresh family's `idle_expires_at`
  (open).
- **OQ-LT-7** — no instance-level refresh limit field exists in the logical
  model (open).
- **OQ-IR-11** — duplicate scope tokens in a refresh `scope` parameter (open;
  lead lean recorded).
- **OQ-TM-4** — mix-up defense at the shared issuer callback. Decided (lead
  decision, 2026-11-19): RFC 9207 `iss` check where advertised, otherwise
  per-provider callback paths; carried into item 2.
- **OQ-TM-5** — native redirect matching. Decided (lead decision, 2026-11-19):
  scheme `http`, IP literal and path fixed, port bound per transaction,
  `localhost` rejected.

New questions raised by this ADR:

- **OQ-ADR004-1 — Retry-envelope key lifecycle.** Design §5.2.2 keeps the retry
  envelope under "a separate protected encryption-key reference" outside the
  database and separate from signing keys. Who provisions it, how it rotates,
  and whether an in-window receipt sealed under the previous key stays
  recoverable after rotation are not stated. Open; to be decided before M4 (lead
  decision, 2026-11-19).
- **OQ-ADR004-2 — Displayed session duration.** The confirmation page shows the
  "approved native-session duration" (design §5.2) and "the browser displays
  these limits at initial approval" (design §5.2.2). Whether the page shows both
  the absolute and the idle family limit, or a single value, is not stated.
  Open; to be decided before M4 (lead decision, 2026-11-19).

## Tests

- A27, A59 — live SSO and a concurrent malicious local PKCE/loopback request:
  explicit confirmation, matching descriptor only for the exact request, deny or
  expiry yields no code.
- A52 — issuer callback and confirmation with the correct native binding;
  transaction ID or app cookie alone denies.
- OQ-TM-4 mix-up — with an RFC 9207 provider, a missing or wrong `iss` denies
  before code exchange; with a provider without it, the native flow completes
  through its `/oauth/callback/{provider_id}` path, and a response for that
  provider on `/oauth/callback` or another provider's path denies before code
  exchange (T30.1, T40.12).
- A34, A57 — concurrent code and refresh reuse, plain versus extension replay,
  lost reply, family limits and switch.
- A41 — packaged crate in an independent CLI on Linux, macOS and Windows with
  default and minimal features.
- A14, A42 — prebuilt Rust CLI unchanged across a provider switch.
- Task tests: T40.8, T40.14, T40.15, T52.3, T26.6 (native).
