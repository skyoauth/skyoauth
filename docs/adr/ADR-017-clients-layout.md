# ADR-017: Client libraries and repository layout

- **Status:** Ratified, M0 — directionally (maintainer, 2026-11-24). The direction is accepted; lead decisions, text marked "(inferred)" and provisional lead picks stay implementation choices that ordinary review can change, while a change to a user ruling goes back to the user (design §12; [status values](README.md#status-values)). Every question under Open questions is already decided; ratification adds no decision.
- **Tasks:** ratified with T00.13 (which names ADR-017) and T00.14
  (bootstrap-aware layout and gates) (the T00.14 pairing is inferred from its
  wording). Implementation: T21.9, T33.1–T33.8, T40.7, T40.9–T40.11, T13.10,
  T50.8.
- **Baseline (tasks §11):** "Preserve service/TypeScript bootstrap; mandatory
  SPA npm package and reusable clients/rust crate, thin native cli/;
  artifact/platform gates"
- **Contracts:** [errors-retry.md](../contracts/errors-retry.md) §6, §9;
  [token-profiles.md](../contracts/token-profiles.md) §1;
  [public-api.md](../contracts/public-api.md) §3.

## Context

PR #2 landed a bootstrap at `8f81df23efd4c4a0cfe522f711a9ca56f294aab1` with
`service/`, a root Cargo workspace, `clients/typescript/` (npm
`@skyoauth/client`, with an unauthenticated `health()` helper) and CI (tasks §1;
design §10.4). SkyOAuth needs two first-class client libraries with different
credential models: a browser SPA library that never sees a token, and a Rust
library for user-owned CLIs and workload tooling (design §10.1). Migration
compatibility is proven by reusing the same prebuilt artifacts across a provider
switch (design §8 step 6), so the libraries' identities, platforms and fixtures
must be fixed in M0. T00.13 asks for "both client library contracts,
package/crate identities, supported browser/native environments, typed errors
and migration fixtures"; T00.14 asks to adopt the tasks §1 layout and "specify
manifest/CI/packaged-consumer gates".

## Decision

### Preserve the bootstrap

1. Keep `service/`, the root Cargo workspace, `clients/typescript/` and CI.
   Server components start as modules under `service/src`, extracting `crates/`
   only for justified reuse or isolation. No duplicate service under
   `crates/server`, no competing `packages/browser` or `crates/client` homes and
   no stale `packages/*` layout (design §10.4; tasks §1).
2. Add members with their implementations, not empty scaffolding that implies
   authentication support: `operator/` in M1a, `clients/rust/` with WIF in M2
   and `cli/` in M4 (design §10.4; tasks §1).
3. The bootstrap `health()` helper is unauthenticated utility code. An
   off-origin health base cannot become an authenticated target (design §10.2;
   T33.7).

### Package identities

4. **TypeScript:** npm `@skyoauth/client` in `clients/typescript/`, required SPA
   library in M3, with `@skyoauth/client/react` and `@skyoauth/client/connect`
   as optional-peer entry points excluded from the framework-neutral core
   (design §10.1, §10.2; T33.1, T33.2).
5. **Rust:** Cargo `skyoauth-client`, imported as `skyoauth_client`, in
   `clients/rust/`; WIF in M2, native in M4 (design §10.1; T21.9).
6. **Reference CLI:** `skyoauth-cli` in `cli/`, a thin consumer: the library
   owns protocol, the CLI owns terminal UX and exit codes (design §10.3; T40.7).
7. **Operator client:** `skyoauth-operator` in `operator/`, not part of either
   client library (design §10.1; ADR-013).
8. The npm and Cargo names are intentionally parallel distributions in separate
   registries, not interchangeable imports; documentation names the language
   explicitly (tasks §1).

### Library contracts

9. **SPA library.** Session and principal state, top-level login, CSRF-protected
   logout, cancellation and authenticated same-origin transport. No token
   getter, no access or refresh tokens in any browser storage, no bearer mixing;
   authenticated targets are same-origin HTTPS with no userinfo and redirects
   are rejected. Unavailable, cancelled and forbidden are distinct from
   unauthenticated; no mutation replay; per-session and shared capacity errors
   are exposed separately (design §10.2; T33.1–T33.7; ADR-010).
10. **Rust library.** Typed configuration and errors, redacted credential
    wrappers, memory-only access cache, cancellation and timeouts, credentials
    attached only to configured HTTPS origins and audiences. Native OAuth uses
    an external system browser and IP-loopback listener (ADR-004). Required
    refresh persists only in a supported OS credential store or an explicit
    memory-only session; never plaintext. No dependency on the service,
    PostgreSQL, operator internals, React, a JS runtime or frontend assets
    (design §10.1, §10.3; T21.9, T40.9–T40.11).
11. **Distinct credential models.** Browser code never gets a token getter,
    native listener or operator key; workload renewal reacquires proofs and
    never gets WIF refresh credentials (design §10.1, §10.3).
12. **Shared fixtures.** Both libraries share versioned wire and error fixtures;
    the fixture-set version, not a body field, versions errors (ERR-071; design
    §10.4). Fixtures live in `tests/conformance/`; each package release ships
    with its fixture-set version (lead decision, 2026-11-19, OQ-ADR017-3).

### Artifact and platform gates

13. **TypeScript.** The packed npm artifact is installed in independent
    `examples/spa`; declarations, exports and a browser bundle without Node
    built-ins, polyfills, React or Connect in the core are verified;
    real-browser tests, not only Node fetch mocks (design §10.2; T33.4, T33.5,
    T33.8). Supported browsers are the current and previous major versions of
    Chrome, Edge, Firefox and Safari (desktop and iOS), tested on Chromium,
    Firefox and WebKit (lead decision, 2026-11-19, OQ-ADR017-1).
14. **Rust.** The packaged crate is compiled by independent `examples/rust-cli`
    without private workspace paths; native support is tested on Linux, macOS
    and Windows with minimal and default feature sets; MSRV, TLS, runtime,
    feature and platform policy is published separately from Linux server
    support (design §10.3; T40.10, T40.11). The policy is a pinned MSRV, rustls
    as the default TLS backend, tokio as the async runtime and a published
    feature matrix (lead decision, 2026-11-19, OQ-ADR017-2).
15. **Operator.** `skyoauth-operator` builds and tests on Linux, macOS and
    Windows independently of server, database and native SDK in M1a (T13.10).
16. **CI with the code.** Each PR adding or moving a member, entry point or
    package updates manifests, exports, lockfiles, CI paths and jobs,
    packed-consumer tests and README together; checks land with T21, T33 and
    T40, not late in M5. The docs-only skip is preserved, and a skipped job is
    not a passed runtime test (tasks §1; T50.8).
17. **Migration.** Prebuilt SPA and Rust CLI artifacts with recorded hashes are
    reused unchanged across provider switch and rollback (design §8 step 6;
    T51.5; ADR-012).

## Consequences and requirements

- Contract requirements: ERR-070 to ERR-072 (versioned shared error fixtures),
  ERR-040 to ERR-049 (client retry behavior), ERR-063 (native cancellation).
- The SPA cannot call APIs on another origin with its session; such APIs need
  their own origin registration (design §10.2).
- Supported browsers must be documented and tested (T33.4).
- Conformance rows: A39, A40, A41, A42; A14 for unchanged artifacts.

## Alternatives considered

- **A second browser core (`packages/browser`) or a `crates/client` home.**
  Rejected (tasks §1).
- **A duplicate service under `crates/server`.** Rejected (design §10.4).
- **Protocol logic in the CLI.** Rejected; the crate owns protocol (design
  §10.3).
- **Token getter or browser token storage in the SPA library.** Rejected (design
  §10.2).
- **Embedded login webview, password or static client secret.** Rejected (design
  §10.3).
- **TypeScript workload helpers in place of the SPA library.** Not a substitute;
  a later separate surface (design §10.2, §11).

## Open questions

Existing contract questions that touch this ADR:

- **OQ-ERR-1** — error envelope. Decided (lead decision, 2026-11-19): errors are
  versioned through the shared fixture set; v0.1 bodies carry no version field;
  401, 403 and generic 503 reasons are `unauthenticated`, `forbidden` and
  `auth_unavailable`.
- **OQ-ERR-2** — Connect codes. Decided (lead decision, 2026-11-19): 401
  `unauthenticated`, 403 `permission_denied`, 429 `rate_limited`
  `resource_exhausted`.
- **OQ-TM-5** — native redirect matching. Decided (lead decision, 2026-11-19):
  the registered rule fixes scheme `http`, IP literal and path; the port is
  bound per transaction; `localhost` is rejected. The Rust crate's listener
  follows it.

New questions raised by this ADR:

- **OQ-ADR017-1 — Supported browser matrix.** Decided (lead decision,
  2026-11-19): current and previous major versions of Chrome, Edge, Firefox and
  Safari (desktop and iOS), tested on Chromium, Firefox and WebKit (item 13).
  Original question: T00.13 asks to freeze "supported browser/native
  environments" and T33.4 requires "tested browser support documented", but no
  source names the supported browsers or versions.
- **OQ-ADR017-2 — Rust MSRV, TLS and runtime.** Decided (lead decision,
  2026-11-19): a pinned MSRV policy, rustls as the default TLS, tokio and a
  published feature matrix (item 14). Original question: Design §10.3 and T40.10
  require publishing MSRV, TLS backend, async runtime and feature policy; none
  is chosen.
- **OQ-ADR017-3 — Fixture home and versioning.** Decided (lead decision,
  2026-11-19): fixtures live in `tests/conformance/`, and each package release
  ships with its fixture-set version (item 12). Original question:
  `tests/conformance/` holds "versioned wire/profile and migration fixtures"
  (tasks §1), but how the TypeScript and Rust packages consume them and how the
  fixture-set version is published with each package release is not stated.

## Tests

- A39 — packed TypeScript core and separately imported adapters.
- A40 — SPA origin, redirect and options attacks.
- A41 — packaged Rust crate on Linux, macOS and Windows with default and minimal
  features.
- A42, A14 — prebuilt consumers through switch and rollback.
- Task tests: T33.5, T33.7, T33.8, T40.8, T40.11, T13.10, T50.8.
