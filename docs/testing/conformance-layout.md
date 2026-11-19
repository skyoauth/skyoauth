# Conformance test layout (proposal)

> Status: proposal only. Nothing below exists yet except the bootstrap `service/tests/shutdown.rs`, the vitest suite in `clients/typescript/test/`, the two 85 % coverage gates and `scripts/ci/docs-only.sh`. Sources: tasks §1, §8 (A01–A64), §9 DAG, §10, T50.8, T51, T52; design §10.

## 1. Layout and ownership

| Home | Holds | Does not hold |
| --- | --- | --- |
| `service/src/**` `#[cfg(test)]`, `service/tests/*.rs`, `clients/*/test(s)/` | Unit tests for one module or package API. These count toward the existing 85 % line gates. They can support a scenario, but a scenario does not count as `implemented` on unit tests alone. | Anything that needs PostgreSQL, Envoy, a cluster or a browser |
| `tests/conformance/` | Versioned wire/profile/migration **fixtures** plus the data-driven tests that replay them against every declared consumer. It also holds the scenario registry. Expected outcomes are fixed here: claim sets, error bodies, digest vectors (A61), comparison vectors (A59), refresh/retry transcripts (A57) and migration decision tables (A15/A42). | Attack-only logic, environment bring-up |
| `tests/security/` | Negative-heavy tests for JWT/OIDC/CSRF/admin/tenant/audience/replay/gateway (T52.1–T52.6), plus fuzz targets and committed seed corpora (T52.7) | Shared positive wire contracts. Those go in conformance and security references them. |
| `tests/integration/` | Real dependencies: PostgreSQL, mock OIDC, two k3s clusters, pinned Envoy Gateway/egctl/Envoy, cert-manager, ConnectRPC test backend and multi-replica service. Shell scripts under `tests/integration/env/` only start and stop environments. Assertions live in Rust or TypeScript so every result is reported the same way (JUnit). | Assertions written in shell |

**Rust.** The workspace has no package at `tests/`. Add one `publish = false` member, `tests/Cargo.toml` (`skyoauth-scenarios`), **in the first M1a PR that adds a scenario test**, not before (tasks §1: no empty scaffolding). It has three `[[test]]` targets: `conformance`, `security` and `integration`. Shared helpers live in its `src/`: an injected-clock builder, PostgreSQL template-DB isolation, a mock GitHub/OIDC issuer, a mock TokenReview, a barrier-driven replica harness and a JWKS server that counts fetches. Hermetic targets run inside the normal `cargo test --workspace`, so their service coverage counts. The `integration` target fails loudly when the environment variables it needs are missing (for example `SKYOAUTH_IT_DATABASE_URL`, `SKYOAUTH_IT_ENVOY`). It never passes vacuously. The generic `rust` job therefore needs `--exclude`, or a `cfg`/feature that the integration job alone enables. This has to be coordinated with the concurrent `ci.yml` work. Keep the bootstrap's `--all-features` behaviour intact.
**TypeScript.** `clients/typescript/test/` keeps the vitest unit tests (fetch spies, typed errors, fixture replay). Add `clients/typescript/test/browser/` with pinned Playwright, driving `examples/spa` built from the **packed tarball** (`npm pack`) in Chromium, Firefox and WebKit. Node mocks alone never satisfy a browser scenario (T33.5, design §10.2).
**Rust client.** `clients/rust/tests/` covers protocol, feature, transport and platform tests. `examples/rust-cli` compiles against the packaged crate with no workspace paths (T40.11).
**Mock OIDC.** Build it in-repo, in Rust, inside the scenario crate's support module, so tests can inject attacks: mix-up, wrong issuer, attacker-initiated callbacks and two providers. A pinned real Zitadel container is a nightly compatibility job (T30.1). It is not the conformance harness.

**Shared fixture format.** Put one directory per scenario at `tests/conformance/fixtures/a61/…`, with one JSON file per case. Cross-scenario catalogues sit beside them: `fixtures/_wire/errors.v1.json` and `fixtures/_profiles/<profile>.v1.json`. Each file looks like this:

```json
{ "fixture_version": 1, "scenario": "A61", "case": "query_4kib_duplicates", "polarity": "neg",
  "consumers": ["service", "rust-client"], "clock": "2026-01-01T00:00:00Z",
  "input": { "...": "..." }, "expected": { "outcome": "deny", "error": "_wire/errors.v1.json#invalid_request" } }
```

- Validate every file against a JSON Schema in `tests/conformance/schema/`. `consumers` is one or more of `service`, `rust-client`, `ts-client` and `backend-verifier`.
- Each consumer has **one data-driven test per fixture kind** that globs all fixtures tagged for it. A new fixture is therefore exercised automatically, and an unknown `kind` or unhandled consumer tag fails the test. Rust reads fixtures through `CARGO_MANIFEST_DIR/../../tests/conformance/fixtures`. vitest reads them with `node:fs` from the test only, never from `src/`, so the browser core stays free of Node.
- Signed-token fixtures are pre-signed with committed **test-only** public/private keys named `*.test-key.json`, which secret scanning allow-lists by path. `exp`/`nbf` are evaluated against the fixture `clock`. Nothing is re-signed at test time, so ECDSA nonces cannot make results vary.
- A breaking wire change adds `*.v2.json` and keeps v1. A42 and T51.7 require prebuilt consumers to keep passing the versions they shipped with. The compatibility window is open question Q10.

## 2. Scenario map

Legend:

- **Layer:** C conformance · S security · I integration · P client package.
- **Harness:** UC in-process service with injected clock · PG PostgreSQL · FX shared fixtures · GH mock GitHub OIDC · GH‑live real Actions OIDC · TRm mock TokenReview · K3 / K3×2 one or two k3s clusters · ENV pinned Envoy Gateway with raw upstream capture · OIDC / OIDC×2 mock human IdP(s) · BR Playwright real browser · RN Rust native on Linux/macOS/Windows · OP `skyoauth-operator` on 3 OSes · REP ≥2 service replicas on one PG with barriers.
- **First → full:** the milestone where a meaningful subset can run, then the milestone where the whole row runs.
- **+ / −:** the minimum positive and negative cases. Every row needs at least one of each.

| ID | Layer | Harness | First → full | Owners | + / − required |
| --- | --- | --- | --- | --- | --- |
| A01 | C+I | FX, GH, PG; GH‑live, ENV | M2 | T12.3, T20.3, T21.4, T22.2, T22.6 | + push with selected grant → WIF profile with signed tenant/grant/revision; − same token blocked by backend tenant/RBAC |
| A02 | S | GH, PG claim-mutation table | M1a (policy on verified-claim fixtures) → M2 | T12.2, T12.7, T22.5, T52.2 | + push; − one case each for pull_request, pull_request_target, workflow_dispatch, issue_comment, workflow_run, missing event, and wrong owner/repo/ref/env/workflow |
| A03 | S | FX, GH with counting JWKS, UC | M1a → M2 | T11.5, T11.7, T21.3, T52.1 | + selected source verifies; − wrong iss/kid/aud, asserting zero alternate verifier or JWKS fetches |
| A04 | C | PG, UC | M1a → M2 | T11.6, T11.9, T24.2 | + old and new keys valid in the overlap, with parent/source/binding/grant IDs unchanged; − each key outside its window |
| A05 | S | UC, FX | M1a | T11.3, T11.5, T24.3, T52.1 | + public-only JWK; − private members, jku, x5u, embedded jwk, unsafe key URL |
| A06 | I | TRm (PR), K3 (merge/nightly) | M2 | T23.2, T23.3, T23.5 | + SA/Pod with intended audience → scoped token for selected tenant/cluster; − policy demanding claims TokenReview does not return is rejected |
| A07 | S+I | TRm, K3 | M2 | T23.4, T23.6, T52.2 | + baseline; − wrong cluster/SA/audience, expired token, deleted Pod/SA, no local-JWT fallback |
| A08 | I | OIDC, PG, ENV, test backend | M3 | T31.4, T32.1, T32.2, T32.5 | + cookie, CSRF and Origin → human_session assertion; − backend tenant/RBAC denies even with a valid assertion |
| A09 | S | UC, ENV, BR | M3 | T31.4, T33.6, T52.3 | + correct Origin/CSRF; − each unsafe method (including Connect POST) with missing or wrong Origin or CSRF |
| A10 | S | UC, ENV | M2 (bearer + assertion) → M3 | T25.2, T31.4, T32.4 | + each credential alone; − cookie + bearer, bearer + internal assertion, duplicate auth cookies |
| A11 | S | UC, PG with fault-injecting repository | M3 | T31.2, T31.5, T32.6 | + live session; − revoked or expired → 401, store down → 503, never an allow |
| A12 | I+P | ENV, ConnectRPC backend, UC, BR, RN | M2 (bearer) → M4 | T26.6, T32.7, T32.8, T32.12, T33.3, T40.15 | + bytes go straight through Envoy, fresh-token reconnect resumes by cursor; − continuing past exp/lease/1 h, restarted mutation, unbounded retry |
| A13 | C+S | FX backend-verifier vectors, test backend | M2 → M3 | T14.2, T20.4, T25.4, T52.6 | + canonical tenant and RBAC match; − valid credential on another tenant's resource, name-only match (Q2) |
| A14 | I | OIDC×2, BR, RN, packed artifacts with recorded sha256 | M5 | T41.5, T51.5, T51.10 | + same artifacts, endpoints and config work after reauth; − old session/refresh denied; any artifact or config hash change fails the test |
| A15 | I | GH, uploaded keyset, K3×2 shared issuer, PG | M5 | T23.7, T51.2, T51.6, T51.7 | + identical decision fixtures before and after; − any changed source/CA/reviewer/keyset ID fails |
| A16 | I | PG, OIDC×2 | M1a (preservation) → M5 | T10.11, T12.10, T51.6 | + IDs, modes, defaults, constraints and revisions equal; − dormant impersonation still disabled and not issuable |
| A17 | I | PG, OIDC×2 | M1b (T13.9) → M5 | T13.9, T51.8 | + policy/audience change made between switch and rollback survives, epochs are fresh; − pre-switch human state not resurrected |
| A18 | S+I | ENV raw capture, OIDC, BR | M2 (header spoof) → M3 | T25.4, T32.4, T50.4, T52.4 | + real SkyOAuth cookie flows work; − Cookie, X-SkyOAuth-CSRF or Set-Cookie on any non-SkyOAuth route (including no-Check routes), missing rule rejected, copies in logs/retries/mirrors, cross-audience assertion |
| A19 | C | FX, UC, ENV JWKS cache | M2 | T20.1, T20.2 | + old and new tokens verify through the overlap with no config change; − retired key after overlap, unknown kid |
| A20 | I | OIDC outage toggle, PG, OP | M3 (switch subcase M5) | T13.7, T30.3, T51.11 | + WIF and operator recovery during the outage; − fresh login fails closed |
| A21 | S | PG, UC | M2 (WIF) → M4 (human) | T12.6, T20.7, T26.5 | + outstanding token verifies offline until exp ≤ 300 s; − new issuance and live check after committed disable |
| A22 | S | UC, OIDC, OP | M1a (operator) → M3 (linking) | T13.1, T13.6, T30.4, T52.3 | + explicit verified link; − email-only match, upstream admin-role claim |
| A23 | C | GH/TRm, PG | M2 | T21.6, T23.5 | + reusable proof used twice → two distinct output jti; − repeat after revocation |
| A24 | S | REP, PG, barriers | M1a (consume primitive) → M2 | T10.9, T21.6, T21.8, T52.7 | + exactly one issuance across N replicas and grants; − missing jti, replay, store failure |
| A25 | C | PG, UC | M1a → M2 | T12.3, T12.8, T21.4, T21.7 | + selector picks the authorized actor/target; − subject/target/mode override, wrong tenant |
| A26 | C | PG, UC | M1a → M2 | T12.8, T21.5 | + omitted scope → explicit defaults; − omitted with no defaults, empty or excessive scope → invalid_scope |
| A27 | S | BR, OIDC with live SSO, RN, attacker loopback process | M4 | T40.2, T40.4, T40.8, T52.3 | + explicit confirmation yields a code; − SSO alone, deny, expiry, attacker's own PKCE/loopback: no code |
| A28 | S | K3×2 (PR: two TRm sharing an issuer string) | M2 | T11.7, T11.10, T23.4 | + selected cluster validates; − other cluster's proof, asserting no probing or fallback |
| A29 | S | PG, proptest with fixed seed | M1a | T10.8, T11.10, T14.8 | + same-issuer and same-name registrations coexist; − each crossed reference |
| A30 | C | FX claim-set vectors per profile | M2 → M4 | T12.9, T20.3, T20.4, T32.5, T40.13 | + complete set per profile; − absent, unknown, contradictory, missing revision, subject-prefix exemption attempt |
| A31 | S | PG, mTLS checker identities, fault injection | M2 → M3 | T14.3, T26.1, T26.3, T26.5 | + correct checker/action; − each wrong dimension, superseded revision; unavailable → typed unavailable, no positive cache, no redirect |
| A32 | S | PG, local verifier, OP, barriers | M1a | T13.4, T13.5, T13.6 | + one bootstrap, signed recovery restores; − concurrent or reopened bootstrap, forged IdP admin, revoked key, replayed recovery |
| A33 | S | PG, UC | M3 | T10.10, T31.2, T31.6 (T30.6?) | + inside both deadlines; − idle expiry, absolute expiry, wrong origin, no revival by coalesced write, wrong sid/provider not revoked (Q3) |
| A34 | S | REP, PG, barriers | M4 → M5 | T10.9, T40.3, T40.5, T40.15, T51.4 | + one code use and one refresh successor; − concurrent reuse, plain replay revokes the family, ID added/removed on replay, post-switch refresh |
| A35 | S | PG, UC | M2 (digest-key rotation, restore) → M5 (switch) | T10.6, T21.8, T51.7, T51.9 | + fresh proof works after each change; − consumed proof stays denied |
| A36 | I | GH‑live, K3, ENV, ConnectRPC | M2 | T22.6, T23.5, T25.5 | + real GitHub and k3s calls reach the API; − spoofed headers, IdP/store outage, direct backend, private listener |
| A37 | C | PG, UC | M1a | T00.12, T12.2 | + optional predicate omitted is unconstrained; − required production predicate omitted rejects, removal needs widening approval |
| A38 | C+S | UC, PG, metadata fixture | M1a → M2 | T10.11, T12.5, T20.1 | + disabled record stored; − device or impersonation not advertised, issuance rejected, capability gain does not activate |
| A39 | P | npm pack, browser bundle check, BR, typecheck | M3 | T33.2, T33.4, T33.8 | + core from the tarball works in the browser; − Node built-in, polyfill, react or connect in the core bundle fails |
| A40 | S+P | vitest fetch spy, BR | M3 | T33.6, T33.7 | + same-origin HTTPS with CSRF; − foreign origin, userinfo, http, redirect, option overrides, off-origin health base: no CSRF or cookie sent |
| A41 | P | RN on 3 OSes, examples/rust-cli, mock issuer | M4 | T40.7, T40.9, T40.10, T40.11 | + PKCE/loopback/cancel with minimal and default features; − plaintext fallback, off-origin forwarding, non-loopback redirect |
| A42 | C | FX v1..vN, prebuilt consumers, OIDC×2 | M4 → M5 | T41.5, T51.5, T51.7 | + every shipped fixture version passes before and after switch/rollback; − cross-profile credential use |
| A43 | S | PG, test backend | M1a (write/issue) → M2 | T14.1, T14.2, T52.6 | + A uses its own audience; − B writes, grants or issues on A's audience, backend tenant mismatch |
| A44 | C+S | FX, UC | M3 → M4 | T12.9, T20.3, T32.5, T40.13 | + complete human_session and human_cli; − missing discriminator, WIF forged into human shape, wrong route |
| A45 | C | PG, mTLS checker | M2 | T14.3, T26.3, T26.5 | + direct grant with null target passes live check; − delegated subject as checker, unknown action, another audience's checker |
| A46 | S | ENV, OIDC×2, PG | M1b (resolution) → M3 | T14.7, T30.2, T30.3 | + each origin resolves to its own tenant/provider; − spoofed Host/Forwarded/tenant query and unknown origin denied before redirect |
| A47 | S | PG | M1b | T10.7, T13.9 | + plan/commit advances pointer and epochs; − PATCH, import, reload, delete or auth-critical edit rejects atomically, epochs unchanged |
| A48 | I | OP, local verifier, empty PG | M1a (workload) → M1b (human) | T13.3, T13.8, T13.10 | + full chain with no SQL; − each step without its role |
| A49 | C | PG, OP | M1a | T10.2, T10.5, T14.8 | + distinct IDs, deterministic export/reapply; − names instead of IDs, cross-tenant probe |
| A50 | C | PG, UC | M1a → M2 | T12.3, T21.4, T21.7 | + grant actor's binding matches despite another actor's overlap; − no eligible match; several same-actor matches give a stable ID with no union |
| A51 | S | BR with attacker and victim contexts, OIDC | M3 | T30.2, T30.7, T33.5, T52.3 | + normal login; − attacker callback in victim browser, wrong cookie, mix-up, tampered return, stale tab: victim session unchanged |
| A52 | S | BR, OIDC, RN | M4 | T40.3, T40.12, T52.3 | + issuer-native flow with approval; − transaction ID alone, app cookie, foreign browser, reused rotated binding |
| A53 | S | PG, UC, OP | M1a | T10.11, T12.10 | + disabled record round-trips through export/import; − enabled input; PATCH/import/upgrade does not activate (Q4) |
| A54 | C+I | TRm with token-file swap (PR), K3 kubelet rotation (nightly) | M1a (single_use rejection) → M2 | T11.11, T21.6, T23.1, T23.5, T23.6 | + renews with the same token, then with the rotated token; − single_use enrollment/import on a TokenReview/projected source |
| A55 | C | FX, UC | M2 → M4 | T00.3, T20.8, T32.2, T40.13 | + exact type/profile/ingress pairs; − at+jwt, ID token, internal token on bearer ingress, WIF token with invented client_id |
| A56 | I+P | PG, ENV, ConnectRPC, UC, BR | M3 | T14.5, T32.6, T32.12, T33.3 | Subcases (Q1). + owner close releases once, cap change affects new admission only; − foreign or replayed close, retry-budget reset loop, 503 → login |
| A57 | C+P | PG, UC, RN, plain OAuth form client | M4 | T40.5, T40.15 | + plain rotation; Rust exact retry ≤ 30 s gets one successor; − consumed replay revokes, added/malformed ID, downgrade, beyond 7 d/24 h |
| A58 | I | K3, ENV, cert-manager, VAP, ≥2 controllers, UC | M1b (prepare/approve persistence) → M3 | T13.2, T14.9, T31.6, T32.3, T32.4, T50.4 | Subcases (Q1): + every approved, mode-matched path; − every listed stale/wrong-mode/revoked/mismatch/hold case |
| A59 | C+S | FX comparison vectors, BR, RN | M4 | T40.2, T40.8, T40.14 | + matching descriptor approves; − each comparison field changed, concurrent malicious request, superseded tab |
| A60 | S | OIDC, PG, barriers, BR/RN | M3 (browser) → M4 (native) | T30.4, T30.8 | + auto_create creates one zero-privilege principal; − default denies, email merge, disabled replacement, migration hold |
| A61 | C+S | FX digest vectors, ENV | M3 | T32.2, T32.13 | + 4 KiB query → fixed 43-char binding; − each byte-level variant, rewrite or rematch; logs redacted |
| A62 | S | UC, PG, REP | M3 | T32.14, T50.3, T52.5 | + rotation and clean promotion; − valid unpromoted-standby signature denies and alerts, invalid-signature kid spoof raises no verified alert, disabled active key with no standby fails closed (Q5) |
| A63 | S | PG, OIDC | M1b (admin) → M3 (sessions) → M4 (refresh) | T13.9, T30.9, T52.5 | + credential-only rotation keeps epochs, sessions and refresh; − semantic change via the rotation path rejects |
| A64 | I | OP on 3 OSes, Linux service | M1a | T13.3, T13.5, T13.7, T13.10 | + scoped remote write and instance-bound signed recovery; − key export into the pod, wrong-instance challenge (Q6) |

Counts by first milestone: M1a 20 · M1b 5 · M2 17 · M3 13 · M4 7 · M5 2 (A14, A15). In the M5 row of the DAG, T51 also completes the full runs of A15–A17, A34, A35 and A42. T52 is the release-time audit: it re-runs every S row against the deployed T50 topology.

## 3. Naming and traceability

**Test names.**

- Rust: `a<NN>_<pos|neg>_<behaviour>`, e.g. `a02_neg_pull_request_target_against_push_binding`. Subcases use `a58_s07_neg_…`.
- vitest/Playwright: the title begins with `A40 neg:` or `A40 pos:`.
- The polarity token lets the checker confirm both a `pos` and a `neg` test for every implemented scenario.

**Registry.** `tests/conformance/scenarios.toml` is the single source and holds all 64 entries from M0:

```toml
current_milestone = "M0"          # bumped only by a milestone-gate PR
[[scenario]]
id = "A24"; layer = "security"; first = "M1a"; full = "M2"
owners = ["T10.9", "T21.6", "T21.8", "T52.7"]
matrix_sha256 = "…"               # hash of the §8 row text (scenario + expected)
status = "planned"                # planned | implemented
tests = []  # e.g. "cargo:skyoauth-scenarios/security::replay::a24_neg_concurrent_single_use"
```

**Check: `check-conformance-registry`** (proposed path under `scripts/ci/`, to land after the concurrent `scripts/ci` work merges).

- *Static part.* Runs on **every** event, including docs-only changes, because the matrix itself lives in Markdown. It needs no build.
  - The `| Axx |` rows of tasks §8 equal the registry IDs exactly: A01–A64, no gaps, duplicates or extras.
  - Every `matrix_sha256` still matches, so an edited matrix row fails until the registry entry is reviewed.
  - IDs are monotonic, and owners exist as task IDs in the tasks doc.
  - Every fixture directory names a registered scenario and validates against its schema.
- *Resolution part.* Runs in the code jobs.
  - Every `implemented` entry lists at least one `pos` and one `neg` test. Each one resolves against `cargo test -- --list`, `vitest list --json` or `playwright test --list --reporter=json`, and none is `#[ignore]`d, `.skip`ped or `.fixme`d.
  - Every listed test whose name matches `^a\d\d_` or `^A\d\d ` is registered, so there are no orphans.
  - Every scenario with `full ≤ current_milestone` is `implemented`. This makes the milestone gates mechanical as well.
- *Result join.* After the test jobs run, a reporter joins JUnit results with the registry. cargo-nextest (pinned) emits JUnit; plain `cargo test` cannot on stable. vitest and Playwright use their junit reporters. Each scenario lands in exactly one of four buckets:
  1. **passed:** every referenced test ran and passed in this run.
  2. **failed**.
  3. **not run:** a test was skipped, filtered, missing, its job was skipped, or the environment was absent.
  4. **planned**.
- Only bucket 1 counts. A `planned` scenario is never counted as a pass, and a skipped test is never counted as a pass. When the docs-only classifier skips the build jobs, the summary reads "runtime conformance: not run (docs-only change)". The `ci-passed` aggregator's `success | skipped` rule satisfies branch protection, but **it is not a conformance signal**. Release gating must read the reporter output, never `ci-passed`.

## 4. CI integration per milestone

**Determinism rules for all layers:**

- Auth code reads time only through an injected `Clock`. Enforce this with clippy `disallowed-methods` on `SystemTime::now`/`Instant::now` outside the clock module. Async timers use `tokio::time::pause`.
- Concurrency tests synchronize on barriers or channels. They never sleep (A24, A34, A56, A60).
- proptest/fuzz use fixed seeds with committed regressions. Jitter and backoff take an injected RNG (A12, A56).
- Servers bind port 0 on loopback. Hermetic jobs need no egress, and every mock issuer is in-process. Cluster/Envoy jobs wait on observed conditions with deadlines, not fixed sleeps.
- Only jobs labelled `live` (real GitHub OIDC, nightly real Zitadel) touch the internet.

| Milestone | New jobs (Rust jobs keep the x86_64/aarch64 matrix where the bootstrap has it) | Required on PR | Merge queue / nightly / release |
| --- | --- | --- | --- |
| M0 | `conformance-registry` (static check, runs even for docs-only changes); fixture schema validation once M0 wire examples land as fixtures. **This is the only M0 deliverable: 64 planned scenarios, 0 implemented.** | yes, via `ci-passed` | — |
| M1a | `skyoauth-scenarios` member (hermetic targets in existing `rust`/`rust-coverage`); `integration-postgres` (pinned PG service container, template DB per test, REP harness); `operator` matrix ubuntu/macos/windows; registry resolution + JUnit join | yes | — |
| M1b | Same jobs extended with human chain, T13.9 transitions, A46 origin resolution, A58 persistence subcases | yes | — |
| M2 | mock GH/TRm in hermetic targets; `clients-rust` (Linux WIF, minimal/default/all features, `cargo package` + consumer); `integration-envoy-k3s` (pinned k3s, Envoy Gateway/egctl/Envoy, ConnectRPC backend; A36 negatives); `live-wif` (real GitHub id-token, push to main/nightly/dispatch only, never fork PRs) | hermetic + PG yes; k3s/Envoy yes if runtime ≤ ~15 min, else merge queue | `live-wif` and kubelet-rotation A54 nightly; release requires both green on the release commit |
| M3 | `typescript-browser` (packed tarball → `examples/spa`, Playwright Chromium/Firefox/WebKit, pinned browsers); `bundle-check` (browser-platform bundle with Node built-ins forbidden, A39); Envoy job adds raw-capture cookie tests, mock OIDC×2, ≥2 controllers, cert-manager, VAP (A58 subcases) | browser + bundle yes; A58 cluster subcases merge queue | Nightly real-Zitadel compatibility |
| M4 | `clients-rust-native` matrix on 3 OSes (loopback, injected browser launcher driving Playwright for confirm, OS keychain: macOS Keychain, Windows Credential Manager, Linux secret-service under dbus); `examples/rust-cli` packaged consumer | yes | — |
| M5 | `migration-rehearsal` (artifacts built once and carried by hash into switch/rollback, OIDC×2, K3×2); `fuzz` (T52.7, time-boxed; PRs replay seed corpora only); load tests; deployed-topology T52 audit | seed replay yes | fuzz/load nightly; **release workflow** requires the reporter to show 64/64 implemented **and passed** on the exact release commit, live jobs included, plus C01–C10 and both libraries |

Coverage: the existing 85 % gates stay hermetic. Integration coverage is uploaded and reported but not gated (Q9).

## 5. Open questions and risks for the lead

1. **Q1 Oversized rows.** A58 (and to a lesser degree A56, A18, A12, A57) bundles dozens of independent behaviours. A single pass/fail would hide partial coverage. Proposal: registered subcase IDs (`A58.01`… with their own `matrix_sha256` taken from the T14.9, T32.3 and T50.4 text) that must all pass. Do we approve sub-IDs in the registry, and who owns the decomposition?
2. **Q2 "Backend denies" (A13, A43, A01, A08).** The backend is user code, and v0.1 ships no backend verifier library. We can prove only our test backend plus published verifier fixtures. Is a `backend-verifier` fixture consumer plus a reference ConnectRPC backend the intended evidence?
3. **Q3 A33 "provider/sid targeting".** Verified-sid targeting relies on optional back-channel logout (T30.6), but the row is unconditional. Is it satisfied by local/upstream logout and switch invalidation (T10.10, T31.6) alone?
4. **Q4 A53 "capability upgrade"** is undefined: is it a service version, a source capability or a feature flag? A38's "capability gain does not activate" overlaps it. Please name the concrete operations to test.
5. **Q5 A62 scope.** Does the standby/tripwire apply only to the internal signer group (T32.14), or also to the M2 public issuer signer (ADR-002 mentions public signer rotation)?
6. **Q6 A64 "against Linux service" on macOS/Windows.** Hosted macOS/Windows runners cannot reach a Linux job's service, and Linux containers are unavailable on them. Options:
   - (a) offline recovery via challenge/response artifacts passed between jobs (true to "offline"), plus mTLS remote writes against a natively built service on that OS;
   - (b) self-hosted runners;
   - (c) a tunnelled Linux service.

   Hardware-signer drills (T13.7) cannot be automated. Is manual drill evidence acceptable in an "automated release blocking" matrix?
7. **Q7 Live dependencies.** A01 and A36 need real GitHub OIDC (id-token: write, egress, unavailable to fork PRs). A54 real kubelet rotation needs ≥ 10-minute projected tokens (rotation at ~80 % of lifetime), so it cannot be a fast PR check. Proposal: the PR uses mocks and a token-file swap, while live runs gate merge-to-main/nightly/release. Confirm this split.
8. **Q8 Envoy real time.** Envoy and kubelet cannot take an injected clock. A12, A56 and A58 deadline narratives (09:00/09:20, 10:00–10:31, 40 s failover) must drive time through the service and controller clocks, with Envoy only carrying bytes. Some cases may need test-profile TTLs below production defaults, which stay within the spec's ceilings. Is that acceptable as conformance evidence?
9. **Q9 Coverage.** Should integration-job coverage merge into the gated number, or stay informational?
10. **Q10 Fixture compatibility window** for A42/T51.7: all versions since v0.1, or the last N?
11. **Q11 C01–C10** are release-blocking but not in §8. Should they be added to the same registry (`C01`…) so the release reporter covers the whole M5 gate?
12. **Risk: ci.yml coordination.** The new scenario crate must be excluded from the generic `--workspace --all-features` run or it will fail without PostgreSQL. This needs a change to `ci.yml`, which another agent is editing now. Land the registry check (M0) first and the crate exclusion with the first M1a scenario PR.
13. **Risk: docs-only blind spot.** Editing the §8 matrix is a docs-only change that today skips all checks. The static registry check must be outside the `changes` gate, or matrix drift will merge unnoticed.
