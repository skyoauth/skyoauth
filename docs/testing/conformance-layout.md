# Conformance test layout (proposal)

> Status: proposal only. Nothing below exists yet except the bootstrap `service/tests/shutdown.rs`, the vitest suite in `clients/typescript/test/`, the two coverage gates and `scripts/ci/docs-only.sh`. The Rust gate is the `cargo coverage` alias in `.cargo/config.toml` (85 % **lines** only). The TypeScript gate is in `clients/typescript/vitest.config.ts` (85 % lines, functions, branches **and** statements). Sources: tasks §1, §8 (A01–A64), §9 DAG, §10, T50.8, T51, T52; design §2 (C01–C10), §5.6, §10. Lead decisions on the former open questions are recorded in section 5.

## 1. Layout and ownership

| Home | Holds | Does not hold |
| --- | --- | --- |
| `service/src/**` `#[cfg(test)]`, `service/tests/*.rs`, `clients/*/test(s)/` | Unit tests for one module or package API. These count toward the existing coverage gates. They can support a scenario, but a scenario stage does not count as `implemented` on unit tests alone. | Anything that needs PostgreSQL, Envoy, a cluster or a browser |
| `tests/conformance/` | Versioned wire/profile/migration **fixtures** and the scenario registry. Expected outcomes are fixed here: claim sets, error bodies, digest vectors (A61), comparison vectors (A59), refresh/retry transcripts (A57) and migration decision tables (A15/A42). | Attack-only logic, environment bring-up |
| `tests/security/` | Negative-heavy tests for JWT/OIDC/CSRF/admin/tenant/audience/replay/gateway (T52.1–T52.6), plus fuzz targets and committed seed corpora (T52.7) | Shared positive wire contracts. Those go in conformance and security references them. |
| `tests/integration/` | Tests against real dependencies: PostgreSQL, mock OIDC, two k3s clusters, pinned Envoy Gateway/egctl/Envoy, cert-manager, the test-only reference ConnectRPC backend and multi-replica service. Shell scripts under `tests/integration/env/` only start and stop environments. Assertions live in Rust or TypeScript so every result is reported the same way (JUnit). | Assertions written in shell |

The three directories are **source homes grouped by layer**. Layer is a label for review and reporting only. Where a test runs is decided by its **execution environment** (section 1.1), not by its directory.

### 1.1 Execution environments

Every scenario lists the environments its required tests need (`envs` in the registry, **Env** column in section 2). Each environment maps to fixed CI jobs and legs:

| Env | Code | Provides | CI job (legs) |
| --- | --- | --- | --- |
| `hermetic` | H | No network, no database. In-process mocks only (GitHub OIDC issuer, TokenReview, human IdP), fixtures, injected clock. | `scenarios-hermetic` (x86_64, aarch64) for the scenario package; `clients-rust` (Linux x86_64) from M2; `typescript` (Node 22, 24) for vitest; `bundle-check` from M3 |
| `pg` | PG | `hermetic` plus a pinned PostgreSQL service container, template DB per test, the barrier-driven replica harness (REP) and fault-injecting repositories. Any test that reads or writes state through the real repository is `pg`. No in-memory repository is proposed, so the atomicity claims (A24, A34) are tested on the real store. | `scenarios-pg` (x86_64) |
| `envoy-k3s` | EK | `pg` plus pinned k3s (one or two clusters), Envoy Gateway/egctl/Envoy with raw upstream capture, cert-manager, VAP, ≥2 controllers and the reference ConnectRPC backend | `scenarios-envoy-k3s` (x86_64); `scenarios-envoy-k3s-nightly` for real kubelet rotation (A54) and long deadline narratives; `migration-rehearsal` from M5 |
| `browser` | BR | Packed `@skyoauth/client` tarball installed in `examples/spa`, Playwright with pinned browsers, against the `envoy-k3s` stack | `typescript-browser` (Chromium, Firefox, WebKit) |
| `native-3os` | N3 | Native binaries on hosted Linux, macOS and Windows runners | `operator` (M1a), `recovery-offline` three-job chain (M1a, see Q6), `clients-rust-native` (M4); each leg is ubuntu, macos, windows unless the row says Linux only |
| `live` | LV | Real GitHub Actions OIDC (`id-token: write` on that job only) and egress | `live-wif`: the **positive** case only from the `push` to `main` run of the commit; **negative** cases from `schedule` and `workflow_dispatch` runs (see section 4) |

Nightly real-Zitadel compatibility (T30.1) is a compatibility job, not a conformance environment. Its result never counts toward a scenario.

### 1.2 Rust scenario package and the CI mechanism

The workspace has no package at `tests/` today. Add one member, `tests/Cargo.toml` (`skyoauth-scenarios`, `publish = false`), **in the first M1a PR that adds a scenario test**, not before (tasks §1: no empty scaffolding). That PR also updates the layout in tasks §1 and design §10.4, which list only `operator`, `clients/rust` and `cli` as new members.

- **Targets by environment, not by layer.** The package has four `[[test]]` targets: `hermetic`, `pg`, `envoy_k3s` and `live`. Each target root declares its modules from the layer directories with `#[path]`. A test's full name is therefore module-qualified, for example `security::a24::a24_neg_concurrent_single_use` in the `pg` binary.
- **No features, no cfg.** The package declares no Cargo features. A feature gate cannot work: the `rust`, `msrv` and coverage jobs pass `--all-features`, which would switch it on. A declared `--cfg` (with `check-cfg` under `unexpected_cfgs`) would work, but it compiles the environment tests out of the generic jobs, so clippy would stop linting them unless a second clippy pass ran with the cfg. Splitting targets avoids both problems.
- **Loud failure.** The `pg`, `envoy_k3s` and `live` targets fail on first use when the variables they need are missing (`SKYOAUTH_IT_DATABASE_URL`, `SKYOAUTH_IT_ENVOY`, …). They never pass vacuously.
- **Shared helpers** live in the package's `src/`: an injected-clock builder, PostgreSQL template-DB isolation, a mock GitHub/OIDC issuer, a mock TokenReview, the replica harness and a JWKS server that counts fetches per source.
- **Mock OIDC** is built in-repo, in Rust, in this package, so tests can inject attacks: mix-up, wrong issuer, attacker-initiated callbacks and two providers.

Required changes, landing with the first M1a scenario PR and coordinated with any concurrent `ci.yml` work:

| File | Change |
| --- | --- |
| `.github/workflows/ci.yml`, job `rust` | Both `cargo test` steps (tests and doctests) become `--workspace --exclude skyoauth-scenarios`. Clippy and `cargo doc` keep `--workspace --all-features`: they only compile, so the package stays linted on both arches without any environment. |
| `.github/workflows/ci.yml`, job `msrv` | Unchanged. `cargo check` only compiles. |
| `.cargo/config.toml`, alias `coverage` | `llvm-cov --workspace --exclude skyoauth-scenarios --all-features --ignore-filename-regex main\\.rs --fail-under-lines 85`. The Rust gate keeps measuring unit tests only. Scenario coverage is informational (Q9). |
| `.github/workflows/ci.yml`, new jobs | `scenarios-hermetic`, `scenarios-pg`, `scenarios-envoy-k3s`: each runs `cargo nextest run --locked -p skyoauth-scenarios --test <target> --profile ci` (pinned cargo-nextest, `retries = 0`, JUnit output uploaded as an artifact). Each is gated on `needs.changes.outputs.code` like the existing jobs and is added to the `needs` list of `ci-passed`. |

**Rust client.** `clients/rust/tests/` covers protocol, feature, transport and platform tests. `examples/rust-cli` compiles against the packaged crate with no workspace paths (T40.11).

**TypeScript.** `clients/typescript/test/` keeps the vitest unit tests (fetch spies, typed errors, fixture replay). Add `clients/typescript/test/browser/` with pinned Playwright, driving `examples/spa` built from the **packed tarball** (`npm pack`) in Chromium, Firefox and WebKit. Node mocks alone never satisfy a browser scenario (T33.5, design §10.2).

### 1.3 Shared fixtures

Put one directory per scenario at `tests/conformance/fixtures/a61/`, with one JSON file per case. Cross-scenario catalogues sit in `_`-prefixed directories beside them: `fixtures/_wire/errors.v1.json` and `fixtures/_profiles/<profile>.v1.json`. The scenario-directory check skips `_`-prefixed directories. Each case file looks like this:

```json
{
  "fixture_version": 1,
  "kind": "request_binding_digest",
  "scenario": "A61",
  "case": "query_reordered_mismatch",
  "polarity": "neg",
  "consumers": ["service", "backend-verifier"],
  "clock": "2026-01-01T00:00:00Z",
  "input": { "raw_target": "/v1/items?b=2&a=1", "asserted_target_sha256": "see-generator-output" },
  "expected": { "outcome": "deny", "error": "_wire/errors.v1.json#invalid_request" }
}
```

- Validate every file against a JSON Schema in `tests/conformance/schema/`. `kind` selects the replay logic. `consumers` is one or more of `service`, `rust-client`, `ts-client` and `backend-verifier`. `case` matches `^[a-z0-9_]+$` and is unique within its scenario. A sub-ID case (section 3) adds `"subcase": "A58.07"`.
- **Each reader has its own fixture path.** Every reader resolves the path through one helper that asserts the directory exists:

  | Reader | Path |
  | --- | --- |
  | `tests/` (`skyoauth-scenarios`) | `CARGO_MANIFEST_DIR/conformance/fixtures` |
  | `service/` (unit support only until it has a nextest job, section 3) | `CARGO_MANIFEST_DIR/../tests/conformance/fixtures` |
  | `operator/` | `CARGO_MANIFEST_DIR/../tests/conformance/fixtures` |
  | `clients/rust/` | `CARGO_MANIFEST_DIR/../../tests/conformance/fixtures` |
  | vitest, `clients/typescript/test/*.test.ts` | `new URL("../../../tests/conformance/fixtures/", import.meta.url)`, read with `node:fs` in the test only, never from `src/`, so the browser core stays free of Node |
  | Playwright, `clients/typescript/test/browser/` | `new URL("../../../../tests/conformance/fixtures/", import.meta.url)` |

  Fixture tests run from the repository checkout only. A packaged crate or tarball never needs the fixtures.
- **One named test per fixture.** A single data-driven test per kind cannot show `pos`/`neg` names to the registry check. Instead:
  - Rust readers use a `harness = false` test target built on pinned `libtest-mimic`, which registers one trial per fixture named `a<NN>_<pos|neg>_<case>` (sub-ID cases `a58_07_neg_<case>`). It supports `--list`, nextest and llvm-cov. A build script is not used because `clients/rust` is published and its build script would run for every consumer.
  - vitest and Playwright create one `it`/`test` per fixture titled `A61 neg: <case>` (sub-ID `A58.07 neg: <case>`).
  - The harness fails, before running any case, if a kind it handles matches **zero** fixtures for its consumer, or if a fixture has an unknown `kind` or a consumer tag nobody handles.
  - The result reporter checks that, per (consumer, kind), the number of executed cases in JUnit equals the number of fixtures on disk.
- Signed-token fixtures are pre-signed with committed **test-only** public/private keys named `*.test-key.json`, which secret scanning allow-lists by path. `exp`/`nbf` are evaluated against the fixture `clock`. Nothing is re-signed at test time, so ECDSA nonces cannot make results vary.
- **Versions.** Every fixture carries `fixture_version`. v0.1 ships version 1 only. A breaking wire change adds `*.v2.json` and keeps v1. A42 and T51.7 require only that the shipped per-profile wire/error contract and the prebuilt consumers stay stable through provider switch and rollback. This proposal promises no compatibility window beyond that.

## 2. Scenario map

This table is the review snapshot. Once `tests/conformance/scenarios.toml` lands it becomes the single source, and the registry check renders this table from it and fails when the committed table differs (section 3).

Legend:

- **Layer:** C conformance · S security · I integration · P client package. A label only.
- **Env:** execution environments from section 1.1 (H, PG, EK, BR, N3, LV). The jobs follow from the env.
- **Harness:** UC in-process service with injected clock · PG PostgreSQL · FX shared fixtures · GH mock GitHub OIDC · GH‑live real Actions OIDC · TRm mock TokenReview · K3 / K3×2 one or two k3s clusters · ENV pinned Envoy Gateway with raw upstream capture · OIDC / OIDC×2 mock human IdP(s) · BR Playwright real browser · RN Rust native on Linux/macOS/Windows · OP `skyoauth-operator` · REP ≥2 service replicas on one PG with barriers · RB test-only reference ConnectRPC backend behind Envoy.
- **Stages:** the milestone at which each part of the row must pass. A row with one milestone has one stage. These map one-to-one to registry stages (section 3).
- **+ / −:** the minimum positive and negative cases. Every row needs at least one of each.
- **Conditional** sub-IDs block release only if the named optional feature ships.

| ID | Layer | Env | Harness | Stages | Owners | + / − required |
| --- | --- | --- | --- | --- | --- | --- |
| A01 | C+I | PG, EK, LV | FX, GH, PG; GH‑live, ENV, RB | M2 | T12.3, T20.3, T21.4, T22.2, T22.6 | + push to `main` with selected grant → WIF profile with signed tenant/grant/revision (live positive only from the push-to-main run of that commit); − same token blocked by RB tenant/RBAC |
| A02 | S | PG, LV | GH, PG claim-mutation table; GH‑live | M1a: policy on verified-claim fixtures · M2: exchange and live negatives | T12.2, T12.7, T22.5, T52.2 | + push; − one case each for pull_request, pull_request_target, workflow_dispatch, issue_comment, workflow_run, missing event, and wrong owner/repo/ref/env/workflow; live: the real token of a `schedule` or `workflow_dispatch` run is denied by the push-only binding |
| A03 | S | H, PG | FX, GH with per-source JWKS fetch counter, UC | M1a: verifier selection · M2: exchange | T11.5, T11.7, T21.3, T52.1 | + selected source verifies; − wrong iss/kid/aud, asserting no verifier call and no discovery/JWKS fetch for any non-selected source |
| A04 | C | PG | PG, UC | M1a: keyset lifecycle · M2: exchange through the overlap | T11.6, T11.9, T24.2 | + old and new keys valid in the overlap, with parent/source/binding/grant IDs unchanged; − each key outside its window |
| A05 | S | H, PG | UC, FX | M1a: upload and token-header rejection · M2: generic issuer keysets | T11.3, T11.5, T24.3, T52.1 | + public-only JWK; − private members, jku, x5u, embedded jwk, unsafe key URL; M2 adds disallowed issuer/alg, conflicting kid, cross-tenant keyset |
| A06 | I | PG, EK | TRm (PR), K3 | M2 | T23.2, T23.3, T23.5 | + SA/Pod with intended audience → scoped token for selected tenant/cluster; − policy demanding claims TokenReview does not return is rejected |
| A07 | S+I | PG, EK | TRm, K3 | M2 | T23.4, T23.6, T52.2 | + baseline; − wrong cluster/SA/audience, expired token, deleted Pod/SA, no local-JWT fallback |
| A08 | I | EK | OIDC, PG, ENV, RB | M3 | T31.4, T32.1, T32.2, T32.5 | + cookie, CSRF and Origin → human_session assertion; − RB tenant/RBAC denies even with a valid assertion |
| A09 | S | PG, EK, BR | UC, ENV, BR | M3 | T31.4, T33.6, T52.3 | + correct Origin/CSRF; − each unsafe method (including Connect POST) with missing or wrong Origin or CSRF |
| A10 | S | PG, EK | UC, ENV | M2: bearer + assertion · M3: cookie | T25.2, T31.4, T32.4 | + each credential alone; − cookie + bearer, bearer + internal assertion, duplicate auth cookies |
| A11 | S | PG | UC, PG with fault-injecting repository | M3 | T31.2, T31.5, T32.6 | + live session; − revoked or expired → 401, store down → 503, never an allow |
| A12 | I+P | PG, EK, BR, N3 | ENV, RB, UC, BR, RN | M2: bearer · M3: browser leases · M4: native reconnect | T26.6, T32.7, T32.8, T32.12, T33.3, T40.15 | + bytes go straight through Envoy, fresh-token reconnect resumes by cursor; − continuing past exp/lease/1 h, restarted mutation, unbounded retry |
| A13 | C+S | H, EK | FX backend-verifier vectors, RB | M2: WIF · M3: human_session · M4: human_cli | T12.9, T14.2, T20.4, T25.4, T40.13, T52.6 | + canonical tenant and RBAC match; − valid credential on another tenant's resource; name-only match; WIF token whose signed allowlist does not cover the resource/action (M2); human_session whose backend RBAC denies (M3); human_cli whose backend RBAC denies (M4) |
| A14 | I | BR, N3 (Linux leg) | OIDC×2, BR, RN, packed artifacts with recorded sha256 | M5 | T41.5, T51.5, T51.10 | + same artifacts, endpoints and config work after reauth; − old session/refresh denied; any artifact or config hash change fails the test |
| A15 | I | PG, EK | GH, uploaded keyset, K3×2 shared issuer, PG | M5 | T23.7, T51.2, T51.6, T51.7 | + identical decision fixtures before and after; − any changed source/CA/reviewer/keyset ID fails |
| A16 | I | PG | PG, OIDC×2 | M1a: preservation · M5: switch | T10.11, T12.10, T51.6 | + IDs, modes, defaults, constraints and revisions equal; − dormant impersonation still disabled and not issuable |
| A17 | I | PG | PG, OIDC×2 | M1b: T13.9 transition · M5: rehearsal | T13.9, T51.8 | + policy/audience change made between switch and rollback survives, epochs are fresh; − pre-switch human state not resurrected |
| A18 | S+I | EK, BR | ENV raw capture, OIDC, BR | M2: header spoof · M3: cookies | T25.4, T32.4, T50.4, T52.4 | + real SkyOAuth cookie flows work; − Cookie, X-SkyOAuth-CSRF or Set-Cookie on any non-SkyOAuth route (including no-Check routes), missing rule rejected, copies in logs/retries/mirrors, cross-audience assertion. Conditional sub-ID (ForwardAuth, T32.9): credential containment and trusted forwarded chain |
| A19 | C | H, EK | FX, UC, ENV JWKS cache | M2 | T20.1, T20.2 | + old and new tokens verify through the overlap with no config change; − retired key after overlap, unknown kid |
| A20 | I | PG, N3 | OIDC outage toggle, PG, OP | M3: outage · M5: switch during outage | T13.7, T30.3, T51.11 | + WIF and operator recovery during the outage; − fresh login fails closed |
| A21 | S | PG | PG, UC | M2: WIF · M4: human | T12.6, T20.7, T26.5 | + outstanding token verifies offline until exp ≤ 300 s; − new issuance and live check after committed disable |
| A22 | S | PG | UC, OIDC, OP | M1a: operator · M3: linking | T13.1, T13.6, T30.4, T52.3 | + explicit verified link; − email-only match, upstream admin-role claim |
| A23 | C | PG | GH/TRm, PG | M2 | T21.6, T23.5 | + reusable proof used twice → two distinct output jti; − repeat after revocation |
| A24 | S | PG | REP, PG, barriers | M1a: consume primitive · M2: exchange | T10.9, T21.6, T21.8, T52.7 | + exactly one issuance across N replicas and grants; − missing jti, replay, store failure |
| A25 | C | PG | PG, UC | M1a: selection · M2: exchange | T12.3, T12.8, T21.4, T21.7 | + selector picks the authorized actor/target; − subject/target/mode override, wrong tenant |
| A26 | C | PG | PG, UC | M1a: policy · M2: exchange | T12.8, T21.5 | + omitted scope → explicit defaults; − omitted with no defaults, empty or excessive scope → invalid_scope |
| A27 | S | BR, N3 | BR, OIDC with live SSO, RN, attacker loopback process | M4 | T40.2, T40.4, T40.8, T52.3 | + explicit confirmation yields a code; − SSO alone, deny, expiry, attacker's own PKCE/loopback: no code. Conditional sub-ID A27.01 (device flow, T40.6): user-code approval, expiry/polling abuse, no interaction bypass |
| A28 | S | PG, EK | K3×2 (PR: two TRm sharing an issuer string) | M2 | T11.7, T11.10, T23.4 | + selected cluster validates; − other cluster's proof, asserting no probing or fallback |
| A29 | S | PG | PG, proptest with fixed seed | M1a: registry and references · M2: exchange | T10.8, T11.10, T14.8, T21.3 | + same-issuer and same-name registrations coexist; − each crossed reference at write (M1a); a proof from one tenant's source with another tenant's grant at exchange (M2) |
| A30 | C | H | FX claim-set vectors per profile | M2: WIF · M3: human_session · M4: human_cli | T12.9, T20.3, T20.4, T32.5, T40.13 | + complete set per profile; − absent, unknown, contradictory, missing revision, subject-prefix exemption attempt |
| A31 | S | PG | PG, mTLS checker identities, fault injection | M2: WIF · M3: human | T14.3, T26.1, T26.3, T26.5 | + correct checker/action; − each wrong dimension, superseded revision; unavailable → typed unavailable, no positive cache, no redirect |
| A32 | S | PG | PG, local verifier, OP, barriers | M1a | T13.4, T13.5, T13.6 | + one bootstrap, signed recovery restores; − concurrent or reopened bootstrap, forged IdP admin, revoked key, replayed recovery |
| A33 | S | PG | PG, UC | M3 | T10.10, T31.2, T31.6 | + inside both deadlines; − idle expiry, absolute expiry, wrong origin, no revival by coalesced write; local and upstream logout revoke exactly the sessions of the indexed sid, switch invalidation revokes affected sessions, other sessions untouched. Conditional sub-ID A33.01 (back-channel logout, T30.6): verified sid targeting |
| A34 | S | PG | REP, PG, barriers | M4: code and refresh · M5: switch/rollback | T10.9, T40.3, T40.5, T40.15, T51.4 | + one code use and one refresh successor; − concurrent reuse, plain replay revokes the family, ID added/removed on replay, post-switch refresh |
| A35 | S | PG | PG, UC | M2: digest-key rotation, restore · M5: switch | T10.6, T21.8, T51.7, T51.9 | + fresh proof works after each change; − consumed proof stays denied |
| A36 | I | EK, LV | GH‑live, K3, ENV, RB | M2 | T22.6, T23.5, T25.5 | + real GitHub (push-to-main run only) and k3s calls reach the API; − spoofed headers, IdP/store outage, direct backend, private listener |
| A37 | C | PG | PG, UC | M1a | T00.12, T12.2 | + optional predicate omitted is unconstrained; − required production predicate omitted rejects, removal needs widening approval |
| A38 | C+S | H, PG | UC, PG, metadata fixture | M1a: storage · M2: metadata and issuance | T10.11, T12.5, T20.1 | + disabled record stored; − device or impersonation not advertised, issuance rejected, capability gain does not activate |
| A39 | P | H, BR | npm pack, browser bundle check, BR, typecheck | M3 | T33.2, T33.4, T33.8 | + core from the tarball works in the browser; − Node built-in, polyfill, react or connect in the core bundle fails |
| A40 | S+P | H, BR | vitest fetch spy, BR | M3 | T33.1, T33.6, T33.7 | + same-origin HTTPS with CSRF; − foreign origin, userinfo, http, redirect, option overrides, off-origin health base: no CSRF or cookie sent; no token getter in the API and nothing written to localStorage/sessionStorage/IndexedDB; caller-supplied Authorization/bearer rejected (no mixed auth); no automatic mutation replay after 401 or login |
| A41 | P | N3 | RN on 3 OSes, examples/rust-cli, mock issuer | M4 | T40.7, T40.9, T40.10, T40.11 | + PKCE/loopback/cancel with minimal and default features; − plaintext fallback, off-origin forwarding, non-loopback redirect, credential or refresh token in logs/`Debug`/error output (redaction) |
| A42 | C | H, BR, N3 | FX v1, prebuilt consumers, OIDC×2 | M4: fixtures · M5: through switch/rollback | T41.5, T51.5, T51.7 | + every shipped fixture version (v1 in v0.1) passes before and after switch/rollback with unchanged artifacts; − cross-profile credential use |
| A43 | S | PG, EK | PG, RB | M1a: write · M2: issuance and backend | T14.1, T14.2, T52.6 | + A uses its own audience; − B writes, grants or issues on A's audience, RB tenant mismatch |
| A44 | C+S | H | FX, UC | M3: human_session · M4: human_cli | T12.9, T20.3, T32.5, T40.13 | + complete human_session and human_cli; − missing discriminator, WIF forged into human shape, wrong route |
| A45 | C | PG | PG, mTLS checker | M2 | T14.3, T26.3, T26.5 | + direct grant with null target passes live check; − delegated subject as checker, unknown action, another audience's checker |
| A46 | S | PG, EK | ENV, OIDC×2, PG | M1b: resolution · M3: redirect | T14.7, T30.2, T30.3 | + each origin resolves to its own tenant/provider; − spoofed Host/Forwarded/tenant query and unknown origin denied before redirect |
| A47 | S | PG | PG | M1b | T10.7, T13.9 | + plan/commit advances pointer and epochs; − PATCH, import, reload, delete or auth-critical edit rejects atomically, epochs unchanged |
| A48 | I | PG | OP, local verifier, empty PG | M1a: workload · M1b: human | T13.3, T13.8, T13.10 | + full chain with no SQL; − each step without its role |
| A49 | C | PG | PG, OP | M1a: IDs, export, reapply · M2: exchange | T10.2, T10.5, T14.8, T21.1 | + distinct IDs, deterministic export/reapply; − cross-tenant probe; exchange with names instead of generated IDs rejects (M2) |
| A50 | C | PG | PG, UC | M1a: matching · M2: exchange | T12.3, T21.4, T21.7 | + grant actor's binding matches despite another actor's overlap; − no eligible match; several same-actor matches give a stable ID with no union |
| A51 | S | BR | BR with attacker and victim contexts, OIDC | M3 | T30.2, T30.7, T33.5, T52.3 | + normal login; − attacker callback in victim browser, wrong cookie, mix-up, tampered return, stale tab: victim session unchanged |
| A52 | S | BR, N3 | BR, OIDC, RN | M4 | T40.3, T40.12, T52.3 | + issuer-native flow with approval; − transaction ID alone, app cookie, foreign browser, reused rotated binding |
| A53 | S | PG | PG, UC, OP, restore fixture | M1a | T10.11, T12.10 | + disabled/requires_reapproval record round-trips through export/import and stays unchanged across restart, forward migration and provider switch; − enabled/approved create or import rejected, enabling PATCH rejected, startup/import with an active unsupported record (seeded by restore fixture) rejected without rewriting it |
| A54 | C+I | PG, EK | TRm with token-file swap (PR), K3 kubelet rotation (nightly) | M1a: single_use rejection · M2: renewal | T11.11, T21.6, T23.1, T23.5, T23.6 | + renews with the same token, then with the rotated token; − single_use enrollment/import on a TokenReview/projected source |
| A55 | C | H | FX, UC | M2: WIF · M3: internal assertion · M4: human_cli | T00.3, T20.8, T32.2, T40.13 | + exact type/profile/ingress pairs; − at+jwt, ID token, internal token on bearer ingress, WIF token with invented client_id |
| A56 | I+P | PG, EK, BR | PG, ENV, RB, UC, BR | M3 | T14.5, T32.6, T32.12, T33.3 | + owner close releases once, cap change affects new admission only; − foreign or replayed close, retry-budget reset loop, 503 → login |
| A57 | C+P | PG, N3 | PG, UC, RN, plain OAuth form client | M4 | T40.5, T40.15 | + plain rotation; Rust exact retry ≤ 30 s gets one successor; − consumed replay revokes, added/malformed ID, downgrade, beyond 7 d/24 h |
| A58 | I | PG, EK | K3, ENV, cert-manager, VAP, ≥2 controllers, UC | M1b: prepare/approve persistence · M3: enforcement | T13.2, T14.9, T31.6, T32.3, T32.4, T50.4 | Sub-IDs A58.01… in the annex (Q1): + every approved, mode-matched path; − every listed stale/wrong-mode/revoked/mismatch/hold case. Conditional sub-ID (ForwardAuth, T32.9): deployment-enforcer equivalence |
| A59 | C+S | H, BR, N3 | FX comparison vectors, BR, RN | M4 | T40.2, T40.8, T40.14 | + matching descriptor approves; − each comparison field changed, concurrent malicious request, superseded tab |
| A60 | S | PG, BR, N3 | OIDC, PG, barriers, BR/RN | M3: browser · M4: native | T30.4, T30.8 | + auto_create creates one zero-privilege principal; − default denies, email merge, disabled replacement, migration hold |
| A61 | C+S | H, EK | FX digest vectors, ENV | M3 | T32.2, T32.13 | + 4 KiB query → fixed 43-char binding; − each byte-level variant, rewrite or rematch; logs redacted |
| A62 | S | PG | UC, PG, REP | M3 | T32.14, T50.3, T52.5 | Internal signer group only (Q5). + rotation and clean promotion; − valid unpromoted-standby signature denies and alerts, invalid-signature kid spoof raises no verified alert, disabled active key with no standby fails closed |
| A63 | S | PG | PG, OIDC | M1b: admin · M3: sessions · M4: refresh | T13.9, T30.9, T52.5 | + credential-only rotation keeps epochs, sessions and refresh; − semantic change via the rotation path rejects |
| A64 | I | H, PG, N3 | OP on 3 OSes, Linux service, SoftHSM2 | M1a | T13.3, T13.5, T13.7, T13.10 | + remote scoped write against the Linux service; offline recovery via the three-job chain on injected clocks, plus one same-job Linux run in real time (Q6); − key export into the pod, wrong-instance challenge, expired challenge at the TTL boundary (hermetic), unsupported adapter fails explicitly |

Counts by first stage: M1a 20 · M1b 5 · M2 17 · M3 13 · M4 7 · M5 2. Counts by final stage: M1a 4 · M1b 2 · M2 21 · M3 16 · M4 13 · M5 8. 34 rows have more than one stage. All 8 M5 stages belong to T51: A14 (T51.5, T51.10), A15, A16, A17, A20, A34, A35 and A42. T52 is the security conformance task group (T52.1–T52.8). The §9 DAG feeds it the deployed T50 topology, but the spec does not say that every S row is re-run there; which S-row tests also run against the deployed topology is for the T52 owner to register as M5 stages.

**Stages are separate evidence.** Each stage has its own tests and its own result, and the gate of its milestone needs that stage passed. For example, A12's M2 stage is the bearer expiry and fresh-token reconnect of T26.6 and must pass at the M2 gate. A12 as a whole stays open until its M3 and M4 stages pass too. A scenario counts as passed for release only when every stage passes.

## 3. Naming and traceability

**Test names.**

- Rust: `a<NN>_<pos|neg>_<behaviour>`, for example `a02_neg_pull_request_target_against_push_binding`. Sub-IDs use `a<NN>_<SS>_<pos|neg>_<behaviour>`, for example `a58_07_neg_stale_approval`.
- vitest/Playwright: the test's own title begins with `A40 pos:` or `A40 neg:`; sub-IDs use `A58.07 neg:`.
- The polarity token lets the checker confirm both a `pos` and a `neg` test for every implemented stage.

**Registry.** `tests/conformance/scenarios.toml` holds all 64 scenarios and the 10 contracts from M0. Sub-IDs live in an annex file `tests/conformance/subcases.toml` with the same entry shape and a `parent` key. An entry carries every column of the section 2 table, so the table can be rendered from it: `layers` (one or more of `conformance`, `security`, `integration`, `package`; the table shows a combined row such as C+I), `envs`, `harness`, `owners`, `positive`, `negative` and one `stage` per milestone. Legs are declared **per stage**. The example parses with Python `tomllib`:

```toml
gates_passed = []    # milestones whose gate PR has merged, e.g. ["M0", "M1a", "M2"]

[[scenario]]
id = "A24"
kind = "scenario"
layers = ["security"]
envs = ["pg"]
harness = ["REP", "PG", "barriers"]
owners = ["T10.9", "T21.6", "T21.8", "T52.7"]
positive = "exactly one issuance across N replicas and grants"
negative = "missing jti, replay, store failure"
matrix_sha256 = "b4df384e7893902f52bfcb5eb9415561d902b68c07ba0ca12972bb8c6e026443"

[[scenario.stage]]
milestone = "M1a"
scope = "consume primitive"
legs = ["scenarios-pg/x86_64"]
status = "planned"    # planned | implemented
tests = []

[[scenario.stage]]
milestone = "M2"
scope = "exchange across replicas and grants"
legs = ["scenarios-pg/x86_64"]
status = "planned"
tests = [
  "nextest:skyoauth-scenarios/pg/security::a24::a24_pos_single_issuance_across_replicas",
  "nextest:skyoauth-scenarios/pg/security::a24::a24_neg_concurrent_single_use",
]

[[scenario]]
id = "A64"
kind = "scenario"
layers = ["integration"]
envs = ["hermetic", "pg", "native-3os"]
harness = ["OP", "Linux service", "SoftHSM2"]
owners = ["T13.3", "T13.5", "T13.7", "T13.10"]
positive = "remote scoped write; offline recovery via the three-job chain"
negative = "key export into the pod, wrong-instance challenge, expired challenge, unsupported adapter"
matrix_sha256 = "078ca6a19a34b32f05d2982cb296c71cf5a182e64f2e6589767807fd36eaeec3"

[[scenario.stage]]
milestone = "M1a"
scope = "full row"
legs = [
  "scenarios-hermetic/x86_64",
  "scenarios-pg/x86_64",
  "operator/ubuntu",
  "operator/macos",
  "operator/windows",
  "recovery-offline/ubuntu",
  "recovery-offline/macos",
  "recovery-offline/windows",
]
status = "planned"
tests = []

[[scenario]]
id = "C07"
kind = "contract"
covered_by = ["A15", "A35"]
matrix_sha256 = "060bdd6d1424c821626c7f63561da93b9fbf89a6869d9f363128efca9fcbbf0b"
```

`matrix_sha256` is the SHA-256 of the UTF-8 bytes of the entry's whole table line, from the leading `|` to the trailing `|`, with no trailing newline: the `| A24 | … |` line in tasks §8 for a scenario, the `| C07 | … |` line in design §2 for a contract. The values above are the current ones. A sub-ID entry instead hashes the task text it was drafted from, by the same rule. A conditional sub-ID adds `conditional_on = "device-flow"` (or `"back-channel-logout"`, `"forwardauth"`).

**Which job produces a test.** A registered test ID names its package and target. The package and target fix the job, and the job fixes the env:

| Test source | Job (legs) | Env |
| --- | --- | --- |
| `skyoauth-scenarios`, targets `hermetic` / `pg` / `envoy_k3s` / `live` | `scenarios-hermetic` / `scenarios-pg` / `scenarios-envoy-k3s`, `scenarios-envoy-k3s-nightly` or `migration-rehearsal` / `live-wif` | hermetic / pg / envoy-k3s / live |
| `clients/rust/tests` | `clients-rust` (Linux x86_64) or `clients-rust-native` (ubuntu, macos, windows) | hermetic or native-3os |
| `operator/tests` | `operator` (ubuntu, macos, windows); `recovery-offline` chain | native-3os |
| `clients/typescript/test/*.test.ts` | `typescript` (Node 22, 24) | hermetic |
| `clients/typescript/test/browser/` | `typescript-browser` (Chromium, Firefox, WebKit) | browser |
| `service/tests`, `service/src` | `rust` today runs plain `cargo test`, which emits no JUnit | none: not registrable |

Service-consumer fixtures are therefore replayed from `skyoauth-scenarios`, which depends on `skyoauth-service`. A `service/` test can be registered only after a nextest job for that package is added; the same rule then applies to it. Every job above that produces registered tests runs cargo-nextest, vitest or Playwright with a JUnit reporter.

**Check: `check-conformance-registry`** (proposed path under `scripts/ci/`, to land after the concurrent `scripts/ci` work merges).

- *Static part.* Runs on **every** event, including docs-only changes, because the matrix itself lives in Markdown. It needs no build.
  - The `| Axx |` rows of tasks §8 equal the registry scenario IDs exactly: A01–A64, no gaps, duplicates or extras. The C rows of design §2 equal the contract IDs C01–C10.
  - Every `matrix_sha256` still matches, so an edited matrix row fails until the registry entry is reviewed.
  - IDs are monotonic, and owners exist as task IDs in the tasks doc.
  - Every stage milestone is a known milestone, and the last stage of each scenario is its full milestone.
  - Every stage `legs` entry names a job and leg from section 1.1, every env in `envs` has at least one leg in some stage, and every leg's job belongs to one of the scenario's `envs`.
  - Every fixture directory not starting with `_` names a registered scenario, and every fixture validates against its schema.
  - The scenario table in this document equals the table rendered from the registry (`id`, `layers`, `envs`, `harness`, stages, `owners`, `positive`, `negative`).
  - A waiver file (see the reporter) names an existing commit, test and leg, and its PR was approved by the lead.
- *Resolution part.* Runs in the code jobs.
  - Every `implemented` stage lists, **for each job among its legs**, at least one `pos` and one `neg` test produced by that job. A declared leg whose job contributes no test fails the check, so a leg such as `recovery-offline/windows` cannot be satisfied by tests from other jobs.
  - Each listed test resolves against `cargo nextest list`, `vitest list --json` or `playwright test --list --reporter=json`, and none is `#[ignore]`d, `.skip`ped or `.fixme`d.
  - **Same job.** Each listed test, from any package (`skyoauth-scenarios`, `clients/rust`, `operator/`, the TypeScript package, or `service/` once it has a nextest job), is produced by the job of one of its stage's legs, per the table above.
  - **No orphans.** Every listed test whose name matches a scenario pattern is registered in some stage's `tests`. This includes every generated fixture case: each case name (`a61_neg_query_reordered_mismatch`, `A61 neg: query_reordered_mismatch`) is listed explicitly, so adding a fixture fails the check until a stage claims it. Rust names are module-qualified, so the check matches the last path segment: `(^|::)a\d\d_`. vitest joins describe titles with ` > `, so it matches `(^|> )A\d\d[ .]`; for Playwright it matches the test's own title with `^A\d\d[ .]`.
  - **Gates.** For every milestone in `gates_passed`, every stage with that milestone is `implemented`. A gate PR changes only `gates_passed`. A PR cannot show live or post-merge stages passed, because `live-wif` and slow jobs never run on PRs. The gate check therefore reads the reporter result for a named commit on `main`: the gate PR's base commit. It passes only if every stage of that milestone is **passed** there, live and post-merge legs included. M1b and M2 can pass in either order. The gate is mechanical only for the scenario stages; the other gate conditions in tasks §3–§7 still need review.
- *Result join (reporter).* After the test jobs run, the reporter collects JUnit from every workflow run for the **same commit SHA** (CI, `live-wif`, nightly, release). cargo-nextest (pinned) emits JUnit; plain `cargo test` cannot on stable. vitest and Playwright use their junit reporters. All retries are 0, and a test that passes only on retry counts as **failed**.
  - **Re-runs never hide a failure.** The reporter reads every attempt of every run for the commit (JUnit artifacts are named with `github.run_attempt`). A failed result for a (test, leg) on a commit is permanent: a later attempt cannot overwrite it. A failure is cleared only by a new commit, or by an audited waiver in `tests/conformance/waivers.toml` naming the commit, test, leg and reason, committed through a PR the lead approved. The reporter reads waivers from the tip of `main` at judging time, because the waived commit's own tree cannot contain its waiver. A leg that produced no result (for example, a cancelled job) is not run, and a later attempt may fill it.
  - For each stage, the reporter checks every pair (test, required leg) where the test belongs to that leg's job. A fixture-driven test is one test per fixture case, so cases are keyed the same way. A pair is **passed** only with a passing JUnit case from that leg. A missing case, skipped or filtered test, skipped job or absent environment makes the pair **not run**. A required leg that never ran is therefore **not run** even if every other leg passed: A64 passing on ubuntu and macos with no windows result is not run, and so is A41 without one of its three OS legs.
  - A stage takes the worst status of its pairs, with precedence **failed > not run > passed**. A scenario takes the worst status of its stages up to the milestone being judged. A parent takes the worst of its required sub-IDs. A contract (`kind = "contract"`) is passed only when every scenario in `covered_by` is passed.
  - `planned` stages are reported as planned and never count as passed.
- Only **passed** counts. When the docs-only classifier skips the build jobs, the summary reads "runtime conformance: not run (docs-only change)". The `ci-passed` aggregator's `success | skipped` rule satisfies branch protection, but **it is not a conformance signal**. Release gating must read the reporter output, never `ci-passed`.
- **Release.** The release check requires every non-conditional scenario stage, every required sub-ID, C01–C10 and both libraries to be passed on the release commit, which must be reachable from `main`. Conditional sub-IDs are required only when the release manifest lists their feature as shipped. The manifest is a committed file owned by the T50/release owner; a change to it needs a PR the lead approved.

## 4. CI integration per milestone

**Determinism rules for all layers:**

- Proposal: auth code reads time only through an injected `Clock`. A `clippy.toml` (none exists yet) would enforce this with `disallowed-methods` on `SystemTime::now`/`Instant::now` outside the clock module. Async timers use `tokio::time::pause`.
- Concurrency tests synchronize on barriers or channels. They never sleep (A24, A34, A56, A60).
- proptest/fuzz use fixed seeds with committed regressions. Jitter and backoff take an injected RNG (A12, A56).
- Servers bind port 0 on loopback. Hermetic jobs need no egress, and every mock issuer is in-process. Cluster/Envoy jobs wait on observed conditions with deadlines, not fixed sleeps.
- Only the `live-wif` job touches the internet for conformance. The nightly real-Zitadel compatibility job also does, but it is not conformance evidence.

**Live WIF (A01, A02, A36).** Production bindings permit `push` only (T22.4). The live positive therefore comes only from the `push` to `main` run of the commit being judged. A `schedule` or `workflow_dispatch` run has a different `event_name`, and the push-only binding must deny it (A02, T22.5). Those runs supply live **negative** cases. A tag push does carry `event_name: push`, but its `ref` is `refs/tags/…`; the production binding's ref predicate (`refs/heads/main`) must deny it. The release reporter joins the push-to-main run by commit SHA. Releases are therefore cut only from commits on `main` that had a passing `live-wif` push run. The release workflow checks that the release commit is reachable from `main`, and a hotfix lands on `main` first.

**Slow jobs and merge queue.** Slow Envoy/k3s jobs are required on PRs if they take about 15 minutes or less. Otherwise they run post-merge on the push to `main`, where the reporter result for that commit gates milestones and release. `ci.yml` has no `merge_group` trigger today. A merge queue needs both the repository setting and a `merge_group:` trigger. Whether to enable one before M3 is a maintainers' repository-setting decision (section 6).

| Milestone | New jobs (Rust jobs keep the x86_64/aarch64 matrix where the bootstrap has it) | Required on PR | Post-merge / nightly / release |
| --- | --- | --- | --- |
| M0 | `conformance-registry` (static check, runs even for docs-only changes); fixture schema validation once M0 wire examples land as fixtures. **This is the only conformance-harness deliverable in M0: 64 planned scenarios and 10 planned contracts, 0 implemented.** The M0 milestone itself is T00's reviewed contracts and threat model (tasks §9). | yes, via `ci-passed` | — |
| M1a | `skyoauth-scenarios` member with `scenarios-hermetic` and `scenarios-pg`, plus the `rust` and coverage-alias changes from section 1.2; `operator` matrix ubuntu/macos/windows; `recovery-offline` three-job chain (Q6); registry resolution and reporter | yes | — |
| M1b | Same jobs extended with the human chain, T13.9 transitions, A46 origin resolution and A58 persistence sub-IDs | yes | — |
| M2 | Mock GH/TRm in `scenarios-hermetic`/`scenarios-pg`; `clients-rust` (Linux WIF, minimal/default/all features, `cargo package` and consumer); `scenarios-envoy-k3s` (pinned k3s, Envoy Gateway/egctl/Envoy, RB; A36 negatives); `live-wif` (positive from push to `main` only, negatives from schedule/dispatch, never on PRs) | hermetic and PG yes; `scenarios-envoy-k3s` yes if runtime ≤ ~15 min, else post-merge | `live-wif` on push to `main` and nightly; `scenarios-envoy-k3s-nightly` (A54 kubelet rotation) |
| M3 | `typescript-browser` (packed tarball → `examples/spa`, Playwright Chromium/Firefox/WebKit, pinned browsers); `bundle-check` (browser-platform bundle with Node built-ins forbidden, A39); Envoy job adds raw-capture cookie tests, mock OIDC×2, ≥2 controllers, cert-manager, VAP (A58 sub-IDs) | browser and bundle yes; A58 cluster sub-IDs post-merge if too slow | Nightly real-Zitadel compatibility (not conformance); nightly run of deadline cases at production defaults (Q8) |
| M4 | `clients-rust-native` matrix on 3 OSes (loopback, injected browser launcher driving Playwright for confirm, OS keychain: macOS Keychain, Windows Credential Manager, Linux secret-service under dbus); `examples/rust-cli` packaged consumer | yes | — |
| M5 | `migration-rehearsal` (artifacts built once and carried by hash into switch/rollback, OIDC×2, K3×2); `fuzz` (T52.7, time-boxed; PRs replay seed corpora only); load tests; deployed-topology T52 audit | seed replay yes | fuzz/load nightly; **release workflow** requires the reporter to show all 64 scenarios **passed** on the release commit, live jobs included, plus C01–C10 and both libraries |

Coverage: the existing gates (Rust 85 % lines; TypeScript 85 % lines/functions/branches/statements) stay on unit tests. Scenario and integration coverage is uploaded and reported but not gated (Q9).

## 5. Decisions

The lead decided these on review. They replace the former open questions Q1–Q11.

1. **Q1 Oversized rows: sub-IDs in an annex.** Scheme `A58.07` in the registry and titles, `a58_07_…` in Rust names. A parent passes only if all its required sub-IDs pass. The scenario count stays 64. The T32.3 owner drafts the A58 sub-IDs before M1b. A56, A18, A12 and A57 are split only if a row has more than about six independent assertions.
2. **Q2 "Backend denies" (A01, A08, A13, A43): yes.** Evidence is the backend-verifier fixture vectors plus a clearly test-only reference ConnectRPC backend (RB) reached through Envoy. v0.1 ships no verifier library.
3. **Q3 A33.** The required part is T10.10, T31.2 and T31.6: idle, absolute and origin expiry; local and upstream logout by indexed sid; switch invalidation; other sessions untouched. Back-channel-driven sid targeting is conditional sub-ID A33.01 and blocks release only if T30.6 ships.
4. **Q4 A53** is the disabled-record lifecycle of design §5.6: export/import round-trip; reject an enabled or approved create/import; reject an enabling PATCH; unchanged across restart and forward migration; reject startup/import with an active unsupported record (seeded through a restore fixture) without rewriting it; unchanged across provider switch. No feature flag is involved.
5. **Q5 A62** covers the internal signer groups only. Public signer rotation and overlap are A19 and C01.
6. **Q6 A64: option (a).**
   - Offline recovery runs as three jobs: Linux emits the challenge as an artifact, macOS/Windows (and Linux) sign it with the workstation operator, Linux verifies and applies it.
   - The M0 contracts set a production default and maximum for the recovery challenge TTL. The chain does not depend on runner latency: service and operator clocks are injected and start from the challenge's `issued_at`, and that clock state is carried between jobs with the artifacts. A hermetic test covers expiry at the TTL boundary, and one same-job Linux run uses real time.
   - Remote writes run a full positive against the Linux service, plus per-OS transport and keystore tests.
   - SoftHSM2/PKCS#11 is automated. Real hardware drills are manual evidence and are never counted as passed.
   - No self-hosted runners or tunnels.
7. **Q7 Live dependencies: confirmed,** with the push-to-main rule in section 4. PRs use mocks and a token-file swap. `live-wif` and real kubelet rotation (A54) run post-merge and nightly and gate release.
8. **Q8 Test-profile timings are acceptable** if they use the same code path, stay within spec ceilings, never shorten a spec minimum, and are recorded as JUnit properties. A nightly job also runs those cases at production defaults.
9. **Q9 Coverage.** Integration coverage, and scenario-package coverage generally, is informational.
10. **Q10 Fixture versions.** No compatibility window is promised. `fixture_version` stays, and a breaking change adds v2 and keeps v1 (section 1.3). A42 and T51.7 require stability through switch/rollback only; v0.1 ships v1.
11. **Q11 Contracts in the registry: yes.** C01–C10 are registered with `kind = "contract"`, `covered_by` and their own `matrix_sha256`. A contract passes only when every covered scenario passes. The mapping is decided: the corrected draft below plus the lead's additions (C03 +A16, A17, A18; C08 +A14; C10 +A64).

| Contract | Covered by | Change from the lead's first draft |
| --- | --- | --- |
| C01 issuer, discovery/JWKS, signing-key rotation | A19, A14 | A04 moved to C05: A04 rotates an external source's uploaded keyset (T11.9, T24.2), not SkyOAuth's signing key. A14 added because its endpoints include the issuer and discovery URLs, which must not change on a provider switch (T51.10). |
| C02 native OAuth, WIF exchange, session and library interfaces, generated selectors | A14, A42, A25, A49 | A25 and A49 added: C02 names generated source/grant selectors, which those rows test |
| C03 audience registrations, IDs, credential profiles, constraint semantics, gateway/backend identity | A30, A44, A55, A37, A16, A17, A18 | A37 added for constraint semantics; A16, A17 (stable IDs and constraints through migration) and A18 (gateway/backend identity) added by the lead |
| C04 human migration needs no client/backend change; clients, origins, human policies stable | A14, A17, A34 | A34 added: its switch/rollback case requires invalid human state with stable registrations |
| C05 external source configurations survive | A15, A04 | A04 added (keyset IDs and lifecycle metadata) |
| C06 bindings, grants, ceilings, scopes, constraints survive; unsupported impersonation unchanged and inactive | A16, A53 | A53 added: it is the unchanged-and-inactive impersonation record |
| C07 identical WIF outcomes; consumed proofs not reset | A15, A35 | none |
| C08 issuer distinct from upstream IdPs | A36, A55, A20, A14 | A20 added: WIF keeps working while the human IdP is down; A14 added by the lead |
| C09 tenant checks and backend RBAC never bypassed | A13, A43, A01, A08 | A01 and A08 added: both require backend tenant/RBAC denial despite a valid credential |
| C10 switch separate from policy administration; authority independent of the human IdP | A17, A47, A20, A22, A32, A63, A64 | A20, A22 and A32 added for authority and recovery independent of the IdP; A63 added because semantic provider changes must go through the guarded transition; A64 added by the lead |

## 6. Answered follow-ups, remaining questions and risks

Answered by the lead in the second review round:

1. **`tests/` as its own workspace member: accepted.** The first M1a scenario PR updates the layout in tasks §1 and design §10.4.
2. **Recovery challenge TTL:** the M0 contracts set a production default and maximum. The test chain is described under Q6 in section 5.
3. **Slow jobs:** required on PRs if about 15 minutes or less, otherwise post-merge on the push to `main` (section 4).
4. **Release commits:** only commits on `main` with a passing `live-wif` push run; the release workflow checks reachability from `main`; hotfixes land on `main` first (section 4).
5. **Contract mapping:** decided (section 5, Q11).
6. **ForwardAuth (T32.9):** two conditional sub-IDs, one under A58 (deployment-enforcer equivalence) and one under A18 (credential containment and trusted forwarded chain). Device flow stays under A27 (A27.01). The release manifest is a committed file owned by the T50/release owner; changes need a PR the lead approved.

Still open:

1. **Merge queue before M3** (maintainers): enabling a merge queue needs a repository setting and a `merge_group:` trigger in `ci.yml`. Until then, slow jobs that miss the PR budget gate only after merge.
2. **Service-side conformance evidence:** the `rust` job runs plain `cargo test`, which emits no JUnit, so `service/` tests cannot be registered (section 3). Is replaying service-consumer fixtures from `skyoauth-scenarios` acceptable, or should the `rust` job move to nextest?

Risks:

1. **ci.yml coordination.** The `rust` job and the `coverage` alias change in section 1.2 must land with the first M1a scenario PR, and another agent is editing `ci.yml` now. Land the registry check (M0) first.
2. **Docs-only blind spot.** Editing the §8 matrix is a docs-only change that today skips all build jobs. The static registry check must run outside the `changes` gate, or matrix drift will merge unnoticed.
