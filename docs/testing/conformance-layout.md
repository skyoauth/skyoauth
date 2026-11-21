# Conformance test layout (proposal)

> Status: proposal, partly in place. What exists: the bootstrap `service/tests/shutdown.rs`, the vitest suite in `clients/typescript/test/`, the two coverage gates, `scripts/ci/docs-only.sh`, the registry in `tests/conformance/` with its generator and the static part of `check-conformance-registry` (section 3, run by the `conformance-registry` job), and its resolution part for nextest test IDs (`--nextest-list`, run by the `scenarios-pg` job), the `service-nextest` job (workspace tests under cargo-nextest with a JUnit report), the Rust scenario package `skyoauth-scenarios` at `tests/` (section 1.2) with its `pg` target and template-DB isolation helper, and the `scenarios-pg` job, which runs that target; the first implemented stage is A29's M1a stage. A first version of the result reporter, `scripts/ci/report-conformance.mjs` (section 3), also exists; its self-test runs in the `conformance-registry` job, and the informational `conformance-report` job runs it on the leg artifacts of each CI run that runs the code jobs and is not cancelled (section 3 **Leg artifacts**), and does not run on docs-only changes; no job yet joins every run of a commit or judges a gate. Everything else below is still a proposal. The Rust gate is the `cargo coverage` alias in `.cargo/config.toml` (85 % **lines** only); the `rust-coverage` job runs it with `-- --include-ignored` against the pinned PostgreSQL service, so the `#[ignore]`d PostgreSQL tests of `service/tests/` count toward it. The TypeScript gate is in `clients/typescript/vitest.config.ts` (85 % lines, functions, branches **and** statements). Sources: tasks §1, §8 (A01–A64), §9 DAG, §10, T50.8, T51, T52; design §2 (C01–C10), §5.6, §10. Lead decisions on the former open questions are recorded in section 5.

## 1. Layout and ownership

| Home | Holds | Does not hold |
| --- | --- | --- |
| `service/src/**` `#[cfg(test)]`, `service/tests/*.rs`, `clients/*/test(s)/` | Unit tests for one module or package API. These count toward the existing coverage gates. `service/` tests may also need PostgreSQL: they are `#[ignore]`d, reach the pinned PostgreSQL service container through `SKYOAUTH_IT_DATABASE_URL`, and count toward the Rust gate like the others (Q9). They can support a scenario, but a scenario stage does not count as `implemented` on these tests alone. | Anything that needs Envoy, a cluster or a browser; outside `service/`, anything that needs PostgreSQL |
| `tests/conformance/` | Versioned wire/profile/migration **fixtures** and the scenario registry. Expected outcomes are fixed here: claim sets, error bodies, digest vectors (A61), comparison vectors (A59), refresh/retry transcripts (A57) and migration decision tables (A15/A42). | Attack-only logic, environment bring-up |
| `tests/security/` | Negative-heavy tests for JWT/OIDC/CSRF/admin/tenant/audience/replay/gateway (T52.1–T52.6), plus fuzz targets and committed seed corpora (T52.7) | Shared positive wire contracts. Those go in conformance and security references them. |
| `tests/integration/` | Tests against real dependencies: PostgreSQL, mock OIDC, two k3s clusters, pinned Envoy Gateway/egctl/Envoy, cert-manager, the test-only reference ConnectRPC backend and multi-replica service. Shell scripts under `tests/integration/env/` only start and stop environments. Assertions live in Rust or TypeScript so every result is reported the same way (JUnit). | Assertions written in shell |

The three directories are **source homes grouped by layer**. Layer is a label for review and reporting only. Where a test runs is decided by its **execution environment** (section 1.1), not by its directory.

### 1.1 Execution environments

Every scenario lists the environments its required tests need (`envs` in the registry, **Env** column in section 2). Each environment maps to fixed CI jobs and legs. The **Leg strings** column lists every leg exactly as a registry stage names it in `legs`: `job/leg`, or the bare job name for a job with a single leg.

| Env | Code | Provides | CI job (legs) | Leg strings |
| --- | --- | --- | --- | --- |
| `hermetic` | H | No network, no database. In-process mocks only (GitHub OIDC issuer, TokenReview, human IdP), fixtures, injected clock. | `scenarios-hermetic` (x86_64, aarch64) for the scenario package; `clients-rust` (Linux x86_64) from M2; `typescript` (Node 22, 24) for vitest; `bundle-check` from M3 | `scenarios-hermetic/x86_64`, `scenarios-hermetic/aarch64`, `clients-rust/x86_64`, `typescript/node22`, `typescript/node24`, `bundle-check` |
| `pg` | PG | `hermetic` plus a pinned PostgreSQL service container, template DB per test, the barrier-driven replica harness (REP) and fault-injecting repositories. Any test that reads or writes state through the real repository is `pg`. No in-memory repository is proposed, so the atomicity claims (A24, A34) are tested on the real store. | `scenarios-pg` (x86_64) | `scenarios-pg/x86_64` |
| `envoy-k3s` | EK | `pg` plus pinned k3s (one or two clusters), Envoy Gateway/egctl/Envoy with raw upstream capture, cert-manager, VAP, ≥2 controllers and the reference ConnectRPC backend | `scenarios-envoy-k3s` (x86_64); `scenarios-envoy-k3s-nightly` for real kubelet rotation (A54) and long deadline narratives; `migration-rehearsal` from M5, which also drives the packed SPA in Playwright and the Linux CLI itself (A14); `deployed-topology-audit` from M5 for the deployed-topology audit stages (A18, A58, A62) | `scenarios-envoy-k3s/x86_64`, `scenarios-envoy-k3s-nightly`, `migration-rehearsal`, `deployed-topology-audit` |
| `browser` | BR | Packed `@skyoauth/client` tarball installed in `examples/spa`, Playwright with pinned browsers, against the `envoy-k3s` stack | `typescript-browser` (Chromium, Firefox, WebKit) | `typescript-browser/chromium`, `typescript-browser/firefox`, `typescript-browser/webkit` |
| `native-3os` | N3 | Native binaries on hosted Linux, macOS and Windows runners | `operator` (M1a), `recovery-offline` three-job chain (M1a, see Q6), `clients-rust-native` (M4); each with the legs ubuntu, macos and windows | `operator/ubuntu`, `operator/macos`, `operator/windows`, `recovery-offline/ubuntu`, `recovery-offline/macos`, `recovery-offline/windows`, `clients-rust-native/ubuntu`, `clients-rust-native/macos`, `clients-rust-native/windows` |
| `live` | LV | Real GitHub Actions OIDC (`id-token: write` on these two jobs only) and egress | `live-wif-push` in the `push` to `main` run of the commit: the **positive** case and a wrong-audience **negative** with the same token; `live-wif-negative` in `schedule` and `workflow_dispatch` runs: the push-only binding's **denials** and a **positive control** against a test-only binding that permits that event (see section 4) | `live-wif-push`, `live-wif-negative` |

The `service-nextest` job (the workspace's unit and DB-backed tests under cargo-nextest, JUnit uploaded as `service-nextest-junit-<attempt>`) is not a conformance job: it has no environment and no leg string, its artifact has no `leg` file, and the reporter ignores it (section 3, section 6 "Still open", item 3).

Nightly real-Zitadel compatibility (T30.1) is a compatibility job, not a conformance environment. Its result never counts toward a scenario.

### 1.2 Rust scenario package and the CI mechanism

The workspace member `tests/Cargo.toml` (`skyoauth-scenarios`, `publish = false`) landed with the first M1a scenario PR (A29), which also updated the layout in tasks §1 and design §10.4. The package was not added before it had a test (tasks §1: no empty scaffolding).

- **Targets by environment, not by layer.** The package has up to four `[[test]]` targets: `hermetic`, `pg`, `envoy_k3s` and `live`. A target is added with its first test, never empty; today only `pg` exists (`autotests = false`, so Cargo discovers no other target). Each target root declares its modules from the layer directories with `#[path]`. A test's full name is therefore module-qualified, for example `security::a24::a24_neg_concurrent_single_use` in the `pg` binary.
- **No features, no cfg.** The package declares no Cargo features. A feature gate cannot work: the `rust`, `msrv` and coverage jobs pass `--all-features`, which would switch it on. A declared `--cfg` (with `check-cfg` under `unexpected_cfgs`) would work, but it compiles the environment tests out of the generic jobs, so clippy would stop linting them unless a second clippy pass ran with the cfg. Splitting targets avoids both problems.
- **Loud failure.** The `pg`, `envoy_k3s` and `live` targets fail on first use when the variables they need are missing (`SKYOAUTH_IT_DATABASE_URL`, `SKYOAUTH_IT_ENVOY`, …). They never pass vacuously.
- **Shared helpers** live in the package's `src/`. Today that is the PostgreSQL template-DB isolation (`tests/src/pg.rs`: the migrations are applied once to a template database named after a digest of the migrations and one of the connecting role, and each test gets a copy). Planned: an injected-clock builder, a mock GitHub/OIDC issuer, a mock TokenReview, the replica harness and a JWKS server that counts fetches per source. A helper used only by the scenario modules of one target may instead be a module of that target in a layer directory, declared in the target root like a scenario module: today `tests/security/grant_fixture.rs`, the A38 and A53 fixture of the `pg` target. Such a module holds no tests, and its name does not match `a\d\d_` (the Rust scenario-name prefix of section 3). The reporter and the resolution part of `check-conformance-registry` read a test as a scenario test only by the last `::` segment of its name, the test function's own name, so a helper module's functions and its name are never taken for scenario tests.
- **Mock OIDC** is built in-repo, in Rust, in this package, so tests can inject attacks: mix-up, wrong issuer, attacker-initiated callbacks and two providers.

Required changes, applied by the first M1a scenario PR (A29):

| File | Change |
| --- | --- |
| `.github/workflows/ci.yml`, job `rust` | Both `cargo test` steps (tests and doctests) become `--workspace --exclude skyoauth-scenarios`. Clippy and `cargo doc` keep `--workspace --all-features`: they only compile, so the package stays linted on both arches without any environment. |
| `.github/workflows/ci.yml`, job `msrv` | Unchanged. `cargo check` only compiles. |
| `.cargo/config.toml`, alias `coverage` | `llvm-cov --workspace --exclude skyoauth-scenarios --all-features --ignore-filename-regex main\\.rs --fail-under-lines 85`. The Rust gate keeps measuring the workspace's own tests (the `service/` PostgreSQL tests included, which `rust-coverage` runs with `-- --include-ignored`), not scenarios. Scenario coverage is informational (Q9). |
| `.github/workflows/ci.yml`, job `service-nextest` | `--workspace --exclude skyoauth-scenarios`: the job reports the workspace's unit and DB tests and has no leg string (section 1.1), so the scenario package's tests run only in their `scenarios-*` jobs. |
| `.github/workflows/ci.yml`, new jobs | `scenarios-hermetic`, `scenarios-pg`, `scenarios-envoy-k3s`: each runs `cargo nextest run --locked -p skyoauth-scenarios --test <target> --profile ci` (pinned cargo-nextest, `retries = 0`, JUnit output uploaded as an artifact). Each is gated on `needs.changes.outputs.code` like the existing jobs and is added to the `needs` list of `ci-passed`. `scenarios-pg` runs exactly this command; with no test filter and no `--no-tests` override, an empty selection fails the job. `scenarios-hermetic` and `scenarios-envoy-k3s` are added with their targets' first tests. |

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
  | `service/` (unit support only until a job that runs it has a leg string, section 3) | `CARGO_MANIFEST_DIR/../tests/conformance/fixtures` |
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
- **Restore-state cases (`kind: "restore_state"`).** A state that the normal APIs must refuse to create, such as A53's active unsupported impersonation record, is seeded from a restore-state case, never from a normal API call. It is an ordinary case file in the scenario's directory (`fixtures/a53/<case>.json`) with the envelope above: `consumers` is `["service"]`, `input.rows` holds the stored rows to seed, keyed by table, and `expected` holds the outcome the service must produce when it meets that state, for example at startup or import. The rows must be written unchanged, and the test asserts afterwards that they still are. Design §5.6 keeps the preservation tests on normal APIs, so a restore-state case seeds only state that those APIs reject. The `kind` is decided; the case shape (`input.rows` keyed by table, and the `expected` outcome) is a proposal until the PR that implements A53 settles it and adds the first case.
- **Versions.** Every fixture carries `fixture_version`. v0.1 ships version 1 only. A breaking wire change adds `*.v2.json` and keeps v1. A42 and T51.7 require only that the shipped per-profile wire/error contract and the prebuilt consumers stay stable through provider switch and rollback. This proposal promises no compatibility window beyond that.

## 2. Scenario map

This table and the counts sentences after it are rendered from `tests/conformance/scenarios.toml` and the `table_text` of `tests/conformance/subcases.toml`, which are the single source. Edit the registry and run `node scripts/ci/gen-conformance-registry.mjs`; the registry check fails when the committed table differs from the rendered one (section 3).

Legend:

- **Layer:** C conformance · S security · I integration · P client package. A label only.
- **Env:** execution environments from section 1.1 (H, PG, EK, BR, N3, LV). The jobs follow from the env.
- **Harness:** UC in-process service with injected clock · PG PostgreSQL · FX shared fixtures · GH mock GitHub OIDC · GH-live real Actions OIDC · TRm mock TokenReview · K3 / K3×2 one or two k3s clusters · ENV pinned Envoy Gateway with raw upstream capture · OIDC / OIDC×2 mock human IdP(s) · BR Playwright real browser · RN Rust native on Linux/macOS/Windows · OP `skyoauth-operator` · REP ≥2 service replicas on one PG with barriers · RB test-only reference ConnectRPC backend behind Envoy.
- **Stages:** the milestone at which each part of the row must pass. A row with one milestone has one stage. These map one-to-one to registry stages (section 3).
- **+ / −:** the minimum positive and negative cases. Every row needs at least one of each.
- **Conditional** sub-IDs block release only if the named optional feature ships.

| ID | Layer | Env | Harness | Stages | Owners | + / − required |
| --- | --- | --- | --- | --- | --- | --- |
| A01 | C+I | PG, EK, LV | FX, GH, PG, GH-live, ENV, RB | M2 | T12.3, T20.3, T21.4, T22.2, T22.6 | + push to `main` with selected grant → WIF profile with signed tenant/grant/revision (live positive only from the push-to-main run of that commit); − same token blocked by RB tenant/RBAC |
| A02 | S | PG, LV | GH, PG claim-mutation table, GH-live | M1a: policy on verified-claim fixtures · M2: exchange and live negatives | T12.2, T12.7, T22.5, T52.2 | + push; − one case each for pull_request, pull_request_target, workflow_dispatch, issue_comment, workflow_run, missing event, and wrong owner/repo/ref/env/workflow; live: the real token of a `schedule` or `workflow_dispatch` run is denied by the push-only binding |
| A03 | S | H, PG | FX, GH with per-source JWKS fetch counter, UC | M1a: verifier selection · M2: exchange | T11.5, T11.7, T21.3, T52.1 | + selected source verifies; − wrong iss/kid/aud, asserting no verifier call and no discovery/JWKS fetch for any non-selected source |
| A04 | C | PG | PG, UC | M1a: keyset lifecycle · M2: exchange through the overlap | T11.3, T11.6, T11.9, T24.2 | + old and new keys valid in the overlap, with parent/source/binding/grant IDs unchanged; − each key outside its window |
| A05 | S | H, PG | UC, FX | M1a: upload, token-header and egress-allowlist rejection · M2: generic issuer keysets | T11.2, T11.3, T11.5, T11.8, T24.3, T52.1 | + public-only JWK; − private members, jku, x5u, embedded jwk, unsafe key URL; a `discovery_url` or `token_review_endpoint` with no enabled matching egress allowlist entry rejected on create or change, a discovered `jwks_uri` with no enabled `jwks` entry not fetched, no new discovery or JWKS fetch through a disabled entry (IR-152); M2 adds disallowed issuer/alg, conflicting kid, cross-tenant keyset |
| A06 | I | PG, EK | TRm (PR), K3 | M2 | T23.2, T23.3, T23.5 | + SA/Pod with intended audience → scoped token for selected tenant/cluster; − policy demanding claims TokenReview does not return is rejected; a TokenReview call through a disabled egress allowlist entry is denied with no fallback |
| A07 | S+I | PG, EK | TRm, K3 | M2 | T23.4, T23.6, T52.2 | + baseline; − wrong cluster/SA/audience, expired token, deleted Pod/SA, no local-JWT fallback |
| A08 | I | EK | OIDC, PG, ENV, RB | M3 | T31.4, T32.1, T32.2, T32.5 | + cookie, CSRF and Origin → human_session assertion; − RB tenant/RBAC denies even with a valid assertion |
| A09 | S | PG, EK, BR | UC, ENV, BR | M3 | T31.4, T33.6, T52.3 | + correct Origin/CSRF; − each unsafe method (including Connect POST) with missing or wrong Origin or CSRF |
| A10 | S | PG, EK | UC, ENV | M2: bearer + assertion · M3: cookie | T25.2, T31.4, T32.4 | + each credential alone; − cookie + bearer, bearer + internal assertion, duplicate auth cookies |
| A11 | S | PG | UC, PG with fault-injecting repository | M3 | T31.2, T31.5, T32.6 | + live session; − revoked or expired → 401, store down → 503, never an allow |
| A12 | I+P | PG, EK, BR, N3 | ENV, RB, UC, BR, RN | M2: bearer · M3: browser leases · M4: native reconnect | T26.6, T32.7, T32.8, T32.12, T33.3, T40.15 | + bytes go straight through Envoy, fresh-token reconnect resumes by cursor; − continuing past exp/lease/1 h, restarted mutation, unbounded retry |
| A13 | C+S | H, EK | FX backend-verifier vectors, RB | M2: WIF · M3: human_session · M4: human_cli | T12.9, T14.2, T20.4, T25.4, T40.13, T52.6 | + canonical tenant and RBAC match; − valid credential on another tenant's resource; name-only match; WIF token whose signed allowlist does not cover the resource/action (M2); human_session whose backend RBAC denies (M3); human_cli whose backend RBAC denies (M4) |
| A14 | I | EK | OIDC×2, BR, RN, packed artifacts with recorded sha256 | M5 | T41.5, T51.5, T51.10 | + same artifacts, endpoints and config work after reauth; − old session/refresh denied; any artifact or config hash change fails the test |
| A15 | I | PG, EK | GH, uploaded keyset, K3×2 shared issuer, PG | M5 | T23.7, T51.2, T51.6, T51.7 | + identical decision fixtures before and after; − any changed source/CA/reviewer/keyset ID fails |
| A16 | I | PG | PG, OIDC×2 | M1b: T13.9 transition · M5: switch | T10.11, T12.10, T13.9, T51.6 | + IDs, modes, defaults, constraints and revisions equal; − dormant impersonation still disabled and not issuable |
| A17 | I | PG | PG, OIDC×2 | M1b: T13.9 transition · M5: rehearsal | T13.9, T51.8 | + policy/audience change made between switch and rollback survives, epochs are fresh; − pre-switch human state not resurrected |
| A18 | S+I | EK, BR | ENV raw capture, OIDC, BR, deployed T50 topology (M5) | M2: header spoof · M3: cookies · M5: deployed-topology audit | T25.4, T32.4, T50.4, T52.4 | + real SkyOAuth cookie flows work, including the native flow through `/oauth/callback/{provider_id}`; − Cookie, X-SkyOAuth-CSRF or Set-Cookie on any enrolled-host route other than the exact exempt cookie paths (including no-Check routes and non-exempt SkyOAuth endpoints such as `/oauth/token`, `/oauth/revoke`, `/.well-known/*` and `/_skyoauth/oidc/backchannel-logout`), missing rule rejected, copies in logs/retries/mirrors, cross-audience assertion. Conditional sub-ID (ForwardAuth, T32.9): credential containment and trusted forwarded chain |
| A19 | C | H, EK | FX, UC, ENV JWKS cache | M2 | T20.1, T20.2 | + old and new tokens verify through the overlap with no config change; with the audit sink missing or unavailable, emergency disable and standby promotion still proceed, with an alert and a local append-only record; − retired key after overlap, unknown kid; public key enrollment, activation or publication with no configured audit sink is refused, including a sink endpoint that is set but fails startup validation |
| A20 | I | PG, N3 | OIDC outage toggle, PG, OP | M3: outage · M5: switch during outage | T13.7, T30.3, T51.11 | + WIF and operator recovery during the outage; − fresh login fails closed |
| A21 | S | PG | PG, UC | M2: WIF · M4: human | T12.6, T20.7, T26.5 | + outstanding token verifies offline until exp ≤ 300 s; − new issuance and live check after committed disable |
| A22 | S | PG | UC, OIDC, OP | M1a: operator · M3: linking | T13.1, T13.6, T30.4, T52.3 | + registered mTLS adm credential with active role (M1a); explicit verified link (M3); − email-only match, upstream admin-role claim |
| A23 | C | PG | GH/TRm, PG | M2 | T21.6, T23.5 | + reusable proof used twice → two distinct output jti; − repeat after revocation |
| A24 | S | PG | REP, PG, barriers | M1a: consume primitive · M2: exchange | T10.9, T21.6, T21.8, T52.7 | + exactly one issuance across N replicas and grants; − missing jti, replay, store failure |
| A25 | C | PG | PG, UC | M1a: selection · M2: exchange | T12.3, T12.8, T21.4, T21.7 | + selector picks the authorized actor/target; − mode override, wrong tenant; subject/target override (M2) |
| A26 | C | PG | PG, UC | M1a: policy · M2: exchange | T12.8, T21.5 | + omitted scope → explicit defaults; − omitted with no defaults, empty or excessive scope → invalid_scope; any `resource` parameter → invalid_target, an audience not in the grant's audience set or not assigned → invalid_target, an unsupported requested_token_type → invalid_request (M2) |
| A27 | S | BR, N3 | BR, OIDC with live SSO, RN, attacker loopback process | M4 | T40.2, T40.4, T40.8, T52.3 | + explicit confirmation yields a code; − SSO alone, deny, expiry, attacker's own PKCE/loopback: no code. Conditional sub-ID A27.90 (device flow, T40.6): user-code approval, expiry/polling abuse, no interaction bypass |
| A28 | S | PG, EK | K3×2 (PR: two TRm sharing an issuer string) | M2 | T11.7, T11.10, T23.4 | + selected cluster validates; − other cluster's proof, asserting no probing or fallback |
| A29 | S | PG | PG | M1a: registry and references · M1b: human registry references · M2: exchange | T10.8, T11.10, T14.8, T21.3 | + same-issuer and same-name registrations coexist; − each crossed reference at write (M1a); a proof from one tenant's source with another tenant's grant at exchange (M2) |
| A30 | C | H | FX claim-set vectors per profile | M2: WIF · M3: human_session · M4: human_cli | T12.9, T20.3, T20.4, T32.5, T40.13 | + complete set per profile; − absent, unknown, contradictory, missing revision, subject-prefix exemption attempt |
| A31 | S | PG | PG, mTLS checker identities, fault injection | M2: WIF · M3: human | T14.3, T26.1, T26.3, T26.5 | + correct checker/action; − each wrong dimension, superseded revision; unavailable → typed unavailable, no positive cache, no redirect |
| A32 | S | PG | PG, local verifier, OP, barriers | M1a | T13.4, T13.5, T13.6 | + one bootstrap, signed recovery restores; − concurrent or reopened bootstrap, forged IdP admin, revoked key, replayed recovery |
| A33 | S | PG | PG, UC | M3 | T10.10, T31.2, T31.6 | + inside both deadlines; − idle expiry, absolute expiry, wrong origin, no revival by coalesced write; local and upstream logout revoke exactly the sessions of the indexed sid, switch invalidation revokes affected sessions, other sessions untouched. Conditional sub-ID A33.90 (back-channel logout, T30.6): verified sid targeting |
| A34 | S | PG | REP, PG, barriers | M4: code and refresh · M5: switch/rollback | T10.9, T40.3, T40.5, T40.15, T51.4 | + one code use and one refresh successor; − concurrent reuse, plain replay revokes the family, ID added/removed on replay, post-switch refresh |
| A35 | S | PG | PG, UC | M2: digest-key rotation, restore · M5: switch | T10.6, T21.8, T51.7, T51.9 | + fresh proof works after each change; − consumed proof stays denied |
| A36 | I | EK, LV | GH-live, K3, ENV, RB | M2 | T22.6, T23.5, T25.5 | + real GitHub (push-to-main run only) and k3s calls reach the API; − spoofed headers, IdP/store outage, direct backend, private listener |
| A37 | C | PG | PG, UC | M1a | T00.12, T12.2 | + optional predicate omitted is unconstrained; − required production predicate omitted rejects, removal needs widening approval |
| A38 | C+S | H, PG | UC, PG, metadata fixture | M1a: dormant impersonation record stored and not enableable or approvable; a delegation grant's re-enable moves its revision forward, never back (registry API) · M2: metadata and issuance; a re-enable does not revive issuance-time dependency_revisions evidence (tasks §3) | T10.11, T12.5, T20.1 | + disabled record stored; − a disable/re-enable cycle cannot revive old evidence: re-enabling a disabled record does not resurrect its prior revision (M1a) or its evidence (M2, tasks §3); device or impersonation not advertised, issuance rejected, capability gain does not activate (M2) |
| A39 | P | H, BR | npm pack, browser bundle check, BR, typecheck | M3 | T33.2, T33.4, T33.8 | + core from the tarball works in the browser; − Node built-in, polyfill, react or connect in the core bundle fails |
| A40 | S+P | H, BR | vitest fetch spy, BR | M3 | T33.1, T33.6, T33.7 | + same-origin HTTPS with CSRF; − foreign origin, userinfo, http, redirect, option overrides, off-origin health base: no CSRF or cookie sent; no token getter in the API and nothing written to localStorage/sessionStorage/IndexedDB; caller-supplied Authorization/bearer rejected (no mixed auth); no automatic mutation replay after 401 or login |
| A41 | P | N3 | RN on 3 OSes, examples/rust-cli, mock issuer | M4 | T40.7, T40.9, T40.10, T40.11 | + PKCE/loopback/cancel with minimal and default features; − plaintext fallback, off-origin forwarding, non-loopback redirect, credential or refresh token in logs/`Debug`/error output (redaction) |
| A42 | C | H, EK, BR, N3 | FX v1, prebuilt consumers, OIDC×2 | M4: fixtures · M5: through switch/rollback | T41.5, T51.5, T51.7 | + every shipped fixture version (v1 in v0.1) passes before and after switch/rollback with unchanged artifacts; − cross-profile credential use |
| A43 | S | PG, EK | PG, RB | M1a: write · M2: issuance and backend | T14.1, T14.2, T52.6 | + A uses its own audience; − B writes, grants or issues on A's audience, RB tenant mismatch |
| A44 | C+S | H | FX, UC | M3: human_session · M4: human_cli | T12.9, T20.3, T32.5, T40.13 | + complete human_session and human_cli; − missing discriminator, WIF forged into human shape, wrong route |
| A45 | C | PG | PG, mTLS checker | M2 | T14.3, T26.3, T26.5 | + direct grant with null target passes live check; − delegated subject as checker, unknown action, another audience's checker |
| A46 | S | PG, EK | ENV, OIDC×2, PG | M1b: resolution · M3: redirect | T14.7, T30.2, T30.3 | + each origin resolves to its own tenant/provider; − spoofed Host/Forwarded/tenant query and unknown origin denied before redirect |
| A47 | S | PG | PG | M1b | T10.7, T13.9 | + plan/commit advances pointer and epochs; − PATCH, import, reload, delete or auth-critical edit rejects atomically, epochs unchanged |
| A48 | I | PG | OP, local verifier, empty PG | M1a: workload · M1b: human | T13.3, T13.8, T13.10 | + full chain with no SQL; with `single_actor_mode` off, a `widening_second_approver` toggle takes effect only when an `approve` operation by a distinct second `security_admin` applies it; with `single_actor_mode` set in deployment configuration, one `security_admin` turns it on or off; − each step without its role; with `single_actor_mode` off, a `widening_second_approver` toggle without a distinct second `security_admin` approver; self-approval of the toggle by the requesting actor; an approver without `security_admin`; an online write to `single_actor_mode` or the audit sink fields |
| A49 | C | PG | PG, OP | M1a: IDs, export, reapply · M2: exchange | T10.2, T10.5, T14.8, T21.1 | + distinct IDs, deterministic export/reapply; − cross-tenant probe; exchange with names instead of generated IDs rejects (M2) |
| A50 | C | PG | PG, UC | M1a: matching · M2: exchange | T12.3, T21.4, T21.7 | + grant actor's binding matches despite another actor's overlap; − no eligible match; several same-actor matches give a stable ID with no union |
| A51 | S | BR | BR with attacker and victim contexts, OIDC | M3 | T30.2, T30.7, T33.5, T52.3 | + normal login; − attacker callback in victim browser, wrong cookie, mix-up, tampered return, stale tab: victim session unchanged |
| A52 | S | BR, N3 | BR, OIDC, RN | M4 | T40.3, T40.12, T52.3 | + issuer-native flow with approval; − transaction ID alone, app cookie, foreign browser, reused rotated binding |
| A53 | S | PG | PG, UC, OP, restore fixture | M1a: disabled-record lifecycle · M1b: forward migration | T10.11, T12.10 | + disabled/requires_reapproval record round-trips through export/import and stays unchanged across restart and forward migration (M1b); − enabled/approved create or import rejected, enabling PATCH rejected, startup/import with an active unsupported record (seeded by restore fixture) rejected without rewriting it; the same restore-fixture startup/import case after forward migration (M1b) |
| A54 | C+I | PG, EK | TRm with token-file swap (PR), K3 kubelet rotation (nightly) | M1a: single_use rejection · M2: renewal | T11.11, T21.6, T23.1, T23.5, T23.6 | + reusable enrollment/import of a TokenReview/projected source accepted (M1a); renews with the same token, then with the rotated token (M2); − single_use enrollment/import on a TokenReview/projected source |
| A55 | C | H | FX, UC | M2: WIF · M3: internal assertion · M4: human_cli | T00.3, T20.8, T32.2, T40.13 | + exact type/profile/ingress pairs; − at+jwt, ID token, internal token on bearer ingress, WIF token with invented client_id |
| A56 | I+P | PG, EK, BR | PG, ENV, RB, UC, BR | M3 | T14.5, T32.6, T32.12, T33.3 | + owner close releases once, cap change affects new admission only; − foreign or replayed close, retry-budget reset loop, 503 → login |
| A57 | C+P | PG, N3 | PG, UC, RN, plain OAuth form client | M4 | T40.5, T40.15 | + plain rotation; Rust exact retry ≤ 30 s gets one successor; − consumed replay revokes, added/malformed ID, downgrade, beyond 7 d/24 h |
| A58 | I | PG, EK | K3, ENV, cert-manager, VAP, ≥2 controllers, UC, deployed T50 topology (M5) | M1b: prepare/approve persistence · M3: enforcement · M5: deployed-topology audit | T13.2, T14.9, T31.6, T32.3, T32.4, T50.4, T52.4 | Sub-IDs A58.01–A58.89 in the annex (Q1): + every approved, mode-matched path; − every listed stale/wrong-mode/revoked/mismatch/hold case. Conditional sub-ID (ForwardAuth, T32.9): deployment-enforcer equivalence |
| A59 | C+S | H, BR, N3 | FX comparison vectors, BR, RN | M4 | T40.2, T40.8, T40.14 | + matching descriptor approves; − each comparison field changed, concurrent malicious request, superseded tab |
| A60 | S | PG, BR, N3 | OIDC, PG, barriers, BR/RN | M3: browser · M4: native | T30.4, T30.8 | + auto_create creates one zero-privilege principal; − default denies, email merge, disabled replacement, migration hold |
| A61 | C+S | H, EK | FX digest vectors, ENV | M3 | T32.2, T32.13 | + 4 KiB query → fixed 43-char binding; − each byte-level variant, rewrite or rematch; logs redacted |
| A62 | S | PG, EK | UC, PG, REP, deployed T50 topology (M5) | M3: internal signer lifecycle and standby tripwire · M5: deployed-topology audit | T32.14, T50.3, T52.5 | Internal signer group only (Q5). + rotation and clean promotion; − valid unpromoted-standby signature denies and alerts, invalid-signature kid spoof raises no verified alert, disabled active key with no standby fails closed |
| A63 | S | PG | PG, OIDC | M1b: admin · M3: sessions · M4: refresh | T13.9, T30.9, T52.5 | + credential-only rotation keeps epochs, sessions and refresh; − semantic change via the rotation path rejects |
| A64 | I | H, PG, N3 | OP on 3 OSes, Linux service, SoftHSM2 | M1a | T13.3, T13.5, T13.7, T13.10 | + remote scoped write against the Linux service; offline recovery via the three-job chain on injected clocks, plus one same-job Linux run in real time (Q6); a challenge signed within its TTL accepted (hermetic); − key export into the pod, wrong-instance challenge, expired challenge at the TTL boundary (hermetic), unsupported adapter fails explicitly |

Counts by first stage: M1a 19 · M1b 6 · M2 17 · M3 13 · M4 7 · M5 2. Counts by final stage: M1a 3 · M1b 3 · M2 21 · M3 13 · M4 13 · M5 11. 36 rows have more than one stage. Of the 11 M5 stages, 8 belong to T51: A14 (T51.5, T51.10), A15, A16, A17, A20, A34, A35 and A42. The other 3 are deployed-topology audits run by the `deployed-topology-audit` job: A18 and A58 (T50.4, T52.4) and A62 (T50.3, T52.5). T52 is the security conformance task group (T52.1–T52.8). The §9 DAG feeds it the deployed T50 topology, but the spec does not say that every S row is re-run there; which other S-row tests also run against the deployed topology is for the T52 owner to register as M5 stages.

**Stages are separate evidence.** Each stage has its own tests and its own result, and the gate of its milestone needs that stage passed. For example, A12's M2 stage is the bearer expiry and fresh-token reconnect of T26.6 and must pass at the M2 gate. A12 as a whole stays open until its M3 and M4 stages pass too. Likewise, A38's M1a stage covers only the storage half of its row: "not approvable" in its scope means that the record's `requires_reapproval` marker cannot be cleared through the registry API, and its part of the re-enable negative is a revision that moves forward through the registry API; the tasks §3 line that the row cites (**Policy revisions**: "A disable/re-enable cycle cannot revive old evidence") is the issuance-time `dependency_revisions` rule, which needs issuance and belongs to A38's M2 stage. A scenario counts as passed for release only when every stage passes.

## 3. Naming and traceability

**Test names.**

- Rust: `a<NN>_<pos|neg>_<behaviour>`, for example `a02_neg_pull_request_target_against_push_binding`. Sub-IDs use `a<NN>_<SS>_<pos|neg>_<behaviour>`, for example `a58_07_neg_stale_approval`.
- vitest/Playwright: the test's own title begins with `A40 pos:` or `A40 neg:`; sub-IDs use `A58.07 neg:`.
- The polarity token lets the checker confirm both a `pos` and a `neg` test for every implemented stage.

**Registry.** `tests/conformance/scenarios.toml` holds all 64 scenarios and the 10 contracts from M0. Sub-IDs live in an annex file `tests/conformance/subcases.toml` as `[[subcase]]` entries with `kind = "subcase"`, the same entry shape and a `parent` key. An entry carries every column of the section 2 table, so the table can be rendered from it: `layers` (one or more of `conformance`, `security`, `integration`, `package`; the table shows a combined row such as C+I), `envs`, `harness`, `owners`, `positive`, `negative`, an optional `note` for text that the **+ / −** cell shows before its `+` (A58, A62), and one `stage` per milestone. The conditional sub-ID sentence that ends a row's **+ / −** cell is rendered from that sub-ID's entry (below). Legs are declared **per stage**, as leg strings from the section 1.1 **Leg strings** column. The example parses with Python `tomllib`:

```toml
gates_passed = []    # milestones whose gate PR has merged, e.g. ["M0", "M1a", "M2"]; M0 has no stages:
                     # ADR ratification and the doc checks gate it, not the reporter

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
scope = "exchange"
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
harness = ["OP on 3 OSes", "Linux service", "SoftHSM2"]
owners = ["T13.3", "T13.5", "T13.7", "T13.10"]
positive = "remote scoped write against the Linux service; offline recovery via the three-job chain on injected clocks, plus one same-job Linux run in real time (Q6); a challenge signed within its TTL accepted (hermetic)"
negative = "key export into the pod, wrong-instance challenge, expired challenge at the TTL boundary (hermetic), unsupported adapter fails explicitly"
matrix_sha256 = "078ca6a19a34b32f05d2982cb296c71cf5a182e64f2e6589767807fd36eaeec3"

[[scenario.stage]]
milestone = "M1a"
scope = "full row"
legs = [
  "scenarios-hermetic/x86_64",
  "scenarios-hermetic/aarch64",
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

A sub-ID entry in `tests/conformance/subcases.toml`:

```toml
[[subcase]]
id = "A27.90"
kind = "subcase"
parent = "A27"
conditional_on = "device-flow"
table_text = "Conditional sub-ID A27.90 (device flow, T40.6): user-code approval, expiry/polling abuse, no interaction bypass"
layers = ["security"]
envs = ["browser", "native-3os"]
harness = ["BR", "OIDC with live SSO", "RN", "attacker loopback process"]
owners = ["T40.6"]
positive = "user-code approval"
negative = "expiry/polling abuse, no interaction bypass"
matrix_sha256 = "02c64cdac8a18ddfb48397e703e048a59f5ea84e7867ab5c31998ee9df5a5fc9"

[[subcase.stage]]
milestone = "M4"
scope = "full row"
legs = [
  "typescript-browser/chromium",
  "typescript-browser/firefox",
  "typescript-browser/webkit",
  "clients-rust-native/ubuntu",
  "clients-rust-native/macos",
  "clients-rust-native/windows",
]
status = "planned"
tests = []
```

`matrix_sha256` is the SHA-256 of the UTF-8 bytes of the entry's whole table line, from the leading `|` to the trailing `|`, with no trailing newline: the `| A24 | … |` line in tasks §8 for a scenario, the `| C07 | … |` line in design §2 for a contract. The values above are examples from when this section was written; `scenarios.toml` and `subcases.toml` hold the current ones. A sub-ID entry instead hashes the task text it was drafted from, by the same rule: the whole tasks.md line `- [ ] **Txx.y** …` of its first owner. A conditional sub-ID adds `conditional_on = "device-flow"` (or `"back-channel-logout"`, `"forwardauth"`) and `table_text`, the exact sentence that its parent's section 2 row shows for it. Every conditional sub-ID that section 2 names must have exactly one entry with that parent, feature and first owner, and the annex holds no conditional sub-ID that section 2 does not name. Conditional sub-IDs are numbered .90–.99. A required (non-conditional) sub-ID has neither `conditional_on` nor `table_text`, need not be named in section 2, and is allowed only under a parent whose section 2 note declares an annex range that contains it, such as A58's `A58.01–A58.89`.

An `implemented` stage lists at least one test and carries `implemented_sha256`: the SHA-256 of the UTF-8 bytes of the entry's `id`, the stage's `milestone`, the stage's `scope` and the entry's `matrix_sha256`, joined by `\n`. The stamp ties the status to what was implemented. A changed scope, a moved milestone or an edited spec row no longer matches it, and both the generator and the check fail until a reviewer sets the stage back to `planned` (removing the stamp) or re-stamps it. A `planned` stage carries no stamp.

**Which job produces a test.** A registered test ID names its package and target. The package and target fix the job, and the job fixes the env:

| Test source | Job (legs) | Env |
| --- | --- | --- |
| `skyoauth-scenarios`, targets `hermetic` / `pg` / `envoy_k3s` / `live` | `scenarios-hermetic` / `scenarios-pg` / `scenarios-envoy-k3s`, `scenarios-envoy-k3s-nightly`, `migration-rehearsal` or `deployed-topology-audit` / `live-wif-push` or `live-wif-negative` | hermetic / pg / envoy-k3s / live |
| `clients/rust/tests` | `clients-rust` (Linux x86_64) or `clients-rust-native` (ubuntu, macos, windows) | hermetic or native-3os |
| `skyoauth-operator` (`operator/tests`), targets `operator` / `recovery_offline` | `operator` (ubuntu, macos, windows) / `recovery-offline` chain | native-3os |
| `clients/typescript/test/*.test.ts` | `typescript` (Node 22, 24) | hermetic |
| `clients/typescript/test/browser/` | `typescript-browser` (Chromium, Firefox, WebKit) | browser |
| `service/tests`, `service/src` | `rust` runs plain `cargo test`, which emits no JUnit. `service-nextest` runs them under cargo-nextest with a JUnit report, but it is a unit-and-DB job with no leg string in section 1.1 (section 6 "Still open", item 3), so it produces no scenario result. `scenarios-pg` runs only `-p skyoauth-scenarios --test pg` (section 1.2), so no `service/` test appears in the report of leg `scenarios-pg/x86_64` either | none: not registrable |

Service-consumer fixtures are therefore replayed from `skyoauth-scenarios`, which depends on `skyoauth-service`. A `service/` test could be registered only once section 1.1 gave a job that runs it under nextest a leg string, which section 6 "Still open", item 3 provisionally rules out; the same rule would then apply to it. Every job above that produces registered tests runs cargo-nextest, vitest or Playwright with a JUnit reporter. DB-backed `service/` tests run in `service-nextest`, which reaches the same pinned PostgreSQL service container as `scenarios-pg` through `SKYOAUTH_IT_DATABASE_URL`; scenario tests run in `scenarios-pg`.

**Check: `check-conformance-registry`** (`scripts/ci/check-conformance-registry.mjs`; its static part runs in the `conformance-registry` CI job, its resolution part in `scenarios-pg`).

- *Static part.* Runs on **every** event, including docs-only changes, because the matrix itself lives in Markdown. It needs no build.
  - The `| Axx |` rows of tasks §8 equal the registry scenario IDs exactly: A01–A64, no gaps, duplicates or extras. The C rows of design §2 equal the contract IDs C01–C10.
  - Every `matrix_sha256` still matches, so an edited matrix row fails until the registry entry is reviewed.
  - IDs are monotonic, and owners exist as task IDs in the tasks doc.
  - Every stage milestone is a known milestone and milestones increase, so the last stage of each scenario is its full milestone; `full row` is the scope of a single-stage entry only.
  - Every `implemented` stage lists at least one test and carries a matching `implemented_sha256` (above). No stage lists a test twice, and no test ID holds a control character, a line break or whitespace other than single spaces inside it; a nextest ID holds no space at all. The check quotes the test IDs and list names it prints as JSON strings and prints every error on one line, with control characters and line separators escaped, so a name cannot inject a workflow command into the CI log.
  - Every stage `legs` entry is a leg string from the section 1.1 **Leg strings** column, every env in `envs` has at least one leg in some stage, and every leg's job belongs to one of the scenario's `envs`.
  - Every fixture directory not starting with `_` names a registered scenario, and every fixture has the section 1.3 envelope. Validation against the JSON Schemas in `tests/conformance/schema/` lands with the first schema; until then the check fails if that directory holds any file, so a schema cannot be added without its check.
  - The scenario table in this document equals the table rendered from the registry (`id`, `layers`, `envs`, `harness`, stages, `owners`, `note`, `positive`, `negative`, and the `table_text` of each conditional sub-ID of the row), and so do the counts sentences after it.
  - Every waiver entry (see **Waivers** below) has all required fields, names a full 40-hex commit SHA that is an ancestor of `origin/main`, a registered test and one of that test's stage legs, and its `expires` is a TOML date. The commit check needs the full history; CI checks out with it, and a local run without it skips that one check with a note.
  - Every registry file parses identically with a full TOML parser and with the generator's TOML subset reader.
- *Resolution part.* Runs in the code jobs, since it needs a built test list. Built for nextest: `check-conformance-registry.mjs --nextest-list FILE` takes the JSON of `cargo nextest list --message-format json`, and the `scenarios-pg` job runs it on the list of `skyoauth-scenarios` (`tests/conformance/README.md`, "The resolution part"). Listing needs the build but no database. The vitest and Playwright ID forms are provisional (section 6 "Still open", item 5), so they are not resolved yet: an implemented stage with such a test, or with a leg of a job that reports with vitest or Playwright or has no decided runner, fails the check. The run in `scenarios-pg` runs the static part too, so a static failure also turns `scenarios-pg` red, besides `conformance-registry`; its steps come after the leg artifact upload, which runs `if: always()`, so the leg artifact is still uploaded. A test of a package the list does not cover fails the check, never passes unchecked, so the step lists every package that `TEST_JOBS` names from the PR that adds that package to the workspace, and one list must cover them all until a per-job mode exists (section 6 "Still open", item 8).
  - Every `implemented` stage lists, **for each job among its legs**, at least one `pos` and one `neg` test produced by that job. A declared leg whose job contributes no test fails the check, so a leg such as `recovery-offline/windows` cannot be satisfied by tests from other jobs.
  - Each listed test resolves against `cargo nextest list`, `vitest list --json` or `playwright test --list --reporter=json`, and none is `#[ignore]`d, `.skip`ped or `.fixme`d.
  - **Same job.** Each listed test, from any package (`skyoauth-scenarios`, `clients/rust`, `operator/`, the TypeScript package, or `service/` once a job that runs it has a leg string), is produced by the job of one of its stage's legs, per the table above.
  - **No orphans.** Every listed test whose name matches a scenario pattern is registered in some stage's `tests`. This includes every generated fixture case: each case name (`a61_neg_query_reordered_mismatch`, `A61 neg: query_reordered_mismatch`) is listed explicitly, so adding a fixture fails the check until a stage claims it. Rust names are module-qualified, so the check matches the last path segment: `(^|::)a\d\d_`. vitest joins describe titles with ` > `, so it matches `(^|> )A\d\d[ .]`; for Playwright it matches the test's own title with `^A\d\d[ .]`.
  - **Gates.** For every milestone in `gates_passed`, every stage with that milestone is `implemented`, except stages of conditional sub-IDs whose feature the release manifest does not list as shipped (see **Release** below); the static part checks this on every change. A PR cannot show live or post-merge stages passed, because the live WIF jobs and slow jobs never run on PRs, so a gate certifies a commit that is already on `main`. The lead decided the rule on 2026-11-20 (section 6 "Still open", item 7):
    - **The judged commit is the merge-base** of the gate PR's head with `main`, `git merge-base origin/main <PR head>`, not the tip the PR merges into. The gate PR is a single commit whose only parent is that merge-base, and its diff changes only the `gates_passed` line of `tests/conformance/scenarios.toml`: it adds milestones and nothing else, so `gates_passed` stays a plain list of milestones and no commit SHA is recorded in the registry. A PR that only removes milestones from `gates_passed` (a revocation) is an ordinary reviewed PR, not a gate PR, and `--gate-pr` does not check it; a gate PR that adds one milestone and removes another fails. `check-conformance-registry.mjs --gate-pr`, run on a full checkout of the PR head, checks both rules whenever `gates_passed` grows, and runs the static part on the specs and `tests/conformance` **as of the merge-base**, with the PR's `gates_passed`. Every stage of each new milestone must therefore be `implemented`, with a valid stamp, at the merge-base; a PR that implements a stage and gates it at once fails.
    - **The reporter must show the gate passed on that commit:** `report-conformance.mjs --commit <merge-base> --require-milestone M` for each new milestone, with `--root` a checkout of the merge-base. Every stage of M must be **passed** there, live and post-merge legs included.
    - **A later tip is not certified.** Results of commits after the merge-base never count for the gate, not even those of the tip the PR merges into. To have a later commit judged, the PR is rebased onto it, which makes it the merge-base, and both checks run again.
    - **Unfinished legs block the merge.** A leg of the merge-base that has no result yet, such as a post-merge job or a live run still to come, is **not run**, so the reporter exits 1 and the gate PR may not merge until every such run on that commit has completed and passed. `live-wif-push` runs only in the push-to-`main` run of the commit it judges, and `live-wif-negative` only in schedule and dispatch runs (section 4), so a merge-base that never got one of them cannot pass; the PR is rebased onto a commit that did.
    - Gates are per milestone: a milestone's gate covers its own stages, not those of earlier milestones. M1b and M2 can pass in either order. M0 has no stages, so the reporter never reports its gate passed; M0 is gated by ADR ratification and the doc checks instead, and `--gate-pr` names no reporter run for it. The gate is mechanical only for the scenario stages; the other gate conditions in tasks §3–§7 still need review.
- *Result join (reporter).* `scripts/ci/report-conformance.mjs` implements this join for one commit from downloaded artifacts; `tests/conformance/README.md` documents its input, output and exit status. The informational `conformance-report` job in `ci.yml` runs it on the leg artifacts of its own run only (**Leg artifacts** below); no job yet collects every run for a commit as this item describes. A reporter error (exit 2) fails that job and so the workflow run, which on `main` turns the README's CI badge red, while `CI passed` stays green because it does not need the job. **Trusted runs only:** the join for a gate or a release, and the gate itself, accept only runs of trusted events, that is `push`, `schedule` and `workflow_dispatch` runs on `refs/heads/main` (`event` and `headBranch` in `run.json`), never `pull_request` runs: a pull request run executes the workflow files of the PR, which the PR controls, so it can upload any artifact under any leg. The reporter does not enforce this yet. It checks only that `headSha` is `--commit`, that `databaseId` is the run directory's name, that `attempt` is a positive integer no artifact exceeds, and that `workflowName` is a non-empty string; it ignores every other field, `event` and `headBranch` included (section 6 "Still open", item 6). After the test jobs run, the reporter collects JUnit from every workflow run for the **same commit SHA** (CI, `live-wif-push`, `live-wif-negative`, nightly, release). cargo-nextest (pinned) emits JUnit; plain `cargo test` cannot on stable. vitest and Playwright use their junit reporters. All retries are 0, and a test that passes only on retry counts as **failed**.
  - **Re-runs never hide a failure.** The reporter reads every attempt of every run for the commit (JUnit artifacts are named with `github.run_attempt`). A failed result for a (test, leg) on a commit is permanent: a later attempt cannot overwrite it. A new commit starts with no results. On the same commit, a failed attempt can be discarded only by a waiver (see **Waivers** below). A leg that produced no result (for example, a cancelled job) is not run, and a later attempt may fill it.
  - For each stage, the reporter checks every pair (test, required leg) where the test belongs to that leg's job. A fixture-driven test is one test per fixture case, so cases are keyed the same way. A pair is **passed** only with a passing JUnit case from that leg. A missing case, skipped or filtered test, skipped job or absent environment makes the pair **not run**. A required leg that never ran is therefore **not run** even if every other leg passed: A64 passing on ubuntu and macos with no windows result is not run, and so is A41 without one of its three OS legs. Where the table above gives one source several jobs (`skyoauth-scenarios` target `envoy_k3s`: four jobs; target `live`: two jobs), the test belongs to every one of those jobs that its stage lists and must pass in each of them, until a per-target job mapping is defined (section 6 "Still open", item 4).
  - A stage takes the worst status of its pairs, with precedence **failed > not run > passed**. A scenario takes the worst status of its stages up to the milestone being judged. A parent takes the worst of its required sub-IDs. A contract (`kind = "contract"`) is passed only when every scenario in `covered_by` is passed. Where an aggregate (a scenario up to a milestone, a parent, a milestone gate or a contract) includes planned stages, the reporter ranks **failed > planned > not run > passed**: a planned stage never counts as passed, and it outranks not run because no evidence for it can exist yet. A milestone gate covers the stages that the **Gates** rule covers, so stages of conditional sub-IDs are reported but gate nothing while no release manifest exists: their failures stay in the report but do not fail any milestone's gate. The reporter's exit status, with and without a required milestone, is defined in `tests/conformance/README.md` ("Output and exit status").
  - `planned` stages are reported as planned and never count as passed.
- **Leg artifacts (naming contract).** A leg's results reach the reporter only as a leg artifact of the workflow run that produced them. `tests/conformance/README.md` ("Input") gives the full directory layout the reporter reads; this is the contract every job that runs a conformance leg follows:
  - **Leg id.** The leg string from the section 1.1 **Leg strings** column with `/` replaced by `-`, since an artifact name cannot hold `/`: `scenarios-pg/x86_64` gives `scenarios-pg-x86_64`, and a bare job name such as `bundle-check` stays as it is. Leg ids must stay distinct across the column; a new leg string whose leg id equals another's (`scenarios-envoy-k3s/nightly` would collide with `scenarios-envoy-k3s-nightly`) needs another name.
  - **Name.** `junit-<leg id>-attempt-<N>`, written in the upload step as `junit-<leg id>-attempt-${{ github.run_attempt }}`. Each attempt of a run therefore uploads its own artifact instead of replacing an earlier attempt's or failing on a name that is already taken, so a failed attempt stays readable (**Re-runs never hide a failure**, above). A matrix job uploads one artifact per leg.
  - **Contents.** Exactly two files at the top of the artifact: `leg`, one line holding the leg string, and `junit.xml`, the runner's JUnit report, which is absent when the job stopped before its tests (that leg then has no result for that attempt). The upload step runs with `if: always()`, so a job whose tests fail still uploads them; a job that never reaches the step (a lost runner) uploads nothing, and its leg has no result for that attempt.
  - **What the reporter derives, and from where.** The **leg** comes from the `leg` file, never from the name: the leg id in the name is for people, and the reporter does not parse it (the `conformance-report` job only checks that it matches the `leg` file, and that the leg's job is the job that named the artifact). The **run attempt** is the `N` of the name's `attempt-N` suffix, and may not exceed `attempt` in the run's `run.json`. The **run ID** is the name of the directory the run's artifacts are downloaded into, `<artifacts>/<run_id>/<artifact name>/`, and must equal `databaseId` in that run's `run.json`, whose `headSha` must be the commit given as `--commit`. The leg's job then decides which tests it produces (`TEST_JOBS` in `scripts/ci/report-conformance.mjs`, the "Which job produces a test" table above) and how its JUnit names map to test IDs (`JOB_RUNNER`, section 6 "Still open", item 5).
  - **Not leg artifacts.** An artifact without a `leg` file is an input error unless it is a known artifact of a job that is not a conformance leg (`NOT_CONFORMANCE` in the reporter); the reporter self-test fails when a workflow uploads an artifact that is neither.
  - **Download by the name the leg job gives.** A leg job in `ci.yml` also names what it uploaded in a job output, `junit-artifact`: the artifact name from the attempt it ran in, or empty when its upload produced no artifact (no `artifact-id`). The `conformance-report` job downloads each leg's artifact by exactly that name, never by a pattern (`actions/download-artifact` extracts a single matching artifact flat into the target directory and several into one directory each, as run 44833181735 showed) and never by a name it builds itself from `github.run_attempt` (a re-run of that job alone would label an attempt-1 artifact attempt 2). A download by name puts the artifact's files directly into a directory of their own; `scripts/ci/report-conformance-ci.sh` accepts it only when it holds exactly the regular file `leg` and, when the tests ran, the regular file `junit.xml` (no directory, symbolic link, `run.json` or other entry), checks the name against `junit-[a-z0-9_-]+-attempt-N`, the `leg` file against the leg id in it and the leg's job (the leg string up to its `/`) against the job of its `DOWNLOADS` line, moves both files to `<artifacts>/<run_id>/<name>/` and only then writes `run.json`; anything else fails the job (exit 2). A leg job with an empty output gets a warning, and its legs are not run in that report. The job therefore reads one attempt per leg job, the latest that job ran in; earlier attempts of a re-run leg are left to the join of every run (**Result join**, above). A matrix leg job needs one output per leg, which no job has yet.
  - **Legs that upload today.** Only `scenarios-pg/x86_64`, as `junit-scenarios-pg-x86_64-attempt-N` from the `scenarios-pg` job. No other job in section 1.1 exists yet, so every other leg has no artifact, and its pairs are not run.
  - **Adding a leg.** The PR that adds a leg's job adds its upload step with this name and these two files and adds the leg to **Legs that upload today**; the reporter self-test checks both in every workflow file. A leg job in `ci.yml` also gets its `junit-artifact` output and is added to the `needs` of the `conformance-report` job there, with a download step for that output and a line in the report step's `DOWNLOADS` (**Download by the name the leg job gives**, above); the self-test checks those too. A leg of another workflow (the schedule-only `live-wif-negative` and nightly legs) runs in another workflow run, which that job cannot need or download; its results reach only the join of every run for a commit (**Result join**, above), which is not built. Its job must have a decided runner in `JOB_RUNNER`: `bundle-check` and `migration-rehearsal` have none, so their artifacts are input errors until section 6 "Still open", item 5 is decided.
- **Waivers.** `tests/conformance/waivers.toml` holds audited exceptions for single failed attempts. The reporter reads it from the tip of `main` at judging time, because the waived commit's own tree cannot contain its waiver.
  - Each waiver is bound to one failed attempt: commit SHA, test, leg, `run_id` and `run_attempt`. It also states a reason and an expiry date.
  - A waiver only discards that one failed attempt. The (test, leg) pair **still needs a passing result** from another attempt on the same commit. A waiver never turns a failure into a pass.
  - A waiver never applies to **not run** or **planned**. A waiver that matches no failed attempt, or whose expiry has passed at judging time, is not applied, and the failure counts again.
  - The reporter lists every waiver it applied in its output, next to the result it affected.

  ```toml
  [[waiver]]
  commit = "0123456789abcdef0123456789abcdef01234567"
  test = "nextest:skyoauth-scenarios/pg/security::a24::a24_neg_concurrent_single_use"
  leg = "scenarios-pg/x86_64"
  run_id = 12345678901
  run_attempt = 1
  reason = "PostgreSQL service container lost mid-test; runner fault, not product behaviour"
  expires = 2026-12-31
  ```

- **Who approves.** No script can verify that the lead approved a PR. The plan is a `.github/CODEOWNERS` file (none exists yet) that names the lead as owner of `tests/conformance/waivers.toml`, `tests/conformance/scenarios.toml`, `tests/conformance/subcases.toml` and the release manifest, combined with "Require review from Code Owners" in branch protection for `main`. That branch-protection setting is a maintainers' decision (section 6). The registry check only validates the file contents.
- Only **passed** counts. When the docs-only classifier skips the build jobs, a reporter run for that commit passes `--docs-only`, and its summary reads "runtime conformance: not run (docs-only change)". The informational `conformance-report` job is skipped with the build jobs, so a docs-only CI run has no conformance summary at all. The `ci-passed` aggregator's `success | skipped` rule satisfies branch protection, but **it is not a conformance signal**. Release gating must read the reporter output, never `ci-passed`.
- **Release.** The release check requires every non-conditional scenario stage, every required sub-ID, C01–C10 and both libraries to be passed on the release commit, which must be reachable from `main`. It names that one commit, as a gate names its merge-base: results of any other commit never count, and the release waits until the release commit's live runs (`live-wif-push` from its push to `main`, `live-wif-negative` from a schedule or dispatch run, section 4) and post-merge runs have completed, since a leg without a result is not run. Conditional sub-IDs are required only when the release manifest lists their feature as shipped. The manifest is a committed file owned by the T50/release owner; a change to it needs a PR the lead approved, enforced through code-owner review (see **Who approves**). A release-manifest PR is a PR that adds a shipped feature to the manifest, which makes that feature's conditional sub-IDs count. It follows the gate PR rule: it is one commit on its merge-base with `main`, and every stage of those sub-IDs is implemented and passed at that merge-base. Its allowed diff (only the manifest entry, as a gate PR changes only `gates_passed`, or more) is undecided until the release job exists (section 6 "Still open", item 7).

## 4. CI integration per milestone

**Determinism rules for all layers:**

- Proposal: auth code reads time only through an injected `Clock`. A `clippy.toml` (none exists yet) would enforce this with `disallowed-methods` on `SystemTime::now`/`Instant::now` outside the clock module. Async timers use `tokio::time::pause`.
- Concurrency tests synchronize on barriers or channels. They never sleep (A24, A34, A56, A60).
- proptest/fuzz use fixed seeds with committed regressions. Jitter and backoff take an injected RNG (A12, A56).
- Servers bind port 0 on loopback. Hermetic jobs need no egress, and every mock issuer is in-process. Cluster/Envoy jobs wait on observed conditions with deadlines, not fixed sleeps.
- Only the `live-wif-push` and `live-wif-negative` jobs touch the internet for conformance. The nightly real-Zitadel compatibility job also does, but it is not conformance evidence.
- Scenario tests never assert audit hash values. They assert chain linkage (each event's `sequence` and `prev_hash` continue the chain) and verification outcomes. The hash definition (identity-registry IR-056) is provisional until the audit writer ships.

**Live WIF (A01, A02, A36).** Production bindings permit `push` only (T22.4), so one run cannot show both a live allow and a live deny of the production binding. The live evidence is therefore split into two jobs, and each has a `pos` and a `neg` test, as every leg of an implemented stage must (section 3):

- `live-wif-push` runs only in the `push` to `main` run of the commit being judged. It supplies the live **positive** (A01, A36) and, from the same run, a **negative**: the same real token presented for a wrong audience is denied.
- `live-wif-negative` runs in `schedule` and `workflow_dispatch` runs. These have a different `event_name`, and the push-only binding must deny their token (A02, T22.5). As a **positive control**, the same token is exchanged against a test-only binding that permits that event, which shows that the denial comes from the event predicate and not from a broken exchange. That binding exists only in the test tenant, never in production configuration.

A tag push does carry `event_name: push`, but its `ref` is `refs/tags/…`; the production binding's ref predicate (`refs/heads/main`) must deny it. The reporter joins both jobs' runs by commit SHA. Releases are therefore cut only from commits on `main` that had a passing `live-wif-push` run, and A02's live stage also needs a passing `live-wif-negative` run on the same commit: a release commit that no scheduled run covered gets a `workflow_dispatch` run. The release workflow checks that the release commit is reachable from `main`, and a hotfix lands on `main` first.

**Slow jobs and merge queue.** Slow Envoy/k3s jobs are required on PRs if they take about 15 minutes or less. Otherwise they run post-merge on the push to `main`, where the reporter result for that commit gates milestones and release. `ci.yml` has no `merge_group` trigger today. A merge queue needs both the repository setting and a `merge_group:` trigger. Whether to enable one before M3 is a maintainers' repository-setting decision (section 6).

| Milestone | New jobs (Rust jobs keep the x86_64/aarch64 matrix where the bootstrap has it) | Required on PR | Post-merge / nightly / release |
| --- | --- | --- | --- |
| M0 | `conformance-registry` (static check, runs even for docs-only changes); fixture schema validation once M0 wire examples land as fixtures. **This is the only conformance-harness deliverable that M0 requires: 64 planned scenarios and 10 planned contracts, 0 implemented.** It is in place; `scenarios-pg` (M1a) also runs, on the `pg` target that the first M1a scenario PR (A29) added. The M0 milestone itself is T00's reviewed contracts and threat model (tasks §9). | yes, via `ci-passed` | — |
| M1a | `skyoauth-scenarios` member with `scenarios-hermetic` and `scenarios-pg`, plus the `rust` and coverage-alias changes from section 1.2; in-process mock discovery/JWKS server with per-source fetch counts in `scenarios-hermetic`/`scenarios-pg` (A03, A05; mock GitHub token issuance and TRm stay M2); `operator` matrix ubuntu/macos/windows; `recovery-offline` three-job chain (Q6); registry resolution and reporter | yes | — |
| M1b | Same jobs extended with the human chain, T13.9 transitions, A29 human registry references, A46 origin resolution and A58 persistence sub-IDs | yes | — |
| M2 | Mock GH/TRm in `scenarios-hermetic`/`scenarios-pg`; `clients-rust` (Linux WIF, minimal/default/all features, `cargo package` and consumer); `scenarios-envoy-k3s` (pinned k3s, Envoy Gateway/egctl/Envoy, RB; A36 negatives); `live-wif-push` (positive and wrong-audience negative from the push to `main` run only) and `live-wif-negative` (denials and the test-only positive control from schedule/dispatch runs); neither runs on PRs | hermetic and PG yes; `scenarios-envoy-k3s` yes if runtime ≤ ~15 min, else post-merge | `live-wif-push` on push to `main`; `live-wif-negative` nightly and on dispatch; `scenarios-envoy-k3s-nightly` (A54 kubelet rotation) |
| M3 | `typescript-browser` (packed tarball → `examples/spa`, Playwright Chromium/Firefox/WebKit, pinned browsers); `bundle-check` (browser-platform bundle with Node built-ins forbidden, A39); Envoy job adds raw-capture cookie tests, mock OIDC×2, ≥2 controllers, cert-manager, VAP (A58 sub-IDs) | browser and bundle yes; A58 cluster sub-IDs post-merge if too slow | Nightly real-Zitadel compatibility (not conformance); nightly run of deadline cases at production defaults (Q8) |
| M4 | `clients-rust-native` matrix on 3 OSes (loopback, injected browser launcher driving Playwright for confirm, OS keychain: macOS Keychain, Windows Credential Manager, Linux secret-service under dbus); `examples/rust-cli` packaged consumer | yes | — |
| M5 | `migration-rehearsal` (artifacts built once and carried by hash into switch/rollback, OIDC×2, K3×2); `fuzz` (T52.7, time-boxed; PRs replay seed corpora only); load tests; `deployed-topology-audit` (the M5 deployed-topology audit stages of A18, A58 and A62, T50.3, T50.4, T52.4, T52.5) | seed replay yes | fuzz/load nightly; **release workflow** requires the reporter to show all 64 scenarios **passed** on the release commit, live jobs included, plus C01–C10 and both libraries |

Coverage: the existing gates (Rust 85 % lines; TypeScript 85 % lines/functions/branches/statements) stay on the packages' own tests; for Rust that includes the `#[ignore]`d PostgreSQL tests in `service/tests/`, which `rust-coverage` runs against the pinned PostgreSQL service. Scenario and integration coverage is uploaded and reported but not gated (Q9).

**PostgreSQL image pin.** The `scenarios-pg`, `service-nextest` and `rust-coverage` service containers are pinned as `postgres:<17.x tag>@sha256:<digest>` in `ci.yml`, with the same pin in all three jobs. Dependabot is not configured to update this pin (`.github/dependabot.yml` covers GitHub Actions, Cargo and npm; its `docker` ecosystem is not documented here as reading workflow `services:` images), so it is bumped by hand: a maintainer opens a PR with each PostgreSQL 17 minor release (and at least quarterly), taking the multi-arch index digest of the new tag from Docker Hub and changing tag and digest together in all three jobs. Each job's check step verifies this: every `postgres` service pin in `ci.yml` must be the same `postgres:<tag>@sha256:<digest>` string, the server must report major version 17, its `server_version` must equal the image tag, and the role must be able to create and drop a database. Moving to a new major version is a design decision, not a bump.

## 5. Decisions

The lead decided these on review. They replace the former open questions Q1–Q11.

1. **Q1 Oversized rows: sub-IDs in an annex.** Scheme `A58.07` in the registry and titles, `a58_07_…` in Rust names. A parent passes only if all its required sub-IDs pass. The scenario count stays 64. The T32.3 owner drafts the A58 sub-IDs before M1b. Required sub-IDs are numbered .01–.89 and live in an annex range that the parent's section 2 note declares (A58: A58.01–A58.89); conditional sub-IDs are numbered .90–.99, so the two never collide. A56, A18, A12 and A57 are split only if a row has more than about six independent assertions.
2. **Q2 "Backend denies" (A01, A08, A13, A43): yes.** Evidence is the backend-verifier fixture vectors plus a clearly test-only reference ConnectRPC backend (RB) reached through Envoy. v0.1 ships no verifier library.
3. **Q3 A33.** The required part is T10.10, T31.2 and T31.6: idle, absolute and origin expiry; local and upstream logout by indexed sid; switch invalidation; other sessions untouched. Back-channel-driven sid targeting is conditional sub-ID A33.90 and blocks release only if T30.6 ships.
4. **Q4 A53** is the disabled-record lifecycle of design §5.6, in two stages. The M1a stage, "disabled-record lifecycle": export/import round-trip; reject an enabled or approved create/import; reject an enabling PATCH; unchanged across restart; reject startup/import with an active unsupported record (seeded through a restore fixture) without rewriting it. The M1b stage, "forward migration": the record is unchanged across a forward migration, and its negative is the restore-fixture startup/import case run after the forward migration: startup or import with an active unsupported record seeded through the restore fixture is rejected without rewriting it. No feature flag is involved. Preservation across a provider switch is A16's M5 stage; C06 maps both A16 and A53.
5. **Q5 A62** covers the internal signer groups only. Public signer rotation and overlap are A19 and C01.
6. **Q6 A64: option (a).**
   - Offline recovery runs as three jobs: Linux emits the challenge as an artifact, macOS/Windows (and Linux) sign it with the workstation operator, Linux verifies and applies it.
   - The M0 contracts set a production default and maximum for the recovery challenge TTL. The chain does not depend on runner latency: service and operator clocks are injected and start from the challenge's `issued_at`, and that clock state is carried between jobs with the artifacts. A hermetic test covers expiry at the TTL boundary, and one same-job Linux run uses real time.
   - Remote writes run a full positive against the Linux service, plus per-OS transport and keystore tests.
   - SoftHSM2/PKCS#11 is automated. Real hardware drills are manual evidence and are never counted as passed.
   - No self-hosted runners or tunnels.
7. **Q7 Live dependencies: confirmed,** with the push-to-main rule in section 4. PRs use mocks and a token-file swap. `live-wif-push`, `live-wif-negative` and real kubelet rotation (A54) run post-merge and nightly and gate release.
8. **Q8 Test-profile timings are acceptable** if they use the same code path, stay within spec ceilings, never shorten a spec minimum, and are recorded as JUnit properties. A nightly job also runs those cases at production defaults.
9. **Q9 Coverage.** The Rust gate (85 % lines) counts the tests of the `service` crate that need PostgreSQL: the `rust-coverage` job sets `SKYOAUTH_IT_DATABASE_URL` to the pinned PostgreSQL service container and runs `cargo coverage` with `-- --include-ignored`, so persistence code that only the database tests exercise is measured. Scenario tests (the `skyoauth-scenarios` package) stay outside the gate; the alias excludes that package (section 1.2). Their coverage, and integration coverage generally, is informational.
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

1. **`tests/` as its own workspace member: accepted.** The first M1a scenario PR (A29) added it and updated the layout in tasks §1 and design §10.4.
2. **Recovery challenge TTL:** the M0 contracts set a production default and maximum. The test chain is described under Q6 in section 5.
3. **Slow jobs:** required on PRs if about 15 minutes or less, otherwise post-merge on the push to `main` (section 4).
4. **Release commits:** only commits on `main` with a passing `live-wif-push` run; the release workflow checks reachability from `main`; hotfixes land on `main` first (section 4).
5. **Contract mapping:** decided (section 5, Q11).
6. **ForwardAuth (T32.9):** two conditional sub-IDs, A58.90 under A58 (deployment-enforcer equivalence) and A18.90 under A18 (credential containment and trusted forwarded chain). Device flow stays under A27 (A27.90). The release manifest is a committed file owned by the T50/release owner; changes need a PR the lead approved.

Decided by the lead in the M1a stage-scope review (2026-11-20):

1. **Per-target job mapping for `operator/tests`:** the `skyoauth-operator` package has two test targets, one per job. Target `operator` runs in `operator` (ubuntu, macos, windows), and target `recovery_offline` runs in the `recovery-offline` three-job chain (section 3 "Which job produces a test"). A test therefore belongs to one of the two jobs, and a stage that lists both jobs (A64) needs a `pos` and a `neg` test from each target. The reporter implements this mapping (`TEST_JOBS` in `scripts/ci/report-conformance.mjs`); a test of any other target of the package is produced by no job.

Still open:

1. **Merge queue before M3** (maintainers): enabling a merge queue needs a repository setting and a `merge_group:` trigger in `ci.yml`. Until then, slow jobs that miss the PR budget gate only after merge.
2. **Code-owner review** (maintainers): turn on "Require review from Code Owners" for `main` and add `.github/CODEOWNERS` for the waiver file, the registry files and the release manifest (section 3). Without it, "lead approved" is a convention, not a check.
3. **Service-side conformance evidence (provisional decision; the lead confirms it in review):** `service/` tests are not conformance evidence for now. `service-nextest` runs the `service/` tests under cargo-nextest with a JUnit report but stays a unit-and-DB job without a leg string in section 1.1, so `service/` tests cannot be registered (section 3); service-consumer fixtures are replayed from `skyoauth-scenarios`. The `rust` job still runs plain `cargo test`, which emits no JUnit.
4. **Per-target job mapping for `envoy_k3s` and `live`:** section 3 "Which job produces a test" still gives two `skyoauth-scenarios` targets several jobs: target `envoy_k3s` (`scenarios-envoy-k3s`, `scenarios-envoy-k3s-nightly`, `migration-rehearsal`, `deployed-topology-audit`) and target `live` (`live-wif-push`, `live-wif-negative`). `operator/tests` is decided (above). Until a per-target (or per-test) mapping is defined, the reporter reads the table literally: such a test must pass in every one of those jobs that its stage lists. Define the mapping before the first stage that lists an `envoy_k3s` or `live` test is implemented.
5. **Test-ID formats and runners:** section 3 shows only the nextest form `nextest:<package>/<target>/<path>`. Not yet decided: the IDs of vitest and Playwright tests and of nextest lib and bin targets, and which runner the `migration-rehearsal` and `bundle-check` legs report with (`bundle-check` has no test source in the section 3 table). The reporter uses provisional proposals, documented in `tests/conformance/README.md` and not ratified: `vitest:<file>/<full title>`, `playwright:<file>/<title path>`, `nextest:<package>/<path>` for a lib unit test and `nextest:<package>/bin/<name>/<path>` for a bin target. The vitest and Playwright formats stay provisional until those runners report conformance tests. `typescript` is read as vitest, `typescript-browser` as Playwright and the other test jobs as nextest; `bundle-check` and `migration-rehearsal` have no runner, so the reporter treats their artifacts as input errors and a stage with one of their legs cannot pass until this is decided.
6. **Artifact manifest check and trusted runs:** the reporter binds each downloaded run to the commit through its `run.json` (`gh run view --json databaseId,headSha,attempt,workflowName,event,headBranch`; the `conformance-report` job writes the same fields), but it checks only `headSha`, `databaseId`, `attempt` and `workflowName`. Not built yet: the trusted-run rule of section 3 **Result join**. The join of every run for a commit, and a gate or release built on it, must use only `push`, `schedule` and `workflow_dispatch` runs on `refs/heads/main`, never a `pull_request` run, whose workflow files the PR controls; it can read that from `event` and `headBranch`, or ask the Actions API instead of trusting the file. The reporter also cannot tell an artifact that failed to download from one that was never uploaded, nor a run that `gh run list` did not return. Not built yet: list the expected runs and, per run and attempt, the expected artifacts from the Actions API, and make a missing one an input error. Also unverified: whether `gh run download` fetches the artifacts of every attempt of a run or only of the latest one; until that is known, a re-run's earlier attempts may be missing from the download without any error. For the `conformance-report` job, unverified as well: whether a re-run that does not re-run a leg job still gets that job's `junit-artifact` output from the earlier attempt (if not, the leg is not run in that report, with a warning), and whether `actions/download-artifact` finds an artifact of an earlier attempt by name (if not, the download fails and so does the job).

7. **Gate PR mechanics (decided by the lead on 2026-11-20; the wiring is open).** A gate certifies the merge-base of the gate PR with `main`; the PR is one commit that changes only `gates_passed`, and it may merge only after that commit's post-merge and live legs have completed and passed (section 3 **Gates**). The release check names the release commit the same way (section 3 **Release**), and a release-manifest PR, a PR that adds a shipped feature to the release manifest, must, like a gate PR, be one commit on its merge-base with the stages of the conditional sub-IDs it makes count implemented and passed there; its allowed diff is undecided until the release job exists. Built: `check-conformance-registry.mjs --gate-pr` (the commit and diff rules and the registry at the merge-base) and the reporter's `--commit` and `--require-milestone`. Not built: the gate job in `ci.yml`, added once a milestone is near its gate. It runs `--gate-pr`, then for each milestone that names, downloads the artifacts of every run for the merge-base and runs the reporter with `--root` a checkout of the merge-base (`--allow-commit-mismatch` makes the report untrusted, exit 2, so it cannot serve a gate). The lead decides these open questions when the gate job is built, before the first gate attempt:
   - **7a. Checkout.** The job must check out `pull_request.head.sha` with `fetch-depth: 0`: the default `pull_request` checkout is the merge ref, whose commit has two parents, so `--gate-pr` would refuse it, and the merge-base needs the full history and `origin/main`.
   - **7b. Live runs for a commit that is not the tip.** `workflow_dispatch` takes a branch or tag, not a commit SHA, so no mechanism is stated for a `live-wif-negative` run on a merge-base or release commit that is no longer the tip of `main` (section 4 says only that such a release commit "gets a `workflow_dispatch` run"), nor whether its test-only binding accepts the ref that such a run would need.
   - **7c. Pushed tips only.** `live-wif-push` runs only in the push-to-`main` run of the commit it judges, so a commit that was not the tip of a push never gets that leg, and a gate PR must be based on a commit that was a pushed tip of `main`.
   - **7d. Re-triggering.** The job fails while a leg is not run, and nothing re-runs it when the merge-base's post-merge and live runs finish: a manual re-run, a `workflow_run` trigger or a scheduled re-check is undecided, and so is making the job required in branch protection (maintainers).

   **Default until decided:** a gate PR is based on a pushed tip of `main`, and its job runs on `pull_request.head.sha` with `fetch-depth: 0`.

   **Note: repairing an unparsable registry.** `--gate-pr` fails closed when `scenarios.toml` at the merge-base or at `HEAD` is not valid TOML, so a PR that repairs an unparsable `scenarios.toml` on `main` fails `--gate-pr` (its merge-base does not parse) and, once the gate job is required in branch protection (7d), needs an admin override to merge.

8. **Per-job resolution lists.** The resolution part takes one test list, from `scenarios-pg`, and checks every implemented stage against it. That works while every package that `TEST_JOBS` names builds and lists on that one runner. When the `operator` targets, the Rust client's native legs or another target whose job runs elsewhere or on other OSes land (the `operator` and `clients-rust-native` legs on ubuntu, macos and windows, the `recovery-offline` chain), the check must be given those jobs' own lists: a per-job mode, in which each job checks its list against the tests its own legs produce, and lists of the same binary from several OSes are each checked. It must not silently ignore tests of other packages, or of other jobs, that a given list does not cover: such a test stays an error unless another list given in the same mode covers it. Build the mode, and run it in those jobs, in the PR that adds the first such job's tests to an implemented stage.

Risks:

1. **ci.yml coordination.** The `rust` job and the `coverage` alias change in section 1.2 landed with the first M1a scenario PR (A29). A later `ci.yml` change that adds a `cargo test`, `cargo nextest` or `cargo llvm-cov` step over the whole workspace must exclude `skyoauth-scenarios` as well, or that step fails without the scenario environments.
2. **Docs-only blind spot.** Editing the §8 matrix is a docs-only change that today skips all build jobs. The static registry check must run outside the `changes` gate, or matrix drift will merge unnoticed.
