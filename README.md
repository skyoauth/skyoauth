# skyoauth

[![CI](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml?query=branch%3Amain)
[![Rust tests](https://github.com/skyoauth/skyoauth/raw/badges/main/rust-tests.svg)](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml?query=branch%3Amain)
[![Rust coverage](https://github.com/skyoauth/skyoauth/raw/badges/main/rust-coverage.svg)](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml?query=branch%3Amain)
[![TypeScript tests](https://github.com/skyoauth/skyoauth/raw/badges/main/typescript-tests.svg)](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml?query=branch%3Amain)
[![TypeScript coverage](https://github.com/skyoauth/skyoauth/raw/badges/main/typescript-coverage.svg)](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml?query=branch%3Amain)

| Path                  | Description                                                        |
| --------------------- | ------------------------------------------------------------------ |
| `service/`            | Rust service (`skyoauth-service`, axum + tokio)                    |
| `service/migrations/` | Versioned PostgreSQL migrations (sqlx, embedded)                   |
| `operator/`           | Workstation operator library and CLI (`skyoauth-operator`)         |
| `clients/typescript`  | TypeScript client library (`@skyoauth/client`)                     |

## Service

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --exclude skyoauth-scenarios --all-features
cargo coverage
cargo run -p skyoauth-service   # listens on $SKYOAUTH_ADDR (default 127.0.0.1:8080)
```

`cargo coverage` is an alias (in `.cargo/config.toml`) for `cargo llvm-cov`
that fails if line coverage is below 85%. It needs `cargo install
cargo-llvm-cov` and `rustup component add llvm-tools-preview`. Plain
`cargo coverage` skips the `#[ignore]`d PostgreSQL tests (see below), so it
reports less than CI, which runs them. To measure what CI measures, point
`SKYOAUTH_IT_DATABASE_URL` at a test server and pass `--include-ignored` to
the test binaries:

```bash
SKYOAUTH_IT_DATABASE_URL=postgres://skyoauth:skyoauth@localhost:5432/skyoauth \
  cargo coverage -- --include-ignored
```

### Database migrations

The server does not need a database yet and never migrates on start.
Migrations are an explicit deploy step:

```bash
SKYOAUTH_DATABASE_URL=postgres://user:password@host:5432/skyoauth \
  cargo run -p skyoauth-service -- migrate
```

| Variable                                 | Meaning                                        |
| ---------------------------------------- | ---------------------------------------------- |
| `SKYOAUTH_DATABASE_URL`                  | `postgres://` or `postgresql://` URL, required |
| `SKYOAUTH_DATABASE_MAX_CONNECTIONS`      | Pool size, 1 to 100, default 10                |
| `SKYOAUTH_DATABASE_ACQUIRE_TIMEOUT_SECS` | Connection wait, 1 to 300 seconds, default 10  |

- The database must use the `UTF8` encoding, and the migration role must own
  it, or at least have `CREATE` on the `public` schema.
- Runners serialize on a session-level advisory lock, so `migrate` needs a
  direct connection, not a transaction-pooling proxy such as PgBouncer in
  transaction mode. Waiting for the lock has no timeout yet (follow-up).
- TLS is strict by default. A URL without `sslmode` gets `verify-full` for a
  remote host and sqlx's `prefer` for `localhost`, a loopback address or a Unix
  socket; the ambient `PGSSLMODE` variable is ignored. An explicit `sslmode`
  in the URL is used as written, and a mode weaker than `verify-full` for a
  remote host logs a WARN. A host is remote by its `hostaddr` when one is set
  (sqlx dials that address), else by its name. sqlx's `sslmode=allow` is
  plaintext only; it never negotiates TLS. The server certificate is checked
  against the public (webpki) roots, so a private CA needs
  `sslrootcert=/path/ca.pem` in the URL. Under `verify-ca` and `verify-full`
  the server needs a leaf certificate issued by a CA: the self-signed
  `CA:TRUE` certificate from a default `openssl req -x509` fails with
  `CaUsedAsEndEntity`. Other `PG*` variables (`PGHOST`, `PGUSER`,
  `PGSSLROOTCERT` and so on) are still read for settings the URL omits; put
  what matters in the URL.
- The URL is checked before sqlx reads it and rejected, with an error that
  repeats none of it, if it has an unencoded `@`, `/`, `?` or `#` in the user
  name or password, an unencoded `@` or `/` in the database name, an unencoded
  `@` or a second `?` in the query, a `#` fragment, a `?` in the user or
  database name, or a query key sqlx does not act on (sqlx would log that key
  with its value). The accepted keys are `sslmode`, `ssl-mode`, `sslrootcert`,
  `ssl-root-cert`, `ssl-ca`, `sslcert`, `ssl-cert`, `sslkey`, `ssl-key`,
  `statement-cache-capacity`, `host`, `hostaddr`, `port`, `dbname`, `user`,
  `password`, `application_name`, `options` and `options[NAME]`, so libpq
  parameters that sqlx ignores (`connect_timeout`, `channel_binding`,
  `target_session_attrs`, `keepalives` and so on) now fail at startup.
  Percent-encode reserved characters in values too: an unencoded `&` in a
  query `password` followed by a supported key (`?password=a&user=b`) cannot
  be detected.
- Database upgrades are supported only between tagged public releases,
  starting with the first tagged release (the first beta); the migration
  mechanism (the runner, its checksum refusal and the tested "Upgrade
  precondition" queries) is provided and tested now. Before that release
  there is no upgrade path: an existing migration may be amended in place,
  and `migrate` refuses a database that applied its earlier text (the
  checksum differs), so recreate that database. The forward-only rule
  applies from the first tagged release.
- Conventions for writing migrations, and the limits of the append-only
  triggers, are in [`service/migrations/README.md`](service/migrations/README.md).

Tests that need PostgreSQL are `#[ignore]`d. To run them, point
`SKYOAUTH_IT_DATABASE_URL` at a server whose role may create databases and
roles (each test creates and drops its own database, always `UTF8`, so the
server's locale must be a UTF-8 one or C/POSIX; the privileges each test needs
are in the table below) and include ignored tests:

```bash
export SKYOAUTH_IT_DATABASE_URL=postgres://skyoauth:skyoauth@localhost:5432/skyoauth
cargo nextest run --workspace --exclude skyoauth-scenarios --all-features --run-ignored all
# or: cargo test --workspace --exclude skyoauth-scenarios --all-features -- --include-ignored
# conformance scenarios of the `pg` environment (never ignored, need the variable):
cargo test -p skyoauth-scenarios --test pg
```

Some tests need more than `CREATEDB`. A superuser has every privilege below,
and CI connects as the service container's superuser; a role that is not one
needs each privilege its tests need (PostgreSQL 15 or later):

| Test role privilege                                         | Needed by                                       |
| ----------------------------------------------------------- | ----------------------------------------------- |
| `CREATEDB`                                                  | every database test                             |
| `CREATEROLE`                                                | the tests that create login roles: in `service/tests`, the search-path tests among them; in the `pg` scenarios, A24 (`a24_neg_store_failure_never_consumes`) and the harness's teardown test |
| `GRANT SET ON PARAMETER session_replication_role TO <role>` | the replica-role tests in `service/tests` (`migrations.rs` and the `schema_*.rs` files), which `SET session_replication_role` and fail with SQLSTATE 42501 without it; the `pg` scenarios do not need it |
| `GRANT pg_signal_backend TO <role>`                         | the `pg` scenarios: each drops its database with `DROP DATABASE … WITH (FORCE)`, which may terminate only backends of roles whose privileges the role has, unless it is in `pg_signal_backend`; a backend of another role still connected (an autovacuum worker, or a session of a test's login role) otherwise makes the drop fail with SQLSTATE 42501, which the harness retries for 5 seconds before it fails the test |

## Operator

`skyoauth-operator` is the workstation library and the command line of the
same name, whose offline commands check a recovery challenge, sign it with
the recovery key of a seed file into a new response file (`--out`), and check
the signed response, without a network or a socket. Run it as the seed
file's owner and never install it setuid or setgid. The commands, the
artifact formats, the seed file's rules (on Windows its protection is not
checked) and the exit codes are in
[the operator CLI proposal](docs/proposals/operator-cli-artifacts.md).
Two online commands, `preview` and `status`, only read: they ask the
service over its deployment-local Unix socket and change nothing (not on
Windows); the commands that write are not in this build. They are in
[the online commands proposal](docs/proposals/operator-cli-online.md).

```bash
cargo test -p skyoauth-operator --all-features
cargo run -p skyoauth-operator -- --help
```

## TypeScript client

Requires Node.js 22.12 or later.

```bash
cd clients/typescript
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test
npm run coverage   # fails if any coverage metric is below 85%
npm run build
```

Linting uses [oxlint](https://oxc.rs) with type-aware rules
(`oxlint-tsgolint`), configured in `clients/typescript/.oxlintrc.json`. It is
used instead of ESLint because `typescript-eslint` does not yet support
TypeScript 7.

## CI

GitHub Actions runs on pushes to `main` and on pull requests:

- Rust: formatting, clippy, tests, doctests and rustdoc on x86_64 and aarch64
  Linux; the coverage gate; and a `cargo check` on the minimum supported Rust
  version declared in `Cargo.toml`. The tests, the doctests and the coverage
  gate exclude the conformance scenario package `skyoauth-scenarios`
  (`tests/`), which only the `scenarios-*` jobs run. The coverage gate
  (`rust-coverage`, x86_64 Linux) runs `cargo coverage` with `-- --include-ignored` against the same
  pinned PostgreSQL 17 service container as `service-nextest`, so the
  PostgreSQL tests count toward it.
- Scenarios on PostgreSQL (`scenarios-pg`): `cargo nextest run -p
  skyoauth-scenarios --test pg --profile ci` runs the conformance scenario
  tests of the `pg` environment (Rust names `a<NN>_<pos|neg>_…`, see
  `docs/testing/conformance-layout.md` §1.2 and §3) against a PostgreSQL 17
  service container, reached through `SKYOAUTH_IT_DATABASE_URL`, and uploads
  the JUnit report for the leg `scenarios-pg/x86_64`. Scenario tests are not
  `#[ignore]`d: without the database they fail. To run them locally, set
  that variable to a role with `CREATEDB` and `CREATEROLE`, and, unless it
  is a superuser, membership in `pg_signal_backend` (the table above), and
  run `cargo test -p skyoauth-scenarios --test pg`.
- Service tests (nextest): `cargo nextest run --workspace --exclude
  skyoauth-scenarios --all-features --profile ci --run-ignored all` on x86_64 Linux, with the pinned cargo-nextest and the `ci`
  profile in `.config/nextest.toml` (no retries, no fail-fast). Its JUnit
  report (`target/nextest/ci/junit.xml`) is uploaded as a workflow artifact
  even when tests fail. nextest skips doctests; the Rust job runs them.
  The job then runs four selections again as root, with a second local
  user in `SKYOAUTH_IT_PEER_USER` (`--profile ci-root`, through
  `scripts/ci/root-transport-run.sh`), also when the first run failed:
  `skyoauth-service`'s `local_transport` integration tests, the operator's
  `local_path` module and its CLI test
  `cli::sign::seed_file_protection_on_unix`, and the scenario harness's
  `socket_path_fixture` module, whose cross-UID and root-only checks only
  print a notice and pass without root and that user. The step fails unless every listed
  test ran and passed, the root-only tests the script names among them
  included, and on a notice that the peer user is missing or that
  root-only cases did not run; the job summary, also in the step log,
  gives the counts, the other notices and whether the runner user (not
  root) may create a user namespace. Its JUnit report
  (`target/nextest/ci-root/junit.xml`) is a separate artifact,
  `service-nextest-root-junit-N`, which exists only when that step got
  far enough to write the JUnit.
  DB-backed tests reach a PostgreSQL 17 service container, with the same
  pinned image as `scenarios-pg` and `rust-coverage`, through
  `SKYOAUTH_IT_DATABASE_URL`. They are `#[ignore]`d, so jobs without a
  database report them as ignored.
- TypeScript: formatting, lint, type check, tests and build on Node 22 and 24;
  and the coverage gate.
- A change that touches only documentation (Markdown files and `LICENSE`, as
  decided by `scripts/ci/docs-only.sh`) skips the build and test jobs.
- Docs consistency runs on every change, docs-only ones included, and
  `CI passed` requires it to pass (a skip does not count):
  `node scripts/ci/docs-check.mjs` cross-checks fences, HTML comments, task,
  ADR and conformance IDs, Mermaid task DAGs and links in `docs/`, and
  `node --test scripts/ci/docs-check.test.mjs` is its self-test. Errors fail
  the job. In CI, errors and warnings are also annotations. ADR numbering
  gaps in the tasks §11 table and ADR files without a table row are
  warning annotations that do not fail the job (locally the latter is an
  info note); ADRs never referenced by ID are one info summary line, listed
  with `--verbose`.
- Conformance registry also runs on every change, and `CI passed` requires it
  to pass: `node scripts/ci/check-conformance-registry.mjs` checks
  `tests/conformance/` (scenario and contract IDs and hashes against the
  specs, stages, legs, sub-IDs, fixtures and waivers), and confirms that the
  layout §2 scenario table equals the one rendered from
  `tests/conformance/scenarios.toml`, which is its source. The job also runs
  `node scripts/ci/gen-conformance-registry.mjs --check`, both
  self-tests, the self-tests of the badge scripts (`node --test
  scripts/ci/publish-badges.test.mjs
  scripts/ci/verify-badges-render.test.mjs`, without network access), the
  self-test of `scripts/ci/root-transport-run.sh` (`node --test
  scripts/ci/root-transport-run.test.mjs`), and the
  self-test of the result reporter
  `scripts/ci/report-conformance.mjs`, which joins the registry with the
  JUnit artifacts of one commit into per-stage and per-milestone passed,
  failed, not run and planned results (no job runs the reporter itself
  yet). Its one dependency, `smol-toml`, is pinned in
  `scripts/ci/package.json` and installed with `npm ci --ignore-scripts`.
  A new artifact in `ci.yml` without a `leg` file needs an entry in the
  reporter's `NOT_CONFORMANCE` list, and a new layout job needs a
  `JOB_RUNNER` decision, or its self-test fails. See
  `tests/conformance/README.md`.
- Demo transcripts also run on every change, and `CI passed` requires them to
  pass: the pure self-tests of `scripts/demo` (the CI wiring included) and
  `node scripts/demo/transcript.mjs check` over the sample and every
  committed transcript under `tests/demo`. The check refuses known shapes and
  known values, also across line breaks and adjacent records: PEM headers,
  JWT-shaped strings, Bearer credentials, hex runs of 96 digits or more,
  base64url runs of 86 characters or more, and the seeds of the committed
  `*.test-key.json` fixtures; and, per line, wall-clock values and control
  characters. It does not find a credential of another shape (a 64-digit
  hex key or seed that is not a fixture's, a short opaque token without the
  Bearer scheme, a password), so golden transcripts still need review. The
  demo videos themselves are rendered by
  a separate workflow, `.github/workflows/demo.yml` (Chromium and ffmpeg),
  and kept only as run artifacts (`demo-videos-N`, and on a failure the raw
  recordings `demo-raw-recordings-N` for 3 days); it is not part of `CI
  passed`, so a demo failure never blocks a merge or a release. See
  `scripts/demo/README.md`.

Coverage reports are uploaded as workflow artifacts and summarized on the run
page. On pushes to `main`, CI generates separate Rust and TypeScript tests and
line-coverage badges as SVG files on the `badges` branch
(`scripts/ci/publish-badges.sh`, rendered by `scripts/ci/badge.sh`), so they
need no external service and render in a private repository too (only
`skyoauth/skyoauth` publishes and checks them; a fork does neither). Rust test
counts come from `service-nextest` (all workspace tests, including PostgreSQL
tests, but not the conformance scenario package) and Rust line coverage comes
from `rust-coverage` (the workspace tests under `cargo llvm-cov`, PostgreSQL tests included); TypeScript test
counts and line coverage come from `typescript-coverage`. When a suite fails
on `main`, CI publishes red failure
badges (`N failed` or `failing`) rather than leaving stale passing figures,
and a coverage badge is red whenever its gate failed, whatever percentage it
shows. Coverage percentages are truncated to one decimal, never rounded up
(84.96 % shows as 84.9 %). The publishing job checks that GitHub serves them
as images from the rendered README (`scripts/ci/verify-badges-render.sh`);
every pull request, and a docs-only push to `main`, which publishes nothing,
run the same check against the badges already published for `main`. On a pull
request, a badge fetch that still fails after curl's retries (a transport
error, 429 or 5xx) and a badge not yet published for `main` (404, as for a
badge the pull request adds or renames) are warnings, not failures.
If the rendered README itself cannot be fetched, the pull request passes with a
warning only when it leaves every README file GitHub could render (`README*` at
the top level, in `.github/` and in `docs/`, none of them a symbolic link) byte
for byte as on the base branch; a pull request that changes one fails, and is
checked in full by re-running the job once the GitHub API recovers. The
`CI passed` check is now required by the ruleset for the protected branches,
`main` included (set up by the user): it passes when
`Docs consistency` and `Conformance registry` passed and every other job
passed or was skipped.
Dependabot keeps actions, crates and npm packages up to date.

## License

Copyright Sky Computing LLC. Licensed under the Functional Source License,
Version 1.1, Apache License 2.0 Future License (`FSL-1.1-ALv2`). See `LICENSE`
for the full text.
