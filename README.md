# skyoauth

[![CI](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml?query=branch%3Amain)

| Path                  | Description                                          |
| --------------------- | ---------------------------------------------------- |
| `service/`            | Rust service (`skyoauth-service`, axum + tokio)      |
| `service/migrations/` | Forward-only PostgreSQL migrations (sqlx, embedded)  |
| `clients/typescript`  | TypeScript client library (`@skyoauth/client`)       |

## Service

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo coverage
cargo run -p skyoauth-service   # listens on $SKYOAUTH_ADDR (default 127.0.0.1:8080)
```

`cargo coverage` is an alias (in `.cargo/config.toml`) for `cargo llvm-cov`
that fails if line coverage is below 85%. It needs `cargo install
cargo-llvm-cov` and `rustup component add llvm-tools-preview`.

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

- The migration role must own the database, or at least have `CREATE` on
  the `public` schema.
- Runners serialize on a session-level advisory lock, so `migrate` needs a
  direct connection, not a transaction-pooling proxy such as PgBouncer in
  transaction mode. Waiting for the lock has no timeout yet (follow-up).
- TLS is strict by default. A URL without `sslmode` gets `verify-full` for a
  remote host and sqlx's `prefer` for `localhost`, a loopback address or a Unix
  socket; the ambient `PGSSLMODE` variable is ignored. An explicit `sslmode`
  in the URL is used as written, and a mode weaker than `verify-full` for a
  remote host logs a WARN. The server certificate is checked against the
  public (webpki) roots, so a private CA needs `sslrootcert=/path/ca.pem` in
  the URL. Other `PG*` variables (`PGHOST`, `PGUSER`, `PGSSLROOTCERT` and so
  on) are still read for settings the URL omits; put what matters in the URL.
- Conventions for writing migrations, and the limits of the append-only
  triggers, are in [`service/migrations/README.md`](service/migrations/README.md).

Tests that need PostgreSQL are `#[ignore]`d. To run them, point
`SKYOAUTH_IT_DATABASE_URL` at a server whose role may create databases (each
test creates and drops its own) and include ignored tests:

```bash
export SKYOAUTH_IT_DATABASE_URL=postgres://skyoauth:skyoauth@localhost:5432/skyoauth
cargo nextest run --workspace --all-features --run-ignored all
# or: cargo test --workspace --all-features -- --include-ignored
```

The replica-role append-only test needs a superuser role.

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
  version declared in `Cargo.toml`.
- Scenarios on PostgreSQL (`scenarios-pg`): cargo-nextest runs the
  conformance scenario tests (Rust names `a<NN>_<pos|neg>_…`, see
  `docs/testing/conformance-layout.md` §3) against a PostgreSQL 17 service
  container, reached through `SKYOAUTH_IT_DATABASE_URL`, and uploads the
  JUnit report for the leg `scenarios-pg/x86_64`. While no scenario test
  exists, the job passes with a warning annotation: no scenario ran, which
  is not a conformance pass.
- Service tests (nextest): `cargo nextest run --workspace --all-features
  --profile ci --run-ignored all` on x86_64 Linux, with the pinned cargo-nextest and the `ci`
  profile in `.config/nextest.toml` (no retries, no fail-fast). Its JUnit
  report (`target/nextest/ci/junit.xml`) is uploaded as a workflow artifact
  even when tests fail. nextest skips doctests; the Rust job runs them.
  DB-backed tests reach a PostgreSQL 17 service container, with the same
  pinned image as `scenarios-pg`, through `SKYOAUTH_IT_DATABASE_URL`. They
  are `#[ignore]`d, so jobs without a database report them as ignored.
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
- Conformance registry also runs on every change, and `CI passed` requires
  it to pass: `node scripts/ci/check-conformance-registry.mjs` checks
  `tests/conformance/` (scenario and contract IDs and hashes against the
  specs, stages, legs, sub-IDs, fixtures and waivers), and confirms that the
  layout §2 scenario table equals the one rendered from
  `tests/conformance/scenarios.toml`, which is its source. The job also runs
  `node scripts/ci/gen-conformance-registry.mjs --check` and both
  self-tests. Its one dependency, `smol-toml`, is pinned in
  `scripts/ci/package.json` and installed with `npm ci --ignore-scripts`.
  See `tests/conformance/README.md`.

Coverage reports are uploaded as workflow artifacts and summarized on the run
page. To protect `main`, require the `CI passed` check: it passes when `Docs
consistency` and `Conformance registry` passed and every other job passed or
was skipped. Dependabot keeps actions, crates and npm
packages up to date.

## License

Copyright Sky Computing LLC. Licensed under the Functional Source License,
Version 1.1, Apache License 2.0 Future License (`FSL-1.1-ALv2`). See `LICENSE`
for the full text.
