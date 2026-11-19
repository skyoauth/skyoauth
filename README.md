# skyoauth

[![CI](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/skyoauth/skyoauth/actions/workflows/ci.yml?query=branch%3Amain)

| Path                 | Description                                     |
| -------------------- | ----------------------------------------------- |
| `service/`           | Rust service (`skyoauth-service`, axum + tokio) |
| `clients/typescript` | TypeScript client library (`@skyoauth/client`)  |

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
- TypeScript: formatting, lint, type check, tests and build on Node 22 and 24;
  and the coverage gate.
- A change that touches only documentation (Markdown files and `LICENSE`, as
  decided by `scripts/ci/docs-only.sh`) skips the build and test jobs.
- Docs consistency runs on every change, docs-only ones included:
  `node scripts/ci/docs-check.mjs` cross-checks fences, task, ADR and
  conformance IDs, Mermaid task DAGs and links in `docs/`, and
  `node --test scripts/ci/docs-check.test.mjs` is its self-test.

Coverage reports are uploaded as workflow artifacts and summarized on the run
page. To protect `main`, require the `CI passed` check: it passes when every
other job passed or was skipped. Dependabot keeps actions, crates and npm
packages up to date.

## License

Copyright Sky Computing LLC. Licensed under the Functional Source License,
Version 1.1, Apache License 2.0 Future License (`FSL-1.1-ALv2`). See `LICENSE`
for the full text.
