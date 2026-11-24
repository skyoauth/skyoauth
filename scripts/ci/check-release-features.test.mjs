// Self-test for check-release-features.mjs:
//   node --test scripts/ci/check-release-features.test.mjs
//
// Needs cargo on PATH, no network: each case builds a small workspace of
// path packages in a temporary directory (`svc`, a library and binary that
// declares `test-support` and turns it on through a dev-dependency on
// itself, as `skyoauth-service` does; `scen`, a library whose
// dev-dependency turns it on, as `skyoauth-scenarios` does), writes its
// lockfile offline, and runs the guard on it. The clean workspace passes;
// each case that injects the feature into a release resolution, or a
// release command with a forbidden flag, must fail with the expected
// error.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { badReleaseCommands, logicalLines, parseTree, scannedKind } from './check-release-features.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'check-release-features.mjs');
const TOP = mkdtempSync(join(tmpdir(), 'check-release-features-test-'));
after(() => rmSync(TOP, { recursive: true, force: true }));

// The environment of cargo and the guard: nothing a surrounding cargo
// build set (`CARGO_*` but the home and network settings, `RUSTFLAGS`).
const ENV = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !(key.startsWith('CARGO') && !/^CARGO_(HOME|NET_|HTTP_|REGISTR)/.test(key)) && !key.startsWith('RUST')),
);

const SVC = (extra = '') => `[package]
name = "svc"
version = "0.1.0"
edition = "2021"

[features]
test-support = []
${extra}
[dev-dependencies]
svc = { path = ".", features = ["test-support"] }
`;

const SCEN = (dependency = '') => `[package]
name = "scen"
version = "0.1.0"
edition = "2021"

[dependencies]
svc = { path = "../svc"${dependency} }

[dev-dependencies]
svc = { path = "../svc", features = ["test-support"] }
`;

let cases = 0;

// A workspace with the members `svc` and `scen` (manifests `svc`, `scen`),
// any `extra` members (name to manifest; each gets a binary), and the
// files in `files` (path to content). Returns its root.
function workspace({ svc = SVC(), scen = SCEN(), extra = {}, files = {} } = {}) {
  const root = join(TOP, `case-${++cases}`);
  const members = ['svc', 'scen', ...Object.keys(extra)];
  const put = (path, content) => {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  };
  put('Cargo.toml', `[workspace]\nmembers = [${members.map((m) => `"${m}"`).join(', ')}]\nresolver = "2"\n`);
  put('svc/Cargo.toml', svc);
  put('svc/src/lib.rs', '');
  put('svc/src/main.rs', 'fn main() {}\n');
  put('scen/Cargo.toml', scen);
  put('scen/src/lib.rs', '');
  for (const [name, manifest] of Object.entries(extra)) {
    put(`${name}/Cargo.toml`, manifest);
    put(`${name}/src/main.rs`, 'fn main() {}\n');
  }
  for (const [path, content] of Object.entries(files)) put(path, content);
  execFileSync('cargo', ['generate-lockfile', '--offline'], { cwd: root, env: ENV, stdio: 'pipe' });
  return root;
}

function guard(root) {
  const result = spawnSync(process.execPath, [SCRIPT, '--root', root], { env: ENV, encoding: 'utf8' });
  return { status: result.status, out: result.stdout + result.stderr };
}

function assertErrors(result, expected) {
  const errors = result.out.split('\n').filter((line) => line.startsWith('error: '));
  assert.deepEqual(errors, expected, result.out);
  assert.equal(result.status, expected.length ? 1 : 0, result.out);
}

describe('the guard on a workspace', () => {
  test('passes when only dev-dependencies turn the feature on', () => {
    const result = guard(workspace());
    assertErrors(result, []);
    assert.match(result.out, /binary packages: svc; declaring `test-support`: svc/);
  });

  test('fails when the binary package turns it on by default', () => {
    const root = workspace({ svc: SVC('default = ["test-support"]\n') });
    assertErrors(guard(root), [
      'error: resolve: `cargo build --release -p svc` would build svc with `test-support`',
      'error: resolve: `cargo build --release --workspace` would build svc with `test-support`',
    ]);
  });

  test('fails when a library member turns it on through a normal dependency', () => {
    const root = workspace({ scen: SCEN(', features = ["test-support"]') });
    assertErrors(guard(root), ['error: resolve: `cargo build --release --workspace` would build svc with `test-support`']);
  });

  test('fails when another binary package turns it on', () => {
    const app = `[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsvc = { path = "../svc", features = ["test-support"] }\n`;
    assertErrors(guard(workspace({ extra: { app } })), [
      'error: resolve: `cargo build --release -p app` would build svc with `test-support`',
      'error: resolve: `cargo build --release --workspace` would build svc with `test-support`',
    ]);
  });

  test('fails when no package declares the feature', () => {
    const svc = `[package]\nname = "svc"\nversion = "0.1.0"\nedition = "2021"\n`;
    const scen = `[package]\nname = "scen"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nsvc = { path = "../svc" }\n`;
    assertErrors(guard(workspace({ svc, scen })), [
      'error: control: no workspace package declares `test-support`, so the guard checks a feature that no longer exists',
    ]);
  });

  test('fails on a release command with a forbidden flag, wherever it runs', () => {
    const files = {
      '.github/workflows/release.yml':
        'jobs:\n  r:\n    steps:\n      - run: cargo build --locked --release \\\n          --all-features\n      - run: cargo build --release -p svc\n',
      Dockerfile: 'RUN cargo build -r --all-targets\n',
      'scripts/release.sh': '#!/bin/sh\ncargo build --profile release -F svc/test-support\n',
      '.cargo/config.toml': '[alias]\nship = "build --release --all-features"\ncheck-all = "check --all-features --all-targets"\n',
      'docs/notes.md': 'cargo build --release --all-features\n',
    };
    assertErrors(guard(workspace({ files })), [
      'error: .cargo/config.toml:2: command: a release build must not use --all-features, --all-targets or test-support: ship = "build --release --all-features"',
      'error: .github/workflows/release.yml:4: command: a release build must not use --all-features, --all-targets or test-support: - run: cargo build --locked --release --all-features',
      'error: Dockerfile:1: command: a release build must not use --all-features, --all-targets or test-support: RUN cargo build -r --all-targets',
      'error: scripts/release.sh:2: command: a release build must not use --all-features, --all-targets or test-support: cargo build --profile release -F svc/test-support',
    ]);
  });
});

describe('the parts', () => {
  test('parseTree reads names and features, duplicates included', () => {
    const tree = parseTree('svc v0.1.0 (/w/svc) [test-support]\nserde v1.0.0 [default,std]\nserde v1.0.0 [default,std] (*)\n');
    assert.deepEqual([...tree.keys()], ['svc', 'serde']);
    assert.deepEqual([...tree.get('svc')], ['test-support']);
    assert.deepEqual([...tree.get('serde')], ['default', 'std']);
    assert.throws(() => parseTree('[dev-dependencies]\n'), /unexpected cargo tree line/);
  });

  test('logicalLines joins continued lines and keeps the first line number', () => {
    assert.deepEqual(logicalLines('a \\\n b\nc'), [
      { line: 1, text: 'a   b' },
      { line: 3, text: 'c' },
    ]);
  });

  test('badReleaseCommands needs both a release command and a forbidden flag', () => {
    assert.deepEqual(badReleaseCommands('cargo test --all-features\ncargo build --release\nrm -r --all-targets\n'), []);
    assert.equal(badReleaseCommands('cargo b -r --all-targets\n').length, 1);
    assert.equal(badReleaseCommands('build --release --all-features\n').length, 0);
    assert.equal(badReleaseCommands('build --release --all-features\n', { cargoConfig: true }).length, 1);
  });

  test('scannedKind picks the files that run builds, not this guard', () => {
    assert.equal(scannedKind('.github/workflows/ci.yml'), 'file');
    assert.equal(scannedKind('.cargo/config.toml'), 'cargo-config');
    assert.equal(scannedKind('deploy/Dockerfile.release'), 'file');
    assert.equal(scannedKind('justfile'), 'file');
    assert.equal(scannedKind('scripts/ci/docs-only.sh'), 'file');
    assert.equal(scannedKind('scripts/ci/check-release-features.mjs'), null);
    assert.equal(scannedKind('scripts/ci/check-release-features.test.mjs'), null);
    assert.equal(scannedKind('docs/notes.md'), null);
  });
});
