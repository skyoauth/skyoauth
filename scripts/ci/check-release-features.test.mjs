// Self-test for check-release-features.mjs:
//   node --test scripts/ci/check-release-features.test.mjs
//
// Needs cargo on PATH, no network: each case builds a small workspace of
// path packages in a temporary directory (`svc`, a library and binary that
// declares `test-support` and turns it on through a dev-dependency on
// itself, as `skyoauth-service` does; `scen`, a library whose
// dev-dependency turns it on, as `skyoauth-scenarios` does), writes its
// lockfile offline, and runs the guard on it. The clean workspace passes;
// each case that injects the feature into a release resolution, a feature
// that turns it on, or a release command with a forbidden flag or test
// targets, must fail with the expected error. Needs smol-toml (npm ci in
// scripts/ci), as the guard does.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { badReleaseCommands, isBadCommand, isReleaseProfile, logicalLines, parseTree, scannedKind, splitCommands } from './check-release-features.mjs';

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

const SCEN = (dependency = '', features = '') => `[package]
name = "scen"
version = "0.1.0"
edition = "2021"

[features]
${features}
[dependencies]
svc = { path = "../svc"${dependency} }

[dev-dependencies]
svc = { path = "../svc", features = ["test-support"] }
`;

let cases = 0;

// A workspace with the members `svc` and `scen` (manifests `svc`, `scen`),
// any `extra` members (name to manifest; each gets a binary), `rootExtra`
// after the root manifest's `[workspace]` table, and the files in `files`
// (path to content). Returns its root.
function workspace({ svc = SVC(), scen = SCEN(), extra = {}, files = {}, rootExtra = '' } = {}) {
  const root = join(TOP, `case-${++cases}`);
  const members = ['svc', 'scen', ...Object.keys(extra)];
  const put = (path, content) => {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  };
  put('Cargo.toml', `[workspace]\nmembers = [${members.map((m) => `"${m}"`).join(', ')}]\nresolver = "2"\n${rootExtra}`);
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

const MESSAGE =
  'a release build must not use --all-features or --all-targets, name test-support or a feature that turns it on, or build test, bench or example targets';
const featureError = (feature, pkg) =>
  `error: features: feature \`${feature}\` of ${pkg} turns on \`test-support\`, so \`--features ${feature}\` or --all-features would build it into a release`;

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
      featureError('default', 'svc'),
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

  test('fails on a release command with a forbidden flag or test targets, wherever it runs', () => {
    const files = {
      '.github/workflows/release.yml': [
        'jobs:',
        '  r:',
        '    steps:',
        '      - run: cargo build --locked --release \\',
        '          --all-features',
        '      - run: cargo build --release -p svc',
        '      - run: >-',
        '          cargo build --release',
        '          --all-features',
        '      - run: |',
        '          cargo build --release -p svc',
        '          cargo test --all-features',
        '      - run: cargo nextest run --all-features --profile ci',
        '      - run: cargo nextest run --cargo-profile release',
        '      - run: cargo ship2 --all-features',
        '',
      ].join('\n'),
      Dockerfile: 'RUN cargo build -r --all-targets\nRUN cargo install --path svc --all-features\nRUN cargo install --path svc\n',
      'scripts/release.sh': [
        '#!/bin/sh',
        'cargo build --profile release -F svc/test-support',
        'cargo build --profile dist --all-features',
        'cargo build --profile fast --all-features',
        'cargo build --profile "$PROFILE" --all-features',
        'cargo build --release --bins --tests',
        'cargo test --release',
        'cargo bench',
        'cargo build --release && cargo test --all-features',
        `RUSTFLAGS='--cfg feature="test-support"' cargo build --release`,
        '',
      ].join('\n'),
      '.cargo/config.toml': '[alias]\nship = "build --release --all-features"\ncheck-all = "check --all-features --all-targets"\nship2 = "build --release"\n',
      'svc/.cargo/config.toml': `[alias]\nship3 = ["build", "--release", "--examples"]\n\n[build]\nrustflags = ["--cfg", 'feature="test-support"']\n`,
      'docs/notes.md': 'cargo build --release --all-features\n',
    };
    const rootExtra = '\n[profile.dist]\ninherits = "release"\n\n[profile.fast]\ninherits = "dev"\n';
    const bad = (where, text) => `error: ${where}: command: ${MESSAGE}: ${text}`;
    assertErrors(guard(workspace({ files, rootExtra })), [
      bad('.cargo/config.toml:2', 'alias ship = build --release --all-features'),
      bad('.github/workflows/release.yml:4', '- run: cargo build --locked --release --all-features'),
      bad('.github/workflows/release.yml:7', '- run: cargo build --release --all-features'),
      bad('.github/workflows/release.yml:14', '- run: cargo nextest run --cargo-profile release'),
      bad('.github/workflows/release.yml:15', '- run: cargo ship2 --all-features'),
      bad('Dockerfile:1', 'RUN cargo build -r --all-targets'),
      bad('Dockerfile:2', 'RUN cargo install --path svc --all-features'),
      bad('scripts/release.sh:2', 'cargo build --profile release -F svc/test-support'),
      bad('scripts/release.sh:3', 'cargo build --profile dist --all-features'),
      bad('scripts/release.sh:5', 'cargo build --profile "$PROFILE" --all-features'),
      bad('scripts/release.sh:6', 'cargo build --release --bins --tests'),
      bad('scripts/release.sh:7', 'cargo test --release'),
      bad('scripts/release.sh:8', 'cargo bench'),
      bad('scripts/release.sh:10', `RUSTFLAGS='--cfg feature="test-support"' cargo build --release`),
      bad('svc/.cargo/config.toml:2', 'alias ship3 = build --release --examples'),
      `error: svc/.cargo/config.toml:5: command: cargo configuration applies to every build and must not name test-support: rustflags = ["--cfg", 'feature="test-support"']`,
    ]);
  });

  test('fails on a feature that turns it on, directly or through other features', () => {
    const svc = SVC('full = ["test-support"]\n');
    const scen = SCEN('', 'leak = ["svc/test-support"]\nall = ["more"]\nmore = ["svc/full"]\nplain = []\n');
    assertErrors(guard(workspace({ svc, scen })), [
      featureError('all', 'scen'),
      featureError('leak', 'scen'),
      featureError('more', 'scen'),
      featureError('full', 'svc'),
    ]);
  });

  test('fails on a non-default release selection that reaches it through a feature', () => {
    const svc = SVC('full = ["test-support"]\n');
    const files = { 'scripts/release.sh': 'cargo build --release -p svc --features full\ncargo build --release -F svc/full\ncargo build --release -p svc\n' };
    assertErrors(guard(workspace({ svc, files })), [
      `error: scripts/release.sh:1: command: ${MESSAGE}: cargo build --release -p svc --features full`,
      `error: scripts/release.sh:2: command: ${MESSAGE}: cargo build --release -F svc/full`,
      featureError('full', 'svc'),
    ]);
  });

  test('fails on a feature that turns on the feature of a dependency outside the workspace', () => {
    const ext = join(TOP, 'ext');
    mkdirSync(join(ext, 'src'), { recursive: true });
    writeFileSync(join(ext, 'Cargo.toml'), '[package]\nname = "ext"\nversion = "0.1.0"\nedition = "2021"\n\n[features]\ntest-support = []\n');
    writeFileSync(join(ext, 'src', 'lib.rs'), '');
    const app = `[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[features]\noutside = ["ext/test-support"]\n\n[dependencies]\next = { path = ${JSON.stringify(ext)} }\n`;
    assertErrors(guard(workspace({ extra: { app } })), [featureError('outside', 'app')]);
  });

  test('fails on a feature that turns it on through an optional dependency', () => {
    const app = [
      '[package]',
      'name = "app"',
      'version = "0.1.0"',
      'edition = "2021"',
      '',
      '[features]',
      'maybe = ["svc?/test-support"]',
      'via-dep = ["dep:svc"]',
      'plain = []',
      '',
      '[dependencies]',
      'svc = { path = "../svc", optional = true, features = ["test-support"] }',
      '',
    ].join('\n');
    assertErrors(guard(workspace({ extra: { app } })), [featureError('maybe', 'app'), featureError('via-dep', 'app')]);
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

  test('parseTree ignores colour codes cargo adds when colour is forced', () => {
    const tree = parseTree('http v1.5.0 [default,std] \x1b[33m\x1b[2m(*)\x1b[39m\x1b[22m\n');
    assert.deepEqual([...tree.get('http')], ['default', 'std']);
  });

  test('logicalLines joins continued lines and keeps the first line number', () => {
    assert.deepEqual(logicalLines('a \\\n b\nc'), [
      { line: 1, text: 'a   b' },
      { line: 3, text: 'c' },
    ]);
  });

  test('logicalLines joins YAML folded and continued plain scalars, not literal ones', () => {
    const yaml = ['- run: >-', '    a', '', '    b', '  env: {}', '- run: c', '    d', '- run: |', '    e', '    f', 'g: h'].join('\n');
    assert.deepEqual(
      logicalLines(yaml, { yaml: true }).map(({ line, text }) => [line, text.replace(/\s+/g, ' ').trim()]),
      [
        [1, '- run: a'],
        [4, 'b'],
        [5, 'env: {}'],
        [6, '- run: c d'],
        [8, '- run: |'],
        [9, 'e'],
        [10, 'f'],
        [11, 'g: h'],
      ],
    );
    assert.equal(logicalLines(yaml).length, 11);
  });

  test('logicalLines ends a folded paragraph at a blank line, as YAML keeps the line break', () => {
    // Joined to the paragraph before, the release command would follow the word `cargo` of an echo.
    const hidden = ['- run: >', '    echo building with cargo', '', '    cargo install --path svc', '    --all-features', ''].join('\n');
    assert.deepEqual(badReleaseCommands(hidden, { yaml: true }), [{ line: 4, text: 'cargo install --path svc --all-features' }]);
    // Joined, the flag of the second paragraph's command would be read as the first one's.
    const separate = ['- run: >-', '    cargo build --release', '', '    ./scripts/lint.sh --all-features', ''].join('\n');
    assert.deepEqual(badReleaseCommands(separate, { yaml: true }), []);
  });

  test('logicalLines reads no YAML key in a literal block', () => {
    const yaml = [
      '- run: |',
      '    if true; then echo note: using cargo',
      '      cargo install --path svc --all-features',
      '    fi',
      '- run: |',
      '    echo step: cargo build --release',
      '      --all-features',
      '  env: {}',
      '',
    ].join('\n');
    assert.deepEqual(badReleaseCommands(yaml, { yaml: true }), [{ line: 3, text: 'cargo install --path svc --all-features' }]);
  });

  test('isReleaseProfile follows inherits and counts an undeclared profile as release', () => {
    const profiles = new Map([
      ['dist', ['release']],
      ['fast', ['dev']],
      ['ci', ['fast']],
      ['loop', ['loop2']],
      ['loop2', ['loop']],
      ['split', ['dev', 'bench']],
    ]);
    for (const name of ['release', 'bench', 'dist', 'loop', 'split', 'undeclared', '$PROFILE']) assert.equal(isReleaseProfile(name, profiles), true, name);
    for (const name of ['dev', 'test', 'fast', 'ci']) assert.equal(isReleaseProfile(name, profiles), false, name);
  });

  test('badReleaseCommands needs both a release command and a forbidden flag', () => {
    assert.deepEqual(badReleaseCommands('cargo test --all-features\ncargo build --release\nrm -r --all-targets\n'), []);
    assert.equal(badReleaseCommands('cargo b -r --all-targets\n').length, 1);
    assert.equal(badReleaseCommands('build --release --all-features\n').length, 0);
    assert.equal(badReleaseCommands('cargo +1.98.1 --locked build --release --example x\n').length, 1);
    assert.equal(badReleaseCommands('cargo nextest run --profile ci --all-features\n').length, 0);
    assert.equal(badReleaseCommands('cargo build --release --features full\n', { leaking: new Set(['full']) }).length, 1);
    assert.equal(badReleaseCommands('cargo build --release --features fast\n', { leaking: new Set(['full']) }).length, 0);
  });

  test('badReleaseCommands checks each command of a line with its own arguments', () => {
    assert.deepEqual(badReleaseCommands('cargo test --all-features && cargo build --release\n'), []);
    assert.deepEqual(badReleaseCommands('cargo build --release; cargo test --all-targets || cargo doc --all-features | tee x\n'), []);
    assert.equal(badReleaseCommands('cargo test --all-features && cargo build --release --all-features\n').length, 1);
    // A separator inside quotes does not end the command.
    assert.equal(badReleaseCommands('cargo build --release --config "x;y" --all-features\n').length, 1);
    assert.equal(badReleaseCommands("cargo build --release --config 'a && b' --all-features\n").length, 1);
  });

  test('splitCommands splits at separators outside quotes', () => {
    assert.deepEqual(splitCommands('a && b || c; d | e'), ['a ', ' b ', ' c', ' d ', ' e']);
    assert.deepEqual(splitCommands(`a "x;y" 'p|q' \\; b`), [`a "x;y" 'p|q' \\; b`]);
  });

  test('splitCommands splits at a single & but not at a redirection, and reads an unmatched quote as a character', () => {
    assert.deepEqual(splitCommands('a & b &> c 2>&1 >&2'), ['a ', ' b &> c 2>&1 >&2']);
    assert.deepEqual(splitCommands("echo don't && b"), ["echo don't ", ' b']);
  });

  test('badReleaseCommands keeps a quoted word whole and still splits feature lists', () => {
    // The quoted `--config` value is one word, so the subcommand after it is read.
    assert.equal(badReleaseCommands(`cargo --config 'build.rustflags = ["-C", "x"]' install --path svc --all-features\n`).length, 1);
    assert.equal(badReleaseCommands('cargo --config "build.jobs = 4" build --release --all-features\n').length, 1);
    assert.equal(badReleaseCommands(`cargo --config 'build.rustflags = ["-C", "x"]' build -p svc\n`).length, 0);
    const leaking = new Set(['full']);
    for (const flag of ['-F=full', '-Ffull', '-F full', '--features=plain,full', '--features "plain full"', "--features 'plain,full'", '-F plain,full']) {
      assert.equal(badReleaseCommands(`cargo build --release ${flag}\n`, { leaking }).length, 1, flag);
    }
    assert.equal(badReleaseCommands('cargo build --release --features "plain fast"\n', { leaking }).length, 0);
    // A feature list given as one word, as the shell passes a quoted one.
    const context = { profiles: new Map(), aliases: new Map(), leaking };
    for (const list of [['--features', 'plain full'], ['-F', 'plain,full'], ['--features=plain, full']]) {
      assert.equal(isBadCommand(['build', '--release', ...list], context), true, list.join(' '));
    }
    assert.equal(isBadCommand(['build', '--release', '--features', 'plain fast'], context), false);
  });

  test('badReleaseCommands splits words at parentheses and redirections', () => {
    const leaking = new Set(['full']);
    for (const line of [
      '(cd service && cargo build --release --all-features)',
      'out=$(cargo build --release --all-features)',
      'cargo build --release --all-features>build.log',
      'cargo build --release --features full>build.log',
    ]) {
      assert.equal(badReleaseCommands(`${line}\n`, { leaking }).length, 1, line);
    }
    // A redirection's target is not the value of the flag before it.
    assert.equal(badReleaseCommands('cargo test --profile dev>test.log\n').length, 0);
  });

  test('badReleaseCommands takes the command as the words after the first one named cargo', () => {
    for (const line of [
      '/usr/local/cargo/bin/cargo install --path service --all-features',
      '~/.cargo/bin/cargo test --release',
      'CARGO_TARGET_DIR=/tmp/cargo cargo install --path svc --all-features',
      "echo cargo, don't panic && cargo install --path svc --all-features",
      // As before: a Makefile recipe prefix, a program that runs its arguments, a quoted command, an exec form.
      '\t@cargo build --release --all-features',
      'sudo cargo install --path svc --all-features',
      'sh -c "cargo build --release --all-features"',
      // A string that the next line closes, and a quote nested in another without an escape.
      'sh -c "cargo build --release --all-features',
      'sh -c "cargo build --config "x=1" --release --all-features"',
      'sh -c "echo using cargo && cargo install --path svc --all-features"',
      'echo "$(cargo build --release --all-features)"',
      'RUN ["cargo", "build", "--release", "--all-features"]',
    ]) {
      assert.equal(badReleaseCommands(`${line}\n`).length, 1, line);
    }
    // Any word cargo starts a command, as before: the guard does not know which programs run their arguments.
    assert.equal(badReleaseCommands('echo cargo install --all-features\n').length, 1);
    // A path that only passes through a directory named cargo is not the command.
    assert.equal(badReleaseCommands('CARGO_HOME=/opt/cargo make build -r --all-features\n').length, 0);
  });

  test('badReleaseCommands reads nextest profiles under llvm-cov too', () => {
    assert.equal(badReleaseCommands('cargo llvm-cov nextest --profile ci\n').length, 0);
    assert.equal(badReleaseCommands('cargo llvm-cov nextest --profile ci --cargo-profile release\n').length, 1);
    assert.equal(badReleaseCommands('cargo llvm-cov --profile ci\n').length, 1);
  });

  test('badReleaseCommands expands short-option clusters letter by letter', () => {
    const leaking = new Set(['full', 'x']);
    for (const line of [
      'cargo build -qr --all-features',
      'cargo build -vr --all-features',
      'cargo build -rF x',
      'cargo build -rFfull',
      'cargo build -rF full',
      'cargo build -rF=full',
      'cargo build -rF test-support',
      'cargo build -vrj4 --all-targets',
      'cargo b -qrp svc --all-features',
      'cargo test -qr',
    ]) {
      assert.equal(badReleaseCommands(`${line}\n`, { leaking }).length, 1, line);
    }
    // A letter that takes a value takes the rest of the word: `-pr` is the package `r`, `-Fr` the feature `r`.
    // The words after `--` are the program's: `-Dwarnings` holds no `-r`.
    for (const line of [
      'cargo build -pr --all-features',
      'cargo build -Fr --all-features',
      'cargo build -qv --all-features',
      'cargo build -j4 --all-features',
      'cargo build -rF plain',
      'cargo rustc --all-features -- -Dwarnings',
    ]) {
      assert.equal(badReleaseCommands(`${line}\n`, { leaking }).length, 0, line);
    }
  });

  test('badReleaseCommands reads cargo-SUB run directly as cargo SUB', () => {
    for (const line of [
      'cargo-nextest nextest run --cargo-profile release',
      'cargo-nextest run -r',
      'cargo-nextest nextest archive -r --archive-file a.tar.zst',
      'cargo-llvm-cov llvm-cov --release',
      'cargo-llvm-cov llvm-cov --profile ci',
      '/usr/local/cargo/bin/cargo-llvm-cov llvm-cov nextest --cargo-profile release',
    ]) {
      assert.equal(badReleaseCommands(`${line}\n`).length, 1, line);
    }
    for (const line of ['cargo-nextest nextest run --profile ci', 'cargo-llvm-cov llvm-cov nextest --profile ci', 'cargo-nextest nextest run --all-features']) {
      assert.equal(badReleaseCommands(`${line}\n`).length, 0, line);
    }
  });

  test('badReleaseCommands reads no option value as the subcommand or the cargo word', () => {
    for (const line of [
      'cargo llvm-cov --color always nextest --profile ci',
      'cargo llvm-cov nextest-archive --profile ci --archive-file a.tar.zst',
      'make -C /opt/cargo build -r --all-features',
      'make -C/opt/cargo build -r --all-features',
    ]) {
      assert.equal(badReleaseCommands(`${line}\n`).length, 0, line);
    }
    for (const line of [
      'cargo llvm-cov --color always nextest --profile ci --cargo-profile release',
      'cargo llvm-cov nextest-archive --cargo-profile release',
      'cargo llvm-cov --color always --profile ci',
      'env -C /opt/cargo cargo build -r --all-features',
      'make -C /opt/cargo && cargo build -r --all-features',
    ]) {
      assert.equal(badReleaseCommands(`${line}\n`).length, 1, line);
    }
  });

  test('badReleaseCommands checks the commands around a single & on their own', () => {
    assert.equal(badReleaseCommands('cargo build --release & cargo test --all-features\n').length, 0);
    assert.equal(badReleaseCommands('cargo build --release --all-features & wait\n').length, 1);
    assert.equal(badReleaseCommands('cargo build --release 2>&1 --all-features\n').length, 1);
  });

  test('badReleaseCommands expands cargo aliases with the arguments after them', () => {
    const aliases = new Map([['ship', [['build', '--release']]]]);
    assert.equal(badReleaseCommands('cargo ship --all-features\n', { aliases }).length, 1);
    assert.equal(badReleaseCommands('cargo ship -p svc\n', { aliases }).length, 0);
  });

  test('scannedKind picks the files that run builds, not this guard', () => {
    assert.equal(scannedKind('.github/workflows/ci.yml'), 'yaml');
    assert.equal(scannedKind('.cargo/config.toml'), 'cargo-config');
    assert.equal(scannedKind('service/.cargo/config'), 'cargo-config');
    assert.equal(scannedKind('tests/Cargo.toml'), 'manifest');
    assert.equal(scannedKind('deploy/Dockerfile.release'), 'file');
    assert.equal(scannedKind('justfile'), 'file');
    assert.equal(scannedKind('scripts/ci/docs-only.sh'), 'file');
    assert.equal(scannedKind('scripts/ci/check-release-features.mjs'), null);
    assert.equal(scannedKind('scripts/ci/check-release-features.test.mjs'), null);
    assert.equal(scannedKind('docs/notes.md'), null);
  });
});
