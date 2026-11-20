// Self-test for publish-badges.sh:  node --test scripts/ci/publish-badges.test.mjs
//
// Every test publishes into a local bare repository standing in for the
// GitHub remote, from a clone of it, so nothing touches the network. Git
// runs with no global or system configuration and fixed identities.
//
// The concurrency test starts PUBLISH_BADGES_STRESS_PUBLISHERS publishers
// (default 24) at once, each for a branch of its own, and repeats that
// PUBLISH_BADGES_STRESS_ROUNDS times (default 3). The deterministic test
// next to it reproduces the same race with a pre-receive hook.

import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'publish-badges.sh');
const PUBLISHERS = Number(process.env.PUBLISH_BADGES_STRESS_PUBLISHERS ?? 24);
const ROUNDS = Number(process.env.PUBLISH_BADGES_STRESS_ROUNDS ?? 3);

const RED = '#e05d44';
const GREEN = '#97ca00';
const BRIGHTGREEN = '#4c1';

const ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'test',
  GIT_AUTHOR_EMAIL: 'test@example.invalid',
  GIT_COMMITTER_NAME: 'test',
  GIT_COMMITTER_EMAIL: 'test@example.invalid',
  BADGES_RETRY_SLEEP: '0',
};
delete ENV.BADGES_REMOTE;
delete ENV.BADGES_BRANCH;
delete ENV.BADGES_ATTEMPTS;

const roots = [];
after(() => {
  for (const root of roots) rmSync(root, { recursive: true, force: true });
});

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, env: ENV, encoding: 'utf8' }).trim();
}

// A bare remote with `main` and BRANCHES at one source commit, and CLONES
// clones of it. Returns paths, the source commit, and fixture writers.
function setup({ branches = [], clones = 1 } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'publish-badges-'));
  roots.push(root);
  const remote = join(root, 'remote.git');
  git(root, 'init', '-q', '--bare', '-b', 'main', remote);
  const seed = join(root, 'seed');
  git(root, 'init', '-q', '-b', 'main', seed);
  writeFileSync(join(seed, 'lib.rs'), '// code\n');
  git(seed, 'add', '.');
  git(seed, 'commit', '-q', '-m', 'init');
  for (const branch of branches) git(seed, 'branch', branch);
  git(seed, 'push', '-q', remote, '--all');
  const sha = git(seed, 'rev-parse', 'HEAD');
  const work = [];
  for (let i = 0; i < clones; i++) {
    const dir = join(root, `clone${i}`);
    git(root, 'clone', '-q', remote, dir);
    work.push(dir);
  }
  const file = (name, value) => {
    const path = join(root, name);
    writeFileSync(path, JSON.stringify(value));
    return path;
  };
  return { root, remote, sha, work, file };
}

const rustReport = (percent) => ({ data: [{ totals: { lines: { percent } } }] });
const tsSummary = (lines) => ({ total: { lines: { pct: lines }, branches: { pct: 70 }, functions: { pct: 80 }, statements: { pct: lines } } });

function publish(cwd, args, env = {}) {
  return spawnSync('sh', [SCRIPT, ...args], { cwd, env: { ...ENV, ...env }, encoding: 'utf8' });
}

function publishAsync(cwd, args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn('sh', [SCRIPT, ...args], { cwd, env: { ...ENV, ...env } });
    let output = '';
    child.stdout.on('data', (d) => (output += d));
    child.stderr.on('data', (d) => (output += d));
    child.on('close', (status) => resolve({ status, output }));
  });
}

// The value colour and text of a published badge, and the summary.
function badge(remote, path) {
  const svg = git(remote, 'show', `badges:${path}`);
  // The value half is the only <rect> with an x offset.
  const color = svg.match(/<rect x="\d+" width="\d+" height="20" fill="(#[0-9a-fA-F]+)"\/>/)[1];
  const title = svg.match(/<title>([^<]*)<\/title>/)[1];
  return { color, title };
}
const summary = (remote, branch) => JSON.parse(git(remote, 'show', `badges:${branch}/summary.json`));

describe('coverage badge colour follows the gate', () => {
  test('a failed gate is red even when the rounded figure reaches the threshold', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], [
      'main', sha,
      '--rust-coverage', file('rust.json', rustReport(84.96)), '--rust-coverage-result', 'failure',
      '--ts-coverage', file('ts.json', tsSummary(100)), '--ts-coverage-result', 'failure',
    ]);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(badge(remote, 'main/rust-coverage.svg'), { color: RED, title: 'rust coverage: 85.0%' });
    assert.deepEqual(badge(remote, 'main/typescript-coverage.svg'), { color: RED, title: 'typescript coverage: 100.0%' });
    const s = summary(remote, 'main');
    assert.equal(s.rust_coverage.gate, 'failed');
    assert.equal(s.typescript_coverage.gate, 'failed');
  });

  test('a cancelled coverage job is red too', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], ['main', sha, '--rust-coverage', file('rust.json', rustReport(97.7)), '--rust-coverage-result', 'cancelled']);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(badge(remote, 'main/rust-coverage.svg').color, RED);
  });

  test('a passed gate keeps the band colours', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], [
      'main', sha,
      '--rust-coverage', file('rust.json', rustReport(85)), '--rust-coverage-result', 'success',
      '--ts-coverage', file('ts.json', tsSummary(100)), '--ts-coverage-result', 'success',
    ]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(badge(remote, 'main/rust-coverage.svg').color, GREEN);
    assert.equal(badge(remote, 'main/typescript-coverage.svg').color, BRIGHTGREEN);
    assert.equal(summary(remote, 'main').rust_coverage.gate, 'passed');
  });

  for (const [name, args, message] of [
    ['a report without its job result', ['--rust-coverage', 'R'], /--rust-coverage requires --rust-coverage-result/],
    ['a job result without a report', ['--ts-coverage-failed', '--ts-coverage-result', 'failure'], /--ts-coverage-result requires --ts-coverage/],
    ['a result that is not a job result', ['--rust-coverage', 'R', '--rust-coverage-result', 'skipped'], /must be success, failure or cancelled/],
  ]) {
    test(`rejects ${name}`, () => {
      const { sha, work, file } = setup();
      const path = file('rust.json', rustReport(90));
      const r = publish(work[0], ['main', sha, ...args.map((a) => (a === 'R' ? path : a))]);
      assert.equal(r.status, 2);
      assert.match(r.stderr, message);
    });
  }
});

describe('push retries', () => {
  // Lands a commit on `badges` from inside the remote while the push is in
  // flight, once: the push then fails as GitHub's does when two updates
  // race, with "cannot lock ref ... is at X but expected Y" and
  // "(failed to update ref)" rather than a non-fast-forward.
  const RACE_HOOK = `#!/bin/sh
[ -e "$GIT_DIR/raced" ] && exit 0
touch "$GIT_DIR/raced"
unset GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
tip=$(git rev-parse refs/heads/badges)
new=$(git commit-tree "$tip^{tree}" -p "$tip" -m "concurrent publication")
git update-ref refs/heads/badges "$new" "$tip"
`;
  const DECLINE_HOOK = `#!/bin/sh
echo "declined by policy" >&2
exit 1
`;
  const hook = (remote, body) => {
    const path = join(remote, 'hooks', 'pre-receive');
    writeFileSync(path, body);
    chmodSync(path, 0o755);
  };
  const args = (sha, file, percent) => ['main', sha, '--rust-coverage', file(`rust-${percent}.json`, rustReport(percent)), '--rust-coverage-result', 'success'];

  test('retries when the badges branch moved under a failed push, whatever the error says', () => {
    const { remote, sha, work, file } = setup();
    assert.equal(publish(work[0], args(sha, file, 90)).status, 0);
    hook(remote, RACE_HOOK);
    const r = publish(work[0], args(sha, file, 91));
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stderr, /failed to update ref/);
    assert.match(r.stdout, /published main .* attempt 2\)/);
    assert.equal(badge(remote, 'main/rust-coverage.svg').title, 'rust coverage: 91.0%');
    assert.match(git(remote, 'log', '--format=%s', 'badges'), /^badges: main .*91\.0%.*\nconcurrent publication\nbadges: main .*90\.0%/);
  });

  test('gives up at once when the push failed and the branch did not move', () => {
    const { remote, sha, work, file } = setup();
    assert.equal(publish(work[0], args(sha, file, 90)).status, 0);
    const before = git(remote, 'rev-parse', 'badges');
    hook(remote, DECLINE_HOOK);
    const r = publish(work[0], args(sha, file, 91), { BADGES_ATTEMPTS: '5' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /declined by policy/);
    assert.match(r.stderr, /did not move .*not a race, giving up/);
    assert.doesNotMatch(r.stdout, /regenerating/);
    assert.equal(git(remote, 'rev-parse', 'badges'), before);
  });

  test('rejects a BADGES_ATTEMPTS that is not a positive integer', () => {
    const { sha, work, file } = setup();
    for (const attempts of ['0', 'x', '-1']) {
      const r = publish(work[0], args(sha, file, 90), { BADGES_ATTEMPTS: attempts });
      assert.equal(r.status, 2, attempts);
      assert.match(r.stderr, /BADGES_ATTEMPTS must be a positive integer/);
    }
  });

  // Each retry follows a publication that landed, so N concurrent
  // publishers need at most N attempts. The first round also races the
  // creation of the badges branch itself.
  test(`${PUBLISHERS} concurrent publishers all land, ${ROUNDS} rounds`, { timeout: 120_000 * ROUNDS }, async () => {
    const branches = Array.from({ length: PUBLISHERS }, (_, i) => `b${i}`);
    const { remote, sha, work, file } = setup({ branches, clones: PUBLISHERS });
    for (let round = 1; round <= ROUNDS; round++) {
      const report = file(`rust-round${round}.json`, rustReport(80 + round));
      const results = await Promise.all(
        branches.map((branch, i) =>
          publishAsync(work[i], [branch, sha, '--rust-coverage', report, '--rust-coverage-result', 'success'], {
            BADGES_ATTEMPTS: String(PUBLISHERS),
          }),
        ),
      );
      const failed = results.map((r, i) => [branches[i], r]).filter(([, r]) => r.status !== 0);
      assert.deepEqual(failed.map(([b, r]) => `${b}: ${r.output}`), [], `round ${round}: ${failed.length}/${PUBLISHERS} failed`);
      for (const branch of branches) {
        assert.equal(badge(remote, `${branch}/rust-coverage.svg`).title, `rust coverage: ${80 + round}.0%`, `round ${round}, ${branch}`);
      }
      assert.equal(Number(git(remote, 'rev-list', '--count', 'badges')), PUBLISHERS * round, `round ${round}: one commit per publication`);
    }
  });
});
