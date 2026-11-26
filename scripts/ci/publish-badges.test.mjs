// Self-test for publish-badges.sh:  node --test scripts/ci/publish-badges.test.mjs
//
// Every test publishes into a local bare repository standing in for the
// GitHub remote, from a clone of it. The tests are hermetic:
//   - git reads no global or system configuration and inherits no GIT_*
//     variable; the identity is set in each temporary repository, the
//     initial branch is named explicitly, and only the `file` transport is
//     allowed, so nothing touches the network or a credential helper;
//   - automatic gc and maintenance are off, so git leaves no background
//     process behind, and every publisher still running when the tests end
//     is killed with its process group;
//   - everything, including the script's own temporary worktrees (TMPDIR),
//     lives under one temporary directory, removed after the tests whether
//     they passed or failed.
// They need node, git, sh and jq, as the script does.
//
// The concurrency test starts PUBLISH_BADGES_STRESS_PUBLISHERS publishers
// (default 24) at once, each for a branch of its own, and repeats that
// PUBLISH_BADGES_STRESS_ROUNDS times (default 3). The deterministic test
// next to it reproduces the same race with a pre-receive hook.

import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { accessSync, chmodSync, closeSync, constants, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'publish-badges.sh');
const CI_SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'publish-badges-ci.sh');
const PUBLISHERS = Number(process.env.PUBLISH_BADGES_STRESS_PUBLISHERS ?? 24);
const ROUNDS = Number(process.env.PUBLISH_BADGES_STRESS_ROUNDS ?? 3);

const RED = '#e05d44';
const GREEN = '#97ca00';
const BRIGHTGREEN = '#4c1';

// Everything the tests create lives under TOP; the script's temporary
// worktrees go to SCRIPT_TMP, which must be empty after every publication.
const TOP = mkdtempSync(join(tmpdir(), 'publish-badges-test-'));
const SCRIPT_TMP = join(TOP, 'tmp');
mkdirSync(SCRIPT_TMP);

// Configuration for every git process the tests start. A push to a local
// remote clears GIT_CONFIG_COUNT for the remote side, so setup() also
// writes it into the bare remote's own config: otherwise its receive-pack
// runs `gc --auto` or, from git 2.47 on, a detached
// `maintenance run --auto` that outlives the push.
const GIT_CONFIG = {
  'gc.auto': '0',
  'gc.autoDetach': 'false',
  'maintenance.auto': 'false',
  'receive.autogc': 'false',
  'credential.helper': '',
};

// No GIT_* variable is inherited. That covers the repository-location
// variables a git hook or `git rebase --exec` exports (GIT_DIR,
// GIT_WORK_TREE, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY,
// GIT_ALTERNATE_OBJECT_DIRECTORIES, GIT_COMMON_DIR, GIT_NAMESPACE,
// GIT_QUARANTINE_PATH, GIT_PREFIX, ...), which would point every git the
// tests run at that repository, as well as identity and configuration
// variables.
const ENV = Object.fromEntries(
  Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_') && !key.startsWith('BADGES_')),
);
Object.assign(ENV, {
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_TERMINAL_PROMPT: '0',
  GIT_ALLOW_PROTOCOL: 'file',
  GIT_CONFIG_COUNT: String(Object.keys(GIT_CONFIG).length),
  TMPDIR: SCRIPT_TMP,
  BADGES_RETRY_SLEEP: '0',
});
Object.entries(GIT_CONFIG).forEach(([key, value], i) => {
  ENV[`GIT_CONFIG_KEY_${i}`] = key;
  ENV[`GIT_CONFIG_VALUE_${i}`] = value;
});

const children = new Set();
after(() => {
  for (const child of children) {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {
      // Already gone.
    }
  }
  rmSync(TOP, { recursive: true, force: true });
});

function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, env: ENV, encoding: 'utf8' }).trim();
}

function identify(repo) {
  git(repo, 'config', 'user.name', 'test');
  git(repo, 'config', 'user.email', 'test@example.invalid');
}

// A bare remote with `main` and BRANCHES at one source commit, and CLONES
// clones of it. Returns paths, the source commit, and fixture writers.
function setup({ branches = [], clones = 1 } = {}) {
  const root = mkdtempSync(join(TOP, 'case-'));
  const remote = join(root, 'remote.git');
  git(root, 'init', '-q', '--bare', '-b', 'main', remote);
  identify(remote);
  for (const [key, value] of Object.entries(GIT_CONFIG)) git(remote, 'config', key, value);
  const seed = join(root, 'seed');
  git(root, 'init', '-q', '-b', 'main', seed);
  identify(seed);
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
    identify(dir);
    work.push(dir);
  }
  const file = (name, value) => {
    const path = join(root, name);
    writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
    return path;
  };
  return { root, remote, sha, work, file };
}

const rustReport = (percent) => ({ data: [{ totals: { lines: { percent } } }] });
const tsSummary = (lines) => ({ total: { lines: { pct: lines }, branches: { pct: 70 }, functions: { pct: 80 }, statements: { pct: lines } } });
// The same reports with the percentage written as a literal JSON number,
// exactly as given (exponent forms, more digits than a double keeps).
const rustReportText = (literal) => `{"data":[{"totals":{"lines":{"percent":${literal}}}}]}`;
const tsSummaryText = (literal) => `{"total":{"lines":{"pct":${literal}},"branches":{"pct":70},"functions":{"pct":80},"statements":{"pct":${literal}}}}`;

function publish(cwd, args, env = {}) {
  return spawnSync('sh', [SCRIPT, ...args], { cwd, env: { ...ENV, ...env }, encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL' });
}

// Runs in a process group of its own, so that `after` can kill the
// publisher and its git processes if a test ends while it still runs.
function publishAsync(cwd, args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn('sh', [SCRIPT, ...args], { cwd, env: { ...ENV, ...env }, detached: true });
    children.add(child);
    let output = '';
    child.stdout.on('data', (d) => (output += d));
    child.stderr.on('data', (d) => (output += d));
    child.on('close', (status) => {
      children.delete(child);
      resolve({ status, output });
    });
  });
}

// The script removes its temporary worktrees whether it published or not.
const assertNoScriptLeftovers = () => assert.deepEqual(readdirSync(SCRIPT_TMP), []);

// The value colour and text of a published badge, and the summary.
function badge(remote, path) {
  const svg = git(remote, 'show', `badges:${path}`);
  // The value half is the only <rect> with an x offset.
  const color = svg.match(/<rect x="\d+" width="\d+" height="20" fill="(#[0-9a-fA-F]+)"\/>/)[1];
  const title = svg.match(/<title>([^<]*)<\/title>/)[1];
  return { color, title };
}
const summary = (remote, branch) => JSON.parse(git(remote, 'show', `badges:${branch}/summary.json`));

test('the child environment carries no inherited git repository location', () => {
  const location = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_NAMESPACE', 'GIT_QUARANTINE_PATH', 'GIT_PREFIX', 'GIT_CEILING_DIRECTORIES'];
  assert.deepEqual(location.filter((key) => key in ENV), []);
  assert.deepEqual(Object.keys(ENV).filter((key) => key.startsWith('GIT_') && !key.startsWith('GIT_CONFIG')), ['GIT_TERMINAL_PROMPT', 'GIT_ALLOW_PROTOCOL']);
});

describe('coverage badge colour follows the gate', () => {
  test('a failed gate is red whatever the figure', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], [
      'main', sha,
      '--rust-coverage', file('rust.json', rustReport(84.96)), '--rust-coverage-result', 'failure',
      '--ts-coverage', file('ts.json', tsSummary(100)), '--ts-coverage-result', 'failure',
    ]);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(badge(remote, 'main/rust-coverage.svg'), { color: RED, title: 'rust coverage: 84.9%' });
    assert.deepEqual(badge(remote, 'main/typescript-coverage.svg'), { color: RED, title: 'typescript coverage: 100.0%' });
    const s = summary(remote, 'main');
    assert.equal(s.rust_coverage.gate, 'failed');
    assert.equal(s.typescript_coverage.gate, 'failed');
    assertNoScriptLeftovers();
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

describe('coverage percentage is truncated to one decimal, never rounded', () => {
  // [literal in the report, badge text]
  const CASES = [
    ['84.96', '84.9'],
    ['84.99999', '84.9'],
    ['84.99999999999999', '84.9'], // the largest double below 85 prints like this
    ['85', '85.0'],
    ['85.04', '85.0'],
    ['84.9', '84.9'], // a double slightly below 84.9; the literal is what counts
    ['99.99', '99.9'],
    ['100', '100.0'],
    ['0', '0.0'],
    ['0.05', '0.0'],
    ['97.80487804878049', '97.8'],
    ['8.496e1', '84.9'],
    ['1E+2', '100.0'],
    ['5e-324', '0.0'],
  ];
  for (const [literal, shown] of CASES) {
    test(`${literal} shows as ${shown}%`, () => {
      const { remote, sha, work, file } = setup();
      const r = publish(work[0], [
        'main', sha,
        '--rust-coverage', file('rust.json', rustReportText(literal)), '--rust-coverage-result', 'success',
        '--ts-coverage', file('ts.json', tsSummaryText(literal)), '--ts-coverage-result', 'success',
      ]);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(badge(remote, 'main/rust-coverage.svg').title, `rust coverage: ${shown}%`);
      assert.equal(badge(remote, 'main/typescript-coverage.svg').title, `typescript coverage: ${shown}%`);
      assert.equal(summary(remote, 'main').rust_coverage.lines_percent, Number(shown));
    });
  }

  test('the colour band follows the truncated figure', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], ['main', sha, '--rust-coverage', file('rust.json', rustReportText('89.96')), '--rust-coverage-result', 'success']);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(badge(remote, 'main/rust-coverage.svg'), { color: GREEN, title: 'rust coverage: 89.9%' });
  });

  // With a gate that did not pass, an unusable figure gives the red
  // `failing` badge rather than leaving the old (possibly green) one.
  for (const [name, args, badgeName, message] of [
    ['a Rust percentage above 100 from a failed gate', (file) => ['--rust-coverage', file('r.json', rustReportText('150')), '--rust-coverage-result', 'failure'], 'rust-coverage', /'150' .* is not a number from 0 to 100; the gate did not pass/],
    ['an unreadable TypeScript percentage from a cancelled job', (file) => ['--ts-coverage', file('t.json', tsSummaryText('"85"')), '--ts-coverage-result', 'cancelled'], 'typescript-coverage', /cannot read line coverage percentage .*; the gate did not pass/],
  ]) {
    test(`${name} publishes a red failing badge`, () => {
      const { remote, sha, work, file } = setup();
      const green = ['--rust-coverage', file('rg.json', rustReport(95)), '--rust-coverage-result', 'success', '--ts-coverage', file('tg.json', tsSummary(95)), '--ts-coverage-result', 'success'];
      assert.equal(publish(work[0], ['main', sha, ...green]).status, 0);
      assert.equal(badge(remote, `main/${badgeName}.svg`).color, BRIGHTGREEN);
      const r = publish(work[0], ['main', sha, ...args(file)]);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.match(r.stderr, message);
      assert.deepEqual(badge(remote, `main/${badgeName}.svg`), { color: RED, title: `${badgeName.replace('-', ' ')}: failing` });
      assert.equal(summary(remote, 'main')[badgeName.replace('-', '_')].status, 'failing');
    });
  }

  for (const literal of ['100.5', '100.01', '1E+3', '1.7976931348623157e308', '-1']) {
    test(`rejects ${literal}, which is not a percentage`, () => {
      const { remote, sha, work, file } = setup();
      const r = publish(work[0], ['main', sha, '--rust-coverage', file('rust.json', rustReportText(literal)), '--rust-coverage-result', 'success']);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /is not a number from 0 to 100/);
      assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
    });
  }
});

describe('push retries', () => {
  // Lands a commit on `badges` from inside the remote while the push is in
  // flight, once: the push then fails as GitHub's does when two updates
  // race, with a ref-update error rather than a non-fast-forward. Its
  // wording depends on the Git version ("cannot lock ref ... is at X but
  // expected Y", "(failed to update ref)", "incorrect old value provided"),
  // so no test matches it.
  const RACE_HOOK = `#!/bin/sh
[ -e "$GIT_DIR/raced" ] && exit 0
touch "$GIT_DIR/raced"
unset GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
tip=$(git rev-parse refs/heads/badges)
new=$(git commit-tree "$tip^{tree}" -p "$tip" -m "concurrent publication")
git update-ref refs/heads/badges "$new" "$tip"
`;
  // The same on every push: the publisher never gets through.
  const ALWAYS_RACE_HOOK = `#!/bin/sh
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
    assert.match(r.stdout, /push rejected \(badges moved from [0-9a-f]+ to [0-9a-f]+: another publication landed\)/);
    assert.match(r.stdout, /published main .* attempt 2\)/);
    assert.equal(badge(remote, 'main/rust-coverage.svg').title, 'rust coverage: 91.0%');
    assert.match(git(remote, 'log', '--format=%s', 'badges'), /^badges: main .*91\.0%.*\nconcurrent publication\nbadges: main .*90\.0%/);
    assertNoScriptLeftovers();
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
    assertNoScriptLeftovers();
  });

  test('gives up after BADGES_ATTEMPTS pushes when every one loses a race', () => {
    const { remote, sha, work, file } = setup();
    assert.equal(publish(work[0], args(sha, file, 90)).status, 0);
    hook(remote, ALWAYS_RACE_HOOK);
    const r = publish(work[0], args(sha, file, 91), { BADGES_ATTEMPTS: '3' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /push rejected 3 times; giving up/);
    assert.equal(r.stdout.match(/regenerating on the new tip/g)?.length, 2);
    assertNoScriptLeftovers();
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
      assertNoScriptLeftovers();
    }
  });
});

describe('numeric settings and counts', () => {
  const args = (sha, file) => ['main', sha, '--rust-coverage', file('rust.json', rustReport(90)), '--rust-coverage-result', 'success'];
  // `main` has moved past `sha` by a code change, so a valid run is
  // superseded and exits 0 without publishing: a setting must be rejected
  // before that, not only on the paths that compare it.
  const superseded = () => {
    const ctx = setup();
    writeFileSync(join(ctx.work[0], 'more.rs'), '// more\n');
    git(ctx.work[0], 'add', '.');
    git(ctx.work[0], 'commit', '-q', '-m', 'more code');
    git(ctx.work[0], 'push', '-q', 'origin', 'main');
    return ctx;
  };

  test('a superseded run exits 0 without publishing, even with an unusable report', () => {
    const { remote, sha, work, file } = superseded();
    const r = publish(work[0], ['main', sha, '--ts-results', file('bad.json', '{"success":true,"numPassedTests":-1,"numFailedTests":0}')]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /superseded, not publishing/);
    assert.doesNotMatch(r.stderr, /cannot read/);
    assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
  });

  test('a valid setting on a superseded commit publishes nothing', () => {
    const { sha, work, file } = superseded();
    const r = publish(work[0], args(sha, file), { BADGES_ATTEMPTS: '5' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /superseded, not publishing/);
  });

  for (const [name, values] of [
    ['BADGES_ATTEMPTS', ['9223372036854775808', '99999999999999999999', '100', '0', '00', '05', '-1', '+3', ' 3', '3 ', 'x', '1e1', '0x10']],
    ['BADGES_RETRY_SLEEP', ['9223372036854775808', '61', '05', '-1', '0.5', 'x']],
  ]) {
    test(`rejects an out-of-range or malformed ${name}`, () => {
      const { sha, work, file } = superseded();
      for (const value of values) {
        const r = publish(work[0], args(sha, file), { [name]: value });
        assert.equal(r.status, 2, `${name}='${value}': ${r.stdout}${r.stderr}`);
        assert.match(r.stderr, new RegExp(`${name} must be a whole number`));
      }
    });
  }

  test('accepts the ends of the BADGES_ATTEMPTS range, and an empty value means the default', () => {
    const { remote, sha, work, file } = setup();
    for (const [value, percent] of [['1', 90], ['99', 91], ['', 92]]) {
      const r = publish(work[0], ['main', sha, '--rust-coverage', file(`r${percent}.json`, rustReport(percent)), '--rust-coverage-result', 'success'], {
        BADGES_ATTEMPTS: value,
        BADGES_RETRY_SLEEP: '60',
      });
      assert.equal(r.status, 0, `'${value}': ${r.stderr}`);
      assert.equal(badge(remote, 'main/rust-coverage.svg').title, `rust coverage: ${percent}.0%`);
    }
  });

  const junit = (attrs) => `<?xml version="1.0"?><testsuites name="t" ${attrs}><testsuite name="s"/></testsuites>`;

  test('reads JUnit counts with leading zeros as decimal', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', junit('tests="010" failures="0" errors="00" skipped="0"'))]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(badge(remote, 'main/rust-tests.svg').title, 'rust tests: 10 passed');
  });

  test('rejects a JUnit count too large to compare', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', junit('tests="12" failures="99999999999999999999" errors="0" skipped="0"'))]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /failures="99999999999999999999" .* is out of range/);
    assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
  });

  test('counts a Vitest failure written as 1.0', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], ['main', sha, '--ts-results', file('results.json', '{"success":true,"numPassedTests":7,"numFailedTests":1.0}')]);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(badge(remote, 'main/typescript-tests.svg'), { color: RED, title: 'typescript tests: 1 failed' });
  });

  test('rejects a Vitest count too large to compare', () => {
    const { sha, work, file } = setup();
    const r = publish(work[0], ['main', sha, '--ts-results', file('results.json', '{"success":true,"numPassedTests":1e30,"numFailedTests":0}')]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /cannot read typescript test results/);
  });

  // A count that is present but not a whole number is not read as absent
  // (zero): `skipped="2x"` would otherwise show all 12 tests as passed.
  for (const [attr, value] of [
    ['skipped', '2x'], ['skipped', ''], ['failures', 'abc'], ['failures', '1.5'], ['errors', '-1'], ['errors', ' 1'], ['tests', '12x'], ['tests', '-12'],
  ]) {
    test(`rejects a malformed JUnit count ${attr}="${value}"`, () => {
      const { remote, sha, work, file } = setup();
      const attrs = { tests: '12', failures: '0', errors: '0', skipped: '0', [attr]: value };
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', junit(Object.entries(attrs).map(([k, v]) => `${k}="${v}"`).join(' ')))]);
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.ok(r.stderr.includes(`${attr}="${value}" in `) && /is not a count/.test(r.stderr), r.stderr);
      assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
    });
  }

  // XML lets the root element span lines, quote values with ' or ", and
  // put spaces around `=`. A count missed in any of these would read as
  // absent (zero), and a report with failures would show as green.
  for (const [form, root] of [
    ['single-quoted', "<testsuites name='t' tests='12' failures='3' errors='0' skipped='1'>"],
    ['single-quoted among double-quoted', `<testsuites name="t" tests="12" failures='3' errors="0" skipped="1">`],
    ['spaced around =', '<testsuites name = "t" tests= "12" failures ="3" errors = \'0\' skipped  =  "1">'],
    ['multi-line', '<testsuites name="t" tests="12"\n    failures="3"\r\n\terrors="0"\n    skipped="1"\n>'],
    ['with a > inside a value', '<testsuites name="a > b" tests="12" failures="3" errors="0" skipped="1">'],
  ]) {
    test(`reads the counts of a ${form} JUnit root element`, () => {
      const { remote, sha, work, file } = setup();
      const xml = `<?xml version="1.0"?>\n${root}<testsuite name="s"/></testsuites>\n`;
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', xml)]);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 3 failed' });
      const { status, passed, failed } = summary(remote, 'main').rust_tests;
      assert.deepEqual({ status, passed, failed }, { status: 'failed', passed: 8, failed: 3 });
    });
  }

  // What cannot be read attribute by attribute is not guessed at.
  for (const [form, xml] of [
    ['an unquoted value', junit('tests="12" failures=3 errors="0" skipped="0"')],
    ['an unterminated value', '<testsuites name="t" tests="12" failures="3>\n<testsuite name=s/></testsuites>\n'],
    ['no space between attributes', junit('tests="12"failures="3" errors="0" skipped="0"')],
    ['a repeated attribute', junit('tests="12" failures="0" errors="0" skipped="0" failures="3"')],
    ['no <testsuites> element', '<?xml version="1.0"?><testsuite name="s" tests="12" failures="3"/>'],
    ['a stray character where an attribute name belongs', junit('tests="12" - failures="3" errors="0" skipped="0"')],
    ['no end to the start tag', '<?xml version="1.0"?>\n<testsuites tests="12" errors="0"\n'],
  ]) {
    test(`rejects a JUnit root element with ${form}`, () => {
      const { remote, sha, work, file } = setup();
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', xml)]);
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /cannot parse the <testsuites> element in .*junit\.xml/);
      assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
    });

    test(`a JUnit root element with ${form} from a failed job publishes a red failing badge`, () => {
      const { remote, sha, work, file } = setup();
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', xml), '--rust-tests-failed']);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: failing' });
    });
  }

  // The counts are read from the root element only: markup before it could
  // hold a <testsuites> of its own, here one with no failures in front of
  // a root with three, so anything but the <?xml ...?> declaration fails.
  const DECOY = '<testsuites tests="12" failures="0" errors="0" skipped="0">';
  const ROOT = '<testsuites name="t" tests="12" failures="3" errors="0" skipped="1"><testsuite name="s"/></testsuites>\n';
  for (const [form, before] of [
    ['a comment', `<!-- ${DECOY} -->\n`],
    ['a DOCTYPE', `<!DOCTYPE testsuites [ <!ENTITY decoy '${DECOY}'> ]>\n`],
    ['a processing instruction', `<?decoy ${DECOY}?>\n`],
  ]) {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n${before}${ROOT}`;
    test(`rejects a JUnit report with ${form} before the root element`, () => {
      const { remote, sha, work, file } = setup();
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', xml)]);
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /cannot parse the <testsuites> element in .*junit\.xml/);
      assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
    });

    test(`a JUnit report with ${form} before the root element from a failed job publishes a red failing badge`, () => {
      const { remote, sha, work, file } = setup();
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', xml), '--rust-tests-failed']);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: failing' });
    });
  }

  test('reads the root element after a multi-line XML declaration and blank lines', () => {
    const { remote, sha, work, file } = setup();
    const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', `<?xml version='1.0'\n  encoding='UTF-8'?>\n\n  ${ROOT}`)]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 3 failed' });
  });

  for (const value of ['99999999999999999999', 'abc']) {
    test(`a JUnit count failures="${value}" from a failed job publishes a red failing badge`, () => {
      const { remote, sha, work, file } = setup();
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', junit(`tests="12" failures="${value}" errors="0" skipped="0"`)), '--rust-tests-failed']);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: failing' });
    });
  }

  // Vitest counts were already checked strictly: none of these reads as a
  // count, so a job that did not fail gets no badge and an error.
  for (const [field, literal] of [
    ['numPassedTests', '-1'], ['numPassedTests', '1.5'], ['numPassedTests', '"7"'], ['numPassedTests', 'null'], ['numPassedTests', '1e9'],
    ['numFailedTests', '-1'], ['numFailedTests', '"0"'],
  ]) {
    test(`rejects a Vitest ${field} of ${literal}`, () => {
      const { remote, sha, work, file } = setup();
      const counts = { numPassedTests: '7', numFailedTests: '0', [field]: literal };
      const r = publish(work[0], ['main', sha, '--ts-results', file('results.json', `{"success":true,"numPassedTests":${counts.numPassedTests},"numFailedTests":${counts.numFailedTests}}`)]);
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /cannot read typescript test results/);
      assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
    });
  }
});

// A failed nextest run keeps the test output in its JUnit report, so the
// report of a red run can be many megabytes. Reading its counts must take
// seconds with every awk the publish job might run, or the job's timeout
// expires before the red badge is published. A run still going after
// LIMIT_MS is killed with its process group, and the test fails.
describe('large JUnit reports', () => {
  const LIMIT_MS = 30_000;

  // Virtual memory for awk in the tests that limit it: far less than the
  // 72 MiB line of BIG_REPORT.
  const AWK_MEMORY_KIB = 45 * 1024;

  // The awk on PATH, and mawk, gawk and busybox awk wherever installed:
  // one entry per distinct binary, each run as the only `awk` on PATH,
  // as is (PATH) and limited to AWK_MEMORY_KIB (LIMITED_PATH, LIMITED_AWK).
  const AWKS = (() => {
    const dirs = (ENV.PATH ?? '').split(':').filter(Boolean);
    const which = (name) => {
      for (const dir of dirs) {
        try {
          accessSync(join(dir, name), constants.X_OK);
          if (statSync(join(dir, name)).isFile()) return join(dir, name);
        } catch {
          // Not in this directory.
        }
      }
      return null;
    };
    const found = new Map();
    for (const [name, argv] of [['awk', []], ['mawk', []], ['gawk', []], ['busybox', ['awk']]]) {
      const path = which(name);
      if (!path || spawnSync(path, [...argv, 'BEGIN { exit 0 }']).status !== 0) continue;
      const key = [realpathSync(path), ...argv].join(' ');
      if (found.has(key)) continue;
      const bin = join(TOP, `awk-${found.size}`);
      const limited = join(TOP, `awk-${found.size}-limited`);
      mkdirSync(bin);
      mkdirSync(limited);
      assert.ok(!path.includes("'"), path);
      writeFileSync(join(bin, 'awk'), `#!/bin/sh\nexec '${path}' ${argv.join(' ')} "$@"\n`);
      writeFileSync(join(limited, 'awk'), `#!/bin/sh\nulimit -v ${AWK_MEMORY_KIB} || exit 125\nexec '${path}' ${argv.join(' ')} "$@"\n`);
      chmodSync(join(bin, 'awk'), 0o755);
      chmodSync(join(limited, 'awk'), 0o755);
      found.set(key, {
        label: name === 'awk' ? `awk on PATH (${basename(realpathSync(path))})` : name,
        PATH: `${bin}:${ENV.PATH}`,
        LIMITED_PATH: `${limited}:${ENV.PATH}`,
        LIMITED_AWK: join(limited, 'awk'),
      });
    }
    return [...found.values()];
  })();

  function publishWithin(cwd, args, env) {
    return new Promise((resolve) => {
      const child = spawn('sh', [SCRIPT, ...args], { cwd, env: { ...ENV, ...env }, detached: true });
      children.add(child);
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      const timer = setTimeout(() => {
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {
          // Already gone.
        }
      }, LIMIT_MS);
      child.on('close', (status, signal) => {
        clearTimeout(timer);
        children.delete(child);
        resolve({ status, signal, stdout, stderr });
      });
    });
  }

  // About 8 MB of test output, one line per test case, as a failed run
  // leaves it.
  const BODY = Array.from({ length: 80_000 }, (_, i) => `<testcase classname="crate::module" name="test_${i}"><system-out>output line ${i} of a failed run</system-out></testcase>\n`).join('');
  const REPORTS = {
    'a large report': `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="nextest-run" tests="12" failures="3" errors="0" skipped="1">\n<testsuite name="s">\n${BODY}</testsuite>\n</testsuites>\n`,
    'a large comment before the root element': `<?xml version="1.0"?>\n<!--\n${BODY}-->\n<testsuites name="t" tests="12" failures="0" errors="0" skipped="0"><testsuite name="s"/></testsuites>\n`,
    'a large DOCTYPE before the root element': `<?xml version="1.0"?>\n<!DOCTYPE testsuites [\n${BODY.replace(/^.*?test_(\d+).*$/gm, '<!ENTITY e$1 "output line $1 of a failed run">')}]>\n<testsuites name="t" tests="12" failures="0" errors="0" skipped="0"><testsuite name="s"/></testsuites>\n`,
  };

  // A compact report can hold the root element and a failed run's whole
  // output on one line, which awk would read as one record. Written in
  // 1 MiB pieces, once, for every test that reads it.
  let bigReport;
  function BIG_REPORT() {
    if (!bigReport) {
      bigReport = join(TOP, 'big-junit.xml');
      const fd = openSync(bigReport, 'w');
      writeSync(fd, '<?xml version="1.0" encoding="UTF-8"?><testsuites name="nextest-run" tests="12" failures="3" errors="0" skipped="1"><testsuite name="s"><testcase name="t"><failure>');
      const piece = Buffer.alloc(1 << 20, 'output of a failed run ');
      for (let i = 0; i < 72; i++) writeSync(fd, piece);
      writeSync(fd, '</failure></testcase></testsuite></testsuites>\n');
      closeSync(fd);
    }
    return bigReport;
  }

  // A UTF-8 locale, as a job's LANG or LC_ALL may name one: the first that
  // `locale -a` lists, or C.UTF-8 (built into glibc from 2.35 on) when it
  // lists none or cannot run.
  const UTF8_LOCALE = (() => {
    const listed = (spawnSync('locale', ['-a'], { encoding: 'utf8' }).stdout ?? '').split('\n');
    return listed.find((l) => /^C\.utf-?8$/i.test(l)) ?? listed.find((l) => /\.utf-?8$/i.test(l)) ?? 'C.UTF-8';
  })();
  // UTF8_LOCALE must be one this system has: in a locale it does not have,
  // the tests that use it would pass as in the C locale, whatever the script
  // sets.
  function assertUtf8Locale() {
    const r = spawnSync('locale', ['charmap'], { encoding: 'utf8', env: { ...ENV, LC_ALL: UTF8_LOCALE } });
    assert.equal(r.status, 0, `locale charmap: ${r.error ?? r.stderr}`);
    assert.equal(r.stdout.trim(), 'UTF-8', `LC_ALL=${UTF8_LOCALE} is a UTF-8 locale here (locale charmap: ${r.stdout.trim()}; ${r.stderr.trim()})`);
  }

  // Reports with bytes outside ASCII in their first 64 KiB, each with the
  // counts of ROOT_COUNTS. In a UTF-8 locale gawk warns about a character
  // that is not valid UTF-8 there ("Invalid multibyte data detected"), and
  // does not match one with `[^?]`.
  const ROOT_COUNTS = 'tests="12" failures="3" errors="0" skipped="1"';
  const NON_ASCII_REPORTS = (() => {
    const start = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="café ✓" ${ROOT_COUNTS}>\n<testsuite name="s"><testcase name="t"><failure>`);
    const end = Buffer.from(' output</failure></testcase></testsuite></testsuites>\n');
    return {
      // Valid UTF-8, with a three-byte character from byte 65535 on, so the
      // 64 KiB that are read end inside it.
      'a UTF-8 report cut inside a character at 64 KiB': Buffer.concat([start, Buffer.alloc(65535 - start.length, 'a'), Buffer.from('✓✓'), end]),
      'a byte that is not UTF-8 in the XML declaration': Buffer.concat([Buffer.from('<?xml version="1.0" encoding="'), Buffer.from([0xff]), Buffer.from(`"?>\n<testsuites ${ROOT_COUNTS}><testsuite name="s"/></testsuites>\n`)]),
    };
  })();

  test('finds an awk to run', () => {
    assert.ok(AWKS.length > 0);
    assert.ok(Buffer.byteLength(REPORTS['a large report']) > 8_000_000);
    const cut = NON_ASCII_REPORTS['a UTF-8 report cut inside a character at 64 KiB'];
    assert.deepEqual([...cut.subarray(65535, 65538)], [0xe2, 0x9c, 0x93], 'the 64 KiB end after the first byte of ✓');
  });

  for (const awk of AWKS) {
    const { label, PATH } = awk;
    test(`a large report with failures publishes a red badge in time (${label})`, async () => {
      const { remote, sha, work, file } = setup();
      const r = await publishWithin(work[0], ['main', sha, '--rust-junit', file('junit.xml', REPORTS['a large report'])], { PATH });
      assert.equal(r.signal, null, `killed after ${LIMIT_MS} ms`);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 3 failed' });
    });

    test(`a 72 MiB report on one line publishes a red badge in time with awk limited to 45 MiB (${label})`, async () => {
      const big = BIG_REPORT();
      assert.ok(statSync(big).size > 72 * (1 << 20));
      const r0 = spawnSync(awk.LIMITED_AWK, ['{ n += length($0) } END { print n }', big], { env: ENV, encoding: 'utf8' });
      assert.ok(r0.status !== 0 && r0.status !== 125, `the limit holds: awk cannot read the whole line (status ${r0.status}, ${r0.stdout}${r0.stderr})`);
      const { remote, sha, work } = setup();
      const r = await publishWithin(work[0], ['main', sha, '--rust-junit', big], { PATH: awk.LIMITED_PATH });
      assert.equal(r.signal, null, `killed after ${LIMIT_MS} ms`);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 3 failed' });
    });

    for (const what of ['a large comment before the root element', 'a large DOCTYPE before the root element']) {
      test(`${what} fails closed in time (${label})`, async () => {
        const { remote, sha, work, file } = setup();
        const r = await publishWithin(work[0], ['main', sha, '--rust-junit', file('junit.xml', REPORTS[what])], { PATH });
        assert.equal(r.signal, null, `killed after ${LIMIT_MS} ms`);
        assert.equal(r.status, 1, r.stdout + r.stderr);
        assert.match(r.stderr, /cannot parse the <testsuites> element in .*junit\.xml/);
        assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1, 'nothing published');
      });
    }

    // The job's locale must not change how the report is read: awk reads
    // bytes, whatever LANG and LC_ALL say. A runner usually sets LANG
    // alone, so LC_ALL=C must reach awk exported, not only set in the shell.
    for (const [what, report] of Object.entries(NON_ASCII_REPORTS)) {
      for (const [how, locale] of [
        ['LANG and LC_ALL', { LANG: UTF8_LOCALE, LC_ALL: UTF8_LOCALE }],
        ['LANG alone', { LANG: UTF8_LOCALE, LC_ALL: undefined, LC_CTYPE: undefined }],
      ]) {
        test(`${what} is read as in the C locale, without an awk warning, with ${how} ${UTF8_LOCALE} (${label})`, async () => {
          assertUtf8Locale();
          const { remote, sha, work, root } = setup();
          const path = join(root, 'junit.xml');
          writeFileSync(path, report);
          const r = await publishWithin(work[0], ['main', sha, '--rust-junit', path], { PATH, ...locale });
          assert.equal(r.signal, null, `killed after ${LIMIT_MS} ms`);
          assert.equal(r.status, 0, r.stdout + r.stderr);
          assert.doesNotMatch(r.stderr, /^[a-z]*awk:|multibyte/im);
          assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 3 failed' });
        });
      }
    }
  }

  // Only the first 64 KiB are read: a start tag that ends within them is
  // read, one that does not is not guessed at.
  for (const [length, status] of [[60_000, 0], [70_000, 1]]) {
    test(`a ${length}-character start tag ${status === 0 ? 'is read' : 'fails closed'}`, () => {
      const { remote, sha, work, file } = setup();
      const xml = `<?xml version="1.0"?>\n<testsuites name="${'x'.repeat(length)}" tests="12" failures="3" errors="0" skipped="1"><testsuite name="s"/></testsuites>\n`;
      const r = publish(work[0], ['main', sha, '--rust-junit', file('junit.xml', xml)]);
      assert.equal(r.status, status, r.stdout + r.stderr);
      if (status === 0) {
        assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 3 failed' });
      } else {
        assert.match(r.stderr, /cannot parse the <testsuites> element in .*junit\.xml/);
      }
    });
  }
});

// A report that cannot be used must not hold back the other badges: a
// failure among them would otherwise leave a stale green badge on main.
describe('an unusable report fails after the other badges are published', () => {
  const failedJunit = '<testsuites name="t" tests="5" failures="2" errors="0" skipped="0"><testsuite name="s"/></testsuites>';
  const failedTs = { success: false, numPassedTests: 6, numFailedTests: 1 };
  // [what, the unusable input, its badge, the badge that fails meanwhile]
  const CASES = [
    ['a Rust coverage percentage above 100', (file) => ['--rust-coverage', file('bad.json', rustReportText('150')), '--rust-coverage-result', 'success'],
      'rust-coverage', 'typescript-tests', /'150' .* is not a number from 0 to 100/],
    ['a TypeScript coverage percentage written as a string', (file) => ['--ts-coverage', file('bad.json', tsSummaryText('"85"')), '--ts-coverage-result', 'success'],
      'typescript-coverage', 'rust-tests', /cannot read line coverage percentage/],
    ['a negative Vitest count', (file) => ['--ts-results', file('bad.json', '{"success":true,"numPassedTests":-1,"numFailedTests":0}')],
      'typescript-tests', 'rust-tests', /cannot read typescript test results/],
    ['a malformed JUnit count', (file) => ['--rust-junit', file('bad.xml', '<testsuites name="t" tests="5" failures="0" errors="0" skipped="x"><testsuite name="s"/></testsuites>')],
      'rust-tests', 'typescript-tests', /skipped="x" .* is not a count/],
  ];
  const green = (file) => [
    '--rust-coverage', file('rust.json', rustReport(90)), '--rust-coverage-result', 'success',
    '--rust-junit', file('junit.xml', '<testsuites name="t" tests="5" failures="0" errors="0" skipped="0"><testsuite name="s"/></testsuites>'),
    '--ts-coverage', file('ts.json', tsSummary(90)), '--ts-coverage-result', 'success',
    '--ts-results', file('results.json', JSON.stringify({ success: true, numPassedTests: 7, numFailedTests: 0 })),
  ];
  const failing = (file, name) => (name === 'rust-tests'
    ? ['--rust-junit', file('failed.xml', failedJunit), '--rust-tests-failed']
    : ['--ts-results', file('failed.json', JSON.stringify(failedTs)), '--ts-tests-failed']);

  for (const [what, unusable, itsBadge, other, message] of CASES) {
    test(what, () => {
      const { remote, sha, work, file } = setup();
      assert.equal(publish(work[0], ['main', sha, ...green(file)]).status, 0);
      const before = badge(remote, `main/${itsBadge}.svg`);
      assert.equal(before.color, BRIGHTGREEN);
      const r = publish(work[0], ['main', sha, ...unusable(file), ...failing(file, other)]);
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stderr, message);
      assert.match(r.stdout, /published main/);
      assert.equal(badge(remote, `main/${other}.svg`).color, RED, `${other} went red`);
      assert.deepEqual(badge(remote, `main/${itsBadge}.svg`), before, `${itsBadge} is left as it was`);
      assertNoScriptLeftovers();
    });
  }

  test('unchanged badges still fail', () => {
    const { remote, sha, work, file } = setup();
    const args = ['main', sha, ...failing(file, 'rust-tests'), '--ts-results', file('bad.json', '{"success":true,"numPassedTests":-1,"numFailedTests":0}')];
    assert.equal(publish(work[0], args).status, 1);
    const tip = git(remote, 'rev-parse', 'badges');
    const r = publish(work[0], args);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /badges unchanged/);
    assert.equal(git(remote, 'rev-parse', 'badges'), tip);
  });
});

describe('the CI job (publish-badges-ci.sh)', () => {
  // Lays out the reports where the publish-badges job downloads them, in
  // the clone the script runs in, and runs it with the given job results.
  const run = (cwd, sha, results, reports = {}) => {
    const put = (path, text) => {
      mkdirSync(dirname(join(cwd, path)), { recursive: true });
      writeFileSync(join(cwd, path), text);
    };
    if (reports.rustCoverage) put('target/coverage/coverage.json', JSON.stringify(rustReport(reports.rustCoverage)));
    if (reports.junit) put('target/nextest-artifacts/service-nextest-junit-1/junit.xml', reports.junit);
    if (reports.tsCoverage) put('clients/typescript/coverage/coverage-summary.json', JSON.stringify(tsSummary(reports.tsCoverage)));
    if (reports.tsResults) put('clients/typescript/coverage/test-results.json', JSON.stringify(reports.tsResults));
    for (const [path, text] of Object.entries(reports.files ?? {})) put(path, text);
    return spawnSync('sh', [CI_SCRIPT], {
      cwd,
      encoding: 'utf8',
      timeout: 60_000,
      killSignal: 'SIGKILL',
      env: {
        ...ENV,
        GITHUB_REF_NAME: 'main',
        GITHUB_SHA: sha,
        RUST_COVERAGE_OK: '',
        RUST_COVERAGE_RESULT: 'skipped',
        RUST_TESTS_RESULT: 'skipped',
        TS_OK: '',
        TS_RESULT: 'skipped',
        ...results,
      },
    });
  };
  const failedJunit = '<testsuites name="t" tests="5" failures="2" errors="0" skipped="0"><testsuite name="s"/></testsuites>';
  const passedJunit = '<testsuites name="t" tests="5" failures="0" errors="0" skipped="0"><testsuite name="s"/></testsuites>';
  const published = (remote, path) => spawnSync('git', ['cat-file', '-e', `badges:${path}`], { cwd: remote, env: ENV }).status === 0;

  test('a coverage job that succeeded without a report still lets failed tests go red, then fails', () => {
    const { remote, sha, work } = setup();
    const r = run(work[0], sha, { RUST_COVERAGE_RESULT: 'success', RUST_TESTS_RESULT: 'failure' }, { junit: failedJunit });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /rust-coverage succeeded without a complete coverage report/);
    assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 2 failed' });
    assert.equal(published(remote, 'main/rust-coverage.svg'), false);
    assertNoScriptLeftovers();
  });

  test('a missing TypeScript report or JUnit file fails after the other badges are published', () => {
    const { remote, sha, work } = setup();
    const r = run(work[0], sha, { RUST_COVERAGE_OK: 'true', RUST_COVERAGE_RESULT: 'success', RUST_TESTS_RESULT: 'success', TS_RESULT: 'success' }, { rustCoverage: 97.7 });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /service-nextest succeeded without a junit\.xml/);
    assert.match(r.stderr, /typescript-coverage succeeded without a complete coverage report/);
    assert.equal(badge(remote, 'main/rust-coverage.svg').title, 'rust coverage: 97.7%');
  });

  // A succeeded job whose report is present and passes the job's own
  // completeness check, but holds a count that cannot be used.
  test('an unusable TypeScript report fails after a red Rust tests badge is published', () => {
    const { remote, sha, work } = setup();
    const r = run(
      work[0], sha,
      { RUST_TESTS_RESULT: 'failure', TS_OK: 'true', TS_RESULT: 'success' },
      { junit: failedJunit, tsCoverage: 90, tsResults: { success: true, numPassedTests: -1, numFailedTests: 0 } },
    );
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /cannot read typescript test results/);
    assert.deepEqual(badge(remote, 'main/rust-tests.svg'), { color: RED, title: 'rust tests: 2 failed' });
    assert.equal(badge(remote, 'main/typescript-coverage.svg').title, 'typescript coverage: 90.0%');
    assert.equal(published(remote, 'main/typescript-tests.svg'), false);
    assertNoScriptLeftovers();
  });

  test('an unusable coverage report from a failed gate publishes a red failing badge', () => {
    const { remote, sha, work } = setup();
    const r = run(
      work[0], sha,
      { TS_OK: 'true', TS_RESULT: 'failure' },
      { tsCoverage: 150, tsResults: { success: true, numPassedTests: 7, numFailedTests: 0 } },
    );
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(badge(remote, 'main/typescript-coverage.svg'), { color: RED, title: 'typescript coverage: failing' });
    assert.equal(badge(remote, 'main/typescript-tests.svg').title, 'typescript tests: 7 passed');
  });

  test('with nothing known it publishes nothing and still fails', () => {
    const { remote, sha, work } = setup();
    const r = run(work[0], sha, { RUST_COVERAGE_RESULT: 'success' });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /no badge to publish/);
    assert.equal(spawnSync('git', ['rev-parse', '--verify', '-q', 'badges'], { cwd: remote, env: ENV }).status, 1);
  });

  test('all reports present publishes the four badges and succeeds', () => {
    const { remote, sha, work } = setup();
    const r = run(
      work[0], sha,
      { RUST_COVERAGE_OK: 'true', RUST_COVERAGE_RESULT: 'success', RUST_TESTS_RESULT: 'success', TS_OK: 'true', TS_RESULT: 'success' },
      { rustCoverage: 97.7, junit: passedJunit, tsCoverage: 100, tsResults: { success: true, numPassedTests: 7, numFailedTests: 0 } },
    );
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(badge(remote, 'main/rust-tests.svg').title, 'rust tests: 5 passed');
    assert.equal(badge(remote, 'main/typescript-tests.svg').title, 'typescript tests: 7 passed');
    assert.equal(badge(remote, 'main/typescript-coverage.svg').title, 'typescript coverage: 100.0%');
  });

  // The Rust tests badge must count the report of service-nextest's first
  // run (target/nextest/ci/junit.xml), laid out as the job uploads it and
  // as publish-badges downloads it with `pattern:`: download-artifact
  // extracts one matching artifact directly into `path` and several into a
  // directory each (ci.yml); upload-artifact keeps each file's path below
  // the deepest directory common to the upload's paths. Both are read from
  // ci.yml, so an upload that nests the report fails (the two-file upload
  // of ci/junit.xml and ci-root/junit.xml once did: on a first attempt the
  // script found both reports and took ci/junit.xml only because `sort -V`
  // orders it after ci-root/junit.xml; after a re-run it found none).
  const CI_YML = readFileSync(join(dirname(SCRIPT), '..', '..', '.github', 'workflows', 'ci.yml'), 'utf8');
  const jobBody = (ci, job) => ci.match(new RegExp(`^  ${job}:\\n((?:(?: {4}.*)?\\n)*)`, 'm'))?.[1] ?? '';
  // The upload steps of a job: [{ name, paths }].
  const uploadsOf = (body) =>
    body
      .split(/^(?= {6}- )/m)
      .filter((step) => /^ {8}uses: actions\/upload-artifact@/m.test(step))
      .map((step) => {
        const block = /^ {10}path: \|\n((?: {12}.*\n)+)/m.exec(step);
        return {
          name: /^ {10}name: (.+)$/m.exec(step)[1],
          paths: block ? block[1].split('\n').filter(Boolean).map((l) => l.trim()) : [/^ {10}path: (.+)$/m.exec(step)[1]],
        };
      });
  const underCommonDir = (paths) => {
    const dirs = paths.map((p) => p.split('/').slice(0, -1));
    let common = 0;
    while (dirs.every((d) => common < d.length && d[common] === dirs[0][common])) common++;
    return paths.map((p) => p.split('/').slice(common).join('/'));
  };
  // A download-artifact pattern (`*` only, as used here) as a RegExp.
  const globOf = (pattern) => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*')}$`);
  // The files publish-badges-ci.sh finds after the download, for the given
  // attempts of service-nextest; each source report counts `count(path,
  // attempt)` tests.
  const downloaded = (ci, attempts, count) => {
    const download = jobBody(ci, 'publish-badges').match(/^ {10}pattern: (.+)\n {10}path: (.+)$/m);
    assert.ok(download, 'publish-badges downloads no pattern');
    const [, pattern, into] = download;
    const glob = globOf(pattern);
    const artifacts = attempts.flatMap((attempt) =>
      uploadsOf(jobBody(ci, 'service-nextest'))
        .map(({ name, paths }) => ({ name: name.replace(/\$\{\{\s*github\.run_attempt\s*\}\}/g, String(attempt)), paths, attempt }))
        .filter(({ name }) => glob.test(name)),
    );
    const files = {};
    for (const { name, paths, attempt } of artifacts) {
      const dir = artifacts.length === 1 ? into : `${into}/${name}`;
      underCommonDir(paths).forEach((rel, i) => {
        files[`${dir}/${rel}`] = `<testsuites name="t" tests="${count(paths[i], attempt)}" failures="0" errors="0" skipped="0"><testsuite name="s"/></testsuites>`;
      });
    }
    return files;
  };
  // The first run's report counts 100 + attempt tests, any other 54.
  const count = (path, attempt) => (path === 'target/nextest/ci/junit.xml' ? 100 + attempt : 54);
  const rustTestsBadge = (ci, attempts) => {
    const { remote, sha, work } = setup();
    const r = run(work[0], sha, { RUST_TESTS_RESULT: 'success' }, { files: downloaded(ci, attempts, count) });
    return { r, title: r.status === 0 ? badge(remote, 'main/rust-tests.svg').title : null };
  };

  test('service-nextest-junit-N holds junit.xml at its top; the root run\'s artifact never matches the download pattern', () => {
    const uploads = uploadsOf(jobBody(CI_YML, 'service-nextest'));
    const junit = uploads.find(({ name }) => name === 'service-nextest-junit-${{ github.run_attempt }}');
    assert.ok(junit, 'no service-nextest-junit upload');
    assert.deepEqual(underCommonDir(junit.paths), ['junit.xml']);
    assert.deepEqual(junit.paths, ['target/nextest/ci/junit.xml']);
    const rootRun = uploads.find(({ paths }) => paths.includes('target/nextest/ci-root/junit.xml'));
    assert.ok(rootRun, 'the root run is uploaded');
    assert.deepEqual(underCommonDir(rootRun.paths), ['junit.xml']);
    const glob = globOf(jobBody(CI_YML, 'publish-badges').match(/^ {10}pattern: (.+)$/m)[1]);
    for (const n of [1, 2, 9, 10, 123]) {
      assert.ok(glob.test(`service-nextest-junit-${n}`), `service-nextest-junit-${n}`);
      assert.ok(!glob.test(rootRun.name.replace(/\$\{\{\s*github\.run_attempt\s*\}\}/g, String(n))), `${rootRun.name} attempt ${n}`);
    }
  });

  test("the Rust tests badge counts service-nextest's first run, after the first attempt and after re-runs", () => {
    // [2]: only attempt 2's artifact downloaded (one match, extracted
    // flat); [1, 2] and [1, 2, 3]: one directory each, the latest counts.
    for (const attempts of [[1], [2], [1, 2], [1, 2, 3]]) {
      const { r, title } = rustTestsBadge(CI_YML, attempts);
      assert.equal(r.status, 0, r.stdout + r.stderr);
      assert.equal(title, `rust tests: ${100 + attempts.at(-1)} passed`, String(attempts));
    }
  });

  test('a service-nextest artifact that nests the report fails the check above', () => {
    const nested = CI_YML.replace(
      '          name: service-nextest-junit-${{ github.run_attempt }}\n          path: target/nextest/ci/junit.xml\n',
      '          name: service-nextest-junit-${{ github.run_attempt }}\n          path: |\n            target/nextest/ci/junit.xml\n            target/nextest/ci-root/junit.xml\n',
    );
    assert.notEqual(nested, CI_YML);
    // First attempt: both reports are found, ci/ wins on sort order alone.
    assert.deepEqual(Object.keys(downloaded(nested, [1], count)).sort(), ['target/nextest-artifacts/ci-root/junit.xml', 'target/nextest-artifacts/ci/junit.xml']);
    // After a re-run: no report found, so the job fails.
    const rerun = rustTestsBadge(nested, [1, 2]);
    assert.equal(rerun.r.status, 1);
    assert.match(rerun.r.stderr, /service-nextest succeeded without a junit\.xml/);
  });

  test('cancelled jobs publish red failing badges', () => {
    const { remote, sha, work } = setup();
    const r = run(work[0], sha, { RUST_COVERAGE_RESULT: 'cancelled', RUST_TESTS_RESULT: 'cancelled', TS_RESULT: 'cancelled' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    for (const name of ['rust-coverage', 'rust-tests', 'typescript-coverage', 'typescript-tests']) {
      assert.equal(badge(remote, `main/${name}.svg`).color, RED, name);
    }
  });
});

// The Rust coverage badge shows the figure of the `rust-coverage` job, and
// the Rust tests badge counts the tests of `service-nextest`, PostgreSQL
// ones included. The coverage job must measure those PostgreSQL tests too:
// its permissions, SKYOAUTH_IT_DATABASE_URL, postgres service and check step
// are copies of service-nextest's, and its coverage step passes
// `-- --include-ignored` to the test binaries. That argument cannot live in
// the `coverage` alias: cargo appends the step's options after the alias,
// so with a `--` in the alias they would reach the test binaries.
describe('the rust-coverage job measures the PostgreSQL tests', () => {
  const REPO = join(dirname(SCRIPT), '..', '..');
  const CI = readFileSync(join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
  const CONFIG = readFileSync(join(REPO, '.cargo', 'config.toml'), 'utf8');
  // A job's body: the lines after `  <job>:` indented by four or more.
  const jobOf = (ci, job) => ci.match(new RegExp(`^  ${job}:\\n((?:(?: {4}.*)?\\n)*)`, 'm'))?.[1] ?? '';
  // A job-level key with its nested lines.
  const keyOf = (body, key) => body.match(new RegExp(`^ {4}${key}:\\n(?:(?: {6}.*)?\\n)*`, 'm'))?.[0] ?? '';
  // A step by name, with the lines indented below its `- name:`.
  const stepOf = (body, name) => body.match(new RegExp(`^ {6}- name: ${name}\\n(?: {8}.*\\n)*`, 'm'))?.[0] ?? '';
  const dbUrlOf = (body) => keyOf(body, 'env').match(/^ {6}SKYOAUTH_IT_DATABASE_URL: .*$/m)?.[0] ?? '';

  const problems = (ci, config) => {
    const out = [];
    const cov = jobOf(ci, 'rust-coverage');
    const nx = jobOf(ci, 'service-nextest');
    if (!cov || !nx) return ['rust-coverage or service-nextest job not found'];
    if (keyOf(cov, 'permissions') !== '    permissions:\n      contents: read\n') out.push('permissions are not exactly contents: read');
    if (!dbUrlOf(nx)) out.push('service-nextest sets no SKYOAUTH_IT_DATABASE_URL');
    else if (dbUrlOf(cov) !== dbUrlOf(nx)) out.push('SKYOAUTH_IT_DATABASE_URL differs from service-nextest');
    const services = keyOf(cov, 'services');
    if (!/^ {6}postgres:\n/m.test(services) || services !== keyOf(nx, 'services')) out.push('services differ from service-nextest');
    const CHECK = 'Check PostgreSQL is reachable';
    const COVER = 'Check coverage threshold';
    const check = stepOf(cov, CHECK);
    if (!check || check !== stepOf(nx, CHECK)) out.push(`step "${CHECK}" differs from service-nextest`);
    else if (cov.indexOf(check) > cov.indexOf(stepOf(cov, COVER))) out.push(`step "${CHECK}" runs after the coverage step`);
    const cmd = stepOf(cov, COVER).match(/^ +(cargo coverage .*?)(?: 2>&1)?(?: \\)?$/m)?.[1];
    if (!cmd) out.push(`step "${COVER}" runs no cargo coverage`);
    else {
      const args = cmd.split(/\s+/);
      const sep = args.indexOf('--');
      if (sep < 0 || args.lastIndexOf('--') !== sep || args.slice(sep + 1).join(' ') !== '--include-ignored') out.push(`step "${COVER}" does not end in "-- --include-ignored": ${cmd}`);
    }
    const alias = config.match(/^coverage = "(.*)"$/m)?.[1].replace(/\\\\/g, '\\');
    if (!alias) out.push('no coverage alias in .cargo/config.toml');
    else {
      if (alias.split(/\s+/).includes('--')) out.push('the coverage alias contains "--"');
      const regex = alias.match(/--ignore-filename-regex (\S+)/)?.[1];
      const env = keyOf(cov, 'env').match(/^ {6}COVERAGE_IGNORE_REGEX: '(.*)'$/m)?.[1];
      if (!regex || regex !== env) out.push(`COVERAGE_IGNORE_REGEX ${env} is not the alias's --ignore-filename-regex ${regex}`);
    }
    return out;
  };

  // Applies `f` to the rust-coverage job's body only. Replacements are
  // functions so that `$` in the shell steps is not a replacement pattern.
  const inCoverageJob = (f) => {
    const body = jobOf(CI, 'rust-coverage');
    return CI.replace(body, () => f(body));
  };

  test('ci.yml and the coverage alias agree', () => {
    assert.deepEqual(problems(CI, CONFIG), []);
  });

  test('each way of dropping the database or the ignored tests is caught', () => {
    const cases = [
      [inCoverageJob((b) => b.replace(keyOf(b, 'services'), () => '')), CONFIG, /services differ/],
      [inCoverageJob((b) => b.replace(/^ {6}SKYOAUTH_IT_DATABASE_URL: .*\n/m, '')), CONFIG, /SKYOAUTH_IT_DATABASE_URL differs/],
      [inCoverageJob((b) => b.replace('localhost:5432', 'localhost:5433')), CONFIG, /SKYOAUTH_IT_DATABASE_URL differs/],
      [inCoverageJob((b) => b.replace('--health-retries 12', '--health-retries 1')), CONFIG, /services differ/],
      [inCoverageJob((b) => b.replace(stepOf(b, 'Check PostgreSQL is reachable'), () => '')), CONFIG, /Check PostgreSQL is reachable" differs/],
      [inCoverageJob((b) => b.replace(' -- --include-ignored', '')), CONFIG, /does not end in "-- --include-ignored"/],
      [inCoverageJob((b) => b.replace(' -- --include-ignored', ' -- --ignored')), CONFIG, /does not end in "-- --include-ignored"/],
      [inCoverageJob((b) => b.replace(' -- --include-ignored', ' -- --include-ignored --exact')), CONFIG, /does not end in "-- --include-ignored"/],
      [inCoverageJob((b) => b.replace('      contents: read\n', '      contents: write\n')), CONFIG, /permissions/],
      [inCoverageJob((b) => b.replace(keyOf(b, 'permissions'), () => '')), CONFIG, /permissions/],
      [CI, CONFIG.replace('--fail-under-lines 85"', '--fail-under-lines 85 -- --include-ignored"'), /alias contains "--"/],
      [CI, CONFIG.replace('main\\\\.rs', 'main\\\\.rs|bin/'), /COVERAGE_IGNORE_REGEX/],
    ];
    for (const [ci, config, want] of cases) {
      assert.notEqual(ci + config, CI + CONFIG, `mutant did not apply: ${want}`);
      assert.match(problems(ci, config).join('\n'), want);
    }
  });
});
