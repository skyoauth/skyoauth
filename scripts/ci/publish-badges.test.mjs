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
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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

  test('cancelled jobs publish red failing badges', () => {
    const { remote, sha, work } = setup();
    const r = run(work[0], sha, { RUST_COVERAGE_RESULT: 'cancelled', RUST_TESTS_RESULT: 'cancelled', TS_RESULT: 'cancelled' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    for (const name of ['rust-coverage', 'rust-tests', 'typescript-coverage', 'typescript-tests']) {
      assert.equal(badge(remote, `main/${name}.svg`).color, RED, name);
    }
  });
});
