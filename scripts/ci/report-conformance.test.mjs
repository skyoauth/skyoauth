// Self-test for report-conformance.mjs:
//   node --test scripts/ci/report-conformance.test.mjs
//
// Each case copies the three specs and the two registry files into a
// temporary root, implements a few stages there, writes throwaway artifact
// directories (DIR/<run_id>/<artifact>/{junit.xml,leg}) and runs the reporter.
// Waiver cases build a throwaway git repository with a local
// refs/remotes/origin/main; nothing touches the network. The judging date is
// always passed with --today, so no case depends on the clock.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { parse as parseStrict } from 'smol-toml';

import { DESIGN, LAYOUT, parseEnvironments, SCENARIOS, sha256, stageStamp, SUBCASES, TASKS } from './gen-conformance-registry.mjs';
import { assertGitImmune, GIT_ENV, normaliseRegistry } from './registry-fixtures.mjs';
import { checkoutHead, clean, code, exitStatus, InputError, JOB_RUNNER, judge, MAX_BYTES, MAX_DEPTH, MAX_LIST, MAX_TEXT, NOT_CONFORMANCE, parseXml, readJUnit, renderMarkdown, run, runnerOf, TEST_JOBS, testId, testInfo, text, worst } from './report-conformance.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'report-conformance.mjs');
const REPO = join(dirname(SCRIPT), '..', '..');
const FILES = [TASKS, DESIGN, LAYOUT, SCENARIOS, SUBCASES];
const TODAY = '2026-11-19';
const SHA = 'a'.repeat(40);

const dirs = [];
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
const tmp = (prefix) => {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
};
const repoText = (rel) => readFileSync(join(REPO, rel), 'utf8');
const write = (path, text) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
};

// ---------------------------------------------------------------------------
// Registry fixtures

// The registry files with every stage planned and no gate passed (the
// registry self-tests' helper), so implementing a real stage or passing a gate
// does not change what these tests see.
const registryText = (rel) => ([SCENARIOS, SUBCASES].includes(rel) ? normaliseRegistry(repoText(rel)) : repoText(rel));
const REG = parseStrict(registryText(SCENARIOS));
const SUB = parseStrict(registryText(SUBCASES));
const matrix = (id) => [...REG.scenario, ...SUB.subcase].find((e) => e.id === id).matrix_sha256;
// The number of stages a milestone gate covers (scenario stages and stages of
// required sub-IDs), counted from the fixture, so no expectation hardcodes the
// size of the committed registry.
const gateStages = (m) =>
  [...REG.scenario.filter((e) => e.kind === 'scenario'), ...SUB.subcase.filter((e) => e.conditional_on === undefined)].flatMap((e) => e.stage).filter((s) => s.milestone === m).length;
const M1A = gateStages('M1a');

function replaceOnce(text, from, to) {
  const i = text.indexOf(from);
  assert.ok(i >= 0, `fixture text not found: ${from}`);
  assert.equal(text.indexOf(from, i + 1), -1, `fixture text not unique: ${from}`);
  return text.slice(0, i) + to + text.slice(i + from.length);
}

// Sets stage `m` of entry `id` (a [[table]]) to implemented with `tests`,
// stamped as the registry check requires.
const implement = (table, id, m, tests) => (text) => {
  const head = `[[${table}]]\nid = "${id}"`;
  const start = text.indexOf(head);
  assert.ok(start >= 0, `no ${table} ${id}`);
  const next = text.indexOf(`[[${table}]]\n`, start + 1);
  const block = text.slice(start, next < 0 ? text.length : next);
  const at = block.indexOf(`[[${table}.stage]]\nmilestone = "${m}"`);
  assert.ok(at >= 0, `no stage ${m} of ${id}`);
  const nextStage = block.indexOf(`[[${table}.stage]]`, at + 1);
  const end = nextStage < 0 ? block.length : nextStage;
  const stage = block.slice(at, end);
  const scope = /scope = "([^"]*)"/.exec(stage)[1];
  const done = replaceOnce(
    stage,
    'status = "planned"\ntests = []',
    `status = "implemented"\nimplemented_sha256 = "${stageStamp(id, m, scope, matrix(id))}"\ntests = [${tests.map((t) => JSON.stringify(t)).join(', ')}]`,
  );
  return replaceOnce(text, block, block.slice(0, at) + done + block.slice(end));
};
// Lists `tests` in a stage that stays planned.
const listPlanned = (id, m, tests) => (text) => {
  const head = `[[scenario]]\nid = "${id}"`;
  const start = text.indexOf(head);
  const at = text.indexOf(`[[scenario.stage]]\nmilestone = "${m}"`, start);
  const end = text.indexOf('tests = []', at) + 'tests = []'.length;
  return text.slice(0, at) + replaceOnce(text.slice(at, end), 'tests = []', `tests = [${tests.map((t) => JSON.stringify(t)).join(', ')}]`) + text.slice(end);
};
const compose = (...fs) => (t) => fs.reduce((x, f) => f(x), t);

// A temporary root with FILES; `edits` maps a file to a function of its text.
function root(edits = {}) {
  const r = tmp('report-root-');
  for (const rel of FILES) write(join(r, rel), (edits[rel] ?? ((t) => t))(registryText(rel)));
  return r;
}

// Test IDs and their JUnit (classname, name).
const rust = (pkg, bin, path) => ({ id: `nextest:${pkg}/${bin}/${path}`, classname: `${pkg}::${bin}`, name: path });
const A24_POS = rust('skyoauth-scenarios', 'pg', 'security::a24::a24_pos_single_issuance');
const A24_NEG = rust('skyoauth-scenarios', 'pg', 'security::a24::a24_neg_replay');
const A24 = [A24_POS, A24_NEG];
const H_POS = rust('skyoauth-scenarios', 'hermetic', 'integration::a64::a64_pos_scoped_write');
const H_NEG = rust('skyoauth-scenarios', 'hermetic', 'integration::a64::a64_neg_expired_challenge');
const PG_POS = rust('skyoauth-scenarios', 'pg', 'integration::a64::a64_pos_remote_write');
const PG_NEG = rust('skyoauth-scenarios', 'pg', 'integration::a64::a64_neg_key_export');
// skyoauth-operator: target operator runs in the operator job, target
// recovery_offline in the recovery-offline chain (layout §3, §6).
const OP_POS = rust('skyoauth-operator', 'operator', 'a64_pos_remote_scoped_write');
const OP_NEG = rust('skyoauth-operator', 'operator', 'a64_neg_unsupported_adapter');
const RO_POS = rust('skyoauth-operator', 'recovery_offline', 'a64_pos_offline_recovery');
const RO_NEG = rust('skyoauth-operator', 'recovery_offline', 'a64_neg_wrong_instance');
const VT_POS = { id: 'vitest:test/csrf.test.ts/csrf > A40 pos: same origin', classname: 'test/csrf.test.ts', name: 'csrf > A40 pos: same origin' };
const VT_NEG = { id: 'vitest:test/csrf.test.ts/csrf > A40 neg: foreign origin', classname: 'test/csrf.test.ts', name: 'csrf > A40 neg: foreign origin' };
const PW_POS = { id: 'playwright:browser/csrf.spec.ts/csrf › A40 pos: same origin', classname: 'browser/csrf.spec.ts', name: 'csrf › A40 pos: same origin' };
const PW_NEG = { id: 'playwright:browser/csrf.spec.ts/A40 neg: foreign origin', classname: 'browser/csrf.spec.ts', name: 'A40 neg: foreign origin' };

const ids = (tests) => tests.map((t) => t.id);
const withA24 = { [SCENARIOS]: implement('scenario', 'A24', 'M1a', ids(A24)) };
const A64_TESTS = [H_POS, H_NEG, PG_POS, PG_NEG, OP_POS, OP_NEG, RO_POS, RO_NEG];
const withA64 = { [SCENARIOS]: implement('scenario', 'A64', 'M1a', ids(A64_TESTS)) };

// ---------------------------------------------------------------------------
// JUnit and artifact fixtures

const esc = (s) => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;');
// nextest-style JUnit; each case is [test, status], status passed | failed |
// skipped | error | flaky | rerun.
function junit(cases) {
  const body = {
    passed: '',
    failed: '<failure message="assertion failed" type="test failure">boom</failure>',
    error: '<error message="crashed"/>',
    skipped: '<skipped/>',
    flaky: '<flakyFailure message="first try failed" type="test failure"><system-out>x</system-out></flakyFailure>',
    rerun: '<failure message="f"/><rerunFailure message="f"/>',
    // A pass after a retry that errored: only the marker says so.
    flakyError: '<flakyError message="first try crashed"/>',
    rerunError: '<rerunError message="crashed"/>',
  };
  const suites = new Map();
  for (const [t, s] of cases) suites.set(t.classname, [...(suites.get(t.classname) ?? []), [t, s]]);
  const xml = [...suites].map(
    ([cls, cs]) =>
      `  <testsuite name="${esc(cls)}" tests="${cs.length}">\n${cs.map(([t, s]) => `    <testcase name="${esc(t.name)}" classname="${esc(cls)}" time="0.01">${body[s]}</testcase>`).join('\n')}\n  </testsuite>`,
  );
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="nextest-run" tests="${cases.length}">\n${xml.join('\n')}\n</testsuites>\n`;
}
const allPass = (tests) => junit(tests.map((t) => [t, 'passed']));

// Writes a run's run.json as `gh run view RUN --json
// databaseId,headSha,attempt,workflowName` does; `over` replaces fields.
const runJson = (d, run, over = {}) => write(join(d, String(run), 'run.json'), JSON.stringify({ attempt: 1, databaseId: Number(run), headSha: SHA, workflowName: 'CI', ...over }));

// Writes artifacts. `spec` is a list of { run, leg, attempt, junit, name }:
// junit is the file text (null: no junit.xml), leg null: no leg file. The
// artifact name defaults to the scenarios-pg pattern. Each run gets a
// run.json for `commit` whose attempt is the run's highest artifact attempt
// (from the name), unless `runs[run]` replaces fields (null: no run.json).
function artifacts(spec, { commit = SHA, runs = {} } = {}) {
  const d = tmp('report-art-');
  const attempts = new Map();
  for (const a of spec) {
    const name = a.name ?? `junit-${(a.leg ?? 'none').replace('/', '-')}-attempt-${a.attempt ?? 1}`;
    const run = String(a.run ?? 100);
    const dir = join(d, run, name);
    mkdirSync(dir, { recursive: true });
    if (a.leg !== null) writeFileSync(join(dir, 'leg'), `${a.leg}\n`);
    if (a.junit !== null) writeFileSync(join(dir, 'junit.xml'), a.junit);
    attempts.set(run, Math.max(attempts.get(run) ?? 1, Number(/attempt-(\d+)$/.exec(name)?.[1] ?? 1)));
  }
  for (const [run, attempt] of attempts) if (runs[run] !== null) runJson(d, run, { attempt, headSha: commit, ...runs[run] });
  return d;
}

// Runs the reporter; returns { code, out, err, json, md }.
function report(rootDir, args = [], { commit = SHA } = {}) {
  const out = [];
  const err = [];
  const j = join(tmp('report-out-'), 'r.json');
  const code = run(['--root', rootDir, '--commit', commit, '--today', TODAY, '--json', j, ...args], { log: (s) => out.push(s), logErr: (s) => err.push(s) });
  let json = null;
  try {
    json = JSON.parse(readFileSync(j, 'utf8'));
  } catch {
    json = null;
  }
  return { code, out: out.join('\n'), err: err.join('\n'), json };
}
// The Markdown with text() escapes undone, for matching prose.
const plain = (md) => md.replace(/\\([\\`*_[\]~|])/g, '$1').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
// The variables of a CI runner (GITHUB_*, RUNNER_*, ACTIONS_*, CI) and of
// the conformance-report job (COMMIT, ARTIFACTS, REPORT_JSON, DOWNLOAD_DIR,
// DOWNLOADS). Every child that this file spawns gets an environment without
// them, so a test sees on a runner what it sees on a laptop, and never
// writes into the real step summary of the job that runs the tests.
const RUNNER_VAR = /^(?:GITHUB_|RUNNER_|ACTIONS_)|^(?:CI|COMMIT|ARTIFACTS|REPORT_JSON|DOWNLOAD_DIR|DOWNLOADS)$/;
const withoutRunner = (env) => Object.fromEntries(Object.entries(env).filter(([k]) => !RUNNER_VAR.test(k)));
// GIT_ENV built at the call, not at load: this process's environment as it
// is now (a test may have changed it) without its GIT_* variables, plus
// GIT_ENV's git settings, less the runner's variables.
const childEnv = () =>
  withoutRunner({
    ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_'))),
    ...Object.fromEntries(Object.entries(GIT_ENV).filter(([k]) => k.startsWith('GIT_'))),
  });
const git = (dir, ...args) => {
  const r = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', env: childEnv() });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
};
// Commits `dir` as a git repository on main, with origin/main at the same
// commit, and returns HEAD: the root is then bound to that commit.
const commitRoot = (dir) => {
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'add', '-A');
  git(dir, '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'registry');
  git(dir, 'update-ref', 'refs/remotes/origin/main', 'HEAD');
  return git(dir, 'rev-parse', 'HEAD');
};
// report() on `rootDir` bound to its own commit (gate mode needs that), with
// artifacts from `spec` (null: none) whose run.json names that commit.
const boundReport = (rootDir, spec, args = []) => {
  const head = commitRoot(rootDir);
  return report(rootDir, [...(spec ? ['--artifacts', artifacts(spec, { commit: head })] : []), ...args], { commit: head });
};
const stage = (json, id, m) => json.stages.find((s) => s.id === id && s.milestone === m);
const pair = (json, id, m, test, leg) => stage(json, id, m).pairs.find((p) => p.test === test.id && p.leg === leg);

const PG = 'scenarios-pg/x86_64';

// ---------------------------------------------------------------------------

describe('statuses', () => {
  test('all passed: the stage, its milestone count and the scenario up to M1a are passed', () => {
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: allPass(A24) }])]);
    assert.equal(r.code, 0, r.err);
    const st = stage(r.json, 'A24', 'M1a');
    assert.equal(st.status, 'passed');
    assert.deepEqual(st.problems, []);
    assert.deepEqual(st.pairs.map((p) => [p.test, p.leg, p.status]), [
      [A24_POS.id, PG, 'passed'],
      [A24_NEG.id, PG, 'passed'],
    ]);
    assert.ok(M1A > 1, 'the fixture has more than one M1a stage');
    assert.deepEqual(r.json.milestones.M1a, { stages: M1A, passed: 1, 'not run': 0, planned: M1A - 1, failed: 0, gate: 'planned' });
    const a24 = r.json.scenarios.find((s) => s.id === 'A24');
    assert.deepEqual(a24.by_milestone, { M1a: 'passed', M1b: 'passed', M2: 'planned', M3: 'planned', M4: 'planned', M5: 'planned' });
    assert.equal(a24.status, 'planned');
    assert.match(r.out, /\| A24 M1a: consume primitive \| passed \| 2 pair\(s\) passed \|/);
    assert.ok(r.out.includes(`| M1a | ${M1A} | 1 | 0 | 0 | ${M1A - 1} | planned |`), r.out);
    assert.equal(r.json.headline, null);
    assert.equal(r.json.format, 1);
    assert.deepEqual(r.json.uncounted, { planned: [], unregistered: [], unknown: [], outside_job: [] });
    assert.ok(r.out.startsWith(`## Conformance results for \`${SHA}\`\n\nJudged on ${TODAY} from 1 JUnit report(s).`), r.out);
    assert.match(r.out, /\| Milestone \| Stages \| Passed \| Failed \| Not run \| Planned \| Gate \|\n\| --- \| --- \| --- \| --- \| --- \| --- \| --- \|\n\| M0 \|/);
    const m5 = gateStages('M5');
    assert.ok(r.out.includes(`| M5 | ${m5} | 0 | 0 | 0 | ${m5} | planned |\n\nThe counts`), r.out);
    assert.match(r.out, /\| planned \|\n\nThe counts cover required stages\. Stages of conditional sub-IDs are listed with the implemented stages but gate no milestone\.\n\n### Implemented stages \(1\)\n\n\| Stage \| Status \| Details \|\n\| --- \| --- \| --- \|\n\| A24 M1a/);
    for (const re of [/docs-only/, /Input errors/, /Results not counted/, /Waivers for this commit/, /\*\*null\*\*/]) assert.doesNotMatch(r.out, re);
    assert.ok(r.out.endsWith('| A24 M1a: consume primitive | passed | 2 pair(s) passed |\n\n- note: the registry is not bound to --commit: --root is not a git checkout\n'), JSON.stringify(r.out.slice(-160)));
    assert.deepEqual(r.json.notes, ['the registry is not bound to --commit: --root is not a git checkout']);
    assert.deepEqual(r.json.reports, [{ run_id: 100, run_attempt: 1, workflow: 'CI', leg: PG, artifact: '100/junit-scenarios-pg-x86_64-attempt-1', cases: 2 }]);
  });

  test('--require-milestone: exit 1 while any stage of the milestone is not passed', () => {
    const r = boundReport(root(withA24), [{ leg: PG, junit: allPass(A24) }], ['--require-milestone', 'M1a']);
    assert.equal(r.code, 1);
    assert.match(r.err, /milestone M1a is planned, not passed/);
    const none = boundReport(root(), null, ['--require-milestone', 'M0']);
    assert.equal(none.code, 1);
    assert.match(none.err, /milestone M0 is no stages, not passed/);
  });

  // Every required M1b stage implemented (all on scenarios-pg), so the M1b
  // gate can pass; A24 M1a and the conditional A33.90 M3 implemented too.
  const M1B = gateStages('M1b');
  const m1bIds = [...REG.scenario, ...SUB.subcase].filter((e) => e.conditional_on === undefined && e.stage?.some((st) => st.milestone === 'M1b')).map((e) => e.id);
  const pgTest = (id, pol) => rust('skyoauth-scenarios', 'pg', `x::${id.toLowerCase().replace('.', '_')}_${pol}_t`);
  const pgPair = (id) => [pgTest(id, 'pos'), pgTest(id, 'neg')];
  const gateRoot = () =>
    root({
      [SCENARIOS]: compose(...m1bIds.map((id) => implement('scenario', id, 'M1b', ids(pgPair(id)))), implement('scenario', 'A24', 'M1a', ids(A24))),
      [SUBCASES]: implement('subcase', 'A33.90', 'M3', ids(pgPair('A33.90'))),
    });
  const gateRun = (fails, args = []) => {
    const all = [...m1bIds.flatMap(pgPair), ...A24, ...pgPair('A33.90')];
    return boundReport(gateRoot(), [{ leg: PG, junit: junit(all.map((t) => [t, fails.some((f) => f.id === t.id) ? 'failed' : 'passed'])) }], args);
  };

  test('--require-milestone M: exit 0 iff the gate of M passed; failures elsewhere, conditional ones included, stay in the report only', () => {
    assert.equal(m1bIds.length, M1B, 'every M1b stage is a scenario stage');
    const fails = [A24_NEG, pgTest('A33.90', 'pos')];
    const gate = gateRun(fails, ['--require-milestone', 'M1b']);
    assert.equal(gate.code, 0, gate.err);
    assert.equal(gate.json.milestones.M1b.gate, 'passed');
    assert.equal(gate.json.trusted, true);
    assert.match(gate.err, /note: implemented stages outside the M1b gate failed; they do not change the exit status/);
    assert.equal(stage(gate.json, 'A33.90', 'M3').status, 'failed');
    assert.match(gate.out, /\| A33\.90 \(conditional: back-channel-logout\) M3: full row \| failed \|/);
    assert.match(gate.out, /\| A24 M1a: consume primitive \| failed \|/);
    // Without the flag, any failed implemented stage exits 1.
    const plainRun = gateRun(fails);
    assert.equal(plainRun.code, 1);
    assert.match(plainRun.err, /some implemented stage has a failed result/);
    // Only the conditional stage failed: still 1 without the flag.
    assert.equal(gateRun([pgTest('A33.90', 'neg')]).code, 1);
    const clean0 = gateRun([], ['--require-milestone', 'M1b']);
    assert.equal(clean0.code, 0);
    assert.equal(clean0.err, '', 'nothing on stderr when the gate passed and nothing else failed');
    assert.equal(gateRun([]).err, '');
    assert.equal(gateRun([]).code, 0);
    // The gate failed and so did a stage outside it: both are said.
    const both = gateRun([pgTest('A47', 'neg'), A24_NEG], ['--require-milestone', 'M1b']);
    assert.equal(both.code, 1);
    assert.match(both.err, /milestone M1b is failed, not passed\n.*note: implemented stages outside the M1b gate failed/);
    // The gate's own failure: 1, and no note about other stages.
    const own = gateRun([pgTest('A47', 'neg')], ['--require-milestone', 'M1b']);
    assert.equal(own.code, 1);
    assert.match(own.err, /milestone M1b is failed, not passed/);
    assert.doesNotMatch(own.err, /outside the M1b gate/);
    const m1a = gateRun([], ['--require-milestone', 'M1a']);
    assert.equal(m1a.code, 1);
    assert.match(m1a.err, /milestone M1a is planned, not passed/);
  });

  test('--require-milestone: a failed result seen outside its job leaves a passed gate passed (exit 0, nothing on stderr)', () => {
    const all = [...m1bIds.flatMap(pgPair), ...A24, ...pgPair('A33.90')];
    const r = boundReport(gateRoot(), [{ leg: PG, junit: allPass(all) }, { leg: 'scenarios-hermetic/x86_64', junit: junit([[pgTest('A47', 'neg'), 'failed']]) }], ['--require-milestone', 'M1b']);
    assert.equal(r.code, 0, r.err);
    assert.equal(r.err, '');
    assert.equal(r.json.milestones.M1b.gate, 'passed');
    assert.deepEqual(r.json.uncounted.outside_job.map((x) => [x.leg, x.status]), [['scenarios-hermetic/x86_64', 'failed']]);
  });

  test('--require-milestone with input errors: exit 2 even when the gate passed, and the JSON says trusted: false', () => {
    const all = [...m1bIds.flatMap(pgPair), ...A24, ...pgPair('A33.90')];
    const r = boundReport(gateRoot(), [{ leg: PG, junit: junit(all.map((t) => [t, t === A24_NEG ? 'failed' : 'passed'])) }, { leg: null, name: 'mystery', junit: null }], ['--require-milestone', 'M1b']);
    assert.equal(r.code, 2);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'failed');
    assert.doesNotMatch(r.err, /outside the M1b gate/, 'an untrusted report gets no note about the gate');
    assert.equal(r.json.milestones.M1b.gate, 'passed');
    assert.equal(r.json.trusted, false);
    assert.equal(r.json.input_errors.length, 1);
    assert.match(r.err, /1 input error\(s\); the report cannot be trusted/);
    assert.doesNotMatch(r.err, /milestone M1b/);
  });

  test('--require-milestone M: a gate with a not run stage is not passed (exit 1)', () => {
    const all = [...m1bIds.flatMap(pgPair), ...A24, ...pgPair('A33.90')].filter((t) => t.id !== pgTest('A47', 'neg').id);
    const r = boundReport(gateRoot(), [{ leg: PG, junit: allPass(all) }], ['--require-milestone', 'M1b']);
    assert.equal(r.code, 1);
    assert.equal(stage(r.json, 'A47', 'M1b').status, 'not run');
    assert.equal(r.json.milestones.M1b.gate, 'not run');
    assert.match(r.err, /milestone M1b is not run, not passed/);
  });

  test('the gate job (layout §3 Gates): --root a worktree of the merge-base, --commit the merge-base, --require-milestone', () => {
    // main (origin/main) holds the registry; the gate PR is one commit on it.
    const dir = gateRoot();
    const mb = commitRoot(dir);
    write(join(dir, SCENARIOS), replaceOnce(readFileSync(join(dir, SCENARIOS), 'utf8'), 'gates_passed = []', 'gates_passed = ["M1b"]'));
    git(dir, '-c', 'commit.gpgsign=false', 'commit', '-q', '-am', 'gate M1b');
    const wt = join(tmp('report-wt-'), 'merge-base');
    git(dir, 'worktree', 'add', '-q', '--detach', wt, mb);
    const all = [...m1bIds.flatMap(pgPair), ...A24, ...pgPair('A33.90')];
    const gate = (rootDir, tests, extra = []) => report(rootDir, ['--require-history', '--require-milestone', 'M1b', '--artifacts', artifacts([{ leg: PG, junit: allPass(tests) }], { commit: mb }), ...extra], { commit: mb });
    const passed = gate(wt, all);
    assert.equal(passed.code, 0, passed.err);
    assert.equal(passed.json.trusted, true);
    assert.deepEqual(passed.json.notes, []);
    // A leg of the merge-base without a result yet (a post-merge or live run
    // that has not finished) is not run: the gate fails until it completes.
    const waiting = gate(wt, all.filter((t) => t.id !== pgTest('A47', 'neg').id));
    assert.equal(waiting.code, 1);
    assert.match(waiting.err, /milestone M1b is not run, not passed/);
    // The PR head is not the judged commit: no report, and with
    // --allow-commit-mismatch an untrusted one (exit 2) though the gate passed.
    const fromHead = gate(dir, all);
    assert.equal(fromHead.code, 2);
    assert.match(fromHead.err, /--root is a checkout of [0-9a-f]{40}, not of --commit/);
    const loose = gate(dir, all, ['--allow-commit-mismatch']);
    assert.equal(loose.code, 2);
    assert.equal(loose.json.milestones.M1b.gate, 'passed');
    assert.equal(loose.json.trusted, false);
  });

  test('--require-milestone on a root not bound to --commit is an input error (exit 2), never a gate verdict', () => {
    const all = [...m1bIds.flatMap(pgPair), ...A24, ...pgPair('A33.90')];
    const UNBOUND = "--require-milestone needs --root bound to --commit, but --root is not a git checkout, so its registry is not known to be the judged commit's";
    // The gate would pass, and would fail: neither verdict is given.
    for (const fails of [[], [pgTest('A47', 'neg')]]) {
      const r = report(gateRoot(), ['--require-milestone', 'M1b', '--artifacts', artifacts([{ leg: PG, junit: junit(all.map((t) => [t, fails.some((f) => f.id === t.id) ? 'failed' : 'passed'])) }])]);
      assert.equal(r.code, 2);
      assert.equal(r.json.trusted, false);
      assert.deepEqual(r.json.input_errors, [UNBOUND]);
      assert.deepEqual(r.json.notes, []);
      assert.match(r.err, /1 input error\(s\); the report cannot be trusted/);
    }
    assert.equal(report(root(), ['--require-milestone', 'M0']).code, 2);
    // A checkout of another commit, printed with --allow-commit-mismatch, is
    // unbound too.
    const dir = gateRoot();
    commitRoot(dir);
    const other = 'b'.repeat(40);
    const mismatch = report(dir, ['--allow-commit-mismatch', '--require-milestone', 'M1b', '--artifacts', artifacts([{ leg: PG, junit: allPass(all) }], { commit: other })], { commit: other });
    assert.equal(mismatch.code, 2);
    assert.equal(mismatch.json.milestones.M1b.gate, 'passed');
    // Without the flag the same unbound root only gets a note.
    const plainRun = report(gateRoot(), ['--artifacts', artifacts([{ leg: PG, junit: allPass(all) }])]);
    assert.equal(plainRun.code, 0, plainRun.err);
    assert.deepEqual(plainRun.json.notes, ['the registry is not bound to --commit: --root is not a git checkout']);
  });

  test('exitStatus', () => {
    const ms = (gate) => Object.fromEntries(['M0', 'M1a'].map((m) => [m, { gate: m === 'M1a' ? gate : 'no stages' }]));
    const res = (o) => ({ input_errors: [], failed: false, milestones: ms('passed'), ...o });
    assert.deepEqual(exitStatus(res({}), undefined), [0, null]);
    assert.deepEqual(exitStatus(res({ failed: true }), undefined), [1, 'some implemented stage has a failed result']);
    assert.deepEqual(exitStatus(res({ failed: true }), 'M1a'), [0, null]);
    assert.deepEqual(exitStatus(res({ milestones: ms('not run') }), 'M1a'), [1, 'milestone M1a is not run, not passed']);
    assert.deepEqual(exitStatus(res({}), 'M0'), [1, 'milestone M0 is no stages, not passed']);
    assert.deepEqual(exitStatus(res({ input_errors: ['x'] }), 'M1a'), [2, '1 input error(s); the report cannot be trusted']);
    assert.deepEqual(exitStatus(res({ input_errors: ['x', 'y'], failed: true }), undefined), [2, '2 input error(s); the report cannot be trusted']);
  });

  test('a failed attempt stays failed after a passing re-run, in either order and across runs', () => {
    for (const spec of [
      [{ attempt: 1, junit: junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]) }, { attempt: 2, junit: allPass(A24) }],
      [{ attempt: 1, junit: allPass(A24) }, { attempt: 2, junit: junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]) }],
      [{ run: 100, junit: junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]) }, { run: 200, junit: allPass(A24) }],
    ]) {
      const r = report(root(withA24), ['--artifacts', artifacts(spec.map((s) => ({ leg: PG, ...s })))]);
      assert.equal(r.code, 1, r.out);
      assert.match(r.err, /some implemented stage has a failed result/);
      assert.equal(stage(r.json, 'A24', 'M1a').status, 'failed');
      assert.equal(pair(r.json, 'A24', 'M1a', A24_NEG, PG).status, 'failed');
      assert.equal(pair(r.json, 'A24', 'M1a', A24_POS, PG).status, 'passed');
      assert.equal(r.json.failed, true);
      assert.match(r.out, /a24_neg_replay` on `scenarios-pg\/x86_64`: failed \(failed in run \d+ attempt \d\)/);
    }
  });

  test('attempts are joined in run and attempt order, numerically', () => {
    const r = report(root(withA24), [
      '--artifacts',
      artifacts([
        { run: 100, attempt: 10, leg: PG, junit: allPass(A24) },
        { run: 100, attempt: 2, leg: PG, junit: allPass(A24) },
        { run: 99, attempt: 1, leg: PG, junit: allPass(A24) },
      ]),
    ]);
    assert.deepEqual(pair(r.json, 'A24', 'M1a', A24_POS, PG).attempts.map((a) => [a.run_id, a.run_attempt, a.status]), [
      [99, 1, 'passed'],
      [100, 2, 'passed'],
      [100, 10, 'passed'],
    ]);
  });

  for (const s of ['flaky', 'rerun', 'error', 'flakyError', 'rerunError']) {
    test(`a testcase with ${s === 'error' ? 'an <error>' : `${s} retry markers`} is failed`, () => {
      const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: junit([[A24_POS, s], [A24_NEG, 'passed']]) }])]);
      assert.equal(r.code, 1);
      assert.equal(pair(r.json, 'A24', 'M1a', A24_POS, PG).status, 'failed');
    });
  }

  test('a skipped or missing case is not run, and a later attempt fills it', () => {
    const skipped = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: junit([[A24_POS, 'passed'], [A24_NEG, 'skipped']]) }])]);
    assert.equal(skipped.code, 0);
    assert.equal(pair(skipped.json, 'A24', 'M1a', A24_NEG, PG).status, 'not run');
    assert.equal(stage(skipped.json, 'A24', 'M1a').status, 'not run');
    const missing = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: allPass([A24_POS]) }])]);
    assert.equal(stage(missing.json, 'A24', 'M1a').status, 'not run');
    assert.match(missing.out, /a24_neg_replay` on `scenarios-pg\/x86_64`: not run/);
    const filled = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, attempt: 1, junit: allPass([A24_POS]) }, { leg: PG, attempt: 2, junit: allPass([A24_NEG]) }])]);
    assert.equal(stage(filled.json, 'A24', 'M1a').status, 'passed');
  });

  test('a case from another leg does not count', () => {
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: 'scenarios-hermetic/x86_64', junit: allPass(A24) }])]);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'not run');
    // Listed as seen outside its job, not counted.
    assert.deepEqual(r.json.uncounted.outside_job.map((x) => [x.test, x.leg, x.job, x.produced_by]), A24.map((t) => [t.id, 'scenarios-hermetic/x86_64', 'scenarios-hermetic', ['scenarios-pg']]));
  });

  test('a leg with no junit.xml (cancelled job) is not run, with a note', () => {
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: null }])]);
    assert.equal(r.code, 0);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'not run');
    assert.match(plain(r.out), /note: 100\/junit-scenarios-pg-x86_64-attempt-1: no junit\.xml; leg scenarios-pg\/x86_64 has no result from run 100 attempt 1/);
  });

  test('no artifacts at all: implemented stages are not run, exit 0', () => {
    const r = report(root(withA24));
    assert.equal(r.code, 0);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'not run');
    assert.match(r.out, /from 0 JUnit report\(s\)/);
  });
});

describe('legs', () => {
  const LEGS = {
    'scenarios-hermetic/x86_64': [H_POS, H_NEG],
    'scenarios-hermetic/aarch64': [H_POS, H_NEG],
    'scenarios-pg/x86_64': [PG_POS, PG_NEG],
    'operator/ubuntu': [OP_POS, OP_NEG],
    'operator/macos': [OP_POS, OP_NEG],
    'operator/windows': [OP_POS, OP_NEG],
    'recovery-offline/ubuntu': [RO_POS, RO_NEG],
    'recovery-offline/macos': [RO_POS, RO_NEG],
    'recovery-offline/windows': [RO_POS, RO_NEG],
  };
  const a64 = (skip = [], commit = SHA) => artifacts(Object.entries(LEGS).filter(([leg]) => !skip.includes(leg)).map(([leg, tests]) => ({ leg, junit: allPass(tests) })), { commit });

  test('A64 with every leg passed is passed', () => {
    const r = report(root(withA64), ['--artifacts', a64()]);
    assert.equal(r.code, 0, r.err);
    const st = stage(r.json, 'A64', 'M1a');
    assert.equal(st.status, 'passed');
    assert.equal(st.pairs.length, 18);
  });

  test('A64 without its operator/windows leg is not run, though every other leg passed', () => {
    const r = report(root(withA64), ['--artifacts', a64(['operator/windows'])]);
    assert.equal(r.code, 0);
    const st = stage(r.json, 'A64', 'M1a');
    assert.equal(st.status, 'not run');
    assert.deepEqual(st.pairs.filter((p) => p.status !== 'passed').map((p) => [p.test, p.leg, p.status]), [
      [OP_POS.id, 'operator/windows', 'not run'],
      [OP_NEG.id, 'operator/windows', 'not run'],
    ]);
    assert.match(r.out, /a64_pos_remote_scoped_write` on `operator\/windows`: not run<br>`nextest:skyoauth-operator\/operator\/a64_neg_unsupported_adapter` on `operator\/windows`: not run \|/);
    const dir = root(withA64);
    const head = commitRoot(dir);
    assert.equal(report(dir, ['--artifacts', a64(['operator/windows'], head), '--require-milestone', 'M1a'], { commit: head }).code, 1);
  });

  test('a stage whose job has no pos or no neg test, or a test of another entry or job, is not run', () => {
    const cases = [
      [[A24_POS.id], /job scenarios-pg produces no neg test of this stage/],
      [[A24_NEG.id], /job scenarios-pg produces no pos test of this stage/],
      [[...ids(A24), 'nextest:skyoauth-scenarios/pg/security::a25::a25_pos_x'], /a25_pos_x is not a pos\/neg scenario test of A24/],
      [[...ids(A24), 'nextest:skyoauth-scenarios/pg/security::a24::a24_helper'], /a24_helper is not a pos\/neg scenario test of A24/],
      [[...ids(A24), 'nextest:skyoauth-service/a24_pos_unit'], /skyoauth-service\/a24_pos_unit is produced by none of the jobs of the stage's legs \(scenarios-pg\)/],
      [[...ids(A24), 'nextest:skyoauth-scenarios/hermetic/a24_pos_h'], /hermetic\/a24_pos_h is produced by none of the jobs/],
      [[...ids(A24), 'junit:whatever'], /junit:whatever is not a pos\/neg scenario test of A24/],
    ];
    for (const [tests, re] of cases) {
      const r = report(root({ [SCENARIOS]: implement('scenario', 'A24', 'M1a', tests) }), ['--artifacts', artifacts([{ leg: PG, junit: allPass(A24) }])]);
      assert.equal(r.code, 0, r.err);
      const st = stage(r.json, 'A24', 'M1a');
      assert.equal(st.status, 'not run', tests.join());
      assert.ok(st.problems.some((p) => re.test(p)), `${re} not in ${st.problems}`);
      assert.match(plain(r.out), re);
    }
  });

  test('each job of a stage needs its own pos and neg test: a neg test of another job does not count', () => {
    // scenarios-pg has only a pos test; the hermetic, operator and
    // recovery-offline jobs have both, so neg tests exist in the stage, just
    // not from scenarios-pg.
    const tests = [H_POS, H_NEG, PG_POS, OP_POS, OP_NEG, RO_POS, RO_NEG];
    const r = report(root({ [SCENARIOS]: implement('scenario', 'A64', 'M1a', ids(tests)) }), [
      '--artifacts',
      artifacts(['scenarios-hermetic/x86_64', 'scenarios-hermetic/aarch64', PG, 'operator/ubuntu', 'operator/macos', 'operator/windows', 'recovery-offline/ubuntu', 'recovery-offline/macos', 'recovery-offline/windows'].map((leg) => ({ leg, junit: allPass(tests) }))),
    ]);
    const st = stage(r.json, 'A64', 'M1a');
    assert.deepEqual(st.problems, ['job scenarios-pg produces no neg test of this stage']);
    assert.equal(st.status, 'not run');
    assert.ok(st.pairs.every((p) => p.status === 'passed'));
  });

  // skyoauth-operator has one job per test target (layout §3 "Which job
  // produces a test", §6): target operator runs in operator, target
  // recovery_offline in recovery-offline; any other target is produced by no
  // job.
  describe('skyoauth-operator targets', () => {
    const jobLegs = (job) => Object.keys(LEGS).filter((leg) => leg.startsWith(`${job}/`));
    const legsOfPairs = (st, t) => st.pairs.filter((p) => p.test === t.id).map((p) => p.leg);
    // The legs of stage `m` of scenario `id`, replaced by `legs`.
    const withLegs = (id, m, legs) => (text) => {
      const start = text.indexOf(`[[scenario]]\nid = "${id}"`);
      const at = text.indexOf(`[[scenario.stage]]\nmilestone = "${m}"`, start);
      assert.ok(start >= 0 && at >= 0, `no stage ${m} of ${id}`);
      const from = text.indexOf('legs = [', at);
      const to = text.indexOf(']', from) + 1;
      return text.slice(0, from) + `legs = [${legs.map((l) => JSON.stringify(l)).join(', ')}]` + text.slice(to);
    };

    test('in A64, which lists both jobs, a target operator test is judged by the operator legs alone and a target recovery_offline test by the recovery-offline legs alone', () => {
      // Each operator leg reports only target operator tests, each
      // recovery-offline leg only target recovery_offline tests.
      const r = report(root(withA64), ['--artifacts', a64()]);
      assert.equal(r.code, 0, r.err);
      const st = stage(r.json, 'A64', 'M1a');
      assert.deepEqual(st.problems, []);
      assert.equal(st.status, 'passed');
      for (const t of [OP_POS, OP_NEG]) assert.deepEqual(legsOfPairs(st, t), jobLegs('operator'), t.id);
      for (const t of [RO_POS, RO_NEG]) assert.deepEqual(legsOfPairs(st, t), jobLegs('recovery-offline'), t.id);
    });

    test('A64 needs a pos and a neg test from each target: one target does not cover the other job', () => {
      const legs = Object.keys(LEGS);
      for (const [tests, job] of [
        [[OP_POS, OP_NEG], 'recovery-offline'],
        [[RO_POS, RO_NEG], 'operator'],
      ]) {
        const all = [H_POS, H_NEG, PG_POS, PG_NEG, ...tests];
        const r = report(root({ [SCENARIOS]: implement('scenario', 'A64', 'M1a', ids(all)) }), ['--artifacts', artifacts(legs.map((leg) => ({ leg, junit: allPass(all) })))]);
        assert.equal(r.code, 0, r.err);
        const st = stage(r.json, 'A64', 'M1a');
        assert.deepEqual(st.problems, [`job ${job} produces no pos test of this stage`, `job ${job} produces no neg test of this stage`], job);
        assert.equal(st.status, 'not run');
        assert.deepEqual(
          st.pairs.filter((p) => p.leg.startsWith(`${job}/`)),
          [],
          `no pair on the ${job} legs`,
        );
      }
    });

    test('a stage whose legs list operator but not recovery-offline (A20 M3): a target operator test is judged by operator alone, a target recovery_offline test is produced by none of its jobs', () => {
      const PG20 = [rust('skyoauth-scenarios', 'pg', 'integration::a20::a20_pos_operator_during_outage'), rust('skyoauth-scenarios', 'pg', 'integration::a20::a20_neg_fresh_login_fails_closed')];
      const OP20 = [rust('skyoauth-operator', 'operator', 'a20_pos_recovery_during_outage'), rust('skyoauth-operator', 'operator', 'a20_neg_no_session')];
      const RO20 = rust('skyoauth-operator', 'recovery_offline', 'a20_pos_offline_recovery');
      const legsA20 = [PG, ...jobLegs('operator'), ...jobLegs('recovery-offline')];
      // Every leg, a recovery-offline leg too, reports every test passed.
      const run20 = (tests) => report(root({ [SCENARIOS]: implement('scenario', 'A20', 'M3', ids(tests)) }), ['--artifacts', artifacts(legsA20.map((leg) => ({ leg, junit: allPass(tests) })))]);

      const ok = run20([...PG20, ...OP20]);
      assert.equal(ok.code, 0, ok.err);
      const st = stage(ok.json, 'A20', 'M3');
      assert.deepEqual(st.problems, []);
      assert.equal(st.status, 'passed');
      for (const t of OP20) assert.deepEqual(legsOfPairs(st, t), jobLegs('operator'), t.id);

      const bad = run20([...PG20, ...OP20, RO20]);
      assert.equal(bad.code, 0, bad.err);
      const st2 = stage(bad.json, 'A20', 'M3');
      assert.deepEqual(st2.problems, [`${RO20.id} is produced by none of the jobs of the stage's legs (scenarios-pg, operator)`]);
      assert.equal(st2.status, 'not run');
      assert.deepEqual(legsOfPairs(st2, RO20), []);
    });

    test('a stage whose legs list recovery-offline but not operator: a target recovery_offline test is judged by recovery-offline alone, a target operator test is produced by none of its jobs', () => {
      const legs = Object.keys(LEGS).filter((leg) => !leg.startsWith('operator/'));
      const fixture = (tests) => ({ [SCENARIOS]: compose(withLegs('A64', 'M1a', legs), implement('scenario', 'A64', 'M1a', ids(tests))) });
      // Every leg, the operator legs too, reports every test passed.
      const run64 = (tests) => report(root(fixture(tests)), ['--artifacts', artifacts(Object.keys(LEGS).map((leg) => ({ leg, junit: allPass(tests) })))]);

      const ok = run64([H_POS, H_NEG, PG_POS, PG_NEG, RO_POS, RO_NEG]);
      assert.equal(ok.code, 0, ok.err);
      const st = stage(ok.json, 'A64', 'M1a');
      assert.deepEqual(st.legs, legs);
      assert.deepEqual(st.problems, []);
      assert.equal(st.status, 'passed');
      for (const t of [RO_POS, RO_NEG]) assert.deepEqual(legsOfPairs(st, t), jobLegs('recovery-offline'), t.id);

      const bad = run64([H_POS, H_NEG, PG_POS, PG_NEG, RO_POS, RO_NEG, OP_POS]);
      assert.equal(bad.code, 0, bad.err);
      const st2 = stage(bad.json, 'A64', 'M1a');
      assert.deepEqual(st2.problems, [`${OP_POS.id} is produced by none of the jobs of the stage's legs (scenarios-hermetic, scenarios-pg, recovery-offline)`]);
      assert.equal(st2.status, 'not run');
      assert.deepEqual(legsOfPairs(st2, OP_POS), []);
    });

    test('a test of any other skyoauth-operator target, or of its lib, is produced by no job: its stage is not run though every leg reports it passed', () => {
      const JOBS = 'scenarios-hermetic, scenarios-pg, operator, recovery-offline';
      for (const odd of [
        rust('skyoauth-operator', 'recovery', 'a64_pos_offline_recovery'),
        rust('skyoauth-operator', 'recovery-offline', 'a64_neg_wrong_instance'),
        rust('skyoauth-operator', 'Operator', 'a64_pos_remote_scoped_write'),
        rust('skyoauth-operator', 'bin/skyoauth-operator', 'a64_neg_cli'),
        { id: 'nextest:skyoauth-operator/a64_pos_lib', classname: 'skyoauth-operator', name: 'a64_pos_lib' },
      ]) {
        const tests = [...A64_TESTS, odd];
        const r = report(root({ [SCENARIOS]: implement('scenario', 'A64', 'M1a', ids(tests)) }), ['--artifacts', artifacts(Object.keys(LEGS).map((leg) => ({ leg, junit: allPass([...LEGS[leg], odd]) })))]);
        assert.equal(r.code, 0, r.err);
        const st = stage(r.json, 'A64', 'M1a');
        assert.deepEqual(st.problems, [`${odd.id} is produced by none of the jobs of the stage's legs (${JOBS})`], odd.id);
        assert.equal(st.status, 'not run', odd.id);
        assert.deepEqual(legsOfPairs(st, odd), [], odd.id);
        assert.ok(st.pairs.every((p) => p.status === 'passed'), odd.id);
      }
    });
  });

  // A registered test in the JUnit of a leg whose job does not produce it is
  // not counted (the registry owns it, and its own jobs judge it), but it is
  // listed as informational: "seen outside its job, not counted".
  describe('seen outside its job', () => {
    // The A64 artifacts, with `extra` cases added to the report of each leg
    // in `legs`.
    const a64With = (legs, extra) => artifacts(Object.entries(LEGS).map(([leg, tests]) => ({ leg, junit: junit([...tests.map((t) => [t, 'passed']), ...(legs.includes(leg) ? extra : [])]) })));
    const RO_LEGS = Object.keys(LEGS).filter((leg) => leg.startsWith('recovery-offline/'));
    const strip = (json) => ({ ...json, uncounted: { ...json.uncounted, outside_job: [] } });

    test('a test seen in its own job is not listed', () => {
      const r = report(root(withA64), ['--artifacts', a64()]);
      assert.equal(r.code, 0, r.err);
      assert.deepEqual(r.json.uncounted.outside_job, []);
      assert.doesNotMatch(r.out, /seen outside its job/);
      assert.doesNotMatch(r.out, /Results not counted/);
    });

    test('an operator-target test reported by a recovery-offline leg is listed, and the stage status and exit code are unchanged', () => {
      const base = report(root(withA64), ['--artifacts', a64()]);
      const r = report(root(withA64), ['--artifacts', a64With(RO_LEGS, [[OP_POS, 'passed']])]);
      assert.equal(r.code, base.code);
      assert.equal(r.code, 0, r.err);
      assert.equal(r.err, base.err);
      assert.equal(stage(r.json, 'A64', 'M1a').status, 'passed');
      assert.deepEqual(stage(r.json, 'A64', 'M1a'), stage(base.json, 'A64', 'M1a'), 'the pairs are those of the owning jobs only');
      assert.equal(r.json.failed, false);
      // In the order the reports are read: by run, then by artifact name.
      assert.deepEqual(r.json.uncounted.outside_job, [...RO_LEGS].sort().map((leg) => ({ test: OP_POS.id, leg, job: 'recovery-offline', produced_by: ['operator'], run_id: 100, run_attempt: 1, status: 'passed' })));
      assert.deepEqual({ ...r.json.uncounted, outside_job: [] }, { planned: [], unregistered: [], unknown: [], outside_job: [] }, 'no other bucket');
      assert.match(r.out, /\n### Results not counted\n\n- seen outside its job, not counted: `nextest:skyoauth-operator\/operator\/a64_pos_remote_scoped_write` on `recovery-offline\/macos` passed \(run 100 attempt 1\); job `recovery-offline` does not produce it, `operator` does\n/);
      assert.equal((r.out.match(/^- seen outside its job, not counted: /gm) ?? []).length, RO_LEGS.length);
      // Everything but the listing is the same as without the stray cases.
      assert.deepEqual(strip(r.json), { ...strip(base.json), reports: r.json.reports });
    });

    test('a failing test seen outside its job is listed but does not fail the stage or change the exit code', () => {
      const base = report(root(withA64), ['--artifacts', a64()]);
      const r = report(root(withA64), ['--artifacts', a64With(['recovery-offline/ubuntu'], [[OP_NEG, 'failed']])]);
      assert.equal(r.code, 0, r.err);
      assert.equal(r.code, base.code);
      assert.equal(r.err, base.err);
      assert.equal(r.json.failed, false);
      assert.equal(stage(r.json, 'A64', 'M1a').status, 'passed');
      assert.deepEqual(stage(r.json, 'A64', 'M1a'), stage(base.json, 'A64', 'M1a'));
      assert.deepEqual(r.json.uncounted.outside_job, [{ test: OP_NEG.id, leg: 'recovery-offline/ubuntu', job: 'recovery-offline', produced_by: ['operator'], run_id: 100, run_attempt: 1, status: 'failed' }]);
      assert.match(r.out, /^- seen outside its job, not counted: `nextest:skyoauth-operator\/operator\/a64_neg_unsupported_adapter` on `recovery-offline\/ubuntu` failed \(run 100 attempt 1\); job `recovery-offline` does not produce it, `operator` does$/m);
      // Gate mode needs a gate that passes (the A64 fixture's M1a gate is
      // planned): see "--require-milestone: a failed result seen outside its
      // job leaves a passed gate passed" under statuses.
    });

    test('produced_by is a copy: changing it cannot change which jobs produce a test (TEST_JOBS)', () => {
      const res = judge({
        scenarios: [{ id: 'A64', stage: [{ milestone: 'M1a', scope: 'full row', legs: ['operator/ubuntu'], status: 'implemented', tests: ids([OP_POS, OP_NEG]) }] }],
        subcases: [],
        contracts: [],
        commit: SHA,
        today: TODAY,
        reports: [{ run_id: 1, run_attempt: 1, leg: 'recovery-offline/ubuntu', artifact: '1/ro-attempt-1', cases: new Map([[OP_POS.id, 'failed']]) }],
      });
      const [x] = res.uncounted.outside_job;
      assert.deepEqual(x.produced_by, ['operator']);
      // Checked by identity first, so a shared array fails here and is never
      // changed (which would leak into every later test).
      assert.notStrictEqual(x.produced_by, testInfo(OP_POS.id).jobs);
      x.produced_by.push('recovery-offline');
      assert.deepEqual(testInfo(OP_POS.id).jobs, ['operator']);
      assert.deepEqual(TEST_JOBS.find(([r, p, t]) => r === 'nextest' && p === 'skyoauth-operator' && t === 'operator')[3], ['operator']);
    });

    test('a registered test that no job produces is listed on every leg that reports it, with no producing job', () => {
      const odd = rust('skyoauth-operator', 'recovery', 'a64_pos_offline_recovery');
      const tests = [...A64_TESTS, odd];
      const r = report(root({ [SCENARIOS]: implement('scenario', 'A64', 'M1a', ids(tests)) }), ['--artifacts', a64With(['operator/ubuntu'], [[odd, 'passed']])]);
      assert.equal(r.code, 0, r.err);
      assert.deepEqual(r.json.uncounted.outside_job, [{ test: odd.id, leg: 'operator/ubuntu', job: 'operator', produced_by: [], run_id: 100, run_attempt: 1, status: 'passed' }]);
      assert.match(r.out, /^- seen outside its job, not counted: `nextest:skyoauth-operator\/recovery\/a64_pos_offline_recovery` on `operator\/ubuntu` passed \(run 100 attempt 1\); no job produces it$/m);
    });
  });

  test('a problem stage with a failed pair is failed', () => {
    const r = report(root({ [SCENARIOS]: implement('scenario', 'A24', 'M1a', [A24_POS.id]) }), ['--artifacts', artifacts([{ leg: PG, junit: junit([[A24_POS, 'failed']]) }])]);
    assert.equal(r.code, 1);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'failed');
  });

  test('a job without a decided runner (migration-rehearsal, bundle-check) is never read as nextest: input error, and its stage cannot pass', () => {
    const MR_POS = rust('skyoauth-scenarios', 'envoy_k3s', 'migration::a14_pos_switch');
    const MR_NEG = rust('skyoauth-scenarios', 'envoy_k3s', 'migration::a14_neg_rollback');
    const r = report(root({ [SCENARIOS]: implement('scenario', 'A14', 'M5', ids([MR_POS, MR_NEG])) }), [
      '--artifacts',
      artifacts([
        { leg: 'migration-rehearsal', junit: allPass([MR_POS, MR_NEG]) },
        { leg: 'bundle-check', junit: allPass([MR_POS]) },
      ]),
    ]);
    assert.equal(r.code, 2);
    assert.deepEqual(r.json.input_errors, [
      '100/junit-bundle-check-attempt-1: job bundle-check has no decided runner (layout §6 "Still open", item 5), so its JUnit cannot be mapped to test IDs; not read',
      '100/junit-migration-rehearsal-attempt-1: job migration-rehearsal has no decided runner (layout §6 "Still open", item 5), so its JUnit cannot be mapped to test IDs; not read',
    ]);
    const st = stage(r.json, 'A14', 'M5');
    assert.equal(st.status, 'not run');
    assert.deepEqual(st.problems, ['job migration-rehearsal has no decided runner (layout §6 "Still open", item 5): its results cannot be read, so this stage cannot pass']);
    assert.deepEqual(st.pairs.map((p) => p.status), ['not run', 'not run']);
  });

  test('runnerOf: every layout §1.1 job but bundle-check and migration-rehearsal has a runner; nothing defaults to nextest', () => {
    // Fails when the layout gains a job: decide its runner (or leave it
    // undecided on purpose) here and in JOB_RUNNER.
    const { catalogue } = parseEnvironments(repoText(LAYOUT), []);
    const jobs = [...new Set([...catalogue.values()].map((v) => v.job))].sort();
    assert.deepEqual(jobs.filter((j) => runnerOf(j) === null), ['bundle-check', 'migration-rehearsal']);
    assert.deepEqual(Object.keys(JOB_RUNNER).filter((j) => !jobs.includes(j)), []);
    assert.equal(runnerOf('typescript'), 'vitest');
    assert.equal(runnerOf('typescript-browser'), 'playwright');
    assert.equal(runnerOf('scenarios-pg'), 'nextest');
    for (const j of ['service-nextest', 'constructor', '__proto__', 'toString', '']) assert.equal(runnerOf(j), null, j);
  });

  test('vitest and Playwright titles: A40 passes on its five legs', () => {
    const edits = { [SCENARIOS]: implement('scenario', 'A40', 'M3', ids([VT_POS, VT_NEG, PW_POS, PW_NEG])) };
    const spec = [
      ...['typescript/node22', 'typescript/node24'].map((leg) => ({ leg, junit: allPass([VT_POS, VT_NEG]) })),
      ...['chromium', 'firefox', 'webkit'].map((b) => ({ leg: `typescript-browser/${b}`, junit: allPass([PW_POS, PW_NEG]) })),
    ];
    const r = report(root(edits), ['--artifacts', artifacts(spec)]);
    assert.equal(r.code, 0, r.err);
    const st = stage(r.json, 'A40', 'M3');
    assert.deepEqual(st.problems, []);
    assert.equal(st.status, 'passed');
    assert.equal(st.pairs.length, 10);
  });
});

describe('sub-IDs and contracts', () => {
  const T32_3 = repoText(TASKS).split('\n').find((l) => l.startsWith('- [ ] **T32.3** '));
  const A58_01 = rust('skyoauth-scenarios', 'pg', 'integration::a58::a58_01_pos_prepare');
  const A58_01N = rust('skyoauth-scenarios', 'pg', 'integration::a58::a58_01_neg_stale');
  const sub01 = (text) =>
    replaceOnce(
      text,
      '[[subcase]]\nid = "A58.90"',
      `[[subcase]]
id = "A58.01"
kind = "subcase"
parent = "A58"
layers = ["integration"]
envs = ["pg"]
harness = ["PG", "UC"]
owners = ["T32.3"]
positive = "approved prepare persists"
negative = "stale approval rejected"
matrix_sha256 = "${sha256(T32_3)}"

[[subcase.stage]]
milestone = "M1b"
scope = "full row"
legs = ["scenarios-pg/x86_64"]
status = "implemented"
implemented_sha256 = "${stageStamp('A58.01', 'M1b', 'full row', sha256(T32_3))}"
tests = ["${A58_01.id}", "${A58_01N.id}"]

[[subcase]]
id = "A58.90"`,
    );

  test('a required sub-ID folds into its parent and its milestone; a failed one fails both', () => {
    const ok = report(root({ [SUBCASES]: sub01 }), ['--artifacts', artifacts([{ leg: PG, junit: allPass([A58_01, A58_01N]) }])]);
    assert.equal(ok.code, 0, ok.err);
    assert.equal(stage(ok.json, 'A58.01', 'M1b').status, 'passed');
    assert.equal(ok.json.milestones.M1b.passed, 1);
    assert.equal(ok.json.milestones.M1b.stages, gateStages('M1b') + 1);
    const bad = report(root({ [SUBCASES]: sub01 }), ['--artifacts', artifacts([{ leg: PG, junit: junit([[A58_01, 'passed'], [A58_01N, 'failed']]) }])]);
    assert.equal(bad.code, 1);
    assert.equal(bad.json.scenarios.find((s) => s.id === 'A58').by_milestone.M1b, 'failed');
    assert.equal(bad.json.milestones.M1b.gate, 'failed');
    assert.equal(bad.json.scenarios.find((s) => s.id === 'A57').by_milestone.M1b, undefined);
  });

  test('a conditional sub-ID does not fold into its parent or gate its milestone, but its failure still exits 1', () => {
    const PWD_POS = { id: 'playwright:browser/device.spec.ts/A27.90 pos: user code approval', classname: 'browser/device.spec.ts', name: 'A27.90 pos: user code approval' };
    const PWD_NEG = { id: 'playwright:browser/device.spec.ts/A27.90 neg: polling abuse', classname: 'browser/device.spec.ts', name: 'A27.90 neg: polling abuse' };
    const RN_POS = rust('skyoauth-client', 'native', 'device::a27_90_pos_approval');
    const RN_NEG = rust('skyoauth-client', 'native', 'device::a27_90_neg_expiry');
    const edits = { [SUBCASES]: implement('subcase', 'A27.90', 'M4', ids([PWD_POS, PWD_NEG, RN_POS, RN_NEG])) };
    const spec = [
      ...['chromium', 'firefox', 'webkit'].map((b) => ({ leg: `typescript-browser/${b}`, junit: junit([[PWD_POS, 'failed'], [PWD_NEG, 'passed']]) })),
      ...['ubuntu', 'macos', 'windows'].map((os) => ({ leg: `clients-rust-native/${os}`, junit: allPass([RN_POS, RN_NEG]) })),
    ];
    const r = report(root(edits), ['--artifacts', artifacts(spec)]);
    assert.equal(r.code, 1);
    const st = stage(r.json, 'A27.90', 'M4');
    assert.equal(st.status, 'failed');
    assert.equal(st.conditional_on, 'device-flow');
    assert.equal(r.json.scenarios.find((s) => s.id === 'A27').status, 'planned');
    assert.equal(r.json.milestones.M4.failed, 0);
    assert.equal(r.json.milestones.M4.stages, gateStages('M4'));
    assert.match(r.out, /\| A27\.90 \(conditional: device-flow\) M4: full row \| failed \|/);
  });

  test('contracts are passed only when every covered scenario is', () => {
    const e = (id, status) => ({ id, stage: [{ milestone: 'M1a', scope: 'full row', legs: [PG], status, tests: status === 'implemented' ? ids(A24) : [] }] });
    const base = { subcases: [], commit: SHA, today: TODAY };
    const res = (reports) =>
      judge({ ...base, scenarios: [e('A24', 'implemented'), e('A25', 'planned')], contracts: [{ id: 'C01', covered_by: ['A24'] }, { id: 'C02', covered_by: ['A24', 'A25'] }], reports });
    assert.equal(res([]).headline, null);
    assert.equal(res([]).docs_only, false);
    const pass = res([{ run_id: 1, run_attempt: 1, leg: PG, cases: new Map(ids(A24).map((t) => [t, 'passed'])) }]);
    assert.deepEqual(pass.contracts.map((c) => [c.id, c.status]), [['C01', 'passed'], ['C02', 'planned']]);
    const none = res([]);
    assert.deepEqual(none.contracts.map((c) => [c.id, c.status]), [['C01', 'not run'], ['C02', 'planned']]);
    const unknown = judge({ ...base, scenarios: [], contracts: [{ id: 'C03', covered_by: ['A99'] }], reports: [] });
    // As in the checker's gates rule, only a subcase is conditional: a stray
    // conditional_on on a scenario keeps its stage in the milestone gate.
    const stray = judge({ ...base, scenarios: [{ ...e('A24', 'planned'), conditional_on: 'device-flow' }], contracts: [], reports: [] });
    assert.equal(stray.stages[0].conditional_on, null);
    assert.equal(stray.milestones.M1a.stages, 1);
    assert.equal(unknown.contracts[0].status, 'not run');
  });
});

describe('planned stages', () => {
  test('a planned stage with passing results for its listed tests stays planned, and they are listed as not counted', () => {
    const r = report(root({ [SCENARIOS]: listPlanned('A24', 'M2', ids(A24)) }), ['--artifacts', artifacts([{ leg: PG, junit: allPass(A24) }])]);
    assert.equal(r.code, 0);
    assert.equal(stage(r.json, 'A24', 'M2').status, 'planned');
    assert.deepEqual(stage(r.json, 'A24', 'M2').pairs, []);
    assert.equal(r.json.scenarios.find((s) => s.id === 'A24').status, 'planned');
    assert.equal(r.json.uncounted.planned.length, 2);
    assert.match(r.out, /planned stage, stays planned: `nextest:skyoauth-scenarios\/pg\/security::a24::a24_pos_single_issuance` on `scenarios-pg\/x86_64` passed/);
    assert.match(r.out, /### Implemented stages \(0\)\n\nNone: every stage is planned\./);
  });

  test('a stray unregistered test of a planned scenario changes nothing', () => {
    const r = report(root(), ['--artifacts', artifacts([{ leg: PG, junit: allPass(A24) }])]);
    assert.equal(r.code, 0);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'planned');
    assert.equal(r.json.milestones.M1a.passed, 0);
    assert.deepEqual(r.json.uncounted.unregistered.map((x) => x.test), ids(A24));
  });
});

describe('test names', () => {
  test('unknown and unregistered scenario names are listed; other tests are ignored', () => {
    const t = (path) => rust('skyoauth-scenarios', 'pg', path);
    const cases = [
      [t('x::a99_pos_nothing'), 'failed'],
      [t('x::a24_helper'), 'passed'],
      [t('x::a58_99_neg_ghost'), 'passed'],
      [t('x::a24_pos_unlisted'), 'failed'],
      [t('x::helper_fn'), 'failed'],
      [t('a24_neg_top_level'), 'passed'],
      ...A24.map((x) => [x, 'passed']),
    ];
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: junit(cases) }])]);
    assert.equal(r.code, 0, r.err);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'passed');
    assert.deepEqual(r.json.uncounted.unknown.map((x) => [x.test.split('/').pop(), x.why]), [
      ['x::a99_pos_nothing', 'no registry entry A99'],
      ['x::a24_helper', 'not a well-formed pos/neg scenario name'],
      ['x::a58_99_neg_ghost', 'no registry entry A58.99'],
    ]);
    assert.deepEqual(r.json.uncounted.unregistered.map((x) => [x.test.split('/').pop(), x.status]), [
      ['x::a24_pos_unlisted', 'failed'],
      ['a24_neg_top_level', 'passed'],
    ]);
    assert.match(r.out, /unknown scenario test \(no registry entry A99\): `nextest:skyoauth-scenarios\/pg\/x::a99_pos_nothing` on `scenarios-pg\/x86_64` failed/);
    assert.match(r.out, /not in any stage's tests: `nextest:skyoauth-scenarios\/pg\/x::a24_pos_unlisted`/);
    assert.doesNotMatch(r.out, /helper_fn/);
  });

  test('a backtick in a test name cannot end its code span', () => {
    const t = rust('skyoauth-scenarios', 'pg', 'x::a24_pos_`<b>bold`');
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: junit([[t, 'passed'], ...A24.map((x) => [x, 'passed'])]) }])]);
    assert.match(r.out, /^- unknown scenario test \(not a well-formed pos\/neg scenario name\): `nextest:skyoauth-scenarios\/pg\/x::a24_pos_'<b>bold'` on /m);
    assert.equal(r.json.uncounted.unknown[0].test, t.id);
  });

  test('testId maps nextest, vitest and Playwright testcases to registry IDs', () => {
    assert.equal(testId('nextest', 'skyoauth-scenarios::pg', 'security::a24::a24_neg_x'), 'nextest:skyoauth-scenarios/pg/security::a24::a24_neg_x');
    assert.equal(testId('nextest', 'skyoauth-service', 'tests::a01_pos_x'), 'nextest:skyoauth-service/tests::a01_pos_x');
    assert.equal(testId('nextest', 'skyoauth-service::bin/skyoauth', 'a01_pos_x'), 'nextest:skyoauth-service/bin/skyoauth/a01_pos_x');
    assert.equal(testId('vitest', 'test/a.test.ts', 'd > A40 pos: x'), 'vitest:test/a.test.ts/d > A40 pos: x');
    assert.equal(testId('playwright', 'b/a.spec.ts', 'A40 pos: x'), 'playwright:b/a.spec.ts/A40 pos: x');
  });

  test('testInfo parses entries, polarity and jobs', () => {
    const pick = (id) => {
      const i = testInfo(id);
      return i && [i.like, i.entry, i.polarity, i.jobs.join(',')];
    };
    assert.deepEqual(pick('nextest:skyoauth-scenarios/pg/m::a24_pos_x'), [true, 'A24', 'pos', 'scenarios-pg']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/hermetic/a58_07_neg_x'), [true, 'A58.07', 'neg', 'scenarios-hermetic']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/envoy_k3s/a54_pos_x'), [true, 'A54', 'pos', 'scenarios-envoy-k3s,scenarios-envoy-k3s-nightly,migration-rehearsal,deployed-topology-audit']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/live/a01_neg_x'), [true, 'A01', 'neg', 'live-wif-push,live-wif-negative']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/other/a01_neg_x'), [true, 'A01', 'neg', '']);
    assert.deepEqual(pick('nextest:skyoauth-client/x/a41_pos_x'), [true, 'A41', 'pos', 'clients-rust,clients-rust-native']);
    assert.deepEqual(pick('nextest:skyoauth-operator/operator/a64_pos_x'), [true, 'A64', 'pos', 'operator']);
    assert.deepEqual(pick('nextest:skyoauth-operator/recovery_offline/a64_neg_x'), [true, 'A64', 'neg', 'recovery-offline']);
    assert.deepEqual(pick('nextest:skyoauth-operator/recovery_offline/m::a20_pos_x'), [true, 'A20', 'pos', 'recovery-offline']);
    assert.deepEqual(pick('nextest:skyoauth-operator/recovery/a64_pos_x'), [true, 'A64', 'pos', '']);
    assert.deepEqual(pick('nextest:skyoauth-operator/recovery-offline/a64_pos_x'), [true, 'A64', 'pos', '']);
    assert.deepEqual(pick('nextest:skyoauth-operator/a64_pos_x'), [true, 'A64', 'pos', '']);
    // A target name maps to its job only in its own package, and only as the
    // whole target: not a prefix of it, not its last segment.
    assert.deepEqual(pick('nextest:skyoauth-scenarios/operator/a64_pos_x'), [true, 'A64', 'pos', '']);
    assert.deepEqual(pick('nextest:skyoauth-service/recovery_offline/a64_neg_x'), [true, 'A64', 'neg', '']);
    assert.deepEqual(pick('nextest:skyoauth-operator/operator_real_time/a64_pos_x'), [true, 'A64', 'pos', '']);
    assert.deepEqual(pick('nextest:skyoauth-operator/bin/operator/a64_pos_x'), [true, 'A64', 'pos', '']);
    assert.deepEqual(pick('nextest:skyoauth-service/a01_pos_x'), [true, 'A01', 'pos', '']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/pg/m::a24_pos_'), [true, null, null, 'scenarios-pg']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/pg/a24_x::helper'), [false, null, null, 'scenarios-pg']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/pg/ma24_pos_x'), [false, null, null, 'scenarios-pg']);
    assert.deepEqual(pick('nextest:skyoauth-scenarios/pg/a24_pos_x-y'), [true, null, null, 'scenarios-pg']);
    assert.deepEqual(pick('vitest:test/a.test.ts/A40 neg: x'), [true, 'A40', 'neg', 'typescript']);
    assert.deepEqual(pick('vitest:test/a.test.ts/outer > A58.07 pos: x'), [true, 'A58.07', 'pos', 'typescript']);
    assert.deepEqual(pick('vitest:test/a.test.ts/outerA40 pos: x'), [false, null, null, 'typescript']);
    assert.deepEqual(pick('vitest:test/a.test.ts/A40 pos:'), [true, null, null, 'typescript']);
    assert.deepEqual(pick('vitest:test/a.test.ts/A40 pass: x'), [true, null, null, 'typescript']);
    assert.deepEqual(pick('playwright:b/a.spec.ts/group › A40 pos: x'), [true, 'A40', 'pos', 'typescript-browser']);
    assert.deepEqual(pick('playwright:b/a.spec.ts/A40 pos: group › x'), [false, null, null, 'typescript-browser']);
    assert.deepEqual(pick('playwright:b/a.spec.ts/group > A40 pos: x'), [false, null, null, 'typescript-browser']);
    assert.deepEqual(pick('nextest:p/x/a24_pos_x'), [true, 'A24', 'pos', '']);
    for (const bad of ['junit:x', 'nextest:', 'nextest:pkg', 'nextest:/a24_pos_x', 'nextest:pkg/x/', 'vitest:a.ts/A40 pos: x', 'vitest:noslash']) assert.equal(testInfo(bad), null, bad);
  });
});

describe('waivers', () => {
  // A git root (A24 M1a implemented, A24 M2 planned with tests) committed on
  // main; returns { dir, head }.
  const gitRoot = () => {
    const dir = root({ [SCENARIOS]: compose(implement('scenario', 'A24', 'M1a', ids(A24)), listPlanned('A24', 'M2', [A24_POS.id])) });
    return { dir, head: commitRoot(dir) };
  };
  const waiver = (commit, over = {}) => {
    const w = { commit: `"${commit}"`, test: `"${A24_NEG.id}"`, leg: `"${PG}"`, run_id: '100', run_attempt: '1', reason: '"runner lost the database"', expires: '2026-12-31', ...over };
    return `[[waiver]]\n${Object.entries(w)
      .map(([k, v]) => `${k} = ${v}`)
      .join('\n')}\n`;
  };
  const waiverFile = (text) => {
    const f = join(tmp('report-waivers-'), 'waivers.toml');
    writeFileSync(f, text);
    return f;
  };
  const failedThenPassed = (commit = SHA) =>
    artifacts(
      [
        { leg: PG, attempt: 1, junit: junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]) },
        { leg: PG, attempt: 2, junit: allPass(A24) },
      ],
      { commit },
    );

  test('a waiver discards the one failed attempt it names; the re-run pass then counts, and the waiver is listed next to it', () => {
    const { dir, head } = gitRoot();
    const r = report(dir, ['--require-history', '--waivers', waiverFile(waiver(head)), '--artifacts', failedThenPassed(head)], { commit: head });
    assert.equal(r.code, 0, r.err);
    const p = pair(r.json, 'A24', 'M1a', A24_NEG, PG);
    assert.equal(p.status, 'passed');
    assert.deepEqual(p.waived, [{ run_id: 100, run_attempt: 1, reason: 'runner lost the database', expires: '2026-12-31' }]);
    assert.equal(r.json.waivers[0].applied, true);
    assert.deepEqual(r.json.waivers[0].applied_to, [{ test: A24_NEG.id, leg: PG, run_id: 100, run_attempt: 1 }]);
    assert.match(r.out, /a24_neg_replay` on `scenarios-pg\/x86_64`: passed; waiver applied to run 100 attempt 1: runner lost the database \(expires 2026-12-31\)/);
    assert.match(r.out, /### Waivers for this commit\n\n- applied: `nextest:.*a24_neg_replay` on `scenarios-pg\/x86_64`, run 100 attempt 1: runner lost the database \(expires 2026-12-31\)/);
  });

  test('a waiver never turns a failure into a pass: without another passing attempt the pair is not run', () => {
    const { dir, head } = gitRoot();
    const r = report(dir, ['--waivers', waiverFile(waiver(head)), '--artifacts', artifacts([{ leg: PG, junit: junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]) }], { commit: head })], { commit: head });
    assert.equal(r.code, 0);
    assert.equal(pair(r.json, 'A24', 'M1a', A24_NEG, PG).status, 'not run');
  });

  test('a waiver is not applied when expired, for another attempt, run, test, leg or commit', () => {
    const { dir, head } = gitRoot();
    const cases = [
      [{ expires: '2026-11-18' }, /expired on 2026-11-18; the failure counts/],
      [{ run_attempt: '2' }, /matches no failed attempt/],
      [{ run_id: '101' }, /matches no failed attempt/],
      [{ test: `"${A24_POS.id}"` }, /matches no failed attempt/],
    ];
    for (const [over, re] of cases) {
      const r = report(dir, ['--waivers', waiverFile(waiver(head, over)), '--artifacts', failedThenPassed(head)], { commit: head });
      assert.equal(r.code, 1, JSON.stringify(over));
      assert.equal(pair(r.json, 'A24', 'M1a', A24_NEG, PG).status, 'failed');
      assert.equal(r.json.waivers[0].applied, false);
      assert.match(r.json.waivers[0].why, re);
      assert.match(r.out, /- \*\*not applied\*\*: /);
    }
    const same = report(dir, ['--waivers', waiverFile(waiver(head, { expires: TODAY })), '--artifacts', failedThenPassed(head)], { commit: head });
    assert.equal(same.code, 0, 'a waiver is valid through its expiry date');
    // A waiver for another commit on main is reported as such, not listed.
    git(dir, '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'next');
    git(dir, 'update-ref', 'refs/remotes/origin/main', 'HEAD');
    const next = git(dir, 'rev-parse', 'HEAD');
    const other = report(dir, ['--waivers', waiverFile(waiver(head)), '--artifacts', failedThenPassed(next)], { commit: next });
    assert.equal(other.code, 1);
    assert.equal(other.json.waivers[0].why, 'for another commit');
    assert.equal(other.json.waivers[0].applied, false);
    assert.doesNotMatch(other.out, /Waivers for this commit/);
  });

  test('a waiver for one attempt leaves another failed attempt of the same run failed', () => {
    const { dir, head } = gitRoot();
    const fail = junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]);
    const r = report(dir, ['--waivers', waiverFile(waiver(head)), '--artifacts', artifacts([1, 2].map((attempt) => ({ leg: PG, attempt, junit: fail })).concat([{ leg: PG, attempt: 3, junit: allPass(A24) }]), { commit: head })], {
      commit: head,
    });
    assert.equal(r.code, 1);
    assert.equal(pair(r.json, 'A24', 'M1a', A24_NEG, PG).status, 'failed');
    assert.match(r.out, /a24_neg_replay` on `scenarios-pg\/x86_64`: failed \(failed in run 100 attempt 2\); waiver applied to run 100 attempt 1: /);
  });

  test('a waiver for the same test, run and attempt on another leg does not apply', () => {
    const P = H_POS.id;
    const N = H_NEG.id;
    const X86 = 'scenarios-hermetic/x86_64';
    const ARM = 'scenarios-hermetic/aarch64';
    const fail = (leg, attempt, n) => ({ run_id: 5, run_attempt: attempt, leg, cases: new Map([[P, 'passed'], [N, n]]) });
    const res = judge({
      scenarios: [{ id: 'A64', stage: [{ milestone: 'M1a', scope: 'full row', legs: [X86, ARM], status: 'implemented', tests: [P, N] }] }],
      subcases: [],
      contracts: [],
      commit: SHA,
      today: TODAY,
      waivers: [{ commit: SHA, test: N, leg: ARM, run_id: 5, run_attempt: 1, reason: 'r', expires: '2026-12-31' }],
      reports: [fail(X86, 1, 'failed'), fail(X86, 2, 'passed'), fail(ARM, 1, 'passed')],
    });
    assert.equal(res.stages[0].pairs.find((p) => p.test === N && p.leg === X86).status, 'failed');
    assert.equal(res.waivers[0].applied, false);
    assert.match(res.waivers[0].why, /matches no failed attempt/);
  });

  test('an expired and a valid waiver for the same attempt: the valid one applies', () => {
    const { dir, head } = gitRoot();
    const r = report(dir, ['--waivers', waiverFile(`${waiver(head, { expires: '2026-01-01' })}\n${waiver(head)}`), '--artifacts', failedThenPassed(head)], { commit: head });
    assert.equal(r.code, 0);
    assert.deepEqual(r.json.waivers.map((w) => w.applied), [false, true]);
  });

  test('a waiver for a not-run pair or a planned stage is rejected', () => {
    const { dir, head } = gitRoot();
    const notRun = report(dir, ['--waivers', waiverFile(waiver(head)), '--artifacts', artifacts([{ leg: PG, junit: allPass([A24_POS]) }], { commit: head })], { commit: head });
    assert.equal(notRun.code, 0);
    assert.equal(pair(notRun.json, 'A24', 'M1a', A24_NEG, PG).status, 'not run');
    assert.match(notRun.json.waivers[0].why, /a waiver never applies to not run or planned/);
    assert.match(notRun.out, /- \*\*not applied\*\*: `nextest:.*a24_neg_replay` on `scenarios-pg\/x86_64`, run 100 attempt 1: matches no failed attempt/);
    const planned = report(dir, ['--waivers', waiverFile(waiver(head, { test: `"${A24_POS.id}"` })), '--artifacts', artifacts([{ leg: PG, junit: junit([[A24_POS, 'failed'], [A24_NEG, 'passed']]) }], { commit: head })], { commit: head });
    // A24_POS is in the implemented M1a stage too, where the waiver applies;
    // the planned M2 stage stays planned.
    assert.equal(stage(planned.json, 'A24', 'M2').status, 'planned');
    assert.equal(planned.json.waivers[0].applied_to.length, 1);
  });

  test('waiver file errors stop the report with exit 2', () => {
    const { dir, head } = gitRoot();
    const side = git(dir, 'commit-tree', 'HEAD^{tree}', '-p', head, '-m', 'side');
    // Judging the side commit (same tree): its own waiver must be on main.
    git(dir, 'checkout', '-q', '--detach', side);
    const offMain = report(dir, ['--waivers', waiverFile(waiver(side))], { commit: side });
    assert.equal(offMain.code, 2);
    assert.match(offMain.err, /commit [0-9a-f]{40} is not on main/);
    git(dir, 'checkout', '-q', '--detach', head);
    for (const [text, re] of [
      [waiver(head, { test: '"nextest:skyoauth-scenarios/pg/nope::a24_pos_x"' }), /is not registered in any stage's tests/],
      [waiver(head, { expires: '"2026-12-31"' }), /expires must be a TOML local date/],
      ['[[waiver]\n', /not valid TOML/],
    ]) {
      const r = report(dir, ['--waivers', waiverFile(text), '--artifacts', failedThenPassed(head)], { commit: head });
      assert.equal(r.code, 2, text);
      assert.match(r.err, re);
      assert.match(r.err, /has \d+ error\(s\); no report/);
      assert.equal(r.json, null);
    }
    const missing = report(dir, ['--waivers', join(dir, 'nope.toml')], { commit: head });
    assert.equal(missing.code, 2);
    assert.match(missing.err, /--waivers .*nope\.toml: no such file/);
    // A directory, such as tests/conformance instead of its waivers.toml, or
    // a character device: a usage error with no report, not an internal
    // error and not an empty waiver list.
    for (const path of [join(dir, 'tests', 'conformance'), dir, '/dev/null']) {
      const r = report(dir, ['--waivers', path, '--artifacts', failedThenPassed(head)], { commit: head });
      assert.equal(r.code, 2, path);
      assert.equal(r.err.split('\n')[0], `report-conformance: --waivers ${path}: not a regular file (give the waivers.toml file, not its directory)`);
      assert.doesNotMatch(r.err, /internal error/);
      assert.equal(r.out, '');
      assert.equal(r.json, null);
    }
  });

  test('waivers for other commits get only the shape checks; errors name the --waivers file and line', () => {
    const { dir, head } = gitRoot();
    const other = 'b'.repeat(40);
    // A test and leg this registry does not have, for a commit that is not
    // even in the history: main may hold it for an older or newer commit.
    const foreign = waiver(other, { test: '"nextest:skyoauth-scenarios/pg/x::a24_neg_renamed_later"', leg: '"scenarios-pg/arm64"' });
    const ok = report(dir, ['--require-history', '--waivers', waiverFile(`${foreign}\n${waiver(head)}`), '--artifacts', failedThenPassed(head)], { commit: head });
    assert.equal(ok.code, 0, ok.err);
    assert.doesNotMatch(ok.out, /reachability/, 'no history note for the waivers of other commits');
    const noHist = report(dir, ['--waivers', waiverFile(foreign), '--artifacts', failedThenPassed(head)], { commit: head });
    assert.doesNotMatch(noHist.out, /reachability/);
    assert.deepEqual(ok.json.waivers.map((w) => [w.commit, w.applied, w.why ?? null]), [
      [other, false, 'for another commit'],
      [head, true, null],
    ]);
    assert.doesNotMatch(ok.out, /renamed_later/);
    for (const [bad, re] of [
      [{ commit: '"B"' }, /:1: error \[waivers\] commit must be a full 40-character lowercase hex SHA$/m],
      [{ expires: '"2026-12-31"' }, /:1: error \[waivers\] expires must be a TOML local date/m],
      [{ run_id: '0' }, /:1: error \[waivers\] run_id must be a positive integer/m],
      [{ color: '"red"' }, /:1: error \[waivers\] unknown field color/m],
    ]) {
      const f = waiverFile(waiver(other, bad));
      const r = report(dir, ['--waivers', f], { commit: head });
      assert.equal(r.code, 2, JSON.stringify(bad));
      assert.ok(r.err.startsWith(`${f}:`), r.err);
      assert.match(r.err, re);
      assert.doesNotMatch(r.err, /tests\/conformance\/waivers\.toml/);
    }
    // The waiver for the judged commit keeps its own line (10, after a
    // foreign waiver of 8 lines and a blank line) and gets the full rule.
    const f = waiverFile(`${foreign}\n${waiver(head, { leg: '"scenarios-pg/arm64"' })}`);
    const mine = report(dir, ['--waivers', f], { commit: head });
    assert.equal(mine.code, 2);
    assert.ok(mine.err.startsWith(`${f}:10: error [waivers] leg "scenarios-pg/arm64" is not a leg of a stage that lists`), mine.err);
  });

  test('in a git checkout, --root must be a checkout of --commit, unless --allow-commit-mismatch, which makes the report untrusted', () => {
    const { dir, head } = gitRoot();
    const other = 'b'.repeat(40);
    const stop = report(dir, ['--artifacts', failedThenPassed(other)], { commit: other });
    assert.equal(stop.code, 2);
    assert.equal(stop.json, null);
    assert.equal(stop.err, `report-conformance: --root is a checkout of ${head}, not of --commit ${other}, so its registry is not the judged commit's; no report (--allow-commit-mismatch prints it as untrusted)`);
    const loose = report(dir, ['--allow-commit-mismatch', '--artifacts', failedThenPassed(other)], { commit: other });
    assert.equal(loose.code, 2);
    assert.equal(loose.json.trusted, false);
    assert.deepEqual(loose.json.input_errors, [`--root is a checkout of ${head}, not of --commit ${other}, so its registry is not the judged commit's (--allow-commit-mismatch)`]);
    assert.equal(stage(loose.json, 'A24', 'M1a').status, 'failed');
    const same = report(dir, ['--artifacts', failedThenPassed(head)], { commit: head });
    assert.equal(same.code, 1);
    assert.equal(same.json.trusted, true);
    assert.deepEqual(same.json.notes, []);
    assert.equal(checkoutHead(dir), head);
    assert.equal(checkoutHead(join(dir, 'tests')), undefined, 'a subdirectory is not the checkout');
    const empty = tmp('report-git-');
    git(empty, 'init', '-q');
    assert.equal(checkoutHead(empty), null);
    const none = report(empty, [], { commit: head });
    assert.equal(none.code, 2);
    assert.match(none.err, /--root is a checkout of no commit, not of --commit/);
  });

  // A git hook or `git rebase --exec` exports GIT_DIR and its kin; git -C
  // obeys them, so a plain directory would pass as a checkout of another
  // repository's HEAD and get a gate verdict.
  test('an inherited GIT_DIR does not bind a plain directory to --commit', () => {
    const other = root(withA24);
    const head = commitRoot(other);
    const plainRoot = root(withA24);
    const gitDir = join(other, '.git');
    const UNBOUND = "--require-milestone needs --root bound to --commit, but --root is not a git checkout, so its registry is not known to be the judged commit's";
    for (const env of [{ GIT_DIR: gitDir }, { GIT_DIR: gitDir, GIT_WORK_TREE: plainRoot }, { GIT_DIR: gitDir, GIT_COMMON_DIR: gitDir, GIT_INDEX_FILE: join(gitDir, 'index'), GIT_OBJECT_DIRECTORY: join(gitDir, 'objects') }]) {
      const j = join(tmp('report-out-'), 'r.json');
      const p = spawnSync(process.execPath, [SCRIPT, '--root', plainRoot, '--commit', head, '--today', TODAY, '--require-milestone', 'M1a', '--json', j], { encoding: 'utf8', env: { ...childEnv(), ...env } });
      assert.equal(p.status, 2, `${Object.keys(env)}: ${p.stderr}`);
      const json = JSON.parse(readFileSync(j, 'utf8'));
      assert.equal(json.trusted, false);
      assert.deepEqual(json.input_errors, [UNBOUND]);
    }
  });

  // The git fixtures above, and the run on the repository below, with an
  // absolute GIT_DIR exported (as in a git hook): they pass and leave that
  // repository alone.
  test('the git fixtures are immune to an inherited GIT_DIR', () => {
    assertGitImmune(fileURLToPath(import.meta.url), ['^in a git checkout, --root must be', '^an inherited GIT_DIR does not bind', '^the script runs on the repository', '^the gate job \\(layout']);
  });

  test('without history a waiver commit is not checked (note), unless --require-history', () => {
    const dir = root(withA24);
    const soft = report(dir, ['--waivers', waiverFile(waiver(SHA)), '--artifacts', failedThenPassed()]);
    assert.equal(soft.code, 0, soft.err);
    assert.match(soft.out, /^note: waivers: commit reachability not checked: the root is not a git checkout/m);
    const strict = report(dir, ['--require-history', '--waivers', waiverFile(waiver(SHA))]);
    assert.equal(strict.code, 2);
    assert.match(strict.err, /--require-history: cannot check waiver commits against origin\/main: the root is not a git checkout/);
    assert.match(strict.err, /the registry has 1 error\(s\); no report/);
  });
});

describe('registry check notes', () => {
  test('notes of the registry check on --root are printed', () => {
    const dir = root(withA24);
    write(join(dir, 'tests/conformance/waivers.toml'), `[[waiver]]\ncommit = "${SHA}"\ntest = "${A24_NEG.id}"\nleg = "${PG}"\nrun_id = 1\nrun_attempt = 1\nreason = "r"\nexpires = 2026-12-31\n`);
    const r = report(dir);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /^note: waivers: commit reachability not checked: the root is not a git checkout$/m);
  });
});

describe('docs-only', () => {
  test('prints "runtime conformance: not run (docs-only change)" and reports nothing as passed', () => {
    const r = report(root(withA24), ['--docs-only']);
    assert.equal(r.code, 0);
    assert.match(r.out, /^## Conformance results for `a{40}`\n\n\*\*runtime conformance: not run \(docs-only change\)\*\*\n/);
    assert.equal(r.json.headline, 'runtime conformance: not run (docs-only change)');
    assert.equal(r.json.docs_only, true);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'not run');
    assert.equal(boundReport(root(withA24), null, ['--docs-only', '--require-milestone', 'M1a']).code, 1);
  });
});

describe('input errors', () => {
  test('malformed JUnit: exit 2, listed, and its results are not used', () => {
    const truncated = allPass(A24).slice(0, -30);
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: truncated }])]);
    assert.equal(r.code, 2);
    assert.match(r.err, /1 input error\(s\)/);
    assert.match(plain(r.out), /\*\*Input errors: this report cannot be trusted \(1\)\.\*\*\n\n- 100\/junit-scenarios-pg-x86_64-attempt-1\/junit\.xml: malformed JUnit: line \d+: <testsuite> is not closed; its results are not used/);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'not run');
    assert.equal(r.json.reports.length, 0);
    assert.equal(r.json.input_errors.length, 1);
  });

  test('duplicate artifacts for one (run, attempt, leg): exit 2, and a failure in either copy counts', () => {
    const r = report(root(withA24), [
      '--artifacts',
      artifacts([
        { leg: PG, name: 'junit-scenarios-pg-x86_64-attempt-1', junit: allPass(A24) },
        { leg: PG, name: 'copy-attempt-1', junit: junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]) },
      ]),
    ]);
    assert.equal(r.code, 2);
    assert.match(plain(r.out), /- 100\/junit-scenarios-pg-x86_64-attempt-1: duplicate artifact for leg scenarios-pg\/x86_64, run 100 attempt 1 \(also 100\/copy-attempt-1\)/);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'failed');
    assert.equal(r.json.reports.length, 2);
  });

  test('a run directory that is not a run ID, a stray file, an unknown leg, or a name without attempt-N', () => {
    const d = artifacts([
      { leg: 'scenarios-pg/arm64', junit: allPass(A24) },
      { leg: PG, name: 'junit-scenarios-pg-x86_64', junit: allPass(A24) },
      { leg: PG, name: 'junit-attempt-0', junit: allPass(A24) },
      { leg: PG, name: 'xattempt-3', junit: allPass(A24) },
    ]);
    mkdirSync(join(d, 'latest'));
    mkdirSync(join(d, '0'));
    writeFileSync(join(d, '7'), '');
    writeFileSync(join(d, '100', 'stray.txt'), '');
    write(join(d, '9', 'junit-scenarios-pg-x86_64-attempt-9', 'leg'), `${PG}\n`);
    runJson(d, 9, { attempt: 9 });
    write(join(d, '9', 'junit-scenarios-pg-x86_64-attempt-9', 'junit.xml'), allPass(A24));
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 2);
    const errs = r.json.input_errors;
    assert.deepEqual(errs, [
      '0: every entry of the artifacts directory is a directory named by a workflow run ID',
      '100/junit-attempt-0: the artifact name does not end in attempt-N, so its run attempt is unknown',
      '100/junit-scenarios-pg-arm64-attempt-1: leg file names "scenarios-pg/arm64", which is not a layout §1.1 leg string',
      '100/junit-scenarios-pg-x86_64: the artifact name does not end in attempt-N, so its run attempt is unknown',
      '100/stray.txt: a run directory holds only artifact directories',
      '100/xattempt-3: the artifact name does not end in attempt-N, so its run attempt is unknown',
      '7: every entry of the artifacts directory is a directory named by a workflow run ID',
      'latest: every entry of the artifacts directory is a directory named by a workflow run ID',
    ]);
    assert.deepEqual(r.json.ignored_artifacts, []);
    assert.deepEqual(r.json.reports.map((x) => [x.run_id, x.run_attempt, x.leg]), [[9, 9, PG]]);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'passed');
  });

  test('a directory or symbolic link where a file belongs, or a symbolic link anywhere, is an input error with a report, not an internal error', () => {
    const name = 'junit-scenarios-pg-x86_64-attempt-1';
    const d = artifacts([
      { run: 1, leg: null, name, junit: allPass(A24) },
      { run: 2, leg: PG, name, junit: null },
      { run: 3, leg: null, name, junit: allPass(A24) },
      { run: 4, leg: PG, name, junit: null },
      { run: 5, leg: PG, name, junit: null },
      { run: 6, leg: PG, name: 'real-attempt-1', junit: allPass(A24) },
      { run: 8, leg: PG, name, junit: allPass(A24) },
    ]);
    mkdirSync(join(d, '1', name, 'leg'));
    mkdirSync(join(d, '2', name, 'junit.xml'));
    symlinkSync(join(d, 'nowhere'), join(d, '3', name, 'leg'));
    symlinkSync(join(d, '6', 'real-attempt-1', 'junit.xml'), join(d, '4', name, 'junit.xml'));
    symlinkSync(join(d, '6', 'real-attempt-1'), join(d, '5', 'linked-attempt-1'));
    symlinkSync(join(d, '6'), join(d, '7'));
    symlinkSync(join(d, 'nowhere'), join(d, '8', name, 'ci'));
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 2);
    const LINK = 'a symbolic link; the artifacts tree holds plain files and directories only';
    assert.deepEqual(r.json.input_errors, [
      `1/${name}/leg: a directory, not a regular file`,
      `2/${name}/junit.xml: a directory, not a regular file`,
      `3/${name}: leg: ${LINK}`,
      `4/${name}: junit.xml: ${LINK}`,
      `5/linked-attempt-1: ${LINK}`,
      '7: every entry of the artifacts directory is a directory named by a workflow run ID',
      `8/${name}: ci: ${LINK}`,
    ]);
    assert.match(r.out, /\*\*Input errors: this report cannot be trusted \(7\)\.\*\*/);
    assert.deepEqual(r.json.reports.map((x) => x.artifact), ['5/junit-scenarios-pg-x86_64-attempt-1', '6/real-attempt-1']);
  });

  test('a FIFO where the leg file belongs is an input error', { skip: process.platform === 'win32' }, () => {
    const name = 'junit-scenarios-pg-x86_64-attempt-1';
    const d = artifacts([{ leg: null, name, junit: allPass(A24) }]);
    const mk = spawnSync('mkfifo', [join(d, '100', name, 'leg')]);
    assert.equal(mk.status, 0, String(mk.stderr));
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 2);
    assert.deepEqual(r.json.input_errors, [`100/${name}/leg: a special file, not a regular file`]);
  });

  test('deeply nested XML is an input error, not a stack overflow', () => {
    const deep = (n) => `${'<testsuites>'.repeat(n)}${'</testsuites>'.repeat(n)}`;
    assert.deepEqual(readJUnit(deep(MAX_DEPTH)), []);
    assert.throws(() => readJUnit(deep(MAX_DEPTH + 1)), (ex) => ex instanceof InputError && /elements nested more than 100 deep/.test(ex.message));
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: deep(100000) }])]);
    assert.equal(r.code, 2);
    assert.match(r.json.input_errors[0], /junit\.xml: malformed JUnit: line 1: elements nested more than 100 deep; its results are not used$/);
  });

  test('run.json binds each run to the judged commit: a missing or mismatched one is an input error and the run is not used', () => {
    const fail = junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]);
    const runs = {
      1: null,
      2: { headSha: 'b'.repeat(40) },
      3: { databaseId: 33 },
      4: { databaseId: '4' },
      5: { attempt: 0 },
      6: { attempt: 1.5 },
      7: { workflowName: '' },
      8: { workflowName: 7 },
      9: { attempt: 1 },
    };
    const spec = Object.keys(runs).map((run) => ({ run: Number(run), leg: PG, attempt: run === '9' ? 2 : 1, junit: fail }));
    const d = artifacts([...spec, { run: 9, leg: PG, attempt: 1, junit: allPass(A24) }, { run: 10, leg: PG, junit: allPass(A24) }, { run: 11, leg: PG, junit: fail }, { run: 12, leg: PG, junit: fail }, { run: 13, leg: PG, junit: fail }, { run: 14, leg: PG, junit: fail }], { runs });
    write(join(d, '11', 'run.json'), '{"headSha": ');
    write(join(d, '12', 'run.json'), '[]');
    rmSync(join(d, '13', 'run.json'));
    mkdirSync(join(d, '13', 'run.json'));
    write(join(d, '14', 'run.json'), `{"x": "${'y'.repeat(64 * 1024)}"}`);
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 2);
    const NOT = "; the run's artifacts are not used";
    assert.deepEqual(r.json.input_errors, [
      `1/run.json: missing (gh run view RUN_ID --json databaseId,headSha,attempt,workflowName), so the run cannot be bound to the commit${NOT}`,
      `11/run.json: not JSON (${r.json.input_errors[1].replace(/^11\/run\.json: not JSON \((.*)\); the run.*$/, '$1')})${NOT}`,
      `12/run.json: not a JSON object${NOT}`,
      `13/run.json: a directory, not a regular file${NOT}`,
      `14/run.json: more than 65536 bytes${NOT}`,
      `2/run.json: headSha is "${'b'.repeat(40)}", not the judged commit ${SHA}${NOT}`,
      `3/run.json: databaseId is 33, not the directory's run ID 3${NOT}`,
      `4/run.json: databaseId is "4", not the directory's run ID 4${NOT}`,
      `5/run.json: attempt is 0, not a positive integer${NOT}`,
      `6/run.json: attempt is 1.5, not a positive integer${NOT}`,
      `7/run.json: workflowName is not a non-empty string${NOT}`,
      `8/run.json: workflowName is not a non-empty string${NOT}`,
      "9/junit-scenarios-pg-x86_64-attempt-2: attempt 2, but 9/run.json says the run has 1 attempt(s); its results are not used",
    ]);
    assert.match(r.json.input_errors[1], /^11\/run\.json: not JSON \(.+\); the run's artifacts are not used$/);
    // Only run 10 and attempt 1 of run 9, both passing, are joined.
    assert.deepEqual(r.json.reports.map((x) => x.artifact), ['10/junit-scenarios-pg-x86_64-attempt-1', '9/junit-scenarios-pg-x86_64-attempt-1']);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'passed');
    assert.equal(r.json.trusted, false);
  });

  test('run.json: null is not an object; exactly 64 KiB is read', () => {
    const d = artifacts([{ run: 1, leg: PG, junit: allPass(A24) }, { run: 2, leg: PG, junit: allPass(A24) }]);
    write(join(d, '1', 'run.json'), 'null');
    const base = JSON.stringify({ attempt: 1, databaseId: 2, headSha: SHA, workflowName: '' });
    write(join(d, '2', 'run.json'), JSON.stringify({ attempt: 1, databaseId: 2, headSha: SHA, workflowName: 'w'.repeat(64 * 1024 - base.length) }));
    assert.equal(readFileSync(join(d, '2', 'run.json')).length, 64 * 1024);
    const r = report(root(withA24), ['--artifacts', d]);
    assert.deepEqual(r.json.input_errors, ["1/run.json: not a JSON object; the run's artifacts are not used"]);
    assert.deepEqual(r.json.reports.map((x) => x.run_id), [2]);
  });

  test('an artifacts path that cannot be read is an input error, not an internal one', () => {
    const f = join(tmp('report-file-'), 'file');
    writeFileSync(f, '');
    const notDir = report(root(withA24), ['--artifacts', join(f, 'x')]);
    assert.equal(notDir.code, 2);
    assert.deepEqual(notDir.json.input_errors, [`${join(f, 'x')}: cannot be read (ENOTDIR)`]);
    const loop = join(tmp('report-loop-'), 'loop');
    symlinkSync(loop, loop);
    const looped = report(root(withA24), ['--artifacts', loop]);
    assert.deepEqual(looped.json.input_errors, [`${loop}: cannot be read (ELOOP)`]);
  });

  test('a leg file of exactly 1024 bytes is read; 1025 is too many', () => {
    const name = 'junit-scenarios-pg-x86_64-attempt-1';
    const d = artifacts([{ run: 1, leg: PG, name, junit: allPass(A24) }, { run: 2, leg: PG, name, junit: allPass(A24) }]);
    writeFileSync(join(d, '1', name, 'leg'), `${PG}${' '.repeat(1024 - PG.length)}`);
    writeFileSync(join(d, '2', name, 'leg'), `${PG}${' '.repeat(1025 - PG.length)}`);
    const r = report(root(withA24), ['--artifacts', d]);
    assert.deepEqual(r.json.input_errors, [`2/${name}/leg: 1025 bytes, more than the 1024 it may hold; not read`]);
    assert.deepEqual(r.json.reports.map((x) => x.run_id), [1]);
  });

  test('a run directory with only run.json is a run without artifacts', () => {
    const d = tmp('report-art-');
    runJson(d, 5);
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json.input_errors, []);
  });

  test('a missing artifacts directory is an input error', () => {
    const r = report(root(withA24), ['--artifacts', join(tmp('report-none-'), 'nope')]);
    assert.equal(r.code, 2);
    assert.match(r.json.input_errors[0], /the artifacts directory does not exist/);
  });

  test('only the known non-conformance artifacts (service-nextest-junit-N, coverage, conformance-report-N) may lack a leg file; they are ignored with a note', () => {
    const d = artifacts([
      { leg: null, name: 'service-nextest-junit-1', junit: junit([[A24_NEG, 'failed']]) },
      { leg: null, name: 'service-nextest-junit-12', junit: null },
      { leg: null, name: 'rust-coverage', junit: null },
      { leg: null, name: 'typescript-coverage', junit: null },
      { leg: null, name: 'conformance-report-3', junit: null },
      { leg: PG, junit: allPass(A24) },
    ]);
    write(join(d, '100', 'rust-coverage', 'html', 'index.html'), '<html/>');
    write(join(d, '100', 'typescript-coverage', 'lcov.info'), '');
    write(join(d, '100', 'conformance-report-3', 'conformance-report.json'), '{}\n');
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 0, r.err);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'passed');
    assert.deepEqual(r.json.ignored_artifacts, ['100/conformance-report-3', '100/rust-coverage', '100/service-nextest-junit-1', '100/service-nextest-junit-12', '100/typescript-coverage']);
    assert.match(r.out, /note: 5 artifact\(s\) without a `leg` file ignored \(not conformance legs\): `100\/conformance-report-3`/);
  });

  test('every artifact the workflows upload is a leg artifact or a known non-conformance artifact', () => {
    // Fails when a workflow gains an artifact without a `leg` file: add it to
    // NOT_CONFORMANCE (or upload a leg file with it), or the reporter calls
    // it an input error. A NOT_CONFORMANCE entry no workflow uploads fails too.
    const uploads = workflowUploads(repoWorkflows());
    assert.ok(uploads.length > 0, 'no upload-artifact steps found');
    const asNamed = (name) => name.replace(/\$\{\{\s*github\.run_attempt\s*\}\}/g, '1');
    const bad = uploads.filter(({ name, paths }) => {
      assert.ok(name, 'an upload step without a name');
      const leg = paths.some((x) => /(^|\/)leg$/.test(x));
      return leg ? !/-attempt-\$\{\{\s*github\.run_attempt\s*\}\}$/.test(name) : !NOT_CONFORMANCE.some((re) => re.test(asNamed(name)));
    });
    assert.deepEqual(bad, [], 'leg artifacts must end in attempt-${{ github.run_attempt }}; others need a NOT_CONFORMANCE entry');
    assert.deepEqual(NOT_CONFORMANCE.filter((re) => !uploads.some(({ name }) => re.test(asNamed(name)))).map(String), [], 'NOT_CONFORMANCE entries no workflow uploads');
  });

  // The scan above only sees block-style steps, so it must not pass over an
  // upload written another way: that artifact would escape the
  // NOT_CONFORMANCE check the README and ci.yml promise.
  test('the upload scan fails closed: an upload-artifact line it does not parse is an error', () => {
    const [wf, text] = repoWorkflows().find(([f]) => f === 'ci.yml');
    const n = workflowUploads([[wf, text]]).length;
    assert.ok(n > 0);
    for (const extra of [
      '      - { name: Upload, uses: actions/upload-artifact@v7, with: { name: stray, path: x } }',
      '      - name: Upload\n        uses: "actions/upload-artifact@v7"\n        with:\n          name: stray\n          path: x',
      '      - name: Upload\n        uses: Actions/Upload-Artifact@v7\n        with:\n          name: stray\n          path: x',
      '      -   uses: actions/upload-artifact@v7\n          with:\n            name: stray\n            path: x',
    ]) {
      assert.throws(() => workflowUploads([[wf, `${text}${extra}\n`]]), new RegExp(`^AssertionError.*${wf}: ${n + 1} non-comment line\\(s\\) name upload-artifact, ${n} upload step\\(s\\) parsed`, 's'), extra);
    }
    // A comment is not an upload.
    assert.equal(workflowUploads([[wf, `${text}      # - uses: actions/upload-artifact@v7\n`]]).length, n);
  });

  test('a failed attempt whose artifact lost its leg file does not vanish: input error, exit 2', () => {
    const r = report(root(withA24), [
      '--artifacts',
      artifacts([
        { leg: null, name: 'junit-scenarios-pg-x86_64-attempt-1', junit: junit([[A24_POS, 'passed'], [A24_NEG, 'failed']]) },
        { leg: PG, attempt: 2, junit: allPass(A24) },
      ]),
    ]);
    assert.equal(r.code, 2);
    assert.deepEqual(r.json.input_errors, [
      '100/junit-scenarios-pg-x86_64-attempt-1: no leg file, and not a known artifact of a non-conformance job (^service-nextest-junit-[1-9]\\d*$, ^rust-coverage$, ^typescript-coverage$, ^conformance-report-[1-9]\\d*$); its results cannot be placed',
    ]);
    assert.deepEqual(r.json.ignored_artifacts, []);
    assert.match(r.out, /\*\*Input errors: this report cannot be trusted \(1\)\.\*\*/);
  });

  test('an unknown artifact without a leg file, a leg or junit.xml one level down, or an extra file in a leg artifact is an input error', () => {
    const d = artifacts([
      { leg: null, name: 'stray', junit: allPass(A24) },
      { leg: null, name: 'empty-dir', junit: null },
      { leg: null, name: 'service-nextest-junit-0', junit: null },
      { leg: null, name: 'rust-coverage-attempt-1', junit: null },
      { leg: null, name: 'nested-attempt-1', junit: null },
      { leg: null, name: 'nested-junit-attempt-1', junit: null },
      { leg: PG, name: 'both-attempt-1', junit: allPass(A24) },
      { leg: PG, name: 'extra-attempt-1', junit: allPass(A24) },
      { leg: null, name: 'rust-coverage', junit: null },
    ]);
    write(join(d, '100', 'nested-attempt-1', 'ci', 'leg'), `${PG}\n`);
    write(join(d, '100', 'nested-junit-attempt-1', 'ci', 'junit.xml'), allPass(A24));
    write(join(d, '100', 'both-attempt-1', 'ci', 'junit.xml'), junit([[A24_NEG, 'failed']]));
    write(join(d, '100', 'extra-attempt-1', 'notes.txt'), 'x');
    write(join(d, '100', 'rust-coverage', 'sub', 'junit.xml'), junit([[A24_NEG, 'failed']]));
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 2);
    const NO_LEG = 'no leg file, and not a known artifact of a non-conformance job';
    assert.deepEqual(r.json.input_errors.map((e) => e.replace(/ \(\^service.*$/, '')), [
      '100/both-attempt-1: ci/ holds a leg or junit.xml file; they belong at the top of the artifact',
      `100/empty-dir: ${NO_LEG}`,
      '100/extra-attempt-1: a leg artifact holds only leg and junit.xml, not notes.txt',
      '100/nested-attempt-1: ci/ holds a leg or junit.xml file; they belong at the top of the artifact',
      '100/nested-junit-attempt-1: ci/ holds a leg or junit.xml file; they belong at the top of the artifact',
      '100/rust-coverage: sub/ holds a leg or junit.xml file; they belong at the top of the artifact',
      `100/rust-coverage-attempt-1: ${NO_LEG}`,
      `100/service-nextest-junit-0: ${NO_LEG}`,
      `100/stray: ${NO_LEG}`,
    ]);
    assert.deepEqual(r.json.reports, []);
  });
});

// ---------------------------------------------------------------------------
// Workflow upload steps (also used by the artifact tests above).

// The upload-artifact steps of the workflow files `files` ([name, text]
// pairs): { at, name, paths } each, from a block-style step
// (`uses: actions/upload-artifact@...` on its own line, `with:` below).
// Fails closed: every line that names upload-artifact, other than a
// comment, must be the `uses:` line of a step parsed here.
const workflowUploads = (files) => {
  const uploads = [];
  for (const [wf, text] of files) {
    const lines = text.split('\n');
    const parsed = uploads.length;
    lines.forEach((l, i) => {
      if (!/^\s*(- )?uses: actions\/upload-artifact@/.test(l)) return;
      // The step's `with:` block: the lines after `uses:` indented deeper
      // than the step's keys.
      const indent = l.search(/\S/) + (l.trimStart().startsWith('- ') ? 2 : 0);
      const block = [];
      for (let j = i + 1; j < lines.length && (lines[j].trim() === '' || lines[j].search(/\S/) >= indent); j++) {
        if (lines[j].search(/\S/) === indent && !/^\s*with:/.test(lines[j])) break;
        block.push(lines[j]);
      }
      const name = block.map((b) => b.match(/^\s*name:\s*(.+?)\s*$/)).find(Boolean)?.[1];
      // `path:` is one path, or a `|` block of one per line.
      const paths = [];
      const p = block.findIndex((b) => /^\s*path:/.test(b));
      if (p >= 0) {
        paths.push(block[p].replace(/^\s*path:\s*\|?\s*/, ''));
        for (let k = p + 1; k < block.length && block[k].search(/\S/) > block[p].search(/\S/); k++) paths.push(block[k].trim());
      }
      uploads.push({ at: `${wf}:${i + 1}`, name, paths });
    });
    const named = lines.filter((l) => /upload-artifact/i.test(l) && !/^\s*#/.test(l)).length;
    assert.equal(named, uploads.length - parsed, `${wf}: ${named} non-comment line(s) name upload-artifact, ${uploads.length - parsed} upload step(s) parsed; write each upload step block-style (\`uses: actions/upload-artifact@...\` on its own line)`);
  }
  return uploads;
};
const repoWorkflows = () => readdirSync(join(REPO, '.github', 'workflows')).filter((f) => /\.ya?ml$/.test(f)).sort().map((wf) => [wf, repoText(join('.github', 'workflows', wf))]);

// ---------------------------------------------------------------------------
// The informational `conformance-report` job in ci.yml and its script,
// scripts/ci/report-conformance-ci.sh (layout §3 "Leg artifacts").

const CI_SH = join(dirname(SCRIPT), 'report-conformance-ci.sh');
const REPORT_JOB = 'conformance-report';
const REPORT_STEP = /^ {8}run: sh scripts\/ci\/report-conformance-ci\.sh$/m;
// The lines of a `key: |` block at `indent` spaces in a step.
const blockOf = (text, key, indent = 10) => {
  const m = new RegExp(`^ {${indent}}${key}: \\|\\n((?: {${indent + 2}}.*\\n)*)`, 'm').exec(text ?? '');
  return m ? m[1].split('\n').filter(Boolean).map((l) => l.trim()) : null;
};
const ciText = () => repoText(join('.github', 'workflows', 'ci.yml'));
// The jobs of a workflow: id -> the job's body (its lines indented four or
// more spaces), from the top-level `jobs:` key.
const workflowJobs = (text) => {
  const at = text.search(/^jobs:\n/m);
  assert.ok(at >= 0, 'no top-level jobs: key');
  const jobs = new Map();
  for (const m of text.slice(at).matchAll(/^ {2}([A-Za-z0-9_-]+):\n((?:(?: {4}.*)?\n)*)/gm)) jobs.set(m[1], m[2]);
  return jobs;
};
// A job's `needs`: inline (`needs: x`, `needs: [x, y]`) or a block list.
const needsOf = (body) => {
  const inline = /^ {4}needs: *(.+)$/m.exec(body);
  if (inline && inline[1].trim() !== '') return inline[1].replace(/^\[|\]$/g, '').split(',').map((s) => s.trim()).filter(Boolean);
  const block = /^ {4}needs:\n((?: {6}- .*\n)+)/m.exec(body);
  return block ? block[1].split('\n').filter(Boolean).map((l) => l.replace(/^ {6}- /, '').trim()) : [];
};
// A job's `if:` as one expression: a plain value, or a folded (`>-`) block
// joined with single spaces as YAML folds it, with a surrounding `${{ }}`
// removed.
const jobIf = (body) => {
  const m = /^ {4}if: *(.*)\n((?: {6}.*\n)*)/m.exec(body);
  if (!m) return null;
  const expr = m[1] === '>-' ? m[2].split('\n').map((l) => l.trim()).filter(Boolean).join(' ') : m[1].trim();
  return /^\$\{\{\s*(.*?)\s*\}\}$/.exec(expr)?.[1] ?? expr;
};
// The steps of a job body, each as its text from `- ` to the next step.
const stepsOf = (body) => body.split(/^(?= {6}- )/m).filter((s) => s.startsWith('      - '));
const stepNamed = (body, re) => stepsOf(body).filter((s) => re.test(s));
// The value of `key:` at `indent` spaces in a step or job text (values such
// as `${{ runner.temp }}/x` hold spaces).
const value = (text, key, indent = 10) => new RegExp(`^ {${indent}}${key}: *(.+?) *$`, 'm').exec(text ?? '')?.[1];
// The artifact name an upload step gives in attempt `n`.
const inAttempt = (name, n = 1) => name.replace(/\$\{\{\s*github\.run_attempt\s*\}\}/g, String(n));
// A download-artifact pattern (`*` only, as used here) as a RegExp.
const globRe = (glob) => new RegExp(`^${glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*')}$`);
// The leg id of a leg string (layout §3 "Leg artifacts").
const legId = (leg) => leg.replaceAll('/', '-');
// The leg artifacts of workflow file `wf`, per job: [{ wf, job, at, name,
// paths, leg }].
const legUploads = (text, wf = 'ci.yml') =>
  [...workflowJobs(text)].flatMap(([job, body]) =>
    workflowUploads([[`${wf}#${job}`, body]])
      .filter(({ paths }) => paths.some((x) => /(^|\/)leg$/.test(x)))
      .map((u) => ({ wf, job, ...u, body, leg: /^ {6}SKYOAUTH_CONFORMANCE_LEG: *(\S+)$/m.exec(body)?.[1] ?? null })),
  );

describe('the conformance-report CI job', () => {
  const catalogue = parseEnvironments(repoText(LAYOUT), []).catalogue;

  test('leg artifacts follow the layout §3 naming contract in every workflow, and the layout lists the legs that upload', () => {
    // Every workflow file: a leg of a schedule-only workflow follows the same
    // contract, although conformance-report cannot need its job.
    const uploads = repoWorkflows().flatMap(([wf, text]) => legUploads(text, wf));
    assert.ok(uploads.some((u) => u.wf === 'ci.yml'), 'no leg artifact in ci.yml');
    for (const u of uploads) {
      // A matrix leg would come from an expression; extend this test then.
      assert.ok(u.leg, `${u.at}: job ${u.job} uploads a leg artifact but sets no literal SKYOAUTH_CONFORMANCE_LEG`);
      assert.ok(catalogue.has(u.leg), `${u.at}: ${u.leg} is not a layout §1.1 leg string`);
      assert.equal(u.name, `junit-${legId(u.leg)}-attempt-\${{ github.run_attempt }}`, `${u.at}: the artifact name`);
      // Both files at the top of the artifact: one directory holds them. (A
      // `path: |` block starts with an empty entry.)
      const paths = u.paths.filter(Boolean);
      const dirs = new Set(paths.map((x) => dirname(x)));
      assert.deepEqual(paths.map((x) => x.slice(x.lastIndexOf('/') + 1)).sort(), ['junit.xml', 'leg'], `${u.at}: a leg artifact uploads exactly junit.xml and leg`);
      assert.equal(dirs.size, 1, `${u.at}: junit.xml and leg come from one directory, so both land at the top of the artifact`);
      const step = stepNamed(u.body, /uses: actions\/upload-artifact@/)[0];
      assert.match(step, /^ {8}if: always\(\)$/m, `${u.at}: the upload runs whatever the tests did`);
    }
    // Leg ids are distinct across the whole §1.1 column, so no two legs can
    // ever upload under one name.
    const byId = new Map();
    for (const leg of catalogue.keys()) byId.set(legId(leg), [...(byId.get(legId(leg)) ?? []), leg]);
    assert.deepEqual([...byId.values()].filter((l) => l.length > 1), [], 'leg strings with the same leg id');
    // "Legs that upload today" names exactly the legs ci.yml uploads.
    const line = repoText(LAYOUT)
      .split('\n')
      .find((l) => l.startsWith('  - **Legs that upload today.**'));
    assert.ok(line, 'layout §3 has no "Legs that upload today" bullet');
    const listed = [...line.matchAll(/`([^`]+)`/g)].map((m) => m[1]).filter((x) => catalogue.has(x));
    assert.deepEqual(listed.sort(), uploads.map((u) => u.leg).sort());
    for (const u of uploads) assert.ok(line.includes(`\`${inAttempt(u.name, 'N')}\``), `the layout names ${inAttempt(u.name, 'N')}`);
  });

  test('it needs every ci.yml job that uploads a leg artifact and downloads each by the name that job gives, never by a pattern', () => {
    const text = ciText();
    const jobs = workflowJobs(text);
    const body = jobs.get(REPORT_JOB);
    assert.ok(body, `no ${REPORT_JOB} job`);
    const needs = needsOf(body);
    assert.ok(needs.includes('changes'), 'needs changes, for its classification');
    const legs = legUploads(text);
    const [report, ...moreReports] = stepNamed(body, REPORT_STEP);
    assert.ok(report && moreReports.length === 0, 'one report step');
    const downloadDir = value(report, 'DOWNLOAD_DIR');
    const artifactsDir = value(report, 'ARTIFACTS');
    assert.ok(downloadDir && artifactsDir, 'the report step sets DOWNLOAD_DIR and ARTIFACTS');
    assert.ok(!`${downloadDir}/`.startsWith(`${artifactsDir}/`) && !`${artifactsDir}/`.startsWith(`${downloadDir}/`), 'the downloads and the artifacts tree the script builds are apart');
    const downloads = stepNamed(body, /uses: actions\/download-artifact@/);
    assert.equal(downloads.length, legs.length, 'one download step per leg job');
    const lines = [];
    for (const u of legs) {
      const out = `needs.${u.job}.outputs.junit-artifact`;
      assert.ok(needs.includes(u.job), `${REPORT_JOB} must need ${u.job}, which uploads a leg artifact: it would race the upload and could not read its output`);
      // The leg job names what it uploaded, from the attempt it ran in, and
      // nothing when the upload produced no artifact.
      const upload = stepNamed(u.body, /uses: actions\/upload-artifact@/)[0];
      const id = /^ {8}id: *(\S+)$/m.exec(upload)?.[1];
      assert.ok(id, `${u.at}: the upload step has an id`);
      const outputs = /^ {4}outputs:\n((?: {6}.*\n)+)/m.exec(u.body)?.[1] ?? '';
      const fmt = u.name.replace('${{ github.run_attempt }}', '{0}');
      assert.ok(!fmt.includes('${{'), `${u.at}: the name holds no other expression`);
      assert.equal(value(outputs, 'junit-artifact', 6), `\${{ steps.${id}.outputs.artifact-id && format('${fmt}', github.run_attempt) || '' }}`, `${u.at}: the junit-artifact output`);
      // Downloaded by exactly that name, into a directory of its own.
      const mine = downloads.filter((d) => value(d, 'name') === `\${{ ${out} }}`);
      assert.equal(mine.length, 1, `one download of ${out}`);
      const [d] = mine;
      assert.match(d, new RegExp(`^ {8}if: ${out.replaceAll('.', '\\.')} != ''$`, 'm'), `${u.job}: no download when the job named nothing`);
      assert.doesNotMatch(d, /^ {10}(pattern|merge-multiple|artifact-ids|run-id|github-token):/m, `${u.job}: by name, from this run only`);
      assert.equal(value(d, 'path'), `${downloadDir}/${u.job}`);
      assert.ok(stepsOf(body).indexOf(d) < stepsOf(body).indexOf(report), 'downloads come before the report');
      lines.push(`${u.job}=\${{ ${out} }}`);
    }
    assert.deepEqual(blockOf(report, 'DOWNLOADS'), lines, 'DOWNLOADS names each leg job and its output, nothing else');
  });

  test('it is informational: after its legs unless the run is cancelled or classified docs-only, not required, read-only, no secrets, no gate flags', () => {
    const jobs = workflowJobs(ciText());
    const body = jobs.get(REPORT_JOB);
    // Runs whatever its legs did, except in a cancelled run, and is skipped
    // with the jobs that a docs-only classification skips.
    const cond = jobIf(body);
    assert.match(cond, /^!cancelled\(\) && /, 'the condition starts with !cancelled(), so a cancelled run gets no report');
    assert.doesNotMatch(/^ {4}if:.*\n(?: {6}.*\n)*/m.exec(body)[0], /always\(\)/, 'always() would also run it in a cancelled run');
    assert.equal(cond, "!cancelled() && needs.changes.outputs.code == 'true'");
    assert.match(body, /^ {4}if: \$\{\{ !cancelled\(\) && needs\.changes\.outputs\.code == 'true' \}\}$/m, 'one line, inside ${{ }}');
    assert.ok(!needsOf(jobs.get('ci-passed')).includes(REPORT_JOB), 'ci-passed must not need it: it is not a required check');
    assert.match(body, /^ {4}permissions:\n {6}contents: read\n(?! {6})/m, 'permissions: contents: read only');
    for (const bad of [/secrets\./, /github\.token/, /GH_TOKEN/, /id-token/, /continue-on-error/, /--require-milestone/, /--require-history/, /--allow-commit-mismatch/, /--docs-only/]) {
      assert.doesNotMatch(body, bad, `${REPORT_JOB} must not use ${bad.source}`);
    }
    // The checkout is the judged commit: the PR head on a pull request.
    assert.match(body, /^ {6}COMMIT: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}$/m);
    const [checkout] = stepNamed(body, /uses: actions\/checkout@/);
    assert.match(checkout, /^ {10}ref: \$\{\{ env\.COMMIT \}\}$/m);
    assert.match(checkout, /^ {10}persist-credentials: false$/m);
    const [report] = stepNamed(body, REPORT_STEP);
    assert.match(report, /^ {8}run: sh scripts\/ci\/report-conformance-ci\.sh$/m);
    assert.doesNotMatch(report, /^ {8}if:/m, 'the report step runs only when the download succeeded: a partial download is not judged');
    const [upload] = stepNamed(body, /uses: actions\/upload-artifact@/);
    assert.match(upload, /^ {8}if: always\(\)$/m);
    assert.ok(value(upload, 'path'), 'the upload has a path');
    assert.equal(value(upload, 'path'), value(report, 'REPORT_JSON'), 'it uploads the JSON the report wrote');
    assert.ok(NOT_CONFORMANCE.some((r) => r.test(inAttempt(value(upload, 'name')))), 'its JSON artifact is a known non-conformance artifact');
    // Actions pinned as elsewhere in the file.
    const elsewhere = new Set([...jobs].filter(([j]) => j !== REPORT_JOB).flatMap(([, b]) => [...b.matchAll(/uses: (\S+)/g)].map((m) => m[1])));
    for (const [, action] of body.matchAll(/uses: (\S+)/g)) assert.ok(elsewhere.has(action), `${action} is not pinned as the other jobs pin it`);
  });

  const PG_ARTIFACT = 'junit-scenarios-pg-x86_64-attempt-1';
  // A fake `node` first on PATH: the run.json writer (`node -e`) runs the
  // real node; the reporter call records its arguments and exits STUB_STATUS.
  const stubbed = (status, env = {}, downloads = undefined) => {
    const bin = tmp('report-ci-bin-');
    write(join(bin, 'node'), '#!/bin/sh\nif [ "$1" = -e ]; then exec "$REAL_NODE" "$@"; fi\nprintf \'%s\\n\' "$@" > "$STUB_ARGS"\nexit "$STUB_STATUS"\n');
    chmodSync(join(bin, 'node'), 0o755);
    const out = tmp('report-ci-out-');
    const e = { PATH: `${bin}:${process.env.PATH}`, REAL_NODE: process.execPath, STUB_ARGS: join(out, 'args'), STUB_STATUS: String(status) };
    return ciScript(REPO, { ...e, ...env }, out, downloads);
  };
  // The leg downloads of a case as the job's download steps leave them: a
  // download by name puts the artifact's files directly into
  // DOWNLOAD_DIR/<job>/. Each is { job, name, files, link }: `files` maps a
  // path under that directory to its text, { link: target } (a symbolic
  // link) or { dir: true }; `link` makes DOWNLOAD_DIR/<job> itself a link;
  // name '' is a job that uploaded nothing (no directory). Returns the
  // DOWNLOADS value naming them.
  const stageDownloads = (dir, downloads) => {
    mkdirSync(dir, { recursive: true });
    for (const { job, files = {}, link } of downloads) {
      if (link) symlinkSync(link, join(dir, job));
      for (const [rel, v] of Object.entries(files)) {
        const p = join(dir, job, rel);
        mkdirSync(dirname(p), { recursive: true });
        if (typeof v === 'string') writeFileSync(p, v);
        else if (v.link) symlinkSync(v.link, p);
        else mkdirSync(p, { recursive: true });
      }
    }
    return downloads.map(({ job, name }) => `${job}=${name}\n`).join('');
  };
  const pgDownload = (files = { leg: `${PG}\n`, 'junit.xml': '<testsuites/>\n' }, name = PG_ARTIFACT) => [{ job: 'scenarios-pg', name, files }];
  // Every entry under `dir`, without following links: `x/` a directory,
  // `x@` a symbolic link, `x` anything else; null when `dir` is missing.
  const tree = (dir) => {
    if (!existsSync(dir)) return null;
    const out = [];
    const walk = (rel) => {
      for (const e of readdirSync(join(dir, rel), { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (e.isSymbolicLink()) out.push(`${r}@`);
        else if (e.isDirectory()) {
          out.push(`${r}/`);
          walk(r);
        } else out.push(r);
      }
    };
    walk('');
    return out.sort();
  };
  // Runs report-conformance-ci.sh from checkout `dir` as the job does: this
  // process's environment with GIT_ENV's git settings, less the runner's
  // and the job's variables (childEnv), then this fixture's values for
  // those, then exactly what the case sets (undefined unsets). On GitHub
  // Actions the runner's GITHUB_RUN_ID and GITHUB_STEP_SUMMARY reached the
  // script before, replacing the fixture's.
  const ciScript = (dir, env, out = tmp('report-ci-out-'), downloads = pgDownload()) => {
    const base = childEnv();
    delete base.NODE_TEST_CONTEXT;
    const downloadDir = join(out, 'download');
    const e = {
      ...base,
      COMMIT: SHA,
      DOWNLOAD_DIR: downloadDir,
      DOWNLOADS: downloads === null ? undefined : stageDownloads(downloadDir, downloads),
      ARTIFACTS: join(out, 'artifacts'),
      REPORT_JSON: join(out, 'report.json'),
      GITHUB_RUN_ID: '100',
      GITHUB_RUN_ATTEMPT: '1',
      GITHUB_WORKFLOW: 'CI',
      GITHUB_EVENT_NAME: 'push',
      GITHUB_REF_NAME: 'main',
      GITHUB_STEP_SUMMARY: join(out, 'summary.md'),
      ...env,
    };
    for (const [k, v] of Object.entries(e)) if (v === undefined) delete e[k];
    const r = spawnSync('sh', [join(dir, 'scripts', 'ci', 'report-conformance-ci.sh')], { cwd: dir, encoding: 'utf8', env: e });
    const read = (p) => (p && existsSync(p) ? readFileSync(p, 'utf8') : null);
    return { status: r.status, out: r.stdout, err: r.stderr, summary: read(e.GITHUB_STEP_SUMMARY), json: read(e.REPORT_JSON) && JSON.parse(read(e.REPORT_JSON)), args: read(env.STUB_ARGS)?.split('\n').slice(0, -1) ?? null, runJson: read(join(e.ARTIFACTS ?? '', String(e.GITHUB_RUN_ID), 'run.json')), env: e, tree: e.ARTIFACTS ? tree(e.ARTIFACTS) : null, left: tree(downloadDir) };
  };

  test('exit status: only a reporter error fails the job; a failed stage is a warning', () => {
    for (const [status, want, annotation] of [
      [0, 0, null],
      [1, 0, /^::warning title=Conformance report::An implemented conformance stage has a failed result/m],
      [2, 2, /^::error title=Conformance report::The conformance reporter found usage, registry or input errors, or crashed \(exit 2\)/m],
      [137, 137, /^::error title=Conformance report::The conformance reporter died with exit status 137\.$/m],
    ]) {
      const r = stubbed(status);
      assert.equal(r.status, want, `reporter ${status}: ${r.out}${r.err}`);
      if (annotation) assert.match(r.out, annotation);
      else assert.doesNotMatch(r.out, /^::(warning|error)/m);
      // The reporter gets the commit, the artifacts, the JSON and the step
      // summary, and nothing that would make it a gate.
      assert.deepEqual(r.args, [join(dirname(SCRIPT), 'report-conformance.mjs'), '--commit', SHA, '--artifacts', r.env.ARTIFACTS, '--json', r.env.REPORT_JSON, '--summary', r.env.GITHUB_STEP_SUMMARY]);
      assert.deepEqual(JSON.parse(r.runJson), { databaseId: 100, headSha: SHA, attempt: 1, workflowName: 'CI', event: 'push', headBranch: 'main' });
      assert.match(r.summary, /^> \*\*Informational\.\*\* This conformance report covers only the leg artifacts of this workflow run \(run 100\) that its leg jobs named, one per leg job from the attempt that job last ran in; [^\n]*\n>\n> - `scenarios-pg`: `junit-scenarios-pg-x86_64-attempt-1`\n/);
      assert.doesNotMatch(r.summary, /attempts 1 to/);
      assert.doesNotMatch(r.summary, /PR head/);
    }
    // In a pull_request run GITHUB_REF_NAME is the merge ref; headBranch is
    // the PR's head branch, as gh run view gives it.
    const pr = stubbed(0, { GITHUB_EVENT_NAME: 'pull_request', GITHUB_HEAD_REF: 'claude/x "y"', GITHUB_REF_NAME: '52/merge', GITHUB_RUN_ID: '98765432101', GITHUB_RUN_ATTEMPT: '3', GITHUB_WORKFLOW: 'CI "x"' });
    assert.equal(pr.status, 0);
    assert.match(pr.summary, /^> In a pull request run the judged commit is the PR head, while the leg jobs tested its merge with the base branch\.$/m);
    assert.deepEqual(JSON.parse(pr.runJson), { databaseId: 98765432101, headSha: SHA, attempt: 3, workflowName: 'CI "x"', event: 'pull_request', headBranch: 'claude/x "y"' });
    // An empty GITHUB_HEAD_REF (any other event) falls back to the ref name.
    const dispatch = stubbed(0, { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_HEAD_REF: '' });
    assert.equal(dispatch.status, 0);
    assert.deepEqual(JSON.parse(dispatch.runJson), { databaseId: 100, headSha: SHA, attempt: 1, workflowName: 'CI', event: 'workflow_dispatch', headBranch: 'main' });
  });

  // The regression on GitHub Actions (PR 52, head cf35ed7): the runner's
  // variables leaked into the script, so GITHUB_RUN_ID replaced the
  // fixture's and an unset variable was not unset. Reproduced here by
  // setting them in this process.
  test('the script sees only the variables a case sets, not those of the runner that runs the tests', () => {
    const real = join(tmp('report-ci-leak-'), 'step-summary.md');
    const LEAK = { GITHUB_RUN_ID: '44833181735', GITHUB_RUN_ATTEMPT: '7', GITHUB_WORKFLOW: 'Leaked', GITHUB_STEP_SUMMARY: real, GITHUB_EVENT_NAME: 'pull_request', GITHUB_HEAD_REF: 'leaked/branch', GITHUB_REF_NAME: '52/merge', GITHUB_ACTIONS: 'true', ACTIONS_RUNTIME_TOKEN: 'leaked', CI: 'true', COMMIT: 'b'.repeat(40), ARTIFACTS: '/nonexistent/a', REPORT_JSON: '/nonexistent/r.json', DOWNLOAD_DIR: '/nonexistent/d', DOWNLOADS: 'leaked=junit-leaked-attempt-1', RUNNER_TEMP: '/nonexistent/t' };
    const saved = Object.fromEntries(Object.keys(LEAK).map((k) => [k, process.env[k]]));
    Object.assign(process.env, LEAK);
    try {
      const r = stubbed(0);
      assert.equal(r.status, 0, r.out + r.err);
      assert.deepEqual(JSON.parse(r.runJson), { databaseId: 100, headSha: SHA, attempt: 1, workflowName: 'CI', event: 'push', headBranch: 'main' });
      assert.doesNotMatch(r.summary, /PR head/);
      for (const k of ['GITHUB_ACTIONS', 'GITHUB_HEAD_REF', 'ACTIONS_RUNTIME_TOKEN', 'CI', 'RUNNER_TEMP']) assert.equal(r.env[k], undefined, k);
      for (const k of ['DOWNLOAD_DIR', 'DOWNLOADS']) assert.notEqual(r.env[k], LEAK[k], k);
      assert.deepEqual(r.tree, ['100/', `100/${PG_ARTIFACT}/`, `100/${PG_ARTIFACT}/junit.xml`, `100/${PG_ARTIFACT}/leg`, '100/run.json']);
      const unset = stubbed(0, { GITHUB_STEP_SUMMARY: undefined });
      assert.equal(unset.status, 2);
      assert.match(unset.out, /GITHUB_STEP_SUMMARY is not set/);
      assert.equal(existsSync(real), false, 'nothing was written into the runner\'s step summary');
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  test('a missing or malformed variable, or an existing run.json, is a usage error before the reporter runs', () => {
    for (const [env, msg] of [
      [{ COMMIT: undefined }, /COMMIT must be a full 40-character lowercase hex SHA, not ''/],
      [{ COMMIT: 'A'.repeat(40) }, /COMMIT must be/],
      [{ COMMIT: 'a'.repeat(39) }, /COMMIT must be/],
      [{ COMMIT: `${'a'.repeat(40)}\n` }, /COMMIT must be/],
      [{ ARTIFACTS: '' }, /ARTIFACTS is not set/],
      [{ REPORT_JSON: undefined }, /REPORT_JSON is not set/],
      [{ GITHUB_STEP_SUMMARY: undefined }, /GITHUB_STEP_SUMMARY is not set/],
      [{ GITHUB_RUN_ID: '0' }, /GITHUB_RUN_ID must be a positive integer, not '0'/],
      [{ GITHUB_RUN_ID: '12a' }, /GITHUB_RUN_ID must be a positive integer/],
      [{ GITHUB_RUN_ATTEMPT: '' }, /GITHUB_RUN_ATTEMPT must be a positive integer, not ''/],
      [{ GITHUB_RUN_ATTEMPT: '01' }, /GITHUB_RUN_ATTEMPT must be a positive integer/],
      [{ GITHUB_WORKFLOW: undefined }, /GITHUB_WORKFLOW is not set/],
      [{ GITHUB_EVENT_NAME: undefined }, /GITHUB_EVENT_NAME must be an event name \(a-z and _\), not ''/],
      [{ GITHUB_EVENT_NAME: 'Push' }, /GITHUB_EVENT_NAME must be an event name/],
      [{ GITHUB_EVENT_NAME: 'push x' }, /GITHUB_EVENT_NAME must be an event name/],
      [{ GITHUB_REF_NAME: undefined }, /GITHUB_HEAD_REF and GITHUB_REF_NAME are both unset or empty/],
      [{ GITHUB_REF_NAME: '', GITHUB_HEAD_REF: '' }, /GITHUB_HEAD_REF and GITHUB_REF_NAME are both unset or empty/],
      [{ DOWNLOAD_DIR: undefined }, /DOWNLOAD_DIR is not set/],
    ]) {
      const r = stubbed(0, env);
      assert.equal(r.status, 2, JSON.stringify(env));
      assert.match(r.out, /^::error title=Conformance report::report-conformance-ci: /m);
      assert.match(r.out, msg);
      assert.equal(r.args, null, 'the reporter did not run');
    }
    // An existing run directory, with or without a run.json in it: nothing
    // in the run directory may predate this script.
    for (const pre of ['run.json', `${PG_ARTIFACT}/leg`]) {
      const out = tmp('report-ci-out-');
      write(join(out, 'artifacts', '100', pre), '{"stale":true}\n');
      const r = stubbed(0, { ARTIFACTS: join(out, 'artifacts') });
      assert.equal(r.status, 2, pre);
      assert.match(r.out, /report-conformance-ci: .*\/artifacts\/100 exists already$/m, pre);
      assert.equal(r.args, null, pre);
      assert.equal(readFileSync(join(out, 'artifacts', '100', pre), 'utf8'), '{"stale":true}\n', pre);
      assert.deepEqual(r.left, ['scenarios-pg/', 'scenarios-pg/junit.xml', 'scenarios-pg/leg'], 'nothing was moved');
    }
  });

  // The leg downloads (layout §3 "Leg artifacts"): the name each leg job
  // gave, never one guessed from the files or from GITHUB_RUN_ATTEMPT; files
  // moved, not copied, into ARTIFACTS/<run_id>/<name>/; run.json last.
  const PG_FILES = [`100/${PG_ARTIFACT}/`, `100/${PG_ARTIFACT}/junit.xml`, `100/${PG_ARTIFACT}/leg`, '100/run.json'];
  test('leg downloads: one artifact is moved under the name its job gave, whatever the attempt of this job', () => {
    // A re-run of this job alone: attempt 3 here, the artifact from 1.
    const r = stubbed(0, { GITHUB_RUN_ATTEMPT: '3' }, [{ job: 'scenarios-pg', name: PG_ARTIFACT, files: { leg: `${PG}\n`, 'junit.xml': '<testsuites/>\n' } }]);
    assert.equal(r.status, 0, r.out + r.err);
    assert.deepEqual(r.tree, ['100/', ...PG_FILES]);
    assert.deepEqual(r.left, [], 'the download directory is emptied: moved, not copied');
    assert.equal(readFileSync(join(r.env.ARTIFACTS, '100', PG_ARTIFACT, 'leg'), 'utf8'), `${PG}\n`);
    assert.equal(JSON.parse(r.runJson).attempt, 3);
    // Moved: the same file (inode), not a copy.
    const out = tmp('report-ci-out-');
    const downloads = pgDownload();
    const before = (() => {
      const d = join(out, 'download');
      stageDownloads(d, downloads);
      return lstatSync(join(d, 'scenarios-pg', 'junit.xml')).ino;
    })();
    const moved = ciScript(REPO, { PATH: r.env.PATH, REAL_NODE: process.execPath, STUB_ARGS: join(out, 'args'), STUB_STATUS: '0', DOWNLOADS: `scenarios-pg=${PG_ARTIFACT}\n` }, out, []);
    assert.equal(moved.status, 0, moved.out + moved.err);
    assert.equal(lstatSync(join(out, 'artifacts', '100', PG_ARTIFACT, 'junit.xml')).ino, before);
    // Without junit.xml (the job stopped before its tests): leg alone.
    const legOnly = stubbed(0, {}, pgDownload({ leg: `${PG}\n` }));
    assert.equal(legOnly.status, 0, legOnly.out + legOnly.err);
    assert.deepEqual(legOnly.tree, ['100/', `100/${PG_ARTIFACT}/`, `100/${PG_ARTIFACT}/leg`, '100/run.json']);
  });

  test('leg downloads: two leg jobs give two artifact directories; a job that uploaded nothing is a warning and not run', () => {
    const TS = 'junit-typescript-node22-attempt-2';
    const two = stubbed(0, {}, [...pgDownload(), { job: 'typescript', name: TS, files: { leg: 'typescript/node22\n', 'junit.xml': '<testsuites/>\n' } }]);
    assert.equal(two.status, 0, two.out + two.err);
    assert.deepEqual(two.tree, ['100/', ...PG_FILES.slice(0, 3), `100/${TS}/`, `100/${TS}/junit.xml`, `100/${TS}/leg`, '100/run.json'].sort());
    assert.deepEqual(two.left, []);
    assert.match(two.summary, /^> - `scenarios-pg`: `junit-scenarios-pg-x86_64-attempt-1`\n> - `typescript`: `junit-typescript-node22-attempt-2`$/m);
    // Zero: the leg job's output was empty, so the workflow downloaded
    // nothing and the run directory holds run.json alone.
    const zero = stubbed(0, {}, [{ job: 'scenarios-pg', name: '' }]);
    assert.equal(zero.status, 0, zero.out + zero.err);
    assert.deepEqual(zero.tree, ['100/', '100/run.json']);
    assert.match(zero.out, /^::warning title=Conformance report::Job scenarios-pg uploaded no leg artifact in this run \(it stopped before its upload, or did not run\), so its legs are not run here\.$/m);
    assert.match(zero.summary, /^> - `scenarios-pg`: no leg artifact$/m);
    assert.ok(zero.args, 'the reporter ran');
  });

  test('leg downloads: anything but the regular files leg and junit.xml, a bad name or a bad leg file is an error before run.json and the reporter', () => {
    const LEG = `${PG}\n`;
    const linkTo = (target) => {
      const l = join(tmp('report-ci-link-'), 'd');
      symlinkSync(target, l);
      return l;
    };
    const J = '<testsuites/>\n';
    const pg = (files, name) => pgDownload(files, name);
    for (const [what, downloads, err, env = {}] of [
      // A pattern download with several matches: one directory per artifact.
      ['nested (a directory per artifact)', pg({ [`${PG_ARTIFACT}/leg`]: LEG, [`${PG_ARTIFACT}/junit.xml`]: J }), /holds 'junit-scenarios-pg-x86_64-attempt-1'; a leg artifact holds only the files leg and junit\.xml, at its top/],
      // A forged attempt planted beside the real files.
      ['flat with a subdirectory', pg({ leg: LEG, 'junit.xml': J, 'junit-x-attempt-9/leg': LEG, 'junit-x-attempt-9/junit.xml': J }), /holds 'junit-x-attempt-9'/],
      ['mixed', pg({ leg: LEG, [`${PG_ARTIFACT}/leg`]: LEG }), /holds 'junit-scenarios-pg-x86_64-attempt-1'/],
      ['an empty subdirectory', pg({ leg: LEG, sub: { dir: true } }), /holds 'sub'/],
      ['a planted run.json', pg({ leg: LEG, 'junit.xml': J, 'run.json': '{}' }), /holds 'run\.json'/],
      ['a dot file', pg({ leg: LEG, '.hidden': 'x' }), /holds '\.hidden'/],
      ['another file', pg({ leg: LEG, 'junit.xml': J, 'extra.xml': J }), /holds 'extra\.xml'/],
      ['leg a symbolic link', pg({ leg: { link: '/etc/hostname' }, 'junit.xml': J }), /junit-scenarios-pg-x86_64-attempt-1\/leg is not a regular file/],
      ['junit.xml a symbolic link', pg({ leg: LEG, 'junit.xml': { link: '/etc/hostname' } }), /attempt-1\/junit\.xml is not a regular file/],
      ['a dangling symbolic link', pg({ leg: LEG, 'junit.xml': { link: '/nonexistent' } }), /attempt-1\/junit\.xml is not a regular file/],
      ['junit.xml a directory', pg({ leg: LEG, 'junit.xml': { dir: true } }), /attempt-1\/junit\.xml is not a regular file/],
      ['the download directory a symbolic link', [{ job: 'scenarios-pg', name: PG_ARTIFACT, link: tmp('report-ci-elsewhere-') }], /scenarios-pg: the download of junit-scenarios-pg-x86_64-attempt-1 is not a directory/],
      ['no download directory', [{ job: 'scenarios-pg', name: PG_ARTIFACT }], /the download of junit-scenarios-pg-x86_64-attempt-1 is not a directory/],
      ['no leg file', pg({ 'junit.xml': J }), /junit-scenarios-pg-x86_64-attempt-1 has no leg file/],
      ['an empty leg file', pg({ leg: '' }), /attempt-1\/leg is not one line holding a leg string/],
      ['a leg without its newline', pg({ leg: PG }), /leg is not one line holding a leg string/],
      ['a leg of two lines', pg({ leg: `${PG}\n${PG}\n` }), /leg is not one line holding a leg string/],
      ['a leg with a carriage return', pg({ leg: `${PG}\r\n` }), /leg is not one line holding a leg string/],
      ['a leg with a space', pg({ leg: ' scenarios-pg/x86_64\n' }), /leg is not one line holding a leg string/],
      ['an oversized leg', pg({ leg: `${'a'.repeat(300)}\n` }), /leg holds 301 bytes, more than one leg string/],
      ['a leg of another artifact name', pg({ leg: 'typescript/node22\n' }), /attempt-1\/leg names leg typescript\/node22, whose artifact is junit-typescript-node22-attempt-N/],
      ['a name that is not a leg artifact name', pg({ leg: LEG }, 'junit-scenarios-pg-x86_64'), /'junit-scenarios-pg-x86_64' is not a leg artifact name junit-<leg id>-attempt-N/],
      ['a name with a path', pg({ leg: LEG }, '../junit-scenarios-pg-x86_64-attempt-1'), /is not a leg artifact name/],
      ['a name with a slash', pg({ leg: LEG }, 'junit-scenarios-pg/x86_64-attempt-1'), /is not a leg artifact name/],
      ['attempt 0', pg({ leg: LEG }, 'junit-scenarios-pg-x86_64-attempt-0'), /is not a leg artifact name/],
      ['an upper-case name', pg({ leg: LEG }, 'junit-Scenarios-pg-x86_64-attempt-1'), /is not a leg artifact name/],
      ['no = in a line', null, /DOWNLOADS line 'scenarios-pg' is not <job>=<artifact name>/, { DOWNLOADS: 'scenarios-pg\n' }],
      ['a bad job id', null, /'\.\.\/x' is not a job id/, { DOWNLOADS: `../x=${PG_ARTIFACT}\n` }],
      ['a job twice', [...pgDownload(), { job: 'scenarios-pg', name: '' }], /DOWNLOADS names job scenarios-pg twice/],
      ['no line', null, /DOWNLOADS names no leg job/, { DOWNLOADS: '\n' }],
      ['DOWNLOAD_DIR a symbolic link', null, /\/d is a symbolic link$/m, { DOWNLOAD_DIR: linkTo(tmp('report-ci-elsewhere-')), DOWNLOADS: 'scenarios-pg=\n' }],
      ['DOWNLOADS unset', null, /DOWNLOADS names no leg job/],
      ['a directory for a job that named nothing', [{ job: 'scenarios-pg', name: '', files: { leg: LEG } }], /scenarios-pg exists, but job scenarios-pg named no leg artifact/],
      ['a download no line names', [...pgDownload(), { job: 'other', name: PG_ARTIFACT, files: { leg: LEG } }], /holds 'other', which no line of DOWNLOADS names/, { DOWNLOADS: `scenarios-pg=${PG_ARTIFACT}\n` }],
    ]) {
      const r = stubbed(0, env, downloads);
      assert.equal(r.status, 2, `${what}: ${r.out}${r.err}`);
      assert.match(r.out, /^::error title=Conformance report::report-conformance-ci: /m, what);
      assert.match(r.out, err, what);
      assert.equal(r.args, null, `${what}: the reporter did not run`);
      assert.equal(r.runJson, null, `${what}: run.json is written only after every download was checked and moved`);
      for (const f of r.tree ?? []) assert.ok(f === '100/' || f.startsWith(`100/${PG_ARTIFACT}`), `${what}: ${f} was created`);
    }
  });

  // An artifact can name its entries anything. The script shows a name it
  // found in the download directory only as A-Za-z0-9._-, every other byte
  // as `?` (one per byte), so the name cannot end the annotation's line and
  // start a workflow command of its own, carry a terminal escape sequence,
  // or hold a backslash escape that dash's echo would turn into one.
  test('leg downloads: a name found in the download directory is shown sanitised, never as raw bytes or a workflow command', () => {
    const LEG = `${PG}\n`;
    const PREFIX = '::error title=Conformance report::report-conformance-ci: ';
    for (const [what, entry, shown] of [
      ['a newline and a workflow command', 'x\n::error::forged', 'x???error??forged'],
      ['a carriage return and a workflow command', 'x\r::warning::forged', 'x???warning??forged'],
      ['an escape sequence', '\x1b[31mred\x1b[0m', '??31mred??0m'],
      ['a backslash escape (dash echo)', 'a\\033[2Jb\\n::error::c', 'a?033?2Jb?n??error??c'],
      ['non-ASCII', 'café .xml', 'caf?????.xml'],
    ]) {
      // In a job's download, beside the leg file, and at the top of
      // DOWNLOAD_DIR, where no DOWNLOADS line names it.
      for (const [where, downloads, env, message] of [
        ['in the download', pgDownload({ leg: LEG, [entry]: 'x' }), {}, `${PG_ARTIFACT} holds '${shown}'; a leg artifact holds only the files leg and junit.xml, at its top`],
        ['beside the downloads', [...pgDownload(), { job: entry, name: PG_ARTIFACT, files: { leg: LEG } }], { DOWNLOADS: `scenarios-pg=${PG_ARTIFACT}\n` }, `holds '${shown}', which no line of DOWNLOADS names`],
      ]) {
        const at = `${what} ${where}`;
        const r = stubbed(0, env, downloads);
        assert.equal(r.status, 2, `${at}: ${r.out}${r.err}`);
        assert.equal(r.args, null, `${at}: the reporter did not run`);
        assert.equal(r.runJson, null, `${at}: no run.json`);
        assert.doesNotMatch(r.out + r.err, /[^\n\x20-\x7e]/, `${at}: only printable ASCII and line ends: ${JSON.stringify(r.out + r.err)}`);
        const lines = r.out.split('\n').filter(Boolean);
        assert.equal(lines.length, 1, `${at}: one line, the script's own error: ${JSON.stringify(r.out)}`);
        assert.ok(lines[0].startsWith(PREFIX), `${at}: ${lines[0]}`);
        assert.ok(lines[0].endsWith(message), `${at}: ${JSON.stringify(lines[0])} ends with ${JSON.stringify(message)}`);
        assert.ok(!lines[0].slice(PREFIX.length).includes('::'), `${at}: no workflow command after the script's own`);
      }
    }
    // Every message is printed as it is, never through dash's echo, which
    // would turn the backslash escapes of a bad DOWNLOADS line into an
    // escape sequence and a line end.
    const line = 'scenarios-pg=junit-x\\033[2J\\n::error::y-attempt-1';
    const r = stubbed(0, { DOWNLOADS: `${line}\n` }, []);
    assert.equal(r.status, 2, r.out + r.err);
    assert.doesNotMatch(r.out + r.err, /[^\n\x20-\x7e]/, JSON.stringify(r.out + r.err));
    assert.deepEqual(r.out.split('\n').filter(Boolean), [`${PREFIX}DOWNLOADS line '${line}': 'junit-x\\033[2J\\n::error::y-attempt-1' is not a leg artifact name junit-<leg id>-attempt-N`]);
  });

  // End to end, as the job runs: a committed checkout of the judged commit
  // holding the specs, the registry and the reporter scripts, the leg
  // artifact as a download by name leaves it (DOWNLOAD_DIR/scenarios-pg/
  // holding junit.xml and leg), and the real reporter.
  const checkout = (edits = {}) => {
    const dir = root(edits);
    for (const f of ['report-conformance-ci.sh', 'report-conformance.mjs', 'check-conformance-registry.mjs', 'gen-conformance-registry.mjs']) write(join(dir, 'scripts', 'ci', f), repoText(join('scripts', 'ci', f)));
    symlinkSync(join(REPO, 'scripts', 'ci', 'node_modules'), join(dir, 'scripts', 'ci', 'node_modules'));
    return { dir, head: commitRoot(dir) };
  };
  // `spec`: { leg, attempt, junit, name } of the artifact scenarios-pg
  // named (leg or junit null: that file is missing), or null when it named
  // none.
  const job = (co, spec, env = {}) => {
    const downloads =
      spec === null
        ? [{ job: 'scenarios-pg', name: '' }]
        : [{ job: 'scenarios-pg', name: spec.name ?? `junit-${legId(spec.leg)}-attempt-${spec.attempt ?? 1}`, files: { ...(spec.leg === null ? {} : { leg: `${spec.leg}\n` }), ...(spec.junit === null ? {} : { 'junit.xml': spec.junit }) } }];
    return ciScript(co.dir, { COMMIT: co.head, ...env }, tmp('report-ci-out-'), downloads);
  };
  // What `cargo nextest run --profile ci` writes to
  // target/nextest/ci/junit.xml in the scenarios-pg job (quick-junit's
  // format: a <testsuite> per binary, classname <package>::<binary>, the
  // disabled count, failures with type and output). Modelled on that
  // format, not captured from a run.
  const nextestJUnit = (cases) => {
    const fails = cases.filter(([, s]) => s === 'failed').length;
    const head = `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites name="nextest-run" tests="${cases.length}" failures="${fails}" errors="0" uuid="0b8a4c4e-1f0e-4c55-9d43-6c1d2f0e7a11" timestamp="2026-11-20T10:00:00.000+00:00" time="0.412">\n`;
    if (!cases.length) return `${head}</testsuites>\n`;
    const tc = ([name, s]) =>
      `        <testcase name="${name}" classname="skyoauth-scenarios::pg" timestamp="2026-11-20T10:00:00.100+00:00" time="0.105">\n` +
      (s === 'failed' ? `            <failure type="test failure with exit code 101">thread '${name}' panicked at tests/pg/security/a24.rs:42:5:\nassertion failed: issued == 1</failure>\n            <system-out>running 1 test\ntest ${name} ... FAILED\n</system-out>\n            <system-err>note: run with \`RUST_BACKTRACE=1\`</system-err>\n` : '') +
      '        </testcase>\n';
    return `${head}    <testsuite name="skyoauth-scenarios::pg" tests="${cases.length}" disabled="0" errors="0" failures="${fails}">\n${cases.map(tc).join('')}    </testsuite>\n</testsuites>\n`;
  };
  const POS = 'security::a24::a24_pos_single_issuance_across_replicas';
  const NEG = 'security::a24::a24_neg_concurrent_single_use';
  const realA24 = { [SCENARIOS]: implement('scenario', 'A24', 'M1a', [POS, NEG].map((n) => `nextest:skyoauth-scenarios/pg/${n}`)) };

  test('end to end on today\'s artifact (an empty nextest selection): exit 0, every stage planned, the JSON and the summary written', () => {
    const co = checkout();
    const r = job(co, { leg: PG, junit: nextestJUnit([]) });
    assert.equal(r.status, 0, r.out + r.err);
    assert.doesNotMatch(r.out, /^::(warning|error)/m);
    // The reporter checks four of run.json's fields and ignores event and
    // headBranch.
    assert.deepEqual(JSON.parse(r.runJson), { databaseId: 100, headSha: co.head, attempt: 1, workflowName: 'CI', event: 'push', headBranch: 'main' });
    assert.equal(r.json.trusted, true);
    assert.deepEqual(r.json.input_errors, []);
    assert.deepEqual(r.json.reports, [{ run_id: 100, run_attempt: 1, workflow: 'CI', leg: PG, artifact: `100/${PG_ARTIFACT}`, cases: 0 }]);
    assert.ok(r.json.stages.every((s) => s.status === 'planned'));
    assert.equal(r.json.failed, false);
    assert.match(r.summary, /^> \*\*Informational\.\*\*[^\n]*\n>\n> - `scenarios-pg`: `junit-scenarios-pg-x86_64-attempt-1`\n\n## Conformance results for `[0-9a-f]{40}`\n/);
    assert.match(r.summary, /Judged on \d{4}-\d\d-\d\d from 1 JUnit report\(s\)/);
  });

  test('end to end with scenario tests: a pass is passed; a failure is a warning, not a job failure, under the attempt its job named', () => {
    const co = checkout(realA24);
    const pass = job(co, { leg: PG, junit: nextestJUnit([[POS, 'passed'], [NEG, 'passed']]) });
    assert.equal(pass.status, 0, pass.out + pass.err);
    assert.equal(stage(pass.json, 'A24', 'M1a').status, 'passed');
    assert.doesNotMatch(pass.out, /^::(warning|error)/m);
    // A re-run of this job alone (attempt 2) over the attempt-1 artifact:
    // the failure stays attempt 1's, as scenarios-pg named it.
    const rerun = job(co, { leg: PG, attempt: 1, junit: nextestJUnit([[POS, 'passed'], [NEG, 'failed']]) }, { GITHUB_RUN_ATTEMPT: '2' });
    assert.equal(rerun.status, 0, rerun.out + rerun.err);
    assert.match(rerun.out, /^::warning title=Conformance report::An implemented conformance stage has a failed result/m);
    assert.equal(stage(rerun.json, 'A24', 'M1a').status, 'failed');
    assert.equal(rerun.json.trusted, true);
    assert.match(rerun.summary, /failed in run 100 attempt 1/);
    assert.deepEqual(rerun.json.reports.map((x) => [x.run_attempt, x.artifact]), [[1, `100/${PG_ARTIFACT}`]]);
  });

  test('end to end: a leg job that uploaded no junit.xml, or no artifact at all, is not run, not an error', () => {
    const co = checkout(realA24);
    const noJunit = job(co, { leg: PG, junit: null });
    assert.equal(noJunit.status, 0, noJunit.out + noJunit.err);
    assert.equal(stage(noJunit.json, 'A24', 'M1a').status, 'not run');
    assert.match(noJunit.summary, /note: 100\/junit-scenarios-pg-x86\\_64-attempt-1: no junit\.xml/);
    const nothing = job(co, null);
    assert.equal(nothing.status, 0, nothing.out + nothing.err);
    assert.match(nothing.out, /^::warning title=Conformance report::Job scenarios-pg uploaded no leg artifact/m);
    assert.deepEqual(nothing.json.reports, []);
    assert.equal(stage(nothing.json, 'A24', 'M1a').status, 'not run');
  });

  test('end to end: bad input fails the job (exit 2)', () => {
    const co = checkout();
    // Bad downloads stop the script before the reporter.
    for (const [what, spec, err] of [
      ['a leg artifact without its leg file', { leg: null, name: PG_ARTIFACT, junit: nextestJUnit([]) }, /junit-scenarios-pg-x86_64-attempt-1 has no leg file/],
      ['a leg string the layout does not know, under its own name', { leg: 'scenarios-pg/arm64', junit: nextestJUnit([]) }, null],
    ]) {
      const r = job(co, spec);
      assert.equal(r.status, 2, `${what}: ${r.out}${r.err}`);
      if (err) {
        assert.match(r.out, err, what);
        assert.equal(r.json, null, what);
      } else {
        // Well-formed, so the reporter judges it: an unknown leg string.
        assert.equal(r.json.trusted, false, what);
        assert.ok(r.json.input_errors.some((e) => /leg file names "scenarios-pg\/arm64", which is not a layout §1\.1 leg string/.test(e)), `${what}: ${r.json.input_errors.join('; ')}`);
      }
    }
    for (const [what, spec, env, err] of [
      ['malformed JUnit', { leg: PG, junit: '<testsuites><testsuite>' }, {}, /junit\.xml: malformed JUnit/],
      ['an artifact from a later attempt', { leg: PG, attempt: 3, junit: nextestJUnit([]) }, { GITHUB_RUN_ATTEMPT: '2' }, /attempt 3, but 100\/run\.json says the run has 2 attempt\(s\)/],
    ]) {
      const r = job(co, spec, env);
      assert.equal(r.status, 2, `${what}: ${r.out}${r.err}`);
      assert.match(r.out, /^::error title=Conformance report::The conformance reporter found usage, registry or input errors/m, what);
      assert.equal(r.json.trusted, false, what);
      assert.ok(r.json.input_errors.some((e) => err.test(e)), `${what}: ${r.json.input_errors.join('; ')}`);
    }
    // A checkout of another commit than COMMIT: no report at all.
    const wrong = job(co, { leg: PG, junit: nextestJUnit([]) }, { COMMIT: 'b'.repeat(40) });
    assert.equal(wrong.status, 2);
    assert.match(wrong.err, /--root is a checkout of [0-9a-f]{40}, not of --commit b{40}/);
    assert.equal(wrong.json, null);
  });
});

describe('XML and JUnit reader', () => {
  test('well-formed input: prolog, comments, CDATA, entities, BOM, self-closing tags, single quotes', () => {
    const x = '﻿<?xml version="1.0"?>\n<!-- c --><testsuites><testsuite name=\'s\'><testcase classname="p::t" name="a &amp; &lt;b&gt; &#65;&#x42; &quot;q&quot; &apos;"><system-out><![CDATA[<not xml>]]></system-out></testcase><testcase classname="p" name="n"/></testsuite></testsuites><!-- end -->\n';
    assert.deepEqual(readJUnit(x), [
      { classname: 'p::t', name: 'a & <b> AB "q" \'', status: 'passed' },
      { classname: 'p', name: 'n', status: 'passed' },
    ]);
    assert.deepEqual(readJUnit('<testsuite name="s"><testcase classname="c" name="n"><skipped/></testcase></testsuite>'), [{ classname: 'c', name: 'n', status: 'skipped' }]);
    assert.deepEqual(readJUnit('<testsuites><testsuites><testsuite><testcase classname="c" name="n"><skipped/><failure/></testcase></testsuite></testsuites></testsuites>'), [{ classname: 'c', name: 'n', status: 'failed' }]);
    assert.deepEqual(readJUnit('<testsuites><testsuite><properties><property name="x" value="y"/></properties></testsuite></testsuites>'), []);
    assert.equal(parseXml('<a\n  b = "1"\n/>').attrs.b, '1');
    assert.equal(parseXml('<a b="&#x30;&#90;&#1;&#x10FFFF;"/>').attrs.b, '0Z\u0001\u{10FFFF}');
  });

  test('passed is an allow-list: skip markers, skip statuses and namespaced failures do not pass', () => {
    const one = (body, attrs = '') => readJUnit(`<testsuite name="s"><testcase classname="c" name="n"${attrs}>${body}</testcase></testsuite>`)[0].status;
    for (const [body, attrs, want] of [
      ['', '', 'passed'],
      ['<system-out>x</system-out><system-err/><properties><property name="a" value="b"/></properties>', '', 'passed'],
      ['', ' status="passed"', 'passed'],
      ['', ' status="success"', 'passed'],
      ['', ' status="run"', 'passed'],
      ['<skipped/>', '', 'skipped'],
      ['<ignored/>', '', 'skipped'],
      ['<disabled/>', '', 'skipped'],
      ['', ' status="skipped"', 'skipped'],
      ['', ' status="notrun"', 'skipped'],
      ['', ' status="disabled"', 'skipped'],
      ['', ' status="ignored"', 'skipped'],
      ['', ' status="failed"', 'failed'],
      ['', ' status="failure"', 'failed'],
      ['', ' status="error"', 'failed'],
      ['<skipped/>', ' status="failed"', 'failed'],
      ['', ' status="skipped"', 'skipped'],
      ['<j:failure/>', '', 'failed'],
      ['<x:flakyError/>', '', 'failed'],
      ['<x:skipped/>', '', 'skipped'],
      ['<flakyError/>', '', 'failed'],
      ['<rerunError/>', '', 'failed'],
    ]) {
      assert.equal(one(body, attrs), want, `${attrs} ${body}`);
    }
    for (const [x, re] of [
      ['<testsuite><testcase classname="c" name="n"><weird/></testcase></testsuite>', /^testcase n: unknown element <weird>$/],
      ['<testsuite><testcase classname="c" name="n" status="maybe"/></testsuite>', /^testcase n: unknown status="maybe"$/],
      ['<testsuite name="s"><error message="setup crashed"/><testcase classname="c" name="n"/></testsuite>', /^a suite-level <error> in <testsuite name="s">: it fails no particular testcase$/],
      ['<testsuites><testsuite><testcase classname="c" name="n"/></testsuite><j:failure/></testsuites>', /^a suite-level <j:failure> in <testsuites>: /],
      ['<testsuite><flakyFailure/></testsuite>', /^a suite-level <flakyFailure> in <testsuite>: /],
      ['<testsuite><skipped/></testsuite>', /^unknown element <skipped> in <testsuite>$/],
      ['<testsuite><testcase classname="c" name="n"/><foo/></testsuite>', /^unknown element <foo> in <testsuite>$/],
    ]) {
      assert.throws(() => readJUnit(x), (ex) => ex instanceof InputError && re.test(ex.message), x);
    }
    assert.deepEqual(readJUnit('<j:testsuite xmlns:j="u"><j:testcase classname="c" name="n"><j:failure/></j:testcase></j:testsuite>'), [{ classname: 'c', name: 'n', status: 'failed' }]);
  });

  test('skipped, disabled and ignored attributes: a testcase flag or a suite count is not a pass', () => {
    const tc = (attrs, body = '') => `<testcase classname="c" name="n"${attrs}>${body}</testcase>`;
    const one = (attrs, body) => readJUnit(`<testsuite name="s">${tc(attrs, body)}</testsuite>`)[0].status;
    // On a testcase: a flag. status="skipped" was already a skip.
    for (const [attrs, want] of [
      [' status="skipped"', 'skipped'],
      [' skipped="true"', 'skipped'],
      [' skipped="1"', 'skipped'],
      [' disabled="true"', 'skipped'],
      [' disabled="1"', 'skipped'],
      [' ignored="true"', 'skipped'],
      [' skipped="false"', 'passed'],
      [' disabled="0"', 'passed'],
      [' skipped="false" disabled="1"', 'skipped'],
      [' disabled="true" status="failed"', 'failed'],
    ]) {
      assert.equal(one(attrs), want, attrs);
    }
    assert.equal(one(' disabled="true"', '<failure/>'), 'failed');
    // On a suite: a count, which the skipped testcases under it must cover.
    const cases = (x) => readJUnit(x).map((c) => c.status);
    const pair = `${tc('')}<testcase classname="c" name="m"><skipped/></testcase>`;
    assert.deepEqual(cases(`<testsuites skipped="1"><testsuite skipped="1" tests="2">${pair}</testsuite></testsuites>`), ['passed', 'skipped']);
    assert.deepEqual(cases(`<testsuites><testsuite disabled="0">${tc('')}</testsuite></testsuites>`), ['passed']);
    assert.deepEqual(cases(`<testsuites><testsuite disabled="1">${tc(' disabled="true"')}</testsuite></testsuites>`), ['skipped']);
    assert.deepEqual(cases(`<testsuites disabled="2"><testsuite>${pair}</testsuite><testsuite>${tc(' skipped="1"')}</testsuite></testsuites>`), ['passed', 'skipped', 'skipped']);
    assert.deepEqual(cases(`<testsuites><testsuite skipped="true">${pair}<testcase classname="c" name="f"><failure/></testcase></testsuite></testsuites>`), ['skipped', 'skipped', 'failed']);
    assert.deepEqual(cases(`<testsuites skipped="false"><testsuite>${tc('')}</testsuite></testsuites>`), ['passed']);
    for (const [x, re] of [
      [`<testsuite name="s">${tc(' skipped="yes"')}</testsuite>`, /^testcase n: skipped="yes" is not true, false, 1 or 0$/],
      [`<testsuite name="s">${tc(' disabled="2"')}</testsuite>`, /^testcase n: disabled="2" is not true, false, 1 or 0$/],
      [`<testsuite name="s">${tc(' ignored=""')}</testsuite>`, /^testcase n: ignored="" is not true, false, 1 or 0$/],
      [`<testsuite name="s">${tc(' skipped="True"')}</testsuite>`, /^testcase n: skipped="True" is not/],
      // A count with no skipped testcase to match: one of them is skipped,
      // but would read as passed.
      [`<testsuite name="s" skipped="1">${tc('')}</testsuite>`, /^<testsuite name="s"> counts 1 skipped or disabled test\(s\), but only 0 of its testcases are marked skipped, so which are skipped cannot be told$/],
      [`<testsuites disabled="2"><testsuite name="s">${pair}</testsuite></testsuites>`, /^<testsuites> counts 2 skipped or disabled test\(s\), but only 1 of its/],
      [`<testsuite name="s" skipped="1" disabled="1">${pair}</testsuite>`, /^<testsuite name="s"> counts 2 skipped/],
      [`<testsuite name="s" skipped="1"/>`, /^<testsuite name="s"> counts 1 skipped/],
      [`<testsuite name="s" disabled="-1">${tc('')}</testsuite>`, /^<testsuite name="s">: disabled="-1" is not a count, true or false$/],
      [`<testsuite name="s" skipped="01">${tc('')}</testsuite>`, /^<testsuite name="s">: skipped="01" is not a count/],
      [`<testsuite name="s" skipped="">${tc('')}</testsuite>`, /^<testsuite name="s">: skipped="" is not a count/],
      [`<testsuite name="s" ignored="1e3">${tc('')}</testsuite>`, /^<testsuite name="s">: ignored="1e3" is not a count/],
    ]) {
      assert.throws(() => readJUnit(x), (ex) => ex instanceof InputError && re.test(ex.message), x);
    }
  });

  // A suite flagged skipped="true" (disabled, ignored) marks the cases under
  // it before the counts of the suites inside it are checked.
  const tcx = (name, body = '') => `<testcase classname="c" name="${name}">${body}</testcase>`;
  const statuses = (x) => readJUnit(x).map((c) => [c.name, c.status]);
  const unaccounted = (x, re) => assert.throws(() => readJUnit(x), (ex) => ex instanceof InputError && re.test(ex.message), x);

  test('inherited skip flag: an enclosing "true" accounts for an inner count', () => {
    assert.deepEqual(statuses(`<testsuites disabled="true"><testsuite skipped="1">${tcx('n')}</testsuite></testsuites>`), [['n', 'skipped']]);
  });

  test('inherited skip flag: through two levels, with counts at each level below it', () => {
    assert.deepEqual(statuses(`<testsuites skipped="true"><testsuites disabled="2"><testsuite skipped="1">${tcx('a')}</testsuite><testsuite>${tcx('b')}</testsuite></testsuites></testsuites>`), [['a', 'skipped'], ['b', 'skipped']]);
    assert.deepEqual(statuses(`<testsuites ignored="true"><testsuites><testsuite>${tcx('a')}${tcx('b', '<skipped/>')}</testsuite></testsuites></testsuites>`), [['a', 'skipped'], ['b', 'skipped']]);
  });

  test('inherited skip flag: a failed case stays failed and does not account for a count', () => {
    assert.deepEqual(statuses(`<testsuites disabled="true"><testsuites><testsuite>${tcx('f', '<failure/>')}${tcx('e', '<error/>')}${tcx('r', '<flakyFailure/>')}${tcx('p')}</testsuite></testsuites></testsuites>`), [['f', 'failed'], ['e', 'failed'], ['r', 'failed'], ['p', 'skipped']]);
    unaccounted(`<testsuites disabled="true"><testsuite name="s" skipped="1">${tcx('f', '<failure/>')}</testsuite></testsuites>`, /^<testsuite name="s"> counts 1 skipped or disabled test\(s\), but only 0 of its testcases are marked skipped/);
  });

  test('inherited skip flag: a count with no flag above it, or a flag only on a sibling or "false", is still unaccounted', () => {
    unaccounted(`<testsuites><testsuite disabled="true">${tcx('a')}</testsuite><testsuite name="t" skipped="1">${tcx('b')}</testsuite></testsuites>`, /^<testsuite name="t"> counts 1 skipped or disabled test\(s\), but only 0 of/);
    unaccounted(`<testsuites disabled="false"><testsuite name="s" skipped="1">${tcx('n')}</testsuite></testsuites>`, /^<testsuite name="s"> counts 1 skipped/);
    unaccounted(`<testsuites skipped="true"><testsuite name="s" skipped="2">${tcx('n')}</testsuite></testsuites>`, /^<testsuite name="s"> counts 2 skipped or disabled test\(s\), but only 1 of/);
  });

  test('inherited skip flag: a testcase skip attribute is still validated under it', () => {
    unaccounted('<testsuite name="s" skipped="true"><testcase classname="c" name="n" skipped="yes"/></testsuite>', /^testcase n: skipped="yes" is not true, false, 1 or 0$/);
    unaccounted('<testsuites disabled="true"><testsuite name="s"><testcase classname="c" name="n" ignored="yes"/></testsuite></testsuites>', /^testcase n: ignored="yes" is not true, false, 1 or 0$/);
    unaccounted('<testsuites><testsuite name="s" ignored="true"><testcase classname="c" name="n" disabled="2"/></testsuite></testsuites>', /^testcase n: disabled="2" is not true, false, 1 or 0$/);
  });

  test('end to end: a bad testcase skip attribute under a suite flagged skipped is an input error', () => {
    for (const [suiteAttr, caseAttr] of [['skipped="true"', 'skipped="yes"'], ['disabled="true"', 'ignored="yes"']]) {
      const x = allPass(A24)
        .replace('<testsuites name="nextest-run"', `<testsuites name="nextest-run" ${suiteAttr}`)
        .replace(/(<testcase name="[^"]*a24_neg_replay")/, `$1 ${caseAttr}`);
      const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: x }])]);
      assert.equal(r.code, 2, suiteAttr);
      assert.equal(r.json.trusted, false);
      assert.equal(r.json.input_errors.length, 1);
      assert.match(r.json.input_errors[0], new RegExp(`junit\\.xml: malformed JUnit: testcase [^ ]*a24_neg_replay: ${caseAttr} is not true, false, 1 or 0; its results are not used$`));
      assert.equal(stage(r.json, 'A24', 'M1a').status, 'not run');
    }
  });

  test('end to end: a testcase marked disabled is not run, and an unaccounted suite count is an input error', () => {
    const marked = allPass(A24).replace(/(<testcase name="[^"]*a24_neg_replay")/, '$1 disabled="true"');
    assert.notEqual(marked, allPass(A24));
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: marked }])]);
    assert.equal(r.code, 0, r.err);
    const st = stage(r.json, 'A24', 'M1a');
    assert.equal(st.status, 'not run');
    assert.deepEqual(st.pairs.map((p) => p.status), ['passed', 'not run']);
    const counted = allPass(A24).replace('<testsuite name="skyoauth-scenarios::pg" tests="2">', '<testsuite name="skyoauth-scenarios::pg" tests="2" disabled="1">');
    assert.notEqual(counted, allPass(A24));
    const c = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: counted }])]);
    assert.equal(c.code, 2);
    assert.equal(c.json.trusted, false);
    assert.match(c.json.input_errors[0], /<testsuite name="skyoauth-scenarios::pg"> counts 1 skipped or disabled test\(s\), but only 0 of its testcases are marked skipped/);
    assert.equal(stage(c.json, 'A24', 'M1a').status, 'not run');
  });

  test('a suite-level error is an input error and the report is not used', () => {
    const x = allPass(A24).replace('<testsuite name="skyoauth-scenarios::pg" tests="2">', '<testsuite name="skyoauth-scenarios::pg" tests="2"><error message="binary crashed"/>');
    assert.notEqual(x, allPass(A24));
    const r = report(root(withA24), ['--artifacts', artifacts([{ leg: PG, junit: x }])]);
    assert.equal(r.code, 2);
    assert.match(plain(r.out), /junit\.xml: malformed JUnit: a suite-level <error> in <testsuite name="skyoauth-scenarios::pg">/);
    assert.equal(stage(r.json, 'A24', 'M1a').status, 'not run');
  });

  test('a duplicate testcase within one report keeps its worst status: failed > skipped > passed', () => {
    const C = rust('skyoauth-scenarios', 'pg', 'security::a24::a24_pos_c');
    const D = rust('skyoauth-scenarios', 'pg', 'security::a24::a24_neg_d');
    const cases = [[A24_POS, 'passed'], [A24_POS, 'failed'], [A24_POS, 'skipped'], [A24_NEG, 'skipped'], [A24_NEG, 'passed'], [C, 'skipped'], [C, 'failed'], [D, 'passed'], [D, 'skipped']];
    const r = report(root({ [SCENARIOS]: implement('scenario', 'A24', 'M1a', ids([...A24, C, D])) }), ['--artifacts', artifacts([{ leg: PG, junit: junit(cases) }])]);
    assert.deepEqual([A24_POS, A24_NEG, C, D].map((t) => pair(r.json, 'A24', 'M1a', t, PG).status), ['failed', 'not run', 'failed', 'not run']);
  });

  for (const [text, re] of [
    ['', /no root element/],
    ['  \n', /no root element/],
    ['<!-- only -->', /no root element/],
    ['<a></b>', /end tag <\/b> does not close <a>/],
    ['<a/></a>', /end tag <\/a> does not close any element/],
    ['<a>', /<a> is not closed/],
    ['<a/><b/>', /more than one root element/],
    ['x<a/>', /text outside the root element/],
    ['<a/>x', /text outside the root element/],
    ['<a b=1/>', /attribute b is not quoted/],
    ['<a b/>', /attribute b has no value/],
    ['<a b="1"c="2"/>', /malformed attribute in <a>/],
    ['<a b="1" b="2"/>', /duplicate attribute b/],
    ['<a b="1/>', /unterminated value of attribute b/],
    ['<a b="<"/>', /"<" in the value of attribute b/],
    ['<a b="&nope;"/>', /unknown entity &nope;/],
    ['<a b="&#0;"/>', /unknown entity &#0;/],
    ['<a b="&#x110000;"/>', /unknown entity &#x110000;/],
    ['<a>&amp</a>', /"&" that does not start an entity reference/],
    ['<a>&</a>', /"&" that does not start an entity reference/],
    ['<!DOCTYPE a><a/>', /DOCTYPE and other declarations are not supported/],
    ['<a><!-- x </a>', /unterminated comment/],
    ['<a><![CDATA[ x </a>', /unterminated CDATA section/],
    ['<![CDATA[x]]><a/>', /CDATA outside the root element/],
    ['<?xml version="1.0"', /unterminated processing instruction/],
    ['< a/>', /malformed start tag/],
    ['<a></ a>', /malformed end tag/],
    ['<a></a x>', /malformed end tag/],
    ['<a>\n\n</b>', /^line 3: /],
    ['\n<a></b>', /^line 2: /],
  ]) {
    test(`malformed XML ${JSON.stringify(text)}`, () => {
      assert.throws(() => parseXml(text), (ex) => ex instanceof InputError && re.test(ex.message));
    });
  }

  for (const [text, re] of [
    ['<report/>', /^the root element is <report>, not <testsuites> or <testsuite>$/],
    ['<testsuites><testcase classname="c" name="n"/></testsuites>', /a <testcase> outside any <testsuite>/],
    ['<testsuite><testcase name="n"/></testsuite>', /without a name or classname attribute \(n\)/],
    ['<testsuite><testcase classname="c"/></testsuite>', /without a name or classname attribute$/],
    ['<testsuite><testcase classname="c" name=""/></testsuite>', /without a name or classname attribute$/],
  ]) {
    test(`malformed JUnit ${JSON.stringify(text)}`, () => {
      assert.throws(() => readJUnit(text), (ex) => ex instanceof InputError && re.test(ex.message));
    });
  }
});

describe('aggregation', () => {
  test('worst ranks failed > planned > not run > passed', () => {
    assert.equal(worst([]), 'passed');
    assert.equal(worst(['passed', 'not run']), 'not run');
    assert.equal(worst(['not run', 'planned', 'passed']), 'planned');
    assert.equal(worst(['planned', 'failed', 'not run']), 'failed');
    assert.equal(worst(['failed', 'passed']), 'failed');
  });

  test('the full Markdown layout: waivers, every not-counted bucket, notes and ignored artifacts', () => {
    const P = 'nextest:skyoauth-scenarios/pg/a24_pos_x';
    const N = 'nextest:skyoauth-scenarios/pg/a24_neg_y';
    const C = 'c'.repeat(40);
    const scen = (id, status, tests) => ({ id, stage: [{ milestone: 'M1a', scope: 'full row', legs: [PG], status, tests }] });
    const res = (extra) =>
      judge({
        scenarios: [scen('A24', 'implemented', [P, N]), scen('A25', 'planned', ['nextest:skyoauth-scenarios/pg/a25_pos_z'])],
        subcases: [],
        contracts: [],
        commit: C,
        today: TODAY,
        waivers: [
          { commit: C, test: N, leg: PG, run_id: 5, run_attempt: 1, reason: 'lost db', expires: '2026-12-31' },
          { commit: C, test: P, leg: PG, run_id: 5, run_attempt: 3, reason: 'x', expires: '2026-12-31' },
        ],
        reports: [
          { run_id: 5, run_attempt: 1, leg: PG, artifact: '5/a-attempt-1', cases: new Map([[P, 'passed'], [N, 'failed'], ...extra]) },
          { run_id: 5, run_attempt: 2, leg: PG, artifact: '5/a-attempt-2', cases: new Map([[P, 'passed'], [N, 'passed']]) },
        ],
      });
    const all = [
      ['nextest:skyoauth-scenarios/pg/a25_pos_z', 'passed'],
      ['nextest:skyoauth-scenarios/pg/a24_pos_new', 'skipped'],
      ['nextest:skyoauth-scenarios/pg/a77_neg_q', 'failed'],
    ];
    const want = [
      "## Conformance results for `cccccccccccccccccccccccccccccccccccccccc`",
      "",
      "Judged on 2026-11-19 from 2 JUnit report(s). Only **passed** counts; `CI passed` is not a conformance signal.",
      "",
      "| Milestone | Stages | Passed | Failed | Not run | Planned | Gate |",
      "| --- | --- | --- | --- | --- | --- | --- |",
      "| M0 | 0 | 0 | 0 | 0 | 0 | no stages |",
      "| M1a | 2 | 1 | 0 | 0 | 1 | planned |",
      "| M1b | 0 | 0 | 0 | 0 | 0 | no stages |",
      "| M2 | 0 | 0 | 0 | 0 | 0 | no stages |",
      "| M3 | 0 | 0 | 0 | 0 | 0 | no stages |",
      "| M4 | 0 | 0 | 0 | 0 | 0 | no stages |",
      "| M5 | 0 | 0 | 0 | 0 | 0 | no stages |",
      "",
      "The counts cover required stages. Stages of conditional sub-IDs are listed with the implemented stages but gate no milestone.",
      "",
      "### Implemented stages (1)",
      "",
      "| Stage | Status | Details |",
      "| --- | --- | --- |",
      "| A24 M1a: full row | passed | `nextest:skyoauth-scenarios/pg/a24_neg_y` on `scenarios-pg/x86_64`: passed; waiver applied to run 5 attempt 1: lost db (expires 2026-12-31) |",
      "",
      "### Waivers for this commit",
      "",
      "- applied: `nextest:skyoauth-scenarios/pg/a24_neg_y` on `scenarios-pg/x86_64`, run 5 attempt 1: lost db (expires 2026-12-31)",
      "- **not applied**: `nextest:skyoauth-scenarios/pg/a24_pos_x` on `scenarios-pg/x86_64`, run 5 attempt 3: matches no failed attempt of a pair of an implemented stage (a waiver never applies to not run or planned)",
      "",
      "### Results not counted",
      "",
      "- planned stage, stays planned: `nextest:skyoauth-scenarios/pg/a25_pos_z` on `scenarios-pg/x86_64` passed (run 5 attempt 1)",
      "- not in any stage's tests: `nextest:skyoauth-scenarios/pg/a24_pos_new` on `scenarios-pg/x86_64` skipped (run 5 attempt 1)",
      "- unknown scenario test (no registry entry A77): `nextest:skyoauth-scenarios/pg/a77_neg_q` on `scenarios-pg/x86_64` failed (run 5 attempt 1)",
      "",
      "- note: n1",
      "- note: 1 artifact(s) without a `leg` file ignored (not conformance legs): `5/cov`",
      "",
    ].join('\n');
    assert.equal(renderMarkdown(res(all), { notes: ['n1'], ignored: ['5/cov'] }), want);
    // Each bucket alone still gets the heading; notes or ignored alone end
    // with a blank line.
    for (const one of all) assert.match(renderMarkdown(res([one])), /\n### Results not counted\n\n- [^\n]+\n$/);
    assert.ok(renderMarkdown(res([]), { notes: ['n1'] }).endsWith('\n- note: n1\n'));
    assert.ok(renderMarkdown(res([]), { ignored: ['5/cov'] }).endsWith('`5/cov`\n'));
    assert.ok(renderMarkdown(res([])).endsWith('(a waiver never applies to not run or planned)\n'));
  });

  test('the seen-outside-its-job listing: its own line under "Results not counted", after the other buckets, capped like them', () => {
    const OP = 'operator/ubuntu';
    const RO = 'recovery-offline/ubuntu';
    const P = 'nextest:skyoauth-operator/operator/a64_pos_x';
    const N = 'nextest:skyoauth-operator/operator/a64_neg_y';
    const res = (roCases, extra = []) =>
      judge({
        scenarios: [{ id: 'A64', stage: [{ milestone: 'M1a', scope: 'full row', legs: [OP], status: 'implemented', tests: [P, N] }] }],
        subcases: [],
        contracts: [],
        commit: SHA,
        today: TODAY,
        reports: [
          { run_id: 7, run_attempt: 1, leg: OP, artifact: '7/op-attempt-1', cases: new Map([[P, 'passed'], [N, 'passed']]) },
          { run_id: 7, run_attempt: 2, leg: RO, artifact: '7/ro-attempt-2', cases: new Map([...roCases, ...extra]) },
        ],
      });
    const one = res([[N, 'failed']]);
    assert.equal(one.failed, false);
    assert.equal(one.stages[0].status, 'passed');
    assert.deepEqual(one.uncounted.outside_job, [{ test: N, leg: RO, job: 'recovery-offline', produced_by: ['operator'], run_id: 7, run_attempt: 2, status: 'failed' }]);
    assert.ok(
      renderMarkdown(one).endsWith(
        '### Results not counted\n\n- seen outside its job, not counted: `nextest:skyoauth-operator/operator/a64_neg_y` on `recovery-offline/ubuntu` failed (run 7 attempt 2); job `recovery-offline` does not produce it, `operator` does\n',
      ),
      renderMarkdown(one),
    );
    // After the other buckets.
    const both = renderMarkdown(res([[N, 'skipped']], [['nextest:skyoauth-operator/recovery_offline/a77_neg_q', 'passed']]));
    assert.match(both, /\n- unknown scenario test \(no registry entry A77\): [^\n]+\n- seen outside its job, not counted: `nextest:skyoauth-operator\/operator\/a64_neg_y` on `recovery-offline\/ubuntu` skipped \(run 7 attempt 2\); [^\n]+\n$/);
    // Several producing jobs are all named; the list is capped at MAX_LIST.
    const many = Array.from({ length: MAX_LIST + 2 }, (_, i) => `nextest:skyoauth-operator/operator/a64_pos_t${i}`);
    const big = judge({
      scenarios: [{ id: 'A64', stage: [{ milestone: 'M1a', scope: 'full row', legs: [OP], status: 'implemented', tests: many }] }],
      subcases: [],
      contracts: [],
      commit: SHA,
      today: TODAY,
      reports: [{ run_id: 7, run_attempt: 1, leg: RO, artifact: '7/ro-attempt-1', cases: new Map(many.map((t) => [t, 'passed'])) }],
    });
    assert.equal(big.uncounted.outside_job.length, MAX_LIST + 2);
    const md = renderMarkdown(big);
    assert.equal((md.match(/^- seen outside its job, not counted: /gm) ?? []).length, MAX_LIST);
    assert.match(md, /^- … and 2 more results seen outside their job \(the JSON lists all of them\)$/m);
    const k3s = judge({
      scenarios: [{ id: 'A54', stage: [{ milestone: 'M1a', scope: 'full row', legs: ['scenarios-envoy-k3s/x86_64'], status: 'implemented', tests: ['nextest:skyoauth-scenarios/envoy_k3s/a54_pos_x'] }] }],
      subcases: [],
      contracts: [],
      commit: SHA,
      today: TODAY,
      reports: [{ run_id: 7, run_attempt: 1, leg: PG, artifact: '7/pg-attempt-1', cases: new Map([['nextest:skyoauth-scenarios/envoy_k3s/a54_pos_x', 'passed']]) }],
    });
    assert.match(renderMarkdown(k3s), /; job `scenarios-pg` does not produce it, `scenarios-envoy-k3s`, `scenarios-envoy-k3s-nightly`, `migration-rehearsal`, `deployed-topology-audit` do\n$/);
  });

  test('the seen-outside-its-job listing shows failed results first, so the MAX_LIST cap cannot hide one; the JSON keeps report order', () => {
    const OP = 'operator/ubuntu';
    const RO = 'recovery-offline/ubuntu';
    const passing = Array.from({ length: MAX_LIST + 2 }, (_, i) => `nextest:skyoauth-operator/operator/a64_pos_t${i}`);
    const F1 = 'nextest:skyoauth-operator/operator/a64_neg_f1';
    const F2 = 'nextest:skyoauth-operator/operator/a64_neg_f2';
    const res = judge({
      scenarios: [{ id: 'A64', stage: [{ milestone: 'M1a', scope: 'full row', legs: [OP], status: 'implemented', tests: [...passing, F1, F2] }] }],
      subcases: [],
      contracts: [],
      commit: SHA,
      today: TODAY,
      // A failed result in the middle and one past the cap, in report order.
      reports: [{ run_id: 7, run_attempt: 1, leg: RO, artifact: '7/ro-attempt-1', cases: new Map([...passing.slice(0, 3).map((t) => [t, 'passed']), [F1, 'failed'], ...passing.slice(3).map((t) => [t, 'passed']), [F2, 'failed']]) }],
    });
    assert.deepEqual(
      res.uncounted.outside_job.map((x) => x.test),
      [...passing.slice(0, 3), F1, ...passing.slice(3), F2],
      'the JSON keeps report order',
    );
    const lines = renderMarkdown(res)
      .split('\n')
      .filter((l) => l.startsWith('- seen outside its job, not counted: ') || l.startsWith('- … and '));
    assert.equal(lines.length, MAX_LIST + 1);
    assert.deepEqual(
      lines.slice(0, MAX_LIST).map((l) => /`([^`]+)` on `[^`]+` (\w+) /.exec(l).slice(1).join(' ')),
      [`${F1} failed`, `${F2} failed`, ...passing.slice(0, MAX_LIST - 2).map((t) => `${t} passed`)],
      'failed first, then the rest in report order',
    );
    assert.equal(lines[MAX_LIST], '- … and 4 more results seen outside their job (the JSON lists all of them)');
  });

  test('one sanitiser for outside text: control characters, line and bidi separators, length; text() escapes HTML and Markdown, code() quotes', () => {
    const ch = (...cps) => String.fromCodePoint(...cps);
    assert.equal(clean(`a${ch(13)}b${ch(10, 13)}c${ch(0)}d${ch(0x7f, 0x85)}e${ch(0x2028)}f${ch(0x2029)}g${ch(0x202e)}h${ch(0x200b)}i${ch(0xfeff)}j`), 'a b c d e f g h i j');
    assert.equal(clean('x'.repeat(MAX_TEXT)), 'x'.repeat(MAX_TEXT));
    assert.equal(clean('x'.repeat(MAX_TEXT + 1)), `${'x'.repeat(MAX_TEXT)}…`);
    assert.equal(clean(ch(0x1f600).repeat(MAX_TEXT + 1)), `${ch(0x1f600).repeat(MAX_TEXT)}…`, 'cut by code point, not inside a surrogate pair');
    assert.equal(text('<h1>a & b</h1>'), '&lt;h1&gt;a &amp; b&lt;/h1&gt;');
    assert.equal(text('&lt;h1&gt;'), '&amp;lt;h1&amp;gt;', 'entity text stays text');
    assert.equal(text('*b* _i_ `c` [l](u) ~s~ \\'), '\\*b\\* \\_i\\_ \\`c\\` \\[l\\](u) \\~s\\~ \\\\');
    assert.equal(code('a`b<c>&lt;'), "`a'b<c>&lt;`");
    assert.equal(code(`a${ch(13)}b`), '`a b`');
  });

  test('renderMarkdown passes every outside string through the sanitiser, escapes table cells and caps lists', () => {
    const res = judge({ scenarios: [], subcases: [], contracts: [], reports: [], commit: SHA, today: TODAY });
    const md = renderMarkdown(res, { inputErrors: ['a|b\nc<i>'], notes: ['x|y*'], ignored: ['5/`x`'] });
    assert.match(md, /^- a\|b c&lt;i&gt;$/m);
    assert.match(md, /^- note: x\|y\\\*$/m);
    assert.match(md, /`5\/'x'`/);
    const many = (n, f) => Array.from({ length: n }, (_, i) => f(i));
    const big = renderMarkdown(res, { inputErrors: many(MAX_LIST + 10, (i) => `e${i}`), notes: many(MAX_LIST + 1, (i) => `n${i}`), ignored: many(MAX_LIST + 2, (i) => `9/i${i}`) });
    assert.equal((big.match(/^- e\d+$/gm) ?? []).length, MAX_LIST);
    assert.match(big, /^- … and 10 more input errors \(the JSON lists all of them\)$/m);
    assert.equal((big.match(/^- note: n\d+$/gm) ?? []).length, MAX_LIST);
    assert.match(big, /^- … and 1 more notes \(the JSON lists all of them\)$/m);
    assert.match(big, /^- note: 52 artifact\(s\) without a `leg` file ignored \(not conformance legs\): `9\/i0`.*`9\/i49` and 2 more$/m);
    // A stage label and its problems from the registry go through text()
    // and cell().
    const P = 'nextest:skyoauth-scenarios/pg/a24_pos_<b>|x';
    const st = judge({ scenarios: [{ id: 'A24', stage: [{ milestone: 'M1a', scope: 'a|b <i>', legs: [PG], status: 'implemented', tests: [P] }] }], subcases: [], contracts: [], reports: [], commit: SHA, today: TODAY });
    const row = renderMarkdown(st).split('\n').find((l) => l.startsWith('| A24'));
    assert.equal(row.split(/(?<!\\)\|/).length, 5, row);
    assert.ok(row.startsWith('| A24 M1a: a\\|b &lt;i&gt; | not run | '), row);
    assert.doesNotMatch(row, /<b>|<i>/);
  });

  test('the documented limits (README "Output and exit status", "Input")', () => {
    assert.equal(MAX_TEXT, 300);
    assert.equal(MAX_LIST, 50);
    assert.equal(MAX_DEPTH, 100);
    assert.deepEqual(MAX_BYTES, { leg: 1024, 'junit.xml': 64 * 1024 * 1024 });
  });

  test('a list of exactly MAX_LIST items is shown whole; a stage with more details is cut', () => {
    const res = judge({ scenarios: [], subcases: [], contracts: [], reports: [], commit: SHA, today: TODAY });
    const many = (n, f) => Array.from({ length: n }, (_, i) => f(i));
    const md = renderMarkdown(res, { inputErrors: many(MAX_LIST, (i) => `e${i}`), ignored: many(MAX_LIST, (i) => `9/i${i}`) });
    assert.doesNotMatch(md, /more/);
    const tests = many(MAX_LIST + 3, (i) => `nextest:skyoauth-scenarios/pg/a25_pos_t${i}`);
    const st = judge({ scenarios: [{ id: 'A24', stage: [{ milestone: 'M1a', scope: 'full row', legs: [PG], status: 'implemented', tests }] }], subcases: [], contracts: [], reports: [], commit: SHA, today: TODAY });
    const row = renderMarkdown(st).split('\n').find((l) => l.startsWith('| A24'));
    const shown = row.split(' | ')[2].split('<br>');
    assert.equal(shown.length, MAX_LIST + 1);
    assert.match(shown[0], /^nextest:skyoauth-scenarios\/pg\/a25\\_pos\\_t0 is not a pos\/neg scenario test of A24$/);
    assert.match(shown[MAX_LIST], /^… and \d+ more \(the JSON lists all of them\)/);
    // Exactly MAX_LIST details (MAX_LIST - 2 tests of another entry, plus no
    // pos and no neg test for the job) are shown whole.
    const exact = judge({ scenarios: [{ id: 'A24', stage: [{ milestone: 'M1a', scope: 'full row', legs: [PG], status: 'implemented', tests: tests.slice(0, MAX_LIST - 2) }] }], subcases: [], contracts: [], reports: [], commit: SHA, today: TODAY });
    assert.equal(exact.stages[0].problems.length, MAX_LIST);
    const exactRow = renderMarkdown(exact).split('\n').find((l) => l.startsWith('| A24'));
    assert.equal(exactRow.split(' | ')[2].split('<br>').length, MAX_LIST);
    assert.doesNotMatch(exactRow, /more \(the JSON/);
  });

  test('hostile artifacts: raw HTML in a leg file, entity text and a lone CR in testcase names, a 3 MB leg file', () => {
    const name = 'junit-scenarios-pg-x86_64-attempt-1';
    const d = artifacts([
      { run: 1, leg: '<h1>hi</h1><img src=x onerror=alert(1)>', name, junit: null },
      { run: 2, leg: PG, name, junit: junit([[rust('skyoauth-scenarios', 'pg', 'x::a99_pos_&lt;h1&gt;y'), 'passed'], [rust('skyoauth-scenarios', 'pg', `x::a98_neg_a${String.fromCharCode(13)}| b`), 'failed']]) },
      { run: 3, leg: null, name, junit: null },
    ]);
    writeFileSync(join(d, '3', name, 'leg'), `${PG}\n${'x'.repeat(3 * 1024 * 1024)}`);
    const r = report(root(withA24), ['--artifacts', d]);
    assert.equal(r.code, 2);
    assert.match(r.out, /^- 1\/junit-scenarios-pg-x86\\_64-attempt-1: leg file names "&lt;h1&gt;hi&lt;\/h1&gt;&lt;img src=x onerror=alert\(1\)&gt;", which is not a layout §1\.1 leg string$/m);
    assert.match(r.out, /^- 3\/junit-scenarios-pg-x86\\_64-attempt-1\/leg: 3145748 bytes, more than the 1024 it may hold; not read$/m);
    // The XML entity &amp;lt; is the text "&lt;": it stays text in a code span.
    assert.match(r.out, /^- unknown scenario test \(not a well-formed pos\/neg scenario name\): `nextest:skyoauth-scenarios\/pg\/x::a99_pos_&lt;h1&gt;y` on/m);
    assert.match(r.out, /^- unknown scenario test \(not a well-formed pos\/neg scenario name\): `nextest:skyoauth-scenarios\/pg\/x::a98_neg_a \| b` on `scenarios-pg\/x86_64` failed/m);
    assert.equal(r.json.uncounted.unknown[1].test, `nextest:skyoauth-scenarios/pg/x::a98_neg_a${String.fromCharCode(13)}| b`, 'the JSON keeps the raw name');
    assert.doesNotMatch(r.out, /<h1>|<img|\r/);
    assert.ok(r.out.length < 20000, `${r.out.length} characters`);
  });
});

describe('cli', () => {
  test('usage errors exit 2', () => {
    const dir = root();
    for (const [args, re] of [
      [[], /--commit must be a full 40-character lowercase hex SHA/],
      [['--commit', 'abc'], /--commit must be/],
      [['--commit', SHA.toUpperCase()], /--commit must be/],
      [['--commit', SHA, '--today', '19.11.2026'], /--today must be a calendar date YYYY-MM-DD/],
      [['--commit', SHA, '--today', '0000-00-00'], /--today must be a calendar date/],
      [['--commit', SHA, '--today', '2026-02-30'], /--today must be a calendar date/],
      [['--commit', SHA, '--today', '2026-13-01'], /--today must be a calendar date/],
      [['--commit', SHA, '--today', '2025-02-29'], /--today must be a calendar date/],
      [['--commit', SHA, '--require-milestone', 'M9'], /--require-milestone must be one of M0, M1a/],
      [['--commit', SHA, '--bogus'], /^usage: /],
      [['--commit', SHA, '--commit', 'b'.repeat(40)], /^report-conformance: --commit given more than once\nusage: /],
      [['--commit', SHA, '--today', TODAY, '--today', TODAY], /--today given more than once/],
      [['--commit', SHA, '--require-milestone', 'M1a', '--require-milestone', 'M1b'], /--require-milestone given more than once/],
      [['--commit', SHA, '--waivers', 'a', '--waivers', 'b'], /--waivers given more than once/],
      [['--commit', SHA, '--artifacts', 'a', '--artifacts', 'b'], /--artifacts given more than once/],
      [['--commit', SHA, '--json', 'a', '--json', 'b'], /--json given more than once/],
      [['--commit', SHA, '--summary', 'a', '--summary', 'b'], /--summary given more than once/],
      [['--root', '.', '--commit', SHA], /--root given more than once/],
      [['--commit'], /^usage: /],
    ]) {
      const err = [];
      const out = [];
      assert.equal(run(['--root', dir, ...args], { log: (s) => out.push(s), logErr: (s) => err.push(s) }), 2, args.join(' '));
      assert.match(err.join('\n'), re);
      assert.deepEqual(out, [], 'no report');
    }
  });

  test('registry errors stop the report with exit 2', () => {
    const dir = root({ [SCENARIOS]: (t) => t.replace('status = "planned"', 'status = "implemented"') });
    const r = report(dir);
    assert.equal(r.code, 2);
    assert.match(r.err, /error \[stages\]/);
    assert.match(r.err, /report-conformance: the registry has \d+ error\(s\); no report/);
    assert.equal(r.json, null);
  });

  test('--json writes indented JSON', () => {
    const j = join(tmp('report-json-'), 'out.json');
    assert.equal(run(['--root', root(), '--commit', SHA, '--today', TODAY, '--json', j], { log: () => {}, logErr: () => {} }), 0);
    assert.equal(run(['--root', root(), '--commit', SHA, '--today', '2028-02-29', '--json', j], { log: () => {}, logErr: () => {} }), 0, 'a leap day is a date');
    assert.ok(readFileSync(j, 'utf8').startsWith('{\n  "format": 1,\n  "commit": "'));
  });

  test('--summary appends the Markdown; --today defaults to the injected date', () => {
    const f = join(tmp('report-sum-'), 'summary.md');
    writeFileSync(f, 'before\n');
    const out = [];
    const code = run(['--root', root(), '--commit', SHA, '--summary', f], { log: (s) => out.push(s), logErr: () => {}, now: new Date('2027-03-04T23:59:59Z') });
    assert.equal(code, 0);
    const text = readFileSync(f, 'utf8');
    assert.ok(text.startsWith('before\n## Conformance results for'));
    assert.ok(text.endsWith(`${out.at(-1)}\n`));
    assert.match(text, /Judged on 2027-03-04 from 0 JUnit report\(s\)\. Only \*\*passed\*\* counts; `CI passed` is not a conformance signal\./);
  });

  // The committed registry changes as stages are implemented and gates pass,
  // so this case checks only that the report is produced and well-formed.
  test('the script runs on the repository: exit 0 and a milestone table', () => {
    // In a git checkout the judged commit must be HEAD.
    const head = spawnSync('git', ['-C', REPO, 'rev-parse', 'HEAD'], { encoding: 'utf8', env: childEnv() });
    // The inherited environment, GIT_DIR included (assertGitImmune runs this
    // test with one exported), less the runner's variables.
    const p = spawnSync(process.execPath, [SCRIPT, '--commit', head.status === 0 ? head.stdout.trim() : SHA, '--today', TODAY], { encoding: 'utf8', env: withoutRunner(process.env) });
    assert.equal(p.status, 0, p.stderr);
    for (const m of ['M0', 'M1a', 'M1b', 'M2', 'M3', 'M4', 'M5']) {
      assert.match(p.stdout, new RegExp(`^\\| ${m} \\| \\d+ \\| \\d+ \\| \\d+ \\| \\d+ \\| \\d+ \\| (?:passed|failed|not run|planned|no stages) \\|$`, 'm'));
    }
    assert.match(p.stdout, /^### Implemented stages \(\d+\)$/m);
    const bad = spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8', env: withoutRunner(process.env) });
    assert.equal(bad.status, 2);
  });
});
