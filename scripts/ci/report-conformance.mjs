#!/usr/bin/env node
// Conformance result reporter: the "Result join (reporter)" of
// docs/testing/conformance-layout.md §3. It joins the JUnit reports of every
// workflow run and attempt for ONE commit with the registry and prints, per
// (scenario, stage) and per milestone, passed / failed / not run / planned.
//
//   node scripts/ci/report-conformance.mjs --commit SHA [--artifacts DIR]
//        [--waivers FILE] [--root DIR] [--today YYYY-MM-DD] [--docs-only]
//        [--require-milestone M] [--require-history]
//        [--allow-commit-mismatch] [--json FILE] [--summary FILE]
//
// Each value option may be given once; a repeat is a usage error.
//
// Input
//   --artifacts DIR   Downloaded artifacts of every run for the commit, one
//                     directory per run named by its numeric run ID, one
//                     directory per artifact inside it (what
//                     `gh run download RUN_ID -D DIR/RUN_ID` writes), and
//                     the run's metadata in run.json:
//                       DIR/<run_id>/run.json
//                       DIR/<run_id>/<artifact name ending in attempt-N>/junit.xml
//                       DIR/<run_id>/<artifact name ending in attempt-N>/leg
//                     run.json is `gh run view RUN_ID --json
//                     databaseId,headSha,attempt,workflowName`: headSha must
//                     be --commit, databaseId the directory name, and no
//                     artifact may be from a later attempt; otherwise the
//                     run is an input error and is not used.
//                     `leg` holds one layout §1.1 leg string; a leg artifact
//                     holds nothing else. Only the known artifacts of other
//                     jobs (NOT_CONFORMANCE: service-nextest-junit-N,
//                     rust-coverage, typescript-coverage) may lack a `leg`
//                     file; they are ignored. Any other artifact without one,
//                     and a leg or junit.xml in a subdirectory, is an input
//                     error.
//                     Omitted: no results at all.
//   --waivers FILE    tests/conformance/waivers.toml from the tip of main
//                     (layout §3 "Waivers"); the caller fetches it, for
//                     example with `git show origin/main:tests/conformance/waivers.toml`.
//                     The waivers for --commit get the registry check's full
//                     waiver rule, the others only its shape checks.
//   --root DIR        Checkout of the judged commit (default: this
//                     repository). In a git checkout, HEAD must be --commit
//                     (else exit 2, no report; --allow-commit-mismatch
//                     prints the report as untrusted). Its registry is
//                     checked first with check-conformance-registry.mjs; any
//                     error stops the report.
//   --today DATE      Judging date for waiver expiry (default: today, UTC);
//                     an impossible date is a usage error.
//   --docs-only       The docs-only classifier skipped the build jobs: the
//                     summary starts with "runtime conformance: not run
//                     (docs-only change)".
//
// Rules (layout §3, §4)
//   * A testcase is failed when it has <failure>, <error> or a retry marker
//     (<flakyFailure>, <flakyError>, <rerunFailure>, <rerunError>), matched
//     by local name: retries are 0, so a pass after a retry is a failure.
//     <skipped>, <ignored>, <disabled> or a skipped status attribute is not
//     run. Passed is an allow-list (only <system-out>, <system-err>,
//     <properties>); an unknown element or a suite-level failure is an input
//     error.
//   * A failed attempt is permanent for (commit, test, leg): a later passing
//     attempt does not overwrite it. Only a waiver that names that exact
//     attempt (commit, test, leg, run_id, run_attempt) and has not expired
//     discards it, and the pair still needs a passing attempt.
//   * A pair (test, leg) is checked for every leg of an implemented stage
//     whose job produces the test (TEST_JOBS). Passed needs a passing case
//     from that leg; a missing or skipped case, or a leg without a report,
//     is not run.
//   * Stage = worst pair, failed > not run > passed. A stage that cannot be
//     judged (a listed test that is not a scenario test of this entry, that
//     no job among its legs produces, or a job without a pos and a neg test)
//     is not run. A planned stage is planned, whatever results exist.
//   * Scenario at milestone M = worst of its stages up to M and those of its
//     required sub-IDs; contract = passed only when every covered scenario
//     passed. Aggregates rank failed > planned > not run > passed.
//
// Output: a Markdown summary on stdout (appended to --summary FILE too, such
// as "$GITHUB_STEP_SUMMARY"), and JSON with --json FILE.
//
// Exit status (exitStatus below; tests/conformance/README.md "Output and
// exit status" is the one place that documents it)
//   2  usage, registry or waiver-file errors (no report), or input errors
//      (the report is printed with trusted: false, but cannot be trusted;
//      with --require-milestone, a --root that is not a git checkout is
//      one, as the gate would judge a registry not bound to --commit);
//   with --require-milestone M, otherwise:
//   0  the gate of M is passed (every stage it covers is passed);
//   1  it is not. Stages of other milestones and of conditional sub-IDs do
//      not change the exit status; their failures stay in the report;
//   without --require-milestone, otherwise:
//   1  some implemented stage, of any milestone, conditional sub-IDs
//      included, has a failed (unwaived) pair;
//   0  none has.

import { spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseStrict } from 'smol-toml';

import { checkRegistry, checkWaivers, formatError, history, load, locate, Report, WAIVERS } from './check-conformance-registry.mjs';
import { LAYOUT, MILESTONES, parseEnvironments, SCENARIOS, SUBCASES } from './gen-conformance-registry.mjs';

// ---------------------------------------------------------------------------
// XML (the subset JUnit reporters write)

export class InputError extends Error {}

const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
const NAME = /[A-Za-z_:][-A-Za-z0-9_:.]*/y;
const SPACE = /[ \t\r\n]/;
// JUnit nests a few levels deep; the limit keeps a hostile file from
// exhausting the stack of the readers that walk the tree.
export const MAX_DEPTH = 100;

// Parses well-formed XML into { name, attrs, children } elements and returns
// the root element. Text is checked but not kept. DOCTYPE is rejected. A
// leading byte order mark is whitespace to trim(), so it needs no case.
export function parseXml(text) {
  let i = 0;
  const fail = (msg, at = i) => {
    throw new InputError(`line ${text.slice(0, at).split('\n').length}: ${msg}`);
  };
  const decode = (s, at) =>
    s.replace(/&([^;&]*)(;?)/g, (all, ent, semi) => {
      if (!semi) fail('"&" that does not start an entity reference', at);
      if (Object.hasOwn(ENTITIES, ent)) return ENTITIES[ent];
      const n = /^#x([0-9A-Fa-f]+)$/.exec(ent) ? parseInt(ent.slice(2), 16) : /^#([0-9]+)$/.test(ent) ? Number(ent.slice(1)) : NaN;
      if (!(n > 0 && n <= 0x10ffff)) fail(`unknown entity &${ent};`, at);
      return String.fromCodePoint(n);
    });
  const name = (at) => {
    NAME.lastIndex = at;
    return NAME.exec(text)?.[0];
  };
  const skip = (j) => {
    while (j < text.length && SPACE.test(text[j])) j++;
    return j;
  };
  const doc = { name: '', attrs: {}, children: [] };
  const stack = [doc];
  while (i < text.length) {
    const lt = text.indexOf('<', i);
    const end = lt < 0 ? text.length : lt;
    if (end > i) {
      const chunk = text.slice(i, end);
      if (stack.length === 1 && chunk.trim() !== '') fail('text outside the root element');
      decode(chunk, i);
      i = end;
      continue;
    }
    const close = (marker, what) => {
      const e = text.indexOf(marker, i);
      if (e < 0) fail(`unterminated ${what}`);
      i = e + marker.length;
    };
    if (text.startsWith('<!--', i)) close('-->', 'comment');
    else if (text.startsWith('<![CDATA[', i)) {
      if (stack.length === 1) fail('CDATA outside the root element');
      close(']]>', 'CDATA section');
    } else if (text.startsWith('<?', i)) close('?>', 'processing instruction');
    else if (text.startsWith('<!', i)) fail('DOCTYPE and other declarations are not supported');
    else if (text.startsWith('</', i)) {
      const n = name(i + 2);
      const j = n ? skip(i + 2 + n.length) : i;
      if (!n || text[j] !== '>') fail('malformed end tag');
      const top = stack.pop();
      if (top === doc || top.name !== n) fail(`end tag </${n}> does not close ${top === doc ? 'any element' : `<${top.name}>`}`);
      i = j + 1;
    } else {
      const n = name(i + 1);
      if (!n) fail('malformed start tag');
      const el = { name: n, attrs: {}, children: [] };
      let j = i + 1 + n.length;
      let empty = false;
      for (;;) {
        const k = skip(j);
        if (text[k] === '>') {
          j = k + 1;
          break;
        }
        if (text.startsWith('/>', k)) {
          j = k + 2;
          empty = true;
          break;
        }
        const a = k > j ? name(k) : undefined;
        if (!a) fail(`malformed attribute in <${n}>`, k);
        let v = skip(k + a.length);
        if (text[v] !== '=') fail(`attribute ${a} has no value`, v);
        v = skip(v + 1);
        const q = text[v];
        if (q !== '"' && q !== "'") fail(`attribute ${a} is not quoted`, v);
        const e = text.indexOf(q, v + 1);
        if (e < 0) fail(`unterminated value of attribute ${a}`, v);
        if (text.slice(v + 1, e).includes('<')) fail(`"<" in the value of attribute ${a}`, v);
        if (Object.hasOwn(el.attrs, a)) fail(`duplicate attribute ${a}`, k);
        el.attrs[a] = decode(text.slice(v + 1, e), v);
        j = e + 1;
      }
      if (stack.length === 1 && doc.children.length) fail('more than one root element');
      stack[stack.length - 1].children.push(el);
      if (!empty) stack.push(el);
      if (stack.length - 1 > MAX_DEPTH) fail(`elements nested more than ${MAX_DEPTH} deep`);
      i = j;
    }
  }
  if (stack.length > 1) fail(`<${stack[stack.length - 1].name}> is not closed`, text.length);
  if (!doc.children.length) fail('no root element');
  return doc.children[0];
}

// ---------------------------------------------------------------------------
// JUnit

// Children that make a testcase failed. The flaky and rerun elements are
// what nextest writes for retries; with retries = 0 they mean a retry ran,
// and a pass after a retry counts as failed (layout §3).
export const FAILED_ELEMENTS = new Set(['failure', 'error', 'flakyFailure', 'flakyError', 'rerunFailure', 'rerunError']);
// Children that make a testcase not run.
export const SKIPPED_ELEMENTS = new Set(['skipped', 'ignored', 'disabled']);
// Children that carry no verdict. "Passed" is an allow-list: a testcase is
// passed only when every child is one of these and its status attribute, if
// any, is a passing one. Any other element is an input error, so a reporter
// that starts writing a new verdict element cannot be read as a pass.
const QUIET_ELEMENTS = new Set(['system-out', 'system-err', 'properties']);
const STATUS_ATTR = { passed: 'passed', success: 'passed', run: 'passed', skipped: 'skipped', notrun: 'skipped', disabled: 'skipped', ignored: 'skipped', failed: 'failed', failure: 'failed', error: 'failed' };
// Elements are matched by local name, so a namespaced <j:failure> is a
// failure too.
const local = (n) => n.slice(n.lastIndexOf(':') + 1);

// The testcases of a JUnit report: [{ classname, name, status }], status one
// of passed, failed, skipped. Throws InputError for a malformed report, for
// an element it does not know inside a <testsuite> or <testcase>, and for a
// suite-level failure (a <failure>, <error> or retry marker directly in a
// <testsuite>, such as a setup crash): it cannot be pinned to a testcase, so
// the report is not used and the result cannot be trusted.
export function readJUnit(text) {
  const root = parseXml(text);
  if (local(root.name) !== 'testsuites' && local(root.name) !== 'testsuite') throw new InputError(`the root element is <${root.name}>, not <testsuites> or <testsuite>`);
  const cases = [];
  const walk = (el, inSuite) => {
    for (const c of el.children) {
      const n = local(c.name);
      if (n === 'testsuite' || n === 'testsuites') walk(c, n === 'testsuite' || inSuite);
      else if (n === 'testcase') {
        if (!inSuite) throw new InputError('a <testcase> outside any <testsuite>');
        const { name, classname } = c.attrs;
        if (!name || classname === undefined) throw new InputError(`a <testcase> without a name or classname attribute${name ? ` (${name})` : ''}`);
        const st = c.attrs.status;
        if (st !== undefined && !Object.hasOwn(STATUS_ATTR, st)) throw new InputError(`testcase ${name}: unknown status="${st}"`);
        const kids = c.children.map((k) => local(k.name));
        const odd = kids.find((k) => !FAILED_ELEMENTS.has(k) && !SKIPPED_ELEMENTS.has(k) && !QUIET_ELEMENTS.has(k));
        if (odd !== undefined) throw new InputError(`testcase ${name}: unknown element <${odd}>`);
        const verdicts = [st === undefined ? 'passed' : STATUS_ATTR[st], ...kids.map((k) => (FAILED_ELEMENTS.has(k) ? 'failed' : SKIPPED_ELEMENTS.has(k) ? 'skipped' : 'passed'))];
        const status = verdicts.includes('failed') ? 'failed' : verdicts.includes('skipped') ? 'skipped' : 'passed';
        cases.push({ classname, name, status });
      } else if (FAILED_ELEMENTS.has(n)) throw new InputError(`a suite-level <${c.name}> in <${el.name}${el.attrs.name !== undefined ? ` name="${el.attrs.name}"` : ''}>: it fails no particular testcase`);
      else if (!QUIET_ELEMENTS.has(n)) throw new InputError(`unknown element <${c.name}> in <${el.name}>`);
    }
  };
  walk(root, local(root.name) === 'testsuite');
  return cases;
}

// ---------------------------------------------------------------------------
// Test IDs and names (layout §3 "Test names", "Which job produces a test")

// PROVISIONAL (docs/testing/conformance-layout.md §6 "Still open", item 5):
// the runner whose JUnit each job's legs upload. A job without an entry has
// no decided runner (bundle-check has no test source; migration-rehearsal
// drives Playwright and the CLI as well as nextest), so its artifacts are an
// input error and a stage with one of its legs cannot pass: never guess
// nextest.
export const JOB_RUNNER = {
  'scenarios-hermetic': 'nextest',
  'scenarios-pg': 'nextest',
  'scenarios-envoy-k3s': 'nextest',
  'scenarios-envoy-k3s-nightly': 'nextest',
  'deployed-topology-audit': 'nextest',
  'live-wif-push': 'nextest',
  'live-wif-negative': 'nextest',
  'clients-rust': 'nextest',
  'clients-rust-native': 'nextest',
  operator: 'nextest',
  'recovery-offline': 'nextest',
  typescript: 'vitest',
  'typescript-browser': 'playwright',
};
export const runnerOf = (job) => (Object.hasOwn(JOB_RUNNER, job) ? JOB_RUNNER[job] : null);
const NO_RUNNER = 'has no decided runner (layout §6 "Still open", item 5)';
export const jobOf = (leg) => leg.split('/')[0];

// Layout §3 "Which job produces a test": [runner, package, target, jobs];
// null matches any package or target. PROVISIONAL in two ways (layout §6
// "Still open"): skyoauth-service is absent because service/ tests are not
// conformance evidence for now (item 3), and a test whose package and target
// fix several jobs is expected from every one of them that its stage lists,
// until a per-target job mapping exists (item 4).
export const TEST_JOBS = [
  ['nextest', 'skyoauth-scenarios', 'hermetic', ['scenarios-hermetic']],
  ['nextest', 'skyoauth-scenarios', 'pg', ['scenarios-pg']],
  ['nextest', 'skyoauth-scenarios', 'envoy_k3s', ['scenarios-envoy-k3s', 'scenarios-envoy-k3s-nightly', 'migration-rehearsal', 'deployed-topology-audit']],
  ['nextest', 'skyoauth-scenarios', 'live', ['live-wif-push', 'live-wif-negative']],
  ['nextest', 'skyoauth-client', null, ['clients-rust', 'clients-rust-native']],
  ['nextest', 'skyoauth-operator', null, ['operator', 'recovery-offline']],
  ['vitest', null, null, ['typescript']],
  ['playwright', null, null, ['typescript-browser']],
];

// The registry test ID of a JUnit testcase. Layout §3 fixes only the nextest
// form with a target; the lib, vitest and Playwright forms are PROVISIONAL
// (layout §6 "Still open", item 5) until those runners report conformance
// tests:
//   nextest     classname "<package>::<binary>" -> nextest:<package>/<binary>/<name>
//               classname "<package>" (lib)      -> nextest:<package>/<name>
//   vitest      classname "<file>"               -> vitest:<file>/<name>
//   playwright  classname "<file>"               -> playwright:<file>/<name>
export function testId(runner, classname, name) {
  if (runner !== 'nextest') return `${runner}:${classname}/${name}`;
  const k = classname.indexOf('::');
  return `nextest:${k < 0 ? classname : `${classname.slice(0, k)}/${classname.slice(k + 2)}`}/${name}`;
}

const TS_FILE = /^(.*?\.(?:test|spec)\.[cm]?[jt]sx?)\/(.+)$/s;
const RUST_LIKE = /^a\d\d_/;
const RUST_NAME = /^a(\d\d)(?:_(\d\d))?_(pos|neg)_\w+$/;
const VITEST_LIKE = /(?:^|> )A\d\d[ .]/;
const VITEST_NAME = /(?:^|> )A(\d\d)(?:\.(\d\d))? (pos|neg): \S/;
const PW_LIKE = /^A\d\d[ .]/;
const PW_NAME = /^A(\d\d)(?:\.(\d\d))? (pos|neg): \S/;

// Parses a test ID. Returns null for an ID that is not runner:… at all, or
// { id, runner, pkg, target, like, entry, polarity }: `like` is true when the
// name matches the scenario pattern of layout §3 (last path segment for Rust,
// any " > " segment for vitest, the own title for Playwright); `entry`
// ("A24" or "A58.07") and `polarity` are set when it is also well-formed.
export function testInfo(id) {
  const m = /^(nextest|vitest|playwright):(.+)$/s.exec(id);
  if (!m) return null;
  const [, runner, rest] = m;
  let pkg = null;
  let target = null;
  let like;
  let named;
  if (runner === 'nextest') {
    const first = rest.indexOf('/');
    const last = rest.lastIndexOf('/');
    if (first <= 0 || last === rest.length - 1) return null;
    pkg = rest.slice(0, first);
    target = first === last ? '' : rest.slice(first + 1, last);
    const segment = rest.slice(last + 1).split('::').pop();
    like = RUST_LIKE.test(segment);
    named = RUST_NAME.exec(segment);
  } else {
    const t = TS_FILE.exec(rest);
    if (!t) return null;
    const title = runner === 'vitest' ? t[2] : t[2].split(' › ').pop();
    like = (runner === 'vitest' ? VITEST_LIKE : PW_LIKE).test(title);
    named = (runner === 'vitest' ? VITEST_NAME : PW_NAME).exec(title);
  }
  const entry = like && named ? `A${named[1]}${named[2] ? `.${named[2]}` : ''}` : null;
  const jobs = TEST_JOBS.find(([r, p, tg]) => r === runner && (p === null || p === pkg) && (tg === null || tg === target))?.[3] ?? [];
  return { id, runner, pkg, target, like, entry, polarity: entry ? named[3] : null, jobs };
}

// ---------------------------------------------------------------------------
// Artifacts

const RANK = { passed: 0, skipped: 1, failed: 2 };

// The files of a conformance (leg) artifact, and the most bytes each may
// hold: a leg string is short, and the reports are not read unbounded.
const LEG_FILES = ['leg', 'junit.xml'];
export const MAX_BYTES = { leg: 1024, 'junit.xml': 64 * 1024 * 1024 };
// Artifacts of jobs that are not conformance legs (ci.yml): the only ones
// that may lack a leg file. Any other artifact without one is an input error.
// The self-test checks this list against the workflows' upload steps.
export const NOT_CONFORMANCE = [/^service-nextest-junit-[1-9]\d*$/, /^rust-coverage$/, /^typescript-coverage$/];

// What a path is, without following a symbolic link: dir, file, symlink,
// other or missing. Other file system errors are thrown.
function kindOf(p) {
  try {
    const st = lstatSync(p);
    return st.isSymbolicLink() ? 'symlink' : st.isDirectory() ? 'dir' : st.isFile() ? 'file' : 'other';
  } catch (ex) {
    if (ex.code === 'ENOENT') return 'missing';
    throw ex;
  }
}
const KIND = { symlink: 'a symbolic link', dir: 'a directory', other: 'a special file', missing: 'missing' };

// Reads one artifact directory. Returns { error }, { ignored: true }, or
// { report, note }; file system errors are thrown.
function readArtifact(dir, run, artifact, catalogue) {
  const rel = `${run}/${artifact}`;
  const path = join(dir, run, artifact);
  const k = kindOf(path);
  if (k !== 'dir') return { error: k === 'symlink' ? `${rel}: a symbolic link; the artifacts tree holds plain files and directories only` : `${rel}: a run directory holds only artifact directories` };
  const entries = readdirSync(path).sort();
  const kinds = new Map(entries.map((x) => [x, kindOf(join(path, x))]));
  const links = entries.filter((x) => kinds.get(x) === 'symlink');
  if (links.length) return { error: `${rel}: ${links.join(', ')}: a symbolic link; the artifacts tree holds plain files and directories only` };
  // A leg or junit.xml one level down (an upload whose paths had another
  // common ancestor) would otherwise go unread.
  const nested = entries.filter((x) => kinds.get(x) === 'dir' && LEG_FILES.some((f) => kindOf(join(path, x, f)) !== 'missing'));
  if (nested.length) return { error: `${rel}: ${nested.map((x) => `${x}/`).join(', ')} holds a leg or junit.xml file; they belong at the top of the artifact` };
  if (!entries.includes('leg')) {
    // Only the known artifacts of other jobs may lack a leg file; any other
    // one (a leg artifact that lost its leg file, say) could hide a failed
    // attempt.
    if (NOT_CONFORMANCE.some((re) => re.test(artifact))) return { ignored: true };
    return { error: `${rel}: no leg file, and not a known artifact of a non-conformance job (${NOT_CONFORMANCE.map((re) => re.source).join(', ')}); its results cannot be placed` };
  }
  const extra = entries.filter((x) => !LEG_FILES.includes(x));
  if (extra.length) return { error: `${rel}: a leg artifact holds only leg and junit.xml, not ${extra.join(', ')}` };
  for (const f of LEG_FILES) {
    if (!kinds.has(f)) continue;
    if (kinds.get(f) !== 'file') return { error: `${rel}/${f}: ${KIND[kinds.get(f)]}, not a regular file` };
    const size = lstatSync(join(path, f)).size;
    if (size > MAX_BYTES[f]) return { error: `${rel}/${f}: ${size} bytes, more than the ${MAX_BYTES[f]} it may hold; not read` };
  }
  const leg = readFileSync(join(path, 'leg'), 'utf8').trim();
  const attempt = /(?:^|-)attempt-([1-9]\d*)$/.exec(artifact);
  if (!catalogue.has(leg)) return { error: `${rel}: leg file names ${JSON.stringify(leg)}, which is not a layout §1.1 leg string` };
  if (!attempt) return { error: `${rel}: the artifact name does not end in attempt-N, so its run attempt is unknown` };
  const job = catalogue.get(leg).job;
  if (runnerOf(job) === null) return { error: `${rel}: job ${job} ${NO_RUNNER}, so its JUnit cannot be mapped to test IDs; not read` };
  const report = { run_id: Number(run), run_attempt: Number(attempt[1]), leg, artifact: rel, cases: new Map() };
  if (!kinds.has('junit.xml')) return { report, note: `${rel}: no junit.xml; leg ${leg} has no result from run ${run} attempt ${report.run_attempt}` };
  let cases;
  try {
    cases = readJUnit(readFileSync(join(path, 'junit.xml'), 'utf8'));
  } catch (ex) {
    if (!(ex instanceof InputError)) throw ex;
    return { error: `${rel}/junit.xml: malformed JUnit: ${ex.message}; its results are not used` };
  }
  const runner = runnerOf(job);
  for (const c of cases) {
    const id = testId(runner, c.classname, c.name);
    const prev = report.cases.get(id);
    if (!prev || RANK[c.status] > RANK[prev]) report.cases.set(id, c.status);
  }
  return { report };
}

// Every run directory holds run.json, the run's metadata as
//   gh run view RUN_ID --json databaseId,headSha,attempt,workflowName
// writes it. It binds the artifacts to the judged commit: headSha must be
// --commit, databaseId the directory name, and no artifact may come from an
// attempt after `attempt` (the run's latest). Returns { attempt,
// workflowName } or { error }; a run with an error is not read at all.
const RUN_JSON = 'run.json';
const MAX_RUN_JSON = 64 * 1024;
function readRunJson(runDir, run, commit) {
  const rel = `${run}/${RUN_JSON}`;
  const bad = (msg) => ({ error: `${rel}: ${msg}; the run's artifacts are not used` });
  const k = kindOf(join(runDir, RUN_JSON));
  if (k === 'missing') return bad('missing (gh run view RUN_ID --json databaseId,headSha,attempt,workflowName), so the run cannot be bound to the commit');
  if (k !== 'file') return bad(`${KIND[k]}, not a regular file`);
  if (lstatSync(join(runDir, RUN_JSON)).size > MAX_RUN_JSON) return bad(`more than ${MAX_RUN_JSON} bytes`);
  let m;
  try {
    m = JSON.parse(readFileSync(join(runDir, RUN_JSON), 'utf8'));
  } catch (ex) {
    if (!(ex instanceof SyntaxError)) throw ex;
    return bad(`not JSON (${ex.message})`);
  }
  if (m === null || typeof m !== 'object' || Array.isArray(m)) return bad('not a JSON object');
  const count = (v) => Number.isSafeInteger(v) && v > 0;
  if (m.headSha !== commit) return bad(`headSha is ${JSON.stringify(m.headSha)}, not the judged commit ${commit}`);
  if (!count(m.databaseId) || String(m.databaseId) !== run) return bad(`databaseId is ${JSON.stringify(m.databaseId)}, not the directory's run ID ${run}`);
  if (!count(m.attempt)) return bad(`attempt is ${JSON.stringify(m.attempt)}, not a positive integer`);
  if (typeof m.workflowName !== 'string' || m.workflowName === '') return bad('workflowName is not a non-empty string');
  return { attempt: m.attempt, workflowName: m.workflowName };
}

// Reads DIR/<run_id>/<artifact>/{junit.xml,leg}. Returns { reports, ignored,
// notes, errors }; a report is { run_id, run_attempt, leg, artifact, cases:
// Map(test ID -> passed | failed | skipped) }. Nothing in the tree is
// trusted: a symbolic link, a directory where a file belongs or a file
// system error is an input error, never an internal one.
export function readArtifacts(dir, catalogue, commit) {
  const out = { reports: [], ignored: [], notes: [], errors: [] };
  const fsError = (where, ex) => {
    if (typeof ex?.code !== 'string') throw ex;
    out.errors.push(`${where}: cannot be read (${ex.code})`);
  };
  let runs;
  try {
    runs = statSync(dir).isDirectory() ? readdirSync(dir).sort() : null;
  } catch (ex) {
    if (ex?.code !== 'ENOENT') {
      fsError(dir, ex);
      return out;
    }
  }
  if (!runs) {
    out.errors.push(`${dir}: the artifacts directory does not exist`);
    return out;
  }
  const seen = new Map();
  for (const run of runs) {
    let artifacts;
    let meta;
    try {
      if (!/^[1-9]\d*$/.test(run) || kindOf(join(dir, run)) !== 'dir') {
        out.errors.push(`${run}: every entry of the artifacts directory is a directory named by a workflow run ID`);
        continue;
      }
      artifacts = readdirSync(join(dir, run))
        .filter((x) => x !== RUN_JSON)
        .sort();
      meta = readRunJson(join(dir, run), run, commit);
    } catch (ex) {
      fsError(run, ex);
      continue;
    }
    if (meta.error) {
      out.errors.push(meta.error);
      continue;
    }
    for (const artifact of artifacts) {
      const rel = `${run}/${artifact}`;
      let a;
      try {
        a = readArtifact(dir, run, artifact, catalogue);
      } catch (ex) {
        fsError(rel, ex);
        continue;
      }
      if (a.report && a.report.run_attempt > meta.attempt) {
        out.errors.push(`${rel}: attempt ${a.report.run_attempt}, but ${run}/${RUN_JSON} says the run has ${meta.attempt} attempt(s); its results are not used`);
        continue;
      }
      if (a.report) a.report.workflow = meta.workflowName;
      if (a.error) out.errors.push(a.error);
      if (a.ignored) out.ignored.push(rel);
      if (a.note) out.notes.push(a.note);
      if (!a.report) continue;
      const r = a.report;
      const key = `${r.run_id}/${r.run_attempt}/${r.leg}`;
      if (seen.has(key)) {
        // Both copies stay in the join, so a failure in either one counts.
        out.errors.push(`${rel}: duplicate artifact for leg ${r.leg}, run ${run} attempt ${r.run_attempt} (also ${seen.get(key)})`);
      } else seen.set(key, rel);
      out.reports.push(r);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The join

// Pair and stage statuses rank failed > not run > passed. Aggregates over
// stages also hold planned, ranked between failed and not run: a planned
// stage never counts as passed.
const SEVERITY = ['passed', 'not run', 'planned', 'failed'];
export const worst = (statuses) => statuses.reduce((w, s) => (SEVERITY.indexOf(s) > SEVERITY.indexOf(w) ? s : w), 'passed');

// waivers: [{ commit, test, leg, run_id, run_attempt, reason, expires }] with
// expires as "YYYY-MM-DD". Returns the result object that the JSON output
// carries.
export function judge({ scenarios, subcases, contracts, reports, waivers = [], commit, today, docsOnly = false }) {
  const byLeg = new Map();
  for (const r of reports) byLeg.set(r.leg, [...(byLeg.get(r.leg) ?? []), r]);
  for (const list of byLeg.values()) list.sort((a, b) => a.run_id - b.run_id || a.run_attempt - b.run_attempt);

  const ws = waivers.map((w, index) => ({ index, ...w, expired: w.expires < today, applied_to: [], matched_expired: false }));
  const mine = ws.filter((w) => w.commit === commit);

  const judgePair = (test, leg) => {
    const attempts = (byLeg.get(leg) ?? []).map((r) => ({ run_id: r.run_id, run_attempt: r.run_attempt, status: r.cases.get(test) ?? 'missing' }));
    const waived = [];
    let failed = false;
    for (const a of attempts) {
      if (a.status !== 'failed') continue;
      const match = mine.filter((w) => w.test === test && w.leg === leg && w.run_id === a.run_id && w.run_attempt === a.run_attempt);
      const w = match.find((x) => !x.expired);
      for (const x of match) if (x.expired) x.matched_expired = true;
      if (w) {
        w.applied_to.push({ test, leg, run_id: a.run_id, run_attempt: a.run_attempt });
        waived.push({ run_id: a.run_id, run_attempt: a.run_attempt, reason: w.reason, expires: w.expires });
      } else failed = true;
    }
    const status = failed ? 'failed' : attempts.some((a) => a.status === 'passed') ? 'passed' : 'not run';
    return { test, leg, status, attempts, waived };
  };

  const registered = new Map(); // test ID -> stage statuses that list it
  const stages = [];
  const entries = [...scenarios.map((e) => ({ e, kind: 'scenario' })), ...subcases.map((e) => ({ e, kind: 'subcase' }))];
  for (const { e, kind } of entries) {
    for (const s of e.stage) {
      for (const t of s.tests) registered.set(t, [...(registered.get(t) ?? []), s.status]);
      const st = {
        id: e.id,
        kind,
        parent: e.parent ?? null,
        // The checker's gates rule: only a subcase can be conditional.
        conditional_on: kind === 'subcase' ? (e.conditional_on ?? null) : null,
        milestone: s.milestone,
        scope: s.scope,
        legs: s.legs,
        tests: s.tests,
        registry_status: s.status,
        status: 'planned',
        problems: [],
        pairs: [],
      };
      stages.push(st);
      if (s.status !== 'implemented') continue;
      const jobs = [...new Set(s.legs.map(jobOf))];
      const infos = s.tests.map((t) => testInfo(t) ?? { id: t, jobs: [], entry: null });
      for (const info of infos) {
        if (info.entry !== e.id) st.problems.push(`${info.id} is not a pos/neg scenario test of ${e.id}`);
        else if (!info.jobs.some((j) => jobs.includes(j))) st.problems.push(`${info.id} is produced by none of the jobs of the stage's legs (${jobs.join(', ')})`);
      }
      const valid = infos.filter((x) => x.entry === e.id);
      for (const job of jobs) if (runnerOf(job) === null) st.problems.push(`job ${job} ${NO_RUNNER}: its results cannot be read, so this stage cannot pass`);
      for (const job of jobs) {
        for (const pol of ['pos', 'neg']) {
          if (!valid.some((x) => x.polarity === pol && x.jobs.includes(job))) st.problems.push(`job ${job} produces no ${pol} test of this stage`);
        }
      }
      for (const leg of s.legs) for (const info of valid) if (info.jobs.includes(jobOf(leg))) st.pairs.push(judgePair(info.id, leg));
      const status = worst(st.pairs.map((p) => p.status));
      // Legs are never empty (registry check), so a stage without pairs has
      // a job without tests, which is a problem.
      st.status = status === 'failed' || !st.problems.length ? status : 'not run';
    }
  }

  // Results that no implemented stage counts.
  const uncounted = { planned: [], unregistered: [], unknown: [] };
  for (const r of reports) {
    for (const [id, status] of r.cases) {
      const reg = registered.get(id);
      if (reg?.includes('implemented')) continue;
      const info = testInfo(id);
      let bucket;
      let why = null;
      if (reg) bucket = 'planned';
      else if (!info?.like) continue;
      else if (info.entry && entries.some(({ e }) => e.id === info.entry)) bucket = 'unregistered';
      else {
        bucket = 'unknown';
        why = info.entry ? `no registry entry ${info.entry}` : 'not a well-formed pos/neg scenario name';
      }
      uncounted[bucket].push({ test: id, leg: r.leg, run_id: r.run_id, run_attempt: r.run_attempt, status, ...(why ? { why } : {}) });
    }
  }

  // Waivers of this commit that were not applied, with the reason.
  const waiverOut = ws.map((w) => {
    const base = { commit: w.commit, test: w.test, leg: w.leg, run_id: w.run_id, run_attempt: w.run_attempt, reason: w.reason, expires: w.expires };
    if (w.commit !== commit) return { ...base, applied: false, why: 'for another commit' };
    if (w.applied_to.length) return { ...base, applied: true, applied_to: w.applied_to };
    if (w.matched_expired) return { ...base, applied: false, why: `expired on ${w.expires}; the failure counts` };
    return { ...base, applied: false, why: 'matches no failed attempt of a pair of an implemented stage (a waiver never applies to not run or planned)' };
  });

  // Aggregates.
  const required = (st) => st.conditional_on === null;
  const upTo = (m) => (st) => MILESTONES.indexOf(st.milestone) <= MILESTONES.indexOf(m);
  const scenarioOut = scenarios.map((e) => {
    const own = stages.filter((st) => st.id === e.id || (st.parent === e.id && required(st)));
    const by = {};
    for (const m of MILESTONES) {
      const sel = own.filter(upTo(m));
      if (sel.length) by[m] = worst(sel.map((st) => st.status));
    }
    return { id: e.id, status: worst(own.map((st) => st.status)), by_milestone: by };
  });
  const overall = new Map(scenarioOut.map((s) => [s.id, s.status]));
  const contractOut = contracts.map((c) => ({ id: c.id, covered_by: c.covered_by, status: worst(c.covered_by.map((id) => overall.get(id) ?? 'not run')) }));
  const milestones = {};
  for (const m of MILESTONES) {
    const sel = stages.filter((st) => st.milestone === m && required(st));
    const counts = Object.fromEntries(SEVERITY.map((s) => [s, sel.filter((st) => st.status === s).length]));
    milestones[m] = { stages: sel.length, ...counts, gate: sel.length ? worst(sel.map((st) => st.status)) : 'no stages' };
  }

  return {
    format: 1,
    commit,
    judged_on: today,
    docs_only: docsOnly,
    headline: docsOnly ? 'runtime conformance: not run (docs-only change)' : null,
    reports: reports.map((r) => ({ run_id: r.run_id, run_attempt: r.run_attempt, workflow: r.workflow ?? null, leg: r.leg, artifact: r.artifact, cases: r.cases.size })),
    milestones,
    stages,
    scenarios: scenarioOut,
    contracts: contractOut,
    waivers: waiverOut,
    uncounted,
    failed: stages.some((st) => st.status === 'failed'),
  };
}

// ---------------------------------------------------------------------------
// Markdown

// Every string that reaches the Markdown from outside this script (artifact
// and file names, leg files, JUnit names, XML error messages, registry and
// waiver text) passes clean(): control characters (CR and LF included),
// U+2028/2029, zero-width and bidirectional controls become a space, and the
// result is cut to MAX_TEXT characters. text() then escapes it for prose
// (HTML and Markdown); code() quotes it as a code span, where neither HTML
// nor Markdown is interpreted. Lists are cut to MAX_LIST items; the JSON
// keeps everything.
export const MAX_TEXT = 300;
export const MAX_LIST = 50;
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]+/g;
export const clean = (s) => {
  const t = String(s).replace(UNSAFE, ' ');
  const chars = Array.from(t);
  return chars.length > MAX_TEXT ? `${chars.slice(0, MAX_TEXT).join('')}…` : t;
};
export const text = (s) =>
  clean(s)
    .replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c])
    .replace(/[\\`*_[\]~]/g, '\\$&');
export const code = (s) => `\`${clean(s).replaceAll('`', "'")}\``;
// A table cell: | would end the cell, even inside a code span.
const cell = (s) => String(s).replaceAll('|', '\\|');
const capped = (items, line, what) =>
  items.length > MAX_LIST ? [...items.slice(0, MAX_LIST).map(line), `- … and ${items.length - MAX_LIST} more ${what} (the JSON lists all of them)`] : items.map(line);

export function renderMarkdown(res, { inputErrors = [], notes = [], ignored = [] } = {}) {
  const out = [`## Conformance results for ${code(res.commit)}`, ''];
  if (res.headline) out.push(`**${res.headline}**`, '');
  if (inputErrors.length) out.push(`**Input errors: this report cannot be trusted (${inputErrors.length}).**`, '', ...capped(inputErrors, (e) => `- ${text(e)}`, 'input errors'), '');
  out.push(`Judged on ${res.judged_on} from ${res.reports.length} JUnit report(s). Only **passed** counts; \`CI passed\` is not a conformance signal.`, '');
  out.push('| Milestone | Stages | Passed | Failed | Not run | Planned | Gate |', '| --- | --- | --- | --- | --- | --- | --- |');
  for (const [m, v] of Object.entries(res.milestones)) out.push(`| ${m} | ${v.stages} | ${v.passed} | ${v.failed} | ${v['not run']} | ${v.planned} | ${v.gate} |`);
  out.push('', 'The counts cover required stages. Stages of conditional sub-IDs are listed with the implemented stages but gate no milestone.', '');
  const impl = res.stages.filter((st) => st.registry_status === 'implemented');
  out.push(`### Implemented stages (${impl.length})`, '');
  if (!impl.length) out.push('None: every stage is planned.', '');
  else {
    out.push('| Stage | Status | Details |', '| --- | --- | --- |');
    for (const st of impl) {
      const details = st.problems.map(text);
      for (const p of st.pairs) {
        const bad = p.attempts.filter((a) => a.status === 'failed' && !p.waived.some((w) => w.run_id === a.run_id && w.run_attempt === a.run_attempt));
        let d = `${code(p.test)} on ${code(p.leg)}: ${p.status}`;
        if (bad.length) d += ` (failed in ${bad.map((a) => `run ${a.run_id} attempt ${a.run_attempt}`).join(', ')})`;
        for (const w of p.waived) d += `; waiver applied to run ${w.run_id} attempt ${w.run_attempt}: ${text(w.reason)} (expires ${w.expires})`;
        if (p.status !== 'passed' || p.waived.length) details.push(d);
      }
      const label = text(`${st.id}${st.conditional_on ? ` (conditional: ${st.conditional_on})` : ''} ${st.milestone}: ${st.scope}`);
      const shown = details.length > MAX_LIST ? [...details.slice(0, MAX_LIST), `… and ${details.length - MAX_LIST} more (the JSON lists all of them)`] : details;
      out.push(`| ${cell(label)} | ${st.status} | ${details.length ? cell(shown.join('<br>')) : `${st.pairs.length} pair(s) passed`} |`);
    }
    out.push('');
  }
  const forCommit = res.waivers.filter((w) => w.commit === res.commit);
  if (forCommit.length) {
    out.push('### Waivers for this commit', '');
    const line = (w) => {
      const what = `${code(w.test)} on ${code(w.leg)}, run ${w.run_id} attempt ${w.run_attempt}`;
      return w.applied ? `- applied: ${what}: ${text(w.reason)} (expires ${w.expires})` : `- **not applied**: ${what}: ${text(w.why)}`;
    };
    out.push(...capped(forCommit, line, 'waivers'));
    out.push('');
  }
  const u = res.uncounted;
  if (u.planned.length || u.unregistered.length || u.unknown.length) {
    out.push('### Results not counted', '');
    const at = (x) => `${code(x.test)} on ${code(x.leg)} ${x.status} (run ${x.run_id} attempt ${x.run_attempt})`;
    out.push(...capped(u.planned, (x) => `- planned stage, stays planned: ${at(x)}`, 'results of planned stages'));
    out.push(...capped(u.unregistered, (x) => `- not in any stage's tests: ${at(x)}`, 'unregistered results'));
    out.push(...capped(u.unknown, (x) => `- unknown scenario test (${text(x.why)}): ${at(x)}`, 'unknown scenario tests'));
    out.push('');
  }
  out.push(...capped(notes, (n) => `- note: ${text(n)}`, 'notes'));
  if (ignored.length) {
    const more = ignored.length > MAX_LIST ? ` and ${ignored.length - MAX_LIST} more` : '';
    out.push(`- note: ${ignored.length} artifact(s) without a \`leg\` file ignored (not conformance legs): ${ignored.slice(0, MAX_LIST).map(code).join(', ')}${more}`);
  }
  if (notes.length || ignored.length) out.push('');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// CLI

const USAGE =
  'usage: report-conformance.mjs --commit SHA [--artifacts DIR] [--waivers FILE] [--root DIR] [--today YYYY-MM-DD] ' +
  '[--docs-only] [--require-milestone M] [--require-history] [--allow-commit-mismatch] [--json FILE] [--summary FILE]';

// HEAD of the git checkout whose top level is `root`; undefined when root is
// not one (or git is missing), null when HEAD names no commit.
export function checkoutHead(root) {
  const git = (...args) => spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  const top = git('rev-parse', '--show-toplevel');
  if (top.status !== 0 || realpathSync(top.stdout.trim()) !== realpathSync(root)) return undefined;
  const head = git('rev-parse', '--verify', '--quiet', 'HEAD^{commit}');
  return head.status === 0 ? head.stdout.trim() : null;
}

const VALUE_FLAGS = ['--commit', '--artifacts', '--waivers', '--root', '--today', '--require-milestone', '--json', '--summary'];

// The exit status of a report (see the header) and the message for stderr.
export function exitStatus(res, requireMilestone) {
  if (res.input_errors.length) return [2, `${res.input_errors.length} input error(s); the report cannot be trusted`];
  if (requireMilestone !== undefined) {
    const gate = res.milestones[requireMilestone].gate;
    return gate === 'passed' ? [0, null] : [1, `milestone ${requireMilestone} is ${gate}, not passed`];
  }
  return res.failed ? [1, 'some implemented stage has a failed result'] : [0, null];
}

export function run(argv, { log = console.log, logErr = console.error, now = new Date() } = {}) {
  const o = { root: resolve(dirname(fileURLToPath(import.meta.url)), '..', '..'), docsOnly: false, requireHistory: false };
  const given = new Set();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    // A value flag given twice is ambiguous (which --commit is judged?), so
    // it is a usage error rather than last-one-wins.
    if (VALUE_FLAGS.includes(a) && given.has(a)) {
      logErr(`report-conformance: ${a} given more than once\n${USAGE}`);
      return 2;
    }
    given.add(a);
    if (a === '--docs-only') o.docsOnly = true;
    else if (a === '--require-history') o.requireHistory = true;
    else if (a === '--allow-commit-mismatch') o.allowCommitMismatch = true;
    else if (VALUE_FLAGS.includes(a) && argv[i + 1] !== undefined) o[a.slice(2).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = argv[++i];
    else {
      logErr(USAGE);
      return 2;
    }
  }
  const usage = (msg) => {
    logErr(`report-conformance: ${msg}\n${USAGE}`);
    return 2;
  };
  if (!o.commit || !/^[0-9a-f]{40}$/.test(o.commit)) return usage('--commit must be a full 40-character lowercase hex SHA');
  const today = o.today ?? now.toISOString().slice(0, 10);
  // A calendar date: Date rolls 2026-02-30 over to March, so the round trip
  // catches it.
  const day = new Date(`${today}T00:00:00Z`);
  if (!/^\d{4}-\d\d-\d\d$/.test(today) || Number.isNaN(day.getTime()) || day.toISOString().slice(0, 10) !== today) return usage('--today must be a calendar date YYYY-MM-DD');
  if (o.requireMilestone !== undefined && !MILESTONES.includes(o.requireMilestone)) return usage(`--require-milestone must be one of ${MILESTONES.join(', ')}`);
  const root = resolve(o.root);

  // The registry judged is the checkout at --root: in a git checkout, its
  // HEAD must be --commit. --allow-commit-mismatch still prints the report,
  // as untrusted (an input error). Outside a git checkout there is nothing
  // to compare (a note); --require-history makes that an error below.
  const bound = { errors: [], notes: [] };
  const head = checkoutHead(root);
  // A gate verdict needs a bound root, so with --require-milestone an
  // unbound one (not a git checkout here, a mismatch above) is an input
  // error: exit 2, never a verdict of 0 or 1.
  if (head === undefined && o.requireMilestone !== undefined) bound.errors.push('--require-milestone needs --root bound to --commit, but --root is not a git checkout, so its registry is not known to be the judged commit\'s');
  else if (head === undefined) bound.notes.push('the registry is not bound to --commit: --root is not a git checkout');
  else if (head !== o.commit) {
    const msg = `--root is a checkout of ${head ?? 'no commit'}, not of --commit ${o.commit}, so its registry is not the judged commit's`;
    if (!o.allowCommitMismatch) {
      logErr(`report-conformance: ${msg}; no report (--allow-commit-mismatch prints it as untrusted)`);
      return 2;
    }
    bound.errors.push(`${msg} (--allow-commit-mismatch)`);
  }

  // The registry of the judged commit must pass the static check first.
  const chk = checkRegistry(root, { requireHistory: o.requireHistory });
  for (const n of chk.notes) log(`note: ${n}`);
  if (chk.errors.length) {
    for (const e of chk.errors) logErr(formatError(e));
    logErr(`report-conformance: the registry has ${chk.errors.length} error(s); no report`);
    return 2;
  }
  const reg = parseStrict(readFileSync(join(root, SCENARIOS), 'utf8'));
  const sub = parseStrict(readFileSync(join(root, SUBCASES), 'utf8'));
  const { catalogue } = parseEnvironments(readFileSync(join(root, LAYOUT), 'utf8'), []);
  const scenarios = reg.scenario.filter((e) => e.kind === 'scenario');
  const contracts = reg.scenario.filter((e) => e.kind === 'contract');
  const subcases = sub.subcase ?? [];

  // Waivers from the tip of main, validated by the registry check's rules.
  let waivers = [];
  if (o.waivers !== undefined) {
    if (!existsSync(o.waivers)) return usage(`--waivers ${o.waivers}: no such file`);
    const text = readFileSync(o.waivers, 'utf8');
    const rep = new Report();
    const doc = load(text, o.waivers, rep);
    if (doc) {
      const stagesByTest = new Map();
      for (const e of [...scenarios, ...subcases]) for (const s of e.stage) for (const t of s.tests) stagesByTest.set(t, [...(stagesByTest.get(t) ?? []), { legs: s.legs }]);
      // The file is main's, the registry the judged commit's: a waiver for
      // another commit may name a test this registry no longer (or not yet)
      // has. Only the waivers for --commit get the full rule; the others get
      // its shape checks (keys, types, commit format), with every test and leg
      // accepted and no history lookup. Each part keeps its line numbers.
      const at = locate(text);
      const part = (keep) => {
        const list = Array.isArray(doc.waiver) ? doc.waiver : [];
        const idx = list.map((w, i) => i).filter((i) => keep(list[i]));
        const lines = new Map(idx.map((i, j) => [`waiver/${j}`, at.get(`waiver/${i}`)]));
        return { waiver: idx.map((i) => list[i]), lines };
      };
      const mine = part((w) => w?.commit === o.commit);
      const others = part((w) => w?.commit !== o.commit);
      // As in checkRegistry: with --require-history the history was probed
      // (and its absence already failed the registry check above).
      checkWaivers(Array.isArray(doc.waiver) ? { ...doc, waiver: mine.waiver } : doc, mine.lines, stagesByTest, root, o.requireHistory, o.requireHistory ? history(root) : null, rep);
      const anyStage = { get: () => [{ legs: { includes: () => true } }] };
      if (others.waiver.length) checkWaivers({ waiver: others.waiver }, others.lines, anyStage, root, true, { reason: 'not checked for other commits' }, rep);
    }
    for (const n of rep.notes) log(`note: ${n}`);
    if (rep.errors.length) {
      // checkWaivers names main's path; this file is the --waivers one.
      for (const e of rep.errors) logErr(formatError(e.file === WAIVERS ? { ...e, file: o.waivers } : e));
      logErr(`report-conformance: ${o.waivers} has ${rep.errors.length} error(s); no report`);
      return 2;
    }
    waivers = (doc.waiver ?? []).map((w) => ({ ...w, expires: w.expires.toISOString().slice(0, 10) }));
  }

  const art = o.artifacts === undefined ? { reports: [], ignored: [], notes: [], errors: [] } : readArtifacts(resolve(o.artifacts), catalogue, o.commit);
  art.errors.unshift(...bound.errors);
  art.notes.unshift(...bound.notes);
  const res = judge({ scenarios, subcases, contracts, reports: art.reports, waivers, commit: o.commit, today, docsOnly: o.docsOnly });
  res.input_errors = art.errors;
  res.trusted = art.errors.length === 0;
  res.notes = art.notes;
  res.ignored_artifacts = art.ignored;
  const md = renderMarkdown(res, { inputErrors: art.errors, notes: art.notes, ignored: art.ignored });
  log(md);
  if (o.summary !== undefined) appendFileSync(o.summary, `${md}\n`);
  if (o.json !== undefined) writeFileSync(o.json, `${JSON.stringify(res, null, 2)}\n`);
  const [status, why] = exitStatus(res, o.requireMilestone);
  if (why) logErr(`report-conformance: ${why}`);
  const outside = (st) => st.status === 'failed' && !(st.milestone === o.requireMilestone && st.conditional_on === null);
  if (o.requireMilestone !== undefined && status !== 2 && res.stages.some(outside)) {
    logErr(`report-conformance: note: implemented stages outside the ${o.requireMilestone} gate failed; they do not change the exit status (see the report)`);
  }
  return status;
}

const isMain = (() => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();

if (isMain) {
  try {
    process.exitCode = run(process.argv.slice(2));
  } catch (ex) {
    console.error(`internal error: ${ex.stack ?? ex}`);
    process.exitCode = 2;
  }
}
