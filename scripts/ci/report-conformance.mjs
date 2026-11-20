#!/usr/bin/env node
// Conformance result reporter: the "Result join (reporter)" of
// docs/testing/conformance-layout.md §3. It joins the JUnit reports of every
// workflow run and attempt for ONE commit with the registry and prints, per
// (scenario, stage) and per milestone, passed / failed / not run / planned.
//
//   node scripts/ci/report-conformance.mjs --commit SHA [--artifacts DIR]
//        [--waivers FILE] [--root DIR] [--today YYYY-MM-DD] [--docs-only]
//        [--require-milestone M] [--require-history] [--json FILE]
//        [--summary FILE]
//
// Input
//   --artifacts DIR   Downloaded artifacts of every run for the commit, one
//                     directory per run named by its numeric run ID, one
//                     directory per artifact inside it (what
//                     `gh run download RUN_ID -D DIR/RUN_ID` writes):
//                       DIR/<run_id>/<artifact name ending in attempt-N>/junit.xml
//                       DIR/<run_id>/<artifact name ending in attempt-N>/leg
//                     `leg` holds one layout §1.1 leg string. An artifact
//                     without a `leg` file (service-nextest-junit-N, coverage
//                     reports) is not a conformance leg and is ignored.
//                     Omitted: no results at all.
//   --waivers FILE    tests/conformance/waivers.toml from the tip of main
//                     (layout §3 "Waivers"); the caller fetches it, for
//                     example with `git show origin/main:tests/conformance/waivers.toml`.
//   --root DIR        Checkout of the judged commit (default: this
//                     repository). Its registry is checked first with
//                     check-conformance-registry.mjs; any error stops the
//                     report.
//   --today DATE      Judging date for waiver expiry (default: today, UTC).
//   --docs-only       The docs-only classifier skipped the build jobs: the
//                     summary starts with "runtime conformance: not run
//                     (docs-only change)".
//
// Rules (layout §3, §4)
//   * A testcase is failed when it has <failure>, <error> or a retry marker
//     (<flakyFailure>, <flakyError>, <rerunFailure>, <rerunError>): retries
//     are 0, so a pass after a retry is a failure. <skipped> is not run.
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
// Exit status
//   0  the report was produced, no implemented stage has a failed pair, and
//      the --require-milestone gate (if given) passed;
//   1  some implemented stage has a failed (unwaived) pair, or the stages of
//      the --require-milestone milestone are not all passed;
//   2  usage errors, registry or waiver-file errors (no report), or input
//      errors (malformed JUnit, duplicate artifacts, a bad leg file or
//      artifact name). The report is still printed for input errors, but
//      it cannot be trusted.

import { appendFileSync, existsSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseStrict } from 'smol-toml';

import { checkRegistry, checkWaivers, formatError, load, locate, Report } from './check-conformance-registry.mjs';
import { LAYOUT, MILESTONES, parseEnvironments, SCENARIOS, SUBCASES } from './gen-conformance-registry.mjs';

// ---------------------------------------------------------------------------
// XML (the subset JUnit reporters write)

export class InputError extends Error {}

const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
const NAME = /[A-Za-z_:][-A-Za-z0-9_:.]*/y;
const SPACE = /[ \t\r\n]/;

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

// The testcases of a JUnit report: [{ classname, name, status }], status one
// of passed, failed, skipped. Throws InputError for a malformed report.
export function readJUnit(text) {
  const root = parseXml(text);
  if (root.name !== 'testsuites' && root.name !== 'testsuite') throw new InputError(`the root element is <${root.name}>, not <testsuites> or <testsuite>`);
  const cases = [];
  const walk = (el, inSuite) => {
    for (const c of el.children) {
      if (c.name === 'testsuite' || c.name === 'testsuites') walk(c, c.name === 'testsuite' || inSuite);
      else if (c.name === 'testcase') {
        if (!inSuite) throw new InputError('a <testcase> outside any <testsuite>');
        const { name, classname } = c.attrs;
        if (!name || classname === undefined) throw new InputError(`a <testcase> without a name or classname attribute${name ? ` (${name})` : ''}`);
        const kids = c.children.map((k) => k.name);
        const status = kids.some((k) => FAILED_ELEMENTS.has(k)) ? 'failed' : kids.includes('skipped') ? 'skipped' : 'passed';
        cases.push({ classname, name, status });
      }
    }
  };
  walk(root, root.name === 'testsuite');
  return cases;
}

// ---------------------------------------------------------------------------
// Test IDs and names (layout §3 "Test names", "Which job produces a test")

// The runner whose JUnit a job's legs upload; every other job runs
// cargo-nextest.
export const JOB_RUNNER = { typescript: 'vitest', 'typescript-browser': 'playwright' };
export const runnerOf = (job) => JOB_RUNNER[job] ?? 'nextest';
export const jobOf = (leg) => leg.split('/')[0];

// Layout §3 "Which job produces a test": [runner, package, target, jobs];
// null matches any package or target. A test whose package and target fix
// several jobs is expected from every one of them that its stage lists.
// skyoauth-service is absent on purpose: it is not registrable (layout §3).
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

// The registry test ID of a JUnit testcase:
//   nextest     classname "<package>::<binary>" -> nextest:<package>/<binary>/<name>
//               classname "<package>" (lib)      -> nextest:<package>/<name>
//   vitest      classname "<file>"               -> vitest:<file>/<name>
//   playwright  classname "<file>"               -> playwright:<file>/<name>
export function testId(runner, classname, name) {
  if (runner !== 'nextest') return `${runner}:${classname}/${name}`;
  const k = classname.indexOf('::');
  return `nextest:${k < 0 ? classname : `${classname.slice(0, k)}/${classname.slice(k + 2)}`}/${name}`;
}

const TS_FILE = /^(.*?\.(?:test|spec)\.[cm]?[jt]sx?)\/(.+)$/;
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
  const m = /^(nextest|vitest|playwright):(.+)$/.exec(id);
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

// Reads DIR/<run_id>/<artifact>/{junit.xml,leg}. Returns { reports, ignored,
// notes, errors }; a report is { run_id, run_attempt, leg, artifact, cases:
// Map(test ID -> passed | failed | skipped) }.
export function readArtifacts(dir, catalogue) {
  const out = { reports: [], ignored: [], notes: [], errors: [] };
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    out.errors.push(`${dir}: the artifacts directory does not exist`);
    return out;
  }
  const seen = new Map();
  for (const run of readdirSync(dir).sort()) {
    if (!/^[1-9]\d*$/.test(run) || !statSync(join(dir, run)).isDirectory()) {
      out.errors.push(`${run}: every entry of the artifacts directory is a directory named by a workflow run ID`);
      continue;
    }
    for (const artifact of readdirSync(join(dir, run)).sort()) {
      const rel = `${run}/${artifact}`;
      const path = join(dir, run, artifact);
      if (!statSync(path).isDirectory()) {
        out.errors.push(`${rel}: a run directory holds only artifact directories`);
        continue;
      }
      if (!existsSync(join(path, 'leg'))) {
        out.ignored.push(rel);
        continue;
      }
      const leg = readFileSync(join(path, 'leg'), 'utf8').trim();
      const attempt = /(?:^|-)attempt-([1-9]\d*)$/.exec(artifact);
      if (!catalogue.has(leg)) {
        out.errors.push(`${rel}: leg file names ${JSON.stringify(leg)}, which is not a layout §1.1 leg string`);
        continue;
      }
      if (!attempt) {
        out.errors.push(`${rel}: the artifact name does not end in attempt-N, so its run attempt is unknown`);
        continue;
      }
      const r = { run_id: Number(run), run_attempt: Number(attempt[1]), leg, artifact: rel, cases: new Map() };
      const key = `${r.run_id}/${r.run_attempt}/${leg}`;
      const junit = join(path, 'junit.xml');
      if (!existsSync(junit)) out.notes.push(`${rel}: no junit.xml; leg ${leg} has no result from run ${run} attempt ${r.run_attempt}`);
      else {
        let cases;
        try {
          cases = readJUnit(readFileSync(junit, 'utf8'));
        } catch (ex) {
          if (!(ex instanceof InputError)) throw ex;
          out.errors.push(`${rel}/junit.xml: malformed JUnit: ${ex.message}; its results are not used`);
          continue;
        }
        const runner = runnerOf(catalogue.get(leg).job);
        for (const c of cases) {
          const id = testId(runner, c.classname, c.name);
          const prev = r.cases.get(id);
          if (!prev || RANK[c.status] > RANK[prev]) r.cases.set(id, c.status);
        }
      }
      if (seen.has(key)) {
        // Both copies stay in the join, so a failure in either one counts.
        out.errors.push(`${rel}: duplicate artifact for leg ${leg}, run ${run} attempt ${r.run_attempt} (also ${seen.get(key)})`);
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
        conditional_on: e.conditional_on ?? null,
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
    reports: reports.map((r) => ({ run_id: r.run_id, run_attempt: r.run_attempt, leg: r.leg, artifact: r.artifact, cases: r.cases.size })),
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

const code = (s) => `\`${String(s).replaceAll('`', "'")}\``;
const cell = (s) => String(s).replaceAll('|', '\\|').replaceAll('\n', ' ');

export function renderMarkdown(res, { inputErrors = [], notes = [], ignored = [] } = {}) {
  const out = [`## Conformance results for ${code(res.commit)}`, ''];
  if (res.headline) out.push(`**${res.headline}**`, '');
  if (inputErrors.length) out.push(`**Input errors: this report cannot be trusted (${inputErrors.length}).**`, '', ...inputErrors.map((e) => `- ${cell(e)}`), '');
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
      const details = [...st.problems];
      for (const p of st.pairs) {
        const bad = p.attempts.filter((a) => a.status === 'failed' && !p.waived.some((w) => w.run_id === a.run_id && w.run_attempt === a.run_attempt));
        let d = `${code(p.test)} on ${code(p.leg)}: ${p.status}`;
        if (bad.length) d += ` (failed in ${bad.map((a) => `run ${a.run_id} attempt ${a.run_attempt}`).join(', ')})`;
        for (const w of p.waived) d += `; waiver applied to run ${w.run_id} attempt ${w.run_attempt}: ${w.reason} (expires ${w.expires})`;
        if (p.status !== 'passed' || p.waived.length) details.push(d);
      }
      const label = `${st.id}${st.conditional_on ? ` (conditional: ${st.conditional_on})` : ''} ${st.milestone}: ${st.scope}`;
      out.push(`| ${cell(label)} | ${st.status} | ${details.length ? cell(details.join('<br>')) : `${st.pairs.length} pair(s) passed`} |`);
    }
    out.push('');
  }
  const forCommit = res.waivers.filter((w) => w.commit === res.commit);
  if (forCommit.length) {
    out.push('### Waivers for this commit', '');
    for (const w of forCommit) {
      const what = `${code(w.test)} on ${code(w.leg)}, run ${w.run_id} attempt ${w.run_attempt}`;
      out.push(w.applied ? `- applied: ${what}: ${cell(w.reason)} (expires ${w.expires})` : `- **not applied**: ${what}: ${w.why}`);
    }
    out.push('');
  }
  const u = res.uncounted;
  if (u.planned.length || u.unregistered.length || u.unknown.length) {
    out.push('### Results not counted', '');
    for (const x of u.planned) out.push(`- planned stage, stays planned: ${code(x.test)} on ${code(x.leg)} ${x.status} (run ${x.run_id} attempt ${x.run_attempt})`);
    for (const x of u.unregistered) out.push(`- not in any stage's tests: ${code(x.test)} on ${code(x.leg)} ${x.status} (run ${x.run_id} attempt ${x.run_attempt})`);
    for (const x of u.unknown) out.push(`- unknown scenario test (${x.why}): ${code(x.test)} on ${code(x.leg)} ${x.status} (run ${x.run_id} attempt ${x.run_attempt})`);
    out.push('');
  }
  for (const n of notes) out.push(`- note: ${cell(n)}`);
  if (ignored.length) out.push(`- note: ${ignored.length} artifact(s) without a \`leg\` file ignored (not conformance legs): ${ignored.map(code).join(', ')}`);
  if (notes.length || ignored.length) out.push('');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// CLI

const USAGE =
  'usage: report-conformance.mjs --commit SHA [--artifacts DIR] [--waivers FILE] [--root DIR] [--today YYYY-MM-DD] ' +
  '[--docs-only] [--require-milestone M] [--require-history] [--json FILE] [--summary FILE]';

const VALUE_FLAGS = ['--commit', '--artifacts', '--waivers', '--root', '--today', '--require-milestone', '--json', '--summary'];

export function run(argv, { log = console.log, logErr = console.error, now = new Date() } = {}) {
  const o = { root: resolve(dirname(fileURLToPath(import.meta.url)), '..', '..'), docsOnly: false, requireHistory: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--docs-only') o.docsOnly = true;
    else if (a === '--require-history') o.requireHistory = true;
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
  if (!/^\d{4}-\d\d-\d\d$/.test(today)) return usage('--today must be YYYY-MM-DD');
  if (o.requireMilestone !== undefined && !MILESTONES.includes(o.requireMilestone)) return usage(`--require-milestone must be one of ${MILESTONES.join(', ')}`);
  const root = resolve(o.root);

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
      checkWaivers(doc, locate(text), stagesByTest, root, o.requireHistory, rep);
    }
    for (const n of rep.notes) log(`note: ${n}`);
    if (rep.errors.length) {
      for (const e of rep.errors) logErr(formatError(e));
      logErr(`report-conformance: ${o.waivers} has ${rep.errors.length} error(s); no report`);
      return 2;
    }
    waivers = (doc.waiver ?? []).map((w) => ({ ...w, expires: w.expires.toISOString().slice(0, 10) }));
  }

  const art = o.artifacts === undefined ? { reports: [], ignored: [], notes: [], errors: [] } : readArtifacts(resolve(o.artifacts), catalogue);
  const res = judge({ scenarios, subcases, contracts, reports: art.reports, waivers, commit: o.commit, today, docsOnly: o.docsOnly });
  res.input_errors = art.errors;
  res.notes = art.notes;
  res.ignored_artifacts = art.ignored;
  const md = renderMarkdown(res, { inputErrors: art.errors, notes: art.notes, ignored: art.ignored });
  log(md);
  if (o.summary !== undefined) appendFileSync(o.summary, `${md}\n`);
  if (o.json !== undefined) writeFileSync(o.json, `${JSON.stringify(res, null, 2)}\n`);
  if (art.errors.length) {
    logErr(`report-conformance: ${art.errors.length} input error(s)`);
    return 2;
  }
  if (res.failed) {
    logErr('report-conformance: some implemented stage has a failed result');
    return 1;
  }
  if (o.requireMilestone !== undefined && res.milestones[o.requireMilestone].gate !== 'passed') {
    logErr(`report-conformance: milestone ${o.requireMilestone} is ${res.milestones[o.requireMilestone].gate}, not passed`);
    return 1;
  }
  return 0;
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
