#!/usr/bin/env node
// Static part of check-conformance-registry (docs/testing/conformance-layout.md
// §3). It needs no build, so CI runs it on every change, docs-only ones
// included.
//
//   node scripts/ci/check-conformance-registry.mjs [--root DIR] [--require-history]
//
// Rules (each error names its rule):
//   toml      Every registry file parses with smol-toml (pinned in
//             scripts/ci/package.json) and with the subset reader of
//             gen-conformance-registry.mjs, and both return the same data.
//   fields    Known keys only, each with the right type.
//   ids       The A rows of tasks §8 equal the registry scenario IDs, and the C
//             rows of design §2 equal the contract IDs: no gaps, duplicates or
//             extras.
//   order     Scenario, contract and subcase IDs increase in file order.
//   hash      Every matrix_sha256 is the SHA-256 of its source line (layout §3).
//   owners    Every owner is a task ID of the tasks doc.
//   stages    Stage milestones are known and increase, so the last stage holds
//             the entry's full milestone; "full row" is the scope of a
//             single-stage entry only. An implemented stage lists tests and
//             carries the implemented_sha256 stamp of its (id, milestone,
//             scope, matrix_sha256); a planned stage carries none.
//   legs      Every leg is a §1.1 leg string, its env is one of the entry's
//             envs, its job exists at the stage's milestone (JOB_FROM), and
//             every env has a leg in some stage.
//   gates     Every scenario or required-subcase stage of a milestone in
//             gates_passed is implemented (layout §3 Gates; the reporter part
//             of that rule is not here). Conditional subcases are skipped
//             until a release manifest selects their feature.
//   table     The layout §2 table and its counts sentences equal the ones
//             rendered from the registry (gen-conformance-registry.mjs renders
//             both; this check imports that code).
//   subcases  Subcase parent, conditional_on and table_text agree. Conditional
//             sub-IDs are numbered .90-.99 and the annex holds exactly the
//             conditional sub-IDs that the committed §2 table names; a required
//             sub-ID lies in the annex range its parent's note declares (such
//             as "A58.01–A58.89", within .01-.89).
//   fixtures  Each tests/conformance/fixtures directory not starting with "_"
//             names a registered scenario, and each of its case files has the
//             layout §1.3 envelope. JSON Schema validation is not implemented:
//             any file under tests/conformance/schema fails the check.
//   waivers   tests/conformance/waivers.toml (optional): every waiver has all
//             fields; commit is a 40-hex SHA on origin/main; test is registered
//             and leg is one of its stages' legs; expires is a TOML date.
//
// The commit check needs the full history and origin/main. Without them it is
// skipped with a note, unless --require-history is given (CI): that probes
// the history up front and makes its absence an error, waivers or not.
//
// Errors exit 1. Usage and internal errors exit 2.

import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseStrict, TomlDate } from 'smol-toml';

import {
  annexRange,
  checkNamedSubcases,
  DESIGN,
  FEATURES,
  findCounts,
  findTable,
  FULL_ROW,
  idRows,
  isConditionalNumber,
  JOB_FROM,
  LAYERS,
  LAYOUT,
  LocalDate,
  MILESTONES,
  parseConditional,
  parseEnvironments,
  parseToml,
  renderCounts,
  renderTable,
  rowConditionals,
  SCENARIOS,
  section,
  sha256,
  SpecError,
  stageStamp,
  STATUSES,
  SUBCASES,
  TABLE_HEADER,
  TASKS,
  taskLines,
} from './gen-conformance-registry.mjs';

export const WAIVERS = 'tests/conformance/waivers.toml';
export const FIXTURES = 'tests/conformance/fixtures';
export const SCHEMAS = 'tests/conformance/schema';
const MAIN = 'refs/remotes/origin/main';

// ---------------------------------------------------------------------------
// Diagnostics

class Report {
  constructor() {
    this.errors = [];
    this.notes = [];
  }
  error(file, line, rule, msg) {
    this.errors.push({ file, line, rule, msg });
  }
  note(msg) {
    this.notes.push(msg);
  }
}

export function formatError(d) {
  const loc = d.file ? (d.line ? `${d.file}:${d.line}: ` : `${d.file}: `) : '';
  return `${loc}error [${d.rule}] ${d.msg}`;
}

// ---------------------------------------------------------------------------
// TOML

// Plain data for comparing the two readers: a date becomes { date: text }.
// The subset reader accepts local dates only (no date-times or times), so a
// TomlDate that reaches this comparison against a LocalDate is a local date.
export function plain(v) {
  if (v instanceof TomlDate) return { date: v.toISOString() };
  if (v instanceof LocalDate) return { date: v.text };
  if (Array.isArray(v)) return v.map(plain);
  if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)]));
  return v;
}

// Parses a registry file with smol-toml and with the generator's reader.
// Returns the smol-toml data, or null after reporting an error.
function load(text, rel, report) {
  let data;
  try {
    data = parseStrict(text);
  } catch (ex) {
    report.error(rel, ex.line, 'toml', `not valid TOML: ${String(ex.message).split('\n')[0]}`);
    return null;
  }
  let subset;
  try {
    subset = parseToml(text, rel);
  } catch (ex) {
    if (!(ex instanceof SpecError)) throw ex;
    report.error(null, null, 'toml', `${ex.message} (outside the TOML subset that gen-conformance-registry.mjs reads)`);
    return null;
  }
  if (JSON.stringify(plain(data)) !== JSON.stringify(plain(subset))) {
    report.error(rel, null, 'toml', 'smol-toml and the gen-conformance-registry.mjs reader return different data');
    return null;
  }
  return data;
}

// 1-based lines of a registry file's [[table]] headers: an entry by ID
// ("A24"), a stage by ID and milestone ("A24/M1a"), a waiver by index
// ("waiver/0"). Keys before the first header are not located.
export function locate(text) {
  const at = new Map();
  let table = '';
  let header;
  let id = '';
  let waivers = 0;
  text.split('\n').forEach((line, i) => {
    const h = /^\[\[([a-z.]+)\]\]/.exec(line);
    if (h) {
      table = h[1];
      header = i + 1;
      if (table === 'waiver') at.set(`waiver/${waivers++}`, header);
      return;
    }
    const m = /^(id|milestone) = "([^"]*)"/.exec(line);
    if (!m || !table) return;
    const stage = table.endsWith('.stage');
    if (m[1] === 'id' && !stage) id = m[2];
    const key = m[1] === 'id' ? id : `${id}/${m[2]}`;
    if ((m[1] === 'milestone') === stage && !at.has(key)) at.set(key, header);
  });
  return at;
}

// ---------------------------------------------------------------------------
// Field types

const isText = (v) => typeof v === 'string' && v !== '';
const isCell = (v) => isText(v) && !/[|\n]/.test(v);
const isList = (v, ok) => Array.isArray(v) && v.length > 0 && v.every(ok);
const isCount = (v) => Number.isSafeInteger(v) && v > 0;

const COLUMNS = ['layers', 'envs', 'harness', 'owners', 'positive', 'negative'];
const KEYS = {
  scenario: ['id', 'kind', ...COLUMNS, 'note', 'matrix_sha256', 'stage'],
  contract: ['id', 'kind', 'covered_by', 'matrix_sha256'],
  subcase: ['id', 'kind', 'parent', 'conditional_on', 'table_text', ...COLUMNS, 'matrix_sha256', 'stage'],
  stage: ['milestone', 'scope', 'legs', 'status', 'implemented_sha256', 'tests'],
  waiver: ['commit', 'test', 'leg', 'run_id', 'run_attempt', 'reason', 'expires'],
};

function unknownKeys(obj, allowed, err) {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) err(`unknown field ${k}`);
}

// The layout §2 columns of a scenario or subcase entry. Text ends up in a
// Markdown table cell, so it holds no "|" or line break.
function columnsValid(e, codes, err) {
  let ok = true;
  const bad = (msg) => {
    err(msg);
    ok = false;
  };
  if (!isList(e.layers, (l) => Object.values(LAYERS).includes(l))) bad(`layers must be a non-empty list of ${Object.values(LAYERS).join(', ')}`);
  if (!isList(e.envs, (v) => Object.values(codes).includes(v))) bad(`envs must be a non-empty list of ${Object.values(codes).join(', ')}`);
  if (!isList(e.harness, isCell)) bad('harness must be a non-empty list of table text');
  if (!isList(e.owners, isCell)) bad('owners must be a non-empty list of task IDs');
  for (const k of ['positive', 'negative']) if (!isCell(e[k])) bad(`${k} must be non-empty table text`);
  if (e.note !== undefined && !isCell(e.note)) bad('note must be non-empty table text when present');
  if (!isList(e.stage, (s) => s !== null && typeof s === 'object' && !Array.isArray(s))) bad('needs at least one stage');
  return ok;
}

// ---------------------------------------------------------------------------
// Rules on one scenario or subcase entry with valid columns

function checkStages(e, stageErr) {
  const n = e.stage.length;
  e.stage.forEach((s, i) => {
    const se = (msg) => stageErr(s.milestone, `${e.id} ${s.milestone}: ${msg}`);
    unknownKeys(s, KEYS.stage, se);
    if (!MILESTONES.includes(s.milestone)) se(`unknown milestone (known: ${MILESTONES.join(', ')})`);
    else if (i > 0 && MILESTONES.indexOf(s.milestone) <= MILESTONES.indexOf(e.stage[i - 1].milestone)) se('stage milestones must increase, so that the last stage is the full milestone');
    if (!isCell(s.scope)) se('scope must be non-empty table text');
    else if ((s.scope === FULL_ROW) !== (n === 1)) se(`scope "${FULL_ROW}" is the scope of a single-stage entry, and only of one`);
    if (!STATUSES.includes(s.status)) se(`status must be one of ${STATUSES.join(', ')}`);
    if (!isList(s.legs, isText)) se('legs must be a non-empty list of leg strings');
    else if (new Set(s.legs).size !== s.legs.length) se('legs lists a leg twice');
    if (!Array.isArray(s.tests) || !s.tests.every(isText)) se('tests must be a list of test IDs');
    if (s.status === 'implemented') {
      if (!(s.tests?.length > 0)) se('an implemented stage must list its tests');
      const want = stageStamp(e.id, s.milestone, s.scope, e.matrix_sha256);
      if (s.implemented_sha256 !== want) {
        se(
          `implemented_sha256 is ${s.implemented_sha256 ?? 'missing'}, but the stage's (id, milestone, scope, matrix_sha256) stamps to ${want}; ` +
            'a changed scope, milestone or spec row needs review: set status = "planned" or re-stamp the stage',
        );
      }
    } else if (s.implemented_sha256 !== undefined) se('implemented_sha256 is only for an implemented stage');
  });
}

function checkLegs(e, catalogue, stageErr, err) {
  const used = new Set();
  for (const s of e.stage) {
    if (!Array.isArray(s.legs)) continue;
    // An unknown milestone is the stages rule's error; it has no jobs to check.
    const at = MILESTONES.indexOf(s.milestone);
    for (const leg of s.legs) {
      const c = catalogue.get(leg);
      if (!c) stageErr(s.milestone, `${e.id} ${s.milestone}: leg "${leg}" is not in the layout §1.1 Leg strings column`);
      else if (!e.envs.includes(c.env)) stageErr(s.milestone, `${e.id} ${s.milestone}: leg "${leg}" runs in job ${c.job} of env ${c.env}, which is not one of envs`);
      else if (at >= 0 && MILESTONES.indexOf(JOB_FROM[c.job]) > at) stageErr(s.milestone, `${e.id} ${s.milestone}: leg "${leg}" runs in job ${c.job}, which exists only from ${JOB_FROM[c.job]}`);
      else used.add(c.env);
    }
  }
  for (const env of e.envs) if (!used.has(env)) err(`${e.id}: env ${env} has no leg in any stage`);
}

// IDs of `entries` must strictly increase in file order.
function checkOrder(entries, file, at, report) {
  for (let i = 1; i < entries.length; i++) {
    if (!(entries[i].id > entries[i - 1].id)) report.error(file, at.get(entries[i].id), 'order', `${entries[i].id} follows ${entries[i - 1].id}: IDs must increase`);
  }
}

// ---------------------------------------------------------------------------
// Fixtures (layout §1.3)

const CONSUMERS = ['service', 'rust-client', 'ts-client', 'backend-verifier'];

function checkFixtures(root, scenarioIds, subcaseIds, report) {
  const schemas = join(root, SCHEMAS);
  if (existsSync(schemas) && readdirSync(schemas).length) {
    report.error(SCHEMAS, null, 'fixtures', 'JSON Schema validation of fixtures is not implemented yet; the PR that adds the first schema must add it to this check');
  }
  const dir = join(root, FIXTURES);
  if (!existsSync(dir)) return 0;
  let files = 0;
  for (const name of readdirSync(dir).sort()) {
    if (name.startsWith('_')) continue;
    const rel = `${FIXTURES}/${name}`;
    const id = /^a\d\d$/.test(name) ? name.toUpperCase() : null;
    if (!statSync(join(dir, name)).isDirectory() || !id || !scenarioIds.has(id)) {
      report.error(rel, null, 'fixtures', 'every entry not starting with "_" must be a directory named after a registered scenario, such as a61');
      continue;
    }
    const cases = new Set();
    for (const f of readdirSync(join(dir, name)).sort()) {
      const frel = `${rel}/${f}`;
      if (!f.endsWith('.json') || !statSync(join(dir, name, f)).isFile()) {
        report.error(frel, null, 'fixtures', 'a scenario fixture directory holds only .json case files');
        continue;
      }
      files++;
      let c;
      try {
        c = JSON.parse(readFileSync(join(dir, name, f), 'utf8'));
      } catch (ex) {
        report.error(frel, null, 'fixtures', `not valid JSON: ${ex.message}`);
        continue;
      }
      const bad = (msg) => report.error(frel, null, 'fixtures', msg);
      if (c === null || typeof c !== 'object' || Array.isArray(c)) {
        bad('a fixture is a JSON object');
        continue;
      }
      if (!isCount(c.fixture_version)) bad('fixture_version must be a positive integer');
      if (!isText(c.kind)) bad('kind must be a non-empty string');
      if (c.scenario !== id) bad(`scenario must be ${id}, the directory's scenario`);
      if (typeof c.case !== 'string' || !/^[a-z0-9_]+$/.test(c.case)) bad('case must match ^[a-z0-9_]+$');
      else if (cases.has(c.case)) bad(`case ${c.case} is not unique within ${id}`);
      else cases.add(c.case);
      if (c.polarity !== 'pos' && c.polarity !== 'neg') bad('polarity must be pos or neg');
      if (!isList(c.consumers, (x) => CONSUMERS.includes(x)) || new Set(c.consumers).size !== c.consumers.length) bad(`consumers must be distinct values of ${CONSUMERS.join(', ')}`);
      for (const k of ['input', 'expected']) if (c[k] === null || typeof c[k] !== 'object') bad(`${k} must be an object`);
      if (c.subcase !== undefined && (c.subcase?.slice?.(0, 3) !== id || !subcaseIds.has(c.subcase))) bad(`subcase must be a registered sub-ID of ${id}`);
    }
  }
  return files;
}

// ---------------------------------------------------------------------------
// Waivers

// Whether origin/main's full history is available in `root`: { onMain(sha) }
// or { reason } when it is not.
export function history(root) {
  const git = (...args) => spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  const top = git('rev-parse', '--show-toplevel');
  if (top.status !== 0 || realpathSync(top.stdout.trim()) !== realpathSync(root)) return { reason: 'the root is not a git checkout' };
  if (git('rev-parse', '--is-shallow-repository').stdout.trim() !== 'false') return { reason: 'the checkout is shallow' };
  if (git('rev-parse', '--verify', '--quiet', `${MAIN}^{commit}`).status !== 0) return { reason: `there is no ${MAIN}` };
  return {
    onMain: (sha) => {
      const r = git('merge-base', '--is-ancestor', sha, MAIN);
      return r.status === 0 ? 'yes' : r.status === 1 ? 'no' : 'unknown';
    },
  };
}

// `hist` is history(root) when --require-history probed it, else null.
function checkWaivers(doc, at, stagesByTest, root, requireHistory, hist, report) {
  const bad = (i, msg) => report.error(WAIVERS, at.get(`waiver/${i}`), 'waivers', msg);
  unknownKeys(doc, ['waiver'], (msg) => report.error(WAIVERS, null, 'fields', msg));
  const waivers = doc.waiver ?? [];
  if (!Array.isArray(waivers)) {
    report.error(WAIVERS, null, 'fields', 'waiver must be an array of tables ([[waiver]])');
    return 0;
  }
  waivers.forEach((w, i) => {
    unknownKeys(w, KEYS.waiver, (msg) => bad(i, msg));
    for (const k of KEYS.waiver) if (w[k] === undefined) bad(i, `missing required field ${k}`);
    if (w.commit !== undefined && !(typeof w.commit === 'string' && /^[0-9a-f]{40}$/.test(w.commit))) bad(i, 'commit must be a full 40-character lowercase hex SHA');
    else if (w.commit !== undefined) {
      hist ??= history(root);
      if (hist.onMain) {
        const on = hist.onMain(w.commit);
        if (on === 'no') bad(i, `commit ${w.commit} is not on main (not an ancestor of origin/main)`);
        else if (on === 'unknown') bad(i, `commit ${w.commit} is not in this repository's history`);
      }
    }
    if (w.test !== undefined) {
      const stages = typeof w.test === 'string' ? stagesByTest.get(w.test) : undefined;
      if (!stages) bad(i, `test ${JSON.stringify(w.test)} is not registered in any stage's tests`);
      else if (w.leg !== undefined && !stages.some((s) => s.legs.includes(w.leg))) bad(i, `leg ${JSON.stringify(w.leg)} is not a leg of a stage that lists ${w.test}`);
    }
    for (const k of ['run_id', 'run_attempt']) if (w[k] !== undefined && !isCount(w[k])) bad(i, `${k} must be a positive integer`);
    if (w.reason !== undefined && !isText(w.reason)) bad(i, 'reason must be a non-empty string');
    // A date-time or time never gets here: the toml rule rejects it.
    if (w.expires !== undefined && !(w.expires instanceof TomlDate)) bad(i, 'expires must be a TOML local date such as 2026-12-31');
  });
  if (waivers.length && hist && !hist.onMain && !requireHistory) report.note(`waivers: commit reachability not checked: ${hist.reason}`);
  return waivers.length;
}

// ---------------------------------------------------------------------------
// The check

const readMaybe = (root, rel) => (existsSync(join(root, rel)) ? readFileSync(join(root, rel), 'utf8') : null);

// Returns { errors, notes, summary }.
export function checkRegistry(root, { requireHistory = false } = {}) {
  const report = new Report();
  const done = (summary = null) => ({ errors: report.errors, notes: report.notes, summary });
  // CI asks for the history whether or not a waiver needs it, so a checkout
  // that lost it (fetch-depth) fails before the first waiver lands.
  const hist = requireHistory ? history(root) : null;
  if (hist && !hist.onMain) report.error(null, null, 'waivers', `--require-history: cannot check waiver commits against origin/main: ${hist.reason} (CI checks out with fetch-depth: 0)`);
  const texts = {};
  for (const rel of [TASKS, DESIGN, LAYOUT, SCENARIOS, SUBCASES]) {
    texts[rel] = readMaybe(root, rel);
    if (texts[rel] === null) report.error(rel, null, 'fields', 'not found');
  }
  if (report.errors.length) return done();

  // Spec side: leg catalogue, task lines, §8 and §2 rows, the §2 table. A spec
  // that cannot be read at all stops the check after these errors.
  const spec = (rule, read) => {
    try {
      return read();
    } catch (ex) {
      if (!(ex instanceof SpecError)) throw ex;
      report.error(null, null, rule, ex.message);
      return null;
    }
  };
  const specErrors = [];
  const env = spec('legs', () => parseEnvironments(texts[LAYOUT], specErrors));
  for (const msg of specErrors) report.error(null, null, 'legs', msg);
  const a = spec('ids', () => idRows(section(texts[TASKS], TASKS, '8.'), TASKS, 'A\\d\\d', 'scenario'));
  const c = spec('ids', () => idRows(section(texts[DESIGN], DESIGN, '2.'), DESIGN, 'C\\d\\d', 'contract'));
  const table = spec('table', () => findTable(texts[LAYOUT]));
  if (!env || !a || !c || !table) return done();
  const { codes, catalogue } = env;
  const counts = findCounts(texts[LAYOUT]);
  for (const msg of [...a.errors, ...c.errors]) report.error(null, null, 'ids', msg);
  const tasksById = taskLines(texts[TASKS]);

  const reg = load(texts[SCENARIOS], SCENARIOS, report);
  const sub = load(texts[SUBCASES], SUBCASES, report);
  const waiverText = readMaybe(root, WAIVERS);
  const wdoc = waiverText === null ? null : load(waiverText, WAIVERS, report);
  if (!reg || !sub) return done();
  const at = locate(texts[SCENARIOS]);
  const subAt = locate(texts[SUBCASES]);

  // scenarios.toml: gates_passed and [[scenario]] entries of two kinds.
  unknownKeys(reg, ['gates_passed', 'scenario'], (msg) => report.error(SCENARIOS, null, 'fields', msg));
  if (!Array.isArray(reg.gates_passed) || !reg.gates_passed.every((g) => MILESTONES.includes(g)) || new Set(reg.gates_passed).size !== reg.gates_passed.length) {
    report.error(SCENARIOS, null, 'fields', `gates_passed must be a list of distinct milestones (${MILESTONES.join(', ')})`);
  }
  const gates = Array.isArray(reg.gates_passed) ? reg.gates_passed.filter((g) => MILESTONES.includes(g)) : [];
  const all = Array.isArray(reg.scenario) ? reg.scenario : [];
  if (!Array.isArray(reg.scenario)) report.error(SCENARIOS, null, 'fields', 'scenario must be an array of tables ([[scenario]])');
  const ofKind = (kind, re) =>
    all.filter((e) => {
      if (e.kind !== kind) return false;
      if (typeof e.id === 'string' && re.test(e.id)) return true;
      report.error(SCENARIOS, at.get(e.id), 'ids', `${JSON.stringify(e.id)}: a ${kind} ID looks like ${kind === 'scenario' ? 'A24' : 'C07'}`);
      return false;
    });
  for (const e of all) if (e.kind !== 'scenario' && e.kind !== 'contract') report.error(SCENARIOS, at.get(e.id), 'fields', `${e.id}: kind must be scenario or contract`);
  const scenarios = ofKind('scenario', /^A\d\d$/);
  const contracts = ofKind('contract', /^C\d\d$/);

  // ids, order, hash against the spec rows.
  const matchRows = (entries, rows, specFile, what) => {
    const byRow = new Map(rows.map((r) => [r.id, r]));
    const seen = new Set();
    for (const e of entries) {
      if (seen.has(e.id)) report.error(SCENARIOS, null, 'ids', `${e.id} is registered more than once`);
      seen.add(e.id);
      const r = byRow.get(e.id);
      if (!r) report.error(SCENARIOS, at.get(e.id), 'ids', `${e.id} is not a ${what} row of ${specFile}`);
      else if (e.matrix_sha256 !== sha256(r.line)) {
        report.error(SCENARIOS, at.get(e.id), 'hash', `${e.id}: matrix_sha256 is ${e.matrix_sha256}, but ${specFile}:${r.n} hashes to ${sha256(r.line)}; review the entry and run the generator`);
      }
    }
    for (const r of rows) if (!seen.has(r.id)) report.error(specFile, r.n, 'ids', `${what} ${r.id} has no registry entry in ${SCENARIOS}`);
  };
  matchRows(scenarios, a.rows, TASKS, 'tasks §8 scenario');
  matchRows(contracts, c.rows, DESIGN, 'design §2 contract');
  checkOrder(scenarios, SCENARIOS, at, report);
  checkOrder(contracts, SCENARIOS, at, report);

  // Contracts.
  const scenarioIds = new Set(scenarios.map((e) => e.id));
  for (const e of contracts) {
    unknownKeys(e, KEYS.contract, (msg) => report.error(SCENARIOS, at.get(e.id), 'fields', `${e.id}: ${msg}`));
    if (!isList(e.covered_by, (id) => scenarioIds.has(id))) report.error(SCENARIOS, at.get(e.id), 'fields', `${e.id}: covered_by must be a non-empty list of registered scenarios`);
  }

  // Scenario and subcase entries: columns, owners, stages, legs.
  let rendered = true;
  const stagesByTest = new Map();
  const checkEntry = (e, file, where, keys) => {
    const err = (msg) => report.error(file, where.get(e.id), 'fields', msg);
    unknownKeys(e, keys, (msg) => err(`${e.id}: ${msg}`));
    if (!columnsValid(e, codes, (msg) => err(`${e.id}: ${msg}`))) {
      rendered = false;
      return;
    }
    for (const o of e.owners) if (!tasksById.has(o)) report.error(file, where.get(e.id), 'owners', `${e.id}: owner ${o} is not a task in ${TASKS}`);
    const r = annexRange(e.id, e.note);
    if (r && (r.from < 1 || r.to > 89 || r.from > r.to)) report.error(file, where.get(e.id), 'subcases', `${e.id}: annex range ${r.text} must lie within ${e.id}.01–${e.id}.89`);
    const stageErr = (rule) => (m, msg) => report.error(file, where.get(`${e.id}/${m}`) ?? where.get(e.id), rule, msg);
    checkStages(e, stageErr('stages'));
    checkLegs(e, catalogue, stageErr('legs'), (msg) => report.error(file, where.get(e.id), 'legs', msg));
    // Layout §3 Release: a conditional sub-ID is required only when the release
    // manifest lists its feature as shipped. No manifest exists yet, so its
    // stages join the gate once one selects their feature.
    const gated = e.conditional_on === undefined;
    for (const s of e.stage) {
      if (gated && gates.includes(s.milestone) && s.status !== 'implemented') stageErr('gates')(s.milestone, `${e.id} ${s.milestone}: gates_passed lists ${s.milestone}, but this stage is ${s.status}, not implemented`);
      for (const t of Array.isArray(s.tests) ? s.tests : []) stagesByTest.set(t, [...(stagesByTest.get(t) ?? []), { legs: Array.isArray(s.legs) ? s.legs : [] }]);
    }
  };
  for (const e of scenarios) checkEntry(e, SCENARIOS, at, KEYS.scenario);

  // subcases.toml.
  unknownKeys(sub, ['subcase'], (msg) => report.error(SUBCASES, null, 'fields', msg));
  const subs = Array.isArray(sub.subcase) ? sub.subcase : [];
  if (sub.subcase !== undefined && !Array.isArray(sub.subcase)) report.error(SUBCASES, null, 'fields', 'subcase must be an array of tables ([[subcase]])');
  for (const s of subs) {
    const err = (rule, msg) => report.error(SUBCASES, subAt.get(s.id), rule, `${s.id}: ${msg}`);
    if (s.kind !== 'subcase') err('fields', 'kind must be subcase');
    if (typeof s.id !== 'string' || !/^A\d\d\.\d\d$/.test(s.id)) err('ids', 'a sub-ID looks like A58.07');
    else if (s.parent !== s.id.slice(0, 3) || !scenarioIds.has(s.parent)) err('subcases', `parent must be the registered scenario ${s.id.slice(0, 3)}`);
    const owner = Array.isArray(s.owners) ? s.owners[0] : undefined;
    if (owner === undefined || !tasksById.has(owner)) err('hash', 'the first owner must be a task, whose tasks.md line matrix_sha256 hashes');
    else if (s.matrix_sha256 !== sha256(tasksById.get(owner))) err('hash', `matrix_sha256 is ${s.matrix_sha256}, but the ${TASKS} line of ${owner} hashes to ${sha256(tasksById.get(owner))}; review the entry and run the generator`);
    const parent = scenarios.find((e) => e.id === s.parent);
    if (s.conditional_on === undefined) {
      if (s.table_text !== undefined) err('subcases', 'table_text is only for a conditional sub-ID');
      const r = annexRange(s.parent, parent?.note);
      const n = Number(String(s.id).slice(4));
      if (!r) err('subcases', `required sub-ID, but the note of ${s.parent} declares no annex range`);
      else if (n < r.from || n > r.to) err('subcases', `required sub-ID is outside the annex range ${r.text} that the note of ${s.parent} declares`);
    } else if (typeof s.id === 'string' && !isConditionalNumber(s.id)) {
      err('subcases', `a conditional sub-ID is numbered ${s.parent}.90–${s.parent}.99`);
    } else if (!Object.values(FEATURES).includes(s.conditional_on)) {
      err('subcases', `conditional_on must be one of ${Object.values(FEATURES).join(', ')}`);
    } else {
      const t = isCell(s.table_text) ? parseConditional(s.table_text) : null;
      if (!t) {
        err('subcases', `table_text must be a "Conditional sub-ID ${s.id} (<feature>, Txx.y): ..." sentence`);
        rendered = false;
      } else {
        if (t.id !== null && t.id !== s.id) err('subcases', `table_text names ${t.id}`);
        if (t.feature !== s.conditional_on) err('subcases', `table_text names feature ${t.feature ?? t.label}, but conditional_on is ${s.conditional_on}`);
        if (t.task !== owner) err('subcases', `table_text names ${t.task}, but the first owner is ${owner}`);
      }
    }
    checkEntry(s, SUBCASES, subAt, KEYS.subcase);
  }
  checkOrder(subs, SUBCASES, subAt, report);
  const named = [];
  table.lines.slice(TABLE_HEADER.length).forEach((line) => named.push(...rowConditionals(line, line.slice(2, 5))));
  const namedErrors = [];
  checkNamedSubcases(named, subs, namedErrors);
  for (const msg of namedErrors) report.error(null, null, 'subcases', msg);

  // The §2 table and counts, rendered from the registry.
  if (rendered) {
    const want = renderTable(scenarios, subs, codes);
    for (let i = 0; i < Math.max(want.length, table.lines.length); i++) {
      if (want[i] === table.lines[i]) continue;
      const row = /^\| (A\d\d) \|/.exec(want[i] ?? table.lines[i]);
      const msg =
        want[i] === undefined
          ? 'the §2 table has a row that the registry does not render'
          : `the §2 table ${row ? `row ${row[1]}` : 'header'} differs from the one rendered from the registry; run node scripts/ci/gen-conformance-registry.mjs. Expected: ${want[i]}`;
      report.error(LAYOUT, table.first + i, 'table', msg);
    }
    const sentences = renderCounts(scenarios);
    if (!counts) report.error(LAYOUT, null, 'table', `the counts sentences after the §2 table are missing; expected: ${sentences}`);
    else if (counts.text !== sentences) report.error(LAYOUT, counts.n, 'table', `the counts sentences differ from the registry; expected: ${sentences}`);
  } else {
    report.note('table: not compared, because some scenario or subcase fields are invalid');
  }

  const fixtures = checkFixtures(root, scenarioIds, new Set(subs.map((s) => s.id)), report);
  const waivers = wdoc ? checkWaivers(wdoc, locate(waiverText), stagesByTest, root, requireHistory, hist, report) : 0;
  return done(`${scenarios.length} scenarios, ${contracts.length} contracts, ${subs.length} subcases, ${fixtures} fixtures, ${waivers} waivers`);
}

export function run(argv, log = console.log, logErr = console.error) {
  let root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  let requireHistory = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--require-history') requireHistory = true;
    else if (argv[i] === '--root' && argv[i + 1]) root = resolve(argv[++i]);
    else {
      logErr('usage: check-conformance-registry.mjs [--root DIR] [--require-history]');
      return 2;
    }
  }
  const { errors, notes, summary } = checkRegistry(root, { requireHistory });
  for (const n of notes) log(`note: ${n}`);
  for (const e of errors) logErr(formatError(e));
  if (errors.length) {
    logErr(`check-conformance-registry: ${errors.length} error(s)`);
    return 1;
  }
  log(`check-conformance-registry: OK (${summary})`);
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
