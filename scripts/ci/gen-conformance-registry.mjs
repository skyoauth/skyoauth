#!/usr/bin/env node
// Generates the conformance registry from the specs.
//
//   node scripts/ci/gen-conformance-registry.mjs [--root DIR]          # write
//   node scripts/ci/gen-conformance-registry.mjs [--root DIR] --check  # verify
//
// Outputs tests/conformance/scenarios.toml and tests/conformance/subcases.toml.
//
// Derived (rewritten on every run, never edit by hand):
//   - scenario IDs A01... and matrix_sha256 from the tasks §8 table rows;
//   - contract IDs C01... and matrix_sha256 from the design §2 table rows;
//   - layers, envs, harness, owners, note, positive, negative and each stage's
//     milestone and scope from the scenario table in
//     docs/testing/conformance-layout.md §2;
//   - contract covered_by from the contract table in the layout doc §5 (Q11);
//   - subcase matrix_sha256 from the tasks bullet line of the subcase's first
//     owner, and every comment in both files.
// Hand-authored (kept from the committed files):
//   - gates_passed;
//   - each stage's legs, status and tests, keyed by (id, milestone). A stage
//     with no committed legs gets the provisional default legs computed by
//     defaultLegs();
//   - every field of a subcase except matrix_sha256.
//
// Checked against the layout doc:
//   - every leg is a leg string of the §1.1 "Leg strings" column, whose env is
//     one of the entry's envs and whose job exists at the stage's milestone;
//   - the §2 table rendered back from the registry equals the committed
//     table. A row's trailing "Conditional sub-ID ..." sentence is rendered
//     from the table_text of that sub-ID's entry in subcases.toml;
//   - subcases.toml holds exactly the sub-IDs that §2 names, with the parent,
//     conditional_on and first owner that §2 gives them;
//   - neither file repeats an ID or a (id, milestone) stage.
//
// matrix_sha256 is the SHA-256 of the UTF-8 bytes of the whole source line,
// from its first character to its last, with no trailing newline.
//
// --check regenerates both files in memory and exits 1 if either differs from
// the committed file, listing each differing (id, field). Spec and registry
// errors exit 1 in both modes and write nothing. Usage and internal errors
// exit 2. Needs only Node (>=20); no dependencies.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const TASKS = 'docs/skyoauth-tasks.md';
export const DESIGN = 'docs/skyoauth-design.md';
export const LAYOUT = 'docs/testing/conformance-layout.md';
export const SCENARIOS = 'tests/conformance/scenarios.toml';
export const SUBCASES = 'tests/conformance/subcases.toml';

export const MILESTONES = ['M0', 'M1a', 'M1b', 'M2', 'M3', 'M4', 'M5'];

const LAYERS = { C: 'conformance', S: 'security', I: 'integration', P: 'package' };
// Feature label in a §2 "Conditional sub-ID (<label>, Txx.y)" sentence ->
// conditional_on value.
const FEATURES = { 'device flow': 'device-flow', 'back-channel logout': 'back-channel-logout', ForwardAuth: 'forwardauth' };
const STATUSES = ['planned', 'implemented'];
// A single-stage row shows only its milestone in the table; its stage scope
// is this fixed text (as in the layout §3 A64 example).
const FULL_ROW = 'full row';
const AUDIT = 'deployed-topology audit';

// First milestone in which each CI job exists (layout §1.1 and the §4 table;
// `typescript` exists already). The jobs and legs themselves come from the
// §1.1 "Leg strings" column; every job there must have an entry here.
export const JOB_FROM = {
  'scenarios-hermetic': 'M1a',
  'clients-rust': 'M2',
  typescript: 'M0',
  'bundle-check': 'M3',
  'scenarios-pg': 'M1a',
  'scenarios-envoy-k3s': 'M2',
  'scenarios-envoy-k3s-nightly': 'M2',
  'migration-rehearsal': 'M5',
  'deployed-topology-audit': 'M5',
  'typescript-browser': 'M3',
  operator: 'M1a',
  'recovery-offline': 'M1a',
  'clients-rust-native': 'M4',
  'live-wif': 'M2',
};

const mIndex = (m) => MILESTONES.indexOf(m);

// Provisional default legs for a stage that has none committed yet; the PR
// that implements a stage confirms its legs. A deployed-topology audit stage
// runs only in its audit job. Otherwise, for each env of the row, the env's
// default jobs that exist at the stage's milestone; an env with no such job is
// left out of that stage. The per-scenario choices below follow the Harness
// column and layout §1.1/§5 Q6.
export function defaultLegs(entry, stage, catalogue) {
  const legsOf = (job) => [...catalogue].filter(([, v]) => v.job === job).map(([leg]) => leg);
  if (stage.scope === AUDIT) return legsOf('deployed-topology-audit');
  const jobsFor = (env) => {
    switch (env) {
      case 'hermetic':
        if (entry.id === 'A39') return ['typescript', 'bundle-check']; // npm pack, bundle check, typecheck
        if (entry.id === 'A40') return ['typescript']; // vitest fetch spy
        return ['scenarios-hermetic'];
      case 'pg':
        return ['scenarios-pg'];
      case 'envoy-k3s':
        if (stage.milestone === 'M5') return ['migration-rehearsal'];
        if (entry.id === 'A54') return ['scenarios-envoy-k3s', 'scenarios-envoy-k3s-nightly']; // kubelet rotation (nightly)
        return ['scenarios-envoy-k3s'];
      case 'browser':
        return ['typescript-browser'];
      case 'native-3os':
        if (entry.id === 'A64') return ['operator', 'recovery-offline']; // §5 Q6
        if (entry.harness.some((h) => /^OP\b/.test(h))) return ['operator'];
        return ['clients-rust-native'];
      case 'live':
        return ['live-wif'];
      default:
        return [];
    }
  };
  const legs = [];
  for (const env of entry.envs) {
    for (const job of jobsFor(env)) {
      if (JOB_FROM[job] && mIndex(JOB_FROM[job]) <= mIndex(stage.milestone)) legs.push(...legsOf(job));
    }
  }
  return legs;
}

// ---------------------------------------------------------------------------
// Markdown

export const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

class SpecError extends Error {}

// Lines of a "## <n>." section, outside fenced code blocks, with 1-based
// line numbers.
function section(text, file, prefix) {
  const lines = text.split('\n');
  const out = [];
  let inside = false;
  let fence = null;
  let found = false;
  lines.forEach((line, i) => {
    const f = /^ {0,3}(`{3,}|~{3,})/.exec(line);
    if (f) {
      if (!fence) fence = f[1];
      else if (f[1][0] === fence[0] && f[1].length >= fence.length && line.trim() === f[1]) fence = null;
      return;
    }
    if (fence) return;
    if (/^## /.test(line)) {
      inside = line.startsWith(`## ${prefix} `);
      if (inside) found = true;
      return;
    }
    if (inside) out.push({ line, n: i + 1 });
  });
  if (!found) throw new SpecError(`${file}: section "## ${prefix}" not found`);
  return out;
}

const cellsOf = (line) => line.slice(2, -2).split(' | ');

// Rows `| <ID> | ...` of a section whose ID matches `re` (anchored, with a
// single capture for the number). Checks for duplicates and gaps from 01.
function idRows(lines, file, re, what) {
  const rows = [];
  const errors = [];
  const seen = new Map();
  for (const { line, n } of lines) {
    const m = new RegExp(`^\\| (${re}) \\|`).exec(line);
    if (!m) continue;
    if (!line.endsWith(' |')) errors.push(`${file}:${n}: ${m[1]} row does not end with " |"`);
    if (seen.has(m[1])) {
      errors.push(`${file}:${n}: duplicate ${what} row ${m[1]} (first at line ${seen.get(m[1])})`);
      continue;
    }
    seen.set(m[1], n);
    rows.push({ id: m[1], line, n });
  }
  const letter = re[0];
  rows.forEach((r, i) => {
    const want = `${letter}${String(i + 1).padStart(2, '0')}`;
    if (r.id !== want && !errors.length) errors.push(`${file}:${r.n}: ${what} rows must run ${letter}01, ${letter}02, ... without gaps: expected ${want}, found ${r.id}`);
  });
  if (!rows.length) errors.push(`${file}: no ${what} rows found`);
  return { rows, errors };
}

// The §1.1 environment table: env codes and the leg catalogue
// (leg string -> { job, env }) from its "Leg strings" column.
export function parseEnvironments(layout, errors) {
  const lines = section(layout, LAYOUT, '1.');
  const start = lines.findIndex((l) => l.line.startsWith('### 1.1 '));
  if (start < 0) throw new SpecError(`${LAYOUT}: subsection "### 1.1" not found`);
  const codes = {};
  const catalogue = new Map();
  let col = -1;
  for (const { line, n } of lines.slice(start + 1)) {
    if (line.startsWith('### ')) break;
    if (!line.startsWith('| ')) continue;
    const cells = cellsOf(line);
    if (cells[0] === 'Env') {
      col = cells.indexOf('Leg strings');
      if (col < 0) throw new SpecError(`${LAYOUT}:${n}: layout §1.1 table has no "Leg strings" column`);
      continue;
    }
    const env = /^`([a-z0-9-]+)`$/.exec(cells[0]);
    if (!env || col < 0) continue;
    codes[cells[1]] = env[1];
    const legs = [...(cells[col] ?? '').matchAll(/`([^`]+)`/g)].map((m) => m[1]);
    if (!legs.length) errors.push(`${LAYOUT}:${n}: env ${env[1]} lists no leg strings`);
    for (const leg of legs) {
      if (!/^[a-z0-9-]+(\/[a-z0-9_]+)?$/.test(leg)) errors.push(`${LAYOUT}:${n}: malformed leg string "${leg}"`);
      const job = leg.split('/')[0];
      if (catalogue.has(leg)) {
        errors.push(`${LAYOUT}:${n}: leg ${leg} is listed under both ${catalogue.get(leg).env} and ${env[1]}`);
        continue;
      }
      if (!JOB_FROM[job]) errors.push(`${LAYOUT}:${n}: job ${job} of the layout §1.1 Leg strings column has no known first milestone (add it to JOB_FROM)`);
      catalogue.set(leg, { job, env: env[1] });
    }
  }
  if (col < 0) throw new SpecError(`${LAYOUT}: layout §1.1 table has no "Leg strings" column`);
  const jobs = new Set([...catalogue.values()].map((v) => v.job));
  for (const job of Object.keys(JOB_FROM)) if (!jobs.has(job)) errors.push(`${LAYOUT}: job ${job} is not in the layout §1.1 Leg strings column`);
  return { codes, catalogue };
}

// Splits on `sep` outside parentheses and backticks.
function splitTop(s, sep) {
  const out = [];
  let depth = 0;
  let tick = false;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '`') tick = !tick;
    else if (!tick && c === '(') depth++;
    else if (!tick && c === ')') depth--;
    else if (!tick && depth === 0 && s.startsWith(sep, i)) {
      out.push(s.slice(start, i));
      start = i + sep.length;
      i += sep.length - 1;
    }
  }
  out.push(s.slice(start));
  return out;
}

const POS = '+ ';
const NEG = '; − '; // U+2212 MINUS SIGN, as in the table
const COND = '. Conditional sub-ID';
const COND_RE = /^Conditional sub-ID(?: (A\d\d\.\d\d))? \(([^,()]+), (T\d\d\.\d+)\): (.+)$/;

// Parses a "Conditional sub-ID [Axx.yy] (<feature>, Txx.y): <text>" sentence.
export function parseConditional(text) {
  const m = COND_RE.exec(text);
  if (!m) return null;
  return { id: m[1] ?? null, label: m[2], feature: FEATURES[m[2]] ?? null, task: m[3] };
}

// Parses one row of the layout §2 scenario table. `conditional` lists the
// row's trailing conditional sub-ID sentences; they are not registry fields
// of the row (subcases.toml renders them).
export function parseLayoutRow(line, where, codes) {
  const cells = cellsOf(line);
  if (cells.length !== 7) throw new SpecError(`${where}: expected 7 cells, found ${cells.length}`);
  const [id, layer, env, harness, stages, owners, pm] = cells;
  const fail = (msg) => {
    throw new SpecError(`${where}: ${id}: ${msg}`);
  };
  const entry = { id };
  entry.layers = layer.split('+').map((c) => LAYERS[c] ?? fail(`unknown layer code "${c}"`));
  entry.envs = env.split(', ').map((c) => codes[c] ?? fail(`unknown env "${c}"`));
  entry.harness = splitTop(harness, ', ');
  entry.owners = owners.split(', ');
  for (const o of entry.owners) if (!/^T\d\d\.\d+$/.test(o)) fail(`owner "${o}" is not a task ID`);
  entry.stages = stages.split(' · ').map((part, i, all) => {
    const m = /^(M[0-9][ab]?)(?:: (.+))?$/.exec(part);
    if (!m || !MILESTONES.includes(m[1])) fail(`unparsable stage "${part}"`);
    if (!m[2] && all.length > 1) fail(`stage "${part}" of a multi-stage row has no scope`);
    return { milestone: m[1], scope: m[2] ?? FULL_ROW };
  });
  for (let i = 1; i < entry.stages.length; i++) {
    if (mIndex(entry.stages[i].milestone) <= mIndex(entry.stages[i - 1].milestone)) fail('stage milestones are not increasing');
  }
  let rest = pm;
  if (!rest.startsWith(POS)) {
    const cands = [rest.indexOf(`: ${POS}`), rest.indexOf(`. ${POS}`)].filter((x) => x >= 0);
    if (!cands.length) fail('"+ / −" cell has no "+ " part');
    const p = Math.min(...cands);
    entry.note = rest.slice(0, p + 1);
    rest = rest.slice(p + 2);
  }
  rest = rest.slice(POS.length);
  const sentences = rest.split(COND);
  rest = sentences.shift();
  entry.conditional = sentences.map((s) => {
    const text = `Conditional sub-ID${s}`;
    const c = parseConditional(text);
    if (!c) fail(`unparsable sentence "${text}"`);
    if (!c.feature) fail(`unknown conditional feature "${c.label}" (known: ${Object.keys(FEATURES).join(', ')})`);
    if (c.id && c.id.slice(0, 3) !== id) fail(`conditional sub-ID ${c.id} is not a sub-ID of ${id}`);
    return { ...c, parent: id, text, n: where };
  });
  const parts = splitTop(rest, NEG);
  if (parts.length !== 2) fail(`"+ / −" cell must contain exactly one "${NEG}", found ${parts.length - 1}`);
  [entry.positive, entry.negative] = parts;
  if (renderLayoutRow(entry, codes, entry.conditional.map((c) => c.text)) !== line) fail('row does not round-trip through the registry fields');
  return entry;
}

// Renders a scenario entry back into its layout §2 table row. `sentences` are
// the table_text values of the row's conditional sub-IDs, in ID order.
export function renderLayoutRow(e, codes, sentences = []) {
  const code = (v) => Object.keys(codes).find((k) => codes[k] === v) ?? `?${v}`;
  const stages =
    e.stages.length === 1 && e.stages[0].scope === FULL_ROW
      ? e.stages[0].milestone
      : e.stages.map((s) => `${s.milestone}: ${s.scope}`).join(' · ');
  const pm = `${e.note ? `${e.note} ` : ''}${POS}${e.positive}${NEG}${e.negative}${sentences.map((s) => `. ${s}`).join('')}`;
  const cells = [e.id, e.layers.map((l) => Object.keys(LAYERS).find((k) => LAYERS[k] === l)).join('+'), e.envs.map(code).join(', '), e.harness.join(', '), stages, e.owners.join(', '), pm];
  return `| ${cells.join(' | ')} |`;
}

// Task IDs defined as "- [ ] **T12.3** ..." bullets, with their lines.
export function taskLines(text) {
  const map = new Map();
  for (const line of text.split('\n')) {
    const m = /^- \[[ xX]\] \*\*(T\d\d\.\d+)\*\*/.exec(line);
    if (m && !map.has(m[1])) map.set(m[1], line);
  }
  return map;
}

// ---------------------------------------------------------------------------
// TOML subset reader (what this script writes: comments, [[tables]], keys with
// basic strings, integers, booleans, arrays and inline tables). Each [[table]]
// object carries its header line in the non-enumerable property __line.

export function parseToml(text, file = 'toml') {
  let i = 0;
  let line = 1;
  const root = {};
  let cur = root;
  const err = (msg) => {
    throw new SpecError(`${file}:${line}: ${msg}`);
  };
  const ws = (nl) => {
    for (;;) {
      const c = text[i];
      if (c === ' ' || c === '\t' || c === '\r') i++;
      else if (c === '#') while (i < text.length && text[i] !== '\n') i++;
      else if (nl && c === '\n') {
        i++;
        line++;
      } else return;
    }
  };
  const key = () => {
    const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 200));
    if (!m) err('expected a bare key');
    i += m[0].length;
    return m[0];
  };
  const value = () => {
    const c = text[i];
    if (c === '"') {
      let s = '';
      i++;
      for (;;) {
        const d = text[i++];
        if (d === undefined || d === '\n') err('unterminated string');
        if (d === '"') return s;
        if (d === '\\') {
          const e = text[i++];
          const simple = { '"': '"', '\\': '\\', n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' };
          if (e in simple) s += simple[e];
          else if (e === 'u' || e === 'U') {
            const len = e === 'u' ? 4 : 8;
            s += String.fromCodePoint(parseInt(text.slice(i, i + len), 16));
            i += len;
          } else err(`bad escape \\${e}`);
        } else s += d;
      }
    }
    if (c === '[') {
      i++;
      const arr = [];
      for (;;) {
        ws(true);
        if (text[i] === ']') {
          i++;
          return arr;
        }
        arr.push(value());
        ws(true);
        if (text[i] === ',') i++;
        else if (text[i] !== ']') err('expected "," or "]"');
      }
    }
    if (c === '{') {
      i++;
      const obj = {};
      ws(false);
      if (text[i] === '}') {
        i++;
        return obj;
      }
      for (;;) {
        ws(false);
        const k = key();
        ws(false);
        if (text[i++] !== '=') err('expected "="');
        ws(false);
        obj[k] = value();
        ws(false);
        if (text[i] === ',') i++;
        else if (text[i] === '}') {
          i++;
          return obj;
        } else err('expected "," or "}"');
      }
    }
    const m = /^(true|false|-?\d+)/.exec(text.slice(i, i + 40));
    if (!m) err('unsupported value');
    i += m[0].length;
    return m[0] === 'true' ? true : m[0] === 'false' ? false : Number(m[0]);
  };
  for (;;) {
    ws(true);
    if (i >= text.length) return root;
    if (text.startsWith('[[', i)) {
      const end = text.indexOf(']]', i);
      if (end < 0) err('unterminated table header');
      const path = text.slice(i + 2, end).trim().split('.');
      i = end + 2;
      let parent = root;
      for (const p of path.slice(0, -1)) {
        const a = parent[p];
        if (!Array.isArray(a) || !a.length) err(`[[${path.join('.')}]] without a parent`);
        parent = a[a.length - 1];
      }
      const last = path[path.length - 1];
      cur = {};
      // The header's line, for duplicate-key errors; not enumerable, so it
      // never shows up as a field.
      Object.defineProperty(cur, '__line', { value: line });
      (parent[last] ??= []).push(cur);
    } else {
      const k = key();
      ws(false);
      if (text[i++] !== '=') err('expected "="');
      ws(false);
      if (k in cur) err(`duplicate key ${k}`);
      cur[k] = value();
    }
    ws(false);
    if (i < text.length && text[i] !== '\n') err('expected end of line');
  }
}

// ---------------------------------------------------------------------------
// TOML writer: one key per line, fixed key order.

const q = (s) =>
  '"' +
  s.replace(/[\\"\u0000-\u001f\u007f]/g, (c) => {
    const named = { '\\': '\\\\', '"': '\\"', '\n': '\\n', '\t': '\\t', '\r': '\\r' };
    return named[c] ?? `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
  }) +
  '"';

const MAX = 100;
function kv(k, v) {
  if (typeof v === 'string') return `${k} = ${q(v)}`;
  if (Array.isArray(v)) {
    const inline = `${k} = [${v.map(q).join(', ')}]`;
    if (v.length < 2 || inline.length <= MAX) return inline;
    return `${k} = [\n${v.map((x) => `  ${q(x)},\n`).join('')}]`;
  }
  throw new Error(`cannot write ${k}`);
}

function stageBlock(table, s) {
  return [
    `[[${table}.stage]]`,
    kv('milestone', s.milestone),
    kv('scope', s.scope),
    kv('legs', s.legs),
    kv('status', s.status),
    kv('tests', s.tests),
  ].join('\n');
}

function scenarioBlock(e) {
  const out = ['[[scenario]]', kv('id', e.id), kv('kind', 'scenario'), kv('layers', e.layers), kv('envs', e.envs)];
  out.push(kv('harness', e.harness), kv('owners', e.owners));
  if (e.note) out.push(kv('note', e.note));
  out.push(kv('positive', e.positive), kv('negative', e.negative), kv('matrix_sha256', e.matrix_sha256));
  return [out.join('\n'), ...e.stages.map((s) => stageBlock('scenario', s))].join('\n\n');
}

function contractBlock(c) {
  return ['[[scenario]]', kv('id', c.id), kv('kind', 'contract'), kv('covered_by', c.covered_by), kv('matrix_sha256', c.matrix_sha256)].join('\n');
}

function subcaseBlock(e, sourceLine) {
  const out = ['[[subcase]]', kv('id', e.id), kv('kind', 'subcase'), kv('parent', e.parent)];
  if (e.conditional_on !== undefined) out.push(kv('conditional_on', e.conditional_on), kv('table_text', e.table_text));
  out.push(kv('layers', e.layers), kv('envs', e.envs), kv('harness', e.harness), kv('owners', e.owners));
  out.push(kv('positive', e.positive), kv('negative', e.negative));
  out.push(`# matrix_sha256: SHA-256 of the whole ${TASKS} line of ${e.owners[0]}, no trailing newline:`);
  out.push(`#   ${sourceLine.length > 96 ? `${sourceLine.slice(0, 95)}…` : sourceLine}`);
  out.push(kv('matrix_sha256', e.matrix_sha256));
  return [out.join('\n'), ...e.stages.map((s) => stageBlock('subcase', s))].join('\n\n');
}

const SCENARIOS_HEADER = `# Conformance scenario registry: A01–A64 (tasks §8) and C01–C10 (design §2).
# Generated by scripts/ci/gen-conformance-registry.mjs; see tests/conformance/README.md.
# Hand-edit only gates_passed and each stage's legs, status and tests; the
# generator keeps those and rewrites everything else from the specs.
`;

const SUBCASES_HEADER = `# Sub-ID annex of the conformance registry (layout doc §3, §5 Q1/Q3, §6).
# Hand-authored except matrix_sha256 and comments, which
# scripts/ci/gen-conformance-registry.mjs rewrites; see tests/conformance/README.md.
`;

// ---------------------------------------------------------------------------
// Generation

function readMaybe(root, rel) {
  const p = join(root, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

// Duplicate IDs and duplicate (id, milestone) stages in a committed file,
// reported before anything is keyed by them.
function duplicateErrors(doc, file, table) {
  const errors = [];
  const ids = new Map();
  for (const e of doc[table] ?? []) {
    if (ids.has(e.id)) errors.push(`${file}:${e.__line}: duplicate ${table} ${e.id} (first at line ${ids.get(e.id)})`);
    else ids.set(e.id, e.__line);
    const ms = new Map();
    for (const s of e.stage ?? []) {
      if (ms.has(s.milestone)) errors.push(`${file}:${s.__line}: duplicate stage ${e.id} ${s.milestone} (first at line ${ms.get(s.milestone)})`);
      else ms.set(s.milestone, s.__line);
    }
  }
  return errors;
}

function validStages(stages, where, errors) {
  for (const s of stages) {
    if (!MILESTONES.includes(s.milestone)) errors.push(`${where}: unknown stage milestone ${s.milestone}`);
    if (!STATUSES.includes(s.status)) errors.push(`${where} ${s.milestone}: status must be planned or implemented`);
    if (!Array.isArray(s.legs) || !s.legs.length) errors.push(`${where} ${s.milestone}: stage has no legs`);
  }
}

// Leg checks of layout §3: each leg is a §1.1 leg string, its env is one of
// the entry's envs and its job exists at the stage's milestone; each env has
// a leg in some stage.
function checkLegs(e, where, catalogue, errors) {
  const used = new Set();
  for (const s of e.stages) {
    for (const leg of s.legs ?? []) {
      const c = catalogue.get(leg);
      if (!c) errors.push(`${where} ${s.milestone}: unknown leg "${leg}" (not in the layout §1.1 Leg strings column)`);
      else if (!e.envs.includes(c.env)) errors.push(`${where} ${s.milestone}: leg "${leg}" belongs to env ${c.env}, not in envs`);
      else if (JOB_FROM[c.job] && mIndex(JOB_FROM[c.job]) > mIndex(s.milestone)) errors.push(`${where} ${s.milestone}: job ${c.job} exists only from ${JOB_FROM[c.job]}`);
      else used.add(c.env);
    }
  }
  for (const env of e.envs) if (!used.has(env)) errors.push(`${where}: env ${env} has no leg in any stage`);
}

// Matches subcases.toml against the conditional sub-IDs that layout §2 names.
// A named ID must exist with the named parent, feature and first owner; an
// unnumbered one must match exactly one entry by those three; every entry
// must be named.
function checkNamedSubcases(named, subs, errors) {
  const matched = new Set();
  const explicit = new Set(named.filter((n) => n.id).map((n) => n.id));
  const desc = (n) => `${n.id ?? `sub-ID of ${n.parent}`} (${n.feature}, ${n.task}) is named in ${LAYOUT} §2 row ${n.parent}`;
  for (const n of named.filter((x) => x.id)) {
    const s = subs.find((x) => x.id === n.id);
    if (!s) {
      errors.push(`${desc(n)} but missing from ${SUBCASES}`);
      continue;
    }
    matched.add(s);
    if (s.parent !== n.parent) errors.push(`${SUBCASES}: ${s.id}: parent is ${s.parent}, but the layout doc names it under ${n.parent}`);
    if (s.conditional_on !== n.feature) errors.push(`${SUBCASES}: ${s.id}: conditional_on is ${s.conditional_on}, but the layout doc names ${n.feature}`);
    if (s.owners?.[0] !== n.task) errors.push(`${SUBCASES}: ${s.id}: first owner is ${s.owners?.[0]}, but the layout doc names ${n.task}`);
  }
  for (const n of named.filter((x) => !x.id)) {
    const c = subs.filter((s) => !matched.has(s) && !explicit.has(s.id) && s.parent === n.parent && s.conditional_on === n.feature && s.owners?.[0] === n.task);
    if (c.length === 1) matched.add(c[0]);
    else if (!c.length) errors.push(`${desc(n)} but missing from ${SUBCASES}`);
    else errors.push(`${desc(n)} without an ID, but ${c.map((s) => s.id).join(' and ')} all match it`);
  }
  for (const s of subs) if (!matched.has(s)) errors.push(`${SUBCASES}: ${s.id} is not a sub-ID named in ${LAYOUT} §2`);
}

// Returns { files: { [path]: text }, errors: string[], entries, catalogue, codes }.
export function generate(root) {
  const errors = [];
  const read = (rel) => {
    const t = readMaybe(root, rel);
    if (t === null) throw new SpecError(`${rel}: not found`);
    return t;
  };
  const fail = (extra = {}) => ({ files: null, errors, entries: null, catalogue: null, ...extra });
  try {
    const tasks = read(TASKS);
    const design = read(DESIGN);
    const layout = read(LAYOUT);
    const tasksById = taskLines(tasks);
    const { codes, catalogue } = parseEnvironments(layout, errors);

    // Committed files: reject repeated keys before anything is keyed by them.
    const oldScenarios = readMaybe(root, SCENARIOS);
    const old = oldScenarios === null ? {} : parseToml(oldScenarios, SCENARIOS);
    const subText = readMaybe(root, SUBCASES);
    const subDoc = subText === null ? {} : parseToml(subText, SUBCASES);
    const dups = [...duplicateErrors(old, SCENARIOS, 'scenario'), ...duplicateErrors(subDoc, SUBCASES, 'subcase')];
    if (dups.length) {
      errors.push(...dups);
      return fail({ catalogue });
    }

    const a = idRows(section(tasks, TASKS, '8.'), TASKS, 'A\\d\\d', 'scenario');
    const c = idRows(section(design, DESIGN, '2.'), DESIGN, 'C\\d\\d', 'contract');
    const l = idRows(section(layout, LAYOUT, '2.'), LAYOUT, 'A\\d\\d', 'layout scenario');
    errors.push(...a.errors, ...c.errors, ...l.errors);

    const aIds = a.rows.map((r) => r.id);
    const lIds = new Set(l.rows.map((r) => r.id));
    for (const id of aIds) if (!lIds.has(id)) errors.push(`${LAYOUT}: scenario ${id} of ${TASKS} §8 has no row in the §2 table`);
    for (const id of lIds) if (!aIds.includes(id)) errors.push(`${LAYOUT}: §2 row ${id} is not a scenario of ${TASKS} §8`);

    const layoutById = new Map();
    const named = [];
    for (const r of l.rows) {
      try {
        const e = parseLayoutRow(r.line, `${LAYOUT}:${r.n}`, codes);
        for (const o of e.owners) if (!tasksById.has(o)) errors.push(`${LAYOUT}:${r.n}: ${r.id}: owner ${o} is not a task in ${TASKS}`);
        named.push(...e.conditional);
        layoutById.set(r.id, e);
      } catch (ex) {
        if (!(ex instanceof SpecError)) throw ex;
        errors.push(ex.message);
      }
    }

    // Contract mapping: "| C01 <title> | A19, A14 | ... |" rows of layout §5.
    const covered = new Map();
    for (const { line, n } of section(layout, LAYOUT, '5.')) {
      const m = /^\| (C\d\d) [^|]*\| ([^|]*) \|/.exec(line);
      if (!m) continue;
      if (covered.has(m[1])) errors.push(`${LAYOUT}:${n}: duplicate contract mapping ${m[1]}`);
      const ids = m[2].split(', ');
      for (const id of ids) if (!aIds.includes(id)) errors.push(`${LAYOUT}:${n}: ${m[1]} is covered by unknown scenario ${id}`);
      covered.set(m[1], ids);
    }
    for (const r of c.rows) if (!covered.has(r.id)) errors.push(`${LAYOUT}: contract ${r.id} has no "Covered by" row in §5`);
    for (const id of covered.keys()) if (!c.rows.some((r) => r.id === id)) errors.push(`${LAYOUT}: §5 maps ${id}, which is not a contract of ${DESIGN} §2`);

    // Hand-authored stage fields from the committed file.
    const oldStages = new Map();
    for (const e of old.scenario ?? []) for (const s of e.stage ?? []) oldStages.set(`${e.id}/${s.milestone}`, s);
    const gates = old.gates_passed ?? [];
    for (const g of gates) if (!MILESTONES.includes(g)) errors.push(`${SCENARIOS}: gates_passed has unknown milestone ${g}`);

    const scenarios = [];
    for (const r of a.rows) {
      const e = layoutById.get(r.id);
      if (!e) continue;
      e.matrix_sha256 = sha256(r.line);
      e.stages = e.stages.map((s) => {
        const prev = oldStages.get(`${e.id}/${s.milestone}`);
        return {
          ...s,
          legs: prev?.legs ?? defaultLegs(e, s, catalogue),
          status: prev?.status ?? 'planned',
          tests: prev?.tests ?? [],
        };
      });
      validStages(e.stages, `${SCENARIOS}: ${e.id}`, errors);
      checkLegs(e, `${SCENARIOS}: ${e.id}`, catalogue, errors);
      scenarios.push(e);
    }
    const contracts = c.rows.map((r) => ({ id: r.id, covered_by: covered.get(r.id) ?? [], matrix_sha256: sha256(r.line) }));

    // Subcases: everything but matrix_sha256 is hand-authored.
    const subs = subDoc.subcase ?? [];
    const byId = new Map(scenarios.map((e) => [e.id, e]));
    const subBlocks = [];
    for (const s of subs) {
      const where = `${SUBCASES}: ${s.id}`;
      const before = errors.length;
      if (!/^A\d\d\.\d\d$/.test(s.id ?? '')) errors.push(`${where}: id must look like A58.07`);
      if (s.parent !== s.id?.slice(0, 3) || !byId.has(s.parent)) errors.push(`${where}: parent must be the registered scenario ${s.id?.slice(0, 3)}`);
      for (const k of ['layers', 'envs', 'harness', 'owners', 'stage']) if (!Array.isArray(s[k]) || !s[k].length) errors.push(`${where}: ${k} must be a non-empty list`);
      for (const k of ['positive', 'negative']) if (typeof s[k] !== 'string' || !s[k]) errors.push(`${where}: ${k} must be a non-empty string`);
      if (s.conditional_on === undefined) {
        if (s.table_text !== undefined) errors.push(`${where}: table_text is only for a conditional sub-ID`);
      } else if (!Object.values(FEATURES).includes(s.conditional_on)) {
        errors.push(`${where}: conditional_on must be one of ${Object.values(FEATURES).join(', ')}`);
      } else {
        const t = typeof s.table_text === 'string' ? parseConditional(s.table_text) : null;
        if (!t) errors.push(`${where}: table_text must be a "Conditional sub-ID ${s.id} (<feature>, Txx.y): ..." sentence`);
        else {
          if (t.id && t.id !== s.id) errors.push(`${where}: table_text names ${t.id}`);
          if (t.feature !== s.conditional_on) errors.push(`${where}: table_text names ${t.feature ?? t.label}, but conditional_on is ${s.conditional_on}`);
          if (Array.isArray(s.owners) && t.task !== s.owners[0]) errors.push(`${where}: table_text names ${t.task}, but the first owner is ${s.owners[0]}`);
        }
      }
      if (errors.length > before) continue;
      for (const o of s.owners) if (!tasksById.has(o)) errors.push(`${where}: owner ${o} is not a task in ${TASKS}`);
      if (!tasksById.has(s.owners[0])) continue;
      const entry = { ...s, stages: s.stage, matrix_sha256: sha256(tasksById.get(s.owners[0])) };
      validStages(entry.stages, where, errors);
      checkLegs(entry, where, catalogue, errors);
      subBlocks.push({ id: s.id, text: subcaseBlock(entry, tasksById.get(s.owners[0])), entry });
    }
    subBlocks.sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
    checkNamedSubcases(named, subs, errors);

    const scenariosToml =
      `${SCENARIOS_HEADER}\n${kv('gates_passed', gates)}\n\n` +
      [...scenarios.map(scenarioBlock), ...contracts.map(contractBlock)].join('\n\n') +
      '\n';
    const subcasesToml = `${SUBCASES_HEADER}\n` + subBlocks.map((b) => b.text).join('\n\n') + '\n';

    // The table must be renderable from the registry (layout §3), with each
    // row's conditional sub-ID sentences taken from subcases.toml.
    for (const r of l.rows) {
      const e = byId.get(r.id);
      if (!e) continue;
      const sentences = subBlocks.filter((b) => b.entry.parent === r.id && b.entry.conditional_on !== undefined).map((b) => b.entry.table_text);
      if (renderLayoutRow(e, codes, sentences) !== r.line) errors.push(`${LAYOUT}:${r.n}: ${r.id}: rendered row differs from the committed row`);
    }

    return {
      files: { [SCENARIOS]: scenariosToml, [SUBCASES]: subcasesToml },
      errors,
      entries: { scenarios, contracts, subcases: subBlocks.map((b) => b.entry) },
      catalogue,
      codes,
    };
  } catch (ex) {
    if (!(ex instanceof SpecError)) throw ex;
    errors.push(ex.message);
    return fail();
  }
}


// Field-level differences between a committed and a regenerated file.
export function describeDiff(path, committed, regenerated) {
  if (committed === null) return [`${path}: missing; run node scripts/ci/gen-conformance-registry.mjs`];
  let oldDoc;
  try {
    oldDoc = parseToml(committed, path);
  } catch (ex) {
    return [ex.message];
  }
  const newDoc = parseToml(regenerated, path);
  const out = [];
  const same = (x, y) => JSON.stringify(x) === JSON.stringify(y);
  if (!same(oldDoc.gates_passed, newDoc.gates_passed)) out.push(`${path}: gates_passed differs`);
  for (const table of ['scenario', 'subcase']) {
    const o = new Map((oldDoc[table] ?? []).map((e) => [e.id, e]));
    const n = new Map((newDoc[table] ?? []).map((e) => [e.id, e]));
    for (const id of n.keys()) if (!o.has(id)) out.push(`${path}: ${id} is missing`);
    for (const id of o.keys()) if (!n.has(id)) out.push(`${path}: ${id} is not in the specs`);
    for (const [id, ne] of n) {
      const oe = o.get(id);
      if (!oe) continue;
      for (const k of new Set([...Object.keys(oe), ...Object.keys(ne)])) {
        if (same(oe[k], ne[k])) continue;
        if (k === 'matrix_sha256') out.push(`${path}: ${id}: matrix_sha256 is ${oe[k]}, but its spec line hashes to ${ne[k]} (spec row changed; review the entry)`);
        else out.push(`${path}: ${id}: ${k} differs from the specs`);
      }
    }
  }
  if (!out.length) {
    const a = committed.split('\n');
    const b = regenerated.split('\n');
    const i = a.findIndex((x, j) => x !== b[j]);
    const at = i < 0 ? a.length : i;
    out.push(`${path}:${at + 1}: formatting differs from generated output (expected ${JSON.stringify(b[at] ?? '<EOF>')})`);
  }
  return out;
}

export function run(argv, log = console.log, logErr = console.error) {
  let root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  let check = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--check') check = true;
    else if (argv[i] === '--root' && argv[i + 1]) root = resolve(argv[++i]);
    else {
      logErr(`usage: gen-conformance-registry.mjs [--root DIR] [--check]`);
      return 2;
    }
  }
  const { files, errors } = generate(root);
  if (errors.length) {
    for (const e of errors) logErr(`error: ${e}`);
    return 1;
  }
  if (check) {
    const problems = [];
    for (const [rel, text] of Object.entries(files)) {
      const committed = readMaybe(root, rel);
      if (committed !== text) problems.push(...describeDiff(rel, committed, text));
    }
    for (const p of problems) logErr(`error: ${p}`);
    if (problems.length) return 1;
    log('conformance registry: up to date');
    return 0;
  }
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
    log(`wrote ${rel}`);
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
