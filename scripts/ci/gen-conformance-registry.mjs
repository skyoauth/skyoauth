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
//   - layers, envs, env_notes, harness, owners, positive, negative,
//     pos_neg_prefix, pos_neg_suffix and each stage's milestone and scope
//     from the scenario table in docs/testing/conformance-layout.md §2;
//   - contract covered_by from the contract table in the layout doc §5 (Q11);
//   - subcase matrix_sha256 from the tasks bullet line of the subcase's first
//     owner, and every comment in both files.
// Hand-authored (kept from the committed files):
//   - gates_passed;
//   - each stage's legs, status and tests, keyed by (id, milestone). A stage
//     with no committed legs gets the default legs computed by defaultLegs();
//   - every field of a subcase except matrix_sha256.
//
// matrix_sha256 is the SHA-256 of the UTF-8 bytes of the whole source line,
// from its first character to its last, with no trailing newline.
//
// --check regenerates both files in memory and exits 1 if either differs from
// the committed file, listing each differing (id, field). It also checks that
// the layout §2 table rendered back from the registry equals the committed
// table, so every table column stays representable in the registry.
// Spec errors (missing, duplicate or unparsable rows, unknown owners or legs)
// exit 1 in both modes and write nothing. Usage and internal errors exit 2.
// Needs only Node (>=20); no dependencies.

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
const ENVS = { H: 'hermetic', PG: 'pg', EK: 'envoy-k3s', BR: 'browser', N3: 'native-3os', LV: 'live' };
const CONDITIONAL_ON = ['device-flow', 'back-channel-logout', 'forwardauth'];
const STATUSES = ['planned', 'implemented'];
// A single-stage row shows only its milestone in the table; its stage scope
// is this fixed text (as in the layout §3 A64 example).
const FULL_ROW = 'full row';

// CI jobs and legs of the layout doc §1.1. `env` is the environment the job
// belongs to, `from` the first milestone in which the job exists (§1.1 and
// the §4 table; `typescript` exists already). A job that §1.1 lists without
// legs has the single leg named by the bare job name.
export const JOBS = {
  'scenarios-hermetic': { env: 'hermetic', from: 'M1a', legs: ['x86_64', 'aarch64'] },
  'clients-rust': { env: 'hermetic', from: 'M2', legs: ['x86_64'] },
  typescript: { env: 'hermetic', from: 'M0', legs: ['node22', 'node24'] },
  'bundle-check': { env: 'hermetic', from: 'M3', legs: [] },
  'scenarios-pg': { env: 'pg', from: 'M1a', legs: ['x86_64'] },
  'scenarios-envoy-k3s': { env: 'envoy-k3s', from: 'M2', legs: ['x86_64'] },
  'scenarios-envoy-k3s-nightly': { env: 'envoy-k3s', from: 'M2', legs: [] },
  'migration-rehearsal': { env: 'envoy-k3s', from: 'M5', legs: [] },
  'typescript-browser': { env: 'browser', from: 'M3', legs: ['chromium', 'firefox', 'webkit'] },
  operator: { env: 'native-3os', from: 'M1a', legs: ['ubuntu', 'macos', 'windows'] },
  'recovery-offline': { env: 'native-3os', from: 'M1a', legs: ['ubuntu', 'macos', 'windows'] },
  'clients-rust-native': { env: 'native-3os', from: 'M4', legs: ['ubuntu', 'macos', 'windows'] },
  'live-wif': { env: 'live', from: 'M2', legs: [] },
};

export function legNames(job) {
  const j = JOBS[job];
  return j.legs.length ? j.legs.map((l) => `${job}/${l}`) : [job];
}

export const KNOWN_LEGS = new Map(Object.keys(JOBS).flatMap((job) => legNames(job).map((leg) => [leg, job])));

const mIndex = (m) => MILESTONES.indexOf(m);

// Default legs for a stage that has none committed yet. For each env of the
// row, the env's default jobs that exist at the stage's milestone; an env
// with no such job is left out of that stage. The per-scenario choices below
// follow the Harness column and layout §1.1/§5 Q6; everything else uses the
// env's default job.
export function defaultLegs(entry, milestone) {
  const jobsFor = (env) => {
    switch (env) {
      case 'hermetic':
        if (entry.id === 'A39') return ['typescript', 'bundle-check']; // npm pack, bundle check, typecheck
        if (entry.id === 'A40') return ['typescript']; // vitest fetch spy
        return ['scenarios-hermetic'];
      case 'pg':
        return ['scenarios-pg'];
      case 'envoy-k3s':
        if (milestone === 'M5') return ['migration-rehearsal'];
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
        throw new Error(`no default job for env ${env}`);
    }
  };
  const legs = [];
  for (const env of entry.envs) {
    for (const job of jobsFor(env)) {
      if (mIndex(JOBS[job].from) > mIndex(milestone)) continue;
      let names = legNames(job);
      if (env === 'native-3os' && entry.env_notes?.[env] === 'Linux leg') names = names.filter((n) => n.endsWith('/ubuntu'));
      legs.push(...names);
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

// Parses one row of the layout §2 scenario table.
export function parseLayoutRow(line, where) {
  const cells = cellsOf(line);
  if (cells.length !== 7) throw new SpecError(`${where}: expected 7 cells, found ${cells.length}`);
  const [id, layer, env, harness, stages, owners, pm] = cells;
  const fail = (msg) => {
    throw new SpecError(`${where}: ${id}: ${msg}`);
  };
  const entry = { id };
  entry.layers = layer.split('+').map((c) => LAYERS[c] ?? fail(`unknown layer code "${c}"`));
  entry.envs = [];
  entry.env_notes = {};
  for (const item of splitTop(env, ', ')) {
    const m = /^([A-Z0-9]+)(?: \(([^()]+)\))?$/.exec(item);
    if (!m || !ENVS[m[1]]) fail(`unknown env "${item}"`);
    entry.envs.push(ENVS[m[1]]);
    if (m[2]) entry.env_notes[ENVS[m[1]]] = m[2];
  }
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
  const p = pm.startsWith(POS) ? 0 : Math.max(pm.indexOf(`: ${POS}`) + 2, pm.indexOf(`. ${POS}`) + 2);
  if (p < 2 && p !== 0) fail('"+ / −" cell has no "+ " part');
  entry.pos_neg_prefix = pm.slice(0, p);
  let rest = pm.slice(p + POS.length);
  const c = rest.lastIndexOf(COND);
  entry.pos_neg_suffix = c >= 0 ? rest.slice(c) : '';
  if (c >= 0) rest = rest.slice(0, c);
  const parts = splitTop(rest, NEG);
  if (parts.length !== 2) fail(`"+ / −" cell must contain exactly one "${NEG}", found ${parts.length - 1}`);
  [entry.positive, entry.negative] = parts;
  if (renderLayoutRow(entry) !== line) fail('row does not round-trip through the registry fields');
  return entry;
}

const CODE = (map, v) => Object.keys(map).find((k) => map[k] === v);

// Renders a scenario entry back into its layout §2 table row.
export function renderLayoutRow(e) {
  const env = e.envs.map((v) => CODE(ENVS, v) + (e.env_notes?.[v] ? ` (${e.env_notes[v]})` : '')).join(', ');
  const stages =
    e.stages.length === 1 && e.stages[0].scope === FULL_ROW
      ? e.stages[0].milestone
      : e.stages.map((s) => `${s.milestone}: ${s.scope}`).join(' · ');
  const pm = `${e.pos_neg_prefix ?? ''}${POS}${e.positive}${NEG}${e.negative}${e.pos_neg_suffix ?? ''}`;
  const cells = [e.id, e.layers.map((l) => CODE(LAYERS, l)).join('+'), env, e.harness.join(', '), stages, e.owners.join(', '), pm];
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
// basic strings, integers, booleans, arrays and inline tables).

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
      (parent[last] ??= []).push((cur = {}));
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
  if (v && typeof v === 'object') {
    return `${k} = { ${Object.entries(v)
      .map(([a, b]) => `${/^[A-Za-z0-9_-]+$/.test(a) ? a : q(a)} = ${q(b)}`)
      .join(', ')} }`;
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
  if (Object.keys(e.env_notes).length) out.push(kv('env_notes', e.env_notes));
  out.push(kv('harness', e.harness), kv('owners', e.owners), kv('positive', e.positive), kv('negative', e.negative));
  if (e.pos_neg_prefix) out.push(kv('pos_neg_prefix', e.pos_neg_prefix));
  if (e.pos_neg_suffix) out.push(kv('pos_neg_suffix', e.pos_neg_suffix));
  out.push(kv('matrix_sha256', e.matrix_sha256));
  return [out.join('\n'), ...e.stages.map((s) => stageBlock('scenario', s))].join('\n\n');
}

function contractBlock(c) {
  return ['[[scenario]]', kv('id', c.id), kv('kind', 'contract'), kv('covered_by', c.covered_by), kv('matrix_sha256', c.matrix_sha256)].join('\n');
}

function subcaseBlock(e, sourceLine) {
  const out = [
    '[[subcase]]',
    kv('id', e.id),
    kv('kind', 'subcase'),
    kv('parent', e.parent),
  ];
  if (e.conditional_on !== undefined) out.push(kv('conditional_on', e.conditional_on));
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

function validStages(stages, where, errors) {
  for (const s of stages) {
    if (!MILESTONES.includes(s.milestone)) errors.push(`${where}: unknown stage milestone ${s.milestone}`);
    if (!STATUSES.includes(s.status)) errors.push(`${where} ${s.milestone}: status must be planned or implemented`);
    if (!Array.isArray(s.legs) || !s.legs.length) errors.push(`${where} ${s.milestone}: stage has no legs`);
  }
}

// Leg checks of layout §3: legs are known, each leg's job belongs to one of
// the entry's envs, each env has a leg in some stage.
function checkLegs(e, where, errors) {
  const used = new Set();
  for (const s of e.stages) {
    for (const leg of s.legs ?? []) {
      const job = KNOWN_LEGS.get(leg);
      if (!job) errors.push(`${where} ${s.milestone}: unknown leg "${leg}" (not in layout §1.1)`);
      else if (!e.envs.includes(JOBS[job].env)) errors.push(`${where} ${s.milestone}: leg "${leg}" belongs to env ${JOBS[job].env}, not in envs`);
      else if (mIndex(JOBS[job].from) > mIndex(s.milestone)) errors.push(`${where} ${s.milestone}: job ${job} exists only from ${JOBS[job].from}`);
      else used.add(JOBS[job].env);
    }
  }
  for (const env of e.envs) if (!used.has(env)) errors.push(`${where}: env ${env} has no leg in any stage`);
}

// Returns { files: { [path]: text }, errors: string[], entries }.
export function generate(root) {
  const errors = [];
  const read = (rel) => {
    const t = readMaybe(root, rel);
    if (t === null) throw new SpecError(`${rel}: not found`);
    return t;
  };
  try {
    const tasks = read(TASKS);
    const design = read(DESIGN);
    const layout = read(LAYOUT);
    const tasksById = taskLines(tasks);

    const a = idRows(section(tasks, TASKS, '8.'), TASKS, 'A\\d\\d', 'scenario');
    const c = idRows(section(design, DESIGN, '2.'), DESIGN, 'C\\d\\d', 'contract');
    const l = idRows(section(layout, LAYOUT, '2.'), LAYOUT, 'A\\d\\d', 'layout scenario');
    errors.push(...a.errors, ...c.errors, ...l.errors);

    const aIds = a.rows.map((r) => r.id);
    const lIds = new Set(l.rows.map((r) => r.id));
    for (const id of aIds) if (!lIds.has(id)) errors.push(`${LAYOUT}: scenario ${id} of ${TASKS} §8 has no row in the §2 table`);
    for (const id of lIds) if (!aIds.includes(id)) errors.push(`${LAYOUT}: §2 row ${id} is not a scenario of ${TASKS} §8`);

    const layoutById = new Map();
    for (const r of l.rows) {
      try {
        const e = parseLayoutRow(r.line, `${LAYOUT}:${r.n}`);
        for (const o of e.owners) if (!tasksById.has(o)) errors.push(`${LAYOUT}:${r.n}: ${r.id}: owner ${o} is not a task in ${TASKS}`);
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

    // Hand-authored fields from the committed files.
    const oldScenarios = readMaybe(root, SCENARIOS);
    const old = oldScenarios === null ? {} : parseToml(oldScenarios, SCENARIOS);
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
          legs: prev?.legs ?? defaultLegs(e, s.milestone),
          status: prev?.status ?? 'planned',
          tests: prev?.tests ?? [],
        };
      });
      validStages(e.stages, `${SCENARIOS}: ${e.id}`, errors);
      checkLegs(e, `${SCENARIOS}: ${e.id}`, errors);
      scenarios.push(e);
    }
    const contracts = c.rows.map((r) => ({ id: r.id, covered_by: covered.get(r.id) ?? [], matrix_sha256: sha256(r.line) }));

    // Subcases: everything but matrix_sha256 is hand-authored.
    const subText = readMaybe(root, SUBCASES);
    const subs = subText === null ? [] : (parseToml(subText, SUBCASES).subcase ?? []);
    const byId = new Map(scenarios.map((e) => [e.id, e]));
    const subBlocks = [];
    const seenSub = new Set();
    for (const s of subs) {
      const where = `${SUBCASES}: ${s.id}`;
      const before = errors.length;
      if (!/^A\d\d\.\d\d$/.test(s.id ?? '')) errors.push(`${where}: id must look like A58.07`);
      if (seenSub.has(s.id)) errors.push(`${where}: duplicate subcase`);
      seenSub.add(s.id);
      if (s.parent !== s.id?.slice(0, 3) || !byId.has(s.parent)) errors.push(`${where}: parent must be the registered scenario ${s.id?.slice(0, 3)}`);
      if (s.conditional_on !== undefined && !CONDITIONAL_ON.includes(s.conditional_on)) errors.push(`${where}: conditional_on must be one of ${CONDITIONAL_ON.join(', ')}`);
      for (const k of ['layers', 'envs', 'harness', 'owners', 'stage']) if (!Array.isArray(s[k]) || !s[k].length) errors.push(`${where}: ${k} must be a non-empty list`);
      for (const k of ['positive', 'negative']) if (typeof s[k] !== 'string' || !s[k]) errors.push(`${where}: ${k} must be a non-empty string`);
      if (errors.length > before) continue;
      for (const o of s.owners) if (!tasksById.has(o)) errors.push(`${where}: owner ${o} is not a task in ${TASKS}`);
      if (!tasksById.has(s.owners[0])) continue;
      const entry = { ...s, stages: s.stage, matrix_sha256: sha256(tasksById.get(s.owners[0])) };
      validStages(entry.stages, where, errors);
      checkLegs(entry, where, errors);
      subBlocks.push({ id: s.id, text: subcaseBlock(entry, tasksById.get(s.owners[0])), entry });
    }
    subBlocks.sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));

    const scenariosToml =
      `${SCENARIOS_HEADER}\n${kv('gates_passed', gates)}\n\n` +
      [...scenarios.map(scenarioBlock), ...contracts.map(contractBlock)].join('\n\n') +
      '\n';
    const subcasesToml = `${SUBCASES_HEADER}\n` + subBlocks.map((b) => b.text).join('\n\n') + '\n';

    // The table must be renderable from the registry (layout §3).
    for (const r of l.rows) {
      const e = byId.get(r.id);
      if (e && renderLayoutRow(e) !== r.line) errors.push(`${LAYOUT}:${r.n}: ${r.id}: rendered row differs from the committed row`);
    }

    return {
      files: { [SCENARIOS]: scenariosToml, [SUBCASES]: subcasesToml },
      errors,
      entries: { scenarios, contracts, subcases: subBlocks.map((b) => b.entry) },
    };
  } catch (ex) {
    if (!(ex instanceof SpecError)) throw ex;
    return { files: null, errors: [...errors, ex.message], entries: null };
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
