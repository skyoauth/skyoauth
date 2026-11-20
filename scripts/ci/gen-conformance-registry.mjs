#!/usr/bin/env node
// Generates the conformance registry files and the layout §2 scenario table.
//
//   node scripts/ci/gen-conformance-registry.mjs [--root DIR]          # write
//   node scripts/ci/gen-conformance-registry.mjs [--root DIR] --check  # verify
//
// Outputs tests/conformance/scenarios.toml, tests/conformance/subcases.toml
// and the §2 scenario table (with its "Counts by first stage ..." sentences)
// in docs/testing/conformance-layout.md.
//
// Source of truth (layout §2, §3): scenarios.toml is authoritative for every
// scenario column of the §2 table, and subcases.toml for the conditional
// sub-ID sentences; the generator renders the table from them. It never
// parses the table back into the registry.
//
// Derived (rewritten on every run, never edit by hand):
//   - the order of the scenario entries and their matrix_sha256, from the
//     tasks §8 table rows (an ID there without a registry entry, or a registry
//     scenario that is not a row there, is an error);
//   - contract IDs C01..., covered_by and matrix_sha256 from the design §2
//     table rows and the layout doc §5 (Q11) contract table;
//   - subcase matrix_sha256 from the tasks bullet line of the subcase's first
//     owner, and every comment in both files;
//   - the layout §2 table and its counts sentences, rendered from the registry.
// Hand-authored (kept from the committed files):
//   - gates_passed;
//   - every scenario column (layers, envs, harness, owners, note, positive,
//     negative) and every stage field (milestone, scope, legs, status, tests,
//     implemented_sha256). A stage without a legs key gets the provisional
//     default legs computed by defaultLegs(); a missing status is planned and
//     missing tests are [];
//   - every field of a subcase except matrix_sha256.
//
// Checked (hand-authored input is validated; any error exits 1):
//   - every leg is a leg string of the layout §1.1 "Leg strings" column, whose
//     env is one of the entry's envs and whose job exists at the stage's
//     milestone; every env has a leg in some stage;
//   - stage milestones are known and increase; "full row" is the scope of a
//     single-stage entry, and only of one;
//   - an implemented stage lists tests and carries implemented_sha256, the
//     stamp of the (id, milestone, scope, matrix_sha256) it was implemented
//     for (stageStamp()). A changed scope, a moved milestone or a changed
//     spec row therefore never keeps a stage implemented silently: the run
//     fails and writes nothing until a reviewer resets the stage to planned
//     or re-stamps it. Stages are never re-keyed, so a moved stage keeps its
//     tests;
//   - conditional sub-IDs are numbered .90-.99 and are the ones the rendered
//     §2 table names; required sub-IDs lie in the annex range that the
//     parent's note declares (e.g. "A58.01–A58.89");
//   - neither file repeats an ID or a (id, milestone) stage.
//
// matrix_sha256 is the SHA-256 of the UTF-8 bytes of the whole source line,
// from its first character to its last, with no trailing newline.
//
// --check regenerates everything in memory and exits 1 if any output differs
// from the committed file, listing each differing (id, field) or table row.
// Spec and registry errors exit 1 in both modes and write nothing. Usage and
// internal errors exit 2. Needs only Node (>=20); no dependencies. The CI
// check scripts/ci/check-conformance-registry.mjs imports the derive and
// render code below.

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

// Lookup tables without a prototype, so that a key read from a spec or the
// registry (`toString`, `constructor`, `__proto__`) finds nothing it did not list.
const lookup = (entries) => Object.freeze(Object.assign(Object.create(null), entries));

export const LAYERS = lookup({ C: 'conformance', S: 'security', I: 'integration', P: 'package' });
// Feature label in a §2 "Conditional sub-ID (<label>, Txx.y)" sentence ->
// conditional_on value.
export const FEATURES = lookup({ 'device flow': 'device-flow', 'back-channel logout': 'back-channel-logout', ForwardAuth: 'forwardauth' });
// The optional task behind each conditional feature, as the layout §2 rows name
// it (and §5 decision 6 for ForwardAuth).
export const FEATURE_TASK = lookup({ 'device-flow': 'T40.6', 'back-channel-logout': 'T30.6', forwardauth: 'T32.9' });
export const STATUSES = ['planned', 'implemented'];
// A single-stage row shows only its milestone in the table; its stage scope
// is this fixed text (as in the layout §3 A64 example).
export const FULL_ROW = 'full row';
const AUDIT = 'deployed-topology audit';

// First milestone in which each CI job exists (layout §1.1 and the §4 table;
// `typescript` exists already). The jobs and legs themselves come from the
// §1.1 "Leg strings" column; every job there must have an entry here.
export const JOB_FROM = lookup({
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
  'live-wif-push': 'M2',
  'live-wif-negative': 'M2',
});

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
        // A02's live cases are the schedule/dispatch denials (layout §4).
        return entry.id === 'A02' ? ['live-wif-negative'] : ['live-wif-push'];
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

// A value in a diagnostic or a stamp: a string as it is, anything else as JSON.
// Interpolating it directly throws for smol-toml's prototype-less tables.
export const show = (v) => (typeof v === 'string' ? v : (JSON.stringify(v) ?? String(v)));

export class SpecError extends Error {}

// Lines of a "## <n>." section, outside fenced code blocks, with 1-based
// line numbers.
export function section(text, file, prefix) {
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
export function idRows(lines, file, re, what) {
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
  const codes = Object.create(null);
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

const POS = '+ ';
const NEG = '; − '; // U+2212 MINUS SIGN, as in the table
const COND = '. Conditional sub-ID';
const COND_RE = /^Conditional sub-ID(?: (A\d\d\.\d\d))? \(([^,()]+), (T\d\d\.\d+)\): (.+)$/;

// Conditional sub-IDs are numbered .90–.99; required ones .01–.89, inside
// the annex range that the parent's §2 note declares (layout §3, §5 Q1).
export const isConditionalNumber = (id) => Number(id.slice(4)) >= 90;

// The annex range for required sub-IDs that a scenario's note declares, such
// as "A58.01–A58.89" (en dash): { from, to, text }, or null.
export function annexRange(id, note) {
  if (typeof id !== 'string' || (note !== undefined && typeof note !== 'string')) return null;
  const r = new RegExp(`\\b${id}\\.(\\d\\d)–${id}\\.(\\d\\d)\\b`).exec(note ?? '');
  return r ? { from: Number(r[1]), to: Number(r[2]), text: r[0] } : null;
}

// Parses a "Conditional sub-ID [Axx.yy] (<feature>, Txx.y): <text>" sentence.
export function parseConditional(text) {
  const m = COND_RE.exec(text);
  if (!m) return null;
  return { id: m[1] ?? null, label: m[2], feature: FEATURES[m[2]] ?? null, task: m[3] };
}

// The conditional sub-IDs that a layout §2 row names in the trailing
// sentences of its "+ / −" cell, as checkNamedSubcases() takes them. An
// unparsable sentence is returned with feature and task null.
export function rowConditionals(line, id) {
  return (cellsOf(line).at(-1) ?? '')
    .split(COND)
    .slice(1)
    .map((rest) => {
      const text = `Conditional sub-ID${rest}`;
      const c = parseConditional(text) ?? { id: null, label: text, feature: null, task: null };
      return { ...c, parent: id, text };
    });
}

// Renders a scenario entry into its layout §2 table row. `sentences` are the
// table_text values of the row's conditional sub-IDs, in ID order. The entry
// may have the generator's shape (stages) or the registry's (stage).
export function renderLayoutRow(e, codes, sentences = []) {
  const code = (v) => Object.keys(codes).find((k) => codes[k] === v) ?? `?${v}`;
  const st = e.stages ?? e.stage;
  const stages = st.length === 1 && st[0].scope === FULL_ROW ? show(st[0].milestone) : st.map((s) => `${show(s.milestone)}: ${show(s.scope)}`).join(' · ');
  const pm = `${e.note ? `${e.note} ` : ''}${POS}${e.positive}${NEG}${e.negative}${sentences.map((s) => `. ${s}`).join('')}`;
  const cells = [e.id, e.layers.map((l) => Object.keys(LAYERS).find((k) => LAYERS[k] === l)).join('+'), e.envs.map(code).join(', '), e.harness.join(', '), stages, e.owners.join(', '), pm];
  return `| ${cells.join(' | ')} |`;
}

export const TABLE_HEADER = ['| ID | Layer | Env | Harness | Stages | Owners | + / − required |', '| --- | --- | --- | --- | --- | --- | --- |'];

// The layout §2 scenario table (header, separator, rows) rendered from the
// scenario entries in order, each row ending with the table_text of its
// conditional sub-IDs in ID order.
export function renderTable(scenarios, subcases, codes) {
  const id = (s) => show(s.id);
  const sorted = [...subcases].sort((x, y) => (id(x) < id(y) ? -1 : id(x) > id(y) ? 1 : 0));
  const rows = scenarios.map((e) =>
    renderLayoutRow(
      e,
      codes,
      sorted.filter((s) => s.parent === e.id && s.conditional_on !== undefined).map((s) => s.table_text),
    ),
  );
  return [...TABLE_HEADER, ...rows];
}

// Locates the §2 scenario table: { first, lines } with the 1-based line of
// its header and its consecutive "|" lines.
export function findTable(layout) {
  const lines = section(layout, LAYOUT, '2.');
  const h = lines.findIndex((l) => l.line === TABLE_HEADER[0]);
  if (h < 0) throw new SpecError(`${LAYOUT}: layout §2 scenario table header not found (expected "${TABLE_HEADER[0]}")`);
  const out = [];
  for (let i = h; i < lines.length && lines[i].line.startsWith('|') && lines[i].n === lines[h].n + out.length; i++) out.push(lines[i].line);
  return { first: lines[h].n, lines: out };
}

// The mechanical counts sentences after the §2 table: entries per first and
// per final stage milestone, and the number of multi-stage rows.
export function renderCounts(scenarios) {
  const count = (pick) => {
    const n = new Map();
    for (const e of scenarios) {
      const m = pick(e.stages ?? e.stage).milestone;
      n.set(m, (n.get(m) ?? 0) + 1);
    }
    return MILESTONES.filter((m) => n.has(m)).map((m) => `${m} ${n.get(m)}`).join(' · ');
  };
  const multi = scenarios.filter((e) => (e.stages ?? e.stage).length > 1).length;
  return `Counts by first stage: ${count((st) => st[0])}. Counts by final stage: ${count((st) => st[st.length - 1])}. ${multi} rows have more than one stage.`;
}

export const COUNTS_RE = /^Counts by first stage: [^.]*\. Counts by final stage: [^.]*\. \d+ rows have more than one stage\./;

// Locates the counts sentences in §2: { n, text } (1-based line, the matched
// sentences), or null.
export function findCounts(layout) {
  for (const { line, n } of section(layout, LAYOUT, '2.')) {
    const m = COUNTS_RE.exec(line);
    if (m) return { n, text: m[0] };
  }
  return null;
}

// The stamp an implemented stage carries in implemented_sha256: SHA-256 of
// id, milestone, scope and the entry's matrix_sha256, joined by "\n".
export const stageStamp = (id, milestone, scope, matrix) => sha256([id, milestone, scope, matrix].map(show).join('\n'));

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
// basic strings, integers, booleans, arrays and inline tables, plus local
// dates such as a waiver's `expires = 2026-12-31`). Each [[table]] object
// carries its header line in the non-enumerable symbol property LINE. Every
// key, `__proto__` and `constructor` included, is an own property: tables are
// ordinary objects, set with Object.defineProperty and read with Object.hasOwn.

export const LINE = Symbol('line');

// A TOML local date (YYYY-MM-DD). Offset and local date-times and times are
// not part of the subset.
export class LocalDate {
  constructor(text) {
    this.text = text;
  }
  toString() {
    return this.text;
  }
  toJSON() {
    return this.text;
  }
}

const isLeap = (y) => y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
const DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

// True for a calendar date: month 01-12 and a day that exists in that month.
export function validDate(y, m, d) {
  if (m < 1 || m > 12 || d < 1) return false;
  return d <= (m === 2 && isLeap(y) ? 29 : DAYS[m - 1]);
}

export function parseToml(text, file = 'toml') {
  let i = 0;
  let line = 1;
  const root = {};
  let cur = root;
  const err = (msg) => {
    throw new SpecError(`${file}:${line}: ${msg}`);
  };
  // The arrays that [[headers]] create; every other value is final.
  const headerArrays = new WeakSet();
  const own = (obj, k) => (Object.hasOwn(obj, k) ? obj[k] : undefined);
  const unique = (obj, k) => {
    if (Object.hasOwn(obj, k)) err(`duplicate key ${k}`);
  };
  // An own data property even for `__proto__`, which a plain assignment would
  // take as the prototype.
  const set = (obj, k, v) => Object.defineProperty(obj, k, { value: v, writable: true, enumerable: true, configurable: true });
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
            const hex = text.slice(i, i + len);
            if (!new RegExp(`^[0-9A-Fa-f]{${len}}$`).test(hex)) err(`bad \\${e} escape "\\${e}${hex}"`);
            const cp = parseInt(hex, 16);
            if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) err(`\\${e} escape "\\${e}${hex}" is not a Unicode scalar value`);
            s += String.fromCodePoint(cp);
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
        unique(obj, k);
        set(obj, k, value());
        ws(false);
        if (text[i] === ',') i++;
        else if (text[i] === '}') {
          i++;
          return obj;
        } else err('expected "," or "}"');
      }
    }
    const date = /^(\d{4})-(\d{2})-(\d{2})/.exec(text.slice(i, i + 40));
    if (date) {
      // A time part ("T10:00", " 10:00") would make it a date-time.
      if (/^[Tt]|^ \d/.test(text.slice(i + 10, i + 12))) err('only local dates are supported, not date-times');
      if (!validDate(Number(date[1]), Number(date[2]), Number(date[3]))) err(`invalid date ${date[0]}`);
      i += 10;
      return new LocalDate(date[0]);
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
      const header = text.slice(i + 2, end).trim();
      const path = header.split('.');
      i = end + 2;
      // An existing value of a header's key must be an array that headers made.
      const tables = (obj, k) => {
        const a = own(obj, k);
        if (a !== undefined && !headerArrays.has(a)) err(`[[${header}]]: key ${k} already holds a value that is not an array of tables`);
        return a;
      };
      let parent = root;
      for (const p of path.slice(0, -1)) {
        const a = tables(parent, p);
        if (a === undefined) err(`[[${header}]] without a parent`);
        parent = a[a.length - 1];
      }
      const last = path[path.length - 1];
      cur = {};
      // The header's line, for error messages; a symbol, so it never shows up
      // as a field and no key can collide with it.
      Object.defineProperty(cur, LINE, { value: line });
      let a = tables(parent, last);
      if (a === undefined) {
        a = [];
        headerArrays.add(a);
        set(parent, last, a);
      }
      a.push(cur);
    } else {
      const k = key();
      ws(false);
      if (text[i++] !== '=') err('expected "="');
      ws(false);
      unique(cur, k);
      set(cur, k, value());
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
    ...(s.implemented_sha256 === undefined ? [] : [kv('implemented_sha256', s.implemented_sha256)]),
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
# The source of the layout §2 scenario table, which
# scripts/ci/gen-conformance-registry.mjs renders from it; see tests/conformance/README.md.
# Hand-edit gates_passed, the scenario columns and the stages. The generator
# rewrites the entry order, matrix_sha256, the contracts and the comments.
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

// Top-level keys of a committed file: only `keys`, and the table among them
// (the last) an array of tables when present.
function shapeErrors(doc, file, keys) {
  const errors = [];
  for (const k of Object.keys(doc)) if (!keys.includes(k)) errors.push(`${file}: unknown top-level key ${k}`);
  const table = keys[keys.length - 1];
  if (doc[table] !== undefined && !Array.isArray(doc[table])) errors.push(`${file}: ${table} must be an array of tables ([[${table}]])`);
  return errors;
}

// Duplicate IDs and duplicate (id, milestone) stages in a committed file,
// reported before anything is keyed by them.
function duplicateErrors(doc, file, table) {
  const errors = [];
  const ids = new Map();
  for (const e of doc[table] ?? []) {
    if (ids.has(e.id)) errors.push(`${file}:${e[LINE]}: duplicate ${table} ${e.id} (first at line ${ids.get(e.id)})`);
    else ids.set(e.id, e[LINE]);
    const ms = new Map();
    for (const s of Array.isArray(e.stage) ? e.stage : []) {
      if (ms.has(s.milestone)) errors.push(`${file}:${s[LINE]}: duplicate stage ${e.id} ${s.milestone} (first at line ${ms.get(s.milestone)})`);
      else ms.set(s.milestone, s[LINE]);
    }
  }
  return errors;
}

// Type checks of one committed stage; returns true if it added errors.
// `where` is "file:line: id milestone".
function stageErrors(s, where, errors) {
  const before = errors.length;
  const strings = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');
  if (typeof s.milestone !== 'string' || !MILESTONES.includes(s.milestone)) errors.push(`${where}: milestone must be one of ${MILESTONES.join(', ')}`);
  if (typeof s.scope !== 'string' || !s.scope) errors.push(`${where}: scope must be a string`);
  if (!strings(s.legs) || !s.legs.length) errors.push(`${where}: legs must be a non-empty list of strings`);
  else for (const leg of new Set(s.legs.filter((x, i) => s.legs.indexOf(x) !== i))) errors.push(`${where}: legs lists ${leg} twice`);
  if (!STATUSES.includes(s.status)) errors.push(`${where}: status must be planned or implemented`);
  if (!strings(s.tests)) errors.push(`${where}: tests must be a list of strings`);
  return errors.length > before;
}

// 1-based line of the first top-level `key =` in a TOML text (0 if absent).
function lineOfKey(text, key) {
  if (text === null) return 0;
  const i = text.split('\n').findIndex((l) => new RegExp(`^${key}\\s*=`).test(l));
  return i + 1;
}

const SCENARIO_KEYS = ['id', 'kind', 'layers', 'envs', 'harness', 'owners', 'note', 'positive', 'negative', 'matrix_sha256', 'stage'];
const STAGE_KEYS = ['milestone', 'scope', 'legs', 'status', 'implemented_sha256', 'tests'];
// Text rendered into a §2 table cell: non-empty, no "|" or line break.
const isCell = (v) => typeof v === 'string' && v !== '' && !/[|\n]/.test(v);
const isCells = (v) => Array.isArray(v) && v.length > 0 && v.every(isCell);

// The hand-authored §2 columns of a scenario entry; true if they are valid.
function validScenario(s, where, codes, tasksById, errors) {
  const before = errors.length;
  for (const k of Object.keys(s)) if (!SCENARIO_KEYS.includes(k)) errors.push(`${where}: unknown field ${k}`);
  for (const k of ['layers', 'envs', 'harness', 'owners']) if (!isCells(s[k])) errors.push(`${where}: ${k} must be a non-empty list of table text`);
  for (const k of ['positive', 'negative']) if (!isCell(s[k])) errors.push(`${where}: ${k} must be non-empty table text`);
  if (s.note !== undefined && !isCell(s.note)) errors.push(`${where}: note must be non-empty table text when present`);
  if (!Array.isArray(s.stage) || !s.stage.length) errors.push(`${where}: needs at least one [[scenario.stage]]`);
  if (errors.length > before) return false;
  for (const x of s.layers) if (!Object.values(LAYERS).includes(x)) errors.push(`${where}: unknown layer "${x}"`);
  for (const x of s.envs) if (!Object.values(codes).includes(x)) errors.push(`${where}: unknown env "${x}"`);
  for (const o of s.owners) if (!tasksById.has(o)) errors.push(`${where}: owner ${o} is not a task in ${TASKS}`);
  const r = annexRange(s.id, s.note);
  if (r && (r.from < 1 || r.to > 89 || r.from > r.to)) errors.push(`${where}: annex range ${r.text} must lie within ${s.id}.01–${s.id}.89`);
  return errors.length === before;
}

// Checks of a scenario's or subcase's type-checked stages, in order. `e` has
// its derived matrix_sha256; `at(s)` is "file:line: id milestone".
function validStages(e, at, errors) {
  const n = e.stages.length;
  e.stages.forEach((s, i) => {
    const prev = e.stages[i - 1];
    if (prev && mIndex(s.milestone) <= mIndex(prev.milestone)) errors.push(`${at(s)}: stage ${s.milestone} comes after ${prev.milestone}; stage milestones must increase`);
    for (const k of Object.keys(s)) if (!STAGE_KEYS.includes(k)) errors.push(`${at(s)}: unknown stage field ${k}`);
    if ((s.scope === FULL_ROW) !== (n === 1)) errors.push(`${at(s)}: scope "${FULL_ROW}" is the scope of a single-stage entry, and only of one`);
    else if (/[|\n]/.test(s.scope)) errors.push(`${at(s)}: scope must be table text (no "|" or line break)`);
    if (s.status === 'implemented') {
      if (!s.tests.length) errors.push(`${at(s)}: an implemented stage must list its tests`);
      const want = stageStamp(e.id, s.milestone, s.scope, e.matrix_sha256);
      if (s.implemented_sha256 !== want) {
        errors.push(
          `${at(s)}: implemented_sha256 is ${s.implemented_sha256 ?? 'missing'}, but this stage's (id, milestone, scope, matrix_sha256) stamps to ${want}. ` +
            'The stage changed since it was marked implemented: review it, then set status = "planned" or re-stamp it',
        );
      }
    } else if (s.implemented_sha256 !== undefined) errors.push(`${at(s)}: implemented_sha256 is only for an implemented stage`);
  });
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
// unnumbered one must match exactly one entry by those three; every
// conditional entry must be named. Required sub-IDs need not be named (their
// annex range is checked in generate()).
export function checkNamedSubcases(named, subs, errors) {
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
    if (s.parent !== n.parent) errors.push(`${SUBCASES}: ${s.id}: parent is ${show(s.parent)}, but the layout doc names it under ${n.parent}`);
    if (s.conditional_on !== n.feature) errors.push(`${SUBCASES}: ${s.id}: conditional_on is ${show(s.conditional_on)}, but the layout doc names ${n.feature}`);
    if (s.owners?.[0] !== n.task) errors.push(`${SUBCASES}: ${s.id}: first owner is ${show(s.owners?.[0])}, but the layout doc names ${n.task}`);
  }
  for (const n of named.filter((x) => !x.id)) {
    const c = subs.filter((s) => !matched.has(s) && !explicit.has(s.id) && s.parent === n.parent && s.conditional_on === n.feature && s.owners?.[0] === n.task);
    if (c.length === 1) matched.add(c[0]);
    else if (!c.length) errors.push(`${desc(n)} but missing from ${SUBCASES}`);
    else errors.push(`${desc(n)} without an ID, but ${c.map((s) => show(s.id)).join(' and ')} all match it`);
  }
  for (const s of subs) {
    if (!matched.has(s) && s.conditional_on !== undefined) errors.push(`${SUBCASES}: ${show(s.id)} is a conditional sub-ID not named in ${LAYOUT} §2`);
  }
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
    // scenarios.toml is the source of the scenario columns, so it must exist.
    const oldScenarios = read(SCENARIOS);
    const old = parseToml(oldScenarios, SCENARIOS);
    const subText = readMaybe(root, SUBCASES);
    const subDoc = subText === null ? {} : parseToml(subText, SUBCASES);
    const shape = [...shapeErrors(old, SCENARIOS, ['gates_passed', 'scenario']), ...shapeErrors(subDoc, SUBCASES, ['subcase'])];
    if (shape.length) {
      errors.push(...shape);
      return fail({ catalogue });
    }
    const dups = [...duplicateErrors(old, SCENARIOS, 'scenario'), ...duplicateErrors(subDoc, SUBCASES, 'subcase')];
    if (dups.length) {
      errors.push(...dups);
      return fail({ catalogue });
    }

    const a = idRows(section(tasks, TASKS, '8.'), TASKS, 'A\\d\\d', 'scenario');
    const c = idRows(section(design, DESIGN, '2.'), DESIGN, 'C\\d\\d', 'contract');
    errors.push(...a.errors, ...c.errors);
    const aIds = a.rows.map((r) => r.id);
    const table = findTable(layout);
    const counts = findCounts(layout);
    if (!counts) errors.push(`${LAYOUT}: the "Counts by first stage: ... rows have more than one stage." sentences after the §2 table are missing`);

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

    let gates = old.gates_passed ?? [];
    const gatesAt = `${SCENARIOS}:${lineOfKey(oldScenarios, 'gates_passed')}`;
    if (!Array.isArray(gates) || !gates.every((g) => typeof g === 'string')) {
      errors.push(`${gatesAt}: gates_passed must be a list of milestones`);
      gates = [];
    }
    for (const g of gates) if (!MILESTONES.includes(g)) errors.push(`${gatesAt}: gates_passed has unknown milestone ${g}`);
    for (const g of new Set(gates.filter((g, i) => gates.indexOf(g) !== i))) errors.push(`${gatesAt}: gates_passed lists ${g} twice`);

    // Scenarios: the tasks §8 rows give the IDs, their order and matrix_sha256;
    // everything else comes from the registry entry. Stages are taken as they
    // are, never re-keyed, so a stage that moves milestone keeps its tests.
    const registered = new Map();
    for (const e of old.scenario ?? []) {
      if (e.kind === 'scenario') registered.set(e.id, e);
      else if (e.kind !== 'contract') errors.push(`${SCENARIOS}:${e[LINE]}: ${e.id}: kind must be scenario or contract`);
    }
    for (const [id, e] of registered) if (!aIds.includes(id)) errors.push(`${SCENARIOS}:${e[LINE]}: scenario ${id} is not a row of ${TASKS} §8`);
    const scenarios = [];
    for (const r of a.rows) {
      const s = registered.get(r.id);
      if (!s) {
        errors.push(`${TASKS}:${r.n}: scenario ${r.id} has no [[scenario]] entry in ${SCENARIOS}; add one with its layout §2 columns and stages`);
        continue;
      }
      const where = `${SCENARIOS}:${s[LINE]}: ${r.id}`;
      if (!validScenario(s, where, codes, tasksById, errors)) continue;
      const e = { id: r.id, layers: s.layers, envs: s.envs, harness: s.harness, owners: s.owners, note: s.note, positive: s.positive, negative: s.negative, matrix_sha256: sha256(r.line) };
      const at = (st) => `${SCENARIOS}:${st[LINE]}: ${r.id} ${st.milestone}`;
      const before = errors.length;
      e.stages = s.stage.map((st) => {
        const full = { ...st, legs: st.legs ?? defaultLegs(e, st, catalogue), status: st.status ?? 'planned', tests: st.tests ?? [] };
        Object.defineProperty(full, LINE, { value: st[LINE] });
        stageErrors(full, at(full), errors);
        if (st.implemented_sha256 !== undefined && typeof st.implemented_sha256 !== 'string') errors.push(`${at(full)}: implemented_sha256 must be a string`);
        return full;
      });
      if (errors.length > before) continue;
      validStages(e, at, errors);
      checkLegs(e, where, catalogue, errors);
      if (errors.length === before) scenarios.push(e);
    }
    const contracts = c.rows.map((r) => ({ id: r.id, covered_by: covered.get(r.id) ?? [], matrix_sha256: sha256(r.line) }));

    // Subcases: everything but matrix_sha256 is hand-authored.
    const subs = subDoc.subcase ?? [];
    const byId = new Map([...registered].filter(([id]) => aIds.includes(id)));
    const subBlocks = [];
    for (const s of subs) {
      const where = `${SUBCASES}:${s[LINE]}: ${s.id}`;
      const before = errors.length;
      if (typeof s.id !== 'string' || !/^A\d\d\.\d\d$/.test(s.id)) errors.push(`${where}: id must look like A58.07`);
      else if (s.parent !== s.id.slice(0, 3) || !byId.has(s.parent)) errors.push(`${where}: parent must be the registered scenario ${s.id.slice(0, 3)}`);
      for (const k of ['layers', 'envs', 'harness', 'owners']) {
        if (!Array.isArray(s[k]) || !s[k].length || !s[k].every((x) => typeof x === 'string' && x)) errors.push(`${where}: ${k} must be a non-empty list of strings`);
      }
      if (!Array.isArray(s.stage) || !s.stage.length) errors.push(`${where}: needs at least one [[subcase.stage]]`);
      for (const k of ['positive', 'negative']) if (typeof s[k] !== 'string' || !s[k]) errors.push(`${where}: ${k} must be a non-empty string`);
      if (errors.length > before) continue;
      for (const x of s.layers) if (!Object.values(LAYERS).includes(x)) errors.push(`${where}: unknown layer "${x}"`);
      for (const x of s.envs) if (!Object.values(codes).includes(x)) errors.push(`${where}: unknown env "${x}"`);
      const stageAt = (st) => `${SUBCASES}:${st[LINE]}: ${s.id} ${st.milestone}`;
      for (const st of s.stage) {
        stageErrors(st, stageAt(st), errors);
        if (st.implemented_sha256 !== undefined && typeof st.implemented_sha256 !== 'string') errors.push(`${stageAt(st)}: implemented_sha256 must be a string`);
      }
      const parent = byId.get(s.parent);
      if (s.conditional_on === undefined) {
        if (s.table_text !== undefined) errors.push(`${where}: table_text is only for a conditional sub-ID`);
        const n = Number(s.id.slice(4));
        const r = annexRange(s.parent, parent?.note);
        if (!r) errors.push(`${where}: required sub-ID, but layout §2 row ${s.parent} declares no annex range`);
        else if (n < r.from || n > r.to) {
          const fmt = (x) => `${s.parent}.${String(x).padStart(2, '0')}`;
          errors.push(`${where}: required sub-ID is outside the annex range ${fmt(r.from)}–${fmt(r.to)} that layout §2 row ${s.parent} declares`);
        }
      } else if (!isConditionalNumber(s.id)) {
        errors.push(`${where}: conditional sub-ID ${s.id} must be numbered ${s.parent}.90–${s.parent}.99`);
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
      validStages(entry, stageAt, errors);
      checkLegs(entry, where, catalogue, errors);
      subBlocks.push({ id: s.id, text: subcaseBlock(entry, tasksById.get(s.owners[0])), entry });
    }
    subBlocks.sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
    const subEntries = subBlocks.map((b) => b.entry);

    // The §2 table and its counts are rendered from the registry (layout §2,
    // §3). Every conditional sub-ID is one that the rendered table names.
    const rendered = renderTable(scenarios, subEntries, codes);
    checkNamedSubcases(
      rendered.slice(TABLE_HEADER.length).flatMap((line) => rowConditionals(line, line.slice(2, 5))),
      subs,
      errors,
    );
    const lines = layout.split('\n');
    if (counts) lines[counts.n - 1] = renderCounts(scenarios) + lines[counts.n - 1].slice(counts.text.length);
    lines.splice(table.first - 1, table.lines.length, ...rendered);

    const scenariosToml =
      `${SCENARIOS_HEADER}\n${kv('gates_passed', gates)}\n\n` +
      [...scenarios.map(scenarioBlock), ...contracts.map(contractBlock)].join('\n\n') +
      '\n';
    const subcasesToml = `${SUBCASES_HEADER}\n` + subBlocks.map((b) => b.text).join('\n\n') + '\n';

    return {
      files: { [SCENARIOS]: scenariosToml, [SUBCASES]: subcasesToml, [LAYOUT]: lines.join('\n') },
      errors,
      entries: { scenarios, contracts, subcases: subEntries },
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
  if (path === LAYOUT) {
    const a = committed.split('\n');
    const b = regenerated.split('\n');
    const out = [];
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if (a[i] === b[i]) continue;
      const row = /^\| (A\d\d) \|/.exec(b[i] ?? '') ?? /^\| (A\d\d) \|/.exec(a[i] ?? '');
      const what = row ? `§2 row ${row[1]}` : COUNTS_RE.test(b[i] ?? '') ? 'the §2 counts sentences' : 'line';
      out.push(`${path}:${i + 1}: ${what} differs from the table rendered from the registry; run node scripts/ci/gen-conformance-registry.mjs`);
    }
    return out;
  }
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
    if (readMaybe(root, rel) === text) continue;
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
