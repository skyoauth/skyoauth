// Self-test for check-conformance-registry.mjs:
//   node --test scripts/ci/check-conformance-registry.test.mjs
//
// Each case copies the three specs and the two registry files into a
// temporary root, changes one thing, and runs the check there. Every rule has
// a passing case (the repository itself, or a valid edit) and failing ones.
// Waiver cases build a throwaway git repository with a local
// refs/remotes/origin/main; nothing touches the network. The repository
// itself is only read.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { parse as parseStrict, TomlDate } from 'smol-toml';

import { checkRegistry, FIXTURES, formatError, history, locate, plain, run, SCHEMAS, WAIVERS } from './check-conformance-registry.mjs';
import { DESIGN, FEATURES, JOB_FROM, LAYOUT, LocalDate, parseConditional, parseToml, run as generateRun, SCENARIOS, sha256, stageStamp, SUBCASES, TASKS } from './gen-conformance-registry.mjs';
import { normaliseRegistry, valueSwaps } from './registry-fixtures.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'check-conformance-registry.mjs');
const REPO = join(dirname(SCRIPT), '..', '..');
const FILES = [TASKS, DESIGN, LAYOUT, SCENARIOS, SUBCASES];

const roots = [];
after(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

const rawRepoText = (rel) => readFileSync(join(REPO, rel), 'utf8');
// Fixtures start from the registry with every stage planned and no gate
// passed (registry-fixtures.mjs), however far the real registry has got.
const repoText = (rel) => (rel === SCENARIOS || rel === SUBCASES ? normaliseRegistry(rawRepoText(rel)) : rawRepoText(rel));

// A temporary root holding copies of FILES. `edits` maps a file to a function
// of its text (null drops the file); `extra` maps more files to their text.
function fixture(edits = {}, extra = {}) {
  const root = mkdtempSync(join(tmpdir(), 'check-registry-'));
  roots.push(root);
  const files = { ...Object.fromEntries(FILES.map((rel) => [rel, (edits[rel] ?? ((t) => t))(repoText(rel))])), ...extra };
  for (const [rel, text] of Object.entries(files)) {
    if (text === null) continue;
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

const check = (root, opts) => checkRegistry(root, opts);
const read = (root, rel) => readFileSync(join(root, rel), 'utf8');
const dump = (res) => res.errors.map(formatError).join('\n') || '(no errors)';

function expectOk(res) {
  assert.deepEqual(res.errors.map(formatError), []);
}

// Some error has `rule` and its formatted text matches `re`.
function expectError(res, rule, re) {
  assert.ok(
    res.errors.some((e) => e.rule === rule && re.test(formatError(e))),
    `no [${rule}] error matching ${re}; got:\n${dump(res)}`,
  );
}

// The only error is the one described.
function expectOnly(res, rule, re) {
  assert.equal(res.errors.length, 1, dump(res));
  expectError(res, rule, re);
}

function replaceOnce(text, from, to) {
  const i = text.indexOf(from);
  assert.ok(i >= 0, `fixture text not found: ${from}`);
  assert.equal(text.indexOf(from, i + 1), -1, `fixture text not unique: ${from}`);
  return text.slice(0, i) + to + text.slice(i + from.length);
}

// 1-based line of `needle`, searching from the first occurrence of `from`.
function lineOf(text, needle, from = '') {
  const start = text.indexOf(from);
  assert.ok(start >= 0, `not found: ${from}`);
  const i = text.indexOf(needle, start);
  assert.ok(i >= 0, `not found: ${needle}`);
  return text.slice(0, i).split('\n').length;
}

const head = (table, id) => `[[${table}]]\nid = "${id}"`;
const entryLine = (text, table, id) => lineOf(text, head(table, id));
const stageLine = (text, table, id, m) => lineOf(text, `[[${table}.stage]]\nmilestone = "${m}"`, head(table, id));
const specLine = (text, id) => lineOf(text, `| ${id} |`);

// The block of entry `id`, from its header to the next entry header.
function entryBlock(text, table, id) {
  const start = text.indexOf(head(table, id));
  assert.ok(start >= 0, `no ${table} ${id}`);
  const next = text.indexOf(`[[${table}]]\n`, start + 1);
  return text.slice(start, next < 0 ? text.length : next);
}

// Replaces `from` with `to` once inside entry `id`, or inside its stage `m`.
function editEntry(text, table, id, from, to) {
  const block = entryBlock(text, table, id);
  return replaceOnce(text, block, replaceOnce(block, from, to));
}
function editStage(text, table, id, m, from, to) {
  const block = entryBlock(text, table, id);
  const at = block.indexOf(`[[${table}.stage]]\nmilestone = "${m}"`);
  assert.ok(at >= 0, `no stage ${m} of ${id}`);
  const next = block.indexOf(`[[${table}.stage]]`, at + 1);
  const end = next < 0 ? block.length : next;
  return replaceOnce(text, block, block.slice(0, at) + replaceOnce(block.slice(at, end), from, to) + block.slice(end));
}
const sc = (id, from, to) => (t) => editEntry(t, 'scenario', id, from, to);
const st = (id, m, from, to) => (t) => editStage(t, 'scenario', id, m, from, to);
const su = (id, from, to) => (t) => editEntry(t, 'subcase', id, from, to);

const failing = (rel, edit) => check(fixture({ [rel]: edit }));

// A24's M1a stage, implemented: stamp and tests. The hash is derived from the
// tasks §8 row, so an amended row needs no change here.
const A24_HASH = sha256(repoText(TASKS).split('\n').find((l) => l.startsWith('| A24 |')));
const A24_NEG = 'nextest:skyoauth-scenarios/pg/security::a24::a24_neg_y';
const A24_TESTS = `tests = ["nextest:skyoauth-scenarios/pg/security::a24::a24_pos_x", "${A24_NEG}"]`;
const implementedA24 = (t, { stamp = stageStamp('A24', 'M1a', 'consume primitive', A24_HASH), tests = A24_TESTS } = {}) =>
  editStage(t, 'scenario', 'A24', 'M1a', 'status = "planned"\ntests = []', `status = "implemented"\n${stamp === null ? '' : `implemented_sha256 = "${stamp}"\n`}${tests}`);

// A required A58 sub-ID, with the matrix_sha256 of its first owner T32.3.
const T32_3 = repoText(TASKS).split('\n').find((l) => l.startsWith('- [ ] **T32.3** '));
const requiredA58 = (id, extra = '') => `
[[subcase]]
id = "${id}"
kind = "subcase"
parent = "A58"
${extra}layers = ["integration"]
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
status = "planned"
tests = []
`;
// Inserts `entry` (a [[subcase]] block for `id`) before the first entry with a
// greater ID, so that the order rule holds.
function insertSub(t, id, entry) {
  const next = [...t.matchAll(/^\[\[subcase\]\]\nid = "([^"]+)"/gm)].find((m) => m[1] > id);
  return next ? `${t.slice(0, next.index)}${entry.trimStart()}\n${t.slice(next.index)}` : t + entry;
}
const withSub = (id, extra) => (t) => insertSub(t, id, requiredA58(id, extra));

// Every `m` stage of the `table` entries (except entry `except`), implemented
// with its stamp and one test.
function implementAll(t, table, m, except = null) {
  let id;
  let matrix;
  return t
    .split('\n\n')
    .map((b) => {
      const e = new RegExp(`^\\[\\[${table}\\]\\]\\nid = "([^"]+)"`).exec(b);
      if (e) {
        id = e[1];
        matrix = /^matrix_sha256 = "([0-9a-f]+)"$/m.exec(b)[1];
        return b;
      }
      if (id === except || !b.startsWith(`[[${table}.stage]]\nmilestone = "${m}"\n`)) return b;
      const scope = JSON.parse(/^scope = (".*")$/m.exec(b)[1]);
      return replaceOnce(b, 'status = "planned"\ntests = []', `status = "implemented"\nimplemented_sha256 = "${stageStamp(id, m, scope, matrix)}"\ntests = ["nextest:gate::${id.toLowerCase()}_pos_x"]`);
    })
    .join('\n\n');
}

const A03_LEGS = '"scenarios-hermetic/x86_64", "scenarios-hermetic/aarch64", "scenarios-pg/x86_64"';
const HISTORY_ERROR = (reason) => `error [waivers] --require-history: cannot check waiver commits against origin/main: ${reason} (CI checks out with fetch-depth: 0)`;

// ---------------------------------------------------------------------------

describe('the repository', () => {
  test('passes, with the entry counts in the summary', () => {
    const res = check(REPO);
    expectOk(res);
    assert.deepEqual(res.notes, []);
    assert.equal(res.summary, '64 scenarios, 10 contracts, 4 subcases, 0 fixtures, 0 waivers');
  });

  test('a copy of the registry files passes', () => {
    expectOk(check(fixture()));
  });
});

describe('cli', () => {
  const cli = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });

  test('run() returns 0, 1 and 2', () => {
    const quiet = () => {};
    assert.equal(run(['--root', REPO], quiet, quiet), 0);
    assert.equal(run(['--root', fixture({ [SUBCASES]: () => null })], quiet, quiet), 1);
    assert.equal(run(['--nope'], quiet, quiet), 2);
  });

  test('--require-history turns the skipped commit check into an error', () => {
    const root = fixture({ [SCENARIOS]: implementedA24 }, { [WAIVERS]: waiver({ commit: `"${'a'.repeat(40)}"` }) });
    const soft = cli('--root', root);
    assert.equal(soft.status, 0, soft.stderr);
    assert.match(soft.stdout, /^note: waivers: commit reachability not checked: the root is not a git checkout\ncheck-conformance-registry: OK \(.*, 1 waivers\)\n$/);
    const strict = cli('--require-history', '--root', root);
    assert.equal(strict.status, 1);
    assert.equal(strict.stderr, `${HISTORY_ERROR('the root is not a git checkout')}\ncheck-conformance-registry: 1 error(s)\n`);
  });

  test('--require-history fails without the history even with no waivers', () => {
    const root = fixture();
    assert.equal(cli('--root', root).status, 0);
    const strict = cli('--require-history', '--root', root);
    assert.equal(strict.status, 1);
    assert.equal(strict.stderr, `${HISTORY_ERROR('the root is not a git checkout')}\ncheck-conformance-registry: 1 error(s)\n`);
    assert.equal(strict.stdout, '');
  });

  test('exit 0 and OK on the repository (default root)', () => {
    const r = cli();
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, 'check-conformance-registry: OK (64 scenarios, 10 contracts, 4 subcases, 0 fixtures, 0 waivers)\n');
    assert.equal(r.stderr, '');
  });

  test('exit 1 with file:line errors and a count', () => {
    const root = fixture({ [SCENARIOS]: sc('A24', `matrix_sha256 = "${A24_HASH}"`, `matrix_sha256 = "${'0'.repeat(64)}"`) });
    // --require-history on a root that is not a git checkout: the history
    // error does not hide the registry errors.
    const r = cli('--root', root, '--require-history');
    assert.equal(r.status, 1);
    const line = entryLine(read(root, SCENARIOS), 'scenario', 'A24');
    assert.match(r.stderr, new RegExp(`^tests/conformance/scenarios\\.toml:${line}: error \\[hash\\] A24: matrix_sha256 is 0{64}, but docs/skyoauth-tasks\\.md:\\d+ hashes to ${A24_HASH}`, 'm'));
    assert.ok(r.stderr.startsWith(`${HISTORY_ERROR('the root is not a git checkout')}\n`), r.stderr);
    assert.match(r.stderr, /^check-conformance-registry: 2 error\(s\)$/m);
    assert.equal(r.stdout, '');
  });

  test('notes go to stdout', () => {
    const root = fixture({}, { [WAIVERS]: waiver({ commit: `"${'a'.repeat(40)}"` }) });
    const out = [];
    const err = [];
    assert.equal(run(['--root', root], (m) => out.push(m), (m) => err.push(m)), 1);
    assert.ok(out.includes('note: waivers: commit reachability not checked: the root is not a git checkout'), out.join('\n'));
  });

  for (const args of [['--bogus'], ['--root'], ['extra']]) {
    test(`usage error exits 2: ${args.join(' ')}`, () => {
      const r = cli(...args);
      assert.equal(r.status, 2);
      assert.equal(r.stderr, 'usage: check-conformance-registry.mjs [--root DIR] [--require-history]\n');
    });
  }

  test('formatError', () => {
    assert.equal(formatError({ file: 'f', line: 3, rule: 'r', msg: 'm' }), 'f:3: error [r] m');
    assert.equal(formatError({ file: 'f', line: null, rule: 'r', msg: 'm' }), 'f: error [r] m');
    assert.equal(formatError({ file: null, line: null, rule: 'r', msg: 'm' }), 'error [r] m');
  });
});

describe('locate', () => {
  test('entries, stages and waivers by header line', () => {
    const text = [
      'id = "Z"', // before any header: not located
      '[[scenario]]', // 1
      'id = "A01"',
      '[[scenario.stage]]', // 3
      'milestone = "M1a"',
      '[[scenario.stage]]', // 5
      'id = "Q"', // not an entry ID inside a stage
      'milestone = "M2"',
      '[[subcase]]', // 7
      'id = "A02.90"',
      'parent = "A02"',
      '[[subcase.stage]]', // 10
      'milestone = "M3"',
      '[[waiver]]', // 12
      'commit = "x"',
      '[[waiver]]', // 14
      '[[scenario]]', // 15
      'id = "A01"',
      'milestone = "M9"',
    ].join('\n');
    assert.deepEqual(
      [...locate(text)],
      [
        ['A01', 2],
        ['A01/M1a', 4],
        ['A01/M2', 6],
        ['A02.90', 9],
        ['A02.90/M3', 12],
        ['waiver/0', 14],
        ['waiver/1', 16],
      ],
    );
  });
});

describe('rule toml', () => {
  test('invalid TOML, with the smol-toml line and the first line of its message', () => {
    const text = `${repoText(SUBCASES)}broken = \n`;
    let first;
    assert.throws(() => parseStrict(text), (ex) => ((first = ex.message.split('\n')[0]), true));
    assert.ok(first.length > 0 && !first.includes('\n'));
    const res = failing(SUBCASES, () => text);
    expectOnly(res, 'toml', new RegExp(`^tests/conformance/subcases\\.toml:${text.split('\n').length - 1}: error \\[toml\\] not valid TOML: ${first.replace(/[|.*+?()[\]\\^$]/g, '\\$&')}$`));
  });

  test('valid TOML outside the generator subset', () => {
    const res = failing(SUBCASES, (t) => `x = 'literal'\n${t}`);
    expectOnly(res, 'toml', /^error \[toml\] tests\/conformance\/subcases\.toml:1: unsupported value \(outside the TOML subset that gen-conformance-registry\.mjs reads\)$/);
  });

  test('an impossible date, which smol-toml would roll over, is rejected', () => {
    // smol-toml 1.9.1 turns 2026-02-30 into 2026-03-02; the subset reader and
    // Python tomllib reject it.
    assert.equal(parseStrict('d = 2026-02-30').d.toISOString(), '2026-03-02');
    const res = check(fixture({}, { [WAIVERS]: waiver({ expires: '2026-02-30' }) }));
    expectOnly(res, 'toml', /tests\/conformance\/waivers\.toml:8: invalid date 2026-02-30 \(outside the TOML subset/);
  });

  test('a date-time is rejected', () => {
    const res = check(fixture({}, { [WAIVERS]: waiver({ expires: '2026-12-31T00:00:00' }) }));
    expectOnly(res, 'toml', /only local dates are supported, not date-times/);
  });

  test('the two readers disagree', () => {
    // The subset reader takes a [[header]] key verbatim, quotes included, so
    // [["x"]] is the table x to smol-toml but the table "x" to the subset reader.
    const text = '[["x"]]\n';
    assert.equal(JSON.stringify(plain(parseStrict(text))), '{"x":[{}]}');
    assert.equal(JSON.stringify(plain(parseToml(text))), '{"\\"x\\"":[{}]}');
    const res = failing(SUBCASES, (t) => `${t}\n${text}`);
    expectOnly(res, 'toml', /^tests\/conformance\/subcases\.toml: error \[toml\] smol-toml and the gen-conformance-registry\.mjs reader return different data$/);
  });

  test('keys named after Object.prototype members: both readers agree, and the fields rule reports them', () => {
    for (const k of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      for (const text of [`${k} = 1\n`, `x = { ${k} = { ${k} = "y" } }\n`, `[[${k}]]\n${k} = 2\n`, `[[t]]\n[[t.${k}]]\n`]) {
        assert.equal(JSON.stringify(plain(parseToml(text))), JSON.stringify(plain(parseStrict(text))), text);
      }
      expectOnly(failing(SUBCASES, (t) => `${k} = { ${k} = "y" }\n${t}`), 'fields', new RegExp(`^tests/conformance/subcases\\.toml: error \\[fields\\] unknown field ${k}$`));
      expectOnly(failing(SUBCASES, (t) => `${t}\n[[${k}]]\n`), 'fields', new RegExp(`^tests/conformance/subcases\\.toml: error \\[fields\\] unknown field ${k}$`));
      const res = failing(SCENARIOS, (t) => `${t}\n[[scenario.${k}]]\n`);
      expectOnly(res, 'fields', new RegExp(`^tests/conformance/scenarios\\.toml:\\d+: error \\[fields\\] C10: unknown field ${k}$`));
    }
  });

  test('a waivers.toml error does not hide the registry checks', () => {
    const root = fixture({ [SCENARIOS]: sc('A24', 'owners = ["T10.9",', 'owners = ["T99.9", "T10.9",') }, { [WAIVERS]: 'x = \n' });
    const res = check(root);
    expectError(res, 'toml', /waivers\.toml:1: error \[toml\] not valid TOML/);
    expectError(res, 'owners', /owner T99\.9/);
  });
});

describe('rule fields', () => {
  for (const rel of FILES) {
    test(`missing ${rel}`, () => {
      expectOnly(check(fixture({ [rel]: () => null })), 'fields', new RegExp(`^${rel.replaceAll('.', '\\.')}: error \\[fields\\] not found$`));
    });
  }

  test('unknown top-level keys', () => {
    expectOnly(failing(SCENARIOS, (t) => replaceOnce(t, 'gates_passed = []', 'gates_passed = []\nextra = 1')), 'fields', /^tests\/conformance\/scenarios\.toml: error \[fields\] unknown field extra$/);
    expectOnly(failing(SUBCASES, (t) => `extra = 1\n${t}`), 'fields', /^tests\/conformance\/subcases\.toml: error \[fields\] unknown field extra$/);
  });

  test('gates_passed', () => {
    expectOk(check(fixture({ [SCENARIOS]: (t) => implementAll(replaceOnce(t, 'gates_passed = []', 'gates_passed = ["M0", "M1a"]'), 'scenario', 'M1a') })));
    for (const v of ['["M9"]', '["M0", "M0"]', '"M0"']) {
      expectOnly(failing(SCENARIOS, (t) => replaceOnce(t, 'gates_passed = []', `gates_passed = ${v}`)), 'fields', /gates_passed must be a list of distinct milestones \(M0, M1a, M1b, M2, M3, M4, M5\)/);
    }
    expectOnly(failing(SCENARIOS, (t) => replaceOnce(t, 'gates_passed = []\n', '')), 'fields', /gates_passed must be a list/);
  });

  test('scenario must be an array of tables', () => {
    const res = failing(SCENARIOS, () => 'gates_passed = []\nscenario = 1\n');
    expectError(res, 'fields', /^tests\/conformance\/scenarios\.toml: error \[fields\] scenario must be an array of tables/);
    expectError(res, 'ids', /^docs\/skyoauth-tasks\.md:\d+: error \[ids\] tasks §8 scenario A01 has no registry entry/);
  });

  test('subcase must be an array of tables; no [[subcase]] is allowed', () => {
    expectError(failing(SUBCASES, () => 'subcase = 1\n'), 'fields', /subcases\.toml: error \[fields\] subcase must be an array of tables/);
    const res = failing(SUBCASES, () => '');
    // Only the conditional sub-IDs that the §2 table names go missing.
    assert.ok(res.errors.every((e) => e.rule === 'subcases' || e.rule === 'table'), dump(res));
    expectError(res, 'subcases', /A27\.90 \(device-flow, T40\.6\) is named in docs\/testing\/conformance-layout\.md §2 row A27 but missing/);
  });

  test('unknown kind', () => {
    const t = sc('A24', 'kind = "scenario"', 'kind = "scenari"')(repoText(SCENARIOS));
    const res = failing(SCENARIOS, () => t);
    expectError(res, 'fields', new RegExp(`^tests/conformance/scenarios\\.toml:${entryLine(t, 'scenario', 'A24')}: error \\[fields\\] A24: kind must be scenario or contract$`));
    expectError(res, 'ids', /scenario A24 has no registry entry/);
  });

  test('unknown entry fields', () => {
    const t = sc('A24', 'kind = "scenario"\n', 'kind = "scenario"\nfoo = "x"\n')(repoText(SCENARIOS));
    expectOnly(failing(SCENARIOS, () => t), 'fields', new RegExp(`scenarios\\.toml:${entryLine(t, 'scenario', 'A24')}: error \\[fields\\] A24: unknown field foo$`));
    expectOnly(failing(SCENARIOS, (x) => editEntry(x, 'scenario', 'C07', 'kind = "contract"\n', 'kind = "contract"\nnote = "x"\n')), 'fields', /C07: unknown field note$/);
    expectOnly(failing(SUBCASES, su('A33.90', 'kind = "subcase"\n', 'kind = "subcase"\nnote = "x"\n')), 'fields', /A33\.90: unknown field note$/);
  });

  test('contract covered_by', () => {
    for (const v of ['[]', '["A99"]', '"A01"']) {
      const t = editEntry(repoText(SCENARIOS), 'scenario', 'C07', /covered_by = .*/.exec(entryBlock(repoText(SCENARIOS), 'scenario', 'C07'))[0], `covered_by = ${v}`);
      expectOnly(failing(SCENARIOS, () => t), 'fields', new RegExp(`scenarios\\.toml:${entryLine(t, 'scenario', 'C07')}: error \\[fields\\] C07: covered_by must be a non-empty list of registered scenarios`));
    }
  });

  const columns = [
    ['layers unknown', 'layers = ["security"]', 'layers = ["securty"]', /A24: layers must be a non-empty list of conformance, security, integration, package/],
    ['layers empty', 'layers = ["security"]', 'layers = []', /A24: layers must be a non-empty list/],
    ['envs unknown', 'envs = ["pg"]', 'envs = ["pgsql"]', /A24: envs must be a non-empty list of [a-z]/],
    ['envs not a list', 'envs = ["pg"]', 'envs = "pg"', /A24: envs must be a non-empty list/],
    ['harness with |', 'harness = ["REP",', 'harness = ["R|P",', /A24: harness must be a non-empty list of table text/],
    ['harness empty string', 'harness = ["REP",', 'harness = ["",', /A24: harness must be a non-empty list of table text/],
    ['owners empty', 'owners = ["T10.9", "T21.6", "T21.8", "T52.7"]', 'owners = []', /A24: owners must be a non-empty list of task IDs/],
    ['positive empty', 'positive = "exactly one issuance across N replicas and grants"', 'positive = ""', /A24: positive must be non-empty table text/],
    ['negative with a line break', 'negative = "missing jti, replay, store failure"', 'negative = "missing jti\\nreplay"', /A24: negative must be non-empty table text/],
    ['note empty', 'kind = "scenario"\n', 'kind = "scenario"\nnote = ""\n', /A24: note must be non-empty table text when present/],
    ['no stage tables', /\n\[\[scenario\.stage\]\][^]*$/, '\nstage = ["x"]\n', /A24: needs at least one stage/],
  ];
  for (const [name, from, to, re] of columns) {
    test(`column: ${name}`, () => {
      const edit = (t) => {
        const block = entryBlock(t, 'scenario', 'A24');
        return replaceOnce(t, block, typeof from === 'string' ? replaceOnce(block, from, to) : block.replace(from, to));
      };
      const res = failing(SCENARIOS, edit);
      expectOnly(res, 'fields', re);
      assert.deepEqual(res.notes, ['table: not compared, because some scenario or subcase fields are invalid']);
    });
  }

  test('a valid note is kept', () => {
    const res = failing(SCENARIOS, sc('A24', 'kind = "scenario"\n', 'kind = "scenario"\nnote = "Some note:"\n'));
    expectOnly(res, 'table', /row A24 differs .*Expected: \| A24 \|.*\| Some note: \+ exactly one/);
  });

  test('subcase kind', () => {
    const res = failing(SUBCASES, su('A33.90', 'kind = "subcase"', 'kind = "scenario"'));
    expectOnly(res, 'fields', /subcases\.toml:\d+: error \[fields\] A33\.90: kind must be subcase$/);
  });

  test('waivers.toml shape', () => {
    expectOnly(check(fixture({}, { [WAIVERS]: 'extra = 1\n' })), 'fields', /^tests\/conformance\/waivers\.toml: error \[fields\] unknown field extra$/);
    const notArray = check(fixture({}, { [WAIVERS]: 'waiver = 1\n' }));
    expectOnly(notArray, 'fields', /waivers\.toml: error \[fields\] waiver must be an array of tables/);
    assert.match(notArray.summary, /, 0 waivers$/);
    const empty = check(fixture({}, { [WAIVERS]: '# no waivers\n' }));
    expectOk(empty);
    assert.match(empty.summary, /, 0 waivers$/);
  });
});

describe('rule ids', () => {
  test('a tasks §8 row without an entry', () => {
    const block = entryBlock(repoText(SCENARIOS), 'scenario', 'A24');
    const res = failing(SCENARIOS, (t) => replaceOnce(t, block, ''));
    expectError(res, 'ids', new RegExp(`^docs/skyoauth-tasks\\.md:${specLine(repoText(TASKS), 'A24')}: error \\[ids\\] tasks §8 scenario A24 has no registry entry in tests/conformance/scenarios\\.toml$`));
  });

  test('an entry without a tasks §8 row', () => {
    const t = repoText(SCENARIOS);
    const a64 = entryBlock(t, 'scenario', 'A64');
    const edited = replaceOnce(t, a64, a64 + a64.replace('id = "A64"', 'id = "A65"'));
    const res = failing(SCENARIOS, () => edited);
    expectError(res, 'ids', new RegExp(`scenarios\\.toml:${entryLine(edited, 'scenario', 'A65')}: error \\[ids\\] A65 is not a tasks §8 scenario row of docs/skyoauth-tasks\\.md$`));
  });

  test('an entry registered twice', () => {
    const t = repoText(SCENARIOS);
    const a24 = entryBlock(t, 'scenario', 'A24');
    const res = failing(SCENARIOS, () => replaceOnce(t, a24, a24 + a24));
    expectError(res, 'ids', /^tests\/conformance\/scenarios\.toml: error \[ids\] A24 is registered more than once$/);
    expectError(res, 'order', /A24 follows A24: IDs must increase/);
  });

  test('a malformed scenario or contract ID', () => {
    const r1 = failing(SCENARIOS, sc('A24', 'id = "A24"', 'id = "A2"'));
    expectError(r1, 'ids', /"A2": a scenario ID looks like A24$/);
    expectError(r1, 'ids', /scenario A24 has no registry entry/);
    // The malformed entry is not matched against the spec rows.
    assert.equal(r1.errors.filter((e) => e.rule === 'ids').length, 2, dump(r1));
    const r2 = failing(SCENARIOS, (t) => editEntry(t, 'scenario', 'C07', 'id = "C07"', 'id = "C7"'));
    expectError(r2, 'ids', /"C7": a contract ID looks like C07$/);
    expectError(r2, 'ids', new RegExp(`^docs/skyoauth-design\\.md:${specLine(repoText(DESIGN), 'C07')}: error \\[ids\\] design §2 contract C07 has no registry entry`));
  });

  test('a contract without a design §2 row', () => {
    const t = repoText(SCENARIOS);
    const c10 = entryBlock(t, 'scenario', 'C10');
    const res = failing(SCENARIOS, () => replaceOnce(t, c10, c10 + c10.replace('id = "C10"', 'id = "C11"')));
    expectOnly(res, 'ids', /C11 is not a design §2 contract row of docs\/skyoauth-design\.md$/);
  });

  test('tasks §8 row errors', () => {
    const row = repoText(TASKS).split('\n').find((l) => l.startsWith('| A24 |'));
    const res = failing(TASKS, (t) => replaceOnce(t, row, `${row}\n${row}`));
    expectError(res, 'ids', /docs\/skyoauth-tasks\.md:\d+: duplicate scenario row A24/);
  });

  test('a spec section that is missing', () => {
    expectOnly(failing(TASKS, (t) => t.replace(/^## 8\. /m, '## 8x ')), 'ids', /^error \[ids\] docs\/skyoauth-tasks\.md: section "## 8\." not found$/);
    expectOnly(failing(DESIGN, (t) => t.replace(/^## 2\. /m, '## 2x ')), 'ids', /^error \[ids\] docs\/skyoauth-design\.md: section "## 2\." not found$/);
  });

  test('a malformed sub-ID', () => {
    const res = failing(SUBCASES, su('A33.90', 'id = "A33.90"', 'id = "A33.9"'));
    expectError(res, 'ids', /A33\.9: a sub-ID looks like A58\.07$/);
  });
});

describe('rule order', () => {
  const swap = (t, table, x, y) => {
    const bx = entryBlock(t, table, x);
    const by = entryBlock(t, table, y);
    return replaceOnce(t, bx + by, by + bx);
  };
  test('scenarios', () => {
    const t = swap(repoText(SCENARIOS), 'scenario', 'A24', 'A25');
    const res = failing(SCENARIOS, () => t);
    expectError(res, 'order', new RegExp(`scenarios\\.toml:${entryLine(t, 'scenario', 'A24')}: error \\[order\\] A24 follows A25: IDs must increase$`));
    assert.equal(res.errors.filter((e) => e.rule === 'order').length, 1);
  });
  test('contracts', () => {
    const t = swap(repoText(SCENARIOS), 'scenario', 'C01', 'C02');
    expectOnly(failing(SCENARIOS, () => t), 'order', /C01 follows C02: IDs must increase$/);
  });
  test('subcases', () => {
    const t = swap(repoText(SUBCASES), 'subcase', 'A18.90', 'A27.90');
    expectOnly(failing(SUBCASES, () => t), 'order', new RegExp(`subcases\\.toml:${entryLine(t, 'subcase', 'A18.90')}: error \\[order\\] A18\\.90 follows A27\\.90`));
  });
});

describe('rule hash', () => {
  test('a hand-edited scenario matrix_sha256', () => {
    const res = failing(SCENARIOS, sc('A24', A24_HASH, 'f'.repeat(64)));
    expectOnly(res, 'hash', new RegExp(`A24: matrix_sha256 is f{64}, but docs/skyoauth-tasks\\.md:${specLine(repoText(TASKS), 'A24')} hashes to ${A24_HASH}; review the entry and run the generator$`));
  });

  test('an edited tasks §8 row', () => {
    const row = repoText(TASKS).split('\n').find((l) => l.startsWith('| A24 |'));
    const edited = row.replace(/ \|$/, ' x |');
    const res = failing(TASKS, (t) => replaceOnce(t, row, edited));
    expectOnly(res, 'hash', new RegExp(`A24: matrix_sha256 is ${A24_HASH}, but docs/skyoauth-tasks\\.md:\\d+ hashes to ${sha256(edited)}`));
  });

  test('a contract matrix_sha256', () => {
    const t = repoText(SCENARIOS);
    const h = /matrix_sha256 = "([0-9a-f]+)"/.exec(entryBlock(t, 'scenario', 'C07'))[1];
    expectOnly(failing(SCENARIOS, (x) => editEntry(x, 'scenario', 'C07', h, '0'.repeat(64))), 'hash', /C07: matrix_sha256 is 0{64}, but docs\/skyoauth-design\.md:\d+ hashes to/);
  });

  test('a subcase matrix_sha256', () => {
    const h = /matrix_sha256 = "([0-9a-f]+)"/.exec(entryBlock(repoText(SUBCASES), 'subcase', 'A33.90'))[1];
    const res = failing(SUBCASES, su('A33.90', `matrix_sha256 = "${h}"`, 'matrix_sha256 = "x"'));
    expectOnly(res, 'hash', new RegExp(`A33\\.90: matrix_sha256 is x, but the docs/skyoauth-tasks\\.md line of T30\\.6 hashes to ${h}; review`));
  });

  test('a subcase whose first owner is not a task', () => {
    const res = failing(SUBCASES, su('A33.90', 'owners = ["T30.6"]', 'owners = ["T99.9"]'));
    expectError(res, 'hash', /A33\.90: the first owner must be a task, whose tasks\.md line matrix_sha256 hashes$/);
    expectError(res, 'owners', /A33\.90: owner T99\.9 is not a task/);
  });

  test('a subcase without owners', () => {
    const res = failing(SUBCASES, su('A33.90', 'owners = ["T30.6"]', 'owners = []'));
    expectError(res, 'hash', /A33\.90: the first owner must be a task/);
    expectError(res, 'fields', /A33\.90: owners must be a non-empty list/);
  });
});

describe('rule owners', () => {
  test('an owner that is not a task', () => {
    const t = sc('A24', 'owners = ["T10.9",', 'owners = ["T99.9", "T10.9",')(repoText(SCENARIOS));
    const res = failing(SCENARIOS, () => t);
    expectError(res, 'owners', new RegExp(`scenarios\\.toml:${entryLine(t, 'scenario', 'A24')}: error \\[owners\\] A24: owner T99\\.9 is not a task in docs/skyoauth-tasks\\.md$`));
    assert.equal(res.errors.filter((e) => e.rule === 'owners').length, 1);
  });
});

describe('rule stages', () => {
  const stageCase = (name, edit, re, { only = true, rel = SCENARIOS, line } = {}) =>
    test(name, () => {
      const t = edit(repoText(rel));
      const res = failing(rel, () => t);
      if (only) expectOnly(res, 'stages', re);
      else expectError(res, 'stages', re);
      if (line) assert.ok(res.errors.some((e) => e.rule === 'stages' && e.line === line(t)), dump(res));
    });

  stageCase('unknown milestone', st('A24', 'M1a', 'milestone = "M1a"', 'milestone = "M9"'), /A24 M9: unknown milestone \(known: M0, M1a, M1b, M2, M3, M4, M5\)$/, {
    only: false,
    line: (t) => stageLine(t, 'scenario', 'A24', 'M9'),
  });
  stageCase(
    'milestones out of order',
    (t) => st('A24', 'M1a', 'milestone = "M1a"', 'milestone = "M2"')(st('A24', 'M2', 'milestone = "M2"', 'milestone = "M1a"')(t)),
    /A24 M1a: stage milestones must increase, so that the last stage is the full milestone$/,
    { only: false },
  );
  stageCase('the same milestone twice', st('A24', 'M2', 'milestone = "M2"', 'milestone = "M1a"'), /A24 M1a: stage milestones must increase/, { only: false });
  stageCase('"full row" in a multi-stage entry', st('A24', 'M1a', 'scope = "consume primitive"', 'scope = "full row"'), /A24 M1a: scope "full row" is the scope of a single-stage entry, and only of one$/, {
    only: false,
    line: (t) => stageLine(t, 'scenario', 'A24', 'M1a'),
  });
  stageCase('a single-stage entry that is not "full row"', (t) => editStage(t, 'scenario', 'A01', 'M2', 'scope = "full row"', 'scope = "part"'), /A01 M2: scope "full row" is the scope of a single-stage entry/, { only: false });
  stageCase('empty scope', st('A24', 'M1a', 'scope = "consume primitive"', 'scope = ""'), /A24 M1a: scope must be non-empty table text$/, { only: false });
  stageCase('scope with |', st('A24', 'M1a', 'scope = "consume primitive"', 'scope = "consume | primitive"'), /A24 M1a: scope must be non-empty table text$/, { only: false });
  stageCase('unknown status', st('A24', 'M1a', 'status = "planned"', 'status = "done"'), /A24 M1a: status must be one of planned, implemented$/);
  test('legs not a list', () => {
    const res = failing(SCENARIOS, st('A24', 'M1a', 'legs = ["scenarios-pg/x86_64"]', 'legs = "scenarios-pg/x86_64"'));
    expectError(res, 'stages', /A24 M1a: legs must be a non-empty list of leg strings$/);
    // The string's characters are not checked as legs, and pg keeps its leg
    // through the M2 stage, so there is no legs error at all.
    assert.ok(!res.errors.some((e) => e.rule === 'legs'), dump(res));
    assert.equal(res.errors.length, 1, dump(res));
  });
  stageCase('empty legs', st('A24', 'M1a', 'legs = ["scenarios-pg/x86_64"]', 'legs = []'), /A24 M1a: legs must be a non-empty list of leg strings$/);
  stageCase('a leg twice', st('A24', 'M1a', 'legs = ["scenarios-pg/x86_64"]', 'legs = ["scenarios-pg/x86_64", "scenarios-pg/x86_64"]'), /A24 M1a: legs lists a leg twice$/);
  stageCase('tests not a list', st('A24', 'M1a', 'tests = []', 'tests = "a24_pos_x"'), /A24 M1a: tests must be a list of test IDs$/);
  stageCase('an empty test ID', st('A24', 'M1a', 'tests = []', 'tests = [""]'), /A24 M1a: tests must be a list of test IDs$/);
  stageCase('unknown stage field', st('A24', 'M1a', 'tests = []', 'tests = []\nowner = "x"'), /A24 M1a: unknown field owner$/);

  test('an implemented stage with its stamp and tests passes', () => {
    const res = check(fixture({ [SCENARIOS]: implementedA24 }));
    expectOk(res);
    // The stamp formula of layout §3.
    assert.equal(stageStamp('A24', 'M1a', 'consume primitive', A24_HASH), sha256(['A24', 'M1a', 'consume primitive', A24_HASH].join('\n')));
  });

  stageCase('an implemented stage without tests', (t) => implementedA24(t, { tests: 'tests = []' }), /A24 M1a: an implemented stage must list its tests$/);
  stageCase('an implemented stage without a stamp', (t) => implementedA24(t, { stamp: null }), /A24 M1a: implemented_sha256 is missing, but the stage's \(id, milestone, scope, matrix_sha256\) stamps to [0-9a-f]{64}; a changed scope/);
  stageCase('an implemented stage whose scope changed', (t) => st('A24', 'M1a', 'scope = "consume primitive"', 'scope = "consume primitive v2"')(implementedA24(t)), /A24 M1a: implemented_sha256 is [0-9a-f]{64}, but .* stamps to/, { only: false });
  stageCase('an implemented stage moved to another milestone', (t) => st('A24', 'M1a', 'milestone = "M1a"', 'milestone = "M1b"')(implementedA24(t)), /A24 M1b: implemented_sha256 is [0-9a-f]{64}, but/, { only: false });

  test('an implemented stage whose tasks §8 row changed', () => {
    const row = repoText(TASKS).split('\n').find((l) => l.startsWith('| A24 |'));
    const edited = row.replace(/ \|$/, ' x |');
    const res = check(fixture({ [SCENARIOS]: (t) => sc('A24', A24_HASH, sha256(edited))(implementedA24(t)), [TASKS]: (t) => replaceOnce(t, row, edited) }));
    expectOnly(res, 'stages', /A24 M1a: implemented_sha256 is [0-9a-f]{64}, but/);
  });

  stageCase('a stamp on a planned stage', st('A24', 'M1a', 'status = "planned"', 'status = "planned"\nimplemented_sha256 = "x"'), /A24 M1a: implemented_sha256 is only for an implemented stage$/);

  test('an implemented subcase stage', () => {
    const h = /matrix_sha256 = "([0-9a-f]+)"/.exec(entryBlock(repoText(SUBCASES), 'subcase', 'A33.90'))[1];
    const impl = (stamp) => su('A33.90', 'status = "planned"\ntests = []', `status = "implemented"\nimplemented_sha256 = "${stamp}"\ntests = ["vitest:a33"]`);
    expectOk(check(fixture({ [SUBCASES]: impl(stageStamp('A33.90', 'M3', 'full row', h)) })));
    expectOnly(failing(SUBCASES, impl(stageStamp('A33', 'M3', 'full row', h))), 'stages', /A33\.90 M3: implemented_sha256 is/);
  });
});

describe('rule legs', () => {
  test('a leg that is not in the catalogue', () => {
    const t = st('A24', 'M1a', 'legs = ["scenarios-pg/x86_64"]', 'legs = ["scenarios-pg/arm64"]')(repoText(SCENARIOS));
    const res = failing(SCENARIOS, () => t);
    expectOnly(res, 'legs', new RegExp(`scenarios\\.toml:${stageLine(t, 'scenario', 'A24', 'M1a')}: error \\[legs\\] A24 M1a: leg "scenarios-pg/arm64" is not in the layout §1\\.1 Leg strings column$`));
  });

  test('a leg of an env the entry does not list', () => {
    const res = failing(SCENARIOS, st('A24', 'M1a', 'legs = ["scenarios-pg/x86_64"]', 'legs = ["scenarios-pg/x86_64", "scenarios-envoy-k3s/x86_64"]'));
    expectOnly(res, 'legs', /A24 M1a: leg "scenarios-envoy-k3s\/x86_64" runs in job scenarios-envoy-k3s of env envoy-k3s, which is not one of envs$/);
  });

  test('a leg whose job does not exist yet at the stage milestone', () => {
    // clients-rust (env hermetic) exists from M2: not in A03's M1a stage, but in its M2 stage.
    const t = st('A03', 'M1a', `legs = [${A03_LEGS}]`, `legs = [${A03_LEGS}, "clients-rust/x86_64"]`)(repoText(SCENARIOS));
    expectOnly(failing(SCENARIOS, () => t), 'legs', new RegExp(`scenarios\\.toml:${stageLine(t, 'scenario', 'A03', 'M1a')}: error \\[legs\\] A03 M1a: leg "clients-rust/x86_64" runs in job clients-rust, which exists only from M2$`));
    expectOk(check(fixture({ [SCENARIOS]: st('A03', 'M2', `legs = [${A03_LEGS}]`, `legs = [${A03_LEGS}, "clients-rust/x86_64"]`) })));
    // A job that exists from M0 is fine in a stage of any milestone.
    expectOk(check(fixture({ [SCENARIOS]: st('A03', 'M1a', `legs = [${A03_LEGS}]`, `legs = [${A03_LEGS}, "typescript/node22"]`) })));
  });

  test('an M0 stage, the first milestone, is checked too', () => {
    const t = st('A03', 'M1a', 'milestone = "M1a"', 'milestone = "M0"')(repoText(SCENARIOS));
    const res = failing(SCENARIOS, () => t);
    const legs = res.errors.filter((e) => e.rule === 'legs').map(formatError);
    const at = stageLine(t, 'scenario', 'A03', 'M0');
    assert.deepEqual(legs, ['scenarios-hermetic/x86_64', 'scenarios-hermetic/aarch64', 'scenarios-pg/x86_64'].map((leg) => `tests/conformance/scenarios.toml:${at}: error [legs] A03 M0: leg "${leg}" runs in job ${leg.split('/')[0]}, which exists only from M1a`));
  });

  test('a leg of a stage with an unknown milestone is not checked against JOB_FROM', () => {
    const res = failing(SCENARIOS, st('A03', 'M1a', 'milestone = "M1a"', 'milestone = "M9"'));
    // The table rule fires too (the rendered row shows M9); no legs error does.
    assert.ok(!res.errors.some((e) => e.rule === 'legs'), dump(res));
    expectError(res, 'stages', /A03 M9: unknown milestone/);
  });

  test('an env without a leg', () => {
    const t = sc('A24', 'envs = ["pg"]', 'envs = ["pg", "envoy-k3s"]')(repoText(SCENARIOS));
    const res = failing(SCENARIOS, () => t);
    expectError(res, 'legs', new RegExp(`scenarios\\.toml:${entryLine(t, 'scenario', 'A24')}: error \\[legs\\] A24: env envoy-k3s has no leg in any stage$`));
    assert.equal(res.errors.filter((e) => e.rule === 'legs').length, 1);
  });

  test('the split live WIF legs', () => {
    const legs = (id) => parseToml(repoText(SCENARIOS)).scenario.find((e) => e.id === id).stage.flatMap((s) => s.legs);
    assert.ok(legs('A01').includes('live-wif-push'));
    assert.ok(legs('A02').includes('live-wif-negative'));
    assert.ok(legs('A36').includes('live-wif-push'));
    const res = failing(SCENARIOS, (t) => editStage(t, 'scenario', 'A01', 'M2', '"live-wif-push"', '"live-wif"'));
    expectError(res, 'legs', /A01 M2: leg "live-wif" is not in the layout §1\.1 Leg strings column/);
    expectError(res, 'legs', /A01: env live has no leg in any stage$/);
  });

  test('a malformed leg string in layout §1.1', () => {
    const res = failing(LAYOUT, (t) => replaceOnce(t, '`scenarios-envoy-k3s/x86_64`, `scenarios-envoy-k3s-nightly`, `migration', '`scenarios-envoy-k3s/x86_64`, `Bad Leg`, `scenarios-envoy-k3s-nightly`, `migration'));
    expectError(res, 'legs', /^error \[legs\] docs\/testing\/conformance-layout\.md:\d+: malformed leg string "Bad Leg"$/);
    assert.ok(res.errors.every((e) => e.rule === 'legs'), dump(res));
  });

  test('layout §1.1 missing', () => {
    const res = failing(LAYOUT, (t) => replaceOnce(t, '### 1.1', '### 1.x'));
    expectOnly(res, 'legs', /^error \[legs\] docs\/testing\/conformance-layout\.md: subsection "### 1\.1" not found$/);
  });
});

describe('rule gates', () => {
  const gate = (v) => (t) => replaceOnce(t, 'gates_passed = []', `gates_passed = ${v}`);
  const stagesAt = (t, m) => (t.match(new RegExp(`^\\[\\[scenario\\.stage\\]\\]\\nmilestone = "${m}"$`, 'gm')) ?? []).length;
  const m1aStages = (t) => stagesAt(t, 'M1a');

  test('an empty gates_passed (the normalised fixtures) and a gate without stages pass', () => {
    assert.equal(m1aStages(repoText(SCENARIOS)) > 1, true);
    assert.deepEqual(parseStrict(repoText(SCENARIOS)).gates_passed, []);
    expectOk(check(fixture({ [SCENARIOS]: gate('["M0"]') })));
  });

  test('a gate whose stages are all implemented passes', () => {
    expectOk(check(fixture({ [SCENARIOS]: (t) => implementAll(gate('["M1a"]')(t), 'scenario', 'M1a') })));
  });

  test('a gate with one planned stage', () => {
    const t = implementAll(gate('["M0", "M1a"]')(repoText(SCENARIOS)), 'scenario', 'M1a', 'A24');
    const res = failing(SCENARIOS, () => t);
    expectOnly(res, 'gates', new RegExp(`^tests/conformance/scenarios\\.toml:${stageLine(t, 'scenario', 'A24', 'M1a')}: error \\[gates\\] A24 M1a: gates_passed lists M1a, but this stage is planned, not implemented$`));
  });

  test('a gate with every stage planned reports each stage', () => {
    const res = failing(SCENARIOS, gate('["M1a"]'));
    assert.equal(res.errors.length, m1aStages(repoText(SCENARIOS)), dump(res));
    assert.ok(res.errors.every((e) => e.rule === 'gates' && /: gates_passed lists M1a, but this stage is planned, not implemented$/.test(e.msg)), dump(res));
    expectError(res, 'gates', /scenarios\.toml:\d+: error \[gates\] A64 M1a: /);
  });

  test('planned stages of conditional subcases do not block a gate (no release manifest yet)', () => {
    // The four conditional sub-IDs: three planned M3 stages, one planned M4 stage.
    const conditional = parseStrict(repoText(SUBCASES)).subcase.filter((s) => s.conditional_on !== undefined);
    const planned = (m) => conditional.filter((s) => s.stage.some((x) => x.milestone === m && x.status === 'planned')).map((s) => s.id);
    assert.deepEqual([planned('M3').length, planned('M4').length, conditional.length], [3, 1, 4]);
    for (const m of ['M3', 'M4']) {
      expectOk(check(fixture({ [SCENARIOS]: (t) => implementAll(gate(`["${m}"]`)(t), 'scenario', m) })));
    }
    // A scenario stage at that gate still counts.
    const res = check(fixture({ [SCENARIOS]: (t) => implementAll(gate('["M4"]')(t), 'scenario', 'M4', 'A27') }));
    expectOnly(res, 'gates', /scenarios\.toml:\d+: error \[gates\] A27 M4: gates_passed lists M4, but this stage is planned, not implemented$/);
  });

  test('a failing gate that is not the last one in gates_passed', () => {
    const res = failing(SCENARIOS, (t) => implementAll(gate('["M1b", "M1a"]')(t), 'scenario', 'M1a'));
    assert.equal(res.errors.length, stagesAt(repoText(SCENARIOS), 'M1b'), dump(res));
    assert.ok(res.errors.every((e) => e.rule === 'gates' && / M1b: gates_passed lists M1b, but this stage is planned, not implemented$/.test(e.msg)), dump(res));
  });

  test('an M2 gate reports each planned M2 stage and no other', () => {
    const res = failing(SCENARIOS, gate('["M2"]'));
    const n = stagesAt(repoText(SCENARIOS), 'M2');
    assert.ok(n > m1aStages(repoText(SCENARIOS)), `${n} M2 stages`);
    assert.equal(res.errors.length, n, dump(res));
    assert.ok(res.errors.every((e) => e.rule === 'gates' && /^A\d\d M2: gates_passed lists M2, but this stage is planned, not implemented$/.test(e.msg)), dump(res));
    expectError(res, 'gates', /scenarios\.toml:\d+: error \[gates\] A01 M2: /);
  });

  test('a scenario with a stray conditional_on key is still gated', () => {
    const t = sc('A24', 'kind = "scenario"\n', 'kind = "scenario"\nconditional_on = "forwardauth"\n')(implementAll(gate('["M1a"]')(repoText(SCENARIOS)), 'scenario', 'M1a', 'A24'));
    const res = failing(SCENARIOS, () => t);
    expectError(res, 'fields', /A24: unknown field conditional_on$/);
    expectError(res, 'gates', /A24 M1a: gates_passed lists M1a, but this stage is planned, not implemented$/);
    assert.equal(res.errors.length, 2, dump(res));
  });

  test('the fixtures do not depend on implemented stages or passed gates in the real registry', () => {
    // A first real stage PR (A02 M1a implemented, as the generator writes it)
    // and a gate-only PR (gates_passed = ["M0"]) are valid registries...
    const real = rawRepoText(SCENARIOS);
    // A02's M1a stage implemented with its stamp and a test; every other stage as committed.
    const a02 = replaceOnce(real, entryBlock(real, 'scenario', 'A02'), entryBlock(implementAll(normaliseRegistry(real), 'scenario', 'M1a'), 'scenario', 'A02'));
    const variants = { 'A02 M1a implemented': a02, 'gates_passed = ["M0"]': real.replace(/^gates_passed = \[.*\]$/m, 'gates_passed = ["M0"]') };
    for (const [name, text] of Object.entries(variants)) {
      const root = fixture({}, { [SCENARIOS]: text });
      assert.equal(generateRun(['--root', root], () => {}, () => {}), 0, name);
      const committed = read(root, SCENARIOS);
      expectOk(check(root));
      // ...and every fixture built from them is the one built from the real registry.
      assert.equal(normaliseRegistry(committed), repoText(SCENARIOS), name);
    }
    assert.equal(normaliseRegistry(rawRepoText(SUBCASES)), repoText(SUBCASES));
  });

  test('a subcase stage counts too', () => {
    const res = check(fixture({ [SCENARIOS]: (t) => implementAll(gate('["M1b"]')(t), 'scenario', 'M1b'), [SUBCASES]: withSub('A58.07') }));
    expectOnly(res, 'gates', new RegExp(`^tests/conformance/subcases\\.toml:\\d+: error \\[gates\\] A58\\.07 M1b: gates_passed lists M1b, but this stage is planned, not implemented$`));
  });
});

describe('rule table', () => {
  const layoutRow = (id) => repoText(LAYOUT).split('\n').find((l) => l.startsWith(`| ${id} |`));

  test('an edited row', () => {
    const row = layoutRow('A24');
    const res = failing(LAYOUT, (t) => replaceOnce(t, row, row.replace(' | S | ', ' | C | ')));
    expectOnly(res, 'table', new RegExp(`^docs/testing/conformance-layout\\.md:${specLine(repoText(LAYOUT), 'A24')}: error \\[table\\] the §2 table row A24 differs from the one rendered from the registry; run node scripts/ci/gen-conformance-registry\\.mjs\\. Expected: ${row.replace(/[|.*+?()[\]\\]/g, '\\$&')}$`));
  });

  test('an edited registry column', () => {
    const res = failing(SCENARIOS, sc('A24', 'negative = "missing jti, replay, store failure"', 'negative = "missing jti, replay"'));
    expectOnly(res, 'table', /row A24 differs .*Expected: .*− missing jti, replay \|$/);
  });

  test('an edited header', () => {
    const res = failing(LAYOUT, (t) => replaceOnce(t, '| --- | --- | --- | --- | --- | --- | --- |', '| --- | --- | --- | --- | --- | --- | :-- |'));
    expectOnly(res, 'table', /:\d+: error \[table\] the §2 table header differs from the one rendered from the registry/);
  });

  test('a missing table header', () => {
    const res = failing(LAYOUT, (t) => replaceOnce(t, '| ID | Layer | Env | Harness | Stages | Owners | + / − required |', '| ID | Layer |'));
    expectOnly(res, 'table', /^error \[table\] docs\/testing\/conformance-layout\.md: layout §2 scenario table header not found/);
  });

  test('a row the registry does not render', () => {
    const row = layoutRow('A64');
    const t = replaceOnce(repoText(LAYOUT), row, `${row}\n${row.replace('| A64 |', '| A65 |')}`);
    const res = failing(LAYOUT, () => t);
    expectOnly(res, 'table', new RegExp(`conformance-layout\\.md:${specLine(t, 'A65')}: error \\[table\\] the §2 table has a row that the registry does not render$`));
  });

  test('a missing row', () => {
    const res = failing(LAYOUT, (t) => replaceOnce(t, `${layoutRow('A24')}\n`, ''));
    expectError(res, 'table', new RegExp(`conformance-layout\\.md:${specLine(repoText(LAYOUT), 'A24')}: error \\[table\\] the §2 table row A24 differs`));
  });

  test('stale counts', () => {
    const counts = /^Counts by first stage: .*$/m.exec(repoText(LAYOUT))[0];
    const res = failing(LAYOUT, (t) => replaceOnce(t, 'Counts by first stage: M1a 20', 'Counts by first stage: M1a 21'));
    const want = /^Counts by first stage: [^.]*\. Counts by final stage: [^.]*\. \d+ rows have more than one stage\./.exec(counts)[0];
    expectOnly(res, 'table', new RegExp(`conformance-layout\\.md:${lineOf(repoText(LAYOUT), 'Counts by first stage')}: error \\[table\\] the counts sentences differ from the registry; expected: ${want.replace(/[|.*+?()[\]\\]/g, '\\$&')}$`));
  });

  test('missing counts', () => {
    const res = failing(LAYOUT, (t) => replaceOnce(t, 'Counts by first stage: ', 'Counts by first stage (sic): '));
    expectOnly(res, 'table', /^docs\/testing\/conformance-layout\.md: error \[table\] the counts sentences after the §2 table are missing; expected: Counts by first stage: M1a 20 /);
  });

  test('moving a stage changes the expected counts', () => {
    const res = failing(SCENARIOS, st('A24', 'M2', 'milestone = "M2"', 'milestone = "M3"'));
    expectError(res, 'table', /row A24 differs .*Expected: .*M1a: consume primitive · M3: exchange/);
    expectError(res, 'table', /counts sentences differ .*Counts by final stage: M1a 4 · M1b 2 · M2 20 · M3 14 /);
  });

  test('not compared when a subcase table_text is malformed', () => {
    const res = failing(SUBCASES, su('A33.90', /table_text = .*/.exec(entryBlock(repoText(SUBCASES), 'subcase', 'A33.90'))[0], 'table_text = "something else"'));
    expectError(res, 'subcases', /A33\.90: table_text must be a "Conditional sub-ID A33\.90 \(<feature>, Txx\.y\): \.\.\." sentence$/);
    assert.deepEqual(res.notes, ['table: not compared, because some scenario or subcase fields are invalid']);
    assert.ok(!res.errors.some((e) => e.rule === 'table'), dump(res));
  });
});

describe('rule subcases', () => {
  const tt = (id) => /table_text = .*/.exec(entryBlock(repoText(SUBCASES), 'subcase', id))[0];

  test('parent', () => {
    const t = su('A33.90', 'parent = "A33"', 'parent = "A34"')(repoText(SUBCASES));
    const res = failing(SUBCASES, () => t);
    expectError(res, 'subcases', new RegExp(`subcases\\.toml:${entryLine(t, 'subcase', 'A33.90')}: error \\[subcases\\] A33\\.90: parent must be the registered scenario A33$`));
  });

  test('a conditional sub-ID numbered outside .90–.99', () => {
    const res = failing(SUBCASES, (t) => t.replaceAll('A27.90', 'A27.05'));
    expectError(res, 'subcases', /A27\.05: a conditional sub-ID is numbered A27\.90–A27\.99$/);
    expectError(res, 'subcases', /^error \[subcases\] A27\.90 \(device-flow, T40\.6\) is named in docs\/testing\/conformance-layout\.md §2 row A27 but missing from tests\/conformance\/subcases\.toml$/);
  });

  test('.99 is a conditional number, .89 is not', () => {
    expectError(failing(SUBCASES, (t) => t.replaceAll('A27.90', 'A27.89')), 'subcases', /A27\.89: a conditional sub-ID is numbered/);
    const res = failing(SUBCASES, (t) => t.replaceAll('A27.90', 'A27.99'));
    assert.ok(!res.errors.some((e) => /is numbered/.test(e.msg)), dump(res));
  });

  test('unknown conditional_on', () => {
    const res = failing(SUBCASES, su('A27.90', 'conditional_on = "device-flow"', 'conditional_on = "magic"'));
    expectError(res, 'subcases', /A27\.90: conditional_on must be one of device-flow, back-channel-logout, forwardauth$/);
    expectError(res, 'subcases', /A27\.90: conditional_on is magic, but the layout doc names device-flow$/);
  });

  test('table_text naming another sub-ID, feature or task', () => {
    expectError(failing(SUBCASES, su('A27.90', 'Conditional sub-ID A27.90 (', 'Conditional sub-ID A27.91 (')), 'subcases', /A27\.90: table_text names A27\.91$/);
    expectError(failing(SUBCASES, su('A27.90', 'conditional_on = "device-flow"', 'conditional_on = "forwardauth"')), 'subcases', /A27\.90: table_text names feature device-flow, but conditional_on is forwardauth$/);
    expectError(failing(SUBCASES, su('A27.90', '(device flow, T40.6)', '(device flow, T40.5)')), 'subcases', /A27\.90: table_text names T40\.5, but the first owner is T40\.6$/);
  });

  test('a table_text without an ID matches its own entry', () => {
    assert.doesNotMatch(tt('A18.90'), /A18\.90/);
    expectOk(check(fixture()));
  });

  test('table_text with a |', () => {
    const res = failing(SUBCASES, su('A27.90', 'table_text = "Conditional sub-ID A27.90 (device flow, T40.6): user-code approval,', 'table_text = "Conditional sub-ID A27.90 (device flow, T40.6): user-code | approval,'));
    expectError(res, 'subcases', /A27\.90: table_text must be a "Conditional sub-ID/);
  });

  test('a conditional sub-ID that layout §2 does not name', () => {
    const t = repoText(SUBCASES);
    const b = entryBlock(t, 'subcase', 'A27.90');
    const extra = b.replaceAll('A27.90', 'A27.91');
    // The rendered table would name it, but the committed one does not.
    const res = failing(SUBCASES, () => replaceOnce(t, b, b + extra));
    expectError(res, 'subcases', /^error \[subcases\] tests\/conformance\/subcases\.toml: A27\.91 is a conditional sub-ID not named in docs\/testing\/conformance-layout\.md §2$/);
    expectError(res, 'table', /row A27 differs/);
  });

  test('a required sub-ID inside the annex range is accepted, boundaries included', () => {
    for (const id of ['A58.01', 'A58.02', 'A58.89']) {
      const res = check(fixture({ [SUBCASES]: withSub(id) }));
      expectOk(res);
      assert.match(res.summary, /, 5 subcases,/);
    }
  });

  for (const id of ['A58.00', 'A58.91', 'A58.99']) {
    test(`a required sub-ID outside the annex range: ${id}`, () => {
      expectOnly(failing(SUBCASES, withSub(id)), 'subcases', new RegExp(`${id.replace('.', '\\.')}: required sub-ID is outside the annex range A58\\.01–A58\\.89 that the note of A58 declares$`));
    });
  }

  test('a required sub-ID under a parent without an annex range', () => {
    const res = failing(SUBCASES, (t) => insertSub(t, 'A33.02', requiredA58('A33.02').replace('parent = "A58"', 'parent = "A33"')));
    expectOnly(res, 'subcases', /A33\.02: required sub-ID, but the note of A33 declares no annex range$/);
  });

  test('table_text on a required sub-ID', () => {
    expectOnly(failing(SUBCASES, withSub('A58.02', 'table_text = "x"\n')), 'subcases', /A58\.02: table_text is only for a conditional sub-ID$/);
  });

  test('a scenario annex range must lie within .01–.89', () => {
    for (const [range, ok] of [
      ['A58.01–A58.89', true],
      ['A58.10–A58.20', true],
      ['A58.10–A58.10', true],
      ['A58.00–A58.89', false],
      ['A58.01–A58.90', false],
      ['A58.20–A58.10', false],
    ]) {
      const res = failing(SCENARIOS, sc('A58', 'A58.01–A58.89', range));
      const hit = res.errors.filter((e) => e.rule === 'subcases');
      if (ok) assert.deepEqual(hit, []);
      else assert.match(formatError(hit[0] ?? { rule: '-', msg: dump(res) }), new RegExp(`scenarios\\.toml:\\d+: error \\[subcases\\] A58: annex range ${range} must lie within A58\\.01–A58\\.89$`));
    }
  });

  test('two unnumbered named sub-IDs that both match', () => {
    const t = repoText(SUBCASES);
    const b = entryBlock(t, 'subcase', 'A18.90');
    const res = failing(SUBCASES, () => replaceOnce(t, b, b + b.replaceAll('A18.90', 'A18.91')));
    expectError(res, 'subcases', /sub-ID of A18 \(forwardauth, T32\.9\) is named in .* without an ID, but A18\.90 and A18\.91 all match it/);
  });
});

describe('rule fixtures', () => {
  const layoutJson = /```json\n([^]*?)\n```/.exec(repoText(LAYOUT))[1];
  const good = (over = {}) => JSON.stringify({ ...JSON.parse(layoutJson), ...over });
  const at = (...p) => [FIXTURES, ...p].join('/');

  test('no fixtures directory is fine (the repository)', () => {
    assert.match(check(REPO).summary, /, 0 fixtures,/);
  });

  test('the layout §1.3 example passes; _ directories are skipped', () => {
    const res = check(fixture({}, { [at('a61', 'query_reordered_mismatch.json')]: layoutJson, [at('_wire', 'errors.v1.json')]: '{not json', [at('_note.txt')]: 'x' }));
    expectOk(res);
    assert.match(res.summary, /, 1 fixtures,/);
  });

  test('a sub-ID case', () => {
    expectOk(check(fixture({ [SUBCASES]: withSub('A58.07') }, { [at('a58', 'x.json')]: good({ scenario: 'A58', subcase: 'A58.07' }) })));
    for (const subcase of ['A58.08', 'A27.90', 7]) {
      expectOnly(check(fixture({ [SUBCASES]: withSub('A58.07') }, { [at('a58', 'x.json')]: good({ scenario: 'A58', subcase }) })), 'fixtures', /a58\/x\.json: error \[fixtures\] subcase must be a registered sub-ID of A58$/);
    }
  });

  for (const [name, rel] of [
    ['a file in the fixtures root', at('a61.json')],
    ['an unregistered scenario', at('a65', 'x.json')],
    ['an upper-case directory', at('A61', 'x.json')],
    ['a file named after a scenario', at('a61')],
    ['a directory not named after a scenario', at('wire', 'x.json')],
  ]) {
    test(`fixtures layout: ${name}`, () => {
      const top = rel.split('/').slice(0, 4).join('/');
      expectOnly(check(fixture({}, { [rel]: good() })), 'fixtures', new RegExp(`^${top.replaceAll('.', '\\.')}: error \\[fixtures\\] every entry not starting with "_" must be a directory named after a registered scenario, such as a61$`));
    });
  }

  test('a non-JSON file in a scenario directory', () => {
    expectOnly(check(fixture({}, { [at('a61', 'x.yaml')]: 'x' })), 'fixtures', /a61\/x\.yaml: error \[fixtures\] a scenario fixture directory holds only \.json case files$/);
    expectOnly(check(fixture({}, { [at('a61', 'sub.json', 'x.json')]: good() })), 'fixtures', /a61\/sub\.json: error \[fixtures\] a scenario fixture directory holds only/);
  });

  test('invalid JSON and non-objects', () => {
    expectOnly(check(fixture({}, { [at('a61', 'x.json')]: '{' })), 'fixtures', /a61\/x\.json: error \[fixtures\] not valid JSON: /);
    for (const v of ['[]', 'null', '1']) expectOnly(check(fixture({}, { [at('a61', 'x.json')]: v })), 'fixtures', /a61\/x\.json: error \[fixtures\] a fixture is a JSON object$/);
  });

  const envelope = [
    [{ fixture_version: 0 }, /fixture_version must be a positive integer/],
    [{ fixture_version: '1' }, /fixture_version must be a positive integer/],
    [{ fixture_version: 1.5 }, /fixture_version must be a positive integer/],
    [{ kind: '' }, /kind must be a non-empty string/],
    [{ scenario: 'A62' }, /scenario must be A61, the directory's scenario/],
    [{ case: 'Bad-Case' }, /case must match \^\[a-z0-9_\]\+\$/],
    [{ case: 7 }, /case must match/],
    [{ polarity: 'positive' }, /polarity must be pos or neg/],
    [{ consumers: [] }, /consumers must be distinct values of service, rust-client, ts-client, backend-verifier/],
    [{ consumers: ['service', 'service'] }, /consumers must be distinct values/],
    [{ consumers: ['browser'] }, /consumers must be distinct values/],
    [{ input: null }, /input must be an object/],
    [{ expected: 'deny' }, /expected must be an object/],
  ];
  for (const [over, re] of envelope) {
    test(`envelope: ${JSON.stringify(over)}`, () => {
      expectOnly(check(fixture({}, { [at('a61', 'x.json')]: good(over) })), 'fixtures', re);
    });
  }

  test('each envelope field is required', () => {
    for (const k of ['fixture_version', 'kind', 'scenario', 'case', 'polarity', 'consumers', 'input', 'expected']) {
      const c = JSON.parse(layoutJson);
      delete c[k];
      const res = check(fixture({}, { [at('a61', 'x.json')]: JSON.stringify(c) }));
      assert.equal(res.errors.length, 1, `${k}: ${dump(res)}`);
    }
  });

  test('both polarities and a case unique per scenario', () => {
    expectOk(check(fixture({}, { [at('a61', 'a.json')]: good({ case: 'a', polarity: 'pos' }), [at('a61', 'b.json')]: good({ case: 'b' }), [at('a62', 'a.json')]: good({ scenario: 'A62', case: 'a' }) })));
    expectOnly(check(fixture({}, { [at('a61', 'a.json')]: good({ case: 'same' }), [at('a61', 'b.json')]: good({ case: 'same' }) })), 'fixtures', /a61\/b\.json: error \[fixtures\] case same is not unique within A61$/);
  });

  test('schema files fail closed; an empty schema directory does not', () => {
    expectOnly(check(fixture({}, { [`${SCHEMAS}/fixture.v1.json`]: '{}' })), 'fixtures', /^tests\/conformance\/schema: error \[fixtures\] JSON Schema validation of fixtures is not implemented yet/);
    const root = fixture();
    mkdirSync(join(root, SCHEMAS), { recursive: true });
    expectOk(check(root));
  });
});

// ---------------------------------------------------------------------------
// Waivers

// waivers.toml text with one [[waiver]]; `over` replaces raw TOML values,
// null drops a key.
function waiver(over = {}) {
  const w = {
    commit: `"${'0'.repeat(40)}"`,
    test: `"${A24_NEG}"`,
    leg: '"scenarios-pg/x86_64"',
    run_id: '12345678901',
    run_attempt: '1',
    reason: '"runner fault"',
    expires: '2026-12-31',
    ...over,
  };
  return `[[waiver]]\n${Object.entries(w)
    .filter(([, v]) => v !== null)
    .map(([k, v]) => `${k} = ${v}`)
    .join('\n')}\n`;
}

const GIT_ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' };
function git(root, ...args) {
  const r = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', env: GIT_ENV });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

// A git root with the registry (A24 M1a implemented) committed on main; with
// `originMain`, refs/remotes/origin/main points at that commit.
function gitRoot({ originMain = true } = {}) {
  const root = fixture({ [SCENARIOS]: implementedA24 });
  git(root, 'init', '-q', '-b', 'main');
  git(root, 'add', '-A');
  git(root, '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'registry');
  if (originMain) git(root, 'update-ref', 'refs/remotes/origin/main', 'HEAD');
  return { root, head: git(root, 'rev-parse', 'HEAD') };
}
const withWaiver = (root, text) => {
  writeFileSync(join(root, WAIVERS), text);
  return root;
};

describe('rule waivers', () => {
  test('a waiver for a commit on main passes, with and without --require-history', () => {
    const { root, head } = gitRoot();
    withWaiver(root, waiver({ commit: `"${head}"` }));
    for (const requireHistory of [false, true]) {
      const res = check(root, { requireHistory });
      expectOk(res);
      assert.deepEqual(res.notes, []);
      assert.match(res.summary, /, 1 waivers$/);
    }
  });

  test('the layout §3 example waiver is valid apart from its commit', () => {
    const block = /```toml\n((?: {2}.*\n)*?) {2}```/.exec(repoText(LAYOUT).slice(repoText(LAYOUT).indexOf('[[waiver]]') - 20))[1].replace(/^ {2}/gm, '');
    const { root, head } = gitRoot();
    const t = block
      .replace(/commit = "[0-9a-f]+"/, `commit = "${head}"`)
      .replace(/test = ".*"/, `test = "${A24_NEG}"`);
    expectOk(check(withWaiver(root, t), { requireHistory: true }));
  });

  test('a commit that is not on main', () => {
    const { root, head } = gitRoot();
    const side = git(root, 'commit-tree', 'HEAD^{tree}', '-p', head, '-m', 'side');
    const res = check(withWaiver(root, waiver({ commit: `"${side}"` })));
    expectOnly(res, 'waivers', new RegExp(`^tests/conformance/waivers\\.toml:1: error \\[waivers\\] commit ${side} is not on main \\(not an ancestor of origin/main\\)$`));
  });

  test('a commit that is not in the repository', () => {
    const { root } = gitRoot();
    const res = check(withWaiver(root, waiver({ commit: `"${'f'.repeat(40)}"` })));
    expectOnly(res, 'waivers', /commit f{40} is not in this repository's history$/);
  });

  test('the line of the n-th waiver', () => {
    const { root, head } = gitRoot();
    const res = check(withWaiver(root, `${waiver({ commit: `"${head}"` })}\n${waiver({ commit: `"${head}"`, reason: '""' })}`));
    expectOnly(res, 'waivers', /waivers\.toml:10: error \[waivers\] reason must be a non-empty string$/);
  });

  for (const [name, setup, reason] of [
    ['not a git checkout', () => fixture({ [SCENARIOS]: implementedA24 }), 'the root is not a git checkout'],
    ['a subdirectory of a git checkout', () => {
      const { root } = gitRoot();
      const sub = join(root, 'nested');
      for (const rel of FILES) {
        mkdirSync(dirname(join(sub, rel)), { recursive: true });
        writeFileSync(join(sub, rel), read(root, rel));
      }
      return sub;
    }, 'the root is not a git checkout'],
    ['no origin/main', () => gitRoot({ originMain: false }).root, 'there is no refs/remotes/origin/main'],
    ['a shallow clone', () => {
      const { root } = gitRoot();
      git(root, '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'second');
      const clone = mkdtempSync(join(tmpdir(), 'check-registry-clone-'));
      roots.push(clone);
      const r = spawnSync('git', ['clone', '-q', '--depth', '1', '--no-local', `file://${root}`, clone], { encoding: 'utf8', env: GIT_ENV });
      assert.equal(r.status, 0, r.stderr);
      return clone;
    }, 'the checkout is shallow'],
  ]) {
    test(`history unavailable: ${name}`, () => {
      const root = setup();
      assert.equal(history(root).reason, reason);
      withWaiver(root, waiver({ commit: `"${'a'.repeat(40)}"` }));
      const soft = check(root);
      expectOk(soft);
      assert.deepEqual(soft.notes, [`waivers: commit reachability not checked: ${reason}`]);
      const strict = check(root, { requireHistory: true });
      assert.deepEqual(strict.errors.map(formatError), [HISTORY_ERROR(reason)]);
      assert.deepEqual(strict.notes, []);
      // The probe does not wait for a waiver: a lost fetch-depth: 0 fails at once.
      rmSync(join(root, WAIVERS));
      assert.deepEqual(check(root, { requireHistory: true }).errors.map(formatError), [HISTORY_ERROR(reason)]);
      expectOk(check(root));
    });
  }

  test('--require-history passes with the history and no waivers', () => {
    const { root } = gitRoot();
    const res = check(root, { requireHistory: true });
    expectOk(res);
    assert.deepEqual(res.notes, []);
  });

  test('history() of the repository answers yes for origin/main itself when available', () => {
    const h = history(REPO);
    if (h.reason) return assert.ok(typeof h.reason === 'string');
    assert.equal(h.onMain(git(REPO, 'rev-parse', 'refs/remotes/origin/main')), 'yes');
  });

  const fieldCases = [
    ['missing commit', { commit: null }, /missing required field commit$/],
    ['missing test', { test: null }, /missing required field test$/],
    ['missing leg', { leg: null }, /missing required field leg$/],
    ['missing run_id', { run_id: null }, /missing required field run_id$/],
    ['missing run_attempt', { run_attempt: null }, /missing required field run_attempt$/],
    ['missing reason', { reason: null }, /missing required field reason$/],
    ['missing expires', { expires: null }, /missing required field expires$/],
    ['unknown field', { approver: '"lead"' }, /unknown field approver$/],
    ['short commit', { commit: '"0123456"' }, /commit must be a full 40-character lowercase hex SHA$/],
    ['upper-case commit', { commit: `"${'A'.repeat(40)}"` }, /commit must be a full 40-character lowercase hex SHA$/],
    ['commit with a suffix', { commit: `"${'a'.repeat(41)}"` }, /commit must be a full 40-character lowercase hex SHA$/],
    ['commit not a string', { commit: '1' }, /commit must be a full 40-character lowercase hex SHA$/],
    ['unregistered test', { test: '"nextest:other"' }, /test "nextest:other" is not registered in any stage's tests$/],
    ['test not a string', { test: '1' }, /test 1 is not registered in any stage's tests$/],
    ['leg of another stage', { leg: '"scenarios-envoy-k3s/x86_64"' }, /leg "scenarios-envoy-k3s\/x86_64" is not a leg of a stage that lists nextest:skyoauth-scenarios\/pg\/security::a24::a24_neg_y$/],
    ['run_id zero', { run_id: '0' }, /run_id must be a positive integer$/],
    ['run_attempt a string', { run_attempt: '"1"' }, /run_attempt must be a positive integer$/],
    ['empty reason', { reason: '""' }, /reason must be a non-empty string$/],
    ['expires a string', { expires: '"2026-12-31"' }, /expires must be a TOML local date such as 2026-12-31$/],
  ];
  for (const [name, over, re] of fieldCases) {
    test(`field: ${name}`, () => {
      const { root, head } = gitRoot();
      const res = check(withWaiver(root, waiver({ commit: `"${head}"`, ...over })));
      expectOnly(res, 'waivers', re);
    });
  }

  test('a test listed by a planned stage is registered too', () => {
    const { root, head } = gitRoot();
    writeFileSync(join(root, SCENARIOS), st('A24', 'M2', 'tests = []', 'tests = ["nextest:a24_m2"]')(read(root, SCENARIOS)));
    expectOk(check(withWaiver(root, waiver({ commit: `"${head}"`, test: '"nextest:a24_m2"' }))));
  });

  test('the leg may come from any stage that lists the test', () => {
    const { root, head } = gitRoot();
    const t = read(root, SCENARIOS);
    const a01 = (x) => editStage(x, 'scenario', 'A01', 'M2', 'tests = []', `tests = ["${A24_NEG}"]`);
    writeFileSync(join(root, SCENARIOS), a01(t));
    expectOk(check(withWaiver(root, waiver({ commit: `"${head}"`, leg: '"live-wif-push"' }))));
  });
});

// ---------------------------------------------------------------------------
// The two TOML readers agree, and agree with Python tomllib.

// Every ```toml block of the layout doc, dedented.
const layoutExamples = () => [...repoText(LAYOUT).matchAll(/^( *)```toml\n([^]*?)\n\1```$/gm)].map((m) => m[2].replace(new RegExp(`^${m[1]}`, 'gm'), ''));

describe('values of the wrong type', () => {
  // smol-toml returns prototype-less tables: a template literal cannot
  // stringify them, so each of these used to crash the check (exit 2).
  const gateM1a = (t) => replaceOnce(t, 'gates_passed = []', 'gates_passed = ["M1a"]');
  const cases = [
    ['stage status (gated)', SCENARIOS, (t) => gateM1a(st('A24', 'M1a', 'status = "planned"', 'status = {}')(t)), 'gates', /A24 M1a: gates_passed lists M1a, but this stage is \{\}, not implemented$/],
    ['stage milestone', SCENARIOS, st('A24', 'M1a', 'milestone = "M1a"', 'milestone = {}'), 'stages', /A24 \{\}: unknown milestone/],
    ['stage implemented_sha256', SCENARIOS, st('A24', 'M1a', 'status = "planned"\ntests = []', 'status = "implemented"\nimplemented_sha256 = {}\ntests = ["x"]'), 'stages', /A24 M1a: implemented_sha256 is \{\}, but the stage's/],
    ['stage scope', SCENARIOS, st('A24', 'M1a', 'scope = "consume primitive"', 'scope = { a = 1 }'), 'stages', /A24 M1a: scope must be non-empty table text$/],
    ['stage legs element', SCENARIOS, st('A24', 'M1a', 'legs = ["scenarios-pg/x86_64"]', 'legs = [{}]'), 'stages', /A24 M1a: legs must be a non-empty list of leg strings$/],
    ['scenario matrix_sha256', SCENARIOS, sc('A24', `matrix_sha256 = "${A24_HASH}"`, 'matrix_sha256 = {}'), 'hash', /A24: matrix_sha256 is \{\}, but docs\/skyoauth-tasks\.md:/],
    ['subcase id', SUBCASES, su('A33.90', 'id = "A33.90"', 'id = {}'), 'ids', /subcases\.toml: error \[ids\] \{\}: a sub-ID looks like A58\.07$/],
    ['subcase parent', SUBCASES, su('A33.90', 'parent = "A33"', 'parent = { a = 1 }'), 'subcases', /A33\.90: parent must be the registered scenario A33$/],
    ['subcase conditional_on', SUBCASES, su('A33.90', 'conditional_on = "back-channel-logout"', 'conditional_on = {}'), 'subcases', /A33\.90: conditional_on must be one of /],
    ['subcase first owner', SUBCASES, su('A33.90', 'owners = ["T30.6"]', 'owners = [{}]'), 'hash', /A33\.90: the first owner must be a task/],
    ['subcase matrix_sha256', SUBCASES, (t) => t.replace(/(id = "A33\.90"[^]*?)matrix_sha256 = "[0-9a-f]+"/, '$1matrix_sha256 = {}'), 'hash', /A33\.90: matrix_sha256 is \{\}, but the docs\/skyoauth-tasks\.md line of T30\.6/],
  ];
  for (const [name, rel, edit, rule, re] of cases) {
    test(`an inline table as ${name} is a diagnostic, not a crash`, () => {
      expectError(failing(rel, edit), rule, re);
    });
  }

  // The generator's fuzz of the same keys (gen-conformance-registry.test.mjs):
  // smol-toml's tables have no prototype, so an own toString key is an
  // ordinary key there and show() prints the table as JSON.
  for (const value of ['{ toString = 1 }', '{ toString = "x", valueOf = 1 }', '[{ toString = 1 }]']) {
    test(`every key of A24, C07 and A33.90 as ${value}`, () => {
      const cases = [
        ['gates_passed', SCENARIOS, replaceOnce(repoText(SCENARIOS), 'gates_passed = []', `gates_passed = ${value}`)],
        ...valueSwaps(repoText(SCENARIOS), 'scenario', 'A24', value, { entry: ['note'], stage: ['implemented_sha256'] }).map(([l, t]) => [l, SCENARIOS, t]),
        ...valueSwaps(repoText(SCENARIOS), 'scenario', 'C07', value).map(([l, t]) => [l, SCENARIOS, t]),
        ...valueSwaps(repoText(SUBCASES), 'subcase', 'A33.90', value, { stage: ['implemented_sha256'] }).map(([l, t]) => [l, SUBCASES, t]),
      ];
      assert.ok(cases.length >= 40, String(cases.length));
      for (const [label, rel, text] of cases) {
        const res = failing(rel, () => text);
        assert.ok(res.errors.length > 0, label);
        assert.ok(!res.errors.some((e) => e.rule === 'toml'), `${label}\n${dump(res)}`);
        assert.doesNotMatch(dump(res), /\[object /, label);
      }
    });
  }

  test('the CLI exits 1 for one', () => {
    const r = spawnSync(process.execPath, [SCRIPT, '--root', fixture({ [SCENARIOS]: st('A24', 'M1a', 'milestone = "M1a"', 'milestone = {}') })], { encoding: 'utf8' });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /error \[stages\] A24 \{\}: unknown milestone/);
    assert.doesNotMatch(r.stderr, /internal error/);
  });
});

describe('malformed subcases are diagnostics, not crashes', () => {
  const tt = /table_text = .*/.exec(entryBlock(repoText(SUBCASES), 'subcase', 'A33.90'))[0];
  const notCompared = (res) => {
    assert.deepEqual(res.notes, ['table: not compared, because some scenario or subcase fields are invalid']);
    assert.ok(!res.errors.some((e) => e.rule === 'table'), dump(res));
  };
  // Each conditional branch that does not parse table_text still renders it
  // into the parent row; a table there used to crash the table rule (exit 2).
  for (const [name, edit, re] of [
    ['a conditional sub-ID numbered outside .90–.99', (t) => su('A33.90', tt, 'table_text = {}')(t).replaceAll('A33.90', 'A33.50'), /A33\.50: a conditional sub-ID is numbered A33\.90–A33\.99$/],
    ['an unknown conditional_on', (t) => su('A33.90', tt, 'table_text = { a = 1 }')(su('A33.90', 'conditional_on = "back-channel-logout"', 'conditional_on = "magic"')(t)), /A33\.90: conditional_on must be one of /],
  ]) {
    test(`${name} with a table as table_text`, () => {
      const res = failing(SUBCASES, edit);
      expectError(res, 'subcases', re);
      notCompared(res);
    });
  }

  test('the CLI exits 1 for one', () => {
    const root = fixture({ [SUBCASES]: (t) => su('A33.90', tt, 'table_text = {}')(su('A33.90', 'conditional_on = "back-channel-logout"', 'conditional_on = "magic"')(t)) });
    const r = spawnSync(process.execPath, [SCRIPT, '--root', root], { encoding: 'utf8' });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /error \[subcases\] A33\.90: conditional_on must be one of /);
    assert.doesNotMatch(r.stderr, /internal error/);
  });

  // annexRange() used to build a regex from the ID or parent.
  for (const [name, id, parent, re] of [
    ['a parent with a regex metacharacter', 'A58.05', 'A5(', /A58\.05: parent must be the registered scenario A58$/],
    ['an ID with a regex metacharacter', 'A5(.05', 'A58', /A5\(\.05: a sub-ID looks like A58\.07$/],
    ['an ID with a regex metacharacter in its number', 'A58.0(', 'A58', /A58\.0\(: a sub-ID looks like A58\.07$/],
  ]) {
    test(`a required sub-ID: ${name}`, () => {
      const root = fixture({ [SUBCASES]: (t) => t + requiredA58(id).replace(`id = "${id}"\nkind = "subcase"\nparent = "A58"`, `id = "${id}"\nkind = "subcase"\nparent = "${parent}"`) });
      expectError(check(root), id === 'A58.05' ? 'subcases' : 'ids', re);
      const r = spawnSync(process.execPath, [SCRIPT, '--root', root], { encoding: 'utf8' });
      assert.equal(r.status, 1, r.stderr);
      assert.doesNotMatch(r.stderr, /internal error/);
    });
  }

  test('a required sub-ID under an unregistered parent has no annex range', () => {
    const res = failing(SUBCASES, (t) => t + requiredA58('A58.05').replace('parent = "A58"', 'parent = "A.8"'));
    expectError(res, 'subcases', /A58\.05: required sub-ID, but the note of A\.8 declares no annex range$/);
  });
});

describe('names of Object.prototype members in the specs', () => {
  test('a feature label such as toString is not a feature', () => {
    for (const label of ['toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      assert.equal(parseConditional(`Conditional sub-ID A58.90 (${label}, T32.9): x`).feature, null, label);
      assert.equal(FEATURES[label], undefined, label);
    }
    const res = failing(SUBCASES, su('A58.90', '(ForwardAuth, T32.9)', '(toString, T32.9)'));
    expectError(res, 'subcases', /A58\.90: table_text names feature toString, but conditional_on is forwardauth$/);
  });

  test('a job named constructor has no first milestone', () => {
    assert.equal(JOB_FROM.constructor, undefined);
    assert.equal(JOB_FROM.toString, undefined);
    const res = failing(LAYOUT, (t) => replaceOnce(t, '`typescript/node24`, ', '`typescript/node24`, `constructor`, '));
    expectError(res, 'legs', /job constructor of the layout §1\.1 Leg strings column has no known first milestone \(add it to JOB_FROM\)$/);
  });
});

describe('conditional features belong to their tasks', () => {
  test('a conditional sub-ID owned by another task is reported', () => {
    const res = failing(SUBCASES, su('A33.90', 'owners = ["T30.6"]', 'owners = ["T31.2", "T30.6"]'));
    expectError(res, 'subcases', /A33\.90: conditional_on back-channel-logout is the feature of task T30\.6, but the first owner is T31\.2$/);
  });

  test('the committed conditional sub-IDs are owned by their feature tasks', () => {
    const owners = Object.fromEntries(parseStrict(repoText(SUBCASES)).subcase.filter((s) => s.conditional_on).map((s) => [s.id, `${s.conditional_on} ${s.owners[0]}`]));
    assert.deepEqual(owners, { 'A18.90': 'forwardauth T32.9', 'A27.90': 'device-flow T40.6', 'A33.90': 'back-channel-logout T30.6', 'A58.90': 'forwardauth T32.9' });
  });
});

describe('smol-toml and the generator reader', () => {
  test('return the same data for the committed registry files', () => {
    for (const rel of [SCENARIOS, SUBCASES]) {
      const text = repoText(rel);
      assert.deepEqual(plain(parseToml(text, rel)), plain(parseStrict(text)), rel);
    }
  });

  test('return the same data for the layout §3 examples, the waiver date included', () => {
    const blocks = layoutExamples();
    assert.equal(blocks.length, 3);
    for (const b of blocks) assert.deepEqual(plain(parseToml(b)), plain(parseStrict(b)));
    const w = parseStrict(blocks[2]).waiver[0];
    assert.ok(w.expires instanceof TomlDate && w.expires.isDate());
    assert.deepEqual(plain(parseToml(blocks[2]).waiver[0].expires), { date: '2026-12-31' });
  });

  test('dates: leap days, month ends, and the forms only smol-toml accepts', () => {
    for (const d of ['2024-02-29', '2026-12-31', '2026-01-01', '2000-02-29']) {
      const t = `d = ${d}\n`;
      assert.deepEqual(plain(parseToml(t)), plain(parseStrict(t)), d);
      assert.ok(parseToml(t).d instanceof LocalDate);
    }
    for (const d of ['2026-02-29', '2100-02-29', '2026-04-31', '2026-13-01', '2026-00-10', '2026-01-00']) assert.throws(() => parseToml(`d = ${d}\n`), /invalid date/, d);
    for (const d of ['2026-12-31T00:00:00', '2026-12-31T00:00:00Z', '2026-12-31 00:00:00', '2026-12-31t00:00:00']) assert.throws(() => parseToml(`d = ${d}\n`), /only local dates/, d);
  });

  test('plain()', () => {
    assert.deepEqual(plain({ a: [1, 'x', { d: new LocalDate('2026-12-31') }], b: parseStrict('d = 2026-12-31').d, c: null, e: true }), {
      a: [1, 'x', { d: { date: '2026-12-31' } }],
      b: { date: '2026-12-31' },
      c: null,
      e: true,
    });
  });

  const python = spawnSync('python3', ['-c', 'import tomllib'], { encoding: 'utf8' });
  test('and Python tomllib', { skip: python.status === 0 ? false : 'python3 with tomllib (3.11+) is not installed' }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'check-registry-py-'));
    roots.push(dir);
    const texts = [repoText(SCENARIOS), repoText(SUBCASES), ...layoutExamples()];
    texts.forEach((t, i) => writeFileSync(join(dir, `${i}.toml`), t));
    const py = [
      'import datetime, json, sys, tomllib',
      'def p(v):',
      '    if isinstance(v, datetime.datetime) or isinstance(v, datetime.time): raise SystemExit("unexpected date-time")',
      '    if isinstance(v, datetime.date): return {"date": v.isoformat()}',
      '    if isinstance(v, list): return [p(x) for x in v]',
      '    if isinstance(v, dict): return {k: p(x) for k, x in v.items()}',
      '    return v',
      'print(json.dumps([p(tomllib.load(open(f, "rb"))) for f in sys.argv[1:]]))',
    ].join('\n');
    const r = spawnSync('python3', ['-I', '-c', py, ...texts.map((_, i) => join(dir, `${i}.toml`))], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), texts.map((t) => plain(parseToml(t))));
    // tomllib rejects the date that smol-toml rolls over.
    writeFileSync(join(dir, 'bad.toml'), 'd = 2026-02-30\n');
    assert.notEqual(spawnSync('python3', ['-I', '-c', py, join(dir, 'bad.toml')], { encoding: 'utf8' }).status, 0);
  });
});
