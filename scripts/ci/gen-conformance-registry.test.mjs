// Self-test for gen-conformance-registry.mjs:
//   node --test scripts/ci/gen-conformance-registry.test.mjs
//
// Each case copies the three specs and the two committed registry files into
// a temporary root, changes exactly one thing, and runs the generator there.
// The repository itself is only read.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  DESIGN,
  generate,
  LAYOUT,
  parseLayoutRow,
  parseToml,
  renderLayoutRow,
  run,
  SCENARIOS,
  sha256,
  SUBCASES,
  TASKS,
} from './gen-conformance-registry.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'gen-conformance-registry.mjs');
const REPO = join(dirname(SCRIPT), '..', '..');
const FILES = [TASKS, DESIGN, LAYOUT, SCENARIOS, SUBCASES];

const roots = [];
after(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

// A temporary root holding copies of FILES, with `edit(rel, text)` applied.
function fixture(edit = (_rel, text) => text) {
  const root = mkdtempSync(join(tmpdir(), 'gen-registry-'));
  roots.push(root);
  for (const rel of FILES) {
    const text = edit(rel, readFileSync(join(REPO, rel), 'utf8'));
    if (text === null) continue;
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

const read = (root, rel) => readFileSync(join(root, rel), 'utf8');

// Runs the CLI and returns { status, stderr, stdout }.
function cli(...args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });
}

// Replaces exactly one occurrence of `from` in `text`.
function replaceOnce(text, from, to) {
  const i = text.indexOf(from);
  assert.ok(i >= 0, `fixture text not found: ${from}`);
  assert.equal(text.indexOf(from, i + 1), -1, `fixture text not unique: ${from}`);
  return text.slice(0, i) + to + text.slice(i + from.length);
}

const specLine = (text, id) => text.split('\n').find((l) => l.startsWith(`| ${id} |`));

describe('committed registry', () => {
  test('--check passes on the repository', () => {
    const r = cli('--root', REPO, '--check');
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /up to date/);
  });

  test('64 scenarios, 10 contracts, 4 subcases', () => {
    const doc = parseToml(read(REPO, SCENARIOS));
    const kinds = doc.scenario.map((e) => e.kind);
    assert.equal(kinds.filter((k) => k === 'scenario').length, 64);
    assert.equal(kinds.filter((k) => k === 'contract').length, 10);
    assert.deepEqual(doc.gates_passed, []);
    const subs = parseToml(read(REPO, SUBCASES)).subcase.map((s) => s.id);
    assert.deepEqual(subs, ['A18.01', 'A27.01', 'A33.01', 'A58.01']);
  });

  test('layout §3 example hashes (A24, A64, C07) are reproduced', () => {
    const byId = new Map(parseToml(read(REPO, SCENARIOS)).scenario.map((e) => [e.id, e]));
    assert.equal(byId.get('A24').matrix_sha256, 'b4df384e7893902f52bfcb5eb9415561d902b68c07ba0ca12972bb8c6e026443');
    assert.equal(byId.get('A64').matrix_sha256, '078ca6a19a34b32f05d2982cb296c71cf5a182e64f2e6589767807fd36eaeec3');
    assert.equal(byId.get('C07').matrix_sha256, '060bdd6d1424c821626c7f63561da93b9fbf89a6869d9f363128efca9fcbbf0b');
    assert.deepEqual(byId.get('C07').covered_by, ['A15', 'A35']);
  });

  test('generation is idempotent and deterministic', () => {
    const root = fixture();
    assert.equal(run(['--root', root], () => {}, () => {}), 0);
    const once = [read(root, SCENARIOS), read(root, SUBCASES)];
    assert.equal(once[0], read(REPO, SCENARIOS));
    assert.equal(once[1], read(REPO, SUBCASES));
    assert.equal(run(['--root', root], () => {}, () => {}), 0);
    assert.deepEqual([read(root, SCENARIOS), read(root, SUBCASES)], once);
  });

  test('every layout §2 row renders back from the registry', () => {
    const layout = read(REPO, LAYOUT);
    const { entries, errors, codes } = generate(REPO);
    assert.deepEqual(errors, []);
    for (const e of entries.scenarios) {
      const sentences = entries.subcases.filter((s) => s.parent === e.id && s.conditional_on).map((s) => s.table_text);
      assert.equal(renderLayoutRow(e, codes, sentences), specLine(layout, e.id));
    }
    // A18, A27, A33 and A58 end with a conditional sub-ID sentence from subcases.toml.
    assert.equal(entries.subcases.filter((s) => s.conditional_on).length, 4);
  });

  test('every leg is a §1.1 leg string whose env is one of the entry envs', () => {
    const { entries, catalogue } = generate(REPO);
    assert.ok(catalogue.size > 0);
    for (const e of [...entries.scenarios, ...entries.subcases]) {
      for (const s of e.stages) {
        for (const leg of s.legs) {
          assert.ok(catalogue.has(leg), `${e.id}: ${leg}`);
          assert.ok(e.envs.includes(catalogue.get(leg).env), `${e.id}: ${leg}`);
        }
      }
    }
  });

  test('the §1.1 Leg strings column is the leg catalogue', () => {
    const { catalogue } = generate(REPO);
    assert.deepEqual(catalogue.get('typescript/node24'), { job: 'typescript', env: 'hermetic' });
    assert.deepEqual(catalogue.get('live-wif'), { job: 'live-wif', env: 'live' });
    assert.deepEqual(catalogue.get('deployed-topology-audit'), { job: 'deployed-topology-audit', env: 'envoy-k3s' });
    assert.deepEqual(catalogue.get('clients-rust/x86_64'), { job: 'clients-rust', env: 'hermetic' });
  });

  test('registry fields follow the lead decisions on the table notation', () => {
    const doc = parseToml(read(REPO, SCENARIOS));
    const byId = new Map(doc.scenario.map((e) => [e.id, e]));
    assert.deepEqual(byId.get('A01').harness, ['FX', 'GH', 'PG', 'GH-live', 'ENV', 'RB']);
    assert.deepEqual(byId.get('A02').harness, ['GH', 'PG claim-mutation table', 'GH-live']);
    assert.deepEqual(byId.get('A14').envs, ['envoy-k3s']);
    assert.deepEqual(byId.get('A42').envs, ['hermetic', 'envoy-k3s', 'browser', 'native-3os']);
    assert.equal(byId.get('A58').note, 'Sub-IDs A58.01… in the annex (Q1):');
    assert.equal(byId.get('A62').note, 'Internal signer group only (Q5).');
    for (const e of doc.scenario) {
      for (const k of ['env_notes', 'pos_neg_prefix', 'pos_neg_suffix']) assert.ok(!(k in e), `${e.id} has ${k}`);
      assert.ok(!JSON.stringify(e).includes('\u2011'), `${e.id} has U+2011`);
    }
    for (const id of ['A18', 'A58', 'A62']) {
      const last = byId.get(id).stage.at(-1);
      assert.deepEqual([last.milestone, last.scope, last.legs], ['M5', 'deployed-topology audit', ['deployed-topology-audit']]);
    }
  });
});

describe('drift is detected', () => {
  test('an edited tasks §8 row fails --check with a hash mismatch', () => {
    const root = fixture((rel, t) =>
      rel === TASKS ? replaceOnce(t, 'Exactly one issuance, missing jti', 'Exactly one issuance, absent jti') : t,
    );
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    const want = sha256(specLine(read(root, TASKS), 'A24'));
    assert.match(r.stderr, new RegExp(`A24: matrix_sha256 is b4df384e[0-9a-f]+, but its spec line hashes to ${want}`));
  });

  test('an edited design §2 row fails --check with a hash mismatch', () => {
    const root = fixture((rel, t) => (rel === DESIGN ? replaceOnce(t, 'Consumed-proof state is not reset.', 'Consumed proofs stay consumed.') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /C07: matrix_sha256 is 060bdd6d/);
  });

  test('an edited subcase source task line fails --check', () => {
    const root = fixture((rel, t) => (rel === TASKS ? replaceOnce(t, '**T40.6** Device flow conditional:', '**T40.6** Device flow, conditional:') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /A27\.01: matrix_sha256 is 02c64cda/);
  });

  test('an edited layout §2 cell fails --check on that field', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '| A26 | C | PG | PG, UC |', '| A26 | C | PG | PG, UC, FX |') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /A26: harness differs from the specs/);
  });

  test('a new env in the layout table needs legs before it passes', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '| A26 | C | PG |', '| A26 | C | H, PG |') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /A26: env hermetic has no leg in any stage/);
  });

  test('a hand-edited derived field fails --check', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'negative = "missing jti, replay, store failure"', 'negative = "replay"') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /A24: negative differs from the specs/);
  });

  test('a formatting-only change fails --check with a line number', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'gates_passed = []', 'gates_passed = [ ]') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /scenarios\.toml:6: formatting differs/);
  });

  test('a scenario missing from the registry fails --check', () => {
    const root = fixture((rel, t) => {
      if (rel !== SCENARIOS) return t;
      const start = t.indexOf('[[scenario]]\nid = "A33"');
      const end = t.indexOf('[[scenario]]\nid = "A34"');
      return t.slice(0, start) + t.slice(end);
    });
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /A33 is missing/);
  });

  test('a missing registry file fails --check', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? null : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /scenarios\.toml: missing/);
  });

  test('a missing subcases file fails on every named sub-ID', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? null : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    for (const re of [/A27\.01 \(device-flow/, /A33\.01 \(back-channel-logout/, /sub-ID of A18 \(forwardauth/, /sub-ID of A58 \(forwardauth/]) assert.match(r.stderr, re);
  });
});

describe('spec errors stop generation', () => {
  const errorsOf = (root) => generate(root).errors.join('\n');

  test('a tasks §8 row removed leaves a gap', () => {
    const root = fixture((rel, t) => (rel === TASKS ? t.replace(`${specLine(t, 'A40')}\n`, '') : t));
    assert.match(errorsOf(root), /expected A40, found A41/);
    assert.match(errorsOf(root), /§2 row A40 is not a scenario/);
  });

  test('a layout §2 row removed is a missing scenario', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? t.replace(`${specLine(t, 'A12')}\n`, '') : t));
    assert.match(errorsOf(root), /scenario A12 of docs\/skyoauth-tasks\.md §8 has no row in the §2 table/);
    // and the CLI writes nothing
    const before = read(root, SCENARIOS);
    assert.equal(cli('--root', root).status, 1);
    assert.equal(read(root, SCENARIOS), before);
  });

  test('a duplicate contract row', () => {
    const root = fixture((rel, t) => (rel === DESIGN ? t.replace(`${specLine(t, 'C03')}\n`, (l) => l + l) : t));
    assert.match(errorsOf(root), /duplicate contract row C03/);
  });

  test('an owner that is not a task', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '| T12.8, T21.5 |', '| T12.8, T21.99 |') : t));
    assert.match(errorsOf(root), /A26: owner T21\.99 is not a task/);
  });

  test('a contract without a covered_by mapping', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? t.replace(/^\| C05 .*\n/m, '') : t));
    assert.match(errorsOf(root), /contract C05 has no "Covered by" row/);
  });

  test('an unknown leg in a hand-authored stage', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'legs = ["scenarios-pg/x86_64"]', 'legs = ["scenarios-pg/arm"]') : t));
    assert.match(errorsOf(root), /A33\.01 M3: unknown leg "scenarios-pg\/arm"/);
  });

  test('a leg whose job is outside the entry envs', () => {
    const root = fixture((rel, t) =>
      rel === SCENARIOS ? t.replace(/(id = "A26"[\s\S]*?legs = )\["scenarios-pg\/x86_64"\]/, '$1["scenarios-pg/x86_64", "live-wif"]') : t,
    );
    assert.match(errorsOf(root), /A26 M1a: leg "live-wif" belongs to env live/);
  });

  test('an unparsable stage cell', () => {
    assert.throws(
      () => parseLayoutRow('| A99 | C | PG | PG | M2 · M3 | T10.1 | + a; − b |', 'x', { PG: 'pg' }),
      /stage "M2" of a multi-stage row has no scope/,
    );
    assert.throws(() => parseLayoutRow('| A99 | C | PG | PG | M2 | T10.1 | + a, − b |', 'x', { PG: 'pg' }), /exactly one/);
    assert.throws(() => parseLayoutRow('| A99 | X | PG | PG | M2 | T10.1 | + a; − b |', 'x', { PG: 'pg' }), /unknown layer/);
    assert.throws(() => parseLayoutRow('| A99 | C | XX | PG | M2 | T10.1 | + a; − b |', 'x', { PG: 'pg' }), /unknown env "XX"/);
    assert.throws(
      () => parseLayoutRow('| A99 | C | PG | PG | M2 | T10.1 | + a; − b. Conditional sub-ID A99.01 (magic, T10.1): x |', 'x', { PG: 'pg' }),
      /unknown conditional feature "magic"/,
    );
    assert.throws(
      () => parseLayoutRow('| A99 | C | PG | PG | M2 | T10.1 | + a; − b. Conditional sub-ID A98.01 (device flow, T10.1): x |', 'x', { PG: 'pg' }),
      /A98\.01 is not a sub-ID of A99/,
    );
  });

  test('a note before "+" and a trailing conditional sentence', () => {
    const e = parseLayoutRow('| A99 | C | PG | PG | M2 | T10.1 | Only this (Q9). + a; − b. Conditional sub-ID (ForwardAuth, T32.9): x |', 'x', { PG: 'pg' });
    assert.equal(e.note, 'Only this (Q9).');
    assert.deepEqual([e.positive, e.negative], ['a', 'b']);
    assert.deepEqual(
      e.conditional.map((c) => [c.id, c.feature, c.task, c.text]),
      [[null, 'forwardauth', 'T32.9', 'Conditional sub-ID (ForwardAuth, T32.9): x']],
    );
  });
});

// 1-based line of the n-th (0-based) occurrence of `needle` in `text`.
function lineOf(text, needle, n = 0) {
  let i = -1;
  for (let k = 0; k <= n; k++) {
    i = text.indexOf(needle, i + 1);
    assert.ok(i >= 0, `not found: ${needle}`);
  }
  return text.slice(0, i).split('\n').length;
}

// The block of `[[table]]` entry `id`, from its header to the next entry header.
function entryBlock(text, table, id) {
  const start = text.indexOf(`[[${table}]]\nid = "${id}"`);
  assert.ok(start >= 0, `no ${table} ${id}`);
  const next = text.indexOf(`[[${table}]]\n`, start + 1);
  return text.slice(start, next < 0 ? text.length : next);
}

// Both modes must fail with `re` and the write mode must leave the files alone.
function failsBothModes(root, re) {
  const before = [read(root, SCENARIOS), read(root, SUBCASES)];
  for (const args of [['--root', root], ['--root', root, '--check']]) {
    const r = cli(...args);
    assert.equal(r.status, 1, `${args.join(' ')}: ${r.stderr}`);
    assert.match(r.stderr, re);
  }
  assert.deepEqual([read(root, SCENARIOS), read(root, SUBCASES)], before);
}

describe('duplicate keys in the committed files are rejected', () => {
  test('a second stage with the same scenario and milestone', () => {
    let dupLine;
    const root = fixture((rel, t) => {
      if (rel !== SCENARIOS) return t;
      const stage = '[[scenario.stage]]\nmilestone = "M1a"\nscope = "consume primitive"\nlegs = ["scenarios-pg/x86_64"]\nstatus = "planned"\ntests = []\n\n';
      const block = entryBlock(t, 'scenario', 'A24');
      const out = replaceOnce(t, block, block.replace(stage, stage + stage));
      dupLine = lineOf(out, stage, 1);
      return out;
    });
    const first = lineOf(read(root, SCENARIOS), '[[scenario.stage]]\nmilestone = "M1a"\nscope = "consume primitive"');
    failsBothModes(root, new RegExp(`scenarios\\.toml:${dupLine}: duplicate stage A24 M1a \\(first at line ${first}\\)`));
  });

  test('a duplicate scenario ID', () => {
    const root = fixture((rel, t) => {
      if (rel !== SCENARIOS) return t;
      const block = entryBlock(t, 'scenario', 'A24');
      return replaceOnce(t, block, block + block);
    });
    const text = read(root, SCENARIOS);
    failsBothModes(root, new RegExp(`scenarios\\.toml:${lineOf(text, '[[scenario]]\nid = "A24"', 1)}: duplicate scenario A24 \\(first at line ${lineOf(text, '[[scenario]]\nid = "A24"')}\\)`));
  });

  test('a duplicate contract ID', () => {
    const root = fixture((rel, t) => {
      if (rel !== SCENARIOS) return t;
      const block = entryBlock(t, 'scenario', 'C07');
      return replaceOnce(t, block, `${block}\n${block}`);
    });
    const text = read(root, SCENARIOS);
    failsBothModes(root, new RegExp(`scenarios\\.toml:${lineOf(text, '[[scenario]]\nid = "C07"', 1)}: duplicate scenario C07`));
  });

  test('a duplicate subcase ID', () => {
    const root = fixture((rel, t) => {
      if (rel !== SUBCASES) return t;
      const block = entryBlock(t, 'subcase', 'A33.01');
      return replaceOnce(t, block, block + block);
    });
    const text = read(root, SUBCASES);
    failsBothModes(root, new RegExp(`subcases\\.toml:${lineOf(text, '[[subcase]]\nid = "A33.01"', 1)}: duplicate subcase A33\\.01`));
  });

  test('a second stage with the same subcase and milestone', () => {
    const root = fixture((rel, t) => {
      if (rel !== SUBCASES) return t;
      const block = entryBlock(t, 'subcase', 'A33.01');
      const stage = block.slice(block.indexOf('[[subcase.stage]]'));
      return replaceOnce(t, block, block.trimEnd() + '\n\n' + stage);
    });
    const text = read(root, SUBCASES);
    const at = text.indexOf('[[subcase]]\nid = "A33.01"');
    const dup = text.slice(0, text.indexOf('[[subcase.stage]]', text.indexOf('[[subcase.stage]]', at) + 1)).split('\n').length;
    failsBothModes(root, new RegExp(`subcases\\.toml:${dup}: duplicate stage A33\\.01 M3`));
  });
});

describe('subcases match the sub-IDs the layout doc names', () => {
  test('a named sub-ID missing from subcases.toml', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? t.replace(entryBlock(t, 'subcase', 'A27.01'), '') : t));
    failsBothModes(root, /A27\.01 \(device-flow, T40\.6\) is named in .*conformance-layout\.md.* but missing from tests\/conformance\/subcases\.toml/);
  });

  test('an unnumbered named sub-ID missing from subcases.toml', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? t.replace(entryBlock(t, 'subcase', 'A18.01'), '') : t));
    failsBothModes(root, /sub-ID of A18 \(forwardauth, T32\.9\) is named in .* but missing/);
  });

  test('a wrong parent', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'parent = "A27"', 'parent = "A28"') : t));
    failsBothModes(root, /A27\.01: parent is A28, but the layout doc names it under A27/);
  });

  test('a wrong conditional_on', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'conditional_on = "device-flow"', 'conditional_on = "forwardauth"') : t));
    failsBothModes(root, /A27\.01: conditional_on is forwardauth, but the layout doc names device-flow/);
  });

  test('a wrong source task', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'owners = ["T30.6"]', 'owners = ["T31.2"]') : t));
    failsBothModes(root, /A33\.01: first owner is T31\.2, but the layout doc names T30\.6/);
  });

  test('a sub-ID the layout doc does not name', () => {
    const root = fixture((rel, t) => {
      if (rel !== SUBCASES) return t;
      const extra = entryBlock(t, 'subcase', 'A33.01').replace('id = "A33.01"', 'id = "A33.02"');
      return `${t.trimEnd()}\n\n${extra}`;
    });
    failsBothModes(root, /A33\.02 is not a sub-ID named in .*conformance-layout\.md/);
  });

  test('a renumbered sub-ID in the layout doc', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, 'Conditional sub-ID A33.01 (back-channel', 'Conditional sub-ID A33.02 (back-channel') : t));
    failsBothModes(root, /A33\.02 \(back-channel-logout, T30\.6\) is named in .* but missing/);
  });
});

describe('the §1.1 leg catalogue', () => {
  test('a leg that the Leg strings column no longer lists', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '`typescript/node22`, `typescript/node24`, ', '`typescript/node22`, ') : t));
    failsBothModes(root, /A39 M3: unknown leg "typescript\/node24" \(not in the layout §1\.1 Leg strings column\)/);
  });

  test('a job whose first milestone the generator does not know', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '`scenarios-pg/x86_64` |', '`scenarios-pg/x86_64`, `scenarios-pg-extra` |') : t));
    failsBothModes(root, /job scenarios-pg-extra of the layout §1\.1 Leg strings column has no known first milestone/);
  });

  test('a leg string listed under two envs', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '`scenarios-pg/x86_64` |', '`scenarios-pg/x86_64`, `live-wif` |') : t));
    failsBothModes(root, /leg live-wif is listed under both pg and live/);
  });

  test('a §1.1 table without the Leg strings column', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '| CI job (legs) | Leg strings |', '| CI job (legs) | Legs |') : t));
    failsBothModes(root, /layout §1\.1 table has no "Leg strings" column/);
  });
});

describe('conditional sub-ID sentences are rendered from subcases.toml', () => {
  test('an edited table_text no longer renders the parent row', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'user-code approval, expiry/polling abuse, no interaction bypass"', 'user-code approval"') : t));
    failsBothModes(root, /A27: rendered row differs from the committed row/);
  });

  test('a table_text that names another task than the first owner', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, '(device flow, T40.6)', '(device flow, T40.7)') : t));
    failsBothModes(root, /A27\.01: table_text names T40\.7, but the first owner is T40\.6/);
  });

  test('a table_text whose feature does not match conditional_on', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'Conditional sub-ID A33.01 (back-channel logout,', 'Conditional sub-ID A33.01 (device flow,') : t));
    failsBothModes(root, /A33\.01: table_text names device-flow, but conditional_on is back-channel-logout/);
  });

  test('an edited sentence in the layout row', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '(back-channel logout, T30.6): verified sid targeting', '(back-channel logout, T30.6): verified sid targeting only') : t));
    failsBothModes(root, /A33: rendered row differs from the committed row/);
  });
});

describe('hand-authored fields are kept', () => {
  test('legs, status, tests and gates_passed survive regeneration', () => {
    const tests = 'tests = [\n  "nextest:skyoauth-scenarios/pg/security::a24::a24_pos_x",\n  "nextest:skyoauth-scenarios/pg/security::a24::a24_neg_y",\n]';
    const root = fixture((rel, t) => {
      if (rel !== SCENARIOS) return t;
      t = replaceOnce(t, 'gates_passed = []', 'gates_passed = ["M0", "M1a"]');
      return t.replace(/(id = "A24"[\s\S]*?milestone = "M1a"[\s\S]*?)status = "planned"\ntests = \[\]/, `$1status = "implemented"\n${tests}`);
    });
    const before = read(root, SCENARIOS);
    assert.notEqual(before, read(REPO, SCENARIOS));
    assert.equal(run(['--root', root], () => {}, () => {}), 0);
    assert.equal(read(root, SCENARIOS), before);
    assert.equal(cli('--root', root, '--check').status, 0);
  });

  test('a stage without committed legs gets the default legs', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? null : t));
    assert.equal(run(['--root', root], () => {}, () => {}), 0);
    const doc = parseToml(read(root, SCENARIOS));
    assert.deepEqual(doc.gates_passed, []);
    const byId = new Map(doc.scenario.map((e) => [e.id, e]));
    assert.deepEqual(byId.get('A14').stage[0].legs, ['migration-rehearsal']);
    assert.deepEqual(byId.get('A62').stage[1].legs, ['deployed-topology-audit']);
    assert.deepEqual(byId.get('A24').stage[0].legs, ['scenarios-pg/x86_64']);
    assert.equal(cli('--root', root, '--check').status, 0);
  });
});

describe('TOML', () => {
  test('strings with quotes, backslashes and control characters round-trip', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '+ selected source verifies;', '+ "selected" \\ source\tverifies;') : t));
    const { files, errors } = generate(root);
    assert.deepEqual(errors, []);
    const a03 = parseToml(files[SCENARIOS]).scenario.find((e) => e.id === 'A03');
    assert.equal(a03.positive, '"selected" \\ source\tverifies');
  });

  test('python3 tomllib parses both files', (t) => {
    const probe = spawnSync('python3', ['-c', 'import tomllib'], { encoding: 'utf8' });
    if (probe.error || probe.status !== 0) {
      t.skip('python3 with tomllib (3.11+) not available');
      return;
    }
    for (const rel of [SCENARIOS, SUBCASES]) {
      const r = spawnSync('python3', ['-I', '-c', 'import sys, tomllib, json; print(json.dumps(tomllib.load(open(sys.argv[1], "rb"))))', join(REPO, rel)], {
        encoding: 'utf8',
      });
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(JSON.parse(r.stdout), parseToml(read(REPO, rel)));
    }
  });
});
