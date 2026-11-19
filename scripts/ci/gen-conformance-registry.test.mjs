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
  LocalDate,
  parseConditional,
  parseToml,
  renderLayoutRow,
  rowConditionals,
  stageStamp,
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
    assert.deepEqual(subs, ['A18.90', 'A27.90', 'A33.90', 'A58.90']);
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
    assert.deepEqual(catalogue.get('live-wif-push'), { job: 'live-wif-push', env: 'live' });
    assert.deepEqual(catalogue.get('live-wif-negative'), { job: 'live-wif-negative', env: 'live' });
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
    assert.equal(byId.get('A58').note, 'Sub-IDs A58.01–A58.89 in the annex (Q1):');
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
    assert.match(r.stderr, /A27\.90: matrix_sha256 is 02c64cda/);
  });

  test('a hand-edited §2 table row fails --check, and the write mode renders it back', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '| A26 | C | PG | PG, UC |', '| A26 | C | PG | PG, UC, FX |') : t));
    const line = lineOf(read(root, LAYOUT), '| A26 |');
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, new RegExp(`conformance-layout\\.md:${line}: §2 row A26 differs from the table rendered from the registry`));
    assert.equal(cli('--root', root).status, 0);
    assert.equal(read(root, LAYOUT), read(REPO, LAYOUT));
  });

  test('an edited registry column is rendered into the §2 table', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'harness = ["PG", "UC"]\nowners = ["T12.8", "T21.5"]', 'harness = ["PG", "UC", "FX"]\nowners = ["T12.8", "T21.5"]') : t));
    assert.match(cli('--root', root, '--check').stderr, /§2 row A26 differs from the table rendered from the registry/);
    assert.equal(cli('--root', root).status, 0);
    assert.equal(specLine(read(root, LAYOUT), 'A26'), specLine(read(REPO, LAYOUT), 'A26').replace('| PG, UC |', '| PG, UC, FX |'));
    assert.equal(read(root, SCENARIOS), read(REPO, SCENARIOS).replace('harness = ["PG", "UC"]\nowners = ["T12.8", "T21.5"]', 'harness = ["PG", "UC", "FX"]\nowners = ["T12.8", "T21.5"]'));
    assert.equal(cli('--root', root, '--check').status, 0);
  });

  test('a stale counts sentence fails --check and is rendered back', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, 'Counts by first stage: M1a 20 ', 'Counts by first stage: M1a 21 ') : t));
    assert.match(cli('--root', root, '--check').stderr, /conformance-layout\.md:\d+: the §2 counts sentences differ/);
    assert.equal(cli('--root', root).status, 0);
    assert.equal(read(root, LAYOUT), read(REPO, LAYOUT));
  });

  test('a new env in the registry needs legs before it passes', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'envs = ["pg"]\nharness = ["PG", "UC"]\nowners = ["T12.8", "T21.5"]', 'envs = ["hermetic", "pg"]\nharness = ["PG", "UC"]\nowners = ["T12.8", "T21.5"]') : t));
    failsBothModes(root, /A26: env hermetic has no leg in any stage/);
  });

  test('a hand-edited matrix_sha256 fails --check', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'b4df384e7893902f52bfcb5eb9415561d902b68c07ba0ca12972bb8c6e026443', '0'.repeat(64)) : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /A24: matrix_sha256 is 0{64}, but its spec line hashes to b4df384e/);
  });

  test('a formatting-only change fails --check with a line number', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'gates_passed = []', 'gates_passed = [ ]') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, new RegExp(`scenarios\\.toml:${lineOf(read(root, SCENARIOS), 'gates_passed = ')}: formatting differs`));
  });

  test('a scenario missing from the registry cannot be generated', () => {
    const root = fixture((rel, t) => {
      if (rel !== SCENARIOS) return t;
      const start = t.indexOf('[[scenario]]\nid = "A33"');
      const end = t.indexOf('[[scenario]]\nid = "A34"');
      return t.slice(0, start) + t.slice(end);
    });
    failsBothModes(root, new RegExp(`skyoauth-tasks\\.md:${lineOf(read(root, TASKS), '| A33 |')}: scenario A33 has no \\[\\[scenario\\]\\] entry`));
  });

  test('a registry scenario that is not a tasks §8 row', () => {
    const root = fixture((rel, t) => (rel === TASKS ? t.replace(`${specLine(t, 'A64')}\n`, '') : t));
    failsBothModes(root, /scenarios\.toml:\d+: scenario A64 is not a row of docs\/skyoauth-tasks\.md §8/);
  });

  test('a missing registry file is an error: it is the source', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? null : t));
    for (const args of [['--root', root], ['--root', root, '--check']]) {
      const r = cli(...args);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /scenarios\.toml: not found/);
    }
  });

  test('a missing subcases file drops the conditional sentences from the table', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? null : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    for (const id of ['A18', 'A27', 'A33', 'A58']) assert.match(r.stderr, new RegExp(`§2 row ${id} differs`));
    assert.match(r.stderr, /subcases\.toml: missing/);
  });
});

describe('spec errors stop generation', () => {
  const errorsOf = (root) => generate(root).errors.join('\n');

  test('a tasks §8 row removed leaves a gap', () => {
    const root = fixture((rel, t) => (rel === TASKS ? t.replace(`${specLine(t, 'A40')}\n`, '') : t));
    assert.match(errorsOf(root), /expected A40, found A41/);
    assert.match(errorsOf(root), /scenario A40 is not a row of docs\/skyoauth-tasks\.md §8/);
  });

  test('a layout §2 row removed is rendered back', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? t.replace(`${specLine(t, 'A12')}\n`, '') : t));
    assert.match(cli('--root', root, '--check').stderr, /§2 row A12 differs/);
    assert.equal(cli('--root', root).status, 0);
    assert.equal(read(root, LAYOUT), read(REPO, LAYOUT));
  });

  test('a missing §2 table header', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '| ID | Layer | Env |', '| ID | Layers | Env |') : t));
    failsBothModes(root, /layout §2 scenario table header not found/);
  });

  test('missing counts sentences', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, 'Counts by first stage:', 'Counted by first stage:') : t));
    failsBothModes(root, /the "Counts by first stage: \.\.\. rows have more than one stage\." sentences after the §2 table are missing/);
  });

  test('a duplicate contract row', () => {
    const root = fixture((rel, t) => (rel === DESIGN ? t.replace(`${specLine(t, 'C03')}\n`, (l) => l + l) : t));
    assert.match(errorsOf(root), /duplicate contract row C03/);
  });

  test('an owner that is not a task', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'owners = ["T12.8", "T21.5"]', 'owners = ["T12.8", "T21.99"]') : t));
    assert.match(errorsOf(root), /A26: owner T21\.99 is not a task/);
  });

  test('a contract without a covered_by mapping', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? t.replace(/^\| C05 .*\n/m, '') : t));
    assert.match(errorsOf(root), /contract C05 has no "Covered by" row/);
  });

  test('an unknown leg in a hand-authored stage', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'legs = ["scenarios-pg/x86_64"]', 'legs = ["scenarios-pg/arm"]') : t));
    assert.match(errorsOf(root), /A33\.90 M3: unknown leg "scenarios-pg\/arm"/);
  });

  test('a leg whose job is outside the entry envs', () => {
    const root = fixture((rel, t) =>
      rel === SCENARIOS ? t.replace(/(id = "A26"[\s\S]*?legs = )\["scenarios-pg\/x86_64"\]/, '$1["scenarios-pg/x86_64", "live-wif-push"]') : t,
    );
    assert.match(errorsOf(root), /A26 M1a: leg "live-wif-push" belongs to env live/);
  });

  // A fixture whose A26 registry entry (stages M1a and M2) has `from` replaced by `to`.
  const a26 = (from, to) => fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, entryBlock(t, 'scenario', 'A26'), replaceOnce(entryBlock(t, 'scenario', 'A26'), from, to)) : t));

  test('an unknown layer or env in a registry entry', () => {
    failsBothModes(a26('layers = ["conformance"]', 'layers = ["conform"]'), /A26: unknown layer "conform"/);
    failsBothModes(a26('envs = ["pg"]', 'envs = ["pg", "moon"]'), /A26: unknown env "moon"/);
  });

  test('a registry entry with a missing column, an unknown field or a "|" in a cell', () => {
    failsBothModes(a26('positive = ', 'positiv = '), /A26: unknown field positiv/);
    failsBothModes(a26('positive = ', 'positiv = '), /A26: positive must be non-empty table text/);
    failsBothModes(a26('harness = ["PG", "UC"]', 'harness = ["PG | UC"]'), /A26: harness must be a non-empty list of table text/);
    failsBothModes(a26('owners = ["T12.8", "T21.5"]', 'owners = []'), /A26: owners must be a non-empty list of table text/);
    failsBothModes(a26('kind = "scenario"\n', 'kind = "scenario"\nnote = ""\n'), /A26: note must be non-empty table text when present/);
  });

  test('a registry entry without stages', () => {
    const root = fixture((rel, t) => {
      if (rel !== SCENARIOS) return t;
      const block = entryBlock(t, 'scenario', 'A26');
      return replaceOnce(t, block, block.slice(0, block.indexOf('[[scenario.stage]]')));
    });
    failsBothModes(root, /A26: needs at least one \[\[scenario\.stage\]\]/);
  });

  test('an unknown kind', () => {
    failsBothModes(a26('kind = "scenario"', 'kind = "scenery"'), /A26: kind must be scenario or contract/);
  });

  test('stage order and the "full row" scope', () => {
    failsBothModes(a26('milestone = "M2"', 'milestone = "M1a"'), /duplicate stage A26 M1a/);
    failsBothModes(a26('milestone = "M1a"', 'milestone = "M3"'), /A26 M2: stage M2 comes after M3; stage milestones must increase/);
    failsBothModes(a26('scope = "policy"', 'scope = "full row"'), /A26 M1a: scope "full row" is the scope of a single-stage entry, and only of one/);
    failsBothModes(a26('scope = "policy"', 'scope = "po|icy"'), /A26 M1a: scope must be table text/);
    const one = fixture((rel, t) => (rel === SCENARIOS ? editStage(t, 'scenario', 'A24', 'scope = "consume primitive"', 'scope = "full row"') : t));
    failsBothModes(one, /A24 M1a: scope "full row" is the scope of a single-stage entry/);
    const single = fixture((rel, t) => (rel === SCENARIOS ? editStage(t, 'scenario', 'A23', 'scope = "full row"', 'scope = "exchange"') : t));
    failsBothModes(single, /A23 M2: scope "full row" is the scope of a single-stage entry, and only of one/);
  });

  test('an unknown stage field', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? editStage(t, 'scenario', 'A26', 'status = "planned"', 'status = "planned"\nowner = "T12.8"') : t));
    failsBothModes(root, /A26 M1a: unknown stage field owner/);
  });

  test('an annex range in a note must lie within .01–.89', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'note = "Sub-IDs A58.01–A58.89 in the annex (Q1):"', 'note = "Sub-IDs A58.01–A58.95 in the annex (Q1):"') : t));
    failsBothModes(root, /A58: annex range A58\.01–A58\.95 must lie within A58\.01–A58\.89/);
    const rev = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'note = "Sub-IDs A58.01–A58.89 in the annex (Q1):"', 'note = "Sub-IDs A58.50–A58.10 in the annex (Q1):"') : t));
    failsBothModes(rev, /A58: annex range A58\.50–A58\.10 must lie within/);
    const zero = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'note = "Sub-IDs A58.01–A58.89 in the annex (Q1):"', 'note = "Sub-IDs A58.00–A58.10 in the annex (Q1):"') : t));
    failsBothModes(zero, /A58: annex range A58\.00–A58\.10 must lie within/);
  });

  test('conditional sentences of a row are parsed for the named check', () => {
    assert.deepEqual(
      rowConditionals('| A99 | C | PG | PG | M2 | T10.1 | Only this (Q9). + a; − b. Conditional sub-ID (ForwardAuth, T32.9): x. Conditional sub-ID A99.91 (magic, T10.1): y |', 'A99').map((c) => [c.id, c.feature, c.task, c.text]),
      [
        [null, 'forwardauth', 'T32.9', 'Conditional sub-ID (ForwardAuth, T32.9): x'],
        ['A99.91', null, 'T10.1', 'Conditional sub-ID A99.91 (magic, T10.1): y'],
      ],
    );
    assert.deepEqual(rowConditionals('| A99 | C | PG | PG | M2 | T10.1 | + a; − b |', 'A99'), []);
    assert.deepEqual(rowConditionals('| A99 | C | PG | PG | M2 | T10.1 | + a; − b. Conditional sub-ID A99.90 x |', 'A99').map((c) => [c.id, c.feature, c.task]), [[null, null, null]]);
    assert.equal(parseConditional('Conditional sub-ID A27.90 (device flow T40.6): x'), null);
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
      const block = entryBlock(t, 'subcase', 'A33.90');
      return replaceOnce(t, block, block + block);
    });
    const text = read(root, SUBCASES);
    failsBothModes(root, new RegExp(`subcases\\.toml:${lineOf(text, '[[subcase]]\nid = "A33.90"', 1)}: duplicate subcase A33\\.90`));
  });

  test('a second stage with the same subcase and milestone', () => {
    const root = fixture((rel, t) => {
      if (rel !== SUBCASES) return t;
      const block = entryBlock(t, 'subcase', 'A33.90');
      const stage = block.slice(block.indexOf('[[subcase.stage]]'));
      return replaceOnce(t, block, block.trimEnd() + '\n\n' + stage);
    });
    const text = read(root, SUBCASES);
    const at = text.indexOf('[[subcase]]\nid = "A33.90"');
    const dup = text.slice(0, text.indexOf('[[subcase.stage]]', text.indexOf('[[subcase.stage]]', at) + 1)).split('\n').length;
    failsBothModes(root, new RegExp(`subcases\\.toml:${dup}: duplicate stage A33\\.90 M3`));
  });
});

describe('subcases are consistent with their §2 sentences', () => {
  test('a removed conditional sub-ID drops its sentence from the table', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? t.replace(entryBlock(t, 'subcase', 'A27.90'), '') : t));
    assert.match(cli('--root', root, '--check').stderr, /§2 row A27 differs from the table rendered from the registry/);
    assert.equal(cli('--root', root).status, 0);
    assert.ok(!specLine(read(root, LAYOUT), 'A27').includes('Conditional sub-ID'));
  });

  test('a wrong parent', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'parent = "A27"', 'parent = "A28"') : t));
    failsBothModes(root, /A27\.90: parent must be the registered scenario A27/);
  });

  test('a wrong conditional_on', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'conditional_on = "device-flow"', 'conditional_on = "forwardauth"') : t));
    failsBothModes(root, /A27\.90: table_text names device-flow, but conditional_on is forwardauth/);
  });

  test('a wrong source task', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'owners = ["T30.6"]', 'owners = ["T31.2"]') : t));
    failsBothModes(root, /A33\.90: table_text names T30\.6, but the first owner is T31\.2/);
  });

  test('a new conditional sub-ID is rendered into its parent row', () => {
    const root = fixture((rel, t) => {
      if (rel !== SUBCASES) return t;
      const extra = entryBlock(t, 'subcase', 'A33.90').replace('id = "A33.90"', 'id = "A33.91"').replace('sub-ID A33.90', 'sub-ID A33.91');
      return `${t.trimEnd()}\n\n${extra}`;
    });
    assert.equal(cli('--root', root).status, 0);
    assert.match(specLine(read(root, LAYOUT), 'A33'), /\. Conditional sub-ID A33\.90 \(back-channel logout, T30\.6\): verified sid targeting\. Conditional sub-ID A33\.91 /);
    assert.equal(cli('--root', root, '--check').status, 0);
  });

  test('two unnumbered sentences of one parent, feature and task', () => {
    const root = fixture((rel, t) => {
      if (rel !== SUBCASES) return t;
      const extra = entryBlock(t, 'subcase', 'A18.90').replace('id = "A18.90"', 'id = "A18.91"');
      return `${t.trimEnd()}\n\n${extra}`;
    });
    failsBothModes(root, /sub-ID of A18 \(forwardauth, T32\.9\) is named in .* without an ID, but A18\.90 and A18\.91 all match it/);
  });
});

// A required (non-conditional) A58 sub-ID, as the T32.3 owner would add it.
const REQUIRED_A58 = (id) => `
[[subcase]]
id = "${id}"
kind = "subcase"
parent = "A58"
layers = ["integration"]
envs = ["pg"]
harness = ["PG", "UC"]
owners = ["T32.3"]
positive = "approved prepare persists"
negative = "stale approval rejected"
matrix_sha256 = ""

[[subcase.stage]]
milestone = "M1b"
scope = "full row"
legs = ["scenarios-pg/x86_64"]
status = "planned"
tests = []
`;

describe('required and conditional sub-ID numbering', () => {
  test('a required sub-ID inside the annex range A58 declares is accepted', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? t + REQUIRED_A58('A58.02') : t));
    const r = cli('--root', root);
    assert.equal(r.status, 0, r.stderr);
    const sub = parseToml(read(root, SUBCASES)).subcase.find((e) => e.id === 'A58.02');
    assert.ok(sub && !('conditional_on' in sub) && !('table_text' in sub));
    assert.equal(sub.matrix_sha256, sha256(read(root, TASKS).split('\n').find((l) => l.startsWith('- [ ] **T32.3** '))));
    assert.equal(cli('--root', root, '--check').status, 0);
  });

  test('a required sub-ID outside the declared annex range', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? t + REQUIRED_A58('A58.89').replace('A58.89', 'A58.95') : t));
    failsBothModes(root, /A58\.95: required sub-ID is outside the annex range A58\.01–A58\.89 that layout §2 row A58 declares/);
  });

  test('a required sub-ID under a parent with no declared annex range', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? t + REQUIRED_A58('A33.02').replace('parent = "A58"', 'parent = "A33"') : t));
    failsBothModes(root, /A33\.02: required sub-ID, but layout §2 row A33 declares no annex range/);
  });

  test('a conditional sub-ID numbered outside .90–.99', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? t.replaceAll('A27.90', 'A27.05') : t));
    failsBothModes(root, /conditional sub-ID A27\.05 must be numbered A27\.90–A27\.99/);
  });

  test('table_text on a required sub-ID', () => {
    const root = fixture((rel, t) =>
      rel === SUBCASES ? t + REQUIRED_A58('A58.02').replace('owners = ["T32.3"]', 'table_text = "x"\nowners = ["T32.3"]') : t,
    );
    failsBothModes(root, /A58\.02: table_text is only for a conditional sub-ID/);
  });
});

// Replaces `from` with `to` inside the first stage of entry `id`.
function editStage(text, table, id, from, to) {
  const block = entryBlock(text, table, id);
  const at = block.indexOf(`[[${table}.stage]]`);
  const next = block.indexOf(`[[${table}.stage]]`, at + 1);
  const end = next < 0 ? block.length : next;
  return replaceOnce(text, block, block.slice(0, at) + replaceOnce(block.slice(at, end), from, to) + block.slice(end));
}
const stageLine = (text, table, id) => lineOf(text, `[[${table}]]\nid = "${id}"`) + entryBlock(text, table, id).slice(0, entryBlock(text, table, id).indexOf(`[[${table}.stage]]`)).split('\n').length - 1;
const entryLine = (text, table, id) => lineOf(text, `[[${table}]]\nid = "${id}"`);

describe('hand-authored input is validated', () => {
  const failsAt = (rel, edit, reFor) => {
    const root = fixture((r, t) => (r === rel ? edit(t) : t));
    failsBothModes(root, reFor(read(root, rel)));
  };

  test('tests must be a list', () => {
    failsAt(SCENARIOS, (t) => editStage(t, 'scenario', 'A24', 'tests = []', 'tests = "a24_pos_x"'),
      (t) => new RegExp(`scenarios\\.toml:${stageLine(t, 'scenario', 'A24')}: A24 M1a: tests must be a list of strings`));
  });

  test('scope must be a string', () => {
    failsAt(SUBCASES, (t) => editStage(t, 'subcase', 'A33.90', 'scope = "full row"', 'scope = ["full row"]'),
      (t) => new RegExp(`subcases\\.toml:${stageLine(t, 'subcase', 'A33.90')}: A33\\.90 M3: scope must be a string`));
  });

  test('subcase layers must be known layers', () => {
    failsAt(SUBCASES, (t) => replaceOnce(t, 'layers = ["security"]\nenvs = ["pg"]', 'layers = ["secure"]\nenvs = ["pg"]'),
      (t) => new RegExp(`subcases\\.toml:${entryLine(t, 'subcase', 'A33.90')}: A33\\.90: unknown layer "secure"`));
  });

  test('subcase envs must be known envs', () => {
    failsAt(SUBCASES, (t) => replaceOnce(t, 'layers = ["security"]\nenvs = ["pg"]', 'layers = ["security"]\nenvs = ["pg", "moon"]'),
      (t) => new RegExp(`subcases\\.toml:${entryLine(t, 'subcase', 'A33.90')}: A33\\.90: unknown env "moon"`));
  });

  test('subcase stage milestones must increase', () => {
    failsAt(SUBCASES, (t) => {
      const block = entryBlock(t, 'subcase', 'A27.90');
      const extra = '\n[[subcase.stage]]\nmilestone = "M3"\nscope = "browser"\nlegs = ["typescript-browser/chromium"]\nstatus = "planned"\ntests = []\n';
      return replaceOnce(t, block, block.trimEnd() + '\n' + extra + '\n');
    }, (t) => new RegExp(`subcases\\.toml:${lineOf(t, 'milestone = "M3"\nscope = "browser"') - 1}: A27\\.90 M3: stage M3 comes after M4; stage milestones must increase`));
  });

  test('duplicate legs', () => {
    failsAt(SCENARIOS, (t) => editStage(t, 'scenario', 'A24', 'legs = ["scenarios-pg/x86_64"]', 'legs = ["scenarios-pg/x86_64", "scenarios-pg/x86_64"]'),
      (t) => new RegExp(`scenarios\\.toml:${stageLine(t, 'scenario', 'A24')}: A24 M1a: legs lists scenarios-pg/x86_64 twice`));
  });

  test('legs must be a list', () => {
    failsAt(SCENARIOS, (t) => editStage(t, 'scenario', 'A24', 'legs = ["scenarios-pg/x86_64"]', 'legs = "scenarios-pg/x86_64"'),
      (t) => new RegExp(`scenarios\\.toml:${stageLine(t, 'scenario', 'A24')}: A24 M1a: legs must be a non-empty list of strings`));
  });

  test('duplicate gates_passed entries', () => {
    failsAt(SCENARIOS, (t) => replaceOnce(t, 'gates_passed = []', 'gates_passed = ["M1a", "M1a"]'),
      (t) => new RegExp(`scenarios\\.toml:${lineOf(t, 'gates_passed = [')}: gates_passed lists M1a twice`));
  });

  test('gates_passed must be a list', () => {
    failsAt(SCENARIOS, (t) => replaceOnce(t, 'gates_passed = []', 'gates_passed = "M0"'),
      (t) => new RegExp(`scenarios\\.toml:${lineOf(t, 'gates_passed = ')}: gates_passed must be a list of milestones`));
  });

  test('a subcase stage without tests', () => {
    failsAt(SUBCASES, (t) => editStage(t, 'subcase', 'A33.90', 'status = "planned"\ntests = []\n', 'status = "planned"\n'),
      (t) => new RegExp(`subcases\\.toml:${stageLine(t, 'subcase', 'A33.90')}: A33\\.90 M3: tests must be a list of strings`));
  });

  test('a subcase stage without scope', () => {
    failsAt(SUBCASES, (t) => editStage(t, 'subcase', 'A33.90', 'scope = "full row"\n', ''),
      (t) => new RegExp(`subcases\\.toml:${stageLine(t, 'subcase', 'A33.90')}: A33\\.90 M3: scope must be a string`));
  });

  for (const [name, esc, re] of [
    ['non-hex \\u escape', '\\\\uZZZZ', /bad \\u escape/],
    ['out-of-range \\U escape', '\\\\U00110000', /\\U escape .* is not a Unicode scalar value/],
    ['surrogate \\u escape', '\\\\uD800', /\\u escape .* is not a Unicode scalar value/],
    ['short \\u escape', '\\\\u12', /bad \\u escape/],
  ]) {
    test(`a ${name} is a clean error`, () => {
      const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'positive = "verified sid targeting"', `positive = "verified ${esc.replaceAll('\\\\', '\\')} sid"`) : t));
      const line = lineOf(read(root, SUBCASES), 'positive = "verified \\');
      failsBothModes(root, new RegExp(`subcases\\.toml:${line}: ${re.source}`));
      assert.throws(() => parseToml(`a = "${esc.replaceAll('\\\\', '\\')}"`, 'x'), (ex) => ex.message.startsWith('x:1: ') && re.test(ex.message));
    });
  }

  test('valid \\u and \\U escapes still parse', () => {
    assert.deepEqual(parseToml('a = "\\u00e9\\U0001F600"'), { a: 'é😀' });
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
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '`scenarios-pg/x86_64` |', '`scenarios-pg/x86_64`, `live-wif-push` |') : t));
    failsBothModes(root, /leg live-wif-push is listed under both pg and live/);
  });

  test('a §1.1 table without the Leg strings column', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '| CI job (legs) | Leg strings |', '| CI job (legs) | Legs |') : t));
    failsBothModes(root, /layout §1\.1 table has no "Leg strings" column/);
  });
});

describe('conditional sub-ID sentences are rendered from subcases.toml', () => {
  test('an edited table_text is rendered into the parent row', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'user-code approval, expiry/polling abuse, no interaction bypass"', 'user-code approval"') : t));
    assert.match(cli('--root', root, '--check').stderr, /§2 row A27 differs from the table rendered from the registry/);
    assert.equal(cli('--root', root).status, 0);
    assert.ok(specLine(read(root, LAYOUT), 'A27').endsWith('. Conditional sub-ID A27.90 (device flow, T40.6): user-code approval |'));
  });

  test('a table_text that names another task than the first owner', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, '(device flow, T40.6)', '(device flow, T40.7)') : t));
    failsBothModes(root, /A27\.90: table_text names T40\.7, but the first owner is T40\.6/);
  });

  test('a table_text whose feature does not match conditional_on', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? replaceOnce(t, 'Conditional sub-ID A33.90 (back-channel logout,', 'Conditional sub-ID A33.90 (device flow,') : t));
    failsBothModes(root, /A33\.90: table_text names device-flow, but conditional_on is back-channel-logout/);
  });

  test('a hand-edited sentence in the layout row is rendered back', () => {
    const root = fixture((rel, t) => (rel === LAYOUT ? replaceOnce(t, '(back-channel logout, T30.6): verified sid targeting', '(back-channel logout, T30.6): verified sid targeting only') : t));
    assert.match(cli('--root', root, '--check').stderr, /§2 row A33 differs/);
    assert.equal(cli('--root', root).status, 0);
    assert.equal(read(root, LAYOUT), read(REPO, LAYOUT));
  });
});

const STAMP_A24 = (scope = 'consume primitive', matrix = 'b4df384e7893902f52bfcb5eb9415561d902b68c07ba0ca12972bb8c6e026443') => stageStamp('A24', 'M1a', scope, matrix);
const A24_TESTS = 'tests = [\n  "nextest:skyoauth-scenarios/pg/security::a24::a24_pos_x",\n  "nextest:skyoauth-scenarios/pg/security::a24::a24_neg_y",\n]';
// scenarios.toml with A24's M1a stage implemented, stamped with `stamp`.
const implementedA24 = (t, stamp = STAMP_A24()) =>
  editStage(t, 'scenario', 'A24', 'status = "planned"\ntests = []', `status = "implemented"\n${stamp === null ? '' : `implemented_sha256 = "${stamp}"\n`}${A24_TESTS}`);

describe('hand-authored fields are kept', () => {
  test('legs, status, tests, the stamp and gates_passed survive regeneration', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? implementedA24(replaceOnce(t, 'gates_passed = []', 'gates_passed = ["M0", "M1a"]')) : t));
    const before = read(root, SCENARIOS);
    assert.notEqual(before, read(REPO, SCENARIOS));
    assert.equal(run(['--root', root], () => {}, () => {}), 0);
    assert.equal(read(root, SCENARIOS), before);
    assert.equal(cli('--root', root, '--check').status, 0);
  });

  test('a stage without a legs key gets the default legs', () => {
    const drop = (t, id, i) => {
      const block = entryBlock(t, 'scenario', id);
      const at = block.split('[[scenario.stage]]')[i + 1];
      const legs = /legs = .*\n/.exec(at)[0];
      return replaceOnce(t, block, block.replace(at, at.replace(legs, '')));
    };
    const root = fixture((rel, t) => (rel === SCENARIOS ? drop(drop(drop(drop(drop(t, 'A14', 0), 'A62', 1), 'A24', 0), 'A01', 0), 'A02', 1) : t));
    assert.equal(run(['--root', root], () => {}, () => {}), 0);
    // The committed legs of these stages are the defaults.
    assert.equal(read(root, SCENARIOS), read(REPO, SCENARIOS));
  });

  test('a stage that moves milestone keeps its tests', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? editStage(t, 'scenario', 'A24', 'milestone = "M1a"\nscope = "consume primitive"\nlegs = ["scenarios-pg/x86_64"]\nstatus = "planned"\ntests = []', `milestone = "M1b"\nscope = "consume primitive"\nlegs = ["scenarios-pg/x86_64"]\nstatus = "planned"\n${A24_TESTS}`) : t));
    assert.equal(cli('--root', root).status, 0);
    const a24 = parseToml(read(root, SCENARIOS)).scenario.find((e) => e.id === 'A24');
    assert.deepEqual([a24.stage[0].milestone, a24.stage[0].tests.length], ['M1b', 2]);
    assert.match(specLine(read(root, LAYOUT), 'A24'), /\| M1b: consume primitive · M2: exchange \|/);
    assert.match(read(root, LAYOUT), /Counts by first stage: M1a 19 · M1b 6 /);
  });
});

describe('an implemented stage is tied to what was implemented', () => {
  const unchanged = (root, re) => {
    const before = [SCENARIOS, SUBCASES, LAYOUT].map((rel) => read(root, rel));
    failsBothModes(root, re);
    assert.deepEqual([SCENARIOS, SUBCASES, LAYOUT].map((rel) => read(root, rel)), before);
  };

  test('an implemented stage without a stamp', () => {
    unchanged(fixture((rel, t) => (rel === SCENARIOS ? implementedA24(t, null) : t)), new RegExp(`A24 M1a: implemented_sha256 is missing, but this stage's \\(id, milestone, scope, matrix_sha256\\) stamps to ${STAMP_A24()}`));
  });

  test('a changed scope of an implemented stage', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? editStage(implementedA24(t), 'scenario', 'A24', 'scope = "consume primitive"', 'scope = "consume primitive and replay"') : t));
    unchanged(root, new RegExp(`A24 M1a: implemented_sha256 is ${STAMP_A24()}, but .* stamps to ${STAMP_A24('consume primitive and replay')}\\. The stage changed`));
  });

  test('an implemented stage that moves milestone', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? editStage(implementedA24(t), 'scenario', 'A24', 'milestone = "M1a"', 'milestone = "M1b"') : t));
    unchanged(root, /A24 M1b: implemented_sha256 is [0-9a-f]{64}, but .* stamps to/);
  });

  test('an edited tasks §8 row of an implemented stage is not re-hashed silently', () => {
    const root = fixture((rel, t) => {
      if (rel === SCENARIOS) return implementedA24(t);
      return rel === TASKS ? replaceOnce(t, 'Exactly one issuance, missing jti', 'Exactly one issuance, absent jti') : t;
    });
    const matrix = sha256(specLine(read(root, TASKS), 'A24'));
    unchanged(root, new RegExp(`A24 M1a: implemented_sha256 is ${STAMP_A24()}, but .* stamps to ${STAMP_A24(undefined, matrix)}`));
  });

  test('a re-stamped stage is accepted', () => {
    const root = fixture((rel, t) => {
      if (rel === SCENARIOS) return editStage(implementedA24(t, STAMP_A24('consume primitive and replay')), 'scenario', 'A24', 'scope = "consume primitive"', 'scope = "consume primitive and replay"');
      return t;
    });
    assert.equal(cli('--root', root).status, 0);
    assert.equal(cli('--root', root, '--check').status, 0);
  });

  test('an implemented stage without tests', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? editStage(t, 'scenario', 'A24', 'status = "planned"\ntests = []', `status = "implemented"\nimplemented_sha256 = "${STAMP_A24()}"\ntests = []`) : t));
    unchanged(root, /A24 M1a: an implemented stage must list its tests/);
  });

  test('a stamp on a planned stage', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? editStage(t, 'scenario', 'A24', 'status = "planned"', `status = "planned"\nimplemented_sha256 = "${STAMP_A24()}"`) : t));
    unchanged(root, /A24 M1a: implemented_sha256 is only for an implemented stage/);
  });

  test('a stamp that is not a string', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? editStage(implementedA24(t), 'scenario', 'A24', `implemented_sha256 = "${STAMP_A24()}"`, 'implemented_sha256 = 1') : t));
    unchanged(root, /A24 M1a: implemented_sha256 must be a string/);
    const sub = fixture((rel, t) => (rel === SUBCASES ? editStage(t, 'subcase', 'A33.90', 'status = "planned"', 'status = "planned"\nimplemented_sha256 = 1') : t));
    unchanged(sub, /A33\.90 M3: implemented_sha256 must be a string/);
  });

  test('a subcase stage follows the same rule', () => {
    const root = fixture((rel, t) => (rel === SUBCASES ? editStage(t, 'subcase', 'A33.90', 'status = "planned"\ntests = []', 'status = "implemented"\ntests = ["x"]') : t));
    const matrix = parseToml(read(REPO, SUBCASES)).subcase.find((s) => s.id === 'A33.90').matrix_sha256;
    unchanged(root, new RegExp(`A33\\.90 M3: implemented_sha256 is missing, but .* stamps to ${stageStamp('A33.90', 'M3', 'full row', matrix)}`));
  });

  test('the stamp is the SHA-256 of id, milestone, scope and matrix_sha256 joined by newlines', () => {
    assert.equal(stageStamp('A24', 'M1a', 's', 'h'), sha256('A24\nM1a\ns\nh'));
  });
});

describe('TOML', () => {
  test('strings with quotes, backslashes and control characters round-trip', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'positive = "selected source verifies"', 'positive = "\\"selected\\" \\\\ source\\tverifies"') : t));
    const { files, errors } = generate(root);
    assert.deepEqual(errors, []);
    const a03 = parseToml(files[SCENARIOS]).scenario.find((e) => e.id === 'A03');
    assert.equal(a03.positive, '"selected" \\ source\tverifies');
    assert.equal(files[SCENARIOS], read(root, SCENARIOS));
    assert.match(specLine(files[LAYOUT], 'A03'), /\| \+ "selected" \\ source\tverifies; − /);
  });

  test('local dates', () => {
    const d = parseToml('a = 2026-12-31 # c\nb = [2024-02-29, 2000-02-29]\n');
    assert.ok(d.a instanceof LocalDate);
    assert.deepEqual(JSON.parse(JSON.stringify(d)), { a: '2026-12-31', b: ['2024-02-29', '2000-02-29'] });
    assert.equal(String(d.a), '2026-12-31');
    for (const bad of ['2026-02-29', '1900-02-29', '2026-04-31', '2026-13-01', '2026-00-10', '2026-01-00', '2026-01-32']) {
      assert.throws(() => parseToml(`a = ${bad}`, 'x'), new RegExp(`x:1: invalid date ${bad}$`));
    }
    for (const dt of ['2026-12-31T00:00:00Z', '2026-12-31t00:00:00', '2026-12-31 10:00:00']) {
      assert.throws(() => parseToml(`a = ${dt}`, 'x'), /x:1: only local dates are supported, not date-times/);
    }
    assert.deepEqual(parseToml('a = 2026-12-31\nb = 2026'), { a: new LocalDate('2026-12-31'), b: 2026 });
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
