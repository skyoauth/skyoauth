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
  annexRange,
  checkNamedSubcases,
  DESIGN,
  generate,
  LAYOUT,
  LINE,
  LocalDate,
  MILESTONES,
  parseConditional,
  parseToml,
  renderLayoutRow,
  renderTable,
  rowConditionals,
  stageStamp,
  run,
  SCENARIOS,
  sha256,
  SpecError,
  SUBCASES,
  TASKS,
} from './gen-conformance-registry.mjs';
import { normaliseRegistry } from './registry-fixtures.mjs';

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
    const text = edit(rel, registry(rel));
    if (text === null) continue;
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

const read = (root, rel) => readFileSync(join(root, rel), 'utf8');
// A repository file as fixtures start from it: the registry files with every
// stage planned and no gate passed (registry-fixtures.mjs), the specs as they are.
const registry = (rel) => (rel === SCENARIOS || rel === SUBCASES ? normaliseRegistry(read(REPO, rel)) : read(REPO, rel));

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
// matrix_sha256 of a spec row, derived from the repository so that an amended
// row needs no change in this test.
const rowHash = (rel, id) => sha256(specLine(readFileSync(join(REPO, rel), 'utf8'), id));
const A24_HASH = rowHash(TASKS, 'A24');

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
    assert.ok(doc.gates_passed.every((g) => MILESTONES.includes(g)));
    const subs = parseToml(read(REPO, SUBCASES)).subcase.map((s) => s.id);
    assert.deepEqual(subs, ['A18.90', 'A27.90', 'A33.90', 'A58.90']);
  });

  test('the A24, A64 and C07 hashes are those of their spec rows', () => {
    const byId = new Map(parseToml(read(REPO, SCENARIOS)).scenario.map((e) => [e.id, e]));
    assert.equal(byId.get('A24').matrix_sha256, A24_HASH);
    assert.equal(byId.get('A64').matrix_sha256, rowHash(TASKS, 'A64'));
    assert.equal(byId.get('C07').matrix_sha256, rowHash(DESIGN, 'C07'));
    assert.deepEqual(byId.get('C07').covered_by, ['A15', 'A35']);
  });

  test('generation is idempotent and deterministic', () => {
    const root = fixture();
    assert.equal(run(['--root', root], () => {}, () => {}), 0);
    const once = [read(root, SCENARIOS), read(root, SUBCASES)];
    assert.equal(once[0], registry(SCENARIOS));
    assert.equal(once[1], registry(SUBCASES));
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
    assert.match(r.stderr, new RegExp(`A24: matrix_sha256 is ${A24_HASH}, but its spec line hashes to ${want}`));
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
    const t40_6 = read(REPO, TASKS).split('\n').find((l) => l.startsWith('- [ ] **T40.6** '));
    assert.match(r.stderr, new RegExp(`A27\\.90: matrix_sha256 is ${sha256(t40_6)}, but`));
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
    assert.equal(read(root, SCENARIOS), registry(SCENARIOS).replace('harness = ["PG", "UC"]\nowners = ["T12.8", "T21.5"]', 'harness = ["PG", "UC", "FX"]\nowners = ["T12.8", "T21.5"]'));
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
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, A24_HASH, '0'.repeat(64)) : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, new RegExp(`A24: matrix_sha256 is 0{64}, but its spec line hashes to ${A24_HASH} `));
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

  test('a §5 covered_by mapping with an unknown scenario, twice, or for a non-contract', () => {
    const c05 = (t) => /^\| C05 .*$/m.exec(t)[0];
    const edit = (f) => fixture((rel, t) => (rel === LAYOUT ? f(t) : t));
    assert.match(errorsOf(edit((t) => replaceOnce(t, c05(t), c05(t).replace(/^(\| C05 [^|]*\| )/, '$1A99, ')))), /conformance-layout\.md:\d+: C05 is covered by unknown scenario A99/);
    assert.match(errorsOf(edit((t) => replaceOnce(t, c05(t), `${c05(t)}\n${c05(t)}`))), /conformance-layout\.md:\d+: duplicate contract mapping C05/);
    assert.match(errorsOf(edit((t) => replaceOnce(t, c05(t), `${c05(t)}\n${c05(t).replace('| C05 ', '| C11 ')}`))), /§5 maps C11, which is not a contract of docs\/skyoauth-design\.md §2/);
  });

  test('covered_by is rendered from §5, so a hand-edited covered_by fails --check', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, 'covered_by = ["A15", "A35"]', 'covered_by = ["A15"]') : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /scenarios\.toml: C07: covered_by differs from the specs/);
    const { files, errors } = generate(root);
    assert.deepEqual(errors, []);
    assert.match(files[SCENARIOS], /id = "C07"\nkind = "contract"\ncovered_by = \["A15", "A35"\]/);
  });

  // clients-rust (env hermetic) exists from M2 (JOB_FROM).
  const A03_LEGS = '"scenarios-hermetic/x86_64", "scenarios-hermetic/aarch64", "scenarios-pg/x86_64"';
  const a03Legs = (stageAt, extra) => fixture((rel, t) => (rel === SCENARIOS ? editStageAt(t, 'A03', stageAt, `legs = [${A03_LEGS}]`, `legs = [\n  ${A03_LEGS.split(', ').join(',\n  ')},\n  ${extra},\n]`) : t));

  test('a leg whose job does not exist yet at the stage milestone', () => {
    failsBothModes(a03Legs('M1a', '"clients-rust/x86_64"'), /A03 M1a: job clients-rust exists only from M2$/m);
  });

  test('a leg whose job exists from the stage milestone, or earlier, is accepted', () => {
    for (const [m, leg] of [['M2', '"clients-rust/x86_64"'], ['M1a', '"typescript/node22"']]) {
      const root = a03Legs(m, leg);
      assert.deepEqual(generate(root).errors, [], `${m} ${leg}`);
      assert.equal(cli('--root', root, '--check').status, 0, `${m} ${leg}`);
    }
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

  test('annexRange: only a scenario ID declares a range, and no ID is built into a regex', () => {
    assert.deepEqual(annexRange('A58', 'x A58.01–A58.89 y'), { from: 1, to: 89, text: 'A58.01–A58.89' });
    assert.equal(annexRange('A58', undefined), null);
    assert.equal(annexRange('A58', 1), null);
    assert.equal(annexRange(58, 'A58.01–A58.89'), null);
    // Regex metacharacters: "(" used to throw a SyntaxError, "." to match any digit.
    for (const id of ['A5(', 'A5(.05', 'A58.0(', 'A.8', 'A5.', '.*', 'A58.90', 'A58 ', 'xA58', 'A588']) {
      assert.equal(annexRange(id, 'A58.01–A58.89 A5(.01–A5(.89 A.8.01–A.8.89'), null, id);
    }
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
// Replaces `from` with `to` once inside the `m` stage of scenario `id`.
function editStageAt(text, id, m, from, to) {
  const block = entryBlock(text, 'scenario', id);
  const at = block.indexOf(`[[scenario.stage]]\nmilestone = "${m}"`);
  assert.ok(at >= 0, `no stage ${m} of ${id}`);
  const next = block.indexOf('[[scenario.stage]]', at + 1);
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

  // Values of the wrong shape where an array of tables is expected used to
  // crash the duplicate check with a TypeError (exit 2).
  for (const [name, rel, edit, re] of [
    ['scenario = 1 in scenarios.toml', SCENARIOS, () => 'gates_passed = []\nscenario = 1\n', /^error: tests\/conformance\/scenarios\.toml: scenario must be an array of tables \(\[\[scenario\]\]\)$/m],
    ['subcase = 1 in subcases.toml', SUBCASES, () => 'subcase = 1\n', /^error: tests\/conformance\/subcases\.toml: subcase must be an array of tables \(\[\[subcase\]\]\)$/m],
    ['subcase = 1 in scenarios.toml', SCENARIOS, (t) => replaceOnce(t, 'gates_passed = []', 'gates_passed = []\nsubcase = 1'), /^error: tests\/conformance\/scenarios\.toml: unknown top-level key subcase$/m],
    ['scenario = 1 in subcases.toml', SUBCASES, (t) => 'scenario = 1\n' + t, /^error: tests\/conformance\/subcases\.toml: unknown top-level key scenario$/m],
    ['[[constructor]] in scenarios.toml', SCENARIOS, (t) => t + '\n[[constructor]]\nx = 1\n', /^error: tests\/conformance\/scenarios\.toml: unknown top-level key constructor$/m],
  ]) {
    test(`${name} is a validation error, not a crash`, () => {
      const root = fixture((r, t) => (r === rel ? edit(t) : t));
      failsBothModes(root, re);
      assert.doesNotMatch(cli('--root', root).stderr, /TypeError|at .*\.mjs:\d+/);
    });
  }

  test('stage = 1 in a contract entry is drift, not a crash', () => {
    // A contract has no stages, so the write mode regenerates the entry
    // without it; --check reports it.
    const root = fixture((r, t) => (r === SCENARIOS ? replaceOnce(t, 'id = "C07"\n', 'id = "C07"\nstage = 1\n') : t));
    const check = cli('--root', root, '--check');
    assert.equal(check.status, 1, check.stderr);
    assert.match(check.stderr, /^error: tests\/conformance\/scenarios\.toml: C07: stage differs from the specs$/m);
    assert.doesNotMatch(check.stderr, /TypeError|at .*\.mjs:\d+/);
    const write = cli('--root', root);
    assert.equal(write.status, 0, write.stderr);
    assert.equal(read(root, SCENARIOS), registry(SCENARIOS));
  });

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

  test('a sub-ID named in another row, for another feature and task', () => {
    // The checker runs checkNamedSubcases() on the committed table (the
    // generator only on the table it renders). Row A33 names A27.90 (back-channel
    // logout, T30.6): its parent, feature and first owner each disagree.
    const layout = replaceOnce(read(REPO, LAYOUT), 'Conditional sub-ID A33.90 (back-channel logout, T30.6)', 'Conditional sub-ID A27.90 (back-channel logout, T30.6)');
    const named = ['A18', 'A27', 'A33', 'A58'].flatMap((id) => rowConditionals(specLine(layout, id), id));
    const errors = [];
    checkNamedSubcases(named, parseToml(registry(SUBCASES)).subcase, errors);
    assert.deepEqual(errors, [
      `${SUBCASES}: A27.90: parent is A27, but the layout doc names it under A33`,
      `${SUBCASES}: A27.90: conditional_on is device-flow, but the layout doc names back-channel-logout`,
      `${SUBCASES}: A27.90: first owner is T40.6, but the layout doc names T30.6`,
      `${SUBCASES}: A33.90 is a conditional sub-ID not named in ${LAYOUT} §2`,
    ]);
  });

  test('a row renders its conditional sub-ID sentences in ID order, whatever the input order', () => {
    const { entries, codes } = generate(REPO);
    const a2790 = entries.subcases.find((s) => s.id === 'A27.90');
    const a2791 = { ...a2790, id: 'A27.91', table_text: 'Conditional sub-ID A27.91 (device flow, T40.6): second' };
    const a2792 = { ...a2790, id: 'A27.92', table_text: 'Conditional sub-ID A27.92 (device flow, T40.6): third' };
    const want = renderLayoutRow(entries.scenarios.find((e) => e.id === 'A27'), codes, [a2790, a2791, a2792].map((s) => s.table_text));
    for (const order of [[a2792, a2791, a2790], [a2791, a2790, a2792], [a2790, a2792, a2791]]) {
      const rows = renderTable(entries.scenarios, [...entries.subcases.filter((s) => s.parent !== 'A27'), ...order], codes);
      assert.equal(rows.find((r) => r.startsWith('| A27 |')), want);
    }
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

const STAMP_A24 = (scope = 'consume primitive', matrix = A24_HASH) => stageStamp('A24', 'M1a', scope, matrix);
const A24_TESTS = 'tests = [\n  "nextest:skyoauth-scenarios/pg/security::a24::a24_pos_x",\n  "nextest:skyoauth-scenarios/pg/security::a24::a24_neg_y",\n]';
// scenarios.toml with A24's M1a stage implemented, stamped with `stamp`.
const implementedA24 = (t, stamp = STAMP_A24()) =>
  editStage(t, 'scenario', 'A24', 'status = "planned"\ntests = []', `status = "implemented"\n${stamp === null ? '' : `implemented_sha256 = "${stamp}"\n`}${A24_TESTS}`);

describe('hand-authored fields are kept', () => {
  test('legs, status, tests, the stamp and gates_passed survive regeneration', () => {
    const root = fixture((rel, t) => (rel === SCENARIOS ? implementedA24(replaceOnce(t, 'gates_passed = []', 'gates_passed = ["M0", "M1a"]')) : t));
    const before = read(root, SCENARIOS);
    assert.notEqual(before, registry(SCENARIOS));
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
    assert.equal(read(root, SCENARIOS), registry(SCENARIOS));
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

  // Keys that name Object.prototype members are ordinary TOML keys.
  const PROTO_KEYS = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf'];

  test('__proto__ is an own key of an inline table, a table and the root', () => {
    const d = parseToml('x = { __proto__ = "y", b = 1 }\n__proto__ = 2\n[[t]]\n__proto__ = { __proto__ = 3 }\n');
    assert.equal(Object.getPrototypeOf(d.x), Object.prototype);
    assert.ok(Object.hasOwn(d.x, '__proto__'));
    assert.deepEqual(Object.keys(d.x), ['__proto__', 'b']);
    assert.equal(d.x.__proto__, 'y');
    assert.ok(Object.hasOwn(d, '__proto__'));
    assert.equal(JSON.stringify(d), '{"x":{"__proto__":"y","b":1},"__proto__":2,"t":[{"__proto__":{"__proto__":3}}]}');
    // Ordinary data properties, as JSON.parse makes them: writable and configurable.
    assert.deepEqual(Object.getOwnPropertyDescriptors(d.x), Object.getOwnPropertyDescriptors(JSON.parse('{"__proto__":"y","b":1}')));
    assert.deepEqual(Object.getOwnPropertyDescriptor(d.t[0], '__proto__'), Object.getOwnPropertyDescriptor(JSON.parse('{"__proto__":{"__proto__":3}}'), '__proto__'));
    // The key never reaches the prototype chain.
    assert.equal({}.y, undefined);
    assert.equal(Object.getPrototypeOf(d.t[0]), Object.prototype);
  });

  test('__proto__ as a table header key', () => {
    const d = parseToml('[[__proto__]]\na = 1\n[[__proto__]]\na = 2\n[[t]]\n[[t.__proto__]]\nb = 3\n');
    assert.ok(Array.isArray(d.__proto__) && Object.hasOwn(d, '__proto__'));
    assert.equal(JSON.stringify(d), '{"__proto__":[{"a":1},{"a":2}],"t":[{"__proto__":[{"b":3}]}]}');
  });

  for (const k of PROTO_KEYS.slice(1)) {
    test(`${k} is an ordinary key at the top level, in tables and as a header`, () => {
      assert.equal(JSON.stringify(parseToml(`${k} = 1\n`)), `{"${k}":1}`);
      assert.equal(JSON.stringify(parseToml(`[[t]]\n${k} = "v"\n`)), `{"t":[{"${k}":"v"}]}`);
      assert.equal(JSON.stringify(parseToml(`x = { ${k} = { ${k} = true } }\n`)), `{"x":{"${k}":{"${k}":true}}}`);
      assert.equal(JSON.stringify(parseToml(`[[${k}]]\na = 1\n[[${k}]]\n`)), `{"${k}":[{"a":1},{}]}`);
      assert.equal(JSON.stringify(parseToml(`[[scenario]]\nid = "A01"\n[[scenario.${k}]]\nb = 2\n`)), `{"scenario":[{"id":"A01","${k}":[{"b":2}]}]}`);
    });
  }

  test('duplicate keys are still rejected, prototype names included', () => {
    for (const k of ['a', ...PROTO_KEYS]) {
      const dup = (line) => (ex) => ex instanceof SpecError && ex.message === `x:${line}: duplicate key ${k}`;
      assert.throws(() => parseToml(`${k} = 1\n# c\n${k} = [\n2]\n`, 'x'), dup(3));
      assert.throws(() => parseToml(`[[t]]\nb = 0\n${k} = 1\n${k} = 2\n`, 'x'), dup(4));
      assert.throws(() => parseToml(`\nx = { ${k} = 1, ${k} = 2 }\n`, 'x'), dup(2));
    }
    // The same key in two tables, or in a table and an inline table, is fine.
    assert.equal(JSON.stringify(parseToml('a = { a = 1 }\n[[t]]\na = 2\n[[t]]\na = 3\n')), '{"a":{"a":1},"t":[{"a":2},{"a":3}]}');
  });

  test('a header whose key already holds a value, or has no parent, is a clean error', () => {
    for (const [text, line, msg] of [
      ['x = 1\n[[x]]\n', 2, '[[x]]: key x already holds a value that is not an array of tables'],
      ['x = []\n[[x]]\n', 2, '[[x]]: key x already holds a value that is not an array of tables'],
      ['x = [{ a = 1 }]\n\n[[x.b]]\n', 3, '[[x.b]]: key x already holds a value that is not an array of tables'],
      ['[[a]]\nb = 1\n[[a.b]]\n', 3, '[[a.b]]: key b already holds a value that is not an array of tables'],
      ['[[a]]\n[[b.c]]\n', 2, '[[b.c]] without a parent'],
      ['[[constructor.x]]\n', 1, '[[constructor.x]] without a parent'],
      ['[[toString.x]]\n', 1, '[[toString.x]] without a parent'],
      ['[[__proto__.x]]\n', 1, '[[__proto__.x]] without a parent'],
    ]) {
      assert.throws(() => parseToml(text, 'x'), (ex) => ex instanceof SpecError && ex.message === `x:${line}: ${msg}`, text);
    }
  });

  test('the header line is a symbol, so __line is an ordinary key', () => {
    const d = parseToml('\n[[t]]\n__line = 7\n');
    assert.equal(d.t[0][LINE], 2);
    assert.equal(d.t[0].__line, 7);
    assert.deepEqual(Object.keys(d.t[0]), ['__line']);
    assert.equal(JSON.stringify(d), '{"t":[{"__line":7}]}');
  });

  test('prototype-named keys survive a JSON round trip and deep equality', () => {
    const text = `${PROTO_KEYS.map((k, n) => `${k} = ${n}`).join('\n')}\nx = { __proto__ = { constructor = "c" } }\n[[t]]\nvalueOf = [1, 2]\n[[t.__proto__]]\n`;
    const d = parseToml(text);
    assert.deepEqual(JSON.parse(JSON.stringify(d)), d);
    assert.deepEqual(Object.keys(d), [...PROTO_KEYS, 'x', 't']);
    assert.deepEqual(Object.keys(d.t[0]), ['valueOf', '__proto__']);
  });

  test('the generator reports prototype-named fields of an entry as unknown fields', () => {
    for (const k of ['__proto__', 'constructor', 'toString']) {
      const root = fixture((rel, t) => (rel === SCENARIOS ? replaceOnce(t, entryBlock(t, 'scenario', 'A26'), entryBlock(t, 'scenario', 'A26').replace('kind = "scenario"\n', `kind = "scenario"\n${k} = "x"\n`)) : t));
      failsBothModes(root, new RegExp(`scenarios\\.toml:${entryLine(read(root, SCENARIOS), 'scenario', 'A26')}: A26: unknown field ${k}$`, 'm'));
    }
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
