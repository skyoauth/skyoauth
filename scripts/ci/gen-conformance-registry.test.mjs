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
  JOBS,
  KNOWN_LEGS,
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
    const { entries, errors } = generate(REPO);
    assert.deepEqual(errors, []);
    for (const e of entries.scenarios) assert.equal(renderLayoutRow(e), specLine(layout, e.id));
  });

  test('every leg is a §1.1 leg whose job serves one of the entry envs', () => {
    const { entries } = generate(REPO);
    for (const e of [...entries.scenarios, ...entries.subcases]) {
      for (const s of e.stages) {
        for (const leg of s.legs) {
          assert.ok(KNOWN_LEGS.has(leg), `${e.id}: ${leg}`);
          assert.ok(e.envs.includes(JOBS[KNOWN_LEGS.get(leg)].env), `${e.id}: ${leg}`);
        }
      }
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
    const root = fixture((rel, t) => (rel === SUBCASES ? null : t));
    const r = cli('--root', root, '--check');
    assert.equal(r.status, 1);
    assert.match(r.stderr, /subcases\.toml: missing/);
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
      () => parseLayoutRow('| A99 | C | PG | PG | M2 · M3 | T10.1 | + a; − b |', 'x'),
      /stage "M2" of a multi-stage row has no scope/,
    );
    assert.throws(() => parseLayoutRow('| A99 | C | PG | PG | M2 | T10.1 | + a, − b |', 'x'), /exactly one/);
    assert.throws(() => parseLayoutRow('| A99 | X | PG | PG | M2 | T10.1 | + a; − b |', 'x'), /unknown layer/);
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
    const a14 = doc.scenario.find((e) => e.id === 'A14');
    assert.deepEqual(a14.env_notes, { 'native-3os': 'Linux leg' });
    assert.ok(a14.stage[0].legs.includes('clients-rust-native/ubuntu'));
    assert.ok(!a14.stage[0].legs.includes('clients-rust-native/macos'));
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
