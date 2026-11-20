// Test helpers for the self-tests; not used by CI scripts themselves.
//
// Registry fixtures (check-conformance-registry.test.mjs and
// gen-conformance-registry.test.mjs): they start from the committed
// scenarios.toml and subcases.toml with every stage reset to `planned` (no
// stamp, `tests = []`) and `gates_passed = []`, so that implementing a real
// stage or passing a gate does not change what the tests see. Stage legs,
// scopes and milestones are kept as committed.
//
// Git fixtures (every self-test that runs git itself): GIT_ENV and
// assertGitImmune() below. This module needs nothing but Node, so the
// docs-check job can use it without `npm ci`.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// A stage's status, optional stamp and tests, as the generator writes them
// (tests inline or one string per line).
const STATUS = /^status = "(?:planned|implemented)"\n(?:implemented_sha256 = "[0-9a-f]*"\n)?tests = \[(?:\s*"(?:[^"\\\n]|\\.)*",?)*\s*\]$/gm;

export function normaliseRegistry(text) {
  return text.replace(/^gates_passed = \[.*\]$/m, 'gates_passed = []').replace(STATUS, 'status = "planned"\ntests = []');
}

// Every way of giving one key of the `[[table]]` entry `id` (its stages
// included) the TOML `value`, and of adding the keys `extra.entry` to the entry
// and `extra.stage` to each stage with that value: [label, text] pairs, for
// fuzzing what a value of the wrong type does to diagnostics.
export function valueSwaps(text, table, id, value, extra = {}) {
  const start = text.indexOf(`[[${table}]]\nid = "${id}"`);
  if (start < 0) throw new Error(`no ${table} ${id}`);
  const next = text.indexOf(`\n[[${table}]]\n`, start + 1);
  const block = text.slice(start, next < 0 ? text.length : next);
  const at = (i, len, s) => text.slice(0, start + i) + s + text.slice(start + i + len);
  const out = [];
  let where = id;
  let stages = 0;
  for (const m of block.matchAll(/^\[\[[a-z.]+\]\]$|^([a-z_0-9]+) = (\[\n(?:.*\n)*?\]|.*)$/gm)) {
    if (!m[1]) {
      where = m[0] === `[[${table}.stage]]` ? `${id} stage ${++stages}` : id;
      for (const k of where === id ? [] : (extra.stage ?? [])) out.push([`${where} +${k}`, at(m.index + m[0].length, 0, `\n${k} = ${value}`)]);
      continue;
    }
    out.push([`${where} ${m[1]}`, at(m.index, m[0].length, `${m[1]} = ${value}`)]);
    if (m[1] === 'id') for (const k of extra.entry ?? []) out.push([`${id} +${k}`, at(m.index + m[0].length, 0, `\n${k} = ${value}`)]);
  }
  return out;
}

// The environment of a self-test's own git runs: no inherited GIT_*
// variable, so none of those that point git at another repository (GIT_DIR,
// GIT_WORK_TREE, GIT_INDEX_FILE, ..., which a git hook or `git rebase
// --exec` exports, would make the fixtures be committed into that
// repository), no global or system configuration, and a fixed identity.
export const GIT_ENV = {
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_'))),
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_AUTHOR_NAME: 't',
  GIT_AUTHOR_EMAIL: 't@example.invalid',
  GIT_COMMITTER_NAME: 't',
  GIT_COMMITTER_EMAIL: 't@example.invalid',
};

// Every file under `dir` with the SHA-256 of its contents.
function snapshot(dir, rel = '', out = {}) {
  for (const e of readdirSync(join(dir, rel), { withFileTypes: true })) {
    const p = join(rel, e.name);
    if (e.isDirectory()) snapshot(dir, p, out);
    else out[p] = e.isFile() ? createHash('sha256').update(readFileSync(join(dir, p))).digest('hex') : 'other';
  }
  return out;
}

// Runs the tests of the self-test `file` named by `patterns`
// (--test-name-pattern, one test each) in a child `node --test` that
// inherits an absolute GIT_DIR of a scratch repository, and asserts that the
// scratch repository is unchanged, file for file, and that they all ran and
// passed.
export function assertGitImmune(file, patterns) {
  const scratch = mkdtempSync(join(tmpdir(), 'git-immune-'));
  try {
    for (const args of [['init', '-q', '-b', 'main'], ['-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'scratch']]) {
      const r = spawnSync('git', ['-C', scratch, ...args], { encoding: 'utf8', env: GIT_ENV });
      assert.equal(r.status, 0, r.stderr);
    }
    const before = snapshot(scratch);
    const env = { ...process.env, GIT_DIR: join(scratch, '.git') };
    delete env.NODE_TEST_CONTEXT; // set for files run by `node --test`; the child reports on its own
    // The child's summary is read from TAP, forced here: the default reporter
    // differs between Node versions (Node 24 writes spec even to a pipe), and
    // a reporter in NODE_OPTIONS would be added to this one (and fail without
    // a destination of its own), so it is removed.
    if (env.NODE_OPTIONS !== undefined) env.NODE_OPTIONS = env.NODE_OPTIONS.replace(/(^|\s)--test-reporter(?:-destination)?(?:=\S*|\s+\S+)/g, '$1');
    const p = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-reporter-destination=stdout', ...patterns.map((t) => `--test-name-pattern=${t}`), file], { encoding: 'utf8', env, timeout: 300_000 });
    assert.deepEqual(snapshot(scratch), before, 'the repository GIT_DIR names is untouched');
    assert.equal(p.status, 0, p.stdout + p.stderr);
    for (const [key, n] of [['tests', patterns.length], ['pass', patterns.length], ['fail', 0]]) {
      assert.match(p.stdout, new RegExp(`^# ${key} ${n}$`, 'm'), `# ${key} ${n}: each pattern names one test, and it passed\n${p.stdout}`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
