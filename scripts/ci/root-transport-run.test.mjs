// Self-test of root-transport-run.sh and of the `service-nextest` steps
// that use it in .github/workflows/ci.yml:
//   node --test scripts/ci/root-transport-run.test.mjs
// It needs sh, awk, sed, sort, od and tee, as the script does, and bash for
// one check of the fixture. Every file it writes lives under one temporary
// directory, removed afterwards; nothing runs as root or reaches a network.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'root-transport-run.sh');
const REPO = join(dirname(SCRIPT), '..', '..');
const TOP = mkdtempSync(join(tmpdir(), 'root-transport-run-test-'));
after(() => rmSync(TOP, { recursive: true, force: true }));

let n = 0;
const fresh = (name) => join(TOP, `${++n}-${name}`);

// The step's calls; `sh` is the shell the step's `sh` resolves to.
const sh = (args, opts = {}) => spawnSync('sh', [SCRIPT, ...args], { encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024, ...opts });

// The listing `summarize` reads by default: the stdout of `cargo nextest
// list --message-format oneline --verbose` (nextest 0.9) for a run of the
// three selections, shortened: the selected tests, then tests of the same
// binaries that the filterset leaves out, which end in ` (skipped)`. The
// selected tests are the script's REQUIRED ones and one more of each
// selection (EXTRA, which no check requires by name).
// The script's SELECTIONS, as [binary ID, test name prefix] pairs.
const SELECTIONS = /^SELECTIONS='([^']*)'$/m
  .exec(readFileSync(SCRIPT, 'utf8'))[1]
  .split('\n')
  .map((l) => [l.split(' ')[0], l.split(' ')[1] ?? '']);
const REQUIRED = /^REQUIRED='([^']*)'$/m.exec(readFileSync(SCRIPT, 'utf8'))[1].split('\n');
const EXTRA = [
  'skyoauth-operator::operator local_path::a_relative_path_is_checked_as_its_absolute_form',
  'skyoauth-scenarios::pg harness::socket_path_fixture::socket_path_fixture_outcomes_are_complete',
  'skyoauth-service::local_transport a_socket_path_up_to_the_limit_works',
];
const SELECTED = [...EXTRA, ...REQUIRED];
const N = SELECTED.length;
// How many of these tests are in the selection of this binary.
const inBinary = (bin, tests = SELECTED) => tests.filter((t) => t.startsWith(`${bin} `)).length;
const LEFT_OUT = [
  'skyoauth-operator::operator challenge::challenge_fixture_envelope_matches_the_crate',
  'skyoauth-operator::operator identity_bounds_and_form',
  'skyoauth-scenarios::pg harness::socket_path_fixture_other::a_test',
];
const listLine = (t, skipped = false) => {
  const bin = t.split(' ')[0].split('::')[1];
  return `${t} [bin: /work/target/debug/deps/${bin}-0123456789abcdef] [cwd: /work/x] [build platform: target]${skipped ? ' (skipped)' : ''}`;
};
const listing = (selected = SELECTED, leftOut = LEFT_OUT) => [...selected.map((t) => listLine(t)), ...leftOut.map((t) => listLine(t, true))].map((l) => `${l}\n`).join('');
const LISTING = listing();
// The command the step lists the selection with, through `run`: `sh -c
// LIST_WRAPPER sh LIST COMMAND...` sends COMMAND's stdout (the listing) to
// LIST and leaves its stderr to `run`, which copies it to its log and to
// the step log with workflow commands stopped.
const LIST_WRAPPER = 'out=$1; shift; exec "$@" > "$out"';

// Runs `summarize` on a log with this text (null: no log file) and a
// listing (null: no listing file) and returns { status, stdout, stderr,
// summary, lines }: `lines` are stdout's lines (its error and warning
// annotations, the summary's section between SECTION_START and
// SECTION_END, then the counts' `::notice::`).
function summarize(text, userns = '0', status = '0', list = LISTING, listStatus = '0') {
  const log = fresh('run.log');
  if (text !== null) writeFileSync(log, text);
  const listPath = fresh('run.list');
  if (list !== null) writeFileSync(listPath, list);
  const summary = fresh('summary.md');
  writeFileSync(summary, '# earlier step\n');
  const r = sh(['summarize', log, userns, status, listPath, listStatus], { env: { ...process.env, GITHUB_STEP_SUMMARY: summary } });
  return { ...r, summary: readFileSync(summary, 'utf8'), lines: r.stdout.split('\n').filter(Boolean) };
}

// What nextest 0.9 prints with --no-capture and CARGO_TERM_COLOR=never
// (the lines the script reads, as in a real run of the three selections
// as root): START and PASS lines (the counter padded as nextest pads it),
// and the summary line, whose skipped count is the tests the filterset
// leaves out.
const START = `    Starting ${SELECTED.length} tests across 3 binaries (${LEFT_OUT.length} tests skipped)\n`;
const passLines = (tests = SELECTED) => tests.map((t, i) => `       START [         ] (${String(i + 1).padStart(2)}/${tests.length}) ${t}\n        PASS [   0.004s] (${String(i + 1).padStart(2)}/${tests.length}) ${t}\n`).join('');
const SUMMARY = `Summary [  56.610s] ${SELECTED.length} tests run: ${SELECTED.length} passed, ${LEFT_OUT.length} skipped`;
const PASSED = `────────────\n     ${SUMMARY}\n`;
const PEER = 'NOTICE: SKYOAUTH_IT_PEER_USER is not set: the cross-UID peer check was NOT run (it needs root and a second local user; set SKYOAUTH_IT_PEER_USER=<user> to run it)';
const PROC = 'NOTICE: a bind without /proc was NOT tested: the mount namespace or the mount on /proc was denied (unshare: cannot change root filesystem propagation: Permission denied)';
const log = (...lines) => `${START}${passLines()}${lines.map((l) => `${l}\n`).join('')}${PASSED}`;
// A log with every PASS line and this summary line (the text after it).
const withSummary = (line) => `${START}${passLines()}     ${line}\n`;
const errors = (r) => r.lines.filter((l) => l.startsWith('::error::'));
const warnings = (r) => r.lines.filter((l) => l.startsWith('::warning::'));
// The script's error and warning annotations, in order.
const annotations = (r) => r.lines.filter((l) => l.startsWith('::error::') || l.startsWith('::warning::'));
// The counts' notice, and every workflow command the script prints.
const countNotices = (r) => r.lines.filter((l) => l.startsWith('::notice::'));
const ownCommands = (r) => r.lines.filter((l) => l.startsWith('::'));
const SECTION_START = 'Root-only tests summary:';
const SECTION_END = 'End of the root-only tests summary.';
// What `summarize` appended to GITHUB_STEP_SUMMARY (after the earlier
// step's line the helper writes there).
const EARLIER = '# earlier step\n';
const appended = (r) => {
  assert.ok(r.summary.startsWith(EARLIER), r.summary);
  return r.summary.slice(EARLIER.length);
};
// The lines of the step log that the Actions runner reads as workflow
// commands (actions/runner, ActionCommandManager.TryProcessCommand): it
// reads stdout a line at a time with .NET's ReadLine, which ends a line at
// LF, CR or CR LF; a line is a command when it starts with `::` once its
// leading white space is trimmed (ActionCommand.TryParseV2), or when it
// holds `##[` anywhere (TryParse, the old syntax).
const commands = (stdout) => stdout.split(/\r\n|\r|\n/).filter((l) => l.trimStart().startsWith('::') || l.includes('##['));
const escapeRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const HEADING = '### Root-only tests: `local_transport`, operator `local_path`, `harness::socket_path_fixture`';
const LT = inBinary('skyoauth-service::local_transport');
const OP = inBinary('skyoauth-operator::operator');
const PG = inBinary('skyoauth-scenarios::pg');
const COUNTS =
  `- \`skyoauth-service::local_transport\`: ${LT} of ${LT} selected tests ran and passed\n` +
  `- \`skyoauth-operator::operator\` \`local_path::*\`: ${OP} of ${OP} selected tests ran and passed\n` +
  `- \`skyoauth-scenarios::pg\` \`harness::socket_path_fixture::*\`: ${PG} of ${PG} selected tests ran and passed\n` +
  `- Required root-only tests (REQUIRED in scripts/ci/root-transport-run.sh): ${REQUIRED.length} of ${REQUIRED.length} ran and passed\n`;
const requiredError = (t, why) => `::error::required root-only test ${t} did not run: ${why}`;

// The notice kinds: a string each notice holds, and whether it fails the
// step or warns (the script's comment lists them; NOTICE_FAILS the first).
const KINDS = [
  ['SKYOAUTH_IT_PEER_USER is not set', 'fails'],
  ['socket path cases were NOT run: they need root', 'fails'],
  ['socket path cases were NOT bound by the service', 'fails'],
  ['the owner check needs root: it was NOT tried', 'fails'],
  ['no socket path case was bound by the service: it binds on Linux', 'fails'],
  ['this kernel follows at most', 'warns'],
  ["is not root's, sticky and writable by all: the shared directory was NOT tried in it", 'warns'],
  ['the working directory is too long for a relative socket path', 'warns'],
  ['/proc/self/fd is missing', 'warns'],
  ['a bind without /proc was NOT tested', 'warns'],
  ['a user namespace was denied', 'warns'],
];

// The string literals of Rust source, each { text, line } (the text as
// written, escapes and all), skipping comments and char literals.
function stringLiterals(src) {
  const out = [];
  let line = 1;
  const advance = (from, to) => {
    for (let k = from; k < to; k++) if (src[k] === '\n') line++;
    return to;
  };
  let i = 0;
  while (i < src.length) {
    if (src.startsWith('//', i)) {
      const j = src.indexOf('\n', i);
      i = j < 0 ? src.length : j;
      continue;
    }
    if (src.startsWith('/*', i)) {
      i = advance(i, src.indexOf('*/', i + 2) + 2);
      continue;
    }
    const raw = /^b?r(#*)"/.exec(src.slice(i, i + 16));
    if (raw && !/\w/.test(src[i - 1] ?? '')) {
      const close = `"${raw[1]}`;
      const from = i + raw[0].length;
      const to = src.indexOf(close, from);
      out.push({ text: src.slice(from, to), line });
      i = advance(i, to + close.length);
      continue;
    }
    if (src[i] === '"') {
      let j = i + 1;
      while (src[j] !== '"') j += src[j] === '\\' ? 2 : 1;
      out.push({ text: src.slice(i + 1, j), line });
      i = advance(i, j + 1);
      continue;
    }
    if (src[i] === "'") {
      const ch = /^'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'/.exec(src.slice(i, i + 12));
      i += ch ? ch[0].length : 1;
      continue;
    }
    i = advance(i, i + 1);
  }
  return out;
}

// The files a test target compiles in, from its crate root: { file, path }
// with the module path (`a::b::`) of each, following `mod NAME;`, inline
// `mod NAME { ... }` (closed by a `}` at its indentation, as rustfmt writes
// it) and `#[path = "..."]`.
function moduleFiles(root) {
  const out = [{ file: root, path: '' }];
  const walk = (file, dir, path) => {
    const stack = [{ indent: -1, dir, path }];
    let pathAttr = null;
    for (const text of readFileSync(join(REPO, file), 'utf8').split('\n')) {
      if (stack.length > 1 && text === `${' '.repeat(stack.at(-1).indent)}}`) {
        stack.pop();
        continue;
      }
      const attr = /^\s*#\[path = "([^"]+)"\]$/.exec(text);
      if (attr) pathAttr = attr[1];
      if (/^\s*(#\[|\/\/)/.test(text)) continue;
      const m = /^(\s*)(?:pub(?:\([^)]*\))? )?mod (\w+)(;| \{)$/.exec(text);
      if (m) {
        const cur = stack.at(-1);
        if (m[3] === ' {') stack.push({ indent: m[1].length, dir: join(cur.dir, m[2]), path: `${cur.path}${m[2]}::` });
        else {
          const child = pathAttr ? join(cur.dir, pathAttr) : [join(cur.dir, `${m[2]}.rs`), join(cur.dir, m[2], 'mod.rs')].find((f) => existsSync(join(REPO, f)));
          assert.ok(child && existsSync(join(REPO, child)), `${file}: mod ${m[2]}: no file`);
          out.push({ file: child, path: `${cur.path}${m[2]}::` });
          walk(child, child.endsWith('/mod.rs') ? dirname(child) : child.slice(0, -'.rs'.length), `${cur.path}${m[2]}::`);
        }
      }
      pathAttr = null;
    }
  };
  walk(root, dirname(root), '');
  return out;
}

// The selections' targets: binary ID and crate root.
const TARGETS = [
  ['skyoauth-service::local_transport', 'service/tests/local_transport.rs'],
  ['skyoauth-operator::operator', 'operator/tests/operator.rs'],
  ['skyoauth-scenarios::pg', 'tests/pg.rs'],
];
// The files whose notices are checked: a selection's own modules, and of
// its target the crate root and the helper modules (`common`, `support`,
// `harness::*`), each with `selected` when it is in the selection.
const SCANNED = TARGETS.flatMap(([bin, root]) => {
  const prefix = SELECTIONS.find(([b]) => b === bin)[1];
  return moduleFiles(root)
    .map((m) => ({ bin, ...m, selected: m.path.startsWith(prefix) || (m.path === '' && prefix === '') }))
    .filter((m) => m.selected || m.path === '' || /^(common|support|harness)::/.test(m.path));
});

// Every notice of SCANNED: { file, line, text, bin, path, selected, fn,
// test }, the text as printed (continuations joined, `{NAME}` replaced by
// that constant's value, other placeholders by X), and the function around
// it, if it is still open there (no `}` at its indentation in between),
// and whether that function is a test.
function sourceNotices() {
  const out = [];
  for (const { bin, file, path, selected } of SCANNED) {
    const source = readFileSync(join(REPO, file), 'utf8');
    const lines = source.split('\n');
    const consts = Object.fromEntries([...source.matchAll(/^const (\w+): (?:&str = "([^"]*)"|\w+ = (\d+));$/gm)].map((m) => [m[1], m[2] ?? m[3]]));
    for (const { text: raw, line } of stringLiterals(source)) {
      if (!raw.includes('NOTICE:')) continue;
      const text = raw.replace(/\\\n\s*/g, '').replace(/\\"/g, '"').replace(/\{(\w*)[^}]*\}/g, (_, name) => consts[name] ?? 'X');
      let fn;
      let test = false;
      for (let k = line - 1; k >= 0; k--) {
        const m = /^(\s*)(?:pub(?:\([^)]*\))? )?(?:async )?fn (\w+)/.exec(lines[k]);
        if (!m) continue;
        if (lines.slice(k + 1, line - 1).some((l) => l === `${m[1]}}`)) break;
        fn = m[2];
        for (let a = k - 1; a >= 0 && /^\s*(#\[|\/\/)/.test(lines[a]); a--) if (/^\s*#\[(tokio::)?test\b/.test(lines[a])) test = true;
        break;
      }
      out.push({ file, line, text, bin, path, selected, fn, test });
    }
  }
  return out;
}

describe('summarize', () => {
  test('no notices and every test passed: passes, and the summary says so', () => {
    const r = summarize(log('147 private directories swapped during 400 binds, 398 served'));
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(annotations(r), []);
    assert.equal(
      r.summary,
      `# earlier step\n${HEADING}\n\n` +
        `- nextest: ${SUMMARY} (the listing selects ${N} tests and leaves out 3 of the same binaries)\n` +
        COUNTS +
        '- User namespaces for the runner user (not root; `unshare --user --map-root-user --mount true`): allowed (exit 0)\n' +
        '- Every selected test ran as root and passed, and none printed a notice: each root-only check of the `local_transport` integration target, of operator `local_path` and of `harness::socket_path_fixture` ran.\n',
    );
  });

  test('the user namespace probe is reported as allowed or denied with its exit status', () => {
    assert.match(summarize(log(), '0').summary, /^- User namespaces for the runner user .*: allowed \(exit 0\)$/m);
    assert.match(summarize(log(), '1').summary, /^- User namespaces for the runner user .*: denied \(exit 1\)$/m);
    assert.match(summarize(log(), '127').summary, /: denied \(exit 127\)$/m);
    for (const bad of ['', 'x', '-1', '1 2']) {
      assert.equal(summarize(log(), bad).status, 2, JSON.stringify(bad));
      assert.equal(summarize(log(), '0', bad).status, 2, JSON.stringify(bad));
      assert.equal(summarize(log(), '0', '0', LISTING, bad).status, 2, JSON.stringify(bad));
    }
  });

  test('a notice about SKYOAUTH_IT_PEER_USER fails, with an error and the notice as a warning', () => {
    const r = summarize(log(PEER));
    assert.equal(r.status, 1, r.stdout);
    assert.deepEqual(errors(r), ['::error::a test printed a notice about SKYOAUTH_IT_PEER_USER although the step sets it: the root-only cross-UID checks did not run']);
    assert.deepEqual(warnings(r), [`::warning::${PEER}`]);
    assert.match(r.summary, /^- \*\*Failed:\*\* a test printed a notice about SKYOAUTH_IT_PEER_USER/m);
    assert.match(r.summary, new RegExp(`^- ${escapeRe(PEER)}$`, 'm'));
  });

  // The notices of operator `local_path` and of the harness module that say
  // their cases did not run for want of root or of the peer user, as a run
  // that is not root (or is root without the peer user) prints them.
  const OPERATOR_ROOT = "NOTICE: 20 of 72 socket path cases were NOT run: they need root (an entry of root or of another UID, or a root-owned case root): ancestor_of_another_uid, ancestor_of_root";
  const HARNESS_ROOT = "NOTICE: 23 of 72 socket path cases were NOT bound by the service: socket_in_a_sticky_directory_of_root (an entry of root or of another UID), root_only_socket_in_a_directory_of_root (root's bind for another UID)";
  const HARNESS_PEER = 'NOTICE: 41 of 72 socket path cases were NOT bound by the service: socket_of_root (as root, the peer user)';
  const OPERATOR_OWNER = 'NOTICE: the owner check needs root: it was NOT tried';
  const HARNESS_PLATFORM = 'NOTICE: no socket path case was bound by the service: it binds on Linux on x86_64, aarch64 and riscv64 only';

  test('a notice that root-only socket path cases did not run fails, each with its own error', () => {
    for (const [notice, pattern] of [
      [OPERATOR_ROOT, 'socket path cases were NOT run: they need root'],
      [HARNESS_ROOT, 'socket path cases were NOT bound by the service'],
      [HARNESS_PEER, 'socket path cases were NOT bound by the service'],
      [OPERATOR_OWNER, 'the owner check needs root'],
      [HARNESS_PLATFORM, 'no socket path case was bound by the service'],
    ]) {
      const r = summarize(log(notice));
      assert.equal(r.status, 1, notice);
      assert.deepEqual(errors(r), [`::error::a test printed a notice that its root-only cases did not run (${pattern}) although the step runs as root with SKYOAUTH_IT_PEER_USER set`]);
      assert.deepEqual(warnings(r), [`::warning::${notice}`]);
      assert.match(r.summary, /^- \*\*Failed:\*\* a test printed a notice that its root-only cases did not run/m);
      assert.match(r.summary, new RegExp(`^- ${escapeRe(notice)}$`, 'm'));
      assert.doesNotMatch(r.summary, COMPLETE);
    }
    const all = summarize(log(OPERATOR_ROOT, HARNESS_ROOT, PEER));
    assert.equal(all.status, 1);
    assert.equal(errors(all).length, 3, all.stdout);
    assert.equal(warnings(all).length, 3, all.stdout);
  });

  test('a notice that does not depend on root or the peer user is a warning and passes, without the completion claim', () => {
    for (const notice of [
      'NOTICE: chain_of_40_links: this kernel follows at most 32 symbolic links: expected refused as lookup, not accept',
      'NOTICE: the working directory is too long for a relative socket path that fits once absolute: that half was NOT tried',
      "NOTICE: /tmp is not root's, sticky and writable by all: the shared directory was NOT tried in it",
      PROC,
    ]) {
      const r = summarize(log(notice));
      assert.equal(r.status, 0, notice + r.stdout);
      assert.deepEqual(errors(r), []);
      assert.deepEqual(warnings(r), [`::warning::${notice}`]);
      assert.match(r.summary, new RegExp(`^- ${escapeRe(notice)}$`, 'm'));
      assert.doesNotMatch(r.summary, COMPLETE);
    }
  });

  test('another notice is a warning and in the summary, and passes; repeats are shown once', () => {
    const r = summarize(log(PROC, 'some output', `  ${PROC.replace('NOTICE', 'NOTICE')}`, PROC));
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(errors(r), []);
    assert.deepEqual(warnings(r), [`::warning::  ${PROC}`, `::warning::${PROC}`]);
    assert.match(r.summary, /Notices printed by tests \(a test that could not run its check\):\n\n- {3}NOTICE: a bind without \/proc.*\n- NOTICE: a bind without \/proc[^\n]*\n$/);
    assert.doesNotMatch(r.summary, COMPLETE);
  });

  test('a notice cannot inject a workflow command: %, CR and LF are escaped', () => {
    const evil = 'NOTICE: x %0A::error::injected %25 50% \r::error::cr';
    const r = summarize(log(evil));
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(annotations(r), ['::warning::NOTICE: x %250A::error::injected %2525 50%25 %0D::error::cr']);
    // That annotation and the counts' notice are the only workflow
    // commands on stdout.
    assert.deepEqual(commands(r.stdout), ownCommands(r));
    assert.equal(ownCommands(r).length, 2);
    assert.ok(!r.stdout.includes('\r'));
  });

  test('an error that quotes the log is escaped too', () => {
    const r = summarize(withSummary('Summary [   1.000s] 5 tests run: 4 passed %0A::error::injected 50% \r::warning::cr'));
    assert.equal(r.status, 1);
    assert.deepEqual(annotations(r), ['::error::not every root-only test ran and passed: Summary [   1.000s] 5 tests run: 4 passed %250A::error::injected 50%25 %0D::warning::cr']);
    assert.deepEqual(commands(r.stdout), ownCommands(r));
  });

  // The section `summarize` appends to GITHUB_STEP_SUMMARY is printed to
  // stdout too, after the annotations, so that the step log holds it.
  const expectedStdout = (r) => {
    const section = appended(r);
    assert.ok(section.endsWith('\n'), section);
    assert.equal(countNotices(r).length, 1, r.stdout);
    return [...annotations(r), SECTION_START, ...section.slice(0, -1).split('\n').map((l) => `| ${l}`), SECTION_END, ...countNotices(r), ''].join('\n');
  };
  const PEER_FIXTURE = () => summarize(log(PEER));

  test('stdout holds the annotations, then the summary\'s section, line by line, each line prefixed', () => {
    const cases = [
      [summarize(log()), 0],
      [summarize(log(PROC)), 0],
      [summarize(log(PROC, PEER)), 1],
      [PEER_FIXTURE(), 1],
      [summarize(withSummary('Summary [   1.000s] 5 tests run: 4 passed, 1 failed, 3 skipped')), 1],
      [summarize(null, '1', '101', null, '101'), 1],
    ];
    for (const [r, status] of cases) {
      assert.equal(r.status, status, r.stdout);
      assert.equal(r.stdout, expectedStdout(r));
      assert.match(appended(r), new RegExp(`^${escapeRe(HEADING)}\n`));
      // Each line of the section is on stdout as `| LINE`, in order.
      const start = r.lines.indexOf(SECTION_START);
      assert.deepEqual(r.stdout.split('\n').slice(start + 1, -3), appended(r).split('\n').slice(0, -1).map((l) => `| ${l}`));
      assert.equal(r.stderr, '');
    }
    // The passing run: its counts are in the step log.
    const pass = cases[0][0];
    for (const line of COUNTS.split('\n').filter(Boolean)) assert.ok(pass.lines.includes(`| ${line}`), line);
    assert.ok(pass.lines.includes(`| - nextest: ${SUMMARY} (the listing selects ${N} tests and leaves out 3 of the same binaries)`));
  });

  test('no line of the section on stdout is a workflow command, whatever a notice, a test name or the summary line holds', () => {
    const evil = [
      '::error::x',
      '::set-output name=a::b',
      '  ::error::indented',
      '\t::warning::tab',
      'a \r::error::after a CR',
      'a \r  ::set-output name=c::d',
      'old ##[error]syntax ##[set-output name=e;]f',
      '###[error]three',
      '%0A::error::escaped',
    ];
    const notices = evil.map((e) => `NOTICE: ${e}`);
    // A test name: its listing line quoted in the error for a test outside
    // the selections, and for a line that is not `BINARY-ID TEST ...`.
    const names = ['skyoauth-scenarios::pg ::error::name', 'skyoauth-scenarios::pg ##[error]name', 'skyoauth-scenarios::pg x\r::error::name'];
    const runs = [
      summarize(log(...notices)),
      summarize(`${START}${passLines([...SELECTED, ...names])}${notices.join('\n')}\n     Summary [   1.000s] ${N + names.length} tests run: ${N + names.length} passed, 3 skipped\n`, '0', '0', listing([...SELECTED, ...names])),
      summarize(log(), '0', '0', `::error::listing\n  ::set-output name=g::h\n##[error]listing\n${LISTING}`),
      summarize(withSummary('Summary [   1.000s] 5 tests run: 4 passed ::error::s \r::set-output name=i::j ##[error]k')),
    ];
    for (const r of runs) {
      // The section went to GITHUB_STEP_SUMMARY unchanged ...
      assert.ok(appended(r).includes('::error::'), appended(r));
      // ... and the only workflow commands on stdout are the script's own
      // annotations, all before the section, and the counts' notice after it.
      const own = annotations(r);
      assert.ok(own.length > 0, r.stdout);
      assert.deepEqual(commands(r.stdout), ownCommands(r));
      assert.deepEqual(ownCommands(r), [...own, ...countNotices(r)]);
      assert.ok(own.every((l) => l.startsWith('::error::') || l.startsWith('::warning::')), own.join('\n'));
      assert.ok(own.every((l) => !l.includes('\r')), own.join('\n'));
      const start = r.lines.indexOf(SECTION_START);
      assert.ok(start >= own.length, r.stdout);
      assert.deepEqual(r.lines.slice(0, own.length), own);
      const section = r.lines.slice(start + 1, -2);
      assert.equal(r.lines.at(-2), SECTION_END);
      assert.match(r.lines.at(-1), /^::notice::/);
      assert.ok(section.length > 0);
      assert.ok(section.every((l) => l.startsWith('| ') && !l.includes('\r') && !l.includes('##[')), section.join('\n'));
      // Line by line, the summary's section with CR shown as `^M` and `##[`
      // as `# #[`.
      assert.deepEqual(section, appended(r).split('\n').slice(0, -1).map((l) => `| ${l.replaceAll('\r', '^M').replaceAll('##[', '# #[')}`));
    }
    // The notices are in the section on stdout, readable.
    assert.ok(runs[0].lines.includes('| - NOTICE: ::error::x'));
    assert.ok(runs[0].lines.includes('| - NOTICE: a ^M::error::after a CR'));
    assert.ok(runs[0].lines.includes('| - NOTICE: old # #[error]syntax # #[set-output name=e;]f'));
  });

  // The counts as one `::notice::` on the check run: numbers, and the
  // names of SELECTIONS, only.
  const NOTICE_SHAPE = new RegExp(
    '^::notice::Root-only tests: nextest ran (\\d+|\\?) \\(all passed: (yes|no)\\) and skipped \\d+; ' +
      'the listing selects (\\d+|\\?) and leaves out (\\d+|\\?); passed per selection: ' +
      `(${SELECTIONS.map(([bin, prefix]) => escapeRe(`${bin}${prefix ? ` ${prefix}*` : ''}`) + ' \\d+/\\d+').join(', ')}|\\?); ` +
      `required root-only tests that ran and passed: (\\d+|\\?) of ${REQUIRED.length}$`,
  );

  test('the counts are one notice annotation, after the section', () => {
    const r = summarize(log());
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(countNotices(r), [
      `::notice::Root-only tests: nextest ran ${N} (all passed: yes) and skipped 3; the listing selects ${N} and leaves out 3; passed per selection: ` +
        `skyoauth-service::local_transport ${LT}/${LT}, skyoauth-operator::operator local_path::* ${OP}/${OP}, skyoauth-scenarios::pg harness::socket_path_fixture::* ${PG}/${PG}; ` +
        `required root-only tests that ran and passed: ${REQUIRED.length} of ${REQUIRED.length}`,
    ]);
    assert.equal(r.lines.at(-1), countNotices(r)[0]);
    // On a failure too, with what is known.
    for (const failed of [summarize(log(PEER)), summarize(null, '1', '101', null, '101'), summarize(withSummary('Summary [   1.000s] 5 tests run: 4 passed, 1 failed, 3 skipped'))]) {
      assert.equal(failed.status, 1);
      assert.equal(countNotices(failed).length, 1, failed.stdout);
      assert.match(countNotices(failed)[0], NOTICE_SHAPE);
    }
    assert.match(countNotices(summarize(null, '1', '101', null, '101'))[0], /nextest ran \? \(all passed: no\) and skipped 0; the listing selects \? and leaves out \?; passed per selection: \?; required .*: \? of /);
  });

  test('the counts\' notice holds no text of the log or the listing', () => {
    const attack = ['::error::n', '%0A::error::p', '\r::warning::q', '##[error]r', '::set-output name=s::t'];
    const names = attack.map((a, i) => `skyoauth-scenarios::pg harness::socket_path_fixture::x${i}${a.replace(/[\s]/g, '')}`);
    for (const r of [
      summarize(log(...attack.map((a) => `NOTICE: ${a}`))),
      summarize(`${START}${passLines([...SELECTED, ...names])}     Summary [   1.000s] ${N + names.length} tests run: ${N + names.length} passed, 3 skipped\n`, '0', '0', listing([...SELECTED, ...names])),
      summarize(withSummary(`Summary [   1.000s] ${N} tests run: ${N} passed, 3 skipped ${attack.join(' ')}`)),
      summarize(log(), '0', '0', `${attack.join('\n')}\n${LISTING}`),
    ]) {
      const [notice, ...more] = countNotices(r);
      assert.deepEqual(more, [], r.stdout);
      assert.match(notice, NOTICE_SHAPE, r.stdout);
      for (const a of ['::error', '::warning', '##[', 'set-output', '%0A', '%25', 'x0']) assert.ok(!notice.slice('::notice::'.length).includes(a), `${a} in ${notice}`);
    }
  });

  test('printing the section does not change the exit status or the annotations', () => {
    for (const [r, status, errorCount, warningCount] of [
      [summarize(log()), 0, 0, 0],
      [summarize(log(PROC)), 0, 0, 1],
      [PEER_FIXTURE(), 1, 1, 1],
      [summarize(log(), '0', '4'), 1, 1, 0],
      [summarize(log('NOTICE: ::error::x')), 0, 0, 1],
      [summarize('', '0', '0', '', '0'), 1, 2, 0],
    ]) {
      assert.equal(r.status, status, r.stdout);
      assert.equal(errors(r).length, errorCount, r.stdout);
      assert.equal(warnings(r).length, warningCount, r.stdout);
      assert.equal(annotations(r).length, errorCount + warningCount, r.stdout);
      assert.equal(r.lines.filter((l) => l === SECTION_START).length, 1, r.stdout);
      assert.equal(r.lines.at(-2), SECTION_END, r.stdout);
      assert.equal(countNotices(r).length, 1, r.stdout);
    }
    // A usage error prints no section.
    const usage = summarize(log(), 'x');
    assert.equal(usage.status, 2);
    assert.equal(usage.stdout, '');
    assert.equal(appended(usage), '');
  });

  test('more than 64 KiB of notices: the peer notice is still found (no SIGPIPE false negative)', () => {
    // The peer notice sorts first; about 1 MiB of other notices follow it.
    const filler = Array.from({ length: 8000 }, (_, i) => `NOTICE: zz filler notice ${String(i).padStart(5, '0')} ${'x'.repeat(120)}`);
    const notices = [PEER, ...filler].sort();
    assert.equal(notices[0], PEER);
    // The fixture would have caught the old check, `printf | grep -q` under
    // pipefail: grep stops after the first match, printf dies of SIGPIPE.
    const file = fresh('notices');
    writeFileSync(file, `${notices.join('\n')}\n`);
    const old = spawnSync('bash', ['-c', 'set -o pipefail; notices="$(cat "$1")"; printf "%s\\n" "$notices" | grep -q SKYOAUTH_IT_PEER_USER', 'old', file], { encoding: 'utf8' });
    assert.equal(old.status, 141, 'the old check is a false negative on this fixture');
    const r = summarize(log(...filler, PEER));
    assert.equal(r.status, 1);
    assert.equal(errors(r).length, 1);
    assert.match(errors(r)[0], /SKYOAUTH_IT_PEER_USER/);
    assert.equal(warnings(r).length, filler.length + 1);
  });

  const COMPLETE = /each root-only check .* ran/;

  test('a failed build (no notices, a non-zero status, no summary line, no listing) is recorded as failed and not called complete', () => {
    const r = summarize('   Compiling skyoauth-service v0.1.0\nerror[E0425]: cannot find value `x` in this scope\nerror: could not compile `skyoauth-service` (test "local_transport") due to 1 previous error\n', '0', '101', '', '101');
    assert.equal(r.status, 1);
    assert.equal(errors(r)[0], '::error::the root run exited 101');
    assert.equal(errors(r)[1], "::error::the listing of the root run's selection (cargo nextest list) exited 101");
    assert.equal(errors(r)[2], '::error::the root run printed no nextest summary line (`Summary [...] N tests run: ...`)');
    assert.match(errors(r)[3], /^::error::the listing of the root run's selection is missing or empty /);
    assert.equal(errors(r).length, 4, r.stdout);
    assert.match(r.summary, /^- \*\*Failed:\*\* the root run exited 101$/m);
    assert.doesNotMatch(r.summary, COMPLETE);
  });

  test('a non-zero status fails and is not called complete even with a passing summary line', () => {
    const r = summarize(log(), '0', '4');
    assert.equal(r.status, 1);
    assert.deepEqual(errors(r), ['::error::the root run exited 4']);
    assert.doesNotMatch(r.summary, COMPLETE);
  });

  test('no completion claim for a failed summary line, a missing log or a peer notice', () => {
    for (const r of [summarize(withSummary('Summary [   1.000s] 5 tests run: 4 passed, 1 failed, 3 skipped')), summarize(''), summarize(log(PEER))]) {
      assert.equal(r.status, 1);
      assert.doesNotMatch(r.summary, COMPLETE);
    }
  });

  test('an empty or missing log fails, and so does every selection, whose tests have no PASS line', () => {
    for (const text of ['', null]) {
      const r = summarize(text);
      assert.equal(r.status, 1, String(text));
      assert.match(errors(r)[0], /^::error::the root run left no output in /);
      assert.deepEqual(errors(r).slice(1), [
        `::error::\`skyoauth-service::local_transport\`: 0 of its ${LT} selected tests passed`,
        `::error::\`skyoauth-operator::operator\` \`local_path::*\`: 0 of its ${OP} selected tests passed`,
        `::error::\`skyoauth-scenarios::pg\` \`harness::socket_path_fixture::*\`: 0 of its ${PG} selected tests passed`,
        ...REQUIRED.map((t) => requiredError(t, 'no PASS line')),
      ]);
      assert.match(r.summary, /^- \*\*Failed:\*\* the root run left no output/m);
    }
  });

  test('a log without the nextest summary line fails', () => {
    for (const text of [`${START}${passLines()}`, `${START}${passLines()}test result: ok. 1 passed; 0 failed\n5 tests run: 5 passed\n`]) {
      const r = summarize(text);
      assert.equal(r.status, 1, text);
      assert.deepEqual(errors(r), ['::error::the root run printed no nextest summary line (`Summary [...] N tests run: ...`)']);
    }
  });

  test('a summary line that does not show every test run and passed fails', () => {
    for (const line of [
      'Summary [   1.000s] 5 tests run: 4 passed, 1 failed, 3 skipped',
      'Summary [   1.000s] 2/5 tests run: 2 passed, 3 skipped',
      'Summary [   1.000s] 0 tests run: 0 passed, 3 skipped',
      'Summary [   1.000s] 5 tests run: 4 passed (1 slow), 1 timed out, 3 skipped',
      'Summary [   1.000s] something else',
    ]) {
      const r = summarize(withSummary(line));
      assert.equal(r.status, 1, line);
      assert.deepEqual(errors(r), [`::error::not every root-only test ran and passed: ${line}`]);
    }
  });

  // nextest counts the tests of the built binaries that the filterset
  // leaves out as skipped. That count is tolerated only when it is exactly
  // the number the listing leaves out, and the run count must be exactly
  // the number it selects.
  test('the run and skipped counts must be exactly the listing\'s selected and left-out tests', () => {
    for (const [line, selected, leftOut] of [
      [`Summary [   1.000s] ${N} tests run: ${N} passed, 4 skipped`, SELECTED, LEFT_OUT],
      [`Summary [   1.000s] ${N} tests run: ${N} passed, 2 skipped`, SELECTED, LEFT_OUT],
      [`Summary [   1.000s] ${N} tests run: ${N} passed`, SELECTED, LEFT_OUT],
      [`Summary [   1.000s] ${N} tests run: ${N} passed, 0 skipped`, SELECTED, LEFT_OUT],
      [`Summary [   1.000s] ${N} tests run: ${N} passed, 3 skipped`, SELECTED, []],
      [`Summary [   1.000s] ${N + 1} tests run: ${N + 1} passed, 3 skipped`, SELECTED, LEFT_OUT],
      [`Summary [   1.000s] ${N - 1} tests run: ${N - 1} passed, 3 skipped`, SELECTED, LEFT_OUT],
    ]) {
      const r = summarize(withSummary(line), '0', '0', listing(selected, leftOut));
      assert.equal(r.status, 1, line);
      const run = /(\d+) tests run/.exec(line)[1];
      const skipped = /(\d+) skipped/.exec(line)?.[1] ?? '0';
      assert.deepEqual(errors(r), [`::error::nextest ran ${run} tests and skipped ${skipped}, but the listing selects ${selected.length} and leaves out ${leftOut.length}: ${line}`]);
      assert.doesNotMatch(r.summary, COMPLETE);
    }
    // No test left out and none skipped, with or without the count.
    for (const line of [`Summary [   0.100s] ${N} tests run: ${N} passed, 0 skipped`, `Summary [   0.100s] ${N} tests run: ${N} passed`]) {
      const r = summarize(withSummary(line), '0', '0', listing(SELECTED, []));
      assert.equal(r.status, 0, line + r.stdout);
      assert.match(r.summary, new RegExp(`the listing selects ${N} tests and leaves out 0 of the same binaries`));
    }
  });

  test('only the listing\'s ` (skipped)` mark leaves a test out, not the word in its name', () => {
    const selected = [...SELECTED, 'skyoauth-service::local_transport a_bind_is_never_skipped'];
    const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${N + 1} tests run: ${N + 1} passed, 3 skipped\n`, '0', '0', listing(selected));
    assert.equal(r.status, 0, r.stdout);
    assert.match(r.summary, new RegExp(`^- \`skyoauth-service::local_transport\`: ${LT + 1} of ${LT + 1} selected tests ran and passed$`, 'm'));
  });

  test('the last summary line counts; a slow test passes', () => {
    for (const line of [SUMMARY, `Summary [ 120.000s] ${N} tests run: ${N} passed (2 slow), 3 skipped`]) {
      const r = summarize(`${START}${passLines()}     Summary [   0.1s] 2 tests run: 1 passed, 1 failed\n     ${line}\n`);
      assert.equal(r.status, 0, line + r.stdout);
      assert.match(r.summary, new RegExp(`^- nextest: ${escapeRe(line)} \\(the listing`, 'm'));
    }
  });

  test('a selection the listing has no test of fails', () => {
    for (const [gone, name] of [
      ['skyoauth-scenarios::pg ', '`skyoauth-scenarios::pg` `harness::socket_path_fixture::*`'],
      ['skyoauth-operator::operator ', '`skyoauth-operator::operator` `local_path::*`'],
      ['skyoauth-service::local_transport ', '`skyoauth-service::local_transport`'],
    ]) {
      const selected = SELECTED.filter((t) => !t.startsWith(gone));
      const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, 3 skipped\n`, '0', '0', listing(selected));
      assert.equal(r.status, 1, gone);
      // That selection's required tests are not listed either.
      assert.deepEqual(errors(r), [`::error::the listing selects no test of ${name}`, ...REQUIRED.filter((t) => t.startsWith(gone)).map((t) => requiredError(t, 'not listed'))]);
      assert.match(r.summary, new RegExp(`^- ${escapeRe(name)}: 0 of 0 selected tests ran and passed$`, 'm'));
      assert.doesNotMatch(r.summary, COMPLETE);
    }
  });

  test('a selected test without a PASS line fails its selection, even when the counts agree', () => {
    // A test no check requires by name, so its selection's count is the
    // only error.
    const missing = EXTRA[0];
    assert.match(missing, /^skyoauth-operator::operator local_path::/);
    const text = `${START}${passLines(SELECTED.filter((t) => t !== missing))}        PASS [   0.004s] ( 9/5) skyoauth-operator::operator local_path::another_test\n${PASSED}`;
    const r = summarize(text);
    assert.equal(r.status, 1);
    assert.deepEqual(errors(r), [`::error::\`skyoauth-operator::operator\` \`local_path::*\`: ${OP - 1} of its ${OP} selected tests passed`]);
    // A FAIL line is no PASS line.
    const failed = summarize(`${START}${passLines(SELECTED.filter((t) => t !== missing))}        FAIL [   0.004s] ( 1/5) ${missing}\n${PASSED}`);
    assert.deepEqual(errors(failed), [`::error::\`skyoauth-operator::operator\` \`local_path::*\`: ${OP - 1} of its ${OP} selected tests passed`]);
  });

  test('a listing that selects a test outside the three selections fails', () => {
    const outside = [
      'skyoauth-scenarios::pg a01_a_scenario_that_needs_the_database',
      'skyoauth-operator::operator local_path_other::a_test',
      'skyoauth-scenarios::pg harness::socket_path_fixture_other::a_test',
      'skyoauth-service::local_wire a_test',
    ];
    for (const t of outside) {
      const selected = [...SELECTED, t];
      const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${N + 1} tests run: ${N + 1} passed, 3 skipped\n`, '0', '0', listing(selected));
      assert.equal(r.status, 1, t);
      assert.deepEqual(errors(r), [`::error::the filterset selects tests outside the three selections: 1 (${t})`]);
    }
    const many = Array.from({ length: 7 }, (_, i) => `skyoauth-scenarios::pg a0${i}_x`);
    const r = summarize(`${START}${passLines([...SELECTED, ...many])}     Summary [   1.000s] ${N + many.length} tests run: ${N + many.length} passed, 3 skipped\n`, '0', '0', listing([...SELECTED, ...many]));
    assert.deepEqual(errors(r), [`::error::the filterset selects tests outside the three selections: 7 (${many.slice(0, 5).join(', ')}, ...)`]);
  });

  // A profile or filterset change that leaves out a test of a selection:
  // the listing marks it skipped and nextest counts it as skipped, so the
  // totals alone would still agree; it is a failure of its own, and it is
  // not counted as an expected exclusion.
  test('a test of a selection that the listing marks skipped fails, though its siblings pass', () => {
    for (const dropped of [
      'skyoauth-operator::operator local_path::the_socket_must_be_the_expected_owners',
      'skyoauth-scenarios::pg harness::socket_path_fixture::socket_path_fixture_cases_match_the_services_bind',
      'skyoauth-service::local_transport the_service_uid_cannot_redirect_a_bind',
    ]) {
      // The harness selection has one test: give it a sibling that runs.
      const sibling = 'skyoauth-scenarios::pg harness::socket_path_fixture::a_sibling';
      const selected = [...SELECTED.filter((t) => t !== dropped), ...(dropped.startsWith('skyoauth-scenarios') ? [sibling] : [])];
      const leftOut = [...LEFT_OUT, dropped];
      const line = `Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, ${leftOut.length} skipped`;
      const r = summarize(`${START}${passLines(selected)}     ${line}\n`, '0', '0', listing(selected, leftOut));
      assert.equal(r.status, 1, dropped);
      assert.deepEqual(errors(r), [
        `::error::the listing marks 1 tests of the selections as skipped (${dropped}): the filterset leaves out tests it should run`,
        requiredError(dropped, 'listed as skipped'),
        // The dropped test is not an expected exclusion, so nextest's
        // skipped count is one more than the tests the listing leaves out.
        `::error::nextest ran ${selected.length} tests and skipped ${leftOut.length}, but the listing selects ${selected.length} and leaves out ${LEFT_OUT.length}: ${line}`,
      ]);
      assert.match(r.summary, /^- \*\*Failed:\*\* the listing marks 1 tests of the selections as skipped /m);
      assert.doesNotMatch(r.summary, COMPLETE);
    }
    // More than five: the first five names, then `...`.
    const many = Array.from({ length: 6 }, (_, i) => `skyoauth-operator::operator local_path::dropped_${i}`);
    const r = summarize(log(), '0', '0', listing(SELECTED, [...LEFT_OUT, ...many]));
    assert.equal(r.status, 1);
    assert.equal(errors(r)[0], `::error::the listing marks 6 tests of the selections as skipped (${many.slice(0, 5).join(', ')}, ...): the filterset leaves out tests it should run`);
  });

  test('a skipped test of a selection\'s binary outside its prefix is an expected exclusion', () => {
    const leftOut = [...LEFT_OUT, 'skyoauth-operator::operator redaction::x', 'skyoauth-operator::operator local_pathology::y', 'skyoauth-scenarios::pg harness::socket_path_fixture_more::z'];
    const line = `Summary [   1.000s] ${SELECTED.length} tests run: ${SELECTED.length} passed, ${leftOut.length} skipped`;
    const r = summarize(`${START}${passLines()}     ${line}\n`, '0', '0', listing(SELECTED, leftOut));
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(annotations(r), []);
    assert.match(r.summary, new RegExp(`^- nextest: ${escapeRe(line)} \\(the listing selects ${N} tests and leaves out 6 of the same binaries\\)$`, 'm'));
    assert.match(r.summary, COMPLETE);
  });

  test('a failed, missing, empty or malformed listing fails', () => {
    const failed = summarize(log(), '0', '0', LISTING, '1');
    assert.equal(failed.status, 1);
    assert.deepEqual(errors(failed), ["::error::the listing of the root run's selection (cargo nextest list) exited 1"]);
    for (const list of [null, '']) {
      const r = summarize(log(), '0', '0', list);
      assert.equal(r.status, 1, String(list));
      assert.equal(errors(r).length, 1, r.stdout);
      assert.match(errors(r)[0], /^::error::the listing of the root run's selection is missing or empty \(/);
      assert.doesNotMatch(r.summary, COMPLETE);
    }
    const bad = summarize(log(), '0', '0', `    Finished \`test\` profile\n${LISTING}`);
    assert.equal(bad.status, 1);
    assert.deepEqual(errors(bad), ['::error::the listing holds a line that is not `BINARY-ID TEST ...`:     Finished `test` profile']);
    // A blank line is malformed too, and does not hide a later malformed
    // line: the valid lines still match the run, so this is the only error.
    for (const [list, shown] of [
      [`\n    Finished \`test\` profile\n${LISTING}`, '(blank line)'],
      [`${LISTING}\n`, '(blank line)'],
      [`${LISTING.slice(0, LISTING.indexOf('\n') + 1)}  \t\n${LISTING.slice(LISTING.indexOf('\n') + 1)}`, '(blank line)'],
      [`${LISTING}%0A::error::x 50%\n`, '%250A::error::x 50%25'],
    ]) {
      const r = summarize(log(), '0', '0', list);
      assert.equal(r.status, 1, JSON.stringify(list.slice(0, 40)));
      assert.deepEqual(errors(r), [`::error::the listing holds a line that is not \`BINARY-ID TEST ...\`: ${shown}`]);
      assert.doesNotMatch(r.summary, COMPLETE);
    }
  });

  test('every failure is reported, not only the first', () => {
    const r = summarize(`${START}${passLines(SELECTED.slice(1))}${PEER}\n     Summary [   1.000s] 5 tests run: 4 passed, 1 failed, 3 skipped\n`);
    assert.equal(r.status, 1);
    assert.equal(errors(r).length, 3, r.stdout);
  });

  // Every NOTICE the three selections' sources print, through `summarize`:
  // each is one of the two kinds the script's comment lists, so that a
  // notice added or reworded there is classified here before it can pass
  // as a warning where it should fail the step (or the reverse). The
  // sources are every file the selections' modules are in, and the files
  // of their targets' helper modules and crate roots (SCANNED).
  test('each NOTICE of the selections\' sources fails or warns as the script documents', () => {
    const notices = sourceNotices();
    for (const [pattern] of KINDS) assert.ok(notices.some((n) => n.text.includes(pattern)), `no source prints a notice with ${JSON.stringify(pattern)}`);
    for (const { file, line, text } of notices) {
      const kinds = KINDS.filter(([pattern]) => text.includes(pattern));
      assert.equal(kinds.length, 1, `${file}:${line}: ${text}: not classified (or twice); add it to the script's comment and here`);
      const r = summarize(log(text));
      assert.deepEqual(warnings(r), [`::warning::${text}`], text);
      assert.equal(r.status, kinds[0][1] === 'fails' ? 1 : 0, `${file}:${line}: ${text} ${kinds[0][1]}\n${r.stdout}`);
    }
  });

  test('the scanned sources are the selections\' modules and their targets\' helpers and crate roots', () => {
    assert.deepEqual(
      SCANNED.map(({ bin, file, path }) => `${bin} ${file} ${path}`),
      [
        'skyoauth-service::local_transport service/tests/local_transport.rs ',
        'skyoauth-service::local_transport service/tests/common/mod.rs common::',
        'skyoauth-operator::operator operator/tests/operator.rs ',
        'skyoauth-operator::operator operator/tests/local_path/mod.rs local_path::',
        'skyoauth-operator::operator operator/tests/support/mod.rs support::',
        'skyoauth-scenarios::pg tests/pg.rs ',
        'skyoauth-scenarios::pg tests/harness/local_transport_wire.rs harness::local_transport_wire::',
        'skyoauth-scenarios::pg tests/harness/pg_teardown.rs harness::pg_teardown::',
        'skyoauth-scenarios::pg tests/harness/public_identity_fixture.rs harness::public_identity_fixture::',
        'skyoauth-scenarios::pg tests/harness/recovery_challenge_fixture.rs harness::recovery_challenge_fixture::',
        'skyoauth-scenarios::pg tests/harness/recovery_key_fixture.rs harness::recovery_key_fixture::',
        'skyoauth-scenarios::pg tests/harness/recovery_signature_fixture.rs harness::recovery_signature_fixture::',
        'skyoauth-scenarios::pg tests/harness/socket_path_fixture.rs harness::socket_path_fixture::',
        'skyoauth-scenarios::pg tests/harness/wire_errors.rs harness::wire_errors::',
        'skyoauth-scenarios::pg tests/harness/wire_fixture_keys.rs harness::wire_fixture_keys::',
      ],
    );
    // A notice anywhere in a literal is found, and none in a comment.
    const found = stringLiterals('// "NOTICE: in a comment"\n/* "NOTICE: x" */ let c = \'"\'; let s = "a NOTICE: b \\" c"; let r = r#"NOTICE: raw "q""#;\n');
    assert.deepEqual(found.filter((l) => l.text.includes('NOTICE:')).map((l) => l.text), ['a NOTICE: b \\" c', 'NOTICE: raw "q"']);
  });

  // REQUIRED, the tests that must run and pass by name, is the set of
  // tests around the notices that fail the step or say they need root, so
  // that a notice added, moved or renamed with its test fails here until
  // the script's list follows.
  test('REQUIRED is the tests around each notice that fails the step or says it needs root', () => {
    const required = new Set();
    for (const n of sourceNotices()) {
      const kind = KINDS.find(([pattern]) => n.text.includes(pattern))?.[1];
      if (kind !== 'fails' && !/\bneeds? root\b/.test(n.text)) continue;
      assert.ok(n.selected, `${n.file}:${n.line}: a notice that fails the step outside the selections' modules (${n.text}): map it to its tests in REQUIRED by hand`);
      assert.ok(n.test, `${n.file}:${n.line}: the notice is in \`fn ${n.fn ?? '?'}\`, not in a test: map it to its tests in REQUIRED by hand`);
      required.add(`${n.bin} ${n.path}${n.fn}`);
    }
    assert.deepEqual(REQUIRED, [...required].sort());
    for (const t of REQUIRED) {
      const [bin, name] = t.split(' ');
      assert.ok(SELECTIONS.some(([b, prefix]) => b === bin && name.startsWith(prefix)), `${t} is in no selection`);
    }
  });

  test('a required test that is not listed and did not run fails, by name, though every count agrees', () => {
    for (const gone of REQUIRED) {
      const selected = SELECTED.filter((t) => t !== gone);
      const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, ${LEFT_OUT.length} skipped\n`, '0', '0', listing(selected));
      assert.equal(r.status, 1, gone);
      assert.deepEqual(errors(r), [requiredError(gone, 'not listed')]);
      assert.match(r.summary, new RegExp(`^- \\*\\*Failed:\\*\\* required root-only test ${escapeRe(gone)} did not run: not listed$`, 'm'));
      assert.match(r.summary, new RegExp(`^- Required root-only tests .*: ${REQUIRED.length - 1} of ${REQUIRED.length} ran and passed$`, 'm'));
      assert.doesNotMatch(r.summary, COMPLETE);
    }
  });

  test('a required test listed as skipped, or listed without a PASS line, fails by name', () => {
    for (const gone of REQUIRED) {
      const selected = SELECTED.filter((t) => t !== gone);
      const skipped = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, ${LEFT_OUT.length + 1} skipped\n`, '0', '0', listing(selected, [...LEFT_OUT, gone]));
      assert.equal(skipped.status, 1, gone);
      assert.ok(errors(skipped).includes(requiredError(gone, 'listed as skipped')), skipped.stdout);
      const noPass = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${N} tests run: ${N} passed, ${LEFT_OUT.length} skipped\n`);
      assert.equal(noPass.status, 1, gone);
      assert.ok(errors(noPass).includes(requiredError(gone, 'no PASS line')), noPass.stdout);
    }
  });

  test('the script documents each notice kind and lists the failing ones in NOTICE_FAILS', () => {
    const source = readFileSync(SCRIPT, 'utf8');
    const fails = /^NOTICE_FAILS='([^']*)'$/m.exec(source)?.[1].split('\n');
    assert.deepEqual(fails, [
      'SKYOAUTH_IT_PEER_USER',
      'socket path cases were NOT run: they need root',
      'the owner check needs root',
      'socket path cases were NOT bound by the service',
      'no socket path case was bound by the service',
    ]);
  });
});

describe('run', () => {
  // Runs `run` with a fake test command (a shell script) and returns the
  // result, the log and stdout's lines.
  function runWith(script, logPath = fresh('run.log')) {
    const cmd = fresh('cmd.sh');
    writeFileSync(cmd, script);
    chmodSync(cmd, 0o755);
    const r = sh(['run', logPath, 'sh', cmd]);
    let logText = null;
    try {
      logText = readFileSync(logPath, 'utf8');
    } catch {}
    return { ...r, log: logText, lines: r.stdout.split('\n') };
  }
  const TOKEN = /^::stop-commands::([0-9a-f]{32})$/;
  // How many lines resume commands (the token on a line of its own).
  const resumes = (lines, token) => lines.filter((l) => l === `::${token}::`).length;

  test('workflow commands are stopped around the output, which is also in the log; the status is the command\'s', () => {
    const r = runWith('echo "::error::from a test"\necho "to stderr ::warning::x" >&2\nexit 3\n');
    assert.equal(r.status, 3, r.stderr);
    const token = TOKEN.exec(r.lines[0])?.[1];
    assert.ok(token, r.stdout);
    assert.deepEqual(r.lines.slice(1), ['::error::from a test', 'to stderr ::warning::x', '', `::${token}::`, '']);
    assert.equal(r.log, '::error::from a test\nto stderr ::warning::x\n');
    assert.equal(r.stderr, '');
  });

  // The step's listing: COMMAND through LIST_WRAPPER, as in ci.yml. Its
  // stderr is copied with workflow commands stopped; its stdout is the
  // listing file, byte for byte, and in neither the log nor the step log.
  test('a listing through the step\'s wrapper: stderr copied with commands stopped, stdout untouched in the listing, the command\'s status', () => {
    const listing = `${LISTING}::error::a test name\nno final newline`;
    for (const exit of [0, 3]) {
      const cmd = fresh('list.sh');
      writeFileSync(cmd, `printf '%s' "$LISTING_TEXT"\necho "warning: a manifest line ::error::x" >&2\necho "::set-output name=a::b" >&2\nprintf '##[error]y' >&2\nexit ${exit}\n`);
      const listPath = fresh('run.list');
      const logPath = fresh('list.log');
      const r = sh(['run', logPath, 'sh', '-c', LIST_WRAPPER, 'sh', listPath, 'sh', cmd], { env: { ...process.env, LISTING_TEXT: listing } });
      assert.equal(r.status, exit, r.stdout + r.stderr);
      assert.equal(readFileSync(listPath, 'utf8'), listing);
      const diagnostics = 'warning: a manifest line ::error::x\n::set-output name=a::b\n##[error]y';
      assert.equal(readFileSync(logPath, 'utf8'), diagnostics);
      const lines = r.stdout.split('\n');
      const token = TOKEN.exec(lines[0])?.[1];
      assert.ok(token, r.stdout);
      assert.deepEqual(lines.slice(1), [...diagnostics.split('\n'), `::${token}::`, '']);
      assert.equal(r.stderr, '');
    }
  });

  test('a listing through the step\'s wrapper that cannot write the listing file fails, with the reason in the log', () => {
    const listPath = join(TOP, 'missing-dir', 'run.list');
    const logPath = fresh('list.log');
    const r = sh(['run', logPath, 'sh', '-c', LIST_WRAPPER, 'sh', listPath, 'sh', '-c', 'echo listed; echo "::error::x" >&2']);
    assert.notEqual(r.status, 0, r.stdout);
    assert.match(readFileSync(logPath, 'utf8'), /run\.list/);
    assert.ok(!existsSync(listPath));
    assert.ok(!r.stdout.includes('::error::x'), r.stdout);
  });

  test('a passing command exits 0; each run has a new token', () => {
    const a = runWith('echo ok\n');
    const b = runWith('echo ok\n');
    assert.equal(a.status, 0);
    assert.notEqual(TOKEN.exec(a.lines[0])[1], TOKEN.exec(b.lines[0])[1]);
  });

  test('output without a final newline does not swallow the resume token', () => {
    const r = runWith('printf "no newline"\n');
    const token = TOKEN.exec(r.lines[0])[1];
    assert.deepEqual(r.lines.slice(1), ['no newline', `::${token}::`, '']);
  });

  test('when the log cannot be written: commands resume once, then the error is a live annotation, and the exit is 2', () => {
    for (const exit of [0, 3]) {
      const logPath = join(TOP, 'missing-dir', 'run.log');
      const r = runWith(`echo x\nexit ${exit}\n`, logPath);
      assert.equal(r.status, 2, r.stdout + r.stderr);
      const token = TOKEN.exec(r.lines[0])?.[1];
      assert.ok(token, r.stdout);
      // The token line comes before the annotation: an annotation inside
      // the stopped region would be read as plain text.
      assert.deepEqual(r.lines.slice(1), ['x', '', `::${token}::`, `::error::could not write the log ${logPath} (tee exited 1)`, '']);
      assert.equal(resumes(r.lines, token), 1, r.stdout);
    }
  });

  // The signal tests below cover signals delivered to the helper, that is
  // when the script itself gets TERM, INT or HUP (a signal to its process
  // group, e.g. from a terminal or `timeout`); on a cancel the Actions
  // runner signals only the step's shell, so the script usually gets none,
  // and a stop it leaves ends with the step. None of them is a hosted
  // cancellation.
  //
  // runSignalled starts `run` of a command that prints `ready` and then
  // waits for its stdin to close (the `read` builtin) in a process group of
  // its own, and sends SIGNAL to the helper:
  //   - to: 'group': to the whole group once `ready` is out;
  //   - to: 'script': to the script alone once `ready` is out, and stdin is
  //     closed only after the signal was sent;
  //   - hook: NAME: from a stand-in for the external command NAME, put
  //     first on PATH, the first time the script runs it: the stand-in
  //     sends SIGNAL to the script (whose PID the test wrote to a file
  //     before closing stdin, so before the command can end), records that
  //     it did, and then runs the real NAME. `kill` returns once the signal
  //     is pending, so it reaches the script at that point of its run.
  // The command then prints `done` and exits with `exit` (default 0); the
  // log is written to `logPath` (default: a new file).
  // It returns the exit status, the signal that killed the script (null if
  // none), stdout's lines and whether the hook fired. The one timer is a
  // backstop that kills the group, so a broken script fails the test
  // instead of hanging it.
  function runSignalled(signal, { to, hook, exit = 0, logPath = fresh('run.log') } = {}) {
    const cmd = fresh('cmd.sh');
    writeFileSync(cmd, `echo ready\nwhile read -r _; do :; done\necho done\nexit ${exit}\n`);
    const env = { ...process.env };
    const pidFile = fresh('pid');
    const fired = fresh('fired');
    if (hook) {
      const bin = fresh('bin');
      mkdirSync(bin);
      writeFileSync(
        join(bin, hook),
        `#!/bin/sh\nif [ ! -e "$HOOK_FIRED" ]; then\n  : > "$HOOK_FIRED"\n  read -r pid < "$HOOK_PID"\n  kill -${signal.replace(/^SIG/, '')} "$pid"\nfi\nPATH=$HOOK_REAL_PATH exec ${hook} "$@"\n`,
      );
      chmodSync(join(bin, hook), 0o755);
      Object.assign(env, { PATH: `${bin}:${process.env.PATH}`, HOOK_REAL_PATH: process.env.PATH, HOOK_PID: pidFile, HOOK_FIRED: fired });
    }
    const child = spawn('sh', [SCRIPT, 'run', logPath, 'sh', cmd], { detached: true, stdio: ['pipe', 'pipe', 'pipe'], env });
    if (hook) {
      writeFileSync(pidFile, `${child.pid}\n`);
      child.stdin.end();
    }
    let stdout = '';
    let sent = false;
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      if (to && !sent && /^ready$/m.test(stdout)) {
        sent = true;
        process.kill(to === 'group' ? -child.pid : child.pid, signal);
        child.stdin.end();
      }
    });
    const backstop = setTimeout(() => {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {}
    }, 30_000);
    return new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (status, sig) => {
        clearTimeout(backstop);
        resolve({ status, signal: sig, lines: stdout.split('\n'), fired: existsSync(fired) });
      });
    });
  }

  describe('a signal delivered to the helper', () => {
    for (const [signal, status] of [['SIGTERM', 143], ['SIGINT', 130], ['SIGHUP', 129]]) {
      test(`a ${signal} delivered to the helper's process group still resumes commands, once, and exits ${status}`, async () => {
        const r = await runSignalled(signal, { to: 'group' });
        assert.equal(r.signal, null, `killed by ${r.signal}: the EXIT trap did not run`);
        assert.equal(r.status, status, r.lines.join('\n'));
        const token = TOKEN.exec(r.lines[0])?.[1];
        assert.ok(token, r.lines.join('\n'));
        assert.deepEqual(r.lines.slice(1), ['ready', '', `::${token}::`, '']);
      });
    }

    test('a SIGTERM delivered to the helper alone resumes commands, once, after the command ends, and exits 143', async () => {
      const r = await runSignalled('SIGTERM', { to: 'script' });
      assert.equal(r.signal, null, `killed by ${r.signal}: the EXIT trap did not run`);
      assert.equal(r.status, 143, r.lines.join('\n'));
      const token = TOKEN.exec(r.lines[0])?.[1];
      assert.deepEqual(r.lines.slice(1), ['ready', 'done', '', `::${token}::`, '']);
    });

    // After the command and the copy have ended and before the script
    // exits: `cat` reads the command's status, `rm` removes that file on
    // the way out. The resume token is printed exactly once either way.
    for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
      test(`a ${signal} delivered to the helper after the command ended, while it reads the status, resumes commands once`, async () => {
        const r = await runSignalled(signal, { hook: 'cat' });
        assert.ok(r.fired, 'the cat stand-in did not run: the test no longer reaches this point of the script');
        assert.equal(r.signal, null, `killed by ${r.signal}: the EXIT trap did not run`);
        assert.equal(r.status, { SIGTERM: 143, SIGINT: 130, SIGHUP: 129 }[signal], r.lines.join('\n'));
        const token = TOKEN.exec(r.lines[0])?.[1];
        assert.deepEqual(r.lines.slice(1), ['ready', 'done', '', `::${token}::`, '']);
      });
    }

    // While `resume` runs, after it printed the token: `rm` removes the
    // status file, and for a failed copy `awk` writes the `::error::`
    // annotation (`annotate`; neither runs earlier in `run`). `resume`
    // ignores TERM, INT and HUP, so the signal changes nothing: neither the
    // exit status (the command's, or 2 for a failed copy, never 143, 130 or
    // 129), nor the token (once), nor the annotation after it.
    for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
      test(`a ${signal} delivered to the helper while it cleans up on the way out is ignored: the command's status, the token once`, async () => {
        const r = await runSignalled(signal, { hook: 'rm', exit: 3 });
        assert.ok(r.fired, 'the rm stand-in did not run: the test no longer reaches this point of the script');
        assert.equal(r.signal, null, `killed by ${r.signal}: the signal was not trapped on the way out`);
        assert.equal(r.status, 3, `${r.status}: the signal was not ignored while resume ran\n${r.lines.join('\n')}`);
        const token = TOKEN.exec(r.lines[0])?.[1];
        assert.ok(token, r.lines.join('\n'));
        assert.deepEqual(r.lines.slice(1), ['ready', 'done', '', `::${token}::`, '']);
      });

      for (const hook of ['rm', 'awk']) {
        test(`a ${signal} delivered to the helper while it reports a failed copy (${hook}) is ignored: exit 2, the token once, then the error`, async () => {
          const logPath = join(TOP, 'missing-dir', 'run.log');
          const r = await runSignalled(signal, { hook, exit: 3, logPath });
          assert.ok(r.fired, `the ${hook} stand-in did not run: the test no longer reaches this point of the script`);
          assert.equal(r.signal, null, `killed by ${r.signal}: the signal was not trapped on the way out`);
          assert.equal(r.status, 2, `${r.status}: the signal was not ignored while resume ran\n${r.lines.join('\n')}`);
          const token = TOKEN.exec(r.lines[0])?.[1];
          assert.ok(token, r.lines.join('\n'));
          assert.deepEqual(r.lines.slice(1), ['ready', 'done', '', `::${token}::`, `::error::could not write the log ${logPath} (tee exited 1)`, '']);
        });
      }
    }
  });

  // A second signal that arrives while a handler runs, before `resume`
  // ignores signals, cannot be placed by a test: the handlers and `resume`
  // up to its `trap ''` run only builtins, so no stand-in runs in that gap,
  // and signals sent together are not run one after another (dash runs the
  // trap of the lowest-numbered pending one, which exits). So the source is
  // read: every handler ignores the three signals before it exits, the
  // script ignores them once COMMAND's status is read (a later signal would
  // otherwise land between the last trap check and `resume`, and lose the
  // token), and `resume` ignores them first.
  test('each signal handler, the script after the status read, and resume ignore TERM, INT and HUP', () => {
    const source = readFileSync(SCRIPT, 'utf8');
    const body = source.slice(source.indexOf('\nrun() {'), source.indexOf('\nsummarize() {'));
    assert.deepEqual(body.match(/^\s*trap\b.*$/gm), [
      "        trap '' TERM INT HUP",
      '    trap resume EXIT',
      `    trap 'trap "" TERM INT HUP; exit 143' TERM`,
      `    trap 'trap "" TERM INT HUP; exit 130' INT`,
      `    trap 'trap "" TERM INT HUP; exit 129' HUP`,
      "    trap '' TERM INT HUP",
    ]);
    const resume = body.slice(body.indexOf('resume() {'), body.indexOf('\n    }\n', body.indexOf('resume() {')));
    assert.equal(resume.split('\n')[1], "        trap '' TERM INT HUP", 'resume does not ignore signals first');
  });

  test('the EXIT trap is the only place that prints the resume token, and it is never cleared', () => {
    const source = readFileSync(SCRIPT, 'utf8');
    const body = source.slice(source.indexOf('\nrun() {'), source.indexOf('\nsummarize() {'));
    assert.ok(body.length > 0);
    // One printf of the token, inside `resume`, and `resume` is the EXIT trap.
    assert.equal(body.split("printf '\\n::%s::\\n' \"$token\"").length - 1, 1, 'the resume token is printed from more than one place');
    const resume = body.slice(body.indexOf('resume() {'), body.indexOf('\n    }\n', body.indexOf('resume() {')));
    assert.match(resume, /printf '\\n::%s::\\n' "\$token"/);
    assert.deepEqual(body.match(/^\s*trap\b.*\bEXIT\b.*$/gm), ['    trap resume EXIT']);
    assert.doesNotMatch(body, /^\s*trap\s+-/m, 'a trap is cleared');
  });

  test('usage errors exit 2', () => {
    for (const args of [[], ['run'], ['run', fresh('x.log')], ['summarize', fresh('x.log')], ['other']]) {
      assert.equal(sh(args, { env: { ...process.env, GITHUB_STEP_SUMMARY: fresh('s.md') } }).status, 2, args.join(' '));
    }
  });
});

// ---------------------------------------------------------------------------
// The `service-nextest` job in ci.yml.

const CI = readFileSync(join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
const jobOf = (ci, job) => ci.match(new RegExp(`^  ${job}:\\n((?:(?: {4}.*)?\\n)*)`, 'm'))?.[1] ?? '';
const stepsOf = (body) => body.split(/^(?= {6}- )/m).filter((s) => s.startsWith('      - '));
const stepNamed = (body, name) => stepsOf(body).filter((s) => s.startsWith(`      - name: ${name}\n`));
// An upload step's `name` and its paths (one `path:` value or a `|` block).
const upload = (step) => {
  const name = /^ {10}name: (.+)$/m.exec(step)?.[1];
  const block = /^ {10}path: \|\n((?: {12}.*\n)+)/m.exec(step);
  const paths = block ? block[1].split('\n').filter(Boolean).map((l) => l.trim()) : [/^ {10}path: (.+)$/m.exec(step)?.[1]];
  return { name, paths, if: /^ {8}if: (.+)$/m.exec(step)?.[1] };
};

// The step's `selection=(...)` array: its flags before `-E`, and the
// filterset after it (one single-quoted word).
const selectionOf = (run) => {
  const m = /^ {10}selection=\(((?:[^)']|'[^']*')*)\)$/m.exec(run);
  if (!m) return undefined;
  const [flags, filter] = m[1].split(/\s+-E\s+/);
  return { flags: flags.trim().split(/\s+/), filter: /^'([^']*)'$/.exec(filter?.trim() ?? '')?.[1] };
};

const problems = (ci) => {
  const out = [];
  const job = jobOf(ci, 'service-nextest');
  if (!job) return ['no service-nextest job'];
  const uploads = stepsOf(job).filter((s) => /^ {8}uses: actions\/upload-artifact@/m.test(s)).map(upload);
  const want = [
    { name: 'service-nextest-junit-${{ github.run_attempt }}', paths: ['target/nextest/ci/junit.xml'], if: 'always()' },
    // Only when the root step started: when it was skipped (the normal run
    // never started, or the job was cancelled first) there is nothing to
    // upload, and `if-no-files-found: warn` would warn for nothing.
    { name: 'service-nextest-root-junit-${{ github.run_attempt }}', paths: ['target/nextest/ci-root/junit.xml'], if: "${{ always() && steps.root.outcome != 'skipped' }}" },
  ];
  // One file each, so it is at the top of its artifact (upload-artifact
  // strips the files' common directory): a nested junit.xml breaks the
  // conformance reporter and the badge publisher.
  if (JSON.stringify(uploads) !== JSON.stringify(want)) out.push(`uploads ${JSON.stringify(uploads)}, want ${JSON.stringify(want)}`);
  const tests = stepNamed(job, 'Run tests')[0] ?? '';
  const root = stepNamed(job, 'Run the root-only local transport tests')[0] ?? '';
  if (!root) return [...out, 'no root step'];
  if (!/^ {8}id: tests$/m.test(tests)) out.push('the normal run has no `id: tests`');
  if (!/^ {8}id: root$/m.test(root)) out.push('the root step has no `id: root`, which gates its upload');
  // A missing report after a root step that started is not silent.
  for (const step of stepsOf(job).filter((s) => /^ {8}uses: actions\/upload-artifact@/m.test(s))) {
    if (!/^ {10}if-no-files-found: warn$/m.test(step)) out.push(`upload ${upload(step).name} does not warn when its file is missing`);
  }
  if (stepsOf(job).indexOf(root) !== stepsOf(job).indexOf(tests) + 1) out.push('the root step does not follow the normal run');
  // It runs after a failed normal run too, not when that never ran.
  if (!/^ {8}if: \$\{\{ !cancelled\(\) && steps\.tests\.outcome != 'skipped' \}\}$/m.test(root)) out.push('the root step does not run after a failed normal run');
  const run = root.slice(root.indexOf('        run: |\n'));
  if (!/^ {10}set -euo pipefail$/m.test(run)) out.push('the root step does not set -euo pipefail');
  if (!/^ {10}sh scripts\/ci\/root-transport-run\.sh run "\$log" \\$/m.test(run)) out.push('the root step does not run the tests through root-transport-run.sh run');
  if (!/^ {10}sh scripts\/ci\/root-transport-run\.sh summarize "\$log" "\$userns" "\$status" "\$list" "\$listed" \|\| status=\$\?$/m.test(run)) out.push('the root step does not call root-transport-run.sh summarize with the run\'s status and the listing');
  // The step's exit is the run's, the listing's (through summarize) and
  // summarize's: its last line, and nothing lets the job pass without it.
  // The `run: |` block alone: its lines indented under it (what follows
  // in this text is the next step's comment).
  const block = /^ {8}run: \|\n((?:(?: {10}.*)?\n)*)/m.exec(root)?.[1].trimEnd() ?? '';
  if (!block.endsWith('\n          exit "$status"')) out.push('the root step does not end with exit "$status"');
  if (/^\s*continue-on-error:/m.test(job)) out.push('the service-nextest job or one of its steps has continue-on-error');
  const gate = jobOf(ci, 'ci-passed');
  const needs = /^ {4}needs:\n((?: {6}- .*\n)+)/m.exec(gate)?.[1].split('\n').map((l) => l.trim().replace(/^- /, '')).filter(Boolean) ?? [];
  if (!needs.includes('service-nextest')) out.push('ci-passed does not need service-nextest');
  if (!/^ {4}if: always\(\)$/m.test(gate) || !/RESULTS: \$\{\{ join\(needs\.\*\.result, ' '\) \}\}/.test(gate) || !/success \| skipped\) ;;\n\s*\*\) exit 1 ;;/.test(gate)) out.push('ci-passed does not fail on a needed job that did not succeed');
  if (!/"CARGO_TERM_COLOR=never"/.test(run) || /CARGO_TERM_COLOR=\$/.test(run)) out.push('the root run does not set CARGO_TERM_COLOR=never');
  if (!/^ {12}"\$\{as_root\[@\]\}" cargo nextest run "\$\{selection\[@\]\}" --no-capture \\$/m.test(run)) out.push('the root run is not the selection, as root, with --no-capture');
  const listCall = [
    '          sh scripts/ci/root-transport-run.sh run "$list_log" \\',
    `            sh -c '${LIST_WRAPPER}' sh "$list" \\`,
    '            "${as_root[@]}" cargo nextest list "${selection[@]}" --message-format oneline --verbose \\',
    '            || listed=$?',
  ].join('\n');
  if (!run.includes(`\n          listed=0\n${listCall}\n`)) out.push('the selection is not listed as root, one test per line, its stdout into $list and its stderr through root-transport-run.sh run into $list_log');
  if ((run.match(/cargo nextest list/g) ?? []).length !== 1) out.push('the selection is listed more than once, or outside root-transport-run.sh run');
  const assigned = (name) => new RegExp(`^ {10}${name}="([^"]*)"$`, 'm').exec(run)?.[1];
  if (!assigned('list_log') || [assigned('log'), assigned('list')].includes(assigned('list_log'))) out.push("the listing's log is not a file of its own");
  if (!/^ {10}as_root=\(sudo env .*"SKYOAUTH_IT_PEER_USER=\$peer"\)$/m.test(run.replace(/\n {12}(?=")/g, ' '))) out.push('as_root does not run as root with SKYOAUTH_IT_PEER_USER');
  const selection = selectionOf(run);
  if (!selection) out.push('no selection array');
  else {
    const want = SELECTIONS.map(([bin, prefix]) => {
      const [pkg, target] = bin.split('::');
      return `(package(${pkg}) & binary(${target})${prefix ? ` & test(/^${prefix}/)` : ''})`;
    });
    if (selection.filter !== want.join(' | ')) out.push(`the filterset ${JSON.stringify(selection.filter)} is not the script's SELECTIONS ${JSON.stringify(want.join(' | '))}`);
    const flags = ['--locked', ...SELECTIONS.flatMap(([bin]) => ['-p', bin.split('::')[0]]), ...SELECTIONS.flatMap(([bin]) => ['--test', bin.split('::')[1]]), '--all-features', '--profile', 'ci-root', '--run-ignored', 'all'];
    if (JSON.stringify(selection.flags) !== JSON.stringify(flags)) out.push(`the selection's flags ${JSON.stringify(selection.flags)} are not ${JSON.stringify(flags)}`);
  }
  if (!/^ {10}unshare --user --map-root-user --mount true \|\| userns=\$\?$/m.test(run)) out.push('the user namespace probe is missing or runs as root');
  if (/\|\s*grep\s+(-\w*\s+)*-\w*q/.test(run)) out.push('a pipe into grep -q under pipefail');
  if (/::(warning|error|notice)::\$/.test(run)) out.push('an annotation with an unescaped variable');
  return out;
};

describe('the service-nextest job in ci.yml', () => {
  test('uploads one JUnit file per artifact and runs the root step through the script', () => {
    assert.deepEqual(problems(CI), []);
  });

  test('each way of breaking it is caught', () => {
    const job = jobOf(CI, 'service-nextest');
    const inJob = (f) => CI.replace(job, () => f(job));
    const cases = [
      // The nested two-file upload this job once had.
      [(b) => b.replace('          path: target/nextest/ci/junit.xml\n', '          path: |\n            target/nextest/ci/junit.xml\n            target/nextest/ci-root/junit.xml\n'), /uploads/],
      [(b) => b.replace('service-nextest-root-junit-', 'service-nextest-junit-root-'), /uploads/],
      [(b) => b.replace("if: ${{ !cancelled() && steps.tests.outcome != 'skipped' }}", 'if: success()'), /after a failed normal run/],
      [(b) => b.replace('"CARGO_TERM_COLOR=never"', '"CARGO_TERM_COLOR=$CARGO_TERM_COLOR"'), /CARGO_TERM_COLOR=never/],
      [(b) => b.replace(/^ {10}sh scripts\/ci\/root-transport-run\.sh run "\$log" \\\n/m, '          ( \\\n'), /through root-transport-run\.sh run/],
      [(b) => b.replace(/^( {10}sh scripts\/ci\/root-transport-run\.sh summarize .*)$/m, '$1\n          if printf \'%s\\n\' "$x" | grep -q y; then exit 1; fi'), /grep -q/],
      [(b) => b.replace(/^( {10}sh scripts\/ci\/root-transport-run\.sh summarize .*)$/m, '$1\n          echo "::warning::$x"'), /unescaped/],
      [(b) => b.replace('          unshare --user --map-root-user --mount true || userns=$?\n', '          sudo unshare --user --map-root-user --mount true || userns=$?\n'), /probe/],
      [(b) => b.replace('        id: tests\n', ''), /id: tests/],
      [(b) => b.replace('        id: root\n', ''), /id: root/],
      // The upload as it was: it warned when the root step was skipped.
      [(b) => b.replace("if: ${{ always() && steps.root.outcome != 'skipped' }}", 'if: always()'), /uploads/],
      [(b) => b.replace(/(service-nextest-root-junit-.*\n.*\n {10}if-no-files-found: )warn/, '$1ignore'), /service-nextest-root-junit-.* does not warn/],
      [(b) => b.replace('summarize "$log" "$userns" "$status"', 'summarize "$log" "$userns" 0'), /with the run's status/],
      [(b) => b.replace('"$status" "$list" "$listed" ||', '"$status" "$list" 0 ||'), /and the listing/],
      // The selection: widened to the whole `pg` target (its database
      // scenarios), narrowed to one selection, or out of step with SELECTIONS.
      [(b) => b.replace(' & test(/^harness::socket_path_fixture::/)', ''), /is not the script's SELECTIONS/],
      [(b) => b.replace(/ \| \(package\(skyoauth-scenarios\)[^']*/, ''), /is not the script's SELECTIONS/],
      [(b) => b.replace('test(/^local_path::/)', 'test(/^local_path/)'), /is not the script's SELECTIONS/],
      [(b) => b.replace(' -p skyoauth-scenarios', ''), /the selection's flags/],
      [(b) => b.replace(' --test pg', ''), /the selection's flags/],
      [(b) => b.replace('--all-features --profile ci-root --run-ignored all\n', '--profile ci-root --run-ignored all\n'), /the selection's flags/],
      [(b) => b.replace('"${selection[@]}" --no-capture', '"${selection[@]}"'), /with --no-capture/],
      [(b) => b.replace('cargo nextest run "${selection[@]}"', 'cargo nextest run --locked -p skyoauth-service --test local_transport'), /the selection, as root/],
      [(b) => b.replace('"${as_root[@]}" cargo nextest list', 'cargo nextest list'), /listed as root/],
      [(b) => b.replace(' --message-format oneline --verbose', ''), /one test per line/],
      [(b) => b.replace(' "SKYOAUTH_IT_PEER_USER=$peer")', ')'), /SKYOAUTH_IT_PEER_USER/],
      // The listing as it was: run bare, its stderr reaching the runner
      // with workflow commands live.
      [(b) => b.replace(/^ {10}sh scripts\/ci\/root-transport-run\.sh run "\$list_log" \\\n {12}sh -c '[^']*' sh "\$list" \\\n {12}("\$\{as_root\[@\]\}" cargo nextest list .*) \\\n {12}\|\| listed=\$\?$/m, '          $1 > "$list" || listed=$?'), /its stderr through root-transport-run\.sh run/],
      // Its stderr into the listing, or its stdout into the copy.
      [(b) => b.replace('exec "$@" > "$out"\'', 'exec "$@" > "$out" 2>&1\''), /its stdout into \$list/],
      [(b) => b.replace(`sh -c '${LIST_WRAPPER}' sh "$list" \\\n            `, ''), /its stdout into \$list/],
      [(b) => b.replace('root-transport-run.sh run "$list_log"', 'root-transport-run.sh run "$log"'), /into \$list_log/],
      [(b) => b.replace('list_log="$RUNNER_TEMP/local-transport-root-list.log"', 'list_log="$RUNNER_TEMP/local-transport-root.log"'), /a file of its own/],
      [(b) => b.replace('            || listed=$?\n', '            || status=$?\n'), /listed as root/],
      [(b) => b.replace(/^( {10}sudo chown .*)$/m, '$1\n          "${as_root[@]}" cargo nextest list "${selection[@]}" > /dev/null'), /listed more than once/],
      // The step's exit.
      [(b) => b.replace('          exit "$status"\n', '          exit 0\n'), /end with exit "\$status"/],
      [(b) => b.replace('"$list" "$listed" || status=$?', '"$list" "$listed" || true'), /summarize with the run's status/],
      [(b) => b.replace('        id: root\n', '        id: root\n        continue-on-error: true\n'), /continue-on-error/],
      [(b) => b.replace(/^( {4}runs-on: .*)$/m, '$1\n    continue-on-error: true'), /continue-on-error/],
    ];
    for (const [f, re] of cases) {
      const changed = inJob(f);
      assert.notEqual(changed, CI, `${re}: the mutation did not apply`);
      assert.match(problems(changed).join('\n'), re);
    }
    // The aggregate job.
    const gate = jobOf(CI, 'ci-passed');
    for (const [f, re] of [
      [(b) => b.replace('      - service-nextest\n', ''), /ci-passed does not need service-nextest/],
      [(b) => b.replace('              *) exit 1 ;;\n', '              *) ;;\n'), /does not fail on a needed job/],
      [(b) => b.replace('    if: always()\n', ''), /does not fail on a needed job/],
    ]) {
      const changed = CI.replace(gate, () => f(gate));
      assert.notEqual(changed, CI, `${re}: the mutation did not apply`);
      assert.match(problems(changed).join('\n'), re);
    }
  });
});
