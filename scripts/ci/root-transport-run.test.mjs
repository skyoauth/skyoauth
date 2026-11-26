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

// The step's two calls; `sh` is the shell the step's `sh` resolves to.
const sh = (args, opts = {}) => spawnSync('sh', [SCRIPT, ...args], { encoding: 'utf8', timeout: 60_000, killSignal: 'SIGKILL', maxBuffer: 64 * 1024 * 1024, ...opts });

// Runs `summarize` on a log with this text (null: no log file) and returns
// { status, stdout, stderr, summary, lines }: `lines` are stdout's lines.
function summarize(text, userns = '0', status = '0') {
  const log = fresh('run.log');
  if (text !== null) writeFileSync(log, text);
  const summary = fresh('summary.md');
  writeFileSync(summary, '# earlier step\n');
  const r = sh(['summarize', log, userns, status], { env: { ...process.env, GITHUB_STEP_SUMMARY: summary } });
  return { ...r, summary: readFileSync(summary, 'utf8'), lines: r.stdout.split('\n').filter(Boolean) };
}

// What nextest 0.9 prints with --no-capture and CARGO_TERM_COLOR=never
// (the lines the script reads, as in a real run of the local_transport
// binary as root).
const START = '    Starting 54 tests across 1 binary\n       START [         ] (1/54) skyoauth-service::local_transport a\n';
const PASSED = '────────────\n     Summary [  56.610s] 54 tests run: 54 passed, 0 skipped\n';
const PEER = 'NOTICE: SKYOAUTH_IT_PEER_USER is not set: the cross-UID peer check was NOT run (it needs root and a second local user; set SKYOAUTH_IT_PEER_USER=<user> to run it)';
const PROC = 'NOTICE: a bind without /proc was NOT tested: the mount namespace or the mount on /proc was denied (unshare: cannot change root filesystem propagation: Permission denied)';
const log = (...lines) => `${START}${lines.map((l) => `${l}\n`).join('')}${PASSED}`;
const errors = (r) => r.lines.filter((l) => l.startsWith('::error::'));
const warnings = (r) => r.lines.filter((l) => l.startsWith('::warning::'));

describe('summarize', () => {
  test('no notices and every test passed: passes, and the summary says so', () => {
    const r = summarize(log('147 private directories swapped during 400 binds, 398 served'));
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(r.lines, []);
    assert.equal(
      r.summary,
      '# earlier step\n### Root-only local transport tests\n\n' +
        '- nextest: Summary [  56.610s] 54 tests run: 54 passed, 0 skipped\n' +
        '- User namespaces for the runner user (not root; `unshare --user --map-root-user --mount true`): allowed (exit 0)\n' +
        '- Every test of the `local_transport` integration target ran as root and passed, and none printed a notice: each of its root-only checks ran.\n',
    );
  });

  test('the user namespace probe is reported as allowed or denied with its exit status', () => {
    assert.match(summarize(log(), '0').summary, /^- User namespaces for the runner user .*: allowed \(exit 0\)$/m);
    assert.match(summarize(log(), '1').summary, /^- User namespaces for the runner user .*: denied \(exit 1\)$/m);
    assert.match(summarize(log(), '127').summary, /: denied \(exit 127\)$/m);
    for (const bad of ['', 'x', '-1', '1 2']) {
      assert.equal(summarize(log(), bad).status, 2, JSON.stringify(bad));
      assert.equal(summarize(log(), '0', bad).status, 2, JSON.stringify(bad));
    }
  });

  test('a notice about SKYOAUTH_IT_PEER_USER fails, with an error and the notice as a warning', () => {
    const r = summarize(log(PEER));
    assert.equal(r.status, 1, r.stdout);
    assert.deepEqual(errors(r), ['::error::a test printed a notice about SKYOAUTH_IT_PEER_USER although the step sets it: the root-only cross-UID checks did not run']);
    assert.deepEqual(warnings(r), [`::warning::${PEER}`]);
    assert.match(r.summary, /^- \*\*Failed:\*\* a test printed a notice about SKYOAUTH_IT_PEER_USER/m);
    assert.match(r.summary, new RegExp(`^- ${PEER.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
  });

  test('another notice is a warning and in the summary, and passes; repeats are shown once', () => {
    const r = summarize(log(PROC, 'some output', `  ${PROC.replace('NOTICE', 'NOTICE')}`, PROC));
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(errors(r), []);
    assert.deepEqual(warnings(r), [`::warning::  ${PROC}`, `::warning::${PROC}`]);
    assert.match(r.summary, /Notices printed by tests \(a test that could not run its check\):\n\n- {3}NOTICE: a bind without \/proc.*\n- NOTICE: a bind without \/proc[^\n]*\n$/);
    assert.doesNotMatch(r.summary, /each of its root-only checks ran/);
  });

  test('a notice cannot inject a workflow command: %, CR and LF are escaped', () => {
    const evil = 'NOTICE: x %0A::error::injected %25 50% \r::error::cr';
    const r = summarize(log(evil));
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(r.lines, ['::warning::NOTICE: x %250A::error::injected %2525 50%25 %0D::error::cr']);
    // Every stdout line is one annotation: no other workflow command.
    assert.ok(r.stdout.split('\n').every((l) => l === '' || l.startsWith('::warning::')));
    assert.ok(!r.stdout.includes('\r'));
  });

  test('an error that quotes the log is escaped too', () => {
    const r = summarize(`${START}     Summary [   1.000s] 5 tests run: 4 passed %0A::error::injected 50% \r::warning::cr\n`);
    assert.equal(r.status, 1);
    assert.deepEqual(r.lines, ['::error::not every root-only test ran and passed: Summary [   1.000s] 5 tests run: 4 passed %250A::error::injected 50%25 %0D::warning::cr']);
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

  const COMPLETE = /each of its root-only checks ran/;

  test('a failed build (no notices, a non-zero status, no summary line) is recorded as failed and not called complete', () => {
    const r = summarize('   Compiling skyoauth-service v0.1.0\nerror[E0425]: cannot find value `x` in this scope\nerror: could not compile `skyoauth-service` (test "local_transport") due to 1 previous error\n', '0', '101');
    assert.equal(r.status, 1);
    assert.deepEqual(errors(r), ['::error::the root run exited 101', '::error::the root run printed no nextest summary line (`Summary [...] N tests run: ...`)']);
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
    for (const r of [summarize(`${START}     Summary [   1.000s] 54 tests run: 53 passed, 1 failed, 0 skipped\n`), summarize(''), summarize(log(PEER))]) {
      assert.equal(r.status, 1);
      assert.doesNotMatch(r.summary, COMPLETE);
    }
  });

  test('an empty or missing log fails', () => {
    for (const text of ['', null]) {
      const r = summarize(text);
      assert.equal(r.status, 1, String(text));
      assert.equal(errors(r).length, 1);
      assert.match(errors(r)[0], /^::error::the root run left no output in /);
      assert.match(r.summary, /^- \*\*Failed:\*\* the root run left no output/m);
    }
  });

  test('a log without the nextest summary line fails', () => {
    for (const text of [START, `${START}test result: ok. 1 passed; 0 failed\n54 tests run: 54 passed\n`, 'error: could not compile `skyoauth-service`\n']) {
      const r = summarize(text);
      assert.equal(r.status, 1, text);
      assert.deepEqual(errors(r), ['::error::the root run printed no nextest summary line (`Summary [...] N tests run: ...`)']);
    }
  });

  test('a summary line that does not show every test run and passed fails', () => {
    for (const line of [
      'Summary [   1.000s] 54 tests run: 50 passed, 4 failed, 0 skipped',
      'Summary [   1.000s] 10/54 tests run: 10 passed, 0 skipped',
      'Summary [   1.000s] 0 tests run: 0 passed, 0 skipped',
      'Summary [   1.000s] 54 tests run: 54 passed, 3 skipped',
      'Summary [   1.000s] 54 tests run: 53 passed (1 slow), 1 timed out, 0 skipped',
      'Summary [   1.000s] something else',
    ]) {
      const r = summarize(`${START}     ${line}\n`);
      assert.equal(r.status, 1, line);
      assert.deepEqual(errors(r), [`::error::not every root-only test ran and passed: ${line}`]);
    }
  });

  test('the last summary line counts; one test and a slow test pass', () => {
    for (const line of ['Summary [   0.100s] 1 test run: 1 passed, 0 skipped', 'Summary [ 120.000s] 54 tests run: 54 passed (2 slow), 0 skipped', 'Summary [   0.100s] 3 tests run: 3 passed']) {
      const r = summarize(`${START}     Summary [   0.1s] 2 tests run: 1 passed, 1 failed\n     ${line}\n`);
      assert.equal(r.status, 0, line + r.stdout);
      assert.match(r.summary, new RegExp(`^- nextest: ${line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
    }
  });

  test('every failure is reported, not only the first', () => {
    const r = summarize(`${START}${PEER}\n     Summary [   1.000s] 54 tests run: 53 passed, 1 failed, 0 skipped\n`);
    assert.equal(r.status, 1);
    assert.equal(errors(r).length, 2);
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
  // read: every handler ignores the three signals before it exits, and
  // `resume` ignores them first.
  test('each signal handler, and resume, ignores TERM, INT and HUP first', () => {
    const source = readFileSync(SCRIPT, 'utf8');
    const body = source.slice(source.indexOf('\nrun() {'), source.indexOf('\nsummarize() {'));
    assert.deepEqual(body.match(/^\s*trap\b.*$/gm), [
      "        trap '' TERM INT HUP",
      '    trap resume EXIT',
      `    trap 'trap "" TERM INT HUP; exit 143' TERM`,
      `    trap 'trap "" TERM INT HUP; exit 130' INT`,
      `    trap 'trap "" TERM INT HUP; exit 129' HUP`,
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
  if (!/^ {10}sh scripts\/ci\/root-transport-run\.sh summarize "\$log" "\$userns" "\$status" \|\| status=\$\?$/m.test(run)) out.push('the root step does not call root-transport-run.sh summarize with the run\'s status');
  if (!/"CARGO_TERM_COLOR=never"/.test(run) || /CARGO_TERM_COLOR=\$/.test(run)) out.push('the root run does not set CARGO_TERM_COLOR=never');
  if (!/cargo nextest run --locked -p skyoauth-service --test local_transport --all-features --profile ci-root --run-ignored all --no-capture/.test(run)) out.push('the root run is not the local_transport binary under the ci-root profile with --no-capture');
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
    ];
    for (const [f, re] of cases) {
      const changed = inJob(f);
      assert.notEqual(changed, CI, `${re}: the mutation did not apply`);
      assert.match(problems(changed).join('\n'), re);
    }
  });
});
