// Self-test of root-transport-run.sh and of the `service-nextest` steps
// that use it in .github/workflows/ci.yml:
//   node --test scripts/ci/root-transport-run.test.mjs
// It needs sh, awk, sed, sort, od and tee, as the script does, and bash for
// one check of the fixture. It reads the workspace's Rust sources and
// manifests (no cargo): every test target's files, for root-only notices
// and branches outside the selections, and the selections' test counts.
// Every file it writes lives under one temporary directory, removed
// afterwards (a scratch copy of a source lives in memory only); nothing
// runs as root or reaches a network.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, normalize } from 'node:path';
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
// four selections, shortened: the selected tests, then tests of the same
// binaries that the filterset leaves out, which end in ` (skipped)`. The
// selected tests are the script's REQUIRED ones, one more of each
// selection of a prefix (EXTRA, which no check requires by name), and as
// many made-up ones (FILLER) as bring each selection to its MIN_TESTS.
// The script's SELECTIONS, as [binary ID, prefix or test name] pairs: a
// prefix is empty or ends in `::` and selects the tests whose names start
// with it; anything else is one test's full name, which selects it alone.
// A binary can have several selections.
const SELECTIONS = /^SELECTIONS='([^']*)'$/m
  .exec(readFileSync(SCRIPT, 'utf8'))[1]
  .split('\n')
  .map((l) => [l.split(' ')[0], l.split(' ')[1] ?? '']);
const isPrefix = (prefix) => prefix === '' || prefix.endsWith('::');
// Whether a test's name (its module path and function) is in a selection
// with this prefix or name.
const covers = (prefix, name) => (isPrefix(prefix) ? name.startsWith(prefix) : name === prefix);
// The index in SELECTIONS of the selection a test `BINARY-ID NAME` is in
// (-1: none).
const selectionOfTest = (t) => {
  const [bin, name] = t.split(' ');
  return SELECTIONS.findIndex(([b, prefix]) => b === bin && covers(prefix, name));
};
const selectionIndex = (bin, prefix) => {
  const i = SELECTIONS.findIndex(([b, p]) => b === bin && p === prefix);
  assert.ok(i >= 0, `no selection ${bin} ${prefix}`);
  return i;
};
// A selection's prefix as the script shows it: `PREFIX*`, a test's name
// as itself, none for every test.
const shown = (prefix) => (prefix === '' ? '' : isPrefix(prefix) ? `${prefix}*` : prefix);
// A selection's name in the script's errors and summary, in Markdown, and
// as plain text (the counts' notice, this self-test's own messages).
const label = (bin, prefix) => `\`${bin}\`${shown(prefix) ? ` \`${shown(prefix)}\`` : ''}`;
const plain = (bin, prefix) => `${bin}${shown(prefix) ? ` ${shown(prefix)}` : ''}`;
const REQUIRED = /^REQUIRED='([^']*)'$/m.exec(readFileSync(SCRIPT, 'utf8'))[1].split('\n');
// The script's MIN_TESTS, as [binary ID, prefix or test name, minimum]:
// `BINARY-ID [PREFIX] N`, the number last.
const MIN_TESTS = /^MIN_TESTS='([^']*)'$/m
  .exec(readFileSync(SCRIPT, 'utf8'))[1]
  .split('\n')
  .map((l) => {
    const f = l.split(' ');
    return [f[0], f.slice(1, -1).join(' '), Number(f.at(-1))];
  });
const minOf = (bin, prefix) => MIN_TESTS.find(([b, p]) => b === bin && p === prefix)?.[2];
const EXTRA = [
  'skyoauth-operator::operator local_path::a_relative_path_is_checked_as_its_absolute_form',
  'skyoauth-scenarios::pg harness::socket_path_fixture::socket_path_fixture_outcomes_are_complete',
  'skyoauth-service::local_transport a_socket_path_up_to_the_limit_works',
];
// A test of the selection of a prefix (its index in SELECTIONS) that no
// source has, for a fixture; a selection of one test's name has no other.
const madeUp = (i, name) => {
  const [bin, prefix] = SELECTIONS[i];
  assert.ok(isPrefix(prefix), `${bin} ${prefix} selects one test: no other can be in it`);
  return `${bin} ${prefix}${name}`;
};
const FILLER = SELECTIONS.flatMap(([bin, prefix], i) => {
  const have = [...EXTRA, ...REQUIRED].filter((t) => selectionOfTest(t) === i).length;
  return Array.from({ length: Math.max(0, minOf(bin, prefix) - have) }, (_, k) => madeUp(i, `listed_test_${k}`));
});
const SELECTED = [...EXTRA, ...REQUIRED, ...FILLER];
const N = SELECTED.length;
// How many of these tests are in the selection with this index.
const inSelection = (i, tests = SELECTED) => tests.filter((t) => selectionOfTest(t) === i).length;
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
// (the lines the script reads, as in a real run of the four selections
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
const HEADING = '### Root-only tests: `local_transport`, operator `local_path` and `cli::sign::seed_file_protection_on_unix`, `harness::socket_path_fixture`';
const SIGN_TEST = 'skyoauth-operator::operator cli::sign::seed_file_protection_on_unix';
const LT = inSelection(selectionIndex('skyoauth-service::local_transport', ''));
const OP = inSelection(selectionIndex('skyoauth-operator::operator', 'local_path::'));
const SIGN = inSelection(selectionIndex('skyoauth-operator::operator', 'cli::sign::seed_file_protection_on_unix'));
const PG = inSelection(selectionIndex('skyoauth-scenarios::pg', 'harness::socket_path_fixture::'));
const COUNTS =
  `- \`skyoauth-service::local_transport\`: ${LT} of ${LT} selected tests ran and passed (MIN_TESTS: ${minOf('skyoauth-service::local_transport', '')})\n` +
  `- \`skyoauth-operator::operator\` \`local_path::*\`: ${OP} of ${OP} selected tests ran and passed (MIN_TESTS: ${minOf('skyoauth-operator::operator', 'local_path::')})\n` +
  `- \`skyoauth-operator::operator\` \`cli::sign::seed_file_protection_on_unix\`: ${SIGN} of ${SIGN} selected tests ran and passed (MIN_TESTS: ${minOf('skyoauth-operator::operator', 'cli::sign::seed_file_protection_on_unix')})\n` +
  `- \`skyoauth-scenarios::pg\` \`harness::socket_path_fixture::*\`: ${PG} of ${PG} selected tests ran and passed (MIN_TESTS: ${minOf('skyoauth-scenarios::pg', 'harness::socket_path_fixture::')})\n` +
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
  ['not root: the other-owner case was NOT tried', 'fails'],
  ['this kernel follows at most', 'warns'],
  ["is not root's, sticky and writable by all: the shared directory was NOT tried in it", 'warns'],
  ['the working directory is too long for a relative socket path', 'warns'],
  ['/proc/self/fd is missing', 'warns'],
  ['a bind without /proc was NOT tested', 'warns'],
  ['a user namespace was denied', 'warns'],
  ['no mkfifo: the named pipe case was NOT tried', 'warns'],
];

// The Rust sources, read once each. `withSources` swaps in other texts
// for some files (a scratch copy in memory, never the repository's) while
// a check runs, so that the self-test can show what each check catches.
const OVERLAY = new Map();
const caches = [];
const cached = (f) => {
  const cache = new Map();
  caches.push(cache);
  return (file) => {
    if (!cache.has(file)) cache.set(file, f(file));
    return cache.get(file);
  };
};
const read = cached((file) => OVERLAY.get(file) ?? readFileSync(join(REPO, file), 'utf8'));
const exists = (file) => OVERLAY.has(file) || existsSync(join(REPO, file));
// Each cache is by file, but for the one entry `all` (workspaceFiles),
// which any file can change.
function withSources(texts, check) {
  const forget = () => {
    for (const cache of caches) for (const key of [...Object.keys(texts), 'all']) cache.delete(key);
  };
  for (const [file, text] of Object.entries(texts)) OVERLAY.set(file, text);
  forget();
  try {
    return check();
  } finally {
    OVERLAY.clear();
    forget();
  }
}
// A file's text with `from` (which must occur once) replaced by `to`.
const edited = (file, from, to) => {
  const text = read(file);
  assert.equal(text.split(from).length, 2, `${file}: ${JSON.stringify(from)} does not occur once`);
  return text.replace(from, () => to);
};

// Rust source, lexed: its string literals, each { text, line, start, end }
// (the text as written, escapes and all; start and end the offsets of the
// whole literal, prefix and delimiters included), and `code`, the source
// with every comment (nested block comments too) and the contents of every
// string and char literal blanked to spaces, newlines kept, so that offsets
// and lines are the source's and nothing in a comment or a literal reads as
// code. An unterminated comment or literal throws.
function lex(src) {
  const literals = [];
  const code = src.split('');
  const blank = (from, to) => {
    for (let k = from; k < to; k++) if (code[k] !== '\n') code[k] = ' ';
  };
  const starts = [0];
  for (let k = 0; k < src.length; k++) if (src[k] === '\n') starts.push(k + 1);
  const lineAt = (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  let i = 0;
  while (i < src.length) {
    if (src.startsWith('//', i)) {
      const j = src.indexOf('\n', i);
      const to = j < 0 ? src.length : j;
      blank(i, to);
      i = to;
      continue;
    }
    if (src.startsWith('/*', i)) {
      let depth = 0;
      let j = i;
      do {
        if (j >= src.length) throw new Error(`unterminated block comment at line ${lineAt(i)}`);
        if (src.startsWith('/*', j)) {
          depth++;
          j += 2;
        } else if (src.startsWith('*/', j)) {
          depth--;
          j += 2;
        } else j++;
      } while (depth > 0);
      blank(i, j);
      i = j;
      continue;
    }
    const raw = /^[bc]?r(#*)"/.exec(src.slice(i, i + 260));
    if (raw && !/\w/.test(src[i - 1] ?? '')) {
      const close = `"${raw[1]}`;
      const from = i + raw[0].length;
      const to = src.indexOf(close, from);
      if (to < 0) throw new Error(`unterminated raw string at line ${lineAt(i)}`);
      literals.push({ text: src.slice(from, to), line: lineAt(i), start: i, end: to + close.length });
      blank(from, to);
      i = to + close.length;
      continue;
    }
    if (src[i] === '"') {
      let j = i + 1;
      while (src[j] !== '"') {
        if (j >= src.length) throw new Error(`unterminated string at line ${lineAt(i)}`);
        j += src[j] === '\\' ? 2 : 1;
      }
      const start = /[bc]/.test(src[i - 1] ?? '') && !/\w/.test(src[i - 2] ?? '') ? i - 1 : i;
      literals.push({ text: src.slice(i + 1, j), line: lineAt(i), start, end: j + 1 });
      blank(i + 1, j);
      i = j + 1;
      continue;
    }
    if (src[i] === "'") {
      // A char literal, or a lifetime (no closing quote).
      const ch = /^'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'/.exec(src.slice(i, i + 12));
      if (ch) {
        blank(i + 1, i + ch[0].length - 1);
        i += ch[0].length;
      } else i++;
      continue;
    }
    i++;
  }
  return { literals, code: code.join(''), lineAt, starts };
}
const lexed = cached((file) => lex(read(file)));
// The string literals of Rust source, each { text, line }.
const stringLiterals = (src) => lex(src).literals;

// Whether a `cfg(...)` predicate holds in the root step's build: Linux on
// x86_64 (unix), `--all-features`, a test build. Any other predicate
// throws, to be classified here by hand.
function cfgOn(expr) {
  const tokens = expr.match(/\w+|"[^"]*"|[(),=]/g) ?? [];
  let k = 0;
  const parse = () => {
    const name = tokens[k++];
    if (['any', 'all', 'not'].includes(name)) {
      assert.equal(tokens[k++], '(', `cfg(${expr})`);
      const args = [];
      while (tokens[k] !== ')') {
        if (k >= tokens.length) throw new Error(`cfg(${expr}): not closed`);
        args.push(parse());
        if (tokens[k] === ',') k++;
      }
      k++;
      if (name === 'not') {
        assert.equal(args.length, 1, `cfg(${expr})`);
        return !args[0];
      }
      return name === 'any' ? args.some(Boolean) : args.every(Boolean);
    }
    if (tokens[k] === '=') {
      k++;
      const value = JSON.parse(tokens[k++]);
      if (name === 'target_os') return value === 'linux';
      if (name === 'target_arch') return value === 'x86_64';
      if (name === 'target_family') return value === 'unix';
      if (name === 'feature') return true;
      throw new Error(`cfg(${expr}): ${name} = ${JSON.stringify(value)} is not classified: add it to cfgOn`);
    }
    if (name === 'unix' || name === 'test') return true;
    if (name === 'windows') return false;
    throw new Error(`cfg(${expr}): ${name} is not classified: add it to cfgOn`);
  };
  const value = parse();
  assert.equal(k, tokens.length, `cfg(${expr}): trailing tokens`);
  return value;
}

// The calls of the macros the checks read, in a file's code: each { name,
// line, open, close, literals, code, plainPath }, with its delimiters'
// offsets, the string literals between them, its code (literals blanked)
// and, when its one argument is one plain string literal, that literal's
// text. A `name!` in a comment or a literal is no call.
const FORMATTING = ['print', 'println', 'eprint', 'eprintln', 'format', 'format_args', 'write', 'writeln', 'panic', 'assert', 'assert_eq', 'assert_ne', 'debug_assert', 'unreachable', 'todo', 'unimplemented'];
const BUILDING = ['concat', 'include', 'include_str', 'include_bytes', 'stringify'];
const macroCalls = cached((file) => {
  const src = read(file);
  const { code, literals, lineAt } = lexed(file);
  const out = [];
  for (const m of code.matchAll(/\b([a-z_]+)\s*!\s*([([{])/g)) {
    if (!FORMATTING.includes(m[1]) && !BUILDING.includes(m[1])) continue;
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let close = open;
    for (; close < code.length; close++) {
      if ('([{'.includes(code[close])) depth++;
      else if (')]}'.includes(code[close]) && --depth === 0) break;
    }
    if (code[close] !== { '(': ')', '[': ']', '{': '}' }[m[2]]) throw new Error(`${file}:${lineAt(m.index)}: ${m[1]}! is not closed`);
    const inside = literals.filter((l) => l.start > open && l.end <= close);
    const plain = inside.length === 1 && src[inside[0].start] === '"' && code.slice(open + 1, inside[0].start).trim() === '' && code.slice(inside[0].end, close).trim() === '';
    out.push({ name: m[1], line: lineAt(m.index), open, close, literals: inside, code: code.slice(open + 1, close), plainPath: plain ? inside[0].text : null });
  }
  return out;
});

// The files a crate root compiles in: { file, path, cfgs }, with the module
// path (`a::b::`) of each and the cfg predicates its module is under,
// following `mod NAME;`, inline `mod NAME { ... }` (closed by a `}` at its
// indentation, as rustfmt writes it), `#[path = "..."]` and `include!` (the
// included file is scanned as part of the file that includes it). It reads
// the code alone (comments and literals blanked), and every `mod`, `#[path]`
// and `include!` there must be one it followed, else it throws: a module
// it could not follow would be a file no check reads.
function moduleFiles(root) {
  const out = [];
  const walk = (file, dir, path, cfgs) => {
    const lines = read(file).split('\n');
    const { code } = lexed(file);
    const codeLines = code.split('\n');
    const inner = codeLines.flatMap((l, k) => (/^\s*#!\[cfg\(/.test(l) ? [/^\s*#!\[cfg\((.*)\)\]\s*$/.exec(lines[k])[1]] : []));
    const own = [...cfgs, ...inner];
    out.push({ file, path, cfgs: own });
    const stack = [{ indent: -1, dir, path, cfgs: own }];
    let pathAttr = null;
    let attrCfgs = [];
    let mods = 0;
    let paths = 0;
    codeLines.forEach((text, k) => {
      const trimmed = text.trimEnd();
      if (stack.length > 1 && trimmed === `${' '.repeat(stack.at(-1).indent)}}`) {
        stack.pop();
        return;
      }
      if (/^\s*#\[/.test(text)) {
        const p = /^\s*#\[path = "([^"]+)"\]\s*$/.exec(lines[k]);
        if (p) pathAttr = p[1];
        const c = /^\s*#\[cfg\((.*)\)\]\s*$/.exec(lines[k]);
        if (c) attrCfgs.push(c[1]);
        return;
      }
      if (trimmed === '') return;
      const m = /^(\s*)(?:pub(?:\([^)]*\))? )?mod (\w+)\s*(;|\{)$/.exec(trimmed);
      if (m) {
        mods++;
        const cur = stack.at(-1);
        const modCfgs = [...cur.cfgs, ...attrCfgs];
        if (m[3] === '{') {
          if (pathAttr) throw new Error(`${file}:${k + 1}: #[path] on an inline module is not followed`);
          stack.push({ indent: m[1].length, dir: join(cur.dir, m[2]), path: `${cur.path}${m[2]}::`, cfgs: modCfgs });
        } else {
          if (pathAttr) paths++;
          const child = pathAttr ? normalize(join(cur.dir, pathAttr)) : [join(cur.dir, `${m[2]}.rs`), join(cur.dir, m[2], 'mod.rs')].find(exists);
          if (!child || !exists(child)) throw new Error(`${file}:${k + 1}: mod ${m[2]}: no file`);
          walk(child, child.endsWith('/mod.rs') || pathAttr ? dirname(child) : child.slice(0, -'.rs'.length), `${cur.path}${m[2]}::`, modCfgs);
        }
      }
      pathAttr = null;
      attrCfgs = [];
    });
    const declared = (code.match(/\bmod\s+\w+\s*[;{]/g) ?? []).length;
    if (declared !== mods) throw new Error(`${file}: ${declared} module declarations in the code, ${mods} followed: write each on a line of its own, as rustfmt does`);
    const pathAttrs = (code.match(/#\s*\[\s*path\b/g) ?? []).length;
    if (pathAttrs !== paths) throw new Error(`${file}: ${pathAttrs} #[path] attributes in the code, ${paths} followed`);
    if (/\bcfg_attr\s*\([^\]]*\bpath\s*=/.test(code)) throw new Error(`${file}: #[cfg_attr(..., path = ...)] is not followed: classify it by hand`);
    for (const call of macroCalls(file).filter((c) => c.name === 'include')) {
      if (call.plainPath === null) throw new Error(`${file}:${call.line}: include! of a path that is not one string literal: classify it by hand`);
      const target = normalize(join(dirname(file), call.plainPath));
      if (!exists(target)) throw new Error(`${file}:${call.line}: include!(${JSON.stringify(call.plainPath)}): no such file`);
      out.push({ file: target, path, cfgs: own, includedBy: file });
    }
  };
  walk(root, dirname(root), '', []);
  return out;
}

// The functions of a file: { name, start, end, test, cfgs, mods }, with
// their 0-based first and last lines (the closing `}` at the `fn`'s
// indentation; a declaration without a body, or a body on one line, ends
// where it starts), whether an attribute above is `#[test]` or
// `#[tokio::test...]`, the cfg predicates of its attributes and of the
// inline modules around it, and those modules' path (`a::b::`).
const functions = cached((file) => {
  const lines = read(file).split('\n');
  const { code, starts } = lexed(file);
  const codeLines = code.split('\n');
  const out = [];
  const stack = [{ indent: -1, path: '', cfgs: [] }];
  let attrCfgs = [];
  codeLines.forEach((text, k) => {
    const trimmed = text.trimEnd();
    if (stack.length > 1 && trimmed === `${' '.repeat(stack.at(-1).indent)}}`) stack.pop();
    if (/^\s*#\[/.test(text)) {
      const c = /^\s*#\[cfg\((.*)\)\]\s*$/.exec(lines[k]);
      if (c) attrCfgs.push(c[1]);
      return;
    }
    if (trimmed === '') return;
    const mod = /^(\s*)(?:pub(?:\([^)]*\))? )?mod (\w+)\s*\{$/.exec(trimmed);
    if (mod) stack.push({ indent: mod[1].length, path: `${stack.at(-1).path}${mod[2]}::`, cfgs: [...stack.at(-1).cfgs, ...attrCfgs] });
    const fn = /^(\s*)(?:pub(?:\([^)]*\))? )?(?:const )?(?:async )?(?:unsafe )?(?:extern "\s*" )?fn (\w+)/.exec(text);
    if (fn) {
      const attrs = [];
      for (let a = k - 1; a >= 0 && (/^\s*#\[/.test(codeLines[a]) || codeLines[a].trim() === ''); a--) if (/^\s*#\[/.test(codeLines[a])) attrs.push(lines[a]);
      const rest = code.slice(starts[k]);
      const brace = rest.indexOf('{');
      const semi = rest.indexOf(';');
      let end = k;
      if (brace >= 0 && (semi < 0 || brace < semi) && !/\}$/.test(trimmed)) {
        end = codeLines.findIndex((l, j) => j > k && l.trimEnd() === `${fn[1]}}`);
        if (end < 0) throw new Error(`${file}:${k + 1}: fn ${fn[2]}: no closing } at its indentation`);
      }
      out.push({ name: fn[2], start: k, end, test: attrs.some((l) => /^\s*#\[(tokio::)?test\b/.test(l)), cfgs: [...stack.at(-1).cfgs, ...attrCfgs], mods: stack.at(-1).path });
    }
    attrCfgs = [];
  });
  return out;
});
// The innermost function around a 1-based line, if any.
const functionAt = (file, line) => functions(file).filter((f) => f.start <= line - 1 && line - 1 <= f.end).at(-1);

// Every test target of the workspace, as nextest names its binary: { id,
// kind, root }. From the manifests: the workspace's members and of each its
// library (`src/lib.rs`: its unit tests), its binary (`src/main.rs`) and
// `src/bin/*` binaries, `tests/*.rs` and `tests/*/main.rs` unless
// `autotests = false`, and each `[[test]]`. A manifest table or a
// directory of targets this does not read (`[lib]`, `[[bin]]`, examples,
// benches) throws, to be added here.
function workspaceTargets() {
  const members = /^members = \[([^\]]*)\]$/m.exec(read('Cargo.toml'))[1].match(/"[^"]+"/g).map((s) => JSON.parse(s));
  const out = [];
  for (const dir of members) {
    const toml = read(join(dir, 'Cargo.toml'));
    const pkg = /^\[package\]\nname = "([^"]+)"$/m.exec(toml)[1];
    for (const table of toml.match(/^\[\[?[^\]]+\]\]?$/gm)) {
      if (!['[package]', '[dependencies]', '[dev-dependencies]', '[build-dependencies]', '[features]', '[lints]', '[[test]]', '[[bin]]'].includes(table) && !/^\[(target\.|lints\.|package\.metadata)/.test(table)) throw new Error(`${dir}/Cargo.toml: ${table}: a table the target discovery does not read`);
    }
    for (const d of ['examples', 'benches']) if (exists(join(dir, d))) throw new Error(`${dir}/${d}: targets the discovery does not read`);
    const at = (f) => exists(join(dir, f));
    if (at('src/lib.rs')) out.push({ id: pkg, kind: 'lib', root: join(dir, 'src/lib.rs') });
    if (at('src/main.rs')) out.push({ id: `${pkg}::bin/${pkg}`, kind: 'bin', root: join(dir, 'src/main.rs') });
    const entries = (d) => (at(d) ? readdirSync(join(REPO, dir, d), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1)) : []);
    for (const e of entries('src/bin')) {
      if (e.isFile() && e.name.endsWith('.rs')) out.push({ id: `${pkg}::bin/${e.name.slice(0, -3)}`, kind: 'bin', root: join(dir, 'src/bin', e.name) });
      else if (e.isDirectory() && at(`src/bin/${e.name}/main.rs`)) out.push({ id: `${pkg}::bin/${e.name}`, kind: 'bin', root: join(dir, 'src/bin', e.name, 'main.rs') });
    }
    // A `[[bin]]` is read only as `test = false` (no test target) at the path
    // discovery already found; anything else throws, to be added here.
    for (const block of toml.split(/^\[\[bin\]\]$/m).slice(1)) {
      const body = block.split(/^\[/m)[0];
      const name = /^name = "([^"]+)"$/m.exec(body)?.[1];
      const path = /^path = "([^"]+)"$/m.exec(body)?.[1];
      if (!name || !/^test = false$/m.test(body) || path !== `src/bin/${name}/main.rs`) throw new Error(`${dir}/Cargo.toml: [[bin]] ${name}: only \`test = false\` at src/bin/<name>/main.rs is read`);
      const at = out.findIndex((t) => t.id === `${pkg}::bin/${name}`);
      if (at < 0) throw new Error(`${dir}/Cargo.toml: [[bin]] ${name}: not a discovered binary`);
      out.splice(at, 1);
    }
    if (!/^autotests = false$/m.test(toml)) {
      for (const e of entries('tests')) {
        if (e.isFile() && e.name.endsWith('.rs')) out.push({ id: `${pkg}::${e.name.slice(0, -3)}`, kind: 'test', root: join(dir, 'tests', e.name) });
        else if (e.isDirectory() && at(`tests/${e.name}/main.rs`)) out.push({ id: `${pkg}::${e.name}`, kind: 'test', root: join(dir, 'tests', e.name, 'main.rs') });
      }
    }
    for (const block of toml.split(/^\[\[test\]\]$/m).slice(1)) {
      const body = block.split(/^\[/m)[0];
      const name = /^name = "([^"]+)"$/m.exec(body)[1];
      out.push({ id: `${pkg}::${name}`, kind: 'test', root: join(dir, /^path = "([^"]+)"$/m.exec(body)?.[1] ?? `tests/${name}.rs`) });
    }
  }
  return out;
}

// Every file a test target compiles in: file -> [{ bin, path, cfgs }], one
// per target and module it is in (a shared helper is in several).
const workspaceFilesOnce = cached(() => {
  const files = new Map();
  for (const t of workspaceTargets()) {
    for (const m of moduleFiles(t.root)) {
      if (!files.has(m.file)) files.set(m.file, []);
      files.get(m.file).push({ bin: t.id, path: m.path, cfgs: m.cfgs });
    }
  }
  return files;
});
const workspaceFiles = () => workspaceFilesOnce('all');
// Whether a line of a file, in this function (if any), is in a selection
// in every target and module the file is in: its module is in a
// selection's prefix, or the function is the test a selection names.
const inSelections = (file, f) =>
  workspaceFiles()
    .get(file)
    .every(({ bin, path }) => SELECTIONS.some(([b, prefix]) => b === bin && (isPrefix(prefix) ? path.startsWith(prefix) : f?.test === true && `${path}${f.mods}${f.name}` === prefix)));

// The selections' targets: binary ID and crate root.
const TARGETS = [
  ['skyoauth-service::local_transport', 'service/tests/local_transport.rs'],
  ['skyoauth-operator::operator', 'operator/tests/operator.rs'],
  ['skyoauth-scenarios::pg', 'tests/pg.rs'],
];
// The files whose notices are checked: a selection's own modules, the
// file of each test a selection names (`only`: that test's name; of that
// file, the test and the functions that are no test are checked, not its
// other tests), and of its target the crate root and the helper modules
// (`common`, `support`, `harness::*`), each with `selected` when it is in
// a selection's prefix.
const SCANNED = [...new Set(TARGETS.map(([bin]) => bin))].flatMap((bin) => {
  const root = TARGETS.find(([b]) => b === bin)[1];
  const mine = SELECTIONS.filter(([b]) => b === bin).map(([, prefix]) => prefix);
  return moduleFiles(root)
    .map((m) => {
      const only = mine.find((name) => !isPrefix(name) && functions(m.file).some((f) => f.test && `${m.path}${f.mods}${f.name}` === name));
      return { bin, file: m.file, path: m.path, selected: mine.some((prefix) => isPrefix(prefix) && m.path.startsWith(prefix)), ...(only ? { only } : {}) };
    })
    .filter((m) => m.selected || m.only || m.path === '' || /^(common|support|harness)::/.test(m.path));
});

// The tests of a selection (its binary ID and its prefix or test name) that
// compile in the root step's build: their names as nextest lists them
// (module path and function), from the test functions (`#[test]`,
// `#[tokio::test]`) of its target's files whose name it covers (starts
// with its prefix, or is its test's name), leaving out those under a cfg
// that does not hold there (cfgOn). Every test attribute in those files
// must be on a function it found, else it throws.
function sourceTests(bin, prefix) {
  const root = workspaceTargets().find((t) => t.id === bin).root;
  const names = [];
  const seen = new Set();
  for (const m of moduleFiles(root)) {
    const fns = functions(m.file).filter((f) => f.test && covers(prefix, `${m.path}${f.mods}${f.name}`));
    if (fns.length === 0) continue;
    if (seen.has(m.file)) throw new Error(`${m.file} is in ${bin} twice`);
    seen.add(m.file);
    const attrs = (lexed(m.file).code.match(/#\s*\[\s*(?:tokio\s*::\s*)?test\b/g) ?? []).length;
    if (attrs !== functions(m.file).filter((f) => f.test).length) throw new Error(`${m.file}: ${attrs} test attributes, ${functions(m.file).filter((f) => f.test).length} on functions found: write each on a line of its own above its fn`);
    for (const f of fns) if ([...m.cfgs, ...f.cfgs].every(cfgOn)) names.push(`${m.path}${f.mods}${f.name}`);
  }
  return names;
}

// Every notice of SCANNED: { file, line, text, bin, path, selected, fn,
// test }, the text as printed (continuations joined, `{NAME}` replaced by
// that constant's value, other placeholders by X), the function around it
// (with the path of the inline modules it is in), if any, and whether that
// function is a test. In a file of a test a selection names (`only`), the
// notices of its other tests are left out (they do not run as root), and
// that test's are `selected`.
function sourceNotices() {
  const out = [];
  for (const { bin, file, path, selected, only } of SCANNED) {
    const consts = Object.fromEntries([...read(file).matchAll(/^const (\w+): (?:&str = "([^"]*)"|\w+ = (\d+));$/gm)].map((m) => [m[1], m[2] ?? m[3]]));
    for (const { text: raw, line } of lexed(file).literals) {
      if (!raw.includes('NOTICE:')) continue;
      const text = raw.replace(/\\\n\s*/g, '').replace(/\\"/g, '"').replace(/\{(\w*)[^}]*\}/g, (_, name) => consts[name] ?? 'X');
      const f = functionAt(file, line);
      const named = only !== undefined && f?.test === true && `${path}${f.mods}${f.name}` === only;
      if (only !== undefined && !selected && f?.test === true && !named) continue;
      out.push({ file, line, text, bin, path: `${path}${f?.mods ?? ''}`, selected: selected || named, fn: f?.name, test: f?.test ?? false });
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
        '- Every selected test ran as root and passed, and none printed a notice: each root-only check of the `local_transport` integration target, of operator `local_path` and `cli::sign::seed_file_protection_on_unix` and of `harness::socket_path_fixture` ran.\n',
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
      `(${SELECTIONS.map(([bin, prefix]) => escapeRe(plain(bin, prefix)) + ' \\d+/\\d+').join(', ')}|\\?); ` +
      `required root-only tests that ran and passed: (\\d+|\\?) of ${REQUIRED.length}$`,
  );

  test('the counts are one notice annotation, after the section', () => {
    const r = summarize(log());
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(countNotices(r), [
      `::notice::Root-only tests: nextest ran ${N} (all passed: yes) and skipped 3; the listing selects ${N} and leaves out 3; passed per selection: ` +
        `skyoauth-service::local_transport ${LT}/${LT}, skyoauth-operator::operator local_path::* ${OP}/${OP}, skyoauth-operator::operator cli::sign::seed_file_protection_on_unix ${SIGN}/${SIGN}, skyoauth-scenarios::pg harness::socket_path_fixture::* ${PG}/${PG}; ` +
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
        `::error::\`skyoauth-operator::operator\` \`cli::sign::seed_file_protection_on_unix\`: 0 of its ${SIGN} selected tests passed`,
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
    assert.match(r.summary, new RegExp(`^- \`skyoauth-service::local_transport\`: ${LT + 1} of ${LT + 1} selected tests ran and passed \\(MIN_TESTS: ${LT}\\)$`, 'm'));
  });

  test('the last summary line counts; a slow test passes', () => {
    for (const line of [SUMMARY, `Summary [ 120.000s] ${N} tests run: ${N} passed (2 slow), 3 skipped`]) {
      const r = summarize(`${START}${passLines()}     Summary [   0.1s] 2 tests run: 1 passed, 1 failed\n     ${line}\n`);
      assert.equal(r.status, 0, line + r.stdout);
      assert.match(r.summary, new RegExp(`^- nextest: ${escapeRe(line)} \\(the listing`, 'm'));
    }
  });

  test('a selection the listing has no test of fails', () => {
    for (const [bin, prefix, name] of [
      ['skyoauth-scenarios::pg', 'harness::socket_path_fixture::', '`skyoauth-scenarios::pg` `harness::socket_path_fixture::*`'],
      ['skyoauth-operator::operator', 'local_path::', '`skyoauth-operator::operator` `local_path::*`'],
      ['skyoauth-operator::operator', 'cli::sign::seed_file_protection_on_unix', '`skyoauth-operator::operator` `cli::sign::seed_file_protection_on_unix`'],
      ['skyoauth-service::local_transport', '', '`skyoauth-service::local_transport`'],
    ]) {
      const i = selectionIndex(bin, prefix);
      const gone = `${bin} ${prefix}`;
      const selected = SELECTED.filter((t) => selectionOfTest(t) !== i);
      const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, 3 skipped\n`, '0', '0', listing(selected));
      assert.equal(r.status, 1, gone);
      // That selection's required tests are not listed either; the other
      // selection of the same binary is not affected.
      assert.deepEqual(errors(r), [`::error::the listing selects no test of ${name}`, ...REQUIRED.filter((t) => selectionOfTest(t) === i).map((t) => requiredError(t, 'not listed'))]);
      assert.match(r.summary, new RegExp(`^- ${escapeRe(name)}: 0 of 0 selected tests ran and passed \\(MIN_TESTS: \\d+\\)$`, 'm'));
      assert.doesNotMatch(r.summary, COMPLETE);
    }
  });

  // A test removed from a selection (deleted, renamed out of its prefix,
  // compiled out) that no check requires by name: every count still
  // agrees, and only MIN_TESTS notices.
  test('a selection that lists fewer tests than its MIN_TESTS fails, naming both numbers; more pass', () => {
    for (const [i, [bin, prefix]] of SELECTIONS.entries()) {
      // A selection of one test's name lists it or none (the test above).
      if (!isPrefix(prefix)) {
        assert.equal(minOf(bin, prefix), 1, `${bin} ${prefix}`);
        continue;
      }
      const gone = FILLER.find((t) => selectionOfTest(t) === i) ?? EXTRA.find((t) => selectionOfTest(t) === i);
      const selected = SELECTED.filter((t) => t !== gone);
      const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, ${LEFT_OUT.length} skipped\n`, '0', '0', listing(selected));
      assert.equal(r.status, 1, bin);
      const name = label(bin, prefix);
      const min = minOf(bin, prefix);
      const message = `${name}: the listing selects ${min - 1} tests, fewer than its minimum of ${min} (MIN_TESTS in scripts/ci/root-transport-run.sh): a test was removed, renamed or compiled out`;
      assert.deepEqual(errors(r), [`::error::${message}`]);
      assert.match(r.summary, new RegExp(`^- \\*\\*Failed:\\*\\* ${escapeRe(message)}$`, 'm'));
      assert.match(r.summary, new RegExp(`^- ${escapeRe(name)}: ${min - 1} of ${min - 1} selected tests ran and passed \\(MIN_TESTS: ${min}\\)$`, 'm'));
      assert.doesNotMatch(r.summary, COMPLETE);
      // One more than the minimum passes.
      const more = [...SELECTED, madeUp(i, 'a_new_test')];
      const ok = summarize(`${START}${passLines(more)}     Summary [   1.000s] ${more.length} tests run: ${more.length} passed, ${LEFT_OUT.length} skipped\n`, '0', '0', listing(more));
      assert.equal(ok.status, 0, ok.stdout);
    }
    // The fixture lists exactly each minimum.
    for (const [bin, prefix, min] of MIN_TESTS) assert.equal(inSelection(selectionIndex(bin, prefix)), min, `${bin} ${prefix}`);
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

  test('a listing that selects a test outside the four selections fails', () => {
    const outside = [
      'skyoauth-scenarios::pg a01_a_scenario_that_needs_the_database',
      'skyoauth-operator::operator local_path_other::a_test',
      // A sibling of the one test a selection names, and a test whose name
      // that test's name starts.
      'skyoauth-operator::operator cli::sign::an_out_write_that_fails_is_exit_3',
      'skyoauth-operator::operator cli::sign::seed_file_protection_on_unix_too',
      'skyoauth-scenarios::pg harness::socket_path_fixture_other::a_test',
      'skyoauth-service::local_wire a_test',
    ];
    for (const t of outside) {
      const selected = [...SELECTED, t];
      const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${N + 1} tests run: ${N + 1} passed, 3 skipped\n`, '0', '0', listing(selected));
      assert.equal(r.status, 1, t);
      assert.deepEqual(errors(r), [`::error::the filterset selects tests outside the four selections: 1 (${t})`]);
    }
    const many = Array.from({ length: 7 }, (_, i) => `skyoauth-scenarios::pg a0${i}_x`);
    const r = summarize(`${START}${passLines([...SELECTED, ...many])}     Summary [   1.000s] ${N + many.length} tests run: ${N + many.length} passed, 3 skipped\n`, '0', '0', listing([...SELECTED, ...many]));
    assert.deepEqual(errors(r), [`::error::the filterset selects tests outside the four selections: 7 (${many.slice(0, 5).join(', ')}, ...)`]);
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
      SIGN_TEST,
    ]) {
      // A sibling that runs takes its place, so that its selection still
      // lists MIN_TESTS tests and the skipped mark is what fails; the one
      // test a selection names has none, so its selection lists no test.
      const i = selectionOfTest(dropped);
      const [bin, prefix] = SELECTIONS[i];
      const selected = [...SELECTED.filter((t) => t !== dropped), ...(isPrefix(prefix) ? [madeUp(i, 'a_sibling')] : [])];
      const leftOut = [...LEFT_OUT, dropped];
      const line = `Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, ${leftOut.length} skipped`;
      const r = summarize(`${START}${passLines(selected)}     ${line}\n`, '0', '0', listing(selected, leftOut));
      assert.equal(r.status, 1, dropped);
      assert.deepEqual(errors(r), [
        `::error::the listing marks 1 tests of the selections as skipped (${dropped}): the filterset leaves out tests it should run`,
        ...(isPrefix(prefix) ? [] : [`::error::the listing selects no test of ${label(bin, prefix)}`]),
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
    // The siblings of the one test a selection names, and a test whose name
    // that test's name starts, are left out too.
    const leftOut = [
      ...LEFT_OUT,
      'skyoauth-operator::operator redaction::x',
      'skyoauth-operator::operator local_pathology::y',
      'skyoauth-scenarios::pg harness::socket_path_fixture_more::z',
      'skyoauth-operator::operator cli::sign::an_out_write_that_fails_is_exit_3',
      'skyoauth-operator::operator cli::sign::seed_file_protection_on_unix_too',
    ];
    const line = `Summary [   1.000s] ${SELECTED.length} tests run: ${SELECTED.length} passed, ${leftOut.length} skipped`;
    const r = summarize(`${START}${passLines()}     ${line}\n`, '0', '0', listing(SELECTED, leftOut));
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(annotations(r), []);
    assert.match(r.summary, new RegExp(`^- nextest: ${escapeRe(line)} \\(the listing selects ${N} tests and leaves out ${leftOut.length} of the same binaries\\)$`, 'm'));
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

  // Every NOTICE the four selections' sources print, through `summarize`:
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
      SCANNED.map(({ bin, file, path, only }) => `${bin} ${file} ${path}${only ? ` only ${only}` : ''}`),
      [
        'skyoauth-service::local_transport service/tests/local_transport.rs ',
        'skyoauth-service::local_transport service/tests/common/mod.rs common::',
        'skyoauth-operator::operator operator/tests/operator.rs ',
        'skyoauth-operator::operator operator/tests/cli/sign.rs cli::sign:: only cli::sign::seed_file_protection_on_unix',
        'skyoauth-operator::operator operator/tests/local_path/mod.rs local_path::',
        'skyoauth-operator::operator operator/tests/support/mod.rs support::',
        'skyoauth-scenarios::pg tests/pg.rs ',
        'skyoauth-scenarios::pg tests/harness/local_client_round_trip.rs harness::local_client_round_trip::',
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
    for (const t of REQUIRED) assert.ok(selectionOfTest(t) >= 0, `${t} is in no selection`);
    // The one test a selection names is required: its notice fails the step.
    assert.ok(REQUIRED.includes(SIGN_TEST));
  });

  test('a required test that is not listed and did not run fails, by name, though every count agrees', () => {
    for (const gone of REQUIRED) {
      // Another test in its place: its selection still lists MIN_TESTS (the
      // one test a selection names has none: its selection lists none).
      const i = selectionOfTest(gone);
      const [bin, prefix] = SELECTIONS[i];
      const selected = [...SELECTED.filter((t) => t !== gone), ...(isPrefix(prefix) ? [madeUp(i, 'another_test')] : [])];
      const r = summarize(`${START}${passLines(selected)}     Summary [   1.000s] ${selected.length} tests run: ${selected.length} passed, ${LEFT_OUT.length} skipped\n`, '0', '0', listing(selected));
      assert.equal(r.status, 1, gone);
      assert.deepEqual(errors(r), [...(isPrefix(prefix) ? [] : [`::error::the listing selects no test of ${label(bin, prefix)}`]), requiredError(gone, 'not listed')]);
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
      'not root: the other-owner case was NOT tried',
    ]);
  });

  // A scratch copy of the script, edited, through `summarize` on the
  // default fixture (which selects the operator's
  // `cli::sign::seed_file_protection_on_unix`, as the step's filterset does).
  const withScript = (edit, text = log()) => {
    const original = readFileSync(SCRIPT, 'utf8');
    const changed = edit(original);
    assert.notEqual(changed, original, 'the edit did not apply');
    const copy = fresh('root-transport-run.sh');
    writeFileSync(copy, changed);
    const logFile = fresh('run.log');
    writeFileSync(logFile, text);
    const listFile = fresh('run.list');
    writeFileSync(listFile, LISTING);
    const summary = fresh('summary.md');
    writeFileSync(summary, EARLIER);
    const r = spawnSync('sh', [copy, 'summarize', logFile, '0', '0', listFile, '0'], { encoding: 'utf8', timeout: 60_000, env: { ...process.env, GITHUB_STEP_SUMMARY: summary } });
    return { ...r, lines: r.stdout.split('\n').filter(Boolean) };
  };

  test('the selection of the one test the operator\'s second selection names: dropped from SELECTIONS, the step fails', () => {
    // Out of SELECTIONS, MIN_TESTS and REQUIRED: the listing's test is
    // outside every selection.
    const r = withScript((t) =>
      t
        .replace(`\n${SIGN_TEST}\n`, '\n')
        .replace(`\n${SIGN_TEST} 1\n`, '\n')
        .replace(`REQUIRED='${SIGN_TEST}\n`, "REQUIRED='"),
    );
    assert.equal(r.status, 1, r.stdout);
    assert.deepEqual(errors(r), [`::error::the filterset selects tests outside the four selections: 1 (${SIGN_TEST})`]);
    // Out of SELECTIONS only: its MIN_TESTS entry has no selection, and
    // REQUIRED still names it.
    const only = withScript((t) => t.replace(`\n${SIGN_TEST}\n`, '\n'));
    assert.equal(only.status, 1, only.stdout);
    assert.deepEqual(errors(only), [`::error::the filterset selects tests outside the four selections: 1 (${SIGN_TEST})`]);
  });

  test('the not-root notice of `cli::sign::seed_file_protection_on_unix` fails the step through NOTICE_FAILS, and the mkfifo one warns', () => {
    const notRoot = 'NOTICE: not root: the other-owner case was NOT tried';
    const r = summarize(log(notRoot));
    assert.equal(r.status, 1, r.stdout);
    assert.deepEqual(errors(r), ['::error::a test printed a notice that its root-only cases did not run (not root: the other-owner case was NOT tried) although the step runs as root with SKYOAUTH_IT_PEER_USER set']);
    assert.deepEqual(warnings(r), [`::warning::${notRoot}`]);
    // Without its NOTICE_FAILS line, it would only warn.
    const without = withScript((t) => t.replace('\nnot root: the other-owner case was NOT tried\'', "'"), log(notRoot));
    assert.equal(without.status, 0, without.stdout);
    const fifo = summarize(log('NOTICE: no mkfifo: the named pipe case was NOT tried'));
    assert.equal(fifo.status, 0, fifo.stdout);
    assert.deepEqual(errors(fifo), []);
    assert.doesNotMatch(fifo.summary, COMPLETE);
  });
});

// The checks of the whole workspace's Rust sources: root-only notices and
// branches outside the selections (ROOT_ALLOWLIST), notices built where
// the literal scan cannot see them (MACRO_ALLOWLIST), and each selection's
// test count against MIN_TESTS.
const NOTICE_FAILS = /^NOTICE_FAILS='([^']*)'$/m.exec(readFileSync(SCRIPT, 'utf8'))[1].split('\n');
// Text that says root-only cases did not run: a NOTICE_FAILS string, the
// peer user variable, "need(s) root", or a notice that mentions root.
const rootOnlyText = (t) => NOTICE_FAILS.some((f) => t.includes(f)) || /\bPEER_USER_VAR\b/.test(t) || /\bneeds? root\b/i.test(t) || (/\bnotice\b/i.test(t) && /\broot\b/i.test(t));
// Code that branches on running as root (UID 0), e.g. `if uid == 0 {`,
// `uid != ROOT_UID`, `geteuid().as_raw() != 0`, `Uid::effective().is_root()`:
// a test that does part of its work only as root (or only not as root),
// with or without a notice.
const ROOT_BRANCH = /\b\w*uid\w*\b[\w().:]*\s*(?:==|!=)\s*(?:0|ROOT_UID)\b|\b(?:0|ROOT_UID)\s*(?:==|!=)\s*[\w().:&]*uid|\bis_root\s*\(/;

// What is root-only outside the four selections, by the test function it
// is in: each entry's `lines` are the source lines found there (trimmed),
// and its reason says why it need not run in the root step. A finding
// outside the selections that is not listed here, or listed with other
// lines, fails; so does an entry nothing matches any more.
const LIBRARY_ROOT_TESTS = "the library's own root-only tests are not part of the root step (manual root run)";
const ROOT_ALLOWLIST = [
  {
    file: 'service/src/local_transport/connection.rs',
    fn: 'a_refused_peer_is_answered_before_any_read',
    lines: ['if uid == ROOT_UID {', 'eprintln!("NOTICE: running as root: the in-process refused-peer check was NOT run");'],
    reason: 'it skips itself as root, with a notice, and runs in the non-root jobs; as root, `local_transport` `a_peer_of_another_uid_is_refused` (REQUIRED) checks the refused peer',
  },
  {
    file: 'operator/tests/local_exchange/mod.rs',
    fn: 'a_connection_without_permission_is_not_sent',
    lines: ['if std::fs::metadata(&path).unwrap().uid() == 0 {', 'eprintln!("NOTICE: running as root: the socket mode check was NOT run");'],
    reason: 'it skips itself as root, with a notice (root is not held back by the socket mode it checks), and runs in the non-root operator jobs',
  },
  // Its root-only case ("another owner") is skipped silently, with no
  // notice: `continue` when not root.
  { file: 'service/src/local_transport/socket.rs', fn: 'a_directory_swapped_in_before_its_check_is_not_verified', lines: ['if what == "another owner" && uid != 0 {'], reason: LIBRARY_ROOT_TESTS },
  { file: 'service/src/local_transport/socket.rs', fn: 'a_leftover_directory_keeps_what_a_bind_did_not_put_there', lines: ['if uid == 0 {'], reason: LIBRARY_ROOT_TESTS },
  { file: 'service/src/local_transport/socket.rs', fn: 'the_socket_directory_has_a_trusted_owner', lines: ['if uid == 0 {'], reason: LIBRARY_ROOT_TESTS },
  { file: 'service/src/local_transport/socket.rs', fn: 'every_directory_on_the_way_is_checked', lines: ['if uid == 0 {', 'if uid == 0 {', 'if uid == 0 {'], reason: LIBRARY_ROOT_TESTS },
  {
    file: 'service/src/local_transport/socket.rs',
    fn: 'a_link_in_a_sticky_directory_needs_a_trusted_owner',
    // The first line checks that /tmp is root's (not that the test runs as
    // root).
    lines: ['.is_ok_and(|metadata| metadata.uid() == 0 && metadata.mode() & 0o1002 == 0o1002)', 'eprintln!("NOTICE: no root-owned sticky /tmp: links in it were NOT tested");', 'if uid == 0 {', 'if uid == 0 {'],
    reason: `${LIBRARY_ROOT_TESTS}; its notice is about the machine's /tmp, which running as root does not change`,
  },
];

// Every root-only finding of the workspace's test targets: { file, line,
// kind, fn, source, selected }, `selected` when, in every target and module
// the file is in, its module is in a selection's prefix or its function is
// the test a selection names.
function rootOnlyFindings() {
  const out = [];
  for (const [file] of workspaceFiles()) {
    const { literals, code } = lexed(file);
    const lines = read(file).split('\n');
    const found = new Map();
    for (const { text, line } of literals) if (rootOnlyText(text)) found.set(line, 'root-only text');
    code.split('\n').forEach((c, k) => {
      if (found.has(k + 1)) return;
      if (/\bPEER_USER_VAR\b/.test(c)) found.set(k + 1, 'the peer user variable');
      else if (ROOT_BRANCH.test(c) && functionAt(file, k + 1)?.test) found.set(k + 1, 'a branch on root');
    });
    for (const [line, kind] of [...found].sort((a, b) => a[0] - b[0])) {
      const f = functionAt(file, line);
      out.push({ file, line, kind, fn: f?.name, source: lines[line - 1].trim(), selected: inSelections(file, f) });
    }
  }
  return out;
}

function rootOnlyProblems(findings = rootOnlyFindings()) {
  const out = [];
  const groups = new Map();
  for (const f of findings.filter((x) => !x.selected)) {
    const key = `${f.file} ${f.fn}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }
  for (const [key, found] of groups) {
    const entry = ROOT_ALLOWLIST.find((e) => `${e.file} ${e.fn}` === key);
    if (!entry) {
      for (const f of found) out.push(`${f.file}:${f.line}: ${f.kind} outside the four selections (${f.fn ? `fn ${f.fn}` : 'no function'}): ${f.source}: run it in a selection of the root step, or add it to ROOT_ALLOWLIST with the reason it need not run there`);
    } else if (JSON.stringify(found.map((f) => f.source).sort()) !== JSON.stringify([...entry.lines].sort())) {
      out.push(`ROOT_ALLOWLIST: ${key}: it lists ${JSON.stringify(entry.lines)}, the source has ${JSON.stringify(found.map((f) => f.source))}`);
    }
  }
  for (const e of ROOT_ALLOWLIST) if (!groups.has(`${e.file} ${e.fn}`)) out.push(`ROOT_ALLOWLIST: ${e.file} ${e.fn}: nothing root-only there any more`);
  return out;
}

// The calls of concat!, include!, include_str!, include_bytes! and
// stringify! that may stand in a file whose notices are classified
// (SCANNED), or in a function that says NOTICE, each with a reason; the
// calls are still checked for notice text.
const FIXTURE_PATH = 'the path of a conformance fixture under CARGO_MANIFEST_DIR; no notice text';
const MACRO_ALLOWLIST = [
  { file: 'tests/harness/local_transport_wire.rs', fn: 'fixture', macro: 'concat', reason: FIXTURE_PATH },
  { file: 'tests/harness/public_identity_fixture.rs', fn: 'fixture', macro: 'concat', reason: FIXTURE_PATH },
  { file: 'tests/harness/recovery_challenge_fixture.rs', fn: 'fixture', macro: 'concat', reason: FIXTURE_PATH },
  { file: 'tests/harness/recovery_key_fixture.rs', fn: 'fixture', macro: 'concat', reason: FIXTURE_PATH },
  { file: 'tests/harness/socket_path_fixture.rs', fn: 'fixture', macro: 'concat', reason: FIXTURE_PATH },
  { file: 'tests/harness/wire_errors.rs', fn: 'catalogue', macro: 'concat', reason: FIXTURE_PATH },
];

// The string constants a file defines (`const NAME: &str = "...";`), by
// name.
const stringConsts = cached((file) => Object.fromEntries([...read(file).matchAll(/^\s*(?:pub(?:\([^)]*\))? )?(?:const|static) (\w+): &(?:'static )?str = "((?:[^"\\]|\\.)*)";$/gm)].map((m) => [m[1], m[2]])));
// What a formatting macro call prints, as far as its file shows: its
// literals with `{NAME}` replaced by the file's string constant NAME, and
// each constant passed as an argument, joined.
function resolvedText(file, call) {
  const consts = stringConsts(file);
  const parts = call.literals.map((l) => l.text.replace(/\{(\w+)[^}]*\}/g, (all, name) => consts[name] ?? all));
  for (const m of call.code.matchAll(/\b([A-Z][A-Z0-9_]*)\b/g)) if (m[1] in consts) parts.push(consts[m[1]]);
  return parts.join('');
}

// Notices the literal scan cannot see: built by concat! or stringify!, read
// by include_str!/include_bytes!, or printed from parts or constants (no
// one literal of the call holds `NOTICE:`); and the macros that need an
// entry in MACRO_ALLOWLIST. include! is followed by moduleFiles.
function constructProblems() {
  const out = [];
  const scanned = new Set(SCANNED.map((s) => s.file));
  const used = new Set();
  for (const [file] of workspaceFiles()) {
    const lines = read(file).split('\n');
    for (const call of macroCalls(file)) {
      const where = `${file}:${call.line}: ${call.name}!`;
      if (FORMATTING.includes(call.name)) {
        if (/NOTICE/.test(resolvedText(file, call)) && !call.literals.some((l) => l.text.includes('NOTICE:'))) out.push(`${where} prints a NOTICE built from parts or constants: write the notice as one literal`);
        continue;
      }
      const parts = call.literals.map((l) => l.text).join('');
      if (call.name === 'concat' && (/notice/i.test(parts) || rootOnlyText(parts))) out.push(`${where} builds notice text from parts: write it as one literal`);
      if (call.name === 'stringify' && /notice/i.test(call.code)) out.push(`${where} turns code that says NOTICE into text`);
      if (call.name === 'include_str' || call.name === 'include_bytes') {
        const target = call.plainPath === null ? null : normalize(join(dirname(file), call.plainPath));
        if (target === null) out.push(`${where} of a path that is not one string literal: classify it by hand`);
        else if (!exists(target)) out.push(`${where}: ${target}: no such file`);
        else if (/notice/i.test(read(target)) || rootOnlyText(read(target))) out.push(`${where}: ${target} holds notice or root-only text`);
      }
      const f = functionAt(file, call.line);
      const entry = MACRO_ALLOWLIST.find((e) => e.file === file && e.fn === f?.name && e.macro === call.name);
      const scope = f ? lines.slice(f.start, f.end + 1).join('\n') : read(file).slice(call.open, call.close + 1);
      if (entry) used.add(entry);
      else if (/notice/i.test(scope)) out.push(`${where} in ${f ? `fn ${f.name}` : 'an item'}, which says NOTICE: classify it by hand (MACRO_ALLOWLIST)`);
      else if (scanned.has(file)) out.push(`${where} in a file whose notices are classified (SCANNED): add it to MACRO_ALLOWLIST with a reason`);
    }
  }
  for (const e of MACRO_ALLOWLIST) if (!used.has(e)) out.push(`MACRO_ALLOWLIST: ${e.file} fn ${e.fn}: no ${e.macro}! there any more`);
  return out;
}

// Each selection's tests in the sources against its MIN_TESTS (exact).
const minProblems = () =>
  SELECTIONS.flatMap(([bin, prefix]) => {
    const count = sourceTests(bin, prefix).length;
    return count === minOf(bin, prefix) ? [] : [`${plain(bin, prefix)}: ${count} tests in the sources, MIN_TESTS says ${minOf(bin, prefix)}: set it to ${count}`];
  });

// Every .rs file under the workspace's members (not under `target`).
const rustFiles = () => {
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(join(REPO, dir), { withFileTypes: true })) {
      if (e.isDirectory() && e.name !== 'target' && e.name !== 'node_modules') walk(join(dir, e.name));
      else if (e.isFile() && e.name.endsWith('.rs')) out.push(join(dir, e.name));
    }
  };
  for (const m of /^members = \[([^\]]*)\]$/m.exec(read('Cargo.toml'))[1].match(/"[^"]+"/g).map((s) => JSON.parse(s))) walk(m);
  return out.sort();
};
// The .rs files no test target compiles in, each with a reason.
const OPERATOR_BIN = 'the operator binary (`test = false`): it holds no tests; the operator target runs the built binary';
const NOT_IN_A_TARGET = {
  'service/build.rs': 'the build script: it is no test target and prints no test output',
  'operator/src/bin/skyoauth-operator/args.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/artifact.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/cmd_preview.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/cmd_sign.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/cmd_status.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/cmd_verify_challenge.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/cmd_verify_response.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/input.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/main.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/online.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/out_file.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/seed_file.rs': OPERATOR_BIN,
  'operator/src/bin/skyoauth-operator/show.rs': OPERATOR_BIN,
};

// A scratch copy of a test function's text with a line added after its
// first line (in memory, see withSources).
const withLineIn = (file, fnName, line) => {
  const f = functions(file).find((x) => x.name === fnName);
  assert.ok(f, `${file}: no fn ${fnName}`);
  const lines = read(file).split('\n');
  lines.splice(f.start + 1, 0, line);
  return lines.join('\n');
};
const firstTest = (file) => functions(file).find((f) => f.test && f.end > f.start + 1).name;
const OTHER_TARGET = 'service/tests/jwk.rs';
const OPERATOR_OTHER = 'operator/tests/challenge/mod.rs';
// The file of the one test a selection names, and that test.
const SIGN_FILE = 'operator/tests/cli/sign.rs';
const SIGN_FN = 'seed_file_protection_on_unix';

describe('the workspace\'s Rust sources', () => {
  test('the lexer: comments, nested comments, raw, byte and C strings, chars and lifetimes, escapes', () => {
    const src = [
      '/// "NOTICE: a doc comment"',
      '//! "NOTICE: an inner doc comment"',
      '/* outer /* "NOTICE: nested" */ still a comment "NOTICE: x" */',
      "fn f<'a>(x: &'a str) -> char { let q = '\"'; let e = '\\''; let b = '\\\\'; let u = '\\u{22}'; q }",
      'let s = "a \\" NOTICE: b"; let r = r##"raw "# NOTICE: c"##; let y = b"NOTICE: d"; let z = c"NOTICE: e"; let w = br#"NOTICE: f"#;',
      'let m = "include!(\\"x.rs\\") concat!(\\"NOTI\\", \\"CE\\")"; // include!("y.rs")',
      'let multi = "NOTICE: one \\',
      '    two";',
    ].join('\n');
    const { literals, code } = lex(src);
    assert.deepEqual(
      literals.map((l) => [l.line, l.text]),
      [
        [5, 'a \\" NOTICE: b'],
        [5, 'raw "# NOTICE: c'],
        [5, 'NOTICE: d'],
        [5, 'NOTICE: e'],
        [5, 'NOTICE: f'],
        [6, 'include!(\\"x.rs\\") concat!(\\"NOTI\\", \\"CE\\")'],
        [7, 'NOTICE: one \\\n    two'],
      ],
    );
    // The code: the same length and lines, nothing of a comment or a
    // literal left, and so no macro call in them.
    assert.equal(code.length, src.length);
    assert.deepEqual(code.split('\n').map((l) => l.length), src.split('\n').map((l) => l.length));
    assert.doesNotMatch(code, /NOTICE|include|concat|doc comment|nested/);
    assert.match(code, /fn f<'a>\(x: &'a str\)/);
    assert.equal(code.slice(literals[2].start, literals[2].end), 'b"         "');
    withSources({ 'scratch/lexer.rs': src }, () => assert.deepEqual(macroCalls('scratch/lexer.rs'), []));
    for (const bad of ['let s = "open', '/* open /* */', 'let r = r#"open"']) assert.throws(() => lex(bad), /unterminated/);
  });

  test('cfgOn: the root step\'s build (Linux on x86_64, all features); anything else must be classified', () => {
    for (const [expr, on] of [
      ['unix', true],
      ['test', true],
      ['target_os = "linux"', true],
      ['not(target_os = "linux")', false],
      ['any(target_os = "linux", target_os = "android")', true],
      ['not(any(target_os = "linux", target_os = "android"))', false],
      ['all(target_os = "linux", target_arch = "aarch64")', false],
      ['feature = "test-support"', true],
      ['any()', false],
      ['all()', true],
      ['not(unix)', false],
    ]) {
      assert.equal(cfgOn(expr), on, expr);
    }
    for (const expr of ['miri', 'debug_assertions', 'target_env = "musl"', 'panic = "abort"']) assert.throws(() => cfgOn(expr), /is not classified/, expr);
  });

  test('every test target is found, and every file a target compiles in is read', (t) => {
    const targets = workspaceTargets();
    for (const [bin, root] of TARGETS) assert.ok(targets.some((x) => x.id === bin && x.root === root), bin);
    for (const lib of ['skyoauth-service', 'skyoauth-operator', 'skyoauth-scenarios']) assert.ok(targets.some((x) => x.id === lib && x.kind === 'lib'), lib);
    assert.ok(targets.some((x) => x.id === 'skyoauth-service::bin/skyoauth-service'));
    assert.ok(targets.filter((x) => x.kind === 'test' && x.id.startsWith('skyoauth-service::')).length > 30);
    // Only operator and scenarios declare their test targets.
    assert.deepEqual(targets.filter((x) => x.kind === 'test' && !x.id.startsWith('skyoauth-service::')).map((x) => x.id), ['skyoauth-scenarios::pg', 'skyoauth-operator::operator']);
    const files = workspaceFiles();
    assert.deepEqual(rustFiles().filter((f) => !files.has(f)), Object.keys(NOT_IN_A_TARGET).sort());
    t.diagnostic(`${targets.length} test targets (${targets.map((x) => x.id).join(', ')}), ${files.size} files`);
    // A module the walk cannot follow, or a #[path] or include! it would
    // have to, fails instead of leaving a file unread.
    for (const [text, re] of [
      ['#[cfg(test)] mod sneaky;\n', /jwk\.rs: 1 module declarations in the code, 0 followed/],
      ['mod sneaky { mod inner; }\n', /module declarations in the code/],
      ['#[path = "nowhere.rs"]\nmod sneaky;\n', /mod sneaky: no file/],
      ['#[cfg_attr(unix, path = "x.rs")]\nmod sneaky;\n', /cfg_attr|no file/],
      ['include!(concat!(env!("OUT_DIR"), "/x.rs"));\n', /include! of a path that is not one string literal/],
      ['include!("nowhere.rs");\n', /no such file/],
    ]) {
      withSources({ [OTHER_TARGET]: `${read(OTHER_TARGET)}\n${text}` }, () => assert.throws(() => workspaceFiles(), re, text));
    }
    // A #[path] module and an included file are read like any module.
    withSources({ [OTHER_TARGET]: `${read(OTHER_TARGET)}\n#[path = "elsewhere/x.rs"]\nmod sneaky;\ninclude!("y.rs");\n`, 'service/tests/elsewhere/x.rs': '', 'service/tests/y.rs': '' }, () => {
      assert.deepEqual(workspaceFiles().get('service/tests/elsewhere/x.rs'), [{ bin: 'skyoauth-service::jwk', path: 'sneaky::', cfgs: [] }]);
      assert.deepEqual(workspaceFiles().get('service/tests/y.rs'), [{ bin: 'skyoauth-service::jwk', path: '', cfgs: [] }]);
    });
  });

  // A test outside the four selections that says root-only cases
  // did not run, or branches on root, never runs as root in CI: each one is
  // listed with its reason, so that a new one is a decision.
  test('every root-only notice or branch outside the four selections is on ROOT_ALLOWLIST, with a reason', (t) => {
    const findings = rootOnlyFindings();
    assert.deepEqual(rootOnlyProblems(findings), []);
    for (const e of ROOT_ALLOWLIST) assert.ok(e.reason.length > 20, `${e.file} ${e.fn}: no reason`);
    assert.equal(ROOT_ALLOWLIST.find((e) => e.fn === 'a_directory_swapped_in_before_its_check_is_not_verified').reason, "the library's own root-only tests are not part of the root step (manual root run)");
    // What the scan finds, per target (a shared file counts in each).
    for (const target of workspaceTargets()) {
      const mine = findings.filter((f) => workspaceFiles().get(f.file).some((o) => o.bin === target.id));
      if (mine.length === 0) continue;
      const inside = mine.filter((f) => f.selected).length;
      t.diagnostic(`${target.id}: ${mine.length} root-only findings, ${inside} in the selections, ${mine.length - inside} allowlisted: ${[...new Set(mine.filter((f) => !f.selected).map((f) => `${f.file} ${f.fn}`))].join('; ') || '-'}`);
    }
    assert.ok(findings.some((f) => f.selected && f.file === 'service/tests/local_transport.rs'));
    // The one test a selection names: its branch on root and its notice
    // are in a selection, though its file's other tests are not.
    assert.deepEqual(
      findings.filter((f) => f.file === SIGN_FILE).map(({ kind, fn, selected }) => `${kind} ${fn} ${selected}`),
      [`a branch on root ${SIGN_FN} true`, `root-only text ${SIGN_FN} true`],
    );
  });

  test('a new root-only notice or branch outside the selections fails, and so does a stale entry', () => {
    const swapped = 'service/src/local_transport/socket.rs';
    for (const [texts, re] of [
      // A NOTICE_FAILS notice in another target's test.
      [{ [OTHER_TARGET]: withLineIn(OTHER_TARGET, firstTest(OTHER_TARGET), '    eprintln!("NOTICE: the owner check needs root: it was NOT tried");') }, /service\/tests\/jwk\.rs:\d+: root-only text outside the four selections .*the owner check needs root/],
      // Beside the one test a selection names: in a sibling test, or in a
      // helper of its file, which other tests call too; and that test
      // renamed, so that no selection names it any more.
      [{ [SIGN_FILE]: withLineIn(SIGN_FILE, 'an_out_write_that_fails_is_exit_3', '    eprintln!("NOTICE: not root: the other-owner case was NOT tried");') }, /operator\/tests\/cli\/sign\.rs:\d+: root-only text outside the four selections \(fn an_out_write_that_fails_is_exit_3\)/],
      [{ [SIGN_FILE]: withLineIn(SIGN_FILE, 'an_out_write_that_fails_is_exit_3', '    if rustix::process::geteuid().as_raw() != 0 { return; }') }, /operator\/tests\/cli\/sign\.rs:\d+: a branch on root outside the four selections \(fn an_out_write_that_fails_is_exit_3\)/],
      [{ [SIGN_FILE]: withLineIn(SIGN_FILE, 'seed_hex', '    eprintln!("NOTICE: running as root: x was NOT run");') }, /operator\/tests\/cli\/sign\.rs:\d+: root-only text outside the four selections \(fn seed_hex\)/],
      [{ [SIGN_FILE]: edited(SIGN_FILE, `fn ${SIGN_FN}() {`, `fn ${SIGN_FN}_renamed() {`) }, new RegExp(`a branch on root outside the four selections \\(fn ${SIGN_FN}_renamed\\)`)],
      [{ [OTHER_TARGET]: withLineIn(OTHER_TARGET, firstTest(OTHER_TARGET), '    eprintln!("skipped: this needs root");') }, /root-only text outside/],
      [{ [OPERATOR_OTHER]: withLineIn(OPERATOR_OTHER, firstTest(OPERATOR_OTHER), '    if std::env::var("SKYOAUTH_IT_PEER_USER").is_err() { return; }') }, /operator\/tests\/challenge\/mod\.rs:\d+: root-only text outside/],
      [{ [OPERATOR_OTHER]: withLineIn(OPERATOR_OTHER, firstTest(OPERATOR_OTHER), '    let _ = PEER_USER_VAR;') }, /the peer user variable outside/],
      // A silent skip: a branch on root with no notice.
      [{ [OPERATOR_OTHER]: withLineIn(OPERATOR_OTHER, firstTest(OPERATOR_OTHER), '    if rustix::process::geteuid().as_raw() != 0 { return; }') }, /a branch on root outside/],
      [{ [OPERATOR_OTHER]: withLineIn(OPERATOR_OTHER, firstTest(OPERATOR_OTHER), '    if !nix::unistd::Uid::effective().is_root() { return; }') }, /a branch on root outside/],
      [{ [OPERATOR_OTHER]: withLineIn(OPERATOR_OTHER, firstTest(OPERATOR_OTHER), '    if 0 != uid { return; }') }, /a branch on root outside/],
      // In a helper shared with targets outside the selections.
      [{ 'service/tests/common/mod.rs': `${read('service/tests/common/mod.rs')}\npub fn x() { eprintln!("NOTICE: running as root: x was NOT run"); }\n` }, /service\/tests\/common\/mod\.rs:\d+: root-only text outside/],
      // In the library's unit tests, besides an allowlisted one.
      [{ [swapped]: withLineIn(swapped, 'a_directory_swapped_in_before_its_check_is_not_verified', '        eprintln!("NOTICE: running as root: x was NOT run");') }, /ROOT_ALLOWLIST: service\/src\/local_transport\/socket\.rs a_directory_swapped_in_before_its_check_is_not_verified: it lists/],
      // The allowlisted silent skip gone: the entry is stale.
      [{ [swapped]: edited(swapped, 'if what == "another owner" && uid != 0 {', 'if what == "another owner" && false {') }, /a_directory_swapped_in_before_its_check_is_not_verified: nothing root-only there any more/],
    ]) {
      withSources(texts, () => assert.match(rootOnlyProblems().join('\n'), re));
    }
    // In a selection, the same notice is the selection's (its kind and
    // REQUIRED are checked by the other tests): no problem here.
    const lt = 'service/tests/local_transport.rs';
    withSources({ [lt]: withLineIn(lt, firstTest(lt), '    eprintln!("NOTICE: the owner check needs root: it was NOT tried");') }, () => assert.deepEqual(rootOnlyProblems(), []));
    withSources({ [SIGN_FILE]: withLineIn(SIGN_FILE, SIGN_FN, '    if rustix::process::geteuid().as_raw() != 0 { return; }') }, () => assert.deepEqual(rootOnlyProblems(), []));
  });

  test('no notice is built where the literal scan cannot see it; the macros that could are allowlisted', () => {
    assert.deepEqual(constructProblems(), []);
    for (const e of MACRO_ALLOWLIST) assert.ok(SCANNED.some((s) => s.file === e.file) && e.reason, `${e.file}: not a scanned file, or no reason`);
  });

  test('a notice built by concat!, stringify!, an included file or from parts fails', () => {
    const scannedFile = 'operator/tests/local_path/mod.rs';
    const at = (file, line, extra = {}) => ({ [file]: withLineIn(file, firstTest(file), line), ...extra });
    for (const [texts, re] of [
      [at(OTHER_TARGET, '    eprintln!(concat!("NOTI", "CE: the owner check needs root: it was NOT tried"));'), /jwk\.rs:\d+: concat! builds notice text from parts/],
      [at(OTHER_TARGET, '    eprintln!(concat!("NOTI", "CE: x"));'), /concat! builds notice text from parts/],
      [at(OTHER_TARGET, '    eprintln!("{}{}", "NOTI", "CE: the owner check needs root");'), /eprintln! prints a NOTICE built from parts/],
      [{ [OTHER_TARGET]: `const PREFIX: &str = "NOTICE:";\n${withLineIn(OTHER_TARGET, firstTest(OTHER_TARGET), '    eprintln!("{PREFIX} the owner check was NOT tried");')}` }, /eprintln! prints a NOTICE built from parts or constants/],
      [{ [OTHER_TARGET]: `const PREFIX: &str = "NOTICE:";\n${withLineIn(OTHER_TARGET, firstTest(OTHER_TARGET), '    eprintln!("{} the owner check was NOT tried", PREFIX);')}` }, /eprintln! prints a NOTICE built from parts or constants/],
      [at(OTHER_TARGET, '    eprintln!("{}", stringify!(NOTICE the owner check was not tried));'), /stringify! turns code that says NOTICE into text/],
      [at(OTHER_TARGET, '    eprint!("{}", include_str!("notice.txt"));', { 'service/tests/notice.txt': 'NOTICE: the owner check needs root\n' }), /include_str!: service\/tests\/notice\.txt holds notice or root-only text/],
      [at(OTHER_TARGET, '    let _ = include_str!("nowhere.txt");'), /include_str!: service\/tests\/nowhere\.txt: no such file/],
      [at(OTHER_TARGET, '    let _ = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/x.txt"));'), /include_str! of a path that is not one string literal/],
      // A macro in a function that says NOTICE, anywhere.
      [at(OTHER_TARGET, '    let _ = (concat!("a", "b"), "NOTICE: x");'), /concat! in fn \w+, which says NOTICE: classify it by hand/],
      // Any of them in a file whose notices are classified.
      [at(scannedFile, '    let _ = concat!("a", "b");'), /local_path\/mod\.rs:\d+: concat! in a file whose notices are classified/],
      // An entry with nothing left to match.
      [{ 'tests/harness/wire_errors.rs': edited('tests/harness/wire_errors.rs', 'concat!(', 'std::convert::identity(') }, /MACRO_ALLOWLIST: tests\/harness\/wire_errors\.rs fn catalogue: no concat! there any more/],
    ]) {
      withSources(texts, () => assert.match(constructProblems().join('\n'), re));
    }
    // An included file's notices are scanned like a module's.
    withSources({ [OTHER_TARGET]: `${read(OTHER_TARGET)}\ninclude!("extra.rs");\n`, 'service/tests/extra.rs': '#[test]\nfn extra() {\n    eprintln!("NOTICE: the owner check needs root: it was NOT tried");\n}\n' }, () =>
      assert.match(rootOnlyProblems().join('\n'), /service\/tests\/extra\.rs:3: root-only text outside the four selections \(fn extra\)/),
    );
  });

  // MIN_TESTS: exact here, a lower bound in the script (its comment says
  // why), so that it cannot fall behind the sources unnoticed.
  test('MIN_TESTS is each selection\'s test count in the Rust sources, on Linux with all features', (t) => {
    // One entry per selection, in its order, keyed by binary ID and prefix
    // or test name.
    assert.deepEqual(
      MIN_TESTS.map(([bin, prefix]) => `${bin} ${prefix}`),
      SELECTIONS.map(([bin, prefix]) => `${bin} ${prefix}`),
    );
    for (const [, , min] of MIN_TESTS) assert.ok(Number.isInteger(min) && min > 0, String(min));
    // No two selections overlap: a binary's selections have prefixes
    // neither of which starts the other, and a test a selection names is in
    // no prefix of its binary.
    for (const [i, [bin, a]] of SELECTIONS.entries()) {
      for (const [k, [other, b]] of SELECTIONS.entries()) {
        if (i === k || bin !== other) continue;
        assert.notEqual(a, b, `${bin} ${a} twice`);
        if (isPrefix(b)) assert.ok(!a.startsWith(b), `${bin}: ${a} is in ${b}`);
      }
    }
    assert.deepEqual(minProblems(), []);
    const all = [];
    for (const [i, [bin, prefix]] of SELECTIONS.entries()) {
      const names = sourceTests(bin, prefix);
      t.diagnostic(`${plain(bin, prefix)}: ${names.length} tests in the sources, MIN_TESTS ${minOf(bin, prefix)}`);
      for (const r of [...REQUIRED, ...EXTRA].filter((x) => selectionOfTest(x) === i)) assert.ok(names.includes(r.slice(bin.length + 1)), `${r}: not a test of the sources`);
      all.push(...names.map((name) => `${bin} ${name}`));
    }
    assert.equal(new Set(all).size, all.length, 'a test in two selections');
    // The one test a selection names, compiled on Linux under its
    // `#[cfg(unix)]` (above its `#[test]`).
    assert.deepEqual(sourceTests('skyoauth-operator::operator', `cli::sign::${SIGN_FN}`), [`cli::sign::${SIGN_FN}`]);
    assert.deepEqual(functions(SIGN_FILE).find((f) => f.name === SIGN_FN).cfgs, ['unix']);
    // `local_transport` has one test that does not compile on Linux.
    assert.ok(!sourceTests('skyoauth-service::local_transport', '').includes('a_socket_path_over_the_limit_is_refused'));
  });

  test('a test deleted, compiled out or added in the sources makes MIN_TESTS fail here', () => {
    const file = 'operator/tests/local_path/mod.rs';
    const name = 'the_socket_must_be_the_expected_owners';
    const f = functions(file).find((x) => x.name === name);
    const lines = read(file).split('\n');
    const attr = lines.slice(0, f.start).findLastIndex((l) => /^\s*#\[test\]$/.test(l));
    assert.ok(attr >= 0 && attr >= f.start - 3, 'no #[test] right above it');
    const without = (k) => [...lines.slice(0, k), ...lines.slice(k + 1)].join('\n');
    const withLine = (k, text) => [...lines.slice(0, k), text, ...lines.slice(k)].join('\n');
    // Against the sources as they are (the test above checks that they
    // match MIN_TESTS).
    const min = minOf('skyoauth-operator::operator', 'local_path::');
    const base = sourceTests('skyoauth-operator::operator', 'local_path::').length;
    const fewer = new RegExp(`^skyoauth-operator::operator local_path::\\*: ${base - 1} tests in the sources, MIN_TESTS says ${min}: set it to ${base - 1}$`);
    for (const [text, re] of [
      [without(attr), fewer],
      [withLine(attr, '#[cfg(any())]'), fewer],
      [withLine(attr, '#[cfg(not(unix))]'), fewer],
      [`${read(file)}\n#[test]\nfn one_more() {}\n`, new RegExp(`: ${base + 1} tests in the sources, MIN_TESTS says ${min}: set it to ${base + 1}$`)],
    ]) {
      withSources({ [file]: text }, () => assert.match(minProblems().filter((p) => p.startsWith('skyoauth-operator::operator local_path::*:')).join('\n'), re));
    }
    // The one test a selection names: deleted, compiled out or renamed,
    // its selection has no test in the sources (MIN_TESTS 1); the other
    // selection of its binary is unchanged.
    {
      const g = functions(SIGN_FILE).find((x) => x.name === SIGN_FN);
      const own = read(SIGN_FILE).split('\n');
      const at = own.slice(0, g.start).findLastIndex((l) => /^\s*#\[test\]$/.test(l));
      assert.ok(at >= 0 && at >= g.start - 3, 'no #[test] right above it');
      const none = `skyoauth-operator::operator cli::sign::${SIGN_FN}: 0 tests in the sources, MIN_TESTS says 1: set it to 0`;
      for (const text of [
        [...own.slice(0, at), ...own.slice(at + 1)].join('\n'),
        [...own.slice(0, at), '#[cfg(any())]', ...own.slice(at)].join('\n'),
        [...own.slice(0, at), '#[cfg(windows)]', ...own.slice(at)].join('\n'),
        edited(SIGN_FILE, `fn ${SIGN_FN}() {`, `fn ${SIGN_FN}_renamed() {`),
      ]) {
        withSources({ [SIGN_FILE]: text }, () => assert.deepEqual(minProblems(), [none]));
      }
    }
    // A cfg it cannot evaluate, or a test attribute it does not see on a
    // function, throws instead of miscounting.
    withSources({ [file]: withLine(attr, '#[cfg(miri)]') }, () => assert.throws(() => minProblems(), /miri is not classified/));
    withSources({ [file]: `${read(file)}\n#[test] fn one_line() {}\n` }, () => assert.throws(() => minProblems(), /test attributes, \d+ on functions found/));
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

// The problems of the job in this ci.yml, against these SELECTIONS (the
// script's, unless a check passes others).
const problems = (ci, selections = SELECTIONS) => {
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
  // The `run: |` block alone: its lines indented under it (what follows
  // in this text is the next step's comment).
  const block = /^ {8}run: \|\n((?:(?: {10}.*)?\n)*)/m.exec(root)?.[1].trimEnd() ?? '';
  if (!/^ {10}set -euo pipefail$/m.test(run)) out.push('the root step does not set -euo pipefail');
  if (!/^ {10}sh scripts\/ci\/root-transport-run\.sh run "\$log" \\$/m.test(run)) out.push('the root step does not run the tests through root-transport-run.sh run');
  if (!/^ {10}sh scripts\/ci\/root-transport-run\.sh summarize "\$log" "\$userns" "\$status" "\$list" "\$listed" \|\| status=\$\?$/m.test(run)) out.push('the root step does not call root-transport-run.sh summarize with the run\'s status and the listing');
  // The step's exit is the run's, the listing's (through summarize) and
  // summarize's: its last line, and nothing lets the job pass without it.
  if (!block.endsWith('\n          exit "$status"')) out.push('the root step does not end with exit "$status"');
  if (/^\s*continue-on-error:/m.test(job)) out.push('the service-nextest job or one of its steps has continue-on-error');
  const gate = jobOf(ci, 'ci-passed');
  const needs = /^ {4}needs:\n((?: {6}- .*\n)+)/m.exec(gate)?.[1].split('\n').map((l) => l.trim().replace(/^- /, '')).filter(Boolean) ?? [];
  if (!needs.includes('service-nextest')) out.push('ci-passed does not need service-nextest');
  if (!/^ {4}if: always\(\)$/m.test(gate) || !/RESULTS: \$\{\{ join\(needs\.\*\.result, ' '\) \}\}/.test(gate) || !/success \| skipped\) ;;\n\s*\*\) exit 1 ;;/.test(gate)) out.push('ci-passed does not fail on a needed job that did not succeed');
  if (!/"CARGO_TERM_COLOR=never"/.test(run) || /CARGO_TERM_COLOR=\$/.test(run)) out.push('the root run does not set CARGO_TERM_COLOR=never');
  if (!/^ {12}"\$\{as_root\[@\]\}" cargo nextest run "\$\{selection\[@\]\}" --no-capture \\$/m.test(run)) out.push('the root run is not the selection, as root, with --no-capture');
  // The run's status goes to `status` and on to summarize, which fails the
  // step on it: the call, its continuation line, and nothing between it
  // and the listing.
  const runCall = [
    '          status=0',
    '          sh scripts/ci/root-transport-run.sh run "$log" \\',
    '            "${as_root[@]}" cargo nextest run "${selection[@]}" --no-capture \\',
    '            || status=$?',
    '          listed=0',
  ].join('\n');
  if (!block.includes(`\n${runCall}\n`)) out.push('the root run\'s status is not kept by `|| status=$?` on the line after its call');
  // `status` is set three times: before the run, after it and by
  // summarize.
  if ((block.match(/\bstatus=/g) ?? []).length !== 3) out.push('`status` is set elsewhere than before the run, by the run and by summarize');
  // A trap could replace the step's exit status (`trap 'exit 0' EXIT`).
  if (/\btrap\b/.test(block)) out.push('the root step\'s run block sets a trap');
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
    // A prefix is `test(/^PREFIX/)`; one test's name, `test(/^NAME$/)`.
    const want = selections.map(([bin, prefix]) => {
      const [pkg, target] = bin.split('::');
      return `(package(${pkg}) & binary(${target})${prefix ? ` & test(/^${prefix}${isPrefix(prefix) ? '' : '$'}/)` : ''})`;
    });
    if (selection.filter !== want.join(' | ')) out.push(`the filterset ${JSON.stringify(selection.filter)} is not the script's SELECTIONS ${JSON.stringify(want.join(' | '))}`);
    // Each binary once, in the order of its first selection.
    const bins = [...new Set(selections.map(([bin]) => bin))];
    const flags = ['--locked', ...bins.flatMap((bin) => ['-p', bin.split('::')[0]]), ...bins.flatMap((bin) => ['--test', bin.split('::')[1]]), '--all-features', '--profile', 'ci-root', '--run-ignored', 'all'];
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
      // The one test a selection names: dropped, widened to its module or
      // to the names it starts, or joined to the other operator clause.
      [(b) => b.replace(' | (package(skyoauth-operator) & binary(operator) & test(/^cli::sign::seed_file_protection_on_unix$/))', ''), /is not the script's SELECTIONS/],
      [(b) => b.replace('test(/^cli::sign::seed_file_protection_on_unix$/)', 'test(/^cli::sign::/)'), /is not the script's SELECTIONS/],
      [(b) => b.replace('test(/^cli::sign::seed_file_protection_on_unix$/)', 'test(/^cli::sign::seed_file_protection_on_unix/)'), /is not the script's SELECTIONS/],
      [(b) => b.replace(' -p skyoauth-operator', ' -p skyoauth-operator -p skyoauth-operator'), /the selection's flags/],
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
      // The run's own status: dropped, or ignored.
      [(b) => b.replace('--no-capture \\\n            || status=$?\n', '--no-capture\n'), /kept by `\|\| status=\$\?`/],
      [(b) => b.replace('--no-capture \\\n            || status=$?\n', '--no-capture \\\n            || true\n'), /kept by `\|\| status=\$\?`/],
      [(b) => b.replace('--no-capture \\\n            || status=$?\n', '--no-capture \\\n            || status=0\n'), /kept by `\|\| status=\$\?`/],
      [(b) => b.replace('            || status=$?\n          listed=0\n', '            || status=$?\n          status=0\n          listed=0\n'), /kept by `\|\| status=\$\?`/],
      [(b) => b.replace(/^( {10}sudo chown .*)$/m, '$1\n          status=0'), /`status` is set elsewhere/],
      [(b) => b.replace('          set -euo pipefail\n', "          set -euo pipefail\n          trap 'exit 0' EXIT\n"), /sets a trap/],
      [(b) => b.replace('          exit "$status"\n', '          trap \'status=0\' ERR\n          exit "$status"\n'), /sets a trap/],
      [(b) => b.replace('        id: root\n', '        id: root\n        continue-on-error: true\n'), /continue-on-error/],
      [(b) => b.replace(/^( {4}runs-on: .*)$/m, '$1\n    continue-on-error: true'), /continue-on-error/],
    ];
    for (const [f, re] of cases) {
      const changed = inJob(f);
      assert.notEqual(changed, CI, `${re}: the mutation did not apply`);
      assert.match(problems(changed).join('\n'), re);
    }
    // SELECTIONS without a selection the filterset has (the one test the
    // operator's second selection names, or its `local_path`), or with one
    // more, are out of step with the step too.
    for (const selections of [
      SELECTIONS.filter(([, prefix]) => prefix !== 'cli::sign::seed_file_protection_on_unix'),
      SELECTIONS.filter(([, prefix]) => prefix !== 'local_path::'),
      [...SELECTIONS, ['skyoauth-operator::operator', 'cli::sign::out_is_created_new_or_not_at_all']],
    ]) {
      assert.match(problems(CI, selections).join('\n'), /is not the script's SELECTIONS/);
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
