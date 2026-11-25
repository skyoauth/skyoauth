#!/usr/bin/env node
// Release-build guard for the `test-support` feature.
//
//   node scripts/ci/check-release-features.mjs [--root DIR]
//
// `skyoauth-service`'s `test-support` feature exposes ungated writers to
// tests (`persistence::registry::test_support`, `trust::test_support`), so
// no build that ships may turn it on. Only dev-dependency entries name it,
// which Cargo applies to builds that need dev-dependencies (test targets);
// `service/tests/ungated_writes_private.rs` checks the plain workspace
// build of libraries and binaries. This guard checks the feature
// resolution of a release build, the features that could turn it on, and
// the commands that would run one:
//
//   resolve  For every workspace package with a binary target, and for the
//            whole workspace, `cargo tree -e no-dev --target all` (the
//            feature resolution of `cargo build --release -p PKG`, or of
//            `--workspace`: default features, no dev-dependency, every
//            platform) enables `test-support` on no package. Features do
//            not depend on the profile, so this is the release build's
//            resolution (inferred: `-e no-dev` resolves features without
//            dev units, as such a build does). At least one binary package
//            must exist, so the guard cannot pass by checking nothing.
//   features No `[features]` entry of a workspace package but a
//            `test-support` key itself turns `test-support` on: neither
//            `test-support`, `DEP/test-support` nor `DEP?/test-support`
//            (any dependency), nor an optional dependency (`dep:DEP`,
//            `DEP`, `DEP/F`) whose declaration turns it on, nor another
//            feature that does, in its own package or a workspace
//            dependency, at any depth. Such a feature passes `resolve`
//            while off, and `--features F` or `--all-features` would turn
//            it on in a release build.
//   control  For every package that declares `test-support`, the same
//            resolution with `--features test-support` does show it on that
//            package, so a change of cargo's output that hid features fails
//            the guard instead of passing it. At least one package must
//            declare it, so a renamed feature fails the guard too.
//   command  No release command uses `--all-features` or `--all-targets`,
//            names `test-support` or a feature that `features` finds, or
//            builds test, bench or example targets
//            (`--tests`, `--benches`, `--examples`, `--test`, `--bench`,
//            `--example`, or `cargo test`, `cargo bench`, `cargo nextest`):
//            with those, cargo unifies the dev-dependencies' features into
//            the one library build, so `target/release/<bin>` is built with
//            `test-support`. A command is a release command when it is
//            `cargo install` or `cargo bench`, or passes `--release`, `-r`
//            or `--profile X` (`--cargo-profile X` for cargo-nextest and
//            `cargo llvm-cov nextest` or `nextest-archive`, whose
//            `--profile` is nextest's own) for any X but `dev`, `test` and a
//            profile that inherits from them: the `[profile.*]` `inherits`
//            keys of every `Cargo.toml` and cargo configuration in the tree
//            are followed, and a profile they do not declare (`$PROFILE`
//            included) counts as release. Cargo aliases (`[alias]` of every
//            `.cargo/config` and `.cargo/config.toml` in the tree) are
//            expanded wherever they are called, and each alias is itself
//            checked as a command; a cargo configuration file must not name
//            `test-support` at all (`[build] rustflags` would reach every
//            build). The command check reads the workflows and composite
//            actions, shell scripts, scripts under scripts/, Dockerfiles,
//            justfiles and Makefiles. A line ending in `\` continues on the
//            next one; in YAML, a plain scalar continued on more indented
//            lines and each paragraph of a folded block scalar (`>`, `>-`,
//            `>+`; a blank line ends one) are one logical line, and the
//            lines of a literal block scalar (`|`, `|-`) are shell lines,
//            as the shell reads them, never YAML keys. A line is split into
//            commands at `&&`, `||`, `;`, `|` and `&` (not a redirection's)
//            outside quotes, a command into shell words (a quoted string is
//            one; `(`, `)`, `<`, `>`, `[`, `]` and `,` separate words too),
//            and the words after each word that runs cargo (`cargo` or a
//            path to it, not an assignment `NAME=value` nor the value of a
//            `-C`, as in `make -C /opt/cargo`; `cargo-SUB` run directly,
//            such as `cargo-nextest` or `cargo-llvm-cov`, is `cargo SUB`, so
//            an image or wrapper named `cargo-X` before the real `cargo`
//            hides nothing) are checked as its arguments; so are the words
//            read with quotes as separators, and the contents of each quoted
//            string are read as a line of their own (`sh -c "..."`,
//            `"$(...)"`). A short-option cluster before `--` is read letter
//            by letter, as cargo reads it (`-qr` is `-q -r`, `-rFfull` is
//            `-r -F full`), with the short options of the subcommand it is
//            given to (`SHORT_OPTIONS`, from each one's `--help`: cargo
//            before its subcommand, its build commands, `install`, `clippy`,
//            `tree`, `metadata` and `fmt`, cargo-nextest's `run`, `list`,
//            `archive` and `bench`, cargo-llvm-cov's): a letter that takes a
//            value takes the rest of the word or the next word, so `-pr`
//            names the package `r`, `-mservice/Cargo.toml` is a manifest
//            path, `cargo tree -efeatures` an edge kind, `cargo nextest run
//            -Pstrict` a nextest profile and `-E'binary(pg)'` a filterset,
//            none of them a release flag. Fail-closed: a letter of a
//            cluster that the subcommand's table does not name (any letter,
//            for a subcommand with no table) is an error that names the
//            letter, as the guard cannot tell whether the rest of the word
//            holds `-r`; the fix is to add it to the table. An alias's
//            arguments are read with the table of the subcommand it runs.
//            The word `cargo` starts a command wherever it
//            is (`echo cargo ...` included): the guard does not know which
//            programs run their arguments. This file and its self-test are
//            not scanned: they name the flags as patterns. What the guard
//            cannot see: a command built at run time (a flag or a
//            subcommand in an environment variable, a Makefile variable or
//            a recipe that calls another), a quoted string that spans lines
//            (each line is read on its own, so a cargo command's arguments
//            after the line break are not read with it), a build outside
//            the files it reads, and cargo configuration outside the
//            repository (`$CARGO_HOME`, `CARGO_*` variables).
//
// Errors exit 1, one line each. Usage errors and internal failures (cargo
// not found, unparsable output or TOML) exit 2. Needs Node (>=20), cargo on
// PATH and smol-toml (scripts/ci lockfile: `npm ci --ignore-scripts` in
// scripts/ci); `cargo tree` and `cargo metadata` run with `--locked` and
// build nothing. Self-test: node --test scripts/ci/check-release-features.test.mjs

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseToml } from 'smol-toml';

export const FEATURE = 'test-support';

const SELF = fileURLToPath(import.meta.url);
const SELF_FILES = new Set([basename(SELF), 'check-release-features.test.mjs']);

// Directories never scanned: build output, dependencies, version control.
const SKIP_DIRS = new Set(['.git', 'node_modules', 'target']);

class InternalError extends Error {}

function cargo(root, args) {
  const result = spawnSync(process.env.CARGO || 'cargo', args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw new InternalError(`cargo ${args[0]}: ${result.error.message}`);
  if (result.status !== 0) {
    throw new InternalError(`cargo ${args.join(' ')} failed (exit ${result.status}):\n${result.stderr.trim()}`);
  }
  return result.stdout;
}

// `{p} [{f}]` with `--prefix none`: `name vVERSION [(source)] [features]`,
// then ` (*)` for a package already shown.
const TREE_LINE = /^(\S+) v\S+(?: \(.*?\))? \[([^\]]*)\](?: \(\*\))?$/;

// The packages of a `cargo tree` resolution, each with its features.
export function parseTree(text) {
  const features = new Map();
  // cargo colours the `(*)` marker when the terminal setting forces it (CI does).
  for (const line of text.replace(/\x1b\[[0-9;]*m/g, '').split('\n')) {
    if (!line.trim()) continue;
    const match = TREE_LINE.exec(line);
    if (!match) throw new InternalError(`unexpected cargo tree line: ${line}`);
    const set = features.get(match[1]) ?? new Set();
    for (const feature of match[2].split(',').filter(Boolean)) set.add(feature);
    features.set(match[1], set);
  }
  return features;
}

function resolution(root, selection, extra = []) {
  const args = ['tree', '--locked', '--color', 'never', ...selection, '-e', 'no-dev', '--target', 'all'];
  args.push('--prefix', 'none', '--format', '{p} [{f}]', ...extra);
  return parseTree(cargo(root, args));
}

// `KEY: VALUE` in YAML (a sequence entry's `- KEY: VALUE` included); group 1
// ends at the key's column.
const YAML_KEY = /^(\s*(?:-\s+)?)[^\s#-][^#]*?:(?:\s+(.*?))?\s*$/;
const indentOf = (line) => line.search(/\S/);

// Logical lines of `text`: a line ending in `\` joins the next one. With
// `yaml`, a key's plain scalar continued on more indented lines, and each
// paragraph of its folded block scalar (`>`, `>-`, `>+`; YAML keeps the
// line break at a blank line), join too; a literal block scalar's lines
// (`|`) stay lines, and none of them is read as a YAML key. Each carries
// the number of its first line.
export function logicalLines(text, { yaml = false } = {}) {
  const lines = text.split('\n');
  const out = [];
  const join = (number, parts) => out.push({ line: number, text: parts.map((part) => part.replace(/\\\s*$/, '')).join(' ') });
  let current = null;
  // The column of the key whose literal block scalar holds the line, or -1.
  let literal = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (literal >= 0 && line.trim() && indentOf(line) <= literal) literal = -1;
    const key = yaml && !current && literal < 0 ? YAML_KEY.exec(line) : null;
    const value = key?.[2] ?? '';
    if (/^\|[-+0-9]*(?:\s+#.*)?$/.test(value)) {
      literal = key[1].length;
    } else if (value) {
      const folded = /^>[-+0-9]*(?:\s+#.*)?$/.test(value);
      const column = key[1].length;
      let end = i + 1;
      // A folded scalar takes blank lines too; a plain one ends at one.
      while (end < lines.length && (lines[end].trim() ? indentOf(lines[end]) > column : folded)) end++;
      if (folded) {
        let paragraph = { number: i + 1, parts: [line.slice(0, line.lastIndexOf(value))] };
        for (let j = i + 1; j < end; j++) {
          if (lines[j].trim()) {
            paragraph ??= { number: j + 1, parts: [] };
            paragraph.parts.push(lines[j]);
          } else if (paragraph) {
            join(paragraph.number, paragraph.parts);
            paragraph = null;
          }
        }
        if (paragraph) join(paragraph.number, paragraph.parts);
        i = end - 1;
        continue;
      }
      if (end > i + 1) {
        join(i + 1, lines.slice(i, end));
        i = end - 1;
        continue;
      }
    }
    const continues = /\\\s*$/.test(line);
    const body = continues ? line.replace(/\\\s*$/, ' ') : line;
    if (current) current.text += body;
    else current = { line: i + 1, text: body };
    if (!continues) {
      out.push(current);
      current = null;
    }
  }
  if (current) out.push(current);
  return out;
}

// cargo's built-in aliases of the subcommands this check reads.
const BUILTIN_ALIASES = { b: 'build', c: 'check', d: 'doc', r: 'run', t: 'test' };
// Long options that take a value as the next word, before a subcommand or
// after it (`--color always nextest`: `always` is no subcommand).
const LONG_WITH_VALUE = new Set(['--config', '--color', '--manifest-path']);
// Subcommands that build test or bench targets.
const TEST_COMMANDS = new Set(['test', 'bench', 'nextest', 'llvm-cov']);
const TEST_TARGETS = /^--(?:tests|benches|examples|test|bench|example|all-targets)(?:=|$)/;

// The short options of each subcommand the check reads, as its `--help`
// lists them (cargo 1.100.0, cargo-nextest 0.9.151, cargo-llvm-cov 0.9.1):
// `flags` are letters that take no value (`-r` is `--release`), `values`
// letters that take one, the rest of the word (an `=` after the letter
// dropped) or, when nothing follows the letter, the next word. A letter
// with an optional value (`-p [<SPEC>]`, `-i [<SPEC>]`) takes the rest of
// the word as cargo does, so it is a value letter here. `''` is cargo
// before its subcommand; `nextest` and `llvm-cov` are those tools before
// their own subcommand, which is read after a space (`nextest run`).
const shortOptions = (flags, values) => ({ flags: new Set(flags), values: new Set(values) });
// `cargo build --help`, and the same letters in `check`, `doc`, `fix`,
// `run`, `rustc`, `rustdoc` and `test`; clippy adds `-V` to `check`'s.
const CARGO_BUILD = shortOptions('hqrv', 'FZjmp');
// `cargo llvm-cov --help`; `test`, `run` and `report` have the same letters but `-V`.
const LLVM_COV = shortOptions('hqrv', 'FZjp');
const SHORT_OPTIONS = new Map([
  ['', shortOptions('Vhqv', 'CZ')],
  ...['build', 'check', 'doc', 'fix', 'run', 'rustc', 'rustdoc', 'test'].map((sub) => [sub, CARGO_BUILD]),
  ['bench', shortOptions('hqv', 'FZjmp')],
  ['clippy', shortOptions('Vhqrv', 'FZjmp')],
  ['install', shortOptions('fhnqv', 'FZj')],
  ['tree', shortOptions('dhqv', 'FZefimp')],
  ['metadata', shortOptions('hqv', 'FZm')],
  ['fmt', shortOptions('hqv', 'p')],
  ['nextest', shortOptions('Vhv', 'P')],
  ['nextest run', shortOptions('hrv', 'EFPRZjp')],
  ['nextest list', shortOptions('hrv', 'EFPTZp')],
  ['nextest archive', shortOptions('hrv', 'EFPZp')],
  ['nextest bench', shortOptions('hrv', 'EFPZp')],
  ['llvm-cov', shortOptions('Vhqrv', 'FZjp')],
  ['llvm-cov test', LLVM_COV],
  ['llvm-cov run', LLVM_COV],
  ['llvm-cov report', LLVM_COV],
  // `cargo llvm-cov nextest` takes llvm-cov's options and `cargo nextest
  // run`'s, `nextest-archive` llvm-cov's and `cargo nextest archive`'s; the
  // letters both name take a value in both.
  ['llvm-cov nextest', shortOptions('Vhqrv', 'EFPRZjp')],
  ['llvm-cov nextest-archive', shortOptions('Vhqrv', 'EFPZjp')],
]);
// The subcommands of the tools with their own (`cargo nextest --help`:
// `r` is `run`, `b` is `bench`; `cargo llvm-cov --help`), which take the
// first word after the tool's options. Another word there leaves the
// tool's own table in use (`cargo llvm-cov` alone runs `test`).
const NESTED_COMMANDS = new Map([
  ['nextest', { run: 'run', r: 'run', list: 'list', archive: 'archive', bench: 'bench', b: 'bench' }],
  ['llvm-cov', { test: 'test', run: 'run', report: 'report', nextest: 'nextest', 'nextest-archive': 'nextest-archive' }],
]);
// The llvm-cov subcommands that run nextest, whose `--profile` is
// nextest's own (cargo's is `--cargo-profile`): both pass their options on
// to cargo-nextest (cargo-llvm-cov's `docs/cargo-llvm-cov-nextest*.txt`).
const LLVM_COV_NEXTEST = new Set(['nextest', 'nextest-archive']);
const MAX_ALIAS_DEPTH = 8;
const MAX_QUOTE_DEPTH = 8;

const QUOTES = `"'\``;
// What separates shell words outside quotes: white space, and for this
// check `(`, `)`, `<` and `>` (a subshell, `$(...)`, a redirection), `[`,
// `]` and `,` (an exec form `["cargo", "build"]`, a feature list).
const WORD_SEPARATOR = /[\s()<>[\],]/;

// The index of the quote that closes the one at `start` of `text`, or -1:
// a single quote ends at the next one, a double quote or backquote at the
// next one a backslash does not escape. An unmatched quote (an apostrophe
// in prose, or a string that continues on another line) quotes nothing.
function closingQuote(text, start) {
  const quote = text[start];
  for (let i = start + 1; i < text.length; i++) {
    if (text[i] === '\\' && quote !== "'") i++;
    else if (text[i] === quote) return i;
  }
  return -1;
}

// The shell words of `command`, quotes removed (a quoted string, `--config`
// values included, stays in one word; an unmatched quote separates words),
// and the contents of its quoted strings, which can hold commands of their
// own (`sh -c "..."`, `"$(...)"`). With `quoting` false, every quote
// separates words.
function shellWords(command, { quoting = true } = {}) {
  const words = [];
  const quoted = [];
  let word = null;
  for (let i = 0; i < command.length; i++) {
    const char = command[i];
    const close = quoting && QUOTES.includes(char) ? closingQuote(command, i) : -1;
    if (close > 0) {
      const content = command.slice(i + 1, close);
      const value = char === "'" ? content : content.replace(/\\(["\\$`])/g, '$1');
      quoted.push(value);
      word = (word ?? '') + value;
      i = close;
    } else if (char === '\\' && i + 1 < command.length) {
      word = (word ?? '') + command[++i];
    } else if (WORD_SEPARATOR.test(char) || QUOTES.includes(char)) {
      if (word !== null) words.push(word);
      word = null;
    } else {
      word = (word ?? '') + char;
    }
  }
  if (word !== null) words.push(word);
  return { words, quoted };
}

const tokenize = (command) => shellWords(command).words;

// The cargo subcommand that the shell word `word` runs, or null if it runs
// no cargo: its last path component, after a Makefile recipe prefix (`@`,
// `-`, `+`), is `cargo` (`cargo`, `~/.cargo/bin/cargo`: '') or `cargo-SUB`,
// a subcommand run directly (`cargo-nextest`: `nextest`), and it is no
// assignment `NAME=value` nor a short option with its value attached
// (`-C/opt/cargo`).
export function cargoWord(word) {
  if (word.includes('=') || (/^-[A-Za-z]/.test(word) && !/^[@+-]*cargo/.test(word))) return null;
  const match = /(?:^[@+-]*|\/)cargo(?:-([\w-]+))?$/.exec(word);
  return match ? (match[1] ?? '') : null;
}

// The short-option word `token` (`-r`, `-qr`, `-rFfull`) of the subcommand
// `key` read letter by letter with its `SHORT_OPTIONS` table, as cargo
// reads it: a value letter takes the rest of the word (an `=` after it
// dropped), so `-pr` is the package `r` and `-mservice/Cargo.toml` a
// manifest path, not `--release`. `words` are the letters as options and
// the value; `next` is whether the last letter takes the next word. A
// letter of a cluster that the table does not name (or a subcommand with
// no table) adds a problem to `problems` and is read as a flag, so the
// letters after it are still read: the guard cannot tell whether it takes
// a value, and so whether the rest of the word holds `-r`.
function readShortOptions(token, key, problems) {
  const table = SHORT_OPTIONS.get(key);
  const words = [];
  for (let i = 1; i < token.length; i++) {
    const letter = token[i];
    if (!/[A-Za-z]/.test(letter)) {
      words.push(token.slice(i));
      break;
    }
    words.push(`-${letter}`);
    if (table?.values.has(letter)) {
      const value = token.slice(i + 1).replace(/^=/, '');
      if (value) words.push(value);
      return { words, next: !value };
    }
    if (!table?.flags.has(letter) && token.length > 2) {
      const command = key ? `cargo ${key}` : 'cargo';
      problems.push(
        `unknown short option -${letter} in ${token}: \`${command}\` has no such letter in SHORT_OPTIONS in scripts/ci/check-release-features.mjs, so the guard cannot tell whether the rest of the word holds -r (--release); add it there, as a flag or as a letter that takes a value, as \`${command} --help\` lists it`,
      );
    }
  }
  return { words, next: false };
}

// The cargo command `tokens` (the words after `cargo`) up to its
// subcommand: `name`, the subcommand's word (an alias's name included),
// `rest`, the words after it as written, and `problems` (unknown letters,
// `readShortOptions`) of cargo's own options before it.
function readCommand(tokens) {
  const problems = [];
  let at = 0;
  while (at < tokens.length && /^[+-]/.test(tokens[at])) {
    const token = tokens[at++];
    if (LONG_WITH_VALUE.has(token) || (/^-[A-Za-z]/.test(token) && readShortOptions(token, '', problems).next)) at++;
  }
  return { name: tokens[at] ?? '', rest: tokens.slice(at + 1), problems };
}

// The arguments `rest` of the subcommand `sub`, each short-option word
// before `--` read with the table of `sub` (`readShortOptions`), and of the
// tool's own subcommand once it is read (`NESTED_COMMANDS`): `args`, the
// words read, `nested`, the tool's subcommand or undefined, and `problems`.
// The words after `--` are the program's, not cargo's, and stay as they
// are (`-- -Dwarnings`).
function readArguments(sub, rest) {
  const problems = [];
  const args = [];
  const nestedNames = NESTED_COMMANDS.get(sub);
  let key = sub;
  let nested;
  let looking = Boolean(nestedNames);
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (token === '--') {
      args.push(...rest.slice(i));
      break;
    }
    args.push(token);
    if (/^-[A-Za-z]/.test(token)) {
      const { words, next } = readShortOptions(token, key, problems);
      args.splice(args.length - 1, 1, ...words);
      // The next word is the option's value, never a subcommand.
      if (next && i + 1 < rest.length && !rest[i + 1].startsWith('-')) args.push(rest[++i]);
    } else if (LONG_WITH_VALUE.has(token)) {
      if (i + 1 < rest.length) args.push(rest[++i]);
    } else if (looking && !token.startsWith('-')) {
      looking = false;
      nested = nestedNames[token];
      if (nested) key = `${sub} ${nested}`;
    }
  }
  return { args, nested, problems };
}

// Whether the profile `name` is a release profile: `release` and `bench`
// are, `dev` and `test` are not, and a custom one is if any `inherits`
// chain declared for it reaches a release profile or a name nothing
// declares. `profiles` maps a name to the `inherits` values declared for it.
export function isReleaseProfile(name, profiles, seen = new Set()) {
  if (name === 'release' || name === 'bench') return true;
  if (name === 'dev' || name === 'test') return false;
  const parents = profiles.get(name);
  if (!parents?.length || seen.has(name)) return true;
  seen.add(name);
  return parents.some((parent) => isReleaseProfile(parent, profiles, seen));
}

// The message of a release command that uses a forbidden flag, names the
// feature or builds test targets.
const RELEASE_MESSAGE = `a release build must not use --all-features or --all-targets, name ${FEATURE} or a feature that turns it on, or build test, bench or example targets`;

// What is wrong with the cargo command `tokens` (the words after `cargo`,
// or an alias value), or null: `RELEASE_MESSAGE` for a release command that
// uses a forbidden flag, names the feature or builds test targets, or an
// unknown letter of a short-option cluster (`readShortOptions`), which is
// refused whether the command is a release one or not. `context` holds
// `profiles`, `aliases` (name to the values declared for it, each a token
// list) and `leaking`, the features that turn the feature on (`F` and
// `PKG/F`, `leakingFeatures`): a release command's argument that is one of
// them is refused as well. An alias is read with the table of the
// subcommand it runs; its name is read as a subcommand of its own only when
// cargo has one of that name.
function commandProblem(command, context, depth = 0) {
  const { name, rest, problems } = readCommand(command);
  if (problems.length) return problems[0];
  const sub = BUILTIN_ALIASES[name] ?? name;
  const expansions = context.aliases.get(name);
  if (expansions && depth < MAX_ALIAS_DEPTH) {
    for (const expansion of expansions) {
      const problem = commandProblem([...expansion, ...rest], context, depth + 1);
      if (problem) return problem;
    }
    if (!SHORT_OPTIONS.has(sub)) return null;
  }
  const read = readArguments(sub, rest);
  if (read.problems.length) return read.problems[0];
  const { args } = read;
  // `cargo llvm-cov nextest` (and `nextest-archive`) runs nextest too, with
  // nextest's `--profile`.
  const nextest = sub === 'nextest' || (sub === 'llvm-cov' && LLVM_COV_NEXTEST.has(read.nested));
  const profileFlag = nextest ? '--cargo-profile' : '--profile';
  let profile;
  args.forEach((arg, index) => {
    if (arg === profileFlag) profile = args[index + 1] ?? '';
    else if (arg.startsWith(`${profileFlag}=`)) profile = arg.slice(profileFlag.length + 1);
  });
  const release =
    sub === 'install' ||
    args.includes('--release') ||
    args.includes('-r') ||
    (profile !== undefined ? isReleaseProfile(profile, context.profiles) : sub === 'bench');
  if (!release) return null;
  const leaking = context.leaking ?? new Set();
  // A feature list is split at commas and white space (`-F a,b`, `--features "a b"`).
  const names = (arg) => arg.replace(/^(?:--features=|-F=?)/, '').split(/[\s,]+/);
  const bad =
    TEST_COMMANDS.has(sub) ||
    args.some((arg) => arg === '--all-features' || arg.includes(FEATURE) || TEST_TARGETS.test(arg) || names(arg).some((n) => leaking.has(n)));
  return bad ? RELEASE_MESSAGE : null;
}

// Whether `commandProblem` finds something wrong with the cargo command `command`.
export const isBadCommand = (command, context, depth = 0) => commandProblem(command, context, depth) !== null;

// The commands of a logical line: it split at `&&`, `||`, `;`, `|` and `&`
// (not a redirection's: `&>`, `2>&1`) outside quotes (a backslash escapes
// the next character outside single quotes; an unmatched quote is a
// character), so each cargo command is checked with its own arguments only.
export function splitCommands(line) {
  const commands = [];
  let current = '';
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    const close = QUOTES.includes(char) ? closingQuote(line, i) : -1;
    if (close > 0) {
      current += line.slice(i, close + 1);
      i = close;
    } else if (char === '\\' && i + 1 < line.length) {
      current += char + line[++i];
    } else if (char === ';' || char === '|' || (char === '&' && !/[<>]/.test(line[i - 1] ?? '') && line[i + 1] !== '>')) {
      if (line[i + 1] === char) i++;
      commands.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  commands.push(current);
  return commands;
}

// What is wrong with a command of the line `line` (`splitCommands`), or
// null: the problem (`commandProblem`) of the shell words (`shellWords`)
// after a word that runs cargo (`cargoWord`), each such word in turn (a
// `cargo-X` image or wrapper before the real `cargo` hides nothing), with
// the feature's name looked for in the whole command, an environment prefix
// included. The words are read as the shell reads them and, as well, with
// quotes read as separators: a quote nested in another without an escape
// (`sh -c "cargo build -F "a b" -r"`) pairs with the wrong one. The
// contents of each quoted string are read as a line of their own.
function lineProblem(line, context, depth = 0) {
  for (const segment of splitCommands(line)) {
    const { words, quoted } = shellWords(segment);
    for (const view of [words, shellWords(segment, { quoting: false }).words]) {
      for (let at = 0; at < view.length; at++) {
        // A value of `-C` (`make -C /opt/cargo`) is a directory, not cargo.
        const sub = cargoWord(view[at]);
        if (sub === null || view[at - 1] === '-C') continue;
        const tokens = view.slice(at + 1);
        // `cargo-SUB` run directly is `cargo SUB`; cargo passes it `SUB` first.
        if (sub && tokens[0] !== sub) tokens.unshift(sub);
        if (segment.includes(FEATURE)) tokens.push(FEATURE);
        const problem = commandProblem(tokens, context);
        if (problem) return problem;
      }
    }
    if (depth < MAX_QUOTE_DEPTH) {
      for (const content of quoted) {
        const problem = lineProblem(content, context, depth + 1);
        if (problem) return problem;
      }
    }
  }
  return null;
}

// The commands of one file that `lineProblem` refuses: `[{ line, text }]`
// for a release command that uses a forbidden flag, names the feature or
// builds test targets, with `problem` when it is something else (an
// unknown short option).
export function badReleaseCommands(text, { yaml = false, profiles = new Map(), aliases = new Map(), leaking = new Set() } = {}) {
  const bad = [];
  for (const { line, text: logical } of logicalLines(text, { yaml })) {
    const problem = lineProblem(logical, { profiles, aliases, leaking });
    if (problem) bad.push({ line, text: logical.trim().replace(/\s+/g, ' '), ...(problem === RELEASE_MESSAGE ? {} : { problem }) });
  }
  return bad;
}

// Whether `path` (relative, `/`-separated) is a file the command check
// reads (`file`, or `yaml` for a workflow or action), cargo configuration
// (`cargo-config`), or a manifest (`manifest`, read for profiles only).
export function scannedKind(path) {
  const name = path.split('/').pop();
  if (SELF_FILES.has(name) && path.startsWith('scripts/ci/')) return null;
  if (/(?:^|\/)\.cargo\/config(?:\.toml)?$/.test(path)) return 'cargo-config';
  if (name === 'Cargo.toml') return 'manifest';
  if (/^\.github\/(workflows\/[^/]+|actions\/.+\/action)\.ya?ml$/.test(path)) return 'yaml';
  if (/^(Dockerfile|Containerfile)(\..+)?$/.test(name) || /\.(Dockerfile|dockerfile)$/.test(name)) return 'file';
  if (['justfile', 'Justfile', '.justfile', 'Makefile', 'makefile', 'GNUmakefile'].includes(name)) return 'file';
  if (/\.(sh|bash)$/.test(name)) return 'file';
  if (path.startsWith('scripts/') && /\.(mjs|cjs|js)$/.test(name)) return 'file';
  return null;
}

function walk(root, dir, files) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(root, join(dir, entry.name), files);
    } else if (entry.isFile()) {
      files.push(relative(root, join(dir, entry.name)).split(sep).join('/'));
    }
  }
  return files;
}

const isTable = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

// The features of the workspace packages `packages` (`cargo metadata`)
// that turn `FEATURE` on, but the `FEATURE` keys themselves:
// `[{ pkg, feature }]`, sorted.
export function leakingFeatures(packages) {
  const byName = new Map(packages.map((pkg) => [pkg.name, pkg]));
  const on = new Set();
  const key = (pkg, feature) => `${pkg}\0${feature}`;
  for (const pkg of packages) if (Object.hasOwn(pkg.features, FEATURE)) on.add(key(pkg.name, FEATURE));

  // The normal and build dependencies of `pkg` under the name `dep`.
  const dependencies = (pkg, dep) => pkg.dependencies.filter((d) => (d.rename ?? d.name) === dep && d.kind !== 'dev');
  // Whether a dependency declaration turns the feature on when active.
  const declarationLeaks = (declaration) => {
    const target = byName.get(declaration.name);
    const features = [...declaration.features, ...(declaration.uses_default_features ? ['default'] : [])];
    return features.some((feature) => feature === FEATURE || (target && on.has(key(target.name, feature))));
  };
  const valueLeaks = (pkg, value) => {
    const slash = /^([^/]+?)\??\/(.+)$/.exec(value);
    if (slash) {
      const [, dep, feature] = slash;
      if (feature === FEATURE) return true;
      return dependencies(pkg, dep).some((d) => {
        const target = byName.get(d.name);
        return (target && on.has(key(target.name, feature))) || (d.optional && !value.includes('?/') && declarationLeaks(d));
      });
    }
    const dep = value.startsWith('dep:') ? value.slice('dep:'.length) : null;
    if (dep === null && Object.hasOwn(pkg.features, value)) return on.has(key(pkg.name, value));
    return dependencies(pkg, dep ?? value).some((d) => d.optional && declarationLeaks(d));
  };

  for (let changed = true; changed; ) {
    changed = false;
    for (const pkg of packages) {
      for (const [feature, values] of Object.entries(pkg.features)) {
        if (on.has(key(pkg.name, feature))) continue;
        if (values.some((value) => valueLeaks(pkg, value))) {
          on.add(key(pkg.name, feature));
          changed = true;
        }
      }
    }
  }
  return [...on]
    .map((entry) => entry.split('\0'))
    .filter(([, feature]) => feature !== FEATURE)
    .map(([pkg, feature]) => ({ pkg, feature }))
    .sort((a, b) => a.pkg.localeCompare(b.pkg) || a.feature.localeCompare(b.feature));
}

function readToml(root, path) {
  try {
    return parseToml(readFileSync(join(root, path), 'utf8'));
  } catch (error) {
    throw new InternalError(`${path}: ${error.message}`);
  }
}

export function checkReleaseFeatures({ root }) {
  const errors = [];
  const stats = { binaries: [], declaring: [], scanned: 0 };

  const metadata = JSON.parse(cargo(root, ['metadata', '--locked', '--format-version', '1', '--no-deps']));
  const leaks = leakingFeatures(metadata.packages);
  const leaking = new Set(leaks.flatMap(({ pkg, feature }) => [feature, `${pkg}/${feature}`]));

  const files = walk(root, root, [])
    .sort()
    .map((path) => ({ path, kind: scannedKind(path) }))
    .filter(({ kind }) => kind);
  const profiles = new Map();
  const aliases = new Map();
  const configs = [];
  const add = (map, name, value) => map.set(name, [...(map.get(name) ?? []), value]);
  for (const { path, kind } of files) {
    if (kind !== 'manifest' && kind !== 'cargo-config') continue;
    const toml = readToml(root, path);
    if (isTable(toml.profile)) {
      for (const [name, profile] of Object.entries(toml.profile)) {
        if (isTable(profile) && typeof profile.inherits === 'string') add(profiles, name, profile.inherits);
      }
    }
    if (kind === 'cargo-config') {
      configs.push(path);
      for (const [name, value] of Object.entries(isTable(toml.alias) ? toml.alias : {})) {
        const tokens = Array.isArray(value) ? value.map(String) : tokenize(String(value));
        add(aliases, name, tokens);
      }
    }
  }

  const commandErrors = [];
  for (const path of configs) {
    stats.scanned++;
    const text = readFileSync(join(root, path), 'utf8');
    const lines = text.split('\n');
    const lineOf = (pattern) => lines.findIndex((line) => pattern.test(line)) + 1 || 1;
    lines.forEach((line, index) => {
      if (line.replace(/^\s*#.*$/, '').includes(FEATURE)) {
        commandErrors.push({ path, line: index + 1, text: `cargo configuration applies to every build and must not name ${FEATURE}: ${line.trim()}` });
      }
    });
    const toml = readToml(root, path);
    for (const [name, value] of Object.entries(isTable(toml.alias) ? toml.alias : {})) {
      const tokens = Array.isArray(value) ? value.map(String) : tokenize(String(value));
      const problem = commandProblem(tokens, { profiles, aliases, leaking });
      if (problem) {
        const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const line = lineOf(new RegExp(`^\\s*(?:alias\\.)?["']?${escaped}["']?\\s*=`));
        commandErrors.push({ path, line, text: `${problem}: alias ${name} = ${tokens.join(' ')}` });
      }
    }
  }
  for (const { path, kind } of files) {
    if (kind !== 'file' && kind !== 'yaml') continue;
    stats.scanned++;
    const text = readFileSync(join(root, path), 'utf8');
    for (const { line, text: command, problem = RELEASE_MESSAGE } of badReleaseCommands(text, { yaml: kind === 'yaml', profiles, aliases, leaking })) {
      commandErrors.push({ path, line, text: `${problem}: ${command}` });
    }
  }
  commandErrors.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.line - b.line));
  for (const { path, line, text } of commandErrors) errors.push(`${path}:${line}: command: ${text}`);

  for (const pkg of metadata.packages) {
    if (pkg.targets.some((target) => target.kind.includes('bin'))) stats.binaries.push(pkg.name);
    if (Object.hasOwn(pkg.features, FEATURE)) stats.declaring.push(pkg.name);
  }
  stats.binaries.sort();
  stats.declaring.sort();
  if (stats.binaries.length === 0) errors.push(`resolve: the workspace has no binary package, so nothing was checked`);
  if (stats.declaring.length === 0) errors.push(`control: no workspace package declares \`${FEATURE}\`, so the guard checks a feature that no longer exists`);

  for (const { pkg, feature } of leaks) {
    errors.push(
      `features: feature \`${feature}\` of ${pkg} turns on \`${FEATURE}\`, so \`--features ${feature}\` or --all-features would build it into a release`,
    );
  }

  const selections = [...stats.binaries.map((name) => ['-p', name]), ['--workspace']];
  for (const selection of selections) {
    const shown = selection.join(' ');
    for (const [name, features] of resolution(root, selection)) {
      if (features.has(FEATURE)) {
        errors.push(`resolve: \`cargo build --release ${shown}\` would build ${name} with \`${FEATURE}\``);
      }
    }
  }

  for (const name of stats.declaring) {
    const features = resolution(root, ['-p', name], ['--features', FEATURE]).get(name);
    if (!features?.has(FEATURE)) {
      errors.push(`control: \`cargo tree -p ${name} --features ${FEATURE}\` does not show the feature, so the resolve check cannot see it`);
    }
  }
  return { errors, stats };
}

function main(argv) {
  let root = resolve(dirname(SELF), '..', '..');
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--root' || arg.startsWith('--root=')) {
      const value = arg === '--root' ? argv[++i] : arg.slice('--root='.length);
      if (!value) {
        console.error('check-release-features: --root needs a directory');
        return 2;
      }
      root = resolve(value);
    } else if (arg === '--help' || arg === '-h') {
      console.log('usage: node scripts/ci/check-release-features.mjs [--root DIR]');
      return 0;
    } else {
      console.error(`check-release-features: unknown argument '${arg}'`);
      return 2;
    }
  }
  let result;
  try {
    result = checkReleaseFeatures({ root });
  } catch (error) {
    if (!(error instanceof InternalError)) throw error;
    console.error(`check-release-features: ${error.message}`);
    return 2;
  }
  const { errors, stats } = result;
  for (const error of errors) console.log(`error: ${error}`);
  console.log(
    [
      `check-release-features: binary packages: ${stats.binaries.join(', ') || 'none'}; declaring \`${FEATURE}\`: ${stats.declaring.join(', ') || 'none'}; ${stats.scanned} files scanned for release commands`,
      errors.length ? `FAILED: ${errors.length} error(s)` : 'OK',
    ].join('\n'),
  );
  return errors.length ? 1 : 0;
}

// Compare real paths: Node resolves symlinks in import.meta.url but not in
// argv[1], and a missed match here would exit 0 without checking anything.
const isMain = (() => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(SELF);
  } catch {
    return false;
  }
})();
if (isMain) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (error) {
    console.error(error);
    process.exit(2);
  }
}
