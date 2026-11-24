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
//            or `--profile X` (`--cargo-profile X` for cargo-nextest, whose
//            `--profile` is its own) for any X but `dev`, `test` and a
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
//            lines and a folded block scalar (`>`, `>-`, `>+`) are one
//            logical line, and the lines of a literal block scalar (`|`,
//            `|-`) are shell lines, as the shell reads them. A line is split
//            into commands at `&&`, `||`, `;` and `|` outside quotes, and
//            each command is checked with its own arguments. This file and its
//            self-test are not scanned: they name the flags as patterns.
//            What the guard cannot see: a command built at run time (a
//            flag or a subcommand in an environment variable, a Makefile
//            variable or a recipe that calls another), a build outside the
//            files it reads, and cargo configuration outside the
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
// `yaml`, a key's plain scalar continued on more indented lines, and its
// folded block scalar (`>`, `>-`, `>+`), join too; a literal block scalar's
// lines (`|`) stay lines. Each carries the number of its first line.
export function logicalLines(text, { yaml = false } = {}) {
  const lines = text.split('\n');
  const out = [];
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const key = yaml && !current ? YAML_KEY.exec(line) : null;
    const value = key?.[2] ?? '';
    if (value && !/^\|[-+0-9]*(?:\s+#.*)?$/.test(value)) {
      const folded = /^>[-+0-9]*(?:\s+#.*)?$/.test(value);
      const column = key[1].length;
      let end = i + 1;
      // A folded scalar takes blank lines too; a plain one ends at one.
      while (end < lines.length && (lines[end].trim() ? indentOf(lines[end]) > column : folded)) end++;
      if (folded || end > i + 1) {
        const head = folded ? line.slice(0, line.lastIndexOf(value)) : line;
        const parts = [head, ...lines.slice(i + 1, end)].map((part) => part.replace(/\\\s*$/, ''));
        out.push({ line: i + 1, text: parts.join(' ') });
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
// Global options that take a value before the subcommand.
const GLOBAL_WITH_VALUE = new Set(['-C', '-Z', '--config', '--color', '--manifest-path']);
// Subcommands that build test or bench targets.
const TEST_COMMANDS = new Set(['test', 'bench', 'nextest', 'llvm-cov']);
const TEST_TARGETS = /^--(?:tests|benches|examples|test|bench|example|all-targets)(?:=|$)/;
const MAX_ALIAS_DEPTH = 8;

const tokenize = (command) => command.split(/[\s"'`[\],]+/).filter(Boolean);

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

// Whether the cargo command `tokens` (the words after `cargo`, or an alias
// value) is a release command that uses a forbidden flag, names the feature
// or builds test targets. `context` holds `profiles`, `aliases` (name to
// the values declared for it, each a token list) and `leaking`, the
// features that turn the feature on (`F` and `PKG/F`, `leakingFeatures`):
// a release command's argument that is one of them is refused as well.
export function isBadCommand(tokens, context, depth = 0) {
  let at = 0;
  while (at < tokens.length && (tokens[at].startsWith('+') || tokens[at].startsWith('-'))) {
    at += GLOBAL_WITH_VALUE.has(tokens[at]) ? 2 : 1;
  }
  const name = tokens[at] ?? '';
  const expansions = context.aliases.get(name);
  if (expansions && depth < MAX_ALIAS_DEPTH) {
    const rest = tokens.slice(at + 1);
    if (expansions.some((expansion) => isBadCommand([...expansion, ...rest], context, depth + 1))) return true;
  }
  const sub = BUILTIN_ALIASES[name] ?? name;
  const args = tokens.slice(at + 1);
  const profileFlag = sub === 'nextest' ? '--cargo-profile' : '--profile';
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
  if (!release) return false;
  const leaking = context.leaking ?? new Set();
  return (
    TEST_COMMANDS.has(sub) ||
    args.some((arg) => arg === '--all-features' || arg.includes(FEATURE) || TEST_TARGETS.test(arg) || leaking.has(arg.replace(/^(?:--features=|-F)/, '')))
  );
}

// The commands of a logical line: it split at `&&`, `||`, `;` and `|`
// outside quotes (a backslash escapes the next character outside single
// quotes), so each cargo command is checked with its own arguments only.
export function splitCommands(line) {
  const commands = [];
  let current = '';
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (quote) {
      if (char === '\\' && quote === '"' && i + 1 < line.length) current += char + line[++i];
      else {
        if (char === quote) quote = null;
        current += char;
      }
    } else if (char === '\\' && i + 1 < line.length) {
      current += char + line[++i];
    } else if (char === '"' || char === "'" || char === '`') {
      quote = char;
      current += char;
    } else if (char === ';' || char === '|' || (char === '&' && line[i + 1] === '&')) {
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

// The release commands of one file that use a forbidden flag, name the
// feature or build test targets: `[{ line, text }]`. A command is the part
// of one of a line's commands (`splitCommands`) after the word `cargo`; the
// feature's name is looked for in the whole command, an environment prefix
// included.
export function badReleaseCommands(text, { yaml = false, profiles = new Map(), aliases = new Map(), leaking = new Set() } = {}) {
  const bad = [];
  for (const { line, text: logical } of logicalLines(text, { yaml })) {
    const offending = splitCommands(logical).some((segment) => {
      const at = segment.search(/\bcargo\b/);
      if (at < 0) return false;
      const tokens = tokenize(segment.slice(at + 'cargo'.length));
      if (segment.includes(FEATURE)) tokens.push(FEATURE);
      return isBadCommand(tokens, { profiles, aliases, leaking });
    });
    if (offending) bad.push({ line, text: logical.trim().replace(/\s+/g, ' ') });
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
  const message = `a release build must not use --all-features or --all-targets, name ${FEATURE} or a feature that turns it on, or build test, bench or example targets`;
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
      if (isBadCommand(tokens, { profiles, aliases, leaking })) {
        const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const line = lineOf(new RegExp(`^\\s*(?:alias\\.)?["']?${escaped}["']?\\s*=`));
        commandErrors.push({ path, line, text: `${message}: alias ${name} = ${tokens.join(' ')}` });
      }
    }
  }
  for (const { path, kind } of files) {
    if (kind !== 'file' && kind !== 'yaml') continue;
    stats.scanned++;
    const text = readFileSync(join(root, path), 'utf8');
    for (const { line, text: command } of badReleaseCommands(text, { yaml: kind === 'yaml', profiles, aliases, leaking })) {
      commandErrors.push({ path, line, text: `${message}: ${command}` });
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
