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
// resolution of a release build and the commands that would run one:
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
//   control  For every package that declares `test-support`, the same
//            resolution with `--features test-support` does show it on that
//            package, so a change of cargo's output that hid features fails
//            the guard instead of passing it. At least one package must
//            declare it, so a renamed feature fails the guard too.
//   command  No release command (`cargo` with `--release`, `-r` or
//            `--profile release`; in the cargo configuration any line with
//            those, since an alias omits the word `cargo`) in a workflow, a
//            shell script, a script under scripts/, a Dockerfile, a
//            justfile, a Makefile or the cargo configuration uses
//            `--all-features` or `--all-targets` or names `test-support`.
//            A line ending in `\` continues on the next one. This file and
//            its self-test are not scanned: they name the flags as
//            patterns.
//
// Errors exit 1, one line each. Usage errors and internal failures (cargo
// not found, unparsable output) exit 2. Needs Node (>=20) and cargo on
// PATH; `cargo tree` and `cargo metadata` run with `--locked` and build
// nothing. Self-test: node --test scripts/ci/check-release-features.test.mjs

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

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

// Logical lines of `text`: a line ending in `\` joins the next one. Each
// carries the number of its first line.
export function logicalLines(text) {
  const out = [];
  let current = null;
  text.split('\n').forEach((line, index) => {
    const continues = /\\\s*$/.test(line);
    const body = continues ? line.replace(/\\\s*$/, ' ') : line;
    if (current) current.text += body;
    else current = { line: index + 1, text: body };
    if (!continues) {
      out.push(current);
      current = null;
    }
  });
  if (current) out.push(current);
  return out;
}

const RELEASE = /--release\b|--profile[= ]+release\b|(?:^|\s)-r(?=\s|$)/;
const FORBIDDEN = [/--all-features\b/, /--all-targets\b/, new RegExp(FEATURE)];

// The release commands of one file that use a forbidden flag or the
// feature: `[{ line, text }]`. In the cargo configuration every line counts
// as a command; elsewhere only the part of a line from `cargo` on.
export function badReleaseCommands(text, { cargoConfig = false } = {}) {
  const bad = [];
  for (const { line, text: logical } of logicalLines(text)) {
    let command = logical;
    if (!cargoConfig) {
      const at = logical.search(/\bcargo\b/);
      if (at < 0) continue;
      command = logical.slice(at);
    }
    if (RELEASE.test(command) && FORBIDDEN.some((pattern) => pattern.test(command))) {
      bad.push({ line, text: logical.trim().replace(/\s+/g, ' ') });
    }
  }
  return bad;
}

// Whether `path` (relative, `/`-separated) is a file the command check
// reads, and whether it is cargo configuration.
export function scannedKind(path) {
  const name = path.split('/').pop();
  if (SELF_FILES.has(name) && path.startsWith('scripts/ci/')) return null;
  if (/^\.cargo\/config(\.toml)?$/.test(path)) return 'cargo-config';
  if (/^\.github\/(workflows\/[^/]+|actions\/.+\/action)\.ya?ml$/.test(path)) return 'file';
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

export function checkReleaseFeatures({ root }) {
  const errors = [];
  const stats = { binaries: [], declaring: [], scanned: 0 };

  for (const path of walk(root, root, []).sort()) {
    const kind = scannedKind(path);
    if (!kind) continue;
    stats.scanned++;
    const text = readFileSync(join(root, path), 'utf8');
    for (const { line, text: command } of badReleaseCommands(text, { cargoConfig: kind === 'cargo-config' })) {
      errors.push(`${path}:${line}: command: a release build must not use --all-features, --all-targets or ${FEATURE}: ${command}`);
    }
  }

  const metadata = JSON.parse(cargo(root, ['metadata', '--locked', '--format-version', '1', '--no-deps']));
  for (const pkg of metadata.packages) {
    if (pkg.targets.some((target) => target.kind.includes('bin'))) stats.binaries.push(pkg.name);
    if (Object.hasOwn(pkg.features, FEATURE)) stats.declaring.push(pkg.name);
  }
  stats.binaries.sort();
  stats.declaring.sort();
  if (stats.binaries.length === 0) errors.push(`resolve: the workspace has no binary package, so nothing was checked`);
  if (stats.declaring.length === 0) errors.push(`control: no workspace package declares \`${FEATURE}\`, so the guard checks a feature that no longer exists`);

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
