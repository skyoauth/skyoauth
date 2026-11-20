// Self-test of verify-badges-render.sh. No network: a stub `curl` placed
// first on PATH answers every request from a per-test rules file and logs
// each call and each (emulated) retry. The script runs in a real git
// checkout built for each case (git reads no global or system
// configuration), through a `git` wrapper that logs each call. Run with
//   node --test scripts/ci/verify-badges-render.test.mjs
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'verify-badges-render.sh');
const REPO = 'skyoauth/skyoauth';
const SHA = '0123456789abcdef0123456789abcdef01234567';
const BADGES = ['rust-tests', 'rust-coverage', 'typescript-tests', 'typescript-coverage'];
const README_URL = `https://api.github.com/repos/${REPO}/readme`;
const raw = (badge) => `https://raw.githubusercontent.com/${REPO}/badges/main/${badge}.svg`;

const TOP = mkdtempSync(join(tmpdir(), 'verify-badges-test-'));
after(() => rmSync(TOP, { recursive: true, force: true }));

// The stub curl (verify-badges-render.stub-curl.sh, which documents its
// rules) is installed as `curl` first on PATH.
const STUB = join(dirname(SCRIPT), 'verify-badges-render.stub-curl.sh');

let cases = 0;

function readme(badges = BADGES) {
  const imgs = badges.map((b) => `<p><a href="x"><img src="https://github.com/${REPO}/raw/badges/main/${b}.svg" alt="${b}" style="max-width: 100%;"></a></p>`);
  return `<div id="readme"><h1>skyoauth</h1>\n${imgs.join('\n')}\n</div>\n`;
}

// The README.md of the base branch, as the repository's own embeds the
// badges.
const BASE_README = `# skyoauth\n\n${BADGES.map((b) => `[![${b}](https://github.com/${REPO}/raw/badges/main/${b}.svg)](https://github.com/${REPO}/actions)`).join('\n')}\n\nText.\n`;

// git for the fixtures and the script: no inherited GIT_* variable, no
// global or system configuration, a fixed identity.
const REAL_GIT = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
const GIT_ENV = {
  ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))),
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'test',
  GIT_AUTHOR_EMAIL: 'test@example.invalid',
  GIT_COMMITTER_NAME: 'test',
  GIT_COMMITTER_EMAIL: 'test@example.invalid',
};
const git = (cwd, ...args) => execFileSync(REAL_GIT, args, { cwd, env: GIT_ENV, encoding: 'utf8' }).trim();

// Builds the checkout the script runs in, at `work`:
//   merge    the merge commit of a pull request (HEAD^1 the base tip, whose
//            README is `base`; the pull request's README is `md`), with
//            full history
//   depth2   the same, cloned with --depth 2 (the job's fetch-depth)
//   shallow  the same, cloned with --depth 1: HEAD has no parent
//   root     a single commit with README `md`: no parent either
//   linear   the pull request's own commit, fast-forwarded onto the base:
//            one parent, which is not the base tip of a merge
//   octopus  a merge of the pull request and a second branch: three
//            parents
//   none     a plain directory holding README `md`, not a repository
// The base commit also holds the files in `baseFiles`, and the pull
// request, which always changes another file so the merge is never empty,
// writes README `md` (when it differs from `base`) and the files in
// `extra`. Those maps take a path to its content, or to `{ link: target }`
// for a symbolic link (a README.md in `baseFiles` replaces `base`).
function put(root, path, value) {
  const at = join(root, path);
  mkdirSync(dirname(at), { recursive: true });
  rmSync(at, { force: true });
  if (typeof value === 'string') writeFileSync(at, value);
  else symlinkSync(value.link, at);
}

function checkout(dir, work, kind, base, md, extra, baseFiles) {
  if (kind === 'none') {
    mkdirSync(work);
    writeFileSync(join(work, 'README.md'), md);
    return;
  }
  const origin = ['merge', 'root', 'linear', 'octopus'].includes(kind) ? work : join(dir, 'origin');
  mkdirSync(origin);
  git(origin, 'init', '-q', '-b', 'main');
  if (kind === 'root') {
    writeFileSync(join(origin, 'README.md'), md);
    git(origin, 'add', '.');
    git(origin, 'commit', '-q', '-m', 'root');
    return;
  }
  for (const [path, value] of Object.entries({ 'README.md': base, 'lib.rs': '// base\n', ...baseFiles })) put(origin, path, value);
  git(origin, 'add', '.');
  git(origin, 'commit', '-q', '-m', 'base');
  git(origin, 'checkout', '-q', '-b', 'pr');
  if (md !== base) put(origin, 'README.md', md);
  for (const [path, value] of Object.entries({ 'lib.rs': '// pull request\n', ...extra })) put(origin, path, value);
  git(origin, 'add', '-A');
  git(origin, 'commit', '-q', '-m', 'pull request');
  git(origin, 'checkout', '-q', 'main');
  if (kind === 'linear') {
    git(origin, 'merge', '-q', '--ff-only', 'pr');
    return;
  }
  if (kind === 'octopus') {
    git(origin, 'checkout', '-q', '-b', 'other', 'main');
    put(origin, 'other.rs', '// other\n');
    git(origin, 'add', '.');
    git(origin, 'commit', '-q', '-m', 'other');
    git(origin, 'checkout', '-q', 'main');
    git(origin, 'merge', '-q', '--no-ff', '-m', 'merge', 'pr', 'other');
    return;
  }
  git(origin, 'merge', '-q', '--no-ff', '-m', 'merge', 'pr');
  if (kind !== 'merge') git(dir, 'clone', '-q', '--depth', kind === 'depth2' ? '2' : '1', `file://${origin}`, work);
}

// Runs the script against the given rules. `rules` maps a URL substring
// to its responses; raw badge URLs not named answer 200 SVG. The script
// runs in a checkout of the given kind (see checkout()), and README_REF
// is its HEAD unless `args` says otherwise (SHA where there is no HEAD).
// With `gitFails`, `git diff` exits 128, as on a corrupt repository.
// With `sub`, the script runs in that subdirectory of the checkout.
function verify({ pr, rules = {}, html = readme(), base = BASE_README, md = base, extra = {}, baseFiles = {}, repo = 'merge', gitFails = false, sub = '', args }) {
  const dir = join(TOP, `case-${++cases}`);
  const bin = join(dir, 'bin');
  const tmp = join(dir, 'tmp');
  const work = join(dir, 'work');
  mkdirSync(bin, { recursive: true });
  mkdirSync(tmp);
  copyFileSync(STUB, join(bin, 'curl'));
  chmodSync(join(bin, 'curl'), 0o755);
  writeFileSync(join(bin, 'git'), `#!/bin/sh
printf '%s\\n' "$*" >> "$CURL_STUB_DIR/git.log"
if [ "\${GIT_STUB_FAIL_DIFF-}" = 1 ] && [ "$1" = diff ]; then exit 128; fi
exec '${REAL_GIT}' "$@"
`);
  chmodSync(join(bin, 'git'), 0o755);
  checkout(dir, work, repo, base, md, extra, baseFiles);
  const head = repo === 'none' ? SHA : git(work, 'rev-parse', 'HEAD');
  args ??= [REPO, 'main', head];
  writeFileSync(join(dir, 'readme.html'), html);
  const all = { [README_URL]: '200:application/vnd.github.html+json:readme', ...rules };
  const lines = Object.entries(all).map(([sub, responses]) => `${sub} ${responses}`);
  lines.push('https://raw.githubusercontent.com/ 200:image/svg+xml');
  writeFileSync(join(dir, 'rules'), `${lines.join('\n')}\n`);
  mkdirSync(join(work, sub), { recursive: true });
  const r = spawnSync('sh', [SCRIPT, ...(pr ? ['--pull-request'] : []), ...args], {
    cwd: join(work, sub),
    encoding: 'utf8',
    timeout: 60_000,
    killSignal: 'SIGKILL',
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      GH_TOKEN: 'test-token',
      CURL_STUB_DIR: dir,
      TMPDIR: tmp,
      LC_ALL: 'C',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CEILING_DIRECTORIES: dir,
      ...(gitFails ? { GIT_STUB_FAIL_DIFF: '1' } : {}),
    },
  });
  assert.equal(r.error, undefined);
  const read = (name) => {
    try {
      return readFileSync(join(dir, name), 'utf8').split('\n').filter(Boolean);
    } catch {
      return [];
    }
  };
  return { ...r, head, calls: read('calls.log'), attempts: read('attempts.log'), gitCalls: read('git.log'), leftovers: readdirSync(tmp) };
}

const MODES = [
  ['pull request', true],
  ['strict (main)', false],
];

function warnings(r) {
  return r.stdout.split('\n').filter((line) => line.startsWith('::warning::'));
}

describe('verify-badges-render.sh with a stub curl', () => {
  for (const [mode, pr] of MODES) {
    describe(mode, () => {
      test('passes when the README embeds the four badges and each is served as SVG', () => {
        const r = verify({ pr });
        assert.equal(r.status, 0, r.stderr);
        assert.deepEqual(warnings(r), []);
        assert.equal(r.calls.length, 5);
        for (const badge of BADGES) assert.match(r.stdout, new RegExp(`${raw(badge)} -> 200 image/svg\\+xml`));
        assert.deepEqual(r.leftovers, []);
      });

      test('passes every curl --retry 3 --retry-delay 2 --retry-max-time 60 --max-time 20', () => {
        const r = verify({ pr });
        assert.equal(r.status, 0, r.stderr);
        for (const call of r.calls) assert.match(call, /(^| )--retry 3 --retry-delay 2 --retry-max-time 60 --max-time 20( |$)/, call);
      });

      for (const [what, responses, attempts] of [
        ['a 429', '429', 4],
        ['a 503', '503', 4],
        ['a DNS failure (curl exit 6)', 'x6', 4],
        ['a timeout (curl exit 28)', 'x28', 4],
        ['a refused connection (curl exit 7)', 'x7', 1],
      ]) {
        test(`README fetch that keeps failing with ${what}: ${pr ? 'warning when the README is unchanged' : 'failure'}`, () => {
          const r = verify({ pr, rules: { [README_URL]: responses } });
          assert.equal(r.attempts.filter((a) => a.startsWith(README_URL)).length, attempts, r.attempts.join('\n'));
          if (pr) {
            assert.equal(r.status, 0, r.stderr);
            assert.equal(warnings(r).length, 1);
            assert.match(warnings(r)[0], /could not fetch the rendered README .*the README is unchanged from the base branch/);
            assert.equal(r.calls.length, 5, 'the four published badge files are fetched');
            for (const badge of BADGES) assert.match(r.stdout, new RegExp(`${raw(badge)} -> 200 image/svg\\+xml`));
          } else {
            assert.equal(r.status, 1);
            assert.deepEqual(warnings(r), []);
            assert.match(r.stderr, /could not fetch the rendered README .*nothing was checked/);
            assert.equal(r.calls.length, 1, 'no badge is fetched without the README');
          }
          assert.deepEqual(r.leftovers, []);
        });
      }

      for (const code of ['404', '403']) {
        test(`README fetch answered ${code}: failure in both modes`, () => {
          const r = verify({ pr, rules: { [README_URL]: `${code}:application/json` } });
          assert.equal(r.status, 1);
          assert.deepEqual(warnings(r), []);
          assert.match(r.stderr, new RegExp(`README .*HTTP ${code}`));
        });
      }

      test('a README fetch that fails once, then succeeds, passes after a retry', () => {
        const r = verify({ pr, rules: { [README_URL]: '503 200:application/vnd.github.html+json:readme' } });
        assert.equal(r.status, 0, r.stderr);
        assert.deepEqual(warnings(r), []);
        assert.equal(r.attempts.filter((a) => a.startsWith(README_URL)).length, 2);
      });

      test('a badge that is not published yet (404): ' + (pr ? 'warning' : 'failure'), () => {
        const r = verify({ pr, rules: { [raw('rust-coverage')]: '404:text/plain' } });
        if (pr) {
          assert.equal(r.status, 0, r.stderr);
          assert.equal(warnings(r).length, 1);
          assert.match(warnings(r)[0], /rust-coverage\.svg .*not published for main yet/);
        } else {
          assert.equal(r.status, 1);
          assert.match(r.stderr, /rust-coverage\.svg is not served as SVG \(HTTP 404/);
        }
        assert.equal(r.calls.length, 5, 'the other badges are still checked');
      });

      test('a badge served with a non-SVG type: failure in both modes', () => {
        const r = verify({ pr, rules: { [raw('typescript-tests')]: '200:text/plain' } });
        assert.equal(r.status, 1);
        assert.deepEqual(warnings(r), []);
        assert.match(r.stderr, /typescript-tests\.svg is not served as SVG \(HTTP 200 text\/plain\)/);
      });

      for (const [what, responses, attempts] of [
        ['a 503', '503', 4],
        ['a 429', '429', 4],
        ['a DNS failure (curl exit 6)', 'x6', 4],
      ]) {
        test(`a badge fetch that keeps failing with ${what}: ${pr ? 'warning' : 'failure'}`, () => {
          const r = verify({ pr, rules: { [raw('rust-tests')]: responses } });
          assert.equal(r.attempts.filter((a) => a.startsWith(raw('rust-tests'))).length, attempts);
          if (pr) {
            assert.equal(r.status, 0, r.stderr);
            assert.equal(warnings(r).length, 1);
            assert.match(warnings(r)[0], /could not fetch .*rust-tests\.svg/);
          } else {
            assert.equal(r.status, 1);
            assert.match(r.stderr, /could not fetch .*rust-tests\.svg/);
          }
        });
      }

      test('a flaky badge fetch (503, then 200 SVG) passes after a retry', () => {
        const r = verify({ pr, rules: { [raw('typescript-coverage')]: '503 200:image/svg+xml' } });
        assert.equal(r.status, 0, r.stderr);
        assert.deepEqual(warnings(r), []);
        assert.deepEqual(
          r.attempts.filter((a) => a.startsWith(raw('typescript-coverage'))),
          [`${raw('typescript-coverage')} 503`, `${raw('typescript-coverage')} 200:image/svg+xml`],
        );
      });

      test('a README that lacks a badge: failure in both modes', () => {
        const r = verify({ pr, html: readme(BADGES.filter((b) => b !== 'typescript-tests')) });
        assert.equal(r.status, 1);
        assert.match(r.stderr, /does not embed badges\/main\/typescript-tests\.svg/);
      });

      test('a README that embeds a badge twice: failure in both modes', () => {
        const r = verify({ pr, html: readme([...BADGES, 'rust-tests']) });
        assert.equal(r.status, 1);
        assert.match(r.stderr, /rust-tests\.svg is embedded more than once \(2\)/);
      });

      test('a README that embeds a badge the script does not know: failure in both modes', () => {
        const r = verify({ pr, html: readme([...BADGES, 'rust-doctests']), rules: { [raw('rust-doctests')]: '404:text/plain' } });
        assert.equal(r.status, 1);
        assert.match(r.stderr, /unexpected badge URL .*rust-doctests\.svg/);
      });

      test('a README without any badge: failure in both modes', () => {
        const r = verify({ pr, html: readme([]) });
        assert.equal(r.status, 1);
        assert.match(r.stderr, /no badge <img> in the rendered README/);
      });
    });
  }

  // A pull request whose rendered README cannot be fetched passes only
  // when its README is byte for byte the base branch's (HEAD^1 of the
  // merge commit); nothing parses the Markdown.
  describe('pull request, rendered README unavailable', () => {
    const down = { [README_URL]: '503' };
    const changed = BASE_README.replace('Text.', 'Other text.');

    test('an unchanged README passes with a warning, and the four badge files are checked', () => {
      const r = verify({ pr: true, rules: down });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(warnings(r).length, 1);
      assert.match(warnings(r)[0], /could not fetch the rendered README at .* \(HTTP 503\); the README is unchanged from the base branch/);
      assert.deepEqual(r.calls.map((c) => c.split(' ').pop()), [`${README_URL}?ref=${r.head}`, ...BADGES.map(raw)]);
      assert.deepEqual(r.gitCalls.map((c) => c.split(' ')[0]), ['rev-parse', 'show', 'rev-parse', 'rev-parse', 'rev-parse', 'ls-tree', 'ls-tree', 'diff']);
      assert.deepEqual(r.leftovers, []);
    });

    test('a checkout with fetch-depth 2 is enough', () => {
      const r = verify({ pr: true, rules: down, repo: 'depth2' });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(warnings(r).length, 1);
    });

    test('a pull request that changes the README fails, asking for a re-run', () => {
      const r = verify({ pr: true, rules: down, md: changed });
      assert.equal(r.status, 1);
      assert.deepEqual(warnings(r), []);
      assert.match(r.stderr, /this pull request changes the README, .*re-run this job once the GitHub API answers again/);
      assert.equal(r.calls.length, 1, 'no badge is fetched');
    });

    test('a README that hides all four badges in an HTML comment fails', () => {
      const hidden = BASE_README.replace(/(\[!\[[\s\S]*\))\n\n/, '<!--\n$1\n-->\n\n');
      assert.notEqual(hidden, BASE_README);
      const r = verify({ pr: true, rules: down, md: hidden });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /this pull request changes the README/);
    });

    test('a whitespace-only change to the README fails too', () => {
      const r = verify({ pr: true, rules: down, md: BASE_README.replace('Text.', 'Text. ') });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /this pull request changes the README/);
    });

    for (const [path, what] of [['.github/README.md', 'a .github/README.md, which GitHub renders first'], ['docs/readme.rst', 'a docs/readme.rst']]) {
      test(`a pull request that adds ${what} fails`, () => {
        const r = verify({ pr: true, rules: down, extra: { [path]: '# not the README with the badges\n' } });
        assert.equal(r.status, 1);
        assert.match(r.stderr, /this pull request changes the README/);
      });
    }

    for (const [repo, what] of [['shallow', 'a shallow checkout (fetch-depth 1)'], ['root', 'a commit without a parent']]) {
      test(`${what} fails`, () => {
        const r = verify({ pr: true, rules: down, repo });
        assert.equal(r.status, 1);
        assert.deepEqual(warnings(r), []);
        assert.match(r.stderr, /cannot compare the README with the base branch: no parent commit of HEAD/);
        assert.equal(r.calls.length, 1);
      });
    }

    for (const [repo, what, parents] of [['linear', 'a non-merge (fast-forwarded) commit', 1], ['octopus', 'a merge commit with three parents', 3]]) {
      test(`${what} fails, even with the README unchanged`, () => {
        const r = verify({ pr: true, rules: down, repo });
        assert.equal(r.status, 1, r.stdout + r.stderr);
        assert.deepEqual(warnings(r), []);
        assert.match(r.stderr, new RegExp(`HEAD is not a merge commit with two parents \\(${parents} parents\\), so HEAD\\^1 is not known to be the base tip`));
        assert.equal(r.calls.length, 1);
      });
    }

    // The README paths are the checkout's top-level ones wherever the
    // script runs; a subdirectory's own README.md is not one of them.
    test('run from a subdirectory, a changed README still fails', () => {
      const r = verify({ pr: true, rules: down, md: changed, sub: 'lib/inner', extra: { 'lib/inner/README.md': '# inner\n' }, baseFiles: { 'lib/inner/README.md': '# inner\n' } });
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /this pull request changes the README/);
    });

    test('run from a subdirectory, a symbolic-link README still fails', () => {
      const r = verify({ pr: true, rules: down, sub: 'lib', baseFiles: { 'README.md': { link: 'doc/home.md' }, 'doc/home.md': BASE_README } });
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.ok(r.stderr.includes('a README path is not a regular file in HEAD or HEAD^1, so an unchanged README proves nothing: README.md (mode 120000)'), r.stderr);
    });

    test('run from a subdirectory, an unchanged README passes', () => {
      const r = verify({ pr: true, rules: down, sub: 'lib' });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(warnings(r).length, 1);
    });

    test('a directory that is not a git repository fails', () => {
      const r = verify({ pr: true, rules: down, repo: 'none' });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /cannot compare the README with the base branch: no parent commit of HEAD/);
      assert.equal(r.calls.length, 1);
    });

    test('a git error while comparing fails', () => {
      const r = verify({ pr: true, rules: down, gitFails: true });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /git could not compare the README with the base branch \(git diff exit 128\)/);
      assert.equal(r.calls.length, 1);
    });

    test('a README_REF that is not the checked-out commit fails', () => {
      // The base tip: a commit that exists here, but not HEAD.
      const base = verify({ pr: true, rules: down, args: [REPO, 'main', 'HEAD^1'] });
      assert.equal(base.status, 1);
      assert.match(base.stderr, /the current directory is not a checkout of HEAD\^1 \(HEAD is [0-9a-f]{40}, HEAD\^1 is [0-9a-f]{40}\)/);
      assert.equal(base.calls.length, 1);
      const unknown = verify({ pr: true, rules: down, args: [REPO, 'main', SHA] });
      assert.equal(unknown.status, 1);
      assert.match(unknown.stderr, new RegExp(`not a checkout of ${SHA} \\(HEAD is [0-9a-f]{40}, ${SHA} is no commit here\\)`));
    });

    test('README_REF given as a ref that resolves to HEAD passes', () => {
      const r = verify({ pr: true, rules: down, args: [REPO, 'main', 'main'] });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(warnings(r).length, 1);
    });

    // A README that is a symbolic link renders its target, which can
    // change while the README path itself does not.
    const linked = { 'README.md': { link: 'doc/home.md' }, 'doc/home.md': BASE_README };
    const hiddenTarget = { 'doc/home.md': '# skyoauth\n\nNo badges here.\n' };
    for (const [what, opts, path] of [
      ['in both commits, whose target the pull request changes', { baseFiles: linked, extra: hiddenTarget }, 'README.md'],
      ['in both commits, unchanged', { baseFiles: linked }, 'README.md'],
      ['only in the base commit (the pull request makes it a file)', { baseFiles: linked, md: BASE_README.replace('Text.', 'Text!') }, 'README.md'],
      ['only in the pull request', { extra: { 'README.md': { link: 'doc/home.md' }, 'doc/home.md': BASE_README } }, 'README.md'],
      ['as .github/README.md in both commits', { baseFiles: { '.github/README.md': { link: '../doc/home.md' }, 'doc/home.md': BASE_README }, extra: hiddenTarget }, '.github/README.md'],
      ['in place of the docs/ directory', { baseFiles: { docs: { link: 'doc' }, 'doc/README.md': BASE_README }, extra: { 'doc/README.md': '# moved\n' } }, 'docs'],
    ]) {
      test(`a symbolic link at a README path ${what} fails`, () => {
        const r = verify({ pr: true, rules: down, ...opts });
        assert.equal(r.status, 1, r.stdout + r.stderr);
        assert.deepEqual(warnings(r), []);
        assert.ok(r.stderr.includes(`a README path is not a regular file in HEAD or HEAD^1, so an unchanged README proves nothing: ${path} (mode 120000)`), r.stderr);
        assert.equal(r.calls.length, 1);
      });
    }

    test('the badge files are still checked: a non-SVG one fails', () => {
      const r = verify({ pr: true, rules: { ...down, [raw('rust-tests')]: '200:text/plain' } });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /rust-tests\.svg is not served as SVG \(HTTP 200 text\/plain\)/);
    });

    test('git is not consulted when the rendered README was fetched', () => {
      const r = verify({ pr: true, md: changed });
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(warnings(r), []);
      assert.deepEqual(r.gitCalls, []);
    });

    test('strict mode never falls back, even for an unchanged README', () => {
      const r = verify({ pr: false, rules: down });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /nothing was checked/);
      assert.deepEqual(r.gitCalls, []);
      assert.equal(r.calls.length, 1);
    });
  });

  test('the README ref defaults to the branch and is passed to the API', () => {
    const withRef = verify({ pr: true });
    assert.match(withRef.calls[0], new RegExp(`${README_URL}\\?ref=${withRef.head}`));
    const withoutRef = verify({ pr: false, args: [REPO, 'main'] });
    assert.equal(withoutRef.status, 0, withoutRef.stderr);
    assert.match(withoutRef.calls[0], new RegExp(`${README_URL}\\?ref=main`));
  });

  // A job that runs the script has a timeout, and one long enough for the
  // script to finish on its own: at worst 5 fetches, each retried for up
  // to 60 seconds with a last attempt of up to 20 (about 7 minutes).
  test('the CI jobs that run it have a timeout above its worst case', () => {
    const ci = readFileSync(join(dirname(SCRIPT), '..', '..', '.github', 'workflows', 'ci.yml'), 'utf8');
    for (const job of ['verify-badges', 'publish-badges']) {
      const block = ci.match(new RegExp(`^  ${job}:\\n((?:(?:    .*)?\\n)*)`, 'm'))?.[1] ?? '';
      assert.match(block, /verify-badges-render\.sh/, `${job} runs the script`);
      const minutes = Number(block.match(/^    timeout-minutes: (\d+)$/m)?.[1]);
      assert.ok(minutes >= 8 && minutes <= 30, `${job}: timeout-minutes ${minutes}`);
    }
  });

  test('the pull request job checks out the merge commit with its parent (fetch-depth 2)', () => {
    const ci = readFileSync(join(dirname(SCRIPT), '..', '..', '.github', 'workflows', 'ci.yml'), 'utf8');
    const block = ci.match(/^ {2}verify-badges:\n((?:(?: {4}.*)?\n)*)/m)?.[1] ?? '';
    assert.match(block, /- uses: actions\/checkout@\S+\n(?: {8}.*\n)*? {10}fetch-depth: 2\n/);
  });

  test('an unknown option is a usage error', () => {
    const r = verify({ pr: false, args: ['--pr', REPO, 'main'] });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /usage/);
    assert.deepEqual(r.calls, []);
  });
});
