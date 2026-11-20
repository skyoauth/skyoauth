// Self-test of verify-badges-render.sh. No network: a stub `curl` placed
// first on PATH answers every request from a per-test rules file and logs
// each call and each (emulated) retry. Run with
//   node --test scripts/ci/verify-badges-render.test.mjs
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
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

// The checked-out README.md, as the repository's own embeds the badges.
function markdown(urls = BADGES.map((b) => `https://github.com/${REPO}/raw/badges/main/${b}.svg`)) {
  const lines = urls.map((u) => `[![badge](${u})](https://github.com/${REPO}/actions/workflows/ci.yml?query=branch%3Amain)`);
  return `# skyoauth\n\n${lines.join('\n')}\n\nThe badges are SVG files on the badges branch.\n`;
}

// Runs the script against the given rules. `rules` maps a URL substring
// to its responses; raw badge URLs not named answer 200 SVG. The script
// runs in the case directory, whose README.md (none for `md: null`) is
// what the offline fallback reads.
function verify({ pr, rules = {}, html = readme(), md = markdown(), args = [REPO, 'main', SHA] }) {
  const dir = join(TOP, `case-${++cases}`);
  const bin = join(dir, 'bin');
  const tmp = join(dir, 'tmp');
  mkdirSync(bin, { recursive: true });
  mkdirSync(tmp);
  copyFileSync(STUB, join(bin, 'curl'));
  chmodSync(join(bin, 'curl'), 0o755);
  writeFileSync(join(dir, 'readme.html'), html);
  if (md !== null) writeFileSync(join(dir, 'README.md'), md);
  const all = { [README_URL]: '200:application/vnd.github.html+json:readme', ...rules };
  const lines = Object.entries(all).map(([sub, responses]) => `${sub} ${responses}`);
  lines.push('https://raw.githubusercontent.com/ 200:image/svg+xml');
  writeFileSync(join(dir, 'rules'), `${lines.join('\n')}\n`);
  const r = spawnSync('sh', [SCRIPT, ...(pr ? ['--pull-request'] : []), ...args], {
    cwd: dir,
    encoding: 'utf8',
    timeout: 60_000,
    killSignal: 'SIGKILL',
    env: {
      PATH: `${bin}:${process.env.PATH}`,
      GH_TOKEN: 'test-token',
      CURL_STUB_DIR: dir,
      TMPDIR: tmp,
      LC_ALL: 'C',
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
  return { ...r, calls: read('calls.log'), attempts: read('attempts.log'), leftovers: readdirSync(tmp) };
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
        test(`README fetch that keeps failing with ${what}: ${pr ? 'warning, then the checked-out README.md is checked' : 'failure'}`, () => {
          const r = verify({ pr, rules: { [README_URL]: responses } });
          assert.equal(r.attempts.filter((a) => a.startsWith(README_URL)).length, attempts, r.attempts.join('\n'));
          if (pr) {
            assert.equal(r.status, 0, r.stderr);
            assert.equal(warnings(r).length, 1);
            assert.match(warnings(r)[0], /could not fetch the rendered README .*checking the badge URLs in the checked-out README\.md instead/);
            assert.equal(r.calls.length, 5, 'the four badges from README.md are fetched');
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

  // The offline fallback of a pull request whose rendered README cannot
  // be fetched: the checked-out README.md must embed each badge URL once.
  describe('pull request, rendered README unavailable: the checked-out README.md', () => {
    const down = { [README_URL]: '503' };
    const url = (b, ref = 'main') => `https://github.com/${REPO}/raw/badges/${ref}/${b}.svg`;

    test('a README.md that lacks a badge: failure', () => {
      const r = verify({ pr: true, rules: down, md: markdown(BADGES.filter((b) => b !== 'typescript-tests').map((b) => url(b))) });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /the README\.md does not embed badges\/main\/typescript-tests\.svg/);
    });

    test('a README.md that embeds a badge twice: failure', () => {
      const r = verify({ pr: true, rules: down, md: markdown([...BADGES, 'rust-coverage'].map((b) => url(b))) });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /rust-coverage\.svg is embedded more than once \(2\)/);
    });

    test('a README.md badge URL that points elsewhere: failure', () => {
      const urls = BADGES.map((b) => url(b));
      urls[1] = url('rust-coverage', 'feature');
      const r = verify({ pr: true, rules: down, md: markdown(urls) });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /unexpected badge URL in the README\.md: .*badges\/feature\/rust-coverage\.svg/);
      assert.match(r.stderr, /does not embed badges\/main\/rust-coverage\.svg/);
    });

    test('a README.md without any badge URL: failure', () => {
      const r = verify({ pr: true, rules: down, md: markdown([]) });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /no badge URL in README\.md/);
      assert.equal(r.calls.length, 1);
    });

    test('no README.md in the current directory: failure', () => {
      const r = verify({ pr: true, rules: down, md: null });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /cannot read README\.md/);
      assert.equal(r.calls.length, 1);
    });

    test('the badge files are still checked: a non-SVG one fails', () => {
      const r = verify({ pr: true, rules: { ...down, [raw('rust-tests')]: '200:text/plain' } });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /rust-tests\.svg is not served as SVG \(HTTP 200 text\/plain\)/);
    });

    test('the README.md is not read when the rendered README was fetched', () => {
      const r = verify({ pr: true, md: markdown([]) });
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(warnings(r), []);
    });

    test('strict mode never falls back: a broken README.md is not reached', () => {
      const r = verify({ pr: false, rules: down, md: markdown([]) });
      assert.equal(r.status, 1);
      assert.match(r.stderr, /nothing was checked/);
      assert.doesNotMatch(r.stderr, /README\.md/);
    });
  });

  test('the README ref defaults to the branch and is passed to the API', () => {
    const withRef = verify({ pr: true });
    assert.match(withRef.calls[0], new RegExp(`${README_URL}\\?ref=${SHA}`));
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

  test('an unknown option is a usage error', () => {
    const r = verify({ pr: false, args: ['--pr', REPO, 'main'] });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /usage/);
    assert.deepEqual(r.calls, []);
  });
});
