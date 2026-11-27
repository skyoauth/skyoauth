// Pins the CI wiring of scripts/demo (pure, no dependencies):
//   node --test scripts/demo/workflows.test.mjs
//
// ci.yml: no `pull_request_target`; the `demo-transcripts` job runs for
// every change (no `needs`, no `if`), installs with `npm ci
// --ignore-scripts`, runs the pure self-tests and the transcript check
// against the committed test keys, and `ci-passed` both needs it and
// requires its result to be `success`.
// demo.yml: read-only (`permissions: contents: read` at the top and in
// every job, no other permission), no `pull_request_target`, no secret,
// `npm ci --ignore-scripts`, the check and the render against the
// committed test keys, DEMO_KEEP_RAW on the e2e and render steps, a video
// upload that errors on no files, a raw-recording upload only on failure
// (its own artifact name, 3 days, no error when empty), and it is not
// wired into ci.yml.
//
// The workflows are read as text with strict line patterns (the layout
// ci.yml uses: two-space indents, block lists), not with a YAML library;
// each rule has a mutant below that it must catch.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKFLOWS = join(HERE, '..', '..', '.github', 'workflows');
const CI = readFileSync(join(WORKFLOWS, 'ci.yml'), 'utf8');
const DEMO = readFileSync(join(WORKFLOWS, 'demo.yml'), 'utf8');

// Job id -> body (the lines indented four or more spaces after `  id:`).
export function jobs(text) {
  const at = text.search(/^jobs:\n/m);
  if (at < 0) return new Map();
  const out = new Map();
  for (const m of text.slice(at).matchAll(/^ {2}([A-Za-z0-9_-]+):\n((?:(?: {4}.*)?\n)*)/gm)) out.set(m[1], m[2]);
  return out;
}

// A job's block-list `needs`.
const needsOf = (body) => {
  const block = /^ {4}needs:\n((?: {6}- .*\n)+)/m.exec(body ?? '');
  return block ? block[1].split('\n').filter(Boolean).map((l) => l.replace(/^ {6}- /, '').trim()) : [];
};

// Lines that are not comments.
const code = (text) => text.split('\n').filter((l) => !/^\s*#/.test(l));

// Every problem of the npm ci lines in `text`: each must carry
// --ignore-scripts when it runs in scripts/demo; returns the count of
// scripts/demo installs too.
function npmCi(body) {
  const problems = [];
  let demoInstalls = 0;
  for (const step of body.split(/^(?= {6}- )/m)) {
    if (!/\bnpm ci\b/.test(code(step).join('\n'))) continue;
    if (!/^ {8}working-directory: scripts\/demo$/m.test(step)) continue;
    demoInstalls++;
    if (!/^ {8}run: npm ci --ignore-scripts$/m.test(step)) problems.push('a scripts/demo npm ci without --ignore-scripts');
  }
  return { problems, demoInstalls };
}

export function ciProblems(ci) {
  const out = [];
  if (/pull_request_target/.test(code(ci).join('\n'))) out.push('ci.yml uses pull_request_target');
  const all = jobs(ci);
  const job = all.get('demo-transcripts');
  if (!job) return ['ci.yml has no demo-transcripts job'];
  if (/^ {4}(needs|if):/m.test(job)) out.push('demo-transcripts has a needs or if: it must run for every change');
  if (!/^ {4}permissions:\n {6}contents: read\n(?! {6})/m.test(job)) out.push('demo-transcripts is not permissions: contents: read');
  const npm = npmCi(job);
  out.push(...npm.problems);
  if (npm.demoInstalls !== 1) out.push(`demo-transcripts has ${npm.demoInstalls} scripts/demo npm ci steps, not 1`);
  if (!/^ {10}cache-dependency-path: scripts\/demo\/package-lock\.json$/m.test(job)) out.push('demo-transcripts does not key its npm cache on scripts/demo/package-lock.json');
  if (!/find scripts\/demo -maxdepth 1 -type f -name '\*\.test\.mjs' ! -name '\*\.e2e\.test\.mjs'/.test(job) || !/node --test "\$\{tests\[@\]\}"/.test(job)) {
    out.push('demo-transcripts does not run the pure self-tests of scripts/demo');
  }
  if (!/node scripts\/demo\/transcript\.mjs check "\$\{secret_files\[@\]\}" scripts\/demo\/sample\/sample\.transcript\.jsonl "\$\{goldens\[@\]\}"/.test(job)) {
    out.push('demo-transcripts does not check the sample and the goldens against the test keys');
  }
  if (!/find tests\/conformance\/fixtures -type f -name '\*\.test-key\.json'/.test(job) || !/secret_files\+=\(--secret-file "\$key"\)/.test(job)) {
    out.push('demo-transcripts does not pass every *.test-key.json as --secret-file');
  }
  const gate = all.get('ci-passed') ?? '';
  if (!needsOf(gate).includes('demo-transcripts')) out.push('ci-passed does not need demo-transcripts');
  if (!/^ {10}DEMO_TRANSCRIPTS: \$\{\{ needs\.demo-transcripts\.result \}\}$/m.test(gate)) out.push('ci-passed does not read the demo-transcripts result');
  if (!/^ {10}if \[ "\$DEMO_TRANSCRIPTS" != success \]; then\n {12}echo .*\n {12}exit 1\n {10}fi$/m.test(gate)) {
    out.push('ci-passed does not require demo-transcripts to succeed (a skip would pass)');
  }
  for (const [id, body] of all) {
    if (id !== 'demo-transcripts' && /scripts\/demo\/render|render\.e2e/.test(code(body).join('\n'))) out.push(`ci.yml job ${id} renders the demo: that belongs to demo.yml`);
  }
  return out;
}

export function demoProblems(demo) {
  const out = [];
  const lines = code(demo);
  const text = lines.join('\n');
  if (/pull_request_target/.test(text)) out.push('demo.yml uses pull_request_target');
  if (/\$\{\{\s*secrets\./.test(text)) out.push('demo.yml reads a secret');
  if (!/^permissions:\n {2}contents: read\n(?! )/m.test(`${text}\n`)) out.push('demo.yml top-level permissions are not exactly contents: read');
  // Every permissions block, at any level, holds contents: read and nothing else.
  for (const m of `${text}\n`.matchAll(/^( *)permissions:(.*)\n((?:\1 {2}.*\n)*)/gm)) {
    const body = m[3].split('\n').filter(Boolean).map((l) => l.trim());
    if (m[2].trim() !== '' || body.length !== 1 || body[0] !== 'contents: read') out.push(`demo.yml has a permissions block other than contents: read: ${JSON.stringify(m[0])}`);
  }
  if (!/^on:\n {2}push:\n {4}branches: \[main\]\n {2}pull_request:\n {4}paths:\n {6}- scripts\/demo\/\*\*\n {6}- tests\/demo\/\*\*\n {6}- \.github\/workflows\/demo\.yml\n {2}workflow_dispatch:\n/m.test(`${text}\n`)) {
    out.push('demo.yml triggers are not push to main, pull_request on its paths and workflow_dispatch');
  }
  const all = jobs(text);
  if (all.size === 0) out.push('demo.yml has no jobs');
  for (const [id, body] of all) {
    const npm = npmCi(body);
    out.push(...npm.problems);
    if (npm.demoInstalls === 0 && /\bnpm ci\b/.test(body)) out.push(`demo.yml job ${id} runs npm ci outside scripts/demo`);
  }
  if (!/^ {10}if-no-files-found: error$/m.test(text)) out.push('demo.yml upload does not error on no files');
  if (!/^ {10}retention-days: \$\{\{ github\.event_name == 'pull_request' && 7 \|\| 90 \}\}$/m.test(text)) out.push('demo.yml retention is not 7 days on pull requests, 90 otherwise');
  // The test keys: listed once (failing when there are none), then passed
  // to both the check and the render.
  if (
    !/find tests\/conformance\/fixtures -type f -name '\*\.test-key\.json'/.test(text) ||
    !/if \[ "\$\{#keys\[@\]\}" -eq 0 \]; then\n(?: {12}.*\n)* {12}exit 1\n/.test(text) ||
    !/printf -- '--secret-file\\0%s\\0' "\$key"; done > "\$RUNNER_TEMP\/demo-secret-files"/.test(text)
  ) {
    out.push('demo.yml does not list every *.test-key.json as --secret-file, failing when there is none');
  }
  const steps = text.split(/^(?= {6}- )/m);
  const step = (name) => steps.find((st) => st.startsWith(`      - name: ${name}\n`)) ?? '';
  const keys = / {10}mapfile -d '' secret_files < "\$RUNNER_TEMP\/demo-secret-files"\n/;
  if (!keys.test(step('Check the transcripts')) || !/^ {10}node scripts\/demo\/transcript\.mjs check "\$\{secret_files\[@\]\}" /m.test(step('Check the transcripts'))) {
    out.push('demo.yml checks the transcripts without the test keys');
  }
  if (!keys.test(step('Render the sample')) || !/^ {10}node scripts\/demo\/render\.mjs .* "\$\{secret_files\[@\]\}"$/m.test(step('Render the sample'))) {
    out.push('demo.yml renders without the test keys');
  }
  for (const name of ['End-to-end test of the renderer', 'Render the sample']) {
    if (!/^ {8}env:\n {10}DEMO_KEEP_RAW: \$\{\{ runner\.temp \}\}\/demo-raw$/m.test(step(name))) out.push(`demo.yml step "${name}" does not set DEMO_KEEP_RAW`);
  }
  const raw = step('Upload the raw recordings of failed renders');
  const rawExpected = [
    /^ {8}if: failure\(\)$/m,
    /^ {8}uses: actions\/upload-artifact@v7$/m,
    /^ {10}name: demo-raw-recordings-\$\{\{ github\.run_attempt \}\}$/m,
    /^ {10}path: \$\{\{ runner\.temp \}\}\/demo-raw$/m,
    /^ {10}retention-days: 3$/m,
    /^ {10}if-no-files-found: ignore$/m,
  ];
  if (rawExpected.some((re) => !re.test(raw))) out.push('demo.yml does not upload the raw recordings only on failure, as demo-raw-recordings-N for 3 days');
  return out;
}

describe('workflow wiring of scripts/demo', () => {
  it('ci.yml: demo-transcripts runs everywhere, and ci-passed needs it and requires success', () => {
    assert.deepEqual(ciProblems(CI), []);
  });

  it('demo.yml: read-only, no pull_request_target, no secret, npm ci --ignore-scripts', () => {
    assert.deepEqual(demoProblems(DEMO), []);
  });

  it('demo.yml is not a job of ci.yml, and ci-passed needs no demo render job', () => {
    assert.ok(!jobs(CI).has('render'));
    assert.ok(!needsOf(jobs(CI).get('ci-passed')).some((j) => /render|demo-video/.test(j)));
  });
});

describe('the wiring checks catch their mutants', () => {
  const ciMutants = [
    ['ci-passed without the need', (t) => t.replace('      - demo-transcripts\n', ''), /ci-passed does not need demo-transcripts/],
    ['ci-passed without the result', (t) => t.replace(/ {10}DEMO_TRANSCRIPTS: .*\n/, ''), /does not read the demo-transcripts result/],
    ['ci-passed without the status check', (t) => t.replace(/ {10}if \[ "\$DEMO_TRANSCRIPTS" != success \]; then\n.*\n.*\n {10}fi\n/, ''), /does not require demo-transcripts to succeed/],
    ['status check that does not exit', (t) => t.replace(/("\$DEMO_TRANSCRIPTS" != success \]; then\n.*\n) {12}exit 1\n/, '$1            true\n'), /does not require demo-transcripts to succeed/],
    ['npm ci with scripts', (t) => t.replace(/(working-directory: scripts\/demo\n {8}run: npm ci) --ignore-scripts/, '$1'), /without --ignore-scripts/],
    ['job gated on changes', (t) => t.replace('  demo-transcripts:\n    name: Demo transcripts\n', '  demo-transcripts:\n    name: Demo transcripts\n    needs: changes\n'), /must run for every change/],
    ['no secret files', (t) => t.replace('"${secret_files[@]}" ', ''), /against the test keys/],
    ['e2e in the pure run', (t) => t.replace(" ! -name '*.e2e.test.mjs'", ''), /pure self-tests/],
    ['wider permissions', (t) => t.replace('  demo-transcripts:\n    name: Demo transcripts\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n', '  demo-transcripts:\n    name: Demo transcripts\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      pull-requests: write\n'), /not permissions: contents: read/],
    ['job removed', (t) => t.replace('  demo-transcripts:\n', '  demo-transcripts-old:\n'), /no demo-transcripts job/],
    ['pull_request_target', (t) => t.replace('  pull_request:\n  workflow_dispatch:\n', '  pull_request_target:\n  workflow_dispatch:\n'), /ci\.yml uses pull_request_target/],
    ['pull_request_target added', (t) => t.replace('  workflow_dispatch:\n', '  workflow_dispatch:\n  pull_request_target:\n'), /ci\.yml uses pull_request_target/],
  ];
  for (const [name, mutate, expected] of ciMutants) {
    it(`ci.yml: ${name}`, () => {
      const mutated = mutate(CI);
      assert.notEqual(mutated, CI, 'the mutant changed nothing');
      assert.ok(ciProblems(mutated).some((p) => expected.test(p)), JSON.stringify(ciProblems(mutated)));
    });
  }

  const demoMutants = [
    ['pull_request_target', (t) => t.replace('  pull_request:\n', '  pull_request_target:\n'), /pull_request_target/],
    ['write permission at the top', (t) => t.replace('permissions:\n  contents: read\n', 'permissions:\n  contents: write\n'), /top-level permissions/],
    ['extra permission in the job', (t) => t.replace('    permissions:\n      contents: read\n', '    permissions:\n      contents: read\n      id-token: write\n'), /permissions block other than contents: read/],
    ['write-all', (t) => t.replace('    permissions:\n      contents: read\n', '    permissions: write-all\n'), /permissions block other than contents: read/],
    ['a secret', (t) => t.replace('      - name: Install demo dependencies\n', '      - name: Install demo dependencies\n        env:\n          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n'), /reads a secret/],
    ['npm ci with scripts', (t) => t.replace('run: npm ci --ignore-scripts', 'run: npm ci'), /without --ignore-scripts/],
    ['upload tolerates no files', (t) => t.replace('if-no-files-found: error', 'if-no-files-found: warn'), /error on no files/],
    ['retention', (t) => t.replace("&& 7 || 90", '&& 7 || 400'), /retention/],
    ['wider trigger', (t) => t.replace('  pull_request:\n    paths:\n', '  pull_request:\n    branches: ["**"]\n    paths:\n'), /triggers/],
    ['no test keys listed', (t) => t.replace("find tests/conformance/fixtures -type f -name '*.test-key.json'", "find tests/conformance/fixtures -type f -name '*.nothing'"), /every \*\.test-key\.json/],
    ['no keys is not a failure', (t) => t.replace(/(if \[ "\$\{#keys\[@\]\}" -eq 0 \]; then\n(?: {12}.*\n)*) {12}exit 1\n/, '$1            true\n'), /failing when there is none/],
    ['check without keys', (t) => t.replace('transcript.mjs check "${secret_files[@]}" ', 'transcript.mjs check '), /checks the transcripts without the test keys/],
    ['render without keys', (t) => t.replace(' --out "$RUNNER_TEMP/demo" "${secret_files[@]}"', ' --out "$RUNNER_TEMP/demo"'), /renders without the test keys/],
    ['e2e without DEMO_KEEP_RAW', (t) => t.replace('      - name: End-to-end test of the renderer\n        env:\n          DEMO_KEEP_RAW: ${{ runner.temp }}/demo-raw\n', '      - name: End-to-end test of the renderer\n'), /"End-to-end test of the renderer" does not set DEMO_KEEP_RAW/],
    ['render without DEMO_KEEP_RAW', (t) => t.replace(/( {6}- name: Render the sample\n {8}shell: bash\n) {8}env:\n {10}DEMO_KEEP_RAW: .*\n/, '$1'), /"Render the sample" does not set DEMO_KEEP_RAW/],
    ['raw upload always', (t) => t.replace('        if: failure()\n', ''), /raw recordings only on failure/],
    ['raw upload under the video name', (t) => t.replace('name: demo-raw-recordings-${{ github.run_attempt }}', 'name: demo-videos-${{ github.run_attempt }}'), /raw recordings only on failure/],
    ['raw upload kept long', (t) => t.replace('          retention-days: 3\n', '          retention-days: 90\n'), /raw recordings only on failure/],
    ['raw upload errors when empty', (t) => t.replace('if-no-files-found: ignore', 'if-no-files-found: error'), /raw recordings only on failure/],
  ];
  for (const [name, mutate, expected] of demoMutants) {
    it(`demo.yml: ${name}`, () => {
      const mutated = mutate(DEMO);
      assert.notEqual(mutated, DEMO, 'the mutant changed nothing');
      assert.ok(demoProblems(mutated).some((p) => expected.test(p)), JSON.stringify(demoProblems(mutated)));
    });
  }

  it('a commented-out pull_request_target or secret is not a finding', () => {
    assert.deepEqual(demoProblems(`${DEMO}# pull_request_target: ${'${{ secrets.X }}'}\n`), []);
  });
});
