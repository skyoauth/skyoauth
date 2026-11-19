// Self-test for docs-check.mjs:  node --test scripts/ci/docs-check.test.mjs
//
// Fixtures are generated into temporary directories so that no Markdown
// fixture lands under docs/. Each check has a positive case (the base
// fixture passes) and negative cases that break exactly one thing and must
// produce an error at the expected file:line.

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkDocs, findCycle, findRefs, formatAnnotation, githubSlug, MermaidError, parseFlowchart, scanFences } from './docs-check.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'docs-check.mjs');

// Runs the CLI. The output format depends on GITHUB_ACTIONS, so it is removed
// from the inherited environment unless a test sets it.
function cli(args, { env = {}, cwd } = {}) {
  const base = { ...process.env };
  delete base.GITHUB_ACTIONS;
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd, env: { ...base, ...env }, encoding: 'utf8' });
}

const DESIGN = `# Design

> Paired with [the tasks](skyoauth-tasks.md) and [their DAG](skyoauth-tasks.md#task-dag).

## 1. Summary

Scope is T00.1 and T10.1–T10.2; ADR-001 and A01 apply. See tasks §8 and design §2.

## 2. Stable compatibility contract (MUST)

| ID | Invariant |
| --- | --- |
| C01 | Stable issuer. |
| C02 | Stable clients. |

## 3. Architecture

~~~mermaid
flowchart TB
  subgraph Clients
    B[Browser / SPA library]
  end
  DB[(PostgreSQL: state)]
  U[Upstream]
  B -->|bytes| DB
  B -. metadata-only check .-> U
  U <--> DB
~~~

\`\`\`text
T99.9 ADR-999 A99 [dead](missing.md) inside a code block are ignored
\`\`\`

Back to [the summary](#1-summary).
`;

const TASKS = `# Tasks

> Paired with [the design](skyoauth-design.md#3-architecture). C01–C02 hold.

## 2. Specification

### T00 — Protocol (M0)

- [ ] **T00.1** Freeze contracts (ADR-001).
- [ ] **T00.2** Threat model; see design §3.

### T10 — Schema

- [ ] **T10.1** Migrations after T00.1–T00.2 and T00, T10.
- [ ] **T10.2** IDs per T00.1-2 and \`T10.1\`.

## 8. Conformance matrix — automated release blocking

| ID | Scenario | Expected result |
| --- | --- | --- |
| A01 | Valid push | Scoped |
| A02 | Wrong repo | Denied |

## 9. Delivery

### Task DAG

~~~mermaid
flowchart TD
    %% Milestones
    M0["M0 · T00 contracts"] --> SCHEMA["T10.1–T10.2 · schema"]
    M0 & SCHEMA --> GATE["Gate · A01–A02, C01–C02"]
    classDef gate fill:#eee
    class GATE gate
~~~

\`\`\`\`mermaid
graph LR
  X["T00.1"] -->|feeds| Y["T00.2"] --> Z["T10.2"]
  X -- also --> Z
\`\`\`\`

## 11. ADR decisions to ratify

| ADR | Decision | Proposed baseline |
| --- | --- | --- |
| ADR-001 | Issuer | One issuer |
| ADR-002 | Signer | Separate keys |

[Back](#task-dag)
`;

const roots = [];
after(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

function fixture(files = {}, { design = DESIGN, tasks = TASKS } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'docs-check-'));
  roots.push(root);
  const all = { 'docs/skyoauth-design.md': design, 'docs/skyoauth-tasks.md': tasks, ...files };
  for (const [p, text] of Object.entries(all)) {
    if (text === null) continue;
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), text);
  }
  return root;
}

// Replaces exactly one occurrence, so a fixture edit cannot silently miss.
function edit(text, from, to) {
  const i = text.indexOf(from);
  assert.ok(i >= 0, `fixture does not contain ${JSON.stringify(from)}`);
  assert.equal(text.indexOf(from, i + 1), -1, `fixture contains ${JSON.stringify(from)} more than once`);
  return text.slice(0, i) + to + text.slice(i + from.length);
}

const lineOf = (text, needle) => text.slice(0, text.indexOf(needle)).split('\n').length;

function run(opts, files) {
  return checkDocs({ root: fixture(files, opts) });
}

function expectError(result, { file, line, check, match }) {
  const hit = result.errors.find(
    (e) => e.file === file && (line === undefined || e.line === line) && e.check === check && match.test(e.msg),
  );
  assert.ok(hit, `expected ${check} error at ${file}:${line} matching ${match}; got:\n${JSON.stringify(result.errors, null, 2)}`);
}

const D = 'docs/skyoauth-design.md';
const T = 'docs/skyoauth-tasks.md';

describe('positive fixture', () => {
  test('base fixture passes with no errors or warnings', () => {
    const r = run();
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings, []);
    assert.equal(r.stats.taskGroups, 2);
    assert.equal(r.stats.subtasks, 4);
    assert.equal(r.stats.scenarios, 2);
    assert.equal(r.stats.invariants, 2);
    assert.equal(r.stats.adrs, 2);
    assert.deepEqual(r.stats.mermaid, { [D]: 1, [T]: 2 });
    assert.ok(r.stats.taskRanges >= 4);
    assert.ok(r.stats.anchors >= 4);
  });

  test('defined-but-unreferenced ADR is informational only', () => {
    const r = run();
    assert.ok(r.infos.some((i) => i.check === 'adr' && /ADR-002 is defined but never referenced/.test(i.msg)));
    assert.equal(r.errors.length, 0);
  });

  test('a tolerated extra docs file is checked best-effort without failing', () => {
    const extra = `# Threat model

Covers T00.2, T10.1–T10.2, A02, ADR-002 and ADR-003; see [protocol](skyoauth-tasks.md#t00--protocol-m0)
and [the ADR](adr/ADR-003-signer.md).

\`\`\`mermaid
sequenceDiagram
  A->>B: hi
\`\`\`
`;
    const adr = '# ADR-003: Signer custody\n\nExtends ADR-002 and T00.1.\n';
    const r = run({}, { 'docs/threat-model.md': extra, 'docs/adr/ADR-003-signer.md': adr });
    assert.deepEqual(r.errors, []);
    assert.equal(r.stats.adrs, 3);
    assert.ok(r.warnings.some((w) => w.file === 'docs/threat-model.md' && w.check === 'mermaid' && /sequenceDiagram/.test(w.msg)));
    assert.ok(r.infos.some((i) => i.file === 'docs/adr/ADR-003-signer.md' && /only by this ADR file/.test(i.msg)));
  });
});

describe('fences', () => {
  test('unclosed fence at EOF', () => {
    const tasks = `${TASKS}\n\`\`\`js\nconst x = 1;\n`;
    expectError(run({ tasks }), { file: T, line: tasks.split('\n').length - 2, check: 'fence', match: /never closed/ });
  });
  test('~~~ fence closed by ``` does not close', () => {
    const design = edit(DESIGN, 'U <--> DB\n~~~', 'U <--> DB\n```');
    expectError(run({ design }), { file: D, line: lineOf(design, '~~~mermaid'), check: 'fence', match: /cannot close it/ });
  });
  test('shorter closing fence does not close a longer opener', () => {
    const tasks = edit(TASKS, '  X -- also --> Z\n````', '  X -- also --> Z\n```');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, '````mermaid'), check: 'fence', match: /4\+ '`'/ });
  });
  test('scanFences follows CommonMark length/char rules', () => {
    const { blocks, errors } = scanFences(['````md', '```', 'x', '~~~', '`````', '```a`b```', 'text']);
    assert.deepEqual(errors, []);
    assert.equal(blocks.length, 1);
    assert.deepEqual([blocks[0].start, blocks[0].end, blocks[0].lang], [1, 5, 'md']);
    // Deliberate nesting with a longer outer fence is fine.
    assert.deepEqual(scanFences(['````md', '```js', 'x', '```', '````']).errors, []);
  });
  test('missing closer that a later fence silently re-pairs', () => {
    // Without the closer after the diagram, the ~~~json opener is content and
    // the json block's closer ends the mermaid block, so the fences balance.
    const design = edit(DESIGN, 'U <--> DB\n~~~\n', 'U <--> DB\n\n~~~json\n{}\n~~~\n');
    expectError(run({ design }), { file: D, line: lineOf(design, '~~~json'), check: 'fence', match: /block opened at line \d+; .*missing its closing fence/ });
  });
  test('extra file fences are checked too', () => {
    const r = run({}, { 'docs/contracts/wire.md': '# Wire\n\n~~~json\n{}\n' });
    expectError(r, { file: 'docs/contracts/wire.md', line: 3, check: 'fence', match: /never closed/ });
  });
  test('a fence inside an HTML comment block is not a fence', () => {
    // CommonMark HTML block (type 2): everything up to the line holding
    // "-->" is raw HTML, so this unmatched fence is invisible.
    const design = edit(DESIGN, '## 3. Architecture\n', '## 3. Architecture\n\n<!--\nOld example:\n```js\nconst x = T99.9;\n-->\n\nStill checked: T00.9.\n');
    const r = run({ design });
    assert.deepEqual(r.errors.map((e) => [e.line, e.check]), [[lineOf(design, 'Still checked'), 'task']]);
    assert.deepEqual(scanFences(['<!--', '```js', '-->', '```', 'x', '```']), {
      blocks: [{ start: 4, end: 6, char: '`', len: 3, info: '', lang: '', body: ['x'] }],
      comments: [{ start: 1, end: 3, col: 0, closeCol: 0 }],
      errors: [],
    });
    assert.deepEqual(scanFences(['> <!-- a --> ```', '```']).blocks.length, 0);
  });
  test('comment-like text inside a real fence is code', () => {
    const design = edit(DESIGN, '## 3. Architecture\n', '## 3. Architecture\n\n```html\n<!-- open\n```\n\nStill checked: T00.9.\n');
    const r = run({ design });
    assert.deepEqual(r.errors.map((e) => [e.line, e.check]), [[lineOf(design, 'Still checked'), 'task']]);
  });
  test('a fence still interrupts a paragraph with an open inline comment', () => {
    // "Text <!-- note" is a paragraph; the fence ends it, so "<!--" is shown
    // as text and the "-->" is code.
    const tasks = `${TASKS}\nText <!-- note\n\`\`\`js\n-->\n\`\`\`\nafter --> T00.9\n`;
    const r = run({ tasks });
    assert.deepEqual(r.errors.map((e) => [e.line, e.check]), [
      [lineOf(tasks, 'Text <!--'), 'comment'],
      [lineOf(tasks, 'after -->'), 'task'],
    ]);
    expectError(r, { file: T, line: lineOf(tasks, 'Text <!--'), check: 'comment', match: /not closed before its paragraph ends/ });
    // Unclosed, the fence is reported too.
    const t2 = `${TASKS}\nText <!-- note\n\`\`\`js\n-->\n`;
    expectError(run({ tasks: t2 }), { file: T, line: lineOf(t2, '```js'), check: 'fence', match: /never closed/ });
  });
});

describe('HTML comments', () => {
  test('closed comments hide references and links, inline and multi-line', () => {
    const design = edit(
      DESIGN,
      '## 3. Architecture\n',
      '## 3. Architecture\n\nKeep <!-- T99.9 [x](missing.md) --> going, <!-- ADR-999\nA99 --> done.\n\n<!--\nC99 [y](gone.md)\n\n```\n-->\n',
    );
    assert.deepEqual(run({ design }).errors, []);
  });
  test('text after a closed comment is still checked', () => {
    const design = edit(DESIGN, '## 3. Architecture\n', '## 3. Architecture\n\nText <!-- a --> T99.8 <!-- b\nc --> T99.9\n');
    const r = run({ design });
    expectError(r, { file: D, line: lineOf(design, 'T99.8'), check: 'task', match: /undefined task T99\.8/ });
    expectError(r, { file: D, line: lineOf(design, 'c --> T99.9'), check: 'task', match: /undefined task T99\.9/ });
  });
  test('text after a comment block on its closing line is checked', () => {
    const design = edit(DESIGN, '## 3. Architecture\n', '## 3. Architecture\n\n<!-- one line --> T99.7\n\n<!--\nT99.8\n--> T99.9\n');
    const r = run({ design });
    assert.deepEqual(r.errors.map((e) => [e.line, e.msg]), [
      [lineOf(design, '--> T99.7'), 'undefined task T99.7'],
      [lineOf(design, '--> T99.9'), 'undefined task T99.9'],
    ]);
    assert.deepEqual(scanFences(['  <!-- x --> ```', '```', '```']).comments, [{ start: 1, end: 1, col: 2, closeCol: 9 }]);
  });
  test('an unmatched backtick does not stop comment masking', () => {
    const design = edit(DESIGN, 'Back to [the summary](#1-summary).', 'Lone ` tick <!-- T99.9 --> then T00.9.\n\nBack to [the summary](#1-summary).');
    assert.deepEqual(run({ design }).errors.map((e) => [e.line, e.msg]), [[lineOf(design, 'Lone `'), 'undefined task T00.9']]);
  });
  test('"<!--" inside a code span does not start a comment', () => {
    const design = edit(DESIGN, 'Back to [the summary](#1-summary).', 'Write `<!--` or `` a`<!--`b `` to start a comment.\n\nBack to [the summary](#1-summary) and T00.9.');
    const r = run({ design });
    assert.deepEqual(r.errors.map((e) => [e.line, e.check, e.msg]), [[lineOf(design, 'and T00.9'), 'task', 'undefined task T00.9']]);
  });
  test('a comment opened before a code span wins over the span', () => {
    const design = edit(DESIGN, 'Back to [the summary](#1-summary).', 'x <!-- a ` T99.9 --> T00.9 ` d\n\nBack to [the summary](#1-summary).');
    const r = run({ design });
    assert.deepEqual(r.errors.map((e) => [e.line, e.msg]), [[lineOf(design, 'x <!--'), 'undefined task T00.9']]);
  });
  test('an inline comment left open is an error and hides nothing after its paragraph', () => {
    const design = edit(DESIGN, 'Back to [the summary](#1-summary).', 'Note <!-- unfinished T99.9\n\nBack to [the summary](#1-summary) and T00.9.');
    const r = run({ design });
    assert.deepEqual(r.errors.map((e) => [e.line, e.check]), [
      [lineOf(design, 'Note <!--'), 'comment'],
      [lineOf(design, 'and T00.9'), 'task'],
    ]);
    expectError(r, { file: D, line: lineOf(design, 'Note <!--'), check: 'comment', match: /Markdown shows it as text/ });
  });
  test('an inline comment open at end of file is an error', () => {
    const tasks = `${TASKS}\nTrailing <!-- note`;
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, 'Trailing'), check: 'comment', match: /not closed/ });
  });
  test('a comment block open at end of file is an error', () => {
    const tasks = `${TASKS}\n<!--\nT99.9 hidden\n`;
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, '<!--\nT99.9'), check: 'comment', match: /never closed.*hides the rest of the file/ });
  });
});

describe('task IDs', () => {
  test('undefined subtask reference', () => {
    const design = edit(DESIGN, 'Scope is T00.1', 'Scope is T00.3');
    expectError(run({ design }), { file: D, line: lineOf(design, 'Scope is'), check: 'task', match: /undefined task T00\.3/ });
  });
  test('range whose end is undefined (en dash)', () => {
    const tasks = edit(TASKS, 'after T00.1–T00.2', 'after T00.1–T00.3');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, 'after T00'), check: 'task', match: /range 'T00\.1–T00\.3' includes undefined task T00\.3/ });
  });
  test('range whose end is undefined (hyphen, abbreviated)', () => {
    const tasks = edit(TASKS, 'IDs per T00.1-2', 'IDs per T00.1-3');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, 'IDs per'), check: 'task', match: /T00\.3/ });
  });
  test('reversed range', () => {
    const tasks = edit(TASKS, 'after T00.1–T00.2', 'after T00.2–T00.1');
    expectError(run({ tasks }), { file: T, check: 'task', match: /end is not after its start/ });
  });
  test('subtask range across groups', () => {
    const tasks = edit(TASKS, 'after T00.1–T00.2', 'after T00.1–T10.2');
    expectError(run({ tasks }), { file: T, check: 'task', match: /spans two task groups/ });
  });
  test('group range over an undefined group', () => {
    const tasks = edit(TASKS, 'and T00, T10.', 'and T00–T10.');
    expectError(run({ tasks }), { file: T, check: 'task', match: /range 'T00–T10' includes undefined task T01, .*T09$/ });
  });
  test('undefined task in a Mermaid node label', () => {
    const tasks = edit(TASKS, 'SCHEMA["T10.1–T10.2 · schema"]', 'SCHEMA["T10.1–T10.4 · schema"]');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, 'SCHEMA["T10.1–T10.4'), check: 'task', match: /T10\.3, T10\.4/ });
  });
  test('duplicate subtask definition', () => {
    const tasks = edit(TASKS, '- [ ] **T10.2** IDs', '- [ ] **T10.1** IDs');
    expectError(run({ tasks }), { file: T, check: 'task', match: /T10\.1 is defined more than once/ });
  });
  test('numbering gap', () => {
    const tasks = edit(edit(TASKS, '- [ ] **T10.2** IDs', '- [ ] **T10.3** IDs'), 'T10.1–T10.2 · schema', 'T10.1 · schema');
    expectError(run({ tasks }), { file: T, check: 'task', match: /T10\.2 is missing/ });
  });
  test('subtask under the wrong heading', () => {
    const tasks = edit(TASKS, '- [ ] **T00.2** Threat', '- [ ] **T10.3** Threat');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, '**T10.3**'), check: 'task', match: /listed under ### T00/ });
  });
  test('subtask out of order', () => {
    const tasks = edit(TASKS, '- [ ] **T10.1** Migrations after T00.1–T00.2 and T00, T10.\n- [ ] **T10.2** IDs per T00.1-2 and `T10.1`.', '- [ ] **T10.2** IDs per T00.1-2 and `T10.1`.\n- [ ] **T10.1** Migrations after T00.1–T00.2 and T00, T10.');
    const r = run({ tasks });
    assert.deepEqual(r.errors.map((e) => [e.line, e.msg]), [[lineOf(tasks, '**T10.1** Migrations'), 'T10.1 is out of order after T10.2']]);
  });
  test('subtasks without a group heading', () => {
    const tasks = edit(TASKS, '### T10 — Schema\n', '### Schema\n');
    const r = run({ tasks });
    expectError(r, { file: T, line: lineOf(tasks, '**T10.1**'), check: 'task', match: /^subtasks of T10 have no "### T10" heading$/ });
    expectError(r, { file: T, line: lineOf(tasks, '**T10.1**'), check: 'task', match: /T10\.1 is listed under no task heading, not ### T10/ });
  });
  test('a level-4 heading does not end a task group', () => {
    const tasks = edit(TASKS, '- [ ] **T10.2** IDs', '#### Notes\n\n- [ ] **T10.2** IDs');
    assert.deepEqual(run({ tasks }).errors, []);
    const t2 = edit(TASKS, '- [ ] **T10.2** IDs', '### Notes\n\n- [ ] **T10.2** IDs');
    expectError(run({ tasks: t2 }), { file: T, line: lineOf(t2, '**T10.2**'), check: 'task', match: /listed under no task heading/ });
  });
  test('malformed checkbox task IDs', () => {
    for (const bad of ['**T1.2**', '**T10.2a**', '**T10.** ', '**T10**']) {
      const tasks = edit(TASKS, '**T10.2** IDs', `${bad} IDs`);
      const r = run({ tasks });
      expectError(r, { file: T, line: lineOf(tasks, `${bad} IDs`), check: 'task', match: /^malformed task checkbox ID \(expected \*\*Tgg\.n\*\*\)$/ });
    }
    // Prose that merely starts with a bold task ID outside a checkbox is fine.
    assert.deepEqual(run({ tasks: edit(TASKS, '## 9. Delivery\n', '## 9. Delivery\n\n**T10.2** is last.\n') }).errors, []);
  });
  test('subtask ID with a leading zero', () => {
    const tasks = edit(TASKS, '- [ ] **T10.2** IDs', '- [ ] **T10.02** IDs');
    const r = run({ tasks });
    assert.deepEqual(r.errors.map((e) => [e.line, e.msg]), [[lineOf(tasks, '**T10.02**'), 'task ID T10.02 has a leading zero (write T10.2)']]);
  });
  test('range mixing a task group and a subtask', () => {
    for (const range of ['T00–T10.1', 'T00.1–T10']) {
      const tasks = edit(TASKS, 'and T00, T10.', `and ${range}.`);
      expectError(run({ tasks }), { file: T, line: lineOf(tasks, range), check: 'task', match: new RegExp(`task range '${range}': range mixes a task group and a subtask`) });
    }
  });
  test('reversed and empty ranges of every kind', () => {
    const cases = [
      ['and T00, T10.', 'and T10–T00.', 'task', /task range 'T10–T00': range end is not after its start/],
      ['and T00, T10.', 'and T10–T10.', 'task', /range end is not after its start/],
      ['IDs per T00.1-2', 'IDs per T00.2-2', 'task', /range end is not after its start/],
      ['Gate · A01–A02', 'Gate · A02–A01', 'scenario', /scenario range 'A02–A01': range end is not after its start/],
      ['Gate · A01–A02', 'Gate · A01–A01', 'scenario', /scenario range 'A01–A01': range end is not after its start/],
      ['C01–C02 hold', 'C02–C01 hold', 'invariant', /compatibility invariant range 'C02–C01'/],
      ['Freeze contracts (ADR-001)', 'Freeze contracts (ADR-002–001)', 'adr', /ADR range 'ADR-002–001'/],
    ];
    for (const [from, to, check, match] of cases) {
      const tasks = edit(TASKS, from, to);
      expectError(run({ tasks }), { file: T, line: lineOf(tasks, to), check, match });
    }
  });
  test('an extra file cannot define tasks', () => {
    const r = run({}, { 'docs/notes.md': '# Notes\n\n### T30 — Sessions\n\n- [ ] **T30.1** x\n\nSee T30.1.\n' });
    expectError(r, { file: 'docs/notes.md', line: 7, check: 'task', match: /undefined task T30\.1/ });
  });
  test('findRefs ranges and boundaries', () => {
    const keys = (s) => findRefs('task', s).map((r) => r.keys.join(','));
    assert.deepEqual(keys('T13.1–T13.3 and T14.1-T14.2'), ['T13.1,T13.2,T13.3', 'T14.1,T14.2']);
    assert.deepEqual(keys('T10–T12'), ['T10,T11,T12']);
    assert.deepEqual(keys("T23.7's case, T32.3/T50.4, T13.10."), ['T23.7', 'T32.3', 'T50.4', 'T13.10']);
    assert.deepEqual(keys('XT10 T30s RT10.1 T1'), []);
    assert.deepEqual(findRefs('scenario', 'A01–A64 and A58').map((r) => r.keys.length), [64, 1]);
    assert.deepEqual(findRefs('adr', 'ADR-009, ADR-0010').map((r) => r.keys[0]), ['ADR-009', 'ADR-010']);
  });
});

describe('ADRs', () => {
  test('reference to an ADR missing from the table', () => {
    const design = edit(DESIGN, 'ADR-001 and A01', 'ADR-007 and A01');
    expectError(run({ design }), { file: D, line: lineOf(design, 'ADR-007'), check: 'adr', match: /undefined ADR ADR-007/ });
  });
  test('duplicate ADR row', () => {
    const tasks = edit(TASKS, '| ADR-002 | Signer', '| ADR-001 | Signer');
    expectError(run({ tasks }), { file: T, check: 'adr', match: /ADR-001 is defined more than once/ });
  });
  test('missing §11 ADR table', () => {
    const tasks = edit(TASKS, '## 11. ADR decisions to ratify', '## 11. Decisions');
    expectError(run({ tasks }), { file: T, check: 'adr', match: /no section heading/ });
  });
  test('ADR file whose name and title disagree', () => {
    const r = run({}, { 'docs/adr/ADR-004-x.md': '# ADR-005: X\n' });
    expectError(r, { file: 'docs/adr/ADR-004-x.md', line: 1, check: 'adr', match: /file name says ADR-004 but title says ADR-005/ });
  });
  test('two ADR files for the same number', () => {
    const r = run({}, { 'docs/adr/0003-a.md': '# Signer\n', 'docs/adr/ADR-003-b.md': 'No title.\n' });
    assert.deepEqual(r.errors, [{ file: 'docs/adr/ADR-003-b.md', line: 1, check: 'adr', msg: 'ADR-003 is also defined by docs/adr/0003-a.md' }]);
    assert.equal(r.stats.adrs, 3);
  });
  test('ADR table numbering gap and out-of-order rows', () => {
    const tasks = edit(TASKS, '| ADR-002 | Signer', '| ADR-004 | Signer');
    const r = run({ tasks });
    assert.deepEqual(r.errors, []);
    assert.deepEqual(r.warnings.map((w) => [w.line, w.check, w.msg]), [
      [lineOf(TASKS, '## 11.'), 'adr', 'ADR-002 is missing from the ADR table (rows run up to ADR-004)'],
      [lineOf(TASKS, '## 11.'), 'adr', 'ADR-003 is missing from the ADR table (rows run up to ADR-004)'],
    ]);
    const t2 = edit(TASKS, '| ADR-001 | Issuer | One issuer |\n| ADR-002 | Signer | Separate keys |', '| ADR-002 | Signer | Separate keys |\n| ADR-001 | Issuer | One issuer |');
    expectError(run({ tasks: t2 }), { file: T, line: lineOf(t2, '| ADR-001 |'), check: 'adr', match: /^ADR-001 is out of order in the ADR table \(after ADR-002\)$/ });
  });
  test('an ADR table with no rows', () => {
    const tasks = edit(TASKS, '| ADR-001 | Issuer | One issuer |\n| ADR-002 | Signer | Separate keys |\n', '');
    expectError(run({ tasks }), { file: T, line: lineOf(TASKS, '## 11.'), check: 'adr', match: /ADR table under "11\. ADR decisions to ratify" has no rows/ });
  });
});

describe('table sections', () => {
  test('extra headings that mention ADRs, the matrix or the contract do not move the tables', () => {
    const tasks = edit(
      TASKS,
      '## 8. Conformance matrix',
      '### Where the conformance matrix lives\n\nBelow.\n\n#### ADR-002 notes\n\nNotes.\n\n#### Conformance matrix\n\n| A09 | x | y |\n\n## 8. Conformance matrix',
    );
    const design = edit(DESIGN, '## 2. Stable compatibility contract', '### Compatibility contract notes\n\n| C09 | x |\n\n## 2. Stable compatibility contract');
    const r = run({ tasks, design });
    // The stray rows are references to undefined IDs, nothing else.
    assert.deepEqual(r.errors.map((e) => [e.file, e.line, e.msg]), [
      [D, lineOf(design, '| C09 |'), 'undefined compatibility invariant C09'],
      [T, lineOf(tasks, '| A09 |'), 'undefined scenario A09'],
    ]);
    assert.deepEqual([r.stats.adrs, r.stats.scenarios, r.stats.invariants], [2, 2, 2]);
  });
  test('the table sections must be numbered headings', () => {
    const tasks = edit(TASKS, '## 8. Conformance matrix', '## Conformance matrix');
    expectError(run({ tasks }), { file: T, line: 0, check: 'scenario', match: /no section heading matching/ });
    const design = edit(DESIGN, '## 2. Stable compatibility contract', '## Stable compatibility contract');
    expectError(run({ design }), { file: D, line: 0, check: 'invariant', match: /no section heading matching/ });
  });
  test('two numbered headings for one table are an error', () => {
    const tasks = `${TASKS}\n## 12. ADR decisions, continued\n\n| ADR-003 | x | y |\n`;
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, '## 12.'), check: 'adr', match: /second section heading for the ADR table/ });
  });
});

describe('conformance scenarios and invariants', () => {
  test('gap in the A-ID table', () => {
    const tasks = edit(TASKS, '| A02 | Wrong repo', '| A03 | Wrong repo');
    expectError(run({ tasks }), { file: T, check: 'scenario', match: /A02 is missing from the conformance matrix/ });
  });
  test('duplicate A-ID row', () => {
    const tasks = edit(TASKS, '| A02 | Wrong repo', '| A01 | Wrong repo');
    expectError(run({ tasks }), { file: T, check: 'scenario', match: /A01 is defined more than once/ });
  });
  test('A-ID reference outside the table', () => {
    const design = edit(DESIGN, 'ADR-001 and A01', 'ADR-001 and A03');
    expectError(run({ design }), { file: D, line: lineOf(design, 'and A03'), check: 'scenario', match: /undefined scenario A03/ });
  });
  test('A-ID range in a Mermaid label beyond the table', () => {
    const tasks = edit(TASKS, 'Gate · A01–A02', 'Gate · A01–A64');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, 'Gate · A01–A64'), check: 'scenario', match: /A03.*A64/ });
  });
  test('A-ID rows out of order', () => {
    const tasks = edit(TASKS, '| A01 | Valid push | Scoped |\n| A02 | Wrong repo | Denied |', '| A02 | Wrong repo | Denied |\n| A01 | Valid push | Scoped |');
    expectError(run({ tasks }), { file: T, check: 'scenario', match: /A01 is out of order/ });
  });
  test('C-ID reference beyond the design table', () => {
    const tasks = edit(TASKS, 'C01–C02 hold', 'C01–C03 hold');
    expectError(run({ tasks }), { file: T, line: 3, check: 'invariant', match: /C03/ });
  });
});

describe('mermaid', () => {
  test('cycle in a task DAG', () => {
    const tasks = edit(TASKS, '    classDef gate', '    GATE --> M0\n    classDef gate');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, '~~~mermaid'), check: 'mermaid', match: /cycle: .*GATE --> M0/ });
  });
  test('edge to an undefined node in a task DAG', () => {
    const tasks = edit(TASKS, '    classDef gate', '    GATE --> RELEASE\n    classDef gate');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, 'GATE --> RELEASE'), check: 'mermaid', match: /'RELEASE' is used but has no labelled definition/ });
  });
  test('class statement naming an undefined node', () => {
    const tasks = edit(TASKS, 'class GATE gate', 'class GATES gate');
    expectError(run({ tasks }), { file: T, check: 'mermaid', match: /'GATES' is used/ });
  });
  test('syntax error', () => {
    const tasks = edit(TASKS, '--> SCHEMA["T10.1–T10.2 · schema"]', '--> SCHEMA[["T10.1–T10.2 · schema"]');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, 'SCHEMA[['), check: 'mermaid', match: /expected '\]\]'/ });
  });
  test('unknown link syntax', () => {
    const tasks = edit(TASKS, 'X["T00.1"] -->|feeds|', 'X["T00.1"] ->|feeds|');
    expectError(run({ tasks }), { file: T, line: lineOf(tasks, '->|feeds|'), check: 'mermaid', match: /expected a link/ });
  });
  test('conflicting labels for one node', () => {
    const tasks = edit(TASKS, '    classDef gate', '    M0["M0 · other"] --> GATE\n    classDef gate');
    expectError(run({ tasks }), { file: T, check: 'mermaid', match: /'M0' redefined with a different label/ });
  });
  test('unclosed subgraph in the design diagram', () => {
    const design = edit(DESIGN, '    B[Browser / SPA library]\n  end\n', '    B[Browser / SPA library]\n');
    expectError(run({ design }), { file: D, line: lineOf(design, 'subgraph Clients'), check: 'mermaid', match: /never closed/ });
  });
  test('unsupported diagram type is an error in a spec', () => {
    const design = edit(DESIGN, 'flowchart TB\n  subgraph', 'sequenceDiagram\n  subgraph');
    expectError(run({ design }), { file: D, check: 'mermaid', match: /unsupported diagram type 'sequenceDiagram'/ });
  });
  test('design diagram is parsed but not cycle-checked', () => {
    // U <--> DB is a two-node cycle and B, DB, U are fine as undirected-ish
    // architecture; only the tasks spec carries DAG rules.
    assert.deepEqual(run().errors, []);
  });
  test('parseFlowchart subset', () => {
    const g = parseFlowchart(
      [
        'flowchart LR',
        '  %% comment',
        '  subgraph S["Group"]',
        '    direction TB',
        '    A["a"] & B(b) --> C{c} -.-> D[(d)]',
        '  end',
        '  D ==>|x| E([e]) --- F[[f]]',
        '  E -- text --> F;  F --o G>g]',
        '  style A fill:#fff',
        '  click A href "https://example.com"',
        '  linkStyle 0 stroke:#000',
      ],
      10,
    );
    assert.deepEqual([...g.used.keys()].sort(), ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'S']);
    assert.equal(g.edges.length, 7);
    assert.deepEqual(
      g.edges.map((e) => `${e.from}${e.directed ? '>' : '-'}${e.to}:${e.line}`),
      ['A>C:14', 'B>C:14', 'C>D:14', 'D>E:16', 'E-F:16', 'E>F:17', 'F-G:17'],
    );
    assert.equal(findCycle(g), null);
    assert.deepEqual(findCycle(parseFlowchart(['graph TD', 'a["a"] --> b["b"] --> c["c"] --> a'])), ['a', 'b', 'c', 'a']);
    for (const bad of [['flowchart XY'], ['flowchart TD', 'end'], ['flowchart TD', 'A["x" --> B'], ['flowchart TD', 'A --> '], ['flowchart TD', 'A -> B'], ['flowchart TD', 'A[x(y)] --> B']]) {
      assert.throws(() => parseFlowchart(bad), MermaidError, bad.join('\\n'));
    }
  });
  test('a header ending in ";" keeps the semicolon out of the direction', () => {
    // Checked against mermaid 12.2.0: it accepts the first three and rejects
    // the rest.
    assert.equal(parseFlowchart(['flowchart TD;', 'A["a"] --> B["b"]']).direction, 'TD');
    assert.equal(parseFlowchart(['graph LR;', 'A["a"] --> B["b"]']).direction, 'LR');
    assert.equal(parseFlowchart(['graph TD;;', 'A["a"] --> B["b"]']).direction, 'TD');
    assert.throws(() => parseFlowchart(['flowchart XY;']), /invalid flowchart direction 'XY'$/);
    for (const bad of ['graph ;', 'flowchart;', 'flowchart TD ;']) {
      assert.throws(() => parseFlowchart([bad]), new RegExp(`: invalid flowchart header '${bad}'$`));
    }
    const tasks = edit(TASKS, 'flowchart TD\n    %% Milestones', 'flowchart TD;\n    %% Milestones');
    assert.deepEqual(run({ tasks }).errors, []);
  });
  test('undirected link in a task DAG', () => {
    const tasks = edit(TASKS, '    classDef gate', '    SCHEMA --- GATE\n    classDef gate');
    const r = run({ tasks });
    expectError(r, { file: T, line: lineOf(tasks, 'SCHEMA --- GATE'), check: 'mermaid', match: /undirected link SCHEMA --- GATE in a task DAG/ });
    // The design diagram is not a task DAG: its undirected links are fine.
    assert.deepEqual(run({ design: edit(DESIGN, 'U <--> DB', 'U --- DB') }).errors, []);
  });
  test('"%%" comment lines are not scanned for references', () => {
    const tasks = edit(TASKS, '    %% Milestones', '    %% Milestones T99.9 A99 ADR-999');
    assert.deepEqual(run({ tasks }).errors, []);
    // Only whole-line comments are stripped; a label is still checked.
    const t2 = edit(TASKS, '    %% Milestones', '    %% Milestones\n    Q["T99.9"] --> GATE');
    expectError(run({ tasks: t2 }), { file: T, line: lineOf(t2, 'Q["T99.9"]'), check: 'task', match: /undefined task T99\.9/ });
  });
  test('an internal error in the Mermaid parser is not reported as a docs error', () => {
    const root = fixture();
    const boom = () => {
      throw new TypeError('boom');
    };
    assert.throws(() => checkDocs({ root, parseMermaid: boom }), /boom/);
    const bad = () => {
      throw new MermaidError(7, 'nope');
    };
    const r = checkDocs({ root, parseMermaid: bad });
    assert.equal(r.errors.filter((e) => e.check === 'mermaid' && e.msg === 'nope' && e.line === 7).length, 3);
  });
});

describe('links and anchors', () => {
  test('missing link target', () => {
    const design = edit(DESIGN, '[the tasks](skyoauth-tasks.md)', '[the tasks](skyoauth-task.md)');
    expectError(run({ design }), { file: D, line: 3, check: 'link', match: /'skyoauth-task\.md' does not exist/ });
  });
  test('missing cross-file anchor', () => {
    const tasks = edit(TASKS, 'skyoauth-design.md#3-architecture', 'skyoauth-design.md#3-architectures');
    expectError(run({ tasks }), { file: T, line: 3, check: 'link', match: /anchor '#3-architectures' not found in docs\/skyoauth-design\.md/ });
  });
  test('wrong-case anchor gets a hint', () => {
    const design = edit(DESIGN, '(#1-summary)', '(#1-Summary)');
    expectError(run({ design }), { file: D, check: 'link', match: /did you mean '#1-summary'/ });
  });
  test('same-file anchor and duplicate-heading suffixes', () => {
    const extra = '# Notes\n\n## Same\n\n## Same\n\n[one](#same) [two](#same-1) [three](#same-2)\n';
    const r = run({}, { 'docs/notes.md': extra });
    assert.equal(r.errors.length, 1);
    expectError(r, { file: 'docs/notes.md', line: 7, check: 'link', match: /'#same-2'/ });
  });
  test('link to a file outside docs that is not tracked', () => {
    const root = fixture();
    execFileSync('git', ['init', '-q', root], { stdio: 'ignore' });
    writeFileSync(join(root, 'README.md'), '# r\n');
    writeFileSync(join(root, 'docs', 'untracked.md'), '# u\n\nT99.1 [x](nowhere.md)\n');
    const design = edit(DESIGN, '[the tasks](skyoauth-tasks.md)', '[readme](../README.md)');
    writeFileSync(join(root, 'docs', 'skyoauth-design.md'), design);
    execFileSync('git', ['-C', root, 'add', 'docs/skyoauth-design.md', 'docs/skyoauth-tasks.md']);
    const r = checkDocs({ root });
    // README.md exists but is untracked; docs/untracked.md is not scanned.
    assert.deepEqual(r.stats.files, ['docs/skyoauth-design.md', 'docs/skyoauth-tasks.md']);
    expectError(r, { file: D, line: 3, check: 'link', match: /'\.\.\/README\.md' does not exist as a git-tracked file/ });
    assert.equal(r.errors.length, 1);
    execFileSync('git', ['-C', root, 'add', 'README.md']);
    assert.deepEqual(checkDocs({ root }).errors, []);
  });
  test('reference links need a definition', () => {
    const design = edit(DESIGN, 'Back to [the summary](#1-summary).', 'See [the tasks][tasks], [Tasks][] and [the plan][plan].\n\n[tasks]: skyoauth-tasks.md#task-dag');
    const r = run({ design });
    assert.deepEqual(r.errors.map((e) => [e.line, e.check, e.msg]), [[lineOf(design, 'See [the tasks]'), 'link', 'reference link [plan] has no definition']]);
    // The definition's target is itself checked.
    const d2 = edit(design, '[tasks]: skyoauth-tasks.md#task-dag', '[tasks]: skyoauth-tasks.md#no-such\n[plan]: plan.md');
    const r2 = run({ design: d2 });
    expectError(r2, { file: D, line: lineOf(d2, '[tasks]: '), check: 'link', match: /anchor '#no-such' not found/ });
    expectError(r2, { file: D, line: lineOf(d2, '[plan]: '), check: 'link', match: /'plan\.md' does not exist/ });
  });
  test('a link leaving the repository', () => {
    for (const target of ['../../outside.md', '/../outside.md']) {
      const design = edit(DESIGN, '[the tasks](skyoauth-tasks.md)', `[out](${target})`);
      expectError(run({ design }), { file: D, line: 3, check: 'link', match: new RegExp(`^link '${target.replace(/\./g, '\\.')}' leaves the repository$`) });
    }
    // A root-relative link resolves against the repository root.
    const design = edit(DESIGN, '[the tasks](skyoauth-tasks.md)', '[the tasks](/docs/skyoauth-tasks.md#task-dag)');
    assert.deepEqual(run({ design }).errors, []);
  });
  test('a malformed link target', () => {
    const design = edit(DESIGN, '[the tasks](skyoauth-tasks.md)', '[the tasks](skyoauth-%E0%A4%A.md)');
    expectError(run({ design }), { file: D, line: 3, check: 'link', match: /^malformed link target 'skyoauth-%E0%A4%A\.md'$/ });
    // Percent-encoded paths that do decode are resolved.
    const d2 = edit(DESIGN, '[the tasks](skyoauth-tasks.md)', '[the tasks](skyoauth%2Dtasks.md)');
    assert.deepEqual(run({ design: d2 }).errors, []);
  });
  test('links inside code spans are not checked', () => {
    const design = edit(DESIGN, 'Back to [the summary](#1-summary).', 'Write `[x](missing.md)` or ``[y][nolabel]`` literally.\n\nBack to [the summary](#1-summary).');
    assert.deepEqual(run({ design }).errors, []);
  });
  test('setext headings are anchors and numbered sections', () => {
    const design = edit(
      DESIGN,
      'Back to [the summary](#1-summary).',
      'Back to [the summary](#1-summary).\n\nSetext title\n============\n\nSee [it](#setext-title) and [sub](#setext-sub).\n\nSetext sub\n----------\n',
    );
    assert.deepEqual(run({ design }).errors, []);
    const d2 = edit(design, '[sub](#setext-sub)', '[sub](#setext-subs)');
    expectError(run({ design: d2 }), { file: D, check: 'link', match: /anchor '#setext-subs' not found/ });
  });
  test('githubSlug matches GitHub', () => {
    assert.equal(githubSlug('T00 — Protocol and threat model (M0)'), 't00--protocol-and-threat-model-m0');
    assert.equal(githubSlug('5.2.1 Match the browser approval to the initiating CLI'), '521-match-the-browser-approval-to-the-initiating-cli');
    assert.equal(githubSlug('2. Stable compatibility contract (MUST)'), '2-stable-compatibility-contract-must');
    assert.equal(githubSlug('Use `route_control` and [links](x.md)'), 'use-route_control-and-links');
  });
});

describe('section references', () => {
  test('explicit reference to a missing section', () => {
    const design = edit(DESIGN, 'See tasks §8', 'See tasks §7');
    expectError(run({ design }), { file: D, line: lineOf(design, 'tasks §7'), check: 'section', match: /'tasks §7' names no numbered section/ });
  });
  test('bare reference only resolving in the other spec is informational', () => {
    const tasks = edit(TASKS, 'Threat model; see design §3.', 'Threat model; see §3.');
    const r = run({ tasks });
    assert.deepEqual(r.errors, []);
    assert.ok(r.infos.some((i) => i.check === 'section' && i.file === T && /bare '§3'/.test(i.msg)));
  });
});

describe('command line', () => {
  test('exit 0 and a summary on success, from any cwd', () => {
    const root = fixture();
    const p = cli(['--root', root], { cwd: tmpdir() });
    assert.equal(p.status, 0, p.stdout + p.stderr);
    assert.match(p.stdout, /tasks: 2 groups, 4 subtasks/);
    assert.match(p.stdout, /\nOK \(0 warning\(s\)\)/);
    assert.doesNotMatch(p.stdout, /^::/m);
  });
  test('exit 1 with file:line messages on failure', () => {
    const root = fixture({}, { tasks: edit(TASKS, 'after T00.1–T00.2', 'after T00.1–T00.9') });
    const p = cli([`--root=${root}`], { cwd: tmpdir() });
    assert.equal(p.status, 1, p.stdout + p.stderr);
    assert.match(p.stdout, /^docs\/skyoauth-tasks\.md:\d+: error \[task\] range 'T00\.1–T00\.9' includes undefined task T00\.3/m);
    assert.match(p.stdout, /FAILED: 1 error/);
  });
  test('missing spec fails', () => {
    const root = fixture({ 'docs/skyoauth-design.md': null });
    const p = cli(['--root', root]);
    assert.equal(p.status, 1);
    assert.match(p.stdout, /docs\/skyoauth-design\.md: error \[files\] spec is missing/);
  });
  test('--root without a value exits 2 instead of checking the default root', () => {
    for (const args of [['--root'], ['--root='], ['--verbose', '--root']]) {
      const p = cli(args);
      assert.equal(p.status, 2, `${args.join(' ')}: ${p.stdout}${p.stderr}`);
      assert.match(p.stderr, /--root needs a directory/);
      assert.equal(p.stdout, '');
    }
  });
  test('an internal crash (--root naming a file) exits 2', () => {
    const root = fixture();
    const p = cli(['--root', join(root, 'docs', 'skyoauth-tasks.md')]);
    assert.equal(p.status, 2, p.stdout + p.stderr);
    assert.match(p.stderr, /ENOTDIR/);
  });
  test('in GitHub Actions, diagnostics and ADR notes are annotations and still exit 0', () => {
    // ADR-002 is missing from the table (a numbering gap), ADR-003 is never
    // referenced, and ADR-004 exists only as a file (a missing row).
    const tasks = edit(TASKS, '| ADR-002 | Signer', '| ADR-003 | Signer');
    const root = fixture({ 'docs/adr/ADR-004-x.md': '# ADR-004: X\n' }, { tasks: edit(tasks, 'Threat model; see design §3.', 'Threat model; see §3.') });
    const table = lineOf(TASKS, '## 11. ADR decisions');
    const local = cli(['--root', root, '--verbose']);
    assert.equal(local.status, 0, local.stdout + local.stderr);
    assert.doesNotMatch(local.stdout, /^::/m);
    assert.match(local.stdout, new RegExp(`^docs/skyoauth-tasks\\.md:${table}: warning \\[adr\\] ADR-002 is missing from the ADR table`, 'm'));

    const p = cli(['--root', root], { env: { GITHUB_ACTIONS: 'true' } });
    assert.equal(p.status, 0, p.stdout + p.stderr);
    const ann = p.stdout.split('\n').filter((l) => l.startsWith('::'));
    assert.deepEqual(ann, [
      `::warning file=docs/skyoauth-tasks.md,line=${table},title=docs-check [adr]::docs/skyoauth-tasks.md:${table}: warning [adr] ADR-002 is missing from the ADR table (rows run up to ADR-003)`,
      `::warning file=docs/adr/ADR-004-x.md,line=1,title=docs-check [adr]::docs/adr/ADR-004-x.md:1: info [adr] ADR-004 is defined but never referenced`,
      `::warning file=docs/adr/ADR-004-x.md,line=1,title=docs-check [adr]::docs/adr/ADR-004-x.md:1: info [adr] ADR-004 is defined only by this ADR file, not the tasks §11 table`,
      `::warning file=docs/skyoauth-tasks.md,line=${lineOf(tasks, '| ADR-003 |')},title=docs-check [adr]::docs/skyoauth-tasks.md:${lineOf(tasks, '| ADR-003 |')}: info [adr] ADR-003 is defined but never referenced`,
    ]);
    // The bare-§ note is not an ADR note: it stays a counted info line.
    assert.match(p.stdout, /\(1 info notes; rerun with --verbose to list them\)/);
    assert.match(p.stdout, /\nOK \(1 warning\(s\)\)/);
  });
  test('in GitHub Actions, errors are ::error annotations and exit 1', () => {
    const root = fixture({}, { tasks: edit(TASKS, 'after T00.1–T00.2', 'after T00.1–T00.9') });
    const p = cli(['--root', root], { env: { GITHUB_ACTIONS: 'true' } });
    assert.equal(p.status, 1, p.stdout + p.stderr);
    const line = lineOf(TASKS, 'after T00.1');
    assert.match(
      p.stdout,
      new RegExp(`^::error file=docs/skyoauth-tasks\\.md,line=${line},title=docs-check \\[task\\]::docs/skyoauth-tasks\\.md:${line}: error \\[task\\] range 'T00\\.1–T00\\.9'`, 'm'),
    );
  });
  test('formatAnnotation escapes workflow-command metacharacters', () => {
    assert.equal(
      formatAnnotation('warning', { file: 'docs/a,b:c.md', line: 0, check: 'x', msg: '50% done\r\nnext' }),
      '::warning file=docs/a%2Cb%3Ac.md,title=docs-check [x]::docs/a,b:c.md: warning [x] 50%25 done%0D%0Anext',
    );
  });
  test('runs when invoked through a symlinked path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'docs-check-link-'));
    roots.push(dir);
    symlinkSync(dirname(SCRIPT), join(dir, 'ci'));
    const root = fixture({}, { tasks: edit(TASKS, 'after T00.1–T00.2', 'after T00.1–T00.9') });
    const env = { ...process.env };
    delete env.GITHUB_ACTIONS;
    const p = spawnSync(process.execPath, [join(dir, 'ci', 'docs-check.mjs'), '--root', root], { env, encoding: 'utf8' });
    assert.equal(p.status, 1, p.stdout + p.stderr);
    assert.match(p.stdout, /FAILED: 1 error/);
  });
  test('unknown argument exits 2', () => {
    const p = cli(['--bogus']);
    assert.equal(p.status, 2);
  });
});
