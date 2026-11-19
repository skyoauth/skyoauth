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

import { checkDocs, findCycle, findRefs, githubSlug, MermaidError, parseFlowchart, scanFences } from './docs-check.mjs';

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), 'docs-check.mjs');

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
    const p = spawnSync(process.execPath, [SCRIPT, '--root', root], { cwd: tmpdir(), encoding: 'utf8' });
    assert.equal(p.status, 0, p.stdout + p.stderr);
    assert.match(p.stdout, /tasks: 2 groups, 4 subtasks/);
    assert.match(p.stdout, /\nOK \(0 warning\(s\)\)/);
  });
  test('exit 1 with file:line messages on failure', () => {
    const root = fixture({}, { tasks: edit(TASKS, 'after T00.1–T00.2', 'after T00.1–T00.9') });
    const p = spawnSync(process.execPath, [SCRIPT, `--root=${root}`], { cwd: tmpdir(), encoding: 'utf8' });
    assert.equal(p.status, 1, p.stdout + p.stderr);
    assert.match(p.stdout, /^docs\/skyoauth-tasks\.md:\d+: error \[task\] range 'T00\.1–T00\.9' includes undefined task T00\.3/m);
    assert.match(p.stdout, /FAILED: 1 error/);
  });
  test('missing spec fails', () => {
    const root = fixture({ 'docs/skyoauth-design.md': null });
    const p = spawnSync(process.execPath, [SCRIPT, '--root', root], { encoding: 'utf8' });
    assert.equal(p.status, 1);
    assert.match(p.stdout, /docs\/skyoauth-design\.md: error \[files\] spec is missing/);
  });
  test('runs when invoked through a symlinked path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'docs-check-link-'));
    roots.push(dir);
    symlinkSync(dirname(SCRIPT), join(dir, 'ci'));
    const root = fixture({}, { tasks: edit(TASKS, 'after T00.1–T00.2', 'after T00.1–T00.9') });
    const p = spawnSync(process.execPath, [join(dir, 'ci', 'docs-check.mjs'), '--root', root], { encoding: 'utf8' });
    assert.equal(p.status, 1, p.stdout + p.stderr);
    assert.match(p.stdout, /FAILED: 1 error/);
  });
  test('unknown argument exits 2', () => {
    const p = spawnSync(process.execPath, [SCRIPT, '--bogus'], { encoding: 'utf8' });
    assert.equal(p.status, 2);
  });
});
