// Self-test of the chapter record and the milestone checks of
// transcript.mjs (docs/proposals/demo-walkthroughs.md §6.1 to §6.3, §6.9),
// pure: no browser, no ffmpeg, no network:
//   node --test scripts/demo/milestone.test.mjs
//
// Each milestone case builds its directory under a fresh temporary
// directory from the committed sample milestone (scripts/demo/sample/m1a)
// and one change, and expects the exact file:line message.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { MAX_CHAPTER_CHARS, MAX_MANIFEST_BYTES, MAX_RECORD_BYTES, MAX_REPORTED_ENTRIES, checkMilestone, joinJourneys, main, parseManifest, printableName, readNoFollow, secretsFromFile, validateTranscript } from './transcript.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'transcript.mjs');
const SAMPLE = join(HERE, 'sample', 'sample.transcript.jsonl');
const SAMPLE_M1A = join(HERE, 'sample', 'm1a');
const KEY_FILE = join(HERE, '..', '..', 'tests', 'conformance', 'fixtures', '_recovery', 'recovery.test-key.json');
const KEYS = JSON.parse(readFileSync(KEY_FILE, 'utf8')).keys;
const TMP = mkdtempSync(join(tmpdir(), 'demo-milestone-test-'));
after(() => rmSync(TMP, { recursive: true, force: true }));

const JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
const SIG_HEX = createHash('sha512').update('demo signature').digest('hex');
const B64 = createHash('sha512').update('demo b64').digest('base64url');

const line = (step, type, text, allow) => JSON.stringify(allow ? { step, type, text, allow } : { step, type, text });
// A transcript of [type, text, allow?] records, steps from 0.
const transcript = (...records) => records.map(([type, text, allow], step) => `${line(step, type, text, allow)}\n`).join('');
const check = (text, options) => validateTranscript(Buffer.from(text, 'utf8'), options);
const errorsOf = (text, options) => check(text, options).errors;

let dirs = 0;
// A copy of the sample milestone in a fresh directory named `name`;
// `files` replaces (string) or removes (null) files in it.
function milestone(files = {}, name = 'm1a') {
  const root = join(TMP, `case-${++dirs}`);
  const dir = join(root, name);
  mkdirSync(root);
  cpSync(SAMPLE_M1A, dir, { recursive: true });
  for (const [f, content] of Object.entries(files)) {
    if (content === null) rmSync(join(dir, f), { recursive: true, force: true });
    else writeFileSync(join(dir, f), content);
  }
  return dir;
}
// Each problem as "<path relative to dir or as given>:<line>: message".
const problemsOf = (dir, options) => {
  const r = checkMilestone(dir, options);
  return r.problems.map((p) => `${p.path.startsWith(`${dir}/`) ? p.path.slice(dir.length + 1) : p.path}${p.line === null ? '' : `:${p.line}`}: ${p.message}`);
};
const sampleLines = (name) => readFileSync(join(SAMPLE_M1A, name), 'utf8').trimEnd().split('\n');
// A journey file from records [type, text] after its chapter.
const journey = (title, ...records) => transcript(['chapter', title], ...records);

describe('the chapter record (§6.1)', () => {
  it('is accepted as step 0 of a single file, as `check` reads it', () => {
    const { errors, records } = check(journey('M1a-2: Recover the operator', ['caption', 'c']));
    assert.deepEqual(errors, []);
    assert.deepEqual(records[0], { step: 0, type: 'chapter', text: 'M1a-2: Recover the operator' });
  });

  it('is refused at a later step of a single file', () => {
    assert.deepEqual(errorsOf(transcript(['caption', 'c'], ['chapter', 'M1a-1: Title'])), [
      { line: 2, message: 'a chapter is only allowed as the first record, at step 0 (a later one only in a joined milestone stream)' },
    ]);
  });

  it('is refused a second time in a single file', () => {
    assert.deepEqual(errorsOf(journey('M1a-1: One', ['caption', 'c'], ['chapter', 'M1a-1: Two'])), [
      { line: 3, message: 'a second chapter: a single journey file holds at most one, as step 0' },
    ]);
  });

  it('is not in the committed sample transcript', () => {
    const { errors, records } = validateTranscript(readFileSync(SAMPLE));
    assert.deepEqual(errors, []);
    assert.ok(records.length > 0 && records.every((r) => r.type !== 'chapter'));
  });

  it('is one line', () => {
    assert.deepEqual(errorsOf(journey('M1a-1: Two\nlines')), [{ line: 1, message: 'a chapter is one line: "text" holds a line feed' }]);
  });

  it(`is at most ${MAX_CHAPTER_CHARS} code points`, () => {
    const at = (n, ch = 'x') => `M1a-1: ${ch.repeat(n - 7)}`;
    assert.deepEqual(errorsOf(journey(at(MAX_CHAPTER_CHARS))), []);
    assert.deepEqual(errorsOf(journey(at(MAX_CHAPTER_CHARS, 'é'))), []);
    assert.deepEqual(errorsOf(journey(at(MAX_CHAPTER_CHARS + 1))), [{ line: 1, message: 'a chapter is at most 80 characters (code points), this one is 81' }]);
  });

  it('starts with a journey id, a colon, a space and a title', () => {
    for (const ok of ['M1a-1: t', 'M5-12: Title', 'M2b-3: a: b']) assert.deepEqual(errorsOf(journey(ok)), [], ok);
    for (const bad of ['Bootstrap the operator', 'M1a: no journey number', 'M1a-0: zero', 'M1a-01: leading zero', 'm1a-1: lower case', 'M1A-1: upper case', 'M6-1: no such milestone', 'M1c-1: no such part', 'M1a-1:no space', 'M1a-1: ', 'M1a-1:  blank first', ' M1a-1: leading blank']) {
      assert.deepEqual(errorsOf(journey(bad)), [{ line: 1, message: 'a chapter is "<journey id>: <title>": a journey id such as M1a-2, a colon, a space and a title' }], bad);
    }
  });

  it('takes no allow marker', () => {
    assert.deepEqual(errorsOf(transcript(['chapter', 'M1a-1: t', 'hex-across-lines'])), [{ line: 1, message: 'a chapter takes no "allow" marker' }]);
  });

  it('is transcript text: the secret, timestamp and --secret-file rules apply to its title', () => {
    assert.deepEqual(errorsOf(journey(`M1a-1: ${JWT}`)), [{ line: 1, message: 'JWT-shaped string in "text"' }]);
    assert.deepEqual(errorsOf(journey('M1a-1: Bearer abc123')), [{ line: 1, message: 'Bearer credential in "text"' }]);
    assert.deepEqual(errorsOf(journey('M1a-1: at 10:15:00')), [{ line: 1, message: 'timestamp-like value (time of day) in "text"' }]);
    const secrets = secretsFromFile(KEY_FILE);
    assert.deepEqual(errorsOf(journey(`M1a-1: ${KEYS[0].seed}`), { secrets }), [{ line: 1, message: 'the value of recovery.test-key.json keys[0].seed appears in the record' }]);
    assert.deepEqual(errorsOf(journey('M1a-1: x pw-not-real-1234'), { secrets: new Map([['DEMO_PW', 'pw-not-real-1234']]) }), [{ line: 1, message: 'the value of DEMO_PW appears in the record' }]);
  });

  it('in milestone mode: opens the stream at step 0, and is allowed at a later step', () => {
    const joined = transcript(['chapter', 'M1a-1: One'], ['caption', 'c'], ['chapter', 'M1a-2: Two'], ['output', 'o']);
    assert.deepEqual(errorsOf(joined, { milestone: true }), []);
    // `check` (the default mode) refuses the same bytes.
    assert.deepEqual(errorsOf(joined), [{ line: 3, message: 'a second chapter: a single journey file holds at most one, as step 0' }]);
    assert.deepEqual(errorsOf(transcript(['caption', 'c'], ['chapter', 'M1a-1: One']), { milestone: true }), [{ line: 1, message: 'a joined milestone stream opens with a chapter at step 0' }]);
  });

  it('in milestone mode: a chapter ends a run of output and note records', () => {
    const parts = [SIG_HEX.slice(0, 43), SIG_HEX.slice(43, 86), SIG_HEX.slice(86)];
    const run = (between) => transcript(['chapter', 'M1a-1: One'], ['output', parts[0]], ['output', parts[1]], ...between, ['output', parts[2]]);
    assert.deepEqual(errorsOf(run([['chapter', 'M1a-2: Two']]), { milestone: true }), []);
    // Control: without the chapter the three records are one run.
    assert.match(errorsOf(run([]), { milestone: true })[0].message, /^hex run of 96 .* across the records on lines 2-4/);
  });

  it('in a journey file of a milestone: opens it, and names the file\'s journey', () => {
    assert.deepEqual(errorsOf(journey('M1a-2: t'), { journeyFile: 'm1a-2.jsonl' }), []);
    assert.deepEqual(errorsOf(transcript(['caption', 'c']), { journeyFile: 'm1a-2.jsonl' }), [{ line: 1, message: 'a journey file of a milestone opens with its chapter, at step 0' }]);
    assert.deepEqual(errorsOf(journey('M1a-3: t'), { journeyFile: 'm1a-2.jsonl' }), [{ line: 1, message: 'the chapter names journey M1a-3, not this file\'s M1a-2' }]);
    assert.deepEqual(errorsOf(journey('M1a-3: t'), { journeyFile: 'notes.jsonl' }), [{ line: 1, message: 'the chapter names journey M1a-3, whose file is m1a-3.jsonl, not this one' }]);
    // An unreadable first line is reported once, not also as a missing chapter.
    assert.deepEqual(errorsOf('not json\n', { journeyFile: 'm1a-2.jsonl' }), [{ line: 1, message: 'not JSON at character 1' }]);
    assert.throws(() => validateTranscript(Buffer.from(journey('M1a-1: t')), { milestone: true, journeyFile: 'm1a-1.jsonl' }), /exclude each other/);
  });
});

describe('the sample milestone', () => {
  it('passes check-milestone, with the test keys too, and every caption is marked SAMPLE', () => {
    const r = checkMilestone(SAMPLE_M1A, { secrets: secretsFromFile(KEY_FILE) });
    assert.deepEqual(r.problems, []);
    assert.deepEqual(r.notes, []);
    assert.equal(r.milestone, 'M1a');
    assert.equal(r.files, 2);
    assert.ok(r.joined.filter((x) => x.type === 'caption').every((x) => /\bSAMPLE\b/.test(x.text)));
    assert.ok(r.joined.filter((x) => x.type === 'chapter').every((x) => /\bSAMPLE\b/.test(x.text)));
  });

  it('has two journeys whose titles hold each of \\ = ; # (for the mp4 chapter escaping, §6.6)', () => {
    const titles = checkMilestone(SAMPLE_M1A).joined.filter((x) => x.type === 'chapter').map((x) => x.text);
    assert.equal(titles.length, 2);
    for (const ch of ['\\', '=', ';', '#']) assert.ok(titles.some((t) => t.includes(ch)), ch);
  });
});

describe('the join (§6.3)', () => {
  it('renumbers: step = records in the earlier journeys + step in the file', () => {
    const r = checkMilestone(SAMPLE_M1A);
    const n1 = sampleLines('m1a-1.jsonl').length;
    assert.deepEqual(r.joined.map((x) => x.step), [...r.joined.keys()]);
    assert.deepEqual(r.joined[n1], { ...JSON.parse(sampleLines('m1a-2.jsonl')[0]), step: n1 });
    assert.deepEqual(joinJourneys([[{ step: 0, type: 'chapter', text: 'a' }, { step: 1, type: 'caption', text: 'b' }], [{ step: 0, type: 'chapter', text: 'c' }]]).map((x) => x.step), [0, 1, 2]);
    // The joined stream is a valid milestone-mode transcript.
    const bytes = r.joined.map((x) => `${JSON.stringify(x)}\n`).join('');
    assert.deepEqual(errorsOf(bytes, { milestone: true }), []);
  });

  it('finds a value split over a journey\'s last record and the next chapter, at file:line', () => {
    const last = sampleLines('m1a-1.jsonl').length + 1;
    const dir = milestone({ 'm1a-1.jsonl': `${sampleLines('m1a-1.jsonl').join('\n')}\n${line(last - 1, 'output', `sig: ${B64.slice(0, 84)}`)}\n` });
    assert.deepEqual(problemsOf(dir), [`m1a-2.jsonl:1: base64url run of 86 or more characters (signature-sized) across the records on m1a-1.jsonl:${last} - m1a-2.jsonl:1 (texts joined)`]);
  });

  it('finds a value split over a journey boundary with the chapter between (the chapter-stripped pass), at file:line', () => {
    const [a, b] = [JWT.slice(0, 33), JWT.slice(33)];
    const last = sampleLines('m1a-1.jsonl').length + 1;
    const dir = milestone({
      'm1a-1.jsonl': `${sampleLines('m1a-1.jsonl').join('\n')}\n${line(last - 1, 'output', `token ${a}`)}\n`,
      'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', `${b} end`]),
    });
    assert.deepEqual(problemsOf(dir), [`m1a-2.jsonl:2: JWT-shaped string across the records on m1a-1.jsonl:${last} - m1a-2.jsonl:2 (chapters removed)`]);
  });

  it('builds the joined passes from every parsed record: one invalid in its file still takes part', () => {
    const [a, b] = [JWT.slice(0, 33), JWT.slice(33)];
    const last = sampleLines('m1a-1.jsonl').length + 1;
    // Invalid alone twice over: a time of day, and not in canonical form.
    const bad = `{"step": ${last - 1}, "type": "output", "text": "at 10:15:00\\ntoken ${a}"}`;
    const dir = milestone({ 'm1a-1.jsonl': `${sampleLines('m1a-1.jsonl').join('\n')}\n${bad}\n`, 'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', b]) });
    assert.deepEqual(problemsOf(dir), [
      `m1a-1.jsonl:${last}: not in canonical form: keys step, type, text (then allow, if any) in that order, no spaces, no duplicate keys, JSON.stringify escaping`,
      `m1a-1.jsonl:${last}: timestamp-like value (time of day) in "text"`,
      `m1a-2.jsonl:2: JWT-shaped string across the records on m1a-1.jsonl:${last} - m1a-2.jsonl:2 (chapters removed)`,
    ]);
    assert.equal(checkMilestone(dir).joined, null);
  });

  it('runs no run window across a journey boundary: only the pairs cross it', () => {
    const parts = [SIG_HEX.slice(0, 43), SIG_HEX.slice(43, 86), SIG_HEX.slice(86)];
    const dir = milestone({
      'm1a-1.jsonl': journey('M1a-1: SAMPLE first', ['caption', 'SAMPLE'], ['output', parts[0]], ['output', parts[1]]),
      'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', parts[2]], ['caption', 'SAMPLE']),
    });
    assert.deepEqual(problemsOf(dir), []);
    // Control: the same three records in one file are one run, and refused.
    assert.match(problemsOf(milestone({ 'm1a-1.jsonl': journey('M1a-1: SAMPLE first', ['output', parts[0]], ['output', parts[1]], ['output', parts[2]]) }))[0], /^m1a-1\.jsonl:4: hex run of 96 .* across the records on lines 2-4/);
  });

  it('repeats no error: a value found in its file is not reported again across the boundary', () => {
    const last = sampleLines('m1a-1.jsonl').length + 1;
    const dir = milestone({
      'm1a-1.jsonl': `${sampleLines('m1a-1.jsonl').join('\n')}\n${line(last - 1, 'output', `token ${JWT}`)}\n`,
      'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', '.more']),
    });
    assert.deepEqual(problemsOf(dir), [`m1a-1.jsonl:${last}: JWT-shaped string in "text"`]);
  });

  it('repeats no error: a pair that both passes see (no chapter between) is reported once', () => {
    const [a, b] = [JWT.slice(0, 33), JWT.slice(33)];
    const last = sampleLines('m1a-1.jsonl').length + 1;
    const dir = milestone({
      'm1a-1.jsonl': `${sampleLines('m1a-1.jsonl').join('\n')}\n${line(last - 1, 'output', a)}\n`,
      'm1a-2.jsonl': transcript(['output', b], ['caption', 'SAMPLE']),
    });
    assert.deepEqual(problemsOf(dir), [
      'm1a-2.jsonl:1: a journey file of a milestone opens with its chapter, at step 0',
      `m1a-2.jsonl:1: JWT-shaped string across the records on m1a-1.jsonl:${last} - m1a-2.jsonl:1 (texts joined)`,
    ]);
  });

  it('carries allow markers over unchanged', () => {
    const key = createHash('sha256').update('pk').digest('hex');
    const last = sampleLines('m1a-1.jsonl').length + 1;
    const marked = milestone({
      'm1a-1.jsonl': `${sampleLines('m1a-1.jsonl').join('\n')}\n${line(last - 1, 'output', key, 'hex-across-lines')}\n`,
      'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', key]),
    });
    assert.deepEqual(problemsOf(marked), []);
    const unmarked = milestone({
      'm1a-1.jsonl': `${sampleLines('m1a-1.jsonl').join('\n')}\n${line(last - 1, 'output', key)}\n`,
      'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', key]),
    });
    assert.match(problemsOf(unmarked)[0], /^m1a-2\.jsonl:2: hex run of 96 .* across the records on m1a-1\.jsonl:\d+ - m1a-2\.jsonl:2/);
  });

  it('checks the chapter titles joined, with a space (Bearer and its value split over two titles)', () => {
    const dir = milestone({ 'm1a-1.jsonl': journey('M1a-1: SAMPLE first Bearer', ['caption', 'SAMPLE']), 'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['caption', 'SAMPLE']) });
    assert.deepEqual(problemsOf(dir), ['m1a-2.jsonl:1: Bearer credential across the chapter titles on m1a-1.jsonl:1 - m1a-2.jsonl:1 (titles joined)']);
  });

  it('checks the chapter titles joined directly (a --secret-env value split over two titles)', () => {
    const secrets = new Map([['DEMO_PW', 'journey-oneM1a-2']]);
    const dir = milestone({ 'm1a-1.jsonl': journey('M1a-1: SAMPLE journey-one', ['caption', 'SAMPLE']), 'm1a-2.jsonl': journey('M1a-2: SAMPLE two', ['caption', 'SAMPLE']) });
    assert.deepEqual(problemsOf(dir, { secrets }), ['m1a-2.jsonl:1: the value of DEMO_PW across the chapter titles on m1a-1.jsonl:1 - m1a-2.jsonl:1 (titles joined)']);
  });
});

describe('names and manifest (§6.2)', () => {
  const manifest = (m) => (typeof m === 'string' ? m : JSON.stringify(m));
  const withManifest = (m, extra = {}) => milestone({ 'milestone.json': manifest(m), ...extra });
  const M = 'milestone.json: ';

  it('refuses a bad milestone id, without echoing it', () => {
    for (const id of ['M6', 'M0', 'm1a', 'M1c', 'M1ab', 'M1a ', 'eyJsecretvalue', 5, null]) {
      const p = problemsOf(withManifest({ milestone: id, journeys: ['M1a-1', 'M1a-2'] }));
      assert.ok(p.includes(`${M}"milestone" is not a milestone id (^M[1-5][ab]?$)`), `${id}: ${p}`);
      if (typeof id === 'string' && id.length > 3) assert.ok(!p.join('\n').includes(id), p.join('\n'));
    }
  });

  it('refuses a missing key, an unknown key (not named), a repeated key, not JSON and not an object', () => {
    assert.deepEqual(problemsOf(withManifest({ journeys: ['M1a-1', 'M1a-2'] })).filter((p) => p.startsWith(M)), [`${M}missing key "milestone"`]);
    assert.deepEqual(problemsOf(withManifest({ milestone: 'M1a' })).filter((p) => p.startsWith(M)), [`${M}missing key "journeys"`]);
    const unknown = problemsOf(withManifest({ milestone: 'M1a', journeys: ['M1a-1', 'M1a-2'], 'secret-key-name-77': 1 }));
    assert.deepEqual(unknown, [`${M}1 unknown key(s) (allowed: milestone, journeys)`]);
    assert.deepEqual(problemsOf(withManifest('{"milestone":"M1a","milestone":"M1a","journeys":["M1a-1","M1a-2"]}')), [`${M}key "milestone" appears 2 times`]);
    assert.deepEqual(problemsOf(withManifest('{"milestone": eyJsecret}')).filter((p) => p.startsWith(M)), [`${M}not JSON at character 15`]);
    assert.deepEqual(problemsOf(withManifest('["M1a"]')).filter((p) => p.startsWith(M)), [`${M}must be a JSON object {"milestone":"M1a","journeys":["M1a-1",...]}`]);
    assert.deepEqual(parseManifest(Buffer.from([0xff])), { problems: ['not valid UTF-8'] });
  });

  it('refuses an empty list, a list that is not one, a bad journey id and a repeated one', () => {
    assert.deepEqual(problemsOf(withManifest({ milestone: 'M1a', journeys: [] })).filter((p) => p.startsWith(M)), [`${M}"journeys" is empty: a milestone lists at least one journey`]);
    assert.deepEqual(problemsOf(withManifest({ milestone: 'M1a', journeys: 'M1a-1' })).filter((p) => p.startsWith(M)), [`${M}"journeys" must be a list of journey ids`]);
    for (const id of ['M1a-0', 'M1a-01', 'M1a-x', 'M1a', 'm1a-1', 'M1a-1 ', 7]) {
      assert.deepEqual(problemsOf(withManifest({ milestone: 'M1a', journeys: ['M1a-1', id] })).filter((p) => p.startsWith(M)), [`${M}journeys[1] is not a journey id (^M[1-5][ab]?-[1-9][0-9]*$)`], String(id));
    }
    assert.deepEqual(problemsOf(withManifest({ milestone: 'M1a', journeys: ['M1a-1', 'M1a-2', 'M1a-1'] })), [`${M}journeys[2] (M1a-1) repeats journeys[0]: each journey is listed once`]);
  });

  it('refuses a journey id of another milestone', () => {
    for (const id of ['M1b-2', 'M1-2', 'M2-2', 'M1a2-2']) {
      const p = problemsOf(withManifest({ milestone: 'M1a', journeys: ['M1a-1', id] })).filter((x) => x.startsWith(M));
      if (id === 'M1a2-2') assert.deepEqual(p, [`${M}journeys[1] is not a journey id (^M[1-5][ab]?-[1-9][0-9]*$)`]);
      else assert.deepEqual(p, [`${M}journeys[1] (${id}) is not a journey of M1a: its id must start with M1a-`]);
    }
    // M1a-2 under M1: the prefix is "M1-", not "M1".
    const m1 = join(TMP, 'm1-case');
    mkdirSync(join(m1, 'm1'), { recursive: true });
    writeFileSync(join(m1, 'm1', 'milestone.json'), JSON.stringify({ milestone: 'M1', journeys: ['M1a-2'] }));
    assert.deepEqual(problemsOf(join(m1, 'm1')).filter((x) => x.startsWith(M)), [`${M}journeys[0] (M1a-2) is not a journey of M1: its id must start with M1-`]);
  });

  it('refuses a directory not named the lower case of the milestone id', () => {
    const wrong = milestone({}, 'm1b');
    assert.deepEqual(problemsOf(wrong), [`${wrong}: the directory name is not m1a, the lower case of the milestone id M1a`]);
    const upper = milestone({}, 'M1a');
    assert.deepEqual(problemsOf(upper), [`${upper}: the directory name is not m1a, the lower case of the milestone id M1a`]);
    const noManifest = milestone({ 'milestone.json': null }, 'demo');
    assert.ok(problemsOf(noManifest).includes(`${noManifest}: the directory name is not a lower-case milestone id (such as m1a or m2)`));
  });

  it('refuses a missing manifest, a missing listed file and an unlisted file', () => {
    assert.deepEqual(problemsOf(milestone({ 'milestone.json': null })), ['milestone.json: missing: a milestone directory holds its manifest']);
    assert.deepEqual(problemsOf(milestone({ 'm1a-2.jsonl': null })), ['m1a-2.jsonl: missing: milestone.json lists M1a-2']);
    // A journey file name is printed; any other name by its place in the
    // sorted listing (m1a-1.jsonl, m1a-2.jsonl, milestone.json and it).
    for (const [name, shownAs] of [['m1a-3.jsonl', 'm1a-3.jsonl'], ['notes.txt', '<entry 4>'], ['.gitkeep', '<entry 1>'], ['README.md', '<entry 1>']]) {
      assert.deepEqual(problemsOf(milestone({ [name]: journey('M1a-3: SAMPLE third') })), [`${shownAs}: not listed in milestone.json: a milestone directory holds only its manifest and the files of the journeys it lists`], name);
    }
  });

  it('refuses a file whose name is not its journey id\'s', () => {
    const dir = milestone({ 'm1a-2.jsonl': null, 'M1a-2.jsonl': readFileSync(join(SAMPLE_M1A, 'm1a-2.jsonl')) });
    assert.deepEqual(problemsOf(dir), [
      'm1a-2.jsonl: missing: milestone.json lists M1a-2',
      '<entry 1>: not listed in milestone.json: a milestone directory holds only its manifest and the files of the journeys it lists',
      '<entry 1>:1: the chapter names journey M1a-2, whose file is m1a-2.jsonl, not this one',
    ]);
    // The chapter must name the file's journey.
    assert.deepEqual(problemsOf(milestone({ 'm1a-2.jsonl': journey('M1a-1: SAMPLE twice', ['caption', 'SAMPLE']) })), ["m1a-2.jsonl:1: the chapter names journey M1a-1, not this file's M1a-2"]);
    // Every journey file must have its chapter.
    assert.deepEqual(problemsOf(milestone({ 'm1a-2.jsonl': transcript(['caption', 'SAMPLE']) })), ['m1a-2.jsonl:1: a journey file of a milestone opens with its chapter, at step 0']);
  });

  it('refuses an empty journey file', () => {
    assert.deepEqual(problemsOf(milestone({ 'm1a-2.jsonl': '' })), ['m1a-2.jsonl:1: empty transcript: it needs at least one record']);
  });

  it('refuses a nested directory', () => {
    const dir = milestone();
    mkdirSync(join(dir, 'm1a-3.jsonl'));
    mkdirSync(join(dir, 'nested'));
    assert.deepEqual(problemsOf(dir), [
      'm1a-3.jsonl: a nested directory: a milestone directory holds only milestone.json and its journey files',
      '<entry 5>: a nested directory: a milestone directory holds only milestone.json and its journey files',
    ]);
  });

  it('refuses a symlink, for a journey file, the manifest, an unlisted name and the directory itself, and never follows it', () => {
    const outside = join(TMP, 'outside.jsonl');
    writeFileSync(outside, transcript(['output', `token ${JWT}`]));
    const dir = milestone();
    unlinkSync(join(dir, 'm1a-2.jsonl'));
    symlinkSync(join(SAMPLE_M1A, 'm1a-2.jsonl'), join(dir, 'm1a-2.jsonl'));
    symlinkSync(outside, join(dir, 'm1a-3.jsonl'));
    const sym = 'a symlink: a milestone directory holds only regular files, and symlinks are not followed';
    assert.deepEqual(problemsOf(dir), [`m1a-2.jsonl: ${sym}`, `m1a-3.jsonl: ${sym}`]);
    assert.deepEqual(checkMilestone(dir).notes, [`${dir}: the joined checks were not run: a listed journey file is missing or unreadable`]);
    const man = milestone();
    unlinkSync(join(man, 'milestone.json'));
    symlinkSync(join(SAMPLE_M1A, 'milestone.json'), join(man, 'milestone.json'));
    assert.deepEqual(problemsOf(man), [`milestone.json: ${sym}`]);
    const linkRoot = join(TMP, 'dir-link');
    mkdirSync(linkRoot);
    symlinkSync(SAMPLE_M1A, join(linkRoot, 'm1a'));
    for (const arg of [join(linkRoot, 'm1a'), `${join(linkRoot, 'm1a')}/`]) {
      assert.deepEqual(problemsOf(arg), [`${arg}: a symlink: a milestone directory must be a directory, not a link to one`]);
    }
  });

  it('reads a journey file without following a symlink, even one that appeared after the lstat', () => {
    const link = join(TMP, 'late-link.jsonl');
    symlinkSync(join(SAMPLE_M1A, 'm1a-1.jsonl'), link);
    assert.throws(() => readNoFollow(link), (e) => e.code === 'ELOOP');
    assert.throws(() => readNoFollow(TMP), (e) => e.code === 'not a regular file');
    assert.deepEqual(readNoFollow(join(SAMPLE_M1A, 'm1a-1.jsonl')), readFileSync(join(SAMPLE_M1A, 'm1a-1.jsonl')));
  });

  it('with a bad manifest, still checks every .jsonl file alone, and skips the joined checks', () => {
    const dir = milestone({ 'milestone.json': '{}', 'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', `token ${JWT}`]), 'other.jsonl': transcript(['caption', 'x']) });
    assert.deepEqual(problemsOf(dir), [
      `${M}missing key "milestone"`,
      `${M}missing key "journeys"`,
      '<entry 4>: neither milestone.json nor a journey file (<lower-case journey id>.jsonl)',
      'm1a-2.jsonl:2: JWT-shaped string in "text"',
      '<entry 4>:1: a journey file of a milestone opens with its chapter, at step 0',
    ]);
    const r = checkMilestone(dir);
    assert.equal(r.files, 3);
    assert.deepEqual(r.notes, [`${dir}: the joined checks were not run: the manifest is missing or bad`]);
  });

  it('refuses a path that is not a directory, or does not exist', () => {
    assert.deepEqual(problemsOf(join(TMP, 'no-such-m1a')), [`${join(TMP, 'no-such-m1a')}: cannot read: ENOENT`]);
    assert.deepEqual(problemsOf(SAMPLE), [`${SAMPLE}: not a directory`]);
  });
});

describe('check-milestone CLI', () => {
  const cli = (args, env = {}) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });

  it('exits 0 on the sample milestone, with the test keys, and prints a summary', () => {
    const r = cli(['check-milestone', '--secret-file', KEY_FILE, SAMPLE_M1A]);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stderr, '');
    assert.match(r.stdout, /^transcript check-milestone: 1 director\(ies\), 2 journey file\(s\), 10 valid record\(s\), 0 director\(ies\) with errors\n$/);
  });

  it('exits 2 with no directory, so a glob that matched nothing fails, and on a usage error', () => {
    const r = cli(['check-milestone']);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /no milestone directory given/);
    assert.equal(cli(['check-milestone', '--secret-file', KEY_FILE]).status, 2);
    assert.equal(cli(['check-milestone', '--all', SAMPLE_M1A]).status, 2);
    assert.equal(cli(['check-milestone', '--secret-env', 'UNSET_X', SAMPLE_M1A]).status, 2);
  });

  it('carries on across directories, after a missing one and a bad manifest', () => {
    const bad = milestone({ 'milestone.json': '{"milestone":"M1a","journeys":[]}', 'm1a-2.jsonl': journey('M1a-2: SAMPLE', ['output', 'Bearer abc123']) });
    const missing = join(TMP, 'missing-m2');
    const r = cli(['check-milestone', missing, bad, SAMPLE_M1A]);
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes(`${missing}: cannot read: ENOENT`), r.stderr);
    assert.ok(r.stderr.includes(`${bad}/milestone.json: "journeys" is empty: a milestone lists at least one journey`), r.stderr);
    assert.ok(r.stderr.includes(`${bad}/m1a-2.jsonl:2: Bearer credential in "text"`), r.stderr);
    assert.ok(r.stderr.includes(`${bad}: the joined checks were not run: the manifest is missing or bad`), r.stderr);
    assert.match(r.stdout, /3 director\(ies\), 4 journey file\(s\), \d+ valid record\(s\), 2 director\(ies\) with errors/);
  });

  it('main() is callable in process', () => {
    const out = [];
    const err = [];
    assert.equal(main(['check-milestone', SAMPLE_M1A], { out: (s) => out.push(s), error: (s) => err.push(s) }), 0);
    assert.deepEqual(err, []);
    assert.equal(out.length, 1);
  });

  it('never echoes the input: titles, records, manifest values and keys, file names', () => {
    const SECRET_ENV = 'dummy-env-secret-987654';
    const SECRET_KEY = 'secret-manifest-key-4321';
    const SECRET_NAME = 'tok en=SECRETNAME77.jsonl';
    const [a, b] = [JWT.slice(0, 33), JWT.slice(33)];
    const bad = milestone({
      'milestone.json': JSON.stringify({ milestone: 'M1a', journeys: ['M1a-1', 'M1a-2', 'M1a-x-eyJsecretid'], [SECRET_KEY]: SECRET_ENV }),
      'm1a-1.jsonl': journey(`M1a-1: ${JWT}`, ['output', `pw ${SECRET_ENV}`], ['output', `token ${a}`]),
      'm1a-2.jsonl': journey(`M1a-2: ${SECRET_ENV}`, ['output', b]),
      [SECRET_NAME]: 'x',
    });
    const good = milestone({
      'm1a-1.jsonl': journey('M1a-1: SAMPLE Bearer', ['output', `token ${a}`]),
      'm1a-2.jsonl': journey('M1a-2: SAMPLE', ['output', b]),
    });
    const r = cli(['check-milestone', '--secret-env', 'DUMMY', bad, good], { DUMMY: SECRET_ENV });
    assert.equal(r.status, 1);
    const printed = r.stdout + r.stderr;
    assert.ok(printed.includes(`${good}/m1a-2.jsonl:2: JWT-shaped string across the records on m1a-1.jsonl:2 - m1a-2.jsonl:2 (chapters removed)`), printed);
    assert.ok(printed.includes(`${good}/m1a-2.jsonl:1: Bearer credential across the chapter titles on m1a-1.jsonl:1 - m1a-2.jsonl:1 (titles joined)`), printed);
    assert.ok(printed.includes(`${bad}/<entry `), printed);
    for (const needle of [JWT, JWT.slice(0, 16), b, SECRET_ENV, SECRET_ENV.slice(0, 12), SECRET_KEY, 'SECRETNAME77', 'eyJsecretid']) {
      assert.ok(!printed.includes(needle), `printed ${needle}:\n${printed}`);
    }
  });
});

describe('the sample directory', () => {
  it('holds the sample transcript and the sample milestone only', () => {
    assert.deepEqual(readdirSync(join(HERE, 'sample')).sort(), ['m1a', 'sample.transcript.jsonl']);
  });
});

// Review follow-ups of #219 (the lead's items and the automated review).
const ESC = String.fromCharCode(27);
const CR = String.fromCharCode(13);
const LF = String.fromCharCode(10);
const RLO = String.fromCharCode(0x202e);
const cliRun = (args, { env = {}, cwd } = {}) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', cwd, env: { PATH: process.env.PATH, ...env } });

// An output record of exactly `bytes` bytes as a line of a journey file at
// `step`: lines of 100 characters, the last one padded (at most 120).
function outputOfBytes(step, bytes) {
  const size = (t) => Buffer.byteLength(line(step, 'output', t));
  let text = 'y';
  let last = 1;
  while (size(text) < bytes) {
    if (last >= 100 && bytes - size(text) >= 3) {
      text += `${LF}y`;
      last = 1;
    } else {
      text += 'y';
      last++;
    }
  }
  assert.equal(size(text), bytes);
  return line(step, 'output', text);
}

describe('the joined stream in milestone mode (lead item 1)', () => {
  // m1a-1: its chapter and 11 captions; m1a-2: its chapter, then a record
  // of `bytes` bytes at step 1, which the join renumbers to step 13.
  const capDir = (bytes) =>
    milestone({
      'm1a-1.jsonl': journey('M1a-1: SAMPLE first', ...Array.from({ length: 11 }, (_, i) => ['caption', `SAMPLE ${i}`])),
      'm1a-2.jsonl': `${line(0, 'chapter', 'M1a-2: SAMPLE second')}\n${outputOfBytes(1, bytes)}\n`,
    });

  it(`refuses a record that renumbering pushes over ${MAX_RECORD_BYTES} bytes, at its file and line`, () => {
    const dir = capDir(MAX_RECORD_BYTES);
    // Alone, each file is valid.
    for (const f of ['m1a-1.jsonl', 'm1a-2.jsonl']) assert.deepEqual(validateTranscript(readFileSync(join(dir, f))).errors, [], f);
    assert.deepEqual(problemsOf(dir), [`m1a-2.jsonl:2: record longer than ${MAX_RECORD_BYTES} bytes (in the joined milestone stream, as step 13)`]);
    assert.equal(checkMilestone(dir).joined, null);
  });

  it('accepts the same record one byte shorter', () => {
    const r = checkMilestone(capDir(MAX_RECORD_BYTES - 1));
    assert.deepEqual(r.problems, []);
    assert.equal(r.joined[13].step, 13);
  });

  it('when a file has errors, still checks the pair across the boundary from every parsed record', () => {
    const dir = milestone({ 'm1a-1.jsonl': journey('M1a-1: SAMPLE first', ['caption', 'at 10:15:00'], ['output', `sig: ${B64.slice(0, 84)}`]) });
    assert.deepEqual(problemsOf(dir), [
      'm1a-1.jsonl:2: timestamp-like value (time of day) in "text"',
      'm1a-2.jsonl:1: base64url run of 86 or more characters (signature-sized) across the records on m1a-1.jsonl:3 - m1a-2.jsonl:1 (texts joined)',
    ]);
  });

  it('tells the joined pass "(texts joined)" from the chapter-stripped pass "(chapters removed)"', () => {
    const [a, b] = [JWT.slice(0, 33), JWT.slice(33)];
    const joinedPass = problemsOf(milestone({ 'm1a-1.jsonl': journey('M1a-1: SAMPLE first', ['output', `sig: ${B64.slice(0, 84)}`]) }));
    const strippedPass = problemsOf(milestone({ 'm1a-1.jsonl': journey('M1a-1: SAMPLE first', ['output', `token ${a}`]), 'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', b]) }));
    assert.equal(joinedPass.length, 1);
    assert.equal(strippedPass.length, 1);
    assert.match(joinedPass[0], / \(texts joined\)$/);
    assert.match(strippedPass[0], / \(chapters removed\)$/);
  });
});

describe('the manifest\'s limits (lead items 2 and 3)', () => {
  const M = 'milestone.json: ';

  it('reports a manifest too deeply nested to read, without echoing it, and goes on to the next directory', () => {
    const deep = `{"milestone":"M1a","journeys":${'['.repeat(30000)}`;
    assert.deepEqual(parseManifest(Buffer.from(deep)), { problems: ['too deeply nested to read: a manifest is one object holding a list'] });
    const dir = milestone({ 'milestone.json': deep });
    assert.deepEqual(problemsOf(dir), [`${M}too deeply nested to read: a manifest is one object holding a list`]);
    const r = cliRun(['check-milestone', dir, SAMPLE_M1A]);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /2 director\(ies\), 4 journey file\(s\), 20 valid record\(s\), 1 director\(ies\) with errors/);
    assert.ok(!r.stderr.includes('[[[['), r.stderr.slice(0, 500));
  });

  it(`reads a manifest of up to ${MAX_MANIFEST_BYTES} bytes, and refuses a larger one unread`, () => {
    const body = JSON.stringify({ milestone: 'M1a', journeys: ['M1a-1', 'M1a-2'] });
    const padded = (n) => body + ' '.repeat(n - body.length);
    assert.deepEqual(problemsOf(milestone({ 'milestone.json': padded(MAX_MANIFEST_BYTES) })), []);
    const too = `${M}larger than ${MAX_MANIFEST_BYTES} bytes (64 KiB): a manifest lists journey ids only`;
    assert.deepEqual(problemsOf(milestone({ 'milestone.json': padded(MAX_MANIFEST_BYTES + 1) })), [too]);
    assert.deepEqual(parseManifest(Buffer.from(padded(MAX_MANIFEST_BYTES + 1))), { problems: [too.slice(M.length)] });
    assert.throws(() => readNoFollow(join(SAMPLE_M1A, 'milestone.json'), 10), (e) => e.code === 'too large');
  });

  it('caps the manifest at 64 KiB, and does not read a larger one (a sparse 3 GiB file)', () => {
    assert.equal(MAX_MANIFEST_BYTES, 64 * 1024);
    const dir = milestone();
    truncateSync(join(dir, 'milestone.json'), 3 * 2 ** 30);
    assert.deepEqual(problemsOf(dir), [`${M}larger than ${MAX_MANIFEST_BYTES} bytes (64 KiB): a manifest lists journey ids only`]);
  });

  it(`reports at most ${MAX_REPORTED_ENTRIES} bad entries, then how many more`, () => {
    const bad = (n) => problemsOf(milestone({ 'milestone.json': JSON.stringify({ milestone: 'M1a', journeys: ['M1a-1', 'M1a-2', ...Array.from({ length: n }, (_, i) => `M2-${i + 1}`)] }) }));
    const twenty = bad(MAX_REPORTED_ENTRIES);
    assert.equal(twenty.length, MAX_REPORTED_ENTRIES);
    assert.equal(twenty.at(-1), `${M}journeys[21] (M2-20) is not a journey of M1a: its id must start with M1a-`);
    const more = bad(MAX_REPORTED_ENTRIES + 5);
    assert.equal(more.length, MAX_REPORTED_ENTRIES + 1);
    assert.equal(more.at(-2), `${M}journeys[21] (M2-20) is not a journey of M1a: its id must start with M1a-`);
    assert.equal(more.at(-1), `${M}... and 5 more bad entries in "journeys"`);
  });

  it(`reports at most ${MAX_REPORTED_ENTRIES} listed journeys with no file, then how many more`, () => {
    const dir = milestone({ 'milestone.json': JSON.stringify({ milestone: 'M1a', journeys: Array.from({ length: 25 }, (_, i) => `M1a-${i + 1}`) }) });
    const p = problemsOf(dir);
    assert.equal(p.length, MAX_REPORTED_ENTRIES + 1);
    assert.equal(p[0], 'm1a-3.jsonl: missing: milestone.json lists M1a-3');
    assert.equal(p.at(-2), 'm1a-22.jsonl: missing: milestone.json lists M1a-22');
    assert.equal(p.at(-1), `${dir}: ... and 3 more listed journeys have no file`);
  });
});

describe('the title length counts code points (lead item 5)', () => {
  it('80 code points with astral characters pass, 81 fail', () => {
    const emoji = String.fromCodePoint(0x1f600);
    const title = (n) => `M1a-1: ${emoji.repeat(n - 7)}`;
    assert.equal(Array.from(title(80)).length, 80);
    assert.ok(title(80).length > 80, 'more UTF-16 units than code points');
    assert.deepEqual(errorsOf(journey(title(80))), []);
    assert.deepEqual(errorsOf(journey(title(81))), [{ line: 1, message: 'a chapter is at most 80 characters (code points), this one is 81' }]);
  });
});

describe('names in messages (lead item 7, review finding a)', () => {
  it('printableName escapes control and bidirectional characters, line feeds included', () => {
    assert.equal(printableName(`a${ESC}[31mb${CR}c${LF}d${RLO}e`), 'a<U+001B>[31mb<U+000D>c<U+000A>d<U+202E>e');
    assert.equal(printableName('plain/m1a'), 'plain/m1a');
  });

  it('checkMilestone names a directory through printableName when no label is given', () => {
    const bad = join(TMP, `missing${ESC}[2J`);
    assert.deepEqual(checkMilestone(bad).problems, [{ path: printableName(bad), line: null, message: 'cannot read: ENOENT' }]);
    assert.ok(!printableName(bad).includes(ESC));
  });

  it('check and check-milestone print a path with control characters escaped', () => {
    const parent = join(TMP, `esc${ESC}[31m${CR}x`);
    mkdirSync(parent);
    cpSync(SAMPLE_M1A, join(parent, 'm1a'), { recursive: true });
    writeFileSync(join(parent, 'm1a', 'm1a-2.jsonl'), journey('M1a-2: SAMPLE', ['output', 'Bearer abc123']));
    const shownParent = printableName(parent);
    const m = cliRun(['check-milestone', join(parent, 'm1a')]);
    const c = cliRun(['check', join(parent, 'm1a', 'm1a-2.jsonl'), join(parent, 'missing.jsonl')]);
    const s = cliRun(['check', '--secret-file', join(parent, 'missing.json'), SAMPLE]);
    assert.ok(m.stderr.includes(`${shownParent}/m1a/m1a-2.jsonl:2: Bearer credential in "text"`), m.stderr);
    assert.ok(c.stderr.includes(`${shownParent}/m1a/m1a-2.jsonl:2: Bearer credential in "text"`), c.stderr);
    assert.ok(c.stderr.includes(`${shownParent}/missing.jsonl: cannot read: ENOENT`), c.stderr);
    assert.equal(s.status, 2);
    assert.ok(s.stderr.includes(`--secret-file ${shownParent}/missing.json: cannot read`), s.stderr);
    for (const r of [m, c, s]) assert.ok(!(r.stdout + r.stderr).includes(ESC) && !(r.stdout + r.stderr).includes(CR), JSON.stringify(r.stderr));
  });

  it('prints only recognized entry names: any other entry by its place in the listing', () => {
    const SECRET = 'hunter2-not-real-77';
    const dir = milestone({ [SECRET]: 'x', [JWT]: 'x' });
    const r = cliRun(['check-milestone', '--secret-env', 'S', dir], { env: { S: SECRET } });
    assert.equal(r.status, 1);
    // Sorted: the JWT name, the secret, m1a-1.jsonl, m1a-2.jsonl, milestone.json.
    assert.ok(r.stderr.includes(`${dir}/<entry 1>: not listed in milestone.json`), r.stderr);
    assert.ok(r.stderr.includes(`${dir}/<entry 2>: not listed in milestone.json`), r.stderr);
    for (const needle of [SECRET, JWT.slice(0, 20)]) assert.ok(!(r.stdout + r.stderr).includes(needle), r.stderr);
  });

  it('never prints a recognized name, a listed file\'s name or a path argument that matches a secret value', () => {
    const name = 'm1a-9.jsonl';
    const dir = milestone({ [name]: journey('M1a-9: SAMPLE nine') });
    const r = cliRun(['check-milestone', '--secret-env', 'S', dir], { env: { S: name } });
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes(`${dir}/<entry 3>: not listed in milestone.json`), r.stderr);
    assert.ok(!(r.stdout + r.stderr).includes(name), r.stderr);
    const listedMissing = milestone({ 'm1a-2.jsonl': null });
    const l = cliRun(['check-milestone', '--secret-env', 'S', listedMissing], { env: { S: 'm1a-2.jsonl' } });
    assert.ok(l.stderr.includes(`${listedMissing}/<listed file 2>: missing: milestone.json lists M1a-2`), l.stderr);
    assert.ok(!l.stderr.includes('m1a-2.jsonl'), l.stderr);
    const SECRET = 'path-secret-55555';
    const root = join(TMP, SECRET);
    mkdirSync(root);
    cpSync(SAMPLE_M1A, join(root, 'm1a'), { recursive: true });
    writeFileSync(join(root, 'm1a', 'extra.txt'), 'x');
    for (const args of [['check-milestone', SAMPLE_M1A, join(root, 'm1a')], ['check', SAMPLE, join(root, 'missing.jsonl')]]) {
      const a = cliRun([args[0], '--secret-env', 'S', ...args.slice(1)], { env: { S: SECRET } });
      assert.equal(a.status, 1);
      assert.ok(a.stderr.includes('<argument 2>'), a.stderr);
      assert.ok(!(a.stdout + a.stderr).includes(SECRET), a.stderr);
    }
  });
});

describe('records refused for their fields keep their place (review finding b)', () => {
  const [a, b] = [JWT.slice(0, 33), JWT.slice(33)];

  it('in a single file: a value split over a record with an unknown or a missing field is found', () => {
    const extra = `${JSON.stringify({ step: 0, type: 'output', text: `token ${a}`, extra: 1 })}\n${line(1, 'output', b)}\n`;
    assert.deepEqual(errorsOf(extra), [
      { line: 1, message: '1 unknown field(s) (allowed: step, type, text, allow)' },
      { line: 2, message: 'JWT-shaped string across the records on lines 1-2 (texts joined)' },
    ]);
    const noType = `${JSON.stringify({ step: 0, text: `token ${a}` })}\n${line(1, 'output', b)}\n`;
    assert.deepEqual(errorsOf(noType), [
      { line: 1, message: 'missing field "type"' },
      { line: 2, message: 'JWT-shaped string across the records on lines 1-2 (texts joined)' },
    ]);
    // Never in the returned records.
    assert.deepEqual(check(`${JSON.stringify({ step: 0, type: 'output', text: 'x', extra: 1 })}\n`).records, []);
  });

  it('across a journey boundary: the chapter-stripped pass pairs the right neighbours', () => {
    const dir = milestone({
      'm1a-1.jsonl': `${line(0, 'chapter', 'M1a-1: SAMPLE first')}\n${line(1, 'caption', 'SAMPLE')}\n${JSON.stringify({ step: 2, type: 'output', text: `token ${a}`, extra: 1 })}\n`,
      'm1a-2.jsonl': journey('M1a-2: SAMPLE second', ['output', b]),
    });
    assert.deepEqual(problemsOf(dir), [
      'm1a-1.jsonl:3: 1 unknown field(s) (allowed: step, type, text, allow)',
      'm1a-2.jsonl:2: JWT-shaped string across the records on m1a-1.jsonl:3 - m1a-2.jsonl:2 (chapters removed)',
    ]);
  });
});

describe('reading without following a link, on every platform (review finding c)', () => {
  it('refuses a symlink at lstat, and a file replaced between the lstat and the open', () => {
    const dir = join(TMP, 'swap');
    mkdirSync(dir);
    const target = join(dir, 'm1a-1.jsonl');
    const other = join(dir, 'other.jsonl');
    const reset = () => {
      rmSync(target, { force: true });
      writeFileSync(target, 'original\n');
      writeFileSync(other, 'other\n');
    };
    reset();
    assert.equal(readNoFollow(target).toString(), 'original\n');
    // Another regular file renamed over it: no O_NOFOLLOW can see that, the
    // device and inode comparison does.
    assert.throws(() => readNoFollow(target, Infinity, { beforeOpen: () => renameSync(other, target) }), (e) => e.code === 'changed');
    // A symlink put in its place: O_NOFOLLOW refuses it where Node has it
    // (ELOOP), the comparison everywhere else ('changed').
    reset();
    assert.throws(
      () =>
        readNoFollow(target, Infinity, {
          beforeOpen: () => {
            unlinkSync(target);
            symlinkSync(other, target);
          },
        }),
      (e) => e.code === 'ELOOP' || e.code === 'changed',
    );
    // A symlink already there is refused by the lstat.
    assert.throws(() => readNoFollow(target), (e) => e.code === 'ELOOP');
  });
});

describe('the directory\'s own name (review finding d)', () => {
  it('is taken from the resolved path: ".", "m1a/", "m1a/." and "./m1a" pass', () => {
    const root = join(TMP, 'dot');
    mkdirSync(root);
    cpSync(SAMPLE_M1A, join(root, 'm1a'), { recursive: true });
    assert.equal(cliRun(['check-milestone', '.'], { cwd: join(root, 'm1a') }).status, 0);
    for (const arg of ['m1a/', 'm1a/.', './m1a', 'm1a//']) {
      const r = cliRun(['check-milestone', arg], { cwd: root });
      assert.equal(r.status, 0, `${arg}: ${r.stderr}`);
    }
  });

  it('still refuses a symlinked directory, however the path ends', () => {
    const root = join(TMP, 'dot-link');
    mkdirSync(root);
    symlinkSync(SAMPLE_M1A, join(root, 'm1a'));
    for (const arg of ['m1a', 'm1a/', 'm1a/.']) {
      const r = cliRun(['check-milestone', arg], { cwd: root });
      assert.equal(r.status, 1, arg);
      assert.match(r.stderr, /a symlink: a milestone directory must be a directory, not a link to one/, arg);
    }
  });
});
