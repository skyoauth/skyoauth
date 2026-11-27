// Pure tests of render.mjs (no browser, no ffmpeg):
//   node --test scripts/demo/render.test.mjs
//
// The transcript is read once: validation, captions, the published copy and
// its checksum come from that snapshot, never from the input path again.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { LEAD_IN_DETECTIONS, detectLeadIn, keepRawRecording, leadInLine, outputName, parseBlackIntervals, publishFiles } from './render.mjs';
import { recordsFromBytes } from './transcript.mjs';
import { toVtt } from './vtt.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLE = join(HERE, 'sample', 'sample.transcript.jsonl');
const TMP = mkdtempSync(join(tmpdir(), 'demo-render-test-'));
after(() => rmSync(TMP, { recursive: true, force: true }));
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

describe('the transcript snapshot', () => {
  it('publishes the snapshot, even when the input file has changed since it was read', () => {
    const input = join(TMP, 'snap.transcript.jsonl');
    writeFileSync(input, readFileSync(SAMPLE));
    const bytes = readFileSync(input);
    const records = recordsFromBytes(bytes, input);
    // The file changes after the read (here to a transcript that would fail).
    writeFileSync(input, '{"step":0,"type":"output","text":"Bearer abc123"}\n');
    const out = mkdtempSync(join(TMP, 'out-'));
    writeFileSync(join(out, 'snap.mp4'), 'not a video');
    const files = publishFiles({ outDir: out, name: outputName(input), bytes, records });
    assert.deepEqual(readFileSync(files.transcript), bytes);
    assert.equal(readFileSync(files.vtt, 'utf8'), toVtt(records));
    const sums = Object.fromEntries(
      readFileSync(files.sums, 'utf8')
        .trimEnd()
        .split('\n')
        .map((l) => l.split('  ').reverse()),
    );
    assert.deepEqual(Object.keys(sums).sort(), ['snap.mp4', 'snap.transcript.jsonl', 'snap.vtt']);
    assert.equal(sums['snap.transcript.jsonl'], sha256(bytes));
    assert.equal(sums['snap.vtt'], sha256(readFileSync(files.vtt)));
  });

  it('render() reads the input path once and never copies or re-reads it', () => {
    const source = readFileSync(join(HERE, 'render.mjs'), 'utf8');
    const body = source.slice(source.indexOf('export async function render('), source.indexOf('const USAGE'));
    assert.equal(body.match(/readFileSync\(/g)?.length, 1, 'one read in render()');
    assert.match(body, /const bytes = readFileSync\(transcriptPath\);/);
    assert.match(body, /recordsFromBytes\(bytes, transcriptPath/);
    assert.match(body, /publishFiles\(\{ outDir, name, bytes, records \}\)/);
    assert.doesNotMatch(source, /copyFileSync|readTranscript\(|createReadStream/);
  });

  it('names the outputs after the transcript', () => {
    assert.equal(outputName('/x/m1a.transcript.jsonl'), 'm1a');
    assert.equal(outputName('m1a.jsonl'), 'm1a');
  });
});

describe('DEMO_KEEP_RAW', () => {
  const raw = join(TMP, 'raw');
  mkdirSync(raw, { recursive: true });
  writeFileSync(join(raw, 'page.webm'), 'raw recording');

  it('copies the raw recording directory and says where', () => {
    const dest = join(TMP, 'kept', 'here');
    assert.equal(keepRawRecording(raw, dest), `kept the raw recording in ${dest}`);
    assert.equal(readFileSync(join(dest, 'page.webm'), 'utf8'), 'raw recording');
  });

  it('never throws: a copy that fails is a line, not an exception', () => {
    const file = join(TMP, 'a-file');
    writeFileSync(file, 'x');
    const dest = join(file, 'below');
    let note;
    assert.doesNotThrow(() => {
      note = keepRawRecording(raw, dest);
    });
    assert.equal(note, `DEMO_KEEP_RAW: could not keep the raw recording in ${dest} (ENOTDIR)`);
    assert.equal(existsSync(dest), false);
  });

  it('render() reports the copy and rethrows its own error', () => {
    const source = readFileSync(join(HERE, 'render.mjs'), 'utf8');
    const handler = /\} catch \(e\) \{\n([\s\S]*?)\n  \} finally \{/.exec(source.slice(source.indexOf('export async function render(')));
    assert.ok(handler, 'render() has a catch (e) ... finally');
    assert.match(handler[1], /if \(env\.DEMO_KEEP_RAW\) warn\(`render: \$\{keepRawRecording\(rawDir, env\.DEMO_KEEP_RAW\)\}`\);/);
    assert.match(handler[1], /\n    throw e;$/);
    assert.doesNotMatch(handler[1], /cpSync|mkdirSync/);
  });
});

// blackdetect's stderr for the given [start, end] intervals in seconds.
const blackdetect = (...intervals) =>
  ['Input #0, matroska,webm, from raw.webm:', ...intervals.map(([s, e]) => `[blackdetect @ 0x5] black_start:${s} black_end:${e} black_duration:${(e - s).toFixed(3)}`), 'video:0kB'].join('\n');
// A detect() that answers the k-th call with answers[k] and records the filters.
function scripted(...answers) {
  const filters = [];
  const detect = (filter) => {
    filters.push(filter);
    assert.ok(filters.length <= answers.length, `detect() called ${filters.length} times, scripted ${answers.length}`);
    return answers[filters.length - 1];
  };
  return { detect, filters };
}
const FILTERS = LEAD_IN_DETECTIONS.map((d) => d.filter);

describe('the lead-in cut and its page-clock cross-check', () => {
  // A page-clock estimate of 900 ms expects the cut at 840 ms (the page
  // clock runs 60 ms late), and accepts 640 to 1040 ms.
  it('parses every black interval, in order', () => {
    assert.deepEqual(parseBlackIntervals(blackdetect([0, 0.84], [3.2, 3.24])), [
      { start: 0, end: 0.84 },
      { start: 3.2, end: 3.24 },
    ]);
    assert.deepEqual(parseBlackIntervals('no black here'), []);
  });

  it('tries three different detections, the first finding any black frame', () => {
    assert.equal(FILTERS.length, 3);
    assert.equal(new Set(FILTERS).size, 3);
    assert.match(FILTERS[0], /^blackdetect=d=0\.01:/);
    for (const f of FILTERS) assert.match(f, /^blackdetect=d=[\d.]+:pix_th=[\d.]+:pic_th=[\d.]+$/);
  });

  it('in tolerance: takes the first detection, runs it once and logs the delta', () => {
    const { detect, filters } = scripted(blackdetect([0, 0.84]));
    const lead = detectLeadIn({ estimateMs: 900.4, detect });
    assert.deepEqual(filters, [FILTERS[0]]);
    assert.equal(lead.cutSeconds, 0.84);
    assert.equal(lead.deltaMs, -60);
    assert.equal(lead.detection, 1);
    assert.equal(leadInLine(lead, 900.4), 'lead-in cut 0.840 s, page-clock estimate 900 ms, delta -60 ms (detection 1: any black frame)');
  });

  it('accepts a cut 200 ms either side of the expected one, and not 201 ms', () => {
    for (const end of [0.64, 1.04]) assert.equal(detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, end])).detect }).cutSeconds, end);
    for (const end of [0.639, 1.041]) {
      const { detect, filters } = scripted(blackdetect([0, end]), blackdetect([0, end]), blackdetect([0, end]));
      assert.throws(() => detectLeadIn({ estimateMs: 900, detect }), /fails the page-clock cross-check/);
      assert.equal(filters.length, 3);
    }
  });

  it('takes the black interval whose end is nearest the expected cut, not the first', () => {
    // 0.84 is the expected cut; 0.95 is nearer the raw estimate (900 ms),
    // and 0.30 comes first.
    const lead = detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.3], [0.5, 0.95], [0.6, 0.84])).detect });
    assert.equal(lead.cutSeconds, 0.84);
    assert.deepEqual(lead.black, { start: 0.6, end: 0.84 });
    // A first interval of 0.08 s (outside the tolerance) loses to the next.
    assert.equal(detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.08], [0.1, 0.8])).detect }).cutSeconds, 0.8);
  });

  it('out then in: retries on the same recording with the next detection', () => {
    const { detect, filters } = scripted(blackdetect([0, 0.08]), blackdetect([0.1, 0.86]));
    const lead = detectLeadIn({ estimateMs: 900, detect });
    assert.deepEqual(filters, FILTERS.slice(0, 2));
    assert.equal(lead.cutSeconds, 0.86);
    assert.equal(lead.deltaMs, -40);
    assert.equal(lead.detection, 2);
    assert.deepEqual(lead.tried, ['1. any black frame: cut 0.080 s, delta -820 ms', '2. black of 0.3 s or more: cut 0.860 s, delta -40 ms']);
    assert.match(leadInLine(lead, 900), /^lead-in cut 0\.860 s, page-clock estimate 900 ms, delta -40 ms \(detection 2: black of 0\.3 s or more\)$/);
  });

  it('a detection that finds no black at all counts as out of tolerance', () => {
    const { detect, filters } = scripted('nothing', blackdetect([0, 0.84]));
    assert.equal(detectLeadIn({ estimateMs: 900, detect }).detection, 2);
    assert.equal(filters.length, 2);
  });

  it('a recording whose frames froze after t0 fails instead of being cut seconds late', () => {
    // Seen under load: black from 0.12 to 5.24 s in a recording whose page
    // clock put t0 near 0.9 s. Every detection finds the same interval.
    const frozen = blackdetect([0.12, 5.24]);
    const { detect, filters } = scripted(frozen, frozen, frozen);
    assert.throws(() => detectLeadIn({ estimateMs: 905, detect }), /page-clock estimate 905 ms, expected cut 845 ms .*cut 5\.240 s, delta 4335 ms$/);
    assert.equal(filters.length, 3);
  });

  it('always out: fails after three detections, with every number', () => {
    const { detect, filters } = scripted(blackdetect([0, 1.2]), 'nothing', blackdetect([0, 0.5], [1, 1.3]));
    let error;
    assert.throws(
      () => detectLeadIn({ estimateMs: 900, detect }),
      (e) => {
        error = e;
        return true;
      },
    );
    assert.deepEqual(filters, FILTERS);
    assert.equal(
      error.message,
      'lead-in cut fails the page-clock cross-check after 3 detections: page-clock estimate 900 ms, expected cut 840 ms +/- 200 ms; ' +
        '1. any black frame: cut 1.200 s, delta 300 ms; 2. black of 0.3 s or more: no black interval; ' +
        '3. near-black of 0.3 s or more: cut 0.500 s, delta -400 ms',
    );
    assert.equal(error.constructor.name, 'RenderError');
  });
});
