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

import { LEAD_IN_FILTER, LEAD_IN_LATE_SLACK_MS, RECORDING_FRAME_MS, detectLeadIn, keepRawRecording, leadInLine, outputName, parseBlackIntervals, publishFiles } from './render.mjs';
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

  it('keeps nothing, and creates nothing, when no recording was written', () => {
    const empty = join(TMP, 'raw-empty');
    mkdirSync(empty);
    const dest = join(TMP, 'kept-nothing');
    assert.equal(keepRawRecording(empty, dest), 'DEMO_KEEP_RAW: no raw recording was written, nothing kept');
    assert.equal(keepRawRecording(join(TMP, 'raw-missing'), dest), 'DEMO_KEEP_RAW: no raw recording was written, nothing kept');
    assert.equal(existsSync(dest), false);
  });

  it('a raw directory that cannot be read is reported as that, not as an empty one', () => {
    // A file where the directory should be: readdir fails with ENOTDIR (a
    // permission error, EACCES, takes the same path; as root it cannot be
    // provoked with chmod).
    const notADir = join(TMP, 'raw-is-a-file');
    writeFileSync(notADir, 'x');
    const dest = join(TMP, 'kept-unreadable');
    assert.equal(keepRawRecording(notADir, dest), 'DEMO_KEEP_RAW: could not read the raw recording directory (ENOTDIR), nothing kept');
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
// A detect() that answers its one call with `answer` and records the filters.
function scripted(answer) {
  const filters = [];
  const detect = (filter) => {
    filters.push(filter);
    assert.equal(filters.length, 1, 'detect() called more than once');
    return answer;
  };
  return { detect, filters };
}
const failure = (fn) => {
  let error;
  assert.throws(fn, (e) => {
    error = e;
    return true;
  });
  assert.equal(error.constructor.name, 'RenderError');
  return error.message;
};

describe('the lead-in cut and its page-clock late bound', () => {
  // A page-clock estimate of 900 ms accepts a cut up to 980 ms (two 40 ms
  // frames of the 25 fps recording later), and any cut before that.
  it('parses every black interval, in order', () => {
    assert.deepEqual(parseBlackIntervals(blackdetect([0, 0.84], [3.2, 3.24])), [
      { start: 0, end: 0.84 },
      { start: 3.2, end: 3.24 },
    ]);
    assert.deepEqual(parseBlackIntervals('no black here'), []);
  });

  it('the late slack is two frames of the 25 fps recording', () => {
    assert.equal(RECORDING_FRAME_MS, 40);
    assert.equal(LEAD_IN_LATE_SLACK_MS, 80);
  });

  it('runs one detection, any black frame, and logs the cut, the estimate and the delta', () => {
    const { detect, filters } = scripted(blackdetect([0, 0.84]));
    const lead = detectLeadIn({ estimateMs: 900.4, detect });
    assert.deepEqual(filters, [LEAD_IN_FILTER]);
    assert.match(LEAD_IN_FILTER, /^blackdetect=d=0\.01:pix_th=[\d.]+:pic_th=[\d.]+$/);
    assert.equal(lead.cutSeconds, 0.84);
    assert.deepEqual(lead.black, { start: 0, end: 0.84 });
    assert.equal(lead.deltaMs, -60);
    assert.equal(leadInLine(lead, 900.4), 'lead-in cut 0.840 s, page-clock estimate 900 ms, delta -60 ms (late bound +80 ms)');
  });

  it('accepts a cut up to two frames after the estimate, and fails one a millisecond later', () => {
    assert.equal(detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.98])).detect }).deltaMs, 80);
    assert.match(failure(() => detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.981])).detect })), /^lead-in cut 0\.981 s is later than the page clock allows: .* delta 81 ms;/);
  });

  it('a late cut fails, with every number', () => {
    const message = failure(() => detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.3], [0.5, 1.2])).detect }));
    assert.equal(
      message,
      'lead-in cut 1.200 s is later than the page clock allows: page-clock estimate 900 ms, late bound 980 ms ' +
        '(estimate + 80 ms, two 25 fps frames), delta 300 ms; black intervals 0.000-0.300 s, 0.500-1.200 s',
    );
  });

  it('a cut far before the estimate passes: there is no early-side check', () => {
    // newPage() returning late under load puts the estimate hundreds of ms
    // after t0 in the recording; the cut is still correct.
    for (const [end, estimateMs, deltaMs] of [
      [0.84, 1300, -460],
      [0.12, 2000, -1880],
    ]) {
      const lead = detectLeadIn({ estimateMs, detect: scripted(blackdetect([0, end])).detect });
      assert.equal(lead.cutSeconds, end);
      assert.equal(lead.deltaMs, deltaMs);
    }
  });

  it('takes the black interval whose end is nearest the estimate, not the first', () => {
    // 0.95 is nearest the estimate (900 ms); 0.30 comes first (and the
    // earlier intervals are ignored, as a start-up flash).
    const lead = detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.3], [0.5, 0.84], [0.86, 0.95])).detect });
    assert.equal(lead.cutSeconds, 0.95);
    assert.deepEqual(lead.black, { start: 0.86, end: 0.95 });
    // Nearest, early or late: 0.97 (70 ms late) beats 0.75 (150 ms early).
    assert.equal(detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.75], [0.8, 0.97])).detect }).cutSeconds, 0.97);
    // Not the last either: 0.88 is nearest, and the black after it fails
    // the render (taking the last, 0.95, would pass a cut after a flash).
    assert.match(
      failure(() => detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.3], [0.5, 0.88], [0.9, 0.95])).detect })),
      /^black after the lead-in cut 0\.880 s .* first at 0\.900 s:/,
    );
  });

  it('black before the chosen interval (a start-up flash) is ignored: the cut drops it', () => {
    const lead = detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0, 0.04], [0.2, 0.84])).detect });
    assert.equal(lead.cutSeconds, 0.84);
    assert.deepEqual(lead.black, { start: 0.2, end: 0.84 });
  });

  it('any black after the chosen cut fails, with every number: the nearest endpoint was a start-up flash', () => {
    // The reviewer's controlled recording: black ending at 0.040 s and at
    // 5.240 s, page clock 905 ms. 0.040 is nearest and within the bound,
    // but 5.1 s of black would follow t0 in the mp4.
    assert.equal(
      failure(() => detectLeadIn({ estimateMs: 905, detect: scripted(blackdetect([0, 0.04], [0.12, 5.24])).detect })),
      "black after the lead-in cut 0.040 s (the player's frames are never black: a frozen or blank recording), first at 0.120 s: " +
        'page-clock estimate 905 ms, late bound 985 ms (estimate + 80 ms, two 25 fps frames), delta -865 ms; ' +
        'black intervals 0.000-0.040 s, 0.120-5.240 s',
    );
  });

  it('a frozen tail after a valid cut fails', () => {
    // A valid lead-in (0.10-0.84 s, page clock 900 ms), then a long black
    // interval later in the recording.
    assert.match(
      failure(() => detectLeadIn({ estimateMs: 900, detect: scripted(blackdetect([0.1, 0.84], [3, 7.5])).detect })),
      /^black after the lead-in cut 0\.840 s .*first at 3\.000 s: .*delta -60 ms; black intervals 0\.100-0\.840 s, 3\.000-7\.500 s$/,
    );
    // Seen locally with 8 renders at once (and passed before this check):
    // the t0 frame, then 4.2 s of black.
    assert.match(
      failure(() => detectLeadIn({ estimateMs: 1816, detect: scripted(blackdetect([0.28, 1.48], [1.52, 5.72])).detect })),
      /^black after the lead-in cut 1\.480 s .*first at 1\.520 s: .*delta -336 ms; black intervals 0\.280-1\.480 s, 1\.520-5\.720 s$/,
    );
  });

  it('no black interval at all fails, with the estimate', () => {
    assert.equal(
      failure(() => detectLeadIn({ estimateMs: 900, detect: scripted('nothing').detect })),
      'no black lead-in found in the recording: page-clock estimate 900 ms, late bound 980 ms (estimate + 80 ms, two 25 fps frames)',
    );
  });

  it('a recording whose frames froze after t0 fails instead of being cut seconds late', () => {
    // Seen under load: black from 0.12 to 5.24 s in a recording whose page
    // clock put t0 near 0.9 s.
    assert.match(
      failure(() => detectLeadIn({ estimateMs: 905, detect: scripted(blackdetect([0.12, 5.24])).detect })),
      /^lead-in cut 5\.240 s is later than the page clock allows: page-clock estimate 905 ms, late bound 985 ms .*, delta 4335 ms; black intervals 0\.120-5\.240 s$/,
    );
  });
});

describe('render() and its page clock', () => {
  const source = readFileSync(join(HERE, 'render.mjs'), 'utf8');
  const record = source.slice(source.indexOf('async function record('), source.indexOf('export function publishFiles('));
  const body = source.slice(source.indexOf('export async function render('), source.indexOf('const USAGE'));

  it('takes the page-clock start before newPage() is called, and estimates t0 from it', () => {
    const start = /\n    const (\w+) = Date\.now\(\);\n(?:    \/\/.*\n)*    const page = await context\.newPage\(\);\n/.exec(record);
    assert.ok(start, 'Date.now() taken on the line before await context.newPage()');
    assert.equal(record.match(/Date\.now\(\)/g).length, 1, 'one Date.now() in record()');
    assert.match(record, new RegExp(`leadInEstimateMs: report\\.t0Epoch - ${start[1]} \\}`));
  });

  it('logs the lead-in cut line of every render, once, after the cut is found', () => {
    const logged = body.match(/\blog\(`render: \$\{leadInLine\(lead, leadInEstimateMs\)\}`\);/g);
    assert.equal(logged?.length, 1, 'render() logs leadInLine(lead, leadInEstimateMs)');
    assert.ok(body.indexOf(logged[0]) > body.indexOf('lead = detectLeadIn('), 'logged after detectLeadIn');
    assert.ok(body.indexOf(logged[0]) < body.indexOf("'ffmpeg encode'"), 'logged before the encode');
  });
});
