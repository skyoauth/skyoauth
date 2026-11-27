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

import { keepRawRecording, outputName, publishFiles } from './render.mjs';
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

  it('render() reports the copy and rethrows its own error', () => {
    const source = readFileSync(join(HERE, 'render.mjs'), 'utf8');
    const handler = /\} catch \(e\) \{\n([\s\S]*?)\n  \} finally \{/.exec(source.slice(source.indexOf('export async function render(')));
    assert.ok(handler, 'render() has a catch (e) ... finally');
    assert.match(handler[1], /if \(env\.DEMO_KEEP_RAW\) warn\(`render: \$\{keepRawRecording\(rawDir, env\.DEMO_KEEP_RAW\)\}`\);/);
    assert.match(handler[1], /\n    throw e;$/);
    assert.doesNotMatch(handler[1], /cpSync|mkdirSync/);
  });
});
