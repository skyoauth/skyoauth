// Pure tests of render.mjs (no browser, no ffmpeg):
//   node --test scripts/demo/render.test.mjs
//
// The transcript is read once: validation, captions, the published copy and
// its checksum come from that snapshot, never from the input path again.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { outputName, publishFiles } from './render.mjs';
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
