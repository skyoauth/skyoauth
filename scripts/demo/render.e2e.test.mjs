// End-to-end test of render.mjs: needs Chromium for Playwright, ffmpeg and
// ffprobe, and fails (never skips) when one is missing.
//   node --test scripts/demo/render.e2e.test.mjs
//
// It renders the sample transcript twice and checks the mp4 (ffprobe:
// 1280x720 H.264 yuv420p, 30 fps, no audio, faststart, duration of the
// timeline), that the first frame is the player and not the black or blank
// lead-in, that the caption bar changes at each VTT cue boundary, the VTT,
// the checksums, and that both runs give the same transcript copy and VTT.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { FPS, HEIGHT, WIDTH, render } from './render.mjs';
import timing from './timing.js';
import { readTranscript } from './transcript.mjs';
import { parseVtt, toVtt } from './vtt.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'render.mjs');
const SAMPLE = join(HERE, 'sample', 'sample.transcript.jsonl');
const RECORDS = readTranscript(SAMPLE);
const TOTAL_MS = timing.totalMs(timing.buildTimeline(RECORDS));
const TMP = mkdtempSync(join(tmpdir(), 'demo-render-e2e-'));
after(() => rmSync(TMP, { recursive: true, force: true }));
const FFMPEG = process.env.FFMPEG || 'ffmpeg';
const FFPROBE = process.env.FFPROBE || 'ffprobe';
// One frame of the 25 fps recording plus one of the 30 fps output, rounded up.
const FRAME_SLACK_S = 0.1;

const sh = (cmd, args, opts = {}) => spawnSync(cmd, args, { maxBuffer: 256 * 1024 * 1024, ...opts });
const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

// Grey pixels of the caption bar (y 610..720) of the frame at `seconds`.
function captionBar(mp4, seconds) {
  const r = sh(FFMPEG, ['-v', 'error', '-ss', seconds.toFixed(3), '-i', mp4, '-frames:v', '1', '-vf', 'crop=1280:110:0:610,format=gray', '-f', 'rawvideo', '-']);
  assert.equal(r.status, 0, String(r.stderr));
  assert.equal(r.stdout.length, 1280 * 110);
  return r.stdout;
}

function meanAbsDiff(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += Math.abs(a[i] - b[i]);
  return sum / a.length;
}

// Top-level MP4 box types in file order.
function topLevelBoxes(path) {
  const buf = readFileSync(path);
  const boxes = [];
  for (let off = 0; off + 8 <= buf.length; ) {
    let size = buf.readUInt32BE(off);
    const type = buf.toString('latin1', off + 4, off + 8);
    if (size === 1) size = Number(buf.readBigUInt64BE(off + 8));
    else if (size === 0) size = buf.length - off;
    boxes.push(type);
    if (size < 8) break;
    off += size;
  }
  return boxes;
}

describe('render.mjs end to end', () => {
  let first;
  let second;
  // Each render's lead-in line (cut, page-clock estimate, delta), printed
  // as a diagnostic so a run's log keeps them.
  const leadInLines = [];
  const keepLeadIn = (line) => {
    if (line.startsWith('render: lead-in cut ')) leadInLines.push(line);
  };
  const outA = join(TMP, 'a');
  const outB = join(TMP, 'b');

  before(async () => {
    // Preconditions are assertions: a missing tool fails the suite.
    for (const tool of [FFMPEG, FFPROBE]) {
      const r = sh(tool, ['-version']);
      assert.ok(!r.error && r.status === 0, `${tool} is required for this test and was not found (install ffmpeg)`);
    }
    const { chromium } = await import('playwright');
    const browser = await chromium.launch().catch((e) => {
      assert.fail(`Chromium for Playwright is required for this test and did not launch (npx playwright install --with-deps chromium): ${e.message.split('\n')[0]}`);
    });
    await browser.close();
    first = await render(SAMPLE, outA, { log: keepLeadIn });
    second = await render(SAMPLE, outB, { log: keepLeadIn });
  });

  it('writes the mp4, the VTT, the transcript copy and SHA256SUMS', () => {
    for (const f of ['sample.mp4', 'sample.vtt', 'sample.transcript.jsonl', 'SHA256SUMS']) assert.ok(existsSync(join(outA, f)), f);
    assert.deepEqual(first.mp4, join(outA, 'sample.mp4'));
  });

  it('encodes 1280x720 H.264 yuv420p at a fixed 30 fps, no audio, for the length of the timeline', () => {
    const r = sh(FFPROBE, ['-v', 'error', '-show_streams', '-show_format', '-of', 'json', first.mp4], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    const probe = JSON.parse(r.stdout);
    assert.equal(probe.streams.length, 1, 'one stream, no audio');
    const [v] = probe.streams;
    assert.equal(v.codec_type, 'video');
    assert.equal(v.codec_name, 'h264');
    assert.equal(v.width, WIDTH);
    assert.equal(v.height, HEIGHT);
    assert.equal(v.pix_fmt, 'yuv420p');
    assert.equal(v.r_frame_rate, `${FPS}/1`);
    assert.equal(v.avg_frame_rate, `${FPS}/1`);
    const duration = Number(probe.format.duration);
    assert.ok(Math.abs(duration - TOTAL_MS / 1000) <= FRAME_SLACK_S, `duration ${duration} s, timeline ${TOTAL_MS / 1000} s`);
  });

  it('puts the moov box before mdat (faststart)', () => {
    const boxes = topLevelBoxes(first.mp4);
    assert.ok(boxes.includes('moov') && boxes.includes('mdat'), boxes.join(','));
    assert.ok(boxes.indexOf('moov') < boxes.indexOf('mdat'), boxes.join(','));
  });

  it('cuts the lead-in: the first frame already shows the player and the first caption', (t) => {
    for (const line of leadInLines) t.diagnostic(line);
    assert.ok(first.leadInSeconds > timing.LEAD_IN_MS / 1000 - FRAME_SLACK_S, `lead-in ${first.leadInSeconds}`);
    // The page clock estimate and the blackdetect cut agree to within a
    // few frames.
    assert.ok(Math.abs(first.leadInSeconds * 1000 - first.leadInEstimateMs) < 250, `${first.leadInSeconds} s vs ${first.leadInEstimateMs} ms`);
    const r = sh(FFMPEG, ['-v', 'error', '-i', first.mp4, '-frames:v', '1', '-vf', 'crop=1280:36:0:0,format=gray', '-f', 'rawvideo', '-']);
    assert.equal(r.status, 0);
    const titleBar = r.stdout.reduce((a, b) => a + b, 0) / r.stdout.length;
    assert.ok(titleBar > 150, `title bar mean grey ${titleBar}: frame 0 is not the player`);
    const bar = captionBar(first.mp4, 0);
    assert.ok(bar.some((p) => p > 200), 'no caption text in frame 0');
  });

  it('changes the caption bar at each VTT cue boundary and not between them', () => {
    const cues = parseVtt(readFileSync(first.vtt, 'utf8'));
    for (const cue of cues.slice(1)) {
      const b = cue.startMs / 1000;
      const beforeA = captionBar(first.mp4, b - 0.5);
      const beforeB = captionBar(first.mp4, b - 0.15);
      const after = captionBar(first.mp4, b + 0.15);
      assert.ok(meanAbsDiff(beforeA, beforeB) < 1, `caption bar changed before the cue at ${b} s`);
      assert.ok(meanAbsDiff(beforeB, after) > 3, `caption bar did not change across the cue at ${b} s`);
    }
  });

  it('writes one VTT cue per caption, timed by timing.js', () => {
    const vtt = readFileSync(first.vtt, 'utf8');
    assert.equal(vtt, toVtt(RECORDS));
    assert.equal(parseVtt(vtt).length, RECORDS.filter((r) => r.type === 'caption').length);
    assert.equal(first.captions, 3);
  });

  it('writes SHA256SUMS that verify', () => {
    const lines = readFileSync(first.sums, 'utf8').trimEnd().split('\n');
    assert.deepEqual(
      lines.map((l) => l.split('  ')[1]),
      ['sample.mp4', 'sample.transcript.jsonl', 'sample.vtt'],
    );
    for (const l of lines) {
      const [hash, name] = l.split('  ');
      assert.equal(hash, sha256(join(outA, name)), name);
    }
  });

  it('gives an identical transcript copy and VTT on a rerun (the mp4 is not compared)', () => {
    assert.equal(sha256(second.transcript), sha256(first.transcript));
    assert.equal(sha256(first.transcript), sha256(SAMPLE));
    assert.equal(sha256(second.vtt), sha256(first.vtt));
  });
});

describe('render.mjs failures', () => {
  const cli = (args, env = {}) => sh(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });

  it('fails with a clear message when ffmpeg is missing', () => {
    const out = join(TMP, 'noffmpeg');
    const r = cli([SAMPLE, '--out', out], { FFMPEG: join(TMP, 'no-such-ffmpeg') });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /render: ffmpeg not found/);
    assert.equal(existsSync(out), false);
  });

  it('fails with a clear message when the browser is missing', () => {
    const out = join(TMP, 'nobrowser');
    const r = cli([SAMPLE, '--out', out], { PLAYWRIGHT_BROWSERS_PATH: mkdtempSync(join(TMP, 'no-browsers-')) });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /render: cannot launch Chromium for Playwright/);
    assert.match(r.stderr, /npx playwright install --with-deps chromium/);
    assert.equal(existsSync(join(out, 'sample.mp4')), false);
  });

  it('keeps the raw recording of a failed render in DEMO_KEEP_RAW', () => {
    const keep = join(TMP, 'keep-raw');
    const r = cli([SAMPLE, '--out', join(TMP, 'nobrowser-keep')], { PLAYWRIGHT_BROWSERS_PATH: mkdtempSync(join(TMP, 'no-browsers-')), DEMO_KEEP_RAW: keep });
    assert.equal(r.status, 1);
    assert.match(r.stderr, new RegExp(`render: kept the raw recording in ${keep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    assert.match(r.stderr, /render: cannot launch Chromium for Playwright/);
    assert.equal(existsSync(keep), true);
  });

  it('a DEMO_KEEP_RAW that cannot be written does not hide the render error', () => {
    const blocker = join(TMP, 'keep-raw-is-a-file');
    writeFileSync(blocker, 'x');
    const r = cli([SAMPLE, '--out', join(TMP, 'nobrowser-nokeep')], { PLAYWRIGHT_BROWSERS_PATH: mkdtempSync(join(TMP, 'no-browsers-')), DEMO_KEEP_RAW: join(blocker, 'raw') });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /render: DEMO_KEEP_RAW: could not keep the raw recording in .* \(ENOTDIR\)/);
    assert.match(r.stderr, /render: cannot launch Chromium for Playwright/);
  });

  it('refuses an invalid transcript before recording anything', () => {
    const out = join(TMP, 'invalid');
    const r = cli([join(HERE, 'render.e2e.test.mjs'), '--out', out]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /render\.e2e\.test\.mjs:1: not JSON/);
    assert.equal(existsSync(out), false);
  });

  it('refuses a missing --out', () => {
    assert.equal(cli([SAMPLE]).status, 2);
  });
});
