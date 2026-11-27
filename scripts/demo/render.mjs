#!/usr/bin/env node
// Renders a demo transcript to a video (docs/proposals/demo-walkthroughs.md
// §2 "Rendering").
//
//   node scripts/demo/render.mjs <transcript.jsonl> --out <dir> [--secret-env NAME]... [--secret-file PATH]...
//
// Writes into <dir>, for <name>.transcript.jsonl or <name>.jsonl:
//   <name>.mp4               H.264, yuv420p, 1280x720, 30 fps, no audio, faststart
//   <name>.vtt               WebVTT captions (timing.js, as the player shows them)
//   <name>.transcript.jsonl  a byte copy of the transcript
//   SHA256SUMS               sha256sum -c format over the three files
//
// The transcript is validated first (transcript.mjs). Chromium, driven by
// Playwright, records player.html (recordVideo, 1280x720) while it plays the
// records; ffmpeg cuts the load lead-in and encodes. The player holds a pure
// black screen for timing.js LEAD_IN_MS before its first frame (t0); the
// renderer finds the end of the first black interval of the recording with
// ffmpeg's blackdetect filter and starts the mp4 there, so time 0 of the
// mp4 is t0 of the timeline and the VTT cues line up (to a frame of the
// 25 fps recording). Every render logs the cut, the page clock's own
// estimate of t0 and their difference, and the cut must agree with that
// estimate (detectLeadIn); otherwise blackdetect runs again on the same
// recording with other settings, and the render fails with every number
// when none agrees. During the lead-in the player repaints a 4px corner
// square in two shades that blackdetect counts as black, so the screencast
// keeps receiving black frames (twice locally, before that repaint existed,
// a render found no black interval at all), and stops LEAD_IN_QUIET_MS
// before t0: a screencast busy with that repaint delivered the t0 frame
// late and the cut with it (see the README). DEMO_KEEP_RAW=<dir>
// keeps the raw recording of a failed render for inspection; a copy that
// fails is reported on stderr and never replaces the render's own error.
//
// Missing ffmpeg, ffprobe or browser is an error (exit 1), never a skip.
// FFMPEG and FFPROBE override the binaries' paths.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import timing from './timing.js';
import { recordsFromBytes, secretsFromEnv, secretsFromFile } from './transcript.mjs';
import { toVtt } from './vtt.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const WIDTH = 1280;
export const HEIGHT = 720;
export const FPS = 30;
// Largest accepted gap between a step's planned and actual start in the
// page. A larger one means the recording is out of step with the VTT.
export const MAX_DRIFT_MS = 500;

class RenderError extends Error {}

export function outputName(transcriptPath) {
  return basename(transcriptPath).replace(/\.jsonl$/, '').replace(/\.transcript$/, '');
}

function run(cmd, args, what) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error) {
    throw new RenderError(
      r.error.code === 'ENOENT' ? `${what} not found (${cmd}): install it (Ubuntu: apt-get install ffmpeg) or set its path` : `${what}: ${r.error.message}`,
    );
  }
  if (r.status !== 0) throw new RenderError(`${what} failed (exit ${r.status}): ${cmd} ${args.join(' ')}\n${r.stderr.slice(-4000)}`);
  return r;
}

export function requireTools(env = process.env) {
  const ffmpeg = env.FFMPEG || 'ffmpeg';
  const ffprobe = env.FFPROBE || 'ffprobe';
  run(ffmpeg, ['-hide_banner', '-version'], 'ffmpeg');
  run(ffprobe, ['-hide_banner', '-version'], 'ffprobe');
  const encoders = run(ffmpeg, ['-hide_banner', '-encoders'], 'ffmpeg').stdout;
  if (!/\blibx264\b/.test(encoders)) throw new RenderError(`ffmpeg (${ffmpeg}) has no libx264 encoder`);
  return { ffmpeg, ffprobe };
}

// Every black interval blackdetect reported, in order: [{ start, end }].
export function parseBlackIntervals(stderr) {
  return [...String(stderr).matchAll(/black_start:\s*([\d.]+)\s+black_end:\s*([\d.]+)/g)].map((m) => ({ start: Number(m[1]), end: Number(m[2]) }));
}

// The page-clock cross-check of the lead-in cut. The page's own estimate of
// t0 (its t0 in epoch time less the time the page was created) runs later
// than t0 in the recording by about PAGE_CLOCK_OFFSET_MS, because the
// recording's time 0 is its first frame, which comes after the page is
// created (14 to 75 ms after, median 60, over 12 renders measured against
// the visible steps). A cut is accepted within LEAD_IN_TOLERANCE_MS of
// estimate - PAGE_CLOCK_OFFSET_MS. Locally, over 125 renders, the cut was
// -101 to +86 ms off that (-43 to +62 one render at a time; the rest two
// at a time on two cores), in 40 ms steps (the 25 fps recording). The page
// clock scatters more the busier the machine: the -101 was a correct cut
// (25 ms from t0 found from the visible steps) with an estimate 137 ms
// late. 200 ms, twice the worst seen, leaves room for a slower runner. The
// check is for errors of a quarter second and more (a recording whose
// frames froze for 4.4 s after t0 under load, a wrong black interval); a
// cut a frame or two off is within the page clock's own scatter, and the
// quiet lead-in, checked by the e2e test, is what keeps the cut on its
// frame.
export const PAGE_CLOCK_OFFSET_MS = 60;
export const LEAD_IN_TOLERANCE_MS = 200;
// The detections tried, in order, on the same raw recording (never a new
// recording), until one gives a cut that passes the cross-check: any black
// frame; only black intervals of 0.3 s or more; and near-black ones of
// 0.3 s or more. In each, the interval whose end is nearest the expected
// cut is taken.
export const LEAD_IN_DETECTIONS = [
  { name: 'any black frame', filter: 'blackdetect=d=0.01:pix_th=0.05:pic_th=0.98' },
  { name: 'black of 0.3 s or more', filter: 'blackdetect=d=0.3:pix_th=0.05:pic_th=0.98' },
  { name: 'near-black of 0.3 s or more', filter: 'blackdetect=d=0.3:pix_th=0.10:pic_th=0.95' },
];

// Finds the lead-in cut. `detect(filter)` runs one blackdetect filter on
// the raw recording and returns ffmpeg's stderr; `estimateMs` is the page
// clock estimate of t0 in the recording. Returns { cutSeconds, black,
// deltaMs, detection, tried }: deltaMs is the cut less the estimate,
// detection the 1-based index in LEAD_IN_DETECTIONS. Throws a RenderError
// with every measurement when no detection passes: a cut outside the
// cross-check is never used.
export function detectLeadIn({ estimateMs, detect }) {
  const expectedMs = estimateMs - PAGE_CLOCK_OFFSET_MS;
  const off = (black) => Math.abs(Math.round(black.end * 1000) - expectedMs);
  const tried = [];
  for (const [i, detection] of LEAD_IN_DETECTIONS.entries()) {
    const intervals = parseBlackIntervals(detect(detection.filter));
    if (intervals.length === 0) {
      tried.push(`${i + 1}. ${detection.name}: no black interval`);
      continue;
    }
    const black = intervals.reduce((a, b) => (off(b) < off(a) ? b : a));
    const deltaMs = Math.round(Math.round(black.end * 1000) - estimateMs);
    tried.push(`${i + 1}. ${detection.name}: cut ${black.end.toFixed(3)} s, delta ${deltaMs} ms`);
    if (off(black) <= LEAD_IN_TOLERANCE_MS) {
      return { cutSeconds: black.end, black, deltaMs, detection: i + 1, tried };
    }
  }
  throw new RenderError(
    `lead-in cut fails the page-clock cross-check after ${LEAD_IN_DETECTIONS.length} detections: page-clock estimate ${Math.round(estimateMs)} ms, ` +
      `expected cut ${Math.round(expectedMs)} ms +/- ${LEAD_IN_TOLERANCE_MS} ms; ${tried.join('; ')}`,
  );
}

// The line every render logs for its lead-in cut.
export function leadInLine(lead, estimateMs) {
  return (
    `lead-in cut ${lead.cutSeconds.toFixed(3)} s, page-clock estimate ${Math.round(estimateMs)} ms, delta ${lead.deltaMs} ms ` +
    `(detection ${lead.detection}: ${LEAD_IN_DETECTIONS[lead.detection - 1].name})`
  );
}

function probeDurationSeconds(ffprobe, file) {
  // Playwright's webm carries no duration in its header: count the time of
  // the last packet instead.
  const r = run(ffprobe, ['-v', 'error', '-select_streams', 'v:0', '-show_entries', 'packet=pts_time', '-of', 'csv=p=0', file], 'ffprobe');
  const times = r.stdout.split('\n').map(Number).filter((x) => Number.isFinite(x) && x > 0);
  return times.length ? Math.max(...times) : 0;
}

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

async function launchBrowser() {
  let playwright;
  try {
    playwright = await import('playwright');
  } catch (e) {
    throw new RenderError(`cannot load playwright (${e.code ?? e.message}): run npm ci --ignore-scripts in scripts/demo`);
  }
  try {
    return await playwright.chromium.launch({ args: ['--force-color-profile=srgb', '--font-render-hinting=none'] });
  } catch (e) {
    throw new RenderError(
      `cannot launch Chromium for Playwright: ${String(e.message).split('\n')[0]}\n` +
        'install it with: npx playwright install --with-deps chromium (in scripts/demo)',
    );
  }
}

// Plays the records in the player and returns the raw recording's path
// (inside rawDir) with the page's report.
async function record(records, rawDir) {
  const browser = await launchBrowser();
  try {
    const context = await browser.newContext({
      viewport: { width: WIDTH, height: HEIGHT },
      deviceScaleFactor: 1,
      colorScheme: 'dark',
      locale: 'en-US',
      timezoneId: 'UTC',
      recordVideo: { dir: rawDir, size: { width: WIDTH, height: HEIGHT } },
    });
    const blocked = [];
    await context.route('**/*', (route) => {
      const url = route.request().url();
      if (url.startsWith('file:')) return route.continue();
      blocked.push(url);
      return route.abort();
    });
    const page = await context.newPage();
    const recordingStartedAt = Date.now();
    const pageErrors = [];
    page.on('pageerror', (e) => pageErrors.push(e.message));
    await page.goto(pathToFileURL(join(HERE, 'player.html')).href);
    await page.waitForFunction(() => typeof window.playTranscript === 'function' && typeof window.DemoTiming === 'object');
    const report = await page.evaluate(async (rs) => {
      const r = await window.playTranscript(rs);
      return { ...r, t0Epoch: performance.timeOrigin + r.t0, done: window.__demoDone };
    }, records);
    const video = page.video();
    await context.close();
    const rawPath = await video.path();
    if (pageErrors.length) throw new RenderError(`the player threw: ${pageErrors.join('; ')}`);
    if (blocked.length) throw new RenderError(`the player tried to reach the network: ${blocked.join(', ')}`);
    if (report.done !== true) throw new RenderError('the player did not set window.__demoDone');
    return { rawPath, report, leadInEstimateMs: report.t0Epoch - recordingStartedAt };
  } finally {
    await browser.close();
  }
}

// Writes the VTT, the transcript copy and SHA256SUMS beside <name>.mp4 in
// outDir, from the snapshot `bytes` and its `records` (never from the input
// path). Returns the four paths.
export function publishFiles({ outDir, name, bytes, records }) {
  const mp4 = `${name}.mp4`;
  const vtt = `${name}.vtt`;
  const copy = `${name}.transcript.jsonl`;
  writeFileSync(join(outDir, vtt), toVtt(records));
  writeFileSync(join(outDir, copy), bytes);
  const sums = [copy, mp4, vtt].sort().map((f) => `${sha256(join(outDir, f))}  ${f}\n`).join('');
  writeFileSync(join(outDir, 'SHA256SUMS'), sums);
  return { mp4: join(outDir, mp4), vtt: join(outDir, vtt), transcript: join(outDir, copy), sums: join(outDir, 'SHA256SUMS') };
}

// DEMO_KEEP_RAW=<dir>: copies the raw recording directory of a failed
// render into `dest`. Never throws, so a failed copy cannot replace the
// render's own error: returns a line saying what happened.
export function keepRawRecording(rawDir, dest) {
  try {
    mkdirSync(dest, { recursive: true });
    cpSync(rawDir, dest, { recursive: true });
    return `kept the raw recording in ${dest}`;
  } catch (e) {
    return `DEMO_KEEP_RAW: could not keep the raw recording in ${dest} (${e.code ?? 'error'})`;
  }
}

export async function render(transcriptPath, outDir, { secretEnv = [], secretFiles = [], env = process.env, log = console.log, warn = console.error } = {}) {
  const secrets = secretsFromEnv(secretEnv, env);
  for (const f of secretFiles) for (const [k, v] of secretsFromFile(f)) secrets.set(k, v);
  // The one read of the transcript: validation, playback, the captions, the
  // published copy and its checksum all use this snapshot, so a file
  // changed during the render cannot publish unchecked bytes.
  const bytes = readFileSync(transcriptPath);
  const records = recordsFromBytes(bytes, transcriptPath, { secrets });
  const { ffmpeg, ffprobe } = requireTools(env);
  const timeline = timing.buildTimeline(records);
  const totalMs = timing.totalMs(timeline);

  const rawDir = mkdtempSync(join(tmpdir(), 'skyoauth-demo-raw-'));
  try {
    const { rawPath, report, leadInEstimateMs } = await record(records, rawDir);
    const drift = Math.max(0, ...report.events.map((e) => Math.abs(e.actualMs - e.plannedMs)));
    if (drift > MAX_DRIFT_MS) throw new RenderError(`the player ran ${Math.round(drift)} ms off its schedule (cap ${MAX_DRIFT_MS} ms)`);

    // The player's frames are never black (its light title bar alone is
    // over 2 % of the picture), so the end of the lead-in's black interval
    // is t0 however late the recording started. detectLeadIn cross-checks
    // it against the page clock and fails rather than use a doubtful cut.
    const rawSeconds = probeDurationSeconds(ffprobe, rawPath);
    let lead;
    try {
      lead = detectLeadIn({
        estimateMs: leadInEstimateMs,
        detect: (filter) => run(ffmpeg, ['-hide_banner', '-nostats', '-i', rawPath, '-vf', filter, '-an', '-f', 'null', '-'], 'ffmpeg blackdetect').stderr,
      });
    } catch (detectError) {
      if (detectError instanceof RenderError) detectError.message += ` (raw recording ${rawSeconds.toFixed(3)} s)`;
      throw detectError;
    }
    const { black } = lead;
    const leadIn = lead.cutSeconds;
    log(`render: ${leadInLine(lead, leadInEstimateMs)}`);
    const available = rawSeconds - leadIn;
    // The recording must cover the whole timeline (one 25 fps frame of slack).
    if (available + 0.04 < totalMs / 1000) {
      throw new RenderError(`the recording holds ${available.toFixed(3)} s after t0, the timeline needs ${(totalMs / 1000).toFixed(3)} s`);
    }

    mkdirSync(outDir, { recursive: true });
    const name = outputName(transcriptPath);
    const mp4 = `${name}.mp4`;
    run(
      ffmpeg,
      [
        '-hide_banner', '-nostats', '-y',
        '-i', rawPath,
        '-ss', leadIn.toFixed(3),
        '-t', (totalMs / 1000).toFixed(3),
        '-vf', `fps=${FPS},scale=${WIDTH}:${HEIGHT}:flags=bicubic,format=yuv420p`,
        '-an',
        '-c:v', 'libx264', '-preset', 'medium', '-crf', '20', '-pix_fmt', 'yuv420p', '-g', String(FPS * 2),
        '-map_metadata', '-1', '-fflags', '+bitexact', '-flags:v', '+bitexact',
        '-movflags', '+faststart',
        join(outDir, mp4),
      ],
      'ffmpeg encode',
    );
    const files = publishFiles({ outDir, name, bytes, records });

    const result = {
      ...files,
      totalMs,
      leadInSeconds: leadIn,
      leadInEstimateMs: Math.round(leadInEstimateMs),
      leadInDeltaMs: lead.deltaMs,
      leadInDetection: lead.detection,
      maxDriftMs: Math.round(drift),
      captions: records.filter((r) => r.type === 'caption').length,
    };
    log(
      `render: ${records.length} records, timeline ${totalMs} ms, ${result.captions} captions; ` +
        `lead-in black ${black.start.toFixed(3)}-${black.end.toFixed(3)} s; ` +
        `max step drift ${result.maxDriftMs} ms`,
    );
    log(`render: wrote ${result.mp4}, ${result.vtt}, ${result.transcript}, ${result.sums}`);
    return result;
  } catch (e) {
    // DEMO_KEEP_RAW=<dir> keeps the raw recording of a failed render there;
    // the render's error is thrown whether or not that copy works.
    if (env.DEMO_KEEP_RAW) warn(`render: ${keepRawRecording(rawDir, env.DEMO_KEEP_RAW)}`);
    throw e;
  } finally {
    rmSync(rawDir, { recursive: true, force: true });
  }
}

const USAGE = 'usage: node scripts/demo/render.mjs <transcript.jsonl> --out <dir> [--secret-env NAME]... [--secret-file PATH]...';

export async function main(argv) {
  let transcript;
  let out;
  const secretEnv = [];
  const secretFiles = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out' && i + 1 < argv.length) out = argv[++i];
    else if (a === '--secret-env' && i + 1 < argv.length) secretEnv.push(argv[++i]);
    else if (a === '--secret-file' && i + 1 < argv.length) secretFiles.push(resolve(argv[++i]));
    else if (a === '-h' || a === '--help') {
      console.log(USAGE);
      return 0;
    } else if (!a.startsWith('--') && transcript === undefined) transcript = a;
    else {
      console.error(`render: unexpected argument ${JSON.stringify(a)}\n${USAGE}`);
      return 2;
    }
  }
  if (!transcript || !out) {
    console.error(`render: a transcript and --out are required\n${USAGE}`);
    return 2;
  }
  try {
    await render(resolve(transcript), resolve(out), { secretEnv, secretFiles });
    return 0;
  } catch (e) {
    console.error(`render: ${e.message}`);
    return 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = await main(process.argv.slice(2));
}
