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
// renderer runs ffmpeg's blackdetect filter on the recording and starts the
// mp4 at the end of the black interval nearest the page clock's estimate of
// t0, so time 0 of the mp4 is t0 of the timeline and the VTT cues line up
// (to about a frame of the 25 fps recording, as measured; see the README:
// a measurement, not a guarantee). Every render logs the cut, the page
// clock's estimate of t0 and their difference, and the cut must not be
// later than that estimate by more than two recording frames, nor be
// followed by more black (detectLeadIn); otherwise the render fails with
// every number. During
// the lead-in the player repaints a 4px corner square in two shades that
// blackdetect counts as black, so the screencast keeps receiving black
// frames (twice locally, before that repaint existed, a render found no
// black interval at all), and stops LEAD_IN_QUIET_MS before t0: a
// screencast busy with that repaint delivered the t0 frame late and the
// cut with it (see the README). DEMO_KEEP_RAW=<dir> keeps the raw
// recording of a failed render for inspection; a copy that fails is
// reported on stderr and never replaces the render's own error.
//
// Missing ffmpeg, ffprobe or browser is an error (exit 1), never a skip.
// FFMPEG and FFPROBE override the binaries' paths.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import timing from './timing.js';
import { mergeSecrets, recordsFromBytes, secretsFromEnv, secretsFromFile } from './transcript.mjs';
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

// Playwright's recordVideo writes 25 fps (its FfmpegVideoRecorder, -r 25).
export const RECORDING_FPS = 25;
export const RECORDING_FRAME_MS = 1000 / RECORDING_FPS;
// The page-clock check of the lead-in cut is a one-sided late bound. The
// estimate is t0 in the page's epoch time less Date.now() taken just before
// newPage() is called (both wall clock). The recording cannot start before
// that call: Playwright times its frames from a recorder created inside
// newPage(), and time 0 of the webm is no earlier than that. So t0 in the
// recording is at most the estimate, plus the time the t0 frame takes to
// reach the screencast and the 25 fps frame grid: LEAD_IN_LATE_SLACK_MS,
// two recording frames. How much earlier than the estimate the cut is
// depends on how long newPage() and the first frame take, which is
// unbounded under load (with 8 renders at once newPage() returned 87 to
// 298 ms late, and the video started from 177 ms before to 383 ms after
// it returned), so there is no early-side check. None is needed: the cut
// is the end of the lead-in's black interval, the first non-black frame,
// and the player shows nothing but black from its load until t0. The bound
// catches a cut seconds late (a recording whose frames froze for 4.4 s
// after t0 under load, black from 0.12 to 5.24 s). A cut a frame or two
// off is caught by nothing here; the quiet lead-in, checked by the e2e
// test, is what keeps the cut on its frame.
export const LEAD_IN_LATE_SLACK_MS = 2 * RECORDING_FRAME_MS;
// The one blackdetect run: any black frame counts (the player's own frames
// are never black).
export const LEAD_IN_FILTER = 'blackdetect=d=0.01:pix_th=0.05:pic_th=0.98';

// Finds the lead-in cut. `detect(filter)` runs blackdetect on the raw
// recording and returns ffmpeg's stderr; `estimateMs` is the page-clock
// estimate of t0 in the recording (an upper bound on it, to within
// LEAD_IN_LATE_SLACK_MS). Takes the black interval whose end is nearest the
// estimate. Returns { cutSeconds, black, deltaMs }, deltaMs the cut less
// the estimate. Throws a RenderError with every number and every black
// interval when no black interval is found, when the cut is later than
// estimateMs + LEAD_IN_LATE_SLACK_MS, or when any black interval comes
// after the cut: the player's frames are never black, so black after t0 is
// a recording fault (frames that froze), whichever interval the cut took.
// Such a cut is never used.
export function detectLeadIn({ estimateMs, detect }) {
  const boundMs = estimateMs + LEAD_IN_LATE_SLACK_MS;
  const intervals = parseBlackIntervals(detect(LEAD_IN_FILTER));
  const numbers = `page-clock estimate ${Math.round(estimateMs)} ms, late bound ${Math.round(boundMs)} ms (estimate + ${LEAD_IN_LATE_SLACK_MS} ms, two ${RECORDING_FPS} fps frames)`;
  if (intervals.length === 0) throw new RenderError(`no black lead-in found in the recording: ${numbers}`);
  const cutMsOf = (black) => Math.round(black.end * 1000);
  const off = (black) => Math.abs(cutMsOf(black) - estimateMs);
  const black = intervals.reduce((a, b) => (off(b) < off(a) ? b : a));
  const deltaMs = Math.round(cutMsOf(black) - estimateMs);
  const all = `black intervals ${intervals.map((i) => `${i.start.toFixed(3)}-${i.end.toFixed(3)} s`).join(', ')}`;
  if (cutMsOf(black) > boundMs) {
    throw new RenderError(`lead-in cut ${black.end.toFixed(3)} s is later than the page clock allows: ${numbers}, delta ${deltaMs} ms; ${all}`);
  }
  const after = intervals.filter((i) => i !== black && i.start >= black.end);
  if (after.length > 0) {
    throw new RenderError(
      `black after the lead-in cut ${black.end.toFixed(3)} s (the player's frames are never black: a frozen or blank recording), ` +
        `first at ${after[0].start.toFixed(3)} s: ${numbers}, delta ${deltaMs} ms; ${all}`,
    );
  }
  return { cutSeconds: black.end, black, deltaMs };
}

// The line every render logs for its lead-in cut.
export function leadInLine(lead, estimateMs) {
  return `lead-in cut ${lead.cutSeconds.toFixed(3)} s, page-clock estimate ${Math.round(estimateMs)} ms, delta ${lead.deltaMs} ms (late bound +${LEAD_IN_LATE_SLACK_MS} ms)`;
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
    // Taken before newPage(): the recording cannot start earlier, so the
    // estimate below is an upper bound on t0 in the recording (detectLeadIn).
    const newPageCalledAt = Date.now();
    const page = await context.newPage();
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
    return { rawPath, report, leadInEstimateMs: report.t0Epoch - newPageCalledAt };
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
// render's own error: returns a line saying what happened. A render that
// failed before the browser wrote a recording (an empty or missing raw
// directory) keeps nothing and does not create `dest`; a raw directory
// that cannot be read is reported as such, never as an empty one.
export function keepRawRecording(rawDir, dest) {
  let written;
  try {
    written = readdirSync(rawDir);
  } catch (e) {
    if (e.code !== 'ENOENT') return `DEMO_KEEP_RAW: could not read the raw recording directory (${e.code ?? 'error'}), nothing kept`;
    written = [];
  }
  if (written.length === 0) return 'DEMO_KEEP_RAW: no raw recording was written, nothing kept';
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
  for (const f of secretFiles) mergeSecrets(secrets, secretsFromFile(f));
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
    // is t0 however late the recording started. detectLeadIn checks it
    // against the page clock's late bound and fails rather than use a cut
    // later than that.
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
