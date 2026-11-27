#!/usr/bin/env node
// Renders a demo transcript to a video (docs/proposals/demo-walkthroughs.md
// §2 "Rendering").
//
//   node scripts/demo/render.mjs <transcript.jsonl> --out <dir> [--secret-env NAME]...
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
// 25 fps recording). It also prints a second estimate of the lead-in from
// the page's own clock, as a cross-check.
//
// Missing ffmpeg, ffprobe or browser is an error (exit 1), never a skip.
// FFMPEG and FFPROBE override the binaries' paths.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import timing from './timing.js';
import { readTranscript, secretsFromEnv } from './transcript.mjs';
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

// The first black interval of the recording: [start, end] in seconds.
export function parseBlackdetect(stderr) {
  const m = /black_start:\s*([\d.]+)\s+black_end:\s*([\d.]+)/.exec(stderr);
  return m ? { start: Number(m[1]), end: Number(m[2]) } : null;
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

export async function render(transcriptPath, outDir, { secretEnv = [], env = process.env, log = console.log } = {}) {
  const records = readTranscript(transcriptPath, { secrets: secretsFromEnv(secretEnv, env) });
  const { ffmpeg, ffprobe } = requireTools(env);
  const timeline = timing.buildTimeline(records);
  const totalMs = timing.totalMs(timeline);

  const rawDir = mkdtempSync(join(tmpdir(), 'skyoauth-demo-raw-'));
  try {
    const { rawPath, report, leadInEstimateMs } = await record(records, rawDir);
    const drift = Math.max(0, ...report.events.map((e) => Math.abs(e.actualMs - e.plannedMs)));
    if (drift > MAX_DRIFT_MS) throw new RenderError(`the player ran ${Math.round(drift)} ms off its schedule (cap ${MAX_DRIFT_MS} ms)`);

    // Any black frame counts (d=0.01, below one frame): the player's frames
    // are never black (its light title bar alone is over 2 % of the
    // picture), so the first black interval is the lead-in, and its end is
    // t0 however late the recording started.
    const detect = run(
      ffmpeg,
      ['-hide_banner', '-nostats', '-i', rawPath, '-vf', 'blackdetect=d=0.01:pix_th=0.05:pic_th=0.98', '-an', '-f', 'null', '-'],
      'ffmpeg blackdetect',
    );
    const black = parseBlackdetect(detect.stderr);
    if (!black) {
      throw new RenderError(
        `no black lead-in found in the recording (${probeDurationSeconds(ffprobe, rawPath).toFixed(3)} s; ` +
          `the page clock puts t0 ${Math.round(leadInEstimateMs)} ms after recording started): cannot find t0`,
      );
    }
    const leadIn = black.end;
    const rawSeconds = probeDurationSeconds(ffprobe, rawPath);
    const available = rawSeconds - leadIn;
    // The recording must cover the whole timeline (one 25 fps frame of slack).
    if (available + 0.04 < totalMs / 1000) {
      throw new RenderError(`the recording holds ${available.toFixed(3)} s after t0, the timeline needs ${(totalMs / 1000).toFixed(3)} s`);
    }

    mkdirSync(outDir, { recursive: true });
    const name = outputName(transcriptPath);
    const mp4 = `${name}.mp4`;
    const vtt = `${name}.vtt`;
    const copy = `${name}.transcript.jsonl`;
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
    writeFileSync(join(outDir, vtt), toVtt(records));
    copyFileSync(transcriptPath, join(outDir, copy));
    const sums = [copy, mp4, vtt].sort().map((f) => `${sha256(join(outDir, f))}  ${f}\n`).join('');
    writeFileSync(join(outDir, 'SHA256SUMS'), sums);

    const result = {
      mp4: join(outDir, mp4),
      vtt: join(outDir, vtt),
      transcript: join(outDir, copy),
      sums: join(outDir, 'SHA256SUMS'),
      totalMs,
      leadInSeconds: leadIn,
      leadInEstimateMs: Math.round(leadInEstimateMs),
      maxDriftMs: Math.round(drift),
      captions: records.filter((r) => r.type === 'caption').length,
    };
    log(
      `render: ${records.length} records, timeline ${totalMs} ms, ${result.captions} captions; ` +
        `lead-in cut at ${leadIn.toFixed(3)} s (blackdetect black ${black.start.toFixed(3)}-${black.end.toFixed(3)} s; page clock estimate ${result.leadInEstimateMs} ms); ` +
        `max step drift ${result.maxDriftMs} ms`,
    );
    log(`render: wrote ${result.mp4}, ${result.vtt}, ${result.transcript}, ${result.sums}`);
    return result;
  } finally {
    rmSync(rawDir, { recursive: true, force: true });
  }
}

const USAGE = 'usage: node scripts/demo/render.mjs <transcript.jsonl> --out <dir> [--secret-env NAME]...';

export async function main(argv) {
  let transcript;
  let out;
  const secretEnv = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out' && i + 1 < argv.length) out = argv[++i];
    else if (a === '--secret-env' && i + 1 < argv.length) secretEnv.push(argv[++i]);
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
    await render(resolve(transcript), resolve(out), { secretEnv });
    return 0;
  } catch (e) {
    console.error(`render: ${e.message}`);
    return 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = await main(process.argv.slice(2));
}
