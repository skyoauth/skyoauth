# Demo walk-through player and renderer

The player, the transcript checker and the render script of
[the demo walk-through proposal](../../docs/proposals/demo-walkthroughs.md)
(§2 "The mechanism", §5). No journey exists yet: the only transcript is
`sample/sample.transcript.jsonl`, an invented sample. A walk-through is not
evidence; only the conformance scenarios gate a release.

## Run

Node 24 (22 works), and for rendering Chromium for Playwright and ffmpeg
(with ffprobe and libx264).

```bash
cd scripts/demo
npm ci --ignore-scripts
npx playwright install --with-deps chromium   # rendering only
cd ../..

node scripts/demo/transcript.mjs check scripts/demo/sample/sample.transcript.jsonl
node scripts/demo/render.mjs scripts/demo/sample/sample.transcript.jsonl --out scripts/demo/out

node --test scripts/demo/transcript.test.mjs scripts/demo/timing.test.mjs scripts/demo/vtt.test.mjs
node --test scripts/demo/render.e2e.test.mjs   # needs Chromium and ffmpeg; fails without them
```

`render.mjs` writes `<name>.mp4` (H.264, yuv420p, 1280x720, 30 fps, no audio,
faststart), `<name>.vtt`, a byte copy `<name>.transcript.jsonl` and
`SHA256SUMS`. A missing ffmpeg, ffprobe or browser is an error, never a skip.
Both commands take `--secret-env NAME` (repeatable): a record holding the
value of that environment variable is refused.

## Transcript format

UTF-8 JSON lines, each exactly `{"step":N,"type":T,"text":S}` as
`JSON.stringify` writes it (that key order, no spaces), with a final line
feed. `type` is `caption` (the caption bar), `command` (typed at the prompt),
`output` or `note` (a dim annotation such as a captioned library call); only
`output` and `note` may hold `\n`. `step` counts from 0 with no gap. The
checker refuses unknown fields and types, wall-clock fields and
timestamp-like values (a date with a time, an HTTP date, a time of day with
seconds, a 10- or 13-digit Unix time; a bare date is allowed), PEM blocks,
JWT-shaped strings, Bearer credentials (write `<redacted>`), CR, other
control and bidirectional characters, a displayed line over 120 characters,
a record over 16 KiB and a missing final line feed. Errors are `file:line:`
messages; exit 1 on errors, 2 on a usage error (an empty file list included).

## Timing and determinism

`timing.js` is the one timing model: the player, the WebVTT writer and the
renderer all use it. Every time is computed from a record's step index and
content only (a fixed typing speed per character, fixed pauses), never from
a clock. Two runs of a journey must give byte-identical transcripts: the
transcript (and the VTT made from it) is what is compared, never the mp4,
which is only as stable as the browser and the encoder.

The player holds a pure black screen for `LEAD_IN_MS` before its first frame
(t0). The recording starts earlier, with the page load, so the renderer runs
ffmpeg's `blackdetect` on the raw recording (any black frame counts; the
player's own frames are never black) and starts the mp4 at the end of the
first black interval: time 0 of the mp4 is t0 and the VTT cues line up to
about one frame of the 25 fps recording. It also prints the lead-in as the
page's clock saw it, as a cross-check (locally, over a dozen renders: cuts
of 0.80 to 0.92 s against estimates of 852 to 932 ms, never more than 80 ms
apart; the estimate is later, presumably because the recording starts a
little after the page is created). `render.e2e.test.mjs` checks that frame 0 is the player
and that the caption bar changes at each cue boundary and not before;
`vtt.test.mjs` runs the player's own script on a virtual clock and checks
that each caption appears exactly at its cue's start.

## Never committed

The mp4 files and `out/` (in `.gitignore`). The videos are run artifacts of
`.github/workflows/demo.yml`, which is not part of `CI passed`; the
`demo-transcripts` job of `ci.yml` checks the committed transcripts on every
change.
