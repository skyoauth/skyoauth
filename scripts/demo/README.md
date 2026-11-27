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

node --test scripts/demo/transcript.test.mjs scripts/demo/timing.test.mjs scripts/demo/vtt.test.mjs scripts/demo/workflows.test.mjs
node --test scripts/demo/render.e2e.test.mjs   # needs Chromium and ffmpeg; fails without them
```

`render.mjs` reads the transcript once and uses that snapshot for
validation, playback, the captions, the copy and its checksum. It writes
`<name>.mp4` (H.264, yuv420p, 1280x720, 30 fps, no audio,
faststart), `<name>.vtt`, a byte copy `<name>.transcript.jsonl` and
`SHA256SUMS`. A missing ffmpeg, ffprobe or browser is an error, never a skip.
Both commands take `--secret-env NAME` and `--secret-file PATH`
(repeatable): a record holding the value of that environment variable, or
any string under a `seed`, `private_key`, `secret` or `password` key of that
JSON file (a hex value also as upper-case hex, base64 and base64url), is
refused. CI passes every `tests/conformance/fixtures/**/*.test-key.json`.
A message names such a value by the file and its key path
(`recovery.test-key.json keys[0].seed`); a key name that is not plain
`[A-Za-z0-9_]` is shown by its position in its object (`<key 2>`), never
as itself. That position counts in JavaScript property order (as
`Object.keys` lists the parsed object: integer-like keys such as `"1"`
first, in ascending order, then the others in file order), not file order.
No value is dropped: a key repeated in one object (which `JSON.parse` would
keep only once) and a label shared by two files of the same name keep every
value, the later ones labelled `#2`, `#3`, ...

## Transcript format

UTF-8 JSON lines, each exactly `{"step":N,"type":T,"text":S}` as
`JSON.stringify` writes it (that key order, no spaces), optionally with a
fourth key `"allow":"hex-across-lines"` (below), with a final line feed.
`type` is `caption` (the caption bar), `command` (typed at the prompt),
`output` or `note` (dim annotation lines, such as a captioned library call);
only `output` and `note` may hold `\n`. `step` counts from 0 with no gap.
Errors are `file:line:` messages that name the rule or the expected field,
type or JSON position, and never repeat the record's text, its values or
unknown key names (so a rejected secret is not printed into a CI log); exit
1 on errors, 2 on a usage error (an empty file list included).

Refused in each line of a record's text:

- unknown fields, types and allow markers; CR, other control characters and
  bidirectional characters; a line over 120 characters; a record over
  16 KiB; a missing final line feed;
- timestamp-like values: a date with a time, an HTTP date, a time of day
  with seconds, a number of exactly 10 digits (seconds) or 13 (milliseconds)
  whose value is a Unix time from 2001-09-09 to 2286-11-20, whatever the
  number means (a counter or an ID of that size is refused too). A bare
  date is allowed.

Refused in a record's text, in that text with its line feeds removed (and
with them replaced by spaces), in each pair of adjacent records of any type,
and in each run of three or more consecutive `output` and `note` records
(texts concatenated directly, and joined with spaces); these joined forms
are what the allow marker below and the Authorization rule refer to:

- a PEM header (`-----BEGIN ...-----`);
- a JWT-shaped string (`eyJ...` with two more dot-separated segments);
- a Bearer credential. In an `Authorization` or `Proxy-Authorization` field
  (any case; a header, or a quoted JSON or YAML key, also JSON-escaped as
  in `{\"Authorization\": \"Bearer ...\"}`) the Bearer value (up to a
  blank, quote, backslash, comma or semicolon) must be exactly `<redacted>` in
  the record: anything else, `<redacted>x`, an empty value or `$TOKEN`
  included, is refused. Only in a joined form, which may glue the next line
  or record to it, need the value merely start with `<redacted>`.
  Elsewhere, `Bearer` and a token68 value with a digit or one of `_~+/=`,
  or of 16 characters or more; prose (`Bearer tokens are...`) and
  `<redacted>` pass, and so does an auth-param whose name is `realm`,
  `scope`, `error`, `error_description`, `error_uri` or
  `resource_metadata` (any case: `WWW-Authenticate: Bearer
  realm="skyoauth"`, `Bearer error="invalid_token"`, also with JSON-escaped
  quotes). Any other `name=` after `Bearer` is a padded token and refused
  (`Bearer dGhpc2lz...MTI=` in a JSON value, `Bearer a1b2c3d4=e5f6`);
- a hex run of 96 digits or more (an Ed25519 signature is 128). A 64-digit
  run, a public key or a hash, passes: it cannot be told from a seed, so
  only the seeds given with `--secret-file` are refused at that size;
- a base64url run of 86 characters or more (an Ed25519 signature) holding
  an upper-case letter, a lower-case letter and a digit;
- `--secret-env` and `--secret-file` values.

`"allow":"hex-across-lines"` lifts only the hex rule, only from the joined
forms that hold the marked record, for output such as two bare public keys
on adjacent lines. The hex rule still applies to each line, every other
rule still applies, and secret values are refused with the marker too.
Within a run of `output` and `note` records that holds marked records, each
stretch of three or more unmarked records between them is checked as its
own joined form, so a signature split over them is still refused (shorter
stretches are already covered as pairs).

This is a check for known shapes and known values, not a proof that a
transcript holds no secret. Not found: a credential of another shape; a
64-digit key or seed that is not a fixture's; a value split by anything but
line breaks and record boundaries (spaces, other characters, a different
encoding); a value split over three or more records unless they are all
`output` or `note`. A review still reads every golden
transcript.

## Timing and determinism

`timing.js` is the one timing model: the player, the WebVTT writer and the
renderer all use it. Every time is computed from a record's step index and
content only (a fixed typing speed per character, fixed pauses), never from
a clock. Two runs of a journey must give byte-identical transcripts: the
transcript (and the VTT made from it) is what is compared, never the mp4,
which is only as stable as the browser and the encoder.

The player holds a pure black screen for `LEAD_IN_MS` before its first frame
(t0). The recording usually starts earlier, with the page load, but its
first frame can come late, inside the lead-in, so it may hold less than
`LEAD_IN_MS` of black: there is no minimum lead-in. The renderer runs
ffmpeg's `blackdetect` on the raw recording once (any black frame counts; the
player's own frames are never black) and starts the mp4 at the end of the
black interval nearest the page clock's estimate of t0: time 0 of the mp4 is
t0. In the measurements below the VTT cues lined up to about one frame of
the 25 fps recording; that is what was measured, not a guarantee, and
nothing in the render checks it to that precision.

The cut is checked against a one-sided late bound from the page's own clock.
The estimate is t0 (in the page's epoch time) less `Date.now()` taken just
before `newPage()` is called. The recording cannot start before that call
(Playwright times its frames from a recorder created inside it), so t0 in
the recording is at most the estimate plus the time the t0 frame takes to
reach the recording and the 25 fps frame grid: the render fails when the
cut is later than the estimate plus `LEAD_IN_LATE_SLACK_MS`, two recording
frames (80 ms). There is no early-side check. How much earlier than the
estimate the cut comes depends on how long `newPage()` and the recording's
first frame take, and that is unbounded under load: with 8 renders at once,
`newPage()` returned 87 to 298 ms late and the video started from 177 ms
before to 383 ms after it returned, and a two-sided check (an estimate taken
after `newPage()`, 200 ms either side) rejected 7 correct cuts of 24. None
is needed either: the cut is the first non-black frame after the lead-in,
and the player shows nothing but black from its load until t0, so the cut
cannot be early. Every render logs `lead-in cut X s, page-clock estimate Y
ms, delta D ms (late bound +80 ms)` (D is the cut less the estimate; it is
usually negative, by about the start-up time). A cut past the bound is never
used: the render fails with the estimate, the bound, the delta and every
black interval found. What it catches was seen under load: a
recording whose frames froze for 4.4 s after t0 (black from 0.12 to 5.24 s,
while the page clock put t0 near 0.9 s), which used to fail later with "the
recording holds 20.5 s after t0" and now fails at the cut with the numbers.

Black after the cut also fails the render, with the same numbers: since the
player's frames are never black, any black interval that starts after the
chosen one is a recording fault (frames that froze or went blank), even when
the cut itself is within the bound. A start-up flash can make that happen:
black ending at 0.04 s and at 5.24 s with the page clock at 905 ms puts the
cut at 0.04 s, nearest the estimate, and would have left 5.1 s of black in
the mp4. With 8 renders at once, 1 of 16 recordings showed the t0 frame and
then 4.2 s of black (cut at 1.48 s, black again from 1.52 to 5.72 s) and
passed before this check. Black before the chosen interval (a start-up
flash) is ignored: the cut drops it.

A cut a frame or two late is not caught by the bound; the quiet lead-in
below is what keeps the cut on its frame, and the e2e test checks the
captions against the cues.

During the lead-in the player repaints a 4px corner square in two shades
that `blackdetect` still counts as black, so the screencast keeps receiving
black frames (twice locally, before that repaint was added, a render failed
with "no black lead-in found"). The repaint stops `LEAD_IN_QUIET_MS` (300
ms) before t0. While it ran up to t0, the screencast, busy with a frame
every refresh, delivered the t0 frame 43 to 83 ms late (20 renders, against
t0 measured from when each caption and output step became visible), so the
cut was as late, every caption came that much early in the mp4, and 6 of 25
e2e runs found the caption bar changing more than 150 ms before a cue. With
the quiet end, the same measurement gave -17 to +15 ms (12 renders), and 35
of 35 runs passed.

Set `DEMO_KEEP_RAW=<dir>` to keep the raw recording of a failed
render; a copy that fails is reported on stderr and never replaces the
render's own error, and a render that failed before the browser wrote a
recording reports that nothing was kept. `demo.yml` sets it and, when a step fails, uploads the
recordings as `demo-raw-recordings-N` (3 days). `render.e2e.test.mjs` checks that frame 0 is the player
and that the caption bar changes at each cue boundary and not before;
`vtt.test.mjs` runs the player's own script on a virtual clock and checks
that each caption appears exactly at its cue's start.

## Chapters and milestone videos (designed, not built)

One video per milestone, joined from per-journey transcripts with a
`chapter` record per journey, chapter tracks (WebVTT and mp4), a generated
opening commit caption, staged publication and one merged `SHA256SUMS`: the
design is section 6 of
[the proposal](../../docs/proposals/demo-walkthroughs.md#6-chapters-and-one-video-per-milestone-design-not-built),
for the lead's review. None of it is implemented yet.

## Never committed

The mp4 files and `out/` (in `.gitignore`). The videos are run artifacts of
`.github/workflows/demo.yml`, which is not part of `CI passed`; it checks
and renders against the seeds of every committed `*.test-key.json`
(`--secret-file`, failing when there is none), as the `demo-transcripts`
job of `ci.yml` does for the committed transcripts on every change.
