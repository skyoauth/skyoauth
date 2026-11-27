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
(t0). The recording starts earlier, with the page load, so the renderer runs
ffmpeg's `blackdetect` on the raw recording (any black frame counts; the
player's own frames are never black) and starts the mp4 at the end of the
first black interval: time 0 of the mp4 is t0 and the VTT cues line up to
about one frame of the 25 fps recording. It also prints the lead-in as the
page's clock saw it, as a cross-check (locally, over a dozen renders: cuts
of 0.80 to 0.92 s against estimates of 852 to 932 ms, never more than 80 ms
apart; the estimate is later, presumably because the recording starts a
little after the page is created). During the lead-in the player repaints a
4px corner square every animation frame in two shades that `blackdetect`
still counts as black, so the screencast keeps receiving black frames: twice
locally, before that repaint was added, a render failed with "no black
lead-in found" (not reproduced in a dozen later renders; the cause was not
confirmed). Set `DEMO_KEEP_RAW=<dir>` to keep the raw recording of a failed
render; a copy that fails is reported on stderr and never replaces the
render's own error, and a render that failed before the browser wrote a
recording reports that nothing was kept. `demo.yml` sets it and, when a step fails, uploads the
recordings as `demo-raw-recordings-N` (3 days). `render.e2e.test.mjs` checks that frame 0 is the player
and that the caption bar changes at each cue boundary and not before;
`vtt.test.mjs` runs the player's own script on a virtual clock and checks
that each caption appears exactly at its cue's start, and that each title
card (below) clears the terminal and the caption bar for exactly its step.

### Chapters, the title card and the opening lead-in

The player and the timing model know the `chapter` record of section 6.1
of the proposal, `{"step":N,"type":"chapter","text":"M1a-2: <title>"}`
(the checker does not yet: see below):

- **Title card.** At a chapter's start the player clears the terminal and
  the caption bar and shows the title, centred, until the chapter's step
  ends. Its duration is the caption rule applied to the title (1200 ms plus
  40 ms a code point), at least 1200 ms (`TITLE_CARD_MIN_MS`) and at most
  3000 ms (`TITLE_CARD_MAX_MS`). After the card the terminal starts empty
  and the caption bar stays empty until the next caption record.
- **Captions track.** A chapter is not a caption and has no cue in
  `<name>.vtt`. A caption's cue ends at the next caption's start or the
  next chapter's start, whichever comes first (the last one at the end of
  the video), which is when the player replaces or empties the bar.
- **Chapters track** (`toChaptersVtt` in `vtt.mjs`, `timing.chapterCues`):
  one cue per chapter, ids `chapter-<n>` (1-based, stream order), texts
  escaped like captions, contiguous from 0 to the end of the video: chapter
  1 starts at 0, every later one at its chapter record's start, and each
  ends where the next starts. Without a chapter it is the `WEBVTT` header
  alone.
- **Opening lead-in.** A caption record with no `step`, allowed only as
  the first record, lasts `OPENING_MS` (3000 ms) whatever its text: every
  later time moves by `OPENING_MS` and no step changes (the typing speed
  still follows each record's own step). Its captions cue has the id
  `opening` and always ends at `OPENING_MS`, its own step's end: a step-0
  caption or chapter replaces or empties the bar at that instant, and
  before any other step 0 (output, a command or a note) the player
  empties the bar itself, so the commit is never shown past the lead-in.
  It is not `LEAD_IN_MS`, the black screen before t0 that the renderer
  cuts: the opening is inside the timeline, from t0. Any other record
  without a step is refused.

Not built yet (section 6 of
[the proposal](../../docs/proposals/demo-walkthroughs.md#6-chapters-and-one-video-per-milestone-design-not-built)):
the `chapter` record in `transcript.mjs` and `check-milestone`, the
milestone render (`render.mjs --milestone`, `--commit`, which writes the
opening caption and the chapters VTT, and the mp4 chapters), staged
publication with one merged `SHA256SUMS`, and the CI steps. `render.mjs`
renders single transcripts only and refuses a `chapter` record (its
transcript check does not know the type); it writes no chapters VTT and no
opening.

## Never committed

The mp4 files and `out/` (in `.gitignore`). The videos are run artifacts of
`.github/workflows/demo.yml`, which is not part of `CI passed`; it checks
and renders against the seeds of every committed `*.test-key.json`
(`--secret-file`, failing when there is none), as the `demo-transcripts`
job of `ci.yml` does for the committed transcripts on every change.
