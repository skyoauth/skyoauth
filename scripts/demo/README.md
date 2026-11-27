# Demo walk-through player and renderer

The player, the transcript checker and the render script of
[the demo walk-through proposal](../../docs/proposals/demo-walkthroughs.md)
(§2 "The mechanism", §5, §6). No journey exists yet: the only transcripts
are invented samples, `sample/sample.transcript.jsonl` and the sample
milestone `sample/m1a/` (two short journeys). A walk-through is not
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
node scripts/demo/transcript.mjs check-milestone scripts/demo/sample/m1a
node scripts/demo/render.mjs scripts/demo/sample/sample.transcript.jsonl --out scripts/demo/out

node --test scripts/demo/transcript.test.mjs scripts/demo/milestone.test.mjs scripts/demo/timing.test.mjs scripts/demo/vtt.test.mjs scripts/demo/workflows.test.mjs
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
`output` or `note` (dim annotation lines, such as a captioned library call),
or `chapter` (a journey's title, below); only `output` and `note` may hold
`\n`. `step` counts from 0 with no gap.
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
  in `{\"Authorization\": \"Bearer ...\"}`) the Bearer value must be
  exactly `<redacted>` in the record: anything else, `<redacted>x`, an
  empty value or `$TOKEN` included, is refused. The value ends at a blank,
  a quote, a comma or a semicolon, or at an escape that decodes to a blank
  or a quote: `\n`, `\r`, `\t`, `\"` or `\'`, lower case only. Any other
  backslash is part of the value, so `<redacted>\\abc`, `<redacted>\/abc`,
  `<redacted>\b`, `<redacted>\f`, `<redacted>\u0041` and an upper-case
  `<redacted>\N` or `<redacted>\U1b2c3` are refused. When the value is
  quoted (`"Bearer ...`), an escape after it other than its closing quote
  continues the string and is refused. Only in a joined form, which may
  glue the next line or record to it, need the value merely start with
  `<redacted>`.
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
that each caption appears exactly at its cue's start.

## Chapters and milestone directories

A `chapter` record, `{"step":0,"type":"chapter","text":"M1a-2: Recover the
operator"}`, is a journey's title: one line of at most 80 code points, a
journey id (`M1a-2`, matching `^M[1-5][ab]?-[1-9][0-9]*$`), a colon, a space
and a title; no `allow` marker. Its text is transcript text: every rule
above and the `--secret-env` and `--secret-file` values apply to it. In a
single file (`check`) there is at most one, and only as the first record, at
step 0. The sample transcript holds none.

A milestone directory holds `milestone.json` and one transcript per
journey:

```text
<m>/milestone.json   {"milestone":"M1a","journeys":["M1a-1","M1a-2"]}
<m>/<journey>.jsonl  m1a-1.jsonl, m1a-2.jsonl, ...
```

`check-milestone <dir>...` (the same `--secret-env` and `--secret-file`
options) checks, for each directory:

1. the names: the directory (resolved, so `.` and `m1a/` work) is named
   the lower case of the milestone id, which matches `^M[1-5][ab]?$`; the
   manifest is at most 64 KiB and has exactly the keys `milestone` and
   `journeys` (each once), a non-empty list of journey ids of that
   milestone (`M1a-...`), each once; each listed journey has its file,
   named `<lower-case journey id>.jsonl`; the directory holds nothing else.
   Every entry is checked with `lstat`: a symlink (the directory itself,
   the manifest or a journey file) or a nested directory is an error, and
   no symlink is followed. A file is read only after an `lstat` and must be
   the same file (device and inode) once open; where Node has `O_NOFOLLOW`
   (Linux, macOS) the open also refuses a link. Windows has no
   `O_NOFOLLOW` in Node, so there the `lstat` and the device and inode
   comparison are the whole guard (not run on Windows);
2. each journey file alone, with every rule, plus its chapter as the first
   record, at step 0, naming the file's journey;
3. the joined stream, the journeys in manifest order, each step renumbered
   to the records of the earlier journeys plus its step in its file. When
   every journey file is valid, that stream is serialized and checked in
   milestone mode with every rule, so a record that renumbering pushes
   over the 16 KiB cap is refused (`record longer than 16384 bytes (in the
   joined milestone stream, as step 13)`); each error is mapped back to its
   file and line. When a file has errors, only the pairs across each
   journey boundary (the last record of one journey and the next one's
   chapter) are checked, over every parsed record of every file, the ones
   with errors included;
4. the same records without the chapters, each keeping its file and line:
   the pair of the last record of one journey and the first record of the
   next, reported as `(chapters removed)`;
5. every chapter's text joined, in manifest order (directly and with a
   space), reported as `(titles joined)`.

A run of `output` and `note` records never spans a journey boundary (a
chapter ends it), so the passes 3 and 4 add only the pairs across it; every
other window is one file's, already checked alone. Not found: a value split
over three or more records across a boundary (the last record of one
journey, the next chapter and the next journey's first record; or two
records on one side and one on the other). The lead accepted that gap: the
title card clears the terminal, so the pieces are never on screen together.

A record refused for its fields (an unknown key, a missing `step` or
`type`) is never in the valid records, but when its `text` is a string it
keeps its place: its text is checked, and it stays its neighbours'
neighbour in every window. Its valid `step` still counts, so the next record
is not refused for a gap.

Errors are printed at a file and line, never at a joined line
(`m1a-2.jsonl:1: JWT-shaped string across the records on m1a-1.jsonl:14 -
m1a-2.jsonl:1 (texts joined)`); an error already reported for a file alone
is not repeated, and allow markers carry over. Names are never echoed as
given:

- a directory entry is printed only when it is `milestone.json` or a journey
  file name and matches no secret rule or `--secret-env`/`--secret-file`
  value; any other entry is `<entry N>` (its place in the sorted listing),
  and a listed journey's missing file that matches a secret value is
  `<listed file N>`;
- a path argument (of `check` or `check-milestone`) that matches a secret
  rule or value is `<argument N>`;
- every other name printed (paths, `--secret-file` paths and labels,
  `--secret-env` names) has its control and bidirectional characters and
  line feeds escaped as `<U+001B>`, so a name cannot move the cursor,
  rewrite a line or fake another message.

A manifest that is too deeply nested to read is reported as such. At most
20 bad entries of `journeys`, and at most 20 listed journeys with no file,
are reported one by one, then `... and N more`. With a bad manifest every
`.jsonl` file of the directory is still checked alone, the joined checks
are skipped (said on stderr), and the command goes on to the next
directory. Exit 1 when anything failed, 2 on a usage error, including no
directory at all, so a glob that matched nothing fails.

`validateTranscript(bytes, { milestone: true })` is the milestone mode for
a joined stream: it opens with a chapter at step 0 and allows a chapter at
a later step; `check` never uses it.

Not built yet (section 6 of
[the proposal](../../docs/proposals/demo-walkthroughs.md#6-chapters-and-one-video-per-milestone-design-not-built)):
the title card in the player and the chapter timing, the chapters VTT, the
milestone render (`render.mjs --milestone`, `--commit`), and the CI steps
that run `check-milestone`. Until the player knows the `chapter` type,
`render.mjs` refuses a transcript that holds one (the timing model throws
on the unknown type). The sample milestone is invented but its id is
`M1a`: it is rendered only by the e2e test, never into a published
directory.

## Never committed

The mp4 files and `out/` (in `.gitignore`). The videos are run artifacts of
`.github/workflows/demo.yml`, which is not part of `CI passed`; it checks
and renders against the seeds of every committed `*.test-key.json`
(`--secret-file`, failing when there is none), as the `demo-transcripts`
job of `ci.yml` does for the committed transcripts on every change.
