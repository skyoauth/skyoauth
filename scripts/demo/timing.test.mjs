// Self-test of timing.js (pure: no browser, no ffmpeg, no network):
//   node --test scripts/demo/timing.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

import timing from './timing.js';
import { readTranscript } from './transcript.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLE = readTranscript(join(HERE, 'sample', 'sample.transcript.jsonl'));
const r = (step, type, text) => ({ step, type, text });

describe('timeline', () => {
  it('is back to back from 0, one entry per record, in whole milliseconds', () => {
    const tl = timing.buildTimeline(SAMPLE);
    assert.equal(tl.length, SAMPLE.length);
    assert.equal(tl[0].startMs, 0);
    tl.forEach((e, i) => {
      assert.equal(e.step, SAMPLE[i].step);
      assert.ok(Number.isSafeInteger(e.startMs) && Number.isSafeInteger(e.endMs));
      assert.ok(e.endMs > e.startMs);
      if (i > 0) assert.equal(e.startMs, tl[i - 1].endMs);
    });
    assert.deepEqual(Object.keys(tl[0]).sort(), ['endMs', 'startMs', 'step']);
  });

  it('is deterministic: the same records give the same timeline', () => {
    const copy = JSON.parse(JSON.stringify(SAMPLE));
    assert.deepEqual(timing.buildTimeline(copy), timing.buildTimeline(SAMPLE));
    assert.equal(timing.totalMs(timing.buildTimeline(copy)), timing.totalMs(timing.buildTimeline(SAMPLE)));
  });

  it('depends only on step and content: a changed text changes its step only, the later steps shift by the difference', () => {
    const a = [r(0, 'caption', 'abc'), r(1, 'command', 'ls'), r(2, 'output', 'x')];
    const b = [r(0, 'caption', 'abcdef'), r(1, 'command', 'ls'), r(2, 'output', 'x')];
    const ta = timing.buildTimeline(a);
    const tb = timing.buildTimeline(b);
    const delta = 3 * 40;
    assert.equal(tb[0].endMs - ta[0].endMs, delta);
    assert.equal(tb[1].endMs - tb[1].startMs, ta[1].endMs - ta[1].startMs);
    assert.equal(tb[2].startMs - ta[2].startMs, delta);
  });

  it('times each type from its content', () => {
    assert.equal(timing.stepDuration(r(0, 'caption', 'x'.repeat(10))), 1200 + 400);
    assert.equal(timing.stepDuration(r(0, 'caption', 'x'.repeat(500))), 6000);
    assert.equal(timing.stepDuration(r(0, 'output', 'a\nb\nc')), 3 * 40 + 900);
    assert.equal(timing.stepDuration(r(0, 'note', 'anything at all')), 1600);
    // A long note is printed line by line like output: its duration covers
    // every line.
    const long = Array.from({ length: 60 }, (_, i) => `note line ${i}`).join('\n');
    assert.equal(timing.stepDuration(r(0, 'note', long)), 60 * 40 + 900);
    assert.equal(timing.stepDuration(r(0, 'note', 'a\nb\nc')), 1600);
    const cmd = r(4, 'command', 'echo hi');
    const offsets = timing.typingOffsets(cmd);
    assert.equal(offsets.length, 7);
    assert.equal(timing.stepDuration(cmd), offsets[6] + 500);
  });

  it('types at a fixed speed derived from the step index: strictly increasing offsets, 28 to 40 ms a character', () => {
    for (const step of [0, 1, 7, 123]) {
      const offsets = timing.typingOffsets(r(step, 'command', 'example-operator status --verbose'));
      assert.equal(offsets[0] - 400, timing.charDelay(step, 0));
      for (let i = 1; i < offsets.length; i++) {
        const d = offsets[i] - offsets[i - 1];
        assert.ok(d >= 28 && d <= 40, `step ${step} char ${i}: ${d}`);
        assert.equal(d, timing.charDelay(step, i));
      }
    }
    assert.notDeepEqual(timing.typingOffsets(r(1, 'command', 'abcdef')), timing.typingOffsets(r(2, 'command', 'abcdef')));
  });

  it('counts characters as code points', () => {
    assert.equal(timing.typingOffsets(r(0, 'command', 'é€😀')).length, 3);
    assert.equal(timing.stepDuration(r(0, 'caption', '😀😀')), 1200 + 80);
  });

  it('ends TAIL_MS after the last step, and throws on an unknown type', () => {
    const tl = timing.buildTimeline(SAMPLE);
    assert.equal(timing.totalMs(tl), tl[tl.length - 1].endMs + timing.TAIL_MS);
    assert.deepEqual(timing.buildTimeline([]), []);
    assert.equal(timing.totalMs([]), timing.TAIL_MS);
    assert.throws(() => timing.buildTimeline([r(0, 'video', 'x')]), /unknown record type "video" at step 0/);
  });
});

describe('caption cues', () => {
  it('has one cue per caption, from its start to the next caption, the last to the end', () => {
    const cues = timing.captionCues(SAMPLE);
    const tl = timing.buildTimeline(SAMPLE);
    const captions = SAMPLE.map((x, i) => [x, i]).filter(([x]) => x.type === 'caption');
    assert.equal(cues.length, captions.length);
    cues.forEach((c, k) => {
      const [x, i] = captions[k];
      assert.equal(c.step, x.step);
      assert.equal(c.text, x.text);
      assert.equal(c.startMs, tl[i].startMs);
      assert.equal(c.endMs, k + 1 < cues.length ? cues[k + 1].startMs : timing.totalMs(tl));
    });
  });

  it('is empty without captions', () => {
    assert.deepEqual(timing.captionCues([r(0, 'command', 'ls')]), []);
  });
});

// A joined milestone stream (two journeys, docs/proposals/demo-walkthroughs.md
// 6.3) and the opening lead-in render.mjs puts before it (6.4).
const JOINED = [
  r(0, 'chapter', 'M1a-1: First journey'),
  r(1, 'caption', 'first caption'),
  r(2, 'command', 'ls'),
  r(3, 'output', 'x'),
  r(4, 'caption', 'cut short by the next chapter'),
  r(5, 'output', 'y'),
  r(6, 'chapter', 'M1a-2: Second journey'),
  r(7, 'command', 'pwd'),
  r(8, 'caption', 'second journey caption'),
  r(9, 'output', 'z'),
];
const OPENING = { type: 'caption', text: 'M1a at commit 0123456789ab' };

describe('chapters: the title card', () => {
  it('is timed from its title by the caption rule, capped at 3000 ms', () => {
    assert.equal(timing.TITLE_CARD_MIN_MS, 1200);
    assert.equal(timing.TITLE_CARD_MAX_MS, 3000);
    assert.equal(timing.stepDuration(r(0, 'chapter', 'M1a-1: x')), 1200 + 8 * 40);
    assert.equal(timing.stepDuration(r(0, 'chapter', 'x'.repeat(44))), 2960);
    assert.equal(timing.stepDuration(r(0, 'chapter', 'x'.repeat(45))), 3000);
    assert.equal(timing.stepDuration(r(0, 'chapter', 'x'.repeat(46))), 3000);
    assert.equal(timing.stepDuration(r(0, 'chapter', 'x'.repeat(80))), 3000);
    // A caption of the same text is not capped at 3000 ms.
    assert.equal(timing.stepDuration(r(0, 'caption', 'x'.repeat(80))), 4400);
    assert.equal(timing.stepDuration(r(0, 'chapter', '😀'.repeat(10))), 1200 + 10 * 40);
  });

  it('is floored at 1200 ms (the caption rule never goes below it)', () => {
    assert.equal(timing.stepDuration(r(0, 'chapter', '')), 1200);
    assert.equal(timing.stepDuration(r(0, 'chapter', 'M')), 1240);
  });

  it('takes its place in the timeline like any step, and shifts no step', () => {
    const tl = timing.buildTimeline(JOINED);
    assert.deepEqual(tl.map((e) => e.step), JOINED.map((x) => x.step));
    assert.equal(tl[6].endMs - tl[6].startMs, timing.stepDuration(JOINED[6]));
    assert.equal(tl[7].startMs, tl[6].endMs);
  });
});

describe('the opening lead-in', () => {
  it('lasts OPENING_MS whatever its text, before step 0, and moves every later time by OPENING_MS', () => {
    assert.ok(Number.isSafeInteger(timing.OPENING_MS) && timing.OPENING_MS > 0);
    const plain = timing.buildTimeline(JOINED);
    const opened = timing.buildTimeline([OPENING, ...JOINED]);
    assert.equal(opened.length, plain.length + 1);
    assert.deepEqual(opened[0], { step: undefined, startMs: 0, endMs: timing.OPENING_MS });
    plain.forEach((e, i) => {
      assert.deepEqual(opened[i + 1], { step: e.step, startMs: e.startMs + timing.OPENING_MS, endMs: e.endMs + timing.OPENING_MS });
    });
    assert.equal(timing.totalMs(opened), timing.totalMs(plain) + timing.OPENING_MS);
    for (const text of ['M1a at commit 0123456', 'x'.repeat(100)]) {
      assert.equal(timing.buildTimeline([{ type: 'caption', text }])[0].endMs, timing.OPENING_MS);
    }
    // The typing speed follows the step index, which the opening leaves alone.
    assert.deepEqual(timing.typingOffsets(JOINED[2]), timing.typingOffsets(r(2, 'command', 'ls')));
  });

  it('is only the first record, and only a caption: any other record with no step is refused', () => {
    assert.throws(() => timing.buildTimeline([r(0, 'caption', 'a'), OPENING]), /no step at index 1: only the opening caption/);
    assert.throws(() => timing.buildTimeline([OPENING, OPENING]), /no step at index 1/);
    for (const type of ['command', 'output', 'note', 'chapter']) {
      assert.throws(() => timing.buildTimeline([{ type, text: 'M1a-1: x' }]), /no step at index 0/, type);
    }
  });
});

describe('caption cues with chapters', () => {
  it('ends a cue at the next caption or the next chapter, whichever starts first; a chapter has no cue', () => {
    const tl = timing.buildTimeline(JOINED);
    const total = timing.totalMs(tl);
    assert.deepEqual(timing.captionCues(JOINED), [
      { step: 1, startMs: tl[1].startMs, endMs: tl[4].startMs, text: 'first caption' },
      { step: 4, startMs: tl[4].startMs, endMs: tl[6].startMs, text: 'cut short by the next chapter' },
      { step: 8, startMs: tl[8].startMs, endMs: total, text: 'second journey caption' },
    ]);
  });

  it('gives the opening a cue with no step, cut at the first chapter', () => {
    const tl = timing.buildTimeline([OPENING, ...JOINED]);
    const cues = timing.captionCues([OPENING, ...JOINED]);
    assert.deepEqual(cues[0], { step: undefined, startMs: 0, endMs: timing.OPENING_MS, text: OPENING.text });
    assert.equal(tl[1].startMs, timing.OPENING_MS);
    assert.deepEqual(cues.slice(1).map((c) => c.step), [1, 4, 8]);
    assert.equal(cues[2].endMs, tl[7].startMs);
  });

  it('a chapter after the last caption ends it; a caption after a chapter starts at its own step', () => {
    const records = [r(0, 'caption', 'a'), r(1, 'chapter', 'M1a-2: b'), r(2, 'output', 'o'), r(3, 'caption', 'c')];
    const tl = timing.buildTimeline(records);
    assert.deepEqual(
      timing.captionCues(records).map((c) => [c.step, c.startMs, c.endMs]),
      [
        [0, 0, tl[1].startMs],
        [3, tl[3].startMs, timing.totalMs(tl)],
      ],
    );
    assert.deepEqual(timing.captionCues([r(0, 'chapter', 'M1a-1: only'), r(1, 'output', 'o')]), []);
  });
});

describe('chapter cues', () => {
  it('has one cue per chapter, numbered from 1, contiguous from 0 to totalMs', () => {
    const tl = timing.buildTimeline(JOINED);
    assert.deepEqual(timing.chapterCues(JOINED), [
      { n: 1, step: 0, startMs: 0, endMs: tl[6].startMs, text: 'M1a-1: First journey' },
      { n: 2, step: 6, startMs: tl[6].startMs, endMs: timing.totalMs(tl), text: 'M1a-2: Second journey' },
    ]);
  });

  it('starts chapter 1 at 0, covering the opening lead-in; the later ones at their chapter record', () => {
    const records = [OPENING, ...JOINED, r(10, 'chapter', 'M1a-3: Third'), r(11, 'caption', 'third')];
    const tl = timing.buildTimeline(records);
    const cues = timing.chapterCues(records);
    assert.deepEqual(
      cues.map((c) => [c.n, c.step, c.startMs, c.endMs]),
      [
        [1, 0, 0, tl[7].startMs],
        [2, 6, tl[7].startMs, tl[11].startMs],
        [3, 10, tl[11].startMs, timing.totalMs(tl)],
      ],
    );
    assert.equal(tl[1].startMs, timing.OPENING_MS);
    for (let k = 1; k < cues.length; k++) assert.equal(cues[k].startMs, cues[k - 1].endMs);
  });

  it('is empty without a chapter (the sample transcript)', () => {
    assert.deepEqual(timing.chapterCues(SAMPLE), []);
    assert.deepEqual(timing.chapterCues([OPENING, r(0, 'caption', 'a')]), []);
    assert.deepEqual(timing.chapterCues([]), []);
  });
});

describe('the module itself', () => {
  const source = readFileSync(join(HERE, 'timing.js'), 'utf8');

  it('reads no clock, random source or environment', () => {
    const code = source.replace(/\/\/.*$/gm, '');
    for (const banned of [/\bDate\b/, /Math\.random/, /performance/, /process\./, /crypto/, /setTimeout/, /require\(/]) {
      assert.doesNotMatch(code, banned);
    }
  });

  it('is UMD: in a browser-like global it defines DemoTiming with the same results', () => {
    const sandbox = {};
    sandbox.self = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(source, sandbox, { filename: 'timing.js' });
    assert.equal(typeof sandbox.DemoTiming, 'object');
    const inBrowser = JSON.parse(JSON.stringify(sandbox.DemoTiming.buildTimeline(SAMPLE)));
    assert.deepEqual(inBrowser, timing.buildTimeline(SAMPLE));
    const stream = [OPENING, ...JOINED];
    for (const f of ['buildTimeline', 'captionCues', 'chapterCues']) {
      assert.deepEqual(JSON.parse(JSON.stringify(sandbox.DemoTiming[f](stream))), JSON.parse(JSON.stringify(timing[f](stream))), f);
    }
    assert.equal(sandbox.DemoTiming.OPENING_MS, timing.OPENING_MS);
  });
});
