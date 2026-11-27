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
  });
});
