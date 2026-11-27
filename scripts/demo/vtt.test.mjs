// Self-test of vtt.mjs and of the player's schedule (pure: no browser, no
// ffmpeg, no network):
//   node --test scripts/demo/vtt.test.mjs
//
// The player test runs player.html's own scripts (timing.js and the inline
// player) in a node:vm context with a small DOM stand-in and a virtual
// clock, and checks that each caption appears at exactly the time of its
// WebVTT cue, and that a chapter's title card clears the terminal and the
// caption bar for exactly its step.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

import { MAX_DRIFT_MS } from './render.mjs';
import timing from './timing.js';
import { readTranscript } from './transcript.mjs';
import { escapeCueText, formatVttTime, parseVtt, toChaptersVtt, toVtt } from './vtt.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLE = readTranscript(join(HERE, 'sample', 'sample.transcript.jsonl'));
const PLAYER = readFileSync(join(HERE, 'player.html'), 'utf8');
const r = (step, type, text) => ({ step, type, text });
// A joined milestone stream of two journeys and the opening lead-in before
// it (docs/proposals/demo-walkthroughs.md 6.3, 6.4).
const OPENING = { type: 'caption', text: 'M1a at commit 0123456789ab' };
const JOINED = [
  r(0, 'chapter', 'M1a-1: First journey'),
  r(1, 'caption', 'first caption'),
  r(2, 'command', 'ls'),
  r(3, 'output', 'one\ntwo'),
  r(4, 'caption', 'cut short by the next chapter'),
  r(5, 'output', 'y'),
  r(6, 'chapter', 'M1a-2: Second <journey> & more'),
  r(7, 'command', 'pwd'),
  r(8, 'caption', 'second journey caption'),
  r(9, 'output', 'z'),
];
const STREAM = [OPENING, ...JOINED];

describe('WebVTT', () => {
  it('formats times as HH:MM:SS.mmm and refuses bad ones', () => {
    assert.equal(formatVttTime(0), '00:00:00.000');
    assert.equal(formatVttTime(9223), '00:00:09.223');
    assert.equal(formatVttTime(3723004), '01:02:03.004');
    for (const bad of [-1, 1.5, NaN]) assert.throws(() => formatVttTime(bad), /bad time/);
  });

  it('escapes &, < and > so a caption cannot hold markup or "-->"', () => {
    assert.equal(escapeCueText('a <b> & c --> d'), 'a &lt;b&gt; &amp; c --&gt; d');
    const vtt = toVtt([r(0, 'caption', 'x --> y <i>')]);
    assert.equal(vtt.split('-->').length, 2);
  });

  it('writes the header, one cue per caption and a final LF', () => {
    const vtt = toVtt(SAMPLE);
    assert.ok(vtt.startsWith('WEBVTT\n\n'));
    assert.ok(vtt.endsWith('\n') && !vtt.includes('\r'));
    const cues = parseVtt(vtt);
    assert.equal(cues.length, SAMPLE.filter((x) => x.type === 'caption').length);
    assert.deepEqual(
      cues.map((c) => c.id),
      SAMPLE.filter((x) => x.type === 'caption').map((x) => `step-${x.step}`),
    );
  });

  it('times the cues with timing.captionCues', () => {
    const expected = timing.captionCues(SAMPLE);
    const cues = parseVtt(toVtt(SAMPLE));
    assert.deepEqual(
      cues.map(({ startMs, endMs, text }) => ({ startMs, endMs, text })),
      expected.map(({ startMs, endMs, text }) => ({ startMs, endMs, text })),
    );
    assert.equal(cues[0].startMs, 0);
    assert.equal(cues[cues.length - 1].endMs, timing.totalMs(timing.buildTimeline(SAMPLE)));
  });

  it('is byte-identical for the same records', () => {
    assert.equal(toVtt(JSON.parse(JSON.stringify(SAMPLE))), toVtt(SAMPLE));
  });

  it('names the opening cue `opening` and cuts a caption cue at the next chapter', () => {
    const cues = parseVtt(toVtt(STREAM));
    const tl = timing.buildTimeline(STREAM);
    assert.deepEqual(
      cues.map((c) => [c.id, c.startMs, c.endMs, c.text]),
      [
        ['opening', 0, timing.OPENING_MS, OPENING.text],
        ['step-1', tl[2].startMs, tl[5].startMs, 'first caption'],
        ['step-4', tl[5].startMs, tl[7].startMs, 'cut short by the next chapter'],
        ['step-8', tl[9].startMs, timing.totalMs(tl), 'second journey caption'],
      ],
    );
    // A chapter title is no caption: it is not in the captions track.
    assert.doesNotMatch(toVtt(STREAM), /journey<|Journey|M1a-[12]:/);
    assert.equal(toVtt(JOINED).includes('opening'), false);
  });

  it('writes only the header without captions', () => {
    assert.equal(toVtt([r(0, 'command', 'ls')]), 'WEBVTT\n');
    assert.deepEqual(parseVtt('WEBVTT\n'), []);
    assert.throws(() => parseVtt('WEBVTT'), /final line feed/);
  });
});

describe('chapters WebVTT', () => {
  it('writes one cue per chapter, ids chapter-<n>, contiguous from 0 to totalMs, chapter 1 covering the opening', () => {
    const tl = timing.buildTimeline(STREAM);
    const total = timing.totalMs(tl);
    const t = formatVttTime;
    assert.equal(
      toChaptersVtt(STREAM),
      'WEBVTT\n\n' +
        `chapter-1\n${t(0)} --> ${t(tl[7].startMs)}\nM1a-1: First journey\n\n` +
        `chapter-2\n${t(tl[7].startMs)} --> ${t(total)}\nM1a-2: Second &lt;journey&gt; &amp; more\n`,
    );
    const cues = parseVtt(toChaptersVtt(STREAM));
    assert.deepEqual(
      cues.map(({ id, startMs, endMs }) => ({ id, startMs, endMs })),
      timing.chapterCues(STREAM).map((c) => ({ id: `chapter-${c.n}`, startMs: c.startMs, endMs: c.endMs })),
    );
    assert.equal(cues[0].startMs, 0);
    assert.equal(cues[cues.length - 1].endMs, total);
    for (let k = 1; k < cues.length; k++) assert.equal(cues[k].startMs, cues[k - 1].endMs);
  });

  it('holds no caption, is byte-identical for the same records, and is only the header without chapters', () => {
    assert.doesNotMatch(toChaptersVtt(STREAM), /caption|commit/);
    assert.equal(toChaptersVtt(JSON.parse(JSON.stringify(STREAM))), toChaptersVtt(STREAM));
    assert.equal(toChaptersVtt(SAMPLE), 'WEBVTT\n');
    assert.equal(toChaptersVtt([]), 'WEBVTT\n');
  });

  it('matches the format of the proposal (6.4)', () => {
    // Over a minute long: 1700 output lines.
    const records = [r(0, 'chapter', 'M1a-1: Bootstrap the operator'), r(1, 'output', Array.from({ length: 1700 }, () => 'x').join('\n'))];
    const total = timing.totalMs(timing.buildTimeline(records));
    assert.equal(formatVttTime(total), '00:01:12.760');
    assert.equal(toChaptersVtt(records), 'WEBVTT\n\nchapter-1\n00:00:00.000 --> 00:01:12.760\nM1a-1: Bootstrap the operator\n');
  });
});

// A DOM element stand-in with just what player.html uses.
class Element {
  constructor(tag, onText, onRemove = () => {}) {
    this.tagName = tag;
    this.children = [];
    this.ownText = '';
    this.className = '';
    this.id = '';
    this.onText = onText;
    this.onRemove = onRemove;
  }
  get firstChild() {
    return this.children[0] ?? null;
  }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    const i = this.children.indexOf(child);
    if (i < 0) throw new Error('removeChild: not a child');
    this.children.splice(i, 1);
    this.onRemove(this, child);
    return child;
  }
  get textContent() {
    return this.ownText + this.children.map((c) => c.textContent).join('');
  }
  set textContent(value) {
    this.ownText = String(value);
    this.children = [];
    this.onText(this);
  }
}

// Runs player.html's scripts against a virtual clock and returns the
// caption changes and typed characters, with times relative to t0.
async function playInVm(records) {
  let now = 0;
  let seq = 0;
  const timers = [];
  const log = [];
  const onText = (el) => log.push({ at: now, id: el.id, cls: el.className, text: el.ownText });
  const removed = [];
  const onRemove = (parent, child) => removed.push({ at: now, from: parent.id, cls: child.className, text: child.textContent });
  const byId = {};
  for (const id of ['screen', 'term', 'caption', 'tick']) {
    byId[id] = new Element('div', onText, onRemove);
    byId[id].id = id;
  }
  const document = {
    body: { className: '' },
    getElementById: (id) => byId[id] ?? null,
    createElement: (tag) => new Element(tag, onText, onRemove),
  };
  let revealedAt = null;
  let frames = 0;
  let tickChanges = 0;
  let tickClass = 'a';
  Object.defineProperty(byId.tick, 'className', {
    set(v) {
      if (v !== tickClass) tickChanges++;
      tickClass = v;
    },
    get() {
      return tickClass;
    },
  });
  const body = document.body;
  Object.defineProperty(body, 'className', {
    set(v) {
      if (v === 'playing' && revealedAt === null) revealedAt = now;
      this._c = v;
    },
    get() {
      return this._c ?? '';
    },
  });
  const setTimeout = (fn, ms) => timers.push({ at: now + Math.max(0, Math.ceil(ms)), seq: seq++, fn });
  const sandbox = {
    document,
    performance: { now: () => now },
    setTimeout,
    requestAnimationFrame: (fn) => {
      frames++;
      setTimeout(() => fn(now), 16);
    },
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);

  assert.match(PLAYER, /<script src="timing\.js"><\/script>/);
  vm.runInContext(readFileSync(join(HERE, 'timing.js'), 'utf8'), sandbox, { filename: 'timing.js' });
  const inline = [...PLAYER.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  assert.equal(inline.length, 1, 'player.html has one inline script');
  vm.runInContext(inline[0], sandbox, { filename: 'player.html' });

  let settled = false;
  let result;
  let failure;
  sandbox.playTranscript(records).then(
    (v) => {
      settled = true;
      result = v;
    },
    (e) => {
      settled = true;
      failure = e;
    },
  );
  const drain = () => new Promise((resolve) => setImmediate(resolve));
  await drain();
  while (!settled) {
    assert.ok(timers.length > 0, 'the player is waiting on nothing');
    timers.sort((a, b) => a.at - b.at || a.seq - b.seq);
    const t = timers.shift();
    now = t.at;
    t.fn();
    await drain();
  }
  if (failure) throw failure;
  // Objects made in the VM have that realm's prototypes: copy them out.
  result = JSON.parse(JSON.stringify(result));
  const t0 = result.t0;
  return {
    t0,
    revealedAt,
    frames,
    tickChanges,
    endAt: now,
    done: sandbox.__demoDone,
    result,
    log: log.map((e) => ({ ...e, at: e.at - t0 })),
    removed: removed.map((e) => ({ ...e, at: e.at - t0 })),
    term: byId.term.children.map((c) => ({ cls: c.className, text: c.textContent })),
  };
}

describe('player schedule (player.html in a VM with a virtual clock)', () => {
  it('holds the black lead-in, then shows each caption exactly at its VTT cue start', async () => {
    const run = await playInVm(SAMPLE);
    assert.equal(run.done, true);
    assert.ok(run.revealedAt >= timing.LEAD_IN_MS, `revealed at ${run.revealedAt}`);
    // The lead-in repaints every frame (about LEAD_IN_MS / 16), then stops.
    assert.ok(run.frames >= timing.LEAD_IN_MS / 16 - 2, `${run.frames} frames`);
    assert.ok(run.frames < timing.LEAD_IN_MS / 16 + 5, `${run.frames} frames: the repaint did not stop`);
    // Each of those frames changes the #tick shade, so each one is painted.
    assert.ok(run.tickChanges >= timing.LEAD_IN_MS / 16 - 2, `${run.tickChanges} repaints`);
    const shown = run.log.filter((e) => e.id === 'caption').map((e) => ({ startMs: e.at, text: e.text }));
    const cues = parseVtt(toVtt(SAMPLE)).map((c) => ({ startMs: c.startMs, text: c.text }));
    assert.deepEqual(shown, cues);
    // Each caption stays until the next one replaces it: the cue's end.
    const vttCues = parseVtt(toVtt(SAMPLE));
    for (let k = 0; k + 1 < vttCues.length; k++) assert.equal(vttCues[k].endMs, shown[k + 1].startMs);
  });

  it('ends exactly at totalMs and reports the timing.js timeline it played', async () => {
    const run = await playInVm(SAMPLE);
    const tl = timing.buildTimeline(SAMPLE);
    assert.equal(run.endAt - run.t0, timing.totalMs(tl));
    assert.equal(run.result.totalMs, timing.totalMs(tl));
    assert.deepEqual(
      run.result.events.map((e) => [e.step, e.plannedMs, e.actualMs]),
      tl.map((e) => [e.step, e.startMs, e.startMs]),
    );
  });

  it('keeps to the timeline through a 60-line note: every line within its step, captions on their cues', async () => {
    const note = Array.from({ length: 60 }, (_, i) => `library call line ${i}`).join('\n');
    const records = [r(0, 'caption', 'before'), r(1, 'note', note), r(2, 'caption', 'after'), r(3, 'output', 'done')];
    const run = await playInVm(records);
    const tl = timing.buildTimeline(records);
    assert.deepEqual(
      run.result.events.map((e) => [e.step, e.plannedMs, e.actualMs]),
      tl.map((e) => [e.step, e.startMs, e.startMs]),
    );
    // The renderer refuses a recording whose steps drift more than
    // MAX_DRIFT_MS from the timeline; on the virtual clock the drift is 0.
    const drift = Math.max(...run.result.events.map((e) => Math.abs(e.actualMs - e.plannedMs)));
    assert.ok(drift <= MAX_DRIFT_MS, `drift ${drift} ms`);
    assert.equal(drift, 0);
    const noteLines = run.log.filter((e) => e.cls === 'line note');
    assert.equal(noteLines.length, 60);
    assert.equal(noteLines[59].at, tl[1].startMs + 59 * timing.OUTPUT_LINE_MS);
    assert.ok(noteLines.every((e) => e.at >= tl[1].startMs && e.at < tl[1].endMs), 'a note line outside its step');
    const shown = run.log.filter((e) => e.id === 'caption').map((e) => ({ startMs: e.at, text: e.text }));
    assert.deepEqual(shown, parseVtt(toVtt(records)).map((c) => ({ startMs: c.startMs, text: c.text })));
    assert.equal(run.endAt - run.t0, timing.totalMs(tl));
  });

  it('types each command character at its timing.typingOffsets time', async () => {
    const records = [r(0, 'caption', 'typing'), r(1, 'command', 'abc def'), r(2, 'output', 'one\ntwo'), r(3, 'note', 'n')];
    const run = await playInVm(records);
    const tl = timing.buildTimeline(records);
    const typed = run.log.filter((e) => e.cls === 'typed' && e.text !== '');
    assert.deepEqual(
      typed.map((e) => [e.at, e.text]),
      timing.typingOffsets(records[1]).map((o, i) => [tl[1].startMs + o, 'abc def'.slice(0, i + 1)]),
    );
    const lines = run.log.filter((e) => /^line (output|note)$/.test(e.cls));
    assert.deepEqual(
      lines.map((e) => [e.at, e.text]),
      [
        [tl[2].startMs, 'one'],
        [tl[2].startMs + timing.OUTPUT_LINE_MS, 'two'],
        [tl[3].startMs, '# n'],
      ],
    );
  });
});

describe('player chapters (player.html in a VM with a virtual clock)', () => {
  it('shows each chapter as a title card in a cleared terminal for exactly its step', async () => {
    const run = await playInVm(STREAM);
    const tl = timing.buildTimeline(STREAM);
    const chapters = STREAM.map((x, i) => [x, i]).filter(([x]) => x.type === 'chapter');
    // The terminal is cleared at each chapter start and nowhere else.
    assert.deepEqual(
      run.log.filter((e) => e.id === 'term').map((e) => [e.at, e.text]),
      chapters.map(([, i]) => [tl[i].startMs, '']),
    );
    // The card shows the title from the chapter's start ...
    assert.deepEqual(
      run.log.filter((e) => e.cls === 'card').map((e) => [e.at, e.text]),
      chapters.map(([x, i]) => [tl[i].startMs, x.text]),
    );
    // ... and is taken away exactly at its end, when the next step starts.
    assert.deepEqual(
      run.removed.filter((e) => e.cls === 'card').map((e) => [e.at, e.from, e.text]),
      chapters.map(([x, i]) => [tl[i].endMs, 'term', x.text]),
    );
    for (const [, i] of chapters) assert.equal(tl[i].endMs - tl[i].startMs, timing.stepDuration(STREAM[i]));
    // Nothing is drawn in the terminal while a card shows.
    for (const [, i] of chapters) {
      const drawn = run.log.filter((e) => e.id !== 'caption' && e.cls !== 'card' && e.at > tl[i].startMs && e.at < tl[i].endMs);
      assert.deepEqual(drawn, []);
    }
    // After the second card, the terminal holds only the second journey.
    assert.deepEqual(
      run.term.map((l) => l.text),
      ['$ pwd', 'z'],
    );
  });

  it('empties the caption bar at each chapter start until the next caption: the bar follows the captions VTT exactly', async () => {
    const run = await playInVm(STREAM);
    const tl = timing.buildTimeline(STREAM);
    const changes = run.log.filter((e) => e.id === 'caption').map((e) => [e.at, e.text]);
    assert.deepEqual(changes, [
      [0, OPENING.text],
      [tl[1].startMs, ''],
      [tl[2].startMs, 'first caption'],
      [tl[5].startMs, 'cut short by the next chapter'],
      [tl[7].startMs, ''],
      [tl[9].startMs, 'second journey caption'],
    ]);
    // Each VTT cue starts at a change to its text and ends at the next
    // change of the bar (or the end of the video): a cue cut by a chapter
    // ends where the bar empties. Between cues the bar is empty.
    const cues = parseVtt(toVtt(STREAM));
    const total = timing.totalMs(tl);
    for (const cue of cues) {
      const k = changes.findIndex(([at, text]) => at === cue.startMs && text === cue.text);
      assert.ok(k >= 0, `cue ${cue.id} not shown at its start`);
      assert.equal(k + 1 < changes.length ? changes[k + 1][0] : total, cue.endMs, `cue ${cue.id}`);
    }
    const covered = (at) => cues.some((c) => at >= c.startMs && at < c.endMs);
    for (const [at, text] of changes) if (text === '') assert.equal(covered(at), false, `empty bar at ${at} inside a cue`);
    // The second journey types its command under an empty caption bar.
    const typed = run.log.filter((e) => e.cls === 'typed' && e.text !== '' && e.at >= tl[7].startMs);
    assert.ok(typed.length > 0 && typed.every((e) => e.at >= tl[7].endMs && e.at < tl[9].startMs));
  });

  it('plays the opening and the chapters on the timeline, and ends at totalMs', async () => {
    const run = await playInVm(STREAM);
    const tl = timing.buildTimeline(STREAM);
    assert.deepEqual(
      run.result.events.map((e) => [e.step, e.type, e.plannedMs, e.actualMs]),
      tl.map((e, i) => [e.step, STREAM[i].type, e.startMs, e.startMs]),
    );
    assert.equal(run.result.events[0].step, undefined);
    assert.equal(run.endAt - run.t0, timing.totalMs(tl));
    assert.equal(run.result.totalMs, timing.totalMs(tl));
  });
});

describe('player.html is static and offline', () => {
  it('names no remote URL and loads nothing but timing.js', () => {
    assert.doesNotMatch(PLAYER, /:\/\//);
    assert.doesNotMatch(PLAYER, /\b(?:https?|wss?|ftp):/i);
    assert.doesNotMatch(PLAYER, /@import|url\(|<link\b|<iframe\b|<img\b|fetch\(|XMLHttpRequest|WebSocket|import\(/);
    assert.deepEqual([...PLAYER.matchAll(/\b(?:src|href)\s*=\s*"([^"]*)"/g)].map((m) => m[1]), ['timing.js']);
  });

  it('sets a content security policy that blocks connections', () => {
    const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(PLAYER);
    assert.ok(csp, 'no CSP meta');
    for (const d of ["default-src 'none'", "connect-src 'none'", "img-src 'none'", "font-src 'none'"]) assert.ok(csp[1].includes(d), d);
  });

  it('writes text only through textContent: no HTML parsing of transcript text', () => {
    assert.doesNotMatch(PLAYER, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment|DOMParser|\beval\(|new Function/);
  });

  it('is laid out at 1280x720', () => {
    assert.match(PLAYER, /width: 1280px;\s*height: 720px;/);
  });

  it('repaints the lead-in only in shades the renderer counts as black, and hides the repaint during playback', () => {
    const render = readFileSync(join(HERE, 'render.mjs'), 'utf8');
    const pixTh = Number(/blackdetect=[^']*pix_th=([0-9.]+)/.exec(render)[1]);
    const shades = [...PLAYER.matchAll(/#tick\.[ab] \{ background: #([0-9a-f]{6}); \}/g)].map((m) => m[1]);
    assert.equal(shades.length, 2, 'two #tick shades');
    assert.notEqual(shades[0], shades[1], 'the shades differ, so every frame changes');
    for (const hex of shades) {
      for (let i = 0; i < 6; i += 2) assert.ok(parseInt(hex.slice(i, i + 2), 16) / 255 < pixTh, `#${hex} is not black for pix_th=${pixTh}`);
    }
    assert.match(PLAYER, /body\.playing #tick \{ display: none; \}/);
  });
});
