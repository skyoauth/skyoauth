// The one timing model of the demo pipeline. The player (player.html, as
// window.DemoTiming), the WebVTT writer (vtt.mjs) and the renderer
// (render.mjs) all take their times from here, so the captions of the
// sidecar line up with what the page shows.
//
// Every time is a whole number of milliseconds from the first frame of
// playback (t0, see player.html), computed from the record's step index and
// its content only: never from a clock, a random source or the environment.
// The same records always give the same timeline.
//
// Chapters (docs/proposals/demo-walkthroughs.md 6.1, 6.4): a `chapter`
// record is played as a title card; a caption's cue ends at the next
// caption or the next chapter, whichever starts first; chapterCues gives
// the chapters track. The opening lead-in is a caption record with no
// `step`, allowed only as the first record: it lasts OPENING_MS whatever
// its text, so every later time moves by OPENING_MS and no step changes.
//
// UMD: CommonJS for Node (`import timing from './timing.js'` in an .mjs
// file), a `DemoTiming` global in the browser.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DemoTiming = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Black screen the player holds before t0 (not part of the timeline). The
  // renderer finds its end in the recording to cut the load lead-in.
  var LEAD_IN_MS = 800;
  // Hold after the last step, inside the timeline.
  var TAIL_MS = 1500;

  // caption: shown in the caption bar; long enough to read.
  var CAPTION_BASE_MS = 1200;
  var CAPTION_PER_CHAR_MS = 40;
  var CAPTION_MAX_MS = 6000;
  // command: a pause at the prompt, typing, then Enter.
  var PROMPT_PAUSE_MS = 400;
  var TYPE_BASE_MS = 28;
  var TYPE_SPREAD_MS = 13;
  var ENTER_PAUSE_MS = 500;
  // output: printed line by line, then a pause to read it.
  var OUTPUT_LINE_MS = 40;
  var OUTPUT_PAUSE_MS = 900;
  // note: dim annotation lines, printed like output, held at least this long.
  var NOTE_MS = 1600;
  // chapter: a title card, timed from its title by the caption rule, then
  // held at least TITLE_CARD_MIN_MS and at most TITLE_CARD_MAX_MS.
  var TITLE_CARD_MIN_MS = 1200;
  var TITLE_CARD_MAX_MS = 3000;
  // The opening caption (render.mjs --commit): a fixed-length lead-in
  // before step 0, inside the timeline.
  var OPENING_MS = 3000;

  function codePoints(text) {
    return Array.from(text);
  }

  // Delay before character i of a command typed at step `step`. The spread
  // only makes the typing look less mechanical; it is a fixed function of
  // (step, i).
  function charDelay(step, i) {
    return TYPE_BASE_MS + ((step * 31 + i * 17) % TYPE_SPREAD_MS);
  }

  // Offsets from the step's start at which each character of a command
  // appears.
  function typingOffsets(record) {
    var chars = codePoints(record.text);
    var offsets = [];
    var t = PROMPT_PAUSE_MS;
    for (var i = 0; i < chars.length; i++) {
      t += charDelay(record.step, i);
      offsets.push(t);
    }
    return offsets;
  }

  function outputLines(record) {
    return record.text.split('\n');
  }

  // The caption timing rule: long enough to read the text.
  function captionMs(text) {
    return Math.min(CAPTION_MAX_MS, CAPTION_BASE_MS + CAPTION_PER_CHAR_MS * codePoints(text).length);
  }

  // The opening lead-in: a caption with no step number.
  function isOpening(record) {
    return record.type === 'caption' && record.step === undefined;
  }

  function stepDuration(record) {
    switch (record.type) {
      case 'caption':
        return isOpening(record) ? OPENING_MS : captionMs(record.text);
      // A chapter's title card: the caption rule, floored and capped.
      case 'chapter':
        return Math.min(TITLE_CARD_MAX_MS, Math.max(TITLE_CARD_MIN_MS, captionMs(record.text)));
      case 'command': {
        var offsets = typingOffsets(record);
        var typed = offsets.length ? offsets[offsets.length - 1] : PROMPT_PAUSE_MS;
        return typed + ENTER_PAUSE_MS;
      }
      case 'output':
        return OUTPUT_LINE_MS * outputLines(record).length + OUTPUT_PAUSE_MS;
      // A note is printed line by line like output, and held at least
      // NOTE_MS.
      case 'note':
        return Math.max(NOTE_MS, OUTPUT_LINE_MS * outputLines(record).length + OUTPUT_PAUSE_MS);
      default:
        throw new Error('timing: unknown record type ' + JSON.stringify(record.type) + ' at step ' + record.step);
    }
  }

  // [{step, startMs, endMs}], one entry per record, back to back from 0.
  // Only the first record may lack a step, and only as the opening caption
  // (its entry's step is undefined).
  function buildTimeline(records) {
    var t = 0;
    var timeline = [];
    for (var i = 0; i < records.length; i++) {
      if (records[i].step === undefined && (i !== 0 || !isOpening(records[i]))) {
        throw new Error('timing: a record with no step at index ' + i + ': only the opening caption, as the first record, has none');
      }
      var d = stepDuration(records[i]);
      timeline.push({ step: records[i].step, startMs: t, endMs: t + d });
      t += d;
    }
    return timeline;
  }

  // Length of the played video: the last step's end plus the tail hold.
  function totalMs(timeline) {
    return (timeline.length ? timeline[timeline.length - 1].endMs : 0) + TAIL_MS;
  }

  // One cue per caption record (the opening included, with an undefined
  // step): from its step's start until the next caption's or the next
  // chapter's start, whichever comes first, or until the end of the video
  // for the last one. A chapter is not a caption and has no cue here: the
  // player clears the caption bar at its start. The player shows each
  // caption over exactly its cue.
  function captionCues(records) {
    var timeline = buildTimeline(records);
    var end = totalMs(timeline);
    var cues = [];
    var open = null;
    for (var i = 0; i < records.length; i++) {
      var type = records[i].type;
      if (type !== 'caption' && type !== 'chapter') continue;
      if (open) open.endMs = timeline[i].startMs;
      open = null;
      if (type === 'chapter') continue;
      open = { step: records[i].step, startMs: timeline[i].startMs, endMs: end, text: records[i].text };
      cues.push(open);
    }
    return cues;
  }

  // The chapters track: one cue per chapter record, numbered n = 1, 2, ...
  // in stream order. Chapter n starts at its record's start, except chapter
  // 1, which starts at 0 (it covers the opening lead-in); each ends where
  // the next starts, the last at the end of the video. No chapter record,
  // no cue.
  function chapterCues(records) {
    var timeline = buildTimeline(records);
    var cues = [];
    for (var i = 0; i < records.length; i++) {
      if (records[i].type !== 'chapter') continue;
      var start = cues.length ? timeline[i].startMs : 0;
      if (cues.length) cues[cues.length - 1].endMs = start;
      cues.push({ n: cues.length + 1, step: records[i].step, startMs: start, endMs: 0, text: records[i].text });
    }
    if (cues.length) cues[cues.length - 1].endMs = totalMs(timeline);
    return cues;
  }

  return {
    LEAD_IN_MS: LEAD_IN_MS,
    TAIL_MS: TAIL_MS,
    OUTPUT_LINE_MS: OUTPUT_LINE_MS,
    TITLE_CARD_MIN_MS: TITLE_CARD_MIN_MS,
    TITLE_CARD_MAX_MS: TITLE_CARD_MAX_MS,
    OPENING_MS: OPENING_MS,
    charDelay: charDelay,
    typingOffsets: typingOffsets,
    outputLines: outputLines,
    stepDuration: stepDuration,
    buildTimeline: buildTimeline,
    totalMs: totalMs,
    captionCues: captionCues,
    chapterCues: chapterCues,
  };
});
