// WebVTT sidecar for a transcript: one cue per caption record, timed by
// timing.js (captionCues), the same schedule the player shows the captions
// on. Pure: no file, clock or environment access.

import timing from './timing.js';

// HH:MM:SS.mmm, as WebVTT requires.
export function formatVttTime(ms) {
  if (!Number.isSafeInteger(ms) || ms < 0) throw new Error(`vtt: bad time ${ms}`);
  const pad = (n, w) => String(n).padStart(w, '0');
  const h = Math.floor(ms / 3600000);
  const m = Math.floor(ms / 60000) % 60;
  const s = Math.floor(ms / 1000) % 60;
  return `${pad(h, 2)}:${pad(m, 2)}:${pad(s, 2)}.${pad(ms % 1000, 3)}`;
}

// Cue text is plain text: escape the three characters WebVTT gives a
// meaning to (which also keeps "-->" out of a cue).
export function escapeCueText(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// The whole file, LF line endings and a final LF.
export function toVtt(records) {
  const lines = ['WEBVTT', ''];
  for (const cue of timing.captionCues(records)) {
    lines.push(`step-${cue.step}`);
    lines.push(`${formatVttTime(cue.startMs)} --> ${formatVttTime(cue.endMs)}`);
    lines.push(escapeCueText(cue.text));
    lines.push('');
  }
  return lines.join('\n');
}

// Minimal reader for the files toVtt writes (used by the tests): the cues
// with their times in milliseconds.
export function parseVtt(text) {
  if (!text.endsWith('\n')) throw new Error('vtt: missing final line feed');
  const blocks = text.slice(0, -1).split('\n\n');
  if (blocks[0] !== 'WEBVTT') throw new Error('vtt: missing WEBVTT header');
  const cues = [];
  for (const block of blocks.slice(1)) {
    if (block === '') continue;
    const [id, times, ...body] = block.split('\n');
    const m = /^(\d{2}):(\d{2}):(\d{2})\.(\d{3}) --> (\d{2}):(\d{2}):(\d{2})\.(\d{3})$/.exec(times ?? '');
    if (!m) throw new Error(`vtt: bad timing line in cue ${id}`);
    const ms = (h, mi, s, f) => ((+h * 60 + +mi) * 60 + +s) * 1000 + +f;
    cues.push({ id, startMs: ms(m[1], m[2], m[3], m[4]), endMs: ms(m[5], m[6], m[7], m[8]), text: body.join('\n') });
  }
  return cues;
}
