#!/usr/bin/env node
// Parser and validator of demo walk-through transcripts
// (docs/proposals/demo-walkthroughs.md §2, §5 and §6).
//
//   node scripts/demo/transcript.mjs check [--secret-env NAME]... [--secret-file PATH]... <file>...
//   node scripts/demo/transcript.mjs check-milestone [--secret-env NAME]... [--secret-file PATH]... <dir>...
//
// A transcript is UTF-8 JSON lines, one record per line, each line exactly
// the canonical serialization {"step":N,"type":T,"text":S} (keys in that
// order, no spaces, no duplicate keys), optionally followed by an allow
// marker ,"allow":"hex-across-lines" (ALLOW_MARKERS), ending with a line
// feed:
//
//   caption  the caption bar text (one line)
//   command  a command typed at the prompt (one line)
//   output   what the command printed (may hold \n)
//   note     a dim annotation, such as "library call: ..." (may hold \n)
//   chapter  "<journey id>: <title>", the journey's title card (one line,
//            1 to MAX_CHAPTER_CHARS code points, no allow marker): in a
//            single file at most one, and only as step 0 (§6.1)
//
// `step` counts from 0 with no gap. The checker refuses anything a
// published video must never carry or that would make two runs differ:
// unknown fields, types or allow markers; timestamp-like values
// (TIMESTAMP_RULES, per line); CR and other control or bidirectional
// characters; a line longer than the cap; a missing final line feed; and
// the SECRET_RULES (PEM blocks, JWT-shaped strings, Bearer credentials,
// signature-sized hex and base64url runs) and the values of --secret-env
// variables and --secret-file keys, each also across line breaks and
// adjacent records (validateTranscript says exactly which joined forms).
// It is a check for known shapes and known values, not a proof that a
// transcript holds no secret: a credential of another shape, or one split
// by more than line breaks and record boundaries, is not found.
//
// Errors are printed as file:line: message; a message names the rule, or
// the expected field, type or JSON position, and never repeats the record's
// text, values or unknown key names. Exit 1 when a file has errors,
// 2 on a usage error (no file; an unset or short --secret-env variable; a
// --secret-file that cannot be read or names no secret).
//
// check-milestone checks milestone directories (§6.2, §6.3): the names and
// the manifest (checkMilestone), each journey file alone, and the joined
// and chapter-stripped passes and the title window over the journeys.
// Exit 1 when anything failed, 2 on a usage error (no directory included).
// Pure Node, no dependencies.

import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const TYPES = ['caption', 'command', 'output', 'note', 'chapter'];
// Types whose text may span several lines.
export const MULTILINE_TYPES = new Set(['output', 'note']);
// Characters per displayed line: the player's terminal is 120 columns.
export const MAX_COLUMNS = 120;
// Bytes per transcript line (one record).
export const MAX_RECORD_BYTES = 16384;
// Code points of a chapter's text, "<journey id>: <title>" (§6.1).
export const MAX_CHAPTER_CHARS = 80;
// A milestone id, a journey id (§6.2), and a chapter's text: the journey id,
// a colon, a space and a title that starts with a non-blank character.
export const MILESTONE_ID = /^M[1-5][ab]?$/;
export const JOURNEY_ID = /^M[1-5][ab]?-[1-9][0-9]*$/;
export const CHAPTER_TEXT = /^(M[1-5][ab]?-[1-9][0-9]*): \S/;
// The manifest of a milestone directory.
export const MANIFEST = 'milestone.json';
// Shortest --secret-env value the check accepts: a shorter one would match
// ordinary text.
export const MIN_SECRET_LENGTH = 8;

// Allow markers: the optional fourth field `allow` of a record. The only one
// is "hex-across-lines": it lifts the signature-sized hex rule from the
// joined forms (below) that hold this record (never from a stretch of
// unmarked records beside it), for output such as two 64-digit
// public keys on adjacent lines, which joined look like one 128-digit
// signature and cannot be told apart from one. Every other rule still
// applies to the record and to its joined forms, the hex rule still applies
// to each of its lines, and --secret-env and --secret-file values are
// refused everywhere.
export const ALLOW_MARKERS = ['hex-across-lines'];

// Secret rules. Each is a regular expression or a test function, applied to
// a record's text and to its joined forms (see validateTranscript).
export const SECRET_RULES = [
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/ },
  // A JOSE compact serialization: base64url header starting {" (eyJ), then
  // at least two more dot-separated segments (JWS, JWE, unsecured JWT).
  { name: 'JWT-shaped string', re: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/ },
  { name: 'Bearer credential', test: (text, joined) => hasBearerCredential(text, { joined }) },
  // A signature or private key in hexadecimal: 96 digits or more (an
  // Ed25519 signature is 128). A 64-digit run, the size of an Ed25519 or
  // other 32-byte public key and also of a seed, is allowed: only the
  // known seeds of --secret-file are refused at that size.
  { name: 'hex run of 96 or more digits (signature-sized)', re: /[0-9a-fA-F]{96,}/, marker: 'hex-across-lines' },
  // A signature in base64url: 86 characters or more of [A-Za-z0-9_-] (an
  // Ed25519 signature is 86 unpadded) holding an upper-case letter, a
  // lower-case letter and a digit, as random bytes almost always do (a
  // line of 86 dashes or a long kebab-case word passes).
  { name: 'base64url run of 86 or more characters (signature-sized)', test: hasLongBase64url },
];

// Wall-clock rules, applied to each line of a record's text only: an ISO
// 8601 / RFC 3339 date-time, an HTTP or RFC 2822 date, a time of day with
// seconds, or a Unix time (hasUnixTime). A bare date (2026-11-27) is
// allowed.
export const TIMESTAMP_RULES = [
  { name: 'timestamp-like value (date and time)', re: /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/ },
  {
    name: 'timestamp-like value (HTTP date)',
    re: /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}\b/,
  },
  { name: 'timestamp-like value (time of day)', re: /\b\d{1,2}:\d{2}:\d{2}\b/ },
  { name: 'timestamp-like value (Unix time)', test: hasUnixTime },
];

// Unix seconds from 2001-09-09T01:46:40Z (the first 10-digit value) to
// 2286-11-20T17:46:39Z (the last one).
export const UNIX_MIN_S = 1_000_000_000;
export const UNIX_MAX_S = 9_999_999_999;

// A Unix time: a number of exactly 10 digits (seconds) or 13 (milliseconds),
// not part of a longer word, number or dotted version (a sentence's final
// dot is fine), whose value in seconds is within UNIX_MIN_S..UNIX_MAX_S.
// Any such number counts, a counter or an ID included.
export function hasUnixTime(text) {
  for (const [digits] of text.matchAll(/(?<![\w.-])(?:\d{13}|\d{10})(?![\w-]|\.\d)/g)) {
    const seconds = digits.length === 13 ? Number(digits) / 1000 : Number(digits);
    if (seconds >= UNIX_MIN_S && seconds <= UNIX_MAX_S + 0.999) return true;
  }
  return false;
}

// `joined`: the text is a joined form (validateTranscript), which may glue
// the next line or record directly to a value.
const hits = (rule, text, joined = false) => (rule.test ? rule.test(text, joined) : rule.re.test(text));

// The one value an Authorization (or Proxy-Authorization) field with the
// Bearer scheme may show.
export const REDACTED = '<redacted>';

// The auth-param names a Bearer challenge may start with (RFC 6750 §3,
// RFC 9728 §5.1): only these count as an auth-param after "Bearer ".
export const BEARER_AUTH_PARAMS = ['realm', 'scope', 'error', 'error_description', 'error_uri', 'resource_metadata'];

// A Bearer credential, either of:
//   - an Authorization or Proxy-Authorization field (any case, as a header
//     `Authorization: Bearer x` or a JSON/YAML key `"authorization": "Bearer
//     x"`, also JSON-escaped `{\"authorization\": \"Bearer x\"}`) whose
//     Bearer value is not exactly <redacted>, an empty value included: no
//     heuristic applies there. The value ends at a blank, quote, comma or
//     semicolon, or at an escape that decodes to a blank or a quote: \n \r
//     \t \" \' (lower case only). Any other backslash is part of the value,
//     so `Bearer <redacted>\a1b2`, `\\abc`, `\/abc`, `\b`, `\f`, `\u0041`
//     and an upper-case `\N` or `\U1b2c3` are refused. The field and scheme
//     names match in any case through explicit [Aa] classes, not the `i`
//     flag, which would also make the escape letters match in either case.
//     When the value is quoted (`"Bearer`, `\"Bearer`), an escape after it
//     other than the closing quote continues the same string (`"Bearer
//     <redacted>\nabc"`) and is refused.
//     In a joined form (`joined`) the value need only start with <redacted>,
//     since the join may glue the next line or record to it; each record
//     alone was already held to the exact value;
//   - anywhere else, the scheme name (any case), blanks, then a token68
//     value that, once trailing sentence punctuation (. -) is dropped, holds
//     a digit or one of _ ~ + / =, or is 16 characters or longer. Not a
//     credential: prose ("Bearer tokens are shown as their type"), a
//     redacted value (<redacted>), and an auth-param (RFC 9110 §11.2) whose
//     name is one of BEARER_AUTH_PARAMS (any case), as in `WWW-Authenticate:
//     Bearer realm="skyoauth"` or `Bearer error="invalid_token"`: the name
//     directly followed by =, or by exactly one = and then a quote (also
//     JSON-escaped, \") or a token character. Any other name=... is a padded token
//     (`Bearer dGhpc2lz=`, `Bearer a1b2=c3`).
export function hasBearerCredential(text, { joined = false } = {}) {
  for (const m of text.matchAll(/\b(?:[Pp][Rr][Oo][Xx][Yy]-)?[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]\\?["']?[ \t]*[:=][ \t]*(\\?["'])?[Bb][Ee][Aa][Rr][Ee][Rr]\b[ \t]*((?:[^\s"',;\\]|\\(?![nrt"']))*)/g)) {
    const [, quote, value] = m;
    if (joined ? !value.startsWith(REDACTED) : value !== REDACTED) return true;
    const rest = text.slice(m.index + m[0].length);
    if (quote && rest.startsWith('\\') && !rest.startsWith(quote)) return true;
  }
  for (const m of text.matchAll(/\bbearer[ \t]+([A-Za-z0-9._~+/-]+)(=*)/gi)) {
    const rest = text.slice(m.index + m[0].length);
    const authParam =
      BEARER_AUTH_PARAMS.includes(m[1].toLowerCase()) && ((m[2] === '' && /^[ \t]*=/.test(rest)) || (m[2] === '=' && /^(?:\\?"|[A-Za-z0-9!#$%&'*+.^_`|~-])/.test(rest)));
    if (authParam) continue;
    const value = (m[1] + m[2]).replace(/[.-]+$/, '');
    if (/[0-9_~+/=]/.test(value) || value.length >= 16) return true;
  }
  return false;
}

export function hasLongBase64url(text) {
  for (const [run] of text.matchAll(/[A-Za-z0-9_-]{86,}/g)) {
    if (/[A-Z]/.test(run) && /[a-z]/.test(run) && /[0-9]/.test(run)) return true;
  }
  return false;
}

// C0 controls other than LF, DEL, C1 controls, and the bidirectional
// embedding, override and isolate characters (which can make a line read
// differently from its bytes).
const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u;

// Control and bidirectional characters (CONTROL) and line feeds, in a name.
const NAME_UNSAFE = new RegExp(`[\\n]|${CONTROL.source}`, 'gu');

// A file or directory name as a message prints it: each control or
// bidirectional character, line feed included, as <U+XXXX>, so a name can
// neither move the cursor (ESC), rewrite the line (CR) nor start a line
// that looks like another message (LF).
export function printableName(name) {
  return String(name).replace(NAME_UNSAFE, (c) => `<${describeChar(c)}>`);
}

// A small RFC 8259 scanner. Parses `text` into plain values, except that an
// object is a JsonObject holding every [key, value] entry in file order,
// duplicate keys included (JSON.parse keeps only the last one). Throws the
// 0-based offset of the first syntax error (a number), never the text.
export class JsonObject {
  constructor(entries) {
    this.entries = entries;
  }
}

export function scanJson(text) {
  let i = 0;
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i++;
  };
  const fail = () => {
    throw i;
  };
  const string = () => {
    if (text[i] !== '"') fail();
    const from = i;
    i++;
    while (i < text.length && text[i] !== '"') {
      const c = text.charCodeAt(i);
      if (c < 0x20) fail();
      if (text[i] === '\\') {
        i++;
        if (text[i] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 1, i + 5))) fail();
          i += 4;
        } else if (!'"\\/bfnrt'.includes(text[i] ?? 'x')) fail();
      }
      i++;
    }
    if (i >= text.length) fail();
    i++;
    return JSON.parse(text.slice(from, i));
  };
  const value = () => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      ws();
      const entries = [];
      if (text[i] === '}') {
        i++;
        return new JsonObject(entries);
      }
      for (;;) {
        ws();
        const key = string();
        ws();
        if (text[i] !== ':') fail();
        i++;
        entries.push([key, value()]);
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === '}') {
          i++;
          return new JsonObject(entries);
        } else fail();
      }
    } else if (c === '[') {
      i++;
      ws();
      const items = [];
      if (text[i] === ']') {
        i++;
        return items;
      }
      for (;;) {
        items.push(value());
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === ']') {
          i++;
          return items;
        } else fail();
      }
    } else if (c === '"') return string();
    else {
      const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
      if (!m) fail();
      i += m[0].length;
      return JSON.parse(m[0]);
    }
  };
  const result = value();
  ws();
  if (i !== text.length) fail();
  return result;
}

// The 0-based offset of the first JSON syntax error in `text`, or -1 when
// it is valid. Used instead of JSON.parse's message, which can quote the
// input.
export function jsonErrorOffset(text) {
  try {
    scanJson(text);
    return -1;
  } catch (at) {
    if (typeof at !== 'number') throw at;
    return at;
  }
}

// " at character N" for the first syntax error of `text`, never its text.
function jsonErrorPosition(text) {
  const at = jsonErrorOffset(text);
  return at >= 0 ? ` at character ${at + 1}` : '';
}

function describeChar(ch) {
  return `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
}

// The strings a secret value is also refused as: its JSON-escaped form and,
// for an even-length hexadecimal value, its bytes in upper and lower case
// hex, base64 (padded and not) and base64url.
export function secretVariants(value) {
  const variants = new Set([value, JSON.stringify(value).slice(1, -1)]);
  if (/^(?:[0-9a-fA-F]{2})+$/.test(value)) {
    const bytes = Buffer.from(value, 'hex');
    const b64 = bytes.toString('base64');
    for (const v of [value.toLowerCase(), value.toUpperCase(), b64, b64.replace(/=+$/, ''), bytes.toString('base64url')]) variants.add(v);
  }
  return [...variants];
}

// Validates one transcript given as bytes (Buffer or Uint8Array).
// `secrets` maps a label to a value, or to a list of values, that must not
// appear (secretsFromEnv, secretsFromFile). Returns { records, errors:
// [{ line, message }] }; records holds the records without errors.
//
// The secret rules, the --secret-env and the --secret-file values are
// applied to these forms, so a value wrapped over lines or split over
// records is still found:
//   1. each record's text;
//   2. each multi-line record's text with its line feeds removed, and with
//      each line feed replaced by a space;
//   3. each pair of adjacent records (any types), each run of three or
//      more consecutive output and note records, and, within such a run
//      that holds allow-marked records, each stretch of three or more
//      unmarked records: their texts, each with its line feeds removed,
//      concatenated directly, and the same texts (line feeds replaced by
//      spaces) joined with a space.
// A rule found in a form is not reported again for a larger form that
// holds the same record. The timestamp rules apply to each line only.
//
// Chapters (§6.1). By default (a single file, as `check` reads it) a
// chapter is allowed only as the first record, at step 0, and only once.
// `milestone: true` is the milestone mode, for a joined milestone stream
// (§6.3): the stream opens with a chapter at step 0, and a chapter is also
// allowed at a later step (the first step of each later journey).
// `journeyFile: '<name>.jsonl'` is a journey file of a milestone checked
// alone (check-milestone): as the default, and the file must open with its
// chapter, whose journey id in lower case plus ".jsonl" is the file's name.
export function validateTranscript(bytes, options = {}) {
  const { records, errors } = validateEntries(bytes, options);
  return { records, errors };
}

// The secret rules and the --secret-env/--secret-file values as rules.
function rulesFor(secrets) {
  const secretList = [...secrets].map(([label, v]) => [label, (Array.isArray(v) ? v : [v]).flatMap(secretVariants)]);
  const secretRule = ([label, values]) => ({ name: `the value of ${label}`, value: true, test: (t) => values.some((v) => t.includes(v)) });
  return [...SECRET_RULES, ...secretList.map(secretRule)];
}

// validateTranscript, also returning every record whose text could be read
// (with or without other errors) as `entries`: { line, raw, step, type,
// text, allow, ok, fired: Set of rule names }. check-milestone builds its
// joined passes from them.
// `lineLabel(line)`, when given, names a line in the message of a window
// (check-milestone maps a joined line back to its file and line).
function validateEntries(bytes, { secrets = new Map(), milestone = false, journeyFile = null, lineLabel = null } = {}) {
  if (milestone && journeyFile !== null) throw new Error('validateTranscript: milestone and journeyFile exclude each other');
  const errors = [];
  const err = (line, message) => errors.push({ line, message });
  const done = (entries = []) => ({ records: [], errors, entries });
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    err(1, 'not valid UTF-8');
    return done();
  }
  if (text.length === 0) {
    err(1, 'empty transcript: it needs at least one record');
    return done();
  }
  if (text.charCodeAt(0) === 0xfeff) err(1, 'byte order mark at the start of the file');
  if (!text.endsWith('\n')) err(text.split('\n').length, 'missing final line feed');

  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const entries = [];
  let expected = 0;
  let chapters = 0;

  lines.forEach((raw, index) => {
    const n = index + 1;
    const line = n === 1 && raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
    if (Buffer.byteLength(line, 'utf8') > MAX_RECORD_BYTES) {
      err(n, `record longer than ${MAX_RECORD_BYTES} bytes`);
      return;
    }
    if (line.includes('\r')) {
      err(n, 'carriage return (CR) in the file: lines must end with LF only');
      return;
    }
    if (line === '') {
      err(n, 'blank line');
      return;
    }
    let value;
    try {
      value = JSON.parse(line);
    } catch {
      err(n, `not JSON${jsonErrorPosition(line)}`);
      return;
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      err(n, 'a record must be a JSON object');
      return;
    }
    // A record refused for its fields still takes part in the secret
    // checks and the windows when its text is a string: it is never in the
    // returned records, but its neighbours stay its neighbours.
    // Its valid step still counts, so the next record is not refused for
    // the gap.
    const refused = () => {
      if (Number.isSafeInteger(value.step) && value.step >= 0) expected = value.step + 1;
      if (typeof value.text !== 'string') return;
      const allow = ALLOW_MARKERS.includes(value.allow) ? value.allow : null;
      entries.push({ line: n, raw: line, step: value.step, type: TYPES.includes(value.type) ? value.type : null, text: value.text, allow, ok: false, fired: new Set() });
    };
    const unknown = Object.keys(value).filter((k) => !['step', 'type', 'text', 'allow'].includes(k));
    if (unknown.length) {
      err(n, `${unknown.length} unknown field(s) (allowed: step, type, text, allow)`);
      refused();
      return;
    }
    for (const k of ['step', 'type', 'text']) {
      if (!(k in value)) err(n, `missing field "${k}"`);
    }
    if (!('step' in value && 'type' in value && 'text' in value)) {
      refused();
      return;
    }
    const { step, type, text: body, allow } = value;
    let ok = true;
    if (!Number.isSafeInteger(step) || step < 0) {
      err(n, '"step" must be a non-negative integer');
      ok = false;
    } else if (step !== expected) {
      err(n, `"step" must be ${expected} (steps count from 0 with no gap)`);
      ok = false;
    }
    if (Number.isSafeInteger(step) && step >= 0) expected = step + 1;
    if (!TYPES.includes(type)) {
      err(n, `"type" must be one of ${TYPES.join(', ')}`);
      ok = false;
    }
    if ('allow' in value && !ALLOW_MARKERS.includes(allow)) {
      err(n, `"allow" must be one of ${ALLOW_MARKERS.join(', ')}`);
      ok = false;
    }
    if (typeof body !== 'string') {
      err(n, '"text" must be a string');
      return;
    }
    if (body.length === 0) {
      err(n, '"text" is empty');
      ok = false;
    }
    const canonical = 'allow' in value ? JSON.stringify({ step, type, text: body, allow }) : JSON.stringify({ step, type, text: body });
    if (ok && canonical !== line) {
      err(n, 'not in canonical form: keys step, type, text (then allow, if any) in that order, no spaces, no duplicate keys, JSON.stringify escaping');
      ok = false;
    }
    const control = CONTROL.exec(body);
    if (control) {
      err(n, `control or bidirectional character ${describeChar(control[0])} in "text"`);
      ok = false;
    }
    if (body.includes('\n') && !MULTILINE_TYPES.has(type)) {
      // Only a known type is named: an unknown one would echo the input.
      err(n, TYPES.includes(type) ? `a ${type} is one line: "text" holds a line feed` : '"text" holds a line feed: only output and note may span lines');
      ok = false;
    }
    body.split('\n').forEach((l, i) => {
      const columns = Array.from(l).length;
      if (columns > MAX_COLUMNS) {
        err(n, `text line ${i + 1} is ${columns} characters, over the ${MAX_COLUMNS}-column cap`);
        ok = false;
      }
    });
    for (const rule of TIMESTAMP_RULES) {
      if (hits(rule, body)) {
        err(n, `${rule.name} in "text"`);
        ok = false;
      }
    }
    if (type === 'chapter') {
      chapters++;
      const chars = Array.from(body).length;
      if (chars > MAX_CHAPTER_CHARS) {
        err(n, `a chapter is at most ${MAX_CHAPTER_CHARS} characters (code points), this one is ${chars}`);
        ok = false;
      }
      if (!CHAPTER_TEXT.test(body)) {
        err(n, 'a chapter is "<journey id>: <title>": a journey id such as M1a-2, a colon, a space and a title');
        ok = false;
      }
      if ('allow' in value) {
        err(n, 'a chapter takes no "allow" marker');
        ok = false;
      }
      // The first record is the one on line 1 (n === 1); a single file
      // allows one chapter there only, milestone mode one at any step.
      if (!milestone && chapters > 1) {
        err(n, 'a second chapter: a single journey file holds at most one, as step 0');
        ok = false;
      } else if (!milestone && (n !== 1 || step !== 0)) {
        err(n, 'a chapter is only allowed as the first record, at step 0 (a later one only in a joined milestone stream)');
        ok = false;
      }
    }
    entries.push({ line: n, raw: line, step, type, text: body, allow: 'allow' in value ? allow : null, ok, fired: new Set() });
  });

  // The opening chapter of a milestone stream or a journey file, and the
  // journey id of a journey file's chapter. Not reported again when line 1
  // already has an error (it may be the chapter, unreadable).
  if (milestone || journeyFile !== null) {
    const first = entries[0];
    if (first?.line === 1 && first.type === 'chapter') {
      const id = CHAPTER_TEXT.exec(first.text)?.[1];
      if (journeyFile !== null && id !== undefined && `${id.toLowerCase()}.jsonl` !== journeyFile) {
        const fileId = journeyIdOfFile(journeyFile);
        err(1, fileId ? `the chapter names journey ${id}, not this file's ${fileId}` : `the chapter names journey ${id}, whose file is ${id.toLowerCase()}.jsonl, not this one`);
        first.ok = false;
      }
    } else if (!errors.some((e) => e.line === 1)) {
      err(1, milestone ? 'a joined milestone stream opens with a chapter at step 0' : 'a journey file of a milestone opens with its chapter, at step 0');
      if (first?.line === 1) first.ok = false;
    }
  }

  const rules = rulesFor(secrets);
  const fire = (group, name, at, where) => {
    for (const e of group) {
      e.fired.add(name);
      e.ok = false;
    }
    err(at, `${name} ${where}`);
  };
  checkRecordForms(entries, rules, (e, rule, where) => fire([e], rule.name, e.line, where));
  checkGroups(recordWindows(entries), rules, (group, rule) => {
    const first = group[0].line;
    const last = group[group.length - 1].line;
    const span = lineLabel ? `${lineLabel(first)} - ${lineLabel(last)}` : `lines ${first}-${last}`;
    fire(group, rule.name, last, `across the records on ${span} (texts joined)`);
  });

  const records = entries.filter((e) => e.ok).map(recordOf);
  return { records, errors: errors.sort((a, b) => a.line - b.line), entries };
}

const recordOf = (e) => (e.allow ? { step: e.step, type: e.type, text: e.text, allow: e.allow } : { step: e.step, type: e.type, text: e.text });

// The journey id whose file is `name` ("m1a-2.jsonl" -> "M1a-2"), or null.
function journeyIdOfFile(name) {
  const m = /^m([1-5][ab]?-[1-9][0-9]*)\.jsonl$/.exec(name);
  return m ? `M${m[1]}` : null;
}

// Forms 1 and 2: each record, then its unwrapped text. `onHit(entry, rule,
// where)` reports and marks.
function checkRecordForms(entries, rules, onHit) {
  for (const e of entries) {
    for (const rule of rules) {
      if (hits(rule, e.text) || (rule.value && hits(rule, e.raw))) {
        onHit(e, rule, rule.value ? 'appears in the record' : 'in "text"');
      }
    }
    if (!e.text.includes('\n')) continue;
    const forms = [e.text.replaceAll('\n', ''), e.text.replaceAll('\n', ' ')];
    for (const rule of rules) {
      if (e.fired.has(rule.name) || (rule.marker && e.allow === rule.marker)) continue;
      if (forms.some((f) => hits(rule, f, true))) onHit(e, rule, 'in "text" with its line breaks removed');
    }
  }
}

// Form 3: adjacent pairs, then runs of three or more output and note
// records (a chapter, like any other type, ends a run).
function recordWindows(entries) {
  const windows = [];
  for (let i = 1; i < entries.length; i++) windows.push(entries.slice(i - 1, i + 1));
  for (let i = 0; i < entries.length; ) {
    let j = i;
    while (j < entries.length && MULTILINE_TYPES.has(entries[j].type)) j++;
    if (j - i >= 3) windows.push(entries.slice(i, j));
    // Within a run that holds marked records, the marker lifts the hex rule
    // from the run: also check each stretch of three or more unmarked
    // records between them, so a signature split over them is still found
    // (shorter stretches are pairs, already windows of their own).
    for (let k = i; k < j; ) {
      let l = k;
      while (l < j && entries[l].allow === null) l++;
      if (l - k >= 3 && l - k < j - i) windows.push(entries.slice(k, l));
      k = l > k ? l : k + 1;
    }
    i = j > i ? j : i + 1;
  }
  return windows;
}

// Applies every rule to each group's joined texts (direct and with a
// space), skipping a rule that a record of the group already fired, and a
// marker-lifted rule when a record of the group carries the marker.
// `onHit(group, rule)` reports and marks.
function checkGroups(groups, rules, onHit) {
  for (const group of groups) {
    const direct = group.map((e) => e.text.replaceAll('\n', '')).join('');
    const spaced = group.map((e) => e.text.replaceAll('\n', ' ')).join(' ');
    for (const rule of rules) {
      if (group.some((e) => e.fired.has(rule.name))) continue;
      if (rule.marker && group.some((e) => e.allow === rule.marker)) continue;
      if (hits(rule, direct, true) || hits(rule, spaced, true)) onHit(group, rule);
    }
  }
}

// Reads and validates a file; throws with every file:line message when it
// is invalid, returns the records otherwise.
export function readTranscript(path, options) {
  return recordsFromBytes(readFileSync(path), path, options);
}

// Validates bytes already read (a snapshot); `path` only labels the
// messages. Throws like readTranscript.
export function recordsFromBytes(bytes, path, options) {
  const { records, errors } = validateTranscript(bytes, options);
  if (errors.length) {
    const e = new Error(errors.map((x) => `${path}:${x.line}: ${x.message}`).join('\n'));
    e.diagnostics = errors;
    throw e;
  }
  return records;
}

// Collects --secret-env values from the environment. Throws a usage error
// for an unset, empty or too short variable: a check that silently
// checked nothing would read as a pass.
export function secretsFromEnv(names, env = process.env) {
  const secrets = new Map();
  for (const name of names) {
    const value = env[name];
    if (value === undefined || value === '') throw new UsageError(`--secret-env ${printableName(name)}: the variable is unset or empty`);
    if (value.length < MIN_SECRET_LENGTH) {
      throw new UsageError(`--secret-env ${printableName(name)}: the value is shorter than ${MIN_SECRET_LENGTH} characters and would match ordinary text`);
    }
    secrets.set(printableName(name), value);
  }
  return secrets;
}

// Secret keys of a --secret-file: every string value, at any depth of the
// JSON, under one of these key names. The committed test keys
// (tests/conformance/fixtures/**/*.test-key.json) hold their private keys
// as `keys[].seed`.
export const SECRET_KEYS = new Set(['seed', 'private_key', 'secret', 'password']);

// Adds one secret to `secrets` (label -> value) without ever replacing
// one: a label already taken by another value moves the new one to
// `label #2`, `label #3`, ...; the same value under the same label is kept
// once.
function addSecret(secrets, label, value) {
  let at = label;
  for (let n = 2; secrets.has(at); n++) {
    if (secrets.get(at) === value) return;
    at = `${label} #${n}`;
  }
  secrets.set(at, value);
}

// Adds the secrets of `source` (label -> value) to `target` without ever
// replacing one: two inputs with the same display label (two files of the same
// name in different directories) keep every value, the later ones under
// `label #2`, `label #3`, ...
export function mergeSecrets(target, source) {
  for (const [label, value] of source) addSecret(target, label, value);
  return target;
}

// Collects the secret values of a JSON file: label -> value. Throws a usage
// error when the file cannot be read or parsed, names no secret, or holds a
// value too short to check. A key that appears twice in one object keeps
// both values (JSON.parse would keep only the last): the file is read with
// scanJson, which keeps every entry.
export function secretsFromFile(path) {
  let content;
  try {
    content = readFileSync(path, 'utf8');
  } catch (e) {
    throw new UsageError(`--secret-file ${printableName(path)}: cannot read: ${e.code ?? 'error'}`);
  }
  let json;
  try {
    json = scanJson(content);
  } catch (at) {
    if (typeof at !== 'number') throw at;
    throw new UsageError(`--secret-file ${printableName(path)}: not JSON at character ${at + 1}`);
  }
  const secrets = new Map();
  // A key name is part of a label (messages, rule names) only when it is
  // plain ([A-Za-z0-9_]); any other name could hold anything, so it is
  // shown by its 1-based position in its object instead: <key 3>. The
  // position is in JavaScript property order (what Object.keys gives for
  // the parsed object: integer-like keys first, in ascending order, then
  // the others in file order), not file order; a repeated key counts once,
  // at its first place.
  const segment = (k, i) => (/^[A-Za-z0-9_]+$/.test(k) ? k : `<key ${i + 1}>`);
  const walk = (node, at) => {
    if (Array.isArray(node)) node.forEach((x, i) => walk(x, `${at}[${i}]`));
    else if (node instanceof JsonObject) {
      const byKey = new Map();
      for (const [k, v] of node.entries) {
        if (!byKey.has(k)) byKey.set(k, []);
        byKey.get(k).push(v);
      }
      const keys = Object.keys(Object.fromEntries([...byKey.keys()].map((k) => [k, true])));
      for (const [i, k] of keys.entries()) {
        const here = at ? `${at}.${segment(k, i)}` : segment(k, i);
        for (const v of byKey.get(k)) {
          if (SECRET_KEYS.has(k) && typeof v === 'string') {
            if (v.length < MIN_SECRET_LENGTH) throw new UsageError(`--secret-file ${printableName(path)}: ${here} is shorter than ${MIN_SECRET_LENGTH} characters`);
            addSecret(secrets, `${printableName(basename(path))} ${here}`, v);
          } else walk(v, here);
        }
      }
    }
  };
  walk(json, '');
  if (secrets.size === 0) throw new UsageError(`--secret-file ${printableName(path)}: no string under a key named ${[...SECRET_KEYS].join(', ')}`);
  return secrets;
}

// Milestone directories (§6.2, §6.3).
//
//   <dir>/milestone.json   {"milestone":"M1a","journeys":["M1a-1","M1a-2",...]}
//   <dir>/<journey>.jsonl  one transcript per listed journey
//
// The directory's name is the milestone id in lower case; each listed
// journey's file is named exactly `<lower-case journey id>.jsonl`; the
// directory holds nothing else (no unlisted file, no nested directory, no
// symlink: every entry is checked with lstat, and files are read with
// readNoFollow). A directory entry is printed only when it is recognized
// (milestone.json or a journey file name, <lower-case journey id>.jsonl)
// and matches no secret rule or value (nameMatchesSecret); any other is
// shown by its 1-based position in the sorted listing, <entry 3>. Every
// other name a message prints goes through printableName, and a path
// argument that matches a secret rule or value is shown as <argument N>.

// Largest manifest read, in bytes: a list of journey ids is far smaller.
export const MAX_MANIFEST_BYTES = 65536;
// Bad manifest entries (and listed journeys with no file) reported one by
// one; the rest are counted in one "... and N more" line.
export const MAX_REPORTED_ENTRIES = 20;

// The first MAX_REPORTED_ENTRIES messages, then one that counts the rest.
function capped(messages, rest) {
  if (messages.length <= MAX_REPORTED_ENTRIES) return messages;
  return [...messages.slice(0, MAX_REPORTED_ENTRIES), `... and ${messages.length - MAX_REPORTED_ENTRIES} more ${rest}`];
}

// Whether a name matches a secret rule or value (`rules`, rulesFor): such
// a name is never printed.
function nameMatchesSecret(name, rules) {
  return rules.some((rule) => hits(rule, name) || hits(rule, name, true));
}

// Reads a regular file without following a symlink at its last component.
// On every platform: the path is checked with lstat (a symlink is refused
// with code ELOOP, anything but a regular file with 'not a regular file'),
// then opened, and the open file must be the same file (device and inode,
// as bigints) as the one lstat saw, so a file replaced between the two
// (by a link or another file) is refused with code 'changed'. Where Node
// has O_NOFOLLOW (POSIX; not Windows), the open also refuses a symlink
// itself. With `maxBytes`, a larger file is not read: code 'too large'.
// `beforeOpen` is a test hook, called between the lstat and the open.
export function readNoFollow(path, maxBytes = Infinity, { beforeOpen = () => {} } = {}) {
  const fail = (code) => Object.assign(new Error(code), { code });
  const seen = lstatSync(path, { bigint: true });
  if (seen.isSymbolicLink()) throw fail('ELOOP');
  if (!seen.isFile()) throw fail('not a regular file');
  beforeOpen();
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile()) throw fail('not a regular file');
    if (st.dev !== seen.dev || st.ino !== seen.ino) throw fail('changed');
    if (st.size > BigInt(Math.min(maxBytes, Number.MAX_SAFE_INTEGER))) throw fail('too large');
    const bytes = readFileSync(fd);
    if (bytes.length > maxBytes) throw fail('too large');
    return bytes;
  } finally {
    closeSync(fd);
  }
}

// Checks a manifest's bytes. Returns { milestone, journeys } or { problems:
// [message] }. A message never repeats a value that is not a valid id, nor
// an unknown key's name. One message per bad entry of "journeys" (the
// first problem found), at most MAX_REPORTED_ENTRIES of them.
export function parseManifest(bytes) {
  const problems = [];
  if (bytes.length > MAX_MANIFEST_BYTES) return { problems: [`larger than ${MAX_MANIFEST_BYTES} bytes (64 KiB): a manifest lists journey ids only`] };
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { problems: ['not valid UTF-8'] };
  }
  let doc;
  try {
    doc = scanJson(text);
  } catch (at) {
    // scanJson recurses once per level: a deep enough nesting exhausts the
    // stack. Its message is not shown.
    if (at instanceof RangeError) return { problems: ['too deeply nested to read: a manifest is one object holding a list'] };
    if (typeof at !== 'number') throw at;
    return { problems: [`not JSON at character ${at + 1}`] };
  }
  if (!(doc instanceof JsonObject)) return { problems: ['must be a JSON object {"milestone":"M1a","journeys":["M1a-1",...]}'] };
  const keys = doc.entries.map(([k]) => k);
  const unknown = keys.filter((k) => k !== 'milestone' && k !== 'journeys');
  if (unknown.length) problems.push(`${unknown.length} unknown key(s) (allowed: milestone, journeys)`);
  for (const k of ['milestone', 'journeys']) {
    const n = keys.filter((x) => x === k).length;
    if (n === 0) problems.push(`missing key "${k}"`);
    if (n > 1) problems.push(`key "${k}" appears ${n} times`);
  }
  const get = (k) => doc.entries.find(([x]) => x === k)?.[1];
  const milestone = get('milestone');
  const milestoneOk = typeof milestone === 'string' && MILESTONE_ID.test(milestone);
  if (keys.includes('milestone') && !milestoneOk) problems.push('"milestone" is not a milestone id (^M[1-5][ab]?$)');
  const journeys = get('journeys');
  if (keys.includes('journeys')) {
    if (!Array.isArray(journeys)) problems.push('"journeys" must be a list of journey ids');
    else if (journeys.length === 0) problems.push('"journeys" is empty: a milestone lists at least one journey');
    else {
      const seen = new Map();
      const bad = [];
      journeys.forEach((id, i) => {
        if (typeof id !== 'string' || !JOURNEY_ID.test(id)) bad.push(`journeys[${i}] is not a journey id (^M[1-5][ab]?-[1-9][0-9]*$)`);
        else if (milestoneOk && !id.startsWith(`${milestone}-`)) bad.push(`journeys[${i}] (${id}) is not a journey of ${milestone}: its id must start with ${milestone}-`);
        else if (seen.has(id)) bad.push(`journeys[${i}] (${id}) repeats journeys[${seen.get(id)}]: each journey is listed once`);
        else seen.set(id, i);
      });
      problems.push(...capped(bad, 'bad entries in "journeys"'));
    }
  }
  return problems.length ? { problems } : { milestone, journeys };
}

// Joins the records of a milestone's journeys, in manifest order: each
// record's step becomes (records in the earlier journeys) + (its step in
// its file). Each list is one journey file's records.
export function joinJourneys(lists) {
  const joined = [];
  for (const records of lists) {
    const offset = joined.length;
    for (const r of records) joined.push({ ...r, step: offset + r.step });
  }
  return joined;
}

// Checks one milestone directory: the names and the manifest, then each
// journey file alone (validateTranscript with journeyFile: every rule, plus
// its chapter at step 0 naming the file's journey), then, when the manifest
// is good and every listed file could be read, the journeys in manifest
// order:
//   - the joined stream. When every journey file is valid, the joined
//     stream itself (joinJourneys, serialized) is validated in milestone
//     mode with every rule, so a rule that depends on the renumbered step
//     (the record byte cap) is applied, and each error is mapped back to its
//     file and line. When a file has errors, its records are not all valid
//     records, so the joined stream is not serialized: the pairs of
//     adjacent records across each journey boundary (the last record of one
//     journey with the next one's chapter) are checked over every parsed
//     record of every file, the ones with errors included. Every other
//     window of the joined stream is one file's, already checked alone (a
//     chapter ends a run of output and note records);
//   - the chapter-stripped stream: every parsed record without the
//     chapters, each keeping its file and line: the pairs of records that
//     the stripping makes adjacent (the last record of one journey and the
//     first record of the next), reported as "(chapters removed)". A run of
//     output and note records never spans a journey boundary;
//   - the title window: every chapter's text joined, in manifest order.
// Each record keeps the rules it fired alone and in the earlier passes, so
// an error already reported is not reported again for a larger window, and
// allow markers carry over unchanged. With a bad manifest every .jsonl file
// of the directory is still checked alone.
//
// `label` is how messages name the directory (default printableName).
// Returns { problems: [{ path, line, message }] (line null for a name or
// manifest problem), notes: [string], files, records, milestone, joined }:
// `joined` is the renumbered joined stream (joinJourneys) when nothing
// failed, else null.
export function checkMilestone(dirArg, { secrets = new Map(), label: dirLabel = printableName(dirArg) } = {}) {
  const problems = [];
  const notes = [];
  const result = { problems, notes, files: 0, records: 0, milestone: null, joined: null };
  const at = (path, message, line = null) => problems.push({ path, line, message });
  // The directory itself, resolved: `.`, `m1a/` and `m1a/.` name it by its
  // own name, and lstat sees a symlink however the path ends.
  const dir = resolve(dirArg);
  const dirShown = dirLabel.length > 1 ? dirLabel.replace(/\/+$/, '') || '/' : dirLabel;
  let st;
  try {
    st = lstatSync(dir);
  } catch (e) {
    at(dirLabel, `cannot read: ${e.code ?? 'error'}`);
    return result;
  }
  if (st.isSymbolicLink()) {
    at(dirLabel, 'a symlink: a milestone directory must be a directory, not a link to one');
    return result;
  }
  if (!st.isDirectory()) {
    at(dirLabel, 'not a directory');
    return result;
  }
  let names;
  try {
    names = readdirSync(dir).sort();
  } catch (e) {
    at(dirLabel, `cannot read: ${e.code ?? 'error'}`);
    return result;
  }
  const rules = rulesFor(secrets);
  // Only a recognized name is printed (the manifest's, or a journey file
  // name), and only when it matches no secret rule or value: any other
  // entry is shown by its place in the sorted listing.
  const recognized = (name) => name === MANIFEST || journeyIdOfFile(name) !== null;
  const shown = (name) => (recognized(name) && !nameMatchesSecret(name, rules) ? name : `<entry ${names.indexOf(name) + 1}>`);
  const pathOf = (name) => join(dirShown, shown(name));

  // Every entry with lstat: only regular files may stay.
  const regular = new Set();
  for (const name of names) {
    let s;
    try {
      s = lstatSync(join(dir, name));
    } catch (e) {
      at(pathOf(name), `cannot read: ${e.code ?? 'error'}`);
      continue;
    }
    if (s.isSymbolicLink()) at(pathOf(name), 'a symlink: a milestone directory holds only regular files, and symlinks are not followed');
    else if (s.isDirectory()) at(pathOf(name), 'a nested directory: a milestone directory holds only milestone.json and its journey files');
    else if (!s.isFile()) at(pathOf(name), 'not a regular file');
    else regular.add(name);
  }

  // The manifest.
  let manifest = null;
  if (!names.includes(MANIFEST)) at(join(dirShown, MANIFEST), 'missing: a milestone directory holds its manifest');
  else if (regular.has(MANIFEST)) {
    let bytes;
    try {
      bytes = readNoFollow(join(dir, MANIFEST), MAX_MANIFEST_BYTES);
    } catch (e) {
      at(join(dirShown, MANIFEST), e.code === 'too large' ? `larger than ${MAX_MANIFEST_BYTES} bytes (64 KiB): a manifest lists journey ids only` : `cannot read: ${e.code ?? 'error'}`);
    }
    if (bytes) {
      const parsed = parseManifest(bytes);
      if (parsed.problems) for (const p of parsed.problems) at(join(dirShown, MANIFEST), p);
      else manifest = parsed;
    }
  }
  const dirName = basename(dir);
  if (manifest) {
    result.milestone = manifest.milestone;
    if (dirName !== manifest.milestone.toLowerCase()) at(dirLabel, `the directory name is not ${manifest.milestone.toLowerCase()}, the lower case of the milestone id ${manifest.milestone}`);
  } else if (!/^m[1-5][ab]?$/.test(dirName)) {
    at(dirLabel, 'the directory name is not a lower-case milestone id (such as m1a or m2)');
  }

  // Listed, missing and unlisted files.
  const listed = manifest ? manifest.journeys.map((id) => ({ id, name: `${id.toLowerCase()}.jsonl` })) : [];
  const listedNames = new Set(listed.map((j) => j.name));
  const missing = listed.filter(({ name }) => !names.includes(name));
  const missingMessages = missing.map(({ id }) => `missing: milestone.json lists ${id}`);
  // A missing file's name comes from its validated id; it is still not
  // printed when it matches a secret value (then by its place in the list).
  const missingShown = ({ id, name }) => (nameMatchesSecret(name, rules) ? `<listed file ${manifest.journeys.indexOf(id) + 1}>` : name);
  capped(missingMessages, 'listed journeys have no file').forEach((m, i) => at(i < MAX_REPORTED_ENTRIES ? join(dirShown, missingShown(missing[i])) : dirShown, m));
  for (const name of names) {
    if (name === MANIFEST || listedNames.has(name) || !regular.has(name)) continue;
    if (manifest) at(pathOf(name), 'not listed in milestone.json: a milestone directory holds only its manifest and the files of the journeys it lists');
    else if (!journeyIdOfFile(name)) at(pathOf(name), 'neither milestone.json nor a journey file (<lower-case journey id>.jsonl)');
  }

  // Each journey file alone: the listed ones in manifest order, then every
  // other regular .jsonl file.
  const alone = new Map();
  const order = [...listed.map((j) => j.name).filter((n) => regular.has(n)), ...names.filter((n) => regular.has(n) && n.endsWith('.jsonl') && !listedNames.has(n))];
  for (const name of order) {
    let bytes;
    try {
      bytes = readNoFollow(join(dir, name));
    } catch (e) {
      at(pathOf(name), `cannot read: ${e.code ?? 'error'}`);
      continue;
    }
    const v = validateEntries(bytes, { secrets, journeyFile: name });
    result.files++;
    result.records += v.records.length;
    alone.set(name, v);
    for (const e of v.errors) at(pathOf(name), e.message, e.line);
  }

  if (!manifest || !listed.every((j) => alone.has(j.name))) {
    notes.push(`${dirLabel}: the joined checks were not run: ${manifest ? 'a listed journey file is missing or unreadable' : 'the manifest is missing or bad'}`);
    return result;
  }

  // Every parsed record (entries), each tagged with its file and its index
  // in that file. `fired` is shared with the file's own pass, so a rule a
  // record fired alone (or in an earlier pass) is not reported again for
  // it.
  const tagged = listed.flatMap(({ name }) => alone.get(name).entries.map((e, idx) => ({ ...e, file: name, idx })));
  const where = (e) => `${shown(e.file)}:${e.line}`;
  const report = (what, how) => (group, rule) => {
    for (const e of group) e.fired.add(rule.name);
    const last = group[group.length - 1];
    at(pathOf(last.file), `${rule.name} across the ${what} on ${where(group[0])} - ${where(last)} (${how})`, last.line);
  };
  const adjacentAlone = (a, b) => a.file === b.file && b.idx === a.idx + 1;
  const newPairs = (list) => list.slice(1).map((b, i) => [list[i], b]).filter(([a, b]) => !adjacentAlone(a, b));

  // The joined stream.
  const allValid = listed.every(({ name }) => alone.get(name).errors.length === 0);
  let joined = null;
  if (allValid) {
    // Every record of every file is valid, so the joined stream's line n is
    // tagged[n - 1].
    joined = joinJourneys(listed.map(({ name }) => alone.get(name).records));
    const bytes = Buffer.from(joined.map((r) => `${JSON.stringify(r)}\n`).join(''), 'utf8');
    const v = validateEntries(bytes, { secrets, milestone: true, lineLabel: (n) => where(tagged[n - 1]) });
    for (const e of v.errors) {
      const t = tagged[e.line - 1];
      at(pathOf(t.file), e.message.includes(' across the records on ') ? e.message : `${e.message} (in the joined milestone stream, as step ${e.line - 1})`, t.line);
    }
    for (const e of v.entries) for (const name of e.fired) tagged[e.line - 1].fired.add(name);
  } else {
    checkGroups(newPairs(tagged), rules, report('records', 'texts joined'));
  }
  // The chapter-stripped stream, then the title window.
  checkGroups(newPairs(tagged.filter((e) => e.type !== 'chapter')), rules, report('records', 'chapters removed'));
  const titles = tagged.filter((e) => e.type === 'chapter');
  if (titles.length > 1) checkGroups([titles], rules, report('chapter titles', 'titles joined'));

  if (problems.length === 0) result.joined = joined;
  return result;
}

class UsageError extends Error {}

const USAGE = [
  'usage: node scripts/demo/transcript.mjs check [--secret-env NAME]... [--secret-file PATH]... <file>...',
  '       node scripts/demo/transcript.mjs check-milestone [--secret-env NAME]... [--secret-file PATH]... <dir>...',
].join('\n');

export function main(argv, { env = process.env, out = console.log, error = console.error } = {}) {
  try {
    const [command, ...rest] = argv;
    if (command === '--help' || command === '-h') {
      out(USAGE);
      return 0;
    }
    if (command !== 'check' && command !== 'check-milestone') throw new UsageError('unknown command: the commands are check and check-milestone');
    const paths = [];
    const names = [];
    const secretFiles = [];
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '--secret-env' || rest[i] === '--secret-file') {
        if (i + 1 >= rest.length) throw new UsageError(`${rest[i]} needs a value`);
        (rest[i] === '--secret-env' ? names : secretFiles).push(rest[++i]);
      } else if (rest[i].startsWith('--')) {
        throw new UsageError(/^--[a-z-]{1,40}$/.test(rest[i]) ? `unknown option ${rest[i]}` : 'unknown option');
      } else {
        paths.push(rest[i]);
      }
    }
    if (paths.length === 0) {
      throw new UsageError(
        command === 'check'
          ? 'no transcript given (an empty list is refused, so a glob that matched nothing fails)'
          : 'no milestone directory given (an empty list is refused, so a glob that matched nothing fails)',
      );
    }
    const secrets = secretsFromEnv(names, env);
    for (const f of secretFiles) mergeSecrets(secrets, secretsFromFile(f));
    // A path as messages name it: printable, and never shown when it
    // matches a secret rule or value (then by its place among the paths).
    const rules = rulesFor(secrets);
    const label = (path, i) => (nameMatchesSecret(path, rules) ? `<argument ${i + 1}>` : printableName(path));
    if (command === 'check-milestone') {
      let failed = 0;
      let files = 0;
      let records = 0;
      for (const [i, dir] of paths.entries()) {
        const r = checkMilestone(dir, { secrets, label: label(dir, i) });
        for (const p of r.problems) error(p.line === null ? `${p.path}: ${p.message}` : `${p.path}:${p.line}: ${p.message}`);
        for (const n of r.notes) error(n);
        if (r.problems.length) failed++;
        files += r.files;
        records += r.records;
      }
      out(`transcript check-milestone: ${paths.length} director(ies), ${files} journey file(s), ${records} valid record(s), ${failed} director(ies) with errors`);
      return failed ? 1 : 0;
    }
    let failed = 0;
    let records = 0;
    for (const [i, path] of paths.entries()) {
      const file = label(path, i);
      let bytes;
      try {
        bytes = readFileSync(path);
      } catch (e) {
        error(`${file}: cannot read: ${e.code ?? 'error'}`);
        failed++;
        continue;
      }
      const result = validateTranscript(bytes, { secrets });
      for (const x of result.errors) error(`${file}:${x.line}: ${x.message}`);
      if (result.errors.length) failed++;
      records += result.records.length;
    }
    out(`transcript check: ${paths.length} file(s), ${records} valid record(s), ${failed} file(s) with errors`);
    return failed ? 1 : 0;
  } catch (e) {
    if (e instanceof UsageError) {
      error(`transcript: ${e.message}\n${USAGE}`);
      return 2;
    }
    throw e;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exitCode = main(process.argv.slice(2));
}
