#!/usr/bin/env node
// Parser and validator of demo walk-through transcripts
// (docs/proposals/demo-walkthroughs.md §2 and §5).
//
//   node scripts/demo/transcript.mjs check [--secret-env NAME]... [--secret-file PATH]... <file>...
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
// Pure Node, no dependencies.

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';

export const TYPES = ['caption', 'command', 'output', 'note'];
// Types whose text may span several lines.
export const MULTILINE_TYPES = new Set(['output', 'note']);
// Characters per displayed line: the player's terminal is 120 columns.
export const MAX_COLUMNS = 120;
// Bytes per transcript line (one record).
export const MAX_RECORD_BYTES = 16384;
// Shortest --secret-env value the check accepts: a shorter one would match
// ordinary text.
export const MIN_SECRET_LENGTH = 8;

// Allow markers: the optional fourth field `allow` of a record. The only one
// is "hex-across-lines": it lifts the signature-sized hex rule from the
// joined forms (below) that hold this record, for output such as two 64-digit
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
  { name: 'Bearer credential', test: hasBearerCredential },
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

const hits = (rule, text) => (rule.test ? rule.test(text) : rule.re.test(text));

// The one value an Authorization (or Proxy-Authorization) field with the
// Bearer scheme may show.
export const REDACTED = '<redacted>';

// A Bearer credential, either of:
//   - an Authorization or Proxy-Authorization field (any case, as a header
//     `Authorization: Bearer x` or a JSON/YAML key `"authorization": "Bearer
//     x"`) whose Bearer value does not start with <redacted>, an empty
//     value included: no heuristic applies there;
//   - anywhere else, the scheme name (any case), blanks, then a token68
//     value that, once trailing sentence punctuation (. -) is dropped, holds
//     a digit or one of _ ~ + / =, or is 16 characters or longer. Not a
//     credential: prose ("Bearer tokens are shown as their type"), a
//     redacted value (<redacted>), and an auth-param (RFC 9110 §11.2: a
//     token, then "=" and a token or quoted string, as in `WWW-Authenticate:
//     Bearer realm="skyoauth"` or `Bearer error="invalid_token"`): a name
//     directly followed by =, or by exactly one = and then a quote or a
//     token character.
export function hasBearerCredential(text) {
  for (const m of text.matchAll(/\b(?:proxy-)?authorization["']?[ \t]*[:=][ \t]*["']?bearer\b[ \t]*([^\s"',;]*)/gi)) {
    // startsWith: a joined form may glue the next record's text to it.
    if (!m[1].startsWith(REDACTED)) return true;
  }
  for (const m of text.matchAll(/\bbearer[ \t]+([A-Za-z0-9._~+/-]+)(=*)/gi)) {
    const rest = text.slice(m.index + m[0].length);
    const authParam = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(m[1]) && ((m[2] === '' && /^[ \t]*=/.test(rest)) || (m[2] === '=' && /^["A-Za-z0-9!#$%&'*+.^_`|~-]/.test(rest)));
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

// The 0-based offset of the first JSON syntax error in `text` (a small
// RFC 8259 scanner), or -1 when it is valid. Used instead of JSON.parse's
// message, which can quote the input.
export function jsonErrorOffset(text) {
  let i = 0;
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i++;
  };
  const fail = () => {
    throw i;
  };
  const string = () => {
    if (text[i] !== '"') fail();
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
  };
  const value = () => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++;
      ws();
      if (text[i] === '}') return void i++;
      for (;;) {
        ws();
        string();
        ws();
        if (text[i] !== ':') fail();
        i++;
        value();
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === '}') return void i++;
        else fail();
      }
    } else if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') return void i++;
      for (;;) {
        value();
        ws();
        if (text[i] === ',') i++;
        else if (text[i] === ']') return void i++;
        else fail();
      }
    } else if (c === '"') string();
    else {
      const m = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(i));
      if (!m) fail();
      i += m[0].length;
    }
  };
  try {
    value();
    ws();
    if (i !== text.length) fail();
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
//   3. each pair of adjacent records (any types), and each run of three or
//      more consecutive output and note records: their texts, each with its
//      line feeds removed, concatenated directly, and the same texts (line
//      feeds replaced by spaces) joined with a space.
// A rule found in a form is not reported again for a larger form that
// holds the same record. The timestamp rules apply to each line only.
export function validateTranscript(bytes, { secrets = new Map() } = {}) {
  const errors = [];
  const err = (line, message) => errors.push({ line, message });
  const secretList = [...secrets].map(([label, v]) => [label, (Array.isArray(v) ? v : [v]).flatMap(secretVariants)]);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    err(1, 'not valid UTF-8');
    return { records: [], errors };
  }
  if (text.length === 0) {
    err(1, 'empty transcript: it needs at least one record');
    return { records: [], errors };
  }
  if (text.charCodeAt(0) === 0xfeff) err(1, 'byte order mark at the start of the file');
  if (!text.endsWith('\n')) err(text.split('\n').length, 'missing final line feed');

  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  // Every record whose text could be read, with or without other errors:
  // { line, raw, type, text, allow, ok, fired: Set of rule names }.
  const entries = [];
  let expected = 0;

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
    const unknown = Object.keys(value).filter((k) => !['step', 'type', 'text', 'allow'].includes(k));
    if (unknown.length) {
      err(n, `${unknown.length} unknown field(s) (allowed: step, type, text, allow)`);
      return;
    }
    for (const k of ['step', 'type', 'text']) {
      if (!(k in value)) err(n, `missing field "${k}"`);
    }
    if (!('step' in value && 'type' in value && 'text' in value)) return;
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
      err(n, `a ${type} is one line: "text" holds a line feed`);
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
    entries.push({ line: n, raw: line, step, type, text: body, allow: 'allow' in value ? allow : null, ok, fired: new Set() });
  });

  // Form 1 and 2: each record, then its unwrapped text.
  const fire = (group, name, at, where) => {
    for (const e of group) {
      e.fired.add(name);
      e.ok = false;
    }
    err(at, `${name} ${where}`);
  };
  const secretRule = ([label, values]) => ({ name: `the value of ${label}`, test: (t) => values.some((v) => t.includes(v)) });
  const allRules = [...SECRET_RULES, ...secretList.map(secretRule)];
  for (const e of entries) {
    for (const rule of allRules) {
      if (hits(rule, e.text) || (rule.name.startsWith('the value of ') && hits(rule, e.raw))) {
        fire([e], rule.name, e.line, rule.name.startsWith('the value of ') ? 'appears in the record' : 'in "text"');
      }
    }
    if (!e.text.includes('\n')) continue;
    const forms = [e.text.replaceAll('\n', ''), e.text.replaceAll('\n', ' ')];
    for (const rule of allRules) {
      if (e.fired.has(rule.name) || (rule.marker && e.allow === rule.marker)) continue;
      if (forms.some((f) => hits(rule, f))) fire([e], rule.name, e.line, 'in "text" with its line breaks removed');
    }
  }

  // Form 3: adjacent pairs, then runs of three or more output and note
  // records.
  const windows = [];
  for (let i = 1; i < entries.length; i++) windows.push(entries.slice(i - 1, i + 1));
  for (let i = 0; i < entries.length; ) {
    let j = i;
    while (j < entries.length && MULTILINE_TYPES.has(entries[j].type)) j++;
    if (j - i >= 3) windows.push(entries.slice(i, j));
    i = j > i ? j : i + 1;
  }
  for (const group of windows) {
    const direct = group.map((e) => e.text.replaceAll('\n', '')).join('');
    const spaced = group.map((e) => e.text.replaceAll('\n', ' ')).join(' ');
    for (const rule of allRules) {
      if (group.some((e) => e.fired.has(rule.name))) continue;
      if (rule.marker && group.some((e) => e.allow === rule.marker)) continue;
      if (hits(rule, direct) || hits(rule, spaced)) {
        const first = group[0].line;
        const last = group[group.length - 1].line;
        fire(group, rule.name, last, `across the records on lines ${first}-${last} (texts joined)`);
      }
    }
  }

  const records = entries.filter((e) => e.ok).map((e) => (e.allow ? { step: e.step, type: e.type, text: e.text, allow: e.allow } : { step: e.step, type: e.type, text: e.text }));
  return { records, errors: errors.sort((a, b) => a.line - b.line) };
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
    if (value === undefined || value === '') throw new UsageError(`--secret-env ${name}: the variable is unset or empty`);
    if (value.length < MIN_SECRET_LENGTH) {
      throw new UsageError(`--secret-env ${name}: the value is shorter than ${MIN_SECRET_LENGTH} characters and would match ordinary text`);
    }
    secrets.set(name, value);
  }
  return secrets;
}

// Secret keys of a --secret-file: every string value, at any depth of the
// JSON, under one of these key names. The committed test keys
// (tests/conformance/fixtures/**/*.test-key.json) hold their private keys
// as `keys[].seed`.
export const SECRET_KEYS = new Set(['seed', 'private_key', 'secret', 'password']);

// Collects the secret values of a JSON file: label -> value. Throws a usage
// error when the file cannot be read or parsed, names no secret, or holds a
// value too short to check.
export function secretsFromFile(path) {
  let content;
  try {
    content = readFileSync(path, 'utf8');
  } catch (e) {
    throw new UsageError(`--secret-file ${path}: cannot read: ${e.code ?? 'error'}`);
  }
  let json;
  try {
    json = JSON.parse(content);
  } catch {
    throw new UsageError(`--secret-file ${path}: not JSON${jsonErrorPosition(content)}`);
  }
  const secrets = new Map();
  const walk = (node, at) => {
    if (Array.isArray(node)) node.forEach((x, i) => walk(x, `${at}[${i}]`));
    else if (node !== null && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) {
        const here = at ? `${at}.${k}` : k;
        if (SECRET_KEYS.has(k) && typeof v === 'string') {
          if (v.length < MIN_SECRET_LENGTH) throw new UsageError(`--secret-file ${path}: ${here} is shorter than ${MIN_SECRET_LENGTH} characters`);
          secrets.set(`${basename(path)} ${here}`, v);
        } else walk(v, here);
      }
    }
  };
  walk(json, '');
  if (secrets.size === 0) throw new UsageError(`--secret-file ${path}: no string under a key named ${[...SECRET_KEYS].join(', ')}`);
  return secrets;
}

class UsageError extends Error {}

const USAGE = 'usage: node scripts/demo/transcript.mjs check [--secret-env NAME]... [--secret-file PATH]... <file>...';

export function main(argv, { env = process.env, out = console.log, error = console.error } = {}) {
  try {
    const [command, ...rest] = argv;
    if (command === '--help' || command === '-h') {
      out(USAGE);
      return 0;
    }
    if (command !== 'check') throw new UsageError('unknown command: the only command is check');
    const files = [];
    const names = [];
    const secretFiles = [];
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '--secret-env' || rest[i] === '--secret-file') {
        if (i + 1 >= rest.length) throw new UsageError(`${rest[i]} needs a value`);
        (rest[i] === '--secret-env' ? names : secretFiles).push(rest[++i]);
      } else if (rest[i].startsWith('--')) {
        throw new UsageError(/^--[a-z-]{1,40}$/.test(rest[i]) ? `unknown option ${rest[i]}` : 'unknown option');
      } else {
        files.push(rest[i]);
      }
    }
    if (files.length === 0) throw new UsageError('no transcript given (an empty list is refused, so a glob that matched nothing fails)');
    const secrets = secretsFromEnv(names, env);
    for (const f of secretFiles) for (const [k, v] of secretsFromFile(f)) secrets.set(k, v);
    let failed = 0;
    let records = 0;
    for (const file of files) {
      let bytes;
      try {
        bytes = readFileSync(file);
      } catch (e) {
        error(`${file}: cannot read: ${e.code ?? e.message}`);
        failed++;
        continue;
      }
      const result = validateTranscript(bytes, { secrets });
      for (const x of result.errors) error(`${file}:${x.line}: ${x.message}`);
      if (result.errors.length) failed++;
      records += result.records.length;
    }
    out(`transcript check: ${files.length} file(s), ${records} valid record(s), ${failed} file(s) with errors`);
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
