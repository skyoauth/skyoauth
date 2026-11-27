#!/usr/bin/env node
// Parser and validator of demo walk-through transcripts
// (docs/proposals/demo-walkthroughs.md §2 and §5).
//
//   node scripts/demo/transcript.mjs check [--secret-env NAME]... <file>...
//
// A transcript is UTF-8 JSON lines, one record per line, each line exactly
// the canonical serialization {"step":N,"type":T,"text":S} (keys in that
// order, no spaces, no duplicate keys), ending with a line feed:
//
//   caption  the caption bar text (one line)
//   command  a command typed at the prompt (one line)
//   output   what the command printed (may hold \n)
//   note     a dim annotation, such as "library call: ..." (may hold \n)
//
// `step` counts from 0 with no gap. The checker refuses anything a
// published video must never carry or that would make two runs differ:
// unknown fields or types, wall-clock fields or timestamp-like values, PEM
// blocks, JWT-shaped strings, Bearer credentials, CR and other control or
// bidirectional-override characters, a line longer than the cap, a missing
// final line feed, and, with --secret-env NAME, the value of that
// environment variable anywhere in a record.
//
// Errors are printed as file:line: message. Exit 1 when a file has errors,
// 2 on a usage error (no file, unset or short --secret-env variable).
// Pure Node, no dependencies.

import { readFileSync } from 'node:fs';
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

// Patterns a transcript must not contain, each a regular expression or a
// test function applied to the decoded text of a record.
export const FORBIDDEN = [
  { name: 'PEM block', re: /-----BEGIN [A-Z0-9 ]*-----/ },
  // A JOSE compact serialization: base64url header starting {" (eyJ), then
  // at least one more dot-separated segment (JWS, JWE and unsecured JWT).
  { name: 'JWT-shaped string', re: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/ },
  // A Bearer credential: the scheme name (any case) followed by a token68
  // value that, once trailing sentence punctuation (. -) is dropped, holds a
  // digit or one of _ ~ + / =, or is 16 characters or longer. Prose such as
  // "Bearer tokens are shown as their type" passes; a redacted value is
  // written as <redacted>, which never matches.
  { name: 'Bearer credential', test: hasBearerCredential },
  // Wall-clock values: an ISO 8601 / RFC 3339 date-time, an HTTP or RFC
  // 2822 date, a time of day with seconds, or a Unix time in seconds or
  // milliseconds between 2001 and 2286. A bare date (2026-11-27) is allowed.
  { name: 'timestamp-like value (date and time)', re: /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/ },
  {
    name: 'timestamp-like value (HTTP date)',
    re: /\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}\b/,
  },
  { name: 'timestamp-like value (time of day)', re: /\b\d{1,2}:\d{2}:\d{2}\b/ },
  { name: 'timestamp-like value (Unix time)', re: /(?<![\w.-])1\d{9}(?:\d{3})?(?![\w.-])/ },
];

export function hasBearerCredential(text) {
  for (const m of text.matchAll(/\bbearer[ \t]+([A-Za-z0-9._~+/-]+=*)/gi)) {
    const value = m[1].replace(/[.-]+$/, '');
    if (/[0-9_~+/=]/.test(value) || value.length >= 16) return true;
  }
  return false;
}

// C0 controls other than LF, DEL, C1 controls, and the bidirectional
// embedding, override and isolate characters (which can make a line read
// differently from its bytes).
const CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩]/u;

function describeChar(ch) {
  return `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
}

// Validates one transcript given as bytes (Buffer or Uint8Array).
// `secrets` maps a label (the variable name) to a value that must not
// appear. Returns { records, errors: [{ line, message }] }; records holds
// the valid ones.
export function validateTranscript(bytes, { secrets = new Map() } = {}) {
  const errors = [];
  const err = (line, message) => errors.push({ line, message });
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
  const records = [];
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
    } catch (e) {
      err(n, `not JSON: ${e.message}`);
      return;
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      err(n, 'a record must be a JSON object');
      return;
    }
    const unknown = Object.keys(value).filter((k) => !['step', 'type', 'text'].includes(k));
    if (unknown.length) {
      err(n, `unknown field ${unknown.map((k) => JSON.stringify(k)).join(', ')} (allowed: step, type, text)`);
      return;
    }
    for (const k of ['step', 'type', 'text']) {
      if (!(k in value)) err(n, `missing field "${k}"`);
    }
    if (!('step' in value && 'type' in value && 'text' in value)) return;
    const { step, type, text: body } = value;
    let ok = true;
    if (!Number.isSafeInteger(step) || step < 0) {
      err(n, `"step" must be a non-negative integer, got ${JSON.stringify(step)}`);
      ok = false;
    } else if (step !== expected) {
      err(n, `"step" is ${step}, expected ${expected} (steps count from 0 with no gap)`);
      ok = false;
    }
    if (Number.isSafeInteger(step) && step >= 0) expected = step + 1;
    if (!TYPES.includes(type)) {
      err(n, `unknown type ${JSON.stringify(type)} (allowed: ${TYPES.join(', ')})`);
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
    if (ok && JSON.stringify({ step, type, text: body }) !== line) {
      err(n, 'not in canonical form: keys step, type, text in that order, no spaces, no duplicate keys, JSON.stringify escaping');
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
    for (const { name, re, test } of FORBIDDEN) {
      if (test ? test(body) : re.test(body)) {
        err(n, `${name} in "text"`);
        ok = false;
      }
    }
    for (const [label, secret] of secrets) {
      if (line.includes(secret) || body.includes(secret) || line.includes(JSON.stringify(secret).slice(1, -1))) {
        err(n, `the value of ${label} appears in the record`);
        ok = false;
      }
    }
    if (ok) records.push({ step, type, text: body });
  });
  return { records, errors };
}

// Reads and validates a file; throws with every file:line message when it
// is invalid, returns the records otherwise.
export function readTranscript(path, options) {
  const { records, errors } = validateTranscript(readFileSync(path), options);
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

class UsageError extends Error {}

const USAGE = 'usage: node scripts/demo/transcript.mjs check [--secret-env NAME]... <file>...';

export function main(argv, { env = process.env, out = console.log, error = console.error } = {}) {
  try {
    const [command, ...rest] = argv;
    if (command === '--help' || command === '-h') {
      out(USAGE);
      return 0;
    }
    if (command !== 'check') throw new UsageError(`unknown command ${JSON.stringify(command ?? '')}`);
    const files = [];
    const names = [];
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '--secret-env') {
        if (i + 1 >= rest.length) throw new UsageError('--secret-env needs a variable name');
        names.push(rest[++i]);
      } else if (rest[i].startsWith('--')) {
        throw new UsageError(`unknown option ${rest[i]}`);
      } else {
        files.push(rest[i]);
      }
    }
    if (files.length === 0) throw new UsageError('no transcript given (an empty list is refused, so a glob that matched nothing fails)');
    const secrets = secretsFromEnv(names, env);
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
