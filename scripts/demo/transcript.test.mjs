// Self-test of transcript.mjs (pure: no browser, no ffmpeg, no network):
//   node --test scripts/demo/transcript.test.mjs
//
// Each rejection is shown with a mutant of a valid transcript: the valid
// one passes, the mutant fails with the expected message on the expected
// line.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { MAX_COLUMNS, MAX_RECORD_BYTES, UNIX_MAX_S, hasBearerCredential, hasLongBase64url, hasUnixTime, jsonErrorOffset, main, secretsFromFile, secretVariants, validateTranscript } from './transcript.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'transcript.mjs');
const SAMPLE = join(HERE, 'sample', 'sample.transcript.jsonl');
const TMP = mkdtempSync(join(tmpdir(), 'demo-transcript-test-'));
after(() => rmSync(TMP, { recursive: true, force: true }));
const KEY_FILE = join(HERE, '..', '..', 'tests', 'conformance', 'fixtures', '_recovery', 'recovery.test-key.json');

const rec = (step, type, text) => JSON.stringify({ step, type, text });
const BASE = [
  rec(0, 'caption', 'A valid caption'),
  rec(1, 'command', 'example-operator status'),
  rec(2, 'output', 'line one\nline two'),
  rec(3, 'note', 'library call: example::read()'),
];
const file = (lines) => Buffer.from(lines.map((l) => `${l}\n`).join(''), 'utf8');
const check = (bytes, options) => validateTranscript(typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes, options);

// Replaces record `index` of BASE (0-based) and expects exactly the errors
// matching `pattern`, on that record's line.
function rejects(replacement, pattern, index = 2) {
  const lines = [...BASE];
  lines[index] = replacement;
  const { errors } = check(file(lines));
  assert.ok(errors.length > 0, `accepted: ${replacement}`);
  assert.ok(
    errors.some((e) => e.line === index + 1 && pattern.test(e.message)),
    `expected ${pattern} on line ${index + 1}, got ${JSON.stringify(errors)}`,
  );
}

function accepts(replacement, index = 2) {
  const lines = [...BASE];
  lines[index] = replacement;
  const { errors, records } = check(file(lines));
  assert.deepEqual(errors, [], `rejected: ${replacement}`);
  assert.equal(records.length, BASE.length);
}

describe('valid transcripts', () => {
  it('accepts the base transcript and returns its records', () => {
    const { errors, records } = check(file(BASE));
    assert.deepEqual(errors, []);
    assert.deepEqual(records[2], { step: 2, type: 'output', text: 'line one\nline two' });
  });

  it('accepts the committed sample, which is marked as a sample in a caption', () => {
    const { errors, records } = check(readFileSync(SAMPLE));
    assert.deepEqual(errors, []);
    assert.ok(records.some((r) => r.type === 'caption' && /\bSAMPLE\b/.test(r.text)));
  });
});

describe('structure', () => {
  it('rejects unknown fields, wall-clock fields included', () => {
    for (const extra of ['ts', 'time', 'timestamp', 'elapsed_ms', 'id']) {
      rejects(JSON.stringify({ step: 2, type: 'output', text: 'x', [extra]: 1 }), /^1 unknown field\(s\) \(allowed: step, type, text, allow\)$/);
    }
  });

  it('rejects missing fields', () => {
    rejects(JSON.stringify({ step: 2, type: 'output' }), /missing field "text"/);
    rejects(JSON.stringify({ step: 2, text: 'x' }), /missing field "type"/);
    rejects(JSON.stringify({ type: 'output', text: 'x' }), /missing field "step"/);
  });

  it('rejects unknown types', () => {
    rejects(rec(2, 'stdout', 'x'), /^"type" must be one of caption, command, output, note$/);
    rejects(rec(2, 'Caption', 'x'), /^"type" must be one of/);
    rejects(JSON.stringify({ step: 2, type: 1, text: 'x' }), /^"type" must be one of/);
  });

  it('rejects a step that does not count from 0 with no gap', () => {
    rejects(rec(1, 'caption', 'x'), /^"step" must be 0 \(steps count from 0 with no gap\)$/, 0);
    rejects(rec(3, 'output', 'x'), /^"step" must be 2 /);
    rejects(rec(1, 'output', 'x'), /^"step" must be 2 /);
    rejects(JSON.stringify({ step: '2', type: 'output', text: 'x' }), /non-negative integer/);
    rejects(JSON.stringify({ step: 2.5, type: 'output', text: 'x' }), /non-negative integer/);
    rejects(JSON.stringify({ step: -1, type: 'output', text: 'x' }), /non-negative integer/);
  });

  it('rejects non-object records, non-JSON and empty or non-string text', () => {
    rejects('[2,"output","x"]', /must be a JSON object/);
    rejects('null', /must be a JSON object/);
    rejects('{"step":2,', /^not JSON at character 11$/);
    rejects('not json', /^not JSON at character 1$/);
    rejects(rec(2, 'output', ''), /"text" is empty/);
    rejects(JSON.stringify({ step: 2, type: 'output', text: 5 }), /"text" must be a string/);
  });

  it('rejects a record that is not in canonical form (spaces, key order, duplicate keys, escapes)', () => {
    rejects('{"step": 2, "type": "output", "text": "x"}', /canonical form/);
    rejects('{"type":"output","step":2,"text":"x"}', /canonical form/);
    rejects('{"step":2,"type":"output","text":"hidden","text":"x"}', /canonical form/);
    rejects('{"step":2,"type":"output","text":"\\u0078"}', /canonical form/);
  });

  it('rejects an empty file, a blank line, a missing final LF, a BOM and invalid UTF-8', () => {
    assert.match(check('').errors[0].message, /empty transcript/);
    const blank = check(`${BASE[0]}\n\n${BASE[1]}\n`).errors;
    assert.ok(blank.some((e) => e.line === 2 && /blank line/.test(e.message)), JSON.stringify(blank));
    const nolf = check(file(BASE).subarray(0, -1)).errors;
    assert.deepEqual(nolf, [{ line: 4, message: 'missing final line feed' }]);
    assert.ok(check(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), file(BASE)])).errors.some((e) => /byte order mark/.test(e.message)));
    assert.match(check(Buffer.concat([file(BASE), Buffer.from([0xff, 0x0a])])).errors[0].message, /not valid UTF-8/);
  });
});

describe('characters and lengths', () => {
  it('rejects CR line endings and CR in text', () => {
    const crlf = check(BASE.map((l) => `${l}\r\n`).join('')).errors;
    assert.ok(crlf.length >= BASE.length && crlf.every((e) => /carriage return/.test(e.message)), JSON.stringify(crlf));
    rejects(rec(2, 'output', 'progress 10%\rprogress 20%'), /control or bidirectional character U\+000D/);
  });

  it('rejects control characters, ANSI escapes, tabs, DEL, C1 and bidirectional overrides', () => {
    for (const [ch, code] of [
      ['\u0000', '0000'],
      ['\u0007', '0007'],
      ['\t', '0009'],
      ['\u001b[31m', '001B'],
      ['\u007f', '007F'],
      ['\u0085', '0085'],
      ['\u202e', '202E'],
      ['\u2066', '2066'],
    ]) {
      rejects(rec(2, 'output', `a${ch}b`), new RegExp(`U\\+${code}`));
    }
  });

  it('allows LF only in output and note', () => {
    accepts(rec(2, 'output', 'a\nb'));
    accepts(rec(3, 'note', 'a\nb'), 3);
    rejects(rec(0, 'caption', 'a\nb'), /a caption is one line/, 0);
    rejects(rec(1, 'command', 'a\nb'), /a command is one line/, 1);
  });

  it(`caps every displayed line at ${MAX_COLUMNS} characters (code points)`, () => {
    accepts(rec(2, 'output', 'x'.repeat(MAX_COLUMNS)));
    accepts(rec(2, 'output', 'é'.repeat(MAX_COLUMNS)));
    rejects(rec(2, 'output', 'x'.repeat(MAX_COLUMNS + 1)), /line 1 is 121 characters/);
    rejects(rec(2, 'output', `ok\n${'x'.repeat(MAX_COLUMNS + 1)}`), /line 2 is 121 characters/);
  });

  it(`caps a record at ${MAX_RECORD_BYTES} bytes`, () => {
    const big = Array.from({ length: 200 }, () => 'y'.repeat(100)).join('\n');
    rejects(rec(2, 'output', big), new RegExp(`longer than ${MAX_RECORD_BYTES} bytes`));
  });
});

describe('secrets and wall-clock values', () => {
  it('rejects PEM blocks of any kind', () => {
    for (const label of ['PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'CERTIFICATE', 'PUBLIC KEY']) {
      rejects(rec(2, 'output', `-----BEGIN ${label}-----\nMC4CAQAwBQYDK2VwBCIEIA\n-----END ${label}-----`), /PEM block/);
    }
  });

  it('rejects JWT-shaped strings (JWS, unsecured JWT, JWE), alone or inside other text', () => {
    const jws = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
    rejects(rec(2, 'output', jws), /JWT-shaped/);
    rejects(rec(2, 'output', `token=${jws};`), /JWT-shaped/);
    rejects(rec(2, 'output', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.'), /JWT-shaped/);
    rejects(rec(2, 'output', 'eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn'), /JWT-shaped/);
    accepts(rec(2, 'output', 'token: <redacted> (type JWT, audience sample-api)'));
  });

  it('rejects Bearer credentials and allows prose and redacted values', () => {
    for (const text of [
      'Authorization: Bearer abc123',
      'authorization: bearer mF_9.B5f-4.1JqM',
      'BEARER dGhpcyBpcyBhIHRva2Vu==',
      'Bearer abcdefghijklmnopqrstuvwxyz',
      'Bearer a/b+c',
    ]) {
      rejects(rec(2, 'output', text), /Bearer credential/);
    }
    for (const text of ['Authorization: Bearer <redacted>', 'Bearer tokens are shown as their type.', 'a Bearer token-bound flow']) {
      accepts(rec(2, 'output', text));
    }
    assert.equal(hasBearerCredential('Bearer authentication'), false);
    assert.equal(hasBearerCredential('Bearer authentication1'), true);
  });

  it('rejects timestamp-like values and allows a bare date', () => {
    for (const [text, what] of [
      ['created_at: 2026-11-27T10:15:00Z', /date and time/],
      ['2026-11-27 10:15', /date and time/],
      ['Date: Fri, 27 Nov 2026 10:15:00 GMT', /HTTP date/],
      ['at 10:15:00', /time of day/],
      ['iat: 1795694100', /Unix time/],
      ['exp=1795694100000', /Unix time/],
    ]) {
      rejects(rec(2, 'output', text), what);
    }
    accepts(rec(2, 'output', 'ruled on 2026-11-27, revision 3, port 8443'));
    accepts(rec(2, 'output', 'id 0123456789 and v1.795694100'));
  });

  it('bounds Unix times numerically: 10-digit seconds and 13-digit milliseconds from 2001 to 2286', () => {
    for (const text of ['1000000000', '2051222400', '2051222400000', '4102444800', `${UNIX_MAX_S}`, '9999999999999', 'at 1795694100.']) {
      assert.equal(hasUnixTime(text), true, text);
    }
    rejects(rec(2, 'output', 'exp: 2051222400'), /Unix time/);
    rejects(rec(2, 'output', 'exp_ms: 2051222400000'), /Unix time/);
    for (const text of ['0999999999', '999999999', '12345678901', '123456789012', '0123456789012', 'v2051222400', '2051222400.5', '1.2051222400']) {
      assert.equal(hasUnixTime(text), false, text);
    }
  });

  it('rejects the value of a --secret-env variable, also in its JSON-escaped form', () => {
    const secrets = new Map([['DEMO_SECRET', 'not-a-real-secret-42']]);
    const lines = [...BASE];
    lines[1] = rec(1, 'command', 'login --password not-a-real-secret-42');
    const { errors } = check(file(lines), { secrets });
    assert.deepEqual(errors, [{ line: 2, message: 'the value of DEMO_SECRET appears in the record' }]);
    const quoted = new Map([['Q', 'quote"and\\slash']]);
    lines[1] = rec(1, 'command', 'echo quote"and\\slash');
    assert.equal(check(file(lines), { secrets: quoted }).errors.length, 1);
    assert.deepEqual(check(file(BASE), { secrets }).errors, []);
  });

  it('reports every bad record with its own line number', () => {
    const lines = [...BASE, rec(4, 'output', 'Bearer abc123'), rec(5, 'output', 'fine'), rec(6, 'output', 'at 10:15:00')];
    const { errors } = check(file(lines));
    assert.deepEqual(
      errors.map((e) => e.line),
      [5, 7],
    );
  });
});

describe('Authorization fields', () => {
  it('require exactly <redacted> as the Bearer value, with no heuristic', () => {
    for (const text of [
      'Authorization: Bearer tokens',
      'authorization: bearer abc',
      'AUTHORIZATION:Bearer x',
      'Proxy-Authorization: Bearer someword',
      'Authorization: Bearer',
      'Authorization: Bearer $TOKEN',
      'curl -H "Authorization: Bearer ${TOKEN}"',
      '{"authorization": "Bearer abc"}',
      "authorization='Bearer abc'",
      'Authorization: Bearer redacted',
      'Authorization: Bearer <REDACTED>',
    ]) {
      assert.equal(hasBearerCredential(text), true, text);
      rejects(rec(2, 'output', text), /^Bearer credential in "text"$/);
    }
    for (const text of ['Authorization: Bearer <redacted>', 'curl -H "Authorization: Bearer <redacted>"', '{"authorization": "Bearer <redacted>"}']) {
      accepts(rec(2, 'output', text));
    }
  });

  it('leave WWW-Authenticate challenges and prose to the general rule', () => {
    accepts(rec(2, 'output', 'WWW-Authenticate: Bearer realm="skyoauth"'));
    accepts(rec(2, 'output', 'the Authorization header carries Bearer tokens'));
  });
});

describe('Bearer auth-params', () => {
  it('passes a WWW-Authenticate challenge and its error parameters', () => {
    for (const text of [
      'WWW-Authenticate: Bearer realm="skyoauth"',
      'Bearer error="invalid_token"',
      'WWW-Authenticate: Bearer realm="skyoauth", error="invalid_token", error_description="expired"',
      'Bearer realm = "skyoauth"',
      'Bearer scope=read',
    ]) {
      accepts(rec(2, 'output', text));
      assert.equal(hasBearerCredential(text), false, text);
    }
  });

  it('still refuses tokens, padded tokens included', () => {
    for (const text of ['Bearer abc123', 'Bearer abc123==', 'Bearer abc123= x', 'Bearer abc123=,', 'Authorization: Bearer mF_9.B5f-4.1JqM realm="x"']) {
      assert.equal(hasBearerCredential(text), true, text);
    }
  });
});

const JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
const SIG_HEX = createHash('sha512').update('demo signature').digest('hex');
const SIG_B64URL = createHash('sha512').update('demo signature').digest('base64url');
const PUB_HEX = createHash('sha256').update('demo public key').digest('hex');
const KEYS = JSON.parse(readFileSync(KEY_FILE, 'utf8')).keys;

// A transcript of the given [type, text] records (and allow markers).
const transcript = (...records) => file(records.map(([type, text, allow], step) => (allow ? JSON.stringify({ step, type, text, allow }) : rec(step, type, text))));
const errorsOf = (bytes, options) => check(bytes, options).errors;

describe('secret rules across line breaks and records', () => {
  it('finds a JWT wrapped over lines of one record', () => {
    const errors = errorsOf(transcript(['caption', 'c'], ['output', `token:\n${JWT.slice(0, 20)}\n${JWT.slice(20)}`]));
    assert.deepEqual(errors, [{ line: 2, message: 'JWT-shaped string in "text" with its line breaks removed' }]);
  });

  it('finds a JWT split over two adjacent records, reported on the last line', () => {
    const errors = errorsOf(transcript(['caption', 'c'], ['output', JWT.slice(0, 30)], ['output', JWT.slice(30)], ['note', 'n']));
    assert.deepEqual(errors, [{ line: 3, message: 'JWT-shaped string across the records on lines 2-3 (texts joined)' }]);
  });

  it('finds a JWT split over three output and note records (no pair holds it)', () => {
    const [a, b, c] = JWT.split('.');
    const errors = errorsOf(transcript(['command', 'x'], ['output', a], ['note', `.${b}`], ['output', `.${c}`]));
    assert.deepEqual(errors, [{ line: 4, message: 'JWT-shaped string across the records on lines 2-4 (texts joined)' }]);
  });

  it('finds a JWT split over adjacent records of other types', () => {
    const errors = errorsOf(transcript(['command', `curl -H x:${JWT.slice(0, 25)}`], ['caption', JWT.slice(25)]));
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /^JWT-shaped string across the records on lines 1-2/);
  });

  it('finds Bearer and its token on separate lines, or in separate records', () => {
    assert.deepEqual(errorsOf(transcript(['output', 'token type: Bearer\nabc123def456'])), [
      { line: 1, message: 'Bearer credential in "text" with its line breaks removed' },
    ]);
    assert.deepEqual(errorsOf(transcript(['command', 'echo Bearer'], ['output', 'abc123def456'])), [
      { line: 2, message: 'Bearer credential across the records on lines 1-2 (texts joined)' },
    ]);
  });

  it('finds a PEM header wrapped over lines', () => {
    assert.match(errorsOf(transcript(['output', '-----BEGIN PRIV\nATE KEY-----']))[0].message, /^PEM block in "text" with its line breaks removed/);
  });

  it('finds a --secret-env value wrapped over lines or split over records', () => {
    const secrets = new Map([['DEMO_SECRET', 'not-a-real-secret-42']]);
    assert.deepEqual(errorsOf(transcript(['output', 'pw: not-a-real-\nsecret-42']), { secrets }), [
      { line: 1, message: 'the value of DEMO_SECRET in "text" with its line breaks removed' },
    ]);
    assert.deepEqual(errorsOf(transcript(['output', 'pw: not-a-real'], ['output', '-secret-42']), { secrets }), [
      { line: 2, message: 'the value of DEMO_SECRET across the records on lines 1-2 (texts joined)' },
    ]);
  });

  it('reports a value found in one record once, not again for the windows that hold it', () => {
    const errors = errorsOf(transcript(['output', 'a'], ['output', JWT], ['output', 'b'], ['output', 'c']));
    assert.deepEqual(errors, [{ line: 2, message: 'JWT-shaped string in "text"' }]);
  });

  it('applies the timestamp rules per line only', () => {
    accepts(rec(2, 'output', 'ends 10:15\n:00 later'));
    accepts(rec(2, 'output', '2026-11-27\n10:15'));
  });
});

describe('signature-sized runs', () => {
  it('refuses 96 or more hex digits and allows 95 and a 64-digit public key', () => {
    rejects(rec(2, 'output', `sig: ${SIG_HEX}`), /^hex run of 96 or more digits \(signature-sized\) in "text"$/);
    rejects(rec(2, 'output', 'a'.repeat(96)), /hex run of 96/);
    accepts(rec(2, 'output', 'a'.repeat(95)));
    accepts(rec(2, 'output', `public_key: ${PUB_HEX}`));
  });

  it('refuses a signature wrapped over lines or split over records', () => {
    rejects(rec(2, 'output', `${SIG_HEX.slice(0, 64)}\n${SIG_HEX.slice(64)}`), /^hex run of 96 .* with its line breaks removed$/);
    const errors = errorsOf(transcript(['output', SIG_HEX.slice(0, 50)], ['output', SIG_HEX.slice(50)]));
    assert.match(errors[0].message, /^hex run of 96 .* across the records on lines 1-2/);
  });

  it('allows labelled public keys on adjacent lines (the labels break the run)', () => {
    accepts(rec(2, 'output', KEYS.map((k) => `public_key: ${k.public_key}`).join('\n')));
  });

  it('refuses 86 or more base64url characters with upper, lower and digit', () => {
    assert.equal(SIG_B64URL.length, 86);
    assert.ok(hasLongBase64url(SIG_B64URL));
    rejects(rec(2, 'output', `sig=${SIG_B64URL}`), /^base64url run of 86 or more characters \(signature-sized\) in "text"$/);
    // Alone: next to another record's text, the direct join would extend the run.
    assert.deepEqual(errorsOf(transcript(['output', SIG_B64URL.slice(0, 85)])), []);
    accepts(rec(2, 'output', '-'.repeat(100)));
    accepts(rec(2, 'output', 'abc1-'.repeat(20)));
    const errors = errorsOf(transcript(['output', SIG_B64URL.slice(0, 43)], ['output', SIG_B64URL.slice(43)]));
    assert.match(errors[0].message, /^base64url run of 86 .* across the records on lines 1-2/);
  });
});

describe('allow marker "hex-across-lines"', () => {
  const twoKeys = `${PUB_HEX}\n${createHash('sha256').update('second key').digest('hex')}`;

  it('lifts only the joined-form hex rule: two bare public keys on adjacent lines', () => {
    assert.match(errorsOf(transcript(['output', twoKeys]))[0].message, /^hex run of 96 .* with its line breaks removed/);
    assert.deepEqual(errorsOf(transcript(['output', twoKeys, 'hex-across-lines'])), []);
    const { records } = check(transcript(['output', twoKeys, 'hex-across-lines']));
    assert.equal(records[0].allow, 'hex-across-lines');
  });

  it('also lifts it for the windows that hold the marked record', () => {
    assert.deepEqual(errorsOf(transcript(['output', PUB_HEX, 'hex-across-lines'], ['output', PUB_HEX])), []);
    assert.match(errorsOf(transcript(['output', PUB_HEX], ['output', PUB_HEX]))[0].message, /across the records on lines 1-2/);
  });

  it('does not lift the hex rule on a single line, nor any other rule', () => {
    for (const [text, re] of [
      [SIG_HEX, /^hex run of 96 .* in "text"$/],
      [`${JWT.slice(0, 20)}\n${JWT.slice(20)}`, /^JWT-shaped string .*line breaks removed/],
      [JWT, /^JWT-shaped string in "text"$/],
      ['Authorization: Bearer\nabc123', /^Bearer credential/],
      ['-----BEGIN PRIVATE KEY-----', /^PEM block/],
      [`${SIG_B64URL.slice(0, 40)}\n${SIG_B64URL.slice(40)}`, /^base64url run/],
      ['at 10:15:00', /^timestamp-like value/],
    ]) {
      const errors = errorsOf(transcript(['output', text, 'hex-across-lines']));
      assert.ok(errors.some((e) => re.test(e.message)), `${text}: ${JSON.stringify(errors)}`);
    }
  });

  it('does not let a seed through: --secret-file values are refused with the marker', () => {
    const secrets = secretsFromFile(KEY_FILE);
    const seed = KEYS[0].seed;
    const errors = errorsOf(transcript(['output', `${PUB_HEX}\n${seed}`, 'hex-across-lines']), { secrets });
    assert.deepEqual(errors, [{ line: 1, message: 'the value of recovery.test-key.json keys[0].seed appears in the record' }]);
  });

  it('refuses an unknown marker and a marker out of canonical order', () => {
    rejects(JSON.stringify({ step: 2, type: 'output', text: 'x', allow: 'everything' }), /^"allow" must be one of hex-across-lines$/);
    rejects(JSON.stringify({ step: 2, type: 'output', text: 'x', allow: ['hex-across-lines'] }), /^"allow" must be one of/);
    rejects(JSON.stringify({ step: 2, allow: 'hex-across-lines', type: 'output', text: 'x' }), /canonical form/);
  });
});

describe('--secret-file', () => {
  const secrets = secretsFromFile(KEY_FILE);

  it('reads every keys[].seed of the committed test keys, and no public key', () => {
    assert.deepEqual([...secrets.keys()], KEYS.map((_, i) => `recovery.test-key.json keys[${i}].seed`));
    assert.deepEqual([...secrets.values()], KEYS.map((k) => k.seed));
  });

  it('refuses each seed as hex in either case, base64 and base64url, alone, wrapped or split', () => {
    for (const [i, k] of KEYS.entries()) {
      const label = `recovery.test-key.json keys[${i}].seed`;
      const bytes = Buffer.from(k.seed, 'hex');
      for (const shown of [k.seed, k.seed.toUpperCase(), bytes.toString('base64'), bytes.toString('base64url')]) {
        assert.ok(secretVariants(k.seed).includes(shown));
        assert.deepEqual(errorsOf(transcript(['output', `seed: ${shown}`]), { secrets }), [{ line: 1, message: `the value of ${label} appears in the record` }]);
      }
      assert.deepEqual(errorsOf(transcript(['output', `${k.seed.slice(0, 32)}\n${k.seed.slice(32)}`]), { secrets }), [
        { line: 1, message: `the value of ${label} in "text" with its line breaks removed` },
      ]);
      assert.deepEqual(errorsOf(transcript(['output', k.seed.slice(0, 10)], ['output', k.seed.slice(10)]), { secrets }), [
        { line: 2, message: `the value of ${label} across the records on lines 1-2 (texts joined)` },
      ]);
      assert.deepEqual(errorsOf(transcript(['output', `public_key: ${k.public_key}`]), { secrets }), []);
    }
  });

  it('refuses a file it cannot use (usage error)', () => {
    const none = join(TMP, 'none.json');
    writeFileSync(none, '{"keys":[{"public_key":"abcdefabcdef"}]}');
    const short = join(TMP, 'short.json');
    writeFileSync(short, '{"seed":"abc"}');
    const bad = join(TMP, 'bad.json');
    writeFileSync(bad, 'not json');
    for (const f of [none, short, bad, join(TMP, 'missing.json')]) assert.throws(() => secretsFromFile(f), /--secret-file/);
  });
});

describe('JSON syntax position', () => {
  it('agrees with JSON.parse on validity, for every one-character deletion of the sample records', () => {
    const lines = readFileSync(SAMPLE, 'utf8').trimEnd().split('\n').concat(['{"a":[1,2.5e-3,true,null,{"b":"\\u00e9\\n"}]}', '[]', '{}']);
    let checked = 0;
    for (const line of lines) {
      for (let i = 0; i <= line.length; i++) {
        const text = line.slice(0, i) + line.slice(i + 1);
        let valid = true;
        try {
          JSON.parse(text);
        } catch {
          valid = false;
        }
        assert.equal(jsonErrorOffset(text) === -1, valid, text);
        checked++;
      }
    }
    assert.ok(checked > 500);
  });
});

describe('diagnostics never echo the input', () => {
  const SECRET_JWT = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkdW1teSJ9.ZHVtbXlzaWduYXR1cmU';
  const SECRET_BEARER = 'dummyBearer0123456789abcdef';
  const SECRET_ENV = 'dummy-env-secret-987654';
  // Pieces that must not appear: each value and a fragment of it.
  const NEEDLES = [SECRET_JWT, SECRET_JWT.slice(0, 16), SECRET_JWT.slice(-12), SECRET_BEARER, SECRET_BEARER.slice(5, 20), SECRET_ENV, SECRET_ENV.slice(0, 12), 'not-a-real-field-name'];
  const LINES = [
    JSON.stringify({ step: 0, type: 'caption', text: 'c', [SECRET_JWT]: 1 }),
    JSON.stringify({ step: 0, type: 'caption', text: 'c', 'not-a-real-field-name': SECRET_BEARER }),
    JSON.stringify({ step: SECRET_JWT, type: 'output', text: 'x' }),
    JSON.stringify({ step: 1, type: SECRET_JWT, text: 'x' }),
    JSON.stringify({ step: 2, type: 'output', text: 'x', allow: SECRET_ENV }),
    `{"step":3,"type":"output","text":"${SECRET_JWT}`,
    `${SECRET_BEARER} ${SECRET_JWT}`,
    `{"step":4,"type":"output","text":"x" ${SECRET_ENV}}`,
    rec(5, 'output', `token ${SECRET_JWT}`),
    rec(6, 'output', `Authorization: Bearer ${SECRET_BEARER}`),
    rec(7, 'output', `Bearer ${SECRET_BEARER}`),
    rec(8, 'output', `env ${SECRET_ENV}`),
    rec(9, 'output', `${SECRET_JWT.slice(0, 20)}\n${SECRET_JWT.slice(20)}`),
    JSON.stringify({ step: 10, type: 'output', text: SECRET_ENV, [SECRET_ENV]: SECRET_JWT }),
    JSON.stringify({ step: '11', type: 'output', text: 'x' }).replace('"11"', `"${SECRET_ENV}"`),
  ];

  it('the check CLI prints line numbers and rule names only', () => {
    const path = join(TMP, 'echo.jsonl');
    writeFileSync(path, `${LINES.join('\n')}\n${SECRET_ENV}`);
    const r = spawnSync(process.execPath, [SCRIPT, 'check', '--secret-env', 'DUMMY_SECRET', path], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH, DUMMY_SECRET: SECRET_ENV },
    });
    assert.equal(r.status, 1);
    const printed = r.stdout + r.stderr;
    assert.ok(printed.split('\n').filter((l) => l.startsWith(`${path}:`)).length >= LINES.length, printed);
    for (const needle of NEEDLES) assert.ok(!printed.includes(needle), `printed ${needle}:\n${printed}`);
  });

  it('the render CLI, which validates first, prints no input either', () => {
    const path = join(TMP, 'echo-render.jsonl');
    writeFileSync(path, `${LINES.join('\n')}\n`);
    const r = spawnSync(process.execPath, [join(HERE, 'render.mjs'), path, '--out', join(TMP, 'echo-out')], { encoding: 'utf8', env: { PATH: process.env.PATH } });
    assert.equal(r.status, 1);
    const printed = r.stdout + r.stderr;
    assert.ok(printed.includes(`${path}:1:`), printed);
    for (const needle of NEEDLES) assert.ok(!printed.includes(needle), `printed ${needle}:\n${printed}`);
  });

  it('a --secret-file that is not JSON is not echoed', () => {
    const path = join(TMP, 'secret-not-json.json');
    writeFileSync(path, `{"seed": ${SECRET_ENV}}`);
    const r = spawnSync(process.execPath, [SCRIPT, 'check', '--secret-file', path, SAMPLE], { encoding: 'utf8', env: { PATH: process.env.PATH } });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /not JSON at character 10/);
    assert.ok(!(r.stdout + r.stderr).includes(SECRET_ENV.slice(0, 8)));
  });
});

describe('CLI', () => {
  const write = (name, bytes) => {
    const path = join(TMP, name);
    writeFileSync(path, bytes);
    return path;
  };
  const cli = (args, env = {}) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });

  it('exits 0 on valid files and prints a summary', () => {
    const r = cli(['check', SAMPLE, write('ok.jsonl', file(BASE))]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /2 file\(s\), 14 valid record\(s\), 0 file\(s\) with errors/);
  });

  it('exits 1 with file:line messages for each bad file', () => {
    const bad = write('bad.jsonl', file([BASE[0], rec(1, 'output', 'Bearer abc123')]));
    const bad2 = write('bad2.jsonl', file([rec(1, 'caption', 'x')]));
    const r = cli(['check', bad, SAMPLE, bad2]);
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes(`${bad}:2: Bearer credential in "text"`), r.stderr);
    assert.ok(r.stderr.includes(`${bad2}:1: "step" must be 0`), r.stderr);
    assert.match(r.stdout, /3 file\(s\), .* 2 file\(s\) with errors/);
  });

  it('exits 1 for an unreadable file', () => {
    const r = cli(['check', join(TMP, 'missing.jsonl')]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /missing\.jsonl: cannot read: ENOENT/);
  });

  it('exits 2 when no file is given, so an empty glob cannot pass', () => {
    const r = cli(['check']);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /no transcript given/);
  });

  it('exits 2 for an unknown command or option', () => {
    assert.equal(cli(['lint', SAMPLE]).status, 2);
    assert.equal(cli(['check', '--allow-empty', SAMPLE]).status, 2);
  });

  it('--secret-env fails on the value, and refuses an unset, empty or short variable', () => {
    const leak = write('leak.jsonl', file([rec(0, 'output', 'password: hunter2-not-real')]));
    let r = cli(['check', '--secret-env', 'DEMO_PW', leak], { DEMO_PW: 'hunter2-not-real' });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /leak\.jsonl:1: the value of DEMO_PW appears/);
    r = cli(['check', '--secret-env', 'DEMO_PW', SAMPLE], { DEMO_PW: 'hunter2-not-real' });
    assert.equal(r.status, 0, r.stderr);
    for (const env of [{}, { DEMO_PW: '' }, { DEMO_PW: 'short' }]) {
      r = cli(['check', '--secret-env', 'DEMO_PW', SAMPLE], env);
      assert.equal(r.status, 2, JSON.stringify(env));
      assert.match(r.stderr, /--secret-env DEMO_PW/);
    }
    assert.equal(cli(['check', SAMPLE, '--secret-env']).status, 2);
  });

  it('--secret-file refuses the committed seeds, and exits 2 on an unusable file', () => {
    const leak = write('seed.jsonl', file([rec(0, 'output', `seed: ${KEYS[1].seed}`)]));
    let r = cli(['check', '--secret-file', KEY_FILE, leak]);
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes(`${leak}:1: the value of recovery.test-key.json keys[1].seed appears in the record`), r.stderr);
    r = cli(['check', '--secret-file', KEY_FILE, SAMPLE]);
    assert.equal(r.status, 0, r.stderr);
    r = cli(['check', '--secret-file', join(TMP, 'missing.json'), SAMPLE]);
    assert.equal(r.status, 2);
    assert.equal(cli(['check', SAMPLE, '--secret-file']).status, 2);
  });

  it('main() is callable in process with injected output', () => {
    const out = [];
    const err = [];
    assert.equal(main(['check', SAMPLE], { out: (s) => out.push(s), error: (s) => err.push(s) }), 0);
    assert.deepEqual(err, []);
    assert.equal(out.length, 1);
  });
});
