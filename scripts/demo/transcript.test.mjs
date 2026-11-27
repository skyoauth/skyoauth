// Self-test of transcript.mjs (pure: no browser, no ffmpeg, no network):
//   node --test scripts/demo/transcript.test.mjs
//
// Each rejection is shown with a mutant of a valid transcript: the valid
// one passes, the mutant fails with the expected message on the expected
// line.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { MAX_COLUMNS, MAX_RECORD_BYTES, hasBearerCredential, main, validateTranscript } from './transcript.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, 'transcript.mjs');
const SAMPLE = join(HERE, 'sample', 'sample.transcript.jsonl');
const TMP = mkdtempSync(join(tmpdir(), 'demo-transcript-test-'));

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
      rejects(JSON.stringify({ step: 2, type: 'output', text: 'x', [extra]: 1 }), new RegExp(`unknown field "${extra}"`));
    }
  });

  it('rejects missing fields', () => {
    rejects(JSON.stringify({ step: 2, type: 'output' }), /missing field "text"/);
    rejects(JSON.stringify({ step: 2, text: 'x' }), /missing field "type"/);
    rejects(JSON.stringify({ type: 'output', text: 'x' }), /missing field "step"/);
  });

  it('rejects unknown types', () => {
    rejects(rec(2, 'stdout', 'x'), /unknown type "stdout"/);
    rejects(rec(2, 'Caption', 'x'), /unknown type "Caption"/);
    rejects(JSON.stringify({ step: 2, type: 1, text: 'x' }), /unknown type 1/);
  });

  it('rejects a step that does not count from 0 with no gap', () => {
    rejects(rec(1, 'caption', 'x'), /"step" is 1, expected 0/, 0);
    rejects(rec(3, 'output', 'x'), /"step" is 3, expected 2/);
    rejects(rec(1, 'output', 'x'), /"step" is 1, expected 2/);
    rejects(JSON.stringify({ step: '2', type: 'output', text: 'x' }), /non-negative integer/);
    rejects(JSON.stringify({ step: 2.5, type: 'output', text: 'x' }), /non-negative integer/);
    rejects(JSON.stringify({ step: -1, type: 'output', text: 'x' }), /non-negative integer/);
  });

  it('rejects non-object records, non-JSON and empty or non-string text', () => {
    rejects('[2,"output","x"]', /must be a JSON object/);
    rejects('null', /must be a JSON object/);
    rejects('{"step":2,', /not JSON/);
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
      ['‮', '202E'],
      ['⁦', '2066'],
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
    assert.ok(r.stderr.includes(`${bad2}:1: "step" is 1, expected 0`), r.stderr);
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

  it('main() is callable in process with injected output', () => {
    const out = [];
    const err = [];
    assert.equal(main(['check', SAMPLE], { out: (s) => out.push(s), error: (s) => err.push(s) }), 0);
    assert.deepEqual(err, []);
    assert.equal(out.length, 1);
  });
});
