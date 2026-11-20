#!/usr/bin/env node
// Consistency checks for the SkyOAuth specifications.
//
//   node scripts/ci/docs-check.mjs [--root DIR] [--verbose] [--mermaid-oracle=DIR]
//
// The two specs, docs/skyoauth-design.md and docs/skyoauth-tasks.md, are
// authoritative: they alone define task IDs (tasks), ADR rows (tasks §11),
// conformance scenarios A01... (tasks §8) and compatibility invariants
// C01... (design §2), and they are checked strictly. ADR files under
// docs/adr/ may also define ADRs. Every other git-tracked docs/**/*.md file
// is checked best-effort: its fences, links and anchors, its references to
// the IDs above, and whether its Mermaid diagrams parse.
//
// Checks:
//   fence    Markdown ``` and ~~~ fences are balanced (CommonMark closing rules).
//   comment  HTML comments close: a "<!--" block before EOF, an inline one
//            within its paragraph. Fences inside a comment block are text;
//            "<!--" inside a fence or code span is not a comment.
//   task     Task IDs and ranges (T13.1–T13.7, T10–T14) resolve to definitions;
//            definitions are unique, contiguous and under their group heading.
//   adr      ADR-NNN references resolve to the tasks §11 table or docs/adr/.
//   scenario A-IDs are defined once each, contiguous from A01, in tasks §8;
//            C-IDs likewise in design §2; all references resolve.
//   mermaid  Every mermaid block parses (strict flowchart subset parser). In
//            the tasks spec, flowcharts must also be acyclic and every node
//            used must have an explicit labelled definition.
//   link     Relative Markdown links and #anchors resolve (GitHub slug rules).
//   section  Explicit "design §N"/"tasks §N" references name a numbered
//            heading of that spec.
//
// Errors exit 1 with file:line messages. Warnings and info lines never fail.
// Usage errors and internal failures exit 2. With GITHUB_ACTIONS=true the
// messages are printed as ::error/::warning annotations (see main()).
// Needs only Node (>=20) and the files in the repository; no dependencies.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, join, posix, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const DESIGN = 'docs/skyoauth-design.md';
export const TASKS = 'docs/skyoauth-tasks.md';
export const SPECS = [DESIGN, TASKS];

// ---------------------------------------------------------------------------
// Diagnostics

class Report {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.infos = [];
  }
  error(file, line, check, msg) {
    this.errors.push({ file, line, check, msg });
  }
  warn(file, line, check, msg) {
    this.warnings.push({ file, line, check, msg });
  }
  // `tag` marks infos that main() prints specially ('unreferenced-adr',
  // 'adr-without-row').
  info(file, line, check, msg, tag) {
    this.infos.push(tag ? { file, line, check, msg, tag } : { file, line, check, msg });
  }
}

export function formatDiagnostic(level, d) {
  const loc = d.line ? `${d.file}:${d.line}` : d.file;
  return `${loc}: ${level} [${d.check}] ${d.msg}`;
}

// A GitHub Actions workflow command (::error/::warning) for a diagnostic.
// The message keeps the plain file:line form (with level `shown`) so the raw
// log stays readable. Escaping follows the runner's rules for data and
// property values.
export function formatAnnotation(command, d, shown = command) {
  const data = (s) => s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  const prop = (s) => data(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
  const props = [`file=${prop(d.file)}`];
  if (d.line) props.push(`line=${d.line}`);
  props.push(`title=${prop(`docs-check [${d.check}]`)}`);
  return `::${command} ${props.join(',')}::${data(formatDiagnostic(shown, d))}`;
}

// Fence and comment problems come first: an unclosed fence or comment turns
// the rest of a file into code or hides it, so it is usually the cause of
// many later errors (a hidden definitions table makes every reference fail).
// Then by file, line and message.
const blockFirst = (d) => (d.check === 'fence' || d.check === 'comment' ? 0 : 1);

function sortDiagnostics(list) {
  return list.sort(
    (a, b) =>
      blockFirst(a) - blockFirst(b) ||
      a.file.localeCompare(b.file) ||
      (a.line || 0) - (b.line || 0) ||
      a.msg.localeCompare(b.msg),
  );
}

// ---------------------------------------------------------------------------
// File discovery

// The variables that point git at another repository than the one it finds
// from -C (a git hook or `git rebase --exec` exports some of them); git runs
// here without them, so the tracked files are root's own. The same list as
// GIT_LOCATION in check-conformance-registry.mjs, which this script cannot
// import (it has no dependencies).
export const GIT_LOCATION = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_NAMESPACE', 'GIT_PREFIX', 'GIT_CEILING_DIRECTORIES'];

function gitTracked(root) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !GIT_LOCATION.includes(k)));
  try {
    const out = execFileSync('git', ['-C', root, 'ls-files', '-z'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      env,
    });
    // A root that is only a subdirectory of some other repository is not a
    // repository root; fall back to the file system in that case.
    const top = execFileSync('git', ['-C', root, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      env,
    }).trim();
    if (realpathSync(top) !== realpathSync(root)) return null;
    return new Set(out.split('\0').filter(Boolean));
  } catch {
    return null;
  }
}

function walk(root, dir, out) {
  const abs = join(root, dir);
  if (!existsSync(abs)) return out;
  for (const name of readdirSync(abs).sort()) {
    if (name === '.git' || name === 'node_modules') continue;
    const rel = dir ? `${dir}/${name}` : name;
    if (statSync(join(root, rel)).isDirectory()) walk(root, rel, out);
    else out.add(rel);
  }
  return out;
}

// Returns { tracked: Set<string> | null, all: Set<string> } of repo-relative
// POSIX paths. `tracked` is null when root is not a git repository root.
function listRepoFiles(root) {
  const tracked = gitTracked(root);
  if (tracked) {
    // Skip tracked files deleted from the working tree.
    const present = new Set([...tracked].filter((p) => existsSync(join(root, p))));
    return { tracked: present, all: present };
  }
  const all = walk(root, '', new Set());
  return { tracked: null, all };
}

// ---------------------------------------------------------------------------
// Markdown scanning: fences, comments, headings

const FENCE_RE = /^((?:[ \t]*>)*[ \t]*)(`{3,}|~{3,})(.*)$/;
const COMMENT_BLOCK_RE = /^((?:[ \t]*>)*[ \t]*)<!--/;

// Scans the block structure: fenced code blocks and HTML comment blocks.
// Returns { blocks, comments, errors, unclosed }. Each block is { start,
// end, char, len, info, lang, body: string[] } with 1-based line numbers (end
// is the closing fence line). A fence never closed is an error and is
// returned as `unclosed` ({ start, ... } without end), not in `blocks`: as
// in CommonMark it runs to the end of the document, so analyse() treats
// every later line as code. Follows CommonMark: a backtick fence's info string
// cannot contain a backtick; a closing fence uses the same character, is at
// least as long as the opener and has no info string.
//
// A line that starts with "<!--" outside a fence opens an HTML block
// (CommonMark type 2) that ends on the first line containing "-->"; nothing
// in it is Markdown, so a fence-like line inside is text. Each comment is
// { start, end, col, closeCol }: col is the index of "<!--" on the start
// line and closeCol that of "-->" on the end line. Inside a fence, "<!--" is
// code. Comments opened mid-line are inline HTML; analyse() handles them.
export function scanFences(lines) {
  const blocks = [];
  const comments = [];
  const errors = [];
  let open = null;
  let comment = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (comment) {
      const e = line.indexOf('-->');
      if (e >= 0) {
        comments.push({ ...comment, end: i + 1, closeCol: e });
        comment = null;
      }
      continue;
    }
    if (!open) {
      const c = COMMENT_BLOCK_RE.exec(line);
      if (c) {
        const col = c[1].length;
        const e = line.indexOf('-->', col + 4);
        if (e >= 0) comments.push({ start: i + 1, end: i + 1, col, closeCol: e });
        else comment = { start: i + 1, col };
        continue;
      }
    }
    const m = FENCE_RE.exec(line);
    if (!open) {
      if (!m) continue;
      const [, , marker, rest] = m;
      if (marker[0] === '`' && rest.includes('`')) continue; // inline code, not a fence
      const info = rest.trim();
      open = {
        start: i + 1,
        char: marker[0],
        len: marker.length,
        info,
        lang: (info.split(/\s+/)[0] || '').toLowerCase(),
        body: [],
        nearMisses: [],
      };
      continue;
    }
    if (m && m[2][0] === open.char && m[2].length >= open.len && m[3].trim() === '') {
      const { nearMisses, ...block } = open;
      blocks.push({ ...block, end: i + 1 });
      open = null;
      continue;
    }
    if (m && m[3].trim() === '') open.nearMisses.push({ line: i + 1, marker: m[2] });
    // A same-character fence at least as long as the opener but with an info
    // string cannot close the block (CommonMark keeps it as content). Someone
    // nesting fences on purpose uses a longer outer fence, so this is almost
    // always a missing closing fence that silently re-pairs every later fence.
    if (m && m[2][0] === open.char && m[2].length >= open.len && m[3].trim() !== '') {
      errors.push({
        line: i + 1,
        msg: `'${m[2]}${m[3].trim()}' looks like a new fence opener inside the block opened at line ${open.start}; that block is probably missing its closing fence (use a longer outer fence to nest)`,
      });
    }
    open.body.push(line);
  }
  if (open) {
    const opener = open.char.repeat(open.len);
    let msg = `fence ${opener}${open.info ? open.info : ''} opened here is never closed (needs a line of ${open.len}+ '${open.char}')`;
    if (open.nearMisses.length) {
      const n = open.nearMisses[0];
      msg += `; line ${n.line} has '${n.marker}', which cannot close it`;
    }
    errors.push({ line: open.start, msg });
  }
  let unclosed = null;
  if (open) {
    const { nearMisses, ...rest } = open;
    unclosed = { ...rest, unclosed: true };
  }
  if (comment) {
    errors.push({
      line: comment.start,
      check: 'comment',
      msg: 'HTML comment opened here is never closed (no later "-->"), so Markdown hides the rest of the file',
    });
  }
  return { blocks, comments, errors, unclosed };
}

// Index just past the backtick run of exactly `len` backticks that closes a
// code span opened before `from`, or -1.
function codeSpanEnd(s, from, len) {
  for (let j = s.indexOf('`', from); j >= 0; j = s.indexOf('`', j)) {
    let k = j;
    while (s[k] === '`') k++;
    if (k - j === len) return k;
    j = k;
  }
  return -1;
}

// Per-line view of a document: which lines are inside fences, prose with HTML
// comments masked, and the fenced blocks themselves. `errors` holds the
// block scanner's errors plus inline comments that are never closed.
function analyse(text) {
  const lines = text.split(/\r?\n/);
  const { blocks, comments, errors, unclosed } = scanFences(lines);
  const inFence = new Array(lines.length + 1).fill(null); // 1-based -> block
  for (const b of blocks) for (let n = b.start; n <= b.end; n++) inFence[n] = b;
  if (unclosed) for (let n = unclosed.start; n <= lines.length; n++) inFence[n] = unclosed;
  const inComment = new Array(lines.length + 1).fill(null); // 1-based -> comment block
  for (const c of comments) for (let n = c.start; n <= c.end; n++) inComment[n] = c;
  // Mask HTML comments, keeping line structure. Comment blocks come from the
  // block scanner. An inline comment ("text <!-- ... -->") is raw HTML only
  // if it closes within its paragraph; otherwise Markdown shows "<!--" as
  // text, so it is reported and masks nothing past the paragraph. A code span
  // that starts first wins over "<!--" (and vice versa), as in CommonMark.
  const prose = [];
  let inline = null; // { line } of an open inline comment
  const endParagraph = () => {
    if (!inline) return;
    errors.push({
      line: inline.line,
      check: 'comment',
      msg: 'HTML comment opened here is not closed before its paragraph ends, so Markdown shows it as text',
    });
    inline = null;
  };
  for (let i = 0; i < lines.length; i++) {
    const s = lines[i];
    const block = inComment[i + 1];
    if (inFence[i + 1] || block || s.trim() === '') endParagraph();
    if (inFence[i + 1]) {
      prose.push('');
      continue;
    }
    let out = '';
    let pos = 0;
    if (block) {
      // Before "<!--" there is only indentation or ">"; after "-->" on the
      // last line there may be text, which is checked.
      if (i + 1 !== block.end) {
        prose.push('');
        continue;
      }
      pos = block.closeCol + 3;
    }
    while (pos < s.length) {
      if (inline) {
        const e = s.indexOf('-->', pos);
        if (e < 0) break;
        pos = e + 3;
        inline = null;
        continue;
      }
      const b = s.indexOf('<!--', pos);
      const t = s.indexOf('`', pos);
      if (b < 0) {
        out += s.slice(pos);
        break;
      }
      if (t >= 0 && t < b) {
        let k = t;
        while (s[k] === '`') k++;
        const end = codeSpanEnd(s, k, k - t);
        const next = end < 0 ? k : end; // an unmatched run is literal text
        out += s.slice(pos, next);
        pos = next;
        continue;
      }
      out += s.slice(pos, b);
      pos = b + 4;
      inline = { line: i + 1 };
    }
    prose.push(out);
  }
  endParagraph();
  return { lines, prose, blocks, errors, inFence };
}

function stripInlineCode(s) {
  return s.replace(/(`+)(?:(?!\1)[\s\S])*?\1/g, (m) => ' '.repeat(m.length));
}

// GitHub heading slug (github-slugger): lowercase, drop everything except
// letters, marks, numbers, connector punctuation, spaces and hyphens, then
// turn each space into a hyphen. Inline Markdown is reduced to its text.
export function githubSlug(heading) {
  let t = heading
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1') // links/images -> text
    .replace(/<[^>]+>/g, '') // HTML tags
    .replace(/`/g, '');
  t = t.toLowerCase();
  t = t.replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, '');
  return t.replace(/ /g, '-');
}

// Returns [{ line, level, text }] for ATX and setext headings outside fences.
function headings(doc) {
  const out = [];
  const { prose, inFence } = doc;
  for (let i = 0; i < prose.length; i++) {
    if (inFence[i + 1]) continue;
    const m = /^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$/.exec(prose[i]);
    if (m) {
      out.push({ line: i + 1, level: m[1].length, text: (m[2] || '').trim() });
      continue;
    }
    const next = prose[i + 1];
    if (
      next !== undefined &&
      !inFence[i + 2] &&
      prose[i].trim() !== '' &&
      /^ {0,3}(=+|-+)[ \t]*$/.test(next) &&
      // Not a list item (bullet or ordered, 1-9 digits), table row, quote or
      // ATX line. A list marker is followed by a space, a tab or the end of
      // the line; any other whitespace (e.g. U+00A0) makes it paragraph text.
      !/^\s*([-*+]([ \t]|$)|\d{1,9}[.)]([ \t]|$)|\||>|#)/.test(prose[i]) &&
      !(i > 0 && prose[i - 1].trim() !== '' && !inFence[i])
    ) {
      out.push({ line: i + 1, level: next.trim()[0] === '=' ? 1 : 2, text: prose[i].trim() });
    }
  }
  return out;
}

function anchorsOf(doc) {
  const anchors = new Set();
  const counts = new Map();
  for (const h of headings(doc)) {
    const base = githubSlug(h.text);
    let slug = base;
    let n = counts.get(base) || 0;
    while (anchors.has(slug)) slug = `${base}-${++n}`;
    counts.set(base, n);
    anchors.add(slug);
  }
  for (const l of doc.prose) {
    for (const m of l.matchAll(/<a\s+[^>]*\b(?:id|name)\s*=\s*["']([^"']+)["']/gi)) anchors.add(m[1]);
  }
  return anchors;
}

// Section numbers of numbered headings: "## 4. Deployment" -> "4",
// "### 5.1.1 First login" -> "5.1.1".
function sectionNumbers(doc) {
  const out = new Map();
  for (const h of headings(doc)) {
    const m = /^(\d+(?:\.\d+)*)\.?\s/.exec(h.text);
    if (m && !out.has(m[1])) out.set(m[1], h.line);
  }
  return out;
}

// The line range [start, end) of the first section whose heading matches re,
// plus any later headings that match too.
function sectionRange(doc, re) {
  const hs = headings(doc);
  const idx = hs.findIndex((h) => re.test(h.text));
  if (idx < 0) return null;
  const level = hs[idx].level;
  const next = hs.slice(idx + 1).find((h) => h.level <= level);
  const others = hs.slice(idx + 1).filter((h) => re.test(h.text));
  return { heading: hs[idx], start: hs[idx].line, end: next ? next.line : doc.lines.length + 1, others };
}

// The numbered section headings that hold the ID tables (tasks §8 and §11,
// design §2). Anchored to "N. Title" so that other headings mentioning an
// ADR or the matrix ("#### ADR-009 notes") cannot be mistaken for them.
const ADR_SECTION = /^\d+\.\s+ADR decisions\b/i;
const MATRIX_SECTION = /^\d+\.\s+Conformance matrix\b/i;
const CONTRACT_SECTION = /^\d+\.\s+Stable compatibility contract\b/i;

// ---------------------------------------------------------------------------
// Identifier references

// Each kind matches a single ID token; ranges are "X–Y" or "X-Y" between
// two tokens (or with an abbreviated end: T13.1–7, A01–64, ADR-001–024).
const KINDS = {
  task: {
    token: /(?<![\w.])T(\d{2})(?:\.(\d+))?(?![\w]|\.\d)/g,
    key: (m) => (m[2] === undefined ? `T${m[1]}` : `T${m[1]}.${Number(m[2])}`),
    rangeEnd: /^[ \t]?[–-][ \t]?(?:T(\d{2})(?:\.(\d+))?|(\d{2})\.(\d+)|(\d+))(?![\w]|\.\d)/,
  },
  scenario: {
    token: /(?<![\w.-])A(\d{2})(?![\w])/g,
    key: (m) => `A${m[1]}`,
    rangeEnd: /^[ \t]?[–-][ \t]?A?(\d{2})(?![\w])/,
  },
  invariant: {
    token: /(?<![\w.-])C(\d{2})(?![\w])/g,
    key: (m) => `C${m[1]}`,
    rangeEnd: /^[ \t]?[–-][ \t]?C?(\d{2})(?![\w])/,
  },
  adr: {
    token: /(?<![\w.-])ADR-(\d{3,4})(?![\w])/g,
    key: (m) => adrKey(Number(m[1])),
    rangeEnd: /^[ \t]?[–-][ \t]?(?:ADR-)?(\d{3,4})(?![\w])/,
  },
};

const adrKey = (n) => `ADR-${String(n).padStart(3, '0')}`;

// Finds references of one kind in a line. Returns
// [{ col, text, keys: [..] , range: bool, error?: string }].
export function findRefs(kind, line) {
  const k = KINDS[kind];
  const out = [];
  const re = new RegExp(k.token.source, 'g');
  let m;
  while ((m = re.exec(line))) {
    const startKey = k.key(m);
    const after = line.slice(re.lastIndex);
    const r = k.rangeEnd.exec(after);
    if (!r) {
      out.push({ col: m.index + 1, text: m[0], keys: [startKey], range: false });
      continue;
    }
    re.lastIndex += r[0].length;
    const text = m[0] + r[0];
    out.push({ col: m.index + 1, text, ...expandRange(kind, m, r) });
  }
  return out;
}

function expandRange(kind, m, r) {
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  if (kind === 'task') {
    const g1 = Number(m[1]);
    const s1 = m[2] === undefined ? null : Number(m[2]);
    let g2;
    let s2;
    if (r[1] !== undefined) {
      g2 = Number(r[1]);
      s2 = r[2] === undefined ? null : Number(r[2]);
    } else if (r[3] !== undefined) {
      g2 = Number(r[3]);
      s2 = Number(r[4]);
    } else {
      // Bare number: T13.1–7 (subtask end) or T10–14 (group end).
      if (s1 === null) {
        g2 = Number(r[5]);
        s2 = null;
      } else {
        g2 = g1;
        s2 = Number(r[5]);
      }
    }
    if ((s1 === null) !== (s2 === null)) {
      return { range: true, keys: [], error: 'range mixes a task group and a subtask' };
    }
    if (s1 === null) {
      if (g2 <= g1) return { range: true, keys: [], error: 'range end is not after its start' };
      const keys = [];
      for (let g = g1; g <= g2; g++) keys.push(`T${pad(g)}`);
      return { range: true, keys };
    }
    if (g1 !== g2) return { range: true, keys: [], error: 'subtask range spans two task groups' };
    if (s2 <= s1) return { range: true, keys: [], error: 'range end is not after its start' };
    const keys = [];
    for (let s = s1; s <= s2; s++) keys.push(`T${pad(g1)}.${s}`);
    return { range: true, keys };
  }
  const prefix = { scenario: 'A', invariant: 'C', adr: 'ADR-' }[kind];
  const a = Number(m[1]);
  const b = Number(r[1]);
  if (b <= a) return { range: true, keys: [], error: 'range end is not after its start' };
  const keys = [];
  for (let n = a; n <= b; n++) keys.push(kind === 'adr' ? adrKey(n) : `${prefix}${pad(n)}`);
  return { range: true, keys };
}

// ---------------------------------------------------------------------------
// Mermaid: strict flowchart subset parser

export class MermaidError extends Error {
  constructor(line, msg) {
    super(msg);
    this.line = line;
  }
}

const SHAPES = [
  ['(((', ')))'],
  ['((', '))'],
  ['([', '])'],
  ['[[', ']]'],
  ['[(', ')]'],
  ['{{', '}}'],
  ['[/', '/]', '\\]'],
  ['[\\', '\\]', '/]'],
  ['[', ']'],
  ['(', ')'],
  ['{', '}'],
  ['>', ']'],
];

const DIRECTIONS = /^(TB|TD|BT|RL|LR)$/;
const ID_RE = /^[A-Za-z_][A-Za-z0-9_]*/;
const RESERVED = new Set(['end', 'subgraph', 'graph', 'flowchart', 'style', 'class', 'classDef', 'click', 'linkStyle', 'direction']);

// Parses a Mermaid flowchart. `firstLine` is the 1-based document line of
// the first body line. Throws MermaidError on anything outside the subset.
// Returns { type, direction, nodes: Map<id, {label, line, shape}>,
// used: Map<id, line>, edges: [{from, to, directed, label, line}], subgraphs }.
export function parseFlowchart(body, firstLine = 1) {
  const g = { type: null, direction: null, nodes: new Map(), used: new Map(), edges: [], subgraphs: [] };
  const stack = [];
  let headerSeen = false;
  let i = 0;
  // Optional YAML front matter.
  while (i < body.length && body[i].trim() === '') i++;
  if (i < body.length && body[i].trim() === '---') {
    const close = body.findIndex((l, j) => j > i && l.trim() === '---');
    if (close < 0) throw new MermaidError(firstLine + i, 'unterminated front matter');
    i = close + 1;
  }
  for (; i < body.length; i++) {
    const lineNo = firstLine + i;
    const raw = body[i];
    const t = raw.trim();
    if (t === '' || t.startsWith('%%')) continue;
    if (!headerSeen) {
      // "flowchart", "flowchart TD" or "flowchart TD;" (Mermaid also takes
      // extra ";" but rejects "flowchart;" and "flowchart TD ;"). The ";" is
      // not part of the direction.
      const h = /^(flowchart|graph)(?:[ \t]+([^\s;]+)(?:;[\s;]*)?)?$/.exec(t);
      if (!h) {
        const kind = t.split(/[\s;]/)[0];
        if (kind === 'flowchart' || kind === 'graph') throw new MermaidError(lineNo, `invalid flowchart header '${t}'`);
        throw new MermaidError(lineNo, `unsupported diagram type '${kind}' (only flowchart/graph is validated)`);
      }
      if (h[2] !== undefined && !DIRECTIONS.test(h[2])) {
        throw new MermaidError(lineNo, `invalid flowchart direction '${h[2]}'`);
      }
      g.type = h[1];
      g.direction = h[2] || 'TB';
      headerSeen = true;
      continue;
    }
    for (const stmt of splitStatements(t, lineNo)) parseStatement(stmt, lineNo, g, stack);
  }
  if (!headerSeen) throw new MermaidError(firstLine, 'empty diagram');
  if (stack.length) {
    const s = stack[stack.length - 1];
    throw new MermaidError(s.line, `subgraph '${s.id}' is never closed with 'end'`);
  }
  return g;
}

function splitStatements(t, lineNo) {
  const out = [];
  let cur = '';
  let quote = false;
  let pipe = false;
  for (const ch of t) {
    if (ch === '"') quote = !quote;
    else if (ch === '|' && !quote) pipe = !pipe;
    if (ch === ';' && !quote && !pipe) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  if (quote) throw new MermaidError(lineNo, 'unterminated string');
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function parseStatement(s, lineNo, g, stack) {
  const word = s.split(/\s+/)[0];
  if (word === 'subgraph') {
    const rest = s.slice('subgraph'.length).trim();
    if (!rest) throw new MermaidError(lineNo, 'subgraph needs an id or title');
    let id;
    let label;
    const withLabel = /^([A-Za-z_][A-Za-z0-9_]*)[ \t]*\[(?:"([^"]*)"|([^\[\]"]*))\]$/.exec(rest);
    if (withLabel) {
      id = withLabel[1];
      label = withLabel[2] ?? withLabel[3];
    } else if (/^"[^"]*"$/.test(rest)) {
      id = label = rest.slice(1, -1);
    } else if (/^[^\[\]{}()"|;]+$/.test(rest)) {
      id = rest;
      label = rest;
    } else {
      throw new MermaidError(lineNo, `cannot parse subgraph header '${rest}'`);
    }
    defineNode(g, id, label, lineNo, 'subgraph');
    const sg = { id, label, line: lineNo };
    g.subgraphs.push(sg);
    stack.push(sg);
    return;
  }
  if (s === 'end') {
    if (!stack.length) throw new MermaidError(lineNo, "'end' without an open subgraph");
    stack.pop();
    return;
  }
  if (word === 'direction') {
    if (!stack.length) throw new MermaidError(lineNo, "'direction' is only valid inside a subgraph");
    const d = s.split(/\s+/)[1];
    if (!d || !DIRECTIONS.test(d) || s.split(/\s+/).length !== 2) {
      throw new MermaidError(lineNo, `invalid direction statement '${s}'`);
    }
    return;
  }
  if (word === 'classDef') {
    if (!/^classDef\s+[\w-]+(?:\s*,\s*[\w-]+)*\s+\S.*$/.test(s)) throw new MermaidError(lineNo, `invalid classDef '${s}'`);
    return;
  }
  if (word === 'class') {
    const m = /^class\s+([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+([\w-]+)$/.exec(s);
    if (!m) throw new MermaidError(lineNo, `invalid class statement '${s}'`);
    for (const id of m[1].split(/\s*,\s*/)) useNode(g, id, lineNo);
    return;
  }
  if (word === 'style') {
    const m = /^style\s+([A-Za-z_]\w*)\s+\S.*$/.exec(s);
    if (!m) throw new MermaidError(lineNo, `invalid style statement '${s}'`);
    useNode(g, m[1], lineNo);
    return;
  }
  if (word === 'linkStyle') {
    if (!/^linkStyle\s+(?:default|\d+(?:\s*,\s*\d+)*)\s+\S.*$/.test(s)) throw new MermaidError(lineNo, `invalid linkStyle '${s}'`);
    return;
  }
  if (word === 'click') {
    const m = /^click\s+([A-Za-z_]\w*)\s+\S.*$/.exec(s);
    if (!m) throw new MermaidError(lineNo, `invalid click statement '${s}'`);
    useNode(g, m[1], lineNo);
    return;
  }
  parseChain(s, lineNo, g);
}

function defineNode(g, id, label, lineNo, shape) {
  const prev = g.nodes.get(id);
  if (prev && prev.label !== label) {
    throw new MermaidError(lineNo, `node '${id}' redefined with a different label (first defined on line ${prev.line})`);
  }
  if (!prev) g.nodes.set(id, { label, line: lineNo, shape });
  useNode(g, id, lineNo);
}

function useNode(g, id, lineNo) {
  if (!g.used.has(id)) g.used.set(id, lineNo);
}

// chain := group (link group)*;  group := node ('&' node)*
function parseChain(s, lineNo, g) {
  let pos = 0;
  const ws = () => {
    while (pos < s.length && /\s/.test(s[pos])) pos++;
  };
  const fail = (msg) => {
    throw new MermaidError(lineNo, `${msg} at column ${pos + 1} in '${s}'`);
  };

  const parseNode = () => {
    ws();
    const m = ID_RE.exec(s.slice(pos));
    if (!m) fail('expected a node id');
    const id = m[0];
    if (RESERVED.has(id)) fail(`'${id}' cannot be used as a node id`);
    pos += id.length;
    // A link may follow an id directly (A-->B); only a shape opener binds.
    let shapeDef = null;
    for (const [open, ...closers] of SHAPES) {
      if (s.startsWith(open, pos)) {
        shapeDef = { open, closers };
        break;
      }
    }
    if (shapeDef) {
      pos += shapeDef.open.length;
      let label;
      if (s[pos] === '"') {
        const end = s.indexOf('"', pos + 1);
        if (end < 0) fail('unterminated quoted label');
        label = s.slice(pos + 1, end);
        pos = end + 1;
        const closer = shapeDef.closers.find((c) => s.startsWith(c, pos));
        if (!closer) fail(`expected '${shapeDef.closers[0]}' after quoted label of '${id}'`);
        pos += closer.length;
      } else {
        // Unquoted: text up to the closer; no quotes or other brackets inside.
        let end = -1;
        let closer = null;
        for (let j = pos; j < s.length; j++) {
          const c = shapeDef.closers.find((cl) => s.startsWith(cl, j));
          if (c) {
            end = j;
            closer = c;
            break;
          }
          if ('"[]{}()'.includes(s[j])) fail(`unexpected '${s[j]}' in unquoted label of '${id}' (quote the label)`);
        }
        if (end < 0) fail(`unterminated label for node '${id}'`);
        label = s.slice(pos, end).trim();
        if (!label) fail(`empty label for node '${id}'`);
        pos = end + closer.length;
      }
      if (s.startsWith(':::', pos)) {
        const cm = /^:::[\w-]+/.exec(s.slice(pos));
        if (!cm) fail('invalid :::class');
        pos += cm[0].length;
      }
      defineNode(g, id, label, lineNo, shapeDef.open);
    } else {
      if (s.startsWith(':::', pos)) {
        const cm = /^:::[\w-]+/.exec(s.slice(pos));
        if (!cm) fail('invalid :::class');
        pos += cm[0].length;
      }
      useNode(g, id, lineNo);
    }
    return id;
  };

  const parseGroup = () => {
    const ids = [parseNode()];
    for (;;) {
      ws();
      if (s[pos] !== '&') break;
      pos++;
      ids.push(parseNode());
    }
    return ids;
  };

  // Returns { directed, reverse, label } or null when no link starts here.
  const parseLink = () => {
    ws();
    const rest = s.slice(pos);
    let m;
    let label = null;
    let arrow;
    // Text between the link halves: A -- text --> B, A -. text .-> B, A == text ==> B.
    if ((m = /^--(?![-.>ox])\s*([^|]+?)\s*(-{2,}>|-{3,}|--[ox])(?=\s|$|[A-Za-z_])/.exec(rest))) {
      label = m[1];
      arrow = `--${m[2]}`;
    } else if ((m = /^-\.(?![-.>])\s*([^|]+?)\s*(\.-+>|\.-+)(?=\s|$|[A-Za-z_])/.exec(rest))) {
      label = m[1];
      arrow = `-.${m[2]}`;
    } else if ((m = /^==(?![=>ox])\s*([^|]+?)\s*(={2,}>|={3,})(?=\s|$|[A-Za-z_])/.exec(rest))) {
      label = m[1];
      arrow = `==${m[2]}`;
    } else if ((m = /^(<|o|x)?(-{2,}|={2,}|-\.+-|~{3,})(>|o|x)?(?=\s|$|\||[A-Za-z_])/.exec(rest))) {
      arrow = m[0];
      const head = m[1];
      const body = m[2];
      const tail = m[3];
      if (body.startsWith('~') && (head || tail)) fail('invalid invisible link');
      if ((tail === 'o' || tail === 'x') && !/^\s/.test(rest.slice(m[0].length))) fail('ambiguous link end');
      if (!tail && !head && body.length < 3 && !body.includes('.')) fail(`incomplete link '${body}'`);
    } else {
      return null;
    }
    pos += m[0].length;
    if (label === null) {
      ws();
      if (s[pos] === '|') {
        const end = s.indexOf('|', pos + 1);
        if (end < 0) fail('unterminated |label|');
        label = s.slice(pos + 1, end).trim().replace(/^"(.*)"$/, '$1');
        pos = end + 1;
      }
    }
    const directed = /[>]$/.test(arrow);
    const reverse = arrow.startsWith('<');
    if (reverse && !directed) fail(`unsupported link '${arrow}'`);
    return { directed, reverse, label, arrow };
  };

  let left = parseGroup();
  let links = 0;
  for (;;) {
    ws();
    if (pos >= s.length) break;
    const link = parseLink();
    if (!link) fail('expected a link (-->, ---, -.->, ==>) or end of statement');
    const right = parseGroup();
    for (const a of left) {
      for (const b of right) {
        g.edges.push({ from: a, to: b, directed: link.directed, label: link.label, line: lineNo });
        if (link.reverse) g.edges.push({ from: b, to: a, directed: true, label: link.label, line: lineNo, reverseOf: true });
      }
    }
    left = right;
    links++;
  }
  if (!links && left.length && ![...left].every((id) => g.nodes.has(id))) {
    // A bare id on its own line is legal Mermaid but almost always a typo.
    fail('statement is a bare node id without a definition or link');
  }
}

// Returns null when acyclic, otherwise an array of node ids forming a cycle.
export function findCycle(g) {
  const adj = new Map();
  for (const id of g.used.keys()) adj.set(id, []);
  for (const e of g.edges) if (e.directed) adj.get(e.from).push(e.to);
  const state = new Map(); // 1 = on stack, 2 = done
  const stack = [];
  const visit = (u) => {
    state.set(u, 1);
    stack.push(u);
    for (const v of adj.get(u) || []) {
      if (state.get(v) === 1) return [...stack.slice(stack.indexOf(v)), v];
      if (!state.get(v)) {
        const c = visit(v);
        if (c) return c;
      }
    }
    stack.pop();
    state.set(u, 2);
    return null;
  };
  for (const id of [...adj.keys()].sort()) {
    if (!state.get(id)) {
      const c = visit(id);
      if (c) return c;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Main check

// `parseMermaid` replaces parseFlowchart; the self-test uses it to check that
// an internal parser failure propagates instead of becoming a docs error.
export function checkDocs({ root, parseMermaid = parseFlowchart } = {}) {
  root = resolve(root || join(dirname(fileURLToPath(import.meta.url)), '..', '..'));
  const report = new Report();
  const stats = {
    files: [],
    fences: 0,
    taskGroups: 0,
    subtasks: 0,
    taskRefs: 0,
    taskRanges: 0,
    adrs: 0,
    adrRefs: 0,
    scenarios: 0,
    scenarioRefs: 0,
    invariants: 0,
    invariantRefs: 0,
    mermaid: {},
    mermaidNodes: 0,
    mermaidEdges: 0,
    links: 0,
    anchors: 0,
    sectionRefs: 0,
  };
  const { tracked, all } = listRepoFiles(root);
  const docFiles = [...all].filter((p) => p.startsWith('docs/') && p.endsWith('.md')).sort();
  for (const spec of SPECS) {
    if (!docFiles.includes(spec)) report.error(spec, 0, 'files', tracked ? 'spec is not a git-tracked file' : 'spec is missing');
  }
  const docs = new Map();
  for (const f of docFiles) docs.set(f, analyse(readFileSync(join(root, f), 'utf8')));
  stats.files = docFiles;

  // 1. Fences and HTML comments.
  for (const [f, doc] of docs) {
    stats.fences += doc.blocks.length;
    for (const e of doc.errors) report.error(f, e.line, e.check || 'fence', e.msg);
  }

  // Definitions.
  const defs = { task: new Map(), adr: new Map(), scenario: new Map(), invariant: new Map() };
  const defLines = new Set(); // "file:line:col" of defining tokens, not references
  const define = (kind, key, file, line, col) => {
    const map = defs[kind];
    if (map.has(key)) {
      const p = map.get(key);
      report.error(file, line, kind, `${key} is defined more than once (also ${p.file}:${p.line})`);
      return;
    }
    map.set(key, { file, line });
    defLines.add(`${file}:${line}:${col}`);
  };

  const tasks = docs.get(TASKS);
  if (tasks) {
    // 2. Task definitions: group headings and checkbox subtasks.
    let group = null;
    const subs = new Map(); // group -> [{n, line}]
    for (const h of headings(tasks)) {
      const m = /^(T(\d{2}))\b/.exec(h.text);
      if (m) define('task', m[1], TASKS, h.line, tasks.prose[h.line - 1].indexOf(m[1]) + 1);
    }
    const headingAt = new Map(headings(tasks).map((h) => [h.line, h]));
    for (let i = 0; i < tasks.prose.length; i++) {
      const h = headingAt.get(i + 1);
      if (h) group = /^(T\d{2})\b/.exec(h.text)?.[1] ?? (h.level <= 3 ? null : group);
      const m = /^\s*[-*+]\s+\[[ xX]\]\s+\*\*T(\d{2})\.(\d+)\*\*/.exec(tasks.prose[i]);
      if (!m) {
        if (/^\s*[-*+]\s+\[[ xX]\]\s+\*\*T\d/.test(tasks.prose[i])) {
          report.error(TASKS, i + 1, 'task', 'malformed task checkbox ID (expected **Tgg.n**)');
        }
        continue;
      }
      const key = `T${m[1]}.${Number(m[2])}`;
      if (m[2] !== String(Number(m[2]))) report.error(TASKS, i + 1, 'task', `task ID T${m[1]}.${m[2]} has a leading zero (write ${key})`);
      define('task', key, TASKS, i + 1, tasks.prose[i].indexOf(`T${m[1]}.`) + 1);
      if (group !== `T${m[1]}`) {
        report.error(TASKS, i + 1, 'task', `${key} is listed under ${group ? `### ${group}` : 'no task heading'}, not ### T${m[1]}`);
      }
      if (!subs.has(`T${m[1]}`)) subs.set(`T${m[1]}`, []);
      subs.get(`T${m[1]}`).push({ n: Number(m[2]), line: i + 1 });
    }
    for (const [g, list] of subs) {
      if (!defs.task.has(g)) report.error(TASKS, list[0].line, 'task', `subtasks of ${g} have no "### ${g}" heading`);
      const nums = new Set(list.map((x) => x.n));
      const max = Math.max(...nums);
      for (let n = 1; n <= max; n++) {
        if (!nums.has(n)) report.error(TASKS, list[0].line, 'task', `${g}.${n} is missing (${g} subtasks are numbered up to ${g}.${max})`);
      }
      for (let j = 1; j < list.length; j++) {
        if (list[j].n < list[j - 1].n) report.error(TASKS, list[j].line, 'task', `${g}.${list[j].n} is out of order after ${g}.${list[j - 1].n}`);
      }
    }
    stats.taskGroups = [...defs.task.keys()].filter((k) => !k.includes('.')).length;
    stats.subtasks = defs.task.size - stats.taskGroups;

    // 3. ADR table (tasks §11).
    defineTable(tasks, TASKS, ADR_SECTION, /^\|\s*ADR-(\d{3,4})\s*\|/, (m) => adrKey(Number(m[1])), 'adr', define, report, {
      contiguous: 'warn',
      what: 'ADR table',
    });
    // 4. Conformance matrix (tasks §8).
    defineTable(tasks, TASKS, MATRIX_SECTION, /^\|\s*A(\d{2})\s*\|/, (m) => `A${m[1]}`, 'scenario', define, report, {
      contiguous: 'error',
      what: 'conformance matrix',
    });
  }
  const design = docs.get(DESIGN);
  if (design) {
    defineTable(design, DESIGN, CONTRACT_SECTION, /^\|\s*C(\d{2})\s*\|/, (m) => `C${m[1]}`, 'invariant', define, report, {
      contiguous: 'error',
      what: 'compatibility contract table',
    });
  }
  // ADR files: docs/adr/ADR-NNN-*.md, docs/adr/NNNN-*.md or a "# ADR-NNN" title.
  const adrFileDefs = new Map();
  for (const [f, doc] of docs) {
    if (!f.startsWith('docs/adr/')) continue;
    const base = posix.basename(f);
    const h1 = headings(doc).find((h) => h.level === 1);
    const fromTitle = h1 && /^ADR[- ](\d{3,4})\b/i.exec(h1.text);
    const fromName = /^(?:ADR-)?(\d{3,4})\b/i.exec(base);
    const n = fromTitle ? Number(fromTitle[1]) : fromName ? Number(fromName[1]) : null;
    if (n === null) continue;
    if (fromTitle && fromName && Number(fromName[1]) !== n) {
      report.error(f, h1.line, 'adr', `file name says ${adrKey(Number(fromName[1]))} but title says ${adrKey(n)}`);
    }
    const key = adrKey(n);
    if (adrFileDefs.has(key)) {
      report.error(f, h1 ? h1.line : 1, 'adr', `${key} is also defined by ${adrFileDefs.get(key).file}`);
    } else {
      adrFileDefs.set(key, { file: f, line: h1 ? h1.line : 1 });
      if (fromTitle) defLines.add(`${f}:${h1.line}:${doc.prose[h1.line - 1].search(/ADR[- ]\d/i) + 1}`);
      if (!defs.adr.has(key)) report.info(f, h1 ? h1.line : 1, 'adr', `${key} is defined only by this ADR file, not the tasks §11 table`, 'adr-without-row');
    }
  }
  stats.adrs = new Set([...defs.adr.keys(), ...adrFileDefs.keys()]).size;
  stats.scenarios = defs.scenario.size;
  stats.invariants = defs.invariant.size;

  // References (prose, inline code and mermaid blocks; not other code blocks).
  const referenced = { task: new Set(), adr: new Set(), scenario: new Set(), invariant: new Set() };
  const resolves = (kind, key) => defs[kind].has(key) || (kind === 'adr' && adrFileDefs.has(key));
  for (const [f, doc] of docs) {
    for (let i = 0; i < doc.lines.length; i++) {
      const block = doc.inFence[i + 1];
      let text;
      if (block) {
        if (block.unclosed || block.lang !== 'mermaid' || i + 1 === block.start || i + 1 === block.end) continue;
        text = doc.lines[i].replace(/^\s*%%.*$/, '');
      } else text = doc.prose[i];
      for (const kind of Object.keys(KINDS)) {
        for (const ref of findRefs(kind, text)) {
          if (defLines.has(`${f}:${i + 1}:${ref.col}`)) continue;
          const name = { task: 'task', adr: 'ADR', scenario: 'scenario', invariant: 'compatibility invariant' }[kind];
          if (ref.error) {
            report.error(f, i + 1, kind, `${name} range '${ref.text}': ${ref.error}`);
            continue;
          }
          const statKey = { task: 'taskRefs', adr: 'adrRefs', scenario: 'scenarioRefs', invariant: 'invariantRefs' }[kind];
          stats[statKey]++;
          if (kind === 'task' && ref.range) stats.taskRanges++;
          const missing = ref.keys.filter((k) => !resolves(kind, k));
          for (const k of ref.keys) referenced[kind].add(k);
          if (missing.length) {
            const where = ref.range ? `range '${ref.text}' includes undefined ` : 'undefined ';
            report.error(f, i + 1, kind, `${where}${name} ${missing.join(', ')}`);
          }
        }
      }
    }
  }
  for (const [key, d] of [...defs.adr, ...adrFileDefs]) {
    if (!referenced.adr.has(key)) report.info(d.file, d.line, 'adr', `${key} is defined but never referenced`, 'unreferenced-adr');
  }

  // 5. Mermaid.
  for (const [f, doc] of docs) {
    const isSpec = SPECS.includes(f);
    const mermaid = doc.blocks.filter((b) => b.lang === 'mermaid');
    stats.mermaid[f] = mermaid.length;
    for (const b of mermaid) {
      let g;
      try {
        g = parseMermaid(b.body, b.start + 1);
      } catch (e) {
        if (!(e instanceof MermaidError)) throw e; // a bug here, not in the docs: exit 2
        if (!isSpec && /^unsupported diagram type/.test(e.message)) {
          report.warn(f, e.line, 'mermaid', `${e.message}; not validated`);
        } else {
          report.error(f, e.line, 'mermaid', e.message);
        }
        continue;
      }
      stats.mermaidNodes += g.used.size;
      stats.mermaidEdges += g.edges.length;
      if (f !== TASKS) continue;
      // Task DAG rules.
      for (const [id, line] of g.used) {
        if (!g.nodes.has(id)) report.error(f, line, 'mermaid', `node '${id}' is used but has no labelled definition in this diagram`);
      }
      const cycle = findCycle(g);
      if (cycle) report.error(f, b.start, 'mermaid', `task DAG has a cycle: ${cycle.join(' --> ')}`);
      const seen = new Set();
      for (const e of g.edges) {
        const k = `${e.from}->${e.to}`;
        if (seen.has(k)) report.warn(f, e.line, 'mermaid', `duplicate edge ${e.from} --> ${e.to}`);
        seen.add(k);
        if (!e.directed) report.error(f, e.line, 'mermaid', `undirected link ${e.from} --- ${e.to} in a task DAG`);
      }
      for (const id of g.nodes.keys()) {
        if (!g.edges.some((e) => e.from === id || e.to === id) && !g.subgraphs.some((s) => s.id === id)) {
          report.warn(f, g.nodes.get(id).line, 'mermaid', `node '${id}' has no edges`);
        }
      }
    }
  }

  // 6. Links and anchors.
  const anchorCache = new Map();
  const anchorsFor = (f) => {
    if (!anchorCache.has(f)) {
      const doc = docs.get(f) || analyse(readFileSync(join(root, f), 'utf8'));
      anchorCache.set(f, anchorsOf(doc));
    }
    return anchorCache.get(f);
  };
  for (const [f, doc] of docs) {
    const refDefs = new Map();
    for (let i = 0; i < doc.prose.length; i++) {
      const line = stripInlineCode(doc.prose[i]);
      const targets = [];
      for (const m of line.matchAll(/!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*(<[^>]*>|[^\s()]*(?:\([^\s()]*\)[^\s()]*)*)(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?\s*\)/g)) {
        targets.push(m[1].replace(/^<|>$/g, ''));
      }
      const def = /^ {0,3}\[([^\]]+)\]:\s*(\S+)/.exec(line);
      if (def) {
        refDefs.set(def[1].toLowerCase(), i + 1);
        targets.push(def[2].replace(/^<|>$/g, ''));
      }
      for (const target of targets) checkLink(f, i + 1, target);
    }
    // Full/collapsed reference links whose label has no definition.
    for (let i = 0; i < doc.prose.length; i++) {
      const line = stripInlineCode(doc.prose[i]);
      for (const m of line.matchAll(/\[([^\[\]]+)\]\[([^\[\]]*)\]/g)) {
        const label = (m[2] || m[1]).toLowerCase();
        if (!refDefs.has(label)) report.error(f, i + 1, 'link', `reference link [${m[2] || m[1]}] has no definition`);
      }
    }
  }
  function checkLink(f, line, target) {
    if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('//')) return;
    stats.links++;
    const hash = target.indexOf('#');
    let path = hash >= 0 ? target.slice(0, hash) : target;
    const anchor = hash >= 0 ? target.slice(hash + 1) : null;
    path = path.split('?')[0];
    let dest = f;
    if (path) {
      let decoded;
      try {
        decoded = decodeURIComponent(path);
      } catch {
        report.error(f, line, 'link', `malformed link target '${target}'`);
        return;
      }
      const abs = decoded.startsWith('/') ? join(root, decoded) : resolve(join(root, dirname(f)), decoded);
      const rel = relative(root, abs).split(sep).join('/');
      if (rel.startsWith('..')) {
        report.error(f, line, 'link', `link '${target}' leaves the repository`);
        return;
      }
      const isDir = existsSync(abs) && statSync(abs).isDirectory();
      const known = isDir ? [...all].some((p) => p.startsWith(`${rel.replace(/\/$/, '')}/`)) : all.has(rel);
      if (!known) {
        report.error(f, line, 'link', `link target '${decoded}' does not exist${tracked ? ' as a git-tracked file' : ''}`);
        return;
      }
      if (isDir) return;
      dest = rel;
    }
    if (anchor === null) return;
    if (!dest.endsWith('.md')) return;
    stats.anchors++;
    let a;
    try {
      a = decodeURIComponent(anchor);
    } catch {
      a = anchor;
    }
    const set = anchorsFor(dest);
    if (!set.has(a)) {
      const ci = [...set].find((x) => x.toLowerCase() === a.toLowerCase());
      report.error(f, line, 'link', `anchor '#${anchor}' not found in ${dest}${ci ? ` (did you mean '#${ci}'?)` : ''}`);
    }
  }

  // 7. Explicit cross-spec section references ("design §6.2", "Tasks §9").
  const sections = new Map();
  for (const s of SPECS) if (docs.has(s)) sections.set(s, sectionNumbers(docs.get(s)));
  for (const [f, doc] of docs) {
    for (let i = 0; i < doc.prose.length; i++) {
      for (const m of doc.prose[i].matchAll(/\b(design|tasks)(?:\s+document(?:'s)?)?\s+§\s?(\d+(?:\.\d+)*)/gi)) {
        const spec = m[1].toLowerCase() === 'design' ? DESIGN : TASKS;
        if (!sections.has(spec)) continue;
        stats.sectionRefs++;
        if (!sections.get(spec).has(m[2])) {
          report.error(f, i + 1, 'section', `'${m[0]}' names no numbered section of ${spec}`);
        }
      }
    }
  }
  // Bare "§N" in a spec means that spec's own section. Informational only:
  // RFC citations and prose such as "§6.1.1 in the design" are legitimate.
  for (const f of SPECS) {
    if (!docs.has(f) || !sections.has(f)) continue;
    const other = f === DESIGN ? TASKS : DESIGN;
    const doc = docs.get(f);
    for (let i = 0; i < doc.prose.length; i++) {
      const line = doc.prose[i];
      for (const m of line.matchAll(/§\s?(\d+(?:\.\d+)*)/g)) {
        const before = line.slice(Math.max(0, m.index - 60), m.index);
        if (/\b(design|tasks)(?:\s+document(?:'s)?)?\s+$/i.test(before) || /RFC\s?\d+|§$/.test(before)) continue;
        if (/^\s+in the (design|tasks)/i.test(line.slice(m.index + m[0].length))) continue;
        if (sections.get(f).has(m[1])) continue;
        const elsewhere = sections.get(other)?.has(m[1]);
        report.info(
          f,
          i + 1,
          'section',
          elsewhere
            ? `bare '§${m[1]}' is not a section of this file; it exists only in ${other} (write '${other === DESIGN ? 'design' : 'tasks'} §${m[1]}')`
            : `bare '§${m[1]}' is not a numbered section of either spec`,
        );
      }
    }
  }

  sortDiagnostics(report.errors);
  sortDiagnostics(report.warnings);
  sortDiagnostics(report.infos);
  return { errors: report.errors, warnings: report.warnings, infos: report.infos, stats, docs };
}

function defineTable(doc, file, headingRe, rowRe, keyOf, kind, define, report, opts) {
  const range = sectionRange(doc, headingRe);
  if (!range) {
    report.error(file, 0, kind, `no section heading matching ${headingRe} with the ${opts.what}`);
    return;
  }
  for (const h of range.others) {
    report.error(file, h.line, kind, `"${h.text}" is a second section heading for the ${opts.what} (the first is line ${range.start}); its rows are not definitions`);
  }
  const rows = [];
  for (let n = range.start; n < range.end; n++) {
    const m = rowRe.exec(doc.prose[n - 1]);
    if (!m) continue;
    const key = keyOf(m);
    const num = Number(m[1]);
    if (rows.length && num <= rows[rows.length - 1].num) {
      report.error(file, n, kind, `${key} is out of order in the ${opts.what} (after ${rows[rows.length - 1].key})`);
    }
    rows.push({ key, num, line: n });
    // Column of the ID token (the first capital letter in the row).
    define(kind, key, file, n, doc.prose[n - 1].search(/[A-Z]/) + 1);
  }
  if (!rows.length) {
    report.error(file, range.start, kind, `the ${opts.what} under "${range.heading.text}" has no rows`);
    return;
  }
  const nums = new Set(rows.map((r) => r.num));
  const max = Math.max(...nums);
  for (let n = 1; n <= max; n++) {
    if (nums.has(n)) continue;
    const key = keyOf([null, String(n).padStart(kind === 'adr' ? 3 : 2, '0')]);
    const msg = `${key} is missing from the ${opts.what} (rows run up to ${rows.find((r) => r.num === max).key})`;
    if (opts.contiguous === 'error') report.error(file, range.start, kind, msg);
    else report.warn(file, range.start, kind, msg);
  }
}

// ---------------------------------------------------------------------------
// Optional real-Mermaid oracle (local use only; not needed by CI).
//
// DIR must contain node_modules/mermaid and node_modules/jsdom. Mermaid
// cannot be imported under plain Node (DOMPurify needs a window), so a jsdom
// window is installed first. Every mermaid block must parse, and for
// flowcharts the node and edge sets must equal the hand parser's.

export async function loadMermaidOracle(dir) {
  const req = (p) => pathToFileURL(join(resolve(dir), 'node_modules', p)).href;
  const { JSDOM } = await import(req('jsdom/lib/api.js'));
  const dom = new JSDOM('<!doctype html><html><body></body></html>');
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  const mermaid = (await import(req('mermaid/dist/mermaid.core.mjs'))).default;
  mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' });
  // Appends oracle errors to result.errors; returns the number of blocks parsed.
  return async ({ docs, errors }) => {
    const report = { error: (file, line, check, msg) => errors.push({ file, line, check, msg }) };
    let n = 0;
    for (const [f, doc] of docs) {
      for (const b of doc.blocks.filter((x) => x.lang === 'mermaid')) {
        const src = b.body.join('\n');
        try {
          await mermaid.parse(src);
        } catch (e) {
          report.error(f, b.start, 'oracle', `real Mermaid rejects this block: ${String(e.message).split('\n')[0]}`);
          continue;
        }
        n++;
        let mine;
        try {
          mine = parseFlowchart(b.body, b.start + 1);
        } catch {
          continue; // the hand parser already reported it
        }
        const { db } = await mermaid.mermaidAPI.getDiagramFromText(src);
        const subgraphs = (db.getSubGraphs?.() || []).map((s) => s.id);
        const theirsNodes = new Set([...db.getVertices().keys(), ...subgraphs]);
        const mineNodes = new Set(mine.used.keys());
        const theirsEdges = new Set(db.getEdges().map((e) => `${e.start}->${e.end}`));
        const mineEdges = new Set(mine.edges.filter((e) => !e.reverseOf).map((e) => `${e.from}->${e.to}`));
        const diff = (a, b2) => [...a].filter((x) => !b2.has(x)).sort();
        const nd = [...diff(theirsNodes, mineNodes), ...diff(mineNodes, theirsNodes)];
        const ed = [...diff(theirsEdges, mineEdges), ...diff(mineEdges, theirsEdges)];
        if (nd.length || ed.length) {
          report.error(f, b.start, 'oracle', `hand parser disagrees with Mermaid: nodes [${nd.join(', ')}] edges [${ed.join(', ')}]`);
        }
      }
    }
    return n;
  };
}

// ---------------------------------------------------------------------------
// CLI

async function main(argv) {
  let root;
  let verbose = false;
  let oracleDir = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--root' || a.startsWith('--root=')) {
      // Without this check a missing value would silently check the default root.
      root = a === '--root' ? argv[++i] : a.slice('--root='.length);
      if (!root) {
        console.error('docs-check: --root needs a directory');
        return 2;
      }
    } else if (a === '--verbose' || a === '-v') verbose = true;
    else if (a.startsWith('--mermaid-oracle=')) oracleDir = a.slice('--mermaid-oracle='.length);
    else if (a === '--help' || a === '-h') {
      console.log('usage: node scripts/ci/docs-check.mjs [--root DIR] [--verbose] [--mermaid-oracle=DIR]');
      return 0;
    } else {
      console.error(`docs-check: unknown argument '${a}'`);
      return 2;
    }
  }
  const result = checkDocs({ root });
  if (oracleDir) {
    const oracle = await loadMermaidOracle(oracleDir);
    result.stats.oracle = await oracle(result);
    sortDiagnostics(result.errors);
  }
  const { errors, warnings, stats } = result;
  let { infos } = result;
  // In GitHub Actions (GITHUB_ACTIONS=true) errors and warnings are printed
  // as workflow commands, so they become annotations on the run and the pull
  // request. ADR bookkeeping: numbering gaps in the tasks §11 table are
  // warnings everywhere; an ADR that only a docs/adr/ file defines (a
  // missing table row) is an info note locally and a ::warning annotation in
  // CI, so a reviewer sees it. An ADR that is never referenced by ID is plain
  // info everywhere, summarised in one line (--verbose lists them), since
  // most ratification-table ADRs legitimately have no references. Only
  // errors fail (exit 1).
  const gha = process.env.GITHUB_ACTIONS === 'true';
  const print = (level, d) => console.log(gha ? formatAnnotation(level, d) : formatDiagnostic(level, d));
  for (const d of errors) print('error', d);
  for (const d of warnings) print('warning', d);
  // The summary counts warnings as printed: in CI that includes the
  // missing-row annotations, so it equals the number of ::warning lines.
  let warningCount = warnings.length;
  if (gha) {
    const rows = infos.filter((x) => x.tag === 'adr-without-row');
    for (const d of rows) console.log(formatAnnotation('warning', d, 'info'));
    warningCount += rows.length;
    infos = infos.filter((x) => x.tag !== 'adr-without-row');
  }
  if (verbose) for (const d of infos) console.log(formatDiagnostic('info', d));
  else {
    const unreferenced = infos.filter((x) => x.tag === 'unreferenced-adr').length;
    infos = infos.filter((x) => x.tag !== 'unreferenced-adr');
    if (unreferenced === 1) console.log('1 ADR is never referenced by ID; --verbose lists it');
    else if (unreferenced) console.log(`${unreferenced} ADRs are never referenced by ID; --verbose lists them`);
    if (infos.length) console.log(`(${infos.length} info notes; rerun with --verbose to list them)`);
  }
  const mermaid = Object.entries(stats.mermaid)
    .filter(([, n]) => n)
    .map(([f, n]) => `${f}: ${n}`)
    .join(', ');
  console.log(
    [
      `docs-check: ${stats.files.length} Markdown files under docs/ (${stats.fences} fenced blocks)`,
      `  tasks: ${stats.taskGroups} groups, ${stats.subtasks} subtasks; ${stats.taskRefs} references (${stats.taskRanges} ranges)`,
      `  ADRs: ${stats.adrs} defined, ${stats.adrRefs} references`,
      `  conformance scenarios: ${stats.scenarios} defined, ${stats.scenarioRefs} references; compatibility invariants: ${stats.invariants} defined, ${stats.invariantRefs} references`,
      `  mermaid: ${mermaid || 'none'} (${stats.mermaidNodes} nodes, ${stats.mermaidEdges} edges)${stats.oracle !== undefined ? `; real Mermaid parsed ${stats.oracle}` : ''}`,
      `  links: ${stats.links} relative links, ${stats.anchors} anchors; ${stats.sectionRefs} explicit section references`,
      errors.length ? `FAILED: ${errors.length} error(s), ${warningCount} warning(s)` : `OK (${warningCount} warning(s))`,
    ].join('\n'),
  );
  return errors.length ? 1 : 0;
}

// Compare real paths: Node resolves symlinks in import.meta.url but not in
// argv[1], and a missed match here would exit 0 without checking anything.
const isMain = (() => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (isMain) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(e);
      process.exit(2);
    },
  );
}
