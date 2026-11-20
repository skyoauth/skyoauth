// Test helper for the registry self-tests (check-conformance-registry.test.mjs
// and gen-conformance-registry.test.mjs); not used by CI scripts themselves.
//
// Fixtures start from the committed scenarios.toml and subcases.toml with every
// stage reset to `planned` (no stamp, `tests = []`) and `gates_passed = []`,
// so that implementing a real stage or passing a gate does not change what the
// tests see. Stage legs, scopes and milestones are kept as committed.

// A stage's status, optional stamp and tests, as the generator writes them
// (tests inline or one string per line).
const STATUS = /^status = "(?:planned|implemented)"\n(?:implemented_sha256 = "[0-9a-f]*"\n)?tests = \[(?:\s*"(?:[^"\\\n]|\\.)*",?)*\s*\]$/gm;

export function normaliseRegistry(text) {
  return text.replace(/^gates_passed = \[.*\]$/m, 'gates_passed = []').replace(STATUS, 'status = "planned"\ntests = []');
}

// Every way of giving one key of the `[[table]]` entry `id` (its stages
// included) the TOML `value`, and of adding the keys `extra.entry` to the entry
// and `extra.stage` to each stage with that value: [label, text] pairs, for
// fuzzing what a value of the wrong type does to diagnostics.
export function valueSwaps(text, table, id, value, extra = {}) {
  const start = text.indexOf(`[[${table}]]\nid = "${id}"`);
  if (start < 0) throw new Error(`no ${table} ${id}`);
  const next = text.indexOf(`\n[[${table}]]\n`, start + 1);
  const block = text.slice(start, next < 0 ? text.length : next);
  const at = (i, len, s) => text.slice(0, start + i) + s + text.slice(start + i + len);
  const out = [];
  let where = id;
  let stages = 0;
  for (const m of block.matchAll(/^\[\[[a-z.]+\]\]$|^([a-z_0-9]+) = (\[\n(?:.*\n)*?\]|.*)$/gm)) {
    if (!m[1]) {
      where = m[0] === `[[${table}.stage]]` ? `${id} stage ${++stages}` : id;
      for (const k of where === id ? [] : (extra.stage ?? [])) out.push([`${where} +${k}`, at(m.index + m[0].length, 0, `\n${k} = ${value}`)]);
      continue;
    }
    out.push([`${where} ${m[1]}`, at(m.index, m[0].length, `${m[1]} = ${value}`)]);
    if (m[1] === 'id') for (const k of extra.entry ?? []) out.push([`${id} +${k}`, at(m.index + m[0].length, 0, `\n${k} = ${value}`)]);
  }
  return out;
}
