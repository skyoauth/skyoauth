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
