# Conformance registry

This directory holds the conformance scenario registry of [the conformance layout](../../docs/testing/conformance-layout.md) §3. It contains **data only**: the scenario tests themselves live in the `skyoauth-scenarios` package (`tests/Cargo.toml`, layout §1.2), under the layer directories beside this one (`tests/security/` today). There are no fixtures, schemas or waivers here yet. The static part of `check-conformance-registry` checks it in CI on every change, docs-only changes included (the `Conformance registry` job); its [resolution part](#the-resolution-part), which needs a built test list, runs in the `scenarios-pg` job. [`report-conformance.mjs`](#the-reporter) joins the registry with the JUnit results of one commit.

| File | What it holds |
| --- | --- |
| `scenarios.toml` | `gates_passed` (empty: no milestone gate has passed), the 64 scenarios A01–A64 (`kind = "scenario"`) and the 10 contracts C01–C10 (`kind = "contract"`). Every scenario stage is `planned` with `tests = []`, except five `implemented` stages on `scenarios-pg/x86_64`, A29's M1a (the first), A38's M1a, A24's M1a, A25's M1a and A50's M1a, and seven `planned` stages that list partial tests, registered but counting for nothing: A04's M1a, with tests of its registry keyset lifecycle only (`tests/security/a04.rs`: a new keyset version uploaded with its own explicit window that overlaps the old one and enabled next to it, the old one disabled and an open-ended one added, each read back exactly as uploaded but for its status and its own revision, with the parent, source, binding and grant keeping their IDs, columns and revisions (revisions a registry pick, not the spec's) and the tenant's other keyset unchanged, also when replicas upload at once; empty and inverted windows refused by `trust_keyset_version_validity_check`, one empty only in whole microseconds included; stale, other-tenant, missing-keyset and reused-ID rotation steps refused, writing nothing; and exactly one winner among replicas that change one version's status or upload one version ID at once or behind an uncommitted holder), not claiming the verifier's window decision at token time (each key valid in its window and in the overlap, refused outside it; T11.3, T24.2; in M1a inferred and provisional, T24.2 being M2), the live kid conflict and key checks of an upload (T11.3), for both of which the pure `skyoauth_service::jwk` module (`parse_jwk_set`, `check_version_overlap`, `live_keys`) is an unwired building block, or the audited trust_admin keyset endpoints with widening detection (T11.6, T13.8, T13.2; IR-052), and with the rotation's independence of human-provider changes (T11.6) an open owner question; open and provisional: whether adding a keyset version is a widening change that needs review (OQ-ADR008-3, whose original question names it; ADR-008 item 12), and the non-empty window rule, which exists only as the `0004` check and in no spec; the exchange through the overlap is A04's M2 stage, A53's M1a, with the tests of its create and PATCH refusal half (`tests/security/a53.rs`), A37's M1a, with tests (`tests/security/a37.rs`) of its whole row except "removal reviewed as widening", which is uncovered, A22's M1a, with tests of the operator registry lookup only (`tests/security/a22.rs`), without the operator endpoint of the in-process service (UC) and its server side (certificate-chain verification against the deployment trust anchor and canonicalization of the presented key into `public_identity`; T13.1, T13.3), the OP harness component `skyoauth-operator` (T13.10) as the client that presents the key, or the OIDC harness component (the mock human IdP) whose admin-role claim or session must confer nothing there, A32's M1a, with tests of the bootstrap and recovery registry functions only (`tests/security/a32.rs`: one bootstrap, concurrent and blocked bootstraps across replicas, a closed bootstrap that no valid request reopens, and a restoration from an issued challenge that enrolls the replacement its plan names, revokes the operator credentials and rotates the recovery key, refused when replayed, expired, outside `READ COMMITTED` or not the replacement and binding its challenge names, with exactly one restorer when replicas restore at once or behind an uncommitted restore (the holder after its commit, one waiter after its rollback)), without the deployment-local bootstrap command and its Unix socket of mode 0600 (T13.4, OQ-TM-9) and the service-local bootstrap/recovery verifier behind them (T13.3), which are the local verifier harness component and the recovery signature check, a restart or configuration omission beyond a fresh pool, the OP harness component `skyoauth-operator` (T13.10) as the client, the full chain with no SQL through the OP client and the local verifier (A48), the signed offline recovery tooling with its SoftHSM2, hermetic and recovery-offline legs, injected clocks and three operating systems (A64), or the forged IdP admin negative on the wire, A43's M1a, with tests of its registry write slice only (`tests/security/a43.rs`: a tenant's service identities and grants naming its own and a shared assigned audience; one typed refusal in each of the three registry states a name can be in, a resource server assigned to another tenant only, one assigned to no tenant, and no resource server with that ID, to which an unknown ID, every audience string and every assignment ID reduce, the writer's own among them; refused competing resource servers and assignments; audience variants distinct or refused, with an NFD spelling, a no-break space and a zero-width space accepted as a known gap owned by audience syntax and Unicode normalization (OQ-IR-9, open; a service rule per migrations README "What 0003 adds"; T14.1), which a service-layer fix will not turn red; and one winner per tenant and audience among replicas that register or assign it at once, and to one tenant behind an uncommitted holder), without the refusal of a reference whose assignment is disabled (the registry checks only that an assignment exists; T14.2; an open gap, where a database trigger is the lead's recommendation, not a decision), audience syntax and Unicode normalization (OQ-IR-9, open; a service rule per migrations README "What 0003 adds"; T14.1), or the tenant-admin negative at the endpoint (T14.1's tenant-admin clause, enforced by T13.2's scoped roles at the T13.8 endpoints, API-147), which A43's PG and RB harness cannot finish and which is unowned until the maintainer rules between widening A43's harness and crediting it to A22 M1a; issuance and the backends' tenant mapping are A43's M2 stage, the RB harness component (the reference backend's tenant/RBAC check) is not built, and the live recheck at authorization (IR-081) is A31's M2 stage (T14.3, T26.5), and A26's M1a, with tests of its registry and policy slice only (`tests/security/a26.rs`: through registry writes, `load_scope_ceilings` and `policy::resolve_scopes`, an omitted scope resolves to exactly the grant's stored explicit defaults and never to the wider ceiling; no defaults, an explicit empty list, a scope outside any one ceiling (the resource server, the tenant's assignment, the grant and, for a delegation only, the target service), alone or next to an allowed one, an unknown, case or lookalike variant and defaults outside a ceiling narrowed after the grant was written each give the one `ScopeError::Invalid`, not a trimmed set; a request token outside the `scope-token` grammar gives it only because no ceiling contains one, so the grammar check itself is pinned only by the `policy::scope` unit tests and IR-066's grammar here only at write; the registry refuses empty defaults and defaults outside the grant's own scopes by `service_grant_default_scopes_check` and malformed tokens by `skyoauth_scope_list_check`, writing nothing; the other tenant's assignment of the same audience never applies; and an uncommitted or rolled-back ceiling change never decides), without the token endpoint that calls them and maps the error to the wire `invalid_scope` after the audience `invalid_target` of ERR-024 (that order inferred: the ceilings need the audience's resource server), the issued credential's explicit scope, the request layer's `scope` parsing (an absent versus an empty parameter; the wire code for a token outside the grammar is undecided, T21.1; repeated tokens are OQ-IR-11, open), or the `resource`, audience and `requested_token_type` negatives, which are A26's M2 stage, "exchange" (T21.1, T21.2, T21.5), and without the status checks of design §5.7 step 5 (T12.6, T12.7, T14.2, wired in M2 by T21.4 and T21.5); the recorded ceiling revisions (T12.6, T21.5) and a duplicated `scope` parameter (T21.1) are in the tasks only, not in A26's row. **The source of the layout §2 scenario table.** |
| `subcases.toml` | Sub-IDs as `[[subcase]]` entries (`kind = "subcase"`, with `parent`). Today it holds the four conditional sub-IDs that layout §2 names; each carries `conditional_on` and `table_text`. |
| `waivers.toml` | Optional; absent today. Flake waivers (format below). |
| `fixtures/`, `schema/` | Absent today. Layout §1.3. |
| [`scripts/ci/gen-conformance-registry.mjs`](../../scripts/ci/gen-conformance-registry.mjs) | Rewrites the derived fields of both files and renders the layout §2 table from them; `--check` verifies. Node 20 or later, no dependencies. |
| [`scripts/ci/check-conformance-registry.mjs`](../../scripts/ci/check-conformance-registry.mjs) | The registry check (layout §3): the static part, and with a test list the resolution part. Needs `smol-toml` from [`scripts/ci/package.json`](../../scripts/ci/package.json). |
| [`scripts/ci/report-conformance.mjs`](../../scripts/ci/report-conformance.mjs) | The result reporter (layout §3 "Result join", [below](#the-reporter)). Uses the registry check and `smol-toml`. |
| `scripts/ci/*.test.mjs` | Self-tests of the three scripts (`node:test`). |

## Generate and check

```sh
node scripts/ci/gen-conformance-registry.mjs           # rewrite derived fields and the layout §2 table
node scripts/ci/gen-conformance-registry.mjs --check   # exit 1 if any of the three files differs from regenerated output
node --test scripts/ci/gen-conformance-registry.test.mjs

(cd scripts/ci && npm ci --ignore-scripts)              # once: installs the pinned smol-toml
node scripts/ci/check-conformance-registry.mjs          # add --require-history to fail without git history
node scripts/ci/check-conformance-registry.mjs --gate-pr   # on a gate PR's head: see "Gate PRs" below
cargo nextest list --locked -p skyoauth-scenarios --profile ci --message-format json > nextest-list.json
node scripts/ci/check-conformance-registry.mjs --nextest-list nextest-list.json   # the resolution part, as in scenarios-pg
node --test scripts/ci/check-conformance-registry.test.mjs
node --test scripts/ci/report-conformance.test.mjs
```

CI runs the checks and the three self-tests above in the `conformance-registry` job, which `CI passed` requires to pass (a skip does not count); the `--nextest-list` run is in the `scenarios-pg` job instead ([The resolution part](#the-resolution-part)). The job checks out the full history, because the waiver rule needs `origin/main`.

## Source of truth

`scenarios.toml` is authoritative for every column of the layout §2 scenario table, and `subcases.toml` for the conditional sub-ID sentences at the end of a row. The generator renders the table and the "Counts by first stage …" sentences after it into `docs/testing/conformance-layout.md`. It never parses the table back. To change a row, edit its registry entry and run the generator; a hand edit of the table is overwritten by the generator and fails `--check` and the registry check.

IDs and hashes are still derived from the specs: the tasks §8 rows decide which scenarios exist and in what order, the design §2 rows which contracts exist. A tasks §8 row without a registry entry, or an entry without a row, is an error, so a new scenario needs a hand-written entry in the same PR as its row.

| Entry group | Field | Source |
| --- | --- | --- |
| Scenarios A01–A64 | entry order, `matrix_sha256` | Derived from row `\| Axx \| … \|` of tasks §8 ([docs/skyoauth-tasks.md](../../docs/skyoauth-tasks.md)) |
| | `layers`, `envs`, `harness`, `owners`, `note`, `positive`, `negative`, and every stage field | Hand-authored. A stage without a `legs` key gets the provisional default legs (below); a missing `status` is `planned` and missing `tests` are `[]`. |
| Contracts C01–C10 | `id`, `matrix_sha256` | Derived from row `\| Cnn \| … \|` of design §2 ([docs/skyoauth-design.md](../../docs/skyoauth-design.md)) |
| | `covered_by` | Derived from the "Covered by" table in layout §5, decision Q11 |
| Subcases | `matrix_sha256` | Derived from the task line of the subcase's first owner (below) |
| | every other field | Hand-authored |
| File | `gates_passed` | Hand-authored: a plain list of milestones. A gate PR adds to it and changes nothing else ([Gate PRs](#gate-prs), layout §3 **Gates**); a PR that only removes milestones (a revocation) is an ordinary reviewed PR, not a gate PR. |
| File | comments | Generated; hand-written comments are dropped |
| Layout §2 | the scenario table and its counts sentences | Rendered from the registry |

### How a row is rendered

| Column | Registry field | Rule |
| --- | --- | --- |
| ID | `id` | |
| Layer | `layers` | `conformance`, `security`, `integration`, `package` → `C`, `S`, `I`, `P`, joined with `+` in list order |
| Env | `envs` | Env names → the layout §1.1 **Code** column (`H`, `PG`, `EK`, `BR`, `N3`, `LV`), joined with `, ` |
| Harness | `harness` | Joined with `, ` |
| Stages | `[[scenario.stage]]` `milestone`, `scope` | `Mx: scope` parts joined with ` · `. A one-stage entry, whose scope is the fixed text `full row`, shows only `Mx`. |
| Owners | `owners` | Joined with `, ` |
| + / − required | `note`, `positive`, `negative`, plus each conditional sub-ID's `table_text` | `[note + " "] + "+ " + positive + "; − " + negative`, followed by `". " + table_text` for each conditional sub-ID of the row, in ID order |

Every text field is a table cell, so it holds no `|` and no line break.

### Hash rule

`matrix_sha256` is the SHA-256 of the UTF-8 bytes of the entry's whole source line, from its first to its last character, with no trailing newline (layout §3). For a scenario the source line is its tasks §8 table line, and for a contract it is its design §2 table line. A sub-ID hashes the whole `- [ ] **Txx.y** …` bullet line in tasks.md of its first owner. To recompute one by hand:

```sh
grep -m1 '^| A24 |' docs/skyoauth-tasks.md | tr -d '\n' | sha256sum
grep -m1 -F -- '- [ ] **T40.6** ' docs/skyoauth-tasks.md | tr -d '\n' | sha256sum
```

An edited spec line changes its hash, so `--check` and the registry check fail until the generator is re-run. The reviewer then confirms that the entry still matches the row.

### Implemented stages

Status is keyed by the stage's (id, milestone, scope, spec row), not by its position. A stage with `status = "implemented"` must list its `tests` and carry

```toml
implemented_sha256 = "<SHA-256 of id, milestone, scope and matrix_sha256 joined with newlines>"
```

for example `printf '%s\n%s\n%s\n%s' A24 M1a 'consume primitive' "$matrix_sha256" | sha256sum`. A `planned` stage carries none. When the scope changes, the stage moves to another milestone, or the tasks §8 row changes, the stamp no longer matches and both the generator and the check fail until a reviewer either sets the stage back to `planned` (and removes the stamp) or re-stamps it after confirming that its tests still cover the new scope. The generator never fills the stamp itself. Stages are never re-keyed or dropped, so a stage that moves milestone keeps its `tests`.

### Subcases

| ID | Parent | `conditional_on` | Named in layout §2 as | Hash source (tasks.md line) |
| --- | --- | --- | --- | --- |
| A18.90 | A18 | `forwardauth` | "Conditional sub-ID (ForwardAuth, T32.9): credential containment and trusted forwarded chain" | T32.9 |
| A27.90 | A27 | `device-flow` | "Conditional sub-ID A27.90 (device flow, T40.6): …" | T40.6 |
| A33.90 | A33 | `back-channel-logout` | "Conditional sub-ID A33.90 (back-channel logout, T30.6): verified sid targeting" | T30.6 |
| A58.90 | A58 | `forwardauth` | "Conditional sub-ID (ForwardAuth, T32.9): deployment-enforcer equivalence" | T32.9 |

Conditional sub-IDs are numbered .90–.99. Required sub-IDs use .01–.89, inside the annex range that the parent's `note` declares; today only A58 declares one (`A58.01–A58.89`), and a declared range must itself lie within .01–.89. The T32.3 owner drafts A58's required sub-IDs; none exist yet.

`table_text` is the sentence the parent's row ends with: `Conditional sub-ID [Axx.9y] (<feature>, <first owner>): …`. Its feature and task must equal `conditional_on` and the first owner, and that owner must be the feature's own task (layout §2: `device-flow` T40.6, `back-channel-logout` T30.6, `forwardauth` T32.9), since `conditional_on` keeps the sub-ID out of the gates. The check compares the annex with the committed §2 table: a conditional sub-ID that the table names with a number must exist under that number; an unnumbered one, such as the two ForwardAuth sub-IDs, must match exactly one entry by parent, feature and task; a conditional entry the table does not name fails. A required sub-ID has neither `conditional_on` nor `table_text` and need not be named.

## The registry check

`node scripts/ci/check-conformance-registry.mjs` implements the static part of layout §3. Each error names its rule and, where it can, the file and line:

| Rule | Checks |
| --- | --- |
| `toml` | Every registry file parses with smol-toml **and** with the generator's subset reader, and both return the same data. smol-toml 1.9.1 silently rolls an impossible date such as `2026-02-30` over to March; the subset reader rejects it, as Python `tomllib` does. |
| `fields` | Known keys only, with the right types; the files exist. |
| `ids` | Tasks §8 A rows equal the registry scenario IDs, design §2 C rows equal the contract IDs: no gaps, duplicates or extras. |
| `order` | Scenario, contract and subcase IDs increase in file order. |
| `hash` | Every `matrix_sha256` matches its source line. |
| `owners` | Every owner is a task in tasks.md. |
| `stages` | Milestones are known and increase, so the last stage holds the entry's full milestone; `full row` is the scope of a single-stage entry only; the implemented-stage rules above. No stage lists a test twice, and no test ID holds a control character, a line break or whitespace other than single spaces inside it (a nextest ID holds no space at all; the provisional vitest and Playwright titles need them). |
| `legs` | Every leg is a layout §1.1 leg string, its env is one of the entry's `envs`, its job exists at the stage's milestone, no leg repeats in a stage, and every env has a leg. |
| `gates` | Every stage of a scenario or required subcase whose milestone is in `gates_passed` is `implemented`. Conditional subcases are excluded until a release manifest lists their feature as shipped (layout §3 **Release**); none exists yet. The rest of layout §3 **Gates** is `--gate-pr` ([below](#gate-prs)) and the reporter (every such stage **passed** on the gate PR's merge-base). |
| `table` | The layout §2 table and counts sentences equal the ones rendered from the registry. |
| `subcases` | The sub-ID rules above. |
| `fixtures` | Each `fixtures/` entry not starting with `_` is a directory named after a registered scenario (`a61`), holding only `.json` cases with the layout §1.3 envelope (`fixture_version`, `kind`, `scenario`, a unique `case`, `polarity`, `consumers`, `input`, `expected`, an optional registered `subcase`). An absent `fixtures/` is fine. JSON Schema validation is not implemented: any file in `schema/` fails the check until the PR that adds the first schema extends it. |
| `waivers` | The waiver format below. |

The check adds `toml`, `gates`, `fixtures` and `waivers`, names the rule of each error, and is what CI gates on. For the other rules, the generator reports the same spec and registry errors, in both modes, except for these, which hold only in the check:

- a `|` or line break in a subcase's `harness`, `positive` or `negative`, and an empty test ID (`tests = [""]`) in any stage: both generator modes exit 0 and keep the value;
- a `|` in a conditional sub-ID's `table_text`: the write mode renders it into the §2 row, and `--check` passes after that. A `|` with a space on each side fails both modes only because the rendered row then no longer names the sub-ID; a line break there is a generator error;
- a subcase `kind` that is missing or not `"subcase"`, and an unknown subcase field (`note` included): the write mode rewrites the entry with `kind = "subcase"` and without the field, and `--check` reports only that the field "differs from the specs".

### The resolution part

`node scripts/ci/check-conformance-registry.mjs --nextest-list FILE` runs the whole check above and also the resolution part of layout §3, against `FILE`, the JSON that `cargo nextest list --message-format json` writes. Listing needs a build but no database: the scenario tests fail without `SKYOAUTH_IT_DATABASE_URL` only when they run. The `scenarios-pg` job runs it after its tests, whatever they did, on `cargo nextest list --locked -p skyoauth-scenarios --profile ci --message-format json` (the `ci` profile, so a profile filter would show), without `--require-history`. Its steps come after the leg artifact upload, which runs `if: always()`, so a failing check, static errors included, turns the job red but never costs the leg its artifact.

The check never skips a test because its package is missing from the list: such a stage test fails (`resolve`). So the list covers every package that `TEST_JOBS` names, from the PR that adds that package to the workspace: that PR adds `-p <package>` to the step (today only `skyoauth-scenarios` exists; `skyoauth-client` and `skyoauth-operator` do not yet). The reporter self-test checks that the step lists exactly the `TEST_JOBS` packages that are workspace members. This works while every such package builds and lists on the `scenarios-pg` runner; packages whose tests are listed per OS need a per-job mode ([Not here yet](#not-here-yet), layout §6 "Still open", item 8).

Locally, without cargo-nextest, `--libtest-list PKG/TARGET=FILE` takes the output of `cargo test -p PKG --test TARGET -- --list` for one target instead. That output lists every test, ignored ones included, without marking which are `#[ignore]`d, and the fallback reads only it, so with it the ignore rule is not checked, and a note says so; CI always uses `--nextest-list`. To see the ignored tests of a target by hand, run `cargo test -p PKG --test TARGET -- --list --ignored`, which lists only them: a registered test in that output fails in CI. Both options may be repeated and combined, as long as each nextest binary is in one list only. A list file that cannot be read is a usage error (exit 2); `--gate-pr` takes no list.

These rules cover every `implemented` stage, of scenarios and subcases; a `planned` stage may list tests that do not exist yet:

| Rule | Checks |
| --- | --- |
| `resolve` | Each test ID resolves against the list: the package and target of `nextest:<package>/<target>/<path>` are a listed nextest binary (`<package>::<target>`; the lib form `nextest:<package>/<path>` is the binary `<package>`), `<path>` is one of its tests, and the test is neither `#[ignore]`d (`"ignored": true`) nor left out by a filter (`"filter-match"` other than `matches`, such as a profile's `default-filter`). The vitest and Playwright ID forms are provisional (layout §6 "Still open", item 5), so they are **not checked yet**, and the check fails closed: a vitest or Playwright ID in an implemented stage is an error, and so is a leg of a job that reports with those runners (`typescript`, `typescript-browser`) or has no decided runner (`bundle-check`, `migration-rehearsal`). |
| `same-job` | Each test is produced by the job of one of the stage's legs (layout §3 "Which job produces a test", `TEST_JOBS` in the reporter). A test of a package or target that no job produces, such as `skyoauth-service`, fails. |
| `pos-neg` | Each test is a `pos` or `neg` test of the stage's own entry, and every job among the stage's legs produces at least one `pos` and one `neg` of them. |
| `orphans` | Every listed test whose last `::` segment starts with `a<NN>_` is in some stage's `tests` (planned stages included). |
| `list` | Each list is well-formed (the JSON's `rust-suites`, with `binary-id`, `package-name`, a `status` of `listed`, `skipped` or `skipped-default-filter` and, per test, a boolean `ignored` and a `filter-match` status, `matches`, or `mismatch` with a string `reason`; or `<name>: test` lines) and lists at least one test or a skipped binary; no binary is in two lists. A malformed or empty list is an error (exit 1). A binary that nextest skipped, such as one a profile's `default-filter` leaves out (`skipped-default-filter`), lists no tests, so a stage test in it fails `resolve`. |

The messages of the test-ID, resolution and list rules quote each test ID, binary and package name as a JSON string (with `\u` escapes for the C1 controls and U+2028/2029 too), and every error, of any rule, is printed on one line with any control character or line separator left in it escaped, so no name can start a line that a CI log reads as a workflow command such as `::error`.

`scripts/ci/fixtures/` holds real lists of the A29 M1a tests for the self-test: `nextest-list-scenarios.json`, from `cargo nextest list --locked -p skyoauth-scenarios --profile ci --message-format json` with the build paths replaced and the build metadata trimmed, and `libtest-list-scenarios-pg.txt`, from `cargo test --locked -p skyoauth-scenarios --test pg -- --list`. They were made with **cargo-nextest 0.9.151** (the version `ci.yml` pins) and **cargo 1.100.0**, without `SKYOAUTH_IT_DATABASE_URL`. A PR that bumps the cargo-nextest pin regenerates them with the new version, so that a change in its list format shows in the self-test; so does a change to the A29 M1a tests.

### Waivers

`tests/conformance/waivers.toml` is optional. Each flake waiver is one `[[waiver]]` table with every field:

```toml
[[waiver]]
commit = "0123456789abcdef0123456789abcdef01234567"   # 40-hex SHA of a commit on main
test = "nextest:skyoauth-scenarios/pg/security::a24::a24_neg_concurrent_single_use"   # in some stage's tests
leg = "scenarios-pg/x86_64"                            # a leg of a stage that lists the test
run_id = 12345678901                                   # positive integer
run_attempt = 1                                        # positive integer
reason = "PostgreSQL service container lost mid-test; runner fault, not product behaviour"
expires = 2026-12-31                                   # a TOML local date, not a string
```

The file must stay inside the TOML subset the generator reads (basic strings, integers, booleans, local dates, arrays and inline tables nested at most 64 levels deep, `[[table]]` headers). The check confirms that `commit` is an ancestor of `origin/main`. That needs a full, non-shallow checkout with `origin/main`. Without one the commit check is skipped with a note, unless `--require-history` is given, as in CI: that probes the history up front, so a checkout without it fails even when there are no waivers. Expiry against the current date and the reporter's use of waivers are not part of the static check.

### Gate PRs

`node scripts/ci/check-conformance-registry.mjs --gate-pr` checks a gate PR (layout §3 **Gates**, decided by the lead on 2026-11-20) instead of running the plain check. `--root` (default: this checkout) must be a full, non-shallow checkout of the PR head with `origin/main`: the judged commit is `git merge-base origin/main HEAD`, so without that history the mode fails (rule `gate-pr`). Only commits are read; uncommitted changes do not count. When `gates_passed` at `HEAD` adds no milestone to the merge-base's list, the PR is not a gate PR and nothing else is checked; that includes a revocation, a PR that only removes milestones, which is an ordinary reviewed PR. When `scenarios.toml` at the merge-base or at `HEAD` is not valid TOML, the mode cannot tell whether `gates_passed` grows, so it fails closed (rule `gate-pr`: `scenarios.toml:<line>: … tests/conformance/scenarios.toml at the merge-base <sha> is not valid TOML: …; --gate-pr cannot tell whether gates_passed grows`, or `at HEAD <sha>`). Otherwise every error names its rule:

| Rule | Checks |
| --- | --- |
| `gate-pr` | `HEAD` is a single commit whose only parent is the merge-base (`HEAD <sha> is not a single commit on top of the merge-base <sha> with origin/main (its parents: …)`); its diff (`git diff-tree --raw --no-renames --ignore-submodules=none`, so a rename, copy, deletion, mode or type change counts too, and so does a submodule's gitlink that `.gitmodules` marks `ignore = all`) changes no path but `scenarios.toml` (`the gate PR changes <path>; …`), not that file's mode or type (`the gate PR changes the mode of tests/conformance/scenarios.toml from 100644 to 100755; …`), and no line of it but `gates_passed`, which stays one line as the generator writes it, at the same line number as at the merge-base (a moved line is a change outside it), such as `gates_passed = ["M0", "M1a"]` (another form, such as several lines, a trailing comment, other spacing, trailing whitespace, single-quoted strings or backslash escapes, even one that parses to the same list, is a change outside it: `scenarios.toml:<line>: … the gate PR changes this file outside the gates_passed line; …`); and that line removes no milestone of the merge-base's list (`scenarios.toml:<line>: … the gate PR removes <milestones> from gates_passed; a gate PR only adds milestones …`). |
| every rule of the plain check | Run on the specs and `tests/conformance` of the **merge-base**, with `HEAD`'s `gates_passed` line, and the waiver commits checked against this repository's `origin/main`. So `gates` requires every stage of each new milestone to be `implemented`, with a valid stamp, at the merge-base, even if the PR's own registry differs. |

On success stdout ends with two lines for the gate job, `merge_base=<sha>` and `reporter_milestones=<milestones>`: the added milestones except M0, which has no stages and is gated by ADR ratification and the doc checks. For each of them the job runs the reporter on the merge-base, with `--root` a checkout of it, since `--allow-commit-mismatch` makes a report untrusted (exit 2):

```sh
git worktree add --detach "$RUNNER_TEMP/merge-base" "$merge_base"
node scripts/ci/report-conformance.mjs --root "$RUNNER_TEMP/merge-base" --commit "$merge_base" \
  --require-milestone "$m" --require-history --artifacts artifacts "$@"   # "$@": --waivers, as in the reporter script below
```

A post-merge or live leg of the merge-base without a result is not run, so that run exits 1 until the leg has completed and passed. The gate job is not in `ci.yml` yet; its checkout, live runs on a commit that is not the tip, and re-triggering are open questions 7a–7d of layout §6 "Still open", item 7. The default until the lead decides them: a gate PR is based on a pushed tip of `main` (only such a commit gets a `live-wif-push` run), and the job checks out `pull_request.head.sha` with `fetch-depth: 0`, since the default merge ref's commit has two parents and `--gate-pr` would refuse it.

## Legs

Every leg is a leg string from the **Leg strings** column of layout §1.1: `job/leg`, or the bare job name for a single-leg job (`bundle-check`, `scenarios-envoy-k3s-nightly`, `migration-rehearsal`, `deployed-topology-audit`, `live-wif-push`, `live-wif-negative`). The generator reads that column and rejects:

- an unknown leg;
- a leg whose env is not one of the entry's `envs`;
- a leg whose job does not exist yet at the stage's milestone;
- an env that has no leg in any stage.

Each job's first milestone is the `JOB_FROM` table in the generator, taken from layout §1.1 and §4. A job in the column without an entry there is an error.

The live WIF job is split in two (layout §1.1, §4): `live-wif-push` runs on push to `main` (A01's and A36's live positive, plus a wrong-audience negative), and `live-wif-negative` runs on schedule and dispatch (A02's denial of a schedule or dispatch token, plus a positive control). A01 and A36 use `live-wif-push`; A02 uses `live-wif-negative`.

**Legs are provisional.** The PR that implements a stage must confirm its legs and correct them in the same PR. The committed legs are the generator's defaults, with these trims and additions decided on review:

- A12: M2 `scenarios-pg` and `scenarios-envoy-k3s`; M3 `scenarios-envoy-k3s` and `typescript-browser`; M4 `scenarios-envoy-k3s` and `clients-rust-native`.
- A14 M5: `migration-rehearsal` only.
- A38 M1a: `scenarios-pg` only. The M1a cases are database storage, and the hermetic legs stay in M2.
- A42: M4 adds `clients-rust/x86_64`, `typescript/node22` and `typescript/node24` (T51.7 fixtures). M5 has `migration-rehearsal` only, because only that job carries the artifacts through the switch.
- A59 M4: adds `clients-rust/x86_64` (T40.14).
- A60 M4: `scenarios-pg` and `clients-rust-native`.

The default legs are used only when a stage has none committed. For each env of the row they are the env's default jobs that exist at the stage's milestone, as listed below. A `deployed-topology audit` stage gets only `deployed-topology-audit`.

| Env | Default job (legs) | Exceptions |
| --- | --- | --- |
| hermetic | `scenarios-hermetic` (x86_64, aarch64) | A39: `typescript` (node22, node24) and `bundle-check`. A40: `typescript`. |
| pg | `scenarios-pg` (x86_64) | |
| envoy-k3s | `scenarios-envoy-k3s` (x86_64) from M2 | M5 stages: `migration-rehearsal`. A54 adds `scenarios-envoy-k3s-nightly`. |
| browser | `typescript-browser` (chromium, firefox, webkit) from M3 | |
| native-3os | `clients-rust-native` (ubuntu, macos, windows) from M4 | Rows whose harness has `OP`: `operator` from M1a. A64: `operator` and `recovery-offline` (§5 Q6). |
| live | `live-wif-push` from M2 | A02: `live-wif-negative`. |

## The reporter

`node scripts/ci/report-conformance.mjs` implements the layout §3 result join for **one commit**. `--root` (default: this checkout) must be a checkout of the judged commit: when it is a git checkout, its `HEAD` must equal `--commit`, or the reporter stops with exit 2 and no report (`--allow-commit-mismatch` prints the report anyway, as untrusted). A root that is not a git checkout cannot be compared, which the report notes; `--require-history`, as in CI, makes it an error, and so does `--require-milestone`: a gate verdict (exit 0 or 1) is only given on a root bound to `--commit`, and an unbound one is an input error (exit 2). The reporter then runs the registry check on `--root` and stops with exit 2 on any error. Its only git commands are `git rev-parse` for that comparison and the registry check's `origin/main` reachability check for waivers.

In a workflow, mind which commit is checked out. For `pull_request` events, `actions/checkout` checks out the merge ref (`refs/pull/N/merge`, the PR head merged into its base, which is also `github.sha`), not the PR head and not the base, so with the default checkout `HEAD` is a merge commit that no run judged, and the `HEAD` = `--commit` binding does not hold (exit 2, no report). Check out the commit you pass as `--commit`. That commit depends on what the report is for:

- **A diagnostic report for a PR** judges the PR head: check out `ref: ${{ github.event.pull_request.head.sha }}` and pass that SHA as `--commit`, with the artifacts and `run.json` of the PR head's runs. It is informational only: live and post-merge legs never run on a PR, so their pairs are not run and most milestones cannot pass there, and PR runs build the merge commit (`refs/pull/N/merge`) while their `run.json` names the PR head (`headSha`). Do not pass `--require-milestone` for it. The `conformance-report` job in `ci.yml` is such a report for its own run only (the PR head on a pull request, `github.sha` otherwise), through [`scripts/ci/report-conformance-ci.sh`](../../scripts/ci/report-conformance-ci.sh): it downloads each leg job's artifact by the name that job gives in its `junit-artifact` output (layout §3 "Leg artifacts"), checks it and moves its files to `<artifacts>/<run_id>/<name>/`, then writes the run's `run.json` from the runner's environment (the values `gh run view --json databaseId,headSha,attempt,workflowName,event,headBranch` gives for the running attempt), appends the Markdown to the step summary and uploads the JSON as `conformance-report-N`. It fails only on exit 2 or a crash; exit 1, a failed conformance test, is a warning there, and it is not part of `CI passed`. A failed job still fails the workflow run: on `main` the README's CI badge turns red while `CI passed` stays green. It runs after its leg jobs whatever their result unless the run was cancelled (`!cancelled()`), and not at all on a docs-only change, which therefore gets no conformance summary (and no `--docs-only` "not run" line).
- **The milestone gate** (layout §3 "Gates") judges a named commit on `main`, where the live and post-merge legs have run; a PR head cannot have all required runs. The judged commit is the merge base, `git merge-base origin/main <gate PR head>`, and the gate PR is a single commit on top of it that touches only `gates_passed` ([Gate PRs](#gate-prs)). The gate job checks out the PR head with full history (`fetch-depth: 0`, the default for open question 7a of layout §6 "Still open"), where `--gate-pr` prints the merge base; it then adds a worktree of the merge base, downloads the artifacts and `run.json` of that commit's runs, and runs the reporter as `node scripts/ci/report-conformance.mjs --root <merge-base worktree> --commit <merge-base> --require-milestone M --require-history` with those `--artifacts`, as in [Gate PRs](#gate-prs). `--root` is a checkout of the merge base, so that its `HEAD` = `--commit` holds; with a checkout of the PR head or of the merge ref the gate gets no verdict (exit 2). The worktree shares the full checkout's history and `origin/main`, which `--require-history` needs.

### Input

```text
<artifacts>/<run_id>/run.json
<artifacts>/<run_id>/<artifact name ending in attempt-N>/junit.xml
<artifacts>/<run_id>/<artifact name ending in attempt-N>/leg
```

One directory per workflow run of the commit (CI, live, nightly, release), named by its numeric run ID, holding that run's artifacts as `gh run download` writes them and the run's metadata, `run.json`, as `gh run view RUN_ID --json databaseId,headSha,attempt,workflowName,event,headBranch` writes it (the script below; the `conformance-report` job writes the same six fields). The reporter validates four of them, which bind the run to the commit: `databaseId` must be the directory name, `headSha` must equal `--commit`, `attempt` must be a positive integer and no artifact may come from an attempt after it (it is the run's latest), and `workflowName` must be a non-empty string. It ignores the other two, `event` and `headBranch`, and any other field, so it does not tell a `pull_request` run, whose workflow the PR controls, from a run on `main`: whoever collects the runs for a gate must take only `push`, `schedule` and `workflow_dispatch` runs on `main` (layout §3 "Result join", §6 "Still open", item 6), as the script below does. A run directory without a valid, matching `run.json` is an input error, and none of its artifacts are used. The run attempt comes from the artifact name suffix `attempt-N` (`junit-scenarios-pg-x86_64-attempt-2`); the leg comes from the `leg` file, which must hold a layout §1.1 leg string. A leg artifact holds `leg` and `junit.xml` at its top and nothing else. Only the known artifacts of jobs that are not conformance legs, `service-nextest-junit-N`, `rust-coverage`, `typescript-coverage` and the reporter's own `conformance-report-N` (`NOT_CONFORMANCE` in the script), may lack a `leg` file; they are ignored with a note. Any other artifact without a `leg` file is an input error, because it may be a leg artifact whose failed attempt would otherwise vanish; so is a `leg` or `junit.xml` one directory down, and any other file in a leg artifact. A new artifact in a workflow needs an entry in that list unless it is a leg artifact (a `leg` file, a name ending in `attempt-${{ github.run_attempt }}`), and a new layout §1.1 job needs a decision in `JOB_RUNNER` (its runner, or none on purpose); otherwise the reporter self-test fails. Nothing in the tree is trusted: a symbolic link anywhere in it, a directory or special file where `leg` or `junit.xml` belongs, a file system error, and XML nested more than 100 elements deep are input errors too, reported with the rest, never an internal error. A leg artifact without `junit.xml` (a job that stopped before its tests) gives that leg no result for that attempt.

```sh
set -eu
sha=<40-hex commit>
git rev-parse HEAD | grep -qx "$sha"   # --root must be a checkout of the judged commit
mkdir artifacts
# Trusted runs only: push, schedule and workflow_dispatch runs on main.
gh run list --commit "$sha" --branch main --limit 1000 --json databaseId,event \
  --jq '.[] | select(.event == "push" or .event == "schedule" or .event == "workflow_dispatch") | .databaseId' > runs.txt
while read -r id; do
  mkdir "artifacts/$id"
  gh run view "$id" --json databaseId,headSha,attempt,workflowName,event,headBranch > "artifacts/$id/run.json"
  # gh run download fails for a run without artifacts, so ask first.
  if [ "$(gh api "repos/{owner}/{repo}/actions/runs/$id/artifacts" --jq .total_count)" -gt 0 ]; then
    gh run download "$id" --dir "artifacts/$id"
  fi
done < runs.txt
set --   # waivers.toml is optional on main
if git show origin/main:tests/conformance/waivers.toml > waivers.toml 2>/dev/null; then set -- --waivers waivers.toml; fi
node scripts/ci/report-conformance.mjs --commit "$sha" --artifacts artifacts --require-history "$@" \
  --json conformance.json --summary "$GITHUB_STEP_SUMMARY"
```

A partial download is an input error, not a smaller result: the script stops at the first failed `gh` call (`set -eu`) instead of judging what arrived. The reporter itself cannot yet tell an artifact that failed to download from one that was never uploaded; checking the downloads against the artifacts the Actions API lists for each run and attempt is an open question (layout §6 "Still open", item 6). `--limit 1000` is far above the number of runs one commit gets; if `runs.txt` ever holds 1000 lines, raise it.

| Option | Meaning |
| --- | --- |
| `--commit SHA` | Required. The judged commit: the `--root` checkout, each `run.json` and the waivers that apply must name it. |
| `--artifacts DIR` | The layout above. Omitted: no results, so every implemented stage is not run. |
| `--waivers FILE` | `waivers.toml` from the tip of `main` (layout §3: the waived commit's own tree cannot hold its waiver). The waivers for `--commit` are validated by the registry check's full waiver rule (`commit` on `main`, `test` registered in the judged commit's registry, `leg` a leg of a stage that lists it); the others get only its shape checks (keys, types, the commit format), since `main`'s file may hold waivers for tests the judged commit's registry does not have. An error, reported against `FILE`, stops the report (exit 2). A `FILE` that does not exist or is not a regular file (a directory, for example) is a usage error (exit 2, no report). |
| `--today YYYY-MM-DD` | Judging date for waiver expiry; default today (UTC). An impossible date such as `2026-02-30` is a usage error. A waiver is valid through its `expires` date. |
| `--docs-only` | The docs-only classifier skipped the build jobs: the summary starts with `runtime conformance: not run (docs-only change)`. |
| `--require-milestone M` | Gate mode: the exit status answers only whether the gate of milestone M passed (below). Needs a `--root` bound to `--commit` (a git checkout whose `HEAD` is `--commit`); otherwise the report is untrusted and the exit status is 2, not a gate verdict. M0 has no stages, so its gate is `no stages` and `--require-milestone M0` exits 1 on a bound root: M0 is gated by ADR ratification and the doc checks, not by this reporter. |
| `--require-history` | Passed to the registry check: no history is an error, so a `--root` that is not a git checkout is one too. |
| `--allow-commit-mismatch` | Print the report although `--root` is a git checkout of another commit than `--commit`. The mismatch is an input error, so the report is untrusted and the exit status is 2. For looking at results locally, never for a gate. |
| `--json FILE`, `--summary FILE` | Write the JSON result; append the Markdown summary (stdout always gets it). |

Each option that takes a value may be given once; a repeated one (`--commit A --commit B`) is a usage error (exit 2, no report), not last-one-wins.

### Rules

- **Test IDs (provisional, layout §6 "Still open", item 5).** Layout §3 fixes only `nextest:<package>/<target>/<path>`; the vitest, Playwright, lib and bin forms below and the runner of each job are proposals, not ratified. A JUnit testcase maps to a registry test ID by the runner of its leg's job (`JOB_RUNNER` in the script: `typescript`: vitest, `typescript-browser`: Playwright, the other test jobs: cargo-nextest). `bundle-check` and `migration-rehearsal` have no decided runner, and nothing defaults to nextest: their artifacts are input errors, and a stage with one of their legs cannot pass, until layout §6 decides. nextest classname `<package>::<binary>` and name `<path>` give `nextest:<package>/<binary>/<path>` (a lib unit test, classname `<package>`, gives `nextest:<package>/<path>`); vitest and Playwright give `vitest:<file>/<name>` and `playwright:<file>/<name>`, where the file ends in `.test.*` or `.spec.*`.
- **Scenario names** (layout §3): Rust `a<NN>_<pos|neg>_…` or `a<NN>_<SS>_<pos|neg>_…` on the last `::` segment; vitest `A40 pos: …` or `A58.07 neg: …` after the start or a ` > `; Playwright the same on the own title (the last ` › ` segment). The name gives the entry (`A24`, `A58.07`) and the polarity.
- **Jobs of a test** (layout §3 "Which job produces a test", `TEST_JOBS` in the script): `skyoauth-scenarios` targets `hermetic`, `pg`, `envoy_k3s`, `live`; `skyoauth-client`; `skyoauth-operator` targets `operator`, `recovery_offline`; vitest; Playwright. `skyoauth-service` has no job: `service/` tests are not conformance evidence for now (layout §6 "Still open", item 3, provisional), so `service-nextest` stays a unit-and-DB job and service-consumer fixtures are replayed from `skyoauth-scenarios`. `bundle-check` has no test source yet. `skyoauth-operator` has one job per target, as layout §6 decided: target `operator` runs in `operator`, and target `recovery_offline` runs in `recovery-offline`. A stage that lists both jobs (A64) therefore needs a `pos` and a `neg` test from each target, and a test of any other target of the package (its lib or a bin too) is produced by no job, so a stage that lists it is not run. Where one source still maps to several jobs (target `envoy_k3s`: four jobs; target `live`: two jobs), the reporter reads layout §3 literally: the test must pass in every one of those jobs that its stage lists, until a per-target job mapping is defined for them (layout §6 "Still open", item 4).
- **Testcase status.** Elements are matched by local name, so `<j:failure>` is a `<failure>`. `<failure>`, `<error>` or a retry marker (`<flakyFailure>`, `<flakyError>`, `<rerunFailure>`, `<rerunError>`) is failed: retries are 0, so a pass after a retry is a failure. `<skipped>`, `<ignored>`, `<disabled>` or a `status` attribute of `skipped`, `notrun`, `disabled` or `ignored` is not run; `status="failed"`, `"failure"` or `"error"` is failed. Some dialects mark skips with attributes instead: on a testcase, `skipped`, `disabled` or `ignored` set to `true` or `1` is not run (`false` or `0` changes nothing); on a `<testsuite>` or `<testsuites>` they are counts (quick-junit, which nextest uses, writes `disabled="N"`; vitest and Playwright write `skipped="N"`), and their sum may not exceed the testcases under that element that are marked skipped, or a skipped test could read as passed, so the report is an input error; `true` there makes every testcase under it not run, in nested suites too (so it counts toward their counts), except a failed one, which stays failed. **Passed is an allow-list:** a testcase is passed only when every child is `<system-out>`, `<system-err>` or `<properties>`, its `status`, if any, is `passed`, `success` or `run`, and no skip attribute marks it or its suites. Any other element in a testcase, any other `status`, any other value of a skip attribute (`yes`, `True`, `2` on a testcase, `-1` on a suite), and any element in a suite other than `<testcase>`, `<testsuite>` and those three is an input error. A suite-level `<failure>`, `<error>` or retry marker (a setup crash, for example) fails no particular testcase, so it is an input error too: the report's results are not used and the run cannot be trusted (exit 2) until someone looks at it. A testcase listed twice in one report keeps its worst status.
- **Pairs.** For each implemented stage, every (test, leg) whose leg's job produces the test. Any unwaived failed attempt, in any run, makes the pair failed for good; otherwise a passing attempt makes it passed; otherwise it is not run (missing or skipped case, leg without a report).
- **Stages.** Worst pair, failed > not run > passed. A stage that lists a test that is not a pos/neg test of its own entry, a test that no job of its legs produces, or a job with no pos or no neg test, is not run (or failed, if a pair failed). A planned stage is planned whatever results exist; results for its tests are listed as not counted.
- **Aggregates.** A scenario at milestone M takes the worst of its stages up to M and those of its required sub-IDs; a contract is passed only when every covered scenario is. Aggregates rank **failed > planned > not run > passed** (layout §3): a planned stage never counts as passed. A milestone's gate is passed only when every stage that the registry check's `gates` rule covers is passed: scenario stages and required sub-IDs. Conditional sub-IDs are reported, failures included, but they gate nothing while no release manifest exists. Gates are per milestone, not cumulative (layout §3 **Gates**).
- **Waivers.** A waiver discards one failed attempt only when commit, test, leg, `run_id` and `run_attempt` all match and it has not expired; the pair still needs a passing attempt. A waiver never applies to a not-run pair or a planned stage. Every waiver for the commit is listed as applied (next to the pair it affected) or not applied, with the reason.
- **Results not counted.** Testcases with a scenario-like name that no implemented stage lists are listed: tests of planned stages, well-formed names not in any stage's `tests`, and unknown names (malformed, or no such entry). A test that an implemented stage lists is listed too when it is in the report of a leg whose job does not produce it (an `operator`-target test in a `recovery-offline` leg's JUnit, say), as "seen outside its job, not counted", with the leg, that leg's job and the jobs that do produce it (or that none does). Only those jobs judge the test, and one of them that does not report it already leaves its pair not run, so this listing is informational: whatever its status, failed included, it changes no pair, stage or gate and not the exit status. Other testcases are ignored.

### Output and exit status

The Markdown summary has a per-milestone table (stages passed, failed, not run, planned, and the gate), each implemented stage with its non-passed pairs and applied waivers, the waivers for the commit, the results not counted (tests of planned stages, unregistered and unknown names, then results seen outside their job, failed ones first), and notes. Artifacts are untrusted, and so is the text of the judged commit's registry and of the waiver file, so every such string passes one sanitiser before it reaches the Markdown: control characters (CR and LF included), U+2028/2029 and zero-width or bidirectional controls become a space, and the string is cut to 300 characters; prose is then HTML- and Markdown-escaped, and test IDs and artifact names are quoted as code spans. Each list in the summary shows at most 50 items and says how many more the JSON holds. A `leg` file over 1 KiB or a `junit.xml` over 64 MiB is an input error and is not read. The JSON (`format: 1`) holds the same data: `milestones`, `stages` (with `pairs` and their per-attempt statuses), `scenarios` (`status` and `by_milestone`), `contracts`, `waivers`, `uncounted` (`planned`, `unregistered`, `unknown` and `outside_job`; an `outside_job` entry also names the leg's `job` and the jobs that produce the test, `produced_by`), `failed` (some implemented stage failed), `input_errors`, `trusted` (`false` when there are input errors), `notes`.

This table is the one definition of the exit status; the script header and layout §3 refer to it.

| Exit | When |
| --- | --- |
| 2 | Usage error, registry error or waiver-file error (no report); or input errors (any mode). Input errors are: malformed or unusable JUnit (its results are not used), duplicate artifacts for one (run, attempt, leg) (both copies are joined, so a failure in either counts), an unknown leg string, an artifact name without `attempt-N`, an artifact without a `leg` file that is not a known non-conformance artifact, a misplaced, oversized or non-regular file, a symbolic link, a stray entry in the artifacts directory, a missing or mismatched `run.json` (that run is not used), an artifact of a job without a decided runner, a `--root` checkout of another commit under `--allow-commit-mismatch`, and, with `--require-milestone`, a `--root` that is not a git checkout. The report is still printed with the errors at the top and `trusted: false` in the JSON, but it cannot be trusted. |
| 1 | With `--require-milestone M`: the gate of M is not passed (some stage it covers is failed, not run or planned; M0 always). Without it: some implemented stage, of any milestone and conditional sub-IDs included, has a failed (unwaived) pair. |
| 0 | With `--require-milestone M`: the gate of M passed. Failed stages of other milestones and of conditional sub-IDs do not change this; they stay in the report, and stderr says so. Without it: no implemented stage has a failed pair; not run and planned stages do not fail the run. |

The status without `--require-milestone` is informational: it says whether any conformance test failed, not whether a gate passed. A consumer that decides on a gate must pass `--require-milestone`.

Only **passed** counts; `CI passed` is never read and is not a conformance signal (layout §3).

## Not here yet

- Fixtures, fixture schemas and `waivers.toml`.
- A per-job mode of the resolution part (layout §6 "Still open", item 8). Today one list, from `scenarios-pg`, must cover every package that `TEST_JOBS` names. Lists of the same binary per OS (the `operator` and `clients-rust-native` legs on ubuntu, macos and windows, the `recovery-offline` chain) need each job to check its own list against only the stages and tests of its own jobs, without ignoring the tests of other packages silently.
- The resolution part for vitest and Playwright tests (`vitest list --json`, `playwright test --list --reporter=json`) and their orphan patterns: their test IDs are provisional (layout §6 "Still open", item 5), so an implemented stage that uses them fails the check until they are decided.
- A workflow job that downloads the artifacts of every run for a commit, runs the reporter and posts or uploads its result (`conformance-report` covers only its own run, informationally); the gate job that runs `--gate-pr` and the reporter for the gate PR's merge-base ([Gate PRs](#gate-prs), layout §6 "Still open", item 7); the release check.
- A release-manifest PR check: `--gate-pr` does not read the release manifest, which does not exist yet. A release-manifest PR, a PR that adds a shipped feature to it, must be one commit on its merge-base with the stages of the conditional sub-IDs it makes count implemented and passed there (layout §3 **Release**); its allowed diff is undecided until the release job exists, and nothing checks any of this yet.
- The artifact manifest check (layout §6 "Still open", item 6): comparing the downloaded runs, attempts and artifacts with what the Actions API lists, so that a missing download is an input error.
- A check that the `--root` checkout is clean: the reporter compares `HEAD` with `--commit`, but uncommitted changes to the registry files are not detected.
- The reporter's fixture count check of layout §1.3 (per consumer and kind, executed JUnit cases equal fixtures on disk). Each fixture case is listed as its own registered test, so a missing case already makes its pair not run.
- **PENDING FOLLOW-UP: CODEOWNERS.** Layout §3 "Who approves" plans a `.github/CODEOWNERS` file that names the lead as owner of `tests/conformance/waivers.toml`, `tests/conformance/scenarios.toml`, `tests/conformance/subcases.toml` and the release manifest, together with "Require review from Code Owners" in the branch protection of `main`. It is not added here: it needs the lead's real GitHub handle and the maintainers' decision on the branch-protection setting (layout §6 "Still open", item 2). Until then, no check enforces who approved a registry or waiver change.
