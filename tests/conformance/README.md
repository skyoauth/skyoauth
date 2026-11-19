# Conformance registry

This directory holds the conformance scenario registry proposed in [the conformance layout](../../docs/testing/conformance-layout.md) §3. It contains **data only**. There are no runtime tests, fixtures, schemas or waivers here yet. Nothing here is wired into CI: the `check-conformance-registry` check and its `conformance-registry` CI job land in the follow-up PR (layout §3 and the M0 row of §4).

| File | What it holds |
| --- | --- |
| `scenarios.toml` | `gates_passed` (empty: no milestone gate has passed), the 64 scenarios A01–A64 (`kind = "scenario"`) and the 10 contracts C01–C10 (`kind = "contract"`). Every scenario stage is `planned` with `tests = []`. |
| `subcases.toml` | The sub-IDs that layout §2 names, as `[[subcase]]` entries (`kind = "subcase"`, with `parent`, and for a conditional sub-ID `conditional_on` and `table_text`). |
| [`scripts/ci/gen-conformance-registry.mjs`](../../scripts/ci/gen-conformance-registry.mjs) | Generates both files from the specs and checks them with `--check`. Node 20 or later, no dependencies. |
| [`scripts/ci/gen-conformance-registry.test.mjs`](../../scripts/ci/gen-conformance-registry.test.mjs) | Self-test of the generator (`node:test`). |

## Generate and check

```sh
node scripts/ci/gen-conformance-registry.mjs           # rewrite both files from the specs
node scripts/ci/gen-conformance-registry.mjs --check   # exit 1 if either file differs from regenerated output
node --test scripts/ci/gen-conformance-registry.test.mjs
```

The generator is deterministic and idempotent: a second run changes nothing. `--check` names each differing entry and field, for example `A24: matrix_sha256 is …, but its spec line hashes to …` after the tasks §8 A24 row is edited.

Both modes also run these checks and, on any failure, exit 1 and write nothing:

- The layout §2 scenario table, rendered back from the registry, must equal the committed table, so the registry can always reproduce it.
- `subcases.toml` must hold exactly the sub-IDs that layout §2 names, with the parent, feature and task named there.
- Neither file may repeat an ID or a stage milestone within an entry. These errors name the file and line.
- Every leg must be a leg string from the layout §1.1 **Leg strings** column.
- The specs must have no missing, duplicate or out-of-order rows, and no unknown owner, layer or env. Every contract must have a mapping.

Today the layout §2 table is the source and the registry is derived from it. Layout §2 says that once this file lands the direction flips: the registry becomes the single source and the check renders the table from it. That switch belongs to the follow-up PR.

## Where each field comes from

Fields are either **derived**, which means the generator rewrites them on every run, or **hand-authored**, which means the generator keeps the committed value.

| Entry group | Field | Source |
| --- | --- | --- |
| Scenarios A01–A64 | `id`, `matrix_sha256` | Row `\| Axx \| … \|` of tasks §8 ([docs/skyoauth-tasks.md](../../docs/skyoauth-tasks.md)), one entry per row in row order |
| | `layers`, `envs`, `harness`, `owners`, `note`, `positive`, `negative`, and each stage's `milestone` and `scope` | Row `\| Axx \| … \|` of the layout §2 scenario map ([docs/testing/conformance-layout.md](../../docs/testing/conformance-layout.md)) |
| | stage `legs`, `status`, `tests` | Hand-authored. A stage that has no committed legs gets the generator's provisional default legs (below). |
| Contracts C01–C10 | `id`, `matrix_sha256` | Row `\| Cnn \| … \|` of design §2 ([docs/skyoauth-design.md](../../docs/skyoauth-design.md)) |
| | `covered_by` | Row `\| Cnn … \|` of the "Covered by" table in layout §5, decision Q11, in table order |
| Subcases | `matrix_sha256` | The task line of the subcase's first owner (below) |
| | every other field | Hand-authored, then checked against layout §2: `parent`, `conditional_on`, the first owner and `table_text` must match the sentence that §2 shows |
| File | `gates_passed` | Hand-authored. A gate PR changes it (layout §3). |
| File | comments | Generated; hand-written comments are dropped |

### Layout §2 columns

| Column | Registry field | Rule |
| --- | --- | --- |
| ID | `id` | |
| Layer | `layers` | `C`, `S`, `I`, `P` → `conformance`, `security`, `integration`, `package`, kept in the order the cell joins them with `+` |
| Env | `envs` | Codes from the layout §1.1 **Code** column (`H`, `PG`, `EK`, `BR`, `N3`, `LV`) → env names, split on `, ` |
| Harness | `harness` | Split on `, ` outside parentheses and backticks |
| Stages | `[[scenario.stage]]` `milestone`, `scope` | The cell is split on ` · `, and each part is `Mx: scope`. A one-stage cell holds only `Mx`, and its scope is the fixed text `full row`, as in the layout §3 A64 example. |
| Owners | `owners` | The cell is split on `, `. Each owner must be a `**Txx.y**` task in tasks.md. |
| + / − required | `note`, `positive`, `negative`, plus each conditional sub-ID's `table_text` | The cell is `[note + " "] + "+ " + positive + "; − " + negative`, followed by `". " + table_text` for each conditional sub-ID of the row, in ID order. `note` is text shown before the `+`; it is used only by A58 and A62 and is omitted when empty. The trailing sentence is rendered from `subcases.toml`: today that is A18, A27, A33 and A58. |

### Hash rule

`matrix_sha256` is the SHA-256 of the UTF-8 bytes of the entry's whole source line, from its first to its last character, with no trailing newline (layout §3). For a scenario the source line is its tasks §8 table line, and for a contract it is its design §2 table line. Both run from the leading `|` to the trailing `|`. A sub-ID hashes "the task text it was drafted from" (layout §3). Here that is the whole `- [ ] **Txx.y** …` bullet line in tasks.md of the subcase's first owner, which is the task that its §2 sentence names. Each subcase carries a generated comment that quotes the line. To recompute one by hand:

```sh
grep -m1 '^| A24 |' docs/skyoauth-tasks.md | tr -d '\n' | sha256sum
grep -m1 -F -- '- [ ] **T40.6** ' docs/skyoauth-tasks.md | tr -d '\n' | sha256sum
```

An edited spec line changes its hash, so `--check` fails until the generator is re-run. The reviewer then confirms that the entry still matches the row.

### Subcases

| ID | Parent | `conditional_on` | Named in layout §2 as | Hash source (tasks.md line) |
| --- | --- | --- | --- | --- |
| A18.01 | A18 | `forwardauth` | "Conditional sub-ID (ForwardAuth, T32.9): credential containment and trusted forwarded chain" | T32.9 |
| A27.01 | A27 | `device-flow` | "Conditional sub-ID A27.01 (device flow, T40.6): …" | T40.6 |
| A33.01 | A33 | `back-channel-logout` | "Conditional sub-ID A33.01 (back-channel logout, T30.6): verified sid targeting" | T30.6 |
| A58.01 | A58 | `forwardauth` | "Conditional sub-ID (ForwardAuth, T32.9): deployment-enforcer equivalence" | T32.9 |

A sub-ID that §2 names with a number must exist under that number. An unnumbered one, the two ForwardAuth sub-IDs, must match exactly one entry by parent, feature and task, so `A18.01` and `A58.01` are provisional numbers. Any entry that §2 does not name fails the check. The required A58 sub-IDs that layout §5 Q1 assigns to the T32.3 owner are not drafted yet, so they are not here. Once they are drafted, §2 must also name them.

A subcase's `layers`, `envs`, `harness` and stage `legs` copy its parent's stage at the subcase's milestone, which is the milestone of the owning task's group. The layout doc does not specify them.

## Legs

Every leg is a leg string from the **Leg strings** column of layout §1.1: `job/leg`, or the bare job name for a single-leg job (`bundle-check`, `scenarios-envoy-k3s-nightly`, `migration-rehearsal`, `deployed-topology-audit`, `live-wif`). The generator reads that column and rejects:

- an unknown leg;
- a leg whose env is not one of the entry's `envs`;
- a leg whose job does not exist yet at the stage's milestone;
- an env that has no leg in any stage.

Each job's first milestone is the `JOB_FROM` table in the generator, taken from layout §1.1 and §4. A job in the column without an entry there is an error. The planned split of `live-wif` into a push leg and a negative leg is not registered yet.

**Legs are provisional.** The PR that implements a stage must confirm its legs and correct them in the same PR. The committed legs are the generator's defaults, with these trims and additions decided on review:

- A12: M2 `scenarios-pg` and `scenarios-envoy-k3s`; M3 `scenarios-envoy-k3s` and `typescript-browser`; M4 `scenarios-envoy-k3s` and `clients-rust-native`.
- A14 M5: `migration-rehearsal` only.
- A42: M4 adds `clients-rust/x86_64`, `typescript/node22` and `typescript/node24` (T51.7 fixtures); M5 adds `migration-rehearsal`.
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
| live | `live-wif` from M2 | |

## Not in this PR

- Runtime tests, fixtures (`fixtures/`), fixture schemas (`schema/`) and `waivers.toml`.
- The `check-conformance-registry` static and resolution checks, the reporter, and the CI job that runs `--check` on every event, docs-only changes included. These come in the follow-up PR.
- The `live-wif` push and negative leg split.
- `.github/CODEOWNERS` naming the lead as owner of `scenarios.toml`, `subcases.toml`, `waivers.toml` and the release manifest (layout §3 "Who approves" and §6). That is a pending follow-up and is not added here.
