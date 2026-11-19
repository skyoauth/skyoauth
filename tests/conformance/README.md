# Conformance registry

This directory holds the conformance scenario registry proposed in [the conformance layout](../../docs/testing/conformance-layout.md) §3. It contains **data only**. There are no runtime tests, fixtures, schemas or waivers here yet. Nothing here is wired into CI: the `check-conformance-registry` check and its `conformance-registry` CI job land in the follow-up PR (layout §3 and the M0 row of §4).

| File | What it holds |
| --- | --- |
| `scenarios.toml` | `gates_passed`, the 64 scenarios A01–A64 (`kind = "scenario"`) and the 10 contracts C01–C10 (`kind = "contract"`). Every scenario stage is `planned` with `tests = []`. |
| `subcases.toml` | The sub-IDs that the layout doc already names (`kind = "subcase"`, with `parent` and `conditional_on`). |
| [`scripts/ci/gen-conformance-registry.mjs`](../../scripts/ci/gen-conformance-registry.mjs) | Generates both files from the specs and checks them with `--check`. Node 20 or later, no dependencies. |
| [`scripts/ci/gen-conformance-registry.test.mjs`](../../scripts/ci/gen-conformance-registry.test.mjs) | Self-test of the generator (`node:test`). |

## Generate and check

```sh
node scripts/ci/gen-conformance-registry.mjs           # rewrite both files from the specs
node scripts/ci/gen-conformance-registry.mjs --check   # exit 1 if either file differs from regenerated output
node --test scripts/ci/gen-conformance-registry.test.mjs
```

The generator is deterministic and idempotent: a second run changes nothing. `--check` names each differing entry and field, for example `A24: matrix_sha256 is …, but its spec line hashes to …` after the tasks §8 A24 row is edited. It also renders the layout §2 scenario table back from the registry and fails if any rendered row differs from the committed one. The registry can therefore always reproduce the table. Spec errors (a missing, duplicate or out-of-order row; an unknown owner, layer, env or leg; a contract with no mapping) exit 1 and write nothing.

Today the layout §2 table is the source and the registry is derived from it. Layout §2 says that once this file lands the direction flips: the registry becomes the single source and the check renders the table from it. That switch belongs to the follow-up PR.

## Where each field comes from

Fields are either **derived**, which means the generator rewrites them on every run, or **hand-authored**, which means the generator keeps the committed value.

| Entry group | Field | Source |
| --- | --- | --- |
| Scenarios A01–A64 | `id`, `matrix_sha256` | Row `\| Axx \| … \|` of tasks §8 ([docs/skyoauth-tasks.md](../../docs/skyoauth-tasks.md)), one entry per row in row order |
| | `layers`, `envs`, `env_notes`, `harness`, `owners`, `positive`, `negative`, `pos_neg_prefix`, `pos_neg_suffix`, and each stage's `milestone` and `scope` | Row `\| Axx \| … \|` of the layout §2 scenario map ([docs/testing/conformance-layout.md](../../docs/testing/conformance-layout.md)) |
| | stage `legs`, `status`, `tests` | Hand-authored. A stage that has no committed legs gets the generator's default legs (below). |
| Contracts C01–C10 | `id`, `matrix_sha256` | Row `\| Cnn \| … \|` of design §2 ([docs/skyoauth-design.md](../../docs/skyoauth-design.md)) |
| | `covered_by` | Row `\| Cnn … \|` of the "Covered by" table in layout §5, decision Q11, in table order |
| Subcases | `matrix_sha256` | The task line of the subcase's first owner (below) |
| | every other field | Hand-authored, drafted from the layout text and task line listed below |
| File | `gates_passed` | Hand-authored |
| File | comments | Generated; hand-written comments are dropped |

### Layout §2 columns

| Column | Registry field | Rule |
| --- | --- | --- |
| ID | `id` | |
| Layer | `layers` | `C`, `S`, `I`, `P` → `conformance`, `security`, `integration`, `package`, kept in the order the cell joins them with `+` |
| Env | `envs`, `env_notes` | `H`, `PG`, `EK`, `BR`, `N3`, `LV` → `hermetic`, `pg`, `envoy-k3s`, `browser`, `native-3os`, `live`. A parenthesised qualifier is kept in `env_notes`, keyed by env. Today that is only A14, `N3 (Linux leg)`. |
| Harness | `harness` | The cell is split on `, ` outside parentheses and backticks. A01 and A02 also use `; ` inside the cell. That text stays inside one item (`"PG; GH‑live"`) so the row still renders. |
| Stages | `[[scenario.stage]]` `milestone`, `scope` | The cell is split on ` · `, and each part is `Mx: scope`. A one-stage cell holds only `Mx`, and its scope is the fixed text `full row`, as in the layout §3 A64 example. |
| Owners | `owners` | The cell is split on `, `. Each owner must be a `**Txx.y**` task in tasks.md. |
| + / − required | `pos_neg_prefix`, `positive`, `negative`, `pos_neg_suffix` | The cell is `prefix + "+ " + positive + "; − " + negative + suffix`. The prefix is text before the `+ `, as in A58 and A62. The suffix is a trailing `. Conditional sub-ID …` sentence, as in A18, A27, A33 and A58. Both keys are left out when they are empty. |

### Hash rule

`matrix_sha256` is the SHA-256 of the UTF-8 bytes of the entry's whole source line, from its first to its last character, with no trailing newline (layout §3). For a scenario the source line is its tasks §8 table line, and for a contract it is its design §2 table line. Both run from the leading `|` to the trailing `|`. Layout §3 says a sub-ID hashes "the task text it was drafted from". Here that is the whole `- [ ] **Txx.y** …` bullet line in tasks.md of the subcase's first owner, which is the optional task the layout doc names for it. Each subcase carries a generated comment that quotes the line. To recompute one by hand:

```sh
grep -m1 '^| A24 |' docs/skyoauth-tasks.md | tr -d '\n' | sha256sum
grep -m1 -F -- '- [ ] **T40.6** ' docs/skyoauth-tasks.md | tr -d '\n' | sha256sum
```

An edited spec line changes its hash, so `--check` fails until the generator is re-run. The reviewer then confirms that the entry still matches the row.

### Subcases

| ID | Parent | `conditional_on` | Layout text | Hash source (tasks.md line) |
| --- | --- | --- | --- | --- |
| A18.01 | A18 | `forwardauth` | §2 A18 row; §6 answered follow-up 6 ("credential containment and trusted forwarded chain") | T32.9 |
| A27.01 | A27 | `device-flow` | §2 A27 row ("Conditional sub-ID A27.01 (device flow, T40.6)") | T40.6 |
| A33.01 | A33 | `back-channel-logout` | §2 A33 row; §5 Q3 | T30.6 |
| A58.01 | A58 | `forwardauth` | §2 A58 row; §6 answered follow-up 6 ("deployment-enforcer equivalence") | T32.9 |

The required A58 sub-IDs that layout §5 Q1 assigns to the T32.3 owner are not drafted yet, so they are not here. The layout doc gives no number for either ForwardAuth sub-ID, so `A18.01` and `A58.01` are provisional numbers. A subcase's `layers`, `envs`, `harness` and stage `legs` copy its parent's stage at the subcase's milestone, which is the milestone of the owning task's group. The layout doc does not specify them.

## Legs

Every leg is a job and leg from layout §1.1, written `job/leg`. A job that §1.1 lists without legs (`live-wif`, `bundle-check`, `migration-rehearsal`, `scenarios-envoy-k3s-nightly`) has one leg, written as the bare job name. The generator rejects an unknown leg, a leg whose job serves none of the entry's `envs`, and a leg whose job does not exist yet at the stage's milestone. It also rejects an env that has no leg in any stage.

The default legs, used only when a stage has none committed, are computed per env of the row from the jobs of that env that exist at the stage's milestone. Each job's first milestone comes from layout §1.1 and §4.

| Env | Default job (legs) | Exceptions |
| --- | --- | --- |
| hermetic | `scenarios-hermetic` (x86_64, aarch64) | A39: `typescript` (node22, node24) and `bundle-check`. A40: `typescript`. |
| pg | `scenarios-pg` (x86_64) | |
| envoy-k3s | `scenarios-envoy-k3s` (x86_64) from M2 | M5 stages: `migration-rehearsal`. A54 adds `scenarios-envoy-k3s-nightly`. |
| browser | `typescript-browser` (chromium, firefox, webkit) from M3 | |
| native-3os | `clients-rust-native` (ubuntu, macos, windows) from M4 | Rows whose harness has `OP`: `operator` from M1a. A64: `operator` and `recovery-offline` (§5 Q6). `N3 (Linux leg)`: ubuntu only. |
| live | `live-wif` from M2 | |

These legs are a starting point for each scenario owner to review. They are not part of the specs.

## Not in this PR

- Runtime tests, fixtures (`fixtures/`), fixture schemas (`schema/`) and `waivers.toml`.
- The `check-conformance-registry` static and resolution checks, the reporter, and the CI job that runs `--check` on every event, docs-only changes included. These come in the follow-up PR.
- `.github/CODEOWNERS` naming the lead as owner of `scenarios.toml`, `subcases.toml`, `waivers.toml` and the release manifest (layout §3 "Who approves" and §6). That is a pending follow-up and is not added here.
