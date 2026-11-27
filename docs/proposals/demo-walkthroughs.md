# Proposal: demo walk-throughs of the critical user journeys, one video per milestone

Status: Draft; the pipeline is implemented, the journeys are not. Implemented
(`scripts/demo/`, see its README): the static player, the Playwright and
`ffmpeg` renderer with its WebVTT sidecar, the transcript format and its
check (schema, timestamps, secret shapes and the committed test-key seeds),
an invented sample transcript, the `demo-transcripts` job of `ci.yml` (in
`CI passed`), the separate `demo.yml` workflow that renders the sample into
run artifacts, and the Dependabot entry for its one npm dependency,
`playwright`. Not implemented: the journey runner and every journey of
section 1, the golden transcripts (`tests/demo/golden/` is empty), the
redaction at the source (section 2, item 2), chapter markers and one
video per milestone (designed in section 6, for the lead's review), and the
release assets of section 5. The rest of this text is the plan as
proposed. It answers a request
of the user (2026-11-27): "a demo walk-through video for the CUJs (no need to
show every permutation) of each milestone". Each choice is labelled **lead
pick** (an implementation choice open to ordinary review) or **open user
question** (listed under "Decisions requested"). State claims about the code
are as of `main` at `a6a75e5`, read against the repository for this revision
(see "Not verified": no journey, workflow or pipeline was run). Revised after
the lead's review: the Needs and status tables are corrected against tasks
§8, §9 and §13 and the scenario registry; the consistency rule, the delivery
rule and the dependencies are rewritten.

A walk-through shows one journey end to end, with a caption for every step, and
leaves out the permutations: the conformance scenarios of
[tasks §8](../skyoauth-tasks.md) stay the proof, a walk-through is a guided
tour of the same behaviour for a person who will not read the tests.

## What a walk-through is, and is not

- **Is:** a scripted, deterministic run against the service code and a private
  PostgreSQL, whose commands (or, where no command exists yet, captioned
  library calls), redacted outputs and captions are played back as a video.
- **Is not:** evidence. A conformance scenario (`tests/conformance/scenarios.toml`)
  is the only thing that gates a release; a demo that passes proves nothing the
  scenarios do not. A demo script that diverges from its scenarios is a bug in
  the demo.
- **Is not committed as video:** the video is a retained artifact of a gate
  run or a release asset (section 5), never in git (size). The scripts, the
  renderer and the small text **golden transcripts** are in git.

## 1. The critical user journeys per milestone

Each journey lists the conformance IDs it maps to (tasks §8), the slices that
must have landed (S-numbers as tasks §13 "Plan splits" and the lead's slice
plan name them; T-numbers as tasks §9 and §13 name them), and what the viewer
sees. **Lead pick**: the list is the smallest set that covers the journeys of
each milestone; it does not claim to cover each milestone's gate (Gate M1a
also names the audit sink, replay and public-key metadata, which M1a-7 and
the optional rows add only in part), and a journey that needs a later
milestone is placed in that later milestone. "Library level" means the
journey can be driven through the service and operator libraries (the
scenarios' bare registry writers, the admin read router with an
already-verified peer, the local transport codec), with captioned library
calls instead of commands, because the surface that would serve it is not
built.

### M1a: workload authority, the operator and recovery

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M1a-1 | Provision an empty installation with no SQL: bootstrap the first `security_admin`, then tenant, audience, principal, trust source and grant through the operator | A48 (workload chain), A32, A64 | S3a and the trust writes (merged, library); S2a egress entry (merged) or an uploaded keyset; S3b (service identity and grants; D3 ruled by the user, 2026-11-27, relayed by the lead; recorded in tasks §13 (#195); not yet implemented) and S3c (not merged); the S4 write router (only the S4a reads are merged; the IR-034 interim rule (lead decision, 2026-11-24) keeps `create_tenant` off every HTTP surface until the `secret_namespace` generator is ruled); S5 (nothing else can enrol a tenant `trust_admin`, and roles do not inherit); S6; S7 (the key algorithm set ruled by the user, 2026-11-27, relayed by the lead; recorded in tasks §13 (#195); the algorithm, form and key validity check is U6, in review as #198); S9 (the remote mTLS client) and the T13.3 workstation binary; the local-transport binding path; S10a and S10b if they are the T13.8 chain | an empty database, then each object created with a generated ID and a revision; a final read of the chain; no `psql` anywhere |
| M1a-2 | Two tenants, the same labels, crossed references | A49, A29, A43 (the write side; the exchange side is M2) | S3a and the trust writes (library); on the wire the S4 write router, S5 and S6 | identical names in two tenants get distinct IDs; a write that names the other tenant's object is denied and reveals nothing |
| M1a-3 | Several grants for one audience: the generated selector picks the actor, an override or the wrong tenant denies | A25, A50 (A45 is M2) | grant selection (library, registry API); served: S3b grant writes, S4 and S6 (selection itself is served by the M2 exchange) | the selector the server generated, the authorized choice, and the denials |
| M1a-4 | A widening write needs a second approver: the toggle, a gated keyset version and a gated trust source | A48, A04, A05 (not A37, which is the predicate row) | library level now (#114 to #118, #136, #161, the S4a reads); on the wire the S4 approve and cancel, S5, S6 and S7; not S8 | the first actor's write returns a pending operation and changes nothing; a distinct `security_admin` approves; one transaction applies it; the audit event |
| M1a-5 | Recovery: the operator signs a challenge offline, the registry verifies, a replacement credential is enrolled, a replay is refused | A32, A64 (the Linux leg) | library level now (#139, #188, #170) plus `skyoauth-operator` as a scenarios dev-dependency; through the socket C2 (#191), C3 (#192) and C4; served: the binding subcommand and S7 | the instance-bound challenge on one side, the signature produced on the workstation (the private key never shown), the restore, the same response refused a second time |
| M1a-6 | Fail closed: a missing role, a token or claim in place of a registered credential, a closed bootstrap | A22, A32, A48 (partial) | library level and the admin read router now; the roles of S4 to S7 on the wire | each denial with its typed error and the same 401 or 403 for every lever; no write left behind |
| M1a-7 | The audit trail (partial): an admin write leaves an event; the audit sink fields cannot be written online; no public key is enrolled without a sink | A48 (the M1a negative: an online write to the audit sink fields; no test is listed for it yet), A19 (the M2 negative: refusing to enrol a public key without a sink), as partial evidence; Gate M1a text, T13.3, OQ-TM-12 | the D6 forwarder (ruled by the user, 2026-11-27, relayed by the lead; recorded in tasks §13 (#195); not yet built) and its configuration check at startup. The admin router serves only the four operation GETs (`service/src/admin_http/mod.rs`): there is no audit read, so an event is shown only through library calls | one write and its event (library level), the refused online write to the sink fields, and a sink outage raising an alert and a local record once the forwarder exists |
| M1a-8 | Optional: the replay primitive: one single-use proof, two replicas, one issuance | A24 | the replica harness (merged, library) | two replicas, one winner, the loser refused |
| M1a-9 | Optional: `single_use` refused (A54, partial) | A54 (the M1a stage `single_use rejection`; the renewal with a reused then a rotated token is the M2 stage, T21.6, T23.1, T23.5 and T23.6, and there is no workload library in M1a) | the registry writes (library) | a reusable TokenReview source accepted, a `single_use` enrollment or import refused |
| M1a-10 | Optional: the local socket refuses another UID | T13.4 (the root-only local transport tests, #178) | the local transport (merged, library); it needs root and a second local user, so it runs in the root step of `service-nextest` (profile `ci-root`), not in `scenarios-pg` | a second UID refused at the socket; the service UID served |

### M1b: human authority and state

Before any M1b slice starts, the lead decides OQ-GW-15 and the schema gains
`RouteBundle.kind` (Gate M1b, tasks §9). The human tables do not exist yet, and
no M1b test exists.

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M1b-1 | Initial human provider through a staged plan: dry run, approval, guarded commit | A47, A48 (human chain) | the human registry and the provider transition (T13.9, M1b) | the plan text, the diff, the approval, the one commit that advances the pointer and the epochs |
| M1b-2 | A generic write to the active provider is refused atomically | A47 | as above | PATCH, import and reload each rejected; epochs unchanged |
| M1b-3 | Two origins, two tenants, two providers | A46 (resolution only; the redirect is M3) | versioned origins (T14.7, M1b) | each registered origin resolves its own provider and tenant; a spoofed Host or forwarded header denies |
| M1b-4 | Route bundle approval | A58 (the registry-only part) | route bundles and the controller identity (T14.9, M1b) | a prepared bundle, the exact mode-bound approval, a stale approval denied |

### M2: usable WIF and the bearer gateway

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M2-1 | A GitHub Actions push gets a scoped token | A01, A02, A30 | T20, T21, T22 with the mock GitHub issuer (planned, layout §1.2) or `envoy_k3s`; real GitHub only in the live push-to-main leg | a simulated push proof (captioned "simulated"), the token's audience and scope, the PR, dispatch and wrong-ref contexts denied |
| M2-2 | A k3s workload gets a scoped token through TokenReview | A06, A07, A28 | T20, T21, T23 with the mock TokenReview (planned) or `envoy_k3s` | the service-account proof (simulated), the token for the selected tenant and cluster, a wrong cluster denied |
| M2-3 | The same token through Envoy to a backend; spoofed and direct paths denied | A36, A13 | T20 to T23, T25, T26, the test-only reference backend, `envoy_k3s` | the positive bearer path, then the spoof, the outage and the direct-backend attacks |
| M2-4 | Issuer key rotation without a client change | A19, A04 | T20, T24 | the overlap window, the same client config before and after |
| M2-5 | Disable a grant with a token outstanding | A21, A23 | T20, T21, T26 | no new issuance, the residual TTL stated, a live check denying where one is committed |

### M3: browser sessions and the TypeScript SPA

M3 has no transcript source: the SPA is recorded with Playwright (section 2).

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M3-1 | Sign in to the SPA and call a backend through the browser gateway | A08, A46, A51 | T30 to T33 | the redirect, the callback bound to the browser flow, the cookie never readable by script, the backend call with typed human-session evidence |
| M3-2 | Unsafe calls without the right Origin or CSRF header, mixed credentials | A09, A10, A40 | T32, T33 | each denial before any credential is forwarded |
| M3-3 | An attacker-initiated callback in a victim's browser | A51 | T30 | no victim session created, replaced or linked |
| M3-4 | A session ends: idle, absolute, revoked, store unavailable | A11, A33 | T31 | 401 or 503 as specified, never fail-open |
| M3-5 | The human IdP is down; workloads and the operator still work | A20 | T30, M2 | the fresh login fails closed, a WIF exchange and an operator recovery succeed |
| M3-6 | A long stream outlives its credential and reconnects | A12, A56 | T32 | the close at the lease, the reconnect with a fresh credential, no restarted mutation |
| M3-7 | First login policy: default denies, opt-in creates one zero-privilege principal (moved from M1b: A60 has no M1b stage) | A60 (the M3 browser stage) | T30.4, T30.8, and the enrolment and client policy of M1b | the default denial, the opt-in write, the single principal that results |
| M3-8 | Cookie containment: no Cookie or CSRF header reaches a backend, no Set-Cookie leaves one | A18 (the M3 stage) | T25.4, T32.3, T32.4, `envoy_k3s` raw capture | the capture at a billing, a public and a no-Check backend; the fixed SkyOAuth cookie flows still working |

### M4: native OAuth and the reusable Rust CLI

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M4-1 | Native login with an explicit confirmation | A27, A52, A59 | T40 | the CLI showing a port and a code, the page asking for the matching acknowledgement, the token |
| M4-2 | A malicious concurrent native request | A59, A27 | T40 | the legitimate CLI unaffected; no silent replacement |
| M4-3 | Refresh rotation, a replay revokes, the opt-in exact retry | A34, A57 | T40 | the rotated successor, the replay and the revoked family, the retry inside 30 s returning one successor |
| M4-4 | The CLI on Linux, macOS and Windows, with no server dependency | A41 | T40; `native-3os` (one transcript per OS) | the same run on three systems, no plaintext keychain fallback |
| M4-5 | A human CLI token accepted by a backend, a forged one refused | A44, A55 | T40, T41 | the explicit human profile accepted, a WIF token in a human shape denied |

### M5: deployment, migration and v0.1

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M5-1 | A provider switch with unchanged artifacts | A14, A42 | T51 | the same SPA and CLI artifact hashes and endpoints before and after, human re-authentication only |
| M5-2 | Migration keeps IDs, modes and revisions | A15, A16 | T51 | the before and after of the preserved objects, dormant impersonation still disabled |
| M5-3 | A rollback after an independent change | A17, A35 | T51, T21.8 | the independent policy change untouched, no resurrected state, consumed proofs still consumed |
| M5-4 | Signer compromise and standby promotion | A62 (the M3 and M5 stages), A19 | T32.14, T50.3, T52.5 | the audited promotion, the denial of unpromoted-standby evidence |
| M5-5 | Rotate a provider secret versus change the issuer | A63 (the M1b, M3 and M4 stages) | T13.9, T30.9, T52.5 | the credential-only revision keeping sessions, the semantic change needing the guarded transition |

## 2. The mechanism

**Lead pick**, in four parts, each replaceable without the others.

1. **A journey runner** drives the service and a private PostgreSQL with the
   conventions of the existing scenarios crate and harness (an environment
   variable for the database, per-test databases from the template-database
   isolation, the deterministic ID generator under `test-support`, the
   cross-UID conventions of the root step where a journey needs them). Each
   journey is a script of steps; a step is a command or a library call, a
   caption, and what to show. It emits a **typed transcript** as JSON lines:
   `caption`, `command`, `output`, `note`, with a monotonic step index and no
   wall-clock time. M1a journeys run through libraries today; a journey moves
   to commands against a served binary as the surfaces of section 3 land.
2. **Redaction at the source.** The runner redacts before it writes: private
   keys never reach the transcript (the operator signs in its own process and
   the transcript shows the public result), **signatures** are not shown
   either (a captured recovery response can restore an operator against an
   old database backup, the residual of TM-15), tokens and cookies are shown
   as their type, audience and scope with the value replaced, generated IDs
   are kept (they are opaque) but are stable only with the deterministic
   generator. A redaction test fails the run when a known secret pattern, or
   any value taken from a secret-holding variable, appears in a transcript.
3. **A player** is a small static HTML page (no framework, no network) that
   plays a transcript as a terminal: typed commands, output, caption bar. A
   browser journey (M3) is recorded directly with Playwright against the real
   SPA instead, with the same caption bar overlaid; it has no transcript, so
   the rules that name a transcript (section 5) need a different rule there,
   and so does frame redaction (open to the lead).
4. **Rendering.** Playwright records the player (`recordVideo`) and `ffmpeg`
   transcodes it to mp4, with the captions burnt in by the page, not by `ffmpeg`
   (no font handling in the pipeline), plus a WebVTT sidecar. No `asciinema` or
   `vhs` is needed. Recording is real time: about five minutes per milestone
   plus setup.

**Determinism and its hazards.** Fixed seeds, the deterministic ID generator,
a fixed terminal size, a fixed typing speed derived from the step index, and
no wall-clock value in the transcript. "Test clock" means each test's own
fixed clock (`FixedClock` in the harness and the wire fixture); the
injected-clock builder of layout §1.2 is only planned. Two runs of a journey
must give byte-identical transcripts, which the golden comparison below
checks; the video is only as stable as the encoder, so the transcript, not the
mp4, is what is compared. The hazards to name before any journey is written:

- CI installs the unpinned `stable` toolchain (no `rust-toolchain` file), so a
  transcript holds only fields the project formats itself, never a `Debug` or
  `Display` of a std or third-party type.
- Several tables have `created_at ... DEFAULT now()` columns (migrations 0001,
  0002 and 0005): those columns never appear in a transcript.
- The PostgreSQL image digest pin must be the same in any release or demo job
  as in `rust-coverage`, `service-nextest` and `scenarios-pg`. The pin check
  step reads `ci.yml` only, so a job in another workflow file is not covered
  by it.
- nextest runs tests in parallel processes: one transcript file per journey,
  joined in a fixed order by the render script, never one shared file.
- Journeys that are not deterministic by nature: real GitHub tokens (M2, so
  those journeys are simulated by default); a tag-triggered run, which is not
  the push-to-main run the live push leg needs (layout §4 and open question
  7b: whether its test-only binding accepts another ref is unresolved); the
  M3 Playwright recordings (no transcript); and M4-4, which has one
  transcript per operating system.

**Where it lives.** **Lead pick**: the journeys are harness modules of the
existing `pg` target of `skyoauth-scenarios` (layout §1.2 allows up to four
targets, so no `demo` target is added), in a new layer directory declared with
`#[path]` like the existing ones. They always run in the `scenarios-pg` job
(except a journey that needs root, below) and compare their transcript with the committed **golden transcript**; when
`SKYOAUTH_DEMO_OUT` names a directory they also write the transcript there. **Required-check effect:** `scenarios-pg` is in `ci-passed`, so a golden-transcript
mismatch blocks a merge. That is intended (a changed transcript is a reviewed
change); it does not block a release. M1a-10 needs root and a second user, which
`scenarios-pg` does not have: it runs in the root step of `service-nextest`
(profile `ci-root`, which a separate root-step CI PR extends), not in
`scenarios-pg`. A later PR must also amend `docs/testing/conformance-layout.md`
§1.2 for the new directory and modules. A
`SKYOAUTH_DEMO_OUT`-gated silent skip is ruled out: the targets "never pass
vacuously" (layout §1.2). Test names must not match `a\d\d_` (the "no
orphans" rule of the registry check would otherwise demand that a stage claim
them), and the runner must not live in `tests/src`: that library compiles
against the service with `test-support` on, and
`service/tests/ungated_writes_private.rs` keeps `test-support` out of the
workspace's libraries. The golden transcripts are committed text (small,
reviewable diffs); a changed transcript is a reviewed change. The player and
the render script are under `scripts/demo/` (Node, as `scripts/ci/`). Not
committed: the mp4 files.

**Extra dependencies (need the lead's approval at implementation time).** The
statement "no new crate" holds only for this PR. Implementing the plan needs:

- `skyoauth-operator` as a dev-dependency of `skyoauth-scenarios` (it has none
  today, and the operator crate does not depend on the service, so the
  direction is allowed);
- npm `playwright` in a new `scripts/demo/package.json` and lockfile, with a
  new Dependabot entry for it (`.github/dependabot.yml` has none for it);
- a browser and `ffmpeg` on the runner.

## 3. What is demoable now

"Nothing end to end" is true only for **served** surfaces: the service binary
does health and `migrate` and nothing else, the admin router is served nowhere
until S6 (tasks §13, D5), and there is no operator binary. At library level
several M1a journeys run today in the scenarios, as follows (a stage marked
`planned` lists partial tests that count for nothing in the report).

| Journey | Library level today | Served or on the wire | Unblocked by |
| --- | --- | --- | --- |
| M1a-1 | pieces only: the audited workload writes and the egress writer | none | S3b, S3c, S4 writes, S5, S6, S7, S9 and the workstation binary, the binding path |
| M1a-2 | write side: A29 (implemented), A49 and A43 (partial), the `a49_wire` reads | the admin read router with an already-verified peer | S4 writes, S5, S6 |
| M1a-3 | A25 and A50 (implemented) | none | S3b grant writes, S4, S6 |
| M1a-4 | A48, A04, A05 (partial tests) | the S4a reads only | S4 approve and cancel, S5, S6, S7 |
| M1a-5 | A32 (partial tests), the operator signer, the local transport codec and library | none | C2, C3, C4, the binding subcommand, S7 |
| M1a-6 (partial) | A22 (and `a22_wire`), A32 and A48 negatives | the admin read router with a verified peer | S4 to S7 |
| M1a-7 (partial) | audit events written at library level (A29, A32); no audit read exists | no sink; the router serves only the four operation GETs | the D6 forwarder, an audit read |
| M1a-8 | A24 (implemented) | none | none beyond the journey script |
| M1a-9 | A54 `single_use` rejection (partial) | none | none beyond the journey script (renewal is M2) |
| M1a-10 | the root-only local transport tests (#178) | none | the root-step CI PR that extends the root run |

| Milestone | Today | Unblocked by |
| --- | --- | --- |
| M1b | No human tables and no M1b test (the earlier "registry state tests only" was wrong) | OQ-GW-15, `RouteBundle.kind`, the M1b slices |
| M2 | None | T20 to T26 |
| M3 | None | T30 to T33 |
| M4 | None | T40, T41 |
| M5 | None | T50 to T52 |

**Order to build**: the runner, redaction check and player first (they need no
milestone), then M1a-5 and M1a-3 at library level, M1a-4, M1a-2 and M1a-6, and
each journey's served form as its slices land, then the other milestones'
journeys as the slices of their column land. The runner and the player are
built once, against M1a-5.

## 4. Who owns what

- **Test session:** the runner, the transcript format, the golden transcripts,
  the redaction check, the player, the render script, the workflows, the
  journey scripts and their captions, and the determinism check.
- **Coding session:** the command layer a journey needs. T13.3 already
  requires a portable workstation operator binary in M1a, so this is not an
  unscheduled gap: **the open question is which slice delivers it** (the lead
  will ask coding). Until it exists the M1a video shows captioned library
  calls, which is the choice that most changes what the video looks like.
- **Lead:** the review of this proposal, the journey lists, the approval of the
  extra dependencies and of the workflows.

## 5. The videos: gate artifacts and release assets

The user asked (2026-11-27) that the videos be part of the release artifacts
(Decision 3). **Lead pick** for the details; the instruction is the user's.

- **Two deliveries.** (a) For a gate that is not a tag, the videos are a
  retained artifact of the gate run (`retention-days` set): gates are commits on
  `main` listed in `gates_passed`, not tags, and the first tagged release is
  the first beta (OQ-ADR024-1 is open). (b) On a tagged release they are
  release assets.
- **Retention.** `retention-days` is capped at 90 days on public repositories (unverified), so gate artifacts may expire before the first beta; hence the golden transcripts are also kept in git.
- **What is published:** one mp4 per milestone that the release contains (a
  release without M3 has no M3 video), the committed golden transcripts they
  were rendered from (for M3, whatever rule replaces them), and a SHA-256
  checksum file over the mp4 files and the transcripts. They are not files in
  git. GitHub's limit for a release asset (2 GiB each) is no constraint at the
  expected size. The repository is public, so release assets are
  world-downloadable: the redaction rule below applies to every video.
- **The asset list is separate from the conformance release manifest.** That
  manifest is T50's committed list of shipped conditional features (layout §6,
  item 6); the demo asset list is a different file, owned by the demo job.
- **How they are built:** the demo job re-runs the journeys at the commit (the
  gate commit, or the tagged commit), the harness modules compare each
  transcript with its golden file, and the job renders from the goldens. The
  release job re-runs and compares against the goldens at the tag.
- **A difference fails the demo job loudly but does not block a release.**
  Only conformance gates a release. A transcript or demo failure makes the demo
  job red and visible, publishes no video for that milestone, and leaves the
  release otherwise unaffected.
- **Redaction still applies:** no key, signature or credential bytes in a
  transcript, a caption or a video frame, with the same redaction check, which
  runs on every run.
- **Open questions of the release job** (not 7a to 7d, which are about the gate
  job of layout §6):
  - the trigger: `release: published` or a tag push;
  - `contents: write`: today only the badge job has it, so the release job
    needs its own permission block;
  - draft-release handling if immutable releases are on (unverified: the
    repository setting was not read);
  - whether the runner image carries Chrome and `ffmpeg`, or the job installs
    them (unverified).
- **Not built yet:** the release job and release assets, which wait for
  these questions. Built: the pipeline only, without journeys (the status
  line above): `demo.yml` renders the sample transcript into run artifacts
  (`demo-videos-N`, 7 days on a pull request, 90 otherwise; the raw
  recordings of a failed render, `demo-raw-recordings-N`, 3 days) and is not in
  `CI passed`; the `demo-transcripts` job of `ci.yml` checks the committed
  transcripts and is.

## 6. Chapters and one video per milestone (design, not built)

**Lead pick** (the lead's design; written down here for the lead's review
before any code). Not built: the record type, the manifest, the join, the
chapter tracks and the merged checksums below are a specification for the
implementation PRs at the end of this section. The checks of
`scripts/demo/transcript.mjs` stay as they are; this section adds to them.

**6.1 The `chapter` record.** A fifth record type:
`{"step":N,"type":"chapter","text":S}`, in the same canonical form as the
others. Rules, on top of every existing rule:

- `text` is one line of 1 to 80 code points and starts with the journey id
  and a colon (`M1a-2: Recover the operator`); no `allow` field;
- `check` accepts at most one chapter record per file, and only as step 0;
  `check-milestone` (6.3) requires it in every journey file. The sample holds
  none (a test pins that);
- it is transcript text: the character, timestamp and secret rules, and the
  `--secret-file` and `--secret-env` values, apply to it as to a caption. Its
  text is the only source of a chapter title (the WebVTT chapter cue and the
  mp4 chapter both come from the checked record, never from the manifest or
  a file name).

The player shows a chapter as a title card: it clears the terminal, shows the
title, and clears the caption bar, for a duration derived from its title by
the caption timing rule, floored at 1200 ms and capped at 3000 ms (6.9). It is not a caption, so it is not in the captions VTT.

**6.2 Layout and manifest.**

```text
tests/demo/golden/<milestone>/milestone.json   order of the journeys (committed by hand)
tests/demo/golden/<milestone>/<journey>.jsonl  one golden transcript per journey (written by the runner)
```

`<milestone>` is the lower-case milestone id (`m1a`), `<journey>` the
lower-case journey id (`m1a-2`). `milestone.json` holds exactly
`{"milestone":"M1a","journeys":["M1a-1","M1a-2",...]}`: no other key, each
id once, matching `^M[1-5][ab]?-[1-9][0-9]*$`, prefixed by the milestone id.
The array order is the video's order. The manifest is a reviewed file owned
by whoever owns the journey list of section 1 (the lead), not by the runner.
Every listed id has its file in the same directory, and every `.jsonl` there
is listed: a missing or an unlisted file is an error.

**6.3 Join and renumbering.** The **joined stream** of a milestone is its
journey files in manifest order, each record re-serialized canonically with
`step` = (records in the earlier journeys) + (its step in its file): a
monotonic step from 0 with no gap, a chapter record at the first step of each
journey. It is derived, never committed. `transcript.mjs` gets a
`check-milestone <dir>...` command that checks:

1. the manifest (6.2);
2. each journey file alone, with every rule (as `check` does today);
3. the joined stream through `validateTranscript`, so the pair windows cross
   journey boundaries (last record of one journey with the chapter of the
   next, and that chapter with the next journey's first record). Because a
   chapter breaks the runs of `output` and `note` records, the joined stream
   is also checked once with its chapter records removed, so a value split
   over the last record of one journey and the first of the next is found.

An error of the joined stream is reported at a file and line, never at a
joined line: `m1a-2.jsonl:1: JWT-shaped string across the records on
m1a-1.jsonl:14 - m1a-2.jsonl:1 (texts joined)`. An error already reported
for a file alone is not repeated. Allow markers carry over unchanged.

**6.4 Timing.** The milestone video plays the joined stream, so every time
comes from `timing.buildTimeline(joined records)`. The typing delays depend
on the step index, so a journey types differently when it is played inside
its milestone than when it is played alone; only the joined form is ever
rendered. Chapter *k* starts at the `startMs` of its chapter record and ends
where chapter *k+1* starts; the last ends at `totalMs`. The chapters are
written as a WebVTT chapters file (`kind="chapters"`), one cue per journey,
contiguous and covering 0 to `totalMs`:

```text
WEBVTT

chapter-1
00:00:00.000 --> 00:01:12.340
M1a-1: Bootstrap the operator
```

Cue ids are `chapter-<n>` (1-based, manifest order). The text is escaped
with `escapeCueText`, as captions are. The captions VTT keeps its format, with
`step-<joined step>` ids.

**6.5 Outputs.** `render.mjs --milestone <dir>... --out <dir>` writes, per
milestone `<m>`: `<m>.mp4`, `<m>.vtt` (captions), `<m>.chapters.vtt`,
`<m>.transcript.jsonl` (the joined stream as rendered) and
`<m>.milestone.json` (a byte copy of the manifest). The mp4 carries the same
chapters as mp4 metadata, from an ffmpeg `FFMETADATA1` file of `[CHAPTER]`
blocks (`TIMEBASE=1/1000`, `START`, `END`, `title`) mapped with
`-map_chapters`. Checked locally with ffmpeg 6.1.1 on a test clip:
`ffprobe -show_chapters` lists the titles and times, `moov` stays before
`mdat`, and two encodes with the existing bitexact flags are byte-identical.
The mp4 gains a second stream (a QuickTime chapter text track) beside a Nero
`chpl` box, so the e2e test's "one stream" check becomes "one video stream,
no audio, one chapter track".

One `SHA256SUMS` lists every file of the output directory, for all
milestones rendered into it, merged and never overwritten. Before rendering a
milestone, the script reads `SHA256SUMS` (strict format `<64 hex>  <name>`,
sorted by name; any other content is an error), and fails, writing nothing,
when the directory is inconsistent (a listed file that is missing, a file that
is not listed) or when any of its output names already exists. After
rendering, it writes the new files, then rewrites `SHA256SUMS` with the union,
sorted (temporary file, then rename). Re-rendering a milestone into a
directory that has it is therefore an error, never a silent replacement. The
single-transcript mode (`render.mjs <file>`) moves to the same merge.

**6.6 Determinism.** Unchanged rule: the transcripts are compared, never the
mp4. Compared byte for byte between two runs: each journey file (the harness
against its golden), and the derived joined stream, captions VTT, chapters
VTT and their `SHA256SUMS` lines. The mp4's chapters (`ffprobe -show_chapters`)
must equal the chapters VTT to the millisecond.

**6.7 CI.**

- `demo-transcripts` (`ci.yml`, in `CI passed`): the golden step runs `check`
  over every `.jsonl` under `tests/demo` (each file alone, as today) and
  `check-milestone` over every `tests/demo/golden/*/` directory, both with the
  test keys. A `.jsonl` under `tests/demo/golden/` that is not in a milestone
  directory with a manifest is an error.
- `demo.yml` (not in `CI passed`): renders the sample and every milestone
  directory into `$RUNNER_TEMP/demo`, then `sha256sum --strict -c`. One
  `demo-videos-N` artifact holds all of them, flat, with the one
  `SHA256SUMS`; retention as today (7 days on a pull request, 90 otherwise).
  `timeout-minutes` grows with the milestones (real-time recording, about
  five minutes each). Raw recordings as today.

**6.8 Failure modes and the tests of the implementation PRs.** Each with a
test, and a mutant the test kills:

- the record: a chapter that is not step 0, a second chapter, a chapter in
  the sample, a multi-line or over-long or id-less title, `allow` on a
  chapter, a secret, timestamp or `--secret-file` seed in a title;
- the manifest: an unknown key, a duplicate or malformed id, an id of another
  milestone, a listed file that is missing, an unlisted `.jsonl`;
- the join: renumbering (steps 0..n-1 across journeys), a value split over a
  journey boundary (with and without the chapter between), errors mapped back
  to file and line, no repeated error;
- timing: the chapter cues equal the chapter records' `startMs`, contiguous,
  ending at `totalMs`; the player's title card in the VM test (6.1);
- outputs: the mp4 chapters equal the chapters VTT (e2e); `SHA256SUMS`
  merges two milestones rendered one after the other, refuses a re-render, a
  missing or unlisted file and a malformed line, and is never left half
  written;
- CI: the wiring test (`workflows.test.mjs`) pins the `check-milestone` step
  and the demo.yml milestone render.

**6.9 Decisions on the open questions** (the lead's picks, not user rulings).

1. When one milestone fails to render, every milestone is still rendered and
   what rendered is uploaded; the step fails at the end and lists the
   failures.
2. A title card is shown at each chapter start, kept short.
3. Its duration is derived from the title like a caption (the caption timing
   rule), with a floor of 1200 ms and a ceiling of 3000 ms; it is not the
   fixed duration the first draft proposed.
4. A milestone video opens with one caption naming the milestone and the short
   commit SHA. The renderer injects it at render time from the environment
   (`GITHUB_SHA`); it is NOT written in a golden transcript (it would change on
   every commit). It passes the same secret rules as any caption.
5. M3 (browser recordings, no transcript) is deferred: nothing is built for it
   now. It is expected to get its chapters from a small `chapters.json` beside
   its recordings (a title and a page-clock offset); the format is decided when
   M3 is scheduled.

**6.10 Implementation breakdown.** Four PRs, each with its tests:

1. `transcript.mjs`: the `chapter` type, the manifest, `check-milestone`, the
   join and the error mapping.
2. `timing.js`, `player.html`, `vtt.mjs`: the chapter-card duration rule, the title
   card, the chapters VTT and the injected opening caption.
3. `render.mjs`: `--milestone`, the ffmpeg chapter metadata, the merged
   `SHA256SUMS`, the e2e test.
4. CI: the `ci.yml` golden step, the `demo.yml` milestone render and timeout,
   the wiring tests, and the docs. The journeys and their golden files remain
   separate PRs, as in section 2.

## Decisions requested

Open user questions:

1. Captions and voice-over: captions only, or also a voice-over (and in which
   language)? **Lead pick:** captions only, no audio, in English, burnt in with
   a WebVTT sidecar, so that a video can be regenerated from a transcript.
2. Length: one video per milestone of about five minutes, or one per journey?
   **Lead pick:** one per milestone, with chapter markers per journey.
3. Where the videos are published: the user's instruction (2026-11-27) is
   "include the videos as part of the release artifacts". **Lead picks** for
   how: on each tagged release, a milestone-by-milestone selection of the
   milestones the release contains, the transcripts and the checksums beside
   the videos, and GitHub release assets as the place. The retained-artifact
   delivery of the non-tagged gates is also a lead pick. An external host
   stays open only if the user wants a second copy.
4. Simulated or real GitHub, k3s and IdP: **default** simulated, captioned
   "simulated", using the layout §1.2 mocks; real GitHub only in the live
   push-to-main leg.
5. Player style: **default** terminal player at 1280x720.

Open to the lead (defaults given):

6. Which slice delivers the portable operator binary of T13.3 (section 4), and
   whether M1a may show library calls before it exists: **default** yes,
   captioned.
7. Whether a demo failure blocks a release: **default** no, it fails loudly
   (section 5).
8. The extra dependencies of section 2 (approval at implementation time) and
   the rule for the M3 recordings that have no transcript.
9. The release job's open questions (section 5).

Cost: recording is real time, about five minutes per milestone plus setup.

## Not verified

- No journey was run, and no part of the mechanism was built: the availability
  of Playwright, a browser and `ffmpeg` on the runner is not checked (the
  CI runner image was not read), and the repository's immutable-release
  setting was not read.
- Checked against the repository for this revision: tasks §8 (A-IDs and their
  expected results), §9 and §13 (slice splits, D5 "served nowhere between S4
  and S6"), the stage tables and test lists of `tests/conformance/scenarios.toml`,
  `docs/testing/conformance-layout.md` §1.2 (up to four targets, "never pass
  vacuously", the orphans rule `(^|::)a\d\d_`), `service/src/main.rs` (serve
  and `migrate` only), `operator/` (a library, no binary), the PR numbers
  #114 to #118, #136, #139, #161, #170 and #188 in `git log`, and `ci.yml`
  (unpinned `stable`, the PostgreSQL pin check, `contents: write` only on the
  badge job).
- Recorded: D6 and the key algorithm set (S7) are recorded in tasks §13 (#195); D3 is the widening rule there. Not yet in the repository: the `secret_namespace` generator ruling (the IR-034 interim rule itself is in the repository, `service/src/admin/mod.rs`, lead decision 2026-11-24). Also not found: the slice names S3b to S10b beyond the splits tasks §13 states, and the slices C2 (#191), C3 (#192) and C4. This text depends on these being recorded in tasks §13.
- The 90-day cap of `retention-days` on public repositories is from memory, not read.
- Whether each journey needs exactly the slices listed was not checked slice
  by slice beyond the above.
- The "demoable now" tables list what the repository has at `a6a75e5` as read;
  no test was rerun.
