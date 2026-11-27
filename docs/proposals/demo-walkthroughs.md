# Proposal: demo walk-throughs of the critical user journeys, one video per milestone

Status: Draft, plan only. Nothing here is implemented: this text changes no
code, no contract and no test, adds no crate and no dependency (the extra
dependencies of the plan itself are listed in section 2 and need the lead's
approval when it is implemented), and publishes no video. It answers a request
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
| M1a-1 | Provision an empty installation with no SQL: bootstrap the first `security_admin`, then tenant, audience, principal, trust source and grant through the operator | A48 (workload chain), A32, A64 | S3a and the trust writes (merged, library); S2a egress entry (merged) or an uploaded keyset; S3b (service identity and grants; D3 ruled by the user, 2026-11-27, relayed by the lead; to be recorded in tasks §13) and S3c (not merged); the S4 write router (only the S4a reads are merged; the IR-034 interim rule (lead decision, 2026-11-24) keeps `create_tenant` off every HTTP surface until the `secret_namespace` generator is ruled); S5 (nothing else can enrol a tenant `trust_admin`, and roles do not inherit); S6; S7 (the key algorithm set ruled by the user, 2026-11-27, relayed by the lead; to be recorded in tasks §13); S9 (the remote mTLS client) and the T13.3 workstation binary; the local-transport binding path; S10a and S10b if they are the T13.8 chain | an empty database, then each object created with a generated ID and a revision; a final read of the chain; no `psql` anywhere |
| M1a-2 | Two tenants, the same labels, crossed references | A49, A29, A43 (the write side; the exchange side is M2) | S3a and the trust writes (library); on the wire the S4 write router, S5 and S6 | identical names in two tenants get distinct IDs; a write that names the other tenant's object is denied and reveals nothing |
| M1a-3 | Several grants for one audience: the generated selector picks the actor, an override or the wrong tenant denies | A25, A50 (A45 is M2) | grant selection (library, registry API); served: S3b grant writes, S4 and S6 (selection itself is served by the M2 exchange) | the selector the server generated, the authorized choice, and the denials |
| M1a-4 | A widening write needs a second approver: the toggle, a gated keyset version and a gated trust source | A48, A04, A05 (not A37, which is the predicate row) | library level now (#114 to #118, #136, #161, the S4a reads); on the wire the S4 approve and cancel, S5, S6 and S7; not S8 | the first actor's write returns a pending operation and changes nothing; a distinct `security_admin` approves; one transaction applies it; the audit event |
| M1a-5 | Recovery: the operator signs a challenge offline, the registry verifies, a replacement credential is enrolled, a replay is refused | A32, A64 (the Linux leg) | library level now (#139, #188, #170) plus `skyoauth-operator` as a scenarios dev-dependency; through the socket C2 (#191), C3 (#192) and C4; served: the binding subcommand and S7 | the instance-bound challenge on one side, the signature produced on the workstation (the private key never shown), the restore, the same response refused a second time |
| M1a-6 | Fail closed: a missing role, a token or claim in place of a registered credential, a closed bootstrap | A22, A32, A48 (partial) | library level and the admin read router now; the roles of S4 to S7 on the wire | each denial with its typed error and the same 401 or 403 for every lever; no write left behind |
| M1a-7 | The audit trail (partial): an admin write leaves an event; the audit sink fields cannot be written online; no public key is enrolled without a sink | A48 (the M1a negative: an online write to the audit sink fields; no test is listed for it yet), A19 (the M2 negative: refusing to enrol a public key without a sink), as partial evidence; Gate M1a text, T13.3, OQ-TM-12 | the D6 forwarder (ruled by the user, 2026-11-27, relayed by the lead; to be recorded in tasks §13) and its configuration check at startup. The admin router serves only the four operation GETs (`service/src/admin_http/mod.rs`): there is no audit read, so an event is shown only through library calls | one write and its event (library level), the refused online write to the sink fields, and a sink outage raising an alert and a local record once the forwarder exists |
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
- **Not in this PR:** no workflow or CI code; the demo and release jobs are
  built after these questions are ruled.

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
