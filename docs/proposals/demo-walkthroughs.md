# Proposal: demo walk-throughs of the critical user journeys, one video per milestone

Status: Draft, plan only. Nothing here is implemented: this text changes no
code, no contract and no test, adds no crate and no dependency, and publishes
no video. It answers a request of the user (2026-11-27): "a demo walk-through
video for the CUJs (no need to show every permutation) of each milestone". Each
choice is labelled **lead pick** (an implementation choice open to ordinary
review) or **open user question** (listed under "Decisions requested"). State
claims about the code are as of `main` at `a6a75e5`; this text's author ran
nothing for it (see "Not verified").

A walk-through shows one journey end to end, with a caption for every step, and
leaves out the permutations: the conformance scenarios of
[tasks §8](../skyoauth-tasks.md) stay the proof, a walk-through is a guided
tour of the same behaviour for a person who will not read the tests.

## What a walk-through is, and is not

- **Is:** a scripted, deterministic run against a real service and a private
  PostgreSQL, whose commands, redacted outputs and captions are played back as
  a video.
- **Is not:** evidence. A conformance scenario (`tests/conformance/scenarios.toml`)
  is the only thing that gates a release; a demo that passes proves nothing the
  scenarios do not. A demo script that diverges from its scenarios is a bug in
  the demo.
- **Is not committed:** the video is a release asset (section 5), never in git
  (size); the scripts and the renderer are in git.

## 1. The critical user journeys per milestone

Each journey lists the conformance IDs it maps to (tasks §8), the slices that
must have landed (tasks §9 and §13, named as those sections name them), and what
the viewer sees. Three to six per milestone; **lead pick**: the list is the
smallest set that covers each milestone's gate, and a journey that needs a
later milestone is placed in that later milestone.

### M1a: workload authority, the operator and recovery

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M1a-1 | Provision an empty installation with no SQL: bootstrap the first `security_admin`, then tenant, audience, principal, trust source and grant through the operator | A48 (workload chain), A32, A64 | the local bootstrap and recovery transport, the admin transport and the operator's remote client (S4 to S7, S9) | an empty database, then each object created with a generated ID and a revision; a final read of the chain; no `psql` anywhere |
| M1a-2 | Two tenants, the same labels, crossed references | A49, A29, A43 | tenant, audience and grant writes (S3 to S5) | identical names in two tenants get distinct IDs; an exchange or write that names the other tenant's object is denied and reveals nothing |
| M1a-3 | Several grants for one audience: the generated selector picks the actor, an override or the wrong tenant denies | A25, A50, A45 | grant selection (S5) | the selector the server generated, the authorized choice, and the three denials |
| M1a-4 | A widening write needs a second approver | A37 (removal as widening), the IR-052 and IR-054 contract rows | the instance security policy and the operations endpoints (S8) | the first actor's write returns a pending operation and changes nothing; a distinct `security_admin` approves; one transaction applies it; the audit event |
| M1a-5 | Recovery: the operator signs a challenge offline, the registry verifies, a replacement credential is enrolled, a replay is refused | A32, A64 | the recovery registry (ADR-013 item 7, merged), the operator's signer (merged), the local transport (merged) | the instance-bound challenge on one side, the signature produced on the workstation (the private key never shown), the restore, the same response refused a second time |
| M1a-6 | Fail closed: missing role, closed bootstrap, unavailable store | A48 (missing roles deny), A32 | the roles of S4 to S7 | each denial with its typed error; no write left behind |

### M1b: human authority and state

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M1b-1 | Initial human provider through a staged plan: dry run, approval, guarded commit | A47, A48 (human chain) | the human registry and the provider transition (M1b) | the plan text, the diff, the approval, the one commit that advances the pointer and the epochs |
| M1b-2 | A generic write to the active provider is refused atomically | A47 | as above | PATCH, import and reload each rejected; epochs unchanged |
| M1b-3 | Two origins, two tenants, two providers | A46 | versioned origins (M1b) | each registered origin resolves its own provider and tenant; a spoofed Host or forwarded header denies before any redirect |
| M1b-4 | First login policy: default denies, opt-in creates one zero-privilege principal | A60 (state level; the browser login itself is M3) | enrolment and client policy (M1b) | the default denial, the opt-in write, the single principal that results |
| M1b-5 | Route bundle approval | A58 (the registry-only part) | route bundles and the controller identity (M1b) | a prepared bundle, the exact mode-bound approval, a stale approval denied |

### M2: usable WIF and the bearer gateway

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M2-1 | A GitHub Actions push gets a scoped token | A01, A02, A30 | T20 to T22 | a real or recorded push proof, the token's audience and scope, the PR, dispatch and wrong-ref contexts denied |
| M2-2 | A k3s workload gets a scoped token through TokenReview | A06, A07, A28 | T23 | the service-account proof, the token for the selected tenant and cluster, a wrong cluster denied |
| M2-3 | The same token through Envoy to a backend; spoofed and direct paths denied | A36, A13 | T25, T26 | the positive bearer path, then the spoof, the outage and the direct-backend attacks |
| M2-4 | Issuer key rotation without a client change | A19, A04 | T20, T24 | the overlap window, the same client config before and after |
| M2-5 | Disable a grant with a token outstanding | A21, A23 | T21 | no new issuance, the residual TTL stated, a live check denying where one is committed |

### M3: browser sessions and the TypeScript SPA

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M3-1 | Sign in to the SPA and call a backend through the browser gateway | A08, A46, A51 | T30 to T33 | the redirect, the callback bound to the browser flow, the cookie never readable by script, the backend call with typed human-session evidence |
| M3-2 | Unsafe calls without the right Origin or CSRF header, mixed credentials | A09, A10, A40 | T32, T33 | each denial before any credential is forwarded |
| M3-3 | An attacker-initiated callback in a victim's browser | A51 | T30 | no victim session created, replaced or linked |
| M3-4 | A session ends: idle, absolute, revoked, store unavailable | A11, A33 | T31 | 401 or 503 as specified, never fail-open |
| M3-5 | The human IdP is down; workloads and the operator still work | A20 | T30, M2 | the fresh login fails closed, a WIF exchange and an operator recovery succeed |
| M3-6 | A long stream outlives its credential and reconnects | A12, A56 | T32 | the close at the lease, the reconnect with a fresh credential, no restarted mutation |

### M4: native OAuth and the reusable Rust CLI

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M4-1 | Native login with an explicit confirmation | A27, A52, A59 | T40 | the CLI showing a port and a code, the page asking for the matching acknowledgement, the token |
| M4-2 | A malicious concurrent native request | A59, A27 | T40 | the legitimate CLI unaffected; no silent replacement |
| M4-3 | Refresh rotation, a replay revokes, the opt-in exact retry | A34, A57 | T40 | the rotated successor, the replay and the revoked family, the retry inside 30 s returning one successor |
| M4-4 | The CLI on Linux, macOS and Windows, with no server dependency | A41, A64 | T40 | the same run on three systems, no plaintext keychain fallback |
| M4-5 | A human CLI token accepted by a backend, a forged one refused | A44, A55 | T40, T41 | the explicit human profile accepted, a WIF token in a human shape denied |

### M5: deployment, migration and v0.1

| # | Journey | Maps to | Needs | The viewer sees |
| --- | --- | --- | --- | --- |
| M5-1 | A provider switch with unchanged artifacts | A14, A42 | T51 | the same SPA and CLI artifact hashes and endpoints before and after, human re-authentication only |
| M5-2 | Migration keeps IDs, modes and revisions | A15, A16 | T51 | the before and after of the preserved objects, dormant impersonation still disabled |
| M5-3 | A rollback after an independent change | A17, A35 | T51 | the independent policy change untouched, no resurrected state, consumed proofs still consumed |
| M5-4 | Signer compromise and standby promotion | A62, A19 | T26, T52 | the audited promotion, the denial of unpromoted-standby evidence |
| M5-5 | Rotate a provider secret versus change the issuer | A63 | T51 | the credential-only revision keeping sessions, the semantic change needing the guarded transition |

## 2. The mechanism

**Lead pick**, in four parts, each replaceable without the others.

1. **A scenario runner** drives a real `skyoauth-service` and a private
   PostgreSQL with the conventions of the existing scenarios crate and harness
   (an environment variable for the database, per-scenario databases, injected
   clock and generators under `test-support`, the cross-UID conventions of the
   root step where a journey needs them). Each journey is a script of steps;
   a step is a command or a library call, a caption, and what to show. It emits
   a **typed transcript** as JSON lines: `caption`, `command`, `output`,
   `note`, with a monotonic step index and no wall-clock time.
2. **Redaction at the source.** The runner redacts before it writes: private
   keys never reach the transcript (the operator signs in its own process and
   the transcript shows the public result), tokens and cookies are shown as
   their type, audience and scope with the value replaced, generated IDs are
   kept (they are opaque) but are stable only with the deterministic generator.
   A redaction test fails the run when a known secret pattern, or any value
   taken from a secret-holding variable, appears in a transcript.
3. **A player** is a small static HTML page (no framework, no network) that
   plays a transcript as a terminal: typed commands, output, caption bar. A
   later browser journey (M3) is recorded directly with Playwright against the
   real SPA instead, with the same caption bar overlaid.
4. **Rendering.** Playwright records the player (`recordVideo`) and `ffmpeg`
   transcodes it to mp4, with the captions burnt in by the page, not by `ffmpeg`
   (no font handling in the pipeline). Both tools are in this container. No
   `asciinema` or `vhs` is needed.

Determinism: fixed seeds, the test clock, the deterministic ID generator, a
fixed terminal size, a fixed typing speed derived from the step index, and no
wall-clock values in the transcript. Two runs of a journey give byte-identical
transcripts, which a CI check compares; the video is only as stable as the
encoder, so the transcript, not the mp4, is the thing compared.

Where it lives (**open to the lead**, no new crate without approval): the
scripts as a `demo` test target of the existing `skyoauth-scenarios` crate,
run only when `SKYOAUTH_DEMO_OUT` names a directory, so that `cargo nextest`
never runs them in the normal jobs; the player and the render script under
`scripts/demo/` (Node, as `scripts/ci/`); a manual workflow for a trial run and the release job of section 5.
Not committed: the mp4 files and the transcripts' generated output.

## 3. What is demoable now

| Milestone | End to end today | Library or test-level segments that exist | Unblocked by |
| --- | --- | --- | --- |
| M1a | None | The recovery challenge sign and verify (operator crate and the registry's `recovery.rs`, pinned by the shared fixtures); the local transport and its wire codec (service and operator); the PostgreSQL scenarios (the A25 store-failure legs among them); the cross-UID root step | M1a-5 first (no new slice needed; a command layer is), then M1a-1 when S4 to S7 and S9 land |
| M1b | None | Registry state tests only | M1b slices |
| M2 | None | None | T20 to T26 |
| M3 | None | None | T30 to T33 |
| M4 | None | None | T40, T41 |
| M5 | None | None | T50 to T52 |

**Order to build**: M1a-5, M1a-1, M1a-3 and M1a-4 as their slices land, the
runner, redaction check and player first (they need no milestone), then the
other milestones' journeys as the slices of their column land. The runner and
the player are built once, against M1a-5.

## 4. Who owns what

- **Test session:** the runner, the transcript format, the redaction check, the
  player, the render script, the workflows, the journey scripts and their
  captions, and the determinism check.
- **Coding session:** any command layer a journey needs. **The `skyoauth-operator`
  crate has no command line yet** (it is a library with tests); M1a-1 and M1a-5
  need one, or the runner drives the library directly and the video shows
  library calls instead of commands. That is a gap to schedule, and it is the
  decision that most changes what the M1a video looks like.
- **Lead:** the review of this proposal, the journey lists, the crate placement
  and the approval of the workflows.

## 5. The videos as release assets

The user asked (2026-11-27) whether the videos can be part of the release
artifacts. They can, as follows (**lead pick** for the details; the principle
is the user's).

- **What is published:** on each tagged release, one mp4 per milestone that the
  release contains (a release that does not contain M3 has no M3 video), the
  **deterministic JSONL transcripts** each video was rendered from, and a
  **SHA-256 checksum file** over the mp4 files and the transcripts. They are
  release assets, not files in git. GitHub's limit for a release asset
  (2 GiB each) is no constraint at the expected size.
- **How they are built:** the release job renders them from the **tagged
  commit**, against a real service and a private PostgreSQL, with the runner of
  section 2. A trial run of the same job is available manually before a tag.
- **The consistency rule:** a release MUST NOT publish a video whose transcript
  differs from the transcript that CI compared on that commit (section 2,
  determinism). The release job therefore takes the CI transcript for the
  commit, re-runs the journeys, requires the two to be byte-identical, and
  renders only then; a difference fails the release job and publishes no video.
- **Redaction still applies:** no key, signature or credential bytes in a
  transcript, a caption or a video frame, with the same redaction check, which
  runs on the release job's transcripts too.
- **Dependencies, both open:** the release manifest format and the gate-job
  rulings 7a to 7d (the lead rules on them when the first M1a gate is close; the
  demo assets are added to the manifest then), and ADR-024 OQ-ADR024-1 (whether
  the usable M2 slice is a tagged release, which decides whether there is an M2
  video of its own). Until both are ruled, this section fixes the principle and
  the rules above, not the manifest entries.
- **Not in this PR:** no workflow or CI code; the release job is built after the
  manifest format is ruled.

## Decisions requested

Open user questions:

1. Captions and voice-over: captions only, or also a voice-over (and in which
   language)? **Lead pick:** captions only, no audio, so that a video can be
   regenerated from a transcript without a recording.
2. Length: one video per milestone of about five minutes, or one per journey?
   **Lead pick:** one per milestone, with chapter markers per journey.
3. Where the videos are published: **decided** by the user (2026-11-27), as
   release assets of each tagged release (section 5); an external host stays
   open only if the user wants a second copy.
4. Whether a viewer outside the project sees them, which sets how strict the
   redaction check is (**lead pick:** strict in all cases).

Open to the lead:

5. The crate placement of section 2.
6. Whether the operator command layer (section 4) is scheduled before M1a-1.

## Not verified

- No journey was run, and no part of the mechanism was built: the tools'
  availability (Playwright and Chromium, `ffmpeg`) is from the container's
  setup, not from a run of the pipeline.
- The slice names (S4 to S10, T-numbers) are those of tasks §9 and §13; whether
  each journey needs exactly the slices listed was not checked slice by slice,
  and the lead's review should correct the "Needs" column.
- The "demoable now" column lists what the repository has at `a6a75e5` as read
  by the author; it was not rerun.
