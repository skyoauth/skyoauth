# Proposal: verify the recovery signature inside `restore_operator` (T13.5)

Status: Accepted (user, 2026-11-24, relayed by the lead: the user accepted the
lead's recommendations); implemented in the library by PR #139 (`issue_recovery_challenge` hashes, `preview_recovery_response`, `restore_operator` verifies inside), while the binary's transport and its wiring stay pending (T13.3, T13.5). ADRs ratified directionally (maintainer, 2026-11-24). Drafted the same day
for the lead's review and the user's decision. The choices the user accepted
are those marked "provisional lead pick, 2026-11-24" below; Q2 to Q6 of the
review are accepted as implementation choices that ordinary review can change.
Other choices are marked "(inferred)". The ADRs were ratified separately,
directionally, by the maintainer on 2026-11-24 (T00.8–T00.17; Gate M0 is left to the lead's separate PR); the provisional lead picks below are accepted as implementation choices, not frozen, that ordinary review can change. This text ratifies no ADR and ticks no task. It
changes no code: the implementation PR does, and edits the places under
"Reconciliation". Line numbers refer to `main` at `3028360`, except those into
`service/migrations/README.md`, `registry/mod.rs`, `registry_recovery.rs` and
the second-approver proposal, retargeted after the 2026-11-24 amendment of
`0005` moved them.

The combined shape is ruled: `restore_operator` takes the signed response
itself and verifies it against the rows it has locked (section 1). The
earlier "verified response" value design is kept, with its conditions, under
"Alternative: a `VerifiedRecoveryResponse` value" as the documented rejected
alternative.

It answers the open decision "the recovery writers" of
`docs/proposals/second-approver-gated-writes.md` (:2259-2275), in a file of its
own because that proposal is about the second-approver flow for trust writes
and records its PRs as implemented.

## Problem

`restore_operator` (`service/src/persistence/registry/recovery.rs:1032`)
enrolls a replacement `security_admin`, revokes every operator credential and
rotates the recovery key. It trusts its caller to have checked the Ed25519
signature: "**The registry does not verify signatures**" (`recovery.rs:22-25`;
`docs/contracts/identity-registry.md:328-332`). Its inputs, a `RestoreRequest`
with a `ChallengeBinding` (`recovery.rs:572-581`, `:636-667`), are plain public
structs. So any crate that links the library and holds a `READ COMMITTED`
transaction can call `issue_recovery_challenge` (`:925`) and then
`restore_operator` with the binding it just chose, and enroll a
`security_admin` with no signature. Both are public
(`service/src/persistence/registry/mod.rs:482-488`), and so is
`bootstrap_instance` (`bootstrap.rs:481`);
`service/tests/ungated_writes_private.rs:190-201` keeps all three public on
purpose, pending this decision.

PRs 7, 9 and 10 closed the same kind of gap for other writers by making them
crate-private. That does not work here on its own: the design puts the
deployment-local verifier in the service binary (design :666, :724; tasks
:30, :84, :189), and `service/src/main.rs` is a crate of its own that uses the
library as any other crate does. If the check lived in the binary,
`restore_operator` would stay public, and the check would protect only the
binary's own call.

## Proposal

### 1. The shape

```rust
pub struct SignedRecoveryResponse<'a> {
    pub operation_id: &'a str,
    pub signature: &'a [u8], // untrusted input; 64 bytes
}

pub struct RestoreRequest<'a> {
    pub audit_event_id: &'a str,
    pub rotation_audit_event_id: &'a str,
    pub now: SystemTime,
}

pub async fn restore_operator(
    transaction: &mut Transaction<'_, Postgres>,
    response: &SignedRecoveryResponse<'_>,
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError>;
```

The library, not the binary, checks the signature, inside the restore, against
the recovery state and the challenge row the restore has locked. The binding
and the replacement come from the stored row, never from the caller. No value
that stands for "verified" crosses a call boundary, so there is nothing to
forge or to carry from one database to another (provisional lead pick,
2026-11-24).

An optional read-only pre-check, `preview_recovery_response(transaction,
&SignedRecoveryResponse, now) -> Result<RecoveryPreview, RestoreError>`,
runs the same checks without locks or writes and returns a plain summary (the
replacement's IDs, the new key's epoch, `expires_at`) for the binary to show
the deployment operator. It grants nothing: the restore checks everything
again (provisional lead pick, 2026-11-24).

The aim, as in PRs 7, 9 and 10: after bootstrap is closed, and in a build
without the `test-support` feature (whose `test_support` module exposes
`create_admin_identity` and the other operator writers), no safe call path of
the library enrolls a `security_admin` without a signature by the current
recovery key. Privacy does not stop `unsafe` code in a dependent (the library
has `#![forbid(unsafe_code)]`, `service/src/lib.rs:1`), nor SQL written with
the rights a restore needs.

### 2. The restore steps

Before any statement, as today. Then, in its savepoint, the steps of
`recovery.rs:128-183` change as follows:

0. `READ COMMITTED` only, unchanged;
1. every unrevoked credential locked, unchanged;
2. the `recovery_state` row locked `FOR NO KEY UPDATE` (`:1069`); it must
   exist and be closed;
3. new: the challenge row read by ID `FOR NO KEY UPDATE` (the lock the
   consume takes anyway, so the `0005` order holds), with a private query: the
   lead ruling that no registry getter returns the row (identity-registry
   :343-344) stands. Then, against the locked rows:
   - the row is an `operator_restoration` of no tenant, `challenge_hash` set,
     unconsumed, unrevoked, outcome `issued`, `now < expires_at`;
   - its plan's `instance_id` and `recovery_key_epoch` and its
     `expected_revision` are the state's;
   - `C` and `M` (section 4), rebuilt from the row, hash to its stored
     `request_digest` and `challenge_hash`, so a row whose stored hash or
     digest is not the library's encoding of that row is refused;
   - the state's key is not weak (section 4);
   - the signature is 64 bytes (else `BadSignature`) and verifies over `M`
     with the state's key;
4. the consume (`:459-478`), unchanged, bound to the row's own values;
5. the replacement taken from the consumed plan and checked as
   `validate_restore` checks it today (`:886-910`); today's step 4 comparison
   with the request has nothing left to compare and goes;
6. to 10. as today (`RecoveryKeyUnchanged` stays as defence; see section 3).

The key that verifies the signature is the one the restore then rotates, read
under the same lock in the same database, so no key comparison between two
calls is needed (review finding 1 applies only to the alternative). Every
refusal leaves the challenge unconsumed and nothing written, as today.

### 3. The issue side

`issue_recovery_challenge` computes `request_digest` and `challenge_hash`
itself; `IssueChallenge` loses both fields, and `RecoveryChallenge` returns
`M` for the binary to hand to the workstation. This reverses the pick that the
registry does not hash (`recovery.rs:90-91`, `:121-124`; identity-registry
:342-343) and matches D6 of the second-approver proposal and `0005`'s "the
service computes it" (`service/migrations/0005_operator.sql:273-274`)
(provisional lead pick, 2026-11-24).

Both columns are immutable once inserted (`0005_operator.sql:424-431`, the
names at :428-429), so `C` is computed before the insert from exactly the
values the insert binds: the ID, `deployment_operator`, the kind, the
`revision` read `FOR SHARE` at step 1, `expires_at` as `now + ttl` floored to
the microsecond (`floor_to_microsecond`, `registry/model.rs:265`), the plan
and no tenant. It is not recomputed from `RETURNING`.

Refused before any statement, so that the issue never stores a challenge no
restore can use (provisional lead pick, 2026-11-24):

- a plan with members other than the eight it needs (`instance_id`,
  `recovery_key_epoch`, `admin_id`, `credential_id`, `binding_id`,
  `public_identity`, `trust_anchor_ref`, `new_recovery_public_key`), which
  ends "Other members are the caller's" (`recovery.rs:88-90`);
- a plan with no canonical form (`NotCanonical`, `operation/digest.rs:78-82`:
  a fraction, or an integer above `i64::MAX`);
- a reserved `admin_id`, an empty or over-2048-byte `public_identity` or
  `trust_anchor_ref` (today's restore checks, moved forward);
- a new key that is weak or not canonically encoded (section 4).

After step 1 reads the state, a new key equal to the current one is
`NotIssuable`. A restore of a library-issued challenge therefore cannot meet
`RecoveryKeyUnchanged` (today's step 5, `:1085`): the key can become equal only
through a rotation, which advances the epoch (`0005_operator.sql:227-231`) and
so retires the challenge. The variant stays as defence against a row written
by other means (inferred).

`bootstrap_instance` stays public, a separate decision, but gets the same key
checks for the key it enrolls (provisional lead pick, 2026-11-24).

No migration is needed: the computed digest and hash are 32 bytes, inside the
`0005` checks of 32 to 64, and `0005` already says the service computes the
hash.

### 4. What is signed, and with what

The signed bytes reuse the canonical request of the second-approver flow
(`service/src/operation/digest.rs:5-18`, `DigestEnvelope` at `:97`; that
proposal's D6 and D29) under a prefix of their own (provisional lead pick,
2026-11-24):

```text
C              = canonical JSON of {"actor_id": "deployment_operator",
                   "expected_revision", "expires_at" (µs, as bound), "id",
                   "kind": "operator_restoration", "plan", "tenant_id": null}
request_digest = SHA-256("skyoauth.administrative_operation.v1\n" || C)
M              = "skyoauth.recovery_challenge.v1\n" || C
challenge_hash = SHA-256(M)
signature      = Ed25519(recovery private key, M)   (pure, RFC 8032; 64 bytes)
```

- `C` carries what the challenge must bind: the instance and the key epoch
  (plan), the operation and its arguments (plan), the expected revision, and
  the expiry the workstation displays (design :668; T13.5).
- The prefix separates the signed message from the request digest and from
  any other use of the key. The signature is over `M`, not its hash, so the
  workstation signs what it displays.
- `skyoauth-operator` parses `C`, requires the closed eight-member plan,
  re-encodes it canonically and compares the bytes with what it received
  before it displays and signs (design :668; ADR-013 item 8): a non-canonical
  or extended `C` is never signed (provisional lead pick, 2026-11-24).
- `C`'s form does not depend on `serde_json`'s map order (the writer sorts
  members itself, `digest.rs:12-18`, `:147-149`).
- The key is the raw 32-byte Ed25519 public key (identity-registry :273-276,
  :545-547; `RECOVERY_PUBLIC_KEY_LENGTH`, `bootstrap.rs:227-229`; lead pick
  dated 2026-11-21, provisional).

**Weak and non-canonical keys (required; provisional lead pick, 2026-11-24).**
Today only the length is checked (identity-registry :274-276;
`recovery.rs:890`). The review's probe showed that under `ring` 0.17.14 a
small-order key (the identity encoding `01 00 … 00`, or its non-canonical
`y = p + 1` form) accepts one fixed signature over any message. So the
library refuses a small-order key at verify (step 3, failing closed), and
refuses small-order, non-canonical and undecodable keys at enrollment: the
bootstrap key, the plan's `new_recovery_public_key` at issue, and again at
restore.

Which property comes from where (per the review, not re-checked here; the
implementation PR confirms each against the chosen crate's documentation and
pins it with a test):

| Property                                       | `ring` 0.17.14                         | `ed25519-dalek` 3                                                  |
| ---------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------ |
| `S` below the group order; canonical `R`       | crate                                  | crate (`verify_strict`)                                            |
| small-order key refused at verify              | library code: a blocklist of encodings | crate (`verify_strict`; `is_weak` at enrollment)                   |
| non-canonical or undecodable key at enrollment | library code (`y < p`, blocklist)      | library code: decode, re-encode, compare (`from_bytes` is ZIP-215) |

**Dependency (question 1, the user's).** No Ed25519 crate is a direct
dependency of `skyoauth-service` (`service/Cargo.toml`); `sha2` 0.11.1 is
(`:19`). `ring` 0.17.14 is in `Cargo.lock` (:975) only through `rustls` under
`sqlx`'s `tls-rustls`. The repository has no `deny.toml`, `cargo-vet`
configuration or `supply-chain/` directory (checked). Nothing is added until
the user decides.

### 5. Refusals

`RestoreError::NotRestorable` gains a reason, after
`operation::NotApprovableReason` (`service/src/operation/mod.rs:485-493`), with
fixed `Display` text per reason (as `ApprovalError`'s, `:564-574`) and a
`Debug` that names the variant only (provisional lead pick, 2026-11-24).
Reasons (names inferred): `NoRecoveryState`, `NotFound`, `Consumed`,
`Revoked`, `Expired`, `WrongKind`, `NotBound` (instance, epoch or revision),
`NotLibraryEncoding`, `WeakKey`, `BadSignature`. Neither `Display` nor `Debug`
holds an ID, a public identity, the plan, a digest or the signature
(`service/tests/redaction.rs:3-7`); `SignedRecoveryResponse` and
`RecoveryPreview` get a hand-written `Debug` like `PreparedApproval`'s
(`operation/approval.rs:134-140`, the kind only). The reasons disclose
nothing a caller with the database rights cannot read (inferred).

### 6. Time and replay

`now` is the caller's (`recovery.rs:285-300`). The expiry, the TTL and the
order of a preview before a restore bind only an honest caller's clock: a
library caller holding a captured response can pass any `now`. Against such a
caller the restore rests on the signature, the single consume (LT-107;
`recovery.rs:34-43`), and the binding of `C` to the instance, the key epoch and
the recovery state revision; the expiry tests are not security-boundary tests.

A replay of a consumed response fails at the consume; after a rotation it
fails at step 3, because the epoch and revision in `C` are no longer the
state's. Reusing a retired key is not refused (identity-registry :353-354);
that does not reopen a replay, since the epoch has moved.

Residual (TM-15, "an old database backup", `docs/threat-model.md:876-877`):
on a backup taken after an issue and before its restore, the captured response
restores again. On a backup taken before the issue, a library caller can issue
an identical challenge (same ID, plan and `now`, so the same `expires_at`) and
replay. Option, not picked: a library-generated random nonce as a ninth plan
member makes the second case fail (the re-issued `C` differs); it needs a
random source, so it joins question 1, and it does not stop a row inserted by
raw SQL. No migration either way (inferred).

### 7. Where the code lives

| Option                                                         | Signature check | Can the restore require a signature?                                                                                                                    |
| -------------------------------------------------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A. The service library, in `persistence::registry::recovery`   | library         | yes: it verifies inside                                                                                                                                 |
| B. A separate crate (the "operator crate" of `recovery.rs:23`) | that crate      | no: its entry would be public to every crate; and `operator/` (`skyoauth-operator`) must have no server or database dependency (design :666; tasks :84) |
| C. The service binary, `service/src/main.rs`                   | binary          | no: `restore_operator` stays public and unverified for the binary to call                                                                               |

Recommendation (provisional lead pick): **A**. The binary's recovery
subcommand (T13.3, T13.5; not built) does only deployment-local transport: the
Unix socket owned by the service UID with mode 0600 (T13.4, OQ-TM-9); the
plan the deployment operator asks for, `issue_recovery_challenge`, `M` handed
out; the signed response read back; `now` from its own clock; a
`READ COMMITTED` transaction with `lock_timeout` and `statement_timeout`
(`recovery.rs:294-300`); optionally the preview; `restore_operator`; commit. It
holds no private key and verifies nothing. That matches "the service binary
retains only the deployment-local bootstrap/recovery verifier" (design :666;
tasks :84; ADR-013 item 7) when "binary" is read as the `skyoauth-service`
package; the tasks layout already plans a library home for "bootstrap and
recovery" (tasks :36, `src/admin/`).

**A module cycle (a consequence, and a choice).** `registry::recovery` would
use `crate::operation::DigestEnvelope` (re-exported at `operation/mod.rs:229`),
while `operation::digest` imports `JsonObject`, `floor_to_microsecond` and
`push_string` from the registry (`digest.rs:29`). Rust accepts the cycle. The
cleaner choice is to move the canonical writer and its prefix into the
registry and keep `operation`'s public names as re-exports (inferred; the
implementation PR picks).

### 8. The public surface afterwards

| Item                                                                        | Visibility                                                                 |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `restore_operator`, `SignedRecoveryResponse`, `RestoreRequest` (IDs, `now`) | public: verifies inside                                                    |
| `preview_recovery_response`, `RecoveryPreview`                              | public, read-only, grants nothing                                          |
| `issue_recovery_challenge`, `get_recovery_state`                            | public: an issue alone writes an expiring row and an event, enrolls no one |
| `bootstrap_instance`                                                        | public, separate decision; gains the key checks                            |
| `ChallengeBinding`; `IssueChallenge::request_digest`, `::challenge_hash`    | removed                                                                    |
| the row query, the encoder of `C` and `M`, the key checks                   | private to `recovery` (or the registry, section 7)                         |

Nothing becomes `pub(crate)` and no `test_support` wrapper is added: tests sign
with a test key. `service/tests/ungated_writes_private.rs` would change (not
written here): `restore_operator` and `issue_recovery_challenge` leave
`REGISTRY_KEPT_PUBLIC` (:195-201), whose doc (:190-194) then names
`bootstrap_instance` alone, and join the control probe (:874) with the new
public names; one new probe: `persistence::registry::ChallengeBinding` is
unresolved (E0432, `assert_unreachable`, :513). No E0451, E0599 or E0277 probes
are needed. That the restore verifies is a database test, not a probe.

## Tests

The implementation PR adds or adapts (a list, not code):

- the probe above;
- known answers: RFC 8032 test vector 1 through the verify helper; a pinned `C`
  and `M` for a fixed challenge, so the workstation can conform;
- a signed response restores (`registry_recovery.rs:1659`, adapted);
- bad signature (one bit flipped, all zeros, 63 and 65 bytes), wrong key
  (another key, the plan's new key, the retired key after a rotation), wrong
  message (over `challenge_hash`, over `C` without the prefix, over the
  request-digest prefix), malleability (`S + L`, a non-canonical `R`): each
  `NotRestorable` with its reason, nothing written, the challenge unconsumed;
- weak keys: a small-order current key (the identity point and its
  `y = p + 1` form) with the fixed signature is refused at restore; the same
  keys and an undecodable one are refused at bootstrap and as a plan's new key
  at issue;
- replay: the same response twice; two restores at once, exactly one wins
  (`:1516`, adapted); a response after a rotation;
- issue refusals: an extra plan member, a fraction, an integer above
  `i64::MAX`, a reserved `admin_id`, the string bounds, a weak or equal new key;
- a raw-inserted row (`insert_raw`, `:361`) whose hash or digest is not the
  library's encoding is refused;
- expiry and isolation as today (expiry tests check an honest clock only,
  section 6);
- preview: the same refusals, no lock held, nothing written;
- redaction: `Display` and `Debug` of every new reason and of
  `SignedRecoveryResponse` and `RecoveryPreview` (`service/tests/redaction.rs`);
- `registry_recovery.rs` moves to a test signing key: the helpers `plan_for`
  (:105), `issue_request` (:129), `binding` (:142), `restore_request` (:154)
  and `other_request` (:174); the tests of caller-supplied digest and hash
  lengths (:641, :1299, :1319, :1368) go, since those inputs disappear.
  `every_consume_miss_is_the_same_not_restorable` (:927) inserts 14 raw rows
  (:973-1075); their columns are immutable, so most of them cannot be made to
  carry a valid signature and become reason cases of step 3;
- the other callers of `issue_recovery_challenge` and `restore_operator` sign
  with a test key: `service/tests/operation_approval.rs` (its `restore`,
  :837-839) and `service/tests/source_approval.rs` (:1079-1081);
- `tests/security/a32.rs` (the test session's file): its helpers (:1485
  onward) sign instead of inventing `challenge_hash`, which needs the Ed25519
  crate as a dev-dependency in `tests/Cargo.toml` (`[dev-dependencies]`, :29);
  A32's M1a row (conformance-layout :145) still lacks the socket and the
  workstation, A48 and A64 are unchanged, and no stage moves;
- fixture churn from the weak-key checks: fixtures that enroll arbitrary 32
  bytes (`tests/security/a04.rs:1289`, `a48.rs:393`, and at least six files
  under `service/`) need real public keys.

## Alternative: a `VerifiedRecoveryResponse` value

The previously approved shape. `verify_recovery_response(tx, &response, now)`
runs step 3 without locks and returns a value with private fields (the
operation ID, instance, epoch, revision, the key it verified with, digest,
hash, `expires_at`, the parsed replacement), no public constructor,
`Default`, `From`, `TryFrom`, `Deserialize`, `Clone` or `Copy`, and a
hand-written `Debug` (section 5). `restore_operator` takes it by value. Its
conditions, all needed for it to be as strong as the combined shape:

- **The key comparison is load-bearing (review finding 1).** The value names
  no database. An attacker builds a second database with the same instance,
  epoch and revision but their own key, issues the same challenge on both (the
  caller picks `now` and the TTL), verifies on theirs with their own
  signature, and restores on the real one. Only a comparison, at restore step
  2, of the locked row's `recovery_public_key` with the value's key refuses
  it. Epoch and revision do not, and since a key change always moves the
  epoch (`0005_operator.sql:227-231`), no other listed test would fail without
  it. It is the binding between the signature and the database, and needs its
  own test: verify on A, restore on B with the same instance, epoch and
  revision and another key, `NotRestorable`.
- The restore also rebinds digest, hash, instance, epoch and revision from the
  value at its consume, and refuses a `now` before the verify's (an honest
  clock only, section 6).
- Probes: a struct literal (E0451), `Default` (E0277), and `Clone`. A probe
  calling `.clone()` on `&VerifiedRecoveryResponse` compiles (it clones the
  reference), so the `Clone` probe takes the value by value or uses a trait
  bound (`fn f<T: Clone>() {}` with `f::<VerifiedRecoveryResponse>()`). The
  source check (`MENTIONS`, :224) keeps the struct literal in the verify step
  only.

It keeps a separate verify step for the binary, which the combined shape's
preview gives without granting anything.

Also considered and rejected: keeping `restore_operator` public and
documented (today's gap); the check in the binary (option C); a separate
verifier or operator crate (option B); a sealed-trait witness (as strong as
private fields, more machinery; inferred); tying the value's lifetime to the
transaction (the combined shape makes it unnecessary).

## Rulings and open questions

Ruled by the user, 2026-11-24, relayed by the lead (the lead's recommendations
accepted): the library hashes; the format of `M`, with a closed plan and the
workstation's re-encode check; weak-key refusal at verify and enrollment; a
reason enum; the combined shape (over the earlier approved value shape);
`bootstrap_instance` stays public with the key checks; the raw-key pick is
dated 2026-11-21 (identity-registry :547, `bootstrap.rs:227-228`).

1. **The Ed25519 crate: closed.** The user chose `ed25519-dalek` 3.0.0 with
   `default-features = false`. The facts below are to be verified by cargo in
   the implementation PR, not taken from this text. It is a new direct
   dependency, and the tests need one to sign. The `ring` option, kept for the
   record:
   - `ring` 0.17.14: already in the lock, so no new crate; couples its version
     to `rustls`; the small-order blocklist and the key-encoding check are
     hand-written library code.
   - `ed25519-dalek` 3.0.0 (chosen; the reviewer's pick, for `verify_strict` and
     `is_weak`): the local registry index shows 3.0.0 with `rust_version`
     1.85 and normal dependencies `curve25519-dalek` ^5, `ed25519` ^3, `sha2`
     ^0.11 and `subtle`. The review reports a 2026-07-06 release under BSD-3,
     reuse of `sha2` 0.11, `digest` 0.11, `rand_core` 0.10 and `cpufeatures`
     0.3 (all four in `Cargo.lock` today, checked), and about eight new crates
     with `default-features = false` (`ed25519-dalek`, `curve25519-dalek`, its
     `-derive`, `ed25519`, `signature`, `fiat-crypto`, `rustc_version`,
     `semver`); the date, the license and the count were not checked here.
     `ed25519-dalek` 2.x would duplicate `sha2` and `digest` at 0.10.
2. **The nonce option (section 6): recorded as an option, not built.** The
   residual risk stays in the threat model (TM-15); the user accepted that
   default.
3. **Combined shape or value shape: closed.** The combined shape is ruled.
4. **Spec wording: done** (design :666, :724 and tasks :30, :84, :189 and
   ADR-013 item 7 carry the library-verifies wording).

## Reconciliation

Places that call the check the "operator crate"'s, place it in the binary, or
say the registry neither verifies nor hashes. The implementation PR edits the
code and its own docs; the test session edits its files; the spec rows are the
lead's. This proposal edits none of them.

| Place                                                         | Says                                                                                                                            | Change                                                                                     |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `service/src/persistence/registry/recovery.rs:15-18`          | "the local recovery verifier builds the restoration plan and calls" the issue                                                   | the binary builds the plan; the issue hashes and returns `M`                               |
| `recovery.rs:19-25`                                           | "The registry does not verify signatures: that belongs to the future operator crate"                                            | the restore verifies; `skyoauth-operator` only signs; the binary carries the response      |
| `recovery.rs:88-91`, `:121-124`                               | other plan members "are the caller's"; `challenge_hash` "computed by the caller"; "the registry still does not hash"            | closed plan; the library hashes                                                            |
| `recovery.rs:547-549`, `:569-581`                             | `IssueChallenge::challenge_hash` "computed by the caller"; `ChallengeBinding`                                                   | removed                                                                                    |
| `service/src/persistence/registry/mod.rs:352-355`, `:366-367` | the recovery writers stay public, "an open decision"; "does not verify a recovery signature (the verifier does"                 | the restore verifies                                                                       |
| `service/src/persistence/registry/operator.rs:37-39`          | nothing stops "enrolling a `security_admin` while ... `issue_recovery_challenge` and `restore_operator` stay public"            | only `bootstrap_instance` remains, before closure                                          |
| `service/tests/ungated_writes_private.rs:190-201`             | kept public, "whose verifier is the open decision"                                                                              | section 8                                                                                  |
| `service/migrations/README.md:3184-3185`                      | "the registry still does not hash"                                                                                              | the library hashes                                                                         |
| `service/migrations/README.md:3202-3203`                      | "The registry does not verify the recovery signature: the caller verifies it first"                                             | the restore verifies                                                                       |
| `docs/contracts/identity-registry.md:328-332`, `:342-344`     | the caller verifies; "The registry still does not hash"                                                                         | the restore verifies over `M` rebuilt from the row; the library hashes                     |
| `identity-registry.md:274-276`, `:548-549`                    | the key's length only, "it does not check the bytes further"; "the signature check is not implemented yet"                      | the weak-key checks; the restore's check                                                   |
| `tests/security/a32.rs:188-199`, `:238-245`, `:2260-2262`     | "the registry neither hashes nor verifies"; "The verifier is the only check"; that the hash is signed is "the local verifier's" | the test session rewords                                                                   |
| `service/tests/operation_approval.rs:837-839`                 | "The registry does not verify the recovery key's signature; the digest and challenge hash are the caller's bytes"               | signs with a test key                                                                      |
| `service/tests/source_approval.rs:1079-1081`                  | the same                                                                                                                        | the same                                                                                   |
| `docs/proposals/second-approver-gated-writes.md:2259-2275`    | the open decision; quotes "belongs to the future operator crate"                                                                | points here; closed once ruled                                                             |
| `docs/skyoauth-design.md:666`                                 | "The service binary retains only the deployment-local bootstrap/recovery verifier"                                              | none if "binary" means the package; else the lead adds "(library check, binary transport)" |
| `docs/skyoauth-design.md:724`                                 | verifier home: "Existing `skyoauth-service` subcommands"                                                                        | none: the subcommands are the entry point                                                  |
| `docs/skyoauth-tasks.md:30`                                   | "`src/main.rs` Process/listener wiring; M1a local bootstrap/recovery verifier"                                                  | the lead may add that the check is in the library (tasks :36)                              |
| `docs/skyoauth-tasks.md:84`, `:189`; ADR-013 :68-69 (item 7)  | the service binary keeps the verifier                                                                                           | as design :666                                                                             |

Not affected: "operator tooling" at identity-registry :278, `bootstrap.rs:181`
and the migrations README (:3100) names who canonicalizes an mTLS key, not the
recovery check. The string "operator crate" occurs only at `recovery.rs:23`
and in the second-approver proposal (:2271).
