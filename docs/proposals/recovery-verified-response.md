# Proposal: a verified recovery response for `restore_operator` (T13.5)

Status: proposal only, drafted 2026-11-24 for the lead's review and the
user's decision. The user approved the "verified response" direction (relayed
by the lead); every design choice below is a provisional lead pick or marked
"(inferred)", and all of them stay provisional until the maintainer ratifies
the ADRs (T00.8–T00.17, Gate M0). This text ratifies no ADR and ticks no task.
It changes no code: the implementation PR does, and edits the places listed
under "Reconciliation". Line numbers refer to `main` at `3028360`.

It answers the open decision "the recovery writers" of
`docs/proposals/second-approver-gated-writes.md` (:2232-2247), in a file of its
own because that proposal is about the second-approver flow for trust writes,
is accepted, and records its PRs as implemented; this is a separate decision
about the break-glass path.

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
`security_admin` with no signature at all. Both are public
(`service/src/persistence/registry/mod.rs:479-485`), and so is
`bootstrap_instance` (`bootstrap.rs:481`);
`service/tests/ungated_writes_private.rs:190-201` keeps all three public on
purpose, pending this decision.

PRs 7, 9 and 10 closed the same kind of gap for other writers by making them
crate-private. That does not work here on its own: the design puts the
deployment-local verifier in the service binary (design :666, :724; tasks
:30, :84, :189), and `service/src/main.rs` is a crate of its own that uses the
library as any other crate does. If the signature check lived in the binary,
`restore_operator` would have to stay public, and the check would protect
only the binary's own call.

## Proposal

The library, not the binary, checks the signature, and proves it did with a
value nobody else can make: a `VerifiedRecoveryResponse`. `restore_operator`
takes that value instead of a caller-chosen binding. The binary keeps the
deployment-local transport only.

### 1. The type

```rust
/// A recovery response whose Ed25519 signature this module checked
/// against the current recovery key, over the challenge it rebuilt from
/// the stored operation row. Only `verify_recovery_response` makes one.
#[derive(Debug)]
pub struct VerifiedRecoveryResponse {
    operation_id: String,
    instance_id: String,
    recovery_key_epoch: i64,
    expected_revision: i64,       // the recovery_state revision it binds
    recovery_public_key: [u8; 32], // the key the signature was checked with
    request_digest: [u8; 32],
    challenge_hash: [u8; 32],      // SHA-256 of the signed bytes (section 4)
    expires_at: SystemTime,
    verified_at: SystemTime,       // the verifier's `now`
    replacement: Replacement,      // the plan's six members, parsed
}
```

`Replacement` (private) holds `admin_id`, `credential_id`, `binding_id`,
`public_identity`, `trust_anchor_ref` and the new 32-byte key, parsed from the
stored plan. There is no tenant member: an `operator_restoration` challenge
has none (`recovery.rs:462`); the M1b provider transition (T13.5) adds its own
kind and fields then. The signature itself is not kept: the audit envelope has
no member for it (`recovery.rs:181-183`), and nothing after the check needs it
(inferred).

Why only the library can build one (inferred mechanism):

- every field is private, so a struct literal outside the defining module is
  a compile error, and there is no public constructor, `Default`, `From`,
  `TryFrom` or `Deserialize`;
- not `Clone` or `Copy`: `restore_operator` takes it by value, so one
  verification feeds one restore;
- read-only accessors (`operation_id()`, `admin_id()`, the new key...) let the
  binary show the operator what is about to happen;
- `#[non_exhaustive]` adds nothing once a field is private, so it is not used;
- the constructor lives in the module that owns `restore_operator`
  (`recovery.rs`, or a child `recovery/verify.rs`, which can read its parent's
  private fields), so the fields need no wider visibility.

Privacy does not stop `unsafe` code in a dependent (the library itself has
`#![forbid(unsafe_code)]`, `service/src/lib.rs:1`), nor SQL written with the
rights a restore needs. The aim, as in PRs 7, 9 and 10, is that no safe call
path of the library enrolls a `security_admin` without a checked signature.

### 2. Building it: `verify_recovery_response`

```rust
pub struct SignedRecoveryResponse<'a> {
    pub operation_id: &'a str,
    pub signature: &'a [u8], // 64 bytes; untrusted input
}

pub async fn verify_recovery_response(
    transaction: &mut Transaction<'_, Postgres>,
    response: &SignedRecoveryResponse<'_>,
    now: SystemTime,
) -> Result<VerifiedRecoveryResponse, VerifyError>;
```

It writes nothing. Before any statement it refuses a signature that is not 64
bytes and a `now` outside the range a restore accepts. Then:

1. reads the `recovery_state` row with the query of `get_recovery_state`
   (`:913`), no lock: it must exist and be closed. The key is the row's,
   never one the caller passes;
2. reads the operation row by ID with a private query (the lead ruling that no
   registry getter returns the row, identity-registry :343-344, stands): no
   tenant, kind `operator_restoration`, `challenge_hash` set, unconsumed,
   unrevoked, outcome `issued`, `now < expires_at`, the plan's `instance_id`
   and `recovery_key_epoch` the state's, and `expected_revision` the state's
   `revision` (the predicates of the consume, `recovery.rs:459-478`);
3. rebuilds the signed bytes `M` from the stored row (section 4) and requires
   SHA-256 of `M` to equal the stored `challenge_hash` and the recomputed
   request digest to equal the stored one. A row whose hash the library did
   not compute, an insert by raw SQL say, never verifies;
4. parses the replacement and runs the checks `validate_restore` runs today
   (`:886-910`: a reserved `admin_id`, a key of 32 bytes, the string bounds)
   and the step 5 check that the new key is not the current one (`:1085`);
5. verifies the Ed25519 signature over `M` with the state's 32-byte key,
   strictly (section 4);
6. returns the value, with the state's key, epoch and revision.

Every miss of steps 1 to 5 is one unit refusal, `VerifyError::NotVerified`,
with no detail, as `RestoreError::NotRestorable` (`:697`) is today (inferred;
see open question 5); a store failure is `VerifyError::Store`.

### 3. Restoring with it

`restore_operator(transaction, verified: VerifiedRecoveryResponse, request:
&RestoreRequest)`, where `RestoreRequest` keeps only the two audit event IDs
and `now`. The replacement and the binding come from the value, so the caller
cannot pass other ones. Its steps stay those of `recovery.rs:128-183`, with
three changes:

- step 2, after locking `recovery_state` `FOR NO KEY UPDATE`: refuse
  (`NotRestorable`) unless the row's `instance_id`, `recovery_public_key`,
  `recovery_key_epoch` and `revision` equal the value's. This closes the window
  between verify and restore: a concurrent restore that rotated the key, or
  any change of the row, is caught under the lock;
- step 3, the consume, binds the value's digest, challenge hash, instance,
  epoch and revision, as today's `ChallengeBinding` does, at the restore's own
  `now`, so a challenge that expired after the verify is refused there;
- before step 0: refuse a `now` earlier than `verified_at` (inferred; it keeps
  a caller from running the restore on an older clock than the check).

Step 4 still compares the consumed plan with the value's replacement. The plan,
the digest and the challenge hash cannot change after the issue: the `0005`
trigger `administrative_operation_immutable` refuses it
(`service/migrations/0005_operator.sql:424-431`), and `outcome` and `revision`
are the only mutable columns (`recovery.rs:168-170`). The comparison stays as
defence in depth (inferred).

Replay and races, inside the one restore savepoint: the consume stays the
only single-use mechanism (LT-107; `recovery.rs:34-43`), so a second restore
from the same response, or from a second value verified before the first
committed, is `NotRestorable`; after a rotation the old key is no longer
current, so the response no longer verifies. The verify should run in the
restore's own `READ COMMITTED` transaction just before it (inferred); the type
does not force that, and need not, since the restore rechecks every bound
value under its lock (so tying the value's lifetime to the transaction was
dropped).

### 4. What is signed, and with what

The signed bytes reuse the canonical request of the second-approver flow
(`service/src/operation/digest.rs:5-18`, `DigestEnvelope` at `:97`; that
proposal's D6 and D29), under a prefix of their own (inferred):

```text
C              = canonical JSON of {"actor_id": "deployment_operator",
                   "expected_revision", "expires_at" (µs, as stored), "id",
                   "kind": "operator_restoration", "plan", "tenant_id": null}
request_digest = SHA-256("skyoauth.administrative_operation.v1\n" || C)
M              = "skyoauth.recovery_challenge.v1\n" || C
challenge_hash = SHA-256(M)
signature      = Ed25519(recovery private key, M)   (64 bytes)
```

- `C` already carries what the design asks the challenge to bind: the instance
  and the key epoch (in the plan), the operation, its arguments (the plan) and
  the expected revision (design :668; T13.5), plus the expiry the workstation
  displays. It is JSON, so `skyoauth-operator` can parse and display it
  before signing (design :668; ADR-013 item 8).
- The distinct prefix separates the signed message from the request digest
  and from any other use of the key.
- The signature is over `M`, not over its hash, so the workstation signs what
  it displays; the hash is only the database binding. Pure Ed25519 (RFC 8032),
  no pre-hash or context variant (inferred).
- `issue_recovery_challenge` computes `request_digest` and `challenge_hash`
  itself from the row it inserts and returns `M`; `IssueChallenge` loses both
  fields. This reverses the current pick that the registry does not hash
  (`recovery.rs:90-91`, `:121-124`; identity-registry :342-343): see open
  question 2.
- The key is the raw 32-byte Ed25519 public key (identity-registry :273-276,
  :545-547; lead pick 2026-11-21, provisional; `RECOVERY_PUBLIC_KEY_LENGTH`,
  `bootstrap.rs:229`).
- Strict verification: reject a signature whose `S` is not below the group
  order, a non-canonical encoding of `R` or of the key, and use the cofactorless
  equation, so a valid signature cannot be altered into another valid one.
  Whether a small-order key is also refused, at verify or at enrollment, is
  open question 4. The implementation PR confirms each property against the
  chosen crate's documentation and pins it with a test.
- `C`'s canonical form does not depend on `serde_json`'s map order (the
  writer sorts members itself, `digest.rs:12-18`, `:147-149`), so a
  `preserve_order` feature turned on elsewhere in the build cannot change it.

**Dependency.** No Ed25519 crate is a direct dependency of `skyoauth-service`
today (`service/Cargo.toml`). `ring` 0.17.14 is in `Cargo.lock` (:975), only
through `rustls` under `sqlx`'s `tls-rustls`; there is no `ed25519-dalek`,
`aws-lc-rs` or other Ed25519 crate. `sha2` is a direct dependency already
(`service/Cargo.toml:19`). Verifying, and signing in tests, therefore needs a
new direct dependency either way: open question 1. Nothing is added until the
user decides.

### 5. Where the code lives

| Option                                                         | Signature check | Can `restore_operator` require proof?                                                                                                                                                                                |
| -------------------------------------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A. The service library, in `persistence::registry::recovery`   | library         | yes: constructor and restore in one module                                                                                                                                                                           |
| B. A separate crate (the "operator crate" of `recovery.rs:23`) | that crate      | no: its constructor would have to be public for `skyoauth-service` to receive it, so anyone could call it; and `operator/` (`skyoauth-operator`) must have no server or database dependency (design :666; tasks :84) |
| C. The service binary, `service/src/main.rs`                   | binary          | no: `restore_operator` stays public for the binary to call it                                                                                                                                                        |

Recommendation (provisional lead pick): **A**. The verify, the restore and
the value live in `service/src/persistence/registry/recovery.rs` (or its
child module): the signature check is in the library. The binary's recovery
subcommand (T13.3, T13.5; not built) does only the deployment-local transport:
the Unix socket owned by the service UID with mode 0600 (T13.4, OQ-TM-9); the
plan the deployment operator asks for, `issue_recovery_challenge`, and `M`
handed out; the signed response read back; `now` from its own clock; a
`READ COMMITTED` transaction with `lock_timeout` and `statement_timeout`
(`recovery.rs:294-300`); then `verify_recovery_response`, `restore_operator`
with the value, and commit. It holds no private key and verifies nothing.
That still matches "the service binary retains only the deployment-local
bootstrap/recovery verifier" (design :666; tasks :84; ADR-013 item 7) when
"binary" is read as the `skyoauth-service` package, whose library is part of
it; the tasks layout already plans a library home for "bootstrap and
recovery" (tasks :36, `src/admin/`). A crate shared later with
`skyoauth-operator` could hold the encoding of `C` and `M` for display, never
the constructor (inferred).

### 6. The public surface afterwards

| Item                                                                | Visibility                                                                 |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `verify_recovery_response`, `SignedRecoveryResponse`, `VerifyError` | public (new)                                                               |
| `VerifiedRecoveryResponse`                                          | public type, private fields, no constructor                                |
| `restore_operator`                                                  | public, safe by construction: takes the value                              |
| `RestoreRequest`                                                    | public, IDs and `now` only                                                 |
| `ChallengeBinding`, the replacement members of `RestoreRequest`     | removed (the value carries them)                                           |
| `IssueChallenge::request_digest`, `::challenge_hash`                | removed (computed)                                                         |
| `issue_recovery_challenge`, `get_recovery_state`                    | public: an issue alone writes an expiring row and an event, enrolls no one |
| `bootstrap_instance`                                                | public, unchanged: open question 7                                         |
| the verify steps, the row query, the encoder of `M`                 | private to `recovery`                                                      |

Nothing becomes `pub(crate)`: the unverified restore has no form at all, so no
`test_support` wrapper is added for it either; tests sign with a test key.

`service/tests/ungated_writes_private.rs` would change as follows (the test is
the implementation PR's, not written here): `restore_operator` and
`issue_recovery_challenge` leave `REGISTRY_KEPT_PUBLIC` (:195-201), whose doc
(:190-194) then names `bootstrap_instance` alone as open, and join a list of
public items checked by the control probe (:874) with the new names; new probes
must fail with a specific code, which needs a helper beside
`assert_unreachable` (:513), which accepts only E0603 and E0432: a struct
literal of the value (E0451), `.clone()` on it (E0599), `Default::default()`
for it (E0277), and the old path `persistence::registry::ChallengeBinding`
(E0432). The source check (`MENTIONS`, :224) gains rows so that the value's
struct literal appears only in the verify step, once, and no `impl From`,
`impl TryFrom`, `Clone`, `Default` or `Deserialize` names it.

## Tests

The implementation PR adds or adapts (a list, not code):

- the compile-fail probes and source rows above;
- a known-answer test: RFC 8032 test vector 1 through the verify helper, and a
  pinned `M` for a fixed challenge, so the workstation can conform;
- a signed response verifies and restores (`registry_recovery.rs:1639`,
  adapted);
- a bad signature is `NotVerified`, writing nothing, the challenge unconsumed:
  one bit flipped, all zeros, 63 and 65 bytes;
- the wrong key: another key, the plan's new key, the retired key after a
  rotation;
- malleability: `S + L`, a non-canonical `R`; a small-order key if question 4
  says so;
- the wrong message: a signature over `challenge_hash`, over `C` without the
  prefix, over the request-digest prefix;
- replay: the same response twice; two values verified before either restore
  commits, exactly one wins (`:1496`, adapted);
- expiry: verify at or after `expires_at` is `NotVerified`; verify before and
  restore after it is `NotRestorable`; a restore `now` before `verified_at`;
- plan tampering: a raw-inserted row (`insert_raw`, `:361`) whose hash is not
  the library's never verifies; the `0005` trigger refuses an update of the
  plan or hash after the issue;
- TOCTOU: verify, rotate the key or advance the revision in another
  transaction, then restore: `NotRestorable`, nothing written;
- isolation: a restore outside `READ COMMITTED` is refused as today;
- the existing tests move to a test signing key: the helpers `plan_for` (:105),
  `issue_request` (:129), `binding` (:142), `restore_request` (:154) and
  `other_request` (:174); the tests of caller-supplied digest and hash lengths
  (:641, :1279, :1299, :1348) are replaced, since those inputs disappear;
  `every_consume_miss_is_the_same_not_restorable` (:927) keeps its misses
  through raw SQL after a valid verify;
- `tests/security/a32.rs` (the test session's file): its recovery helpers
  (:1485 onward) sign instead of inventing `challenge_hash`; A32's M1a row
  (conformance-layout :145) still lacks the socket and the workstation, and
  A48 and A64 are unchanged; no stage moves.

## Alternatives considered

- **Keep `restore_operator` public, documented.** Today's state: any linking
  crate enrolls a `security_admin` unverified. Rejected.
- **Move the check into the binary.** See option C: the binary is another
  crate, so `restore_operator` stays public. Rejected.
- **A separate verifier or operator crate.** See option B. Rejected.
- **A sealed-trait witness** (`restore_operator<W: Verified>` with a private
  supertrait). As strong as private fields for outside crates, more machinery,
  nothing gained. Rejected (inferred).
- **One public function that verifies and restores**, with `restore_operator`
  `pub(crate)`. Equally safe and smaller; it loses the step where the binary
  shows the verified replacement before restoring, and the separate errors.
  Open question 6.

## Open questions (for the user or the lead)

1. **The Ed25519 crate (the user's).** `ring` 0.17.14 is already in the lock,
   so making it direct adds no new crate, but couples its version to
   `rustls`; `ed25519-dalek` 2 has `verify_strict` but adds crates. Either is a
   new direct dependency, and the tests need it to sign.
2. Reverse the pick that the registry does not hash, so the library computes
   `request_digest` and `challenge_hash` (section 4)?
3. The format of `M`: the D6 canonical `C` under a recovery prefix (inferred).
4. Refuse small-order or non-canonical recovery keys at bootstrap and at
   rotation? Today only the length is checked (identity-registry :274-276).
   The fixtures that enroll arbitrary 32 bytes (`tests/security/a04.rs:1289`,
   `a48.rs:393` and at least six files under `service/`) would need real
   keys.
5. One `NotVerified` with no detail, or distinct refusals for the operator?
6. Keep `restore_operator` public taking the value, or one combined function?
7. `bootstrap_instance` stays public: it has no signature to check, the local
   channel is its authority (design :666) and it refuses once closed. Whether
   to narrow it is the separate decision of rank 3 in the second-approver
   proposal's survey.
8. The date of the raw-key pick: the docs record 2026-11-21
   (identity-registry :547); the assignment of this proposal said 2026-11-23.

## Reconciliation

Places that call the check the "operator crate"'s, place the verifier in the
binary, or say the registry neither verifies nor hashes. The implementation PR
edits the code and its own docs; the spec rows are the lead's. Nothing here
is edited by this proposal.

| Place                                                         | Says                                                                                                                                                     | Change in the implementation PR                                                                                          |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `service/src/persistence/registry/recovery.rs:15-18`          | "the local recovery verifier builds the restoration plan and calls" the issue                                                                            | the binary's subcommand builds the plan; the issue computes the digest and hash and returns `M`                          |
| `recovery.rs:19-25`                                           | "The registry does not verify signatures: that belongs to the future operator crate"                                                                     | `verify_recovery_response` in this module verifies; `skyoauth-operator` only signs; the binary only carries the response |
| `recovery.rs:90-91`, `:121-124`                               | `challenge_hash` "computed by the caller"; "the registry still does not hash"                                                                            | the library computes both (question 2)                                                                                   |
| `recovery.rs:547-549`, `:569-581`                             | `IssueChallenge::challenge_hash` "computed by the caller"; `ChallengeBinding`                                                                            | fields and type removed                                                                                                  |
| `service/src/persistence/registry/mod.rs:349-352`, `:363-364` | the recovery writers "stay public (how the recovery verifier calls them is an open decision)"; "does not verify a recovery signature (the verifier does" | restore is public only through the value; the library verifies                                                           |
| `service/tests/ungated_writes_private.rs:190-201`             | kept public, "whose verifier is the open decision"                                                                                                       | section 6                                                                                                                |
| `docs/contracts/identity-registry.md:328-332`, `:342-344`     | the caller verifies; "The registry still does not hash"                                                                                                  | the library verifies over `M` rebuilt from the row, and hashes                                                           |
| `identity-registry.md:548-549`                                | "the signature check is not implemented yet"                                                                                                             | names the verify function                                                                                                |
| `tests/security/a32.rs:188-199`, `:238-245`                   | "the registry neither hashes nor verifies"; "The verifier is the only check"                                                                             | the test session rewords                                                                                                 |
| `docs/proposals/second-approver-gated-writes.md:2232-2247`    | the open decision; quotes "belongs to the future operator crate"                                                                                         | points here; closed once ruled                                                                                           |
| `docs/skyoauth-design.md:666`                                 | "The service binary retains only the deployment-local bootstrap/recovery verifier"                                                                       | none needed if "binary" means the package; else the lead adds "(library check, binary transport)"                        |
| `docs/skyoauth-design.md:724`                                 | verifier home: "Existing `skyoauth-service` subcommands"                                                                                                 | none: the subcommands are the entry point                                                                                |
| `docs/skyoauth-tasks.md:30`                                   | "`src/main.rs` Process/listener wiring; M1a local bootstrap/recovery verifier"                                                                           | the lead may add that the check is in the library (tasks :36 plans `src/admin/`)                                         |
| `docs/skyoauth-tasks.md:84`, `:189`; ADR-013 :68-69 (item 7)  | the service binary keeps the verifier                                                                                                                    | as design :666                                                                                                           |

Not affected: "operator tooling" at identity-registry :278, `bootstrap.rs:181`
and the migrations README (:3047) names who canonicalizes an mTLS key, not the
recovery check. The string "operator crate" occurs only at `recovery.rs:23`
and in the second-approver proposal (:2243).
