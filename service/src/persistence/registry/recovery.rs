//! Break-glass operator restoration at the registry level (design section
//! 7.2; ADR-013 item 8; identity-registry section 5.2; lifetimes LT-107;
//! T13.5; `docs/proposals/recovery-verified-response.md`):
//! [`get_recovery_state`] reads the recovery key and its epoch,
//! [`issue_recovery_challenge`] records an expiring challenge and returns
//! the bytes the recovery key signs, [`preview_recovery_response`] checks a
//! signed response without locks or writes, and [`restore_operator`]
//! verifies the signature, consumes the challenge once and, in the same
//! savepoint, enrolls the replacement `security_admin` the challenge names,
//! revokes every operator credential, rotates the recovery key and records
//! the audit events.
//!
//! Every ruling below, a lead's, a user's or an inferred one, is
//! provisional until the maintainer ratifies the ADRs (T00.8 to T00.17,
//! Gate M0).
//!
//! # Flow
//!
//! 1. The service binary's recovery subcommand builds the restoration plan
//!    the deployment operator asks for and calls [`issue_recovery_challenge`]
//!    in a transaction of its own, which computes the request digest and
//!    the challenge hash, records the challenge as an
//!    `administrative_operation` row with its audit event, and returns `M`
//!    (see "What is signed"); the binary commits.
//! 2. The binary hands `M` to the portable workstation, which checks and
//!    displays it and signs it with the offline recovery key
//!    (`skyoauth-operator` only signs); the signed response comes back over
//!    the deployment-local channel. The binary holds no private key and
//!    verifies nothing.
//! 3. In one transaction the binary calls [`restore_operator`] with the
//!    response, optionally after [`preview_recovery_response`], and commits.
//!    **The restore verifies the Ed25519 signature itself**, against the
//!    recovery state and the challenge row it has locked (the user's
//!    ruling, 2026-11-24, the combined shape: no value that stands for
//!    "verified" crosses a call boundary), then consumes the challenge and
//!    restores inside one savepoint. Any failure is an `Err` with the
//!    savepoint rolled back, the consume included: the challenge is then
//!    still unconsumed, and nothing of the restore is left, even if the
//!    caller commits; the caller still rolls back on `Err`. (inferred: the
//!    restore consumes itself, so that one savepoint covers the consume and
//!    the restoration.)
//!
//! The consume is not a function of its own (lead ruling): only
//! [`restore_operator`] consumes a challenge. It is the only thing that
//! makes a challenge single-use (LT-107). It sets `consumed_at` in one
//! `UPDATE` whose `WHERE` holds every condition; the database backs it:
//! the set-once guard `administrative_operation_set_once` refuses a second
//! `consumed_at`, the `administrative_operation_no_consume_after_revoke`
//! guard refuses to consume a revoked challenge (both `SK001`), and
//! `administrative_operation_consumed_before_expiry_check` refuses a
//! consumption at or after `expires_at` (`23514`), even when a statement
//! leaves the predicate out.
//!
//! # What is signed
//!
//! The signed bytes reuse the canonical request `C` of the second-approver
//! flow ([`DigestEnvelope`](crate::operation::DigestEnvelope)) under a
//! prefix of their own (provisional lead pick, 2026-11-24):
//!
//! ```text
//! C              = canonical JSON of {"actor_id": "deployment_operator",
//!                    "expected_revision", "expires_at" (µs, as bound), "id",
//!                    "kind": "operator_restoration", "plan", "tenant_id": null}
//! request_digest = SHA-256("skyoauth.administrative_operation.v1\n" || C)
//! M              = "skyoauth.recovery_challenge.v1\n" || C
//! challenge_hash = SHA-256(M)
//! signature      = Ed25519(recovery private key, M)   (pure, RFC 8032; 64 bytes)
//! ```
//!
//! `C` binds the instance and the key epoch (plan), the replacement (plan),
//! the recovery state's revision and the expiry. The prefix separates `M`
//! from the request digest and from any other use of the key; the
//! signature is over `M`, not its hash. The library computes both
//! `request_digest` and `challenge_hash` (provisional lead pick,
//! 2026-11-24; `0005`'s "the service computes it").
//!
//! # Keys
//!
//! A recovery public key is the raw 32-byte Ed25519 key (identity-registry
//! section 5.2; lead pick dated 2026-11-21, provisional). At every
//! enrollment point, the bootstrap key
//! ([`bootstrap_instance`]), the plan's `new_recovery_public_key` at the
//! issue and again at the restore, a key is refused unless it is 32 bytes
//! that decode to a curve point, encode that point canonically (decoded and
//! re-encoded, the bytes are the same: the crate's decoding accepts
//! non-canonical encodings), and are not of small order (provisional lead
//! pick, 2026-11-24). The current key is checked the same way when a
//! response is verified ([`NotRestorableReason::WeakKey`]), and the
//! signature is checked with `ed25519-dalek`'s `verify_strict`, which also
//! refuses an `S` not below the group order, a non-canonical `R` and a
//! small-order `R` or key.
//!
//! # Issue
//!
//! [`issue_recovery_challenge`] checks its input before any statement (see
//! "Validation"), then, in the caller's [`Transaction`]:
//!
//! 1. reads the `recovery_state` row `FOR SHARE`. No row, or one whose
//!    `bootstrap_closed` is false, is [`ChallengeError::NotIssuable`]; so is
//!    a plan whose `instance_id` or `recovery_key_epoch` is not the row's,
//!    or whose new key is the current one (a restore of it could only meet
//!    [`RestoreError::RecoveryKeyUnchanged`]). `expected_revision` is the
//!    row's `revision`, read here; `C` is computed from exactly the values
//!    the insert binds (the ID, the revision, `expires_at` floored to the
//!    microsecond, the plan), since both hashes are immutable once
//!    inserted;
//! 2. appends the audit event FIRST, because `administrative_operation.audit_id`
//!    is an immediate foreign key (migrations README, "What 0005 adds",
//!    steps 2 and 3): instance scope, actor
//!    `{"type": "operator", "id": "deployment_operator"}` (the local
//!    deployment operator records it; nobody has signed yet; inferred),
//!    action `administrative_operation.create`, `object_id` the operation
//!    ID, `previous_revision` none, `new_revision` 1, outcome `success`;
//! 3. inserts the operation: no tenant, `actor_id` `deployment_operator`,
//!    the kind, the computed digest, the plan and the computed challenge
//!    hash, `expected_revision`, `expires_at = now + ttl`, `audit_id` the
//!    event, outcome `issued`, revision 1, unconsumed and unrevoked. A taken
//!    operation ID is the insert's `23505`, [`RegistryError::AlreadyExists`]
//!    naming `administrative_operation_pkey`.
//!
//! The action name `administrative_operation.create` (inferred) is the
//! `create` verb of any operation insert: the T13.3 operations (an IR-054
//! approval, say) will write the same name, so a consumer that needs the
//! challenge issues joins the event's `object_id` to the operation row and
//! reads its `kind`.
//!
//! `FOR SHARE` (inferred) lets concurrent issues proceed together and makes
//! an issue and a restore wait for each other on the one row, so a
//! challenge is never issued against an epoch a restore is retiring: an
//! issue that waited sees the advanced epoch and is `NotIssuable`. No
//! deadlock: an issue holds the row and then takes the audit head; a
//! restore takes the head last (see "Locks").
//!
//! # The plan
//!
//! The caller builds `immutable_plan`; the registry fills nothing in. It is
//! a JSON object with exactly eight members (lead ruling; closed,
//! provisional lead pick, 2026-11-24): the string `instance_id`, the
//! integer `recovery_key_epoch` (no column), and the replacement the signer
//! approves: the strings `admin_id`, `credential_id`, `binding_id`,
//! `public_identity` and `trust_anchor_ref`, and `new_recovery_public_key`,
//! the new 32-byte key as 64 lowercase hexadecimal digits. A plan with any
//! other member is refused, so the issue never stores a challenge that the
//! workstation would not sign or that no restore could use: a reserved
//! `admin_id`, an empty or over-2048-byte `public_identity` or
//! `trust_anchor_ref`, and a new key refused under "Keys" are refused at
//! the issue too. The plan is kept for the life of the row.
//!
//! # Restore
//!
//! [`restore_operator`] checks its input before any statement, then, inside
//! a savepoint of its own:
//!
//! 0. reads the transaction's `transaction_isolation` and refuses any
//!    value but `read committed` with
//!    [`RestoreError::UnsupportedIsolation`] (lead ruling; see "Locks",
//!    "READ COMMITTED only");
//! 1. locks every unrevoked `admin_credential` row
//!    `FOR NO KEY UPDATE`, in key order, in one statement;
//! 2. locks the `recovery_state` row `FOR NO KEY UPDATE` and reads it; it
//!    must exist and be closed ([`NotRestorableReason::NoRecoveryState`]);
//! 3. reads the challenge row by the response's operation ID
//!    `FOR NO KEY UPDATE` (the lock the consume takes anyway, so the `0005`
//!    order holds) with a query of its own: no registry getter returns the
//!    row (lead ruling). Then, against the locked rows, in this order, each
//!    miss a [`NotRestorableReason`]: the row exists (`NotFound`); it is an
//!    `operator_restoration` of no tenant by `deployment_operator` with
//!    `challenge_hash` set (`WrongKind`); unconsumed (`Consumed`), unrevoked
//!    (`Revoked`), outcome `issued` (`WrongKind`); `now < expires_at`
//!    (`Expired`); its plan's `instance_id` and `recovery_key_epoch` and its
//!    `expected_revision` are the state's (`NotBound`); `C` and `M`, rebuilt
//!    from the row, hash to its stored `request_digest` and `challenge_hash`,
//!    so a row whose stored digest or hash is not the library's encoding of
//!    that row is refused (`NotLibraryEncoding`); the state's key passes the
//!    checks of "Keys" (`WeakKey`); the signature verifies over `M` with the
//!    state's key (`BadSignature`);
//! 4. consumes the challenge (see "Consume"), at `now`, bound to the row's
//!    own values, against the state it holds;
//! 5. takes the replacement from the consumed plan and checks it as the
//!    issue does (see "The plan"; an error of "Validation"), and refuses a
//!    new recovery key equal to the current one,
//!    [`RestoreError::RecoveryKeyUnchanged`]: neither can happen to a
//!    challenge this module issued (its issue refuses both, and the key can
//!    become equal only through a rotation, which advances the epoch and so
//!    retires the challenge), so both stay as defence against a row written
//!    by other means (inferred);
//! 6. revokes every credential still unrevoked, in one statement: sets
//!    `revoked_at = now` and `status = 'disabled'` on every `admin_credential`
//!    row whose `revoked_at` is `NULL`, enabled or not, the credential of the
//!    operator being replaced included. The replacement credential is
//!    created after this statement, so it is not among them. A credential
//!    revoked before keeps its first `revoked_at`;
//! 7. enrolls the replacement with
//!    [`create_admin_identity`](super::create_admin_identity),
//!    [`create_admin_credential`](super::create_admin_credential) and
//!    [`create_admin_role_binding`](super::create_admin_role_binding), as
//!    bootstrap does: an enabled identity created at `now`, an enabled
//!    unrevoked credential and an enabled instance `security_admin`
//!    binding. A taken key is the insert's `23505`,
//!    [`RegistryError::AlreadyExists`] naming `admin_identity_pkey`,
//!    `admin_credential_pkey`, `admin_credential_public_identity_key` (a key
//!    registered before, revoked or not) or `admin_role_binding_pkey`;
//! 8. rotates the key: `recovery_public_key` the new key,
//!    `recovery_key_epoch` and `revision` one more, so the used key is
//!    retired (OQ-TM-8; the `0005` trigger
//!    `skyoauth_check_recovery_key_rotation` requires the epoch to advance
//!    exactly when the key changes). No other path replaces the key
//!    (OQ-TM-15);
//! 9. sets the operation's `outcome` to `restored` and advances its
//!    revision; `consumed_at` stays as the consume set it (`outcome` and
//!    `revision` are the only plain mutable columns of the row);
//! 10. appends two audit events LAST (lead ruling), as for every write that
//!     inserts no operation (the audit-before-operation order applies only
//!     to an operation insert; this operation exists already and has the
//!     issue event), both at instance scope, with the actor
//!     `{"type": "operator", "id": "recovery_key:<epoch>"}`, the epoch of
//!     the key whose signature authorized the restore (the old one), and
//!     outcome `success`: first `admin_identity.restore`, `object_id` the
//!     new operator's ID, revisions none (an identity has no revision);
//!     then `recovery_state.rotate_key`, `object_id` the `instance_id`,
//!     `previous_revision` and `new_revision` the recovery state's before
//!     and after the rotation. The envelope has no member for the
//!     operation's ID, so neither event records it (the operation row's
//!     `consumed_at` equals the events' timestamp).
//!
//! The key that verifies the signature is the one the restore then
//! rotates, read under the same lock in the same database, so no key
//! comparison between two calls is needed. Every refusal of steps 2 and 3
//! is [`RestoreError::NotRestorable`] with its reason, whose `Display` is
//! fixed text and whose `Debug` names the variant and the reason only; the
//! savepoint rollback leaves the challenge unconsumed and nothing written.
//! As for [`select_grant`](super::select_grant), no claim is made about
//! timing.
//!
//! [`preview_recovery_response`] runs steps 2, 3 and 5 without locks, in a
//! savepoint it always rolls back, and returns a [`RecoveryPreview`] for the
//! binary to show the deployment operator. It grants nothing: the restore
//! checks everything again (provisional lead pick, 2026-11-24).
//!
//! It touches no identity or role binding but the new ones, and no
//! workload, trust, grant, audience or token state. It does only what T13.5
//! permits M1a: enroll a replacement `security_admin` credential and revoke
//! operator credentials.
//!
//! # Consume
//!
//! Step 4 of a restore runs one statement, unchanged from before the
//! library verified: `UPDATE administrative_operation SET consumed_at =
//! $now` (and the revision by one) where the ID matches, there is no
//! tenant, the kind is `operator_restoration`, `challenge_hash` is set,
//! `consumed_at` and `revoked_at` are unset, the outcome is still `issued`,
//! `$now < expires_at`, `request_digest`, `challenge_hash` and
//! `expected_revision` equal the row's as step 3 read them, the plan's
//! `instance_id` is a JSON string equal byte-wise (`COLLATE "C"`) to the
//! state's and its `recovery_key_epoch` a JSON number whose text is the
//! state's epoch in decimal, and the `recovery_state` row is closed
//! (`bootstrap_closed`) and has that `instance_id`, that epoch and the
//! row's `expected_revision` as its `revision` (inferred: the challenge is
//! bound to the revision of the state it rotates). Under the locks of steps
//! 2 and 3 it cannot miss after step 3 passed; a miss is still
//! `NotRestorable` ([`NotRestorableReason::Consumed`]). It writes no audit
//! event of its own: the restore's events, in the same savepoint, record it
//! (inferred).
//!
//! # Locks
//!
//! Restore takes its locks in the `0005` order of the migrations README
//! (credentials, the recovery state, then the operation row, at step 3)
//! and the audit head last. An issue takes the
//! recovery state `FOR SHARE` and then the head. A restore waits for an
//! issue holding the row, which does not wait for the restore; an issue
//! waits for a restore holding the row, which does not wait for the issue.
//! Two restores wait on the credentials or the recovery state, and the
//! second then finds the challenge consumed or the epoch advanced:
//! `NotRestorable`. An issue may run at any isolation level: under
//! `REPEATABLE READ` or `SERIALIZABLE`, an issue that waited for a restore
//! fails with `40001` ([`RegistryError::Retry`]) only when the awaited row
//! changed after its snapshot (the restore rotated the key and committed).
//! A wait for a lock alone, on a row nobody changed, ends without `40001`.
//!
//! Step 1 waits for every transaction that holds a credential
//! `FOR SHARE`, the locks of
//! [`authorize_operator_locked`](super::authorize_operator_locked), and
//! step 2 for every operator write that holds the recovery state
//! `FOR SHARE`: the writes that can add operator access lock it (see the
//! operator module, "Writes and a restoration"). Such a write commits
//! before step 6, whose statement, under `READ COMMITTED`, then sees what
//! it enrolled and revokes it; a write that starts after step 2 waits for
//! the restore to commit, and its caller's lookup after the write, under
//! `READ COMMITTED`, then sees the revocation.
//!
//! ## READ COMMITTED only
//!
//! The revocation of step 6 must see a credential that a write committed
//! while the restore waited at step 1 or 2. Under `READ COMMITTED` each
//! statement reads the rows committed before it starts, so it does. Under
//! `REPEATABLE READ` or `SERIALIZABLE` the restore reads its transaction's
//! older snapshot: the write only locked the `recovery_state` row and did
//! not change it, so the restore's lock is granted without `40001`, and the
//! revocation misses the enrolled credential, which stays active (only
//! `SERIALIZABLE` against a `SERIALIZABLE` writer fails with `40001`). So a
//! restore runs only under `READ COMMITTED` (lead ruling): inside its
//! savepoint, before step 1, it reads `transaction_isolation` and refuses
//! any other value with [`RestoreError::UnsupportedIsolation`], which is
//! not retryable as is: the caller retries in a `READ COMMITTED`
//! transaction. `READ UNCOMMITTED`, which PostgreSQL runs as
//! `READ COMMITTED`, is refused as well, since the check compares the
//! setting by name. The refusal writes nothing and leaves the challenge
//! unconsumed and the caller's transaction usable.
//!
//! ## A deadlock that fails closed
//!
//! One cycle of waits remains (accepted, lead ruling): a write that commits
//! after step 1 and before step 2 enrolled a credential that step 1 did not
//! lock. A caller that then follows the documented order on that
//! credential, [`authorize_operator_locked`](super::authorize_operator_locked)
//! (`FOR SHARE`) and then a write (the `recovery_state` row `FOR SHARE`),
//! waits for the restore, which holds the recovery state from step 2, while
//! step 6 waits for the credential the caller holds. PostgreSQL fails one of
//! the two with `40P01` ([`RegistryError::Retry`]), either one. If the
//! restore is the victim, its savepoint is rolled back: nothing of it
//! persists and the challenge stays unconsumed, and its caller retries the
//! whole transaction. If the writer is, its caller denies and rolls back,
//! and the restore revokes the credential. Locking before the authorization
//! would close the cycle but changes the `0005` order; it is a follow-up of
//! the migrations README.
//!
//! # Validation
//!
//! Before any statement, as an encode error ([`RegistryError::Other`] in
//! `Store`, naming no value), as in [`bootstrap_instance`]:
//!
//! - issue: a kind other than `operator_restoration` (the M1a set,
//!   inferred); a plan without a string `instance_id` or an integer
//!   `recovery_key_epoch` (a JSON number that is an `i64`: a fraction or an
//!   integer above `i64::MAX` is refused here, so a plan that passes has a
//!   canonical form), without the five replacement strings, without a
//!   `new_recovery_public_key` of 64 lowercase hexadecimal digits, or with
//!   a member other than the eight; a reserved `admin_id`
//!   ([`RegistryError::ReservedActorId`]); an empty or over-2048-byte
//!   `public_identity` or `trust_anchor_ref`; a new key refused under
//!   "Keys"; a `ttl` below [`MIN_CHALLENGE_TTL`] or above
//!   [`MAX_CHALLENGE_TTL`];
//! - restore and preview: a signature that is not 64 bytes;
//! - all three: a `now` outside the `0007` range, or outside the years
//!   `0000` to `9999` the audit event can carry.
//!
//! Such a failure runs no statement and leaves the transaction usable. The
//! restore's step 5 refuses a stored plan with the same errors, after
//! statements, inside its savepoint.
//!
//! # Time
//!
//! `now` is always the caller's, never the database's `now()`. Expiry is
//! checked against that `now`, at step 3 and again in the consume. The TTL
//! defaults to [`DEFAULT_CHALLENGE_TTL`], 5 minutes, and may be at most
//! [`MAX_CHALLENGE_TTL`], 15 minutes (LT-107; OQ-LT-17, Decided, lead
//! decision 2026-11-19), and at least [`MIN_CHALLENGE_TTL`], 1 second
//! (lead ruling). `expires_at` is `now + ttl`, truncated to the microsecond
//! as every stored time. A restore uses its one `now` for the consume, the
//! revocations, the new operator and its audit events.
//!
//! A restore that waits for a lock still compares the expiry with the `now`
//! it was given, so it can consume a challenge that expired in wall time
//! while it waited (inferred pick). The caller therefore takes `now`
//! immediately before the call and sets `lock_timeout` and
//! `statement_timeout` on its transaction: the overshoot past the expiry is
//! then at most the time the restore's statements may wait, which those
//! two settings bound.
//!
//! The expiry binds only an honest caller's clock: a library caller holding
//! a captured response can pass any `now`. Against such a caller the
//! restore rests on the signature, the single consume and the binding of
//! `C` to the instance, the key epoch and the recovery state revision. A
//! replay of a consumed response fails at step 3 (`Consumed`); after a
//! rotation it fails at step 3 too (`NotBound`), since the epoch and
//! revision in `C` are no longer the state's. Residual (TM-15, an old
//! database backup): on a backup taken after an issue and before its
//! restore, the captured response restores again, and on one taken before
//! the issue, a library caller can issue an identical challenge (same ID,
//! plan and `now`) and replay; a library-generated nonce in the plan would
//! close the second case and is recorded as an option, not built (the
//! user's ruling, 2026-11-24).
//!
//! # Errors and rollback
//!
//! None of these functions commits or rolls back the caller's transaction.
//! Each runs its statements inside a savepoint of its own
//! (`Transaction::begin` on the caller's transaction), releases it on `Ok`
//! and rolls it back on every `Err` (the preview always rolls it back): a
//! refusal, a failed statement, or an error the audit writer returns in
//! Rust after the head lock (a sequence above `2^53 - 1`, say). A caller
//! that commits after an `Err` therefore commits none of the function's
//! rows, and its transaction stays usable. The caller must still roll back
//! on `Err`: a failed savepoint rollback leaves the rows in place. A
//! `23505` of a caller-supplied event ID (`audit_event_pkey`, from the
//! audit writer), of a taken operation ID (`administrative_operation_pkey`)
//! and of the replacement's keys (step 7 of "Restore") is the ordinary
//! [`RegistryError::AlreadyExists`] in `Store`, naming only the
//! constraint. A [`RegistryError::Retry`] in `Store` (`40001`, or `40P01`
//! from the cycle of "Locks") means retrying the whole transaction;
//! [`RestoreError::UnsupportedIsolation`] means retrying it at
//! `READ COMMITTED`.
//!
//! When the commit's outcome is unknown, for example because the
//! connection failed during `COMMIT`, the uncertain-commit rule of
//! [`bootstrap_instance`] applies to [`restore_operator`] too: the caller
//! keeps the response (the operation ID and the signature) and the event
//! IDs until it has reconnected and reconciled the durable state: whether
//! the operation is `restored` and the recovery state is at the new epoch
//! with the new key, or the challenge is still unconsumed. It then retries
//! the same request. A retry of a restoration that committed is
//! [`RestoreError::NotRestorable`] (its challenge is consumed), which with
//! that state means the restoration happened; one that did not commit
//! restores, unless the challenge expired meanwhile: the retry's `now` is
//! later, so it is `NotRestorable` too, with the challenge still
//! unconsumed, and the binary issues a new challenge. A retry of an issue
//! that committed fails with `AlreadyExists` on `audit_event_pkey`.
//!
//! [`bootstrap_instance`]: super::bootstrap_instance

use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{SIGNATURE_LENGTH, Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{
    Connection, FromRow, PgExecutor, Postgres, Row, Transaction,
    postgres::{PgRow, types::PgInterval},
    types::Json,
};

use super::{
    AdminRole, AuditActor, AuditEvent, DEPLOYMENT_OPERATOR_ACTOR, JsonObject, NewAdminCredential,
    NewAdminIdentity, NewAdminRoleBinding, NewAuditEvent, RECOVERY_PUBLIC_KEY_LENGTH,
    RegistryError, Status, append_audit_event, create_admin_credential, create_admin_identity,
    create_admin_role_binding,
    events::{YEAR_OUT_OF_RANGE, in_envelope_years},
    is_reserved_actor_id, micros,
    model::{Origin, json, required_timestamp, since_epoch},
    recovery_key_actor,
};
use crate::operation::{DigestEnvelope, NotCanonical};

/// The TTL of a challenge when the caller has no other: 5 minutes (LT-107;
/// OQ-LT-17, Decided, lead decision 2026-11-19).
pub const DEFAULT_CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// The longest TTL of a challenge: 15 minutes (LT-107; OQ-LT-17, Decided,
/// lead decision 2026-11-19).
pub const MAX_CHALLENGE_TTL: Duration = Duration::from_secs(15 * 60);

/// The shortest TTL of a challenge: 1 second (lead ruling, provisional).
pub const MIN_CHALLENGE_TTL: Duration = Duration::from_secs(1);

/// The one challenge kind of M1a (T13.5; inferred name).
pub const OPERATOR_RESTORATION: &str = "operator_restoration";

/// The plan member that names the instance.
pub const PLAN_INSTANCE_ID: &str = "instance_id";

/// The plan member that names the epoch of the key that must sign.
pub const PLAN_RECOVERY_KEY_EPOCH: &str = "recovery_key_epoch";

/// The plan member that names the replacement operator.
pub const PLAN_ADMIN_ID: &str = "admin_id";

/// The plan member that names the replacement's credential.
pub const PLAN_CREDENTIAL_ID: &str = "credential_id";

/// The plan member that names the replacement's role binding.
pub const PLAN_BINDING_ID: &str = "binding_id";

/// The plan member that holds the replacement credential's
/// `public_identity`.
pub const PLAN_PUBLIC_IDENTITY: &str = "public_identity";

/// The plan member that holds the replacement credential's
/// `trust_anchor_ref`.
pub const PLAN_TRUST_ANCHOR_REF: &str = "trust_anchor_ref";

/// The plan member that holds the new recovery public key, 64 lowercase
/// hexadecimal digits.
pub const PLAN_NEW_RECOVERY_PUBLIC_KEY: &str = "new_recovery_public_key";

/// The domain-separation prefix of the signed challenge `M`, with its
/// newline (see the module docs, "What is signed").
const CHALLENGE_PREFIX: &[u8] = b"skyoauth.recovery_challenge.v1\n";

/// The action of the issue event (inferred; see the module docs).
const ISSUE_ACTION: &str = "administrative_operation.create";

/// The action of the first restore event (identity-registry IR-059).
const RESTORE_ACTION: &str = "admin_identity.restore";

/// The action of the second restore event (identity-registry IR-059).
const ROTATE_ACTION: &str = "recovery_state.rotate_key";

/// The outcome of an issued challenge (inferred).
const ISSUED: &str = "issued";

/// The outcome of a challenge whose restore ran (inferred).
const RESTORED: &str = "restored";

/// The outcome of the events (inferred, as for bootstrap).
const SUCCESS: &str = "success";

/// The revision of a new operation row (`0005`).
const FIRST_REVISION: i64 = 1;

/// The longest `public_identity` and `trust_anchor_ref`, in bytes (`0005`).
const MAX_EXACT_STRING: usize = 2048;

/// The encode error of a key that is not 32 bytes.
const KEY_LENGTH: &str = "recovery public key is not a 32-byte Ed25519 key";

/// The encode error of 32 bytes that decode to no curve point.
const KEY_UNDECODABLE: &str = "recovery public key is not an Ed25519 point";

/// The encode error of a point encoded non-canonically.
const KEY_NOT_CANONICAL: &str = "recovery public key is not canonically encoded";

/// The encode error of a point of small order (a weak key).
const KEY_SMALL_ORDER: &str = "recovery public key is a small-order Ed25519 point";

/// The recovery state row: its columns.
macro_rules! state_columns {
    () => {
        "SELECT instance_id, bootstrap_closed, recovery_public_key, recovery_key_epoch, revision \
         FROM recovery_state"
    };
}

const READ_RECOVERY_STATE: &str = state_columns!();

/// Step 1 of an issue: the row, shared (see the module docs).
const SHARE_RECOVERY_STATE: &str = concat!(state_columns!(), " FOR SHARE");

/// Step 2 of a restore: the row, locked for the rotation.
const LOCK_RECOVERY_STATE: &str = concat!(state_columns!(), " FOR NO KEY UPDATE");

/// The challenge row step 3 of a restore checks: its columns, by ID.
macro_rules! challenge_columns {
    () => {
        concat!(
            "SELECT id, tenant_id, actor_id, kind, request_digest, expected_revision, \
             immutable_plan, challenge_hash, consumed_at IS NOT NULL AS consumed, \
             revoked_at IS NOT NULL AS revoked, outcome, ",
            micros!("expires_at"),
            " FROM administrative_operation WHERE id = $1"
        )
    };
}

/// The preview's read of the challenge row: no lock.
const READ_CHALLENGE: &str = challenge_columns!();

/// Step 3 of a restore: the challenge row, locked as the consume locks it.
const LOCK_CHALLENGE: &str = concat!(challenge_columns!(), " FOR NO KEY UPDATE");

const INSERT_CHALLENGE: &str = concat!(
    "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
     expected_revision, immutable_plan, challenge_hash, expires_at, outcome, audit_id) \
     VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, timestamptz 'epoch' + $8::interval, $9, $10) \
     RETURNING id, expected_revision, ",
    micros!("expires_at")
);

/// Step 4 of a restore. `$1` the ID, `$2` `now`, `$3` the digest, `$4` the
/// expected revision, `$5` the instance, `$6` the epoch and `$7` the
/// challenge hash.
const CONSUME_CHALLENGE: &str = "UPDATE administrative_operation \
     SET consumed_at = timestamptz 'epoch' + $2::interval, revision = revision + 1 \
     WHERE id = $1 \
       AND tenant_id IS NULL \
       AND kind = 'operator_restoration' \
       AND challenge_hash IS NOT NULL \
       AND consumed_at IS NULL \
       AND revoked_at IS NULL \
       AND outcome = 'issued' \
       AND timestamptz 'epoch' + $2::interval < expires_at \
       AND request_digest = $3 \
       AND challenge_hash = $7 \
       AND expected_revision = $4 \
       AND jsonb_typeof(immutable_plan -> 'instance_id') = 'string' \
       AND immutable_plan ->> 'instance_id' = $5 COLLATE \"C\" \
       AND jsonb_typeof(immutable_plan -> 'recovery_key_epoch') = 'number' \
       AND immutable_plan ->> 'recovery_key_epoch' = $6::bigint::text \
       AND EXISTS (SELECT FROM recovery_state r WHERE r.bootstrap_closed \
         AND r.instance_id = $5 AND r.recovery_key_epoch = $6 AND r.revision = $4) \
     RETURNING immutable_plan";

/// Step 0 of a restore: the transaction's isolation level.
const TRANSACTION_ISOLATION: &str = "SELECT current_setting('transaction_isolation')";

/// The one isolation level a restore runs at, as `transaction_isolation`
/// names it.
const READ_COMMITTED: &str = "read committed";

/// Step 1 of a restore: every unrevoked credential, in key order.
const LOCK_CREDENTIALS: &str = "SELECT id FROM admin_credential WHERE revoked_at IS NULL \
     ORDER BY id COLLATE \"C\" FOR NO KEY UPDATE";

/// Step 6 of a restore: one statement for every unrevoked credential.
const REVOKE_ALL_CREDENTIALS: &str = "UPDATE admin_credential \
     SET status = 'disabled', revoked_at = timestamptz 'epoch' + $1::interval \
     WHERE revoked_at IS NULL RETURNING id";

/// Step 8 of a restore. `$1` the instance, `$2` the new key, `$3` the
/// current epoch.
const ROTATE_RECOVERY_KEY: &str = "UPDATE recovery_state \
     SET recovery_public_key = $2, recovery_key_epoch = recovery_key_epoch + 1, \
         revision = revision + 1 \
     WHERE instance_id = $1 AND recovery_key_epoch = $3 \
     RETURNING recovery_key_epoch, revision";

/// Step 9 of a restore.
const MARK_RESTORED: &str = "UPDATE administrative_operation \
     SET outcome = $2, revision = revision + 1 WHERE id = $1 RETURNING revision";

/// The `recovery_state` row (`0005`), written by bootstrap and rotated by
/// [`restore_operator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryState {
    pub instance_id: String,
    pub bootstrap_closed: bool,
    /// The current recovery public key, the raw 32-byte Ed25519 key of the
    /// identity-registry section 5.2 pick (the database allows 1 to 8192
    /// bytes).
    pub recovery_public_key: Vec<u8>,
    /// The epoch of that key; 1 for the bootstrap key.
    pub recovery_key_epoch: i64,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for RecoveryState {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            instance_id: row.try_get("instance_id")?,
            bootstrap_closed: row.try_get("bootstrap_closed")?,
            recovery_public_key: row.try_get("recovery_public_key")?,
            recovery_key_epoch: row.try_get("recovery_key_epoch")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of [`issue_recovery_challenge`]. Every value is the caller's;
/// the registry computes the request digest and the challenge hash.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IssueChallenge<'a> {
    pub operation_id: &'a str,
    /// [`OPERATOR_RESTORATION`], the only kind of M1a.
    pub kind: &'a str,
    /// A JSON object with exactly the eight members of a restoration: the
    /// string [`PLAN_INSTANCE_ID`], the integer [`PLAN_RECOVERY_KEY_EPOCH`]
    /// and the replacement (see the module docs, "The plan"); no secrets.
    pub immutable_plan: &'a JsonObject,
    /// [`MIN_CHALLENGE_TTL`] to [`MAX_CHALLENGE_TTL`];
    /// [`DEFAULT_CHALLENGE_TTL`] unless the caller has a reason.
    pub ttl: Duration,
    pub now: SystemTime,
    pub audit_event_id: &'a str,
}

/// What [`issue_recovery_challenge`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryChallenge {
    pub operation_id: String,
    /// `now + ttl`, as stored (truncated to the microsecond).
    pub expires_at: SystemTime,
    /// The `recovery_state` revision read in the transaction.
    pub expected_revision: i64,
    /// `M`, the bytes the workstation displays and signs with the recovery
    /// key (see the module docs, "What is signed"). Public: it holds the
    /// plan, the ID, the revision and the expiry, no secret.
    pub challenge: Vec<u8>,
    /// The `administrative_operation.create` event.
    pub audit_event: AuditEvent,
}

/// Why a challenge was not issued.
///
/// Values compare equal when they are the same unit variant; a `Store`
/// value never compares equal, since [`RegistryError`] has no equality.
#[derive(Debug)]
pub enum ChallengeError {
    /// No closed recovery state, the plan names another instance or epoch,
    /// or its new key is the current one. No detail.
    NotIssuable,
    /// Invalid input or a store failure. [`RegistryError::Retry`] means
    /// retry the whole transaction.
    Store(RegistryError),
}

impl PartialEq for ChallengeError {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Self::NotIssuable, Self::NotIssuable))
    }
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotIssuable => f.write_str("a recovery challenge cannot be issued"),
            Self::Store(err) => write!(f, "recovery challenge failed: {err}"),
        }
    }
}

impl std::error::Error for ChallengeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotIssuable => None,
            Self::Store(err) => Some(err),
        }
    }
}

impl From<RegistryError> for ChallengeError {
    fn from(err: RegistryError) -> Self {
        Self::Store(err)
    }
}

impl From<sqlx::Error> for ChallengeError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

/// A signed recovery response, as the workstation returned it: untrusted
/// input. `Debug` prints neither the ID nor the signature.
#[derive(Clone, Copy)]
pub struct SignedRecoveryResponse<'a> {
    /// The restoration challenge the signature answers.
    pub operation_id: &'a str,
    /// The Ed25519 signature over the challenge's `M`, 64 bytes.
    pub signature: &'a [u8],
}

impl fmt::Debug for SignedRecoveryResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedRecoveryResponse")
            .finish_non_exhaustive()
    }
}

/// The input of [`restore_operator`] besides the response: the event IDs
/// (T10.2) and the time. The replacement is the challenge's plan's, never
/// the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreRequest<'a> {
    /// The ID of the `admin_identity.restore` event.
    pub audit_event_id: &'a str,
    /// The ID of the `recovery_state.rotate_key` event.
    pub rotation_audit_event_id: &'a str,
    /// The time of the consume, the revocations, the new operator and the
    /// audit events, taken immediately before the call (see the module
    /// docs, "Time").
    pub now: SystemTime,
}

/// What [`restore_operator`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    /// The credentials step 6 revoked, sorted byte-wise.
    pub revoked_credential_ids: Vec<String>,
    /// The new epoch, one more than the used key's.
    pub recovery_key_epoch: i64,
    /// The recovery state's new revision.
    pub recovery_state_revision: i64,
    /// The `admin_identity.restore` event.
    pub audit_event: AuditEvent,
    /// The `recovery_state.rotate_key` event, right after it.
    pub rotation_audit_event: AuditEvent,
}

/// What [`preview_recovery_response`] found: a plain summary for the
/// binary to show the deployment operator. It grants nothing. `Debug`
/// prints none of its values.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPreview {
    /// The replacement operator the plan names.
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    /// The epoch the new recovery key would have, one more than the
    /// current one.
    pub new_recovery_key_epoch: i64,
    /// The challenge's expiry, as stored.
    pub expires_at: SystemTime,
}

impl fmt::Debug for RecoveryPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryPreview").finish_non_exhaustive()
    }
}

/// Why a response does not authorize a restoration (see the module docs,
/// "Restore", step 3). `Debug` names the variant only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotRestorableReason {
    /// There is no closed recovery state.
    NoRecoveryState,
    /// No operation has the response's ID.
    NotFound,
    /// The challenge was already consumed.
    Consumed,
    /// The challenge was revoked.
    Revoked,
    /// `now >= expires_at`.
    Expired,
    /// Not an issued `operator_restoration` challenge of no tenant by
    /// `deployment_operator`.
    WrongKind,
    /// The plan's instance or epoch, or the expected revision, is not the
    /// recovery state's.
    NotBound,
    /// The stored request digest or challenge hash is not the library's
    /// encoding of the row.
    NotLibraryEncoding,
    /// The current recovery key is not usable: not 32 bytes, not a
    /// canonically encoded point, or of small order.
    WeakKey,
    /// The signature does not verify over the challenge with the current
    /// recovery key.
    BadSignature,
}

/// Why [`restore_operator`] or [`preview_recovery_response`] did not
/// succeed. On every variant the savepoint is rolled back; the caller rolls
/// back too.
///
/// `Display` is fixed text per variant (and per reason of
/// [`Self::NotRestorable`]) and `Debug` names the variant and the reason;
/// neither holds an ID, a public identity, the plan, a digest or the
/// signature. Values compare equal when they are the same unit variant or
/// `NotRestorable` with the same reason; a `Store` value never compares
/// equal.
#[derive(Debug)]
pub enum RestoreError {
    /// The response does not authorize a restoration: see the reason.
    NotRestorable(NotRestorableReason),
    /// The new recovery key is the current one, which must be retired.
    RecoveryKeyUnchanged,
    /// The caller's transaction does not run at `READ COMMITTED`, the only
    /// level at which a restore sees every enrolled credential (see the
    /// module docs, "READ COMMITTED only"). Not retryable as is: the caller
    /// retries in a `READ COMMITTED` transaction. No detail.
    UnsupportedIsolation,
    /// Invalid input or a store failure; see the module docs.
    Store(RegistryError),
}

impl PartialEq for RestoreError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NotRestorable(a), Self::NotRestorable(b)) => a == b,
            (Self::RecoveryKeyUnchanged, Self::RecoveryKeyUnchanged)
            | (Self::UnsupportedIsolation, Self::UnsupportedIsolation) => true,
            _ => false,
        }
    }
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRestorable(reason) => f.write_str(match reason {
                NotRestorableReason::NoRecoveryState => "there is no closed recovery state",
                NotRestorableReason::NotFound => "no such recovery challenge",
                NotRestorableReason::Consumed => "the recovery challenge was already used",
                NotRestorableReason::Revoked => "the recovery challenge was revoked",
                NotRestorableReason::Expired => "the recovery challenge has expired",
                NotRestorableReason::WrongKind => {
                    "the operation is not an issued operator restoration challenge"
                }
                NotRestorableReason::NotBound => {
                    "the recovery challenge is not bound to the current recovery state"
                }
                NotRestorableReason::NotLibraryEncoding => {
                    "the recovery challenge's stored digest or hash is not its encoding"
                }
                NotRestorableReason::WeakKey => "the current recovery public key is not usable",
                NotRestorableReason::BadSignature => {
                    "the signature does not verify with the current recovery key"
                }
            }),
            Self::RecoveryKeyUnchanged => {
                f.write_str("the new recovery public key is the current one")
            }
            Self::UnsupportedIsolation => {
                f.write_str("operator restoration runs only at READ COMMITTED")
            }
            Self::Store(err) => write!(f, "operator restoration failed: {err}"),
        }
    }
}

impl std::error::Error for RestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotRestorable(_) | Self::RecoveryKeyUnchanged | Self::UnsupportedIsolation => {
                None
            }
            Self::Store(err) => Some(err),
        }
    }
}

impl From<RegistryError> for RestoreError {
    fn from(err: RegistryError) -> Self {
        Self::Store(err)
    }
}

impl From<sqlx::Error> for RestoreError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

impl From<NotRestorableReason> for RestoreError {
    fn from(reason: NotRestorableReason) -> Self {
        Self::NotRestorable(reason)
    }
}

fn encode_error(message: &'static str) -> RegistryError {
    sqlx::Error::Encode(message.into()).into()
}

/// `now` as the interval a statement adds to `timestamptz 'epoch'`, when it
/// lies in the years the audit event carries.
fn audit_time(now: SystemTime) -> Result<PgInterval, RegistryError> {
    let interval = since_epoch(now)?;
    if !in_envelope_years(interval.microseconds) {
        return Err(encode_error(YEAR_OUT_OF_RANGE));
    }
    Ok(interval)
}

/// The time `microseconds` after the Unix epoch (before it when
/// negative), or `None` when `SystemTime` cannot hold it.
fn from_micros(microseconds: i64) -> Option<SystemTime> {
    let magnitude = Duration::from_micros(microseconds.unsigned_abs());
    if microseconds >= 0 {
        UNIX_EPOCH.checked_add(magnitude)
    } else {
        UNIX_EPOCH.checked_sub(magnitude)
    }
}

/// Whether `value` is 1 to 2048 bytes.
fn bounded(value: &str) -> bool {
    (1..=MAX_EXACT_STRING).contains(&value.len())
}

/// The recovery key in `bytes`, if it passes the checks of the module
/// docs, "Keys": 32 bytes, a point, canonically encoded, not of small
/// order. Otherwise the fixed message of the first check it fails. Shared
/// with [`bootstrap_instance`](super::bootstrap_instance).
pub(super) fn recovery_key(bytes: &[u8]) -> Result<VerifyingKey, &'static str> {
    let bytes: &[u8; RECOVERY_PUBLIC_KEY_LENGTH] = bytes.try_into().map_err(|_| KEY_LENGTH)?;
    // ZIP-215 decoding: accepts a `y` at or above the field prime and a
    // negative zero `x`, so the re-encoding below is the canonical check.
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| KEY_UNDECODABLE)?;
    if key.to_edwards().compress().as_bytes() != bytes {
        return Err(KEY_NOT_CANONICAL);
    }
    if key.is_weak() {
        return Err(KEY_SMALL_ORDER);
    }
    Ok(key)
}

/// Whether `signature` verifies over `message` with the recovery key
/// `key` (step 3 of a restore): [`NotRestorableReason::WeakKey`] for a key
/// [`recovery_key`] refuses, [`NotRestorableReason::BadSignature`] for a
/// signature `verify_strict` refuses.
fn verify_signature(
    key: &[u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_LENGTH],
) -> Result<(), NotRestorableReason> {
    let key = recovery_key(key).map_err(|_| NotRestorableReason::WeakKey)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| NotRestorableReason::BadSignature)
}

/// `C`, `M` and their hashes (see the module docs, "What is signed").
#[derive(Debug, PartialEq, Eq)]
struct Encoded {
    request_digest: [u8; 32],
    challenge: Vec<u8>,
    challenge_hash: [u8; 32],
}

/// Encodes the challenge with this ID, expected revision, expiry (whole
/// microseconds since the Unix epoch) and plan.
fn encode_challenge(
    id: &str,
    expected_revision: i64,
    expires_at_us: i64,
    plan: &JsonObject,
) -> Result<Encoded, NotCanonical> {
    let envelope = DigestEnvelope {
        id,
        tenant_id: None,
        actor_id: DEPLOYMENT_OPERATOR_ACTOR,
        kind: OPERATOR_RESTORATION,
        expected_revision,
        expires_at_us,
        plan,
    };
    let canonical = envelope.canonical_json()?;
    let mut challenge = Vec::with_capacity(CHALLENGE_PREFIX.len() + canonical.len());
    challenge.extend_from_slice(CHALLENGE_PREFIX);
    challenge.extend_from_slice(canonical.as_bytes());
    Ok(Encoded {
        request_digest: *envelope.digest()?.as_bytes(),
        challenge_hash: Sha256::digest(&challenge).into(),
        challenge,
    })
}

/// The eight members of a restoration plan.
const PLAN_MEMBERS: [&str; 8] = [
    PLAN_INSTANCE_ID,
    PLAN_RECOVERY_KEY_EPOCH,
    PLAN_ADMIN_ID,
    PLAN_CREDENTIAL_ID,
    PLAN_BINDING_ID,
    PLAN_PUBLIC_IDENTITY,
    PLAN_TRUST_ANCHOR_REF,
    PLAN_NEW_RECOVERY_PUBLIC_KEY,
];

/// A plan that passed [`parse_plan`].
#[derive(Debug, PartialEq, Eq)]
struct Plan<'a> {
    instance_id: &'a str,
    recovery_key_epoch: i64,
    admin_id: &'a str,
    credential_id: &'a str,
    binding_id: &'a str,
    public_identity: &'a str,
    trust_anchor_ref: &'a str,
    new_recovery_public_key: [u8; RECOVERY_PUBLIC_KEY_LENGTH],
}

/// The plan's instance and epoch: a string and an `i64` JSON integer.
fn plan_binding(plan: &JsonObject) -> Option<(&str, i64)> {
    let instance_id = plan.get(PLAN_INSTANCE_ID).and_then(Value::as_str)?;
    let epoch = plan.get(PLAN_RECOVERY_KEY_EPOCH).and_then(Value::as_i64)?;
    Some((instance_id, epoch))
}

/// The string member `name` of `plan`.
fn plan_text<'a>(plan: &'a JsonObject, name: &str) -> Option<&'a str> {
    plan.get(name).and_then(Value::as_str)
}

/// The value of one lowercase hexadecimal digit.
fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The key in the plan's form, 64 lowercase hexadecimal digits, as bytes.
fn plan_key(value: &str) -> Option<[u8; RECOVERY_PUBLIC_KEY_LENGTH]> {
    let digits = value.as_bytes();
    if digits.len() != 2 * RECOVERY_PUBLIC_KEY_LENGTH {
        return None;
    }
    let mut key = [0; RECOVERY_PUBLIC_KEY_LENGTH];
    for (byte, [high, low]) in key.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = (hex_digit(*high)? << 4) | hex_digit(*low)?;
    }
    Some(key)
}

/// The checks of a restoration plan (see the module docs, "The plan" and
/// "Validation"), at the issue, the preview and step 5 of the restore.
fn parse_plan(plan: &JsonObject) -> Result<Plan<'_>, RegistryError> {
    let Some((instance_id, recovery_key_epoch)) = plan_binding(plan) else {
        return Err(encode_error(
            "plan lacks a string instance_id or an integer recovery_key_epoch",
        ));
    };
    let text = |name| plan_text(plan, name);
    let (
        Some(admin_id),
        Some(credential_id),
        Some(binding_id),
        Some(public_identity),
        Some(trust_anchor_ref),
    ) = (
        text(PLAN_ADMIN_ID),
        text(PLAN_CREDENTIAL_ID),
        text(PLAN_BINDING_ID),
        text(PLAN_PUBLIC_IDENTITY),
        text(PLAN_TRUST_ANCHOR_REF),
    )
    else {
        return Err(encode_error(
            "plan lacks a string admin_id, credential_id, binding_id, public_identity or \
             trust_anchor_ref",
        ));
    };
    let Some(new_recovery_public_key) = text(PLAN_NEW_RECOVERY_PUBLIC_KEY).and_then(plan_key)
    else {
        return Err(encode_error(
            "plan new_recovery_public_key is not 64 lowercase hexadecimal digits",
        ));
    };
    // The eight are present, so any other member makes the plan longer.
    if plan.len() != PLAN_MEMBERS.len() {
        return Err(encode_error(
            "plan has a member other than the eight of an operator restoration",
        ));
    }
    if is_reserved_actor_id(admin_id) {
        return Err(RegistryError::ReservedActorId);
    }
    if !bounded(public_identity) {
        return Err(encode_error("public identity is empty or over 2048 bytes"));
    }
    if !bounded(trust_anchor_ref) {
        return Err(encode_error(
            "trust anchor reference is empty or over 2048 bytes",
        ));
    }
    recovery_key(&new_recovery_public_key).map_err(encode_error)?;
    Ok(Plan {
        instance_id,
        recovery_key_epoch,
        admin_id,
        credential_id,
        binding_id,
        public_identity,
        trust_anchor_ref,
        new_recovery_public_key,
    })
}

/// The checks of an issue that run before any statement: `expires_at` as
/// an interval, and the plan.
fn validate_issue<'a>(
    request: &IssueChallenge<'a>,
) -> Result<(PgInterval, Plan<'a>), RegistryError> {
    if request.kind != OPERATOR_RESTORATION {
        return Err(encode_error(
            "recovery challenge kind is not operator_restoration",
        ));
    }
    let plan = parse_plan(request.immutable_plan)?;
    if request.ttl < MIN_CHALLENGE_TTL || request.ttl > MAX_CHALLENGE_TTL {
        return Err(encode_error("challenge TTL is not 1 second to 15 minutes"));
    }
    audit_time(request.now)?;
    let expires_at = request
        .now
        .checked_add(request.ttl)
        .ok_or_else(|| encode_error("timestamp out of range"))?;
    Ok((since_epoch(expires_at)?, plan))
}

/// The checks of a restore or a preview that run before any statement: the
/// signature as 64 bytes and `now` as an interval.
fn validate_response(
    response: &SignedRecoveryResponse<'_>,
    now: SystemTime,
) -> Result<([u8; SIGNATURE_LENGTH], PgInterval), RegistryError> {
    let signature = response
        .signature
        .try_into()
        .map_err(|_| encode_error("recovery signature is not 64 bytes"))?;
    Ok((signature, audit_time(now)?))
}

/// Reads the recovery state, or `None` before bootstrap. Takes no lock.
pub async fn get_recovery_state<'e>(
    executor: impl PgExecutor<'e>,
) -> Result<Option<RecoveryState>, RegistryError> {
    Ok(sqlx::query_as(READ_RECOVERY_STATE)
        .fetch_optional(executor)
        .await?)
}

/// Records a recovery challenge in `transaction`: the audit event, then the
/// operation (see the module docs), and returns `M` for the workstation.
/// Never commits or rolls back the caller's transaction, only its own
/// savepoint, which it rolls back on every `Err`.
pub async fn issue_recovery_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    request: &IssueChallenge<'_>,
) -> Result<RecoveryChallenge, ChallengeError> {
    let (expires_at, plan) = validate_issue(request)?;
    let mut savepoint = transaction.begin().await?;
    match issue_steps(&mut savepoint, request, expires_at, &plan).await {
        Ok(challenge) => {
            savepoint.commit().await?;
            Ok(challenge)
        }
        Err(err) => {
            // The step's error says more than a failed savepoint rollback.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}

/// Steps 1 to 3 of an issue, in the savepoint of
/// [`issue_recovery_challenge`].
async fn issue_steps(
    transaction: &mut Transaction<'_, Postgres>,
    request: &IssueChallenge<'_>,
    expires_at: PgInterval,
    plan: &Plan<'_>,
) -> Result<RecoveryChallenge, ChallengeError> {
    // Step 1: the closed recovery state, shared.
    let state: Option<RecoveryState> = sqlx::query_as(SHARE_RECOVERY_STATE)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(state) = state.filter(|state| state.bootstrap_closed) else {
        return Err(ChallengeError::NotIssuable);
    };
    if state.instance_id != plan.instance_id
        || state.recovery_key_epoch != plan.recovery_key_epoch
        || state.recovery_public_key[..] == plan.new_recovery_public_key[..]
    {
        return Err(ChallengeError::NotIssuable);
    }
    // `C` from exactly the values the insert binds.
    let encoded = encode_challenge(
        request.operation_id,
        state.revision,
        expires_at.microseconds,
        request.immutable_plan,
    )
    .map_err(|NotCanonical| encode_error("plan has no canonical form"))?;

    // Step 2: the event, before the operation that references it.
    let audit_event = append_audit_event(
        transaction,
        &NewAuditEvent {
            id: request.audit_event_id.into(),
            tenant_id: None,
            timestamp: request.now,
            actor: AuditActor::Operator(DEPLOYMENT_OPERATOR_ACTOR.into()),
            action: ISSUE_ACTION.into(),
            object_id: request.operation_id.into(),
            previous_revision: None,
            new_revision: Some(FIRST_REVISION),
            outcome: SUCCESS.into(),
        },
    )
    .await?;

    // Step 3: the operation.
    let row = sqlx::query(INSERT_CHALLENGE)
        .bind(request.operation_id)
        .bind(DEPLOYMENT_OPERATOR_ACTOR)
        .bind(request.kind)
        .bind(&encoded.request_digest[..])
        .bind(state.revision)
        .bind(Json(request.immutable_plan))
        .bind(&encoded.challenge_hash[..])
        .bind(expires_at)
        .bind(ISSUED)
        .bind(&audit_event.id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(RecoveryChallenge {
        operation_id: row.try_get("id")?,
        expires_at: required_timestamp(
            &row,
            Origin::new("administrative_operation"),
            "expires_at",
        )?,
        expected_revision: row.try_get("expected_revision")?,
        challenge: encoded.challenge,
        audit_event,
    })
}

/// The challenge row step 3 of a restore checks.
struct ChallengeRow {
    id: String,
    tenant_id: Option<String>,
    actor_id: String,
    kind: String,
    request_digest: Vec<u8>,
    expected_revision: i64,
    immutable_plan: JsonObject,
    challenge_hash: Option<Vec<u8>>,
    consumed: bool,
    revoked: bool,
    outcome: String,
    /// The stored expiry in whole microseconds, as `C` carries it.
    expires_at_us: i64,
}

impl FromRow<'_, PgRow> for ChallengeRow {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            actor_id: row.try_get("actor_id")?,
            kind: row.try_get("kind")?,
            request_digest: row.try_get("request_digest")?,
            expected_revision: row.try_get("expected_revision")?,
            immutable_plan: json(row, "immutable_plan")?,
            challenge_hash: row.try_get("challenge_hash")?,
            consumed: row.try_get("consumed")?,
            revoked: row.try_get("revoked")?,
            outcome: row.try_get("outcome")?,
            expires_at_us: row.try_get("expires_at_us")?,
        })
    }
}

/// The checks of step 3 against the state and the challenge row, in the
/// order of the module docs; shared by the restore and the preview.
fn check_challenge(
    state: &RecoveryState,
    row: &ChallengeRow,
    signature: &[u8; SIGNATURE_LENGTH],
    now: PgInterval,
) -> Result<(), NotRestorableReason> {
    let Some(challenge_hash) = row.challenge_hash.as_deref() else {
        return Err(NotRestorableReason::WrongKind);
    };
    if row.kind != OPERATOR_RESTORATION
        || row.tenant_id.is_some()
        || row.actor_id != DEPLOYMENT_OPERATOR_ACTOR
    {
        return Err(NotRestorableReason::WrongKind);
    }
    if row.consumed {
        return Err(NotRestorableReason::Consumed);
    }
    if row.revoked {
        return Err(NotRestorableReason::Revoked);
    }
    if row.outcome != ISSUED {
        return Err(NotRestorableReason::WrongKind);
    }
    if now.microseconds >= row.expires_at_us {
        return Err(NotRestorableReason::Expired);
    }
    if plan_binding(&row.immutable_plan) != Some((&state.instance_id[..], state.recovery_key_epoch))
        || row.expected_revision != state.revision
    {
        return Err(NotRestorableReason::NotBound);
    }
    let encoded = encode_challenge(
        &row.id,
        row.expected_revision,
        row.expires_at_us,
        &row.immutable_plan,
    )
    .map_err(|NotCanonical| NotRestorableReason::NotLibraryEncoding)?;
    if row.request_digest[..] != encoded.request_digest[..]
        || challenge_hash != &encoded.challenge_hash[..]
    {
        return Err(NotRestorableReason::NotLibraryEncoding);
    }
    verify_signature(&state.recovery_public_key, &encoded.challenge, signature)
}

/// Checks a signed response as [`restore_operator`] would, at `now`,
/// without locks or writes (see the module docs, "Restore"), and returns
/// what a restore would enroll. It grants nothing: the restore checks
/// everything again. Its statements run in a savepoint it always rolls
/// back; it never commits or rolls back the caller's transaction.
pub async fn preview_recovery_response(
    transaction: &mut Transaction<'_, Postgres>,
    response: &SignedRecoveryResponse<'_>,
    now: SystemTime,
) -> Result<RecoveryPreview, RestoreError> {
    let (signature, now) = validate_response(response, now)?;
    let mut savepoint = transaction.begin().await?;
    let preview = preview_steps(&mut savepoint, response, &signature, now).await;
    // Read-only: nothing to keep. The step's error says more than a failed
    // rollback.
    let rolled_back = savepoint.rollback().await;
    let preview = preview?;
    rolled_back?;
    Ok(preview)
}

/// Steps 2, 3 and 5 of a restore without locks, in the savepoint of
/// [`preview_recovery_response`].
async fn preview_steps(
    transaction: &mut Transaction<'_, Postgres>,
    response: &SignedRecoveryResponse<'_>,
    signature: &[u8; SIGNATURE_LENGTH],
    now: PgInterval,
) -> Result<RecoveryPreview, RestoreError> {
    let state: Option<RecoveryState> = sqlx::query_as(READ_RECOVERY_STATE)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(state) = state.filter(|state| state.bootstrap_closed) else {
        return Err(NotRestorableReason::NoRecoveryState.into());
    };
    let row: Option<ChallengeRow> = sqlx::query_as(READ_CHALLENGE)
        .bind(response.operation_id)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(row) = row else {
        return Err(NotRestorableReason::NotFound.into());
    };
    check_challenge(&state, &row, signature, now)?;
    let plan = parse_plan(&row.immutable_plan)?;
    if state.recovery_public_key[..] == plan.new_recovery_public_key[..] {
        return Err(RestoreError::RecoveryKeyUnchanged);
    }
    let new_recovery_key_epoch = state
        .recovery_key_epoch
        .checked_add(1)
        .ok_or_else(|| encode_error("recovery key epoch out of range"))?;
    let expires_at =
        from_micros(row.expires_at_us).ok_or_else(|| encode_error("timestamp out of range"))?;
    Ok(RecoveryPreview {
        admin_id: plan.admin_id.into(),
        credential_id: plan.credential_id.into(),
        binding_id: plan.binding_id.into(),
        new_recovery_key_epoch,
        expires_at,
    })
}

/// The consume statement, bound to the checked row and the locked state:
/// the consumed challenge's plan, or `None` on any miss (see the module
/// docs, "Consume").
async fn consume(
    transaction: &mut Transaction<'_, Postgres>,
    state: &RecoveryState,
    row: &ChallengeRow,
    now: PgInterval,
) -> Result<Option<JsonObject>, sqlx::Error> {
    let consumed = sqlx::query(CONSUME_CHALLENGE)
        .bind(&row.id)
        .bind(now)
        .bind(&row.request_digest)
        .bind(row.expected_revision)
        .bind(&state.instance_id)
        .bind(state.recovery_key_epoch)
        .bind(&row.challenge_hash)
        .fetch_optional(&mut **transaction)
        .await?;
    consumed.map(|row| json(&row, "immutable_plan")).transpose()
}

/// Verifies the signed response against the challenge and the recovery
/// key, consumes the challenge and restores operator authority in
/// `transaction` (see the module docs for the steps). Never commits or
/// rolls back the caller's transaction, only its own savepoint, which it
/// rolls back on every `Err`, the consume included: the caller commits on
/// `Ok` and rolls back on `Err`.
pub async fn restore_operator(
    transaction: &mut Transaction<'_, Postgres>,
    response: &SignedRecoveryResponse<'_>,
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError> {
    let (signature, now) = validate_response(response, request.now)?;
    let mut savepoint = transaction.begin().await?;
    match restore_steps(&mut savepoint, response, &signature, request, now).await {
        Ok(restored) => {
            savepoint.commit().await?;
            Ok(restored)
        }
        Err(err) => {
            // The step's error says more than a failed savepoint rollback.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}

/// Steps 0 to 10 of a restore, in the savepoint of [`restore_operator`].
async fn restore_steps(
    transaction: &mut Transaction<'_, Postgres>,
    response: &SignedRecoveryResponse<'_>,
    signature: &[u8; SIGNATURE_LENGTH],
    request: &RestoreRequest<'_>,
    now: PgInterval,
) -> Result<Restored, RestoreError> {
    // Step 0: READ COMMITTED only.
    let isolation: String = sqlx::query_scalar(TRANSACTION_ISOLATION)
        .fetch_one(&mut **transaction)
        .await?;
    if isolation != READ_COMMITTED {
        return Err(RestoreError::UnsupportedIsolation);
    }
    // Step 1: every unrevoked credential, in key order.
    sqlx::query(LOCK_CREDENTIALS)
        .execute(&mut **transaction)
        .await?;
    // Step 2: the closed recovery state.
    let state: Option<RecoveryState> = sqlx::query_as(LOCK_RECOVERY_STATE)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(state) = state.filter(|state| state.bootstrap_closed) else {
        return Err(NotRestorableReason::NoRecoveryState.into());
    };
    // Step 3: the challenge row, locked, and the signature over it.
    let row: Option<ChallengeRow> = sqlx::query_as(LOCK_CHALLENGE)
        .bind(response.operation_id)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(row) = row else {
        return Err(NotRestorableReason::NotFound.into());
    };
    check_challenge(&state, &row, signature, now)?;
    // Step 4: consume it, bound to the row's own values.
    let Some(consumed_plan) = consume(transaction, &state, &row, now).await? else {
        return Err(NotRestorableReason::Consumed.into());
    };
    // Step 5: the replacement the signer approved; the used key is retired.
    let plan = parse_plan(&consumed_plan)?;
    if state.recovery_public_key[..] == plan.new_recovery_public_key[..] {
        return Err(RestoreError::RecoveryKeyUnchanged);
    }

    // Step 6: revoke every unrevoked credential, before the new one exists.
    let mut revoked_credential_ids: Vec<String> = sqlx::query_scalar(REVOKE_ALL_CREDENTIALS)
        .bind(now)
        .fetch_all(&mut **transaction)
        .await?;
    revoked_credential_ids.sort_unstable();

    // Step 7: the replacement security_admin, as bootstrap enrolls one.
    let identity = create_admin_identity(
        &mut **transaction,
        &NewAdminIdentity {
            id: plan.admin_id.into(),
            status: Status::Enabled,
            created_at: request.now,
        },
    )
    .await?;
    let credential = create_admin_credential(
        &mut **transaction,
        &NewAdminCredential {
            id: plan.credential_id.into(),
            admin_id: identity.id.clone(),
            public_identity: plan.public_identity.into(),
            trust_anchor_ref: plan.trust_anchor_ref.into(),
            status: Status::Enabled,
        },
    )
    .await?;
    let binding = create_admin_role_binding(
        &mut **transaction,
        &NewAdminRoleBinding {
            id: plan.binding_id.into(),
            admin_id: identity.id.clone(),
            role: AdminRole::SecurityAdmin,
            tenant_id: None,
            status: Status::Enabled,
        },
    )
    .await?;

    // Step 8: rotate the recovery key.
    let rotated = sqlx::query(ROTATE_RECOVERY_KEY)
        .bind(&state.instance_id)
        .bind(&plan.new_recovery_public_key[..])
        .bind(state.recovery_key_epoch)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(rotated) = rotated else {
        return Err(NotRestorableReason::NotBound.into());
    };
    let recovery_key_epoch: i64 = rotated.try_get("recovery_key_epoch")?;
    let recovery_state_revision: i64 = rotated.try_get("revision")?;

    // Step 9: the operation's outcome.
    sqlx::query(MARK_RESTORED)
        .bind(&row.id)
        .bind(RESTORED)
        .fetch_one(&mut **transaction)
        .await?;

    // Step 10, last: the events, by the key that signed.
    let actor = AuditActor::Operator(recovery_key_actor(state.recovery_key_epoch));
    let audit_event = append_audit_event(
        transaction,
        &NewAuditEvent {
            id: request.audit_event_id.into(),
            tenant_id: None,
            timestamp: request.now,
            actor: actor.clone(),
            action: RESTORE_ACTION.into(),
            object_id: identity.id.clone(),
            previous_revision: None,
            new_revision: None,
            outcome: SUCCESS.into(),
        },
    )
    .await?;
    let rotation_audit_event = append_audit_event(
        transaction,
        &NewAuditEvent {
            id: request.rotation_audit_event_id.into(),
            tenant_id: None,
            timestamp: request.now,
            actor,
            action: ROTATE_ACTION.into(),
            object_id: state.instance_id,
            previous_revision: Some(state.revision),
            new_revision: Some(recovery_state_revision),
            outcome: SUCCESS.into(),
        },
    )
    .await?;

    Ok(Restored {
        admin_id: identity.id,
        credential_id: credential.id,
        binding_id: binding.id,
        revoked_credential_ids,
        recovery_key_epoch,
        recovery_state_revision,
        audit_event,
        rotation_audit_event,
    })
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, time::UNIX_EPOCH};

    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
    use serde_json::json;

    use super::*;

    /// RFC 8032 section 7.1, test 1: the secret key, the public key and the
    /// signature of the empty message.
    const RFC_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC_SIGNATURE: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    /// The eight small-order points, canonically encoded.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    /// Non-canonical encodings that the crate's decoding accepts: the
    /// identity as `y = p + 1`, the order-4 point `y = 0` as `y = p`, the
    /// identity with the sign bit of a zero `x`, and a point of large order
    /// as `y = p + 3`.
    const NON_CANONICAL: [&str; 4] = [
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    /// 32 bytes that decode to no point.
    const UNDECODABLE: [[u8; 32]; 2] = [[7; 32], [0xa3; 32]];

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), 2 * N, "{hex}");
        let mut out = [0; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).unwrap();
        }
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_790_000_000)
    }

    fn plan(value: serde_json::Value) -> JsonObject {
        match value {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    /// `value` with the replacement of [`good_plan`] added where absent.
    fn full(value: serde_json::Value) -> JsonObject {
        let mut plan = plan(value);
        for (name, member) in [
            (PLAN_ADMIN_ID, "adm_new"),
            (PLAN_CREDENTIAL_ID, "crd_new"),
            (PLAN_BINDING_ID, "rb_new"),
            (PLAN_PUBLIC_IDENTITY, "spki-sha256:new"),
            (PLAN_TRUST_ANCHOR_REF, "deployment/operator-ca"),
            (PLAN_NEW_RECOVERY_PUBLIC_KEY, RFC_PUBLIC),
        ] {
            plan.entry(name).or_insert_with(|| json!(member));
        }
        plan
    }

    fn good_plan() -> JsonObject {
        full(json!({
            "instance_id": "01936f4e-8a2b-7c3d-9e4f-0123456789ab",
            "recovery_key_epoch": 1,
        }))
    }

    fn issue(plan: &JsonObject) -> IssueChallenge<'_> {
        IssueChallenge {
            operation_id: "op_1",
            kind: OPERATOR_RESTORATION,
            immutable_plan: plan,
            ttl: DEFAULT_CHALLENGE_TTL,
            now: now(),
            audit_event_id: "aud_1",
        }
    }

    fn response(signature: &[u8]) -> SignedRecoveryResponse<'_> {
        SignedRecoveryResponse {
            operation_id: "op_1",
            signature,
        }
    }

    #[track_caller]
    fn encode<T: fmt::Debug>(result: Result<T, RegistryError>) -> String {
        match result {
            Err(RegistryError::Other(sqlx::Error::Encode(err))) => err.to_string(),
            other => panic!("expected an encode error: {other:?}"),
        }
    }

    #[test]
    fn the_ttl_defaults_to_five_minutes_and_is_one_second_to_fifteen_minutes() {
        assert_eq!(DEFAULT_CHALLENGE_TTL, Duration::from_secs(300));
        assert_eq!(MAX_CHALLENGE_TTL, Duration::from_secs(900));
        assert_eq!(MIN_CHALLENGE_TTL, Duration::from_secs(1));
        let plan = good_plan();
        for ttl in [
            MIN_CHALLENGE_TTL,
            MIN_CHALLENGE_TTL + Duration::from_nanos(1),
            DEFAULT_CHALLENGE_TTL,
            MAX_CHALLENGE_TTL,
        ] {
            let mut request = issue(&plan);
            request.ttl = ttl;
            let (expires_at, _) = validate_issue(&request).unwrap();
            assert_eq!(
                expires_at.microseconds,
                since_epoch(now() + ttl).unwrap().microseconds,
                "{ttl:?}"
            );
        }
        for ttl in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_micros(1),
            MIN_CHALLENGE_TTL - Duration::from_nanos(1),
            MAX_CHALLENGE_TTL + Duration::from_nanos(1),
            MAX_CHALLENGE_TTL + Duration::from_secs(1),
            Duration::MAX,
        ] {
            let mut request = issue(&plan);
            request.ttl = ttl;
            assert_eq!(
                encode(validate_issue(&request)),
                "challenge TTL is not 1 second to 15 minutes",
                "{ttl:?}"
            );
        }
    }

    #[test]
    fn only_operator_restoration_is_issued() {
        let plan = good_plan();
        assert_eq!(OPERATOR_RESTORATION, "operator_restoration");
        for kind in [
            "",
            "approve",
            "Operator_restoration",
            "operator_restoration ",
            "provider_transition",
        ] {
            let mut request = issue(&plan);
            request.kind = kind;
            assert_eq!(
                encode(validate_issue(&request)),
                "recovery challenge kind is not operator_restoration",
                "{kind:?}"
            );
        }
    }

    #[test]
    fn the_plan_carries_a_string_instance_and_an_integer_epoch() {
        for (value, binding) in [
            (
                json!({"instance_id": "inst", "recovery_key_epoch": 1}),
                ("inst", 1),
            ),
            (json!({"instance_id": "", "recovery_key_epoch": 7}), ("", 7)),
            // Not this function's to refuse: the transaction compares them.
            (
                json!({"instance_id": "inst", "recovery_key_epoch": -1}),
                ("inst", -1),
            ),
            (
                json!({"instance_id": "inst", "recovery_key_epoch": i64::MAX}),
                ("inst", i64::MAX),
            ),
        ] {
            let plan = full(value);
            let (_, parsed) = validate_issue(&issue(&plan)).unwrap();
            assert_eq!((parsed.instance_id, parsed.recovery_key_epoch), binding);
        }
        for value in [
            json!({}),
            json!({"recovery_key_epoch": 1}),
            json!({"instance_id": "inst"}),
            json!({"instance_id": "inst", "recovery_key_epoch": "1"}),
            json!({"instance_id": "inst", "recovery_key_epoch": 1.0}),
            json!({"instance_id": "inst", "recovery_key_epoch": 1.5}),
            json!({"instance_id": "inst", "recovery_key_epoch": null}),
            json!({"instance_id": "inst", "recovery_key_epoch": u64::MAX}),
            json!({"instance_id": "inst", "recovery_key_epoch": [1]}),
            json!({"instance_id": 1, "recovery_key_epoch": 1}),
            json!({"instance_id": null, "recovery_key_epoch": 1}),
            json!({"instance_id": ["inst"], "recovery_key_epoch": 1}),
            json!({"Instance_id": "inst", "recovery_key_epoch": 1}),
        ] {
            let plan = full(value.clone());
            assert_eq!(
                encode(validate_issue(&issue(&plan))),
                "plan lacks a string instance_id or an integer recovery_key_epoch",
                "{value}"
            );
        }
    }

    /// Each replacement member must be a string, and the key 64 lowercase
    /// hexadecimal digits.
    #[test]
    fn the_plan_carries_the_replacement() {
        assert_eq!(
            PLAN_MEMBERS,
            [
                "instance_id",
                "recovery_key_epoch",
                "admin_id",
                "credential_id",
                "binding_id",
                "public_identity",
                "trust_anchor_ref",
                "new_recovery_public_key",
            ]
        );
        let message = "plan lacks a string admin_id, credential_id, binding_id, public_identity \
                       or trust_anchor_ref";
        for name in [
            PLAN_ADMIN_ID,
            PLAN_CREDENTIAL_ID,
            PLAN_BINDING_ID,
            PLAN_PUBLIC_IDENTITY,
            PLAN_TRUST_ANCHOR_REF,
        ] {
            for bad in [None, Some(json!(1)), Some(json!(null)), Some(json!(["x"]))] {
                let mut plan = good_plan();
                match bad.clone() {
                    None => plan.remove(name),
                    Some(value) => plan.insert(name.into(), value),
                };
                assert_eq!(
                    encode(validate_issue(&issue(&plan))),
                    message,
                    "{name} {bad:?}"
                );
            }
        }
        // The IDs may be any string, the empty one included: the inserts
        // refuse what the database refuses.
        for name in [PLAN_CREDENTIAL_ID, PLAN_BINDING_ID] {
            let mut plan = good_plan();
            plan.insert(name.into(), json!(""));
            assert!(validate_issue(&issue(&plan)).is_ok(), "{name}");
        }
        let message = "plan new_recovery_public_key is not 64 lowercase hexadecimal digits";
        for bad in [
            None,
            Some(json!(1)),
            Some(json!(null)),
            Some(json!("")),
            Some(json!(&RFC_PUBLIC[2..])),
            Some(json!(format!("{RFC_PUBLIC}00"))),
            Some(json!(&RFC_PUBLIC[1..])),
            Some(json!(RFC_PUBLIC.to_uppercase())),
            Some(json!(format!("{}g0", &RFC_PUBLIC[..62]))),
            Some(json!(format!("{} 0", &RFC_PUBLIC[..62]))),
            Some(json!(format!("0x{}", &RFC_PUBLIC[..62]))),
            Some(json!([RFC_PUBLIC])),
        ] {
            let mut plan = good_plan();
            match bad.clone() {
                None => plan.remove(PLAN_NEW_RECOVERY_PUBLIC_KEY),
                Some(value) => plan.insert(PLAN_NEW_RECOVERY_PUBLIC_KEY.into(), value),
            };
            assert_eq!(encode(validate_issue(&issue(&plan))), message, "{bad:?}");
        }
        assert_eq!(
            plan_key("0123456789abcdef".repeat(4).as_str()),
            Some(bytes("0123456789abcdef".repeat(4).as_str()))
        );
        assert_eq!(plan_key(RFC_PUBLIC), Some(bytes(RFC_PUBLIC)));
        let plan = good_plan();
        let (_, parsed) = validate_issue(&issue(&plan)).unwrap();
        assert_eq!(
            parsed,
            Plan {
                instance_id: "01936f4e-8a2b-7c3d-9e4f-0123456789ab",
                recovery_key_epoch: 1,
                admin_id: "adm_new",
                credential_id: "crd_new",
                binding_id: "rb_new",
                public_identity: "spki-sha256:new",
                trust_anchor_ref: "deployment/operator-ca",
                new_recovery_public_key: bytes(RFC_PUBLIC),
            }
        );
    }

    /// The plan is closed to its eight members, and what a restore would
    /// refuse is refused at the issue (provisional lead pick, 2026-11-24).
    #[test]
    fn the_plan_is_closed_and_checked_as_a_restore_checks_it() {
        assert_eq!(good_plan().len(), 8);
        for (name, value) in [
            ("operation", json!("restore")),
            ("nonce", json!("n")),
            ("Instance_id", json!("inst")),
            ("", json!(null)),
            ("x", json!(1.5)),
            ("y", json!(u64::MAX)),
        ] {
            let mut plan = good_plan();
            plan.insert(name.into(), value);
            assert_eq!(
                encode(validate_issue(&issue(&plan))),
                "plan has a member other than the eight of an operator restoration",
                "{name}"
            );
        }
        for id in [DEPLOYMENT_OPERATOR_ACTOR, "recovery_key:", "recovery_key:1"] {
            let mut plan = good_plan();
            plan.insert(PLAN_ADMIN_ID.into(), json!(id));
            assert!(
                matches!(
                    validate_issue(&issue(&plan)),
                    Err(RegistryError::ReservedActorId)
                ),
                "{id}"
            );
        }
        let long = "k".repeat(2049);
        let longest = "k".repeat(2048);
        for (name, message) in [
            (
                PLAN_PUBLIC_IDENTITY,
                "public identity is empty or over 2048 bytes",
            ),
            (
                PLAN_TRUST_ANCHOR_REF,
                "trust anchor reference is empty or over 2048 bytes",
            ),
        ] {
            for bad in ["", &long[..]] {
                let mut plan = good_plan();
                plan.insert(name.into(), json!(bad));
                assert_eq!(encode(validate_issue(&issue(&plan))), message, "{name}");
            }
            let mut plan = good_plan();
            plan.insert(name.into(), json!(longest));
            assert!(validate_issue(&issue(&plan)).is_ok(), "{name}");
        }
        // The new key: the checks of "Keys", with their messages.
        let refused = SMALL_ORDER
            .iter()
            .map(|key| (key.to_string(), KEY_SMALL_ORDER))
            .chain(
                NON_CANONICAL
                    .iter()
                    .map(|key| (key.to_string(), KEY_NOT_CANONICAL)),
            )
            .chain(UNDECODABLE.iter().map(|key| (hex(key), KEY_UNDECODABLE)));
        for (key, message) in refused {
            let mut plan = good_plan();
            plan.insert(PLAN_NEW_RECOVERY_PUBLIC_KEY.into(), json!(key));
            assert_eq!(encode(validate_issue(&issue(&plan))), message, "{key}");
        }
    }

    /// The key checks of "Keys", at every enrollment point and at verify:
    /// small order, non-canonical and undecodable keys are refused, each
    /// with its message. The crate's decoding accepts every non-canonical
    /// encoding listed (ZIP-215), so the re-encoding is what refuses them.
    #[test]
    fn weak_non_canonical_and_undecodable_keys_are_refused() {
        for key in SMALL_ORDER {
            let key: [u8; 32] = bytes(key);
            assert!(VerifyingKey::from_bytes(&key).unwrap().is_weak());
            assert_eq!(recovery_key(&key).unwrap_err(), KEY_SMALL_ORDER, "{key:?}");
        }
        for key in NON_CANONICAL {
            let key: [u8; 32] = bytes(key);
            assert!(VerifyingKey::from_bytes(&key).is_ok(), "{key:?}");
            assert_eq!(
                recovery_key(&key).unwrap_err(),
                KEY_NOT_CANONICAL,
                "{key:?}"
            );
        }
        // `y = p + 3` is of large order: only the re-encoding refuses it.
        let large: [u8; 32] = bytes(NON_CANONICAL[3]);
        assert!(!VerifyingKey::from_bytes(&large).unwrap().is_weak());
        for key in UNDECODABLE {
            assert!(VerifyingKey::from_bytes(&key).is_err());
            assert_eq!(recovery_key(&key).unwrap_err(), KEY_UNDECODABLE);
        }
        for length in [0, 1, 31, 33, 64] {
            assert_eq!(recovery_key(&vec![0x11; length]).unwrap_err(), KEY_LENGTH);
        }
        for key in [bytes(RFC_PUBLIC), [0x11; 32]] {
            assert_eq!(recovery_key(&key).unwrap().as_bytes(), &key);
        }
        assert_eq!(
            KEY_LENGTH,
            "recovery public key is not a 32-byte Ed25519 key"
        );
    }

    /// RFC 8032 section 7.1, test 1, through the verify helper; and the
    /// signing key of the test signs the same bytes.
    #[test]
    fn the_rfc_8032_vector_verifies() {
        let public: [u8; 32] = bytes(RFC_PUBLIC);
        let signature: [u8; 64] = bytes(RFC_SIGNATURE);
        assert_eq!(verify_signature(&public, b"", &signature), Ok(()));
        let signing = SigningKey::from_bytes(&bytes(RFC_SECRET));
        assert_eq!(signing.verifying_key().as_bytes(), &public);
        assert_eq!(signing.sign(b"").to_bytes(), signature);
        assert_eq!(
            verify_signature(&public, b"x", &signature),
            Err(NotRestorableReason::BadSignature)
        );
    }

    /// `verify_strict` refuses what plain verification accepts: `S + L`,
    /// a small-order key with the fixed signature that verifies over any
    /// message, and a non-canonical `R`.
    #[test]
    fn malleable_and_weak_key_signatures_are_refused() {
        let public: [u8; 32] = bytes(RFC_PUBLIC);
        let mut signature: [u8; 64] = bytes(RFC_SIGNATURE);
        // S + L, computed independently.
        signature[32..].copy_from_slice(&bytes::<32>(
            "4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b",
        ));
        assert_eq!(
            verify_signature(&public, b"", &signature),
            Err(NotRestorableReason::BadSignature)
        );
        // R the identity, S zero: [S]B = R + [k]A for the identity key A.
        let mut fixed = [0; 64];
        fixed[0] = 1;
        for key in [SMALL_ORDER[0], NON_CANONICAL[0]] {
            let key: [u8; 32] = bytes(key);
            let lax = VerifyingKey::from_bytes(&key).unwrap();
            for message in [&b""[..], b"any message", b"restore me"] {
                assert!(lax.verify(message, &Signature::from_bytes(&fixed)).is_ok());
                assert_eq!(
                    verify_signature(&key, message, &fixed),
                    Err(NotRestorableReason::WeakKey)
                );
            }
        }
        // A small-order R (the identity) with S = k * a mod L, for the RFC
        // key's secret scalar a and k = H(R || A || M), computed
        // independently: the plain equation holds, so `verify` accepts it;
        // `verify_strict` refuses a small-order R.
        let small_r: [u8; 64] = bytes(
            "0100000000000000000000000000000000000000000000000000000000000000\
             db2ea1a49738237b2becd56e7bfaf5733c90126821b8e8a59756568718a9ff02",
        );
        let message = b"skyoauth small-order R";
        let lax = VerifyingKey::from_bytes(&public).unwrap();
        assert!(
            lax.verify(message, &Signature::from_bytes(&small_r))
                .is_ok()
        );
        assert_eq!(
            verify_signature(&public, message, &small_r),
            Err(NotRestorableReason::BadSignature)
        );
        // A non-canonical R (the identity as y = p + 1) never verifies.
        let mut non_canonical = [0; 64];
        non_canonical[..32].copy_from_slice(&bytes::<32>(NON_CANONICAL[0]));
        assert_eq!(
            verify_signature(&public, b"", &non_canonical),
            Err(NotRestorableReason::BadSignature)
        );
        for key in UNDECODABLE {
            assert_eq!(
                verify_signature(&key, b"", &bytes(RFC_SIGNATURE)),
                Err(NotRestorableReason::WeakKey)
            );
        }
        assert_eq!(
            verify_signature(&public[..31], b"", &bytes(RFC_SIGNATURE)),
            Err(NotRestorableReason::WeakKey)
        );
    }

    /// The pinned `C` and `M` of a fixed challenge, for the workstation to
    /// conform to; the hashes computed independently of this code (Python's
    /// `hashlib` over the same bytes).
    #[test]
    fn the_signed_message_is_pinned() {
        let plan = good_plan();
        let encoded = encode_challenge("op_1", 1, 1_790_000_300_000_000, &plan).unwrap();
        let canonical = concat!(
            r#"{"actor_id":"deployment_operator","expected_revision":1,"#,
            r#""expires_at":1790000300000000,"id":"op_1","kind":"operator_restoration","#,
            r#""plan":{"admin_id":"adm_new","binding_id":"rb_new","credential_id":"crd_new","#,
            r#""instance_id":"01936f4e-8a2b-7c3d-9e4f-0123456789ab","#,
            r#""new_recovery_public_key":"#,
            r#""d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","#,
            r#""public_identity":"spki-sha256:new","recovery_key_epoch":1,"#,
            r#""trust_anchor_ref":"deployment/operator-ca"},"tenant_id":null}"#
        );
        assert_eq!(CHALLENGE_PREFIX, b"skyoauth.recovery_challenge.v1\n");
        assert_eq!(
            encoded.challenge,
            [
                &b"skyoauth.recovery_challenge.v1\n"[..],
                canonical.as_bytes()
            ]
            .concat()
        );
        assert_eq!(
            hex(&encoded.request_digest),
            "34694852ec1514d9054822e6a5c7b650637176d5b16ab18bf4442d9531170808"
        );
        assert_eq!(
            hex(&encoded.challenge_hash),
            "38bfce122a7807a760f2e556496415859ce931a2589e0b9f4098f3eaf23bbcf4"
        );
        // The request digest is the second-approver flow's over the same C.
        let envelope = DigestEnvelope {
            id: "op_1",
            tenant_id: None,
            actor_id: "deployment_operator",
            kind: "operator_restoration",
            expected_revision: 1,
            expires_at_us: 1_790_000_300_000_000,
            plan: &plan,
        };
        assert_eq!(envelope.canonical_json().unwrap(), canonical);
        assert_eq!(
            envelope.digest().unwrap().as_bytes(),
            &encoded.request_digest
        );
        // Every input changes M.
        let mut other = good_plan();
        other.insert(PLAN_ADMIN_ID.into(), json!("adm_other"));
        for changed in [
            encode_challenge("op_2", 1, 1_790_000_300_000_000, &plan),
            encode_challenge("op_1", 2, 1_790_000_300_000_000, &plan),
            encode_challenge("op_1", 1, 1_790_000_300_000_001, &plan),
            encode_challenge("op_1", 1, 1_790_000_300_000_000, &other),
        ] {
            let changed = changed.unwrap();
            assert_ne!(changed.challenge, encoded.challenge);
            assert_ne!(changed.challenge_hash, encoded.challenge_hash);
            assert_ne!(changed.request_digest, encoded.request_digest);
        }
        let mut fraction = good_plan();
        fraction.insert("x".into(), json!(1.5));
        assert_eq!(encode_challenge("op_1", 1, 0, &fraction), Err(NotCanonical));
    }

    /// The audit writer's years, as in bootstrap, for every call.
    #[test]
    fn only_the_audit_years_are_accepted() {
        const EARLIEST: u64 = 62_167_219_200_000_000;
        const LATEST: u64 = 253_402_300_799_999_999;
        let plan = good_plan();
        let signature = [0; 64];
        for time in [
            UNIX_EPOCH - Duration::from_micros(EARLIEST),
            UNIX_EPOCH + Duration::from_micros(LATEST) + Duration::from_nanos(999),
        ] {
            let mut request = issue(&plan);
            request.now = time;
            assert!(validate_issue(&request).is_ok(), "{time:?}");
            assert!(audit_time(time).is_ok(), "{time:?}");
            assert!(validate_response(&response(&signature), time).is_ok());
        }
        for time in [
            UNIX_EPOCH - Duration::from_micros(EARLIEST + 1),
            UNIX_EPOCH + Duration::from_micros(LATEST + 1),
        ] {
            let mut request = issue(&plan);
            request.now = time;
            let message = "audit timestamp outside the years 0000 to 9999";
            assert_eq!(encode(validate_issue(&request)), message);
            assert_eq!(encode(audit_time(time)), message);
            assert_eq!(
                encode(validate_response(&response(&signature), time)),
                message
            );
        }
        let far = UNIX_EPOCH + Duration::from_micros(u64::try_from(i64::MAX).unwrap());
        assert_eq!(encode(audit_time(far)), "timestamp out of range");
    }

    #[test]
    fn a_signature_is_64_bytes() {
        let signature = [5; 64];
        let (checked, at) = validate_response(&response(&signature), now()).unwrap();
        assert_eq!(checked, signature);
        assert_eq!(at.microseconds, since_epoch(now()).unwrap().microseconds);
        for length in [0, 1, 32, 63, 65, 128] {
            let signature = vec![5; length];
            assert_eq!(
                encode(validate_response(&response(&signature), now())),
                "recovery signature is not 64 bytes",
                "{length}"
            );
        }
    }

    #[test]
    fn the_refusals_carry_no_detail() {
        let error = ChallengeError::NotIssuable;
        assert_eq!(error.to_string(), "a recovery challenge cannot be issued");
        assert_eq!(format!("{error:?}"), "NotIssuable");
        assert!(error.source().is_none());
        assert_eq!(ChallengeError::NotIssuable, ChallengeError::NotIssuable);
        let store = ChallengeError::from(sqlx::Error::PoolClosed);
        assert_ne!(store, ChallengeError::from(sqlx::Error::PoolClosed));
        assert_ne!(store, ChallengeError::NotIssuable);
        assert_eq!(
            store.to_string(),
            "recovery challenge failed: registry database error"
        );
        assert_eq!(format!("{store:?}"), "Store(Other { sqlstate: None, .. })");
        assert!(store.source().is_some());

        for (error, display, debug) in [
            (
                RestoreError::RecoveryKeyUnchanged,
                "the new recovery public key is the current one",
                "RecoveryKeyUnchanged",
            ),
            (
                RestoreError::UnsupportedIsolation,
                "operator restoration runs only at READ COMMITTED",
                "UnsupportedIsolation",
            ),
        ] {
            assert_eq!(error.to_string(), display);
            assert_eq!(format!("{error:?}"), debug);
            assert!(error.source().is_none());
        }
        assert_eq!(
            RestoreError::UnsupportedIsolation,
            RestoreError::UnsupportedIsolation
        );
        assert_ne!(
            RestoreError::UnsupportedIsolation,
            RestoreError::RecoveryKeyUnchanged
        );
        assert_ne!(
            RestoreError::NotRestorable(NotRestorableReason::NotFound),
            RestoreError::RecoveryKeyUnchanged
        );
        assert_ne!(
            RestoreError::NotRestorable(NotRestorableReason::NotFound),
            RestoreError::NotRestorable(NotRestorableReason::Consumed)
        );
        assert_eq!(
            RestoreError::from(NotRestorableReason::Expired),
            RestoreError::NotRestorable(NotRestorableReason::Expired)
        );
        let store = RestoreError::from(RegistryError::ReservedActorId);
        assert_ne!(store, RestoreError::from(RegistryError::ReservedActorId));
        assert_eq!(
            store.to_string(),
            "operator restoration failed: registry ID is reserved for an actor that is not an \
             operator identity"
        );
        assert!(store.source().is_some());
    }

    #[test]
    fn the_statements_hold_every_predicate_and_no_clock() {
        for predicate in [
            "WHERE id = $1",
            "tenant_id IS NULL",
            "kind = 'operator_restoration'",
            "challenge_hash IS NOT NULL",
            "consumed_at IS NULL",
            "revoked_at IS NULL",
            "outcome = 'issued'",
            "timestamptz 'epoch' + $2::interval < expires_at",
            "request_digest = $3",
            "challenge_hash = $7",
            "expected_revision = $4",
            "jsonb_typeof(immutable_plan -> 'instance_id') = 'string'",
            "immutable_plan ->> 'instance_id' = $5 COLLATE \"C\"",
            "jsonb_typeof(immutable_plan -> 'recovery_key_epoch') = 'number'",
            "immutable_plan ->> 'recovery_key_epoch' = $6::bigint::text",
            "r.bootstrap_closed",
            "r.instance_id = $5",
            "r.recovery_key_epoch = $6",
            "r.revision = $4",
        ] {
            assert_eq!(
                CONSUME_CHALLENGE.matches(predicate).count(),
                1,
                "{predicate}"
            );
        }
        assert_eq!(
            TRANSACTION_ISOLATION,
            "SELECT current_setting('transaction_isolation')"
        );
        assert_eq!(READ_COMMITTED, "read committed");
        assert!(SHARE_RECOVERY_STATE.ends_with("FROM recovery_state FOR SHARE"));
        assert!(LOCK_RECOVERY_STATE.ends_with("FROM recovery_state FOR NO KEY UPDATE"));
        assert!(LOCK_CREDENTIALS.ends_with("ORDER BY id COLLATE \"C\" FOR NO KEY UPDATE"));
        assert!(REVOKE_ALL_CREDENTIALS.contains("WHERE revoked_at IS NULL RETURNING id"));
        assert!(READ_CHALLENGE.ends_with("FROM administrative_operation WHERE id = $1"));
        assert_eq!(
            LOCK_CHALLENGE,
            format!("{READ_CHALLENGE} FOR NO KEY UPDATE")
        );
        assert!(!READ_CHALLENGE.contains("FOR "));
        assert!(!READ_RECOVERY_STATE.contains("FOR "));
        assert_eq!(ISSUE_ACTION, "administrative_operation.create");
        assert_eq!(RESTORE_ACTION, "admin_identity.restore");
        assert_eq!(ROTATE_ACTION, "recovery_state.rotate_key");
        for action in [ISSUE_ACTION, RESTORE_ACTION, ROTATE_ACTION] {
            assert!(super::super::is_audit_action(action), "{action}");
        }
        for sql in [
            READ_RECOVERY_STATE,
            SHARE_RECOVERY_STATE,
            LOCK_RECOVERY_STATE,
            READ_CHALLENGE,
            LOCK_CHALLENGE,
            INSERT_CHALLENGE,
            CONSUME_CHALLENGE,
            LOCK_CREDENTIALS,
            REVOKE_ALL_CREDENTIALS,
            ROTATE_RECOVERY_KEY,
            MARK_RESTORED,
        ] {
            // Plain statements: no clock, one statement, and a conflict is
            // the database's `23505`.
            for absent in ["now()", "current_timestamp", ";", "ON CONFLICT"] {
                assert!(!sql.contains(absent), "{sql}");
            }
        }
    }
}
