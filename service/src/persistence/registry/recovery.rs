//! Break-glass operator restoration at the registry level (design section
//! 7.2; ADR-013 item 8; identity-registry section 5.2; lifetimes LT-107;
//! T13.5): [`get_recovery_state`] reads the recovery key and its epoch,
//! [`issue_recovery_challenge`] records an expiring challenge, and
//! [`restore_operator`] consumes it once and, in the same savepoint,
//! enrolls the replacement `security_admin` the challenge names, revokes
//! every operator credential, rotates the recovery key and records the
//! audit events.
//!
//! Every ruling below, a lead's or an inferred one, is provisional until
//! the maintainer ratifies the ADRs (T00.8 to T00.17, Gate M0).
//!
//! # Flow
//!
//! 1. The local recovery verifier builds the restoration plan and calls
//!    [`issue_recovery_challenge`] in a transaction of its own, which
//!    records the challenge as an `administrative_operation` row with its
//!    audit event, and commits.
//! 2. The portable workstation signs the challenge with the offline
//!    recovery key; the signed response comes back over the deployment-local
//!    channel. The verifier checks the Ed25519 signature over the challenge
//!    with the key [`get_recovery_state`] returns. **The registry does not
//!    verify signatures**: that belongs to the future operator crate
//!    (identity-registry section 5.2, lead pick: raw 32-byte Ed25519 key).
//!    The verifier verifies the signature *before* it calls the restore.
//! 3. In one transaction the verifier calls [`restore_operator`], which
//!    consumes the challenge and restores inside one savepoint, and
//!    commits. Any failure is an `Err` with the savepoint rolled back, the
//!    consume included: the challenge is then still unconsumed, and nothing
//!    of the restore is left, even if the caller commits; the caller still
//!    rolls back on `Err`. (inferred: the restore consumes itself, so that
//!    one savepoint covers the consume and the restoration.)
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
//! # Issue
//!
//! [`issue_recovery_challenge`] checks its input before any statement (see
//! "Validation"), then, in the caller's [`Transaction`]:
//!
//! 1. reads the `recovery_state` row `FOR SHARE`. No row, or one whose
//!    `bootstrap_closed` is false, is [`ChallengeError::NotIssuable`]; so is
//!    a plan whose `instance_id` or `recovery_key_epoch` is not the row's.
//!    `expected_revision` is the row's `revision`, read here;
//! 2. appends the audit event FIRST, because `administrative_operation.audit_id`
//!    is an immediate foreign key (migrations README, "What 0005 adds",
//!    steps 2 and 3): instance scope, actor
//!    `{"type": "operator", "id": "deployment_operator"}` (the local
//!    verifier records it; nobody has signed yet; inferred), action
//!    `administrative_operation.create`, `object_id` the operation ID,
//!    `previous_revision` none, `new_revision` 1, outcome `success`;
//! 3. inserts the operation: no tenant, `actor_id` `deployment_operator`,
//!    the kind, digest, plan and challenge hash, `expected_revision`,
//!    `expires_at = now + ttl`, `audit_id` the event, outcome `issued`,
//!    revision 1, unconsumed and unrevoked. A taken operation ID is the
//!    insert's `23505`, [`RegistryError::AlreadyExists`] naming
//!    `administrative_operation_pkey`.
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
//! a JSON object that must carry (lead ruling) the string `instance_id`,
//! the integer `recovery_key_epoch` (no column), and the replacement the
//! signer approves: the strings `admin_id`, `credential_id`, `binding_id`,
//! `public_identity` and `trust_anchor_ref`, and `new_recovery_public_key`,
//! the new 32-byte key as 64 lowercase hexadecimal digits. Other members
//! are the caller's, and must hold no secret: the plan is kept for the life
//! of the row. `challenge_hash` is computed by the caller as well; the
//! registry does not hash. The issue checks only the members' types and
//! the key's form; a value that a restore could not use (a reserved
//! `admin_id`, say) makes a challenge that no restore can use.
//!
//! # Consume
//!
//! Step 3 of a restore runs one statement:
//! `UPDATE administrative_operation SET consumed_at = $now` (and the revision
//! by one) where the ID matches, there is no tenant, the kind is
//! `operator_restoration`, `challenge_hash` is set, `consumed_at` and
//! `revoked_at` are unset, the outcome is still `issued`,
//! `$now < expires_at`, `request_digest` and `expected_revision` equal the
//! binding's, the plan's `instance_id` is a JSON string equal byte-wise
//! (`COLLATE "C"`) to the binding's and its `recovery_key_epoch` a JSON
//! number whose text is the binding's epoch in decimal, and the
//! `recovery_state` row is closed (`bootstrap_closed`) and has the
//! binding's `instance_id`, the binding's epoch and the binding's
//! `expected_revision` as its `revision` (inferred: the challenge is bound
//! to the revision of the state it rotates). A plan epoch that is a string,
//! a fraction (`1.5`, and `1.0` too, whose `jsonb` text keeps the
//! fraction), `null`, negative or missing therefore matches nothing. It
//! writes no audit event of its own: the restore's events, in the same
//! savepoint, record it (inferred).
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
//! 2. locks the `recovery_state` row `FOR NO KEY UPDATE` and reads it;
//! 3. consumes the challenge (see "Consume"), at `now`, for the request's
//!    binding, against the row it holds;
//! 4. compares each replacement member of the consumed plan with the
//!    request: `admin_id`, `credential_id`, `binding_id`, `public_identity`
//!    and `trust_anchor_ref` byte-wise, and `new_recovery_public_key` with
//!    the request's key in lowercase hexadecimal (lead ruling);
//! 5. refuses a new recovery key equal to the current one,
//!    [`RestoreError::RecoveryKeyUnchanged`];
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
//! A miss of step 2 (no recovery state), 3 (any miss of the consume) or 4
//! (any member that differs) is the one unit value
//! [`RestoreError::NotRestorable`], with no detail and the same `Debug`
//! and `Display`; the savepoint rollback undoes the consume of step 3. As
//! for [`select_grant`](super::select_grant), no claim is made about
//! timing.
//!
//! It touches no identity or role binding but the new ones, and no
//! workload, trust, grant, audience or token state. It does only what T13.5
//! permits M1a: enroll a replacement `security_admin` credential and revoke
//! operator credentials.
//!
//! # Locks
//!
//! Restore takes its locks in the `0005` order of the migrations README
//! (credentials, the recovery state, then the operation row by the
//! consume) and the audit head last. An issue takes the
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
//!   inferred); a `request_digest` or `challenge_hash` not 32 to 64 bytes;
//!   a plan without a string `instance_id` or an integer
//!   `recovery_key_epoch` (a JSON number that is an `i64`), without the five
//!   replacement strings, or without a `new_recovery_public_key` of 64
//!   lowercase hexadecimal digits; a `ttl` below [`MIN_CHALLENGE_TTL`] or
//!   above [`MAX_CHALLENGE_TTL`];
//! - restore: a reserved `admin_id` ([`RegistryError::ReservedActorId`]); a
//!   new recovery key that is not exactly 32 bytes; an empty or
//!   over-2048-byte `public_identity` or `trust_anchor_ref`;
//! - both: a `now` outside the `0007` range, or outside the years
//!   `0000` to `9999` the audit event can carry.
//!
//! Such a failure runs no statement and leaves the transaction usable.
//!
//! # Time
//!
//! `now` is always the caller's, never the database's `now()`. Expiry is
//! checked in the statement against that `now`. The TTL defaults to
//! [`DEFAULT_CHALLENGE_TTL`], 5 minutes, and may be at most
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
//! # Errors and rollback
//!
//! None of these functions commits or rolls back the caller's transaction.
//! Each runs its statements inside a savepoint of its own
//! (`Transaction::begin` on the caller's transaction), releases it on `Ok`
//! and rolls it back on every `Err`: a refusal, a failed statement, or an
//! error the audit writer returns in Rust after the head lock (a sequence
//! above `2^53 - 1`, say). A caller that commits after an `Err` therefore
//! commits none of the function's rows, and its transaction stays usable.
//! The caller must still roll back on `Err`: a failed savepoint rollback
//! leaves the rows in place. A `23505` of a caller-supplied event ID
//! (`audit_event_pkey`, from the audit writer), of a taken operation ID
//! (`administrative_operation_pkey`) and of the replacement's keys (step 7
//! of "Restore") is the ordinary [`RegistryError::AlreadyExists`] in
//! `Store`, naming only the constraint. A [`RegistryError::Retry`] in
//! `Store` (`40001`, or `40P01` from the cycle of "Locks") means retrying
//! the whole transaction; [`RestoreError::UnsupportedIsolation`] means
//! retrying it at `READ COMMITTED`.
//!
//! When the commit's outcome is unknown, for example because the
//! connection failed during `COMMIT`, the uncertain-commit rule of
//! [`bootstrap_instance`] applies to [`restore_operator`] too: the caller
//! keeps all the request's material (the IDs, the signed challenge and its
//! binding, the replacement's credential and the new recovery public key)
//! until it has reconnected and reconciled the durable state: whether the
//! operation is `restored` and the recovery state is at the new epoch with
//! the new key, or the challenge is still unconsumed. It then retries the
//! same request. A retry of a restoration that committed is
//! [`RestoreError::NotRestorable`] (its challenge is consumed), which with
//! that state means the restoration happened; one that did not commit
//! restores, unless the challenge expired meanwhile: the retry's `now` is
//! later, so it is `NotRestorable` too, with the challenge still
//! unconsumed, and the verifier issues a new challenge. A retry of an issue
//! that committed fails with `AlreadyExists` on `audit_event_pkey`.
//!
//! [`bootstrap_instance`]: super::bootstrap_instance

use std::{
    fmt,
    fmt::Write as _,
    time::{Duration, SystemTime},
};

use serde_json::Value;
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

/// The bounds of `request_digest` and `challenge_hash`, in bytes (`0005`).
const MIN_DIGEST: usize = 32;
const MAX_DIGEST: usize = 64;

/// The longest `public_identity` and `trust_anchor_ref`, in bytes (`0005`).
const MAX_EXACT_STRING: usize = 2048;

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

const INSERT_CHALLENGE: &str = concat!(
    "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
     expected_revision, immutable_plan, challenge_hash, expires_at, outcome, audit_id) \
     VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, timestamptz 'epoch' + $8::interval, $9, $10) \
     RETURNING id, expected_revision, ",
    micros!("expires_at")
);

/// Step 3 of a restore. `$1` the ID, `$2` `now`, `$3` the digest, `$4` the
/// expected revision, `$5` the instance and `$6` the epoch.
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

/// The input of [`issue_recovery_challenge`]. Every value is the caller's.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IssueChallenge<'a> {
    pub operation_id: &'a str,
    /// [`OPERATOR_RESTORATION`], the only kind of M1a.
    pub kind: &'a str,
    /// The digest of the operation and its arguments, 32 to 64 bytes.
    pub request_digest: &'a [u8],
    /// A JSON object with the string [`PLAN_INSTANCE_ID`], the integer
    /// [`PLAN_RECOVERY_KEY_EPOCH`] and the replacement (see the module
    /// docs, "The plan"); no secrets.
    pub immutable_plan: &'a JsonObject,
    /// The hash of the challenge the workstation signs, 32 to 64 bytes,
    /// computed by the caller.
    pub challenge_hash: &'a [u8],
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
    /// The `administrative_operation.create` event.
    pub audit_event: AuditEvent,
}

/// What a restore's consume must match besides the operation's ID: the
/// values the signed challenge carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeBinding<'a> {
    pub request_digest: &'a [u8],
    pub instance_id: &'a str,
    pub expected_revision: i64,
    pub recovery_key_epoch: i64,
}

/// Why a challenge was not issued.
///
/// Values compare equal when they are the same unit variant; a `Store`
/// value never compares equal, since [`RegistryError`] has no equality.
#[derive(Debug)]
pub enum ChallengeError {
    /// No closed recovery state, or the plan names another instance or
    /// epoch. No detail.
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

/// The input of [`restore_operator`]. Every ID is the caller's (T10.2).
/// The replacement's values must be the ones the challenge's plan names.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RestoreRequest<'a> {
    /// The restoration challenge the restore consumes, inside its own
    /// savepoint.
    pub operation_id: &'a str,
    /// What the signed challenge carried.
    pub binding: ChallengeBinding<'a>,
    /// The replacement operator; not reserved; the plan's
    /// [`PLAN_ADMIN_ID`].
    pub admin_id: &'a str,
    /// The plan's [`PLAN_CREDENTIAL_ID`].
    pub credential_id: &'a str,
    /// The plan's [`PLAN_BINDING_ID`].
    pub binding_id: &'a str,
    /// The canonical public-key identity of the replacement's mTLS
    /// credential, 1 to 2048 bytes, not registered before; the plan's
    /// [`PLAN_PUBLIC_IDENTITY`].
    pub public_identity: &'a str,
    /// 1 to 2048 bytes; the plan's [`PLAN_TRUST_ANCHOR_REF`].
    pub trust_anchor_ref: &'a str,
    /// The raw Ed25519 public key that replaces the used one: exactly
    /// [`RECOVERY_PUBLIC_KEY_LENGTH`] bytes and not the current key; in
    /// lowercase hexadecimal, the plan's [`PLAN_NEW_RECOVERY_PUBLIC_KEY`].
    pub new_recovery_public_key: &'a [u8],
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

/// Why [`restore_operator`] did not restore. On every variant its savepoint
/// is rolled back; the caller rolls back too.
///
/// Values compare equal when they are the same unit variant; a `Store`
/// value never compares equal.
#[derive(Debug)]
pub enum RestoreError {
    /// No recovery state, the challenge is not consumable for the binding
    /// (every miss of the consume), or the request is not the replacement
    /// the plan names. No detail.
    NotRestorable,
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
        matches!(
            (self, other),
            (Self::NotRestorable, Self::NotRestorable)
                | (Self::RecoveryKeyUnchanged, Self::RecoveryKeyUnchanged)
                | (Self::UnsupportedIsolation, Self::UnsupportedIsolation)
        )
    }
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRestorable => f.write_str("no recovery challenge authorizes this restoration"),
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
            Self::NotRestorable | Self::RecoveryKeyUnchanged | Self::UnsupportedIsolation => None,
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

/// Whether `digest` is 32 to 64 bytes.
fn digest_length(digest: &[u8]) -> bool {
    (MIN_DIGEST..=MAX_DIGEST).contains(&digest.len())
}

/// Whether `value` is 1 to 2048 bytes.
fn bounded(value: &str) -> bool {
    (1..=MAX_EXACT_STRING).contains(&value.len())
}

/// `bytes` as lowercase hexadecimal digits.
fn lower_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` does not fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Whether `value` is a recovery key in the plan's form: 64 lowercase
/// hexadecimal digits.
fn plan_key(value: &str) -> bool {
    value.len() == 2 * RECOVERY_PUBLIC_KEY_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The plan's instance and epoch: a string and an `i64` JSON integer.
fn plan_binding(plan: &JsonObject) -> Option<(&str, i64)> {
    let instance_id = plan.get(PLAN_INSTANCE_ID).and_then(Value::as_str)?;
    let epoch = plan.get(PLAN_RECOVERY_KEY_EPOCH).and_then(Value::as_i64)?;
    Some((instance_id, epoch))
}

/// The plan members a restore compares with the request byte-wise.
const PLAN_REPLACEMENT: [&str; 5] = [
    PLAN_ADMIN_ID,
    PLAN_CREDENTIAL_ID,
    PLAN_BINDING_ID,
    PLAN_PUBLIC_IDENTITY,
    PLAN_TRUST_ANCHOR_REF,
];

/// The string member `name` of `plan`.
fn plan_text<'a>(plan: &'a JsonObject, name: &str) -> Option<&'a str> {
    plan.get(name).and_then(Value::as_str)
}

/// Whether the plan names exactly the request's replacement (step 4).
fn plan_names(plan: &JsonObject, request: &RestoreRequest<'_>) -> bool {
    let requested = [
        request.admin_id,
        request.credential_id,
        request.binding_id,
        request.public_identity,
        request.trust_anchor_ref,
    ];
    PLAN_REPLACEMENT
        .iter()
        .zip(requested)
        .all(|(name, value)| plan_text(plan, name) == Some(value))
        && plan_text(plan, PLAN_NEW_RECOVERY_PUBLIC_KEY)
            == Some(&lower_hex(request.new_recovery_public_key)[..])
}

/// The checks of an issue that run before any statement: `expires_at` as
/// an interval, and the plan's instance and epoch.
fn validate_issue<'a>(
    request: &IssueChallenge<'a>,
) -> Result<(PgInterval, (&'a str, i64)), RegistryError> {
    if request.kind != OPERATOR_RESTORATION {
        return Err(encode_error(
            "recovery challenge kind is not operator_restoration",
        ));
    }
    if !digest_length(request.request_digest) {
        return Err(encode_error("request digest is not 32 to 64 bytes"));
    }
    if !digest_length(request.challenge_hash) {
        return Err(encode_error("challenge hash is not 32 to 64 bytes"));
    }
    let plan = request.immutable_plan;
    let Some(binding) = plan_binding(plan) else {
        return Err(encode_error(
            "plan lacks a string instance_id or an integer recovery_key_epoch",
        ));
    };
    if !PLAN_REPLACEMENT
        .iter()
        .all(|name| plan_text(plan, name).is_some())
    {
        return Err(encode_error(
            "plan lacks a string admin_id, credential_id, binding_id, public_identity or \
             trust_anchor_ref",
        ));
    }
    if !plan_text(plan, PLAN_NEW_RECOVERY_PUBLIC_KEY).is_some_and(plan_key) {
        return Err(encode_error(
            "plan new_recovery_public_key is not 64 lowercase hexadecimal digits",
        ));
    }
    if request.ttl < MIN_CHALLENGE_TTL || request.ttl > MAX_CHALLENGE_TTL {
        return Err(encode_error("challenge TTL is not 1 second to 15 minutes"));
    }
    audit_time(request.now)?;
    let expires_at = request
        .now
        .checked_add(request.ttl)
        .ok_or_else(|| encode_error("timestamp out of range"))?;
    Ok((since_epoch(expires_at)?, binding))
}

/// The checks of a restore that run before any statement: `now` as an
/// interval.
fn validate_restore(request: &RestoreRequest<'_>) -> Result<PgInterval, RegistryError> {
    if is_reserved_actor_id(request.admin_id) {
        return Err(RegistryError::ReservedActorId);
    }
    if request.new_recovery_public_key.len() != RECOVERY_PUBLIC_KEY_LENGTH {
        return Err(encode_error(
            "recovery public key is not a 32-byte Ed25519 key",
        ));
    }
    if !bounded(request.public_identity) {
        return Err(encode_error("public identity is empty or over 2048 bytes"));
    }
    if !bounded(request.trust_anchor_ref) {
        return Err(encode_error(
            "trust anchor reference is empty or over 2048 bytes",
        ));
    }
    audit_time(request.now)
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
/// operation (see the module docs). Never commits or rolls back the
/// caller's transaction, only its own savepoint, which it rolls back on
/// every `Err`.
pub async fn issue_recovery_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    request: &IssueChallenge<'_>,
) -> Result<RecoveryChallenge, ChallengeError> {
    let (expires_at, plan) = validate_issue(request)?;
    let mut savepoint = transaction.begin().await?;
    match issue_steps(&mut savepoint, request, expires_at, plan).await {
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
    (plan_instance, plan_epoch): (&str, i64),
) -> Result<RecoveryChallenge, ChallengeError> {
    // Step 1: the closed recovery state, shared.
    let state: Option<RecoveryState> = sqlx::query_as(SHARE_RECOVERY_STATE)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(state) = state.filter(|state| state.bootstrap_closed) else {
        return Err(ChallengeError::NotIssuable);
    };
    if state.instance_id != plan_instance || state.recovery_key_epoch != plan_epoch {
        return Err(ChallengeError::NotIssuable);
    }

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
        .bind(request.request_digest)
        .bind(state.revision)
        .bind(Json(request.immutable_plan))
        .bind(request.challenge_hash)
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
        audit_event,
    })
}

/// The consume statement: the consumed challenge's plan, or `None` on any
/// miss (see the module docs, "Consume").
async fn consume(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    binding: &ChallengeBinding<'_>,
    now: PgInterval,
) -> Result<Option<JsonObject>, sqlx::Error> {
    let row = sqlx::query(CONSUME_CHALLENGE)
        .bind(operation_id)
        .bind(now)
        .bind(binding.request_digest)
        .bind(binding.expected_revision)
        .bind(binding.instance_id)
        .bind(binding.recovery_key_epoch)
        .fetch_optional(&mut **transaction)
        .await?;
    row.map(|row| json(&row, "immutable_plan")).transpose()
}

/// Consumes the challenge and restores operator authority in
/// `transaction` (see the module docs for the steps). Never commits or
/// rolls back the caller's transaction, only its own savepoint, which it
/// rolls back on every `Err`, the consume included: the caller commits on
/// `Ok` and rolls back on `Err`.
pub async fn restore_operator(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError> {
    let now = validate_restore(request)?;
    let mut savepoint = transaction.begin().await?;
    match restore_steps(&mut savepoint, request, now).await {
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
    // Step 2: the recovery state.
    let state: Option<RecoveryState> = sqlx::query_as(LOCK_RECOVERY_STATE)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(state) = state else {
        return Err(RestoreError::NotRestorable);
    };
    // Step 3: consume the challenge, bound to the locked state.
    let Some(plan) = consume(transaction, request.operation_id, &request.binding, now).await?
    else {
        return Err(RestoreError::NotRestorable);
    };
    // Step 4: the replacement is the one the signer approved.
    if !plan_names(&plan, request) {
        return Err(RestoreError::NotRestorable);
    }
    // Step 5: the used key is retired, not kept.
    if state.recovery_public_key == request.new_recovery_public_key {
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
            id: request.admin_id.into(),
            status: Status::Enabled,
            created_at: request.now,
        },
    )
    .await?;
    let credential = create_admin_credential(
        &mut **transaction,
        &NewAdminCredential {
            id: request.credential_id.into(),
            admin_id: identity.id.clone(),
            public_identity: request.public_identity.into(),
            trust_anchor_ref: request.trust_anchor_ref.into(),
            status: Status::Enabled,
        },
    )
    .await?;
    let binding = create_admin_role_binding(
        &mut **transaction,
        &NewAdminRoleBinding {
            id: request.binding_id.into(),
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
        .bind(request.new_recovery_public_key)
        .bind(state.recovery_key_epoch)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(rotated) = rotated else {
        return Err(RestoreError::NotRestorable);
    };
    let recovery_key_epoch: i64 = rotated.try_get("recovery_key_epoch")?;
    let recovery_state_revision: i64 = rotated.try_get("revision")?;

    // Step 9: the operation's outcome.
    sqlx::query(MARK_RESTORED)
        .bind(request.operation_id)
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

    use serde_json::json;

    use super::*;

    const DIGEST: [u8; 32] = [1; 32];
    const HASH: [u8; 64] = [2; 64];
    const KEY: [u8; 32] = [0xa3; 32];

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_790_000_000)
    }

    fn plan(value: serde_json::Value) -> JsonObject {
        match value {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    /// `value` with the replacement of [`restore`] added.
    fn full(value: serde_json::Value) -> JsonObject {
        let mut plan = plan(value);
        let key = "a3".repeat(32);
        for (name, member) in [
            (PLAN_ADMIN_ID, "adm_new"),
            (PLAN_CREDENTIAL_ID, "crd_new"),
            (PLAN_BINDING_ID, "rb_new"),
            (PLAN_PUBLIC_IDENTITY, "spki-sha256:new"),
            (PLAN_TRUST_ANCHOR_REF, "deployment/operator-ca"),
            (PLAN_NEW_RECOVERY_PUBLIC_KEY, &key[..]),
        ] {
            plan.entry(name).or_insert_with(|| json!(member));
        }
        plan
    }

    fn good_plan() -> JsonObject {
        full(json!({"instance_id": "inst", "recovery_key_epoch": 1, "operation": "restore"}))
    }

    fn issue(plan: &JsonObject) -> IssueChallenge<'_> {
        IssueChallenge {
            operation_id: "op_1",
            kind: OPERATOR_RESTORATION,
            request_digest: &DIGEST,
            immutable_plan: plan,
            challenge_hash: &HASH,
            ttl: DEFAULT_CHALLENGE_TTL,
            now: now(),
            audit_event_id: "aud_1",
        }
    }

    fn restore() -> RestoreRequest<'static> {
        RestoreRequest {
            operation_id: "op_1",
            binding: ChallengeBinding {
                request_digest: &DIGEST,
                instance_id: "inst",
                expected_revision: 1,
                recovery_key_epoch: 1,
            },
            admin_id: "adm_new",
            credential_id: "crd_new",
            binding_id: "rb_new",
            public_identity: "spki-sha256:new",
            trust_anchor_ref: "deployment/operator-ca",
            new_recovery_public_key: &KEY,
            audit_event_id: "aud_restore",
            rotation_audit_event_id: "aud_rotate",
            now: now(),
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
    fn digests_are_32_to_64_bytes() {
        let plan = good_plan();
        for length in [0, 1, 31, 65, 128] {
            let bytes = vec![9; length];
            let mut request = issue(&plan);
            request.request_digest = &bytes;
            assert_eq!(
                encode(validate_issue(&request)),
                "request digest is not 32 to 64 bytes"
            );
            let mut request = issue(&plan);
            request.challenge_hash = &bytes;
            assert_eq!(
                encode(validate_issue(&request)),
                "challenge hash is not 32 to 64 bytes"
            );
        }
        for length in [32, 48, 64] {
            let bytes = vec![9; length];
            let mut request = issue(&plan);
            request.request_digest = &bytes;
            request.challenge_hash = &bytes;
            assert!(validate_issue(&request).is_ok(), "{length}");
        }
    }

    #[test]
    fn the_plan_carries_a_string_instance_and_an_integer_epoch() {
        for (value, binding) in [
            (
                json!({"instance_id": "inst", "recovery_key_epoch": 1}),
                ("inst", 1),
            ),
            (
                json!({"instance_id": "", "recovery_key_epoch": 7, "x": [1]}),
                ("", 7),
            ),
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
            assert_eq!(parsed, binding);
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
    /// hexadecimal digits; their values are the restore's to compare.
    #[test]
    fn the_plan_carries_the_replacement() {
        assert_eq!(
            PLAN_REPLACEMENT,
            [
                "admin_id",
                "credential_id",
                "binding_id",
                "public_identity",
                "trust_anchor_ref"
            ]
        );
        assert_eq!(PLAN_NEW_RECOVERY_PUBLIC_KEY, "new_recovery_public_key");
        let message = "plan lacks a string admin_id, credential_id, binding_id, public_identity \
                       or trust_anchor_ref";
        for name in PLAN_REPLACEMENT {
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
            // Any string passes the issue, the empty one included.
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
            Some(json!("a3".repeat(31))),
            Some(json!("a3".repeat(33))),
            Some(json!(format!("{}a", "a3".repeat(31)))),
            Some(json!("A3".repeat(32))),
            Some(json!(format!("{}g0", "a3".repeat(31)))),
            Some(json!(format!("{} 0", "a3".repeat(31)))),
            Some(json!(format!("0x{}", "a3".repeat(31)))),
            Some(json!([KEY])),
        ] {
            let mut plan = good_plan();
            match bad.clone() {
                None => plan.remove(PLAN_NEW_RECOVERY_PUBLIC_KEY),
                Some(value) => plan.insert(PLAN_NEW_RECOVERY_PUBLIC_KEY.into(), value),
            };
            assert_eq!(encode(validate_issue(&issue(&plan))), message, "{bad:?}");
        }
        for good in ["0123456789abcdef".repeat(4), "f".repeat(64), "0".repeat(64)] {
            assert!(plan_key(&good), "{good}");
            let mut plan = good_plan();
            plan.insert(PLAN_NEW_RECOVERY_PUBLIC_KEY.into(), json!(good));
            assert!(validate_issue(&issue(&plan)).is_ok());
        }
    }

    /// Step 4: every member equal, byte-wise; any one changed is a miss.
    #[test]
    fn a_restore_names_exactly_the_planned_replacement() {
        assert_eq!(lower_hex(&[]), "");
        assert_eq!(lower_hex(&[0, 1, 0x0f, 0x10, 0xab, 0xff]), "00010f10abff");
        assert_eq!(lower_hex(&KEY), "a3".repeat(32));
        let plan = good_plan();
        assert!(plan_names(&plan, &restore()));
        let other_key = [0xa4; 32];
        let changes: [fn(&mut RestoreRequest<'static>); 7] = [
            |request| request.admin_id = "adm_other",
            |request| request.credential_id = "crd_other",
            |request| request.binding_id = "rb_other",
            |request| request.public_identity = "spki-sha256:other",
            |request| request.trust_anchor_ref = "deployment/other-ca",
            |request| request.admin_id = "ADM_NEW",
            |request| request.public_identity = "spki-sha256:new ",
        ];
        for (index, change) in changes.iter().enumerate() {
            let mut request = restore();
            change(&mut request);
            assert!(!plan_names(&plan, &request), "{index}");
        }
        let mut request = restore();
        request.new_recovery_public_key = &other_key;
        assert!(!plan_names(&plan, &request));
        // An upper-case plan key names no key.
        let mut upper = good_plan();
        upper.insert(PLAN_NEW_RECOVERY_PUBLIC_KEY.into(), json!("A3".repeat(32)));
        assert!(!plan_names(&upper, &restore()));
        // A member that is missing or not a string names nothing.
        for name in PLAN_REPLACEMENT
            .into_iter()
            .chain([PLAN_NEW_RECOVERY_PUBLIC_KEY])
        {
            let mut missing = good_plan();
            missing.remove(name);
            assert!(!plan_names(&missing, &restore()), "{name}");
            let mut number = good_plan();
            number.insert(name.into(), json!(1));
            assert!(!plan_names(&number, &restore()), "{name}");
        }
    }

    /// The audit writer's years, as in bootstrap, for both calls.
    #[test]
    fn only_the_audit_years_are_accepted() {
        const EARLIEST: u64 = 62_167_219_200_000_000;
        const LATEST: u64 = 253_402_300_799_999_999;
        let plan = good_plan();
        for time in [
            UNIX_EPOCH - Duration::from_micros(EARLIEST),
            UNIX_EPOCH + Duration::from_micros(LATEST) + Duration::from_nanos(999),
        ] {
            let mut request = issue(&plan);
            request.now = time;
            assert!(validate_issue(&request).is_ok(), "{time:?}");
            assert!(audit_time(time).is_ok(), "{time:?}");
            let mut restored = restore();
            restored.now = time;
            assert!(validate_restore(&restored).is_ok(), "{time:?}");
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
            let mut restored = restore();
            restored.now = time;
            assert_eq!(encode(validate_restore(&restored)), message);
        }
        let far = UNIX_EPOCH + Duration::from_micros(u64::try_from(i64::MAX).unwrap());
        assert_eq!(encode(audit_time(far)), "timestamp out of range");
    }

    #[test]
    fn a_restore_checks_its_input_before_any_statement() {
        assert!(validate_restore(&restore()).is_ok());
        for id in [DEPLOYMENT_OPERATOR_ACTOR, "recovery_key:", "recovery_key:1"] {
            let mut reserved = restore();
            reserved.admin_id = id;
            reserved.new_recovery_public_key = &[];
            assert!(
                matches!(
                    validate_restore(&reserved),
                    Err(RegistryError::ReservedActorId)
                ),
                "{id}"
            );
        }
        for length in [0, 1, 31, 33, 64] {
            let key = vec![1; length];
            let mut bad = restore();
            bad.new_recovery_public_key = &key;
            assert_eq!(
                encode(validate_restore(&bad)),
                "recovery public key is not a 32-byte Ed25519 key",
                "{length}"
            );
        }
        let long = "k".repeat(2049);
        let longest = "k".repeat(2048);
        for (value, ok) in [("", false), (&long[..], false), (&longest[..], true)] {
            let mut checked = restore();
            checked.public_identity = value;
            match ok {
                true => assert!(validate_restore(&checked).is_ok()),
                false => assert_eq!(
                    encode(validate_restore(&checked)),
                    "public identity is empty or over 2048 bytes"
                ),
            }
            let mut checked = restore();
            checked.trust_anchor_ref = value;
            match ok {
                true => assert!(validate_restore(&checked).is_ok()),
                false => assert_eq!(
                    encode(validate_restore(&checked)),
                    "trust anchor reference is empty or over 2048 bytes"
                ),
            }
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
                RestoreError::NotRestorable,
                "no recovery challenge authorizes this restoration",
                "NotRestorable",
            ),
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
        assert_eq!(RestoreError::NotRestorable, RestoreError::NotRestorable);
        assert_ne!(
            RestoreError::NotRestorable,
            RestoreError::RecoveryKeyUnchanged
        );
        assert_eq!(
            RestoreError::UnsupportedIsolation,
            RestoreError::UnsupportedIsolation
        );
        assert_ne!(
            RestoreError::UnsupportedIsolation,
            RestoreError::NotRestorable
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
