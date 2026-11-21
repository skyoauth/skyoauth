//! Break-glass operator restoration at the registry level (design section
//! 7.2; ADR-013 item 8; identity-registry section 5.2; lifetimes LT-107;
//! T13.5): [`get_recovery_state`] reads the recovery key and its epoch,
//! [`issue_recovery_challenge`] records an expiring challenge,
//! [`consume_recovery_challenge`] uses it up once, and [`restore_operator`]
//! consumes it the same way and, in the same savepoint, enrolls a
//! replacement `security_admin`, revokes every operator credential, rotates
//! the recovery key and records the audit event.
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
//!    (identity-registry section 5.2, provisional lead pick: raw 32-byte
//!    Ed25519 key). The verifier verifies the signature *before* it
//!    consumes the challenge.
//! 3. In one transaction the verifier calls [`restore_operator`], which
//!    consumes the challenge (the statement of
//!    [`consume_recovery_challenge`]) and restores inside one savepoint, and
//!    commits. Any failure is an `Err` with the savepoint rolled back, the
//!    consume included: the challenge is then still unconsumed, and nothing
//!    of the restore is left, even if the caller commits; the caller still
//!    rolls back on `Err`. (inferred: the restore consumes itself, so that
//!    one savepoint covers the consume and the restoration.)
//!
//! [`consume_recovery_challenge`] stands alone for a later break-glass kind
//! (the M1b provider transitions); for a restoration the caller does not
//! call it before [`restore_operator`], which would then find the challenge
//! consumed.
//!
//! The consume statement is the only thing that makes a challenge
//! single-use (LT-107). It sets `consumed_at` in one `UPDATE` whose `WHERE`
//! holds every condition; the database backs it: the set-once guard
//! `administrative_operation_set_once` refuses a second `consumed_at`, the
//! `administrative_operation_no_consume_after_revoke` guard refuses to
//! consume a revoked challenge (both `SK001`), and
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
//!    verifier records it; nobody has signed yet), action
//!    `administrative_operation.create`, `object_id` the operation ID,
//!    `previous_revision` none, `new_revision` 1, outcome `success`;
//! 3. inserts the operation: no tenant, `actor_id` `deployment_operator`,
//!    the kind, digest, plan and challenge hash, `expected_revision`,
//!    `expires_at = now + ttl`, `audit_id` the event, outcome `issued`,
//!    revision 1, unconsumed and unrevoked.
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
//! a JSON object that must carry the string `instance_id` and the integer
//! `recovery_key_epoch` (lead ruling: the epoch lives in the plan, no
//! column); other members are the caller's (the operation and its
//! arguments), and must hold no secret: the plan is kept for the life of
//! the row. `challenge_hash` is computed by the caller as well; the registry
//! does not hash.
//!
//! # Consume
//!
//! [`consume_recovery_challenge`] runs one statement:
//! `UPDATE administrative_operation SET consumed_at = $now` (and the revision
//! by one) where the ID matches, the kind is `operator_restoration`,
//! `challenge_hash` is set, `consumed_at` and `revoked_at` are unset, the
//! outcome is still `issued`, `$now < expires_at`, `request_digest` and `expected_revision` equal the
//! binding's, the plan's `instance_id` is a JSON string equal to the
//! binding's and its `recovery_key_epoch` a JSON number whose text is the
//! binding's epoch in decimal, and the `recovery_state` row has the
//! binding's `instance_id`, the binding's epoch and the binding's
//! `expected_revision` as its `revision` (inferred: the challenge is bound
//! to the revision of the state it rotates). A plan epoch that is a string,
//! a fraction (`1.5`, and `1.0` too, whose `jsonb` text keeps the
//! fraction), `null`, negative or missing therefore matches nothing.
//!
//! Every miss (an unknown ID; an expired, consumed or revoked challenge;
//! another outcome; another kind; a digest, instance, revision or epoch that is not the
//! binding's; a retired epoch; a missing or malformed plan epoch) is the
//! one unit value [`ChallengeError::NotConsumable`], with no detail and the
//! same `Debug` and `Display`. As for
//! [`select_grant`](super::select_grant), no claim is made about timing.
//!
//! The standalone consume reads the `recovery_state` row without locking
//! it; [`restore_operator`] runs the statement after locking the row, so
//! there the binding is checked against the state it rotates. Of two
//! concurrent consumes of one challenge, under
//! `READ COMMITTED`, the second waits for the first's row lock; when the
//! first commits it finds `consumed_at` set and is `NotConsumable`, and when
//! the first rolls back it consumes. Consume writes no audit event: the
//! restore event records it.
//!
//! # Restore
//!
//! [`restore_operator`] checks its input before any statement, then, inside
//! a savepoint of its own:
//!
//! 1. locks every unrevoked `admin_credential` row
//!    `FOR NO KEY UPDATE`, in key order, in one statement;
//! 2. locks the `recovery_state` row `FOR NO KEY UPDATE` and reads it; no
//!    row is [`RestoreError::NotRestorable`];
//! 3. consumes the challenge with the consume statement (see "Consume"),
//!    at `now`, for the request's binding, against the row it holds; a miss
//!    is the one unit value [`RestoreError::NotRestorable`];
//! 4. refuses a new recovery key equal to the current one,
//!    [`RestoreError::RecoveryKeyUnchanged`];
//! 5. revokes every credential still unrevoked, in one statement: sets
//!    `revoked_at = now` and `status = 'disabled'` on every `admin_credential`
//!    row whose `revoked_at` is `NULL`, enabled or not, the credential of the
//!    operator being replaced included. The replacement credential is
//!    created after this statement, so it is not among them. A credential
//!    revoked before keeps its first `revoked_at`;
//! 6. enrolls the replacement: an enabled identity created at `now`, an
//!    enabled unrevoked credential and an enabled instance `security_admin`
//!    binding, each with `INSERT ... ON CONFLICT DO NOTHING RETURNING` and no
//!    conflict target (only the `INSERT` privilege needed). An insert that
//!    returns no row met an existing key: [`RegistryError::AlreadyExists`]
//!    naming `admin_identity_pkey`, `admin_credential_pkey` (the credential
//!    ID is taken), `admin_credential_public_identity_key` (otherwise: a key
//!    registered before, revoked or not) or `admin_role_binding_pkey`;
//! 7. rotates the key: `recovery_public_key` the new key,
//!    `recovery_key_epoch` and `revision` one more, so the used key is
//!    retired (OQ-TM-8; the `0005` trigger
//!    `skyoauth_check_recovery_key_rotation` requires the epoch to advance
//!    exactly when the key changes). No other path replaces the key
//!    (OQ-TM-15);
//! 8. sets the operation's `outcome` to `restored` and advances its
//!    revision; `consumed_at` stays as the consume set it (`outcome` and
//!    `revision` are the only plain mutable columns of the row);
//! 9. appends the audit event LAST, as for every write that inserts no
//!    operation (the audit-before-operation order applies only to an
//!    operation insert; this operation exists already and has the issue
//!    event): instance scope, actor
//!    `{"type": "operator", "id": "recovery_key:<epoch>"}` with the epoch of
//!    the key whose signature authorized the restore (the old one), action
//!    `admin_identity.restore`, `object_id` the new operator's ID, revisions
//!    none (an identity has no revision), outcome `success`. The envelope
//!    has no member for the operation's ID: `object_id` names the new
//!    operator, and the revisions are integers, so the event does not record
//!    it (the operation row's `consumed_at` equals the event's timestamp).
//!
//! It touches no identity or role binding but the new ones, and no
//! workload, trust, grant, audience or token state. It does only what T13.5
//! permits M1a: enroll a replacement `security_admin` credential and revoke
//! operator credentials. The M1b provider transitions are not here.
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
//! second then finds the epoch advanced: `NotRestorable`. Under
//! `REPEATABLE READ` or `SERIALIZABLE` a waiter fails with `40001`
//! ([`RegistryError::Retry`]) instead.
//!
//! Step 1 waits for every transaction that holds a credential
//! `FOR SHARE`, the locks of
//! [`authorize_operator_locked`](super::authorize_operator_locked), so an
//! operator write authorized before the restore commits before step 5,
//! whose snapshot then sees a credential it enrolled; one authorized after
//! step 1 waits for the restore and then finds its credential revoked. An
//! operator write authorized by the unlocked
//! [`authorize_operator`](super::authorize_operator) has no such guarantee.
//!
//! # Validation
//!
//! Before any statement, as an encode error ([`RegistryError::Other`] in
//! `Store`, naming no value), as in [`bootstrap_instance`]:
//!
//! - issue: a kind other than `operator_restoration` (the M1a set,
//!   inferred); a `request_digest` or `challenge_hash` not 32 to 64 bytes;
//!   a plan without a string `instance_id` or an integer
//!   `recovery_key_epoch` (a JSON number that is an `i64`); a `ttl` of zero
//!   or above [`MAX_CHALLENGE_TTL`];
//! - restore: a reserved `admin_id` ([`RegistryError::ReservedActorId`]); a
//!   new recovery key that is not exactly 32 bytes; an empty or
//!   over-2048-byte `public_identity` or `trust_anchor_ref`;
//! - all three: a `now` outside the `0007` range, or outside the years
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
//! decision 2026-11-19); the strictly positive lower bound is inferred.
//! `expires_at` is `now + ttl`, truncated to the microsecond as every
//! stored time. A restore uses its one `now` for the consume, the
//! revocations, the new operator and its audit event.
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
//! (`audit_event_pkey`, from the audit writer) and a caller-supplied
//! operation ID taken (`administrative_operation_pkey`, from an insert
//! that returned no row) are the ordinary [`RegistryError::AlreadyExists`]
//! in `Store`, as are the replacement's keys (step 6 of "Restore").
//!
//! When the commit's outcome is unknown, for example because the
//! connection failed during `COMMIT`, the caller keeps all the request's
//! material (the IDs, the signed challenge and its binding, the
//! replacement's credential and the new recovery public key) until it has
//! reconnected and reconciled the durable state: whether the operation is
//! `restored` and the recovery state is at the new epoch with the new key,
//! or the challenge is still unconsumed. It then retries the same request.
//! A retry of a restoration that committed is
//! [`RestoreError::NotRestorable`] (its challenge is consumed), which with
//! that state means the restoration happened; one that did not commit
//! restores. A retry of an issue that committed fails with
//! `AlreadyExists` on `audit_event_pkey`.
//!
//! [`bootstrap_instance`]: super::bootstrap_instance

use std::{
    fmt,
    time::{Duration, SystemTime},
};

use serde_json::Value;
use sqlx::{
    Connection, FromRow, PgExecutor, Postgres, Row, Transaction,
    postgres::{PgRow, types::PgInterval},
    types::Json,
};

use super::{
    AuditActor, AuditEvent, DEPLOYMENT_OPERATOR_ACTOR, JsonObject, NewAuditEvent,
    RECOVERY_PUBLIC_KEY_LENGTH, RegistryError, append_audit_event,
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

/// The one challenge kind of M1a (T13.5; inferred name).
pub const OPERATOR_RESTORATION: &str = "operator_restoration";

/// The plan member that names the instance.
pub const PLAN_INSTANCE_ID: &str = "instance_id";

/// The plan member that names the epoch of the key that must sign.
pub const PLAN_RECOVERY_KEY_EPOCH: &str = "recovery_key_epoch";

/// The action of the issue event (inferred; see the module docs).
const ISSUE_ACTION: &str = "administrative_operation.create";

/// The action of the restore event (identity-registry IR-059).
const RESTORE_ACTION: &str = "admin_identity.restore";

/// The outcome of an issued challenge (inferred).
const ISSUED: &str = "issued";

/// The outcome of a challenge whose restore ran (inferred).
const RESTORED: &str = "restored";

/// The outcome of both events (inferred, as for bootstrap).
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
     ON CONFLICT DO NOTHING RETURNING id, expected_revision, ",
    micros!("expires_at")
);

/// `$1` the ID, `$2` `now`, `$3` the digest, `$4` the expected revision,
/// `$5` the instance and `$6` the epoch.
const CONSUME_CHALLENGE: &str = concat!(
    "UPDATE administrative_operation \
     SET consumed_at = timestamptz 'epoch' + $2::interval, revision = revision + 1 \
     WHERE id = $1 \
       AND kind = 'operator_restoration' \
       AND challenge_hash IS NOT NULL \
       AND consumed_at IS NULL \
       AND revoked_at IS NULL \
       AND outcome = 'issued' \
       AND timestamptz 'epoch' + $2::interval < expires_at \
       AND request_digest = $3 \
       AND expected_revision = $4 \
       AND jsonb_typeof(immutable_plan -> 'instance_id') = 'string' \
       AND immutable_plan ->> 'instance_id' = $5 \
       AND jsonb_typeof(immutable_plan -> 'recovery_key_epoch') = 'number' \
       AND immutable_plan ->> 'recovery_key_epoch' = $6::bigint::text \
       AND EXISTS (SELECT FROM recovery_state r WHERE r.instance_id = $5 \
         AND r.recovery_key_epoch = $6 AND r.revision = $4) \
     RETURNING id, request_digest, expected_revision, immutable_plan, revision, ",
    micros!("expires_at"),
    ", ",
    micros!("consumed_at")
);

/// Step 1 of a restore: every unrevoked credential, in key order.
const LOCK_CREDENTIALS: &str = "SELECT id FROM admin_credential WHERE revoked_at IS NULL \
     ORDER BY id COLLATE \"C\" FOR NO KEY UPDATE";

/// Step 5 of a restore: one statement for every unrevoked credential.
const REVOKE_ALL_CREDENTIALS: &str = "UPDATE admin_credential \
     SET status = 'disabled', revoked_at = timestamptz 'epoch' + $1::interval \
     WHERE revoked_at IS NULL RETURNING id";

/// Step 6 of a restore: the replacement, or no row when a row holds the
/// ID. No conflict target: any unique key, and `INSERT` suffices.
const INSERT_IDENTITY: &str = "INSERT INTO admin_identity (id, status, created_at) \
     VALUES ($1, 'enabled', timestamptz 'epoch' + $2::interval) \
     ON CONFLICT DO NOTHING RETURNING id";

/// Step 6: the replacement's credential, or no row when a row holds the ID
/// or the public identity.
const INSERT_CREDENTIAL: &str = "INSERT INTO admin_credential \
     (id, admin_id, public_identity, trust_anchor_ref, status) \
     VALUES ($1, $2, $3, $4, 'enabled') ON CONFLICT DO NOTHING RETURNING id";

/// Which key a credential insert that returned no row conflicted on.
const CREDENTIAL_ID_TAKEN: &str = "SELECT EXISTS (SELECT FROM admin_credential WHERE id = $1)";

/// Step 6: the replacement's instance `security_admin` binding, or no row
/// when a row holds the ID (the new identity has no other binding).
const INSERT_BINDING: &str = "INSERT INTO admin_role_binding \
     (id, admin_id, role, tenant_id, status) \
     VALUES ($1, $2, 'security_admin', NULL, 'enabled') ON CONFLICT DO NOTHING RETURNING id";

/// Step 7 of a restore. `$1` the instance, `$2` the new key, `$3` the
/// current epoch.
const ROTATE_RECOVERY_KEY: &str = "UPDATE recovery_state \
     SET recovery_public_key = $2, recovery_key_epoch = recovery_key_epoch + 1, \
         revision = revision + 1 \
     WHERE instance_id = $1 AND recovery_key_epoch = $3 \
     RETURNING recovery_key_epoch, revision";

/// Step 8 of a restore.
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
    /// A JSON object with the string [`PLAN_INSTANCE_ID`] and the integer
    /// [`PLAN_RECOVERY_KEY_EPOCH`]; no secrets.
    pub immutable_plan: &'a JsonObject,
    /// The hash of the challenge the workstation signs, 32 to 64 bytes,
    /// computed by the caller.
    pub challenge_hash: &'a [u8],
    /// More than zero and at most [`MAX_CHALLENGE_TTL`];
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

/// What a consume must match besides the operation's ID: the values the
/// signed challenge carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeBinding<'a> {
    pub request_digest: &'a [u8],
    pub instance_id: &'a str,
    pub expected_revision: i64,
    pub recovery_key_epoch: i64,
}

/// A challenge [`consume_recovery_challenge`] consumed: the operation row
/// as the consume left it.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsumedChallenge {
    pub operation_id: String,
    /// The binding's, equal to the plan's and the recovery state's.
    pub instance_id: String,
    /// The binding's, equal to the plan's and the recovery state's.
    pub recovery_key_epoch: i64,
    pub expected_revision: i64,
    pub request_digest: Vec<u8>,
    pub immutable_plan: JsonObject,
    pub expires_at: SystemTime,
    /// The consume's `now`, as stored.
    pub consumed_at: SystemTime,
    /// The operation's revision after the consume.
    pub revision: i64,
}

impl FromRow<'_, PgRow> for ConsumedChallenge {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("administrative_operation");
        Ok(Self {
            operation_id: row.try_get("id")?,
            instance_id: String::new(),
            recovery_key_epoch: 0,
            expected_revision: row.try_get("expected_revision")?,
            request_digest: row.try_get("request_digest")?,
            immutable_plan: json(row, "immutable_plan")?,
            expires_at: required_timestamp(row, ORIGIN, "expires_at")?,
            consumed_at: required_timestamp(row, ORIGIN, "consumed_at")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// Why a challenge was not issued or consumed.
///
/// Values compare equal when they are the same unit variant; a `Store`
/// value never compares equal, since [`RegistryError`] has no equality.
#[derive(Debug)]
pub enum ChallengeError {
    /// No closed recovery state, or the plan names another instance or
    /// epoch. No detail.
    NotIssuable,
    /// Every miss of a consume, one value with no detail (see the module
    /// docs).
    NotConsumable,
    /// Invalid input or a store failure. [`RegistryError::Retry`] means
    /// retry the whole transaction.
    Store(RegistryError),
}

impl PartialEq for ChallengeError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::NotIssuable, Self::NotIssuable) | (Self::NotConsumable, Self::NotConsumable)
        )
    }
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotIssuable => f.write_str("a recovery challenge cannot be issued"),
            Self::NotConsumable => f.write_str("the recovery challenge is not consumable"),
            Self::Store(err) => write!(f, "recovery challenge failed: {err}"),
        }
    }
}

impl std::error::Error for ChallengeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotIssuable | Self::NotConsumable => None,
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RestoreRequest<'a> {
    /// The restoration challenge the restore consumes, as
    /// [`consume_recovery_challenge`] would, inside its own savepoint.
    pub operation_id: &'a str,
    /// What the signed challenge carried.
    pub binding: ChallengeBinding<'a>,
    /// The replacement operator; not reserved.
    pub admin_id: &'a str,
    pub credential_id: &'a str,
    pub binding_id: &'a str,
    /// The canonical public-key identity of the replacement's mTLS
    /// credential, 1 to 2048 bytes, not registered before.
    pub public_identity: &'a str,
    /// 1 to 2048 bytes.
    pub trust_anchor_ref: &'a str,
    /// The raw Ed25519 public key that replaces the used one: exactly
    /// [`RECOVERY_PUBLIC_KEY_LENGTH`] bytes and not the current key.
    pub new_recovery_public_key: &'a [u8],
    pub audit_event_id: &'a str,
    /// The time of the consume, the revocations, the new operator and the
    /// audit event.
    pub now: SystemTime,
}

/// What [`restore_operator`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    /// The credentials step 5 revoked, sorted byte-wise.
    pub revoked_credential_ids: Vec<String>,
    /// The new epoch, one more than the used key's.
    pub recovery_key_epoch: i64,
    /// The recovery state's new revision.
    pub recovery_state_revision: i64,
    /// The `admin_identity.restore` event.
    pub audit_event: AuditEvent,
}

/// Why [`restore_operator`] did not restore. On every variant its savepoint
/// is rolled back; the caller rolls back too.
///
/// Values compare equal when they are the same unit variant; a `Store`
/// value never compares equal.
#[derive(Debug)]
pub enum RestoreError {
    /// No recovery state, or the challenge is not consumable for the
    /// binding (every miss of the consume). No detail.
    NotRestorable,
    /// The new recovery key is the current one, which must be retired.
    RecoveryKeyUnchanged,
    /// Invalid input or a store failure; see the module docs.
    Store(RegistryError),
}

impl PartialEq for RestoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::NotRestorable, Self::NotRestorable)
                | (Self::RecoveryKeyUnchanged, Self::RecoveryKeyUnchanged)
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
            Self::Store(err) => write!(f, "operator restoration failed: {err}"),
        }
    }
}

impl std::error::Error for RestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotRestorable | Self::RecoveryKeyUnchanged => None,
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

/// The plan's instance and epoch: a string and an `i64` JSON integer.
fn plan_binding(plan: &JsonObject) -> Option<(&str, i64)> {
    let instance_id = plan.get(PLAN_INSTANCE_ID).and_then(Value::as_str)?;
    let epoch = plan.get(PLAN_RECOVERY_KEY_EPOCH).and_then(Value::as_i64)?;
    Some((instance_id, epoch))
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
    let Some(binding) = plan_binding(request.immutable_plan) else {
        return Err(encode_error(
            "plan lacks a string instance_id or an integer recovery_key_epoch",
        ));
    };
    if request.ttl.is_zero() || request.ttl > MAX_CHALLENGE_TTL {
        return Err(encode_error(
            "challenge TTL is not more than zero and at most 15 minutes",
        ));
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
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(row) = row else {
        return Err(RegistryError::AlreadyExists {
            constraint: "administrative_operation_pkey",
        }
        .into());
    };
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

/// Consumes the challenge `operation_id` at `now` if it matches `binding`,
/// in one statement inside a savepoint of its own (see the module docs).
/// Every miss is [`ChallengeError::NotConsumable`]. The caller verified the
/// signature before. [`restore_operator`] runs the same statement itself.
pub async fn consume_recovery_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    binding: &ChallengeBinding<'_>,
    now: SystemTime,
) -> Result<ConsumedChallenge, ChallengeError> {
    let now = audit_time(now)?;
    let mut savepoint = transaction.begin().await?;
    match consume(&mut savepoint, operation_id, binding, now).await {
        Ok(Some(consumed)) => {
            savepoint.commit().await?;
            Ok(consumed)
        }
        Ok(None) => {
            let _ = savepoint.rollback().await;
            Err(ChallengeError::NotConsumable)
        }
        Err(err) => {
            let _ = savepoint.rollback().await;
            Err(err.into())
        }
    }
}

/// The consume statement: the consumed challenge, or `None` on any miss.
async fn consume(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    binding: &ChallengeBinding<'_>,
    now: PgInterval,
) -> Result<Option<ConsumedChallenge>, sqlx::Error> {
    let consumed: Option<ConsumedChallenge> = sqlx::query_as(CONSUME_CHALLENGE)
        .bind(operation_id)
        .bind(now)
        .bind(binding.request_digest)
        .bind(binding.expected_revision)
        .bind(binding.instance_id)
        .bind(binding.recovery_key_epoch)
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(consumed.map(|mut consumed| {
        consumed.instance_id = binding.instance_id.into();
        consumed.recovery_key_epoch = binding.recovery_key_epoch;
        consumed
    }))
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

/// Steps 1 to 9 of a restore, in the savepoint of [`restore_operator`].
async fn restore_steps(
    transaction: &mut Transaction<'_, Postgres>,
    request: &RestoreRequest<'_>,
    now: PgInterval,
) -> Result<Restored, RestoreError> {
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
    if consume(transaction, request.operation_id, &request.binding, now)
        .await?
        .is_none()
    {
        return Err(RestoreError::NotRestorable);
    }
    // Step 4: the used key is retired, not kept.
    if state.recovery_public_key == request.new_recovery_public_key {
        return Err(RestoreError::RecoveryKeyUnchanged);
    }

    // Step 5: revoke every unrevoked credential, before the new one exists.
    let mut revoked_credential_ids: Vec<String> = sqlx::query_scalar(REVOKE_ALL_CREDENTIALS)
        .bind(now)
        .fetch_all(&mut **transaction)
        .await?;
    revoked_credential_ids.sort_unstable();

    // Step 6: the replacement security_admin.
    let admin_id: Option<String> = sqlx::query_scalar(INSERT_IDENTITY)
        .bind(request.admin_id)
        .bind(now)
        .fetch_optional(&mut **transaction)
        .await?;
    let admin_id = admin_id.ok_or(RegistryError::AlreadyExists {
        constraint: "admin_identity_pkey",
    })?;
    let credential_id: Option<String> = sqlx::query_scalar(INSERT_CREDENTIAL)
        .bind(request.credential_id)
        .bind(&admin_id)
        .bind(request.public_identity)
        .bind(request.trust_anchor_ref)
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(credential_id) = credential_id else {
        let id_taken: bool = sqlx::query_scalar(CREDENTIAL_ID_TAKEN)
            .bind(request.credential_id)
            .fetch_one(&mut **transaction)
            .await?;
        return Err(RegistryError::AlreadyExists {
            constraint: if id_taken {
                "admin_credential_pkey"
            } else {
                "admin_credential_public_identity_key"
            },
        }
        .into());
    };
    let binding_id: Option<String> = sqlx::query_scalar(INSERT_BINDING)
        .bind(request.binding_id)
        .bind(&admin_id)
        .fetch_optional(&mut **transaction)
        .await?;
    let binding_id = binding_id.ok_or(RegistryError::AlreadyExists {
        constraint: "admin_role_binding_pkey",
    })?;

    // Step 7: rotate the recovery key.
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

    // Step 8: the operation's outcome.
    sqlx::query(MARK_RESTORED)
        .bind(request.operation_id)
        .bind(RESTORED)
        .fetch_one(&mut **transaction)
        .await?;

    // Step 9, last: the event, by the key that signed.
    let audit_event = append_audit_event(
        transaction,
        &NewAuditEvent {
            id: request.audit_event_id.into(),
            tenant_id: None,
            timestamp: request.now,
            actor: AuditActor::Operator(recovery_key_actor(state.recovery_key_epoch)),
            action: RESTORE_ACTION.into(),
            object_id: admin_id.clone(),
            previous_revision: None,
            new_revision: None,
            outcome: SUCCESS.into(),
        },
    )
    .await?;

    Ok(Restored {
        admin_id,
        credential_id,
        binding_id,
        revoked_credential_ids,
        recovery_key_epoch,
        recovery_state_revision,
        audit_event,
    })
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, time::UNIX_EPOCH};

    use serde_json::json;

    use super::*;

    const DIGEST: [u8; 32] = [1; 32];
    const HASH: [u8; 64] = [2; 64];
    const KEY: [u8; 32] = [3; 32];

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_790_000_000)
    }

    fn plan(value: serde_json::Value) -> JsonObject {
        match value {
            Value::Object(map) => map,
            other => panic!("not an object: {other}"),
        }
    }

    fn good_plan() -> JsonObject {
        plan(json!({"instance_id": "inst", "recovery_key_epoch": 1, "operation": "restore"}))
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
    fn the_ttl_defaults_to_five_minutes_and_is_at_most_fifteen() {
        assert_eq!(DEFAULT_CHALLENGE_TTL, Duration::from_secs(300));
        assert_eq!(MAX_CHALLENGE_TTL, Duration::from_secs(900));
        let plan = good_plan();
        for ttl in [
            Duration::from_nanos(1),
            Duration::from_micros(1),
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
            MAX_CHALLENGE_TTL + Duration::from_nanos(1),
            MAX_CHALLENGE_TTL + Duration::from_secs(1),
            Duration::MAX,
        ] {
            let mut request = issue(&plan);
            request.ttl = ttl;
            assert_eq!(
                encode(validate_issue(&request)),
                "challenge TTL is not more than zero and at most 15 minutes",
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
            let plan = plan(value);
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
            let plan = plan(value.clone());
            assert_eq!(
                encode(validate_issue(&issue(&plan))),
                "plan lacks a string instance_id or an integer recovery_key_epoch",
                "{value}"
            );
        }
    }

    /// The audit writer's years, as in bootstrap, for all three calls.
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
        for (error, display, debug) in [
            (
                ChallengeError::NotIssuable,
                "a recovery challenge cannot be issued",
                "NotIssuable",
            ),
            (
                ChallengeError::NotConsumable,
                "the recovery challenge is not consumable",
                "NotConsumable",
            ),
        ] {
            assert_eq!(error.to_string(), display);
            assert_eq!(format!("{error:?}"), debug);
            assert!(error.source().is_none());
        }
        assert_eq!(ChallengeError::NotConsumable, ChallengeError::NotConsumable);
        assert_ne!(ChallengeError::NotConsumable, ChallengeError::NotIssuable);
        let store = ChallengeError::from(sqlx::Error::PoolClosed);
        assert_ne!(store, ChallengeError::from(sqlx::Error::PoolClosed));
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
            "kind = 'operator_restoration'",
            "challenge_hash IS NOT NULL",
            "consumed_at IS NULL",
            "revoked_at IS NULL",
            "outcome = 'issued'",
            "timestamptz 'epoch' + $2::interval < expires_at",
            "request_digest = $3",
            "expected_revision = $4",
            "jsonb_typeof(immutable_plan -> 'instance_id') = 'string'",
            "immutable_plan ->> 'instance_id' = $5",
            "jsonb_typeof(immutable_plan -> 'recovery_key_epoch') = 'number'",
            "immutable_plan ->> 'recovery_key_epoch' = $6::bigint::text",
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
        // No conflict target: any unique key, and only `INSERT` needed.
        for insert in [
            INSERT_CHALLENGE,
            INSERT_IDENTITY,
            INSERT_CREDENTIAL,
            INSERT_BINDING,
        ] {
            assert_eq!(
                insert.matches(" ON CONFLICT DO NOTHING RETURNING ").count(),
                1,
                "{insert}"
            );
        }
        assert!(SHARE_RECOVERY_STATE.ends_with("FROM recovery_state FOR SHARE"));
        assert!(LOCK_RECOVERY_STATE.ends_with("FROM recovery_state FOR NO KEY UPDATE"));
        assert!(LOCK_CREDENTIALS.ends_with("ORDER BY id COLLATE \"C\" FOR NO KEY UPDATE"));
        assert!(REVOKE_ALL_CREDENTIALS.contains("WHERE revoked_at IS NULL RETURNING id"));
        assert_eq!(ISSUE_ACTION, "administrative_operation.create");
        assert_eq!(RESTORE_ACTION, "admin_identity.restore");
        for action in [ISSUE_ACTION, RESTORE_ACTION] {
            assert!(super::super::is_audit_action(action), "{action}");
        }
        for sql in [
            READ_RECOVERY_STATE,
            SHARE_RECOVERY_STATE,
            LOCK_RECOVERY_STATE,
            INSERT_CHALLENGE,
            CONSUME_CHALLENGE,
            LOCK_CREDENTIALS,
            INSERT_IDENTITY,
            INSERT_CREDENTIAL,
            CREDENTIAL_ID_TAKEN,
            INSERT_BINDING,
            REVOKE_ALL_CREDENTIALS,
            ROTATE_RECOVERY_KEY,
            MARK_RESTORED,
        ] {
            for absent in ["now()", "current_timestamp", ";"] {
                assert!(!sql.contains(absent), "{sql}");
            }
        }
    }
}
