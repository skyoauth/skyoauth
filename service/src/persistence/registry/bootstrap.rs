//! One-time instance bootstrap at the registry level: [`bootstrap_instance`]
//! enrolls the first `security_admin` operator with its mTLS credential and
//! the offline recovery public key, records one audit event and closes
//! bootstrap for good, all in the caller's transaction (design section 7.2;
//! ADR-013 item 5; identity-registry IR-053, IR-057 and section 5.2;
//! T13.4, T13.6).
//!
//! # Steps
//!
//! In the caller's [`Transaction`], inside a savepoint of bootstrap's own
//! (see "Errors and rollback"), in this order:
//!
//! 1. Lock the policy row, `SELECT instance_id FROM instance_security_policy
//!    FOR UPDATE`, then, in a separate statement, read whether a
//!    `recovery_state` row exists. A row there means bootstrap is closed:
//!    [`BootstrapError::AlreadyClosed`], whatever valid request it is given
//!    (the checks of "Validation and trust" come first). With a policy row
//!    and no recovery state, bootstrap adopts the row (see "Adopting a
//!    policy row"). With no policy row, it inserts one with the request's
//!    `instance_id` and the column defaults for the rest, with
//!    `INSERT ... ON CONFLICT DO NOTHING RETURNING`, with no conflict
//!    target. An insert that returns no row found
//!    a policy row another transaction committed meanwhile; bootstrap then
//!    locks the row and reads the recovery state again, as above, and is
//!    `AlreadyClosed`, adopts the row or is
//!    [`BootstrapError::InstanceIdMismatch`] (see "Closure").
//! 2. Insert the `recovery_state` row: the effective `instance_id`,
//!    `bootstrap_closed = true`, the recovery public key and
//!    `recovery_key_epoch = 1` (the first epoch, `0005`), at revision 1.
//! 3. Create the operator with [`create_admin_identity`],
//!    [`create_admin_credential`] and [`create_admin_role_binding`], all
//!    enabled, the credential unrevoked and the binding `security_admin` of
//!    the instance (no tenant). Each takes the `recovery_state` row of step
//!    2 `FOR SHARE`, a row bootstrap's own transaction inserted, so it waits
//!    for no one there (the operator module, "Writes and a restoration").
//! 4. Append the audit event with [`append_audit_event`], last, as for
//!    every audited write (see [`append_audit_event`]'s module): an
//!    instance-scope event (no tenant, so no tenant row is locked), action
//!    `recovery_state.create`, `object_id` the effective `instance_id`
//!    (IR-057), actor `{"type": "operator", "id": "deployment_operator"}`
//!    ([`DEPLOYMENT_OPERATOR_ACTOR`]; identity-registry section 5.2),
//!    `previous_revision` none, `new_revision` the recovery state's
//!    revision, 1, outcome `success` (inferred: the value the audit tests
//!    use; no table of outcomes exists), timestamp the request's `now`.
//!
//! Bootstrap is one event: `recovery_state.create` records the policy row
//! too when bootstrap inserts it, so `instance_security_policy.create`,
//! which stays in the action table for a later startup path, is not
//! written here (provisional lead pick, 2026-11-21; identity-registry
//! section 5.2 and IR-059). A distinct bootstrap action may replace the name later;
//! that changes no stored event's hash. No `administrative_operation` row
//! is written (inferred: bootstrap is not an operator API write and has no
//! pending, approved or challenged operation to record).
//!
//! # Closure
//!
//! The database alone says whether bootstrap is closed: a `recovery_state`
//! row exists. Nothing here reads a configuration, an environment variable
//! or a clock, so a restart or an empty configuration cannot reopen it
//! (T13.4). The row cannot be deleted or truncated (`0006`),
//! `recovery_state_set_once` keeps `bootstrap_closed` true once it is
//! (`0005`), and `recovery_state_single_row` allows one row. A row whose
//! `bootstrap_closed` is false, which only a write by other means can
//! leave, still counts as closed here (inferred): the single row is taken.
//!
//! Two concurrent bootstraps serialize (T13.6). Under `READ COMMITTED`:
//!
//! - On an empty database neither finds a policy row to lock, and both
//!   insert one. The second waits on the first's unique index entry
//!   (`instance_security_policy_single_row`, or
//!   `instance_security_policy_pkey` for the same ID). When the first
//!   commits, the second's insert returns no row, and its repeated lock and
//!   check, statements after the wait, see the first's committed recovery
//!   state: [`BootstrapError::AlreadyClosed`]. When the first rolls back,
//!   the second's insert goes on and it bootstraps. A transaction that
//!   commits only a policy row meanwhile, as a startup path might, is
//!   adopted like a row found by the first lock: the same `instance_id`
//!   bootstraps, another is [`BootstrapError::InstanceIdMismatch`].
//! - With a policy row, the second waits for the first's row lock; when
//!   the first commits, the recovery state check, a statement after the
//!   lock, sees its committed row: [`BootstrapError::AlreadyClosed`].
//! - A `23505` on `recovery_state_single_row` or `recovery_state_pkey` is
//!   [`BootstrapError::AlreadyClosed`] too.
//!
//! Under `REPEATABLE READ` and `SERIALIZABLE` the repeated lock cannot see
//! a policy row committed after the transaction's snapshot, so it cannot
//! tell whether that row closes bootstrap. PostgreSQL fails the insert
//! itself with `40001` when the conflicting row is not in the snapshot;
//! should the insert still return no row and the repeated lock find none,
//! bootstrap returns [`RegistryError::Retry`] in [`BootstrapError::Store`]
//! (wrapping [`sqlx::Error::RowNotFound`]), never a closure. With a policy
//! row present, a bootstrap whose snapshot predates another's commit
//! misses the recovery state, adopts the row (which the other only locked)
//! and fails its recovery state insert with `23505` on
//! `recovery_state_pkey`: `AlreadyClosed`. That holds when the committed
//! bootstrap ran under `READ COMMITTED`; when both ran under
//! `SERIALIZABLE`, the late one fails with `40001` instead (both tested on
//! PostgreSQL 17.12, the CI pin). Any `40001` or `40P01` is
//! [`RegistryError::Retry`] in [`BootstrapError::Store`], and retrying the
//! whole transaction then gives `AlreadyClosed`.
//!
//! Only the two unique keys of step 2 mean "closed". The policy insert
//! raises no `23505` on its own keys (`ON CONFLICT DO NOTHING`), and one
//! that did would stay [`RegistryError::AlreadyExists`]. A `23505` of
//! step 3 or 4 is a collision of a caller-supplied value with an existing
//! row and stays the typed [`RegistryError::AlreadyExists`] in
//! [`BootstrapError::Store`], naming only the constraint:
//! `admin_identity_pkey`, `admin_credential_pkey`,
//! `admin_credential_public_identity_key` (a key already registered,
//! revoked or not), `admin_role_binding_pkey` or `audit_event_pkey`.
//!
//! Bootstrap locks or inserts the `instance_security_policy` row before
//! its `0005` writes and takes the audit head last, and it locks no tenant
//! row, so it cannot form a lock cycle with appenders that lock a tenant
//! and then the head.
//!
//! # Adopting a policy row
//!
//! IR-053 says "`single_actor_mode` is set at install, and the row mirrors
//! it", and that a change is "recorded in an audit event at startup".
//! IR-057 says the `instance_id` is "generated once, at first bootstrap,
//! and stored immutably on the `InstanceSecurityPolicy` row". Neither says
//! whether the policy row exists before bootstrap. Reading them together,
//! the lead ruled (2026-11-21, provisional) that bootstrap adopts a policy
//! row it finds without a recovery state, the state of a service started
//! before bootstrap: it keeps the stored `instance_id` and writes nothing
//! to the row. The request's `instance_id` must equal the stored one byte
//! for byte; another is [`BootstrapError::InstanceIdMismatch`], which names
//! neither value, and nothing is written.
//!
//! The startup path does not exist yet. A startup that creates the row
//! before bootstrap needs an `instance_id` then, which contradicts
//! "generated at first bootstrap" unless startup generates it and
//! bootstrap adopts it, as here. When bootstrap inserts the row, the other
//! columns take their defaults (`single_actor_mode` and
//! `widening_second_approver` false, no audit sink) until the startup
//! mirror of IR-053 exists: that mirror, not bootstrap, writes deployment
//! configuration into the row. For the startup-path change:
//!
//! - a stored `instance_id` that is not a lowercase hyphenated UUIDv7 (the
//!   database checks only its length) equals no request that passes
//!   validation, so bootstrap is impossible on that database and fails
//!   closed with [`BootstrapError::InstanceIdMismatch`]; startup must
//!   write a lowercase UUIDv7;
//! - a startup insert that races a bootstrap on an empty database and
//!   commits first is adopted by that bootstrap (or is a mismatch), not a
//!   false [`BootstrapError::AlreadyClosed`].
//!
//! # Validation and trust
//!
//! Before any statement, bootstrap rejects, as an encode error
//! ([`RegistryError::Other`] in [`BootstrapError::Store`], naming no
//! value):
//!
//! - an `admin_id` reserved for an actor that is not an operator identity,
//!   as [`RegistryError::ReservedActorId`] through the check of
//!   [`create_admin_identity`] ([`is_reserved_actor_id`]), first;
//! - an `instance_id` that is not a UUIDv7 in lowercase hyphenated form
//!   (IR-057): 36 bytes, hyphens at 8, 13, 18 and 23, lowercase hex
//!   elsewhere, version nibble `7` and the RFC 9562 variant (`8`, `9`, `a`
//!   or `b` at 19). The timestamp bits are not checked;
//! - a recovery public key that is not exactly 32 bytes, the raw Ed25519
//!   public key of the identity-registry section 5.2 pick, or whose bytes
//!   do not decode to a curve point, do not encode it canonically, or
//!   encode a point of small order (a weak key): the checks every
//!   enrollment of a recovery key runs (the recovery module, "Keys";
//!   provisional lead pick, 2026-11-24), so a key that could never verify
//!   a restoration, or one that verifies a fixed signature over any
//!   message, is not enrolled;
//! - an empty `public_identity` or `trust_anchor_ref`, or one longer than
//!   2048 bytes (the `0005` bounds);
//! - a `now` outside the `0007` range (`timestamp out of range`, as
//!   everywhere in the registry), or inside it but outside the years `0000`
//!   to `9999`, from `0000-01-01T00:00:00.000000Z` to
//!   `9999-12-31T23:59:59.999999Z` after truncation to the microsecond:
//!   the audit writer's bound and message (`audit timestamp outside the
//!   years 0000 to 9999`), checked with the writer's own helper, so a time
//!   the event could not carry writes nothing.
//!
//! A failure of these runs no statement, writes nothing and leaves the
//! transaction usable; the caller still rolls back on every `Err`.
//!
//! Bootstrap trusts its caller, the deployment-local bootstrap command
//! (ADR-013 items 5 and 7): it does not canonicalize or check the mTLS
//! public key behind `public_identity`, which it takes as given today (the
//! service is to derive it with `crate::identity::canonical_public_identity`
//! from the DER key the operator tooling supplies, T13.1), nor resolve
//! `trust_anchor_ref`. Other bad input fails at a
//! statement as in [`create_admin_credential`] and its neighbours.
//!
//! # Errors and rollback
//!
//! Bootstrap neither commits nor rolls back the caller's transaction. It
//! runs steps 1 to 4 inside a savepoint of its own and rolls the savepoint
//! back on every `Err`, including one the audit writer returns in Rust
//! after the head lock, so a caller that commits after an `Err` commits
//! none of bootstrap's rows. The caller must still roll the transaction
//! back on `Err`: a failed savepoint rollback leaves the rows in place.
//! That is how a missing store or a failed audit append fails closed
//! (T13.6): nothing commits without the audit event, and the next attempt
//! finds bootstrap open. On `Ok` the caller commits; a commit failure
//! leaves bootstrap open too.
//!
//! When the commit's outcome is unknown, for example because the
//! connection failed during `COMMIT`, the caller keeps all the request's
//! material (its IDs, the operator's credential and the recovery public
//! key) until it has reconnected and reconciled the durable state, and
//! then retries the same request: `AlreadyClosed` if the first attempt
//! committed. The same rule applies to
//! [`restore_operator`](super::restore_operator) too.
//!
//! [`create_admin_identity`]: super::create_admin_identity
//! [`create_admin_credential`]: super::create_admin_credential
//! [`create_admin_role_binding`]: super::create_admin_role_binding
//! [`append_audit_event`]: super::append_audit_event
//! [`DEPLOYMENT_OPERATOR_ACTOR`]: super::DEPLOYMENT_OPERATOR_ACTOR
//! [`is_reserved_actor_id`]: super::is_reserved_actor_id

use std::{fmt, time::SystemTime};

use sqlx::{Connection, Postgres, Row, Transaction};

use super::{
    AdminRole, AuditActor, AuditEvent, DEPLOYMENT_OPERATOR_ACTOR, NewAdminCredential,
    NewAdminIdentity, NewAdminRoleBinding, NewAuditEvent, RegistryError, Status,
    append_audit_event, create_admin_credential, create_admin_identity, create_admin_role_binding,
    events::{YEAR_OUT_OF_RANGE, in_envelope_years},
    is_reserved_actor_id,
    model::since_epoch,
    recovery::recovery_key,
};

/// The length of a raw Ed25519 public key, the only recovery key bootstrap
/// accepts (identity-registry section 5.2, provisional lead pick,
/// 2026-11-21).
pub const RECOVERY_PUBLIC_KEY_LENGTH: usize = 32;

/// The longest `public_identity` and `trust_anchor_ref`, in bytes (`0005`).
const MAX_EXACT_STRING: usize = 2048;

/// The epoch of the first recovery key (`0005`, inferred there).
const FIRST_RECOVERY_KEY_EPOCH: i64 = 1;

/// The action of the bootstrap event (see the module docs).
const BOOTSTRAP_ACTION: &str = "recovery_state.create";

/// The outcome of the bootstrap event (inferred).
const SUCCESS: &str = "success";

/// `unique_violation`.
const UNIQUE_VIOLATION: &str = "23505";

/// The unique keys of step 2 whose `23505` means another bootstrap got
/// there first: [`BootstrapError::AlreadyClosed`]. Not the policy row's
/// keys: a policy row may be another writer's, which bootstrap adopts.
const CLOSING_KEYS: &[&str] = &["recovery_state_pkey", "recovery_state_single_row"];

/// Locks the policy row, if there is one.
const LOCK_POLICY: &str = "SELECT instance_id FROM instance_security_policy FOR UPDATE";

/// Whether bootstrap is closed. A statement of its own after the lock, so
/// that under `READ COMMITTED` it sees what a bootstrap that held the lock
/// committed.
const RECOVERY_STATE_EXISTS: &str = "SELECT EXISTS (SELECT FROM recovery_state) AS closed";

/// Inserts the policy row, or nothing when a committed row conflicts on
/// any unique key. No conflict target, so it needs only `INSERT`.
const INSERT_POLICY: &str = "INSERT INTO instance_security_policy (instance_id) VALUES ($1) \
     ON CONFLICT DO NOTHING RETURNING instance_id";

const INSERT_RECOVERY_STATE: &str = "INSERT INTO recovery_state \
     (instance_id, bootstrap_closed, recovery_public_key, recovery_key_epoch) \
     VALUES ($1, true, $2, $3) RETURNING recovery_key_epoch, revision";

/// The input of [`bootstrap_instance`]. Every value is the caller's: IDs
/// (T10.2 generates them), the key and the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapRequest<'a> {
    /// A UUIDv7 in lowercase hyphenated form (IR-057). With a policy row
    /// already present, it must equal the stored one.
    pub instance_id: &'a str,
    /// The first operator's ID; not reserved
    /// ([`is_reserved_actor_id`](super::is_reserved_actor_id)).
    pub admin_id: &'a str,
    pub credential_id: &'a str,
    /// The canonical public-key identity of the operator's mTLS credential,
    /// 1 to 2048 bytes, as the caller computed it.
    pub public_identity: &'a str,
    /// 1 to 2048 bytes.
    pub trust_anchor_ref: &'a str,
    pub binding_id: &'a str,
    /// The raw Ed25519 public key of the offline recovery key holder,
    /// exactly [`RECOVERY_PUBLIC_KEY_LENGTH`] bytes, a canonically encoded
    /// point not of small order (see "Validation and trust").
    pub recovery_public_key: &'a [u8],
    pub audit_event_id: &'a str,
    /// The time of the operator's `created_at` and of the audit event.
    pub now: SystemTime,
}

/// What [`bootstrap_instance`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapOutcome {
    /// The instance's ID: the stored one when bootstrap adopted a policy
    /// row, equal to the request's, or the request's.
    pub instance_id: String,
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    /// The `recovery_state.create` event, with its sequence and hash.
    pub audit_event: AuditEvent,
    /// Always 1, the first epoch.
    pub recovery_key_epoch: i64,
}

/// Why [`bootstrap_instance`] did not bootstrap. On every variant the
/// caller rolls back.
#[derive(Debug)]
pub enum BootstrapError {
    /// Bootstrap is closed: a recovery state exists, or a concurrent
    /// bootstrap committed first. No detail, no value.
    AlreadyClosed,
    /// A policy row exists without a recovery state, and its `instance_id`
    /// is not the request's. Neither value is carried. Bootstrap is still
    /// open.
    InstanceIdMismatch,
    /// Invalid input or a store failure; see the module docs.
    /// [`RegistryError::Retry`] means retry the whole transaction.
    Store(RegistryError),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyClosed => f.write_str("bootstrap is already closed"),
            Self::InstanceIdMismatch => f.write_str(
                "the instance security policy holds another instance ID; bootstrap is still open",
            ),
            Self::Store(err) => write!(f, "bootstrap failed: {err}"),
        }
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AlreadyClosed | Self::InstanceIdMismatch => None,
            Self::Store(err) => Some(err),
        }
    }
}

impl From<RegistryError> for BootstrapError {
    fn from(err: RegistryError) -> Self {
        Self::Store(err)
    }
}

impl From<sqlx::Error> for BootstrapError {
    fn from(err: sqlx::Error) -> Self {
        Self::Store(err.into())
    }
}

/// The error of the step 2 insert: [`BootstrapError::AlreadyClosed`]
/// for a `23505` on one of [`CLOSING_KEYS`], otherwise the registry
/// error.
fn closed_or_store(err: sqlx::Error) -> BootstrapError {
    let closing = err.as_database_error().is_some_and(|db| {
        db.code().as_deref() == Some(UNIQUE_VIOLATION)
            && db
                .constraint()
                .is_some_and(|name| CLOSING_KEYS.contains(&name))
    });
    if closing {
        BootstrapError::AlreadyClosed
    } else {
        err.into()
    }
}

fn encode_error(message: &'static str) -> BootstrapError {
    sqlx::Error::Encode(message.into()).into()
}

/// Whether `id` is a UUIDv7 in lowercase hyphenated form (IR-057): the
/// 8-4-4-4-12 layout of lowercase hex digits, version `7` and the RFC 9562
/// variant `10xx`. Shared with `crate::local_transport`, which checks a
/// request's value before it calls [`bootstrap_instance`].
pub(crate) fn is_lowercase_uuid_v7(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, &byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

/// Whether `value` is 1 to 2048 bytes.
fn bounded(value: &str) -> bool {
    (1..=MAX_EXACT_STRING).contains(&value.len())
}

/// The checks that run before any statement (see the module docs).
fn validate(request: &BootstrapRequest<'_>) -> Result<(), BootstrapError> {
    if is_reserved_actor_id(request.admin_id) {
        return Err(RegistryError::ReservedActorId.into());
    }
    if !is_lowercase_uuid_v7(request.instance_id) {
        return Err(encode_error(
            "instance ID is not a lowercase hyphenated UUIDv7",
        ));
    }
    recovery_key(request.recovery_public_key).map_err(encode_error)?;
    if !bounded(request.public_identity) {
        return Err(encode_error("public identity is empty or over 2048 bytes"));
    }
    if !bounded(request.trust_anchor_ref) {
        return Err(encode_error(
            "trust anchor reference is empty or over 2048 bytes",
        ));
    }
    // The audit writer's own bound, checked here so that a time it would
    // refuse fails before step 1 rather than after step 3.
    if !in_envelope_years(since_epoch(request.now)?.microseconds) {
        return Err(encode_error(YEAR_OUT_OF_RANGE));
    }
    Ok(())
}

/// Locks the policy row, if there is one, and then reads whether bootstrap
/// is closed: [`BootstrapError::AlreadyClosed`], or the stored
/// `instance_id`.
async fn lock_open_policy(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Option<String>, BootstrapError> {
    let stored: Option<String> = sqlx::query_scalar(LOCK_POLICY)
        .fetch_optional(&mut **transaction)
        .await?;
    let closed: bool = sqlx::query_scalar(RECOVERY_STATE_EXISTS)
        .fetch_one(&mut **transaction)
        .await?;
    if closed {
        return Err(BootstrapError::AlreadyClosed);
    }
    Ok(stored)
}

/// Step 1: the effective `instance_id`, from the policy row bootstrap
/// adopts or inserts.
async fn claim_policy(
    transaction: &mut Transaction<'_, Postgres>,
    request: &BootstrapRequest<'_>,
) -> Result<String, BootstrapError> {
    let stored = match lock_open_policy(transaction).await? {
        Some(stored) => stored,
        None => {
            let inserted: Option<String> = sqlx::query_scalar(INSERT_POLICY)
                .bind(request.instance_id)
                .fetch_optional(&mut **transaction)
                .await?;
            if let Some(inserted) = inserted {
                return Ok(inserted);
            }
            // Another transaction committed a policy row. Under `READ
            // COMMITTED` these statements see it; an older snapshot that
            // misses it cannot tell whether bootstrap is closed: retry.
            lock_open_policy(transaction).await?.ok_or_else(|| {
                BootstrapError::Store(RegistryError::Retry(sqlx::Error::RowNotFound))
            })?
        }
    };
    if stored == request.instance_id {
        Ok(stored)
    } else {
        Err(BootstrapError::InstanceIdMismatch)
    }
}

/// Bootstraps the instance in `transaction` (see the module docs for the
/// steps, the adopt rule and the errors). Never commits or rolls back the
/// caller's transaction, only its own savepoint: the caller commits on
/// `Ok` and rolls back on `Err`.
pub async fn bootstrap_instance(
    transaction: &mut Transaction<'_, Postgres>,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    validate(request)?;
    let mut savepoint = transaction.begin().await?;
    match bootstrap_steps(&mut savepoint, request).await {
        Ok(outcome) => {
            savepoint.commit().await?;
            Ok(outcome)
        }
        Err(err) => {
            // The caller rolls back on every `Err` anyway; the step's error
            // says more than a failed savepoint rollback would.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}

/// Steps 1 to 4, in the savepoint of [`bootstrap_instance`].
async fn bootstrap_steps(
    transaction: &mut Transaction<'_, Postgres>,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    // Step 1: lock, adopt or insert the policy row, after checking closure.
    let instance_id = claim_policy(transaction, request).await?;

    // Step 2: the recovery state closes bootstrap.
    let recovery = sqlx::query(INSERT_RECOVERY_STATE)
        .bind(&instance_id)
        .bind(request.recovery_public_key)
        .bind(FIRST_RECOVERY_KEY_EPOCH)
        .fetch_one(&mut **transaction)
        .await
        .map_err(closed_or_store)?;
    let recovery_key_epoch: i64 = recovery.try_get("recovery_key_epoch")?;
    let recovery_revision: i64 = recovery.try_get("revision")?;

    // Step 3: the first security_admin.
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

    // Step 4, last: the audit event.
    let audit_event = append_audit_event(
        transaction,
        &NewAuditEvent {
            id: request.audit_event_id.into(),
            tenant_id: None,
            timestamp: request.now,
            actor: AuditActor::Operator(DEPLOYMENT_OPERATOR_ACTOR.into()),
            action: BOOTSTRAP_ACTION.into(),
            object_id: instance_id.clone(),
            previous_revision: None,
            new_revision: Some(recovery_revision),
            outcome: SUCCESS.into(),
        },
    )
    .await?;

    Ok(BootstrapOutcome {
        instance_id,
        admin_id: identity.id,
        credential_id: credential.id,
        binding_id: binding.id,
        audit_event,
        recovery_key_epoch,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error as _,
        time::{Duration, UNIX_EPOCH},
    };

    use super::*;

    const INSTANCE: &str = "01936f4e-8a2b-7c3d-9e4f-0123456789ab";
    /// A canonically encoded point of large order.
    const KEY: [u8; 32] = [0x11; 32];

    fn request(instance_id: &str) -> BootstrapRequest<'_> {
        BootstrapRequest {
            instance_id,
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: "spki-sha256:first",
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &KEY,
            audit_event_id: "aud_bootstrap",
            now: UNIX_EPOCH + Duration::from_secs(1_790_000_000),
        }
    }

    #[track_caller]
    fn encode(result: Result<(), BootstrapError>) -> String {
        match result {
            Err(BootstrapError::Store(RegistryError::Other(sqlx::Error::Encode(err)))) => {
                err.to_string()
            }
            other => panic!("expected an encode error: {other:?}"),
        }
    }

    #[test]
    fn only_lowercase_hyphenated_uuid_v7_is_an_instance_id() {
        for id in [
            INSTANCE,
            "00000000-0000-7000-8000-000000000000",
            "ffffffff-ffff-7fff-bfff-ffffffffffff",
            "01936f4e-8a2b-7c3d-8e4f-0123456789ab",
            "01936f4e-8a2b-7c3d-ae4f-0123456789ab",
            "01936f4e-8a2b-7c3d-be4f-0123456789ab",
        ] {
            assert!(is_lowercase_uuid_v7(id), "{id}");
            assert!(validate(&request(id)).is_ok(), "{id}");
        }
        for id in [
            "",
            // Upper case.
            "01936F4E-8A2B-7C3D-9E4F-0123456789AB",
            "01936f4e-8a2b-7c3d-9e4f-0123456789aB",
            // Versions 4, 6 and 8.
            "01936f4e-8a2b-4c3d-9e4f-0123456789ab",
            "01936f4e-8a2b-6c3d-9e4f-0123456789ab",
            "01936f4e-8a2b-8c3d-9e4f-0123456789ab",
            // Variants NCS, Microsoft and reserved.
            "01936f4e-8a2b-7c3d-7e4f-0123456789ab",
            "01936f4e-8a2b-7c3d-0e4f-0123456789ab",
            "01936f4e-8a2b-7c3d-ce4f-0123456789ab",
            "01936f4e-8a2b-7c3d-fe4f-0123456789ab",
            // Nil and max.
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            // Layout.
            "01936f4e8a2b7c3d9e4f0123456789ab",
            "{01936f4e-8a2b-7c3d-9e4f-0123456789ab}",
            "urn:uuid:01936f4e-8a2b-7c3d-9e4f-0123456789ab",
            "01936f4e-8a2b-7c3d-9e4f-0123456789a",
            "01936f4e-8a2b-7c3d-9e4f-0123456789abc",
            "01936f4e-8a2b-7c3d-9e4f_0123456789ab",
            "01936f4e8-a2b-7c3d-9e4f-0123456789ab",
            " 01936f4e-8a2b-7c3d-9e4f-0123456789a",
            "01936f4e-8a2b-7c3d-9e4f-0123456789ag",
            "01936f4e-8a2b-7c3d-9e4f-01234567\u{e9}ab",
        ] {
            assert!(!is_lowercase_uuid_v7(id), "{id}");
            assert_eq!(
                encode(validate(&request(id))),
                "instance ID is not a lowercase hyphenated UUIDv7",
                "{id}"
            );
        }
    }

    #[test]
    fn the_recovery_key_is_exactly_32_bytes() {
        for length in [0, 1, 31, 33, 64, 8192] {
            let key = vec![1; length];
            let mut bad = request(INSTANCE);
            bad.recovery_public_key = &key;
            assert_eq!(
                encode(validate(&bad)),
                "recovery public key is not a 32-byte Ed25519 key",
                "{length}"
            );
        }
        assert!(validate(&request(INSTANCE)).is_ok());
        assert_eq!(RECOVERY_PUBLIC_KEY_LENGTH, 32);
    }

    /// The enrollment checks of the recovery module, "Keys": 32 bytes that
    /// are no point, a non-canonical encoding, or a small-order point are
    /// refused, each with its message.
    #[test]
    fn the_recovery_key_is_a_canonical_point_of_large_order() {
        let mut identity_p_plus_1 = [0xff; 32];
        identity_p_plus_1[0] = 0xee;
        identity_p_plus_1[31] = 0x7f;
        let mut large_p_plus_3 = identity_p_plus_1;
        large_p_plus_3[0] = 0xf0;
        let mut identity = [0; 32];
        identity[0] = 1;
        for (key, message) in [
            ([7; 32], "recovery public key is not an Ed25519 point"),
            (
                [0; 32],
                "recovery public key is a small-order Ed25519 point",
            ),
            (
                identity,
                "recovery public key is a small-order Ed25519 point",
            ),
            (
                identity_p_plus_1,
                "recovery public key is not canonically encoded",
            ),
            (
                large_p_plus_3,
                "recovery public key is not canonically encoded",
            ),
        ] {
            let mut bad = request(INSTANCE);
            bad.recovery_public_key = &key;
            assert_eq!(encode(validate(&bad)), message, "{key:?}");
        }
    }

    #[test]
    fn public_identity_and_trust_anchor_are_bounded_only() {
        let long = "k".repeat(2049);
        let longest = "k".repeat(2048);
        for (public_identity, ok) in [("", false), (&long[..], false), (&longest[..], true)] {
            let mut checked = request(INSTANCE);
            checked.public_identity = public_identity;
            match ok {
                true => assert!(validate(&checked).is_ok()),
                false => assert_eq!(
                    encode(validate(&checked)),
                    "public identity is empty or over 2048 bytes"
                ),
            }
        }
        for (trust_anchor_ref, ok) in [("", false), (&long[..], false), (&longest[..], true)] {
            let mut checked = request(INSTANCE);
            checked.trust_anchor_ref = trust_anchor_ref;
            match ok {
                true => assert!(validate(&checked).is_ok()),
                false => assert_eq!(
                    encode(validate(&checked)),
                    "trust anchor reference is empty or over 2048 bytes"
                ),
            }
        }
        // No canonicalization: whitespace and any form pass here.
        let mut loose = request(INSTANCE);
        loose.public_identity = " Not Canonical ";
        assert!(validate(&loose).is_ok());
    }

    #[test]
    fn a_reserved_admin_id_is_checked_first() {
        for id in [DEPLOYMENT_OPERATOR_ACTOR, "recovery_key:", "recovery_key:1"] {
            let mut reserved = request("not-a-uuid");
            reserved.admin_id = id;
            reserved.recovery_public_key = &[];
            assert!(
                matches!(
                    validate(&reserved),
                    Err(BootstrapError::Store(RegistryError::ReservedActorId))
                ),
                "{id}"
            );
        }
        let mut lookalike = request(INSTANCE);
        lookalike.admin_id = "Deployment_Operator";
        assert!(validate(&lookalike).is_ok());
    }

    #[test]
    fn a_time_outside_the_range_is_an_encode_error() {
        let mut far = request(INSTANCE);
        far.now = UNIX_EPOCH + Duration::from_micros(u64::try_from(i64::MAX).unwrap());
        assert_eq!(encode(validate(&far)), "timestamp out of range");
    }

    /// The audit writer's years, `0000-01-01T00:00:00.000000Z` to
    /// `9999-12-31T23:59:59.999999Z`, after truncation to the microsecond.
    #[test]
    fn only_the_audit_years_are_accepted() {
        const EARLIEST: u64 = 62_167_219_200_000_000;
        const LATEST: u64 = 253_402_300_799_999_999;
        let at = |time| {
            let mut timed = request(INSTANCE);
            timed.now = time;
            validate(&timed)
        };
        for time in [
            UNIX_EPOCH - Duration::from_micros(EARLIEST),
            UNIX_EPOCH + Duration::from_micros(LATEST),
            UNIX_EPOCH + Duration::from_micros(LATEST) + Duration::from_nanos(999),
        ] {
            assert!(at(time).is_ok(), "{time:?}");
        }
        for time in [
            UNIX_EPOCH - Duration::from_micros(EARLIEST + 1),
            UNIX_EPOCH - Duration::from_micros(EARLIEST) - Duration::from_nanos(1),
            UNIX_EPOCH + Duration::from_micros(LATEST + 1),
            // Inside the 0007 range, past the year 9999.
            UNIX_EPOCH + Duration::from_secs(253_402_300_800 * 2),
        ] {
            assert_eq!(
                encode(at(time)),
                "audit timestamp outside the years 0000 to 9999",
                "{time:?}"
            );
        }
    }

    #[test]
    fn the_closed_outcomes_carry_no_detail() {
        let closed = BootstrapError::AlreadyClosed;
        assert_eq!(closed.to_string(), "bootstrap is already closed");
        assert_eq!(format!("{closed:?}"), "AlreadyClosed");
        assert!(closed.source().is_none());
        let mismatch = BootstrapError::InstanceIdMismatch;
        assert_eq!(
            mismatch.to_string(),
            "the instance security policy holds another instance ID; bootstrap is still open"
        );
        assert_eq!(format!("{mismatch:?}"), "InstanceIdMismatch");
        assert!(mismatch.source().is_none());
        let store = BootstrapError::from(sqlx::Error::PoolClosed);
        assert_eq!(
            store.to_string(),
            "bootstrap failed: registry database error"
        );
        assert_eq!(format!("{store:?}"), "Store(Other { sqlstate: None, .. })");
        assert!(store.source().is_some());
    }

    #[test]
    fn only_the_recovery_state_keys_close_bootstrap() {
        assert_eq!(
            CLOSING_KEYS,
            ["recovery_state_pkey", "recovery_state_single_row"]
        );
        assert!(matches!(
            closed_or_store(sqlx::Error::PoolClosed),
            BootstrapError::Store(RegistryError::Other(_))
        ));
    }

    #[test]
    fn the_statements_close_bootstrap_at_the_first_epoch() {
        assert!(INSERT_RECOVERY_STATE.contains("VALUES ($1, true, $2, $3)"));
        // No conflict target: any unique key, and only `INSERT` needed.
        assert!(
            INSERT_POLICY.ends_with("VALUES ($1) ON CONFLICT DO NOTHING RETURNING instance_id")
        );
        assert_eq!(FIRST_RECOVERY_KEY_EPOCH, 1);
        assert_eq!(BOOTSTRAP_ACTION, "recovery_state.create");
        assert!(super::super::is_audit_action(BOOTSTRAP_ACTION));
        for sql in [
            LOCK_POLICY,
            RECOVERY_STATE_EXISTS,
            INSERT_POLICY,
            INSERT_RECOVERY_STATE,
        ] {
            assert!(!sql.contains("now()"), "{sql}");
            assert!(!sql.contains(';'), "{sql}");
        }
    }
}
