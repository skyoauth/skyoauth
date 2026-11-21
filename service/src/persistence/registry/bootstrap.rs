//! One-time instance bootstrap at the registry level: [`bootstrap_instance`]
//! enrolls the first `security_admin` operator with its mTLS credential and
//! the offline recovery public key, records one audit event and closes
//! bootstrap for good, all in the caller's transaction (design section 7.2;
//! ADR-013 item 5; identity-registry IR-053, IR-057 and section 5.2;
//! T13.4, T13.6).
//!
//! # Steps
//!
//! In the caller's [`Transaction`], in this order:
//!
//! 1. Lock the policy row, `SELECT instance_id FROM instance_security_policy
//!    FOR UPDATE`, then, in a separate statement, read whether a
//!    `recovery_state` row exists. A row there means bootstrap is closed:
//!    [`BootstrapError::AlreadyClosed`], whatever the request holds. With a
//!    policy row and no recovery state, bootstrap adopts the row (see
//!    "Adopting a policy row"). With no policy row, it inserts one with the
//!    request's `instance_id` and the column defaults for the rest.
//! 2. Insert the `recovery_state` row: the effective `instance_id`,
//!    `bootstrap_closed = true`, the recovery public key and
//!    `recovery_key_epoch = 1` (the first epoch, `0005`), at revision 1.
//! 3. Create the operator with [`create_admin_identity`],
//!    [`create_admin_credential`] and [`create_admin_role_binding`], all
//!    enabled, the credential unrevoked and the binding `security_admin` of
//!    the instance (no tenant).
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
//!   `instance_security_policy_pkey` for the same ID); when the first
//!   commits it fails with `23505`, which is
//!   [`BootstrapError::AlreadyClosed`]. When the first rolls back, the
//!   second goes on and bootstraps.
//! - With a policy row, the second waits for the first's row lock; when
//!   the first commits, the recovery state check, a statement after the
//!   lock, sees its committed row: [`BootstrapError::AlreadyClosed`].
//! - A `23505` on `recovery_state_single_row` or `recovery_state_pkey` is
//!   [`BootstrapError::AlreadyClosed`] too.
//!
//! Under `REPEATABLE READ` and `SERIALIZABLE`, a bootstrap whose snapshot
//! predates another's commit misses the recovery state, adopts the policy
//! row (which the other only locked) and then fails its recovery state
//! insert with `23505` on `recovery_state_pkey`: `AlreadyClosed` too
//! (tested on PostgreSQL 16). Any `40001` or `40P01` is
//! [`RegistryError::Retry`] in [`BootstrapError::Store`], and retrying the
//! whole transaction then gives `AlreadyClosed`. A `23505` on
//! the policy row maps to `AlreadyClosed` whoever inserted the competing
//! row; today only bootstrap inserts one, and a retry adopts a row another
//! writer committed without a recovery state (inferred).
//!
//! Only those four unique keys of steps 1 and 2 mean "closed". A `23505` of
//! step 3 or 4 is a collision of a caller-supplied value with an existing
//! row and stays the typed [`RegistryError::AlreadyExists`] in
//! [`BootstrapError::Store`], naming only the constraint:
//! `admin_identity_pkey`, `admin_credential_pkey`,
//! `admin_credential_public_identity_key` (a key already registered,
//! revoked or not), `admin_role_binding_pkey` or `audit_event_pkey`.
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
//! `widening_second_approver` false, no audit sink): the startup mirror of
//! IR-053, not bootstrap, writes deployment configuration into the row.
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
//!   public key of the identity-registry section 5.2 pick. The bytes are
//!   not checked further: whether they are a valid curve point is the
//!   verifier's concern (T13.5);
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
//! public key behind `public_identity`, which the operator tooling computes
//! (T13.1), nor resolve `trust_anchor_ref`. Other bad input fails at a
//! statement as in [`create_admin_credential`] and its neighbours.
//!
//! # Errors and rollback
//!
//! Bootstrap neither commits nor rolls back. On `Err` the caller must roll
//! the transaction back: steps before the failure may have written rows,
//! and a failed statement aborts the transaction. That is how a missing
//! store or a failed audit append fails closed (T13.6): nothing commits
//! without the audit event, and the next attempt finds bootstrap open. On
//! `Ok` the caller commits; a commit failure leaves bootstrap open too.
//!
//! [`create_admin_identity`]: super::create_admin_identity
//! [`create_admin_credential`]: super::create_admin_credential
//! [`create_admin_role_binding`]: super::create_admin_role_binding
//! [`append_audit_event`]: super::append_audit_event
//! [`DEPLOYMENT_OPERATOR_ACTOR`]: super::DEPLOYMENT_OPERATOR_ACTOR
//! [`is_reserved_actor_id`]: super::is_reserved_actor_id

use std::{fmt, time::SystemTime};

use sqlx::{Postgres, Row, Transaction};

use super::{
    AdminRole, AuditActor, AuditEvent, DEPLOYMENT_OPERATOR_ACTOR, NewAdminCredential,
    NewAdminIdentity, NewAdminRoleBinding, NewAuditEvent, RegistryError, Status,
    append_audit_event, create_admin_credential, create_admin_identity, create_admin_role_binding,
    events::{YEAR_OUT_OF_RANGE, in_envelope_years},
    is_reserved_actor_id,
    model::since_epoch,
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

/// The unique keys of steps 1 and 2 whose `23505` means another bootstrap
/// got there first: [`BootstrapError::AlreadyClosed`].
const CLOSING_KEYS: &[&str] = &[
    "instance_security_policy_pkey",
    "instance_security_policy_single_row",
    "recovery_state_pkey",
    "recovery_state_single_row",
];

/// Locks the policy row, if there is one.
const LOCK_POLICY: &str = "SELECT instance_id FROM instance_security_policy FOR UPDATE";

/// Whether bootstrap is closed. A statement of its own after the lock, so
/// that under `READ COMMITTED` it sees what a bootstrap that held the lock
/// committed.
const RECOVERY_STATE_EXISTS: &str = "SELECT EXISTS (SELECT FROM recovery_state) AS closed";

const INSERT_POLICY: &str =
    "INSERT INTO instance_security_policy (instance_id) VALUES ($1) RETURNING instance_id";

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
    /// exactly [`RECOVERY_PUBLIC_KEY_LENGTH`] bytes.
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

/// The error of a step 1 or 2 insert: [`BootstrapError::AlreadyClosed`]
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
/// variant `10xx`.
fn is_lowercase_uuid_v7(id: &str) -> bool {
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
    if request.recovery_public_key.len() != RECOVERY_PUBLIC_KEY_LENGTH {
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
    // The audit writer's own bound, checked here so that a time it would
    // refuse fails before step 1 rather than after step 3.
    if !in_envelope_years(since_epoch(request.now)?.microseconds) {
        return Err(encode_error(YEAR_OUT_OF_RANGE));
    }
    Ok(())
}

/// Bootstraps the instance in `transaction` (see the module docs for the
/// steps, the adopt rule and the errors). Never commits or rolls back: the
/// caller commits on `Ok` and rolls back on `Err`.
pub async fn bootstrap_instance(
    transaction: &mut Transaction<'_, Postgres>,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    validate(request)?;

    // Step 1: lock or insert the policy row, after checking closure.
    let stored: Option<String> = sqlx::query_scalar(LOCK_POLICY)
        .fetch_optional(&mut **transaction)
        .await?;
    let closed: bool = sqlx::query_scalar(RECOVERY_STATE_EXISTS)
        .fetch_one(&mut **transaction)
        .await?;
    if closed {
        return Err(BootstrapError::AlreadyClosed);
    }
    let instance_id = match stored {
        Some(stored) if stored == request.instance_id => stored,
        Some(_) => return Err(BootstrapError::InstanceIdMismatch),
        None => sqlx::query_scalar(INSERT_POLICY)
            .bind(request.instance_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(closed_or_store)?,
    };

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
    const KEY: [u8; 32] = [7; 32];

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
        // Any 32 bytes pass: the key is not checked further.
        let zero = [0; 32];
        let mut good = request(INSTANCE);
        good.recovery_public_key = &zero;
        assert!(validate(&good).is_ok());
        assert_eq!(RECOVERY_PUBLIC_KEY_LENGTH, 32);
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
    fn only_the_policy_and_recovery_keys_close_bootstrap() {
        assert_eq!(
            CLOSING_KEYS,
            [
                "instance_security_policy_pkey",
                "instance_security_policy_single_row",
                "recovery_state_pkey",
                "recovery_state_single_row",
            ]
        );
        assert!(matches!(
            closed_or_store(sqlx::Error::PoolClosed),
            BootstrapError::Store(RegistryError::Other(_))
        ));
    }

    #[test]
    fn the_statements_close_bootstrap_at_the_first_epoch() {
        assert!(INSERT_RECOVERY_STATE.contains("VALUES ($1, true, $2, $3)"));
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
