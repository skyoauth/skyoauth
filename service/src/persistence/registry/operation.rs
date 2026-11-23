//! The registry floor of the second-approver flow
//! (`docs/proposals/second-approver-gated-writes.md` sections 2, 3 and 9;
//! IR-052 to IR-054): the `administrative_operation` row of a pending gated
//! write, an approval or a revocation, the `instance_security_policy` row
//! locks, and the two locked operator lookups of a request and an approval.
//! Nothing calls these functions yet: the service flow (`crate::operation`,
//! the gated `submit_*` writes) comes later, and no endpoint is wired.
//!
//! # Operation rows
//!
//! The writers are bare, like the other registry writers: they check
//! nothing the database does not, write no audit event and read no clock.
//! The caller supplies every ID and time (T10.2) and orders the statements
//! as the migrations README prescribes for a write that creates an
//! operation ("What 0005 adds": the rows it references or updates locked
//! first, then the audit head and the event, then the operation, then the
//! remaining updates).
//!
//! - [`insert_administrative_operation`] inserts a new operation, unconsumed
//!   and unrevoked, with no challenge (a recovery challenge has its own
//!   writer, [`issue_recovery_challenge`](super::issue_recovery_challenge)),
//!   and returns the row. A pending gated write has an `expires_at` and no
//!   approved operation; an `approve` names the operation it approves; a
//!   `cancel` or `reject` has neither (section 2).
//! - [`lock_administrative_operation`] reads the row `FOR NO KEY UPDATE`
//!   (the README's lock for a row a write updates), or `None`.
//! - [`consume_administrative_operation`] sets `consumed_at` and the
//!   `outcome` and advances the revision; [`revoke_administrative_operation`]
//!   sets `revoked_at` and `revocation_operation_id` together, as the `0005`
//!   check `administrative_operation_revocation_check` requires, with the
//!   `outcome`, and advances the revision. Both return the new revision and
//!   are [`RegistryError::NotFound`] for a missing row.
//!
//! **The consume and revoke writers are not idempotency guards.** They do
//! not compare the operation's state, and the set-once guard rejects only a
//! *changed* value: a repeat with the same `consumed_at`, or the same
//! `revoked_at` and `revocation_operation_id`, succeeds, advances the
//! revision and may overwrite the `outcome`. The caller must lock the row
//! with [`lock_administrative_operation`] (`FOR NO KEY UPDATE`) first and
//! check `consumed_at`, `revoked_at` and `expires_at` under that lock. What
//! the database does refuse: a repeat with a different value is the
//! set-once guard's [`RegistryError::Guard`], a consume of a revoked,
//! unconsumed operation the consume-after-revoke guard's
//! [`RegistryError::Guard`], and a consume at or after `expires_at`
//! `administrative_operation_consumed_before_expiry_check`
//! ([`RegistryError::Invariant`]).
//!
//! Since the amended `0005` the database also refuses, with `23514`, an
//! `approve` that names an operation of another tenant or of its own actor,
//! and a revocation whose revoking operation is of another tenant
//! ([`InvariantKind::SameTenantOperation`](super::InvariantKind::SameTenantOperation)
//! and [`InvariantKind::DistinctApprover`](super::InvariantKind::DistinctApprover);
//! migrations README, "What 0005 adds"). Only kind `approve` is checked: a
//! `route_bundle_approval` by the same actor stays allowed, and the tenant of
//! the operation any other kind names is the caller's to check.
//!
//! # The policy row
//!
//! [`lock_instance_security_policy_shared`] reads the row `FOR SHARE`, as a
//! widening trust write does (section 3, request step 4; D10), and
//! [`lock_instance_security_policy`] `FOR NO KEY UPDATE`, as the toggle
//! does in both its branches (D19): the toggle's lock conflicts with the
//! trust writes' and with another toggle's, and two trust writes do not
//! wait for each other. Before bootstrap there is no row:
//! [`RegistryError::NotFound`], which the service reports as
//! `PolicyUnavailable` (D18). A role that takes the row `FOR SHARE` needs
//! `SELECT` on `instance_security_policy` and `UPDATE` on one of its
//! columns; the proposal's grant is `UPDATE (instance_id)`, a column
//! `instance_security_policy_immutable` keeps unchangeable (migrations
//! README, "What 0005 adds", "Privileges").
//!
//! # Locked operator lookups
//!
//! Both run the unlocked lookup of
//! [`authorize_operator`](super::authorize_operator) (an enabled, unrevoked
//! credential of an enabled operator with an enabled binding of exactly the
//! role and scope), lock the rows it found `FOR SHARE`, then repeat the
//! lookups and keep the answer only if it is unchanged, as
//! [`authorize_operator_locked`](super::authorize_operator_locked) does. A
//! miss of the first lookup locks nothing. The locks are taken in the
//! `0005` order of the migrations README: the `admin_identity` rows, then
//! the `admin_credential` rows, then the `admin_role_binding` rows, each
//! table's rows in one statement ordered by ID byte-wise (inferred: one
//! ordered statement per table, as the README asks "where possible" and
//! section 3 asks for the bindings). The locks are held until the caller's
//! transaction ends; in a savepoint, until it is rolled back.
//!
//! - [`authorize_roles_locked`] is the requester's lookup: the operator of
//!   one presented credential and, for each listed role and scope, the
//!   binding that grants it, if any. A request needs the role of its kind;
//!   under `single_actor_mode` it also asks for instance `security_admin`,
//!   which is locked in the same ordered statement (section 3, request step
//!   2; Q4). `None` when the credential or its operator fails, when no
//!   listed role is held, or when the repeat differs (inferred: the
//!   operator is known only through a held binding). **`Some` does not mean
//!   authorized:** it is returned when *any* listed role is held, so an
//!   operator that holds only the optional instance `security_admin` gets
//!   `Some` with the required role missing. The caller must check
//!   [`RolesHeld::holds`] for each role it requires (`holds(0)` for the
//!   kind's role when it is listed first).
//! - [`authorize_approval_locked`] is the approve's: the approver, by the
//!   presented credential, must hold instance `security_admin` (IR-054) and
//!   be another operator than the requester (byte-wise `admin_id`), and the
//!   requester, by the `admin_id` and `credential_id` the plan holds, must
//!   still have that credential enabled and unrevoked, an enabled identity
//!   and an enabled binding of the kind's role (Q5; D21). Both operators'
//!   rows are locked (section 3, approve step 3). The refusals come in that
//!   order, each with nothing locked when the first lookup decides it:
//!   [`ApprovalAuthority::ApproverNotAuthorized`],
//!   [`ApprovalAuthority::SelfApproval`],
//!   [`ApprovalAuthority::RequesterNotAuthorized`].
//!
//! Neither reads a clock, writes anything or checks the transaction's
//! isolation level; under `REPEATABLE READ` or `SERIALIZABLE` a lock on a
//! row changed after the snapshot is `40001` ([`RegistryError::Retry`]).
//!
//! # Time
//!
//! Times are explicit arguments, written as whole microseconds truncated
//! toward the past, and a time outside the `0007` range is
//! [`RegistryError::Other`] before any statement runs, as everywhere in the
//! registry.

use std::time::SystemTime;

use sqlx::{FromRow, Postgres, Row, Transaction, postgres::PgRow, types::Json};

use super::{
    AdminRole, InstanceSecurityPolicy, JsonObject, RegistryError, authorize_operator,
    instance::policy_columns,
    micros,
    model::{Origin, json, optional_since_epoch, since_epoch, timestamp},
    operator::{AuthorizedOperator, OperatorRequest, OperatorScope, authorize_credential},
};

/// An `administrative_operation` row (`0005`; tasks section 3): an operator
/// write, a pending gated write, an approval, a revocation or a recovery
/// challenge. Every column; `tenant_id` is `None` for the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdministrativeOperation {
    pub id: String,
    pub tenant_id: Option<String>,
    /// The requester, approver or revoker; not an operator foreign key.
    pub actor_id: String,
    pub kind: String,
    /// 32 to 64 bytes.
    pub request_digest: Vec<u8>,
    pub expected_revision: i64,
    pub immutable_plan: JsonObject,
    pub challenge_hash: Option<Vec<u8>>,
    pub expires_at: Option<SystemTime>,
    /// Set once, by [`consume_administrative_operation`].
    pub consumed_at: Option<SystemTime>,
    /// Set once, with `revocation_operation_id`, by
    /// [`revoke_administrative_operation`].
    pub revoked_at: Option<SystemTime>,
    pub revocation_operation_id: Option<String>,
    pub approves_operation_id: Option<String>,
    pub revision: i64,
    pub outcome: String,
    pub audit_id: String,
}

impl FromRow<'_, PgRow> for AdministrativeOperation {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("administrative_operation");
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            actor_id: row.try_get("actor_id")?,
            kind: row.try_get("kind")?,
            request_digest: row.try_get("request_digest")?,
            expected_revision: row.try_get("expected_revision")?,
            immutable_plan: json(row, "immutable_plan")?,
            challenge_hash: row.try_get("challenge_hash")?,
            expires_at: timestamp(row, ORIGIN, "expires_at")?,
            consumed_at: timestamp(row, ORIGIN, "consumed_at")?,
            revoked_at: timestamp(row, ORIGIN, "revoked_at")?,
            revocation_operation_id: row.try_get("revocation_operation_id")?,
            approves_operation_id: row.try_get("approves_operation_id")?,
            revision: row.try_get("revision")?,
            outcome: row.try_get("outcome")?,
            audit_id: row.try_get("audit_id")?,
        })
    }
}

/// The input of [`insert_administrative_operation`]: every column a new
/// operation of the second-approver flow sets. It starts unconsumed and
/// unrevoked, at revision 1, with no challenge (inferred: section 2 sets
/// `consumed_at` and the revocation only by an update, and a recovery
/// challenge has its own writer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAdministrativeOperation {
    pub id: String,
    pub tenant_id: Option<String>,
    pub actor_id: String,
    pub kind: String,
    pub request_digest: Vec<u8>,
    pub expected_revision: i64,
    pub immutable_plan: JsonObject,
    /// The caller's expiry; `None` for an approval or a revocation.
    pub expires_at: Option<SystemTime>,
    /// The approved operation, for an `approve`.
    pub approves_operation_id: Option<String>,
    pub outcome: String,
    /// The event that records the operation, appended first.
    pub audit_id: String,
}

/// What [`authorize_approval_locked`] decided. Only
/// [`Self::Authorized`] lets an approval proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalAuthority {
    /// Both operators hold their roles and are distinct; their identity,
    /// credential and binding rows are locked `FOR SHARE` until the
    /// transaction ends.
    Authorized {
        /// The approver's instance `security_admin` rows.
        approver: AuthorizedOperator,
        /// The requester's rows: the plan's credential and the binding of
        /// the kind's role.
        requester: AuthorizedOperator,
    },
    /// The presented credential is no enabled, unrevoked credential of an
    /// enabled operator with an enabled instance `security_admin` binding
    /// (the service's `Unauthorized`).
    ApproverNotAuthorized,
    /// The approver is the requester: the same `admin_id` (IR-054).
    SelfApproval,
    /// The requester's identity is disabled, the plan's credential is not
    /// theirs or is disabled or revoked, or the role is no longer held
    /// (Q5; D21).
    RequesterNotAuthorized,
}

/// What [`authorize_roles_locked`] found: the operator of the presented
/// credential and, for each requested role, the binding that grants it.
/// Holding one role is enough to get a `RolesHeld`: check [`Self::holds`]
/// for every role the request requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolesHeld {
    pub admin_id: String,
    pub credential_id: String,
    /// One entry per requested `(scope, role)`, in the order given: the ID
    /// of the enabled binding that grants it, or `None`. At least one is
    /// set.
    pub bindings: Vec<Option<String>>,
}

impl RolesHeld {
    /// Whether the role at `index` of the request is held.
    pub fn holds(&self, index: usize) -> bool {
        self.bindings.get(index).is_some_and(Option::is_some)
    }
}

macro_rules! operation_columns {
    () => {
        concat!(
            "id, tenant_id, actor_id, kind, request_digest, expected_revision, \
             immutable_plan, challenge_hash, ",
            micros!("expires_at"),
            ", ",
            micros!("consumed_at"),
            ", ",
            micros!("revoked_at"),
            ", revocation_operation_id, approves_operation_id, revision, outcome, audit_id"
        )
    };
}

const INSERT_OPERATION: &str = concat!(
    "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
     expected_revision, immutable_plan, expires_at, approves_operation_id, outcome, audit_id) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, timestamptz 'epoch' + $8::interval, $9, $10, $11) \
     RETURNING ",
    operation_columns!()
);

/// The operation row, locked for the update the caller makes later.
const LOCK_OPERATION: &str = concat!(
    "SELECT ",
    operation_columns!(),
    " FROM administrative_operation WHERE id = $1 FOR NO KEY UPDATE"
);

const CONSUME_OPERATION: &str = "UPDATE administrative_operation \
     SET consumed_at = timestamptz 'epoch' + $2::interval, outcome = $3, \
     revision = revision + 1 WHERE id = $1 RETURNING revision";

const REVOKE_OPERATION: &str = "UPDATE administrative_operation \
     SET revoked_at = timestamptz 'epoch' + $3::interval, revocation_operation_id = $2, \
     outcome = $4, revision = revision + 1 WHERE id = $1 RETURNING revision";

const SHARE_POLICY: &str = concat!(
    "SELECT ",
    policy_columns!(),
    " FROM instance_security_policy FOR SHARE"
);

const LOCK_POLICY: &str = concat!(
    "SELECT ",
    policy_columns!(),
    " FROM instance_security_policy FOR NO KEY UPDATE"
);

/// The operator row locks, in the `0005` table order, each table's rows in
/// one statement in key order. `$1` is the array of IDs.
const LOCK_IDENTITIES: &str =
    "SELECT FROM admin_identity WHERE id = ANY($1) ORDER BY id COLLATE \"C\" FOR SHARE";
const LOCK_CREDENTIALS: &str =
    "SELECT FROM admin_credential WHERE id = ANY($1) ORDER BY id COLLATE \"C\" FOR SHARE";
const LOCK_BINDINGS: &str =
    "SELECT FROM admin_role_binding WHERE id = ANY($1) ORDER BY id COLLATE \"C\" FOR SHARE";

/// Inserts a new operation (see the module documentation, "Operation
/// rows") and returns it. A time outside the `0007` range is
/// [`RegistryError::Other`] before any statement runs; the database's
/// refusals map as everywhere in the registry.
pub async fn insert_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    new: &NewAdministrativeOperation,
) -> Result<AdministrativeOperation, RegistryError> {
    let expires_at = optional_since_epoch(new.expires_at)?;
    Ok(sqlx::query_as(INSERT_OPERATION)
        .bind(&new.id)
        .bind(new.tenant_id.as_deref())
        .bind(&new.actor_id)
        .bind(&new.kind)
        .bind(&new.request_digest)
        .bind(new.expected_revision)
        .bind(Json(&new.immutable_plan))
        .bind(expires_at)
        .bind(new.approves_operation_id.as_deref())
        .bind(&new.outcome)
        .bind(&new.audit_id)
        .fetch_one(&mut **transaction)
        .await?)
}

/// The operation `id`, locked `FOR NO KEY UPDATE` until the transaction
/// ends, or `None`.
pub async fn lock_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Option<AdministrativeOperation>, RegistryError> {
    Ok(sqlx::query_as(LOCK_OPERATION)
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?)
}

/// Sets the operation's `consumed_at` to `now` and its `outcome`, advances
/// its revision and returns the new one. Checks nothing the database does
/// not: a repeat with the same `now` succeeds again (see the module
/// documentation, "Operation rows"), so check `consumed_at` under
/// [`lock_administrative_operation`] first.
pub async fn consume_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<i64, RegistryError> {
    let now = since_epoch(now)?;
    let row = sqlx::query(CONSUME_OPERATION)
        .bind(id)
        .bind(now)
        .bind(outcome)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)?;
    Ok(row.try_get("revision")?)
}

/// Sets the operation's `revoked_at` to `now` and its
/// `revocation_operation_id` to `revoking_operation_id`, in one statement,
/// and its `outcome`; advances its revision and returns the new one. Checks
/// nothing the database does not: a repeat with the same `now` and
/// `revoking_operation_id` succeeds again (see the module documentation,
/// "Operation rows"), so check `revoked_at` under
/// [`lock_administrative_operation`] first.
pub async fn revoke_administrative_operation(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    revoking_operation_id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<i64, RegistryError> {
    let now = since_epoch(now)?;
    let row = sqlx::query(REVOKE_OPERATION)
        .bind(id)
        .bind(revoking_operation_id)
        .bind(now)
        .bind(outcome)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)?;
    Ok(row.try_get("revision")?)
}

/// The policy row `FOR SHARE` (a widening trust write; D10);
/// [`RegistryError::NotFound`] before bootstrap (D18).
pub async fn lock_instance_security_policy_shared(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<InstanceSecurityPolicy, RegistryError> {
    sqlx::query_as(SHARE_POLICY)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)
}

/// The policy row `FOR NO KEY UPDATE` (the toggle, both branches; D19);
/// [`RegistryError::NotFound`] before bootstrap (D18).
pub async fn lock_instance_security_policy(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<InstanceSecurityPolicy, RegistryError> {
    sqlx::query_as(LOCK_POLICY)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)
}

/// Locks the operator rows `FOR SHARE` in the `0005` order: identities,
/// credentials, bindings, each table in one statement in byte-wise ID
/// order. A table with no ID is skipped.
async fn lock_operator_rows(
    transaction: &mut Transaction<'_, Postgres>,
    identities: &[&str],
    credentials: &[&str],
    bindings: &[&str],
) -> Result<(), RegistryError> {
    for (lock, ids) in [
        (LOCK_IDENTITIES, identities),
        (LOCK_CREDENTIALS, credentials),
        (LOCK_BINDINGS, bindings),
    ] {
        if ids.is_empty() {
            continue;
        }
        sqlx::query(lock)
            .bind(ids)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

/// The approver's request: instance `security_admin` (IR-054).
fn approver_request(public_identity: &str) -> OperatorRequest<'_> {
    OperatorRequest {
        public_identity,
        scope: OperatorScope::Instance,
        role: AdminRole::SecurityAdmin,
    }
}

/// The approver and the requester of an operation, both locked `FOR SHARE`
/// in the `0005` order and both still authorized after the locks (see the
/// module documentation, "Locked operator lookups"). The approver is found
/// by `approver_public_identity` and must hold instance `security_admin`;
/// the requester by `requester_admin_id` and `requester_credential_id`, the
/// plan's, and must hold `requester_role` in `requester_scope`. Reads no
/// clock and writes nothing.
pub async fn authorize_approval_locked(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    requester_admin_id: &str,
    requester_credential_id: &str,
    requester_scope: OperatorScope<'_>,
    requester_role: AdminRole,
) -> Result<ApprovalAuthority, RegistryError> {
    let approver_request = approver_request(approver_public_identity);
    let Some(approver) = authorize_operator(&mut **transaction, &approver_request).await? else {
        return Ok(ApprovalAuthority::ApproverNotAuthorized);
    };
    if approver.admin_id == requester_admin_id {
        return Ok(ApprovalAuthority::SelfApproval);
    }
    let requester = (
        requester_admin_id,
        requester_credential_id,
        requester_scope,
        requester_role,
    );
    let Some(requester_first) = authorize_requester(transaction, requester).await? else {
        return Ok(ApprovalAuthority::RequesterNotAuthorized);
    };
    lock_operator_rows(
        transaction,
        &[&approver.admin_id, &requester_first.admin_id],
        &[&approver.credential_id, &requester_first.credential_id],
        &[&approver.binding_id, &requester_first.binding_id],
    )
    .await?;
    let approver_again = authorize_operator(&mut **transaction, &approver_request).await?;
    if approver_again.as_ref() != Some(&approver) {
        return Ok(ApprovalAuthority::ApproverNotAuthorized);
    }
    let requester_again = authorize_requester(transaction, requester).await?;
    if requester_again.as_ref() != Some(&requester_first) {
        return Ok(ApprovalAuthority::RequesterNotAuthorized);
    }
    Ok(ApprovalAuthority::Authorized {
        approver,
        requester: requester_first,
    })
}

/// The requester's lookup of [`authorize_approval_locked`]: its operator
/// and credential IDs, scope and role.
async fn authorize_requester(
    transaction: &mut Transaction<'_, Postgres>,
    (admin_id, credential_id, scope, role): (&str, &str, OperatorScope<'_>, AdminRole),
) -> Result<Option<AuthorizedOperator>, RegistryError> {
    authorize_credential(&mut **transaction, admin_id, credential_id, scope, role).await
}

/// The unlocked lookup of [`authorize_roles_locked`]: one
/// [`authorize_operator`] per role. `None` when no role is held.
async fn roles_held(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    roles: &[(OperatorScope<'_>, AdminRole)],
) -> Result<Option<RolesHeld>, RegistryError> {
    let mut operator: Option<(String, String)> = None;
    let mut bindings = Vec::with_capacity(roles.len());
    for &(scope, role) in roles {
        let request = OperatorRequest {
            public_identity,
            scope,
            role,
        };
        let hit = authorize_operator(&mut **transaction, &request).await?;
        bindings.push(hit.map(|hit| {
            // `public_identity` is unique, so every hit names one
            // credential of one operator.
            operator.get_or_insert((hit.admin_id, hit.credential_id));
            hit.binding_id
        }));
    }
    Ok(operator.map(|(admin_id, credential_id)| RolesHeld {
        admin_id,
        credential_id,
        bindings,
    }))
}

/// The roles that the operator of the presented credential holds among
/// `roles`, with the rows locked `FOR SHARE` in the `0005` order: its
/// identity, its credential, then every held binding in one ordered
/// statement; the lookup is repeated after the locks and kept only if
/// unchanged (see the module documentation, "Locked operator lookups").
/// `None` when no listed role is held. Reads no clock and writes nothing.
///
/// # A `Some` is not an authorization
///
/// `Some` means that *at least one* listed role is held, not all of them:
/// asked for `[(tenant, trust_admin), (Instance, security_admin)]`, an
/// operator holding only the instance `security_admin` gets `Some` with
/// `bindings == [None, Some(_)]`. Check [`RolesHeld::holds`] for every
/// required role (here `holds(0)`) and refuse when one is missing.
pub async fn authorize_roles_locked(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    roles: &[(OperatorScope<'_>, AdminRole)],
) -> Result<Option<RolesHeld>, RegistryError> {
    let Some(first) = roles_held(transaction, public_identity, roles).await? else {
        return Ok(None);
    };
    let bindings: Vec<&str> = first
        .bindings
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    lock_operator_rows(
        transaction,
        &[&first.admin_id],
        &[&first.credential_id],
        &bindings,
    )
    .await?;
    let second = roles_held(transaction, public_identity, roles).await?;
    Ok(second.filter(|second| *second == first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operation_locks_and_writes_have_their_strength_and_columns() {
        assert!(
            LOCK_OPERATION
                .ends_with(" FROM administrative_operation WHERE id = $1 FOR NO KEY UPDATE")
        );
        assert!(SHARE_POLICY.ends_with(" FROM instance_security_policy FOR SHARE"));
        assert!(LOCK_POLICY.ends_with(" FROM instance_security_policy FOR NO KEY UPDATE"));
        for (lock, table) in [
            (LOCK_IDENTITIES, "admin_identity"),
            (LOCK_CREDENTIALS, "admin_credential"),
            (LOCK_BINDINGS, "admin_role_binding"),
        ] {
            assert_eq!(
                lock,
                format!(
                    "SELECT FROM {table} WHERE id = ANY($1) ORDER BY id COLLATE \"C\" FOR SHARE"
                )
            );
        }
        // The revocation sets both columns of the 0005 check in one
        // statement; neither writer compares the operation's state.
        assert!(REVOKE_OPERATION.contains("revoked_at = timestamptz 'epoch' + $3::interval"));
        assert!(REVOKE_OPERATION.contains("revocation_operation_id = $2"));
        for statement in [CONSUME_OPERATION, REVOKE_OPERATION] {
            assert!(
                statement.ends_with(" WHERE id = $1 RETURNING revision"),
                "{statement}"
            );
            assert!(statement.contains("revision = revision + 1"), "{statement}");
            assert!(!statement.contains("now()"), "{statement}");
        }
    }

    #[test]
    fn roles_held_reports_each_requested_role() {
        let held = RolesHeld {
            admin_id: "adm_1".into(),
            credential_id: "crd_1".into(),
            bindings: vec![None, Some("rb_1".into())],
        };
        assert!(!held.holds(0));
        assert!(held.holds(1));
        assert!(!held.holds(2));
    }
}
