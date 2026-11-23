//! The approval of a pending operation, and its cancel and reject
//! (proposal section 3, "Approve" and "Cancel and reject"). See the module
//! docs of [`crate::operation`] for the steps and the picks.

use std::{fmt, time::SystemTime};

use serde_json::Value;
use sqlx::{
    PgExecutor, PgPool, Postgres, Row, Transaction, postgres::PgRow, postgres::types::PgInterval,
    types::Json,
};

use super::{
    Applied, ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, DigestEnvelope,
    NotApprovableReason, OUTCOME_APPLIED, OUTCOME_CANCELLED, OUTCOME_REJECTED, OUTCOME_SUCCESS,
    OperationKind, PLAN_REQUESTER_CREDENTIAL_ID, RequestDigest, Requester, RevokeIds,
    digest::microseconds_since_epoch,
    toggle::{TogglePlan, apply_policy_toggle, lock_policy_at},
};
use crate::persistence::registry::{
    AdminRole, AdministrativeOperation, ApprovalAuthority, AuditActor, AuthorizedOperator,
    JsonObject, NewAdministrativeOperation, NewAuditEvent, OperatorRequest, OperatorScope,
    RegistryError, append_audit_event, authorize_approval_locked, authorize_operator,
    authorize_operator_locked, consume_administrative_operation, floor_to_microsecond,
    insert_administrative_operation, lock_administrative_operation,
    revoke_administrative_operation,
};
use crate::trust::write::{in_savepoint, require_read_committed};

/// The kind of an approval (IR-054), of a cancel and of a reject (section
/// 2; inferred names, as the audit verbs).
const APPROVE_KIND: &str = "approve";
const CANCEL_KIND: &str = "cancel";
const REJECT_KIND: &str = "reject";

const APPROVE_ACTION: &str = "administrative_operation.approve";
const CANCEL_ACTION: &str = "administrative_operation.cancel";
const REJECT_ACTION: &str = "administrative_operation.reject";

/// The operation's immutable columns that decide its scope, its requester
/// and its kind, read without a lock (approve step 2).
const READ_HEADER: &str =
    "SELECT tenant_id, actor_id, kind FROM administrative_operation WHERE id = $1";

/// [`READ_HEADER`] with the state [`prepare_approval`] checks without a
/// lock: whether the operation is consumed, revoked, or still open at `$2`
/// (the caller's `now`, floored to a microsecond: `now < expires_at`).
const READ_STATE: &str = "SELECT tenant_id, actor_id, kind, \
     consumed_at IS NOT NULL AS consumed, revoked_at IS NOT NULL AS revoked, \
     (expires_at IS NOT NULL AND expires_at > timestamptz 'epoch' + $2::interval) AS open \
     FROM administrative_operation WHERE id = $1";

/// The digest and the plan, read only once the caller is authorized (D20).
const READ_PLAN: &str =
    "SELECT request_digest, immutable_plan FROM administrative_operation WHERE id = $1";

/// What an approval needs of a kind's plan: the plan parsed as the kind's.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Payload {
    InstanceSecurityPolicyUpdate(TogglePlan),
}

impl Payload {
    /// The plan of an operation of `kind`, or `None` when it is not one.
    fn parse(kind: OperationKind, plan: &JsonObject) -> Option<Self> {
        match kind {
            OperationKind::InstanceSecurityPolicyUpdate => {
                TogglePlan::from_plan(plan).map(Self::InstanceSecurityPolicyUpdate)
            }
        }
    }

    fn kind(&self) -> OperationKind {
        match self {
            Self::InstanceSecurityPolicyUpdate(_) => OperationKind::InstanceSecurityPolicyUpdate,
        }
    }
}

/// An operation authorized and read without a lock, its plan parsed
/// outside any transaction, by [`prepare_approval`]: the input of
/// [`approve_operation`]. `Debug` prints the kind only.
pub struct PreparedApproval {
    operation_id: String,
    request_digest: Vec<u8>,
    payload: Payload,
}

impl PreparedApproval {
    /// The operation to approve.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Its kind.
    pub fn kind(&self) -> OperationKind {
        self.payload.kind()
    }
}

impl fmt::Debug for PreparedApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedApproval")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

/// The operation's immutable columns of [`READ_HEADER`].
struct Header {
    tenant_id: Option<String>,
    actor_id: String,
    kind: String,
}

impl Header {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            tenant_id: row.try_get("tenant_id")?,
            actor_id: row.try_get("actor_id")?,
            kind: row.try_get("kind")?,
        })
    }

    /// The kind of the flow, and its requester's scope and role, or
    /// [`NotApprovableReason::WrongKind`].
    fn kind(&self) -> Result<(OperationKind, OperatorScope<'_>, AdminRole), ApprovalError> {
        let wrong_kind = ApprovalError::NotApprovable(NotApprovableReason::WrongKind);
        let kind = OperationKind::from_name(&self.kind).ok_or(wrong_kind)?;
        let (scope, role) = kind
            .requester_role(self.tenant_id.as_deref())
            .ok_or(ApprovalError::NotApprovable(NotApprovableReason::WrongKind))?;
        Ok((kind, scope, role))
    }

    /// The approver's checks of approve step 2, in order: the path's scope
    /// ([`ApprovalError::NotFound`]), the approver is not the requester
    /// ([`ApprovalError::SelfApproval`]), the kind.
    fn check_approver(
        &self,
        scope: ApprovalScope<'_>,
        approver: &AuthorizedOperator,
    ) -> Result<(OperationKind, OperatorScope<'_>, AdminRole), ApprovalError> {
        if !scope.holds(self.tenant_id.as_deref()) {
            return Err(ApprovalError::NotFound);
        }
        if self.actor_id == approver.admin_id {
            return Err(ApprovalError::SelfApproval);
        }
        self.kind()
    }
}

/// The approver's request: instance `security_admin` (IR-054).
fn approver_request(public_identity: &str) -> OperatorRequest<'_> {
    OperatorRequest {
        public_identity,
        scope: OperatorScope::Instance,
        role: AdminRole::SecurityAdmin,
    }
}

/// The requester's request on a path (inferred: every instance kind of the
/// flow is an instance `security_admin` write, every tenant kind a tenant
/// `trust_admin` write; section 6).
fn requester_request<'a>(
    public_identity: &'a str,
    scope: ApprovalScope<'a>,
) -> OperatorRequest<'a> {
    let (scope, role) = match scope {
        ApprovalScope::Instance => (OperatorScope::Instance, AdminRole::SecurityAdmin),
        ApprovalScope::Tenant(tenant_id) => {
            (OperatorScope::Tenant(tenant_id), AdminRole::TrustAdmin)
        }
    };
    OperatorRequest {
        public_identity,
        scope,
        role,
    }
}

async fn read_header<'e>(executor: impl PgExecutor<'e>, id: &str) -> Result<Header, ApprovalError> {
    let row = sqlx::query(READ_HEADER)
        .bind(id)
        .fetch_optional(executor)
        .await?
        .ok_or(ApprovalError::NotFound)?;
    Ok(Header::from_row(&row)?)
}

async fn read_plan<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<(Vec<u8>, JsonObject), ApprovalError> {
    let row = sqlx::query(READ_PLAN)
        .bind(id)
        .fetch_optional(executor)
        .await?
        .ok_or(ApprovalError::NotFound)?;
    let plan: Json<JsonObject> = row.try_get("immutable_plan")?;
    Ok((row.try_get("request_digest")?, plan.0))
}

/// `time` as an interval from the epoch, floored to a whole microsecond.
fn since_epoch(time: SystemTime) -> Result<PgInterval, ApprovalError> {
    let microseconds = microseconds_since_epoch(time).ok_or_else(|| {
        ApprovalError::from(RegistryError::Other(sqlx::Error::Encode(
            "the time is outside the time range".into(),
        )))
    })?;
    Ok(PgInterval {
        months: 0,
        days: 0,
        microseconds,
    })
}

/// The digest recomputed from the stored row (D6), or
/// [`ApprovalError::PlanIntegrity`] when the row has no canonical form.
fn recompute(
    row: &AdministrativeOperation,
    expires_at: SystemTime,
) -> Result<RequestDigest, ApprovalError> {
    let expires_at_us = microseconds_since_epoch(expires_at).ok_or(ApprovalError::PlanIntegrity)?;
    DigestEnvelope {
        id: &row.id,
        tenant_id: row.tenant_id.as_deref(),
        actor_id: &row.actor_id,
        kind: &row.kind,
        expected_revision: row.expected_revision,
        expires_at_us,
        plan: &row.immutable_plan,
    }
    .digest()
    .map_err(|_| ApprovalError::PlanIntegrity)
}

/// Consumed or revoked, under the row lock.
fn check_open(locked: &AdministrativeOperation) -> Result<(), ApprovalError> {
    if locked.consumed_at.is_some() {
        return Err(ApprovalError::NotApprovable(NotApprovableReason::Consumed));
    }
    if locked.revoked_at.is_some() {
        return Err(ApprovalError::NotApprovable(NotApprovableReason::Revoked));
    }
    Ok(())
}

/// Authorizes the operator of `approver_public_identity` to approve the
/// operation `operation_id` on the path `scope`, reads it without a lock
/// and parses its plan, outside any transaction, in this order (D20): the
/// approver's lookup ([`ApprovalError::Unauthorized`]), the operation's
/// scope ([`ApprovalError::NotFound`]), self-approval, its kind, whether it
/// is consumed, revoked or expired at `now` ([`ApprovalError::NotApprovable`]);
/// only then the digest and the plan ([`ApprovalError::PlanIntegrity`] for a
/// plan that is not its kind's). Takes no lock and writes nothing.
pub async fn prepare_approval(
    pool: &PgPool,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
    now: SystemTime,
) -> Result<PreparedApproval, ApprovalError> {
    let approver = authorize_operator(pool, &approver_request(approver_public_identity))
        .await?
        .ok_or(ApprovalError::Unauthorized)?;
    let row = sqlx::query(READ_STATE)
        .bind(operation_id)
        .bind(since_epoch(now)?)
        .fetch_optional(pool)
        .await?
        .ok_or(ApprovalError::NotFound)?;
    let header = Header::from_row(&row)?;
    let (kind, _, _) = header.check_approver(scope, &approver)?;
    for (column, reason) in [
        ("consumed", NotApprovableReason::Consumed),
        ("revoked", NotApprovableReason::Revoked),
    ] {
        if row.try_get::<bool, _>(column)? {
            return Err(ApprovalError::NotApprovable(reason));
        }
    }
    if !row.try_get::<bool, _>("open")? {
        return Err(ApprovalError::NotApprovable(NotApprovableReason::Expired));
    }
    let (request_digest, plan) = read_plan(pool, operation_id).await?;
    let payload = Payload::parse(kind, &plan).ok_or(ApprovalError::PlanIntegrity)?;
    Ok(PreparedApproval {
        operation_id: operation_id.into(),
        request_digest,
        payload,
    })
}

/// Approves the operation `prepared` names, on the path `scope`, for the
/// instance `security_admin` whose credential has
/// `approver_public_identity`, with the approver's `echo`, and applies it:
/// the approve operation, the write and the events (see the module docs,
/// "Approve"; `clock` is sampled once, after the write, D28). Runs in a
/// savepoint of `transaction`, only under `READ COMMITTED`; the caller
/// commits on `Ok` and rolls back on `Err`.
pub async fn approve_operation(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    ids: &ApprovalIds<'_>,
    clock: &dyn Clock,
) -> Result<Applied, ApprovalError> {
    in_savepoint(transaction, async |savepoint| {
        let approval = Approval {
            approver_public_identity,
            scope,
            prepared,
            echo,
            ids,
            clock,
        };
        approve_steps(savepoint, &approval).await
    })
    .await
}

/// The input of [`approve_steps`].
struct Approval<'a> {
    approver_public_identity: &'a str,
    scope: ApprovalScope<'a>,
    prepared: &'a PreparedApproval,
    echo: &'a ApprovalEcho,
    ids: &'a ApprovalIds<'a>,
    clock: &'a dyn Clock,
}

async fn approve_steps(
    transaction: &mut Transaction<'_, Postgres>,
    approval: &Approval<'_>,
) -> Result<Applied, ApprovalError> {
    let Approval {
        approver_public_identity,
        scope,
        prepared,
        echo,
        ids,
        clock,
    } = *approval;
    let id = prepared.operation_id.as_str();
    // Step 0.
    require_read_committed::<ApprovalError>(transaction).await?;
    // Step 2: the approver before anything about the operation is read.
    let approver = authorize_operator(
        &mut **transaction,
        &approver_request(approver_public_identity),
    )
    .await?
    .ok_or(ApprovalError::Unauthorized)?;
    let header = read_header(&mut **transaction, id).await?;
    let (kind, requester_scope, requester_role) = header.check_approver(scope, &approver)?;
    let (_, plan) = read_plan(&mut **transaction, id).await?;
    let credential_id = plan
        .get(PLAN_REQUESTER_CREDENTIAL_ID)
        .and_then(Value::as_str)
        .ok_or(ApprovalError::PlanIntegrity)?;
    // Step 3: both operators' rows FOR SHARE.
    let authority = authorize_approval_locked(
        transaction,
        approver_public_identity,
        &header.actor_id,
        credential_id,
        requester_scope,
        requester_role,
    )
    .await?;
    let (approver, requester) = match authority {
        ApprovalAuthority::Authorized {
            approver,
            requester,
        } => (approver, requester),
        ApprovalAuthority::ApproverNotAuthorized => return Err(ApprovalError::Unauthorized),
        ApprovalAuthority::SelfApproval => return Err(ApprovalError::SelfApproval),
        ApprovalAuthority::RequesterNotAuthorized => {
            return Err(ApprovalError::RequesterNotAuthorized);
        }
    };
    // Step 4: the operation row FOR NO KEY UPDATE.
    let locked = lock_administrative_operation(transaction, id)
        .await?
        .ok_or(ApprovalError::NotFound)?;
    check_open(&locked)?;
    if locked.request_digest != echo.request_digest.as_bytes()
        || locked.expected_revision != echo.expected_revision
        || locked.request_digest != prepared.request_digest
    {
        return Err(ApprovalError::EchoMismatch);
    }
    let expires_at = locked.expires_at.ok_or(ApprovalError::PlanIntegrity)?;
    if recompute(&locked, expires_at)?.as_bytes()[..] != locked.request_digest[..] {
        return Err(ApprovalError::PlanIntegrity);
    }
    let payload =
        Payload::parse(kind, &locked.immutable_plan).ok_or(ApprovalError::PlanIntegrity)?;
    if payload != prepared.payload {
        return Err(ApprovalError::PlanIntegrity);
    }
    // Step 5: the kind's post-authorization step, through the registry
    // write.
    let requester = Requester {
        admin_id: requester.admin_id,
        credential_id: requester.credential_id,
    };
    let (applied, event) = match payload {
        Payload::InstanceSecurityPolicyUpdate(plan) => {
            let policy = lock_policy_at(transaction, locked.expected_revision).await?;
            let (row, event) = apply_policy_toggle(
                transaction,
                &requester,
                &policy,
                plan.widening_second_approver,
            )
            .await?;
            (Applied::InstanceSecurityPolicy(row), event)
        }
    };
    // Step 6: the one clock sample (D28).
    let now = floor_to_microsecond(clock.now());
    if now >= expires_at {
        return Err(ApprovalError::NotApprovable(NotApprovableReason::Expired));
    }
    // Step 7: the audit head last.
    append_audit_event(
        transaction,
        &NewAuditEvent {
            id: ids.approve_event_id.into(),
            tenant_id: locked.tenant_id.clone(),
            timestamp: now,
            actor: AuditActor::Operator(approver.admin_id.clone()),
            action: APPROVE_ACTION.into(),
            object_id: locked.id.clone(),
            previous_revision: Some(locked.revision),
            new_revision: Some(locked.revision + 1),
            outcome: OUTCOME_SUCCESS.into(),
        },
    )
    .await?;
    insert_administrative_operation(
        transaction,
        &NewAdministrativeOperation {
            id: ids.approve_operation_id.into(),
            tenant_id: locked.tenant_id.clone(),
            actor_id: approver.admin_id,
            kind: APPROVE_KIND.into(),
            request_digest: locked.request_digest.clone(),
            expected_revision: locked.expected_revision,
            immutable_plan: JsonObject::new(),
            expires_at: None,
            approves_operation_id: Some(locked.id.clone()),
            outcome: OUTCOME_SUCCESS.into(),
            audit_id: ids.approve_event_id.into(),
        },
    )
    .await?;
    append_audit_event(
        transaction,
        &event.stamp(ids.write_event_id, now, OUTCOME_SUCCESS),
    )
    .await?;
    consume_administrative_operation(transaction, id, now, OUTCOME_APPLIED).await?;
    Ok(applied)
}

/// A cancel or a reject.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Revocation {
    Cancel,
    Reject,
}

/// Cancels the operation `operation_id` on the path `scope` for its
/// requester, whose operator's credential has `requester_public_identity`
/// (any enabled, unrevoked credential of that identity), at `now` (see the
/// module docs, "Cancel and reject"). Runs in a savepoint of
/// `transaction`, only under `READ COMMITTED`; the caller commits on `Ok`
/// and rolls back on `Err`.
pub async fn cancel_operation(
    transaction: &mut Transaction<'_, Postgres>,
    requester_public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
    ids: &RevokeIds<'_>,
    now: SystemTime,
) -> Result<(), ApprovalError> {
    let revoke = Revoke {
        revocation: Revocation::Cancel,
        public_identity: requester_public_identity,
        scope,
        operation_id,
        ids,
        now,
    };
    in_savepoint(transaction, async |savepoint| {
        revoke_steps(savepoint, &revoke).await
    })
    .await
}

/// As [`cancel_operation`], by an instance `security_admin` who is not the
/// requester, whose credential has `approver_public_identity`.
pub async fn reject_operation(
    transaction: &mut Transaction<'_, Postgres>,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
    ids: &RevokeIds<'_>,
    now: SystemTime,
) -> Result<(), ApprovalError> {
    let revoke = Revoke {
        revocation: Revocation::Reject,
        public_identity: approver_public_identity,
        scope,
        operation_id,
        ids,
        now,
    };
    in_savepoint(transaction, async |savepoint| {
        revoke_steps(savepoint, &revoke).await
    })
    .await
}

/// The input of [`revoke_steps`].
struct Revoke<'a> {
    revocation: Revocation,
    public_identity: &'a str,
    scope: ApprovalScope<'a>,
    operation_id: &'a str,
    ids: &'a RevokeIds<'a>,
    now: SystemTime,
}

async fn revoke_steps(
    transaction: &mut Transaction<'_, Postgres>,
    revoke: &Revoke<'_>,
) -> Result<(), ApprovalError> {
    let id = revoke.operation_id;
    require_read_committed::<ApprovalError>(transaction).await?;
    let request = match revoke.revocation {
        Revocation::Cancel => requester_request(revoke.public_identity, revoke.scope),
        Revocation::Reject => approver_request(revoke.public_identity),
    };
    // The actor's lookup, before anything about the operation is read.
    let actor = authorize_operator(&mut **transaction, &request)
        .await?
        .ok_or(ApprovalError::Unauthorized)?;
    let header = read_header(&mut **transaction, id).await?;
    match revoke.revocation {
        Revocation::Cancel => {
            if !revoke.scope.holds(header.tenant_id.as_deref()) {
                return Err(ApprovalError::NotFound);
            }
            if header.actor_id != actor.admin_id {
                return Err(ApprovalError::Unauthorized);
            }
            let (_, scope, role) = header.kind()?;
            // The kind's role is the path's (see `requester_request`).
            if (scope, role) != (request.scope, request.role) {
                return Err(ApprovalError::NotApprovable(NotApprovableReason::WrongKind));
            }
        }
        Revocation::Reject => {
            header.check_approver(revoke.scope, &actor)?;
        }
    }
    // The actor's rows FOR SHARE, the lookup repeated.
    let locked_actor = authorize_operator_locked(transaction, &request).await?;
    if locked_actor.as_ref() != Some(&actor) {
        return Err(ApprovalError::Unauthorized);
    }
    let locked = lock_administrative_operation(transaction, id)
        .await?
        .ok_or(ApprovalError::NotFound)?;
    check_open(&locked)?;
    let (kind, action, outcome) = match revoke.revocation {
        Revocation::Cancel => (CANCEL_KIND, CANCEL_ACTION, OUTCOME_CANCELLED),
        Revocation::Reject => (REJECT_KIND, REJECT_ACTION, OUTCOME_REJECTED),
    };
    let ids = revoke.ids;
    append_audit_event(
        transaction,
        &NewAuditEvent {
            id: ids.event_id.into(),
            tenant_id: locked.tenant_id.clone(),
            timestamp: revoke.now,
            actor: AuditActor::Operator(actor.admin_id.clone()),
            action: action.into(),
            object_id: locked.id.clone(),
            previous_revision: Some(locked.revision),
            new_revision: Some(locked.revision + 1),
            outcome: OUTCOME_SUCCESS.into(),
        },
    )
    .await?;
    insert_administrative_operation(
        transaction,
        &NewAdministrativeOperation {
            id: ids.revoking_operation_id.into(),
            tenant_id: locked.tenant_id.clone(),
            actor_id: actor.admin_id,
            kind: kind.into(),
            request_digest: locked.request_digest.clone(),
            expected_revision: locked.expected_revision,
            immutable_plan: JsonObject::new(),
            expires_at: None,
            approves_operation_id: None,
            outcome: OUTCOME_SUCCESS.into(),
            audit_id: ids.event_id.into(),
        },
    )
    .await?;
    revoke_administrative_operation(
        transaction,
        id,
        ids.revoking_operation_id,
        revoke.now,
        outcome,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unlocked_reads_take_no_lock_and_the_plan_comes_last() {
        for statement in [READ_HEADER, READ_STATE, READ_PLAN] {
            assert!(!statement.contains(" FOR "), "{statement}");
            assert!(
                statement.ends_with(" FROM administrative_operation WHERE id = $1"),
                "{statement}"
            );
        }
        for statement in [READ_HEADER, READ_STATE] {
            assert!(!statement.contains("immutable_plan"), "{statement}");
            assert!(!statement.contains("request_digest"), "{statement}");
        }
        assert!(READ_STATE.contains("expires_at > timestamptz 'epoch' + $2::interval"));
    }

    #[test]
    fn a_cancel_looks_up_the_paths_requester_role() {
        assert_eq!(
            requester_request("key", ApprovalScope::Instance),
            OperatorRequest {
                public_identity: "key",
                scope: OperatorScope::Instance,
                role: AdminRole::SecurityAdmin,
            }
        );
        assert_eq!(
            requester_request("key", ApprovalScope::Tenant("ten_a")),
            OperatorRequest {
                public_identity: "key",
                scope: OperatorScope::Tenant("ten_a"),
                role: AdminRole::TrustAdmin,
            }
        );
        assert_eq!(
            approver_request("key"),
            OperatorRequest {
                public_identity: "key",
                scope: OperatorScope::Instance,
                role: AdminRole::SecurityAdmin,
            }
        );
    }
}
