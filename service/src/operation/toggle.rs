//! The toggle of `widening_second_approver`, the first gated kind (proposal
//! section 3, "The toggle"; D16, D18, D19), and the pending insert every
//! gated request shares (section 3, request step 8). See the module docs of
//! [`crate::operation`].

use serde_json::Value;
use sqlx::{Postgres, Transaction};

use super::{
    ApprovalError, DigestEnvelope, Gated, OUTCOME_PENDING, OUTCOME_SUCCESS,
    OUTCOME_SUCCESS_SINGLE_ACTOR, OperationKind, PENDING_OPERATION_TTL,
    PLAN_REQUESTER_CREDENTIAL_ID, PLAN_WIDENING_SECOND_APPROVER, PendingOperation, Requester,
    Submission, UnstampedEvent, digest::microseconds_since_epoch,
};
use crate::persistence::registry::{
    AdminRole, AuditActor, InstanceSecurityPolicy, JsonObject, NewAdministrativeOperation,
    NewAuditEvent, OperatorRequest, OperatorScope, RegistryError, append_audit_event,
    authorize_operator_locked, floor_to_microsecond, insert_administrative_operation,
    lock_instance_security_policy, set_widening_second_approver,
};
use crate::trust::write::{in_savepoint, require_acknowledged, require_read_committed};

/// The event of a policy write (identity-registry IR-059).
const POLICY_UPDATE_ACTION: &str = "instance_security_policy.update";

/// The event that records a new operation, appended before it.
pub(super) const CREATE_ACTION: &str = "administrative_operation.create";

/// The toggle's plan: exactly these two members (section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TogglePlan {
    pub(super) requester_credential_id: String,
    pub(super) widening_second_approver: bool,
}

impl TogglePlan {
    pub(super) fn to_plan(&self) -> JsonObject {
        JsonObject::from_iter([
            (
                PLAN_REQUESTER_CREDENTIAL_ID.to_owned(),
                Value::String(self.requester_credential_id.clone()),
            ),
            (
                PLAN_WIDENING_SECOND_APPROVER.to_owned(),
                Value::Bool(self.widening_second_approver),
            ),
        ])
    }

    /// The plan of a stored toggle, or `None` when it is not exactly the
    /// two members with their types.
    pub(super) fn from_plan(plan: &JsonObject) -> Option<Self> {
        if plan.len() != 2 {
            return None;
        }
        Some(Self {
            requester_credential_id: plan.get(PLAN_REQUESTER_CREDENTIAL_ID)?.as_str()?.to_owned(),
            widening_second_approver: plan.get(PLAN_WIDENING_SECOND_APPROVER)?.as_bool()?,
        })
    }
}

/// The policy row `FOR NO KEY UPDATE`, never `FOR SHARE` (D19), at
/// `expected_revision`: a missing row is
/// [`ApprovalError::PolicyUnavailable`] (D18), another revision
/// [`ApprovalError::StaleRevision`].
pub(super) async fn lock_policy_at(
    transaction: &mut Transaction<'_, Postgres>,
    expected_revision: i64,
) -> Result<InstanceSecurityPolicy, ApprovalError> {
    let policy = match lock_instance_security_policy(transaction).await {
        Ok(policy) => policy,
        Err(RegistryError::NotFound) => return Err(ApprovalError::PolicyUnavailable),
        Err(err) => return Err(err.into()),
    };
    if policy.revision != expected_revision {
        return Err(ApprovalError::StaleRevision);
    }
    Ok(policy)
}

/// The toggle's post-authorization step (D26): the compare-and-set of the
/// policy row its caller holds from [`lock_policy_at`], by `requester`.
/// Returns the row and its `instance_security_policy.update` event,
/// unstamped; appends nothing.
pub(crate) async fn apply_policy_toggle(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    locked: &InstanceSecurityPolicy,
    widening_second_approver: bool,
) -> Result<(InstanceSecurityPolicy, UnstampedEvent), ApprovalError> {
    let row = set_widening_second_approver(
        transaction,
        &locked.instance_id,
        locked.revision,
        widening_second_approver,
    )
    .await
    .map_err(|err| match err {
        RegistryError::StaleRevision => ApprovalError::StaleRevision,
        RegistryError::NotFound => ApprovalError::PolicyUnavailable,
        other => other.into(),
    })?;
    let event = UnstampedEvent {
        tenant_id: None,
        actor: AuditActor::Operator(requester.admin_id.clone()),
        action: POLICY_UPDATE_ACTION,
        // IR-057: an instance-scope event names the instance.
        object_id: row.instance_id.clone(),
        previous_revision: Some(locked.revision),
        new_revision: Some(row.revision),
    };
    Ok((row, event))
}

/// What [`insert_pending`] stores besides the submission.
pub(crate) struct PendingRequest<'a> {
    pub(crate) kind: OperationKind,
    pub(crate) tenant_id: Option<&'a str>,
    pub(crate) expected_revision: i64,
    pub(crate) plan: JsonObject,
}

/// The pending branch of a request (section 3, request step 8): the
/// `administrative_operation.create` event through the audit head first,
/// then the operation, with its digest and an expiry of the submission's
/// `now` plus [`PENDING_OPERATION_TTL`], floored to a whole microsecond
/// (D5). Shared by every gated kind, so generic over the kind's error.
pub(crate) async fn insert_pending<E: From<RegistryError>>(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    requester: &Requester,
    request: PendingRequest<'_>,
) -> Result<PendingOperation, E> {
    let expires_at = submission
        .now
        .checked_add(PENDING_OPERATION_TTL)
        .map(floor_to_microsecond)
        .ok_or_else(|| encode_error("the expiry is outside the time range"))?;
    let expires_at_us = microseconds_since_epoch(expires_at)
        .ok_or_else(|| encode_error("the expiry is outside the time range"))?;
    let kind = request.kind.as_str();
    let request_digest = DigestEnvelope {
        id: submission.operation_id,
        tenant_id: request.tenant_id,
        actor_id: &requester.admin_id,
        kind,
        expected_revision: request.expected_revision,
        expires_at_us,
        plan: &request.plan,
    }
    .digest()
    .map_err(|_| encode_error("the plan has no canonical form"))?;
    append_audit_event(
        transaction,
        &NewAuditEvent {
            id: submission.event_id.into(),
            tenant_id: request.tenant_id.map(Into::into),
            timestamp: submission.now,
            actor: AuditActor::Operator(requester.admin_id.clone()),
            action: CREATE_ACTION.into(),
            object_id: submission.operation_id.into(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: OUTCOME_SUCCESS.into(),
        },
    )
    .await?;
    insert_administrative_operation(
        transaction,
        &NewAdministrativeOperation {
            id: submission.operation_id.into(),
            tenant_id: request.tenant_id.map(Into::into),
            actor_id: requester.admin_id.clone(),
            kind: kind.into(),
            request_digest: request_digest.as_bytes().to_vec(),
            expected_revision: request.expected_revision,
            immutable_plan: request.plan,
            expires_at: Some(expires_at),
            approves_operation_id: None,
            outcome: OUTCOME_PENDING.into(),
            audit_id: submission.event_id.into(),
        },
    )
    .await?;
    Ok(PendingOperation {
        id: submission.operation_id.into(),
        kind: request.kind,
        request_digest,
        expected_revision: request.expected_revision,
        expires_at,
    })
}

/// An encode error, before or instead of a statement.
pub(crate) fn encode_error<E: From<RegistryError>>(message: &'static str) -> E {
    RegistryError::Other(sqlx::Error::Encode(message.into())).into()
}

/// Requests `widening_second_approver = widening_second_approver` at the
/// policy row's `expected_revision` for the instance `security_admin`
/// whose credential has `submission.public_identity`: applied at once under
/// `single_actor_mode`, otherwise a pending
/// `instance_security_policy_update` operation (see the module docs, "The
/// toggle"). A request for `false` without
/// `submission.acknowledge_widening` is
/// [`ApprovalError::WideningNotAcknowledged`]. Runs in a savepoint of
/// `transaction`, only under `READ COMMITTED`; the caller commits on `Ok`
/// and rolls back on `Err`.
pub async fn submit_widening_toggle(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    expected_revision: i64,
    widening_second_approver: bool,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError> {
    in_savepoint(transaction, async |savepoint| {
        toggle_steps(
            savepoint,
            submission,
            expected_revision,
            widening_second_approver,
        )
        .await
    })
    .await
}

async fn toggle_steps(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    expected_revision: i64,
    widening_second_approver: bool,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError> {
    require_read_committed::<ApprovalError>(transaction).await?;
    let request = OperatorRequest {
        public_identity: submission.public_identity,
        scope: OperatorScope::Instance,
        role: AdminRole::SecurityAdmin,
    };
    let operator = authorize_operator_locked(transaction, &request)
        .await?
        .ok_or(ApprovalError::Unauthorized)?;
    let requester = Requester {
        admin_id: operator.admin_id,
        credential_id: operator.credential_id,
    };
    // Request step 3, as the trust writes take it: after the authorization,
    // before the policy row's lock and any write. Setting false is widening
    // whatever the current value (the user's ruling, 2026-11-24).
    if !widening_second_approver {
        require_acknowledged::<ApprovalError>(submission)?;
    }
    let policy = lock_policy_at(transaction, expected_revision).await?;
    if policy.single_actor_mode {
        let (row, event) =
            apply_policy_toggle(transaction, &requester, &policy, widening_second_approver).await?;
        let event = event.stamp(
            submission.event_id,
            submission.now,
            OUTCOME_SUCCESS_SINGLE_ACTOR,
        );
        append_audit_event(transaction, &event).await?;
        return Ok(Gated::Applied(row));
    }
    let plan = TogglePlan {
        requester_credential_id: requester.credential_id.clone(),
        widening_second_approver,
    };
    let request = PendingRequest {
        kind: OperationKind::InstanceSecurityPolicyUpdate,
        tenant_id: None,
        expected_revision,
        plan: plan.to_plan(),
    };
    let pending =
        insert_pending::<ApprovalError>(transaction, submission, &requester, request).await?;
    Ok(Gated::Pending(pending))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_toggle_plan_is_exactly_its_two_members() {
        let plan = TogglePlan {
            requester_credential_id: "crd_1".into(),
            widening_second_approver: true,
        };
        let stored = plan.to_plan();
        assert_eq!(
            Value::Object(stored.clone()),
            json!({"requester_credential_id": "crd_1", "widening_second_approver": true})
        );
        assert_eq!(TogglePlan::from_plan(&stored), Some(plan));
        for bad in [
            json!({}),
            json!({"requester_credential_id": "crd_1"}),
            json!({"widening_second_approver": true}),
            json!({"requester_credential_id": 1, "widening_second_approver": true}),
            json!({"requester_credential_id": "crd_1", "widening_second_approver": "true"}),
            json!({"requester_credential_id": "crd_1", "widening_second_approver": true, "x": 1}),
            json!({"requester_credential_id": "crd_1", "x": true}),
        ] {
            let Value::Object(bad) = bad else {
                unreachable!()
            };
            assert_eq!(TogglePlan::from_plan(&bad), None, "{bad:?}");
        }
    }
}
