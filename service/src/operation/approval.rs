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
    UnstampedEvent,
    digest::{from_microseconds, microseconds_since_epoch},
    keyset_plan::{CreatePlan, EnablePlan},
    source_plan::{CreateSourcePlan, UpdateSourcePlan, changed_members},
    toggle::{TogglePlan, apply_policy_toggle, lock_policy_at},
};
use crate::jwk::{Algorithm, ValidatedKeyset};
use crate::persistence::registry::{
    AdminRole, AdministrativeOperation, ApprovalAuthority, AuditActor, AuthorizedOperator,
    JsonObject, NewAdministrativeOperation, NewAuditEvent, OperatorRequest, OperatorScope,
    RegistryError, append_audit_event, authorize_approval_locked, authorize_operator,
    authorize_operator_locked, consume_administrative_operation, floor_to_microsecond,
    insert_administrative_operation, lock_administrative_operation,
    revoke_administrative_operation,
};
use crate::trust::{
    NewKeysetVersion,
    keyset::{apply_create_version, apply_enable_version, check_provenance, read_version_identity},
    source::{apply_create_source, apply_locked_update, lock_source, proof_bounds_equal},
    validate_upload,
    write::{in_savepoint, require_read_committed},
};

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
    TrustKeysetVersionCreate(CreatePlan),
    TrustKeysetVersionEnable(EnablePlan),
    TrustSourceCreate(CreateSourcePlan),
    TrustSourceUpdate(UpdateSourcePlan),
    InstanceSecurityPolicyUpdate(TogglePlan),
}

impl Payload {
    /// The plan of an operation of `kind`, or `None` when it is not one.
    fn parse(kind: OperationKind, plan: &JsonObject) -> Option<Self> {
        match kind {
            OperationKind::TrustKeysetVersionCreate => {
                CreatePlan::from_plan(plan).map(Self::TrustKeysetVersionCreate)
            }
            OperationKind::TrustKeysetVersionEnable => {
                EnablePlan::from_plan(plan).map(Self::TrustKeysetVersionEnable)
            }
            OperationKind::TrustSourceCreate => {
                CreateSourcePlan::from_plan(plan).map(Self::TrustSourceCreate)
            }
            OperationKind::TrustSourceUpdate => {
                UpdateSourcePlan::from_plan(plan).map(Self::TrustSourceUpdate)
            }
            OperationKind::InstanceSecurityPolicyUpdate => {
                TogglePlan::from_plan(plan).map(Self::InstanceSecurityPolicyUpdate)
            }
        }
    }

    fn kind(&self) -> OperationKind {
        match self {
            Self::TrustKeysetVersionCreate(_) => OperationKind::TrustKeysetVersionCreate,
            Self::TrustKeysetVersionEnable(_) => OperationKind::TrustKeysetVersionEnable,
            Self::TrustSourceCreate(_) => OperationKind::TrustSourceCreate,
            Self::TrustSourceUpdate(_) => OperationKind::TrustSourceUpdate,
            Self::InstanceSecurityPolicyUpdate(_) => OperationKind::InstanceSecurityPolicyUpdate,
        }
    }
}

/// An operation authorized and read without a lock, its plan parsed
/// outside any transaction, by [`prepare_approval`]: the input of
/// [`approve_operation`]. `Debug` prints the kind only.
pub struct PreparedApproval {
    operation_id: String,
    request_digest: RequestDigest,
    payload: Payload,
    /// A keyset create's projection, parsed in full on the Stage A pool
    /// (D25); `None` for every other kind.
    keys: Option<ValidatedKeyset>,
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

/// A stored digest as a [`RequestDigest`]: 32 bytes, or
/// [`ApprovalError::PlanIntegrity`] (the column allows 32 to 64 bytes, and
/// this flow writes 32 only).
fn stored_digest(bytes: &[u8]) -> Result<RequestDigest, ApprovalError> {
    RequestDigest::try_from(bytes).map_err(|_| ApprovalError::PlanIntegrity)
}

/// The locked row's stored digest, checked before the echo is compared
/// (D6): 32 bytes, and equal to the digest recomputed from the row's ID,
/// tenant, actor, kind, expected revision, expiry and plan. Anything else
/// is [`ApprovalError::PlanIntegrity`], a data-integrity error, never an
/// [`ApprovalError::EchoMismatch`].
fn verified_digest(locked: &AdministrativeOperation) -> Result<RequestDigest, ApprovalError> {
    let stored = stored_digest(&locked.request_digest)?;
    let expires_at = locked.expires_at.ok_or(ApprovalError::PlanIntegrity)?;
    if recompute(locked, expires_at)? != stored {
        return Err(ApprovalError::PlanIntegrity);
    }
    Ok(stored)
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
/// stored digest that is not 32 bytes, or a plan that is not its kind's).
/// For a keyset create it then parses the plan's projection in full on the
/// Stage A pool ([`validate_upload`]) against the plan's
/// `allowed_algorithms` intersected with `allowed`, the caller's current
/// set (D25; a refusal is [`ApprovalError::Keyset`]), and compares its
/// fingerprint with the plan's ([`ApprovalError::PlanIntegrity`]); whether
/// the projection is byte for byte the plan's is the approve's check, under
/// the lock (D24). Takes no lock and writes nothing.
pub async fn prepare_approval(
    pool: &PgPool,
    approver_public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
    allowed: &[Algorithm],
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
    let request_digest = stored_digest(&request_digest)?;
    let payload = Payload::parse(kind, &plan).ok_or(ApprovalError::PlanIntegrity)?;
    let keys = match &payload {
        Payload::TrustKeysetVersionCreate(plan) => Some(prepare_keys(plan, allowed).await?),
        Payload::TrustKeysetVersionEnable(_)
        | Payload::TrustSourceCreate(_)
        | Payload::TrustSourceUpdate(_)
        | Payload::InstanceSecurityPolicyUpdate(_) => None,
    };
    Ok(PreparedApproval {
        operation_id: operation_id.into(),
        request_digest,
        payload,
        keys,
    })
}

/// A keyset create's projection parsed in full on the Stage A pool, against
/// the plan's algorithms that `allowed` holds too (D25), with the plan's
/// fingerprint. Text that is not JSON, or a fingerprint other than the
/// plan's, is [`ApprovalError::PlanIntegrity`]; a set the rules refuse,
/// an empty intersection included, is [`ApprovalError::Keyset`].
async fn prepare_keys(
    plan: &CreatePlan,
    allowed: &[Algorithm],
) -> Result<ValidatedKeyset, ApprovalError> {
    let value: Value =
        serde_json::from_str(&plan.public_jwks).map_err(|_| ApprovalError::PlanIntegrity)?;
    let both: Vec<Algorithm> = plan
        .allowed_algorithms
        .iter()
        .copied()
        .filter(|alg| allowed.contains(alg))
        .collect();
    let keys = validate_upload(value, &both).await?;
    if keys.fingerprint().as_str() != plan.fingerprint {
        return Err(ApprovalError::PlanIntegrity);
    }
    Ok(keys)
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
    // The stored digest first: a row that does not match its own digest is
    // a data-integrity error whatever the echo says.
    let stored = verified_digest(&locked)?;
    if stored != echo.request_digest
        || locked.expected_revision != echo.expected_revision
        || stored != prepared.request_digest
    {
        return Err(ApprovalError::EchoMismatch);
    }
    let expires_at = locked.expires_at.ok_or(ApprovalError::PlanIntegrity)?;
    let payload =
        Payload::parse(kind, &locked.immutable_plan).ok_or(ApprovalError::PlanIntegrity)?;
    if payload != prepared.payload {
        return Err(ApprovalError::PlanIntegrity);
    }
    // D24: what the preparation parsed is byte for byte the locked plan's
    // projection.
    if let Payload::TrustKeysetVersionCreate(plan) = &payload
        && prepared.keys.as_ref().map(ValidatedKeyset::public_json) != Some(&plan.public_jwks)
    {
        return Err(ApprovalError::PlanIntegrity);
    }
    // Step 5: the kind's post-authorization step, through the registry
    // write.
    let requester = Requester {
        admin_id: requester.admin_id,
        credential_id: requester.credential_id,
    };
    let (applied, event) = match payload {
        Payload::TrustKeysetVersionCreate(plan) => {
            apply_create(transaction, &locked, prepared, &requester, &plan).await?
        }
        Payload::TrustKeysetVersionEnable(plan) => {
            apply_enable(transaction, &locked, &requester, &plan).await?
        }
        Payload::TrustSourceCreate(plan) => {
            apply_source_create(transaction, &locked, &requester, &plan).await?
        }
        Payload::TrustSourceUpdate(plan) => {
            apply_source_update(transaction, &locked, &requester, &plan).await?
        }
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

/// Step 5 of a keyset create's approve: the create's steps from the plan
/// (D26), on the projection [`prepare_approval`] parsed and step 4
/// compared with the locked plan. The provenance private-member check runs
/// again (section 4); the window is the plan's whole microseconds; the
/// tenant is the operation's.
async fn apply_create(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &AdministrativeOperation,
    prepared: &PreparedApproval,
    requester: &Requester,
    plan: &CreatePlan,
) -> Result<(Applied, UnstampedEvent), ApprovalError> {
    let provenance = plan.provenance().ok_or(ApprovalError::PlanIntegrity)?;
    check_provenance(&provenance)?;
    let keys = prepared.keys.as_ref().ok_or(ApprovalError::PlanIntegrity)?;
    let tenant_id = locked
        .tenant_id
        .as_deref()
        .ok_or(ApprovalError::PlanIntegrity)?;
    let effective_at =
        from_microseconds(plan.effective_at_us).ok_or(ApprovalError::PlanIntegrity)?;
    let expires_at = match plan.expires_at_us {
        Some(micros) => Some(from_microseconds(micros).ok_or(ApprovalError::PlanIntegrity)?),
        None => None,
    };
    let new = NewKeysetVersion {
        id: &plan.version_id,
        tenant_id,
        keyset_id: &plan.keyset_id,
        keys,
        effective_at,
        expires_at,
        status: plan.status,
        provenance: &provenance,
    };
    let (row, event) = apply_create_version(transaction, requester, &new).await?;
    Ok((Applied::KeysetVersion(row), event))
}

/// Step 5 of a keyset enable's approve: the version's keyset and stored
/// fingerprint must be the plan's (inferred: both are immutable, so another
/// value is a data-integrity error, [`ApprovalError::PlanIntegrity`]), then
/// the enable's steps at the operation's `expected_revision` (D26).
async fn apply_enable(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &AdministrativeOperation,
    requester: &Requester,
    plan: &EnablePlan,
) -> Result<(Applied, UnstampedEvent), ApprovalError> {
    let tenant_id = locked
        .tenant_id
        .as_deref()
        .ok_or(ApprovalError::PlanIntegrity)?;
    let identity = read_version_identity(transaction, tenant_id, &plan.version_id).await?;
    if identity.keyset_id != plan.keyset_id || identity.fingerprint != plan.fingerprint {
        return Err(ApprovalError::PlanIntegrity);
    }
    let (row, event) = apply_enable_version(
        transaction,
        requester,
        tenant_id,
        &plan.version_id,
        locked.expected_revision,
    )
    .await?;
    Ok((Applied::KeysetVersion(row), event))
}

/// Step 5 of a trust source create's approve: the create's steps from the
/// plan (D26): the syntax of its destinations again, each entry
/// `FOR SHARE` and the insert. The tenant is the operation's; a plan that
/// names another is [`ApprovalError::PlanIntegrity`] (inferred: the
/// request writes the operation in the source's tenant, so another value
/// is a data-integrity error).
async fn apply_source_create(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &AdministrativeOperation,
    requester: &Requester,
    plan: &CreateSourcePlan,
) -> Result<(Applied, UnstampedEvent), ApprovalError> {
    let new = plan.to_new().ok_or(ApprovalError::PlanIntegrity)?;
    if locked.tenant_id.as_deref() != Some(new.tenant_id.as_str()) {
        return Err(ApprovalError::PlanIntegrity);
    }
    let (row, event) = apply_create_source(transaction, requester, &new).await?;
    Ok((Applied::Source(row), event))
}

/// Step 5 of a trust source update's approve: the stored row at the
/// operation's `expected_revision` `FOR NO KEY UPDATE`, whose members the
/// changes differ from must be the plan's `changed` (inferred: at the same
/// revision the row is the one the request read, so another list is a
/// data-integrity error, [`ApprovalError::PlanIntegrity`]); then the
/// update's steps (D26). The class is not computed again: the revision
/// binds the row the request classified.
async fn apply_source_update(
    transaction: &mut Transaction<'_, Postgres>,
    locked: &AdministrativeOperation,
    requester: &Requester,
    plan: &UpdateSourcePlan,
) -> Result<(Applied, UnstampedEvent), ApprovalError> {
    let tenant_id = locked
        .tenant_id
        .as_deref()
        .ok_or(ApprovalError::PlanIntegrity)?;
    let changes = plan.to_changes().ok_or(ApprovalError::PlanIntegrity)?;
    let stored = lock_source(
        transaction,
        tenant_id,
        &plan.source_id,
        locked.expected_revision,
    )
    .await?;
    let equal = proof_bounds_equal(transaction, &stored, &changes.proof_bounds).await?;
    if changed_members(&stored, &changes, equal) != plan.changed {
        return Err(ApprovalError::PlanIntegrity);
    }
    let (row, event) = apply_locked_update(transaction, requester, &stored, &changes).await?;
    Ok((Applied::Source(row), event))
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
            // Another operator's operation: on a tenant path `NotFound`,
            // like a missing one, so one `trust_admin` learns nothing of
            // another's operations; on the instance path `Unauthorized`,
            // which tells an instance `security_admin` that the operation
            // exists, which it may read anyway there (Q1).
            if header.actor_id != actor.admin_id {
                return Err(match revoke.scope {
                    ApprovalScope::Tenant(_) => ApprovalError::NotFound,
                    ApprovalScope::Instance => ApprovalError::Unauthorized,
                });
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
    use serde_json::json;

    use super::*;

    /// A pending toggle row whose digest is the one recomputed from it.
    fn locked_row() -> AdministrativeOperation {
        let Value::Object(plan) = json!({
            "requester_credential_id": "crd_1",
            "widening_second_approver": true,
        }) else {
            unreachable!()
        };
        let mut row = AdministrativeOperation {
            id: "op_1".into(),
            tenant_id: None,
            actor_id: "adm_1".into(),
            kind: "instance_security_policy_update".into(),
            request_digest: Vec::new(),
            expected_revision: 1,
            immutable_plan: plan,
            challenge_hash: None,
            expires_at: Some(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_790_000_000),
            ),
            consumed_at: None,
            revoked_at: None,
            revocation_operation_id: None,
            approves_operation_id: None,
            revision: 1,
            outcome: "pending".into(),
            audit_id: "evt_op_1".into(),
        };
        row.request_digest = recompute(&row, row.expires_at.unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
        row
    }

    #[test]
    fn a_stored_digest_is_32_bytes_and_its_rows_own() {
        let row = locked_row();
        let digest = verified_digest(&row).unwrap();
        assert_eq!(digest.as_bytes()[..], row.request_digest[..]);
        assert_eq!(stored_digest(&row.request_digest).unwrap(), digest);
        // Another length, even with the right 32 bytes first.
        for bytes in [
            [&row.request_digest[..], &[0][..]].concat(),
            [&row.request_digest[..], &row.request_digest[..]].concat(),
            row.request_digest[..31].to_vec(),
            Vec::new(),
        ] {
            assert!(matches!(
                stored_digest(&bytes),
                Err(ApprovalError::PlanIntegrity)
            ));
            let longer = AdministrativeOperation {
                request_digest: bytes,
                ..row.clone()
            };
            assert!(matches!(
                verified_digest(&longer),
                Err(ApprovalError::PlanIntegrity)
            ));
        }
        // 32 bytes that are not the row's digest, and a row changed under
        // its digest.
        let mut other = row.clone();
        other.request_digest[0] ^= 1;
        assert!(matches!(
            verified_digest(&other),
            Err(ApprovalError::PlanIntegrity)
        ));
        let mut moved = row.clone();
        moved.expected_revision = 2;
        assert!(matches!(
            verified_digest(&moved),
            Err(ApprovalError::PlanIntegrity)
        ));
        let mut no_expiry = row;
        no_expiry.expires_at = None;
        assert!(matches!(
            verified_digest(&no_expiry),
            Err(ApprovalError::PlanIntegrity)
        ));
    }

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

    /// The cancel's guard that the kind's role is the path's cannot refuse
    /// a cancel the path check let through: for every kind, on every path
    /// that holds the operation, the kind's requester role is the one
    /// `requester_request` looked up, or the kind is refused as
    /// `WrongKind` before the guard. The guard stays as a defence against
    /// a future kind that breaks this.
    #[test]
    fn a_kinds_requester_role_is_its_paths() {
        for &kind in OperationKind::ALL {
            for scope in [ApprovalScope::Instance, ApprovalScope::Tenant("ten_a")] {
                for tenant_id in [None, Some("ten_a"), Some("ten_b")] {
                    if !scope.holds(tenant_id) {
                        continue;
                    }
                    let Some((role_scope, role)) = kind.requester_role(tenant_id) else {
                        continue;
                    };
                    let request = requester_request("key", scope);
                    assert_eq!(
                        (role_scope, role),
                        (request.scope, request.role),
                        "{kind:?} {tenant_id:?}"
                    );
                }
            }
        }
    }
}
