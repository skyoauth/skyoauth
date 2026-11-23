//! The steps the trust keyset version writes ([`super::keyset`]) and the
//! trust source writes ([`super::source`]) share: the `READ COMMITTED`
//! check of step 0, the `trust_admin` authorization of step 1 and the
//! savepoint each write runs its steps in; and, for a gated write, request
//! steps 1, 3 and 4 of the second-approver flow (proposal section 3,
//! "Request"): together for a write whose class its kind fixes
//! ([`authorize_widening_write`]), or one by one for a source update, which
//! classifies after it has read its stored row (Q2). Each module's docs
//! state the rules; this module only holds the code once. The isolation
//! check and the savepoint are shared with the second-approver flow too
//! ([`crate::operation`]). It is crate-private and adds nothing to the
//! public API. Nothing here names a kind of write.

use sqlx::{Connection, Postgres, Transaction};

use crate::operation::{
    OUTCOME_SUCCESS_SINGLE_ACTOR, OUTCOME_SUCCESS_WIDENING, Requester, Submission,
};
use crate::persistence::registry::{
    AdminRole, InstanceSecurityPolicy, OperatorRequest, OperatorScope, RegistryError,
    authorize_operator_locked, authorize_roles_locked, lock_instance_security_policy_shared,
};

/// Step 0: the transaction's isolation level.
const TRANSACTION_ISOLATION: &str = "SELECT current_setting('transaction_isolation')";

/// The one isolation level the writes run at, as `transaction_isolation`
/// names it.
const READ_COMMITTED: &str = "read committed";

/// The error of a trust write, with the two refusals the shared steps
/// return. Each is a unit variant of fixed text, naming no input.
pub(crate) trait WriteError: From<sqlx::Error> + From<RegistryError> {
    /// Step 0's refusal: the transaction does not run at `READ COMMITTED`.
    const UNSUPPORTED_ISOLATION: Self;
    /// Step 1's refusal: the operator is not a `trust_admin` of the tenant.
    const UNAUTHORIZED: Self;
}

/// Step 0: `READ COMMITTED` only.
pub(crate) async fn require_read_committed<E: WriteError>(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), E> {
    let isolation: String = sqlx::query_scalar(TRANSACTION_ISOLATION)
        .fetch_one(&mut **transaction)
        .await?;
    if isolation != READ_COMMITTED {
        return Err(E::UNSUPPORTED_ISOLATION);
    }
    Ok(())
}

/// The error of a gated trust write: a [`WriteError`] with the two
/// refusals of the gate's own steps (proposal section 10), unit variants of
/// fixed text.
pub(crate) trait GatedWriteError: WriteError {
    /// Request step 3: a widening write without `acknowledge_widening`.
    const WIDENING_NOT_ACKNOWLEDGED: Self;
    /// Request step 4: no `instance_security_policy` row (D18).
    const POLICY_UNAVAILABLE: Self;
}

/// What a gated write does once it is classified and request step 4 has
/// read the policy row (proposal section 1, the mode table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Applied at once; its domain event takes this outcome:
    /// `success_widening` while `widening_second_approver` is off (D23),
    /// `success_single_actor` with it on under `single_actor_mode` for a
    /// requester who also holds instance `security_admin` (Q4), `success`
    /// for a write that is not widening (a disable-only source update, Q2).
    Apply(&'static str),
    /// A pending operation; the target is not written.
    Pending,
}

/// Step 1: a `trust_admin` of `tenant_id`, locked until the transaction
/// ends; the operator's ID and the credential it presented (D26).
pub(super) async fn authorize_trust_admin<E: WriteError>(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
) -> Result<Requester, E> {
    let request = OperatorRequest {
        public_identity,
        scope: OperatorScope::Tenant(tenant_id),
        role: AdminRole::TrustAdmin,
    };
    match authorize_operator_locked(transaction, &request).await? {
        Some(operator) => Ok(Requester {
            admin_id: operator.admin_id,
            credential_id: operator.credential_id,
        }),
        None => Err(E::UNAUTHORIZED),
    }
}

/// The requester of a gated trust write as request step 1 authorized it:
/// a `trust_admin` of the tenant, and whether it also holds instance
/// `security_admin`, which `single_actor_mode` asks for (Q4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatedRequester {
    pub(crate) requester: Requester,
    /// [`RolesHeld::holds`]`(1)`: the instance `security_admin` binding.
    ///
    /// [`RolesHeld::holds`]: crate::persistence::registry::RolesHeld::holds
    security_admin: bool,
}

/// Request step 1 of a gated trust write of `tenant_id` (proposal section
/// 3, "Request"), after step 0: the requester's operator rows `FOR SHARE`
/// through [`authorize_roles_locked`], asking for the tenant `trust_admin`
/// and the instance `security_admin` in one ordered statement (Q4). A
/// `Some` means that at least one is held: only [`RolesHeld::holds`]`(0)`,
/// the `trust_admin`, authorizes the write, and anything else is
/// `UNAUTHORIZED`. The instance binding is always asked for, before the
/// policy row says whether `single_actor_mode` needs it (inferred: the
/// operator rows come before the policy row in the lock order). Because the
/// instance binding is always asked for and the whole [`RolesHeld`] is
/// compared before and after the locks, an instance `security_admin`
/// binding granted or disabled in that window makes even a pure
/// `trust_admin` request `UNAUTHORIZED`, although the mode would not have
/// needed it: this fails closed, and a retry works.
///
/// [`RolesHeld`]: crate::persistence::registry::RolesHeld
/// [`RolesHeld::holds`]: crate::persistence::registry::RolesHeld::holds
pub(crate) async fn authorize_gated_requester<E: WriteError>(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    tenant_id: &str,
) -> Result<GatedRequester, E> {
    let roles = [
        (OperatorScope::Tenant(tenant_id), AdminRole::TrustAdmin),
        (OperatorScope::Instance, AdminRole::SecurityAdmin),
    ];
    let held = authorize_roles_locked(transaction, submission.public_identity, &roles)
        .await?
        .filter(|held| held.holds(0))
        .ok_or(E::UNAUTHORIZED)?;
    Ok(GatedRequester {
        security_admin: held.holds(1),
        requester: Requester {
            admin_id: held.admin_id,
            credential_id: held.credential_id,
        },
    })
}

/// Request step 3 of a widening write: without `acknowledge_widening`,
/// `WIDENING_NOT_ACKNOWLEDGED`.
pub(crate) fn require_acknowledged<E: GatedWriteError>(
    submission: &Submission<'_>,
) -> Result<(), E> {
    if submission.acknowledge_widening {
        Ok(())
    } else {
        Err(E::WIDENING_NOT_ACKNOWLEDGED)
    }
}

/// Request step 4: the `instance_security_policy` row `FOR SHARE` (D10);
/// `None` when there is none. The caller decides what a missing row means
/// ([`widening_mode`]: `POLICY_UNAVAILABLE`, D18).
pub(crate) async fn lock_policy_shared<E: From<RegistryError>>(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Option<InstanceSecurityPolicy>, E> {
    match lock_instance_security_policy_shared(transaction).await {
        Ok(policy) => Ok(Some(policy)),
        Err(RegistryError::NotFound) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// The mode of a widening write (proposal section 1, the mode table) from
/// the policy row that step 4 read: a missing row is `POLICY_UNAVAILABLE`
/// (D18); `widening_second_approver` off applies it with
/// `success_widening` (D23); on, with `single_actor_mode` on and a
/// requester who also holds instance `security_admin`, with
/// `success_single_actor` (Q4); otherwise it is pending.
pub(crate) fn widening_mode<E: GatedWriteError>(
    requester: &GatedRequester,
    policy: Option<&InstanceSecurityPolicy>,
) -> Result<Mode, E> {
    let policy = policy.ok_or(E::POLICY_UNAVAILABLE)?;
    Ok(if !policy.widening_second_approver {
        Mode::Apply(OUTCOME_SUCCESS_WIDENING)
    } else if policy.single_actor_mode && requester.security_admin {
        Mode::Apply(OUTCOME_SUCCESS_SINGLE_ACTOR)
    } else {
        Mode::Pending
    })
}

/// Request steps 1, 3 and 4 of a write of `tenant_id` whose class is
/// widening by its kind (proposal section 3, "Request"), after step 0:
///
/// 1. the requester ([`authorize_gated_requester`]);
/// 3. without `acknowledge_widening`, `WIDENING_NOT_ACKNOWLEDGED`
///    ([`require_acknowledged`]): every write that calls this is widening,
///    a class fixed by its kind;
/// 4. the `instance_security_policy` row `FOR SHARE` (D10); a missing row is
///    `POLICY_UNAVAILABLE` (D18). The mode follows from it
///    ([`widening_mode`]).
///
/// A source update, whose class depends on the stored row (Q2), calls the
/// steps one by one instead, and classifies after its own row lock.
pub(crate) async fn authorize_widening_write<E: GatedWriteError>(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    tenant_id: &str,
) -> Result<(Requester, Mode), E> {
    let requester = authorize_gated_requester::<E>(transaction, submission, tenant_id).await?;
    require_acknowledged::<E>(submission)?;
    let policy = lock_policy_shared::<E>(transaction).await?;
    let mode = widening_mode::<E>(&requester, policy.as_ref())?;
    Ok((requester.requester, mode))
}

/// Runs `steps` in a savepoint of `transaction` (`Transaction::begin`):
/// releases it on `Ok` and rolls it back on `Err`, returning the step's
/// error, not a failed rollback's.
pub(crate) async fn in_savepoint<T, E: From<sqlx::Error>>(
    transaction: &mut Transaction<'_, Postgres>,
    steps: impl AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<T, E>,
) -> Result<T, E> {
    let mut savepoint = transaction.begin().await?;
    match steps(&mut savepoint).await {
        Ok(value) => {
            savepoint.commit().await?;
            Ok(value)
        }
        Err(err) => {
            // The step's error says more than a failed savepoint rollback.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}
