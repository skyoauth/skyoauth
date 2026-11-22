//! The steps the trust keyset version writes ([`super::keyset`]) and the
//! trust source writes ([`super::source`]) share: the `READ COMMITTED`
//! check of step 0, the `trust_admin` authorization of step 1 and the
//! savepoint each write runs its steps in. Each module's docs state the
//! rules; this module only holds the code once. It is crate-private and
//! adds nothing to the public API.

use sqlx::{Connection, Postgres, Transaction};

use crate::persistence::registry::{
    AdminRole, OperatorRequest, OperatorScope, RegistryError, authorize_operator_locked,
};

/// Step 0: the transaction's isolation level.
const TRANSACTION_ISOLATION: &str = "SELECT current_setting('transaction_isolation')";

/// The one isolation level the writes run at, as `transaction_isolation`
/// names it.
const READ_COMMITTED: &str = "read committed";

/// The error of a trust write, with the two refusals the shared steps
/// return. Each is a unit variant of fixed text, naming no input.
pub(super) trait WriteError: From<sqlx::Error> + From<RegistryError> {
    /// Step 0's refusal: the transaction does not run at `READ COMMITTED`.
    const UNSUPPORTED_ISOLATION: Self;
    /// Step 1's refusal: the operator is not a `trust_admin` of the tenant.
    const UNAUTHORIZED: Self;
}

/// Step 0: `READ COMMITTED` only.
pub(super) async fn require_read_committed<E: WriteError>(
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

/// Step 1: a `trust_admin` of `tenant_id`, locked until the transaction
/// ends; the operator's ID.
pub(super) async fn authorize_trust_admin<E: WriteError>(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
) -> Result<String, E> {
    let request = OperatorRequest {
        public_identity,
        scope: OperatorScope::Tenant(tenant_id),
        role: AdminRole::TrustAdmin,
    };
    match authorize_operator_locked(transaction, &request).await? {
        Some(operator) => Ok(operator.admin_id),
        None => Err(E::UNAUTHORIZED),
    }
}

/// Runs `steps` in a savepoint of `transaction` (`Transaction::begin`):
/// releases it on `Ok` and rolls it back on `Err`, returning the step's
/// error, not a failed rollback's.
pub(super) async fn in_savepoint<T, E: From<sqlx::Error>>(
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
