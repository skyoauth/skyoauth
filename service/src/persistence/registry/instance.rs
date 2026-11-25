//! The instance security policy and the egress allowlist (`0002`). The
//! policy row is read only here: its writes carry service rules this module
//! does not hold (the startup mirror owns `single_actor_mode` and the sink
//! fields; IR-052..IR-054), so they come with the operator and policy work
//! (inferred). The egress allowlist has two bare writers,
//! [`create_egress_allowlist_entry`] and [`update_egress_allowlist_entry`],
//! crate-private (`pub(crate)`): they authorize no one, append no audit
//! event, check no destination syntax and know no second-approver rule, so
//! only the audited, authorized writes of
//! [`crate::admin::egress`] call them (tests reach them through
//! `registry::test_support`).

use sqlx::PgExecutor;

use super::{
    EgressAllowlistEntry, InstanceSecurityPolicy, NewEgressAllowlistEntry, Page, RegistryError,
    Status, compare_and_set, list_page, micros, updated,
};

/// The columns of the instance security policy row, as
/// [`InstanceSecurityPolicy`] reads them; shared with the row locks of
/// [`lock_instance_security_policy`](super::lock_instance_security_policy)
/// and
/// [`lock_instance_security_policy_shared`](super::lock_instance_security_policy_shared).
macro_rules! policy_columns {
    () => {
        concat!(
            "instance_id, widening_second_approver, single_actor_mode, \
             audit_sink_config_digest, ",
            micros!("audit_sink_validated_at"),
            ", revision"
        )
    };
}
pub(super) use policy_columns;

macro_rules! egress_columns {
    () => {
        "id, purpose, exact_destination, status, revision"
    };
}

/// Reads the instance security policy, the table's single row.
/// [`RegistryError::NotFound`] before bootstrap has inserted it.
pub async fn get_instance_security_policy<'e>(
    executor: impl PgExecutor<'e>,
) -> Result<InstanceSecurityPolicy, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        policy_columns!(),
        " FROM instance_security_policy"
    ))
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Reads an egress allowlist entry by ID.
pub async fn get_egress_allowlist_entry<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<EgressAllowlistEntry, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        egress_columns!(),
        " FROM egress_allowlist_entry WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Lists egress allowlist entries by ID.
pub async fn list_egress_allowlist_entries<'e>(
    executor: impl PgExecutor<'e>,
    page: Page<'_>,
) -> Result<Vec<EgressAllowlistEntry>, RegistryError> {
    Ok(
        sqlx::query_as(list_page!("egress_allowlist_entry", egress_columns!()))
            .bind(page.after_id())
            .bind(i64::from(page.limit()))
            .fetch_all(executor)
            .await?,
    )
}

/// Creates an egress allowlist entry with the caller's ID at revision 1.
/// A `(purpose, exact_destination)` pair another entry has, enabled or
/// not, is [`RegistryError::AlreadyExists`] naming
/// `egress_allowlist_entry_purpose_exact_destination_key`; the `0002`
/// checks refuse an empty destination, one with whitespace or a control
/// character and one over 2048 bytes (`Invariant` of kind `Check`).
///
/// **The unchecked floor, crate-private.** Nothing else is checked: no
/// authorization, no audit event, no destination syntax (the `0002`
/// comment leaves the URL rule to the service) and no second-approver rule
/// (IR-052, IR-152: adding an entry is widening-class). Within the crate
/// only [`crate::admin::egress::create_egress_entry`] calls it, after its
/// own checks and with the audit event.
pub(crate) async fn create_egress_allowlist_entry<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewEgressAllowlistEntry,
) -> Result<EgressAllowlistEntry, RegistryError> {
    Ok(sqlx::query_as(concat!(
        "INSERT INTO egress_allowlist_entry (id, purpose, exact_destination, status) \
         VALUES ($1, $2, $3, $4) RETURNING ",
        egress_columns!()
    ))
    .bind(&new.id)
    .bind(new.purpose.as_str())
    .bind(&new.exact_destination)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Sets the `status` of the egress allowlist entry `id` at
/// `expected_revision` and advances its revision by one; `purpose` and
/// `exact_destination` are immutable (`0002`), so nothing else changes.
/// Setting the status it already has still advances the revision. A
/// missing entry is [`RegistryError::NotFound`], one at another revision
/// [`RegistryError::StaleRevision`].
///
/// The `UPDATE` takes the entry row `FOR NO KEY UPDATE` until the
/// transaction ends, which conflicts with the `FOR SHARE` that a trust
/// source write takes on the entry it checks ([`crate::trust::source`],
/// the `0011` guard): either waits for the other. It locks no other row.
///
/// **The unchecked floor, crate-private**, like
/// [`create_egress_allowlist_entry`]: re-enabling is widening-class
/// (IR-152), and only [`crate::admin::egress::enable_egress_entry`] and
/// [`crate::admin::egress::disable_egress_entry`] call it, after the
/// authorization and with the audit event.
pub(crate) async fn update_egress_allowlist_entry<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    status: Status,
) -> Result<EgressAllowlistEntry, RegistryError> {
    let row = sqlx::query(compare_and_set!(
        "egress_allowlist_entry",
        "status = $3",
        egress_columns!()
    ))
    .bind(id)
    .bind(expected_revision)
    .bind(status.as_str())
    .fetch_one(executor)
    .await?;
    updated(&row)
}
