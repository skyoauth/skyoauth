//! The instance security policy and the egress allowlist (`0002`), read
//! only. Their writes carry service rules this module does not hold (the
//! startup mirror owns `single_actor_mode` and the sink fields, and adding
//! or re-enabling an egress entry needs a second approver; IR-052..IR-054),
//! so they come with the operator and policy work (inferred).

use sqlx::PgExecutor;

use super::{EgressAllowlistEntry, InstanceSecurityPolicy, Page, RegistryError, list_page};

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
    sqlx::query_as(
        "SELECT instance_id, widening_second_approver, single_actor_mode, \
         audit_sink_config_digest, \
         (extract(epoch FROM audit_sink_validated_at) * 1000000)::bigint \
         AS audit_sink_validated_at_us, revision FROM instance_security_policy",
    )
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
