//! The scope ceilings of one exchange: a grant's scopes and defaults, the
//! requested audience's resource server and the tenant's assignment for it,
//! and the target service of a delegation, loaded in one statement (IR-062,
//! IR-063, IR-083; ADR-015 items 7 and 9; errors-retry ERR-024; design
//! section 5.7; T12.8; groundwork for T21.5; conformance A26).
//! [`resolve_scopes`](crate::policy::resolve_scopes) applies them.
//!
//! [`load_scope_ceilings`] finds the grant by tenant and ID, and the
//! resource server by its exact `audience`. The resource server must be in
//! the grant's audience set (`service_grant_resource_server`) and assigned
//! to the grant's tenant (`audience_tenant_assignment`). A grant with a
//! target service also loads that service identity of the same tenant, and
//! the resource server must be in the target service's audience set too
//! (`service_identity_resource_server`; IR-083: "in the target service's
//! set for delegation"). The `0004` foreign keys already keep a listed
//! audience assigned to the grant's tenant, the target in the grant's
//! tenant and a service's audience row in the service's tenant; the
//! statement checks all three again rather than rely on them.
//!
//! When the grant does not exist in the tenant, or the audience does not
//! exist, is not assigned to the tenant, is not in the grant's set or, for
//! a grant with a target service, is not in that service's set, the result
//! is `None`: one value with no detail, so the caller can map all of them
//! to the same `invalid_target` (ERR-024 (3); ADR-015 item 9.4). The
//! registry does no such mapping.
//!
//! # Not done here
//!
//! - No status is checked: a chain with a disabled grant, resource server,
//!   assignment or target service is still `Some` (the dormant
//!   impersonation grant, always disabled, too). Their IDs, statuses and
//!   revisions are returned so that step 5 (design section 5.7) can check
//!   them and record the revisions; those status checks belong to T12.6,
//!   T12.7 and T14.2, wired into the exchange in M2 (T21.4, T21.5).
//!   [`LoadedCeilings::all_enabled`] says whether every loaded record is
//!   enabled, so a caller cannot leave one out; it is not all of step 5.
//! - The tenant's status and revision are not loaded; step 5 needs them
//!   too (design section 5.7), as well as the grant's `activation_state`
//!   and `valid_until` and the actor's status, none of which is loaded.
//! - No OAuth error code or ordering (ERR-024; M2).
//! - Resource constraint ceilings (IR-123) and TTL caps are not loaded.

use sqlx::{PgExecutor, Row, postgres::PgRow};

use crate::policy::ScopeCeilings;

use super::{
    GrantMode, RegistryError, Status,
    model::{json, optional_json, text},
};

/// The statement. `$1` is the tenant, `$2` the grant and `$3` the
/// audience. It returns at most one row: the grant is found by its key,
/// its audience row by `(grant, resource server)`, the resource server by
/// its unique audience, the assignment by `(tenant, resource server)`, the
/// service by its key and its audience row by `(service, resource server)`.
/// A grant whose target service is missing (which
/// the `0004` foreign key prevents), or whose target service does not list
/// the resource server (IR-083), gives no row.
const LOAD_SCOPE_CEILINGS: &str = "\
    SELECT g.id AS grant_id, g.mode AS grant_mode, g.status AS grant_status, \
           g.revision AS grant_revision, g.scopes AS grant_scopes, \
           g.default_scopes AS grant_default_scopes, \
           rs.id AS resource_server_id, rs.status AS resource_server_status, \
           rs.revision AS resource_server_revision, rs.scopes AS resource_server_scopes, \
           a.id AS assignment_id, a.status AS assignment_status, \
           a.revision AS assignment_revision, a.allowed_scopes AS assignment_scopes, \
           s.id AS service_id, s.status AS service_status, \
           s.revision AS service_revision, s.max_scopes AS service_scopes \
      FROM service_grant g \
      JOIN service_grant_resource_server gr \
        ON gr.grant_id = g.id AND gr.tenant_id = g.tenant_id \
      JOIN resource_server rs ON rs.id = gr.resource_server_id \
      JOIN audience_tenant_assignment a \
        ON a.tenant_id = g.tenant_id AND a.resource_server_id = rs.id \
      LEFT JOIN service_identity s \
        ON s.tenant_id = g.tenant_id AND s.id = g.target_service_id \
     WHERE g.tenant_id = $1 AND g.id = $2 AND rs.audience = $3 \
       AND (g.target_service_id IS NULL \
            OR (s.id IS NOT NULL \
                AND EXISTS (SELECT FROM service_identity_resource_server sr \
                             WHERE sr.tenant_id = g.tenant_id AND sr.service_id = s.id \
                               AND sr.resource_server_id = rs.id)))";

/// The ID, status, revision and scope list of one ceiling's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingRecord {
    pub id: String,
    /// Not checked by the loader.
    pub status: Status,
    pub revision: i64,
    /// The record's scope ceiling: `scopes`, `allowed_scopes` or
    /// `max_scopes`.
    pub scopes: Vec<String>,
}

/// The ceilings [`load_scope_ceilings`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedCeilings {
    /// The grant, with its `scopes`.
    pub grant: CeilingRecord,
    pub grant_mode: GrantMode,
    /// The grant's `default_scopes`.
    pub grant_default_scopes: Option<Vec<String>>,
    /// The resource server of the requested audience, with its `scopes`.
    pub resource_server: CeilingRecord,
    /// The tenant's assignment of that resource server, with its
    /// `allowed_scopes`.
    pub assignment: CeilingRecord,
    /// The grant's target service identity, with its `max_scopes`: `Some`
    /// exactly for a grant with a target (delegation; impersonation, which
    /// is stored only disabled, too).
    pub target_service: Option<CeilingRecord>,
}

impl LoadedCeilings {
    /// The ceilings for [`resolve_scopes`](crate::policy::resolve_scopes).
    /// The target service's `max_scopes` is a ceiling exactly when the grant
    /// has a target (IR-062; inferred for impersonation, which v0.1 never
    /// issues).
    pub fn scope_ceilings(&self) -> ScopeCeilings {
        ScopeCeilings {
            resource_server: self.resource_server.scopes.clone(),
            assignment: self.assignment.scopes.clone(),
            grant: self.grant.scopes.clone(),
            target_service: self
                .target_service
                .as_ref()
                .map(|service| service.scopes.clone()),
        }
    }

    /// The grant's `default_scopes`, for
    /// [`resolve_scopes`](crate::policy::resolve_scopes).
    pub fn default_scopes(&self) -> Option<&[String]> {
        self.grant_default_scopes.as_deref()
    }

    /// Whether the grant, the resource server, the assignment and, for a
    /// grant with a target, the target service were all enabled when
    /// loaded. The loader returns disabled records too (see the module
    /// docs); this is the status part of step 5 for the records it loads,
    /// not all of step 5: the tenant, the actor and the grant's
    /// `activation_state` and `valid_until` are not loaded.
    pub fn all_enabled(&self) -> bool {
        self.grant.status == Status::Enabled
            && self.resource_server.status == Status::Enabled
            && self.assignment.status == Status::Enabled
            && self
                .target_service
                .as_ref()
                .is_none_or(|service| service.status == Status::Enabled)
    }
}

fn record(row: &PgRow, prefix: &str) -> Result<CeilingRecord, sqlx::Error> {
    Ok(CeilingRecord {
        id: row.try_get(format!("{prefix}_id").as_str())?,
        status: text(row, &format!("{prefix}_status"))?,
        revision: row.try_get(format!("{prefix}_revision").as_str())?,
        scopes: json(row, &format!("{prefix}_scopes"))?,
    })
}

/// Loads the scope ceilings of grant `grant_id` of `tenant_id` for the
/// resource server of `audience`, in one statement (see the module docs).
/// `None` when the grant, the audience, its assignment to the tenant, its
/// place in the grant's audience set or, for a grant with a target service,
/// its place in that service's audience set is missing. Disabled records
/// are returned; see [`LoadedCeilings::all_enabled`].
pub async fn load_scope_ceilings<'e>(
    executor: impl PgExecutor<'e>,
    tenant_id: &str,
    grant_id: &str,
    audience: &str,
) -> Result<Option<LoadedCeilings>, RegistryError> {
    let Some(row) = sqlx::query(LOAD_SCOPE_CEILINGS)
        .bind(tenant_id)
        .bind(grant_id)
        .bind(audience)
        .fetch_optional(executor)
        .await?
    else {
        return Ok(None);
    };
    let target_service = match row.try_get::<Option<&str>, _>("service_id")? {
        Some(_) => Some(record(&row, "service")?),
        None => None,
    };
    Ok(Some(LoadedCeilings {
        grant: record(&row, "grant")?,
        grant_mode: text(&row, "grant_mode")?,
        grant_default_scopes: optional_json(&row, "grant_default_scopes")?,
        resource_server: record(&row, "resource_server")?,
        assignment: record(&row, "assignment")?,
        target_service,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled(id: &str) -> CeilingRecord {
        CeilingRecord {
            id: id.to_owned(),
            status: Status::Enabled,
            revision: 1,
            scopes: vec!["read".to_owned()],
        }
    }

    fn loaded(target_service: Option<CeilingRecord>) -> LoadedCeilings {
        LoadedCeilings {
            grant: enabled("grt_1"),
            grant_mode: if target_service.is_some() {
                GrantMode::Delegation
            } else {
                GrantMode::Direct
            },
            grant_default_scopes: None,
            resource_server: enabled("rs_1"),
            assignment: enabled("ata_1"),
            target_service,
        }
    }

    #[test]
    fn all_enabled_needs_every_loaded_record_enabled() {
        assert!(loaded(None).all_enabled());
        assert!(loaded(Some(enabled("svc_1"))).all_enabled());
        let disable: [fn(&mut LoadedCeilings) -> &mut CeilingRecord; 4] = [
            |l| &mut l.grant,
            |l| &mut l.resource_server,
            |l| &mut l.assignment,
            |l| l.target_service.as_mut().unwrap(),
        ];
        for (index, record) in disable.into_iter().enumerate() {
            let mut ceilings = loaded(Some(enabled("svc_1")));
            record(&mut ceilings).status = Status::Disabled;
            assert!(!ceilings.all_enabled(), "record {index}");
        }
    }
}
