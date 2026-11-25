//! The audited, authorized writes of the workload provisioning objects:
//! tenants, workload and service principals, resource servers, audience
//! tenant assignments, checkers with their tenant sets, and resource
//! actions. See the [module docs](super) for who may perform each write,
//! the steps, the audit event, the lock order and the D3 seams.
//!
//! A create takes an input without an ID ([`TenantCreate`] and the other
//! `*Create` types): the ID comes from the request's generator. An update
//! takes the registry's patch or changes type and the expected revision,
//! but a checker's, which takes [`CheckerChanges`]: a checker's identity is
//! derived from the DER key a create or a rotation gives, never taken from
//! the caller. A `disable_*` write sets only `status` to `disabled` at the
//! expected revision and keeps every other column.

use std::fmt;

use sqlx::{Postgres, Transaction, types::Json};

use super::{AdminRequest, AdminWriteError, Audited};
use crate::identity::canonical_public_identity;
use crate::ids::IdKind;
use crate::operation::{OUTCOME_SUCCESS, Requester};
use crate::persistence::registry::{
    self, AdminRole, AudienceTenantAssignment, AudienceTenantAssignmentChanges, AuditActor,
    AuditEvent, NewAudienceTenantAssignment, NewAuditEvent, NewPrincipal, NewResourceAction,
    NewResourceServer, NewResourceServerChecker, NewTenant, OperatorRequest, OperatorScope,
    Principal, PrincipalKind, PrincipalPatch, Profile, RegistryError, ResourceAction,
    ResourceActionChanges, ResourceServer, ResourceServerChanges, ResourceServerChecker,
    ResourceServerCheckerChanges, Status, Tenant, TenantPatch, append_audit_event,
    authorize_operator_locked,
};
use crate::trust::write::{in_savepoint, require_read_committed};

/// The audit actions of one table (identity-registry IR-059; the names of
/// [`AUDIT_ACTIONS`](crate::persistence::registry::AUDIT_ACTIONS)).
struct Actions {
    create: &'static str,
    update: &'static str,
    enable: &'static str,
    disable: &'static str,
}

impl Actions {
    /// The action of an update from a row of status `before` to one of
    /// status `after`: enable or disable when only the status changed
    /// (`status_only`, every other column equal), update otherwise.
    fn of_update(&self, status_only: bool, before: Status, after: Status) -> &'static str {
        match (status_only && before != after, after) {
            (true, Status::Enabled) => self.enable,
            (true, Status::Disabled) => self.disable,
            (false, _) => self.update,
        }
    }
}

const TENANT: Actions = Actions {
    create: "tenant.create",
    update: "tenant.update",
    enable: "tenant.enable",
    disable: "tenant.disable",
};

const PRINCIPAL: Actions = Actions {
    create: "principal.create",
    update: "principal.update",
    enable: "principal.enable",
    disable: "principal.disable",
};

const RESOURCE_SERVER: Actions = Actions {
    create: "resource_server.create",
    update: "resource_server.update",
    enable: "resource_server.enable",
    disable: "resource_server.disable",
};

const ASSIGNMENT: Actions = Actions {
    create: "audience_tenant_assignment.create",
    update: "audience_tenant_assignment.update",
    enable: "audience_tenant_assignment.enable",
    disable: "audience_tenant_assignment.disable",
};

const CHECKER: Actions = Actions {
    create: "resource_server_checker.create",
    update: "resource_server_checker.update",
    enable: "resource_server_checker.enable",
    disable: "resource_server_checker.disable",
};

const ACTION: Actions = Actions {
    create: "resource_action.create",
    update: "resource_action.update",
    enable: "resource_action.enable",
    disable: "resource_action.disable",
};

/// The input of [`create_tenant`]: a tenant without its ID and secret
/// namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantCreate {
    pub name: String,
    pub status: Status,
}

/// The input of [`create_workload_principal`]: a workload principal without
/// its ID, tenant and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalCreate {
    /// Unique within the tenant among workload principals (IR-021).
    pub name: String,
    pub status: Status,
}

/// The input of [`create_resource_server`]: a resource server without its
/// ID.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceServerCreate {
    pub audience: String,
    pub name: String,
    pub allowed_profiles: Vec<Profile>,
    pub scopes: Vec<String>,
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
}

/// The input of [`create_audience_tenant_assignment`]: an assignment
/// without its ID.
#[derive(Debug, Clone, PartialEq)]
pub struct AssignmentCreate {
    pub resource_server_id: String,
    pub tenant_id: String,
    pub allowed_profiles: Vec<Profile>,
    pub allowed_scopes: Vec<String>,
    pub constraint_versions: Vec<serde_json::Value>,
    pub status: Status,
}

/// The input of [`create_resource_server_checker`]: a checker without its
/// ID and identity. It starts with no tenants; see
/// [`add_resource_server_checker_tenant`].
///
/// `Debug` leaves out the key bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckerCreate {
    pub resource_server_id: String,
    /// The DER `SubjectPublicKeyInfo` of the checker's mTLS key. The write
    /// derives `public_mtls_identity` from it with
    /// [`canonical_public_identity`]; bytes that are not one well-formed
    /// DER `SubjectPublicKeyInfo` are [`AdminWriteError::PublicKey`].
    pub public_key_der: Vec<u8>,
    pub status: Status,
}

impl fmt::Debug for CheckerCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckerCreate")
            .field("resource_server_id", &self.resource_server_id)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// The input of [`update_resource_server_checker`]: a checker's new key, or
/// none, and its status.
///
/// `Debug` leaves out the key bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckerChanges {
    /// The DER `SubjectPublicKeyInfo` of the checker's new mTLS key (a
    /// rotation), from which the write derives the new
    /// `public_mtls_identity` as [`CheckerCreate`] does; `None` keeps the
    /// stored identity (a status-only write).
    pub public_key_der: Option<Vec<u8>>,
    pub status: Status,
}

impl fmt::Debug for CheckerChanges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckerChanges")
            .field("rotates", &self.public_key_der.is_some())
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// The input of [`create_resource_action`]: an action rule without its ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionCreate {
    pub resource_server_id: String,
    pub action_name: String,
    pub required_scopes: Vec<String>,
    pub accepted_profiles: Vec<Profile>,
    pub required_resource_dimensions: Vec<String>,
    pub live_check_required: bool,
    pub status: Status,
}

/// What one write's audit event records besides the request's time, the
/// requester and the generated ID.
struct Change<'a> {
    tenant_id: Option<&'a str>,
    action: &'static str,
    object_id: &'a str,
    previous_revision: Option<i64>,
    new_revision: i64,
}

/// Steps 1 and 2 of an instance write: `READ COMMITTED`, then an instance
/// `security_admin`, locked.
async fn security_admin(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
) -> Result<Requester, AdminWriteError> {
    require_read_committed::<AdminWriteError>(transaction).await?;
    authorize(
        transaction,
        &OperatorRequest {
            public_identity: request.public_identity,
            scope: OperatorScope::Instance,
            role: AdminRole::SecurityAdmin,
        },
    )
    .await
}

/// Steps 1 and 2 of a principal write: `READ COMMITTED`, then a
/// `trust_admin` of exactly `tenant_id`, locked.
async fn trust_admin(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    tenant_id: &str,
) -> Result<Requester, AdminWriteError> {
    require_read_committed::<AdminWriteError>(transaction).await?;
    authorize(
        transaction,
        &OperatorRequest {
            public_identity: request.public_identity,
            scope: OperatorScope::Tenant(tenant_id),
            role: AdminRole::TrustAdmin,
        },
    )
    .await
}

/// The locked lookup of `operator`; every miss is `Unauthorized`.
async fn authorize(
    transaction: &mut Transaction<'_, Postgres>,
    operator: &OperatorRequest<'_>,
) -> Result<Requester, AdminWriteError> {
    match authorize_operator_locked(transaction, operator).await? {
        Some(operator) => Ok(Requester {
            admin_id: operator.admin_id,
            credential_id: operator.credential_id,
        }),
        None => Err(AdminWriteError::Unauthorized),
    }
}

/// Step 3 of an update: the stored row is at the expected revision.
fn check_revision(stored: i64, expected: i64) -> Result<(), AdminWriteError> {
    if stored == expected {
        Ok(())
    } else {
        Err(RegistryError::StaleRevision.into())
    }
}

/// Step 3 of a write in a tenant: the write needs an eligible tenant, one
/// that exists and is enabled, or any tenant when the write is `narrowing`
/// (see the module docs, "Disabled tenants"). A tenant that does not exist
/// is [`RegistryError::NotFound`], and a disabled one for a write that is
/// not `narrowing` is [`AdminWriteError::TenantDisabled`]. The tenant row
/// is locked `FOR SHARE` in the write's savepoint: when the write succeeds
/// the lock is held until the caller's transaction ends, so a tenant enable
/// or disable waits for this write, and this write for it; when the write
/// returns `Err` the savepoint's rollback releases it.
async fn check_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    narrowing: bool,
) -> Result<(), AdminWriteError> {
    let disabled: Option<bool> =
        sqlx::query_scalar("SELECT status <> 'enabled' FROM tenant WHERE id = $1 FOR SHARE")
            .bind(tenant_id)
            .fetch_optional(&mut **transaction)
            .await?;
    match disabled {
        None => Err(RegistryError::NotFound.into()),
        Some(true) if !narrowing => Err(AdminWriteError::TenantDisabled),
        Some(_) => Ok(()),
    }
}

/// The tables [`disable_status`] writes: a closed set, so that it runs one
/// of two fixed statements and never one its caller passes.
#[derive(Clone, Copy)]
enum DisableTable {
    ResourceServer,
    Assignment,
}

/// Step 5 of [`disable_resource_server`] and
/// [`disable_audience_tenant_assignment`]: one statement that sets only
/// `status` to `disabled` and advances `revision` of the row `id` of
/// `table`, as a compare-and-set at `expected_revision`, so the row's other
/// columns are not read back through Rust and written again (a `jsonb`
/// number that an `f64` cannot hold stays as stored). The caller read the
/// row at `expected_revision` first, so a miss is
/// [`RegistryError::StaleRevision`].
///
/// It authorizes nothing and appends no event, so it stays private to this
/// module; the proof test `service/tests/ungated_writes_private.rs` lists
/// it with the module's other helpers and refuses a wider visibility.
async fn disable_status(
    transaction: &mut Transaction<'_, Postgres>,
    table: DisableTable,
    id: &str,
    expected_revision: i64,
) -> Result<(), AdminWriteError> {
    let statement = match table {
        DisableTable::ResourceServer => {
            "UPDATE resource_server SET status = $3, revision = revision + 1 \
             WHERE id = $1 AND revision = $2"
        }
        DisableTable::Assignment => {
            "UPDATE audience_tenant_assignment SET status = $3, revision = revision + 1 \
             WHERE id = $1 AND revision = $2"
        }
    };
    let updated = sqlx::query(statement)
        .bind(id)
        .bind(expected_revision)
        .bind(Status::Disabled.as_str())
        .execute(&mut **transaction)
        .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(RegistryError::StaleRevision.into())
    }
}

/// Whether `changes` keeps every mutable column of the resource server `id`
/// at `expected_revision` but `status`, compared in PostgreSQL as
/// [`same_assignment_ceiling`] compares an assignment's: the `jsonb`
/// columns with `jsonb` equality (`1` and `1.0` are one number, and an
/// object's key order is not kept), so the two writers classify the same
/// `constraint_versions` alike. The row is read without a lock (the
/// compare-and-set after it holds the revision); a row no longer at
/// `expected_revision` is [`RegistryError::StaleRevision`].
async fn same_resource_server(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceServerChanges,
) -> Result<bool, AdminWriteError> {
    let same: Option<bool> = sqlx::query_scalar(
        "SELECT name = $3 AND allowed_profiles = $4 AND scopes = $5 \
         AND constraint_versions = $6 \
         FROM resource_server WHERE id = $1 AND revision = $2",
    )
    .bind(id)
    .bind(expected_revision)
    .bind(&changes.name)
    .bind(Json(&changes.allowed_profiles))
    .bind(Json(&changes.scopes))
    .bind(Json(&changes.constraint_versions))
    .fetch_optional(&mut **transaction)
    .await?;
    same.ok_or(RegistryError::StaleRevision.into())
}

/// Whether `changes` keeps every mutable column of the assignment `id` at
/// `expected_revision` but `status`, compared in PostgreSQL with `jsonb`
/// equality, as the columns are stored: `1` and `1.0` are one number there,
/// though not as a `serde_json::Value`. The row is read without a lock
/// (the compare-and-set after it holds the revision); a row no longer at
/// `expected_revision` is [`RegistryError::StaleRevision`].
async fn same_assignment_ceiling(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    expected_revision: i64,
    changes: &AudienceTenantAssignmentChanges,
) -> Result<bool, AdminWriteError> {
    let same: Option<bool> = sqlx::query_scalar(
        "SELECT allowed_profiles = $3 AND allowed_scopes = $4 AND constraint_versions = $5 \
         FROM audience_tenant_assignment WHERE id = $1 AND revision = $2",
    )
    .bind(id)
    .bind(expected_revision)
    .bind(Json(&changes.allowed_profiles))
    .bind(Json(&changes.allowed_scopes))
    .bind(Json(&changes.constraint_versions))
    .fetch_optional(&mut **transaction)
    .await?;
    same.ok_or(RegistryError::StaleRevision.into())
}

/// Step 6: the write's event, last, with a generated ID.
async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    requester: &Requester,
    change: Change<'_>,
) -> Result<AuditEvent, AdminWriteError> {
    let event = NewAuditEvent {
        id: request.ids.new_id(IdKind::AuditEvent)?,
        tenant_id: change.tenant_id.map(Into::into),
        timestamp: request.now,
        actor: AuditActor::Operator(requester.admin_id.clone()),
        action: change.action.into(),
        object_id: change.object_id.into(),
        previous_revision: change.previous_revision,
        new_revision: Some(change.new_revision),
        outcome: OUTCOME_SUCCESS.into(),
    };
    Ok(append_audit_event(transaction, &event).await?)
}

/// The event of a create of `object_id` at `revision`.
fn created<'a>(
    actions: &Actions,
    tenant_id: Option<&'a str>,
    object_id: &'a str,
    revision: i64,
) -> Change<'a> {
    Change {
        tenant_id,
        action: actions.create,
        object_id,
        previous_revision: None,
        new_revision: revision,
    }
}

/// The event of a write of `object_id` from `expected` to `revision`.
fn changed<'a>(
    action: &'static str,
    tenant_id: Option<&'a str>,
    object_id: &'a str,
    expected: i64,
    revision: i64,
) -> Change<'a> {
    Change {
        tenant_id,
        action,
        object_id,
        previous_revision: Some(expected),
        new_revision: revision,
    }
}

// ---------------------------------------------------------------------------
// Tenants: instance `security_admin`.

/// Creates a tenant with a generated ID ([`IdKind::Tenant`]) and the
/// caller's `secret_namespace`, and appends `tenant.create`.
///
/// `secret_namespace` must be a server-generated opaque value, never one
/// from a request (IR-034): its generator awaits a ruling (see the module
/// docs, "Not done here"). One already used is
/// [`RegistryError::AlreadyExists`]
/// naming `tenant_secret_namespace_key`.
pub async fn create_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    secret_namespace: &str,
    new: &TenantCreate,
) -> Result<Audited<Tenant>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let new = NewTenant {
            id: request.ids.new_id(IdKind::Tenant)?,
            name: new.name.clone(),
            secret_namespace: secret_namespace.into(),
            status: new.status,
        };
        let row = registry::create_tenant(&mut **transaction, &new).await?;
        let change = created(&TENANT, None, &row.id, row.revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// Changes the columns set in `patch` of the tenant `id` at
/// `expected_revision`, and appends `tenant.update`, or `tenant.enable` or
/// `tenant.disable` for a status-only change. An empty patch is the
/// registry's encode error.
pub async fn update_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
    patch: &TenantPatch,
) -> Result<Audited<Tenant>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_tenant(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        // The tenant itself: a disabled tenant takes a status-only write (an
        // enable or a disable) and nothing else. The compare-and-set below
        // holds the status read here.
        let status_only = patch.name.as_ref().is_none_or(|name| *name == before.name);
        if before.status != Status::Enabled && !status_only {
            return Err(AdminWriteError::TenantDisabled);
        }
        let row = registry::update_tenant(&mut **transaction, id, expected_revision, patch).await?;
        let status_only = row.name == before.name;
        let action = TENANT.of_update(status_only, before.status, row.status);
        let change = changed(action, None, &row.id, expected_revision, row.revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// Disables the tenant `id` at `expected_revision` and appends
/// `tenant.disable`.
pub async fn disable_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<Tenant>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let patch = TenantPatch {
            name: None,
            status: Some(Status::Disabled),
        };
        let row =
            registry::update_tenant(&mut **transaction, id, expected_revision, &patch).await?;
        let change = changed(
            TENANT.disable,
            None,
            &row.id,
            expected_revision,
            row.revision,
        );
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

// ---------------------------------------------------------------------------
// Principals: `trust_admin` of the principal's tenant.

/// Creates a workload principal of `tenant_id` with a generated ID
/// ([`IdKind::WorkloadPrincipal`]) and appends `principal.create` in the
/// tenant. A name another workload principal of the tenant has is
/// [`RegistryError::AlreadyExists`]
/// naming `principal_tenant_id_kind_name_key`.
///
/// Only a workload principal: a `trust_admin` creates no human principal
/// (IR-043), and a service principal is created atomically with its
/// service identity, not here (identity-registry section 5.1).
pub async fn create_workload_principal(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    tenant_id: &str,
    new: &PrincipalCreate,
) -> Result<Audited<Principal>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = trust_admin(transaction, request, tenant_id).await?;
        check_tenant(transaction, tenant_id, false).await?;
        let new = NewPrincipal {
            id: request.ids.new_id(IdKind::WorkloadPrincipal)?,
            tenant_id: tenant_id.into(),
            kind: PrincipalKind::Workload,
            name: new.name.clone(),
            status: new.status,
        };
        let row = registry::create_principal(&mut **transaction, &new).await?;
        let change = created(&PRINCIPAL, Some(tenant_id), &row.id, row.revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// Step 3 of a principal write: the principal `id` of `tenant_id`
/// (another tenant's is `NotFound`), of a kind this path changes, at
/// `expected_revision`.
async fn stored_principal(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
) -> Result<Principal, AdminWriteError> {
    let before = registry::get_principal(&mut **transaction, tenant_id, id).await?;
    match before.kind {
        PrincipalKind::Workload | PrincipalKind::Service => {}
        PrincipalKind::Human => return Err(AdminWriteError::PrincipalKindNotAllowed),
    }
    check_revision(before.revision, expected_revision)?;
    Ok(before)
}

/// Changes the columns set in `patch` of the workload or service principal
/// `id` of `tenant_id` at `expected_revision`, and appends
/// `principal.update`, or `principal.enable` or `principal.disable` for a
/// status-only change, in the tenant. A human principal is
/// [`AdminWriteError::PrincipalKindNotAllowed`]; another tenant's principal
/// is `NotFound`.
pub async fn update_principal(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    patch: &PrincipalPatch,
) -> Result<Audited<Principal>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = trust_admin(transaction, request, tenant_id).await?;
        let before = stored_principal(transaction, tenant_id, id, expected_revision).await?;
        let disable_only = patch.status.unwrap_or(before.status) == Status::Disabled
            && patch.name.as_ref().is_none_or(|name| *name == before.name);
        check_tenant(transaction, tenant_id, disable_only).await?;
        let row =
            registry::update_principal(&mut **transaction, tenant_id, id, expected_revision, patch)
                .await?;
        let status_only = row.name == before.name;
        let action = PRINCIPAL.of_update(status_only, before.status, row.status);
        let change = changed(
            action,
            Some(tenant_id),
            &row.id,
            expected_revision,
            row.revision,
        );
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// Disables the workload or service principal `id` of `tenant_id` at
/// `expected_revision` and appends `principal.disable` in the tenant, with
/// the refusals of [`update_principal`].
pub async fn disable_principal(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<Principal>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = trust_admin(transaction, request, tenant_id).await?;
        stored_principal(transaction, tenant_id, id, expected_revision).await?;
        check_tenant(transaction, tenant_id, true).await?;
        let patch = PrincipalPatch {
            name: None,
            status: Some(Status::Disabled),
        };
        let row = registry::update_principal(
            &mut **transaction,
            tenant_id,
            id,
            expected_revision,
            &patch,
        )
        .await?;
        let change = changed(
            PRINCIPAL.disable,
            Some(tenant_id),
            &row.id,
            expected_revision,
            row.revision,
        );
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

// ---------------------------------------------------------------------------
// Resource servers: instance `security_admin`.

/// Creates a resource server with a generated ID ([`IdKind::ResourceServer`])
/// and appends `resource_server.create`. An audience already registered is
/// [`RegistryError::AlreadyExists`].
pub async fn create_resource_server(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    new: &ResourceServerCreate,
) -> Result<Audited<ResourceServer>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let new = NewResourceServer {
            id: request.ids.new_id(IdKind::ResourceServer)?,
            audience: new.audience.clone(),
            name: new.name.clone(),
            allowed_profiles: new.allowed_profiles.clone(),
            scopes: new.scopes.clone(),
            constraint_versions: new.constraint_versions.clone(),
            status: new.status,
        };
        let row = registry::create_resource_server(&mut **transaction, &new).await?;
        let change = created(&RESOURCE_SERVER, None, &row.id, row.revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// The update of the resource server `id` from `before` to `changes`;
/// `status_only` is [`same_resource_server`]'s answer for them.
async fn write_resource_server(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    requester: &Requester,
    (id, expected_revision, before): (&str, i64, &ResourceServer),
    changes: &ResourceServerChanges,
    status_only: bool,
) -> Result<Audited<ResourceServer>, AdminWriteError> {
    let row = registry::update_resource_server(&mut **transaction, id, expected_revision, changes)
        .await?;
    let action = RESOURCE_SERVER.of_update(status_only, before.status, row.status);
    let change = changed(action, None, &row.id, expected_revision, row.revision);
    let event = append_event(transaction, request, requester, change).await?;
    Ok(Audited { row, event })
}

/// Replaces the mutable columns of the resource server `id` at
/// `expected_revision` with `changes`, and appends `resource_server.update`,
/// or `.enable` or `.disable` for a status-only change. Whether the other
/// columns change is decided in PostgreSQL with `jsonb` equality, as for an
/// assignment ([`update_audience_tenant_assignment`]).
pub async fn update_resource_server(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceServerChanges,
) -> Result<Audited<ResourceServer>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_resource_server(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        let status_only = same_resource_server(transaction, id, expected_revision, changes).await?;
        let target = (id, expected_revision, &before);
        write_resource_server(
            transaction,
            request,
            &requester,
            target,
            changes,
            status_only,
        )
        .await
    })
    .await
}

/// Disables the resource server `id` at `expected_revision`, writing only
/// its `status` and `revision`, and appends `resource_server.disable`.
pub async fn disable_resource_server(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<ResourceServer>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_resource_server(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        disable_status(
            transaction,
            DisableTable::ResourceServer,
            id,
            expected_revision,
        )
        .await?;
        let row = registry::get_resource_server(&mut **transaction, id).await?;
        let change = changed(
            RESOURCE_SERVER.disable,
            None,
            &row.id,
            expected_revision,
            row.revision,
        );
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

// ---------------------------------------------------------------------------
// Audience tenant assignments: instance `security_admin`.

/// Creates an audience assignment of a tenant with a generated ID
/// ([`IdKind::AudienceAssignment`]) and appends
/// `audience_tenant_assignment.create`. The tenant must exist
/// ([`RegistryError::NotFound`] otherwise) and be enabled
/// ([`AdminWriteError::TenantDisabled`] otherwise), checked under its lock
/// before any ID is generated.
pub async fn create_audience_tenant_assignment(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    new: &AssignmentCreate,
) -> Result<Audited<AudienceTenantAssignment>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        check_tenant(transaction, &new.tenant_id, false).await?;
        let new = NewAudienceTenantAssignment {
            id: request.ids.new_id(IdKind::AudienceAssignment)?,
            resource_server_id: new.resource_server_id.clone(),
            tenant_id: new.tenant_id.clone(),
            allowed_profiles: new.allowed_profiles.clone(),
            allowed_scopes: new.allowed_scopes.clone(),
            constraint_versions: new.constraint_versions.clone(),
            status: new.status,
        };
        let row = registry::create_audience_tenant_assignment(&mut **transaction, &new).await?;
        let change = created(&ASSIGNMENT, None, &row.id, row.revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// The update of the assignment `id` from `before` to `changes`;
/// `status_only` is [`same_assignment_ceiling`]'s answer for them.
async fn write_assignment(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    requester: &Requester,
    (id, expected_revision, before): (&str, i64, &AudienceTenantAssignment),
    changes: &AudienceTenantAssignmentChanges,
    status_only: bool,
) -> Result<Audited<AudienceTenantAssignment>, AdminWriteError> {
    let row = registry::update_audience_tenant_assignment(
        &mut **transaction,
        id,
        expected_revision,
        changes,
    )
    .await?;
    let action = ASSIGNMENT.of_update(status_only, before.status, row.status);
    let change = changed(action, None, &row.id, expected_revision, row.revision);
    let event = append_event(transaction, request, requester, change).await?;
    Ok(Audited { row, event })
}

/// Replaces the mutable columns of the assignment `id` at
/// `expected_revision` with `changes`, and appends
/// `audience_tenant_assignment.update`, or `.enable` or `.disable` for a
/// status-only change. Whether the other columns change is decided in
/// PostgreSQL with `jsonb` equality, the stored columns' own (`1` and `1.0`
/// are one number), for the tenant check and the event's action alike. Enabling revalidates nothing and disabling
/// strands the rows that reference it (the registry writer's rules).
pub async fn update_audience_tenant_assignment(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
    changes: &AudienceTenantAssignmentChanges,
) -> Result<Audited<AudienceTenantAssignment>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_audience_tenant_assignment(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        let status_only =
            same_assignment_ceiling(transaction, id, expected_revision, changes).await?;
        let disable_only = status_only && changes.status == Status::Disabled;
        check_tenant(transaction, &before.tenant_id, disable_only).await?;
        let target = (id, expected_revision, &before);
        write_assignment(
            transaction,
            request,
            &requester,
            target,
            changes,
            status_only,
        )
        .await
    })
    .await
}

/// Disables the assignment `id` at `expected_revision`, writing only its
/// `status` and `revision`, and appends `audience_tenant_assignment.disable`.
pub async fn disable_audience_tenant_assignment(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<AudienceTenantAssignment>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_audience_tenant_assignment(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        check_tenant(transaction, &before.tenant_id, true).await?;
        disable_status(transaction, DisableTable::Assignment, id, expected_revision).await?;
        let row = registry::get_audience_tenant_assignment(&mut **transaction, id).await?;
        let change = changed(
            ASSIGNMENT.disable,
            None,
            &row.id,
            expected_revision,
            row.revision,
        );
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

// ---------------------------------------------------------------------------
// Checkers and their tenant sets: instance `security_admin`.

/// Creates a checker, with no tenants, with a generated ID
/// ([`IdKind::Checker`]) and the canonical public identity of
/// `new.public_key_der` ([`canonical_public_identity`]), and appends
/// `resource_server_checker.create`. Key bytes that are not one well-formed
/// DER `SubjectPublicKeyInfo` are [`AdminWriteError::PublicKey`], after the
/// authorization and before any ID is generated; an identity another
/// checker has is [`RegistryError::AlreadyExists`].
///
/// Interim: the per-algorithm form rule of [`crate::identity`] ("A hard
/// requirement on the callers") is not enforced yet, so this write must not
/// be exposed on any HTTP surface until it is (see the module docs, "Not
/// done here").
pub async fn create_resource_server_checker(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    new: &CheckerCreate,
) -> Result<Audited<ResourceServerChecker>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let public_mtls_identity = canonical_public_identity(&new.public_key_der)?;
        let new = NewResourceServerChecker {
            id: request.ids.new_id(IdKind::Checker)?,
            resource_server_id: new.resource_server_id.clone(),
            public_mtls_identity,
            status: new.status,
        };
        let row = registry::create_resource_server_checker(&mut **transaction, &new).await?;
        let change = created(&CHECKER, None, &row.id, row.revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// The update of the checker `id` from `before` to `changes`.
async fn write_checker(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    requester: &Requester,
    (id, expected_revision, before): (&str, i64, &ResourceServerChecker),
    changes: &ResourceServerCheckerChanges,
    disable: bool,
) -> Result<Audited<ResourceServerChecker>, AdminWriteError> {
    let row = registry::update_resource_server_checker(
        &mut **transaction,
        id,
        expected_revision,
        changes,
    )
    .await?;
    let action = if disable {
        CHECKER.disable
    } else {
        // Compared in Rust, and needs no `jsonb` comparison in PostgreSQL as
        // a resource server's and an assignment's do: a checker has no
        // `jsonb` column (text columns, and a tenant set of text rows).
        let unchanged = ResourceServerChecker {
            status: row.status,
            revision: row.revision,
            ..before.clone()
        };
        CHECKER.of_update(unchanged == row, before.status, row.status)
    };
    let change = changed(action, None, &row.id, expected_revision, row.revision);
    let event = append_event(transaction, request, requester, change).await?;
    Ok(Audited { row, event })
}

/// Sets the status of the checker `id` at `expected_revision` and, for a
/// rotation, its identity to the canonical public identity of
/// `changes.public_key_der`, and appends `resource_server_checker.update`,
/// or `.enable` or `.disable` for a status-only change (no key, or a key of
/// the stored identity). Without a key the stored identity is kept. Key
/// bytes that are not one well-formed DER `SubjectPublicKeyInfo` are
/// [`AdminWriteError::PublicKey`], after the authorization and before the
/// stored row is read. Its tenant set is unchanged.
///
/// Interim, as [`create_resource_server_checker`]: not to be exposed on any
/// HTTP surface until the per-algorithm form rule lands.
pub async fn update_resource_server_checker(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
    changes: &CheckerChanges,
) -> Result<Audited<ResourceServerChecker>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let rotated = (changes.public_key_der.as_deref())
            .map(canonical_public_identity)
            .transpose()?;
        let before = registry::get_resource_server_checker(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        let changes = ResourceServerCheckerChanges {
            public_mtls_identity: rotated.unwrap_or_else(|| before.public_mtls_identity.clone()),
            status: changes.status,
        };
        let target = (id, expected_revision, &before);
        write_checker(transaction, request, &requester, target, &changes, false).await
    })
    .await
}

/// Disables the checker `id` at `expected_revision`, keeping its identity
/// and tenant set, and appends `resource_server_checker.disable`.
pub async fn disable_resource_server_checker(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<ResourceServerChecker>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_resource_server_checker(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        let changes = ResourceServerCheckerChanges {
            public_mtls_identity: before.public_mtls_identity.clone(),
            status: Status::Disabled,
        };
        let target = (id, expected_revision, &before);
        write_checker(transaction, request, &requester, target, &changes, true).await
    })
    .await
}

/// Adds `tenant_id` to the tenant set of the checker `checker_id` at
/// `expected_revision` and appends `resource_server_checker.update`. The
/// tenant must exist ([`RegistryError::NotFound`] otherwise) and be enabled
/// ([`AdminWriteError::TenantDisabled`] otherwise), and needs an assignment
/// of the checker's resource server, whatever its status (the registry
/// writer's rules).
pub async fn add_resource_server_checker_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    checker_id: &str,
    expected_revision: i64,
    tenant_id: &str,
) -> Result<Audited<ResourceServerChecker>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        check_tenant(transaction, tenant_id, false).await?;
        let revision = registry::add_resource_server_checker_tenant(
            &mut **transaction,
            checker_id,
            expected_revision,
            tenant_id,
        )
        .await?;
        let row = registry::get_resource_server_checker(&mut **transaction, checker_id).await?;
        let change = changed(CHECKER.update, None, &row.id, expected_revision, revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// Removes `tenant_id` from the tenant set of the checker `checker_id` at
/// `expected_revision` and appends `resource_server_checker.update`. A
/// tenant not in the set, or not at all, is `NotFound`. The removal only
/// narrows, so it applies whatever the tenant's status; it still locks the
/// tenant row `FOR SHARE`, as the addition does, so a tenant status write
/// and the change of its checkers wait for each other.
pub async fn remove_resource_server_checker_tenant(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    checker_id: &str,
    expected_revision: i64,
    tenant_id: &str,
) -> Result<Audited<ResourceServerChecker>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        check_tenant(transaction, tenant_id, true).await?;
        let revision = registry::remove_resource_server_checker_tenant(
            &mut **transaction,
            checker_id,
            expected_revision,
            tenant_id,
        )
        .await?;
        let row = registry::get_resource_server_checker(&mut **transaction, checker_id).await?;
        let change = changed(CHECKER.update, None, &row.id, expected_revision, revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

// ---------------------------------------------------------------------------
// Resource actions: instance `security_admin`.

/// Creates an action rule with a generated ID ([`IdKind::ResourceAction`])
/// and appends `resource_action.create`.
pub async fn create_resource_action(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    new: &ActionCreate,
) -> Result<Audited<ResourceAction>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let new = NewResourceAction {
            id: request.ids.new_id(IdKind::ResourceAction)?,
            resource_server_id: new.resource_server_id.clone(),
            action_name: new.action_name.clone(),
            required_scopes: new.required_scopes.clone(),
            accepted_profiles: new.accepted_profiles.clone(),
            required_resource_dimensions: new.required_resource_dimensions.clone(),
            live_check_required: new.live_check_required,
            status: new.status,
        };
        let row = registry::create_resource_action(&mut **transaction, &new).await?;
        let change = created(&ACTION, None, &row.id, row.revision);
        let event = append_event(transaction, request, &requester, change).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// The update of the action rule `id` from `before` to `changes`.
async fn write_action(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    requester: &Requester,
    (id, expected_revision, before): (&str, i64, &ResourceAction),
    changes: &ResourceActionChanges,
    disable: bool,
) -> Result<Audited<ResourceAction>, AdminWriteError> {
    let row = registry::update_resource_action(&mut **transaction, id, expected_revision, changes)
        .await?;
    let action = if disable {
        ACTION.disable
    } else {
        // Compared in Rust, and needs no `jsonb` comparison in PostgreSQL as
        // a resource server's and an assignment's do: an action's `jsonb`
        // columns hold only strings (their domains refuse any other element),
        // no number or object, so `jsonb` equality and `Vec` equality agree.
        let unchanged = ResourceAction {
            status: row.status,
            revision: row.revision,
            ..before.clone()
        };
        ACTION.of_update(unchanged == row, before.status, row.status)
    };
    let change = changed(action, None, &row.id, expected_revision, row.revision);
    let event = append_event(transaction, request, requester, change).await?;
    Ok(Audited { row, event })
}

/// Replaces the mutable columns of the action rule `id` at
/// `expected_revision` with `changes`, and appends
/// `resource_action.update`, or `.enable` or `.disable` for a status-only
/// change.
pub async fn update_resource_action(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
    changes: &ResourceActionChanges,
) -> Result<Audited<ResourceAction>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_resource_action(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        let target = (id, expected_revision, &before);
        write_action(transaction, request, &requester, target, changes, false).await
    })
    .await
}

/// Disables the action rule `id` at `expected_revision`, keeping its other
/// columns, and appends `resource_action.disable`.
pub async fn disable_resource_action(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<ResourceAction>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let before = registry::get_resource_action(&mut **transaction, id).await?;
        check_revision(before.revision, expected_revision)?;
        let changes = ResourceActionChanges {
            required_scopes: before.required_scopes.clone(),
            accepted_profiles: before.accepted_profiles.clone(),
            required_resource_dimensions: before.required_resource_dimensions.clone(),
            live_check_required: before.live_check_required,
            status: Status::Disabled,
        };
        let target = (id, expected_revision, &before);
        write_action(transaction, request, &requester, target, &changes, true).await
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::registry::is_audit_action;

    #[test]
    fn every_action_is_in_the_table() {
        for actions in [
            &TENANT,
            &PRINCIPAL,
            &RESOURCE_SERVER,
            &ASSIGNMENT,
            &CHECKER,
            &ACTION,
        ] {
            for action in [
                actions.create,
                actions.update,
                actions.enable,
                actions.disable,
            ] {
                assert!(is_audit_action(action), "{action}");
            }
        }
    }

    #[test]
    fn an_update_is_enable_or_disable_only_for_a_status_only_change() {
        use Status::{Disabled, Enabled};
        assert_eq!(TENANT.of_update(true, Enabled, Disabled), "tenant.disable");
        assert_eq!(TENANT.of_update(true, Disabled, Enabled), "tenant.enable");
        assert_eq!(TENANT.of_update(true, Enabled, Enabled), "tenant.update");
        assert_eq!(TENANT.of_update(true, Disabled, Disabled), "tenant.update");
        assert_eq!(TENANT.of_update(false, Enabled, Disabled), "tenant.update");
        assert_eq!(TENANT.of_update(false, Disabled, Enabled), "tenant.update");
    }

    #[test]
    fn a_stale_revision_is_the_registrys() {
        assert!(check_revision(3, 3).is_ok());
        assert!(matches!(
            check_revision(4, 3),
            Err(AdminWriteError::Registry(RegistryError::StaleRevision))
        ));
    }
}
