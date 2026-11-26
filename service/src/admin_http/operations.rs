//! The operation reads of D4: one operation by ID and one page of the open
//! ones, on the instance path and on a tenant's (see the module docs of
//! [`crate::admin_http`], "Routes").

use axum::{
    Json,
    extract::{
        Path, Query, State,
        rejection::{PathRejection, QueryRejection},
    },
};
use serde::{Deserialize, Serialize};

use super::{AdminHttpError, AdminPeer, AdminState, error::from_operation_read};
use crate::jwk::base64url;
use crate::operation::{
    ApprovalScope, OperationReadError, OperationRecord, list_operations, read_operation,
};
use crate::persistence::registry::Page;

/// The page size of a list that names no `limit` (inferred).
pub const DEFAULT_PAGE_SIZE: u32 = 100;

/// One operation on the wire: the digest envelope (D29) with the stored
/// digest, the outcome and the row's revision.
#[derive(Debug, Serialize)]
pub(super) struct OperationBody {
    id: String,
    tenant_id: Option<String>,
    actor_id: String,
    kind: &'static str,
    /// Unpadded base64url of the 32 bytes (inferred, as the
    /// second-approver proposal, section 2).
    request_digest: String,
    expected_revision: i64,
    /// Whole microseconds since the Unix epoch: the preimage's integer.
    expires_at: i64,
    /// The plan's canonical text, verbatim: a JSON string, not an object.
    plan: String,
    outcome: String,
    revision: i64,
}

impl From<OperationRecord> for OperationBody {
    fn from(record: OperationRecord) -> Self {
        Self {
            request_digest: base64url::encode(record.request_digest.as_bytes()),
            kind: record.kind.as_str(),
            id: record.id,
            tenant_id: record.tenant_id,
            actor_id: record.actor_id,
            expected_revision: record.expected_revision,
            expires_at: record.expires_at_us,
            plan: record.plan,
            outcome: record.outcome,
            revision: record.revision,
        }
    }
}

/// One page of a list: the operations, and the cursor of the next page
/// (the last ID) when this one is full, else `null`.
#[derive(Debug, Serialize)]
pub(super) struct PageBody {
    operations: Vec<OperationBody>,
    next: Option<String>,
}

/// The query of a list: `limit` (clamped to `1..=500`, [`Page`]) and the
/// cursor `after`, the last ID of the previous page. Any other parameter,
/// a repeated one, a `limit` that is not a `u32` and a cursor with a NUL
/// character are 400 `invalid_request`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListQuery {
    limit: Option<u32>,
    after: Option<String>,
}

/// The query, or 400 `invalid_request`.
fn list_query(
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<ListQuery, AdminHttpError> {
    let Ok(Query(query)) = query else {
        return Err(AdminHttpError::INVALID_REQUEST);
    };
    if query
        .after
        .as_deref()
        .is_some_and(|after| after.contains('\0'))
    {
        return Err(AdminHttpError::INVALID_REQUEST);
    }
    Ok(query)
}

/// The response of a read error, logged first when it is a server-side
/// one (the error's `Debug`, which holds no value of the request).
fn failed(err: &OperationReadError) -> AdminHttpError {
    let mapped = from_operation_read(err);
    if mapped.status().is_server_error() {
        tracing::warn!(error = ?err, "admin operation read failed");
    }
    mapped
}

async fn read(
    state: &AdminState,
    peer: &AdminPeer,
    scope: ApprovalScope<'_>,
    operation_id: &str,
) -> Result<Json<OperationBody>, AdminHttpError> {
    let record = read_operation(&state.pool, peer.public_identity(), scope, operation_id)
        .await
        .map_err(|err| failed(&err))?;
    Ok(Json(OperationBody::from(record)))
}

async fn list(
    state: &AdminState,
    peer: &AdminPeer,
    scope: ApprovalScope<'_>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<PageBody>, AdminHttpError> {
    let query = list_query(query)?;
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    let page = match query.after.as_deref() {
        Some(after) => Page::after(after, limit),
        None => Page::first(limit),
    };
    let records = list_operations(
        &state.pool,
        peer.public_identity(),
        scope,
        state.clock.now(),
        page,
    )
    .await
    .map_err(|err| failed(&err))?;
    let full = records.len() == usize::try_from(page.limit()).unwrap_or(usize::MAX);
    let next = records.last().filter(|_| full).map(|last| last.id.clone());
    Ok(Json(PageBody {
        operations: records.into_iter().map(OperationBody::from).collect(),
        next,
    }))
}

/// `GET /admin/v1/operations/{operation}`.
pub(super) async fn read_instance(
    peer: AdminPeer,
    State(state): State<AdminState>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<OperationBody>, AdminHttpError> {
    let Ok(Path(operation_id)) = path else {
        return Err(AdminHttpError::INVALID_REQUEST);
    };
    read(&state, &peer, ApprovalScope::Instance, &operation_id).await
}

/// `GET /admin/v1/operations`.
pub(super) async fn list_instance(
    peer: AdminPeer,
    State(state): State<AdminState>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<PageBody>, AdminHttpError> {
    list(&state, &peer, ApprovalScope::Instance, query).await
}

/// `GET /admin/v1/tenants/{tenant}/operations/{operation}`.
pub(super) async fn read_tenant(
    peer: AdminPeer,
    State(state): State<AdminState>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<OperationBody>, AdminHttpError> {
    let Ok(Path((tenant_id, operation_id))) = path else {
        return Err(AdminHttpError::INVALID_REQUEST);
    };
    read(
        &state,
        &peer,
        ApprovalScope::Tenant(&tenant_id),
        &operation_id,
    )
    .await
}

/// `GET /admin/v1/tenants/{tenant}/operations`.
pub(super) async fn list_tenant(
    peer: AdminPeer,
    State(state): State<AdminState>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<PageBody>, AdminHttpError> {
    let Ok(Path(tenant_id)) = path else {
        return Err(AdminHttpError::INVALID_REQUEST);
    };
    list(&state, &peer, ApprovalScope::Tenant(&tenant_id), query).await
}
