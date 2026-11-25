//! The read path of operations (Q1 of the second-approver proposal,
//! OQ-API-14, D22 and D29; D4 of the M1a lead decisions, tasks section 13):
//! [`read_operation`] reads one operation of the flow by its ID and
//! [`list_operations`] one page of the open ones, each on the path of its
//! scope, the instance or one tenant ([`ApprovalScope`], the same scope the
//! approve, cancel and reject take). Both take no lock and write nothing.
//!
//! # Who
//!
//! Readable by an instance `security_admin`, by the requester and, for a
//! tenant operation, by that tenant's `auditor` (tasks:149; Q1, ruled by the
//! user, 2026-11-23). In this order, each a point-in-time
//! [`authorize_operator`] lookup (a read needs no lock):
//!
//! 1. instance `security_admin`: every operation of the path;
//! 2. on a tenant path, that tenant's `auditor`: every operation of the
//!    path;
//! 3. on a tenant path, that tenant's `trust_admin`: only the operations it
//!    requested (`actor_id` its own `admin_id`); another `trust_admin`'s
//!    operation is [`OperationReadError::NotFound`], like a missing one, as
//!    for a cancel on a tenant path (inferred: the requester of every tenant
//!    kind of the flow is its tenant's `trust_admin`, and the requester of
//!    the instance kind is an instance `security_admin`, already step 1).
//!
//! Any other caller is [`OperationReadError::Unauthorized`], before any
//! operation is read, so it learns nothing about one: an unknown, revoked
//! or disabled credential, a disabled operator, another role (a
//! `client_admin`, a `provider_admin`), an instance `auditor` (inferred: not
//! named by the ruling), or a tenant role of another tenant.
//!
//! # What is found
//!
//! Only an operation of a kind of the flow ([`OperationKind`]) whose
//! requester's scope is the path's: a toggle on the instance path, a trust
//! keyset or source kind on its tenant's path. An operation of another
//! tenant, of the other scope, of another kind (an `approve`, `cancel` or
//! `reject` row, a recovery challenge), another `trust_admin`'s for a
//! requester, and a missing one are the one [`OperationReadError::NotFound`]
//! (no existence oracle: the same error as the approve and cancel give for
//! an operation outside the path, [`ApprovalError::NotFound`]). An ID with a
//! NUL character, which no row can hold, is that `NotFound` too, after the
//! authorization (inferred).
//!
//! [`read_operation`] returns an operation in any state: pending (also once
//! expired, D22: the outcome stays `pending`), applied, cancelled or
//! rejected. [`list_operations`] returns the open ones only: unconsumed,
//! unrevoked and unexpired at the caller's `now` (the proposal's read query,
//! D22), ordered by ID byte-wise in a [`Page`] (at most
//! [`MAX_PAGE_SIZE`](crate::persistence::registry::MAX_PAGE_SIZE) rows after
//! the cursor). The request layer must reject a cursor with a NUL character
//! before it calls (`22021` is otherwise a [`RegistryError::Other`]).
//!
//! # What is returned
//!
//! [`OperationRecord`]: the whole digest envelope (D29), so a client
//! recomputes the request digest from the record alone before it echoes it:
//! the ID, the tenant, the requester's `actor_id`, the kind, the expected
//! revision, `expires_at` as the integer microseconds the preimage uses, and
//! the plan as its canonical text ([`canonical_plan`]: exactly the bytes the
//! preimage embeds, not a JSON value, since a plan's integer may exceed
//! 2^53); with the stored digest, the outcome and the row's revision. A row
//! of the flow's kinds whose digest is not 32 bytes, that has no expiry, or
//! whose plan has no canonical form is [`OperationReadError::PlanIntegrity`]
//! (a data-integrity error, as for the approve), checked only once the row
//! is known to be the caller's to read, so an out-of-scope row never
//! answers anything but `NotFound`.
//!
//! [`ApprovalError::NotFound`]: super::ApprovalError::NotFound

use std::{fmt, time::SystemTime};

use sqlx::PgPool;

use super::{
    ApprovalScope, OperationKind, RequestDigest, digest::canonical_plan,
    digest::microseconds_since_epoch,
};
use crate::persistence::registry::{
    AdminRole, AdministrativeOperation, OperatorRequest, OperatorScope, Page, RegistryError,
    authorize_operator, get_administrative_operation, list_open_administrative_operations,
};

/// One operation as the read path returns it: the digest envelope (D29),
/// the stored digest, the outcome and the revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRecord {
    pub id: String,
    /// `None` for an instance operation.
    pub tenant_id: Option<String>,
    /// The requester's `admin_id`.
    pub actor_id: String,
    pub kind: OperationKind,
    pub request_digest: RequestDigest,
    pub expected_revision: i64,
    /// Whole microseconds since the Unix epoch, as the preimage holds it.
    pub expires_at_us: i64,
    /// The plan's canonical text ([`canonical_plan`]).
    pub plan: String,
    /// `pending`, `applied`, `cancelled` or `rejected` (D22: `pending`
    /// also once expired).
    pub outcome: String,
    /// The row's revision: 1 while pending, 2 once consumed or revoked.
    pub revision: i64,
}

/// Why a read did not succeed. `Display` is fixed text per variant and
/// `Debug` names the variant; the [`RegistryError`] inside
/// [`Self::Registry`] prints only constraint, table and column names and a
/// SQLSTATE. Neither holds an ID or another value of the request.
/// `#[non_exhaustive]`: a later read may add a variant.
#[derive(Debug)]
#[non_exhaustive]
pub enum OperationReadError {
    /// The presented credential may read no operation of the path (see the
    /// module docs, "Who").
    Unauthorized,
    /// No such operation the caller may read on this path (see the module
    /// docs, "What is found").
    NotFound,
    /// A row of the flow's kinds without a 32-byte digest, an expiry or a
    /// canonical plan: a data-integrity error, not a client error.
    PlanIntegrity,
    /// A store failure, [`RegistryError::Retry`], or a row the registry
    /// cannot read ([`RegistryError::UnreadableTimestamp`]).
    Registry(RegistryError),
}

impl fmt::Display for OperationReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("the operator may not read operations of this scope"),
            Self::NotFound => f.write_str("no such operation in this scope"),
            Self::PlanIntegrity => {
                f.write_str("the stored operation has no digest envelope to return")
            }
            Self::Registry(err) => write!(f, "operation read failed: {err}"),
        }
    }
}

impl std::error::Error for OperationReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(err) => Some(err),
            _ => None,
        }
    }
}

impl From<RegistryError> for OperationReadError {
    /// [`RegistryError::NotFound`] is [`Self::NotFound`]; every other error
    /// is [`Self::Registry`].
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::NotFound => Self::NotFound,
            err => Self::Registry(err),
        }
    }
}

/// Who the authorized caller reads as.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reader {
    /// An instance `security_admin`, or the tenant's `auditor`: every
    /// operation of the path.
    Any,
    /// A `trust_admin` of the tenant: only its own operations.
    Requester(String),
}

impl Reader {
    /// The actor a list is limited to, if any.
    fn actor(&self) -> Option<&str> {
        match self {
            Self::Any => None,
            Self::Requester(admin_id) => Some(admin_id),
        }
    }
}

/// Whether PostgreSQL text can hold `value` (no NUL character): a value
/// that cannot is no stored ID or identity.
fn storable(value: &str) -> bool {
    !value.contains('\0')
}

/// The tenant of a path, `None` for the instance.
fn tenant_of(scope: ApprovalScope<'_>) -> Option<&str> {
    match scope {
        ApprovalScope::Instance => None,
        ApprovalScope::Tenant(tenant_id) => Some(tenant_id),
    }
}

/// The names of the flow's kinds whose requester's scope is the path's.
fn kinds_of(scope: ApprovalScope<'_>) -> Vec<&'static str> {
    let tenant_id = tenant_of(scope);
    OperationKind::ALL
        .iter()
        .filter(|kind| kind.requester_role(tenant_id).is_some())
        .map(|kind| kind.as_str())
        .collect()
}

/// The caller's reading rights on the path (see the module docs, "Who").
async fn authorize_reader(
    pool: &PgPool,
    public_identity: &str,
    scope: ApprovalScope<'_>,
) -> Result<Reader, OperationReadError> {
    if !storable(public_identity) {
        return Err(OperationReadError::Unauthorized);
    }
    let lookup = |scope, role| OperatorRequest {
        public_identity,
        scope,
        role,
    };
    let instance = lookup(OperatorScope::Instance, AdminRole::SecurityAdmin);
    if authorize_operator(pool, &instance).await?.is_some() {
        return Ok(Reader::Any);
    }
    let Some(tenant_id) = tenant_of(scope).filter(|tenant_id| storable(tenant_id)) else {
        return Err(OperationReadError::Unauthorized);
    };
    let auditor = lookup(OperatorScope::Tenant(tenant_id), AdminRole::Auditor);
    if authorize_operator(pool, &auditor).await?.is_some() {
        return Ok(Reader::Any);
    }
    let trust_admin = lookup(OperatorScope::Tenant(tenant_id), AdminRole::TrustAdmin);
    match authorize_operator(pool, &trust_admin).await? {
        Some(operator) => Ok(Reader::Requester(operator.admin_id)),
        None => Err(OperationReadError::Unauthorized),
    }
}

/// The row as a record, if the reader may read it on the path: the kind
/// and the requester first (a miss is [`OperationReadError::NotFound`]),
/// then the envelope's integrity.
fn record(
    row: AdministrativeOperation,
    scope: ApprovalScope<'_>,
    reader: &Reader,
) -> Result<OperationRecord, OperationReadError> {
    let kind = OperationKind::from_name(&row.kind)
        .filter(|kind| kind.requester_role(row.tenant_id.as_deref()).is_some())
        .ok_or(OperationReadError::NotFound)?;
    if !scope.holds(row.tenant_id.as_deref()) {
        return Err(OperationReadError::NotFound);
    }
    if reader.actor().is_some_and(|actor| actor != row.actor_id) {
        return Err(OperationReadError::NotFound);
    }
    let request_digest = RequestDigest::try_from(row.request_digest.as_slice())
        .map_err(|_| OperationReadError::PlanIntegrity)?;
    let expires_at_us = row
        .expires_at
        .and_then(microseconds_since_epoch)
        .ok_or(OperationReadError::PlanIntegrity)?;
    let plan =
        canonical_plan(&row.immutable_plan).map_err(|_| OperationReadError::PlanIntegrity)?;
    Ok(OperationRecord {
        id: row.id,
        tenant_id: row.tenant_id,
        actor_id: row.actor_id,
        kind,
        request_digest,
        expected_revision: row.expected_revision,
        expires_at_us,
        plan,
        outcome: row.outcome,
        revision: row.revision,
    })
}

/// Reads the operation `operation_id` on the path `scope` for the operator
/// of `public_identity` (see the module docs): the authorization
/// ([`OperationReadError::Unauthorized`]), then the row
/// ([`OperationReadError::NotFound`] for every row the caller may not read
/// here), then its envelope ([`OperationReadError::PlanIntegrity`]). Takes
/// no lock and writes nothing.
pub async fn read_operation(
    pool: &PgPool,
    public_identity: &str,
    scope: ApprovalScope<'_>,
    operation_id: &str,
) -> Result<OperationRecord, OperationReadError> {
    let reader = authorize_reader(pool, public_identity, scope).await?;
    let tenant_id = tenant_of(scope);
    if !storable(operation_id) || !tenant_id.is_none_or(storable) {
        return Err(OperationReadError::NotFound);
    }
    let row = get_administrative_operation(pool, tenant_id, operation_id).await?;
    record(row, scope, &reader)
}

/// One page of the open operations on the path `scope` that the operator
/// of `public_identity` may read, at `now` (see the module docs): the
/// authorization ([`OperationReadError::Unauthorized`]), then the page, by
/// ID byte-wise; a `trust_admin` lists only its own. A row of the page
/// without an envelope fails the whole page with
/// [`OperationReadError::PlanIntegrity`]. Takes no lock and writes nothing.
pub async fn list_operations(
    pool: &PgPool,
    public_identity: &str,
    scope: ApprovalScope<'_>,
    now: SystemTime,
    page: Page<'_>,
) -> Result<Vec<OperationRecord>, OperationReadError> {
    let reader = authorize_reader(pool, public_identity, scope).await?;
    let tenant_id = tenant_of(scope);
    if !tenant_id.is_none_or(storable) {
        return Ok(Vec::new());
    }
    let kinds = kinds_of(scope);
    let rows =
        list_open_administrative_operations(pool, tenant_id, &kinds, reader.actor(), now, page)
            .await
            .map_err(OperationReadError::Registry)?;
    rows.into_iter()
        .map(|row| record(row, scope, &reader))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::operation::DigestEnvelope;

    fn row(tenant_id: Option<&str>, kind: &str, actor_id: &str) -> AdministrativeOperation {
        let plan = match json!({"requester_credential_id": "crd_1", "n": i64::MAX}) {
            serde_json::Value::Object(plan) => plan,
            _ => unreachable!(),
        };
        let expires_at_us = 1_790_086_400_123_456;
        let digest = DigestEnvelope {
            id: "op_1",
            tenant_id,
            actor_id,
            kind,
            expected_revision: 3,
            expires_at_us,
            plan: &plan,
        }
        .digest()
        .unwrap();
        AdministrativeOperation {
            id: "op_1".into(),
            tenant_id: tenant_id.map(Into::into),
            actor_id: actor_id.into(),
            kind: kind.into(),
            request_digest: digest.as_bytes().to_vec(),
            expected_revision: 3,
            immutable_plan: plan,
            challenge_hash: None,
            expires_at: super::super::digest::from_microseconds(expires_at_us),
            consumed_at: None,
            revoked_at: None,
            revocation_operation_id: None,
            approves_operation_id: None,
            revision: 1,
            outcome: "pending".into(),
            audit_id: "evt_1".into(),
        }
    }

    const TEN_A: ApprovalScope<'static> = ApprovalScope::Tenant("ten_a");

    #[test]
    fn the_kinds_of_a_path_are_its_requesters() {
        assert_eq!(
            kinds_of(ApprovalScope::Instance),
            ["instance_security_policy_update"]
        );
        assert_eq!(
            kinds_of(TEN_A),
            [
                "trust_keyset_version_create",
                "trust_keyset_version_enable",
                "trust_source_create",
                "trust_source_update",
            ]
        );
    }

    /// The record is the envelope: recomputing the digest from it alone
    /// gives the stored one, the plan's large integer included.
    #[test]
    fn a_record_recomputes_its_digest() {
        let stored = row(Some("ten_a"), "trust_source_create", "adm_1");
        let digest = stored.request_digest.clone();
        let record = record(stored, TEN_A, &Reader::Any).unwrap();
        assert_eq!(
            record.plan,
            r#"{"n":9223372036854775807,"requester_credential_id":"crd_1"}"#
        );
        let plan: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&record.plan).unwrap();
        let envelope = DigestEnvelope {
            id: &record.id,
            tenant_id: record.tenant_id.as_deref(),
            actor_id: &record.actor_id,
            kind: record.kind.as_str(),
            expected_revision: record.expected_revision,
            expires_at_us: record.expires_at_us,
            plan: &plan,
        };
        assert_eq!(envelope.digest().unwrap().as_bytes().as_slice(), digest);
        assert_eq!(record.request_digest.as_bytes().as_slice(), digest);
    }

    /// Every row outside the reader's view is the one `NotFound`, also when
    /// it is broken; a broken row in view is `PlanIntegrity`.
    #[test]
    fn rows_outside_the_view_are_not_found_before_integrity() {
        let requester = Reader::Requester("adm_1".into());
        let cases: [(AdministrativeOperation, ApprovalScope<'_>, &Reader); 7] = [
            (
                row(Some("ten_b"), "trust_source_create", "adm_1"),
                TEN_A,
                &Reader::Any,
            ),
            (
                row(None, "trust_source_create", "adm_1"),
                ApprovalScope::Instance,
                &Reader::Any,
            ),
            (
                row(Some("ten_a"), "instance_security_policy_update", "adm_1"),
                TEN_A,
                &Reader::Any,
            ),
            (
                row(None, "instance_security_policy_update", "adm_1"),
                TEN_A,
                &Reader::Any,
            ),
            (row(Some("ten_a"), "approve", "adm_1"), TEN_A, &Reader::Any),
            (
                row(Some("ten_a"), "trust_source_create", "adm_2"),
                TEN_A,
                &requester,
            ),
            (
                row(Some("ten_a"), "Trust_source_create", "adm_1"),
                TEN_A,
                &Reader::Any,
            ),
        ];
        for (mut stored, scope, reader) in cases {
            stored.request_digest = vec![0; 33];
            let err = record(stored, scope, reader).unwrap_err();
            assert!(matches!(err, OperationReadError::NotFound), "{err:?}");
        }
        let mut short = row(Some("ten_a"), "trust_source_create", "adm_1");
        short.request_digest = vec![0; 64];
        let mut no_expiry = row(Some("ten_a"), "trust_source_create", "adm_1");
        no_expiry.expires_at = None;
        let mut float = row(Some("ten_a"), "trust_source_create", "adm_1");
        float.immutable_plan.insert("f".into(), json!(1.5));
        for stored in [short, no_expiry, float] {
            let err = record(stored, TEN_A, &requester).unwrap_err();
            assert!(matches!(err, OperationReadError::PlanIntegrity), "{err:?}");
        }
        let own = row(Some("ten_a"), "trust_source_create", "adm_1");
        assert!(record(own, TEN_A, &requester).is_ok());
        let toggle = row(None, "instance_security_policy_update", "adm_9");
        assert!(record(toggle, ApprovalScope::Instance, &Reader::Any).is_ok());
    }

    #[test]
    fn errors_print_fixed_text() {
        for (err, debug, display) in [
            (
                OperationReadError::Unauthorized,
                "Unauthorized",
                "the operator may not read operations of this scope",
            ),
            (
                OperationReadError::NotFound,
                "NotFound",
                "no such operation in this scope",
            ),
            (
                OperationReadError::PlanIntegrity,
                "PlanIntegrity",
                "the stored operation has no digest envelope to return",
            ),
        ] {
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(err.to_string(), display);
            assert!(std::error::Error::source(&err).is_none());
        }
        let err = OperationReadError::from(RegistryError::NotFound);
        assert!(matches!(err, OperationReadError::NotFound));
        let err = OperationReadError::from(RegistryError::StaleRevision);
        assert_eq!(format!("{err:?}"), "Registry(StaleRevision)");
        assert!(err.to_string().starts_with("operation read failed: "));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn a_nul_is_never_storable() {
        assert!(storable("op_1"));
        assert!(storable(""));
        assert!(!storable("op\0"));
    }
}
