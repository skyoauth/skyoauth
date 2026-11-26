//! The admin error-to-HTTP mapping: one pure function per error family,
//! each an exhaustive `match` that names every variant of the crate's
//! error enums, the ones inside an [`ApprovalError`] included (a new
//! variant fails the build), and the one response shape. The whole table is in the module docs of
//! [`crate::admin_http`], "Errors".

use axum::{
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::admin::AdminWriteError;
use crate::identity::IdentityError;
use crate::ids::IdError;
use crate::operation::{ApprovalError, NotApprovableReason, OperationReadError};
use crate::persistence::registry::{InvariantKind, RegistryError};
use crate::trust::{KeysetWriteError, SourceWriteError};

/// The `Retry-After` of a retryable 503, in seconds (inferred: one
/// second, well inside the 300 s bound of ERR-047).
pub const RETRY_AFTER_SECONDS: u32 = 1;

/// SQLSTATE class 08, `connection_exception`.
const CONNECTION_EXCEPTION_CLASS: &str = "08";
/// SQLSTATE class 53, `insufficient_resources`.
const INSUFFICIENT_RESOURCES_CLASS: &str = "53";
/// The SQLSTATEs of class 57, `operator_intervention`, that start with
/// `57P0`, matched as a prefix (any `57P0x`): the defined ones are `57P01`
/// to `57P05`, `admin_shutdown`, `crash_shutdown`, `cannot_connect_now`,
/// `database_dropped` and `idle_session_timeout`. Not `57014`
/// ([`QUERY_CANCELED`]).
const SHUTDOWN_PREFIX: &str = "57P0";
/// `lock_not_available`: a `NOWAIT` lock or a `lock_timeout`.
const LOCK_NOT_AVAILABLE: &str = "55P03";
/// `query_canceled`: a `statement_timeout`, or a cancel request.
const QUERY_CANCELED: &str = "57014";

/// The value of the body's one member, `error`. Each code has one status
/// ([`Self::status`]). `unauthenticated`, `forbidden` and `auth_unavailable`
/// are the frozen reasons of errors-retry ERR-070, `invalid_request` and
/// `server_error` the OAuth `error` values (RFC 6749); the others are
/// proposed by this module (see the module docs of [`crate::admin_http`],
/// "Wire codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    /// 401: no verified peer identity on the request.
    Unauthenticated,
    /// 403: the peer's credential does not authorize the request.
    Forbidden,
    /// 404: no such object the caller may see on this path.
    NotFound,
    /// 400: the request or one of its values is malformed.
    InvalidRequest,
    /// 409: the target moved: read it again.
    StaleRevision,
    /// 409: the request conflicts with the stored state.
    Conflict,
    /// 409: the operation is consumed, revoked, expired or not of the flow.
    NotApprovable,
    /// 409: the write's tenant is disabled.
    TenantDisabled,
    /// 422: a widening write without `acknowledge_widening`.
    WideningNotAcknowledged,
    /// 500: a server or data-integrity error; nothing was written.
    ServerError,
    /// 503: the store or another dependency is unavailable.
    AuthUnavailable,
}

impl ErrorCode {
    /// Every code.
    pub const ALL: [Self; 11] = [
        Self::Unauthenticated,
        Self::Forbidden,
        Self::NotFound,
        Self::InvalidRequest,
        Self::StaleRevision,
        Self::Conflict,
        Self::NotApprovable,
        Self::TenantDisabled,
        Self::WideningNotAcknowledged,
        Self::ServerError,
        Self::AuthUnavailable,
    ];

    /// The wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::InvalidRequest => "invalid_request",
            Self::StaleRevision => "stale_revision",
            Self::Conflict => "conflict",
            Self::NotApprovable => "not_approvable",
            Self::TenantDisabled => "tenant_disabled",
            Self::WideningNotAcknowledged => "widening_not_acknowledged",
            Self::ServerError => "server_error",
            Self::AuthUnavailable => "auth_unavailable",
        }
    }

    /// The code's status.
    pub const fn status(self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::StaleRevision | Self::Conflict | Self::NotApprovable | Self::TenantDisabled => {
                StatusCode::CONFLICT
            }
            Self::WideningNotAcknowledged => StatusCode::UNPROCESSABLE_ENTITY,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::AuthUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// An admin error response: the code, and whether it carries
/// `Retry-After: 1` ([`RETRY_AFTER_SECONDS`]). The body is
/// `{"error":"<code>"}` and nothing else: no description, no value of the
/// request or of a row, no key byte, no version member (ERR-072).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminHttpError {
    code: ErrorCode,
    retry: bool,
}

impl AdminHttpError {
    /// No verified peer identity (see [`super::AdminPeer`]).
    pub const UNAUTHENTICATED: Self = Self::of(ErrorCode::Unauthenticated);
    /// The one `NotFound` of every admin path.
    pub const NOT_FOUND: Self = Self::of(ErrorCode::NotFound);
    /// A malformed request.
    pub const INVALID_REQUEST: Self = Self::of(ErrorCode::InvalidRequest);

    const fn of(code: ErrorCode) -> Self {
        Self { code, retry: false }
    }

    /// A retryable 503 with `Retry-After`.
    const fn retry(code: ErrorCode) -> Self {
        Self { code, retry: true }
    }

    pub const fn code(self) -> ErrorCode {
        self.code
    }

    pub const fn status(self) -> StatusCode {
        self.code.status()
    }

    /// The `Retry-After` seconds, if any.
    pub const fn retry_after(self) -> Option<u32> {
        if self.retry {
            Some(RETRY_AFTER_SECONDS)
        } else {
            None
        }
    }

    /// The body's bytes: `{"error":"<code>"}`.
    pub fn body(self) -> String {
        format!("{{\"error\":\"{}\"}}", self.code.as_str())
    }
}

impl IntoResponse for AdminHttpError {
    fn into_response(self) -> Response {
        let mut response = (self.status(), self.body()).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(seconds) = self.retry_after() {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

const fn code(code: ErrorCode) -> AdminHttpError {
    AdminHttpError::of(code)
}

/// [`IdError`]: every variant is a server error (D1: an RNG failure
/// answers 5xx and the write writes nothing).
pub const fn from_id(err: &IdError) -> AdminHttpError {
    match err {
        IdError::SourceFailed | IdError::Exhausted => code(ErrorCode::ServerError),
    }
}

/// [`IdentityError`]: the submitted key bytes are not one DER
/// `SubjectPublicKeyInfo`, a malformed value.
pub const fn from_identity(err: &IdentityError) -> AdminHttpError {
    match err {
        IdentityError::Empty
        | IdentityError::TooLarge
        | IdentityError::Truncated
        | IdentityError::NotDer
        | IdentityError::TrailingBytes
        | IdentityError::NotSpki => code(ErrorCode::InvalidRequest),
    }
}

/// [`InvariantKind`] of a [`RegistryError::Invariant`].
const fn from_invariant(kind: InvariantKind) -> AdminHttpError {
    match kind {
        // A value the schema's checks refuse: a length, a character set, a
        // list domain, a missing required value.
        InvariantKind::Check | InvariantKind::NotNull => code(ErrorCode::InvalidRequest),
        // A referenced row is missing or not enabled: the stored state.
        InvariantKind::ForeignKey
        | InvariantKind::AssignmentActive
        | InvariantKind::EgressEntryEnabled => code(ErrorCode::Conflict),
        // Tripwires behind checks the service makes first: reaching one is
        // a server error.
        InvariantKind::SameTenantOperation | InvariantKind::DistinctApprover => {
            code(ErrorCode::ServerError)
        }
    }
}

/// The [`sqlx::Error`] of a [`RegistryError::Other`], which the registry
/// leaves unclassified: an unavailable store is 503, a lock or statement
/// timeout 503 with `Retry-After` (as a [`RegistryError::Retry`]: the
/// whole request may succeed again), and everything else 500.
///
/// - 503: a connection or TLS failure ([`sqlx::Error::Io`],
///   [`sqlx::Error::Tls`]), no pooled connection in time or a closed pool
///   ([`sqlx::Error::PoolTimedOut`], [`sqlx::Error::PoolClosed`]), and the
///   SQLSTATE classes 08 (`connection_exception`) and 53
///   (`insufficient_resources`) and every code with the prefix `57P0` (a
///   prefix match; PostgreSQL defines `57P01` to `57P05`: a server
///   shutting down, starting up or dropping the database, an idle session
///   timed out).
/// - 503 with `Retry-After`: `55P03` (`lock_not_available`) and `57014`
///   (`query_canceled`). The registry keeps them in `Other` (only `40001`
///   and `40P01` are its `Retry`); the HTTP layer retries them as it
///   retries those.
/// - 500: a decode or encode failure, a protocol error, an unknown
///   SQLSTATE, and a constraint violation whose name is not in
///   [`KNOWN_CONSTRAINTS`](crate::persistence::registry::KNOWN_CONSTRAINTS):
///   a server or data-integrity error (inferred).
fn from_store_failure(err: &sqlx::Error) -> AdminHttpError {
    match err {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed => code(ErrorCode::AuthUnavailable),
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some(LOCK_NOT_AVAILABLE | QUERY_CANCELED) => {
                AdminHttpError::retry(ErrorCode::AuthUnavailable)
            }
            Some(sqlstate)
                if sqlstate.starts_with(CONNECTION_EXCEPTION_CLASS)
                    || sqlstate.starts_with(INSUFFICIENT_RESOURCES_CLASS)
                    || sqlstate.starts_with(SHUTDOWN_PREFIX) =>
            {
                code(ErrorCode::AuthUnavailable)
            }
            _ => code(ErrorCode::ServerError),
        },
        _ => code(ErrorCode::ServerError),
    }
}

/// [`RegistryError`].
pub fn from_registry(err: &RegistryError) -> AdminHttpError {
    match err {
        RegistryError::NotFound => AdminHttpError::NOT_FOUND,
        RegistryError::StaleRevision => code(ErrorCode::StaleRevision),
        RegistryError::AlreadyExists { .. } | RegistryError::Guard => code(ErrorCode::Conflict),
        RegistryError::Invariant { kind, .. } => from_invariant(*kind),
        RegistryError::UnreadableTimestamp { .. } => code(ErrorCode::ServerError),
        RegistryError::Retry(_) => AdminHttpError::retry(ErrorCode::AuthUnavailable),
        RegistryError::Other(err) => from_store_failure(err),
        RegistryError::ReservedActorId | RegistryError::RequiredPredicate { .. } => {
            code(ErrorCode::InvalidRequest)
        }
    }
}

/// [`AdminWriteError`].
pub fn from_admin_write(err: &AdminWriteError) -> AdminHttpError {
    match err {
        AdminWriteError::Unauthorized | AdminWriteError::PrincipalKindNotAllowed => {
            code(ErrorCode::Forbidden)
        }
        AdminWriteError::UnsupportedIsolation => code(ErrorCode::ServerError),
        AdminWriteError::TenantDisabled => code(ErrorCode::TenantDisabled),
        AdminWriteError::InvalidDestination => code(ErrorCode::InvalidRequest),
        // An enable's stored destination: a refusal by the stored state.
        AdminWriteError::InvalidStoredDestination => code(ErrorCode::Conflict),
        AdminWriteError::WideningNotAcknowledged => code(ErrorCode::WideningNotAcknowledged),
        // The gate is on and no egress operation kind exists, so the write
        // cannot proceed in this state (a conflict with the instance policy).
        AdminWriteError::SecondApproverRequired => code(ErrorCode::Conflict),
        // Effectively unreachable after the authorization: bootstrap writes
        // the policy row in the transaction that enrolls the first
        // operator, so no request before it is authorized. Mapped as a
        // store failure that a retry may clear (D18: it never widens).
        AdminWriteError::PolicyUnavailable => AdminHttpError::retry(ErrorCode::AuthUnavailable),
        AdminWriteError::PublicKey(err) => from_identity(err),
        AdminWriteError::Id(err) => from_id(err),
        AdminWriteError::Registry(err) => from_registry(err),
    }
}

/// [`KeysetWriteError`], also inside [`ApprovalError::Keyset`].
pub fn from_keyset_write(err: &KeysetWriteError) -> AdminHttpError {
    match err {
        KeysetWriteError::Unauthorized => code(ErrorCode::Forbidden),
        KeysetWriteError::Upload(_) | KeysetWriteError::PrivateMemberInProvenance => {
            code(ErrorCode::InvalidRequest)
        }
        KeysetWriteError::Overlap(_) | KeysetWriteError::TooManyEnabledVersions => {
            code(ErrorCode::Conflict)
        }
        KeysetWriteError::StoredVersion { .. }
        | KeysetWriteError::StoredFingerprintMismatch
        | KeysetWriteError::UnsupportedIsolation => code(ErrorCode::ServerError),
        KeysetWriteError::WorkerUnavailable => code(ErrorCode::AuthUnavailable),
        // `PolicyUnavailable` is effectively unreachable after the
        // authorization (see [`from_admin_write`]).
        KeysetWriteError::ValidationBusy | KeysetWriteError::PolicyUnavailable => {
            AdminHttpError::retry(ErrorCode::AuthUnavailable)
        }
        KeysetWriteError::WideningNotAcknowledged => code(ErrorCode::WideningNotAcknowledged),
        KeysetWriteError::Registry(err) => from_registry(err),
    }
}

/// [`SourceWriteError`], also inside [`ApprovalError::Source`].
pub fn from_source_write(err: &SourceWriteError) -> AdminHttpError {
    match err {
        SourceWriteError::Unauthorized => code(ErrorCode::Forbidden),
        SourceWriteError::InvalidDestination { .. } => code(ErrorCode::InvalidRequest),
        SourceWriteError::EgressNotAllowed { .. } => code(ErrorCode::Conflict),
        SourceWriteError::UnsupportedIsolation => code(ErrorCode::ServerError),
        SourceWriteError::WideningNotAcknowledged => code(ErrorCode::WideningNotAcknowledged),
        // Effectively unreachable after the authorization (see
        // [`from_admin_write`]).
        SourceWriteError::PolicyUnavailable => AdminHttpError::retry(ErrorCode::AuthUnavailable),
        SourceWriteError::Registry(err) => from_registry(err),
    }
}

/// A [`RegistryError`] of the approval family, also inside
/// [`ApprovalError::Keyset`] and [`ApprovalError::Source`]: the values an
/// approve writes are the stored plan's (D7: the database constraints run
/// at approve only), and a cancel, reject or toggle submits no value a
/// constraint checks, so a check or not-null refusal is one by the stored
/// state, 409 `not_approvable`; every other error maps as
/// [`from_registry`]. Every variant is named, so a new one fails the build
/// here too.
fn from_applied_registry(err: &RegistryError) -> AdminHttpError {
    match err {
        RegistryError::Invariant {
            kind: InvariantKind::Check | InvariantKind::NotNull,
            ..
        } => code(ErrorCode::NotApprovable),
        RegistryError::Invariant {
            kind:
                InvariantKind::ForeignKey
                | InvariantKind::AssignmentActive
                | InvariantKind::EgressEntryEnabled
                | InvariantKind::SameTenantOperation
                | InvariantKind::DistinctApprover,
            ..
        }
        | RegistryError::NotFound
        | RegistryError::StaleRevision
        | RegistryError::AlreadyExists { .. }
        | RegistryError::Guard
        | RegistryError::UnreadableTimestamp { .. }
        | RegistryError::Retry(_)
        | RegistryError::Other(_)
        | RegistryError::ReservedActorId
        | RegistryError::RequiredPredicate { .. } => from_registry(err),
    }
}

/// [`ApprovalError`]: the approve, cancel, reject and toggle. A refusal
/// of the stored plan's values, which a direct write gives as 400 (an
/// upload the plan's algorithms refuse, a private member in the plan's
/// provenance, a destination that is not canonical, a check or not-null
/// constraint), is 409 `not_approvable` here: the approver submitted none
/// of them, and no retry of the approve can succeed.
pub fn from_approval(err: &ApprovalError) -> AdminHttpError {
    match err {
        ApprovalError::Unauthorized | ApprovalError::SelfApproval => code(ErrorCode::Forbidden),
        ApprovalError::NotFound => AdminHttpError::NOT_FOUND,
        ApprovalError::NotApprovable(
            NotApprovableReason::Consumed
            | NotApprovableReason::Revoked
            | NotApprovableReason::Expired
            | NotApprovableReason::WrongKind,
        ) => code(ErrorCode::NotApprovable),
        ApprovalError::EchoMismatch | ApprovalError::RequesterNotAuthorized => {
            code(ErrorCode::Conflict)
        }
        ApprovalError::StaleRevision => code(ErrorCode::StaleRevision),
        ApprovalError::PlanIntegrity | ApprovalError::UnsupportedIsolation => {
            code(ErrorCode::ServerError)
        }
        // Effectively unreachable after the authorization (see
        // [`from_admin_write`]).
        ApprovalError::PolicyUnavailable => AdminHttpError::retry(ErrorCode::AuthUnavailable),
        ApprovalError::WideningNotAcknowledged => code(ErrorCode::WideningNotAcknowledged),
        ApprovalError::Keyset(
            KeysetWriteError::Upload(_) | KeysetWriteError::PrivateMemberInProvenance,
        )
        | ApprovalError::Source(SourceWriteError::InvalidDestination { .. }) => {
            code(ErrorCode::NotApprovable)
        }
        ApprovalError::Keyset(KeysetWriteError::Registry(err))
        | ApprovalError::Source(SourceWriteError::Registry(err))
        | ApprovalError::Registry(err) => from_applied_registry(err),
        // Every other variant, named so that a new one fails the build.
        ApprovalError::Keyset(
            err @ (KeysetWriteError::Unauthorized
            | KeysetWriteError::Overlap(_)
            | KeysetWriteError::StoredVersion { .. }
            | KeysetWriteError::StoredFingerprintMismatch
            | KeysetWriteError::TooManyEnabledVersions
            | KeysetWriteError::UnsupportedIsolation
            | KeysetWriteError::WorkerUnavailable
            | KeysetWriteError::ValidationBusy
            | KeysetWriteError::WideningNotAcknowledged
            | KeysetWriteError::PolicyUnavailable),
        ) => from_keyset_write(err),
        ApprovalError::Source(
            err @ (SourceWriteError::Unauthorized
            | SourceWriteError::EgressNotAllowed { .. }
            | SourceWriteError::UnsupportedIsolation
            | SourceWriteError::WideningNotAcknowledged
            | SourceWriteError::PolicyUnavailable),
        ) => from_source_write(err),
    }
}

/// [`OperationReadError`]: the operation reads.
pub fn from_operation_read(err: &OperationReadError) -> AdminHttpError {
    match err {
        // The presented key names no usable credential (ERR-010).
        OperationReadError::Unauthenticated => AdminHttpError::UNAUTHENTICATED,
        OperationReadError::Unauthorized => code(ErrorCode::Forbidden),
        OperationReadError::NotFound => AdminHttpError::NOT_FOUND,
        OperationReadError::PlanIntegrity => code(ErrorCode::ServerError),
        OperationReadError::Registry(err) => from_registry(err),
    }
}

macro_rules! from_family {
    ($($error:ty => $function:ident),* $(,)?) => {
        $(
            impl From<&$error> for AdminHttpError {
                fn from(err: &$error) -> Self {
                    $function(err)
                }
            }
        )*
    };
}

from_family!(
    IdError => from_id,
    IdentityError => from_identity,
    RegistryError => from_registry,
    AdminWriteError => from_admin_write,
    KeysetWriteError => from_keyset_write,
    SourceWriteError => from_source_write,
    ApprovalError => from_approval,
    OperationReadError => from_operation_read,
);

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::body::to_bytes;

    use super::*;
    use crate::jwk::{
        DEFAULT_ALLOWED_ALGORITHMS, JwkSetError, KeysetVersion, OverlapError, VersionStatus,
        check_version_overlap, parse_jwk_set,
    };

    const UNAUTHENTICATED: (u16, &str, bool) = (401, "unauthenticated", false);
    const FORBIDDEN: (u16, &str, bool) = (403, "forbidden", false);
    const NOT_FOUND: (u16, &str, bool) = (404, "not_found", false);
    const INVALID: (u16, &str, bool) = (400, "invalid_request", false);
    const STALE: (u16, &str, bool) = (409, "stale_revision", false);
    const CONFLICT: (u16, &str, bool) = (409, "conflict", false);
    const NOT_APPROVABLE: (u16, &str, bool) = (409, "not_approvable", false);
    const TENANT_DISABLED: (u16, &str, bool) = (409, "tenant_disabled", false);
    const WIDENING: (u16, &str, bool) = (422, "widening_not_acknowledged", false);
    const SERVER: (u16, &str, bool) = (500, "server_error", false);
    const UNAVAILABLE: (u16, &str, bool) = (503, "auth_unavailable", false);
    const RETRY: (u16, &str, bool) = (503, "auth_unavailable", true);

    fn seen(err: AdminHttpError) -> (u16, &'static str, bool) {
        (
            err.status().as_u16(),
            err.code().as_str(),
            err.retry_after().is_some(),
        )
    }

    #[track_caller]
    fn check<E: std::fmt::Debug>(
        map: impl Fn(&E) -> AdminHttpError,
        rows: Vec<(E, (u16, &str, bool))>,
        variants: usize,
    ) {
        let mut names = BTreeSet::new();
        for (err, expected) in &rows {
            assert_eq!(seen(map(err)), *expected, "{err:?}");
            let debug = format!("{err:?}");
            names.insert(debug.split(['(', ' ']).next().unwrap().to_owned());
        }
        assert_eq!(names.len(), variants, "a variant is missing: {names:?}");
    }

    fn other() -> sqlx::Error {
        sqlx::Error::PoolTimedOut
    }

    /// A database error with a chosen SQLSTATE and constraint, whose text
    /// stands for a value of the row.
    #[derive(Debug)]
    struct FakeDbError {
        code: Option<&'static str>,
        constraint: Option<&'static str>,
    }

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Key (id)=(ten_secret_marker) failed")
        }
    }

    impl std::error::Error for FakeDbError {}

    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            "ten_secret_marker"
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.map(std::borrow::Cow::Borrowed)
        }
        fn constraint(&self) -> Option<&str> {
            self.constraint
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    /// The registry's error for a database error of `code` naming
    /// `constraint`, as the registry classifies it.
    fn database(code: &'static str, constraint: Option<&'static str>) -> RegistryError {
        RegistryError::from(sqlx::Error::database(FakeDbError {
            code: Some(code),
            constraint,
        }))
    }

    /// Every registry variant and every invariant kind.
    fn registry_rows() -> Vec<(RegistryError, (u16, &'static str, bool))> {
        let invariant = |kind| RegistryError::Invariant {
            kind,
            constraint: None,
        };
        vec![
            (RegistryError::NotFound, NOT_FOUND),
            (RegistryError::StaleRevision, STALE),
            (
                RegistryError::AlreadyExists {
                    constraint: "tenant_pkey",
                },
                CONFLICT,
            ),
            (invariant(InvariantKind::ForeignKey), CONFLICT),
            (invariant(InvariantKind::Check), INVALID),
            (invariant(InvariantKind::NotNull), INVALID),
            (invariant(InvariantKind::AssignmentActive), CONFLICT),
            (invariant(InvariantKind::EgressEntryEnabled), CONFLICT),
            (invariant(InvariantKind::SameTenantOperation), SERVER),
            (invariant(InvariantKind::DistinctApprover), SERVER),
            (RegistryError::Guard, CONFLICT),
            (
                RegistryError::UnreadableTimestamp {
                    table: "tenant",
                    column: "created_at",
                    id: "ten_secret".into(),
                },
                SERVER,
            ),
            (RegistryError::Retry(other()), RETRY),
            (RegistryError::Other(other()), UNAVAILABLE),
            (RegistryError::ReservedActorId, INVALID),
            (
                RegistryError::RequiredPredicate {
                    claim: "repository_owner_id",
                    problem: crate::persistence::registry::PredicateProblem::Empty,
                },
                INVALID,
            ),
        ]
    }

    /// A guard that a new [`InvariantKind`] fails to compile here too,
    /// beside [`from_invariant`]: the table above must list it.
    #[test]
    fn every_invariant_kind_is_in_the_table() {
        let listed: Vec<InvariantKind> = registry_rows()
            .into_iter()
            .filter_map(|(err, _)| match err {
                RegistryError::Invariant { kind, .. } => Some(kind),
                _ => None,
            })
            .collect();
        for kind in &listed {
            match kind {
                InvariantKind::ForeignKey
                | InvariantKind::Check
                | InvariantKind::NotNull
                | InvariantKind::AssignmentActive
                | InvariantKind::EgressEntryEnabled
                | InvariantKind::SameTenantOperation
                | InvariantKind::DistinctApprover => {}
            }
        }
        assert_eq!(listed.len(), 7);
    }

    #[test]
    fn the_registry_table() {
        check(from_registry, registry_rows(), 10);
    }

    /// What the registry leaves in `Other`: an unavailable store is 503, a
    /// lock or statement timeout 503 with `Retry-After`, everything else
    /// (a decode failure, an unknown SQLSTATE, a constraint the registry
    /// does not know) 500. `40001` and `40P01` are the registry's `Retry`.
    #[test]
    fn the_store_failure_table() {
        let io = || std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let unavailable = [
            sqlx::Error::Io(io()),
            sqlx::Error::Tls(io().into()),
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
        ];
        for err in unavailable {
            let err = RegistryError::Other(err);
            assert_eq!(seen(from_registry(&err)), UNAVAILABLE, "{err:?}");
        }
        let rows = [
            // Class 08, connection_exception.
            ("08000", UNAVAILABLE),
            ("08003", UNAVAILABLE),
            ("08006", UNAVAILABLE),
            ("08P01", UNAVAILABLE),
            // Class 53, insufficient_resources.
            ("53000", UNAVAILABLE),
            ("53100", UNAVAILABLE),
            ("53200", UNAVAILABLE),
            ("53300", UNAVAILABLE),
            // The prefix `57P0` (a prefix match), whose defined codes are
            // 57P01 to 57P05: shutdown, startup, a dropped database, an
            // idle session timeout.
            ("57P01", UNAVAILABLE),
            ("57P02", UNAVAILABLE),
            ("57P03", UNAVAILABLE),
            ("57P04", UNAVAILABLE),
            ("57P05", UNAVAILABLE),
            // A lock or statement timeout: retried as a `Retry` is.
            ("55P03", RETRY),
            ("57014", RETRY),
            // The registry's own `Retry`.
            ("40001", RETRY),
            ("40P01", RETRY),
            // Everything else: a server error.
            ("57000", SERVER),
            ("55000", SERVER),
            ("55006", SERVER),
            ("40002", SERVER),
            ("22021", SERVER),
            ("22003", SERVER),
            ("54000", SERVER),
            ("42P01", SERVER),
            ("XX000", SERVER),
            ("5", SERVER),
            ("", SERVER),
        ];
        for (code, expected) in rows {
            let err = database(code, None);
            assert!(
                matches!(err, RegistryError::Other(_) | RegistryError::Retry(_)),
                "{code}: {err:?}"
            );
            assert_eq!(seen(from_registry(&err)), expected, "{code}");
        }
        // A database error without a SQLSTATE.
        let err = RegistryError::Other(sqlx::Error::database(FakeDbError {
            code: None,
            constraint: None,
        }));
        assert_eq!(seen(from_registry(&err)), SERVER);
        // A constraint violation the registry does not know is `Other`, a
        // server error, not the 400 or 409 of a known one.
        for code in ["23505", "23503", "23514"] {
            let err = database(code, Some("not_a_known_constraint"));
            assert!(matches!(err, RegistryError::Other(_)), "{code}: {err:?}");
            assert_eq!(seen(from_registry(&err)), SERVER, "{code}");
            let known = database(code, Some("tenant_pkey"));
            assert!(!matches!(known, RegistryError::Other(_)), "{code}");
        }
        // A decode, encode or protocol failure, and the other non-database
        // errors.
        for err in [
            sqlx::Error::Decode("bad".into()),
            sqlx::Error::Encode("bad".into()),
            sqlx::Error::ColumnDecode {
                index: "status".into(),
                source: "bad".into(),
            },
            sqlx::Error::Protocol("bad".into()),
            sqlx::Error::RowNotFound,
            sqlx::Error::ColumnNotFound("status".into()),
            sqlx::Error::WorkerCrashed,
        ] {
            let err = RegistryError::from(err);
            assert!(matches!(err, RegistryError::Other(_)), "{err:?}");
            assert_eq!(seen(from_registry(&err)), SERVER, "{err:?}");
        }
        // Every family passes a store failure through.
        let timeout = || database("57014", None);
        assert_eq!(seen(from_admin_write(&timeout().into())), RETRY);
        assert_eq!(
            seen(from_operation_read(
                &OperationReadError::Registry(timeout())
            )),
            RETRY
        );
        let decode = || RegistryError::Other(sqlx::Error::Decode("bad".into()));
        assert_eq!(
            seen(from_approval(&ApprovalError::Registry(decode()))),
            SERVER
        );
        assert_eq!(
            seen(from_keyset_write(&KeysetWriteError::Registry(decode()))),
            SERVER
        );
        assert_eq!(
            seen(from_source_write(&SourceWriteError::Registry(database(
                "08006", None
            )))),
            UNAVAILABLE
        );
    }

    #[test]
    fn the_id_and_identity_tables() {
        check(
            from_id,
            vec![
                (IdError::SourceFailed, SERVER),
                (IdError::Exhausted, SERVER),
            ],
            2,
        );
        check(
            from_identity,
            vec![
                (IdentityError::Empty, INVALID),
                (IdentityError::TooLarge, INVALID),
                (IdentityError::Truncated, INVALID),
                (IdentityError::NotDer, INVALID),
                (IdentityError::TrailingBytes, INVALID),
                (IdentityError::NotSpki, INVALID),
            ],
            6,
        );
    }

    #[test]
    fn the_admin_write_table() {
        let mut rows = vec![
            (AdminWriteError::Unauthorized, FORBIDDEN),
            (AdminWriteError::UnsupportedIsolation, SERVER),
            (AdminWriteError::PrincipalKindNotAllowed, FORBIDDEN),
            (AdminWriteError::TenantDisabled, TENANT_DISABLED),
            (AdminWriteError::InvalidDestination, INVALID),
            (AdminWriteError::InvalidStoredDestination, CONFLICT),
            (AdminWriteError::WideningNotAcknowledged, WIDENING),
            (AdminWriteError::SecondApproverRequired, CONFLICT),
            (AdminWriteError::PolicyUnavailable, RETRY),
            (AdminWriteError::PublicKey(IdentityError::NotDer), INVALID),
            (AdminWriteError::Id(IdError::SourceFailed), SERVER),
            (AdminWriteError::Id(IdError::Exhausted), SERVER),
        ];
        rows.extend(
            registry_rows()
                .into_iter()
                .map(|(err, expected)| (AdminWriteError::Registry(err), expected)),
        );
        check(from_admin_write, rows, 12);
    }

    /// An [`OverlapError`] from two versions that give one `kid` two keys.
    fn overlap() -> OverlapError {
        let set = |x: &str| {
            let set = serde_json::json!({
                "keys": [{"kty": "OKP", "crv": "Ed25519", "x": x, "kid": "k1"}],
            });
            parse_jwk_set(&set, DEFAULT_ALLOWED_ALGORITHMS).unwrap()
        };
        let first = set("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        let second = set("UfRYmkzHj6GwuLYsI-tTkGiXTCnuDGoilEBRjZFj8OQ");
        let version = |id, keys| KeysetVersion {
            id,
            effective_at: std::time::UNIX_EPOCH,
            expires_at: None,
            status: VersionStatus::Enabled,
            keys,
        };
        check_version_overlap(&version("ver_2", &second), &[version("ver_1", &first)]).unwrap_err()
    }

    fn keyset_rows() -> Vec<(KeysetWriteError, (u16, &'static str, bool))> {
        vec![
            (KeysetWriteError::Unauthorized, FORBIDDEN),
            (KeysetWriteError::Upload(JwkSetError::NoKeys), INVALID),
            (KeysetWriteError::Overlap(overlap()), CONFLICT),
            (
                KeysetWriteError::StoredVersion {
                    version_id: "ver_secret".into(),
                    error: JwkSetError::NotJson,
                },
                SERVER,
            ),
            (KeysetWriteError::StoredFingerprintMismatch, SERVER),
            (KeysetWriteError::TooManyEnabledVersions, CONFLICT),
            (KeysetWriteError::PrivateMemberInProvenance, INVALID),
            (KeysetWriteError::UnsupportedIsolation, SERVER),
            (KeysetWriteError::WorkerUnavailable, UNAVAILABLE),
            (KeysetWriteError::ValidationBusy, RETRY),
            (KeysetWriteError::WideningNotAcknowledged, WIDENING),
            (KeysetWriteError::PolicyUnavailable, RETRY),
            (
                KeysetWriteError::Registry(RegistryError::StaleRevision),
                STALE,
            ),
        ]
    }

    fn source_rows() -> Vec<(SourceWriteError, (u16, &'static str, bool))> {
        vec![
            (SourceWriteError::Unauthorized, FORBIDDEN),
            (
                SourceWriteError::InvalidDestination {
                    member: "discovery_url",
                },
                INVALID,
            ),
            (
                SourceWriteError::EgressNotAllowed {
                    member: "discovery_url",
                },
                CONFLICT,
            ),
            (SourceWriteError::UnsupportedIsolation, SERVER),
            (SourceWriteError::WideningNotAcknowledged, WIDENING),
            (SourceWriteError::PolicyUnavailable, RETRY),
            (
                SourceWriteError::Registry(RegistryError::NotFound),
                NOT_FOUND,
            ),
        ]
    }

    #[test]
    fn the_keyset_and_source_tables() {
        check(from_keyset_write, keyset_rows(), 13);
        check(from_source_write, source_rows(), 7);
    }

    #[test]
    fn the_approval_table() {
        let mut rows = vec![
            (ApprovalError::Unauthorized, FORBIDDEN),
            (ApprovalError::NotFound, NOT_FOUND),
            (
                ApprovalError::NotApprovable(NotApprovableReason::Consumed),
                NOT_APPROVABLE,
            ),
            (
                ApprovalError::NotApprovable(NotApprovableReason::Revoked),
                NOT_APPROVABLE,
            ),
            (
                ApprovalError::NotApprovable(NotApprovableReason::Expired),
                NOT_APPROVABLE,
            ),
            (
                ApprovalError::NotApprovable(NotApprovableReason::WrongKind),
                NOT_APPROVABLE,
            ),
            (ApprovalError::SelfApproval, FORBIDDEN),
            (ApprovalError::EchoMismatch, CONFLICT),
            (ApprovalError::RequesterNotAuthorized, CONFLICT),
            (ApprovalError::PlanIntegrity, SERVER),
            (ApprovalError::PolicyUnavailable, RETRY),
            (ApprovalError::StaleRevision, STALE),
            (ApprovalError::UnsupportedIsolation, SERVER),
            (ApprovalError::WideningNotAcknowledged, WIDENING),
        ];
        // Inside an approval, a refusal of the stored plan's values is
        // 409 `not_approvable`, not the direct write's 400; every other
        // row maps as in its family.
        let stored = |err: &RegistryError, expected| match err {
            RegistryError::Invariant {
                kind: InvariantKind::Check | InvariantKind::NotNull,
                ..
            } => NOT_APPROVABLE,
            _ => expected,
        };
        rows.extend(keyset_rows().into_iter().map(|(err, expected)| {
            let expected = match &err {
                KeysetWriteError::Upload(_) | KeysetWriteError::PrivateMemberInProvenance => {
                    NOT_APPROVABLE
                }
                _ => expected,
            };
            (ApprovalError::Keyset(err), expected)
        }));
        rows.extend(source_rows().into_iter().map(|(err, expected)| {
            let expected = match &err {
                SourceWriteError::InvalidDestination { .. } => NOT_APPROVABLE,
                _ => expected,
            };
            (ApprovalError::Source(err), expected)
        }));
        for (err, expected) in registry_rows() {
            let expected = stored(&err, expected);
            rows.push((ApprovalError::Registry(err), expected));
        }
        for (err, expected) in registry_rows() {
            let expected = stored(&err, expected);
            rows.push((
                ApprovalError::Keyset(KeysetWriteError::Registry(err)),
                expected,
            ));
        }
        for (err, expected) in registry_rows() {
            let expected = stored(&err, expected);
            rows.push((
                ApprovalError::Source(SourceWriteError::Registry(err)),
                expected,
            ));
        }
        check(from_approval, rows, 14);
        // The direct writes keep their 400 for the same errors.
        let check_kind = |kind| RegistryError::Invariant {
            kind,
            constraint: None,
        };
        for kind in [InvariantKind::Check, InvariantKind::NotNull] {
            assert_eq!(seen(from_registry(&check_kind(kind))), INVALID);
            assert_eq!(
                seen(from_keyset_write(&KeysetWriteError::Registry(check_kind(
                    kind
                )))),
                INVALID
            );
            assert_eq!(
                seen(from_source_write(&SourceWriteError::Registry(check_kind(
                    kind
                )))),
                INVALID
            );
        }
        assert_eq!(
            seen(from_keyset_write(&KeysetWriteError::Upload(
                JwkSetError::NoKeys
            ))),
            INVALID
        );
        assert_eq!(
            seen(from_source_write(&SourceWriteError::InvalidDestination {
                member: "discovery_url"
            })),
            INVALID
        );
    }

    #[test]
    fn the_operation_read_table() {
        let mut rows = vec![
            (OperationReadError::Unauthenticated, UNAUTHENTICATED),
            (OperationReadError::Unauthorized, FORBIDDEN),
            (OperationReadError::NotFound, NOT_FOUND),
            (OperationReadError::PlanIntegrity, SERVER),
        ];
        rows.extend(
            registry_rows()
                .into_iter()
                .map(|(err, expected)| (OperationReadError::Registry(err), expected)),
        );
        check(from_operation_read, rows, 5);
        // The credential's 401 is the missing peer's, byte for byte.
        assert_eq!(
            from_operation_read(&OperationReadError::Unauthenticated),
            AdminHttpError::UNAUTHENTICATED
        );
    }

    /// Every code has its one status, and the codes are distinct.
    #[test]
    fn the_codes() {
        let table = [
            (ErrorCode::Unauthenticated, UNAUTHENTICATED),
            (ErrorCode::Forbidden, FORBIDDEN),
            (ErrorCode::NotFound, NOT_FOUND),
            (ErrorCode::InvalidRequest, INVALID),
            (ErrorCode::StaleRevision, STALE),
            (ErrorCode::Conflict, CONFLICT),
            (ErrorCode::NotApprovable, NOT_APPROVABLE),
            (ErrorCode::TenantDisabled, TENANT_DISABLED),
            (ErrorCode::WideningNotAcknowledged, WIDENING),
            (ErrorCode::ServerError, SERVER),
            (ErrorCode::AuthUnavailable, UNAVAILABLE),
        ];
        assert_eq!(table.map(|(code, _)| code), ErrorCode::ALL);
        for (code, expected) in table {
            assert_eq!(seen(AdminHttpError::of(code)), expected);
        }
        let names: BTreeSet<_> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        assert_eq!(names.len(), ErrorCode::ALL.len());
        assert_eq!(seen(AdminHttpError::UNAUTHENTICATED), UNAUTHENTICATED);
        assert_eq!(seen(AdminHttpError::NOT_FOUND), NOT_FOUND);
        assert_eq!(seen(AdminHttpError::INVALID_REQUEST), INVALID);
    }

    /// Every not-found of every family is one response, byte for byte.
    #[test]
    fn not_found_is_one_value_everywhere() {
        let all = [
            from_registry(&RegistryError::NotFound),
            from_approval(&ApprovalError::NotFound),
            from_approval(&ApprovalError::Registry(RegistryError::NotFound)),
            from_admin_write(&AdminWriteError::Registry(RegistryError::NotFound)),
            from_operation_read(&OperationReadError::NotFound),
            from_operation_read(&OperationReadError::Registry(RegistryError::NotFound)),
            from_keyset_write(&KeysetWriteError::Registry(RegistryError::NotFound)),
            from_source_write(&SourceWriteError::Registry(RegistryError::NotFound)),
        ];
        for err in all {
            assert_eq!(err, AdminHttpError::NOT_FOUND);
        }
    }

    /// The response: the status, the JSON body with the code only, and
    /// `Retry-After` exactly on a retryable 503. No value of the error (an
    /// ID, a constraint name, a member name) reaches it.
    #[tokio::test]
    async fn the_response_carries_the_code_only() {
        let cases = [
            (
                from_registry(&RegistryError::UnreadableTimestamp {
                    table: "tenant",
                    column: "created_at",
                    id: "ten_secret_marker".into(),
                }),
                "{\"error\":\"server_error\"}",
                None,
            ),
            (
                from_source_write(&SourceWriteError::EgressNotAllowed {
                    member: "discovery_url",
                }),
                "{\"error\":\"conflict\"}",
                None,
            ),
            (
                from_registry(&RegistryError::Retry(other())),
                "{\"error\":\"auth_unavailable\"}",
                Some("1"),
            ),
            (
                from_registry(&database("57014", None)),
                "{\"error\":\"auth_unavailable\"}",
                Some("1"),
            ),
            (
                from_registry(&database("23505", Some("ten_secret_marker_key"))),
                "{\"error\":\"server_error\"}",
                None,
            ),
            (
                from_registry(&RegistryError::Other(other())),
                "{\"error\":\"auth_unavailable\"}",
                None,
            ),
            (
                AdminHttpError::UNAUTHENTICATED,
                "{\"error\":\"unauthenticated\"}",
                None,
            ),
        ];
        for (err, body, retry_after) in cases {
            let response = err.into_response();
            assert_eq!(response.status(), err.status());
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .map(|value| value.to_str().unwrap()),
                retry_after
            );
            let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(bytes, body.as_bytes());
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json.as_object().unwrap().len(), 1);
        }
    }

    #[test]
    fn the_from_impls_are_the_functions() {
        assert_eq!(
            AdminHttpError::from(&AdminWriteError::TenantDisabled),
            from_admin_write(&AdminWriteError::TenantDisabled)
        );
        assert_eq!(
            AdminHttpError::from(&IdError::SourceFailed).code(),
            ErrorCode::ServerError
        );
        assert_eq!(
            AdminHttpError::from(&IdentityError::Empty).code(),
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            AdminHttpError::from(&RegistryError::StaleRevision).code(),
            ErrorCode::StaleRevision
        );
        assert_eq!(
            AdminHttpError::from(&KeysetWriteError::ValidationBusy).retry_after(),
            Some(1)
        );
        assert_eq!(
            AdminHttpError::from(&SourceWriteError::Unauthorized).code(),
            ErrorCode::Forbidden
        );
        assert_eq!(
            AdminHttpError::from(&ApprovalError::SelfApproval).code(),
            ErrorCode::Forbidden
        );
        assert_eq!(
            AdminHttpError::from(&OperationReadError::PlanIntegrity).code(),
            ErrorCode::ServerError
        );
    }
}
