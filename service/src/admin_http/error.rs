//! The admin error-to-HTTP mapping: one pure function per error family,
//! each an exhaustive `match` (a new variant fails the build), and the one
//! response shape. The whole table is in the module docs of
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

/// [`RegistryError`].
pub const fn from_registry(err: &RegistryError) -> AdminHttpError {
    match err {
        RegistryError::NotFound => AdminHttpError::NOT_FOUND,
        RegistryError::StaleRevision => code(ErrorCode::StaleRevision),
        RegistryError::AlreadyExists { .. } | RegistryError::Guard => code(ErrorCode::Conflict),
        RegistryError::Invariant { kind, .. } => from_invariant(*kind),
        RegistryError::UnreadableTimestamp { .. } => code(ErrorCode::ServerError),
        RegistryError::Retry(_) => AdminHttpError::retry(ErrorCode::AuthUnavailable),
        RegistryError::Other(_) => code(ErrorCode::AuthUnavailable),
        RegistryError::ReservedActorId | RegistryError::RequiredPredicate { .. } => {
            code(ErrorCode::InvalidRequest)
        }
    }
}

/// [`AdminWriteError`].
pub const fn from_admin_write(err: &AdminWriteError) -> AdminHttpError {
    match err {
        AdminWriteError::Unauthorized | AdminWriteError::PrincipalKindNotAllowed => {
            code(ErrorCode::Forbidden)
        }
        AdminWriteError::UnsupportedIsolation => code(ErrorCode::ServerError),
        AdminWriteError::TenantDisabled => code(ErrorCode::TenantDisabled),
        AdminWriteError::PublicKey(err) => from_identity(err),
        AdminWriteError::Id(err) => from_id(err),
        AdminWriteError::Registry(err) => from_registry(err),
    }
}

/// [`KeysetWriteError`], also inside [`ApprovalError::Keyset`].
pub const fn from_keyset_write(err: &KeysetWriteError) -> AdminHttpError {
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
        KeysetWriteError::ValidationBusy | KeysetWriteError::PolicyUnavailable => {
            AdminHttpError::retry(ErrorCode::AuthUnavailable)
        }
        KeysetWriteError::WideningNotAcknowledged => code(ErrorCode::WideningNotAcknowledged),
        KeysetWriteError::Registry(err) => from_registry(err),
    }
}

/// [`SourceWriteError`], also inside [`ApprovalError::Source`].
pub const fn from_source_write(err: &SourceWriteError) -> AdminHttpError {
    match err {
        SourceWriteError::Unauthorized => code(ErrorCode::Forbidden),
        SourceWriteError::InvalidDestination { .. } => code(ErrorCode::InvalidRequest),
        SourceWriteError::EgressNotAllowed { .. } => code(ErrorCode::Conflict),
        SourceWriteError::UnsupportedIsolation => code(ErrorCode::ServerError),
        SourceWriteError::WideningNotAcknowledged => code(ErrorCode::WideningNotAcknowledged),
        SourceWriteError::PolicyUnavailable => AdminHttpError::retry(ErrorCode::AuthUnavailable),
        SourceWriteError::Registry(err) => from_registry(err),
    }
}

/// [`ApprovalError`]: the approve, cancel, reject and toggle.
pub const fn from_approval(err: &ApprovalError) -> AdminHttpError {
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
        ApprovalError::PolicyUnavailable => AdminHttpError::retry(ErrorCode::AuthUnavailable),
        ApprovalError::WideningNotAcknowledged => code(ErrorCode::WideningNotAcknowledged),
        ApprovalError::Keyset(err) => from_keyset_write(err),
        ApprovalError::Source(err) => from_source_write(err),
        ApprovalError::Registry(err) => from_registry(err),
    }
}

/// [`OperationReadError`]: the operation reads.
pub const fn from_operation_read(err: &OperationReadError) -> AdminHttpError {
    match err {
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
            (AdminWriteError::PublicKey(IdentityError::NotDer), INVALID),
            (AdminWriteError::Id(IdError::SourceFailed), SERVER),
            (AdminWriteError::Id(IdError::Exhausted), SERVER),
        ];
        rows.extend(
            registry_rows()
                .into_iter()
                .map(|(err, expected)| (AdminWriteError::Registry(err), expected)),
        );
        check(from_admin_write, rows, 7);
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
        rows.extend(
            keyset_rows()
                .into_iter()
                .map(|(err, expected)| (ApprovalError::Keyset(err), expected)),
        );
        rows.extend(
            source_rows()
                .into_iter()
                .map(|(err, expected)| (ApprovalError::Source(err), expected)),
        );
        rows.extend(
            registry_rows()
                .into_iter()
                .map(|(err, expected)| (ApprovalError::Registry(err), expected)),
        );
        check(from_approval, rows, 14);
    }

    #[test]
    fn the_operation_read_table() {
        let mut rows = vec![
            (OperationReadError::Unauthorized, FORBIDDEN),
            (OperationReadError::NotFound, NOT_FOUND),
            (OperationReadError::PlanIntegrity, SERVER),
        ];
        rows.extend(
            registry_rows()
                .into_iter()
                .map(|(err, expected)| (OperationReadError::Registry(err), expected)),
        );
        check(from_operation_read, rows, 4);
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
