//! The refusal codes of the local transport and the mapping of every error
//! family a request can meet to one of them: one pure function per family,
//! each an exhaustive `match` (a new variant fails the build; only the
//! foreign [`sqlx::Error`] has a catch-all). The table is in the module docs
//! of [`crate::local_transport`], "Errors".

use crate::ids::IdError;
use crate::persistence::registry::{
    BootstrapError, ChallengeError, InvariantKind, RegistryError, RestoreError,
};

/// SQLSTATE class 08, `connection_exception`.
const CONNECTION_EXCEPTION_CLASS: &str = "08";
/// SQLSTATE class 53, `insufficient_resources`.
const INSUFFICIENT_RESOURCES_CLASS: &str = "53";
/// `57P01` to `57P05`, matched as a prefix: the server is shutting down,
/// starting up or dropping the database, or an idle session timed out.
const SHUTDOWN_PREFIX: &str = "57P0";
/// `lock_not_available`: the transaction's `lock_timeout`.
const LOCK_NOT_AVAILABLE: &str = "55P03";
/// `query_canceled`: the transaction's `statement_timeout`.
const QUERY_CANCELED: &str = "57014";

/// The value of a refusal's one member, `error`: a closed set (see the
/// module docs of [`crate::local_transport`], "Errors").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ErrorCode {
    /// The peer's UID is neither the service UID nor root.
    Forbidden,
    /// The request, or one of its values, is malformed.
    InvalidRequest,
    /// The stored state refuses the request: bootstrap is closed, the
    /// instance ID is not the stored one, no challenge can be issued, a
    /// value is already registered.
    Conflict,
    /// The signed response does not authorize a restoration.
    NotRestorable,
    /// The store is unavailable or the transaction must be retried; nothing
    /// was written.
    AuthUnavailable,
    /// A server or data-integrity error; nothing was written.
    ServerError,
}

impl ErrorCode {
    /// Every code.
    pub const ALL: [Self; 6] = [
        Self::Forbidden,
        Self::InvalidRequest,
        Self::Conflict,
        Self::NotRestorable,
        Self::AuthUnavailable,
        Self::ServerError,
    ];

    /// The wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::InvalidRequest => "invalid_request",
            Self::Conflict => "conflict",
            Self::NotRestorable => "not_restorable",
            Self::AuthUnavailable => "auth_unavailable",
            Self::ServerError => "server_error",
        }
    }
}

/// [`IdError`]: every variant is a server error (D1).
pub(super) const fn from_id(err: &IdError) -> ErrorCode {
    match err {
        IdError::SourceFailed | IdError::Exhausted => ErrorCode::ServerError,
    }
}

/// [`InvariantKind`] of a [`RegistryError::Invariant`].
const fn from_invariant(kind: InvariantKind) -> ErrorCode {
    match kind {
        InvariantKind::Check | InvariantKind::NotNull => ErrorCode::InvalidRequest,
        InvariantKind::ForeignKey
        | InvariantKind::AssignmentActive
        | InvariantKind::EgressEntryEnabled => ErrorCode::Conflict,
        InvariantKind::SameTenantOperation | InvariantKind::DistinctApprover => {
            ErrorCode::ServerError
        }
    }
}

/// An unclassified [`sqlx::Error`]: an unavailable store or a timeout of
/// the transaction is `auth_unavailable`, anything else `server_error`
/// (the classes of `crate::admin_http`'s mapping).
pub(super) fn from_store_failure(err: &sqlx::Error) -> ErrorCode {
    match err {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed => ErrorCode::AuthUnavailable,
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some(LOCK_NOT_AVAILABLE | QUERY_CANCELED) => ErrorCode::AuthUnavailable,
            Some(sqlstate)
                if sqlstate.starts_with(CONNECTION_EXCEPTION_CLASS)
                    || sqlstate.starts_with(INSUFFICIENT_RESOURCES_CLASS)
                    || sqlstate.starts_with(SHUTDOWN_PREFIX) =>
            {
                ErrorCode::AuthUnavailable
            }
            _ => ErrorCode::ServerError,
        },
        _ => ErrorCode::ServerError,
    }
}

/// [`RegistryError`]. An encode error (`Other`) is a server error: the
/// transport checks every value it submits before the registry does, so
/// the registry's own checks refuse only what the server supplied (its
/// clock, the audit chain's sequence).
pub(super) fn from_registry(err: &RegistryError) -> ErrorCode {
    match err {
        RegistryError::NotFound
        | RegistryError::StaleRevision
        | RegistryError::AlreadyExists { .. }
        | RegistryError::Guard => ErrorCode::Conflict,
        RegistryError::Invariant { kind, .. } => from_invariant(*kind),
        RegistryError::UnreadableTimestamp { .. } => ErrorCode::ServerError,
        RegistryError::Retry(_) => ErrorCode::AuthUnavailable,
        RegistryError::Other(err) => from_store_failure(err),
        RegistryError::ReservedActorId | RegistryError::RequiredPredicate { .. } => {
            ErrorCode::InvalidRequest
        }
    }
}

/// [`BootstrapError`].
pub(super) fn from_bootstrap(err: &BootstrapError) -> ErrorCode {
    match err {
        BootstrapError::AlreadyClosed | BootstrapError::InstanceIdMismatch => ErrorCode::Conflict,
        BootstrapError::Store(err) => from_registry(err),
    }
}

/// [`ChallengeError`].
pub(super) fn from_challenge(err: &ChallengeError) -> ErrorCode {
    match err {
        ChallengeError::NotIssuable => ErrorCode::Conflict,
        ChallengeError::Store(err) => from_registry(err),
    }
}

/// [`RestoreError`]: every reason is one code, so a refusal says nothing
/// more than "not restorable".
pub(super) fn from_restore(err: &RestoreError) -> ErrorCode {
    match err {
        RestoreError::NotRestorable(_) | RestoreError::RecoveryKeyUnchanged => {
            ErrorCode::NotRestorable
        }
        // The transport begins every transaction at `READ COMMITTED`.
        RestoreError::UnsupportedIsolation => ErrorCode::ServerError,
        RestoreError::Store(err) => from_registry(err),
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, error::Error as StdError, fmt};

    use sqlx::error::{DatabaseError, ErrorKind};

    use super::*;
    use crate::persistence::registry::{NotRestorableReason, PredicateProblem};

    #[derive(Debug)]
    struct FakeDbError(&'static str);

    impl fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("fake")
        }
    }

    impl StdError for FakeDbError {}

    impl DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            "fake"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.0))
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    fn database(sqlstate: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(FakeDbError(sqlstate)))
    }

    #[test]
    fn the_codes_are_closed_and_distinct() {
        let names: Vec<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        assert_eq!(
            names,
            [
                "forbidden",
                "invalid_request",
                "conflict",
                "not_restorable",
                "auth_unavailable",
                "server_error"
            ]
        );
    }

    #[test]
    fn store_failures_are_unavailable_or_server_errors() {
        for err in [
            sqlx::Error::Io(std::io::Error::other("x")),
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            database("08006"),
            database("53300"),
            database("57P01"),
            database("57P05"),
            database("55P03"),
            database("57014"),
        ] {
            assert_eq!(
                from_store_failure(&err),
                ErrorCode::AuthUnavailable,
                "{err:?}"
            );
        }
        for err in [
            sqlx::Error::RowNotFound,
            sqlx::Error::Encode("x".into()),
            sqlx::Error::Protocol("x".into()),
            database("23505"),
            database("22021"),
            database("57000"),
        ] {
            assert_eq!(from_store_failure(&err), ErrorCode::ServerError, "{err:?}");
        }
    }

    #[test]
    fn each_registry_variant_has_its_code() {
        let invariant = |kind| RegistryError::Invariant {
            kind,
            constraint: None,
        };
        for (err, code) in [
            (RegistryError::NotFound, ErrorCode::Conflict),
            (RegistryError::StaleRevision, ErrorCode::Conflict),
            (
                RegistryError::AlreadyExists {
                    constraint: "admin_credential_public_identity_key",
                },
                ErrorCode::Conflict,
            ),
            (RegistryError::Guard, ErrorCode::Conflict),
            (invariant(InvariantKind::Check), ErrorCode::InvalidRequest),
            (invariant(InvariantKind::NotNull), ErrorCode::InvalidRequest),
            (invariant(InvariantKind::ForeignKey), ErrorCode::Conflict),
            (
                invariant(InvariantKind::AssignmentActive),
                ErrorCode::Conflict,
            ),
            (
                invariant(InvariantKind::EgressEntryEnabled),
                ErrorCode::Conflict,
            ),
            (
                invariant(InvariantKind::SameTenantOperation),
                ErrorCode::ServerError,
            ),
            (
                invariant(InvariantKind::DistinctApprover),
                ErrorCode::ServerError,
            ),
            (
                RegistryError::UnreadableTimestamp {
                    table: "t",
                    column: "c",
                    id: "x".into(),
                },
                ErrorCode::ServerError,
            ),
            (
                RegistryError::Retry(database("40001")),
                ErrorCode::AuthUnavailable,
            ),
            (
                RegistryError::Other(sqlx::Error::PoolClosed),
                ErrorCode::AuthUnavailable,
            ),
            (
                RegistryError::Other(sqlx::Error::Encode("audit integer above 2^53 - 1".into())),
                ErrorCode::ServerError,
            ),
            (RegistryError::ReservedActorId, ErrorCode::InvalidRequest),
            (
                RegistryError::RequiredPredicate {
                    claim: "c",
                    problem: PredicateProblem::Missing,
                },
                ErrorCode::InvalidRequest,
            ),
        ] {
            assert_eq!(from_registry(&err), code, "{err:?}");
        }
    }

    #[test]
    fn each_operation_error_has_its_code() {
        assert_eq!(
            from_bootstrap(&BootstrapError::AlreadyClosed),
            ErrorCode::Conflict
        );
        assert_eq!(
            from_bootstrap(&BootstrapError::InstanceIdMismatch),
            ErrorCode::Conflict
        );
        assert_eq!(
            from_bootstrap(&BootstrapError::Store(RegistryError::Retry(database(
                "40P01"
            )))),
            ErrorCode::AuthUnavailable
        );
        assert_eq!(
            from_challenge(&ChallengeError::NotIssuable),
            ErrorCode::Conflict
        );
        assert_eq!(
            from_challenge(&ChallengeError::Store(RegistryError::Other(
                sqlx::Error::PoolClosed
            ))),
            ErrorCode::AuthUnavailable
        );
        for reason in [
            NotRestorableReason::NoRecoveryState,
            NotRestorableReason::NotFound,
            NotRestorableReason::Consumed,
            NotRestorableReason::Revoked,
            NotRestorableReason::Expired,
            NotRestorableReason::WrongKind,
            NotRestorableReason::NotBound,
            NotRestorableReason::NotLibraryEncoding,
            NotRestorableReason::WeakKey,
            NotRestorableReason::BadSignature,
        ] {
            assert_eq!(
                from_restore(&RestoreError::NotRestorable(reason)),
                ErrorCode::NotRestorable,
                "{reason:?}"
            );
        }
        assert_eq!(
            from_restore(&RestoreError::RecoveryKeyUnchanged),
            ErrorCode::NotRestorable
        );
        assert_eq!(
            from_restore(&RestoreError::UnsupportedIsolation),
            ErrorCode::ServerError
        );
        assert_eq!(
            from_restore(&RestoreError::Store(RegistryError::Guard)),
            ErrorCode::Conflict
        );
        assert_eq!(from_id(&IdError::SourceFailed), ErrorCode::ServerError);
        assert_eq!(from_id(&IdError::Exhausted), ErrorCode::ServerError);
    }
}
