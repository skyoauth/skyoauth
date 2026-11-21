//! Typed errors of the registry functions and their SQLSTATE mapping.

use std::{borrow::Cow, error::Error as StdError, fmt};

use sqlx::error::DatabaseError;

/// `unique_violation`.
const UNIQUE_VIOLATION: &str = "23505";
/// `foreign_key_violation`.
const FOREIGN_KEY_VIOLATION: &str = "23503";
/// `check_violation`, also raised by a domain's `CHECK`.
const CHECK_VIOLATION: &str = "23514";
/// `not_null_violation`.
const NOT_NULL_VIOLATION: &str = "23502";
/// The project SQLSTATE every guard trigger raises (migrations README,
/// "Conventions").
const GUARD: &str = "SK001";

/// Every constraint of the tables the registry writes (`tenant`,
/// `principal` and the five `0003` tables) and of the three list domains,
/// as migrations `0002` to `0004` name them, sorted. A unique, foreign key
/// or check violation maps to a typed variant only for a name listed here.
/// The database test `registry_constraint_names_match_the_catalog` keeps the
/// list equal to the catalog.
pub const KNOWN_CONSTRAINTS: &[&str] = &[
    "audience_tenant_assignment_constraint_versions_check",
    "audience_tenant_assignment_id_check",
    "audience_tenant_assignment_id_octet_length_check",
    "audience_tenant_assignment_pkey",
    "audience_tenant_assignment_resource_server_id_fkey",
    "audience_tenant_assignment_revision_check",
    "audience_tenant_assignment_server_id_octet_length_check",
    "audience_tenant_assignment_status_check",
    "audience_tenant_assignment_tenant_id_fkey",
    "audience_tenant_assignment_tenant_id_octet_length_check",
    "audience_tenant_assignment_tenant_id_resource_server_id_key",
    "principal_id_check",
    "principal_id_octet_length_check",
    "principal_kind_check",
    "principal_name_check",
    "principal_pkey",
    "principal_status_check",
    "principal_tenant_id_fkey",
    "principal_tenant_id_id_key",
    "principal_tenant_id_id_kind_key",
    "principal_tenant_id_octet_length_check",
    "resource_action_action_name_check",
    "resource_action_action_name_no_space_check",
    "resource_action_action_name_octet_length_check",
    "resource_action_id_check",
    "resource_action_id_octet_length_check",
    "resource_action_pkey",
    "resource_action_resource_server_id_action_name_key",
    "resource_action_resource_server_id_fkey",
    "resource_action_resource_server_id_octet_length_check",
    "resource_action_revision_check",
    "resource_action_status_check",
    "resource_server_audience_check",
    "resource_server_audience_key",
    "resource_server_audience_no_space_check",
    "resource_server_audience_octet_length_check",
    "resource_server_checker_id_check",
    "resource_server_checker_id_octet_length_check",
    "resource_server_checker_id_resource_server_id_key",
    "resource_server_checker_pkey",
    "resource_server_checker_public_mtls_identity_check",
    "resource_server_checker_public_mtls_identity_key",
    "resource_server_checker_public_mtls_identity_octet_length_check",
    "resource_server_checker_resource_server_id_fkey",
    "resource_server_checker_resource_server_id_octet_length_check",
    "resource_server_checker_revision_check",
    "resource_server_checker_status_check",
    "resource_server_checker_tenant_assignment_fkey",
    "resource_server_checker_tenant_checker_fkey",
    "resource_server_checker_tenant_checker_id_octet_length_check",
    "resource_server_checker_tenant_pkey",
    "resource_server_checker_tenant_server_id_octet_length_check",
    "resource_server_checker_tenant_tenant_id_octet_length_check",
    "resource_server_constraint_versions_check",
    "resource_server_id_check",
    "resource_server_id_octet_length_check",
    "resource_server_name_check",
    "resource_server_pkey",
    "resource_server_revision_check",
    "resource_server_status_check",
    "skyoauth_profile_list_check",
    "skyoauth_scope_list_check",
    "skyoauth_string_list_check",
    "tenant_id_check",
    "tenant_id_octet_length_check",
    "tenant_name_check",
    "tenant_pkey",
    "tenant_secret_namespace_check",
    "tenant_secret_namespace_key",
    "tenant_secret_namespace_octet_length_check",
    "tenant_status_check",
];

/// The error of a registry function.
///
/// The variants carry only constraint names from [`KNOWN_CONSTRAINTS`],
/// never a value from the request or the row, and `Display` and `Debug`
/// print nothing else. The database's own message for an unmapped error is
/// reachable only through [`std::error::Error::source`] of
/// [`RegistryError::Other`]: that source is the raw [`sqlx::Error`], whose
/// message and detail may quote request or row values, so logging must not
/// walk the source chain.
pub enum RegistryError {
    /// No row has the given ID (in the given tenant, for a tenant-owned
    /// table), or a checker does not list the tenant to remove.
    NotFound,
    /// The row exists, but its revision is not the expected one: another
    /// write came first. Nothing was changed.
    StaleRevision,
    /// A unique key (`23505`) already holds the value: the primary key or
    /// another unique constraint, named by `constraint`.
    AlreadyExists {
        /// The violated constraint, for example `tenant_secret_namespace_key`.
        constraint: &'static str,
    },
    /// A foreign key (`23503`), check (`23514`) or not-null (`23502`)
    /// constraint rejected the write.
    Invariant {
        /// Which kind of constraint.
        kind: InvariantKind,
        /// The violated constraint, so callers can tell a length bound
        /// (`…_octet_length_check`) from a character rule (`…_no_space_check`)
        /// or a list domain (`skyoauth_scope_list_check`). `None` for a
        /// not-null violation, which PostgreSQL does not name.
        constraint: Option<&'static str>,
    },
    /// A guard trigger rejected the write (`SK001`), for example a change to
    /// an immutable column or a revision that does not advance by one.
    Guard,
    /// Any other error: a connection or decode failure, an unexpected
    /// SQLSTATE, or a constraint missing from [`KNOWN_CONSTRAINTS`].
    Other(sqlx::Error),
}

/// The kind of constraint behind [`RegistryError::Invariant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantKind {
    /// `23503`: a referenced row does not exist, for example a checker
    /// tenant without an assignment of the checker's resource server.
    ForeignKey,
    /// `23514`: a table or domain `CHECK`.
    Check,
    /// `23502`: a required column is `NULL`.
    NotNull,
}

impl InvariantKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ForeignKey => "foreign key",
            Self::Check => "check",
            Self::NotNull => "not-null",
        }
    }
}

/// The constraint name as listed in [`KNOWN_CONSTRAINTS`].
fn known_constraint(name: &str) -> Option<&'static str> {
    KNOWN_CONSTRAINTS
        .binary_search(&name)
        .ok()
        .map(|index| KNOWN_CONSTRAINTS[index])
}

/// The typed error for a database error, or `None` when it maps to
/// [`RegistryError::Other`].
fn classify(error: &dyn DatabaseError) -> Option<RegistryError> {
    let named = || error.constraint().and_then(known_constraint);
    Some(match error.code()?.as_ref() {
        UNIQUE_VIOLATION => RegistryError::AlreadyExists {
            constraint: named()?,
        },
        FOREIGN_KEY_VIOLATION => RegistryError::Invariant {
            kind: InvariantKind::ForeignKey,
            constraint: Some(named()?),
        },
        CHECK_VIOLATION => RegistryError::Invariant {
            kind: InvariantKind::Check,
            constraint: Some(named()?),
        },
        NOT_NULL_VIOLATION => RegistryError::Invariant {
            kind: InvariantKind::NotNull,
            constraint: None,
        },
        GUARD => RegistryError::Guard,
        _ => return None,
    })
}

impl From<sqlx::Error> for RegistryError {
    fn from(error: sqlx::Error) -> Self {
        match error.as_database_error().and_then(classify) {
            Some(mapped) => mapped,
            None => Self::Other(error),
        }
    }
}

impl RegistryError {
    /// The SQLSTATE of an [`RegistryError::Other`] database error.
    fn other_sqlstate(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Other(error) => error.as_database_error()?.code(),
            _ => None,
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "registry row not found"),
            Self::StaleRevision => write!(
                f,
                "registry row is not at the expected revision; read it again"
            ),
            Self::AlreadyExists { constraint } => {
                write!(f, "registry row already exists (unique {constraint})")
            }
            Self::Invariant {
                kind,
                constraint: Some(constraint),
            } => write!(
                f,
                "registry write violates {} constraint {constraint}",
                kind.as_str()
            ),
            Self::Invariant {
                kind,
                constraint: None,
            } => write!(f, "registry write violates a {} constraint", kind.as_str()),
            Self::Guard => write!(f, "registry write rejected by a schema guard (SK001)"),
            Self::Other(_) => match self.other_sqlstate() {
                Some(code) => write!(f, "registry database error (SQLSTATE {code})"),
                None => write!(f, "registry database error"),
            },
        }
    }
}

/// Like `Display`, `Debug` leaves out the wrapped [`sqlx::Error`], whose
/// `Debug` includes the server's detail line (the key values of a
/// violation).
impl fmt::Debug for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("NotFound"),
            Self::StaleRevision => f.write_str("StaleRevision"),
            Self::AlreadyExists { constraint } => f
                .debug_struct("AlreadyExists")
                .field("constraint", constraint)
                .finish(),
            Self::Invariant { kind, constraint } => f
                .debug_struct("Invariant")
                .field("kind", kind)
                .field("constraint", constraint)
                .finish(),
            Self::Guard => f.write_str("Guard"),
            Self::Other(_) => f
                .debug_struct("Other")
                .field("sqlstate", &self.other_sqlstate())
                .finish_non_exhaustive(),
        }
    }
}

impl StdError for RegistryError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::error::ErrorKind;

    /// A database error with a chosen SQLSTATE and constraint, and a message
    /// and detail that stand for user-supplied values.
    #[derive(Debug)]
    struct FakeDbError {
        code: Option<&'static str>,
        constraint: Option<&'static str>,
    }

    const SECRET: &str = "user-value-ns_secret";

    impl fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Key (secret_namespace)=({SECRET}) already exists")
        }
    }

    impl StdError for FakeDbError {}

    impl DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            SECRET
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.map(Cow::Borrowed)
        }
        fn constraint(&self) -> Option<&str> {
            self.constraint
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

    fn map(code: Option<&'static str>, constraint: Option<&'static str>) -> RegistryError {
        RegistryError::from(sqlx::Error::database(FakeDbError { code, constraint }))
    }

    fn assert_redacted(error: &RegistryError) {
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("user-value"), "{text}");
        }
    }

    #[test]
    fn known_constraints_are_sorted_and_unique() {
        assert!(KNOWN_CONSTRAINTS.windows(2).all(|w| w[0] < w[1]));
        for name in KNOWN_CONSTRAINTS {
            assert_eq!(known_constraint(name), Some(*name));
        }
        assert_eq!(known_constraint("tenant_pkey_x"), None);
        assert_eq!(known_constraint(""), None);
    }

    #[test]
    fn unique_violation_maps_to_already_exists_with_its_constraint() {
        let error = map(Some("23505"), Some("tenant_secret_namespace_key"));
        assert!(matches!(
            error,
            RegistryError::AlreadyExists {
                constraint: "tenant_secret_namespace_key"
            }
        ));
        assert_eq!(
            error.to_string(),
            "registry row already exists (unique tenant_secret_namespace_key)"
        );
        assert_redacted(&error);
    }

    #[test]
    fn foreign_key_violation_maps_to_invariant_with_its_constraint() {
        let error = map(
            Some("23503"),
            Some("resource_server_checker_tenant_assignment_fkey"),
        );
        assert!(matches!(
            error,
            RegistryError::Invariant {
                kind: InvariantKind::ForeignKey,
                constraint: Some("resource_server_checker_tenant_assignment_fkey")
            }
        ));
        assert_eq!(
            error.to_string(),
            "registry write violates foreign key constraint \
             resource_server_checker_tenant_assignment_fkey"
        );
        assert_redacted(&error);
    }

    #[test]
    fn check_violation_keeps_the_name_that_tells_bound_from_character_rule() {
        for name in [
            "resource_server_audience_octet_length_check",
            "resource_server_audience_no_space_check",
            "skyoauth_scope_list_check",
        ] {
            let error = map(Some("23514"), Some(name));
            match &error {
                RegistryError::Invariant {
                    kind: InvariantKind::Check,
                    constraint: Some(constraint),
                } => assert_eq!(*constraint, name),
                other => panic!("{other:?}"),
            }
            assert_redacted(&error);
        }
    }

    #[test]
    fn not_null_violation_maps_to_invariant_without_a_name() {
        let error = map(Some("23502"), None);
        assert!(matches!(
            error,
            RegistryError::Invariant {
                kind: InvariantKind::NotNull,
                constraint: None
            }
        ));
        assert_eq!(
            error.to_string(),
            "registry write violates a not-null constraint"
        );
    }

    #[test]
    fn guard_sqlstate_maps_to_guard() {
        let error = map(Some("SK001"), None);
        assert!(matches!(error, RegistryError::Guard));
        assert_eq!(
            error.to_string(),
            "registry write rejected by a schema guard (SK001)"
        );
        assert_redacted(&error);
    }

    #[test]
    fn unknown_constraints_and_codes_map_to_other_without_their_message() {
        for (code, constraint) in [
            (Some("23505"), Some("some_later_table_key")),
            (Some("23505"), None),
            (Some("23503"), Some("some_later_table_fkey")),
            (Some("23514"), None),
            (Some("54000"), None),
            (Some("P0001"), None),
            (None, Some("tenant_pkey")),
        ] {
            let error = map(code, constraint);
            assert!(matches!(error, RegistryError::Other(_)), "{error:?}");
            assert!(error.source().is_some());
            assert_redacted(&error);
        }
        let error = map(Some("54000"), None);
        assert_eq!(
            error.to_string(),
            "registry database error (SQLSTATE 54000)"
        );
        assert_eq!(
            format!("{error:?}"),
            r#"Other { sqlstate: Some("54000"), .. }"#
        );
    }

    #[test]
    fn non_database_errors_map_to_other() {
        let error = RegistryError::from(sqlx::Error::PoolTimedOut);
        assert!(matches!(error, RegistryError::Other(_)));
        assert_eq!(error.to_string(), "registry database error");
        assert_eq!(format!("{error:?}"), "Other { sqlstate: None, .. }");
    }

    #[test]
    fn plain_outcomes_display_without_values() {
        assert_eq!(
            RegistryError::NotFound.to_string(),
            "registry row not found"
        );
        assert_eq!(format!("{:?}", RegistryError::NotFound), "NotFound");
        assert_eq!(
            RegistryError::StaleRevision.to_string(),
            "registry row is not at the expected revision; read it again"
        );
        assert_eq!(
            format!("{:?}", RegistryError::StaleRevision),
            "StaleRevision"
        );
        assert!(RegistryError::Guard.source().is_none());
    }
}
