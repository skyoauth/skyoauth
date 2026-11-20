//! Typed reads and writes of the registry tables of migrations `0002` to
//! `0004` (T10.1, T10.8): tenants (with their secret namespace), principals,
//! resource servers, audience tenant assignments, resource server checkers
//! with their tenant rows, and resource actions; trust keysets and their
//! versions, trust sources, principal bindings, service identities with
//! their audience rows, and service grants with their binding and audience
//! rows; and, read-only, the instance security policy and the egress
//! allowlist.
//!
//! The module lives under `persistence` because it is the first Rust entry
//! point to the schema that module migrates; later registry tables belong
//! here too (inferred).
//!
//! # Executors and transactions
//!
//! Every function takes any [`PgExecutor`](sqlx::PgExecutor): `&PgPool`,
//! `&mut PgConnection` or `&mut *transaction`, and runs exactly one SQL
//! statement, so each call is atomic on its own and composes with others,
//! such as the audit event of the same write, inside a caller transaction
//! (inferred: free functions instead of a handle type, so the caller owns
//! the transaction). A failed statement aborts the caller's transaction, as
//! any PostgreSQL error does.
//!
//! # IDs, revisions and updates
//!
//! - Writes take caller-supplied IDs and `secret_namespace`; generating them
//!   is T10.2. Rows are created at revision 1 (the database's default).
//! - An update replaces every mutable column of the row with the caller's
//!   values (read, modify, then write back) and is a compare-and-set on the
//!   revision: the caller passes the expected revision, and the statement
//!   sets `revision = expected + 1` where `revision = expected`, as the
//!   `0002` guard `skyoauth_check_revision()` requires. A row at another
//!   revision gives [`RegistryError::StaleRevision`] and changes nothing; a
//!   missing row gives [`RegistryError::NotFound`]. Of two concurrent updates
//!   from the same revision exactly one succeeds: the second waits for the
//!   first's row lock, then finds the revision moved.
//! - Columns the migrations make immutable (IDs, `secret_namespace`,
//!   `audience`, each row's `resource_server_id`, an assignment's
//!   `tenant_id`, an action's `action_name`, a principal's `tenant_id` and
//!   `kind`; in `0004` every `tenant_id`, a source's `kind`, `cluster_id`
//!   and `jwks_keyset_id`, a binding's source and principal, a grant's
//!   actor, target and mode, and every column of a keyset version and of a
//!   list row) are set only on create; no update touches them.
//! - `tenant` and `principal` have no revision column yet (migrations
//!   README, "Not done in `0002`"), so this module offers no update for them:
//!   an update without an expected revision would break API-003 (inferred;
//!   an open question for the coding session).
//! - A checker's tenant set (`allowed_tenant_ids`) changes one row at a time
//!   with [`add_resource_server_checker_tenant`] and
//!   [`remove_resource_server_checker_tenant`]. Each is a compare-and-set on
//!   the checker's revision and advances it in the same statement, since the
//!   rows have no revision of their own (`0003`).
//! - The `0004` list sets change the same way, each a compare-and-set on its
//!   owner's revision: a service identity's audiences
//!   ([`add_service_identity_resource_server`],
//!   [`remove_service_identity_resource_server`]), a grant's allowed
//!   bindings ([`add_service_grant_binding`],
//!   [`remove_service_grant_binding`]) and a grant's audiences
//!   ([`add_service_grant_resource_server`],
//!   [`remove_service_grant_resource_server`]). A service identity and a
//!   grant are created with their initial sets in the same statement.
//! - A trust keyset version has no revision column and is immutable but for
//!   its `status` (`0004`), so this module only creates and reads versions,
//!   as it does tenants (inferred; an open question for the coding
//!   session).
//!
//! # A grant keeps one binding
//!
//! A grant's allowed bindings are never empty (identity-registry section
//! 10). The `0004` constraint trigger checks it when the transaction
//! commits, not at the statement, and fails the commit with `SK001`:
//!
//! - [`create_service_grant`] inserts the grant and its binding rows in one
//!   statement, so a grant created with at least one binding passes on any
//!   executor. With none, a call on a pool or a bare connection, which
//!   commits at once, fails with [`RegistryError::Guard`]; inside a caller
//!   transaction the call succeeds and the commit fails, unless the caller
//!   adds a binding first.
//! - [`remove_service_grant_binding`] of a grant's last binding fails the
//!   same way: at once with [`RegistryError::Guard`] outside a transaction,
//!   at commit inside one, unless a binding is added before.
//!
//! The commit is the caller's: `RegistryError::from` maps its
//! [`sqlx::Error`], so `SK001` at commit is [`RegistryError::Guard`] too.
//! Two concurrent removals from one grant revision serialize on the grant
//! row first: under `READ COMMITTED` the later one is
//! [`RegistryError::StaleRevision`]; under `REPEATABLE READ` and
//! `SERIALIZABLE` PostgreSQL fails the later one with `40001`, which maps
//! to [`RegistryError::Other`] (inferred: no typed retry variant yet).
//!
//! # Reads and pages
//!
//! Instance-owned rows are read by ID; tenant-owned rows (a principal and
//! every `0004` table) by tenant and ID, so a read, update or list-set
//! change with another tenant's ID is [`RegistryError::NotFound`], and a
//! list holds one tenant's rows. Lists are ordered by ID byte-wise
//! (`COLLATE "C"`) and paged with a [`Page`]: at most [`MAX_PAGE_SIZE`]
//! rows after an optional ID cursor. The next page starts after the last
//! ID returned. A keyset's versions are listed per keyset.
//!
//! # Timestamps
//!
//! Timestamps are [`SystemTime`](std::time::SystemTime)s. PostgreSQL keeps
//! microseconds, so a written time is truncated toward the past to a whole
//! microsecond (inferred), and a time outside the range of 64-bit
//! microseconds since the Unix epoch is [`RegistryError::Other`] before any
//! statement runs.
//!
//! # Errors
//!
//! Database errors map to [`RegistryError`] by SQLSTATE and, for constraint
//! errors, by the constraint name, which must be one of
//! [`KNOWN_CONSTRAINTS`] (the named constraints of the migrations README):
//!
//! | SQLSTATE | Condition                                  | Variant                                               |
//! | -------- | ------------------------------------------ | ----------------------------------------------------- |
//! | —        | no row with the ID                         | `NotFound`                                            |
//! | —        | the row is at another revision             | `StaleRevision`                                       |
//! | `23505`  | `unique_violation`                         | `AlreadyExists { constraint }`                        |
//! | `23503`  | `foreign_key_violation`                    | `Invariant { kind: ForeignKey, constraint: Some(_) }` |
//! | `23514`  | `check_violation` (table or list domain)   | `Invariant { kind: Check, constraint: Some(_) }`      |
//! | `23502`  | `not_null_violation`                       | `Invariant { kind: NotNull, constraint: None }`       |
//! | `SK001`  | a guard trigger                            | `Guard`                                               |
//! | other    | anything else, or an unlisted constraint   | `Other(sqlx::Error)`                                  |
//!
//! Error text never includes a value from the request or the row: the
//! variants carry only constraint names, and `Display` and `Debug` of
//! `Other` print only the SQLSTATE. Its [`source`](std::error::Error::source)
//! is the raw [`sqlx::Error`], with the server's message.
//!
//! # Not done here
//!
//! The registry does not authorize (API-147 and the endpoint roles are
//! T14.1 and T14.2), does not write audit events (T13.x; the caller writes
//! the event in the same transaction), does not check rules the database
//! does not enforce (an enabled same-tenant assignment behind a reference,
//! scope and profile vocabulary, leaving a disabled assignment's tenant out
//! of a checker's effective set; migrations README, "What 0003 adds"; the
//! egress check of a source's URLs, secret reference resolution, template
//! predicates, JWK checks, the other scope ceilings and keeping an
//! impersonation grant dormant; "What 0004 adds"), does not generate IDs
//! (T10.2) and does not run migrations.

mod audience;
mod error;
mod grant;
mod instance;
mod model;
mod tenant;
mod trust;

pub use audience::{
    add_resource_server_checker_tenant, create_audience_tenant_assignment, create_resource_action,
    create_resource_server, create_resource_server_checker, get_audience_tenant_assignment,
    get_resource_action, get_resource_server, get_resource_server_checker,
    list_audience_tenant_assignments, list_resource_actions, list_resource_server_checkers,
    list_resource_servers, remove_resource_server_checker_tenant,
    update_audience_tenant_assignment, update_resource_action, update_resource_server,
    update_resource_server_checker,
};
pub use error::{InvariantKind, KNOWN_CONSTRAINTS, RegistryError};
pub use grant::{
    add_service_grant_binding, add_service_grant_resource_server,
    add_service_identity_resource_server, create_principal_binding, create_service_grant,
    create_service_identity, get_principal_binding, get_service_grant, get_service_identity,
    list_principal_bindings, list_service_grants, list_service_identities,
    remove_service_grant_binding, remove_service_grant_resource_server,
    remove_service_identity_resource_server, update_principal_binding, update_service_grant,
    update_service_identity,
};
pub use instance::{
    get_egress_allowlist_entry, get_instance_security_policy, list_egress_allowlist_entries,
};
pub use model::{
    ActivationState, AssertionProfile, AudienceTenantAssignment, AudienceTenantAssignmentChanges,
    BindingProfile, EgressAllowlistEntry, EgressPurpose, GrantMode, InstanceSecurityPolicy,
    JsonObject, NewAudienceTenantAssignment, NewPrincipal, NewPrincipalBinding, NewResourceAction,
    NewResourceServer, NewResourceServerChecker, NewServiceGrant, NewServiceIdentity, NewTenant,
    NewTrustKeyset, NewTrustKeysetVersion, NewTrustSource, Principal, PrincipalBinding,
    PrincipalBindingChanges, PrincipalKind, Profile, ReplayMode, ResourceAction,
    ResourceActionChanges, ResourceServer, ResourceServerChanges, ResourceServerChecker,
    ResourceServerCheckerChanges, ServiceGrant, ServiceGrantChanges, ServiceIdentity,
    ServiceIdentityChanges, Status, Tenant, TrustKeyset, TrustKeysetChanges, TrustKeysetVersion,
    TrustSource, TrustSourceChanges, TrustSourceKind, UnknownValue,
};
pub use tenant::{
    create_principal, create_tenant, get_principal, get_tenant, list_principals, list_tenants,
};
pub use trust::{
    create_trust_keyset, create_trust_keyset_version, create_trust_source, get_trust_keyset,
    get_trust_keyset_version, get_trust_source, list_trust_keyset_versions, list_trust_keysets,
    list_trust_sources, update_trust_keyset, update_trust_source,
};

use sqlx::{FromRow, Row, postgres::PgRow};

/// The largest page a list returns (inferred).
pub const MAX_PAGE_SIZE: u32 = 500;

/// One page of a list: at most `limit` rows whose ID sorts byte-wise after
/// `after_id`, or from the first row when there is no cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page<'a> {
    after_id: Option<&'a str>,
    limit: u32,
}

impl<'a> Page<'a> {
    /// The first `limit` rows. `limit` is clamped to `1..=MAX_PAGE_SIZE`.
    pub fn first(limit: u32) -> Self {
        Self {
            after_id: None,
            limit: limit.clamp(1, MAX_PAGE_SIZE),
        }
    }

    /// The `limit` rows after the row with ID `after_id`, which need not
    /// exist. `limit` is clamped to `1..=MAX_PAGE_SIZE`.
    pub fn after(after_id: &'a str, limit: u32) -> Self {
        Self {
            after_id: Some(after_id),
            ..Self::first(limit)
        }
    }

    /// The cursor, if any.
    pub fn after_id(&self) -> Option<&'a str> {
        self.after_id
    }

    /// The clamped page size.
    pub fn limit(&self) -> u32 {
        self.limit
    }
}

/// The columns of a compare-and-set update of `$table`: `$set` assigns the
/// mutable columns from `$3` on, `$1` is the ID and `$2` the expected
/// revision. The statement returns one row: the updated columns, or `NULL`s
/// when nothing matched, and `found`, whether a row with the ID exists.
macro_rules! compare_and_set {
    ($table:literal, $set:literal, $columns:expr) => {
        concat!(
            "WITH updated AS (UPDATE ",
            $table,
            " SET ",
            $set,
            ", revision = $2 + 1 WHERE id = $1 AND revision = $2 RETURNING ",
            $columns,
            ") SELECT updated.*, EXISTS (SELECT FROM ",
            $table,
            " WHERE id = $1) AS found FROM (SELECT) AS one LEFT JOIN updated ON true"
        )
    };
}
use compare_and_set;

/// [`compare_and_set!`] for a tenant-owned `$table`: `$3` is the tenant,
/// and `$set` assigns the mutable columns from `$4` on. A row of another
/// tenant is not found.
macro_rules! tenant_compare_and_set {
    ($table:literal, $set:literal, $columns:expr) => {
        concat!(
            "WITH updated AS (UPDATE ",
            $table,
            " SET ",
            $set,
            ", revision = $2 + 1 WHERE id = $1 AND revision = $2 AND tenant_id = $3 RETURNING ",
            $columns,
            ") SELECT updated.*, EXISTS (SELECT FROM ",
            $table,
            " WHERE id = $1 AND tenant_id = $3) AS found FROM (SELECT) AS one LEFT JOIN updated ON true"
        )
    };
}
use tenant_compare_and_set;

/// `SELECT $columns FROM $table` for one [`Page`]: `$1` is the cursor and
/// `$2` the limit.
macro_rules! list_page {
    ($table:literal, $columns:expr) => {
        concat!(
            "SELECT ",
            $columns,
            " FROM ",
            $table,
            " WHERE $1::text IS NULL OR id > $1 COLLATE \"C\" ORDER BY id COLLATE \"C\" LIMIT $2"
        )
    };
}
use list_page;

/// [`list_page!`] for a tenant-owned `$table`: `$1` is the tenant, `$2` the
/// cursor and `$3` the limit.
macro_rules! tenant_list_page {
    ($table:literal, $columns:expr) => {
        concat!(
            "SELECT ",
            $columns,
            " FROM ",
            $table,
            " WHERE tenant_id = $1 AND ($2::text IS NULL OR id > $2 COLLATE \"C\") \
             ORDER BY id COLLATE \"C\" LIMIT $3"
        )
    };
}
use tenant_list_page;

/// The outcome of a [`compare_and_set!`] statement.
fn updated<T>(row: &PgRow) -> Result<T, RegistryError>
where
    T: for<'r> FromRow<'r, PgRow>,
{
    if row.try_get::<Option<&str>, _>("id")?.is_some() {
        Ok(T::from_row(row)?)
    } else if row.try_get("found")? {
        Err(RegistryError::StaleRevision)
    } else {
        Err(RegistryError::NotFound)
    }
}

/// The outcome of a list-set change (a checker's tenants, a service
/// identity's audiences, a grant's bindings or audiences): the owner's new
/// `revision`, or why nothing changed. `current_revision` (the owner's, or
/// `NULL` when there is no owner) and `listed` (whether the row is in the
/// set; always true for an add) are read from the statement's snapshot, so
/// when both say the change should have applied, a concurrent write moved
/// the revision first.
fn list_change(row: &PgRow, expected: i64) -> Result<i64, RegistryError> {
    if let Some(revision) = row.try_get("revision")? {
        return Ok(revision);
    }
    match row.try_get::<Option<i64>, _>("current_revision")? {
        None => Err(RegistryError::NotFound),
        Some(current) if current != expected => Err(RegistryError::StaleRevision),
        Some(_) if !row.try_get::<bool, _>("listed")? => Err(RegistryError::NotFound),
        Some(_) => Err(RegistryError::StaleRevision),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limits_are_clamped() {
        assert_eq!(Page::first(0).limit(), 1);
        assert_eq!(Page::first(1).limit(), 1);
        assert_eq!(Page::first(MAX_PAGE_SIZE).limit(), MAX_PAGE_SIZE);
        assert_eq!(Page::first(MAX_PAGE_SIZE + 1).limit(), MAX_PAGE_SIZE);
        assert_eq!(Page::first(10).after_id(), None);
        let page = Page::after("ten_b", u32::MAX);
        assert_eq!(page.after_id(), Some("ten_b"));
        assert_eq!(page.limit(), MAX_PAGE_SIZE);
    }

    #[test]
    fn compare_and_set_sets_revision_to_expected_plus_one_where_it_matches() {
        let sql = compare_and_set!("t", "a = $3", "id, a, revision");
        assert_eq!(
            sql,
            "WITH updated AS (UPDATE t SET a = $3, revision = $2 + 1 \
             WHERE id = $1 AND revision = $2 RETURNING id, a, revision) \
             SELECT updated.*, EXISTS (SELECT FROM t WHERE id = $1) AS found \
             FROM (SELECT) AS one LEFT JOIN updated ON true"
        );
    }

    #[test]
    fn tenant_compare_and_set_also_matches_and_finds_by_tenant() {
        let sql = tenant_compare_and_set!("t", "a = $4", "id, a, revision");
        assert_eq!(
            sql,
            "WITH updated AS (UPDATE t SET a = $4, revision = $2 + 1 \
             WHERE id = $1 AND revision = $2 AND tenant_id = $3 RETURNING id, a, revision) \
             SELECT updated.*, EXISTS (SELECT FROM t WHERE id = $1 AND tenant_id = $3) AS found \
             FROM (SELECT) AS one LEFT JOIN updated ON true"
        );
    }

    #[test]
    fn tenant_list_page_filters_by_tenant_before_the_cursor() {
        assert_eq!(
            tenant_list_page!("t", "id, a"),
            "SELECT id, a FROM t WHERE tenant_id = $1 AND ($2::text IS NULL OR id > $2 \
             COLLATE \"C\") ORDER BY id COLLATE \"C\" LIMIT $3"
        );
    }
}
