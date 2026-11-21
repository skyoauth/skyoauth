//! Typed reads and writes of the registry tables of migrations `0002` to
//! `0005` (T10.1, T10.8, T10.9): tenants (with their secret namespace),
//! principals, resource servers, audience tenant assignments, resource
//! server checkers with their tenant rows, and resource actions; trust
//! keysets and their versions, trust sources, principal bindings, service
//! identities with their audience rows, and service grants with their
//! binding and audience rows; the consumed single-use proofs
//! (`consumed_assertion`, insert only); and, read-only, the instance
//! security policy and the egress allowlist. [`select_grant`] and
//! [`match_binding`] select a grant and its matching binding for the
//! workload exchange (ADR-015 item 4 steps 1, 3 and 4; see their module).
//! [`load_scope_ceilings`] loads the scope ceilings of an exchange and
//! [`resolve_scopes`] applies them (IR-062, IR-063, IR-083; see their
//! modules).
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
//!   values (read, modify, then write back); [`update_tenant`] and
//!   [`update_principal`] instead take a patch of the columns to change
//!   (lead ruling, 2026-11-21). Every update is a compare-and-set on the
//!   revision: the caller passes the expected revision, and the statement
//!   sets `revision = revision + 1` where `revision = expected`, so the row
//!   moves to `expected + 1` as the `0002` guard `skyoauth_check_revision()`
//!   requires. The expected revision is only compared, never computed with,
//!   so any `i64`, `i64::MAX` included, is a valid argument. A row at
//!   another revision gives [`RegistryError::StaleRevision`] and changes
//!   nothing; a missing row gives [`RegistryError::NotFound`]. Only a row
//!   already at revision `i64::MAX` cannot advance: an update or list-set
//!   change of it with expected revision `i64::MAX` gives
//!   [`RegistryError::Other`] with SQLSTATE `22003`
//!   (`numeric_value_out_of_range`) from `revision + 1`, on every table.
//!   That is unreachable in practice, since revisions start at 1 and
//!   advance by 1.
//! - Under `READ COMMITTED`, PostgreSQL's default, of two concurrent updates
//!   from the same revision exactly one succeeds: the second waits for the
//!   first's row lock, then finds the revision moved and gives
//!   [`RegistryError::StaleRevision`]. In a caller transaction at
//!   `REPEATABLE READ` or `SERIALIZABLE` the second instead fails with
//!   SQLSTATE `40001` (`serialization_failure`), which is
//!   [`RegistryError::Retry`]: it means "retry the whole transaction", not
//!   "read the row again", so it is deliberately not mapped to
//!   `StaleRevision`.
//! - Columns the migrations make immutable (IDs, `secret_namespace`,
//!   `audience`, each row's `resource_server_id`, an assignment's
//!   `tenant_id`, an action's `action_name`, a principal's `tenant_id` and
//!   `kind`; in `0004` every `tenant_id`, a source's `kind`, `cluster_id`
//!   and `jwks_keyset_id`, a binding's source and principal, a grant's
//!   actor, target and mode, and every column of a list row) are set only
//!   on create; no update touches them. A tenant's `secret_namespace` and
//!   `created_at` and a principal's `created_at` are immutable too; a
//!   tenant's and a principal's `name` and `status` are mutable (lead
//!   ruling, 2026-11-21). Of a keyset version only `status` changes, with
//!   [`update_trust_keyset_version`].
//! - [`update_tenant`] and [`update_principal`] take a patch: only the
//!   columns set in it change. An empty patch is an encode error,
//!   [`RegistryError::Other`], before any statement runs, so it neither
//!   reaches the database nor advances the revision (lead ruling,
//!   2026-11-21). A patch that sets a column to its current value still
//!   advances the revision (inferred).
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
//! - A trust keyset version is immutable but for its `status` (`0004`).
//!   [`update_trust_keyset_version`] enables or disables it as a
//!   compare-and-set on the version's own revision (added by `0007`), like
//!   the other tables, with no tie to the keyset's revision (lead decision,
//!   2026-11-21).
//! - Disabling and re-enabling a tenant, a principal or a keyset version is
//!   a plain status change here. Whether re-enabling needs an approval, and
//!   any other widening rule, belongs to the service layer (provisional
//!   lead pick, 2026-11-21).
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
//! to [`RegistryError::Retry`].
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
//! microsecond (inferred), and a time outside the range the `0007` checks
//! hold, from `-210_866_803_200_000_000` (`4714-11-24 00:00:00+00 BC`) to
//! `i64::MAX - 1` microseconds from the Unix epoch, is
//! [`RegistryError::Other`] before any statement runs.
//!
//! The `0007` range checks keep every stored time inside that range. A row
//! written while a check was dropped (or left in place by a `NOT VALID`
//! re-add), or read from a schema not yet migrated to `0007`, can still
//! hold `infinity`, `-infinity` or a later finite time. A read of such a
//! row, by a get, a list or an update's returned row, is
//! [`RegistryError::UnreadableTimestamp`] naming the table, the column and
//! the row's ID, instead of failing the whole statement with `0A000` or
//! `22003` (lead ruling, 2026-11-21). A list stops at the first such row
//! (inferred).
//!
//! An update that leaves such a column untouched ([`update_tenant`],
//! [`update_principal`] and [`update_trust_keyset_version`], none of which
//! writes a timestamp) behaves in one of two ways:
//!
//! - With a range check in force but `NOT VALID`, PostgreSQL checks the
//!   whole new row, so the update fails with `23514` naming the range check
//!   ([`RegistryError::Invariant`]) and changes nothing.
//! - With the check dropped, the update applies its write and then returns
//!   [`RegistryError::UnreadableTimestamp`] for the row it read back. On a
//!   pool or a bare connection the write is committed; inside a caller
//!   transaction the caller can roll it back.
//!
//! A grant's `valid_until` is different:
//!
//! - [`update_service_grant`] replaces `valid_until`, so it repairs such a
//!   row: with the check in force (even `NOT VALID`) a revision-checked
//!   update that sets a finite `valid_until` (or none) succeeds and returns
//!   the readable row.
//! - A grant list-set change ([`add_service_grant_binding`],
//!   [`remove_service_grant_binding`], [`add_service_grant_resource_server`]
//!   and [`remove_service_grant_resource_server`]) writes only the grant's
//!   revision, so with the check in force it still fails with `23514`. With
//!   the check dropped it applies and returns only the new revision: it
//!   does not read the timestamp column.
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
//! | —        | a stored time outside the readable range   | `UnreadableTimestamp { table, column, id }`           |
//! | `40001`  | `serialization_failure`                    | `Retry(sqlx::Error)`                                  |
//! | `40P01`  | `deadlock_detected`                        | `Retry(sqlx::Error)`                                  |
//! | other    | anything else, or an unlisted constraint   | `Other(sqlx::Error)`                                  |
//!
//! `Retry` means "retry the whole transaction": PostgreSQL aborted it, so
//! the caller rolls back and runs every statement of the transaction again,
//! reading the rows anew; the registry does not retry. A `40001` is never
//! `StaleRevision`.
//!
//! The `Display` and `Debug` text of a [`RegistryError`] never includes a
//! value from the request or the row: the variants carry only constraint,
//! table and column names, `Display` and `Debug` of `Retry` and `Other`
//! print only the SQLSTATE, and those of `UnreadableTimestamp` leave out
//! its row ID (inferred). The [`source`](std::error::Error::source) of
//! `Retry` and `Other` is the raw [`sqlx::Error`], whose message and detail
//! may quote request or row values (for example the key of a unique
//! violation), so logging must not walk the source chain of a
//! `RegistryError`.
//!
//! PostgreSQL text and `jsonb` cannot hold U+0000. A NUL character in any
//! string argument (an ID, a name, a page cursor, an element of a `text[]`
//! such as `allowed_binding_ids` or `resource_server_ids`, or a string
//! inside a `jsonb` value such as a scope element or a constraint version)
//! fails the statement with `22021` (`character_not_in_repertoire`) for a
//! `text` or `text[]` argument, or `22P05` (`untranslatable_character`) for
//! a `jsonb` one only, both [`RegistryError::Other`]. The request layer
//! (T14.1) must reject it before calling the registry.
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

mod assertion;
mod audience;
mod ceilings;
mod error;
mod grant;
mod instance;
mod model;
mod predicate;
mod scope;
mod selection;
mod tenant;
mod trust;

pub use assertion::{
    Consumption, MAX_ASSERTION_SET, NewConsumedAssertion, consume_assertion, consume_assertion_set,
};
pub use audience::{
    add_resource_server_checker_tenant, create_audience_tenant_assignment, create_resource_action,
    create_resource_server, create_resource_server_checker, get_audience_tenant_assignment,
    get_resource_action, get_resource_server, get_resource_server_checker,
    list_audience_tenant_assignments, list_resource_actions, list_resource_server_checkers,
    list_resource_servers, remove_resource_server_checker_tenant,
    update_audience_tenant_assignment, update_resource_action, update_resource_server,
    update_resource_server_checker,
};
pub use ceilings::{CeilingRecord, LoadedCeilings, load_scope_ceilings};
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
    PrincipalBindingChanges, PrincipalKind, PrincipalPatch, Profile, ReplayMode, ResourceAction,
    ResourceActionChanges, ResourceServer, ResourceServerChanges, ResourceServerChecker,
    ResourceServerCheckerChanges, ServiceGrant, ServiceGrantChanges, ServiceIdentity,
    ServiceIdentityChanges, Status, Tenant, TenantPatch, TrustKeyset, TrustKeysetChanges,
    TrustKeysetVersion, TrustSource, TrustSourceChanges, TrustSourceKind, UnknownValue,
};
pub use predicate::{GITHUB_JOB_WORKFLOW_REF, required_claims, validate_claim_match_policy};
pub use scope::{ScopeCeilings, ScopeError, ScopeRequest, resolve_scopes};
pub use selection::{
    EligibleBinding, Evidence, Selection, SelectionError, match_binding, select_grant,
};
pub use tenant::{
    create_principal, create_tenant, get_principal, get_tenant, list_principals, list_tenants,
    update_principal, update_tenant,
};
pub use trust::{
    create_trust_keyset, create_trust_keyset_version, create_trust_source, get_trust_keyset,
    get_trust_keyset_version, get_trust_source, list_trust_keyset_versions, list_trust_keysets,
    list_trust_sources, update_trust_keyset, update_trust_keyset_version, update_trust_source,
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

/// `$column`, a `timestamptz`, as signed microseconds from the Unix epoch,
/// named `<column>_us`. A time outside the range `0007` checks (`infinity`,
/// `-infinity` or a finite time after `i64::MAX - 1` microseconds) is
/// [`UNREADABLE_MICROSECONDS`] instead of failing the statement with
/// `0A000` or `22003`, so the row's reader can name the row (lead ruling,
/// 2026-11-21; the marker is inferred). The bounds are those of the `0007`
/// range checks, with an explicit offset; `NULL` stays `NULL`.
macro_rules! micros {
    ($column:literal) => {
        concat!(
            "CASE WHEN NOT (",
            $column,
            " >= timestamptz '4714-11-24 00:00:00+00 BC' AND ",
            $column,
            // The marker, i64::MAX: no stored value can produce it, since
            // the 0007 range checks cap stored values at i64::MAX - 1.
            " <= timestamptz '294247-01-10 04:00:54.775806+00') THEN 9223372036854775807 \
             ELSE (extract(epoch FROM ",
            $column,
            ") * 1000000)::bigint END AS ",
            $column,
            "_us"
        )
    };
}
use micros;

/// The value [`micros!`] gives for a time outside the readable range:
/// `i64::MAX`, one past the latest readable microsecond.
///
/// It cannot collide with a stored time: the `0007` range checks cap stored
/// values at `i64::MAX - 1` microseconds, and [`micros!`] gives the marker
/// for anything later before it extracts a value. The registry test
/// `times_at_the_range_check_bounds_read_back_exactly` reads rows at both
/// bounds back as themselves.
const UNREADABLE_MICROSECONDS: i64 = i64::MAX;

/// The columns of a compare-and-set update of `$table`: `$set` assigns the
/// mutable columns from `$3` on, `$1` is the ID and `$2` the expected
/// revision. The statement returns one row: the updated columns, or `NULL`s
/// when nothing matched, and `found`, whether a row with the ID exists.
///
/// The new revision is `revision + 1`, not `$2 + 1`: the planner can fold
/// `$2 + 1` before any row is matched, so `$2 = i64::MAX` would fail with
/// `22003` (`numeric_value_out_of_range`) instead of a stale or missing row.
macro_rules! compare_and_set {
    ($table:literal, $set:literal, $columns:expr) => {
        concat!(
            "WITH updated AS (UPDATE ",
            $table,
            " SET ",
            $set,
            ", revision = revision + 1 WHERE id = $1 AND revision = $2 RETURNING ",
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
            ", revision = revision + 1 WHERE id = $1 AND revision = $2 AND tenant_id = $3 RETURNING ",
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
    fn micros_marks_times_outside_the_range_checks() {
        assert_eq!(
            micros!("t"),
            "CASE WHEN NOT (t >= timestamptz '4714-11-24 00:00:00+00 BC' \
             AND t <= timestamptz '294247-01-10 04:00:54.775806+00') \
             THEN 9223372036854775807 ELSE (extract(epoch FROM t) * 1000000)::bigint END AS t_us"
        );
        assert_eq!(UNREADABLE_MICROSECONDS, i64::MAX);
    }

    #[test]
    fn compare_and_set_advances_the_revision_by_one_where_it_matches() {
        let sql = compare_and_set!("t", "a = $3", "id, a, revision");
        assert_eq!(
            sql,
            "WITH updated AS (UPDATE t SET a = $3, revision = revision + 1 \
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
            "WITH updated AS (UPDATE t SET a = $4, revision = revision + 1 \
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
