//! Operator identities, their mTLS credentials and their role bindings
//! (`0005`), and the operator authorization lookups [`authorize_operator`]
//! and [`authorize_operator_locked`] (design section 7.2; identity-registry
//! section 5.2; ADR-013 items 1 and 2; public-api API-002 and API-120;
//! T13.1, T13.2).
//!
//! # Rows
//!
//! All three tables are instance authority, so rows are read by their own
//! ID. Writes take caller-supplied IDs (T10.2 generates them).
//!
//! - An [`AdminIdentity`] is created with [`create_admin_identity`], read
//!   with [`get_admin_identity`] and disabled with
//!   [`disable_admin_identity`]. It has no revision: the logical model gives
//!   it none (`0005`).
//! - An [`AdminCredential`] is created unrevoked with
//!   [`create_admin_credential`], read with [`get_admin_credential`] and
//!   revoked with [`revoke_admin_credential`], which sets `revoked_at` and
//!   `status = 'disabled'` in one statement. It has no revision either.
//! - An [`AdminRoleBinding`] is created with [`create_admin_role_binding`],
//!   read with [`get_admin_role_binding`] and changed with
//!   [`update_admin_role_binding`], a compare-and-set on its revision like
//!   every other registry update. Only its `status` is mutable: its
//!   operator, role and tenant are immutable (`admin_role_binding_immutable`),
//!   so another scope is another binding.
//!
//! A second row with the same ID, or a credential whose `public_identity`
//! is already registered, is [`RegistryError::AlreadyExists`] naming only
//! the constraint (`admin_identity_pkey`, `admin_credential_pkey`,
//! `admin_credential_public_identity_key`, `admin_role_binding_pkey`, or
//! `admin_role_binding_admin_id_role_tenant_id_key` for a second binding of
//! one operator, role and scope), never the colliding value.
//!
//! # One-way state
//!
//! Revocation is one-way, and the database enforces it, not only this
//! module:
//!
//! - `admin_credential_set_once` (`0005`, `skyoauth_reject_change_once_set('revoked_at')`)
//!   rejects an `UPDATE` that clears or changes a set `revoked_at` with
//!   `SK001` ([`RegistryError::Guard`]).
//! - `admin_credential_revoked_disabled_check` (`0005`) rejects a revoked
//!   credential whose `status` is not `disabled` with `23514`
//!   ([`RegistryError::Invariant`]), so a revoked credential cannot be
//!   re-enabled while `revoked_at` stays set, and the set-once guard keeps
//!   it set.
//! - `admin_credential_immutable` (`0005`) keeps `public_identity`,
//!   `admin_id` and `trust_anchor_ref` unchanged, so a revoked key cannot be
//!   moved off its row, and `admin_credential_no_delete` and
//!   `admin_credential_no_truncate` (`0006`) keep the row, so
//!   `admin_credential_public_identity_key` refuses the key's registration
//!   again for as long as the row exists.
//!
//! [`revoke_admin_credential`] of a credential already revoked keeps the
//! first `revoked_at` and returns the row unchanged (inferred: a repeated
//! revocation is not an error, and the first time is the fact).
//!
//! Only credential revocation is one-way in the database. The registry has
//! no setter that enables or otherwise updates an identity or a credential,
//! and no way to disable a credential without revoking it: public-api
//! section 7.1 names enrollment and disable only, so after it is created an
//! identity can only be disabled ([`disable_admin_identity`]) and a
//! credential only revoked ([`revoke_admin_credential`]). The database does
//! not forbid re-enabling either: no guard keeps `admin_identity.status`, or
//! the `status` of an unrevoked credential (one created `disabled`), from
//! going back to `enabled` by other means, and this module adds none (no
//! migration in this slice). The lead ruling that re-enabling is a plain
//! status change (2026-11-21; provisional until the maintainer ratifies the
//! ADRs, T00.8 to T00.17, Gate M0) applies to the tables the registry
//! updates: a role binding is re-enabled rather than assigned twice
//! (`0005`, inferred there), so [`update_admin_role_binding`] changes its
//! status both ways.
//!
//! # Reserved actor IDs
//!
//! Bootstrap acts for the deployment operator and break-glass recovery for
//! the holder of the offline recovery key; neither is an operator identity
//! (design section 7.2; `administrative_operation.actor_id` is no foreign
//! key for that reason). They are recorded as the actor IDs
//! [`DEPLOYMENT_OPERATOR_ACTOR`] and [`recovery_key_actor`]`(epoch)`, with
//! the audit actor type `operator` (lead pick, 2026-11-21; provisional
//! until the maintainer ratifies the ADRs, T00.8 to T00.17, Gate M0;
//! identity-registry section 5.2). So that no real operator can act under
//! those IDs, [`create_admin_identity`] rejects `deployment_operator` and
//! every ID that begins with `recovery_key:` with
//! [`RegistryError::ReservedActorId`] before any statement runs. The
//! comparison is exact and byte-wise, as every ID comparison of the
//! registry is: `Deployment_Operator` is another ID. Since `0009` the
//! database refuses the same IDs with `admin_identity_id_not_reserved_check`,
//! the backstop for an identity inserted by other means, which maps to
//! [`RegistryError::Invariant`] naming the check.
//!
//! # Authorization lookup
//!
//! [`authorize_operator`] answers one question: does the enabled,
//! unrevoked credential with exactly this `public_identity` belong to an
//! enabled operator that holds an enabled binding of exactly this role in
//! exactly this scope? It runs one statement that joins the credential, its
//! identity and the identity's bindings and returns at most one row:
//! `public_identity` is unique, and so is a binding's operator, role and
//! tenant (`NULLS NOT DISTINCT`). Every comparison is an equality on a
//! `COLLATE "C"` column, so it is byte-wise whatever the database
//! collation: no case folding, trimming or normalization.
//!
//! - Roles do not inherit one another (public-api API-120): only a binding
//!   of the requested role counts, so `security_admin` does not satisfy a
//!   `trust_admin` request.
//! - Scope fails closed: [`OperatorScope::Instance`] needs a binding with
//!   no tenant, and [`OperatorScope::Tenant`] a binding of exactly that
//!   tenant. An instance-scoped `auditor` does not satisfy a tenant request
//!   and a tenant `auditor` does not satisfy an instance request
//!   (OQ-ADR013-3; lead pick, 2026-11-21; provisional until the maintainer
//!   ratifies the ADRs, T00.8 to T00.17, Gate M0). The schema already keeps
//!   `security_admin` instance-only and the three tenant roles tenant-only
//!   (`admin_role_binding_scope_check`), so a request of the other scope
//!   for them finds nothing.
//! - Every miss (an unknown key; a disabled or revoked credential; a
//!   disabled identity; no binding, or a disabled one, of that role and
//!   scope) is the same `Ok(None)`: the statement returns no row, and the
//!   Rust code after it has one path for no row. As for
//!   [`select_grant`](super::select_grant), the claim is only that every
//!   miss gives the same value; the database does different work for
//!   different misses, and no claim is made about timing (inferred).
//! - The inputs are not validated before the statement, as for
//!   [`select_grant`](super::select_grant): an empty or over-long
//!   `public_identity` or tenant ID matches no row and is `Ok(None)`. A NUL
//!   character fails the statement with `22021`, [`RegistryError::Other`],
//!   as everywhere in the registry; the request layer rejects it first. A
//!   store failure is an `Err`, which the caller denies too.
//!
//! What it does not do: it reads no clock, writes no audit event and no
//! `administrative_operation` row, and changes nothing. It does not check
//! the TLS handshake, the certificate chain or the deployment trust anchor
//! (`trust_anchor_ref`); the caller canonicalizes the presented key into
//! `public_identity` after the handshake (T13.1). It has no OIDC, email,
//! group or WIF path: those never grant operator authority (API-002). It
//! does not decide which role an endpoint needs (T14.1, T14.2). The T13.3
//! caller writes the audit event of the authorized write in the same
//! transaction.
//!
//! Tenant status is not part of either lookup: an operator bound to a
//! disabled tenant is still found. ADR-014 item 11 lists what a disabled
//! tenant denies (issuance, live checks, admission and refresh) and does
//! not name operator writes; T14 must check the tenant's status where a
//! write needs it.
//!
//! [`authorize_operator`] takes no row locks: its answer is a point in
//! time. Under `READ COMMITTED` a revocation, a disable or a binding change
//! can commit between the lookup and the caller's write, also when both run
//! in one transaction. A decision that must hold until the caller's
//! transaction commits uses [`authorize_operator_locked`].
//!
//! # Locked lookup
//!
//! [`authorize_operator_locked`] runs in the caller's transaction (it takes
//! a [`Transaction`], as the audit append does, so that its statements run
//! on one connection in one open transaction; inferred). It runs the same
//! lookup; on a miss of this first lookup it returns `None` and locks
//! nothing. On a hit it locks
//! the three returned rows by ID, one statement and one row each, in the
//! `0005` lock order of `service/migrations/README.md`: the
//! `admin_identity` row, then the `admin_credential` row, then the
//! `admin_role_binding` row. It then repeats the lookup and returns its
//! result only if it equals the first one; any difference, a miss
//! included, is `None` (inferred: a change between the two lookups is
//! denied rather than followed); a `None` from the repeat keeps the locks
//! already taken. The locks are held until the caller's transaction ends,
//! so a revocation, an identity disable or a binding update of those rows
//! waits for that commit or rollback, and the decision holds until the
//! authorized write commits. This holds for locks taken in the caller's
//! transaction itself: when `transaction` is a savepoint, rolling that
//! savepoint back releases the locks taken in it.
//!
//! - The lock strength is `FOR SHARE` (inferred: the README prescribes
//!   `FOR NO KEY UPDATE` for rows a write updates or an operation
//!   references, and nothing for an authorization check). `FOR SHARE`
//!   conflicts with the `UPDATE` of a status or `revoked_at`, which takes a
//!   `FOR NO KEY UPDATE` row lock, and not with another `FOR SHARE` or with
//!   the `FOR KEY SHARE` of a foreign-key check, so concurrent
//!   authorizations of one operator do not wait for each other.
//! - The repeat catches a change committed after the first lookup and
//!   before a lock was granted: under `READ COMMITTED` the repeat reads the
//!   rows as committed after the locks. Under `REPEATABLE READ` or
//!   `SERIALIZABLE`, a lock on a row changed after the transaction's
//!   snapshot fails with `40001` ([`RegistryError::Retry`]), as for any
//!   locking writer (README, `0005` lock order).
//! - No deadlock with the registry's writers: every locker of these rows
//!   takes them in the same table order, identity, credential, binding, and
//!   this lookup holds at most one row of each table. A revocation, an
//!   identity disable and a binding update lock only the one row they
//!   change among these tables (a binding update then also takes the
//!   `recovery_state` row, which no lookup locks; see "Writes and a
//!   restoration"), and a writer that follows the README's step 1 locks its rows
//!   in that same order, so no cycle of waits forms.
//! - Caveat for the caller: once the lookup holds its locks, the caller's
//!   own later locks of operator rows come after them, outside the README
//!   order. A transaction that then updates one of the rows it holds
//!   `FOR SHARE` (upgrading the lock), or locks another operator's rows,
//!   can deadlock with a transaction that does the same the other way
//!   round; PostgreSQL then fails one of them with `40P01`, an `Err` and so
//!   a deny. T13.3 decides how its writes order these locks.
//!
//! # Writes and a restoration
//!
//! A break-glass restoration
//! ([`restore_operator`](super::restore_operator)) revokes every unrevoked
//! credential and must not leave behind operator access that a concurrent
//! write adds. So the four writes that can add enabled operator access,
//! [`create_admin_identity`], [`create_admin_credential`],
//! [`create_admin_role_binding`] and [`update_admin_role_binding`] (the
//! status change that re-enables a binding), lock the `recovery_state` row
//! `FOR SHARE` in their one statement (there is no setter that enables an
//! identity or a credential; see "One-way state"). The lock conflicts with
//! the restoration's `FOR NO KEY UPDATE` of that row and with nothing
//! else of the registry: an issue of a recovery challenge takes it
//! `FOR SHARE` too. Before bootstrap there is no row and nothing is locked;
//! bootstrap's own writes find the row it inserted. The choice of lock and
//! its order are inferred, provisional until the maintainer ratifies the
//! ADRs (T00.8 to T00.17, Gate M0).
//!
//! - The three creates take the lock first, before they insert (a
//!   materialized `WITH` the insert selects from). The inserted row is new,
//!   so no other transaction holds it; locking first keeps a create from
//!   holding a key the restoration is about to insert (its replacement's
//!   IDs) while it waits for the row the restoration holds.
//! - The binding update takes the lock in its `RETURNING`, after it has
//!   locked and updated the binding row, in the `0005` table order of the
//!   migrations README (binding, then the recovery state), and only when it
//!   updated a row.
//!
//! The restoration locks every unrevoked credential `FOR NO KEY UPDATE`,
//! then the `recovery_state` row, and revokes in a later statement. It runs
//! only under `READ COMMITTED` and refuses other levels
//! ([`RestoreError::UnsupportedIsolation`](super::RestoreError::UnsupportedIsolation)):
//! under `REPEATABLE READ` or `SERIALIZABLE` its revocation would read a
//! snapshot older than a write it waited for. A write that holds the row
//! `FOR SHARE` makes the restoration wait for its commit, and the
//! revocation, under `READ COMMITTED`, then sees the row it wrote: a
//! credential enrolled that way is revoked with the others. A write that
//! starts while the restoration holds the row waits for it to commit, then
//! writes. So a caller re-authorizes after its write, in the same
//! transaction: under `READ COMMITTED` that lookup sees the revocation and
//! denies, and the caller rolls back. A write under `REPEATABLE READ` or
//! `SERIALIZABLE` that waited for a restoration that committed fails with
//! `40001` ([`RegistryError::Retry`]) instead, since the restoration changed
//! the row it waited for.
//!
//! The order for a caller is the README's: [`authorize_operator_locked`]
//! (identity, credential, binding `FOR SHARE`) first, then the write
//! (`recovery_state` `FOR SHARE`). The restoration takes credentials before
//! the recovery state too: a restoration waiting at its credential lock for
//! a credential the caller holds holds no `recovery_state` lock yet, and the
//! caller's write goes through. That does not rule out every cycle. A
//! credential that a write committed after the restoration's credential lock
//! and before its `recovery_state` lock is not among the credentials it
//! locked; a caller that authorizes on that credential and then writes
//! waits for the restoration's `recovery_state` lock while the
//! restoration's revocation waits for the caller's `FOR SHARE` on the
//! credential. PostgreSQL fails one of them with `40P01`
//! ([`RegistryError::Retry`]), either one, and the failure is closed: a
//! restoration that is the victim leaves nothing and its challenge
//! unconsumed, and its caller retries; a writer that is the victim denies.
//! Closing the cycle needs a lock before the authorization, a change of the
//! `0005` order (a follow-up of the migrations README). A caller that writes
//! first and then takes a locked lookup holds the recovery state while it
//! waits for a credential, outside the documented order: against a
//! restoration that holds the credentials and waits for the recovery state
//! it fails with `40P01` ([`RegistryError::Retry`]), a deny.
//!
//! # Time
//!
//! Time is always an explicit argument here, never the database's `now()`
//! (lead pick, 2026-11-21; provisional until the maintainer ratifies the
//! ADRs, T00.8 to T00.17, Gate M0): [`NewAdminIdentity::created_at`] and
//! the `now` of [`revoke_admin_credential`]. Times are written as
//! whole microseconds, truncated toward the past, and a time outside the
//! `0007` range is [`RegistryError::Other`] before any statement runs, as
//! everywhere in the registry.

use std::time::SystemTime;

use sqlx::{FromRow, PgExecutor, Postgres, Row, Transaction, postgres::PgRow};

use super::{
    AdminRole, RegistryError, Status, micros,
    model::{Origin, required_timestamp, since_epoch, text, timestamp},
    updated,
};

/// The actor ID of the deployment operator, who runs bootstrap (design
/// section 7.2; T13.4). Not an operator identity; reserved, so no
/// [`AdminIdentity`] can have it (lead pick, 2026-11-21; provisional until
/// the maintainer ratifies the ADRs, T00.8 to T00.17, Gate M0).
pub const DEPLOYMENT_OPERATOR_ACTOR: &str = "deployment_operator";

/// The prefix of the actor ID of an offline recovery key holder, followed by
/// the key's `recovery_key_epoch` (see [`recovery_key_actor`]). Every ID
/// that begins with it is reserved (lead pick, 2026-11-21; provisional
/// until the maintainer ratifies the ADRs, T00.8 to T00.17, Gate M0).
pub const RECOVERY_KEY_ACTOR_PREFIX: &str = "recovery_key:";

/// The actor ID of the holder of the recovery key of `epoch`, as
/// break-glass recovery records it (design section 7.2; T13.5):
/// `recovery_key:<epoch>` with the epoch in decimal.
pub fn recovery_key_actor(epoch: i64) -> String {
    format!("{RECOVERY_KEY_ACTOR_PREFIX}{epoch}")
}

/// Whether `id` is reserved for an actor that is not an operator identity:
/// exactly [`DEPLOYMENT_OPERATOR_ACTOR`], or any ID that begins with
/// [`RECOVERY_KEY_ACTOR_PREFIX`]. Byte-wise, with no case folding.
pub fn is_reserved_actor_id(id: &str) -> bool {
    id == DEPLOYMENT_OPERATOR_ACTOR || id.starts_with(RECOVERY_KEY_ACTOR_PREFIX)
}

/// An independent `adm_*` operator identity (design section 7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminIdentity {
    pub id: String,
    /// Set `disabled` by [`disable_admin_identity`]; never enabled again by
    /// the registry.
    pub status: Status,
    /// Immutable.
    pub created_at: SystemTime,
}

impl FromRow<'_, PgRow> for AdminIdentity {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("admin_identity");
        Ok(Self {
            id: row.try_get("id")?,
            status: text(row, "status")?,
            created_at: required_timestamp(row, ORIGIN, "created_at")?,
        })
    }
}

/// The input of [`create_admin_identity`]. `created_at` is the caller's
/// `now`, not the database's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAdminIdentity {
    /// Neither [`DEPLOYMENT_OPERATOR_ACTOR`] nor an ID beginning with
    /// [`RECOVERY_KEY_ACTOR_PREFIX`].
    pub id: String,
    pub status: Status,
    pub created_at: SystemTime,
}

/// A registered mTLS public credential of an operator (design section 7.2;
/// T13.1). Every column but `status` and `revoked_at` is immutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCredential {
    pub id: String,
    pub admin_id: String,
    /// The canonical public-key identity, unique across every credential,
    /// revoked ones included.
    pub public_identity: String,
    pub trust_anchor_ref: String,
    /// `disabled` once revoked.
    pub status: Status,
    /// Set once, by [`revoke_admin_credential`].
    pub revoked_at: Option<SystemTime>,
}

impl FromRow<'_, PgRow> for AdminCredential {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        const ORIGIN: Origin = Origin::new("admin_credential");
        Ok(Self {
            id: row.try_get("id")?,
            admin_id: row.try_get("admin_id")?,
            public_identity: row.try_get("public_identity")?,
            trust_anchor_ref: row.try_get("trust_anchor_ref")?,
            status: text(row, "status")?,
            revoked_at: timestamp(row, ORIGIN, "revoked_at")?,
        })
    }
}

/// The input of [`create_admin_credential`]. The credential starts
/// unrevoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAdminCredential {
    pub id: String,
    pub admin_id: String,
    pub public_identity: String,
    pub trust_anchor_ref: String,
    pub status: Status,
}

/// One explicit role assignment of an operator (design section 7.2;
/// T13.2): `tenant_id` is `None` for the instance scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRoleBinding {
    pub id: String,
    /// Immutable.
    pub admin_id: String,
    /// Immutable.
    pub role: AdminRole,
    /// Immutable. `None` for `security_admin` and an instance `auditor`,
    /// set for the three tenant roles and a tenant `auditor`.
    pub tenant_id: Option<String>,
    pub status: Status,
    pub revision: i64,
}

impl FromRow<'_, PgRow> for AdminRoleBinding {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            admin_id: row.try_get("admin_id")?,
            role: text(row, "role")?,
            tenant_id: row.try_get("tenant_id")?,
            status: text(row, "status")?,
            revision: row.try_get("revision")?,
        })
    }
}

/// The input of [`create_admin_role_binding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAdminRoleBinding {
    pub id: String,
    pub admin_id: String,
    pub role: AdminRole,
    pub tenant_id: Option<String>,
    pub status: Status,
}

/// The mutable columns of a role binding, replaced by
/// [`update_admin_role_binding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRoleBindingChanges {
    pub status: Status,
}

/// The scope an operator request acts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorScope<'a> {
    /// The instance: only a binding with no tenant satisfies it.
    Instance,
    /// One tenant, by exact ID: only a binding of that tenant satisfies it.
    Tenant(&'a str),
}

/// What [`authorize_operator`] checks: the presented credential's canonical
/// `public_identity`, and the role and scope the operation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorRequest<'a> {
    /// The canonical public-key identity of the presented mTLS credential,
    /// compared byte-wise with `admin_credential.public_identity`.
    pub public_identity: &'a str,
    pub scope: OperatorScope<'a>,
    pub role: AdminRole,
}

/// The rows that authorized an operator request: the operator, the
/// credential it presented and the binding that grants the role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedOperator {
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    pub role: AdminRole,
}

impl FromRow<'_, PgRow> for AuthorizedOperator {
    fn from_row(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            admin_id: row.try_get("admin_id")?,
            credential_id: row.try_get("credential_id")?,
            binding_id: row.try_get("binding_id")?,
            role: text(row, "role")?,
        })
    }
}

macro_rules! identity_columns {
    () => {
        concat!("id, status, ", micros!("created_at"))
    };
}

macro_rules! credential_columns {
    () => {
        concat!(
            "id, admin_id, public_identity, trust_anchor_ref, status, ",
            micros!("revoked_at")
        )
    };
}

macro_rules! binding_columns {
    () => {
        "id, admin_id, role, tenant_id, status, revision"
    };
}

/// An authorization statement that finds the credential by `$credential`.
/// `$2` is the role and `$3` the tenant, `NULL` for the instance scope. The
/// scope predicate is true for an instance request only on a binding with
/// no tenant, and for a tenant request only on a binding of exactly that
/// tenant; `b.tenant_id = NULL` is never true, so an instance request never
/// reaches the second disjunct.
macro_rules! authorize_statement {
    ($credential:literal) => {
        concat!(
            "SELECT i.id AS admin_id, c.id AS credential_id, \
             b.id AS binding_id, b.role \
             FROM admin_credential c \
             JOIN admin_identity i ON i.id = c.admin_id \
             JOIN admin_role_binding b ON b.admin_id = i.id \
             WHERE ",
            $credential,
            " AND c.status = 'enabled' \
               AND c.revoked_at IS NULL \
               AND i.status = 'enabled' \
               AND b.status = 'enabled' \
               AND b.role = $2 \
               AND (($3::text IS NULL AND b.tenant_id IS NULL) OR b.tenant_id = $3::text)"
        )
    };
}

/// The authorization statement of [`authorize_operator`]: `$1` is the
/// `public_identity`.
const AUTHORIZE_OPERATOR: &str = authorize_statement!("c.public_identity = $1");

/// The same lookup by the credential's ID (`$1`) and its operator's ID
/// (`$4`), for an operator known by its IDs rather than by a presented key:
/// the requester of an approval
/// ([`authorize_approval_locked`](super::authorize_approval_locked)).
const AUTHORIZE_CREDENTIAL: &str = authorize_statement!("c.id = $1 AND c.admin_id = $4");

/// The row locks of [`authorize_operator_locked`], in the `0005` lock order:
/// identity, credential, binding, each by its ID.
const LOCK_IDENTITY: &str = "SELECT FROM admin_identity WHERE id = $1 FOR SHARE";
const LOCK_CREDENTIAL: &str = "SELECT FROM admin_credential WHERE id = $1 FOR SHARE";
const LOCK_BINDING: &str = "SELECT FROM admin_role_binding WHERE id = $1 FOR SHARE";

/// The start of the four writes that can add operator access (see the
/// module documentation, "Writes and a restoration"): the `recovery_state`
/// row `FOR SHARE`, no row before bootstrap.
macro_rules! share_recovery_state {
    () => {
        "WITH recovery AS MATERIALIZED (SELECT FROM recovery_state FOR SHARE) "
    };
}

/// The `FROM` of an insert after [`share_recovery_state!`]: one row, once
/// the lock is held, so the lock comes before the insert.
macro_rules! after_recovery_state {
    () => {
        "FROM (SELECT count(*) FROM recovery) AS locked"
    };
}

/// [`update_admin_role_binding`]: the registry's `compare_and_set!` whose `RETURNING`
/// takes the `recovery_state` lock, after the binding row is locked and
/// only when it is updated (the `0005` table order: binding, then the
/// recovery state).
const UPDATE_BINDING: &str = concat!(
    share_recovery_state!(),
    ", updated AS (UPDATE admin_role_binding SET status = $3, revision = revision + 1 \
     WHERE id = $1 AND revision = $2 RETURNING ",
    binding_columns!(),
    ", (SELECT count(*) FROM recovery) AS locked) \
     SELECT updated.*, EXISTS (SELECT FROM admin_role_binding WHERE id = $1) AS found \
     FROM (SELECT) AS one LEFT JOIN updated ON true"
);

/// The error of [`create_admin_identity`] for a reserved ID.
fn reserved(id: &str) -> Result<(), RegistryError> {
    if is_reserved_actor_id(id) {
        Err(RegistryError::ReservedActorId)
    } else {
        Ok(())
    }
}

/// Creates an operator identity with the caller's ID and `created_at`.
/// A reserved ID ([`is_reserved_actor_id`]) is
/// [`RegistryError::ReservedActorId`] and a time outside the `0007` range
/// [`RegistryError::Other`], both before any statement runs. Locks the
/// `recovery_state` row `FOR SHARE` before it inserts (see the module
/// documentation, "Writes and a restoration").
pub async fn create_admin_identity<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAdminIdentity,
) -> Result<AdminIdentity, RegistryError> {
    reserved(&new.id)?;
    let created_at = since_epoch(new.created_at)?;
    Ok(sqlx::query_as(concat!(
        share_recovery_state!(),
        "INSERT INTO admin_identity (id, status, created_at) \
         SELECT $1, $2, timestamptz 'epoch' + $3::interval ",
        after_recovery_state!(),
        " RETURNING ",
        identity_columns!()
    ))
    .bind(&new.id)
    .bind(new.status.as_str())
    .bind(created_at)
    .fetch_one(executor)
    .await?)
}

/// Reads an operator identity by ID.
pub async fn get_admin_identity<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<AdminIdentity, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        identity_columns!(),
        " FROM admin_identity WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Disables an operator identity. Disabling a disabled identity changes
/// nothing and returns it. There is no function that enables it again (see
/// the module documentation, "One-way state").
pub async fn disable_admin_identity<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<AdminIdentity, RegistryError> {
    sqlx::query_as(concat!(
        "UPDATE admin_identity SET status = 'disabled' WHERE id = $1 RETURNING ",
        identity_columns!()
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Registers a credential of an existing operator, unrevoked. A
/// `public_identity` already registered, revoked or not, is
/// [`RegistryError::AlreadyExists`] with
/// `admin_credential_public_identity_key`. Locks the `recovery_state` row
/// `FOR SHARE` before it inserts (see the module documentation, "Writes and
/// a restoration").
pub async fn create_admin_credential<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAdminCredential,
) -> Result<AdminCredential, RegistryError> {
    Ok(sqlx::query_as(concat!(
        share_recovery_state!(),
        "INSERT INTO admin_credential (id, admin_id, public_identity, trust_anchor_ref, status) \
         SELECT $1, $2, $3, $4, $5 ",
        after_recovery_state!(),
        " RETURNING ",
        credential_columns!()
    ))
    .bind(&new.id)
    .bind(&new.admin_id)
    .bind(&new.public_identity)
    .bind(&new.trust_anchor_ref)
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a credential by ID.
pub async fn get_admin_credential<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<AdminCredential, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        credential_columns!(),
        " FROM admin_credential WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Revokes a credential at `now`: sets `revoked_at` and `status =
/// 'disabled'` in one statement. A credential already revoked keeps its
/// first `revoked_at` and is returned unchanged (inferred). Revocation is
/// permanent, and the database guards keep it so (see the module
/// documentation, "One-way state"). A `now` outside the `0007` range is
/// [`RegistryError::Other`] before any statement runs.
pub async fn revoke_admin_credential<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    now: SystemTime,
) -> Result<AdminCredential, RegistryError> {
    let now = since_epoch(now)?;
    sqlx::query_as(concat!(
        "UPDATE admin_credential SET status = 'disabled', \
         revoked_at = coalesce(revoked_at, timestamptz 'epoch' + $2::interval) \
         WHERE id = $1 RETURNING ",
        credential_columns!()
    ))
    .bind(id)
    .bind(now)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Creates a role binding at revision 1. `tenant_id` must be `None` for
/// `security_admin` and set for the three tenant roles
/// (`admin_role_binding_scope_check`); a second binding of the same
/// operator, role and scope, disabled or not, is
/// [`RegistryError::AlreadyExists`] with
/// `admin_role_binding_admin_id_role_tenant_id_key`. Locks the
/// `recovery_state` row `FOR SHARE` before it inserts (see the module
/// documentation, "Writes and a restoration").
pub async fn create_admin_role_binding<'e>(
    executor: impl PgExecutor<'e>,
    new: &NewAdminRoleBinding,
) -> Result<AdminRoleBinding, RegistryError> {
    Ok(sqlx::query_as(concat!(
        share_recovery_state!(),
        "INSERT INTO admin_role_binding (id, admin_id, role, tenant_id, status) \
         SELECT $1, $2, $3, $4, $5 ",
        after_recovery_state!(),
        " RETURNING ",
        binding_columns!()
    ))
    .bind(&new.id)
    .bind(&new.admin_id)
    .bind(new.role.as_str())
    .bind(new.tenant_id.as_deref())
    .bind(new.status.as_str())
    .fetch_one(executor)
    .await?)
}

/// Reads a role binding by ID.
pub async fn get_admin_role_binding<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
) -> Result<AdminRoleBinding, RegistryError> {
    sqlx::query_as(concat!(
        "SELECT ",
        binding_columns!(),
        " FROM admin_role_binding WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await?
    .ok_or(RegistryError::NotFound)
}

/// Replaces the status of the role binding `id` at `expected_revision` and
/// advances its revision by one. Its operator, role and tenant keep their
/// values. Re-enabling a disabled binding is a plain status change here;
/// whether it needs an approval belongs to the service layer. Locks the
/// `recovery_state` row `FOR SHARE` after the binding row, when it updates
/// one (see the module documentation, "Writes and a restoration").
pub async fn update_admin_role_binding<'e>(
    executor: impl PgExecutor<'e>,
    id: &str,
    expected_revision: i64,
    changes: &AdminRoleBindingChanges,
) -> Result<AdminRoleBinding, RegistryError> {
    let row = sqlx::query(UPDATE_BINDING)
        .bind(id)
        .bind(expected_revision)
        .bind(changes.status.as_str())
        .fetch_one(executor)
        .await?;
    updated(&row)
}

/// The operator that `request` authorizes, or `None`: in one statement,
/// the enabled, unrevoked credential with exactly `request.public_identity`,
/// its enabled identity, and that identity's enabled binding of exactly
/// `request.role` in exactly `request.scope` (see the module
/// documentation, "Authorization lookup"). Every miss is the same
/// `Ok(None)`; a store failure is an `Err`, also a deny. Reads no clock,
/// writes nothing and takes no row locks: the answer is a point in time. A
/// decision that must hold until the caller's write commits uses
/// [`authorize_operator_locked`].
pub async fn authorize_operator<'e>(
    executor: impl PgExecutor<'e>,
    request: &OperatorRequest<'_>,
) -> Result<Option<AuthorizedOperator>, RegistryError> {
    let tenant_id = match request.scope {
        OperatorScope::Instance => None,
        OperatorScope::Tenant(tenant_id) => Some(tenant_id),
    };
    Ok(sqlx::query_as(AUTHORIZE_OPERATOR)
        .bind(request.public_identity)
        .bind(request.role.as_str())
        .bind(tenant_id)
        .fetch_optional(executor)
        .await?)
}

/// [`authorize_operator`] for the credential `credential_id` of the operator
/// `admin_id`, by their IDs instead of a presented `public_identity`: the
/// same statuses, role and scope, every miss the same `Ok(None)`, no lock
/// and no clock. For
/// [`authorize_approval_locked`](super::authorize_approval_locked), which
/// checks the requester of an operation by the IDs its plan holds.
pub(super) async fn authorize_credential<'e>(
    executor: impl PgExecutor<'e>,
    admin_id: &str,
    credential_id: &str,
    scope: OperatorScope<'_>,
    role: AdminRole,
) -> Result<Option<AuthorizedOperator>, RegistryError> {
    let tenant_id = match scope {
        OperatorScope::Instance => None,
        OperatorScope::Tenant(tenant_id) => Some(tenant_id),
    };
    Ok(sqlx::query_as(AUTHORIZE_CREDENTIAL)
        .bind(credential_id)
        .bind(role.as_str())
        .bind(tenant_id)
        .bind(admin_id)
        .fetch_optional(executor)
        .await?)
}

/// [`authorize_operator`] whose decision holds until `transaction` ends: on
/// a hit, locks the identity, credential and binding rows `FOR SHARE` by ID,
/// in that order, repeats the lookup and returns the hit only if the repeat
/// gives the same one; otherwise `None` (see the module documentation,
/// "Locked lookup"). A miss of the first lookup locks nothing; a `None`
/// from the repeat keeps the locks until the transaction ends. Locks taken
/// in a savepoint are released if that savepoint is rolled back. Reads no
/// clock and writes nothing.
pub async fn authorize_operator_locked(
    transaction: &mut Transaction<'_, Postgres>,
    request: &OperatorRequest<'_>,
) -> Result<Option<AuthorizedOperator>, RegistryError> {
    let Some(first) = authorize_operator(&mut **transaction, request).await? else {
        return Ok(None);
    };
    for (lock, id) in [
        (LOCK_IDENTITY, &first.admin_id),
        (LOCK_CREDENTIAL, &first.credential_id),
        (LOCK_BINDING, &first.binding_id),
    ] {
        sqlx::query(lock)
            .bind(id)
            .execute(&mut **transaction)
            .await?;
    }
    let second = authorize_operator(&mut **transaction, request).await?;
    Ok(second.filter(|second| *second == first))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reserved_actor_ids_are_exact_and_byte_wise() {
        assert_eq!(DEPLOYMENT_OPERATOR_ACTOR, "deployment_operator");
        assert_eq!(RECOVERY_KEY_ACTOR_PREFIX, "recovery_key:");
        assert_eq!(recovery_key_actor(1), "recovery_key:1");
        assert_eq!(
            recovery_key_actor(i64::MAX),
            "recovery_key:9223372036854775807"
        );
        for id in [
            "deployment_operator",
            "recovery_key:",
            "recovery_key:1",
            "recovery_key:anything",
            &recovery_key_actor(42),
        ] {
            assert!(is_reserved_actor_id(id), "{id}");
            assert!(matches!(reserved(id), Err(RegistryError::ReservedActorId)));
        }
        for id in [
            "",
            "adm_1",
            "deployment_operator ",
            " deployment_operator",
            "deployment_operator2",
            "Deployment_Operator",
            "deployment_operato",
            "recovery_key",
            "Recovery_key:1",
            "recovery-key:1",
            "x_recovery_key:1",
            "adm_deployment_operator",
        ] {
            assert!(!is_reserved_actor_id(id), "{id}");
            assert!(reserved(id).is_ok(), "{id}");
        }
    }

    #[test]
    fn roles_round_trip_and_reject_other_values() {
        for role in [
            AdminRole::SecurityAdmin,
            AdminRole::TrustAdmin,
            AdminRole::ClientAdmin,
            AdminRole::ProviderAdmin,
            AdminRole::Auditor,
        ] {
            assert_eq!(role.as_str().parse::<AdminRole>(), Ok(role));
            assert_eq!(role.to_string(), role.as_str());
        }
        for other in [
            "",
            "admin",
            "Auditor",
            "security_admin ",
            "instance_auditor",
        ] {
            assert!(other.parse::<AdminRole>().is_err(), "{other}");
        }
    }

    #[test]
    fn the_locks_are_for_share_by_id() {
        for (lock, table) in [
            (LOCK_IDENTITY, "admin_identity"),
            (LOCK_CREDENTIAL, "admin_credential"),
            (LOCK_BINDING, "admin_role_binding"),
        ] {
            assert_eq!(lock, format!("SELECT FROM {table} WHERE id = $1 FOR SHARE"));
        }
    }

    /// The lookup by IDs is the lookup by key with only the credential
    /// predicate replaced.
    #[test]
    fn the_lookup_by_ids_differs_only_in_the_credential_predicate() {
        assert_eq!(
            AUTHORIZE_CREDENTIAL,
            AUTHORIZE_OPERATOR.replace(
                "WHERE c.public_identity = $1 AND",
                "WHERE c.id = $1 AND c.admin_id = $4 AND"
            )
        );
        assert_eq!(AUTHORIZE_CREDENTIAL.matches("c.public_identity").count(), 0);
    }

    #[test]
    fn the_statement_checks_every_status_role_and_scope() {
        for predicate in [
            "JOIN admin_identity i ON i.id = c.admin_id",
            "JOIN admin_role_binding b ON b.admin_id = i.id",
            "c.public_identity = $1",
            "c.status = 'enabled'",
            "c.revoked_at IS NULL",
            "i.status = 'enabled'",
            "b.status = 'enabled'",
            "b.role = $2",
            "(($3::text IS NULL AND b.tenant_id IS NULL) OR b.tenant_id = $3::text)",
        ] {
            assert_eq!(
                AUTHORIZE_OPERATOR.matches(predicate).count(),
                1,
                "{predicate}"
            );
        }
        // One statement, no ordering, no clock.
        for absent in [
            ";",
            "ORDER BY",
            "now()",
            "current_timestamp",
            "LIKE",
            "lower(",
        ] {
            assert!(!AUTHORIZE_OPERATOR.contains(absent), "{absent}");
        }
    }
}
