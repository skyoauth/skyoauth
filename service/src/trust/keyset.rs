//! The audited write path of a trust keyset version (T11.3, T11.9;
//! ADR-005 items 1, 5 and 8; tasks section 3, the
//! `/admin/v1/tenants/{tenant}/keysets` row; migrations README, "What 0004
//! adds", the service rules).
//!
//! [`create_version`], [`enable_version`] and [`disable_version`] wrap the
//! registry's bare [`create_trust_keyset_version`] and
//! [`update_trust_keyset_version`], which check nothing the database does
//! not. They run in the caller's transaction and neither commit nor roll
//! it back. The upload is validated before that transaction, by
//! [`validate_upload`]. The picks below are the lead's (provisional lead
//! pick, 2026-11-22) unless marked (inferred); all are provisional until
//! the maintainer ratifies the ADRs (T00.8 to T00.17, Gate M0), and so are
//! the [`crate::jwk`] picks dated 2026-11-21 that this module relies on.
//! The widening ruling below is the user's, not a provisional pick.
//!
//! # Not wired, and the one write path
//!
//! - **Widening.** A keyset version write (a create, an enable, a
//!   re-enable) counts as widening: while `widening_second_approver` is on
//!   it needs an IR-054 approval by a second approver (ruled by the user,
//!   2026-11-22, relayed by the lead; this decides OQ-ADR008-3 and the
//!   widening question of identity-registry IR-052 for this write). What
//!   remains is the design of the second-approver flow (T14.1, T14.2).
//! - **No endpoint.** Nothing calls these functions yet, and they must not
//!   be wired to any endpoint before the T14.1 and T14.2 design of the
//!   second-approver flow, and before the request layer of T14.1 and T14.2
//!   exists (generated IDs, the raw body bound, the role of each endpoint).
//! - **Single actor.** A write takes effect at once on one operator's
//!   authority: no write waits for an approval. With
//!   `widening_second_approver` on, a [`create_version`] or an
//!   [`enable_version`] here would apply a widening write without the
//!   approval it needs, which is why the module must not be wired before
//!   that flow is designed. (The ruling names a create, an enable and a
//!   re-enable; [`disable_version`] is not among them.)
//! - **The only write path.** The registry writers
//!   [`create_trust_keyset_version`] and [`update_trust_keyset_version`]
//!   are the unchecked floor: they store any `public_jwks` and
//!   `fingerprint` the `0004` `CHECK`s allow and re-enable a version with no
//!   overlap check. They stay public for the integration and scenario tests
//!   (the scenario crate calls them, so they cannot be crate-private), are
//!   documented as test-only, and must stay unreachable from any endpoint.
//!   This module must be the only path that writes a keyset version
//!   outside tests. The A04 scenario tests (`tests/security`) stay on the
//!   raw writers until A04 M1a is claimed, then switch to this module
//!   (follow-up).
//!
//! # Stage A: the upload, outside the transaction
//!
//! [`validate_upload`] runs [`validate_keyset`] on the parsed upload, every
//! point check included, and returns the [`ValidatedKeyset`]. The caller
//! runs it before it opens the write's transaction, so no lock is held
//! while an upload is validated. Validation is CPU-bound (about 8.8 ms per
//! Ed25519 key in release, about 0.18 s per 20-key set; [`crate::jwk`],
//! "Follow-ups"), so it runs on tokio's blocking pool
//! (`spawn_blocking`), at most [`VALIDATION_WORKERS`] at a time across the
//! process (2, inferred), behind a semaphore; a caller over the limit waits
//! for a worker, without a bound. This pool is Stage A's alone: the
//! in-transaction parses of Stage B have their own (see "Cost"). The
//! semaphore is tokio's: this crate's manifest names
//! tokio's `sync` feature, which `sqlx` and `hyper` already compiled in, so
//! the lockfile did not change. The raw request body must be bounded before
//! it is parsed into the `Value` this function takes (64 KiB is consistent;
//! [`crate::jwk`], "Rules"): that is the wiring's.
//!
//! The write functions take that `&ValidatedKeyset`, never a
//! [`StoredKeyset`](crate::jwk::StoredKeyset) or a bare string, so only a
//! fully validated set reaches a write.
//!
//! # Stage B: the write, in the caller's transaction
//!
//! - **Who.** The operator must be a `trust_admin` of the version's tenant
//!   (tasks section 3: tenant `trust_admin` for `/keysets`):
//!   [`authorize_operator_locked`] with the presented `public_identity`,
//!   [`OperatorScope::Tenant`] of the tenant and [`AdminRole::TrustAdmin`].
//!   The functions build that request themselves, so a caller cannot ask
//!   for another role or scope (inferred). Roles do not inherit: a
//!   `security_admin`, another tenant's `trust_admin`, a `client_admin` or
//!   an `auditor` of the tenant is refused. Every miss is the one
//!   [`KeysetWriteError::Unauthorized`], and an unauthorized write learns
//!   nothing about the keyset or the version, not even whether it exists.
//!   T13.2 owns the role semantics; this is the role the tasks table names,
//!   and [`authorize_operator_locked`] expresses it as is.
//! - **What is stored.** The version's `public_jwks` is the validated
//!   canonical public projection ([`ValidatedKeyset::public_json`]: only
//!   `alg`, `kty`, `kid` and the key members), never the raw upload, and its
//!   `fingerprint` column holds [`KeysetFingerprint::as_str`] (the
//!   unpadded base64url SHA-256 of the projection; provisional lead pick,
//!   2026-11-22). `jsonb` keeps the projection's members, not its bytes; a
//!   reader recomputes the projection with [`parse_stored`].
//! - **Provenance** (inferred). `provenance` is stored as given, and the
//!   database floor does not look at it. It must never carry upload
//!   content: [`create_version`] refuses one with a member named like a JWK
//!   private member ([`PRIVATE_MEMBERS`]), at any depth and inside arrays,
//!   with [`KeysetWriteError::PrivateMemberInProvenance`], before any
//!   statement. Member names only: a value is not looked at.
//! - **Overlap.** [`check_version_overlap`] runs wherever a version becomes
//!   enabled: [`create_version`] of an enabled version and
//!   [`enable_version`] (a re-enable included). A disabled create and
//!   [`disable_version`] run no overlap check. The check compares the
//!   version with every other enabled version of the keyset whose window
//!   intersects its own ([`crate::jwk`], "Versions"). An
//!   [`enable_version`] of a version that is already enabled is checked and
//!   written like any other (inferred: the revision advances and the event
//!   is appended).
//! - **Whole microseconds** (inferred). The registry stores a time floored
//!   to a whole microsecond, so [`create_version`] floors `effective_at`
//!   and `expires_at` the same way, through the one helper the writer uses,
//!   before the check: a window `[T0, T1 + 500 ns)` next to an enabled
//!   `[T1, T2)` is stored as `[T0, T1)` and is accepted whether it is
//!   created enabled or created disabled and then enabled. A window empty
//!   once floored (`[T, T + 500 ns)`) is not checked: the `0004` validity
//!   check refuses it ([`RegistryError::Invariant`],
//!   `trust_keyset_version_validity_check`).
//! - **At most [`MAX_ENABLED_VERSIONS_PER_KEYSET`] enabled versions** (8,
//!   provisional lead pick, 2026-11-22). Where a version becomes enabled,
//!   the other enabled versions of the keyset are counted under the parent
//!   lock, before any stored version is parsed; at the bound the write is
//!   [`KeysetWriteError::TooManyEnabledVersions`]. Disabled versions do not
//!   count, and a re-enable does not count itself. An enabled version past
//!   its expiry still counts: disabling it is what frees its slot.
//! - **Stored versions are parsed again in full.** The check needs every
//!   compared version as a [`JwkSet`], which only the full parse builds, and
//!   [`KeysetVersion`] is not changed here. So each stored version the check
//!   compares (the other enabled versions whose windows intersect, and for
//!   [`enable_version`] the enabled version itself) is first read through
//!   [`parse_stored`] as a cheap gate (size before the parse, then shape and
//!   member rules, no point arithmetic), then fully parsed with
//!   `validate_keyset(&stored, &KNOWN_ALGORITHMS)`, point checks included,
//!   on the in-transaction pool, not Stage A's (see "Cost"). A stored
//!   version that fails either is [`KeysetWriteError::StoredVersion`], a
//!   data-integrity error naming no value, and the version is not enabled.
//!   An enabled version whose window does not intersect is not parsed
//!   (inferred: the check would skip it).
//! - **Cost.** That full parse runs inside the transaction and is linear in
//!   the intersecting enabled versions; the cap holds it to up to 8 stored
//!   sets per write (an enable's target and at most 7 others). While it
//!   runs it holds the parent keyset row, the operator rows `FOR SHARE`, a
//!   database connection and one of the [`IN_TRANSACTION_WORKERS`]
//!   process-wide workers (2, inferred), a pool of its own, separate from
//!   Stage A's [`VALIDATION_WORKERS`]: an upload being validated never
//!   delays a lock-holding parse, and a parse never takes a Stage A worker
//!   (second-approver proposal, section 8, D13). Each parse step (an
//!   enable's own target first, then the compared versions, even when
//!   none intersects) waits at most [`IN_TRANSACTION_WAIT`]
//!   (2 s, inferred) for a worker, under the locks above; a worker not
//!   granted in time is [`KeysetWriteError::ValidationBusy`], retryable, and
//!   the write's savepoint rollback releases the parent lock and the
//!   operator rows. The bound is on the wait only, not on the parse; it is
//!   tokio's `timeout`, so the manifest names tokio's `time` feature, which
//!   `sqlx` and `axum` already compiled in (the lockfile did not change).
//!   The estimate is about 0.18 s per compared 20-key set in release, plus that
//!   wait; debug builds measured 0.30 s for 1 and 1.31 s for 8 compared
//!   versions, the most the cap allows. It is a known cost, not a design
//!   goal. **Wiring precondition** (done): before any endpoint calls this
//!   module, the in-transaction parses needed a permit or priority of their
//!   own, separate from Stage A's; they now have the pool, the bounded wait
//!   and [`KeysetWriteError::ValidationBusy`] above. Follow-up: a change of
//!   [`KeysetVersion`] to take stored keys, or a stored marker that a
//!   projection passed the point checks, would remove the parse.
//! - **The verifier.** The T11.7 verifier's key cache is built the same
//!   way, from `validate_keyset(&stored, &KNOWN_ALGORITHMS)` per version,
//!   never from [`parse_stored`], whose keys are not verifier-ready.
//! - **Rotation** (inferred, [`crate::jwk`], "Versions"). Validity windows
//!   are immutable in the registry, so disabling is the only way to retire a
//!   version, an open-ended one included. To replace the key of a `kid`:
//!   [`disable_version`] the old open-ended version, then
//!   [`create_version`] the replacement, enabled, with the same `kid`. A
//!   re-enable of the old version is refused with
//!   [`KeysetWriteError::Overlap`] while the replacement is enabled, and
//!   accepted once it is disabled. Whether windows should stay immutable, so
//!   that an operator could close an open-ended window instead, is an open
//!   question.
//!
//! No error's `Display` or `Debug` contains a `kid`, key material, an ID
//! or another value of the request (see [`KeysetWriteError`]).
//!
//! # Order and locks
//!
//! [`create_version`] first refuses a `provenance` naming a private member,
//! before any statement. Then each write function runs these steps in a
//! savepoint of its own:
//!
//! 0. reads `transaction_isolation` and refuses any value but
//!    `read committed` with [`KeysetWriteError::UnsupportedIsolation`],
//!    before any other statement and any lock (see "Isolation");
//! 1. [`authorize_operator_locked`]: the operator's `admin_identity`,
//!    `admin_credential` and `admin_role_binding` rows `FOR SHARE`, in the
//!    `0005` order;
//! 2. [`enable_version`] and [`disable_version`] only: reads the version's
//!    `keyset_id`, without a lock (the column is immutable). A version
//!    missing from the tenant is [`RegistryError::NotFound`];
//! 3. the parent `trust_keyset` row by tenant and ID `FOR NO KEY UPDATE`.
//!    A keyset missing from the tenant is [`RegistryError::NotFound`]. This
//!    lock serializes the writes of one keyset: every write here takes it
//!    before it reads the versions, so two writes of one keyset never both
//!    see the keyset without the other's version;
//! 4. reads only what the write needs, in new statements after the parent
//!    lock and with no lock of their own (the parent lock covers them;
//!    inferred): a create of a disabled version reads no version; a create
//!    of an enabled version reads the keyset's enabled versions; an enable
//!    reads its target (keys included), refuses another revision with
//!    [`RegistryError::StaleRevision`], then reads the enabled versions; a
//!    disable reads its target's revision only and refuses another one the
//!    same way. A disabled version other than the target is never fetched,
//!    so its size or content costs the write nothing;
//! 5. when the version becomes enabled: the count of the other enabled
//!    versions against [`MAX_ENABLED_VERSIONS_PER_KEYSET`], then the full
//!    parse of the compared stored versions on the in-transaction pool
//!    (see "Cost") and [`check_version_overlap`];
//! 6. the registry write: the insert (whose foreign-key checks take
//!    `FOR KEY SHARE` on the tenant and the keyset, already held more
//!    strongly by step 3) or the compare-and-set status update (which
//!    locks the version row);
//! 7. [`append_audit_event`] last, which locks the tenant row
//!    `FOR KEY SHARE` and then the chain head (migrations README, "append
//!    audit events in this order").
//!
//! So the lock order is: operator rows, then the `trust_keyset` row
//! (`FOR NO KEY UPDATE`), then the version row (a status change), then the
//! audit head. `FOR NO KEY UPDATE` conflicts with another
//! `FOR NO KEY UPDATE` and with a keyset update, not with the
//! `FOR KEY SHARE` of a trust source insert's or update's foreign-key
//! check. A trust source update holds its own source row `FOR UPDATE`
//! ([`crate::trust::source`]), a row this path never locks.
//!
//! **One keyset per transaction.** A caller's transaction writes the
//! versions of one keyset only. The audit head a write takes last stays
//! held until the caller's transaction ends (the write's savepoint is
//! released, not rolled back), so a second write of another keyset in the
//! same transaction locks a `trust_keyset` row after the audit head,
//! against the order above. Two such transactions writing two keysets in
//! opposite orders deadlock: PostgreSQL aborts one statement with `40P01`,
//! which is [`RegistryError::Retry`] in [`KeysetWriteError::Registry`];
//! its savepoint is rolled back, and the caller retries the whole
//! transaction.
//!
//! # Isolation
//!
//! The functions run only under `READ COMMITTED`, as the trust source
//! writes and [`restore_operator`](crate::persistence::registry::restore_operator)
//! do: any other level is [`KeysetWriteError::UnsupportedIsolation`] at
//! step 0, which takes no lock, writes nothing and leaves the caller's
//! transaction usable. Under `READ COMMITTED` the read of step 4, a new
//! statement after the parent lock was granted, sees every version a write
//! that held the lock before committed; under `REPEATABLE READ` it would
//! read the snapshot and miss it. A `40001` or `40P01` from any step is
//! [`RegistryError::Retry`] in [`KeysetWriteError::Registry`]: retry the
//! whole transaction.
//!
//! # Audit event
//!
//! One event, last, in the version's tenant: actor the authorized operator
//! (`{"type": "operator", "id": <admin_id>}`), `object_id` the version's
//! ID, outcome `success` (inferred, as for bootstrap and restore). A create
//! is `trust_keyset_version.create` with no previous revision and the new
//! row's revision; a status change is `trust_keyset_version.enable` or
//! `trust_keyset_version.disable` (identity-registry IR-059) with the
//! stored and the new revision. The envelope has no member for the keys,
//! the fingerprint or the window, so the event records none of them: the
//! link from an event to the keys it covers rests on the version row,
//! whose keys, fingerprint and window the `0004` immutability triggers
//! keep fixed (IR-059). Whether the event should carry the fingerprint is
//! an ADR question (see "Not done here").
//!
//! # Errors and rollback
//!
//! Each write function runs its steps in a savepoint (`Transaction::begin`
//! on the caller's transaction), releases it on `Ok` and rolls it back on
//! every `Err`: a caller that commits after an `Err` commits none of the
//! function's rows, and its transaction stays usable. Rolling the savepoint
//! back releases the locks taken in it. The caller still rolls back on
//! `Err`, since a failed savepoint rollback leaves the rows in place.
//!
//! # Not done here
//!
//! - Wiring to an endpoint, and the second-approver flow that the widening
//!   ruling above requires (IR-054 approvals while
//!   `widening_second_approver` is on; OQ-ADR008-3, IR-052; T14.1, T14.2).
//! - The raw request-body bound before the upload is parsed.
//! - The keyset's own status: a version of a disabled keyset is written
//!   like any other (inferred: the verifier reads the keyset's status).
//! - Tenant status (the operator lookup does not read it).
//! - Import and restore paths (T10.5): they must run the same overlap
//!   check where a version becomes enabled.
//! - What the design section 5.7 export carries of a version (OQ-IR-6).
//! - A fingerprint in the audit event (an ADR question: the envelope has
//!   no member for it).
//! - Moving the A04 scenario tests from the raw writers to this module,
//!   once A04 M1a is claimed.
//!
//! [`authorize_operator_locked`]: crate::persistence::registry::authorize_operator_locked
//! [`OperatorScope::Tenant`]: crate::persistence::registry::OperatorScope::Tenant
//! [`AdminRole::TrustAdmin`]: crate::persistence::registry::AdminRole::TrustAdmin

use std::{
    fmt,
    time::{Duration, SystemTime},
};

use serde_json::Value;
use sqlx::{Postgres, Transaction};
use tokio::sync::{Semaphore, SemaphorePermit};

use super::write::{WriteError, authorize_trust_admin, in_savepoint, require_read_committed};
use crate::jwk::{
    Algorithm, JwkSet, JwkSetError, KNOWN_ALGORITHMS, KeysetFingerprint, KeysetVersion,
    OverlapError, PRIVATE_MEMBERS, ValidatedKeyset, VersionStatus, check_version_overlap,
    parse_stored, validate_keyset,
};
use crate::persistence::registry::{
    AuditActor, JsonObject, KeysetVersionText, NewAuditEvent, NewTrustKeysetVersion, RegistryError,
    Status, TrustKeysetVersion, append_audit_event, create_trust_keyset_version,
    floor_to_microsecond, read_enabled_keyset_versions, read_keyset_version,
    update_trust_keyset_version,
};

/// The most Stage A validations ([`validate_upload`]) that run at once,
/// across the process (inferred). Each takes one blocking worker. The
/// in-transaction parses do not count against it: they have
/// [`IN_TRANSACTION_WORKERS`].
pub const VALIDATION_WORKERS: usize = 2;

/// The most in-transaction parses of stored versions that run at once,
/// across the process (inferred; second-approver proposal, section 8,
/// D13). Each takes one blocking worker, from a pool separate from
/// Stage A's [`VALIDATION_WORKERS`] (see the module docs, "Cost").
pub const IN_TRANSACTION_WORKERS: usize = 2;

/// How long an in-transaction parse waits for one of the
/// [`IN_TRANSACTION_WORKERS`] (inferred; second-approver proposal,
/// section 8, D13). It bounds the wait for the permit only, not the parse:
/// a permit not granted in time is [`KeysetWriteError::ValidationBusy`].
pub const IN_TRANSACTION_WAIT: Duration = Duration::from_secs(2);

/// The most enabled versions one keyset may have (provisional lead pick,
/// 2026-11-22). A create of an enabled version or an enable that would
/// pass it is [`KeysetWriteError::TooManyEnabledVersions`], counted under
/// the parent keyset lock and before any stored version is parsed; disabled
/// versions do not count. It bounds the in-transaction parse of
/// [`check_version_overlap`]'s input (see the module docs, "Cost").
pub const MAX_ENABLED_VERSIONS_PER_KEYSET: usize = 8;

/// The permits of Stage A's bounded validation pool.
static VALIDATION: Semaphore = Semaphore::const_new(VALIDATION_WORKERS);

/// The permits of the in-transaction parse pool.
static IN_TRANSACTION: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);

/// The audit action of [`create_version`] (identity-registry IR-059).
const CREATE_ACTION: &str = "trust_keyset_version.create";

/// The audit action of [`enable_version`] (identity-registry IR-059).
const ENABLE_ACTION: &str = "trust_keyset_version.enable";

/// The audit action of [`disable_version`] (identity-registry IR-059).
const DISABLE_ACTION: &str = "trust_keyset_version.disable";

/// The outcome of the event (inferred, as for bootstrap).
const SUCCESS: &str = "success";

/// Step 2 of a status change: the version's keyset, immutable, unlocked.
const VERSION_KEYSET: &str =
    "SELECT keyset_id FROM trust_keyset_version WHERE tenant_id = $1 AND id = $2";

/// Step 4 of a disable: the version's revision, after the parent lock; no
/// other column is fetched.
const TARGET_REVISION: &str =
    "SELECT revision FROM trust_keyset_version WHERE tenant_id = $1 AND id = $2";

/// Step 3: the parent keyset, locked for the rest of the transaction.
const LOCK_KEYSET: &str =
    "SELECT revision FROM trust_keyset WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE";

/// What the write's audit event takes from the caller: its ID
/// (caller-generated, T10.2) and the caller's `now`, never the database's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeysetAudit<'a> {
    pub event_id: &'a str,
    pub now: SystemTime,
}

/// The input of [`create_version`]: the registry's
/// [`NewTrustKeysetVersion`] with the keys as a [`ValidatedKeyset`] from
/// [`validate_upload`] in place of the `public_jwks` and `fingerprint`
/// columns, which the function derives from it.
#[derive(Debug, Clone, Copy)]
pub struct NewKeysetVersion<'a> {
    pub id: &'a str,
    pub tenant_id: &'a str,
    pub keyset_id: &'a str,
    pub keys: &'a ValidatedKeyset,
    pub effective_at: SystemTime,
    /// `None` for no expiry; after `effective_at` when set (the `0004`
    /// validity check refuses an empty window).
    pub expires_at: Option<SystemTime>,
    /// [`Status::Enabled`] runs the overlap check; [`Status::Disabled`]
    /// does not.
    pub status: Status,
    /// Who supplied the keys and from where; no shape is specified. It
    /// must never carry upload content: a member named like a JWK private
    /// member ([`PRIVATE_MEMBERS`]), at any depth, is
    /// [`KeysetWriteError::PrivateMemberInProvenance`] (inferred).
    pub provenance: &'a JsonObject,
}

/// Why [`validate_upload`], [`create_version`], [`enable_version`] or
/// [`disable_version`] did not succeed. On every variant from a write
/// function, its savepoint is rolled back; the caller rolls back too.
///
/// `Display` is fixed text per variant and `Debug` names the variant (and
/// the conflict kind of [`Self::Overlap`]) only: neither contains a `kid`,
/// key material, an ID or another value of the request. The inner
/// [`JwkSetError`] and [`OverlapError`], which do name `kid`s and version
/// IDs, are in the variants for the caller to map, and are not returned by
/// `source()`, so an error-chain report does not print them (inferred).
///
/// The enum is `#[non_exhaustive]`: a later task may add a variant.
#[non_exhaustive]
pub enum KeysetWriteError {
    /// The presented credential does not authorize a `trust_admin` of the
    /// version's tenant. Every cause is this one value, with no detail.
    Unauthorized,
    /// The upload breaks a rule of [`crate::jwk`] (a client error).
    Upload(JwkSetError),
    /// The version, becoming enabled, conflicts with another enabled
    /// version of the keyset whose window intersects its own.
    Overlap(OverlapError),
    /// A stored version the overlap check compares fails [`parse_stored`]
    /// or the full [`validate_keyset`] pass: a data-integrity error (a row
    /// written outside this module), not a client error.
    StoredVersion {
        /// The stored version's ID.
        version_id: String,
        /// The rule it breaks.
        error: JwkSetError,
    },
    /// The version, becoming enabled, would give the keyset more than
    /// [`MAX_ENABLED_VERSIONS_PER_KEYSET`] enabled versions. Disable one
    /// first.
    TooManyEnabledVersions,
    /// The version's `provenance` names a JWK private member
    /// ([`PRIVATE_MEMBERS`]) at some depth (inferred): it may carry no
    /// upload content. Checked before any statement.
    PrivateMemberInProvenance,
    /// The caller's transaction does not run at `READ COMMITTED` (see the
    /// module docs, "Isolation"). Not retryable as is: the caller retries
    /// in a `READ COMMITTED` transaction.
    UnsupportedIsolation,
    /// The blocking validation worker returned no result (the runtime is
    /// shutting down).
    WorkerUnavailable,
    /// No in-transaction parse worker ([`IN_TRANSACTION_WORKERS`]) was free
    /// within [`IN_TRANSACTION_WAIT`], so the stored versions were not
    /// parsed and the version was not enabled (see the module docs,
    /// "Cost"). Retryable: the write's savepoint is rolled back, which
    /// releases the parent keyset lock and the operator rows. Only a write
    /// that makes a version enabled returns it; [`validate_upload`] waits
    /// for its own workers without a bound.
    ValidationBusy,
    /// A registry error: a store failure, [`RegistryError::Retry`] (retry
    /// the whole transaction), or the write's own outcome, such as
    /// [`RegistryError::NotFound`], [`RegistryError::StaleRevision`],
    /// [`RegistryError::AlreadyExists`] or a `0004` constraint.
    Registry(RegistryError),
}

/// The fixed name of a conflict kind.
fn conflict_kind(err: &OverlapError) -> &'static str {
    match err {
        OverlapError::KidConflict { .. } => "KidConflict",
        OverlapError::KeyConflict { .. } => "KeyConflict",
        OverlapError::AlgorithmConflict { .. } => "AlgorithmConflict",
    }
}

impl fmt::Display for KeysetWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => {
                f.write_str("the operator may not write this tenant's trust keyset versions")
            }
            Self::Upload(_) => f.write_str("the uploaded JWK set breaks the JWK set rules"),
            Self::Overlap(err) => {
                let what = match err {
                    OverlapError::KidConflict { .. } => "a kid with a different key",
                    OverlapError::KeyConflict { .. } => "a key with a different kid",
                    OverlapError::AlgorithmConflict { .. } => "a kid with a different algorithm",
                };
                write!(
                    f,
                    "the keyset version gives {what} than an enabled version of the keyset \
                     whose validity window intersects its own"
                )
            }
            Self::StoredVersion { .. } => {
                f.write_str("a stored version of the keyset breaks the JWK set rules")
            }
            Self::TooManyEnabledVersions => {
                f.write_str("the keyset already has the most enabled versions allowed")
            }
            Self::PrivateMemberInProvenance => {
                f.write_str("the keyset version's provenance names a JWK private member")
            }
            Self::UnsupportedIsolation => {
                f.write_str("trust keyset version writes run only at READ COMMITTED")
            }
            Self::WorkerUnavailable => f.write_str("no JWK set validation worker returned"),
            Self::ValidationBusy => {
                f.write_str("the in-transaction validation workers are busy; retry")
            }
            Self::Registry(err) => write!(f, "trust keyset version write failed: {err}"),
        }
    }
}

impl fmt::Debug for KeysetWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("Unauthorized"),
            Self::Upload(_) => f.write_str("Upload(..)"),
            Self::Overlap(err) => write!(f, "Overlap({})", conflict_kind(err)),
            Self::StoredVersion { .. } => f.write_str("StoredVersion { .. }"),
            Self::TooManyEnabledVersions => f.write_str("TooManyEnabledVersions"),
            Self::PrivateMemberInProvenance => f.write_str("PrivateMemberInProvenance"),
            Self::UnsupportedIsolation => f.write_str("UnsupportedIsolation"),
            Self::WorkerUnavailable => f.write_str("WorkerUnavailable"),
            Self::ValidationBusy => f.write_str("ValidationBusy"),
            Self::Registry(err) => f.debug_tuple("Registry").field(err).finish(),
        }
    }
}

impl std::error::Error for KeysetWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(err) => Some(err),
            _ => None,
        }
    }
}

impl From<RegistryError> for KeysetWriteError {
    fn from(err: RegistryError) -> Self {
        Self::Registry(err)
    }
}

impl From<sqlx::Error> for KeysetWriteError {
    fn from(err: sqlx::Error) -> Self {
        Self::Registry(err.into())
    }
}

impl WriteError for KeysetWriteError {
    const UNSUPPORTED_ISOLATION: Self = Self::UnsupportedIsolation;
    const UNAUTHORIZED: Self = Self::Unauthorized;
}

/// Runs `work` on tokio's blocking pool once one of the
/// [`VALIDATION_WORKERS`] permits is free, however long that takes
/// (Stage A). The permit moves into the blocking task, so it is held until
/// `work` returns even if the caller's future is dropped first.
async fn on_validation_worker<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, KeysetWriteError> {
    on_pool(&VALIDATION, work).await
}

/// Runs `work` on tokio's blocking pool once one of the
/// [`IN_TRANSACTION_WORKERS`] permits is free, waiting at most
/// [`IN_TRANSACTION_WAIT`] for it; past that, `work` does not run and the
/// result is [`KeysetWriteError::ValidationBusy`]. The bound is on the
/// wait only: once granted, the permit moves into the blocking task, which
/// runs `work` to its end and holds the permit until it returns, even if
/// the caller's future is dropped first.
async fn on_in_transaction_worker<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, KeysetWriteError> {
    on_pool_within(&IN_TRANSACTION, IN_TRANSACTION_WAIT, work).await
}

/// [`on_validation_worker`] on the pool `pool` (the tests use pools of
/// their own, so tests running in one process cannot disturb each other's
/// permit counts).
async fn on_pool<T: Send + 'static>(
    pool: &'static Semaphore,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, KeysetWriteError> {
    let permit = pool
        .acquire()
        .await
        .map_err(|_| KeysetWriteError::WorkerUnavailable)?;
    run_holding(permit, work).await
}

/// [`on_in_transaction_worker`] on the pool `pool`, waiting at most `wait`
/// for a permit (the tests use pools and waits of their own). A waiter
/// that gives up leaves the semaphore's queue as it was: tokio's `Acquire`
/// gives back on drop any permit it was granted, so the next waiter in
/// line gets it.
async fn on_pool_within<T: Send + 'static>(
    pool: &'static Semaphore,
    wait: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, KeysetWriteError> {
    let permit = match tokio::time::timeout(wait, pool.acquire()).await {
        Ok(acquired) => acquired.map_err(|_| KeysetWriteError::WorkerUnavailable)?,
        Err(_elapsed) => return Err(KeysetWriteError::ValidationBusy),
    };
    run_holding(permit, work).await
}

/// Runs `work` on tokio's blocking pool, `permit` moved into the blocking
/// task so that it is released when `work` returns or unwinds, not when the
/// caller's future is dropped. A panic in `work` is resumed in the caller.
async fn run_holding<T: Send + 'static>(
    permit: SemaphorePermit<'static>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, KeysetWriteError> {
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    });
    match task.await {
        Ok(value) => Ok(value),
        Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
        Err(_) => Err(KeysetWriteError::WorkerUnavailable),
    }
}

/// Stage A: validates the parsed upload `upload` with [`validate_keyset`]
/// against the `allowed` algorithms, on the bounded blocking pool (see the
/// module docs). Run it before opening the write's transaction; pass the
/// result to [`create_version`]. A refused upload is
/// [`KeysetWriteError::Upload`].
pub async fn validate_upload(
    upload: Value,
    allowed: &[Algorithm],
) -> Result<ValidatedKeyset, KeysetWriteError> {
    let allowed = allowed.to_vec();
    on_validation_worker(move || validate_keyset(&upload, &allowed))
        .await?
        .map_err(KeysetWriteError::Upload)
}

/// A stored set parsed in full: [`parse_stored`] first, as a gate, then
/// [`validate_keyset`] with [`KNOWN_ALGORITHMS`], point checks included.
fn parse_in_full(stored: &str) -> Result<ValidatedKeyset, JwkSetError> {
    parse_stored(stored)?;
    let value: Value = serde_json::from_str(stored).map_err(|_| JwkSetError::NotJson)?;
    validate_keyset(&value, &KNOWN_ALGORITHMS)
}

/// [`parse_in_full`] of each stored version, in order, on one of the
/// [`IN_TRANSACTION_WORKERS`] (not Stage A's pool); the first failure names
/// its version. No permit within [`IN_TRANSACTION_WAIT`] is
/// [`KeysetWriteError::ValidationBusy`].
async fn parse_stored_versions(
    rows: Vec<KeysetVersionText>,
) -> Result<Vec<(KeysetVersionText, ValidatedKeyset)>, KeysetWriteError> {
    on_in_transaction_worker(move || {
        rows.into_iter()
            .map(|row| match parse_in_full(&row.public_jwks) {
                Ok(keys) => Ok((row, keys)),
                Err(error) => Err(KeysetWriteError::StoredVersion {
                    version_id: row.id,
                    error,
                }),
            })
            .collect()
    })
    .await?
}

/// A stored version as [`check_version_overlap`] takes it, with `keys`.
fn as_version<'a>(row: &'a KeysetVersionText, keys: &'a JwkSet) -> KeysetVersion<'a> {
    KeysetVersion {
        id: &row.id,
        effective_at: row.effective_at,
        expires_at: row.expires_at,
        status: match row.status {
            Status::Enabled => VersionStatus::Enabled,
            Status::Disabled => VersionStatus::Disabled,
        },
        keys,
    }
}

/// Step 5: `version`, becoming enabled, against the keyset's enabled
/// versions `rows` (as [`read_enabled_keyset_versions`] reads them) but its
/// own ID, those whose windows intersect its own, each parsed in full first.
async fn check_overlap(
    version: &KeysetVersion<'_>,
    rows: Vec<KeysetVersionText>,
) -> Result<(), KeysetWriteError> {
    let compared: Vec<KeysetVersionText> = rows
        .into_iter()
        // Excluding the version's own ID is not only a saving: the check
        // skips it anyway, but a create that reuses the ID of a stored
        // version would parse that row and could fail as `StoredVersion`
        // instead of the insert's `AlreadyExists`.
        .filter(|row| row.id != version.id)
        // The window only: `version`'s keys stand in for the unparsed ones.
        .filter(|row| version.windows_intersect(&as_version(row, version.keys)))
        .collect();
    let parsed = parse_stored_versions(compared).await?;
    let existing: Vec<KeysetVersion<'_>> = parsed
        .iter()
        .map(|(row, keys)| as_version(row, keys.set()))
        .collect();
    check_version_overlap(version, &existing).map_err(KeysetWriteError::Overlap)
}

/// Step 5, first: refuses a version becoming enabled when the keyset
/// already has [`MAX_ENABLED_VERSIONS_PER_KEYSET`] enabled versions but
/// `id` in `rows` (its enabled versions, read under the parent lock),
/// before any parse.
fn check_enabled_count(rows: &[KeysetVersionText], id: &str) -> Result<(), KeysetWriteError> {
    let enabled = rows.iter().filter(|row| row.id != id).count();
    if enabled >= MAX_ENABLED_VERSIONS_PER_KEYSET {
        return Err(KeysetWriteError::TooManyEnabledVersions);
    }
    Ok(())
}

/// Whether `provenance` has a member named like a JWK private member
/// ([`PRIVATE_MEMBERS`]), in itself or in any object it holds, arrays
/// included. Iterative, so a deep value cannot exhaust the stack.
fn names_a_private_member(provenance: &JsonObject) -> bool {
    let mut pending: Vec<&Value> = Vec::new();
    let mut object = Some(provenance);
    loop {
        if let Some(members) = object.take() {
            if members
                .keys()
                .any(|name| PRIVATE_MEMBERS.contains(&name.as_str()))
            {
                return true;
            }
            pending.extend(members.values());
        }
        match pending.pop() {
            None => return false,
            Some(Value::Object(members)) => object = Some(members),
            Some(Value::Array(items)) => pending.extend(items),
            Some(_) => {}
        }
    }
}

/// Step 3: the parent keyset `FOR NO KEY UPDATE`.
async fn lock_keyset(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    keyset_id: &str,
) -> Result<(), KeysetWriteError> {
    sqlx::query(LOCK_KEYSET)
        .bind(tenant_id)
        .bind(keyset_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)?;
    Ok(())
}

/// The registry's form of the stored projection.
fn projection(keys: &ValidatedKeyset) -> Result<JsonObject, KeysetWriteError> {
    serde_json::from_str(keys.public_json())
        .map_err(|err| RegistryError::Other(sqlx::Error::Encode(err.into())).into())
}

/// Step 7: the event of a write by `admin_id`.
async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    audit: &KeysetAudit<'_>,
    admin_id: String,
    action: &str,
    previous_revision: Option<i64>,
    version: &TrustKeysetVersion,
) -> Result<(), KeysetWriteError> {
    append_audit_event(
        transaction,
        &NewAuditEvent {
            id: audit.event_id.into(),
            tenant_id: Some(version.tenant_id.clone()),
            timestamp: audit.now,
            actor: AuditActor::Operator(admin_id),
            action: action.into(),
            object_id: version.id.clone(),
            previous_revision,
            new_revision: Some(version.revision),
            outcome: SUCCESS.into(),
        },
    )
    .await?;
    Ok(())
}

/// Creates the keyset version `new` at revision 1 for the operator whose
/// credential has `public_identity`, storing the projection and fingerprint
/// of `new.keys`; when `new.status` is enabled, after the overlap check
/// against the keyset's enabled versions; and appends its
/// `trust_keyset_version.create` event last, in `transaction` (see the
/// module docs for the rules, the order and the locks). Runs only under
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`.
pub async fn create_version(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewKeysetVersion<'_>,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    if names_a_private_member(new.provenance) {
        return Err(KeysetWriteError::PrivateMemberInProvenance);
    }
    in_savepoint(transaction, async |savepoint| {
        create_steps(savepoint, public_identity, new, audit).await
    })
    .await
}

/// Steps 0 to 7 of [`create_version`], in its savepoint.
async fn create_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewKeysetVersion<'_>,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    require_read_committed::<KeysetWriteError>(transaction).await?;
    let admin_id =
        authorize_trust_admin::<KeysetWriteError>(transaction, public_identity, new.tenant_id)
            .await?;
    lock_keyset(transaction, new.tenant_id, new.keyset_id).await?;
    if new.status == Status::Enabled {
        let rows =
            read_enabled_keyset_versions(&mut **transaction, new.tenant_id, new.keyset_id).await?;
        check_enabled_count(&rows, new.id)?;
        // The window as the write stores it: the stored versions are whole
        // microseconds, so an unfloored bound could see an intersection
        // that a later enable of the stored row would not (inferred).
        let effective_at = floor_to_microsecond(new.effective_at);
        let expires_at = new.expires_at.map(floor_to_microsecond);
        // An empty window is the `0004` validity check's to refuse. The
        // check would compare nothing with it (an empty window intersects
        // none), so skipping it only spares a worker.
        if expires_at.is_none_or(|expires_at| expires_at > effective_at) {
            let version = KeysetVersion {
                id: new.id,
                effective_at,
                expires_at,
                status: VersionStatus::Enabled,
                keys: new.keys.set(),
            };
            check_overlap(&version, rows).await?;
        }
    }
    let fingerprint: &KeysetFingerprint = new.keys.fingerprint();
    let version = create_trust_keyset_version(
        &mut **transaction,
        &NewTrustKeysetVersion {
            id: new.id.into(),
            tenant_id: new.tenant_id.into(),
            keyset_id: new.keyset_id.into(),
            public_jwks: projection(new.keys)?,
            fingerprint: fingerprint.as_str().into(),
            effective_at: new.effective_at,
            expires_at: new.expires_at,
            status: new.status,
            provenance: new.provenance.clone(),
        },
    )
    .await?;
    append_event(transaction, audit, admin_id, CREATE_ACTION, None, &version).await?;
    Ok(version)
}

/// Enables the keyset version `id` of `tenant_id` at `expected_revision`
/// for the operator whose credential has `public_identity`, after the
/// overlap check of its stored keys against the keyset's other enabled
/// versions, and appends its `trust_keyset_version.enable` event last, in
/// `transaction` (see the module docs). A re-enable after a rotation is
/// refused while the replacement is enabled. Runs only under
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`.
pub async fn enable_version(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    let target = (tenant_id, id, expected_revision);
    set_status(transaction, public_identity, target, Status::Enabled, audit).await
}

/// Disables the keyset version `id` of `tenant_id` at `expected_revision`
/// for the operator whose credential has `public_identity`, and appends its
/// `trust_keyset_version.disable` event last, in `transaction` (see the
/// module docs). No overlap check runs. Runs only under `READ COMMITTED`.
/// The caller commits on `Ok` and rolls back on `Err`.
pub async fn disable_version(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    let target = (tenant_id, id, expected_revision);
    set_status(
        transaction,
        public_identity,
        target,
        Status::Disabled,
        audit,
    )
    .await
}

/// [`enable_version`] or [`disable_version`] in a savepoint. `target` is
/// the tenant, the ID and the expected revision.
async fn set_status(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    target: (&str, &str, i64),
    status: Status,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    in_savepoint(transaction, async |savepoint| {
        status_steps(savepoint, public_identity, target, status, audit).await
    })
    .await
}

/// Steps 0 to 7 of a status change, in its savepoint.
async fn status_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    (tenant_id, id, expected_revision): (&str, &str, i64),
    status: Status,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    require_read_committed::<KeysetWriteError>(transaction).await?;
    let admin_id =
        authorize_trust_admin::<KeysetWriteError>(transaction, public_identity, tenant_id).await?;
    let keyset_id: String = sqlx::query_scalar(VERSION_KEYSET)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)?;
    lock_keyset(transaction, tenant_id, &keyset_id).await?;
    // The target, in a new statement after the parent lock: an enable reads
    // the row with its keys, a disable its revision only.
    let (previous_revision, action) = match status {
        Status::Enabled => {
            let stored = read_keyset_version(&mut **transaction, tenant_id, id)
                .await?
                .ok_or(RegistryError::NotFound)?;
            let previous_revision = stored.revision;
            if previous_revision != expected_revision {
                return Err(RegistryError::StaleRevision.into());
            }
            let rows =
                read_enabled_keyset_versions(&mut **transaction, tenant_id, &keyset_id).await?;
            check_enabled_count(&rows, id)?;
            let mut own = parse_stored_versions(vec![stored]).await?;
            let (row, keys) = own.remove(0);
            let version = KeysetVersion {
                status: VersionStatus::Enabled,
                ..as_version(&row, keys.set())
            };
            check_overlap(&version, rows).await?;
            (previous_revision, ENABLE_ACTION)
        }
        Status::Disabled => {
            let previous_revision: i64 = sqlx::query_scalar(TARGET_REVISION)
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&mut **transaction)
                .await?
                .ok_or(RegistryError::NotFound)?;
            if previous_revision != expected_revision {
                return Err(RegistryError::StaleRevision.into());
            }
            (previous_revision, DISABLE_ACTION)
        }
    };
    let version =
        update_trust_keyset_version(&mut **transaction, tenant_id, id, expected_revision, status)
            .await?;
    append_event(
        transaction,
        audit,
        admin_id,
        action,
        Some(previous_revision),
        &version,
    )
    .await?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::jwk::{DEFAULT_ALLOWED_ALGORITHMS, Kid};

    /// The RFC 7517 appendix A.1 P-256 key, as `kid`.
    fn p256(kid: &str) -> Value {
        json!({"keys": [{
            "kty": "EC", "kid": kid, "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        }]})
    }

    fn kid(text: &str) -> Kid {
        let set = validate_keyset(&p256(text), DEFAULT_ALLOWED_ALGORITHMS).unwrap();
        set.keys()[0].kid().clone()
    }

    #[test]
    fn the_statements_name_their_rows_exactly() {
        assert_eq!(
            LOCK_KEYSET,
            "SELECT revision FROM trust_keyset WHERE tenant_id = $1 AND id = $2 \
             FOR NO KEY UPDATE"
        );
        assert_eq!(
            VERSION_KEYSET,
            "SELECT keyset_id FROM trust_keyset_version WHERE tenant_id = $1 AND id = $2"
        );
        assert_eq!(
            TARGET_REVISION,
            "SELECT revision FROM trust_keyset_version WHERE tenant_id = $1 AND id = $2"
        );
        assert_eq!(
            [CREATE_ACTION, ENABLE_ACTION, DISABLE_ACTION],
            [
                "trust_keyset_version.create",
                "trust_keyset_version.enable",
                "trust_keyset_version.disable"
            ]
        );
    }

    #[test]
    fn errors_print_fixed_text_without_values() {
        let versions = || ("ver_old".to_string(), "ver_new".to_string());
        let overlap = |make: fn(String, String) -> OverlapError| {
            let (first, second) = versions();
            KeysetWriteError::Overlap(make(first, second))
        };
        for (err, text, debug) in [
            (
                KeysetWriteError::Unauthorized,
                "the operator may not write this tenant's trust keyset versions",
                "Unauthorized",
            ),
            (
                KeysetWriteError::Upload(JwkSetError::DuplicateKid {
                    kid: kid("secret-kid"),
                    first: 0,
                    second: 1,
                }),
                "the uploaded JWK set breaks the JWK set rules",
                "Upload(..)",
            ),
            (
                overlap(|first_version, second_version| OverlapError::KidConflict {
                    kid: kid("secret-kid"),
                    first_version,
                    second_version,
                }),
                "the keyset version gives a kid with a different key than an enabled version \
                 of the keyset whose validity window intersects its own",
                "Overlap(KidConflict)",
            ),
            (
                overlap(|first_version, second_version| OverlapError::KeyConflict {
                    first_kid: kid("secret-kid"),
                    second_kid: kid("other-kid"),
                    first_version,
                    second_version,
                }),
                "the keyset version gives a key with a different kid than an enabled version \
                 of the keyset whose validity window intersects its own",
                "Overlap(KeyConflict)",
            ),
            (
                overlap(
                    |first_version, second_version| OverlapError::AlgorithmConflict {
                        kid: kid("secret-kid"),
                        first_version,
                        second_version,
                    },
                ),
                "the keyset version gives a kid with a different algorithm than an enabled \
                 version of the keyset whose validity window intersects its own",
                "Overlap(AlgorithmConflict)",
            ),
            (
                KeysetWriteError::StoredVersion {
                    version_id: "ver_old".into(),
                    error: JwkSetError::DuplicateKid {
                        kid: kid("secret-kid"),
                        first: 0,
                        second: 1,
                    },
                },
                "a stored version of the keyset breaks the JWK set rules",
                "StoredVersion { .. }",
            ),
            (
                KeysetWriteError::TooManyEnabledVersions,
                "the keyset already has the most enabled versions allowed",
                "TooManyEnabledVersions",
            ),
            (
                KeysetWriteError::PrivateMemberInProvenance,
                "the keyset version's provenance names a JWK private member",
                "PrivateMemberInProvenance",
            ),
            (
                KeysetWriteError::UnsupportedIsolation,
                "trust keyset version writes run only at READ COMMITTED",
                "UnsupportedIsolation",
            ),
            (
                KeysetWriteError::WorkerUnavailable,
                "no JWK set validation worker returned",
                "WorkerUnavailable",
            ),
            (
                KeysetWriteError::ValidationBusy,
                "the in-transaction validation workers are busy; retry",
                "ValidationBusy",
            ),
            (
                KeysetWriteError::Registry(RegistryError::StaleRevision),
                "trust keyset version write failed: registry row is not at the expected \
                 revision; read it again",
                "Registry(StaleRevision)",
            ),
        ] {
            assert_eq!(err.to_string(), text);
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(
                std::error::Error::source(&err).is_some(),
                matches!(err, KeysetWriteError::Registry(_)),
                "{debug}"
            );
        }
    }

    #[test]
    fn the_pool_has_its_workers() {
        // Only the constant: other tests borrow permits of the shared pool
        // while they run in the same process.
        assert_eq!(VALIDATION_WORKERS, 2);
        assert!(VALIDATION.available_permits() <= VALIDATION_WORKERS);
    }

    /// A validation waits for a free worker and runs once one is free.
    #[tokio::test]
    async fn a_validation_waits_for_a_free_worker() {
        static POOL: Semaphore = Semaphore::const_new(VALIDATION_WORKERS);
        let held = POOL
            .acquire_many(u32::try_from(VALIDATION_WORKERS).unwrap())
            .await
            .unwrap();
        let waiting = tokio::spawn(on_pool(&POOL, || 7_u8));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());
        drop(held);
        let value = tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(value, 7);
        assert_eq!(POOL.available_permits(), VALIDATION_WORKERS);
    }

    /// A running validation holds its permit until its work returns.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_running_validation_holds_its_worker() {
        static POOL: Semaphore = Semaphore::const_new(VALIDATION_WORKERS);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, running) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(on_pool(&POOL, move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        }));
        running.await.unwrap();
        assert_eq!(POOL.available_permits(), VALIDATION_WORKERS - 1);
        release.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(POOL.available_permits(), VALIDATION_WORKERS);
    }

    /// A panic in the work reaches the caller as that panic, not as
    /// [`KeysetWriteError::WorkerUnavailable`], and its permit comes back.
    #[tokio::test]
    async fn a_panicking_validation_panics_its_caller_and_frees_its_worker() {
        static POOL: Semaphore = Semaphore::const_new(VALIDATION_WORKERS);
        let task = tokio::spawn(on_pool(&POOL, || -> u8 {
            std::panic::panic_any("validation panicked")
        }));
        let err = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .expect_err("the caller panics");
        assert!(err.is_panic());
        assert_eq!(
            err.into_panic().downcast_ref::<&str>(),
            Some(&"validation panicked")
        );
        assert_eq!(POOL.available_permits(), VALIDATION_WORKERS);
        // The pool still runs work.
        assert_eq!(on_pool(&POOL, || 7_u8).await.unwrap(), 7);
    }

    #[test]
    fn a_provenance_naming_a_private_member_is_found_at_any_depth() {
        let object = |value: Value| value.as_object().unwrap().clone();
        for value in [
            json!({"d": "x"}),
            json!({"source": {"jwk": {"kty": "EC", "x": "x", "dq": "x"}}}),
            json!({"keys": [{"kty": "oct", "k": "x"}]}),
            json!({"history": [[{"other": [{"oth": []}]}]]}),
        ] {
            assert!(names_a_private_member(&object(value.clone())), "{value}");
        }
        // Names only, exactly: a value or a longer name is not a member.
        for value in [
            json!({}),
            json!({"supplied_by": "d", "via": ["p", "q"], "kid": "k"}),
            json!({"d_source": {"key_ops": ["sign"]}, "notes": [{"D": 1}]}),
        ] {
            assert!(!names_a_private_member(&object(value.clone())), "{value}");
        }
    }

    #[tokio::test]
    async fn a_refused_upload_is_an_upload_error() {
        let err = validate_upload(json!({"keys": []}), DEFAULT_ALLOWED_ALGORITHMS)
            .await
            .unwrap_err();
        assert!(matches!(err, KeysetWriteError::Upload(JwkSetError::NoKeys)));
        // The allowed set is the caller's.
        let err = validate_upload(p256("k"), &[Algorithm::Rs256])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            KeysetWriteError::Upload(JwkSetError::Key { index: 0, .. })
        ));
    }

    #[test]
    fn a_stored_set_is_parsed_in_full() {
        let stored = validate_keyset(&p256("k"), DEFAULT_ALLOWED_ALGORITHMS).unwrap();
        assert_eq!(parse_in_full(stored.public_json()).unwrap(), stored);
        // Off the curve: parse_stored accepts it, the full parse does not.
        let mut off = p256("k");
        off["keys"][0]["y"] = json!("AB530pP2cpYhadpS5FNwg9m8w4UgWFlJJkxIxFl_MPk");
        let off = off.to_string();
        assert!(parse_stored(&off).is_ok());
        assert!(matches!(
            parse_in_full(&off),
            Err(JwkSetError::Key { index: 0, .. })
        ));
        // Too long for the gate: refused before any parse.
        let long = format!("{off}{}", " ".repeat(crate::jwk::MAX_STORED_BYTES));
        assert_eq!(parse_in_full(&long), Err(JwkSetError::TooLarge));
        assert_eq!(parse_in_full("not json"), Err(JwkSetError::NotJson));
    }

    // The in-transaction parse permit (second-approver proposal, section 8,
    // D13). The mechanism tests run `on_pool_within` on pools and waits of
    // their own; only the tests that show which pool a real parse or upload
    // takes hold the process-wide permits, one test at a time (`STATICS`).

    /// Serializes the tests that hold permits of the process-wide pools, so
    /// that, run in one process (`cargo test`), they cannot take each
    /// other's workers. The other tests never hold those permits.
    static STATICS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A bound on every wait of these tests, so a hang fails instead.
    const HANG: Duration = Duration::from_secs(10);

    /// A short wait for the tests' own pools, in place of
    /// [`IN_TRANSACTION_WAIT`].
    const SHORT_WAIT: Duration = Duration::from_millis(150);

    fn all_permits() -> u32 {
        u32::try_from(IN_TRANSACTION_WORKERS).unwrap()
    }

    /// Polls until `pool` has all of its permits back.
    async fn until_all_free(pool: &Semaphore) {
        tokio::time::timeout(HANG, async {
            while pool.available_permits() != IN_TRANSACTION_WORKERS {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the pool never got its permits back");
    }

    /// A stored version as the step 4 read returns it.
    fn stored(id: &str, keys: &Value) -> KeysetVersionText {
        KeysetVersionText {
            id: id.into(),
            public_jwks: keys.to_string(),
            effective_at: SystemTime::UNIX_EPOCH,
            expires_at: None,
            status: Status::Enabled,
            revision: 1,
        }
    }

    #[test]
    fn the_in_transaction_pool_has_its_bounds() {
        assert_eq!(IN_TRANSACTION_WORKERS, 2);
        assert_eq!(IN_TRANSACTION_WAIT, Duration::from_secs(2));
        // A pool of its own, not a share of Stage A's.
        assert!(!std::ptr::eq(&IN_TRANSACTION, &VALIDATION));
    }

    /// At most [`IN_TRANSACTION_WORKERS`] parses run at once; a third
    /// waits until one returns, then runs.
    #[tokio::test(flavor = "multi_thread")]
    async fn at_most_the_in_transaction_workers_parse_at_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        static RUNNING: AtomicUsize = AtomicUsize::new(0);
        static MOST: AtomicUsize = AtomicUsize::new(0);
        let (started_tx, mut started) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let mut releases = Vec::new();
        let mut tasks = Vec::new();
        for n in 0..=IN_TRANSACTION_WORKERS {
            let (release, wait) = std::sync::mpsc::channel::<()>();
            releases.push(release);
            let started_tx = started_tx.clone();
            tasks.push(tokio::spawn(on_pool_within(&POOL, HANG, move || {
                let now = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
                MOST.fetch_max(now, Ordering::SeqCst);
                started_tx.send(n).unwrap();
                wait.recv().unwrap();
                RUNNING.fetch_sub(1, Ordering::SeqCst);
                n
            })));
            // In order, so the last one is the one that waits.
            if n < IN_TRANSACTION_WORKERS {
                let first = tokio::time::timeout(HANG, started.recv()).await.unwrap();
                assert_eq!(first, Some(n));
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(started.try_recv().is_err(), "a third parse runs");
        assert_eq!(RUNNING.load(Ordering::SeqCst), IN_TRANSACTION_WORKERS);
        assert_eq!(POOL.available_permits(), 0);
        // One returns: the third runs.
        releases[0].send(()).unwrap();
        let third = tokio::time::timeout(HANG, started.recv()).await.unwrap();
        assert_eq!(third, Some(IN_TRANSACTION_WORKERS));
        for release in &releases[1..] {
            release.send(()).unwrap();
        }
        for (n, task) in tasks.into_iter().enumerate() {
            let value = tokio::time::timeout(HANG, task).await.unwrap().unwrap();
            assert_eq!(value.unwrap(), n);
        }
        assert_eq!(MOST.load(Ordering::SeqCst), IN_TRANSACTION_WORKERS);
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
    }

    /// A permit not granted within the wait is `ValidationBusy`; the work
    /// never runs, and no permit is lost.
    #[tokio::test]
    async fn no_permit_within_the_wait_is_validation_busy() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        static RAN: AtomicBool = AtomicBool::new(false);
        let held = POOL.acquire_many(all_permits()).await.unwrap();
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            HANG,
            on_pool_within(&POOL, SHORT_WAIT, || RAN.store(true, Ordering::SeqCst)),
        )
        .await
        .expect("the wait is bounded");
        let waited = start.elapsed();
        assert!(
            matches!(result, Err(KeysetWriteError::ValidationBusy)),
            "{result:?}"
        );
        assert!(waited >= SHORT_WAIT, "{waited:?}");
        assert!(!RAN.load(Ordering::SeqCst));
        drop(held);
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
        assert_eq!(on_pool_within(&POOL, SHORT_WAIT, || 7_u8).await.unwrap(), 7);
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
    }

    /// The wait bounds the permit only: a parse that runs longer than the
    /// wait still returns its value.
    #[tokio::test]
    async fn the_wait_bounds_the_permit_not_the_parse() {
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        let value = on_pool_within(&POOL, SHORT_WAIT, || {
            std::thread::sleep(SHORT_WAIT * 3);
            7_u8
        })
        .await
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
    }

    /// A waiter that gives up neither takes nor blocks a permit: the next
    /// waiter in line gets the first permit freed, and the one after it the
    /// next (the semaphore's order), and every permit comes back.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_timed_out_waiter_takes_no_permit_from_the_next() {
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        let mut held = POOL.acquire_many(all_permits()).await.unwrap();
        let early = tokio::spawn(on_pool_within(&POOL, SHORT_WAIT, || 1_u8));
        tokio::time::sleep(Duration::from_millis(30)).await;
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, running) = tokio::sync::oneshot::channel::<()>();
        let next = tokio::spawn(on_pool_within(&POOL, HANG, move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
            2_u8
        }));
        tokio::time::sleep(Duration::from_millis(30)).await;
        let last = tokio::spawn(on_pool_within(&POOL, HANG, || 3_u8));
        let early = tokio::time::timeout(HANG, early).await.unwrap().unwrap();
        assert!(
            matches!(early, Err(KeysetWriteError::ValidationBusy)),
            "{early:?}"
        );
        // One permit freed: it goes to `next`, not to `last`, and the
        // waiter that gave up holds none.
        drop(held.split(1).unwrap());
        tokio::time::timeout(HANG, running).await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!last.is_finished());
        assert_eq!(POOL.available_permits(), 0);
        release.send(()).unwrap();
        let next = tokio::time::timeout(HANG, next).await.unwrap().unwrap();
        assert_eq!(next.unwrap(), 2);
        let last = tokio::time::timeout(HANG, last).await.unwrap().unwrap();
        assert_eq!(last.unwrap(), 3);
        drop(held);
        // Settled: nothing took a permit after the fact.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
    }

    /// A caller dropped while it waits for a permit takes none: its work
    /// never runs and every permit comes back.
    #[tokio::test]
    async fn a_caller_dropped_while_it_waits_takes_no_permit() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        static RAN: AtomicBool = AtomicBool::new(false);
        let held = POOL.acquire_many(all_permits()).await.unwrap();
        let task = tokio::spawn(on_pool_within(&POOL, HANG, || {
            RAN.store(true, Ordering::SeqCst);
        }));
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        let err = tokio::time::timeout(HANG, task)
            .await
            .unwrap()
            .expect_err("aborted");
        assert!(err.is_cancelled());
        drop(held);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!RAN.load(Ordering::SeqCst));
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
        // The next caller gets a worker at once.
        assert_eq!(on_pool_within(&POOL, SHORT_WAIT, || 7_u8).await.unwrap(), 7);
    }

    /// A running parse holds its permit until its work returns, also when
    /// its caller is dropped meanwhile; then the permit comes back.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_running_parse_holds_its_worker_after_its_caller_is_dropped() {
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, running) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(on_pool_within(&POOL, HANG, move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        }));
        tokio::time::timeout(HANG, running).await.unwrap().unwrap();
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS - 1);
        task.abort();
        let err = tokio::time::timeout(HANG, task)
            .await
            .unwrap()
            .expect_err("aborted");
        assert!(err.is_cancelled());
        // The caller is gone; the work still runs and holds the permit.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS - 1);
        release.send(()).unwrap();
        until_all_free(&POOL).await;
    }

    /// A parse holds its permit while it runs and gives it back when it
    /// returns, a value or an error value alike.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_parse_gives_its_worker_back_when_it_returns() {
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started, running) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(on_pool_within(&POOL, HANG, move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
            7_u8
        }));
        tokio::time::timeout(HANG, running).await.unwrap().unwrap();
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS - 1);
        release.send(()).unwrap();
        assert_eq!(task.await.unwrap().unwrap(), 7);
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
        let refused = on_pool_within(&POOL, SHORT_WAIT, || {
            Err::<(), _>(KeysetWriteError::TooManyEnabledVersions)
        })
        .await
        .unwrap();
        assert!(matches!(
            refused,
            Err(KeysetWriteError::TooManyEnabledVersions)
        ));
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
    }

    /// A panic in a parse reaches the caller as that panic, not as
    /// [`KeysetWriteError::WorkerUnavailable`], and its permit comes back.
    #[tokio::test]
    async fn a_panicking_parse_panics_its_caller_and_frees_its_worker() {
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        let task = tokio::spawn(on_pool_within(&POOL, HANG, || -> u8 {
            std::panic::panic_any("parse panicked")
        }));
        let err = tokio::time::timeout(HANG, task)
            .await
            .unwrap()
            .expect_err("the caller panics");
        assert!(err.is_panic());
        assert_eq!(
            err.into_panic().downcast_ref::<&str>(),
            Some(&"parse panicked")
        );
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);
        assert_eq!(on_pool_within(&POOL, HANG, || 7_u8).await.unwrap(), 7);
    }

    /// The stored versions are parsed on the in-transaction pool: with every
    /// Stage A worker taken, the parse still runs at once.
    #[tokio::test]
    async fn a_stored_version_is_parsed_while_stage_a_is_saturated() {
        let _statics = STATICS.lock().await;
        let held = VALIDATION
            .acquire_many(u32::try_from(VALIDATION_WORKERS).unwrap())
            .await
            .unwrap();
        let parsed = tokio::time::timeout(
            IN_TRANSACTION_WAIT / 2,
            parse_stored_versions(vec![stored("ver_1", &p256("k"))]),
        )
        .await
        .expect("the parse waits for no Stage A worker")
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0.id, "ver_1");
        drop(held);
    }

    /// Stage A runs on its own pool: with every in-transaction worker taken,
    /// an upload is still validated, while a stored version waits
    /// [`IN_TRANSACTION_WAIT`] and is `ValidationBusy`.
    #[tokio::test]
    async fn an_upload_is_validated_while_the_in_transaction_pool_is_saturated() {
        let _statics = STATICS.lock().await;
        let held = IN_TRANSACTION.acquire_many(all_permits()).await.unwrap();
        let keys = tokio::time::timeout(
            IN_TRANSACTION_WAIT / 2,
            validate_upload(p256("k"), DEFAULT_ALLOWED_ALGORITHMS),
        )
        .await
        .expect("Stage A waits for no in-transaction worker")
        .unwrap();
        assert_eq!(keys.keys().len(), 1);
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            HANG,
            parse_stored_versions(vec![stored("ver_1", &p256("k"))]),
        )
        .await
        .expect("the wait is bounded");
        assert!(matches!(result, Err(KeysetWriteError::ValidationBusy)));
        assert!(start.elapsed() >= IN_TRANSACTION_WAIT);
        drop(held);
    }

    /// The real write functions against a real PostgreSQL server: with the
    /// in-transaction pool saturated, a write that makes a version enabled
    /// is `ValidationBusy` after the wait, writes nothing and holds no lock
    /// once it returns. Needs `SKYOAUTH_IT_DATABASE_URL`, as the
    /// `service/tests` database tests (see `service/tests/common/mod.rs`).
    mod database {
        use std::str::FromStr;

        use sqlx::{AssertSqlSafe, Connection, PgConnection, postgres::PgConnectOptions};

        use super::*;
        use crate::persistence::{
            self, DatabaseConfig, PgPool,
            registry::{
                self, AdminRole, NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding,
                NewTenant, NewTrustKeyset,
            },
        };

        /// The key of the `trust_admin` of `ten_a`.
        const TRUST: &str = "key_adm_trust";

        /// A database of its own, dropped by [`Db::drop`] or, after a
        /// failure, by `Drop`.
        struct Db {
            admin_url: String,
            name: String,
            pool: Option<PgPool>,
        }

        impl Db {
            /// A fresh database, migrated, with tenant `ten_a`, its keyset
            /// `ks_1` and `adm_trust`, `trust_admin` of `ten_a`.
            async fn create() -> Self {
                let admin_url = std::env::var("SKYOAUTH_IT_DATABASE_URL")
                    .ok()
                    .filter(|url| !url.is_empty())
                    .expect("SKYOAUTH_IT_DATABASE_URL must be set to run this database test");
                let nanos = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos();
                let name = format!("skyoauth_test_{}_permit_{nanos}", std::process::id());
                let mut admin = PgConnection::connect(&admin_url).await.unwrap();
                // The name is digits and underscores.
                sqlx::raw_sql(AssertSqlSafe(format!(
                    "CREATE DATABASE {name} TEMPLATE template0 ENCODING 'UTF8'"
                )))
                .execute(&mut admin)
                .await
                .unwrap();
                admin.close().await.unwrap();
                let mut db = Self {
                    admin_url,
                    name,
                    pool: None,
                };
                let connect = PgConnectOptions::from_str(&db.admin_url)
                    .unwrap()
                    .database(&db.name);
                let config = DatabaseConfig::new(connect, None, 4, HANG).unwrap();
                let pool = persistence::connect(&config).await.unwrap();
                persistence::migrate(&pool).await.unwrap();
                seed(&pool).await;
                db.pool = Some(pool);
                db
            }

            fn pool(&self) -> &PgPool {
                self.pool.as_ref().unwrap()
            }

            async fn drop(mut self) {
                if let Some(pool) = self.pool.take() {
                    pool.close().await;
                }
                drop_database(&self.admin_url, &self.name).await;
                self.name.clear();
            }
        }

        /// A test that fails before [`Db::drop`] drops its database on a
        /// thread with a runtime of its own; errors are ignored.
        impl Drop for Db {
            fn drop(&mut self) {
                if self.name.is_empty() {
                    return;
                }
                let (admin_url, name) = (self.admin_url.clone(), self.name.clone());
                let cleanup = std::thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()?;
                    runtime.block_on(drop_database(&admin_url, &name));
                    Some(())
                });
                let _ = cleanup.join();
            }
        }

        /// `DROP DATABASE … WITH (FORCE)`, retried for up to 5 s while it
        /// is refused with 42501 (a backend of another role, such as an
        /// autovacuum worker, still connected; `service/tests/common`).
        async fn drop_database(admin_url: &str, name: &str) {
            let Ok(mut admin) = PgConnection::connect(admin_url).await else {
                return;
            };
            let start = std::time::Instant::now();
            loop {
                let result = sqlx::raw_sql(AssertSqlSafe(format!(
                    "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                )))
                .execute(&mut admin)
                .await;
                let Err(err) = result else { return };
                let denied = err
                    .as_database_error()
                    .and_then(|err| err.code())
                    .is_some_and(|code| code == "42501");
                if !denied || start.elapsed() >= Duration::from_secs(5) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        async fn seed(pool: &PgPool) {
            registry::create_tenant(
                pool,
                &NewTenant {
                    id: "ten_a".into(),
                    name: "Tenant ten_a".into(),
                    secret_namespace: "ns_ten_a".into(),
                    status: Status::Enabled,
                },
            )
            .await
            .unwrap();
            registry::create_trust_keyset(
                pool,
                &NewTrustKeyset {
                    id: "ks_1".into(),
                    tenant_id: "ten_a".into(),
                    name: "keyset-ks_1".into(),
                    status: Status::Enabled,
                },
            )
            .await
            .unwrap();
            registry::create_admin_identity(
                pool,
                &NewAdminIdentity {
                    id: "adm_trust".into(),
                    status: Status::Enabled,
                    created_at: now(),
                },
            )
            .await
            .unwrap();
            registry::create_admin_credential(
                pool,
                &NewAdminCredential {
                    id: "crd_adm_trust".into(),
                    admin_id: "adm_trust".into(),
                    public_identity: TRUST.into(),
                    trust_anchor_ref: "deployment/operator-ca".into(),
                    status: Status::Enabled,
                },
            )
            .await
            .unwrap();
            registry::create_admin_role_binding(
                pool,
                &NewAdminRoleBinding {
                    id: "rb_adm_trust".into(),
                    admin_id: "adm_trust".into(),
                    role: AdminRole::TrustAdmin,
                    tenant_id: Some("ten_a".into()),
                    status: Status::Enabled,
                },
            )
            .await
            .unwrap();
        }

        fn now() -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
        }

        fn audit(event_id: &str) -> KeysetAudit<'_> {
            KeysetAudit {
                event_id,
                now: now(),
            }
        }

        /// A second P-256 key (see `service/tests/trust_keyset_version.rs`).
        fn p256_b(kid: &str) -> Value {
            json!({"keys": [{
                "kty": "EC", "kid": kid, "crv": "P-256",
                "x": "60KU-t7I0SkALarT8sfRB5iNa5QkWCUlbefzbW7OlQw",
                "y": "AB530pP2cpYhadpS5FNwg9m8w4UgWFlJJkxIxFl_MPk",
            }]})
        }

        /// A version of `ks_1`, open-ended from [`now`], so every two
        /// versions' windows intersect.
        fn version<'a>(
            id: &'a str,
            keys: &'a ValidatedKeyset,
            status: Status,
            provenance: &'a JsonObject,
        ) -> NewKeysetVersion<'a> {
            NewKeysetVersion {
                id,
                tenant_id: "ten_a",
                keyset_id: "ks_1",
                keys,
                effective_at: now(),
                expires_at: None,
                status,
                provenance,
            }
        }

        /// `(id, status, revision)` of the keyset's versions, and the
        /// number of audit events.
        async fn stored_state(pool: &PgPool) -> (Vec<(String, String, i64)>, i64) {
            let versions =
                sqlx::query_as("SELECT id, status, revision FROM trust_keyset_version ORDER BY id")
                    .fetch_all(pool)
                    .await
                    .unwrap();
            let events = sqlx::query_scalar("SELECT count(*) FROM audit_event")
                .fetch_one(pool)
                .await
                .unwrap();
            (versions, events)
        }

        /// Whether another connection can lock the parent keyset row
        /// `FOR NO KEY UPDATE` and the operator's identity row `FOR UPDATE`
        /// at once: `None` if both are free, else the first refusal's
        /// SQLSTATE (`55P03` while a write holds them).
        async fn lock_refusal(pool: &PgPool) -> Option<String> {
            let mut other = pool.begin().await.unwrap();
            let mut refusal = None;
            for statement in [
                "SELECT 1 FROM trust_keyset WHERE tenant_id = 'ten_a' AND id = 'ks_1' \
                 FOR NO KEY UPDATE NOWAIT",
                "SELECT 1 FROM admin_identity WHERE id = 'adm_trust' FOR UPDATE NOWAIT",
            ] {
                if let Err(err) = sqlx::query(statement).execute(&mut *other).await {
                    refusal = err
                        .as_database_error()
                        .and_then(|err| err.code())
                        .map(|code| code.into_owned());
                    assert!(refusal.is_some(), "{err}");
                    break;
                }
            }
            other.rollback().await.unwrap();
            refusal
        }

        /// Polls until [`lock_refusal`] sees the write's locks, while the
        /// write waits for its permit.
        async fn until_locked(pool: &PgPool) {
            tokio::time::timeout(IN_TRANSACTION_WAIT / 2, async {
                loop {
                    if let Some(code) = lock_refusal(pool).await {
                        assert_eq!(code, "55P03");
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the write never held its locks while it waited");
        }

        /// `write` in its own transaction while every in-transaction
        /// worker is taken: it waits under its locks, returns
        /// `ValidationBusy` after [`IN_TRANSACTION_WAIT`] with its locks
        /// released, and leaves the transaction usable; the transaction is
        /// then committed.
        async fn busy(
            pool: &PgPool,
            write: impl AsyncFnOnce(
                &mut Transaction<'static, Postgres>,
            ) -> Result<TrustKeysetVersion, KeysetWriteError>,
        ) {
            let mut tx = pool.begin().await.unwrap();
            let start = std::time::Instant::now();
            let (result, ()) = tokio::join!(
                async { tokio::time::timeout(HANG, write(&mut tx)).await },
                until_locked(pool),
            );
            let result = result.expect("the wait is bounded");
            assert!(
                matches!(result, Err(KeysetWriteError::ValidationBusy)),
                "{result:?}"
            );
            assert!(start.elapsed() >= IN_TRANSACTION_WAIT);
            // The savepoint is rolled back: the locks are free while the
            // caller's transaction is still open, and it is usable.
            assert_eq!(lock_refusal(pool).await, None);
            sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
            // A caller that commits after the error commits nothing.
            tx.commit().await.unwrap();
        }

        #[tokio::test(flavor = "multi_thread")]
        #[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
        async fn a_write_with_no_in_transaction_worker_is_validation_busy_and_writes_nothing() {
            let _statics = STATICS.lock().await;
            let db = Db::create().await;
            let pool = db.pool();
            let provenance = JsonObject::new();
            let key_1 = validate_upload(p256("k1"), DEFAULT_ALLOWED_ALGORITHMS)
                .await
                .unwrap();
            let key_2 = validate_upload(p256_b("k2"), DEFAULT_ALLOWED_ALGORITHMS)
                .await
                .unwrap();
            let mut tx = pool.begin().await.unwrap();
            let enabled_1 = version("ver_1", &key_1, Status::Enabled, &provenance);
            create_version(&mut tx, TRUST, &enabled_1, &audit("aud_1"))
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let one = || vec![("ver_1".to_string(), "enabled".to_string(), 1_i64)];
            assert_eq!(stored_state(pool).await, (one(), 1));

            let held = IN_TRANSACTION.acquire_many(all_permits()).await.unwrap();
            // A create of an enabled version, which compares `ver_1`.
            let enabled_2 = version("ver_2", &key_2, Status::Enabled, &provenance);
            busy(pool, async |tx| {
                create_version(tx, TRUST, &enabled_2, &audit("aud_2")).await
            })
            .await;
            assert_eq!(stored_state(pool).await, (one(), 1));
            // A disabled create parses nothing and needs no worker.
            let disabled_2 = version("ver_2", &key_2, Status::Disabled, &provenance);
            let mut tx = pool.begin().await.unwrap();
            create_version(&mut tx, TRUST, &disabled_2, &audit("aud_2"))
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let two = |status: &str, revision: i64| {
                let mut rows = one();
                rows.push(("ver_2".into(), status.into(), revision));
                rows
            };
            assert_eq!(stored_state(pool).await, (two("disabled", 1), 2));
            // An enable, which parses its target.
            busy(pool, async |tx| {
                enable_version(tx, TRUST, "ten_a", "ver_2", 1, &audit("aud_3")).await
            })
            .await;
            assert_eq!(stored_state(pool).await, (two("disabled", 1), 2));

            // With the workers free again, the same enable goes through.
            drop(held);
            let mut tx = pool.begin().await.unwrap();
            enable_version(&mut tx, TRUST, "ten_a", "ver_2", 1, &audit("aud_3"))
                .await
                .unwrap();
            tx.commit().await.unwrap();
            assert_eq!(stored_state(pool).await, (two("enabled", 2), 3));
            db.drop().await;
        }
    }
}
