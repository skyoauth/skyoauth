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
//!
//! # Not wired, and the one write path
//!
//! - **No endpoint.** Nothing calls these functions yet, and they must not
//!   be wired to any endpoint before the maintainer rules whether a keyset
//!   version write (a create, an enable, a re-enable) counts as widening and
//!   so needs an IR-054 approval while `widening_second_approver` is on
//!   (OQ-ADR008-3, identity-registry IR-052), and before the request layer
//!   of T14.1 and T14.2 exists (generated IDs, the raw body bound, the role
//!   of each endpoint).
//! - **Single actor.** A write takes effect at once on one operator's
//!   authority: no write waits for an approval, so the module assumes
//!   either that the setting is off or that the write is not widening, which
//!   is exactly what is undecided above.
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
//! for a worker. The semaphore is tokio's: this crate's manifest names
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
//!   on the same bounded blocking pool as Stage A. A stored version that
//!   fails either is [`KeysetWriteError::StoredVersion`], a data-integrity
//!   error naming no value, and the version is not enabled. An enabled
//!   version whose window does not intersect is not parsed (inferred: the
//!   check would skip it).
//! - **Cost.** That full parse runs inside the transaction and is linear in
//!   the intersecting enabled versions; the cap holds it to up to 8 stored
//!   sets per write (an enable's target and at most 7 others). While it
//!   runs it holds the parent
//!   keyset row, the operator rows `FOR SHARE`, a database connection and
//!   one of the [`VALIDATION_WORKERS`] process-wide workers, so it can
//!   starve every other tenant's Stage A. The estimate is about 0.18 s per
//!   compared 20-key set in release, plus any wait for a free worker; debug
//!   builds measured 0.30 s for 1 and 1.31 s for 8 compared versions, the
//!   most the cap allows. It is a known cost, not a design goal. **Wiring
//!   precondition:** before any endpoint calls this module, the
//!   in-transaction parses need a permit or priority of their own,
//!   separate from Stage A's (or the stored marker below, which removes
//!   them). Follow-up: a change of [`KeysetVersion`] to take stored keys,
//!   or a stored marker that a projection passed the point checks, would
//!   remove the parse.
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
//!    parse of the compared stored versions on the blocking pool and
//!    [`check_version_overlap`];
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
//! - Wiring to an endpoint, and the widening decision above (OQ-ADR008-3,
//!   IR-052; T14.1, T14.2).
//! - The raw request-body bound before the upload is parsed.
//! - The keyset's own status: a version of a disabled keyset is written
//!   like any other (inferred: the verifier reads the keyset's status).
//! - Tenant status (the operator lookup does not read it).
//! - Import and restore paths (T10.5): they must run the same overlap
//!   check where a version becomes enabled.
//! - What the design section 5.7 export carries of a version (OQ-IR-6).
//! - A fingerprint in the audit event (an ADR question: the envelope has
//!   no member for it).
//! - A separate permit or priority for the in-transaction parses (the
//!   wiring precondition under "Cost").
//! - Moving the A04 scenario tests from the raw writers to this module,
//!   once A04 M1a is claimed.

use std::{fmt, time::SystemTime};

use serde_json::Value;
use sqlx::{Connection, Postgres, Transaction};
use tokio::sync::Semaphore;

use crate::jwk::{
    Algorithm, JwkSet, JwkSetError, KNOWN_ALGORITHMS, KeysetFingerprint, KeysetVersion,
    OverlapError, PRIVATE_MEMBERS, ValidatedKeyset, VersionStatus, check_version_overlap,
    parse_stored, validate_keyset,
};
use crate::persistence::registry::{
    AdminRole, AuditActor, JsonObject, KeysetVersionText, NewAuditEvent, NewTrustKeysetVersion,
    OperatorRequest, OperatorScope, RegistryError, Status, TrustKeysetVersion, append_audit_event,
    authorize_operator_locked, create_trust_keyset_version, floor_to_microsecond,
    read_enabled_keyset_versions, read_keyset_version, update_trust_keyset_version,
};

/// The most JWK set validations that run at once, across the process
/// (inferred). Each takes one blocking worker.
pub const VALIDATION_WORKERS: usize = 2;

/// The most enabled versions one keyset may have (provisional lead pick,
/// 2026-11-22). A create of an enabled version or an enable that would
/// pass it is [`KeysetWriteError::TooManyEnabledVersions`], counted under
/// the parent keyset lock and before any stored version is parsed; disabled
/// versions do not count. It bounds the in-transaction parse of
/// [`check_version_overlap`]'s input (see the module docs, "Cost").
pub const MAX_ENABLED_VERSIONS_PER_KEYSET: usize = 8;

/// The permits of the bounded validation pool.
static VALIDATION: Semaphore = Semaphore::const_new(VALIDATION_WORKERS);

/// The audit action of [`create_version`] (identity-registry IR-059).
const CREATE_ACTION: &str = "trust_keyset_version.create";

/// The audit action of [`enable_version`] (identity-registry IR-059).
const ENABLE_ACTION: &str = "trust_keyset_version.enable";

/// The audit action of [`disable_version`] (identity-registry IR-059).
const DISABLE_ACTION: &str = "trust_keyset_version.disable";

/// The outcome of the event (inferred, as for bootstrap).
const SUCCESS: &str = "success";

/// Step 0: the transaction's isolation level.
const TRANSACTION_ISOLATION: &str = "SELECT current_setting('transaction_isolation')";

/// The one isolation level the writes run at, as `transaction_isolation`
/// names it.
const READ_COMMITTED: &str = "read committed";

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

/// Runs `work` on tokio's blocking pool once one of the
/// [`VALIDATION_WORKERS`] permits is free. The permit moves into the
/// blocking task, so it is held until `work` returns even if the caller's
/// future is dropped first.
async fn on_validation_worker<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, KeysetWriteError> {
    on_pool(&VALIDATION, work).await
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

/// [`parse_in_full`] of each stored version, in order, on the bounded
/// blocking pool; the first failure names its version.
async fn parse_stored_versions(
    rows: Vec<KeysetVersionText>,
) -> Result<Vec<(KeysetVersionText, ValidatedKeyset)>, KeysetWriteError> {
    on_validation_worker(move || {
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

/// Step 0: `READ COMMITTED` only.
async fn require_read_committed(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), KeysetWriteError> {
    let isolation: String = sqlx::query_scalar(TRANSACTION_ISOLATION)
        .fetch_one(&mut **transaction)
        .await?;
    if isolation != READ_COMMITTED {
        return Err(KeysetWriteError::UnsupportedIsolation);
    }
    Ok(())
}

/// Step 1: a `trust_admin` of `tenant_id`, locked until the transaction
/// ends; the operator's ID.
async fn authorize(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
) -> Result<String, KeysetWriteError> {
    let request = OperatorRequest {
        public_identity,
        scope: OperatorScope::Tenant(tenant_id),
        role: AdminRole::TrustAdmin,
    };
    match authorize_operator_locked(transaction, &request).await? {
        Some(operator) => Ok(operator.admin_id),
        None => Err(KeysetWriteError::Unauthorized),
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
    let mut savepoint = transaction.begin().await?;
    match create_steps(&mut savepoint, public_identity, new, audit).await {
        Ok(version) => {
            savepoint.commit().await?;
            Ok(version)
        }
        Err(err) => {
            // The step's error says more than a failed savepoint rollback.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}

/// Steps 0 to 7 of [`create_version`], in its savepoint.
async fn create_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewKeysetVersion<'_>,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    require_read_committed(transaction).await?;
    let admin_id = authorize(transaction, public_identity, new.tenant_id).await?;
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
    let mut savepoint = transaction.begin().await?;
    match status_steps(&mut savepoint, public_identity, target, status, audit).await {
        Ok(version) => {
            savepoint.commit().await?;
            Ok(version)
        }
        Err(err) => {
            // The step's error says more than a failed savepoint rollback.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}

/// Steps 0 to 7 of a status change, in its savepoint.
async fn status_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    (tenant_id, id, expected_revision): (&str, &str, i64),
    status: Status,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    require_read_committed(transaction).await?;
    let admin_id = authorize(transaction, public_identity, tenant_id).await?;
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
}
