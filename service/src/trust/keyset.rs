//! The audited write path of a trust keyset version (T11.3, T11.9;
//! ADR-005 items 1, 5 and 8; tasks section 3, the
//! `/admin/v1/tenants/{tenant}/keysets` row; migrations README, "What 0004
//! adds", the service rules).
//!
//! [`create_version`], [`enable_version`] and [`disable_version`] wrap the
//! registry's bare [`create_trust_keyset_version`] and
//! [`update_trust_keyset_version`], which check nothing the database does
//! not. [`submit_create_version`] and [`submit_enable_version`] are the
//! gated create and enable of the second-approver flow
//! (`docs/proposals/second-approver-gated-writes.md`, PR 4; see "The
//! gate"). They run in the caller's transaction and neither commit nor
//! roll it back. The upload is validated before that transaction, by
//! [`validate_upload`]. The picks below are the lead's (provisional lead
//! pick, 2026-11-22; the gate's, 2026-11-23) unless marked (inferred); all
//! are provisional until the maintainer ratifies the ADRs (T00.8 to T00.17,
//! Gate M0), and so are the [`crate::jwk`] picks dated 2026-11-21 that this
//! module relies on. The widening ruling below is the user's, not a
//! provisional pick.
//!
//! # Not wired, and the one write path
//!
//! - **Widening.** A keyset version write (a create, an enable, a
//!   re-enable) counts as widening: while `widening_second_approver` is on
//!   it needs an IR-054 approval by a second approver (ruled by the user,
//!   2026-11-22, relayed by the lead; this decides OQ-ADR008-3 and the
//!   widening question of identity-registry IR-052 for this write). The
//!   second-approver flow is designed in
//!   `docs/proposals/second-approver-gated-writes.md` (accepted,
//!   2026-11-23); no task ID names it (the nearest owners are T13.3, T13.2,
//!   T13.8, T11.6, T10.4 and T10.2). [`submit_create_version`] and
//!   [`submit_enable_version`] put this module's widening writes through
//!   it (see "The gate").
//! - **No endpoint.** Nothing calls these functions yet, and they must not
//!   be wired to any endpoint before the request layer exists (generated
//!   IDs, T10.2; the raw body bound; the role of each endpoint, T13.2,
//!   T13.3). An endpoint calls the `submit_*` functions, never the ungated
//!   ones.
//! - **Ungated writes.** [`create_version`] and [`enable_version`] take
//!   effect at once on one operator's authority: with
//!   `widening_second_approver` on, they would apply a widening write
//!   without the approval it needs. They stay public for the tests until
//!   the proposal's PR 7 makes them crate-private. (The ruling names a
//!   create, an enable and a re-enable; [`disable_version`] is not among
//!   them and is never gated.)
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
//! # The gate
//!
//! [`submit_create_version`] and [`submit_enable_version`] (proposal
//! sections 1 to 3). Every keyset create, enabled or disabled (Q3), and
//! every enable, a re-enable and an enable of an enabled version included,
//! is widening: the server decides it, never the caller. A request runs,
//! in its savepoint:
//!
//! 1. the requester, a `trust_admin` of the version's tenant: its identity,
//!    its credential, its `trust_admin` binding and its instance
//!    `security_admin` binding, if any, `FOR SHARE` in one lookup (Q4;
//!    inferred: the instance binding is always looked up, so the lock set
//!    does not depend on the policy). A `security_admin` without the tenant
//!    role is [`KeysetWriteError::Unauthorized`] like any other miss;
//! 2. `acknowledge_widening`: a request without it is
//!    [`KeysetWriteError::WideningNotAcknowledged`];
//! 3. the policy row `FOR SHARE`; missing (before bootstrap), it is
//!    [`KeysetWriteError::PolicyUnavailable`] (D18);
//! 4. the mode. `widening_second_approver` off: the write is applied at
//!    once, its event's outcome `success_widening` (D23).
//!    `single_actor_mode` on and the requester also an instance
//!    `security_admin`: applied at once, outcome `success_single_actor`
//!    (Q4). Otherwise the write's own checks run under its locks (D7), and
//!    a pending operation is written with its `administrative_operation.create`
//!    event; no version is written. A create's plan holds the projection,
//!    the fingerprint and the algorithms `new.keys` was validated against
//!    (D25), never the raw upload; an enable's names the version, its
//!    keyset and its stored fingerprint.
//!
//! The approval ([`crate::operation::approve_operation`]) reruns the
//! write's steps 3 to 6 below under the approval's locks, from the locked
//! plan, and samples the clock once, after the registry write (D28). The
//! steps are split for it (D26): `apply_create_version` and
//! `apply_enable_version` return the row and its event unstamped, and the
//! caller stamps and appends the event. A permit wait under the gate is the
//! direct write's: [`KeysetWriteError::ValidationBusy`], with the
//! savepoint's locks released.
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
//!   Stage A's [`VALIDATION_WORKERS`] (second-approver proposal, section 8,
//!   D13): a parse never waits for a Stage A permit, and an upload never
//!   waits for an in-transaction one. Both pools share tokio's blocking pool
//!   (512 threads by default; this module is the service's only direct
//!   `spawn_blocking` caller; sqlx uses that pool too, for a host-name
//!   lookup when it opens a connection and for file reads) and the CPU.
//!   A write waits at most once, [`IN_TRANSACTION_WAIT`] (2 s, inferred),
//!   for a permit, under the locks above: the bound covers the semaphore
//!   wait only, not a queue in the blocking pool or the parse. An enable
//!   parses its target and its compared versions in one blocking task, and
//!   a write that compares no stored version (a create whose window
//!   intersects no enabled version) takes no permit at all. A worker not granted in time
//!   is [`KeysetWriteError::ValidationBusy`], retryable: the write's
//!   savepoint rollback releases the parent lock and the operator rows;
//!   retry after a back-off (proposal section 10: 503 with `Retry-After`).
//!   A retry in the same transaction waits again under any locks the caller
//!   holds outside the write. The bound is on the wait only, not on the
//!   parse; it is tokio's `timeout`, so the manifest names tokio's `time`
//!   feature, which `sqlx` and `axum` already compiled in (the lockfile did
//!   not change). A permit is held only by the blocking task's CPU work,
//!   never across a statement, so a permit wait cannot form a cycle with
//!   row locks. The estimate is about 0.18 s per compared 20-key set in
//!   release, plus that wait; debug builds measured 0.30 s for 1 and 1.31 s
//!   for 8 compared versions, the most the cap allows. It is a known cost,
//!   not a design goal. **Wiring precondition** (done): before any endpoint
//!   calls this module, the in-transaction parses needed a permit or
//!   priority of their own, separate from Stage A's; they now have the
//!   pool, the bounded wait and [`KeysetWriteError::ValidationBusy`] above.
//!   A runtime built with `max_blocking_threads` must leave room for both
//!   pools ([`VALIDATION_WORKERS`] plus [`IN_TRANSACTION_WORKERS`]) and
//!   headroom for other blocking work (sqlx's lookups, tokio's own).
//!   Follow-up: a change of
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
//!    `keyset_id` and `fingerprint`, without a lock (both columns are
//!    immutable). A version missing from the tenant is
//!    [`RegistryError::NotFound`];
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
//!    parse of the compared stored versions (and an enable's target, in
//!    the same blocking task) on the in-transaction pool (see "Cost") and
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
//! ID, outcome `success` (inferred, as for bootstrap and restore; a gated
//! write applied at once has `success_widening` or `success_single_actor`,
//! and an approved one `success` with the requester as actor, after the
//! approval's own event: see "The gate"). A create
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
//! - Wiring to an endpoint (see "Not wired"), and making the ungated
//!   [`create_version`] and [`enable_version`] crate-private (the
//!   proposal's PR 7).
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

use super::write::{
    GatedWriteError, Mode, WriteError, authorize_trust_admin, authorize_widening_write,
    in_savepoint, require_read_committed,
};
use crate::jwk::{
    Algorithm, JwkError, JwkSet, JwkSetError, KNOWN_ALGORITHMS, KeysetFingerprint, KeysetVersion,
    OverlapError, PRIVATE_MEMBERS, ValidatedKeyset, VersionStatus, check_version_overlap,
    parse_stored, validate_keyset,
};
use crate::operation::{
    Gated, OUTCOME_SUCCESS, OperationKind, PendingRequest, Requester, Submission, UnstampedEvent,
    encode_error, insert_pending,
    keyset_plan::{CreatePlan, CreateRequest, EnablePlan},
};
use crate::persistence::registry::{
    AuditActor, InvariantKind, JsonObject, KeysetVersionText, NewTrustKeysetVersion, RegistryError,
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

/// The outcome of the event of an ungated write (inferred, as for
/// bootstrap).
const SUCCESS: &str = OUTCOME_SUCCESS;

/// Step 2 of a status change: the version's keyset and fingerprint, both
/// immutable, unlocked. The fingerprint is a gated enable's plan member
/// (proposal section 2).
const VERSION_IDENTITY: &str =
    "SELECT keyset_id, fingerprint FROM trust_keyset_version WHERE tenant_id = $1 AND id = $2";

/// The `0004` check that a version ID is not empty, under PostgreSQL's
/// default name (D27 pre-validates it at a gated request).
const VERSION_ID_CHECK: &str = "trust_keyset_version_id_check";

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
    /// parsed, the overlap check did not run and the write wrote nothing
    /// (see the module docs, "Cost"). Retryable: the write's savepoint is
    /// rolled back, which releases the parent keyset lock and the operator
    /// rows; retry after a back-off (proposal section 10: 503 with
    /// `Retry-After`). A retry in the same transaction waits again under
    /// any locks the caller holds outside the write. Only a write that
    /// makes a version enabled and compares a stored version returns it;
    /// [`validate_upload`] waits for its own workers without a bound.
    ValidationBusy,
    /// A gated write ([`submit_create_version`], [`submit_enable_version`])
    /// without `acknowledge_widening`: each is widening (proposal section
    /// 1), whether `widening_second_approver` is on or off.
    WideningNotAcknowledged,
    /// A gated write found no `instance_security_policy` row (D18).
    /// Retryable once the instance is bootstrapped.
    PolicyUnavailable,
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
            Self::WideningNotAcknowledged => {
                f.write_str("the trust keyset version write is widening and was not acknowledged")
            }
            Self::PolicyUnavailable => f.write_str("the instance security policy is unavailable"),
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
            Self::WideningNotAcknowledged => f.write_str("WideningNotAcknowledged"),
            Self::PolicyUnavailable => f.write_str("PolicyUnavailable"),
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

impl GatedWriteError for KeysetWriteError {
    const WIDENING_NOT_ACKNOWLEDGED: Self = Self::WideningNotAcknowledged;
    const POLICY_UNAVAILABLE: Self = Self::PolicyUnavailable;
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
/// `work` is CPU work only: a permit is never held across a statement, so
/// a permit wait cannot form a cycle with row locks.
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

/// How a stored set is parsed: [`parse_in_full`] (the tests pass a parse
/// of their own to [`parse_enable_on`]).
type Parse = fn(&str) -> Result<ValidatedKeyset, JwkSetError>;

/// A stored version with its keys, parsed in full.
type Parsed = (KeysetVersionText, ValidatedKeyset);

/// `parse` of the stored version `row`; a failure names it.
fn parse_one(parse: Parse, row: KeysetVersionText) -> Result<Parsed, KeysetWriteError> {
    match parse(&row.public_jwks) {
        Ok(keys) => Ok((row, keys)),
        Err(error) => Err(KeysetWriteError::StoredVersion {
            version_id: row.id,
            error,
        }),
    }
}

/// `parse` of each stored version, in order; the first failure names its
/// version.
fn parse_rows(parse: Parse, rows: Vec<KeysetVersionText>) -> Result<Vec<Parsed>, KeysetWriteError> {
    rows.into_iter().map(|row| parse_one(parse, row)).collect()
}

/// [`parse_in_full`] of each stored version, in order, on one of the
/// [`IN_TRANSACTION_WORKERS`] (not Stage A's pool); the first failure names
/// its version. No permit within [`IN_TRANSACTION_WAIT`] is
/// [`KeysetWriteError::ValidationBusy`]. An empty `rows` takes no permit
/// and cannot be busy.
async fn parse_stored_versions(
    rows: Vec<KeysetVersionText>,
) -> Result<Vec<Parsed>, KeysetWriteError> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    on_in_transaction_worker(move || parse_rows(parse_in_full, rows)).await?
}

/// An enable's one parse step: [`parse_in_full`] of its stored `target`,
/// then of the keyset's enabled versions `rows` that
/// [`compared_rows`] keeps against it, all in one blocking task on one of
/// the [`IN_TRANSACTION_WORKERS`], so the write waits for a permit once
/// (at most [`IN_TRANSACTION_WAIT`]). A failure of the target names the
/// target, before any other version is parsed.
async fn parse_enable(
    target: KeysetVersionText,
    rows: Vec<KeysetVersionText>,
) -> Result<(Parsed, Vec<Parsed>), KeysetWriteError> {
    parse_enable_on(
        &IN_TRANSACTION,
        IN_TRANSACTION_WAIT,
        parse_in_full,
        target,
        rows,
    )
    .await
}

/// [`parse_enable`] on the pool `pool`, waiting at most `wait`, with
/// `parse` (the tests use pools, waits and parses of their own). The
/// window filter runs in the blocking task too: it needs the target's
/// window only, which is known once the target is parsed.
async fn parse_enable_on(
    pool: &'static Semaphore,
    wait: Duration,
    parse: Parse,
    target: KeysetVersionText,
    rows: Vec<KeysetVersionText>,
) -> Result<(Parsed, Vec<Parsed>), KeysetWriteError> {
    on_pool_within(pool, wait, move || {
        let (target, keys) = parse_one(parse, target)?;
        let compared = compared_rows(&enabled(&target, keys.set()), rows);
        let parsed = parse_rows(parse, compared)?;
        Ok(((target, keys), parsed))
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

/// The stored version `row` with `keys`, as it is once enabled.
fn enabled<'a>(row: &'a KeysetVersionText, keys: &'a JwkSet) -> KeysetVersion<'a> {
    KeysetVersion {
        status: VersionStatus::Enabled,
        ..as_version(row, keys)
    }
}

/// The versions of `rows` (the keyset's enabled versions, as
/// [`read_enabled_keyset_versions`] reads them) that the overlap check of
/// `version` compares: all but its own ID whose windows intersect its own.
fn compared_rows(
    version: &KeysetVersion<'_>,
    rows: Vec<KeysetVersionText>,
) -> Vec<KeysetVersionText> {
    rows.into_iter()
        // Excluding the version's own ID is not only a saving: the check
        // skips it anyway, but a create that reuses the ID of a stored
        // version would parse that row and could fail as `StoredVersion`
        // instead of the insert's `AlreadyExists`.
        .filter(|row| row.id != version.id)
        // The window only: `version`'s keys stand in for the unparsed ones.
        .filter(|row| version.windows_intersect(&as_version(row, version.keys)))
        .collect()
}

/// [`check_version_overlap`] of `version` against the `compared` versions,
/// parsed in full.
fn check_against(version: &KeysetVersion<'_>, compared: &[Parsed]) -> Result<(), KeysetWriteError> {
    let existing: Vec<KeysetVersion<'_>> = compared
        .iter()
        .map(|(row, keys)| as_version(row, keys.set()))
        .collect();
    check_version_overlap(version, &existing).map_err(KeysetWriteError::Overlap)
}

/// Step 5 of a create: `version`, becoming enabled, against the keyset's
/// enabled versions `rows` that [`compared_rows`] keeps, each parsed in
/// full first (no permit when none is kept).
async fn check_overlap(
    version: &KeysetVersion<'_>,
    rows: Vec<KeysetVersionText>,
) -> Result<(), KeysetWriteError> {
    let parsed = parse_stored_versions(compared_rows(version, rows)).await?;
    check_against(version, &parsed)
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

/// Refuses a `provenance` naming a JWK private member, before any
/// statement (see the module docs, "Provenance"). The approve of a gated
/// create runs it again on the plan's provenance (proposal section 4).
pub(crate) fn check_provenance(provenance: &JsonObject) -> Result<(), KeysetWriteError> {
    if names_a_private_member(provenance) {
        return Err(KeysetWriteError::PrivateMemberInProvenance);
    }
    Ok(())
}

/// The pure checks of a gated create's request step 1, before any
/// statement: the provenance ([`check_provenance`]); an empty version ID,
/// refused as the `0004` check `trust_keyset_version_id_check` refuses it
/// at the insert (D27, the one plainly typed constraint of a version: its
/// other `0004` and `0007` checks are lengths, characters, ranges and the
/// window, which stay approve-time); and a key whose algorithm is outside
/// `allowed`, the set the plan records as the one `new.keys` was validated
/// against (D25; inferred: refused as [`validate_keyset`] refuses it, the
/// key named by its index in the validated set's `kid` order, since only
/// the caller knows which set it validated with).
fn check_create_request(
    new: &NewKeysetVersion<'_>,
    allowed: &[Algorithm],
) -> Result<(), KeysetWriteError> {
    check_provenance(new.provenance)?;
    if new.id.is_empty() {
        return Err(RegistryError::Invariant {
            kind: InvariantKind::Check,
            constraint: Some(VERSION_ID_CHECK),
        }
        .into());
    }
    for (index, key) in new.keys.keys().iter().enumerate() {
        if !allowed.contains(&key.algorithm()) {
            let error = match key.alg() {
                Some(alg) => JwkError::AlgorithmNotAllowed(alg),
                None => JwkError::NoAllowedAlgorithm,
            };
            return Err(KeysetWriteError::Upload(JwkSetError::Key { index, error }));
        }
    }
    Ok(())
}

/// A step function's event of a write by `requester` of `version`,
/// unstamped (D26).
fn unstamped(
    requester: &Requester,
    action: &'static str,
    previous_revision: Option<i64>,
    version: &TrustKeysetVersion,
) -> UnstampedEvent {
    UnstampedEvent {
        tenant_id: Some(version.tenant_id.clone()),
        actor: AuditActor::Operator(requester.admin_id.clone()),
        action,
        object_id: version.id.clone(),
        previous_revision,
        new_revision: Some(version.revision),
    }
}

/// Step 7: `event` stamped with the caller's ID, `now` and `outcome`,
/// through the audit head.
async fn append_stamped(
    transaction: &mut Transaction<'_, Postgres>,
    event: UnstampedEvent,
    event_id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<(), KeysetWriteError> {
    append_audit_event(transaction, &event.stamp(event_id, now, outcome)).await?;
    Ok(())
}

/// Creates the keyset version `new` at revision 1 for the operator whose
/// credential has `public_identity`, storing the projection and fingerprint
/// of `new.keys`; when `new.status` is enabled, after the overlap check
/// against the keyset's enabled versions; and appends its
/// `trust_keyset_version.create` event last, in `transaction` (see the
/// module docs for the rules, the order and the locks). Runs only under
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`.
///
/// Ungated: it applies a widening write on one operator's authority, so it
/// stays test-only until it becomes crate-private (see the module docs,
/// "Not wired"); [`submit_create_version`] is the gated write.
pub async fn create_version(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewKeysetVersion<'_>,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    check_provenance(new.provenance)?;
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
    let requester =
        authorize_trust_admin::<KeysetWriteError>(transaction, public_identity, new.tenant_id)
            .await?;
    let (version, event) = apply_create_version(transaction, &requester, new).await?;
    append_stamped(transaction, event, audit.event_id, audit.now, SUCCESS).await?;
    Ok(version)
}

/// Steps 3 to 5 of a create, through the checks and before the insert:
/// the parent lock, then, when `new.status` is enabled, the count of the
/// keyset's enabled versions and the overlap check. A gated create's
/// pending request runs exactly these (D7); [`apply_create_version`] runs
/// them and then [`insert_create_version`].
pub(crate) async fn check_create_version(
    transaction: &mut Transaction<'_, Postgres>,
    new: &NewKeysetVersion<'_>,
) -> Result<(), KeysetWriteError> {
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
    Ok(())
}

/// Step 6 of a create: the insert by `requester`, after
/// [`check_create_version`] in the same savepoint. Returns the row and its
/// `trust_keyset_version.create` event, unstamped; appends nothing (D26).
/// The insert can wait: on a conflicting uncommitted version ID, until
/// that transaction ends (proposal section 3, approve step 6).
pub(crate) async fn insert_create_version(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    new: &NewKeysetVersion<'_>,
) -> Result<(TrustKeysetVersion, UnstampedEvent), KeysetWriteError> {
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
    let event = unstamped(requester, CREATE_ACTION, None, &version);
    Ok((version, event))
}

/// The post-authorization steps of a create (D26): steps 3 to 6, the
/// checks ([`check_create_version`]) and the insert
/// ([`insert_create_version`]), by `requester`, whom the caller authorized.
/// Returns the row and its event, unstamped; the caller appends it. The
/// provenance is the caller's to check first ([`check_provenance`]).
pub(crate) async fn apply_create_version(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    new: &NewKeysetVersion<'_>,
) -> Result<(TrustKeysetVersion, UnstampedEvent), KeysetWriteError> {
    check_create_version(transaction, new).await?;
    insert_create_version(transaction, requester, new).await
}

/// Requests the create of the keyset version `new` (proposal section 3,
/// "Request"): a widening write, enabled or disabled (Q3), for the
/// `trust_admin` of `new.tenant_id` whose credential has
/// `submission.public_identity`. `allowed` is the set [`validate_upload`]
/// validated `new.keys` against; the plan records it (D25).
///
/// Before any statement: the provenance check, an empty version ID (D27)
/// and a key outside `allowed`. Then, in a savepoint, only under
/// `READ COMMITTED`: the requester's rows `FOR SHARE` (with its instance
/// `security_admin` binding, if any; Q4), `acknowledge_widening`
/// ([`KeysetWriteError::WideningNotAcknowledged`]), the policy row
/// `FOR SHARE` ([`KeysetWriteError::PolicyUnavailable`]), and the mode:
///
/// - `widening_second_approver` off: applied at once, as
///   [`create_version`], with the event's outcome `success_widening` (D23);
/// - on, `single_actor_mode` on and the requester also an instance
///   `security_admin`: applied at once, outcome `success_single_actor`
///   (Q4);
/// - otherwise the create's checks (the parent lock, the cap and the
///   overlap check), then a pending `trust_keyset_version_create`
///   operation at expected revision 0, whose plan holds the projection and
///   fingerprint, never the raw upload. No version is written.
///
/// The caller commits on `Ok` and rolls back on `Err`.
pub async fn submit_create_version(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    new: &NewKeysetVersion<'_>,
    allowed: &[Algorithm],
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError> {
    check_create_request(new, allowed)?;
    in_savepoint(transaction, async |savepoint| {
        submit_create_steps(savepoint, submission, new, allowed).await
    })
    .await
}

/// Request steps 0 to 8 of [`submit_create_version`], in its savepoint.
async fn submit_create_steps(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    new: &NewKeysetVersion<'_>,
    allowed: &[Algorithm],
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError> {
    require_read_committed::<KeysetWriteError>(transaction).await?;
    let (requester, mode) =
        authorize_widening_write::<KeysetWriteError>(transaction, submission, new.tenant_id)
            .await?;
    match mode {
        Mode::Apply(outcome) => {
            let (version, event) = apply_create_version(transaction, &requester, new).await?;
            append_stamped(
                transaction,
                event,
                submission.event_id,
                submission.now,
                outcome,
            )
            .await?;
            Ok(Gated::Applied(version))
        }
        Mode::Pending => {
            check_create_version(transaction, new).await?;
            let plan = CreatePlan::new(&CreateRequest {
                requester_credential_id: &requester.credential_id,
                version_id: new.id,
                keyset_id: new.keyset_id,
                keys: new.keys,
                allowed,
                effective_at: new.effective_at,
                expires_at: new.expires_at,
                status: new.status,
                provenance: new.provenance,
            })
            .map_err(|_| encode_error::<KeysetWriteError>("a time is outside the time range"))?;
            let request = PendingRequest {
                kind: OperationKind::TrustKeysetVersionCreate,
                tenant_id: Some(new.tenant_id),
                // A create has no target revision (README:946).
                expected_revision: 0,
                plan: plan.to_plan(),
            };
            let pending =
                insert_pending::<KeysetWriteError>(transaction, submission, &requester, request)
                    .await?;
            Ok(Gated::Pending(pending))
        }
    }
}

/// Enables the keyset version `id` of `tenant_id` at `expected_revision`
/// for the operator whose credential has `public_identity`, after the
/// overlap check of its stored keys against the keyset's other enabled
/// versions, and appends its `trust_keyset_version.enable` event last, in
/// `transaction` (see the module docs). A re-enable after a rotation is
/// refused while the replacement is enabled. Runs only under
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`.
///
/// Ungated, as [`create_version`]; [`submit_enable_version`] is the gated
/// write.
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
/// The caller commits on `Ok` and rolls back on `Err`. Never gated: a
/// disable is not widening (proposal section 1).
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
    target: (&str, &str, i64),
    status: Status,
    audit: &KeysetAudit<'_>,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    require_read_committed::<KeysetWriteError>(transaction).await?;
    let requester =
        authorize_trust_admin::<KeysetWriteError>(transaction, public_identity, target.0).await?;
    let identity = read_version_identity(transaction, target.0, target.1).await?;
    let (version, event) =
        apply_status(transaction, &requester, target, &identity.keyset_id, status).await?;
    append_stamped(transaction, event, audit.event_id, audit.now, SUCCESS).await?;
    Ok(version)
}

/// A version's immutable `keyset_id` and `fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VersionIdentity {
    pub(crate) keyset_id: String,
    pub(crate) fingerprint: String,
}

/// Step 2 of a status change: the version's [`VersionIdentity`], without a
/// lock (both columns are immutable). A version missing from the tenant is
/// [`RegistryError::NotFound`].
pub(crate) async fn read_version_identity(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    id: &str,
) -> Result<VersionIdentity, KeysetWriteError> {
    let (keyset_id, fingerprint) = sqlx::query_as(VERSION_IDENTITY)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)?;
    Ok(VersionIdentity {
        keyset_id,
        fingerprint,
    })
}

/// Steps 3 to 5 of a status change of the version `id` of `tenant_id` in
/// `keyset_id`, through the checks: the parent lock, then the target in a
/// new statement (an enable reads the row with its keys, a disable its
/// revision only) against `expected_revision`, then, for an enable, the
/// count and the overlap check. Returns the stored revision. A gated
/// enable's pending request runs exactly these (D7).
async fn check_status(
    transaction: &mut Transaction<'_, Postgres>,
    (tenant_id, id, expected_revision): (&str, &str, i64),
    keyset_id: &str,
    status: Status,
) -> Result<i64, KeysetWriteError> {
    lock_keyset(transaction, tenant_id, keyset_id).await?;
    match status {
        Status::Enabled => {
            let stored = read_keyset_version(&mut **transaction, tenant_id, id)
                .await?
                .ok_or(RegistryError::NotFound)?;
            let previous_revision = stored.revision;
            if previous_revision != expected_revision {
                return Err(RegistryError::StaleRevision.into());
            }
            let rows =
                read_enabled_keyset_versions(&mut **transaction, tenant_id, keyset_id).await?;
            check_enabled_count(&rows, id)?;
            // The target and its compared versions in one parse step: one
            // permit, one wait, per write.
            let ((row, keys), compared) = parse_enable(stored, rows).await?;
            check_against(&enabled(&row, keys.set()), &compared)?;
            Ok(previous_revision)
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
            Ok(previous_revision)
        }
    }
}

/// Steps 3 to 6 of a status change by `requester`: [`check_status`], then
/// the compare-and-set. Returns the row and its event, unstamped.
async fn apply_status(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    target: (&str, &str, i64),
    keyset_id: &str,
    status: Status,
) -> Result<(TrustKeysetVersion, UnstampedEvent), KeysetWriteError> {
    let previous_revision = check_status(transaction, target, keyset_id, status).await?;
    let (tenant_id, id, expected_revision) = target;
    let version =
        update_trust_keyset_version(&mut **transaction, tenant_id, id, expected_revision, status)
            .await?;
    let action = match status {
        Status::Enabled => ENABLE_ACTION,
        Status::Disabled => DISABLE_ACTION,
    };
    let event = unstamped(requester, action, Some(previous_revision), &version);
    Ok((version, event))
}

/// The post-authorization steps of an enable (D26): steps 2 to 6 of the
/// version `id` of `tenant_id` at `expected_revision`, by `requester`,
/// whom the caller authorized: the version's keyset, the parent lock, the
/// target and its revision, the count, the overlap check of its stored
/// keys on the in-transaction pool, and the compare-and-set. Returns the
/// row and its `trust_keyset_version.enable` event, unstamped; the caller
/// appends it.
pub(crate) async fn apply_enable_version(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
) -> Result<(TrustKeysetVersion, UnstampedEvent), KeysetWriteError> {
    let identity = read_version_identity(transaction, tenant_id, id).await?;
    let target = (tenant_id, id, expected_revision);
    apply_status(
        transaction,
        requester,
        target,
        &identity.keyset_id,
        Status::Enabled,
    )
    .await
}

/// Requests the enable of the keyset version `id` of `tenant_id` at
/// `expected_revision` (proposal section 3, "Request"): a widening write,
/// a re-enable and an enable of an enabled version included, for the
/// `trust_admin` whose credential has `submission.public_identity`. In a
/// savepoint, only under `READ COMMITTED`: the requester's rows, the flag
/// and the policy row as [`submit_create_version`], then the version's
/// keyset and fingerprint and the mode:
///
/// - applied at once, as [`enable_version`], with the event's outcome
///   `success_widening` or `success_single_actor` (D23; Q4);
/// - otherwise the enable's checks (the parent lock, the target's
///   revision, the cap, the parse and the overlap check), then a pending
///   `trust_keyset_version_enable` operation at `expected_revision`, whose
///   plan names the version, its keyset and its stored fingerprint. The
///   version is not written.
///
/// The caller commits on `Ok` and rolls back on `Err`.
pub async fn submit_enable_version(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError> {
    let target = (tenant_id, id, expected_revision);
    in_savepoint(transaction, async |savepoint| {
        submit_enable_steps(savepoint, submission, target).await
    })
    .await
}

/// Request steps 0 to 8 of [`submit_enable_version`], in its savepoint.
async fn submit_enable_steps(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    target: (&str, &str, i64),
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError> {
    let (tenant_id, id, expected_revision) = target;
    require_read_committed::<KeysetWriteError>(transaction).await?;
    let (requester, mode) =
        authorize_widening_write::<KeysetWriteError>(transaction, submission, tenant_id).await?;
    let identity = read_version_identity(transaction, tenant_id, id).await?;
    match mode {
        Mode::Apply(outcome) => {
            let (version, event) = apply_status(
                transaction,
                &requester,
                target,
                &identity.keyset_id,
                Status::Enabled,
            )
            .await?;
            append_stamped(
                transaction,
                event,
                submission.event_id,
                submission.now,
                outcome,
            )
            .await?;
            Ok(Gated::Applied(version))
        }
        Mode::Pending => {
            check_status(transaction, target, &identity.keyset_id, Status::Enabled).await?;
            let plan = EnablePlan {
                requester_credential_id: requester.credential_id.clone(),
                version_id: id.into(),
                keyset_id: identity.keyset_id,
                fingerprint: identity.fingerprint,
            };
            let request = PendingRequest {
                kind: OperationKind::TrustKeysetVersionEnable,
                tenant_id: Some(tenant_id),
                expected_revision,
                plan: plan.to_plan(),
            };
            let pending =
                insert_pending::<KeysetWriteError>(transaction, submission, &requester, request)
                    .await?;
            Ok(Gated::Pending(pending))
        }
    }
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
            VERSION_IDENTITY,
            "SELECT keyset_id, fingerprint FROM trust_keyset_version \
             WHERE tenant_id = $1 AND id = $2"
        );
        assert_eq!(VERSION_ID_CHECK, "trust_keyset_version_id_check");
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
                KeysetWriteError::WideningNotAcknowledged,
                "the trust keyset version write is widening and was not acknowledged",
                "WideningNotAcknowledged",
            ),
            (
                KeysetWriteError::PolicyUnavailable,
                "the instance security policy is unavailable",
                "PolicyUnavailable",
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
    ///
    /// Hazard: any lib test that runs [`create_version`] or
    /// [`enable_version`] of an enabled version, or
    /// [`parse_stored_versions`], must take `STATICS` too. Otherwise it gets
    /// [`KeysetWriteError::ValidationBusy`] while a test below holds every
    /// in-transaction permit (the upload test for about 2.3 s, the
    /// database test for about 5 s, in a debug build). A test that only
    /// runs [`validate_upload`] waits while Stage A's permits are held, and
    /// does not fail.
    static STATICS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// tokio's default `max_blocking_threads` (the runtime of `main` and of
    /// `#[tokio::test]` keeps it).
    const TOKIO_DEFAULT_MAX_BLOCKING_THREADS: usize = 512;

    /// A bound on every wait of these tests, so a hang fails instead.
    const HANG: Duration = Duration::from_secs(10);

    /// A short wait for the tests' own pools, in place of
    /// [`IN_TRANSACTION_WAIT`].
    const SHORT_WAIT: Duration = Duration::from_millis(150);

    /// `permits` permits of `pool`, or a failure (not a hang) when the pool
    /// has fewer than the test expects.
    async fn hold(pool: &'static Semaphore, permits: usize) -> SemaphorePermit<'static> {
        let permits = u32::try_from(permits).unwrap();
        tokio::time::timeout(HANG, pool.acquire_many(permits))
            .await
            .expect("the pool has fewer permits than its workers")
            .unwrap()
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

    /// Both pools fit far inside tokio's default blocking pool, which they
    /// share with other blocking work (see the module docs, "Cost"). That is
    /// all this checks: it does not read the service runtime's
    /// configuration. The endpoint-wiring PR owns the runtime builder and
    /// carries the test that pins `max_blocking_threads`.
    #[test]
    fn both_pools_fit_far_inside_the_blocking_pool() {
        let workers = VALIDATION_WORKERS + IN_TRANSACTION_WORKERS;
        assert!(
            workers <= TOKIO_DEFAULT_MAX_BLOCKING_THREADS / 64,
            "{workers}"
        );
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
        let held = hold(&POOL, IN_TRANSACTION_WORKERS).await;
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
        let mut held = hold(&POOL, IN_TRANSACTION_WORKERS).await;
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
        let held = hold(&POOL, IN_TRANSACTION_WORKERS).await;
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
        let held = hold(&VALIDATION, VALIDATION_WORKERS).await;
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
    /// [`IN_TRANSACTION_WAIT`] and is `ValidationBusy`. And Stage A's wait
    /// has no bound: with every Stage A worker taken too, an upload still
    /// waits after more than [`IN_TRANSACTION_WAIT`], and is validated once
    /// a worker is free.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_upload_is_validated_while_the_in_transaction_pool_is_saturated() {
        let _statics = STATICS.lock().await;
        let held = hold(&IN_TRANSACTION, IN_TRANSACTION_WORKERS).await;
        let keys = tokio::time::timeout(
            IN_TRANSACTION_WAIT / 2,
            validate_upload(p256("k"), DEFAULT_ALLOWED_ALGORITHMS),
        )
        .await
        .expect("Stage A waits for no in-transaction worker")
        .unwrap();
        assert_eq!(keys.keys().len(), 1);
        let stage_a = hold(&VALIDATION, VALIDATION_WORKERS).await;
        let pending = tokio::spawn(validate_upload(p256("k"), DEFAULT_ALLOWED_ALGORITHMS));
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            HANG,
            parse_stored_versions(vec![stored("ver_1", &p256("k"))]),
        )
        .await
        .expect("the wait is bounded");
        assert!(matches!(result, Err(KeysetWriteError::ValidationBusy)));
        assert!(start.elapsed() >= IN_TRANSACTION_WAIT);
        // Past the in-transaction bound, and some margin, the upload waits on.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!pending.is_finished(), "Stage A's wait has a bound");
        drop(stage_a);
        let keys = tokio::time::timeout(HANG, pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(keys.keys().len(), 1);
        drop(held);
    }

    /// An enable's parse step on a pool of its own, with a parse that waits
    /// for the test: the target and its compared versions are parsed in one
    /// blocking task on one permit, which that task holds until it returns,
    /// even after its caller is dropped.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_enable_parses_on_one_permit_held_by_its_blocking_task() {
        use std::sync::Mutex;
        use std::sync::mpsc::{Receiver, channel};
        use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
        static POOL: Semaphore = Semaphore::const_new(IN_TRANSACTION_WORKERS);
        static STARTED: Mutex<Option<UnboundedSender<String>>> = Mutex::new(None);
        static RELEASE: Mutex<Option<Receiver<()>>> = Mutex::new(None);
        /// Reports the set it parses, waits for the test, then parses it.
        fn gated(stored: &str) -> Result<ValidatedKeyset, JwkSetError> {
            let started = STARTED.lock().unwrap().clone().unwrap();
            started.send(stored.to_owned()).unwrap();
            RELEASE.lock().unwrap().as_ref().unwrap().recv().unwrap();
            parse_in_full(stored)
        }
        let (started_tx, mut started) = unbounded_channel();
        *STARTED.lock().unwrap() = Some(started_tx);
        let (release, release_rx) = channel::<()>();
        *RELEASE.lock().unwrap() = Some(release_rx);
        let next = async |started: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            tokio::time::timeout(HANG, started.recv())
                .await
                .unwrap()
                .unwrap()
        };
        let target = || stored("ver_t", &p256("k"));
        let compared = || stored("ver_c", &p256("other"));
        let rows = || {
            let mut outside = stored("ver_x", &p256("x"));
            outside.expires_at = Some(SystemTime::UNIX_EPOCH);
            outside.effective_at = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
            // The target's own row, a version whose window does not
            // intersect, and one that does: only the last is compared.
            vec![target(), outside, compared()]
        };

        let task = tokio::spawn(parse_enable_on(&POOL, HANG, gated, target(), rows()));
        assert_eq!(next(&mut started).await, target().public_jwks);
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS - 1);
        release.send(()).unwrap();
        assert_eq!(next(&mut started).await, compared().public_jwks);
        // Still the one permit, held across both parses.
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS - 1);
        release.send(()).unwrap();
        let ((row, _), parsed) = tokio::time::timeout(HANG, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(row.id, "ver_t");
        let ids: Vec<&str> = parsed.iter().map(|(row, _)| row.id.as_str()).collect();
        assert_eq!(ids, ["ver_c"]);
        assert!(started.try_recv().is_err());
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS);

        // The caller dropped while the target is parsed: the blocking task
        // keeps the permit through both parses, then gives it back.
        let task = tokio::spawn(parse_enable_on(&POOL, HANG, gated, target(), rows()));
        assert_eq!(next(&mut started).await, target().public_jwks);
        task.abort();
        let joined = tokio::time::timeout(HANG, task).await.unwrap();
        assert!(joined.is_err_and(|err| err.is_cancelled()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS - 1);
        release.send(()).unwrap();
        assert_eq!(next(&mut started).await, compared().public_jwks);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(POOL.available_permits(), IN_TRANSACTION_WORKERS - 1);
        release.send(()).unwrap();
        until_all_free(&POOL).await;
    }

    /// An empty list of stored versions takes no permit, so it cannot be
    /// busy.
    #[tokio::test]
    async fn no_stored_version_to_parse_takes_no_permit() {
        let _statics = STATICS.lock().await;
        let held = hold(&IN_TRANSACTION, IN_TRANSACTION_WORKERS).await;
        let parsed = tokio::time::timeout(IN_TRANSACTION_WAIT / 2, parse_stored_versions(vec![]))
            .await
            .expect("no wait for a worker")
            .unwrap();
        assert!(parsed.is_empty());
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
        async fn busy<T: std::fmt::Debug>(
            pool: &PgPool,
            write: impl AsyncFnOnce(&mut Transaction<'static, Postgres>) -> Result<T, KeysetWriteError>,
        ) {
            busy_as(pool, "ValidationBusy", write).await;
        }

        /// [`busy`] for a call whose error prints as `expected` (an
        /// approval's `Keyset(ValidationBusy)`).
        async fn busy_as<T: std::fmt::Debug, E: std::fmt::Debug>(
            pool: &PgPool,
            expected: &str,
            write: impl AsyncFnOnce(&mut Transaction<'static, Postgres>) -> Result<T, E>,
        ) {
            let mut tx = pool.begin().await.unwrap();
            let start = std::time::Instant::now();
            let (result, ()) = tokio::join!(
                async { tokio::time::timeout(HANG, write(&mut tx)).await },
                until_locked(pool),
            );
            match result.expect("the wait is bounded") {
                Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
                Err(err) => assert_eq!(format!("{err:?}"), expected),
            }
            // One wait per write, not one per parse.
            let waited = start.elapsed();
            assert!(waited >= IN_TRANSACTION_WAIT, "{waited:?}");
            assert!(waited < 2 * IN_TRANSACTION_WAIT, "{waited:?}");
            // The savepoint is rolled back: the locks are free while the
            // caller's transaction is still open, and it is usable.
            assert_eq!(lock_refusal(pool).await, None);
            sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
            // A caller that commits after the error commits nothing.
            tx.commit().await.unwrap();
        }

        /// `write` in its own transaction, committed: it needs no worker,
        /// so it succeeds at once while every in-transaction worker is
        /// taken.
        async fn at_once<T>(
            pool: &PgPool,
            write: impl AsyncFnOnce(&mut Transaction<'static, Postgres>) -> Result<T, KeysetWriteError>,
        ) -> T {
            let mut tx = pool.begin().await.unwrap();
            let result = tokio::time::timeout(IN_TRANSACTION_WAIT / 2, write(&mut tx))
                .await
                .expect("the write waited for a worker");
            let value = result.unwrap_or_else(|err| panic!("{err:?}"));
            tx.commit().await.unwrap();
            value
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
            let mut held = hold(&IN_TRANSACTION, IN_TRANSACTION_WORKERS).await;

            // A write that compares no stored version takes no permit: an
            // enabled create in the empty keyset, and one whose window
            // intersects no enabled version.
            let enabled_1 = version("ver_1", &key_1, Status::Enabled, &provenance);
            at_once(pool, async |tx| {
                create_version(tx, TRUST, &enabled_1, &audit("aud_1")).await
            })
            .await;
            let enabled_3 = NewKeysetVersion {
                effective_at: now() - Duration::from_secs(1000),
                expires_at: Some(now() - Duration::from_secs(500)),
                ..version("ver_3", &key_1, Status::Enabled, &provenance)
            };
            at_once(pool, async |tx| {
                create_version(tx, TRUST, &enabled_3, &audit("aud_2")).await
            })
            .await;
            let rows = |ver_2: Option<(&str, i64)>| {
                let mut rows = vec![("ver_1".to_string(), "enabled".to_string(), 1_i64)];
                if let Some((status, revision)) = ver_2 {
                    rows.push(("ver_2".into(), status.into(), revision));
                }
                rows.push(("ver_3".into(), "enabled".into(), 1));
                rows
            };
            assert_eq!(stored_state(pool).await, (rows(None), 2));

            // A create of an enabled version, which compares `ver_1`.
            let enabled_2 = version("ver_2", &key_2, Status::Enabled, &provenance);
            busy(pool, async |tx| {
                create_version(tx, TRUST, &enabled_2, &audit("aud_3")).await
            })
            .await;
            assert_eq!(stored_state(pool).await, (rows(None), 2));
            // A disabled create parses nothing and needs no worker.
            let disabled_2 = version("ver_2", &key_2, Status::Disabled, &provenance);
            at_once(pool, async |tx| {
                create_version(tx, TRUST, &disabled_2, &audit("aud_3")).await
            })
            .await;
            assert_eq!(stored_state(pool).await, (rows(Some(("disabled", 1))), 3));
            // An enable, which parses its target and `ver_1`.
            busy(pool, async |tx| {
                enable_version(tx, TRUST, "ten_a", "ver_2", 1, &audit("aud_4")).await
            })
            .await;
            assert_eq!(stored_state(pool).await, (rows(Some(("disabled", 1))), 3));

            // One wait per write: an enable granted a worker after waiting
            // most of its wait parses its target and `ver_1` on that one
            // worker. Another waiter, queued behind it, takes the worker as
            // soon as the enable gives it back, so an enable that waited a
            // second time would be `ValidationBusy`.
            let task_pool = pool.clone();
            let start = std::time::Instant::now();
            let enable = tokio::spawn(async move {
                let mut tx = task_pool.begin().await.unwrap();
                let audit = audit("aud_4");
                let result = enable_version(&mut tx, TRUST, "ten_a", "ver_2", 1, &audit).await;
                if result.is_ok() {
                    tx.commit().await.unwrap();
                }
                result
            });
            until_locked(pool).await;
            tokio::time::sleep(IN_TRANSACTION_WAIT / 4).await;
            assert!(!enable.is_finished());
            let behind = tokio::spawn(async { IN_TRANSACTION.acquire().await.unwrap() });
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(held.split(1).unwrap());
            let version = tokio::time::timeout(HANG, enable)
                .await
                .unwrap()
                .unwrap()
                .unwrap_or_else(|err| panic!("{err:?}"));
            assert_eq!((version.status, version.revision), (Status::Enabled, 2));
            assert!(start.elapsed() < 2 * IN_TRANSACTION_WAIT);
            let behind = tokio::time::timeout(HANG, behind).await.unwrap().unwrap();
            drop((behind, held));
            assert_eq!(stored_state(pool).await, (rows(Some(("enabled", 2))), 4));
            db.drop().await;
        }

        /// A clock at [`now`].
        struct Now;

        impl crate::operation::Clock for Now {
            fn now(&self) -> SystemTime {
                now()
            }
        }

        fn submission<'a>(operation_id: &'a str, event_id: &'a str) -> Submission<'a> {
            Submission {
                public_identity: TRUST,
                acknowledge_widening: true,
                operation_id,
                event_id,
                now: now(),
            }
        }

        /// The number of administrative operations.
        async fn operations(pool: &PgPool) -> i64 {
            sqlx::query_scalar("SELECT count(*) FROM administrative_operation")
                .fetch_one(pool)
                .await
                .unwrap()
        }

        /// The gated writes keep the direct writes' permit semantics: a
        /// request, pending or applied at once, and an approval that must
        /// compare a stored version wait for an in-transaction worker under
        /// their locks and are `ValidationBusy` when none frees up, with
        /// nothing written and the locks released; a disabled create needs
        /// no worker.
        #[tokio::test(flavor = "multi_thread")]
        #[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
        async fn a_gated_write_with_no_in_transaction_worker_is_validation_busy() {
            use crate::operation::{
                ApprovalEcho, ApprovalIds, ApprovalScope, approve_operation, prepare_approval,
            };
            use crate::persistence::registry::{BootstrapRequest, bootstrap_instance};

            let _statics = STATICS.lock().await;
            let db = Db::create().await;
            let pool = db.pool();
            // The policy row, and an instance `security_admin` to approve.
            let mut tx = pool.begin().await.unwrap();
            bootstrap_instance(
                &mut tx,
                &BootstrapRequest {
                    instance_id: "019a9f3c-5b2e-7c41-9d8e-0123456789ab",
                    admin_id: "adm_sec",
                    credential_id: "crd_adm_sec",
                    public_identity: "key_adm_sec",
                    trust_anchor_ref: "deployment/operator-ca",
                    binding_id: "rb_adm_sec",
                    recovery_public_key: &[0x11; 32],
                    audit_event_id: "aud_bootstrap",
                    now: now(),
                },
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            let set_widening = async |on: bool| {
                sqlx::query(
                    "UPDATE instance_security_policy \
                     SET widening_second_approver = $1, revision = revision + 1",
                )
                .bind(on)
                .execute(pool)
                .await
                .unwrap();
            };
            set_widening(true).await;
            let provenance = JsonObject::new();
            let key_1 = validate_upload(p256("k1"), DEFAULT_ALLOWED_ALGORITHMS)
                .await
                .unwrap();
            let key_2 = validate_upload(p256_b("k2"), DEFAULT_ALLOWED_ALGORITHMS)
                .await
                .unwrap();
            let enabled_1 = version("ver_1", &key_1, Status::Enabled, &provenance);
            let disabled_2 = version("ver_2", &key_2, Status::Disabled, &provenance);
            let enabled_3 = version("ver_3", &key_2, Status::Enabled, &provenance);
            let enabled_4 = version("ver_4", &key_2, Status::Enabled, &provenance);
            let allowed = DEFAULT_ALLOWED_ALGORITHMS;
            at_once(pool, async |tx| {
                create_version(tx, TRUST, &enabled_1, &audit("aud_1")).await
            })
            .await;
            at_once(pool, async |tx| {
                create_version(tx, TRUST, &disabled_2, &audit("aud_2")).await
            })
            .await;
            let Gated::Pending(op) = at_once(pool, async |tx| {
                submit_create_version(tx, &submission("op_3", "aud_3"), &enabled_3, allowed).await
            })
            .await
            else {
                panic!("not pending");
            };
            let prepared = prepare_approval(
                pool,
                "key_adm_sec",
                ApprovalScope::Tenant("ten_a"),
                "op_3",
                allowed,
                now(),
            )
            .await
            .unwrap();
            let echo = ApprovalEcho {
                request_digest: op.request_digest,
                expected_revision: op.expected_revision,
            };
            let state = (stored_state(pool).await, operations(pool).await);
            let held = hold(&IN_TRANSACTION, IN_TRANSACTION_WORKERS).await;

            // Pending requests: a create and an enable, each comparing
            // `ver_1`.
            busy(pool, async |tx| {
                submit_create_version(tx, &submission("op_4", "aud_4"), &enabled_4, allowed).await
            })
            .await;
            busy(pool, async |tx| {
                let submission = submission("op_4", "aud_4");
                submit_enable_version(tx, &submission, "ten_a", "ver_2", 1).await
            })
            .await;
            // The approval reruns the create under its locks.
            busy_as(pool, "Keyset(ValidationBusy)", async |tx| {
                let ids = ApprovalIds {
                    approve_operation_id: "appr_3",
                    approve_event_id: "aud_appr_3",
                    write_event_id: "aud_write_3",
                };
                let scope = ApprovalScope::Tenant("ten_a");
                approve_operation(tx, "key_adm_sec", scope, &prepared, &echo, &ids, &Now).await
            })
            .await;
            assert_eq!((stored_state(pool).await, operations(pool).await), state);
            // Applied at once, the toggle off.
            set_widening(false).await;
            busy(pool, async |tx| {
                submit_create_version(tx, &submission("op_4", "aud_4"), &enabled_4, allowed).await
            })
            .await;
            assert_eq!((stored_state(pool).await, operations(pool).await), state);
            // A disabled create compares nothing.
            let disabled_4 = version("ver_4", &key_2, Status::Disabled, &provenance);
            let applied = at_once(pool, async |tx| {
                submit_create_version(tx, &submission("op_4", "aud_4"), &disabled_4, allowed).await
            })
            .await;
            assert!(matches!(applied, Gated::Applied(_)), "{applied:?}");
            drop(held);
            db.drop().await;
        }
    }
}
