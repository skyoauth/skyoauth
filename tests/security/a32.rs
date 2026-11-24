//! A32: concurrent or reopened bootstrap, forged IdP admin, revoked
//! operator or replayed recovery. Expected: one enrollment only, no
//! elevation or replay, audited independent restoration (tasks §8; T13.4,
//! T13.5, T13.6).
//!
//! **A32 partial: the bootstrap and recovery registry slice only; A32 M1a
//! stays planned (scope "full row").** These tests are registered on A32's
//! planned M1a stage, so they are no evidence for it: the reporter lists
//! their results as not counted, and they are no claim. They run through
//! the typed registry API (`skyoauth_service::persistence::registry`:
//! [`bootstrap_instance`], [`issue_recovery_challenge`],
//! [`preview_recovery_response`], [`restore_operator`],
//! [`get_recovery_state`], the operator getters,
//! `disable_admin_identity` and `revoke_admin_credential`,
//! [`authorize_operator`], [`get_instance_security_policy`] and
//! [`verify_audit_chain`]; and, through `registry::test_support`, a
//! `#[doc(hidden)]` module behind the `test-support` feature, the operator
//! creates, `update_admin_role_binding` and [`append_audit_event`] for the
//! event that holds the audit chain head in the failure tests) against a
//! real PostgreSQL, one fresh database
//! per test (per round in the replica tests), and write nothing past the
//! registry. The only SQL of their own is one read-only helper, [`counts`]
//! (see its docs), and two `SET SESSION CHARACTERISTICS AS TRANSACTION
//! ISOLATION LEVEL` statements in
//! `a32_neg_a_restore_outside_read_committed_writes_nothing`: one gives
//! each replica its isolation level ([`OTHER_ISOLATION`]), and the second
//! switches the last replica back to `READ COMMITTED` before its restore.
//! The concurrent tests use the replica harness (REP,
//! `skyoauth_scenarios::rep`): [`Replicas::race`], whose replicas a barrier
//! releases together,
//! [`rep::wait_until_blocked`] and, for a lost store,
//! [`rep::terminate`]. The fixture is local: every bootstrap
//! request is valid and has IDs, keys and an instance ID of its own
//! ([`ids`]), and each bootstrap runs in a transaction of its own that
//! commits on `Ok` and rolls back on every `Err`, as the caller must
//! ([`bootstrap`]). Likewise every recovery ([`recovery`]) is valid for the
//! instance and epoch it names, its response is signed by the recovery key
//! of that epoch over the `M` its issue returns ([`issue`]), as the
//! workstation would sign it, and it has a replacement, a new recovery key
//! and event IDs of its own; each issue and restore runs in a
//! transaction of its own, committed on `Ok` and rolled back on `Err`
//! ([`issue_on`], [`restore`]); a restore's transaction is
//! `READ COMMITTED`, the session default. The exceptions are in the
//! failure tests: their claimants ([`fail_at_append`]), a bootstrap or a
//! restore whose event ID is taken on purpose and whose caller commits
//! after its `Err` ([`end_claim`]), which the registry allows, and an issue
//! whose event ID is taken, whose caller also commits after its `Err`. The
//! registry reads no clock: every `now` is the test's and fixed
//! ([`issued_at`], [`restored_at`]). Every key is an Ed25519 test key
//! derived from a fixed seed ([`test_key`]), so every signature is the same
//! on every run.
//!
//! - **Bootstrap, positive.** One bootstrap on an empty database: the IDs of its
//!   outcome are the rows the getters read back, the instance
//!   `security_admin` it enrolls authorizes with exactly those IDs, and the
//!   audit chain is intact at sequence 1. As a cheap extra check, the
//!   recovery public key (as hex or base64) and the instance
//!   ID, presented as an operator credential's `public_identity`, authorize
//!   no role (`a32_pos_one_bootstrap_enrolls_one_operator_and_closes`).
//! - **Bootstrap, negative.** Of 8 replicas that bootstrap at once with requests that
//!   share nothing, exactly one succeeds and 7 are `AlreadyClosed`; the losers' rows do not exist, the winner's are the
//!   only ones and the chain is intact at 1, in 3 fresh databases, whichever
//!   replica wins (`a32_neg_concurrent_bootstraps_across_replicas_have_one_winner`).
//!   Four replicas seen blocked behind a holder's uncommitted bootstrap
//!   follow its end: after its commit all 4 are `AlreadyClosed` and the
//!   state is the holder's; after its rollback exactly one of them
//!   bootstraps and the state is that one's
//!   (`a32_neg_blocked_bootstraps_follow_the_holder_commit_or_rollback`).
//!   A closed bootstrap is never reopened: with the operator as enrolled,
//!   then with its identity disabled, its credential revoked and its
//!   binding disabled, one lever after another, the same request, a request
//!   with new IDs and requests that reuse the existing admin ID, credential
//!   key or audit event ID are each `AlreadyClosed` and write nothing,
//!   also on a fresh pool; and the revoked key cannot be registered for
//!   another operator, by the inferred `0005` rule below
//!   (`a32_neg_a_closed_bootstrap_is_never_reopened`). A bootstrap that
//!   waits for the audit chain head at its append, its last step (after its
//!   writes, by `registry::bootstrap`; not asserted here), with 4 replicas
//!   blocked behind it, fails there, with its event ID
//!   taken (`AlreadyExists` on `audit_event_pkey`; its caller then commits)
//!   or with its session terminated (the store is gone; `57P01`): it
//!   writes nothing (with its event ID taken, the replicas finish while its
//!   transaction is still open), exactly one of them bootstraps and 3 are
//!   `AlreadyClosed`, and the chain is intact
//!   (`a32_neg_a_bootstrap_failing_at_its_audit_append_writes_nothing`).
//! - **Recovery, positive.** After a bootstrap, with its operator enrolled
//!   (and given a second credential) or locked out (identity disabled,
//!   first credential revoked, binding disabled, so no key authorizes a
//!   `security_admin`), a challenge is issued, its `M` binds exactly the
//!   operation, the plan, the expected revision and the expiry, and its
//!   response, signed by the bootstrap recovery key, is previewed (which
//!   grants nothing, though its caller commits) and restored: the replacement
//!   its plan names (its six members) is enrolled and authorizes with
//!   exactly the plan's IDs; every operator credential still unrevoked is
//!   revoked at the restore's `now` and no old key authorizes any role,
//!   while the old identity and binding stay as they were; the recovery
//!   state ([`get_recovery_state`]) holds the plan's key at epoch 2, closed;
//!   the issue, restore and rotation events are sequences 2, 3 and 4, each
//!   linked to the one before, and the chain is intact at 4; bootstrap stays
//!   closed, also on a fresh pool
//!   (`a32_pos_signed_recovery_restores_a_replacement_operator`).
//! - **Recovery, negative.** A replay is `NotRestorable` and writes nothing,
//!   on the restoring pool and on a fresh one: the identical response and
//!   request (the retry of an uncertain commit), the same response later
//!   with event IDs of its own and the same challenge signed by the rotated
//!   key are `Consumed`, and a second challenge issued before the rotation,
//!   so for the retired key, is `NotBound`, signed by either key; no
//!   challenge is issued for the retired epoch, a restore rolled back before
//!   it left the challenge restorable, and a challenge of the new epoch,
//!   signed by the new key, then restores
//!   (`a32_neg_a_replayed_recovery_is_refused`). A response whose signature
//!   is not the current recovery key's over its challenge's `M` (signed over
//!   that challenge with any one member of its plan, its operation ID, its
//!   expected revision or its expiry changed, over another challenge, over
//!   `C` without the prefix or under the request-digest prefix, by another
//!   key, or altered, malleated or zero) is `NotRestorable`
//!   (`BadSignature`) at the restore and at the preview and enrolls nothing,
//!   one for no challenge is `NotFound`, and a challenge for another
//!   instance is not issued; the untouched challenge then restores and the
//!   other is retired (`NotBound`)
//!   (`a32_neg_a_restore_must_be_the_one_its_challenge_names`). At the
//!   shortest, default and longest TTL, a restore at `expires_at`, a
//!   microsecond after and a longest TTL after is `NotRestorable`
//!   (`Expired`) and one a microsecond before restores, over three
//!   successive epochs, each signed by the key of its epoch
//!   (`a32_neg_an_expired_challenge_is_refused`). Replicas whose sessions
//!   default to `REPEATABLE READ`, `SERIALIZABLE` or `READ UNCOMMITTED` get
//!   `UnsupportedIsolation`, keep a usable transaction and commit nothing,
//!   and the challenge then restores at `READ COMMITTED`
//!   (`a32_neg_a_restore_outside_read_committed_writes_nothing`). Of 8
//!   replicas that restore at once, one challenge for all or one each,
//!   exactly one restores and 7 are `NotRestorable` (`Consumed` for the one
//!   challenge, `NotBound` for their own), in 4 fresh databases
//!   (`a32_neg_concurrent_restores_across_replicas_have_one_winner`); 4
//!   replicas seen blocked behind a holder's uncommitted restore all get
//!   `NotRestorable` (`Consumed`) after its commit, and exactly one of them
//!   restores after its rollback
//!   (`a32_neg_blocked_restores_follow_the_holder_commit_or_rollback`). An
//!   issue whose event ID is taken is `AlreadyExists` and writes nothing,
//!   also when its caller commits after the `Err`, and the chain stays
//!   intact.
//!   A restore that waits for the chain head at its appends, its last step
//!   (after its consume and writes, by `registry::recovery`; not asserted
//!   here), with 4 replicas restoring the same challenge blocked behind
//!   it, fails at its appends, with its second event ID
//!   taken (its first event is appended; its caller then commits) or with
//!   its session terminated: it writes nothing, neither its first event nor
//!   its advance of the head is left, exactly one replica restores and 3
//!   are `NotRestorable` (`Consumed`), and the chain is intact
//!   (`a32_neg_a_recovery_failing_at_its_audit_append_writes_nothing`).
//!
//! The lost store of those two tests is a session that the server
//! terminates while the call waits: the call is a typed store error, not a
//! panic, and the database, which stays up, holds nothing of it. At the
//! registry level that is the only store failure a call can meet: these
//! functions take an open transaction, so neither a pool closed on the
//! client side nor a server that is down or unreachable for the whole call
//! ever reaches them, and neither is tested here. A store outage for a
//! whole bootstrap, issue or restore, and the state once the store comes
//! back, are a service-level (UC) gap, like a store error at the operator
//! endpoint: no scenario row names them, and their owner is to be ruled.
//! Their harness piece is the `pg` environment's planned fault-injecting
//! repository (conformance layout §1.1; compare A11's "store down → 503");
//! if ruled into A32, they belong with its end-to-end parts, the bootstrap
//! command and the service binary's recovery subcommand on UC (T13.3,
//! T13.4). A failed audit
//! append is pinned only where it fails, with a
//! taken event ID or a lost session; an append that fails in Rust after
//! the head lock is left to the service tests (below).
//!
//! A challenge bound to its instance, its operation and arguments digest
//! and the expected revision, expiring and single use, is the spec's
//! (tasks T13.5, design §7.2, threat model "Recovery response"; LT-107).
//! The recovery tests also pin these picks of the registry, recorded as
//! lead rulings or inferred in identity-registry section 5.2 and in
//! `registry::recovery` and provisional until the ADRs are ratified:
//! registry behaviour, not the spec's. The plan's members (the new key as
//! 64 lowercase hexadecimal digits); `M`, the bytes signed, as the prefix
//! `skyoauth.recovery_challenge.v1` and a newline followed by `C`, the
//! canonical JSON of the challenge (its ID, the actor `deployment_operator`,
//! the kind, the expected revision, `expires_at` in whole microseconds,
//! the plan and no tenant; members sorted, no whitespace); the signature as
//! pure Ed25519 over `M` (not its hash) with the raw 32-byte key of the
//! current epoch, an `S` at or above the group order refused; the binding
//! to the recovery key epoch; that the expected revision is the recovery
//! state's (inferred); the refusal of every level but
//! `READ COMMITTED`, by name, so `READ UNCOMMITTED` too; the TTL minimum of
//! 1 second; the issue event `administrative_operation.create` by
//! `deployment_operator`, with the operation as its object and
//! `new_revision` 1; the restore events' actor `recovery_key:<epoch>` of the
//! key that signed, the epoch before the rotation, and the rotation event's
//! revisions; every refusal of a restore as `NotRestorable` with the
//! reason its first failed check names (`registry::recovery` "Restore",
//! step 3: a consumed challenge is `Consumed` before it is `NotBound`, and
//! an expired one `Expired`), matched by variant, reason and `Debug` text,
//! not by its `Display` text; and a
//! restoration that revokes every unrevoked credential but leaves the
//! replaced operator's identity and binding enabled. The TTL default and
//! maximum (5 and 15 minutes; LT-107, OQ-LT-17) and the actions
//! `admin_identity.restore` and `recovery_state.rotate_key` (IR-059) are
//! the spec's. The events' `outcome` (`success`, inferred) is not asserted.
//!
//! The expiry is compared with the caller's `now` only (the registry reads
//! no clock), so a refusal for expiry writes nothing and is not final:
//! registry behaviour, not the spec's. The expiry test restores a
//! challenge a microsecond before `expires_at` after a restore at
//! `expires_at` was refused, and a `now` earlier than the issue time is
//! accepted as well (not asserted). LT-107's "the challenge expires" holds
//! only when `now` is taken from the service binary's own clock (T13.3) and
//! is tested with A64's injected clocks on its hermetic leg, not here.
//!
//! The restore checks the recovery signature itself (the user's ruling,
//! 2026-11-24, `docs/proposals/recovery-verified-response.md`;
//! `registry::recovery` "Restore", step 3): over `M` rebuilt from the
//! challenge row it has locked, with the recovery key of the state it has
//! locked, so the replacement, the binding and the key all come from the
//! database, never from the caller. These tests therefore sign the `M`
//! that [`issue_recovery_challenge`] returns, and test the refusals of a
//! signature that is not the current key's over that `M`. One obligation
//! still rests on the service binary's recovery subcommand (T13.3), not on
//! the registry, and is a gap of these tests: `now` must come from its own
//! clock immediately before the call, never from the response or the
//! operator; a library caller that holds a captured response can pass any
//! `now` (`registry::recovery` "Time"). Neither [`issue_recovery_challenge`] nor [`restore_operator`] takes an
//! operator identity (the issue is recorded by `deployment_operator`, the
//! restore by the recovery key), so "a revoked or disabled operator cannot
//! issue or restore" has no registry test; the positive's locked-out round
//! shows that a restoration needs no authorized operator.
//!
//! `AlreadyClosed` before a collision is the registry's documented
//! behaviour (#78, `registry::bootstrap` "Steps" and "Closure": the closure
//! check comes before any write), not a requirement of the spec, which
//! asks only that a closed bootstrap stays closed. Likewise, that a revoked
//! key cannot be registered again is the `0005` schema rule
//! `admin_credential_public_identity_key`, which `0005` marks inferred
//! (the delete guard that keeps the row is a follow-up in
//! `service/migrations/README.md`): registry behaviour, not the spec's. The registry tests cover it too
//! (`re_registering_a_revoked_key_in_a_transaction_is_refused_and_rolled_back`
//! in `service/tests/registry_operator.rs`,
//! `collisions_of_caller_ids_stay_already_exists` in
//! `service/tests/registry_bootstrap.rs`). The helpers pin two more of the
//! registry's current picks, not the spec's, and leave a third alone: no
//! `administrative_operation` row and `recovery_key_epoch = 1` (both
//! inferred in `registry::bootstrap`) are asserted, while `AlreadyClosed` is
//! matched by variant only, not by its `Display` text, "bootstrap is
//! already closed", which the spec does not define. Invalid requests (a
//! reserved admin ID, an instance ID that is not a lowercase UUIDv7, a
//! recovery key that is not 32 bytes, does not decode to a point, is not
//! canonically encoded or is of small order, an empty or over-long key or
//! anchor,
//! a `now` out of range) are refused before any statement, whatever the
//! state, so they reveal only whether the input is valid, never whether
//! bootstrap is open; they are not tested here
//! (`service/tests/registry_bootstrap.rs` tests them).
//!
//! **Missing, so not a claim.** A32 M1a needs its row end to end; these
//! tests reach only the registry functions in the middle of it. Not built
//! yet, with the owner of each part:
//!
//! - The deployment-local bootstrap command and its Unix socket, owned by
//!   the service UID with mode 0600 (T13.4, OQ-TM-9), and the service
//!   binary's recovery subcommand behind them (design §7.2, ADR-013 item 7;
//!   T13.3 builds it), which carries the plan to the issue, `M` to the
//!   workstation and the signed response back to the restore, with `now`
//!   from its own clock: with the restore's own check of the signature,
//!   which is tested here, the "local verifier" harness component of the
//!   row. Nothing here goes through a command, a socket or the binary: the
//!   tests call the registry functions in its place and sign `M`
//!   themselves, with fixed test keys, in the workstation's place.
//! - The restart and configuration-omission half of "durably closes" (T13.4)
//!   beyond a fresh pool: no service starts or restarts here, and no
//!   configuration is read; a new pool on the same database is all that is
//!   tested.
//! - The OP harness component, `skyoauth-operator` (T13.10), as the client
//!   whose key the bootstrap enrolls and that presents it afterwards, and
//!   that presents the replacement's key after a restoration.
//! - The signed offline recovery tooling: the portable workstation that
//!   parses and re-encodes `C` before it displays and signs `M` with the
//!   offline recovery key (ADR-013 item 8), with its SoftHSM2,
//!   hermetic and recovery-offline legs, injected clocks and the three
//!   operating systems, which belong to A64. A48 owns the full chain with
//!   no SQL through the OP client and the local verifier. Both are
//!   integration rows, not these tests.
//! - The forged IdP admin negative on the wire: an upstream admin-role
//!   claim or session from the OIDC harness component (the mock human IdP)
//!   must not reach an operator through the OP harness component, as for
//!   A22's upstream admin-role claim. For A32 the real claim is an
//!   architecture property, that no IdP-reachable path calls
//!   `bootstrap_instance` or `restore_operator`, which is not a registry
//!   test.
//! - Adopting a policy row written before bootstrap and its
//!   `InstanceIdMismatch`: no public API creates a policy row, so they stay
//!   with the service tests (`service/tests/registry_bootstrap.rs`).
//!
//! Not covered here either, because `service/tests/registry_bootstrap.rs`
//! covers it: the stored columns of every row bootstrap writes; a
//! bootstrap whose snapshot predates another's commit (`REPEATABLE READ`,
//! `SERIALIZABLE`); a policy row committed while bootstrap waits; an audit
//! append that fails in Rust after the head lock (a head at `2^53 - 1`) and
//! a caller that commits after it; a failed audit append, alone, whose
//! caller rolls back and retries with a fresh event ID; the audit append
//! as the last step; the bounds of `now`; collisions of caller IDs before
//! bootstrap; and the two paths that need a row written by other means: a
//! bootstrap that waits for an existing policy row's lock
//! (`a_second_bootstrap_waits_for_the_policy_lock_then_is_closed`) and a
//! `recovery_state` row not marked closed
//! (`a_recovery_state_not_marked_closed_still_closes_bootstrap`).
//!
//! Recovery that `service/tests/registry_recovery.rs` covers, mostly with
//! rows written by other means or a snapshot of every table, is not
//! repeated here: the columns of the operation row (`consumed_at`, its
//! revision and `outcome`), which no getter reads; a challenge consumed,
//! revoked or failed by other means, and the database guards that refuse a
//! second consume; malformed plans, the issue's input checks (the closed
//! plan, and a plan's new key that is weak, not canonically encoded or not
//! a point) and the TTL bounds of an issue; a known-answer `C` and `M`;
//! signatures that are not 64 bytes, over the challenge hash, with a
//! non-canonical `R`, and the retired key after a rotation; a weak current
//! recovery key, which no public path can enroll (bootstrap refuses it);
//! a row whose stored digest or hash is not the library's encoding
//! (`NotLibraryEncoding`) and a plan changed after the issue;
//! `RecoveryKeyUnchanged`, reserved admin IDs, key lengths and the bounds
//! of `now`; a replacement whose ID or key is taken
//! (`AlreadyExists`); a failed restore or issue that the caller commits,
//! other than the restore here whose second event ID is taken and the
//! issue here whose event ID is taken (a taken first event ID, the
//! writer's error in Rust after the head lock, an issue whose operation ID
//! is taken); a lock timeout; the lock order, the waits between a restore, an issue and
//! the operator writes, and the deadlock that fails closed; the preview's
//! own refusals beyond those of the tamper test; and that a restore changes
//! no other table. A restore checks the locked challenge row (unconsumed,
//! unrevoked, still `issued`, unexpired, its plan's instance and epoch and
//! its expected revision the recovery state's) before its consume, whose
//! statement repeats those predicates under the same locks, so through the
//! public API the consume can never miss after the checks passed. A replay
//! here is refused by the checks, with their reason: a consume that no
//! longer sets `consumed_at` leaves the row unconsumed but `restored`, so a
//! replay is refused for the wrong reason and the reason checks here catch
//! it; a consume that no longer requires it unset or the outcome `issued`,
//! or that no longer compares the plan's instance or epoch, the expected
//! revision or the recovery state, is caught only by the service tests, if
//! at all. So is a restore that no longer locks the credentials first,
//! which needs a concurrent operator write.
//!
//! Overlap with `service/tests/registry_recovery.rs`, which calls the same
//! public functions: each recovery test here repeats some of its checks and
//! adds what the scenario adds. The positive repeats
//! `a_restore_enrolls_a_replacement_revokes_every_credential_and_rotates_the_key`
//! and adds the path from bootstrap through public reads only, a locked-out
//! operator and bootstrap closed after the restore, also on a fresh pool.
//! The positive's preview repeats
//! `a_preview_checks_as_a_restore_does_and_grants_nothing` with a committed
//! preview. The replay test repeats `a_challenge_is_consumed_once` and
//! adds the identical retry, a fresh pool, the rolled-back restore, a
//! replay signed by the rotated key and the retired epoch at issue and at
//! restore. The tamper test's signature refusals repeat
//! `a_restore_needs_a_signature_by_the_current_key_over_m` in kind; it adds
//! a signature over the challenge with each one member of `C` changed, the
//! splices of two issued challenges, the preview of each refusal, and one
//! challenge that survives every refusal. The expiry test repeats `a_challenge_expires_at_its_expiry`
//! (default TTL) and adds the shortest and longest TTL over successive
//! epochs. The isolation test repeats `a_restore_runs_only_at_read_committed`
//! (a level set per transaction) with the level as a replica's session
//! default. The replica tests extend
//! `of_two_concurrent_restores_of_one_challenge_exactly_one_wins` (two
//! sessions) to 8 replicas with one challenge or one each, and to 4 waiters
//! blocked transitively behind a holder.
//!
//! [`bootstrap_instance`]: registry::bootstrap_instance
//! [`issue_recovery_challenge`]: registry::issue_recovery_challenge
//! [`restore_operator`]: registry::restore_operator
//! [`preview_recovery_response`]: registry::preview_recovery_response
//! [`get_recovery_state`]: registry::get_recovery_state
//! [`authorize_operator`]: registry::authorize_operator
//! [`get_instance_security_policy`]: registry::get_instance_security_policy
//! [`verify_audit_chain`]: registry::verify_audit_chain
//! [`append_audit_event`]: registry::test_support::append_audit_event

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use skyoauth_scenarios::{
    pg::TestDb,
    rep::{self, Replicas},
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, AdminCredential, AdminIdentity, AdminRole, AdminRoleBinding, AdminRoleBindingChanges,
        AuditActor, AuditEvent, AuthorizedOperator, BootstrapError, BootstrapOutcome,
        BootstrapRequest, ChainVerdict, ChallengeError, DEFAULT_CHALLENGE_TTL,
        DEPLOYMENT_OPERATOR_ACTOR, IssueChallenge, JsonObject, MAX_CHALLENGE_TTL,
        MIN_CHALLENGE_TTL, NewAdminCredential, NewAdminIdentity, NewAuditEvent,
        NotRestorableReason, OPERATOR_RESTORATION, OperatorRequest, OperatorScope,
        RecoveryChallenge, RecoveryPreview, RecoveryState, RegistryError, RestoreError,
        RestoreRequest, Restored, SignedRecoveryResponse, Status, bootstrap_instance,
        restore_operator,
    },
};
use sqlx::{Connection, PgConnection, Postgres, Row, Transaction, pool::PoolConnection};
use tokio::sync::oneshot;

/// Every role: a key that is not an operator's authorizes none of them.
const ROLES: [AdminRole; 5] = [
    AdminRole::SecurityAdmin,
    AdminRole::TrustAdmin,
    AdminRole::ClientAdmin,
    AdminRole::ProviderAdmin,
    AdminRole::Auditor,
];

/// The `Debug` text of every refused bootstrap here.
const CLOSED: &str = "Err(AlreadyClosed)";

/// The caller's `now` of every bootstrap; the registry reads no clock.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

/// The material of one bootstrap request, owned.
#[derive(Debug, Clone)]
struct Ids {
    instance_id: String,
    admin_id: String,
    credential_id: String,
    public_identity: String,
    trust_anchor_ref: String,
    binding_id: String,
    /// The private half of the recovery key: it signs the challenges of
    /// epoch 1.
    recovery_key: SigningKey,
    recovery_public_key: Vec<u8>,
    audit_event_id: String,
}

impl Ids {
    fn request(&self) -> BootstrapRequest<'_> {
        BootstrapRequest {
            instance_id: &self.instance_id,
            admin_id: &self.admin_id,
            credential_id: &self.credential_id,
            public_identity: &self.public_identity,
            trust_anchor_ref: &self.trust_anchor_ref,
            binding_id: &self.binding_id,
            recovery_public_key: &self.recovery_public_key,
            audit_event_id: &self.audit_event_id,
            now: now(),
        }
    }
}

/// The Ed25519 test key number `n` of the family `tag`: its 32-byte seed is
/// `tag` followed by `n` (little-endian), so keys of different tags or
/// numbers differ. Fixed, so every run signs with the same keys.
fn test_key(tag: &[u8; 24], n: usize) -> SigningKey {
    let mut seed = [0; 32];
    seed[..24].copy_from_slice(tag);
    seed[24..].copy_from_slice(&u64::try_from(n).unwrap().to_le_bytes());
    SigningKey::from_bytes(&seed)
}

/// The raw 32-byte public half of `key`, the form the registry stores.
fn public_key(key: &SigningKey) -> Vec<u8> {
    let public = key.verifying_key();
    // A key derived from a seed is a point of large order, canonically
    // encoded: the registry's key checks accept it.
    assert!(!public.is_weak());
    public.to_bytes().to_vec()
}

/// Valid request material number `n`, sharing nothing with any other `n`:
/// a lowercase hyphenated UUIDv7 instance ID (version `7`, variant `9`),
/// a non-reserved admin ID, a credential key and IDs of its own, and an
/// Ed25519 recovery key pair of its own ([`test_key`]), whose public half
/// is the 32 bytes bootstrap enrolls.
fn ids(n: usize) -> Ids {
    let recovery_key = test_key(b"a32 bootstrap recovery..", n);
    let ids = Ids {
        instance_id: format!("019a9f3c-5b2e-7c41-9d8e-{n:012x}"),
        admin_id: format!("adm_a32_{n}"),
        credential_id: format!("crd_a32_{n}"),
        public_identity: format!("spki-sha256:a32-operator-{n}"),
        trust_anchor_ref: "deployment/operator-ca".into(),
        binding_id: format!("rb_a32_{n}"),
        recovery_public_key: public_key(&recovery_key),
        recovery_key,
        audit_event_id: format!("aud_a32_bootstrap_{n}"),
    };
    assert_eq!(
        ids.recovery_public_key.len(),
        registry::RECOVERY_PUBLIC_KEY_LENGTH
    );
    ids
}

/// A fresh database with every migration and nothing else.
async fn fixture() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    (db, pool)
}

/// Bootstraps in a transaction of its own on `conn`: commits on `Ok` and
/// rolls back on every `Err`, as the caller of `bootstrap_instance` must.
async fn bootstrap(
    conn: &mut PgConnection,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    let mut tx = conn.begin().await.unwrap();
    let outcome = bootstrap_instance(&mut tx, request).await;
    match outcome {
        Ok(_) => tx.commit().await.unwrap(),
        Err(_) => tx.rollback().await.unwrap(),
    }
    outcome
}

async fn bootstrap_on(
    pool: &PgPool,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    bootstrap(&mut pool.acquire().await.unwrap(), request).await
}

/// `result` is `AlreadyClosed`, matched by variant; returns its `Debug`
/// text ([`CLOSED`]) for the callers' tallies of refusals.
#[track_caller]
fn closed_text(result: &Result<BootstrapOutcome, BootstrapError>, what: &str) -> String {
    match result {
        Err(BootstrapError::AlreadyClosed) => {}
        other => panic!("{what}: expected AlreadyClosed: {other:?}"),
    }
    let text = format!("{result:?}");
    assert_eq!(text, CLOSED, "{what}");
    text
}

/// Row counts of the tables bootstrap, an issue and a restore write, and of
/// the rows that are `owner`'s: its recovery state as bootstrap wrote it
/// (its instance ID and recovery key, closed, epoch 1; a restore rotates it
/// away) and its `recovery_state.create` event.
#[derive(Debug, PartialEq, Eq)]
struct Counts {
    policy: i64,
    recovery_state: i64,
    owner_recovery_state: i64,
    admin_identity: i64,
    admin_credential: i64,
    admin_role_binding: i64,
    audit_event: i64,
    owner_audit_event: i64,
    administrative_operation: i64,
}

/// One bootstrap's rows, all of them `owner`'s, and no administrative
/// operation.
const ONE: Counts = Counts {
    policy: 1,
    recovery_state: 1,
    owner_recovery_state: 1,
    admin_identity: 1,
    admin_credential: 1,
    admin_role_binding: 1,
    audit_event: 1,
    owner_audit_event: 1,
    administrative_operation: 0,
};

const NONE: Counts = Counts {
    policy: 0,
    recovery_state: 0,
    owner_recovery_state: 0,
    admin_identity: 0,
    admin_credential: 0,
    admin_role_binding: 0,
    audit_event: 0,
    owner_audit_event: 0,
    administrative_operation: 0,
};

/// [`Counts`] with `owner`'s rows. The recovery state is read through the
/// registry's [`get_recovery_state`]: the `0005` index
/// `recovery_state_single_row` allows one row at most, so its `Some` is the
/// count, and `owner`'s row is its bootstrap state (its instance ID and
/// recovery key, closed, epoch 1; the revision is not compared). The rest
/// is the only SQL of this module, read-only: the registry lists neither
/// policy rows, operators, audit events nor administrative operations, so
/// "these rows and no others" needs counts of them.
///
/// [`get_recovery_state`]: registry::get_recovery_state
async fn counts(pool: &PgPool, owner: &Ids) -> Counts {
    let state = registry::get_recovery_state(pool).await.unwrap();
    let owner_state = state.as_ref().is_some_and(|state| {
        state.instance_id == owner.instance_id
            && state.recovery_public_key == owner.recovery_public_key
            && state.bootstrap_closed
            && state.recovery_key_epoch == 1
    });
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM instance_security_policy) AS policy, \
                (SELECT count(*) FROM admin_identity) AS admin_identity, \
                (SELECT count(*) FROM admin_credential) AS admin_credential, \
                (SELECT count(*) FROM admin_role_binding) AS admin_role_binding, \
                (SELECT count(*) FROM audit_event) AS audit_event, \
                (SELECT count(*) FROM audit_event WHERE id = $2 AND object_id = $1 \
                    AND action = 'recovery_state.create') AS owner_audit_event, \
                (SELECT count(*) FROM administrative_operation) AS administrative_operation",
    )
    .bind(&owner.instance_id)
    .bind(&owner.audit_event_id)
    .fetch_one(pool)
    .await
    .unwrap();
    Counts {
        policy: row.get("policy"),
        recovery_state: i64::from(state.is_some()),
        owner_recovery_state: i64::from(owner_state),
        admin_identity: row.get("admin_identity"),
        admin_credential: row.get("admin_credential"),
        admin_role_binding: row.get("admin_role_binding"),
        audit_event: row.get("audit_event"),
        owner_audit_event: row.get("owner_audit_event"),
        administrative_operation: row.get("administrative_operation"),
    }
}

async fn verify(pool: &PgPool) -> ChainVerdict {
    registry::verify_audit_chain(&mut pool.acquire().await.unwrap())
        .await
        .unwrap()
}

async fn authorize(
    pool: &PgPool,
    key: &str,
    role: AdminRole,
) -> Result<Option<AuthorizedOperator>, RegistryError> {
    registry::authorize_operator(
        pool,
        &OperatorRequest {
            public_identity: key,
            scope: OperatorScope::Instance,
            role,
        },
    )
    .await
}

/// The three rows of the bootstrapped operator, as the getters read them.
#[derive(Debug, PartialEq, Eq)]
struct Operator {
    identity: AdminIdentity,
    credential: AdminCredential,
    binding: AdminRoleBinding,
}

async fn read_operator(pool: &PgPool, owner: &Ids) -> Operator {
    Operator {
        identity: registry::get_admin_identity(pool, &owner.admin_id)
            .await
            .unwrap(),
        credential: registry::get_admin_credential(pool, &owner.credential_id)
            .await
            .unwrap(),
        binding: registry::get_admin_role_binding(pool, &owner.binding_id)
            .await
            .unwrap(),
    }
}

/// `outcome` is `owner`'s bootstrap and the database holds exactly its
/// rows: the outcome's IDs read back through the getters as the enrolled,
/// enabled instance `security_admin`, which authorizes with exactly those
/// IDs; the policy row carries its instance ID; the event is its
/// `recovery_state.create` at sequence 1, and the chain is intact at 1.
async fn assert_only_owner(pool: &PgPool, owner: &Ids, outcome: &BootstrapOutcome) {
    assert_owner_after(pool, owner, outcome, 0).await;
}

/// [`assert_only_owner`] after `earlier` audit events that are not
/// bootstrap's: the event is at sequence `earlier + 1`, the only one of
/// bootstrap, and the chain is intact there.
async fn assert_owner_after(pool: &PgPool, owner: &Ids, outcome: &BootstrapOutcome, earlier: i64) {
    let sequence = earlier + 1;
    assert_eq!(
        (
            &outcome.instance_id[..],
            &outcome.admin_id[..],
            &outcome.credential_id[..],
            &outcome.binding_id[..],
            outcome.recovery_key_epoch,
        ),
        (
            &owner.instance_id[..],
            &owner.admin_id[..],
            &owner.credential_id[..],
            &owner.binding_id[..],
            1
        )
    );
    let event = &outcome.audit_event;
    assert_eq!(
        (
            &event.id[..],
            event.sequence,
            &event.action[..],
            &event.object_id[..],
            &event.actor,
        ),
        (
            &owner.audit_event_id[..],
            sequence,
            "recovery_state.create",
            &owner.instance_id[..],
            &AuditActor::Operator(DEPLOYMENT_OPERATOR_ACTOR.into()),
        )
    );
    assert_eq!(
        read_operator(pool, owner).await,
        Operator {
            identity: AdminIdentity {
                id: outcome.admin_id.clone(),
                status: Status::Enabled,
                created_at: now(),
            },
            credential: AdminCredential {
                id: outcome.credential_id.clone(),
                admin_id: outcome.admin_id.clone(),
                public_identity: owner.public_identity.clone(),
                trust_anchor_ref: owner.trust_anchor_ref.clone(),
                status: Status::Enabled,
                revoked_at: None,
            },
            binding: AdminRoleBinding {
                id: outcome.binding_id.clone(),
                admin_id: outcome.admin_id.clone(),
                role: AdminRole::SecurityAdmin,
                tenant_id: None,
                status: Status::Enabled,
                revision: 1,
            },
        }
    );
    assert_eq!(
        authorize(pool, &owner.public_identity, AdminRole::SecurityAdmin)
            .await
            .unwrap(),
        Some(AuthorizedOperator {
            admin_id: outcome.admin_id.clone(),
            credential_id: outcome.credential_id.clone(),
            binding_id: outcome.binding_id.clone(),
            role: AdminRole::SecurityAdmin,
        })
    );
    assert_eq!(
        registry::get_instance_security_policy(pool)
            .await
            .unwrap()
            .instance_id,
        owner.instance_id
    );
    assert_eq!(
        counts(pool, owner).await,
        Counts {
            audit_event: sequence,
            ..ONE
        }
    );
    assert_eq!(
        verify(pool).await,
        ChainVerdict::Intact {
            last_sequence: sequence
        }
    );
}

#[track_caller]
fn assert_not_found<T: std::fmt::Debug>(result: Result<T, RegistryError>, what: &str) {
    assert!(
        matches!(result, Err(RegistryError::NotFound)),
        "{what}: {result:?}"
    );
}

/// None of `other`'s rows exist, except those whose ID it shares with
/// `existing` (a colliding request), and its key authorizes no
/// `security_admin` unless it is `existing`'s.
async fn assert_absent(pool: &PgPool, other: &Ids, existing: &Ids) {
    if other.admin_id != existing.admin_id {
        assert_not_found(
            registry::get_admin_identity(pool, &other.admin_id).await,
            &other.admin_id,
        );
    }
    if other.credential_id != existing.credential_id {
        assert_not_found(
            registry::get_admin_credential(pool, &other.credential_id).await,
            &other.credential_id,
        );
    }
    if other.binding_id != existing.binding_id {
        assert_not_found(
            registry::get_admin_role_binding(pool, &other.binding_id).await,
            &other.binding_id,
        );
    }
    if other.public_identity != existing.public_identity {
        assert_eq!(
            authorize(pool, &other.public_identity, AdminRole::SecurityAdmin)
                .await
                .unwrap(),
            None,
            "{}",
            other.public_identity
        );
    }
}

/// Lowercase and uppercase hex of `bytes`.
fn hex(bytes: &[u8]) -> (String, String) {
    let lower: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let upper = lower.to_uppercase();
    (lower, upper)
}

/// Standard base64 with padding (RFC 4648 §4) and the URL-safe alphabet
/// without it (§5) of `bytes`.
fn base64(bytes: &[u8]) -> (String, String) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut standard = String::new();
    for chunk in bytes.chunks(3) {
        let group = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (group >> (18 - 6 * i)) & 0x3f;
                standard.push(char::from(ALPHABET[index as usize]));
            } else {
                standard.push('=');
            }
        }
    }
    let url = standard
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    (standard, url)
}

#[tokio::test]
async fn a32_pos_one_bootstrap_enrolls_one_operator_and_closes() {
    let (db, pool) = fixture().await;
    let first = ids(0);
    assert_eq!(counts(&pool, &first).await, NONE);
    assert_not_found(
        registry::get_instance_security_policy(&pool).await,
        "policy",
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 0 }
    );

    let outcome = bootstrap_on(&pool, &first.request()).await.unwrap();
    assert_only_owner(&pool, &first, &outcome).await;

    // The recovery key is not an operator key, in any form a caller might
    // present it, and neither is the instance ID.
    let key = &first.recovery_public_key[..];
    let (lower, upper) = hex(key);
    let (standard, url) = base64(key);
    assert_eq!(
        base64(b"\xfb\xff\x00"),
        ("+/8A".to_owned(), "-_8A".to_owned())
    );
    for form in [lower, upper, standard, url, first.instance_id.clone()] {
        assert_ne!(form, first.public_identity);
        for role in ROLES {
            assert_eq!(
                authorize(&pool, &form, role).await.unwrap(),
                None,
                "{form} {role}"
            );
        }
    }
    // The lookups changed nothing.
    assert_only_owner(&pool, &first, &outcome).await;
    db.drop([pool]).await;
}

/// 8 replicas, each a session of its own, released together by the
/// harness's barrier, each with a request that shares nothing with the
/// others' (instance ID included). In each of 3 fresh databases exactly
/// one bootstraps; the 7 others are `AlreadyClosed`, and the
/// database holds the winner's rows only. Which replica wins is not
/// asserted.
#[tokio::test(flavor = "multi_thread")]
async fn a32_neg_concurrent_bootstraps_across_replicas_have_one_winner() {
    const REPLICAS: usize = 8;
    const DATABASES: usize = 3;
    for round in 0..DATABASES {
        let (db, pool) = fixture().await;
        let base = round * REPLICAS;
        let replicas = Replicas::start(&db, REPLICAS).await;
        let outcomes = replicas
            .race(move |replica, mut conn| {
                let mine = ids(base + replica);
                async move { bootstrap(&mut conn, &mine.request()).await }
            })
            .await;
        assert_eq!(outcomes.len(), REPLICAS);
        let winners: Vec<usize> = (0..REPLICAS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        let winner = winners[0];
        let mut refusals = Vec::new();
        for (replica, outcome) in outcomes.iter().enumerate() {
            if replica != winner {
                refusals.push(closed_text(
                    outcome,
                    &format!("round {round}, replica {replica}"),
                ));
            }
        }
        assert_eq!(refusals, vec![CLOSED; REPLICAS - 1], "round {round}");

        let owner = ids(base + winner);
        let outcome = outcomes[winner].as_ref().unwrap();
        assert_only_owner(&pool, &owner, outcome).await;
        for replica in (0..REPLICAS).filter(|&r| r != winner) {
            assert_absent(&pool, &ids(base + replica), &owner).await;
        }
        db.drop(std::iter::once(pool).chain(replicas.into_pools()))
            .await;
    }
}

/// A holder session bootstraps in an open transaction; 4 replicas start
/// their own bootstraps, each sharing nothing with the holder's or the
/// others', and the harness sees all 4 blocked behind the holder
/// (`pg_blocking_pids`, transitively) before it ends. None finishes before
/// the holder ends. After the holder's commit all 4 are `AlreadyClosed`
/// and the state is the holder's; after its rollback
/// exactly one of the 4 bootstraps, the other 3 are `AlreadyClosed`, and
/// the state is that one's. Each in a fresh database.
#[tokio::test(flavor = "multi_thread")]
async fn a32_neg_blocked_bootstraps_follow_the_holder_commit_or_rollback() {
    const WAITERS: usize = 4;
    for commit in [true, false] {
        let (db, pool) = fixture().await;
        let holder_pool = db.pool_with_max_connections(1).await;
        let mut holder_conn = holder_pool.acquire().await.unwrap();
        let holder_pid = rep::backend_pid(&mut holder_conn).await;
        let waiters = Replicas::start(&db, WAITERS).await;
        let pids = waiters.backend_pids().await;

        let held = ids(100);
        let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
        let held_outcome = bootstrap_instance(&mut tx, &held.request()).await.unwrap();
        // Set just before the holder ends: a waiter that finished earlier
        // reads `false`.
        let ending = Arc::new(AtomicBool::new(false));
        let observer = &pool;
        let release = {
            let ending = Arc::clone(&ending);
            async move {
                rep::wait_until_blocked(observer, &pids, holder_pid).await;
                ending.store(true, Ordering::SeqCst);
                if commit {
                    tx.commit().await.unwrap();
                } else {
                    tx.rollback().await.unwrap();
                }
            }
        };
        let race = waiters.race({
            let ending = Arc::clone(&ending);
            move |replica, mut conn| {
                let mine = ids(replica);
                let ending = Arc::clone(&ending);
                async move {
                    let outcome = bootstrap(&mut conn, &mine.request()).await;
                    (outcome, ending.load(Ordering::SeqCst))
                }
            }
        });
        let (results, ()) = tokio::join!(race, release);
        drop(holder_conn);

        let mut outcomes = Vec::new();
        for (replica, (outcome, after_holder)) in results.into_iter().enumerate() {
            assert!(
                after_holder,
                "commit {commit}: replica {replica} finished before the holder ended: {outcome:?}"
            );
            outcomes.push(outcome);
        }
        let winners: Vec<usize> = (0..WAITERS).filter(|&r| outcomes[r].is_ok()).collect();
        let owner = if commit {
            assert_eq!(winners, Vec::<usize>::new(), "{outcomes:?}");
            assert_only_owner(&pool, &held, &held_outcome).await;
            held.clone()
        } else {
            assert_eq!(winners.len(), 1, "{outcomes:?}");
            let owner = ids(winners[0]);
            assert_only_owner(&pool, &owner, outcomes[winners[0]].as_ref().unwrap()).await;
            assert_absent(&pool, &held, &owner).await;
            owner
        };
        let refusals: Vec<String> = (0..WAITERS)
            .filter(|r| !winners.contains(r))
            .map(|r| closed_text(&outcomes[r], &format!("commit {commit}, replica {r}")))
            .collect();
        assert_eq!(refusals.len(), WAITERS - winners.len(), "commit {commit}");
        assert!(refusals.iter().all(|text| text == CLOSED), "{refusals:?}");
        for replica in (0..WAITERS).filter(|r| !winners.contains(r)) {
            assert_absent(&pool, &ids(replica), &owner).await;
        }
        let pools = [pool, holder_pool].into_iter().chain(waiters.into_pools());
        db.drop(pools).await;
    }
}

/// One change to the bootstrapped operator, through the registry's own
/// mutators; `Enrolled` changes nothing.
#[derive(Debug, Clone, Copy)]
enum Lever {
    Enrolled,
    DisableIdentity,
    RevokeCredential,
    DisableBinding,
}

impl Lever {
    async fn pull(self, pool: &PgPool, operator: &mut Operator) {
        match self {
            Lever::Enrolled => {}
            Lever::DisableIdentity => {
                operator.identity = registry::disable_admin_identity(pool, &operator.identity.id)
                    .await
                    .unwrap();
                assert_eq!(operator.identity.status, Status::Disabled);
            }
            Lever::RevokeCredential => {
                operator.credential =
                    registry::revoke_admin_credential(pool, &operator.credential.id, now())
                        .await
                        .unwrap();
                assert_eq!(
                    (operator.credential.status, operator.credential.revoked_at),
                    (Status::Disabled, Some(now()))
                );
            }
            Lever::DisableBinding => {
                operator.binding = registry::test_support::update_admin_role_binding(
                    pool,
                    &operator.binding.id,
                    operator.binding.revision,
                    &AdminRoleBindingChanges {
                        status: Status::Disabled,
                    },
                )
                .await
                .unwrap();
                assert_eq!(
                    (operator.binding.status, operator.binding.revision),
                    (Status::Disabled, 2)
                );
            }
        }
    }
}

/// Valid requests against a closed bootstrap whose operator is `first`:
/// the same request, one with new IDs (instance ID included), and ones with
/// new IDs except the existing admin ID, the existing credential key or the
/// existing audit event ID. `step` keeps each call's new IDs apart.
fn attempts(first: &Ids, step: usize) -> Vec<(&'static str, Ids)> {
    let fresh = |i| ids(1000 + 10 * step + i);
    let mut admin = fresh(1);
    admin.admin_id = first.admin_id.clone();
    let mut key = fresh(2);
    key.public_identity = first.public_identity.clone();
    let mut event = fresh(3);
    event.audit_event_id = first.audit_event_id.clone();
    vec![
        ("the same request", first.clone()),
        ("new IDs", fresh(0)),
        ("the existing admin ID", admin),
        ("the existing credential key", key),
        ("the existing audit event ID", event),
    ]
}

/// Runs every attempt of [`attempts`] and checks that each is
/// `AlreadyClosed` and that nothing changed: `first`'s counts, its
/// operator as `expected`, the policy row and the chain.
async fn assert_stays_closed(pool: &PgPool, first: &Ids, expected: &Operator, step: usize) {
    let mut refusals = Vec::new();
    for (what, attempt) in attempts(first, step) {
        let what = format!("step {step}: {what}");
        let result = bootstrap_on(pool, &attempt.request()).await;
        refusals.push(closed_text(&result, &what));
        assert_eq!(counts(pool, first).await, ONE, "{what}");
        assert_eq!(&read_operator(pool, first).await, expected, "{what}");
        assert_absent(pool, &attempt, first).await;
        assert_eq!(
            registry::get_instance_security_policy(pool)
                .await
                .unwrap()
                .instance_id,
            first.instance_id,
            "{what}"
        );
        assert_eq!(
            verify(pool).await,
            ChainVerdict::Intact { last_sequence: 1 },
            "{what}"
        );
    }
    assert_eq!(refusals, vec![CLOSED; 5], "step {step}");
}

/// After a bootstrap, with its operator as enrolled and then after each
/// lever (identity disabled, credential revoked, binding disabled, pulled
/// one after another, so the instance ends without an authorized
/// `security_admin`), every valid request is `AlreadyClosed` and
/// writes nothing, those that reuse an existing ID or key included: the
/// closure check comes first, so a collision never surfaces as
/// `AlreadyExists` (the registry's documented behaviour, #78; see the
/// module docs). On a fresh pool it is still closed. The revoked key
/// cannot be registered as another operator's credential: the `0005` rule
/// `admin_credential_public_identity_key`, inferred there (registry
/// behaviour, not the spec's; the registry tests cover it too, see the
/// module docs).
///
/// No failure-then-retry case is folded in: a first attempt that fails
/// alone (an audit event ID or an operator ID taken before bootstrap) and
/// leaves bootstrap open after the rollback is
/// `a_failed_audit_append_leaves_nothing_after_rollback` and
/// `collisions_of_caller_ids_stay_already_exists` in
/// `service/tests/registry_bootstrap.rs`, through the same public API; a
/// copy here would add nothing. What the scenario adds, a failed audit
/// append or a lost store while replicas wait behind it, is
/// `a32_neg_a_bootstrap_failing_at_its_audit_append_writes_nothing`.
#[tokio::test]
async fn a32_neg_a_closed_bootstrap_is_never_reopened() {
    let (db, pool) = fixture().await;
    let first = ids(0);
    let outcome = bootstrap_on(&pool, &first.request()).await.unwrap();
    assert_only_owner(&pool, &first, &outcome).await;
    let mut operator = read_operator(&pool, &first).await;

    for (step, lever) in [
        Lever::Enrolled,
        Lever::DisableIdentity,
        Lever::RevokeCredential,
        Lever::DisableBinding,
    ]
    .into_iter()
    .enumerate()
    {
        lever.pull(&pool, &mut operator).await;
        assert_eq!(read_operator(&pool, &first).await, operator, "{lever:?}");
        let found = authorize(&pool, &first.public_identity, AdminRole::SecurityAdmin)
            .await
            .unwrap();
        assert_eq!(
            found.is_some(),
            matches!(lever, Lever::Enrolled),
            "{lever:?}"
        );
        assert_stays_closed(&pool, &first, &operator, step).await;
    }

    // A fresh pool, as after a restart on the same database: still closed.
    pool.close().await;
    let pool = db.pool().await;
    assert_stays_closed(&pool, &first, &operator, 4).await;

    // The revoked key cannot be registered for another operator: the
    // inferred `0005` rule (see the module docs), not a spec requirement.
    let mut tx = pool.begin().await.unwrap();
    registry::test_support::create_admin_identity(
        &mut *tx,
        &NewAdminIdentity {
            id: "adm_a32_other".into(),
            status: Status::Enabled,
            created_at: now(),
        },
    )
    .await
    .unwrap();
    let again = registry::test_support::create_admin_credential(
        &mut *tx,
        &NewAdminCredential {
            id: "crd_a32_other".into(),
            admin_id: "adm_a32_other".into(),
            public_identity: first.public_identity.clone(),
            trust_anchor_ref: first.trust_anchor_ref.clone(),
            status: Status::Enabled,
        },
    )
    .await;
    assert!(
        matches!(
            again,
            Err(RegistryError::AlreadyExists {
                constraint: "admin_credential_public_identity_key"
            })
        ),
        "{again:?}"
    );
    tx.rollback().await.unwrap();
    assert_eq!(counts(&pool, &first).await, ONE);
    assert_eq!(read_operator(&pool, &first).await, operator);
    db.drop([pool]).await;
}

// A failing audit append and a lost store (T13.6: "missing store/audit"),
// for a bootstrap and for a restore that waits at its audit append with
// replicas waiting behind it.

/// How the claimant, the call that waits at its audit append, fails there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendFailure {
    /// Its event ID is the one the head holder appended, and the holder
    /// commits: the append is the writer's `AlreadyExists` on
    /// `audit_event_pkey`. Its caller keeps the transaction open until the
    /// waiters have finished and then commits after the `Err`, which the
    /// registry allows (its savepoint is rolled back on every `Err`).
    TakenEventId,
    /// Its backend is terminated while it waits: the store is gone, and the
    /// call is a store error. The head holder then rolls back.
    LostStore,
}

/// The event ID the head holder appends.
const HELD_EVENT_ID: &str = "aud_a32_held";

/// The SQLSTATE a session terminated by `pg_terminate_backend` reports.
const ADMIN_SHUTDOWN: &str = "57P01";

/// The event the head holder appends: one that is neither bootstrap's nor
/// a recovery's.
fn held_event() -> NewAuditEvent {
    NewAuditEvent {
        id: HELD_EVENT_ID.into(),
        tenant_id: None,
        timestamp: now(),
        actor: AuditActor::System,
        action: "instance_security_policy.mirror".into(),
        object_id: "a32_held_object".into(),
        previous_revision: None,
        new_revision: None,
        outcome: "success".into(),
    }
}

/// `err`, the store error of a call that failed at its append, is
/// `failure`'s: `AlreadyExists` on `audit_event_pkey`, or the terminated
/// session's `57P01`; matched by variant and SQLSTATE, not by text.
#[track_caller]
fn assert_append_failure(failure: AppendFailure, err: &RegistryError, what: &str) {
    match failure {
        AppendFailure::TakenEventId => assert!(
            matches!(
                err,
                RegistryError::AlreadyExists {
                    constraint: "audit_event_pkey"
                }
            ),
            "{what}: {err:?}"
        ),
        AppendFailure::LostStore => {
            let code = match err {
                RegistryError::Other(err) => err
                    .as_database_error()
                    .and_then(|db| db.code())
                    .map(|code| code.into_owned()),
                _ => None,
            };
            assert_eq!(code.as_deref(), Some(ADMIN_SHUTDOWN), "{what}: {err:?}");
        }
    }
}

/// Ends the claimant's transaction after its call: on
/// [`AppendFailure::TakenEventId`] (`commit_after` is `Some`) it waits,
/// within [`rep::DEADLINE`], until the waiters have all finished, so they
/// finished while it was still open, and then commits; on a lost store its
/// session is gone and the transaction is dropped.
async fn end_claim(tx: Transaction<'_, Postgres>, commit_after: Option<oneshot::Receiver<()>>) {
    if let Some(raced) = commit_after {
        tokio::time::timeout(rep::DEADLINE, raced)
            .await
            .expect("the waiters did not finish within the deadline")
            .expect("the race ended without finishing");
        tx.commit().await.unwrap();
    }
}

/// What [`fail_at_append`] observed.
struct AppendFailed<C, W> {
    /// The claimant's outcome.
    claimed: C,
    /// Each waiter's outcome, and whether it finished after the head
    /// holder began to end.
    waited: Vec<(W, bool)>,
    /// The head holder's event, committed on
    /// [`AppendFailure::TakenEventId`] only.
    held: AuditEvent,
    /// The pools to close.
    pools: Vec<PgPool>,
}

/// A head holder, a session of its own, appends [`held_event`] in an open
/// transaction, so it holds the audit chain head. The claimant, on a
/// session of its own, runs `claim` (its call, then [`end_claim`]), and
/// the harness sees it blocked behind the holder, at its append. Then `waiters` replicas run `work`, and the
/// harness sees them all blocked behind the holder, through the claimant.
/// Then, for [`AppendFailure::TakenEventId`], the holder commits, so the
/// claimant's append fails; for [`AppendFailure::LostStore`], the
/// claimant's backend is terminated, the harness sees the waiters blocked
/// behind the holder again (one of them now waits for the head), and the
/// holder rolls back. Every wait is bounded by [`rep::DEADLINE`].
async fn fail_at_append<C, CF, CT, W, WF, WT>(
    db: &TestDb,
    observer: &PgPool,
    failure: AppendFailure,
    waiters: usize,
    claim: C,
    work: W,
) -> AppendFailed<CT, WT>
where
    C: FnOnce(PoolConnection<Postgres>, Option<oneshot::Receiver<()>>) -> CF,
    CF: Future<Output = CT> + Send + 'static,
    CT: Send + 'static,
    W: Fn(usize, PoolConnection<Postgres>) -> WF + Send + Sync + 'static,
    WF: Future<Output = WT> + Send + 'static,
    WT: Send + 'static,
{
    let head_pool = db.pool_with_max_connections(1).await;
    let mut head_conn = head_pool.acquire().await.unwrap();
    let head_pid = rep::backend_pid(&mut head_conn).await;
    let claimant_pool = db.pool_with_max_connections(1).await;
    let mut claimant_conn = claimant_pool.acquire().await.unwrap();
    let claimant_pid = rep::backend_pid(&mut claimant_conn).await;
    let replicas = Replicas::start(db, waiters).await;
    let pids = replicas.backend_pids().await;

    let mut head = Connection::begin(&mut *head_conn).await.unwrap();
    let held = registry::test_support::append_audit_event(&mut head, &held_event())
        .await
        .unwrap();
    let (raced, raced_rx) = oneshot::channel();
    let commit_after = (failure == AppendFailure::TakenEventId).then_some(raced_rx);
    let claimant = tokio::spawn(claim(claimant_conn, commit_after));
    rep::wait_until_blocked(observer, &[claimant_pid], head_pid).await;

    // Set just before the holder begins to end: a waiter that finished
    // earlier reads `false`.
    let ending = Arc::new(AtomicBool::new(false));
    let release = {
        let ending = Arc::clone(&ending);
        async move {
            rep::wait_until_blocked(observer, &pids, head_pid).await;
            ending.store(true, Ordering::SeqCst);
            match failure {
                AppendFailure::TakenEventId => head.commit().await.unwrap(),
                AppendFailure::LostStore => {
                    rep::terminate(observer, claimant_pid).await;
                    rep::wait_until_blocked(observer, &pids, head_pid).await;
                    head.rollback().await.unwrap();
                }
            }
        }
    };
    let race = async {
        let waited = replicas
            .race({
                let ending = Arc::clone(&ending);
                move |replica, conn| {
                    let ending = Arc::clone(&ending);
                    let work = work(replica, conn);
                    async move {
                        let outcome = work.await;
                        (outcome, ending.load(Ordering::SeqCst))
                    }
                }
            })
            .await;
        // The claimant's transaction is still open here.
        let _ = raced.send(());
        waited
    };
    let (waited, ()) = tokio::join!(race, release);
    let claimed = tokio::time::timeout(rep::DEADLINE, claimant)
        .await
        .expect("the claimant did not finish within the deadline")
        .unwrap();
    drop(head_conn);
    let pools = [head_pool, claimant_pool]
        .into_iter()
        .chain(replicas.into_pools())
        .collect();
    AppendFailed {
        claimed,
        waited,
        held,
        pools,
    }
}

/// Each waiter's outcome, after checking that it finished only after the
/// head holder began to end.
#[track_caller]
fn after_the_holder<T: std::fmt::Debug>(waited: Vec<(T, bool)>, what: &str) -> Vec<T> {
    let mut outcomes = Vec::new();
    for (replica, (outcome, after_holder)) in waited.into_iter().enumerate() {
        assert!(
            after_holder,
            "{what}: replica {replica} finished before the holder ended: {outcome:?}"
        );
        outcomes.push(outcome);
    }
    outcomes
}

/// A bootstrap that fails at its audit append, its last step (after its
/// writes, by the registry's documented order, which this test does not
/// observe), writes nothing and leaves bootstrap open, in two fresh databases: once with
/// its event ID taken by an event committed while it waits for the head
/// (`AlreadyExists` on `audit_event_pkey`; its caller commits after the
/// `Err`, once the waiters have finished), once with its session
/// terminated while it waits (a store error, `57P01`). 4 replicas that
/// bootstrap with requests sharing nothing with it or with each other are
/// seen blocked behind it; after its failure exactly one of them
/// bootstraps, the 3 others are `AlreadyClosed`, and the state is the
/// winner's alone: its event directly after the committed one, or first,
/// and the chain intact. With its event ID taken, the waiters finish while
/// the failed claimant's transaction is still open: a failed bootstrap
/// keeps bootstrap claimed for no one until its caller ends the
/// transaction. (PostgreSQL releases what the failed statement's
/// subtransaction held when the statement fails, so this holds with or
/// without the registry's own savepoint rollback, and the commit after the
/// `Err` writes nothing either way. Without that rollback, sqlx's `Drop`
/// only queues `ROLLBACK TO SAVEPOINT` for the connection's next use, so
/// after an error in Rust, with no failed statement, the head lock would
/// stay held until the caller's next statement; that case is the service
/// tests'.)
#[tokio::test(flavor = "multi_thread")]
async fn a32_neg_a_bootstrap_failing_at_its_audit_append_writes_nothing() {
    const WAITERS: usize = 4;
    for failure in [AppendFailure::TakenEventId, AppendFailure::LostStore] {
        let what = format!("{failure:?}");
        let (db, pool) = fixture().await;
        let mut failing = ids(100);
        if failure == AppendFailure::TakenEventId {
            failing.audit_event_id = HELD_EVENT_ID.into();
        }
        let claim = {
            let failing = failing.clone();
            move |mut conn: PoolConnection<Postgres>, commit_after| async move {
                let mut tx = Connection::begin(&mut *conn).await.unwrap();
                let outcome = bootstrap_instance(&mut tx, &failing.request()).await;
                end_claim(tx, commit_after).await;
                outcome
            }
        };
        let failed = fail_at_append(
            &db,
            &pool,
            failure,
            WAITERS,
            claim,
            |replica, mut conn| async move { bootstrap(&mut conn, &ids(replica).request()).await },
        )
        .await;
        match &failed.claimed {
            Err(BootstrapError::Store(err)) => assert_append_failure(failure, err, &what),
            other => panic!("{what}: expected a store error: {other:?}"),
        }

        let outcomes = after_the_holder(failed.waited, &what);
        let winners: Vec<usize> = (0..WAITERS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "{what}: {outcomes:?}");
        let winner = winners[0];
        let refusals: Vec<String> = (0..WAITERS)
            .filter(|&r| r != winner)
            .map(|r| closed_text(&outcomes[r], &format!("{what}, replica {r}")))
            .collect();
        assert_eq!(refusals, vec![CLOSED; WAITERS - 1], "{what}");

        let owner = ids(winner);
        let outcome = outcomes[winner].as_ref().unwrap();
        let taken = failure == AppendFailure::TakenEventId;
        assert_owner_after(&pool, &owner, outcome, i64::from(taken)).await;
        assert_eq!(
            outcome.audit_event.prev_hash,
            taken.then_some(failed.held.hash),
            "{what}"
        );
        assert_absent(&pool, &failing, &owner).await;
        for replica in (0..WAITERS).filter(|&r| r != winner) {
            assert_absent(&pool, &ids(replica), &owner).await;
        }
        db.drop(std::iter::once(pool).chain(failed.pools)).await;
    }
}

// Registry-level recovery (T13.5): `issue_recovery_challenge`,
// `preview_recovery_response`, `restore_operator` and `get_recovery_state`,
// after a bootstrap.

/// The prefix of `M`, the bytes the recovery key signs: `M` is this prefix
/// followed by `C`, the canonical JSON of the challenge (`registry::recovery`
/// "What is signed").
const CHALLENGE_PREFIX: &[u8] = b"skyoauth.recovery_challenge.v1\n";

/// The prefix of the request digest, `SHA-256(prefix || C)`: a signature
/// over `C` under it is not one over `M`.
const DIGEST_PREFIX: &[u8] = b"skyoauth.administrative_operation.v1\n";

/// The `Debug` text of a restore refused for `reason`.
fn refused(reason: NotRestorableReason) -> String {
    format!("Err(NotRestorable({reason:?}))")
}

/// The issue time of a challenge: a second after bootstrap. Whole
/// seconds, so no stored time is truncated.
fn issued_at() -> SystemTime {
    now() + Duration::from_secs(1)
}

/// The restore time: a second after the issue, well inside every TTL.
fn restored_at() -> SystemTime {
    now() + Duration::from_secs(2)
}

/// `time` in whole microseconds since the Unix epoch, as `C` carries
/// `expires_at`.
fn micros(time: SystemTime) -> i64 {
    i64::try_from(time.duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap()
}

/// The material of one recovery, owned: the challenge the service binary
/// would ask for (its operation and what its plan binds: the instance and
/// the epoch of the key that signs, and the recovery state's revision it
/// expects), the replacement its plan names, the key that signs, the
/// response once the challenge is issued, and the restore's event IDs.
#[derive(Debug, Clone)]
struct Recovery {
    operation_id: String,
    issue_event_id: String,
    instance_id: String,
    recovery_key_epoch: i64,
    expected_revision: i64,
    admin_id: String,
    credential_id: String,
    binding_id: String,
    public_identity: String,
    trust_anchor_ref: String,
    /// The private half of the new recovery key: it signs the challenges
    /// of the next epoch once this recovery has restored.
    new_recovery_key: SigningKey,
    new_recovery_public_key: Vec<u8>,
    /// The recovery key of `recovery_key_epoch`, which signs this
    /// challenge, as the offline workstation would.
    signer: SigningKey,
    /// `M` as [`issue`] returned it; empty before the issue.
    challenge: Vec<u8>,
    /// The response's signature: the signer's over `challenge`, set by
    /// [`issue`]; empty before the issue.
    signature: Vec<u8>,
    restore_event_id: String,
    rotation_event_id: String,
}

/// Valid recovery material number `n` for `first`'s instance at `epoch`,
/// signed by `signer`, the recovery key of that epoch, sharing nothing with
/// any other `n` or with any bootstrap of [`ids`]: a replacement with IDs
/// and a key of its own, and a new recovery key pair of its own
/// ([`test_key`]). The expected revision is the epoch: bootstrap writes
/// both as 1 and every restore advances both by one, and nothing else here
/// changes the recovery state.
fn recovery(n: usize, first: &Ids, epoch: i64, signer: &SigningKey) -> Recovery {
    let new_recovery_key = test_key(b"a32 new recovery key....", n);
    let recovery = Recovery {
        operation_id: format!("op_a32_restore_{n}"),
        issue_event_id: format!("aud_a32_issue_{n}"),
        instance_id: first.instance_id.clone(),
        recovery_key_epoch: epoch,
        expected_revision: epoch,
        admin_id: format!("adm_a32_restored_{n}"),
        credential_id: format!("crd_a32_restored_{n}"),
        binding_id: format!("rb_a32_restored_{n}"),
        public_identity: format!("spki-sha256:a32-restored-{n}"),
        trust_anchor_ref: "deployment/operator-ca".into(),
        new_recovery_public_key: public_key(&new_recovery_key),
        new_recovery_key,
        signer: signer.clone(),
        challenge: Vec::new(),
        signature: Vec::new(),
        restore_event_id: format!("aud_a32_restore_{n}"),
        rotation_event_id: format!("aud_a32_rotate_{n}"),
    };
    assert_eq!(
        recovery.new_recovery_public_key.len(),
        registry::RECOVERY_PUBLIC_KEY_LENGTH
    );
    recovery
}

/// `bytes` in lowercase hexadecimal, the plan's form of a key.
fn lower_hex(bytes: &[u8]) -> String {
    hex(bytes).0
}

/// `key`'s Ed25519 signature over `message`, 64 bytes.
fn sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    key.sign(message).to_bytes().to_vec()
}

impl Recovery {
    /// The plan the signer approves, with the member names of
    /// identity-registry section 5.2 written out, not taken from the
    /// registry's constants.
    fn plan(&self) -> JsonObject {
        match json!({
            "instance_id": self.instance_id,
            "recovery_key_epoch": self.recovery_key_epoch,
            "admin_id": self.admin_id,
            "credential_id": self.credential_id,
            "binding_id": self.binding_id,
            "public_identity": self.public_identity,
            "trust_anchor_ref": self.trust_anchor_ref,
            "new_recovery_public_key": lower_hex(&self.new_recovery_public_key),
        }) {
            Value::Object(plan) => plan,
            other => unreachable!("{other}"),
        }
    }

    fn issue_request<'a>(
        &'a self,
        plan: &'a JsonObject,
        ttl: Duration,
        at: SystemTime,
    ) -> IssueChallenge<'a> {
        IssueChallenge {
            operation_id: &self.operation_id,
            kind: OPERATOR_RESTORATION,
            immutable_plan: plan,
            ttl,
            now: at,
            audit_event_id: &self.issue_event_id,
        }
    }

    /// The signed response the workstation returns for this challenge.
    fn response(&self) -> SignedRecoveryResponse<'_> {
        SignedRecoveryResponse {
            operation_id: &self.operation_id,
            signature: &self.signature,
        }
    }

    /// The restore's event IDs and `now`, `at`.
    fn request(&self, at: SystemTime) -> RestoreRequest<'_> {
        RestoreRequest {
            audit_event_id: &self.restore_event_id,
            rotation_audit_event_id: &self.rotation_event_id,
            now: at,
        }
    }

    /// The same challenge and response with event IDs of their own,
    /// numbered `n`, as another replica's attempt would carry.
    fn with_events(&self, n: usize) -> Recovery {
        Recovery {
            restore_event_id: format!("{}_{n}", self.restore_event_id),
            rotation_event_id: format!("{}_{n}", self.rotation_event_id),
            ..self.clone()
        }
    }

    /// The same challenge with `signature` in its response.
    fn with_signature(&self, signature: Vec<u8>) -> Recovery {
        Recovery {
            signature,
            ..self.clone()
        }
    }
}

/// Issues in a transaction of its own: commits on `Ok`, rolls back on
/// every `Err`, as the caller of `issue_recovery_challenge` must.
async fn issue_on(
    pool: &PgPool,
    request: &IssueChallenge<'_>,
) -> Result<RecoveryChallenge, ChallengeError> {
    let mut tx = pool.begin().await.unwrap();
    let issued = registry::issue_recovery_challenge(&mut tx, request).await;
    match issued {
        Ok(_) => tx.commit().await.unwrap(),
        Err(_) => tx.rollback().await.unwrap(),
    }
    issued
}

/// Issues `recovery`'s challenge with `ttl` at `at`, and signs the `M` it
/// returns with `recovery`'s signer, as the workstation would: the
/// signature is `recovery`'s response from then on.
async fn issue(
    pool: &PgPool,
    recovery: &mut Recovery,
    ttl: Duration,
    at: SystemTime,
) -> RecoveryChallenge {
    let plan = recovery.plan();
    let challenge = issue_on(pool, &recovery.issue_request(&plan, ttl, at))
        .await
        .unwrap();
    recovery.signature = sign(&recovery.signer, &challenge.challenge);
    recovery.challenge.clone_from(&challenge.challenge);
    challenge
}

/// Restores `recovery`'s response at `at` in a transaction of its own on
/// `conn` (`READ COMMITTED`, the session default): commits on `Ok` and
/// rolls back on every `Err`, as the caller of `restore_operator` must.
async fn restore(
    conn: &mut PgConnection,
    recovery: &Recovery,
    at: SystemTime,
) -> Result<Restored, RestoreError> {
    let mut tx = conn.begin().await.unwrap();
    let restored = restore_operator(&mut tx, &recovery.response(), &recovery.request(at)).await;
    match restored {
        Ok(_) => tx.commit().await.unwrap(),
        Err(_) => tx.rollback().await.unwrap(),
    }
    restored
}

async fn restore_on(
    pool: &PgPool,
    recovery: &Recovery,
    at: SystemTime,
) -> Result<Restored, RestoreError> {
    restore(&mut pool.acquire().await.unwrap(), recovery, at).await
}

/// Previews `recovery`'s response at `at` in a transaction of its own,
/// which it commits whatever the outcome: a preview grants nothing and
/// writes nothing, even when its caller commits.
async fn preview_on(
    pool: &PgPool,
    recovery: &Recovery,
    at: SystemTime,
) -> Result<RecoveryPreview, RestoreError> {
    let mut tx = pool.begin().await.unwrap();
    let preview = registry::preview_recovery_response(&mut tx, &recovery.response(), at).await;
    tx.commit().await.unwrap();
    preview
}

/// `result` is `NotRestorable` for `reason`, matched by variant and
/// reason; returns its `Debug` text ([`refused`]) for the callers' tallies
/// of refusals.
#[track_caller]
fn not_restorable_text<T: std::fmt::Debug>(
    result: &Result<T, RestoreError>,
    reason: NotRestorableReason,
    what: &str,
) -> String {
    match result {
        Err(RestoreError::NotRestorable(found)) if *found == reason => {}
        other => panic!("{what}: expected NotRestorable({reason:?}): {other:?}"),
    }
    let text = format!("{result:?}");
    assert_eq!(text, refused(reason), "{what}");
    text
}

/// What the registry API shows of the recovery: [`counts`], the recovery
/// state and the audit chain. A refusal that "writes nothing" leaves it
/// equal; that it left the challenge unconsumed is shown by the restore of
/// that challenge that each test ends with.
#[derive(Debug, PartialEq)]
struct State {
    counts: Counts,
    recovery_state: Option<RecoveryState>,
    chain: ChainVerdict,
}

async fn state(pool: &PgPool, first: &Ids) -> State {
    State {
        counts: counts(pool, first).await,
        recovery_state: registry::get_recovery_state(pool).await.unwrap(),
        chain: verify(pool).await,
    }
}

/// The recovery state that `first`'s bootstrap writes.
fn bootstrap_state(first: &Ids) -> RecoveryState {
    RecoveryState {
        instance_id: first.instance_id.clone(),
        bootstrap_closed: true,
        recovery_public_key: first.recovery_public_key.clone(),
        recovery_key_epoch: 1,
        revision: 1,
    }
}

/// Bootstraps `first` on an empty database and checks it, as the bootstrap
/// tests above do.
async fn bootstrapped(pool: &PgPool, first: &Ids) {
    let outcome = bootstrap_on(pool, &first.request()).await.unwrap();
    assert_only_owner(pool, first, &outcome).await;
    assert_eq!(
        registry::get_recovery_state(pool).await.unwrap(),
        Some(bootstrap_state(first))
    );
}

/// The issued challenge is `recovery`'s, issued at `at` with `ttl` as the
/// event at `sequence`: `expires_at` is `at + ttl`, the expected revision
/// the recovery state's, and the event is `administrative_operation.create`
/// by `deployment_operator` with the operation as its object.
#[track_caller]
fn assert_issued(
    challenge: &RecoveryChallenge,
    recovery: &Recovery,
    ttl: Duration,
    at: SystemTime,
    sequence: i64,
) {
    let event = &challenge.audit_event;
    assert_eq!(
        (
            &challenge.operation_id[..],
            challenge.expires_at,
            challenge.expected_revision,
            &event.id[..],
            event.sequence,
            event.timestamp,
            &event.actor,
            &event.action[..],
            &event.object_id[..],
            event.previous_revision,
            event.new_revision,
        ),
        (
            &recovery.operation_id[..],
            at + ttl,
            recovery.expected_revision,
            &recovery.issue_event_id[..],
            sequence,
            at,
            &AuditActor::Operator(DEPLOYMENT_OPERATOR_ACTOR.into()),
            "administrative_operation.create",
            &recovery.operation_id[..],
            None,
            Some(1),
        )
    );
    // `M`, what the workstation displays and signs: the prefix, then `C`,
    // which binds exactly the operation, its plan (the instance, the epoch
    // and the replacement), the expected revision and the expiry, as
    // canonical JSON (members sorted byte-wise at every level, no
    // whitespace: `serde_json`'s map is sorted, so re-encoding the parsed
    // value gives the same bytes back).
    let (prefix, canonical) = challenge.challenge.split_at(CHALLENGE_PREFIX.len());
    assert_eq!(prefix, CHALLENGE_PREFIX);
    let parsed: Value = serde_json::from_slice(canonical).unwrap();
    assert_eq!(
        parsed,
        json!({
            "actor_id": "deployment_operator",
            "expected_revision": recovery.expected_revision,
            "expires_at": micros(at + ttl),
            "id": recovery.operation_id,
            "kind": "operator_restoration",
            "plan": recovery.plan(),
            "tenant_id": null,
        })
    );
    assert_eq!(serde_json::to_vec(&parsed).unwrap(), canonical);
}

/// `restored` is `recovery`'s restore at `at`: the outcome names the plan's
/// replacement and the next epoch and revision; its two events are
/// `admin_identity.restore` (the new operator) and right after it
/// `recovery_state.rotate_key` (the instance, the revision before and
/// after), both by `recovery_key:<epoch>` of the key that signed and each
/// hashing as the chain does; the replacement reads back as an enabled
/// instance `security_admin` that authorizes with exactly the plan's IDs;
/// and the recovery state holds the plan's new key at the next epoch.
async fn assert_restored(pool: &PgPool, recovery: &Recovery, restored: &Restored, at: SystemTime) {
    let epoch = recovery.recovery_key_epoch;
    let revision = recovery.expected_revision;
    assert_eq!(
        (
            &restored.admin_id[..],
            &restored.credential_id[..],
            &restored.binding_id[..],
            restored.recovery_key_epoch,
            restored.recovery_state_revision,
        ),
        (
            &recovery.admin_id[..],
            &recovery.credential_id[..],
            &recovery.binding_id[..],
            epoch + 1,
            revision + 1,
        )
    );
    let actor = AuditActor::Operator(format!("recovery_key:{epoch}"));
    let (event, rotation) = (&restored.audit_event, &restored.rotation_audit_event);
    assert_eq!(
        (
            &event.id[..],
            event.tenant_id.as_deref(),
            event.timestamp,
            &event.actor,
            &event.action[..],
            &event.object_id[..],
            event.previous_revision,
            event.new_revision,
        ),
        (
            &recovery.restore_event_id[..],
            None,
            at,
            &actor,
            "admin_identity.restore",
            &recovery.admin_id[..],
            None,
            None,
        )
    );
    assert_eq!(
        (
            &rotation.id[..],
            rotation.tenant_id.as_deref(),
            rotation.sequence,
            rotation.prev_hash,
            rotation.timestamp,
            &rotation.actor,
            &rotation.action[..],
            &rotation.object_id[..],
            rotation.previous_revision,
            rotation.new_revision,
        ),
        (
            &recovery.rotation_event_id[..],
            None,
            event.sequence + 1,
            Some(event.hash),
            at,
            &actor,
            "recovery_state.rotate_key",
            &recovery.instance_id[..],
            Some(revision),
            Some(revision + 1),
        )
    );
    assert_eq!(event.compute_hash().unwrap(), event.hash);
    assert_eq!(rotation.compute_hash().unwrap(), rotation.hash);
    assert_eq!(
        (
            registry::get_admin_identity(pool, &recovery.admin_id)
                .await
                .unwrap(),
            registry::get_admin_credential(pool, &recovery.credential_id)
                .await
                .unwrap(),
            registry::get_admin_role_binding(pool, &recovery.binding_id)
                .await
                .unwrap(),
        ),
        (
            AdminIdentity {
                id: recovery.admin_id.clone(),
                status: Status::Enabled,
                created_at: at,
            },
            AdminCredential {
                id: recovery.credential_id.clone(),
                admin_id: recovery.admin_id.clone(),
                public_identity: recovery.public_identity.clone(),
                trust_anchor_ref: recovery.trust_anchor_ref.clone(),
                status: Status::Enabled,
                revoked_at: None,
            },
            AdminRoleBinding {
                id: recovery.binding_id.clone(),
                admin_id: recovery.admin_id.clone(),
                role: AdminRole::SecurityAdmin,
                tenant_id: None,
                status: Status::Enabled,
                revision: 1,
            },
        )
    );
    assert_eq!(
        authorize(pool, &recovery.public_identity, AdminRole::SecurityAdmin)
            .await
            .unwrap(),
        Some(AuthorizedOperator {
            admin_id: recovery.admin_id.clone(),
            credential_id: recovery.credential_id.clone(),
            binding_id: recovery.binding_id.clone(),
            role: AdminRole::SecurityAdmin,
        })
    );
    assert_eq!(
        registry::get_recovery_state(pool).await.unwrap(),
        Some(RecoveryState {
            instance_id: recovery.instance_id.clone(),
            bootstrap_closed: true,
            recovery_public_key: recovery.new_recovery_public_key.clone(),
            recovery_key_epoch: epoch + 1,
            revision: revision + 1,
        })
    );
}

/// None of `recovery`'s replacement exists and its key authorizes no role.
async fn assert_not_enrolled(pool: &PgPool, recovery: &Recovery) {
    assert_not_found(
        registry::get_admin_identity(pool, &recovery.admin_id).await,
        &recovery.admin_id,
    );
    assert_not_found(
        registry::get_admin_credential(pool, &recovery.credential_id).await,
        &recovery.credential_id,
    );
    assert_not_found(
        registry::get_admin_role_binding(pool, &recovery.binding_id).await,
        &recovery.binding_id,
    );
    for role in ROLES {
        assert_eq!(
            authorize(pool, &recovery.public_identity, role)
                .await
                .unwrap(),
            None,
            "{} {role}",
            recovery.public_identity
        );
    }
}

/// Every bootstrap attempt of [`attempts`] after a recovery is
/// `AlreadyClosed` and changes nothing the registry shows: a restore does
/// not reopen bootstrap.
async fn assert_bootstrap_stays_closed(pool: &PgPool, first: &Ids, step: usize) {
    let before = state(pool, first).await;
    let mut refusals = Vec::new();
    for (what, attempt) in attempts(first, step) {
        let what = format!("after a restore, step {step}: {what}");
        refusals.push(closed_text(
            &bootstrap_on(pool, &attempt.request()).await,
            &what,
        ));
        assert_eq!(state(pool, first).await, before, "{what}");
        assert_absent(pool, &attempt, first).await;
    }
    assert_eq!(refusals, vec![CLOSED; 5], "step {step}");
}

/// The recovery after a bootstrap, end to end through the registry API, in
/// two fresh databases: once with the bootstrapped operator enrolled and
/// with a second credential, and once with that operator locked out (its
/// identity disabled, its first credential revoked, its binding disabled,
/// so no key authorizes a `security_admin`): restoration does not depend
/// on an operator. In both, the challenge is issued as the event after
/// bootstrap and changes no authority; its `M` (see [`assert_issued`]) is
/// signed with the bootstrap recovery key, as the workstation would, and a
/// preview of that response, committed, names the plan's replacement, the
/// next epoch and the expiry and grants nothing; the restore verifies the
/// signature and enrolls exactly the
/// replacement the plan names, which authorizes; every operator credential
/// still unrevoked is revoked at the restore's `now` (one revoked before
/// keeps its time), and no old key authorizes any role; the old identity
/// and binding are as they were (identity-registry section 5.2: a
/// restoration disables no identity and no role assignment); the recovery
/// key is rotated to the plan's at epoch 2; the three events are the issue,
/// the restore and the rotation, linked in that order, and the chain is
/// intact at 4; and bootstrap stays closed, also on a fresh pool.
#[tokio::test]
async fn a32_pos_signed_recovery_restores_a_replacement_operator() {
    for locked_out in [false, true] {
        let (db, pool) = fixture().await;
        let first = ids(0);
        bootstrapped(&pool, &first).await;
        let second = NewAdminCredential {
            id: format!("{}_second", first.credential_id),
            admin_id: first.admin_id.clone(),
            public_identity: format!("{}-second", first.public_identity),
            trust_anchor_ref: first.trust_anchor_ref.clone(),
            status: Status::Enabled,
        };
        registry::test_support::create_admin_credential(&pool, &second)
            .await
            .unwrap();
        let mut operator = read_operator(&pool, &first).await;
        if locked_out {
            for lever in [
                Lever::DisableIdentity,
                Lever::RevokeCredential,
                Lever::DisableBinding,
            ] {
                lever.pull(&pool, &mut operator).await;
            }
        }
        let old_keys = [&first.public_identity, &second.public_identity];
        for key in old_keys {
            assert_eq!(
                authorize(&pool, key, AdminRole::SecurityAdmin)
                    .await
                    .unwrap()
                    .is_some(),
                !locked_out,
                "locked out {locked_out}: {key}"
            );
        }

        let mut recovery = recovery(0, &first, 1, &first.recovery_key);
        let challenge = issue(&pool, &mut recovery, DEFAULT_CHALLENGE_TTL, issued_at()).await;
        assert_issued(&challenge, &recovery, DEFAULT_CHALLENGE_TTL, issued_at(), 2);
        let issued = State {
            counts: Counts {
                admin_credential: 2,
                audit_event: 2,
                administrative_operation: 1,
                ..ONE
            },
            recovery_state: Some(bootstrap_state(&first)),
            chain: ChainVerdict::Intact { last_sequence: 2 },
        };
        assert_eq!(state(&pool, &first).await, issued);
        // The challenge alone changes no authority.
        assert_not_enrolled(&pool, &recovery).await;
        assert_eq!(read_operator(&pool, &first).await, operator);
        // Nor does a preview of the signed response, committed.
        let preview = preview_on(&pool, &recovery, restored_at()).await.unwrap();
        assert_eq!(
            (
                &preview.admin_id[..],
                &preview.credential_id[..],
                &preview.binding_id[..],
                preview.new_recovery_key_epoch,
                preview.expires_at,
            ),
            (
                &recovery.admin_id[..],
                &recovery.credential_id[..],
                &recovery.binding_id[..],
                2,
                challenge.expires_at,
            )
        );
        assert_eq!(state(&pool, &first).await, issued);
        assert_not_enrolled(&pool, &recovery).await;
        assert_eq!(read_operator(&pool, &first).await, operator);

        let restored = restore_on(&pool, &recovery, restored_at()).await.unwrap();
        assert_restored(&pool, &recovery, &restored, restored_at()).await;
        assert_eq!(
            (
                restored.audit_event.sequence,
                restored.audit_event.prev_hash
            ),
            (3, Some(challenge.audit_event.hash))
        );
        let mut revoked = vec![second.id.clone()];
        if !locked_out {
            revoked.push(first.credential_id.clone());
        }
        revoked.sort();
        assert_eq!(restored.revoked_credential_ids, revoked);
        let first_revoked_at = if locked_out { now() } else { restored_at() };
        for (id, revoked_at) in [
            (&first.credential_id, first_revoked_at),
            (&second.id, restored_at()),
        ] {
            let credential = registry::get_admin_credential(&pool, id).await.unwrap();
            assert_eq!(
                (credential.status, credential.revoked_at),
                (Status::Disabled, Some(revoked_at)),
                "locked out {locked_out}: {id}"
            );
        }
        for key in old_keys {
            for role in ROLES {
                assert_eq!(
                    authorize(&pool, key, role).await.unwrap(),
                    None,
                    "locked out {locked_out}: {key} {role}"
                );
            }
        }
        assert_eq!(
            (
                registry::get_admin_identity(&pool, &first.admin_id)
                    .await
                    .unwrap(),
                registry::get_admin_role_binding(&pool, &first.binding_id)
                    .await
                    .unwrap(),
            ),
            (operator.identity.clone(), operator.binding.clone())
        );
        let restored_state = State {
            counts: Counts {
                owner_recovery_state: 0,
                admin_identity: 2,
                admin_credential: 3,
                admin_role_binding: 2,
                audit_event: 4,
                administrative_operation: 1,
                ..ONE
            },
            recovery_state: registry::get_recovery_state(&pool).await.unwrap(),
            chain: ChainVerdict::Intact { last_sequence: 4 },
        };
        assert_eq!(state(&pool, &first).await, restored_state);
        assert_bootstrap_stays_closed(&pool, &first, 0).await;

        // A fresh pool, as after a restart on the same database.
        pool.close().await;
        let pool = db.pool().await;
        assert_eq!(state(&pool, &first).await, restored_state);
        assert_eq!(
            authorize(&pool, &recovery.public_identity, AdminRole::SecurityAdmin)
                .await
                .unwrap()
                .map(|found| found.credential_id),
            Some(recovery.credential_id.clone())
        );
        assert_bootstrap_stays_closed(&pool, &first, 1).await;
        db.drop([pool]).await;
    }
}

/// A recovery is never replayed. Two challenges are issued at epoch 1 and
/// signed by the bootstrap recovery key. A restore of the first whose
/// transaction rolls back leaves nothing and the challenge restorable, and
/// its retry restores (the uncertain-commit rule: a restore that did not
/// commit restores). After that restore, each replay is `NotRestorable`
/// and changes nothing the registry shows, on the pool that restored and on
/// a fresh one: the identical response and request (the retry of a restore
/// whose commit was uncertain), the same response later with event IDs of
/// its own and the same challenge signed by the rotated key are
/// `Consumed`; the second challenge (issued before the rotation, so for the
/// retired key), signed by the retired key or by the rotated one, is
/// `NotBound`: its plan names the retired epoch. No challenge can be issued
/// for the retired epoch any more (`NotIssuable`). A challenge of epoch 2,
/// signed by the key the first restore rotated to, then restores, revokes
/// the first replacement and is recorded by `recovery_key:2`, and the first
/// challenge signed by the key of epoch 3 is `Consumed` too.
#[tokio::test]
async fn a32_neg_a_replayed_recovery_is_refused() {
    use NotRestorableReason::{Consumed, NotBound};
    let (db, pool) = fixture().await;
    let first = ids(0);
    bootstrapped(&pool, &first).await;
    let mut used = recovery(1, &first, 1, &first.recovery_key);
    let mut stale = recovery(2, &first, 1, &first.recovery_key);
    issue(&pool, &mut used, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    issue(&pool, &mut stale, DEFAULT_CHALLENGE_TTL, issued_at()).await;

    let issued = state(&pool, &first).await;
    let mut tx = pool.begin().await.unwrap();
    restore_operator(&mut tx, &used.response(), &used.request(restored_at()))
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(state(&pool, &first).await, issued);
    assert_not_enrolled(&pool, &used).await;
    let restored = restore_on(&pool, &used, restored_at()).await.unwrap();
    assert_restored(&pool, &used, &restored, restored_at()).await;
    let after = state(&pool, &first).await;
    assert_eq!(after.chain, ChainVerdict::Intact { last_sequence: 5 });

    // The key `used` rotated to, the current one now.
    let rotated = &used.new_recovery_key;
    let later = restored_at() + Duration::from_secs(1);
    let replays = [
        (
            "the identical response and request",
            used.clone(),
            restored_at(),
            Consumed,
        ),
        (
            "later, with event IDs of its own",
            used.with_events(1),
            later,
            Consumed,
        ),
        (
            "signed by the rotated key",
            used.with_signature(sign(rotated, &used.challenge)),
            later,
            Consumed,
        ),
        (
            "a challenge of the retired epoch",
            stale.clone(),
            later,
            NotBound,
        ),
        (
            "a challenge of the retired epoch, signed by the rotated key",
            stale.with_signature(sign(rotated, &stale.challenge)),
            later,
            NotBound,
        ),
    ];
    let retired = recovery(5, &first, 1, &first.recovery_key);
    for fresh in [false, true] {
        let pool = if fresh { db.pool().await } else { pool.clone() };
        let mut refusals = Vec::new();
        for (what, replay, at, reason) in &replays {
            let what = format!("fresh pool {fresh}: {what}");
            refusals.push(not_restorable_text(
                &restore_on(&pool, replay, *at).await,
                *reason,
                &what,
            ));
            assert_eq!(state(&pool, &first).await, after, "{what}");
        }
        assert_eq!(
            refusals,
            replays
                .iter()
                .map(|(_, _, _, reason)| refused(*reason))
                .collect::<Vec<_>>(),
            "{fresh}"
        );
        let plan = retired.plan();
        let refused = issue_on(
            &pool,
            &retired.issue_request(&plan, DEFAULT_CHALLENGE_TTL, later),
        )
        .await;
        assert!(
            matches!(refused, Err(ChallengeError::NotIssuable)),
            "{refused:?}"
        );
        assert_eq!(state(&pool, &first).await, after, "fresh pool {fresh}");
        assert_eq!(
            authorize(&pool, &used.public_identity, AdminRole::SecurityAdmin)
                .await
                .unwrap()
                .map(|found| found.credential_id),
            Some(used.credential_id.clone())
        );
        assert_not_enrolled(&pool, &stale).await;
        if fresh {
            pool.close().await;
        }
    }

    let mut next = recovery(6, &first, 2, rotated);
    let next_issued = issued_at() + Duration::from_secs(10);
    let next_at = restored_at() + Duration::from_secs(10);
    issue(&pool, &mut next, DEFAULT_CHALLENGE_TTL, next_issued).await;
    let again = restore_on(&pool, &next, next_at).await.unwrap();
    assert_restored(&pool, &next, &again, next_at).await;
    assert_eq!(
        again.revoked_credential_ids,
        vec![used.credential_id.clone()]
    );
    for role in ROLES {
        assert_eq!(
            authorize(&pool, &used.public_identity, role).await.unwrap(),
            None
        );
    }
    let at_three = used
        .with_events(2)
        .with_signature(sign(&next.new_recovery_key, &used.challenge));
    let restored_twice = state(&pool, &first).await;
    assert_eq!(
        restored_twice.chain,
        ChainVerdict::Intact { last_sequence: 8 }
    );
    not_restorable_text(
        &restore_on(&pool, &at_three, next_at).await,
        Consumed,
        "the first challenge signed by the key of epoch 3",
    );
    assert_eq!(state(&pool, &first).await, restored_twice);
    assert_bootstrap_stays_closed(&pool, &first, 0).await;
    db.drop([pool]).await;
}

/// `signature` with `S` replaced by `S + L`, `L` the order of the Ed25519
/// base point: the same equation holds, so a verifier that does not
/// require `S < L` accepts the malleated signature.
fn malleate(signature: &[u8]) -> Vec<u8> {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut out = signature.to_vec();
    let mut carry = 0_u16;
    for (byte, add) in out[32..].iter_mut().zip(L) {
        let sum = u16::from(*byte) + u16::from(add) + carry;
        *byte = u8::try_from(sum & 0xff).unwrap();
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// One change to the `C` of a challenge, as parsed JSON.
type Tamper = fn(&mut Value);

/// `m`, a challenge's `M`, with `tamper` applied to its `C`, re-encoded
/// as `C` is (see [`assert_issued`]).
fn tampered(m: &[u8], tamper: Tamper) -> Vec<u8> {
    let mut canonical: Value = serde_json::from_slice(&m[CHALLENGE_PREFIX.len()..]).unwrap();
    tamper(&mut canonical);
    let out = [CHALLENGE_PREFIX, &serde_json::to_vec(&canonical).unwrap()].concat();
    assert_ne!(out, m);
    out
}

/// A restore must be exactly the one its challenge names, signed by the
/// current recovery key over that challenge's `M`. Two challenges, A and B,
/// are issued at epoch 1, each naming a replacement of its own, and signed
/// with the bootstrap recovery key. A's response is `NotRestorable` with
/// `BadSignature`, changes nothing the registry shows and enrolls nothing,
/// and its preview is refused alike, when its signature:
///
/// - is over A's challenge with one member of `C` changed, as a signer
///   shown another plan would sign: any one of the six replacement members
///   (`admin_id`, `credential_id`, `binding_id`, `public_identity`,
///   `trust_anchor_ref`, `new_recovery_public_key`), the instance, the
///   epoch, the operation ID, the expected revision or the expiry;
/// - is over other bytes: B's `M` (A's ID with B's signature), `C` without
///   the prefix, or `C` under the request-digest prefix;
/// - is by another key over A's `M`: A's plan's new key, B's, or a key of
///   its own;
/// - is A's own signature altered: one bit flipped in `R` or in `S`, `S`
///   replaced by `S + L` (malleated), or all zeros;
///
/// and B's ID with A's signature is `BadSignature` too. A's signature under
/// an operation ID that names no challenge is `NotFound`; a challenge for
/// another instance is not issued. After all that, A's exact response
/// restores: no refusal consumed it. B is then `NotRestorable` too, even
/// exact: its plan names the epoch A's restore retired (`NotBound`).
///
/// Every response here is what a caller can hand the public path; that the
/// stored row itself (its plan, digest or hash) cannot be changed, and that
/// a row whose stored digest or hash is not the library's encoding is
/// refused, needs rows written by other means and is
/// `service/tests/registry_recovery.rs`'s (`a_tampered_plan_is_refused`).
#[tokio::test]
async fn a32_neg_a_restore_must_be_the_one_its_challenge_names() {
    use NotRestorableReason::{BadSignature, NotBound, NotFound};
    let (db, pool) = fixture().await;
    let first = ids(0);
    bootstrapped(&pool, &first).await;
    let key = &first.recovery_key;
    let mut a = recovery(1, &first, 1, key);
    let mut b = recovery(2, &first, 1, key);
    issue(&pool, &mut a, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    issue(&pool, &mut b, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    let issued = state(&pool, &first).await;

    let tampers: [(&str, Tamper); 11] = [
        ("admin_id", |c| {
            c["plan"]["admin_id"] = json!("adm_a32_tampered")
        }),
        ("credential_id", |c| {
            c["plan"]["credential_id"] = json!("crd_a32_tampered");
        }),
        ("binding_id", |c| {
            c["plan"]["binding_id"] = json!("rb_a32_tampered");
        }),
        ("public_identity", |c| {
            c["plan"]["public_identity"] = json!("spki-sha256:a32-tampered");
        }),
        ("trust_anchor_ref", |c| {
            c["plan"]["trust_anchor_ref"] = json!("deployment/tampered-ca");
        }),
        ("new_recovery_public_key", |c| {
            let stranger = public_key(&test_key(b"a32 tampered recovery...", 0));
            c["plan"]["new_recovery_public_key"] = json!(lower_hex(&stranger));
        }),
        ("instance", |c| {
            c["plan"]["instance_id"] = json!(ids(9).instance_id)
        }),
        ("epoch", |c| c["plan"]["recovery_key_epoch"] = json!(2)),
        ("operation ID", |c| {
            c["id"] = json!("op_a32_restore_unknown")
        }),
        ("expected revision", |c| c["expected_revision"] = json!(2)),
        ("expiry", |c| {
            let expires_at = c["expires_at"].as_i64().unwrap();
            c["expires_at"] = json!(expires_at + 1);
        }),
    ];
    let mut attempts: Vec<(String, Recovery, NotRestorableReason)> = tampers
        .iter()
        .map(|(what, tamper)| {
            (
                format!("A signed over its challenge with its {what} changed"),
                a.with_signature(sign(key, &tampered(&a.challenge, *tamper))),
                BadSignature,
            )
        })
        .collect();
    let canonical = &a.challenge[CHALLENGE_PREFIX.len()..];
    let mut flipped_r = a.signature.clone();
    flipped_r[0] ^= 1;
    let mut flipped_s = a.signature.clone();
    flipped_s[40] ^= 0x10;
    let stranger = test_key(b"a32 stranger key........", 0);
    for (what, signature) in [
        ("A with B's signature", b.signature.clone()),
        ("A signed over C without the prefix", sign(key, canonical)),
        (
            "A signed over C under the request-digest prefix",
            sign(key, &[DIGEST_PREFIX, canonical].concat()),
        ),
        (
            "A signed by its plan's new key",
            sign(&a.new_recovery_key, &a.challenge),
        ),
        (
            "A signed by B's plan's new key",
            sign(&b.new_recovery_key, &a.challenge),
        ),
        (
            "A signed by a key of its own",
            sign(&stranger, &a.challenge),
        ),
        ("A with a bit of R flipped", flipped_r),
        ("A with a bit of S flipped", flipped_s),
        ("A with S + L", malleate(&a.signature)),
        ("A with a signature of zeros", vec![0; 64]),
    ] {
        attempts.push((what.into(), a.with_signature(signature), BadSignature));
    }
    attempts.push((
        "B with A's signature".into(),
        b.with_signature(a.signature.clone()),
        BadSignature,
    ));
    attempts.push((
        "A's signature for an operation ID that names no challenge".into(),
        Recovery {
            operation_id: "op_a32_restore_unknown".into(),
            ..a.clone()
        },
        NotFound,
    ));
    let mut refusals = Vec::new();
    for (what, attempt, reason) in &attempts {
        assert_eq!(attempt.signature.len(), 64, "{what}");
        not_restorable_text(
            &preview_on(&pool, attempt, restored_at()).await,
            *reason,
            &format!("preview: {what}"),
        );
        refusals.push(not_restorable_text(
            &restore_on(&pool, attempt, restored_at()).await,
            *reason,
            what,
        ));
        assert_eq!(state(&pool, &first).await, issued, "{what}");
        assert_not_enrolled(&pool, &a).await;
        assert_not_enrolled(&pool, &b).await;
    }
    assert_eq!(
        refusals,
        attempts
            .iter()
            .map(|(_, _, reason)| refused(*reason))
            .collect::<Vec<_>>()
    );

    let elsewhere = Recovery {
        instance_id: ids(9).instance_id,
        ..recovery(3, &first, 1, key)
    };
    let plan = elsewhere.plan();
    let refused = issue_on(
        &pool,
        &elsewhere.issue_request(&plan, DEFAULT_CHALLENGE_TTL, issued_at()),
    )
    .await;
    assert!(
        matches!(refused, Err(ChallengeError::NotIssuable)),
        "{refused:?}"
    );
    assert_eq!(state(&pool, &first).await, issued);

    let restored = restore_on(&pool, &a, restored_at()).await.unwrap();
    assert_restored(&pool, &a, &restored, restored_at()).await;
    assert_eq!(
        restored.revoked_credential_ids,
        vec![first.credential_id.clone()]
    );
    let after = state(&pool, &first).await;
    assert_eq!(after.chain, ChainVerdict::Intact { last_sequence: 5 });
    not_restorable_text(
        &restore_on(&pool, &b, restored_at()).await,
        NotBound,
        "B after A",
    );
    assert_eq!(state(&pool, &first).await, after);
    assert_not_enrolled(&pool, &b).await;
    db.drop([pool]).await;
}

/// A challenge expires at `expires_at`, compared with the caller's `now`
/// (the registry reads no clock). Three restorations in a row, each from
/// a challenge of the then current epoch, issued with the shortest, the
/// default and the longest TTL ([`MIN_CHALLENGE_TTL`],
/// [`DEFAULT_CHALLENGE_TTL`], [`MAX_CHALLENGE_TTL`]): each challenge's
/// `expires_at` is its issue time plus its TTL; a restore at `expires_at`,
/// a microsecond after it and a longest TTL after it is `NotRestorable`
/// (`Expired`) and changes nothing; the restore a microsecond before it,
/// signed by the key of the then current epoch, restores, at the
/// next epoch, recorded by the key of the epoch before. The chain ends
/// intact at 10, at epoch 4, with only the last replacement authorized.
/// The three TTLs are checked first: 5 and 15 minutes are LT-107 and
/// OQ-LT-17, the 1-second minimum a lead ruling (provisional).
///
/// That the restore a microsecond before `expires_at` succeeds after the
/// refusal at `expires_at` is registry behaviour, not the spec's: the
/// refusal wrote nothing and is not final, because only the caller's `now`
/// is compared, and a `now` before the issue time is accepted too. LT-107's
/// "the challenge expires" holds only with `now` taken from the service
/// binary's own clock (T13.3), which A64's hermetic leg tests with
/// injected clocks (see the module docs).
#[tokio::test]
async fn a32_neg_an_expired_challenge_is_refused() {
    // 5 and 15 minutes: LT-107, OQ-LT-17; 1 s: lead ruling, provisional.
    assert_eq!(
        (MIN_CHALLENGE_TTL, DEFAULT_CHALLENGE_TTL, MAX_CHALLENGE_TTL),
        (
            Duration::from_secs(1),
            Duration::from_secs(5 * 60),
            Duration::from_secs(15 * 60)
        )
    );
    let (db, pool) = fixture().await;
    let first = ids(0);
    bootstrapped(&pool, &first).await;
    let mut restored = Vec::new();
    // The recovery key of the current epoch: bootstrap's, then each
    // restore's new one.
    let mut signer = first.recovery_key.clone();
    for (cycle, ttl) in [MIN_CHALLENGE_TTL, DEFAULT_CHALLENGE_TTL, MAX_CHALLENGE_TTL]
        .into_iter()
        .enumerate()
    {
        let epoch = i64::try_from(cycle).unwrap() + 1;
        let mut recovery = recovery(cycle, &first, epoch, &signer);
        let at = now() + Duration::from_secs(3600 * (u64::try_from(cycle).unwrap() + 1));
        let challenge = issue(&pool, &mut recovery, ttl, at).await;
        assert_issued(&challenge, &recovery, ttl, at, 3 * epoch - 1);
        let expires_at = challenge.expires_at;
        let before = state(&pool, &first).await;
        for late in [
            expires_at,
            expires_at + Duration::from_micros(1),
            expires_at + MAX_CHALLENGE_TTL,
        ] {
            not_restorable_text(
                &restore_on(&pool, &recovery, late).await,
                NotRestorableReason::Expired,
                &format!("{ttl:?} at {late:?}"),
            );
            assert_eq!(state(&pool, &first).await, before, "{ttl:?} at {late:?}");
        }
        assert_not_enrolled(&pool, &recovery).await;
        let last = expires_at - Duration::from_micros(1);
        let outcome = restore_on(&pool, &recovery, last).await.unwrap();
        assert_restored(&pool, &recovery, &outcome, last).await;
        signer = recovery.new_recovery_key.clone();
        restored.push(recovery);
    }
    assert_eq!(
        state(&pool, &first).await,
        State {
            counts: Counts {
                owner_recovery_state: 0,
                admin_identity: 4,
                admin_credential: 4,
                admin_role_binding: 4,
                audit_event: 10,
                administrative_operation: 3,
                ..ONE
            },
            recovery_state: registry::get_recovery_state(&pool).await.unwrap(),
            chain: ChainVerdict::Intact { last_sequence: 10 },
        }
    );
    for (index, recovery) in restored.iter().enumerate() {
        let found = authorize(&pool, &recovery.public_identity, AdminRole::SecurityAdmin)
            .await
            .unwrap();
        assert_eq!(found.is_some(), index == restored.len() - 1, "{index}");
    }
    db.drop([pool]).await;
}

/// The session defaults of a replica whose transactions do not run at
/// `READ COMMITTED`, as a misconfigured replica's would.
const OTHER_ISOLATION: [(&str, &str); 3] = [
    (
        "REPEATABLE READ",
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ",
    ),
    (
        "SERIALIZABLE",
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE",
    ),
    (
        "READ UNCOMMITTED",
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ UNCOMMITTED",
    ),
];

/// A restore runs only at `READ COMMITTED` (lead ruling,
/// `registry::recovery` "READ COMMITTED only"). Three replicas whose
/// sessions default to `REPEATABLE READ`, `SERIALIZABLE` and
/// `READ UNCOMMITTED` (which PostgreSQL runs as `READ COMMITTED`, and which
/// the registry refuses by name) each try the one challenge: each is
/// `UnsupportedIsolation`; its transaction stays usable (the registry
/// reads the recovery state in it), and a caller that commits after the
/// refusal anyway commits nothing. The last replica, switched to
/// `READ COMMITTED`, then restores the same challenge: no refusal consumed
/// it.
#[tokio::test]
async fn a32_neg_a_restore_outside_read_committed_writes_nothing() {
    let (db, pool) = fixture().await;
    let first = ids(0);
    bootstrapped(&pool, &first).await;
    let mut recovery = recovery(1, &first, 1, &first.recovery_key);
    issue(&pool, &mut recovery, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    let issued = state(&pool, &first).await;
    let mut replicas = Vec::new();
    for (level, set) in OTHER_ISOLATION {
        let replica = db.pool_with_max_connections(1).await;
        let mut conn = replica.acquire().await.unwrap();
        sqlx::query(set).execute(&mut *conn).await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        match restore_operator(
            &mut tx,
            &recovery.response(),
            &recovery.request(restored_at()),
        )
        .await
        {
            Err(err @ RestoreError::UnsupportedIsolation) => {
                assert_eq!(format!("{err:?}"), "UnsupportedIsolation", "{level}");
            }
            other => panic!("{level}: expected UnsupportedIsolation: {other:?}"),
        }
        assert_eq!(
            registry::get_recovery_state(&mut *tx).await.unwrap(),
            Some(bootstrap_state(&first)),
            "{level}"
        );
        tx.commit().await.unwrap();
        drop(conn);
        assert_eq!(state(&pool, &first).await, issued, "{level}");
        assert_not_enrolled(&pool, &recovery).await;
        replicas.push(replica);
    }

    let last = replicas.last().unwrap();
    let mut conn = last.acquire().await.unwrap();
    sqlx::query("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *conn)
        .await
        .unwrap();
    let restored = restore(&mut conn, &recovery, restored_at()).await.unwrap();
    drop(conn);
    assert_restored(&pool, &recovery, &restored, restored_at()).await;
    assert_eq!(
        restored.revoked_credential_ids,
        vec![first.credential_id.clone()]
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 4 }
    );
    db.drop(std::iter::once(pool).chain(replicas)).await;
}

/// 8 replicas, each a session of its own, released together by the
/// harness's barrier, restore at once, in 4 fresh databases: in two, all 8
/// restore the one issued challenge (the same replacement, event IDs of
/// their own); in the other two, each restores a challenge of its own, all
/// issued at epoch 1. In each database exactly one restores and the 7
/// others are `NotRestorable`: a challenge is consumed once (`Consumed`),
/// and one restoration retires the epoch the others are bound to
/// (`NotBound`). The state is the
/// winner's: its replacement, the key at epoch 2, its two events after the
/// issues and nothing of the losers'. Which replica wins is not asserted.
#[tokio::test(flavor = "multi_thread")]
async fn a32_neg_concurrent_restores_across_replicas_have_one_winner() {
    const REPLICAS: usize = 8;
    for (round, shared) in [true, true, false, false].into_iter().enumerate() {
        let (db, pool) = fixture().await;
        let first = ids(0);
        bootstrapped(&pool, &first).await;
        let base = round * REPLICAS;
        let mine: Vec<Recovery> = if shared {
            let mut one = recovery(base, &first, 1, &first.recovery_key);
            issue(&pool, &mut one, DEFAULT_CHALLENGE_TTL, issued_at()).await;
            (0..REPLICAS).map(|r| one.with_events(r)).collect()
        } else {
            let mut each: Vec<Recovery> = (0..REPLICAS)
                .map(|r| recovery(base + r, &first, 1, &first.recovery_key))
                .collect();
            for recovery in &mut each {
                issue(&pool, recovery, DEFAULT_CHALLENGE_TTL, issued_at()).await;
            }
            each
        };
        // A loser finds the one challenge consumed, or its own bound to
        // the epoch the winner retired.
        let lost = if shared {
            NotRestorableReason::Consumed
        } else {
            NotRestorableReason::NotBound
        };
        let issues = if shared { 1 } else { REPLICAS };
        let replicas = Replicas::start(&db, REPLICAS).await;
        let outcomes = replicas
            .race({
                let mine = mine.clone();
                move |replica, mut conn| {
                    let recovery = mine[replica].clone();
                    async move { restore(&mut conn, &recovery, restored_at()).await }
                }
            })
            .await;
        assert_eq!(outcomes.len(), REPLICAS);
        let winners: Vec<usize> = (0..REPLICAS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        let winner = winners[0];
        let refusals: Vec<String> = (0..REPLICAS)
            .filter(|&r| r != winner)
            .map(|r| {
                not_restorable_text(&outcomes[r], lost, &format!("round {round}, replica {r}"))
            })
            .collect();
        assert_eq!(refusals, vec![refused(lost); REPLICAS - 1], "round {round}");

        let outcome = outcomes[winner].as_ref().unwrap();
        assert_restored(&pool, &mine[winner], outcome, restored_at()).await;
        assert_eq!(
            outcome.revoked_credential_ids,
            vec![first.credential_id.clone()]
        );
        let issues = i64::try_from(issues).unwrap();
        assert_eq!(
            state(&pool, &first).await,
            State {
                counts: Counts {
                    owner_recovery_state: 0,
                    admin_identity: 2,
                    admin_credential: 2,
                    admin_role_binding: 2,
                    audit_event: 1 + issues + 2,
                    administrative_operation: issues,
                    ..ONE
                },
                recovery_state: registry::get_recovery_state(&pool).await.unwrap(),
                chain: ChainVerdict::Intact {
                    last_sequence: 1 + issues + 2
                },
            },
            "round {round}"
        );
        if !shared {
            for replica in (0..REPLICAS).filter(|&r| r != winner) {
                assert_not_enrolled(&pool, &mine[replica]).await;
            }
        }
        db.drop(std::iter::once(pool).chain(replicas.into_pools()))
            .await;
    }
}

/// A holder session restores the one issued challenge in an open
/// transaction; 4 replicas start restores of the same challenge (event IDs
/// of their own), and the harness sees all 4 blocked behind the holder
/// (`pg_blocking_pids`, transitively) before it ends. None finishes before
/// the holder ends. After the holder's commit all 4 are `NotRestorable`
/// (`Consumed`) and the state is the holder's; after its rollback exactly
/// one of the 4 restores, the other 3 are `NotRestorable` (`Consumed`), and
/// the state is that one's.
/// Each in a fresh database.
#[tokio::test(flavor = "multi_thread")]
async fn a32_neg_blocked_restores_follow_the_holder_commit_or_rollback() {
    const WAITERS: usize = 4;
    for commit in [true, false] {
        let (db, pool) = fixture().await;
        let first = ids(0);
        bootstrapped(&pool, &first).await;
        let mut held = recovery(1, &first, 1, &first.recovery_key);
        issue(&pool, &mut held, DEFAULT_CHALLENGE_TTL, issued_at()).await;
        let holder_pool = db.pool_with_max_connections(1).await;
        let mut holder_conn = holder_pool.acquire().await.unwrap();
        let holder_pid = rep::backend_pid(&mut holder_conn).await;
        let waiters = Replicas::start(&db, WAITERS).await;
        let pids = waiters.backend_pids().await;

        let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
        let held_outcome =
            restore_operator(&mut tx, &held.response(), &held.request(restored_at()))
                .await
                .unwrap();
        // Set just before the holder ends: a waiter that finished earlier
        // reads `false`.
        let ending = Arc::new(AtomicBool::new(false));
        let observer = &pool;
        let release = {
            let ending = Arc::clone(&ending);
            async move {
                rep::wait_until_blocked(observer, &pids, holder_pid).await;
                ending.store(true, Ordering::SeqCst);
                if commit {
                    tx.commit().await.unwrap();
                } else {
                    tx.rollback().await.unwrap();
                }
            }
        };
        let mine: Vec<Recovery> = (0..WAITERS).map(|r| held.with_events(r)).collect();
        let race = waiters.race({
            let ending = Arc::clone(&ending);
            let mine = mine.clone();
            move |replica, mut conn| {
                let recovery = mine[replica].clone();
                let ending = Arc::clone(&ending);
                async move {
                    let outcome = restore(&mut conn, &recovery, restored_at()).await;
                    (outcome, ending.load(Ordering::SeqCst))
                }
            }
        });
        let (results, ()) = tokio::join!(race, release);
        drop(holder_conn);

        let mut outcomes = Vec::new();
        for (replica, (outcome, after_holder)) in results.into_iter().enumerate() {
            assert!(
                after_holder,
                "commit {commit}: replica {replica} finished before the holder ended: {outcome:?}"
            );
            outcomes.push(outcome);
        }
        let winners: Vec<usize> = (0..WAITERS).filter(|&r| outcomes[r].is_ok()).collect();
        let (owner, outcome) = if commit {
            assert_eq!(winners, Vec::<usize>::new(), "{outcomes:?}");
            (&held, &held_outcome)
        } else {
            assert_eq!(winners.len(), 1, "{outcomes:?}");
            let winner = winners[0];
            (&mine[winner], outcomes[winner].as_ref().unwrap())
        };
        assert_restored(&pool, owner, outcome, restored_at()).await;
        assert_eq!(
            outcome.revoked_credential_ids,
            vec![first.credential_id.clone()],
            "commit {commit}"
        );
        let refusals: Vec<String> = (0..WAITERS)
            .filter(|r| !winners.contains(r))
            .map(|r| {
                not_restorable_text(
                    &outcomes[r],
                    NotRestorableReason::Consumed,
                    &format!("commit {commit}, replica {r}"),
                )
            })
            .collect();
        assert_eq!(refusals.len(), WAITERS - winners.len(), "commit {commit}");
        assert!(
            refusals
                .iter()
                .all(|text| *text == refused(NotRestorableReason::Consumed)),
            "{refusals:?}"
        );
        assert_eq!(
            state(&pool, &first).await,
            State {
                counts: Counts {
                    owner_recovery_state: 0,
                    admin_identity: 2,
                    admin_credential: 2,
                    admin_role_binding: 2,
                    audit_event: 4,
                    administrative_operation: 1,
                    ..ONE
                },
                recovery_state: registry::get_recovery_state(&pool).await.unwrap(),
                chain: ChainVerdict::Intact { last_sequence: 4 },
            },
            "commit {commit}"
        );
        let pools = [pool, holder_pool].into_iter().chain(waiters.into_pools());
        db.drop(pools).await;
    }
}

/// A recovery whose audit append fails writes nothing and leaves its
/// challenge restorable, in two fresh databases after a bootstrap. First,
/// an issue whose event ID is bootstrap's is `AlreadyExists` on
/// `audit_event_pkey` and changes nothing the registry shows, the chain
/// included, though its caller commits after the `Err`; with its own
/// ID the challenge then issues as the event after bootstrap. Then a
/// restore of it fails at its audit appends, its last step (after its
/// consume and writes, by the registry's documented order, which this test
/// does not observe): once with its rotation
/// event ID taken by an event committed while it waits for the head, so
/// its first event is appended and its second is `AlreadyExists` (its
/// caller commits after the `Err`, once the waiters have finished), once
/// with its session terminated while it waits (a store error, `57P01`). 4
/// replicas that restore the same challenge with event IDs of their own
/// are seen blocked behind it; after its failure exactly one of them
/// restores, the 3 others are `NotRestorable` (`Consumed`), and the state is the
/// winner's alone: the replacement enrolled once, the key at epoch 2, its
/// two events directly after the committed one or the issue, and the chain
/// intact, so neither the failed restore's first event nor its advance of
/// the chain head is left.
#[tokio::test(flavor = "multi_thread")]
async fn a32_neg_a_recovery_failing_at_its_audit_append_writes_nothing() {
    const WAITERS: usize = 4;
    for failure in [AppendFailure::TakenEventId, AppendFailure::LostStore] {
        let what = format!("{failure:?}");
        let (db, pool) = fixture().await;
        let first = ids(0);
        bootstrapped(&pool, &first).await;
        let mut challenge = recovery(1, &first, 1, &first.recovery_key);
        let mut taken = challenge.clone();
        taken.issue_event_id = first.audit_event_id.clone();
        let before = state(&pool, &first).await;
        let plan = taken.plan();
        let request = taken.issue_request(&plan, DEFAULT_CHALLENGE_TTL, issued_at());
        let mut tx = pool.begin().await.unwrap();
        match registry::issue_recovery_challenge(&mut tx, &request).await {
            Err(ChallengeError::Store(err)) => {
                assert_append_failure(AppendFailure::TakenEventId, &err, "issue");
            }
            other => panic!("{what}: expected the issue's store error: {other:?}"),
        }
        // Its caller commits after the `Err`: nothing is written.
        tx.commit().await.unwrap();
        assert_eq!(state(&pool, &first).await, before, "{what}");
        let issued = issue(&pool, &mut challenge, DEFAULT_CHALLENGE_TTL, issued_at()).await;
        assert_issued(&issued, &challenge, DEFAULT_CHALLENGE_TTL, issued_at(), 2);

        let mut failing = challenge.with_events(100);
        if failure == AppendFailure::TakenEventId {
            failing.rotation_event_id = HELD_EVENT_ID.into();
        }
        let mine: Vec<Recovery> = (0..WAITERS).map(|r| challenge.with_events(r)).collect();
        let claim = move |mut conn: PoolConnection<Postgres>, commit_after| async move {
            let mut tx = Connection::begin(&mut *conn).await.unwrap();
            let restored = restore_operator(
                &mut tx,
                &failing.response(),
                &failing.request(restored_at()),
            )
            .await;
            end_claim(tx, commit_after).await;
            restored
        };
        let work = {
            let mine = mine.clone();
            move |replica: usize, mut conn: PoolConnection<Postgres>| {
                let recovery = mine[replica].clone();
                async move { restore(&mut conn, &recovery, restored_at()).await }
            }
        };
        let failed = fail_at_append(&db, &pool, failure, WAITERS, claim, work).await;
        match &failed.claimed {
            Err(RestoreError::Store(err)) => assert_append_failure(failure, err, &what),
            other => panic!("{what}: expected a store error: {other:?}"),
        }

        let outcomes = after_the_holder(failed.waited, &what);
        let winners: Vec<usize> = (0..WAITERS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "{what}: {outcomes:?}");
        let winner = winners[0];
        let refusals: Vec<String> = (0..WAITERS)
            .filter(|&r| r != winner)
            .map(|r| {
                not_restorable_text(
                    &outcomes[r],
                    NotRestorableReason::Consumed,
                    &format!("{what}, replica {r}"),
                )
            })
            .collect();
        assert_eq!(
            refusals,
            vec![refused(NotRestorableReason::Consumed); WAITERS - 1],
            "{what}"
        );

        let outcome = outcomes[winner].as_ref().unwrap();
        assert_restored(&pool, &mine[winner], outcome, restored_at()).await;
        assert_eq!(
            outcome.revoked_credential_ids,
            vec![first.credential_id.clone()],
            "{what}"
        );
        let taken = failure == AppendFailure::TakenEventId;
        let earlier = i64::from(taken);
        let before_restore = if taken {
            failed.held.hash
        } else {
            issued.audit_event.hash
        };
        assert_eq!(
            (outcome.audit_event.sequence, outcome.audit_event.prev_hash),
            (3 + earlier, Some(before_restore)),
            "{what}"
        );
        assert_eq!(
            state(&pool, &first).await,
            State {
                counts: Counts {
                    owner_recovery_state: 0,
                    admin_identity: 2,
                    admin_credential: 2,
                    admin_role_binding: 2,
                    audit_event: 4 + earlier,
                    administrative_operation: 1,
                    ..ONE
                },
                recovery_state: registry::get_recovery_state(&pool).await.unwrap(),
                chain: ChainVerdict::Intact {
                    last_sequence: 4 + earlier
                },
            },
            "{what}"
        );
        db.drop(std::iter::once(pool).chain(failed.pools)).await;
    }
}
