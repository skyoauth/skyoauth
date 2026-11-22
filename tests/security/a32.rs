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
//! [`restore_operator`], [`get_recovery_state`], the operator getters and
//! mutators, [`authorize_operator`], [`get_instance_security_policy`] and
//! [`verify_audit_chain`]) against a real PostgreSQL, one fresh database
//! per test (per round in the replica tests), and write nothing past the
//! registry. The only SQL of their own is one read-only helper, [`counts`]
//! (see its docs), and two `SET SESSION CHARACTERISTICS AS TRANSACTION
//! ISOLATION LEVEL` statements in
//! `a32_neg_a_restore_outside_read_committed_writes_nothing`: one gives
//! each replica its isolation level ([`OTHER_ISOLATION`]), and the second
//! switches the last replica back to `READ COMMITTED` before its restore.
//! The concurrent tests use the replica harness (REP,
//! `skyoauth_scenarios::rep`): [`Replicas::race`], whose replicas a barrier
//! releases together, and
//! [`rep::wait_until_blocked`]. The fixture is local: every bootstrap
//! request is valid and has IDs, keys and an instance ID of its own
//! ([`ids`]), and each bootstrap runs in a transaction of its own that
//! commits on `Ok` and rolls back on every `Err`, as the caller must
//! ([`bootstrap`]). Likewise every recovery ([`recovery`]) is valid for the
//! instance and epoch it names and has a digest, a hash, a replacement, a
//! new key and event IDs of its own, and each issue and restore runs in a
//! transaction of its own, committed on `Ok` and rolled back on `Err`
//! ([`issue_on`], [`restore`]); a restore's transaction is
//! `READ COMMITTED`, the session default. The registry reads no clock:
//! every `now` is the test's and fixed ([`issued_at`], [`restored_at`]).
//!
//! - **Bootstrap, positive.** One bootstrap on an empty database: the IDs of its
//!   outcome are the rows the getters read back, the instance
//!   `security_admin` it enrolls authorizes with exactly those IDs, and the
//!   audit chain is intact at sequence 1. As a cheap extra check, the
//!   recovery public key (as plain text, hex or base64) and the instance
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
//!   (`a32_neg_a_closed_bootstrap_is_never_reopened`).
//! - **Recovery, positive.** After a bootstrap, with its operator enrolled
//!   (and given a second credential) or locked out (identity disabled,
//!   first credential revoked, binding disabled, so no key authorizes a
//!   `security_admin`), a challenge is issued and restored: the replacement
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
//!   on the restoring pool and on a fresh one: the identical request (the
//!   retry of an uncertain commit), the same challenge later with event IDs
//!   of its own or bound to the rotated state, and a second challenge issued
//!   before the rotation, so for the retired key; no challenge is issued for
//!   the retired epoch, a restore rolled back before it left the challenge
//!   restorable, and a challenge of the new epoch then restores
//!   (`a32_neg_a_replayed_recovery_is_refused`). A restore that differs from
//!   its challenge in any of the six plan members, in its operation ID,
//!   digest, challenge hash, instance, epoch or expected revision, or that
//!   splices two issued challenges, is `NotRestorable` and enrolls nothing,
//!   and a challenge for another instance is not issued; the untouched
//!   challenge then restores and the other is retired
//!   (`a32_neg_a_restore_must_be_the_one_its_challenge_names`). At the
//!   shortest, default and longest TTL, a restore at `expires_at`, a
//!   microsecond after and a longest TTL after is `NotRestorable` and one a
//!   microsecond before restores, over three successive epochs
//!   (`a32_neg_an_expired_challenge_is_refused`). Replicas whose sessions
//!   default to `REPEATABLE READ`, `SERIALIZABLE` or `READ UNCOMMITTED` get
//!   `UnsupportedIsolation`, keep a usable transaction and commit nothing,
//!   and the challenge then restores at `READ COMMITTED`
//!   (`a32_neg_a_restore_outside_read_committed_writes_nothing`). Of 8
//!   replicas that restore at once, one challenge for all or one each,
//!   exactly one restores and 7 are `NotRestorable`, in 4 fresh databases
//!   (`a32_neg_concurrent_restores_across_replicas_have_one_winner`); 4
//!   replicas seen blocked behind a holder's uncommitted restore all get
//!   `NotRestorable` after its commit, and exactly one of them restores
//!   after its rollback
//!   (`a32_neg_blocked_restores_follow_the_holder_commit_or_rollback`).
//!
//! A challenge bound to its instance, its operation and arguments digest
//! and the expected revision, expiring and single use, is the spec's
//! (tasks T13.5, design §7.2, threat model "Recovery response"; LT-107).
//! The recovery tests also pin these picks of the registry, recorded as
//! lead rulings or inferred in identity-registry section 5.2 and in
//! `registry::recovery` and provisional until the ADRs are ratified:
//! registry behaviour, not the spec's. The plan's members (the new key as
//! 64 lowercase hexadecimal digits); the byte-wise comparison of the
//! replacement and of the instance; the binding to the challenge hash,
//! compared byte-wise (inferred); the binding to the recovery key epoch;
//! that the expected revision is the recovery state's (inferred); the
//! refusal of every level but
//! `READ COMMITTED`, by name, so `READ UNCOMMITTED` too; the TTL minimum of
//! 1 second; the issue event `administrative_operation.create` by
//! `deployment_operator`, with the operation as its object and
//! `new_revision` 1; the restore events' actor `recovery_key:<epoch>` of the
//! key that signed, the epoch before the rotation, and the rotation event's
//! revisions; every refusal of a restore as the one `NotRestorable`, matched
//! by variant and `Debug` text, not by its `Display` text; and a
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
//! only when `now` is taken from the local verifier's own clock (T13.3) and
//! is tested with A64's injected clocks on its hermetic leg, not here.
//!
//! Two obligations therefore rest on the local verifier (T13.3), not on the
//! registry; they are gaps of these tests, and the lead's rulings behind
//! them are provisional. First, the restore's binding carries the
//! challenge's `challenge_hash` and the consume compares it byte-wise with
//! the stored one, but the registry neither hashes nor verifies the
//! recovery signature, so the verifier must check the signature over the
//! challenge whose hash it passes (the operation's stored challenge, or
//! one recomputed from exactly the values it passes to
//! [`restore_operator`]), never over a hash taken from the response or
//! from the operator; no registry getter returns the operation row.
//! Second, `now` must come from the verifier's own clock immediately
//! before the call, never from the response or the operator.
//! Neither [`issue_recovery_challenge`] nor [`restore_operator`] takes an
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
//! recovery key that is not 32 bytes, an empty or over-long key or anchor,
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
//!   the service UID with mode 0600 (T13.4, OQ-TM-9), and the service-local
//!   bootstrap/recovery verifier behind them (design §7.2, ADR-013 item 7;
//!   T13.3 builds it): the "local verifier" harness component of the row.
//!   Nothing here goes through a command, a socket or the verifier. The
//!   verifier is the only check of the recovery signature: the registry
//!   verifies none and hashes nothing (`registry::recovery` "Flow"). A
//!   restore carries the challenge's `challenge_hash` and the consume
//!   compares it byte-wise with the stored one, which binds the restore to
//!   the hash issued, not to a signature, so a restore here stands for one
//!   whose signed challenge, the one whose hash it carries, the verifier
//!   has checked against the key [`get_recovery_state`] returns.
//! - The restart and configuration-omission half of "durably closes" (T13.4)
//!   beyond a fresh pool: no service starts or restarts here, and no
//!   configuration is read; a new pool on the same database is all that is
//!   tested.
//! - The OP harness component, `skyoauth-operator` (T13.10), as the client
//!   whose key the bootstrap enrolls and that presents it afterwards, and
//!   that presents the replacement's key after a restoration.
//! - The signed offline recovery tooling: the portable workstation that
//!   signs the challenge with the offline recovery key, with its SoftHSM2,
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
//! `SERIALIZABLE`); a policy row committed while bootstrap waits; a failed
//! audit append and a caller that commits after an `Err`; the audit append
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
//! second consume; malformed plans, the issue's input checks and the TTL
//! bounds of an issue; `RecoveryKeyUnchanged`, reserved admin IDs, key
//! lengths and the bounds of `now`; a replacement whose ID or key is taken
//! (`AlreadyExists`); a failed restore or issue that the caller commits; a
//! lock timeout; the lock order, the waits between a restore, an issue and
//! the operator writes, and the deadlock that fails closed; and that a
//! restore changes no other table. Through the public API every consume
//! is a restore that also advances the epoch and the revision, so a replay
//! here is refused by its binding to the retired state whether or not the
//! single-use predicates of the consume hold. And a challenge can only be
//! issued for the current instance, epoch and revision, so the consume
//! compares each of them twice, the stored plan instance, plan epoch and
//! expected revision with the binding and the binding with the recovery
//! state, and through the public API the two copies are always equal. A
//! consume that no longer sets `consumed_at`; no longer requires it unset
//! and the outcome `issued`; no longer compares the plan's instance, the
//! plan's epoch or the stored expected revision with the binding; or no
//! longer compares the binding with the recovery state's instance, epoch or
//! revision is therefore caught only by the service tests, whose rows are
//! written by other means. So is a restore that no longer locks the
//! credentials first, which needs a concurrent operator write.
//!
//! Overlap with `service/tests/registry_recovery.rs`, which calls the same
//! public functions: each recovery test here repeats some of its checks and
//! adds what the scenario adds. The positive repeats
//! `a_restore_enrolls_a_replacement_revokes_every_credential_and_rotates_the_key`
//! and adds the path from bootstrap through public reads only, a locked-out
//! operator and bootstrap closed after the restore, also on a fresh pool.
//! The replay test repeats `a_challenge_is_consumed_once` and adds the
//! identical retry, a fresh pool, the rolled-back restore and the retired
//! epoch at issue and at restore. The tamper test's per-member and binding
//! refusals repeat `a_restore_must_name_the_planned_*` and
//! `every_consume_miss_is_the_same_not_restorable` one for one; it adds the
//! splices of two issued challenges, a challenge hash that differs from the
//! issued one only in case, and one challenge that survives every refusal. The expiry test repeats `a_challenge_expires_at_its_expiry`
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
//! [`get_recovery_state`]: registry::get_recovery_state
//! [`authorize_operator`]: registry::authorize_operator
//! [`get_instance_security_policy`]: registry::get_instance_security_policy
//! [`verify_audit_chain`]: registry::verify_audit_chain

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use skyoauth_scenarios::{
    pg::TestDb,
    rep::{self, Replicas},
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, AdminCredential, AdminIdentity, AdminRole, AdminRoleBinding, AdminRoleBindingChanges,
        AuditActor, AuthorizedOperator, BootstrapError, BootstrapOutcome, BootstrapRequest,
        ChainVerdict, ChallengeBinding, ChallengeError, DEFAULT_CHALLENGE_TTL,
        DEPLOYMENT_OPERATOR_ACTOR, IssueChallenge, JsonObject, MAX_CHALLENGE_TTL,
        MIN_CHALLENGE_TTL, NewAdminCredential, NewAdminIdentity, OPERATOR_RESTORATION,
        OperatorRequest, OperatorScope, RecoveryChallenge, RecoveryState, RegistryError,
        RestoreError, RestoreRequest, Restored, Status, bootstrap_instance, restore_operator,
    },
};
use sqlx::{Connection, PgConnection, Row};

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

/// Valid request material number `n`, sharing nothing with any other `n`:
/// a lowercase hyphenated UUIDv7 instance ID (version `7`, variant `9`),
/// a non-reserved admin ID, a credential key and IDs of its own, and a
/// recovery key of exactly 32 bytes, printable so that its plain-text form
/// is the key itself.
fn ids(n: usize) -> Ids {
    let ids = Ids {
        instance_id: format!("019a9f3c-5b2e-7c41-9d8e-{n:012x}"),
        admin_id: format!("adm_a32_{n}"),
        credential_id: format!("crd_a32_{n}"),
        public_identity: format!("spki-sha256:a32-operator-{n}"),
        trust_anchor_ref: "deployment/operator-ca".into(),
        binding_id: format!("rb_a32_{n}"),
        recovery_public_key: format!("a32-recovery-key-{n:015}").into_bytes(),
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
            1,
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
    assert_eq!(counts(pool, owner).await, ONE);
    assert_eq!(
        verify(pool).await,
        ChainVerdict::Intact { last_sequence: 1 }
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
    let plain = std::str::from_utf8(key).unwrap().to_owned();
    let (lower, upper) = hex(key);
    let (standard, url) = base64(key);
    assert_eq!(
        base64(b"\xfb\xff\x00"),
        ("+/8A".to_owned(), "-_8A".to_owned())
    );
    for form in [
        plain,
        lower,
        upper,
        standard,
        url,
        first.instance_id.clone(),
    ] {
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
                operator.binding = registry::update_admin_role_binding(
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
/// (an audit event ID or an operator ID taken before bootstrap) and leaves
/// bootstrap open after the rollback is
/// `a_failed_audit_append_leaves_nothing_after_rollback` and
/// `collisions_of_caller_ids_stay_already_exists` in
/// `service/tests/registry_bootstrap.rs`, through the same public API; a
/// copy here would add nothing.
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
    registry::create_admin_identity(
        &mut *tx,
        &NewAdminIdentity {
            id: "adm_a32_other".into(),
            status: Status::Enabled,
            created_at: now(),
        },
    )
    .await
    .unwrap();
    let again = registry::create_admin_credential(
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

// Registry-level recovery (T13.5): `issue_recovery_challenge`,
// `restore_operator` and `get_recovery_state`, after a bootstrap.

/// The `Debug` text of every refused restore here but the isolation one.
const NOT_RESTORABLE: &str = "Err(NotRestorable)";

/// The issue time of a challenge: a second after bootstrap. Whole
/// seconds, so no stored time is truncated.
fn issued_at() -> SystemTime {
    now() + Duration::from_secs(1)
}

/// The restore time: a second after the issue, well inside every TTL.
fn restored_at() -> SystemTime {
    now() + Duration::from_secs(2)
}

/// The material of one recovery, owned: the challenge the local verifier
/// issues (its operation, digest and hash, and what it is bound to: the
/// instance, the epoch of the key that signs and the recovery state's
/// revision), the replacement its plan names, and the restore's event IDs.
#[derive(Debug, Clone)]
struct Recovery {
    operation_id: String,
    issue_event_id: String,
    request_digest: Vec<u8>,
    challenge_hash: Vec<u8>,
    instance_id: String,
    recovery_key_epoch: i64,
    expected_revision: i64,
    admin_id: String,
    credential_id: String,
    binding_id: String,
    public_identity: String,
    trust_anchor_ref: String,
    new_recovery_public_key: Vec<u8>,
    restore_event_id: String,
    rotation_event_id: String,
}

/// Valid recovery material number `n` for `first`'s instance at `epoch`,
/// sharing nothing with any other `n` or with any bootstrap of [`ids`]: a
/// 32-byte digest, a 48-byte challenge hash, a replacement with IDs and a
/// key of its own, and a new 32-byte recovery key. The expected revision is
/// the epoch: bootstrap writes both as 1 and every restore advances both by
/// one, and nothing else here changes the recovery state.
fn recovery(n: usize, first: &Ids, epoch: i64) -> Recovery {
    let recovery = Recovery {
        operation_id: format!("op_a32_restore_{n}"),
        issue_event_id: format!("aud_a32_issue_{n}"),
        request_digest: format!("a32-request-digest-{n:013}").into_bytes(),
        challenge_hash: format!("a32-challenge-hash-{n:029}").into_bytes(),
        instance_id: first.instance_id.clone(),
        recovery_key_epoch: epoch,
        expected_revision: epoch,
        admin_id: format!("adm_a32_restored_{n}"),
        credential_id: format!("crd_a32_restored_{n}"),
        binding_id: format!("rb_a32_restored_{n}"),
        public_identity: format!("spki-sha256:a32-restored-{n}"),
        trust_anchor_ref: "deployment/operator-ca".into(),
        new_recovery_public_key: format!("a32-new-recovery-key-{n:011}").into_bytes(),
        restore_event_id: format!("aud_a32_restore_{n}"),
        rotation_event_id: format!("aud_a32_rotate_{n}"),
    };
    assert_eq!(
        (
            recovery.request_digest.len(),
            recovery.challenge_hash.len(),
            recovery.new_recovery_public_key.len(),
        ),
        (32, 48, registry::RECOVERY_PUBLIC_KEY_LENGTH)
    );
    recovery
}

/// `bytes` in lowercase hexadecimal, the plan's form of a key.
fn lower_hex(bytes: &[u8]) -> String {
    hex(bytes).0
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
            request_digest: &self.request_digest,
            immutable_plan: plan,
            challenge_hash: &self.challenge_hash,
            ttl,
            now: at,
            audit_event_id: &self.issue_event_id,
        }
    }

    /// The restore of this challenge at `at`, naming its replacement.
    fn request(&self, at: SystemTime) -> RestoreRequest<'_> {
        RestoreRequest {
            operation_id: &self.operation_id,
            binding: ChallengeBinding {
                request_digest: &self.request_digest,
                challenge_hash: &self.challenge_hash,
                instance_id: &self.instance_id,
                expected_revision: self.expected_revision,
                recovery_key_epoch: self.recovery_key_epoch,
            },
            admin_id: &self.admin_id,
            credential_id: &self.credential_id,
            binding_id: &self.binding_id,
            public_identity: &self.public_identity,
            trust_anchor_ref: &self.trust_anchor_ref,
            new_recovery_public_key: &self.new_recovery_public_key,
            audit_event_id: &self.restore_event_id,
            rotation_audit_event_id: &self.rotation_event_id,
            now: at,
        }
    }

    /// The same challenge and replacement with event IDs of its own,
    /// numbered `n`, as another replica's attempt would carry.
    fn with_events(&self, n: usize) -> Recovery {
        Recovery {
            restore_event_id: format!("{}_{n}", self.restore_event_id),
            rotation_event_id: format!("{}_{n}", self.rotation_event_id),
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

/// Issues `recovery`'s challenge with `ttl` at `at`.
async fn issue(
    pool: &PgPool,
    recovery: &Recovery,
    ttl: Duration,
    at: SystemTime,
) -> RecoveryChallenge {
    let plan = recovery.plan();
    issue_on(pool, &recovery.issue_request(&plan, ttl, at))
        .await
        .unwrap()
}

/// Restores in a transaction of its own on `conn` (`READ COMMITTED`, the
/// session default): commits on `Ok` and rolls back on every `Err`, as the
/// caller of `restore_operator` must.
async fn restore(
    conn: &mut PgConnection,
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError> {
    let mut tx = conn.begin().await.unwrap();
    let restored = restore_operator(&mut tx, request).await;
    match restored {
        Ok(_) => tx.commit().await.unwrap(),
        Err(_) => tx.rollback().await.unwrap(),
    }
    restored
}

async fn restore_on(pool: &PgPool, request: &RestoreRequest<'_>) -> Result<Restored, RestoreError> {
    restore(&mut pool.acquire().await.unwrap(), request).await
}

/// `result` is `NotRestorable`, matched by variant; returns its `Debug`
/// text ([`NOT_RESTORABLE`]) for the callers' tallies of refusals.
#[track_caller]
fn not_restorable_text(result: &Result<Restored, RestoreError>, what: &str) -> String {
    match result {
        Err(RestoreError::NotRestorable) => {}
        other => panic!("{what}: expected NotRestorable: {other:?}"),
    }
    let text = format!("{result:?}");
    assert_eq!(text, NOT_RESTORABLE, "{what}");
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
/// on an operator. No signature is made or checked: the registry verifies
/// none (T13.3). In both, the challenge is issued as the event after
/// bootstrap and changes no authority; the restore enrolls exactly the
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
        registry::create_admin_credential(&pool, &second)
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

        let recovery = recovery(0, &first, 1);
        let challenge = issue(&pool, &recovery, DEFAULT_CHALLENGE_TTL, issued_at()).await;
        assert_issued(&challenge, &recovery, DEFAULT_CHALLENGE_TTL, issued_at(), 2);
        assert_eq!(
            state(&pool, &first).await,
            State {
                counts: Counts {
                    admin_credential: 2,
                    audit_event: 2,
                    administrative_operation: 1,
                    ..ONE
                },
                recovery_state: Some(bootstrap_state(&first)),
                chain: ChainVerdict::Intact { last_sequence: 2 },
            }
        );
        // The challenge alone changes no authority.
        assert_not_enrolled(&pool, &recovery).await;
        assert_eq!(read_operator(&pool, &first).await, operator);

        let restored = restore_on(&pool, &recovery.request(restored_at()))
            .await
            .unwrap();
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

/// A recovery is never replayed. Two challenges are issued at epoch 1. A
/// restore of the first whose transaction rolls back leaves nothing and the
/// challenge restorable, and its retry restores (the uncertain-commit rule:
/// a restore that did not commit restores). After that restore, each replay
/// is `NotRestorable` and changes nothing the registry shows, on the pool
/// that restored and on a fresh one: the identical request (the retry of a
/// restore whose commit was uncertain), the same challenge later with event
/// IDs of its own, the same challenge bound to the rotated state (epoch 2,
/// revision 2) with another new key, the second challenge (issued before
/// the rotation, so signed by the retired key) with its own binding and
/// with the rotated state's. No challenge can be issued for the retired
/// epoch any more (`NotIssuable`). A challenge of epoch 2 then restores,
/// revokes the first replacement and is recorded by `recovery_key:2`, and
/// the first challenge is refused at epoch 3 too.
#[tokio::test]
async fn a32_neg_a_replayed_recovery_is_refused() {
    let (db, pool) = fixture().await;
    let first = ids(0);
    bootstrapped(&pool, &first).await;
    let used = recovery(1, &first, 1);
    let stale = recovery(2, &first, 1);
    issue(&pool, &used, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    issue(&pool, &stale, DEFAULT_CHALLENGE_TTL, issued_at()).await;

    let issued = state(&pool, &first).await;
    let mut tx = pool.begin().await.unwrap();
    restore_operator(&mut tx, &used.request(restored_at()))
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(state(&pool, &first).await, issued);
    assert_not_enrolled(&pool, &used).await;
    let restored = restore_on(&pool, &used.request(restored_at()))
        .await
        .unwrap();
    assert_restored(&pool, &used, &restored, restored_at()).await;
    let after = state(&pool, &first).await;
    assert_eq!(after.chain, ChainVerdict::Intact { last_sequence: 5 });

    let rebound = |recovery: &Recovery, key_of: usize| Recovery {
        recovery_key_epoch: 2,
        expected_revision: 2,
        new_recovery_public_key: self::recovery(key_of, &first, 2).new_recovery_public_key,
        ..recovery.clone()
    };
    let later = restored_at() + Duration::from_secs(1);
    let replays = [
        ("the identical request", used.clone(), restored_at()),
        (
            "later, with event IDs of its own",
            used.with_events(1),
            later,
        ),
        ("bound to the rotated state", rebound(&used, 3), later),
        ("a challenge of the retired epoch", stale.clone(), later),
        (
            "a challenge of the retired epoch, bound to the rotated state",
            rebound(&stale, 4),
            later,
        ),
    ];
    let retired = recovery(5, &first, 1);
    for fresh in [false, true] {
        let pool = if fresh { db.pool().await } else { pool.clone() };
        let mut refusals = Vec::new();
        for (what, replay, at) in &replays {
            let what = format!("fresh pool {fresh}: {what}");
            refusals.push(not_restorable_text(
                &restore_on(&pool, &replay.request(*at)).await,
                &what,
            ));
            assert_eq!(state(&pool, &first).await, after, "{what}");
        }
        assert_eq!(refusals, vec![NOT_RESTORABLE; replays.len()], "{fresh}");
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

    let next = recovery(6, &first, 2);
    let next_issued = issued_at() + Duration::from_secs(10);
    let next_at = restored_at() + Duration::from_secs(10);
    issue(&pool, &next, DEFAULT_CHALLENGE_TTL, next_issued).await;
    let again = restore_on(&pool, &next.request(next_at)).await.unwrap();
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
    let at_three = Recovery {
        recovery_key_epoch: 3,
        expected_revision: 3,
        ..used.with_events(2)
    };
    let restored_twice = state(&pool, &first).await;
    assert_eq!(
        restored_twice.chain,
        ChainVerdict::Intact { last_sequence: 8 }
    );
    not_restorable_text(
        &restore_on(&pool, &at_three.request(next_at)).await,
        "the first challenge at epoch 3",
    );
    assert_eq!(state(&pool, &first).await, restored_twice);
    assert_bootstrap_stays_closed(&pool, &first, 0).await;
    db.drop([pool]).await;
}

/// One change to a restore request, against the challenge it names.
type Tamper = fn(&mut Recovery);

/// A restore must be exactly the one its challenge names. Two challenges,
/// A and B, are issued at epoch 1, each naming a replacement of its own.
/// A's restore with any one of the six replacement members of the plan
/// changed (`admin_id`, `credential_id`, `binding_id`, `public_identity`,
/// `trust_anchor_ref`, `new_recovery_public_key`), or with its binding
/// changed (the operation ID, the request digest, the challenge hash, the
/// instance, the epoch or the expected revision), or spliced with B (A's
/// challenge naming B's replacement, B's challenge naming A's, A's
/// challenge with B's digest, A's challenge with B's hash), is
/// `NotRestorable`, changes nothing the registry shows and enrolls
/// nothing; a challenge for another instance is not issued. After all
/// that, A's exact request restores: no refusal consumed it. B is then
/// `NotRestorable` too, even exact: the epoch it was bound to is retired.
///
/// The registry binds all six members (step 4 of `registry::recovery`
/// "Restore") and the binding (its consume), the challenge hash byte-wise
/// like the digest. The changed hash is A's in upper case, 48 bytes like
/// A's, so it passes the length check made before any statement and
/// reaches the consume: it differs from A's only in case and only in its
/// first bytes, and sorts before it, while B's hash differs from A's only
/// in its last byte and sorts after it: a consume that compared only the
/// lengths would accept both, and one that compared one end only, ignored
/// case or compared by order would accept one. The registry neither hashes
/// nor verifies the signature: that the hash is the signed challenge's is
/// the local verifier's (T13.3), not tested here.
#[tokio::test]
async fn a32_neg_a_restore_must_be_the_one_its_challenge_names() {
    let (db, pool) = fixture().await;
    let first = ids(0);
    bootstrapped(&pool, &first).await;
    let a = recovery(1, &first, 1);
    let b = recovery(2, &first, 1);
    issue(&pool, &a, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    issue(&pool, &b, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    let issued = state(&pool, &first).await;

    let tampers: [(&str, Tamper); 12] = [
        ("admin_id", |r| r.admin_id = "adm_a32_tampered".into()),
        ("credential_id", |r| {
            r.credential_id = "crd_a32_tampered".into()
        }),
        ("binding_id", |r| r.binding_id = "rb_a32_tampered".into()),
        ("public_identity", |r| {
            r.public_identity = "spki-sha256:a32-tampered".into()
        }),
        ("trust_anchor_ref", |r| {
            r.trust_anchor_ref = "deployment/tampered-ca".into()
        }),
        ("new_recovery_public_key", |r| {
            r.new_recovery_public_key = b"a32-tampered-recovery-key-000000".to_vec()
        }),
        ("operation ID", |r| {
            r.operation_id = "op_a32_restore_unknown".into()
        }),
        ("request digest", |r| {
            r.request_digest = b"a32-tampered-request-digest-0000".to_vec()
        }),
        ("challenge hash", |r| {
            r.challenge_hash.make_ascii_uppercase()
        }),
        ("instance", |r| r.instance_id = ids(9).instance_id),
        ("epoch", |r| r.recovery_key_epoch = 2),
        ("expected revision", |r| r.expected_revision = 2),
    ];
    let replacement_of = |from: &Recovery, to: &Recovery| Recovery {
        admin_id: to.admin_id.clone(),
        credential_id: to.credential_id.clone(),
        binding_id: to.binding_id.clone(),
        public_identity: to.public_identity.clone(),
        trust_anchor_ref: to.trust_anchor_ref.clone(),
        new_recovery_public_key: to.new_recovery_public_key.clone(),
        ..from.clone()
    };
    let mut attempts: Vec<(String, Recovery)> = tampers
        .iter()
        .map(|(what, tamper)| {
            let mut attempt = a.with_events(1);
            tamper(&mut attempt);
            (format!("A with its {what} changed"), attempt)
        })
        .collect();
    attempts.push((
        "A's challenge naming B's replacement".into(),
        replacement_of(&a, &b),
    ));
    attempts.push((
        "B's challenge naming A's replacement".into(),
        replacement_of(&b, &a),
    ));
    attempts.push((
        "A's challenge with B's digest".into(),
        Recovery {
            request_digest: b.request_digest.clone(),
            ..a.with_events(2)
        },
    ));
    attempts.push((
        "A's challenge with B's hash".into(),
        Recovery {
            challenge_hash: b.challenge_hash.clone(),
            ..a.with_events(3)
        },
    ));
    let mut refusals = Vec::new();
    for (what, attempt) in &attempts {
        assert_eq!(
            attempt.new_recovery_public_key.len(),
            registry::RECOVERY_PUBLIC_KEY_LENGTH,
            "{what}"
        );
        assert_eq!(
            attempt.challenge_hash.len(),
            a.challenge_hash.len(),
            "{what}"
        );
        refusals.push(not_restorable_text(
            &restore_on(&pool, &attempt.request(restored_at())).await,
            what,
        ));
        assert_eq!(state(&pool, &first).await, issued, "{what}");
        assert_not_enrolled(&pool, attempt).await;
    }
    assert_eq!(refusals, vec![NOT_RESTORABLE; attempts.len()]);

    let elsewhere = Recovery {
        instance_id: ids(9).instance_id,
        ..recovery(3, &first, 1)
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

    let restored = restore_on(&pool, &a.request(restored_at())).await.unwrap();
    assert_restored(&pool, &a, &restored, restored_at()).await;
    assert_eq!(
        restored.revoked_credential_ids,
        vec![first.credential_id.clone()]
    );
    let after = state(&pool, &first).await;
    assert_eq!(after.chain, ChainVerdict::Intact { last_sequence: 5 });
    not_restorable_text(
        &restore_on(&pool, &b.request(restored_at())).await,
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
/// a microsecond after it and a longest TTL after it is `NotRestorable` and
/// changes nothing; the restore a microsecond before it restores, at the
/// next epoch, recorded by the key of the epoch before. The chain ends
/// intact at 10, at epoch 4, with only the last replacement authorized.
/// The three TTLs are checked first: 5 and 15 minutes are LT-107 and
/// OQ-LT-17, the 1-second minimum a lead ruling (provisional).
///
/// That the restore a microsecond before `expires_at` succeeds after the
/// refusal at `expires_at` is registry behaviour, not the spec's: the
/// refusal wrote nothing and is not final, because only the caller's `now`
/// is compared, and a `now` before the issue time is accepted too. LT-107's
/// "the challenge expires" holds only with `now` taken from the local
/// verifier's own clock (T13.3), which A64's hermetic leg tests with
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
    for (cycle, ttl) in [MIN_CHALLENGE_TTL, DEFAULT_CHALLENGE_TTL, MAX_CHALLENGE_TTL]
        .into_iter()
        .enumerate()
    {
        let epoch = i64::try_from(cycle).unwrap() + 1;
        let recovery = recovery(cycle, &first, epoch);
        let at = now() + Duration::from_secs(3600 * (u64::try_from(cycle).unwrap() + 1));
        let challenge = issue(&pool, &recovery, ttl, at).await;
        assert_issued(&challenge, &recovery, ttl, at, 3 * epoch - 1);
        let expires_at = challenge.expires_at;
        let before = state(&pool, &first).await;
        for late in [
            expires_at,
            expires_at + Duration::from_micros(1),
            expires_at + MAX_CHALLENGE_TTL,
        ] {
            not_restorable_text(
                &restore_on(&pool, &recovery.request(late)).await,
                &format!("{ttl:?} at {late:?}"),
            );
            assert_eq!(state(&pool, &first).await, before, "{ttl:?} at {late:?}");
        }
        assert_not_enrolled(&pool, &recovery).await;
        let last = expires_at - Duration::from_micros(1);
        let outcome = restore_on(&pool, &recovery.request(last)).await.unwrap();
        assert_restored(&pool, &recovery, &outcome, last).await;
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
    let recovery = recovery(1, &first, 1);
    issue(&pool, &recovery, DEFAULT_CHALLENGE_TTL, issued_at()).await;
    let issued = state(&pool, &first).await;
    let mut replicas = Vec::new();
    for (level, set) in OTHER_ISOLATION {
        let replica = db.pool_with_max_connections(1).await;
        let mut conn = replica.acquire().await.unwrap();
        sqlx::query(set).execute(&mut *conn).await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        match restore_operator(&mut tx, &recovery.request(restored_at())).await {
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
    let restored = restore(&mut conn, &recovery.request(restored_at()))
        .await
        .unwrap();
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
/// others are `NotRestorable`: a challenge is consumed once, and one
/// restoration retires the epoch the others are bound to. The state is the
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
            let one = recovery(base, &first, 1);
            issue(&pool, &one, DEFAULT_CHALLENGE_TTL, issued_at()).await;
            (0..REPLICAS).map(|r| one.with_events(r)).collect()
        } else {
            let each: Vec<Recovery> = (0..REPLICAS)
                .map(|r| recovery(base + r, &first, 1))
                .collect();
            for recovery in &each {
                issue(&pool, recovery, DEFAULT_CHALLENGE_TTL, issued_at()).await;
            }
            each
        };
        let issues = if shared { 1 } else { REPLICAS };
        let replicas = Replicas::start(&db, REPLICAS).await;
        let outcomes = replicas
            .race({
                let mine = mine.clone();
                move |replica, mut conn| {
                    let recovery = mine[replica].clone();
                    async move { restore(&mut conn, &recovery.request(restored_at())).await }
                }
            })
            .await;
        assert_eq!(outcomes.len(), REPLICAS);
        let winners: Vec<usize> = (0..REPLICAS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        let winner = winners[0];
        let refusals: Vec<String> = (0..REPLICAS)
            .filter(|&r| r != winner)
            .map(|r| not_restorable_text(&outcomes[r], &format!("round {round}, replica {r}")))
            .collect();
        assert_eq!(
            refusals,
            vec![NOT_RESTORABLE; REPLICAS - 1],
            "round {round}"
        );

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
/// the holder ends. After the holder's commit all 4 are `NotRestorable` and
/// the state is the holder's; after its rollback exactly one of the 4
/// restores, the other 3 are `NotRestorable`, and the state is that one's.
/// Each in a fresh database.
#[tokio::test(flavor = "multi_thread")]
async fn a32_neg_blocked_restores_follow_the_holder_commit_or_rollback() {
    const WAITERS: usize = 4;
    for commit in [true, false] {
        let (db, pool) = fixture().await;
        let first = ids(0);
        bootstrapped(&pool, &first).await;
        let held = recovery(1, &first, 1);
        issue(&pool, &held, DEFAULT_CHALLENGE_TTL, issued_at()).await;
        let holder_pool = db.pool_with_max_connections(1).await;
        let mut holder_conn = holder_pool.acquire().await.unwrap();
        let holder_pid = rep::backend_pid(&mut holder_conn).await;
        let waiters = Replicas::start(&db, WAITERS).await;
        let pids = waiters.backend_pids().await;

        let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
        let held_outcome = restore_operator(&mut tx, &held.request(restored_at()))
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
                    let outcome = restore(&mut conn, &recovery.request(restored_at())).await;
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
            .map(|r| not_restorable_text(&outcomes[r], &format!("commit {commit}, replica {r}")))
            .collect();
        assert_eq!(refusals.len(), WAITERS - winners.len(), "commit {commit}");
        assert!(
            refusals.iter().all(|text| text == NOT_RESTORABLE),
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
