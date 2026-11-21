//! A32: concurrent or reopened bootstrap, forged IdP admin, revoked
//! operator or replayed recovery. Expected: one enrollment only, no
//! elevation or replay, audited independent restoration (tasks §8; T13.4,
//! T13.5, T13.6).
//!
//! **A32 partial: the bootstrap registry slice only; A32 M1a stays planned
//! (scope "full row").** These tests are registered on A32's planned M1a
//! stage, so they are no evidence for it: the reporter lists their results
//! as not counted, and they are no claim. They run through the typed
//! registry API (`skyoauth_service::persistence::registry`:
//! [`bootstrap_instance`], the operator getters and mutators,
//! [`authorize_operator`], [`get_instance_security_policy`] and
//! [`verify_audit_chain`]) against a real PostgreSQL, one fresh database
//! per test (per round in the replica tests), and write nothing past the
//! registry. The only SQL of their own is one read-only helper,
//! [`counts`] (see its docs). The concurrent tests use the replica harness
//! (REP, `skyoauth_scenarios::rep`): [`Replicas::race`], whose replicas a
//! barrier releases together, and [`rep::wait_until_blocked`]. The
//! fixture is local: every bootstrap request is valid and has IDs, keys and
//! an instance ID of its own ([`ids`]), and each bootstrap runs in a
//! transaction of its own that commits on `Ok` and rolls back on every
//! `Err`, as the caller must ([`bootstrap`]).
//!
//! - **Positive.** One bootstrap on an empty database: the IDs of its
//!   outcome are the rows the getters read back, the instance
//!   `security_admin` it enrolls authorizes with exactly those IDs, and the
//!   audit chain is intact at sequence 1. As a cheap extra check, the
//!   recovery public key (as plain text, hex or base64) and the instance
//!   ID, presented as an operator credential's `public_identity`, authorize
//!   no role (`a32_pos_one_bootstrap_enrolls_one_operator_and_closes`).
//! - **Negative.** Of 8 replicas that bootstrap at once with requests that
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
//! tests reach only the registry function in the middle of it. Not built
//! yet, with the owner of each part:
//!
//! - The deployment-local bootstrap command and its Unix socket, owned by
//!   the service UID with mode 0600 (T13.4, OQ-TM-9), and the service-local
//!   bootstrap/recovery verifier behind them (design §7.2, ADR-013 item 7;
//!   T13.3 builds it): the "local verifier" harness component of the row.
//!   Nothing here goes through a command, a socket or the verifier.
//! - The restart and configuration-omission half of "durably closes" (T13.4)
//!   beyond a fresh pool: no service starts or restarts here, and no
//!   configuration is read; a new pool on the same database is all that is
//!   tested.
//! - The OP harness component, `skyoauth-operator` (T13.10), as the client
//!   whose key the bootstrap enrolls and that presents it afterwards.
//! - Signed recovery restores and replayed recovery (T13.5): the recovery
//!   verifier, its challenge and the operator restoration do not exist.
//!   Operator restoration is `restore_operator`, a later change (PR 3a, as
//!   `registry::bootstrap` and identity-registry say), with A48 and A64 for
//!   the operator tools and the offline signing, not these tests.
//! - The forged IdP admin negative on the wire: an upstream admin-role
//!   claim or session from the OIDC harness component (the mock human IdP)
//!   must not reach an operator through the OP harness component, as for
//!   A22's upstream admin-role claim. For A32 the real claim is an
//!   architecture property, that no IdP-reachable path calls
//!   `bootstrap_instance`, which is not a registry test.
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
//! [`bootstrap_instance`]: registry::bootstrap_instance
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

use skyoauth_scenarios::{
    pg::TestDb,
    rep::{self, Replicas},
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, AdminCredential, AdminIdentity, AdminRole, AdminRoleBinding, AdminRoleBindingChanges,
        AuditActor, AuthorizedOperator, BootstrapError, BootstrapOutcome, BootstrapRequest,
        ChainVerdict, DEPLOYMENT_OPERATOR_ACTOR, NewAdminCredential, NewAdminIdentity,
        OperatorRequest, OperatorScope, RegistryError, Status, bootstrap_instance,
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

/// Row counts of the tables bootstrap writes, and of the rows that are
/// `owner`'s: its recovery state (its instance ID and recovery key, closed,
/// epoch 1) and its `recovery_state.create` event.
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

/// [`Counts`] with `owner`'s rows. The only SQL of this module, read-only:
/// the registry has no getter for `recovery_state` (a `get_recovery_state`
/// is expected from a later change, which should replace this read of it)
/// and lists neither operators nor audit events, so "these rows and no
/// others" needs counts.
async fn counts(pool: &PgPool, owner: &Ids) -> Counts {
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM instance_security_policy) AS policy, \
                (SELECT count(*) FROM recovery_state) AS recovery_state, \
                (SELECT count(*) FROM recovery_state WHERE instance_id = $1 \
                    AND recovery_public_key = $2 AND bootstrap_closed \
                    AND recovery_key_epoch = 1) AS owner_recovery_state, \
                (SELECT count(*) FROM admin_identity) AS admin_identity, \
                (SELECT count(*) FROM admin_credential) AS admin_credential, \
                (SELECT count(*) FROM admin_role_binding) AS admin_role_binding, \
                (SELECT count(*) FROM audit_event) AS audit_event, \
                (SELECT count(*) FROM audit_event WHERE id = $3 AND object_id = $1 \
                    AND action = 'recovery_state.create') AS owner_audit_event, \
                (SELECT count(*) FROM administrative_operation) AS administrative_operation",
    )
    .bind(&owner.instance_id)
    .bind(&owner.recovery_public_key)
    .bind(&owner.audit_event_id)
    .fetch_one(pool)
    .await
    .unwrap();
    Counts {
        policy: row.get("policy"),
        recovery_state: row.get("recovery_state"),
        owner_recovery_state: row.get("owner_recovery_state"),
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
