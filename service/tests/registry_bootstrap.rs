//! One-time instance bootstrap (`persistence::registry::bootstrap`;
//! design section 7.2; ADR-013 item 5; identity-registry IR-053, IR-057
//! and section 5.2; T13.4, T13.6): a full bootstrap on an empty database,
//! closure after commit and across connections, two concurrent bootstraps,
//! the adopt rule for a policy row written before bootstrap or committed
//! while bootstrap waits, a failed audit append that leaves nothing behind
//! once the caller rolls back, or even commits, input rejected before any
//! statement, and collisions of caller-supplied IDs that stay
//! `AlreadyExists`.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! creates and drops its own database. They are registry tests, not
//! conformance scenarios (A32 belongs to the test session in
//! `tests/security`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, AdminRole, AdminRoleBinding, AuditActor, AuthorizedOperator, BootstrapError,
        BootstrapOutcome, BootstrapRequest, ChainVerdict, DEPLOYMENT_OPERATOR_ACTOR,
        InstanceSecurityPolicy, NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding,
        NewAuditEvent, OperatorRequest, OperatorScope, RegistryError, Status, authorize_operator,
        bootstrap_instance, test_support::append_audit_event, verify_audit_chain,
    },
};
use sqlx::{Connection, PgConnection, Row};
use tokio::sync::Barrier;

const INSTANCE: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const OTHER_INSTANCE: &str = "019a9f3c-5b2e-7c41-ad8e-ba9876543210";
const KEY: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];
const OTHER_KEY: [u8; 32] = [0xee; 32];
const T0: u64 = 1_790_000_000_123_456;

/// The bootstrap time: sub-microsecond digits, so a write truncates it.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0) + Duration::from_nanos(789)
}

/// `now()` as stored.
fn stored_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0)
}

fn request(instance_id: &'static str) -> BootstrapRequest<'static> {
    BootstrapRequest {
        instance_id,
        admin_id: "adm_first",
        credential_id: "crd_first",
        public_identity: "spki-sha256:first",
        trust_anchor_ref: "deployment/operator-ca",
        binding_id: "rb_first",
        recovery_public_key: &KEY,
        audit_event_id: "aud_bootstrap",
        now: now(),
    }
}

/// A second, entirely different request: other IDs, key and instance.
fn other_request() -> BootstrapRequest<'static> {
    BootstrapRequest {
        instance_id: OTHER_INSTANCE,
        admin_id: "adm_second",
        credential_id: "crd_second",
        public_identity: "spki-sha256:second",
        trust_anchor_ref: "deployment/operator-ca-2",
        binding_id: "rb_second",
        recovery_public_key: &OTHER_KEY,
        audit_event_id: "aud_bootstrap_2",
        now: now() + Duration::from_secs(5),
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// Bootstraps in a transaction of its own; commits on `Ok`, rolls back on
/// `Err`, as the caller must.
async fn bootstrap(
    connection: &mut PgConnection,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    bootstrap_at(connection, "READ COMMITTED", request).await
}

/// [`bootstrap`] at the isolation level `isolation`.
async fn bootstrap_at(
    connection: &mut PgConnection,
    isolation: &str,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    let mut transaction = connection.begin().await.unwrap();
    set_isolation(&mut transaction, isolation).await;
    let outcome = bootstrap_instance(&mut transaction, request).await;
    match outcome {
        Ok(_) => transaction.commit().await.unwrap(),
        Err(_) => transaction.rollback().await.unwrap(),
    }
    outcome
}

async fn bootstrap_on(
    pool: &PgPool,
    request: &BootstrapRequest<'_>,
) -> Result<BootstrapOutcome, BootstrapError> {
    let mut connection = pool.acquire().await.unwrap();
    bootstrap(&mut connection, request).await
}

#[track_caller]
fn assert_closed<T: std::fmt::Debug>(result: Result<T, BootstrapError>) {
    match result {
        Err(err @ BootstrapError::AlreadyClosed) => {
            assert_eq!(format!("{err:?}"), "AlreadyClosed");
            assert_eq!(err.to_string(), "bootstrap is already closed");
        }
        other => panic!("expected AlreadyClosed: {other:?}"),
    }
}

/// Sets the isolation level of the transaction, which has run no statement
/// yet, and takes its snapshot.
async fn set_isolation(connection: &mut PgConnection, isolation: &str) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "SET TRANSACTION ISOLATION LEVEL {isolation}; SELECT 1"
    )))
    .execute(connection)
    .await
    .unwrap();
}

#[track_caller]
fn assert_retry<T: std::fmt::Debug>(result: Result<T, BootstrapError>) {
    match result {
        Err(BootstrapError::Store(RegistryError::Retry(_))) => {}
        other => panic!("expected Retry: {other:?}"),
    }
}

#[track_caller]
fn assert_store_exists<T: std::fmt::Debug>(result: Result<T, BootstrapError>, name: &str) {
    match result {
        Err(BootstrapError::Store(RegistryError::AlreadyExists { constraint })) => {
            assert_eq!(constraint, name)
        }
        other => panic!("expected AlreadyExists {name}: {other:?}"),
    }
}

#[track_caller]
fn assert_encode<T: std::fmt::Debug>(result: Result<T, BootstrapError>, message: &str) {
    match result {
        Err(BootstrapError::Store(RegistryError::Other(sqlx::Error::Encode(err)))) => {
            assert_eq!(err.to_string(), message)
        }
        other => panic!("expected an encode error {message:?}: {other:?}"),
    }
}

/// Row counts of the tables bootstrap writes, in the order policy,
/// recovery state, identity, credential, binding, audit event,
/// administrative operation.
async fn counts(connection: &mut PgConnection) -> [i64; 7] {
    let row = sqlx::query(
        "SELECT (SELECT count(*) FROM instance_security_policy) AS a, \
                (SELECT count(*) FROM recovery_state) AS b, \
                (SELECT count(*) FROM admin_identity) AS c, \
                (SELECT count(*) FROM admin_credential) AS d, \
                (SELECT count(*) FROM admin_role_binding) AS e, \
                (SELECT count(*) FROM audit_event) AS f, \
                (SELECT count(*) FROM administrative_operation) AS g",
    )
    .fetch_one(connection)
    .await
    .unwrap();
    ["a", "b", "c", "d", "e", "f", "g"].map(|column| row.get(column))
}

async fn pool_counts(pool: &PgPool) -> [i64; 7] {
    counts(&mut pool.acquire().await.unwrap()).await
}

/// Every column of every row bootstrap can write, and the chain head, as
/// one text, to compare states.
async fn state(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT concat_ws(' | ', \
           coalesce((SELECT string_agg(concat_ws(',', instance_id, widening_second_approver, \
               single_actor_mode, encode(audit_sink_config_digest, 'hex'), \
               audit_sink_validated_at, revision), ';') FROM instance_security_policy), '-'), \
           coalesce((SELECT string_agg(concat_ws(',', instance_id, bootstrap_closed, \
               encode(recovery_public_key, 'hex'), recovery_key_epoch, revision), ';') \
               FROM recovery_state), '-'), \
           coalesce((SELECT string_agg(concat_ws(',', id, status, created_at), ';' ORDER BY id) \
               FROM admin_identity), '-'), \
           coalesce((SELECT string_agg(concat_ws(',', id, admin_id, public_identity, \
               trust_anchor_ref, status, revoked_at), ';' ORDER BY id) FROM admin_credential), '-'), \
           coalesce((SELECT string_agg(concat_ws(',', id, admin_id, role, tenant_id, status, \
               revision), ';' ORDER BY id) FROM admin_role_binding), '-'), \
           coalesce((SELECT string_agg(concat_ws(',', id, sequence, object_id, action), ';' \
               ORDER BY sequence) FROM audit_event), '-'), \
           (SELECT concat_ws(',', sequence, encode(head_hash, 'hex')) FROM audit_chain_head))",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The recovery state row: `(instance_id, bootstrap_closed, key, epoch,
/// revision)`.
async fn recovery_state(pool: &PgPool) -> Option<(String, bool, Vec<u8>, i64, i64)> {
    sqlx::query_as(
        "SELECT instance_id, bootstrap_closed, recovery_public_key, recovery_key_epoch, revision \
         FROM recovery_state",
    )
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn verify(pool: &PgPool) -> ChainVerdict {
    verify_audit_chain(&mut pool.acquire().await.unwrap())
        .await
        .unwrap()
}

async fn authorize_security_admin(pool: &PgPool, key: &str) -> Option<AuthorizedOperator> {
    authorize_operator(
        pool,
        &OperatorRequest {
            public_identity: key,
            scope: OperatorScope::Instance,
            role: AdminRole::SecurityAdmin,
        },
    )
    .await
    .unwrap()
}

/// Whether the transaction still runs statements, and what it holds.
async fn usable_and_empty(connection: &mut PgConnection) {
    assert_eq!(counts(connection).await, [0; 7]);
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bootstrap_on_an_empty_database_enrolls_closes_and_audits() {
    let (db, pool) = migrated().await;
    assert_eq!(pool_counts(&pool).await, [0; 7]);
    assert!(matches!(
        registry::get_instance_security_policy(&pool).await,
        Err(RegistryError::NotFound)
    ));

    let outcome = bootstrap_on(&pool, &request(INSTANCE)).await.unwrap();
    assert_eq!(
        (
            &outcome.instance_id[..],
            &outcome.admin_id[..],
            &outcome.credential_id[..],
            &outcome.binding_id[..],
            outcome.recovery_key_epoch,
        ),
        (INSTANCE, "adm_first", "crd_first", "rb_first", 1)
    );

    // The policy row, with the column defaults.
    assert_eq!(
        registry::get_instance_security_policy(&pool).await.unwrap(),
        InstanceSecurityPolicy {
            instance_id: INSTANCE.into(),
            widening_second_approver: false,
            single_actor_mode: false,
            audit_sink_config_digest: None,
            audit_sink_validated_at: None,
            revision: 1,
        }
    );
    // The recovery state: closed, the exact key bytes, epoch 1.
    assert_eq!(
        recovery_state(&pool).await,
        Some((INSTANCE.into(), true, KEY.to_vec(), 1, 1))
    );

    // The first security_admin, enabled and unrevoked, at the caller's time.
    let identity = registry::get_admin_identity(&pool, "adm_first")
        .await
        .unwrap();
    assert_eq!(
        (identity.status, identity.created_at),
        (Status::Enabled, stored_now())
    );
    let credential = registry::get_admin_credential(&pool, "crd_first")
        .await
        .unwrap();
    assert_eq!(
        (
            &credential.admin_id[..],
            &credential.public_identity[..],
            &credential.trust_anchor_ref[..],
            credential.status,
            credential.revoked_at,
        ),
        (
            "adm_first",
            "spki-sha256:first",
            "deployment/operator-ca",
            Status::Enabled,
            None
        )
    );
    assert_eq!(
        registry::get_admin_role_binding(&pool, "rb_first")
            .await
            .unwrap(),
        AdminRoleBinding {
            id: "rb_first".into(),
            admin_id: "adm_first".into(),
            role: AdminRole::SecurityAdmin,
            tenant_id: None,
            status: Status::Enabled,
            revision: 1,
        }
    );
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:first").await,
        Some(AuthorizedOperator {
            admin_id: "adm_first".into(),
            credential_id: "crd_first".into(),
            binding_id: "rb_first".into(),
            role: AdminRole::SecurityAdmin,
        })
    );

    // One instance-scope event by the deployment operator.
    let event = &outcome.audit_event;
    assert_eq!(
        (
            &event.id[..],
            event.tenant_id.as_deref(),
            event.sequence,
            event.prev_hash,
            event.timestamp,
            &event.actor,
            &event.action[..],
            &event.object_id[..],
            event.previous_revision,
            event.new_revision,
            &event.outcome[..],
        ),
        (
            "aud_bootstrap",
            None,
            1,
            None,
            stored_now(),
            &AuditActor::Operator(DEPLOYMENT_OPERATOR_ACTOR.into()),
            "recovery_state.create",
            INSTANCE,
            None,
            Some(1),
            "success",
        )
    );
    assert_eq!(event.compute_hash().unwrap(), event.hash);
    let stored: (String, String, String) = sqlx::query_as(
        "SELECT actor, action, object_id FROM audit_event WHERE id = 'aud_bootstrap'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        (
            r#"{"id":"deployment_operator","type":"operator"}"#.into(),
            "recovery_state.create".into(),
            INSTANCE.into()
        )
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 1 }
    );
    // Exactly these rows, and no administrative operation.
    assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
    db.drop([pool]).await;
}

/// After commit, any second bootstrap, the same request or another, is the
/// same `AlreadyClosed` and changes nothing; so is one on a new pool and
/// connection, which is what a restart sees: the database is the only
/// input that says bootstrap is closed.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_bootstrap_after_commit_is_already_closed_and_changes_nothing() {
    let (db, pool) = migrated().await;
    bootstrap_on(&pool, &request(INSTANCE)).await.unwrap();
    let before = state(&pool).await;

    // The same request again, and an entirely different one (another
    // instance ID too: closure is checked before the adopt rule).
    assert_closed(bootstrap_on(&pool, &request(INSTANCE)).await);
    assert_closed(bootstrap_on(&pool, &other_request()).await);
    // Inside the transaction the refusal ran no failing statement.
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    assert_closed(bootstrap_instance(&mut transaction, &other_request()).await);
    assert_eq!(counts(&mut transaction).await, [1, 1, 1, 1, 1, 1, 0]);
    transaction.rollback().await.unwrap();
    drop(connection);
    assert_eq!(state(&pool).await, before);

    // A new pool and connection: still closed.
    pool.close().await;
    let pool = db.pool().await;
    let mut fresh = pool.acquire().await.unwrap().detach();
    assert_closed(bootstrap(&mut fresh, &other_request()).await);
    assert_closed(bootstrap(&mut fresh, &request(INSTANCE)).await);
    fresh.close().await.unwrap();
    assert_eq!(state(&pool).await, before);
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:second").await,
        None
    );
    db.drop([pool]).await;
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// Waits until the backend `blocked` waits for a lock held by `holder`.
async fn wait_until_blocked(pool: &PgPool, blocked: i32, holder: i32) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                .bind(holder)
                .bind(blocked)
                .fetch_one(pool)
                .await
                .unwrap();
            if waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the second bootstrap never waited for the first");
}

/// Two bootstraps released together on separate connections: exactly one
/// succeeds, the other is `AlreadyClosed`, and the state is the winner's
/// alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn of_two_concurrent_bootstraps_exactly_one_wins() {
    let (db, pool) = migrated().await;
    let barrier = Arc::new(Barrier::new(2));
    let mut tasks = Vec::new();
    for request in [request(INSTANCE), other_request()] {
        let mut connection = pool.acquire().await.unwrap().detach();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let outcome = bootstrap(&mut connection, &request).await;
            connection.close().await.unwrap();
            (request, outcome)
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        let (request, outcome) = task.await.unwrap();
        match outcome {
            Ok(outcome) => winners.push((request, outcome)),
            Err(err) => assert_closed(Err::<(), _>(err)),
        }
    }
    assert_eq!(winners.len(), 1);
    let (winner, outcome) = &winners[0];
    assert_eq!(outcome.instance_id, winner.instance_id);
    assert_eq!(
        recovery_state(&pool).await,
        Some((
            winner.instance_id.into(),
            true,
            winner.recovery_public_key.to_vec(),
            1,
            1
        ))
    );
    let admins: Vec<String> = sqlx::query_scalar("SELECT id FROM admin_identity")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(admins, [winner.admin_id]);
    assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 1 }
    );
    db.drop([pool]).await;
}

/// The second of two bootstraps on an empty database waits on the first's
/// policy row insert. When the first commits, the second's insert inserts
/// nothing and its repeated check finds the first's recovery state:
/// `AlreadyClosed`, for the same instance ID and for another. When the
/// first rolls back, the second bootstraps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_waiting_second_bootstrap_follows_the_first_commit_or_rollback() {
    for (second_instance, commit) in [
        (INSTANCE, true),
        (OTHER_INSTANCE, true),
        (OTHER_INSTANCE, false),
    ] {
        let (db, pool) = migrated().await;
        let mut first = pool.acquire().await.unwrap().detach();
        let mut second = pool.acquire().await.unwrap().detach();
        let (first_pid, second_pid) = (
            backend_pid(&mut first).await,
            backend_pid(&mut second).await,
        );
        let mut transaction = first.begin().await.unwrap();
        bootstrap_instance(&mut transaction, &request(INSTANCE))
            .await
            .unwrap();
        let waiting = tokio::spawn(async move {
            let mut request = other_request();
            request.instance_id = second_instance;
            let outcome = bootstrap(&mut second, &request).await;
            second.close().await.unwrap();
            outcome
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        assert!(!waiting.is_finished());
        if commit {
            transaction.commit().await.unwrap();
            assert_closed(waiting.await.unwrap());
            assert_eq!(
                recovery_state(&pool).await,
                Some((INSTANCE.into(), true, KEY.to_vec(), 1, 1))
            );
        } else {
            transaction.rollback().await.unwrap();
            let outcome = waiting.await.unwrap().unwrap();
            assert_eq!(outcome.instance_id, second_instance);
            assert_eq!(
                recovery_state(&pool).await,
                Some((second_instance.into(), true, OTHER_KEY.to_vec(), 1, 1))
            );
        }
        first.close().await.unwrap();
        assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
        db.drop([pool]).await;
    }
}

/// The policy row as a service started before bootstrap might leave it:
/// no recovery state, and deployment configuration already mirrored.
async fn seed_policy(pool: &PgPool, instance_id: &str) {
    sqlx::query(
        "INSERT INTO instance_security_policy (instance_id, single_actor_mode) VALUES ($1, true)",
    )
    .bind(instance_id)
    .execute(pool)
    .await
    .unwrap();
}

/// With a policy row and no recovery state, bootstrap adopts the row: it
/// keeps the stored instance ID, which the outcome and the event's
/// `object_id` carry, and leaves the row unchanged. A request with another
/// instance ID is `InstanceIdMismatch`, naming neither ID, and writes
/// nothing; bootstrap stays open.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bootstrap_adopts_a_policy_row_written_before_it() {
    let (db, pool) = migrated().await;
    seed_policy(&pool, INSTANCE).await;
    let seeded = registry::get_instance_security_policy(&pool).await.unwrap();

    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let err = bootstrap_instance(&mut transaction, &request(OTHER_INSTANCE))
        .await
        .unwrap_err();
    assert!(matches!(err, BootstrapError::InstanceIdMismatch), "{err:?}");
    for text in [err.to_string(), format!("{err:?}")] {
        for id in [INSTANCE, OTHER_INSTANCE, "019a9f3c"] {
            assert!(!text.contains(id), "{text}");
        }
    }
    assert_eq!(format!("{err:?}"), "InstanceIdMismatch");
    // Nothing was written, and the transaction is usable.
    assert_eq!(counts(&mut transaction).await, [1, 0, 0, 0, 0, 0, 0]);
    transaction.rollback().await.unwrap();
    drop(connection);
    assert_eq!(pool_counts(&pool).await, [1, 0, 0, 0, 0, 0, 0]);

    let outcome = bootstrap_on(&pool, &request(INSTANCE)).await.unwrap();
    assert_eq!(outcome.instance_id, INSTANCE);
    assert_eq!(outcome.audit_event.object_id, INSTANCE);
    assert_eq!(outcome.audit_event.new_revision, Some(1));
    assert_eq!(
        registry::get_instance_security_policy(&pool).await.unwrap(),
        seeded
    );
    assert!(seeded.single_actor_mode);
    assert_eq!(
        recovery_state(&pool).await,
        Some((INSTANCE.into(), true, KEY.to_vec(), 1, 1))
    );
    assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
    // Now closed: a mismatching request is AlreadyClosed, not a mismatch.
    assert_closed(bootstrap_on(&pool, &request(OTHER_INSTANCE)).await);
    db.drop([pool]).await;
}

/// A recovery state row whose `bootstrap_closed` is false, which only a
/// write by other means can leave, still closes bootstrap: `AlreadyClosed`
/// for the stored instance ID and for another, and nothing changes.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_recovery_state_not_marked_closed_still_closes_bootstrap() {
    let (db, pool) = migrated().await;
    seed_policy(&pool, INSTANCE).await;
    sqlx::query(
        "INSERT INTO recovery_state \
         (instance_id, bootstrap_closed, recovery_public_key, recovery_key_epoch) \
         VALUES ($1, false, $2, 1)",
    )
    .bind(INSTANCE)
    .bind(&KEY[..])
    .execute(&pool)
    .await
    .unwrap();
    let before = state(&pool).await;
    assert_closed(bootstrap_on(&pool, &request(INSTANCE)).await);
    assert_closed(bootstrap_on(&pool, &request(OTHER_INSTANCE)).await);
    assert_eq!(state(&pool).await, before);
    assert_eq!(pool_counts(&pool).await, [1, 1, 0, 0, 0, 0, 0]);
    db.drop([pool]).await;
}

/// With a policy row, the second of two bootstraps waits for the first's
/// row lock and then finds the first's committed recovery state. It is
/// `AlreadyClosed` also with another instance ID: closure is read after
/// the lock, before the adopt rule, so the second never sees the open
/// state it would have seen before the lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_bootstrap_waits_for_the_policy_lock_then_is_closed() {
    for second_instance in [INSTANCE, OTHER_INSTANCE] {
        let (db, pool) = migrated().await;
        seed_policy(&pool, INSTANCE).await;
        let mut first = pool.acquire().await.unwrap().detach();
        let mut second = pool.acquire().await.unwrap().detach();
        let (first_pid, second_pid) = (
            backend_pid(&mut first).await,
            backend_pid(&mut second).await,
        );
        let mut transaction = first.begin().await.unwrap();
        bootstrap_instance(&mut transaction, &request(INSTANCE))
            .await
            .unwrap();
        let waiting = tokio::spawn(async move {
            let mut request = other_request();
            request.instance_id = second_instance;
            let outcome = bootstrap(&mut second, &request).await;
            second.close().await.unwrap();
            outcome
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        transaction.commit().await.unwrap();
        assert_closed(waiting.await.unwrap());
        first.close().await.unwrap();
        assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
        db.drop([pool]).await;
    }
}

/// A bootstrap whose snapshot predates another bootstrap's commit does not
/// see the recovery state, adopts the policy row (the other bootstrap only
/// locked it) and then collides with the committed recovery state. When
/// the committed bootstrap ran under `READ COMMITTED`, that is still
/// `AlreadyClosed` under `REPEATABLE READ` and under `SERIALIZABLE`,
/// through the unique key of the recovery state (`recovery_state_pkey`,
/// the key both rows share). When both ran under `SERIALIZABLE`, the late
/// one fails with `40001` instead: `Retry`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_stale_snapshot_bootstrap_is_still_closed() {
    for (first, isolation) in [
        ("READ COMMITTED", "REPEATABLE READ"),
        ("READ COMMITTED", "SERIALIZABLE"),
        ("SERIALIZABLE", "SERIALIZABLE"),
    ] {
        let (db, pool) = migrated().await;
        seed_policy(&pool, INSTANCE).await;
        let mut late = pool.acquire().await.unwrap().detach();
        let mut transaction = late.begin().await.unwrap();
        set_isolation(&mut transaction, isolation).await;
        let mut committed = pool.acquire().await.unwrap();
        bootstrap_at(&mut committed, first, &request(INSTANCE))
            .await
            .unwrap();
        drop(committed);
        let mut request = other_request();
        request.instance_id = INSTANCE;
        let outcome = bootstrap_instance(&mut transaction, &request).await;
        transaction.rollback().await.unwrap();
        if first == "SERIALIZABLE" {
            assert!(
                matches!(&outcome, Err(BootstrapError::Store(err))
                    if format!("{err:?}") == r#"Retry { sqlstate: Some("40001"), .. }"#),
                "{outcome:?}"
            );
        } else {
            assert_closed(outcome);
        }
        late.close().await.unwrap();
        assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
        db.drop([pool]).await;
    }
}

/// Another writer, such as a startup path, inserts only a policy row and
/// holds its transaction open while a bootstrap on the empty database
/// waits on that row's unique entry (seen with `pg_blocking_pids`). Under
/// `READ COMMITTED`, once the writer commits, the bootstrap's insert inserts
/// nothing and it adopts the committed row: it bootstraps with the same
/// instance ID and is `InstanceIdMismatch` with another, never
/// `AlreadyClosed`. Under `REPEATABLE READ` its snapshot cannot see the
/// row: `Retry`, after which the whole transaction, retried, adopts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_policy_row_committed_while_bootstrap_waits_is_adopted() {
    for (writer_instance, isolation) in [
        (INSTANCE, "READ COMMITTED"),
        (OTHER_INSTANCE, "READ COMMITTED"),
        (INSTANCE, "REPEATABLE READ"),
    ] {
        let (db, pool) = migrated().await;
        let mut writer = pool.acquire().await.unwrap().detach();
        let mut waiter = pool.acquire().await.unwrap().detach();
        let (writer_pid, waiter_pid) = (
            backend_pid(&mut writer).await,
            backend_pid(&mut waiter).await,
        );
        let mut transaction = writer.begin().await.unwrap();
        sqlx::query("INSERT INTO instance_security_policy (instance_id) VALUES ($1)")
            .bind(writer_instance)
            .execute(&mut *transaction)
            .await
            .unwrap();
        let waiting = tokio::spawn(async move {
            let outcome = bootstrap_at(&mut waiter, isolation, &request(INSTANCE)).await;
            (waiter, outcome)
        });
        wait_until_blocked(&pool, waiter_pid, writer_pid).await;
        assert!(!waiting.is_finished());
        transaction.commit().await.unwrap();
        let (mut waiter, outcome) = waiting.await.unwrap();
        let written = registry::get_instance_security_policy(&pool).await.unwrap();
        assert_eq!(
            (&written.instance_id[..], written.revision),
            (writer_instance, 1)
        );
        match (writer_instance, isolation) {
            (INSTANCE, "READ COMMITTED") => {
                let outcome = outcome.unwrap();
                assert_eq!(outcome.instance_id, INSTANCE);
                assert_eq!(outcome.audit_event.object_id, INSTANCE);
                assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
            }
            (OTHER_INSTANCE, _) => {
                let err = outcome.unwrap_err();
                assert!(matches!(err, BootstrapError::InstanceIdMismatch), "{err:?}");
                assert_eq!(pool_counts(&pool).await, [1, 0, 0, 0, 0, 0, 0]);
            }
            _ => {
                assert_retry(outcome);
                assert_eq!(pool_counts(&pool).await, [1, 0, 0, 0, 0, 0, 0]);
                // The whole transaction, retried, adopts the row.
                let outcome = bootstrap_at(&mut waiter, isolation, &request(INSTANCE))
                    .await
                    .unwrap();
                assert_eq!(outcome.instance_id, INSTANCE);
                assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
            }
        }
        assert_eq!(
            registry::get_instance_security_policy(&pool).await.unwrap(),
            written
        );
        waiter.close().await.unwrap();
        writer.close().await.unwrap();
        db.drop([pool]).await;
    }
}

/// An event that is not bootstrap's, as the startup path might write.
fn earlier_event(id: &str) -> NewAuditEvent {
    NewAuditEvent {
        id: id.into(),
        tenant_id: None,
        timestamp: stored_now(),
        actor: AuditActor::System,
        action: "instance_security_policy.mirror".into(),
        object_id: INSTANCE.into(),
        previous_revision: None,
        new_revision: None,
        outcome: "success".into(),
    }
}

/// Appends and commits [`earlier_event`] `id`.
async fn append_earlier(pool: &PgPool, id: &str) {
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    append_audit_event(&mut transaction, &earlier_event(id))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// A failed audit append, here a duplicate event ID that fails the event
/// insert, fails the bootstrap; once the caller rolls back, no policy row,
/// recovery state or operator remains, and bootstrap is still open.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_audit_append_leaves_nothing_after_rollback() {
    let (db, pool) = migrated().await;
    // An earlier event holds the ID bootstrap will use.
    append_earlier(&pool, "aud_bootstrap").await;
    let before = state(&pool).await;

    assert_store_exists(
        bootstrap_on(&pool, &request(INSTANCE)).await,
        "audit_event_pkey",
    );
    assert_eq!(state(&pool).await, before);
    assert_eq!(pool_counts(&pool).await, [0, 0, 0, 0, 0, 1, 0]);
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:first").await,
        None
    );

    // Bootstrap is still open.
    let mut fresh = request(INSTANCE);
    fresh.audit_event_id = "aud_bootstrap_ok";
    let outcome = bootstrap_on(&pool, &fresh).await.unwrap();
    assert_eq!(outcome.audit_event.sequence, 2);
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// Bootstrap rolls back its own savepoint on every error, also one the
/// audit writer returns in Rust after the head lock (here, a head at
/// `2^53 - 1` leaves no sequence for the event). A caller that commits
/// anyway commits none of bootstrap's rows, and the head is unchanged.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_caller_that_commits_after_an_error_commits_nothing() {
    let (db, pool) = migrated().await;
    sqlx::raw_sql(
        "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
         UPDATE audit_chain_head SET sequence = 9007199254740991, \
             head_hash = decode(repeat('cd', 32), 'hex'); \
         ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER audit_chain_head_advance",
    )
    .execute(&pool)
    .await
    .unwrap();
    let before = state(&pool).await;

    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    assert_encode(
        bootstrap_instance(&mut transaction, &request(INSTANCE)).await,
        "audit integer above 2^53 - 1",
    );
    // The transaction is usable and holds none of bootstrap's rows.
    usable_and_empty(&mut transaction).await;
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(state(&pool).await, before);
    assert_eq!(pool_counts(&pool).await, [0; 7]);
    assert!(recovery_state(&pool).await.is_none());
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:first").await,
        None
    );
    db.drop([pool]).await;
}

/// Whether the backend `pid` holds or waits for any lock on `table`.
async fn locks_on(pool: &PgPool, pid: i32, table: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM pg_locks WHERE pid = $1 AND relation = $2::regclass)",
    )
    .bind(pid)
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The audit append is the last step: while another transaction holds the
/// chain head, a bootstrap waits for it having already written the policy
/// row, the recovery state and the three operator rows (it holds their
/// tables' locks). Once the head is released it appends after the other
/// event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_audit_append_is_the_last_step() {
    let (db, pool) = migrated().await;
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut waiter = pool.acquire().await.unwrap().detach();
    let (holder_pid, waiter_pid) = (
        backend_pid(&mut holder).await,
        backend_pid(&mut waiter).await,
    );
    let mut transaction = holder.begin().await.unwrap();
    append_audit_event(&mut transaction, &earlier_event("aud_earlier"))
        .await
        .unwrap();
    let waiting = tokio::spawn(async move {
        let outcome = bootstrap(&mut waiter, &request(INSTANCE)).await;
        waiter.close().await.unwrap();
        outcome
    });
    wait_until_blocked(&pool, waiter_pid, holder_pid).await;
    for table in [
        "instance_security_policy",
        "recovery_state",
        "admin_identity",
        "admin_credential",
        "admin_role_binding",
        "audit_chain_head",
    ] {
        assert!(locks_on(&pool, waiter_pid, table).await, "{table}");
    }
    transaction.commit().await.unwrap();
    let outcome = waiting.await.unwrap().unwrap();
    assert_eq!(outcome.audit_event.sequence, 2);
    holder.close().await.unwrap();
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// `now` must lie in the years the audit writer accepts,
/// `0000-01-01T00:00:00.000000Z` to `9999-12-31T23:59:59.999999Z`; one
/// microsecond outside either bound, or a time inside the `0007` range but
/// past the year 9999, is refused with the writer's message before any
/// statement: nothing is written, the chain head is unchanged and the
/// transaction stays usable. Both bounds bootstrap.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn now_outside_the_audit_years_writes_nothing() {
    const EARLIEST: u64 = 62_167_219_200_000_000;
    const LATEST: u64 = 253_402_300_799_999_999;
    let (db, pool) = migrated().await;
    append_earlier(&pool, "aud_earlier").await;
    let before = state(&pool).await;
    let read_head = "SELECT sequence, head_hash FROM audit_chain_head";
    let committed_head: (i64, Vec<u8>) = sqlx::query_as(read_head).fetch_one(&pool).await.unwrap();

    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    for now in [
        UNIX_EPOCH - Duration::from_micros(EARLIEST + 1),
        UNIX_EPOCH - Duration::from_micros(EARLIEST) - Duration::from_nanos(1),
        UNIX_EPOCH + Duration::from_micros(LATEST + 1),
        UNIX_EPOCH + Duration::from_secs(253_402_300_800),
    ] {
        let mut late = request(INSTANCE);
        late.now = now;
        assert_encode(
            bootstrap_instance(&mut transaction, &late).await,
            "audit timestamp outside the years 0000 to 9999",
        );
        assert_eq!(
            counts(&mut transaction).await,
            [0, 0, 0, 0, 0, 1, 0],
            "{now:?}"
        );
        let in_transaction: (i64, Vec<u8>) = sqlx::query_as(read_head)
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        assert_eq!(in_transaction, committed_head, "{now:?}");
    }
    // The earliest time bootstraps in the same transaction.
    let mut earliest = request(INSTANCE);
    earliest.now = UNIX_EPOCH - Duration::from_micros(EARLIEST);
    let outcome = bootstrap_instance(&mut transaction, &earliest)
        .await
        .unwrap();
    assert_eq!(outcome.audit_event.timestamp, earliest.now);
    transaction.rollback().await.unwrap();
    drop(connection);
    assert_eq!(state(&pool).await, before);

    // So does the latest, with nanoseconds truncated.
    let mut latest = request(INSTANCE);
    latest.now = UNIX_EPOCH + Duration::from_micros(LATEST) + Duration::from_nanos(999);
    let outcome = bootstrap_on(&pool, &latest).await.unwrap();
    assert_eq!(
        outcome.audit_event.timestamp,
        UNIX_EPOCH + Duration::from_micros(LATEST)
    );
    assert_eq!(
        registry::get_admin_identity(&pool, "adm_first")
            .await
            .unwrap()
            .created_at,
        UNIX_EPOCH + Duration::from_micros(LATEST)
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// Input checked before any statement: the transaction stays usable and
/// holds nothing. Every one of these would otherwise bootstrap, since the
/// database accepts any non-empty instance ID and a key of 1 to 8192 bytes,
/// a point or not.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bad_input_is_refused_before_any_statement() {
    let (db, pool) = migrated().await;
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();

    for admin_id in [DEPLOYMENT_OPERATOR_ACTOR, "recovery_key:1", "recovery_key:"] {
        let mut reserved = request(INSTANCE);
        reserved.admin_id = admin_id;
        let err = bootstrap_instance(&mut transaction, &reserved)
            .await
            .unwrap_err();
        assert!(
            matches!(err, BootstrapError::Store(RegistryError::ReservedActorId)),
            "{err:?}"
        );
        usable_and_empty(&mut transaction).await;
    }

    for instance_id in [
        // Version 4.
        "019a9f3c-5b2e-4c41-9d8e-0123456789ab",
        // Upper case.
        "019A9F3C-5B2E-7C41-9D8E-0123456789AB",
        // Variant bits 11.
        "019a9f3c-5b2e-7c41-cd8e-0123456789ab",
        // Variant bits 0x.
        "019a9f3c-5b2e-7c41-7d8e-0123456789ab",
        "019a9f3c5b2e7c419d8e0123456789ab",
        "instance-1",
    ] {
        assert_encode(
            bootstrap_instance(&mut transaction, &request(instance_id)).await,
            "instance ID is not a lowercase hyphenated UUIDv7",
        );
        usable_and_empty(&mut transaction).await;
    }

    for length in [0, 31, 33, 64] {
        let key = vec![9; length];
        let mut bad = request(INSTANCE);
        bad.recovery_public_key = &key;
        assert_encode(
            bootstrap_instance(&mut transaction, &bad).await,
            "recovery public key is not a 32-byte Ed25519 key",
        );
        usable_and_empty(&mut transaction).await;
    }

    // 32 bytes that are not a canonically encoded point of large order: the
    // identity, the point of order 2, the order-4 point `y = 0`, the
    // identity as `y = p + 1`, a point of large order as `y = p + 3`, and
    // bytes that decode to no point.
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut order_two = [0xff; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    let mut identity_p_plus_1 = [0xff; 32];
    identity_p_plus_1[0] = 0xee;
    identity_p_plus_1[31] = 0x7f;
    let mut large_p_plus_3 = identity_p_plus_1;
    large_p_plus_3[0] = 0xf0;
    for (key, message) in [
        (
            identity,
            "recovery public key is a small-order Ed25519 point",
        ),
        (
            order_two,
            "recovery public key is a small-order Ed25519 point",
        ),
        (
            [0; 32],
            "recovery public key is a small-order Ed25519 point",
        ),
        (
            identity_p_plus_1,
            "recovery public key is not canonically encoded",
        ),
        (
            large_p_plus_3,
            "recovery public key is not canonically encoded",
        ),
        ([7; 32], "recovery public key is not an Ed25519 point"),
    ] {
        let mut bad = request(INSTANCE);
        bad.recovery_public_key = &key;
        assert_encode(bootstrap_instance(&mut transaction, &bad).await, message);
        usable_and_empty(&mut transaction).await;
    }

    let long = "k".repeat(2049);
    for (public_identity, trust_anchor_ref, message) in [
        ("", "anchor", "public identity is empty or over 2048 bytes"),
        (
            &long[..],
            "anchor",
            "public identity is empty or over 2048 bytes",
        ),
        (
            "key",
            "",
            "trust anchor reference is empty or over 2048 bytes",
        ),
        (
            "key",
            &long[..],
            "trust anchor reference is empty or over 2048 bytes",
        ),
    ] {
        let mut bad = request(INSTANCE);
        bad.public_identity = public_identity;
        bad.trust_anchor_ref = trust_anchor_ref;
        assert_encode(bootstrap_instance(&mut transaction, &bad).await, message);
        usable_and_empty(&mut transaction).await;
    }

    let mut far = request(INSTANCE);
    far.now = UNIX_EPOCH + Duration::from_micros(u64::try_from(i64::MAX).unwrap());
    assert_encode(
        bootstrap_instance(&mut transaction, &far).await,
        "timestamp out of range",
    );
    usable_and_empty(&mut transaction).await;

    // The same transaction then bootstraps.
    bootstrap_instance(&mut transaction, &request(INSTANCE))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(pool_counts(&pool).await, [1, 1, 1, 1, 1, 1, 0]);
    db.drop([pool]).await;
}

/// Before bootstrap an operator exists (written by other means) whose
/// credential is revoked. Bootstrap cannot re-enroll that credential's key,
/// nor reuse any ID of its rows: each collision is the ordinary
/// `AlreadyExists` naming the constraint, never `AlreadyClosed`, and after
/// the rollback bootstrap is still open.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn collisions_of_caller_ids_stay_already_exists() {
    let (db, pool) = migrated().await;
    registry::test_support::create_admin_identity(
        &pool,
        &NewAdminIdentity {
            id: "adm_old".into(),
            status: Status::Enabled,
            created_at: stored_now(),
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_credential(
        &pool,
        &NewAdminCredential {
            id: "crd_old".into(),
            admin_id: "adm_old".into(),
            public_identity: "spki-sha256:revoked".into(),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_role_binding(
        &pool,
        &NewAdminRoleBinding {
            id: "rb_old".into(),
            admin_id: "adm_old".into(),
            role: AdminRole::Auditor,
            tenant_id: None,
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::revoke_admin_credential(&pool, "crd_old", stored_now())
        .await
        .unwrap();
    let before = state(&pool).await;

    let mut revoked_key = request(INSTANCE);
    revoked_key.public_identity = "spki-sha256:revoked";
    let mut admin = request(INSTANCE);
    admin.admin_id = "adm_old";
    let mut credential = request(INSTANCE);
    credential.credential_id = "crd_old";
    let mut binding = request(INSTANCE);
    binding.binding_id = "rb_old";
    for (colliding, constraint) in [
        (revoked_key, "admin_credential_public_identity_key"),
        (admin, "admin_identity_pkey"),
        (credential, "admin_credential_pkey"),
        (binding, "admin_role_binding_pkey"),
    ] {
        assert_store_exists(bootstrap_on(&pool, &colliding).await, constraint);
        assert_eq!(state(&pool).await, before, "{constraint}");
    }
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:revoked").await,
        None
    );
    assert!(recovery_state(&pool).await.is_none());
    // Still open.
    bootstrap_on(&pool, &request(INSTANCE)).await.unwrap();
    db.drop([pool]).await;
}
