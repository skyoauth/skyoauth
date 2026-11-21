//! The assertion-consume primitive of the registry
//! (`persistence::registry::consume_assertion` and
//! `consume_assertion_set`, over `consumed_assertion` of `0005`) against a
//! real PostgreSQL server: consumption and replay, key independence,
//! concurrent consumers under `READ COMMITTED`, all-or-none sets on a pool
//! and in a caller transaction, rejections before the statement, tenant
//! crossing through the composite foreign key, and the constraint mapping.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database.

mod common;

use std::{
    fmt::Debug,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, AssertionProfile, Consumption, InvariantKind, JsonObject, MAX_ASSERTION_SET,
        NewConsumedAssertion, NewTenant, NewTrustSource, RegistryError, ReplayMode, Status,
        TrustSourceKind,
    },
};
use sqlx::{Connection, PgConnection, postgres::PgPoolOptions};
use tokio::sync::Barrier;

/// 2026-01-02T03:04:05.678901Z, in microseconds from the Unix epoch.
const T0: i64 = 1_767_323_045_678_901;

fn at(micros: i64) -> SystemTime {
    let offset = Duration::from_micros(micros.unsigned_abs());
    if micros >= 0 {
        UNIX_EPOCH + offset
    } else {
        UNIX_EPOCH - offset
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

fn oidc_source(tenant_id: &str, id: &str) -> NewTrustSource {
    NewTrustSource {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: format!("github-{id}"),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: "https://token.actions.githubusercontent.com".into(),
        discovery_url: Some(
            "https://token.actions.githubusercontent.com/.well-known/openid-configuration".into(),
        ),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: vec!["https://identity.example.com".into()],
        algorithms: Some(vec!["RS256".into()]),
        proof_bounds: JsonObject::new(),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    }
}

/// Tenants `ten_a` and `ten_b`; sources `src_a` and `src_a2` of `ten_a` and
/// `src_b` of `ten_b`.
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    for tenant in ["ten_a", "ten_b"] {
        registry::create_tenant(
            &pool,
            &NewTenant {
                id: tenant.into(),
                name: format!("Tenant {tenant}"),
                secret_namespace: format!("ns_{tenant}"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    for (tenant, source) in [("ten_a", "src_a"), ("ten_a", "src_a2"), ("ten_b", "src_b")] {
        registry::create_trust_source(&pool, &oidc_source(tenant, source))
            .await
            .unwrap();
    }
    (db, pool)
}

/// A row of `source` in `tenant` whose 32-byte digest is `digest` repeated,
/// under digest-key `version`, consumed at `T0` and kept ten minutes.
fn proof(tenant: &str, source: &str, digest: u8, version: &str) -> NewConsumedAssertion {
    NewConsumedAssertion {
        tenant_id: tenant.into(),
        trust_source_id: source.into(),
        replay_key_digest: vec![digest; 32],
        digest_key_version: version.into(),
        consumed_at: at(T0),
        retain_until: at(T0 + 600_000_000),
    }
}

/// A stored row: tenant, source, digest, version, consumed_at and
/// retain_until in microseconds.
type Row = (String, String, Vec<u8>, String, i64, i64);

fn stored(new: &NewConsumedAssertion) -> Row {
    let micros = |time: SystemTime| {
        i64::try_from(time.duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap()
    };
    (
        new.tenant_id.clone(),
        new.trust_source_id.clone(),
        new.replay_key_digest.clone(),
        new.digest_key_version.clone(),
        micros(new.consumed_at),
        micros(new.retain_until),
    )
}

/// Every row of `consumed_assertion`, in key order.
async fn rows(pool: &PgPool) -> Vec<Row> {
    sqlx::query_as(
        "SELECT tenant_id::text, trust_source_id::text, replay_key_digest,
                digest_key_version::text,
                (extract(epoch FROM consumed_at) * 1000000)::bigint,
                (extract(epoch FROM retain_until) * 1000000)::bigint
           FROM consumed_assertion
          ORDER BY tenant_id COLLATE \"C\", trust_source_id COLLATE \"C\", replay_key_digest",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[track_caller]
fn assert_invariant<T: Debug>(result: Result<T, RegistryError>, kind: InvariantKind, name: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: actual,
            constraint: Some(constraint),
        }) => assert_eq!((actual, constraint), (kind, name)),
        other => panic!("expected {kind:?} {name}: {other:?}"),
    }
}

/// An encode error with `message`, returned before any statement.
#[track_caller]
fn assert_encode<T: Debug>(result: Result<T, RegistryError>, message: &str) {
    match result {
        Err(RegistryError::Other(sqlx::Error::Encode(err))) => {
            assert_eq!(err.to_string(), message);
        }
        other => panic!("expected the encode error {message:?}: {other:?}"),
    }
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
    .expect("the second consumer never waited for the first");
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// Two detached connections of `pool` and their backend PIDs.
async fn two_connections(pool: &PgPool) -> ((PgConnection, i32), (PgConnection, i32)) {
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let level: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(&mut second)
        .await
        .unwrap();
    assert_eq!(level, "read committed");
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    ((first, first_pid), (second, second_pid))
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_proof_is_consumed_once_and_a_replay_leaves_its_row_unchanged() {
    let (db, pool) = seeded().await;
    let first = proof("ten_a", "src_a", 1, "dk_1");
    assert_eq!(
        registry::consume_assertion(&pool, &first).await.unwrap(),
        Consumption::Consumed
    );
    assert_eq!(rows(&pool).await, [stored(&first)]);
    // The same key with other values: a replay that overwrites nothing.
    let mut again = first.clone();
    again.digest_key_version = "dk_2".into();
    again.consumed_at = at(T0 + 1_000_000);
    again.retain_until = at(T0 + 3_600_000_000);
    for replay in [&first, &again] {
        assert_eq!(
            registry::consume_assertion(&pool, replay).await.unwrap(),
            Consumption::Replay
        );
        assert_eq!(
            registry::consume_assertion_set(&pool, std::slice::from_ref(replay))
                .await
                .unwrap(),
            Consumption::Replay
        );
    }
    assert_eq!(rows(&pool).await, [stored(&first)]);
    db.drop([pool]).await;
}

/// The key is `(tenant_id, trust_source_id, replay_key_digest)`: the same
/// digest under another source or tenant is another proof. The digest-key
/// version is not part of the key.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_same_digest_under_another_source_or_tenant_is_independent() {
    let (db, pool) = seeded().await;
    let proofs = [
        proof("ten_a", "src_a", 7, "dk_1"),
        proof("ten_a", "src_a2", 7, "dk_1"),
        proof("ten_b", "src_b", 7, "dk_1"),
    ];
    for new in &proofs {
        assert_eq!(
            registry::consume_assertion(&pool, new).await.unwrap(),
            Consumption::Consumed
        );
    }
    assert_eq!(
        rows(&pool).await,
        proofs.iter().map(stored).collect::<Vec<_>>()
    );
    assert_eq!(
        registry::consume_assertion(&pool, &proof("ten_a", "src_a", 7, "dk_9"))
            .await
            .unwrap(),
        Consumption::Replay
    );
    db.drop([pool]).await;
}

/// Of many concurrent consumers of one key, on separate connections and
/// released together, exactly one consumes. The key has no grant column,
/// so consumers acting for different grants race the same way; there is no
/// separate case for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_consumers_of_one_key_have_exactly_one_winner() {
    const CONSUMERS: usize = 8;
    let (db, pool) = seeded().await;
    for round in 0..5u8 {
        let barrier = Arc::new(Barrier::new(CONSUMERS));
        let mut tasks = Vec::new();
        for n in 0..CONSUMERS {
            let mut conn = pool.acquire().await.unwrap().detach();
            let barrier = barrier.clone();
            let mut new = proof("ten_a", "src_a", round, "dk_1");
            new.digest_key_version = format!("dk_{n}");
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let outcome = registry::consume_assertion(&mut conn, &new).await;
                conn.close().await.unwrap();
                outcome
            }));
        }
        let mut outcomes = Vec::new();
        for task in tasks {
            outcomes.push(task.await.unwrap().unwrap());
        }
        let consumed = outcomes
            .iter()
            .filter(|outcome| **outcome == Consumption::Consumed)
            .count();
        assert_eq!((consumed, outcomes.len()), (1, CONSUMERS), "{outcomes:?}");
    }
    assert_eq!(rows(&pool).await.len(), 5);
    db.drop([pool]).await;
}

/// A second consumer waits for the first one's open transaction; it is a
/// replay if the first commits and consumes if the first rolls back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_consumer_waits_for_the_first_and_follows_its_outcome() {
    let (db, pool) = seeded().await;
    for commit in [true, false] {
        let digest = u8::from(commit);
        let ((mut first, first_pid), (mut second, second_pid)) = two_connections(&pool).await;
        let mut tx = first.begin().await.unwrap();
        let new = proof("ten_a", "src_a", digest, "dk_1");
        assert_eq!(
            registry::consume_assertion(&mut *tx, &new).await.unwrap(),
            Consumption::Consumed
        );
        let waiting = tokio::spawn(async move {
            let outcome =
                registry::consume_assertion(&mut second, &proof("ten_a", "src_a", digest, "dk_2"))
                    .await;
            (outcome, second)
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        assert!(!waiting.is_finished());
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        let (outcome, second) = waiting.await.unwrap();
        let expected = if commit {
            Consumption::Replay
        } else {
            Consumption::Consumed
        };
        assert_eq!(outcome.unwrap(), expected);
        // The row is the winner's.
        let versions: Vec<String> = sqlx::query_scalar(
            "SELECT digest_key_version::text FROM consumed_assertion
              WHERE replay_key_digest = $1",
        )
        .bind(vec![digest; 32])
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(versions, [if commit { "dk_1" } else { "dk_2" }]);
        drop((first, second));
    }
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_set_is_consumed_all_or_none_on_a_pool() {
    let (db, pool) = seeded().await;
    // One proof under the current version and a retiring one still
    // draining, the retiring row capped earlier.
    let current = proof("ten_a", "src_a", 1, "dk_2");
    let mut retiring = proof("ten_a", "src_a", 2, "dk_1");
    retiring.retain_until = at(T0 + 60_000_000);
    // Given out of key order: each row keeps its own times.
    assert_eq!(
        registry::consume_assertion_set(&pool, &[retiring.clone(), current.clone()])
            .await
            .unwrap(),
        Consumption::Consumed
    );
    let before = rows(&pool).await;
    assert_eq!(before, [stored(&current), stored(&retiring)]);

    // A replay of any one row writes none of the others, wherever it is.
    let fresh = |digest| proof("ten_a", "src_a", digest, "dk_3");
    for set in [
        vec![fresh(3), retiring.clone()],
        vec![current.clone(), fresh(3)],
        vec![fresh(3), fresh(4), current.clone(), fresh(5)],
    ] {
        assert_eq!(
            registry::consume_assertion_set(&pool, &set).await.unwrap(),
            Consumption::Replay
        );
        assert_eq!(rows(&pool).await, before);
    }
    // A key twice in one set, under another version too, is refused before
    // the statement, not reported as a replay; nothing is written.
    let mut again = fresh(6);
    again.digest_key_version = "dk_4".into();
    assert_encode(
        registry::consume_assertion_set(&pool, &[fresh(6), fresh(7), again]).await,
        "duplicate key in assertion set",
    );
    assert_eq!(rows(&pool).await, before);
    // The largest set is accepted.
    let largest: Vec<_> = (0..MAX_ASSERTION_SET)
        .map(|n| fresh(10 + u8::try_from(n).unwrap()))
        .collect();
    assert_eq!(
        registry::consume_assertion_set(&pool, &largest)
            .await
            .unwrap(),
        Consumption::Consumed
    );
    assert_eq!(rows(&pool).await.len(), 2 + MAX_ASSERTION_SET);
    db.drop([pool]).await;
}

/// Inside a caller transaction the replay's `23505` aborts the
/// transaction: the call still reports the replay, every later statement
/// fails until the caller rolls back, and the rollback undoes the
/// transaction's earlier writes too.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_replayed_set_aborts_the_callers_transaction() {
    let (db, pool) = seeded().await;
    let consumed = proof("ten_a", "src_a", 1, "dk_1");
    registry::consume_assertion(&pool, &consumed).await.unwrap();
    let before = rows(&pool).await;

    let mut tx = pool.begin().await.unwrap();
    let earlier = proof("ten_a", "src_a2", 9, "dk_1");
    assert_eq!(
        registry::consume_assertion(&mut *tx, &earlier)
            .await
            .unwrap(),
        Consumption::Consumed
    );
    assert_eq!(
        registry::consume_assertion_set(
            &mut *tx,
            &[proof("ten_a", "src_a", 2, "dk_2"), consumed.clone()]
        )
        .await
        .unwrap(),
        Consumption::Replay
    );
    let err = sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap_err();
    assert_eq!(
        err.as_database_error()
            .and_then(|err| err.code())
            .as_deref(),
        Some("25P02"),
        "the transaction is aborted"
    );
    tx.rollback().await.unwrap();
    assert_eq!(rows(&pool).await, before);
    db.drop([pool]).await;
}

/// Two concurrent sets that share one key: exactly one wins, and the loser
/// writes none of its rows, the ones it does not share included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_overlapping_sets_have_exactly_one_winner() {
    let (db, pool) = seeded().await;
    for round in 0..5u8 {
        let base = round * 3;
        let sets = [
            vec![
                proof("ten_a", "src_a", base, "dk_1"),
                proof("ten_a", "src_a", base + 1, "dk_1"),
            ],
            vec![
                proof("ten_a", "src_a", base + 1, "dk_1"),
                proof("ten_a", "src_a", base + 2, "dk_1"),
            ],
        ];
        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for set in sets.clone() {
            let mut conn = pool.acquire().await.unwrap().detach();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let outcome = registry::consume_assertion_set(&mut conn, &set).await;
                conn.close().await.unwrap();
                outcome
            }));
        }
        let mut outcomes = Vec::new();
        for task in tasks {
            outcomes.push(task.await.unwrap().unwrap());
        }
        let winner = match outcomes[..] {
            [Consumption::Consumed, Consumption::Replay] => 0,
            [Consumption::Replay, Consumption::Consumed] => 1,
            _ => panic!("{outcomes:?}"),
        };
        let digests: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT replay_key_digest FROM consumed_assertion
              WHERE replay_key_digest = ANY($1) ORDER BY replay_key_digest",
        )
        .bind((base..base + 3).map(|d| vec![d; 32]).collect::<Vec<_>>())
        .fetch_all(&pool)
        .await
        .unwrap();
        let expected: Vec<Vec<u8>> = sets[winner]
            .iter()
            .map(|row| row.replay_key_digest.clone())
            .collect();
        assert_eq!(digests, expected);
    }
    db.drop([pool]).await;
}

/// The loser of two overlapping sets waits for the winner's open
/// transaction and is a replay once it commits. Because a set inserts its
/// rows in primary-key order, it waits on its first shared key without
/// holding a later one, so the winner can still write that later key in
/// the same transaction without a deadlock. The keys differ by digest, then
/// by source under the same digest, so the order must take in the whole key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn overlapping_sets_wait_in_key_order_without_deadlock() {
    let (db, pool) = seeded().await;
    let cases = [
        (
            proof("ten_a", "src_a", 1, "dk_1"),
            proof("ten_a", "src_a", 2, "dk_1"),
        ),
        (
            proof("ten_a", "src_a", 3, "dk_1"),
            proof("ten_a", "src_a2", 3, "dk_1"),
        ),
    ];
    for (k1, k2) in &cases {
        let ((mut first, first_pid), (mut second, second_pid)) = two_connections(&pool).await;
        let mut tx = first.begin().await.unwrap();
        assert_eq!(
            registry::consume_assertion_set(&mut *tx, std::slice::from_ref(k1))
                .await
                .unwrap(),
            Consumption::Consumed
        );
        // Given in reverse key order.
        let set = vec![k2.clone(), k1.clone()];
        let waiting = tokio::spawn(async move {
            let outcome = registry::consume_assertion_set(&mut second, &set).await;
            (outcome, second)
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        assert_eq!(
            registry::consume_assertion_set(&mut *tx, std::slice::from_ref(k2))
                .await
                .unwrap(),
            Consumption::Consumed
        );
        tx.commit().await.unwrap();
        let (outcome, second) = waiting.await.unwrap();
        assert_eq!(outcome.unwrap(), Consumption::Replay);
        drop((first, second));
    }
    let expected: Vec<Row> = cases
        .iter()
        .flat_map(|(k1, k2)| [stored(k1), stored(k2)])
        .collect();
    assert_eq!(rows(&pool).await, expected);
    db.drop([pool]).await;
}

/// Two concurrent sets with the same members given in opposite order: the
/// function sorts them, so neither deadlocks (no `40P01`), and exactly one
/// consumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_sets_in_opposite_order_do_not_deadlock() {
    let (db, pool) = seeded().await;
    for round in 0..20u8 {
        let members = [
            proof("ten_a", "src_a", round * 2, "dk_1"),
            proof("ten_a", "src_a2", round * 2 + 1, "dk_1"),
        ];
        let reversed = vec![members[1].clone(), members[0].clone()];
        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for set in [members.to_vec(), reversed] {
            let mut conn = pool.acquire().await.unwrap().detach();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let outcome = registry::consume_assertion_set(&mut conn, &set).await;
                conn.close().await.unwrap();
                outcome
            }));
        }
        let mut outcomes = Vec::new();
        for task in tasks {
            match task.await.unwrap() {
                Ok(outcome) => outcomes.push(outcome),
                Err(err) => panic!("round {round}: {err:?}"),
            }
        }
        outcomes.sort_by_key(|outcome| *outcome == Consumption::Replay);
        assert_eq!(outcomes, [Consumption::Consumed, Consumption::Replay]);
    }
    assert_eq!(rows(&pool).await.len(), 40);
    db.drop([pool]).await;
}

/// The SQLSTATE of a [`RegistryError::Retry`], or a panic.
#[track_caller]
fn retry_code<T: Debug>(result: Result<T, RegistryError>) -> String {
    match result {
        Err(RegistryError::Retry(err)) => err
            .as_database_error()
            .and_then(|err| err.code())
            .unwrap()
            .into_owned(),
        other => panic!("expected Retry: {other:?}"),
    }
}

/// Begins a transaction at `level` on `pool` and reads `digest`, taking
/// the snapshot.
async fn reading_transaction(
    pool: &PgPool,
    level: &'static str,
    digest: u8,
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(level).execute(&mut *tx).await.unwrap();
    let seen: i64 =
        sqlx::query_scalar("SELECT count(*) FROM consumed_assertion WHERE replay_key_digest = $1")
            .bind(vec![digest; 32])
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(seen, 0);
    tx
}

/// Above `READ COMMITTED` a consumer whose snapshot predates the winner's
/// commit may fail with `40001`, which both functions map to `Retry`.
/// `consume_assertion` (its `ON CONFLICT`) does under `REPEATABLE READ` and
/// `SERIALIZABLE`. `consume_assertion_set` does only when both transactions
/// are serializable and both read the key's range first; otherwise its
/// plain `INSERT` gets `23505` on the committed key, a `Replay`, as under
/// `REPEATABLE READ` here. Both deny.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_serialization_failure_is_retry() {
    const RR: &str = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ";
    const SER: &str = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE";
    let (db, pool) = seeded().await;
    for (level, set, retry) in [
        (RR, false, true),
        (SER, false, true),
        (RR, true, false),
        (SER, true, true),
    ] {
        let digest = u8::try_from(rows(&pool).await.len()).unwrap();
        let mut tx = reading_transaction(&pool, level, digest).await;
        let first = proof("ten_a", "src_a", digest, "dk_1");
        if level == SER {
            let mut winner = reading_transaction(&pool, SER, digest).await;
            registry::consume_assertion_set(&mut *winner, std::slice::from_ref(&first))
                .await
                .unwrap();
            winner.commit().await.unwrap();
        } else {
            registry::consume_assertion(&pool, &first).await.unwrap();
        }
        let late = proof("ten_a", "src_a", digest, "dk_2");
        let outcome = if set {
            registry::consume_assertion_set(&mut *tx, std::slice::from_ref(&late)).await
        } else {
            registry::consume_assertion(&mut *tx, &late).await
        };
        if retry {
            assert_eq!(retry_code(outcome), "40001", "{level}, set: {set}");
        } else {
            assert_eq!(outcome.unwrap(), Consumption::Replay, "{level}, set: {set}");
        }
        tx.rollback().await.unwrap();
    }
    assert_eq!(rows(&pool).await.len(), 4);
    db.drop([pool]).await;
}

/// Two caller transactions that consume two keys in opposite order, in
/// separate calls, deadlock: the victim's call is `Retry` with `40P01`, and
/// the other consumes once the victim rolls back. Both functions are the
/// waiting call in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_deadlock_between_caller_transactions_is_retry() {
    let (db, pool) = seeded().await;
    for (round, waiting_set) in [(0u8, true), (1, false)] {
        let ((mut first, first_pid), (mut second, second_pid)) = two_connections(&pool).await;
        let k1 = proof("ten_a", "src_a", round * 2, "dk_1");
        let k2 = proof("ten_a", "src_a", round * 2 + 1, "dk_1");
        sqlx::query("BEGIN").execute(&mut first).await.unwrap();
        sqlx::query("BEGIN").execute(&mut second).await.unwrap();
        registry::consume_assertion(&mut first, &k1).await.unwrap();
        registry::consume_assertion(&mut second, &k2).await.unwrap();
        let waiting = tokio::spawn({
            let k2 = k2.clone();
            async move {
                let outcome = if waiting_set {
                    registry::consume_assertion_set(&mut first, std::slice::from_ref(&k2)).await
                } else {
                    registry::consume_assertion(&mut first, &k2).await
                };
                let end = if outcome.is_ok() {
                    "COMMIT"
                } else {
                    "ROLLBACK"
                };
                sqlx::query(end).execute(&mut first).await.unwrap();
                outcome
            }
        });
        wait_until_blocked(&pool, first_pid, second_pid).await;
        let closing = if waiting_set {
            registry::consume_assertion(&mut second, &k1).await
        } else {
            registry::consume_assertion_set(&mut second, std::slice::from_ref(&k1)).await
        };
        let end = if closing.is_ok() {
            "COMMIT"
        } else {
            "ROLLBACK"
        };
        sqlx::query(end).execute(&mut second).await.unwrap();
        let waited = waiting.await.unwrap();
        let (victim, winner) = match (waited, closing) {
            (Err(err), Ok(outcome)) | (Ok(outcome), Err(err)) => (err, outcome),
            other => panic!("expected one deadlock victim: {other:?}"),
        };
        assert_eq!(retry_code::<()>(Err(victim)), "40P01");
        // The survivor's second key was the victim's first: it waited for
        // the rollback and consumed it.
        assert_eq!(winner, Consumption::Consumed);
        drop(second);
    }
    // Each round keeps the survivor's two rows.
    assert_eq!(rows(&pool).await.len(), 4);
    db.drop([pool]).await;
}

/// An empty or oversized set, or one with a key twice, fails before any
/// statement: on a closed pool,
/// where any statement fails with `PoolClosed`, it is still the encode
/// error. A store failure is `Other`, which the caller treats as a deny.
#[tokio::test]
async fn empty_oversized_and_duplicate_sets_fail_before_any_statement() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://registry-test.invalid/none")
        .unwrap();
    pool.close().await;
    let row = |n: usize| proof("ten_a", "src_a", u8::try_from(n).unwrap(), "dk_1");
    assert_encode(
        registry::consume_assertion_set(&pool, &[]).await,
        "empty assertion set",
    );
    let oversized: Vec<_> = (0..=MAX_ASSERTION_SET).map(row).collect();
    assert_encode(
        registry::consume_assertion_set(&pool, &oversized).await,
        "assertion set too large",
    );
    // A duplicate is found after sorting, wherever it is in the set.
    let mut twice = row(3);
    twice.digest_key_version = "dk_2".into();
    assert_encode(
        registry::consume_assertion_set(&pool, &[row(3), row(1), row(2), twice]).await,
        "duplicate key in assertion set",
    );
    // At the cap, and for a single row, the call reaches the pool.
    let largest: Vec<_> = (0..MAX_ASSERTION_SET).map(row).collect();
    for err in [
        registry::consume_assertion_set(&pool, &largest)
            .await
            .unwrap_err(),
        registry::consume_assertion(&pool, &row(0))
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(err, RegistryError::Other(sqlx::Error::PoolClosed)),
            "{err:?}"
        );
    }
    // A time the registry cannot write is rejected before the statement too.
    let mut early = row(0);
    early.consumed_at = at(-210_866_803_200_000_001);
    assert_encode(
        registry::consume_assertion(&pool, &early).await,
        "timestamp out of range",
    );
    assert_encode(
        registry::consume_assertion_set(&pool, &[row(1), early]).await,
        "timestamp out of range",
    );
}

/// The composite foreign key `(tenant_id, trust_source_id)` refuses a row of
/// one tenant naming another tenant's source, in both directions, on both
/// functions, and nothing is written.
///
/// This registry test is not the conformance scenario. The scenario is
/// `a24_neg_consume_names_other_tenants_source` in `tests/security/a24.rs`,
/// listed in the A24 M1a stage of `tests/conformance/scenarios.toml`. The
/// A29 closed list has no entry for this crossing: it covers `0004` only,
/// and `tests/security/a29.rs` says this `0005` foreign key is covered by
/// that A24 scenario instead.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn consume_naming_another_tenants_source_is_refused() {
    let (db, pool) = seeded().await;
    for (tenant, source) in [("ten_a", "src_b"), ("ten_b", "src_a")] {
        let crossing = proof(tenant, source, 1, "dk_1");
        assert_invariant(
            registry::consume_assertion(&pool, &crossing).await,
            InvariantKind::ForeignKey,
            "consumed_assertion_trust_source_id_fkey",
        );
        // In a set with a valid row, neither is written.
        let own = if tenant == "ten_a" { "src_a" } else { "src_b" };
        assert_invariant(
            registry::consume_assertion_set(&pool, &[proof(tenant, own, 2, "dk_1"), crossing])
                .await,
            InvariantKind::ForeignKey,
            "consumed_assertion_trust_source_id_fkey",
        );
    }
    assert_eq!(rows(&pool).await, []);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn constraint_errors_map_by_name_and_write_nothing() {
    let (db, pool) = seeded().await;
    let mut empty_window = proof("ten_a", "src_a", 1, "dk_1");
    empty_window.retain_until = empty_window.consumed_at;
    let mut backwards = proof("ten_a", "src_a", 1, "dk_1");
    backwards.retain_until = at(T0 - 1);
    let mut short = proof("ten_a", "src_a", 1, "dk_1");
    short.replay_key_digest = vec![1; 31];
    let mut long = proof("ten_a", "src_a", 1, "dk_1");
    long.replay_key_digest = vec![1; 65];
    let mut no_version = proof("ten_a", "src_a", 1, "dk_1");
    no_version.digest_key_version.clear();
    let mut long_version = proof("ten_a", "src_a", 1, "dk_1");
    long_version.digest_key_version = "v".repeat(256);
    let mut long_tenant = proof("ten_a", "src_a", 1, "dk_1");
    long_tenant.tenant_id = "t".repeat(256);
    let cases = [
        (
            empty_window,
            InvariantKind::Check,
            "consumed_assertion_retention_check",
        ),
        (
            backwards,
            InvariantKind::Check,
            "consumed_assertion_retention_check",
        ),
        (
            short,
            InvariantKind::Check,
            "consumed_assertion_replay_key_digest_octet_length_check",
        ),
        (
            long,
            InvariantKind::Check,
            "consumed_assertion_replay_key_digest_octet_length_check",
        ),
        (
            no_version,
            InvariantKind::Check,
            "consumed_assertion_digest_key_version_check",
        ),
        (
            long_version,
            InvariantKind::Check,
            "consumed_assertion_digest_key_version_octet_length_check",
        ),
        (
            long_tenant,
            InvariantKind::Check,
            "consumed_assertion_tenant_id_octet_length_check",
        ),
        (
            proof("ten_a", "src_missing", 1, "dk_1"),
            InvariantKind::ForeignKey,
            "consumed_assertion_trust_source_id_fkey",
        ),
    ];
    for (new, kind, name) in &cases {
        assert_invariant(registry::consume_assertion(&pool, new).await, *kind, name);
        assert_invariant(
            registry::consume_assertion_set(&pool, std::slice::from_ref(new)).await,
            *kind,
            name,
        );
    }
    assert_eq!(rows(&pool).await, []);

    // The row's checks run before the conflict is looked for: an invalid
    // replay is the check's error.
    registry::consume_assertion(&pool, &proof("ten_a", "src_a", 1, "dk_1"))
        .await
        .unwrap();
    assert_invariant(
        registry::consume_assertion(&pool, &cases[0].0).await,
        InvariantKind::Check,
        "consumed_assertion_retention_check",
    );

    // The range checks cannot be reached through the registry, which
    // rejects such times before the statement; from raw statements they map
    // by name.
    for (sql, name) in [
        (
            "INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', '\\x0202020202020202020202020202020202020202020202020202020202020202', 'dk_1', '-infinity', '2026-01-01Z')",
            "consumed_assertion_consumed_at_range_check",
        ),
        (
            "INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', '\\x0202020202020202020202020202020202020202020202020202020202020202', 'dk_1', '2026-01-01Z', 'infinity')",
            "consumed_assertion_retain_until_range_check",
        ),
    ] {
        let err = sqlx::raw_sql(sql).execute(&pool).await.expect_err(sql);
        assert_invariant::<()>(Err(RegistryError::from(err)), InvariantKind::Check, name);
    }
    assert_eq!(rows(&pool).await.len(), 1);
    db.drop([pool]).await;
}

/// A row is never updated. `0005` rejects every `UPDATE`, an
/// `ON CONFLICT … DO UPDATE` included (`SK001`); a replay through the
/// registry is not rejected, because `DO NOTHING` never updates, and the
/// row stays as it was.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_replay_never_updates_the_row() {
    let (db, pool) = seeded().await;
    let consumed = proof("ten_a", "src_a", 1, "dk_1");
    registry::consume_assertion(&pool, &consumed).await.unwrap();
    let err = sqlx::raw_sql(
        "INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a',
             '\\x0101010101010101010101010101010101010101010101010101010101010101',
             'dk_2', '2026-01-02Z', '2026-01-03Z')
         ON CONFLICT (tenant_id, trust_source_id, replay_key_digest)
         DO UPDATE SET digest_key_version = excluded.digest_key_version",
    )
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(matches!(RegistryError::from(err), RegistryError::Guard));
    let mut replay = consumed.clone();
    replay.digest_key_version = "dk_2".into();
    assert_eq!(
        registry::consume_assertion(&pool, &replay).await.unwrap(),
        Consumption::Replay
    );
    assert_eq!(rows(&pool).await, [stored(&consumed)]);
    db.drop([pool]).await;
}

/// Only a `23505` on `consumed_assertion_pkey` is a replay. The table has
/// no other unique key, so a test-only unique index (in a rolled-back
/// transaction) stands in for one: its violation is an error, here `Other`
/// since the index is not a known constraint, and never a replay.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn another_unique_violation_in_a_set_is_not_a_replay() {
    let (db, pool) = seeded().await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(
        "CREATE UNIQUE INDEX consumed_assertion_version_test_key
             ON consumed_assertion (digest_key_version)",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        registry::consume_assertion_set(&mut *tx, &[proof("ten_a", "src_a", 1, "dk_1")])
            .await
            .unwrap(),
        Consumption::Consumed
    );
    let err = registry::consume_assertion_set(&mut *tx, &[proof("ten_a", "src_a", 2, "dk_1")])
        .await
        .unwrap_err();
    match &err {
        RegistryError::Other(source) => {
            let db_err = source.as_database_error().expect("a database error");
            assert_eq!(
                (db_err.code().as_deref(), db_err.constraint()),
                (Some("23505"), Some("consumed_assertion_version_test_key"))
            );
        }
        other => panic!("expected Other: {other:?}"),
    }
    tx.rollback().await.unwrap();
    assert_eq!(rows(&pool).await, []);
    db.drop([pool]).await;
}

/// The registry consumes with `INSERT` alone, the runtime role's only
/// privilege on `consumed_assertion` (migrations README, "Privileges"):
/// the foreign key check runs as the table owner, and neither function
/// names a conflict target, which would need `SELECT` as well.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_consumption_needs_only_insert() {
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "GRANT INSERT ON consumed_assertion TO {role}"
    )))
    .execute(&pool)
    .await
    .unwrap();
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    let one = proof("ten_a", "src_a", 1, "dk_1");
    let set = [
        proof("ten_a", "src_a", 3, "dk_1"),
        proof("ten_a", "src_a", 2, "dk_2"),
    ];
    for expected in [Consumption::Consumed, Consumption::Replay] {
        assert_eq!(
            registry::consume_assertion(&mut writer, &one)
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            registry::consume_assertion_set(&mut writer, &set)
                .await
                .unwrap(),
            expected
        );
    }
    // The foreign key still refuses another tenant's source.
    assert_invariant(
        registry::consume_assertion(&mut writer, &proof("ten_a", "src_b", 4, "dk_1")).await,
        InvariantKind::ForeignKey,
        "consumed_assertion_trust_source_id_fkey",
    );
    // Naming the conflict target needs SELECT: 42501 under this role.
    let err = sqlx::query(
        "INSERT INTO consumed_assertion
             (tenant_id, trust_source_id, replay_key_digest, digest_key_version, consumed_at,
              retain_until)
         VALUES ('ten_a', 'src_a', $1, 'dk_1', now(), now() + interval '1 minute')
         ON CONFLICT (tenant_id, trust_source_id, replay_key_digest) DO NOTHING",
    )
    .bind(vec![5u8; 32])
    .execute(&mut writer)
    .await
    .unwrap_err();
    assert_eq!(
        err.as_database_error()
            .and_then(|err| err.code())
            .as_deref(),
        Some("42501"),
        "{err:?}"
    );
    writer.close().await.unwrap();
    let mut expected = vec![stored(&one), stored(&set[1]), stored(&set[0])];
    expected.sort();
    assert_eq!(rows(&pool).await, expected);
    db.drop([pool]).await;
}
