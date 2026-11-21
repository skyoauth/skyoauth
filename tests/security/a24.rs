//! A24: eligible on-demand single-use proof replay across replicas/grants.
//! Expected: exactly one issuance, missing jti/replay/store failure denied
//! (tasks §8; T10.9, T21.6, T21.8, T52.7).
//!
//! Stage M1a, "consume primitive: one consumption across replica pools;
//! replay and store failure denied (registry API)": the atomic consume
//! primitive of a `single_use` source (`registry::consume_assertion` and
//! `registry::consume_assertion_set`, over `consumed_assertion` of `0005`)
//! against a real PostgreSQL, one fresh database per test, driven by the
//! replica harness (REP, `skyoauth_scenarios::rep`): each replica is a pool
//! of one connection, one backend session, as one service replica with its
//! own pool would be. Two tenants each have one `single_use` source
//! (`on_demand_jwt` on `oidc_discovery`, as the `0004`
//! `trust_source_single_use_replay_check` requires), created through the
//! registry API. Keys are fixed 32-byte digests; the times are fixed
//! constants passed by the test, as the caller passes them (the registry
//! reads no clock).
//!
//! - **Positive.** Of N replicas racing on one key, exactly one consumes and
//!   every other is a replay, and the key has exactly one row, the
//!   winner's: free races (8 replicas, 16 rounds) and forced ones, in which
//!   a holder session consumes in an open transaction until the 3 other
//!   replicas are seen blocked behind it, then commits (all 3 replay) or
//!   rolls back (exactly one of the 3 consumes)
//!   (`a24_pos_one_consumption_across_replica_pools`).
//! - **Negative.** A consumed proof stays consumed: a sequential replay, a
//!   replay with other values (a later `retain_until` included), a replay
//!   of a row past its `retain_until` that was not pruned, and a set with
//!   one consumed member are replays, and none changes or adds a row; two
//!   replicas consuming overlapping sets in opposite member order end with
//!   one winner and no deadlock (`a24_neg_replay_after_consumption`). A
//!   store failure never consumes: a closed pool, a `statement_timeout`
//!   while blocked behind a holder, a holder whose backend is killed while
//!   others wait, a `REPEATABLE READ` serialization failure, a role without
//!   `INSERT`, and an invalid row (empty retention window, digest length)
//!   are errors that write nothing (`a24_neg_store_failure_never_consumes`).
//!   A consume naming another tenant's source, in both directions, or an
//!   unknown tenant or source, is refused by
//!   `consumed_assertion_trust_source_id_fkey` and writes nothing
//!   (`a24_neg_consume_names_other_tenants_source`).
//!
//! **Once per source.** The key is `(tenant_id, trust_source_id,
//! replay_key_digest)`. A tenant that registers the same issuer as two
//! `single_use` sources has two independent replay records: the same digest
//! under the other source is another proof
//! (`a24_neg_replay_after_consumption`). So "exactly one" holds per source,
//! not per issuer. In the service the digest also covers the source ID
//! (migrations README: a keyed digest of `(tenant, source_id,
//! exact_issuer, verified_jti)`), so one assertion presented through both
//! sources yields two different digests in any case.
//!
//! **Not tested: a lost commit acknowledgement.** A crash after the
//! consuming insert commits and before the caller sees the commit burns the
//! proof (ADR-016 item 6: it stays consumed, and a retry needs a fresh
//! assertion). Losing exactly the acknowledgement of a commit that the
//! server applied cannot be injected deterministically from a test: a
//! terminated backend either has committed or has not, and the test cannot
//! choose which. Only the observable halves are tested: a killed holder's
//! uncommitted consumption is rolled back and another replica consumes,
//! and a committed one stays consumed for every later attempt.
//!
//! **The set is plain `INSERT`.** `consume_assertion_set` inserts all rows
//! in one plain `INSERT`, sorted by primary key, and maps a primary-key
//! `23505` to a replay; it deliberately uses no savepoint per row and no
//! `ON CONFLICT`, so a replay of one member writes none of the others, and
//! sets that share keys take their row locks in the same order.
//!
//! Not covered here: the M2 stage (issuance at exchange, one issuance
//! across grants, a missing `jti`, the wire error of OQ-ERR-7, a retry that
//! needs a fresh assertion); digest-key rotation and restore (A35); the
//! function-level contract that `service/tests/registry_assertion.rs`
//! covers (encode errors before any statement, `SERIALIZABLE`, a deadlock
//! between caller transactions, the mapping of every `consumed_assertion`
//! check, the no-update trigger).

use std::{
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use skyoauth_scenarios::{
    pg::TestDb,
    rep::{self, Replicas},
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, AssertionProfile, Consumption, InvariantKind, JsonObject, NewConsumedAssertion,
        NewTenant, NewTrustSource, RegistryError, ReplayMode, Status, TrustSourceKind,
    },
};
use sqlx::{Connection, Postgres, pool::PoolConnection};

const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The composite foreign key `(tenant_id, trust_source_id)` of `0005`.
const SOURCE_FKEY: &str = "consumed_assertion_trust_source_id_fkey";

/// 2026-01-02T03:04:05Z, in seconds from the Unix epoch: the fixed
/// `consumed_at` of every row.
const T0: u64 = 1_767_323_045;

/// The fixed retention window: `retain_until` is `T0` plus ten minutes.
const RETENTION: u64 = 600;

/// The `statement_timeout` of a replica blocked behind a holder: long
/// enough for the harness to observe the wait first.
const TIMEOUT: Duration = Duration::from_secs(2);

/// One of the two tenants and its one `single_use` source.
#[derive(Clone, Copy)]
struct Side {
    tenant: &'static str,
    source: &'static str,
}

const A: Side = Side {
    tenant: "ten_a",
    source: "src_a",
};
const B: Side = Side {
    tenant: "ten_b",
    source: "src_b",
};

/// (owner, intruder): the intruder's consume names the owner's source.
const DIRECTIONS: [(Side, Side); 2] = [(A, B), (B, A)];

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// The fixed 32-byte digest number `n`: `n` in every byte.
fn digest(n: u8) -> Vec<u8> {
    [n; 32].to_vec()
}

/// A `single_use` source: `on_demand_jwt` on `oidc_discovery`.
fn single_use_source(tenant: &str, id: &str, name: &str) -> NewTrustSource {
    NewTrustSource {
        id: id.into(),
        tenant_id: tenant.into(),
        name: name.into(),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: ISSUER.into(),
        discovery_url: Some(format!("{ISSUER}/.well-known/openid-configuration")),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: vec!["https://skyoauth.example".into()],
        algorithms: Some(vec!["RS256".into()]),
        proof_bounds: JsonObject::new(),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    }
}

/// Tenants `ten_a` and `ten_b`, each with its `single_use` source.
async fn two_tenants() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for side in [A, B] {
        registry::create_tenant(
            &pool,
            &NewTenant {
                id: side.tenant.into(),
                name: "Example".into(),
                secret_namespace: format!("ns_{}", side.tenant),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        registry::create_trust_source(
            &pool,
            &single_use_source(side.tenant, side.source, "github"),
        )
        .await
        .unwrap();
    }
    (db, pool)
}

/// Proof `n` of `side`'s source under digest-key `version`, consumed at
/// `T0` and kept for `RETENTION`.
fn proof(side: Side, n: u8, version: &str) -> NewConsumedAssertion {
    NewConsumedAssertion {
        tenant_id: side.tenant.into(),
        trust_source_id: side.source.into(),
        replay_key_digest: digest(n),
        digest_key_version: version.into(),
        consumed_at: at(T0),
        retain_until: at(T0 + RETENTION),
    }
}

/// A stored row: tenant, source, digest, digest-key version, and
/// `consumed_at` and `retain_until` in microseconds.
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
        "SELECT tenant_id::text, trust_source_id::text, replay_key_digest, \
                digest_key_version::text, \
                (extract(epoch FROM consumed_at) * 1000000)::bigint, \
                (extract(epoch FROM retain_until) * 1000000)::bigint \
           FROM consumed_assertion \
          ORDER BY tenant_id COLLATE \"C\", trust_source_id COLLATE \"C\", replay_key_digest",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The digest-key versions of the rows with `side`'s key `n`: which
/// consumer's row exists, if any.
async fn versions(pool: &PgPool, side: Side, n: u8) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT digest_key_version::text FROM consumed_assertion \
          WHERE tenant_id = $1 AND trust_source_id = $2 AND replay_key_digest = $3",
    )
    .bind(side.tenant)
    .bind(side.source)
    .bind(digest(n))
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The replicas whose outcome is `Consumed`; every other outcome must be a
/// `Replay`, and an error fails the test at the caller's line.
#[track_caller]
fn consumed_by(outcomes: Vec<Result<Consumption, RegistryError>>) -> Vec<usize> {
    let mut consumed = Vec::new();
    for (replica, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Ok(Consumption::Consumed) => consumed.push(replica),
            Ok(Consumption::Replay) => {}
            Err(err) => panic!("replica {replica}: {err:?}"),
        }
    }
    consumed
}

#[track_caller]
fn assert_invariant<T: Debug>(result: Result<T, RegistryError>, kind: InvariantKind, name: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: actual,
            constraint: Some(constraint),
        }) => assert_eq!((actual, constraint), (kind, name)),
        other => panic!("expected Invariant {{ {kind:?}, {name} }}: {other:?}"),
    }
}

/// `RegistryError::Other` from a database error with SQLSTATE `code`.
#[track_caller]
fn assert_other_code<T: Debug>(result: Result<T, RegistryError>, code: &str) {
    match result {
        Err(RegistryError::Other(err)) => assert_eq!(
            err.as_database_error()
                .and_then(|err| err.code())
                .as_deref(),
            Some(code),
            "{err:?}"
        ),
        other => panic!("expected Other with SQLSTATE {code}: {other:?}"),
    }
}

/// A holder session outside the replicas: a pool of one connection, that
/// connection, and its backend PID.
async fn holder(db: &TestDb) -> (PgPool, PoolConnection<Postgres>, i32) {
    let pool = db.pool_with_max_connections(1).await;
    let mut conn = pool.acquire().await.unwrap();
    let pid = rep::backend_pid(&mut conn).await;
    (pool, conn, pid)
}

/// Exactly one replica consumes each key, in free races and in races forced
/// behind a holder that commits or rolls back.
#[tokio::test(flavor = "multi_thread")]
async fn a24_pos_one_consumption_across_replica_pools() {
    const REPLICAS: usize = 8;
    const ROUNDS: u8 = 16;
    let (db, pool) = two_tenants().await;

    // Free races: N replicas released together on one key per round, each
    // writing its own digest-key version, so the row names the winner.
    let replicas = Replicas::start(&db, REPLICAS).await;
    for round in 0..ROUNDS {
        let outcomes = replicas
            .race(move |replica, mut conn| {
                let new = proof(A, round, &format!("dk_r{replica}"));
                async move { registry::consume_assertion(&mut *conn, &new).await }
            })
            .await;
        assert_eq!(outcomes.len(), REPLICAS);
        let winners = consumed_by(outcomes);
        assert_eq!(winners.len(), 1, "round {round}: winners {winners:?}");
        // The other N-1 were replays (`winners` unwrapped every outcome).
        assert_eq!(
            versions(&pool, A, round).await,
            [format!("dk_r{}", winners[0])],
            "round {round}"
        );
    }
    assert_eq!(rows(&pool).await.len(), usize::from(ROUNDS));

    // Forced races: 4 replica sessions, a holder and 3 waiters. The holder
    // consumes in an open transaction; the waiters start only then and are
    // seen blocked behind it before it ends.
    let (holder_pool, mut holder_conn, holder_pid) = holder(&db).await;
    let waiters = Replicas::start(&db, 3).await;
    let pids = waiters.backend_pids().await;
    for (n, commit) in [(100u8, true), (101, false)] {
        let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
        assert_eq!(
            registry::consume_assertion(&mut *tx, &proof(A, n, "dk_holder"))
                .await
                .unwrap(),
            Consumption::Consumed
        );
        let release = async {
            rep::wait_until_blocked(&pool, &pids, holder_pid).await;
            if commit {
                tx.commit().await.unwrap();
            } else {
                tx.rollback().await.unwrap();
            }
        };
        let (outcomes, ()) = tokio::join!(
            waiters.race(move |replica, mut conn| {
                let new = proof(A, n, &format!("dk_w{replica}"));
                async move { registry::consume_assertion(&mut *conn, &new).await }
            }),
            release
        );
        let winners = consumed_by(outcomes);
        if commit {
            // The holder's commit wins: all 3 waiters replay.
            assert_eq!(winners, Vec::<usize>::new());
            assert_eq!(versions(&pool, A, n).await, ["dk_holder"]);
        } else {
            // The rollback frees the key: exactly one waiter consumes.
            assert_eq!(winners.len(), 1, "{winners:?}");
            assert_eq!(versions(&pool, A, n).await, [format!("dk_w{}", winners[0])]);
        }
    }
    assert_eq!(rows(&pool).await.len(), usize::from(ROUNDS) + 2);
    drop(holder_conn);
    let pools = [pool, holder_pool]
        .into_iter()
        .chain(replicas.into_pools())
        .chain(waiters.into_pools());
    db.drop(pools).await;
}

/// A consumed proof stays consumed, whatever the replay carries and however
/// long after; a set with one consumed member writes nothing; the same
/// digest under another source is another proof; overlapping sets in
/// opposite order have one winner and do not deadlock.
#[tokio::test(flavor = "multi_thread")]
async fn a24_neg_replay_after_consumption() {
    let (db, pool) = two_tenants().await;

    // Sequential replay, through both functions.
    let first = proof(A, 1, "dk_1");
    assert_eq!(
        registry::consume_assertion(&pool, &first).await.unwrap(),
        Consumption::Consumed
    );
    // The same key with another digest-key version, a later consumed_at and
    // a later retain_until.
    let mut later = first.clone();
    later.digest_key_version = "dk_2".into();
    later.consumed_at = at(T0 + 60);
    later.retain_until = at(T0 + 86_400);
    // The same key at explicit times after the row's retain_until: the
    // registry has no "now", and an unpruned row still counts.
    let mut expired = first.clone();
    expired.consumed_at = at(T0 + RETENTION + 1);
    expired.retain_until = at(T0 + 2 * RETENTION);
    for replay in [&first, &later, &expired] {
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
    // The first row is unchanged: version, consumed_at and retain_until.
    assert_eq!(rows(&pool).await, [stored(&first)]);
    // That row is past its retain_until by the database clock and still a
    // replay: pruning, not the clock, ends a replay record.
    let past: bool =
        sqlx::query_scalar("SELECT bool_and(retain_until < now()) FROM consumed_assertion")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(past, "the first row should be past its retain_until");
    assert_eq!(
        registry::consume_assertion(&pool, &first).await.unwrap(),
        Consumption::Replay
    );

    // Per source: the same issuer registered as a second single-use source
    // of the same tenant has its own record, so the same digest there is
    // another proof, consumed once there too.
    let second = Side {
        tenant: A.tenant,
        source: "src_a2",
    };
    registry::create_trust_source(
        &pool,
        &single_use_source(second.tenant, second.source, "github-2"),
    )
    .await
    .unwrap();
    let mut expected = vec![stored(&first)];
    for side in [second, B] {
        let other = proof(side, 1, "dk_1");
        assert_eq!(
            registry::consume_assertion(&pool, &other).await.unwrap(),
            Consumption::Consumed
        );
        assert_eq!(
            registry::consume_assertion(&pool, &other).await.unwrap(),
            Consumption::Replay
        );
        expected.push(stored(&other));
    }
    expected.sort();
    assert_eq!(rows(&pool).await, expected);

    // Set replay: one member already consumed. Sorted, key 0 is inserted
    // before the consumed key 1 conflicts; neither it nor key 9 is kept.
    let set = [
        proof(A, 9, "dk_3"),
        proof(A, 1, "dk_3"),
        proof(A, 0, "dk_3"),
    ];
    assert_eq!(
        registry::consume_assertion_set(&pool, &set).await.unwrap(),
        Consumption::Replay
    );
    assert_eq!(rows(&pool).await, expected);
    for n in [0, 9] {
        assert_eq!(versions(&pool, A, n).await, Vec::<String>::new());
    }

    // Overlapping sets in opposite member order on two replicas, forced:
    // a holder consumes shared key 11 and the two sets, given as
    // [11, 12, 13] and [14, 12, 11], are seen blocked behind it. Sorted,
    // each waits on 11 holding none of its keys, so the holder can still
    // consume shared key 12 in the same transaction without a deadlock;
    // given in member order, the second set would hold 14 and 12 and the
    // holder's 12 would deadlock with it. The holder commits and wins.
    let replicas = Replicas::start(&db, 2).await;
    let pids = replicas.backend_pids().await;
    let (holder_pool, mut holder_conn, holder_pid) = holder(&db).await;
    let sets = |base: u8| {
        [
            vec![
                proof(A, base, "dk_a"),
                proof(A, base + 1, "dk_a"),
                proof(A, base + 2, "dk_a"),
            ],
            vec![
                proof(A, base + 3, "dk_b"),
                proof(A, base + 1, "dk_b"),
                proof(A, base, "dk_b"),
            ],
        ]
    };
    let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
    assert_eq!(
        registry::consume_assertion(&mut *tx, &proof(A, 11, "dk_holder"))
            .await
            .unwrap(),
        Consumption::Consumed
    );
    let release = async {
        rep::wait_until_blocked(&pool, &pids, holder_pid).await;
        assert_eq!(
            registry::consume_assertion(&mut *tx, &proof(A, 12, "dk_holder"))
                .await
                .unwrap(),
            Consumption::Consumed
        );
        tx.commit().await.unwrap();
    };
    let (outcomes, ()) = tokio::join!(
        replicas.race(move |replica, mut conn| {
            let set = sets(11)[replica].clone();
            async move { registry::consume_assertion_set(&mut *conn, &set).await }
        }),
        release
    );
    assert_eq!(consumed_by(outcomes), Vec::<usize>::new());
    for (n, version) in [
        (11, &["dk_holder"][..]),
        (12, &["dk_holder"]),
        (13, &[]),
        (14, &[]),
    ] {
        assert_eq!(versions(&pool, A, n).await, version, "key {n}");
    }
    drop(holder_conn);

    // The same sets released together, free: one winner, whose rows are all
    // kept, and no error (no 40P01).
    for round in 0..16u8 {
        let base = 20 + 4 * round;
        let outcomes = replicas
            .race(move |replica, mut conn| {
                let set = sets(base)[replica].clone();
                async move { registry::consume_assertion_set(&mut *conn, &set).await }
            })
            .await;
        let winners = consumed_by(outcomes);
        assert_eq!(winners.len(), 1, "round {round}: winners {winners:?}");
        let mut kept: Vec<Vec<u8>> = Vec::new();
        for n in base..base + 4 {
            if !versions(&pool, A, n).await.is_empty() {
                kept.push(digest(n));
            }
        }
        let mut won: Vec<Vec<u8>> = sets(base)[winners[0]]
            .iter()
            .map(|row| row.replay_key_digest.clone())
            .collect();
        won.sort();
        assert_eq!(kept, won, "round {round}");
    }
    let pools = [pool, holder_pool].into_iter().chain(replicas.into_pools());
    db.drop(pools).await;
}

/// A store failure is an error, never `Consumed`, and the failed call
/// writes no row.
#[tokio::test(flavor = "multi_thread")]
async fn a24_neg_store_failure_never_consumes() {
    let (mut db, pool) = two_tenants().await;

    // A closed pool: both functions fail before reaching the database.
    let closed = db.pool().await;
    closed.close().await;
    let new = proof(A, 1, "dk_1");
    for result in [
        registry::consume_assertion(&closed, &new).await,
        registry::consume_assertion_set(&closed, std::slice::from_ref(&new)).await,
    ] {
        assert!(
            matches!(result, Err(RegistryError::Other(sqlx::Error::PoolClosed))),
            "{result:?}"
        );
    }
    assert_eq!(rows(&pool).await, []);

    // statement_timeout: two replicas, a single consume and a set, blocked
    // behind a holder's open consumption of key 0x20, time out (57014). The
    // set's other member, 0x1f, sorts first and was inserted before the
    // set blocked; the timeout rolls it back. After the holder commits, the
    // key has exactly one row, the holder's.
    let (holder_pool, mut holder_conn, holder_pid) = holder(&db).await;
    let timed = Replicas::start(&db, 2).await;
    let pids = timed.backend_pids().await;
    for replica in timed.pools() {
        let mut conn = replica.acquire().await.unwrap();
        rep::set_statement_timeout(&mut conn, TIMEOUT).await;
    }
    let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
    assert_eq!(
        registry::consume_assertion(&mut *tx, &proof(A, 0x20, "dk_holder"))
            .await
            .unwrap(),
        Consumption::Consumed
    );
    let (outcomes, ()) = tokio::join!(
        timed.race(|replica, mut conn| async move {
            let new = proof(A, 0x20, "dk_timed");
            if replica == 0 {
                registry::consume_assertion(&mut *conn, &new).await
            } else {
                let set = [new, proof(A, 0x1f, "dk_timed")];
                registry::consume_assertion_set(&mut *conn, &set).await
            }
        }),
        rep::wait_until_blocked(&pool, &pids, holder_pid)
    );
    for outcome in outcomes {
        assert_other_code(outcome, "57014");
    }
    tx.commit().await.unwrap();
    assert_eq!(versions(&pool, A, 0x20).await, ["dk_holder"]);
    assert_eq!(versions(&pool, A, 0x1f).await, Vec::<String>::new());

    // A killed holder: it consumes key 0x30 in an open transaction, 3
    // replicas wait behind it, and its backend is terminated. Its insert is
    // rolled back with the session, exactly one waiter consumes, and the
    // holder's next call is an error.
    let waiters = Replicas::start(&db, 3).await;
    let pids = waiters.backend_pids().await;
    let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
    assert_eq!(
        registry::consume_assertion(&mut *tx, &proof(A, 0x30, "dk_holder"))
            .await
            .unwrap(),
        Consumption::Consumed
    );
    let kill = async {
        rep::wait_until_blocked(&pool, &pids, holder_pid).await;
        rep::terminate(&pool, holder_pid).await;
    };
    let (outcomes, ()) = tokio::join!(
        waiters.race(|replica, mut conn| async move {
            let new = proof(A, 0x30, &format!("dk_w{replica}"));
            registry::consume_assertion(&mut *conn, &new).await
        }),
        kill
    );
    let winners = consumed_by(outcomes);
    assert_eq!(winners.len(), 1, "{winners:?}");
    let after_kill = registry::consume_assertion(&mut *tx, &proof(A, 0x31, "dk_holder")).await;
    assert!(
        matches!(after_kill, Err(RegistryError::Other(_))),
        "{after_kill:?}"
    );
    drop(tx);
    drop(holder_conn);
    assert_eq!(
        versions(&pool, A, 0x30).await,
        [format!("dk_w{}", winners[0])]
    );
    assert_eq!(versions(&pool, A, 0x31).await, Vec::<String>::new());

    // REPEATABLE READ: a consume whose snapshot predates another replica's
    // committed consumption of key 0x40 is a serialization failure, Retry
    // (40001), never Consumed; a set in the same position is a Replay.
    // Retrying the whole transaction is then a Replay.
    let rr = Replicas::start(&db, 2).await;
    let [late, early] = rr.pools() else {
        unreachable!()
    };
    let mut late_conn = late.acquire().await.unwrap();
    let mut tx = Connection::begin(&mut *late_conn).await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .unwrap();
    let seen: i64 =
        sqlx::query_scalar("SELECT count(*) FROM consumed_assertion WHERE replay_key_digest = $1")
            .bind(digest(0x40))
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(seen, 0);
    assert_eq!(
        registry::consume_assertion(early, &proof(A, 0x40, "dk_early"))
            .await
            .unwrap(),
        Consumption::Consumed
    );
    match registry::consume_assertion(&mut *tx, &proof(A, 0x40, "dk_late")).await {
        Err(RegistryError::Retry(err)) => assert_eq!(
            err.as_database_error()
                .and_then(|err| err.code())
                .as_deref(),
            Some("40001")
        ),
        other => panic!("expected Retry (40001): {other:?}"),
    }
    tx.rollback().await.unwrap();
    for set in [false, true] {
        let mut tx = Connection::begin(&mut *late_conn).await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .unwrap();
        let new = proof(A, 0x40, "dk_late");
        let outcome = if set {
            registry::consume_assertion_set(&mut *tx, std::slice::from_ref(&new)).await
        } else {
            registry::consume_assertion(&mut *tx, &new).await
        };
        assert_eq!(outcome.unwrap(), Consumption::Replay, "set: {set}");
        tx.rollback().await.unwrap();
    }
    drop(late_conn);
    assert_eq!(versions(&pool, A, 0x40).await, ["dk_early"]);

    // Privileges: a role with INSERT on consumed_assertion alone (the
    // runtime role's grant) consumes and replays through both functions; a
    // role without INSERT gets 42501 and writes nothing.
    let (_, writer) = db
        .create_login_role(&["INSERT ON consumed_assertion"], 1)
        .await;
    let single = proof(A, 0x50, "dk_1");
    let set = [proof(A, 0x52, "dk_1"), proof(A, 0x51, "dk_1")];
    for expected in [Consumption::Consumed, Consumption::Replay] {
        assert_eq!(
            registry::consume_assertion(&writer, &single).await.unwrap(),
            expected
        );
        assert_eq!(
            registry::consume_assertion_set(&writer, &set)
                .await
                .unwrap(),
            expected
        );
    }
    let (_, no_insert) = db.create_login_role(&[], 1).await;
    let denied = proof(A, 0x53, "dk_1");
    assert_other_code(
        registry::consume_assertion(&no_insert, &denied).await,
        "42501",
    );
    assert_other_code(
        registry::consume_assertion_set(&no_insert, std::slice::from_ref(&denied)).await,
        "42501",
    );
    assert_eq!(versions(&pool, A, 0x53).await, Vec::<String>::new());

    // Invalid rows: an empty or backwards retention window, a digest of 31
    // or 65 bytes. Each is the named check's error and writes nothing.
    let before = rows(&pool).await;
    let invalid = |change: fn(&mut NewConsumedAssertion)| {
        let mut new = proof(A, 0x60, "dk_1");
        change(&mut new);
        new
    };
    let cases = [
        (
            invalid(|new| new.retain_until = new.consumed_at),
            "consumed_assertion_retention_check",
        ),
        (
            invalid(|new| new.retain_until = at(T0 - 1)),
            "consumed_assertion_retention_check",
        ),
        (
            invalid(|new| new.replay_key_digest = vec![0x60; 31]),
            "consumed_assertion_replay_key_digest_octet_length_check",
        ),
        (
            invalid(|new| new.replay_key_digest = vec![0x60; 65]),
            "consumed_assertion_replay_key_digest_octet_length_check",
        ),
    ];
    for (new, name) in &cases {
        assert_invariant(
            registry::consume_assertion(&pool, new).await,
            InvariantKind::Check,
            name,
        );
        assert_invariant(
            registry::consume_assertion_set(&pool, std::slice::from_ref(new)).await,
            InvariantKind::Check,
            name,
        );
    }
    assert_eq!(rows(&pool).await, before);

    // In all: the holder's 0x20, the one waiter's 0x30, the early 0x40 and
    // the writer's three rows.
    assert_eq!(before.len(), 6);
    let pools = [pool, closed, holder_pool, writer, no_insert]
        .into_iter()
        .chain(timed.into_pools())
        .chain(waiters.into_pools())
        .chain(rr.into_pools());
    db.drop(pools).await;
}

/// A consume naming another tenant's source is refused by the composite
/// foreign key in both directions, through both functions, and writes
/// nothing; so is one naming an unknown tenant or source. The refusals burn
/// nothing: each tenant then consumes the same digests on its own source.
#[tokio::test]
async fn a24_neg_consume_names_other_tenants_source() {
    let (db, pool) = two_tenants().await;
    let crossing = |tenant: &str, source: &str| NewConsumedAssertion {
        tenant_id: tenant.into(),
        trust_source_id: source.into(),
        ..proof(A, 1, "dk_1")
    };
    for (owner, intruder) in DIRECTIONS {
        let new = crossing(intruder.tenant, owner.source);
        assert_invariant(
            registry::consume_assertion(&pool, &new).await,
            InvariantKind::ForeignKey,
            SOURCE_FKEY,
        );
        // With a valid row of the intruder's own source: neither is written.
        assert_invariant(
            registry::consume_assertion_set(&pool, &[proof(intruder, 2, "dk_1"), new]).await,
            InvariantKind::ForeignKey,
            SOURCE_FKEY,
        );
    }
    for new in [crossing("ten_x", A.source), crossing(A.tenant, "src_x")] {
        assert_invariant(
            registry::consume_assertion(&pool, &new).await,
            InvariantKind::ForeignKey,
            SOURCE_FKEY,
        );
        assert_invariant(
            registry::consume_assertion_set(&pool, std::slice::from_ref(&new)).await,
            InvariantKind::ForeignKey,
            SOURCE_FKEY,
        );
    }
    assert_eq!(rows(&pool).await, []);
    for side in [A, B] {
        assert_eq!(
            registry::consume_assertion(&pool, &proof(side, 1, "dk_1"))
                .await
                .unwrap(),
            Consumption::Consumed
        );
        assert_eq!(
            registry::consume_assertion_set(&pool, &[proof(side, 2, "dk_1")])
                .await
                .unwrap(),
            Consumption::Consumed
        );
    }
    assert_eq!(rows(&pool).await.len(), 4);
    db.drop([pool]).await;
}
