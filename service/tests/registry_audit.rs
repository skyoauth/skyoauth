//! The audit event writer and chain verifier
//! (`persistence::registry::append_audit_event` and `verify_audit_chain`;
//! identity-registry IR-055 to IR-059, OQ-IR-15). The tests without a
//! database check the envelope and hash against known answers computed
//! independently (with Python's `hashlib` and `json`), and that every absent
//! value hashes apart from a present one. The database tests append events
//! in chains, concurrently and in rolled-back transactions, reject bad input
//! before any statement, and edit stored rows in rolled-back transactions
//! with the guard triggers off to show that verification finds each edit.
//!
//! Unit tests may assert hash values; conformance scenarios must not
//! (IR-056).
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database.

mod common;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, AuditActor, AuditEvent, ChainBreak, ChainVerdict, InvariantKind, NewAuditEvent,
        RegistryError, append_audit_event, verify_audit_chain,
    },
};
use sqlx::{Connection, PgConnection};
use tokio::sync::Barrier;

/// 2026-11-21T09:30:00Z in microseconds from the Unix epoch.
const T0: u64 = 1_795_253_400_000_000;
/// The `0007` range bounds, in microseconds from the Unix epoch.
const EARLIEST: u64 = 210_866_803_200_000_000;
const LATEST: u64 = i64::MAX as u64 - 1;

fn at(microseconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(microseconds)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

/// The first known-answer event: instance scope, system actor.
fn kat_first() -> AuditEvent {
    AuditEvent {
        id: "aud_0001".into(),
        tenant_id: None,
        sequence: 1,
        prev_hash: None,
        timestamp: at(T0),
        actor: AuditActor::System,
        action: "instance_security_policy.mirror".into(),
        object_id: "019a9f3c-5b2e-7c41-9d8e-0123456789ab".into(),
        previous_revision: Some(3),
        new_revision: Some(4),
        outcome: "success".into(),
        hash: [0; 32],
    }
}

/// The second: a tenant create by an operator whose ID needs escapes.
fn kat_second() -> AuditEvent {
    AuditEvent {
        id: "aud_0002".into(),
        tenant_id: Some("ten_a".into()),
        sequence: 2,
        prev_hash: Some(unhex(KAT_FIRST_HASH)),
        timestamp: at(T0 + 123_456),
        actor: AuditActor::Operator("adm_\u{e9}\u{1}\"\\/".into()),
        action: "tenant.create".into(),
        object_id: "ten_a".into(),
        previous_revision: None,
        new_revision: Some(1),
        outcome: "success".into(),
        hash: [0; 32],
    }
}

const KAT_FIRST_HASH: &str = "d9d8a30f52203c633d4f8b7da01f8e815e9a351be245507a430c8027f782610c";
const KAT_SECOND_HASH: &str = "80022011ed828f478a9c6b3423695c3e675ea34693c6ab83309b5cda26ff67dd";

/// Known answers from an independent computation (Python `json.dumps` with
/// sorted keys and no spaces, `hashlib.sha256`).
#[test]
fn the_envelope_and_hash_match_known_answers() {
    let first = kat_first();
    assert_eq!(
        first.envelope().unwrap(),
        r#"{"action":"instance_security_policy.mirror","actor":{"id":"system","type":"system"},"id":"aud_0001","new_revision":4,"object_id":"019a9f3c-5b2e-7c41-9d8e-0123456789ab","outcome":"success","previous_revision":3,"sequence":1,"tenant_id":null,"timestamp":"2026-11-21T09:30:00.000000Z"}"#
    );
    assert_eq!(hex(&first.compute_hash().unwrap()), KAT_FIRST_HASH);
    let second = kat_second();
    assert_eq!(
        second.envelope().unwrap(),
        "{\"action\":\"tenant.create\",\"actor\":{\"id\":\"adm_\u{e9}\\u0001\\\"\\\\/\",\
         \"type\":\"operator\"},\"id\":\"aud_0002\",\"new_revision\":1,\"object_id\":\"ten_a\",\
         \"outcome\":\"success\",\"previous_revision\":null,\"sequence\":2,\
         \"tenant_id\":\"ten_a\",\"timestamp\":\"2026-11-21T09:30:00.123456Z\"}"
    );
    assert_eq!(hex(&second.compute_hash().unwrap()), KAT_SECOND_HASH);
    // The first event hashes no previous bytes: 32 zero bytes would give
    // another digest (also computed with Python).
    let mut zeros = first.clone();
    zeros.prev_hash = Some([0; 32]);
    assert_eq!(
        hex(&zeros.compute_hash().unwrap()),
        "d1feac813eaf094a3a091961bb94a46eec2991af8fdf837cf08c8217b597e90e"
    );
    // The stored hash field is not an input.
    let mut with_hash = second.clone();
    with_hash.hash = [9; 32];
    assert_eq!(hex(&with_hash.compute_hash().unwrap()), KAT_SECOND_HASH);
    assert_eq!(registry::AUDIT_HASH_PREFIX, b"skyoauth.audit.v1\0");
}

/// Each nullable member hashes apart when absent and when present, a
/// present value that looks like `null` or is empty included.
#[test]
fn absent_and_present_values_hash_differently() {
    let base = kat_second();
    let mut variants = vec![base.clone()];
    for tenant_id in [None, Some(""), Some("null"), Some("ten_b")] {
        let mut event = base.clone();
        event.tenant_id = tenant_id.map(Into::into);
        variants.push(event);
    }
    for revision in [None, Some(1), Some(2)] {
        let mut event = base.clone();
        event.previous_revision = revision;
        variants.push(event);
        let mut event = base.clone();
        event.new_revision = revision;
        variants.push(event);
    }
    for prev_hash in [None, Some([0; 32]), Some([1; 32])] {
        let mut event = base.clone();
        event.prev_hash = prev_hash;
        variants.push(event);
    }
    // One hash per distinct combination of the four values.
    let mut hashes = BTreeMap::new();
    for event in &variants {
        let fields = (
            event.tenant_id.clone(),
            event.previous_revision,
            event.new_revision,
            event.prev_hash,
        );
        hashes.insert(fields, event.compute_hash().unwrap());
    }
    // The base, four tenant IDs, two of each revision and three hashes.
    assert_eq!(hashes.len(), 1 + 4 + 2 + 2 + 3);
    let distinct: BTreeSet<_> = hashes.values().collect();
    assert_eq!(distinct.len(), hashes.len());
    let mut absent = base.clone();
    absent.tenant_id = None;
    absent.new_revision = None;
    let envelope = absent.envelope().unwrap();
    for member in [
        r#""tenant_id":null"#,
        r#""new_revision":null"#,
        r#""previous_revision":null"#,
    ] {
        assert!(envelope.contains(member), "{envelope}");
    }
}

/// Six fractional digits and `Z`, truncated to the microsecond; the `0007`
/// bounds as expanded years; beyond them an encode error.
#[test]
fn timestamps_are_written_with_microseconds_and_z() {
    let timestamp = |time: SystemTime| {
        let mut event = kat_first();
        event.timestamp = time;
        event.envelope().map(|envelope| {
            let start = envelope.find(r#""timestamp":""#).unwrap() + 13;
            envelope[start..envelope.len() - 2].to_string()
        })
    };
    assert_eq!(timestamp(at(T0)).unwrap(), "2026-11-21T09:30:00.000000Z");
    assert_eq!(
        timestamp(at(T0) + Duration::from_nanos(999)).unwrap(),
        "2026-11-21T09:30:00.000000Z"
    );
    assert_eq!(
        timestamp(at(T0) + Duration::from_nanos(1_000)).unwrap(),
        "2026-11-21T09:30:00.000001Z"
    );
    assert_eq!(
        timestamp(UNIX_EPOCH - Duration::from_nanos(1)).unwrap(),
        "1969-12-31T23:59:59.999999Z"
    );
    assert_eq!(
        timestamp(UNIX_EPOCH - Duration::from_micros(EARLIEST)).unwrap(),
        "-004713-11-24T00:00:00.000000Z"
    );
    assert_eq!(
        timestamp(at(LATEST)).unwrap(),
        "+294247-01-10T04:00:54.775806Z"
    );
    for beyond in [
        UNIX_EPOCH - Duration::from_micros(EARLIEST + 1),
        at(LATEST + 1),
    ] {
        assert!(matches!(timestamp(beyond), Err(RegistryError::Other(_))));
    }
    let mut big = kat_first();
    big.new_revision = Some(1 << 53);
    assert!(matches!(big.envelope(), Err(RegistryError::Other(_))));
    big.new_revision = Some(registry::MAX_ENVELOPE_INTEGER);
    assert!(
        big.envelope()
            .unwrap()
            .contains(r#""new_revision":9007199254740991"#)
    );
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    sqlx::raw_sql(
        "INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled')",
    )
    .execute(&pool)
    .await
    .unwrap();
    (db, pool)
}

fn new_event(id: &str, tenant_id: Option<&str>, microseconds: u64) -> NewAuditEvent {
    NewAuditEvent {
        id: id.into(),
        tenant_id: tenant_id.map(Into::into),
        timestamp: at(microseconds),
        actor: AuditActor::Operator("adm_1".into()),
        action: "tenant.update".into(),
        object_id: tenant_id.unwrap_or("instance").into(),
        previous_revision: Some(1),
        new_revision: Some(2),
        outcome: "success".into(),
    }
}

/// Appends `event` in its own committed transaction.
async fn append(pool: &PgPool, event: &NewAuditEvent) -> AuditEvent {
    let mut transaction = pool.begin().await.unwrap();
    let stored = append_audit_event(&mut transaction, event).await.unwrap();
    transaction.commit().await.unwrap();
    stored
}

async fn head(pool: &PgPool) -> (i64, Option<Vec<u8>>) {
    sqlx::query_as("SELECT sequence, head_hash FROM audit_chain_head")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn verify(pool: &PgPool) -> ChainVerdict {
    let mut connection = pool.acquire().await.unwrap();
    verify_audit_chain(&mut connection).await.unwrap()
}

/// The first event has no `prev_hash`, each next one the hash before it,
/// and the head records the last; the stored event is the written one,
/// timestamp truncated to the microsecond, and its actor column is the
/// envelope's actor byte for byte.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn events_chain_from_the_first_and_the_head_follows() {
    let (db, pool) = migrated().await;
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 0 }
    );
    // An instance-scope event by the system actor.
    let mut startup = new_event("aud_1", None, T0);
    startup.actor = AuditActor::System;
    startup.action = "instance_security_policy.mirror".into();
    startup.object_id = "019a9f3c-5b2e-7c41-9d8e-0123456789ab".into();
    startup.timestamp = at(T0) + Duration::from_nanos(1_999);
    let first = append(&pool, &startup).await;
    assert_eq!(
        (first.sequence, first.prev_hash, first.tenant_id.as_deref()),
        (1, None, None)
    );
    assert_eq!(first.timestamp, at(T0 + 1));
    assert_eq!(first.actor, AuditActor::System);
    assert_eq!(first.hash, first.compute_hash().unwrap());
    assert_eq!(head(&pool).await, (1, Some(first.hash.to_vec())));

    let second = append(&pool, &new_event("aud_2", Some("ten_a"), T0 + 5)).await;
    assert_eq!((second.sequence, second.prev_hash), (2, Some(first.hash)));
    assert_eq!(second.hash, second.compute_hash().unwrap());
    assert_eq!(
        (
            &second.id[..],
            second.tenant_id.as_deref(),
            &second.action[..],
            &second.object_id[..],
            second.previous_revision,
            second.new_revision,
            &second.outcome[..],
            second.timestamp,
        ),
        (
            "aud_2",
            Some("ten_a"),
            "tenant.update",
            "ten_a",
            Some(1),
            Some(2),
            "success",
            at(T0 + 5)
        )
    );
    assert_eq!(head(&pool).await, (2, Some(second.hash.to_vec())));

    let actors: Vec<(String, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT actor, prev_hash FROM audit_event ORDER BY sequence")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(actors[0].0, r#"{"id":"system","type":"system"}"#);
    assert_eq!(actors[1].0, r#"{"id":"adm_1","type":"operator"}"#);
    assert_eq!(actors[1].1.as_deref(), Some(&first.hash[..]));
    for ((actor, _), event) in actors.iter().zip([&first, &second]) {
        let envelope = event.envelope().unwrap();
        assert!(
            envelope.contains(&format!(r#""actor":{actor},"id":"#)),
            "{envelope}"
        );
    }
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// Events at both `0007` bounds are written, read back exactly and verify.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn events_at_the_range_check_bounds_round_trip() {
    let (db, pool) = migrated().await;
    let mut early = new_event("aud_early", Some("ten_a"), 0);
    early.timestamp = UNIX_EPOCH - Duration::from_micros(EARLIEST);
    let early_stored = append(&pool, &early).await;
    assert_eq!(early_stored.timestamp, early.timestamp);
    let late = new_event("aud_late", Some("ten_a"), LATEST);
    let late_stored = append(&pool, &late).await;
    assert_eq!(late_stored.timestamp, at(LATEST));
    assert!(
        late_stored
            .envelope()
            .unwrap()
            .contains(r#""timestamp":"+294247-01-10T04:00:54.775806Z""#)
    );
    let texts: Vec<String> = sqlx::query_scalar(
        "SELECT to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US BC')
           FROM audit_event ORDER BY sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        texts,
        [
            "4714-11-24 00:00:00.000000 BC",
            "294247-01-10 04:00:54.775806 AD"
        ]
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// Bad input is rejected before any statement: the transaction holds no
/// head lock and is still usable, and nothing is written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bad_input_is_rejected_before_any_statement() {
    let (db, pool) = migrated().await;
    let first = append(&pool, &new_event("aud_1", Some("ten_a"), T0)).await;
    // Each bad event with the reason the writer gives, never a value.
    let syntax = "audit action is not <resource>.<verb>";
    let mut bad = Vec::new();
    for (action, reason) in [
        ("tenant.explode", "audit action is not in the action table"),
        ("Tenant.create", syntax),
        ("tenant", syntax),
        ("tenant.create.extra", syntax),
        ("", syntax),
    ] {
        let mut event = new_event("aud_x", Some("ten_a"), T0);
        event.action = action.into();
        bad.push((event, reason));
    }
    let mut event = new_event("aud_x", Some("ten_a"), T0);
    event.actor = AuditActor::Operator(String::new());
    bad.push((event, "audit actor ID is empty"));
    for revision in [1 << 53, i64::MAX] {
        let mut event = new_event("aud_x", Some("ten_a"), T0);
        event.new_revision = Some(revision);
        bad.push((event, "audit integer above 2^53 - 1"));
    }
    let mut event = new_event("aud_x", Some("ten_a"), LATEST + 1);
    bad.push((event.clone(), "timestamp out of range"));
    event.timestamp = UNIX_EPOCH - Duration::from_micros(EARLIEST + 1);
    bad.push((event, "timestamp out of range"));

    let mut transaction = pool.begin().await.unwrap();
    for (event, reason) in &bad {
        let err = append_audit_event(&mut transaction, event)
            .await
            .unwrap_err();
        let RegistryError::Other(source) = &err else {
            panic!("{err:?}");
        };
        assert!(
            matches!(source, sqlx::Error::Encode(message) if message.to_string() == *reason),
            "{source:?}"
        );
        assert_eq!(err.to_string(), "registry database error");
        // No head lock is held: another session takes it at once.
        let mut other = pool.begin().await.unwrap();
        sqlx::query("SELECT FROM audit_chain_head FOR UPDATE NOWAIT")
            .execute(&mut *other)
            .await
            .unwrap();
        other.rollback().await.unwrap();
    }
    // The transaction is not aborted.
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    assert_eq!(one, 1);
    transaction.commit().await.unwrap();
    assert_eq!(head(&pool).await, (1, Some(first.hash.to_vec())));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    db.drop([pool]).await;
}

/// A rolled-back append leaves the chain as it was, and the next append
/// takes the same sequence. A missing tenant and a duplicate ID map by
/// constraint name.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_rolled_back_or_refused_append_leaves_the_chain_unchanged() {
    let (db, pool) = migrated().await;
    let first = append(&pool, &new_event("aud_1", Some("ten_a"), T0)).await;
    let mut transaction = pool.begin().await.unwrap();
    let dropped = append_audit_event(&mut transaction, &new_event("aud_2", Some("ten_a"), T0))
        .await
        .unwrap();
    assert_eq!(dropped.sequence, 2);
    transaction.rollback().await.unwrap();
    assert_eq!(head(&pool).await, (1, Some(first.hash.to_vec())));
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 1 }
    );

    let mut transaction = pool.begin().await.unwrap();
    let err = append_audit_event(&mut transaction, &new_event("aud_2", Some("ten_x"), T0))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegistryError::Invariant {
                kind: InvariantKind::ForeignKey,
                constraint: Some("audit_event_tenant_id_fkey")
            }
        ),
        "{err:?}"
    );
    transaction.rollback().await.unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let err = append_audit_event(&mut transaction, &new_event("aud_1", Some("ten_a"), T0))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegistryError::AlreadyExists {
                constraint: "audit_event_pkey"
            }
        ),
        "{err:?}"
    );
    transaction.rollback().await.unwrap();

    let second = append(&pool, &new_event("aud_2", Some("ten_b"), T0)).await;
    assert_eq!((second.sequence, second.prev_hash), (2, Some(first.hash)));
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
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
    .expect("the second appender never waited for the first");
}

/// Two appends from separate connections, the second started while the
/// first's transaction still holds the head: the second waits for the
/// head lock, then extends the committed head. Both succeed and the chain
/// is unbroken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_appender_waits_for_the_head_and_extends_it() {
    let (db, pool) = migrated().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    let one = append_audit_event(&mut transaction, &new_event("aud_1", Some("ten_a"), T0))
        .await
        .unwrap();
    let waiting = tokio::spawn(async move {
        let mut transaction = second.begin().await.unwrap();
        let outcome =
            append_audit_event(&mut transaction, &new_event("aud_2", Some("ten_b"), T0)).await;
        if outcome.is_ok() {
            transaction.commit().await.unwrap();
        }
        outcome
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    assert!(!waiting.is_finished());
    transaction.commit().await.unwrap();
    let two = waiting.await.unwrap().unwrap();
    assert_eq!((one.sequence, two.sequence), (1, 2));
    assert_eq!(two.prev_hash, Some(one.hash));
    assert_eq!(head(&pool).await, (2, Some(two.hash.to_vec())));
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// Many appenders released together on separate connections all succeed
/// and leave one unbroken chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_appenders_all_succeed_in_one_chain() {
    const APPENDERS: usize = 8;
    const EACH: usize = 5;
    let (db, pool) = migrated().await;
    let barrier = Arc::new(Barrier::new(APPENDERS));
    let mut tasks = Vec::new();
    for n in 0..APPENDERS {
        let mut connection = pool.acquire().await.unwrap().detach();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut sequences = Vec::new();
            for k in 0..EACH {
                let mut transaction = connection.begin().await.unwrap();
                let event = new_event(&format!("aud_{n}_{k}"), Some("ten_a"), T0);
                let stored = append_audit_event(&mut transaction, &event).await.unwrap();
                transaction.commit().await.unwrap();
                sequences.push(stored.sequence);
            }
            connection.close().await.unwrap();
            sequences
        }));
    }
    let mut sequences = Vec::new();
    for task in tasks {
        sequences.extend(task.await.unwrap());
    }
    sequences.sort_unstable();
    let total = i64::try_from(APPENDERS * EACH).unwrap();
    assert_eq!(sequences, (1..=total).collect::<Vec<_>>());
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact {
            last_sequence: total
        }
    );
    db.drop([pool]).await;
}

/// Runs `sql` in a transaction on one connection, verifies there and rolls
/// back.
async fn verdict_after(pool: &PgPool, sql: &str) -> ChainVerdict {
    let mut connection = pool.acquire().await.unwrap();
    sqlx::raw_sql("BEGIN")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(&mut *connection)
        .await
        .unwrap_or_else(|err| panic!("{sql}: {err}"));
    let verdict = verify_audit_chain(&mut connection).await.unwrap();
    sqlx::raw_sql("ROLLBACK")
        .execute(&mut *connection)
        .await
        .unwrap();
    verdict
}

const EDIT: &str = "ALTER TABLE audit_event DISABLE TRIGGER audit_event_append_only;";

/// Verification finds every edit of a stored event, a missing event, a
/// forged head and an event past the head. Each edit runs with the guard
/// triggers off in a rolled-back transaction. An edit of event `k` shows
/// at event `k + 1`, whose `prev_hash` no longer matches, or at the head
/// for the last event.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn verification_finds_each_edit() {
    let (db, pool) = migrated().await;
    let mut startup = new_event("aud_1", None, T0);
    startup.actor = AuditActor::System;
    startup.action = "instance_security_policy.mirror".into();
    append(&pool, &startup).await;
    append(&pool, &new_event("aud_2", Some("ten_a"), T0 + 1)).await;
    let mut create = new_event("aud_3", Some("ten_a"), T0 + 2);
    create.action = "principal.create".into();
    create.previous_revision = None;
    create.new_revision = Some(1);
    append(&pool, &create).await;
    let intact = ChainVerdict::Intact { last_sequence: 3 };
    assert_eq!(verify(&pool).await, intact);
    let broken = |sequence, reason| ChainVerdict::Broken { sequence, reason };

    // A no-op update changes nothing.
    assert_eq!(
        verdict_after(
            &pool,
            &format!("{EDIT} UPDATE audit_event SET outcome = outcome")
        )
        .await,
        intact
    );
    for (set, sequence) in [
        ("timestamp = timestamp + interval '1 microsecond'", 2),
        ("timestamp = timestamp - interval '1 microsecond'", 3),
        (r#"actor = '{"id":"adm_2","type":"operator"}'"#, 2),
        (r#"actor = '{"id":"adm_1","type":"operator"}'"#, 1),
        ("action = 'tenant.create'", 2),
        ("action = 'tenant.update'", 3),
        ("object_id = 'ten_b'", 2),
        ("outcome = 'failure'", 2),
        ("outcome = 'failure'", 3),
        ("previous_revision = NULL", 2),
        ("previous_revision = 7", 2),
        ("previous_revision = 1", 3),
        ("previous_revision = 5", 1),
        ("new_revision = NULL", 2),
        ("new_revision = 3", 2),
        ("new_revision = 2", 3),
        ("tenant_id = NULL", 2),
        ("tenant_id = 'ten_b'", 2),
        ("tenant_id = 'ten_a'", 1),
        ("id = 'aud_9'", 2),
    ] {
        let sql = format!("{EDIT} UPDATE audit_event SET {set} WHERE sequence = {sequence}");
        let expected = if sequence == 3 {
            broken(3, ChainBreak::HeadMismatch)
        } else {
            broken(sequence + 1, ChainBreak::PrevHashMismatch)
        };
        assert_eq!(verdict_after(&pool, &sql).await, expected, "{sql}");
    }
    for (sql, expected) in [
        // The link itself.
        (
            format!(
                "{EDIT} UPDATE audit_event SET prev_hash = decode(repeat('ab', 32), 'hex') \
                 WHERE sequence = 2"
            ),
            broken(2, ChainBreak::PrevHashMismatch),
        ),
        (
            format!(
                "{EDIT} ALTER TABLE audit_event DROP CONSTRAINT audit_event_check; \
                 UPDATE audit_event SET prev_hash = decode(repeat('00', 32), 'hex') \
                 WHERE sequence = 1"
            ),
            broken(1, ChainBreak::PrevHashMismatch),
        ),
        // Rows the writer could not have written.
        (
            format!(
                r#"{EDIT} UPDATE audit_event SET actor = '{{"id": "adm_1","type":"operator"}}'
                   WHERE sequence = 2"#
            ),
            broken(2, ChainBreak::Unencodable),
        ),
        (
            format!(
                "{EDIT} ALTER TABLE audit_event DROP CONSTRAINT audit_event_timestamp_range_check; \
                 UPDATE audit_event SET timestamp = 'infinity' WHERE sequence = 2"
            ),
            broken(2, ChainBreak::Unencodable),
        ),
        (
            format!(
                "{EDIT} UPDATE audit_event SET new_revision = 9007199254740992 WHERE sequence = 2"
            ),
            broken(2, ChainBreak::Unencodable),
        ),
        // Missing events.
        (
            format!("{EDIT} DELETE FROM audit_event WHERE sequence = 2"),
            broken(2, ChainBreak::Gap),
        ),
        (
            format!("{EDIT} DELETE FROM audit_event WHERE sequence = 3"),
            broken(3, ChainBreak::Gap),
        ),
        (
            format!("{EDIT} UPDATE audit_event SET sequence = 5 WHERE sequence = 3"),
            broken(3, ChainBreak::Gap),
        ),
        // A forged head.
        (
            "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
             UPDATE audit_chain_head SET head_hash = decode(repeat('cd', 32), 'hex')"
                .to_string(),
            broken(3, ChainBreak::HeadMismatch),
        ),
        (
            "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
             UPDATE audit_chain_head SET sequence = 2"
                .to_string(),
            broken(2, ChainBreak::HeadMismatch),
        ),
        (
            "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
             UPDATE audit_chain_head SET sequence = 2, \
                 head_hash = (SELECT prev_hash FROM audit_event WHERE sequence = 3)"
                .to_string(),
            broken(3, ChainBreak::HeadMismatch),
        ),
        // An event past the head; the head is never advanced to it (its
        // deferred check would fail the commit, which never comes).
        (
            r#"INSERT INTO audit_event VALUES ('aud_4', 'ten_a', 4,
                   (SELECT head_hash FROM audit_chain_head), now(),
                   '{"id":"adm_1","type":"operator"}', 'tenant.update', 'ten_a', 1, 2, 'success')"#
                .to_string(),
            broken(4, ChainBreak::HeadMismatch),
        ),
    ] {
        assert_eq!(verdict_after(&pool, &sql).await, expected, "{sql}");
    }
    // Every edit was rolled back.
    assert_eq!(verify(&pool).await, intact);
    db.drop([pool]).await;
}

/// Verification pages through a chain longer than one page.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn verification_pages_through_a_long_chain() {
    let (db, pool) = migrated().await;
    let mut transaction = pool.begin().await.unwrap();
    for n in 0..1_203 {
        append_audit_event(
            &mut transaction,
            &new_event(&format!("aud_{n:05}"), Some("ten_a"), T0 + n),
        )
        .await
        .unwrap();
    }
    transaction.commit().await.unwrap();
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact {
            last_sequence: 1_203
        }
    );
    // An edit on the last page is found there.
    assert_eq!(
        verdict_after(
            &pool,
            &format!("{EDIT} UPDATE audit_event SET outcome = 'x' WHERE sequence = 1101")
        )
        .await,
        ChainVerdict::Broken {
            sequence: 1102,
            reason: ChainBreak::PrevHashMismatch
        }
    );
    db.drop([pool]).await;
}
