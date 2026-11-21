//! Break-glass operator restoration (`persistence::registry::recovery`;
//! design section 7.2; ADR-013 item 8; identity-registry section 5.2;
//! lifetimes LT-107; T13.5): the issued challenge and its audit event, the
//! TTL bounds, single use (in the statement and in the database guards),
//! every miss of a restore as one value, the replacement the plan binds,
//! two concurrent restores of one challenge, the full restoration (enroll,
//! revoke every credential, rotate the key, two audit events last), that
//! nothing else changes, that a failed restore rolls the consume back, that
//! a restore runs only at `READ COMMITTED`, that a restore and an issue
//! wait for each other without deadlock, that an operator write that adds
//! access serializes with a restore (a colliding create waiting before its
//! insert), and that the one remaining deadlock fails closed.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! creates and drops its own database. They are registry tests, not
//! conformance scenarios (A48 and A64 belong to the test session in
//! `tests/security`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    collections::BTreeMap,
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use serde_json::{Value, json};
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, AdminRole, AdminRoleBindingChanges, AuditActor, AuthorizedOperator, BootstrapRequest,
        ChainVerdict, ChallengeBinding, ChallengeError, DEFAULT_CHALLENGE_TTL, InvariantKind,
        IssueChallenge, JsonObject, MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL, NewAdminCredential,
        NewAdminIdentity, NewAdminRoleBinding, NewAuditEvent, NewPrincipal, NewTenant,
        OPERATOR_RESTORATION, OperatorRequest, OperatorScope, PrincipalKind, RecoveryChallenge,
        RecoveryState, RegistryError, RestoreError, RestoreRequest, Restored, Status,
        bootstrap_instance, get_recovery_state, issue_recovery_challenge, restore_operator,
        verify_audit_chain,
    },
};
use sqlx::{AssertSqlSafe, Connection, PgConnection, Postgres, Transaction};

const INSTANCE: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const OTHER_INSTANCE: &str = "019a9f3c-5b2e-7c41-ad8e-ba9876543210";
const KEY: [u8; 32] = [0x11; 32];
const NEW_KEY: [u8; 32] = [0x22; 32];
const THIRD_KEY: [u8; 32] = [0x33; 32];
const DIGEST: [u8; 32] = [0xd1; 32];
const OTHER_DIGEST: [u8; 32] = [0xd2; 32];
const HASH: [u8; 48] = [0xc7; 48];
const T0: u64 = 1_790_000_000_123_456;

/// `micros` after `T0`.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

/// The issue time: sub-microsecond digits, so a write truncates it.
fn issue_time() -> SystemTime {
    at(1_000_000) + Duration::from_nanos(789)
}

/// The default expiry as stored: the issue time plus five minutes,
/// truncated.
fn expires() -> SystemTime {
    at(301_000_000)
}

/// The consume and restore time.
fn now() -> SystemTime {
    at(2_000_000)
}

fn micros(time: SystemTime) -> i64 {
    i64::try_from(time.duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap()
}

/// `bytes` in lowercase hexadecimal, as the plan carries a key.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// The plan of a challenge for `instance` and `epoch` that names the
/// replacement of `request`.
fn plan_for(instance: &str, epoch: Value, request: &RestoreRequest<'_>) -> JsonObject {
    object(json!({
        "instance_id": instance,
        "recovery_key_epoch": epoch,
        "operation": "operator_restoration",
        "admin_id": request.admin_id,
        "credential_id": request.credential_id,
        "binding_id": request.binding_id,
        "public_identity": request.public_identity,
        "trust_anchor_ref": request.trust_anchor_ref,
        "new_recovery_public_key": hex(request.new_recovery_public_key),
    }))
}

/// The plan for `instance` and `epoch` that names [`restore_request`]'s
/// replacement.
fn plan(instance: &str, epoch: Value) -> JsonObject {
    plan_for(instance, epoch, &restore_request(""))
}

fn good_plan() -> JsonObject {
    plan(INSTANCE, json!(1))
}

fn issue_request<'a>(id: &'a str, audit: &'a str, plan: &'a JsonObject) -> IssueChallenge<'a> {
    IssueChallenge {
        operation_id: id,
        kind: OPERATOR_RESTORATION,
        request_digest: &DIGEST,
        immutable_plan: plan,
        challenge_hash: &HASH,
        ttl: DEFAULT_CHALLENGE_TTL,
        now: issue_time(),
        audit_event_id: audit,
    }
}

fn binding() -> ChallengeBinding<'static> {
    ChallengeBinding {
        request_digest: &DIGEST,
        instance_id: INSTANCE,
        expected_revision: 1,
        recovery_key_epoch: 1,
    }
}

/// A restore of the challenge `id` with [`binding`] at `now()`, naming the
/// replacement of [`good_plan`].
fn restore_request(id: &str) -> RestoreRequest<'_> {
    RestoreRequest {
        operation_id: id,
        binding: binding(),
        admin_id: "adm_new",
        credential_id: "crd_new",
        binding_id: "rb_new",
        public_identity: "spki-sha256:new",
        trust_anchor_ref: "deployment/operator-ca",
        new_recovery_public_key: &NEW_KEY,
        audit_event_id: "aud_restore",
        rotation_audit_event_id: "aud_rotate",
        now: now(),
    }
}

/// A change to a request.
type Change = fn(&mut RestoreRequest<'static>);

/// [`restore_request`] with another replacement (`*_other`) and `key`.
fn other_request<'a>(id: &'a str, key: &'a [u8]) -> RestoreRequest<'a> {
    RestoreRequest {
        admin_id: "adm_other",
        credential_id: "crd_other",
        binding_id: "rb_other",
        public_identity: "spki-sha256:other",
        audit_event_id: "aud_other",
        rotation_audit_event_id: "aud_other_rotate",
        new_recovery_public_key: key,
        ..restore_request(id)
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// A migrated database after bootstrap: `adm_first` with `crd_first`
/// (`spki-sha256:first`) and `rb_first`, the recovery key `KEY` at epoch 1,
/// and the bootstrap event `aud_bootstrap` (sequence 1).
async fn bootstrapped() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: INSTANCE,
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: "spki-sha256:first",
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &KEY,
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    (db, pool)
}

/// [`bootstrapped`] with the challenge `op_1` (event `aud_issue_1`) issued
/// and committed.
async fn issued() -> (TestDb, PgPool) {
    let (db, pool) = bootstrapped().await;
    issue(&pool, "op_1", "aud_issue_1").await;
    (db, pool)
}

async fn issue_on(
    pool: &PgPool,
    request: &IssueChallenge<'_>,
) -> Result<RecoveryChallenge, ChallengeError> {
    let mut transaction = pool.begin().await.unwrap();
    let issued = issue_recovery_challenge(&mut transaction, request).await;
    if issued.is_ok() {
        transaction.commit().await.unwrap();
    } else {
        transaction.rollback().await.unwrap();
    }
    issued
}

async fn issue(pool: &PgPool, id: &str, audit: &str) -> RecoveryChallenge {
    let plan = good_plan();
    issue_on(pool, &issue_request(id, audit, &plan))
        .await
        .unwrap()
}

/// Restores in a transaction of its own; commits on `Ok`.
async fn restore_on(pool: &PgPool, request: &RestoreRequest<'_>) -> Result<Restored, RestoreError> {
    let mut transaction = pool.begin().await.unwrap();
    let restored = restore_operator(&mut transaction, request).await;
    if restored.is_ok() {
        transaction.commit().await.unwrap();
    } else {
        transaction.rollback().await.unwrap();
    }
    restored
}

/// Restores with `restore_request(id)` in `transaction`.
async fn consume_and_restore(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Restored, RestoreError> {
    restore_operator(transaction, &restore_request(id)).await
}

/// The whole operation row.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
struct Operation {
    id: String,
    tenant_id: Option<String>,
    actor_id: String,
    kind: String,
    request_digest: Vec<u8>,
    expected_revision: i64,
    immutable_plan: Value,
    challenge_hash: Option<Vec<u8>>,
    expires_us: Option<i64>,
    consumed_us: Option<i64>,
    revoked_us: Option<i64>,
    revocation_operation_id: Option<String>,
    approves_operation_id: Option<String>,
    revision: i64,
    outcome: String,
    audit_id: String,
}

async fn operation(connection: &mut PgConnection, id: &str) -> Operation {
    sqlx::query_as(
        "SELECT id, tenant_id, actor_id, kind, request_digest, expected_revision, \
         immutable_plan, challenge_hash, \
         (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_us, \
         (extract(epoch FROM consumed_at) * 1000000)::bigint AS consumed_us, \
         (extract(epoch FROM revoked_at) * 1000000)::bigint AS revoked_us, \
         revocation_operation_id, approves_operation_id, revision, outcome, audit_id \
         FROM administrative_operation WHERE id = $1",
    )
    .bind(id)
    .fetch_one(connection)
    .await
    .unwrap()
}

async fn pool_operation(pool: &PgPool, id: &str) -> Operation {
    operation(&mut pool.acquire().await.unwrap(), id).await
}

/// Every row of every table of the schema, as text, by table.
async fn snapshot(connection: &mut PgConnection) -> BTreeMap<String, Vec<String>> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema() \
         AND tablename NOT LIKE '\\_sqlx%' ORDER BY 1",
    )
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    assert!(tables.len() > 20, "{tables:?}");
    let mut snapshot = BTreeMap::new();
    for table in tables {
        // The names come from the catalog.
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT t::text FROM \"{table}\" t ORDER BY t::text COLLATE \"C\""
        )))
        .fetch_all(&mut *connection)
        .await
        .unwrap();
        snapshot.insert(table, rows);
    }
    snapshot
}

async fn pool_snapshot(pool: &PgPool) -> BTreeMap<String, Vec<String>> {
    snapshot(&mut pool.acquire().await.unwrap()).await
}

async fn verify(pool: &PgPool) -> ChainVerdict {
    verify_audit_chain(&mut pool.acquire().await.unwrap())
        .await
        .unwrap()
}

fn security_admin(key: &str) -> OperatorRequest<'_> {
    OperatorRequest {
        public_identity: key,
        scope: OperatorScope::Instance,
        role: AdminRole::SecurityAdmin,
    }
}

async fn authorize_security_admin(pool: &PgPool, key: &str) -> Option<AuthorizedOperator> {
    registry::authorize_operator(pool, &security_admin(key))
        .await
        .unwrap()
}

/// Inserts an operation row by other means: `kind`, `plan`, with or
/// without a challenge hash, at `expected_revision`, expiring at
/// `expires()`, recorded by `aud_issue_1`.
async fn insert_raw(
    pool: &PgPool,
    id: &str,
    kind: &str,
    plan: Value,
    challenge_hash: bool,
    expected_revision: i64,
) {
    sqlx::query(
        "INSERT INTO administrative_operation (id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, challenge_hash, expires_at, outcome, audit_id) \
         VALUES ($1, 'deployment_operator', $2, $3, $4, $5, CASE WHEN $6 THEN $7::bytea END, \
         timestamptz 'epoch' + $8 * interval '1 microsecond', 'issued', 'aud_issue_1')",
    )
    .bind(id)
    .bind(kind)
    .bind(&DIGEST[..])
    .bind(expected_revision)
    .bind(plan)
    .bind(challenge_hash)
    .bind(&HASH[..])
    .bind(micros(expires()))
    .execute(pool)
    .await
    .unwrap();
}

/// Sets `consumed_at` to `$2` microseconds after the epoch by other means.
const RAW_CONSUME: &str = "UPDATE administrative_operation \
     SET consumed_at = timestamptz 'epoch' + $2 * interval '1 microsecond', \
     revision = revision + 1 WHERE id = $1";

/// Revokes the operation `id` by other means, naming `by`.
async fn raw_revoke(connection: &mut PgConnection, id: &str, by: &str) {
    sqlx::query(
        "UPDATE administrative_operation SET revoked_at = timestamptz 'epoch' + $3 * interval \
         '1 microsecond', revocation_operation_id = $2, revision = revision + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(by)
    .bind(micros(at(1_500_000)))
    .execute(connection)
    .await
    .unwrap();
}

#[track_caller]
fn assert_not_issuable<T: Debug>(result: Result<T, ChallengeError>) {
    match result {
        Err(err @ ChallengeError::NotIssuable) => {
            assert_eq!(format!("{err:?}"), "NotIssuable");
        }
        other => panic!("expected NotIssuable: {other:?}"),
    }
}

#[track_caller]
fn assert_not_restorable<T: Debug>(result: Result<T, RestoreError>) -> RestoreError {
    match result {
        Err(err @ RestoreError::NotRestorable) => {
            assert_eq!(format!("{err:?}"), "NotRestorable");
            assert_eq!(
                err.to_string(),
                "no recovery challenge authorizes this restoration"
            );
            err
        }
        other => panic!("expected NotRestorable: {other:?}"),
    }
}

#[track_caller]
fn assert_issue_encode<T: Debug>(result: Result<T, ChallengeError>, message: &str) {
    match result {
        Err(ChallengeError::Store(RegistryError::Other(sqlx::Error::Encode(err)))) => {
            assert_eq!(err.to_string(), message)
        }
        other => panic!("expected an encode error {message:?}: {other:?}"),
    }
}

#[track_caller]
fn assert_restore_encode<T: Debug>(result: Result<T, RestoreError>, message: &str) {
    match result {
        Err(RestoreError::Store(RegistryError::Other(sqlx::Error::Encode(err)))) => {
            assert_eq!(err.to_string(), message)
        }
        other => panic!("expected an encode error {message:?}: {other:?}"),
    }
}

#[track_caller]
fn assert_restore_exists<T: Debug>(result: Result<T, RestoreError>, name: &str) {
    match result {
        Err(RestoreError::Store(RegistryError::AlreadyExists { constraint })) => {
            assert_eq!(constraint, name)
        }
        other => panic!("expected AlreadyExists {name}: {other:?}"),
    }
}

/// The counts of operations and audit events, and the unrevoked
/// credentials, as `connection` sees them.
async fn counts(connection: &mut PgConnection) -> [i64; 3] {
    let row: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM administrative_operation), \
                (SELECT count(*) FROM audit_event), \
                (SELECT count(*) FROM admin_credential WHERE revoked_at IS NULL)",
    )
    .fetch_one(connection)
    .await
    .unwrap();
    [row.0, row.1, row.2]
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_recovery_state_is_read_after_bootstrap_only() {
    let (db, pool) = migrated().await;
    assert_eq!(get_recovery_state(&pool).await.unwrap(), None);
    db.drop([pool]).await;

    let (db, pool) = bootstrapped().await;
    assert_eq!(
        get_recovery_state(&pool).await.unwrap(),
        Some(RecoveryState {
            instance_id: INSTANCE.into(),
            bootstrap_closed: true,
            recovery_public_key: KEY.to_vec(),
            recovery_key_epoch: 1,
            revision: 1,
        })
    );
    db.drop([pool]).await;
}

/// The event comes first, with the operation's ID as its object, and the
/// row references it; every column of the row is exact.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_issue_appends_its_event_and_then_inserts_the_operation() {
    let (db, pool) = bootstrapped().await;
    let challenge = issue(&pool, "op_1", "aud_issue_1").await;
    assert_eq!(
        (
            &challenge.operation_id[..],
            challenge.expires_at,
            challenge.expected_revision
        ),
        ("op_1", expires(), 1)
    );
    let event = &challenge.audit_event;
    assert_eq!(
        (
            &event.id[..],
            event.tenant_id.as_deref(),
            event.sequence,
            event.timestamp,
            &event.actor,
            &event.action[..],
            &event.object_id[..],
            event.previous_revision,
            event.new_revision,
            &event.outcome[..],
        ),
        (
            "aud_issue_1",
            None,
            2,
            at(1_000_000),
            &AuditActor::Operator("deployment_operator".into()),
            "administrative_operation.create",
            "op_1",
            None,
            Some(1),
            "success",
        )
    );
    assert_eq!(event.compute_hash().unwrap(), event.hash);
    let actor: String =
        sqlx::query_scalar("SELECT actor FROM audit_event WHERE id = 'aud_issue_1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(actor, r#"{"id":"deployment_operator","type":"operator"}"#);
    assert_eq!(
        pool_operation(&pool, "op_1").await,
        Operation {
            id: "op_1".into(),
            tenant_id: None,
            actor_id: "deployment_operator".into(),
            kind: "operator_restoration".into(),
            request_digest: DIGEST.to_vec(),
            expected_revision: 1,
            immutable_plan: Value::Object(good_plan()),
            challenge_hash: Some(HASH.to_vec()),
            expires_us: Some(micros(expires())),
            consumed_us: None,
            revoked_us: None,
            revocation_operation_id: None,
            approves_operation_id: None,
            revision: 1,
            outcome: "issued".into(),
            audit_id: "aud_issue_1".into(),
        }
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    // The recovery state is read, not written.
    assert_eq!(
        get_recovery_state(&pool).await.unwrap().map(|s| s.revision),
        Some(1)
    );
    db.drop([pool]).await;
}

/// TTLs of 1 s to 15 min are accepted and stored as `now + ttl`; 0, 1 ns,
/// 1 s - 1 ns, 15 min + 1 ns and `Duration::MAX` are encode errors that
/// run no statement, so the transaction stays usable and holds nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_ttl_is_one_second_to_fifteen_minutes() {
    let (db, pool) = bootstrapped().await;
    let plan = good_plan();
    for (index, ttl) in [MIN_CHALLENGE_TTL, DEFAULT_CHALLENGE_TTL, MAX_CHALLENGE_TTL]
        .into_iter()
        .enumerate()
    {
        let id = format!("op_ttl_{index}");
        let audit = format!("aud_ttl_{index}");
        let mut request = issue_request(&id, &audit, &plan);
        request.ttl = ttl;
        let challenge = issue_on(&pool, &request).await.unwrap();
        let expected = UNIX_EPOCH
            + Duration::from_micros(
                u64::try_from(
                    (issue_time() + ttl)
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros(),
                )
                .unwrap(),
            );
        assert_eq!(challenge.expires_at, expected, "{ttl:?}");
        assert_eq!(
            pool_operation(&pool, &id).await.expires_us,
            Some(micros(expected))
        );
    }
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let before = counts(&mut transaction).await;
    for ttl in [
        Duration::ZERO,
        Duration::from_nanos(1),
        MIN_CHALLENGE_TTL - Duration::from_nanos(1),
        MAX_CHALLENGE_TTL + Duration::from_nanos(1),
        Duration::MAX,
    ] {
        let mut request = issue_request("op_bad", "aud_bad", &plan);
        request.ttl = ttl;
        assert_issue_encode(
            issue_recovery_challenge(&mut transaction, &request).await,
            "challenge TTL is not 1 second to 15 minutes",
        );
        assert_eq!(counts(&mut transaction).await, before, "{ttl:?}");
    }
    transaction.rollback().await.unwrap();
    drop(connection);
    db.drop([pool]).await;
}

/// Another kind, a digest of another length, a plan without a string
/// `instance_id` and an integer `recovery_key_epoch`, without the
/// replacement's strings or without its key in lowercase hexadecimal are
/// encode errors before any statement.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_issue_checks_its_kind_digests_and_plan_before_any_statement() {
    let (db, pool) = bootstrapped().await;
    let good = good_plan();
    let changed = |name: &str, value: Option<Value>| {
        let mut plan = good_plan();
        match value {
            Some(value) => plan.insert(name.into(), value),
            None => plan.remove(name),
        };
        plan
    };
    let binding_plans = [
        plan(INSTANCE, json!("1")),
        plan(INSTANCE, json!(1.0)),
        plan(INSTANCE, json!(null)),
        changed("recovery_key_epoch", None),
        changed("instance_id", None),
        changed("instance_id", Some(json!(7))),
    ];
    let replacement_plans = [
        changed("admin_id", None),
        changed("credential_id", Some(json!(1))),
        changed("binding_id", Some(json!(null))),
        changed("public_identity", Some(json!(["spki-sha256:new"]))),
        changed("trust_anchor_ref", None),
    ];
    let key_plans = [
        changed("new_recovery_public_key", None),
        changed("new_recovery_public_key", Some(json!(hex(&NEW_KEY[..31])))),
        changed(
            "new_recovery_public_key",
            Some(json!(hex(&NEW_KEY).to_uppercase().replace('2', "A"))),
        ),
        changed("new_recovery_public_key", Some(json!(NEW_KEY.to_vec()))),
    ];
    let short = [1; 31];
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let before = snapshot(&mut transaction).await;
    for kind in ["approve", "", "OPERATOR_RESTORATION"] {
        let mut request = issue_request("op_bad", "aud_bad", &good);
        request.kind = kind;
        assert_issue_encode(
            issue_recovery_challenge(&mut transaction, &request).await,
            "recovery challenge kind is not operator_restoration",
        );
    }
    let mut request = issue_request("op_bad", "aud_bad", &good);
    request.request_digest = &short;
    assert_issue_encode(
        issue_recovery_challenge(&mut transaction, &request).await,
        "request digest is not 32 to 64 bytes",
    );
    let mut request = issue_request("op_bad", "aud_bad", &good);
    request.challenge_hash = &short;
    assert_issue_encode(
        issue_recovery_challenge(&mut transaction, &request).await,
        "challenge hash is not 32 to 64 bytes",
    );
    for (plans, message) in [
        (
            &binding_plans[..],
            "plan lacks a string instance_id or an integer recovery_key_epoch",
        ),
        (
            &replacement_plans[..],
            "plan lacks a string admin_id, credential_id, binding_id, public_identity or \
             trust_anchor_ref",
        ),
        (
            &key_plans[..],
            "plan new_recovery_public_key is not 64 lowercase hexadecimal digits",
        ),
    ] {
        for plan in plans {
            assert_issue_encode(
                issue_recovery_challenge(
                    &mut transaction,
                    &issue_request("op_bad", "aud_bad", plan),
                )
                .await,
                message,
            );
        }
    }
    let mut request = issue_request("op_bad", "aud_bad", &good);
    request.now = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    assert_issue_encode(
        issue_recovery_challenge(&mut transaction, &request).await,
        "audit timestamp outside the years 0000 to 9999",
    );
    assert_eq!(snapshot(&mut transaction).await, before);
    // Still usable: a good issue goes through in the same transaction.
    issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_1", "aud_issue_1", &good),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(pool_operation(&pool, "op_1").await.revision, 1);
    db.drop([pool]).await;
}

/// No recovery state, or one whose `bootstrap_closed` is false (only a
/// write by other means leaves one), is `NotIssuable`, and nothing is
/// written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn no_challenge_is_issued_without_a_closed_recovery_state() {
    let (db, pool) = migrated().await;
    let before = pool_snapshot(&pool).await;
    assert_not_issuable(issue_on(&pool, &issue_request("op_1", "aud_1", &good_plan())).await);
    assert_eq!(pool_snapshot(&pool).await, before);

    sqlx::raw_sql(
        "INSERT INTO instance_security_policy (instance_id) \
         VALUES ('019a9f3c-5b2e-7c41-9d8e-0123456789ab'); \
         INSERT INTO recovery_state (instance_id, bootstrap_closed, recovery_public_key, \
         recovery_key_epoch) VALUES ('019a9f3c-5b2e-7c41-9d8e-0123456789ab', false, \
         '\\x1111111111111111111111111111111111111111111111111111111111111111', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let before = pool_snapshot(&pool).await;
    assert_not_issuable(issue_on(&pool, &issue_request("op_1", "aud_1", &good_plan())).await);
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A plan for another instance or another epoch is `NotIssuable`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn no_challenge_is_issued_for_another_instance_or_epoch() {
    let (db, pool) = bootstrapped().await;
    let before = pool_snapshot(&pool).await;
    for plan in [
        plan(OTHER_INSTANCE, json!(1)),
        plan("", json!(1)),
        plan(INSTANCE, json!(2)),
        plan(INSTANCE, json!(0)),
        plan(INSTANCE, json!(-1)),
    ] {
        assert_not_issuable(issue_on(&pool, &issue_request("op_1", "aud_1", &plan)).await);
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// `expected_revision` is the recovery state's revision when the challenge
/// is issued, and a restore must name it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_binds_the_current_recovery_state_revision() {
    let (db, pool) = bootstrapped().await;
    issue(&pool, "op_0", "aud_issue_0").await;
    sqlx::query("UPDATE recovery_state SET revision = revision + 1")
        .execute(&pool)
        .await
        .unwrap();
    let challenge = issue(&pool, "op_1", "aud_issue_1").await;
    assert_eq!(challenge.expected_revision, 2);
    assert_eq!(pool_operation(&pool, "op_1").await.expected_revision, 2);
    let before = pool_snapshot(&pool).await;
    assert_not_restorable(restore_on(&pool, &restore_request("op_1")).await);
    // A challenge issued at revision 1 is restorable neither at its own
    // revision, which is no longer the state's, nor at the state's.
    for revision in [1, 2] {
        let mut stale = restore_request("op_0");
        stale.binding.expected_revision = revision;
        assert_not_restorable(restore_on(&pool, &stale).await);
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    let mut bound = restore_request("op_1");
    bound.binding.expected_revision = 2;
    let restored = restore_on(&pool, &bound).await.unwrap();
    assert_eq!(restored.recovery_state_revision, 3);
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!(
        (row.expected_revision, row.consumed_us),
        (2, Some(micros(now())))
    );
    assert_eq!(pool_operation(&pool, "op_0").await.consumed_us, None);
    db.drop([pool]).await;
}

/// The restore consumes the challenge: `consumed_at` is `now` and the
/// revision advances; a replay, in the same transaction or after the
/// commit, is `NotRestorable` and writes nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_is_consumed_once() {
    let (db, pool) = issued().await;
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    let after = snapshot(&mut transaction).await;
    let mut replay = restore_request("op_1");
    replay.audit_event_id = "aud_replay";
    replay.rotation_audit_event_id = "aud_replay_rotate";
    assert_not_restorable(restore_operator(&mut transaction, &replay).await);
    assert_eq!(snapshot(&mut transaction).await, after);
    transaction.commit().await.unwrap();
    drop(connection);
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!(
        (row.consumed_us, row.revision, &row.outcome[..]),
        (Some(micros(now())), 3, "restored")
    );
    let before = pool_snapshot(&pool).await;
    for later in [now(), now() + Duration::from_secs(1)] {
        let mut request = replay;
        request.now = later;
        assert_not_restorable(restore_on(&pool, &request).await);
        // Also bound to the state the restore left.
        request.binding.recovery_key_epoch = 2;
        request.binding.expected_revision = 2;
        request.new_recovery_public_key = &THIRD_KEY;
        assert_not_restorable(restore_on(&pool, &request).await);
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// `$now < expires_at`, in the statement, against the caller's `now`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_expires_at_its_expiry() {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    for late in [
        expires(),
        expires() + Duration::from_micros(1),
        expires() + Duration::from_secs(3600),
    ] {
        let mut request = restore_request("op_1");
        request.now = late;
        assert_not_restorable(restore_on(&pool, &request).await);
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    // A `now` the audit event could not carry is refused before the
    // statement, not compared.
    let mut request = restore_request("op_1");
    request.now = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    assert_restore_encode(
        restore_on(&pool, &request).await,
        "audit timestamp outside the years 0000 to 9999",
    );
    let last = expires() - Duration::from_micros(1);
    let mut request = restore_request("op_1");
    request.now = last;
    let restored = restore_on(&pool, &request).await.unwrap();
    assert_eq!(restored.audit_event.timestamp, last);
    assert_eq!(
        pool_operation(&pool, "op_1").await.consumed_us,
        Some(micros(last))
    );
    db.drop([pool]).await;
}

/// A challenge revoked before its restore is `NotRestorable`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_revoked_challenge_is_not_restorable() {
    let (db, pool) = issued().await;
    issue(&pool, "op_2", "aud_issue_2").await;
    raw_revoke(&mut pool.acquire().await.unwrap(), "op_1", "op_2").await;
    let before = pool_snapshot(&pool).await;
    assert_not_restorable(restore_on(&pool, &restore_request("op_1")).await);
    assert_eq!(pool_snapshot(&pool).await, before);
    // The other one still is.
    restore_on(&pool, &restore_request("op_2")).await.unwrap();
    db.drop([pool]).await;
}

/// Every miss of the consume is the same `NotRestorable`, equal by
/// `Debug`, `Display` and `PartialEq`, and writes nothing. A row written by
/// other means with every value right is restorable, so each miss is its
/// one difference.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_consume_miss_is_the_same_not_restorable() {
    let (db, pool) = issued().await;
    issue(&pool, "op_revoker", "aud_issue_2").await;
    issue(&pool, "op_revoked", "aud_issue_3").await;
    raw_revoke(
        &mut pool.acquire().await.unwrap(),
        "op_revoked",
        "op_revoker",
    )
    .await;
    issue(&pool, "op_replayed", "aud_issue_4").await;
    issue(&pool, "op_failed", "aud_issue_5").await;
    sqlx::query(
        "UPDATE administrative_operation SET outcome = 'failed', revision = revision + 1 \
         WHERE id = 'op_failed'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(RAW_CONSUME)
        .bind("op_replayed")
        .bind(micros(now()))
        .execute(&pool)
        .await
        .unwrap();
    let with = |name: &str, value: Value| {
        let mut plan = good_plan();
        plan.insert(name.into(), value);
        json!(plan)
    };
    let without = |name: &str| {
        let mut plan = good_plan();
        plan.remove(name);
        json!(plan)
    };
    let rows: [(&str, &str, Value, bool, i64); 14] = [
        (
            "raw_good",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            true,
            1,
        ),
        (
            "raw_kind",
            "route_bundle_approval",
            json!(good_plan()),
            true,
            1,
        ),
        (
            "raw_no_hash",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            false,
            1,
        ),
        (
            "raw_epoch_string",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!("1")),
            true,
            1,
        ),
        (
            "raw_epoch_float",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(1.0)),
            true,
            1,
        ),
        (
            "raw_epoch_fraction",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(1.5)),
            true,
            1,
        ),
        (
            "raw_epoch_null",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(null)),
            true,
            1,
        ),
        (
            "raw_epoch_negative",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(-1)),
            true,
            1,
        ),
        (
            "raw_epoch_array",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!([1])),
            true,
            1,
        ),
        (
            "raw_epoch_missing",
            OPERATOR_RESTORATION,
            without("recovery_key_epoch"),
            true,
            1,
        ),
        (
            "raw_instance_missing",
            OPERATOR_RESTORATION,
            without("instance_id"),
            true,
            1,
        ),
        (
            "raw_instance_number",
            OPERATOR_RESTORATION,
            with("instance_id", json!(1)),
            true,
            1,
        ),
        (
            "raw_other_instance",
            OPERATOR_RESTORATION,
            json!(plan(OTHER_INSTANCE, json!(1))),
            true,
            1,
        ),
        (
            "raw_upper_instance",
            OPERATOR_RESTORATION,
            json!(plan(&INSTANCE.to_uppercase(), json!(1))),
            true,
            1,
        ),
    ];
    for (id, kind, plan, hash, revision) in rows {
        insert_raw(&pool, id, kind, plan, hash, revision).await;
    }
    // A tenant's operation with every other value right.
    registry::create_tenant(
        &pool,
        &NewTenant {
            id: "ten_a".into(),
            name: "Tenant A".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, challenge_hash, expires_at, outcome, audit_id) \
         SELECT 'raw_tenant', 'ten_a', actor_id, kind, request_digest, expected_revision, \
         immutable_plan, challenge_hash, expires_at, outcome, audit_id \
         FROM administrative_operation WHERE id = 'raw_good'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let bound = binding();
    let other_digest = ChallengeBinding {
        request_digest: &OTHER_DIGEST,
        ..bound
    };
    let short_digest = ChallengeBinding {
        request_digest: &DIGEST[..31],
        ..bound
    };
    let other_instance = ChallengeBinding {
        instance_id: OTHER_INSTANCE,
        ..bound
    };
    let upper_instance = ChallengeBinding {
        instance_id: "019A9F3C-5B2E-7C41-9D8E-0123456789AB",
        ..bound
    };
    let other_revision = ChallengeBinding {
        expected_revision: 2,
        ..bound
    };
    let zero_revision = ChallengeBinding {
        expected_revision: 0,
        ..bound
    };
    let other_epoch = ChallengeBinding {
        recovery_key_epoch: 2,
        ..bound
    };
    let negative_epoch = ChallengeBinding {
        recovery_key_epoch: -1,
        ..bound
    };
    let before = pool_snapshot(&pool).await;
    let mut misses = Vec::new();
    for (id, binding, at) in [
        ("op_unknown", bound, now()),
        ("", bound, now()),
        ("op_1", other_digest, now()),
        ("op_1", short_digest, now()),
        ("op_1", other_instance, now()),
        ("op_1", upper_instance, now()),
        ("op_1", other_revision, now()),
        ("op_1", zero_revision, now()),
        ("op_1", other_epoch, now()),
        ("op_1", bound, expires()),
        ("op_revoked", bound, now()),
        ("op_replayed", bound, now()),
        ("op_failed", bound, now()),
        ("raw_kind", bound, now()),
        ("raw_no_hash", bound, now()),
        ("raw_tenant", bound, now()),
        ("raw_epoch_string", bound, now()),
        ("raw_epoch_float", bound, now()),
        ("raw_epoch_fraction", bound, now()),
        ("raw_epoch_null", bound, now()),
        ("raw_epoch_negative", bound, now()),
        // A plan whose epoch is negative matches a binding with that epoch
        // only if the recovery state had it, which it cannot.
        ("raw_epoch_negative", negative_epoch, now()),
        ("raw_epoch_array", bound, now()),
        ("raw_epoch_missing", bound, now()),
        ("raw_instance_missing", bound, now()),
        ("raw_instance_number", bound, now()),
        ("raw_other_instance", bound, now()),
        ("raw_other_instance", other_instance, now()),
        ("raw_upper_instance", bound, now()),
        ("raw_upper_instance", upper_instance, now()),
    ] {
        let mut request = restore_request(id);
        request.binding = binding;
        request.now = at;
        misses.push((id, assert_not_restorable(restore_on(&pool, &request).await)));
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    let (_, first) = &misses[0];
    for (id, miss) in &misses {
        assert_eq!(miss, first, "{id}");
        assert_eq!(format!("{miss:?}"), format!("{first:?}"), "{id}");
        assert_eq!(miss.to_string(), first.to_string(), "{id}");
    }
    // The issued challenge is restorable, and so is the control row.
    let mut transaction = pool.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.rollback().await.unwrap();
    restore_on(&pool, &restore_request("raw_good"))
        .await
        .unwrap();
    db.drop([pool]).await;
}

/// The single-use property holds in the database even for a statement
/// without the predicates: a replay and a consume after a revocation fail
/// with `SK001`, and a consume at the expiry with `23514`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_database_refuses_a_replay_a_late_consume_and_one_after_revocation() {
    let (db, pool) = issued().await;
    issue(&pool, "op_revoker", "aud_issue_2").await;
    issue(&pool, "op_revoked", "aud_issue_3").await;
    raw_revoke(
        &mut pool.acquire().await.unwrap(),
        "op_revoked",
        "op_revoker",
    )
    .await;
    restore_on(&pool, &restore_request("op_1")).await.unwrap();
    let before = pool_snapshot(&pool).await;
    for (id, at, expected) in [
        ("op_1", now() + Duration::from_secs(1), None),
        ("op_revoked", now(), None),
        (
            "op_revoker",
            expires(),
            Some("administrative_operation_consumed_before_expiry_check"),
        ),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        let err = sqlx::query(RAW_CONSUME)
            .bind(id)
            .bind(micros(at))
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        let code = err
            .as_database_error()
            .unwrap()
            .code()
            .unwrap()
            .into_owned();
        match (RegistryError::from(err), expected) {
            (RegistryError::Guard, None) => assert_eq!(code, "SK001", "{id}"),
            (
                RegistryError::Invariant {
                    kind: InvariantKind::Check,
                    constraint: Some(constraint),
                },
                Some(name),
            ) => {
                assert_eq!((&code[..], constraint), ("23514", name), "{id}");
            }
            (other, _) => panic!("{id}: {other:?}"),
        }
        transaction.rollback().await.unwrap();
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// Whether the backend `blocked` waits for a lock held by `holder`.
async fn is_blocked(pool: &PgPool, blocked: i32, holder: i32) -> bool {
    sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
        .bind(holder)
        .bind(blocked)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Waits, without sleeping, until the backend `blocked` waits for a lock
/// held by `holder`.
async fn wait_until_blocked(pool: &PgPool, blocked: i32, holder: i32) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !is_blocked(pool, blocked, holder).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the second transaction never waited for the first");
}

/// Waits, without sleeping, until the backend `blocked` of `task` waits
/// for a lock held by `holder` (`true`), or `task` ends without having
/// waited (`false`).
async fn waits_for<T>(
    pool: &PgPool,
    blocked: i32,
    holder: i32,
    task: &tokio::task::JoinHandle<T>,
) -> bool {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if is_blocked(pool, blocked, holder).await {
                return true;
            }
            if task.is_finished() {
                return false;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the task neither waited nor ended")
}

/// Two restores of one challenge: the second waits for the first (on the
/// credentials it locked); after the first commits it is `NotRestorable`,
/// after a rollback it restores.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn of_two_concurrent_restores_of_one_challenge_exactly_one_wins() {
    for commit in [true, false] {
        let (db, pool) = issued().await;
        let mut first = pool.acquire().await.unwrap().detach();
        let mut second = pool.acquire().await.unwrap().detach();
        let (first_pid, second_pid) = (
            backend_pid(&mut first).await,
            backend_pid(&mut second).await,
        );
        let mut transaction = first.begin().await.unwrap();
        consume_and_restore(&mut transaction, "op_1").await.unwrap();
        let later = now() + Duration::from_secs(1);
        let waiting = tokio::spawn(async move {
            let mut other = second.begin().await.unwrap();
            let mut request = restore_request("op_1");
            request.now = later;
            let restored = restore_operator(&mut other, &request).await;
            if restored.is_ok() {
                other.commit().await.unwrap();
            } else {
                other.rollback().await.unwrap();
            }
            second.close().await.unwrap();
            restored
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        if commit {
            transaction.commit().await.unwrap();
        } else {
            transaction.rollback().await.unwrap();
        }
        first.close().await.unwrap();
        let outcome = waiting.await.unwrap();
        let row = pool_operation(&pool, "op_1").await;
        let winner = if commit {
            assert_not_restorable(outcome);
            now()
        } else {
            let restored = outcome.unwrap();
            assert_eq!(restored.audit_event.timestamp, later);
            later
        };
        assert_eq!(
            (row.consumed_us, row.revision, &row.outcome[..]),
            (Some(micros(winner)), 3, "restored")
        );
        let state = get_recovery_state(&pool).await.unwrap().unwrap();
        assert_eq!((state.recovery_key_epoch, state.revision), (2, 2));
        assert_eq!(
            verify(&pool).await,
            ChainVerdict::Intact { last_sequence: 4 }
        );
        db.drop([pool]).await;
    }
}

/// Operators besides the bootstrap one: `adm_two` (enabled) with an
/// enabled, a disabled unrevoked and a revoked credential, an instance
/// `security_admin` and a tenant `trust_admin` binding; `adm_three`
/// (disabled) with an enabled credential and an instance `auditor`
/// binding.
async fn more_operators(pool: &PgPool) {
    registry::create_tenant(
        pool,
        &NewTenant {
            id: "ten_a".into(),
            name: "Tenant A".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (id, status) in [
        ("adm_two", Status::Enabled),
        ("adm_three", Status::Disabled),
    ] {
        registry::create_admin_identity(
            pool,
            &NewAdminIdentity {
                id: id.into(),
                status,
                created_at: at(100),
            },
        )
        .await
        .unwrap();
    }
    for (id, admin, status) in [
        ("crd_two_a", "adm_two", Status::Enabled),
        ("crd_two_b", "adm_two", Status::Disabled),
        ("crd_two_c", "adm_two", Status::Enabled),
        ("crd_three", "adm_three", Status::Enabled),
    ] {
        registry::create_admin_credential(
            pool,
            &NewAdminCredential {
                id: id.into(),
                admin_id: admin.into(),
                public_identity: format!("spki-sha256:{id}"),
                trust_anchor_ref: "deployment/operator-ca".into(),
                status,
            },
        )
        .await
        .unwrap();
    }
    registry::revoke_admin_credential(pool, "crd_two_c", at(500))
        .await
        .unwrap();
    for (id, admin, role, tenant) in [
        ("rb_two", "adm_two", AdminRole::SecurityAdmin, None),
        (
            "rb_two_ten",
            "adm_two",
            AdminRole::TrustAdmin,
            Some("ten_a"),
        ),
        ("rb_three", "adm_three", AdminRole::Auditor, None),
    ] {
        registry::create_admin_role_binding(
            pool,
            &NewAdminRoleBinding {
                id: id.into(),
                admin_id: admin.into(),
                role,
                tenant_id: tenant.map(Into::into),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
}

/// The full restoration: a replacement `security_admin` that authorizes,
/// every unrevoked credential revoked at `now` (the replaced operator's
/// included), the revoked one untouched, identities and bindings unchanged,
/// the key rotated to epoch 2, the operation restored, both events exact
/// and the chain intact; the old epoch is refused afterwards and the new
/// one works.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_enrolls_a_replacement_revokes_every_credential_and_rotates_the_key() {
    let (db, pool) = bootstrapped().await;
    more_operators(&pool).await;
    let issue_event = issue(&pool, "op_1", "aud_issue_1").await.audit_event;
    let last_issue = issue(&pool, "op_2", "aud_issue_2").await.audit_event;
    let identities_before: Vec<(String, String)> =
        sqlx::query_as("SELECT id, status FROM admin_identity ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let bindings_before: Vec<String> =
        sqlx::query_scalar("SELECT b::text FROM admin_role_binding b ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let operation_before = pool_operation(&pool, "op_1").await;

    let mut transaction = pool.begin().await.unwrap();
    let restored = consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.commit().await.unwrap();

    assert_eq!(
        (
            &restored.admin_id[..],
            &restored.credential_id[..],
            &restored.binding_id[..],
            &restored.revoked_credential_ids[..],
            restored.recovery_key_epoch,
            restored.recovery_state_revision,
        ),
        (
            "adm_new",
            "crd_new",
            "rb_new",
            &["crd_first", "crd_three", "crd_two_a", "crd_two_b"].map(String::from)[..],
            2,
            2,
        )
    );
    // Every previously unrevoked credential, enabled or not, is revoked at
    // `now`; the one revoked before keeps its time.
    for id in ["crd_first", "crd_three", "crd_two_a", "crd_two_b"] {
        let credential = registry::get_admin_credential(&pool, id).await.unwrap();
        assert_eq!(
            (credential.status, credential.revoked_at),
            (Status::Disabled, Some(now())),
            "{id}"
        );
    }
    let earlier = registry::get_admin_credential(&pool, "crd_two_c")
        .await
        .unwrap();
    assert_eq!(
        (earlier.status, earlier.revoked_at),
        (Status::Disabled, Some(at(500)))
    );
    // The replacement: enabled, unrevoked, an instance security_admin.
    let identity = registry::get_admin_identity(&pool, "adm_new")
        .await
        .unwrap();
    assert_eq!(
        (identity.status, identity.created_at),
        (Status::Enabled, now())
    );
    let credential = registry::get_admin_credential(&pool, "crd_new")
        .await
        .unwrap();
    assert_eq!(
        (
            &credential.admin_id[..],
            &credential.public_identity[..],
            &credential.trust_anchor_ref[..],
            credential.status,
            credential.revoked_at
        ),
        (
            "adm_new",
            "spki-sha256:new",
            "deployment/operator-ca",
            Status::Enabled,
            None
        )
    );
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:new").await,
        Some(AuthorizedOperator {
            admin_id: "adm_new".into(),
            credential_id: "crd_new".into(),
            binding_id: "rb_new".into(),
            role: AdminRole::SecurityAdmin,
        })
    );
    for key in ["spki-sha256:first", "spki-sha256:crd_two_a"] {
        assert_eq!(authorize_security_admin(&pool, key).await, None, "{key}");
    }
    // Identities and the bindings that existed are unchanged.
    let identities_after: Vec<(String, String)> =
        sqlx::query_as("SELECT id, status FROM admin_identity WHERE id <> 'adm_new' ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(identities_after, identities_before);
    let bindings_after: Vec<String> = sqlx::query_scalar(
        "SELECT b::text FROM admin_role_binding b WHERE id <> 'rb_new' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(bindings_after, bindings_before);
    let role_binding = registry::get_admin_role_binding(&pool, "rb_new")
        .await
        .unwrap();
    assert_eq!(
        (
            &role_binding.admin_id[..],
            role_binding.role,
            role_binding.tenant_id,
            role_binding.status,
            role_binding.revision
        ),
        (
            "adm_new",
            AdminRole::SecurityAdmin,
            None,
            Status::Enabled,
            1
        )
    );
    // The key is rotated and the used one retired.
    assert_eq!(
        get_recovery_state(&pool).await.unwrap(),
        Some(RecoveryState {
            instance_id: INSTANCE.into(),
            bootstrap_closed: true,
            recovery_public_key: NEW_KEY.to_vec(),
            recovery_key_epoch: 2,
            revision: 2,
        })
    );
    // The operation: consumed at `now`, restored, at revision 3.
    assert_eq!(
        pool_operation(&pool, "op_1").await,
        Operation {
            consumed_us: Some(micros(now())),
            revision: 3,
            outcome: "restored".into(),
            ..operation_before
        }
    );
    // The events, by the key that signed (epoch 1), last in the chain: the
    // restore, then the rotation.
    let event = &restored.audit_event;
    let rotation = &restored.rotation_audit_event;
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
            "aud_restore",
            None,
            4,
            Some(last_issue.hash),
            now(),
            &AuditActor::Operator("recovery_key:1".into()),
            "admin_identity.restore",
            "adm_new",
            None,
            None,
            "success",
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
            &rotation.outcome[..],
        ),
        (
            "aud_rotate",
            None,
            5,
            Some(event.hash),
            now(),
            &AuditActor::Operator("recovery_key:1".into()),
            "recovery_state.rotate_key",
            INSTANCE,
            Some(1),
            Some(2),
            "success",
        )
    );
    assert_eq!(issue_event.sequence, 2);
    assert_eq!(event.compute_hash().unwrap(), event.hash);
    assert_eq!(rotation.compute_hash().unwrap(), rotation.hash);
    let stored: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT id, actor, sequence FROM audit_event WHERE sequence > 3 ORDER BY sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let actor = r#"{"id":"recovery_key:1","type":"operator"}"#;
    assert_eq!(
        stored,
        [
            ("aud_restore".into(), actor.into(), 4),
            ("aud_rotate".into(), actor.into(), 5)
        ]
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );

    // The retired epoch is refused for a challenge issued before, also
    // with the new state's binding.
    let before = pool_snapshot(&pool).await;
    assert_not_restorable(restore_on(&pool, &other_request("op_2", &THIRD_KEY)).await);
    assert_not_restorable(restore_on(&pool, &restore_request("op_2")).await);
    let mut current = other_request("op_2", &THIRD_KEY);
    current.binding.recovery_key_epoch = 2;
    current.binding.expected_revision = 2;
    assert_not_restorable(restore_on(&pool, &current).await);
    assert_eq!(pool_snapshot(&pool).await, before);
    // A challenge of the new epoch works.
    let request = RestoreRequest {
        operation_id: "op_3",
        ..current
    };
    let plan = plan_for(INSTANCE, json!(2), &request);
    let challenge = issue_on(&pool, &issue_request("op_3", "aud_issue_3", &plan))
        .await
        .unwrap();
    assert_eq!(challenge.expected_revision, 2);
    let again = restore_on(&pool, &request).await.unwrap();
    assert_eq!(
        (
            again.recovery_key_epoch,
            &again.audit_event.actor,
            &again.revoked_credential_ids[..]
        ),
        (
            3,
            &AuditActor::Operator("recovery_key:2".into()),
            &["crd_new".to_owned()][..]
        )
    );
    db.drop([pool]).await;
}

/// The tables a restore writes, and no other: every row of every other
/// table is the same before and after.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_changes_nothing_else() {
    let (db, pool) = bootstrapped().await;
    more_operators(&pool).await;
    registry::create_principal(
        &pool,
        &NewPrincipal {
            id: "prn_a".into(),
            tenant_id: "ten_a".into(),
            kind: PrincipalKind::Workload,
            name: "workload a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    issue(&pool, "op_1", "aud_issue_1").await;
    issue(&pool, "op_2", "aud_issue_2").await;
    let before = pool_snapshot(&pool).await;
    let mut transaction = pool.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.commit().await.unwrap();
    let after = pool_snapshot(&pool).await;
    let changed: Vec<&str> = before
        .keys()
        .filter(|table| before[*table] != after[*table])
        .map(String::as_str)
        .collect();
    assert_eq!(
        changed,
        [
            "admin_credential",
            "admin_identity",
            "admin_role_binding",
            "administrative_operation",
            "audit_chain_head",
            "audit_event",
            "recovery_state",
        ]
    );
    // Rows are added to these and none is removed.
    for (table, added) in [
        ("admin_identity", 1),
        ("admin_credential", 1),
        ("admin_role_binding", 1),
        ("audit_event", 2),
        ("administrative_operation", 0),
        ("recovery_state", 0),
        ("audit_chain_head", 0),
    ] {
        assert_eq!(after[table].len(), before[table].len() + added, "{table}");
    }
    // Of the operations only op_1 changed.
    let unchanged: Vec<_> = after["administrative_operation"]
        .iter()
        .filter(|row| before["administrative_operation"].contains(row))
        .collect();
    assert_eq!(unchanged.len(), 1);
    assert!(unchanged[0].starts_with("(op_2,"), "{unchanged:?}");
    db.drop([pool]).await;
}

/// A restore that fails after its consume, on a statement or in Rust after
/// the audit head lock, rolls its savepoint back, the consume included: a
/// caller that commits after the `Err` commits nothing of it, and the
/// challenge stays restorable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_restore_commits_nothing_even_when_the_caller_commits() {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    // A statement fails: an event ID is taken (`23505` from the writer),
    // the first event's, the second's, or the second is the first's.
    for (restore_id, rotation_id) in [
        ("aud_issue_1", "aud_rotate"),
        ("aud_restore", "aud_bootstrap"),
        ("aud_restore", "aud_restore"),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        let mut request = restore_request("op_1");
        request.audit_event_id = restore_id;
        request.rotation_audit_event_id = rotation_id;
        assert_restore_exists(
            restore_operator(&mut transaction, &request).await,
            "audit_event_pkey",
        );
        // The transaction is usable and its commit writes nothing.
        sqlx::query("SELECT 1")
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        assert_eq!(pool_snapshot(&pool).await, before, "{restore_id}");
    }

    // The writer refuses in Rust after the head lock: the next sequence
    // would be above 2^53 - 1, for the first event or only for the second.
    let head: Vec<u8> = sqlx::query_scalar("SELECT head_hash FROM audit_chain_head")
        .fetch_one(&pool)
        .await
        .unwrap();
    for sequence in [9_007_199_254_740_991_i64, 9_007_199_254_740_990] {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
             UPDATE audit_chain_head SET sequence = {sequence}; \
             ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER audit_chain_head_advance"
        )))
        .execute(&pool)
        .await
        .unwrap();
        let before = pool_snapshot(&pool).await;
        let mut transaction = pool.begin().await.unwrap();
        match restore_operator(&mut transaction, &restore_request("op_1")).await {
            Err(RestoreError::Store(RegistryError::Other(sqlx::Error::Encode(_)))) => {}
            other => panic!("expected the writer's encode error: {other:?}"),
        }
        transaction.commit().await.unwrap();
        assert_eq!(pool_snapshot(&pool).await, before, "{sequence}");
    }
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!((row.consumed_us, row.revision), (None, 1));
    let credential = registry::get_admin_credential(&pool, "crd_first")
        .await
        .unwrap();
    assert_eq!(
        (credential.status, credential.revoked_at),
        (Status::Enabled, None)
    );
    assert!(
        registry::get_admin_identity(&pool, "adm_new")
            .await
            .is_err()
    );
    assert_eq!(
        get_recovery_state(&pool)
            .await
            .unwrap()
            .unwrap()
            .recovery_key_epoch,
        1
    );

    // With the head back, the same request restores.
    sqlx::raw_sql(
        "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
         UPDATE audit_chain_head SET sequence = 2; \
         ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER audit_chain_head_advance",
    )
    .execute(&pool)
    .await
    .unwrap();
    let restored: Vec<u8> = sqlx::query_scalar("SELECT head_hash FROM audit_chain_head")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(restored, head);
    let mut transaction = pool.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(pool_operation(&pool, "op_1").await.outcome, "restored");
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 4 }
    );
    db.drop([pool]).await;
}

/// An issue whose operation ID is taken fails after its audit event and
/// rolls the event back with its savepoint; a caller that commits after
/// the `Err` commits nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_issue_commits_nothing_even_when_the_caller_commits() {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    let plan = good_plan();
    let mut transaction = pool.begin().await.unwrap();
    match issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_1", "aud_issue_2", &plan),
    )
    .await
    {
        Err(ChallengeError::Store(RegistryError::AlreadyExists { constraint })) => {
            assert_eq!(constraint, "administrative_operation_pkey")
        }
        other => panic!("expected AlreadyExists: {other:?}"),
    }
    sqlx::query("SELECT 1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// A restore whose consume fails (here on a lock timeout, while another
/// transaction holds the operation row) rolls its savepoint back: the
/// caller's transaction stays usable and commits nothing of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_that_times_out_leaves_the_transaction_usable() {
    let (db, pool) = issued().await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM administrative_operation WHERE id = 'op_1' FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let before = pool_snapshot(&pool).await;
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '50ms'")
        .execute(&mut *transaction)
        .await
        .unwrap();
    match restore_operator(&mut transaction, &restore_request("op_1")).await {
        Err(RestoreError::Store(RegistryError::Other(err))) => {
            let code = err
                .as_database_error()
                .unwrap()
                .code()
                .unwrap()
                .into_owned();
            assert_eq!(code, "55P03");
        }
        other => panic!("expected a lock timeout: {other:?}"),
    }
    sqlx::query("SELECT 1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    holder.rollback().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    restore_on(&pool, &restore_request("op_1")).await.unwrap();
    db.drop([pool]).await;
}

/// The replacement's IDs, credential identity and the event IDs must be
/// new: each collision is the insert's or the writer's `AlreadyExists`
/// with its constraint, and the savepoint is rolled back, the consume
/// included, also when the caller commits. Each challenge names the
/// colliding replacement.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_colliding_replacement_is_already_exists() {
    let (db, pool) = issued().await;
    let cases: [(&str, Change, &str); 6] = [
        (
            "op_admin",
            |request| request.admin_id = "adm_first",
            "admin_identity_pkey",
        ),
        (
            "op_credential",
            |request| request.credential_id = "crd_first",
            "admin_credential_pkey",
        ),
        (
            "op_binding",
            |request| request.binding_id = "rb_first",
            "admin_role_binding_pkey",
        ),
        (
            "op_identity",
            |request| request.public_identity = "spki-sha256:first",
            "admin_credential_public_identity_key",
        ),
        (
            "op_both",
            |request| {
                request.credential_id = "crd_first";
                request.public_identity = "spki-sha256:first";
            },
            // Both credential keys taken: the ID is named.
            "admin_credential_pkey",
        ),
        (
            "op_1",
            |request| request.audit_event_id = "aud_bootstrap",
            "audit_event_pkey",
        ),
    ];
    for (index, (id, change, constraint)) in cases.into_iter().enumerate() {
        let mut request = restore_request(id);
        change(&mut request);
        if id != "op_1" {
            let plan = plan_for(INSTANCE, json!(1), &request);
            let audit = format!("aud_issue_{id}");
            issue_on(&pool, &issue_request(id, &audit, &plan))
                .await
                .unwrap();
        }
        let before = pool_snapshot(&pool).await;
        let mut transaction = pool.begin().await.unwrap();
        assert_restore_exists(
            restore_operator(&mut transaction, &request).await,
            constraint,
        );
        transaction.commit().await.unwrap();
        assert_eq!(pool_snapshot(&pool).await, before, "{index} {constraint}");
    }
    db.drop([pool]).await;
}

/// A new key equal to the current one is `RecoveryKeyUnchanged`, a key of
/// another length, a reserved admin ID or a time outside the audit years an
/// encode error; none leaves anything written, and the transaction stays
/// usable for a good restore.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_refused_restore_leaves_nothing_written() {
    let (db, pool) = issued().await;
    let mut same = restore_request("op_same");
    same.new_recovery_public_key = &KEY;
    let plan = plan_for(INSTANCE, json!(1), &same);
    issue_on(&pool, &issue_request("op_same", "aud_issue_same", &plan))
        .await
        .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let before = snapshot(&mut transaction).await;

    match restore_operator(&mut transaction, &same).await {
        Err(err @ RestoreError::RecoveryKeyUnchanged) => {
            assert_eq!(format!("{err:?}"), "RecoveryKeyUnchanged");
            assert_eq!(
                err.to_string(),
                "the new recovery public key is the current one"
            );
        }
        other => panic!("expected RecoveryKeyUnchanged: {other:?}"),
    }
    assert_eq!(snapshot(&mut transaction).await, before);
    // A challenge that is not consumable is refused first (inferred order).
    let mut request = restore_request("op_unknown");
    request.new_recovery_public_key = &KEY;
    assert_not_restorable(restore_operator(&mut transaction, &request).await);
    assert_eq!(snapshot(&mut transaction).await, before);
    // So is a replacement the plan does not name (inferred order).
    let mut request = same;
    request.admin_id = "adm_other";
    assert_not_restorable(restore_operator(&mut transaction, &request).await);
    assert_eq!(snapshot(&mut transaction).await, before);

    let long = [0x22; 33];
    for key in [&[][..], &NEW_KEY[..31], &long[..]] {
        let mut request = restore_request("op_1");
        request.new_recovery_public_key = key;
        assert_restore_encode(
            restore_operator(&mut transaction, &request).await,
            "recovery public key is not a 32-byte Ed25519 key",
        );
    }
    for admin in ["deployment_operator", "recovery_key:1", "recovery_key:2"] {
        let mut request = restore_request("op_1");
        request.admin_id = admin;
        match restore_operator(&mut transaction, &request).await {
            Err(RestoreError::Store(RegistryError::ReservedActorId)) => {}
            other => panic!("{admin}: expected ReservedActorId: {other:?}"),
        }
    }
    let mut request = restore_request("op_1");
    request.now = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    assert_restore_encode(
        restore_operator(&mut transaction, &request).await,
        "audit timestamp outside the years 0000 to 9999",
    );
    assert_eq!(snapshot(&mut transaction).await, before);

    let restored = restore_operator(&mut transaction, &restore_request("op_1"))
        .await
        .unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(
        get_recovery_state(&pool)
            .await
            .unwrap()
            .map(|state| state.recovery_public_key),
        Some(NEW_KEY.to_vec())
    );
    db.drop([pool]).await;
}

/// A restore consumes the challenge with the consume statement against the
/// recovery state it locked: every miss is `NotRestorable`, also for a
/// recovery state whose `bootstrap_closed` is false (written by other
/// means), and nothing is left written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_needs_a_consumable_challenge_for_the_current_state() {
    let (db, pool) = issued().await;
    issue(&pool, "op_revoker", "aud_issue_2").await;
    issue(&pool, "op_revoked", "aud_issue_3").await;
    issue(&pool, "op_failed", "aud_issue_4").await;
    issue(&pool, "op_consumed", "aud_issue_5").await;
    raw_revoke(
        &mut pool.acquire().await.unwrap(),
        "op_revoked",
        "op_revoker",
    )
    .await;
    sqlx::query(
        "UPDATE administrative_operation SET outcome = 'failed', revision = revision + 1 \
         WHERE id = 'op_failed'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(RAW_CONSUME)
        .bind("op_consumed")
        .bind(micros(now()))
        .execute(&pool)
        .await
        .unwrap();
    for (id, kind, plan, hash) in [
        (
            "raw_kind",
            "route_bundle_approval",
            json!(good_plan()),
            true,
        ),
        (
            "raw_no_hash",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            false,
        ),
        (
            "raw_epoch_string",
            OPERATOR_RESTORATION,
            json!(plan(INSTANCE, json!("1"))),
            true,
        ),
        (
            "raw_epoch_two",
            OPERATOR_RESTORATION,
            json!(plan(INSTANCE, json!(2))),
            true,
        ),
        (
            "raw_other_instance",
            OPERATOR_RESTORATION,
            json!(plan(OTHER_INSTANCE, json!(1))),
            true,
        ),
    ] {
        insert_raw(&pool, id, kind, plan, hash, 1).await;
    }
    let committed = pool_snapshot(&pool).await;

    let bound = binding();
    // The recovery state left open, by other means; the guards that would
    // refuse that write are off only inside the test's transaction.
    let reopen = "ALTER TABLE recovery_state DISABLE TRIGGER USER; \
                  UPDATE recovery_state SET bootstrap_closed = false; \
                  ALTER TABLE recovery_state ENABLE TRIGGER USER";
    let cases: [(&str, ChallengeBinding<'_>, SystemTime, Option<&str>); 16] = [
        ("op_unknown", bound, now(), None),
        ("op_revoked", bound, now(), None),
        ("op_failed", bound, now(), None),
        ("op_consumed", bound, now(), None),
        ("op_1", bound, expires(), None),
        (
            "op_1",
            ChallengeBinding {
                request_digest: &OTHER_DIGEST,
                ..bound
            },
            now(),
            None,
        ),
        (
            "op_1",
            ChallengeBinding {
                expected_revision: 2,
                ..bound
            },
            now(),
            None,
        ),
        (
            "op_1",
            ChallengeBinding {
                instance_id: OTHER_INSTANCE,
                ..bound
            },
            now(),
            None,
        ),
        (
            "op_1",
            bound,
            now(),
            Some("UPDATE recovery_state SET revision = revision + 1"),
        ),
        ("op_1", bound, now(), Some(reopen)),
        ("raw_kind", bound, now(), None),
        ("raw_no_hash", bound, now(), None),
        ("raw_epoch_string", bound, now(), None),
        (
            "raw_epoch_two",
            ChallengeBinding {
                recovery_key_epoch: 2,
                ..bound
            },
            now(),
            None,
        ),
        (
            "raw_other_instance",
            ChallengeBinding {
                instance_id: OTHER_INSTANCE,
                ..bound
            },
            now(),
            None,
        ),
        ("raw_other_instance", bound, now(), None),
    ];
    for (id, binding, at, statement) in cases {
        let mut connection = pool.acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        if let Some(statement) = statement {
            sqlx::raw_sql(AssertSqlSafe(statement))
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        let before = snapshot(&mut transaction).await;
        let mut request = restore_request(id);
        request.binding = binding;
        request.now = at;
        let refused = restore_operator(&mut transaction, &request).await;
        assert!(
            matches!(refused, Err(RestoreError::NotRestorable)),
            "{id} {statement:?}: {refused:?}"
        );
        assert_eq!(snapshot(&mut transaction).await, before, "{id}");
        transaction.rollback().await.unwrap();
    }
    assert_eq!(pool_snapshot(&pool).await, committed);

    // The control, with every value right; then a second restore of the
    // restored operation.
    restore_on(&pool, &restore_request("op_1")).await.unwrap();
    let restored = pool_snapshot(&pool).await;
    let mut request = restore_request("op_1");
    request.audit_event_id = "aud_again";
    request.rotation_audit_event_id = "aud_again_rotate";
    request.binding.recovery_key_epoch = 2;
    request.binding.expected_revision = 2;
    assert_not_restorable(restore_on(&pool, &request).await);
    assert_eq!(pool_snapshot(&pool).await, restored);
    db.drop([pool]).await;
}

/// Each replacement member the plan names must be the request's: a request
/// that differs in that one member is `NotRestorable`, and the restore and
/// its consume roll back, also when the caller commits; the request the
/// plan names then restores.
async fn a_restore_must_name_the_planned(change: Change) {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    let mut request = restore_request("op_1");
    change(&mut request);
    assert_ne!(request, restore_request("op_1"));
    let mut transaction = pool.begin().await.unwrap();
    assert_not_restorable(restore_operator(&mut transaction, &request).await);
    transaction.commit().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!((row.consumed_us, row.revision), (None, 1));
    let restored = restore_on(&pool, &restore_request("op_1")).await.unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_must_name_the_planned_admin_id() {
    a_restore_must_name_the_planned(|request| request.admin_id = "adm_other").await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_must_name_the_planned_credential_id() {
    a_restore_must_name_the_planned(|request| request.credential_id = "crd_other").await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_must_name_the_planned_binding_id() {
    a_restore_must_name_the_planned(|request| request.binding_id = "rb_other").await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_must_name_the_planned_public_identity() {
    a_restore_must_name_the_planned(|request| request.public_identity = "spki-sha256:other").await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_must_name_the_planned_trust_anchor_ref() {
    a_restore_must_name_the_planned(|request| request.trust_anchor_ref = "deployment/other-ca")
        .await;
}

/// Another replacement key with the binding unchanged.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_must_name_the_planned_recovery_key() {
    a_restore_must_name_the_planned(|request| request.new_recovery_public_key = &THIRD_KEY).await;
}

/// A restore and an issue wait for each other on the recovery state, in
/// either order, without a deadlock: an issue after a restore sees the new
/// epoch, and a restore after an issue retires the issued challenge's
/// epoch. Of two concurrent restores (of two challenges) the second is
/// `NotRestorable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_and_an_issue_wait_for_each_other() {
    // The restore first.
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    let waiting = tokio::spawn(async move {
        let plan = good_plan();
        let mut other = second.begin().await.unwrap();
        let issued =
            issue_recovery_challenge(&mut other, &issue_request("op_2", "aud_issue_2", &plan))
                .await;
        other.rollback().await.unwrap();
        second.close().await.unwrap();
        issued
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_not_issuable(waiting.await.unwrap());
    let plan = plan(INSTANCE, json!(2));
    issue_on(&pool, &issue_request("op_2", "aud_issue_2", &plan))
        .await
        .unwrap();
    db.drop([pool]).await;

    // The issue first.
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let plan = good_plan();
    let mut transaction = first.begin().await.unwrap();
    issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_2", "aud_issue_2", &plan),
    )
    .await
    .unwrap();
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        other.commit().await.unwrap();
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = waiting.await.unwrap().unwrap();
    assert_eq!(
        (
            restored.recovery_key_epoch,
            restored.audit_event.sequence,
            restored.rotation_audit_event.sequence
        ),
        (2, 4, 5)
    );
    assert_not_restorable(restore_on(&pool, &other_request("op_2", &THIRD_KEY)).await);
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );
    db.drop([pool]).await;

    // Two restores.
    let (db, pool) = issued().await;
    let plan = plan_for(INSTANCE, json!(1), &other_request("op_2", &THIRD_KEY));
    issue_on(&pool, &issue_request("op_2", "aud_issue_2", &plan))
        .await
        .unwrap();
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = restore_operator(&mut other, &other_request("op_2", &THIRD_KEY)).await;
        other.rollback().await.unwrap();
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_not_restorable(waiting.await.unwrap());
    assert_eq!(
        get_recovery_state(&pool)
            .await
            .unwrap()
            .map(|state| (state.recovery_public_key, state.recovery_key_epoch)),
        Some((NEW_KEY.to_vec(), 2))
    );
    assert_eq!(pool_operation(&pool, "op_2").await.consumed_us, None);
    db.drop([pool]).await;
}

/// A restoration takes the audit chain head after the recovery state: an
/// issue that has read the recovery state (step 1) while a restoration
/// waits for that row still appends its event and commits, with no
/// deadlock, and the restoration then goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_waiting_for_the_recovery_state_holds_no_audit_head() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    // An issue's step 1, as it holds the row.
    sqlx::query("SELECT instance_id FROM recovery_state FOR SHARE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let plan = good_plan();
    let challenge = issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_2", "aud_issue_2", &plan),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_eq!(challenge.audit_event.sequence, 3);
    let restored = waiting.await.unwrap().unwrap();
    assert_eq!(
        (
            restored.audit_event.sequence,
            restored.rotation_audit_event.sequence
        ),
        (4, 5)
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );
    db.drop([pool]).await;
}

/// A restoration appends its events after its writes, holding no audit
/// head while it waits for one of them (here for a replacement ID another
/// transaction is inserting): that transaction can still append an event
/// and commit, with no deadlock, and the restoration then finds the ID
/// taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_appends_its_events_after_its_writes() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO admin_identity (id, status, created_at) \
         VALUES ('adm_new', 'enabled', timestamptz 'epoch')",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        other.rollback().await.unwrap();
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let event = registry::append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: "aud_other_write".into(),
            tenant_id: None,
            timestamp: now(),
            actor: AuditActor::Operator("adm_first".into()),
            action: "admin_identity.create".into(),
            object_id: "adm_new".into(),
            previous_revision: None,
            new_revision: None,
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(event.sequence, 3);
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_restore_exists(restoring.await.unwrap(), "admin_identity_pkey");
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!((row.consumed_us, row.revision), (None, 1));
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:first")
            .await
            .map(|a| a.credential_id),
        Some("crd_first".into())
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 3 }
    );
    db.drop([pool]).await;
}

/// A plan's `instance_id` must be a JSON string, also where its text would
/// match: with a recovery state for the instance `12345` (written by other
/// means), a plan naming the number `12345` is not restorable, and one
/// naming the string is.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_plan_instance_is_a_json_string() {
    let (db, pool) = migrated().await;
    sqlx::raw_sql(
        "INSERT INTO instance_security_policy (instance_id) VALUES ('12345'); \
         INSERT INTO recovery_state (instance_id, bootstrap_closed, recovery_public_key, \
         recovery_key_epoch) VALUES ('12345', true, \
         '\\x1111111111111111111111111111111111111111111111111111111111111111', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let bound = ChallengeBinding {
        instance_id: "12345",
        ..binding()
    };
    let string = plan_for("12345", json!(1), &restore_request(""));
    issue_on(&pool, &issue_request("op_1", "aud_issue_1", &string))
        .await
        .unwrap();
    let mut number = string.clone();
    number.insert("instance_id".into(), json!(12345));
    insert_raw(
        &pool,
        "raw_number",
        OPERATOR_RESTORATION,
        json!(number),
        true,
        1,
    )
    .await;

    let before = pool_snapshot(&pool).await;
    let mut request = restore_request("raw_number");
    request.binding = bound;
    assert_not_restorable(restore_on(&pool, &request).await);
    assert_eq!(pool_snapshot(&pool).await, before);

    let mut request = restore_request("op_1");
    request.binding = bound;
    restore_on(&pool, &request).await.unwrap();
    db.drop([pool]).await;
}

/// Before bootstrap there is no recovery state, so nothing is restorable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn nothing_is_restorable_before_bootstrap() {
    let (db, pool) = migrated().await;
    let before = pool_snapshot(&pool).await;
    let mut transaction = pool.begin().await.unwrap();
    assert_not_restorable(restore_operator(&mut transaction, &restore_request("op_1")).await);
    transaction.rollback().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A restoration locks the credentials before the recovery state (the
/// `0005` table order): while an operator write holds its credential
/// `FOR SHARE` (`authorize_operator_locked`), the restoration waits for it
/// holding nothing the write needs, so the write can still issue a
/// challenge and commit, with no deadlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_locks_the_credentials_before_the_recovery_state() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    let authorized =
        registry::authorize_operator_locked(&mut transaction, &security_admin("spki-sha256:first"))
            .await
            .unwrap();
    assert_eq!(
        authorized.map(|a| a.credential_id),
        Some("crd_first".into())
    );
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let plan = good_plan();
    issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_2", "aud_issue_2", &plan),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = waiting.await.unwrap().unwrap();
    assert_eq!(restored.revoked_credential_ids, ["crd_first"]);
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );
    db.drop([pool]).await;
}

/// A restoration holds the recovery state from its check to the rotation:
/// an issue that starts while the restoration waits (here on a replacement
/// ID another transaction is inserting) waits for it, and after the
/// restoration commits it sees the new epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_holds_the_recovery_state_until_it_commits() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let mut third = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid, third_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
        backend_pid(&mut third).await,
    );
    let mut transaction = first.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO admin_identity (id, status, created_at) \
         VALUES ('adm_new', 'enabled', timestamptz 'epoch')",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let issuing = tokio::spawn(async move {
        let plan = good_plan();
        let mut other = third.begin().await.unwrap();
        let issued =
            issue_recovery_challenge(&mut other, &issue_request("op_2", "aud_issue_2", &plan))
                .await;
        if issued.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        third.close().await.unwrap();
        issued
    });
    wait_until_blocked(&pool, third_pid, second_pid).await;
    transaction.rollback().await.unwrap();
    first.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    assert_not_issuable(issuing.await.unwrap());
    db.drop([pool]).await;
}

/// The tenant `ten_a` and a disabled instance `auditor` binding `rb_off`
/// of `adm_first`, for the operator writes below.
async fn write_targets(pool: &PgPool) {
    registry::create_tenant(
        pool,
        &NewTenant {
            id: "ten_a".into(),
            name: "Tenant A".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: "rb_off".into(),
            admin_id: "adm_first".into(),
            role: AdminRole::Auditor,
            tenant_id: None,
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
}

/// The four operator writes that can add access, by index: an enabled
/// identity `adm_late`, an enabled credential `crd_late`
/// (`spki-sha256:late`) of `admin`, an enabled tenant `client_admin`
/// binding `rb_late` of `admin`, and `rb_off` re-enabled.
async fn operator_write(
    transaction: &mut Transaction<'_, Postgres>,
    write: usize,
    admin: &str,
) -> Result<(), RegistryError> {
    match write {
        0 => registry::create_admin_identity(
            &mut **transaction,
            &NewAdminIdentity {
                id: "adm_late".into(),
                status: Status::Enabled,
                created_at: now(),
            },
        )
        .await
        .map(drop),
        1 => registry::create_admin_credential(
            &mut **transaction,
            &NewAdminCredential {
                id: "crd_late".into(),
                admin_id: admin.into(),
                public_identity: "spki-sha256:late".into(),
                trust_anchor_ref: "deployment/operator-ca".into(),
                status: Status::Enabled,
            },
        )
        .await
        .map(drop),
        2 => registry::create_admin_role_binding(
            &mut **transaction,
            &NewAdminRoleBinding {
                id: "rb_late".into(),
                admin_id: admin.into(),
                role: AdminRole::ClientAdmin,
                tenant_id: Some("ten_a".into()),
                status: Status::Enabled,
            },
        )
        .await
        .map(drop),
        _ => registry::update_admin_role_binding(
            &mut **transaction,
            "rb_off",
            1,
            &AdminRoleBindingChanges {
                status: Status::Enabled,
            },
        )
        .await
        .map(drop),
    }
}

/// An enrollment that holds the recovery state (its credential insert)
/// when a restoration starts makes the restoration wait for its commit;
/// the restoration then revokes the enrolled credential with the others,
/// so it does not stay active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_enrollment_that_commits_while_a_restore_waits_is_revoked() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    operator_write(&mut transaction, 1, "adm_first")
        .await
        .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    // The restoration began (its snapshot is older than the enrollment's
    // commit) and waits for the enrollment.
    assert!(waits_for(&pool, second_pid, first_pid, &restoring).await);
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.revoked_credential_ids, ["crd_first", "crd_late"]);
    let late = registry::get_admin_credential(&pool, "crd_late")
        .await
        .unwrap();
    assert_eq!(
        (late.status, late.revoked_at),
        (Status::Disabled, Some(now()))
    );
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:late").await,
        None
    );
    db.drop([pool]).await;
}

/// Each of the four writes that can add operator access waits for a
/// restoration that holds the recovery state, and the writer's lookup
/// after the write, in its transaction, sees the revocation and denies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_operator_write_waits_for_a_restore_and_then_sees_the_revocation() {
    let (db, pool) = issued().await;
    write_targets(&pool).await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    // The restoration holds the recovery state and waits for a replacement
    // ID another transaction is inserting.
    let mut transaction = first.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO admin_identity (id, status, created_at) \
         VALUES ('adm_new', 'enabled', timestamptz 'epoch')",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let mut writers = Vec::new();
    for write in 0..4 {
        let mut connection = pool.acquire().await.unwrap().detach();
        let pid = backend_pid(&mut connection).await;
        let writer = tokio::spawn(async move {
            let mut writing = connection.begin().await.unwrap();
            let written = operator_write(&mut writing, write, "adm_first").await;
            let authorized =
                registry::authorize_operator(&mut *writing, &security_admin("spki-sha256:first"))
                    .await
                    .unwrap();
            writing.rollback().await.unwrap();
            connection.close().await.unwrap();
            (written, authorized)
        });
        assert!(
            waits_for(&pool, pid, second_pid, &writer).await,
            "write {write} did not wait for the restoration"
        );
        writers.push(writer);
    }
    transaction.rollback().await.unwrap();
    first.close().await.unwrap();
    restoring.await.unwrap().unwrap();
    for (write, writer) in writers.into_iter().enumerate() {
        let (written, authorized) = writer.await.unwrap();
        assert!(written.is_ok(), "{write}: {written:?}");
        assert_eq!(authorized, None, "{write}");
    }
    db.drop([pool]).await;
}

/// The caller's order (a locked authorization, then the writes) and the
/// restoration's (credentials, then the recovery state) do not deadlock:
/// the restoration waits at its credential lock holding no recovery state,
/// the four writes go through and commit, and the restoration then revokes
/// the enrolled credential too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_authorized_enrollment_does_not_deadlock_with_a_restore() {
    let (db, pool) = issued().await;
    write_targets(&pool).await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    assert!(
        registry::authorize_operator_locked(&mut transaction, &security_admin("spki-sha256:first"))
            .await
            .unwrap()
            .is_some()
    );
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    for write in 0..4 {
        operator_write(&mut transaction, write, "adm_late")
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.revoked_credential_ids, ["crd_first", "crd_late"]);
    assert_eq!(
        registry::get_admin_credential(&pool, "crd_late")
            .await
            .unwrap()
            .revoked_at,
        Some(now())
    );
    assert_eq!(
        registry::get_admin_role_binding(&pool, "rb_off")
            .await
            .unwrap()
            .status,
        Status::Enabled
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 4 }
    );
    db.drop([pool]).await;
}

/// The SQLSTATE of a store error.
fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|err| err.code())
        .map(|code| code.into_owned())
        .unwrap_or_default()
}

/// A restore at any isolation level but `READ COMMITTED` is
/// `UnsupportedIsolation`, decided inside its savepoint before its first
/// lock: it does not wait for an enrollment that holds the recovery state,
/// writes nothing, leaves the challenge unconsumed and the transaction
/// usable. The same challenge then restores at `READ COMMITTED`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_runs_only_at_read_committed() {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    // An uncommitted enrollment holds the recovery state `FOR SHARE`.
    let mut enrolling = pool.begin().await.unwrap();
    operator_write(&mut enrolling, 1, "adm_first")
        .await
        .unwrap();
    for isolation in ["REPEATABLE READ", "SERIALIZABLE", "READ UNCOMMITTED"] {
        let mut connection = pool.acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        sqlx::raw_sql(AssertSqlSafe(format!(
            "SET TRANSACTION ISOLATION LEVEL {isolation}; SET LOCAL lock_timeout = '5s'"
        )))
        .execute(&mut *transaction)
        .await
        .unwrap();
        let inside = snapshot(&mut transaction).await;
        match restore_operator(&mut transaction, &restore_request("op_1")).await {
            Err(err @ RestoreError::UnsupportedIsolation) => {
                assert_eq!(format!("{err:?}"), "UnsupportedIsolation");
                assert_eq!(
                    err.to_string(),
                    "operator restoration runs only at READ COMMITTED"
                );
            }
            other => panic!("{isolation}: expected UnsupportedIsolation: {other:?}"),
        }
        assert_eq!(snapshot(&mut transaction).await, inside, "{isolation}");
        let row = operation(&mut transaction, "op_1").await;
        assert_eq!((row.consumed_us, row.revision), (None, 1), "{isolation}");
        transaction.commit().await.unwrap();
    }
    enrolling.rollback().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .unwrap();
    let restored = consume_and_restore(&mut transaction, "op_1").await.unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    transaction.commit().await.unwrap();
    drop(connection);
    db.drop([pool]).await;
}

/// The cycle that remains: a credential enrolled after the restore's
/// credential lock and before its recovery-state lock is not locked by it.
/// A writer that then authorizes on that credential (`FOR SHARE`) and
/// writes, in the documented order, waits for the restore's recovery
/// state, while the restore's revocation waits for that credential.
/// PostgreSQL fails one side with `40P01`, a `Retry`, and the outcome is
/// closed either way: a restore that is the victim leaves nothing and its
/// challenge unconsumed, and its retry revokes the credential; a writer
/// that is the victim writes nothing and the restore revokes the
/// credential. PostgreSQL's deadlock check runs first in the side that
/// started waiting first, which is then the usual victim:
/// `restore_waits_first` picks that side.
async fn documented_order_deadlock(restore_waits_first: bool) {
    let (db, pool) = issued().await;
    let mut enroller = pool.acquire().await.unwrap().detach();
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut gate = pool.acquire().await.unwrap().detach();
    let mut restorer = pool.acquire().await.unwrap().detach();
    let mut writer = pool.acquire().await.unwrap().detach();
    let (enroller_pid, holder_pid, gate_pid, restorer_pid, writer_pid) = (
        backend_pid(&mut enroller).await,
        backend_pid(&mut holder).await,
        backend_pid(&mut gate).await,
        backend_pid(&mut restorer).await,
        backend_pid(&mut writer).await,
    );
    // The enrollment of `crd_late` holds the recovery state.
    let mut enrolling = enroller.begin().await.unwrap();
    operator_write(&mut enrolling, 1, "adm_first")
        .await
        .unwrap();
    // The operation row is held, so the restore stops at its consume.
    let mut holding = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM administrative_operation WHERE id = 'op_1' FOR UPDATE")
        .execute(&mut *holding)
        .await
        .unwrap();
    // The gate holds the writer between its lookup and its write.
    let mut gating = gate.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(81)")
        .execute(&mut *gating)
        .await
        .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = restorer.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        restorer.close().await.unwrap();
        restored
    });
    // Step 1 locked `crd_first` only; step 2 waits for the enrollment,
    // which commits between the two.
    wait_until_blocked(&pool, restorer_pid, enroller_pid).await;
    enrolling.commit().await.unwrap();
    enroller.close().await.unwrap();
    // The restore holds the recovery state and waits at its consume.
    wait_until_blocked(&pool, restorer_pid, holder_pid).await;
    let writing = tokio::spawn(async move {
        let mut transaction = writer.begin().await.unwrap();
        let authorized = registry::authorize_operator_locked(
            &mut transaction,
            &security_admin("spki-sha256:late"),
        )
        .await
        .unwrap();
        assert!(authorized.is_some());
        if restore_waits_first {
            sqlx::query("SELECT pg_advisory_xact_lock(81)")
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        let written = operator_write(&mut transaction, 0, "adm_first").await;
        if written.is_ok() {
            transaction.commit().await.unwrap();
        } else {
            transaction.rollback().await.unwrap();
        }
        writer.close().await.unwrap();
        written
    });
    if restore_waits_first {
        // The writer holds `crd_late` and waits at the gate; the restore
        // goes on to its revocation and waits for the writer; then the
        // writer writes and waits for the restore.
        wait_until_blocked(&pool, writer_pid, gate_pid).await;
        holding.rollback().await.unwrap();
        wait_until_blocked(&pool, restorer_pid, writer_pid).await;
        gating.rollback().await.unwrap();
    } else {
        // The writer waits for the restore; then the restore goes on to its
        // revocation and waits for the writer.
        assert!(waits_for(&pool, writer_pid, restorer_pid, &writing).await);
        holding.rollback().await.unwrap();
        gating.rollback().await.unwrap();
    }
    holder.close().await.unwrap();
    gate.close().await.unwrap();
    let restored = restoring.await.unwrap();
    let written = writing.await.unwrap();
    let late = registry::get_admin_credential(&pool, "crd_late")
        .await
        .unwrap();
    let late_identity: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_identity WHERE id = 'adm_late'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let state = get_recovery_state(&pool).await.unwrap().unwrap();
    let row = pool_operation(&pool, "op_1").await;
    match (restored, written) {
        // The restore was the victim: nothing of it persists.
        (Err(RestoreError::Store(RegistryError::Retry(err))), Ok(())) => {
            assert_eq!(sqlstate(&err), "40P01");
            assert_eq!((row.consumed_us, row.revision), (None, 1));
            assert_eq!(row.outcome, "issued");
            assert_eq!((state.recovery_key_epoch, state.revision), (1, 1));
            assert_eq!(state.recovery_public_key, KEY);
            assert_eq!(late.revoked_at, None);
            assert_eq!(late_identity, 1);
            assert_eq!(
                verify(&pool).await,
                ChainVerdict::Intact { last_sequence: 2 }
            );
            // The retry restores and revokes the enrolled credential.
            let retried = restore_on(&pool, &restore_request("op_1")).await.unwrap();
            assert_eq!(retried.revoked_credential_ids, ["crd_first", "crd_late"]);
        }
        // The writer was the victim: it wrote nothing, and the restore
        // revoked the enrolled credential.
        (Ok(restored), Err(RegistryError::Retry(err))) => {
            assert_eq!(sqlstate(&err), "40P01");
            assert_eq!(restored.revoked_credential_ids, ["crd_first", "crd_late"]);
            assert_eq!(late.revoked_at, Some(now()));
            assert_eq!(late_identity, 0);
            assert_eq!(row.outcome, "restored");
            assert_eq!(state.recovery_key_epoch, 2);
        }
        other => panic!("expected one 40P01 victim: {other:?}"),
    }
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:late").await,
        None
    );
    db.drop([pool]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_waiting_first_on_a_credential_enrolled_during_it_deadlocks_closed() {
    documented_order_deadlock(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_writer_waiting_first_on_a_credential_enrolled_during_a_restore_deadlocks_closed() {
    documented_order_deadlock(false).await;
}

/// A create that collides with the restore's replacement (its operator,
/// credential or binding ID, or its credential's public identity) waits for
/// the restore's recovery-state lock before it inserts, so it holds no key
/// the restore is about to insert: the restore commits, and the create is
/// then `AlreadyExists` with the replacement's constraint, with no
/// deadlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_create_colliding_with_the_replacement_waits_for_the_restore_first() {
    let (db, pool) = issued().await;
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut restorer = pool.acquire().await.unwrap().detach();
    let (holder_pid, restorer_pid) = (
        backend_pid(&mut holder).await,
        backend_pid(&mut restorer).await,
    );
    let mut holding = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM administrative_operation WHERE id = 'op_1' FOR UPDATE")
        .execute(&mut *holding)
        .await
        .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = restorer.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        restorer.close().await.unwrap();
        restored
    });
    // The restore holds the recovery state and has inserted nothing yet.
    wait_until_blocked(&pool, restorer_pid, holder_pid).await;
    let mut creates = Vec::new();
    for create in 0..4 {
        let mut connection = pool.acquire().await.unwrap().detach();
        let pid = backend_pid(&mut connection).await;
        let task = tokio::spawn(async move {
            let mut transaction = connection.begin().await.unwrap();
            let created = match create {
                0 => registry::create_admin_identity(
                    &mut *transaction,
                    &NewAdminIdentity {
                        id: "adm_new".into(),
                        status: Status::Enabled,
                        created_at: now(),
                    },
                )
                .await
                .map(drop),
                1 | 2 => registry::create_admin_credential(
                    &mut *transaction,
                    &NewAdminCredential {
                        id: if create == 1 {
                            "crd_new"
                        } else {
                            "crd_collide"
                        }
                        .into(),
                        admin_id: "adm_first".into(),
                        public_identity: if create == 1 {
                            "spki-sha256:collide"
                        } else {
                            "spki-sha256:new"
                        }
                        .into(),
                        trust_anchor_ref: "deployment/operator-ca".into(),
                        status: Status::Enabled,
                    },
                )
                .await
                .map(drop),
                _ => registry::create_admin_role_binding(
                    &mut *transaction,
                    &NewAdminRoleBinding {
                        id: "rb_new".into(),
                        admin_id: "adm_first".into(),
                        role: AdminRole::Auditor,
                        tenant_id: None,
                        status: Status::Enabled,
                    },
                )
                .await
                .map(drop),
            };
            transaction.rollback().await.unwrap();
            connection.close().await.unwrap();
            created
        });
        assert!(
            waits_for(&pool, pid, restorer_pid, &task).await,
            "create {create} did not wait for the restore"
        );
        creates.push(task);
    }
    holding.rollback().await.unwrap();
    holder.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.admin_id, "adm_new");
    for (task, constraint) in creates.into_iter().zip([
        "admin_identity_pkey",
        "admin_credential_pkey",
        "admin_credential_public_identity_key",
        "admin_role_binding_pkey",
    ]) {
        match task.await.unwrap() {
            Err(RegistryError::AlreadyExists { constraint: name }) => {
                assert_eq!(name, constraint)
            }
            other => panic!("expected AlreadyExists {constraint}: {other:?}"),
        }
    }
    db.drop([pool]).await;
}
