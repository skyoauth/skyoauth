//! The second-approver flow of `crate::operation`
//! (`docs/proposals/second-approver-gated-writes.md` sections 2 and 3) on a
//! real database: the pending toggle and its digest, the approval with its
//! one clock sample, its refusals and their order, cancel and reject, the
//! toggle under `single_actor_mode`, the policy row's lock, and races
//! between two connections.
//!
//! Every helper here commits the outer transaction even when the call
//! returned an error, so each refusal also shows that the call's savepoint
//! left nothing behind.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database. They are
//! registry tests, not conformance scenarios.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    fmt::Debug,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use skyoauth_service::{
    jwk::{Algorithm, DEFAULT_ALLOWED_ALGORITHMS},
    operation::{
        Applied, ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, DigestEnvelope,
        Gated, OperationKind, PendingOperation, PreparedApproval, RequestDigest, RevokeIds,
        Submission, approve_operation, cancel_operation, prepare_approval, reject_operation,
        submit_widening_toggle,
    },
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AdminRoleBindingChanges, AdministrativeOperation, AuditActor,
            BootstrapRequest, ChainVerdict, DEFAULT_CHALLENGE_TTL, InstanceSecurityPolicy,
            IssueChallenge, JsonObject, NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding,
            NewAdministrativeOperation, NewAuditEvent, NewTenant, OPERATOR_RESTORATION,
            RestoreRequest, Restored, SignedRecoveryResponse, Status, bootstrap_instance,
            get_recovery_state, issue_recovery_challenge, lock_administrative_operation,
            lock_instance_security_policy_shared, restore_operator,
            test_support::{append_audit_event, insert_administrative_operation},
            verify_audit_chain,
        },
    },
};
use sqlx::{AssertSqlSafe, Connection, PgConnection, Postgres, Transaction, types::Json};
use tokio::task::JoinHandle;

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;
/// [`skyoauth_service::operation::PENDING_OPERATION_TTL`] in microseconds.
const DAY: u64 = 86_400_000_000;
const KIND: &str = "instance_security_policy_update";
const INSTANCE: ApprovalScope<'static> = ApprovalScope::Instance;
const TEN_A: ApprovalScope<'static> = ApprovalScope::Tenant("ten_a");
const TEN_B: ApprovalScope<'static> = ApprovalScope::Tenant("ten_b");
const SEC: AdminRole = AdminRole::SecurityAdmin;
const TRUST: AdminRole = AdminRole::TrustAdmin;
/// The current `allowed` algorithms of every `prepare_approval` here: a
/// toggle parses no keys.
const ALLOWED: &[Algorithm] = DEFAULT_ALLOWED_ALGORITHMS;

/// `micros` after `T0`, with sub-microsecond digits, so a write truncates
/// it.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros) + Duration::from_nanos(789)
}

/// [`at`] as stored: truncated to the microsecond.
fn stored(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

/// The expiry of a request made at `at(0)`.
fn expiry() -> SystemTime {
    stored(DAY)
}

/// A clock the test sets, which counts its samples.
struct TestClock {
    now: Mutex<SystemTime>,
    samples: AtomicUsize,
}

impl TestClock {
    fn new(now: SystemTime) -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(now),
            samples: AtomicUsize::new(0),
        })
    }

    fn set(&self, now: SystemTime) {
        *self.now.lock().unwrap() = now;
    }

    fn samples(&self) -> usize {
        self.samples.load(Ordering::SeqCst)
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        self.samples.fetch_add(1, Ordering::SeqCst);
        *self.now.lock().unwrap()
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// One operator `admin` with a credential `crd_<admin>` (`key`) and the
/// enabled bindings `(id, role, tenant)`.
async fn operator(
    pool: &PgPool,
    admin: &str,
    key: &str,
    bindings: &[(&str, AdminRole, Option<&str>)],
) {
    registry::test_support::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: admin.into(),
            status: Status::Enabled,
            created_at: at(0),
        },
    )
    .await
    .unwrap();
    credential(pool, &format!("crd_{admin}"), admin, key).await;
    for &(id, role, tenant_id) in bindings {
        registry::test_support::create_admin_role_binding(
            pool,
            &NewAdminRoleBinding {
                id: id.into(),
                admin_id: admin.into(),
                role,
                tenant_id: tenant_id.map(Into::into),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
}

async fn credential(pool: &PgPool, id: &str, admin: &str, key: &str) {
    registry::test_support::create_admin_credential(
        pool,
        &NewAdminCredential {
            id: id.into(),
            admin_id: admin.into(),
            public_identity: key.into(),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// A bootstrapped instance (`adm_first`, the policy row at revision 1 with
/// both flags off, the bootstrap event), the tenants `ten_a` and `ten_b`,
/// and these operators, all enabled, each with a credential `crd_<admin>`:
///
/// - `adm_req` (`key_req`), instance `security_admin` (`rb_req`): the
///   requester, with a second credential `crd_adm_req_b` (`key_req_b`).
/// - `adm_sec1` (`key_sec1`) and `adm_sec2` (`key_sec2`), instance
///   `security_admin`: the approvers.
/// - `adm_trust` (`key_trust`), `trust_admin` of `ten_a` only.
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: INSTANCE_ID,
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: "spki-sha256:first",
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &recovery_key(&RECOVERY_SEED),
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    for (id, ns) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::test_support::create_tenant(
            &pool,
            &NewTenant {
                id: id.into(),
                name: format!("Tenant {id}"),
                secret_namespace: ns.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    operator(&pool, "adm_req", "key_req", &[("rb_req", SEC, None)]).await;
    credential(&pool, "crd_adm_req_b", "adm_req", "key_req_b").await;
    operator(&pool, "adm_sec1", "key_sec1", &[("rb_sec1", SEC, None)]).await;
    operator(&pool, "adm_sec2", "key_sec2", &[("rb_sec2", SEC, None)]).await;
    operator(
        &pool,
        "adm_trust",
        "key_trust",
        &[("rb_trust", TRUST, Some("ten_a"))],
    )
    .await;
    (db, pool)
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn toggle_plan(credential_id: &str, value: bool) -> JsonObject {
    object(json!({
        "requester_credential_id": credential_id,
        "widening_second_approver": value,
    }))
}

#[track_caller]
fn refused<T: Debug>(result: Result<T, ApprovalError>, expected: &str) {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => assert_eq!(format!("{err:?}"), expected),
    }
}

/// Requests the toggle to `value` at the policy's `revision` with `key`, as
/// the operation `op` recorded by `evt_<op>`, with `acknowledge_widening`
/// set to `acknowledge`, at `now`, in `transaction`.
async fn submit_in(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    op: &str,
    revision: i64,
    value: bool,
    acknowledge: bool,
    now: SystemTime,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError> {
    let event_id = format!("evt_{op}");
    submit_widening_toggle(
        transaction,
        &Submission {
            public_identity: key,
            acknowledge_widening: acknowledge,
            operation_id: op,
            event_id: &event_id,
            now,
        },
        revision,
        value,
    )
    .await
}

/// [`submit_in`] at `at(0)` in a transaction committed either way.
async fn submit(
    pool: &PgPool,
    key: &str,
    op: &str,
    revision: i64,
    value: bool,
    acknowledge: bool,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = submit_in(
        &mut transaction,
        key,
        op,
        revision,
        value,
        acknowledge,
        at(0),
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

/// [`submit_in`] acknowledging the widening exactly when it turns the
/// setting off: turning it off needs `acknowledge_widening`, turning it on
/// does not (the user's ruling, 2026-11-24), so every request on here is
/// also one without the acknowledgement.
async fn request_in(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    op: &str,
    revision: i64,
    value: bool,
    now: SystemTime,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError> {
    submit_in(transaction, key, op, revision, value, !value, now).await
}

/// [`request_in`] at `at(0)` in a transaction committed either way.
async fn request(
    pool: &PgPool,
    key: &str,
    op: &str,
    revision: i64,
    value: bool,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError> {
    submit(pool, key, op, revision, value, !value).await
}

/// A pending toggle to `value` by `key` at `revision`.
async fn pending(
    pool: &PgPool,
    key: &str,
    op: &str,
    revision: i64,
    value: bool,
) -> PendingOperation {
    match request(pool, key, op, revision, value).await.unwrap() {
        Gated::Pending(pending) => pending,
        other => panic!("not pending: {other:?}"),
    }
}

fn echo(pending: &PendingOperation) -> ApprovalEcho {
    ApprovalEcho {
        request_digest: pending.request_digest,
        expected_revision: pending.expected_revision,
    }
}

/// [`prepare_approval`] on the instance path at `at(1)`.
async fn prepare(pool: &PgPool, key: &str, op: &str) -> Result<PreparedApproval, ApprovalError> {
    prepare_approval(pool, key, INSTANCE, op, ALLOWED, at(1)).await
}

async fn approve_in(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    scope: ApprovalScope<'_>,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    clock: &dyn Clock,
) -> Result<Applied, ApprovalError> {
    let tag = format!("{}_{key}", prepared.operation_id());
    let approve_operation_id = format!("appr_{tag}");
    let approve_event_id = format!("evt_appr_{tag}");
    let write_event_id = format!("evt_write_{tag}");
    approve_operation(
        transaction,
        key,
        scope,
        prepared,
        echo,
        &ApprovalIds {
            approve_operation_id: &approve_operation_id,
            approve_event_id: &approve_event_id,
            write_event_id: &write_event_id,
        },
        clock,
    )
    .await
}

/// [`approve_in`] in a transaction committed either way.
async fn approve(
    pool: &PgPool,
    key: &str,
    scope: ApprovalScope<'_>,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    clock: &dyn Clock,
) -> Result<Applied, ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = approve_in(&mut transaction, key, scope, prepared, echo, clock).await;
    transaction.commit().await.unwrap();
    result
}

#[derive(Clone, Copy)]
enum Revocation {
    Cancel,
    Reject,
}

async fn revoke_in(
    transaction: &mut Transaction<'_, Postgres>,
    revocation: Revocation,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
    now: SystemTime,
) -> Result<(), ApprovalError> {
    let (name, call) = match revocation {
        Revocation::Cancel => ("cancel", true),
        Revocation::Reject => ("reject", false),
    };
    let revoking_operation_id = format!("{name}_{op}_{key}");
    let event_id = format!("evt_{name}_{op}_{key}");
    let ids = RevokeIds {
        revoking_operation_id: &revoking_operation_id,
        event_id: &event_id,
    };
    if call {
        cancel_operation(transaction, key, scope, op, &ids, now).await
    } else {
        reject_operation(transaction, key, scope, op, &ids, now).await
    }
}

/// A cancel or reject in a transaction committed either way.
async fn revoke(
    pool: &PgPool,
    revocation: Revocation,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
    now: SystemTime,
) -> Result<(), ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = revoke_in(&mut transaction, revocation, key, scope, op, now).await;
    transaction.commit().await.unwrap();
    result
}

async fn cancel(
    pool: &PgPool,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
) -> Result<(), ApprovalError> {
    revoke(pool, Revocation::Cancel, key, scope, op, at(7)).await
}

async fn reject(
    pool: &PgPool,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
) -> Result<(), ApprovalError> {
    revoke(pool, Revocation::Reject, key, scope, op, at(7)).await
}

/// The operation `id`, read under its lock in a transaction rolled back.
async fn operation(pool: &PgPool, id: &str) -> AdministrativeOperation {
    let mut transaction = pool.begin().await.unwrap();
    let row = lock_administrative_operation(&mut transaction, id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no operation {id}"));
    transaction.rollback().await.unwrap();
    row
}

async fn policy(pool: &PgPool) -> InstanceSecurityPolicy {
    registry::get_instance_security_policy(pool).await.unwrap()
}

/// An audit event as stored: ID, tenant, actor, action, object, revisions,
/// outcome and microseconds since the epoch.
type Event = (
    String,
    Option<String>,
    String,
    String,
    String,
    Option<i64>,
    Option<i64>,
    String,
    i64,
);

#[allow(clippy::too_many_arguments)]
fn event(
    id: &str,
    actor: &str,
    action: &str,
    object_id: &str,
    previous_revision: Option<i64>,
    new_revision: Option<i64>,
    outcome: &str,
    micros: u64,
) -> Event {
    (
        id.into(),
        None,
        AuditActor::Operator(actor.into()).canonical_json(),
        action.into(),
        object_id.into(),
        previous_revision,
        new_revision,
        outcome.into(),
        i64::try_from(T0 + micros).unwrap(),
    )
}

/// The events after the bootstrap event, in sequence order.
async fn events(pool: &PgPool) -> Vec<Event> {
    sqlx::query_as(
        "SELECT id, tenant_id, actor, action, object_id, previous_revision, new_revision, \
         outcome, (extract(epoch FROM timestamp) * 1000000)::bigint \
         FROM audit_event WHERE id <> 'aud_bootstrap' ORDER BY sequence",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// What a toggle request may write, counted: the operations, the audit
/// events, and the policy row's revision and value.
async fn written(pool: &PgPool) -> (i64, i64, i64, bool) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM administrative_operation), \
         (SELECT count(*) FROM audit_event), revision, widening_second_approver \
         FROM instance_security_policy",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn assert_chain_intact(pool: &PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    assert!(matches!(
        verify_audit_chain(&mut connection).await.unwrap(),
        ChainVerdict::Intact { .. }
    ));
}

/// Every row an operation call may write, as text.
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let mut rows = Vec::new();
    for table in [
        "instance_security_policy",
        "administrative_operation",
        "audit_event",
        "audit_chain_head",
        "admin_identity",
        "admin_credential",
        "admin_role_binding",
    ] {
        let texts: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT to_jsonb(t)::text FROM {table} AS t ORDER BY to_jsonb(t)::text"
        )))
        .fetch_all(pool)
        .await
        .unwrap();
        rows.extend(texts.into_iter().map(|text| format!("{table} {text}")));
    }
    rows
}

/// A toggle operation `id` by `adm_req` at revision 1, expiring at
/// [`expiry`], with `plan` and `digest` (the correct digest when `None`).
fn raw_toggle(id: &str, plan: JsonObject, digest: Option<Vec<u8>>) -> NewAdministrativeOperation {
    let digest = digest.unwrap_or_else(|| {
        DigestEnvelope {
            id,
            tenant_id: None,
            actor_id: "adm_req",
            kind: KIND,
            expected_revision: 1,
            expires_at_us: i64::try_from(T0 + DAY).unwrap(),
            plan: &plan,
        }
        .digest()
        .unwrap()
        .as_bytes()
        .to_vec()
    });
    NewAdministrativeOperation {
        id: id.into(),
        tenant_id: None,
        actor_id: "adm_req".into(),
        kind: KIND.into(),
        request_digest: digest,
        expected_revision: 1,
        immutable_plan: plan,
        expires_at: Some(expiry()),
        approves_operation_id: None,
        outcome: "pending".into(),
        audit_id: format!("evt_{id}"),
    }
}

/// Appends the operation's `administrative_operation.create` event and
/// inserts it, committed.
async fn insert_raw(pool: &PgPool, new: &NewAdministrativeOperation) {
    let mut transaction = pool.begin().await.unwrap();
    append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: new.audit_id.clone(),
            tenant_id: new.tenant_id.clone(),
            timestamp: at(0),
            actor: AuditActor::Operator(new.actor_id.clone()),
            action: "administrative_operation.create".into(),
            object_id: new.id.clone(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    insert_administrative_operation(&mut transaction, new)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn conflicts(pool: &PgPool, table: &str, id_column: &str, id: &str, strength: &str) -> bool {
    let mut other = pool.begin().await.unwrap();
    let result = sqlx::query(AssertSqlSafe(format!(
        "SELECT FROM {table} WHERE {id_column} = $1 {strength} NOWAIT"
    )))
    .bind(id)
    .execute(&mut *other)
    .await;
    other.rollback().await.unwrap();
    match result {
        Ok(done) => {
            assert_eq!(done.rows_affected(), 1, "{table} {id}");
            false
        }
        Err(err) => {
            let code = err.as_database_error().and_then(|e| e.code());
            assert_eq!(code.as_deref(), Some("55P03"), "{table} {id}: {err}");
            true
        }
    }
}

async fn policy_conflicts(pool: &PgPool, strength: &str) -> bool {
    conflicts(
        pool,
        "instance_security_policy",
        "instance_id",
        INSTANCE_ID,
        strength,
    )
    .await
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// Waits until the backend `blocked`, which runs `task`, waits for a lock
/// held by `holder`. Fails at once if `task` finished without waiting.
async fn wait_until_blocked<T>(pool: &PgPool, blocked: i32, holder: i32, task: &JoinHandle<T>) {
    wait_until_blocked_by_any(pool, blocked, &[holder], task).await;
}

/// [`wait_until_blocked`] by any of `holders`: a waiter queued behind
/// another waiter may be blocked by that waiter, not the holder.
async fn wait_until_blocked_by_any<T>(
    pool: &PgPool,
    blocked: i32,
    holders: &[i32],
    task: &JoinHandle<T>,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT pg_blocking_pids($2) && $1")
                .bind(holders)
                .bind(blocked)
                .fetch_one(pool)
                .await
                .unwrap();
            if waiting {
                return;
            }
            assert!(!task.is_finished(), "finished without waiting for the lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("never waited for the lock");
}

async fn finished<T>(task: JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the task never finished")
        .unwrap()
}

/// The operator rows are held `FOR SHARE` by another transaction: they
/// conflict with `FOR UPDATE`, not with `FOR SHARE`.
async fn assert_operator_rows_shared(
    pool: &PgPool,
    identities: &[&str],
    credentials: &[&str],
    bindings: &[&str],
) {
    for (table, ids) in [
        ("admin_identity", identities),
        ("admin_credential", credentials),
        ("admin_role_binding", bindings),
    ] {
        for id in ids {
            assert!(
                conflicts(pool, table, "id", id, "FOR UPDATE").await,
                "{table} {id}"
            );
            assert!(
                !conflicts(pool, table, "id", id, "FOR SHARE").await,
                "{table} {id}"
            );
        }
    }
}

/// A detached connection and its backend PID.
async fn connection(pool: &PgPool) -> (PgConnection, i32) {
    let mut connection = pool.acquire().await.unwrap().detach();
    let pid = backend_pid(&mut connection).await;
    (connection, pid)
}

/// An approval on its own connection, in a transaction committed either
/// way; returns the backend PID and the task.
async fn spawn_approve(
    pool: &PgPool,
    key: &'static str,
    prepared: PreparedApproval,
    echo: ApprovalEcho,
    clock: Arc<TestClock>,
) -> (i32, JoinHandle<Result<Applied, ApprovalError>>) {
    let (mut connection, pid) = connection(pool).await;
    let task = tokio::spawn(async move {
        let mut transaction = connection.begin().await.unwrap();
        let result = approve_in(&mut transaction, key, INSTANCE, &prepared, &echo, &*clock).await;
        transaction.commit().await.unwrap();
        connection.close().await.unwrap();
        result
    });
    (pid, task)
}

/// A cancel by `key_req` on its own connection, as [`spawn_approve`].
async fn spawn_cancel(
    pool: &PgPool,
    op: &'static str,
) -> (i32, JoinHandle<Result<(), ApprovalError>>) {
    let (mut connection, pid) = connection(pool).await;
    let task = tokio::spawn(async move {
        let mut transaction = connection.begin().await.unwrap();
        let result = revoke_in(
            &mut transaction,
            Revocation::Cancel,
            "key_req",
            INSTANCE,
            op,
            at(7),
        )
        .await;
        transaction.commit().await.unwrap();
        connection.close().await.unwrap();
        result
    });
    (pid, task)
}

/// A toggle request on its own connection, as [`spawn_approve`].
async fn spawn_request(
    pool: &PgPool,
    op: &'static str,
    revision: i64,
    value: bool,
) -> (
    i32,
    JoinHandle<Result<Gated<InstanceSecurityPolicy>, ApprovalError>>,
) {
    let (mut connection, pid) = connection(pool).await;
    let task = tokio::spawn(async move {
        let mut transaction = connection.begin().await.unwrap();
        let result = request_in(&mut transaction, "key_req", op, revision, value, at(0)).await;
        transaction.commit().await.unwrap();
        connection.close().await.unwrap();
        result
    });
    (pid, task)
}

/// Turns `single_actor_mode` on (policy revision 2).
async fn single_actor_mode(pool: &PgPool) {
    sqlx::query(
        "UPDATE instance_security_policy SET single_actor_mode = true, revision = revision + 1",
    )
    .execute(pool)
    .await
    .unwrap();
}

/// `tgenabled` of `administrative_operation_immutable`: `A` (fires
/// always) as `0005` leaves it.
async fn immutable_guard(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT tgenabled::text FROM pg_trigger \
         WHERE tgrelid = 'administrative_operation'::regclass \
         AND tgname = 'administrative_operation_immutable'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Writes `plan` over the stored plan of the operation `id`, past the
/// immutability guard, and leaves its digest as it was: in one
/// transaction the guard is disabled, the plan written (the revision
/// advanced, as the revision guard requires) and the guard enabled
/// `ALWAYS` again. DDL is transactional, so a failure rolls the disable
/// back with the write; either way the guard fires always afterwards.
async fn rewrite_plan(pool: &PgPool, id: &str, plan: Value) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await.unwrap();
    let written = async {
        sqlx::query(
            "ALTER TABLE administrative_operation \
             DISABLE TRIGGER administrative_operation_immutable",
        )
        .execute(&mut *transaction)
        .await?;
        let done = sqlx::query(
            "UPDATE administrative_operation SET immutable_plan = $2, \
             revision = revision + 1 WHERE id = $1",
        )
        .bind(id)
        .bind(Json(plan))
        .execute(&mut *transaction)
        .await?;
        assert_eq!(done.rows_affected(), 1, "{id}");
        sqlx::query(
            "ALTER TABLE administrative_operation \
             ENABLE ALWAYS TRIGGER administrative_operation_immutable",
        )
        .execute(&mut *transaction)
        .await?;
        Ok::<(), sqlx::Error>(())
    }
    .await;
    match written {
        Ok(()) => transaction.commit().await.unwrap(),
        Err(_) => transaction.rollback().await.unwrap(),
    }
    assert_eq!(immutable_guard(pool).await, "A");
    written
}

/// The SQLSTATE of a database error.
fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
}

/// The replacement operator a restoration enrolls: `adm_new` with
/// `crd_new` (`key_new`) and `rb_new`, an instance `security_admin`.
const RESTORED_KEY: &str = "key_new";

/// A break-glass restoration, committed: the challenge `op_restore` issued
/// at `at(2)` for [`RESTORED_KEY`]'s operator, then restored at `at(3)`.
/// It revokes every operator credential still unrevoked (the recovery
/// module docs, "Restore", step 6). The returned challenge `M` is signed
/// with the test recovery key [`RECOVERY_SEED`], which bootstrap enrolled;
/// the plan's new key is [`NEW_RECOVERY_SEED`]'s.
async fn restore(pool: &PgPool) -> Restored {
    let state = get_recovery_state(pool).await.unwrap().unwrap();
    let new_key = recovery_key(&NEW_RECOVERY_SEED);
    let plan = object(json!({
        "instance_id": INSTANCE_ID,
        "recovery_key_epoch": state.recovery_key_epoch,
        "admin_id": "adm_new",
        "credential_id": "crd_new",
        "binding_id": "rb_new",
        "public_identity": RESTORED_KEY,
        "trust_anchor_ref": "deployment/operator-ca",
        "new_recovery_public_key": new_key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    }));
    let mut transaction = pool.begin().await.unwrap();
    let challenge = issue_recovery_challenge(
        &mut transaction,
        &IssueChallenge {
            operation_id: "op_restore",
            kind: OPERATOR_RESTORATION,
            immutable_plan: &plan,
            ttl: DEFAULT_CHALLENGE_TTL,
            now: at(2),
            audit_event_id: "evt_issue_restore",
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    let signature = SigningKey::from_bytes(&RECOVERY_SEED)
        .sign(&challenge.challenge)
        .to_bytes();
    let mut transaction = pool.begin().await.unwrap();
    let restored = restore_operator(
        &mut transaction,
        &SignedRecoveryResponse {
            operation_id: "op_restore",
            signature: &signature,
        },
        &RestoreRequest {
            audit_event_id: "evt_restore",
            rotation_audit_event_id: "evt_rotate",
            now: at(3),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    restored
}

/// The seed of the test recovery key that bootstrap enrolls.
const RECOVERY_SEED: [u8; 32] = [0x51; 32];

/// The seed of the key a restoration rotates to.
const NEW_RECOVERY_SEED: [u8; 32] = [0x52; 32];

/// The Ed25519 public key of `seed`.
fn recovery_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// A gated toggle is a pending operation: its `create` event first, then
/// the row, pending, expiring 24 hours after the request's `now` floored to
/// the microsecond, with a digest that recomputes from the stored row and
/// a plan naming the credential the request presented. The policy row is
/// not written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_gated_toggle_is_a_pending_operation() {
    let (db, pool) = seeded().await;
    let before = policy(&pool).await;
    assert_eq!(
        (before.revision, before.widening_second_approver),
        (1, false)
    );
    assert!(!before.single_actor_mode);

    let pending_1 = pending(&pool, "key_req", "op_1", 1, true).await;
    let pending_2 = pending(&pool, "key_req_b", "op_2", 1, true).await;
    assert_eq!(pending_1.id, "op_1");
    assert_eq!(pending_1.kind, OperationKind::InstanceSecurityPolicyUpdate);
    assert_eq!(pending_1.expected_revision, 1);
    assert_eq!(pending_1.expires_at, expiry());
    assert_ne!(pending_1.request_digest, pending_2.request_digest);
    assert_eq!(policy(&pool).await, before);
    assert_eq!(
        events(&pool).await,
        [
            event(
                "evt_op_1",
                "adm_req",
                "administrative_operation.create",
                "op_1",
                None,
                Some(1),
                "success",
                0
            ),
            event(
                "evt_op_2",
                "adm_req",
                "administrative_operation.create",
                "op_2",
                None,
                Some(1),
                "success",
                0
            ),
        ]
    );
    for (pending, credential_id) in [(&pending_1, "crd_adm_req"), (&pending_2, "crd_adm_req_b")] {
        let row = operation(&pool, &pending.id).await;
        assert_eq!(
            row,
            AdministrativeOperation {
                id: pending.id.clone(),
                tenant_id: None,
                actor_id: "adm_req".into(),
                kind: KIND.into(),
                request_digest: pending.request_digest.as_bytes().to_vec(),
                expected_revision: 1,
                immutable_plan: toggle_plan(credential_id, true),
                challenge_hash: None,
                expires_at: Some(expiry()),
                consumed_at: None,
                revoked_at: None,
                revocation_operation_id: None,
                approves_operation_id: None,
                revision: 1,
                outcome: "pending".into(),
                audit_id: format!("evt_{}", pending.id),
            }
        );
        let recomputed = DigestEnvelope {
            id: &row.id,
            tenant_id: row.tenant_id.as_deref(),
            actor_id: &row.actor_id,
            kind: &row.kind,
            expected_revision: row.expected_revision,
            expires_at_us: i64::try_from(T0 + DAY).unwrap(),
            plan: &row.immutable_plan,
        }
        .digest()
        .unwrap();
        assert_eq!(recomputed, pending.request_digest);
    }
    // Turning the flag off is gated too.
    let off = pending(&pool, "key_req", "op_off", 1, false).await;
    assert_eq!(
        operation(&pool, "op_off").await.immutable_plan,
        toggle_plan("crd_adm_req", false)
    );
    assert_eq!(off.expires_at, expiry());
    assert_eq!(policy(&pool).await, before);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// An approval by another `security_admin` writes, in order, its
/// `approve` event, the `approve` operation, the policy row with its
/// `instance_security_policy.update` event by the requester, and the
/// operation consumed and `applied`, all at the one clock sample. The
/// reverse toggle goes through the same flow.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_applies_the_toggle_at_its_one_clock_sample() {
    let (db, pool) = seeded().await;
    let on = pending(&pool, "key_req", "op_on", 1, true).await;
    let prepared = prepare(&pool, "key_sec1", "op_on").await.unwrap();
    assert_eq!(prepared.operation_id(), "op_on");
    assert_eq!(prepared.kind(), OperationKind::InstanceSecurityPolicyUpdate);
    assert_eq!(
        format!("{prepared:?}"),
        "PreparedApproval { kind: InstanceSecurityPolicyUpdate, .. }"
    );
    let clock = TestClock::new(at(10));
    let applied = approve(&pool, "key_sec1", INSTANCE, &prepared, &echo(&on), &*clock)
        .await
        .unwrap();
    assert_eq!(clock.samples(), 1);
    let after = policy(&pool).await;
    assert_eq!(applied, Applied::InstanceSecurityPolicy(after.clone()));
    assert_eq!((after.revision, after.widening_second_approver), (2, true));
    assert_eq!(
        events(&pool).await[1..],
        [
            event(
                "evt_appr_op_on_key_sec1",
                "adm_sec1",
                "administrative_operation.approve",
                "op_on",
                Some(1),
                Some(2),
                "success",
                10
            ),
            event(
                "evt_write_op_on_key_sec1",
                "adm_req",
                "instance_security_policy.update",
                INSTANCE_ID,
                Some(1),
                Some(2),
                "success",
                10
            ),
        ]
    );
    let consumed = operation(&pool, "op_on").await;
    assert_eq!(consumed.consumed_at, Some(stored(10)));
    assert_eq!(consumed.revoked_at, None);
    assert_eq!(consumed.outcome, "applied");
    assert_eq!(consumed.revision, 2);
    assert_eq!(
        operation(&pool, "appr_op_on_key_sec1").await,
        AdministrativeOperation {
            id: "appr_op_on_key_sec1".into(),
            tenant_id: None,
            actor_id: "adm_sec1".into(),
            kind: "approve".into(),
            request_digest: on.request_digest.as_bytes().to_vec(),
            expected_revision: 1,
            immutable_plan: JsonObject::new(),
            challenge_hash: None,
            expires_at: None,
            consumed_at: None,
            revoked_at: None,
            revocation_operation_id: None,
            approves_operation_id: Some("op_on".into()),
            revision: 1,
            outcome: "success".into(),
            audit_id: "evt_appr_op_on_key_sec1".into(),
        }
    );

    // Back off, approved by the other approver.
    let off = pending(&pool, "key_req_b", "op_off", 2, false).await;
    let prepared = prepare(&pool, "key_sec2", "op_off").await.unwrap();
    let clock = TestClock::new(at(20));
    approve(&pool, "key_sec2", INSTANCE, &prepared, &echo(&off), &*clock)
        .await
        .unwrap();
    let after = policy(&pool).await;
    assert_eq!((after.revision, after.widening_second_approver), (3, false));
    assert_eq!(clock.samples(), 1);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The clock sample is floored to the microsecond and refused at the
/// expiry; a microsecond before it is accepted. `prepare_approval` draws
/// the same line with its `now`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_is_refused_from_its_expiry_on() {
    let (db, pool) = seeded().await;
    let op = pending(&pool, "key_req", "op_1", 1, true).await;
    let just_before = expiry() - Duration::from_nanos(1);
    refused(
        prepare_approval(&pool, "key_sec1", INSTANCE, "op_1", ALLOWED, expiry()).await,
        "NotApprovable(Expired)",
    );
    refused(
        prepare_approval(
            &pool,
            "key_sec1",
            INSTANCE,
            "op_1",
            ALLOWED,
            expiry() + Duration::from_secs(1),
        )
        .await,
        "NotApprovable(Expired)",
    );
    let prepared = prepare_approval(&pool, "key_sec1", INSTANCE, "op_1", ALLOWED, just_before)
        .await
        .unwrap();
    let before = snapshot(&pool).await;
    for late in [
        expiry(),
        expiry() + Duration::from_nanos(999),
        expiry() + Duration::from_secs(1),
    ] {
        let clock = TestClock::new(late);
        refused(
            approve(&pool, "key_sec1", INSTANCE, &prepared, &echo(&op), &*clock).await,
            "NotApprovable(Expired)",
        );
        assert_eq!(clock.samples(), 1);
        assert_eq!(snapshot(&pool).await, before);
    }
    let clock = TestClock::new(just_before);
    approve(&pool, "key_sec1", INSTANCE, &prepared, &echo(&op), &*clock)
        .await
        .unwrap();
    assert_eq!(
        operation(&pool, "op_1").await.consumed_at,
        Some(expiry() - Duration::from_micros(1))
    );
    assert_eq!(
        events(&pool).await[1].8,
        i64::try_from(T0 + DAY - 1).unwrap()
    );
    db.drop([pool]).await;
}

/// The clock is sampled after the registry write's lock: an approval that
/// waits for the policy row is judged by the time after the wait. Past the
/// expiry it writes nothing; before it, the operation is consumed at the
/// sample taken after the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_clock_is_sampled_after_the_policy_wait() {
    let (db, pool) = seeded().await;
    let op = pending(&pool, "key_req", "op_1", 1, true).await;
    let before = snapshot(&pool).await;
    for expired in [true, false] {
        let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
        let clock = TestClock::new(at(10));
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        lock_instance_security_policy_shared(&mut held)
            .await
            .unwrap();
        let (pid, task) =
            spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        assert_eq!(clock.samples(), 0, "sampled before the policy wait");
        let later = if expired {
            expiry()
        } else {
            expiry() - Duration::from_micros(1)
        };
        clock.set(later);
        held.rollback().await.unwrap();
        let result = finished(task).await;
        holder.close().await.unwrap();
        assert_eq!(clock.samples(), 1);
        if expired {
            refused(result, "NotApprovable(Expired)");
            assert_eq!(snapshot(&pool).await, before);
        } else {
            result.unwrap();
            assert_eq!(operation(&pool, "op_1").await.consumed_at, Some(later));
            assert!(policy(&pool).await.widening_second_approver);
        }
    }
    db.drop([pool]).await;
}

/// The clock is sampled before the first append: an approval that waits
/// for the audit head has already sampled once, keeps that sample through
/// the wait and is not judged again after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_clock_is_sampled_before_the_audit_head_wait() {
    let (db, pool) = seeded().await;
    let op = pending(&pool, "key_req", "op_1", 1, true).await;
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let clock = TestClock::new(at(10));
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    append_audit_event(
        &mut held,
        &NewAuditEvent {
            id: "evt_other".into(),
            tenant_id: None,
            timestamp: at(5),
            actor: AuditActor::Operator("adm_first".into()),
            action: "administrative_operation.create".into(),
            object_id: "op_other".into(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    let (pid, task) = spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    assert_eq!(clock.samples(), 1, "not sampled once before the head wait");
    clock.set(expiry() + Duration::from_secs(60));
    held.commit().await.unwrap();
    finished(task).await.unwrap();
    holder.close().await.unwrap();
    assert_eq!(clock.samples(), 1);
    assert_eq!(operation(&pool, "op_1").await.consumed_at, Some(stored(10)));
    let events = events(&pool).await;
    assert_eq!(events[1].0, "evt_other");
    assert_eq!(
        events[2..]
            .iter()
            .map(|e| (e.0.as_str(), e.8))
            .collect::<Vec<_>>(),
        [
            ("evt_appr_op_1_key_sec1", i64::try_from(T0 + 10).unwrap()),
            ("evt_write_op_1_key_sec1", i64::try_from(T0 + 10).unwrap()),
        ]
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The approver must be another enabled instance `security_admin` with an
/// enabled, unrevoked credential; every refusal writes nothing and samples
/// no clock.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_approver_is_another_security_admin() {
    let (db, pool) = seeded().await;
    operator(&pool, "adm_sec3", "key_sec3", &[("rb_sec3", SEC, None)]).await;
    let op = pending(&pool, "key_req", "op_1", 1, true).await;
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let prepared_3 = prepare(&pool, "key_sec3", "op_1").await.unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_sec3", at(3))
        .await
        .unwrap();
    let clock = TestClock::new(at(10));
    let before = snapshot(&pool).await;
    for (key, expected) in [
        ("key_req", "SelfApproval"),
        ("key_req_b", "SelfApproval"),
        ("key_trust", "Unauthorized"),
        ("spki-sha256:unknown", "Unauthorized"),
        ("key_sec3", "Unauthorized"),
    ] {
        refused(prepare(&pool, key, "op_1").await, expected);
        refused(
            approve(&pool, key, INSTANCE, &prepared, &echo(&op), &*clock).await,
            expected,
        );
    }
    refused(
        approve(
            &pool,
            "key_sec3",
            INSTANCE,
            &prepared_3,
            &echo(&op),
            &*clock,
        )
        .await,
        "Unauthorized",
    );
    // An unknown operation is not found for an approver only, and the
    // approver is authorized before the path's scope is checked.
    refused(prepare(&pool, "key_sec1", "op_none").await, "NotFound");
    refused(prepare(&pool, "key_trust", "op_none").await, "Unauthorized");
    refused(
        prepare_approval(&pool, "key_trust", TEN_A, "op_1", ALLOWED, at(1)).await,
        "Unauthorized",
    );
    refused(
        approve(&pool, "key_trust", TEN_A, &prepared, &echo(&op), &*clock).await,
        "Unauthorized",
    );
    assert_eq!(clock.samples(), 0);
    assert_eq!(snapshot(&pool).await, before);
    // The first admin, a security_admin too, may approve.
    approve(
        &pool,
        "spki-sha256:first",
        INSTANCE,
        &prepared,
        &echo(&op),
        &*clock,
    )
    .await
    .unwrap();
    assert_eq!(
        operation(&pool, "appr_op_1_spki-sha256:first")
            .await
            .actor_id,
        "adm_first"
    );
    db.drop([pool]).await;
}

/// The echo must be the operation's own digest and expected revision, the
/// prepared plan's digest must still be the row's, and the row must still
/// match its digest.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_echo_and_the_stored_digest_must_match() {
    let (db, pool) = seeded().await;
    let op = pending(&pool, "key_req", "op_1", 1, true).await;
    // The same plan, by the same requester, at the same revision.
    let twin = pending(&pool, "key_req", "op_2", 1, true).await;
    assert_ne!(op.request_digest, twin.request_digest);
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let clock = TestClock::new(at(10));
    let before = snapshot(&pool).await;
    let mut off_by_one = *op.request_digest.as_bytes();
    off_by_one[31] ^= 1;
    let mut first_off = *op.request_digest.as_bytes();
    first_off[0] ^= 0x80;
    for bad in [
        ApprovalEcho {
            request_digest: RequestDigest::from_bytes(off_by_one),
            ..echo(&op)
        },
        ApprovalEcho {
            request_digest: RequestDigest::from_bytes(first_off),
            ..echo(&op)
        },
        ApprovalEcho {
            request_digest: twin.request_digest,
            ..echo(&op)
        },
        ApprovalEcho {
            expected_revision: 2,
            ..echo(&op)
        },
        ApprovalEcho {
            expected_revision: 0,
            ..echo(&op)
        },
        echo(&twin),
    ] {
        refused(
            approve(&pool, "key_sec1", INSTANCE, &prepared, &bad, &*clock).await,
            "EchoMismatch",
        );
    }
    assert_eq!(snapshot(&pool).await, before);
    // An echo of another length is not a digest at all.
    let digest = op.request_digest.as_bytes();
    assert!(RequestDigest::try_from(&digest[..31]).is_err());
    let mut longer = digest.to_vec();
    longer.push(0);
    assert!(RequestDigest::try_from(&longer[..]).is_err());
    assert_eq!(
        RequestDigest::try_from(&digest[..]).unwrap(),
        op.request_digest
    );

    // A stored digest of another length is a data-integrity error, even
    // when its first 32 bytes are the row's digest: prepare_approval
    // refuses it, so no approval of it starts. (The approve's own check
    // under the lock is unit-tested: `verified_digest` in approval.rs.)
    for (id, repeat) in [("op_long", false), ("op_double", true)] {
        let mut new = raw_toggle(id, toggle_plan("crd_adm_req", true), None);
        if repeat {
            new.request_digest = new.request_digest.repeat(2);
        } else {
            new.request_digest.push(0);
        }
        insert_raw(&pool, &new).await;
        refused(prepare(&pool, "key_sec1", id).await, "PlanIntegrity");
        // Authorization still comes first.
        refused(prepare(&pool, "key_trust", id).await, "Unauthorized");
    }
    // A stored digest the row does not recompute to is a data-integrity
    // error whatever the echo: the stored digest is checked before the echo
    // is compared with it.
    let forged = raw_toggle(
        "op_forged",
        toggle_plan("crd_adm_req", true),
        Some(vec![0xd1; 32]),
    );
    insert_raw(&pool, &forged).await;
    let prepared_forged = prepare(&pool, "key_sec1", "op_forged").await.unwrap();
    let before_forged = snapshot(&pool).await;
    for echoed in [
        RequestDigest::from_bytes([0xd1; 32]),
        RequestDigest::from_bytes([0xd2; 32]),
        op.request_digest,
    ] {
        let forged_echo = ApprovalEcho {
            request_digest: echoed,
            expected_revision: 1,
        };
        refused(
            approve(
                &pool,
                "key_sec1",
                INSTANCE,
                &prepared_forged,
                &forged_echo,
                &*clock,
            )
            .await,
            "PlanIntegrity",
        );
    }
    // A valid stored digest and an echo of another valid digest.
    let good = raw_toggle("op_good", toggle_plan("crd_adm_req", true), None);
    insert_raw(&pool, &good).await;
    let prepared_good = prepare(&pool, "key_sec1", "op_good").await.unwrap();
    let good_echo = ApprovalEcho {
        request_digest: RequestDigest::try_from(&good.request_digest[..]).unwrap(),
        expected_revision: 1,
    };
    let before_forged = {
        let mut rows = before_forged;
        rows.retain(|row| !row.starts_with("audit_chain_head "));
        rows
    };
    for wrong in [RequestDigest::from_bytes([0xd1; 32]), op.request_digest] {
        refused(
            approve(
                &pool,
                "key_sec1",
                INSTANCE,
                &prepared_good,
                &ApprovalEcho {
                    request_digest: wrong,
                    ..good_echo
                },
                &*clock,
            )
            .await,
            "EchoMismatch",
        );
    }
    let mut after = snapshot(&pool).await;
    after.retain(|row| !row.starts_with("audit_chain_head ") && !row.contains("op_good"));
    assert_eq!(after, before_forged);
    assert_eq!(clock.samples(), 0);

    // The right echo still applies op_1.
    approve(&pool, "key_sec1", INSTANCE, &prepared, &echo(&op), &*clock)
        .await
        .unwrap();
    // The twin and the raw rows are now stale: the policy moved on.
    let prepared_twin = prepare(&pool, "key_sec1", "op_2").await.unwrap();
    refused(
        approve(
            &pool,
            "key_sec1",
            INSTANCE,
            &prepared_twin,
            &echo(&twin),
            &*clock,
        )
        .await,
        "StaleRevision",
    );
    db.drop([pool]).await;
}

/// The approver is authorized before the plan is read: a malformed plan is
/// `PlanIntegrity` for an approver only, and anybody else is `Unauthorized`
/// whatever the operation holds, or whether it exists.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_approver_is_authorized_before_the_plan_is_read() {
    let (db, pool) = seeded().await;
    for (id, plan) in [
        (
            "op_type",
            json!({"requester_credential_id": "crd_adm_req", "widening_second_approver": "yes"}),
        ),
        ("op_short", json!({"widening_second_approver": true})),
        (
            "op_extra",
            json!({
                "requester_credential_id": "crd_adm_req",
                "widening_second_approver": true,
                "x": 1,
            }),
        ),
        (
            "op_float",
            json!({"requester_credential_id": "crd_adm_req", "widening_second_approver": 1.5}),
        ),
    ] {
        insert_raw(&pool, &raw_toggle(id, object(plan), Some(vec![0xd1; 32]))).await;
        for key in ["key_trust", "key_req_b", "spki-sha256:unknown"] {
            let expected = if key == "key_req_b" {
                "SelfApproval"
            } else {
                "Unauthorized"
            };
            refused(prepare(&pool, key, id).await, expected);
        }
        refused(prepare(&pool, "key_sec1", id).await, "PlanIntegrity");
    }
    db.drop([pool]).await;
}

/// A plan written past the immutability guard (`ALTER TABLE ... DISABLE
/// TRIGGER`, then enabled again) is `PlanIntegrity`, writes nothing and
/// samples no clock, whichever check sees it first:
///
/// - written between the preparation and the approval, under its old
///   digest: the locked row no longer recomputes to its digest (D6), and
///   its plan is not the prepared one (D24);
/// - prepared again after that write: the prepared plan is the locked one,
///   so only the recomputed digest refuses it (D6);
/// - written before the preparation and put back before the approval: the
///   locked row recomputes to its digest again and the echo and the
///   prepared digest are its own, so only the comparison of the prepared
///   plan with the locked one refuses it (D24; `prepare_approval` checks
///   the stored digest's length, not the plan against it).
///
/// The guard fires always again after every write, a failed one included.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_plan_written_past_its_guard_is_plan_integrity() {
    let (db, pool) = seeded().await;
    assert_eq!(immutable_guard(&pool).await, "A");
    let op_b = pending(&pool, "key_req", "op_b", 1, true).await;
    let op_a = pending(&pool, "key_req", "op_a", 1, true).await;
    let original = Value::Object(toggle_plan("crd_adm_req", true));
    let flipped = Value::Object(toggle_plan("crd_adm_req", false));
    let clock = TestClock::new(at(10));

    // The guard refuses a plain write of the plan; a rewrite that fails
    // leaves the guard on and the row as it was.
    let before = snapshot(&pool).await;
    let err = sqlx::query(
        "UPDATE administrative_operation SET immutable_plan = $2, revision = revision + 1 \
         WHERE id = $1",
    )
    .bind("op_b")
    .bind(Json(flipped.clone()))
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("SK001"), "{err}");
    let err = rewrite_plan(&pool, "op_b", json!([])).await.unwrap_err();
    assert_eq!(sqlstate(&err).as_deref(), Some("23514"), "{err}");
    assert_eq!(snapshot(&pool).await, before);

    // Between the preparation and the approval.
    let prepared_b = prepare(&pool, "key_sec1", "op_b").await.unwrap();
    rewrite_plan(&pool, "op_b", flipped.clone()).await.unwrap();
    let row = operation(&pool, "op_b").await;
    assert_eq!(Value::Object(row.immutable_plan), flipped);
    assert_eq!(row.request_digest, op_b.request_digest.as_bytes());
    let prepared_b_after = prepare(&pool, "key_sec1", "op_b").await.unwrap();
    let before = snapshot(&pool).await;
    for prepared in [&prepared_b, &prepared_b_after] {
        refused(
            approve(&pool, "key_sec1", INSTANCE, prepared, &echo(&op_b), &*clock).await,
            "PlanIntegrity",
        );
    }
    assert_eq!(snapshot(&pool).await, before);

    // Before the preparation, put back before the approval.
    rewrite_plan(&pool, "op_a", flipped).await.unwrap();
    let prepared_a = prepare(&pool, "key_sec1", "op_a").await.unwrap();
    rewrite_plan(&pool, "op_a", original.clone()).await.unwrap();
    let row = operation(&pool, "op_a").await;
    assert_eq!(Value::Object(row.immutable_plan.clone()), original);
    let recomputed = DigestEnvelope {
        id: "op_a",
        tenant_id: None,
        actor_id: "adm_req",
        kind: KIND,
        expected_revision: 1,
        expires_at_us: i64::try_from(T0 + DAY).unwrap(),
        plan: &row.immutable_plan,
    }
    .digest()
    .unwrap();
    assert_eq!(recomputed, op_a.request_digest);
    assert_eq!(row.request_digest, op_a.request_digest.as_bytes());
    let before = snapshot(&pool).await;
    refused(
        approve(
            &pool,
            "key_sec1",
            INSTANCE,
            &prepared_a,
            &echo(&op_a),
            &*clock,
        )
        .await,
        "PlanIntegrity",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(clock.samples(), 0);
    let unchanged = policy(&pool).await;
    assert_eq!(
        (unchanged.revision, unchanged.widening_second_approver),
        (1, false)
    );
    assert_chain_intact(&pool).await;
    assert_eq!(immutable_guard(&pool).await, "A");

    // Prepared again from the row as it is, the approval applies it.
    let prepared_a = prepare(&pool, "key_sec1", "op_a").await.unwrap();
    approve(
        &pool,
        "key_sec1",
        INSTANCE,
        &prepared_a,
        &echo(&op_a),
        &*clock,
    )
    .await
    .unwrap();
    assert!(policy(&pool).await.widening_second_approver);
    assert_eq!(operation(&pool, "op_a").await.outcome, "applied");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The approval locks the requester's operator rows and refuses an
/// operation whose plan's credential is disabled, revoked or rotated away,
/// whose identity is disabled, or whose role binding is disabled; the
/// requester may still cancel it with another credential.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_requester_must_still_hold_the_plans_credential_and_role() {
    let (db, pool) = seeded().await;
    for n in 1..=6 {
        operator(
            &pool,
            &format!("adm_r{n}"),
            &format!("key_r{n}"),
            &[(&format!("rb_r{n}"), SEC, None)],
        )
        .await;
    }
    credential(&pool, "crd_adm_r3_b", "adm_r3", "key_r3_b").await;
    let mut ops = Vec::new();
    for n in 1..=6 {
        let id = format!("op_r{n}");
        let op = pending(&pool, &format!("key_r{n}"), &id, 1, true).await;
        let prepared = prepare(&pool, "key_sec1", &id).await.unwrap();
        ops.push((op, prepared));
    }
    sqlx::query("UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_r1'")
        .execute(&pool)
        .await
        .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_r2", at(2))
        .await
        .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_r3", at(2))
        .await
        .unwrap();
    registry::disable_admin_identity(&pool, "adm_r4")
        .await
        .unwrap();
    registry::test_support::update_admin_role_binding(
        &pool,
        "rb_r5",
        1,
        &AdminRoleBindingChanges {
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    let clock = TestClock::new(at(10));
    let before = snapshot(&pool).await;
    for (op, prepared) in &ops[..5] {
        refused(
            approve(&pool, "key_sec1", INSTANCE, prepared, &echo(op), &*clock).await,
            "RequesterNotAuthorized",
        );
    }
    assert_eq!(clock.samples(), 0);
    assert_eq!(snapshot(&pool).await, before);
    // The rotated requester cancels with its new credential.
    cancel(&pool, "key_r3_b", INSTANCE, "op_r3").await.unwrap();
    assert_eq!(operation(&pool, "op_r3").await.outcome, "cancelled");
    let (op, prepared) = &ops[5];
    approve(&pool, "key_sec1", INSTANCE, prepared, &echo(op), &*clock)
        .await
        .unwrap();

    // The credential checked is the plan's, not another of the requester's:
    // `adm_r7` and `adm_r8` request with their second credentials; the
    // plan's revoked refuses, another revoked does not.
    for n in [7, 8] {
        let admin = format!("adm_r{n}");
        operator(
            &pool,
            &admin,
            &format!("key_r{n}"),
            &[(&format!("rb_r{n}"), SEC, None)],
        )
        .await;
        credential(
            &pool,
            &format!("crd_{admin}_b"),
            &admin,
            &format!("key_r{n}_b"),
        )
        .await;
    }
    let op_7 = pending(&pool, "key_r7_b", "op_r7", 2, false).await;
    let op_8 = pending(&pool, "key_r8_b", "op_r8", 2, false).await;
    assert_eq!(
        operation(&pool, "op_r7").await.immutable_plan,
        toggle_plan("crd_adm_r7_b", false)
    );
    let prepared_7 = prepare(&pool, "key_sec1", "op_r7").await.unwrap();
    let prepared_8 = prepare(&pool, "key_sec1", "op_r8").await.unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_r7_b", at(3))
        .await
        .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_r8", at(3))
        .await
        .unwrap();
    refused(
        approve(
            &pool,
            "key_sec1",
            INSTANCE,
            &prepared_7,
            &echo(&op_7),
            &*clock,
        )
        .await,
        "RequesterNotAuthorized",
    );
    approve(
        &pool,
        "key_sec1",
        INSTANCE,
        &prepared_8,
        &echo(&op_8),
        &*clock,
    )
    .await
    .unwrap();
    db.drop([pool]).await;
}

/// A break-glass restoration between the request and the approval revokes
/// every operator credential, the plan's included, and leaves the
/// requester's identity and role binding enabled. The replacement
/// `security_admin` it enrolls may prepare the operation, but its approval
/// is `RequesterNotAuthorized` (D21), whether prepared before or after the
/// restoration, and writes nothing; an approver from before the
/// restoration is `Unauthorized`. The replacement may still reject it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restoration_between_the_request_and_the_approval_refuses_it() {
    let (db, pool) = seeded().await;
    let op = pending(&pool, "key_req", "op_1", 1, true).await;
    let prepared_before = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let restored = restore(&pool).await;
    for id in ["crd_adm_req", "crd_adm_req_b", "crd_adm_sec1"] {
        assert!(
            restored.revoked_credential_ids.iter().any(|c| c == id),
            "{id}"
        );
    }
    let (status, revoked): (String, bool) = sqlx::query_as(
        "SELECT c.status, c.revoked_at IS NOT NULL FROM admin_credential c \
         JOIN admin_identity i ON i.id = c.admin_id \
         JOIN admin_role_binding b ON b.admin_id = i.id \
         WHERE c.id = 'crd_adm_req' AND i.status = 'enabled' \
         AND b.id = 'rb_req' AND b.status = 'enabled'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((status.as_str(), revoked), ("disabled", true));

    refused(prepare(&pool, "key_sec1", "op_1").await, "Unauthorized");
    let prepared_after = prepare(&pool, RESTORED_KEY, "op_1").await.unwrap();
    let clock = TestClock::new(at(10));
    let before = snapshot(&pool).await;
    for prepared in [&prepared_before, &prepared_after] {
        refused(
            approve(&pool, RESTORED_KEY, INSTANCE, prepared, &echo(&op), &*clock).await,
            "RequesterNotAuthorized",
        );
        refused(
            approve(&pool, "key_sec1", INSTANCE, prepared, &echo(&op), &*clock).await,
            "Unauthorized",
        );
    }
    assert_eq!(clock.samples(), 0);
    assert_eq!(snapshot(&pool).await, before);
    let row = operation(&pool, "op_1").await;
    assert_eq!(
        (row.outcome.as_str(), row.consumed_at, row.revoked_at),
        ("pending", None, None)
    );
    let unchanged = policy(&pool).await;
    assert_eq!(
        (unchanged.revision, unchanged.widening_second_approver),
        (1, false)
    );
    assert_chain_intact(&pool).await;

    reject(&pool, RESTORED_KEY, INSTANCE, "op_1").await.unwrap();
    assert_eq!(operation(&pool, "op_1").await.outcome, "rejected");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Consumed, revoked and foreign operations: an operation is approved once,
/// a revoked one never, an operation of another kind or scope is not
/// approvable on this path, and a path that does not hold the operation
/// does not find it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn consumed_revoked_and_foreign_operations_are_refused() {
    let (db, pool) = seeded().await;
    let clock = TestClock::new(at(10));
    let op_1 = pending(&pool, "key_req", "op_1", 1, true).await;
    let op_2 = pending(&pool, "key_req", "op_2", 1, true).await;
    let prepared_1 = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let prepared_1b = prepare(&pool, "key_sec2", "op_1").await.unwrap();
    let prepared_2 = prepare(&pool, "key_sec1", "op_2").await.unwrap();

    // The path's scope comes first.
    for scope in [TEN_A, TEN_B] {
        refused(
            prepare_approval(&pool, "key_sec1", scope, "op_1", ALLOWED, at(1)).await,
            "NotFound",
        );
        refused(
            approve(&pool, "key_sec1", scope, &prepared_1, &echo(&op_1), &*clock).await,
            "NotFound",
        );
        refused(reject(&pool, "key_sec1", scope, "op_1").await, "NotFound");
    }
    refused(cancel(&pool, "key_trust", TEN_A, "op_1").await, "NotFound");

    approve(
        &pool,
        "key_sec1",
        INSTANCE,
        &prepared_1,
        &echo(&op_1),
        &*clock,
    )
    .await
    .unwrap();
    let before = snapshot(&pool).await;
    refused(
        prepare(&pool, "key_sec2", "op_1").await,
        "NotApprovable(Consumed)",
    );
    refused(
        approve(
            &pool,
            "key_sec2",
            INSTANCE,
            &prepared_1b,
            &echo(&op_1),
            &*clock,
        )
        .await,
        "NotApprovable(Consumed)",
    );
    refused(
        cancel(&pool, "key_req", INSTANCE, "op_1").await,
        "NotApprovable(Consumed)",
    );
    refused(
        reject(&pool, "key_sec2", INSTANCE, "op_1").await,
        "NotApprovable(Consumed)",
    );
    assert_eq!(snapshot(&pool).await, before);

    cancel(&pool, "key_req", INSTANCE, "op_2").await.unwrap();
    let before = snapshot(&pool).await;
    refused(
        prepare(&pool, "key_sec1", "op_2").await,
        "NotApprovable(Revoked)",
    );
    refused(
        approve(
            &pool,
            "key_sec1",
            INSTANCE,
            &prepared_2,
            &echo(&op_2),
            &*clock,
        )
        .await,
        "NotApprovable(Revoked)",
    );
    refused(
        cancel(&pool, "key_req", INSTANCE, "op_2").await,
        "NotApprovable(Revoked)",
    );
    refused(
        reject(&pool, "key_sec1", INSTANCE, "op_2").await,
        "NotApprovable(Revoked)",
    );
    assert_eq!(snapshot(&pool).await, before);

    // Operations of a kind outside the flow, and the flow's own records.
    let mut restoration = raw_toggle("op_restore", JsonObject::new(), Some(vec![0xd1; 32]));
    restoration.kind = "operator_restoration".into();
    insert_raw(&pool, &restoration).await;
    let mut tenant_toggle = raw_toggle("op_tenant", toggle_plan("crd_adm_trust", true), None);
    tenant_toggle.tenant_id = Some("ten_a".into());
    tenant_toggle.actor_id = "adm_trust".into();
    insert_raw(&pool, &tenant_toggle).await;
    let mut own_tenant_toggle = tenant_toggle.clone();
    own_tenant_toggle.id = "op_own_tenant".into();
    own_tenant_toggle.actor_id = "adm_sec1".into();
    own_tenant_toggle.audit_id = "evt_op_own_tenant".into();
    insert_raw(&pool, &own_tenant_toggle).await;
    let before = snapshot(&pool).await;
    // The scope before self-approval before the kind.
    refused(
        prepare(&pool, "key_sec1", "op_own_tenant").await,
        "NotFound",
    );
    refused(
        prepare_approval(&pool, "key_sec1", TEN_A, "op_own_tenant", ALLOWED, at(1)).await,
        "SelfApproval",
    );
    refused(
        prepare(&pool, "key_sec1", "appr_op_1_key_sec1").await,
        "SelfApproval",
    );
    for id in ["op_restore", "appr_op_1_key_sec1", "cancel_op_2_key_req"] {
        refused(
            prepare(&pool, "key_sec2", id).await,
            "NotApprovable(WrongKind)",
        );
        refused(
            reject(&pool, "key_sec2", INSTANCE, id).await,
            "NotApprovable(WrongKind)",
        );
    }
    refused(
        cancel(&pool, "key_req", INSTANCE, "op_restore").await,
        "NotApprovable(WrongKind)",
    );
    refused(
        prepare_approval(&pool, "key_sec1", TEN_A, "op_tenant", ALLOWED, at(1)).await,
        "NotApprovable(WrongKind)",
    );
    refused(
        reject(&pool, "key_sec1", TEN_A, "op_tenant").await,
        "NotApprovable(WrongKind)",
    );
    refused(
        cancel(&pool, "key_trust", TEN_A, "op_tenant").await,
        "NotApprovable(WrongKind)",
    );
    for scope in [INSTANCE, TEN_B] {
        refused(
            prepare_approval(&pool, "key_sec1", scope, "op_tenant", ALLOWED, at(1)).await,
            "NotFound",
        );
        refused(
            reject(&pool, "key_sec1", scope, "op_tenant").await,
            "NotFound",
        );
    }
    refused(prepare(&pool, "key_sec1", "op_none").await, "NotFound");
    refused(
        reject(&pool, "key_sec1", INSTANCE, "op_none").await,
        "NotFound",
    );
    refused(
        cancel(&pool, "key_req", INSTANCE, "op_none").await,
        "NotFound",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(clock.samples(), 1);
    db.drop([pool]).await;
}

/// A cancel is the requester's, with any of its credentials, and a reject
/// another instance `security_admin`'s; each records its operation and
/// event and revokes the pending one, also after its expiry, without
/// touching the policy row.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn cancel_is_the_requesters_and_reject_another_approvers() {
    let (db, pool) = seeded().await;
    let op_1 = pending(&pool, "key_req", "op_1", 1, true).await;
    let op_2 = pending(&pool, "key_req", "op_2", 1, true).await;
    let policy_before = policy(&pool).await;
    let before = snapshot(&pool).await;
    for (key, expected) in [
        ("key_sec1", "Unauthorized"),
        ("key_trust", "Unauthorized"),
        ("spki-sha256:unknown", "Unauthorized"),
    ] {
        refused(cancel(&pool, key, INSTANCE, "op_1").await, expected);
    }
    for (key, expected) in [
        ("key_req", "SelfApproval"),
        ("key_req_b", "SelfApproval"),
        ("key_trust", "Unauthorized"),
        ("spki-sha256:unknown", "Unauthorized"),
    ] {
        refused(reject(&pool, key, INSTANCE, "op_1").await, expected);
    }
    // Anybody but an approver is unauthorized before a missing operation
    // is looked up.
    refused(
        cancel(&pool, "key_trust", INSTANCE, "op_none").await,
        "Unauthorized",
    );
    refused(
        reject(&pool, "key_trust", INSTANCE, "op_none").await,
        "Unauthorized",
    );
    assert_eq!(snapshot(&pool).await, before);

    cancel(&pool, "key_req_b", INSTANCE, "op_1").await.unwrap();
    let cancelled = operation(&pool, "op_1").await;
    assert_eq!(cancelled.revoked_at, Some(stored(7)));
    assert_eq!(
        cancelled.revocation_operation_id.as_deref(),
        Some("cancel_op_1_key_req_b")
    );
    assert_eq!(cancelled.consumed_at, None);
    assert_eq!(cancelled.outcome, "cancelled");
    assert_eq!(cancelled.revision, 2);
    assert_eq!(
        operation(&pool, "cancel_op_1_key_req_b").await,
        AdministrativeOperation {
            id: "cancel_op_1_key_req_b".into(),
            tenant_id: None,
            actor_id: "adm_req".into(),
            kind: "cancel".into(),
            request_digest: op_1.request_digest.as_bytes().to_vec(),
            expected_revision: 1,
            immutable_plan: JsonObject::new(),
            challenge_hash: None,
            expires_at: None,
            consumed_at: None,
            revoked_at: None,
            revocation_operation_id: None,
            approves_operation_id: None,
            revision: 1,
            outcome: "success".into(),
            audit_id: "evt_cancel_op_1_key_req_b".into(),
        }
    );

    // A reject after the expiry.
    revoke(
        &pool,
        Revocation::Reject,
        "key_sec2",
        INSTANCE,
        "op_2",
        at(DAY + 5),
    )
    .await
    .unwrap();
    let rejected = operation(&pool, "op_2").await;
    assert_eq!(rejected.revoked_at, Some(stored(DAY + 5)));
    assert_eq!(rejected.outcome, "rejected");
    assert_eq!(
        rejected.revocation_operation_id.as_deref(),
        Some("reject_op_2_key_sec2")
    );
    let reject_row = operation(&pool, "reject_op_2_key_sec2").await;
    assert_eq!(
        (
            reject_row.kind.as_str(),
            reject_row.actor_id.as_str(),
            reject_row.request_digest,
            reject_row.outcome.as_str(),
            reject_row.expires_at,
            reject_row.approves_operation_id,
        ),
        (
            "reject",
            "adm_sec2",
            op_2.request_digest.as_bytes().to_vec(),
            "success",
            None,
            None
        )
    );
    assert_eq!(
        events(&pool).await[2..],
        [
            event(
                "evt_cancel_op_1_key_req_b",
                "adm_req",
                "administrative_operation.cancel",
                "op_1",
                Some(1),
                Some(2),
                "success",
                7
            ),
            event(
                "evt_reject_op_2_key_sec2",
                "adm_sec2",
                "administrative_operation.reject",
                "op_2",
                Some(1),
                Some(2),
                "success",
                DAY + 5
            ),
        ]
    );
    assert_eq!(policy(&pool).await, policy_before);
    // An expired operation may be cancelled too.
    pending(&pool, "key_req", "op_3", 1, true).await;
    revoke(
        &pool,
        Revocation::Cancel,
        "key_req",
        INSTANCE,
        "op_3",
        at(DAY),
    )
    .await
    .unwrap();
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Under `single_actor_mode` the toggle applies at once, both ways, with an
/// `instance_security_policy.update` event whose outcome is
/// `success_single_actor`, and writes no operation.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn single_actor_mode_applies_the_toggle_at_once() {
    let (db, pool) = seeded().await;
    single_actor_mode(&pool).await;
    for (n, value) in [(2, true), (3, false)] {
        let op = format!("op_{n}");
        let Gated::Applied(row) = request(&pool, "key_req", &op, n, value).await.unwrap() else {
            panic!("not applied")
        };
        assert_eq!(row, policy(&pool).await);
        assert_eq!((row.revision, row.widening_second_approver), (n + 1, value));
        assert!(row.single_actor_mode);
    }
    assert_eq!(
        events(&pool).await,
        [
            event(
                "evt_op_2",
                "adm_req",
                "instance_security_policy.update",
                INSTANCE_ID,
                Some(2),
                Some(3),
                "success_single_actor",
                0
            ),
            event(
                "evt_op_3",
                "adm_req",
                "instance_security_policy.update",
                INSTANCE_ID,
                Some(3),
                Some(4),
                "success_single_actor",
                0
            ),
        ]
    );
    let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM administrative_operation")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(operations, 0);
    let before = snapshot(&pool).await;
    refused(
        request(&pool, "key_req", "op_x", 3, true).await,
        "StaleRevision",
    );
    refused(
        request(&pool, "key_req", "op_x", 5, true).await,
        "StaleRevision",
    );
    refused(
        request(&pool, "key_trust", "op_x", 4, true).await,
        "Unauthorized",
    );
    refused(
        request(&pool, "spki-sha256:unknown", "op_x", 4, true).await,
        "Unauthorized",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The toggle's refusals: a stale revision, an unauthorized key, another
/// isolation level, and no policy row (D18). Each writes nothing and
/// releases the policy row, and the transaction stays usable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_toggles_refusals_write_nothing_and_release_the_policy_row() {
    let (db, pool) = seeded().await;
    let before = snapshot(&pool).await;
    for (key, revision, expected) in [
        ("key_req", 2, "StaleRevision"),
        ("key_req", 0, "StaleRevision"),
        ("key_trust", 1, "Unauthorized"),
        ("spki-sha256:unknown", 1, "Unauthorized"),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        refused(
            request_in(&mut transaction, key, "op_x", revision, true, at(0)).await,
            expected,
        );
        assert!(!policy_conflicts(&pool, "FOR UPDATE").await);
        // The transaction goes on.
        let Gated::Pending(_) = request_in(&mut transaction, "key_req", "op_y", 1, true, at(0))
            .await
            .unwrap()
        else {
            panic!("not pending")
        };
        transaction.rollback().await.unwrap();
    }
    assert_eq!(snapshot(&pool).await, before);

    let op = pending(&pool, "key_req", "op_1", 1, true).await;
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let clock = TestClock::new(at(10));
    for level in ["REPEATABLE READ", "SERIALIZABLE"] {
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query(AssertSqlSafe(format!(
            "SET TRANSACTION ISOLATION LEVEL {level}"
        )))
        .execute(&mut *transaction)
        .await
        .unwrap();
        refused(
            request_in(&mut transaction, "key_req", "op_x", 1, true, at(0)).await,
            "UnsupportedIsolation",
        );
        // The isolation comes before the authorization and the
        // acknowledgement: turning the setting off without it, by a
        // `security_admin` or by a credential without the role.
        for key in ["key_req", "key_trust"] {
            refused(
                submit_in(&mut transaction, key, "op_x", 1, false, false, at(0)).await,
                "UnsupportedIsolation",
            );
        }
        refused(
            approve_in(
                &mut transaction,
                "key_sec1",
                INSTANCE,
                &prepared,
                &echo(&op),
                &*clock,
            )
            .await,
            "UnsupportedIsolation",
        );
        refused(
            revoke_in(
                &mut transaction,
                Revocation::Cancel,
                "key_req",
                INSTANCE,
                "op_1",
                at(7),
            )
            .await,
            "UnsupportedIsolation",
        );
        refused(
            revoke_in(
                &mut transaction,
                Revocation::Reject,
                "key_sec1",
                INSTANCE,
                "op_1",
                at(7),
            )
            .await,
            "UnsupportedIsolation",
        );
        transaction.commit().await.unwrap();
    }
    assert_eq!(clock.samples(), 0);
    db.drop([pool]).await;

    // No policy row: an operator exists, the policy does not (D18).
    let (db, pool) = migrated().await;
    operator(&pool, "adm_req", "key_req", &[("rb_req", SEC, None)]).await;
    let before = snapshot(&pool).await;
    refused(
        request(&pool, "key_req", "op_1", 1, true).await,
        "PolicyUnavailable",
    );
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A pending toggle from [`submit`].
#[track_caller]
fn gated_pending(result: Result<Gated<InstanceSecurityPolicy>, ApprovalError>) -> PendingOperation {
    match result {
        Ok(Gated::Pending(pending)) => pending,
        other => panic!("not pending: {other:?}"),
    }
}

/// A toggle applied at once from [`submit`].
#[track_caller]
fn gated_applied(
    result: Result<Gated<InstanceSecurityPolicy>, ApprovalError>,
) -> InstanceSecurityPolicy {
    match result {
        Ok(Gated::Applied(row)) => row,
        other => panic!("not applied: {other:?}"),
    }
}

/// Turning `widening_second_approver` off is a widening write (the user's
/// ruling, 2026-11-24): every request that sets it to false needs
/// `acknowledge_widening`, whatever the current value, a false to false
/// request included. Without it the request is `WideningNotAcknowledged`
/// and writes nothing (no operation, no event, the policy row and its
/// revision unchanged), and the transaction goes on. With it the request
/// goes pending and an approval applies it. Turning the setting on needs no
/// acknowledgement.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn turning_the_toggle_off_needs_the_acknowledgement() {
    let (db, pool) = seeded().await;

    // False to false, a request for the current value.
    let before = snapshot(&pool).await;
    assert_eq!(written(&pool).await, (0, 1, 1, false));
    for key in ["key_req", "key_req_b"] {
        let mut transaction = pool.begin().await.unwrap();
        refused(
            submit_in(&mut transaction, key, "op_x", 1, false, false, at(0)).await,
            "WideningNotAcknowledged",
        );
        assert!(!policy_conflicts(&pool, "FOR UPDATE").await);
        // The transaction goes on.
        gated_pending(submit_in(&mut transaction, key, "op_y", 1, false, true, at(0)).await);
        transaction.rollback().await.unwrap();
    }
    assert_eq!(written(&pool).await, (0, 1, 1, false));
    assert_eq!(snapshot(&pool).await, before);
    // Acknowledged, it goes pending, and its approval only advances the
    // revision.
    let same = gated_pending(submit(&pool, "key_req", "op_same", 1, false, true).await);
    assert_eq!(written(&pool).await, (1, 2, 1, false));
    assert_eq!(
        operation(&pool, "op_same").await.immutable_plan,
        toggle_plan("crd_adm_req", false)
    );
    let prepared = prepare(&pool, "key_sec1", "op_same").await.unwrap();
    approve(
        &pool,
        "key_sec1",
        INSTANCE,
        &prepared,
        &echo(&same),
        &*TestClock::new(at(10)),
    )
    .await
    .unwrap();
    assert_eq!(written(&pool).await, (2, 4, 2, false));

    // On, without the acknowledgement: pending, then approved.
    let on = gated_pending(submit(&pool, "key_req", "op_on", 2, true, false).await);
    let prepared = prepare(&pool, "key_sec2", "op_on").await.unwrap();
    approve(
        &pool,
        "key_sec2",
        INSTANCE,
        &prepared,
        &echo(&on),
        &*TestClock::new(at(10)),
    )
    .await
    .unwrap();
    assert_eq!(written(&pool).await, (4, 7, 3, true));

    // True to false, without the acknowledgement: refused, nothing written.
    let before = snapshot(&pool).await;
    for key in ["key_req", "key_req_b"] {
        refused(
            submit(&pool, key, "op_x", 3, false, false).await,
            "WideningNotAcknowledged",
        );
    }
    assert_eq!(written(&pool).await, (4, 7, 3, true));
    assert_eq!(snapshot(&pool).await, before);
    // With it: pending, then approved.
    let off = gated_pending(submit(&pool, "key_req", "op_off", 3, false, true).await);
    assert_eq!(written(&pool).await, (5, 8, 3, true));
    let prepared = prepare(&pool, "key_sec1", "op_off").await.unwrap();
    approve(
        &pool,
        "key_sec1",
        INSTANCE,
        &prepared,
        &echo(&off),
        &*TestClock::new(at(10)),
    )
    .await
    .unwrap();
    assert_eq!(written(&pool).await, (6, 10, 4, false));
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Under `single_actor_mode` turning the setting off needs the
/// acknowledgement too, false to false included: without it the request is
/// `WideningNotAcknowledged` and writes nothing; with it the toggle applies
/// at once. Turning it on applies at once without it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn under_single_actor_mode_turning_the_toggle_off_needs_the_acknowledgement() {
    let (db, pool) = seeded().await;
    single_actor_mode(&pool).await;
    let before = snapshot(&pool).await;
    refused(
        submit(&pool, "key_req", "op_x", 2, false, false).await,
        "WideningNotAcknowledged",
    );
    assert_eq!(written(&pool).await, (0, 1, 2, false));
    assert_eq!(snapshot(&pool).await, before);
    let row = gated_applied(submit(&pool, "key_req", "op_1", 2, false, true).await);
    assert_eq!((row.revision, row.widening_second_approver), (3, false));
    let row = gated_applied(submit(&pool, "key_req", "op_2", 3, true, false).await);
    assert_eq!((row.revision, row.widening_second_approver), (4, true));
    let before = snapshot(&pool).await;
    refused(
        submit(&pool, "key_req", "op_x", 4, false, false).await,
        "WideningNotAcknowledged",
    );
    assert_eq!(written(&pool).await, (0, 3, 4, true));
    assert_eq!(snapshot(&pool).await, before);
    let row = gated_applied(submit(&pool, "key_req", "op_3", 4, false, true).await);
    assert_eq!(row, policy(&pool).await);
    assert_eq!((row.revision, row.widening_second_approver), (5, false));
    assert!(row.single_actor_mode);
    let update = |id, previous| {
        event(
            id,
            "adm_req",
            "instance_security_policy.update",
            INSTANCE_ID,
            Some(previous),
            Some(previous + 1),
            "success_single_actor",
            0,
        )
    };
    assert_eq!(
        events(&pool).await,
        [
            update("evt_op_1", 2),
            update("evt_op_2", 3),
            update("evt_op_3", 4)
        ]
    );
    assert_eq!(written(&pool).await, (0, 4, 5, false));
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The acknowledgement is checked where the trust writes check theirs
/// (request step 3): after the authorization, so an operator without the
/// role gets `Unauthorized`, and before the policy row (its revision, its
/// absence, its lock) and every write, in both branches. A request without
/// it is refused while another transaction holds the policy row and the
/// audit head, and with an operation and event ID already taken.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_acknowledgement_is_checked_after_the_authorization_before_any_lock_or_write() {
    let (db, pool) = seeded().await;
    pending(&pool, "key_req", "op_1", 1, true).await;
    for single in [false, true] {
        if single {
            single_actor_mode(&pool).await;
        }
        let revision = policy(&pool).await.revision;
        let before = snapshot(&pool).await;
        for key in ["key_trust", "spki-sha256:unknown"] {
            refused(
                submit(&pool, key, "op_x", revision, false, false).await,
                "Unauthorized",
            );
        }
        for stale in [revision - 1, revision + 1] {
            refused(
                submit(&pool, "key_req", "op_x", stale, false, false).await,
                "WideningNotAcknowledged",
            );
        }
        // `op_1` and `evt_op_1` are taken.
        refused(
            submit(&pool, "key_req", "op_1", revision, false, false).await,
            "WideningNotAcknowledged",
        );
        // The policy row and the audit head held elsewhere: the refusal
        // waits for neither, and the acknowledged request does.
        let (mut holder, _) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        for table in ["instance_security_policy", "audit_chain_head"] {
            sqlx::query(AssertSqlSafe(format!("SELECT FROM {table} FOR UPDATE")))
                .execute(&mut *held)
                .await
                .unwrap();
        }
        for acknowledge in [false, true] {
            let mut transaction = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL lock_timeout = '1s'")
                .execute(&mut *transaction)
                .await
                .unwrap();
            let result = submit_in(
                &mut transaction,
                "key_req",
                "op_x",
                revision,
                false,
                acknowledge,
                at(0),
            )
            .await;
            transaction.rollback().await.unwrap();
            match (acknowledge, result) {
                (false, result) => refused(result, "WideningNotAcknowledged"),
                (true, Err(ApprovalError::Registry(err))) => {
                    let code = std::error::Error::source(&err)
                        .and_then(|source| source.downcast_ref::<sqlx::Error>())
                        .and_then(|raw| raw.as_database_error())
                        .and_then(|raw| raw.code());
                    assert_eq!(code.as_deref(), Some("55P03"), "{err:?}");
                }
                (true, other) => panic!("expected a lock timeout, got {other:?}"),
            }
        }
        held.rollback().await.unwrap();
        holder.close().await.unwrap();
        assert_eq!(snapshot(&pool).await, before);
    }
    db.drop([pool]).await;

    // No policy row: the flag comes before `PolicyUnavailable`, as for the
    // trust writes.
    let (db, pool) = migrated().await;
    operator(&pool, "adm_req", "key_req", &[("rb_req", SEC, None)]).await;
    let before = snapshot(&pool).await;
    refused(
        submit(&pool, "key_req", "op_1", 1, false, false).await,
        "WideningNotAcknowledged",
    );
    refused(
        submit(&pool, "key_req", "op_1", 1, false, true).await,
        "PolicyUnavailable",
    );
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// The toggle locks the policy row `FOR NO KEY UPDATE` in both branches:
/// it conflicts with a trust write's `FOR SHARE`, not with a foreign key's
/// `FOR KEY SHARE`, and it waits for a trust write in progress.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_toggle_locks_the_policy_row_for_no_key_update() {
    let (db, pool) = seeded().await;
    for single in [false, true] {
        if single {
            single_actor_mode(&pool).await;
        }
        let revision = policy(&pool).await.revision;
        let mut transaction = pool.begin().await.unwrap();
        request_in(
            &mut transaction,
            "key_req",
            "op_held",
            revision,
            true,
            at(0),
        )
        .await
        .unwrap();
        assert!(policy_conflicts(&pool, "FOR SHARE").await);
        assert!(policy_conflicts(&pool, "FOR NO KEY UPDATE").await);
        assert!(!policy_conflicts(&pool, "FOR KEY SHARE").await);
        assert_operator_rows_shared(&pool, &["adm_req"], &["crd_adm_req"], &["rb_req"]).await;
        transaction.rollback().await.unwrap();

        // A toggle waits for a trust write's FOR SHARE.
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        lock_instance_security_policy_shared(&mut held)
            .await
            .unwrap();
        let wait = if single { "op_wait_s" } else { "op_wait_g" };
        let (pid, task) = spawn_request(&pool, wait, revision, true).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        held.rollback().await.unwrap();
        holder.close().await.unwrap();
        let result = finished(task).await.unwrap();
        assert_eq!(matches!(result, Gated::Applied(_)), single);
        if !single {
            // Withdraw it, so the single-actor round starts clean.
            cancel(&pool, "key_req", INSTANCE, wait).await.unwrap();
        }
    }
    db.drop([pool]).await;
}

/// Two approvals of one operation: the second waits for the first's
/// operation lock, then finds it consumed, or applies it when the first
/// rolled back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn two_approvals_of_one_operation_apply_it_once() {
    let (db, pool) = seeded().await;
    for commit in [true, false] {
        let id = if commit { "op_commit" } else { "op_rollback" };
        let revision = policy(&pool).await.revision;
        let op = pending(&pool, "key_req", id, revision, true).await;
        let first = prepare(&pool, "key_sec1", id).await.unwrap();
        let second = prepare(&pool, "key_sec2", id).await.unwrap();
        let clock = TestClock::new(at(10));
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        approve_in(&mut held, "key_sec1", INSTANCE, &first, &echo(&op), &*clock)
            .await
            .unwrap();
        let (pid, task) = spawn_approve(&pool, "key_sec2", second, echo(&op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        if commit {
            held.commit().await.unwrap();
            refused(finished(task).await, "NotApprovable(Consumed)");
            assert_eq!(operation(&pool, id).await.consumed_at, Some(stored(10)));
        } else {
            held.rollback().await.unwrap();
            finished(task).await.unwrap();
            let row = operation(&pool, &format!("appr_{id}_key_sec2")).await;
            assert_eq!(row.actor_id, "adm_sec2");
        }
        holder.close().await.unwrap();
        assert_eq!(clock.samples(), if commit { 1 } else { 2 });
        let after = policy(&pool).await;
        assert_eq!(after.revision, revision + 1);
        // Reset the flag for the next round.
        sqlx::query(
            "UPDATE instance_security_policy SET widening_second_approver = false, \
             revision = revision + 1",
        )
        .execute(&pool)
        .await
        .unwrap();
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// An approval and a cancel of one operation: whichever takes the
/// operation lock first wins and the other finds it consumed or revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_and_a_cancel_race_for_the_operation() {
    let (db, pool) = seeded().await;
    let clock = TestClock::new(at(10));

    // The approval first.
    let op = pending(&pool, "key_req", "op_a", 1, true).await;
    let prepared = prepare(&pool, "key_sec1", "op_a").await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    approve_in(
        &mut held,
        "key_sec1",
        INSTANCE,
        &prepared,
        &echo(&op),
        &*clock,
    )
    .await
    .unwrap();
    assert_operator_rows_shared(
        &pool,
        &["adm_req", "adm_sec1"],
        &["crd_adm_req", "crd_adm_sec1"],
        &["rb_req", "rb_sec1"],
    )
    .await;
    let (pid, task) = spawn_cancel(&pool, "op_a").await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    refused(finished(task).await, "NotApprovable(Consumed)");
    assert_eq!(operation(&pool, "op_a").await.outcome, "applied");

    // The cancel first.
    let op = pending(&pool, "key_req", "op_c", 2, false).await;
    let prepared = prepare(&pool, "key_sec1", "op_c").await.unwrap();
    let mut held = holder.begin().await.unwrap();
    revoke_in(
        &mut held,
        Revocation::Cancel,
        "key_req",
        INSTANCE,
        "op_c",
        at(7),
    )
    .await
    .unwrap();
    assert_operator_rows_shared(&pool, &["adm_req"], &["crd_adm_req"], &["rb_req"]).await;
    let (pid, task) = spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    refused(finished(task).await, "NotApprovable(Revoked)");
    assert_eq!(operation(&pool, "op_c").await.outcome, "cancelled");

    // The cancel first, rolled back: the approval applies.
    let op = pending(&pool, "key_req", "op_r", 2, false).await;
    let prepared = prepare(&pool, "key_sec1", "op_r").await.unwrap();
    let mut held = holder.begin().await.unwrap();
    revoke_in(
        &mut held,
        Revocation::Cancel,
        "key_req",
        INSTANCE,
        "op_r",
        at(7),
    )
    .await
    .unwrap();
    let (pid, task) = spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.rollback().await.unwrap();
    finished(task).await.unwrap();
    holder.close().await.unwrap();
    assert_eq!(operation(&pool, "op_r").await.outcome, "applied");
    assert!(!policy(&pool).await.widening_second_approver);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Two writes of the policy row serialize on it without a deadlock: the
/// approval of a second operation at the same revision waits for the first
/// approval and is stale after it commits; so is a second single-actor
/// toggle, which applies when the first rolls back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn policy_writes_serialize_on_the_policy_row() {
    let (db, pool) = seeded().await;
    let clock = TestClock::new(at(10));
    let op_a = pending(&pool, "key_req", "op_a", 1, true).await;
    let op_b = pending(&pool, "key_req", "op_b", 1, true).await;
    let prepared_a = prepare(&pool, "key_sec1", "op_a").await.unwrap();
    let prepared_b = prepare(&pool, "key_sec2", "op_b").await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    approve_in(
        &mut held,
        "key_sec1",
        INSTANCE,
        &prepared_a,
        &echo(&op_a),
        &*clock,
    )
    .await
    .unwrap();
    let (pid, task) =
        spawn_approve(&pool, "key_sec2", prepared_b, echo(&op_b), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    refused(finished(task).await, "StaleRevision");
    let row_b = operation(&pool, "op_b").await;
    assert_eq!((row_b.consumed_at, row_b.revoked_at), (None, None));
    assert_eq!(policy(&pool).await.revision, 2);

    single_actor_mode(&pool).await;
    for commit in [true, false] {
        let revision = policy(&pool).await.revision;
        let mut held = holder.begin().await.unwrap();
        let first = format!("op_first_{commit}");
        request_in(&mut held, "key_req", &first, revision, false, at(0))
            .await
            .unwrap();
        let second = if commit {
            "op_second_true"
        } else {
            "op_second_false"
        };
        let (pid, task) = spawn_request(&pool, second, revision, false).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        if commit {
            held.commit().await.unwrap();
            refused(finished(task).await, "StaleRevision");
        } else {
            held.rollback().await.unwrap();
            assert!(matches!(finished(task).await.unwrap(), Gated::Applied(_)));
        }
        assert_eq!(policy(&pool).await.revision, revision + 1);
    }
    holder.close().await.unwrap();
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Policy writes queued behind a trust write's `FOR SHARE` on the policy
/// row complete without a deadlock (`40P01`): the first takes the row
/// `FOR NO KEY UPDATE` and applies, the second waits for it and is stale.
/// Had they taken the row `FOR SHARE` before their compare-and-set, both
/// would hold it with the trust write, and each compare-and-set would wait
/// for the other's lock once the trust write ends. A trust write that
/// waits for an approval reads the row the approval wrote.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn policy_writes_behind_a_trust_write_do_not_deadlock() {
    let (db, pool) = seeded().await;
    let (mut holder, holder_pid) = connection(&pool).await;

    // Two approvals behind a trust write.
    let op_a = pending(&pool, "key_req", "op_a", 1, true).await;
    let op_b = pending(&pool, "key_req", "op_b", 1, false).await;
    let prepared_a = prepare(&pool, "key_sec1", "op_a").await.unwrap();
    let prepared_b = prepare(&pool, "key_sec2", "op_b").await.unwrap();
    let (clock_a, clock_b) = (TestClock::new(at(10)), TestClock::new(at(11)));
    let mut held = holder.begin().await.unwrap();
    lock_instance_security_policy_shared(&mut held)
        .await
        .unwrap();
    let (pid_a, task_a) =
        spawn_approve(&pool, "key_sec1", prepared_a, echo(&op_a), clock_a.clone()).await;
    wait_until_blocked(&pool, pid_a, holder_pid, &task_a).await;
    let (pid_b, task_b) =
        spawn_approve(&pool, "key_sec2", prepared_b, echo(&op_b), clock_b.clone()).await;
    wait_until_blocked_by_any(&pool, pid_b, &[holder_pid, pid_a], &task_b).await;
    held.commit().await.unwrap();
    // Neither is a Registry(Retry { sqlstate: Some("40P01") }).
    finished(task_a).await.unwrap();
    refused(finished(task_b).await, "StaleRevision");
    assert_eq!((clock_a.samples(), clock_b.samples()), (1, 0));
    assert_eq!(operation(&pool, "op_a").await.outcome, "applied");
    let row_b = operation(&pool, "op_b").await;
    assert_eq!(
        (row_b.outcome.as_str(), row_b.consumed_at, row_b.revoked_at),
        ("pending", None, None)
    );
    let after = policy(&pool).await;
    assert_eq!((after.revision, after.widening_second_approver), (2, true));

    // A trust write waits for an approval and reads what it wrote.
    let op_c = pending(&pool, "key_req", "op_c", 2, false).await;
    let prepared_c = prepare(&pool, "key_sec1", "op_c").await.unwrap();
    let mut held = holder.begin().await.unwrap();
    approve_in(
        &mut held,
        "key_sec1",
        INSTANCE,
        &prepared_c,
        &echo(&op_c),
        &*TestClock::new(at(12)),
    )
    .await
    .unwrap();
    let (mut writer, writer_pid) = connection(&pool).await;
    let task = tokio::spawn(async move {
        let mut writing = writer.begin().await.unwrap();
        let read = lock_instance_security_policy_shared(&mut writing).await;
        writing.commit().await.unwrap();
        writer.close().await.unwrap();
        read
    });
    wait_until_blocked(&pool, writer_pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    let read = finished(task).await.unwrap();
    assert_eq!((read.revision, read.widening_second_approver), (3, false));

    // Two single-actor toggles behind a trust write.
    single_actor_mode(&pool).await;
    let revision = policy(&pool).await.revision;
    let mut held = holder.begin().await.unwrap();
    lock_instance_security_policy_shared(&mut held)
        .await
        .unwrap();
    let (pid_1, task_1) = spawn_request(&pool, "op_t1", revision, true).await;
    wait_until_blocked(&pool, pid_1, holder_pid, &task_1).await;
    let (pid_2, task_2) = spawn_request(&pool, "op_t2", revision, true).await;
    wait_until_blocked_by_any(&pool, pid_2, &[holder_pid, pid_1], &task_2).await;
    held.commit().await.unwrap();
    assert!(matches!(finished(task_1).await.unwrap(), Gated::Applied(_)));
    refused(finished(task_2).await, "StaleRevision");
    holder.close().await.unwrap();
    let after = policy(&pool).await;
    assert_eq!(
        (after.revision, after.widening_second_approver),
        (revision + 1, true)
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}
