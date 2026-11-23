//! The keyset kinds of the second-approver flow
//! (`docs/proposals/second-approver-gated-writes.md`, PR 4) on a real
//! database: `submit_create_version` and `submit_enable_version` through
//! the gate (the flag, the policy row, the mode and its audit outcome), the
//! pending operation and its plan, the approval that reruns the write under
//! the locks with its one clock sample (D28), the projection compared with
//! the locked plan (D24, D25), the tenant path's cancel, and races between
//! two connections.
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
        Arc, LazyLock, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use serde_json::{Value, json};
use skyoauth_service::{
    jwk::{Algorithm, DEFAULT_ALLOWED_ALGORITHMS, ValidatedKeyset},
    operation::{
        Applied, ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, DigestEnvelope,
        Gated, OperationKind, PendingOperation, PreparedApproval, RevokeIds, Submission,
        approve_operation, cancel_operation, prepare_approval, reject_operation,
    },
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AdminRoleBindingChanges, AdministrativeOperation, AuditActor,
            BootstrapRequest, ChainVerdict, JsonObject, NewAdminCredential, NewAdminIdentity,
            NewAdminRoleBinding, NewAdministrativeOperation, NewAuditEvent, NewTenant,
            NewTrustKeyset, NewTrustKeysetVersion, Status, TrustKeysetVersion, append_audit_event,
            bootstrap_instance, insert_administrative_operation, lock_administrative_operation,
            verify_audit_chain,
        },
    },
    trust::{
        KeysetAudit, KeysetWriteError, NewKeysetVersion, create_version, disable_version,
        submit_create_version, submit_enable_version, validate_upload,
    },
};
use sqlx::{AssertSqlSafe, Connection, PgConnection, Postgres, Transaction};
use tokio::task::JoinHandle;

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;
/// [`skyoauth_service::operation::PENDING_OPERATION_TTL`] in microseconds.
const DAY: u64 = 86_400_000_000;
const CREATE: &str = "trust_keyset_version_create";
const ENABLE: &str = "trust_keyset_version_enable";
const INSTANCE: ApprovalScope<'static> = ApprovalScope::Instance;
const TEN_A: ApprovalScope<'static> = ApprovalScope::Tenant("ten_a");
const TEN_B: ApprovalScope<'static> = ApprovalScope::Tenant("ten_b");
const SEC: AdminRole = AdminRole::SecurityAdmin;
const TRUST: AdminRole = AdminRole::TrustAdmin;
const ALLOWED: &[Algorithm] = DEFAULT_ALLOWED_ALGORITHMS;

// The RFC 7517 appendix A.1 P-256 key and a generated P-256 key (see
// `service/tests/trust_keyset_version.rs`).
const A_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const A_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
const B_X: &str = "60KU-t7I0SkALarT8sfRB5iNa5QkWCUlbefzbW7OlQw";
const B_Y: &str = "AB530pP2cpYhadpS5FNwg9m8w4UgWFlJJkxIxFl_MPk";

static PROVENANCE: LazyLock<JsonObject> =
    LazyLock::new(|| object(json!({"supplied_by": "operator", "n": 1.5, "via": ["upload"]})));

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

fn micros(micros: u64) -> i64 {
    i64::try_from(T0 + micros).unwrap()
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
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

/// The key A or B as a one-key set with `kid`; key A carries `use`, a
/// member outside the projection.
fn key_a(kid: &str) -> Value {
    json!({"keys": [{"kty": "EC", "kid": kid, "crv": "P-256", "x": A_X, "y": A_Y, "use": "sig"}]})
}

fn key_b(kid: &str) -> Value {
    json!({"keys": [{"kty": "EC", "kid": kid, "crv": "P-256", "x": B_X, "y": B_Y}]})
}

async fn upload(keys: Value) -> ValidatedKeyset {
    validate_upload(keys, ALLOWED).await.unwrap()
}

/// A version of `keyset` in `ten_a`, open-ended from `at(0)`.
fn version<'a>(
    id: &'a str,
    keyset: &'a str,
    keys: &'a ValidatedKeyset,
    status: Status,
) -> NewKeysetVersion<'a> {
    NewKeysetVersion {
        id,
        tenant_id: "ten_a",
        keyset_id: keyset,
        keys,
        effective_at: at(0),
        expires_at: None,
        status,
        provenance: &PROVENANCE,
    }
}

/// [`version`] in `[at(n s), at((n + 1) s))`, so no two such windows
/// intersect.
fn slot<'a>(
    id: &'a str,
    keyset: &'a str,
    keys: &'a ValidatedKeyset,
    status: Status,
    n: u64,
) -> NewKeysetVersion<'a> {
    NewKeysetVersion {
        effective_at: at(n * 1_000_000),
        expires_at: Some(at((n + 1) * 1_000_000)),
        ..version(id, keyset, keys, status)
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

async fn operator(
    pool: &PgPool,
    admin: &str,
    key: &str,
    bindings: &[(&str, AdminRole, Option<&str>)],
) {
    registry::create_admin_identity(
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
        registry::create_admin_role_binding(
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
    registry::create_admin_credential(
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

/// The tenants `ten_a` (keysets `ks_1`, `ks_2`) and `ten_b` (keyset
/// `ks_b`), and these operators, all enabled, each with a credential
/// `crd_<admin>`:
///
/// - `adm_trust` (`key_trust`), `trust_admin` of `ten_a`: the requester;
/// - `adm_other` (`key_other`), `trust_admin` of `ten_a` too;
/// - `adm_both` (`key_both`), `trust_admin` of `ten_a` and instance
///   `security_admin` (`rb_both_sec`);
/// - `adm_sec1` (`key_sec1`) and `adm_sec2` (`key_sec2`), instance
///   `security_admin`: the approvers;
/// - `adm_tb` (`key_tb`), `trust_admin` of `ten_b`.
///
/// With `bootstrap`, the instance is bootstrapped first (`adm_first`, the
/// policy row at revision 1 with both flags off).
async fn seeded_with(bootstrap: bool) -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    if bootstrap {
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
                recovery_public_key: &[0x11; 32],
                audit_event_id: "aud_bootstrap",
                now: at(0),
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    for (id, ns) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::create_tenant(
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
    for (id, tenant_id) in [("ks_1", "ten_a"), ("ks_2", "ten_a"), ("ks_b", "ten_b")] {
        registry::create_trust_keyset(
            &pool,
            &NewTrustKeyset {
                id: id.into(),
                tenant_id: tenant_id.into(),
                name: format!("keyset-{id}"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    let ten_a = Some("ten_a");
    operator(
        &pool,
        "adm_trust",
        "key_trust",
        &[("rb_trust", TRUST, ten_a)],
    )
    .await;
    operator(
        &pool,
        "adm_other",
        "key_other",
        &[("rb_other", TRUST, ten_a)],
    )
    .await;
    operator(
        &pool,
        "adm_both",
        "key_both",
        &[("rb_both_trust", TRUST, ten_a), ("rb_both_sec", SEC, None)],
    )
    .await;
    operator(&pool, "adm_sec1", "key_sec1", &[("rb_sec1", SEC, None)]).await;
    operator(&pool, "adm_sec2", "key_sec2", &[("rb_sec2", SEC, None)]).await;
    operator(
        &pool,
        "adm_tb",
        "key_tb",
        &[("rb_tb", TRUST, Some("ten_b"))],
    )
    .await;
    (db, pool)
}

async fn seeded() -> (TestDb, PgPool) {
    seeded_with(true).await
}

/// Sets both flags of the policy row (its revision advances).
async fn set_policy(pool: &PgPool, widening_second_approver: bool, single_actor_mode: bool) {
    sqlx::query(
        "UPDATE instance_security_policy SET widening_second_approver = $1, \
         single_actor_mode = $2, revision = revision + 1",
    )
    .bind(widening_second_approver)
    .bind(single_actor_mode)
    .execute(pool)
    .await
    .unwrap();
}

#[track_caller]
fn refused<T: Debug, E: Debug>(result: Result<T, E>, expected: &str) {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => assert_eq!(format!("{err:?}"), expected),
    }
}

fn submission<'a>(key: &'a str, op: &'a str, event_id: &'a str, ack: bool) -> Submission<'a> {
    Submission {
        public_identity: key,
        acknowledge_widening: ack,
        operation_id: op,
        event_id,
        now: at(0),
    }
}

/// [`submit_create_version`] of `new` by `key` as the operation `op`
/// (event `evt_<op>`), in a transaction committed either way.
async fn submit_create(
    pool: &PgPool,
    key: &str,
    op: &str,
    ack: bool,
    new: &NewKeysetVersion<'_>,
    allowed: &[Algorithm],
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError> {
    let event_id = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let result = submit_create_version(
        &mut transaction,
        &submission(key, op, &event_id, ack),
        new,
        allowed,
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

/// [`submit_enable_version`] of the `ten_a` version `id` at `revision`, as
/// [`submit_create`].
async fn submit_enable(
    pool: &PgPool,
    key: &str,
    op: &str,
    ack: bool,
    id: &str,
    revision: i64,
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError> {
    let event_id = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let result = submit_enable_version(
        &mut transaction,
        &submission(key, op, &event_id, ack),
        "ten_a",
        id,
        revision,
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

#[track_caller]
fn pending(result: Result<Gated<TrustKeysetVersion>, KeysetWriteError>) -> PendingOperation {
    match result {
        Ok(Gated::Pending(pending)) => pending,
        other => panic!("not pending: {other:?}"),
    }
}

#[track_caller]
fn applied(result: Result<Gated<TrustKeysetVersion>, KeysetWriteError>) -> TrustKeysetVersion {
    match result {
        Ok(Gated::Applied(version)) => version,
        other => panic!("not applied: {other:?}"),
    }
}

/// An ungated write's audit input.
fn audit(event_id: &str) -> KeysetAudit<'_> {
    KeysetAudit {
        event_id,
        now: at(0),
    }
}

/// The ungated create of `new` by `adm_trust`, committed.
async fn direct_create(pool: &PgPool, new: &NewKeysetVersion<'_>) -> TrustKeysetVersion {
    let event_id = format!("evt_direct_{}", new.id);
    let mut transaction = pool.begin().await.unwrap();
    let version = create_version(&mut transaction, "key_trust", new, &audit(&event_id))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    version
}

/// The ungated disable of the `ten_a` version `id` at `revision`,
/// committed.
async fn direct_disable(pool: &PgPool, id: &str, revision: i64) -> TrustKeysetVersion {
    let event_id = format!("evt_disable_{id}_{revision}");
    let mut transaction = pool.begin().await.unwrap();
    let version = disable_version(
        &mut transaction,
        "key_trust",
        "ten_a",
        id,
        revision,
        &audit(&event_id),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    version
}

fn echo(pending: &PendingOperation) -> ApprovalEcho {
    ApprovalEcho {
        request_digest: pending.request_digest,
        expected_revision: pending.expected_revision,
    }
}

/// [`prepare_approval`] on the `ten_a` path at `at(1)` with [`ALLOWED`].
async fn prepare(pool: &PgPool, key: &str, op: &str) -> Result<PreparedApproval, ApprovalError> {
    prepare_approval(pool, key, TEN_A, op, ALLOWED, at(1)).await
}

async fn approve_in(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
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
        TEN_A,
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

/// [`approve_in`] on the `ten_a` path, in a transaction committed either
/// way.
async fn approve(
    pool: &PgPool,
    key: &str,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    clock: &dyn Clock,
) -> Result<Applied, ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = approve_in(&mut transaction, key, prepared, echo, clock).await;
    transaction.commit().await.unwrap();
    result
}

#[track_caller]
fn applied_version(result: Result<Applied, ApprovalError>) -> TrustKeysetVersion {
    match result {
        Ok(Applied::KeysetVersion(version)) => version,
        other => panic!("not a keyset version: {other:?}"),
    }
}

async fn revoke_in(
    transaction: &mut Transaction<'_, Postgres>,
    cancel: bool,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
) -> Result<(), ApprovalError> {
    let name = if cancel { "cancel" } else { "reject" };
    let revoking_operation_id = format!("{name}_{op}_{key}");
    let event_id = format!("evt_{name}_{op}_{key}");
    let ids = RevokeIds {
        revoking_operation_id: &revoking_operation_id,
        event_id: &event_id,
    };
    if cancel {
        cancel_operation(transaction, key, scope, op, &ids, at(7)).await
    } else {
        reject_operation(transaction, key, scope, op, &ids, at(7)).await
    }
}

async fn revoke(
    pool: &PgPool,
    cancel: bool,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
) -> Result<(), ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = revoke_in(&mut transaction, cancel, key, scope, op).await;
    transaction.commit().await.unwrap();
    result
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
    at: u64,
) -> Event {
    (
        id.into(),
        Some("ten_a".into()),
        AuditActor::Operator(actor.into()).canonical_json(),
        action.into(),
        object_id.into(),
        previous_revision,
        new_revision,
        outcome.into(),
        micros(at),
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

/// The outcome of the last event.
async fn last_outcome(pool: &PgPool) -> String {
    events(pool).await.pop().unwrap().7
}

async fn assert_chain_intact(pool: &PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    assert!(matches!(
        verify_audit_chain(&mut connection).await.unwrap(),
        ChainVerdict::Intact { .. }
    ));
}

/// Every row a keyset or operation call may write, as text.
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let mut rows = Vec::new();
    for table in [
        "instance_security_policy",
        "administrative_operation",
        "audit_event",
        "audit_chain_head",
        "trust_keyset",
        "trust_keyset_version",
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

async fn version_row(pool: &PgPool, id: &str) -> Option<(String, i64)> {
    sqlx::query_as("SELECT status, revision FROM trust_keyset_version WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap()
}

/// The plan a create request stores for `new` by `adm_trust`.
fn create_plan(new: &NewKeysetVersion<'_>, allowed: &[&str]) -> JsonObject {
    object(json!({
        "requester_credential_id": "crd_adm_trust",
        "version_id": new.id,
        "keyset_id": new.keyset_id,
        "public_jwks": new.keys.public_json(),
        "fingerprint": new.keys.fingerprint().as_str(),
        "allowed_algorithms": allowed,
        "effective_at_us": micros(0),
        "expires_at_us": null,
        "status": new.status.as_str(),
        "provenance": Value::Object(PROVENANCE.clone()).to_string(),
    }))
}

/// A pending keyset operation `id` of `kind` by `adm_trust` in `ten_a`
/// requested at `at(0)`, with `plan` and the digest of `digest_plan` (of
/// `plan` itself when `None`).
fn raw(
    id: &str,
    kind: &str,
    expected_revision: i64,
    plan: JsonObject,
    digest_plan: Option<&JsonObject>,
) -> NewAdministrativeOperation {
    let digest = DigestEnvelope {
        id,
        tenant_id: Some("ten_a"),
        actor_id: "adm_trust",
        kind,
        expected_revision,
        expires_at_us: micros(DAY),
        plan: digest_plan.unwrap_or(&plan),
    }
    .digest()
    .unwrap();
    NewAdministrativeOperation {
        id: id.into(),
        tenant_id: Some("ten_a".into()),
        actor_id: "adm_trust".into(),
        kind: kind.into(),
        request_digest: digest.as_bytes().to_vec(),
        expected_revision,
        immutable_plan: plan,
        expires_at: Some(expiry()),
        approves_operation_id: None,
        outcome: "pending".into(),
        audit_id: format!("evt_{id}"),
    }
}

/// Appends the operation's `administrative_operation.create` event and
/// inserts it, committed; returns its echo.
async fn insert_raw(pool: &PgPool, new: &NewAdministrativeOperation) -> ApprovalEcho {
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
    ApprovalEcho {
        request_digest: new.request_digest[..].try_into().unwrap(),
        expected_revision: new.expected_revision,
    }
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

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// A detached connection and its backend PID.
async fn connection(pool: &PgPool) -> (PgConnection, i32) {
    let mut connection = pool.acquire().await.unwrap().detach();
    let pid = backend_pid(&mut connection).await;
    (connection, pid)
}

/// Waits until the backend `blocked`, which runs `task`, waits for a lock
/// held by `holder`. Fails at once if `task` finished without waiting.
async fn wait_until_blocked<T>(pool: &PgPool, blocked: i32, holder: i32, task: &JoinHandle<T>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT $1 = ANY (pg_blocking_pids($2))")
                .bind(holder)
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
        let result = approve_in(&mut transaction, key, &prepared, &echo, &*clock).await;
        transaction.commit().await.unwrap();
        connection.close().await.unwrap();
        result
    });
    (pid, task)
}

/// A gated create is a pending operation until a distinct
/// `security_admin` approves it: the request writes its
/// `administrative_operation.create` event and the operation, whose plan
/// holds the projection and fingerprint, never the raw upload; no version.
/// The approval writes the approve event, the approve operation in the
/// target's tenant, the version and its event at the one clock sample, and
/// consumes the operation.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_gated_create_is_pending_until_a_second_approver_applies_it() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let keys = upload(key_a("k1")).await;
    let new = version("ver_1", "ks_1", &keys, Status::Enabled);
    let before = snapshot(&pool).await;
    refused(
        submit_create(&pool, "key_trust", "op_1", false, &new, ALLOWED).await,
        "WideningNotAcknowledged",
    );
    assert_eq!(snapshot(&pool).await, before);

    let op = pending(submit_create(&pool, "key_trust", "op_1", true, &new, ALLOWED).await);
    assert_eq!(op.id, "op_1");
    assert_eq!(op.kind, OperationKind::TrustKeysetVersionCreate);
    assert_eq!((op.expected_revision, op.expires_at), (0, expiry()));
    assert_eq!(version_row(&pool, "ver_1").await, None);
    let stored_op = operation(&pool, "op_1").await;
    // The allowed set by name, sorted.
    let mut allowed: Vec<&str> = ALLOWED.iter().map(|alg| alg.name()).collect();
    allowed.sort_unstable();
    allowed.dedup();
    assert_eq!(stored_op.immutable_plan, create_plan(&new, &allowed));
    assert!(
        !stored_op.immutable_plan["public_jwks"]
            .as_str()
            .unwrap()
            .contains("use")
    );
    assert_eq!(
        (
            stored_op.tenant_id.as_deref(),
            stored_op.actor_id.as_str(),
            stored_op.kind.as_str(),
            stored_op.outcome.as_str(),
        ),
        (Some("ten_a"), "adm_trust", CREATE, "pending")
    );
    let digest = DigestEnvelope {
        id: "op_1",
        tenant_id: Some("ten_a"),
        actor_id: "adm_trust",
        kind: CREATE,
        expected_revision: 0,
        expires_at_us: micros(DAY),
        plan: &stored_op.immutable_plan,
    }
    .digest()
    .unwrap();
    assert_eq!(digest, op.request_digest);
    assert_eq!(stored_op.request_digest, digest.as_bytes());

    // Only an instance `security_admin` other than the requester, on the
    // operation's tenant path.
    for scope in [INSTANCE, TEN_B] {
        refused(
            prepare_approval(&pool, "key_sec1", scope, "op_1", ALLOWED, at(1)).await,
            "NotFound",
        );
    }
    for key in ["key_trust", "key_other"] {
        refused(prepare(&pool, key, "op_1").await, "Unauthorized");
    }
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    assert_eq!(prepared.kind(), OperationKind::TrustKeysetVersionCreate);
    let clock = TestClock::new(at(10));
    let row = applied_version(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!(clock.samples(), 1);
    assert_eq!(
        (
            row.id.as_str(),
            row.tenant_id.as_str(),
            row.keyset_id.as_str(),
            row.fingerprint.as_str(),
            row.effective_at,
            row.expires_at,
            row.status,
            row.revision,
        ),
        (
            "ver_1",
            "ten_a",
            "ks_1",
            keys.fingerprint().as_str(),
            stored(0),
            None,
            Status::Enabled,
            1
        )
    );
    assert_eq!(row.provenance, *PROVENANCE);
    assert_eq!(
        events(&pool).await,
        [
            event(
                "evt_op_1",
                "adm_trust",
                "administrative_operation.create",
                "op_1",
                None,
                Some(1),
                "success",
                0
            ),
            event(
                "evt_appr_op_1_key_sec1",
                "adm_sec1",
                "administrative_operation.approve",
                "op_1",
                Some(1),
                Some(2),
                "success",
                10
            ),
            event(
                "evt_write_op_1_key_sec1",
                "adm_trust",
                "trust_keyset_version.create",
                "ver_1",
                None,
                Some(1),
                "success",
                10
            ),
        ]
    );
    let consumed = operation(&pool, "op_1").await;
    assert_eq!(
        (
            consumed.consumed_at,
            consumed.outcome.as_str(),
            consumed.revision
        ),
        (Some(stored(10)), "applied", 2)
    );
    // The approve operation is in the target's tenant (the 0005 guard
    // requires it of an approval).
    let approval = operation(&pool, "appr_op_1_key_sec1").await;
    assert_eq!(
        (
            approval.tenant_id.as_deref(),
            approval.actor_id.as_str(),
            approval.kind.as_str(),
            approval.approves_operation_id.as_deref(),
            approval.request_digest.as_slice(),
            approval.expected_revision,
            approval.outcome.as_str(),
        ),
        (
            Some("ten_a"),
            "adm_sec1",
            "approve",
            Some("op_1"),
            digest.as_bytes().as_slice(),
            0,
            "success"
        )
    );
    // Approved once.
    refused(
        prepare(&pool, "key_sec2", "op_1").await,
        "NotApprovable(Consumed)",
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// A gated enable, a re-enable of an enabled version included, is pending
/// with a plan of the version, its keyset and its stored fingerprint, and
/// its approval runs the enable at the operation's expected revision; a
/// disable of the target meanwhile makes it stale, and nothing is written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_gated_enable_and_re_enable_are_pending_until_approved() {
    let (db, pool) = seeded().await;
    let keys = upload(key_a("k1")).await;
    direct_create(&pool, &version("ver_1", "ks_1", &keys, Status::Disabled)).await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));
    for (n, revision) in [(1, 1), (2, 2)] {
        let op_id = format!("op_{n}");
        let op = pending(submit_enable(&pool, "key_trust", &op_id, true, "ver_1", revision).await);
        assert_eq!(
            (op.kind, op.expected_revision),
            (OperationKind::TrustKeysetVersionEnable, revision)
        );
        let stored_op = operation(&pool, &op_id).await;
        assert_eq!(
            stored_op.immutable_plan,
            object(json!({
                "requester_credential_id": "crd_adm_trust",
                "version_id": "ver_1",
                "keyset_id": "ks_1",
                "fingerprint": keys.fingerprint().as_str(),
            }))
        );
        assert_eq!(
            (stored_op.kind.as_str(), stored_op.expected_revision),
            (ENABLE, revision)
        );
        // Not written until approved.
        assert_eq!(
            version_row(&pool, "ver_1").await.unwrap().1,
            revision,
            "{op_id}"
        );
        let prepared = prepare(&pool, "key_sec1", &op_id).await.unwrap();
        let row = applied_version(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
        assert_eq!((row.status, row.revision), (Status::Enabled, revision + 1));
        let last = events(&pool).await.pop().unwrap();
        assert_eq!(
            last,
            event(
                &format!("evt_write_{op_id}_key_sec1"),
                "adm_trust",
                "trust_keyset_version.enable",
                "ver_1",
                Some(revision),
                Some(revision + 1),
                "success",
                10
            )
        );
    }
    // A disable of the target meanwhile: the approval is stale.
    let op = pending(submit_enable(&pool, "key_trust", "op_3", true, "ver_1", 3).await);
    let prepared = prepare(&pool, "key_sec1", "op_3").await.unwrap();
    direct_disable(&pool, "ver_1", 3).await;
    let before = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "Keyset(Registry(StaleRevision))",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(operation(&pool, "op_3").await.outcome, "pending");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The mode follows the policy row and the requester's roles (section 1),
/// for every keyset kind, a disabled create included (Q3): without the flag
/// every write is refused; with it, `widening_second_approver` off applies
/// it at once with outcome `success_widening` whatever `single_actor_mode`
/// is (D23); on, `single_actor_mode` on and a requester who also holds
/// instance `security_admin` apply it with `success_single_actor` (Q4);
/// otherwise it goes pending and writes no version.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_mode_follows_the_policy_and_the_requesters_roles() {
    let (db, pool) = seeded().await;
    let keys = upload(key_a("k1")).await;
    let mut n = 0;
    for (widening, single_actor) in [(false, false), (false, true), (true, false), (true, true)] {
        set_policy(&pool, widening, single_actor).await;
        for key in ["key_trust", "key_both"] {
            let expected = if !widening {
                Some("success_widening")
            } else if single_actor && key == "key_both" {
                Some("success_single_actor")
            } else {
                None
            };
            for kind in ["create_enabled", "create_disabled", "enable"] {
                n += 1;
                let id = format!("ver_{n}");
                let op = format!("op_{n}");
                let case = format!("{widening} {single_actor} {key} {kind}");
                let before = snapshot(&pool).await;
                let result = |ack| {
                    let (pool, id, op, keys) = (&pool, &id, &op, &keys);
                    async move {
                        match kind {
                            "enable" => submit_enable(pool, key, op, ack, id, 1).await,
                            _ => {
                                let status = if kind == "create_enabled" {
                                    Status::Enabled
                                } else {
                                    Status::Disabled
                                };
                                let new = slot(id, "ks_1", keys, status, n);
                                submit_create(pool, key, op, ack, &new, ALLOWED).await
                            }
                        }
                    }
                };
                if kind == "enable" {
                    // The target: a disabled version of `ks_2`, so no more
                    // than eight versions of one keyset are ever enabled.
                    let new = slot(&id, "ks_2", &keys, Status::Disabled, n);
                    direct_create(&pool, &new).await;
                }
                let before_flag = snapshot(&pool).await;
                refused(result(false).await, "WideningNotAcknowledged");
                assert_eq!(snapshot(&pool).await, before_flag, "{case}");
                let outcome = result(true).await;
                match expected {
                    Some(expected) => {
                        let row = applied(outcome);
                        assert_eq!(row.id, id, "{case}");
                        let status = if kind == "create_disabled" {
                            Status::Disabled
                        } else {
                            Status::Enabled
                        };
                        assert_eq!(row.status, status, "{case}");
                        let last = events(&pool).await.pop().unwrap();
                        // The request's event at the request's `now`.
                        assert_eq!(
                            (last.0.as_str(), last.7.as_str(), last.8),
                            (format!("evt_{op}").as_str(), expected, micros(0)),
                            "{case}"
                        );
                    }
                    None => {
                        let pending = pending(outcome);
                        assert_eq!(pending.id, op, "{case}");
                        assert_eq!(last_outcome(&pool).await, "success", "{case}");
                        if kind != "enable" {
                            assert_eq!(version_row(&pool, &id).await, None, "{case}");
                        } else {
                            assert_eq!(
                                version_row(&pool, &id).await,
                                Some(("disabled".into(), 1)),
                                "{case}"
                            );
                        }
                    }
                }
                drop(before);
            }
        }
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Only a `trust_admin` of the version's tenant requests: an instance
/// `security_admin` without that role is refused although the role lookup
/// finds one of its two roles (`holds(0)`), with `single_actor_mode` on
/// too, and learns nothing of the keyset or the version; and the
/// requester's identity and credential must be enabled and unrevoked. While a request runs, its operator rows (the instance
/// binding included) and the policy row are held `FOR SHARE`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn only_a_trust_admin_of_the_tenant_requests() {
    let (db, pool) = seeded().await;
    let keys = upload(key_a("k1")).await;
    direct_create(&pool, &version("ver_0", "ks_1", &keys, Status::Disabled)).await;
    let new = version("ver_1", "ks_1", &keys, Status::Disabled);
    for (widening, single_actor) in [(true, false), (true, true), (false, false)] {
        set_policy(&pool, widening, single_actor).await;
        let before = snapshot(&pool).await;
        for key in ["key_sec1", "key_tb", "spki-sha256:unknown"] {
            refused(
                submit_create(&pool, key, "op_x", true, &new, ALLOWED).await,
                "Unauthorized",
            );
            refused(
                submit_enable(&pool, key, "op_x", true, "ver_0", 1).await,
                "Unauthorized",
            );
            // Before the flag.
            refused(
                submit_create(&pool, key, "op_x", false, &new, ALLOWED).await,
                "Unauthorized",
            );
            // Nothing about the keyset or the version: a missing one is
            // refused the same way.
            let missing = version("ver_1", "ks_none", &keys, Status::Disabled);
            refused(
                submit_create(&pool, key, "op_x", true, &missing, ALLOWED).await,
                "Unauthorized",
            );
            refused(
                submit_enable(&pool, key, "op_x", true, "ver_none", 1).await,
                "Unauthorized",
            );
        }
        assert_eq!(snapshot(&pool).await, before);
    }
    set_policy(&pool, true, false).await;
    credential(&pool, "crd_adm_other_b", "adm_other", "key_other_b").await;
    sqlx::query("UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_other'")
        .execute(&pool)
        .await
        .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_other_b", at(2))
        .await
        .unwrap();
    registry::disable_admin_identity(&pool, "adm_both")
        .await
        .unwrap();
    let before = snapshot(&pool).await;
    for key in ["key_other", "key_other_b", "key_both"] {
        refused(
            submit_create(&pool, key, "op_x", true, &new, ALLOWED).await,
            "Unauthorized",
        );
    }
    assert_eq!(snapshot(&pool).await, before);

    // The locks of a request, held until its transaction ends.
    let mut tx = pool.begin().await.unwrap();
    let event_id = "evt_op_1";
    let held = submit_create_version(
        &mut tx,
        &submission("key_trust", "op_1", event_id, true),
        &new,
        ALLOWED,
    )
    .await;
    assert!(matches!(held, Ok(Gated::Pending(_))), "{held:?}");
    for (table, id) in [
        ("admin_identity", "adm_trust"),
        ("admin_credential", "crd_adm_trust"),
        ("admin_role_binding", "rb_trust"),
    ] {
        assert!(
            conflicts(&pool, table, "id", id, "FOR UPDATE").await,
            "{id}"
        );
        assert!(
            !conflicts(&pool, table, "id", id, "FOR SHARE").await,
            "{id}"
        );
    }
    for strength in ["FOR NO KEY UPDATE", "FOR SHARE"] {
        assert_eq!(
            conflicts(
                &pool,
                "instance_security_policy",
                "instance_id",
                INSTANCE_ID,
                strength
            )
            .await,
            strength == "FOR NO KEY UPDATE",
            "{strength}"
        );
    }
    tx.rollback().await.unwrap();
    db.drop([pool]).await;
}

/// The requester's instance `security_admin` binding is locked with its
/// `trust_admin` binding (Q4), so a single-actor write cannot run while the
/// binding is being disabled.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_requesters_instance_binding_is_held_for_share() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, true).await;
    let keys = upload(key_a("k1")).await;
    let new = version("ver_1", "ks_1", &keys, Status::Disabled);
    let mut tx = pool.begin().await.unwrap();
    let result = submit_create_version(
        &mut tx,
        &submission("key_both", "op_1", "evt_op_1", true),
        &new,
        ALLOWED,
    )
    .await;
    assert!(matches!(result, Ok(Gated::Applied(_))), "{result:?}");
    for id in ["rb_both_trust", "rb_both_sec"] {
        assert!(
            conflicts(&pool, "admin_role_binding", "id", id, "FOR UPDATE").await,
            "{id}"
        );
    }
    tx.rollback().await.unwrap();
    db.drop([pool]).await;
}

/// The gate's refusals come in the request's order: the isolation, the
/// requester, the flag, then the policy row (missing before bootstrap:
/// `PolicyUnavailable`, D18); each writes nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_gates_refusals_come_in_order() {
    let (db, pool) = seeded_with(false).await;
    let keys = upload(key_a("k1")).await;
    let new = version("ver_1", "ks_1", &keys, Status::Disabled);
    let before = snapshot(&pool).await;
    refused(
        submit_create(&pool, "key_sec1", "op_1", false, &new, ALLOWED).await,
        "Unauthorized",
    );
    refused(
        submit_create(&pool, "key_trust", "op_1", false, &new, ALLOWED).await,
        "WideningNotAcknowledged",
    );
    refused(
        submit_create(&pool, "key_trust", "op_1", true, &new, ALLOWED).await,
        "PolicyUnavailable",
    );
    refused(
        submit_enable(&pool, "key_trust", "op_1", true, "ver_1", 1).await,
        "PolicyUnavailable",
    );
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .unwrap();
    let result = submit_create_version(
        &mut tx,
        &submission("key_sec1", "op_1", "evt_op_1", false),
        &new,
        ALLOWED,
    )
    .await;
    refused(result, "UnsupportedIsolation");
    tx.commit().await.unwrap();
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A pending request runs every check of the direct write (D7): the
/// provenance, an empty version ID (D27), a key outside the allowed set,
/// the keyset and the target, the revision, the cap and the overlap; each
/// refusal writes nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_pending_request_runs_the_writes_checks() {
    let (db, pool) = seeded().await;
    let key_a = upload(key_a("k")).await;
    let key_b = upload(key_b("k")).await;
    direct_create(&pool, &version("ver_a", "ks_1", &key_a, Status::Enabled)).await;
    direct_create(&pool, &version("ver_d", "ks_1", &key_b, Status::Disabled)).await;
    set_policy(&pool, true, false).await;
    let before = snapshot(&pool).await;
    let create = async |new: &NewKeysetVersion<'_>, allowed: &[Algorithm]| {
        submit_create(&pool, "key_trust", "op_1", true, new, allowed).await
    };
    refused(
        create(&version("ver_1", "ks_1", &key_b, Status::Enabled), ALLOWED).await,
        "Overlap(KidConflict)",
    );
    let private = object(json!({"source": {"d": "x"}}));
    refused(
        create(
            &NewKeysetVersion {
                provenance: &private,
                ..version("ver_1", "ks_1", &key_b, Status::Disabled)
            },
            ALLOWED,
        )
        .await,
        "PrivateMemberInProvenance",
    );
    let empty = create(&version("", "ks_1", &key_b, Status::Disabled), ALLOWED).await;
    assert!(
        matches!(
            &empty,
            Err(KeysetWriteError::Registry(
                registry::RegistryError::Invariant {
                    kind: registry::InvariantKind::Check,
                    constraint: Some("trust_keyset_version_id_check"),
                }
            ))
        ),
        "{empty:?}"
    );
    refused(
        create(
            &version("ver_1", "ks_1", &key_b, Status::Disabled),
            &[Algorithm::Rs256],
        )
        .await,
        "Upload(..)",
    );
    refused(
        create(
            &version("ver_1", "ks_none", &key_b, Status::Disabled),
            ALLOWED,
        )
        .await,
        "Registry(NotFound)",
    );
    refused(
        submit_enable(&pool, "key_trust", "op_1", true, "ver_d", 2).await,
        "Registry(StaleRevision)",
    );
    refused(
        submit_enable(&pool, "key_trust", "op_1", true, "ver_none", 1).await,
        "Registry(NotFound)",
    );
    refused(
        submit_enable(&pool, "key_trust", "op_1", true, "ver_d", 1).await,
        "Overlap(KidConflict)",
    );
    assert_eq!(snapshot(&pool).await, before);
    // The cap: seven more enabled versions in windows of their own.
    for n in 1..=7 {
        let id = format!("ver_s{n}");
        direct_create(&pool, &slot(&id, "ks_2", &key_a, Status::Enabled, n)).await;
    }
    direct_create(&pool, &slot("ver_s8", "ks_2", &key_a, Status::Enabled, 8)).await;
    let before = snapshot(&pool).await;
    refused(
        create(&slot("ver_9", "ks_2", &key_a, Status::Enabled, 9), ALLOWED).await,
        "TooManyEnabledVersions",
    );
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// The approval reruns the write's checks under the locks: an overlap
/// introduced since the request refuses it and passes once the conflict is
/// disabled (D14); the cap reached meanwhile and a version ID taken
/// meanwhile refuse it; each refusal writes nothing and leaves the
/// operation pending.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_approval_reruns_the_writes_checks() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let key_a = upload(key_a("k")).await;
    let key_b = upload(key_b("k")).await;
    let clock = TestClock::new(at(10));
    let op = pending(
        submit_create(
            &pool,
            "key_trust",
            "op_1",
            true,
            &version("ver_1", "ks_1", &key_b, Status::Enabled),
            ALLOWED,
        )
        .await,
    );
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    direct_create(&pool, &version("ver_a", "ks_1", &key_a, Status::Enabled)).await;
    let before = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "Keyset(Overlap(KidConflict))",
    );
    assert_eq!(snapshot(&pool).await, before);
    direct_disable(&pool, "ver_a", 1).await;
    applied_version(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);

    // The cap reached meanwhile.
    let op = pending(
        submit_create(
            &pool,
            "key_trust",
            "op_2",
            true,
            &slot("ver_2", "ks_2", &key_a, Status::Enabled, 9),
            ALLOWED,
        )
        .await,
    );
    let prepared = prepare(&pool, "key_sec1", "op_2").await.unwrap();
    for n in 1..=8 {
        let id = format!("ver_s{n}");
        direct_create(&pool, &slot(&id, "ks_2", &key_a, Status::Enabled, n)).await;
    }
    let before = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "Keyset(TooManyEnabledVersions)",
    );
    assert_eq!(snapshot(&pool).await, before);

    // The version ID taken meanwhile, in another keyset.
    let op = pending(
        submit_create(
            &pool,
            "key_trust",
            "op_3",
            true,
            &version("ver_3", "ks_1", &key_a, Status::Disabled),
            ALLOWED,
        )
        .await,
    );
    let prepared = prepare(&pool, "key_sec1", "op_3").await.unwrap();
    direct_create(&pool, &version("ver_3", "ks_2", &key_b, Status::Disabled)).await;
    let before = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "Keyset(Registry(AlreadyExists { constraint: \"trust_keyset_version_pkey\" }))",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(operation(&pool, "op_3").await.outcome, "pending");
    db.drop([pool]).await;
}

/// Expiry is judged at the one sample after the write: at exactly
/// `expires_at` the approval is refused and writes nothing; one
/// microsecond before, it applies and records that sample.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_is_refused_from_its_expiry_on() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let keys = upload(key_a("k1")).await;
    let op = pending(
        submit_create(
            &pool,
            "key_trust",
            "op_1",
            true,
            &version("ver_1", "ks_1", &keys, Status::Enabled),
            ALLOWED,
        )
        .await,
    );
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let before = snapshot(&pool).await;
    let clock = TestClock::new(expiry());
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "NotApprovable(Expired)",
    );
    assert_eq!(clock.samples(), 1);
    assert_eq!(snapshot(&pool).await, before);
    let just_before = expiry() - Duration::from_micros(1);
    clock.set(just_before);
    applied_version(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!(
        operation(&pool, "op_1").await.consumed_at,
        Some(just_before)
    );
    db.drop([pool]).await;
}

/// The clock is sampled after every wait of the write (D28): an approval
/// that waits for the parent keyset row, held by another connection, while
/// the clock passes the expiry is refused and writes nothing; with the
/// clock left before it, the operation is consumed at the sample taken
/// after the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_clock_is_sampled_after_the_keyset_wait() {
    let (db, pool) = seeded().await;
    let keys = upload(key_a("k1")).await;
    direct_create(&pool, &version("ver_1", "ks_1", &keys, Status::Disabled)).await;
    set_policy(&pool, true, false).await;
    let op = pending(submit_enable(&pool, "key_trust", "op_1", true, "ver_1", 1).await);
    let before = snapshot(&pool).await;
    for expired in [true, false] {
        let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
        let clock = TestClock::new(at(10));
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        sqlx::query("SELECT FROM trust_keyset WHERE id = 'ks_1' FOR NO KEY UPDATE")
            .execute(&mut *held)
            .await
            .unwrap();
        let (pid, task) =
            spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        assert_eq!(clock.samples(), 0, "sampled before the keyset wait");
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
            applied_version(result);
            assert_eq!(operation(&pool, "op_1").await.consumed_at, Some(later));
        }
    }
    db.drop([pool]).await;
}

/// The clock is sampled after the registry write, not between the target's
/// lock and the write (D28; the proposal's PR 3 note): a create's insert
/// waits for another transaction's uncommitted version with the same ID;
/// the clock passes the expiry meanwhile; once that transaction rolls back
/// the insert proceeds, and the sample after it refuses the approval, which
/// writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_clock_is_sampled_after_the_insert_waits_for_a_version_id() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let keys = upload(key_a("k1")).await;
    let op = pending(
        submit_create(
            &pool,
            "key_trust",
            "op_1",
            true,
            &version("ver_1", "ks_1", &keys, Status::Disabled),
            ALLOWED,
        )
        .await,
    );
    let before = snapshot(&pool).await;
    for expired in [true, false] {
        let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
        let clock = TestClock::new(at(10));
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        // The same ID in another tenant's keyset: the parent lock does not
        // conflict, only the primary key does.
        registry::create_trust_keyset_version(
            &mut *held,
            &NewTrustKeysetVersion {
                id: "ver_1".into(),
                tenant_id: "ten_b".into(),
                keyset_id: "ks_b".into(),
                public_jwks: object(serde_json::from_str(keys.public_json()).unwrap()),
                fingerprint: keys.fingerprint().as_str().into(),
                effective_at: at(0),
                expires_at: None,
                status: Status::Disabled,
                provenance: JsonObject::new(),
            },
        )
        .await
        .unwrap();
        let (pid, task) =
            spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        assert_eq!(clock.samples(), 0, "sampled before the insert's wait");
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
            let row = applied_version(result);
            assert_eq!(row.tenant_id, "ten_a");
            assert_eq!(operation(&pool, "op_1").await.consumed_at, Some(later));
        }
    }
    db.drop([pool]).await;
}

/// What the approval writes is what the locked plan holds and what the
/// preparation parsed: a plan whose projection does not match its
/// fingerprint, or is not JSON, is refused at the preparation; a projection
/// the plan's and the caller's algorithms do not both allow is refused
/// (D25); a plan that is not the canonical projection (D24), a plan that
/// does not recompute to its digest, a locked plan unequal to the prepared
/// one (the 0005 immutability trigger disabled in between), and an enable
/// whose plan names another fingerprint or keyset than the version's are
/// `PlanIntegrity`; a provenance naming a private member is refused again;
/// none writes anything.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_approval_writes_only_the_prepared_and_locked_plan() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let key_a = upload(key_a("k1")).await;
    let key_b = upload(key_b("k2")).await;
    let clock = TestClock::new(at(10));
    let plan = |keys: &ValidatedKeyset, status: Status| {
        create_plan(&version("ver_1", "ks_1", keys, status), &["ES256"])
    };
    let changed = |mut plan: JsonObject, name: &str, value: Value| {
        plan.insert(name.into(), value);
        plan
    };
    let good = plan(&key_a, Status::Disabled);

    // Refused at the preparation.
    let cases = [
        (
            "op_fp",
            changed(
                good.clone(),
                "fingerprint",
                json!(key_b.fingerprint().as_str()),
            ),
            ALLOWED,
            "PlanIntegrity",
        ),
        (
            "op_json",
            changed(good.clone(), "public_jwks", json!("not json")),
            ALLOWED,
            "PlanIntegrity",
        ),
        (
            "op_rs",
            good.clone(),
            &[Algorithm::Rs256][..],
            "Keyset(Upload(..))",
        ),
        (
            "op_eddsa",
            changed(good.clone(), "allowed_algorithms", json!(["EdDSA"])),
            ALLOWED,
            "Keyset(Upload(..))",
        ),
    ];
    for (id, plan, allowed, expected) in cases {
        insert_raw(&pool, &raw(id, CREATE, 0, plan, None)).await;
        refused(
            prepare_approval(&pool, "key_sec1", TEN_A, id, allowed, at(1)).await,
            expected,
        );
    }
    let before = snapshot(&pool).await;

    // D24: the canonical projection's fingerprint over another text.
    let pretty =
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(key_a.public_json()).unwrap())
            .unwrap();
    assert_ne!(pretty, key_a.public_json());
    let echo_pretty = insert_raw(
        &pool,
        &raw(
            "op_pretty",
            CREATE,
            0,
            changed(good.clone(), "public_jwks", json!(pretty)),
            None,
        ),
    )
    .await;
    let prepared = prepare(&pool, "key_sec1", "op_pretty").await.unwrap();
    let before_pretty = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo_pretty, &*clock).await,
        "PlanIntegrity",
    );
    assert_eq!(snapshot(&pool).await, before_pretty);

    // A plan that does not recompute to its digest, then the locked plan
    // changed under the prepared one (the trigger disabled in between): an
    // enabled create, and a create of key B.
    for (id, locked) in [
        ("op_status", plan(&key_a, Status::Enabled)),
        ("op_keys", plan(&key_b, Status::Disabled)),
    ] {
        let echo = insert_raw(&pool, &raw(id, CREATE, 0, good.clone(), Some(&locked))).await;
        let prepared = prepare(&pool, "key_sec1", id).await.unwrap();
        let before = snapshot(&pool).await;
        refused(
            approve(&pool, "key_sec1", &prepared, &echo, &*clock).await,
            "PlanIntegrity",
        );
        assert_eq!(snapshot(&pool).await, before);
        sqlx::raw_sql(
            "ALTER TABLE administrative_operation \
             DISABLE TRIGGER administrative_operation_immutable",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE administrative_operation SET immutable_plan = $2, revision = revision + 1 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(sqlx::types::Json(&locked))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql(
            "ALTER TABLE administrative_operation \
             ENABLE ALWAYS TRIGGER administrative_operation_immutable",
        )
        .execute(&pool)
        .await
        .unwrap();
        let before = snapshot(&pool).await;
        refused(
            approve(&pool, "key_sec1", &prepared, &echo, &*clock).await,
            "PlanIntegrity",
        );
        assert_eq!(snapshot(&pool).await, before, "{id}");
    }
    assert_eq!(version_row(&pool, "ver_1").await, None);

    // A provenance naming a private member is refused again at the
    // approval (section 4).
    let private = changed(good.clone(), "provenance", json!(r#"{"source":{"d":"x"}}"#));
    let echo_private = insert_raw(&pool, &raw("op_private", CREATE, 0, private, None)).await;
    let prepared = prepare(&pool, "key_sec1", "op_private").await.unwrap();
    let before_private = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo_private, &*clock).await,
        "Keyset(PrivateMemberInProvenance)",
    );
    assert_eq!(snapshot(&pool).await, before_private);

    // An enable whose plan names another fingerprint or keyset.
    direct_create(&pool, &version("ver_e", "ks_1", &key_a, Status::Disabled)).await;
    let enable_plan = |keyset: &str, fingerprint: &str| {
        object(json!({
            "requester_credential_id": "crd_adm_trust",
            "version_id": "ver_e",
            "keyset_id": keyset,
            "fingerprint": fingerprint,
        }))
    };
    for (id, plan) in [
        ("op_e_fp", enable_plan("ks_1", key_b.fingerprint().as_str())),
        ("op_e_ks", enable_plan("ks_2", key_a.fingerprint().as_str())),
    ] {
        let echo = insert_raw(&pool, &raw(id, ENABLE, 1, plan, None)).await;
        let prepared = prepare(&pool, "key_sec1", id).await.unwrap();
        let before = snapshot(&pool).await;
        refused(
            approve(&pool, "key_sec1", &prepared, &echo, &*clock).await,
            "PlanIntegrity",
        );
        assert_eq!(snapshot(&pool).await, before, "{id}");
    }
    let echo = insert_raw(
        &pool,
        &raw(
            "op_e",
            ENABLE,
            1,
            enable_plan("ks_1", key_a.fingerprint().as_str()),
            None,
        ),
    )
    .await;
    let prepared = prepare(&pool, "key_sec1", "op_e").await.unwrap();
    applied_version(approve(&pool, "key_sec1", &prepared, &echo, &*clock).await);
    drop(before);
    db.drop([pool]).await;
}

/// The approval checks the requester again under the locks (Q5; D21): a
/// requester whose binding was disabled, or whose submitting credential
/// was disabled or revoked, is `RequesterNotAuthorized`, and nothing is
/// written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_requester_must_still_be_a_trust_admin_with_its_credential() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let keys = upload(key_a("k1")).await;
    let mut ops = Vec::new();
    for (n, key) in ["key_trust", "key_other", "key_both"]
        .into_iter()
        .enumerate()
    {
        let id = format!("ver_{n}");
        let op_id = format!("op_{n}");
        let op = pending(
            submit_create(
                &pool,
                key,
                &op_id,
                true,
                &version(&id, "ks_1", &keys, Status::Disabled),
                ALLOWED,
            )
            .await,
        );
        let prepared = prepare(&pool, "key_sec1", &op_id).await.unwrap();
        ops.push((op, prepared));
    }
    registry::update_admin_role_binding(
        &pool,
        "rb_trust",
        1,
        &AdminRoleBindingChanges {
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_other'")
        .execute(&pool)
        .await
        .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_both", at(2))
        .await
        .unwrap();
    let clock = TestClock::new(at(10));
    let before = snapshot(&pool).await;
    for (op, prepared) in &ops {
        refused(
            approve(&pool, "key_sec1", prepared, &echo(op), &*clock).await,
            "RequesterNotAuthorized",
        );
    }
    assert_eq!(clock.samples(), 0);
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// On a tenant path a cancel is the requester's: another `trust_admin` of
/// the tenant gets `NotFound`, as for a missing operation, and learns
/// nothing; a cancel on another tenant's path is `NotFound` too; the
/// requester cancels, and a `security_admin` other than the requester
/// rejects. A self-approval by a requester who is also a `security_admin`
/// is refused.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_tenant_cancel_of_another_operators_operation_is_not_found() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let keys = upload(key_a("k1")).await;
    for (op, id, key) in [
        ("op_1", "ver_1", "key_trust"),
        ("op_2", "ver_2", "key_trust"),
        ("op_3", "ver_3", "key_both"),
    ] {
        pending(
            submit_create(
                &pool,
                key,
                op,
                true,
                &version(id, "ks_1", &keys, Status::Disabled),
                ALLOWED,
            )
            .await,
        );
    }
    let before = snapshot(&pool).await;
    for op in ["op_1", "op_none"] {
        refused(
            revoke(&pool, true, "key_other", TEN_A, op).await,
            "NotFound",
        );
        refused(revoke(&pool, true, "key_both", TEN_A, op).await, "NotFound");
    }
    refused(
        revoke(&pool, true, "key_tb", TEN_B, "op_1").await,
        "NotFound",
    );
    refused(
        revoke(&pool, true, "key_trust", TEN_B, "op_1").await,
        "Unauthorized",
    );
    refused(
        revoke(&pool, true, "key_sec1", TEN_A, "op_1").await,
        "Unauthorized",
    );
    refused(
        revoke(&pool, false, "key_sec1", INSTANCE, "op_1").await,
        "NotFound",
    );
    refused(
        revoke(&pool, false, "key_both", TEN_A, "op_3").await,
        "SelfApproval",
    );
    refused(prepare(&pool, "key_both", "op_3").await, "SelfApproval");
    assert_eq!(snapshot(&pool).await, before);
    revoke(&pool, true, "key_trust", TEN_A, "op_1")
        .await
        .unwrap();
    assert_eq!(operation(&pool, "op_1").await.outcome, "cancelled");
    revoke(&pool, false, "key_sec1", TEN_A, "op_2")
        .await
        .unwrap();
    let rejected = operation(&pool, "op_2").await;
    assert_eq!(rejected.outcome, "rejected");
    assert_eq!(
        operation(&pool, "reject_op_2_key_sec1")
            .await
            .tenant_id
            .as_deref(),
        Some("ten_a")
    );
    refused(
        prepare(&pool, "key_sec1", "op_1").await,
        "NotApprovable(Revoked)",
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Two approvals of one operation serialize on its row: the second, once
/// the first commits, reads it consumed; after the first rolls back, it
/// applies. An approval and a cancel race the same way; none ends in
/// `40P01`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn approvals_and_cancels_serialize_on_the_operation() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let keys = upload(key_a("k1")).await;
    let clock = TestClock::new(at(10));
    let mut ops = Vec::new();
    for n in 1..=4 {
        let id = format!("ver_{n}");
        let op_id = format!("op_{n}");
        let new = slot(&id, "ks_1", &keys, Status::Enabled, n);
        ops.push(pending(
            submit_create(&pool, "key_trust", &op_id, true, &new, ALLOWED).await,
        ));
    }
    // Two approvals; the first commits, then rolls back.
    for (op, commit) in [(&ops[0], true), (&ops[1], false)] {
        let first = prepare(&pool, "key_sec1", &op.id).await.unwrap();
        let second = prepare(&pool, "key_sec2", &op.id).await.unwrap();
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        applied_version(approve_in(&mut held, "key_sec1", &first, &echo(op), &*clock).await);
        let (pid, task) = spawn_approve(&pool, "key_sec2", second, echo(op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        if commit {
            held.commit().await.unwrap();
            refused(finished(task).await, "NotApprovable(Consumed)");
        } else {
            held.rollback().await.unwrap();
            applied_version(finished(task).await);
        }
        holder.close().await.unwrap();
        assert_eq!(operation(&pool, &op.id).await.outcome, "applied");
    }
    // An approval waits for a cancel, and a cancel for an approval.
    let (op_3, op_4) = (&ops[2], &ops[3]);
    let prepared = prepare(&pool, "key_sec1", &op_3.id).await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    revoke_in(&mut held, true, "key_trust", TEN_A, &op_3.id)
        .await
        .unwrap();
    let (pid, task) = spawn_approve(&pool, "key_sec1", prepared, echo(op_3), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    refused(finished(task).await, "NotApprovable(Revoked)");
    holder.close().await.unwrap();

    let prepared = prepare(&pool, "key_sec1", &op_4.id).await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    applied_version(approve_in(&mut held, "key_sec1", &prepared, &echo(op_4), &*clock).await);
    let (mut canceller, pid) = connection(&pool).await;
    let op_4_id = op_4.id.clone();
    let task = tokio::spawn(async move {
        let mut transaction = canceller.begin().await.unwrap();
        let result = revoke_in(&mut transaction, true, "key_trust", TEN_A, &op_4_id).await;
        transaction.commit().await.unwrap();
        canceller.close().await.unwrap();
        result
    });
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    refused(finished(task).await, "NotApprovable(Consumed)");
    holder.close().await.unwrap();
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// An approval and a direct write of its target serialize on the parent
/// keyset row, both orders: a disable that commits first makes the
/// approval stale (nothing written, the operation stays pending); an
/// approval that commits first makes the disable stale. None ends in
/// `40P01`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_and_a_direct_write_serialize_on_the_keyset() {
    let (db, pool) = seeded().await;
    let keys = upload(key_a("k1")).await;
    direct_create(&pool, &version("ver_1", "ks_1", &keys, Status::Disabled)).await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));
    let op = pending(submit_enable(&pool, "key_trust", "op_1", true, "ver_1", 1).await);

    // The disable first.
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    disable_version(
        &mut held,
        "key_trust",
        "ten_a",
        "ver_1",
        1,
        &audit("evt_d1"),
    )
    .await
    .unwrap();
    let (pid, task) = spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    holder.close().await.unwrap();
    refused(finished(task).await, "Keyset(Registry(StaleRevision))");
    assert_eq!(operation(&pool, "op_1").await.outcome, "pending");
    assert_eq!(
        version_row(&pool, "ver_1").await,
        Some(("disabled".into(), 2))
    );

    // The approval first.
    let op = pending(submit_enable(&pool, "key_trust", "op_2", true, "ver_1", 2).await);
    let prepared = prepare(&pool, "key_sec1", "op_2").await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    applied_version(approve_in(&mut held, "key_sec1", &prepared, &echo(&op), &*clock).await);
    let (mut writer, pid) = connection(&pool).await;
    let task = tokio::spawn(async move {
        let mut transaction = writer.begin().await.unwrap();
        let result = disable_version(
            &mut transaction,
            "key_trust",
            "ten_a",
            "ver_1",
            2,
            &audit("evt_d2"),
        )
        .await;
        transaction.commit().await.unwrap();
        writer.close().await.unwrap();
        result
    });
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    holder.close().await.unwrap();
    refused(finished(task).await, "Registry(StaleRevision)");
    assert_eq!(
        version_row(&pool, "ver_1").await,
        Some(("enabled".into(), 3))
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}
