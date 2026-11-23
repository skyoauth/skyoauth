//! The registry floor of the second-approver flow
//! (`persistence::registry::operation`;
//! `docs/proposals/second-approver-gated-writes.md` sections 2, 3 and 9;
//! IR-052 to IR-054): the operation writers (insert, lock, consume, revoke)
//! and how the database's refusals map, the `cancel` and `reject` audit
//! actions, the two strengths of the policy row lock and what they conflict
//! with, and the two locked operator lookups, `authorize_approval_locked`
//! and `authorize_roles_locked`: their hits and misses, the order of the
//! approval's refusals, the rows they lock and in which order, that a miss
//! locks nothing, and that a change between the lookup and its lock is
//! caught.
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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use serde_json::{Value, json};
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, AdminRole, AdminRoleBindingChanges, AdministrativeOperation, ApprovalAuthority,
        AuditActor, AuthorizedOperator, BootstrapRequest, InvariantKind, JsonObject,
        NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding, NewAdministrativeOperation,
        NewAuditEvent, NewTenant, OperatorScope, RegistryError, RolesHeld, Status,
        append_audit_event, authorize_approval_locked, authorize_roles_locked, bootstrap_instance,
        consume_administrative_operation, insert_administrative_operation,
        lock_administrative_operation, lock_instance_security_policy,
        lock_instance_security_policy_shared, revoke_administrative_operation,
    },
};
use sqlx::{AssertSqlSafe, Connection, PgConnection, Postgres, Transaction};

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;

/// `micros` after `T0`, with sub-microsecond digits, so a write truncates
/// it.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros) + Duration::from_nanos(789)
}

/// [`at`] as stored: truncated to the microsecond.
fn stored(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

const E: Status = Status::Enabled;
const D: Status = Status::Disabled;
const INSTANCE: OperatorScope<'static> = OperatorScope::Instance;
const TEN_A: OperatorScope<'static> = OperatorScope::Tenant("ten_a");
const TEN_B: OperatorScope<'static> = OperatorScope::Tenant("ten_b");
const SEC: AdminRole = AdminRole::SecurityAdmin;
const TRUST: AdminRole = AdminRole::TrustAdmin;
const CLIENT: AdminRole = AdminRole::ClientAdmin;

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
    registry::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: admin.into(),
            status: E,
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
                status: E,
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
            status: E,
        },
    )
    .await
    .unwrap();
}

/// A bootstrapped instance (`adm_first`, the policy row, the bootstrap
/// event), the tenants `ten_a` and `ten_b`, and these operators, all
/// enabled, each with a credential `crd_<admin>`:
///
/// - `adm_sec1` (`key_sec1`) and `adm_sec2` (`key_sec2`), `security_admin`
///   of the instance (`rb_sec1`, `rb_sec2`); `adm_sec1` has a second
///   credential, `crd_adm_sec1_b` (`key_sec1_b`).
/// - `adm_req` (`key_req`), `trust_admin` of `ten_a` (`rb_req`): the
///   requester. Its ID sorts before the approvers' and it is inserted
///   after them, so an unordered lock would take an approver's row first.
/// - `adm_multi` (`key_multi`): `trust_admin` of `ten_a` (`rb_multi_t`),
///   `security_admin` of the instance (`rb_multi_s`) and a disabled
///   `client_admin` of `ten_a` (`rb_multi_c`).
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
            recovery_public_key: &[0x11; 32],
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    for (id, ns) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::create_tenant(
            &pool,
            &NewTenant {
                id: id.into(),
                name: format!("Tenant {id}"),
                secret_namespace: ns.into(),
                status: E,
            },
        )
        .await
        .unwrap();
    }
    operator(&pool, "adm_sec1", "key_sec1", &[("rb_sec1", SEC, None)]).await;
    credential(&pool, "crd_adm_sec1_b", "adm_sec1", "key_sec1_b").await;
    operator(&pool, "adm_sec2", "key_sec2", &[("rb_sec2", SEC, None)]).await;
    operator(
        &pool,
        "adm_req",
        "key_req",
        &[("rb_req", TRUST, Some("ten_a"))],
    )
    .await;
    operator(
        &pool,
        "adm_multi",
        "key_multi",
        &[
            ("rb_multi_t", TRUST, Some("ten_a")),
            ("rb_multi_s", SEC, None),
            ("rb_multi_c", CLIENT, Some("ten_a")),
        ],
    )
    .await;
    registry::update_admin_role_binding(
        &pool,
        "rb_multi_c",
        1,
        &AdminRoleBindingChanges { status: D },
    )
    .await
    .unwrap();
    (db, pool)
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// Appends the event `id` in `tenant` by `actor` with `action` on
/// `object_id`.
async fn append(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    tenant: Option<&str>,
    actor: &str,
    action: &str,
    object_id: &str,
) -> Result<(), RegistryError> {
    append_audit_event(
        transaction,
        &NewAuditEvent {
            id: id.into(),
            tenant_id: tenant.map(Into::into),
            timestamp: at(1),
            actor: AuditActor::Operator(actor.into()),
            action: action.into(),
            object_id: object_id.into(),
            previous_revision: None,
            new_revision: None,
            outcome: "success".into(),
        },
    )
    .await
    .map(|_| ())
}

/// A new operation `id` of `kind` in `tenant` by `actor`, recorded by
/// `evt_<id>`: a pending one (an hour to expiry, no approved operation)
/// unless it is an `approve`, a `cancel` or a `reject`.
fn new_operation(
    id: &str,
    tenant: Option<&str>,
    actor: &str,
    kind: &str,
    approves: Option<&str>,
) -> NewAdministrativeOperation {
    let pending = !["approve", "cancel", "reject"].contains(&kind);
    NewAdministrativeOperation {
        id: id.into(),
        tenant_id: tenant.map(Into::into),
        actor_id: actor.into(),
        kind: kind.into(),
        request_digest: vec![0xd1; 32],
        expected_revision: 3,
        immutable_plan: object(json!({"status": "enabled", "id": id})),
        expires_at: pending.then(|| at(3_600_000_000)),
        approves_operation_id: approves.map(Into::into),
        outcome: if pending { "pending" } else { "applied" }.into(),
        audit_id: format!("evt_{id}"),
    }
}

/// Appends the operation's event (action `action`) and inserts it, in one
/// transaction committed on success.
async fn create(
    pool: &PgPool,
    new: &NewAdministrativeOperation,
    action: &str,
    object_id: &str,
) -> Result<AdministrativeOperation, RegistryError> {
    let mut transaction = pool.begin().await.unwrap();
    append(
        &mut transaction,
        &new.audit_id,
        new.tenant_id.as_deref(),
        &new.actor_id,
        action,
        object_id,
    )
    .await
    .unwrap();
    let inserted = insert_administrative_operation(&mut transaction, new).await;
    if inserted.is_ok() {
        transaction.commit().await.unwrap();
    }
    inserted
}

/// The stored row of a new operation: what it set, unconsumed and
/// unrevoked, at revision 1, the expiry truncated.
fn row_of(new: &NewAdministrativeOperation) -> AdministrativeOperation {
    AdministrativeOperation {
        id: new.id.clone(),
        tenant_id: new.tenant_id.clone(),
        actor_id: new.actor_id.clone(),
        kind: new.kind.clone(),
        request_digest: new.request_digest.clone(),
        expected_revision: new.expected_revision,
        immutable_plan: new.immutable_plan.clone(),
        challenge_hash: None,
        expires_at: new.expires_at.map(|_| stored(3_600_000_000)),
        consumed_at: None,
        revoked_at: None,
        revocation_operation_id: None,
        approves_operation_id: new.approves_operation_id.clone(),
        revision: 1,
        outcome: new.outcome.clone(),
        audit_id: new.audit_id.clone(),
    }
}

async fn locked_row(pool: &PgPool, id: &str) -> Option<AdministrativeOperation> {
    let mut transaction = pool.begin().await.unwrap();
    let row = lock_administrative_operation(&mut transaction, id)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    row
}

async fn consume(pool: &PgPool, id: &str, now: SystemTime) -> Result<i64, RegistryError> {
    let mut transaction = pool.begin().await.unwrap();
    let consumed = consume_administrative_operation(&mut transaction, id, now, "applied").await;
    if consumed.is_ok() {
        transaction.commit().await.unwrap();
    }
    consumed
}

async fn revoke(pool: &PgPool, id: &str, by: &str, outcome: &str) -> Result<i64, RegistryError> {
    let mut transaction = pool.begin().await.unwrap();
    let revoked = revoke_administrative_operation(&mut transaction, id, by, at(2), outcome).await;
    if revoked.is_ok() {
        transaction.commit().await.unwrap();
    }
    revoked
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

#[track_caller]
fn assert_guard<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::Guard)), "{result:?}");
}

#[track_caller]
fn assert_not_found<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::NotFound)), "{result:?}");
}

/// An operation is inserted as given and read back locked; an `approve`
/// names the operation it approves; a consume sets `consumed_at`
/// (truncated) and the outcome and advances the revision, once; a cancel
/// and a reject each insert their revoking operation, recorded by the
/// `cancel` and `reject` audit actions, and revoke the pending one, once,
/// after which it is not consumed. A missing row is `None` to the lock and
/// `NotFound` to the writers.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn operations_are_inserted_locked_consumed_and_revoked() {
    let (db, pool) = seeded().await;
    let pending = new_operation(
        "op_1",
        Some("ten_a"),
        "adm_req",
        "service_grant.update",
        None,
    );
    let inserted = create(&pool, &pending, "administrative_operation.create", "op_1")
        .await
        .unwrap();
    assert_eq!(inserted, row_of(&pending));
    assert_eq!(locked_row(&pool, "op_1").await, Some(row_of(&pending)));

    let approval = new_operation("op_2", Some("ten_a"), "adm_sec1", "approve", Some("op_1"));
    let inserted = create(&pool, &approval, "administrative_operation.approve", "op_1")
        .await
        .unwrap();
    assert_eq!(inserted, row_of(&approval));
    assert_eq!(inserted.expires_at, None);
    assert_eq!(inserted.approves_operation_id.as_deref(), Some("op_1"));

    assert_eq!(consume(&pool, "op_1", at(10)).await.unwrap(), 2);
    let consumed = locked_row(&pool, "op_1").await.unwrap();
    assert_eq!(
        consumed,
        AdministrativeOperation {
            consumed_at: Some(stored(10)),
            outcome: "applied".into(),
            revision: 2,
            ..row_of(&pending)
        }
    );
    assert_guard(consume(&pool, "op_1", at(11)).await);

    for (n, verb, actor, outcome) in [
        (3, "cancel", "adm_req", "cancelled"),
        (5, "reject", "adm_sec2", "rejected"),
    ] {
        let (id, by) = (format!("op_{n}"), format!("op_{}", n + 1));
        let pending = new_operation(&id, Some("ten_a"), "adm_req", "service_grant.update", None);
        create(&pool, &pending, "administrative_operation.create", &id)
            .await
            .unwrap();
        let revoking = new_operation(&by, Some("ten_a"), actor, verb, None);
        let inserted = create(
            &pool,
            &revoking,
            &format!("administrative_operation.{verb}"),
            &id,
        )
        .await
        .unwrap();
        assert_eq!(inserted, row_of(&revoking));
        assert_eq!(revoke(&pool, &id, &by, outcome).await.unwrap(), 2);
        assert_eq!(
            locked_row(&pool, &id).await.unwrap(),
            AdministrativeOperation {
                revoked_at: Some(stored(2)),
                revocation_operation_id: Some(by.clone()),
                outcome: outcome.into(),
                revision: 2,
                ..row_of(&pending)
            },
            "{verb}"
        );
        // Another revoking operation: the set-once guard (the same values
        // again would change nothing it guards).
        assert_guard(revoke(&pool, &id, "op_2", "again").await);
        assert_guard(consume(&pool, &id, at(10)).await);
    }
    // The events of the cancel and the reject.
    let actions: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, object_id FROM audit_event WHERE id IN ('evt_op_4', 'evt_op_6')
         ORDER BY id COLLATE \"C\"",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            ("administrative_operation.cancel".into(), "op_3".into()),
            ("administrative_operation.reject".into(), "op_5".into()),
        ]
    );

    assert_eq!(locked_row(&pool, "op_missing").await, None);
    assert_not_found(consume(&pool, "op_missing", at(10)).await);
    assert_not_found(revoke(&pool, "op_missing", "op_4", "cancelled").await);
    db.drop([pool]).await;
}

/// The writers check nothing the database does not, and its refusals map
/// as everywhere: a consume at the expiry is the expiry check, an approve
/// by the requester or of another tenant's operation and a revocation by
/// another tenant's operation are the amended `0005` guards'
/// (`DistinctApprover`, `SameTenantOperation`), a revocation by a missing
/// operation is its foreign key. An audit action outside the table is
/// refused before the insert, and a time outside the `0007` range before
/// any statement.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_writers_map_the_databases_refusals() {
    let (db, pool) = seeded().await;
    for (id, tenant) in [
        ("op_a", Some("ten_a")),
        ("op_b", Some("ten_b")),
        ("op_i", None),
    ] {
        let pending = new_operation(id, tenant, "adm_req", "service_grant.update", None);
        create(&pool, &pending, "administrative_operation.create", id)
            .await
            .unwrap();
    }
    assert_invariant(
        consume(&pool, "op_a", stored(3_600_000_000)).await,
        InvariantKind::Check,
        "administrative_operation_consumed_before_expiry_check",
    );
    for (approval, kind, name) in [
        (
            new_operation("op_x", Some("ten_a"), "adm_req", "approve", Some("op_a")),
            InvariantKind::DistinctApprover,
            "administrative_operation_approver_distinct",
        ),
        (
            new_operation("op_x", Some("ten_a"), "adm_sec1", "approve", Some("op_b")),
            InvariantKind::SameTenantOperation,
            "administrative_operation_approves_same_tenant",
        ),
        (
            new_operation("op_x", None, "adm_sec1", "approve", Some("op_a")),
            InvariantKind::SameTenantOperation,
            "administrative_operation_approves_same_tenant",
        ),
    ] {
        assert_invariant(
            create(&pool, &approval, "administrative_operation.approve", "op_a").await,
            kind,
            name,
        );
    }
    let cancel = new_operation("op_c", Some("ten_b"), "adm_req", "cancel", None);
    create(&pool, &cancel, "administrative_operation.cancel", "op_b")
        .await
        .unwrap();
    for revoked in ["op_a", "op_i"] {
        assert_invariant(
            revoke(&pool, revoked, "op_c", "cancelled").await,
            InvariantKind::SameTenantOperation,
            "administrative_operation_revokes_same_tenant",
        );
    }
    assert_invariant(
        revoke(&pool, "op_a", "op_missing", "cancelled").await,
        InvariantKind::ForeignKey,
        "administrative_operation_revocation_operation_id_fkey",
    );
    assert_eq!(revoke(&pool, "op_b", "op_c", "cancelled").await.unwrap(), 2);

    let mut transaction = pool.begin().await.unwrap();
    let refused = append(
        &mut transaction,
        "evt_x",
        Some("ten_a"),
        "adm_req",
        "administrative_operation.revoke",
        "op_a",
    )
    .await;
    assert!(
        matches!(refused, Err(RegistryError::Other(_))),
        "{refused:?}"
    );
    transaction.rollback().await.unwrap();

    let far = UNIX_EPOCH + Duration::from_secs(10_000_000_000_000);
    let mut transaction = pool.begin().await.unwrap();
    let mut late = new_operation(
        "op_y",
        Some("ten_a"),
        "adm_req",
        "service_grant.update",
        None,
    );
    late.expires_at = Some(far);
    for result in [
        insert_administrative_operation(&mut transaction, &late)
            .await
            .map(|_| 0),
        consume_administrative_operation(&mut transaction, "op_a", far, "applied").await,
        revoke_administrative_operation(&mut transaction, "op_a", "op_c", far, "x").await,
    ] {
        match result {
            Err(RegistryError::Other(sqlx::Error::Encode(_))) => {}
            other => panic!("expected an encode error: {other:?}"),
        }
    }
    // Nothing ran: the transaction is still usable.
    assert_eq!(locked_row(&pool, "op_a").await.unwrap().revision, 1);
    sqlx::query("SELECT 1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    db.drop([pool]).await;
}

/// Whether another transaction fails to take `id` of `table` with
/// `strength NOWAIT` (`55P03`); it releases a lock it took at once.
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

/// [`conflicts`] with `FOR UPDATE`: whether the row is locked at all.
async fn is_locked(pool: &PgPool, table: &str, id: &str) -> bool {
    conflicts(pool, table, "id", id, "FOR UPDATE").await
}

/// The operation lock is `FOR NO KEY UPDATE`: it conflicts with `FOR SHARE`
/// and `FOR NO KEY UPDATE`, not with `FOR KEY SHARE` (the foreign key's
/// lock), and lasts until the transaction ends.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_operation_lock_is_for_no_key_update() {
    let (db, pool) = seeded().await;
    let pending = new_operation(
        "op_1",
        Some("ten_a"),
        "adm_req",
        "service_grant.update",
        None,
    );
    create(&pool, &pending, "administrative_operation.create", "op_1")
        .await
        .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    lock_administrative_operation(&mut transaction, "op_1")
        .await
        .unwrap()
        .unwrap();
    for (strength, conflict) in [
        ("FOR NO KEY UPDATE", true),
        ("FOR SHARE", true),
        ("FOR KEY SHARE", false),
    ] {
        assert_eq!(
            conflicts(&pool, "administrative_operation", "id", "op_1", strength).await,
            conflict,
            "{strength}"
        );
    }
    transaction.commit().await.unwrap();
    assert!(!is_locked(&pool, "administrative_operation", "op_1").await);
    db.drop([pool]).await;
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// Waits until the backend `blocked`, which runs `task`, waits for a lock
/// held by `holder`. Fails at once if `task` finished without waiting.
async fn wait_until_blocked<T>(
    pool: &PgPool,
    blocked: i32,
    holder: i32,
    task: &tokio::task::JoinHandle<T>,
) {
    wait_until_blocked_by_any(pool, blocked, &[holder], task).await;
}

/// [`wait_until_blocked`] by any of `holders`: a waiter queued behind
/// another waiter is blocked by that waiter, not the holder.
async fn wait_until_blocked_by_any<T>(
    pool: &PgPool,
    blocked: i32,
    holders: &[i32],
    task: &tokio::task::JoinHandle<T>,
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

async fn finished<T>(task: tokio::task::JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the task never finished")
        .unwrap()
}

/// [`conflicts`] on the policy row.
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

/// Before bootstrap there is no policy row: both locks are `NotFound`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_policy_locks_are_not_found_before_bootstrap() {
    let (db, pool) = migrated().await;
    let mut transaction = pool.begin().await.unwrap();
    assert_not_found(lock_instance_security_policy_shared(&mut transaction).await);
    assert_not_found(lock_instance_security_policy(&mut transaction).await);
    transaction.rollback().await.unwrap();
    db.drop([pool]).await;
}

/// Both policy locks return the row. The shared lock is `FOR SHARE`: two
/// trust writes do not wait for each other, and it conflicts with
/// `FOR NO KEY UPDATE`. The toggle's lock is `FOR NO KEY UPDATE`: it
/// conflicts with `FOR SHARE` and another toggle's, not with
/// `FOR KEY SHARE`. A toggle waits for a trust write until it commits, and
/// a trust write and a second toggle wait for a toggle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_policy_locks_conflict_as_the_flow_needs() {
    let (db, pool) = seeded().await;
    let policy = registry::get_instance_security_policy(&pool).await.unwrap();
    let mut holder = pool.acquire().await.unwrap().detach();
    let holder_pid = backend_pid(&mut holder).await;
    let mut held = holder.begin().await.unwrap();
    assert_eq!(
        lock_instance_security_policy_shared(&mut held)
            .await
            .unwrap(),
        policy
    );
    assert!(!policy_conflicts(&pool, "FOR SHARE").await);
    assert!(policy_conflicts(&pool, "FOR NO KEY UPDATE").await);
    // A second trust write does not wait.
    let mut other = pool.begin().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        lock_instance_security_policy_shared(&mut other),
    )
    .await
    .expect("two shared locks waited")
    .unwrap();
    other.rollback().await.unwrap();
    // A toggle waits for the trust write.
    let mut toggler = pool.acquire().await.unwrap().detach();
    let toggler_pid = backend_pid(&mut toggler).await;
    let task = tokio::spawn(async move {
        let mut toggling = toggler.begin().await.unwrap();
        let locked = lock_instance_security_policy(&mut toggling).await;
        toggling.rollback().await.unwrap();
        (toggler, locked)
    });
    wait_until_blocked(&pool, toggler_pid, holder_pid, &task).await;
    held.rollback().await.unwrap();
    let (toggler, locked) = finished(task).await;
    assert_eq!(locked.unwrap(), policy);
    toggler.close().await.unwrap();

    let mut held = holder.begin().await.unwrap();
    assert_eq!(
        lock_instance_security_policy(&mut held).await.unwrap(),
        policy
    );
    assert!(policy_conflicts(&pool, "FOR SHARE").await);
    assert!(policy_conflicts(&pool, "FOR NO KEY UPDATE").await);
    assert!(!policy_conflicts(&pool, "FOR KEY SHARE").await);
    // A trust write and a second toggle wait for the toggle.
    let mut waiters = Vec::new();
    let mut holders = vec![holder_pid];
    for shared in [true, false] {
        let mut waiter = pool.acquire().await.unwrap().detach();
        let waiter_pid = backend_pid(&mut waiter).await;
        let task = tokio::spawn(async move {
            let mut waiting = waiter.begin().await.unwrap();
            let locked = if shared {
                lock_instance_security_policy_shared(&mut waiting).await
            } else {
                lock_instance_security_policy(&mut waiting).await
            };
            waiting.rollback().await.unwrap();
            (waiter, locked)
        });
        wait_until_blocked_by_any(&pool, waiter_pid, &holders, &task).await;
        holders.push(waiter_pid);
        waiters.push(task);
    }
    held.rollback().await.unwrap();
    for task in waiters {
        let (waiter, locked) = finished(task).await;
        assert_eq!(locked.unwrap(), policy);
        waiter.close().await.unwrap();
    }
    holder.close().await.unwrap();
    db.drop([pool]).await;
}

fn operator_hit(
    admin: &str,
    credential: &str,
    binding: &str,
    role: AdminRole,
) -> AuthorizedOperator {
    AuthorizedOperator {
        admin_id: admin.into(),
        credential_id: credential.into(),
        binding_id: binding.into(),
        role,
    }
}

fn approver_hit() -> AuthorizedOperator {
    operator_hit("adm_sec1", "crd_adm_sec1", "rb_sec1", SEC)
}

fn requester_hit() -> AuthorizedOperator {
    operator_hit("adm_req", "crd_adm_req", "rb_req", TRUST)
}

/// The approval of `adm_req`'s request (`crd_adm_req`, `trust_admin` of
/// `ten_a`) by the operator of `key`.
async fn approve_req(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<ApprovalAuthority, RegistryError> {
    authorize_approval_locked(transaction, key, "adm_req", "crd_adm_req", TEN_A, TRUST).await
}

/// The operator rows of the approver `adm_sec1` and the requester
/// `adm_req`, by table.
const APPROVAL_ROWS: [(&str, &str); 6] = [
    ("admin_identity", "adm_sec1"),
    ("admin_identity", "adm_req"),
    ("admin_credential", "crd_adm_sec1"),
    ("admin_credential", "crd_adm_req"),
    ("admin_role_binding", "rb_sec1"),
    ("admin_role_binding", "rb_req"),
];

/// Asserts whether each row of `rows` is locked.
async fn assert_locked(pool: &PgPool, rows: &[(&str, &str)], locked: bool) {
    for &(table, id) in rows {
        assert_eq!(is_locked(pool, table, id).await, locked, "{table} {id}");
    }
}

/// An approval by another `security_admin` of the instance is authorized
/// and returns both operators' rows, which stay locked `FOR SHARE` until
/// the transaction ends: they conflict with `FOR NO KEY UPDATE`, not with
/// `FOR KEY SHARE`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_by_another_security_admin_is_authorized_and_locked() {
    let (db, pool) = seeded().await;
    let mut transaction = pool.begin().await.unwrap();
    assert_eq!(
        approve_req(&mut transaction, "key_sec1").await.unwrap(),
        ApprovalAuthority::Authorized {
            approver: approver_hit(),
            requester: requester_hit(),
        }
    );
    for (table, id) in APPROVAL_ROWS {
        assert!(
            conflicts(&pool, table, "id", id, "FOR NO KEY UPDATE").await,
            "{id}"
        );
        assert!(
            !conflicts(&pool, table, "id", id, "FOR KEY SHARE").await,
            "{id}"
        );
    }
    // Other operators' rows are not locked.
    assert_locked(
        &pool,
        &[
            ("admin_identity", "adm_sec2"),
            ("admin_credential", "crd_adm_sec1_b"),
            ("admin_role_binding", "rb_sec2"),
        ],
        false,
    )
    .await;
    transaction.commit().await.unwrap();
    assert_locked(&pool, &APPROVAL_ROWS, false).await;

    // A requester of the instance: adm_multi's security_admin binding.
    let mut transaction = pool.begin().await.unwrap();
    assert_eq!(
        authorize_approval_locked(
            &mut transaction,
            "key_sec2",
            "adm_multi",
            "crd_adm_multi",
            INSTANCE,
            SEC
        )
        .await
        .unwrap(),
        ApprovalAuthority::Authorized {
            approver: operator_hit("adm_sec2", "crd_adm_sec2", "rb_sec2", SEC),
            requester: operator_hit("adm_multi", "crd_adm_multi", "rb_multi_s", SEC),
        }
    );
    transaction.rollback().await.unwrap();
    db.drop([pool]).await;
}

/// The refusals of an approval, each decided by the first lookups with
/// nothing locked, in their order: the approver's (an unknown key, an
/// operator without instance `security_admin`, a disabled identity,
/// credential or binding, a revoked credential), then a self-approval (the
/// same `admin_id`, by any of its credentials, whatever the requester's
/// state), then the requester's (another operator's credential, an
/// unknown one, another role or scope, a disabled identity, credential or
/// binding, a revoked credential). The `admin_id` comparison is
/// byte-wise.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_refusals_of_an_approval_come_in_order_and_lock_nothing() {
    let (db, pool) = seeded().await;
    type Change = &'static str;
    let approver_misses: [(&str, Option<Change>); 6] = [
        ("key_unknown", None),
        ("key_req", None),
        (
            "key_sec2",
            Some("UPDATE admin_identity SET status = 'disabled' WHERE id = 'adm_sec2'"),
        ),
        (
            "key_sec2",
            Some("UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_sec2'"),
        ),
        (
            "key_sec2",
            Some(
                "UPDATE admin_role_binding SET status = 'disabled', revision = 2 WHERE id = 'rb_sec2'",
            ),
        ),
        (
            "key_sec2",
            Some(
                "UPDATE admin_credential SET status = 'disabled', revoked_at = now() \
                 WHERE id = 'crd_adm_sec2'",
            ),
        ),
    ];
    for (key, change) in approver_misses {
        let mut transaction = pool.begin().await.unwrap();
        if let Some(change) = change {
            sqlx::raw_sql(change)
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        assert_eq!(
            approve_req(&mut transaction, key).await.unwrap(),
            ApprovalAuthority::ApproverNotAuthorized,
            "{key} {change:?}"
        );
        assert_locked(&pool, &APPROVAL_ROWS, false).await;
        transaction.rollback().await.unwrap();
    }
    // The approver is checked first: a non-approver requester of its own.
    let mut transaction = pool.begin().await.unwrap();
    assert_eq!(
        authorize_approval_locked(
            &mut transaction,
            "key_req",
            "adm_req",
            "crd_adm_req",
            TEN_A,
            TRUST
        )
        .await
        .unwrap(),
        ApprovalAuthority::ApproverNotAuthorized
    );
    transaction.rollback().await.unwrap();

    // Self-approval, by the request's credential or another of the same
    // operator, also when the requester's credential would fail.
    for (key, credential) in [
        ("key_sec1", "crd_adm_sec1"),
        ("key_sec1_b", "crd_adm_sec1"),
        ("key_sec1", "crd_unknown"),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        assert_eq!(
            authorize_approval_locked(&mut transaction, key, "adm_sec1", credential, INSTANCE, SEC)
                .await
                .unwrap(),
            ApprovalAuthority::SelfApproval,
            "{key} {credential}"
        );
        assert_locked(&pool, &APPROVAL_ROWS, false).await;
        transaction.rollback().await.unwrap();
    }

    let requester_misses: [(&str, &str, OperatorScope<'_>, AdminRole, Option<Change>); 13] = [
        ("ADM_REQ", "crd_adm_req", TEN_A, TRUST, None),
        // Not the approver either: the comparison is byte-wise.
        ("ADM_SEC1", "crd_adm_sec1", INSTANCE, SEC, None),
        ("adm_unknown", "crd_adm_req", TEN_A, TRUST, None),
        ("adm_req", "crd_adm_sec2", TEN_A, TRUST, None),
        // The credential of another operator that holds the role.
        ("adm_req", "crd_adm_multi", TEN_A, TRUST, None),
        ("adm_req", "crd_unknown", TEN_A, TRUST, None),
        ("adm_req", "crd_adm_req", TEN_A, CLIENT, None),
        ("adm_req", "crd_adm_req", TEN_B, TRUST, None),
        ("adm_req", "crd_adm_req", INSTANCE, TRUST, None),
        (
            "adm_req",
            "crd_adm_req",
            TEN_A,
            TRUST,
            Some("UPDATE admin_identity SET status = 'disabled' WHERE id = 'adm_req'"),
        ),
        (
            "adm_req",
            "crd_adm_req",
            TEN_A,
            TRUST,
            Some("UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_req'"),
        ),
        (
            "adm_req",
            "crd_adm_req",
            TEN_A,
            TRUST,
            Some(
                "UPDATE admin_credential SET status = 'disabled', revoked_at = now() \
                 WHERE id = 'crd_adm_req'",
            ),
        ),
        (
            "adm_req",
            "crd_adm_req",
            TEN_A,
            TRUST,
            Some(
                "UPDATE admin_role_binding SET status = 'disabled', revision = 2 WHERE id = 'rb_req'",
            ),
        ),
    ];
    for (admin, credential, scope, role, change) in requester_misses {
        let mut transaction = pool.begin().await.unwrap();
        if let Some(change) = change {
            sqlx::raw_sql(change)
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        assert_eq!(
            authorize_approval_locked(&mut transaction, "key_sec1", admin, credential, scope, role)
                .await
                .unwrap(),
            ApprovalAuthority::RequesterNotAuthorized,
            "{admin} {credential} {scope:?} {role:?} {change:?}"
        );
        if change.is_none() {
            assert_locked(&pool, &APPROVAL_ROWS, false).await;
        }
        transaction.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

/// A change committed between an approval's lookups and its locks is
/// caught by the repeated lookups: the change holds the changed row, so
/// the lock statement waits for it (seen with `pg_blocking_pids`); once it
/// commits, a disabled approver is `ApproverNotAuthorized` and a disabled
/// requester `RequesterNotAuthorized`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_change_between_the_approval_lookup_and_its_lock_is_caught() {
    let (db, pool) = seeded().await;
    for (change, want) in [
        (
            "UPDATE admin_identity SET status = 'disabled' WHERE id = 'adm_sec1'",
            ApprovalAuthority::ApproverNotAuthorized,
        ),
        (
            "UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_sec1'",
            ApprovalAuthority::ApproverNotAuthorized,
        ),
        (
            "UPDATE admin_role_binding SET status = 'disabled', revision = 2 WHERE id = 'rb_sec1'",
            ApprovalAuthority::ApproverNotAuthorized,
        ),
        (
            "UPDATE admin_identity SET status = 'disabled' WHERE id = 'adm_req'",
            ApprovalAuthority::RequesterNotAuthorized,
        ),
        (
            "UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_req'",
            ApprovalAuthority::RequesterNotAuthorized,
        ),
        (
            "UPDATE admin_role_binding SET status = 'disabled', revision = 2 WHERE id = 'rb_req'",
            ApprovalAuthority::RequesterNotAuthorized,
        ),
    ] {
        let mut changer = pool.acquire().await.unwrap().detach();
        let mut locker = pool.acquire().await.unwrap().detach();
        let (changer_pid, locker_pid) = (
            backend_pid(&mut changer).await,
            backend_pid(&mut locker).await,
        );
        let mut changing = changer.begin().await.unwrap();
        sqlx::raw_sql(change).execute(&mut *changing).await.unwrap();
        let task = tokio::spawn(async move {
            let mut transaction = locker.begin().await.unwrap();
            let result = approve_req(&mut transaction, "key_sec1").await;
            transaction.rollback().await.unwrap();
            (locker, result)
        });
        wait_until_blocked(&pool, locker_pid, changer_pid, &task).await;
        changing.rollback().await.unwrap();
        // Rolled back: the lookups see the rows unchanged.
        let (mut locker, result) = finished(task).await;
        assert!(
            matches!(result, Ok(ApprovalAuthority::Authorized { .. })),
            "{change}: {result:?}"
        );

        let mut changing = changer.begin().await.unwrap();
        sqlx::raw_sql(change).execute(&mut *changing).await.unwrap();
        let locker_pid = backend_pid(&mut locker).await;
        let task = tokio::spawn(async move {
            let mut transaction = locker.begin().await.unwrap();
            let result = approve_req(&mut transaction, "key_sec1").await;
            transaction.rollback().await.unwrap();
            (locker, result)
        });
        wait_until_blocked(&pool, locker_pid, changer_pid, &task).await;
        // Committed: the repeat sees the change.
        changing.commit().await.unwrap();
        let (locker, result) = finished(task).await;
        assert_eq!(result.unwrap(), want, "{change}");
        locker.close().await.unwrap();
        // Undo the change for the next case.
        let undo = change
            .replace("'disabled'", "'enabled'")
            .replace("revision = 2", "revision = 3");
        sqlx::raw_sql(AssertSqlSafe(undo))
            .execute(&mut changer)
            .await
            .unwrap();
        changer.close().await.unwrap();
    }
    db.drop([pool]).await;
}

/// The locks are taken table by table in the `0005` order (identities,
/// credentials, bindings), each table's rows in ID order: while another
/// transaction holds the requester's identity (`adm_req`, which sorts
/// before the approver's `adm_sec1` but was inserted after it), the
/// approval waits holding nothing; while it holds the requester's
/// credential (`crd_adm_req`, before `crd_adm_sec1`), the approval holds
/// both identities and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_approval_locks_in_table_and_id_order() {
    let (db, pool) = seeded().await;
    for (held, locked) in [
        (("admin_identity", "adm_req"), &[][..]),
        (
            ("admin_credential", "crd_adm_req"),
            &[
                ("admin_identity", "adm_sec1"),
                ("admin_identity", "adm_req"),
            ][..],
        ),
        (("admin_role_binding", "rb_req"), &APPROVAL_ROWS[..4]),
    ] {
        let mut holder = pool.acquire().await.unwrap().detach();
        let mut locker = pool.acquire().await.unwrap().detach();
        let (holder_pid, locker_pid) = (
            backend_pid(&mut holder).await,
            backend_pid(&mut locker).await,
        );
        let mut holding = holder.begin().await.unwrap();
        sqlx::query(AssertSqlSafe(format!(
            "SELECT FROM {} WHERE id = $1 FOR NO KEY UPDATE",
            held.0
        )))
        .bind(held.1)
        .execute(&mut *holding)
        .await
        .unwrap();
        let task = tokio::spawn(async move {
            let mut transaction = locker.begin().await.unwrap();
            let result = approve_req(&mut transaction, "key_sec1").await;
            transaction.rollback().await.unwrap();
            (locker, result)
        });
        wait_until_blocked(&pool, locker_pid, holder_pid, &task).await;
        let free: Vec<(&str, &str)> = APPROVAL_ROWS
            .iter()
            .copied()
            .filter(|row| *row != held && !locked.contains(row))
            .collect();
        assert_locked(&pool, locked, true).await;
        assert_locked(&pool, &free, false).await;
        holding.rollback().await.unwrap();
        let (locker, result) = finished(task).await;
        assert!(
            matches!(result, Ok(ApprovalAuthority::Authorized { .. })),
            "{held:?}: {result:?}"
        );
        locker.close().await.unwrap();
        holder.close().await.unwrap();
    }
    db.drop([pool]).await;
}

const MULTI_ROLES: [(OperatorScope<'static>, AdminRole); 4] = [
    (TEN_A, TRUST),
    (INSTANCE, SEC),
    (TEN_A, CLIENT),
    (TEN_B, TRUST),
];

fn held(admin: &str, bindings: &[Option<&str>]) -> RolesHeld {
    RolesHeld {
        admin_id: admin.into(),
        credential_id: format!("crd_{admin}"),
        bindings: bindings.iter().map(|b| b.map(Into::into)).collect(),
    }
}

/// The requester's lookup reports, for each requested role in order, the
/// enabled binding that grants it; `None` when no listed role is held
/// (also for an empty list), for an unknown key, and for an operator whose
/// identity or credential fails. It locks the identity, the credential and
/// the held bindings `FOR SHARE`, not a binding it does not report, and a
/// miss locks nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_requesters_lookup_reports_and_locks_the_roles_held() {
    let (db, pool) = seeded().await;
    let mut transaction = pool.begin().await.unwrap();
    assert_eq!(
        authorize_roles_locked(&mut transaction, "key_req", &[(TEN_A, TRUST)])
            .await
            .unwrap(),
        Some(held("adm_req", &[Some("rb_req")]))
    );
    transaction.rollback().await.unwrap();

    let mut transaction = pool.begin().await.unwrap();
    assert_eq!(
        authorize_roles_locked(&mut transaction, "key_multi", &MULTI_ROLES)
            .await
            .unwrap(),
        Some(held(
            "adm_multi",
            &[Some("rb_multi_t"), Some("rb_multi_s"), None, None]
        ))
    );
    let multi_rows = [
        ("admin_identity", "adm_multi"),
        ("admin_credential", "crd_adm_multi"),
        ("admin_role_binding", "rb_multi_t"),
        ("admin_role_binding", "rb_multi_s"),
    ];
    for (table, id) in multi_rows {
        assert!(
            conflicts(&pool, table, "id", id, "FOR NO KEY UPDATE").await,
            "{id}"
        );
        assert!(
            !conflicts(&pool, table, "id", id, "FOR KEY SHARE").await,
            "{id}"
        );
    }
    assert!(!is_locked(&pool, "admin_role_binding", "rb_multi_c").await);
    transaction.rollback().await.unwrap();

    let mut transaction = pool.begin().await.unwrap();
    assert_eq!(
        authorize_roles_locked(
            &mut transaction,
            "key_multi",
            &[(TEN_A, CLIENT), (INSTANCE, SEC)]
        )
        .await
        .unwrap(),
        Some(held("adm_multi", &[None, Some("rb_multi_s")]))
    );
    transaction.rollback().await.unwrap();

    for (key, roles, change) in [
        ("key_multi", &[(TEN_A, CLIENT), (TEN_B, TRUST)][..], None),
        ("key_multi", &[][..], None),
        ("key_unknown", &MULTI_ROLES[..], None),
        (
            "key_multi",
            &MULTI_ROLES[..],
            Some("UPDATE admin_identity SET status = 'disabled' WHERE id = 'adm_multi'"),
        ),
        (
            "key_multi",
            &MULTI_ROLES[..],
            Some(
                "UPDATE admin_credential SET status = 'disabled', revoked_at = now() \
                 WHERE id = 'crd_adm_multi'",
            ),
        ),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        if let Some(change) = change {
            sqlx::raw_sql(change)
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        assert_eq!(
            authorize_roles_locked(&mut transaction, key, roles)
                .await
                .unwrap(),
            None,
            "{key} {roles:?} {change:?}"
        );
        if change.is_none() {
            assert_locked(&pool, &multi_rows, false).await;
        }
        transaction.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

/// A change committed between the requester's lookup and its locks is
/// caught: the lock waits for the changed row, and once the change
/// commits the repeated lookup differs, so the answer is `None`, also when
/// only one of two held roles was lost. A change rolled back leaves the
/// answer as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_change_between_the_requesters_lookup_and_its_lock_is_caught() {
    let (db, pool) = seeded().await;
    let roles = [(TEN_A, TRUST), (INSTANCE, SEC)];
    for change in [
        "UPDATE admin_identity SET status = 'disabled' WHERE id = 'adm_multi'",
        "UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_multi'",
        "UPDATE admin_role_binding SET status = 'disabled', revision = 2 WHERE id = 'rb_multi_s'",
    ] {
        for commit in [false, true] {
            let mut changer = pool.acquire().await.unwrap().detach();
            let mut locker = pool.acquire().await.unwrap().detach();
            let (changer_pid, locker_pid) = (
                backend_pid(&mut changer).await,
                backend_pid(&mut locker).await,
            );
            let mut changing = changer.begin().await.unwrap();
            sqlx::raw_sql(change).execute(&mut *changing).await.unwrap();
            let task = tokio::spawn(async move {
                let mut transaction = locker.begin().await.unwrap();
                let result = authorize_roles_locked(&mut transaction, "key_multi", &roles).await;
                transaction.rollback().await.unwrap();
                (locker, result)
            });
            wait_until_blocked(&pool, locker_pid, changer_pid, &task).await;
            if commit {
                changing.commit().await.unwrap();
            } else {
                changing.rollback().await.unwrap();
            }
            let (locker, result) = finished(task).await;
            let want =
                (!commit).then(|| held("adm_multi", &[Some("rb_multi_t"), Some("rb_multi_s")]));
            assert_eq!(result.unwrap(), want, "{change} {commit}");
            locker.close().await.unwrap();
            if commit {
                let undo = change
                    .replace("'disabled'", "'enabled'")
                    .replace("revision = 2", "revision = 3");
                sqlx::raw_sql(AssertSqlSafe(undo))
                    .execute(&mut changer)
                    .await
                    .unwrap();
            }
            changer.close().await.unwrap();
        }
    }
    db.drop([pool]).await;
}
