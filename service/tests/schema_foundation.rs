//! Constraints and guards of the `0002_foundation` migration against a real
//! PostgreSQL server: tenants, principals, the instance security policy, the
//! egress allowlist and the audit hash chain.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use common::TestDb;
use skyoauth_service::persistence::{self, PgPool};
use sqlx::{Executor, PgConnection, Postgres};

const TENANTS: &str = "INSERT INTO tenant VALUES
    ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled')";
const POLICY: &str = "INSERT INTO instance_security_policy
    (instance_id, audit_sink_config_digest) VALUES ('inst_1', '\\x01')";

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

async fn run<'c>(executor: impl Executor<'c, Database = Postgres>, sql: &'static str) {
    if let Err(err) = sqlx::raw_sql(sql).execute(executor).await {
        panic!("{sql}: {err}");
    }
}

fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
        .unwrap_or_else(|| panic!("not a database error: {err}"))
}

/// Runs each case on its own and checks that it fails with its SQLSTATE.
/// A case is one line, `<SQLSTATE> <statement>`; blank lines are skipped.
/// SK001 is the guard triggers' state; 23502 is `not_null_violation`, 23503
/// `foreign_key_violation`, 23505 `unique_violation` and 23514
/// `check_violation`.
async fn assert_rejected(conn: &mut PgConnection, cases: &'static str) {
    for case in cases.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (code, sql) = case.split_once(' ').unwrap();
        let err = sqlx::raw_sql(sql).execute(&mut *conn).await.expect_err(sql);
        assert_eq!(sqlstate(&err), code, "{sql}: {err}");
    }
}

async fn rejects(pool: &PgPool, cases: &'static str) {
    assert_rejected(&mut pool.acquire().await.unwrap(), cases).await;
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

/// Appends audit event `sequence` and advances the chain head to it in one
/// transaction, as the service does.
async fn append(
    pool: &PgPool,
    sequence: i64,
    prev_hash: Option<&[u8]>,
    hash: &[u8],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO audit_event
             (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome)
         VALUES ($1, $2, $3, now(), 'adm_1', 'tenant_create', 'ten_a', 'success')",
    )
    .bind(format!("evt_{sequence}"))
    .bind(sequence)
    .bind(prev_hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE audit_chain_head SET sequence = $1, head_hash = $2")
        .bind(sequence)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

async fn head(pool: &PgPool) -> (i64, Option<Vec<u8>>) {
    sqlx::query_as("SELECT sequence, head_hash FROM audit_chain_head")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn foundation_migration_is_recorded_once_and_rerun_is_a_no_op() {
    let (db, pool) = migrated().await;
    let recorded = || async {
        sqlx::query_as::<_, (i64, String, bool)>(
            "SELECT version, description, success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    let first = recorded().await;
    assert!(first.contains(&(2, "foundation".into(), true)), "{first:?}");

    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    assert_eq!(head(&pool).await, (0, None));
    assert_eq!(
        count(&pool, "SELECT count(*) FROM audit_chain_head").await,
        1
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn tenant_secret_namespace_is_unique_non_null_and_immutable() {
    let (db, pool) = migrated().await;
    run(&pool, TENANTS).await;
    rejects(
        &pool,
        "
        23505 INSERT INTO tenant VALUES ('ten_c', 'c', 'ns_a', 'enabled')
        23502 INSERT INTO tenant VALUES ('ten_c', 'c', NULL, 'enabled')
        23514 INSERT INTO tenant VALUES ('ten_c', 'c', '', 'enabled')
        23514 INSERT INTO tenant VALUES ('ten_c', 'c', 'ns_c', 'active')
        SK001 UPDATE tenant SET secret_namespace = 'ns_z' WHERE id = 'ten_a'
        SK001 UPDATE tenant SET id = 'ten_z' WHERE id = 'ten_a'
        SK001 UPDATE tenant SET created_at = now() - interval '1 day'
    ",
    )
    .await;
    // Name and status stay writable.
    run(&pool, "UPDATE tenant SET name = 'x', status = 'disabled'").await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn principal_belongs_to_one_tenant_and_backs_composite_references() {
    let (db, pool) = migrated().await;
    run(&pool, TENANTS).await;
    run(
        &pool,
        "INSERT INTO principal VALUES
             ('wld_1', 'ten_a', 'workload', 'deployer', 'enabled'),
             ('svc_1', 'ten_a', 'service', 'billing', 'enabled'),
             ('usr_1', 'ten_b', 'human', 'alice', 'enabled');
         -- A later tenant-owned table references (tenant_id, id).
         CREATE TABLE owned (
             tenant_id text NOT NULL,
             principal_id text NOT NULL,
             FOREIGN KEY (tenant_id, principal_id) REFERENCES principal (tenant_id, id)
         );
         INSERT INTO owned VALUES ('ten_a', 'wld_1')",
    )
    .await;
    rejects(
        &pool,
        "
        23503 INSERT INTO principal VALUES ('wld_2', 'ten_x', 'workload', 'w', 'enabled')
        23514 INSERT INTO principal VALUES ('adm_1', 'ten_a', 'operator', 'o', 'enabled')
        23503 INSERT INTO owned VALUES ('ten_b', 'wld_1')
        SK001 UPDATE principal SET tenant_id = 'ten_b' WHERE id = 'svc_1'
        SK001 UPDATE principal SET kind = 'workload' WHERE id = 'svc_1'
        SK001 UPDATE principal SET id = 'svc_2' WHERE id = 'svc_1'
    ",
    )
    .await;
    run(
        &pool,
        "UPDATE principal SET name = 'x', status = 'disabled'",
    )
    .await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn instance_security_policy_is_one_row_with_safe_defaults() {
    let (db, pool) = migrated().await;
    rejects(&pool, r"
        23502 INSERT INTO instance_security_policy (instance_id) VALUES ('inst_1')
        23514 INSERT INTO instance_security_policy (instance_id, audit_sink_config_digest) VALUES ('inst_1', '\x')
        SK001 INSERT INTO instance_security_policy (instance_id, audit_sink_config_digest, revision) VALUES ('inst_1', '\x01', 2)
    ").await;
    run(&pool, POLICY).await;
    let row: (bool, bool, bool, i64) = sqlx::query_as(
        "SELECT widening_second_approver, single_actor_mode,
                audit_sink_validated_at IS NULL, revision
         FROM instance_security_policy",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (false, false, true, 1));
    rejects(&pool, r"
        23505 INSERT INTO instance_security_policy (instance_id, audit_sink_config_digest) VALUES ('inst_2', '\x02')
    ").await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn instance_security_policy_revision_advances_by_one_and_row_is_kept() {
    let (db, pool) = migrated().await;
    run(&pool, POLICY).await;
    run(
        &pool,
        "UPDATE instance_security_policy
         SET widening_second_approver = true, revision = revision + 1",
    )
    .await;
    rejects(
        &pool,
        "
        SK001 UPDATE instance_security_policy SET widening_second_approver = false
        SK001 UPDATE instance_security_policy SET revision = revision + 2
        SK001 UPDATE instance_security_policy SET revision = 1
        SK001 UPDATE instance_security_policy SET instance_id = 'x', revision = revision + 1
        SK001 DELETE FROM instance_security_policy
        SK001 TRUNCATE instance_security_policy
    ",
    )
    .await;
    let row: (bool, i64) =
        sqlx::query_as("SELECT widening_second_approver, revision FROM instance_security_policy")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (true, 2));
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn egress_entry_purpose_is_checked_and_unique_per_destination() {
    let (db, pool) = migrated().await;
    // The same destination under another purpose is a separate entry.
    run(
        &pool,
        "INSERT INTO egress_allowlist_entry VALUES
             ('egr_1', 'oidc_discovery', 'https://idp.example:443/.well-known/x', 'enabled'),
             ('egr_2', 'jwks', 'https://idp.example:443/.well-known/x', 'enabled')",
    )
    .await;
    rejects(&pool, "
        23505 INSERT INTO egress_allowlist_entry VALUES ('egr_3', 'oidc_discovery', 'https://idp.example:443/.well-known/x', 'disabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_3', 'webhook', 'https://hook.example:443/', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_3', 'jwks', 'https://keys.example:443/', 'degraded')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_3', 'token_review', '', 'enabled')
        SK001 INSERT INTO egress_allowlist_entry VALUES ('egr_3', 'jwks', 'https://keys.example:443/', 'enabled', 3)
    ").await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn egress_entry_changes_only_status_and_is_never_deleted() {
    let (db, pool) = migrated().await;
    run(
        &pool,
        "INSERT INTO egress_allowlist_entry VALUES
             ('egr_1', 'token_review', 'https://k8s.example:6443/', 'enabled');
         UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1",
    )
    .await;
    rejects(&pool, "
        SK001 UPDATE egress_allowlist_entry SET exact_destination = 'https://k9s.example:6443/', revision = revision + 1
        SK001 UPDATE egress_allowlist_entry SET purpose = 'jwks', revision = revision + 1
        SK001 UPDATE egress_allowlist_entry SET id = 'egr_2', revision = revision + 1
        SK001 UPDATE egress_allowlist_entry SET status = 'enabled'
        SK001 UPDATE egress_allowlist_entry SET status = 'enabled', revision = 1
        SK001 DELETE FROM egress_allowlist_entry
        SK001 TRUNCATE egress_allowlist_entry
    ").await;
    let row: (String, i64) = sqlx::query_as("SELECT status, revision FROM egress_allowlist_entry")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row, ("disabled".into(), 2));
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_chain_appends_in_order_and_head_tracks_the_last_event() {
    let (db, pool) = migrated().await;
    let first_with_prev = append(&pool, 1, Some(b"h0"), b"h1").await.unwrap_err();
    assert_eq!(sqlstate(&first_with_prev), "SK001");

    append(&pool, 1, None, b"h1").await.unwrap();
    append(&pool, 2, Some(b"h1"), b"h2").await.unwrap();
    assert_eq!(head(&pool).await, (2, Some(b"h2".to_vec())));

    for (sequence, prev_hash) in [
        (4, Some(&b"h2"[..])), // gap
        (2, Some(&b"h2"[..])), // reused sequence
        (1, None),             // older sequence
        (3, Some(&b"h1"[..])), // wrong previous hash
        (3, None),             // missing previous hash
    ] {
        let err = append(&pool, sequence, prev_hash, b"hx").await.unwrap_err();
        assert_eq!(sqlstate(&err), "SK001", "{sequence} {prev_hash:?}: {err}");
    }

    // The head moves one step at a time, only to an event that exists.
    rejects(
        &pool,
        r"
        SK001 UPDATE audit_chain_head SET sequence = 3, head_hash = '\x03'
        SK001 UPDATE audit_chain_head SET sequence = 1, head_hash = '\x01'
        SK001 UPDATE audit_chain_head SET head_hash = '\x09'
        SK001 DELETE FROM audit_chain_head
        SK001 TRUNCATE audit_chain_head
    ",
    )
    .await;
    assert_eq!(head(&pool).await, (2, Some(b"h2".to_vec())));
    assert_eq!(count(&pool, "SELECT count(*) FROM audit_event").await, 2);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_event_without_head_advance_fails_at_commit() {
    let (db, pool) = migrated().await;
    let mut tx = pool.begin().await.unwrap();
    run(
        &mut *tx,
        "INSERT INTO audit_event (id, sequence, timestamp, actor, action, object_id, outcome)
         VALUES ('evt_1', 1, now(), 'adm_1', 'tenant_create', 'ten_a', 'success')",
    )
    .await;
    let err = tx.commit().await.unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");
    assert_eq!(count(&pool, "SELECT count(*) FROM audit_event").await, 0);
    assert_eq!(head(&pool).await, (0, None));
    db.drop([pool]).await;
}

/// Runs, on one connection after `setup`, writes that the foundation guards
/// must reject with SK001.
async fn assert_guards_hold(pool: &PgPool, setup: &'static str) {
    run(pool, TENANTS).await;
    run(pool, POLICY).await;
    run(
        pool,
        "INSERT INTO egress_allowlist_entry VALUES
             ('egr_1', 'jwks', 'https://keys.example:443/', 'enabled')",
    )
    .await;
    append(pool, 1, None, b"h1").await.unwrap();

    let mut conn = pool.acquire().await.unwrap();
    run(&mut *conn, setup).await;
    assert_rejected(&mut conn, r"
        SK001 UPDATE audit_event SET outcome = 'denied'
        SK001 DELETE FROM audit_event
        SK001 TRUNCATE audit_event
        SK001 INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome) VALUES ('evt_9', 9, '\x09', now(), 'adm_1', 'x', 'ten_a', 'success')
        SK001 UPDATE audit_chain_head SET sequence = 5, head_hash = '\x05'
        SK001 DELETE FROM audit_chain_head
        SK001 UPDATE tenant SET secret_namespace = 'ns_z' WHERE id = 'ten_a'
        SK001 UPDATE instance_security_policy SET single_actor_mode = true
        SK001 DELETE FROM instance_security_policy
        SK001 UPDATE egress_allowlist_entry SET purpose = 'token_review', revision = 2
        SK001 DELETE FROM egress_allowlist_entry
    ").await;
    conn.close().await.unwrap();
    assert_eq!(count(pool, "SELECT count(*) FROM audit_event").await, 1);
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn foundation_guards_reject_forbidden_writes() {
    let (db, pool) = migrated().await;
    assert_guards_hold(&pool, "SET session_replication_role = origin").await;
    db.drop([pool]).await;
}

/// `ENABLE ALWAYS` keeps the guards firing in replica mode, which would
/// otherwise skip ordinary triggers. Setting the mode needs a superuser.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn foundation_guards_hold_under_replica_role() {
    let (db, pool) = migrated().await;
    assert_guards_hold(&pool, "SET session_replication_role = replica").await;
    db.drop([pool]).await;
}
