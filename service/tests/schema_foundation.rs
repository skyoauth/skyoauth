//! Constraints and guards of the `0002_foundation` migration against a real
//! PostgreSQL server: tenants, principals, the instance security policy, the
//! egress allowlist and the audit hash chain.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database, and the search-path test also a
//! login role. The URL's role must therefore be able to create roles too
//! (as the superuser of the CI service container can).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::time::Duration;

use common::TestDb;
use skyoauth_service::persistence::{self, PgPool};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Postgres};

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

/// Inserts audit event `sequence`, without advancing the chain head.
async fn insert_event(
    conn: &mut PgConnection,
    sequence: i64,
    prev_hash: Option<&[u8]>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_event
             (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome)
         VALUES ($1, $2, $3, now(), 'adm_1', 'tenant_create', 'ten_a', 'success')",
    )
    .bind(format!("evt_{sequence}"))
    .bind(sequence)
    .bind(prev_hash)
    .execute(&mut *conn)
    .await
    .map(drop)
}

async fn advance_head(
    conn: &mut PgConnection,
    sequence: i64,
    hash: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE audit_chain_head SET sequence = $1, head_hash = $2")
        .bind(sequence)
        .bind(hash)
        .execute(&mut *conn)
        .await
        .map(drop)
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
    insert_event(&mut tx, sequence, prev_hash).await?;
    advance_head(&mut tx, sequence, hash).await?;
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

const FOUNDATION_TABLES: [&str; 6] = [
    "tenant",
    "principal",
    "instance_security_policy",
    "egress_allowlist_entry",
    "audit_event",
    "audit_chain_head",
];

/// Catalog properties that behaviour tests cannot see directly.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn foundation_catalog_pins_collation_triggers_indexes_and_search_path() {
    let (db, pool) = migrated().await;
    let tables: Vec<String> = FOUNDATION_TABLES.iter().map(|t| t.to_string()).collect();

    // Every guard trigger fires in every session_replication_role.
    let triggers: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, t.tgenabled::text
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
         WHERE NOT t.tgisinternal AND c.relnamespace = to_regnamespace(current_schema())
           AND c.relname = ANY($1)
         ORDER BY 1, 2",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    for table in FOUNDATION_TABLES {
        assert!(
            triggers.iter().any(|(t, _, _)| t == table),
            "{table}: {triggers:?}"
        );
    }
    let not_always: Vec<_> = triggers.iter().filter(|(_, _, e)| e != "A").collect();
    assert!(not_always.is_empty(), "{not_always:?}");

    // IDs, keys and references compare byte-wise; only human text does not.
    let not_c: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = ANY($1)
           AND data_type = 'text' AND collation_name IS DISTINCT FROM 'C'
         ORDER BY 1, 2",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    let human_text = [
        ("audit_event", "outcome"),
        ("principal", "name"),
        ("tenant", "name"),
    ];
    let human_text: Vec<(String, String)> = human_text
        .iter()
        .map(|(t, c)| (t.to_string(), c.to_string()))
        .collect();
    assert_eq!(not_c, human_text);

    let index: String = sqlx::query_scalar(
        "SELECT pg_get_indexdef('audit_event_tenant_id_sequence_idx'::regclass)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        index.ends_with("USING btree (tenant_id, sequence)"),
        "{index}"
    );

    // The service supplies the hashed timestamp.
    let default: Option<String> = sqlx::query_scalar(
        "SELECT column_default::text FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = 'audit_event'
           AND column_name = 'timestamp'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(default, None);

    // The chain functions pin search_path and name every table with the
    // schema, so neither the caller's path nor a temporary table matters.
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let functions: Vec<(String, Option<Vec<String>>, String)> = sqlx::query_as(
        "SELECT proname::text, proconfig, prosrc FROM pg_proc
         WHERE proname IN ('skyoauth_audit_event_extends_head',
                           'skyoauth_audit_event_head_reached',
                           'skyoauth_audit_chain_head_advance')
         ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(functions.len(), 3);
    for (name, config, source) in &functions {
        assert_eq!(
            config.as_deref(),
            Some(&[format!("search_path=pg_catalog, {schema}, pg_temp")][..]),
            "{name}"
        );
        let mut tables = 0;
        for table in ["audit_chain_head", "audit_event"] {
            for (at, _) in source.match_indices(table) {
                assert!(
                    source[..at].ends_with(&format!("{schema}.")),
                    "{name} names {table} without its schema: {source}"
                );
                tables += 1;
            }
        }
        assert!(tables > 0, "{name}: {source}");
    }
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
             tenant_id text COLLATE \"C\" NOT NULL,
             principal_id text COLLATE \"C\" NOT NULL,
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

/// A guard argument that names no column is a plain error, not SK001, so a
/// typo in a later migration fails the first update instead of passing it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn immutable_column_guard_with_an_unknown_column_is_an_error() {
    let (db, pool) = migrated().await;
    run(
        &pool,
        "CREATE TABLE typo (id text PRIMARY KEY, name text);
         CREATE TRIGGER typo_immutable BEFORE UPDATE ON typo
             FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_immutable_change('id', 'nmae');
         INSERT INTO typo VALUES ('x', 'n')",
    )
    .await;
    let err = sqlx::raw_sql("UPDATE typo SET name = 'm'")
        .execute(&pool)
        .await
        .unwrap_err();
    // P0001 is raise_exception, PL/pgSQL's default.
    assert_eq!(sqlstate(&err), "P0001", "{err}");
    assert!(
        err.to_string().contains("names unknown column nmae"),
        "{err}"
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn instance_security_policy_is_one_row_with_safe_defaults() {
    let (db, pool) = migrated().await;
    rejects(&pool, r"
        23514 INSERT INTO instance_security_policy (instance_id, audit_sink_config_digest) VALUES ('inst_1', '\x')
        23514 INSERT INTO instance_security_policy (instance_id, audit_sink_validated_at) VALUES ('inst_1', now())
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
        23505 INSERT INTO instance_security_policy (instance_id) VALUES ('inst_2')
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

/// A NULL digest means no sink is configured; `audit_sink_validated_at`
/// needs a digest and cannot outlive a change of it (IR-053).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_sink_validation_belongs_to_the_current_digest() {
    let (db, pool) = migrated().await;
    run(
        &pool,
        "INSERT INTO instance_security_policy (instance_id) VALUES ('inst_1')",
    )
    .await;
    rejects(
        &pool,
        "
        23514 UPDATE instance_security_policy SET audit_sink_validated_at = now(), revision = revision + 1
    ",
    )
    .await;
    // From no validation, any validation time may come with the digest.
    run(
        &pool,
        r"UPDATE instance_security_policy SET audit_sink_config_digest = '\x01',
              audit_sink_validated_at = '2026-01-01T00:00:00Z', revision = revision + 1",
    )
    .await;
    rejects(&pool, r"
        SK001 UPDATE instance_security_policy SET audit_sink_config_digest = '\x02', revision = revision + 1
        SK001 UPDATE instance_security_policy SET audit_sink_config_digest = '\x02', audit_sink_validated_at = '2026-01-01T00:00:00Z', revision = revision + 1
        SK001 UPDATE instance_security_policy SET audit_sink_config_digest = '\x02', audit_sink_validated_at = '2025-12-31T00:00:00Z', revision = revision + 1
        SK001 UPDATE instance_security_policy SET audit_sink_config_digest = NULL, revision = revision + 1
        23514 UPDATE instance_security_policy SET audit_sink_config_digest = NULL, audit_sink_validated_at = '2026-01-02T00:00:00Z', revision = revision + 1
        23514 UPDATE instance_security_policy SET audit_sink_config_digest = '\x', audit_sink_validated_at = NULL, revision = revision + 1
    ").await;
    run(
        &pool,
        r"UPDATE instance_security_policy SET audit_sink_config_digest = '\x02',
              audit_sink_validated_at = '2026-01-02T00:00:00Z', revision = revision + 1;
          UPDATE instance_security_policy SET audit_sink_config_digest = '\x03',
              audit_sink_validated_at = NULL, revision = revision + 1;
          UPDATE instance_security_policy SET audit_sink_validated_at = '2026-01-03T00:00:00Z',
              revision = revision + 1",
    )
    .await;
    let row: (Option<Vec<u8>>, bool, i64) = sqlx::query_as(
        "SELECT audit_sink_config_digest, audit_sink_validated_at IS NOT NULL, revision
         FROM instance_security_policy",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (Some(vec![3]), true, 5));
    // Removing the sink clears the validation with it.
    run(
        &pool,
        "UPDATE instance_security_policy SET audit_sink_config_digest = NULL,
             audit_sink_validated_at = NULL, revision = revision + 1",
    )
    .await;
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

/// The database keeps whitespace, control characters and oversized values
/// out of the unique destination; URL syntax is the service's.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn egress_destination_has_no_whitespace_or_controls_and_is_bounded() {
    let (db, pool) = migrated().await;
    rejects(&pool, r"
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', ' https://keys.example:443/', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', 'https://keys.example:443/ ', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', 'https://keys.example:443/a b', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', E'https://keys.example:443/\t', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', E'https://keys.example:443/\r\n', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', E'https://keys.example:443/\x01', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', E'https://keys.example:443/\x7f', 'enabled')
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', 'https://k.example/' || repeat('a', 2031), 'enabled')
    ").await;
    // 2048 bytes is the largest accepted value.
    run(
        &pool,
        "INSERT INTO egress_allowlist_entry VALUES
             ('egr_1', 'jwks', 'https://k.example/' || repeat('a', 2030), 'enabled')",
    )
    .await;
    assert_eq!(
        count(
            &pool,
            "SELECT octet_length(exact_destination)::bigint FROM egress_allowlist_entry"
        )
        .await,
        2048
    );
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

/// The insert itself is checked against the head, inside the open
/// transaction; the head and commit checks are not the only line.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_event_insert_must_extend_the_head_before_commit() {
    let (db, pool) = migrated().await;
    append(&pool, 1, None, b"h1").await.unwrap();
    append(&pool, 2, Some(b"h1"), b"h2").await.unwrap();

    for (sequence, prev_hash) in [
        (4, Some(&b"h3"[..])), // ahead of the head
        (3, Some(&b"h1"[..])), // next sequence, wrong previous hash
        (3, None),             // next sequence, no previous hash
    ] {
        let mut tx = pool.begin().await.unwrap();
        let err = insert_event(&mut tx, sequence, prev_hash)
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&err), "SK001", "{sequence} {prev_hash:?}: {err}");
        tx.rollback().await.unwrap();
    }

    // Out of order: 4 first, then 3 with a wrong previous hash, then the
    // head through both. The first insert must already fail.
    let mut tx = pool.begin().await.unwrap();
    let steps = async {
        insert_event(&mut tx, 4, Some(b"h3"))
            .await
            .map_err(|e| (1, e))?;
        insert_event(&mut tx, 3, Some(b"hx"))
            .await
            .map_err(|e| (2, e))?;
        advance_head(&mut tx, 3, b"h3").await.map_err(|e| (3, e))?;
        advance_head(&mut tx, 4, b"h4").await.map_err(|e| (4, e))?;
        Ok::<_, (u32, sqlx::Error)>(())
    };
    let (step, err) = steps.await.unwrap_err();
    assert_eq!((step, sqlstate(&err)), (1, "SK001".into()), "{err}");
    tx.rollback().await.unwrap();

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

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_event_references_its_tenant_and_needs_a_unique_sequence_and_timestamp() {
    let (db, pool) = migrated().await;
    run(&pool, TENANTS).await;
    rejects(&pool, "
        23503 INSERT INTO audit_event (id, tenant_id, sequence, timestamp, actor, action, object_id, outcome) VALUES ('evt_1', 'ten_x', 1, now(), 'adm_1', 'principal_create', 'wld_1', 'success')
        23502 INSERT INTO audit_event (id, tenant_id, sequence, actor, action, object_id, outcome) VALUES ('evt_1', 'ten_a', 1, 'adm_1', 'principal_create', 'wld_1', 'success')
    ").await;
    let mut tx = pool.begin().await.unwrap();
    run(
        &mut *tx,
        "INSERT INTO audit_event (id, tenant_id, sequence, timestamp, actor, action, object_id, outcome)
         VALUES ('evt_1', 'ten_a', 1, now(), 'adm_1', 'principal_create', 'wld_1', 'success');
         UPDATE audit_chain_head SET sequence = 1, head_hash = '\\x01'",
    )
    .await;
    tx.commit().await.unwrap();

    // The chain trigger rejects a reused sequence first; with the owner's
    // user triggers disabled, the unique constraint still does.
    let mut tx = pool.begin().await.unwrap();
    run(&mut *tx, "ALTER TABLE audit_event DISABLE TRIGGER USER").await;
    assert_rejected(&mut tx, "
        23505 INSERT INTO audit_event (id, sequence, timestamp, actor, action, object_id, outcome) VALUES ('evt_2', 1, now(), 'adm_1', 'x', 'ten_a', 'success')
    ").await;
    tx.rollback().await.unwrap();
    assert_eq!(count(&pool, "SELECT count(*) FROM audit_event").await, 1);
    db.drop([pool]).await;
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
    .expect("the second appender never waited for the head lock");
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// The chain trigger locks the head, so a second appender waits for the
/// first to commit and is then checked against the committed head (READ
/// COMMITTED, the default): a sequence taken from the old head fails with
/// SK001, and one taken by locking the head first succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_appenders_queue_on_the_chain_head() {
    let (db, pool) = migrated().await;
    append(&pool, 1, None, b"h1").await.unwrap();
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );

    // A stale appender: it read head 1 before the first appender moved it.
    run(&mut first, "BEGIN").await;
    insert_event(&mut first, 2, Some(b"h1")).await.unwrap();
    run(&mut second, "BEGIN").await;
    let stale = tokio::spawn(async move {
        let result = insert_event(&mut second, 2, Some(b"h1")).await;
        (second, result)
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    assert!(!stale.is_finished());
    advance_head(&mut first, 2, b"h2").await.unwrap();
    run(&mut first, "COMMIT").await;
    let (mut second, result) = stale.await.unwrap();
    let err = result.unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");
    run(&mut second, "ROLLBACK").await;

    // The service's way: lock the head, then take the next sequence.
    run(&mut first, "BEGIN").await;
    let locked: (i64, Vec<u8>) =
        sqlx::query_as("SELECT sequence, head_hash FROM audit_chain_head FOR UPDATE")
            .fetch_one(&mut first)
            .await
            .unwrap();
    assert_eq!(locked, (2, b"h2".to_vec()));
    insert_event(&mut first, 3, Some(b"h2")).await.unwrap();
    run(&mut second, "BEGIN").await;
    let queued = tokio::spawn(async move {
        let result: Result<(i64, Vec<u8>), _> =
            sqlx::query_as("SELECT sequence, head_hash FROM audit_chain_head FOR UPDATE")
                .fetch_one(&mut second)
                .await;
        (second, result)
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    advance_head(&mut first, 3, b"h3").await.unwrap();
    run(&mut first, "COMMIT").await;
    let (mut second, locked) = queued.await.unwrap();
    let (sequence, hash) = locked.unwrap();
    assert_eq!((sequence, &hash[..]), (3, &b"h3"[..]));
    insert_event(&mut second, sequence + 1, Some(&hash))
        .await
        .unwrap();
    advance_head(&mut second, sequence + 1, b"h4")
        .await
        .unwrap();
    run(&mut second, "COMMIT").await;

    assert_eq!(head(&pool).await, (4, Some(b"h4".to_vec())));
    assert_eq!(count(&pool, "SELECT count(*) FROM audit_event").await, 4);
    first.close().await.unwrap();
    second.close().await.unwrap();
    db.drop([pool]).await;
}

/// The chain functions resolve their tables through a pinned search_path,
/// not the caller's: a role with only DML grants cannot shadow them with
/// temporary tables, and an empty search_path (logical-replication apply,
/// data-only restore) still works.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_chain_guards_ignore_the_callers_search_path() {
    let (mut db, pool) = migrated().await;
    let (role, connect) = db.create_login_role().await;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT SELECT, INSERT, UPDATE ON audit_event, audit_chain_head TO {role}"
    )))
    .execute(&pool)
    .await
    .unwrap();

    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    let superuser: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&mut writer)
            .await
            .unwrap();
    assert!(!superuser);
    let owner: String = sqlx::query_scalar(
        "SELECT tableowner::text FROM pg_tables WHERE tablename = 'audit_chain_head'",
    )
    .fetch_one(&mut writer)
    .await
    .unwrap();
    assert_ne!(owner, role);

    // Rule 1: a forged head in pg_temp does not make event 42 extend it.
    // The insert itself fails, inside the transaction, not only the commit.
    run(
        &mut writer,
        r"CREATE TEMP TABLE audit_chain_head (singleton boolean, sequence bigint, head_hash bytea);
          INSERT INTO pg_temp.audit_chain_head VALUES (true, 41, '\x41')",
    )
    .await;
    run(&mut writer, "BEGIN").await;
    let err = insert_event(&mut writer, 42, Some(b"\x41"))
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");
    run(&mut writer, "ROLLBACK").await;

    // Rule 3: advancing only the shadow head does not pass the commit check.
    run(&mut writer, "BEGIN").await;
    insert_event(&mut writer, 1, None).await.unwrap();
    run(
        &mut writer,
        r"UPDATE audit_chain_head SET sequence = 1, head_hash = '\x01'",
    )
    .await;
    let err = sqlx::raw_sql("COMMIT")
        .execute(&mut writer)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");

    // Rule 2: a shadow event does not let the real head advance.
    run(
        &mut writer,
        "CREATE TEMP TABLE audit_event (sequence bigint);
         INSERT INTO pg_temp.audit_event VALUES (1)",
    )
    .await;
    assert_rejected(
        &mut writer,
        r"SK001 UPDATE public.audit_chain_head SET sequence = 1, head_hash = '\x01'",
    )
    .await;
    writer.close().await.unwrap();
    assert_eq!(head(&pool).await, (0, None));
    assert_eq!(count(&pool, "SELECT count(*) FROM audit_event").await, 0);

    // An empty search_path, as logical-replication apply and pg_dump set.
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    run(
        &mut writer,
        r"SET search_path = '';
          BEGIN;
          INSERT INTO public.audit_event (id, sequence, timestamp, actor, action, object_id, outcome)
              VALUES ('evt_1', 1, now(), 'adm_1', 'x', 'inst_1', 'success');
          UPDATE public.audit_chain_head SET sequence = 1, head_hash = '\x01';
          COMMIT",
    )
    .await;
    writer.close().await.unwrap();
    assert_eq!(head(&pool).await, (1, Some(vec![1])));
    db.drop([pool]).await;
}

/// Runs, on one connection after `setup`, writes that the foundation guards
/// must reject with SK001.
async fn assert_guards_hold(pool: &PgPool, setup: &'static str) {
    run(pool, TENANTS).await;
    run(
        pool,
        r"INSERT INTO instance_security_policy
              (instance_id, audit_sink_config_digest, audit_sink_validated_at)
          VALUES ('inst_1', '\x01', now())",
    )
    .await;
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
        SK001 UPDATE instance_security_policy SET audit_sink_config_digest = '\x02', revision = revision + 1
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
    // No session setup: this runs in the default replication mode and
    // needs no superuser.
    assert_guards_hold(&pool, "SELECT 1").await;
    db.drop([pool]).await;
}

/// `ENABLE ALWAYS` keeps the guards firing in replica mode, which would
/// otherwise skip ordinary triggers. Setting the mode needs a superuser.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn foundation_guards_hold_under_replica_role() {
    let (db, pool) = migrated().await;
    assert_guards_hold(&pool, "SET session_replication_role = replica").await;
    // Foreign keys, unlike the guards, are not enforced in replica mode
    // (a limit recorded in migrations/README.md).
    let mut conn = pool.acquire().await.unwrap();
    run(
        &mut *conn,
        "SET session_replication_role = replica;
         INSERT INTO principal VALUES ('wld_9', 'ten_missing', 'workload', 'w', 'enabled')",
    )
    .await;
    conn.close().await.unwrap();
    db.drop([pool]).await;
}
