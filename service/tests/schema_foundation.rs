//! Constraints and guards of the `0002_foundation` migration against a real
//! PostgreSQL server: tenants, principals, the instance security policy, the
//! egress allowlist and the audit hash chain.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database, and the search-path tests also a
//! login role. The URL's role therefore needs `CREATEROLE` too, and the
//! replica-role test `SET` on `session_replication_role` (`common/mod.rs`).
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

/// As one [`assert_rejected`] case, and also checks the error message, so a
/// statement that names several tables shows which one rejected it.
async fn assert_rejected_with_message(
    conn: &mut PgConnection,
    code: &str,
    sql: &'static str,
    message: &str,
) {
    let err = sqlx::raw_sql(sql).execute(&mut *conn).await.expect_err(sql);
    assert_eq!(sqlstate(&err), code, "{sql}: {err}");
    let text = err.as_database_error().unwrap().message().to_string();
    assert_eq!(text, message, "{sql}");
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
    append_on(&mut *pool.acquire().await?, sequence, prev_hash, hash).await
}

/// [`append`] on a given connection.
async fn append_on(
    conn: &mut PgConnection,
    sequence: i64,
    prev_hash: Option<&[u8]>,
    hash: &[u8],
) -> Result<(), sqlx::Error> {
    let mut tx = conn.begin().await?;
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

/// Functions of the `0001` migration that pin no `search_path`. Each
/// must resolve no names through the caller's path: `skyoauth_reject_mutation`
/// only raises with `TG_OP` and `TG_TABLE_NAME`.
const UNPINNED_FROZEN_FUNCTIONS: [&str; 1] = ["skyoauth_reject_mutation"];

/// Functions that read tables, so pin the migration's schema too.
const TABLE_READING_FUNCTIONS: [&str; 3] = [
    "skyoauth_audit_chain_head_advance",
    "skyoauth_audit_event_extends_head",
    "skyoauth_audit_event_head_reached",
];

const BUILTIN_ONLY_FUNCTIONS: [&str; 3] = [
    "skyoauth_check_revision",
    "skyoauth_check_sink_validation",
    "skyoauth_reject_immutable_change",
];

/// Every function the migrations created in the current schema, other than
/// extension members and [`UNPINNED_FROZEN_FUNCTIONS`], pins `search_path`
/// to `pg_catalog`, optionally the schema, and `pg_temp` last; functions that
/// read tables name each one with the schema.
async fn assert_functions_pin_search_path(pool: &PgPool) {
    let schema: String = sqlx::query_scalar("SELECT quote_ident(current_schema())")
        .fetch_one(pool)
        .await
        .unwrap();
    let functions: Vec<(String, Option<Vec<String>>, String)> = sqlx::query_as(
        "SELECT p.proname::text, p.proconfig, p.prosrc FROM pg_proc p
         WHERE p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())
           AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
           AND NOT EXISTS (
               SELECT 1 FROM pg_depend d
               WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let names: Vec<&str> = functions.iter().map(|(name, _, _)| name.as_str()).collect();
    for name in UNPINNED_FROZEN_FUNCTIONS
        .iter()
        .chain(&TABLE_READING_FUNCTIONS)
        .chain(&BUILTIN_ONLY_FUNCTIONS)
    {
        assert!(names.contains(name), "{name} missing from {names:?}");
    }
    for (name, config, source) in &functions {
        if UNPINNED_FROZEN_FUNCTIONS.contains(&name.as_str()) {
            assert_eq!(config, &None, "{name}");
            continue;
        }
        let path = config
            .iter()
            .flatten()
            .find_map(|setting| setting.strip_prefix("search_path="))
            .unwrap_or_else(|| panic!("{name} does not pin search_path: {config:?}"));
        let path: Vec<&str> = path.split(", ").collect();
        assert_eq!(path.first(), Some(&"pg_catalog"), "{name}: {path:?}");
        assert_eq!(path.last(), Some(&"pg_temp"), "{name}: {path:?}");
        if TABLE_READING_FUNCTIONS.contains(&name.as_str()) {
            assert_eq!(path, ["pg_catalog", &schema, "pg_temp"], "{name}");
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
        } else if BUILTIN_ONLY_FUNCTIONS.contains(&name.as_str()) {
            assert_eq!(path, ["pg_catalog", "pg_temp"], "{name}");
        } else {
            assert!(
                path.len() == 2 || path == ["pg_catalog", &schema, "pg_temp"],
                "{name}: {path:?}"
            );
        }
    }
}

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

    assert_functions_pin_search_path(&pool).await;
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
        23514 INSERT INTO tenant VALUES ('', 'c', 'ns_c', 'enabled')
        23514 INSERT INTO tenant VALUES ('ten_c', '', 'ns_c', 'enabled')
        23514 INSERT INTO tenant VALUES ('ten_c', 'c', 'ns_c', 'active')
        SK001 UPDATE tenant SET secret_namespace = 'ns_z', revision = revision + 1 WHERE id = 'ten_a'
        SK001 UPDATE tenant SET id = 'ten_z', revision = revision + 1 WHERE id = 'ten_a'
        SK001 UPDATE tenant SET created_at = now() - interval '1 day', revision = revision + 1
    ",
    )
    .await;
    // Name and status stay writable, each update advancing the revision
    // (0007).
    run(
        &pool,
        "UPDATE tenant SET name = 'x', status = 'disabled', revision = revision + 1",
    )
    .await;
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
        23514 INSERT INTO principal VALUES ('wld_2', 'ten_a', 'workload', '', 'enabled')
        23514 INSERT INTO principal VALUES ('wld_2', 'ten_a', 'workload', 'w', 'active')
        23503 INSERT INTO owned VALUES ('ten_b', 'wld_1')
        SK001 UPDATE principal SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'svc_1'
        SK001 UPDATE principal SET kind = 'workload', revision = revision + 1 WHERE id = 'svc_1'
        SK001 UPDATE principal SET id = 'svc_2', revision = revision + 1 WHERE id = 'svc_1'
        SK001 UPDATE principal SET created_at = now() - interval '1 day', revision = revision + 1
    ",
    )
    .await;
    run(
        &pool,
        "UPDATE principal SET name = 'x', status = 'disabled', revision = revision + 1",
    )
    .await;
    db.drop([pool]).await;
}

/// A principal's name is unique within its tenant and kind, disabled rows
/// included, and at most 2048 bytes, so the largest key, an incompressible
/// 2048-byte name next to a 255-byte tenant ID, fits its index, and an
/// over-long name fails with the named check, never with the btree error
/// `54000`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn principal_name_is_unique_per_tenant_and_kind_and_bounded() {
    let (db, pool) = migrated().await;
    run(&pool, TENANTS).await;
    run(
        &pool,
        "INSERT INTO principal VALUES
             ('wld_1', 'ten_a', 'workload', 'deployer', 'disabled'),
             ('svc_1', 'ten_a', 'service', 'deployer', 'enabled'),
             ('usr_1', 'ten_a', 'human', 'deployer', 'enabled'),
             ('wld_b', 'ten_b', 'workload', 'deployer', 'enabled'),
             ('wld_2', 'ten_a', 'workload', 'Deployer', 'enabled'),
             ('wld_3', 'ten_a', 'workload', 'deployer ', 'enabled')",
    )
    .await;
    rejects(
        &pool,
        "
        23505 INSERT INTO principal VALUES ('wld_4', 'ten_a', 'workload', 'deployer', 'enabled')
        23505 INSERT INTO principal VALUES ('usr_2', 'ten_a', 'human', 'deployer', 'enabled')
        23505 UPDATE principal SET name = 'deployer', revision = revision + 1 WHERE id = 'wld_2'
        23514 INSERT INTO principal VALUES ('wld_4', 'ten_a', 'workload', repeat('a', 2049), 'enabled')
        23514 INSERT INTO principal VALUES ('wld_4', 'ten_a', 'workload', repeat('é', 1025), 'enabled')
    ",
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    for (sql, constraint) in [
        (
            "INSERT INTO principal VALUES ('wld_4', 'ten_a', 'workload', 'deployer', 'enabled')",
            "principal_tenant_id_kind_name_key",
        ),
        (
            "INSERT INTO principal VALUES ('wld_4', 'ten_a', 'workload', repeat('a', 2049), 'enabled')",
            "principal_name_octet_length_check",
        ),
    ] {
        let err = sqlx::raw_sql(sql).execute(&mut *conn).await.expect_err(sql);
        assert_eq!(
            err.as_database_error().and_then(|e| e.constraint()),
            Some(constraint),
            "{sql}: {err}"
        );
    }
    drop(conn);
    // The largest key: 255 + 8 + 2048 incompressible bytes.
    let tenant = "left((SELECT string_agg(md5(i::text), '' ORDER BY i) \
                  FROM generate_series(1000, 1007) i), 255)";
    let name =
        "(SELECT string_agg(md5(i::text), '' ORDER BY i) FROM generate_series(2000, 2063) i)";
    sqlx::raw_sql(AssertSqlSafe(format!(
        "INSERT INTO tenant VALUES ({tenant}, 'big', 'ns_big', 'enabled');
         INSERT INTO principal VALUES ('wld_big', {tenant}, 'workload', {name}, 'enabled')"
    )))
    .execute(&pool)
    .await
    .unwrap();
    let lengths: (i32, i32) = sqlx::query_as(
        "SELECT octet_length(tenant_id), octet_length(name) FROM principal WHERE id = 'wld_big'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lengths, (255, 2048));
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
    ",
    )
    .await;
    // 0005 makes the policy row a foreign-key target, so the truncate names
    // the referencing recovery_state; the policy's own guard rejects it.
    assert_rejected_with_message(
        &mut pool.acquire().await.unwrap(),
        "SK001",
        "TRUNCATE instance_security_policy, recovery_state",
        "TRUNCATE on append-only table instance_security_policy is not allowed",
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
    // Without a digest change the validation time may stay as it is.
    run(
        &pool,
        "UPDATE instance_security_policy SET widening_second_approver = true,
             revision = revision + 1",
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
    assert_eq!(row, (Some(vec![3]), true, 6));
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
        23514 ALTER TABLE egress_allowlist_entry DISABLE TRIGGER USER; INSERT INTO egress_allowlist_entry VALUES ('egr_3', 'jwks', 'https://keys.example:443/', 'enabled', 0)
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
        23514 INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', 'https://k.example/' || repeat('é', 1016), 'enabled')
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
        23514 INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome) VALUES ('evt_3', 3, '\x6832', now(), 'adm_1', 'x', 'ten_a', 'success'); UPDATE audit_chain_head SET sequence = 3, head_hash = NULL
        23514 INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome) VALUES ('evt_3', 3, '\x6832', now(), 'adm_1', 'x', 'ten_a', 'success'); UPDATE audit_chain_head SET sequence = 3, head_hash = '\x'
        23514 INSERT INTO audit_chain_head (sequence, head_hash) VALUES (3, '\x')
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
        (4, Some(&b"h2"[..])), // ahead of the head, right previous hash
        (2, Some(&b"h2"[..])), // the head's own sequence, right previous hash
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
        23502 INSERT INTO audit_event (id, tenant_id, sequence, timestamp, actor, action, object_id, outcome) VALUES ('evt_1', 'ten_a', 1, now(), NULL, 'principal_create', 'wld_1', 'success')
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
    // Each case is one implicit transaction, so the error also rolls back
    // the owner's DISABLE TRIGGER, which lets a case reach a CHECK that the
    // chain trigger would otherwise reject first.
    rejects(&pool, r"
        23514 INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome) VALUES ('evt_2', 2, '\x01', now(), 'adm_1', 'x', 'ten_a', '')
        23514 INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, previous_revision, outcome) VALUES ('evt_2', 2, '\x01', now(), 'adm_1', 'x', 'ten_a', 0, 'success')
        23514 INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, new_revision, outcome) VALUES ('evt_2', 2, '\x01', now(), 'adm_1', 'x', 'ten_a', 0, 'success')
        23514 ALTER TABLE audit_event DISABLE TRIGGER USER; INSERT INTO audit_event (id, sequence, timestamp, actor, action, object_id, outcome) VALUES ('evt_2', 2, now(), 'adm_1', 'x', 'ten_a', 'success')
        23514 ALTER TABLE audit_event DISABLE TRIGGER USER; INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome) VALUES ('evt_2', 1, '\x01', now(), 'adm_1', 'x', 'ten_a', 'success')
    ").await;

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

/// Seeds one row in each table with an update guard and returns a login role
/// that may only read and update them.
async fn update_guard_writer(db: &mut TestDb, pool: &PgPool) -> PgConnection {
    run(pool, TENANTS).await;
    run(pool, POLICY).await;
    run(
        pool,
        "INSERT INTO egress_allowlist_entry VALUES
             ('egr_1', 'jwks', 'https://keys.example:443/', 'enabled')",
    )
    .await;
    let (role, connect) = db.create_login_role().await;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT SELECT, UPDATE ON tenant, instance_security_policy, egress_allowlist_entry
         TO {role}"
    )))
    .execute(pool)
    .await
    .unwrap();
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    let superuser: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&mut writer)
            .await
            .unwrap();
    assert!(!superuser);
    writer
}

/// A temporary table named `jsonb` is also a type that the caller's
/// search_path finds before `pg_catalog.jsonb`; the immutable-column guard
/// must still use the built-in type.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn update_guards_ignore_a_temporary_jsonb_type() {
    let (mut db, pool) = migrated().await;
    let mut writer = update_guard_writer(&mut db, &pool).await;
    // Before any guard runs in this session, so none is compiled yet.
    run(&mut writer, "CREATE TEMP TABLE jsonb (x int)").await;
    assert_rejected(
        &mut writer,
        "SK001 UPDATE tenant SET secret_namespace = 'ns_z', revision = revision + 1 WHERE id = 'ten_a'",
    )
    .await;
    run(
        &mut writer,
        "UPDATE tenant SET name = 'x', revision = revision + 1 WHERE id = 'ten_a'",
    )
    .await;
    writer.close().await.unwrap();
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM tenant WHERE secret_namespace = 'ns_a' AND name = 'x'"
        )
        .await,
        1
    );
    db.drop([pool]).await;
}

/// A role that can create objects in some schema puts it ahead of
/// `pg_catalog` with an `=` that calls everything equal. The guards compare
/// with the built-in operators all the same.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn update_guards_ignore_operators_on_the_callers_search_path() {
    let (mut db, pool) = migrated().await;
    let mut writer = update_guard_writer(&mut db, &pool).await;
    run(
        &pool,
        r"UPDATE instance_security_policy SET audit_sink_validated_at = '2026-01-01T00:00:00Z',
              revision = revision + 1",
    )
    .await;
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&mut writer)
        .await
        .unwrap();
    run(&pool, "CREATE SCHEMA evil").await;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT USAGE, CREATE ON SCHEMA evil TO {role}"
    )))
    .execute(&pool)
    .await
    .unwrap();
    run(
        &mut writer,
        "CREATE FUNCTION evil.same(jsonb, jsonb) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.= (LEFTARG = jsonb, RIGHTARG = jsonb, FUNCTION = evil.same);
         CREATE FUNCTION evil.same(bigint, bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.= (LEFTARG = bigint, RIGHTARG = bigint, FUNCTION = evil.same);
         CREATE FUNCTION evil.same(bytea, bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.= (LEFTARG = bytea, RIGHTARG = bytea, FUNCTION = evil.same);
         SET search_path = evil, pg_catalog, public",
    )
    .await;
    // The shadow is in effect for the caller's own expressions.
    let shadowed: bool = sqlx::query_scalar("SELECT 1::bigint = 2::bigint")
        .fetch_one(&mut writer)
        .await
        .unwrap();
    assert!(shadowed);
    assert_rejected(&mut writer, r"
        SK001 UPDATE tenant SET secret_namespace = 'ns_z', revision = revision + 1 WHERE id = 'ten_a'
        SK001 UPDATE egress_allowlist_entry SET purpose = 'token_review', revision = revision + 1
        SK001 UPDATE instance_security_policy SET widening_second_approver = true, revision = 7
        SK001 UPDATE egress_allowlist_entry SET status = 'disabled', revision = 7
        SK001 UPDATE instance_security_policy SET audit_sink_config_digest = '\x02', revision = revision + 1
    ").await;
    run(
        &mut writer,
        "UPDATE tenant SET name = 'x', revision = revision + 1 WHERE id = 'ten_a'",
    )
    .await;
    writer.close().await.unwrap();
    let row: (Option<Vec<u8>>, bool, i64) = sqlx::query_as(
        "SELECT audit_sink_config_digest, widening_second_approver, revision
         FROM instance_security_policy",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (Some(vec![1]), false, 2));
    db.drop([pool]).await;
}

/// The chain guards compare with the built-in operators too: a login role
/// that puts its own `=` and `>=` ahead of `pg_catalog` can neither append
/// out of order nor leave the head behind.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn audit_chain_guards_ignore_operators_on_the_callers_search_path() {
    let (mut db, pool) = migrated().await;
    let (role, connect) = db.create_login_role().await;
    run(&pool, "CREATE SCHEMA evil").await;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT SELECT, INSERT, UPDATE ON audit_event, audit_chain_head TO {role};
         GRANT USAGE, CREATE ON SCHEMA evil TO {role}"
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
    run(
        &mut writer,
        "CREATE FUNCTION evil.same(bigint, bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.= (LEFTARG = bigint, RIGHTARG = bigint, FUNCTION = evil.same);
         CREATE OPERATOR evil.>= (LEFTARG = bigint, RIGHTARG = bigint, FUNCTION = evil.same);
         CREATE FUNCTION evil.same(bytea, bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.= (LEFTARG = bytea, RIGHTARG = bytea, FUNCTION = evil.same);
         SET search_path = evil, pg_catalog, public",
    )
    .await;
    // The shadow is in effect for the caller's own expressions.
    let shadowed: bool = sqlx::query_scalar(
        r"SELECT 1::bigint = 2::bigint AND 1::bigint >= 2::bigint AND '\x01'::bytea = '\x02'::bytea",
    )
    .fetch_one(&mut writer)
    .await
    .unwrap();
    assert!(shadowed);

    append_on(&mut writer, 1, None, b"h1").await.unwrap();
    // Rule 1: the insert itself fails.
    for (sequence, prev_hash) in [
        (3, Some(&b"h1"[..])), // gap
        (2, Some(&b"hx"[..])), // wrong previous hash
    ] {
        let mut tx = writer.begin().await.unwrap();
        let err = insert_event(&mut tx, sequence, prev_hash)
            .await
            .unwrap_err();
        assert_eq!(sqlstate(&err), "SK001", "{sequence} {prev_hash:?}: {err}");
        tx.rollback().await.unwrap();
    }
    // Rule 2: the head does not skip an event.
    let mut tx = writer.begin().await.unwrap();
    insert_event(&mut tx, 2, Some(b"h1")).await.unwrap();
    let err = advance_head(&mut tx, 3, b"h3").await.unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");
    tx.rollback().await.unwrap();
    // Rule 3: the commit fails while the head is behind.
    let mut tx = writer.begin().await.unwrap();
    insert_event(&mut tx, 2, Some(b"h1")).await.unwrap();
    let err = tx.commit().await.unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");

    append_on(&mut writer, 2, Some(b"h1"), b"h2").await.unwrap();
    writer.close().await.unwrap();
    assert_eq!(head(&pool).await, (2, Some(b"h2".to_vec())));
    assert_eq!(count(&pool, "SELECT count(*) FROM audit_event").await, 2);
    db.drop([pool]).await;
}

/// A schema name may contain `$$`, which must not end a function body early,
/// and upper case and spaces, which only a quoted identifier (`%I`, not
/// `%s`) keeps. The migration runs in that schema, and the chain works there.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn foundation_migrates_and_chains_in_a_schema_named_with_dollar_quotes() {
    let db = TestDb::create().await;
    let admin = db.pool().await;
    run(&admin, r#"CREATE SCHEMA "Audit $$2026""#).await;
    let pool = db.pool_with_search_path(r#""Audit $$2026""#).await;
    persistence::migrate(&pool).await.unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(schema, "Audit $$2026");
    assert_eq!(
        count(&admin, "SELECT count(*) FROM pg_tables WHERE tablename = 'audit_event' AND schemaname = 'Audit $$2026'").await,
        1
    );
    assert_eq!(
        count(
            &admin,
            "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'"
        )
        .await,
        0
    );
    assert_functions_pin_search_path(&pool).await;
    append(&pool, 1, None, b"h1").await.unwrap();
    let err = append(&pool, 3, Some(b"h1"), b"h3").await.unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");
    assert_eq!(head(&pool).await, (1, Some(b"h1".to_vec())));
    db.drop([admin, pool]).await;
}

/// Once 0005 is applied, audit_event and instance_security_policy are
/// foreign-key targets: a bare TRUNCATE of either fails with 0A000
/// (`feature_not_supported`, a table referenced in a foreign key) before the
/// truncate guard runs, also under `session_replication_role = replica`.
/// The guard tests above therefore name the referencing tables too.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bare_truncate_of_a_referenced_foundation_table_fails_before_its_guard() {
    let (db, pool) = migrated().await;
    run(&pool, POLICY).await;
    let mut conn = pool.acquire().await.unwrap();
    for setup in [
        "SET session_replication_role = origin",
        "SET session_replication_role = replica",
    ] {
        run(&mut *conn, setup).await;
        for (sql, message) in [
            (
                "TRUNCATE audit_event",
                "cannot truncate a table referenced in a foreign key constraint",
            ),
            (
                "TRUNCATE instance_security_policy",
                "cannot truncate a table referenced in a foreign key constraint",
            ),
        ] {
            assert_rejected_with_message(&mut conn, "0A000", sql, message).await;
        }
    }
    conn.close().await.unwrap();
    assert_eq!(
        count(&pool, "SELECT count(*) FROM instance_security_policy").await,
        1
    );
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
        SK001 INSERT INTO audit_event (id, sequence, prev_hash, timestamp, actor, action, object_id, outcome) VALUES ('evt_9', 9, '\x09', now(), 'adm_1', 'x', 'ten_a', 'success')
        SK001 UPDATE audit_chain_head SET sequence = 5, head_hash = '\x05'
        SK001 DELETE FROM audit_chain_head
        SK001 UPDATE tenant SET secret_namespace = 'ns_z', revision = revision + 1 WHERE id = 'ten_a'
        SK001 UPDATE instance_security_policy SET single_actor_mode = true
        SK001 UPDATE instance_security_policy SET audit_sink_config_digest = '\x02', revision = revision + 1
        SK001 DELETE FROM instance_security_policy
        SK001 UPDATE egress_allowlist_entry SET purpose = 'token_review', revision = 2
        SK001 DELETE FROM egress_allowlist_entry
    ").await;
    // 0005 makes audit events foreign-key targets, so the truncate names the
    // referencing administrative_operation; the event guard rejects it.
    assert_rejected_with_message(
        &mut conn,
        "SK001",
        "TRUNCATE audit_event, administrative_operation",
        "TRUNCATE on append-only table audit_event is not allowed",
    )
    .await;
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
/// otherwise skip ordinary triggers. Setting the mode needs a superuser or
/// `SET` on the parameter.
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
