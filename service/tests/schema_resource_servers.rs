//! Constraints and guards of the `0003_resource_servers` migration against a
//! real PostgreSQL server: resource servers, tenant audience assignments,
//! checker identities and action rules.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database, and the replica-role test needs
//! `SET` on `session_replication_role` (`common/mod.rs`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use common::TestDb;
use skyoauth_service::persistence::{self, PgPool};
use sqlx::{Executor, PgConnection, Postgres};

/// Two tenants, two resource servers, and on `rs_1` an assignment to
/// `ten_a`, a checker and an action.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO resource_server VALUES
        ('rs_1', 'control-plane-api', 'Control plane', '["wif", "human_cli"]', '["projects:read", "projects:write"]', '[1]', 'enabled'),
        ('rs_2', 'billing-api', 'Billing', '["human_session"]', '[]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["projects:read"]', '[1]', 'enabled');
    INSERT INTO resource_server_checker VALUES ('chk_1', 'rs_1', 'sha256:aa', '["ten_a"]', 'enabled');
    INSERT INTO resource_action VALUES
        ('act_1', 'rs_1', 'projects.get', '["projects:read"]', '["wif"]', '["projects"]', true, 'enabled')"#;

const TABLES: [&str; 4] = [
    "resource_server",
    "audience_tenant_assignment",
    "resource_server_checker",
    "resource_action",
];

async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    run(&pool, SEED).await;
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
/// `check_violation` (also raised by a domain's CHECK).
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

async fn revision(pool: &PgPool, table: &str) -> Vec<i64> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT revision FROM {table} ORDER BY id"
    )))
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn resource_server_migration_is_recorded_once_and_rerun_is_a_no_op() {
    let (db, pool) = seeded().await;
    let recorded = || async {
        sqlx::query_as::<_, (i64, String, bool)>(
            "SELECT version, description, success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    let first = recorded().await;
    assert!(
        first.contains(&(3, "resource servers".into(), true)),
        "{first:?}"
    );
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    for table in TABLES {
        assert_eq!(revision(&pool, table).await[0], 1, "{table}");
    }
    db.drop([pool]).await;
}

/// Catalog properties that behaviour tests cannot see directly.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn resource_server_catalog_pins_collation_triggers_and_search_path() {
    let (db, pool) = seeded().await;
    let tables: Vec<String> = TABLES.iter().map(|t| t.to_string()).collect();

    // Every trigger of 0003 is a guard that fires in every
    // session_replication_role and calls a function with a pinned path.
    let mut triggers: Vec<(String, String, String, bool)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, t.tgenabled::text,
                coalesce(array_to_string(p.proconfig, ',') ~ '^search_path=pg_catalog, (.*, )?pg_temp$', false)
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND c.relnamespace = to_regnamespace(current_schema())
           AND c.relname = ANY($1)",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    triggers.sort();
    let mut expected: Vec<(String, String, String, bool)> = TABLES
        .iter()
        .flat_map(|t| {
            ["immutable", "revision"].map(|g| (t.to_string(), format!("{t}_{g}"), "A".into(), true))
        })
        .collect();
    expected.sort();
    assert_eq!(triggers, expected);

    // Every function in the schema, other than the frozen 0001 guard that
    // resolves no names, pins search_path with pg_catalog first and pg_temp
    // last (schema_foundation.rs checks the exact paths).
    let unpinned: Vec<String> = sqlx::query_scalar(
        "SELECT p.proname::text FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(current_schema())
           AND p.proname <> 'skyoauth_reject_mutation'
           AND NOT coalesce(array_to_string(p.proconfig, ',') ~ '^search_path=pg_catalog, (.*, )?pg_temp$', false)
         ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(unpinned.is_empty(), "{unpinned:?}");

    // IDs, keys and references compare byte-wise; only the name does not.
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
    assert_eq!(not_c, [("resource_server".into(), "name".into())]);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn resource_server_audience_is_globally_unique_and_immutable() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23505 INSERT INTO resource_server VALUES ('rs_3', 'control-plane-api', 'Other', '[]', '[]', '[]', 'enabled')
        23505 INSERT INTO resource_server VALUES ('rs_1', 'other-api', 'Other', '[]', '[]', '[]', 'enabled')
        23502 INSERT INTO resource_server VALUES ('rs_3', NULL, 'Other', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', '', 'Other', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('', 'other-api', 'Other', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'other-api', '', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'other-api', 'Other', '[]', '[]', '[]', 'active')
        SK001 INSERT INTO resource_server VALUES ('rs_3', 'other-api', 'Other', '[]', '[]', '[]', 'enabled', 2)
        SK001 UPDATE resource_server SET audience = 'renamed-api', revision = revision + 1 WHERE id = 'rs_1'
        SK001 UPDATE resource_server SET id = 'rs_9', revision = revision + 1 WHERE id = 'rs_1'
    "#).await;
    // Audiences compare byte-wise: case and trailing slashes are distinct.
    run(
        &pool,
        "INSERT INTO resource_server VALUES
             ('rs_3', 'Control-Plane-API', 'Upper', '[]', '[]', '[]', 'enabled'),
             ('rs_4', 'control-plane-api/', 'Slash', '[]', '[]', '[]', 'enabled')",
    )
    .await;
    // Everything else stays writable, one revision at a time.
    run(
        &pool,
        r#"UPDATE resource_server SET name = 'x', allowed_profiles = '["wif"]', scopes = '[]',
               constraint_versions = '[1, 2]', status = 'disabled', revision = revision + 1
           WHERE id = 'rs_1'"#,
    )
    .await;
    rejects(
        &pool,
        "
        SK001 UPDATE resource_server SET status = 'enabled' WHERE id = 'rs_1'
        SK001 UPDATE resource_server SET status = 'enabled', revision = revision + 2 WHERE id = 'rs_1'
        SK001 UPDATE resource_server SET status = 'enabled', revision = 1 WHERE id = 'rs_1'
    ",
    )
    .await;
    assert_eq!(revision(&pool, "resource_server").await, [2, 1, 1, 1]);
    db.drop([pool]).await;
}

/// Lists are jsonb arrays: scope tokens (RFC 6749 scope-token, IR-066),
/// credential profiles, non-empty strings, and arrays of anything for
/// constraint schema versions.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn list_columns_are_arrays_of_well_formed_elements() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '["WIF"]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '["wif", "human"]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[["wif"]]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '"wif"', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '{"wif": true}', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '["a b"]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '[""]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '["a\"b"]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '["a\\b"]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '["a\u007f"]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '["a\n"]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '["café"]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '[["a"]]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '[1]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '[null]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '"a"', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '[]', '{"v": 1}', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', '[]', '1', 'enabled')
        23502 INSERT INTO resource_server VALUES ('rs_3', 'x-api', 'X', '[]', NULL, '[]', 'enabled')
        23514 INSERT INTO audience_tenant_assignment VALUES ('ata_2', 'rs_1', 'ten_b', '["human"]', '[]', '[]', 'enabled')
        23514 INSERT INTO audience_tenant_assignment VALUES ('ata_2', 'rs_1', 'ten_b', '[]', '["a b"]', '[]', 'enabled')
        23514 INSERT INTO audience_tenant_assignment VALUES ('ata_2', 'rs_1', 'ten_b', '[]', '[]', '{}', 'enabled')
        23514 INSERT INTO audience_tenant_assignment VALUES ('ata_2', 'rs_1', 'ten_b', '[]', '[]', '[]', 'active')
        23514 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_1', 'sha256:bb', '[""]', 'enabled')
        23514 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_1', 'sha256:bb', '[1]', 'enabled')
        23514 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_1', 'sha256:bb', '"ten_a"', 'enabled')
        23514 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_1', 'sha256:bb', '[]', 'active')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'x', '["a b"]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'x', '[]', '["human"]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'x', '[]', '[]', '[""]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'x', '[]', '[]', '[]', false, 'active')
        23514 UPDATE resource_action SET required_scopes = '["a b"]', revision = revision + 1
    "#).await;
    // Every character the scope-token grammar allows, at both ends of its
    // ranges, and every profile.
    run(
        &pool,
        r##"INSERT INTO resource_server VALUES
               ('rs_3', 'x-api', 'X', '["wif", "human_cli", "human_session"]',
                '["!", "#", "[", "]", "^", "~", "A-Za-z0-9:/._"]', '["v1", 2, {"x": 1}]', 'enabled')"##,
    )
    .await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn assignment_is_one_per_tenant_and_resource_server_and_keeps_its_selectors() {
    let (db, pool) = seeded().await;
    // The same tenant on another resource server, and another tenant on the
    // same one.
    run(
        &pool,
        "INSERT INTO audience_tenant_assignment VALUES
             ('ata_2', 'rs_2', 'ten_a', '[]', '[]', '[]', 'enabled'),
             ('ata_3', 'rs_1', 'ten_b', '[]', '[]', '[]', 'disabled')",
    )
    .await;
    rejects(&pool, "
        23505 INSERT INTO audience_tenant_assignment VALUES ('ata_4', 'rs_1', 'ten_a', '[]', '[]', '[]', 'disabled')
        23505 INSERT INTO audience_tenant_assignment VALUES ('ata_1', 'rs_2', 'ten_b', '[]', '[]', '[]', 'enabled')
        23503 INSERT INTO audience_tenant_assignment VALUES ('ata_4', 'rs_x', 'ten_b', '[]', '[]', '[]', 'enabled')
        23503 INSERT INTO audience_tenant_assignment VALUES ('ata_4', 'rs_2', 'ten_x', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO audience_tenant_assignment VALUES ('', 'rs_2', 'ten_b', '[]', '[]', '[]', 'enabled')
        SK001 INSERT INTO audience_tenant_assignment VALUES ('ata_4', 'rs_2', 'ten_b', '[]', '[]', '[]', 'enabled', 0)
        SK001 UPDATE audience_tenant_assignment SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'ata_2'
        SK001 UPDATE audience_tenant_assignment SET resource_server_id = 'rs_1', revision = revision + 1 WHERE id = 'ata_2'
        SK001 UPDATE audience_tenant_assignment SET id = 'ata_9', revision = revision + 1 WHERE id = 'ata_2'
        SK001 UPDATE audience_tenant_assignment SET status = 'enabled' WHERE id = 'ata_3'
        SK001 UPDATE audience_tenant_assignment SET status = 'enabled', revision = revision + 2 WHERE id = 'ata_3'
    ").await;
    // Re-enabling and narrowing the ceilings is an ordinary revisioned write.
    run(
        &pool,
        r#"UPDATE audience_tenant_assignment SET status = 'enabled', allowed_profiles = '["wif"]',
               allowed_scopes = '["projects:read"]', constraint_versions = '[1]',
               revision = revision + 1
           WHERE id = 'ata_3'"#,
    )
    .await;
    assert_eq!(
        revision(&pool, "audience_tenant_assignment").await,
        [1, 1, 2]
    );
    db.drop([pool]).await;
}

/// A tenant-owned record that names an audience references the assignment
/// by (tenant_id, resource_server_id), so it cannot name an audience that is
/// assigned only to another tenant (IR-080). Referenced rows hold back
/// deletes.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn assignment_backs_same_tenant_audience_references() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        "CREATE TABLE owned (
             tenant_id text COLLATE \"C\" NOT NULL,
             resource_server_id text COLLATE \"C\" NOT NULL,
             FOREIGN KEY (tenant_id, resource_server_id)
                 REFERENCES audience_tenant_assignment (tenant_id, resource_server_id)
         );
         INSERT INTO owned VALUES ('ten_a', 'rs_1')",
    )
    .await;
    rejects(
        &pool,
        "
        23503 INSERT INTO owned VALUES ('ten_b', 'rs_1')
        23503 INSERT INTO owned VALUES ('ten_a', 'rs_2')
        23503 DELETE FROM audience_tenant_assignment WHERE id = 'ata_1'
        23503 DELETE FROM resource_server WHERE id = 'rs_1'
        23503 DELETE FROM tenant WHERE id = 'ten_a'
    ",
    )
    .await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn checker_identity_is_registered_once_for_one_resource_server() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        r#"INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_2', 'sha256:bb', '[]', 'disabled')"#,
    )
    .await;
    rejects(&pool, r#"
        23505 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_2', 'sha256:aa', '["ten_a"]', 'enabled')
        23505 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', 'sha256:aa', '["ten_b"]', 'enabled')
        23505 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', 'sha256:bb', '["ten_a"]', 'enabled')
        23503 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_x', 'sha256:cc', '[]', 'enabled')
        23514 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', '', '[]', 'enabled')
        23502 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', 'sha256:cc', NULL, 'enabled')
        SK001 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', 'sha256:cc', '[]', 'enabled', 5)
        SK001 UPDATE resource_server_checker SET resource_server_id = 'rs_2', revision = revision + 1 WHERE id = 'chk_1'
        SK001 UPDATE resource_server_checker SET id = 'chk_9', revision = revision + 1 WHERE id = 'chk_1'
        SK001 UPDATE resource_server_checker SET allowed_tenant_ids = '[]' WHERE id = 'chk_1'
        23505 UPDATE resource_server_checker SET public_mtls_identity = 'sha256:bb', revision = revision + 1 WHERE id = 'chk_1'
    "#).await;
    // The identity may be rotated and the tenant set edited.
    run(
        &pool,
        r#"UPDATE resource_server_checker SET public_mtls_identity = 'sha256:cc',
               allowed_tenant_ids = '["ten_a", "ten_b"]', status = 'disabled',
               revision = revision + 1
           WHERE id = 'chk_1'"#,
    )
    .await;
    assert_eq!(revision(&pool, "resource_server_checker").await, [2, 1]);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn action_name_is_unique_per_resource_server_and_immutable() {
    let (db, pool) = seeded().await;
    // The same name on another resource server is another action.
    run(
        &pool,
        "INSERT INTO resource_action VALUES
             ('act_2', 'rs_2', 'projects.get', '[]', '[]', '[]', false, 'enabled')",
    )
    .await;
    rejects(&pool, r#"
        23505 INSERT INTO resource_action VALUES ('act_3', 'rs_1', 'projects.get', '[]', '[]', '[]', false, 'disabled')
        23503 INSERT INTO resource_action VALUES ('act_3', 'rs_x', 'projects.list', '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_3', 'rs_1', '', '[]', '[]', '[]', false, 'enabled')
        23502 INSERT INTO resource_action VALUES ('act_3', 'rs_1', 'projects.list', '[]', '[]', '[]', NULL, 'enabled')
        SK001 INSERT INTO resource_action VALUES ('act_3', 'rs_1', 'projects.list', '[]', '[]', '[]', false, 'enabled', 2)
        SK001 UPDATE resource_action SET action_name = 'projects.list', revision = revision + 1 WHERE id = 'act_1'
        SK001 UPDATE resource_action SET resource_server_id = 'rs_2', revision = revision + 1 WHERE id = 'act_1'
        SK001 UPDATE resource_action SET id = 'act_9', revision = revision + 1 WHERE id = 'act_1'
        SK001 UPDATE resource_action SET live_check_required = false WHERE id = 'act_1'
    "#).await;
    run(
        &pool,
        r#"UPDATE resource_action SET required_scopes = '["projects:read", "projects:write"]',
               accepted_profiles = '["wif", "human_cli"]', required_resource_dimensions = '[]',
               live_check_required = false, status = 'disabled', revision = revision + 1
           WHERE id = 'act_1'"#,
    )
    .await;
    assert_eq!(revision(&pool, "resource_action").await, [2, 1]);
    db.drop([pool]).await;
}

/// `ENABLE ALWAYS` keeps the guards firing in replica mode, which would
/// otherwise skip ordinary triggers; domain and table CHECKs hold anyway.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn resource_server_guards_hold_under_replica_role() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    run(&mut *conn, "SET session_replication_role = replica").await;
    assert_rejected(&mut conn, r#"
        SK001 UPDATE resource_server SET audience = 'renamed-api', revision = revision + 1
        SK001 UPDATE resource_server SET status = 'disabled'
        SK001 UPDATE audience_tenant_assignment SET tenant_id = 'ten_b', revision = revision + 1
        SK001 UPDATE audience_tenant_assignment SET status = 'disabled', revision = 5
        SK001 UPDATE resource_server_checker SET resource_server_id = 'rs_2', revision = revision + 1
        SK001 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_2', 'sha256:bb', '[]', 'enabled', 2)
        SK001 UPDATE resource_action SET action_name = 'projects.list', revision = revision + 1
        SK001 INSERT INTO resource_action VALUES ('act_2', 'rs_2', 'x', '[]', '[]', '[]', false, 'enabled', 0)
        23514 UPDATE resource_server SET scopes = '["a b"]', revision = revision + 1
    "#).await;
    conn.close().await.unwrap();
    for table in TABLES {
        assert_eq!(revision(&pool, table).await[0], 1, "{table}");
    }
    db.drop([pool]).await;
}
