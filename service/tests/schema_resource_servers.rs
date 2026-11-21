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
/// `ten_a`, a checker that lists `ten_a`, and an action.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO resource_server VALUES
        ('rs_1', 'control-plane-api', 'Control plane', '["wif", "human_cli"]', '["projects:read", "projects:write"]', '[1]', 'enabled'),
        ('rs_2', 'billing-api', 'Billing', '["human_session"]', '[]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["projects:read"]', '[1]', 'enabled');
    INSERT INTO resource_server_checker VALUES ('chk_1', 'rs_1', 'sha256:aa', 'enabled');
    INSERT INTO resource_server_checker_tenant VALUES ('chk_1', 'rs_1', 'ten_a');
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
///
/// A `23503` case that deletes a referenced row of a table whose deletes
/// `0006` guards first disables that table's user triggers; the line's
/// implicit transaction rolls that back with the failed delete.
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
    let mut tables: Vec<String> = TABLES.iter().map(|t| t.to_string()).collect();
    tables.push("resource_server_checker_tenant".into());

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
        .chain([(
            "resource_server_checker_tenant".into(),
            "resource_server_checker_tenant_immutable".into(),
            "A".into(),
            true,
        )])
        // The 0006 delete and truncate guards (schema_registry_guards.rs).
        .chain(TABLES.iter().flat_map(|t| {
            ["no_delete", "no_truncate"]
                .map(|g| (t.to_string(), format!("{t}_{g}"), "A".into(), true))
        }))
        .chain([(
            "resource_server_checker_tenant".into(),
            "resource_server_checker_tenant_no_truncate".into(),
            "A".into(),
            true,
        )])
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

    // No column is nullable by design.
    let nullable: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
         WHERE c.relnamespace = to_regnamespace(current_schema()) AND c.relname = ANY($1)
           AND a.attnum > 0 AND NOT a.attisdropped AND NOT a.attnotnull
         ORDER BY 1, 2",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(nullable.is_empty(), "{nullable:?}");

    // Foreign keys are named for the service's 23503 mapping, take no
    // action on delete or update and are checked at once.
    let mut foreign_keys: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT conname::text, confdeltype::text || confupdtype::text,
                condeferrable::text || condeferred::text
         FROM pg_constraint
         WHERE contype = 'f' AND conrelid = ANY($1::text[]::regclass[])",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    foreign_keys.sort();
    let expected: Vec<(String, String, String)> = [
        "audience_tenant_assignment_resource_server_id_fkey",
        "audience_tenant_assignment_tenant_id_fkey",
        "resource_action_resource_server_id_fkey",
        "resource_server_checker_resource_server_id_fkey",
        "resource_server_checker_tenant_assignment_fkey",
        "resource_server_checker_tenant_checker_fkey",
    ]
    .map(|name| (name.into(), "aa".into(), "falsefalse".into()))
    .into();
    assert_eq!(foreign_keys, expected);

    // The full set of checks on the 0003 tables, and the bounds 0003 adds to
    // the 0002 tenant. The bounds and character rules are named for the
    // service's 23514 mapping (README.md); the others keep generated names.
    let mut checks: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint
         WHERE contype = 'c' AND (conrelid = ANY($1::text[]::regclass[])
           OR conname IN ('tenant_id_octet_length_check', 'tenant_secret_namespace_octet_length_check'))",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    checks.sort();
    let non_empty = |column: &str| format!("CHECK (({column} <> ''::text))");
    let at_most = |column: &str, bytes: u32| format!("CHECK ((octet_length({column}) <= {bytes}))");
    let no_space = |column: &str| format!("CHECK (({column} !~ '[[:space:][:cntrl:]]'::text))");
    let status = "CHECK ((status = ANY (ARRAY['enabled'::text, 'disabled'::text])))".to_string();
    let revision = "CHECK ((revision >= 1))".to_string();
    let versions = "CHECK ((jsonb_typeof(constraint_versions) = 'array'::text))".to_string();
    let mut expected: Vec<(String, String)> = [
        (
            "audience_tenant_assignment_constraint_versions_check",
            versions.clone(),
        ),
        ("audience_tenant_assignment_id_check", non_empty("id")),
        (
            "audience_tenant_assignment_id_octet_length_check",
            at_most("id", 255),
        ),
        (
            "audience_tenant_assignment_revision_check",
            revision.clone(),
        ),
        (
            "audience_tenant_assignment_server_id_octet_length_check",
            at_most("resource_server_id", 255),
        ),
        ("audience_tenant_assignment_status_check", status.clone()),
        (
            "audience_tenant_assignment_tenant_id_octet_length_check",
            at_most("tenant_id", 255),
        ),
        (
            "resource_action_action_name_check",
            non_empty("action_name"),
        ),
        (
            "resource_action_action_name_no_space_check",
            no_space("action_name"),
        ),
        (
            "resource_action_action_name_octet_length_check",
            at_most("action_name", 2048),
        ),
        ("resource_action_id_check", non_empty("id")),
        ("resource_action_id_octet_length_check", at_most("id", 255)),
        (
            "resource_action_resource_server_id_octet_length_check",
            at_most("resource_server_id", 255),
        ),
        ("resource_action_revision_check", revision.clone()),
        ("resource_action_status_check", status.clone()),
        ("resource_server_audience_check", non_empty("audience")),
        (
            "resource_server_audience_no_space_check",
            no_space("audience"),
        ),
        (
            "resource_server_audience_octet_length_check",
            at_most("audience", 2048),
        ),
        ("resource_server_constraint_versions_check", versions),
        ("resource_server_id_check", non_empty("id")),
        ("resource_server_id_octet_length_check", at_most("id", 255)),
        ("resource_server_name_check", non_empty("name")),
        ("resource_server_revision_check", revision.clone()),
        ("resource_server_status_check", status.clone()),
        ("resource_server_checker_id_check", non_empty("id")),
        (
            "resource_server_checker_id_octet_length_check",
            at_most("id", 255),
        ),
        (
            "resource_server_checker_public_mtls_identity_check",
            non_empty("public_mtls_identity"),
        ),
        (
            "resource_server_checker_public_mtls_identity_octet_length_check",
            at_most("public_mtls_identity", 2048),
        ),
        (
            "resource_server_checker_resource_server_id_octet_length_check",
            at_most("resource_server_id", 255),
        ),
        ("resource_server_checker_revision_check", revision),
        ("resource_server_checker_status_check", status),
        (
            "resource_server_checker_tenant_checker_id_octet_length_check",
            at_most("checker_id", 255),
        ),
        (
            "resource_server_checker_tenant_server_id_octet_length_check",
            at_most("resource_server_id", 255),
        ),
        (
            "resource_server_checker_tenant_tenant_id_octet_length_check",
            at_most("tenant_id", 255),
        ),
        ("tenant_id_octet_length_check", at_most("id", 255)),
        (
            "tenant_secret_namespace_octet_length_check",
            at_most("secret_namespace", 255),
        ),
    ]
    .into_iter()
    .map(|(name, def)| (name.into(), def))
    .collect();
    expected.sort();
    assert_eq!(checks, expected);

    // The service always states whether an action needs a live check.
    let live_check: (bool, bool) = sqlx::query_as(
        "SELECT attnotnull, atthasdef FROM pg_attribute
         WHERE attrelid = 'resource_action'::regclass AND attname = 'live_check_required'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live_check, (true, false));
    db.drop([pool]).await;
}

/// Every ID is at most 255 bytes, so every key index stays below the btree
/// limit even for values that do not compress (md5 hex), and an over-long ID
/// is a check violation, not 54000.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn ids_in_composite_keys_are_bounded() {
    let (db, pool) = seeded().await;
    rejects(&pool, "
        23514 INSERT INTO tenant VALUES (repeat('t', 256), 'c', 'ns_c', 'enabled')
        23514 INSERT INTO tenant VALUES (repeat('é', 128), 'c', 'ns_c', 'enabled')
        23514 INSERT INTO resource_server VALUES (repeat('r', 256), 'x-api', 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES (repeat('é', 128), 'x-api', 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server_checker VALUES (repeat('c', 256), 'rs_1', 'sha256:bb', 'enabled')
        23514 INSERT INTO resource_server_checker VALUES (repeat('é', 128), 'rs_1', 'sha256:bb', 'enabled')
    ").await;
    let err = sqlx::raw_sql("INSERT INTO tenant VALUES (repeat('t', 256), 'c', 'ns_c', 'enabled')")
        .execute(&pool)
        .await
        .unwrap_err();
    assert_eq!(
        err.as_database_error().and_then(|e| e.constraint()),
        Some("tenant_id_octet_length_check"),
        "{err}"
    );
    // The unique tenant namespace and the single-column primary keys: 256 and
    // 3008 incompressible bytes.
    for value in [md5_hex(1, 8), md5_hex(1, 94)] {
        violates(
            &pool,
            format!("INSERT INTO tenant VALUES ('ten_c', 'c', {value}, 'enabled')"),
            "tenant_secret_namespace_octet_length_check",
        )
        .await;
    }
    for (table, rest, constraint) in [
        (
            "audience_tenant_assignment",
            "'rs_2', 'ten_b', '[]', '[]', '[]', 'enabled'",
            "audience_tenant_assignment_id_octet_length_check",
        ),
        (
            "resource_action",
            "'rs_1', 'projects.list', '[]', '[]', '[]', false, 'enabled'",
            "resource_action_id_octet_length_check",
        ),
    ] {
        for value in [md5_hex(1, 8), md5_hex(1, 94)] {
            violates(
                &pool,
                format!("INSERT INTO {table} VALUES ({value}, {rest})"),
                constraint,
            )
            .await;
        }
    }
    // 255-byte IDs with 2048-byte incompressible names in every composite key.
    run(
        &pool,
        "CREATE TEMP TABLE incompressible AS
             SELECT string_agg(md5(i::text), '' ORDER BY i) AS v FROM generate_series(1, 64) i;
         INSERT INTO tenant SELECT repeat('t', 255), 'c', left(v, 255), 'enabled' FROM incompressible;
         INSERT INTO resource_server VALUES
             (repeat('r', 255), 'x-api', 'X', '[]', '[]', '[]', 'enabled');
         INSERT INTO audience_tenant_assignment
             SELECT left(v, 255), repeat('r', 255), repeat('t', 255), '[]', '[]', '[]', 'enabled'
             FROM incompressible;
         INSERT INTO resource_server_checker
             SELECT repeat('c', 255), repeat('r', 255), v, 'enabled' FROM incompressible;
         INSERT INTO resource_server_checker_tenant
             VALUES (repeat('c', 255), repeat('r', 255), repeat('t', 255));
         INSERT INTO resource_action
             SELECT left(v, 255), repeat('r', 255), v, '[]', '[]', '[]', false, 'enabled'
             FROM incompressible",
    )
    .await;
    let lengths: (i32, i32, i32, i32, i32) = sqlx::query_as(
        "SELECT (SELECT octet_length(action_name) FROM resource_action
                 WHERE resource_server_id = repeat('r', 255)),
                (SELECT octet_length(public_mtls_identity) FROM resource_server_checker
                 WHERE id = repeat('c', 255)),
                (SELECT octet_length(id) FROM resource_action
                 WHERE resource_server_id = repeat('r', 255)),
                (SELECT octet_length(id) FROM audience_tenant_assignment
                 WHERE resource_server_id = repeat('r', 255)),
                (SELECT octet_length(secret_namespace) FROM tenant WHERE id = repeat('t', 255))",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(lengths, (2048, 2048, 255, 255, 255));
    db.drop([pool]).await;
}

/// Checks that `sql` fails with 23514 from the check named `constraint`.
async fn violates(pool: &PgPool, sql: String, constraint: &str) {
    let err = sqlx::raw_sql(sqlx::AssertSqlSafe(sql.clone()))
        .execute(pool)
        .await
        .expect_err(&sql);
    assert_eq!(sqlstate(&err), "23514", "{sql}: {err}");
    assert_eq!(
        err.as_database_error().and_then(|e| e.constraint()),
        Some(constraint),
        "{sql}: {err}"
    );
}

/// SQL for incompressible text: the md5 hex digests of `blocks` consecutive
/// integers from `first`, 32 bytes each.
fn md5_hex(first: u32, blocks: u32) -> String {
    format!(
        "(SELECT string_agg(md5(i::text), '' ORDER BY i) FROM generate_series({first}, {}) i)",
        first + blocks - 1
    )
}

/// Every reference column is bounded too: a CHECK runs before the row enters
/// any index and the foreign key check runs after it, so an over-long
/// reference naming a missing row is a check violation, not 54000 (or
/// 23503). The 255-byte references that name existing rows are accepted in
/// `ids_in_composite_keys_are_bounded`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn references_naming_missing_rows_are_bounded() {
    let (db, pool) = seeded().await;
    let cases = [
        (
            "INSERT INTO audience_tenant_assignment VALUES ('ata_2', {v}, 'ten_b', '[]', '[]', '[]', 'enabled')",
            "audience_tenant_assignment_server_id_octet_length_check",
        ),
        (
            "INSERT INTO audience_tenant_assignment VALUES ('ata_2', 'rs_2', {v}, '[]', '[]', '[]', 'enabled')",
            "audience_tenant_assignment_tenant_id_octet_length_check",
        ),
        (
            "INSERT INTO resource_server_checker VALUES ('chk_2', {v}, 'sha256:bb', 'enabled')",
            "resource_server_checker_resource_server_id_octet_length_check",
        ),
        (
            "INSERT INTO resource_server_checker_tenant VALUES ({v}, 'rs_1', 'ten_a')",
            "resource_server_checker_tenant_checker_id_octet_length_check",
        ),
        (
            "INSERT INTO resource_server_checker_tenant VALUES ('chk_1', {v}, 'ten_b')",
            "resource_server_checker_tenant_server_id_octet_length_check",
        ),
        (
            "INSERT INTO resource_server_checker_tenant VALUES ('chk_1', 'rs_1', {v})",
            "resource_server_checker_tenant_tenant_id_octet_length_check",
        ),
        (
            "INSERT INTO resource_action VALUES ('act_2', {v}, 'projects.list', '[]', '[]', '[]', false, 'enabled')",
            "resource_action_resource_server_id_octet_length_check",
        ),
    ];
    // About 3000 incompressible bytes, and 256 bytes in 128 characters.
    for value in [md5_hex(1, 94), "repeat('é', 128)".to_string()] {
        for (sql, constraint) in cases {
            violates(&pool, sql.replace("{v}", &value), constraint).await;
        }
    }
    // A missing 1000-byte server ID with a 2048-byte incompressible name.
    violates(
        &pool,
        format!(
            "INSERT INTO resource_action VALUES
                 ('act_2', left({}, 1000), {}, '[]', '[]', '[]', false, 'enabled')",
            md5_hex(101, 32),
            md5_hex(1, 64)
        ),
        "resource_action_resource_server_id_octet_length_check",
    )
    .await;
    db.drop([pool]).await;
}

/// The unique free-text keys are bounded below the btree limit, so an
/// over-long value is a check violation, not 54000; names also carry no
/// whitespace or control characters. The mTLS identity may be a subject DN,
/// so it may contain spaces.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn free_text_keys_are_bounded_and_names_have_no_whitespace_or_controls() {
    let (db, pool) = seeded().await;
    rejects(&pool, r"
        23514 INSERT INTO resource_server VALUES ('rs_3', repeat('a', 2049), 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', repeat('é', 1025), 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', repeat('a', 5000), 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api ', 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', ' x-api', 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x api', 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', E'x-api\t', 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', E'x-api\n', 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api' || chr(1), 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api' || chr(127), 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_server VALUES ('rs_3', 'x-api' || chr(133), 'X', '[]', '[]', '[]', 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', repeat('a', 2049), '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', repeat('a', 5000), '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'projects.list ', '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', E'projects.list\t', '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', E'projects.list\n', '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'projects.list' || chr(1), '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'projects.list' || chr(127), '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_action VALUES ('act_2', 'rs_1', 'projects.list' || chr(133), '[]', '[]', '[]', false, 'enabled')
        23514 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_1', repeat('a', 2049), 'enabled')
        23514 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_1', repeat('a', 5000), 'enabled')
    ").await;
    // 2048 bytes is the largest accepted value; a DN with spaces is an
    // identity.
    run(
        &pool,
        "INSERT INTO resource_server VALUES
             ('rs_3', repeat('a', 2048), 'X', '[]', '[]', '[]', 'enabled');
         INSERT INTO resource_action VALUES
             ('act_2', 'rs_1', repeat('a', 2048), '[]', '[]', '[]', false, 'enabled');
         INSERT INTO resource_server_checker VALUES
             ('chk_2', 'rs_1', 'CN=billing checker, O=Example Corp', 'enabled'),
             ('chk_3', 'rs_1', repeat('a', 2048), 'enabled')",
    )
    .await;
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
        23514 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_1', 'sha256:bb', 'active')
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
        23503 ALTER TABLE audience_tenant_assignment DISABLE TRIGGER USER; DELETE FROM audience_tenant_assignment WHERE id = 'ata_1'
        23503 ALTER TABLE resource_server DISABLE TRIGGER USER; DELETE FROM resource_server WHERE id = 'rs_1'
        23503 ALTER TABLE tenant DISABLE TRIGGER USER; DELETE FROM tenant WHERE id = 'ten_a'
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
        "INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_2', 'sha256:bb', 'disabled')",
    )
    .await;
    rejects(&pool, r#"
        23505 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_2', 'sha256:aa', 'enabled')
        23505 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', 'sha256:aa', 'enabled')
        23505 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', 'sha256:bb', 'enabled')
        23503 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_x', 'sha256:cc', 'enabled')
        23514 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', '', 'enabled')
        23502 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', NULL, 'enabled')
        SK001 INSERT INTO resource_server_checker VALUES ('chk_3', 'rs_1', 'sha256:cc', 'enabled', 5)
        SK001 UPDATE resource_server_checker SET resource_server_id = 'rs_2', revision = revision + 1 WHERE id = 'chk_1'
        SK001 UPDATE resource_server_checker SET id = 'chk_9', revision = revision + 1 WHERE id = 'chk_1'
        SK001 UPDATE resource_server_checker SET status = 'disabled' WHERE id = 'chk_1'
        23505 UPDATE resource_server_checker SET public_mtls_identity = 'sha256:bb', revision = revision + 1 WHERE id = 'chk_1'
    "#).await;
    // The identity may be rotated.
    run(
        &pool,
        "UPDATE resource_server_checker SET public_mtls_identity = 'sha256:cc',
             status = 'disabled', revision = revision + 1
         WHERE id = 'chk_1'",
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
        23502 INSERT INTO resource_action (id, resource_server_id, action_name, required_scopes, accepted_profiles, required_resource_dimensions, status) VALUES ('act_3', 'rs_1', 'projects.list', '[]', '[]', '[]', 'enabled')
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

/// A checker lists only tenants assigned to its own resource server
/// (OQ-ADR018-1, existence half): not `ten_c`, which has no assignment, nor
/// `ten_a` for `chk_2`, since `ten_a` is assigned to `rs_1` only, and a row
/// cannot pair a checker with another resource server. Whether the
/// assignment is enabled is the service's rule, so a disabled one still
/// allows the row.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn checker_tenants_are_assigned_to_the_checkers_resource_server() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        "INSERT INTO tenant VALUES ('ten_c', 'c', 'ns_c', 'enabled');
         INSERT INTO audience_tenant_assignment VALUES
             ('ata_2', 'rs_2', 'ten_b', '[]', '[]', '[]', 'enabled'),
             ('ata_3', 'rs_1', 'ten_b', '[]', '[]', '[]', 'disabled');
         INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_2', 'sha256:bb', 'enabled');
         INSERT INTO resource_server_checker_tenant VALUES
             ('chk_1', 'rs_1', 'ten_b'), ('chk_2', 'rs_2', 'ten_b')",
    )
    .await;
    rejects(&pool, "
        23503 INSERT INTO resource_server_checker_tenant VALUES ('chk_1', 'rs_1', 'ten_c')
        23503 INSERT INTO resource_server_checker_tenant VALUES ('chk_2', 'rs_2', 'ten_a')
        23503 INSERT INTO resource_server_checker_tenant VALUES ('chk_2', 'rs_1', 'ten_a')
        23503 INSERT INTO resource_server_checker_tenant VALUES ('chk_x', 'rs_1', 'ten_a')
        23503 INSERT INTO resource_server_checker_tenant VALUES ('chk_1', 'rs_1', 'ten_x')
        23505 INSERT INTO resource_server_checker_tenant VALUES ('chk_1', 'rs_1', 'ten_a')
        23502 INSERT INTO resource_server_checker_tenant VALUES ('chk_1', 'rs_1', NULL)
        23502 INSERT INTO resource_server_checker_tenant VALUES ('chk_1', NULL, 'ten_c')
        23502 INSERT INTO resource_server_checker_tenant VALUES (NULL, 'rs_1', 'ten_b')
        SK001 UPDATE resource_server_checker_tenant SET tenant_id = 'ten_a' WHERE checker_id = 'chk_2'
        SK001 UPDATE resource_server_checker_tenant SET checker_id = 'chk_2' WHERE tenant_id = 'ten_a'
        SK001 UPDATE resource_server_checker_tenant SET resource_server_id = 'rs_2' WHERE checker_id = 'chk_1'
        23503 ALTER TABLE audience_tenant_assignment DISABLE TRIGGER USER; DELETE FROM audience_tenant_assignment WHERE id = 'ata_3'
        23503 ALTER TABLE resource_server_checker DISABLE TRIGGER USER; DELETE FROM resource_server_checker WHERE id = 'chk_2'
    ").await;
    // Removing a tenant from the set deletes its row.
    run(
        &pool,
        "DELETE FROM resource_server_checker_tenant WHERE checker_id = 'chk_1' AND tenant_id = 'ten_b'",
    )
    .await;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT checker_id, tenant_id FROM resource_server_checker_tenant ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            ("chk_1".into(), "ten_a".into()),
            ("chk_2".into(), "ten_b".into())
        ]
    );
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
        SK001 INSERT INTO resource_server_checker VALUES ('chk_2', 'rs_2', 'sha256:bb', 'enabled', 2)
        SK001 UPDATE resource_server_checker_tenant SET tenant_id = 'ten_b'
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
