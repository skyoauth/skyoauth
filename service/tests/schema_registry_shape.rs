//! Shape changes of the `0007_registry_shape` migration against a real
//! PostgreSQL server: the revisions of tenants, principals and trust keyset
//! versions, the named range check on every `timestamptz` column, the
//! referencing-side indexes of the foreign keys, and the upgrade from a
//! `0006` database, with the precondition query of the migrations README.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database, and the replica-role cases need
//! `SET` on `session_replication_role`.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use common::TestDb;
use skyoauth_service::persistence::{self, MIGRATOR, MigrateError, PgPool};
use sqlx::{AssertSqlSafe, Executor, PgConnection, Postgres};

/// One row or more in every table of `0002` to `0005`, insertable at `0006`
/// and at `0007` (the new revision columns come last and default to 1).
/// `op_2` exists so that `op_1` can be revoked by another operation.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO principal VALUES
        ('wld_1', 'ten_a', 'workload', 'w1', 'enabled'),
        ('svc_1', 'ten_a', 'service', 's1', 'enabled');
    INSERT INTO instance_security_policy (instance_id) VALUES ('inst_1');
    INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', 'https://keys.example:443/', 'enabled');
    INSERT INTO audit_event VALUES ('evt_1', NULL, 1, NULL, '2026-11-20Z', 'adm_1', 'tenant.update', 'ten_a', 1, 2, 'success');
    UPDATE audit_chain_head SET sequence = 1, head_hash = '\x01';
    INSERT INTO resource_server VALUES ('rs_1', 'api-1', 'API 1', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO resource_server_checker VALUES ('chk_1', 'rs_1', 'sha256:aa', 'enabled');
    INSERT INTO resource_server_checker_tenant VALUES ('chk_1', 'rs_1', 'ten_a');
    INSERT INTO resource_action VALUES ('act_1', 'rs_1', 'read', '["read"]', '["wif"]', '[]', false, 'enabled');
    INSERT INTO trust_keyset VALUES ('ks_1', 'ten_a', 'partner', 'enabled');
    INSERT INTO trust_keyset_version VALUES
        ('kv_1', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AA", "y": "AA"}]}',
         'sha256:01', '2026-01-01Z', NULL, 'enabled', '{}');
    INSERT INTO trust_source VALUES
        ('src_gh', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'on_demand_jwt', NULL, 'single_use', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_1', 'ten_a', 'live', 'src_gh', 'generic_production', '{"sub": "repo:1"}', 'wld_1', 'enabled');
    INSERT INTO service_identity VALUES ('svc_1', 'ten_a', 'deployer', '["read"]', '{}', 'enabled');
    INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', 'rs_1');
    INSERT INTO service_grant VALUES
        ('grt_1', 'ten_a', 'live', 'wld_1', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required');
    INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_1', 'ten_a', 'wld_1');
    INSERT INTO service_grant_resource_server VALUES ('grt_1', 'ten_a', 'rs_1');
    INSERT INTO admin_identity VALUES ('adm_1', 'enabled');
    INSERT INTO admin_credential VALUES ('crd_1', 'adm_1', 'sha256:c1', 'ops-ca', 'enabled', NULL);
    INSERT INTO admin_role_binding VALUES ('rb_1', 'adm_1', 'security_admin', NULL, 'enabled');
    INSERT INTO recovery_state VALUES ('inst_1', true, '\x0a0b', 1);
    INSERT INTO administrative_operation VALUES
        ('op_1', NULL, 'adm_1', 'tenant.update', sha256('op_1'), 1, '{}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'applied', 'evt_1'),
        ('op_2', NULL, 'adm_1', 'tenant.update', sha256('op_2'), 1, '{}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'applied', 'evt_1');
    INSERT INTO consumed_assertion VALUES
        ('ten_a', 'src_gh', sha256('jti_1'), 'dk_1', now() - interval '2 hours', now() + interval '1 hour')"#;

/// PostgreSQL's earliest `timestamptz`, `-210866803200000000` microseconds
/// from the Unix epoch.
const EARLIEST: &str = "4714-11-24 00:00:00+00 BC";
/// `i64::MAX - 1` microseconds from the Unix epoch, the latest time the
/// registry reads back exactly.
const LATEST: &str = "294247-01-10 04:00:54.775806+00";
/// One microsecond after [`LATEST`].
const PAST_LATEST: &str = "294247-01-10 04:00:54.775807+00";

/// How a range case reaches one seeded row: its table, column, the row's
/// `WHERE`, further assignments that keep the row's other checks true, the
/// values outside the range that violate only the range check, and the
/// bounds the row's other checks let it take.
struct RangeCase {
    table: &'static str,
    column: &'static str,
    row: &'static str,
    also: &'static str,
    outside: &'static [&'static str],
    bounds: &'static [&'static str],
}

const OUTSIDE: &[&str] = &["infinity", "-infinity", PAST_LATEST];
const BOUNDS: &[&str] = &[EARLIEST, LATEST];

const fn case(
    table: &'static str,
    column: &'static str,
    row: &'static str,
    also: &'static str,
    outside: &'static [&'static str],
    bounds: &'static [&'static str],
) -> RangeCase {
    RangeCase {
        table,
        column,
        row,
        also,
        outside,
        bounds,
    }
}

/// Every `timestamptz` column of `0001` to `0005`.
const RANGE_CASES: [RangeCase; 15] = [
    case("schema_info", "created_at", "true", "", OUTSIDE, BOUNDS),
    case("tenant", "created_at", "id = 'ten_a'", "", OUTSIDE, BOUNDS),
    case(
        "principal",
        "created_at",
        "id = 'wld_1'",
        "",
        OUTSIDE,
        BOUNDS,
    ),
    // A validated sink needs a configured one.
    case(
        "instance_security_policy",
        "audit_sink_validated_at",
        "true",
        r", audit_sink_config_digest = '\x01'",
        OUTSIDE,
        BOUNDS,
    ),
    case(
        "audit_event",
        "timestamp",
        "id = 'evt_1'",
        "",
        OUTSIDE,
        BOUNDS,
    ),
    // expires_at is NULL, so the validity check holds for any effective_at.
    case(
        "trust_keyset_version",
        "effective_at",
        "id = 'kv_1'",
        "",
        OUTSIDE,
        BOUNDS,
    ),
    // expires_at must stay after effective_at.
    case(
        "trust_keyset_version",
        "expires_at",
        "id = 'kv_1'",
        "",
        &["infinity", PAST_LATEST],
        &[LATEST],
    ),
    case(
        "service_grant",
        "valid_until",
        "id = 'grt_1'",
        "",
        OUTSIDE,
        BOUNDS,
    ),
    case(
        "admin_identity",
        "created_at",
        "id = 'adm_1'",
        "",
        OUTSIDE,
        BOUNDS,
    ),
    // A revoked credential is disabled.
    case(
        "admin_credential",
        "revoked_at",
        "id = 'crd_1'",
        ", status = 'disabled'",
        OUTSIDE,
        BOUNDS,
    ),
    case(
        "administrative_operation",
        "expires_at",
        "id = 'op_1'",
        "",
        OUTSIDE,
        BOUNDS,
    ),
    case(
        "administrative_operation",
        "consumed_at",
        "id = 'op_1'",
        "",
        OUTSIDE,
        BOUNDS,
    ),
    // A revocation names the revoking operation, which is another one.
    case(
        "administrative_operation",
        "revoked_at",
        "id = 'op_1'",
        ", revocation_operation_id = 'op_2'",
        OUTSIDE,
        BOUNDS,
    ),
    // retain_until must stay after consumed_at.
    case(
        "consumed_assertion",
        "consumed_at",
        "true",
        "",
        &["-infinity"],
        &[EARLIEST],
    ),
    case(
        "consumed_assertion",
        "retain_until",
        "true",
        "",
        &["infinity", PAST_LATEST],
        &[LATEST],
    ),
];

/// The tables that `0007` gives a revision.
const REVISIONED: [&str; 3] = ["tenant", "principal", "trust_keyset_version"];

/// The referencing-side indexes of `0007`: name, table and columns.
const INDEXES: [(&str, &str, &str); 18] = [
    (
        "audience_tenant_assignment_resource_server_id_idx",
        "audience_tenant_assignment",
        "resource_server_id",
    ),
    (
        "resource_server_checker_resource_server_id_idx",
        "resource_server_checker",
        "resource_server_id",
    ),
    (
        "resource_server_checker_tenant_tenant_id_resource_server_id_idx",
        "resource_server_checker_tenant",
        "tenant_id, resource_server_id",
    ),
    (
        "trust_keyset_version_tenant_id_keyset_id_idx",
        "trust_keyset_version",
        "tenant_id, keyset_id",
    ),
    (
        "trust_source_tenant_id_jwks_keyset_id_idx",
        "trust_source",
        "tenant_id, jwks_keyset_id",
    ),
    (
        "principal_binding_tenant_id_trust_source_id_idx",
        "principal_binding",
        "tenant_id, trust_source_id",
    ),
    (
        "principal_binding_tenant_id_workload_principal_idx",
        "principal_binding",
        "tenant_id, workload_principal_id, workload_principal_kind",
    ),
    (
        "service_identity_resource_server_tenant_id_server_id_idx",
        "service_identity_resource_server",
        "tenant_id, resource_server_id",
    ),
    (
        "service_grant_tenant_id_target_service_id_idx",
        "service_grant",
        "tenant_id, target_service_id",
    ),
    (
        "service_grant_tenant_id_actor_principal_idx",
        "service_grant",
        "tenant_id, actor_principal_id, actor_principal_kind",
    ),
    (
        "service_grant_binding_tenant_id_binding_id_actor_principal_idx",
        "service_grant_binding",
        "tenant_id, binding_id, actor_principal_id",
    ),
    (
        "service_grant_resource_server_tenant_id_resource_server_id_idx",
        "service_grant_resource_server",
        "tenant_id, resource_server_id",
    ),
    (
        "admin_credential_admin_id_idx",
        "admin_credential",
        "admin_id",
    ),
    (
        "admin_role_binding_tenant_id_idx",
        "admin_role_binding",
        "tenant_id",
    ),
    (
        "administrative_operation_tenant_id_idx",
        "administrative_operation",
        "tenant_id",
    ),
    (
        "administrative_operation_revocation_operation_id_idx",
        "administrative_operation",
        "revocation_operation_id",
    ),
    (
        "administrative_operation_approves_operation_id_idx",
        "administrative_operation",
        "approves_operation_id",
    ),
    (
        "administrative_operation_audit_id_idx",
        "administrative_operation",
        "audit_id",
    ),
];

/// The foreign keys with no index led by their columns: the leading column
/// of their table's primary key is one of their columns and identifies the
/// referenced row on its own.
const UNINDEXED_FOREIGN_KEYS: [&str; 5] = [
    "resource_server_checker_tenant_checker_fkey",
    "service_grant_binding_grant_id_fkey",
    "service_grant_resource_server_grant_id_fkey",
    "service_identity_id_fkey",
    "service_identity_resource_server_service_id_fkey",
];

/// The session modes every guard must hold in.
const MODES: [&str; 2] = [
    "SET session_replication_role = origin",
    "SET session_replication_role = replica",
];

async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    run(&pool, SEED).await;
    (db, pool)
}

async fn run<'c>(executor: impl Executor<'c, Database = Postgres>, sql: &str) {
    if let Err(err) = sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(executor)
        .await
    {
        panic!("{sql}: {err}");
    }
}

fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
        .unwrap_or_else(|| panic!("not a database error: {err}"))
}

/// Runs `sql` on `conn` and checks that it fails with `code` and, when
/// given, names `constraint` (a `23514`) or carries `message` (an `SK001`).
/// Rolls back a transaction that `sql` opened.
async fn rejected(conn: &mut PgConnection, sql: &str, code: &str, detail: Option<&str>) {
    let err = sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(&mut *conn)
        .await
        .expect_err(sql);
    assert_eq!(sqlstate(&err), code, "{sql}: {err}");
    if let Some(detail) = detail {
        let db_err = err.as_database_error().unwrap();
        let actual = if code == "SK001" {
            db_err.message().to_string()
        } else {
            db_err.constraint().unwrap_or_default().to_string()
        };
        assert_eq!(actual, detail, "{sql}");
    }
    if sql.starts_with("BEGIN") {
        run(&mut *conn, "ROLLBACK").await;
    }
}

/// `column` quoted where it is a keyword.
fn quoted(column: &str) -> String {
    if column == "timestamp" {
        format!("\"{column}\"")
    } else {
        column.to_string()
    }
}

/// The definition `pg_get_constraintdef` prints for a range check, under
/// the `TimeZone` UTC and `DateStyle` ISO that sqlx sets for every
/// connection.
fn range_check(column: &str) -> String {
    let column = quoted(column);
    format!(
        "CHECK ((({column} >= '{EARLIEST}'::timestamp with time zone) \
         AND ({column} <= '{LATEST}'::timestamp with time zone)))"
    )
}

/// The `index`th SQL block of the upgrade precondition in the migrations
/// README ("What 0007 adds"): 0 is the precondition query, 1 the check that
/// a repair left every user trigger enabled. The test runs the text
/// operators copy.
fn precondition_sql(index: usize) -> String {
    let readme = include_str!("../migrations/README.md");
    let mut section = &readme[readme
        .find("- **Upgrade precondition.**")
        .expect("README has the upgrade precondition")..];
    section = &section[..section.find("\n- **").expect("the precondition item ends")];
    for _ in 0..index {
        section = &section[section.find("  ```\n").unwrap() + "  ```\n".len()..];
    }
    let start = section.find("```sql\n").unwrap() + "```sql\n".len();
    let end = start + section[start..].find("  ```").unwrap();
    section[start..end]
        .lines()
        .map(|line| line.strip_prefix("  ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn precondition<'c>(executor: impl Executor<'c, Database = Postgres>) -> Vec<(String, i64)> {
    let mut counts: Vec<(String, i64)> = sqlx::query_as(AssertSqlSafe(precondition_sql(0)))
        .fetch_all(executor)
        .await
        .unwrap();
    counts.sort();
    counts
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_shape_migration_is_recorded_once_and_rerun_is_a_no_op() {
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
        first.contains(&(7, "registry shape".into(), true)),
        "{first:?}"
    );
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    db.drop([pool]).await;
}

/// Every `timestamptz` column of the schema has exactly one named range
/// check, with the two bounds, validated; a later column without one fails
/// here. No column stores a time without a time zone.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_timestamp_column_has_a_named_range_check() {
    let (db, pool) = seeded().await;
    let mut columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
         WHERE c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND c.relkind IN ('r', 'p') AND c.relname <> '_sqlx_migrations'
           AND a.attnum > 0 AND NOT a.attisdropped AND a.atttypid = 'timestamptz'::regtype",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    columns.sort();
    let mut expected: Vec<(String, String)> = RANGE_CASES
        .iter()
        .map(|c| (c.table.to_string(), c.column.to_string()))
        .collect();
    expected.sort();
    assert_eq!(columns, expected);

    // (table, column, name, definition, validated) of every check that
    // names one timestamptz column, and of every check named *_range_check.
    let mut checks: Vec<(String, String, String, String, bool)> = sqlx::query_as(
        r"SELECT c.relname::text, a.attname::text, k.conname::text, pg_get_constraintdef(k.oid),
                k.convalidated
         FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
         JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = k.conkey[1]
         WHERE k.contype = 'c' AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND (k.conname LIKE '%\_range\_check'
                OR (cardinality(k.conkey) = 1 AND a.atttypid = 'timestamptz'::regtype))",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    checks.sort();
    let mut expected: Vec<(String, String, String, String, bool)> = RANGE_CASES
        .iter()
        .map(|c| {
            (
                c.table.to_string(),
                c.column.to_string(),
                format!("{}_{}_range_check", c.table, c.column),
                range_check(c.column),
                true,
            )
        })
        .collect();
    expected.sort();
    assert_eq!(checks, expected);

    let without_zone: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text || '.' || a.attname::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
         WHERE c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND a.attnum > 0 AND NOT a.attisdropped
           AND a.atttypid IN ('timestamp'::regtype, 'date'::regtype, 'time'::regtype, 'timetz'::regtype)",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(without_zone.is_empty(), "{without_zone:?}");
    db.drop([pool]).await;
}

/// The bounds carry an explicit offset, so a migration run from a session
/// in another time zone (here UTC+14, as a `psql` session might be) stores
/// the same checks as the sqlx runner, whose sessions are UTC.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn range_bounds_do_not_depend_on_the_migrating_sessions_time_zone() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    {
        let mut conn = pool.acquire().await.unwrap();
        run(&mut *conn, "SET TimeZone = 'Pacific/Kiritimati'").await;
        MIGRATOR.run(&mut *conn).await.unwrap();
        conn.close().await.unwrap();
    }
    let mut checks: Vec<(String, String)> = sqlx::query_as(
        r"SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint
         WHERE contype = 'c' AND conname LIKE '%\_range\_check'
           AND connamespace = to_regnamespace(quote_ident(current_schema()))",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    checks.sort();
    let mut expected: Vec<(String, String)> = RANGE_CASES
        .iter()
        .map(|c| {
            (
                format!("{}_{}_range_check", c.table, c.column),
                range_check(c.column),
            )
        })
        .collect();
    expected.sort();
    assert_eq!(checks, expected);
    db.drop([pool]).await;
}

/// Each column rejects `infinity`, `-infinity` and the first microsecond
/// past the upper bound with its named check, and takes both bounds. The
/// row's guards are disabled in a rolled-back transaction, so that an
/// immutable or append-only column can be written; the checks do not depend
/// on them.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn timestamps_outside_the_range_fail_and_the_bounds_are_kept() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for case in &RANGE_CASES {
        let RangeCase {
            table,
            column,
            row,
            also,
            ..
        } = case;
        let target = quoted(column);
        let constraint = format!("{table}_{column}_range_check");
        for value in case.outside {
            rejected(
                &mut conn,
                &format!(
                    "BEGIN; ALTER TABLE {table} DISABLE TRIGGER USER;
                     UPDATE {table} SET {target} = timestamptz '{value}'{also} WHERE {row}"
                ),
                "23514",
                Some(&constraint),
            )
            .await;
        }
        for value in case.bounds {
            run(
                &mut *conn,
                &format!(
                    "BEGIN; ALTER TABLE {table} DISABLE TRIGGER USER;
                     UPDATE {table} SET {target} = timestamptz '{value}'{also} WHERE {row}"
                ),
            )
            .await;
            let kept: bool = sqlx::query_scalar(AssertSqlSafe(format!(
                "SELECT bool_and({target} = timestamptz '{value}') FROM {table} WHERE {row}"
            )))
            .fetch_one(&mut *conn)
            .await
            .unwrap();
            run(&mut *conn, "ROLLBACK").await;
            assert!(kept, "{table}.{column} = {value}");
        }
    }
    // With the guards in place, an INSERT fails on the check too.
    for (sql, constraint) in [
        (
            "INSERT INTO tenant (id, name, secret_namespace, status, created_at)
             VALUES ('ten_x', 'x', 'ns_x', 'enabled', 'infinity')",
            "tenant_created_at_range_check",
        ),
        (
            "INSERT INTO trust_keyset_version VALUES
                 ('kv_x', 'ten_a', 'ks_1', '{\"keys\": [{\"kty\": \"EC\"}]}', 'f', '2026-01-01Z',
                  '294247-01-10 04:00:54.775807+00', 'enabled', '{}')",
            "trust_keyset_version_expires_at_range_check",
        ),
        (
            "INSERT INTO consumed_assertion VALUES
                 ('ten_a', 'src_gh', sha256('jti_x'), 'dk_1', now(), 'infinity')",
            "consumed_assertion_retain_until_range_check",
        ),
    ] {
        rejected(&mut conn, sql, "23514", Some(constraint)).await;
    }
    drop(conn);
    db.drop([pool]).await;
}

/// The new revision columns and triggers follow the other revisioned
/// tables: `bigint NOT NULL DEFAULT 1`, a named check, and a `BEFORE INSERT
/// OR UPDATE` trigger on `skyoauth_check_revision()` that fires in every
/// `session_replication_role`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn revision_columns_and_triggers_match_the_other_revisioned_tables() {
    let (db, pool) = seeded().await;
    for table in REVISIONED {
        let (data_type, not_null, default): (String, bool, Option<String>) = sqlx::query_as(
            "SELECT format_type(a.atttypid, a.atttypmod), a.attnotnull, pg_get_expr(d.adbin, d.adrelid)
             FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
             WHERE a.attrelid = $1::regclass AND a.attname = 'revision'",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (data_type.as_str(), not_null, default.as_deref()),
            ("bigint", true, Some("1")),
            "{table}"
        );
        let check: String = sqlx::query_scalar(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint
             WHERE conrelid = $1::regclass AND conname = $1 || '_revision_check'",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(check, "CHECK ((revision >= 1))", "{table}");
        // (name, function, tgtype, tgenabled); tgtype bits: 1 row, 2
        // before, 4 insert, 16 update.
        let trigger: (String, String, i16, String) = sqlx::query_as(
            "SELECT t.tgname::text, p.proname::text, t.tgtype, t.tgenabled::text
             FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
             WHERE t.tgrelid = $1::regclass AND t.tgname = $1 || '_revision'",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            trigger,
            (
                format!("{table}_revision"),
                "skyoauth_check_revision".into(),
                1 | 2 | 4 | 16,
                "A".into()
            )
        );
    }
    db.drop([pool]).await;
}

/// A tenant, a principal and a version start at revision 1 and each UPDATE
/// advances it by exactly 1, in both replication modes, and a version's
/// status stays writable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn revisions_start_at_one_and_advance_by_one() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let revisions =
        |table: &'static str| AssertSqlSafe(format!("SELECT revision FROM {table} ORDER BY id"));
    for table in REVISIONED {
        let seeded: Vec<i64> = sqlx::query_scalar(revisions(table))
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        assert!(seeded.iter().all(|r| *r == 1), "{table}: {seeded:?}");
    }
    for mode in MODES {
        run(&mut *conn, mode).await;
        for (sql, message) in [
            (
                "INSERT INTO tenant VALUES ('ten_x', 'x', 'ns_x', 'enabled', now(), 2)",
                "tenant rows start at revision 1, not 2",
            ),
            (
                "INSERT INTO principal VALUES ('wld_x', 'ten_a', 'workload', 'x', 'enabled', now(), 0)",
                "principal rows start at revision 1, not 0",
            ),
            (
                "INSERT INTO trust_keyset_version VALUES
                     ('kv_x', 'ten_a', 'ks_1', '{\"keys\": [{\"kty\": \"EC\"}]}', 'f', '2026-01-01Z', NULL,
                      'enabled', '{}', 2)",
                "trust_keyset_version rows start at revision 1, not 2",
            ),
            (
                "UPDATE tenant SET name = 'x' WHERE id = 'ten_a'",
                "an update of tenant must advance revision 1 by 1, not to 1",
            ),
            (
                "UPDATE principal SET status = 'disabled', revision = revision + 2 WHERE id = 'wld_1'",
                "an update of principal must advance revision 1 by 1, not to 3",
            ),
            (
                "UPDATE trust_keyset_version SET status = 'disabled' WHERE id = 'kv_1'",
                "an update of trust_keyset_version must advance revision 1 by 1, not to 1",
            ),
        ] {
            rejected(&mut conn, sql, "SK001", Some(message)).await;
        }
    }
    run(&mut *conn, "SET session_replication_role = origin").await;
    // The check backs the trigger.
    rejected(
        &mut conn,
        "BEGIN; ALTER TABLE tenant DISABLE TRIGGER USER; UPDATE tenant SET revision = 0",
        "23514",
        Some("tenant_revision_check"),
    )
    .await;
    run(
        &mut *conn,
        "UPDATE tenant SET name = 'renamed', status = 'disabled', revision = revision + 1 WHERE id = 'ten_a';
         UPDATE principal SET name = 'renamed', revision = revision + 1 WHERE id = 'wld_1';
         UPDATE principal SET status = 'disabled', revision = revision + 1 WHERE id = 'wld_1';
         UPDATE trust_keyset_version SET status = 'disabled', revision = revision + 1 WHERE id = 'kv_1';
         INSERT INTO tenant VALUES ('ten_c', 'c', 'ns_c', 'enabled', now(), 1)",
    )
    .await;
    for (table, expected) in [
        ("tenant", vec![2, 1, 1]),
        ("principal", vec![1, 3]),
        ("trust_keyset_version", vec![2]),
    ] {
        let actual: Vec<i64> = sqlx::query_scalar(revisions(table))
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        assert_eq!(actual, expected, "{table}");
    }
    // The keyset's revision does not move with its version's.
    let keyset: i64 = sqlx::query_scalar("SELECT revision FROM trust_keyset WHERE id = 'ks_1'")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(keyset, 1);
    drop(conn);
    db.drop([pool]).await;
}

/// Every immutable column of a tenant, a principal and a version fails on
/// the table's immutable-column guard, in both replication modes, even when
/// the UPDATE advances the revision as the revision trigger requires: the
/// `SK001` carries the guard's message, so it does not come from the
/// revision trigger. The columns are the guards' lists of `0002` and `0004`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn immutable_columns_fail_on_their_guard_with_an_advancing_revision() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    // (table, row, column, a new value).
    let cases: [(&str, &str, &str, &str); 15] = [
        ("tenant", "ten_a", "id", "'ten_z'"),
        ("tenant", "ten_a", "secret_namespace", "'ns_z'"),
        (
            "tenant",
            "ten_a",
            "created_at",
            "created_at - interval '1 day'",
        ),
        ("principal", "wld_1", "id", "'wld_z'"),
        ("principal", "wld_1", "tenant_id", "'ten_b'"),
        ("principal", "wld_1", "kind", "'service'"),
        (
            "principal",
            "wld_1",
            "created_at",
            "created_at - interval '1 day'",
        ),
        ("trust_keyset_version", "kv_1", "id", "'kv_z'"),
        ("trust_keyset_version", "kv_1", "tenant_id", "'ten_b'"),
        ("trust_keyset_version", "kv_1", "keyset_id", "'ks_z'"),
        (
            "trust_keyset_version",
            "kv_1",
            "public_jwks",
            r#"'{"keys": [{"kty": "RSA"}]}'"#,
        ),
        ("trust_keyset_version", "kv_1", "fingerprint", "'sha256:02'"),
        (
            "trust_keyset_version",
            "kv_1",
            "effective_at",
            "'2026-02-01Z'",
        ),
        (
            "trust_keyset_version",
            "kv_1",
            "expires_at",
            "'2027-01-01Z'",
        ),
        (
            "trust_keyset_version",
            "kv_1",
            "provenance",
            r#"'{"uploaded_by": "adm_2"}'"#,
        ),
    ];
    for mode in MODES {
        run(&mut *conn, mode).await;
        for (table, id, column, value) in cases {
            rejected(
                &mut conn,
                &format!(
                    "UPDATE {table} SET {column} = {value}, revision = revision + 1 WHERE id = '{id}'"
                ),
                "SK001",
                Some(&format!("column {table}.{column} is immutable")),
            )
            .await;
        }
    }
    drop(conn);
    db.drop([pool]).await;
}

/// Every foreign key's columns lead an index of the referencing table,
/// except the listed ones, whose table's primary key leads with one of
/// their columns, and the column it references has a unique index of its
/// own, so that column alone identifies the referenced row; a later foreign
/// key with neither fails here. The `0007` indexes have the expected names
/// and definitions.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_foreign_key_is_served_by_an_index() {
    let (db, pool) = seeded().await;
    // (foreign key, its columns, whether an index leads with exactly those
    // columns in any order, the first column of the table's primary key,
    // and whether the referenced column paired with that first column, if
    // the key has it, has a single-column unique index).
    let mut keys: Vec<(String, Vec<String>, bool, String, bool)> = sqlx::query_as(
        "SELECT k.conname::text,
                (SELECT array_agg(a.attname::text ORDER BY u.ord)
                 FROM unnest(k.conkey) WITH ORDINALITY u(attnum, ord)
                 JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.attnum),
                EXISTS (SELECT 1 FROM pg_index i
                        WHERE i.indrelid = k.conrelid AND i.indpred IS NULL
                          AND i.indnkeyatts >= cardinality(k.conkey)
                          AND (SELECT array_agg(x ORDER BY x)
                               FROM unnest((i.indkey::int2[])[0:cardinality(k.conkey) - 1]) x)
                            = (SELECT array_agg(x ORDER BY x) FROM unnest(k.conkey) x)),
                (SELECT a.attname::text FROM pg_index p
                 JOIN pg_attribute a ON a.attrelid = p.indrelid AND a.attnum = p.indkey[0]
                 WHERE p.indrelid = k.conrelid AND p.indisprimary),
                EXISTS (SELECT 1 FROM pg_index p
                        JOIN unnest(k.conkey, k.confkey) u(conkey, confkey)
                          ON u.conkey = p.indkey[0]
                        JOIN pg_index r
                          ON r.indrelid = k.confrelid AND r.indisunique AND r.indpred IS NULL
                         AND r.indnkeyatts = 1 AND r.indkey[0] = u.confkey
                        WHERE p.indrelid = k.conrelid AND p.indisprimary)
         FROM pg_constraint k
         WHERE k.contype = 'f' AND k.connamespace = to_regnamespace(quote_ident(current_schema()))",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    keys.sort();
    let unindexed: Vec<&str> = keys
        .iter()
        .filter(|(_, _, indexed, _, _)| !indexed)
        .map(|(name, _, _, _, _)| name.as_str())
        .collect();
    assert_eq!(unindexed, UNINDEXED_FOREIGN_KEYS);
    for (name, columns, _, primary, unique) in keys.iter().filter(|(_, _, indexed, _, _)| !indexed)
    {
        assert!(
            columns.contains(primary) && *unique,
            "{name}: {columns:?} {primary} {unique}"
        );
    }

    let mut indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, pg_get_indexdef(c.oid) FROM pg_class c
         WHERE c.relkind = 'i' AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND c.relname = ANY($1)",
    )
    .bind(INDEXES.map(|(name, _, _)| name.to_string()).to_vec())
    .fetch_all(&pool)
    .await
    .unwrap();
    indexes.sort();
    let mut expected: Vec<(String, String)> = INDEXES
        .iter()
        .map(|(name, table, columns)| {
            (
                name.to_string(),
                format!("CREATE INDEX {name} ON public.{table} USING btree ({columns})"),
            )
        })
        .collect();
    expected.sort();
    assert_eq!(indexes, expected);
    db.drop([pool]).await;
}

/// The README precondition query counts the rows outside the range on a
/// `0006` database, an `audit_event` row included; with such a row `0007`
/// fails with `23514` and leaves the database at `0006`; once the table
/// owner repairs the rows with the README's steps, the query counts none
/// and `0007` applies, giving existing rows revision 1.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn upgrade_precondition_finds_the_rows_that_would_fail_the_upgrade() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    MIGRATOR.run_to(6, &pool).await.unwrap();
    run(&pool, SEED).await;
    let zero: Vec<(String, i64)> = {
        let mut zero: Vec<(String, i64)> = RANGE_CASES
            .iter()
            .map(|c| (format!("{}.{}", c.table, c.column), 0))
            .collect();
        zero.sort();
        zero
    };
    let counting = |columns: &[&str]| {
        let mut counted = zero.clone();
        for (column, count) in &mut counted {
            if columns.contains(&column.as_str()) {
                *count = 1;
            }
        }
        counted
    };
    assert_eq!(precondition(&pool).await, zero);

    // An audit event outside the range is counted too. It is not repaired
    // in place (README: an integrity incident), so it is rolled back here.
    {
        let mut conn = pool.acquire().await.unwrap();
        run(
            &mut *conn,
            r"BEGIN;
             INSERT INTO audit_event VALUES
                 ('evt_inf', NULL, 2, '\x01', 'infinity', 'adm_1', 'tenant.update', 'ten_a', 2, 3, 'success');
             UPDATE audit_chain_head SET sequence = 2, head_hash = '\x02'",
        )
        .await;
        assert_eq!(
            precondition(&mut *conn).await,
            counting(&["audit_event.timestamp"])
        );
        run(&mut *conn, "ROLLBACK").await;
    }

    // Rows the registry never writes, but a restore or a hand-written
    // statement can.
    run(
        &pool,
        "INSERT INTO tenant VALUES ('ten_inf', 'inf', 'ns_inf', 'enabled', 'infinity');
         INSERT INTO trust_keyset_version VALUES
             ('kv_far', 'ten_a', 'ks_1', '{\"keys\": [{\"kty\": \"EC\"}]}', 'f', '2026-01-01Z',
              '294247-01-10 04:00:54.775807+00', 'enabled', '{}');
         UPDATE service_grant SET valid_until = 'infinity', revision = revision + 1 WHERE id = 'grt_1';
         INSERT INTO consumed_assertion VALUES
             ('ten_a', 'src_gh', sha256('jti_inf'), 'dk_1', now(), 'infinity');
         BEGIN;
         ALTER TABLE schema_info DISABLE TRIGGER schema_info_append_only;
         UPDATE schema_info SET created_at = '-infinity';
         ALTER TABLE schema_info ENABLE ALWAYS TRIGGER schema_info_append_only;
         COMMIT",
    )
    .await;
    assert_eq!(
        precondition(&pool).await,
        counting(&[
            "schema_info.created_at",
            "tenant.created_at",
            "trust_keyset_version.expires_at",
            "service_grant.valid_until",
            "consumed_assertion.retain_until",
        ])
    );

    let err = persistence::migrate(&pool).await.unwrap_err();
    let cause = match &err {
        MigrateError::Execute(cause) | MigrateError::ExecuteMigration(cause, _) => cause,
        other => panic!("{other:?}"),
    };
    assert_eq!(sqlstate(cause), "23514", "{err}");
    let (version, revision): (i64, Option<String>) = sqlx::query_as(
        "SELECT max(version), (SELECT attname::text FROM pg_attribute
                               WHERE attrelid = 'tenant'::regclass AND attname = 'revision')
         FROM _sqlx_migrations",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((version, revision), (6, None));

    // The owner's repair, as the README lists it: in one transaction, for
    // each table, list its user triggers, disable them, update the row (and
    // advance a revision the table has), and enable every listed trigger
    // ALWAYS again; before the commit no user trigger is in another state.
    let triggers_enabled = precondition_sql(1);
    let mut conn = pool.acquire().await.unwrap();
    run(&mut *conn, "BEGIN").await;
    for (table, update) in [
        ("schema_info", "UPDATE schema_info SET created_at = now()"),
        (
            "tenant",
            "UPDATE tenant SET created_at = now() WHERE id = 'ten_inf'",
        ),
        (
            "trust_keyset_version",
            "UPDATE trust_keyset_version SET expires_at = '2027-01-01Z' WHERE id = 'kv_far'",
        ),
        (
            "service_grant",
            "UPDATE service_grant SET valid_until = '2027-01-01Z', revision = revision + 1
             WHERE id = 'grt_1'",
        ),
        (
            "consumed_assertion",
            "UPDATE consumed_assertion SET retain_until = now() + interval '1 hour'
             WHERE replay_key_digest = sha256('jti_inf')",
        ),
    ] {
        let triggers: Vec<String> = sqlx::query_scalar(
            "SELECT tgname::text FROM pg_trigger WHERE tgrelid = $1::regclass AND NOT tgisinternal",
        )
        .bind(table)
        .fetch_all(&mut *conn)
        .await
        .unwrap();
        run(
            &mut *conn,
            &format!("ALTER TABLE {table} DISABLE TRIGGER USER; {update}"),
        )
        .await;
        // The check sees every trigger the repair has turned off.
        let disabled: i64 = sqlx::query_scalar(AssertSqlSafe(triggers_enabled.clone()))
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(disabled, i64::try_from(triggers.len()).unwrap(), "{table}");
        for trigger in triggers {
            run(
                &mut *conn,
                &format!("ALTER TABLE {table} ENABLE ALWAYS TRIGGER {trigger}"),
            )
            .await;
        }
    }
    let not_always: i64 = sqlx::query_scalar(AssertSqlSafe(triggers_enabled))
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(not_always, 0);
    run(&mut *conn, "COMMIT").await;
    drop(conn);
    assert_eq!(precondition(&pool).await, zero);
    // The repair advanced the grant's revision past the one that set the
    // bad value.
    let grant: i64 = sqlx::query_scalar("SELECT revision FROM service_grant WHERE id = 'grt_1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(grant, 3);

    persistence::migrate(&pool).await.unwrap();
    let revisions: Vec<(String, i64)> = sqlx::query_as(
        "SELECT 'tenant', max(revision) FROM tenant
         UNION ALL SELECT 'principal', max(revision) FROM principal
         UNION ALL SELECT 'trust_keyset_version', max(revision) FROM trust_keyset_version",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        revisions,
        [
            ("tenant".into(), 1),
            ("principal".into(), 1),
            ("trust_keyset_version".into(), 1)
        ]
    );
    // After the upgrade the query still runs and counts nothing.
    assert_eq!(precondition(&pool).await, zero);
    db.drop([pool]).await;
}
