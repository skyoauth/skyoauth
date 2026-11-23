//! Constraints and guards of the `0005_operator` migration against a real
//! PostgreSQL server: operator identities, credentials and role bindings, the
//! recovery state, administrative operations and consumed single-use WIF
//! proofs.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database, the replica-role test needs
//! `SET` on `session_replication_role` and the privilege tests `CREATEROLE`
//! (`common/mod.rs`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use common::TestDb;
use skyoauth_service::persistence::{self, PgPool};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Postgres};
use std::time::Duration;

/// Two tenants, the instance policy row and three audit events; a single-use
/// source in each tenant; two operators with one credential each, both
/// `security_admin`, the second also `trust_admin` of `ten_a`; the recovery
/// state; a pending instance operation (`op_1`) with its approval (`op_2`), a
/// pending tenant operation (`op_3`) and a pending recovery challenge
/// (`op_4`); and one consumed proof.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO instance_security_policy (instance_id) VALUES ('inst_1');
    INSERT INTO audit_event VALUES ('evt_1', NULL, 1, NULL, '2026-11-20Z', 'adm_1', 'instance_security_policy.update', 'inst_1', 1, NULL, 'pending');
    UPDATE audit_chain_head SET sequence = 1, head_hash = '\x01';
    INSERT INTO audit_event VALUES ('evt_2', NULL, 2, '\x01', '2026-11-20Z', 'adm_2', 'administrative_operation.approve', 'op_1', NULL, NULL, 'success');
    UPDATE audit_chain_head SET sequence = 2, head_hash = '\x02';
    INSERT INTO audit_event VALUES ('evt_3', 'ten_a', 3, '\x02', '2026-11-20Z', 'adm_2', 'service_grant.update', 'grt_1', 1, NULL, 'pending');
    UPDATE audit_chain_head SET sequence = 3, head_hash = '\x03';
    -- Enabled egress entries for the seeded destinations (0011 guard).
    INSERT INTO egress_allowlist_entry VALUES
        ('egr_seed_1', 'oidc_discovery', 'https://token.actions.githubusercontent.com/.well-known/openid-configuration', 'enabled'),
        ('egr_seed_2', 'oidc_discovery', 'https://x/d', 'enabled');
    INSERT INTO trust_source VALUES
        ('src_a', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'on_demand_jwt', NULL, 'single_use', 'enabled'),
        ('src_b', 'ten_b', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'on_demand_jwt', NULL, 'single_use', 'enabled');
    INSERT INTO admin_identity VALUES ('adm_1', 'enabled'), ('adm_2', 'enabled');
    INSERT INTO admin_credential VALUES
        ('crd_1', 'adm_1', 'sha256:aa', 'ops-ca', 'enabled', NULL),
        ('crd_2', 'adm_2', 'sha256:13d29e4a916a98f85b3637e0dbafd3c1bda532d9029737d021b920e0981ff9d9', 'ops-ca', 'enabled', NULL);
    INSERT INTO admin_role_binding VALUES
        ('rb_1', 'adm_1', 'security_admin', NULL, 'enabled'),
        ('rb_2', 'adm_2', 'security_admin', NULL, 'enabled'),
        ('rb_3', 'adm_2', 'trust_admin', 'ten_a', 'enabled');
    INSERT INTO recovery_state VALUES ('inst_1', true, '\x0a0b', 1);
    INSERT INTO administrative_operation VALUES
        ('op_1', NULL, 'adm_1', 'instance_security_policy.update', sha256('op_1'), 1,
         '{"widening_second_approver": true}', NULL, '2026-11-20 01:00Z', NULL, NULL, NULL, NULL, 1, 'pending', 'evt_1'),
        ('op_2', NULL, 'adm_2', 'approve', sha256('op_2'), 1, '{}', NULL, NULL, NULL, NULL, NULL, 'op_1', 1, 'applied', 'evt_2'),
        ('op_3', 'ten_a', 'adm_2', 'service_grant.update', sha512('op_3'), 4, '{"status": "enabled"}',
         NULL, '2026-11-20 01:00Z', NULL, NULL, NULL, NULL, 1, 'pending', 'evt_3'),
        ('op_4', NULL, 'recovery', 'operator_restoration', sha256('op_4'), 1, '{}',
         sha256('challenge'), '2026-11-20 00:05Z', NULL, NULL, NULL, NULL, 1, 'pending', 'evt_1');
    INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')"#;

/// Every table of 0005.
const TABLES: [&str; 6] = [
    "admin_identity",
    "admin_credential",
    "admin_role_binding",
    "recovery_state",
    "administrative_operation",
    "consumed_assertion",
];

/// The revisioned tables.
const REVISIONED: [&str; 3] = [
    "admin_role_binding",
    "recovery_state",
    "administrative_operation",
];

/// The functions 0005 adds that resolve no table.
const FUNCTIONS: [&str; 3] = [
    "skyoauth_check_recovery_key_rotation",
    "skyoauth_reject_change_once_set",
    "skyoauth_reject_consume_after_revoke",
];

/// The approval and revocation guard functions 0005 adds; each reads
/// `administrative_operation`, named with its schema
/// (schema_operation_approval_guard.rs).
const READERS: [&str; 2] = [
    "skyoauth_check_operation_approval",
    "skyoauth_check_operation_revocation",
];

/// A row as column and SQL value pairs.
type Row = &'static [(&'static str, &'static str)];

/// Column defaults for [`insert`]: a row that each table accepts in the seed.
const IDENTITY: Row = &[("id", "'adm_x'"), ("status", "'enabled'")];
const CREDENTIAL: Row = &[
    ("id", "'crd_x'"),
    ("admin_id", "'adm_1'"),
    ("public_identity", "'sha256:bb'"),
    ("trust_anchor_ref", "'ops-ca'"),
    ("status", "'enabled'"),
];
const BINDING: Row = &[
    ("id", "'rb_x'"),
    ("admin_id", "'adm_1'"),
    ("role", "'trust_admin'"),
    ("tenant_id", "'ten_b'"),
    ("status", "'enabled'"),
];
/// The seed already holds the single row, so this one is rejected with 23505
/// unless an earlier rule rejects it.
const RECOVERY: Row = &[
    ("instance_id", "'inst_1'"),
    ("bootstrap_closed", "true"),
    ("recovery_public_key", r"'\x01'"),
    ("recovery_key_epoch", "1"),
];
const OPERATION: Row = &[
    ("id", "'op_x'"),
    ("tenant_id", "NULL"),
    ("actor_id", "'adm_1'"),
    ("kind", "'tenant.create'"),
    ("request_digest", "sha256('x')"),
    ("expected_revision", "0"),
    ("immutable_plan", "'{}'"),
    ("challenge_hash", "NULL"),
    ("expires_at", "NULL"),
    ("consumed_at", "NULL"),
    ("revoked_at", "NULL"),
    ("revocation_operation_id", "NULL"),
    ("approves_operation_id", "NULL"),
    ("outcome", "'pending'"),
    ("audit_id", "'evt_1'"),
];
const CONSUMED: Row = &[
    ("tenant_id", "'ten_a'"),
    ("trust_source_id", "'src_a'"),
    ("replay_key_digest", "sha256('x')"),
    ("digest_key_version", "'dk_1'"),
    ("consumed_at", "'2026-11-20Z'"),
    ("retain_until", "'2026-11-21Z'"),
];

/// An INSERT into `table` of the `defaults` row with the columns in `set`
/// replaced (or added).
fn insert(table: &str, defaults: &[(&str, &str)], set: &[(&str, &str)]) -> String {
    let mut columns: Vec<(&str, &str)> = defaults.to_vec();
    for (column, value) in set {
        match columns.iter_mut().find(|(c, _)| c == column) {
            Some(entry) => entry.1 = value,
            None => columns.push((column, value)),
        }
    }
    let names: Vec<&str> = columns.iter().map(|(c, _)| *c).collect();
    let values: Vec<&str> = columns.iter().map(|(_, v)| *v).collect();
    format!(
        "INSERT INTO {table} ({}) VALUES ({})",
        names.join(", "),
        values.join(", ")
    )
}

async fn seeded_on(pool: &PgPool) {
    persistence::migrate(pool).await.unwrap();
    run(pool, SEED).await;
}

async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    seeded_on(&pool).await;
    (db, pool)
}

async fn run<'c>(executor: impl Executor<'c, Database = Postgres>, sql: &'static str) {
    if let Err(err) = sqlx::raw_sql(sql).execute(executor).await {
        panic!("{sql}: {err}");
    }
}

async fn run_owned<'c>(executor: impl Executor<'c, Database = Postgres>, sql: String) {
    if let Err(err) = sqlx::raw_sql(AssertSqlSafe(sql.clone()))
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

/// Runs each case on its own and checks that it fails with its SQLSTATE.
/// A case is one line, `<SQLSTATE> <statements>`; blank lines are skipped.
/// SK001 is the guard triggers' state; 23502 is `not_null_violation`, 23503
/// `foreign_key_violation`, 23505 `unique_violation` and 23514
/// `check_violation`.
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

/// As [`rejects`], for generated statements.
async fn rejects_each(pool: &PgPool, cases: &[(&str, String)]) {
    for (code, sql) in cases {
        let err = sqlx::raw_sql(AssertSqlSafe(sql.clone()))
            .execute(pool)
            .await
            .expect_err(sql);
        assert_eq!(sqlstate(&err), *code, "{sql}: {err}");
    }
}

/// Checks that `sql` fails with 23514 from the check named `constraint`.
async fn violates(pool: &PgPool, sql: String, constraint: &str) {
    let err = sqlx::raw_sql(AssertSqlSafe(sql.clone()))
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

/// Runs `sql` in a transaction that is rolled back, and checks that it
/// succeeds.
async fn accepts(pool: &PgPool, sql: &str) {
    let mut conn = pool.acquire().await.unwrap();
    if let Err(err) = sqlx::raw_sql(AssertSqlSafe(format!("BEGIN; {sql}; ROLLBACK")))
        .execute(&mut *conn)
        .await
    {
        panic!("{sql}: {err}");
    }
}

async fn revisions(pool: &PgPool, table: &str, key: &str) -> Vec<i64> {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT revision FROM {table} ORDER BY {key}"
    )))
    .fetch_all(pool)
    .await
    .unwrap()
}

/// SQL for incompressible text: the md5 hex digests of `blocks` consecutive
/// integers from `first`, 32 bytes each.
fn md5_hex(first: u32, blocks: u32) -> String {
    format!(
        "(SELECT string_agg(md5(i::text), '' ORDER BY i) FROM generate_series({first}, {}) i)",
        first + blocks - 1
    )
}

/// SQL for an incompressible 255-byte ID.
fn md5_id(first: u32) -> String {
    format!("left({}, 255)", md5_hex(first, 8))
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn operator_migration_is_recorded_once_and_rerun_is_a_no_op() {
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
    assert!(first.contains(&(5, "operator".into(), true)), "{first:?}");
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    for (table, key) in [
        ("admin_role_binding", "id"),
        ("recovery_state", "instance_id"),
        ("administrative_operation", "id"),
    ] {
        assert!(
            revisions(&pool, table, key).await.iter().all(|r| *r == 1),
            "{table}"
        );
    }
    db.drop([pool]).await;
}

/// Catalog properties that behaviour tests cannot see directly.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn operator_catalog_pins_keys_bounds_triggers_and_search_path() {
    let (db, pool) = seeded().await;
    let tables: Vec<String> = TABLES.iter().map(|t| t.to_string()).collect();

    // Every trigger of 0005 is a guard that fires in every
    // session_replication_role, none deferred, each calling its function.
    let mut triggers: Vec<(String, String, String, String, bool)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, t.tgenabled::text, p.proname::text,
                t.tgdeferrable OR t.tginitdeferred
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND c.relname = ANY($1)",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    triggers.sort();
    let guard = |table: &str, name: &str, function: &str| {
        (
            table.to_string(),
            format!("{table}_{name}"),
            "A".to_string(),
            function.to_string(),
            false,
        )
    };
    let immutable = "skyoauth_reject_immutable_change";
    let once = "skyoauth_reject_change_once_set";
    let revision = "skyoauth_check_revision";
    let mut expected = vec![
        guard("admin_identity", "immutable", immutable),
        guard("admin_credential", "immutable", immutable),
        guard("admin_credential", "set_once", once),
        guard("admin_role_binding", "immutable", immutable),
        guard("admin_role_binding", "revision", revision),
        guard("recovery_state", "immutable", immutable),
        guard("recovery_state", "set_once", once),
        guard(
            "recovery_state",
            "key_rotation",
            "skyoauth_check_recovery_key_rotation",
        ),
        guard("recovery_state", "revision", revision),
        guard("administrative_operation", "immutable", immutable),
        guard("administrative_operation", "set_once", once),
        guard(
            "administrative_operation",
            "no_consume_after_revoke",
            "skyoauth_reject_consume_after_revoke",
        ),
        guard("administrative_operation", "revision", revision),
        // The approval and revocation guards (AFTER triggers).
        guard(
            "administrative_operation",
            "approval_check",
            "skyoauth_check_operation_approval",
        ),
        guard(
            "administrative_operation",
            "revocation_check",
            "skyoauth_check_operation_revocation",
        ),
        guard(
            "consumed_assertion",
            "no_update",
            "skyoauth_reject_mutation",
        ),
    ];
    // The 0006 delete and truncate guards (schema_registry_guards.rs).
    for table in TABLES {
        expected.push(guard(table, "no_truncate", "skyoauth_reject_truncate"));
    }
    for table in [
        "admin_identity",
        "admin_credential",
        "admin_role_binding",
        "recovery_state",
        "administrative_operation",
    ] {
        expected.push(guard(table, "no_delete", "skyoauth_reject_delete"));
    }
    expected.push(guard(
        "consumed_assertion",
        "delete_after_retention",
        "skyoauth_reject_delete_before_retention",
    ));
    expected.sort();
    assert_eq!(triggers, expected);

    // Each trigger fires on the operations its guard covers, whatever
    // columns an UPDATE names (no UPDATE OF column list), but for the
    // revocation guard, an AFTER trigger on an UPDATE OF its one column.
    let mut events: Vec<(String, i16, i32)> = sqlx::query_as(
        "SELECT t.tgname::text, t.tgtype, cardinality(t.tgattr::int2[])
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
         WHERE NOT t.tgisinternal AND c.relname = ANY($1)",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    events.sort();
    assert_eq!(events.len(), expected.len());
    // tgtype bits: 1 row, 2 before, 4 insert, 8 delete, 16 update, 32
    // truncate.
    for (name, tgtype, columns) in &events {
        if name == "administrative_operation_approval_check" {
            assert_eq!((*tgtype, *columns), (1 | 4, 0), "{name}");
            continue;
        }
        if name == "administrative_operation_revocation_check" {
            assert_eq!((*tgtype, *columns), (1 | 4 | 16, 1), "{name}");
            continue;
        }
        let want = if name.ends_with("_revision") {
            1 | 2 | 4 | 16
        } else if name.ends_with("_no_truncate") {
            2 | 32
        } else if name.contains("_delete") {
            1 | 2 | 8
        } else {
            1 | 2 | 16
        };
        assert_eq!((*tgtype, *columns), (want, 0), "{name}");
    }

    // The new functions resolve no table: they pin exactly pg_catalog and
    // pg_temp, and name no table of the schema.
    let mut functions: Vec<(String, Vec<String>, String)> = sqlx::query_as(
        "SELECT p.proname::text, p.proconfig, p.prosrc FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname = ANY($1)",
    )
    .bind(FUNCTIONS.map(String::from).to_vec())
    .fetch_all(&pool)
    .await
    .unwrap();
    functions.sort();
    assert_eq!(functions.len(), FUNCTIONS.len());
    for (name, config, source) in &functions {
        assert_eq!(config, &["search_path=pg_catalog, pg_temp"], "{name}");
        for table in TABLES {
            assert!(!source.contains(table), "{name} names {table}");
        }
    }
    // The approval and revocation guards pin the same path and name the one
    // table they read with its schema only.
    let mut readers: Vec<(String, Vec<String>, String)> = sqlx::query_as(
        "SELECT p.proname::text, p.proconfig, p.prosrc FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname = ANY($1)",
    )
    .bind(READERS.map(String::from).to_vec())
    .fetch_all(&pool)
    .await
    .unwrap();
    readers.sort();
    assert_eq!(readers.len(), READERS.len());
    for (name, config, source) in &readers {
        assert_eq!(config, &["search_path=pg_catalog, pg_temp"], "{name}");
        // The constraint names they raise start with the table name.
        let read = source.replace("'administrative_operation_", "'");
        assert_eq!(
            read.matches("administrative_operation").count(),
            1,
            "{name}"
        );
        assert_eq!(
            read.matches(" public.administrative_operation o").count(),
            1,
            "{name}"
        );
        for table in TABLES.iter().filter(|t| **t != "administrative_operation") {
            assert!(!source.contains(table), "{name} names {table}");
        }
    }

    // IDs, keys, references and enumerations compare byte-wise; only the
    // outcome text does not.
    let not_c: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = ANY($1)
           AND data_type = 'text' AND collation_name IS DISTINCT FROM 'C'
         ORDER BY 1 USING ~<~, 2 USING ~<~",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        not_c,
        [(
            "administrative_operation".to_string(),
            "outcome".to_string()
        )]
    );

    // Every foreign key of 0005 is named, takes no action on update or
    // delete, is MATCH SIMPLE and is checked at once.
    let mut fkeys: Vec<(String, String, String, bool, String)> = sqlx::query_as(
        "SELECT c.relname::text, k.conname::text, pg_get_constraintdef(k.oid),
                k.condeferrable OR k.condeferred,
                k.confupdtype::text || k.confdeltype::text || k.confmatchtype::text
         FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
         WHERE k.contype = 'f' AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND c.relname = ANY($1)",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    fkeys.sort();
    let fkey = |table: &str, name: &str, def: &str| {
        (
            table.to_string(),
            name.to_string(),
            format!("FOREIGN KEY {def}"),
            false,
            "aas".to_string(),
        )
    };
    let operation = "REFERENCES administrative_operation(id)";
    let mut expected = vec![
        fkey(
            "admin_credential",
            "admin_credential_admin_id_fkey",
            "(admin_id) REFERENCES admin_identity(id)",
        ),
        fkey(
            "admin_role_binding",
            "admin_role_binding_admin_id_fkey",
            "(admin_id) REFERENCES admin_identity(id)",
        ),
        fkey(
            "admin_role_binding",
            "admin_role_binding_tenant_id_fkey",
            "(tenant_id) REFERENCES tenant(id)",
        ),
        fkey(
            "administrative_operation",
            "administrative_operation_approves_operation_id_fkey",
            &format!("(approves_operation_id) {operation}"),
        ),
        fkey(
            "administrative_operation",
            "administrative_operation_audit_id_fkey",
            "(audit_id) REFERENCES audit_event(id)",
        ),
        fkey(
            "administrative_operation",
            "administrative_operation_revocation_operation_id_fkey",
            &format!("(revocation_operation_id) {operation}"),
        ),
        fkey(
            "administrative_operation",
            "administrative_operation_tenant_id_fkey",
            "(tenant_id) REFERENCES tenant(id)",
        ),
        fkey(
            "consumed_assertion",
            "consumed_assertion_trust_source_id_fkey",
            "(tenant_id, trust_source_id) REFERENCES trust_source(tenant_id, id)",
        ),
        fkey(
            "recovery_state",
            "recovery_state_instance_id_fkey",
            "(instance_id) REFERENCES instance_security_policy(instance_id)",
        ),
    ];
    expected.sort();
    assert_eq!(fkeys, expected);

    // The keys and unique indexes, exactly.
    let mut indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, pg_get_indexdef(i.indexrelid) FROM pg_index i
         JOIN pg_class c ON c.oid = i.indexrelid
         WHERE i.indrelid = ANY($1::text[]::regclass[])",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    indexes.sort();
    let index = |name: &str, table: &str, def: &str| {
        (
            name.to_string(),
            format!("CREATE UNIQUE INDEX {name} ON public.{table} USING btree {def}"),
        )
    };
    let mut expected = vec![
        index("admin_identity_pkey", "admin_identity", "(id)"),
        index("admin_credential_pkey", "admin_credential", "(id)"),
        index(
            "admin_credential_public_identity_key",
            "admin_credential",
            "(public_identity)",
        ),
        index("admin_role_binding_pkey", "admin_role_binding", "(id)"),
        index(
            "admin_role_binding_admin_id_role_tenant_id_key",
            "admin_role_binding",
            "(admin_id, role, tenant_id) NULLS NOT DISTINCT",
        ),
        index("recovery_state_pkey", "recovery_state", "(instance_id)"),
        index("recovery_state_single_row", "recovery_state", "((true))"),
        index(
            "administrative_operation_pkey",
            "administrative_operation",
            "(id)",
        ),
        index(
            "consumed_assertion_pkey",
            "consumed_assertion",
            "(tenant_id, trust_source_id, replay_key_digest)",
        ),
        // The approver's read path, a partial index (inferred lead pick;
        // schema_operation_approval_guard.rs).
        (
            "administrative_operation_open_by_tenant".to_string(),
            "CREATE INDEX administrative_operation_open_by_tenant ON public.administrative_operation \
             USING btree (tenant_id, id) WHERE ((consumed_at IS NULL) AND (revoked_at IS NULL) \
             AND (expires_at IS NOT NULL))"
                .to_string(),
        ),
        // The pruning index of 0006 (schema_registry_guards.rs).
        (
            "consumed_assertion_retain_until_idx".to_string(),
            "CREATE INDEX consumed_assertion_retain_until_idx ON public.consumed_assertion \
             USING btree (retain_until)"
                .to_string(),
        ),
    ];
    // The referencing-side indexes of 0007 (schema_registry_shape.rs).
    for (table, column) in [
        ("admin_credential", "admin_id"),
        ("admin_role_binding", "tenant_id"),
        ("administrative_operation", "tenant_id"),
        ("administrative_operation", "revocation_operation_id"),
        ("administrative_operation", "approves_operation_id"),
        ("administrative_operation", "audit_id"),
    ] {
        let name = format!("{table}_{column}_idx");
        let def = format!("CREATE INDEX {name} ON public.{table} USING btree ({column})");
        expected.push((name, def));
    }
    expected.sort();
    assert_eq!(indexes, expected);

    // Only the fields the logical model marks optional may be NULL.
    let nullable: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
         WHERE c.relnamespace = to_regnamespace(quote_ident(current_schema())) AND c.relname = ANY($1)
           AND a.attnum > 0 AND NOT a.attisdropped AND NOT a.attnotnull
         ORDER BY 1 USING ~<~, 2 USING ~<~",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    let optional = [
        ("admin_credential", "revoked_at"),
        ("admin_role_binding", "tenant_id"),
        ("administrative_operation", "approves_operation_id"),
        ("administrative_operation", "challenge_hash"),
        ("administrative_operation", "consumed_at"),
        ("administrative_operation", "expires_at"),
        ("administrative_operation", "revocation_operation_id"),
        ("administrative_operation", "revoked_at"),
        ("administrative_operation", "tenant_id"),
    ];
    let optional: Vec<(String, String)> = optional
        .iter()
        .map(|(t, c)| (t.to_string(), c.to_string()))
        .collect();
    assert_eq!(nullable, optional);

    // Only created_at and revision have defaults; the service states every
    // other value.
    let defaults: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text, column_default::text
         FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = ANY($1)
           AND column_default IS NOT NULL
         ORDER BY 1 USING ~<~, 2 USING ~<~",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut expected: Vec<(String, String, String)> = REVISIONED
        .iter()
        .map(|t| (t.to_string(), "revision".to_string(), "1".to_string()))
        .chain([(
            "admin_identity".to_string(),
            "created_at".to_string(),
            "now()".to_string(),
        )])
        .collect();
    expected.sort();
    assert_eq!(defaults, expected);

    // Every column of a primary key, unique constraint, unique index or
    // foreign key of the 0005 tables has a named bound: an
    // <table>_<column>_octet_length_check (the name may abbreviate the
    // column) of at most 255 or 2048 bytes, or of 32 to 64 bytes for a
    // bytea digest, or, for an enumeration, its value-set check. The key
    // columns are listed first, so the bound check cannot pass vacuously.
    let key_columns = r"
        SELECT i.indrelid AS rel, k.attnum FROM pg_index i, unnest(i.indkey::int2[]) AS k(attnum)
        WHERE i.indisunique AND i.indrelid = ANY($1::text[]::regclass[])
        UNION
        SELECT c.conrelid, k.attnum FROM pg_constraint c, unnest(c.conkey) AS k(attnum)
        WHERE c.contype = 'f' AND c.conrelid = ANY($1::text[]::regclass[])";
    let keys: Vec<(String, String)> = sqlx::query_as(AssertSqlSafe(format!(
        "WITH keys AS ({key_columns})
         SELECT k.rel::regclass::text, a.attname::text
         FROM keys k JOIN pg_attribute a ON a.attrelid = k.rel AND a.attnum = k.attnum
         ORDER BY 1 USING ~<~, 2 USING ~<~"
    )))
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    let expected_keys = [
        ("admin_credential", "admin_id"),
        ("admin_credential", "id"),
        ("admin_credential", "public_identity"),
        ("admin_identity", "id"),
        ("admin_role_binding", "admin_id"),
        ("admin_role_binding", "id"),
        ("admin_role_binding", "role"),
        ("admin_role_binding", "tenant_id"),
        ("administrative_operation", "approves_operation_id"),
        ("administrative_operation", "audit_id"),
        ("administrative_operation", "id"),
        ("administrative_operation", "revocation_operation_id"),
        ("administrative_operation", "tenant_id"),
        ("consumed_assertion", "replay_key_digest"),
        ("consumed_assertion", "tenant_id"),
        ("consumed_assertion", "trust_source_id"),
        ("recovery_state", "instance_id"),
    ];
    let expected_keys: Vec<(String, String)> = expected_keys
        .iter()
        .map(|(t, c)| (t.to_string(), c.to_string()))
        .collect();
    assert_eq!(keys, expected_keys);
    let unbounded: Vec<(String, String)> = sqlx::query_as(AssertSqlSafe(format!(
        r"WITH keys AS ({key_columns})
          SELECT k.rel::regclass::text, a.attname::text
          FROM keys k JOIN pg_attribute a ON a.attrelid = k.rel AND a.attnum = k.attnum
          WHERE NOT EXISTS (
              SELECT FROM pg_constraint c
              WHERE c.conrelid = k.rel AND c.contype = 'c' AND c.conkey = ARRAY[k.attnum]
                AND ((c.conname ~ ('^' || k.rel::regclass::text || '_[a-z_]+_octet_length_check$')
                      AND (pg_get_constraintdef(c.oid)
                               ~ ('^CHECK \(\(octet_length\(' || a.attname || '\) <= (255|2048)\)\)$')
                           OR pg_get_constraintdef(c.oid)
                               ~ ('^CHECK \(\(\(octet_length\(' || a.attname || '\) >= 32\) AND \(octet_length\('
                                  || a.attname || '\) <= 64\)\)\)$')))
                  OR (c.conname = k.rel::regclass::text || '_' || a.attname || '_check'
                      AND pg_get_constraintdef(c.oid)
                          ~ ('^CHECK \(\(' || a.attname || ' = ANY \(ARRAY\[''[a-z_]+''::text(, ''[a-z_]+''::text)*\]\)\)\)$'))))
          ORDER BY 1 USING ~<~, 2 USING ~<~"
    )))
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(unbounded.is_empty(), "{unbounded:?}");

    // The full set of checks on the 0005 tables, with their definitions.
    // The bounds, character rules and multi-column rules are named for the
    // service's 23514 mapping (README.md); the other checks of one column
    // keep generated names.
    let mut checks: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint
         WHERE contype = 'c' AND conrelid = ANY($1::text[]::regclass[])",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    checks.sort();
    let non_empty = |column: &str| format!("CHECK (({column} <> ''::text))");
    let at_most = |column: &str, bytes: u32| format!("CHECK ((octet_length({column}) <= {bytes}))");
    let between = |column: &str, low: u32, high: u32| {
        format!(
            "CHECK (((octet_length({column}) >= {low}) AND (octet_length({column}) <= {high})))"
        )
    };
    let no_space = |column: &str| {
        format!(r#"CHECK ((({column} COLLATE "C") !~ '[[:space:][:cntrl:]]'::text))"#)
    };
    let status = "CHECK ((status = ANY (ARRAY['enabled'::text, 'disabled'::text])))".to_string();
    let revision = "CHECK ((revision >= 1))".to_string();
    let mut expected: Vec<(String, String)> = [
        ("admin_credential_admin_id_octet_length_check", at_most("admin_id", 255)),
        ("admin_credential_id_check", non_empty("id")),
        ("admin_credential_id_octet_length_check", at_most("id", 255)),
        ("admin_credential_public_identity_check", non_empty("public_identity")),
        (
            "admin_credential_public_identity_octet_length_check",
            at_most("public_identity", 2048),
        ),
        (
            "admin_credential_revoked_disabled_check",
            "CHECK (((revoked_at IS NULL) OR (status = 'disabled'::text)))".to_string(),
        ),
        ("admin_credential_status_check", status.clone()),
        ("admin_credential_trust_anchor_ref_check", non_empty("trust_anchor_ref")),
        (
            "admin_credential_trust_anchor_ref_no_space_check",
            no_space("trust_anchor_ref"),
        ),
        (
            "admin_credential_trust_anchor_ref_octet_length_check",
            at_most("trust_anchor_ref", 2048),
        ),
        ("admin_identity_id_check", non_empty("id")),
        ("admin_identity_id_octet_length_check", at_most("id", 255)),
        ("admin_identity_status_check", status.clone()),
        ("admin_role_binding_admin_id_octet_length_check", at_most("admin_id", 255)),
        ("admin_role_binding_id_check", non_empty("id")),
        ("admin_role_binding_id_octet_length_check", at_most("id", 255)),
        ("admin_role_binding_revision_check", revision.clone()),
        (
            "admin_role_binding_role_check",
            "CHECK ((role = ANY (ARRAY['security_admin'::text, 'trust_admin'::text, 'client_admin'::text, 'provider_admin'::text, 'auditor'::text])))".to_string(),
        ),
        (
            "admin_role_binding_scope_check",
            "CHECK (((role = 'auditor'::text) OR ((tenant_id IS NULL) = (role = 'security_admin'::text))))".to_string(),
        ),
        ("admin_role_binding_status_check", status.clone()),
        ("admin_role_binding_tenant_id_octet_length_check", at_most("tenant_id", 255)),
        ("administrative_operation_actor_id_check", non_empty("actor_id")),
        (
            "administrative_operation_actor_id_octet_length_check",
            at_most("actor_id", 255),
        ),
        (
            "administrative_operation_approve_kind_check",
            "CHECK (((kind <> 'approve'::text) OR (approves_operation_id IS NOT NULL)))".to_string(),
        ),
        (
            "administrative_operation_approves_self_check",
            "CHECK ((approves_operation_id <> id))".to_string(),
        ),
        (
            "administrative_operation_approves_id_octet_length_check",
            at_most("approves_operation_id", 255),
        ),
        (
            "administrative_operation_audit_id_octet_length_check",
            at_most("audit_id", 255),
        ),
        (
            "administrative_operation_challenge_expiry_check",
            "CHECK (((challenge_hash IS NULL) OR (expires_at IS NOT NULL)))".to_string(),
        ),
        (
            "administrative_operation_challenge_hash_octet_length_check",
            between("challenge_hash", 32, 64),
        ),
        (
            "administrative_operation_consumed_before_expiry_check",
            "CHECK ((consumed_at < expires_at))".to_string(),
        ),
        (
            "administrative_operation_expected_revision_check",
            "CHECK ((expected_revision >= 0))".to_string(),
        ),
        ("administrative_operation_id_check", non_empty("id")),
        ("administrative_operation_id_octet_length_check", at_most("id", 255)),
        (
            "administrative_operation_immutable_plan_check",
            "CHECK ((jsonb_typeof(immutable_plan) = 'object'::text))".to_string(),
        ),
        ("administrative_operation_kind_check", non_empty("kind")),
        ("administrative_operation_kind_no_space_check", no_space("kind")),
        (
            "administrative_operation_kind_octet_length_check",
            at_most("kind", 2048),
        ),
        ("administrative_operation_outcome_check", non_empty("outcome")),
        (
            "administrative_operation_request_digest_octet_length_check",
            between("request_digest", 32, 64),
        ),
        ("administrative_operation_revision_check", revision.clone()),
        (
            "administrative_operation_revocation_check",
            "CHECK (((revoked_at IS NULL) = (revocation_operation_id IS NULL)))".to_string(),
        ),
        (
            "administrative_operation_revocation_id_octet_length_check",
            at_most("revocation_operation_id", 255),
        ),
        (
            "administrative_operation_revokes_self_check",
            "CHECK ((revocation_operation_id <> id))".to_string(),
        ),
        (
            "administrative_operation_tenant_id_octet_length_check",
            at_most("tenant_id", 255),
        ),
        ("consumed_assertion_digest_key_version_check", non_empty("digest_key_version")),
        (
            "consumed_assertion_digest_key_version_octet_length_check",
            at_most("digest_key_version", 255),
        ),
        (
            "consumed_assertion_replay_key_digest_octet_length_check",
            between("replay_key_digest", 32, 64),
        ),
        (
            "consumed_assertion_retention_check",
            "CHECK ((retain_until > consumed_at))".to_string(),
        ),
        ("consumed_assertion_tenant_id_octet_length_check", at_most("tenant_id", 255)),
        (
            "consumed_assertion_trust_source_id_octet_length_check",
            at_most("trust_source_id", 255),
        ),
        ("recovery_state_instance_id_check", non_empty("instance_id")),
        ("recovery_state_instance_id_octet_length_check", at_most("instance_id", 255)),
        (
            "recovery_state_recovery_key_epoch_check",
            "CHECK ((recovery_key_epoch >= 1))".to_string(),
        ),
        (
            "recovery_state_recovery_public_key_octet_length_check",
            between("recovery_public_key", 1, 8192),
        ),
        ("recovery_state_revision_check", revision.clone()),
    ]
    .into_iter()
    .map(|(name, def)| (name.to_string(), def))
    .collect();
    // The timestamp range checks of 0007 (schema_registry_shape.rs), as
    // pg_get_constraintdef prints them under the TimeZone UTC and DateStyle
    // ISO that sqlx sets for every connection.
    for (table, column) in [
        ("admin_identity", "created_at"),
        ("admin_credential", "revoked_at"),
        ("administrative_operation", "expires_at"),
        ("administrative_operation", "consumed_at"),
        ("administrative_operation", "revoked_at"),
        ("consumed_assertion", "consumed_at"),
        ("consumed_assertion", "retain_until"),
    ] {
        expected.push((
            format!("{table}_{column}_range_check"),
            format!(
                "CHECK ((({column} >= '4714-11-24 00:00:00+00 BC'::timestamp with time zone) \
                 AND ({column} <= '294247-01-10 04:00:54.775806+00'::timestamp with time zone)))"
            ),
        ));
    }
    // The reserved actor IDs of 0009
    // (schema_reserved_ids_and_dormant_grants.rs).
    expected.push((
        "admin_identity_id_not_reserved_check".to_string(),
        "CHECK (((id <> 'deployment_operator'::text) AND \
         (NOT starts_with(id, 'recovery_key:'::text))))"
            .to_string(),
    ));
    expected.sort();
    assert_eq!(checks, expected);
    db.drop([pool]).await;
}

/// Every key column of the whole schema, not only of 0005, is bounded: each
/// text or bytea column of a primary key, unique constraint or unique index,
/// and each column on either side of a foreign key, has a named
/// <table>_<column>_octet_length_check (255 or 2048 bytes, or 32 to 64 bytes
/// for a digest; the name may abbreviate the column), or a value-set or
/// constant check named <table>_<column>_check. The one exception is pinned:
/// the 0002 bound of egress_allowlist_entry.exact_destination keeps
/// its generated name. 0005 adds the bounds of the 0002 key columns that had
/// none.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_key_column_of_the_schema_has_a_named_bound() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    let keys = r"
        SELECT i.indrelid AS rel, k.attnum
        FROM pg_index i JOIN pg_class t ON t.oid = i.indrelid, unnest(i.indkey::int2[]) AS k(attnum)
        WHERE i.indisunique AND t.relnamespace = to_regnamespace(quote_ident(current_schema()))
        UNION
        SELECT c.conrelid, k.attnum FROM pg_constraint c, unnest(c.conkey) AS k(attnum)
        WHERE c.contype = 'f' AND c.connamespace = to_regnamespace(quote_ident(current_schema()))
        UNION
        SELECT c.confrelid, k.attnum FROM pg_constraint c, unnest(c.confkey) AS k(attnum)
        WHERE c.contype = 'f' AND c.connamespace = to_regnamespace(quote_ident(current_schema()))";
    let columns = format!(
        "WITH keys AS ({keys})
         SELECT k.rel, a.attnum, k.rel::regclass::text AS tbl, a.attname::text AS col
         FROM keys k JOIN pg_attribute a ON a.attrelid = k.rel AND a.attnum = k.attnum
         WHERE a.atttypid IN ('text'::regtype, 'bytea'::regtype)"
    );
    // The key columns exist in every slice, so the check below is not
    // vacuous.
    let tables: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT DISTINCT tbl FROM ({columns}) c ORDER BY tbl USING ~<~"
    )))
    .fetch_all(&pool)
    .await
    .unwrap();
    for table in [
        "admin_identity",
        "audit_event",
        "egress_allowlist_entry",
        "instance_security_policy",
        "principal",
        "resource_server",
        "service_grant",
        "tenant",
        "trust_source",
    ] {
        assert!(tables.iter().any(|t| t == table), "{table}: {tables:?}");
    }
    let unbounded: Vec<(String, String)> = sqlx::query_as(AssertSqlSafe(format!(
        r"SELECT tbl, col FROM ({columns}) k
          WHERE NOT EXISTS (
              SELECT FROM pg_constraint c
              WHERE c.conrelid = k.rel AND c.contype = 'c' AND c.conkey = ARRAY[k.attnum]
                AND ((c.conname ~ ('^' || k.tbl || '_[a-z_]+_octet_length_check$')
                      AND (pg_get_constraintdef(c.oid)
                               ~ ('^CHECK \(\(octet_length\(' || k.col || '\) <= (255|2048)\)\)$')
                           OR pg_get_constraintdef(c.oid)
                               ~ ('^CHECK \(\(\(octet_length\(' || k.col || '\) >= 32\) AND \(octet_length\('
                                  || k.col || '\) <= 64\)\)\)$')))
                  OR (c.conname = k.tbl || '_' || k.col || '_check'
                      AND (pg_get_constraintdef(c.oid)
                               ~ ('^CHECK \(\(' || k.col || ' = ANY \(ARRAY\[''[a-z_]+''::text(, ''[a-z_]+''::text)*\]\)\)\)$')
                           OR pg_get_constraintdef(c.oid)
                               ~ ('^CHECK \(\(' || k.col || ' = ''[a-z_]+''::text\)\)$')))
                  OR (k.tbl = 'egress_allowlist_entry' AND k.col = 'exact_destination'
                      AND c.conname = 'egress_allowlist_entry_exact_destination_check2'
                      AND pg_get_constraintdef(c.oid) = 'CHECK ((octet_length(exact_destination) <= 2048))')))
          ORDER BY tbl USING ~<~, col USING ~<~"
    )))
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(unbounded.is_empty(), "{unbounded:?}");
    // The bounds 0005 adds to 0002 tables.
    let added: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT conrelid::regclass::text, conname::text, pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conname = ANY($1)
         ORDER BY conname::text USING ~<~",
    )
    .bind(
        [
            "audit_event_id_octet_length_check",
            "audit_event_tenant_id_octet_length_check",
            "egress_allowlist_entry_id_octet_length_check",
            "instance_security_policy_instance_id_octet_length_check",
        ]
        .map(String::from)
        .to_vec(),
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let bound = |table: &str, name: &str, column: &str| {
        (
            table.to_string(),
            name.to_string(),
            format!("CHECK ((octet_length({column}) <= 255))"),
        )
    };
    assert_eq!(
        added,
        [
            bound("audit_event", "audit_event_id_octet_length_check", "id"),
            bound(
                "audit_event",
                "audit_event_tenant_id_octet_length_check",
                "tenant_id"
            ),
            bound(
                "egress_allowlist_entry",
                "egress_allowlist_entry_id_octet_length_check",
                "id"
            ),
            bound(
                "instance_security_policy",
                "instance_security_policy_instance_id_octet_length_check",
                "instance_id"
            ),
        ]
    );
    db.drop([pool]).await;
}

/// The 0002 key columns that 0005 bounds reject an over-long value, 256 or
/// 3008 incompressible bytes or 256 bytes in 128 characters, with 23514
/// from their named check, never 54000, also where the value names a
/// missing row; 255 bytes fit.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn foundation_key_columns_are_bounded_by_0005() {
    let (db, pool) = seeded().await;
    let event = |id: &str, tenant: &str| {
        format!(
            "INSERT INTO audit_event VALUES ({id}, {tenant}, 4, '\\x03', '2026-11-20Z', 'adm_1',
                 'administrative_operation.create', 'op', NULL, NULL, 'pending')"
        )
    };
    let egress = |id: &str| {
        format!(
            "INSERT INTO egress_allowlist_entry (id, purpose, exact_destination, status)
             VALUES ({id}, 'jwks', 'https://keys.example:443/', 'enabled')"
        )
    };
    let policy =
        |id: &str| format!("INSERT INTO instance_security_policy (instance_id) VALUES ({id})");
    for value in [
        md5_hex(1, 8),
        md5_hex(1, 94),
        "repeat('é', 128)".to_string(),
    ] {
        violates(
            &pool,
            event(&value, "NULL"),
            "audit_event_id_octet_length_check",
        )
        .await;
        violates(
            &pool,
            event("'evt_4'", &value),
            "audit_event_tenant_id_octet_length_check",
        )
        .await;
        violates(
            &pool,
            egress(&value),
            "egress_allowlist_entry_id_octet_length_check",
        )
        .await;
        violates(
            &pool,
            policy(&value),
            "instance_security_policy_instance_id_octet_length_check",
        )
        .await;
    }
    let tenant = md5_id(3);
    accepts(
        &pool,
        &format!(
            "INSERT INTO tenant VALUES ({tenant}, 'big', 'ns_big', 'enabled'); {}",
            event(&md5_id(1), &tenant)
        ),
    )
    .await;
    accepts(&pool, &egress(&md5_id(2))).await;
    // The policy row is single; a 255-byte instance ID fits an empty
    // instance (the_largest_keys_fit_their_indexes).
    db.drop([pool]).await;
}

/// Every column the logical model does not mark optional is NOT NULL, key and
/// reference columns included: a NULL in a reference would make the foreign
/// key skip its check.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn required_columns_reject_null() {
    let (db, pool) = seeded().await;
    let mut cases = Vec::new();
    for column in ["id", "status", "created_at"] {
        cases.push(insert("admin_identity", IDENTITY, &[(column, "NULL")]));
    }
    for column in [
        "id",
        "admin_id",
        "public_identity",
        "trust_anchor_ref",
        "status",
    ] {
        cases.push(insert("admin_credential", CREDENTIAL, &[(column, "NULL")]));
    }
    for column in ["id", "admin_id", "role", "status", "revision"] {
        cases.push(insert("admin_role_binding", BINDING, &[(column, "NULL")]));
    }
    for column in [
        "instance_id",
        "bootstrap_closed",
        "recovery_public_key",
        "recovery_key_epoch",
        "revision",
    ] {
        cases.push(insert("recovery_state", RECOVERY, &[(column, "NULL")]));
    }
    for column in [
        "id",
        "actor_id",
        "kind",
        "request_digest",
        "expected_revision",
        "immutable_plan",
        "revision",
        "outcome",
        "audit_id",
    ] {
        cases.push(insert(
            "administrative_operation",
            OPERATION,
            &[(column, "NULL")],
        ));
    }
    for column in [
        "tenant_id",
        "trust_source_id",
        "replay_key_digest",
        "digest_key_version",
        "consumed_at",
        "retain_until",
    ] {
        cases.push(insert("consumed_assertion", CONSUMED, &[(column, "NULL")]));
    }
    let cases: Vec<(&str, String)> = cases.into_iter().map(|sql| ("23502", sql)).collect();
    rejects_each(&pool, &cases).await;
    db.drop([pool]).await;
}

/// Every ID and reference column is at most 255 bytes: an over-long value,
/// 256 or 3008 incompressible bytes or 256 bytes in 128 characters, fails
/// with 23514 from its named check, also when it names a missing row (a
/// CHECK runs before the row enters any index and before the foreign key
/// check), never with 54000 or 23503.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn ids_and_references_are_bounded() {
    let (db, pool) = seeded().await;
    let cases: Vec<(&str, Row, &str, &str)> = vec![
        ("admin_identity", IDENTITY, "id", "admin_identity_id"),
        ("admin_credential", CREDENTIAL, "id", "admin_credential_id"),
        (
            "admin_credential",
            CREDENTIAL,
            "admin_id",
            "admin_credential_admin_id",
        ),
        ("admin_role_binding", BINDING, "id", "admin_role_binding_id"),
        (
            "admin_role_binding",
            BINDING,
            "admin_id",
            "admin_role_binding_admin_id",
        ),
        (
            "admin_role_binding",
            BINDING,
            "tenant_id",
            "admin_role_binding_tenant_id",
        ),
        (
            "recovery_state",
            RECOVERY,
            "instance_id",
            "recovery_state_instance_id",
        ),
        (
            "administrative_operation",
            OPERATION,
            "id",
            "administrative_operation_id",
        ),
        (
            "administrative_operation",
            OPERATION,
            "tenant_id",
            "administrative_operation_tenant_id",
        ),
        (
            "administrative_operation",
            OPERATION,
            "actor_id",
            "administrative_operation_actor_id",
        ),
        (
            "administrative_operation",
            OPERATION,
            "audit_id",
            "administrative_operation_audit_id",
        ),
        (
            "consumed_assertion",
            CONSUMED,
            "tenant_id",
            "consumed_assertion_tenant_id",
        ),
        (
            "consumed_assertion",
            CONSUMED,
            "trust_source_id",
            "consumed_assertion_trust_source_id",
        ),
        (
            "consumed_assertion",
            CONSUMED,
            "digest_key_version",
            "consumed_assertion_digest_key_version",
        ),
    ];
    let revocation = [("revoked_at", "'2026-11-20Z'")];
    let approve = [("kind", "'approve'")];
    for value in [
        md5_hex(1, 8),
        md5_hex(1, 94),
        "repeat('é', 128)".to_string(),
    ] {
        for (table, defaults, column, prefix) in &cases {
            violates(
                &pool,
                insert(table, defaults, &[(column, value.as_str())]),
                &format!("{prefix}_octet_length_check"),
            )
            .await;
        }
        // The operation references named in the table's own columns; the
        // check names abbreviate them.
        let mut set = revocation.to_vec();
        set.push(("revocation_operation_id", value.as_str()));
        violates(
            &pool,
            insert("administrative_operation", OPERATION, &set),
            "administrative_operation_revocation_id_octet_length_check",
        )
        .await;
        let mut set = approve.to_vec();
        set.push(("approves_operation_id", value.as_str()));
        violates(
            &pool,
            insert("administrative_operation", OPERATION, &set),
            "administrative_operation_approves_id_octet_length_check",
        )
        .await;
    }
    db.drop([pool]).await;
}

/// Digests are 32 to 64 bytes and the recovery key 1 to 8192 bytes; each
/// bound is a named check, so an over-long digest in the consumed-proof key
/// fails with 23514, not 54000.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn digests_and_keys_are_bounded() {
    let (db, pool) = seeded().await;
    let bytes = |text: String| format!("convert_to({text}, 'UTF8')");
    let short = [
        r"'\x'::bytea".to_string(),
        "substring(sha256('x') from 1 for 31)".to_string(),
    ];
    let long = [
        r"sha512('x') || '\x00'::bytea".to_string(),
        bytes(md5_hex(1, 94)),
    ];
    let challenge = [("expires_at", "'2026-11-20 00:05Z'")];
    for value in short.iter().chain(&long) {
        violates(
            &pool,
            insert(
                "administrative_operation",
                OPERATION,
                &[("request_digest", value)],
            ),
            "administrative_operation_request_digest_octet_length_check",
        )
        .await;
        let mut set = challenge.to_vec();
        set.push(("challenge_hash", value));
        violates(
            &pool,
            insert("administrative_operation", OPERATION, &set),
            "administrative_operation_challenge_hash_octet_length_check",
        )
        .await;
        violates(
            &pool,
            insert(
                "consumed_assertion",
                CONSUMED,
                &[("replay_key_digest", value)],
            ),
            "consumed_assertion_replay_key_digest_octet_length_check",
        )
        .await;
    }
    for value in [
        r"'\x'::bytea".to_string(),
        bytes(format!("left({}, 8193)", md5_hex(1, 257))),
        bytes(md5_hex(1, 257)),
    ] {
        violates(
            &pool,
            insert(
                "recovery_state",
                RECOVERY,
                &[("instance_id", "'inst_2'"), ("recovery_public_key", &value)],
            ),
            "recovery_state_recovery_public_key_octet_length_check",
        )
        .await;
    }
    // The limits themselves are accepted.
    for digest in ["substring(sha512('x') from 1 for 32)", "sha512('x')"] {
        accepts(
            &pool,
            &insert(
                "administrative_operation",
                OPERATION,
                &[("request_digest", digest)],
            ),
        )
        .await;
        accepts(
            &pool,
            &insert(
                "administrative_operation",
                OPERATION,
                &[
                    ("challenge_hash", digest),
                    ("expires_at", "'2026-11-20 00:05Z'"),
                ],
            ),
        )
        .await;
        accepts(
            &pool,
            &insert(
                "consumed_assertion",
                CONSUMED,
                &[("replay_key_digest", digest)],
            ),
        )
        .await;
    }
    for key in [
        r"'\x01'".to_string(),
        bytes(format!("left({}, 8192)", md5_hex(1, 256))),
    ] {
        accepts(
            &pool,
            &format!(
                "UPDATE recovery_state SET recovery_public_key = {key}, recovery_key_epoch = 2,
                     revision = 2"
            ),
        )
        .await;
    }
    db.drop([pool]).await;
}

/// The exact strings are at most 2048 bytes; `kind` and `trust_anchor_ref`
/// also hold no ASCII whitespace or control character (U+0085 included),
/// while other Unicode spaces pass. `public_identity` is not checked for
/// them: it is a canonical public-key identity whose encoding the service
/// fixes.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn exact_strings_are_bounded_and_names_have_no_whitespace() {
    let (db, pool) = seeded().await;
    let cases: Vec<(&str, Row, &str, &str, bool)> = vec![
        (
            "admin_credential",
            CREDENTIAL,
            "public_identity",
            "admin_credential_public_identity",
            false,
        ),
        (
            "admin_credential",
            CREDENTIAL,
            "trust_anchor_ref",
            "admin_credential_trust_anchor_ref",
            true,
        ),
        (
            "administrative_operation",
            OPERATION,
            "kind",
            "administrative_operation_kind",
            true,
        ),
    ];
    for (table, defaults, column, prefix, cleaned) in &cases {
        for value in [
            "repeat('a', 2049)".to_string(),
            "repeat('é', 1025)".to_string(),
            md5_hex(1, 94),
        ] {
            violates(
                &pool,
                insert(table, defaults, &[(column, &value)]),
                &format!("{prefix}_octet_length_check"),
            )
            .await;
        }
        accepts(
            &pool,
            &insert(table, defaults, &[(column, &md5_hex(1, 64))]),
        )
        .await;
        let spaced = [
            "'a b'",
            "' a'",
            r"E'a\t'",
            r"E'a\n'",
            "'a' || chr(1)",
            "'a' || chr(127)",
            "'a' || chr(133)",
        ];
        for value in spaced {
            let sql = insert(table, defaults, &[(column, value)]);
            if *cleaned {
                violates(&pool, sql, &format!("{prefix}_no_space_check")).await;
            } else {
                accepts(&pool, &sql).await;
            }
        }
        for code in [12288, 5760, 8192, 8232, 8233] {
            let value = format!("'a' || chr({code}) || 'b'");
            accepts(&pool, &insert(table, defaults, &[(column, &value)])).await;
        }
    }
    db.drop([pool]).await;
}

/// The largest values fit every key, even when they do not compress: 255-byte
/// IDs in every key, a 2048-byte public identity and a 64-byte digest next to
/// two 255-byte IDs in the consumed-proof key.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_largest_keys_fit_their_indexes() {
    let (db, pool) = seeded().await;
    let (t, s, a, c, r, o, p) = (
        md5_id(1000),
        md5_id(2000),
        md5_id(3000),
        md5_id(4000),
        md5_id(5000),
        md5_id(6000),
        md5_id(7000),
    );
    let e = md5_id(9000);
    let sql = format!(
        r#"INSERT INTO audit_event VALUES ({e}, NULL, 4, '\x03', '2026-11-20Z', 'adm_1', 'administrative_operation.create', 'op', NULL, NULL, 'pending');
           UPDATE audit_chain_head SET sequence = 4, head_hash = '\x04';
           INSERT INTO tenant VALUES ({t}, 'big', 'ns_big', 'enabled');
           INSERT INTO trust_source VALUES ({s}, {t}, 'big', 'oidc_discovery', 'https://x', 'https://x/d',
               NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{{}}', 'on_demand_jwt', NULL,
               'single_use', 'enabled');
           INSERT INTO admin_identity VALUES ({a}, 'enabled');
           INSERT INTO admin_credential VALUES ({c}, {a}, {}, 'ops-ca', 'enabled', NULL);
           INSERT INTO admin_role_binding VALUES ({r}, {a}, 'auditor', {t}, 'enabled');
           INSERT INTO administrative_operation VALUES
               ({o}, {t}, {a}, 'tenant.update', sha512('o'), 1, '{{}}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'pending', {e});
           INSERT INTO administrative_operation VALUES
               ({p}, {t}, 'adm_2', 'approve', sha512('p'), 1, '{{}}', NULL, NULL, NULL, NULL, NULL, {o}, 1, 'applied', 'evt_1');
           UPDATE administrative_operation SET revoked_at = '2026-11-20Z', revocation_operation_id = {p},
               revision = 2 WHERE id = {o};
           INSERT INTO consumed_assertion VALUES ({t}, {s}, sha512('jti'), {}, '2026-11-20Z', '2026-11-21Z')"#,
        md5_hex(10001, 64),
        md5_id(20001),
    );
    run_owned(&pool, sql).await;
    let lengths: Vec<(i32, i32, i32)> = sqlx::query_as(
        "SELECT octet_length(admin_id), octet_length(id), octet_length(public_identity) FROM admin_credential
             WHERE id NOT IN ('crd_1', 'crd_2')
         UNION ALL SELECT octet_length(admin_id), octet_length(id), octet_length(tenant_id) FROM admin_role_binding
             WHERE tenant_id IS NOT NULL
         UNION ALL SELECT octet_length(id), octet_length(tenant_id), octet_length(revocation_operation_id)
             FROM administrative_operation WHERE revocation_operation_id IS NOT NULL
         UNION ALL SELECT octet_length(tenant_id), octet_length(trust_source_id), octet_length(replay_key_digest)
             FROM consumed_assertion
         UNION ALL SELECT octet_length(audit_id), octet_length(id), octet_length(actor_id)
             FROM administrative_operation WHERE kind = 'tenant.update'
         ORDER BY 3 DESC, 1 DESC LIMIT 5",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        lengths,
        [
            (255, 255, 2048),
            (255, 255, 255),
            (255, 255, 255),
            (255, 255, 255),
            (255, 255, 64)
        ]
    );
    // The policy row is append-only, so the 255-byte instance ID goes into an
    // empty instance.
    let fresh = TestDb::create().await;
    let empty = fresh.pool().await;
    persistence::migrate(&empty).await.unwrap();
    let i = md5_id(8000);
    run_owned(
        &empty,
        format!(
            r"INSERT INTO instance_security_policy (instance_id) VALUES ({i});
              INSERT INTO recovery_state VALUES ({i}, true, '\x01', 1)"
        ),
    )
    .await;
    let length: i32 = sqlx::query_scalar("SELECT octet_length(instance_id) FROM recovery_state")
        .fetch_one(&empty)
        .await
        .unwrap();
    assert_eq!(length, 255);
    fresh.drop([empty]).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn operator_credentials_are_registered_once_and_revoked_for_good() {
    let (db, pool) = seeded().await;
    rejects(&pool, r"
        23505 INSERT INTO admin_identity VALUES ('adm_1', 'enabled')
        23514 INSERT INTO admin_identity VALUES ('', 'enabled')
        23514 INSERT INTO admin_identity VALUES ('adm_3', 'active')
        SK001 UPDATE admin_identity SET id = 'adm_9' WHERE id = 'adm_1'
        SK001 UPDATE admin_identity SET created_at = '2020-01-01Z' WHERE id = 'adm_1'
        23503 ALTER TABLE admin_identity DISABLE TRIGGER USER; DELETE FROM admin_identity WHERE id = 'adm_1'
        23503 INSERT INTO admin_credential VALUES ('crd_3', 'adm_9', 'sha256:cc', 'ops-ca', 'enabled', NULL)
        23505 INSERT INTO admin_credential VALUES ('crd_1', 'adm_1', 'sha256:cc', 'ops-ca', 'enabled', NULL)
        23505 INSERT INTO admin_credential VALUES ('crd_3', 'adm_2', 'sha256:aa', 'ops-ca', 'enabled', NULL)
        23514 INSERT INTO admin_credential VALUES ('', 'adm_1', 'sha256:cc', 'ops-ca', 'enabled', NULL)
        23514 INSERT INTO admin_credential VALUES ('crd_3', 'adm_1', '', 'ops-ca', 'enabled', NULL)
        23514 INSERT INTO admin_credential VALUES ('crd_3', 'adm_1', 'sha256:cc', '', 'enabled', NULL)
        23514 INSERT INTO admin_credential VALUES ('crd_3', 'adm_1', 'sha256:cc', 'ops-ca', 'revoked', NULL)
        23514 INSERT INTO admin_credential VALUES ('crd_3', 'adm_1', 'sha256:cc', 'ops-ca', 'active', NULL)
        23514 INSERT INTO admin_credential VALUES ('crd_3', 'adm_1', 'sha256:cc', 'ops-ca', 'enabled', '2026-11-20Z')
        SK001 UPDATE admin_credential SET id = 'crd_9' WHERE id = 'crd_1'
        SK001 UPDATE admin_credential SET admin_id = 'adm_2' WHERE id = 'crd_1'
        SK001 UPDATE admin_credential SET public_identity = 'sha256:cc' WHERE id = 'crd_1'
        SK001 UPDATE admin_credential SET trust_anchor_ref = 'other-ca' WHERE id = 'crd_1'
        23514 UPDATE admin_credential SET revoked_at = '2026-11-20Z' WHERE id = 'crd_1'
    ").await;
    // Disable and re-enable, then revoke: revocation disables for good.
    run(
        &pool,
        "UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_1';
         UPDATE admin_credential SET status = 'enabled' WHERE id = 'crd_1';
         UPDATE admin_credential SET status = 'disabled', revoked_at = '2026-11-20Z' WHERE id = 'crd_1';
         UPDATE admin_credential SET revoked_at = '2026-11-20Z' WHERE id = 'crd_1';
         UPDATE admin_identity SET status = 'disabled' WHERE id = 'adm_1'",
    )
    .await;
    rejects(&pool, r"
        SK001 UPDATE admin_credential SET revoked_at = NULL WHERE id = 'crd_1'
        SK001 UPDATE admin_credential SET revoked_at = NULL, status = 'enabled' WHERE id = 'crd_1'
        SK001 UPDATE admin_credential SET revoked_at = '2026-11-21Z' WHERE id = 'crd_1'
        23514 UPDATE admin_credential SET status = 'enabled' WHERE id = 'crd_1'
        23505 INSERT INTO admin_credential VALUES ('crd_3', 'adm_2', 'sha256:aa', 'ops-ca', 'enabled', NULL)
    ").await;
    let row: (String, bool) = sqlx::query_as(
        "SELECT status, revoked_at = '2026-11-20Z' FROM admin_credential WHERE id = 'crd_1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("disabled".to_string(), true));
    db.drop([pool]).await;
}

/// security_admin is an instance role and trust_admin, client_admin and
/// provider_admin are tenant roles; auditor is either (ADR-013 OQ-ADR013-3).
/// No role implies another, and an operator holds each role in each scope
/// once.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn role_bindings_scope_each_role_explicitly() {
    let (db, pool) = seeded().await;
    // An instance auditor (instance audit reads) next to a tenant auditor of
    // the same operator: two separate assignments.
    run(
        &pool,
        "INSERT INTO admin_role_binding VALUES
             ('rb_i', 'adm_2', 'auditor', NULL, 'enabled'),
             ('rb_a', 'adm_2', 'auditor', 'ten_a', 'enabled')",
    )
    .await;
    rejects(&pool, r"
        23514 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'security_admin', 'ten_a', 'enabled')
        23514 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'trust_admin', NULL, 'enabled')
        23514 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'client_admin', NULL, 'enabled')
        23514 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'provider_admin', NULL, 'enabled')
        23514 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'tenant_admin', 'ten_a', 'enabled')
        23514 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'Trust_admin', 'ten_a', 'enabled')
        23514 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'trust_admin', 'ten_a', 'active')
        23514 INSERT INTO admin_role_binding VALUES ('', 'adm_1', 'trust_admin', 'ten_a', 'enabled')
        23503 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_9', 'trust_admin', 'ten_a', 'enabled')
        23503 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'trust_admin', 'ten_x', 'enabled')
        23505 INSERT INTO admin_role_binding VALUES ('rb_1', 'adm_1', 'auditor', 'ten_a', 'enabled')
        23505 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'security_admin', NULL, 'disabled')
        23505 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_2', 'trust_admin', 'ten_a', 'disabled')
        23505 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_2', 'auditor', NULL, 'disabled')
        SK001 UPDATE admin_role_binding SET tenant_id = NULL, revision = revision + 1 WHERE id = 'rb_a'
        SK001 INSERT INTO admin_role_binding VALUES ('rb_x', 'adm_1', 'trust_admin', 'ten_a', 'enabled', 2)
        SK001 UPDATE admin_role_binding SET id = 'rb_9', revision = revision + 1 WHERE id = 'rb_3'
        SK001 UPDATE admin_role_binding SET admin_id = 'adm_1', revision = revision + 1 WHERE id = 'rb_3'
        SK001 UPDATE admin_role_binding SET role = 'client_admin', revision = revision + 1 WHERE id = 'rb_3'
        SK001 UPDATE admin_role_binding SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'rb_3'
        SK001 UPDATE admin_role_binding SET status = 'disabled' WHERE id = 'rb_3'
        SK001 UPDATE admin_role_binding SET status = 'disabled', revision = revision + 2 WHERE id = 'rb_3'
        23503 ALTER TABLE tenant DISABLE TRIGGER USER; DELETE FROM tenant WHERE id = 'ten_a'
    ").await;
    // One operator holds several roles only by explicit assignment, each
    // tenant role per tenant.
    run(
        &pool,
        "INSERT INTO admin_role_binding VALUES
             ('rb_4', 'adm_2', 'trust_admin', 'ten_b', 'enabled'),
             ('rb_5', 'adm_2', 'client_admin', 'ten_a', 'enabled'),
             ('rb_6', 'adm_2', 'provider_admin', 'ten_a', 'enabled'),
             ('rb_7', 'adm_2', 'auditor', 'ten_b', 'enabled'),
             ('rb_8', 'adm_1', 'trust_admin', 'ten_a', 'enabled');
         UPDATE admin_role_binding SET status = 'disabled', revision = revision + 1 WHERE id = 'rb_3'",
    )
    .await;
    assert_eq!(
        revisions(&pool, "admin_role_binding", "id").await,
        [1, 1, 2, 1, 1, 1, 1, 1, 1, 1]
    );
    let instance_auditors: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM admin_role_binding WHERE role = 'auditor' AND tenant_id IS NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(instance_auditors, ["rb_i"]);
    db.drop([pool]).await;
}

/// One recovery row per instance; bootstrap never reopens, and the recovery
/// key changes only with a higher epoch.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn recovery_state_never_reopens_bootstrap_and_rotates_forward() {
    let (db, pool) = seeded().await;
    rejects(
        &pool,
        r"
        23505 INSERT INTO recovery_state VALUES ('inst_1', true, '\x01', 1)
        23505 INSERT INTO recovery_state VALUES ('inst_2', true, '\x01', 1)
        23514 INSERT INTO recovery_state VALUES ('', true, '\x01', 1)
        23514 INSERT INTO recovery_state VALUES ('inst_2', true, '\x01', 0)
        SK001 UPDATE recovery_state SET instance_id = 'inst_2', revision = revision + 1
        SK001 UPDATE recovery_state SET bootstrap_closed = false, revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_public_key = '\x0c', revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_key_epoch = 2, revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_public_key = '\x0c', recovery_key_epoch = 2
        SK001 UPDATE recovery_state SET recovery_key_epoch = 0, revision = revision + 1
        SK001 UPDATE recovery_state SET revision = revision + 2
        SK001 INSERT INTO recovery_state VALUES ('inst_2', true, '\x01', 1, 2)
    ",
    )
    .await;
    // An empty instance: the row may start open and is then closed; the key
    // rotates forward, by any step.
    let fresh = TestDb::create().await;
    let empty = fresh.pool().await;
    persistence::migrate(&empty).await.unwrap();
    rejects(
        &empty,
        r"23503 INSERT INTO recovery_state VALUES ('inst_1', false, '\x01', 1)",
    )
    .await;
    run(
        &empty,
        r"INSERT INTO instance_security_policy (instance_id) VALUES ('inst_1');
          INSERT INTO recovery_state VALUES ('inst_1', false, '\x01', 1);
          UPDATE recovery_state SET bootstrap_closed = false, revision = revision + 1;
          UPDATE recovery_state SET bootstrap_closed = true, revision = revision + 1;
          UPDATE recovery_state SET bootstrap_closed = true, revision = revision + 1;
          UPDATE recovery_state SET recovery_public_key = '\x02', recovery_key_epoch = 2, revision = revision + 1;
          UPDATE recovery_state SET recovery_public_key = '\x03', recovery_key_epoch = 5, revision = revision + 1",
    )
    .await;
    rejects(&empty, r"
        SK001 UPDATE recovery_state SET bootstrap_closed = false, revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_public_key = '\x04', recovery_key_epoch = 4, revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_public_key = '\x02', recovery_key_epoch = 5, revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_key_epoch = 4, revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_key_epoch = 6, revision = revision + 1
    ").await;
    let row: (bool, Vec<u8>, i64, i64) = sqlx::query_as(
        "SELECT bootstrap_closed, recovery_public_key, recovery_key_epoch, revision FROM recovery_state",
    )
    .fetch_one(&empty)
    .await
    .unwrap();
    assert_eq!(row, (true, vec![3], 5, 6));
    fresh.drop([empty]).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn administrative_operation_keeps_its_plan_and_references() {
    let (db, pool) = seeded().await;
    let op = |set: &[(&str, &str)]| insert("administrative_operation", OPERATION, set);
    rejects_each(
        &pool,
        &[
            ("23505", op(&[("id", "'op_1'")])),
            ("23514", op(&[("id", "''")])),
            ("23514", op(&[("actor_id", "''")])),
            ("23514", op(&[("kind", "''")])),
            ("23514", op(&[("outcome", "''")])),
            ("23514", op(&[("expected_revision", "-1")])),
            ("23514", op(&[("immutable_plan", "'[]'")])),
            ("23514", op(&[("immutable_plan", "'\"plan\"'")])),
            ("23514", op(&[("immutable_plan", "'null'")])),
            ("23503", op(&[("tenant_id", "'ten_x'")])),
            ("23503", op(&[("audit_id", "'evt_x'")])),
            (
                "23503",
                op(&[("kind", "'approve'"), ("approves_operation_id", "'op_x9'")]),
            ),
            (
                "23503",
                op(&[
                    ("revoked_at", "'2026-11-20Z'"),
                    ("revocation_operation_id", "'op_x9'"),
                ]),
            ),
            // Every approval names the operation it approves (IR-054), and
            // no operation approves or revokes itself.
            ("23514", op(&[("kind", "'approve'")])),
            (
                "23514",
                op(&[("kind", "'approve'"), ("approves_operation_id", "'op_x'")]),
            ),
            (
                "23514",
                op(&[
                    ("revoked_at", "'2026-11-20Z'"),
                    ("revocation_operation_id", "'op_x'"),
                ]),
            ),
            // Revocation records both the time and the revoking operation.
            ("23514", op(&[("revoked_at", "'2026-11-20Z'")])),
            ("23514", op(&[("revocation_operation_id", "'op_2'")])),
            // A recovery challenge expires.
            ("23514", op(&[("challenge_hash", "sha256('c')")])),
            // A consumed operation was not expired.
            (
                "23514",
                op(&[
                    ("expires_at", "'2026-11-20 01:00Z'"),
                    ("consumed_at", "'2026-11-20 01:00Z'"),
                ]),
            ),
            ("SK001", op(&[("revision", "2")])),
        ],
    )
    .await;
    rejects(&pool, r#"
        SK001 UPDATE administrative_operation SET id = 'op_9', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET tenant_id = NULL, revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET actor_id = 'adm_1', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET kind = 'service_grant.create', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET request_digest = sha256('other'), revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET expected_revision = 5, revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET immutable_plan = '{"status": "disabled"}', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET challenge_hash = sha256('other'), revision = revision + 1 WHERE id = 'op_4'
        SK001 UPDATE administrative_operation SET challenge_hash = NULL, revision = revision + 1 WHERE id = 'op_4'
        SK001 UPDATE administrative_operation SET expires_at = '2026-11-20 02:00Z', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET expires_at = NULL, revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET approves_operation_id = 'op_3', revision = revision + 1 WHERE id = 'op_2'
        SK001 UPDATE administrative_operation SET audit_id = 'evt_2', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET outcome = 'applied' WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET outcome = 'applied', revision = revision + 2 WHERE id = 'op_3'
        23503 ALTER TABLE administrative_operation DISABLE TRIGGER USER; DELETE FROM administrative_operation WHERE id = 'op_1'
        SK001 DELETE FROM audit_event WHERE id = 'evt_1'
        23514 UPDATE administrative_operation SET revoked_at = '2026-11-20Z', revocation_operation_id = 'op_3', revision = revision + 1 WHERE id = 'op_3'
    "#).await;
    // Kinds other than approve may name what they approve: a route bundle
    // approval names its preparation. A consumed operation may also be
    // revoked; see the next test.
    accepts(
        &pool,
        &op(&[
            ("kind", "'route_bundle_approval'"),
            ("approves_operation_id", "'op_3'"),
        ]),
    )
    .await;
    accepts(
        &pool,
        &op(&[
            ("consumed_at", "'2026-11-20Z'"),
            ("revoked_at", "'2026-11-20Z'"),
            ("revocation_operation_id", "'op_2'"),
        ]),
    )
    .await;
    // Operations name tenant and instance scopes alike; outcome and revision
    // change.
    run(
        &pool,
        "UPDATE administrative_operation SET outcome = 'applied', revision = revision + 1 WHERE id = 'op_3'",
    )
    .await;
    assert_eq!(
        revisions(&pool, "administrative_operation", "id").await,
        [1, 1, 2, 1]
    );
    db.drop([pool]).await;
}

/// An operation is consumed once and revoked once, and neither is ever
/// undone.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn administrative_operation_consumption_and_revocation_are_one_way() {
    let (db, pool) = seeded().await;
    // `op_3` is revoked by an operation of its own tenant, `op_5`: since the
    // `0005` revocation guard, one of another tenant is refused
    // (schema_operation_approval_guard.rs).
    run(
        &pool,
        "UPDATE administrative_operation SET consumed_at = '2026-11-20 00:30Z', outcome = 'applied',
             revision = revision + 1 WHERE id = 'op_1';
         UPDATE administrative_operation SET consumed_at = '2026-11-20 00:01Z',
             revision = revision + 1 WHERE id = 'op_4';
         INSERT INTO administrative_operation VALUES ('op_5', 'ten_a', 'adm_2', 'cancel', sha256('op_5'), 4,
             '{}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'success', 'evt_3');
         UPDATE administrative_operation SET revoked_at = '2026-11-20 00:30Z', revocation_operation_id = 'op_5',
             revision = revision + 1 WHERE id = 'op_3'",
    )
    .await;
    rejects(&pool, r"
        SK001 UPDATE administrative_operation SET consumed_at = NULL, revision = revision + 1 WHERE id = 'op_1'
        SK001 UPDATE administrative_operation SET consumed_at = '2026-11-20 00:40Z', revision = revision + 1 WHERE id = 'op_1'
        SK001 UPDATE administrative_operation SET consumed_at = '2026-11-20 00:02Z', revision = revision + 1 WHERE id = 'op_4'
        SK001 UPDATE administrative_operation SET revoked_at = NULL, revocation_operation_id = NULL, revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET revoked_at = '2026-11-20 00:40Z', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET revocation_operation_id = 'op_1', revision = revision + 1 WHERE id = 'op_3'
        23514 UPDATE administrative_operation SET revoked_at = '2026-11-20 00:40Z', revision = revision + 1 WHERE id = 'op_2'
        23503 UPDATE administrative_operation SET revoked_at = '2026-11-20 00:40Z', revocation_operation_id = 'op_x', revision = revision + 1 WHERE id = 'op_2'
    ").await;
    // An operation with no expiry is consumed at any time; the guard lets a
    // write leave a set value as it is.
    run(
        &pool,
        "UPDATE administrative_operation SET consumed_at = '2030-01-01Z', revision = revision + 1 WHERE id = 'op_2';
         UPDATE administrative_operation SET consumed_at = '2030-01-01Z', outcome = 'done',
             revision = revision + 1 WHERE id = 'op_2'",
    )
    .await;
    // A revoked operation is not consumed afterwards, also past its expiry:
    // the guard trigger fires before the expiry check.
    rejects(&pool, r"
        SK001 UPDATE administrative_operation SET consumed_at = '2026-11-20 00:40Z', revision = revision + 1 WHERE id = 'op_3'
        SK001 UPDATE administrative_operation SET consumed_at = '2026-11-20 01:00Z', revision = revision + 1 WHERE id = 'op_3'
    ").await;
    let rows: Vec<(String, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, (consumed_at AT TIME ZONE 'UTC')::text, revocation_operation_id, revision
         FROM administrative_operation ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let consumed = |at: &str| Some(at.to_string());
    assert_eq!(
        rows,
        [
            ("op_1".into(), consumed("2026-11-20 00:30:00"), None, 2),
            ("op_2".into(), consumed("2030-01-01 00:00:00"), None, 3),
            ("op_3".into(), None, Some("op_5".into()), 2),
            ("op_4".into(), consumed("2026-11-20 00:01:00"), None, 2),
            ("op_5".into(), None, None, 1),
        ]
    );
    db.drop([pool]).await;
}

/// A consumed proof is recorded once per tenant, source and digest; the row
/// never changes, and it stays on a source of its own tenant.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn consumed_assertions_are_insert_only_and_scoped_to_their_source() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        "INSERT INTO trust_source SELECT 'src_a2', tenant_id, 'github2', kind, exact_issuer, discovery_url,
             jwks_keyset_id, cluster_id, token_review_endpoint, ca_bundle_ref, ca_fingerprint,
             reviewer_credential_ref, review_timeout_ms, audiences, algorithms, proof_bounds,
             assertion_profile, stale_revocation_acknowledged, replay_mode, status
         FROM trust_source WHERE id = 'src_a'",
    )
    .await;
    rejects(&pool, r"
        23505 INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_1'), 'dk_2', '2026-11-20 00:01Z', '2026-11-20 00:11Z')
        23503 INSERT INTO consumed_assertion VALUES ('ten_a', 'src_b', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
        23503 INSERT INTO consumed_assertion VALUES ('ten_b', 'src_a', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
        23503 INSERT INTO consumed_assertion VALUES ('ten_x', 'src_a', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
        23503 INSERT INTO consumed_assertion VALUES ('ten_a', 'src_x', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
        23514 INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_2'), '', '2026-11-20Z', '2026-11-20 00:10Z')
        23514 INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_2'), 'dk_1', '2026-11-20Z', '2026-11-20Z')
        23514 INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_2'), 'dk_1', '2026-11-20Z', '2026-11-19Z')
        SK001 UPDATE consumed_assertion SET retain_until = '2027-01-01Z'
        SK001 UPDATE consumed_assertion SET retain_until = retain_until
        SK001 UPDATE consumed_assertion SET digest_key_version = 'dk_2'
        SK001 UPDATE consumed_assertion SET replay_key_digest = sha256('jti_2')
        SK001 INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z') ON CONFLICT (tenant_id, trust_source_id, replay_key_digest) DO UPDATE SET retain_until = excluded.retain_until
        23503 ALTER TABLE trust_source DISABLE TRIGGER USER; DELETE FROM trust_source WHERE id = 'src_a'
    ").await;
    // A replay under ON CONFLICT DO NOTHING inserts nothing; the same digest
    // under another source, or another digest, is a separate proof.
    let inserted = sqlx::raw_sql(
        "INSERT INTO consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
         ON CONFLICT DO NOTHING",
    )
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(inserted, 0);
    run(
        &pool,
        "INSERT INTO consumed_assertion VALUES
             ('ten_b', 'src_b', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z'),
             ('ten_a', 'src_a2', sha256('jti_1'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z'),
             ('ten_a', 'src_a', sha256('jti_2'), 'dk_2', '2026-11-20Z', '2026-11-20 00:10Z')",
    )
    .await;
    // Pruning after retain_until is a DELETE; 0006 lets it through only for
    // rows whose retain_until has passed (schema_registry_guards.rs).
    run(
        &pool,
        "DELETE FROM consumed_assertion WHERE retain_until < '2026-11-20 00:20Z' AND tenant_id = 'ten_b'",
    )
    .await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM consumed_assertion")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 3);
    db.drop([pool]).await;
}

/// security_admin may revoke a route bundle approval after begin has
/// consumed it (tasks section 3 "Route preparation, approval and recovery"):
/// both stay recorded, and neither can be undone or changed afterwards.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn consumed_route_bundle_approval_can_still_be_revoked() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        "INSERT INTO administrative_operation VALUES
             ('op_rb', 'ten_a', 'adm_1', 'route_bundle_approval', sha256('op_rb'), 1,
              '{\"abort_until\": \"2026-11-20T02:00:00Z\"}', NULL, '2026-11-20 01:00Z', NULL, NULL, NULL,
              'op_3', 1, 'pending', 'evt_3'),
             ('op_rv', 'ten_a', 'adm_1', 'route_bundle_approval_revoke', sha256('op_rv'), 1, '{}',
              NULL, NULL, NULL, NULL, NULL, NULL, 1, 'applied', 'evt_3');
         UPDATE administrative_operation SET consumed_at = '2026-11-20 00:10Z', outcome = 'begun',
             revision = revision + 1 WHERE id = 'op_rb';
         UPDATE administrative_operation SET revoked_at = '2026-11-20 00:20Z', revocation_operation_id = 'op_rv',
             outcome = 'revoked', revision = revision + 1 WHERE id = 'op_rb'",
    )
    .await;
    rejects(&pool, r#"
        SK001 UPDATE administrative_operation SET consumed_at = NULL, revision = revision + 1 WHERE id = 'op_rb'
        SK001 UPDATE administrative_operation SET revoked_at = NULL, revocation_operation_id = NULL, revision = revision + 1 WHERE id = 'op_rb'
        SK001 UPDATE administrative_operation SET revocation_operation_id = 'op_2', revision = revision + 1 WHERE id = 'op_rb'
        SK001 UPDATE administrative_operation SET immutable_plan = '{}', revision = revision + 1 WHERE id = 'op_rb'
    "#)
    .await;
    let row: (bool, bool, String, String, i64) = sqlx::query_as(
        "SELECT consumed_at = '2026-11-20 00:10Z', revoked_at = '2026-11-20 00:20Z',
                revocation_operation_id, immutable_plan->>'abort_until', revision
         FROM administrative_operation WHERE id = 'op_rb'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            true,
            true,
            "op_rv".to_string(),
            "2026-11-20T02:00:00Z".to_string(),
            3
        )
    );
    db.drop([pool]).await;
}

/// Checks that `sql` fails with `code` and exactly `message`.
async fn assert_rejected_with_message(
    conn: &mut PgConnection,
    code: &str,
    sql: &str,
    message: &str,
) {
    let err = sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(&mut *conn)
        .await
        .expect_err(sql);
    assert_eq!(sqlstate(&err), code, "{sql}: {err}");
    let text = err.as_database_error().unwrap().message().to_string();
    assert_eq!(text, message, "{sql}");
}

/// An operation revoked before it was consumed is never consumed by an
/// UPDATE, an `ON CONFLICT … DO UPDATE` included (lead decision,
/// 2026-11-21). A consumed operation may still be revoked, also through
/// `ON CONFLICT … DO UPDATE`, and an UPDATE that leaves `consumed_at` unset
/// still works on a revoked row. An INSERT, and an UPDATE that sets both
/// columns of a row that has neither, are left to the service: the database
/// does not compare the two timestamps (README.md).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn revoked_operation_is_not_consumed_afterwards() {
    let (db, pool) = seeded().await;
    // `op_3` is revoked by an operation of its own tenant (the `0005`
    // revocation guard).
    run(
        &pool,
        "INSERT INTO administrative_operation VALUES ('op_5', 'ten_a', 'adm_2', 'cancel', sha256('op_5'), 4,
             '{}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'success', 'evt_3');
         UPDATE administrative_operation SET revoked_at = '2026-11-20 00:20Z', revocation_operation_id = 'op_5',
             revision = revision + 1 WHERE id = 'op_3';
         UPDATE administrative_operation SET consumed_at = '2026-11-20 00:10Z', outcome = 'applied',
             revision = revision + 1 WHERE id = 'op_1'",
    )
    .await;
    let upsert = |id: &str, set: &str| {
        format!(
            "{} ON CONFLICT (id) DO UPDATE SET {set}, revision = administrative_operation.revision + 1",
            insert(
                "administrative_operation",
                OPERATION,
                &[("id", &format!("'{id}'"))]
            )
        )
    };
    let mut conn = pool.acquire().await.unwrap();
    for sql in [
        "UPDATE administrative_operation SET consumed_at = '2026-11-20 00:30Z', revision = revision + 1 WHERE id = 'op_3'".to_string(),
        "UPDATE administrative_operation SET consumed_at = '2026-11-20 00:10Z', outcome = 'applied', revision = revision + 1 WHERE id = 'op_3'".to_string(),
        upsert("op_3", "consumed_at = '2026-11-20 00:30Z'"),
    ] {
        assert_rejected_with_message(
            &mut conn,
            "SK001",
            &sql,
            "column administrative_operation.consumed_at cannot be set on revoked row op_3",
        )
        .await;
    }
    drop(conn);
    run_owned(
        &pool,
        format!(
            "UPDATE administrative_operation SET outcome = 'revoked', revision = revision + 1 WHERE id = 'op_3';
             UPDATE administrative_operation SET consumed_at = NULL, outcome = 'closed',
                 revision = revision + 1 WHERE id = 'op_3';
             {}",
            upsert(
                "op_1",
                "revoked_at = '2026-11-20 00:40Z', revocation_operation_id = 'op_2'"
            )
        ),
    )
    .await;
    // A row both consumed and revoked still takes an UPDATE that keeps
    // consumed_at.
    run(
        &pool,
        "UPDATE administrative_operation SET consumed_at = '2026-11-20 00:10Z', outcome = 'revoked',
             revision = revision + 1 WHERE id = 'op_1'",
    )
    .await;
    // Not guarded: an INSERT carrying both, consumption after revocation,
    // and an UPDATE that sets both at once.
    accepts(
        &pool,
        &insert(
            "administrative_operation",
            OPERATION,
            &[
                ("consumed_at", "'2026-11-20 00:30Z'"),
                ("revoked_at", "'2026-11-20 00:20Z'"),
                ("revocation_operation_id", "'op_2'"),
            ],
        ),
    )
    .await;
    accepts(
        &pool,
        "UPDATE administrative_operation SET consumed_at = '2026-11-20 00:02Z', revoked_at = '2026-11-20 00:01Z',
             revocation_operation_id = 'op_2', revision = revision + 1 WHERE id = 'op_4'",
    )
    .await;
    let rows: Vec<(String, bool, bool, String, i64)> = sqlx::query_as(
        "SELECT id, consumed_at IS NOT NULL, revoked_at IS NOT NULL, outcome, revision
         FROM administrative_operation WHERE id IN ('op_1', 'op_3') ORDER BY id COLLATE \"C\"",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            ("op_1".into(), true, true, "revoked".into(), 4),
            ("op_3".into(), false, true, "closed".into(), 4),
        ]
    );
    db.drop([pool]).await;
}

/// The backend pid of `conn`.
async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
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
    .expect("the writer never waited for the other one");
}

/// Runs `sql`, which must not wait for a lock, so the test fails instead of
/// hanging.
async fn run_promptly(conn: &mut PgConnection, sql: &str) {
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        sqlx::raw_sql(AssertSqlSafe(sql.to_string())).execute(conn),
    )
    .await
    .unwrap_or_else(|_| panic!("{sql}: waited for a lock"));
    if let Err(err) = result {
        panic!("{sql}: {err}");
    }
}

type SqlTask = tokio::task::JoinHandle<(PgConnection, Result<(), sqlx::Error>)>;

/// Runs `sql` in a task, then rolls back whatever transaction is left open.
fn spawn_sql(mut conn: PgConnection, sql: String) -> SqlTask {
    tokio::spawn(async move {
        let result = sqlx::raw_sql(AssertSqlSafe(sql))
            .execute(&mut conn)
            .await
            .map(|_| ());
        sqlx::raw_sql("ROLLBACK").execute(&mut conn).await.unwrap();
        (conn, result)
    })
}

async fn finished(task: SqlTask) -> Result<(), sqlx::Error> {
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("a writer never finished")
        .unwrap()
        .1
}

/// The outcomes of two writers that wait for each other: exactly one is
/// chosen as the deadlock victim (40P01) and the other completes.
async fn assert_one_deadlock_victim(first: SqlTask, second: SqlTask) {
    let mut codes: Vec<String> = Vec::new();
    for result in [finished(first).await, finished(second).await] {
        codes.push(match result {
            Ok(()) => "ok".to_string(),
            Err(err) => sqlstate(&err),
        });
    }
    codes.sort();
    assert_eq!(codes, ["40P01", "ok"]);
}

/// The audit append of a writer that already holds its row locks: lock the
/// head, insert the next event and advance the head (0002).
const APPEND_EVENT: &str = r"SELECT FROM audit_chain_head FOR UPDATE;
    INSERT INTO audit_event VALUES ('evt_4', NULL, 4, '\x03', '2026-11-20Z', 'adm_2',
        'administrative_operation.create', 'op_5', NULL, NULL, 'pending');
    UPDATE audit_chain_head SET sequence = 4, head_hash = '\x04'";

/// Deadlock 1 of the README lock-ordering note: a writer that locks a row
/// with FOR UPDATE and then waits for the audit head deadlocks with a head
/// holder that inserts an operation referencing that row, because the
/// insert's foreign-key check takes KEY SHARE, which conflicts with
/// FOR UPDATE. With FOR NO KEY UPDATE the insert does not wait.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn for_update_on_a_referenced_row_deadlocks_with_the_audit_head() {
    let (db, pool) = seeded().await;
    let approve = format!(
        "BEGIN; {APPEND_EVENT};
         INSERT INTO administrative_operation VALUES
             ('op_5', NULL, 'adm_2', 'approve', sha256('op_5'), 1, '{{}}', NULL, NULL, NULL, NULL, NULL,
              'op_1', 1, 'applied', 'evt_4')"
    );
    let mut locker = pool.acquire().await.unwrap().detach();
    let mut head = pool.acquire().await.unwrap().detach();
    let (locker_pid, head_pid) = (backend_pid(&mut locker).await, backend_pid(&mut head).await);
    run_promptly(
        &mut locker,
        "BEGIN; SELECT FROM administrative_operation WHERE id = 'op_1' FOR UPDATE",
    )
    .await;
    let inserter = spawn_sql(head, approve.clone());
    wait_until_blocked(&pool, head_pid, locker_pid).await;
    let locker = spawn_sql(
        locker,
        "SELECT FROM audit_chain_head FOR UPDATE".to_string(),
    );
    assert_one_deadlock_victim(inserter, locker).await;

    // The prescribed lock: the insert's KEY SHARE does not conflict with it.
    let mut locker = pool.acquire().await.unwrap().detach();
    let mut head = pool.acquire().await.unwrap().detach();
    run_promptly(
        &mut locker,
        "BEGIN; SELECT FROM administrative_operation WHERE id = 'op_1' FOR NO KEY UPDATE",
    )
    .await;
    run_promptly(&mut head, &format!("{approve}; ROLLBACK")).await;
    run_promptly(
        &mut locker,
        "SELECT FROM audit_chain_head FOR UPDATE; ROLLBACK",
    )
    .await;
    db.drop([pool]).await;
}

/// Deadlock 2 of the README lock-ordering note: a head holder that updates
/// a row it did not lock before taking the head (here the revoke UPDATE of
/// the revoked operation) deadlocks with a writer that locked that row
/// first and then waits for the head. Locking the revoked row with
/// FOR NO KEY UPDATE before the head, and updating it after the revoking
/// operation is inserted, makes the second writer wait without holding the
/// head.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_row_updated_after_the_audit_head_must_be_locked_first() {
    let (db, pool) = seeded().await;
    let revoke = |lock_first: &str| {
        format!(
            "BEGIN; {lock_first} {APPEND_EVENT};
             INSERT INTO administrative_operation VALUES
                 ('op_5', 'ten_a', 'adm_1', 'route_bundle_approval_revoke', sha256('op_5'), 1, '{{}}', NULL,
                  NULL, NULL, NULL, NULL, NULL, 1, 'applied', 'evt_4');
             UPDATE administrative_operation SET revoked_at = '2026-11-20 00:30Z', revocation_operation_id = 'op_5',
                 revision = revision + 1 WHERE id = 'op_3'"
        )
    };
    let mut locker = pool.acquire().await.unwrap().detach();
    let mut head = pool.acquire().await.unwrap().detach();
    let (locker_pid, head_pid) = (backend_pid(&mut locker).await, backend_pid(&mut head).await);
    run_promptly(
        &mut locker,
        "BEGIN; SELECT FROM administrative_operation WHERE id = 'op_3' FOR NO KEY UPDATE",
    )
    .await;
    let revoker = spawn_sql(head, revoke(""));
    wait_until_blocked(&pool, head_pid, locker_pid).await;
    let locker = spawn_sql(
        locker,
        "SELECT FROM audit_chain_head FOR UPDATE".to_string(),
    );
    assert_one_deadlock_victim(revoker, locker).await;

    // The prescribed order: the revoker waits for the row before it holds
    // the head, so the first writer takes the head and finishes.
    let mut locker = pool.acquire().await.unwrap().detach();
    let mut head = pool.acquire().await.unwrap().detach();
    let (locker_pid, head_pid) = (backend_pid(&mut locker).await, backend_pid(&mut head).await);
    run_promptly(
        &mut locker,
        "BEGIN; SELECT FROM administrative_operation WHERE id = 'op_3' FOR NO KEY UPDATE",
    )
    .await;
    let revoker = spawn_sql(
        head,
        format!(
            "{}; COMMIT",
            revoke("SELECT FROM administrative_operation WHERE id = 'op_3' FOR NO KEY UPDATE;")
        ),
    );
    wait_until_blocked(&pool, head_pid, locker_pid).await;
    run_promptly(
        &mut locker,
        "SELECT FROM audit_chain_head FOR UPDATE; ROLLBACK",
    )
    .await;
    finished(revoker).await.unwrap();
    let revoked: Option<String> = sqlx::query_scalar(
        "SELECT revocation_operation_id FROM administrative_operation WHERE id = 'op_3'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(revoked.as_deref(), Some("op_5"));
    db.drop([pool]).await;
}

/// The domain-row order of the README lock-order note. Two writers that
/// update the same two role bindings in opposite orders deadlock when each
/// locks a row as it updates it. When both first lock the rows with one
/// statement ordered by the key under "C", the second writer waits for the
/// first row while holding neither, and proceeds once the first commits:
/// no 40P01 (under READ COMMITTED). The statement's plan has LockRows on
/// top, with a Sort or an index scan of the primary key directly below, so
/// the rows are locked in key order.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn writers_locking_rows_in_key_order_wait_instead_of_deadlocking() {
    let (db, pool) = seeded().await;
    let update = |id: &str| {
        format!(
            "UPDATE admin_role_binding SET status = 'disabled', revision = revision + 1 WHERE id = '{id}'"
        )
    };
    let lock_both = "SELECT id FROM admin_role_binding WHERE id IN ('rb_3', 'rb_2')
         ORDER BY id COLLATE \"C\" FOR NO KEY UPDATE";
    let plan: Vec<String> =
        sqlx::query_scalar(AssertSqlSafe(format!("EXPLAIN (COSTS OFF) {lock_both}")))
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(plan[0], "LockRows", "{plan:?}");
    assert!(
        plan[1].contains("Sort") || plan[1].contains("Index Scan using admin_role_binding_pkey"),
        "{plan:?}"
    );

    // Unordered: each writer holds the row the other one needs.
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    run_promptly(&mut first, &format!("BEGIN; {}", update("rb_3"))).await;
    run_promptly(&mut second, &format!("BEGIN; {}", update("rb_2"))).await;
    let first = spawn_sql(first, update("rb_2"));
    wait_until_blocked(&pool, first_pid, second_pid).await;
    let second = spawn_sql(second, update("rb_3"));
    assert_one_deadlock_victim(first, second).await;

    // Ordered: the second writer waits for rb_2 without holding rb_3, so the
    // first one updates both, in its own order, and commits.
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    run_promptly(&mut first, &format!("BEGIN; {lock_both}")).await;
    let second = spawn_sql(
        second,
        format!(
            "BEGIN; {lock_both}; {}; {}; COMMIT",
            update("rb_2"),
            update("rb_3")
        ),
    );
    wait_until_blocked(&pool, second_pid, first_pid).await;
    run_promptly(
        &mut first,
        &format!("{}; {}; COMMIT", update("rb_3"), update("rb_2")),
    )
    .await;
    finished(second).await.unwrap();
    assert_eq!(
        revisions(&pool, "admin_role_binding", "id").await,
        [1, 3, 3]
    );
    db.drop([pool]).await;
}

/// Each rule that ties several columns together fails with its own named
/// check, so the service can map the 23514.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn multi_column_rules_fail_with_their_names() {
    let (db, pool) = seeded().await;
    let op = |set: &[(&str, &str)]| insert("administrative_operation", OPERATION, set);
    let cases = [
        (
            insert(
                "admin_credential",
                CREDENTIAL,
                &[("revoked_at", "'2026-11-20Z'")],
            ),
            "admin_credential_revoked_disabled_check",
        ),
        (
            insert(
                "admin_role_binding",
                BINDING,
                &[("role", "'security_admin'")],
            ),
            "admin_role_binding_scope_check",
        ),
        (
            insert("admin_role_binding", BINDING, &[("tenant_id", "NULL")]),
            "admin_role_binding_scope_check",
        ),
        (
            op(&[("kind", "'approve'")]),
            "administrative_operation_approve_kind_check",
        ),
        (
            op(&[("kind", "'approve'"), ("approves_operation_id", "'op_x'")]),
            "administrative_operation_approves_self_check",
        ),
        (
            op(&[
                ("revoked_at", "'2026-11-20Z'"),
                ("revocation_operation_id", "'op_x'"),
            ]),
            "administrative_operation_revokes_self_check",
        ),
        (
            op(&[("revoked_at", "'2026-11-20Z'")]),
            "administrative_operation_revocation_check",
        ),
        (
            op(&[("revocation_operation_id", "'op_2'")]),
            "administrative_operation_revocation_check",
        ),
        (
            op(&[("challenge_hash", "sha256('c')")]),
            "administrative_operation_challenge_expiry_check",
        ),
        (
            op(&[
                ("expires_at", "'2026-11-20 01:00Z'"),
                ("consumed_at", "'2026-11-20 01:00Z'"),
            ]),
            "administrative_operation_consumed_before_expiry_check",
        ),
        (
            insert(
                "consumed_assertion",
                CONSUMED,
                &[("retain_until", "'2026-11-20Z'")],
            ),
            "consumed_assertion_retention_check",
        ),
    ];
    for (sql, constraint) in cases {
        violates(&pool, sql, constraint).await;
    }
    db.drop([pool]).await;
}

/// Runs `sql` on `conn`, checks that it fails with 23503 from the foreign key
/// named `constraint`, and rolls back any transaction it opened.
async fn fk_violation(conn: &mut PgConnection, sql: &str, constraint: &str) {
    let err = sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(&mut *conn)
        .await
        .expect_err(sql);
    assert_eq!(sqlstate(&err), "23503", "{sql}: {err}");
    assert_eq!(
        err.as_database_error().and_then(|e| e.constraint()),
        Some(constraint),
        "{sql}: {err}"
    );
    run(&mut *conn, "ROLLBACK").await;
}

/// Every foreign key holds back a delete of the row it references (no
/// cascade, no SET NULL) and is checked at the statement, even under
/// `SET CONSTRAINTS ALL DEFERRED` (not deferrable), each under its own name.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn references_hold_back_deletes_and_are_never_deferred() {
    let (db, pool) = seeded().await;
    // Rows referenced through exactly one foreign key each.
    run(
        &pool,
        "INSERT INTO tenant VALUES ('ten_r', 'r', 'ns_r', 'enabled'), ('ten_o', 'o', 'ns_o', 'enabled');
         INSERT INTO admin_identity VALUES ('adm_c', 'enabled'), ('adm_r', 'enabled');
         INSERT INTO admin_credential VALUES ('crd_c', 'adm_c', 'sha256:cc', 'ops-ca', 'enabled', NULL);
         INSERT INTO admin_role_binding VALUES ('rb_r', 'adm_r', 'auditor', 'ten_r', 'enabled');
         INSERT INTO administrative_operation VALUES
             ('op_t', 'ten_o', 'adm_1', 'tenant.update', sha256('op_t'), 1, '{}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'pending', 'evt_1'),
             ('op_w', NULL, 'adm_1', 'route_bundle_approval_revoke', sha256('op_w'), 1, '{}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'applied', 'evt_1'),
             ('op_v', NULL, 'adm_1', 'tenant.update', sha256('op_v'), 1, '{}', NULL, NULL, NULL, '2026-11-20Z', 'op_w', NULL, 1, 'revoked', 'evt_1')",
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    let deletes = [
        (
            "DELETE FROM admin_identity WHERE id = 'adm_c'",
            "admin_credential_admin_id_fkey",
        ),
        (
            "DELETE FROM admin_identity WHERE id = 'adm_r'",
            "admin_role_binding_admin_id_fkey",
        ),
        (
            "DELETE FROM tenant WHERE id = 'ten_r'",
            "admin_role_binding_tenant_id_fkey",
        ),
        (
            "DELETE FROM tenant WHERE id = 'ten_o'",
            "administrative_operation_tenant_id_fkey",
        ),
        (
            "DELETE FROM administrative_operation WHERE id = 'op_w'",
            "administrative_operation_revocation_operation_id_fkey",
        ),
        (
            "DELETE FROM administrative_operation WHERE id = 'op_1'",
            "administrative_operation_approves_operation_id_fkey",
        ),
        (
            "DELETE FROM trust_source WHERE id = 'src_a'",
            "consumed_assertion_trust_source_id_fkey",
        ),
    ];
    // 0006 guards deletes of these tables, so each case disables the
    // table's user triggers in its own transaction to reach the foreign key.
    for (sql, constraint) in deletes {
        let table = sql.split(' ').nth(2).unwrap();
        fk_violation(
            &mut conn,
            &format!("BEGIN; ALTER TABLE {table} DISABLE TRIGGER USER; {sql}"),
            constraint,
        )
        .await;
    }
    // The instance policy row and audit events are append-only (0002), so
    // the delete side of their references cannot be reached.
    let op = |set: &[(&str, &str)]| insert("administrative_operation", OPERATION, set);
    let dangling = [
        (
            insert("admin_credential", CREDENTIAL, &[("admin_id", "'adm_x9'")]),
            "admin_credential_admin_id_fkey",
        ),
        (
            insert("admin_role_binding", BINDING, &[("admin_id", "'adm_x9'")]),
            "admin_role_binding_admin_id_fkey",
        ),
        (
            insert("admin_role_binding", BINDING, &[("tenant_id", "'ten_x9'")]),
            "admin_role_binding_tenant_id_fkey",
        ),
        (
            format!(
                "ALTER TABLE recovery_state DISABLE TRIGGER USER; DELETE FROM recovery_state; {}",
                insert("recovery_state", RECOVERY, &[("instance_id", "'inst_x9'")])
            ),
            "recovery_state_instance_id_fkey",
        ),
        (
            op(&[("tenant_id", "'ten_x9'")]),
            "administrative_operation_tenant_id_fkey",
        ),
        (
            op(&[
                ("revoked_at", "'2026-11-20Z'"),
                ("revocation_operation_id", "'op_x9'"),
            ]),
            "administrative_operation_revocation_operation_id_fkey",
        ),
        (
            op(&[("kind", "'approve'"), ("approves_operation_id", "'op_x9'")]),
            "administrative_operation_approves_operation_id_fkey",
        ),
        (
            op(&[("audit_id", "'evt_x9'")]),
            "administrative_operation_audit_id_fkey",
        ),
        (
            insert(
                "consumed_assertion",
                CONSUMED,
                &[("trust_source_id", "'src_x9'")],
            ),
            "consumed_assertion_trust_source_id_fkey",
        ),
    ];
    for (sql, constraint) in dangling {
        fk_violation(
            &mut conn,
            &format!("BEGIN; SET CONSTRAINTS ALL DEFERRED; {sql}; ROLLBACK"),
            constraint,
        )
        .await;
    }
    drop(conn);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    db.drop([pool]).await;
}

/// The set-once guard rejects an argument that names no column, so a typo
/// in a later migration fails the first update instead of passing it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn set_once_guard_with_an_unknown_column_is_an_error() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        "CREATE TABLE typo (id text PRIMARY KEY, done_at timestamptz);
         CREATE TRIGGER typo_set_once BEFORE UPDATE ON typo
             FOR EACH ROW EXECUTE FUNCTION skyoauth_reject_change_once_set('done_at', 'dnoe_at');
         INSERT INTO typo VALUES ('x', NULL)",
    )
    .await;
    let err = sqlx::raw_sql("UPDATE typo SET done_at = now()")
        .execute(&pool)
        .await
        .unwrap_err();
    // P0001 is raise_exception, PL/pgSQL's default.
    assert_eq!(sqlstate(&err), "P0001", "{err}");
    assert!(
        err.to_string().contains("names unknown column dnoe_at"),
        "{err}"
    );
    db.drop([pool]).await;
}

/// `ENABLE ALWAYS` keeps the guards firing in replica mode, which would
/// otherwise skip ordinary triggers; CHECKs hold anyway. Foreign keys do not
/// fire there.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn operator_guards_hold_under_replica_role() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        "UPDATE administrative_operation SET consumed_at = '2026-11-20 00:30Z',
             revision = revision + 1 WHERE id = 'op_1';
         UPDATE administrative_operation SET revoked_at = '2026-11-20 00:01Z', revocation_operation_id = 'op_2',
             revision = revision + 1 WHERE id = 'op_4';
         UPDATE admin_credential SET status = 'disabled', revoked_at = '2026-11-20Z' WHERE id = 'crd_2'",
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    run(&mut *conn, "SET session_replication_role = replica").await;
    assert_rejected(&mut conn, r"
        SK001 UPDATE admin_identity SET created_at = '2020-01-01Z'
        SK001 UPDATE admin_credential SET public_identity = 'sha256:cc' WHERE id = 'crd_1'
        SK001 UPDATE admin_credential SET revoked_at = NULL, status = 'enabled' WHERE id = 'crd_2'
        SK001 UPDATE admin_role_binding SET role = 'auditor', tenant_id = 'ten_a', revision = revision + 1 WHERE id = 'rb_1'
        SK001 UPDATE admin_role_binding SET status = 'disabled' WHERE id = 'rb_1'
        SK001 UPDATE recovery_state SET instance_id = 'inst_2', revision = revision + 1
        SK001 UPDATE recovery_state SET bootstrap_closed = false, revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_public_key = '\x0c', revision = revision + 1
        SK001 UPDATE recovery_state SET recovery_key_epoch = 0
        SK001 UPDATE recovery_state SET revision = revision + 2
        SK001 UPDATE administrative_operation SET immutable_plan = '{}', revision = revision + 1 WHERE id = 'op_1'
        SK001 UPDATE administrative_operation SET consumed_at = NULL, revision = revision + 1 WHERE id = 'op_1'
        SK001 UPDATE administrative_operation SET consumed_at = '2026-11-20 00:02Z', revision = revision + 1 WHERE id = 'op_4'
        SK001 UPDATE administrative_operation SET outcome = 'x' WHERE id = 'op_3'
        SK001 UPDATE consumed_assertion SET retain_until = '2027-01-01Z'
        23514 UPDATE admin_credential SET status = 'enabled' WHERE id = 'crd_2'
        23514 UPDATE administrative_operation SET revoked_at = now(), revision = revision + 1 WHERE id = 'op_1'
    ").await;
    // Foreign keys, unlike the guards, are not enforced in replica mode
    // (migrations/README.md "Limits").
    run(
        &mut *conn,
        "INSERT INTO admin_credential VALUES ('crd_9', 'adm_missing', 'sha256:99', 'ops-ca', 'enabled', NULL)",
    )
    .await;
    conn.close().await.unwrap();
    for (table, key) in [
        ("admin_role_binding", "id"),
        ("recovery_state", "instance_id"),
    ] {
        assert!(
            revisions(&pool, table, key).await.iter().all(|r| *r == 1),
            "{table}"
        );
    }
    db.drop([pool]).await;
}

/// A role that can create objects in some schema puts it ahead of
/// `pg_catalog` with operators that call every value equal and no epoch
/// smaller or larger. The new guards compare with the built-in operators all
/// the same.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn operator_guards_ignore_operators_on_the_callers_search_path() {
    let (mut db, pool) = seeded().await;
    run(
        &pool,
        "UPDATE administrative_operation SET consumed_at = '2026-11-20 00:30Z',
             revision = revision + 1 WHERE id = 'op_1'",
    )
    .await;
    let (role, connect) = db.create_login_role().await;
    run(&pool, "CREATE SCHEMA evil").await;
    run_owned(
        &pool,
        format!(
            "GRANT SELECT, UPDATE ON recovery_state, administrative_operation TO {role};
             GRANT USAGE, CREATE ON SCHEMA evil TO {role}"
        ),
    )
    .await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    run(
        &mut writer,
        "CREATE FUNCTION evil.yes(jsonb, jsonb) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE FUNCTION evil.no(jsonb, jsonb) RETURNS boolean LANGUAGE sql AS 'SELECT false';
         CREATE OPERATOR evil.= (LEFTARG = jsonb, RIGHTARG = jsonb, FUNCTION = evil.yes);
         CREATE OPERATOR evil.<> (LEFTARG = jsonb, RIGHTARG = jsonb, FUNCTION = evil.no);
         CREATE FUNCTION evil.yes(bytea, bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.= (LEFTARG = bytea, RIGHTARG = bytea, FUNCTION = evil.yes);
         CREATE FUNCTION evil.no(bigint, bigint) RETURNS boolean LANGUAGE sql AS 'SELECT false';
         CREATE OPERATOR evil.< (LEFTARG = bigint, RIGHTARG = bigint, FUNCTION = evil.no);
         CREATE OPERATOR evil.> (LEFTARG = bigint, RIGHTARG = bigint, FUNCTION = evil.no);
         SET search_path = evil, pg_catalog, public",
    )
    .await;
    // The shadow is in effect for the caller's own expressions.
    let shadowed: bool = sqlx::query_scalar("SELECT 1::bigint < 2::bigint")
        .fetch_one(&mut writer)
        .await
        .unwrap();
    assert!(!shadowed);
    assert_rejected(
        &mut writer,
        r"
        SK001 UPDATE recovery_state SET bootstrap_closed = false, revision = 2
        SK001 UPDATE recovery_state SET recovery_public_key = '\x0c', revision = 2
        SK001 UPDATE recovery_state SET recovery_key_epoch = 2, revision = 2
        SK001 UPDATE administrative_operation SET consumed_at = NULL, revision = 3 WHERE id = 'op_1'
    ",
    )
    .await;
    writer.close().await.unwrap();
    let row: (bool, Vec<u8>, i64) = sqlx::query_as(
        "SELECT bootstrap_closed, recovery_public_key, recovery_key_epoch FROM recovery_state",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (true, vec![10, 11], 1));
    db.drop([pool]).await;
}

/// Consuming a proof needs only INSERT on `consumed_assertion`: the guards
/// read no table and the foreign key check runs as the table owner. A
/// conflict target needs SELECT as well, so the service uses a plain insert
/// or `ON CONFLICT DO NOTHING` without one (README.md).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn proof_consumption_needs_only_insert() {
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    run_owned(
        &pool,
        format!("GRANT INSERT ON consumed_assertion TO {role}"),
    )
    .await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    run(
        &mut writer,
        "INSERT INTO public.consumed_assertion VALUES
             ('ten_a', 'src_a', sha256('jti_9'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')",
    )
    .await;
    let inserted = sqlx::raw_sql(
        "INSERT INTO public.consumed_assertion VALUES
             ('ten_a', 'src_a', sha256('jti_9'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
         ON CONFLICT DO NOTHING",
    )
    .execute(&mut writer)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(inserted, 0);
    assert_rejected(&mut writer, r"
        23505 INSERT INTO public.consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_9'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
        23503 INSERT INTO public.consumed_assertion VALUES ('ten_a', 'src_b', sha256('jti_9'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z')
        42501 INSERT INTO public.consumed_assertion VALUES ('ten_a', 'src_a', sha256('jti_9'), 'dk_1', '2026-11-20Z', '2026-11-20 00:10Z') ON CONFLICT (tenant_id, trust_source_id, replay_key_digest) DO NOTHING
        42501 DELETE FROM public.consumed_assertion
    ").await;
    writer.close().await.unwrap();
    db.drop([pool]).await;
}
