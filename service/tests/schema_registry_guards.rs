//! Delete and truncate guards of the `0006_registry_guards` migration
//! against a real PostgreSQL server: every registry table of `0002` to
//! `0005` rejects `TRUNCATE`, also one that reaches it through
//! `TRUNCATE ... CASCADE`; the instance, tenant and operator records,
//! credentials included, reject `DELETE`, bindings and grants accept it only
//! when disabled, a consumed proof accepts it only after `retain_until`, and
//! the list rows stay deletable.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database, the replica-role cases need
//! `SET` on `session_replication_role`, and the search-path test
//! `CREATEROLE` (`common/mod.rs`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::time::Duration;

use common::TestDb;
use skyoauth_service::persistence::{self, PgPool};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Postgres};

/// One row or more in every table of `0002` to `0005`. Bindings: `bnd_1`
/// enabled and referenced by `grt_1`, `bnd_2` disabled and unreferenced,
/// `bnd_3` disabled and referenced by the disabled `grt_2`, `bnd_4` enabled
/// and unreferenced. Credentials: `crd_1` live, `crd_r` revoked. Consumed
/// proofs: one past its `retain_until`, one not.
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
    -- Enabled egress entries for the seeded destinations (0011 guard).
    INSERT INTO egress_allowlist_entry VALUES
        ('egr_seed_1', 'oidc_discovery', 'https://token.actions.githubusercontent.com/.well-known/openid-configuration', 'enabled');
    INSERT INTO trust_source VALUES
        ('src_gh', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'on_demand_jwt', NULL, 'single_use', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_1', 'ten_a', 'live', 'src_gh', 'generic_production', '{"sub": "repo:1"}', 'wld_1', 'enabled'),
        ('bnd_2', 'ten_a', 'old', 'src_gh', 'generic_production', '{"sub": "repo:2"}', 'wld_1', 'disabled'),
        ('bnd_3', 'ten_a', 'retired', 'src_gh', 'generic_production', '{"sub": "repo:3"}', 'wld_1', 'disabled'),
        ('bnd_4', 'ten_a', 'spare', 'src_gh', 'generic_production', '{"sub": "repo:4"}', 'wld_1', 'enabled');
    INSERT INTO service_identity VALUES ('svc_1', 'ten_a', 'deployer', '["read"]', '{}', 'enabled');
    INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', 'rs_1');
    INSERT INTO service_grant VALUES
        ('grt_1', 'ten_a', 'live', 'wld_1', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_2', 'ten_a', 'retired', 'wld_1', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'disabled', 'not_required');
    INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_1', 'ten_a', 'wld_1'), ('grt_2', 'bnd_3', 'ten_a', 'wld_1');
    INSERT INTO service_grant_resource_server VALUES ('grt_1', 'ten_a', 'rs_1'), ('grt_2', 'ten_a', 'rs_1');
    INSERT INTO admin_identity VALUES ('adm_1', 'enabled');
    INSERT INTO admin_credential VALUES
        ('crd_1', 'adm_1', 'sha256:c1', 'ops-ca', 'enabled', NULL),
        ('crd_r', 'adm_1', 'sha256:cr', 'ops-ca', 'disabled', '2026-11-20Z');
    INSERT INTO admin_role_binding VALUES ('rb_1', 'adm_1', 'security_admin', NULL, 'enabled');
    INSERT INTO recovery_state VALUES ('inst_1', true, '\x0a0b', 1);
    INSERT INTO administrative_operation VALUES
        ('op_1', NULL, 'adm_1', 'tenant.update', sha256('op_1'), 1, '{}', NULL, NULL, NULL, NULL, NULL, NULL, 1, 'applied', 'evt_1');
    INSERT INTO consumed_assertion VALUES
        ('ten_a', 'src_gh', sha256('jti_old'), 'dk_1', now() - interval '2 hours', now() - interval '1 hour'),
        ('ten_a', 'src_gh', sha256('jti_new'), 'dk_1', now() - interval '1 minute', now() + interval '1 hour')"#;

/// The tables whose rows `0006` never lets go: instance, tenant and operator
/// records, credentials included, and the one-time state.
const NO_DELETE: [&str; 15] = [
    "tenant",
    "principal",
    "resource_server",
    "audience_tenant_assignment",
    "resource_server_checker",
    "resource_action",
    "trust_keyset",
    "trust_keyset_version",
    "trust_source",
    "service_identity",
    "admin_identity",
    "admin_credential",
    "admin_role_binding",
    "recovery_state",
    "administrative_operation",
];

/// The list tables: a row is deleted to shrink its owner's set.
const LIST_TABLES: [&str; 4] = [
    "resource_server_checker_tenant",
    "service_identity_resource_server",
    "service_grant_binding",
    "service_grant_resource_server",
];

/// Every table that `0006` gives a truncate guard, each with a table whose
/// `TRUNCATE ... CASCADE` reaches it (itself where nothing else does).
const CASCADES: [(&str, &str); 22] = [
    ("tenant", "tenant"),
    ("principal", "tenant"),
    ("resource_server", "resource_server"),
    ("audience_tenant_assignment", "tenant"),
    ("resource_server_checker", "resource_server"),
    ("resource_server_checker_tenant", "tenant"),
    ("resource_action", "resource_server"),
    ("trust_keyset", "tenant"),
    ("trust_keyset_version", "tenant"),
    ("trust_source", "tenant"),
    ("principal_binding", "tenant"),
    ("service_identity", "tenant"),
    ("service_identity_resource_server", "resource_server"),
    ("service_grant", "tenant"),
    ("service_grant_binding", "principal_binding"),
    ("service_grant_resource_server", "resource_server"),
    ("admin_identity", "admin_identity"),
    ("admin_credential", "admin_identity"),
    ("admin_role_binding", "tenant"),
    ("recovery_state", "instance_security_policy"),
    ("administrative_operation", "audit_event"),
    ("consumed_assertion", "trust_source"),
];

/// The functions 0006 adds; none reads a table.
const FUNCTIONS: [&str; 5] = [
    "skyoauth_reject_delete",
    "skyoauth_reject_delete_before_retention",
    "skyoauth_reject_delete_grant_unless_disabled",
    "skyoauth_reject_delete_unless_disabled",
    "skyoauth_reject_truncate",
];

/// The tables of `0001` and `0002` whose `DELETE` or `TRUNCATE` guards
/// call `skyoauth_reject_mutation()` of `0001`.
const FROZEN_GUARDED: [&str; 5] = [
    "schema_info",
    "instance_security_policy",
    "egress_allowlist_entry",
    "audit_event",
    "audit_chain_head",
];

/// The message of an unconditional `0006` guard.
fn not_allowed(operation: &str, table: &str) -> String {
    format!("{operation} is not allowed on {table}")
}

/// The session modes every guard must hold in: the default one, and the
/// replica mode of logical-replication apply, which skips triggers that
/// are not `ENABLE ALWAYS` and foreign keys.
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
/// given, `message`, so a statement that reaches several tables shows which
/// guard rejected it. Rolls back a transaction that `sql` opened. SK001 is
/// the guards' state and 23503 `foreign_key_violation`.
async fn rejected(conn: &mut PgConnection, sql: &str, code: &str, message: Option<&str>) {
    let err = sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(&mut *conn)
        .await
        .expect_err(sql);
    assert_eq!(sqlstate(&err), code, "{sql}: {err}");
    if let Some(message) = message {
        let text = err.as_database_error().unwrap().message().to_string();
        assert_eq!(text, message, "{sql}");
    }
    if sql.starts_with("BEGIN") {
        run(&mut *conn, "ROLLBACK").await;
    }
}

async fn count(conn: &mut PgConnection, table: &str) -> i64 {
    sqlx::query_scalar(AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(&mut *conn)
        .await
        .unwrap()
}

/// The row count of every table that `0006` guards.
async fn counts(conn: &mut PgConnection) -> Vec<(&'static str, i64)> {
    let mut all = Vec::new();
    for (table, _) in CASCADES {
        all.push((table, count(conn, table).await));
    }
    all
}

async fn ids(conn: &mut PgConnection, sql: &str) -> Vec<String> {
    let mut ids: Vec<String> = sqlx::query_scalar(AssertSqlSafe(sql.to_string()))
        .fetch_all(&mut *conn)
        .await
        .unwrap();
    ids.sort();
    ids
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_guards_migration_is_recorded_once_and_rerun_is_a_no_op() {
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
        first.contains(&(6, "registry guards".into(), true)),
        "{first:?}"
    );
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    db.drop([pool]).await;
}

/// Catalog properties that behaviour tests cannot see directly: every table
/// of the schema has a truncate guard (so a table a later migration adds
/// without one fails here), every delete guard is the expected one, each
/// fires in every `session_replication_role`, and the new functions pin
/// their `search_path`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_table_guards_truncate_and_each_delete_guard_is_pinned() {
    let (db, pool) = seeded().await;
    let mut tables: Vec<String> = sqlx::query_scalar(
        "SELECT relname::text FROM pg_class
         WHERE relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND relkind IN ('r', 'p') AND relname <> '_sqlx_migrations'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    tables.sort();
    // (table, trigger, function, tgtype, tgenabled) of every user trigger
    // that fires on DELETE or TRUNCATE.
    let mut triggers: Vec<(String, String, String, i16, String)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, p.proname::text, t.tgtype, t.tgenabled::text
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND t.tgtype & (8 | 32) <> 0",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    triggers.sort();

    // tgtype bits: 1 row, 2 before, 4 insert, 8 delete, 16 update, 32 truncate.
    const TRUNCATE: i16 = 2 | 32;
    const DELETE: i16 = 1 | 2 | 8;
    const UPDATE_OR_DELETE: i16 = 1 | 2 | 8 | 16;
    let reject = "skyoauth_reject_mutation";
    let truncate = |table: &str| {
        if FROZEN_GUARDED.contains(&table) {
            reject
        } else {
            "skyoauth_reject_truncate"
        }
    };
    let trigger = |table: &str, name: &str, function: &str, tgtype: i16| {
        (
            table.to_string(),
            format!("{table}_{name}"),
            function.to_string(),
            tgtype,
            "A".to_string(),
        )
    };
    let mut expected: Vec<_> = tables
        .iter()
        .map(|t| trigger(t, "no_truncate", truncate(t), TRUNCATE))
        .chain(
            NO_DELETE
                .iter()
                .map(|t| trigger(t, "no_delete", "skyoauth_reject_delete", DELETE)),
        )
        .chain(
            [
                "instance_security_policy",
                "egress_allowlist_entry",
                "audit_chain_head",
            ]
            .iter()
            .map(|t| trigger(t, "no_delete", reject, DELETE)),
        )
        .chain([
            trigger("schema_info", "append_only", reject, UPDATE_OR_DELETE),
            trigger("audit_event", "append_only", reject, UPDATE_OR_DELETE),
            trigger(
                "principal_binding",
                "delete_disabled_only",
                "skyoauth_reject_delete_unless_disabled",
                DELETE,
            ),
            trigger(
                "service_grant",
                "delete_disabled_only",
                "skyoauth_reject_delete_grant_unless_disabled",
                DELETE,
            ),
            trigger(
                "consumed_assertion",
                "delete_after_retention",
                "skyoauth_reject_delete_before_retention",
                DELETE,
            ),
            // The deferred binding-set check of 0004 (AFTER ... FOR EACH ROW).
            trigger(
                "service_grant_binding",
                "keeps_one",
                "skyoauth_service_grant_has_binding",
                1 | 8,
            ),
            // The impersonation list guards of 0009 (AFTER INSERT OR UPDATE
            // OR DELETE ... FOR EACH ROW;
            // schema_reserved_ids_and_dormant_grants.rs).
            trigger(
                "service_grant_binding",
                "impersonation_frozen",
                "skyoauth_reject_impersonation_grant_list_change",
                1 | 4 | 8 | 16,
            ),
            trigger(
                "service_grant_resource_server",
                "impersonation_frozen",
                "skyoauth_reject_impersonation_grant_list_change",
                1 | 4 | 8 | 16,
            ),
        ])
        .collect();
    expected.sort();
    assert_eq!(triggers, expected);

    // The tables with no BEFORE DELETE guard are exactly the list tables.
    let mut unguarded: Vec<&str> = tables
        .iter()
        .map(String::as_str)
        .filter(|t| {
            !triggers
                .iter()
                .any(|(table, _, _, tgtype, _)| table == t && tgtype & DELETE == DELETE)
        })
        .collect();
    unguarded.sort();
    let mut lists = LIST_TABLES.to_vec();
    lists.sort();
    assert_eq!(unguarded, lists);

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
    assert_eq!(
        functions.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(),
        FUNCTIONS
    );
    for (name, config, source) in &functions {
        assert_eq!(config, &["search_path=pg_catalog, pg_temp"], "{name}");
        for table in &tables {
            assert!(
                !source.contains(&format!(" {table}")),
                "{name} names {table}"
            );
        }
    }

    // The pruning index.
    let index: String = sqlx::query_scalar(
        "SELECT pg_get_indexdef(to_regclass('consumed_assertion_retain_until_idx'))",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        index,
        "CREATE INDEX consumed_assertion_retain_until_idx ON public.consumed_assertion \
         USING btree (retain_until)"
    );
    db.drop([pool]).await;
}

/// The instance, tenant and operator records and the one-time state are
/// never deleted, whether a foreign key would also hold the row back or
/// not, in both replication modes (foreign keys do not fire in replica
/// mode, so there the guard is the only line).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn records_and_one_time_state_are_never_deleted() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let before = counts(&mut conn).await;
    for mode in MODES {
        run(&mut *conn, mode).await;
        for table in NO_DELETE {
            rejected(
                &mut conn,
                &format!("DELETE FROM {table}"),
                "SK001",
                Some(&not_allowed("DELETE", table)),
            )
            .await;
        }
        // Rows nothing references: the guard, not a foreign key, rejects.
        for sql in [
            "DELETE FROM tenant WHERE id = 'ten_b'",
            "DELETE FROM resource_action WHERE id = 'act_1'",
            "DELETE FROM trust_keyset_version WHERE id = 'kv_1'",
            "DELETE FROM admin_role_binding WHERE id = 'rb_1'",
            "DELETE FROM recovery_state",
            "DELETE FROM administrative_operation WHERE id = 'op_1'",
        ] {
            rejected(&mut conn, sql, "SK001", None).await;
        }
    }
    run(&mut *conn, "SET session_replication_role = origin").await;
    assert_eq!(counts(&mut conn).await, before);
    drop(conn);
    db.drop([pool]).await;
}

/// `TRUNCATE` is rejected on every guarded table, named directly with
/// `CASCADE` (a bare `TRUNCATE` of a referenced table fails earlier with
/// 0A000), and also when it reaches the table only through the cascade of
/// another one: with every other truncate guard disabled in the
/// transaction, the reached table's own guard rejects it. Both replication
/// modes.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn truncate_is_rejected_directly_and_through_a_cascade() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let before = counts(&mut conn).await;
    let mut guards: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
         WHERE NOT t.tgisinternal AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND t.tgtype & 32 <> 0",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    guards.sort();
    for mode in MODES {
        run(&mut *conn, mode).await;
        for (table, root) in CASCADES {
            let message = not_allowed("TRUNCATE", table);
            rejected(
                &mut conn,
                &format!("TRUNCATE {table} CASCADE"),
                "SK001",
                Some(&message),
            )
            .await;
            let disable: String = guards
                .iter()
                .filter(|(t, _)| t != table)
                .map(|(t, g)| format!("ALTER TABLE {t} DISABLE TRIGGER {g}; "))
                .collect();
            rejected(
                &mut conn,
                &format!("BEGIN; {disable}TRUNCATE {root} CASCADE"),
                "SK001",
                Some(&message),
            )
            .await;
        }
        // The list tables are referenced by nothing, so a bare TRUNCATE
        // reaches their guard.
        for table in LIST_TABLES {
            rejected(
                &mut conn,
                &format!("TRUNCATE {table}"),
                "SK001",
                Some(&not_allowed("TRUNCATE", table)),
            )
            .await;
        }
    }
    run(&mut *conn, "SET session_replication_role = origin").await;
    assert_eq!(counts(&mut conn).await, before);
    drop(conn);
    db.drop([pool]).await;
}

/// The list rows stay deletable, which is how a set shrinks; a grant's last
/// binding row is still held back at commit by the `0004` check.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn list_rows_stay_deletable() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    run(
        &mut *conn,
        "DELETE FROM resource_server_checker_tenant;
         DELETE FROM service_identity_resource_server;
         DELETE FROM service_grant_resource_server;
         INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_4', 'ten_a', 'wld_1');
         DELETE FROM service_grant_binding WHERE grant_id = 'grt_1' AND binding_id = 'bnd_1'",
    )
    .await;
    rejected(
        &mut conn,
        "DELETE FROM service_grant_binding WHERE grant_id = 'grt_1'",
        "SK001",
        Some("service grant grt_1 has no allowed binding"),
    )
    .await;
    for table in [
        "resource_server_checker_tenant",
        "service_identity_resource_server",
        "service_grant_resource_server",
    ] {
        assert_eq!(count(&mut conn, table).await, 0, "{table}");
    }
    assert_eq!(
        ids(&mut conn, "SELECT binding_id FROM service_grant_binding").await,
        ["bnd_3", "bnd_4"]
    );
    drop(conn);
    db.drop([pool]).await;
}

/// A binding or a grant is hard-deleted only when disabled (ADR-008 item
/// 3); a referenced one is then still held back by its foreign keys, and a
/// grant goes after its list rows. Replica mode does not enforce the
/// foreign keys, so there only the status is checked.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bindings_and_grants_are_deleted_only_when_disabled() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for mode in MODES {
        run(&mut *conn, mode).await;
        for (sql, table) in [
            (
                "DELETE FROM principal_binding WHERE id = 'bnd_4'",
                "principal_binding",
            ),
            ("DELETE FROM principal_binding", "principal_binding"),
            (
                "BEGIN; DELETE FROM service_grant_binding WHERE grant_id = 'grt_1';
                 DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_1';
                 DELETE FROM service_grant WHERE id = 'grt_1'",
                "service_grant",
            ),
        ] {
            let message = format!("only a disabled row of {table} may be deleted");
            rejected(&mut conn, sql, "SK001", Some(&message)).await;
        }
    }
    run(&mut *conn, "SET session_replication_role = origin").await;
    // Disabled but referenced: the foreign keys hold it back.
    for (sql, constraint) in [
        (
            "DELETE FROM principal_binding WHERE id = 'bnd_3'",
            "service_grant_binding_binding_id_fkey",
        ),
        (
            "DELETE FROM service_grant WHERE id = 'grt_2'",
            // Two foreign keys reference the grant; which one fires first
            // depends on the order of their internal triggers, which
            // follows the OIDs, so either name is accepted.
            "service_grant_binding_grant_id_fkey|service_grant_resource_server_grant_id_fkey",
        ),
    ] {
        let err = sqlx::raw_sql(AssertSqlSafe(sql))
            .execute(&mut *conn)
            .await
            .expect_err(sql);
        assert_eq!(sqlstate(&err), "23503", "{sql}: {err}");
        let fired = err
            .as_database_error()
            .and_then(|e| e.constraint())
            .unwrap_or_default();
        assert!(constraint.split('|').any(|c| c == fired), "{sql}: {fired}");
    }
    // In replica mode the status alone is checked: a disabled binding or
    // grant that a list row references goes (migrations/README.md "What
    // 0006 adds").
    run(
        &mut *conn,
        "SET session_replication_role = replica;
         BEGIN;
         DELETE FROM principal_binding WHERE id = 'bnd_3';
         DELETE FROM service_grant WHERE id = 'grt_2'",
    )
    .await;
    run(
        &mut *conn,
        "ROLLBACK; SET session_replication_role = origin",
    )
    .await;
    // Disabled and unreferenced: deleted. A grant's list rows go first, and
    // the deferred binding-set check passes for a grant deleted with them.
    run(
        &mut *conn,
        "DELETE FROM principal_binding WHERE id = 'bnd_2';
         UPDATE principal_binding SET status = 'disabled', revision = revision + 1 WHERE id = 'bnd_4';
         DELETE FROM principal_binding WHERE id = 'bnd_4'",
    )
    .await;
    run(
        &mut *conn,
        "DELETE FROM service_grant_binding WHERE grant_id = 'grt_2';
         DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_2';
         DELETE FROM service_grant WHERE id = 'grt_2'",
    )
    .await;
    assert_eq!(
        ids(&mut conn, "SELECT id FROM principal_binding").await,
        ["bnd_1", "bnd_3"]
    );
    assert_eq!(
        ids(&mut conn, "SELECT id FROM service_grant").await,
        ["grt_1"]
    );
    drop(conn);
    db.drop([pool]).await;
}

/// An impersonation grant is never deleted, disabled or not (lead decision,
/// 2026-11-21): deleting and recreating it under caller-supplied IDs would
/// revive a dormant one. A disabled delegation grant goes; an enabled one
/// does not.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn impersonation_grants_are_never_deleted() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let insert = |id: &str, mode: &str, status: &str, activation: &str| {
        format!(
            "INSERT INTO service_grant VALUES ('{id}', 'ten_a', '{id}', 'wld_1', 'svc_1', '{mode}', '[\"read\"]', NULL, '{{}}', 300, NULL, '{status}', '{activation}');
             INSERT INTO service_grant_binding VALUES ('{id}', 'bnd_1', 'ten_a', 'wld_1');
             INSERT INTO service_grant_resource_server VALUES ('{id}', 'ten_a', 'rs_1');"
        )
    };
    let remove = |id: &str| {
        format!(
            "DELETE FROM service_grant_binding WHERE grant_id = '{id}';
             DELETE FROM service_grant_resource_server WHERE grant_id = '{id}';
             DELETE FROM service_grant WHERE id = '{id}'"
        )
    };
    let impersonation = insert("grt_i", "impersonation", "disabled", "requires_reapproval");
    let delegation_off = insert("grt_d", "delegation", "disabled", "not_required");
    let delegation_on = insert("grt_e", "delegation", "enabled", "not_required");
    for mode in MODES {
        run(&mut *conn, mode).await;
        rejected(
            &mut conn,
            &format!("BEGIN; {impersonation} {}", remove("grt_i")),
            "SK001",
            Some("an impersonation grant of service_grant is never deleted"),
        )
        .await;
        rejected(
            &mut conn,
            &format!("BEGIN; {delegation_on} {}", remove("grt_e")),
            "SK001",
            Some("only a disabled row of service_grant may be deleted"),
        )
        .await;
        // A disabled delegation grant, with its list rows first, goes.
        run(
            &mut *conn,
            &format!("BEGIN; {delegation_off} {}; ROLLBACK", remove("grt_d")),
        )
        .await;
    }
    drop(conn);
    db.drop([pool]).await;
}

/// A credential is never deleted, revoked or not: it leaves service by
/// revocation (T13.6), and its row keeps the revocation record and its
/// public identity registered.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn credentials_are_never_deleted_revoked_or_not() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let message = not_allowed("DELETE", "admin_credential");
    for mode in MODES {
        run(&mut *conn, mode).await;
        for sql in [
            "DELETE FROM admin_credential WHERE id = 'crd_1'",
            "DELETE FROM admin_credential WHERE id = 'crd_r'",
            "BEGIN;
             UPDATE admin_credential SET status = 'disabled', revoked_at = '2026-11-21Z' WHERE id = 'crd_1';
             DELETE FROM admin_credential WHERE id = 'crd_1'",
        ] {
            rejected(&mut conn, sql, "SK001", Some(&message)).await;
        }
    }
    run(&mut *conn, "SET session_replication_role = origin").await;
    // The revoked key cannot be registered again.
    rejected(
        &mut conn,
        "INSERT INTO admin_credential VALUES ('crd_9', 'adm_1', 'sha256:cr', 'ops-ca', 'enabled', NULL)",
        "23505",
        None,
    )
    .await;
    let mut rows: Vec<(String, bool)> =
        sqlx::query_as("SELECT id, revoked_at IS NOT NULL FROM admin_credential")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
    rows.sort();
    assert_eq!(rows, [("crd_1".into(), false), ("crd_r".into(), true)]);
    drop(conn);
    db.drop([pool]).await;
}

/// A consumed proof is deleted only once `retain_until < now()`, where
/// `now()` is the start of the deleting transaction; a row whose
/// `retain_until` equals it is kept. The pruning statement can use the
/// `retain_until` index.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn consumed_assertions_are_pruned_only_after_retain_until() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let message = Some("a row of consumed_assertion cannot be deleted before its retain_until");
    for mode in MODES {
        run(&mut *conn, mode).await;
        for sql in [
            "DELETE FROM consumed_assertion",
            "DELETE FROM consumed_assertion WHERE replay_key_digest = sha256('jti_new')",
            "BEGIN;
             INSERT INTO consumed_assertion VALUES
                 ('ten_a', 'src_gh', sha256('jti_now'), 'dk_1', now() - interval '1 second', now());
             DELETE FROM consumed_assertion WHERE replay_key_digest = sha256('jti_now')",
        ] {
            rejected(&mut conn, sql, "SK001", message).await;
        }
    }
    run(&mut *conn, "SET session_replication_role = origin").await;
    assert_eq!(count(&mut conn, "consumed_assertion").await, 2);

    let plan: Vec<String> = {
        let mut tx = conn.begin().await.unwrap();
        run(&mut *tx, "SET LOCAL enable_seqscan = off").await;
        let plan =
            sqlx::query_scalar("EXPLAIN DELETE FROM consumed_assertion WHERE retain_until < now()")
                .fetch_all(&mut *tx)
                .await
                .unwrap();
        tx.rollback().await.unwrap();
        plan
    };
    assert!(
        plan.iter()
            .any(|line| line.contains("consumed_assertion_retain_until_idx")),
        "{plan:?}"
    );

    // The pruning job's statement removes the expired row only.
    let pruned = sqlx::raw_sql("DELETE FROM consumed_assertion WHERE retain_until < now()")
        .execute(&mut *conn)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(pruned, 1);
    let left: Vec<Vec<u8>> = sqlx::query_scalar("SELECT replay_key_digest FROM consumed_assertion")
        .fetch_all(&mut *conn)
        .await
        .unwrap();
    let new: Vec<u8> = sqlx::query_scalar("SELECT sha256('jti_new')")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(left, [new]);
    drop(conn);
    db.drop([pool]).await;
}

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
    .expect("the deleter never waited for the updater");
}

/// The delete guard judges the row as committed when the delete gets its
/// lock (READ COMMITTED): a delete that waited for a concurrent re-enable
/// fails, and one that waited for a concurrent disable succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn binding_delete_guard_sees_a_concurrent_status_change() {
    let (db, pool) = seeded().await;
    let mut updater = pool.acquire().await.unwrap().detach();
    let mut deleter = pool.acquire().await.unwrap().detach();
    let (updater_pid, deleter_pid) = (
        backend_pid(&mut updater).await,
        backend_pid(&mut deleter).await,
    );
    for (status, binding, deleted) in [("enabled", "bnd_2", false), ("disabled", "bnd_4", true)] {
        run(
            &mut updater,
            &format!(
                "BEGIN; UPDATE principal_binding SET status = '{status}', revision = revision + 1
                 WHERE id = '{binding}'"
            ),
        )
        .await;
        let sql = format!("DELETE FROM principal_binding WHERE id = '{binding}'");
        let waiting = tokio::spawn(async move {
            let result = sqlx::raw_sql(AssertSqlSafe(sql))
                .execute(&mut deleter)
                .await;
            (deleter, result.map(|done| done.rows_affected()))
        });
        wait_until_blocked(&pool, deleter_pid, updater_pid).await;
        run(&mut updater, "COMMIT").await;
        let (returned, result) = waiting.await.unwrap();
        deleter = returned;
        if deleted {
            assert_eq!(result.unwrap(), 1, "{binding}");
        } else {
            let err = result.unwrap_err();
            assert_eq!(sqlstate(&err), "SK001", "{binding}: {err}");
        }
    }
    assert_eq!(
        ids(&mut updater, "SELECT id FROM principal_binding").await,
        ["bnd_1", "bnd_2", "bnd_3"]
    );
    updater.close().await.unwrap();
    deleter.close().await.unwrap();
    db.drop([pool]).await;
}

/// The guards compare with the built-in operators: a login role that puts
/// its own `=` on text and `<` on timestamptz ahead of `pg_catalog` can
/// neither delete an enabled binding nor prune a proof early.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn delete_guards_ignore_operators_on_the_callers_search_path() {
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    run(
        &pool,
        &format!(
            "CREATE SCHEMA evil;
             GRANT USAGE, CREATE ON SCHEMA evil TO {role};
             GRANT SELECT, DELETE ON principal_binding, consumed_assertion TO {role}"
        ),
    )
    .await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    run(
        &mut writer,
        "CREATE FUNCTION evil.yes(text, text) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.= (LEFTARG = text, RIGHTARG = text, FUNCTION = evil.yes);
         CREATE FUNCTION evil.yes(timestamptz, timestamptz) RETURNS boolean LANGUAGE sql AS 'SELECT true';
         CREATE OPERATOR evil.< (LEFTARG = timestamptz, RIGHTARG = timestamptz, FUNCTION = evil.yes);
         SET search_path = evil, pg_catalog, public",
    )
    .await;
    // The shadow is in effect for the caller's own expressions.
    let shadowed: bool =
        sqlx::query_scalar("SELECT 'a'::text = 'b'::text AND now() < now() - interval '1 day'")
            .fetch_one(&mut writer)
            .await
            .unwrap();
    assert!(shadowed);
    rejected(
        &mut writer,
        "DELETE FROM principal_binding",
        "SK001",
        Some("only a disabled row of principal_binding may be deleted"),
    )
    .await;
    rejected(
        &mut writer,
        "DELETE FROM consumed_assertion",
        "SK001",
        Some("a row of consumed_assertion cannot be deleted before its retain_until"),
    )
    .await;
    writer.close().await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(count(&mut conn, "principal_binding").await, 4);
    assert_eq!(count(&mut conn, "consumed_assertion").await, 2);
    drop(conn);
    db.drop([pool]).await;
}
