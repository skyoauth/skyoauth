//! The `0009_reserved_ids_and_dormant_grants` migration against a real
//! PostgreSQL server: `admin_identity` refuses the actor IDs the registry
//! reserves (`deployment_operator` and every ID beginning with
//! `recovery_key:`), byte-wise as `is_reserved_actor_id`, and an
//! impersonation grant is frozen once the transaction that creates it
//! commits: no `UPDATE` of the grant row, and no `INSERT`, `UPDATE` or
//! `DELETE` of its binding and audience rows, while the creating
//! transaction, savepoints included, still builds them. Other grants are
//! unaffected.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. The tests that disable a guard
//! inside a rolled-back transaction need the table owner.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use common::TestDb;
use skyoauth_service::persistence::{
    self, MIGRATOR, MigrateError, PgPool,
    registry::{
        self, ActivationState, GrantMode, InvariantKind, NewServiceGrant, RegistryError,
        ServiceGrantChanges, Status, is_reserved_actor_id,
    },
};
use sqlx::{AssertSqlSafe, Executor, PgConnection, Postgres};

/// A tenant with a workload actor and its two bindings, a service with an
/// audience, and three grants created and committed before any test
/// statement: `grt_d` (direct), `grt_g` (delegation) and `grt_i`, the
/// dormant impersonation grant, each with binding `bnd_1` and audience
/// `rs_1`.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled');
    INSERT INTO principal VALUES
        ('wld_1', 'ten_a', 'workload', 'w1', 'enabled'),
        ('svc_1', 'ten_a', 'service', 's1', 'enabled');
    INSERT INTO resource_server VALUES ('rs_1', 'api-1', 'API 1', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO resource_server VALUES ('rs_2', 'api-2', 'API 2', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled'),
        ('ata_2', 'rs_2', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO trust_source VALUES
        ('src_gh', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_1', 'ten_a', 'one', 'src_gh', 'generic_production', '{"sub": "repo:1"}', 'wld_1', 'enabled'),
        ('bnd_2', 'ten_a', 'two', 'src_gh', 'generic_production', '{"sub": "repo:2"}', 'wld_1', 'enabled');
    INSERT INTO service_identity VALUES ('svc_1', 'ten_a', 'deployer', '["read"]', '{}', 'enabled');
    INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', 'rs_1'), ('svc_1', 'ten_a', 'rs_2');
    INSERT INTO service_grant VALUES
        ('grt_d', 'ten_a', 'direct', 'wld_1', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_g', 'ten_a', 'delegated', 'wld_1', 'svc_1', 'delegation', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_i', 'ten_a', 'dormant', 'wld_1', 'svc_1', 'impersonation', '["read"]', NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval');
    INSERT INTO service_grant_binding VALUES
        ('grt_d', 'bnd_1', 'ten_a', 'wld_1'), ('grt_g', 'bnd_1', 'ten_a', 'wld_1'), ('grt_i', 'bnd_1', 'ten_a', 'wld_1');
    INSERT INTO service_grant_resource_server VALUES
        ('grt_d', 'ten_a', 'rs_1'), ('grt_g', 'ten_a', 'rs_1'), ('grt_i', 'ten_a', 'rs_1')"#;

/// The message of the grant-row guard.
const FROZEN_GRANT: &str = "an impersonation grant of service_grant is never updated";

/// The two list tables of a grant.
const LISTS: [&str; 2] = ["service_grant_binding", "service_grant_resource_server"];

/// The message of the list-row guard on `table`.
fn frozen_rows(table: &str) -> String {
    format!(
        "the rows of {table} of an impersonation grant change only in the transaction that \
         creates it"
    )
}

/// The statements that create the impersonation grant `id` with binding
/// `bnd_1` and audience `rs_1`, without a transaction of their own.
fn create_impersonation(id: &str) -> String {
    format!(
        "INSERT INTO service_grant VALUES ('{id}', 'ten_a', '{id}', 'wld_1', 'svc_1', 'impersonation',
             '[\"read\"]', NULL, '{{}}', 300, NULL, 'disabled', 'requires_reapproval');
         INSERT INTO service_grant_binding VALUES ('{id}', 'bnd_1', 'ten_a', 'wld_1');
         INSERT INTO service_grant_resource_server VALUES ('{id}', 'ten_a', 'rs_1');"
    )
}

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
/// given, `message`. Rolls back a transaction that `sql` opened.
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
    if sql.trim_start().starts_with("BEGIN") {
        run(&mut *conn, "ROLLBACK").await;
    }
}

/// Every grant with its revision and its sorted list rows, as a snapshot a
/// refused write must leave unchanged.
async fn grants(conn: &mut PgConnection) -> Vec<(String, i64, String, String)> {
    sqlx::query_as(
        "SELECT g.id, g.revision,
                coalesce((SELECT string_agg(b.binding_id, ',' ORDER BY b.binding_id)
                          FROM service_grant_binding b WHERE b.grant_id = g.id), ''),
                coalesce((SELECT string_agg(r.resource_server_id, ',' ORDER BY r.resource_server_id)
                          FROM service_grant_resource_server r WHERE r.grant_id = g.id), '')
         FROM service_grant g ORDER BY g.id",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn reserved_ids_and_dormant_grants_migration_is_recorded_once() {
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
        first.contains(&(9, "reserved ids and dormant grants".into(), true)),
        "{first:?}"
    );
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    db.drop([pool]).await;
}

/// Catalog properties that behaviour tests cannot see directly: the check's
/// exact expression, the three triggers (timing, events, `ENABLE ALWAYS`,
/// function), the pinned paths of the two functions, the schema-qualified
/// table in the one that reads a table, and that the foreign-key check of
/// a list row fires before the list guard.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn catalog_pins_the_check_the_triggers_and_their_functions() {
    let (db, pool) = seeded().await;
    let check: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid = 'admin_identity'::regclass
           AND conname = 'admin_identity_id_not_reserved_check'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        check,
        "CHECK (((id <> 'deployment_operator'::text) AND \
         (NOT starts_with(id, 'recovery_key:'::text))))"
    );

    // tgtype bits: 1 row, 2 before, 4 insert, 8 delete, 16 update.
    let mut triggers: Vec<(String, String, String, i16, String)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, p.proname::text, t.tgtype, t.tgenabled::text
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND t.tgname LIKE '%impersonation_frozen'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    triggers.sort();
    let list = "skyoauth_reject_impersonation_grant_list_change";
    let trigger = |table: &str, function: &str, tgtype: i16| {
        (
            table.to_string(),
            format!("{table}_impersonation_frozen"),
            function.to_string(),
            tgtype,
            "A".to_string(),
        )
    };
    assert_eq!(
        triggers,
        [
            trigger(
                "service_grant",
                "skyoauth_reject_impersonation_grant_update",
                1 | 2 | 16
            ),
            trigger("service_grant_binding", list, 1 | 4 | 8 | 16),
            trigger("service_grant_resource_server", list, 1 | 4 | 8 | 16),
        ]
    );

    let mut functions: Vec<(String, Vec<String>, String)> = sqlx::query_as(
        "SELECT p.proname::text, p.proconfig, p.prosrc FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname IN ('skyoauth_reject_impersonation_grant_update',
                             'skyoauth_reject_impersonation_grant_list_change')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    functions.sort();
    let [
        (list_name, list_config, list_source),
        (update_name, update_config, update_source),
    ] = &functions[..]
    else {
        panic!("{functions:?}");
    };
    assert_eq!(list_name, list);
    assert_eq!(list_config, &["search_path=pg_catalog, public, pg_temp"]);
    assert!(
        list_source.contains(" public.service_grant ") && !list_source.contains(" service_grant "),
        "{list_source}"
    );
    assert_eq!(update_name, "skyoauth_reject_impersonation_grant_update");
    assert_eq!(update_config, &["search_path=pg_catalog, pg_temp"]);
    assert!(!update_source.contains("public."), "{update_source}");

    // PostgreSQL fires the AFTER row triggers of an event in name order:
    // the internal foreign-key checks of the inserted row come first.
    for table in LISTS {
        let order: Vec<(String, bool)> = sqlx::query_as(
            "SELECT t.tgname::text, t.tgisinternal FROM pg_trigger t
             WHERE t.tgrelid = to_regclass($1) AND t.tgtype & 2 = 0 AND t.tgtype & 4 <> 0
             ORDER BY t.tgname",
        )
        .bind(table)
        .fetch_all(&pool)
        .await
        .unwrap();
        let guard = order
            .iter()
            .position(|(name, _)| name.ends_with("_impersonation_frozen"))
            .unwrap();
        assert_eq!(guard, order.len() - 1, "{table}: {order:?}");
        assert!(
            order[..guard].len() == 2
                && order[..guard].iter().all(
                    |(name, internal)| *internal && name.starts_with("RI_ConstraintTrigger_c_")
                ),
            "{table}: {order:?}"
        );
    }
    db.drop([pool]).await;
}

/// The check holds exactly the registry's rule, `is_reserved_actor_id`:
/// `deployment_operator`, and every ID beginning with `recovery_key:`, the
/// empty epoch included, byte-wise. A raw insert of a reserved ID fails
/// with `23514`, which the registry maps to `Invariant { Check, name }`;
/// look-alikes, in which `_` stays a literal character, are other IDs.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn admin_identity_refuses_the_reserved_actor_ids_byte_wise() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let reserved = [
        "deployment_operator",
        "recovery_key:",
        "recovery_key:1",
        "recovery_key:18446744073709551615",
        "recovery_key:x",
        "recovery_key::",
        "recovery_key: ",
        "recovery_key:%",
    ];
    let other = [
        "Deployment_Operator",
        "DEPLOYMENT_OPERATOR",
        "deployment_operator ",
        " deployment_operator",
        "deployment_operator2",
        "deployment-operator",
        "deploymentXoperator",
        "recovery_key",
        "Recovery_Key:1",
        "RECOVERY_KEY:1",
        "recovery-key:1",
        "recoveryXkey:1",
        "recovery%key:1",
        " recovery_key:1",
        "adm_recovery_key:1",
        "recovery_key\u{ff1a}1",
    ];
    for id in reserved {
        assert!(is_reserved_actor_id(id), "{id}");
        let err = sqlx::query("INSERT INTO admin_identity (id, status) VALUES ($1, 'enabled')")
            .bind(id)
            .execute(&mut *conn)
            .await
            .expect_err(id);
        assert_eq!(sqlstate(&err), "23514", "{id}: {err}");
        let mapped = RegistryError::from(err);
        assert!(
            matches!(
                mapped,
                RegistryError::Invariant {
                    kind: InvariantKind::Check,
                    constraint: Some("admin_identity_id_not_reserved_check"),
                }
            ),
            "{id}: {mapped:?}"
        );
    }
    for id in other {
        assert!(!is_reserved_actor_id(id), "{id}");
        sqlx::query("INSERT INTO admin_identity (id, status) VALUES ($1, 'enabled')")
            .bind(id)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|err| panic!("{id}: {err}"));
    }
    let mut stored: Vec<String> = sqlx::query_scalar("SELECT id FROM admin_identity")
        .fetch_all(&mut *conn)
        .await
        .unwrap();
    stored.sort();
    let mut want: Vec<String> = other.iter().map(|id| id.to_string()).collect();
    want.sort();
    assert_eq!(stored, want);
    drop(conn);
    db.drop([pool]).await;
}

/// The upgrade precondition query of the migrations README ("What 0009
/// adds"), the fenced block after "Upgrade precondition".
fn precondition_sql() -> String {
    let readme = include_str!("../migrations/README.md");
    let section = &readme[readme.find("## What 0009 adds").unwrap()..];
    let section = &section[section
        .find("- **Upgrade precondition.**")
        .expect("the 0009 section has the upgrade precondition")..];
    let start = section.find("```sql\n").unwrap() + "```sql\n".len();
    let end = start + section[start..].find("  ```").unwrap();
    section[start..end]
        .lines()
        .map(|line| line.strip_prefix("  ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// On a `0008` database the README query lists the operator identities
/// `0009` would reject; with one, `0009` fails with `23514` and leaves the
/// database at `0008`; after the owner-level repair the README describes,
/// the query lists none and `0009` applies.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn upgrade_precondition_lists_the_reserved_operator_ids() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    MIGRATOR.run_to(8, &pool).await.unwrap();
    run(
        &pool,
        "INSERT INTO admin_identity (id, status) VALUES
             ('adm_1', 'enabled'), ('deployment_operator', 'enabled'),
             ('recovery_key:1', 'disabled'), ('recovery_key', 'enabled');
         INSERT INTO admin_credential VALUES
             ('crd_1', 'recovery_key:1', 'sha256:c1', 'ops-ca', 'disabled', '2026-11-20Z');
         INSERT INTO admin_role_binding VALUES
             ('rb_1', 'deployment_operator', 'security_admin', NULL, 'enabled')",
    )
    .await;
    let precondition = || async {
        sqlx::query_as::<_, (String, String)>(AssertSqlSafe(precondition_sql()))
            .fetch_all(&pool)
            .await
            .unwrap()
    };
    assert_eq!(
        precondition().await,
        [
            ("deployment_operator".to_string(), "enabled".to_string()),
            ("recovery_key:1".to_string(), "disabled".to_string()),
        ]
    );
    let err = persistence::migrate(&pool).await.unwrap_err();
    let cause = match &err {
        MigrateError::Execute(cause) | MigrateError::ExecuteMigration(cause, _) => cause,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        cause.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514"),
        "{err}"
    );
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 8);

    // The owner-level repair of the README: in one transaction, remove each
    // listed identity with its credentials and role bindings, with the
    // guards of the three tables disabled, then re-enable every guard as
    // ALWAYS.
    let mut tx = pool.begin().await.unwrap();
    run(
        &mut *tx,
        "ALTER TABLE admin_identity DISABLE TRIGGER USER;
         ALTER TABLE admin_credential DISABLE TRIGGER USER;
         ALTER TABLE admin_role_binding DISABLE TRIGGER USER;
         DELETE FROM admin_credential WHERE admin_id IN ('deployment_operator', 'recovery_key:1');
         DELETE FROM admin_role_binding WHERE admin_id IN ('deployment_operator', 'recovery_key:1');
         DELETE FROM admin_identity WHERE id IN ('deployment_operator', 'recovery_key:1')",
    )
    .await;
    let triggers: Vec<(String, String)> = sqlx::query_as(
        "SELECT tgrelid::regclass::text, tgname::text FROM pg_trigger
         WHERE NOT tgisinternal
           AND tgrelid IN ('admin_identity'::regclass, 'admin_credential'::regclass,
                           'admin_role_binding'::regclass)",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    for (table, trigger) in triggers {
        run(
            &mut *tx,
            &format!("ALTER TABLE {table} ENABLE ALWAYS TRIGGER {trigger}"),
        )
        .await;
    }
    tx.commit().await.unwrap();
    assert_eq!(precondition().await, []);

    persistence::migrate(&pool).await.unwrap();
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 9);
    let not_always: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled <> 'A'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(not_always, 0);
    assert_eq!(precondition().await, []);
    db.drop([pool]).await;
}

/// An impersonation grant is created with its list rows in one
/// transaction, whether the rows come after the grant at the top level,
/// inside savepoints (the grant inserted inside one, then released, has a
/// subtransaction ID as its `xmin`), or in one statement, as the registry
/// writes them; the creating transaction may also delete and re-add its
/// rows. A grant from a rolled-back savepoint is gone, and the same ID can
/// be created again in that transaction.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_impersonation_grant_is_built_in_its_creating_transaction() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    // At the top level, then a second binding added and removed again.
    run(
        &mut *conn,
        &format!(
            "BEGIN; {}
             INSERT INTO service_grant_binding VALUES ('grt_top', 'bnd_2', 'ten_a', 'wld_1');
             INSERT INTO service_grant_resource_server VALUES ('grt_top', 'ten_a', 'rs_2');
             DELETE FROM service_grant_binding WHERE grant_id = 'grt_top' AND binding_id = 'bnd_1';
             DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_top' AND resource_server_id = 'rs_1';
             UPDATE service_grant_binding SET binding_id = binding_id WHERE grant_id = 'grt_top';
             COMMIT",
            create_impersonation("grt_top")
        ),
    )
    .await;
    // The grant inside a released savepoint, the rows inside nested ones.
    run(
        &mut *conn,
        "BEGIN;
         SAVEPOINT a;
         INSERT INTO service_grant VALUES ('grt_sub', 'ten_a', 'grt_sub', 'wld_1', 'svc_1', 'impersonation',
             '[\"read\"]', NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval');
         RELEASE a;
         SAVEPOINT b;
         SAVEPOINT c;
         INSERT INTO service_grant_binding VALUES ('grt_sub', 'bnd_1', 'ten_a', 'wld_1');
         RELEASE c;
         INSERT INTO service_grant_resource_server VALUES ('grt_sub', 'ten_a', 'rs_1');
         RELEASE b;
         INSERT INTO service_grant_binding VALUES ('grt_sub', 'bnd_2', 'ten_a', 'wld_1');
         COMMIT",
    )
    .await;
    // The grant and its rows inside one savepoint that stays open until
    // commit.
    run(
        &mut *conn,
        &format!(
            "BEGIN; SELECT pg_current_xact_id(); SAVEPOINT a; {} COMMIT",
            create_impersonation("grt_open")
        ),
    )
    .await;
    // A grant from a rolled-back savepoint is gone: its rows have nothing
    // to reference. The same ID is then created for good.
    run(
        &mut *conn,
        &format!(
            "BEGIN; SAVEPOINT a; {} ROLLBACK TO SAVEPOINT a; {} COMMIT",
            create_impersonation("grt_again"),
            create_impersonation("grt_again")
        ),
    )
    .await;
    rejected(
        &mut conn,
        &format!(
            "BEGIN; SAVEPOINT a; {} ROLLBACK TO SAVEPOINT a;
             INSERT INTO service_grant_binding VALUES ('grt_gone', 'bnd_1', 'ten_a', 'wld_1')",
            create_impersonation("grt_gone")
        ),
        "23503",
        None,
    )
    .await;
    // One statement, as create_service_grant writes it.
    run(
        &mut *conn,
        "WITH created AS (
             INSERT INTO service_grant VALUES ('grt_cte', 'ten_a', 'grt_cte', 'wld_1', 'svc_1', 'impersonation',
                 '[\"read\"]', NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval')
             RETURNING tenant_id, id, actor_principal_id),
         bound AS (INSERT INTO service_grant_binding SELECT id, 'bnd_1', tenant_id, actor_principal_id FROM created)
         INSERT INTO service_grant_resource_server SELECT id, tenant_id, 'rs_1' FROM created",
    )
    .await;
    let created: Vec<_> = grants(&mut conn)
        .await
        .into_iter()
        .filter(|(id, ..)| !["grt_d", "grt_g", "grt_i"].contains(&id.as_str()))
        .collect();
    let row = |id: &str, bindings: &str, audiences: &str| {
        (
            id.to_string(),
            1,
            bindings.to_string(),
            audiences.to_string(),
        )
    };
    assert_eq!(
        created,
        [
            row("grt_again", "bnd_1", "rs_1"),
            row("grt_cte", "bnd_1", "rs_1"),
            row("grt_open", "bnd_1", "rs_1"),
            row("grt_sub", "bnd_1,bnd_2", "rs_1"),
            row("grt_top", "bnd_2", "rs_2"),
        ]
    );
    // Once committed, each is frozen.
    for id in ["grt_top", "grt_sub", "grt_open", "grt_again", "grt_cte"] {
        let message = frozen_rows("service_grant_binding");
        rejected(
            &mut conn,
            &format!("DELETE FROM service_grant_binding WHERE grant_id = '{id}'"),
            "SK001",
            Some(&message),
        )
        .await;
    }
    drop(conn);
    db.drop([pool]).await;
}

/// After its creating transaction, no `UPDATE` of an impersonation grant
/// passes: of any column, to its own value or to another, with or without
/// the revision step, and the enabling and reapproval writes the `0004`
/// checks used to refuse are now refused by the guard first.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_impersonation_grant_row_never_changes() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let before = grants(&mut conn).await;
    let columns = [
        "id",
        "tenant_id",
        "name",
        "actor_principal_id",
        "target_service_id",
        "mode",
        "scopes",
        "default_scopes",
        "resource_constraints",
        "max_ttl",
        "valid_until",
        "status",
        "activation_state",
        "actor_principal_kind",
    ];
    for column in columns {
        for step in [", revision = revision + 1", ""] {
            rejected(
                &mut conn,
                &format!("UPDATE service_grant SET {column} = {column}{step} WHERE id = 'grt_i'"),
                "SK001",
                Some(FROZEN_GRANT),
            )
            .await;
        }
    }
    for set in [
        "revision = revision + 1",
        "revision = revision",
        "name = 'renamed', revision = revision + 1",
        r#"scopes = '["read", "deploy"]', revision = revision + 1"#,
        "valid_until = '2030-01-01Z', revision = revision + 1",
        "status = 'enabled', revision = revision + 1",
        "activation_state = 'not_required', revision = revision + 1",
        "status = 'enabled', activation_state = 'not_required', revision = revision + 1",
        "status = 'disabled', activation_state = 'requires_reapproval', revision = revision + 1",
    ] {
        rejected(
            &mut conn,
            &format!("UPDATE service_grant SET {set} WHERE id = 'grt_i'"),
            "SK001",
            Some(FROZEN_GRANT),
        )
        .await;
    }
    // A statement that reaches the grant among others is refused whole.
    rejected(
        &mut conn,
        "UPDATE service_grant SET revision = revision + 1",
        "SK001",
        Some(FROZEN_GRANT),
    )
    .await;
    // Also in the transaction that creates the grant.
    rejected(
        &mut conn,
        &format!(
            "BEGIN; {} UPDATE service_grant SET name = 'renamed', revision = revision + 1 WHERE id = 'grt_new'",
            create_impersonation("grt_new")
        ),
        "SK001",
        Some(FROZEN_GRANT),
    )
    .await;
    assert_eq!(grants(&mut conn).await, before);
    drop(conn);
    db.drop([pool]).await;
}

/// No grant becomes, or stops being, an impersonation grant. `mode` is
/// immutable since `0004`, whose trigger fires first; with it disabled for
/// the transaction, the `0009` guard alone still refuses both directions.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn no_grant_changes_into_or_out_of_impersonation() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let before = grants(&mut conn).await;
    let into = [
        "UPDATE service_grant SET mode = 'impersonation', status = 'disabled',
             activation_state = 'requires_reapproval', revision = revision + 1 WHERE id = 'grt_g'",
        "UPDATE service_grant SET mode = 'impersonation', target_service_id = 'svc_1', status = 'disabled',
             activation_state = 'requires_reapproval', revision = revision + 1 WHERE id = 'grt_d'",
    ];
    let out_of = "UPDATE service_grant SET mode = 'delegation', status = 'disabled',
             activation_state = 'not_required', revision = revision + 1 WHERE id = 'grt_i'";
    for sql in into.iter().chain([&out_of]) {
        // The 0004 immutable-column guard, first by name.
        rejected(&mut conn, sql, "SK001", None).await;
        rejected(
            &mut conn,
            &format!(
                "BEGIN; ALTER TABLE service_grant DISABLE TRIGGER service_grant_immutable; {sql}"
            ),
            "SK001",
            Some(FROZEN_GRANT),
        )
        .await;
    }
    assert_eq!(grants(&mut conn).await, before);
    drop(conn);
    db.drop([pool]).await;
}

/// After its creating transaction, no list row of an impersonation grant is
/// added, changed or removed, in either list, also once the grant row is
/// frozen by `VACUUM`; a statement that also reaches other grants' rows is
/// refused whole.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_impersonation_grants_list_rows_never_change() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let before = grants(&mut conn).await;
    for vacuum in [false, true] {
        if vacuum {
            run(&mut *conn, "VACUUM (FREEZE) service_grant").await;
        }
        for (table, sql) in [
            (
                "service_grant_binding",
                "INSERT INTO service_grant_binding VALUES ('grt_i', 'bnd_2', 'ten_a', 'wld_1')",
            ),
            (
                "service_grant_binding",
                "DELETE FROM service_grant_binding WHERE grant_id = 'grt_i'",
            ),
            (
                "service_grant_binding",
                "UPDATE service_grant_binding SET binding_id = binding_id WHERE grant_id = 'grt_i'",
            ),
            (
                "service_grant_binding",
                "BEGIN; INSERT INTO service_grant_binding VALUES ('grt_i', 'bnd_2', 'ten_a', 'wld_1');
                 DELETE FROM service_grant_binding WHERE grant_id = 'grt_i' AND binding_id = 'bnd_1'",
            ),
            ("service_grant_binding", "DELETE FROM service_grant_binding"),
            (
                "service_grant_resource_server",
                "INSERT INTO service_grant_resource_server VALUES ('grt_i', 'ten_a', 'rs_2')",
            ),
            (
                "service_grant_resource_server",
                "DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_i'",
            ),
            (
                "service_grant_resource_server",
                "UPDATE service_grant_resource_server SET resource_server_id = resource_server_id",
            ),
            (
                "service_grant_resource_server",
                "BEGIN; SAVEPOINT a; DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_i'",
            ),
            // A row moved off the frozen grant (its OLD grant) or onto it
            // (its NEW grant) by an UPDATE of grant_id, with the 0004
            // immutable-column guard of the list table disabled, as the day
            // it is dropped.
            (
                "service_grant_binding",
                "BEGIN; ALTER TABLE service_grant_binding DISABLE TRIGGER service_grant_binding_immutable;
                 UPDATE service_grant_binding SET grant_id = 'grt_d', binding_id = 'bnd_2'
                  WHERE grant_id = 'grt_i'",
            ),
            (
                "service_grant_binding",
                "BEGIN; ALTER TABLE service_grant_binding DISABLE TRIGGER service_grant_binding_immutable;
                 UPDATE service_grant_binding SET grant_id = 'grt_i', binding_id = 'bnd_2'
                  WHERE grant_id = 'grt_d'",
            ),
            (
                "service_grant_resource_server",
                "BEGIN; ALTER TABLE service_grant_resource_server
                          DISABLE TRIGGER service_grant_resource_server_immutable;
                 UPDATE service_grant_resource_server
                    SET grant_id = 'grt_d', resource_server_id = 'rs_2' WHERE grant_id = 'grt_i'",
            ),
            (
                "service_grant_resource_server",
                "BEGIN; ALTER TABLE service_grant_resource_server
                          DISABLE TRIGGER service_grant_resource_server_immutable;
                 UPDATE service_grant_resource_server
                    SET grant_id = 'grt_i', resource_server_id = 'rs_2' WHERE grant_id = 'grt_d'",
            ),
        ] {
            rejected(&mut conn, sql, "SK001", Some(&frozen_rows(table))).await;
        }
    }
    // A constraint error of the row still comes first.
    rejected(
        &mut conn,
        "INSERT INTO service_grant_binding VALUES ('grt_i', 'bnd_1', 'ten_a', 'wld_1')",
        "23505",
        None,
    )
    .await;
    assert_eq!(grants(&mut conn).await, before);
    drop(conn);
    db.drop([pool]).await;
}

/// A grant that another transaction created and committed after the
/// current one took its transaction ID has a newer `xmin` than the current
/// top-level ID, yet is not the current transaction's: its list rows are
/// refused (`READ COMMITTED`, where the later commit is visible).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_grant_committed_by_a_later_transaction_is_not_the_current_ones() {
    let (db, pool) = seeded().await;
    let mut writer = pool.acquire().await.unwrap();
    let mut other = pool.acquire().await.unwrap();
    for table in LISTS {
        let id = format!("grt_late_{table}");
        run(&mut *writer, "BEGIN; SELECT pg_current_xact_id()").await;
        run(&mut *other, &create_impersonation(&id)).await;
        let sql = if table == "service_grant_binding" {
            format!("INSERT INTO service_grant_binding VALUES ('{id}', 'bnd_2', 'ten_a', 'wld_1')")
        } else {
            format!("INSERT INTO service_grant_resource_server VALUES ('{id}', 'ten_a', 'rs_2')")
        };
        rejected(&mut writer, &sql, "SK001", Some(&frozen_rows(table))).await;
        run(&mut *writer, "ROLLBACK").await;
    }
    drop(writer);
    drop(other);
    db.drop([pool]).await;
}

/// Direct and delegation grants keep every write they had: updates, and
/// list rows added and removed after their creation. The `0006` delete
/// guard is unchanged: an impersonation grant is never deleted, also in its
/// creating transaction once its rows are gone, and a disabled delegation
/// grant goes after its rows.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn other_grants_are_unaffected_and_impersonation_grants_stay_undeletable() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    run(
        &mut *conn,
        "UPDATE service_grant SET name = 'renamed', revision = revision + 1 WHERE id = 'grt_d';
         UPDATE service_grant SET status = 'disabled', revision = revision + 1 WHERE id = 'grt_g';
         INSERT INTO service_grant_binding VALUES ('grt_d', 'bnd_2', 'ten_a', 'wld_1'), ('grt_g', 'bnd_2', 'ten_a', 'wld_1');
         DELETE FROM service_grant_binding WHERE binding_id = 'bnd_1' AND grant_id IN ('grt_d', 'grt_g');
         INSERT INTO service_grant_resource_server VALUES ('grt_d', 'ten_a', 'rs_2'), ('grt_g', 'ten_a', 'rs_2');
         DELETE FROM service_grant_resource_server WHERE resource_server_id = 'rs_1' AND grant_id IN ('grt_d', 'grt_g');
         UPDATE service_grant_binding SET binding_id = binding_id WHERE grant_id = 'grt_d'",
    )
    .await;
    let row = |id: &str, revision: i64, bindings: &str, audiences: &str| {
        (
            id.to_string(),
            revision,
            bindings.to_string(),
            audiences.to_string(),
        )
    };
    assert_eq!(
        grants(&mut conn).await,
        [
            row("grt_d", 2, "bnd_2", "rs_2"),
            row("grt_g", 2, "bnd_2", "rs_2"),
            row("grt_i", 1, "bnd_1", "rs_1"),
        ]
    );
    let never = Some("an impersonation grant of service_grant is never deleted");
    rejected(
        &mut conn,
        "DELETE FROM service_grant WHERE id = 'grt_i'",
        "SK001",
        never,
    )
    .await;
    rejected(
        &mut conn,
        &format!(
            "BEGIN; {}
             DELETE FROM service_grant_binding WHERE grant_id = 'grt_new';
             DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_new';
             DELETE FROM service_grant WHERE id = 'grt_new'",
            create_impersonation("grt_new")
        ),
        "SK001",
        never,
    )
    .await;
    run(
        &mut *conn,
        "DELETE FROM service_grant_binding WHERE grant_id = 'grt_g';
         DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_g';
         DELETE FROM service_grant WHERE id = 'grt_g'",
    )
    .await;
    assert_eq!(
        grants(&mut conn).await,
        [
            row("grt_d", 2, "bnd_2", "rs_2"),
            row("grt_i", 1, "bnd_1", "rs_1"),
        ]
    );
    drop(conn);
    db.drop([pool]).await;
}

/// Through the registry: a dormant grant is created as before; its update
/// and every list change map to `RegistryError::Guard` and change nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_writes_to_a_dormant_grant_are_guard_errors() {
    let (db, pool) = seeded().await;
    let new = NewServiceGrant {
        id: "grt_reg".into(),
        tenant_id: "ten_a".into(),
        name: "registry".into(),
        actor_principal_id: "wld_1".into(),
        target_service_id: Some("svc_1".into()),
        mode: GrantMode::Impersonation,
        scopes: vec!["read".into()],
        default_scopes: None,
        resource_constraints: Default::default(),
        max_ttl: 300,
        valid_until: None,
        status: Status::Disabled,
        activation_state: ActivationState::RequiresReapproval,
        allowed_binding_ids: vec!["bnd_1".into(), "bnd_2".into()],
        resource_server_ids: vec!["rs_1".into()],
    };
    let created = registry::create_service_grant(&pool, &new).await.unwrap();
    assert_eq!(created.revision, 1);
    assert_eq!(created.allowed_binding_ids, ["bnd_1", "bnd_2"]);
    let changes = ServiceGrantChanges {
        name: "renamed".into(),
        scopes: created.scopes.clone(),
        default_scopes: created.default_scopes.clone(),
        resource_constraints: created.resource_constraints.clone(),
        max_ttl: created.max_ttl,
        valid_until: created.valid_until,
        status: created.status,
        activation_state: created.activation_state,
    };
    let guard = |result: Result<(), RegistryError>| {
        let err = result.expect_err("refused");
        assert!(matches!(err, RegistryError::Guard), "{err:?}");
    };
    guard(
        registry::update_service_grant(&pool, "ten_a", "grt_reg", 1, &changes)
            .await
            .map(|_| ()),
    );
    guard(
        registry::remove_service_grant_binding(&pool, "ten_a", "grt_reg", 1, "bnd_2")
            .await
            .map(|_| ()),
    );
    guard(
        registry::add_service_grant_resource_server(&pool, "ten_a", "grt_reg", 1, "rs_2")
            .await
            .map(|_| ()),
    );
    guard(
        registry::remove_service_grant_resource_server(&pool, "ten_a", "grt_reg", 1, "rs_1")
            .await
            .map(|_| ()),
    );
    assert_eq!(
        registry::get_service_grant(&pool, "ten_a", "grt_reg")
            .await
            .unwrap(),
        created
    );
    db.drop([pool]).await;
}
