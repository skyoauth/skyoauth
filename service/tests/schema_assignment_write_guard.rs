//! The `0010_assignment_write_guard` migration against a real PostgreSQL
//! server: a new audience row of a service identity
//! (`service_identity_resource_server`) or a grant
//! (`service_grant_resource_server`) whose audience tenant assignment exists
//! but is disabled is refused with `23514`, naming the guard trigger, which
//! the registry maps to `Invariant { kind: AssignmentActive, .. }`; a
//! missing assignment is still the foreign key's `23503`. The guards are
//! `AFTER INSERT` row triggers that fire after the foreign-key check; they
//! lock the assignment `FOR SHARE`, so an insert and a concurrent disable
//! serialize, under `READ COMMITTED` by waiting and under `REPEATABLE READ`
//! and `SERIALIZABLE` with `40001`, and an assignment another transaction
//! creates disabled while the statement runs is refused too. The README
//! lock order (owner row, assignment, audit head) does not deadlock; taking
//! the head before the insert does. The tests also pin the catalog, the
//! tenant of the assignment read, the privileges a writer needs, replica
//! mode, the unique and `ON CONFLICT` cases and statements that also write
//! the assignment ("What 0010 adds").
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. The replica-mode test needs
//! `SET` on `session_replication_role`, and the privilege test needs
//! `CREATEROLE`. They claim no conformance scenario.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{error::Error as _, fmt::Debug, time::Duration};

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, ASSIGNMENT_ACTIVE, ActivationState, AudienceTenantAssignmentChanges, GrantMode,
        InvariantKind, KNOWN_CONSTRAINTS, NewServiceGrant, NewServiceIdentity, Profile,
        RegistryError, Status,
    },
};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Postgres};

/// One tenant with a workload actor, a binding and a service identity
/// (`svc_1`, no audiences) and a direct grant (`grt_1`, audience `rs_1`),
/// and four resource servers: `rs_1` with an enabled assignment (`ata_1`),
/// `rs_2` with a disabled one (`ata_2`), `rs_3` disabled itself behind an
/// enabled assignment (`ata_3`), and `rs_4`, not assigned to the tenant.
/// A second tenant, `ten_b`, with the same kind of owners (`svc_b` and
/// `grt_b`, both without audiences), shares `rs_1` and `rs_2` with
/// `ten_a` under the opposite statuses: `atb_1` (`rs_1`) is disabled and
/// `atb_2` (`rs_2`) enabled, so a guard that ignored the tenant would read
/// the other tenant's assignment.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled');
    INSERT INTO principal VALUES
        ('wld_1', 'ten_a', 'workload', 'w1', 'enabled'),
        ('svc_1', 'ten_a', 'service', 's1', 'enabled'),
        ('svc_2', 'ten_a', 'service', 's2', 'enabled');
    INSERT INTO resource_server VALUES
        ('rs_1', 'api-1', 'API 1', '["wif"]', '["read"]', '[]', 'enabled'),
        ('rs_2', 'api-2', 'API 2', '["wif"]', '["read"]', '[]', 'enabled'),
        ('rs_3', 'api-3', 'API 3', '["wif"]', '["read"]', '[]', 'disabled'),
        ('rs_4', 'api-4', 'API 4', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled'),
        ('ata_2', 'rs_2', 'ten_a', '["wif"]', '["read"]', '[]', 'disabled'),
        ('ata_3', 'rs_3', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled');
    -- Enabled egress entry for the seeded destination (0011 guard).
    INSERT INTO egress_allowlist_entry VALUES
        ('egr_seed_1', 'oidc_discovery', 'https://token.actions.githubusercontent.com/.well-known/openid-configuration', 'enabled');
    INSERT INTO trust_source VALUES
        ('src_gh', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_1', 'ten_a', 'one', 'src_gh', 'generic_production', '{"sub": "repo:1"}', 'wld_1', 'enabled');
    INSERT INTO service_identity VALUES ('svc_1', 'ten_a', 'deployer', '["read"]', '{}', 'enabled');
    INSERT INTO service_grant VALUES
        ('grt_1', 'ten_a', 'direct', 'wld_1', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required');
    INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_1', 'ten_a', 'wld_1');
    INSERT INTO service_grant_resource_server VALUES ('grt_1', 'ten_a', 'rs_1');
    INSERT INTO tenant VALUES ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO principal VALUES
        ('wld_b', 'ten_b', 'workload', 'w1', 'enabled'),
        ('svc_b', 'ten_b', 'service', 's1', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('atb_1', 'rs_1', 'ten_b', '["wif"]', '["read"]', '[]', 'disabled'),
        ('atb_2', 'rs_2', 'ten_b', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO trust_source VALUES
        ('src_b', 'ten_b', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_b', 'ten_b', 'one', 'src_b', 'generic_production', '{"sub": "repo:1"}', 'wld_b', 'enabled');
    INSERT INTO service_identity VALUES ('svc_b', 'ten_b', 'deployer', '["read"]', '{}', 'enabled');
    INSERT INTO service_grant VALUES
        ('grt_b', 'ten_b', 'direct', 'wld_b', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required');
    INSERT INTO service_grant_binding VALUES ('grt_b', 'bnd_b', 'ten_b', 'wld_b')"#;

/// The two guarded tables, the owner column and seeded owner of each, and
/// the name of the guard trigger, which its `23514` names as constraint.
const TABLES: [(&str, &str, &str, &str); 2] = [
    (
        "service_identity_resource_server",
        "service_id",
        "svc_1",
        "service_identity_resource_server_assignment_active",
    ),
    (
        "service_grant_resource_server",
        "grant_id",
        "grt_1",
        "service_grant_resource_server_assignment_active",
    ),
];

/// The guard function both triggers run.
const FUNCTION: &str = "skyoauth_require_active_assignment";

/// The message of the guard on `table`.
fn refusal(table: &str) -> String {
    format!("a row of {table} needs an enabled audience tenant assignment")
}

/// An insert of the audience `resource_server_id` for the seeded owner of
/// `table`.
fn insert(table: &str, resource_server_id: &str) -> String {
    let (_, column, owner, _) = guarded(table);
    format!(
        "INSERT INTO {table} ({column}, tenant_id, resource_server_id) \
         VALUES ('{owner}', 'ten_a', '{resource_server_id}')"
    )
}

fn guarded(table: &str) -> (&'static str, &'static str, &'static str, &'static str) {
    *TABLES
        .iter()
        .find(|(name, ..)| *name == table)
        .unwrap_or_else(|| panic!("{table}"))
}

/// Sets the status of the assignment `id`, as an `UPDATE` must (one
/// revision step).
fn set_status(id: &str, status: &str) -> String {
    format!(
        "UPDATE audience_tenant_assignment SET status = '{status}', revision = revision + 1 \
         WHERE id = '{id}'"
    )
}

/// The registry's change of an assignment that keeps its columns but
/// `status`.
fn assignment_changes(status: Status) -> AudienceTenantAssignmentChanges {
    AudienceTenantAssignmentChanges {
        allowed_profiles: vec![Profile::Wif],
        allowed_scopes: vec!["read".into()],
        constraint_versions: vec![],
        status,
    }
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

/// Checks that `err` is the guard's refusal on `table`: `23514`, its
/// message, the trigger's name as constraint, the table and its schema; and
/// that the registry maps it to `AssignmentActive` with that name.
fn assert_guard_refusal(err: sqlx::Error, table: &str) {
    let (_, _, _, trigger) = guarded(table);
    let database = err
        .as_database_error()
        .unwrap_or_else(|| panic!("not a database error: {err}"));
    assert_eq!(database.code().as_deref(), Some("23514"), "{table}: {err}");
    assert_eq!(database.message(), refusal(table));
    assert_eq!(database.constraint(), Some(trigger));
    assert_eq!(database.table(), Some(table));
    assert_active_refusal(Err::<(), _>(RegistryError::from(err)), table);
}

/// A registry result that is the typed refusal of the guard on `table`.
#[track_caller]
fn assert_active_refusal<T: Debug>(result: Result<T, RegistryError>, table: &str) {
    let (_, _, _, trigger) = guarded(table);
    match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::AssignmentActive,
            constraint: Some(constraint),
        }) => assert_eq!(constraint, trigger),
        other => panic!("expected AssignmentActive {trigger}: {other:?}"),
    }
}

/// A registry result that is the foreign key's refusal of a missing
/// assignment on `table`.
#[track_caller]
fn assert_missing_refusal<T: Debug>(result: Result<T, RegistryError>, table: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::ForeignKey,
            constraint: Some(constraint),
        }) => assert_eq!(constraint, format!("{table}_assignment_fkey")),
        other => panic!("expected the assignment foreign key of {table}: {other:?}"),
    }
}

/// The SQLSTATE of a `Retry` error, from its `source()`.
fn retry_sqlstate(err: &RegistryError) -> String {
    assert!(matches!(err, RegistryError::Retry(_)), "{err:?}");
    err.source()
        .and_then(|source| source.downcast_ref::<sqlx::Error>())
        .and_then(sqlx::Error::as_database_error)
        .and_then(|source| source.code())
        .unwrap_or_else(|| panic!("no SQLSTATE: {err:?}"))
        .into_owned()
}

/// The sorted audiences of the seeded owner of `table`.
async fn audiences(pool: &PgPool, table: &str) -> Vec<String> {
    let (_, column, owner, _) = guarded(table);
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT resource_server_id FROM {table} WHERE {column} = $1 \
         ORDER BY resource_server_id COLLATE \"C\""
    )))
    .bind(owner)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The registry's add of `resource_server_id` to the seeded owner of
/// `table`, from revision `expected`.
async fn add<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    table: &str,
    expected: i64,
    resource_server_id: &str,
) -> Result<i64, RegistryError> {
    if table == "service_identity_resource_server" {
        registry::test_support::add_service_identity_resource_server(
            executor,
            "ten_a",
            "svc_1",
            expected,
            resource_server_id,
        )
        .await
    } else {
        registry::test_support::add_service_grant_resource_server(
            executor,
            "ten_a",
            "grt_1",
            expected,
            resource_server_id,
        )
        .await
    }
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
    .expect("the second writer never waited for the first's lock");
}

/// Runs `sql`, which must not wait for a lock.
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

/// Runs `sql` in a task and returns the connection with the result; an
/// open transaction stays open.
fn spawn_sql(mut conn: PgConnection, sql: String) -> SqlTask {
    tokio::spawn(async move {
        let result = sqlx::raw_sql(AssertSqlSafe(sql))
            .execute(&mut conn)
            .await
            .map(|_| ());
        (conn, result)
    })
}

async fn finished(task: SqlTask) -> (PgConnection, Result<(), sqlx::Error>) {
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("a writer never finished")
        .unwrap()
}

/// Waits until the backend `blocked` waits for a lock held by `holder`
/// (`true`) or `task`, its writer, has finished without waiting (`false`).
async fn waits_or_finishes<T>(
    pool: &PgPool,
    blocked: i32,
    holder: i32,
    task: &tokio::task::JoinHandle<T>,
) -> bool {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                .bind(holder)
                .bind(blocked)
                .fetch_one(pool)
                .await
                .unwrap();
            if waiting {
                return true;
            }
            if task.is_finished() {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the writer neither waited nor finished")
}

/// The audit append of a writer, reduced to its locks: the event's tenant
/// `FOR KEY SHARE`, then the chain head `FOR UPDATE` (README "append audit
/// events in this order").
const APPEND_LOCKS: &str = "SELECT FROM tenant WHERE id = 'ten_a' FOR KEY SHARE; \
                            SELECT FROM audit_chain_head FOR UPDATE";

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn assignment_write_guard_migration_is_recorded_once() {
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
    // Recorded, whatever later migrations follow it (`0011` does).
    assert!(
        first.contains(&(10, "assignment write guard".into(), true)),
        "{first:?}"
    );
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    db.drop([pool]).await;
}

/// Catalog properties that behaviour tests cannot see directly: the two
/// triggers (`AFTER INSERT`, each row, not deferrable, `ENABLE ALWAYS`, the
/// one function), no other user trigger runs that function, the function's
/// pinned `search_path`, `SECURITY INVOKER`, its schema-qualified `FOR
/// SHARE` read, and the trigger names in `KNOWN_CONSTRAINTS` and
/// `ASSIGNMENT_ACTIVE`. PostgreSQL fires the `AFTER INSERT` row triggers
/// of a table in name order, so the firing order is pinned too: the
/// immediate foreign-key checks (`RI_ConstraintTrigger_c_<oid>`, the
/// assignment's among them) sort first, then the guard, then on the grant
/// list the `0009` impersonation guard.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn catalog_pins_the_two_triggers_and_their_function() {
    let (db, pool) = seeded().await;
    // tgtype bits: 1 row, 2 before, 4 insert, 8 delete, 16 update.
    let mut triggers: Vec<(String, String, i16, bool, String)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, t.tgtype, t.tgdeferrable, t.tgenabled::text
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND p.proname = $1
           AND p.pronamespace = to_regnamespace(quote_ident(current_schema()))",
    )
    .bind(FUNCTION)
    .fetch_all(&pool)
    .await
    .unwrap();
    triggers.sort();
    let mut expected: Vec<(String, String, i16, bool, String)> = TABLES
        .iter()
        .map(|(table, _, _, trigger)| {
            (
                table.to_string(),
                trigger.to_string(),
                1 | 4,
                false,
                "A".to_string(),
            )
        })
        .collect();
    expected.sort();
    assert_eq!(triggers, expected);

    // The AFTER INSERT row triggers of each table in firing (name) order:
    // the foreign-key checks, none deferrable, then the guard.
    for (table, _, _, trigger) in TABLES {
        let fired: Vec<(String, bool, bool)> = sqlx::query_as(
            "SELECT t.tgname::text, t.tgisinternal, t.tgdeferrable
             FROM pg_trigger t
             WHERE t.tgrelid = to_regclass(quote_ident(current_schema()) || '.' || $1)
               AND t.tgtype & (1 | 2 | 4) = (1 | 4)
             ORDER BY t.tgname COLLATE \"C\"",
        )
        .bind(table)
        .fetch_all(&pool)
        .await
        .unwrap();
        let guard = fired
            .iter()
            .position(|(name, ..)| name == trigger)
            .unwrap_or_else(|| panic!("{table}: {fired:?}"));
        let (checks, after) = fired.split_at(guard);
        assert!(
            !checks.is_empty()
                && checks.iter().all(|(name, internal, deferrable)| {
                    name.starts_with("RI_ConstraintTrigger_c_") && *internal && !*deferrable
                }),
            "{table}: {fired:?}"
        );
        let after: Vec<&str> = after.iter().map(|(name, ..)| name.as_str()).collect();
        let mut want = vec![trigger];
        if table == "service_grant_resource_server" {
            want.push("service_grant_resource_server_impersonation_frozen");
        }
        assert_eq!(after, want, "{table}");
        // Its assignment foreign key is one of those immediate checks.
        let deferrable: bool = sqlx::query_scalar(
            "SELECT condeferrable FROM pg_constraint
             WHERE conrelid = to_regclass(quote_ident(current_schema()) || '.' || $1)
               AND conname = $1 || '_assignment_fkey'",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!deferrable, "{table}");
    }

    let (config, definer, source): (Vec<String>, bool, String) = sqlx::query_as(
        "SELECT p.proconfig, p.prosecdef, p.prosrc FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname = $1",
    )
    .bind(FUNCTION)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(config, ["search_path=pg_catalog, pg_temp"]);
    assert!(!definer, "SECURITY INVOKER");
    assert!(
        source.contains(" public.audience_tenant_assignment ")
            && !source.contains(" audience_tenant_assignment ")
            && source.contains("FOR SHARE;"),
        "{source}"
    );

    let mut names: Vec<&str> = TABLES.iter().map(|(.., trigger)| *trigger).collect();
    names.sort_unstable();
    assert_eq!(names, ASSIGNMENT_ACTIVE);
    for name in names {
        assert!(KNOWN_CONSTRAINTS.binary_search(&name).is_ok(), "{name}");
    }
    db.drop([pool]).await;
}

/// For both tables: a disabled assignment is refused with the guard's
/// `23514` and writes nothing; an enabled one is accepted, also behind a
/// disabled resource server (a dormant reference); a missing one is the
/// foreign key's `23503`. Disabling an assignment that rows reference is
/// not refused and leaves them (stranding), enabling it again revalidates
/// nothing, and a disable earlier in the same transaction is seen.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_disabled_assignment_is_refused_at_insert_and_an_enabled_one_accepted() {
    let (db, pool) = seeded().await;
    for (table, ..) in TABLES {
        let before = audiences(&pool, table).await;
        let err = sqlx::raw_sql(AssertSqlSafe(insert(table, "rs_2")))
            .execute(&pool)
            .await
            .expect_err(table);
        assert_guard_refusal(err, table);
        assert_eq!(audiences(&pool, table).await, before);

        let err = sqlx::raw_sql(AssertSqlSafe(insert(table, "rs_4")))
            .execute(&pool)
            .await
            .expect_err(table);
        assert_eq!(sqlstate(&err), "23503", "{table}: {err}");
        assert_missing_refusal(Err::<(), _>(RegistryError::from(err)), table);

        run(&pool, &insert(table, "rs_3")).await;
        if table == "service_identity_resource_server" {
            run(&pool, &insert(table, "rs_1")).await;
        }
        assert_eq!(audiences(&pool, table).await, ["rs_1", "rs_3"]);
    }

    // Stranding: the disable is not refused and the rows stay.
    run(&pool, &set_status("ata_1", "disabled")).await;
    for (table, ..) in TABLES {
        assert_eq!(audiences(&pool, table).await, ["rs_1", "rs_3"]);
    }
    // Re-enabling revalidates nothing; a new row is accepted again.
    run(&pool, &set_status("ata_2", "enabled")).await;
    for (table, ..) in TABLES {
        run(&pool, &insert(table, "rs_2")).await;
        assert_eq!(audiences(&pool, table).await, ["rs_1", "rs_2", "rs_3"]);
    }
    // A disable earlier in the writer's own transaction is seen.
    let mut conn = pool.acquire().await.unwrap();
    for (table, ..) in TABLES {
        run(
            &mut *conn,
            &format!("BEGIN; {}", set_status("ata_3", "disabled")),
        )
        .await;
        run(
            &mut *conn,
            &format!("DELETE FROM {table} WHERE resource_server_id = 'rs_3'"),
        )
        .await;
        let err = sqlx::raw_sql(AssertSqlSafe(insert(table, "rs_3")))
            .execute(&mut *conn)
            .await
            .expect_err(table);
        assert_guard_refusal(err, table);
        run(&mut *conn, "ROLLBACK").await;
    }
    drop(conn);
    db.drop([pool]).await;
}

/// Through the registry: the two creates, whose statement inserts the owner
/// and its audience rows in one `WITH`, and the two adds, which update the
/// owner first, all refuse a disabled assignment with `AssignmentActive`
/// and write nothing (no owner row, no revision step); a missing assignment
/// stays `ForeignKey`, and the same calls with enabled assignments succeed.
/// A hand-written creating statement in the registry's shape is refused
/// too.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_writes_and_creating_statements_refuse_a_disabled_assignment() {
    let (db, pool) = seeded().await;
    let identity = |id: &str, audiences: &[&str]| NewServiceIdentity {
        id: id.into(),
        tenant_id: "ten_a".into(),
        name: format!("identity-{id}"),
        max_scopes: vec!["read".into()],
        max_resource_constraints: Default::default(),
        resource_server_ids: audiences.iter().map(|id| id.to_string()).collect(),
        status: Status::Enabled,
    };
    let grant = |id: &str, audiences: &[&str]| NewServiceGrant {
        id: id.into(),
        tenant_id: "ten_a".into(),
        name: format!("grant-{id}"),
        actor_principal_id: "wld_1".into(),
        target_service_id: None,
        mode: GrantMode::Direct,
        scopes: vec!["read".into()],
        default_scopes: None,
        resource_constraints: Default::default(),
        max_ttl: 300,
        valid_until: None,
        status: Status::Enabled,
        activation_state: ActivationState::NotRequired,
        allowed_binding_ids: vec!["bnd_1".into()],
        resource_server_ids: audiences.iter().map(|id| id.to_string()).collect(),
    };
    let (identities, grants) = (TABLES[0].0, TABLES[1].0);

    // The creates: the disabled audience among enabled ones.
    assert_active_refusal(
        registry::test_support::create_service_identity(
            &pool,
            &identity("svc_2", &["rs_1", "rs_2", "rs_3"]),
        )
        .await,
        identities,
    );
    assert_active_refusal(
        registry::test_support::create_service_grant(&pool, &grant("grt_2", &["rs_1", "rs_2"]))
            .await,
        grants,
    );
    assert_missing_refusal(
        registry::test_support::create_service_grant(&pool, &grant("grt_2", &["rs_4"])).await,
        grants,
    );
    let owners: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM service_identity WHERE tenant_id = 'ten_a'
         UNION ALL SELECT id FROM service_grant WHERE tenant_id = 'ten_a' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(owners, ["grt_1", "svc_1"]);
    let created = registry::test_support::create_service_identity(
        &pool,
        &identity("svc_2", &["rs_3", "rs_1"]),
    )
    .await
    .unwrap();
    assert_eq!(created.resource_server_ids, ["rs_1", "rs_3"]);
    let created =
        registry::test_support::create_service_grant(&pool, &grant("grt_2", &["rs_1", "rs_3"]))
            .await
            .unwrap();
    assert_eq!(created.resource_server_ids, ["rs_1", "rs_3"]);

    // The adds: the owner's revision does not move on a refusal.
    for (table, expected) in [(identities, 1), (grants, 1)] {
        assert_active_refusal(add(&pool, table, expected, "rs_2").await, table);
        assert_missing_refusal(add(&pool, table, expected, "rs_4").await, table);
        assert_eq!(add(&pool, table, expected, "rs_3").await.unwrap(), 2);
    }
    let revisions: Vec<i64> = sqlx::query_scalar(
        "SELECT (SELECT revision FROM service_identity WHERE id = 'svc_1')
         UNION ALL SELECT (SELECT revision FROM service_grant WHERE id = 'grt_1')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(revisions, [2, 2]);

    // A creating statement written by hand, as the registry writes it.
    let err = sqlx::raw_sql(
        "WITH created AS (INSERT INTO principal VALUES ('svc_3', 'ten_a', 'service', 's3', 'enabled')
                          RETURNING tenant_id, id),
              service AS (INSERT INTO service_identity
                          SELECT id, tenant_id, 'third', '[]', '{}', 'enabled' FROM created
                          RETURNING tenant_id, id)
         INSERT INTO service_identity_resource_server
         SELECT id, tenant_id, u.item FROM service, unnest(ARRAY['rs_1', 'rs_2']) AS u(item)",
    )
    .execute(&pool)
    .await
    .expect_err("a creating statement");
    assert_guard_refusal(err, identities);
    let principals: i64 = sqlx::query_scalar("SELECT count(*) FROM principal WHERE id = 'svc_3'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(principals, 0);
    db.drop([pool]).await;
}

/// A statement that also writes the assignment, in a data-modifying
/// `WITH`: the guard is an `AFTER` trigger, so it runs at the end of the
/// statement and sees every change of it, whatever the order of the
/// sub-statements. The state of the assignment at the end of the statement
/// decides: a `WITH` that creates it `disabled` or disables it is refused,
/// whether the list insert reads the sub-statement or not; one that creates
/// it `enabled` or enables it is accepted (README "What 0010 adds",
/// "Limits").
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_statement_that_also_writes_the_assignment_is_judged_by_its_end_state() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let create = |status: &str| {
        format!(
            "INSERT INTO audience_tenant_assignment
             VALUES ('ata_4', 'rs_4', 'ten_a', '[]', '[]', '[]', '{status}')
             RETURNING tenant_id, resource_server_id"
        )
    };
    for (table, column, owner, _) in TABLES {
        let read = |status: &str| {
            format!(
                "BEGIN;
                 WITH assigned AS ({})
                 INSERT INTO {table} ({column}, tenant_id, resource_server_id)
                 SELECT '{owner}', tenant_id, resource_server_id FROM assigned",
                create(status)
            )
        };
        let unread = |sub: String, resource_server_id: &str| {
            format!(
                "BEGIN; WITH changed AS ({sub}) {}",
                insert(table, resource_server_id)
            )
        };
        let refused = [
            read("disabled"),
            unread(create("disabled"), "rs_4"),
            unread(set_status("ata_3", "disabled"), "rs_3"),
        ];
        for sql in refused {
            let err = sqlx::raw_sql(AssertSqlSafe(sql.clone()))
                .execute(&mut *conn)
                .await
                .expect_err(&sql);
            assert_guard_refusal(err, table);
            run(&mut *conn, "ROLLBACK").await;
        }
        let accepted = [
            (read("enabled"), "rs_4"),
            (unread(create("enabled"), "rs_4"), "rs_4"),
            (unread(set_status("ata_2", "enabled"), "rs_2"), "rs_2"),
        ];
        for (sql, resource_server_id) in accepted {
            run(&mut *conn, &sql).await;
            let stored: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} r JOIN audience_tenant_assignment a
                     USING (tenant_id, resource_server_id)
                 WHERE r.resource_server_id = '{resource_server_id}' AND a.status = 'enabled'"
            )))
            .fetch_one(&mut *conn)
            .await
            .unwrap();
            assert_eq!(stored, 1, "{sql}");
            run(&mut *conn, "ROLLBACK").await;
        }
    }
    drop(conn);
    db.drop([pool]).await;
}

/// The race of the proposal, insert first: the insert's `FOR SHARE` holds
/// the assignment, so a disable waits until the insert's transaction
/// commits, and then disables it, leaving the new row stranded (allowed).
/// The foreign key's `KEY SHARE` alone would not make it wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_insert_holds_the_assignment_so_a_disable_waits_for_its_commit() {
    let (db, pool) = seeded().await;
    for (table, ..) in TABLES {
        let mut inserter = pool.acquire().await.unwrap().detach();
        let mut disabler = pool.acquire().await.unwrap().detach();
        let (inserter_pid, disabler_pid) = (
            backend_pid(&mut inserter).await,
            backend_pid(&mut disabler).await,
        );
        let revision: i64 = sqlx::query_scalar(
            "SELECT revision FROM audience_tenant_assignment WHERE id = 'ata_3'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut tx = inserter.begin().await.unwrap();
        add(&mut *tx, table, 1, "rs_3").await.unwrap();
        let waiting = tokio::spawn(async move {
            registry::test_support::update_audience_tenant_assignment(
                &mut disabler,
                "ata_3",
                revision,
                &assignment_changes(Status::Disabled),
            )
            .await
        });
        wait_until_blocked(&pool, disabler_pid, inserter_pid).await;
        assert!(!waiting.is_finished());
        tx.commit().await.unwrap();
        let disabled = tokio::time::timeout(Duration::from_secs(30), waiting)
            .await
            .expect("the disable never finished")
            .unwrap()
            .unwrap();
        assert_eq!(
            (disabled.status, disabled.revision),
            (Status::Disabled, revision + 1)
        );
        assert!(audiences(&pool, table).await.contains(&"rs_3".to_string()));
        // Ready for the next table.
        run(&pool, &set_status("ata_3", "enabled")).await;
    }
    db.drop([pool]).await;
}

/// The race the other way round, under `READ COMMITTED`: a disable that
/// committed first refuses the insert; one in progress makes the insert
/// wait, and once it commits the insert sees `disabled` and is refused,
/// with the typed error and no revision step. A disable that rolls back
/// lets the waiting insert through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_disable_that_commits_first_refuses_the_insert() {
    let (db, pool) = seeded().await;
    for (table, ..) in TABLES {
        // Committed before the insert starts.
        run(&pool, &set_status("ata_3", "disabled")).await;
        assert_active_refusal(add(&pool, table, 1, "rs_3").await, table);
        run(&pool, &set_status("ata_3", "enabled")).await;

        // In progress when the insert starts: the insert waits.
        for commit in [true, false] {
            let mut disabler = pool.acquire().await.unwrap().detach();
            let mut inserter = pool.acquire().await.unwrap().detach();
            let (disabler_pid, inserter_pid) = (
                backend_pid(&mut disabler).await,
                backend_pid(&mut inserter).await,
            );
            let mut tx = disabler.begin().await.unwrap();
            run(&mut *tx, &set_status("ata_3", "disabled")).await;
            let table_name = table.to_string();
            let waiting =
                tokio::spawn(async move { add(&mut inserter, &table_name, 1, "rs_3").await });
            wait_until_blocked(&pool, inserter_pid, disabler_pid).await;
            assert!(!waiting.is_finished());
            if commit {
                tx.commit().await.unwrap();
            } else {
                tx.rollback().await.unwrap();
            }
            let result = tokio::time::timeout(Duration::from_secs(30), waiting)
                .await
                .expect("the insert never finished")
                .unwrap();
            if commit {
                assert_active_refusal(result, table);
                assert!(!audiences(&pool, table).await.contains(&"rs_3".to_string()));
                run(&pool, &set_status("ata_3", "enabled")).await;
            } else {
                assert_eq!(result.unwrap(), 2);
                assert!(audiences(&pool, table).await.contains(&"rs_3".to_string()));
            }
        }
    }
    db.drop([pool]).await;
}

/// The case a `BEFORE` trigger misses (review of the `0010` pull request,
/// scenario S1), under `READ COMMITTED`: one statement inserts two audience
/// rows, one whose assignment does not exist yet and one whose assignment
/// another transaction holds (an update in progress). While the statement
/// waits, a third transaction creates the missing assignment `disabled` and
/// commits. A `BEFORE` guard has already passed the first row (no
/// assignment then) and the foreign key at the end of the statement finds
/// the new one, so the row would be stored against a never-enabled
/// assignment. With the `AFTER` guard the row is refused in both row
/// orders: held row first, the statement waits in the guard of that row,
/// and the foreign key and the guard of the other row then see the
/// committed `disabled` assignment (`23514`); new row first, its foreign
/// key finds no assignment before anything waits (`23503`). The registry's
/// create, which inserts in the order of the caller's array, is refused the
/// same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_assignment_created_disabled_while_the_statement_runs_is_refused() {
    let (db, pool) = seeded().await;
    let mut next = 10;
    let writers = [TABLES[0].0, TABLES[1].0, "create_service_identity"];
    for writer in writers {
        for held_first in [true, false] {
            next += 1;
            let new = format!("rs_{next}");
            run(
                &pool,
                &format!(
                    "INSERT INTO resource_server VALUES ('{new}', 'api-{next}', 'API {next}',
                         '[\"wif\"]', '[\"read\"]', '[]', 'enabled')"
                ),
            )
            .await;
            let rows = if held_first {
                ["rs_3".to_string(), new.clone()]
            } else {
                [new.clone(), "rs_3".to_string()]
            };
            let mut holder = pool.acquire().await.unwrap().detach();
            let mut inserter = pool.acquire().await.unwrap().detach();
            let (holder_pid, inserter_pid) = (
                backend_pid(&mut holder).await,
                backend_pid(&mut inserter).await,
            );
            run_promptly(
                &mut holder,
                "BEGIN; UPDATE audience_tenant_assignment SET revision = revision + 1
                 WHERE id = 'ata_3'",
            )
            .await;
            let table = if writer == "create_service_identity" {
                TABLES[0].0
            } else {
                writer
            };
            let statement = writer.to_string();
            let audiences_of_statement = rows.clone();
            let task = tokio::spawn(async move {
                if statement == "create_service_identity" {
                    let new = NewServiceIdentity {
                        id: "svc_2".into(),
                        tenant_id: "ten_a".into(),
                        name: "identity-svc_2".into(),
                        max_scopes: vec!["read".into()],
                        max_resource_constraints: Default::default(),
                        resource_server_ids: audiences_of_statement.to_vec(),
                        status: Status::Enabled,
                    };
                    registry::test_support::create_service_identity(&mut inserter, &new)
                        .await
                        .map(|_| ())
                } else {
                    let (_, column, owner, _) = guarded(&statement);
                    let [first, second] = &audiences_of_statement;
                    sqlx::raw_sql(AssertSqlSafe(format!(
                        "INSERT INTO {statement} ({column}, tenant_id, resource_server_id)
                         VALUES ('{owner}', 'ten_a', '{first}'), ('{owner}', 'ten_a', '{second}')"
                    )))
                    .execute(&mut inserter)
                    .await
                    .map(|_| ())
                    .map_err(RegistryError::from)
                }
            });
            let waited = waits_or_finishes(&pool, inserter_pid, holder_pid, &task).await;
            assert_eq!(waited, held_first, "{writer}, {rows:?}");
            // Another transaction creates the assignment disabled and
            // commits while the statement runs.
            run(
                &pool,
                &format!(
                    "INSERT INTO audience_tenant_assignment
                     VALUES ('ata_{next}', '{new}', 'ten_a', '[\"wif\"]', '[\"read\"]', '[]',
                             'disabled')"
                ),
            )
            .await;
            run_promptly(&mut holder, "COMMIT").await;
            let result = tokio::time::timeout(Duration::from_secs(30), task)
                .await
                .expect("the insert never finished")
                .unwrap();
            if held_first {
                assert_active_refusal(result, table);
            } else {
                assert_missing_refusal(result, table);
            }
            let stored: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} WHERE resource_server_id IN ('rs_3', '{new}')"
            )))
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(stored, 0, "{writer}, {rows:?}");
        }
    }
    db.drop([pool]).await;
}

/// Under `REPEATABLE READ` and `SERIALIZABLE`, an insert whose snapshot
/// predates a committed update of the assignment fails with `40001`, which
/// the registry maps to `Retry`: whether the update committed before the
/// insert or while the insert waited for it, and whatever it changed (a
/// disable, or only the scopes of an enabled assignment).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_insert_after_a_concurrent_update_must_retry_under_repeatable_read() {
    let (db, pool) = seeded().await;
    for isolation in ["REPEATABLE READ", "SERIALIZABLE"] {
        for (table, ..) in TABLES {
            for update in [
                set_status("ata_3", "disabled"),
                "UPDATE audience_tenant_assignment SET allowed_scopes = '[]', \
                 revision = revision + 1 WHERE id = 'ata_3'"
                    .to_string(),
            ] {
                for wait in [false, true] {
                    let mut inserter = pool.acquire().await.unwrap().detach();
                    let mut updater = pool.acquire().await.unwrap().detach();
                    let (inserter_pid, updater_pid) = (
                        backend_pid(&mut inserter).await,
                        backend_pid(&mut updater).await,
                    );
                    // The inserter's snapshot starts here.
                    run(
                        &mut inserter,
                        &format!("BEGIN ISOLATION LEVEL {isolation}; SELECT 1"),
                    )
                    .await;
                    run(&mut updater, &format!("BEGIN; {update}")).await;
                    if !wait {
                        run(&mut updater, "COMMIT").await;
                    }
                    let table_name = table.to_string();
                    let task = tokio::spawn(async move {
                        let result = add(&mut inserter, &table_name, 1, "rs_3").await;
                        sqlx::raw_sql("ROLLBACK")
                            .execute(&mut inserter)
                            .await
                            .unwrap();
                        result
                    });
                    if wait {
                        wait_until_blocked(&pool, inserter_pid, updater_pid).await;
                        assert!(!task.is_finished());
                        run(&mut updater, "COMMIT").await;
                    }
                    let err = tokio::time::timeout(Duration::from_secs(30), task)
                        .await
                        .expect("the insert never finished")
                        .unwrap()
                        .expect_err(isolation);
                    assert_eq!(
                        retry_sqlstate(&err),
                        "40001",
                        "{isolation}, {table}, wait {wait}: {update}"
                    );
                    assert!(!audiences(&pool, table).await.contains(&"rs_3".to_string()));
                    run(
                        &pool,
                        "UPDATE audience_tenant_assignment SET status = 'enabled',
                             allowed_scopes = '[\"read\"]', revision = revision + 1
                         WHERE id = 'ata_3'",
                    )
                    .await;
                }
            }
        }
    }
    db.drop([pool]).await;
}

/// The README lock order: owner row, assignment `FOR SHARE`, then the
/// audit head. In that order a list insert and an auditing disable wait for
/// each other without a deadlock, in both orders of arrival: a disable that
/// holds the assignment appends its event while the insert waits, and the
/// insert is then refused; an insert that holds the assignment appends and
/// commits while the disable waits, and the disable then finishes. A writer
/// that takes the audit head before its list insert breaks the order and
/// deadlocks with the auditing disable (`40P01`, which the registry maps to
/// `Retry`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_list_insert_and_a_disable_in_the_prescribed_order_never_deadlock() {
    let (db, pool) = seeded().await;
    for (table, ..) in TABLES {
        // The disable first: it holds the assignment, the insert waits.
        let mut disabler = pool.acquire().await.unwrap().detach();
        let mut inserter = pool.acquire().await.unwrap().detach();
        let (disabler_pid, inserter_pid) = (
            backend_pid(&mut disabler).await,
            backend_pid(&mut inserter).await,
        );
        run_promptly(
            &mut disabler,
            &format!("BEGIN; {}", set_status("ata_3", "disabled")),
        )
        .await;
        let waiting = spawn_sql(inserter, format!("BEGIN; {}", insert(table, "rs_3")));
        wait_until_blocked(&pool, inserter_pid, disabler_pid).await;
        run_promptly(&mut disabler, &format!("{APPEND_LOCKS}; COMMIT")).await;
        let (mut inserter, result) = finished(waiting).await;
        assert_guard_refusal(result.expect_err(table), table);
        run(&mut inserter, "ROLLBACK").await;
        run(&pool, &set_status("ata_3", "enabled")).await;

        // The insert first: it holds the assignment, the disable waits.
        let (inserter_pid, disabler_pid) = (
            backend_pid(&mut inserter).await,
            backend_pid(&mut disabler).await,
        );
        run_promptly(&mut inserter, &format!("BEGIN; {}", insert(table, "rs_3"))).await;
        let waiting = spawn_sql(
            disabler,
            format!(
                "BEGIN; {}; {APPEND_LOCKS}; COMMIT",
                set_status("ata_3", "disabled")
            ),
        );
        wait_until_blocked(&pool, disabler_pid, inserter_pid).await;
        run_promptly(&mut inserter, &format!("{APPEND_LOCKS}; COMMIT")).await;
        let (mut disabler, result) = finished(waiting).await;
        result.unwrap();
        assert!(audiences(&pool, table).await.contains(&"rs_3".to_string()));
        run(
            &pool,
            &format!(
                "DELETE FROM {table} WHERE resource_server_id = 'rs_3'; {}",
                set_status("ata_3", "enabled")
            ),
        )
        .await;

        // Out of order: the writer takes the head before its insert.
        let (inserter_pid, disabler_pid) = (
            backend_pid(&mut inserter).await,
            backend_pid(&mut disabler).await,
        );
        run_promptly(&mut inserter, &format!("BEGIN; {APPEND_LOCKS}")).await;
        run_promptly(
            &mut disabler,
            &format!("BEGIN; {}", set_status("ata_3", "disabled")),
        )
        .await;
        let insert_task = spawn_sql(inserter, insert(table, "rs_3"));
        wait_until_blocked(&pool, inserter_pid, disabler_pid).await;
        let append_task = spawn_sql(disabler, APPEND_LOCKS.to_string());
        let mut codes = Vec::new();
        for task in [insert_task, append_task] {
            let (mut conn, result) = finished(task).await;
            codes.push(match result {
                Ok(()) => "ok".to_string(),
                Err(err) => {
                    let code = sqlstate(&err);
                    assert_eq!(retry_sqlstate(&RegistryError::from(err)), code);
                    code
                }
            });
            run(&mut conn, "ROLLBACK").await;
        }
        // Either is the victim; the survivor's insert or append then runs.
        codes.sort();
        assert_eq!(codes, ["40P01", "ok"], "{table}");
    }
    db.drop([pool]).await;
}

/// The guards are `ENABLE ALWAYS`, so replica mode does not skip them: a
/// disabled assignment is still refused there. Replica mode skips the
/// foreign key, so a row whose assignment is missing is accepted (the guard
/// finds no row and returns): the limit README "What 0010 adds" pins.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn replica_mode_refuses_a_disabled_assignment_but_not_a_missing_one() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for (table, ..) in TABLES {
        run(
            &mut *conn,
            "BEGIN; SET LOCAL session_replication_role = replica",
        )
        .await;
        let err = sqlx::raw_sql(AssertSqlSafe(insert(table, "rs_2")))
            .execute(&mut *conn)
            .await
            .expect_err(table);
        assert_guard_refusal(err, table);
        run(&mut *conn, "ROLLBACK").await;

        run(
            &mut *conn,
            &format!(
                "BEGIN; SET LOCAL session_replication_role = replica; {}",
                insert(table, "rs_4")
            ),
        )
        .await;
        let stored: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE resource_server_id = 'rs_4'"
        )))
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(stored, 1, "{table}");
        run(&mut *conn, "ROLLBACK").await;
    }
    drop(conn);
    db.drop([pool]).await;
}

/// The guard reads the assignment of the row's own tenant: `ten_b` shares
/// `rs_1` and `rs_2` with `ten_a` under the opposite statuses, so a row of
/// `ten_b` for `rs_1` is refused although `ten_a`'s assignment of `rs_1` is
/// enabled, and one for `rs_2` is accepted although `ten_a`'s is disabled.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_guard_reads_the_assignment_of_the_rows_own_tenant() {
    let (db, pool) = seeded().await;
    for (table, column, ..) in TABLES {
        let owner = if table == "service_identity_resource_server" {
            "svc_b"
        } else {
            "grt_b"
        };
        let insert_b = |resource_server_id: &str| {
            format!(
                "INSERT INTO {table} ({column}, tenant_id, resource_server_id) \
                 VALUES ('{owner}', 'ten_b', '{resource_server_id}')"
            )
        };
        let err = sqlx::raw_sql(AssertSqlSafe(insert_b("rs_1")))
            .execute(&pool)
            .await
            .expect_err(table);
        assert_guard_refusal(err, table);
        run(&pool, &insert_b("rs_2")).await;
        let stored: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT resource_server_id FROM {table} WHERE tenant_id = 'ten_b'"
        )))
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(stored, ["rs_2"], "{table}");
        // And the other way round for ten_a.
        let err = sqlx::raw_sql(AssertSqlSafe(insert(table, "rs_2")))
            .execute(&pool)
            .await
            .expect_err(table);
        assert_guard_refusal(err, table);
    }
    db.drop([pool]).await;
}

/// An audience that is already listed is `AlreadyExists` with the list's
/// primary key, as the add functions document, even when its assignment
/// has been disabled since (a stranded row): the `AFTER` guard runs only
/// for a row that is in the table, after its unique check, so the
/// duplicate fails first with `23505`. The owner's revision does not move.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_listed_audience_is_already_exists_even_when_its_assignment_is_disabled() {
    let (db, pool) = seeded().await;
    let (identities, grants) = (TABLES[0].0, TABLES[1].0);
    assert_eq!(add(&pool, identities, 1, "rs_1").await.unwrap(), 2);
    run(&pool, &set_status("ata_1", "disabled")).await;
    for (table, expected) in [(identities, 2), (grants, 1)] {
        match add(&pool, table, expected, "rs_1").await {
            Err(RegistryError::AlreadyExists { constraint }) => {
                assert_eq!(constraint, format!("{table}_pkey"));
            }
            other => panic!("expected AlreadyExists on {table}: {other:?}"),
        }
        let err = sqlx::raw_sql(AssertSqlSafe(insert(table, "rs_1")))
            .execute(&pool)
            .await
            .expect_err(table);
        assert_eq!(sqlstate(&err), "23505", "{table}: {err}");
        assert_eq!(audiences(&pool, table).await, ["rs_1"]);
    }
    let revisions: Vec<i64> = sqlx::query_scalar(
        "SELECT (SELECT revision FROM service_identity WHERE id = 'svc_1')
         UNION ALL SELECT (SELECT revision FROM service_grant WHERE id = 'grt_1')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(revisions, [2, 1]);
    db.drop([pool]).await;
}

/// `INSERT … ON CONFLICT DO NOTHING` of a row that is already listed, here
/// stranded by a later disable, inserts nothing and fires no `AFTER`
/// guard: a no-op, not a refusal. A new row with a disabled assignment in
/// the same statement is still refused.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn on_conflict_do_nothing_of_a_stranded_row_is_a_no_op() {
    let (db, pool) = seeded().await;
    run(&pool, &insert(TABLES[0].0, "rs_1")).await;
    run(&pool, &set_status("ata_1", "disabled")).await;
    for (table, column, owner, _) in TABLES {
        run(
            &pool,
            &format!("{} ON CONFLICT DO NOTHING", insert(table, "rs_1")),
        )
        .await;
        assert_eq!(audiences(&pool, table).await, ["rs_1"]);
        let err = sqlx::raw_sql(AssertSqlSafe(format!(
            "INSERT INTO {table} ({column}, tenant_id, resource_server_id)
             VALUES ('{owner}', 'ten_a', 'rs_1'), ('{owner}', 'ten_a', 'rs_2')
             ON CONFLICT DO NOTHING"
        )))
        .execute(&pool)
        .await
        .expect_err(table);
        assert_guard_refusal(err, table);
        assert_eq!(audiences(&pool, table).await, ["rs_1"]);
    }
    db.drop([pool]).await;
}

/// The guard reads the assignment `FOR SHARE` with the writer's
/// privileges: a role that may insert list rows needs `SELECT` on the
/// assignment's `tenant_id`, `resource_server_id` and `status`, and
/// `UPDATE` on at least one of its columns, which `FOR SHARE` requires;
/// otherwise the insert fails with `42501`. The prescribed grant (README
/// "What 0010 adds", "Privileges") is `UPDATE (id)`, a column the `0003`
/// guard keeps immutable: with it the role takes `FOR SHARE` but cannot
/// change an assignment (`42501` for `status`, `SK001` for `id`).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn list_row_writers_need_select_and_update_on_the_assignment() {
    const PRESCRIBED: &str = "SELECT (tenant_id, resource_server_id, status), UPDATE (id) \
                              ON audience_tenant_assignment";
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    run(
        &pool,
        &format!(
            "GRANT INSERT ON service_identity_resource_server, service_grant_resource_server
                 TO {role};
             GRANT SELECT ON service_grant TO {role}"
        ),
    )
    .await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    for (privilege, allowed) in [
        (None, false),
        (Some("SELECT ON audience_tenant_assignment"), false),
        (
            Some("SELECT (tenant_id, resource_server_id) ON audience_tenant_assignment"),
            false,
        ),
        (
            Some(
                "SELECT (tenant_id, resource_server_id), UPDATE (status) \
                 ON audience_tenant_assignment",
            ),
            false,
        ),
        (Some("UPDATE ON audience_tenant_assignment"), false),
        (Some("SELECT, UPDATE ON audience_tenant_assignment"), true),
        // The prescribed grant, last: the checks below use it.
        (Some(PRESCRIBED), true),
    ] {
        if let Some(privilege) = privilege {
            run(
                &pool,
                &format!(
                    "REVOKE ALL ON audience_tenant_assignment FROM {role};
                     GRANT {privilege} TO {role}"
                ),
            )
            .await;
        }
        for (table, ..) in TABLES {
            let sql = format!("BEGIN; {}", insert(table, "rs_3"));
            let result = sqlx::raw_sql(AssertSqlSafe(sql.clone()))
                .execute(&mut writer)
                .await;
            if allowed {
                result.unwrap_or_else(|err| panic!("{privilege:?}, {table}: {err}"));
            } else {
                let err = result.expect_err(&sql);
                assert_eq!(sqlstate(&err), "42501", "{privilege:?}, {table}: {err}");
                assert_eq!(
                    err.as_database_error().unwrap().message(),
                    "permission denied for table audience_tenant_assignment"
                );
            }
            run(&mut writer, "ROLLBACK").await;
        }
    }

    // With the prescribed grant the role locks an assignment but cannot
    // change it.
    let where_ata_3 = "WHERE tenant_id = 'ten_a' AND resource_server_id = 'rs_3'";
    run(
        &mut writer,
        &format!(
            "BEGIN; SELECT status FROM audience_tenant_assignment {where_ata_3} FOR SHARE; ROLLBACK"
        ),
    )
    .await;
    for (change, code, message) in [
        (
            "status = 'disabled'",
            "42501",
            "permission denied for table audience_tenant_assignment",
        ),
        (
            "revision = revision + 1",
            "42501",
            "permission denied for table audience_tenant_assignment",
        ),
        (
            "id = 'ata_x'",
            "SK001",
            "column audience_tenant_assignment.id is immutable",
        ),
    ] {
        let err = sqlx::raw_sql(AssertSqlSafe(format!(
            "UPDATE audience_tenant_assignment SET {change} {where_ata_3}"
        )))
        .execute(&mut writer)
        .await
        .expect_err(change);
        assert_eq!(sqlstate(&err), code, "{change}: {err}");
        assert_eq!(err.as_database_error().unwrap().message(), message);
    }
    drop(writer);
    db.drop([pool]).await;
}

/// The information query of README "What 0010 adds" ("Upgrade
/// precondition"), run as written there: it lists exactly the audience rows
/// whose assignment is not enabled, here rows stranded by a later disable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_readme_query_lists_rows_that_reference_a_disabled_assignment() {
    let (db, pool) = seeded().await;
    let readme = include_str!("../migrations/README.md");
    let section = &readme[readme.find("## What 0010 adds").unwrap()..];
    let section = &section[section.find("- **Upgrade precondition.**").unwrap()..];
    let start = section.find("```sql\n").unwrap() + "```sql\n".len();
    let end = start + section[start..].find("  ```").unwrap();
    let query: String = section[start..end]
        .lines()
        .map(|line| line.strip_prefix("  ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    let listed = || async {
        sqlx::query_as::<_, (String, String, String, String)>(AssertSqlSafe(query.clone()))
            .fetch_all(&pool)
            .await
            .unwrap()
    };
    assert_eq!(listed().await, []);
    run(&pool, &insert(TABLES[0].0, "rs_1")).await;
    run(&pool, &set_status("ata_1", "disabled")).await;
    let row = |list: &str, owner: &str| {
        (
            list.to_string(),
            "ten_a".to_string(),
            owner.to_string(),
            "rs_1".to_string(),
        )
    };
    assert_eq!(
        listed().await,
        [
            row("service_grant_resource_server", "grt_1"),
            row("service_identity_resource_server", "svc_1"),
        ]
    );
    db.drop([pool]).await;
}
