//! Migration runner safety properties against a real PostgreSQL server.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL`, a URL for a role that may
//! create databases; each test creates and drops its own database. They are
//! `#[ignore]`d, so runs without a database report them as ignored; run them
//! with `cargo nextest run --run-ignored all` (as the `service-nextest` CI
//! job does) or `cargo test -- --include-ignored`. An ignored test that is
//! run without the variable fails loudly instead of passing vacuously.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

use std::{
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use skyoauth_service::persistence::{self, DatabaseConfig, MIGRATOR, MigrateError, PgPool};
use sqlx::{AssertSqlSafe, Connection, PgConnection, postgres::PgConnectOptions};

const IT_DATABASE_URL_VAR: &str = "SKYOAUTH_IT_DATABASE_URL";

struct TestDb {
    admin_url: String,
    name: String,
    config: DatabaseConfig,
}

impl TestDb {
    /// Creates a fresh, empty database.
    ///
    /// # Panics
    ///
    /// When `SKYOAUTH_IT_DATABASE_URL` is unset or empty.
    async fn create() -> Self {
        let admin_url = std::env::var(IT_DATABASE_URL_VAR)
            .ok()
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "{IT_DATABASE_URL_VAR} must be set to run this database test \
                     (a postgres:// URL for a role that may create databases)"
                )
            });
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let name = format!(
            "skyoauth_test_{}_{}_{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let mut admin = PgConnection::connect(&admin_url).await.unwrap();
        // The name is generated above from digits and underscores only.
        sqlx::raw_sql(AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        let connect = PgConnectOptions::from_str(&admin_url)
            .unwrap()
            .database(&name);
        let config = DatabaseConfig::new(connect, None, 4, Duration::from_secs(10)).unwrap();
        Self {
            admin_url,
            name,
            config,
        }
    }

    async fn pool(&self) -> PgPool {
        persistence::connect(&self.config).await.unwrap()
    }

    async fn drop(self, pools: impl IntoIterator<Item = PgPool>) {
        for pool in pools {
            pool.close().await;
        }
        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        sqlx::raw_sql(AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.name
        )))
        .execute(&mut admin)
        .await
        .unwrap();
    }
}

async fn applied(pool: &PgPool) -> Vec<(i64, bool, String)> {
    sqlx::query_as(
        "SELECT version, success, installed_on::text FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn embedded_versions() -> Vec<i64> {
    MIGRATOR.iter().map(|m| m.version).collect()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn applies_in_order_exactly_once_and_rerun_is_a_no_op() {
    let db = TestDb::create().await;
    let pool = db.pool().await;

    persistence::migrate(&pool).await.unwrap();
    let first = applied(&pool).await;
    let versions: Vec<i64> = first.iter().map(|(v, _, _)| *v).collect();
    assert_eq!(versions, embedded_versions());
    assert!(first.iter().all(|(_, success, _)| *success));

    persistence::migrate(&pool).await.unwrap();
    assert_eq!(applied(&pool).await, first);

    let product: String = sqlx::query_scalar("SELECT product FROM schema_info")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(product, "skyoauth");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn modified_applied_migration_is_refused() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();

    sqlx::query("UPDATE _sqlx_migrations SET checksum = '\\x00' WHERE version = 1")
        .execute(&pool)
        .await
        .unwrap();
    let err = persistence::migrate(&pool).await.unwrap_err();
    assert!(matches!(err, MigrateError::VersionMismatch(1)), "{err:?}");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn refused_run_releases_the_migration_lock() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let replica = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = '\\x00' WHERE version = 1")
        .execute(&pool)
        .await
        .unwrap();

    // A refused run must not leave the advisory lock held by a pooled
    // connection: retries on the same pool and runs by another replica would
    // then wait forever.
    for pool in [&pool, &pool, &replica, &pool] {
        let result = tokio::time::timeout(Duration::from_secs(10), persistence::migrate(pool))
            .await
            .expect("migrate hung: the advisory lock is still held");
        assert!(
            matches!(result, Err(MigrateError::VersionMismatch(1))),
            "{result:?}"
        );
    }
    db.drop([pool, replica]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn database_newer_than_the_binary_is_refused() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();

    // As if a newer binary had applied one more migration.
    let newer = embedded_versions().last().unwrap() + 1;
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
         VALUES ($1, 'from a newer binary', true, '\\x00', 0)",
    )
    .bind(newer)
    .execute(&pool)
    .await
    .unwrap();
    let err = persistence::migrate(&pool).await.unwrap_err();
    assert!(
        matches!(err, MigrateError::VersionMissing(v) if v == newer),
        "{err:?}"
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn partially_applied_migration_is_refused() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();

    // As if migration 1 had failed part-way on a store without
    // transactional DDL.
    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = 1")
        .execute(&pool)
        .await
        .unwrap();
    let err = persistence::migrate(&pool).await.unwrap_err();
    assert!(matches!(err, MigrateError::Dirty(1)), "{err:?}");
    db.drop([pool]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_runners_apply_each_migration_once() {
    let db = TestDb::create().await;
    let mut pools = Vec::new();
    for _ in 0..4 {
        pools.push(db.pool().await);
    }

    // Each runner uses its own pool, as separate replicas would.
    let runs: Vec<_> = pools
        .iter()
        .cloned()
        .map(|pool| tokio::spawn(async move { persistence::migrate(&pool).await }))
        .collect();
    for run in runs {
        run.await.unwrap().unwrap();
    }
    let versions: Vec<i64> = applied(&pools[0])
        .await
        .iter()
        .map(|(v, _, _)| *v)
        .collect();
    assert_eq!(versions, embedded_versions());
    db.drop(pools).await;
}

/// Runs each write on one connection, after `setup`, and checks that the
/// append-only guard rejects it with SQLSTATE SK001 and leaves the row.
async fn assert_append_only(pool: &PgPool, setup: &'static str) {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::raw_sql(setup).execute(&mut *conn).await.unwrap();
    for statement in [
        "UPDATE schema_info SET created_at = now()",
        "DELETE FROM schema_info",
        "TRUNCATE schema_info",
    ] {
        let err = sqlx::query(statement)
            .execute(&mut *conn)
            .await
            .unwrap_err();
        let code = err.as_database_error().and_then(|e| e.code());
        assert_eq!(code.as_deref(), Some("SK001"), "{setup} {statement}: {err}");
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_info")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    conn.close().await.unwrap();
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn append_only_guard_rejects_update_delete_and_truncate() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    // No session setup: this runs in the default replication mode and
    // needs no superuser.
    assert_append_only(&pool, "SELECT 1").await;
    db.drop([pool]).await;
}

/// `ENABLE ALWAYS` keeps the guard firing in replica mode, which would
/// otherwise skip ordinary triggers. Setting the mode needs a superuser.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn append_only_guard_holds_under_replica_role() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    assert_append_only(&pool, "SET session_replication_role = replica").await;
    db.drop([pool]).await;
}
