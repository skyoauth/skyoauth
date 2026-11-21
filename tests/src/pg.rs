//! PostgreSQL isolation for the `pg` target (conformance layout §1.1: a
//! template database per test).
//!
//! The tests need `SKYOAUTH_IT_DATABASE_URL`, a URL for a role that may
//! create databases (`CREATEDB`). Without it [`TestDb::create`] panics: a
//! scenario test never passes vacuously (layout §1.2, "Loud failure"), and
//! scenario tests are never `#[ignore]`d.
//!
//! Every migration of `skyoauth-service` is applied once to a template
//! database, named after a digest of the embedded migrations, and each test
//! gets a fresh copy of it (`CREATE DATABASE … TEMPLATE …`), which is
//! faster than migrating an empty database per test. The template is built
//! under a temporary name and renamed when complete, so a crash mid-build
//! never leaves a half-migrated template behind; it stays in the cluster for
//! later runs with the same migrations. Concurrent test processes (nextest
//! runs each test in its own process) serialize the build and the copies on
//! a session-level advisory lock, because a database cannot be copied while
//! another session is connected to it.
//!
//! Duplication: the per-test database, its cleanup on drop and the UTF8
//! encoding rule are adapted from `service/tests/common/mod.rs`, which is a
//! test module of the service package and cannot be imported from here.
//! Keep the two in step until a shared test-support crate is justified.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use skyoauth_service::persistence::{self, DatabaseConfig, MIGRATOR, PgPool};
use sqlx::{AssertSqlSafe, Connection, PgConnection, postgres::PgConnectOptions};

/// The variable that names the PostgreSQL server of the `pg` environment.
pub const IT_DATABASE_URL_VAR: &str = "SKYOAUTH_IT_DATABASE_URL";

/// The advisory lock key that serializes template builds and copies across
/// test processes (an arbitrary constant; "skyoauth" in ASCII, truncated).
const TEMPLATE_LOCK_KEY: i64 = 0x736b_796f_6175_7468;

/// A fresh database, copied from the migrated template, for one test.
pub struct TestDb {
    admin_url: String,
    name: String,
    config: DatabaseConfig,
    /// Set by [`TestDb::drop`]; otherwise `Drop` cleans up.
    dropped: bool,
}

impl TestDb {
    /// Creates a database with every migration applied.
    ///
    /// # Panics
    ///
    /// When `SKYOAUTH_IT_DATABASE_URL` is unset or empty, or the server
    /// refuses the template build or the copy.
    pub async fn create() -> Self {
        let admin_url = std::env::var(IT_DATABASE_URL_VAR)
            .ok()
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "{IT_DATABASE_URL_VAR} must be set to run the `pg` scenario tests \
                     (a postgres:// URL for a role that may create databases)"
                )
            });
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        // Digits and underscores only, so it needs no quoting below.
        let name = format!(
            "skyoauth_scn_{}_{}_{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let template = template_name();
        let mut admin = PgConnection::connect(&admin_url).await.unwrap();
        execute(
            &mut admin,
            format!("SELECT pg_advisory_lock({TEMPLATE_LOCK_KEY})"),
        )
        .await;
        ensure_template(&mut admin, &admin_url, &template).await;
        execute(
            &mut admin,
            format!("CREATE DATABASE {name} TEMPLATE {template}"),
        )
        .await;
        execute(
            &mut admin,
            format!("SELECT pg_advisory_unlock({TEMPLATE_LOCK_KEY})"),
        )
        .await;
        let _ = admin.close().await;
        Self {
            config: config_for(&admin_url, &name),
            admin_url,
            name,
            dropped: false,
        }
    }

    /// A new pool for this test's database.
    pub async fn pool(&self) -> PgPool {
        persistence::connect(&self.config).await.unwrap()
    }

    /// Closes `pools` and drops the database.
    pub async fn drop(mut self, pools: impl IntoIterator<Item = PgPool>) {
        for pool in pools {
            pool.close().await;
        }
        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        execute(&mut admin, self.drop_statement()).await;
        self.dropped = true;
    }

    fn drop_statement(&self) -> String {
        format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name)
    }
}

/// A test that panics before [`TestDb::drop`] would leave its database
/// behind; this removes it on a separate thread with its own runtime, since
/// the test's runtime may be unwinding. Errors are ignored: the test has
/// already failed.
impl Drop for TestDb {
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        let admin_url = self.admin_url.clone();
        let statement = self.drop_statement();
        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            runtime.block_on(async {
                let mut admin = PgConnection::connect(&admin_url).await.ok()?;
                let _ = sqlx::raw_sql(AssertSqlSafe(statement))
                    .execute(&mut admin)
                    .await;
                Some(())
            })
        });
        let _ = cleanup.join();
    }
}

/// The template's name: a digest of every embedded migration's version and
/// checksum, so a changed or added migration gets a new template. The
/// digest only has to agree between the processes of one build.
fn template_name() -> String {
    let mut hasher = DefaultHasher::new();
    for migration in MIGRATOR.iter() {
        migration.version.hash(&mut hasher);
        migration.checksum.hash(&mut hasher);
    }
    format!("skyoauth_scn_tpl_{:016x}", hasher.finish())
}

/// Builds the template unless it exists. The caller holds the advisory lock.
async fn ensure_template(admin: &mut PgConnection, admin_url: &str, template: &str) {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)")
            .bind(template)
            .fetch_one(&mut *admin)
            .await
            .unwrap();
    if exists {
        return;
    }
    // Leftovers of a build that crashed; no one else builds while we hold
    // the lock.
    let stale: Vec<String> =
        sqlx::query_scalar("SELECT datname::text FROM pg_database WHERE starts_with(datname, $1)")
            .bind(format!("{template}_b"))
            .fetch_all(&mut *admin)
            .await
            .unwrap();
    for name in stale {
        execute(
            admin,
            format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
        )
        .await;
    }
    let building = format!("{template}_b{}", std::process::id());
    // UTF8 whatever the cluster's default encoding, as in
    // service/tests/common/mod.rs; only `template0` may be copied with
    // another encoding, so the cluster's locale must be UTF-8 or C/POSIX.
    execute(
        admin,
        format!("CREATE DATABASE {building} TEMPLATE template0 ENCODING 'UTF8'"),
    )
    .await;
    let pool = persistence::connect(&config_for(admin_url, &building))
        .await
        .unwrap();
    persistence::migrate(&pool).await.unwrap();
    pool.close().await;
    execute(
        admin,
        format!("ALTER DATABASE {building} RENAME TO {template}"),
    )
    .await;
}

fn config_for(admin_url: &str, database: &str) -> DatabaseConfig {
    let connect = PgConnectOptions::from_str(admin_url)
        .unwrap()
        .database(database);
    DatabaseConfig::new(connect, None, 4, Duration::from_secs(10)).unwrap()
}

/// Runs one statement built from generated names only (digits, hex and
/// underscores), never from input.
async fn execute(conn: &mut PgConnection, statement: String) {
    if let Err(err) = sqlx::raw_sql(AssertSqlSafe(statement.clone()))
        .execute(&mut *conn)
        .await
    {
        panic!("{statement}: {err}");
    }
}
