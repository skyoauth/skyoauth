//! Shared helper for the database integration tests.
//!
//! The tests need `SKYOAUTH_IT_DATABASE_URL`, a URL for a role that may
//! create databases (`CREATEDB`); each test creates and drops its own
//! database. Tests that create login roles also need `CREATEROLE`, and the
//! replica-role tests `GRANT SET ON PARAMETER session_replication_role`
//! (PostgreSQL 15 or later); no test needs a superuser. They are
//! `#[ignore]`d, so runs without a database report them as ignored; run them
//! with `cargo nextest run --run-ignored all` (as the `service-nextest` CI
//! job does) or `cargo test -- --include-ignored`. An ignored test that is
//! run without the variable fails loudly instead of passing vacuously.

use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use skyoauth_service::persistence::{self, DatabaseConfig, PgPool};
use sqlx::{AssertSqlSafe, Connection, PgConnection, postgres::PgConnectOptions};

const IT_DATABASE_URL_VAR: &str = "SKYOAUTH_IT_DATABASE_URL";

pub struct TestDb {
    admin_url: String,
    name: String,
    config: DatabaseConfig,
    /// Login roles created for this test; dropped after the database.
    roles: Vec<String>,
    /// Set by [`TestDb::drop`]; otherwise `Drop` cleans up.
    dropped: bool,
}

impl TestDb {
    /// Creates a fresh, empty database.
    ///
    /// # Panics
    ///
    /// When `SKYOAUTH_IT_DATABASE_URL` is unset or empty.
    pub async fn create() -> Self {
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
        let config = DatabaseConfig::new(connect, 4, Duration::from_secs(10)).unwrap();
        Self {
            admin_url,
            name,
            config,
            roles: Vec::new(),
            dropped: false,
        }
    }

    pub async fn pool(&self) -> PgPool {
        persistence::connect(&self.config).await.unwrap()
    }

    /// A pool for this test's database whose sessions start with
    /// `search_path` set to `search_path`.
    #[allow(dead_code, reason = "not every test binary sets a search_path")]
    pub async fn pool_with_search_path(&self, search_path: &str) -> PgPool {
        let connect = PgConnectOptions::from_str(&self.admin_url)
            .unwrap()
            .database(&self.name)
            .options([("search_path", search_path)]);
        let config = DatabaseConfig::new(connect, 4, Duration::from_secs(10)).unwrap();
        persistence::connect(&config).await.unwrap()
    }

    /// Creates a login role with no attributes (not a superuser, owns
    /// nothing) and returns its name and options to connect to this test's
    /// database as it. It gets only the privileges `PUBLIC` has; the test
    /// grants the rest. It is dropped with the database.
    ///
    /// # Panics
    ///
    /// When the role of `SKYOAUTH_IT_DATABASE_URL` may not create roles.
    #[allow(dead_code, reason = "not every test binary creates roles")]
    pub async fn create_login_role(&mut self) -> (String, PgConnectOptions) {
        // Roles are cluster-wide, so the name derives from the database's.
        let role = format!("{}_role{}", self.name, self.roles.len());
        let password = format!(
            "{:016x}{:016x}",
            RandomState::new().hash_one(&role),
            RandomState::new().hash_one(&self.name)
        );
        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        // The role name is digits and underscores, the password hex digits.
        sqlx::raw_sql(AssertSqlSafe(format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{password}'"
        )))
        .execute(&mut admin)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "CREATE ROLE failed: {err}; this test needs the role of \
                 {IT_DATABASE_URL_VAR} to have CREATEROLE (or be a superuser)"
            )
        });
        self.roles.push(role.clone());
        let connect = PgConnectOptions::from_str(&self.admin_url)
            .unwrap()
            .database(&self.name)
            .username(&role)
            .password(&password);
        (role, connect)
    }

    /// One statement each: `DROP DATABASE` cannot run in the implicit
    /// transaction of a multi-statement query.
    fn cleanup_statements(&self) -> Vec<String> {
        let database = format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name);
        let roles = self
            .roles
            .iter()
            .map(|role| format!("DROP ROLE IF EXISTS {role}"));
        std::iter::once(database).chain(roles).collect()
    }

    pub async fn drop(mut self, pools: impl IntoIterator<Item = PgPool>) {
        for pool in pools {
            pool.close().await;
        }
        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        for statement in self.cleanup_statements() {
            sqlx::raw_sql(AssertSqlSafe(statement))
                .execute(&mut admin)
                .await
                .unwrap();
        }
        self.dropped = true;
    }
}

/// A test that panics before [`TestDb::drop`] would leave its database and
/// roles behind; this removes them on a separate thread with its own
/// runtime, since the test's runtime may be unwinding. Errors are ignored:
/// the test has already failed.
impl Drop for TestDb {
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        let admin_url = self.admin_url.clone();
        let statements = self.cleanup_statements();
        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            runtime.block_on(async {
                let mut admin = PgConnection::connect(&admin_url).await.ok()?;
                for statement in statements {
                    let _ = sqlx::raw_sql(AssertSqlSafe(statement))
                        .execute(&mut admin)
                        .await;
                }
                Some(())
            })
        });
        let _ = cleanup.join();
    }
}
