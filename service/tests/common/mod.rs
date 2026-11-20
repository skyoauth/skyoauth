//! Shared helper for the database integration tests.
//!
//! The tests need `SKYOAUTH_IT_DATABASE_URL`, a URL for a role that may
//! create databases; each test creates and drops its own database. They are
//! `#[ignore]`d, so runs without a database report them as ignored; run them
//! with `cargo nextest run --run-ignored all` (as the `service-nextest` CI
//! job does) or `cargo test -- --include-ignored`. An ignored test that is
//! run without the variable fails loudly instead of passing vacuously.

use std::{
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
        }
    }

    pub async fn pool(&self) -> PgPool {
        persistence::connect(&self.config).await.unwrap()
    }

    pub async fn drop(self, pools: impl IntoIterator<Item = PgPool>) {
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
