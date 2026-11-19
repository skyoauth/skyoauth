//! PostgreSQL connection pool and schema migrations.
//!
//! PostgreSQL is the authoritative store. The schema is defined by the
//! forward-only, versioned SQL files in `service/migrations/`, embedded into
//! the binary at build time. Migrations are an explicit deploy step
//! (`skyoauth-service migrate`); the server never runs them on start.
//!
//! [`migrate`] refuses to proceed when:
//!
//! - an applied migration's checksum differs from the embedded file (it was
//!   edited after being applied);
//! - the database records a migration this binary does not know (the schema
//!   is newer than the binary);
//! - an earlier migration was left partially applied.
//!
//! Concurrent runners, such as several replicas started at once, serialize on
//! a PostgreSQL advisory lock held for the whole run, so each migration is
//! applied exactly once.

mod config;

pub use config::{
    ACQUIRE_TIMEOUT_VAR, ConfigError, DATABASE_URL_VAR, DatabaseConfig, MAX_CONNECTIONS_VAR,
};
pub use sqlx::{PgPool, migrate::MigrateError};

use sqlx::{migrate::Migrator, postgres::PgPoolOptions};

/// The embedded migrations, in version order.
///
/// This uses sqlx's defaults, which [`migrate`] relies on: the advisory lock
/// is taken and applied migrations missing from the binary are an error.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Opens a connection pool and verifies it by establishing one connection.
pub async fn connect(config: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_connections())
        .acquire_timeout(config.acquire_timeout())
        .connect_with(config.connect_options().clone())
        .await
}

/// Applies every embedded migration not yet applied, in version order.
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::migrate::MigrationType;

    #[test]
    fn migrator_locks_and_refuses_unknown_applied_migrations() {
        assert!(MIGRATOR.locking);
        assert!(!MIGRATOR.ignore_missing);
    }

    #[test]
    fn migrations_are_forward_only_contiguous_and_transactional() {
        let migrations: Vec<_> = MIGRATOR.iter().collect();
        assert!(!migrations.is_empty());
        for (index, migration) in migrations.iter().enumerate() {
            let expected = i64::try_from(index).unwrap() + 1;
            assert_eq!(migration.version, expected, "versions must be 1, 2, 3, ...");
            assert_eq!(migration.migration_type, MigrationType::Simple);
            assert!(
                !migration.no_tx,
                "migration {} must be transactional",
                migration.version
            );
        }
    }
}
