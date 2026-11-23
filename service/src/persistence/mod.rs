//! PostgreSQL connection pool, schema migrations and the typed registry
//! surface ([`registry`]).
//!
//! PostgreSQL is the authoritative store. The schema is defined by the
//! versioned SQL files in `service/migrations/` (no down migrations),
//! embedded into the binary at build time. Migrations are an explicit deploy
//! step (`skyoauth-service migrate`); the server never runs them on start.
//!
//! [`migrate`] refuses to proceed when:
//!
//! - an applied migration's checksum differs from the embedded file (it was
//!   edited after being applied);
//! - the database records a migration this binary does not know (the schema
//!   is newer than the binary);
//! - an earlier migration was left partially applied.
//!
//! Until the first beta release there is no database upgrade path: an
//! existing migration may be amended in place, so a database that applied an
//! earlier text of an amended migration fails the checksum check above and is
//! recreated, not migrated. The forward-only rule (applied files are never
//! edited; fix forward with a new file) starts at the beta release
//! (`service/migrations/README.md`, "Conventions").
//!
//! Concurrent runners, such as several replicas started at once, serialize on
//! a session-level PostgreSQL advisory lock held for the whole run, so each
//! migration is applied exactly once. The run uses a dedicated connection
//! that is closed afterwards, so a refused or failed run cannot leave the
//! lock held by a pooled connection. The lock needs a direct connection, not
//! a transaction-pooling proxy such as PgBouncer in transaction mode, and
//! waiting for it has no timeout; a lock timeout is a follow-up.
//!
//! TLS to the database is strict by default: without `sslmode` in the URL, a
//! remote host gets `verify-full` and a loopback or Unix-socket host gets
//! `prefer`, whatever `PGSSLMODE` says (see [`DatabaseConfig`]). "Remote" is
//! judged on the `hostaddr` when one is set (in the URL, through `PGHOSTADDR`
//! or as [`DatabaseConfig::new`]'s argument), because sqlx dials it instead of
//! the host name, and on the host name otherwise. An explicit weaker mode for
//! a remote host is accepted with a WARN log. sqlx's `sslmode=allow` is
//! plaintext only: it never negotiates TLS. Under `verify-ca` and
//! `verify-full` the server certificate must not be a CA: the self-signed
//! `CA:TRUE` certificate a default `openssl req -x509` produces fails with
//! `CaUsedAsEndEntity`, so issue the server a leaf certificate from a
//! separate CA and name that CA in `sslrootcert`.
//!
//! [`DatabaseConfig`]'s `Debug` shows the SSL mode and the `hostaddr` and
//! omits the password, and a URL whose user-info password has an unencoded
//! `@`, `/`, `?` or `#` is rejected before sqlx parses it, so a password in
//! the user-info part cannot surface as a database name or an unrecognized
//! query parameter. A `password` in the query string is a value like any
//! other, so the query is checked as well: a `#` fragment, a second `?`, a
//! key sqlx does not act on (sqlx logs it with its value; see
//! [`QUERY_KEYS`]) and a `?` in the user or database name are rejected, with
//! errors that repeat nothing from the URL. An unencoded `&` in a query
//! `password` followed by a supported key (`?password=a&user=b`) still
//! splits there undetected; percent-encode `&` as `%26`. The
//! connection-failure tests in `service/tests/redaction.rs` check that
//! errors and trace-level logs do not contain the password.

mod config;
pub mod registry;

pub use config::{
    ACQUIRE_TIMEOUT_VAR, ConfigError, DATABASE_URL_VAR, DatabaseConfig, MAX_CONNECTIONS_VAR,
    QUERY_KEYS,
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
///
/// sqlx releases its session-level advisory lock only when a run succeeds.
/// The run therefore gets its own connection, which never returns to the
/// pool: it is closed here, or on drop if this future is cancelled, and
/// closing the session releases the lock.
pub async fn migrate(pool: &PgPool) -> Result<(), MigrateError> {
    let mut conn = pool.acquire().await?;
    conn.close_on_drop();
    // `run_direct` is what `Migrator::run` calls; `run(&mut *conn)` would
    // make this future not `Send` ("`Acquire` is not general enough"). It
    // is `#[doc(hidden)]`, so sqlx is pinned exactly in Cargo.toml.
    let result = MIGRATOR.run_direct(None, &mut *conn, false).await;
    // A failed close only delays the release until the server notices.
    let _ = conn.close().await;
    result
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

    /// Replaces comments, quoted strings and identifiers, and dollar-quoted
    /// bodies (such as PL/pgSQL functions) with a space, leaving SQL code.
    /// Nested block comments are not handled.
    fn code_only(sql: &str) -> String {
        let mut out = String::with_capacity(sql.len());
        let mut rest = sql;
        while let Some(c) = rest.chars().next() {
            let skip = if rest.starts_with("--") {
                rest.find('\n').unwrap_or(rest.len())
            } else if let Some(comment) = rest.strip_prefix("/*") {
                comment.find("*/").map_or(rest.len(), |i| i + 4)
            } else if c == '\'' || c == '"' {
                rest[1..].find(c).map_or(rest.len(), |i| i + 2)
            } else if let Some(tag) = dollar_tag(rest) {
                rest[tag.len()..]
                    .find(tag)
                    .map_or(rest.len(), |i| 2 * tag.len() + i)
            } else {
                0
            };
            if skip > 0 {
                out.push(' ');
                rest = &rest[skip..];
            } else {
                out.push(c);
                rest = &rest[c.len_utf8()..];
            }
        }
        out
    }

    /// The `$tag$` opening a dollar-quoted string at the start of `sql`.
    fn dollar_tag(sql: &str) -> Option<&str> {
        let end = sql.strip_prefix('$')?.find('$')? + 2;
        let tag = &sql[1..end - 1];
        let valid = tag
            .chars()
            .enumerate()
            .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
        valid.then(|| &sql[..end])
    }

    /// Top-level statements that would end or nest the transaction sqlx runs
    /// each migration in.
    fn transaction_control(sql: &str) -> Vec<String> {
        code_only(sql)
            .split(';')
            .filter_map(|statement| {
                let words: Vec<String> = statement
                    .split_whitespace()
                    .take(2)
                    .map(str::to_ascii_uppercase)
                    .collect();
                let words: Vec<&str> = words.iter().map(String::as_str).collect();
                match words.as_slice() {
                    ["BEGIN" | "COMMIT" | "ROLLBACK" | "END" | "ABORT", ..]
                    | ["SAVEPOINT" | "RELEASE", ..]
                    | ["START" | "PREPARE", "TRANSACTION"] => Some(words.join(" ")),
                    _ => None,
                }
            })
            .collect()
    }

    #[test]
    fn transaction_control_lint_finds_statements_outside_comments_and_strings() {
        let flagged = transaction_control(
            "create table t (x int);\ncommit;\n  Begin ; START transaction; End;
             -- COMMIT;\n/* ROLLBACK; */ select 'commit; abort'; select \"end\";
             create function f() returns int language plpgsql as $body$
             begin return 1; end; $body$; select $$ rollback; $$;",
        );
        assert_eq!(flagged, ["COMMIT", "BEGIN", "START TRANSACTION", "END"]);
    }

    /// Each migration must stay inside the transaction sqlx wraps it in, so
    /// a failure rolls the whole file back. This lint is a test-time rule
    /// over the embedded SQL, not a runtime guarantee: the runner itself
    /// would execute such a statement.
    #[test]
    fn migrations_contain_no_transaction_control() {
        for migration in MIGRATOR.iter() {
            let flagged = transaction_control(migration.sql.as_str());
            assert!(
                flagged.is_empty(),
                "migration {} contains {flagged:?}",
                migration.version
            );
        }
    }

    /// Like the transaction lint, a test-time rule: the runner would accept
    /// gaps, down migrations and `-- no-transaction` files. "Forward-only"
    /// here means no down migrations; it says nothing about amending an
    /// applied file, which is allowed before the beta release (module docs).
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
