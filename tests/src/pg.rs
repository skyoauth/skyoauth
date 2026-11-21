//! PostgreSQL isolation for the `pg` target (conformance layout §1.1: a
//! template database per test).
//!
//! The tests need `SKYOAUTH_IT_DATABASE_URL`, a URL for a role that may
//! create databases (`CREATEDB`) and, for the tests that call
//! [`TestDb::create_login_role`] (A24), roles (`CREATEROLE`). CI connects as
//! a superuser. A role that is not one also needs membership in
//! `pg_signal_backend` (`GRANT pg_signal_backend TO <role>`): the harness
//! drops databases with `DROP DATABASE … WITH (FORCE)`, which terminates the
//! backends still connected to them, and without that membership PostgreSQL
//! refuses (SQLSTATE 42501, "permission denied to terminate process") while
//! a backend of another role is among them, such as an autovacuum worker or
//! a session of a login role of [`TestDb::create_login_role`].
//! [`drop_database`] retries that refusal until [`DROP_DEADLINE`], so a
//! backend that exits by itself (autovacuum on a small database) does not
//! fail the test, but one that stays fails it. The pools of [`TestDb::pool`]
//! and [`TestDb::pool_with_max_connections`], the replicas' included,
//! connect as that role, so a test may terminate their backends
//! ([`crate::rep::terminate`]) without `pg_signal_backend`. Without the
//! variable [`TestDb::create`] panics: a scenario test never passes
//! vacuously (layout §1.2, "Loud failure"), and scenario tests are never
//! `#[ignore]`d.
//!
//! No test of this package sets `session_replication_role`, so a role that
//! is not a superuser needs no `GRANT SET ON PARAMETER
//! session_replication_role TO <role>` here; the replica-role tests of
//! `service/tests` need it, and fail with SQLSTATE 42501 without it
//! (README.md).
//!
//! Timing. Retrying a refused `DROP DATABASE` has no event to wait on, so
//! [`drop_database`] polls every [`DROP_POLL_INTERVAL`] until
//! [`DROP_DEADLINE`], like [`crate::rep::wait_until_blocked`]: a bounded
//! wait on an observed condition (the statement succeeding), never a fixed
//! sleep that stands in for one, and the only other exception to the
//! no-sleep rule (layout §4).
//!
//! Every migration of `skyoauth-service` is applied once to a template
//! database, and each test gets a fresh copy of it (`CREATE DATABASE …
//! TEMPLATE …`), which is faster than migrating an empty database per test.
//! The template is named after a digest of the embedded migrations and a
//! digest of the connecting role (`current_user`): a role without
//! superuser may copy only a database it owns, so each role builds and
//! copies its own template. The template is built under a temporary name
//! and renamed when complete, so a crash mid-build never leaves a
//! half-migrated template behind. It stays in the cluster for later runs
//! with the same migrations and role; a changed migration set, another
//! role or another Rust release (which may change the digest) builds a new
//! one, and the old ones accumulate until dropped by hand
//! (`DROP DATABASE skyoauth_scn_tpl_…`). Concurrent test processes (nextest
//! runs each test in its own process) serialize the build and the copies on
//! a session-level advisory lock, because a database cannot be copied while
//! another session is connected to it.
//!
//! Duplication: the per-test database, its cleanup on drop and the UTF8
//! encoding rule (and [`TestDb::create_login_role`]) are adapted from
//! `service/tests/common/mod.rs`, which is a
//! test module of the service package and cannot be imported from here.
//! Keep the two in step until a shared test-support crate is justified.

use std::{
    collections::hash_map::RandomState,
    fmt,
    hash::{BuildHasher, DefaultHasher, Hash, Hasher},
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use skyoauth_service::persistence::{self, DatabaseConfig, MIGRATOR, PgPool};
use sqlx::{AssertSqlSafe, Connection, PgConnection, postgres::PgConnectOptions};
use tokio::time::Instant;

/// The variable that names the PostgreSQL server of the `pg` environment.
pub const IT_DATABASE_URL_VAR: &str = "SKYOAUTH_IT_DATABASE_URL";

/// How long [`drop_database`] retries a `DROP DATABASE … WITH (FORCE)`
/// that PostgreSQL refuses with SQLSTATE 42501 before it gives up: long
/// enough for an autovacuum worker on a test database to finish.
pub const DROP_DEADLINE: Duration = Duration::from_secs(5);

/// How often [`drop_database`] retries.
pub const DROP_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// SQLSTATE `insufficient_privilege`, which `DROP DATABASE … WITH (FORCE)`
/// returns when it may not terminate a backend connected to the database.
pub const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// The advisory lock key that serializes template builds and copies across
/// test processes (an arbitrary constant; "skyoauth" in ASCII, truncated).
const TEMPLATE_LOCK_KEY: i64 = 0x736b_796f_6175_7468;

/// A fresh database, copied from the migrated template, for one test.
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
                     (a postgres:// URL for a role with CREATEDB, and CREATEROLE for the tests that create roles)"
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
        let mut admin = PgConnection::connect(&admin_url).await.unwrap();
        let role: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&mut admin)
            .await
            .unwrap();
        let template = template_name(&role);
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
            config: config_for(&admin_url, &name, 4),
            admin_url,
            name,
            roles: Vec::new(),
            dropped: false,
        }
    }

    /// A new pool for this test's database.
    pub async fn pool(&self) -> PgPool {
        persistence::connect(&self.config).await.unwrap()
    }

    /// A new pool for this test's database with at most `max_connections`
    /// connections (1 to 100); [`TestDb::pool`] has 4. The replica harness
    /// ([`crate::rep`]) gives each replica a pool of 1.
    pub async fn pool_with_max_connections(&self, max_connections: u32) -> PgPool {
        let config = config_for(&self.admin_url, &self.name, max_connections);
        persistence::connect(&config).await.unwrap()
    }

    /// Creates a login role with no attributes (not a superuser, owns
    /// nothing), runs `GRANT {grant} TO {role}` in this test's database for
    /// each of `grants` (test-written SQL such as `"SELECT, UPDATE ON
    /// consumed_assertion"`, never input), and returns the role's name and
    /// a pool of `max_connections` connecting as it. Beyond `grants` it has
    /// only the privileges of `PUBLIC`. It is dropped after the database.
    ///
    /// # Panics
    ///
    /// When the role of `SKYOAUTH_IT_DATABASE_URL` may not create roles
    /// (`CREATEROLE`) or grant these privileges.
    pub async fn create_login_role(
        &mut self,
        grants: &[&str],
        max_connections: u32,
    ) -> (String, PgPool) {
        // Roles are cluster-wide, so the name derives from the database's:
        // digits and underscores; the password is hex digits.
        let role = format!("{}_role{}", self.name, self.roles.len());
        let password = format!("{:016x}", RandomState::new().hash_one(&role));
        let connect = PgConnectOptions::from_str(&self.admin_url)
            .unwrap()
            .database(&self.name);
        let mut admin = PgConnection::connect_with(&connect).await.unwrap();
        let create = format!("CREATE ROLE {role} LOGIN PASSWORD '{password}'");
        execute(&mut admin, create).await;
        self.roles.push(role.clone());
        for grant in grants {
            execute(&mut admin, format!("GRANT {grant} TO {role}")).await;
        }
        let _ = admin.close().await;
        let connect = connect.username(&role).password(&password);
        let config = DatabaseConfig::new(connect, None, max_connections, Duration::from_secs(10));
        (role, persistence::connect(&config.unwrap()).await.unwrap())
    }

    /// Closes `pools` and drops the database ([`drop_database`]), then the
    /// login roles.
    ///
    /// # Panics
    ///
    /// When the database or a role cannot be dropped.
    pub async fn drop(mut self, pools: impl IntoIterator<Item = PgPool>) {
        for pool in pools {
            pool.close().await;
        }
        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        if let Err(err) = drop_database(&mut admin, &self.name).await {
            panic!("{err}");
        }
        for statement in self.role_cleanup_statements() {
            execute(&mut admin, statement).await;
        }
        self.dropped = true;
    }

    /// One statement per role, run after the database is dropped: a role
    /// with privileges in a database cannot be dropped before it.
    fn role_cleanup_statements(&self) -> Vec<String> {
        (self.roles.iter())
            .map(|role| format!("DROP ROLE IF EXISTS {role}"))
            .collect()
    }
}

/// A test that panics before [`TestDb::drop`] would leave its database and
/// roles behind; this removes them on a separate thread with its own runtime, since
/// the test's runtime may be unwinding. Errors are ignored: the test has
/// already failed.
impl Drop for TestDb {
    fn drop(&mut self) {
        if self.dropped {
            return;
        }
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        let statements = self.role_cleanup_statements();
        let cleanup = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok()?;
            runtime.block_on(async {
                let mut admin = PgConnection::connect(&admin_url).await.ok()?;
                let _ = drop_database(&mut admin, &name).await;
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

/// The template's name for `role`: `skyoauth_scn_tpl_<migrations>_<role>`,
/// two hex digests. The first covers every embedded migration's version and
/// checksum, so a changed or added migration gets a new template; the
/// second covers the role name, so the name stays a plain identifier (lower
/// hex and underscores, 42 bytes, well under PostgreSQL's 63-byte limit
/// even with the `_b<pid>` build suffix) whatever characters the role name
/// holds. The digests only have to agree between the processes of one
/// build.
fn template_name(role: &str) -> String {
    let mut migrations = DefaultHasher::new();
    for migration in MIGRATOR.iter() {
        migration.version.hash(&mut migrations);
        migration.checksum.hash(&mut migrations);
    }
    let mut owner = DefaultHasher::new();
    role.hash(&mut owner);
    format!(
        "skyoauth_scn_tpl_{:016x}_{:08x}",
        migrations.finish(),
        owner.finish() & 0xffff_ffff
    )
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
        if let Err(err) = drop_database(admin, &name).await {
            panic!("{err}");
        }
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
    let pool = persistence::connect(&config_for(admin_url, &building, 4))
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

fn config_for(admin_url: &str, database: &str, max_connections: u32) -> DatabaseConfig {
    let connect = PgConnectOptions::from_str(admin_url)
        .unwrap()
        .database(database);
    DatabaseConfig::new(connect, None, max_connections, Duration::from_secs(10)).unwrap()
}

/// Drops `database` with `DROP DATABASE IF EXISTS … WITH (FORCE)` through
/// `conn`, retrying while PostgreSQL refuses with SQLSTATE 42501
/// ([`retry_drop`] with [`DROP_DEADLINE`] and [`DROP_POLL_INTERVAL`]).
/// `database` is a generated name (digits, hex and underscores), never
/// input. Returns the number of attempts.
///
/// # Errors
///
/// Any other error at once, and SQLSTATE 42501 still at the deadline
/// ([`DropError`], which names the database).
pub async fn drop_database(conn: &mut PgConnection, database: &str) -> Result<u32, DropError> {
    retry_drop(database, DROP_DEADLINE, DROP_POLL_INTERVAL, async || {
        drop_database_once(&mut *conn, database).await
    })
    .await
}

/// One `DROP DATABASE IF EXISTS {database} WITH (FORCE)`, not retried.
/// `database` is as for [`drop_database`].
///
/// # Errors
///
/// What PostgreSQL returns.
pub async fn drop_database_once(conn: &mut PgConnection, database: &str) -> sqlx::Result<()> {
    let statement = format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)");
    sqlx::raw_sql(AssertSqlSafe(statement))
        .execute(conn)
        .await
        .map(|_| ())
}

/// Runs `attempt`, the drop of `database`, until it succeeds, retrying
/// every `interval` while it fails with SQLSTATE 42501
/// ([`is_insufficient_privilege`]) and `deadline` has not passed since the
/// first attempt; the last retry runs at the deadline. Returns the number
/// of attempts. [`drop_database`] is this with the harness's bounds; the
/// parameters are for testing the retry itself.
///
/// # Errors
///
/// The first error that is not SQLSTATE 42501, at once; or the last 42501
/// error when it still fails at the deadline.
pub async fn retry_drop(
    database: &str,
    deadline: Duration,
    interval: Duration,
    mut attempt: impl AsyncFnMut() -> sqlx::Result<()>,
) -> Result<u32, DropError> {
    let start = Instant::now();
    let mut attempts = 0;
    loop {
        attempts += 1;
        let error = match attempt().await {
            Ok(()) => return Ok(attempts),
            Err(error) => error,
        };
        let elapsed = start.elapsed();
        let denied = is_insufficient_privilege(&error);
        if !denied || elapsed >= deadline {
            return Err(DropError {
                database: database.to_owned(),
                attempts,
                deadline: denied.then_some(deadline),
                error,
            });
        }
        tokio::time::sleep(interval.min(deadline - elapsed)).await;
    }
}

/// Whether `error` is PostgreSQL's SQLSTATE 42501 (`insufficient_privilege`).
pub fn is_insufficient_privilege(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| code == INSUFFICIENT_PRIVILEGE)
}

/// A failed [`retry_drop`].
#[derive(Debug)]
pub struct DropError {
    /// The database that was not dropped.
    pub database: String,
    /// How many times the drop was tried.
    pub attempts: u32,
    /// The deadline, when the drop still failed with SQLSTATE 42501 at it;
    /// `None` when it failed with another error, which is never retried.
    pub deadline: Option<Duration>,
    /// The last error.
    pub error: sqlx::Error,
}

impl fmt::Display for DropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            database,
            attempts,
            deadline,
            error,
        } = self;
        write!(f, "DROP DATABASE {database} WITH (FORCE) failed")?;
        if let Some(deadline) = deadline {
            write!(
                f,
                " with SQLSTATE {INSUFFICIENT_PRIVILEGE} for {deadline:?} ({attempts} attempts; \
                 a role that is not a superuser needs `GRANT pg_signal_backend TO <role>`)"
            )?;
        }
        write!(f, ": {error}")
    }
}

impl std::error::Error for DropError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Runs one statement built from generated names only (digits, hex and
/// underscores) or test-written SQL ([`TestDb::create_login_role`]), never
/// from input.
async fn execute(conn: &mut PgConnection, statement: String) {
    if let Err(err) = sqlx::raw_sql(AssertSqlSafe(statement.clone()))
        .execute(&mut *conn)
        .await
    {
        panic!("{statement}: {err}");
    }
}
