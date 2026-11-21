//! Tests of the harness's database teardown (`tests/src/pg.rs`): the retry
//! of `DROP DATABASE … WITH (FORCE)` on SQLSTATE 42501. They test the
//! harness, not the service, so they are not scenario tests: no name here
//! matches `a\d\d_`, and no stage of `tests/conformance/scenarios.toml`
//! lists them (layout §3: the registry checks only scenario-named tests).
//!
//! The retry tests drive [`retry_drop`] with an injected attempt that fails
//! with a fabricated database error, so they need no server; they still run
//! only in the `pg` target, the one CI runs. The live test forces the
//! refusal with a session of another role that holds the database, and
//! releases it only after the first refusal: no autovacuum timing.

use std::{
    borrow::Cow,
    error::Error as StdError,
    fmt,
    time::{Duration, Instant},
};

use skyoauth_scenarios::pg::{
    DROP_DEADLINE, DROP_POLL_INTERVAL, INSUFFICIENT_PRIVILEGE, IT_DATABASE_URL_VAR, TestDb,
    drop_database_once, is_insufficient_privilege, retry_drop,
};
use sqlx::{
    AssertSqlSafe, Connection, PgConnection,
    error::{DatabaseError, ErrorKind},
};
use tokio::sync::Notify;

/// A database error with SQLSTATE `code`, as the PostgreSQL driver returns.
#[derive(Debug)]
struct Fabricated(&'static str);

impl fmt::Display for Fabricated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fabricated error with SQLSTATE {}", self.0)
    }
}

impl StdError for Fabricated {}

impl DatabaseError for Fabricated {
    fn message(&self) -> &str {
        "fabricated error"
    }

    fn code(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.0))
    }

    fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

fn sqlstate(code: &'static str) -> sqlx::Error {
    sqlx::Error::Database(Box::new(Fabricated(code)))
}

/// SQLSTATE `object_in_use`, what a drop without FORCE returns for a
/// database in use: an error the retry must not swallow.
const OBJECT_IN_USE: &str = "55006";

#[test]
fn classifies_only_sqlstate_42501_as_insufficient_privilege() {
    assert!(is_insufficient_privilege(&sqlstate(INSUFFICIENT_PRIVILEGE)));
    assert!(!is_insufficient_privilege(&sqlstate(OBJECT_IN_USE)));
    assert!(!is_insufficient_privilege(&sqlstate("42P01")));
    assert!(!is_insufficient_privilege(&sqlx::Error::PoolTimedOut));
}

#[tokio::test]
async fn retry_drop_retries_42501_until_the_drop_succeeds() {
    let mut calls = 0;
    let attempts = retry_drop("db_x", DROP_DEADLINE, Duration::ZERO, async || {
        calls += 1;
        if calls <= 3 {
            Err(sqlstate(INSUFFICIENT_PRIVILEGE))
        } else {
            Ok(())
        }
    })
    .await
    .unwrap();
    assert_eq!((attempts, calls), (4, 4));
}

#[tokio::test]
async fn retry_drop_succeeds_at_once_without_retrying() {
    let mut calls = 0;
    let attempts = retry_drop("db_x", DROP_DEADLINE, DROP_POLL_INTERVAL, async || {
        calls += 1;
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!((attempts, calls), (1, 1));
}

#[tokio::test]
async fn retry_drop_fails_at_once_on_another_error() {
    let errors: [fn() -> sqlx::Error; 2] =
        [|| sqlstate(OBJECT_IN_USE), || sqlx::Error::PoolTimedOut];
    for error in errors {
        let mut calls = 0;
        let err = retry_drop("db_x", DROP_DEADLINE, DROP_POLL_INTERVAL, async || {
            calls += 1;
            Err(error())
        })
        .await
        .unwrap_err();
        assert_eq!((err.attempts, calls, err.deadline), (1, 1, None));
        assert_eq!(err.database, "db_x");
        let message = err.to_string();
        assert!(
            message.starts_with("DROP DATABASE db_x WITH (FORCE) failed: "),
            "{message}"
        );
        assert!(!message.contains(INSUFFICIENT_PRIVILEGE), "{message}");
    }
}

#[tokio::test]
async fn retry_drop_fails_after_another_error_that_follows_42501() {
    let mut calls = 0;
    let err = retry_drop("db_x", DROP_DEADLINE, Duration::ZERO, async || {
        calls += 1;
        Err(sqlstate(if calls < 3 {
            INSUFFICIENT_PRIVILEGE
        } else {
            OBJECT_IN_USE
        }))
    })
    .await
    .unwrap_err();
    assert_eq!((err.attempts, calls, err.deadline), (3, 3, None));
    assert_eq!(
        err.error.as_database_error().unwrap().code().unwrap(),
        OBJECT_IN_USE
    );
}

/// With a zero deadline the first 42501 is already at the deadline: one
/// attempt, no wait.
#[tokio::test]
async fn retry_drop_gives_up_on_42501_at_a_zero_deadline() {
    let mut calls = 0;
    let err = retry_drop("db_x", Duration::ZERO, DROP_POLL_INTERVAL, async || {
        calls += 1;
        Err(sqlstate(INSUFFICIENT_PRIVILEGE))
    })
    .await
    .unwrap_err();
    assert_eq!(
        (err.attempts, calls, err.deadline),
        (1, 1, Some(Duration::ZERO))
    );
    assert!(is_insufficient_privilege(&err.error));
}

/// A drop that keeps failing with 42501 is retried until the deadline and
/// then fails with the last error, naming the database. Only lower bounds
/// on time are asserted, so a slow runner cannot fail it.
#[tokio::test]
async fn retry_drop_gives_up_on_42501_at_the_deadline() {
    let (deadline, interval) = (Duration::from_millis(60), Duration::from_millis(10));
    let mut calls = 0;
    let start = Instant::now();
    let err = retry_drop("db_x", deadline, interval, async || {
        calls += 1;
        Err(sqlstate(INSUFFICIENT_PRIVILEGE))
    })
    .await
    .unwrap_err();
    assert!(start.elapsed() >= deadline);
    assert_eq!(err.deadline, Some(deadline));
    assert_eq!(err.attempts, calls);
    // The first attempt, and at least the last one at the deadline.
    assert!(calls >= 2, "{calls} attempts");
    assert!(is_insufficient_privilege(&err.error));
    let message = err.to_string();
    assert!(
        message.starts_with("DROP DATABASE db_x WITH (FORCE) failed with SQLSTATE 42501 for 60ms"),
        "{message}"
    );
    assert!(
        message.contains("GRANT pg_signal_backend TO <role>"),
        "{message}"
    );
}

async fn execute(conn: &mut PgConnection, statement: String) {
    if let Err(err) = sqlx::raw_sql(AssertSqlSafe(statement.clone()))
        .execute(&mut *conn)
        .await
    {
        panic!("{statement}: {err}");
    }
}

/// The refusal on a live server, whatever the role of
/// `SKYOAUTH_IT_DATABASE_URL`: the drop runs as `dropper` (`SET ROLE`), a
/// role with no attributes that owns the test's database and is not in
/// `pg_signal_backend`, while a session of `holder`, another such role,
/// stays connected to it. PostgreSQL refuses with 42501 until the holder's
/// session is closed, which happens only after the first refusal; the
/// retry then drops the database.
#[tokio::test]
async fn drop_database_force_retries_while_another_roles_backend_holds_it() {
    let mut db = TestDb::create().await;
    let (dropper, dropper_pool) = db.create_login_role(&[], 1).await;
    let (_holder, holder_pool) = db.create_login_role(&[], 1).await;
    dropper_pool.close().await;
    let mut held = holder_pool.acquire().await.unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()::text")
        .fetch_one(&mut *held)
        .await
        .unwrap();

    let admin_url = std::env::var(IT_DATABASE_URL_VAR).unwrap();
    let mut admin = PgConnection::connect(&admin_url).await.unwrap();
    execute(&mut admin, format!("GRANT {dropper} TO current_user")).await;
    execute(
        &mut admin,
        format!("ALTER DATABASE {database} OWNER TO {dropper}"),
    )
    .await;
    execute(&mut admin, format!("SET ROLE {dropper}")).await;

    let refused = Notify::new();
    let mut codes = Vec::new();
    let drop = retry_drop(&database, DROP_DEADLINE, DROP_POLL_INTERVAL, async || {
        let result = drop_database_once(&mut admin, &database).await;
        if let Err(err) = &result {
            codes.push(
                err.as_database_error()
                    .and_then(|db| db.code())
                    .map(Cow::into_owned),
            );
            if is_insufficient_privilege(err) {
                // Stores a permit when no one waits yet.
                refused.notify_one();
            }
        }
        result
    });
    let release = async {
        refused.notified().await;
        held.close().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(drop, release);
    let attempts = outcome.unwrap_or_else(|err| panic!("{err}"));

    assert!(attempts >= 2, "{attempts} attempts");
    assert_eq!(codes.len(), usize::try_from(attempts - 1).unwrap());
    assert!(
        codes
            .iter()
            .all(|code| code.as_deref() == Some(INSUFFICIENT_PRIVILEGE)),
        "{codes:?}"
    );
    execute(&mut admin, "RESET ROLE".to_owned()).await;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)")
            .bind(&database)
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert!(!exists, "{database} still exists");
    let _ = admin.close().await;
    // The database is gone; this drops the two roles.
    db.drop([holder_pool]).await;
}
