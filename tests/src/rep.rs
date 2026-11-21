//! The replica harness (REP) of the `pg` environment (conformance layout
//! §1.1, §1.2): N service replicas on one PostgreSQL database, released
//! together by a barrier, for the atomicity scenarios (A24, A34).
//!
//! A replica is a pool of exactly one connection to the test's database
//! ([`TestDb::pool_with_max_connections`]), so each replica is one backend
//! session, as one replica process with its own pool would be, and its
//! backend PID can be named in `pg_blocking_pids` and
//! `pg_terminate_backend`. [`Replicas::race`] has every replica acquire its
//! connection first and then wait on a [`Barrier`] of N, so no replica
//! starts its work while another is still connecting.
//!
//! A barrier only starts the replicas together; it cannot make their
//! statements overlap. A test that must see the contended interleaving
//! forces it: a holder session (an observer pool's connection, outside the
//! replicas) opens a transaction and takes the lock the work needs, the
//! race starts, [`wait_until_blocked`] waits until PostgreSQL reports every
//! replica blocked behind the holder (`pg_blocking_pids`), and only then
//! the holder commits or rolls back. The two run side by side, for example with
//! `tokio::join!(replicas.race(work), release_holder)`.
//!
//! Timing. Scenario tests never sleep to synchronize (layout §4). Waiting
//! for PostgreSQL to report a lock wait has no event to wait on, so
//! [`wait_until_blocked`] polls `pg_blocking_pids` every [`POLL_INTERVAL`]
//! until a [`DEADLINE`]: one of the two exceptions (the other is the retry
//! of a refused `DROP DATABASE` in [`crate::pg::drop_database`]), a bounded
//! wait on an observed condition, never a fixed sleep that stands in for
//! one. Every other wait here ([`Replicas::race`], [`terminate`]) is
//! bounded by [`DEADLINE`] too, so a lost wake-up fails the test instead of
//! hanging it.
//!
//! Nothing here is a test, and no name matches `a\d\d_` (layout §1.2).

use std::{future::Future, sync::Arc, time::Duration};

use skyoauth_service::persistence::PgPool;
use sqlx::{PgConnection, Postgres, pool::PoolConnection};
use tokio::{sync::Barrier, task::JoinSet, time::Instant};

use crate::pg::TestDb;

/// How long a race, a lock wait or a termination may take before the test
/// fails: generous for a loaded CI runner, and the same bound as the
/// lock-wait helper of `service/tests/registry.rs`.
pub const DEADLINE: Duration = Duration::from_secs(10);

/// How often [`wait_until_blocked`] polls `pg_blocking_pids`.
pub const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// N replicas, each a pool of one connection to the same test database.
pub struct Replicas {
    pools: Vec<PgPool>,
}

impl Replicas {
    /// Starts `n` replicas on `db`.
    ///
    /// # Panics
    ///
    /// When `n < 2`: a race needs two replicas.
    pub async fn start(db: &TestDb, n: usize) -> Self {
        assert!(n >= 2, "a replica race needs at least 2 replicas, got {n}");
        let mut pools = Vec::with_capacity(n);
        for _ in 0..n {
            pools.push(db.pool_with_max_connections(1).await);
        }
        Self { pools }
    }

    /// The replicas' pools, indexed by replica.
    pub fn pools(&self) -> &[PgPool] {
        &self.pools
    }

    /// The pools, for [`TestDb::drop`].
    pub fn into_pools(self) -> Vec<PgPool> {
        self.pools
    }

    /// Each replica's backend PID, indexed by replica: the PID of its one
    /// connection, which stays the same while that connection lives (the
    /// pool replaces it only after it is closed, for example by
    /// [`terminate`]). Call it before [`Replicas::race`] to name the
    /// replicas in [`wait_until_blocked`].
    pub async fn backend_pids(&self) -> Vec<i32> {
        let mut pids = Vec::with_capacity(self.pools.len());
        for pool in &self.pools {
            pids.push(backend_pid(&mut pool.acquire().await.unwrap()).await);
        }
        pids
    }

    /// Runs `work(replica, connection)` on every replica at once and
    /// returns the outcomes indexed by replica. Each replica runs in its
    /// own task (in parallel on a multi-thread runtime): it acquires its
    /// connection, waits on a barrier until every replica has its
    /// connection, then runs `work`.
    ///
    /// # Panics
    ///
    /// When a replica cannot acquire its connection or `work` panics (the
    /// panic is resumed here), or when the replicas have not all finished
    /// within [`DEADLINE`]; the unfinished ones are then aborted.
    pub async fn race<F, Fut, T>(&self, work: F) -> Vec<T>
    where
        F: Fn(usize, PoolConnection<Postgres>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let n = self.pools.len();
        let barrier = Arc::new(Barrier::new(n));
        let work = Arc::new(work);
        let mut tasks = JoinSet::new();
        for (replica, pool) in self.pools.iter().cloned().enumerate() {
            let (barrier, work) = (Arc::clone(&barrier), Arc::clone(&work));
            tasks.spawn(async move {
                let conn = pool.acquire().await.unwrap_or_else(|err| {
                    panic!("replica {replica} could not acquire its connection: {err}")
                });
                barrier.wait().await;
                (replica, work(replica, conn).await)
            });
        }
        let deadline = Instant::now() + DEADLINE;
        let mut outcomes: Vec<Option<T>> = (0..n).map(|_| None).collect();
        while !tasks.is_empty() {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok((replica, outcome)))) => outcomes[replica] = Some(outcome),
                Ok(Some(Err(err))) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
                Ok(Some(Err(err))) => panic!("a replica task failed: {err}"),
                Ok(None) => break,
                Err(_) => {
                    let pending: Vec<usize> = (0..n).filter(|&r| outcomes[r].is_none()).collect();
                    // Dropping the set aborts the remaining tasks.
                    panic!("replicas {pending:?} did not finish within {DEADLINE:?}");
                }
            }
        }
        outcomes.into_iter().map(Option::unwrap).collect()
    }
}

/// The backend PID of `conn`'s session.
pub async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// Waits until every backend in `blocked` waits, in one observation, for a
/// lock that `holder` holds: directly, or queued behind another waiter for
/// it, as row-lock waiters after the first wait for that first one. It
/// follows `pg_blocking_pids` transitively, polling through `observer` (a
/// pool that is neither the holder nor a blocked replica) every
/// [`POLL_INTERVAL`]. This polling is one of the two exceptions to the
/// no-sleep rule (module documentation).
///
/// # Panics
///
/// When they are not all blocked behind `holder` within [`DEADLINE`]; the
/// message names the ones that were not at the last observation.
pub async fn wait_until_blocked(observer: &PgPool, blocked: &[i32], holder: i32) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let not_yet: Vec<i32> = sqlx::query_scalar(
            "WITH RECURSIVE behind (waiter, pid) AS ( \
                 SELECT p, p FROM unnest($1::int4[]) AS p \
                 UNION \
                 SELECT behind.waiter, ahead \
                 FROM behind, unnest(pg_blocking_pids(behind.pid)) AS ahead \
             ) \
             SELECT p FROM unnest($1::int4[]) AS p \
             WHERE NOT EXISTS (SELECT FROM behind WHERE waiter = p AND pid = $2 AND p <> $2)",
        )
        .bind(blocked)
        .bind(holder)
        .fetch_all(observer)
        .await
        .unwrap();
        if not_yet.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "backends {not_yet:?} were not blocked behind {holder} within {DEADLINE:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Terminates the backend `pid` through `observer` with
/// `pg_terminate_backend` and waits, up to [`DEADLINE`], until it has
/// exited, so the session's statements fail as a lost database connection
/// does. The observer's role must be a superuser, the backend's role or a
/// member of `pg_signal_backend`.
///
/// # Panics
///
/// When the backend does not exist or has not exited within [`DEADLINE`].
pub async fn terminate(observer: &PgPool, pid: i32) {
    let timeout_ms = i64::try_from(DEADLINE.as_millis()).unwrap();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1, $2)")
        .bind(pid)
        .bind(timeout_ms)
        .fetch_one(observer)
        .await
        .unwrap();
    assert!(
        terminated,
        "backend {pid} was not terminated within {DEADLINE:?}"
    );
}

/// Sets `statement_timeout` for the rest of `conn`'s session, so a
/// statement that waits longer fails (SQLSTATE 57014) instead of hanging
/// the test. Pooled connections keep it after they return to the pool.
/// The timeout is rounded up to whole milliseconds, PostgreSQL's unit, so
/// any non-zero duration, even one under a microsecond, sets at least 1 ms;
/// only [`Duration::ZERO`] turns the timeout off.
pub async fn set_statement_timeout(conn: &mut PgConnection, timeout: Duration) {
    set_timeout(conn, timeout, false).await;
}

/// Sets `statement_timeout` until the end of `conn`'s current transaction
/// (`SET LOCAL`); outside a transaction it has no effect. Rounded as for
/// [`set_statement_timeout`].
pub async fn set_local_statement_timeout(conn: &mut PgConnection, timeout: Duration) {
    set_timeout(conn, timeout, true).await;
}

async fn set_timeout(conn: &mut PgConnection, timeout: Duration, local: bool) {
    // Rounded up from nanoseconds, so a non-zero timeout never becomes
    // "0ms", which turns it off: rounding from microseconds made one under
    // 1 µs "0ms".
    let millis = format!("{}ms", timeout.as_nanos().div_ceil(1_000_000));
    sqlx::query("SELECT set_config('statement_timeout', $1, $2)")
        .bind(millis)
        .bind(local)
        .execute(conn)
        .await
        .unwrap();
}
