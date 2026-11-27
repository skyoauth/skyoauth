//! The round trip of the workstation's local client
//! (`skyoauth_operator::local::LocalClient`) against the service's real
//! deployment-local transport (`skyoauth_service::local_transport`,
//! [`LocalTransport`]) on a Unix socket, on a database: the two sides
//! otherwise meet only through the shared fixtures
//! (`harness::local_transport_wire`, `harness::socket_path_fixture` and
//! the `skyoauth-operator` tests of the same files). They test the client
//! and the transport together, not a scenario: no name here matches
//! `a\d\d_`, and no stage of `tests/conformance/scenarios.toml` lists them
//! (layout §3).
//!
//! The transport binds as this process's UID in a private directory
//! (mode 0700, its symbolic links resolved), and the client is the one a
//! real caller uses, [`LocalClient::new`], which checks the socket path
//! before every connect: the socket of this process's UID with mode 0600,
//! the directories trusted as [`AncestorTrust::ServiceOrRoot`]. Signatures
//! are the workstation's: [`check_challenge`] of the issued `M` against
//! what the operator approves, then [`sign_challenge`] with a
//! [`SoftwareSigner`] of a test seed.
//!
//! - the journey: `status` before the bootstrap is
//!   [`BootstrapVerdict::RepeatBootstrap`]; the bootstrap, and its
//!   reconcile [`BootstrapVerdict::Matches`] (enabled, the credential the
//!   bootstrap enrolled); a repeat is `conflict`; the issue, the signature,
//!   the preview and the restore, each naming the plan's replacement; a
//!   repeat of the restore is `not_restorable`; the restore's reconcile is
//!   [`RestoreVerdict::Committed`] with the replacement's IDs, and the
//!   page walk ([`LocalClient::revoked_credential_ids`]) lists every
//!   credential the restore revoked, with the restore reply and without;
//! - the walk over more than a page: 2002 credentials revoked by one
//!   restore, one of them revoked before it at the restore's own
//!   microsecond (the documented tie, listed and counted by the reply), and
//!   one more revoked at that microsecond while the walk runs (before its
//!   first `status` request, after the restore reply), so that page's count
//!   is above the reply's and the walk restarts from `status` alone, once; it
//!   returns every ID in byte order, the late one included, in exactly the
//!   pages of 1000 the restart needs, and a walk from `status` alone agrees;
//!   credentials revoked one microsecond before and after the restore are
//!   in neither;
//! - every operation state through a real `status` and its
//!   [`RestoreVerdict`]: `not_found`, `issued`, `revoked`, `expiring` (with
//!   its `settles_at`) and `expired` through the transport's clock,
//!   `restored` and `retired`.

use std::{
    fs,
    os::unix::{fs::DirBuilderExt as _, fs::MetadataExt as _, net::UnixStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use skyoauth_operator::{
    identity::public_identity_of_spki,
    local::{
        AncestorTrust, BootstrapRequest, BootstrapVerdict, CallError, CheckedSocketPath, Connector,
        ErrorCode, IssueChallengeRequest, LocalClient, OperationState, ResponseRequest,
        RestoreVerdict, SocketExpectations, StatusRequest, Timeouts,
    },
    recovery::{
        Challenge, Expectations, RecoveryPublicKey, RecoverySigner as _, SoftwareSigner,
        check_challenge, sign_challenge,
    },
};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    ids::test_support::SequentialIds, local_transport::LocalTransport, operation::Clock,
    persistence::PgPool,
};
use tokio::{sync::oneshot, task::JoinHandle};

/// The instance, a lowercase hyphenated UUIDv7.
const INSTANCE: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
/// The seed of the bootstrap recovery key, a test key.
const SEED: [u8; 32] = [0x51; 32];
/// The seed of the key a restore rotates to.
const NEW_SEED: [u8; 32] = [0x52; 32];
const ANCHOR: &str = "deployment/operator-ca";
/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
/// The transport's clock at the start of every test.
const T0: Duration = Duration::from_secs(1_790_000_000);
/// The default challenge TTL of the transport.
const TTL: Duration = Duration::from_secs(300);
/// The default transaction timeout of the transport: `settles_at` is
/// `expires_at` plus it.
const SETTLE: Duration = Duration::from_secs(60);
/// The transport's page of revoked credential IDs.
const PAGE: usize = 1000;

/// The DER `SubjectPublicKeyInfo` of the operator key numbered `n`: the
/// Ed25519 public key of the seed of 32 bytes `n`, a valid point.
fn spki(n: u8) -> Vec<u8> {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(SigningKey::from_bytes(&[n; 32]).verifying_key().as_bytes());
    der
}

/// The recovery public key of `seed`, as the workstation's signer reports
/// it.
fn recovery_key(seed: [u8; 32]) -> RecoveryPublicKey {
    let mut seed = seed;
    SoftwareSigner::from_seed(&mut seed).unwrap().public_key()
}

fn micros_of(time: SystemTime) -> i64 {
    i64::try_from(time.duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap()
}

/// A clock the tests move.
struct TestClock(Mutex<SystemTime>);

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(UNIX_EPOCH + T0)))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

/// A fresh private directory under the system's temporary directory, its
/// symbolic links resolved, mode 0700, owned by this process's UID,
/// removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "skyoauth-round-trip-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The transport served on its own task at a socket in a private
/// directory, and what the client expects of that socket.
struct Server {
    path: PathBuf,
    expectations: SocketExpectations,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<()>,
    _dir: TempDir,
}

impl Server {
    /// Serves a transport on `pool` with `clock`, binding as this
    /// process's UID.
    async fn start(pool: &PgPool, clock: &Arc<TestClock>) -> Self {
        let dir = TempDir::new();
        let transport = LocalTransport::new(
            pool.clone(),
            Arc::<TestClock>::clone(clock),
            Arc::new(SequentialIds::with_seed(1)),
            None,
        );
        let listener = transport.bind(&dir.0.join("local.sock")).await.unwrap();
        let path = listener.path().to_path_buf();
        let expectations = SocketExpectations {
            owner_uid: fs::symlink_metadata(&dir.0).unwrap().uid(),
            ancestors: AncestorTrust::ServiceOrRoot,
        };
        let (shutdown, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(listener.serve(async move {
            let _ = stopped.await;
        }));
        Self {
            path,
            expectations,
            shutdown,
            task,
            _dir: dir,
        }
    }

    /// The client a real caller uses: the socket path checked before every
    /// connect.
    fn client(&self) -> LocalClient {
        LocalClient::new(&self.path, self.expectations, Timeouts::default())
    }

    /// The checked client through a [`Counted`] connector, which runs
    /// `hook`, if any, before the connect numbered `at` (from 0).
    fn counted(&self, hook: Option<(usize, Hook)>) -> (LocalClient<Counted>, Arc<AtomicUsize>) {
        let connects = Arc::new(AtomicUsize::new(0));
        let connector = Counted {
            inner: CheckedSocketPath::new(&self.path, self.expectations),
            connects: Arc::clone(&connects),
            hook: Mutex::new(hook),
        };
        (
            LocalClient::with_connector(connector, Timeouts::default()),
            connects,
        )
    }

    async fn stop(self) {
        let _ = self.shutdown.send(());
        tokio::time::timeout(Duration::from_secs(30), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

/// What a [`Counted`] connector runs before one of its connects.
type Hook = Box<dyn FnOnce() + Send>;

/// The checked connector that counts its connects and may run a hook
/// before one of them, on the call's own thread.
struct Counted {
    inner: CheckedSocketPath,
    connects: Arc<AtomicUsize>,
    hook: Mutex<Option<(usize, Hook)>>,
}

impl Connector for Counted {
    type Stream = UnixStream;

    fn connect(&self) -> std::io::Result<UnixStream> {
        let at = self.connects.fetch_add(1, Ordering::SeqCst);
        let mut hook = self.hook.lock().unwrap();
        if hook.as_ref().is_some_and(|(when, _)| *when == at)
            && let Some((_, run)) = hook.take()
        {
            run();
        }
        drop(hook);
        self.inner.connect()
    }
}

/// Runs a blocking client call on this worker thread, handing its other
/// work to the runtime meanwhile (the server runs on it).
fn call<T>(f: impl FnOnce() -> T) -> T {
    tokio::task::block_in_place(f)
}

/// The bootstrap of the tests: operator key 1, the recovery key of
/// [`SEED`].
fn bootstrap_request() -> BootstrapRequest {
    BootstrapRequest {
        instance_id: INSTANCE.into(),
        credential_spki: spki(1),
        trust_anchor_ref: ANCHOR.into(),
        recovery_public_key: recovery_key(SEED),
    }
}

/// The issue of a challenge for the replacement with operator key
/// `credential`, rotating to the recovery key of [`NEW_SEED`].
fn issue_request(credential: u8) -> IssueChallengeRequest {
    IssueChallengeRequest {
        credential_spki: spki(credential),
        trust_anchor_ref: ANCHOR.into(),
        new_recovery_public_key: recovery_key(NEW_SEED),
    }
}

/// The signed response to `challenge`, as the workstation makes it: `M`
/// checked against the replacement with operator key `credential` the
/// operator approves (at epoch 1, the bootstrap's, at the time `now`),
/// then signed by the [`SoftwareSigner`] of [`SEED`].
fn signed(challenge: &Challenge, credential: u8, now: SystemTime) -> ResponseRequest {
    let identity = public_identity_of_spki(&spki(credential)).unwrap();
    let new_key = recovery_key(NEW_SEED);
    let verified = check_challenge(
        challenge,
        &Expectations {
            instance_id: INSTANCE,
            now_micros: micros_of(now),
            recovery_key_epoch: Some(1),
            replacement_public_identity: Some(&identity),
            trust_anchor_ref: Some(ANCHOR),
            new_recovery_public_key: Some(&new_key),
        },
    )
    .unwrap();
    assert!(verified.replacement_confirmed());
    let mut seed = SEED;
    let signer = SoftwareSigner::from_seed(&mut seed).unwrap();
    let response = sign_challenge(&verified, &signer).unwrap();
    ResponseRequest {
        operation_id: response.operation_id().to_owned(),
        signature: *response.signature(),
    }
}

/// `status` of the operation `id` alone.
fn of_operation(id: &str) -> StatusRequest {
    StatusRequest {
        operation_id: Some(id.to_owned()),
        ..StatusRequest::default()
    }
}

/// Inserts `count` enabled credentials of the first operator, IDs `prefix`
/// and five digits; returns their IDs.
async fn insert_credentials(pool: &PgPool, prefix: &str, count: usize) -> Vec<String> {
    sqlx::query_scalar(
        "INSERT INTO admin_credential (id, admin_id, public_identity, trust_anchor_ref, status) \
         SELECT $1 || lpad(g::text, 5, '0'), (SELECT min(id) FROM admin_identity), \
         'bulk-identity/' || $1 || g, 'deployment/bulk', 'enabled' \
         FROM generate_series(1, $2::bigint) AS g RETURNING id",
    )
    .bind(prefix)
    .bind(i64::try_from(count).unwrap())
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Revokes the credential `id` at `at`, exactly to the microsecond, as
/// another writer would.
async fn revoke_credential_at(pool: &PgPool, id: &str, at: SystemTime) {
    let done = sqlx::query(
        "UPDATE admin_credential SET status = 'disabled', \
         revoked_at = timestamptz 'epoch' + $2::bigint * interval '1 microsecond' WHERE id = $1",
    )
    .bind(id)
    .bind(micros_of(at))
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(done.rows_affected(), 1);
}

/// Revokes the operation `id` at `at`, with a revocation operation row of
/// its own (by raw SQL, as `service/tests/local_transport.rs` does).
async fn revoke_operation(pool: &PgPool, id: &str, at: SystemTime) {
    let revocation = format!("{id}_revocation");
    let audit_id: String =
        sqlx::query_scalar("SELECT min(id) FROM audit_event WHERE tenant_id IS NULL")
            .fetch_one(pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, outcome, audit_id) \
         VALUES ($1, NULL, 'adm_revoker', 'revoke', $2, 1, '{}'::jsonb, 'success', $3)",
    )
    .bind(&revocation)
    .bind(vec![0xab_u8; 32])
    .bind(audit_id)
    .execute(pool)
    .await
    .unwrap();
    let done = sqlx::query(
        "UPDATE administrative_operation SET \
         revoked_at = timestamptz 'epoch' + $2::bigint * interval '1 microsecond', \
         revocation_operation_id = $3, revision = revision + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(micros_of(at))
    .bind(&revocation)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(done.rows_affected(), 1);
}

/// The journey of the operator's library through the real transport: the
/// bootstrap and its reconcile, the issue, a signature of the
/// workstation's signer, the preview, the restore, its refused repeat,
/// and the restore's reconcile with every credential it revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operators_client_bootstraps_restores_and_reconciles_through_the_transport() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let clock = TestClock::new();
    let server = Server::start(&pool, &clock).await;
    let client = server.client();
    let bootstrap = bootstrap_request();

    // Before the bootstrap: no recovery state, repeat it.
    let before = call(|| client.status(&StatusRequest::reconciling_bootstrap(&bootstrap))).unwrap();
    assert_eq!(before.instance_id, None);
    assert_eq!(
        BootstrapVerdict::of(&bootstrap, &before),
        BootstrapVerdict::RepeatBootstrap
    );

    let bootstrapped = call(|| client.bootstrap(&bootstrap)).unwrap();
    assert_eq!(bootstrapped.instance_id, INSTANCE);
    assert_eq!(bootstrapped.recovery_key_epoch, 1);
    // Its reconcile: the state matches, the credential enabled.
    let after = call(|| client.status(&StatusRequest::reconciling_bootstrap(&bootstrap))).unwrap();
    assert_eq!(
        BootstrapVerdict::of(&bootstrap, &after),
        BootstrapVerdict::Matches { enabled: true }
    );
    assert_eq!(
        after.enrolled_credential_id.as_deref(),
        Some(bootstrapped.credential_id.as_str())
    );
    assert_eq!(
        after.enrolled_admin_id.as_deref(),
        Some(bootstrapped.admin_id.as_str())
    );
    // A repeat is refused: bootstrap closes once.
    assert_eq!(
        call(|| client.bootstrap(&bootstrap)),
        Err(CallError::Refused(ErrorCode::Conflict))
    );

    // More credentials of the first operator, for the restore to revoke.
    let mut revoked = insert_credentials(&pool, "cred_extra", 5).await;
    revoked.push(bootstrapped.credential_id.clone());
    revoked.sort_unstable();

    let challenge = call(|| client.issue_challenge(&issue_request(2))).unwrap();
    let plan = challenge.plan().clone();
    assert_eq!(plan.instance_id, INSTANCE);
    assert_eq!(plan.recovery_key_epoch, 1);
    let response = signed(&challenge, 2, clock.now());

    let previewed = call(|| client.preview(&response)).unwrap();
    assert_eq!(
        (
            &previewed.admin_id,
            &previewed.credential_id,
            &previewed.binding_id
        ),
        (&plan.admin_id, &plan.credential_id, &plan.binding_id)
    );
    assert_eq!(previewed.new_recovery_key_epoch, 2);
    assert_eq!(previewed.expires_at, challenge.expires_at_micros());

    let restored = call(|| client.restore(&response)).unwrap();
    assert_eq!(
        (
            &restored.admin_id,
            &restored.credential_id,
            &restored.binding_id
        ),
        (&plan.admin_id, &plan.credential_id, &plan.binding_id)
    );
    assert_eq!(restored.recovery_key_epoch, 2);
    assert_eq!(
        restored.revoked_credential_count,
        i64::try_from(revoked.len()).unwrap()
    );
    assert_eq!(restored.revoked_credential_ids, revoked);
    // The restore is single use.
    assert_eq!(
        call(|| client.restore(&response)),
        Err(CallError::Refused(ErrorCode::NotRestorable))
    );

    // Its reconcile: committed, with the replacement and every credential
    // it revoked, read with the restore reply and without it.
    let status = call(|| client.status(&StatusRequest::reconciling_restore(&response))).unwrap();
    assert_eq!(RestoreVerdict::of(&status), RestoreVerdict::Committed);
    assert_eq!(
        (
            status.admin_id.as_ref(),
            status.credential_id.as_ref(),
            status.binding_id.as_ref()
        ),
        (
            Some(&plan.admin_id),
            Some(&plan.credential_id),
            Some(&plan.binding_id)
        )
    );
    assert_eq!(
        status.revoked_credential_count,
        Some(restored.revoked_credential_count)
    );
    let with_reply =
        call(|| client.revoked_credential_ids(&response.operation_id, Some(&restored)));
    let from_status = call(|| client.revoked_credential_ids(&response.operation_id, None));
    assert_eq!(with_reply, Ok(revoked.clone()));
    assert_eq!(from_status, with_reply);
    // The bootstrap no longer matches: the recovery key was rotated.
    let rotated =
        call(|| client.status(&StatusRequest::reconciling_bootstrap(&bootstrap))).unwrap();
    assert_eq!(
        BootstrapVerdict::of(&bootstrap, &rotated),
        BootstrapVerdict::DoesNotMatch
    );

    server.stop().await;
    db.drop([pool]).await;
}

/// The walk over more than a page, with the documented tie (lead ruling
/// (a)) built through the database, the transport's clock fixed: 2000
/// credentials, the bootstrap's and one revoked at the restore's own
/// microsecond before it are the 2002 the restore reply counts; one more
/// revoked at that microsecond while the walk runs raises the count on the
/// walk's first `status` page, and the walk restarts from `status` alone,
/// once. One revoked a microsecond before the restore, and one a
/// microsecond after it, are in no list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_walk_reads_every_page_and_restarts_on_a_tie_through_the_transport() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let clock = TestClock::new();
    let t0 = clock.now();
    let server = Server::start(&pool, &clock).await;
    let client = server.client();
    let bootstrapped = call(|| client.bootstrap(&bootstrap_request())).unwrap();

    let mut expected = insert_credentials(&pool, "cred_b", 2 * PAGE).await;
    expected.push(bootstrapped.credential_id.clone());
    // The tie before the restore, first in byte order.
    let early = insert_credentials(&pool, "cred_!early", 1).await.remove(0);
    revoke_credential_at(&pool, &early, t0).await;
    expected.push(early);
    // A microsecond before the restore: not the restore's.
    let before = insert_credentials(&pool, "cred_!before", 1).await.remove(0);
    revoke_credential_at(&pool, &before, t0 - Duration::from_micros(1)).await;
    expected.sort_unstable();
    assert_eq!(expected.len(), 2 * PAGE + 2);

    let challenge = call(|| client.issue_challenge(&issue_request(2))).unwrap();
    let response = signed(&challenge, 2, t0);
    let restored = call(|| client.restore(&response)).unwrap();
    assert_eq!(
        restored.revoked_credential_count,
        i64::try_from(expected.len()).unwrap()
    );
    assert_eq!(restored.revoked_credential_ids, expected[..PAGE]);
    // A microsecond after the restore: not the restore's either.
    let after = insert_credentials(&pool, "cred_~after", 1).await.remove(0);
    revoke_credential_at(&pool, &after, t0 + Duration::from_micros(1)).await;

    // A credential revoked at the restore's microsecond while the walk
    // runs: before its first `status` request, after the restore reply.
    let late = Arc::new(Mutex::new(None));
    let hook: Hook = {
        let pool = pool.clone();
        let late = Arc::clone(&late);
        let runtime = tokio::runtime::Handle::current();
        Box::new(move || {
            runtime.block_on(async {
                let id = insert_credentials(&pool, "cred_!late", 1).await.remove(0);
                revoke_credential_at(&pool, &id, t0).await;
                *late.lock().unwrap() = Some(id);
            });
        })
    };
    let (walker, connects) = server.counted(Some((0, hook)));
    let walked = call(|| walker.revoked_credential_ids(&response.operation_id, Some(&restored)));
    expected.push(late.lock().unwrap().take().expect("the hook ran"));
    expected.sort_unstable();
    assert_eq!(expected.len(), 2 * PAGE + 3);
    assert_eq!(walked, Ok(expected.clone()));
    // The page after the reply's (its count above the reply's), then the
    // restart from `status` alone: three pages of 1000, 1000 and 3.
    assert_eq!(connects.load(Ordering::SeqCst), 4);
    // The late credential sorts before the reply's cursor, so the walk
    // that only appended it to the reply's page would lose its place.
    assert_eq!(expected[1], "cred_!late00001");
    assert_eq!(expected[PAGE], restored.revoked_credential_ids[PAGE - 1]);

    // From `status` alone, with nothing changing: the same list, in its
    // three pages.
    let (walker, connects) = server.counted(None);
    assert_eq!(
        call(|| walker.revoked_credential_ids(&response.operation_id, None)),
        Ok(expected)
    );
    assert_eq!(connects.load(Ordering::SeqCst), 3);

    server.stop().await;
    db.drop([pool]).await;
}

/// Every operation state, through a real `status` and its restore
/// verdict: an unknown ID is `not_found`; a fresh challenge `issued`; a
/// challenge revoked unconsumed `revoked`; at `expires_at` `expiring`,
/// asked again after `settles_at` (the transaction timeout later), from
/// which on `expired`; a restored challenge `restored`, and once it is,
/// another unconsumed challenge `retired` (the revoked one stays
/// `revoked`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_operation_state_reaches_the_client_through_the_transport() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let clock = TestClock::new();
    let t0 = clock.now();
    let server = Server::start(&pool, &clock).await;
    let client = server.client();
    let state_of = |id: &str| {
        let status = call(|| client.status(&of_operation(id))).unwrap();
        (status.operation_state, RestoreVerdict::of(&status), status)
    };

    let (state, verdict, _) = state_of("oper_unknown");
    assert_eq!(
        (state, verdict),
        (Some(OperationState::NotFound), RestoreVerdict::Unknown)
    );
    call(|| client.bootstrap(&bootstrap_request())).unwrap();
    let (state, verdict, _) = state_of("oper_unknown");
    assert_eq!(
        (state, verdict),
        (Some(OperationState::NotFound), RestoreVerdict::Unknown)
    );

    let first = call(|| client.issue_challenge(&issue_request(2))).unwrap();
    let first_id = first.operation_id().to_owned();
    let expires = t0 + TTL;
    assert_eq!(first.expires_at_micros(), micros_of(expires));
    let (state, verdict, status) = state_of(&first_id);
    assert_eq!(
        (state, verdict),
        (Some(OperationState::Issued), RestoreVerdict::RepeatRestore)
    );
    assert_eq!(status.expires_at, Some(micros_of(expires)));

    let second = call(|| client.issue_challenge(&issue_request(3))).unwrap();
    let second_id = second.operation_id().to_owned();
    revoke_operation(&pool, &second_id, t0).await;
    let (state, verdict, _) = state_of(&second_id);
    assert_eq!(
        (state, verdict),
        (Some(OperationState::Revoked), RestoreVerdict::NeverCommits)
    );

    // From `expires_at` until `settles_at`: expiring.
    clock.advance(TTL);
    let settles = micros_of(expires + SETTLE);
    let (state, verdict, status) = state_of(&first_id);
    assert_eq!(
        (state, verdict),
        (
            Some(OperationState::Expiring),
            RestoreVerdict::AskAgainAfter(settles)
        )
    );
    assert_eq!(status.settles_at, Some(settles));
    clock.advance(SETTLE - Duration::from_micros(1));
    let (state, verdict, _) = state_of(&first_id);
    assert_eq!(
        (state, verdict),
        (
            Some(OperationState::Expiring),
            RestoreVerdict::AskAgainAfter(settles)
        )
    );
    // From `settles_at`: expired.
    clock.advance(Duration::from_micros(1));
    let (state, verdict, status) = state_of(&first_id);
    assert_eq!(
        (state, verdict),
        (Some(OperationState::Expired), RestoreVerdict::Expired)
    );
    assert_eq!(status.settles_at, None);

    // Another challenge, restored: it is `restored`, the first `retired`,
    // the revoked one still `revoked`.
    let third = call(|| client.issue_challenge(&issue_request(4))).unwrap();
    let response = signed(&third, 4, clock.now());
    let restored = call(|| client.restore(&response)).unwrap();
    let (state, verdict, status) = state_of(&response.operation_id);
    assert_eq!(
        (state, verdict),
        (Some(OperationState::Restored), RestoreVerdict::Committed)
    );
    assert_eq!(status.credential_id, Some(restored.credential_id));
    assert_eq!(status.restored_at, Some(micros_of(clock.now())));
    let (state, verdict, _) = state_of(&first_id);
    assert_eq!(
        (state, verdict),
        (Some(OperationState::Retired), RestoreVerdict::NeverCommits)
    );
    let (state, verdict, _) = state_of(&second_id);
    assert_eq!(
        (state, verdict),
        (Some(OperationState::Revoked), RestoreVerdict::NeverCommits)
    );

    server.stop().await;
    db.drop([pool]).await;
}
