//! The trust source kinds of the second-approver flow
//! (`docs/proposals/second-approver-gated-writes.md`, PR 5) on a real
//! database: `submit_create_source` and `submit_update_source` through the
//! gate (the class an update takes from its stored row, Q2; the flag, the
//! policy row, the mode and its audit outcome), the pending operation and
//! its plan, the approval that reruns the write under the locks with its
//! one clock sample (D28), the locked plan compared with the prepared one
//! (D24), the egress entries and the `0011` guard, canonical-form
//! destinations, the tenant path's cancel, a restoration between request
//! and approval, and races between two connections.
//!
//! Every helper here commits the outer transaction even when the call
//! returned an error, so each refusal also shows that the call's savepoint
//! left nothing behind.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database. They are
//! registry tests, not conformance scenarios.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    fmt::Debug,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use serde_json::{Value, json};
use skyoauth_service::{
    jwk::{Algorithm, DEFAULT_ALLOWED_ALGORITHMS},
    operation::{
        Applied, ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, DigestEnvelope,
        Gated, OperationKind, PendingOperation, PreparedApproval, RevokeIds, Submission,
        approve_operation, cancel_operation, prepare_approval, reject_operation,
        submit_widening_toggle,
    },
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AdminRoleBindingChanges, AdministrativeOperation, AssertionProfile,
            AuditActor, BootstrapRequest, ChainVerdict, ChallengeBinding, Consumption,
            DEFAULT_CHALLENGE_TTL, IssueChallenge, JsonObject, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, NewAdministrativeOperation, NewAuditEvent,
            NewConsumedAssertion, NewTenant, NewTrustKeyset, NewTrustSource, OPERATOR_RESTORATION,
            RegistryError, ReplayMode, RestoreRequest, Restored, Status, TrustSource,
            TrustSourceChanges, TrustSourceKind, append_audit_event, bootstrap_instance,
            get_recovery_state, insert_administrative_operation, issue_recovery_challenge,
            lock_administrative_operation, restore_operator, verify_audit_chain,
        },
    },
    trust::{
        SourceAudit, SourceWriteError, submit_create_source, submit_update_source,
        test_support::{create_source, update_source},
    },
};
use sqlx::{AssertSqlSafe, Connection, PgConnection, Postgres, Transaction};
use tokio::task::JoinHandle;

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;
/// [`skyoauth_service::operation::PENDING_OPERATION_TTL`] in microseconds.
const DAY: u64 = 86_400_000_000;
const CREATE: &str = "trust_source_create";
const UPDATE: &str = "trust_source_update";
const INSTANCE: ApprovalScope<'static> = ApprovalScope::Instance;
const TEN_A: ApprovalScope<'static> = ApprovalScope::Tenant("ten_a");
const TEN_B: ApprovalScope<'static> = ApprovalScope::Tenant("ten_b");
const SEC: AdminRole = AdminRole::SecurityAdmin;
const TRUST: AdminRole = AdminRole::TrustAdmin;
/// The current `allowed` algorithms of every `prepare_approval` here: a
/// source parses no keys.
const ALLOWED: &[Algorithm] = DEFAULT_ALLOWED_ALGORITHMS;

/// An enabled `oidc_discovery` entry.
const DISCOVERY: &str = "https://issuer.example/.well-known/openid-configuration";
/// Another enabled `oidc_discovery` entry.
const DISCOVERY_2: &str = "https://issuer2.example/.well-known/openid-configuration";
/// A disabled `oidc_discovery` entry.
const DISCOVERY_OFF: &str = "https://disabled.example/.well-known/openid-configuration";
/// An enabled `token_review` entry.
const TOKEN_REVIEW: &str = "https://k3s.internal.example:6443/";
/// Not in canonical form (an upper-case host), yet listed exactly by an
/// enabled `oidc_discovery` entry, so only the syntax rules refuse it: the
/// `0011` guard would accept it.
const NON_CANONICAL: &str = "https://ISSUER.example/x";

const DISABLE_ENTRY: &str = "UPDATE egress_allowlist_entry \
     SET status = 'disabled', revision = revision + 1 WHERE id = $1";
const ENABLE_ENTRY: &str = "UPDATE egress_allowlist_entry \
     SET status = 'enabled', revision = revision + 1 WHERE id = $1";

/// `micros` after `T0`, with sub-microsecond digits, so a write truncates
/// it.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros) + Duration::from_nanos(789)
}

/// [`at`] as stored: truncated to the microsecond.
fn stored(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

/// The expiry of a request made at `at(0)`.
fn expiry() -> SystemTime {
    stored(DAY)
}

fn micros(micros: u64) -> i64 {
    i64::try_from(T0 + micros).unwrap()
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// A clock the test sets, which counts its samples.
struct TestClock {
    now: Mutex<SystemTime>,
    samples: AtomicUsize,
}

impl TestClock {
    fn new(now: SystemTime) -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(now),
            samples: AtomicUsize::new(0),
        })
    }

    fn set(&self, now: SystemTime) {
        *self.now.lock().unwrap() = now;
    }

    fn samples(&self) -> usize {
        self.samples.load(Ordering::SeqCst)
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        self.samples.fetch_add(1, Ordering::SeqCst);
        *self.now.lock().unwrap()
    }
}

/// An `oidc_discovery` source of `ten_a` named after its ID, with proof
/// bounds that hold a fraction.
fn oidc(id: &str, discovery_url: &str) -> NewTrustSource {
    NewTrustSource {
        id: id.into(),
        tenant_id: "ten_a".into(),
        name: format!("source-{id}"),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: "https://issuer.example".into(),
        discovery_url: Some(discovery_url.into()),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: vec!["https://identity.example.com".into()],
        algorithms: Some(vec!["RS256".into()]),
        proof_bounds: object(json!({"max_ttl_s": 600, "skew": 1.5})),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    }
}

/// A `kubernetes_token_review` source of `ten_a`, with its own cluster.
fn k8s(id: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::KubernetesTokenReview,
        exact_issuer: "https://kubernetes.default.svc".into(),
        discovery_url: None,
        cluster_id: Some(format!("cluster_{id}")),
        token_review_endpoint: Some(TOKEN_REVIEW.into()),
        ca_bundle_ref: Some("ca_k3s".into()),
        ca_fingerprint: Some("sha256:ca".into()),
        reviewer_credential_ref: Some("reviewer_k3s".into()),
        review_timeout_ms: Some(5000),
        algorithms: None,
        assertion_profile: AssertionProfile::ProjectedServiceAccount,
        replay_mode: ReplayMode::Reusable,
        ..oidc(id, DISCOVERY)
    }
}

/// An `uploaded_jwks` source of `ten_a` on the keyset `ks_1`: no egress
/// destination.
fn uploaded(id: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::UploadedJwks,
        discovery_url: None,
        jwks_keyset_id: Some("ks_1".into()),
        algorithms: Some(vec!["ES256".into()]),
        assertion_profile: AssertionProfile::ReusableJwt,
        replay_mode: ReplayMode::Reusable,
        ..oidc(id, DISCOVERY)
    }
}

/// The mutable columns of `source`, unchanged.
fn changes(source: &TrustSource) -> TrustSourceChanges {
    TrustSourceChanges {
        name: source.name.clone(),
        exact_issuer: source.exact_issuer.clone(),
        discovery_url: source.discovery_url.clone(),
        token_review_endpoint: source.token_review_endpoint.clone(),
        ca_bundle_ref: source.ca_bundle_ref.clone(),
        ca_fingerprint: source.ca_fingerprint.clone(),
        reviewer_credential_ref: source.reviewer_credential_ref.clone(),
        review_timeout_ms: source.review_timeout_ms,
        audiences: source.audiences.clone(),
        algorithms: source.algorithms.clone(),
        proof_bounds: source.proof_bounds.clone(),
        assertion_profile: source.assertion_profile,
        stale_revocation_acknowledged: source.stale_revocation_acknowledged,
        replay_mode: source.replay_mode,
        status: source.status,
    }
}

/// `source` renamed: a widening update.
fn renamed(source: &TrustSource, name: &str) -> TrustSourceChanges {
    TrustSourceChanges {
        name: name.into(),
        ..changes(source)
    }
}

/// `source` with only its status set: a disable-only update for
/// `Disabled`, an enable or re-enable for `Enabled`.
fn with_status(source: &TrustSource, status: Status) -> TrustSourceChanges {
    TrustSourceChanges {
        status,
        ..changes(source)
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

async fn operator(
    pool: &PgPool,
    admin: &str,
    key: &str,
    bindings: &[(&str, AdminRole, Option<&str>)],
) {
    registry::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: admin.into(),
            status: Status::Enabled,
            created_at: at(0),
        },
    )
    .await
    .unwrap();
    credential(pool, &format!("crd_{admin}"), admin, key).await;
    for &(id, role, tenant_id) in bindings {
        registry::create_admin_role_binding(
            pool,
            &NewAdminRoleBinding {
                id: id.into(),
                admin_id: admin.into(),
                role,
                tenant_id: tenant_id.map(Into::into),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
}

async fn credential(pool: &PgPool, id: &str, admin: &str, key: &str) {
    registry::create_admin_credential(
        pool,
        &NewAdminCredential {
            id: id.into(),
            admin_id: admin.into(),
            public_identity: key.into(),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

async fn entry(pool: &PgPool, id: &str, purpose: &str, destination: &str, status: &str) {
    sqlx::query(
        "INSERT INTO egress_allowlist_entry (id, purpose, exact_destination, status) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(purpose)
    .bind(destination)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
}

async fn set_entry(pool: &PgPool, id: &str, enabled: bool) {
    let statement = if enabled { ENABLE_ENTRY } else { DISABLE_ENTRY };
    let done = sqlx::query(statement).bind(id).execute(pool).await.unwrap();
    assert_eq!(done.rows_affected(), 1);
}

/// The tenants `ten_a` (keyset `ks_1`) and `ten_b`; the egress entries
/// `egr_disc` ([`DISCOVERY`]), `egr_disc_2` ([`DISCOVERY_2`]),
/// `egr_disc_off` ([`DISCOVERY_OFF`], disabled), `egr_tr`
/// ([`TOKEN_REVIEW`]) and `egr_bad` ([`NON_CANONICAL`]); and these
/// operators, all enabled, each with a credential `crd_<admin>`:
///
/// - `adm_trust` (`key_trust`), `trust_admin` of `ten_a`: the requester;
/// - `adm_other` (`key_other`), `trust_admin` of `ten_a` too;
/// - `adm_both` (`key_both`), `trust_admin` of `ten_a` and instance
///   `security_admin` (`rb_both_sec`);
/// - `adm_sec1` (`key_sec1`) and `adm_sec2` (`key_sec2`), instance
///   `security_admin`: the approvers;
/// - `adm_tb` (`key_tb`), `trust_admin` of `ten_b`.
///
/// With `bootstrap`, the instance is bootstrapped first (`adm_first`, the
/// policy row at revision 1 with both flags off).
async fn seeded_with(bootstrap: bool) -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    if bootstrap {
        let mut transaction = pool.begin().await.unwrap();
        bootstrap_instance(
            &mut transaction,
            &BootstrapRequest {
                instance_id: INSTANCE_ID,
                admin_id: "adm_first",
                credential_id: "crd_first",
                public_identity: "spki-sha256:first",
                trust_anchor_ref: "deployment/operator-ca",
                binding_id: "rb_first",
                recovery_public_key: &[0x11; 32],
                audit_event_id: "aud_bootstrap",
                now: at(0),
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    for (id, ns) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::create_tenant(
            &pool,
            &NewTenant {
                id: id.into(),
                name: format!("Tenant {id}"),
                secret_namespace: ns.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    registry::create_trust_keyset(
        &pool,
        &NewTrustKeyset {
            id: "ks_1".into(),
            tenant_id: "ten_a".into(),
            name: "keyset-1".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (id, purpose, destination, status) in [
        ("egr_disc", "oidc_discovery", DISCOVERY, "enabled"),
        ("egr_disc_2", "oidc_discovery", DISCOVERY_2, "enabled"),
        ("egr_disc_off", "oidc_discovery", DISCOVERY_OFF, "disabled"),
        ("egr_tr", "token_review", TOKEN_REVIEW, "enabled"),
        ("egr_bad", "oidc_discovery", NON_CANONICAL, "enabled"),
    ] {
        entry(&pool, id, purpose, destination, status).await;
    }
    let ten_a = Some("ten_a");
    operator(
        &pool,
        "adm_trust",
        "key_trust",
        &[("rb_trust", TRUST, ten_a)],
    )
    .await;
    operator(
        &pool,
        "adm_other",
        "key_other",
        &[("rb_other", TRUST, ten_a)],
    )
    .await;
    operator(
        &pool,
        "adm_both",
        "key_both",
        &[("rb_both_trust", TRUST, ten_a), ("rb_both_sec", SEC, None)],
    )
    .await;
    operator(&pool, "adm_sec1", "key_sec1", &[("rb_sec1", SEC, None)]).await;
    operator(&pool, "adm_sec2", "key_sec2", &[("rb_sec2", SEC, None)]).await;
    operator(
        &pool,
        "adm_tb",
        "key_tb",
        &[("rb_tb", TRUST, Some("ten_b"))],
    )
    .await;
    (db, pool)
}

async fn seeded() -> (TestDb, PgPool) {
    seeded_with(true).await
}

/// Sets both flags of the policy row (its revision advances).
async fn set_policy(pool: &PgPool, widening_second_approver: bool, single_actor_mode: bool) {
    sqlx::query(
        "UPDATE instance_security_policy SET widening_second_approver = $1, \
         single_actor_mode = $2, revision = revision + 1",
    )
    .bind(widening_second_approver)
    .bind(single_actor_mode)
    .execute(pool)
    .await
    .unwrap();
}

/// The policy row's flags and revision.
async fn policy(pool: &PgPool) -> (bool, bool, i64) {
    sqlx::query_as(
        "SELECT widening_second_approver, single_actor_mode, revision \
         FROM instance_security_policy",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[track_caller]
fn refused<T: Debug, E: Debug>(result: Result<T, E>, expected: &str) {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => assert_eq!(format!("{err:?}"), expected),
    }
}

fn submission<'a>(key: &'a str, op: &'a str, event_id: &'a str, ack: bool) -> Submission<'a> {
    Submission {
        public_identity: key,
        acknowledge_widening: ack,
        operation_id: op,
        event_id,
        now: at(0),
    }
}

type Submitted = Result<Gated<TrustSource>, SourceWriteError>;

/// [`submit_create_source`] of `new` by `key` as the operation `op`
/// (event `evt_<op>`), in a transaction committed either way.
async fn submit_create(
    pool: &PgPool,
    key: &str,
    op: &str,
    ack: bool,
    new: &NewTrustSource,
) -> Submitted {
    let event_id = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let result =
        submit_create_source(&mut transaction, &submission(key, op, &event_id, ack), new).await;
    transaction.commit().await.unwrap();
    result
}

/// [`submit_update_source`] of the `ten_a` source `id` at `revision` to
/// `changes`, as [`submit_create`].
async fn submit_update(
    pool: &PgPool,
    key: &str,
    op: &str,
    ack: bool,
    (id, revision): (&str, i64),
    changes: &TrustSourceChanges,
) -> Submitted {
    let event_id = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let result = submit_update_source(
        &mut transaction,
        &submission(key, op, &event_id, ack),
        "ten_a",
        id,
        revision,
        changes,
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

#[track_caller]
fn pending(result: Submitted) -> PendingOperation {
    match result {
        Ok(Gated::Pending(pending)) => pending,
        other => panic!("not pending: {other:?}"),
    }
}

#[track_caller]
fn applied(result: Submitted) -> TrustSource {
    match result {
        Ok(Gated::Applied(source)) => source,
        other => panic!("not applied: {other:?}"),
    }
}

/// An ungated write's audit input.
fn audit(event_id: &str) -> SourceAudit<'_> {
    SourceAudit {
        event_id,
        now: at(0),
    }
}

/// The ungated create of `new` by `adm_trust`, committed.
async fn direct_create(pool: &PgPool, new: &NewTrustSource) -> TrustSource {
    let event_id = format!("evt_direct_{}", new.id);
    let mut transaction = pool.begin().await.unwrap();
    let source = create_source(&mut transaction, "key_trust", new, &audit(&event_id))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    source
}

/// The ungated update of the `ten_a` source `id` at `revision` by
/// `adm_trust`, in a transaction committed either way.
async fn direct_update(
    pool: &PgPool,
    id: &str,
    revision: i64,
    changes: &TrustSourceChanges,
) -> Result<TrustSource, SourceWriteError> {
    let event_id = format!("evt_direct_{id}_{revision}");
    let mut transaction = pool.begin().await.unwrap();
    let result = update_source(
        &mut transaction,
        "key_trust",
        "ten_a",
        id,
        revision,
        changes,
        &audit(&event_id),
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

fn echo(pending: &PendingOperation) -> ApprovalEcho {
    ApprovalEcho {
        request_digest: pending.request_digest,
        expected_revision: pending.expected_revision,
    }
}

/// [`prepare_approval`] on the `ten_a` path at `at(1)` with [`ALLOWED`].
async fn prepare(pool: &PgPool, key: &str, op: &str) -> Result<PreparedApproval, ApprovalError> {
    prepare_approval(pool, key, TEN_A, op, ALLOWED, at(1)).await
}

async fn approve_in(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    clock: &dyn Clock,
) -> Result<Applied, ApprovalError> {
    let tag = format!("{}_{key}", prepared.operation_id());
    let approve_operation_id = format!("appr_{tag}");
    let approve_event_id = format!("evt_appr_{tag}");
    let write_event_id = format!("evt_write_{tag}");
    approve_operation(
        transaction,
        key,
        TEN_A,
        prepared,
        echo,
        &ApprovalIds {
            approve_operation_id: &approve_operation_id,
            approve_event_id: &approve_event_id,
            write_event_id: &write_event_id,
        },
        clock,
    )
    .await
}

/// [`approve_in`] on the `ten_a` path, in a transaction committed either
/// way.
async fn approve(
    pool: &PgPool,
    key: &str,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    clock: &dyn Clock,
) -> Result<Applied, ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = approve_in(&mut transaction, key, prepared, echo, clock).await;
    transaction.commit().await.unwrap();
    result
}

#[track_caller]
fn applied_source(result: Result<Applied, ApprovalError>) -> TrustSource {
    match result {
        Ok(Applied::Source(source)) => source,
        other => panic!("not a trust source: {other:?}"),
    }
}

async fn revoke_in(
    transaction: &mut Transaction<'_, Postgres>,
    cancel: bool,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
) -> Result<(), ApprovalError> {
    let name = if cancel { "cancel" } else { "reject" };
    let revoking_operation_id = format!("{name}_{op}_{key}");
    let event_id = format!("evt_{name}_{op}_{key}");
    let ids = RevokeIds {
        revoking_operation_id: &revoking_operation_id,
        event_id: &event_id,
    };
    if cancel {
        cancel_operation(transaction, key, scope, op, &ids, at(7)).await
    } else {
        reject_operation(transaction, key, scope, op, &ids, at(7)).await
    }
}

async fn revoke(
    pool: &PgPool,
    cancel: bool,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
) -> Result<(), ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = revoke_in(&mut transaction, cancel, key, scope, op).await;
    transaction.commit().await.unwrap();
    result
}

/// The operation `id`, read under its lock in a transaction rolled back.
async fn operation(pool: &PgPool, id: &str) -> AdministrativeOperation {
    let mut transaction = pool.begin().await.unwrap();
    let row = lock_administrative_operation(&mut transaction, id)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no operation {id}"));
    transaction.rollback().await.unwrap();
    row
}

/// An audit event as stored: ID, tenant, actor, action, object, revisions,
/// outcome and microseconds since the epoch.
type Event = (
    String,
    Option<String>,
    String,
    String,
    String,
    Option<i64>,
    Option<i64>,
    String,
    i64,
);

#[allow(clippy::too_many_arguments)]
fn event(
    id: &str,
    actor: &str,
    action: &str,
    object_id: &str,
    previous_revision: Option<i64>,
    new_revision: Option<i64>,
    outcome: &str,
    at: u64,
) -> Event {
    (
        id.into(),
        Some("ten_a".into()),
        AuditActor::Operator(actor.into()).canonical_json(),
        action.into(),
        object_id.into(),
        previous_revision,
        new_revision,
        outcome.into(),
        micros(at),
    )
}

/// The events after the bootstrap event, in sequence order.
async fn events(pool: &PgPool) -> Vec<Event> {
    sqlx::query_as(
        "SELECT id, tenant_id, actor, action, object_id, previous_revision, new_revision, \
         outcome, (extract(epoch FROM timestamp) * 1000000)::bigint \
         FROM audit_event WHERE id <> 'aud_bootstrap' ORDER BY sequence",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn last_event(pool: &PgPool) -> Event {
    events(pool).await.pop().unwrap()
}

async fn assert_chain_intact(pool: &PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    assert!(matches!(
        verify_audit_chain(&mut connection).await.unwrap(),
        ChainVerdict::Intact { .. }
    ));
}

/// Every row a source or operation call may write, as text.
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let mut rows = Vec::new();
    for table in [
        "instance_security_policy",
        "administrative_operation",
        "audit_event",
        "audit_chain_head",
        "trust_source",
        "egress_allowlist_entry",
        "consumed_assertion",
    ] {
        let texts: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT to_jsonb(t)::text FROM {table} AS t ORDER BY to_jsonb(t)::text"
        )))
        .fetch_all(pool)
        .await
        .unwrap();
        rows.extend(texts.into_iter().map(|text| format!("{table} {text}")));
    }
    rows
}

/// The `ten_a` source `id`, if any.
async fn source_row(pool: &PgPool, id: &str) -> Option<TrustSource> {
    match registry::get_trust_source(pool, "ten_a", id).await {
        Ok(source) => Some(source),
        Err(RegistryError::NotFound) => None,
        Err(err) => panic!("{err:?}"),
    }
}

/// An optional text as JSON.
fn text(value: Option<&String>) -> Value {
    value.map_or(Value::Null, |text| json!(text))
}

/// The fifteen mutable members as a plan stores them.
fn members(changes: &TrustSourceChanges) -> JsonObject {
    object(json!({
        "name": changes.name,
        "exact_issuer": changes.exact_issuer,
        "discovery_url": text(changes.discovery_url.as_ref()),
        "token_review_endpoint": text(changes.token_review_endpoint.as_ref()),
        "ca_bundle_ref": text(changes.ca_bundle_ref.as_ref()),
        "ca_fingerprint": text(changes.ca_fingerprint.as_ref()),
        "reviewer_credential_ref": text(changes.reviewer_credential_ref.as_ref()),
        "review_timeout_ms": changes.review_timeout_ms,
        "audiences": changes.audiences,
        "algorithms": changes.algorithms,
        "proof_bounds": Value::Object(changes.proof_bounds.clone()).to_string(),
        "assertion_profile": changes.assertion_profile.as_str(),
        "stale_revocation_acknowledged": changes.stale_revocation_acknowledged,
        "replay_mode": changes.replay_mode.as_str(),
        "status": changes.status.as_str(),
    }))
}

/// The plan a create request by `adm_trust` stores for `new`, written out
/// member by member.
fn create_plan(new: &NewTrustSource) -> JsonObject {
    let mut plan = object(json!({
        "requester_credential_id": "crd_adm_trust",
        "id": new.id,
        "tenant_id": new.tenant_id,
        "kind": new.kind.as_str(),
        "jwks_keyset_id": text(new.jwks_keyset_id.as_ref()),
        "cluster_id": text(new.cluster_id.as_ref()),
    }));
    plan.extend(members(&TrustSourceChanges {
        name: new.name.clone(),
        exact_issuer: new.exact_issuer.clone(),
        discovery_url: new.discovery_url.clone(),
        token_review_endpoint: new.token_review_endpoint.clone(),
        ca_bundle_ref: new.ca_bundle_ref.clone(),
        ca_fingerprint: new.ca_fingerprint.clone(),
        reviewer_credential_ref: new.reviewer_credential_ref.clone(),
        review_timeout_ms: new.review_timeout_ms,
        audiences: new.audiences.clone(),
        algorithms: new.algorithms.clone(),
        proof_bounds: new.proof_bounds.clone(),
        assertion_profile: new.assertion_profile,
        stale_revocation_acknowledged: new.stale_revocation_acknowledged,
        replay_mode: new.replay_mode,
        status: new.status,
    }));
    plan
}

/// The plan an update request by `adm_trust` stores for `changes` of the
/// source `id`, with `changed`.
fn update_plan(id: &str, changes: &TrustSourceChanges, changed: &[&str]) -> JsonObject {
    let mut plan = object(json!({
        "requester_credential_id": "crd_adm_trust",
        "source_id": id,
        "changed": changed,
    }));
    plan.extend(members(changes));
    plan
}

/// A pending source operation `id` of `kind` by `adm_trust` in `ten_a`
/// requested at `at(0)`, with `plan` and the digest of `digest_plan` (of
/// `plan` itself when `None`).
fn raw(
    id: &str,
    kind: &str,
    expected_revision: i64,
    plan: JsonObject,
    digest_plan: Option<&JsonObject>,
) -> NewAdministrativeOperation {
    let digest = DigestEnvelope {
        id,
        tenant_id: Some("ten_a"),
        actor_id: "adm_trust",
        kind,
        expected_revision,
        expires_at_us: micros(DAY),
        plan: digest_plan.unwrap_or(&plan),
    }
    .digest()
    .unwrap();
    NewAdministrativeOperation {
        id: id.into(),
        tenant_id: Some("ten_a".into()),
        actor_id: "adm_trust".into(),
        kind: kind.into(),
        request_digest: digest.as_bytes().to_vec(),
        expected_revision,
        immutable_plan: plan,
        expires_at: Some(expiry()),
        approves_operation_id: None,
        outcome: "pending".into(),
        audit_id: format!("evt_{id}"),
    }
}

/// Appends the operation's `administrative_operation.create` event and
/// inserts it, committed; returns its echo.
async fn insert_raw(pool: &PgPool, new: &NewAdministrativeOperation) -> ApprovalEcho {
    let mut transaction = pool.begin().await.unwrap();
    append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: new.audit_id.clone(),
            tenant_id: new.tenant_id.clone(),
            timestamp: at(0),
            actor: AuditActor::Operator(new.actor_id.clone()),
            action: "administrative_operation.create".into(),
            object_id: new.id.clone(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    insert_administrative_operation(&mut transaction, new)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    ApprovalEcho {
        request_digest: new.request_digest[..].try_into().unwrap(),
        expected_revision: new.expected_revision,
    }
}

/// Rewrites the plan of the operation `id` past the `0005` immutability
/// trigger, then enables the trigger again as the migrations do.
async fn rewrite_plan(pool: &PgPool, id: &str, plan: &JsonObject) {
    sqlx::raw_sql(
        "ALTER TABLE administrative_operation \
         DISABLE TRIGGER administrative_operation_immutable",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE administrative_operation SET immutable_plan = $2, revision = revision + 1 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(sqlx::types::Json(plan))
    .execute(pool)
    .await
    .unwrap();
    sqlx::raw_sql(
        "ALTER TABLE administrative_operation \
         ENABLE ALWAYS TRIGGER administrative_operation_immutable",
    )
    .execute(pool)
    .await
    .unwrap();
}

/// Whether a `strength` lock of the row of `table` whose `id_column` is
/// `id` conflicts with a lock already held (`NOWAIT`, on another
/// connection).
async fn conflicts(pool: &PgPool, table: &str, id_column: &str, id: &str, strength: &str) -> bool {
    let mut other = pool.begin().await.unwrap();
    let result = sqlx::query(AssertSqlSafe(format!(
        "SELECT FROM {table} WHERE {id_column} = $1 {strength} NOWAIT"
    )))
    .bind(id)
    .execute(&mut *other)
    .await;
    other.rollback().await.unwrap();
    match result {
        Ok(done) => {
            assert_eq!(done.rows_affected(), 1, "{table} {id}");
            false
        }
        Err(err) => {
            let code = err.as_database_error().and_then(|e| e.code());
            assert_eq!(code.as_deref(), Some("55P03"), "{table} {id}: {err}");
            true
        }
    }
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// A detached connection and its backend PID.
async fn connection(pool: &PgPool) -> (PgConnection, i32) {
    let mut connection = pool.acquire().await.unwrap().detach();
    let pid = backend_pid(&mut connection).await;
    (connection, pid)
}

/// Waits until the backend `blocked`, which runs `task`, waits for a lock
/// held by `holder`. Fails at once if `task` finished without waiting.
async fn wait_until_blocked<T>(pool: &PgPool, blocked: i32, holder: i32, task: &JoinHandle<T>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT $1 = ANY (pg_blocking_pids($2))")
                .bind(holder)
                .bind(blocked)
                .fetch_one(pool)
                .await
                .unwrap();
            if waiting {
                return;
            }
            assert!(!task.is_finished(), "finished without waiting for the lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("never waited for the lock");
}

async fn finished<T>(task: JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the task never finished")
        .unwrap()
}

/// An approval on its own connection, in a transaction committed either
/// way; returns the backend PID and the task.
async fn spawn_approve(
    pool: &PgPool,
    key: &'static str,
    prepared: PreparedApproval,
    echo: ApprovalEcho,
    clock: Arc<TestClock>,
) -> (i32, JoinHandle<Result<Applied, ApprovalError>>) {
    let (mut connection, pid) = connection(pool).await;
    let task = tokio::spawn(async move {
        let mut transaction = connection.begin().await.unwrap();
        let result = approve_in(&mut transaction, key, &prepared, &echo, &*clock).await;
        transaction.commit().await.unwrap();
        connection.close().await.unwrap();
        result
    });
    (pid, task)
}

/// A gated create of `new` by `key_trust` (acknowledged) on its own
/// connection, in a transaction committed either way.
async fn spawn_submit_create(
    pool: &PgPool,
    op: &'static str,
    new: NewTrustSource,
) -> (i32, JoinHandle<Submitted>) {
    let (mut connection, pid) = connection(pool).await;
    let task = tokio::spawn(async move {
        let event_id = format!("evt_{op}");
        let mut transaction = connection.begin().await.unwrap();
        let result = submit_create_source(
            &mut transaction,
            &submission("key_trust", op, &event_id, true),
            &new,
        )
        .await;
        transaction.commit().await.unwrap();
        connection.close().await.unwrap();
        result
    });
    (pid, task)
}

/// A consumed assertion of `src_1`, the `n`th of the test: its insert takes
/// the source row `FOR KEY SHARE`.
fn consumed(n: u8) -> NewConsumedAssertion {
    NewConsumedAssertion {
        tenant_id: "ten_a".into(),
        trust_source_id: "src_1".into(),
        replay_key_digest: vec![n; 32],
        digest_key_version: "dk_1".into(),
        consumed_at: at(0),
        retain_until: at(600_000_000),
    }
}

/// The replacement operator a restoration enrolls: `adm_new` with
/// `crd_new` (`key_new`) and `rb_new`, an instance `security_admin`.
const RESTORED_KEY: &str = "key_new";

/// A break-glass restoration, committed: the challenge `op_restore` issued
/// at `at(2)` for [`RESTORED_KEY`]'s operator, then restored at `at(3)`.
/// It revokes every operator credential still unrevoked. The registry does
/// not verify the recovery key's signature; the digest and challenge hash
/// are the caller's bytes.
async fn restore(pool: &PgPool) -> Restored {
    let state = get_recovery_state(pool).await.unwrap().unwrap();
    let new_key = [0x22; 32];
    let plan = object(json!({
        "instance_id": INSTANCE_ID,
        "recovery_key_epoch": state.recovery_key_epoch,
        "admin_id": "adm_new",
        "credential_id": "crd_new",
        "binding_id": "rb_new",
        "public_identity": RESTORED_KEY,
        "trust_anchor_ref": "deployment/operator-ca",
        "new_recovery_public_key": new_key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    }));
    let (digest, hash) = ([0xd1; 32], [0xc7; 48]);
    let mut transaction = pool.begin().await.unwrap();
    issue_recovery_challenge(
        &mut transaction,
        &IssueChallenge {
            operation_id: "op_restore",
            kind: OPERATOR_RESTORATION,
            request_digest: &digest,
            immutable_plan: &plan,
            challenge_hash: &hash,
            ttl: DEFAULT_CHALLENGE_TTL,
            now: at(2),
            audit_event_id: "evt_issue_restore",
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let restored = restore_operator(
        &mut transaction,
        &RestoreRequest {
            operation_id: "op_restore",
            binding: ChallengeBinding {
                request_digest: &digest,
                challenge_hash: &hash,
                instance_id: INSTANCE_ID,
                expected_revision: state.revision,
                recovery_key_epoch: state.recovery_key_epoch,
            },
            admin_id: "adm_new",
            credential_id: "crd_new",
            binding_id: "rb_new",
            public_identity: RESTORED_KEY,
            trust_anchor_ref: "deployment/operator-ca",
            new_recovery_public_key: &new_key,
            audit_event_id: "evt_restore",
            rotation_audit_event_id: "evt_rotate",
            now: at(3),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    restored
}

/// A gated create is a pending operation until a distinct
/// `security_admin` approves it: the request writes its
/// `administrative_operation.create` event and the operation, whose plan
/// holds every member of the source (public fields only: secret
/// references, never secrets); no source. The approval writes the approve
/// event, the approve operation in the target's tenant (M31), the source
/// and its event at the one clock sample, and consumes the operation.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_gated_create_is_pending_until_a_second_approver_applies_it() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let new = oidc("src_1", DISCOVERY);
    let before = snapshot(&pool).await;
    refused(
        submit_create(&pool, "key_trust", "op_1", false, &new).await,
        "WideningNotAcknowledged",
    );
    assert_eq!(snapshot(&pool).await, before);

    let op = pending(submit_create(&pool, "key_trust", "op_1", true, &new).await);
    assert_eq!(op.id, "op_1");
    assert_eq!(op.kind, OperationKind::TrustSourceCreate);
    assert_eq!((op.expected_revision, op.expires_at), (0, expiry()));
    assert_eq!(source_row(&pool, "src_1").await, None);
    let stored_op = operation(&pool, "op_1").await;
    assert_eq!(stored_op.immutable_plan, create_plan(&new));
    assert_eq!(
        stored_op.immutable_plan["proof_bounds"],
        json!(r#"{"max_ttl_s":600,"skew":1.5}"#)
    );
    assert_eq!(
        (
            stored_op.tenant_id.as_deref(),
            stored_op.actor_id.as_str(),
            stored_op.kind.as_str(),
            stored_op.outcome.as_str(),
        ),
        (Some("ten_a"), "adm_trust", CREATE, "pending")
    );
    let digest = DigestEnvelope {
        id: "op_1",
        tenant_id: Some("ten_a"),
        actor_id: "adm_trust",
        kind: CREATE,
        expected_revision: 0,
        expires_at_us: micros(DAY),
        plan: &stored_op.immutable_plan,
    }
    .digest()
    .unwrap();
    assert_eq!(digest, op.request_digest);
    assert_eq!(stored_op.request_digest, digest.as_bytes());

    // Only an instance `security_admin` other than the requester, on the
    // operation's tenant path.
    for scope in [INSTANCE, TEN_B] {
        refused(
            prepare_approval(&pool, "key_sec1", scope, "op_1", ALLOWED, at(1)).await,
            "NotFound",
        );
    }
    for key in ["key_trust", "key_other"] {
        refused(prepare(&pool, key, "op_1").await, "Unauthorized");
    }
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    assert_eq!(prepared.kind(), OperationKind::TrustSourceCreate);
    let clock = TestClock::new(at(10));
    let row = applied_source(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!(clock.samples(), 1);
    assert_eq!(
        row,
        TrustSource {
            id: new.id.clone(),
            tenant_id: new.tenant_id.clone(),
            name: new.name.clone(),
            kind: new.kind,
            exact_issuer: new.exact_issuer.clone(),
            discovery_url: new.discovery_url.clone(),
            jwks_keyset_id: None,
            cluster_id: None,
            token_review_endpoint: None,
            ca_bundle_ref: None,
            ca_fingerprint: None,
            reviewer_credential_ref: None,
            review_timeout_ms: None,
            audiences: new.audiences.clone(),
            algorithms: new.algorithms.clone(),
            proof_bounds: new.proof_bounds.clone(),
            assertion_profile: new.assertion_profile,
            stale_revocation_acknowledged: None,
            replay_mode: new.replay_mode,
            status: Status::Enabled,
            revision: 1,
        }
    );
    assert_eq!(source_row(&pool, "src_1").await, Some(row));
    assert_eq!(
        events(&pool).await,
        [
            event(
                "evt_op_1",
                "adm_trust",
                "administrative_operation.create",
                "op_1",
                None,
                Some(1),
                "success",
                0
            ),
            event(
                "evt_appr_op_1_key_sec1",
                "adm_sec1",
                "administrative_operation.approve",
                "op_1",
                Some(1),
                Some(2),
                "success",
                10
            ),
            event(
                "evt_write_op_1_key_sec1",
                "adm_trust",
                "trust_source.create",
                "src_1",
                None,
                Some(1),
                "success",
                10
            ),
        ]
    );
    let consumed = operation(&pool, "op_1").await;
    assert_eq!(
        (
            consumed.consumed_at,
            consumed.outcome.as_str(),
            consumed.revision
        ),
        (Some(stored(10)), "applied", 2)
    );
    // The approve operation is in the target's tenant (M31; the 0005 guard
    // requires it of an approval).
    let approval = operation(&pool, "appr_op_1_key_sec1").await;
    assert_eq!(
        (
            approval.tenant_id.as_deref(),
            approval.actor_id.as_str(),
            approval.kind.as_str(),
            approval.approves_operation_id.as_deref(),
            approval.request_digest.as_slice(),
            approval.expected_revision,
            approval.outcome.as_str(),
        ),
        (
            Some("ten_a"),
            "adm_sec1",
            "approve",
            Some("op_1"),
            digest.as_bytes().as_slice(),
            0,
            "success"
        )
    );
    refused(
        prepare(&pool, "key_sec2", "op_1").await,
        "NotApprovable(Consumed)",
    );

    // A TokenReview source: its plan holds the secret references, the
    // cluster and the timeout, never a secret.
    let new = k8s("src_k");
    let op = pending(submit_create(&pool, "key_trust", "op_k", true, &new).await);
    let plan = operation(&pool, "op_k").await.immutable_plan;
    assert_eq!(plan, create_plan(&new));
    assert_eq!(
        (
            &plan["cluster_id"],
            &plan["ca_bundle_ref"],
            &plan["reviewer_credential_ref"],
            &plan["review_timeout_ms"],
        ),
        (
            &json!("cluster_src_k"),
            &json!("ca_k3s"),
            &json!("reviewer_k3s"),
            &json!(5000)
        )
    );
    let prepared = prepare(&pool, "key_sec2", "op_k").await.unwrap();
    let row = applied_source(approve(&pool, "key_sec2", &prepared, &echo(&op), &*clock).await);
    assert_eq!(
        (
            row.cluster_id.as_deref(),
            row.token_review_endpoint.as_deref()
        ),
        (Some("cluster_src_k"), Some(TOKEN_REVIEW))
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// A gated update is pending with a plan of the source, its changes and
/// the names of the members they change; its approval runs the update at
/// the operation's expected revision, and the approve operation is in the
/// target's tenant (M31). A direct update of the target meanwhile makes it
/// stale, and nothing is written. An enable of a disabled source, a
/// re-enable, is gated the same way.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_gated_update_and_re_enable_are_pending_until_approved() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_1", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));

    let mut update = renamed(&source, "renamed");
    update.discovery_url = Some(DISCOVERY_2.into());
    update.proof_bounds = object(json!({"skew": 1.5, "max_ttl_s": 600}));
    let op = pending(submit_update(&pool, "key_trust", "op_1", true, ("src_1", 1), &update).await);
    assert_eq!(
        (op.kind, op.expected_revision),
        (OperationKind::TrustSourceUpdate, 1)
    );
    let stored_op = operation(&pool, "op_1").await;
    // The key order of the proof bounds is no change.
    assert_eq!(
        stored_op.immutable_plan,
        update_plan("src_1", &update, &["discovery_url", "name"])
    );
    assert_eq!(
        (stored_op.kind.as_str(), stored_op.expected_revision),
        (UPDATE, 1)
    );
    assert_eq!(source_row(&pool, "src_1").await.unwrap(), source);
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    assert_eq!(prepared.kind(), OperationKind::TrustSourceUpdate);
    let row = applied_source(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!(
        (
            row.name.as_str(),
            row.discovery_url.as_deref(),
            row.revision
        ),
        ("renamed", Some(DISCOVERY_2), 2)
    );
    assert_eq!(
        last_event(&pool).await,
        event(
            "evt_write_op_1_key_sec1",
            "adm_trust",
            "trust_source.update",
            "src_1",
            Some(1),
            Some(2),
            "success",
            10
        )
    );
    assert_eq!(
        operation(&pool, "appr_op_1_key_sec1")
            .await
            .tenant_id
            .as_deref(),
        Some("ten_a")
    );

    // A re-enable: the source disabled (not widening, applied at once),
    // then enabled through the gate.
    let disabled = applied(
        submit_update(
            &pool,
            "key_trust",
            "op_2",
            false,
            ("src_1", 2),
            &with_status(&row, Status::Disabled),
        )
        .await,
    );
    let enable = with_status(&disabled, Status::Enabled);
    let op = pending(submit_update(&pool, "key_trust", "op_3", true, ("src_1", 3), &enable).await);
    assert_eq!(
        operation(&pool, "op_3").await.immutable_plan,
        update_plan("src_1", &enable, &["status"])
    );
    let prepared = prepare(&pool, "key_sec1", "op_3").await.unwrap();
    let row = applied_source(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!((row.status, row.revision), (Status::Enabled, 4));

    // A direct update of the target meanwhile: the approval is stale.
    let op = pending(
        submit_update(
            &pool,
            "key_trust",
            "op_4",
            true,
            ("src_1", 4),
            &renamed(&row, "again"),
        )
        .await,
    );
    let prepared = prepare(&pool, "key_sec1", "op_4").await.unwrap();
    direct_update(&pool, "src_1", 4, &with_status(&row, Status::Disabled))
        .await
        .unwrap();
    let before = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "Source(Registry(StaleRevision))",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(operation(&pool, "op_4").await.outcome, "pending");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The server decides the class of an update from the stored row (Q2): a
/// disable that changes nothing else is not widening and lands at once with
/// outcome `success`, without the acknowledgement, whatever the policy,
/// and writes no operation; a disable of a disabled source with nothing
/// else changed too. A disable that also changes another member, an
/// enable, a re-enable and a write that changes nothing on an enabled
/// source are widening: without the acknowledgement they are
/// `WideningNotAcknowledged`, whatever the caller meant.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_disable_only_update_is_not_widening_and_lands_at_once() {
    let (db, pool) = seeded().await;
    let mut source = direct_create(&pool, &oidc("src_1", DISCOVERY)).await;
    let mut n = 0;
    for (widening, single_actor) in [(true, false), (true, true), (false, false)] {
        set_policy(&pool, widening, single_actor).await;
        for key in ["key_trust", "key_both"] {
            let case = format!("{widening} {single_actor} {key}");
            // Widening, refused without the acknowledgement.
            let mut disable_and_rename = renamed(&source, "renamed");
            disable_and_rename.status = Status::Disabled;
            let mut disable_and_move = with_status(&source, Status::Disabled);
            disable_and_move.discovery_url = Some(DISCOVERY_2.into());
            let before = snapshot(&pool).await;
            for widening_update in [
                disable_and_rename,
                disable_and_move,
                changes(&source),
                TrustSourceChanges {
                    proof_bounds: object(json!({"max_ttl_s": 600.5, "skew": 1.5})),
                    status: Status::Disabled,
                    ..changes(&source)
                },
            ] {
                refused(
                    submit_update(
                        &pool,
                        key,
                        "op_x",
                        false,
                        ("src_1", source.revision),
                        &widening_update,
                    )
                    .await,
                    "WideningNotAcknowledged",
                );
            }
            assert_eq!(snapshot(&pool).await, before, "{case}");
            // The disable lands at once, unacknowledged, outcome `success`.
            n += 1;
            let op = format!("op_{n}");
            let disabled = applied(
                submit_update(
                    &pool,
                    key,
                    &op,
                    false,
                    ("src_1", source.revision),
                    &with_status(&source, Status::Disabled),
                )
                .await,
            );
            assert_eq!(disabled.status, Status::Disabled, "{case}");
            assert_eq!(disabled.revision, source.revision + 1, "{case}");
            let admin = if key == "key_trust" {
                "adm_trust"
            } else {
                "adm_both"
            };
            assert_eq!(
                last_event(&pool).await,
                event(
                    &format!("evt_{op}"),
                    admin,
                    "trust_source.update",
                    "src_1",
                    Some(source.revision),
                    Some(disabled.revision),
                    "success",
                    0
                ),
                "{case}"
            );
            // A disable of the disabled source: disable-only too.
            n += 1;
            let op = format!("op_{n}");
            let again = applied(
                submit_update(
                    &pool,
                    key,
                    &op,
                    false,
                    ("src_1", disabled.revision),
                    &changes(&disabled),
                )
                .await,
            );
            assert_eq!(last_event(&pool).await.7, "success", "{case}");
            // An enable is widening.
            refused(
                submit_update(
                    &pool,
                    key,
                    "op_x",
                    false,
                    ("src_1", again.revision),
                    &with_status(&again, Status::Enabled),
                )
                .await,
                "WideningNotAcknowledged",
            );
            source = direct_update(
                &pool,
                "src_1",
                again.revision,
                &with_status(&again, Status::Enabled),
            )
            .await
            .unwrap();
        }
    }
    let operations: i64 = sqlx::query_scalar("SELECT count(*) FROM administrative_operation")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(operations, 0);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The mode follows the policy row and the requester's roles (section 1),
/// for a create, enabled or disabled, a widening update and a re-enable:
/// `widening_second_approver` off applies it at once with outcome
/// `success_widening` whatever `single_actor_mode` is (D23); on,
/// `single_actor_mode` on and a requester who also holds instance
/// `security_admin` apply it with `success_single_actor` (Q4); otherwise
/// it goes pending and writes no source.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_mode_follows_the_policy_and_the_requesters_roles() {
    let (db, pool) = seeded().await;
    let mut n = 0;
    for (widening, single_actor) in [(false, false), (false, true), (true, false), (true, true)] {
        set_policy(&pool, widening, single_actor).await;
        for key in ["key_trust", "key_both"] {
            let expected = if !widening {
                Some("success_widening")
            } else if single_actor && key == "key_both" {
                Some("success_single_actor")
            } else {
                None
            };
            for kind in ["create_enabled", "create_disabled", "update", "enable"] {
                n += 1;
                let id = format!("src_{n}");
                let op = format!("op_{n}");
                let case = format!("{widening} {single_actor} {key} {kind}");
                let mut new = uploaded(&id);
                let target = match kind {
                    "create_disabled" => {
                        new.status = Status::Disabled;
                        None
                    }
                    "update" => Some(direct_create(&pool, &new).await),
                    "enable" => {
                        new.status = Status::Disabled;
                        Some(direct_create(&pool, &new).await)
                    }
                    _ => None,
                };
                let result = |ack| {
                    let (pool, op, new, target) = (&pool, &op, &new, &target);
                    async move {
                        match target {
                            None => submit_create(pool, key, op, ack, new).await,
                            Some(source) => {
                                let update = if source.status == Status::Disabled {
                                    with_status(source, Status::Enabled)
                                } else {
                                    renamed(source, "renamed-source")
                                };
                                let target = (source.id.as_str(), 1);
                                submit_update(pool, key, op, ack, target, &update).await
                            }
                        }
                    }
                };
                let before = snapshot(&pool).await;
                refused(result(false).await, "WideningNotAcknowledged");
                assert_eq!(snapshot(&pool).await, before, "{case}");
                let outcome = result(true).await;
                match expected {
                    Some(expected) => {
                        let row = applied(outcome);
                        assert_eq!(row.id, id, "{case}");
                        let last = last_event(&pool).await;
                        // The request's event at the request's `now`.
                        assert_eq!(
                            (last.0.as_str(), last.7.as_str(), last.8),
                            (format!("evt_{op}").as_str(), expected, micros(0)),
                            "{case}"
                        );
                    }
                    None => {
                        let pending = pending(outcome);
                        assert_eq!(pending.id, op, "{case}");
                        assert_eq!(last_event(&pool).await.7, "success", "{case}");
                        assert_eq!(source_row(&pool, &id).await, target, "{case}");
                    }
                }
                // Every renamed source frees the name.
                if let Some(row) = source_row(&pool, &id).await
                    && row.name == "renamed-source"
                {
                    let back = renamed(&row, &format!("source-{id}"));
                    direct_update(&pool, &id, row.revision, &back)
                        .await
                        .unwrap();
                }
            }
        }
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Only a `trust_admin` of the source's tenant requests: an instance
/// `security_admin` without that role is refused, with `single_actor_mode`
/// on too, and learns nothing of the source, not even whether it exists;
/// the requester's identity and credential must be enabled and unrevoked.
/// While a request runs, its operator rows (the instance binding included),
/// the policy row (`FOR SHARE`, a disable-only update included), the
/// source row (`FOR NO KEY UPDATE`) and the entry (`FOR SHARE`) are held.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn only_a_trust_admin_of_the_tenant_requests() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    let new = oidc("src_1", DISCOVERY);
    for (widening, single_actor) in [(true, false), (true, true), (false, false)] {
        set_policy(&pool, widening, single_actor).await;
        let before = snapshot(&pool).await;
        for key in ["key_sec1", "key_tb", "spki-sha256:unknown"] {
            for ack in [true, false] {
                refused(
                    submit_create(&pool, key, "op_x", ack, &new).await,
                    "Unauthorized",
                );
                for (target, update) in [
                    (("src_0", 1), renamed(&source, "x")),
                    (("src_0", 1), with_status(&source, Status::Disabled)),
                    (("src_0", 9), renamed(&source, "x")),
                    (("src_none", 1), renamed(&source, "x")),
                ] {
                    refused(
                        submit_update(&pool, key, "op_x", ack, target, &update).await,
                        "Unauthorized",
                    );
                }
            }
        }
        assert_eq!(snapshot(&pool).await, before);
    }
    set_policy(&pool, true, false).await;
    credential(&pool, "crd_adm_other_b", "adm_other", "key_other_b").await;
    sqlx::query("UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_other'")
        .execute(&pool)
        .await
        .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_other_b", at(2))
        .await
        .unwrap();
    registry::disable_admin_identity(&pool, "adm_both")
        .await
        .unwrap();
    let before = snapshot(&pool).await;
    for key in ["key_other", "key_other_b", "key_both"] {
        refused(
            submit_create(&pool, key, "op_x", true, &new).await,
            "Unauthorized",
        );
        refused(
            submit_update(
                &pool,
                key,
                "op_x",
                false,
                ("src_0", 1),
                &with_status(&source, Status::Disabled),
            )
            .await,
            "Unauthorized",
        );
    }
    assert_eq!(snapshot(&pool).await, before);

    // The locks of a pending update, held until its transaction ends.
    let mut moved = renamed(&source, "moved");
    moved.discovery_url = Some(DISCOVERY_2.into());
    for (update, pending) in [
        (moved, true),
        (with_status(&source, Status::Disabled), false),
    ] {
        let mut tx = pool.begin().await.unwrap();
        let held = submit_update_source(
            &mut tx,
            &submission("key_trust", "op_1", "evt_op_1", true),
            "ten_a",
            "src_0",
            1,
            &update,
        )
        .await;
        assert_eq!(matches!(held, Ok(Gated::Pending(_))), pending, "{held:?}");
        for (table, id) in [
            ("admin_identity", "adm_trust"),
            ("admin_credential", "crd_adm_trust"),
            ("admin_role_binding", "rb_trust"),
        ] {
            assert!(
                conflicts(&pool, table, "id", id, "FOR UPDATE").await,
                "{id}"
            );
            assert!(
                !conflicts(&pool, table, "id", id, "FOR SHARE").await,
                "{id}"
            );
        }
        for strength in ["FOR NO KEY UPDATE", "FOR SHARE"] {
            assert_eq!(
                conflicts(
                    &pool,
                    "instance_security_policy",
                    "instance_id",
                    INSTANCE_ID,
                    strength
                )
                .await,
                strength == "FOR NO KEY UPDATE",
                "{strength}"
            );
        }
        // The source row: FOR NO KEY UPDATE while pending (it blocks no
        // reference), FOR UPDATE once the compare-and-set ran.
        assert!(conflicts(&pool, "trust_source", "id", "src_0", "FOR SHARE").await);
        assert_eq!(
            conflicts(&pool, "trust_source", "id", "src_0", "FOR KEY SHARE").await,
            !pending
        );
        // The changed destination's entry, FOR SHARE.
        assert_eq!(
            conflicts(
                &pool,
                "egress_allowlist_entry",
                "id",
                "egr_disc_2",
                "FOR NO KEY UPDATE"
            )
            .await,
            pending
        );
        assert!(
            !conflicts(
                &pool,
                "egress_allowlist_entry",
                "id",
                "egr_disc_2",
                "FOR SHARE"
            )
            .await
        );
        tx.rollback().await.unwrap();
    }
    // A pending create holds its entry FOR SHARE too.
    let mut tx = pool.begin().await.unwrap();
    let held = submit_create_source(
        &mut tx,
        &submission("key_trust", "op_1", "evt_op_1", true),
        &new,
    )
    .await;
    assert!(matches!(held, Ok(Gated::Pending(_))), "{held:?}");
    assert!(
        conflicts(
            &pool,
            "egress_allowlist_entry",
            "id",
            "egr_disc",
            "FOR NO KEY UPDATE"
        )
        .await
    );
    tx.rollback().await.unwrap();
    db.drop([pool]).await;
}

/// The gate's refusals come in the request's order. A create: D27 before
/// any statement (so before the requester), the isolation, the requester,
/// the flag, then the policy row (missing before bootstrap:
/// `PolicyUnavailable`, D18). An update: the requester, the source and its
/// revision, the flag, then the policy row; a disable-only update needs no
/// policy row. Each refusal writes nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_gates_refusals_come_in_order() {
    let (db, pool) = seeded_with(false).await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    let new = oidc("src_1", DISCOVERY);
    let before = snapshot(&pool).await;
    let empty_name = NewTrustSource {
        name: String::new(),
        ..new.clone()
    };
    refused(
        submit_create(&pool, "key_sec1", "op_1", false, &empty_name).await,
        "Registry(Invariant { kind: Check, constraint: Some(\"trust_source_name_check\") })",
    );
    refused(
        submit_create(&pool, "key_sec1", "op_1", false, &new).await,
        "Unauthorized",
    );
    refused(
        submit_create(&pool, "key_trust", "op_1", false, &new).await,
        "WideningNotAcknowledged",
    );
    refused(
        submit_create(&pool, "key_trust", "op_1", true, &new).await,
        "PolicyUnavailable",
    );
    let rename = renamed(&source, "renamed");
    refused(
        submit_update(&pool, "key_sec1", "op_1", false, ("src_none", 9), &rename).await,
        "Unauthorized",
    );
    refused(
        submit_update(&pool, "key_trust", "op_1", false, ("src_none", 9), &rename).await,
        "Registry(NotFound)",
    );
    refused(
        submit_update(&pool, "key_trust", "op_1", false, ("src_0", 9), &rename).await,
        "Registry(StaleRevision)",
    );
    refused(
        submit_update(&pool, "key_trust", "op_1", false, ("src_0", 1), &rename).await,
        "WideningNotAcknowledged",
    );
    refused(
        submit_update(&pool, "key_trust", "op_1", true, ("src_0", 1), &rename).await,
        "PolicyUnavailable",
    );
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .unwrap();
    let result = submit_update_source(
        &mut tx,
        &submission("key_sec1", "op_1", "evt_op_1", false),
        "ten_a",
        "src_none",
        9,
        &rename,
    )
    .await;
    refused(result, "UnsupportedIsolation");
    let result = submit_create_source(
        &mut tx,
        &submission("key_sec1", "op_1", "evt_op_1", false),
        &new,
    )
    .await;
    refused(result, "UnsupportedIsolation");
    tx.commit().await.unwrap();
    assert_eq!(snapshot(&pool).await, before);
    // A disable-only update needs no policy row.
    let disabled = applied(
        submit_update(
            &pool,
            "key_trust",
            "op_2",
            false,
            ("src_0", 1),
            &with_status(&source, Status::Disabled),
        )
        .await,
    );
    assert_eq!(disabled.status, Status::Disabled);
    assert_eq!(last_event(&pool).await.7, "success");
    db.drop([pool]).await;
}

/// D27: a request refuses the plainly typed constraints before any
/// statement, as the database refuses them at the direct write, so an
/// unauthorized caller gets the same refusal; nothing is written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_request_refuses_the_typed_constraints_as_the_database_does() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let source = direct_create(&pool, &k8s("src_0")).await;
    type Change = fn(&mut NewTrustSource);
    let cases: [Change; 14] = [
        |n| n.id.clear(),
        |n| n.name.clear(),
        |n| n.exact_issuer.clear(),
        |n| n.cluster_id = Some(String::new()),
        |n| n.ca_bundle_ref = Some(String::new()),
        |n| n.ca_fingerprint = Some(String::new()),
        |n| n.reviewer_credential_ref = Some(String::new()),
        |n| n.review_timeout_ms = Some(0),
        |n| n.audiences.clear(),
        |n| n.audiences.push(String::new()),
        |n| n.stale_revocation_acknowledged = Some(false),
        |n| {
            n.name.clear();
            n.audiences.clear();
        },
        |n| {
            n.name.clear();
            n.audiences.push(String::new());
        },
        |n| {
            n.review_timeout_ms = Some(-1);
            n.stale_revocation_acknowledged = Some(false);
        },
    ];
    let before = snapshot(&pool).await;
    for (index, change) in cases.into_iter().enumerate() {
        let mut new = k8s("src_1");
        change(&mut new);
        let mut tx = pool.begin().await.unwrap();
        let direct = create_source(&mut tx, "key_trust", &new, &audit("evt_d"))
            .await
            .map(|_| ());
        tx.rollback().await.unwrap();
        let expected = format!("{:?}", direct.expect_err("the database refuses it"));
        for key in ["key_trust", "key_sec1"] {
            refused(
                submit_create(&pool, key, "op_x", true, &new).await,
                &expected,
            );
        }
        // The same on an update, where the member is mutable.
        if index != 0 && index != 3 {
            let mut changes = changes(&source);
            let mut as_new = k8s("src_0");
            change(&mut as_new);
            changes.name = as_new.name;
            changes.exact_issuer = as_new.exact_issuer;
            changes.ca_bundle_ref = as_new.ca_bundle_ref;
            changes.ca_fingerprint = as_new.ca_fingerprint;
            changes.reviewer_credential_ref = as_new.reviewer_credential_ref;
            changes.review_timeout_ms = as_new.review_timeout_ms;
            changes.audiences = as_new.audiences;
            changes.stale_revocation_acknowledged = as_new.stale_revocation_acknowledged;
            let direct = direct_update(&pool, "src_0", 1, &changes).await.map(|_| ());
            let expected = format!("{:?}", direct.expect_err("the database refuses it"));
            for key in ["key_trust", "key_sec1"] {
                refused(
                    submit_update(&pool, key, "op_x", true, ("src_0", 1), &changes).await,
                    &expected,
                );
            }
        }
    }
    // An algorithm list on a TokenReview source: the database's own order.
    let mut new = k8s("src_1");
    new.algorithms = Some(Vec::new());
    let mut tx = pool.begin().await.unwrap();
    let direct = create_source(&mut tx, "key_trust", &new, &audit("evt_d")).await;
    tx.rollback().await.unwrap();
    refused(
        submit_create(&pool, "key_trust", "op_x", true, &new).await,
        &format!("{:?}", direct.unwrap_err()),
    );
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// Canonical-form destinations: a destination the syntax rules refuse is
/// refused at the request even when an enabled entry lists exactly its
/// text (which the `0011` guard would accept), before any statement for a
/// create and once the stored row says it changed for an update; and at
/// the approval of a plan that holds one. Nothing is written; no error
/// names the destination.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn destinations_must_be_in_canonical_form() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    let before = snapshot(&pool).await;
    let invalid = "InvalidDestination { member: \"discovery_url\" }";
    for key in ["key_trust", "key_sec1"] {
        refused(
            submit_create(&pool, key, "op_x", true, &oidc("src_1", NON_CANONICAL)).await,
            invalid,
        );
    }
    let mut moved = changes(&source);
    moved.discovery_url = Some(NON_CANONICAL.into());
    refused(
        submit_update(&pool, "key_trust", "op_x", true, ("src_0", 1), &moved).await,
        invalid,
    );
    // An unauthorized update learns nothing, not even this.
    refused(
        submit_update(&pool, "key_sec1", "op_x", true, ("src_0", 1), &moved).await,
        "Unauthorized",
    );
    assert_eq!(snapshot(&pool).await, before);

    // At the approval: plans the request would never have written.
    let clock = TestClock::new(at(10));
    for (id, kind, expected_revision, plan) in [
        (
            "op_c",
            CREATE,
            0,
            create_plan(&oidc("src_1", NON_CANONICAL)),
        ),
        (
            "op_u",
            UPDATE,
            1,
            update_plan("src_0", &moved, &["discovery_url"]),
        ),
    ] {
        let echo = insert_raw(&pool, &raw(id, kind, expected_revision, plan, None)).await;
        let prepared = prepare(&pool, "key_sec1", id).await.unwrap();
        let before = snapshot(&pool).await;
        let result = approve(&pool, "key_sec1", &prepared, &echo, &*clock).await;
        refused(result, &format!("Source({invalid})"));
        assert_eq!(snapshot(&pool).await, before, "{id}");
    }
    assert_eq!(clock.samples(), 0);
    assert_eq!(source_row(&pool, "src_1").await, None);
    db.drop([pool]).await;
}

/// The approval reruns the write's egress check under its own locks
/// (`0011`; IR-152): an entry disabled after the request refuses the
/// approval with the service's own error, not the guard's, and writes
/// nothing; an update that leaves the destination unchanged is not checked
/// again, whatever its entry. The approval takes the operation row, then
/// the source row, then the entry: an approval that reaches the entry while
/// a disable holds it waits, already holding the source row; the disable
/// committed refuses it, rolled back lets it apply. Once applied, the
/// approval holds the entry `FOR SHARE` and the source row `FOR UPDATE`
/// until it commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_approval_rechecks_the_egress_entry_under_its_locks() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_1", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));

    // At the request, pending or applied: a destination whose entry is
    // disabled, or that no entry lists.
    for (widening, single_actor) in [(true, false), (false, false)] {
        set_policy(&pool, widening, single_actor).await;
        let before = snapshot(&pool).await;
        let mut moved = changes(&source);
        moved.discovery_url = Some(DISCOVERY_OFF.into());
        let refusal = "EgressNotAllowed { member: \"discovery_url\" }";
        refused(
            submit_update(&pool, "key_trust", "op_x", true, ("src_1", 1), &moved).await,
            refusal,
        );
        let mut new = k8s("src_x");
        new.token_review_endpoint = Some("https://unlisted.example/".into());
        refused(
            submit_create(&pool, "key_trust", "op_x", true, &new).await,
            "EgressNotAllowed { member: \"token_review_endpoint\" }",
        );
        refused(
            submit_create(
                &pool,
                "key_trust",
                "op_x",
                true,
                &oidc("src_x", DISCOVERY_OFF),
            )
            .await,
            refusal,
        );
        assert_eq!(snapshot(&pool).await, before);
    }
    set_policy(&pool, true, false).await;

    // A create whose entry is disabled after the request.
    let op = pending(
        submit_create(
            &pool,
            "key_trust",
            "op_c",
            true,
            &oidc("src_2", DISCOVERY_2),
        )
        .await,
    );
    set_entry(&pool, "egr_disc_2", false).await;
    let prepared = prepare(&pool, "key_sec1", "op_c").await.unwrap();
    let before = snapshot(&pool).await;
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "Source(EgressNotAllowed { member: \"discovery_url\" })",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(operation(&pool, "op_c").await.outcome, "pending");
    set_entry(&pool, "egr_disc_2", true).await;

    // A rename of a source whose entry is disabled: not checked again.
    let op = pending(
        submit_update(
            &pool,
            "key_trust",
            "op_r",
            true,
            ("src_1", 1),
            &renamed(&source, "renamed"),
        )
        .await,
    );
    set_entry(&pool, "egr_disc", false).await;
    let prepared = prepare(&pool, "key_sec1", "op_r").await.unwrap();
    let source = applied_source(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!(source.discovery_url.as_deref(), Some(DISCOVERY));
    set_entry(&pool, "egr_disc", true).await;

    // A move to DISCOVERY_2 while a disable of its entry is uncommitted.
    let mut moved = changes(&source);
    moved.discovery_url = Some(DISCOVERY_2.into());
    let op = pending(submit_update(&pool, "key_trust", "op_m", true, ("src_1", 2), &moved).await);
    for commit in [true, false] {
        let prepared = prepare(&pool, "key_sec1", "op_m").await.unwrap();
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        sqlx::query(DISABLE_ENTRY)
            .bind("egr_disc_2")
            .execute(&mut *held)
            .await
            .unwrap();
        let before = snapshot(&pool).await;
        let (pid, task) =
            spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        // Waiting at the entry, it holds the operation and the source row.
        assert!(conflicts(&pool, "administrative_operation", "id", "op_m", "FOR SHARE").await);
        assert!(conflicts(&pool, "trust_source", "id", "src_1", "FOR SHARE").await);
        assert!(!conflicts(&pool, "trust_source", "id", "src_1", "FOR KEY SHARE").await);
        if commit {
            held.commit().await.unwrap();
            holder.close().await.unwrap();
            refused(
                finished(task).await,
                "Source(EgressNotAllowed { member: \"discovery_url\" })",
            );
            assert_eq!(operation(&pool, "op_m").await.outcome, "pending");
            assert_eq!(snapshot(&pool).await.len(), before.len());
            set_entry(&pool, "egr_disc_2", true).await;
        } else {
            held.rollback().await.unwrap();
            holder.close().await.unwrap();
            let row = applied_source(finished(task).await);
            assert_eq!(row.discovery_url.as_deref(), Some(DISCOVERY_2));
        }
    }

    // The locks of an applied approval, held until it commits.
    let current = source_row(&pool, "src_1").await.unwrap();
    let mut back = changes(&current);
    back.discovery_url = Some(DISCOVERY.into());
    let op = pending(submit_update(&pool, "key_trust", "op_b", true, ("src_1", 3), &back).await);
    let prepared = prepare(&pool, "key_sec1", "op_b").await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    applied_source(approve_in(&mut tx, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert!(
        conflicts(
            &pool,
            "egress_allowlist_entry",
            "id",
            "egr_disc",
            "FOR NO KEY UPDATE"
        )
        .await
    );
    assert!(
        !conflicts(
            &pool,
            "egress_allowlist_entry",
            "id",
            "egr_disc",
            "FOR SHARE"
        )
        .await
    );
    assert!(conflicts(&pool, "trust_source", "id", "src_1", "FOR KEY SHARE").await);
    tx.commit().await.unwrap();
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The clock is sampled after the registry write, not between the target's
/// lock and the write (D28): the source update's compare-and-set takes the
/// row `FOR UPDATE` and waits behind a token exchange's uncommitted
/// `consumed_assertion` insert (`FOR KEY SHARE`), which the approval's own
/// `FOR NO KEY UPDATE` did not wait for; the clock passes the expiry
/// meanwhile, and the sample after the write refuses the approval, which
/// writes nothing. With the clock left before the expiry, the operation is
/// consumed at the sample taken after the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_clock_is_sampled_after_the_compare_and_set_waits() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_1", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    let op = pending(
        submit_update(
            &pool,
            "key_trust",
            "op_1",
            true,
            ("src_1", 1),
            &renamed(&source, "renamed"),
        )
        .await,
    );
    let before = snapshot(&pool).await;
    for (n, expired) in [(1, true), (2, false)] {
        let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
        let clock = TestClock::new(at(10));
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        let consumption = registry::consume_assertion(&mut *held, &consumed(n))
            .await
            .unwrap();
        assert_eq!(consumption, Consumption::Consumed);
        let (pid, task) =
            spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        assert_eq!(clock.samples(), 0, "sampled before the compare-and-set");
        // It waits at the compare-and-set: the target lock is already held.
        assert!(conflicts(&pool, "trust_source", "id", "src_1", "FOR SHARE").await);
        let later = if expired {
            expiry()
        } else {
            expiry() - Duration::from_micros(1)
        };
        clock.set(later);
        held.rollback().await.unwrap();
        let result = finished(task).await;
        holder.close().await.unwrap();
        assert_eq!(clock.samples(), 1);
        if expired {
            refused(result, "NotApprovable(Expired)");
            assert_eq!(snapshot(&pool).await, before);
        } else {
            let row = applied_source(result);
            assert_eq!((row.name.as_str(), row.revision), ("renamed", 2));
            let consumed = operation(&pool, "op_1").await;
            assert_eq!(consumed.consumed_at, Some(later));
            let events = events(&pool).await;
            assert_eq!(events[events.len() - 2].8, micros_of(later));
            assert_eq!(events[events.len() - 1].8, micros_of(later));
        }
    }
    db.drop([pool]).await;
}

fn micros_of(at: SystemTime) -> i64 {
    i64::try_from(at.duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap()
}

/// Expiry is judged at the one sample after the write: at exactly
/// `expires_at` the approval is refused and writes nothing; one
/// microsecond before, it applies and records that sample.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_is_refused_from_its_expiry_on() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let op = pending(submit_create(&pool, "key_trust", "op_1", true, &uploaded("src_1")).await);
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let before = snapshot(&pool).await;
    let clock = TestClock::new(expiry());
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "NotApprovable(Expired)",
    );
    assert_eq!(clock.samples(), 1);
    assert_eq!(snapshot(&pool).await, before);
    let just_before = expiry() - Duration::from_micros(1);
    clock.set(just_before);
    applied_source(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!(
        operation(&pool, "op_1").await.consumed_at,
        Some(just_before)
    );
    db.drop([pool]).await;
}

/// What the approval writes is what the locked plan holds and what the
/// preparation parsed (D24): a plan that does not recompute to its digest,
/// and a locked plan unequal to the prepared one (the `0005` immutability
/// trigger disabled in between), are `PlanIntegrity`, for both kinds; so
/// are a create plan naming another tenant than its operation's and an
/// update plan whose `changed` is not what its changes change on the
/// stored row. None writes anything.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_approval_writes_only_the_prepared_and_locked_plan() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));
    let rename = renamed(&source, "renamed");
    let disable = with_status(&source, Status::Disabled);
    let good_create = create_plan(&uploaded("src_1"));
    let good_update = update_plan("src_0", &rename, &["name"]);
    let cases = [
        (
            "op_c",
            CREATE,
            0,
            good_create.clone(),
            create_plan(&oidc("src_1", DISCOVERY)),
        ),
        (
            "op_u",
            UPDATE,
            1,
            good_update.clone(),
            update_plan("src_0", &disable, &["status"]),
        ),
    ];
    for (id, kind, revision, good, locked) in cases {
        // A plan that does not recompute to its digest.
        let echo = insert_raw(&pool, &raw(id, kind, revision, good.clone(), Some(&locked))).await;
        let prepared = prepare(&pool, "key_sec1", id).await.unwrap();
        let before = snapshot(&pool).await;
        refused(
            approve(&pool, "key_sec1", &prepared, &echo, &*clock).await,
            "PlanIntegrity",
        );
        assert_eq!(snapshot(&pool).await, before, "{id}");
        // The locked plan changed under the prepared one.
        rewrite_plan(&pool, id, &locked).await;
        let before = snapshot(&pool).await;
        refused(
            approve(&pool, "key_sec1", &prepared, &echo, &*clock).await,
            "PlanIntegrity",
        );
        assert_eq!(snapshot(&pool).await, before, "{id}");
    }
    // A create plan of another tenant, and an update plan whose `changed`
    // is not the stored row's.
    let mut other_tenant = good_create.clone();
    other_tenant.insert("tenant_id".into(), json!("ten_b"));
    let mut wrong_changed = good_update.clone();
    wrong_changed.insert("changed".into(), json!(["exact_issuer", "name"]));
    for (id, kind, revision, plan) in [
        ("op_t", CREATE, 0, other_tenant),
        ("op_w", UPDATE, 1, wrong_changed),
    ] {
        let echo = insert_raw(&pool, &raw(id, kind, revision, plan, None)).await;
        let prepared = prepare(&pool, "key_sec1", id).await.unwrap();
        let before = snapshot(&pool).await;
        refused(
            approve(&pool, "key_sec1", &prepared, &echo, &*clock).await,
            "PlanIntegrity",
        );
        assert_eq!(snapshot(&pool).await, before, "{id}");
    }
    assert_eq!(clock.samples(), 0);
    assert_eq!(source_row(&pool, "src_1").await, None);
    assert_eq!(source_row(&pool, "src_0").await.unwrap(), source);
    // The good plans apply.
    for (id, kind, revision, plan) in [
        ("op_gc", CREATE, 0, good_create),
        ("op_gu", UPDATE, 1, good_update),
    ] {
        let echo = insert_raw(&pool, &raw(id, kind, revision, plan, None)).await;
        let prepared = prepare(&pool, "key_sec1", id).await.unwrap();
        applied_source(approve(&pool, "key_sec1", &prepared, &echo, &*clock).await);
    }
    db.drop([pool]).await;
}

/// A database constraint that only the write checks refuses at the
/// approval (section 3, "the database constraints run only when the row is
/// written"): a source name taken between the request and the approval, by
/// a create and by a rename, is refused with the unique key's
/// `AlreadyExists`; nothing is written and the operation stays pending.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_name_taken_before_the_approval_refuses_it() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    let create = pending(submit_create(&pool, "key_trust", "op_c", true, &uploaded("src_1")).await);
    let rename = pending(
        submit_update(
            &pool,
            "key_trust",
            "op_u",
            true,
            ("src_0", 1),
            &renamed(&source, "wanted"),
        )
        .await,
    );
    let taken = |id: &str, name: &str| NewTrustSource {
        name: name.into(),
        ..uploaded(id)
    };
    direct_create(&pool, &taken("src_x", "source-src_1")).await;
    direct_create(&pool, &taken("src_y", "wanted")).await;
    let clock = TestClock::new(at(10));
    for (op, id) in [(&create, "op_c"), (&rename, "op_u")] {
        let prepared = prepare(&pool, "key_sec1", id).await.unwrap();
        let before = snapshot(&pool).await;
        refused(
            approve(&pool, "key_sec1", &prepared, &echo(op), &*clock).await,
            "Source(Registry(AlreadyExists { constraint: \"trust_source_tenant_id_name_key\" }))",
        );
        assert_eq!(snapshot(&pool).await, before, "{id}");
        assert_eq!(operation(&pool, id).await.outcome, "pending");
    }
    assert_eq!(clock.samples(), 0);
    // Applied at once, the same refusal leaves the caller's transaction
    // usable and writes nothing.
    set_policy(&pool, false, false).await;
    let before = snapshot(&pool).await;
    let taken_name = "AlreadyExists { constraint: \"trust_source_tenant_id_name_key\" }";
    refused(
        submit_create(&pool, "key_trust", "op_x", true, &taken("src_z", "wanted")).await,
        &format!("Registry({taken_name})"),
    );
    refused(
        submit_update(
            &pool,
            "key_trust",
            "op_x",
            true,
            ("src_0", 1),
            &renamed(&source, "wanted"),
        )
        .await,
        &format!("Registry({taken_name})"),
    );
    assert_eq!(snapshot(&pool).await, before);
    // In one open transaction: each refusal, a database error after the
    // locks or a refusal of the gate, leaves the caller's transaction
    // usable and releases the locks the call took (its savepoint).
    set_policy(&pool, true, false).await;
    let mut tx = pool.begin().await.unwrap();
    let new = taken("src_z", "wanted");
    for result in [
        submit_create_source(
            &mut tx,
            &submission("key_trust", "op_x", "evt_op_x", false),
            &new,
        )
        .await,
        submit_update_source(
            &mut tx,
            &submission("key_trust", "op_x", "evt_op_x", false),
            "ten_a",
            "src_0",
            1,
            &renamed(&source, "other"),
        )
        .await,
    ] {
        assert!(result.is_err(), "{result:?}");
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(one, 1);
        for (table, column, id) in [
            ("instance_security_policy", "instance_id", INSTANCE_ID),
            ("trust_source", "id", "src_0"),
            ("admin_credential", "id", "crd_adm_trust"),
        ] {
            assert!(
                !conflicts(&pool, table, column, id, "FOR UPDATE").await,
                "{table}"
            );
        }
    }
    set_policy(&pool, false, false).await;
    let refusal = submit_update_source(
        &mut tx,
        &submission("key_trust", "op_x", "evt_op_x", true),
        "ten_a",
        "src_0",
        1,
        &renamed(&source, "wanted"),
    )
    .await;
    refused(refusal, &format!("Registry({taken_name})"));
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(one, 1);
    for (table, column, id) in [
        ("instance_security_policy", "instance_id", INSTANCE_ID),
        ("trust_source", "id", "src_0"),
        ("admin_credential", "id", "crd_adm_trust"),
    ] {
        assert!(
            !conflicts(&pool, table, column, id, "FOR UPDATE").await,
            "{table}"
        );
    }
    tx.rollback().await.unwrap();
    db.drop([pool]).await;
}

/// Proof bounds whose floats need the shortest round-trip parse survive
/// the plan's text: a gated rename's plan names only `name` as changed, its
/// approval recomputes the same list from the stored row and applies it;
/// and a disable whose changes went through JSON text (as a request body
/// does) is still disable-only. Each value is stored by `jsonb` in its own
/// decimal spelling (`1.132605069600529e-13` as
/// `0.0000000000001132605069600529`).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn proof_bound_floats_survive_the_plan_and_the_request_text() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));
    let values = [
        1.132605069600529e-13,
        1.979_602_974_600_842_2e21,
        1.436992062783981e-8,
        1.764_183_169_287_183_1e-13,
        0.25,
    ];
    for (n, value) in values.into_iter().enumerate() {
        let id = format!("src_{n}");
        let new = NewTrustSource {
            proof_bounds: object(json!({ "x": value })),
            ..uploaded(&id)
        };
        let source = direct_create(&pool, &new).await;
        let op = format!("op_{n}");
        let pending = pending(
            submit_update(
                &pool,
                "key_trust",
                &op,
                true,
                (&id, 1),
                &renamed(&source, &format!("renamed-{n}")),
            )
            .await,
        );
        let plan = operation(&pool, &op).await.immutable_plan;
        assert_eq!(plan["changed"], json!(["name"]), "{value}");
        let prepared = prepare(&pool, "key_sec1", &op).await.unwrap();
        let row =
            applied_source(approve(&pool, "key_sec1", &prepared, &echo(&pending), &*clock).await);
        assert_eq!(row.revision, 2, "{value}");
        // A disable whose changes went through JSON text.
        let text =
            serde_json::to_string(&with_status(&row, Status::Disabled).proof_bounds).unwrap();
        let disable = TrustSourceChanges {
            proof_bounds: serde_json::from_str(&text).unwrap(),
            ..with_status(&row, Status::Disabled)
        };
        let disabled = applied(
            submit_update(
                &pool,
                "key_trust",
                &format!("op_d{n}"),
                false,
                (&id, 2),
                &disable,
            )
            .await,
        );
        assert_eq!(
            (disabled.status, disabled.revision),
            (Status::Disabled, 3),
            "{value}"
        );
        assert_eq!(last_event(&pool).await.7, "success", "{value}");
    }
    db.drop([pool]).await;
}

/// The class and `changed` compare `proof_bounds` with the database's
/// `jsonb` equality, exact for the stored numbers: on a row whose numbers
/// are beyond `f64` precision (written by raw SQL; the service cannot write
/// them), a disable that echoes the row as read is widening, since the echo
/// rounds them, and a gated rename names `proof_bounds` as changed at the
/// request and at the approval alike. Key order and a number's spelling
/// (`600` and `600.0`) are no change.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn proof_bounds_compare_exactly_with_the_stored_jsonb() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));
    direct_create(&pool, &uploaded("src_1")).await;
    sqlx::query(
        "UPDATE trust_source SET proof_bounds = \
         '{\"max_ttl_s\": 18446744073709551617, \"skew\": 0.10000000000000000001}', \
         revision = revision + 1 WHERE id = 'src_1'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let row = source_row(&pool, "src_1").await.unwrap();
    assert_eq!(row.revision, 2);
    let before = snapshot(&pool).await;
    refused(
        submit_update(
            &pool,
            "key_trust",
            "op_x",
            false,
            ("src_1", 2),
            &with_status(&row, Status::Disabled),
        )
        .await,
        "WideningNotAcknowledged",
    );
    assert_eq!(snapshot(&pool).await, before);
    let rename = renamed(&row, "renamed");
    let op = pending(submit_update(&pool, "key_trust", "op_1", true, ("src_1", 2), &rename).await);
    assert_eq!(
        operation(&pool, "op_1").await.immutable_plan["changed"],
        json!(["name", "proof_bounds"])
    );
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let row = applied_source(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    assert_eq!(row.revision, 3);

    // Key order and a number's spelling are no change: a disable-only update.
    let source = direct_create(&pool, &oidc("src_2", DISCOVERY)).await;
    let disable = TrustSourceChanges {
        proof_bounds: object(json!({"skew": 1.5, "max_ttl_s": 600.0})),
        ..with_status(&source, Status::Disabled)
    };
    let disabled =
        applied(submit_update(&pool, "key_trust", "op_2", false, ("src_2", 1), &disable).await);
    assert_eq!(disabled.status, Status::Disabled);
    assert_eq!(last_event(&pool).await.7, "success");
    db.drop([pool]).await;
}

/// The preparation authorizes before it reads or parses the plan (D20): a
/// plan that is not its kind's is reported only to an instance
/// `security_admin` on the operation's own path (`PlanIntegrity`); any
/// other caller learns nothing (`Unauthorized`), and the right approver on
/// another path finds nothing (`NotFound`).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_preparation_authorizes_before_it_parses_the_plan() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    let mut bad_create = create_plan(&uploaded("src_1"));
    bad_create.insert("review_timeout_ms".into(), json!("5000"));
    let mut bad_update = update_plan("src_0", &renamed(&source, "x"), &["name"]);
    bad_update.insert("changed".into(), json!(["status", "name"]));
    for (id, kind, revision, plan) in [
        ("op_c", CREATE, 0, bad_create),
        ("op_u", UPDATE, 1, bad_update),
    ] {
        insert_raw(&pool, &raw(id, kind, revision, plan, None)).await;
        let prepare_as = async |key: &str, scope: ApprovalScope<'_>| {
            prepare_approval(&pool, key, scope, id, ALLOWED, at(1)).await
        };
        refused(prepare_as("key_sec1", TEN_A).await, "PlanIntegrity");
        for key in ["key_trust", "key_other", "key_tb", "spki-sha256:unknown"] {
            refused(prepare_as(key, TEN_A).await, "Unauthorized");
        }
        for scope in [INSTANCE, TEN_B] {
            refused(prepare_as("key_sec1", scope).await, "NotFound");
        }
    }
    db.drop([pool]).await;
}

/// The approval compares the stored digest with the one the preparation
/// read, not only with the echo: a digest changed past the `0005`
/// immutability trigger while the operation was prepared, then put back,
/// is still `EchoMismatch`; nothing is written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_refuses_a_digest_other_than_the_prepared_one() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let op = pending(submit_create(&pool, "key_trust", "op_1", true, &uploaded("src_1")).await);
    let mut other = op.request_digest.as_bytes().to_vec();
    other[0] ^= 1;
    let write_digest = async |digest: &[u8]| {
        sqlx::raw_sql(
            "ALTER TABLE administrative_operation \
             DISABLE TRIGGER administrative_operation_immutable",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE administrative_operation SET request_digest = $2, revision = revision + 1 \
             WHERE id = $1",
        )
        .bind("op_1")
        .bind(digest)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql(
            "ALTER TABLE administrative_operation \
             ENABLE ALWAYS TRIGGER administrative_operation_immutable",
        )
        .execute(&pool)
        .await
        .unwrap();
    };
    write_digest(&other).await;
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    write_digest(op.request_digest.as_bytes()).await;
    let before = snapshot(&pool).await;
    let clock = TestClock::new(at(10));
    refused(
        approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await,
        "EchoMismatch",
    );
    assert_eq!(snapshot(&pool).await, before);
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    applied_source(approve(&pool, "key_sec1", &prepared, &echo(&op), &*clock).await);
    db.drop([pool]).await;
}

/// The approval checks the requester again under the locks (Q5; D21): a
/// requester whose binding was disabled, or whose submitting credential
/// was disabled or revoked, is `RequesterNotAuthorized`, and nothing is
/// written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_requester_must_still_be_a_trust_admin_with_its_credential() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let mut ops = Vec::new();
    for (n, key) in ["key_trust", "key_other", "key_both"]
        .into_iter()
        .enumerate()
    {
        let op_id = format!("op_{n}");
        let op =
            pending(submit_create(&pool, key, &op_id, true, &uploaded(&format!("src_{n}"))).await);
        let prepared = prepare(&pool, "key_sec1", &op_id).await.unwrap();
        ops.push((op, prepared));
    }
    registry::update_admin_role_binding(
        &pool,
        "rb_trust",
        1,
        &AdminRoleBindingChanges {
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE admin_credential SET status = 'disabled' WHERE id = 'crd_adm_other'")
        .execute(&pool)
        .await
        .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_both", at(2))
        .await
        .unwrap();
    let clock = TestClock::new(at(10));
    let before = snapshot(&pool).await;
    for (op, prepared) in &ops {
        refused(
            approve(&pool, "key_sec1", prepared, &echo(op), &*clock).await,
            "RequesterNotAuthorized",
        );
    }
    assert_eq!(clock.samples(), 0);
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A break-glass restoration between the request and the approval of a
/// trust source operation revokes every operator credential, the plan's
/// included. The replacement `security_admin` may prepare the operation on
/// its tenant path, but its approval is `RequesterNotAuthorized` (D21),
/// whether prepared before or after the restoration, and writes nothing;
/// an approver from before the restoration is `Unauthorized`. The
/// replacement may still reject it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restoration_between_the_request_and_the_approval_refuses_it() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    let op = pending(
        submit_update(
            &pool,
            "key_trust",
            "op_1",
            true,
            ("src_0", 1),
            &renamed(&source, "renamed"),
        )
        .await,
    );
    let prepared_before = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let restored = restore(&pool).await;
    for id in ["crd_adm_trust", "crd_adm_sec1"] {
        assert!(
            restored.revoked_credential_ids.iter().any(|c| c == id),
            "{id}"
        );
    }
    refused(prepare(&pool, "key_sec1", "op_1").await, "Unauthorized");
    let prepared_after = prepare(&pool, RESTORED_KEY, "op_1").await.unwrap();
    let clock = TestClock::new(at(10));
    let before = snapshot(&pool).await;
    for prepared in [&prepared_before, &prepared_after] {
        refused(
            approve(&pool, RESTORED_KEY, prepared, &echo(&op), &*clock).await,
            "RequesterNotAuthorized",
        );
        refused(
            approve(&pool, "key_sec1", prepared, &echo(&op), &*clock).await,
            "Unauthorized",
        );
    }
    assert_eq!(clock.samples(), 0);
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(source_row(&pool, "src_0").await.unwrap(), source);
    revoke(&pool, false, RESTORED_KEY, TEN_A, "op_1")
        .await
        .unwrap();
    assert_eq!(operation(&pool, "op_1").await.outcome, "rejected");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// On a tenant path a cancel of a source operation is the requester's:
/// another `trust_admin` of the tenant gets `NotFound`, as for a missing
/// operation; a cancel on another tenant's path is `NotFound` too; the
/// requester cancels, and a `security_admin` other than the requester
/// rejects, its reject operation in the target's tenant. A self-approval
/// or self-reject by a requester who is also a `security_admin` is
/// refused.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_tenant_cancel_of_another_operators_operation_is_not_found() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_0", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    pending(submit_create(&pool, "key_trust", "op_1", true, &uploaded("src_1")).await);
    pending(
        submit_update(
            &pool,
            "key_trust",
            "op_2",
            true,
            ("src_0", 1),
            &renamed(&source, "renamed"),
        )
        .await,
    );
    pending(submit_create(&pool, "key_both", "op_3", true, &uploaded("src_3")).await);
    let before = snapshot(&pool).await;
    for op in ["op_1", "op_2", "op_none"] {
        refused(
            revoke(&pool, true, "key_other", TEN_A, op).await,
            "NotFound",
        );
        refused(revoke(&pool, true, "key_both", TEN_A, op).await, "NotFound");
    }
    refused(
        revoke(&pool, true, "key_tb", TEN_B, "op_1").await,
        "NotFound",
    );
    refused(
        revoke(&pool, true, "key_trust", TEN_B, "op_1").await,
        "Unauthorized",
    );
    refused(
        revoke(&pool, true, "key_sec1", TEN_A, "op_1").await,
        "Unauthorized",
    );
    refused(
        revoke(&pool, false, "key_sec1", INSTANCE, "op_2").await,
        "NotFound",
    );
    refused(
        revoke(&pool, false, "key_trust", TEN_A, "op_2").await,
        "Unauthorized",
    );
    refused(
        revoke(&pool, false, "key_both", TEN_A, "op_3").await,
        "SelfApproval",
    );
    refused(prepare(&pool, "key_both", "op_3").await, "SelfApproval");
    assert_eq!(snapshot(&pool).await, before);
    revoke(&pool, true, "key_trust", TEN_A, "op_1")
        .await
        .unwrap();
    assert_eq!(operation(&pool, "op_1").await.outcome, "cancelled");
    revoke(&pool, false, "key_sec1", TEN_A, "op_2")
        .await
        .unwrap();
    assert_eq!(operation(&pool, "op_2").await.outcome, "rejected");
    assert_eq!(
        operation(&pool, "reject_op_2_key_sec1")
            .await
            .tenant_id
            .as_deref(),
        Some("ten_a")
    );
    refused(
        prepare(&pool, "key_sec1", "op_1").await,
        "NotApprovable(Revoked)",
    );
    assert_eq!(source_row(&pool, "src_0").await.unwrap(), source);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Two approvals of one operation serialize on its row: the second, once
/// the first commits, reads it consumed; after the first rolls back, it
/// applies. An approval and a cancel race the same way; none ends in
/// `40P01`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn approvals_and_cancels_serialize_on_the_operation() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));
    let mut ops = Vec::new();
    for n in 1..=4 {
        let op_id = format!("op_{n}");
        let new = uploaded(&format!("src_{n}"));
        ops.push(pending(
            submit_create(&pool, "key_trust", &op_id, true, &new).await,
        ));
    }
    for (op, commit) in [(&ops[0], true), (&ops[1], false)] {
        let first = prepare(&pool, "key_sec1", &op.id).await.unwrap();
        let second = prepare(&pool, "key_sec2", &op.id).await.unwrap();
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        applied_source(approve_in(&mut held, "key_sec1", &first, &echo(op), &*clock).await);
        let (pid, task) = spawn_approve(&pool, "key_sec2", second, echo(op), clock.clone()).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        if commit {
            held.commit().await.unwrap();
            refused(finished(task).await, "NotApprovable(Consumed)");
        } else {
            held.rollback().await.unwrap();
            applied_source(finished(task).await);
        }
        holder.close().await.unwrap();
        assert_eq!(operation(&pool, &op.id).await.outcome, "applied");
    }
    let (op_3, op_4) = (&ops[2], &ops[3]);
    let prepared = prepare(&pool, "key_sec1", &op_3.id).await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    revoke_in(&mut held, true, "key_trust", TEN_A, &op_3.id)
        .await
        .unwrap();
    let (pid, task) = spawn_approve(&pool, "key_sec1", prepared, echo(op_3), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    refused(finished(task).await, "NotApprovable(Revoked)");
    holder.close().await.unwrap();
    assert_eq!(source_row(&pool, "src_3").await, None);

    let prepared = prepare(&pool, "key_sec1", &op_4.id).await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    applied_source(approve_in(&mut held, "key_sec1", &prepared, &echo(op_4), &*clock).await);
    let (mut canceller, pid) = connection(&pool).await;
    let op_4_id = op_4.id.clone();
    let task = tokio::spawn(async move {
        let mut transaction = canceller.begin().await.unwrap();
        let result = revoke_in(&mut transaction, true, "key_trust", TEN_A, &op_4_id).await;
        transaction.commit().await.unwrap();
        canceller.close().await.unwrap();
        result
    });
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    refused(finished(task).await, "NotApprovable(Consumed)");
    holder.close().await.unwrap();
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// An approval and a direct write of its target serialize on the source
/// row, both orders: a direct update that commits first makes the approval
/// stale (nothing written, the operation stays pending); an approval that
/// commits first makes the direct update stale. None ends in `40P01`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_and_a_direct_write_serialize_on_the_source() {
    let (db, pool) = seeded().await;
    let source = direct_create(&pool, &oidc("src_1", DISCOVERY)).await;
    set_policy(&pool, true, false).await;
    let clock = TestClock::new(at(10));
    let op = pending(
        submit_update(
            &pool,
            "key_trust",
            "op_1",
            true,
            ("src_1", 1),
            &renamed(&source, "renamed"),
        )
        .await,
    );

    // The direct write first.
    let prepared = prepare(&pool, "key_sec1", "op_1").await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    update_source(
        &mut held,
        "key_trust",
        "ten_a",
        "src_1",
        1,
        &with_status(&source, Status::Disabled),
        &audit("evt_d1"),
    )
    .await
    .unwrap();
    let (pid, task) = spawn_approve(&pool, "key_sec1", prepared, echo(&op), clock.clone()).await;
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    holder.close().await.unwrap();
    refused(finished(task).await, "Source(Registry(StaleRevision))");
    assert_eq!(operation(&pool, "op_1").await.outcome, "pending");
    let disabled = source_row(&pool, "src_1").await.unwrap();
    assert_eq!((disabled.status, disabled.revision), (Status::Disabled, 2));

    // The approval first.
    let op = pending(
        submit_update(
            &pool,
            "key_trust",
            "op_2",
            true,
            ("src_1", 2),
            &with_status(&disabled, Status::Enabled),
        )
        .await,
    );
    let prepared = prepare(&pool, "key_sec1", "op_2").await.unwrap();
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    applied_source(approve_in(&mut held, "key_sec1", &prepared, &echo(&op), &*clock).await);
    let (mut writer, pid) = connection(&pool).await;
    let changes = renamed(&disabled, "renamed");
    let task = tokio::spawn(async move {
        let mut transaction = writer.begin().await.unwrap();
        let result = update_source(
            &mut transaction,
            "key_trust",
            "ten_a",
            "src_1",
            2,
            &changes,
            &audit("evt_d2"),
        )
        .await;
        transaction.commit().await.unwrap();
        writer.close().await.unwrap();
        result
    });
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    holder.close().await.unwrap();
    refused(finished(task).await, "Registry(StaleRevision)");
    let row = source_row(&pool, "src_1").await.unwrap();
    assert_eq!((row.status, row.revision), (Status::Enabled, 3));
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The policy row on the real path: a source request holds it `FOR SHARE`
/// and a single-actor toggle of `widening_second_approver` needs it
/// `FOR NO KEY UPDATE`, on two connections, both commit orders. A source
/// create that holds it first is applied under the flag it read
/// (`success_widening`); the toggle waits and then applies after it. A
/// toggle that holds it first makes the create wait: committed, the create
/// reads the flag on and goes pending; rolled back, it reads the flag off
/// and is applied. None ends in `40P01`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_source_request_and_a_policy_toggle_serialize_on_the_policy_row() {
    let (db, pool) = seeded().await;

    // The source request first.
    set_policy(&pool, false, true).await;
    let (_, _, revision) = policy(&pool).await;
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    let created = submit_create_source(
        &mut held,
        &submission("key_trust", "op_1", "evt_op_1", true),
        &uploaded("src_1"),
    )
    .await;
    assert!(matches!(created, Ok(Gated::Applied(_))), "{created:?}");
    let (mut toggler, pid) = connection(&pool).await;
    let task = tokio::spawn(async move {
        let mut transaction = toggler.begin().await.unwrap();
        let result = submit_widening_toggle(
            &mut transaction,
            &submission("key_sec1", "op_t1", "evt_op_t1", false),
            revision,
            true,
        )
        .await;
        transaction.commit().await.unwrap();
        toggler.close().await.unwrap();
        result
    });
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    held.commit().await.unwrap();
    holder.close().await.unwrap();
    assert!(matches!(finished(task).await, Ok(Gated::Applied(_))));
    assert_eq!(policy(&pool).await, (true, true, revision + 1));
    let events = events(&pool).await;
    let actions: Vec<(&str, &str)> = events
        .iter()
        .map(|event| (event.3.as_str(), event.7.as_str()))
        .collect();
    assert_eq!(
        actions,
        [
            ("trust_source.create", "success_widening"),
            ("instance_security_policy.update", "success_single_actor"),
        ]
    );

    // The toggle first, committed and then rolled back.
    for (n, commit) in [(2, true), (3, false)] {
        set_policy(&pool, false, true).await;
        let (_, _, revision) = policy(&pool).await;
        let (mut holder, holder_pid) = connection(&pool).await;
        let mut held = holder.begin().await.unwrap();
        let (toggle_op, toggle_event) = (format!("op_t{n}"), format!("evt_op_t{n}"));
        let toggled = submit_widening_toggle(
            &mut held,
            &submission("key_sec1", &toggle_op, &toggle_event, false),
            revision,
            true,
        )
        .await;
        assert!(matches!(toggled, Ok(Gated::Applied(_))), "{toggled:?}");
        let op: &'static str = if n == 2 { "op_2" } else { "op_3" };
        let (pid, task) = spawn_submit_create(&pool, op, uploaded(&format!("src_{n}"))).await;
        wait_until_blocked(&pool, pid, holder_pid, &task).await;
        if commit {
            held.commit().await.unwrap();
            holder.close().await.unwrap();
            let pending = pending(finished(task).await);
            assert_eq!(pending.id, op);
            assert_eq!(source_row(&pool, "src_2").await, None);
        } else {
            held.rollback().await.unwrap();
            holder.close().await.unwrap();
            applied(finished(task).await);
            assert_eq!(last_event(&pool).await.7, "success_widening");
        }
    }

    // An update, disable-only or not, waits for the policy row before it
    // locks its source row.
    let source = direct_create(&pool, &uploaded("src_9")).await;
    let (_, _, revision) = policy(&pool).await;
    let (mut holder, holder_pid) = connection(&pool).await;
    let mut held = holder.begin().await.unwrap();
    let toggled = submit_widening_toggle(
        &mut held,
        &submission("key_sec1", "op_t9", "evt_op_t9", false),
        revision,
        false,
    )
    .await;
    assert!(matches!(toggled, Ok(Gated::Applied(_))), "{toggled:?}");
    let (mut updater, pid) = connection(&pool).await;
    let disable = with_status(&source, Status::Disabled);
    let task = tokio::spawn(async move {
        let mut transaction = updater.begin().await.unwrap();
        let result = submit_update_source(
            &mut transaction,
            &submission("key_trust", "op_9", "evt_op_9", false),
            "ten_a",
            "src_9",
            1,
            &disable,
        )
        .await;
        transaction.commit().await.unwrap();
        updater.close().await.unwrap();
        result
    });
    wait_until_blocked(&pool, pid, holder_pid, &task).await;
    assert!(!conflicts(&pool, "trust_source", "id", "src_9", "FOR UPDATE").await);
    held.rollback().await.unwrap();
    holder.close().await.unwrap();
    let row = applied(finished(task).await);
    assert_eq!((row.status, row.revision), (Status::Disabled, 2));
    assert_eq!(last_event(&pool).await.7, "success");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}
