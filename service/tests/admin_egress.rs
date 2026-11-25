//! The audited, authorized egress allowlist writes of
//! `skyoauth_service::admin::egress` on a real database: the one role and
//! scope that may perform them (instance `security_admin`) and every other
//! that may not (a tenant `trust_admin`, an instance `auditor`, a tenant
//! `client_admin`, a revoked credential, a disabled operator, disabled
//! bindings, an unknown credential), the generated IDs, the audit event and
//! the chain, the expected revision, a repeated status write, a taken
//! `(purpose, exact_destination)` pair, the destination rule (a `*` refused
//! in the host only; the stored destination checked again at an enable,
//! never at a disable), the widening gate of a create and an enable
//! (IR-052: the acknowledgement, the policy row `FOR SHARE`, the outcome,
//! the refusal with the toggle on; a disable never gated), the isolation
//! level, the locked lookup, a refused or failed write that leaves nothing
//! behind, errors that never quote the destination, and the trust source
//! writes that an entry disabled through the writer refuses (at the write,
//! through the `0011` guard and at the approval of a pending request).
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
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use skyoauth_service::ids::{IdError, IdGenerator, IdKind, test_support::SequentialIds};
use skyoauth_service::{
    admin::{
        self, AdminRequest, AdminWriteError, Audited, EgressEntryCreate, MAX_DESTINATION_BYTES,
        is_valid_destination,
    },
    jwk::DEFAULT_ALLOWED_ALGORITHMS,
    operation::{
        ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, Gated, Submission,
        approve_operation, prepare_approval,
    },
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AssertionProfile, AuditActor, BootstrapRequest, ChainVerdict,
            EgressAllowlistEntry, EgressPurpose, InvariantKind, JsonObject, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, NewEgressAllowlistEntry, NewTenant,
            NewTrustSource, RegistryError, ReplayMode, Status, TrustSource, TrustSourceChanges,
            TrustSourceKind, bootstrap_instance, verify_audit_chain,
        },
    },
    trust::{SourceWriteError, submit_create_source, submit_update_source},
};
use sqlx::{AssertSqlSafe, Connection, Postgres, Transaction};

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;
const SEC: AdminRole = AdminRole::SecurityAdmin;
const TRUST: AdminRole = AdminRole::TrustAdmin;

/// `micros` after `T0`, with sub-microsecond digits, so a write truncates
/// it.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros) + Duration::from_nanos(789)
}

fn micros(micros: u64) -> i64 {
    i64::try_from(T0 + micros).unwrap()
}

/// The instance `security_admin` that performs the writes.
const KEY_SEC: &str = "key_sec";
/// A second instance `security_admin`, the approver of a gated source
/// write.
const KEY_SEC2: &str = "key_sec2";
/// The `trust_admin` of `ten_a`: the requester of the source writes, and
/// refused by every egress write (tenant operators only choose from it).
const KEY_TRUST_A: &str = "key_trust_a";
/// No credential has it.
const KEY_UNKNOWN: &str = "key_unknown";

/// Every enrolled key that authorizes no egress write, and the unknown
/// one: an instance `auditor`; `ten_a`'s `trust_admin`, `auditor` and
/// `client_admin`; a revoked credential, a disabled operator and disabled
/// bindings, each of an operator that holds (or held) instance
/// `security_admin` and `ten_a`'s `trust_admin`.
const NEITHER: [&str; 8] = [
    "key_aud_i",
    KEY_TRUST_A,
    "key_aud_a",
    "key_client_a",
    "key_revoked",
    "key_disabled",
    "key_bind_off",
    KEY_UNKNOWN,
];

/// The enabled `oidc_discovery` entry `egr_disc`.
const DISCOVERY: &str = "https://issuer.example/.well-known/openid-configuration";
/// The disabled `oidc_discovery` entry `egr_off`.
const DISCOVERY_OFF: &str = "https://off.example/.well-known/openid-configuration";
/// The enabled `token_review` entry `egr_tr`.
const TOKEN_REVIEW: &str = "https://k8s.internal.example:6443/";
/// The destination of the entry each create writes.
const CREATED: &str = "https://created.example/.well-known/openid-configuration";

/// `acknowledge_widening` for a create or an enable: widening writes
/// (IR-052, IR-152), refused without it.
const ACK: bool = true;

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// The operator `admin`, enabled, with the credential `crd_<admin>` of
/// `key` and one binding per entry of `bindings`, each `enabled` or not.
async fn operator(
    pool: &PgPool,
    admin: &str,
    key: &str,
    bindings: &[(AdminRole, Option<&str>)],
    bindings_enabled: bool,
) {
    registry::test_support::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: admin.into(),
            status: Status::Enabled,
            created_at: at(0),
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_credential(
        pool,
        &NewAdminCredential {
            id: format!("crd_{admin}"),
            admin_id: admin.into(),
            public_identity: key.into(),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (index, &(role, tenant_id)) in bindings.iter().enumerate() {
        registry::test_support::create_admin_role_binding(
            pool,
            &NewAdminRoleBinding {
                id: format!("rb_{admin}_{index}"),
                admin_id: admin.into(),
                role,
                tenant_id: tenant_id.map(Into::into),
                status: if bindings_enabled {
                    Status::Enabled
                } else {
                    Status::Disabled
                },
            },
        )
        .await
        .unwrap();
    }
}

/// A bootstrapped instance (`adm_first`, key `spki-sha256:first`, an
/// instance `security_admin`); the tenant `ten_a`; the entries `egr_disc`
/// ([`DISCOVERY`], enabled), `egr_off` ([`DISCOVERY_OFF`], disabled) and
/// `egr_tr` ([`TOKEN_REVIEW`], enabled), written with the bare registry
/// writer; and the operators of [`KEY_SEC`], [`KEY_SEC2`] and [`NEITHER`].
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
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
            recovery_public_key: &SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes(),
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    registry::test_support::create_tenant(
        &pool,
        &NewTenant {
            id: "ten_a".into(),
            name: "Tenant A".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (id, purpose, destination, status) in [
        (
            "egr_disc",
            EgressPurpose::OidcDiscovery,
            DISCOVERY,
            Status::Enabled,
        ),
        (
            "egr_off",
            EgressPurpose::OidcDiscovery,
            DISCOVERY_OFF,
            Status::Disabled,
        ),
        (
            "egr_tr",
            EgressPurpose::TokenReview,
            TOKEN_REVIEW,
            Status::Enabled,
        ),
    ] {
        registry::test_support::create_egress_allowlist_entry(
            &pool,
            &NewEgressAllowlistEntry {
                id: id.into(),
                purpose,
                exact_destination: destination.into(),
                status,
            },
        )
        .await
        .unwrap();
    }
    let (ten_a, inst) = (Some("ten_a"), None);
    let both = [(SEC, inst), (TRUST, ten_a)];
    operator(&pool, "adm_sec", KEY_SEC, &[(SEC, inst)], true).await;
    operator(&pool, "adm_sec2", KEY_SEC2, &[(SEC, inst)], true).await;
    operator(&pool, "adm_trust_a", KEY_TRUST_A, &[(TRUST, ten_a)], true).await;
    for (admin, key, role, tenant) in [
        ("adm_aud_i", "key_aud_i", AdminRole::Auditor, inst),
        ("adm_aud_a", "key_aud_a", AdminRole::Auditor, ten_a),
        (
            "adm_client_a",
            "key_client_a",
            AdminRole::ClientAdmin,
            ten_a,
        ),
    ] {
        operator(&pool, admin, key, &[(role, tenant)], true).await;
    }
    operator(&pool, "adm_revoked", "key_revoked", &both, true).await;
    registry::revoke_admin_credential(&pool, "crd_adm_revoked", at(1))
        .await
        .unwrap();
    operator(&pool, "adm_disabled", "key_disabled", &both, true).await;
    registry::disable_admin_identity(&pool, "adm_disabled")
        .await
        .unwrap();
    operator(&pool, "adm_bind_off", "key_bind_off", &both, false).await;
    (db, pool)
}

/// Each egress write, with a fixed target and input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Write {
    /// An enabled `oidc_discovery` entry for [`CREATED`].
    Create,
    /// `egr_off`, disabled: a re-enable.
    Enable,
    /// `egr_disc`, enabled.
    Disable,
}

const WRITES: [Write; 3] = [Write::Create, Write::Enable, Write::Disable];

impl Write {
    fn target(self) -> &'static str {
        match self {
            Self::Create => panic!("a create has no target"),
            Self::Enable => "egr_off",
            Self::Disable => "egr_disc",
        }
    }

    fn action(self) -> &'static str {
        match self {
            Self::Create => "egress_allowlist_entry.create",
            Self::Enable => "egress_allowlist_entry.enable",
            Self::Disable => "egress_allowlist_entry.disable",
        }
    }

    /// Its event's outcome with `widening_second_approver` off: a create
    /// and an enable are widening (D23), a disable is not.
    fn outcome(self) -> &'static str {
        match self {
            Self::Create | Self::Enable => "success_widening",
            Self::Disable => "success",
        }
    }
}

fn request<'a>(key: &'a str, ids: &'a dyn IdGenerator) -> AdminRequest<'a> {
    AdminRequest {
        public_identity: key,
        ids,
        now: at(5),
    }
}

fn created(destination: &str) -> EgressEntryCreate {
    EgressEntryCreate {
        purpose: EgressPurpose::OidcDiscovery,
        exact_destination: destination.into(),
        status: Status::Enabled,
    }
}

async fn revision(pool: &PgPool, id: &str) -> i64 {
    registry::get_egress_allowlist_entry(pool, id)
        .await
        .unwrap()
        .revision
}

/// `write` by `key` at `expected` in `transaction`, acknowledged.
async fn call(
    transaction: &mut Transaction<'_, Postgres>,
    ids: &dyn IdGenerator,
    write: Write,
    key: &str,
    expected: i64,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    call_with(transaction, ids, write, key, expected, ACK).await
}

/// [`call`] with `acknowledge` as the acknowledgement of a create or an
/// enable (a disable takes none).
async fn call_with(
    transaction: &mut Transaction<'_, Postgres>,
    ids: &dyn IdGenerator,
    write: Write,
    key: &str,
    expected: i64,
    acknowledge: bool,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    let request = request(key, ids);
    match write {
        Write::Create => {
            admin::create_egress_entry(transaction, &request, &created(CREATED), acknowledge).await
        }
        Write::Enable => {
            let target = write.target();
            admin::enable_egress_entry(transaction, &request, target, expected, acknowledge).await
        }
        Write::Disable => {
            admin::disable_egress_entry(transaction, &request, write.target(), expected).await
        }
    }
}

/// `write` by `key` at the target's current revision, in a transaction
/// committed either way.
async fn run(
    pool: &PgPool,
    ids: &dyn IdGenerator,
    write: Write,
    key: &str,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    let expected = match write {
        Write::Create => 0,
        _ => revision(pool, write.target()).await,
    };
    let mut transaction = pool.begin().await.unwrap();
    let result = call(&mut transaction, ids, write, key, expected).await;
    transaction.commit().await.unwrap();
    result
}

/// Runs `steps` in a transaction of its own and commits it, also after an
/// error.
async fn committed<T>(
    pool: &PgPool,
    steps: impl AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<T, AdminWriteError>,
) -> Result<T, AdminWriteError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = steps(&mut transaction).await;
    transaction.commit().await.unwrap();
    result
}

/// A generator that gives the IDs of `inner` but fails its `fail_at`-th
/// call, counted from 1, with `error`.
struct FailingIds<'a> {
    inner: &'a SequentialIds,
    calls: AtomicUsize,
    fail_at: usize,
    error: IdError,
}

impl<'a> FailingIds<'a> {
    fn new(inner: &'a SequentialIds, fail_at: usize, error: IdError) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
            fail_at,
            error,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl IdGenerator for FailingIds<'_> {
    fn new_id(&self, kind: IdKind) -> Result<String, IdError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_at {
            Err(self.error)
        } else {
            self.inner.new_id(kind)
        }
    }
}

#[track_caller]
fn refused<T: std::fmt::Debug, E: std::fmt::Debug>(result: Result<T, E>, expected: &str) {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => assert_eq!(format!("{err:?}"), expected),
    }
}

/// Every row an egress write or a source write may change, as text.
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let mut rows = Vec::new();
    for table in [
        "egress_allowlist_entry",
        "trust_source",
        "administrative_operation",
        "audit_event",
        "audit_chain_head",
        "admin_identity",
        "admin_credential",
        "admin_role_binding",
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

/// A stored event: ID, tenant, actor, action, object, revisions, outcome
/// and time.
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

async fn last_event(pool: &PgPool) -> Event {
    sqlx::query_as(
        "SELECT id, tenant_id, actor, action, object_id, previous_revision, new_revision, \
         outcome, (extract(epoch FROM timestamp) * 1000000)::bigint \
         FROM audit_event ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn event_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_event")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn assert_chain_intact(pool: &PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    let verdict = verify_audit_chain(&mut connection).await.unwrap();
    assert!(
        matches!(verdict, ChainVerdict::Intact { .. }),
        "{verdict:?}"
    );
}

/// Every egress write refuses every operator but an instance
/// `security_admin`: one `Unauthorized`, nothing written, no ID generated.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn every_egress_write_refuses_every_other_operator() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(9);
    let before = snapshot(&pool).await;
    for write in WRITES {
        for key in NEITHER {
            let result = run(&pool, &ids, write, key).await;
            assert!(
                matches!(result, Err(AdminWriteError::Unauthorized)),
                "{write:?} by {key}: {result:?}"
            );
        }
    }
    // A refused create with a destination the rule refuses is
    // `Unauthorized` too: the authorization comes first.
    let refused_create = committed(&pool, async |tx| {
        let request = request(KEY_TRUST_A, &ids);
        admin::create_egress_entry(tx, &request, &created("http://bad.example/"), ACK).await
    })
    .await;
    refused(refused_create, "Unauthorized");
    assert_eq!(snapshot(&pool).await, before);
    let fresh = SequentialIds::with_seed(9);
    for kind in IdKind::ALL {
        assert_eq!(ids.new_id(kind), fresh.new_id(kind), "{kind:?}");
    }
    db.drop([pool]).await;
}

/// Every egress write applies for an instance `security_admin` (the
/// bootstrapped one included): the row with a generated ID (a create) or
/// the next revision and the new status, and its instance event, last; the
/// chain verifies.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn every_egress_write_applies_with_its_event() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(3);
    let expected_ids = SequentialIds::with_seed(3);
    for (write, key, admin_id) in [
        (Write::Create, KEY_SEC, "adm_sec"),
        (Write::Enable, KEY_SEC, "adm_sec"),
        (Write::Disable, "spki-sha256:first", "adm_first"),
    ] {
        let count = event_count(&pool).await;
        let previous = match write {
            Write::Create => None,
            _ => Some(revision(&pool, write.target()).await),
        };
        let done = run(&pool, &ids, write, key)
            .await
            .unwrap_or_else(|err| panic!("{write:?}: {err:?}"));
        let row = &done.row;
        match write {
            Write::Create => {
                assert_eq!(row.id, expected_ids.new_id(IdKind::EgressEntry).unwrap());
                assert!(row.id.starts_with("egr_"), "{}", row.id);
                assert_eq!(
                    (
                        row.purpose,
                        row.exact_destination.as_str(),
                        row.status,
                        row.revision
                    ),
                    (EgressPurpose::OidcDiscovery, CREATED, Status::Enabled, 1)
                );
            }
            Write::Enable | Write::Disable => {
                assert_eq!(row.id, write.target());
                assert_eq!(Some(row.revision - 1), previous);
                let status = if write == Write::Enable {
                    Status::Enabled
                } else {
                    Status::Disabled
                };
                assert_eq!(row.status, status);
            }
        }
        assert_eq!(
            registry::get_egress_allowlist_entry(&pool, &row.id)
                .await
                .unwrap(),
            *row
        );
        let event_id = expected_ids.new_id(IdKind::AuditEvent).unwrap();
        let actor = AuditActor::Operator(admin_id.into());
        assert_eq!(event_count(&pool).await, count + 1, "{write:?}");
        assert_eq!(
            last_event(&pool).await,
            (
                event_id.clone(),
                None,
                actor.canonical_json(),
                write.action().into(),
                row.id.clone(),
                previous,
                Some(row.revision),
                write.outcome().into(),
                micros(5),
            ),
            "{write:?}"
        );
        let event = &done.event;
        assert_eq!(event.id, event_id);
        assert_eq!(event.actor, actor);
        assert_eq!(event.action, write.action());
        assert_eq!(event.object_id, row.id);
        assert_eq!(event.tenant_id, None);
        assert_eq!(event.outcome, write.outcome());
        assert_eq!(event.sequence, count + 1);
    }
    // The other entries are as seeded.
    for (id, status) in [("egr_tr", Status::Enabled)] {
        let entry = registry::get_egress_allowlist_entry(&pool, id)
            .await
            .unwrap();
        assert_eq!((entry.status, entry.revision), (status, 1));
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The widening egress writes: a create, enabled or disabled, and an
/// enable, each with or without the acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Widening {
    Create(Status),
    Enable,
}

const WIDENING: [Widening; 3] = [
    Widening::Create(Status::Enabled),
    Widening::Create(Status::Disabled),
    Widening::Enable,
];

/// `write` by [`KEY_SEC`] with `acknowledge`, in a transaction committed
/// either way: a create for `https://<host>-on.example/` (enabled) or
/// `https://<host>-off.example/` (disabled), an enable of `egr_off` at its
/// current revision.
async fn widening(
    pool: &PgPool,
    ids: &dyn IdGenerator,
    (write, host): (Widening, &str),
    acknowledge: bool,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    let expected = revision(pool, "egr_off").await;
    let sec = request(KEY_SEC, ids);
    committed(pool, async |tx| match write {
        Widening::Create(status) => {
            let suffix = if status == Status::Enabled {
                "on"
            } else {
                "off"
            };
            let destination = format!("https://{host}-{suffix}.example/");
            let new = EgressEntryCreate {
                status,
                ..created(&destination)
            };
            admin::create_egress_entry(tx, &sec, &new, acknowledge).await
        }
        Widening::Enable => {
            admin::enable_egress_entry(tx, &sec, "egr_off", expected, acknowledge).await
        }
    })
    .await
}

/// That `ids` gave no ID: its next IDs are a fresh generator's of `seed`.
#[track_caller]
fn no_id_taken(ids: &SequentialIds, seed: u64) {
    let fresh = SequentialIds::with_seed(seed);
    for kind in [IdKind::EgressEntry, IdKind::AuditEvent] {
        assert_eq!(ids.new_id(kind), fresh.new_id(kind), "{kind:?}");
    }
}

/// With `widening_second_approver` off, a create (enabled or disabled) and
/// an enable without `acknowledge_widening` are `WideningNotAcknowledged`,
/// write nothing and take no ID; acknowledged, each applies with outcome
/// `success_widening` (D23). A disable takes no acknowledgement and records
/// `success`.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_widening_egress_write_needs_the_acknowledgement() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(21);
    let before = snapshot(&pool).await;
    for write in WIDENING {
        refused(
            widening(&pool, &ids, (write, "h1"), false).await,
            "WideningNotAcknowledged",
        );
    }
    assert_eq!(snapshot(&pool).await, before);
    no_id_taken(&ids, 21);
    let ids = SequentialIds::with_seed(22);
    let mut created_status = Vec::new();
    for write in WIDENING {
        let done = widening(&pool, &ids, (write, "h2"), true)
            .await
            .unwrap_or_else(|err| panic!("{write:?}: {err:?}"));
        assert_eq!(done.event.outcome, "success_widening", "{write:?}");
        assert_eq!(last_event(&pool).await.7, "success_widening", "{write:?}");
        if let Widening::Create(status) = write {
            created_status.push(done.row.status);
            assert_eq!(done.row.status, status);
        }
    }
    assert_eq!(created_status, [Status::Enabled, Status::Disabled]);
    let done = try_set_entry(&pool, &ids, "egr_disc", false).await.unwrap();
    assert_eq!(done.event.outcome, "success");
    db.drop([pool]).await;
}

/// With `widening_second_approver` on and `single_actor_mode` off, a
/// create (enabled or disabled) and an enable are refused, acknowledged or
/// not, writing nothing and taking no ID: `SecondApproverRequired` (IR-052:
/// no effect before an approval), after `WideningNotAcknowledged` and after
/// the authorization. A disable is never gated: it applies with `success`.
/// With `single_actor_mode` on too, the requester, an instance
/// `security_admin`, applies them at once with `success_single_actor`
/// (Q4).
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn with_the_gate_on_a_widening_egress_write_is_refused() {
    let (db, pool) = seeded().await;
    set_policy(&pool, true, false).await;
    let ids = SequentialIds::with_seed(23);
    let before = snapshot(&pool).await;
    for write in WIDENING {
        refused(
            widening(&pool, &ids, (write, "h3"), true).await,
            "SecondApproverRequired",
        );
        refused(
            widening(&pool, &ids, (write, "h4"), false).await,
            "WideningNotAcknowledged",
        );
    }
    for write in [Write::Create, Write::Enable] {
        for acknowledge in [true, false] {
            let expected = match write {
                Write::Create => 0,
                _ => revision(&pool, write.target()).await,
            };
            let mut tx = pool.begin().await.unwrap();
            refused(
                call_with(&mut tx, &ids, write, KEY_TRUST_A, expected, acknowledge).await,
                "Unauthorized",
            );
            tx.commit().await.unwrap();
        }
    }
    assert_eq!(snapshot(&pool).await, before);
    no_id_taken(&ids, 23);
    let ids = SequentialIds::with_seed(24);
    let done = try_set_entry(&pool, &ids, "egr_disc", false).await.unwrap();
    assert_eq!(
        (done.row.status, done.event.outcome.as_str()),
        (Status::Disabled, "success")
    );
    set_policy(&pool, true, true).await;
    for write in WIDENING {
        let done = widening(&pool, &ids, (write, "h5"), true)
            .await
            .unwrap_or_else(|err| panic!("{write:?}: {err:?}"));
        assert_eq!(done.event.outcome, "success_single_actor", "{write:?}");
    }
    refused(
        widening(&pool, &ids, (Widening::Enable, "h6"), false).await,
        "WideningNotAcknowledged",
    );
    db.drop([pool]).await;
}

/// Before bootstrap there is no policy row: a create and an enable by an
/// instance `security_admin` are `PolicyUnavailable` (D18), writing nothing
/// and taking no ID.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_widening_egress_write_needs_the_policy_row() {
    let (db, pool) = migrated().await;
    operator(&pool, "adm_sec", KEY_SEC, &[(SEC, None)], true).await;
    registry::test_support::create_egress_allowlist_entry(
        &pool,
        &NewEgressAllowlistEntry {
            id: "egr_off".into(),
            purpose: EgressPurpose::OidcDiscovery,
            exact_destination: DISCOVERY_OFF.into(),
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    let ids = SequentialIds::with_seed(25);
    let before = snapshot(&pool).await;
    for write in WIDENING {
        refused(
            widening(&pool, &ids, (write, "h7"), true).await,
            "PolicyUnavailable",
        );
    }
    assert_eq!(snapshot(&pool).await, before);
    no_id_taken(&ids, 25);
    db.drop([pool]).await;
}

/// A create and an enable hold the policy row `FOR SHARE` until their
/// transaction ends, so a toggle waits for them; a disable takes no policy
/// row.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_widening_egress_write_holds_the_policy_row() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(26);
    for (write, waits) in [
        (Write::Create, true),
        (Write::Enable, true),
        (Write::Disable, false),
    ] {
        let expected = match write {
            Write::Create => 0,
            _ => revision(&pool, write.target()).await,
        };
        let mut tx = pool.begin().await.unwrap();
        call(&mut tx, &ids, write, KEY_SEC, expected).await.unwrap();
        let mut toggle = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout = '200ms'")
            .execute(&mut *toggle)
            .await
            .unwrap();
        let result = sqlx::query(
            "UPDATE instance_security_policy SET widening_second_approver = true, \
             revision = revision + 1",
        )
        .execute(&mut *toggle)
        .await;
        match (waits, result) {
            (true, Err(err)) => assert!(format!("{err:?}").contains("55P03"), "{err:?}"),
            (false, Ok(done)) => assert_eq!(done.rows_affected(), 1),
            (_, other) => panic!("{write:?}: {other:?}"),
        }
        toggle.rollback().await.unwrap();
        tx.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

/// A status write at another revision is the registry's `StaleRevision`,
/// and of an entry that does not exist `NotFound`; neither writes
/// anything or takes an ID.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_status_write_checks_the_expected_revision() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let before = snapshot(&pool).await;
    for write in [Write::Enable, Write::Disable] {
        let current = revision(&pool, write.target()).await;
        for expected in [current - 1, current + 1, 0, i64::MAX] {
            let mut tx = pool.begin().await.unwrap();
            refused(
                call(&mut tx, &ids, write, KEY_SEC, expected).await,
                "Registry(StaleRevision)",
            );
            tx.commit().await.unwrap();
        }
    }
    let sec = request(KEY_SEC, &ids);
    refused(
        committed(&pool, async |tx| {
            admin::enable_egress_entry(tx, &sec, "egr_missing", 1, ACK).await
        })
        .await,
        "Registry(NotFound)",
    );
    refused(
        committed(&pool, async |tx| {
            admin::disable_egress_entry(tx, &sec, "egr_missing", 1).await
        })
        .await,
        "Registry(NotFound)",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(
        ids.new_id(IdKind::AuditEvent).unwrap(),
        SequentialIds::new().new_id(IdKind::AuditEvent).unwrap()
    );
    db.drop([pool]).await;
}

/// A repeated disable and a repeated enable each advance the revision and
/// record their action again; a disabled entry's re-enable is `enable`;
/// a create of a disabled entry is `create`, and its first enable
/// `enable`.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_repeated_status_write_is_recorded_again() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let sec = request(KEY_SEC, &ids);
    let mut actions = Vec::new();
    for (enable, expected, status) in [
        (false, 1, Status::Disabled),
        (false, 2, Status::Disabled),
        (true, 3, Status::Enabled),
        (true, 4, Status::Enabled),
        (false, 5, Status::Disabled),
    ] {
        let done = committed(&pool, async |tx| {
            if enable {
                admin::enable_egress_entry(tx, &sec, "egr_disc", expected, ACK).await
            } else {
                admin::disable_egress_entry(tx, &sec, "egr_disc", expected).await
            }
        })
        .await
        .unwrap();
        assert_eq!((done.row.revision, done.row.status), (expected + 1, status));
        assert_eq!(done.event.previous_revision, Some(expected));
        assert_eq!(done.event.new_revision, Some(expected + 1));
        actions.push(done.event.action);
    }
    assert_eq!(
        actions,
        [
            "egress_allowlist_entry.disable",
            "egress_allowlist_entry.disable",
            "egress_allowlist_entry.enable",
            "egress_allowlist_entry.enable",
            "egress_allowlist_entry.disable",
        ]
    );
    let entry = registry::get_egress_allowlist_entry(&pool, "egr_disc")
        .await
        .unwrap();
    assert_eq!(
        (entry.purpose, entry.exact_destination.as_str()),
        (EgressPurpose::OidcDiscovery, DISCOVERY)
    );
    // A disabled create, then its enable.
    let new = EgressEntryCreate {
        status: Status::Disabled,
        ..created(CREATED)
    };
    let done = committed(&pool, async |tx| {
        admin::create_egress_entry(tx, &sec, &new, ACK).await
    })
    .await
    .unwrap();
    assert_eq!((done.row.status, done.row.revision), (Status::Disabled, 1));
    assert_eq!(done.event.action, "egress_allowlist_entry.create");
    let id = done.row.id;
    let done = committed(&pool, async |tx| {
        admin::enable_egress_entry(tx, &sec, &id, 1, ACK).await
    })
    .await
    .unwrap();
    assert_eq!((done.row.status, done.row.revision), (Status::Enabled, 2));
    assert_eq!(done.event.action, "egress_allowlist_entry.enable");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// A `(purpose, exact_destination)` pair another entry has, enabled or
/// disabled, is `AlreadyExists` naming the unique key, writes nothing and
/// leaves the transaction usable; the same destination of another purpose
/// is another entry.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_taken_pair_is_already_exists() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let sec = request(KEY_SEC, &ids);
    let before = snapshot(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    for (purpose, destination, status) in [
        (EgressPurpose::OidcDiscovery, DISCOVERY, Status::Enabled),
        (EgressPurpose::OidcDiscovery, DISCOVERY, Status::Disabled),
        (EgressPurpose::OidcDiscovery, DISCOVERY_OFF, Status::Enabled),
        (EgressPurpose::TokenReview, TOKEN_REVIEW, Status::Enabled),
    ] {
        let new = EgressEntryCreate {
            purpose,
            exact_destination: destination.into(),
            status,
        };
        refused(
            admin::create_egress_entry(&mut tx, &sec, &new, ACK).await,
            "Registry(AlreadyExists { constraint: \
             \"egress_allowlist_entry_purpose_exact_destination_key\" })",
        );
    }
    tx.commit().await.unwrap();
    assert_eq!(snapshot(&pool).await, before);
    // Another purpose, the same destination.
    for purpose in [EgressPurpose::Jwks, EgressPurpose::TokenReview] {
        let new = EgressEntryCreate {
            purpose,
            ..created(DISCOVERY)
        };
        let done = committed(&pool, async |tx| {
            admin::create_egress_entry(tx, &sec, &new, ACK).await
        })
        .await
        .unwrap();
        assert_eq!(
            (done.row.purpose, done.row.exact_destination.as_str()),
            (purpose, DISCOVERY)
        );
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Destinations the writer refuses: not an exact `https` URL in canonical
/// form, or over the writer's bounds (see the module docs of
/// `skyoauth_service::admin`, "Egress allowlist").
fn invalid_destinations() -> Vec<(&'static str, String)> {
    let long = format!(
        "https://idp.example/{}",
        "a".repeat(MAX_DESTINATION_BYTES - "https://idp.example/".len() + 1)
    );
    let mut cases: Vec<(&'static str, String)> = [
        ("empty", ""),
        ("no scheme", "idp.example/"),
        ("relative", "/.well-known/openid-configuration"),
        ("http", "http://idp.example/"),
        ("http for token review", "http://k8s.internal.example:6443/"),
        ("another scheme", "ftp://idp.example/"),
        ("file", "file:///etc/passwd"),
        ("an upper-case scheme", "HTTPS://idp.example/"),
        ("an upper-case host", "https://IDP.example/"),
        ("no path", "https://idp.example"),
        ("no path, a port", "https://k8s.internal.example:6443"),
        ("the default port", "https://idp.example:443/"),
        ("an empty port", "https://idp.example:/"),
        ("userinfo", "https://user@idp.example/"),
        ("userinfo with a password", "https://user:pw@idp.example/"),
        ("an empty userinfo", "https://@idp.example/"),
        ("a fragment", "https://idp.example/#jwks"),
        ("an empty fragment", "https://idp.example/#"),
        ("a space", "https://idp.example/a b"),
        ("a leading space", " https://idp.example/"),
        ("a trailing newline", "https://idp.example/\n"),
        ("a tab", "https://idp.example/\ta"),
        ("a NUL", "https://idp.example/\u{0}"),
        ("a DEL", "https://idp.example/\u{7f}"),
        ("a C1 control", "https://idp.example/\u{85}"),
        ("a backslash", "https://idp.example/a\\b"),
        ("a bare percent", "https://idp.example/%"),
        ("a short escape", "https://idp.example/%4"),
        ("a non-hex escape", "https://idp.example/%zz"),
        ("an escaped letter", "https://idp.example/%61"),
        ("an escaped host letter", "https://%69dp.example/"),
        ("a hex IPv4 host", "https://0x7f.0.0.1/"),
        ("a short IPv4 host", "https://127.1/"),
        ("an octal IPv4 host", "https://0177.0.0.1/"),
        ("an uncompressed IPv6 host", "https://[0:0:0:0:0:0:0:1]/"),
        ("a U-label host", "https://b\u{fc}cher.example/"),
        ("a fullwidth dot", "https://idp\u{ff0e}example/"),
        ("a dot segment", "https://idp.example/a/../b"),
        ("a single dot segment", "https://idp.example/./b"),
        ("no host", "https:///x"),
        ("a wildcard host", "https://*.idp.example/"),
        ("a star in the host", "https://idp.*/"),
        ("a star host, a path with one", "https://*/keys/*"),
    ]
    .into_iter()
    .map(|(label, destination)| (label, destination.to_owned()))
    .collect();
    cases.push(("over 2048 bytes", long));
    cases
}

/// Destinations the writer takes: canonical `https` URLs within its
/// bounds, of any host spelling the parser keeps as it is.
fn valid_destinations() -> Vec<(&'static str, String)> {
    let at_limit = format!(
        "https://idp.example/{}",
        "a".repeat(MAX_DESTINATION_BYTES - "https://idp.example/".len())
    );
    let mut cases: Vec<(&'static str, String)> = [
        ("a host and a path", "https://v1.example/"),
        (
            "a port",
            "https://v2.example:8443/.well-known/openid-configuration",
        ),
        (
            "a token review endpoint",
            "https://v3.internal.example:6443/",
        ),
        ("a query", "https://v4.example/discovery/keys?appid=a1"),
        ("an empty query", "https://v5.example/keys?"),
        ("an escaped slash", "https://v6.example/a%2Fb"),
        ("an IPv4 host", "https://10.0.0.7/"),
        ("an IPv6 host", "https://[::1]:6443/"),
        ("an A-label host", "https://xn--bcher-kva.example/"),
        ("a literal star in the path", "https://v7.example/keys/*"),
        (
            "a literal star in the query",
            "https://v8.example/keys?kid=*",
        ),
    ]
    .into_iter()
    .map(|(label, destination)| (label, destination.to_owned()))
    .collect();
    cases.push(("exactly 2048 bytes", at_limit));
    cases
}

/// The destination rule: each refused destination is `InvalidDestination`
/// for every purpose and status, writes nothing and takes no ID; each
/// accepted one is written exactly as given. `is_valid_destination` agrees.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_destination_must_be_an_exact_canonical_https_url() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(4);
    let sec = request(KEY_SEC, &ids);
    let before = snapshot(&pool).await;
    for (label, destination) in invalid_destinations() {
        assert!(!is_valid_destination(&destination), "{label}");
        for purpose in [
            EgressPurpose::OidcDiscovery,
            EgressPurpose::Jwks,
            EgressPurpose::TokenReview,
        ] {
            for status in [Status::Enabled, Status::Disabled] {
                let new = EgressEntryCreate {
                    purpose,
                    exact_destination: destination.clone(),
                    status,
                };
                let result = committed(&pool, async |tx| {
                    admin::create_egress_entry(tx, &sec, &new, ACK).await
                })
                .await;
                assert!(
                    matches!(result, Err(AdminWriteError::InvalidDestination)),
                    "{label} {purpose:?} {status:?}: {result:?}"
                );
            }
        }
    }
    assert_eq!(snapshot(&pool).await, before);
    let fresh = SequentialIds::with_seed(4);
    for kind in [IdKind::EgressEntry, IdKind::AuditEvent] {
        assert_eq!(ids.new_id(kind), fresh.new_id(kind), "{kind:?}");
    }
    let purposes = [
        EgressPurpose::OidcDiscovery,
        EgressPurpose::Jwks,
        EgressPurpose::TokenReview,
    ];
    for (n, (label, destination)) in valid_destinations().into_iter().enumerate() {
        assert!(is_valid_destination(&destination), "{label}");
        let new = EgressEntryCreate {
            purpose: purposes[n % purposes.len()],
            exact_destination: destination.clone(),
            status: Status::Enabled,
        };
        let done = committed(&pool, async |tx| {
            admin::create_egress_entry(tx, &sec, &new, ACK).await
        })
        .await
        .unwrap_or_else(|err| panic!("{label}: {err:?}"));
        assert_eq!(done.row.exact_destination, destination, "{label}");
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// A literal `*` in the path or in the query is taken by every writer, as
/// by a source (byte equality: never a wildcard there): a create, enabled
/// and disabled, and the enable of the disabled one, which checks its
/// stored destination again. A `*` in the host is refused, at a create and
/// at the enable of an entry written in SQL.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn only_a_star_in_the_host_is_refused() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(41);
    let sec = request(KEY_SEC, &ids);
    for (n, destination) in [
        "https://s1.example/keys/*",
        "https://s2.example/keys?kid=*",
        "https://s3.example/*/jwks?kid=*&x=*",
    ]
    .into_iter()
    .enumerate()
    {
        for (purpose, status) in [
            (EgressPurpose::Jwks, Status::Enabled),
            (EgressPurpose::OidcDiscovery, Status::Disabled),
        ] {
            let new = EgressEntryCreate {
                purpose,
                exact_destination: destination.into(),
                status,
            };
            let done = committed(&pool, async |tx| {
                admin::create_egress_entry(tx, &sec, &new, ACK).await
            })
            .await
            .unwrap_or_else(|err| panic!("{n} {status:?}: {err:?}"));
            assert_eq!(done.row.exact_destination, destination);
            assert_eq!(done.row.status, status);
            if status == Status::Disabled {
                let enabled = try_set_entry(&pool, &ids, &done.row.id, true)
                    .await
                    .unwrap_or_else(|err| panic!("{n} enable: {err:?}"));
                assert_eq!(enabled.row.status, Status::Enabled);
                assert_eq!(enabled.row.exact_destination, destination);
            }
        }
    }
    let host = "https://*.s4.example/";
    let before = snapshot(&pool).await;
    for status in [Status::Enabled, Status::Disabled] {
        let new = EgressEntryCreate {
            status,
            ..created(host)
        };
        refused(
            committed(&pool, async |tx| {
                admin::create_egress_entry(tx, &sec, &new, ACK).await
            })
            .await,
            "InvalidDestination",
        );
    }
    assert_eq!(snapshot(&pool).await, before);
    seed_entry(&pool, "egr_star_host", host, Status::Disabled).await;
    let before = snapshot(&pool).await;
    refused(
        try_set_entry(&pool, &ids, "egr_star_host", true).await,
        "InvalidDestination",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The entry `id` for `destination`, of `token_review`, written in SQL
/// through the bare registry writer, as a fixture does: no destination
/// check and no event.
async fn seed_entry(pool: &PgPool, id: &str, destination: &str, status: Status) {
    registry::test_support::create_egress_allowlist_entry(
        pool,
        &NewEgressAllowlistEntry {
            id: id.into(),
            purpose: EgressPurpose::TokenReview,
            exact_destination: destination.into(),
            status,
        },
    )
    .await
    .unwrap();
}

/// An entry written in SQL whose destination fails the create rule (the
/// pathless `token_review` URL of the A29 fixture, `tests/security/a29.rs`)
/// cannot be enabled through the writer, disabled or already enabled: the
/// enable checks the stored destination of the row its revision-checked
/// update returns, and is `InvalidDestination` with nothing written, no
/// event and no ID taken. The authorization and the gate come first: a
/// `trust_admin` gets `Unauthorized`, no acknowledgement
/// `WideningNotAcknowledged`, the gate on `SecondApproverRequired`.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn an_enable_checks_the_stored_destination() {
    let (db, pool) = seeded().await;
    let pathless = "https://k8s-a.example:6443";
    assert!(!is_valid_destination(pathless));
    seed_entry(&pool, "egr_bad_off", pathless, Status::Disabled).await;
    seed_entry(
        &pool,
        "egr_bad_on",
        "https://k8s-b.example:6443",
        Status::Enabled,
    )
    .await;
    let ids = SequentialIds::with_seed(42);
    let before = snapshot(&pool).await;
    let count = event_count(&pool).await;
    for id in ["egr_bad_off", "egr_bad_on"] {
        let enable = async |key: &str, acknowledge: bool| {
            let request = request(key, &ids);
            committed(&pool, async |tx| {
                admin::enable_egress_entry(tx, &request, id, 1, acknowledge).await
            })
            .await
        };
        refused(enable(KEY_SEC, ACK).await, "InvalidDestination");
        refused(enable(KEY_TRUST_A, ACK).await, "Unauthorized");
        refused(enable(KEY_SEC, false).await, "WideningNotAcknowledged");
        set_policy(&pool, true, false).await;
        refused(enable(KEY_SEC, ACK).await, "SecondApproverRequired");
        set_policy(&pool, false, false).await;
    }
    // The snapshot leaves out the policy row, whose flags the test set.
    assert_eq!(snapshot(&pool).await, before);
    assert_eq!(event_count(&pool).await, count);
    no_id_taken(&ids, 42);
    db.drop([pool]).await;
}

/// The same SQL-written entry is still disabled through the writer: a
/// disable checks no destination and passes no gate, also with the gate
/// on; it applies with outcome `success`, and the entry then still cannot
/// be enabled.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_disable_checks_no_destination() {
    let (db, pool) = seeded().await;
    let pathless = "https://k8s-a.example:6443";
    seed_entry(&pool, "egr_bad_on", pathless, Status::Enabled).await;
    set_policy(&pool, true, false).await;
    let ids = SequentialIds::with_seed(43);
    for repeat in [false, true] {
        let done = try_set_entry(&pool, &ids, "egr_bad_on", false)
            .await
            .unwrap_or_else(|err| panic!("repeat {repeat}: {err:?}"));
        assert_eq!(done.row.status, Status::Disabled);
        assert_eq!(done.row.exact_destination, pathless);
        assert_eq!(done.event.outcome, "success");
        assert_eq!(last_event(&pool).await.4, "egr_bad_on");
    }
    set_policy(&pool, false, false).await;
    let before = snapshot(&pool).await;
    refused(
        try_set_entry(&pool, &ids, "egr_bad_on", true).await,
        "InvalidDestination",
    );
    assert_eq!(snapshot(&pool).await, before);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// A generator that gives no ID, for the entry or for the event, leaves
/// nothing behind: the entry written before the event's ID failed is rolled
/// back with the savepoint (the atomicity of the write and its event); the
/// write asks for no ID after the failed one.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_failing_generator_leaves_nothing() {
    let (db, pool) = seeded().await;
    let shared = SequentialIds::with_seed(7);
    for write in WRITES {
        let calls = if write == Write::Create { 2 } else { 1 };
        let before = snapshot(&pool).await;
        for fail_at in 1..=calls {
            for error in [IdError::SourceFailed, IdError::Exhausted] {
                let ids = FailingIds::new(&shared, fail_at, error);
                refused(
                    run(&pool, &ids, write, KEY_SEC).await,
                    &format!("Id({error:?})"),
                );
                assert_eq!(ids.calls(), fail_at, "{write:?}");
                assert_eq!(snapshot(&pool).await, before, "{write:?} at {fail_at}");
            }
        }
        let ids = FailingIds::new(&shared, usize::MAX, IdError::SourceFailed);
        run(&pool, &ids, write, KEY_SEC)
            .await
            .unwrap_or_else(|err| panic!("{write:?}: {err:?}"));
        assert_eq!(ids.calls(), calls, "{write:?}");
    }
    // An exhausted counter of either kind.
    for (write, kind) in [
        (Write::Create, IdKind::EgressEntry),
        (Write::Create, IdKind::AuditEvent),
        (Write::Disable, IdKind::AuditEvent),
    ] {
        let before = snapshot(&pool).await;
        let ids = SequentialIds::with_last_count(kind, u64::MAX);
        let mut tx = pool.begin().await.unwrap();
        let new = created("https://exhausted.example/");
        let request = request(KEY_SEC, &ids);
        let result = match write {
            Write::Create => admin::create_egress_entry(&mut tx, &request, &new, ACK).await,
            _ => admin::disable_egress_entry(&mut tx, &request, "egr_tr", 1).await,
        };
        refused(result, "Id(Exhausted)");
        tx.commit().await.unwrap();
        assert_eq!(snapshot(&pool).await, before, "{write:?} {kind:?}");
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The audit append failing after the entry write (here: the chain head
/// row locked by another transaction past a `lock_timeout`) rolls the entry
/// back with the savepoint, and the caller's transaction stays usable.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_audit_append_rolls_the_write_back() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let sec = request(KEY_SEC, &ids);
    let before = snapshot(&pool).await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM audit_chain_head FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '200ms'")
        .execute(&mut *tx)
        .await
        .unwrap();
    for write in WRITES {
        let result = match write {
            Write::Create => {
                admin::create_egress_entry(&mut tx, &sec, &created(CREATED), ACK).await
            }
            Write::Enable => admin::enable_egress_entry(&mut tx, &sec, "egr_off", 1, ACK).await,
            Write::Disable => admin::disable_egress_entry(&mut tx, &sec, "egr_disc", 1).await,
        };
        let err = result.unwrap_err();
        assert!(
            matches!(err, AdminWriteError::Registry(RegistryError::Other(_))),
            "{write:?}: {err:?}"
        );
        assert!(format!("{err:?}").contains("55P03"), "{write:?}: {err:?}");
        // Nothing of the write is left in the transaction.
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM egress_allowlist_entry \
             WHERE exact_destination = $1 OR revision <> 1",
        )
        .bind(CREATED)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(rows, 0, "{write:?}");
    }
    holder.rollback().await.unwrap();
    // The transaction is usable: the same write now applies.
    let done = admin::disable_egress_entry(&mut tx, &sec, "egr_disc", 1)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(done.row.revision, 2);
    let mut after = snapshot(&pool).await;
    assert_ne!(after, before);
    let keep = |row: &String| !row.starts_with("egress_") && !row.starts_with("audit_");
    after.retain(keep);
    let mut expected = before.clone();
    expected.retain(keep);
    assert_eq!(after, expected);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// An egress write runs only under `READ COMMITTED`.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn egress_writes_run_only_at_read_committed() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let before = snapshot(&pool).await;
    for level in ["REPEATABLE READ", "SERIALIZABLE"] {
        for write in WRITES {
            let expected = match write {
                Write::Create => 0,
                _ => revision(&pool, write.target()).await,
            };
            let mut tx = pool.begin().await.unwrap();
            sqlx::query(AssertSqlSafe(format!(
                "SET TRANSACTION ISOLATION LEVEL {level}"
            )))
            .execute(&mut *tx)
            .await
            .unwrap();
            refused(
                call(&mut tx, &ids, write, KEY_SEC, expected).await,
                "UnsupportedIsolation",
            );
            tx.commit().await.unwrap();
        }
    }
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// The authorization holds until the write's transaction ends: a
/// revocation of the requester's credential waits for it.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn the_authorization_is_locked_until_the_transaction_ends() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    for write in WRITES {
        let expected = match write {
            Write::Create => 0,
            _ => revision(&pool, write.target()).await,
        };
        let mut tx = pool.begin().await.unwrap();
        call(&mut tx, &ids, write, KEY_SEC, expected).await.unwrap();
        let mut other = pool.acquire().await.unwrap();
        let mut revoke = Connection::begin(&mut *other).await.unwrap();
        sqlx::query("SET LOCAL lock_timeout = '200ms'")
            .execute(&mut *revoke)
            .await
            .unwrap();
        let err = registry::revoke_admin_credential(&mut *revoke, "crd_adm_sec", at(9))
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("55P03"), "{write:?}: {err:?}");
        revoke.rollback().await.unwrap();
        tx.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

/// No error's `Display` or `Debug` quotes the destination, a key, an ID or
/// a generated ID.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn errors_omit_the_destination() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(0x5ec7);
    let generated = SequentialIds::with_seed(0x5ec7);
    let marker = "marker-7f3a";
    let sec = request(KEY_SEC, &ids);
    let mut errors = Vec::new();
    let mut tx = pool.begin().await.unwrap();
    for destination in [
        format!("http://{marker}.example/"),
        format!("https://{marker}.example/#{marker}"),
        format!("https://{marker}.example/ {marker}"),
        format!("https://*.{marker}.example/"),
        format!("https://{marker}.example/{}", "a".repeat(2048)),
    ] {
        errors.push(
            admin::create_egress_entry(&mut tx, &sec, &created(&destination), ACK)
                .await
                .unwrap_err(),
        );
    }
    errors.push(
        admin::create_egress_entry(&mut tx, &sec, &created(DISCOVERY), ACK)
            .await
            .unwrap_err(),
    );
    errors.push(
        admin::disable_egress_entry(&mut tx, &sec, "egr_disc", 7)
            .await
            .unwrap_err(),
    );
    errors.push(
        admin::enable_egress_entry(&mut tx, &sec, "egr_missing", 1, ACK)
            .await
            .unwrap_err(),
    );
    let trust = request(KEY_TRUST_A, &ids);
    errors.push(
        admin::create_egress_entry(&mut tx, &trust, &created(CREATED), ACK)
            .await
            .unwrap_err(),
    );
    tx.commit().await.unwrap();
    let markers = [
        marker.to_owned(),
        "issuer.example".into(),
        "egr_disc".into(),
        "egr_missing".into(),
        "created.example".into(),
        KEY_SEC.into(),
        KEY_TRUST_A.into(),
        generated.new_id(IdKind::EgressEntry).unwrap(),
    ];
    let mut seen = Vec::new();
    for err in &errors {
        seen.push(format!("{err:?}"));
        for text in [format!("{err}"), format!("{err:?}")] {
            for marker in &markers {
                assert!(!text.contains(marker.as_str()), "{text:?} holds {marker:?}");
            }
        }
    }
    assert_eq!(
        seen,
        [
            "InvalidDestination",
            "InvalidDestination",
            "InvalidDestination",
            "InvalidDestination",
            "InvalidDestination",
            "Registry(AlreadyExists { constraint: \
             \"egress_allowlist_entry_purpose_exact_destination_key\" })",
            "Registry(StaleRevision)",
            "Registry(NotFound)",
            "Unauthorized",
        ]
    );
    db.drop([pool]).await;
}

// ---------------------------------------------------------------------------
// Trust source writes through an entry the writer disables.

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// An `oidc_discovery` source of `ten_a` with `discovery_url`.
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
        proof_bounds: object(json!({"max_ttl_s": 600})),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    }
}

/// A `kubernetes_token_review` source of `ten_a` with
/// `token_review_endpoint`.
fn k8s(id: &str, endpoint: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::KubernetesTokenReview,
        exact_issuer: "https://kubernetes.default.svc".into(),
        discovery_url: None,
        cluster_id: Some(format!("cluster_{id}")),
        token_review_endpoint: Some(endpoint.into()),
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

/// The mutable columns of `source`, renamed to `name`.
fn renamed(source: &TrustSource, name: &str) -> TrustSourceChanges {
    TrustSourceChanges {
        name: name.into(),
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

type Submitted = Result<Gated<TrustSource>, SourceWriteError>;

/// [`submit_create_source`] of `new` by [`KEY_TRUST_A`] as the operation
/// `op`, in a transaction committed either way.
async fn submit_create(pool: &PgPool, op: &str, new: &NewTrustSource) -> Submitted {
    let event_id = format!("evt_{op}");
    let submission = Submission {
        public_identity: KEY_TRUST_A,
        acknowledge_widening: true,
        operation_id: op,
        event_id: &event_id,
        now: at(10),
    };
    let mut transaction = pool.begin().await.unwrap();
    let result = submit_create_source(&mut transaction, &submission, new).await;
    transaction.commit().await.unwrap();
    result
}

/// [`submit_update_source`] of `source` to `changes`, as [`submit_create`].
async fn submit_update(
    pool: &PgPool,
    op: &str,
    source: &TrustSource,
    changes: &TrustSourceChanges,
) -> Submitted {
    let event_id = format!("evt_{op}");
    let submission = Submission {
        public_identity: KEY_TRUST_A,
        acknowledge_widening: true,
        operation_id: op,
        event_id: &event_id,
        now: at(10),
    };
    let mut transaction = pool.begin().await.unwrap();
    let result = submit_update_source(
        &mut transaction,
        &submission,
        "ten_a",
        &source.id,
        source.revision,
        changes,
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

#[track_caller]
fn applied(result: Submitted) -> TrustSource {
    match result {
        Ok(Gated::Applied(source)) => source,
        other => panic!("not applied: {other:?}"),
    }
}

/// The entry `id` disabled or enabled (acknowledged) through the writer
/// by [`KEY_SEC`], at its current revision, committed.
async fn set_entry(pool: &PgPool, ids: &SequentialIds, id: &str, enabled: bool) {
    try_set_entry(pool, ids, id, enabled).await.unwrap();
}

/// [`set_entry`], returning the writer's result.
async fn try_set_entry(
    pool: &PgPool,
    ids: &SequentialIds,
    id: &str,
    enabled: bool,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    let expected = revision(pool, id).await;
    let sec = request(KEY_SEC, ids);
    committed(pool, async |tx| {
        if enabled {
            admin::enable_egress_entry(tx, &sec, id, expected, ACK).await
        } else {
            admin::disable_egress_entry(tx, &sec, id, expected).await
        }
    })
    .await
}

/// Sets the policy row's flags in SQL, as the tests of the gated trust
/// writes do (`service/tests/source_approval.rs`).
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

/// An entry created through the writer, then disabled through it, refuses
/// every trust source write that sets a destination to it, for both
/// members: the gated create and update (gate off), and the bare registry
/// writer through the `0011` guard. A write that leaves the member
/// unchanged is still accepted (IR-152). Re-enabled through the writer,
/// the entry lets the refused create through.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_source_write_through_a_disabled_entry_is_refused() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(11);
    let sec = request(KEY_SEC, &ids);
    let review = "https://k8s-new.internal.example:6443/";
    let mut entries = Vec::new();
    for (purpose, destination) in [
        (EgressPurpose::OidcDiscovery, CREATED),
        (EgressPurpose::TokenReview, review),
    ] {
        let new = EgressEntryCreate {
            purpose,
            exact_destination: destination.into(),
            status: Status::Enabled,
        };
        let done = committed(&pool, async |tx| {
            admin::create_egress_entry(tx, &sec, &new, ACK).await
        })
        .await
        .unwrap();
        entries.push(done.row.id);
    }
    // Sources written while the entries are enabled; and one of each kind
    // on the seeded entries, to move later.
    let s_disc = applied(submit_create(&pool, "op_1", &oidc("src_disc", CREATED)).await);
    let s_k8s = applied(submit_create(&pool, "op_2", &k8s("src_k8s", review)).await);
    let s_other = applied(submit_create(&pool, "op_3", &oidc("src_other", DISCOVERY)).await);
    let s_other_k8s =
        applied(submit_create(&pool, "op_4", &k8s("src_other_k8s", TOKEN_REVIEW)).await);
    for id in &entries {
        set_entry(&pool, &ids, id, false).await;
    }
    let before = snapshot(&pool).await;
    let cases = [
        (
            "discovery_url",
            oidc("src_new", CREATED),
            &s_other,
            CREATED,
            "trust_source_discovery_url_egress_enabled",
        ),
        (
            "token_review_endpoint",
            k8s("src_new_k8s", review),
            &s_other_k8s,
            review,
            "trust_source_token_review_endpoint_egress_enabled",
        ),
    ];
    for (n, (member, new, other, destination, constraint)) in cases.iter().enumerate() {
        let expected = format!("EgressNotAllowed {{ member: {member:?} }}");
        refused(
            submit_create(&pool, &format!("op_refused_{n}"), new).await,
            &expected,
        );
        let mut moved = renamed(other, &other.name);
        if *member == "discovery_url" {
            moved.discovery_url = Some((*destination).into());
        } else {
            moved.token_review_endpoint = Some((*destination).into());
        }
        refused(
            submit_update(&pool, &format!("op_moved_{n}"), other, &moved).await,
            &expected,
        );
        match registry::test_support::create_trust_source(&pool, new).await {
            Err(RegistryError::Invariant {
                kind: InvariantKind::EgressEntryEnabled,
                constraint: Some(name),
            }) => assert_eq!(name, *constraint),
            other => panic!("{member}: expected the 0011 guard: {other:?}"),
        }
    }
    assert_eq!(snapshot(&pool).await, before);
    // Unchanged members: a rename of each source on a disabled entry is
    // accepted.
    for (n, source) in [&s_disc, &s_k8s].into_iter().enumerate() {
        let name = format!("{}-renamed", source.name);
        let done = applied(
            submit_update(
                &pool,
                &format!("op_rename_{n}"),
                source,
                &renamed(source, &name),
            )
            .await,
        );
        assert_eq!((done.name, done.revision), (name, 2));
    }
    // Re-enabled through the writer, the entries let the creates through.
    for id in &entries {
        set_entry(&pool, &ids, id, true).await;
    }
    for (n, (_, new, ..)) in cases.iter().enumerate() {
        let source = applied(submit_create(&pool, &format!("op_again_{n}"), new).await);
        assert_eq!(source.revision, 1);
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// A clock fixed at `at(20)`.
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        at(20)
    }
}

/// With the gate on, a source create on an enabled entry goes pending; the
/// entry is then disabled through the writer (a disable is never gated),
/// and the approval by a distinct `security_admin` is refused with the
/// source path's `EgressNotAllowed`: no source is written and the operation
/// stays pending. The entry's re-enable is widening, so with the gate on it
/// is refused too, writing nothing; with the gate off for the re-enable and
/// on again, the same approval applies.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn an_approval_after_the_writer_disables_its_entry_is_refused() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(12);
    let sec = request(KEY_SEC, &ids);
    let entry = committed(&pool, async |tx| {
        admin::create_egress_entry(tx, &sec, &created(CREATED), ACK).await
    })
    .await
    .unwrap()
    .row;
    set_policy(&pool, true, false).await;
    let new = oidc("src_pending", CREATED);
    let pending = match submit_create(&pool, "op_pending", &new).await {
        Ok(Gated::Pending(pending)) => pending,
        other => panic!("not pending: {other:?}"),
    };
    set_entry(&pool, &ids, &entry.id, false).await;
    let scope = ApprovalScope::Tenant("ten_a");
    let echo = ApprovalEcho {
        request_digest: pending.request_digest,
        expected_revision: pending.expected_revision,
    };
    let approve = async |tag: &str| {
        let prepared = prepare_approval(
            &pool,
            KEY_SEC2,
            scope,
            "op_pending",
            DEFAULT_ALLOWED_ALGORITHMS,
            at(15),
        )
        .await
        .unwrap();
        let approve_operation_id = format!("appr_{tag}");
        let approve_event_id = format!("evt_appr_{tag}");
        let write_event_id = format!("evt_write_{tag}");
        let mut transaction = pool.begin().await.unwrap();
        let result = approve_operation(
            &mut transaction,
            KEY_SEC2,
            scope,
            &prepared,
            &echo,
            &ApprovalIds {
                approve_operation_id: &approve_operation_id,
                approve_event_id: &approve_event_id,
                write_event_id: &write_event_id,
            },
            &FixedClock,
        )
        .await;
        transaction.commit().await.unwrap();
        result
    };
    let before = snapshot(&pool).await;
    match approve("refused").await {
        Err(ApprovalError::Source(err)) => assert_eq!(
            format!("{err:?}"),
            "EgressNotAllowed { member: \"discovery_url\" }"
        ),
        other => panic!("expected ApprovalError::Source: {other:?}"),
    }
    assert_eq!(snapshot(&pool).await, before);
    refused(
        try_set_entry(&pool, &ids, &entry.id, true).await,
        "SecondApproverRequired",
    );
    assert_eq!(snapshot(&pool).await, before);
    set_policy(&pool, false, false).await;
    set_entry(&pool, &ids, &entry.id, true).await;
    set_policy(&pool, true, false).await;
    approve("applied").await.unwrap();
    let written = registry::get_trust_source(&pool, "ten_a", "src_pending")
        .await
        .unwrap();
    assert_eq!(written.discovery_url.as_deref(), Some(CREATED));
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// The text of the one statement of this test's database that waits for
/// a lock, once there is one.
async fn waiting_statement(pool: &PgPool) -> String {
    for _ in 0..1000 {
        let waiting: Vec<String> = sqlx::query_scalar(
            "SELECT query FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        match waiting.as_slice() {
            [] => tokio::time::sleep(Duration::from_millis(10)).await,
            [one] => return one.clone(),
            many => panic!("more than one statement waits: {many:?}"),
        }
    }
    panic!("no statement waits for a lock");
}

/// A gated source create of `src_held` on [`DISCOVERY`] (`egr_disc`) by
/// [`KEY_TRUST_A`], gate off.
fn held_submission() -> Submission<'static> {
    Submission {
        public_identity: KEY_TRUST_A,
        acknowledge_widening: true,
        operation_id: "op_held",
        event_id: "evt_op_held",
        now: at(10),
    }
}

/// The disable and a source write that checks the entry wait for each
/// other, on the entry row itself:
///
/// 1. a source inserted by the bare registry writer, uncommitted, holds
///    the entry through the `0011` guard's `FOR SHARE` alone (it takes no
///    audit head and no operator row), and the disable times out;
/// 2. a gated source create, uncommitted, holds the entry, and the disable
///    waits on its entry `UPDATE`, not on the audit head the create also
///    holds; once the create rolls back the disable applies;
/// 3. an uncommitted disable holds the entry, and a gated source create
///    waits on the service's entry check (`FOR SHARE`), not on the `0011`
///    guard; once the disable commits, that check refuses it with
///    `EgressNotAllowed`, not the guard's `Invariant`.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_disable_and_a_source_write_wait_for_each_other() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(13);
    let sec = request(KEY_SEC, &ids);
    // 1. The 0011 guard's lock.
    let mut holder = pool.begin().await.unwrap();
    registry::test_support::create_trust_source(&mut *holder, &oidc("src_raw", DISCOVERY))
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '200ms'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let err = admin::disable_egress_entry(&mut tx, &sec, "egr_disc", 1)
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("55P03"), "{err:?}");
    tx.rollback().await.unwrap();
    holder.rollback().await.unwrap();
    // 2. A gated source create holds the entry.
    let mut holder = pool.begin().await.unwrap();
    applied(
        submit_create_source(
            &mut holder,
            &held_submission(),
            &oidc("src_held", DISCOVERY),
        )
        .await,
    );
    let mut tx = pool.begin().await.unwrap();
    let (done, waiting) = tokio::join!(
        admin::disable_egress_entry(&mut tx, &sec, "egr_disc", 1),
        async {
            let waiting = waiting_statement(&pool).await;
            holder.rollback().await.unwrap();
            waiting
        }
    );
    // The compare-and-set's `UPDATE`, in its `WITH`.
    assert!(
        waiting.contains("(UPDATE egress_allowlist_entry SET status = "),
        "{waiting}"
    );
    assert_eq!(done.unwrap().row.status, Status::Disabled);
    tx.rollback().await.unwrap();
    // 3. A disable holds the entry.
    let mut disable_tx = pool.begin().await.unwrap();
    admin::disable_egress_entry(&mut disable_tx, &sec, "egr_disc", 1)
        .await
        .unwrap();
    let mut source_tx = pool.begin().await.unwrap();
    let submission = held_submission();
    let held = oidc("src_held", DISCOVERY);
    let (result, waiting) = tokio::join!(
        submit_create_source(&mut source_tx, &submission, &held),
        async {
            let waiting = waiting_statement(&pool).await;
            disable_tx.commit().await.unwrap();
            waiting
        }
    );
    assert!(
        waiting.starts_with("SELECT id, status FROM egress_allowlist_entry")
            && waiting.ends_with("FOR SHARE"),
        "{waiting}"
    );
    refused(result, "EgressNotAllowed { member: \"discovery_url\" }");
    source_tx.rollback().await.unwrap();
    db.drop([pool]).await;
}
