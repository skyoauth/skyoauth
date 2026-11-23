//! A48: from an empty installation to a working chain through the staged
//! operator tools, with no SQL. Expected: the workload chain in M1a and
//! the human chain in M1b, a portable operator client and local verifier,
//! no SQL or M4 dependency, missing roles deny (tasks §8; T13.3, T13.8,
//! T13.10; identity-registry IR-052 to IR-054; design §7.2; ADR-008 item
//! 12).
//!
//! **A48 partial: the second-approver toggle through the library only; A48
//! M1a stays planned (scope "workload").** These tests are registered on
//! A48's planned M1a stage, so they are no evidence for it: the reporter
//! lists their results as not counted, and they are no claim. They test
//! the `widening_second_approver` toggle legs of A48's row through the
//! public API of `skyoauth_service` against a real PostgreSQL, one fresh
//! database per test: [`submit_widening_toggle`], [`prepare_approval`],
//! [`approve_operation`], [`cancel_operation`] and [`reject_operation`]
//! (`skyoauth_service::operation`, the second-approver flow of
//! `docs/proposals/second-approver-gated-writes.md`, PRs 2 and 3), with
//! [`bootstrap_instance`], the operator writers and
//! [`authorize_operator`]'s inputs, [`get_instance_security_policy`],
//! [`lock_administrative_operation`] (in a transaction rolled back, as a
//! read) and [`verify_audit_chain`] of the registry
//! (`skyoauth_service::persistence::registry`). No endpoint exists: the
//! service routes only `/healthz`, and nothing calls these functions yet.
//!
//! The fixture is local ([`fixture`]): an instance bootstrapped through
//! [`bootstrap_instance`] (its operator `adm_first`, instance
//! `security_admin`, key [`FIRST`]), the tenant `ten_a`, and operators made
//! with the registry's operator writers, each enabled with one credential:
//! the requester `adm_req` (instance `security_admin`; keys [`REQ`] and
//! [`REQ_B`], two credentials of one operator), the approvers `adm_sec`
//! ([`SEC`]) and `adm_sec2` ([`SEC_2`]), both instance `security_admin`,
//! an instance `auditor` `adm_aud` ([`AUDITOR`]) and `adm_trust`
//! ([`TRUST`]), `trust_admin` of `ten_a`. Every time is fixed ([`at`]),
//! the approve's clock included ([`FixedClock`]), so the tests pass
//! whatever the date. Each call runs in a transaction of its own that the
//! helper commits whatever the call returned, so a refusal also shows that
//! the call's savepoint left nothing behind.
//!
//! Two pieces of SQL are their own, both documented where they are:
//! [`seed_policy`], the one write, stands in for the startup mirror of
//! deployment configuration (IR-053), which does not exist; and
//! [`events`] and [`operation_ids`], read-only, since the registry lists
//! neither audit events nor operations.
//!
//! - **Positive, a distinct approver.** With `single_actor_mode` off (as
//!   bootstrap leaves it), a `security_admin`'s request to turn
//!   `widening_second_approver` on is a pending
//!   `instance_security_policy_update` operation and changes nothing; it
//!   takes effect only when another instance `security_admin` prepares
//!   and approves it: the policy row moves to revision 2 with the flag on,
//!   the operation is consumed as `applied`, an `approve` operation by the
//!   approver names it, and the events are the request's
//!   `administrative_operation.create`, the approver's
//!   `administrative_operation.approve` and the requester's
//!   `instance_security_policy.update`, at the approve's one clock sample.
//!   Turning it off is gated the same way, here approved by the
//!   bootstrap's operator. `single_actor_mode` and the audit sink fields
//!   stay as they were (`a48_pos_a_distinct_security_admin_approval_applies_the_toggle`).
//! - **Positive, single actor.** With `single_actor_mode` on in the policy
//!   row before bootstrap ([`seed_policy`]), one `security_admin` turns the
//!   flag on and then off, each applied at once with an
//!   `instance_security_policy.update` event of outcome
//!   `success_single_actor` and no operation; `single_actor_mode` and the
//!   audit sink fields stay as seeded; an operator without instance
//!   `security_admin` is still refused and writes nothing
//!   (`a48_pos_single_actor_mode_lets_one_security_admin_toggle_at_once`).
//! - **Negative, no distinct approver.** A pending toggle that nobody else
//!   approves never applies: the policy row and the operation stay as the
//!   request left them through its 24-hour expiry (`PENDING_OPERATION_TTL`;
//!   Q1, ruled by the user, 2026-11-23), and an approval prepared before
//!   the expiry is `NotApprovable(Expired)` at it and after it, writing
//!   nothing; the operation stays `pending`
//!   (`a48_neg_a_toggle_without_a_distinct_approver_never_applies`).
//! - **Negative, self-approval.** The requester, by the credential it
//!   requested with or by its other one, is `SelfApproval` at the
//!   preparation, at the approval (with another approver's preparation)
//!   and at a reject, and so is the bootstrap's operator for a toggle it
//!   requested; nothing is written, and another `security_admin` then
//!   applies it (`a48_neg_self_approval_of_the_toggle_is_refused`).
//! - **Negative, approver without `security_admin`.** A `trust_admin`, an
//!   instance `auditor`, an unknown key, and `security_admin`s whose
//!   binding was disabled, credential revoked or identity disabled after
//!   their own preparation are `Unauthorized` at the preparation, the
//!   approval and a reject, on the instance path and, for the
//!   `trust_admin`, on its tenant's path; nothing is written, and a
//!   `security_admin` then applies it
//!   (`a48_neg_an_approver_without_security_admin_is_refused`).
//! - **Negative, each step without its role.** The toggle's request by an
//!   operator without instance `security_admin` (a `trust_admin`, an
//!   instance `auditor`, an unknown key) is `Unauthorized` and writes
//!   nothing; a cancel by one of them is `Unauthorized`; and once the
//!   requester has lost its role, its own cancel is `Unauthorized` and an
//!   approval is `RequesterNotAuthorized` (Q5; D21), writing nothing
//!   (`a48_neg_each_step_without_its_role_is_refused`).
//! - **Negative, cancel and reject.** A cancel by another
//!   `security_admin` is `Unauthorized` and a reject by the requester
//!   `SelfApproval`; the requester's cancel (by its other credential) and
//!   another `security_admin`'s reject each revoke their toggle, with an
//!   `administrative_operation.cancel` or `.reject` event by their actor,
//!   and neither toggle then applies: its approval (prepared before the
//!   revocation or after it), a second revocation and the other kind of
//!   revocation are `NotApprovable(Revoked)`; the policy row is unchanged
//!   (`a48_neg_a_cancelled_or_rejected_toggle_never_applies`).
//! - **Negative, the refusal order.** What a caller learns depends on the
//!   order of the checks: the approver's authorization before the
//!   operation is looked up (`Unauthorized`, not `NotFound`, for a missing
//!   operation), the path's scope, self-approval before the operation's
//!   state (`SelfApproval`, not `Consumed` or `Expired`), then consumed or
//!   expired; a reject and a cancel authorize their actor before the
//!   lookup too (`a48_neg_refusals_come_in_the_flows_order`).
//!
//! # Spec and flow picks
//!
//! The spec's rules these tests pin through the library: turning
//! `widening_second_approver` on or off is the one online write to
//! `InstanceSecurityPolicy`, by instance `security_admin`, revision-checked
//! and audited, with a distinct second `security_admin` approver, or one
//! actor when `single_actor_mode` is on (IR-052; ADR-008 item 12); an
//! approval is an `approve` operation by a distinct `security_admin`, no
//! self-approval (IR-054); `single_actor_mode` lets one actor act where a
//! second approver is otherwise required (IR-053). The rest is the flow's,
//! provisional lead picks of the proposal (D1 to D29, 2026-11-23) or
//! inferred there, not the spec's: the operation kind's name and its
//! outcomes (`pending`, `applied`, `cancelled`, `rejected`,
//! `success_single_actor`), the event actions and their actors (the
//! approver on `administrative_operation.approve`, the requester on the
//! policy event), the `approve`, `cancel` and `reject` operations, the
//! 24-hour expiry (D5; Q1 is the user's ruling), that an expired operation
//! stays `pending` (D22), that the requester must still hold its role and
//! credential at the approval (Q5; D21), that cancel is the requester's
//! and reject another `security_admin`'s (section 3), and the refusal
//! order and its error names (D20, section 3; `ApprovalError`).
//!
//! # Not expressible through the library, so not tested
//!
//! - **An online write to `single_actor_mode` or the audit sink fields.**
//!   No public path writes them: there is no endpoint, the registry's one
//!   writer of the policy row (`set_widening_second_approver`) is
//!   crate-private, and the toggle writes only `widening_second_approver`
//!   and the revision. The positives check that the toggle, applied at
//!   once or approved, leaves `single_actor_mode` and the sink fields as
//!   they were; the refusal of an online write to them needs the operator
//!   endpoint and is pending (IR-053; T13.3, T13.8).
//! - **`single_actor_mode` from deployment configuration.** The startup
//!   mirror of IR-053 does not exist (bootstrap inserts the row with both
//!   flags off), so [`seed_policy`] writes the row as that mirror would,
//!   before bootstrap, which adopts it. The configuration, its startup
//!   audit event and a restart are pending.
//!
//! **Missing, so not a claim.** A48 M1a needs its row end to end on the
//! workload chain: the full chain from an empty installation through the
//! operator API with no SQL, the OP harness component
//! (`skyoauth-operator`, T13.10) as the client and the service-local
//! verifier (T13.3), each step of that chain refused without its role
//! (tenants, audiences, sources, grants; T13.2, T13.8), and the toggle
//! through the operator endpoints, with the request layer they need
//! (generated IDs, T10.2; the role of each endpoint; T13.3). None of that
//! is built. The read path of a pending operation (OQ-API-14; Q1 ruled) and
//! the external audit sink to which T13.3 emits admin-operation events
//! (OQ-TM-12) are not tested here either. A48's M1b stage, "human", is not
//! touched.
//!
//! # Overlap
//!
//! The flow's own tests are the service tests of
//! `service/tests/operation_approval.rs` (and, for the gated trust kinds,
//! `keyset_approval.rs` and `source_approval.rs`): the digest and its
//! recomputation, the echo, the clock sample, plan integrity, the policy
//! row's locks and races, and `UnsupportedIsolation`. They claim no
//! scenario and count for nothing (layout §1). This module is the
//! scenario slice of A48's row: observable results only (the policy row,
//! the operation's outcome and the audit events), with the operators and
//! the toggle the row names.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    jwk::DEFAULT_ALLOWED_ALGORITHMS,
    operation::{
        Applied, ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, Gated,
        OperationKind, PendingOperation, PreparedApproval, RevokeIds, Submission,
        approve_operation, cancel_operation, prepare_approval, reject_operation,
        submit_widening_toggle,
    },
    persistence::{
        PgPool,
        registry::{
            self, AdminRole, AdminRoleBindingChanges, AdministrativeOperation, AuditActor,
            BootstrapRequest, ChainVerdict, InstanceSecurityPolicy, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, NewTenant, Status, bootstrap_instance,
            lock_administrative_operation,
        },
    },
};

/// The instance ID of every fixture: a lowercase UUIDv7 (IR-057).
const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";

/// The bootstrap event, which [`events`] leaves out.
const BOOTSTRAP_EVENT: &str = "aud_bootstrap";

/// The keys (`public_identity`) of the fixture's credentials.
const FIRST: &str = "spki-sha256:first";
const REQ: &str = "spki-sha256:req";
const REQ_B: &str = "spki-sha256:req-b";
const SEC: &str = "spki-sha256:sec";
const SEC_2: &str = "spki-sha256:sec-2";
const AUDITOR: &str = "spki-sha256:auditor";
const TRUST: &str = "spki-sha256:trust";
/// Registered for nobody.
const UNKNOWN: &str = "spki-sha256:unknown";

const INSTANCE: ApprovalScope<'static> = ApprovalScope::Instance;

/// The pending operation's lifetime in microseconds (24 hours;
/// `skyoauth_service::operation::PENDING_OPERATION_TTL`).
const DAY: u64 = 86_400_000_000;

/// Microseconds from the epoch of [`at`]`(0)`: a whole microsecond, so
/// every stored time equals the time given.
const T0: u64 = 1_790_000_000_123_456;

fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

/// The approve's clock, set by the test (D28).
struct FixedClock(SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// The policy row the fixture starts from.
#[derive(Clone, Copy)]
enum Policy {
    /// The row bootstrap inserts: both flags off, no audit sink.
    Bootstrapped,
    /// The row [`seed_policy`] writes before bootstrap, which adopts it.
    Seeded { single_actor_mode: bool },
}

/// The policy row as the startup mirror of deployment configuration
/// (IR-053) would write it before bootstrap: `single_actor_mode` as given,
/// a configured and validated audit sink, revision 1. That mirror does not
/// exist and no public API writes the row, so this is the one SQL write of
/// the module; bootstrap then adopts the row unchanged (the lead's ruling
/// of 2026-11-21, `registry::bootstrap`, "Adopting a policy row").
async fn seed_policy(pool: &PgPool, single_actor_mode: bool) {
    sqlx::query(
        "INSERT INTO instance_security_policy \
         (instance_id, single_actor_mode, audit_sink_config_digest, audit_sink_validated_at) \
         VALUES ($1, $2, decode(repeat('5a', 32), 'hex'), \
                 timestamptz '2026-11-01 00:00:00+00')",
    )
    .bind(INSTANCE_ID)
    .bind(single_actor_mode)
    .execute(pool)
    .await
    .expect("the seeded policy row");
}

/// One enabled operator `admin` with the credential `crd_<admin>` (`key`)
/// and the enabled bindings `(id, role, tenant)`.
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

/// A fresh database with the instance bootstrapped from `policy`, the
/// tenant `ten_a` and the operators of the module docs.
async fn fixture(policy: Policy) -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    if let Policy::Seeded { single_actor_mode } = policy {
        seed_policy(&pool, single_actor_mode).await;
    }
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: INSTANCE_ID,
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: FIRST,
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &[0x11; 32],
            audit_event_id: BOOTSTRAP_EVENT,
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    registry::create_tenant(
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
    let sec = AdminRole::SecurityAdmin;
    operator(&pool, "adm_req", REQ, &[("rb_req", sec, None)]).await;
    credential(&pool, "crd_adm_req_b", "adm_req", REQ_B).await;
    operator(&pool, "adm_sec", SEC, &[("rb_sec", sec, None)]).await;
    operator(&pool, "adm_sec2", SEC_2, &[("rb_sec2", sec, None)]).await;
    operator(
        &pool,
        "adm_aud",
        AUDITOR,
        &[("rb_aud", AdminRole::Auditor, None)],
    )
    .await;
    operator(
        &pool,
        "adm_trust",
        TRUST,
        &[("rb_trust", AdminRole::TrustAdmin, Some("ten_a"))],
    )
    .await;
    (db, pool)
}

/// Requests the toggle to `value` at the policy's `revision` with `key`,
/// as the operation `op` recorded by the event `evt_<op>`, at `now`, in a
/// transaction committed either way.
async fn request(
    pool: &PgPool,
    key: &str,
    op: &str,
    revision: i64,
    value: bool,
    now: SystemTime,
) -> Result<Gated<InstanceSecurityPolicy>, ApprovalError> {
    let event_id = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let result = submit_widening_toggle(
        &mut transaction,
        &Submission {
            public_identity: key,
            acknowledge_widening: false,
            operation_id: op,
            event_id: &event_id,
            now,
        },
        revision,
        value,
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

/// [`request`], which must go pending.
async fn pending(
    pool: &PgPool,
    key: &str,
    op: &str,
    revision: i64,
    value: bool,
    now: SystemTime,
) -> PendingOperation {
    match request(pool, key, op, revision, value, now).await {
        Ok(Gated::Pending(pending)) => pending,
        other => panic!("{op}: not pending: {other:?}"),
    }
}

/// [`prepare_approval`] of `op` by `key` on `scope` at `now`.
async fn prepare_on(
    pool: &PgPool,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
    now: SystemTime,
) -> Result<PreparedApproval, ApprovalError> {
    prepare_approval(pool, key, scope, op, DEFAULT_ALLOWED_ALGORITHMS, now).await
}

/// [`prepare_on`] the instance path.
async fn prepare(
    pool: &PgPool,
    key: &str,
    op: &str,
    now: SystemTime,
) -> Result<PreparedApproval, ApprovalError> {
    prepare_on(pool, key, INSTANCE, op, now).await
}

/// Approves `prepared` with `key` on the instance path, echoing `pending`,
/// with the clock at `now`, in a transaction committed either way. The
/// IDs it writes are `appr_<op>`, `evt_appr_<op>` and `evt_write_<op>`.
async fn approve(
    pool: &PgPool,
    key: &str,
    prepared: &PreparedApproval,
    pending: &PendingOperation,
    now: SystemTime,
) -> Result<Applied, ApprovalError> {
    let op = prepared.operation_id();
    let (approve_operation_id, approve_event_id, write_event_id) = (
        format!("appr_{op}"),
        format!("evt_appr_{op}"),
        format!("evt_write_{op}"),
    );
    let mut transaction = pool.begin().await.unwrap();
    let result = approve_operation(
        &mut transaction,
        key,
        INSTANCE,
        prepared,
        &ApprovalEcho {
            request_digest: pending.request_digest,
            expected_revision: pending.expected_revision,
        },
        &ApprovalIds {
            approve_operation_id: &approve_operation_id,
            approve_event_id: &approve_event_id,
            write_event_id: &write_event_id,
        },
        &FixedClock(now),
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

#[derive(Clone, Copy)]
enum Revocation {
    Cancel,
    Reject,
}

/// A cancel or a reject of `op` by `key` on `scope` at `now`, in a
/// transaction committed either way. The IDs it writes are `<kind>_<op>`
/// and `evt_<kind>_<op>`.
async fn revoke(
    pool: &PgPool,
    revocation: Revocation,
    key: &str,
    scope: ApprovalScope<'_>,
    op: &str,
    now: SystemTime,
) -> Result<(), ApprovalError> {
    let name = match revocation {
        Revocation::Cancel => "cancel",
        Revocation::Reject => "reject",
    };
    let (revoking_operation_id, event_id) = (format!("{name}_{op}"), format!("evt_{name}_{op}"));
    let ids = RevokeIds {
        revoking_operation_id: &revoking_operation_id,
        event_id: &event_id,
    };
    let mut transaction = pool.begin().await.unwrap();
    let result = match revocation {
        Revocation::Cancel => cancel_operation(&mut transaction, key, scope, op, &ids, now).await,
        Revocation::Reject => reject_operation(&mut transaction, key, scope, op, &ids, now).await,
    };
    transaction.commit().await.unwrap();
    result
}

async fn cancel(pool: &PgPool, key: &str, op: &str, now: SystemTime) -> Result<(), ApprovalError> {
    revoke(pool, Revocation::Cancel, key, INSTANCE, op, now).await
}

async fn reject(pool: &PgPool, key: &str, op: &str, now: SystemTime) -> Result<(), ApprovalError> {
    revoke(pool, Revocation::Reject, key, INSTANCE, op, now).await
}

/// `result` is the error whose `Debug` is `expected` (fixed text per
/// variant; `ApprovalError` prints no value of the request).
#[track_caller]
fn refused<T: std::fmt::Debug>(result: Result<T, ApprovalError>, expected: &str) {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => assert_eq!(format!("{err:?}"), expected),
    }
}

async fn policy(pool: &PgPool) -> InstanceSecurityPolicy {
    registry::get_instance_security_policy(pool).await.unwrap()
}

/// The operation `id`, read under its lock in a transaction rolled back,
/// or `None`.
async fn find_operation(pool: &PgPool, id: &str) -> Option<AdministrativeOperation> {
    let mut transaction = pool.begin().await.unwrap();
    let row = lock_administrative_operation(&mut transaction, id)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    row
}

async fn operation(pool: &PgPool, id: &str) -> AdministrativeOperation {
    find_operation(pool, id)
        .await
        .unwrap_or_else(|| panic!("no operation {id}"))
}

/// The operation's outcome, consumed and revoked times, and revoking
/// operation.
type State = (
    String,
    Option<SystemTime>,
    Option<SystemTime>,
    Option<String>,
);

async fn state(pool: &PgPool, id: &str) -> State {
    let row = operation(pool, id).await;
    (
        row.outcome,
        row.consumed_at,
        row.revoked_at,
        row.revocation_operation_id,
    )
}

fn open() -> State {
    ("pending".into(), None, None, None)
}

/// An audit event as stored: ID, actor, action, object, revisions,
/// outcome, and its time in microseconds after [`at`]`(0)`.
type Event = (
    String,
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
    micros: u64,
) -> Event {
    (
        id.into(),
        AuditActor::Operator(actor.into()).canonical_json(),
        action.into(),
        object_id.into(),
        previous_revision,
        new_revision,
        outcome.into(),
        i64::try_from(micros).unwrap(),
    )
}

/// The `administrative_operation.create` event of a request at `at(micros)`.
fn created(op: &str, micros: u64) -> Event {
    event(
        &format!("evt_{op}"),
        "adm_req",
        "administrative_operation.create",
        op,
        None,
        Some(1),
        "success",
        micros,
    )
}

/// The events after the bootstrap event, in chain order. Read-only SQL:
/// the registry reads no audit event back.
async fn events(pool: &PgPool) -> Vec<Event> {
    sqlx::query_as(
        "SELECT id, actor, action, object_id, previous_revision, new_revision, outcome, \
         (extract(epoch FROM timestamp) * 1000000)::bigint - $2 \
         FROM audit_event WHERE id <> $1 ORDER BY sequence",
    )
    .bind(BOOTSTRAP_EVENT)
    .bind(i64::try_from(T0).unwrap())
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Every operation ID, byte-wise. Read-only SQL: the registry lists no
/// operations.
async fn operation_ids(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT id FROM administrative_operation ORDER BY id COLLATE \"C\"")
        .fetch_all(pool)
        .await
        .unwrap()
}

/// What a refused call must leave unchanged: the policy row, the
/// operations and the events.
async fn written(pool: &PgPool) -> (InstanceSecurityPolicy, Vec<String>, Vec<Event>) {
    (
        policy(pool).await,
        operation_ids(pool).await,
        events(pool).await,
    )
}

async fn assert_chain_intact(pool: &PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    let verdict = registry::verify_audit_chain(&mut connection).await.unwrap();
    assert!(
        matches!(verdict, ChainVerdict::Intact { .. }),
        "{verdict:?}"
    );
}

/// The policy's flag and revision.
fn flag(policy: &InstanceSecurityPolicy) -> (i64, bool) {
    (policy.revision, policy.widening_second_approver)
}

/// The columns no online write may change (IR-053).
fn deployment(
    policy: &InstanceSecurityPolicy,
) -> (bool, Option<Vec<u8>>, Option<SystemTime>, String) {
    (
        policy.single_actor_mode,
        policy.audit_sink_config_digest.clone(),
        policy.audit_sink_validated_at,
        policy.instance_id.clone(),
    )
}

#[tokio::test]
async fn a48_pos_a_distinct_security_admin_approval_applies_the_toggle() {
    let (db, pool) = fixture(Policy::Bootstrapped).await;
    let before = policy(&pool).await;
    assert_eq!(flag(&before), (1, false));
    assert_eq!(deployment(&before), (false, None, None, INSTANCE_ID.into()));

    // The request is a pending operation and changes nothing.
    let on = pending(&pool, REQ, "op_on", 1, true, at(0)).await;
    assert_eq!(on.id, "op_on");
    assert_eq!(on.kind, OperationKind::InstanceSecurityPolicyUpdate);
    assert_eq!(on.expected_revision, 1);
    assert_eq!(on.expires_at, at(DAY));
    assert_eq!(policy(&pool).await, before);
    assert_eq!(state(&pool, "op_on").await, open());
    let request_row = operation(&pool, "op_on").await;
    assert_eq!(
        (
            request_row.tenant_id.as_deref(),
            request_row.actor_id.as_str(),
            request_row.kind.as_str(),
        ),
        (None, "adm_req", "instance_security_policy_update")
    );
    assert_eq!(events(&pool).await, [created("op_on", 0)]);

    // Another security_admin's approval applies it, at its clock sample.
    let prepared = prepare(&pool, SEC, "op_on", at(1)).await.unwrap();
    assert_eq!(prepared.kind(), OperationKind::InstanceSecurityPolicyUpdate);
    let applied = approve(&pool, SEC, &prepared, &on, at(10)).await.unwrap();
    let after = policy(&pool).await;
    assert_eq!(applied, Applied::InstanceSecurityPolicy(after.clone()));
    assert_eq!(flag(&after), (2, true));
    assert_eq!(deployment(&after), deployment(&before));
    assert_eq!(
        state(&pool, "op_on").await,
        ("applied".into(), Some(at(10)), None, None)
    );
    let approval = operation(&pool, "appr_op_on").await;
    assert_eq!(
        (
            approval.kind.as_str(),
            approval.actor_id.as_str(),
            approval.approves_operation_id.as_deref(),
            approval.outcome.as_str(),
            approval.request_digest.as_slice(),
        ),
        (
            "approve",
            "adm_sec",
            Some("op_on"),
            "success",
            on.request_digest.as_bytes().as_slice(),
        )
    );
    assert_eq!(
        events(&pool).await,
        [
            created("op_on", 0),
            event(
                "evt_appr_op_on",
                "adm_sec",
                "administrative_operation.approve",
                "op_on",
                Some(1),
                Some(2),
                "success",
                10
            ),
            event(
                "evt_write_op_on",
                "adm_req",
                "instance_security_policy.update",
                INSTANCE_ID,
                Some(1),
                Some(2),
                "success",
                10
            ),
        ]
    );

    // Turning it off is gated the same way; the bootstrap's operator, a
    // security_admin too, approves it.
    let off = pending(&pool, REQ_B, "op_off", 2, false, at(20)).await;
    assert_eq!(policy(&pool).await, after);
    assert_eq!(state(&pool, "op_off").await, open());
    let prepared = prepare(&pool, FIRST, "op_off", at(21)).await.unwrap();
    approve(&pool, FIRST, &prepared, &off, at(30))
        .await
        .unwrap();
    let last = policy(&pool).await;
    assert_eq!(flag(&last), (3, false));
    assert_eq!(deployment(&last), deployment(&before));
    assert_eq!(operation(&pool, "appr_op_off").await.actor_id, "adm_first");
    assert_eq!(
        events(&pool).await[3..],
        [
            created("op_off", 20),
            event(
                "evt_appr_op_off",
                "adm_first",
                "administrative_operation.approve",
                "op_off",
                Some(1),
                Some(2),
                "success",
                30
            ),
            event(
                "evt_write_op_off",
                "adm_req",
                "instance_security_policy.update",
                INSTANCE_ID,
                Some(2),
                Some(3),
                "success",
                30
            ),
        ]
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a48_pos_single_actor_mode_lets_one_security_admin_toggle_at_once() {
    let (db, pool) = fixture(Policy::Seeded {
        single_actor_mode: true,
    })
    .await;
    let before = policy(&pool).await;
    assert_eq!(flag(&before), (1, false));
    let (single_actor_mode, digest, validated_at, _) = deployment(&before);
    assert!(single_actor_mode);
    assert!(digest.is_some() && validated_at.is_some());

    for (revision, value) in [(1, true), (2, false)] {
        let op = format!("op_{revision}");
        let micros = u64::try_from(revision).unwrap();
        let Ok(Gated::Applied(row)) = request(&pool, REQ, &op, revision, value, at(micros)).await
        else {
            panic!("{op}: not applied at once");
        };
        assert_eq!(row, policy(&pool).await);
        assert_eq!(flag(&row), (revision + 1, value));
        assert_eq!(deployment(&row), deployment(&before));
        assert_eq!(find_operation(&pool, &op).await, None);
    }
    assert_eq!(
        events(&pool).await,
        [
            event(
                "evt_op_1",
                "adm_req",
                "instance_security_policy.update",
                INSTANCE_ID,
                Some(1),
                Some(2),
                "success_single_actor",
                1
            ),
            event(
                "evt_op_2",
                "adm_req",
                "instance_security_policy.update",
                INSTANCE_ID,
                Some(2),
                Some(3),
                "success_single_actor",
                2
            ),
        ]
    );
    assert_eq!(operation_ids(&pool).await, Vec::<String>::new());

    // The one actor must still be an instance security_admin.
    let unchanged = written(&pool).await;
    for key in [TRUST, AUDITOR, UNKNOWN] {
        refused(
            request(&pool, key, "op_x", 3, true, at(5)).await,
            "Unauthorized",
        );
    }
    assert_eq!(written(&pool).await, unchanged);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a48_neg_a_toggle_without_a_distinct_approver_never_applies() {
    let (db, pool) = fixture(Policy::Bootstrapped).await;
    let before = policy(&pool).await;
    let on = pending(&pool, REQ, "op_on", 1, true, at(0)).await;
    assert_eq!(on.expires_at, at(DAY));
    let unchanged = written(&pool).await;
    assert_eq!(unchanged.0, before);

    // A preparation a microsecond before the expiry still succeeds, and an
    // approval with it is refused from the expiry on.
    let prepared = prepare(&pool, SEC, "op_on", at(DAY - 1)).await.unwrap();
    refused(
        prepare(&pool, SEC, "op_on", at(DAY)).await,
        "NotApprovable(Expired)",
    );
    for now in [at(DAY), at(DAY + 1), at(2 * DAY)] {
        refused(
            approve(&pool, SEC, &prepared, &on, now).await,
            "NotApprovable(Expired)",
        );
    }
    assert_eq!(written(&pool).await, unchanged);
    // Expired, the operation stays pending (D22), and the flag stays off.
    assert_eq!(state(&pool, "op_on").await, open());
    assert_eq!(flag(&policy(&pool).await), (1, false));
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a48_neg_self_approval_of_the_toggle_is_refused() {
    let (db, pool) = fixture(Policy::Bootstrapped).await;
    let on = pending(&pool, REQ, "op_on", 1, true, at(0)).await;
    let prepared = prepare(&pool, SEC, "op_on", at(1)).await.unwrap();
    // The bootstrap's operator requests too.
    let first_on = pending(&pool, FIRST, "op_first", 1, true, at(2)).await;
    let first_prepared = prepare(&pool, SEC, "op_first", at(3)).await.unwrap();
    let unchanged = written(&pool).await;

    for (key, op, prepared, pending) in [
        (REQ, "op_on", &prepared, &on),
        (REQ_B, "op_on", &prepared, &on),
        (FIRST, "op_first", &first_prepared, &first_on),
    ] {
        refused(prepare(&pool, key, op, at(4)).await, "SelfApproval");
        refused(
            approve(&pool, key, prepared, pending, at(5)).await,
            "SelfApproval",
        );
        refused(reject(&pool, key, op, at(6)).await, "SelfApproval");
    }
    assert_eq!(written(&pool).await, unchanged);
    assert_eq!(state(&pool, "op_on").await, open());
    assert_eq!(state(&pool, "op_first").await, open());

    // Another security_admin may.
    approve(&pool, SEC, &prepared, &on, at(10)).await.unwrap();
    assert_eq!(flag(&policy(&pool).await), (2, true));
    assert_eq!(operation(&pool, "appr_op_on").await.actor_id, "adm_sec");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a48_neg_an_approver_without_security_admin_is_refused() {
    let (db, pool) = fixture(Policy::Bootstrapped).await;
    let sec = AdminRole::SecurityAdmin;
    // security_admins who lose their authority after preparing.
    operator(
        &pool,
        "adm_lapsed",
        "spki-sha256:lapsed",
        &[("rb_lapsed", sec, None)],
    )
    .await;
    operator(
        &pool,
        "adm_revoked",
        "spki-sha256:revoked",
        &[("rb_revoked", sec, None)],
    )
    .await;
    operator(
        &pool,
        "adm_off",
        "spki-sha256:off",
        &[("rb_off", sec, None)],
    )
    .await;
    let on = pending(&pool, REQ, "op_on", 1, true, at(0)).await;
    let prepared = prepare(&pool, SEC, "op_on", at(1)).await.unwrap();
    let mut lost = Vec::new();
    for key in [
        "spki-sha256:lapsed",
        "spki-sha256:revoked",
        "spki-sha256:off",
    ] {
        lost.push((key, prepare(&pool, key, "op_on", at(1)).await.unwrap()));
    }
    let binding = registry::get_admin_role_binding(&pool, "rb_lapsed")
        .await
        .unwrap();
    registry::update_admin_role_binding(
        &pool,
        "rb_lapsed",
        binding.revision,
        &AdminRoleBindingChanges {
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_revoked", at(2))
        .await
        .unwrap();
    registry::disable_admin_identity(&pool, "adm_off")
        .await
        .unwrap();
    let unchanged = written(&pool).await;

    for key in [
        TRUST,
        AUDITOR,
        UNKNOWN,
        "spki-sha256:lapsed",
        "spki-sha256:revoked",
        "spki-sha256:off",
    ] {
        refused(prepare(&pool, key, "op_on", at(3)).await, "Unauthorized");
        refused(
            approve(&pool, key, &prepared, &on, at(4)).await,
            "Unauthorized",
        );
        refused(reject(&pool, key, "op_on", at(5)).await, "Unauthorized");
    }
    // With its own preparation, made while it held the role.
    for (key, own) in &lost {
        refused(approve(&pool, key, own, &on, at(6)).await, "Unauthorized");
    }
    // The trust_admin on its own tenant's path: an approver is an instance
    // security_admin on every path.
    let ten_a = ApprovalScope::Tenant("ten_a");
    refused(
        prepare_on(&pool, TRUST, ten_a, "op_on", at(7)).await,
        "Unauthorized",
    );
    refused(
        revoke(&pool, Revocation::Reject, TRUST, ten_a, "op_on", at(7)).await,
        "Unauthorized",
    );
    assert_eq!(written(&pool).await, unchanged);
    assert_eq!(state(&pool, "op_on").await, open());

    approve(&pool, SEC, &prepared, &on, at(10)).await.unwrap();
    assert_eq!(flag(&policy(&pool).await), (2, true));
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a48_neg_each_step_without_its_role_is_refused() {
    let (db, pool) = fixture(Policy::Bootstrapped).await;
    let empty = written(&pool).await;
    // The request.
    for key in [TRUST, AUDITOR, UNKNOWN] {
        refused(
            request(&pool, key, "op_x", 1, true, at(0)).await,
            "Unauthorized",
        );
    }
    assert_eq!(written(&pool).await, empty);
    assert_eq!(find_operation(&pool, "op_x").await, None);

    // The cancel.
    let on = pending(&pool, REQ, "op_on", 1, true, at(1)).await;
    let prepared = prepare(&pool, SEC, "op_on", at(2)).await.unwrap();
    let unchanged = written(&pool).await;
    for key in [TRUST, AUDITOR, UNKNOWN] {
        refused(cancel(&pool, key, "op_on", at(3)).await, "Unauthorized");
    }
    assert_eq!(written(&pool).await, unchanged);

    // The requester without its role: its cancel, and an approval of what
    // it requested (Q5; D21).
    let binding = registry::get_admin_role_binding(&pool, "rb_req")
        .await
        .unwrap();
    registry::update_admin_role_binding(
        &pool,
        "rb_req",
        binding.revision,
        &AdminRoleBindingChanges {
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    let unchanged = written(&pool).await;
    for key in [REQ, REQ_B] {
        refused(cancel(&pool, key, "op_on", at(4)).await, "Unauthorized");
    }
    refused(
        approve(&pool, SEC, &prepared, &on, at(5)).await,
        "RequesterNotAuthorized",
    );
    assert_eq!(written(&pool).await, unchanged);
    assert_eq!(state(&pool, "op_on").await, open());
    assert_eq!(flag(&policy(&pool).await), (1, false));
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a48_neg_a_cancelled_or_rejected_toggle_never_applies() {
    let (db, pool) = fixture(Policy::Bootstrapped).await;
    let before = policy(&pool).await;
    let cancelled = pending(&pool, REQ, "op_c", 1, true, at(0)).await;
    let rejected = pending(&pool, REQ, "op_r", 1, true, at(1)).await;
    let prepared_c = prepare(&pool, SEC, "op_c", at(2)).await.unwrap();
    let prepared_r = prepare(&pool, SEC_2, "op_r", at(2)).await.unwrap();

    // The wrong actors: a cancel is the requester's, a reject another
    // security_admin's.
    let unchanged = written(&pool).await;
    for key in [SEC, SEC_2, FIRST] {
        refused(cancel(&pool, key, "op_c", at(3)).await, "Unauthorized");
    }
    for key in [REQ, REQ_B] {
        refused(reject(&pool, key, "op_r", at(3)).await, "SelfApproval");
    }
    assert_eq!(written(&pool).await, unchanged);

    cancel(&pool, REQ_B, "op_c", at(5)).await.unwrap();
    reject(&pool, SEC, "op_r", at(6)).await.unwrap();
    assert_eq!(
        state(&pool, "op_c").await,
        (
            "cancelled".into(),
            None,
            Some(at(5)),
            Some("cancel_op_c".into())
        )
    );
    assert_eq!(
        state(&pool, "op_r").await,
        (
            "rejected".into(),
            None,
            Some(at(6)),
            Some("reject_op_r".into())
        )
    );
    for (id, actor, kind) in [
        ("cancel_op_c", "adm_req", "cancel"),
        ("reject_op_r", "adm_sec", "reject"),
    ] {
        let row = operation(&pool, id).await;
        assert_eq!(
            (
                row.actor_id.as_str(),
                row.kind.as_str(),
                row.outcome.as_str()
            ),
            (actor, kind, "success")
        );
    }
    assert_eq!(
        events(&pool).await,
        [
            created("op_c", 0),
            created("op_r", 1),
            event(
                "evt_cancel_op_c",
                "adm_req",
                "administrative_operation.cancel",
                "op_c",
                Some(1),
                Some(2),
                "success",
                5
            ),
            event(
                "evt_reject_op_r",
                "adm_sec",
                "administrative_operation.reject",
                "op_r",
                Some(1),
                Some(2),
                "success",
                6
            ),
        ]
    );

    // Neither then applies, nor is revoked again.
    let unchanged = written(&pool).await;
    for (op, key, prepared, pending) in [
        ("op_c", SEC, &prepared_c, &cancelled),
        ("op_r", SEC_2, &prepared_r, &rejected),
    ] {
        refused(
            prepare(&pool, key, op, at(7)).await,
            "NotApprovable(Revoked)",
        );
        refused(
            approve(&pool, key, prepared, pending, at(8)).await,
            "NotApprovable(Revoked)",
        );
        refused(
            cancel(&pool, REQ, op, at(9)).await,
            "NotApprovable(Revoked)",
        );
        refused(
            reject(&pool, SEC_2, op, at(9)).await,
            "NotApprovable(Revoked)",
        );
    }
    assert_eq!(written(&pool).await, unchanged);
    assert_eq!(policy(&pool).await, before);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a48_neg_refusals_come_in_the_flows_order() {
    let (db, pool) = fixture(Policy::Bootstrapped).await;
    // op_done: applied. op_late: pending, prepared after its expiry.
    let done = pending(&pool, REQ, "op_done", 1, true, at(0)).await;
    let prepared = prepare(&pool, SEC, "op_done", at(1)).await.unwrap();
    approve(&pool, SEC, &prepared, &done, at(2)).await.unwrap();
    pending(&pool, REQ, "op_late", 2, false, at(3)).await;
    let late = at(3 + DAY);
    let unchanged = written(&pool).await;

    let ten_a = ApprovalScope::Tenant("ten_a");
    for (key, scope, op, now, expected) in [
        // The approver before the operation is looked up.
        (UNKNOWN, INSTANCE, "op_none", at(4), "Unauthorized"),
        (TRUST, INSTANCE, "op_none", at(4), "Unauthorized"),
        (TRUST, INSTANCE, "op_done", at(4), "Unauthorized"),
        (SEC, INSTANCE, "op_none", at(4), "NotFound"),
        // The path's scope before the requester and the state.
        (SEC, ten_a, "op_done", at(4), "NotFound"),
        (REQ, ten_a, "op_done", at(4), "NotFound"),
        // Self-approval before the state.
        (REQ, INSTANCE, "op_done", at(4), "SelfApproval"),
        (REQ, INSTANCE, "op_late", late, "SelfApproval"),
        // Then the state.
        (SEC, INSTANCE, "op_done", at(4), "NotApprovable(Consumed)"),
        (SEC, INSTANCE, "op_late", late, "NotApprovable(Expired)"),
    ] {
        refused(prepare_on(&pool, key, scope, op, now).await, expected);
    }
    // A reject and a cancel authorize their actor before the lookup.
    for (revocation, key, op, expected) in [
        (Revocation::Reject, UNKNOWN, "op_none", "Unauthorized"),
        (Revocation::Reject, TRUST, "op_none", "Unauthorized"),
        (Revocation::Reject, SEC, "op_none", "NotFound"),
        (Revocation::Reject, REQ, "op_done", "SelfApproval"),
        (
            Revocation::Reject,
            SEC_2,
            "op_done",
            "NotApprovable(Consumed)",
        ),
        (Revocation::Cancel, TRUST, "op_none", "Unauthorized"),
        (Revocation::Cancel, REQ, "op_none", "NotFound"),
        (
            Revocation::Cancel,
            REQ,
            "op_done",
            "NotApprovable(Consumed)",
        ),
    ] {
        refused(
            revoke(&pool, revocation, key, INSTANCE, op, at(5)).await,
            expected,
        );
    }
    assert_eq!(written(&pool).await, unchanged);
    assert_eq!(state(&pool, "op_late").await, open());
    assert_eq!(flag(&policy(&pool).await), (2, true));
    db.drop([pool]).await;
}
