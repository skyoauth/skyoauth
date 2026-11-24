//! Break-glass operator restoration (`persistence::registry::recovery`;
//! design section 7.2; ADR-013 item 8; identity-registry section 5.2;
//! lifetimes LT-107; T13.5; `docs/proposals/recovery-verified-response.md`):
//! the issued challenge, its computed digest and hash, the `M` it returns
//! and its audit event, the TTL bounds and the closed plan, the key checks
//! at the issue, single use (in the statement and in the database guards),
//! every refusal of a restore with its reason, the signature over `M` with
//! the current recovery key (bad, wrong-key, wrong-message, malleable and
//! weak-key signatures), the preview, two concurrent restores of one
//! challenge, the full restoration (enroll, revoke every credential, rotate
//! the key, two audit events last), that nothing else changes, that a
//! failed restore rolls the consume back, that a restore runs only at
//! `READ COMMITTED`, that a restore and an issue wait for each other
//! without deadlock, that an operator write that adds access serializes
//! with a restore (a colliding create waiting before its insert), and that
//! the one remaining deadlock fails closed.
//!
//! The tests sign with fixed test keys ([`SEED`], [`NEW_SEED`],
//! [`THIRD_SEED`]); they rebuild `M` from the stored row with the public
//! [`DigestEnvelope`] and the prefix, as the workstation does, so the
//! encoding is checked independently of the library's own.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! creates and drops its own database. They are registry tests, not
//! conformance scenarios (A48 and A64 belong to the test session in
//! `tests/security`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    collections::BTreeMap,
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use skyoauth_service::{
    operation::{DIGEST_PREFIX, DigestEnvelope},
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AdminRoleBindingChanges, AuditActor, AuthorizedOperator,
            BootstrapRequest, ChainVerdict, ChallengeError, DEFAULT_CHALLENGE_TTL, InvariantKind,
            IssueChallenge, JsonObject, MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, NewAuditEvent, NewPrincipal, NewTenant,
            NotRestorableReason, OPERATOR_RESTORATION, OperatorRequest, OperatorScope,
            PrincipalKind, RecoveryChallenge, RecoveryPreview, RecoveryState, RegistryError,
            RestoreError, RestoreRequest, Restored, SignedRecoveryResponse, Status,
            bootstrap_instance, get_recovery_state, issue_recovery_challenge,
            preview_recovery_response, restore_operator, verify_audit_chain,
        },
    },
};
use sqlx::{AssertSqlSafe, Connection, PgConnection, Postgres, Transaction};

const INSTANCE: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const OTHER_INSTANCE: &str = "019a9f3c-5b2e-7c41-ad8e-ba9876543210";
/// The seed of the bootstrap recovery key, a test key.
const SEED: [u8; 32] = [0x51; 32];
/// The seed of the key a restore rotates to.
const NEW_SEED: [u8; 32] = [0x52; 32];
/// The seed of a third key.
const THIRD_SEED: [u8; 32] = [0x53; 32];
/// The public key of [`SEED`] (computed independently; checked against
/// the crate in `the_test_keys_are_their_seeds_keys`).
const KEY: [u8; 32] = [
    0xc0, 0x50, 0xc5, 0x63, 0x7a, 0x44, 0xfa, 0x86, 0x29, 0xff, 0xf3, 0xcc, 0xcc, 0xe2, 0x30, 0x0c,
    0xb3, 0x62, 0xa6, 0x3d, 0x99, 0xd9, 0x5f, 0xc5, 0x41, 0x45, 0x26, 0x6f, 0x43, 0x32, 0x44, 0x5a,
];
/// The public key of [`NEW_SEED`].
const NEW_KEY: [u8; 32] = [
    0x20, 0x12, 0xcb, 0x90, 0xca, 0x60, 0xe8, 0xe5, 0xd8, 0xda, 0xf6, 0x6e, 0x22, 0x72, 0xd2, 0x23,
    0x3e, 0x04, 0x86, 0xd5, 0x57, 0xe8, 0xc6, 0x61, 0x41, 0xed, 0x89, 0x20, 0x17, 0x7d, 0x7e, 0xb7,
];
/// The public key of [`THIRD_SEED`].
const THIRD_KEY: [u8; 32] = [
    0xf8, 0x0c, 0xcc, 0xdc, 0xe4, 0xae, 0x1c, 0x07, 0xae, 0x20, 0x8a, 0x2a, 0xdf, 0x99, 0xa3, 0x10,
    0xae, 0x42, 0x07, 0xe0, 0x30, 0x6f, 0xa0, 0x23, 0x61, 0x10, 0xb0, 0x68, 0x27, 0xbb, 0xb8, 0xd0,
];
/// The prefix of `M` (the recovery module, "What is signed").
const CHALLENGE_PREFIX: &[u8] = b"skyoauth.recovery_challenge.v1\n";
/// The identity point, of small order, canonically encoded.
const IDENTITY: [u8; 32] = {
    let mut key = [0; 32];
    key[0] = 1;
    key
};
/// The identity point as `y = p + 1`: non-canonical and of small order.
const IDENTITY_P_PLUS_1: [u8; 32] = {
    let mut key = [0xff; 32];
    key[0] = 0xee;
    key[31] = 0x7f;
    key
};
/// A point of large order as `y = p + 3`: non-canonical only.
const LARGE_P_PLUS_3: [u8; 32] = {
    let mut key = IDENTITY_P_PLUS_1;
    key[0] = 0xf0;
    key
};
/// 32 bytes that decode to no point.
const UNDECODABLE: [u8; 32] = [7; 32];
/// The signature that verifies over any message under a plain
/// verification for the identity key: `R` the identity, `S` zero.
const FIXED_SIGNATURE: [u8; 64] = {
    let mut signature = [0; 64];
    signature[0] = 1;
    signature
};
/// A signature by [`SEED`] over `M` of `op_1` of [`issued`] (the prefix
/// and [`op_1_canonical`]) with a small-order `R`, the identity, and
/// `S = k * a mod L`, for the secret scalar `a` of [`SEED`] and
/// `k = SHA-512(R || A || M)`, computed independently of this code: the
/// plain equation `[S]B = R + [k]A` holds, so a plain verification accepts
/// it; `verify_strict` refuses a small-order `R`.
const SMALL_ORDER_R_SIGNATURE: [u8; 64] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe7, 0xea, 0x26, 0xa7, 0x8c, 0x0d, 0x7b, 0xe3, 0xe9, 0x39, 0x24, 0x14, 0xcf, 0xc5, 0xa2, 0x0a,
    0x89, 0x0e, 0xa1, 0x8a, 0xdd, 0x8d, 0xaa, 0x3f, 0x8f, 0x74, 0xcc, 0x2b, 0x3e, 0x1c, 0xbe, 0x02,
];
const T0: u64 = 1_790_000_000_123_456;

/// `micros` after `T0`.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

/// The issue time: sub-microsecond digits, so a write truncates it.
fn issue_time() -> SystemTime {
    at(1_000_000) + Duration::from_nanos(789)
}

/// The default expiry as stored: the issue time plus five minutes,
/// truncated.
fn expires() -> SystemTime {
    at(301_000_000)
}

/// The consume and restore time.
fn now() -> SystemTime {
    at(2_000_000)
}

fn micros(time: SystemTime) -> i64 {
    i64::try_from(time.duration_since(UNIX_EPOCH).unwrap().as_micros()).unwrap()
}

/// `bytes` in lowercase hexadecimal, as the plan carries a key.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// The Ed25519 signature of `message` by the key of `seed`.
fn sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    SigningKey::from_bytes(seed)
        .sign(message)
        .to_bytes()
        .to_vec()
}

/// The replacement a plan names.
#[derive(Debug, Clone, Copy)]
struct Replacement<'a> {
    admin_id: &'a str,
    credential_id: &'a str,
    binding_id: &'a str,
    public_identity: &'a str,
    trust_anchor_ref: &'a str,
    key: &'a [u8],
}

/// The replacement of [`good_plan`]: `adm_new`, `crd_new`, `rb_new`,
/// `spki-sha256:new`, and [`NEW_KEY`].
const NEW: Replacement<'static> = Replacement {
    admin_id: "adm_new",
    credential_id: "crd_new",
    binding_id: "rb_new",
    public_identity: "spki-sha256:new",
    trust_anchor_ref: "deployment/operator-ca",
    key: &NEW_KEY,
};

/// Another replacement (`*_other`) with `key`.
fn other(key: &[u8]) -> Replacement<'_> {
    Replacement {
        admin_id: "adm_other",
        credential_id: "crd_other",
        binding_id: "rb_other",
        public_identity: "spki-sha256:other",
        key,
        ..NEW
    }
}

/// The closed plan of a challenge for `instance` and `epoch` that names
/// `replacement`.
fn plan_for(instance: &str, epoch: Value, replacement: &Replacement<'_>) -> JsonObject {
    object(json!({
        "instance_id": instance,
        "recovery_key_epoch": epoch,
        "admin_id": replacement.admin_id,
        "credential_id": replacement.credential_id,
        "binding_id": replacement.binding_id,
        "public_identity": replacement.public_identity,
        "trust_anchor_ref": replacement.trust_anchor_ref,
        "new_recovery_public_key": hex(replacement.key),
    }))
}

/// The plan for `instance` and `epoch` that names [`NEW`].
fn plan(instance: &str, epoch: Value) -> JsonObject {
    plan_for(instance, epoch, &NEW)
}

fn good_plan() -> JsonObject {
    plan(INSTANCE, json!(1))
}

fn issue_request<'a>(id: &'a str, audit: &'a str, plan: &'a JsonObject) -> IssueChallenge<'a> {
    IssueChallenge {
        operation_id: id,
        kind: OPERATOR_RESTORATION,
        immutable_plan: plan,
        ttl: DEFAULT_CHALLENGE_TTL,
        now: issue_time(),
        audit_event_id: audit,
    }
}

/// The event IDs and `now()` of a restore.
fn restore_request() -> RestoreRequest<'static> {
    RestoreRequest {
        audit_event_id: "aud_restore",
        rotation_audit_event_id: "aud_rotate",
        now: now(),
    }
}

/// The response for the operation `id` with `signature`.
fn response<'a>(id: &'a str, signature: &'a [u8]) -> SignedRecoveryResponse<'a> {
    SignedRecoveryResponse {
        operation_id: id,
        signature,
    }
}

/// `C` and `M` as the workstation rebuilds them from the stored row: the
/// row's ID, expected revision, expiry and plan, the fixed actor, kind and
/// tenant. `None` without a row or for a plan with no canonical form.
fn encode(
    id: &str,
    revision: i64,
    expires_us: i64,
    plan: &JsonObject,
) -> Option<(String, Vec<u8>)> {
    let canonical = DigestEnvelope {
        id,
        tenant_id: None,
        actor_id: "deployment_operator",
        kind: OPERATOR_RESTORATION,
        expected_revision: revision,
        expires_at_us: expires_us,
        plan,
    }
    .canonical_json()
    .ok()?;
    let challenge = [CHALLENGE_PREFIX, canonical.as_bytes()].concat();
    Some((canonical, challenge))
}

/// The request digest and the challenge hash of the challenge `id` at
/// `revision` expiring at `expires()` with `plan`, computed here:
/// SHA-256 of the digest prefix and `C`, and of `M`.
fn library(id: &str, revision: i64, plan: &JsonObject) -> Option<(Vec<u8>, Vec<u8>)> {
    let (canonical, challenge) = encode(id, revision, micros(expires()), plan)?;
    Some((
        Sha256::digest([DIGEST_PREFIX, canonical.as_bytes()].concat()).to_vec(),
        Sha256::digest(&challenge).to_vec(),
    ))
}

/// `M` of the stored row `id`, rebuilt (see [`encode`]).
async fn stored_challenge(connection: &mut PgConnection, id: &str) -> Option<Vec<u8>> {
    let row: Option<(String, i64, Option<i64>, Value)> = sqlx::query_as(
        "SELECT id, expected_revision, \
         (extract(epoch FROM expires_at) * 1000000)::bigint, immutable_plan \
         FROM administrative_operation WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(connection)
    .await
    .unwrap();
    let (id, revision, expires_us, plan) = row?;
    let expires_us = expires_us?;
    let Value::Object(plan) = plan else {
        return None;
    };
    encode(&id, revision, expires_us, &plan).map(|(_, challenge)| challenge)
}

/// The signature by `seed` over the stored `M` of `id`, or over other
/// bytes when there is none.
async fn signature_by(connection: &mut PgConnection, id: &str, seed: &[u8; 32]) -> Vec<u8> {
    match stored_challenge(connection, id).await {
        Some(challenge) => sign(seed, &challenge),
        None => sign(seed, b"no challenge"),
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// A migrated database after bootstrap: `adm_first` with `crd_first`
/// (`spki-sha256:first`) and `rb_first`, the recovery key `KEY` at epoch 1,
/// and the bootstrap event `aud_bootstrap` (sequence 1).
async fn bootstrapped() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: INSTANCE,
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: "spki-sha256:first",
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &KEY,
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    (db, pool)
}

/// [`bootstrapped`] with the challenge `op_1` (event `aud_issue_1`) issued
/// and committed.
async fn issued() -> (TestDb, PgPool) {
    let (db, pool) = bootstrapped().await;
    issue(&pool, "op_1", "aud_issue_1").await;
    (db, pool)
}

async fn issue_on(
    pool: &PgPool,
    request: &IssueChallenge<'_>,
) -> Result<RecoveryChallenge, ChallengeError> {
    let mut transaction = pool.begin().await.unwrap();
    let issued = issue_recovery_challenge(&mut transaction, request).await;
    if issued.is_ok() {
        transaction.commit().await.unwrap();
    } else {
        transaction.rollback().await.unwrap();
    }
    issued
}

async fn issue(pool: &PgPool, id: &str, audit: &str) -> RecoveryChallenge {
    let plan = good_plan();
    issue_on(pool, &issue_request(id, audit, &plan))
        .await
        .unwrap()
}

/// Restores `id` with `signature` in a transaction of its own; commits on
/// `Ok`.
async fn restore_with(
    pool: &PgPool,
    id: &str,
    signature: &[u8],
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError> {
    let mut transaction = pool.begin().await.unwrap();
    let restored = restore_operator(&mut transaction, &response(id, signature), request).await;
    if restored.is_ok() {
        transaction.commit().await.unwrap();
    } else {
        transaction.rollback().await.unwrap();
    }
    restored
}

/// Restores `id` signed by `seed` over its stored `M`.
async fn restore_by(
    pool: &PgPool,
    id: &str,
    seed: &[u8; 32],
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError> {
    let signature = signature_by(&mut pool.acquire().await.unwrap(), id, seed).await;
    restore_with(pool, id, &signature, request).await
}

/// Restores `id` signed by the bootstrap key, [`SEED`].
async fn restore_on(
    pool: &PgPool,
    id: &str,
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError> {
    restore_by(pool, id, &SEED, request).await
}

/// Restores `id`, signed by [`SEED`], with [`restore_request`] in
/// `transaction`.
async fn consume_and_restore(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<Restored, RestoreError> {
    restore_in(transaction, id, &restore_request()).await
}

/// Restores `id`, signed by [`SEED`], with `request` in `transaction`.
async fn restore_in(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
    request: &RestoreRequest<'_>,
) -> Result<Restored, RestoreError> {
    let signature = signature_by(&mut *transaction, id, &SEED).await;
    restore_operator(transaction, &response(id, &signature), request).await
}

/// The whole operation row.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
struct Operation {
    id: String,
    tenant_id: Option<String>,
    actor_id: String,
    kind: String,
    request_digest: Vec<u8>,
    expected_revision: i64,
    immutable_plan: Value,
    challenge_hash: Option<Vec<u8>>,
    expires_us: Option<i64>,
    consumed_us: Option<i64>,
    revoked_us: Option<i64>,
    revocation_operation_id: Option<String>,
    approves_operation_id: Option<String>,
    revision: i64,
    outcome: String,
    audit_id: String,
}

async fn operation(connection: &mut PgConnection, id: &str) -> Operation {
    sqlx::query_as(
        "SELECT id, tenant_id, actor_id, kind, request_digest, expected_revision, \
         immutable_plan, challenge_hash, \
         (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_us, \
         (extract(epoch FROM consumed_at) * 1000000)::bigint AS consumed_us, \
         (extract(epoch FROM revoked_at) * 1000000)::bigint AS revoked_us, \
         revocation_operation_id, approves_operation_id, revision, outcome, audit_id \
         FROM administrative_operation WHERE id = $1",
    )
    .bind(id)
    .fetch_one(connection)
    .await
    .unwrap()
}

async fn pool_operation(pool: &PgPool, id: &str) -> Operation {
    operation(&mut pool.acquire().await.unwrap(), id).await
}

/// Every row of every table of the schema, as text, by table.
async fn snapshot(connection: &mut PgConnection) -> BTreeMap<String, Vec<String>> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = current_schema() \
         AND tablename NOT LIKE '\\_sqlx%' ORDER BY 1",
    )
    .fetch_all(&mut *connection)
    .await
    .unwrap();
    assert!(tables.len() > 20, "{tables:?}");
    let mut snapshot = BTreeMap::new();
    for table in tables {
        // The names come from the catalog.
        let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT t::text FROM \"{table}\" t ORDER BY t::text COLLATE \"C\""
        )))
        .fetch_all(&mut *connection)
        .await
        .unwrap();
        snapshot.insert(table, rows);
    }
    snapshot
}

async fn pool_snapshot(pool: &PgPool) -> BTreeMap<String, Vec<String>> {
    snapshot(&mut pool.acquire().await.unwrap()).await
}

async fn verify(pool: &PgPool) -> ChainVerdict {
    verify_audit_chain(&mut pool.acquire().await.unwrap())
        .await
        .unwrap()
}

fn security_admin(key: &str) -> OperatorRequest<'_> {
    OperatorRequest {
        public_identity: key,
        scope: OperatorScope::Instance,
        role: AdminRole::SecurityAdmin,
    }
}

async fn authorize_security_admin(pool: &PgPool, key: &str) -> Option<AuthorizedOperator> {
    registry::authorize_operator(pool, &security_admin(key))
        .await
        .unwrap()
}

/// What a row written by other means stores as its request digest and
/// challenge hash.
#[derive(Debug, Clone)]
enum Stored {
    /// The library's encoding of the row (see [`encode`]); a fixed value
    /// when the plan has no canonical form.
    Library,
    /// These bytes, digest then hash (`None`: no hash).
    Bytes(Vec<u8>, Option<Vec<u8>>),
}

/// Inserts an operation row by other means: `kind`, `plan`, the digest
/// and hash of `stored`, at `expected_revision`, expiring at `expires()`,
/// recorded by `aud_issue_1`, by `deployment_operator`.
async fn insert_raw(
    pool: &PgPool,
    id: &str,
    kind: &str,
    plan: Value,
    stored: Stored,
    expected_revision: i64,
) {
    insert_raw_by(
        pool,
        id,
        "deployment_operator",
        kind,
        plan,
        stored,
        expected_revision,
    )
    .await;
}

/// [`insert_raw`] with the actor `actor`.
async fn insert_raw_by(
    pool: &PgPool,
    id: &str,
    actor: &str,
    kind: &str,
    plan: Value,
    stored: Stored,
    expected_revision: i64,
) {
    let (digest, hash) = match stored {
        Stored::Library => match &plan {
            Value::Object(members) => library(id, expected_revision, members)
                .map_or((vec![0xd1; 32], Some(vec![0xc7; 32])), |(digest, hash)| {
                    (digest, Some(hash))
                }),
            _ => (vec![0xd1; 32], Some(vec![0xc7; 32])),
        },
        Stored::Bytes(digest, hash) => (digest, hash),
    };
    sqlx::query(
        "INSERT INTO administrative_operation (id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, challenge_hash, expires_at, outcome, audit_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, \
         timestamptz 'epoch' + $8 * interval '1 microsecond', 'issued', 'aud_issue_1')",
    )
    .bind(id)
    .bind(actor)
    .bind(kind)
    .bind(digest)
    .bind(expected_revision)
    .bind(plan)
    .bind(hash)
    .bind(micros(expires()))
    .execute(pool)
    .await
    .unwrap();
}

/// Sets `consumed_at` to `$2` microseconds after the epoch by other means.
const RAW_CONSUME: &str = "UPDATE administrative_operation \
     SET consumed_at = timestamptz 'epoch' + $2 * interval '1 microsecond', \
     revision = revision + 1 WHERE id = $1";

/// Revokes the operation `id` by other means, naming `by`.
async fn raw_revoke(connection: &mut PgConnection, id: &str, by: &str) {
    sqlx::query(
        "UPDATE administrative_operation SET revoked_at = timestamptz 'epoch' + $3 * interval \
         '1 microsecond', revocation_operation_id = $2, revision = revision + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(by)
    .bind(micros(at(1_500_000)))
    .execute(connection)
    .await
    .unwrap();
}

/// The fixed `Display` of each reason, as the redaction tests pin it.
fn reason_text(reason: NotRestorableReason) -> &'static str {
    match reason {
        NotRestorableReason::NoRecoveryState => "there is no closed recovery state",
        NotRestorableReason::NotFound => "no such recovery challenge",
        NotRestorableReason::Consumed => "the recovery challenge was already used",
        NotRestorableReason::Revoked => "the recovery challenge was revoked",
        NotRestorableReason::Expired => "the recovery challenge has expired",
        NotRestorableReason::WrongKind => {
            "the operation is not an issued operator restoration challenge"
        }
        NotRestorableReason::NotBound => {
            "the recovery challenge is not bound to the current recovery state"
        }
        NotRestorableReason::NotLibraryEncoding => {
            "the recovery challenge's stored digest or hash is not its encoding"
        }
        NotRestorableReason::WeakKey => "the current recovery public key is not usable",
        NotRestorableReason::BadSignature => {
            "the signature does not verify with the current recovery key"
        }
    }
}

#[track_caller]
fn assert_not_issuable<T: Debug>(result: Result<T, ChallengeError>) {
    match result {
        Err(err @ ChallengeError::NotIssuable) => {
            assert_eq!(format!("{err:?}"), "NotIssuable");
        }
        other => panic!("expected NotIssuable: {other:?}"),
    }
}

/// Asserts `NotRestorable` with `reason`, its `Debug` naming the variant
/// and the reason only and its `Display` the reason's fixed text.
#[track_caller]
fn assert_not_restorable<T: Debug>(
    result: Result<T, RestoreError>,
    reason: NotRestorableReason,
) -> RestoreError {
    match result {
        Err(err @ RestoreError::NotRestorable(got)) if got == reason => {
            assert_eq!(format!("{err:?}"), format!("NotRestorable({reason:?})"));
            assert_eq!(err.to_string(), reason_text(reason));
            err
        }
        other => panic!("expected NotRestorable({reason:?}): {other:?}"),
    }
}

#[track_caller]
fn assert_issue_encode<T: Debug>(result: Result<T, ChallengeError>, message: &str) {
    match result {
        Err(ChallengeError::Store(RegistryError::Other(sqlx::Error::Encode(err)))) => {
            assert_eq!(err.to_string(), message)
        }
        other => panic!("expected an encode error {message:?}: {other:?}"),
    }
}

#[track_caller]
fn assert_restore_encode<T: Debug>(result: Result<T, RestoreError>, message: &str) {
    match result {
        Err(RestoreError::Store(RegistryError::Other(sqlx::Error::Encode(err)))) => {
            assert_eq!(err.to_string(), message)
        }
        other => panic!("expected an encode error {message:?}: {other:?}"),
    }
}

#[track_caller]
fn assert_restore_exists<T: Debug>(result: Result<T, RestoreError>, name: &str) {
    match result {
        Err(RestoreError::Store(RegistryError::AlreadyExists { constraint })) => {
            assert_eq!(constraint, name)
        }
        other => panic!("expected AlreadyExists {name}: {other:?}"),
    }
}

/// The counts of operations and audit events, and the unrevoked
/// credentials, as `connection` sees them.
async fn counts(connection: &mut PgConnection) -> [i64; 3] {
    let row: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM administrative_operation), \
                (SELECT count(*) FROM audit_event), \
                (SELECT count(*) FROM admin_credential WHERE revoked_at IS NULL)",
    )
    .fetch_one(connection)
    .await
    .unwrap();
    [row.0, row.1, row.2]
}

/// The test keys are the public keys of their seeds, canonical points of
/// large order; the bootstrap key is the one bootstrap stored.
#[test]
fn the_test_keys_are_their_seeds_keys() {
    for (seed, key) in [(SEED, KEY), (NEW_SEED, NEW_KEY), (THIRD_SEED, THIRD_KEY)] {
        let signing = SigningKey::from_bytes(&seed);
        assert_eq!(signing.verifying_key().to_bytes(), key);
        assert!(!signing.verifying_key().is_weak());
    }
}

/// Previews `id` with `signature` at `now` in a transaction of its own,
/// rolled back.
async fn preview_with(
    pool: &PgPool,
    id: &str,
    signature: &[u8],
    now: SystemTime,
) -> Result<RecoveryPreview, RestoreError> {
    let mut transaction = pool.begin().await.unwrap();
    let preview = preview_recovery_response(&mut transaction, &response(id, signature), now).await;
    transaction.rollback().await.unwrap();
    preview
}

/// A preview and then a restore of `id` with `signature` at `at` are both
/// `NotRestorable` with `reason`, and neither writes anything.
async fn assert_refused(
    pool: &PgPool,
    id: &str,
    signature: &[u8],
    at: SystemTime,
    reason: NotRestorableReason,
) {
    let before = pool_snapshot(pool).await;
    let mut request = restore_request();
    request.now = at;
    assert_not_restorable(preview_with(pool, id, signature, at).await, reason);
    assert_not_restorable(restore_with(pool, id, signature, &request).await, reason);
    assert_eq!(pool_snapshot(pool).await, before, "{id}: {reason:?}");
}

/// [`assert_refused`] with the signature by [`SEED`] over the stored `M`
/// of `id`.
async fn assert_refused_signed(
    pool: &PgPool,
    id: &str,
    at: SystemTime,
    reason: NotRestorableReason,
) {
    let signature = signature_by(&mut pool.acquire().await.unwrap(), id, &SEED).await;
    assert_refused(pool, id, &signature, at, reason).await;
}

/// `C` of `op_1` of [`issued`], written out by hand: the members sorted
/// byte-wise, no whitespace, the expiry in microseconds.
fn op_1_canonical() -> String {
    format!(
        "{{\"actor_id\":\"deployment_operator\",\"expected_revision\":1,\"expires_at\":{},\
         \"id\":\"op_1\",\"kind\":\"operator_restoration\",\"plan\":{{\
         \"admin_id\":\"adm_new\",\"binding_id\":\"rb_new\",\"credential_id\":\"crd_new\",\
         \"instance_id\":\"{INSTANCE}\",\"new_recovery_public_key\":\"{}\",\
         \"public_identity\":\"spki-sha256:new\",\"recovery_key_epoch\":1,\
         \"trust_anchor_ref\":\"deployment/operator-ca\"}},\"tenant_id\":null}}",
        micros(expires()),
        hex(&NEW_KEY),
    )
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_recovery_state_is_read_after_bootstrap_only() {
    let (db, pool) = migrated().await;
    assert_eq!(get_recovery_state(&pool).await.unwrap(), None);
    db.drop([pool]).await;

    let (db, pool) = bootstrapped().await;
    assert_eq!(
        get_recovery_state(&pool).await.unwrap(),
        Some(RecoveryState {
            instance_id: INSTANCE.into(),
            bootstrap_closed: true,
            recovery_public_key: KEY.to_vec(),
            recovery_key_epoch: 1,
            revision: 1,
        })
    );
    db.drop([pool]).await;
}

/// The event comes first, with the operation's ID as its object, and the
/// row references it; every column of the row is exact. The issue returns
/// `M`, the prefix and `C`; the stored request digest is SHA-256 of the
/// digest prefix and `C`, and the challenge hash SHA-256 of `M`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_issue_appends_its_event_and_then_inserts_the_operation() {
    let (db, pool) = bootstrapped().await;
    let challenge = issue(&pool, "op_1", "aud_issue_1").await;
    assert_eq!(
        (
            &challenge.operation_id[..],
            challenge.expires_at,
            challenge.expected_revision
        ),
        ("op_1", expires(), 1)
    );
    let canonical = op_1_canonical();
    let m = [CHALLENGE_PREFIX, canonical.as_bytes()].concat();
    assert_eq!(
        String::from_utf8(challenge.challenge.clone()).unwrap(),
        String::from_utf8(m.clone()).unwrap()
    );
    assert_eq!(
        stored_challenge(&mut pool.acquire().await.unwrap(), "op_1").await,
        Some(m.clone())
    );
    let event = &challenge.audit_event;
    assert_eq!(
        (
            &event.id[..],
            event.tenant_id.as_deref(),
            event.sequence,
            event.timestamp,
            &event.actor,
            &event.action[..],
            &event.object_id[..],
            event.previous_revision,
            event.new_revision,
            &event.outcome[..],
        ),
        (
            "aud_issue_1",
            None,
            2,
            at(1_000_000),
            &AuditActor::Operator("deployment_operator".into()),
            "administrative_operation.create",
            "op_1",
            None,
            Some(1),
            "success",
        )
    );
    assert_eq!(event.compute_hash().unwrap(), event.hash);
    let actor: String =
        sqlx::query_scalar("SELECT actor FROM audit_event WHERE id = 'aud_issue_1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(actor, r#"{"id":"deployment_operator","type":"operator"}"#);
    assert_eq!(
        pool_operation(&pool, "op_1").await,
        Operation {
            id: "op_1".into(),
            tenant_id: None,
            actor_id: "deployment_operator".into(),
            kind: "operator_restoration".into(),
            request_digest: Sha256::digest([DIGEST_PREFIX, canonical.as_bytes()].concat()).to_vec(),
            expected_revision: 1,
            immutable_plan: Value::Object(good_plan()),
            challenge_hash: Some(Sha256::digest(&m).to_vec()),
            expires_us: Some(micros(expires())),
            consumed_us: None,
            revoked_us: None,
            revocation_operation_id: None,
            approves_operation_id: None,
            revision: 1,
            outcome: "issued".into(),
            audit_id: "aud_issue_1".into(),
        }
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    // The recovery state is read, not written.
    assert_eq!(
        get_recovery_state(&pool).await.unwrap().map(|s| s.revision),
        Some(1)
    );
    db.drop([pool]).await;
}

/// TTLs of 1 s to 15 min are accepted and stored as `now + ttl`; 0, 1 ns,
/// 1 s - 1 ns, 15 min + 1 ns and `Duration::MAX` are encode errors that
/// run no statement, so the transaction stays usable and holds nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_ttl_is_one_second_to_fifteen_minutes() {
    let (db, pool) = bootstrapped().await;
    let plan = good_plan();
    for (index, ttl) in [MIN_CHALLENGE_TTL, DEFAULT_CHALLENGE_TTL, MAX_CHALLENGE_TTL]
        .into_iter()
        .enumerate()
    {
        let id = format!("op_ttl_{index}");
        let audit = format!("aud_ttl_{index}");
        let mut request = issue_request(&id, &audit, &plan);
        request.ttl = ttl;
        let challenge = issue_on(&pool, &request).await.unwrap();
        let expected = UNIX_EPOCH
            + Duration::from_micros(
                u64::try_from(
                    (issue_time() + ttl)
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros(),
                )
                .unwrap(),
            );
        assert_eq!(challenge.expires_at, expected, "{ttl:?}");
        assert_eq!(
            pool_operation(&pool, &id).await.expires_us,
            Some(micros(expected))
        );
        // `C` carries the expiry as stored.
        assert_eq!(
            Some(challenge.challenge),
            stored_challenge(&mut pool.acquire().await.unwrap(), &id).await,
            "{ttl:?}"
        );
    }
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let before = counts(&mut transaction).await;
    for ttl in [
        Duration::ZERO,
        Duration::from_nanos(1),
        MIN_CHALLENGE_TTL - Duration::from_nanos(1),
        MAX_CHALLENGE_TTL + Duration::from_nanos(1),
        Duration::MAX,
    ] {
        let mut request = issue_request("op_bad", "aud_bad", &plan);
        request.ttl = ttl;
        assert_issue_encode(
            issue_recovery_challenge(&mut transaction, &request).await,
            "challenge TTL is not 1 second to 15 minutes",
        );
        assert_eq!(counts(&mut transaction).await, before, "{ttl:?}");
    }
    transaction.rollback().await.unwrap();
    drop(connection);
    db.drop([pool]).await;
}

#[track_caller]
fn assert_issue_reserved<T: Debug>(result: Result<T, ChallengeError>) {
    match result {
        Err(ChallengeError::Store(RegistryError::ReservedActorId)) => {}
        other => panic!("expected ReservedActorId: {other:?}"),
    }
}

/// Another kind, a plan without a string `instance_id` and an integer
/// `recovery_key_epoch` (an `i64`), without the replacement's strings,
/// without its key in lowercase hexadecimal, with a member other than the
/// eight, with a reserved `admin_id`, an empty or over-2048-byte
/// `public_identity` or `trust_anchor_ref`, or a new key that is not a
/// canonical point of large order, are errors before any statement.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_issue_checks_its_kind_and_plan_before_any_statement() {
    let (db, pool) = bootstrapped().await;
    let good = good_plan();
    let changed = |name: &str, value: Option<Value>| {
        let mut plan = good_plan();
        match value {
            Some(value) => plan.insert(name.into(), value),
            None => plan.remove(name),
        };
        plan
    };
    let binding_plans = [
        plan(INSTANCE, json!("1")),
        plan(INSTANCE, json!(1.0)),
        plan(INSTANCE, json!(1.5)),
        plan(INSTANCE, json!(9_223_372_036_854_775_808_u64)),
        plan(INSTANCE, json!(null)),
        changed("recovery_key_epoch", None),
        changed("instance_id", None),
        changed("instance_id", Some(json!(7))),
    ];
    let replacement_plans = [
        changed("admin_id", None),
        changed("credential_id", Some(json!(1))),
        changed("binding_id", Some(json!(null))),
        changed("public_identity", Some(json!(["spki-sha256:new"]))),
        changed("trust_anchor_ref", None),
    ];
    let key_plans = [
        changed("new_recovery_public_key", None),
        changed("new_recovery_public_key", Some(json!(hex(&NEW_KEY[..31])))),
        changed(
            "new_recovery_public_key",
            Some(json!(hex(&NEW_KEY).to_uppercase())),
        ),
        changed("new_recovery_public_key", Some(json!(NEW_KEY.to_vec()))),
    ];
    let open_plans = [
        changed("operation", Some(json!("operator_restoration"))),
        changed("nonce", Some(json!("n"))),
        changed("", Some(json!(null))),
    ];
    let long = "x".repeat(2049);
    let bound_plans = [
        (
            changed("public_identity", Some(json!(""))),
            "public identity is empty or over 2048 bytes",
        ),
        (
            changed("public_identity", Some(json!(long))),
            "public identity is empty or over 2048 bytes",
        ),
        (
            changed("trust_anchor_ref", Some(json!(""))),
            "trust anchor reference is empty or over 2048 bytes",
        ),
        (
            changed("trust_anchor_ref", Some(json!(long))),
            "trust anchor reference is empty or over 2048 bytes",
        ),
    ];
    let weak_plans = [
        (
            plan_for(INSTANCE, json!(1), &other(&IDENTITY)),
            "recovery public key is a small-order Ed25519 point",
        ),
        (
            plan_for(INSTANCE, json!(1), &other(&[0; 32])),
            "recovery public key is a small-order Ed25519 point",
        ),
        (
            plan_for(INSTANCE, json!(1), &other(&IDENTITY_P_PLUS_1)),
            "recovery public key is not canonically encoded",
        ),
        (
            plan_for(INSTANCE, json!(1), &other(&LARGE_P_PLUS_3)),
            "recovery public key is not canonically encoded",
        ),
        (
            plan_for(INSTANCE, json!(1), &other(&UNDECODABLE)),
            "recovery public key is not an Ed25519 point",
        ),
    ];
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let before = snapshot(&mut transaction).await;
    for kind in ["approve", "", "OPERATOR_RESTORATION"] {
        let mut request = issue_request("op_bad", "aud_bad", &good);
        request.kind = kind;
        assert_issue_encode(
            issue_recovery_challenge(&mut transaction, &request).await,
            "recovery challenge kind is not operator_restoration",
        );
    }
    for (plans, message) in [
        (
            &binding_plans[..],
            "plan lacks a string instance_id or an integer recovery_key_epoch",
        ),
        (
            &replacement_plans[..],
            "plan lacks a string admin_id, credential_id, binding_id, public_identity or \
             trust_anchor_ref",
        ),
        (
            &key_plans[..],
            "plan new_recovery_public_key is not 64 lowercase hexadecimal digits",
        ),
        (
            &open_plans[..],
            "plan has a member other than the eight of an operator restoration",
        ),
    ] {
        for plan in plans {
            assert_issue_encode(
                issue_recovery_challenge(
                    &mut transaction,
                    &issue_request("op_bad", "aud_bad", plan),
                )
                .await,
                message,
            );
        }
    }
    for (plan, message) in bound_plans.iter().chain(&weak_plans) {
        assert_issue_encode(
            issue_recovery_challenge(&mut transaction, &issue_request("op_bad", "aud_bad", plan))
                .await,
            message,
        );
    }
    for admin in ["deployment_operator", "recovery_key:1"] {
        let plan = changed("admin_id", Some(json!(admin)));
        assert_issue_reserved(
            issue_recovery_challenge(&mut transaction, &issue_request("op_bad", "aud_bad", &plan))
                .await,
        );
    }
    let mut request = issue_request("op_bad", "aud_bad", &good);
    request.now = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    assert_issue_encode(
        issue_recovery_challenge(&mut transaction, &request).await,
        "audit timestamp outside the years 0000 to 9999",
    );
    assert_eq!(snapshot(&mut transaction).await, before);
    // Still usable: a good issue goes through in the same transaction.
    issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_1", "aud_issue_1", &good),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(pool_operation(&pool, "op_1").await.revision, 1);
    db.drop([pool]).await;
}

/// No recovery state, or one whose `bootstrap_closed` is false (only a
/// write by other means leaves one), is `NotIssuable`, and nothing is
/// written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn no_challenge_is_issued_without_a_closed_recovery_state() {
    let (db, pool) = migrated().await;
    let before = pool_snapshot(&pool).await;
    assert_not_issuable(issue_on(&pool, &issue_request("op_1", "aud_1", &good_plan())).await);
    assert_eq!(pool_snapshot(&pool).await, before);

    sqlx::raw_sql(
        "INSERT INTO instance_security_policy (instance_id) \
         VALUES ('019a9f3c-5b2e-7c41-9d8e-0123456789ab'); \
         INSERT INTO recovery_state (instance_id, bootstrap_closed, recovery_public_key, \
         recovery_key_epoch) VALUES ('019a9f3c-5b2e-7c41-9d8e-0123456789ab', false, \
         '\\xc050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let before = pool_snapshot(&pool).await;
    assert_not_issuable(issue_on(&pool, &issue_request("op_1", "aud_1", &good_plan())).await);
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A plan for another instance or another epoch, or whose new key is the
/// current one, is `NotIssuable`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn no_challenge_is_issued_for_another_instance_or_epoch_or_the_current_key() {
    let (db, pool) = bootstrapped().await;
    let before = pool_snapshot(&pool).await;
    for plan in [
        plan(OTHER_INSTANCE, json!(1)),
        plan("", json!(1)),
        plan(INSTANCE, json!(2)),
        plan(INSTANCE, json!(0)),
        plan(INSTANCE, json!(-1)),
        plan_for(INSTANCE, json!(1), &other(&KEY)),
    ] {
        assert_not_issuable(issue_on(&pool, &issue_request("op_1", "aud_1", &plan)).await);
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// `expected_revision` is the recovery state's revision when the challenge
/// is issued, and `C` binds it: a challenge issued at an older revision is
/// `NotBound`, even signed by the current key.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_binds_the_current_recovery_state_revision() {
    let (db, pool) = bootstrapped().await;
    issue(&pool, "op_0", "aud_issue_0").await;
    sqlx::query("UPDATE recovery_state SET revision = revision + 1")
        .execute(&pool)
        .await
        .unwrap();
    let challenge = issue(&pool, "op_1", "aud_issue_1").await;
    assert_eq!(challenge.expected_revision, 2);
    assert_eq!(pool_operation(&pool, "op_1").await.expected_revision, 2);
    assert!(
        String::from_utf8(challenge.challenge)
            .unwrap()
            .contains("\"expected_revision\":2,")
    );
    assert_refused_signed(&pool, "op_0", now(), NotRestorableReason::NotBound).await;
    let restored = restore_on(&pool, "op_1", &restore_request()).await.unwrap();
    assert_eq!(restored.recovery_state_revision, 3);
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!(
        (row.expected_revision, row.consumed_us),
        (2, Some(micros(now())))
    );
    assert_eq!(pool_operation(&pool, "op_0").await.consumed_us, None);
    db.drop([pool]).await;
}

/// The restore consumes the challenge: `consumed_at` is `now` and the
/// revision advances; a replay, in the same transaction or after the
/// commit, signed by the old key or the new one, is `Consumed` and writes
/// nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_is_consumed_once() {
    let (db, pool) = issued().await;
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    let after = snapshot(&mut transaction).await;
    let replay = RestoreRequest {
        audit_event_id: "aud_replay",
        rotation_audit_event_id: "aud_replay_rotate",
        now: now(),
    };
    assert_not_restorable(
        restore_in(&mut transaction, "op_1", &replay).await,
        NotRestorableReason::Consumed,
    );
    assert_eq!(snapshot(&mut transaction).await, after);
    transaction.commit().await.unwrap();
    drop(connection);
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!(
        (row.consumed_us, row.revision, &row.outcome[..]),
        (Some(micros(now())), 3, "restored")
    );
    let before = pool_snapshot(&pool).await;
    for later in [now(), now() + Duration::from_secs(1)] {
        let mut request = replay;
        request.now = later;
        for seed in [&SEED, &NEW_SEED] {
            assert_not_restorable(
                restore_by(&pool, "op_1", seed, &request).await,
                NotRestorableReason::Consumed,
            );
        }
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// `$now < expires_at`, at step 3 and in the statement, against the
/// caller's `now`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_challenge_expires_at_its_expiry() {
    let (db, pool) = issued().await;
    for late in [
        expires(),
        expires() + Duration::from_micros(1),
        expires() + Duration::from_secs(3600),
    ] {
        assert_refused_signed(&pool, "op_1", late, NotRestorableReason::Expired).await;
    }
    // A `now` the audit event could not carry is refused before the
    // statement, not compared.
    let mut request = restore_request();
    request.now = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    assert_restore_encode(
        restore_on(&pool, "op_1", &request).await,
        "audit timestamp outside the years 0000 to 9999",
    );
    let last = expires() - Duration::from_micros(1);
    let mut request = restore_request();
    request.now = last;
    let restored = restore_on(&pool, "op_1", &request).await.unwrap();
    assert_eq!(restored.audit_event.timestamp, last);
    assert_eq!(
        pool_operation(&pool, "op_1").await.consumed_us,
        Some(micros(last))
    );
    db.drop([pool]).await;
}

/// A challenge revoked before its restore is `Revoked`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_revoked_challenge_is_not_restorable() {
    let (db, pool) = issued().await;
    issue(&pool, "op_2", "aud_issue_2").await;
    raw_revoke(&mut pool.acquire().await.unwrap(), "op_1", "op_2").await;
    assert_refused_signed(&pool, "op_1", now(), NotRestorableReason::Revoked).await;
    // The other one still is.
    restore_on(&pool, "op_2", &restore_request()).await.unwrap();
    db.drop([pool]).await;
}

/// Every refusal of steps 2 and 3 has its reason, the same at the preview
/// and the restore, and writes nothing. A row written by other means with
/// every value right, the library's encoding included, is restorable, so
/// each refusal is its one difference; every row here is signed by the
/// current key over its own `M`, so the signature never decides. A row
/// without a challenge hash and an expiry (an approval, as `0005` allows)
/// is `WrongKind`, and so is a hash without an expiry.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_refusal_has_its_reason() {
    let (db, pool) = issued().await;
    issue(&pool, "op_revoker", "aud_issue_2").await;
    issue(&pool, "op_revoked", "aud_issue_3").await;
    raw_revoke(
        &mut pool.acquire().await.unwrap(),
        "op_revoked",
        "op_revoker",
    )
    .await;
    issue(&pool, "op_replayed", "aud_issue_4").await;
    issue(&pool, "op_failed", "aud_issue_5").await;
    sqlx::query(
        "UPDATE administrative_operation SET outcome = 'failed', revision = revision + 1 \
         WHERE id = 'op_failed'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(RAW_CONSUME)
        .bind("op_replayed")
        .bind(micros(now()))
        .execute(&pool)
        .await
        .unwrap();
    let with = |name: &str, value: Value| {
        let mut plan = good_plan();
        plan.insert(name.into(), value);
        json!(plan)
    };
    let without = |name: &str| {
        let mut plan = good_plan();
        plan.remove(name);
        json!(plan)
    };
    use NotRestorableReason::{
        Consumed, Expired, NotBound, NotFound, NotLibraryEncoding, Revoked, WrongKind,
    };
    let (good_digest, good_hash) = library("raw_good", 1, &good_plan()).unwrap();
    let other_digest = library("raw_bad_hash", 1, &good_plan()).unwrap().0;
    let mut flipped = good_hash.clone();
    flipped[31] ^= 1;
    let rows: Vec<(&str, &str, Value, Stored, i64, NotRestorableReason)> = vec![
        (
            "raw_kind",
            "route_bundle_approval",
            json!(good_plan()),
            Stored::Library,
            1,
            WrongKind,
        ),
        (
            "raw_no_hash",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            Stored::Bytes(good_digest.clone(), None),
            1,
            WrongKind,
        ),
        (
            "raw_revision_0",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            Stored::Library,
            0,
            NotBound,
        ),
        (
            "raw_revision_2",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            Stored::Library,
            2,
            NotBound,
        ),
        (
            "raw_epoch_string",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!("1")),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_epoch_float",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(1.0)),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_epoch_fraction",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(1.5)),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_epoch_null",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(null)),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_epoch_negative",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(-1)),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_epoch_other",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!(2)),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_epoch_array",
            OPERATOR_RESTORATION,
            with("recovery_key_epoch", json!([1])),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_epoch_missing",
            OPERATOR_RESTORATION,
            without("recovery_key_epoch"),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_instance_missing",
            OPERATOR_RESTORATION,
            without("instance_id"),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_instance_number",
            OPERATOR_RESTORATION,
            with("instance_id", json!(1)),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_other_instance",
            OPERATOR_RESTORATION,
            json!(plan(OTHER_INSTANCE, json!(1))),
            Stored::Library,
            1,
            NotBound,
        ),
        (
            "raw_upper_instance",
            OPERATOR_RESTORATION,
            json!(plan(&INSTANCE.to_uppercase(), json!(1))),
            Stored::Library,
            1,
            NotBound,
        ),
        // The digest or the hash of another row, both of another row, the
        // two swapped, one bit of the hash flipped, or the hash extended:
        // each a stored value that is not the library's encoding of its
        // row.
        (
            "raw_bad_digest",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            Stored::Bytes(
                other_digest,
                Some(library("raw_bad_digest", 1, &good_plan()).unwrap().1),
            ),
            1,
            NotLibraryEncoding,
        ),
        (
            "raw_bad_hash",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            Stored::Bytes(
                library("raw_bad_hash", 1, &good_plan()).unwrap().0,
                Some(good_hash.clone()),
            ),
            1,
            NotLibraryEncoding,
        ),
        (
            "raw_good_copy",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            Stored::Bytes(good_digest.clone(), Some(good_hash.clone())),
            1,
            NotLibraryEncoding,
        ),
        (
            "raw_swapped",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            {
                let (digest, hash) = library("raw_swapped", 1, &good_plan()).unwrap();
                Stored::Bytes(hash, Some(digest))
            },
            1,
            NotLibraryEncoding,
        ),
        (
            "raw_flipped",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            Stored::Bytes(
                library("raw_flipped", 1, &good_plan()).unwrap().0,
                Some(flipped),
            ),
            1,
            NotLibraryEncoding,
        ),
        (
            "raw_long_hash",
            OPERATOR_RESTORATION,
            json!(good_plan()),
            {
                let (digest, hash) = library("raw_long_hash", 1, &good_plan()).unwrap();
                Stored::Bytes(digest, Some([&hash[..], &[0; 32]].concat()))
            },
            1,
            NotLibraryEncoding,
        ),
    ];
    insert_raw(
        &pool,
        "raw_good",
        OPERATOR_RESTORATION,
        json!(good_plan()),
        Stored::Library,
        1,
    )
    .await;
    insert_raw_by(
        &pool,
        "raw_actor",
        "adm_first",
        OPERATOR_RESTORATION,
        json!(good_plan()),
        Stored::Library,
        1,
    )
    .await;
    let mut expected = vec![("raw_actor", WrongKind)];
    for (id, kind, plan, stored, revision, reason) in rows {
        insert_raw(&pool, id, kind, plan, stored, revision).await;
        expected.push((id, reason));
    }
    // A tenant's operation with every other value right.
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
    // Its audit event is of its tenant: the 0005 audit guard refuses an
    // operation of ten_a recorded by an instance event.
    let mut transaction = pool.begin().await.unwrap();
    registry::test_support::append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: "aud_raw_tenant".into(),
            tenant_id: Some("ten_a".into()),
            timestamp: now(),
            actor: AuditActor::Operator("deployment_operator".into()),
            action: "administrative_operation.create".into(),
            object_id: "raw_tenant".into(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, challenge_hash, expires_at, outcome, audit_id) \
         SELECT 'raw_tenant', 'ten_a', actor_id, kind, $1, expected_revision, \
         immutable_plan, $2, expires_at, outcome, 'aud_raw_tenant' \
         FROM administrative_operation WHERE id = 'raw_good'",
    )
    .bind(library("raw_tenant", 1, &good_plan()).unwrap().0)
    .bind(library("raw_tenant", 1, &good_plan()).unwrap().1)
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    // A row with neither a challenge hash nor an expiry, as `0005` allows
    // for every approve, cancel and reject row of the second-approver flow:
    // an approval of `op_1`, written by other means.
    sqlx::query(
        "INSERT INTO administrative_operation (id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, approves_operation_id, outcome, audit_id) \
         VALUES ('raw_approve', 'adm_first', 'approve', $1, 1, $2, 'op_1', 'issued', \
         'aud_issue_1')",
    )
    .bind(&good_digest)
    .bind(json!(good_plan()))
    .execute(&pool)
    .await
    .unwrap();
    expected.extend([
        ("raw_approve", WrongKind),
        ("raw_tenant", WrongKind),
        ("op_unknown", NotFound),
        ("", NotFound),
        ("op_revoked", Revoked),
        ("op_replayed", Consumed),
        ("op_failed", WrongKind),
    ]);
    let before = pool_snapshot(&pool).await;
    for (id, reason) in expected {
        assert_refused_signed(&pool, id, now(), reason).await;
    }
    assert_refused_signed(&pool, "op_1", expires(), Expired).await;
    assert_eq!(pool_snapshot(&pool).await, before);
    // A challenge hash without an expiry, which only a schema without the
    // `0005` check could hold (dropped here inside a transaction that rolls
    // back): no challenge either.
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    sqlx::raw_sql(
        "ALTER TABLE administrative_operation \
         DROP CONSTRAINT administrative_operation_challenge_expiry_check",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO administrative_operation (id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, challenge_hash, outcome, audit_id) \
         VALUES ('raw_no_expiry', 'deployment_operator', $1, $2, 1, $3, $4, 'issued', \
         'aud_issue_1')",
    )
    .bind(OPERATOR_RESTORATION)
    .bind(&good_digest)
    .bind(json!(good_plan()))
    .bind(&good_hash)
    .execute(&mut *transaction)
    .await
    .unwrap();
    let signature = sign(&SEED, b"no expiry");
    let presented = response("raw_no_expiry", &signature);
    assert_not_restorable(
        preview_recovery_response(&mut transaction, &presented, now()).await,
        WrongKind,
    );
    assert_not_restorable(
        restore_operator(&mut transaction, &presented, &restore_request()).await,
        WrongKind,
    );
    transaction.rollback().await.unwrap();
    drop(connection);
    assert_eq!(pool_snapshot(&pool).await, before);
    // The issued challenge is restorable, and so is the control row.
    let mut transaction = pool.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.rollback().await.unwrap();
    restore_on(&pool, "raw_good", &restore_request())
        .await
        .unwrap();
    db.drop([pool]).await;
}

/// `signature` with `S` replaced by `S + L`, the group order: the same
/// point, a malleated signature.
fn malleate(signature: &[u8]) -> Vec<u8> {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut out = signature.to_vec();
    let mut carry = 0_u16;
    for (byte, add) in out[32..].iter_mut().zip(L) {
        let sum = u16::from(*byte) + u16::from(add) + carry;
        *byte = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    out
}

/// `op_1` of [`issued`] presented with `signature`: `BadSignature` at the
/// preview and the restore, nothing written, the challenge unconsumed and
/// still `issued`, and the recovery state and the audit chain unchanged.
async fn assert_bad_signature(pool: &PgPool, signature: &[u8], what: &str) {
    let operation = pool_operation(pool, "op_1").await;
    let state = get_recovery_state(pool).await.unwrap();
    let chain = verify(pool).await;
    assert_refused(
        pool,
        "op_1",
        signature,
        now(),
        NotRestorableReason::BadSignature,
    )
    .await;
    let after = pool_operation(pool, "op_1").await;
    assert_eq!(
        (after.consumed_us, &after.outcome[..], after.revision),
        (None, "issued", 1),
        "{what}"
    );
    assert_eq!(after, operation, "{what}");
    assert_eq!(get_recovery_state(pool).await.unwrap(), state, "{what}");
    assert_eq!(verify(pool).await, chain, "{what}");
}

/// The signature must verify over the stored `M` with the current recovery
/// key: a signature with a bit flipped, of zeros, by another key (a third
/// one, or the plan's new key), over other bytes (the challenge hash, `C`
/// without the prefix, `C` under the request-digest prefix, `M` with a
/// byte more, another challenge's `M`), with `S + L`, or with `R` replaced
/// by a non-canonical encoding, is `BadSignature` and writes nothing; the
/// right signature then restores.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_needs_a_signature_by_the_current_key_over_m() {
    let (db, pool) = issued().await;
    issue(&pool, "op_2", "aud_issue_2").await;
    let mut connection = pool.acquire().await.unwrap();
    let m = stored_challenge(&mut connection, "op_1").await.unwrap();
    let other_m = stored_challenge(&mut connection, "op_2").await.unwrap();
    drop(connection);
    let canonical = &m[CHALLENGE_PREFIX.len()..];
    assert_eq!(canonical, op_1_canonical().as_bytes());
    let good = sign(&SEED, &m);
    let mut first = good.clone();
    first[0] ^= 1;
    let mut last = good.clone();
    last[63] ^= 0x80;
    let mut middle = good.clone();
    middle[40] ^= 0x10;
    let mut non_canonical_r = good.clone();
    non_canonical_r[..32].copy_from_slice(&IDENTITY_P_PLUS_1);
    let mut longer = m.clone();
    longer.push(b'\n');
    for (what, signature) in [
        ("first bit", first),
        ("last bit", last),
        ("middle bit", middle),
        ("zeros", vec![0; 64]),
        ("ones", vec![0xff; 64]),
        ("third key", sign(&THIRD_SEED, &m)),
        ("plan key", sign(&NEW_SEED, &m)),
        ("hash", sign(&SEED, &Sha256::digest(&m))),
        ("no prefix", sign(&SEED, canonical)),
        (
            "digest prefix",
            sign(&SEED, &[DIGEST_PREFIX, canonical].concat()),
        ),
        ("longer", sign(&SEED, &longer)),
        ("other challenge", sign(&SEED, &other_m)),
        ("S + L", malleate(&good)),
        ("non-canonical R", non_canonical_r),
    ] {
        assert_bad_signature(&pool, &signature, what).await;
    }
    let restored = restore_with(&pool, "op_1", &good, &restore_request())
        .await
        .unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    assert_eq!(pool_operation(&pool, "op_1").await.outcome, "restored");

    // The retired key no longer signs: a challenge issued at the new
    // epoch needs the new key.
    let next = plan_for(INSTANCE, json!(2), &other(&THIRD_KEY));
    let mut request = issue_request("op_3", "aud_issue_3", &next);
    request.now = at(3_000_000);
    issue_on(&pool, &request).await.unwrap();
    let later = RestoreRequest {
        audit_event_id: "aud_restore_3",
        rotation_audit_event_id: "aud_rotate_3",
        now: at(4_000_000),
    };
    let retired = signature_by(&mut pool.acquire().await.unwrap(), "op_3", &SEED).await;
    assert_refused(
        &pool,
        "op_3",
        &retired,
        later.now,
        NotRestorableReason::BadSignature,
    )
    .await;
    let restored = restore_by(&pool, "op_3", &NEW_SEED, &later).await.unwrap();
    assert_eq!(
        (&restored.admin_id[..], restored.recovery_key_epoch),
        ("adm_other", 3)
    );
    db.drop([pool]).await;
}

/// A plain verification accepts what the restore must refuse; the current
/// key here is a good one, so only `verify_strict` stands between
/// [`SMALL_ORDER_R_SIGNATURE`] and a restore: it is `BadSignature` at the
/// preview and the restore, nothing written; the right signature then
/// restores.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_signature_only_a_plain_verification_accepts_is_refused() {
    let (db, pool) = issued().await;
    let m = stored_challenge(&mut pool.acquire().await.unwrap(), "op_1")
        .await
        .unwrap();
    assert_eq!(m, [CHALLENGE_PREFIX, op_1_canonical().as_bytes()].concat());
    let current = VerifyingKey::from_bytes(&KEY).unwrap();
    current
        .verify(&m, &Signature::from_bytes(&SMALL_ORDER_R_SIGNATURE))
        .expect("a plain verification accepts a small-order R");
    assert!(
        current
            .verify_strict(&m, &Signature::from_bytes(&SMALL_ORDER_R_SIGNATURE))
            .is_err()
    );
    assert_bad_signature(&pool, &SMALL_ORDER_R_SIGNATURE, "small-order R").await;
    let restored = restore_on(&pool, "op_1", &restore_request()).await.unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    db.drop([pool]).await;
}

/// A signature that is not 64 bytes, the right one cut short or extended
/// included, is `BadSignature` at the verify step of step 3, after the
/// locks and the checks before it, at the preview and the restore: it
/// writes nothing and leaves the challenge unconsumed. The checks before
/// the verify step still decide first: an unknown ID is `NotFound`, an
/// expired challenge `Expired`, a retired one `NotBound`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_signature_of_another_length_is_bad_signature_at_the_verify_step() {
    let (db, pool) = issued().await;
    let good = signature_by(&mut pool.acquire().await.unwrap(), "op_1", &SEED).await;
    let mut extended = good.clone();
    extended.push(0);
    let short = [
        Vec::new(),
        vec![0xc7],
        good[..32].to_vec(),
        good[..63].to_vec(),
        extended,
        [&good[..], &good[..]].concat(),
    ];
    for signature in &short {
        assert_bad_signature(&pool, signature, &format!("{} bytes", signature.len())).await;
        assert_refused(
            &pool,
            "op_unknown",
            signature,
            now(),
            NotRestorableReason::NotFound,
        )
        .await;
        assert_refused(
            &pool,
            "op_1",
            signature,
            expires(),
            NotRestorableReason::Expired,
        )
        .await;
    }
    // A challenge whose recovery state moved since the issue is `NotBound`
    // before its signature is looked at.
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    sqlx::query("UPDATE recovery_state SET revision = revision + 1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    for signature in &short {
        assert_not_restorable(
            restore_operator(
                &mut transaction,
                &response("op_1", signature),
                &restore_request(),
            )
            .await,
            NotRestorableReason::NotBound,
        );
    }
    transaction.rollback().await.unwrap();
    drop(connection);
    let restored = restore_with(&pool, "op_1", &good, &restore_request())
        .await
        .unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    db.drop([pool]).await;
}

/// A current recovery key that is not a canonical point of large order (a
/// row written by other means: bootstrap refuses one) is `WeakKey`, even
/// with the signature that a plain verification accepts for the identity
/// key over any message.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_weak_current_key_is_refused() {
    for (index, key) in [
        &IDENTITY[..],
        &[0; 32][..],
        &IDENTITY_P_PLUS_1[..],
        &LARGE_P_PLUS_3[..],
        &UNDECODABLE[..],
        &KEY[..31],
        &[KEY, KEY].concat()[..],
    ]
    .into_iter()
    .enumerate()
    {
        let (db, pool) = issued().await;
        // The rotation trigger requires the epoch to advance with the key.
        sqlx::query(
            "UPDATE recovery_state SET recovery_public_key = $1, \
             recovery_key_epoch = recovery_key_epoch + 1, revision = revision + 1",
        )
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
        insert_raw(
            &pool,
            "raw_weak",
            OPERATOR_RESTORATION,
            json!(plan(INSTANCE, json!(2))),
            Stored::Library,
            2,
        )
        .await;
        if key == IDENTITY {
            // What a plain verification would let through: the fixed
            // signature over this challenge's `M`, under the identity key.
            let m = stored_challenge(&mut pool.acquire().await.unwrap(), "raw_weak")
                .await
                .unwrap();
            VerifyingKey::from_bytes(&IDENTITY)
                .unwrap()
                .verify(&m, &Signature::from_bytes(&FIXED_SIGNATURE))
                .expect("a plain verification accepts the fixed signature");
        }
        for signature in [FIXED_SIGNATURE.to_vec(), vec![0; 64]] {
            assert_refused(
                &pool,
                "raw_weak",
                &signature,
                now(),
                NotRestorableReason::WeakKey,
            )
            .await;
        }
        assert_refused_signed(&pool, "raw_weak", now(), NotRestorableReason::WeakKey).await;
        assert_eq!(
            pool_operation(&pool, "raw_weak").await.consumed_us,
            None,
            "{index}"
        );
        db.drop([pool]).await;
    }
}

/// A key change between the issue and the restore (by other means, or by
/// another restore) retires the challenge: `NotBound`, signed by the old
/// key or the new one.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_key_change_between_issue_and_restore_retires_the_challenge() {
    let (db, pool) = issued().await;
    sqlx::query(
        "UPDATE recovery_state SET recovery_public_key = $1, \
         recovery_key_epoch = recovery_key_epoch + 1, revision = revision + 1",
    )
    .bind(&THIRD_KEY[..])
    .execute(&pool)
    .await
    .unwrap();
    for seed in [&SEED, &THIRD_SEED] {
        let signature = signature_by(&mut pool.acquire().await.unwrap(), "op_1", seed).await;
        assert_refused(
            &pool,
            "op_1",
            &signature,
            now(),
            NotRestorableReason::NotBound,
        )
        .await;
    }
    db.drop([pool]).await;

    // A replay of an unused challenge after another restore rotated.
    let (db, pool) = issued().await;
    issue(&pool, "op_2", "aud_issue_2").await;
    restore_on(&pool, "op_1", &restore_request()).await.unwrap();
    for seed in [&SEED, &NEW_SEED] {
        let signature = signature_by(&mut pool.acquire().await.unwrap(), "op_2", seed).await;
        assert_refused(
            &pool,
            "op_2",
            &signature,
            now(),
            NotRestorableReason::NotBound,
        )
        .await;
    }
    db.drop([pool]).await;
}

/// The restore enrolls the plan the signature covers: a row with another
/// plan, encoded by the library, presented with `op_1`'s signature is
/// `BadSignature`; the same row carrying `op_1`'s digest and hash is
/// `NotLibraryEncoding`. The stored plan cannot be changed in place.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_tampered_plan_is_refused() {
    let (db, pool) = issued().await;
    let evil = Replacement {
        admin_id: "adm_evil",
        credential_id: "crd_evil",
        binding_id: "rb_evil",
        public_identity: "spki-sha256:evil",
        ..other(&THIRD_KEY)
    };
    let evil_plan = json!(plan_for(INSTANCE, json!(1), &evil));
    let op_1 = pool_operation(&pool, "op_1").await;
    insert_raw(
        &pool,
        "raw_evil",
        OPERATOR_RESTORATION,
        evil_plan.clone(),
        Stored::Library,
        1,
    )
    .await;
    insert_raw(
        &pool,
        "raw_evil_copied",
        OPERATOR_RESTORATION,
        evil_plan.clone(),
        Stored::Bytes(op_1.request_digest.clone(), op_1.challenge_hash.clone()),
        1,
    )
    .await;
    let op_1_signature = signature_by(&mut pool.acquire().await.unwrap(), "op_1", &SEED).await;
    assert_refused(
        &pool,
        "raw_evil",
        &op_1_signature,
        now(),
        NotRestorableReason::BadSignature,
    )
    .await;
    assert_refused(
        &pool,
        "raw_evil_copied",
        &op_1_signature,
        now(),
        NotRestorableReason::NotLibraryEncoding,
    )
    .await;
    let err =
        sqlx::query("UPDATE administrative_operation SET immutable_plan = $1 WHERE id = 'op_1'")
            .bind(&evil_plan)
            .execute(&pool)
            .await
            .unwrap_err();
    assert_eq!(sqlstate(&err), "SK001");
    // `op_1` restores its own plan.
    let restored = restore_with(&pool, "op_1", &op_1_signature, &restore_request())
        .await
        .unwrap();
    assert_eq!(restored.admin_id, "adm_new");
    db.drop([pool]).await;
}

/// The preview checks a response as the restore does and returns what it
/// would enroll; it takes no lock, writes nothing and grants nothing: the
/// restore checks again, at its own `now`, with its own signature.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_preview_checks_as_a_restore_does_and_grants_nothing() {
    let (db, pool) = issued().await;
    let signature = signature_by(&mut pool.acquire().await.unwrap(), "op_1", &SEED).await;
    let before = pool_snapshot(&pool).await;
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let preview = preview_recovery_response(&mut transaction, &response("op_1", &signature), now())
        .await
        .unwrap();
    assert_eq!(
        preview,
        RecoveryPreview {
            admin_id: "adm_new".into(),
            credential_id: "crd_new".into(),
            binding_id: "rb_new".into(),
            new_recovery_key_epoch: 2,
            expires_at: expires(),
        }
    );
    assert_eq!(format!("{preview:?}"), "RecoveryPreview { .. }");
    // No lock held: another transaction takes every row a restore locks.
    let mut other = pool.begin().await.unwrap();
    for statement in [
        "SELECT 1 FROM recovery_state FOR UPDATE NOWAIT",
        "SELECT 1 FROM administrative_operation WHERE id = 'op_1' FOR UPDATE NOWAIT",
        "SELECT 1 FROM admin_credential FOR UPDATE NOWAIT",
    ] {
        sqlx::query(statement).execute(&mut *other).await.unwrap();
    }
    other.rollback().await.unwrap();
    assert_eq!(snapshot(&mut transaction).await, before);
    // A preview of the same response again, and a refusal, keep the
    // transaction usable: it still commits, and the commit writes nothing.
    assert_eq!(
        preview_recovery_response(&mut transaction, &response("op_1", &signature), now())
            .await
            .unwrap(),
        preview
    );
    assert_not_restorable(
        preview_recovery_response(&mut transaction, &response("op_1", &[0; 64]), now()).await,
        NotRestorableReason::BadSignature,
    );
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(pool_snapshot(&pool).await, before);

    // Grants nothing: after a good preview, a restore later than the
    // expiry, or with another signature, is refused.
    let mut late = restore_request();
    late.now = expires();
    assert_not_restorable(
        restore_with(&pool, "op_1", &signature, &late).await,
        NotRestorableReason::Expired,
    );
    assert_not_restorable(
        restore_with(&pool, "op_1", &[0; 64], &restore_request()).await,
        NotRestorableReason::BadSignature,
    );
    assert_eq!(pool_snapshot(&pool).await, before);
    // Before bootstrap there is nothing to preview.
    let (empty_db, empty) = migrated().await;
    assert_not_restorable(
        preview_with(&empty, "op_1", &signature, now()).await,
        NotRestorableReason::NoRecoveryState,
    );
    empty_db.drop([empty]).await;
    // A consumed challenge previews as `Consumed`.
    restore_with(&pool, "op_1", &signature, &restore_request())
        .await
        .unwrap();
    assert_not_restorable(
        preview_with(&pool, "op_1", &signature, now()).await,
        NotRestorableReason::Consumed,
    );
    db.drop([pool]).await;
}

/// The single-use property holds in the database even for a statement
/// without the predicates: a replay and a consume after a revocation fail
/// with `SK001`, and a consume at the expiry with `23514`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_database_refuses_a_replay_a_late_consume_and_one_after_revocation() {
    let (db, pool) = issued().await;
    issue(&pool, "op_revoker", "aud_issue_2").await;
    issue(&pool, "op_revoked", "aud_issue_3").await;
    raw_revoke(
        &mut pool.acquire().await.unwrap(),
        "op_revoked",
        "op_revoker",
    )
    .await;
    restore_on(&pool, "op_1", &restore_request()).await.unwrap();
    let before = pool_snapshot(&pool).await;
    for (id, at, expected) in [
        ("op_1", now() + Duration::from_secs(1), None),
        ("op_revoked", now(), None),
        (
            "op_revoker",
            expires(),
            Some("administrative_operation_consumed_before_expiry_check"),
        ),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        let err = sqlx::query(RAW_CONSUME)
            .bind(id)
            .bind(micros(at))
            .execute(&mut *transaction)
            .await
            .unwrap_err();
        let code = err
            .as_database_error()
            .unwrap()
            .code()
            .unwrap()
            .into_owned();
        match (RegistryError::from(err), expected) {
            (RegistryError::Guard, None) => assert_eq!(code, "SK001", "{id}"),
            (
                RegistryError::Invariant {
                    kind: InvariantKind::Check,
                    constraint: Some(constraint),
                },
                Some(name),
            ) => {
                assert_eq!((&code[..], constraint), ("23514", name), "{id}");
            }
            (other, _) => panic!("{id}: {other:?}"),
        }
        transaction.rollback().await.unwrap();
    }
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// Whether the backend `blocked` waits for a lock held by `holder`.
async fn is_blocked(pool: &PgPool, blocked: i32, holder: i32) -> bool {
    sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
        .bind(holder)
        .bind(blocked)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Waits, without sleeping, until the backend `blocked` waits for a lock
/// held by `holder`.
async fn wait_until_blocked(pool: &PgPool, blocked: i32, holder: i32) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !is_blocked(pool, blocked, holder).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the second transaction never waited for the first");
}

/// Waits, without sleeping, until the backend `blocked` of `task` waits
/// for a lock held by `holder` (`true`), or `task` ends without having
/// waited (`false`).
async fn waits_for<T>(
    pool: &PgPool,
    blocked: i32,
    holder: i32,
    task: &tokio::task::JoinHandle<T>,
) -> bool {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if is_blocked(pool, blocked, holder).await {
                return true;
            }
            if task.is_finished() {
                return false;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the task neither waited nor ended")
}

/// Step 3 locks the challenge row before it checks it: a restore waits for
/// a transaction that is revoking the challenge, then checks the row as
/// committed and is `Revoked` (it would pass the check on the old row and
/// miss only in the consume without the lock); after a rollback it
/// restores.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_checks_its_challenge_under_the_row_lock() {
    for commit in [true, false] {
        let (db, pool) = issued().await;
        issue(&pool, "op_2", "aud_issue_2").await;
        let mut first = pool.acquire().await.unwrap().detach();
        let mut second = pool.acquire().await.unwrap().detach();
        let (first_pid, second_pid) = (
            backend_pid(&mut first).await,
            backend_pid(&mut second).await,
        );
        let mut transaction = first.begin().await.unwrap();
        raw_revoke(&mut transaction, "op_1", "op_2").await;
        let signature = signature_by(&mut second, "op_1", &SEED).await;
        let waiting = tokio::spawn(async move {
            let mut other = second.begin().await.unwrap();
            let restored = restore_operator(
                &mut other,
                &response("op_1", &signature),
                &restore_request(),
            )
            .await;
            if restored.is_ok() {
                other.commit().await.unwrap();
            } else {
                other.rollback().await.unwrap();
            }
            second.close().await.unwrap();
            restored
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        if commit {
            transaction.commit().await.unwrap();
        } else {
            transaction.rollback().await.unwrap();
        }
        first.close().await.unwrap();
        let outcome = waiting.await.unwrap();
        if commit {
            assert_not_restorable(outcome, NotRestorableReason::Revoked);
            assert_eq!(pool_operation(&pool, "op_1").await.consumed_us, None);
        } else {
            assert_eq!(outcome.unwrap().recovery_key_epoch, 2);
        }
        db.drop([pool]).await;
    }
}

/// Two restores of one challenge: the second waits for the first (on the
/// credentials it locked); after the first commits it is `Consumed`, after
/// a rollback it restores.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn of_two_concurrent_restores_of_one_challenge_exactly_one_wins() {
    for commit in [true, false] {
        let (db, pool) = issued().await;
        let mut first = pool.acquire().await.unwrap().detach();
        let mut second = pool.acquire().await.unwrap().detach();
        let (first_pid, second_pid) = (
            backend_pid(&mut first).await,
            backend_pid(&mut second).await,
        );
        let mut transaction = first.begin().await.unwrap();
        consume_and_restore(&mut transaction, "op_1").await.unwrap();
        let later = now() + Duration::from_secs(1);
        let waiting = tokio::spawn(async move {
            let mut other = second.begin().await.unwrap();
            let mut request = restore_request();
            request.now = later;
            let restored = restore_in(&mut other, "op_1", &request).await;
            if restored.is_ok() {
                other.commit().await.unwrap();
            } else {
                other.rollback().await.unwrap();
            }
            second.close().await.unwrap();
            restored
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        if commit {
            transaction.commit().await.unwrap();
        } else {
            transaction.rollback().await.unwrap();
        }
        first.close().await.unwrap();
        let outcome = waiting.await.unwrap();
        let row = pool_operation(&pool, "op_1").await;
        let winner = if commit {
            assert_not_restorable(outcome, NotRestorableReason::Consumed);
            now()
        } else {
            let restored = outcome.unwrap();
            assert_eq!(restored.audit_event.timestamp, later);
            later
        };
        assert_eq!(
            (row.consumed_us, row.revision, &row.outcome[..]),
            (Some(micros(winner)), 3, "restored")
        );
        let state = get_recovery_state(&pool).await.unwrap().unwrap();
        assert_eq!((state.recovery_key_epoch, state.revision), (2, 2));
        assert_eq!(
            verify(&pool).await,
            ChainVerdict::Intact { last_sequence: 4 }
        );
        db.drop([pool]).await;
    }
}

/// Operators besides the bootstrap one: `adm_two` (enabled) with an
/// enabled, a disabled unrevoked and a revoked credential, an instance
/// `security_admin` and a tenant `trust_admin` binding; `adm_three`
/// (disabled) with an enabled credential and an instance `auditor`
/// binding.
async fn more_operators(pool: &PgPool) {
    registry::create_tenant(
        pool,
        &NewTenant {
            id: "ten_a".into(),
            name: "Tenant A".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (id, status) in [
        ("adm_two", Status::Enabled),
        ("adm_three", Status::Disabled),
    ] {
        registry::test_support::create_admin_identity(
            pool,
            &NewAdminIdentity {
                id: id.into(),
                status,
                created_at: at(100),
            },
        )
        .await
        .unwrap();
    }
    for (id, admin, status) in [
        ("crd_two_a", "adm_two", Status::Enabled),
        ("crd_two_b", "adm_two", Status::Disabled),
        ("crd_two_c", "adm_two", Status::Enabled),
        ("crd_three", "adm_three", Status::Enabled),
    ] {
        registry::test_support::create_admin_credential(
            pool,
            &NewAdminCredential {
                id: id.into(),
                admin_id: admin.into(),
                public_identity: format!("spki-sha256:{id}"),
                trust_anchor_ref: "deployment/operator-ca".into(),
                status,
            },
        )
        .await
        .unwrap();
    }
    registry::revoke_admin_credential(pool, "crd_two_c", at(500))
        .await
        .unwrap();
    for (id, admin, role, tenant) in [
        ("rb_two", "adm_two", AdminRole::SecurityAdmin, None),
        (
            "rb_two_ten",
            "adm_two",
            AdminRole::TrustAdmin,
            Some("ten_a"),
        ),
        ("rb_three", "adm_three", AdminRole::Auditor, None),
    ] {
        registry::test_support::create_admin_role_binding(
            pool,
            &NewAdminRoleBinding {
                id: id.into(),
                admin_id: admin.into(),
                role,
                tenant_id: tenant.map(Into::into),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
}

/// The full restoration: a replacement `security_admin` that authorizes,
/// every unrevoked credential revoked at `now` (the replaced operator's
/// included), the revoked one untouched, identities and bindings unchanged,
/// the key rotated to epoch 2, the operation restored, both events exact
/// and the chain intact; the old epoch is refused afterwards and the new
/// one works.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_enrolls_a_replacement_revokes_every_credential_and_rotates_the_key() {
    let (db, pool) = bootstrapped().await;
    more_operators(&pool).await;
    let issue_event = issue(&pool, "op_1", "aud_issue_1").await.audit_event;
    let last_issue = issue(&pool, "op_2", "aud_issue_2").await.audit_event;
    let identities_before: Vec<(String, String)> =
        sqlx::query_as("SELECT id, status FROM admin_identity ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let bindings_before: Vec<String> =
        sqlx::query_scalar("SELECT b::text FROM admin_role_binding b ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let operation_before = pool_operation(&pool, "op_1").await;

    let mut transaction = pool.begin().await.unwrap();
    let restored = consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.commit().await.unwrap();

    assert_eq!(
        (
            &restored.admin_id[..],
            &restored.credential_id[..],
            &restored.binding_id[..],
            &restored.revoked_credential_ids[..],
            restored.recovery_key_epoch,
            restored.recovery_state_revision,
        ),
        (
            "adm_new",
            "crd_new",
            "rb_new",
            &["crd_first", "crd_three", "crd_two_a", "crd_two_b"].map(String::from)[..],
            2,
            2,
        )
    );
    // Every previously unrevoked credential, enabled or not, is revoked at
    // `now`; the one revoked before keeps its time.
    for id in ["crd_first", "crd_three", "crd_two_a", "crd_two_b"] {
        let credential = registry::get_admin_credential(&pool, id).await.unwrap();
        assert_eq!(
            (credential.status, credential.revoked_at),
            (Status::Disabled, Some(now())),
            "{id}"
        );
    }
    let earlier = registry::get_admin_credential(&pool, "crd_two_c")
        .await
        .unwrap();
    assert_eq!(
        (earlier.status, earlier.revoked_at),
        (Status::Disabled, Some(at(500)))
    );
    // The replacement: enabled, unrevoked, an instance security_admin.
    let identity = registry::get_admin_identity(&pool, "adm_new")
        .await
        .unwrap();
    assert_eq!(
        (identity.status, identity.created_at),
        (Status::Enabled, now())
    );
    let credential = registry::get_admin_credential(&pool, "crd_new")
        .await
        .unwrap();
    assert_eq!(
        (
            &credential.admin_id[..],
            &credential.public_identity[..],
            &credential.trust_anchor_ref[..],
            credential.status,
            credential.revoked_at
        ),
        (
            "adm_new",
            "spki-sha256:new",
            "deployment/operator-ca",
            Status::Enabled,
            None
        )
    );
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:new").await,
        Some(AuthorizedOperator {
            admin_id: "adm_new".into(),
            credential_id: "crd_new".into(),
            binding_id: "rb_new".into(),
            role: AdminRole::SecurityAdmin,
        })
    );
    for key in ["spki-sha256:first", "spki-sha256:crd_two_a"] {
        assert_eq!(authorize_security_admin(&pool, key).await, None, "{key}");
    }
    // Identities and the bindings that existed are unchanged.
    let identities_after: Vec<(String, String)> =
        sqlx::query_as("SELECT id, status FROM admin_identity WHERE id <> 'adm_new' ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(identities_after, identities_before);
    let bindings_after: Vec<String> = sqlx::query_scalar(
        "SELECT b::text FROM admin_role_binding b WHERE id <> 'rb_new' ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(bindings_after, bindings_before);
    let role_binding = registry::get_admin_role_binding(&pool, "rb_new")
        .await
        .unwrap();
    assert_eq!(
        (
            &role_binding.admin_id[..],
            role_binding.role,
            role_binding.tenant_id,
            role_binding.status,
            role_binding.revision
        ),
        (
            "adm_new",
            AdminRole::SecurityAdmin,
            None,
            Status::Enabled,
            1
        )
    );
    // The key is rotated and the used one retired.
    assert_eq!(
        get_recovery_state(&pool).await.unwrap(),
        Some(RecoveryState {
            instance_id: INSTANCE.into(),
            bootstrap_closed: true,
            recovery_public_key: NEW_KEY.to_vec(),
            recovery_key_epoch: 2,
            revision: 2,
        })
    );
    // The operation: consumed at `now`, restored, at revision 3.
    assert_eq!(
        pool_operation(&pool, "op_1").await,
        Operation {
            consumed_us: Some(micros(now())),
            revision: 3,
            outcome: "restored".into(),
            ..operation_before
        }
    );
    // The events, by the key that signed (epoch 1), last in the chain: the
    // restore, then the rotation.
    let event = &restored.audit_event;
    let rotation = &restored.rotation_audit_event;
    assert_eq!(
        (
            &event.id[..],
            event.tenant_id.as_deref(),
            event.sequence,
            event.prev_hash,
            event.timestamp,
            &event.actor,
            &event.action[..],
            &event.object_id[..],
            event.previous_revision,
            event.new_revision,
            &event.outcome[..],
        ),
        (
            "aud_restore",
            None,
            4,
            Some(last_issue.hash),
            now(),
            &AuditActor::Operator("recovery_key:1".into()),
            "admin_identity.restore",
            "adm_new",
            None,
            None,
            "success",
        )
    );
    assert_eq!(
        (
            &rotation.id[..],
            rotation.tenant_id.as_deref(),
            rotation.sequence,
            rotation.prev_hash,
            rotation.timestamp,
            &rotation.actor,
            &rotation.action[..],
            &rotation.object_id[..],
            rotation.previous_revision,
            rotation.new_revision,
            &rotation.outcome[..],
        ),
        (
            "aud_rotate",
            None,
            5,
            Some(event.hash),
            now(),
            &AuditActor::Operator("recovery_key:1".into()),
            "recovery_state.rotate_key",
            INSTANCE,
            Some(1),
            Some(2),
            "success",
        )
    );
    assert_eq!(issue_event.sequence, 2);
    assert_eq!(event.compute_hash().unwrap(), event.hash);
    assert_eq!(rotation.compute_hash().unwrap(), rotation.hash);
    let stored: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT id, actor, sequence FROM audit_event WHERE sequence > 3 ORDER BY sequence",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let actor = r#"{"id":"recovery_key:1","type":"operator"}"#;
    assert_eq!(
        stored,
        [
            ("aud_restore".into(), actor.into(), 4),
            ("aud_rotate".into(), actor.into(), 5)
        ]
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );

    // A challenge issued before, at the retired epoch, is refused, signed
    // by the retired key or the new one.
    for seed in [&SEED, &NEW_SEED] {
        let signature = signature_by(&mut pool.acquire().await.unwrap(), "op_2", seed).await;
        assert_refused(
            &pool,
            "op_2",
            &signature,
            now(),
            NotRestorableReason::NotBound,
        )
        .await;
    }
    // A challenge of the new epoch works, signed by the new key.
    let plan = plan_for(INSTANCE, json!(2), &other(&THIRD_KEY));
    let challenge = issue_on(&pool, &issue_request("op_3", "aud_issue_3", &plan))
        .await
        .unwrap();
    assert_eq!(challenge.expected_revision, 2);
    let request = RestoreRequest {
        audit_event_id: "aud_other",
        rotation_audit_event_id: "aud_other_rotate",
        now: now(),
    };
    let again = restore_by(&pool, "op_3", &NEW_SEED, &request)
        .await
        .unwrap();
    assert_eq!(
        (
            again.recovery_key_epoch,
            &again.audit_event.actor,
            &again.revoked_credential_ids[..]
        ),
        (
            3,
            &AuditActor::Operator("recovery_key:2".into()),
            &["crd_new".to_owned()][..]
        )
    );
    db.drop([pool]).await;
}

/// The tables a restore writes, and no other: every row of every other
/// table is the same before and after.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_changes_nothing_else() {
    let (db, pool) = bootstrapped().await;
    more_operators(&pool).await;
    registry::create_principal(
        &pool,
        &NewPrincipal {
            id: "prn_a".into(),
            tenant_id: "ten_a".into(),
            kind: PrincipalKind::Workload,
            name: "workload a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    issue(&pool, "op_1", "aud_issue_1").await;
    issue(&pool, "op_2", "aud_issue_2").await;
    let before = pool_snapshot(&pool).await;
    let mut transaction = pool.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.commit().await.unwrap();
    let after = pool_snapshot(&pool).await;
    let changed: Vec<&str> = before
        .keys()
        .filter(|table| before[*table] != after[*table])
        .map(String::as_str)
        .collect();
    assert_eq!(
        changed,
        [
            "admin_credential",
            "admin_identity",
            "admin_role_binding",
            "administrative_operation",
            "audit_chain_head",
            "audit_event",
            "recovery_state",
        ]
    );
    // Rows are added to these and none is removed.
    for (table, added) in [
        ("admin_identity", 1),
        ("admin_credential", 1),
        ("admin_role_binding", 1),
        ("audit_event", 2),
        ("administrative_operation", 0),
        ("recovery_state", 0),
        ("audit_chain_head", 0),
    ] {
        assert_eq!(after[table].len(), before[table].len() + added, "{table}");
    }
    // Of the operations only op_1 changed.
    let unchanged: Vec<_> = after["administrative_operation"]
        .iter()
        .filter(|row| before["administrative_operation"].contains(row))
        .collect();
    assert_eq!(unchanged.len(), 1);
    assert!(unchanged[0].starts_with("(op_2,"), "{unchanged:?}");
    db.drop([pool]).await;
}

/// A restore that fails after its consume, on a statement or in Rust after
/// the audit head lock, rolls its savepoint back, the consume included: a
/// caller that commits after the `Err` commits nothing of it, and the
/// challenge stays restorable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_restore_commits_nothing_even_when_the_caller_commits() {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    // A statement fails: an event ID is taken (`23505` from the writer),
    // the first event's, the second's, or the second is the first's.
    for (restore_id, rotation_id) in [
        ("aud_issue_1", "aud_rotate"),
        ("aud_restore", "aud_bootstrap"),
        ("aud_restore", "aud_restore"),
    ] {
        let mut transaction = pool.begin().await.unwrap();
        let mut request = restore_request();
        request.audit_event_id = restore_id;
        request.rotation_audit_event_id = rotation_id;
        assert_restore_exists(
            restore_in(&mut transaction, "op_1", &request).await,
            "audit_event_pkey",
        );
        // The transaction is usable and its commit writes nothing.
        sqlx::query("SELECT 1")
            .execute(&mut *transaction)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        assert_eq!(pool_snapshot(&pool).await, before, "{restore_id}");
    }

    // The writer refuses in Rust after the head lock: the next sequence
    // would be above 2^53 - 1, for the first event or only for the second.
    let head: Vec<u8> = sqlx::query_scalar("SELECT head_hash FROM audit_chain_head")
        .fetch_one(&pool)
        .await
        .unwrap();
    for sequence in [9_007_199_254_740_991_i64, 9_007_199_254_740_990] {
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
             UPDATE audit_chain_head SET sequence = {sequence}; \
             ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER audit_chain_head_advance"
        )))
        .execute(&pool)
        .await
        .unwrap();
        let before = pool_snapshot(&pool).await;
        let mut transaction = pool.begin().await.unwrap();
        match restore_in(&mut transaction, "op_1", &restore_request()).await {
            Err(RestoreError::Store(RegistryError::Other(sqlx::Error::Encode(_)))) => {}
            other => panic!("expected the writer's encode error: {other:?}"),
        }
        transaction.commit().await.unwrap();
        assert_eq!(pool_snapshot(&pool).await, before, "{sequence}");
    }
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!((row.consumed_us, row.revision), (None, 1));
    let credential = registry::get_admin_credential(&pool, "crd_first")
        .await
        .unwrap();
    assert_eq!(
        (credential.status, credential.revoked_at),
        (Status::Enabled, None)
    );
    assert!(
        registry::get_admin_identity(&pool, "adm_new")
            .await
            .is_err()
    );
    assert_eq!(
        get_recovery_state(&pool)
            .await
            .unwrap()
            .unwrap()
            .recovery_key_epoch,
        1
    );

    // With the head back, the same request restores.
    sqlx::raw_sql(
        "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
         UPDATE audit_chain_head SET sequence = 2; \
         ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER audit_chain_head_advance",
    )
    .execute(&pool)
    .await
    .unwrap();
    let restored: Vec<u8> = sqlx::query_scalar("SELECT head_hash FROM audit_chain_head")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(restored, head);
    let mut transaction = pool.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(pool_operation(&pool, "op_1").await.outcome, "restored");
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 4 }
    );
    db.drop([pool]).await;
}

/// An issue whose operation ID is taken fails after its audit event and
/// rolls the event back with its savepoint; a caller that commits after
/// the `Err` commits nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_issue_commits_nothing_even_when_the_caller_commits() {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    let plan = good_plan();
    let mut transaction = pool.begin().await.unwrap();
    match issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_1", "aud_issue_2", &plan),
    )
    .await
    {
        Err(ChallengeError::Store(RegistryError::AlreadyExists { constraint })) => {
            assert_eq!(constraint, "administrative_operation_pkey")
        }
        other => panic!("expected AlreadyExists: {other:?}"),
    }
    sqlx::query("SELECT 1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// Whether the backend `pid` holds or waits for any lock on `table`.
async fn locks_on(pool: &PgPool, pid: i32, table: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM pg_locks WHERE pid = $1 AND relation = $2::regclass)",
    )
    .bind(pid)
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Sets the chain head's sequence by other means, keeping its hash.
async fn set_head_sequence(pool: &PgPool, sequence: i64) {
    sqlx::raw_sql(AssertSqlSafe(format!(
        "ALTER TABLE audit_chain_head DISABLE TRIGGER audit_chain_head_advance; \
         UPDATE audit_chain_head SET sequence = {sequence}; \
         ALTER TABLE audit_chain_head ENABLE ALWAYS TRIGGER audit_chain_head_advance"
    )))
    .execute(pool)
    .await
    .unwrap();
}

/// An issue that fails in Rust after the audit head lock (a head at
/// `2^53 - 1` leaves no sequence for its event) rolls its savepoint back,
/// not releases it. The issue writes no row before that error, so what the
/// savepoint holds is its locks: once the `Err` is returned the caller's
/// transaction holds none of them (the recovery state `FOR SHARE`, the
/// chain head `FOR UPDATE`), and another transaction takes both at once.
/// The locks must already be released when the function returns (intended:
/// the audit head is a global serialization point, so no other transaction
/// may wait behind a caller whose issue has already failed), so a variant
/// that leaves sqlx to queue the rollback, which only runs at the
/// connection's next use, also fails here. A caller that commits after the `Err` commits nothing of the issue, and
/// with the head back the same request issues.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_issue_that_fails_after_the_head_lock_rolls_its_savepoint_back() {
    let (db, pool) = bootstrapped().await;
    set_head_sequence(&pool, 9_007_199_254_740_991).await;
    let before = pool_snapshot(&pool).await;
    let plan = good_plan();
    let request = issue_request("op_1", "aud_issue_1", &plan);

    let mut connection = pool.acquire().await.unwrap();
    let pid = backend_pid(&mut connection).await;
    let mut transaction = connection.begin().await.unwrap();
    assert_issue_encode(
        issue_recovery_challenge(&mut transaction, &request).await,
        "audit integer above 2^53 - 1",
    );
    // The locks went with the savepoint: a released savepoint would hand
    // them to the caller's transaction until it ends.
    for table in ["recovery_state", "audit_chain_head"] {
        assert!(!locks_on(&pool, pid, table).await, "{table}");
    }
    let mut other = pool.begin().await.unwrap();
    for statement in [
        "SELECT 1 FROM recovery_state FOR UPDATE NOWAIT",
        "SELECT 1 FROM audit_chain_head FOR UPDATE NOWAIT",
    ] {
        sqlx::query(statement)
            .execute(&mut *other)
            .await
            .unwrap_or_else(|err| panic!("{statement}: {err}"));
    }
    other.rollback().await.unwrap();
    // The transaction is usable, sees nothing of the issue, and its commit
    // writes nothing.
    assert_eq!(counts(&mut transaction).await, [0, 1, 1]);
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(pool_snapshot(&pool).await, before);

    // With the head back, the same request issues.
    set_head_sequence(&pool, 1).await;
    let challenge = issue_on(&pool, &request).await.unwrap();
    assert_eq!(
        (
            challenge.operation_id.as_str(),
            challenge.audit_event.sequence
        ),
        ("op_1", 2)
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 2 }
    );
    db.drop([pool]).await;
}

/// A restore whose consume fails (here on a lock timeout, while another
/// transaction holds the operation row) rolls its savepoint back: the
/// caller's transaction stays usable and commits nothing of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_that_times_out_leaves_the_transaction_usable() {
    let (db, pool) = issued().await;
    let mut holder = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM administrative_operation WHERE id = 'op_1' FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let before = pool_snapshot(&pool).await;
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '50ms'")
        .execute(&mut *transaction)
        .await
        .unwrap();
    match restore_in(&mut transaction, "op_1", &restore_request()).await {
        Err(RestoreError::Store(RegistryError::Other(err))) => {
            let code = err
                .as_database_error()
                .unwrap()
                .code()
                .unwrap()
                .into_owned();
            assert_eq!(code, "55P03");
        }
        other => panic!("expected a lock timeout: {other:?}"),
    }
    sqlx::query("SELECT 1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    holder.rollback().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    restore_on(&pool, "op_1", &restore_request()).await.unwrap();
    db.drop([pool]).await;
}

/// The replacement's IDs, credential identity and the event IDs must be
/// new: each collision is the insert's or the writer's `AlreadyExists`
/// with its constraint, and the savepoint is rolled back, the consume
/// included, also when the caller commits. Each challenge names the
/// colliding replacement.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_colliding_replacement_is_already_exists() {
    let (db, pool) = issued().await;
    let cases: [(&str, Replacement<'static>, &str); 5] = [
        (
            "op_admin",
            Replacement {
                admin_id: "adm_first",
                ..NEW
            },
            "admin_identity_pkey",
        ),
        (
            "op_credential",
            Replacement {
                credential_id: "crd_first",
                ..NEW
            },
            "admin_credential_pkey",
        ),
        (
            "op_binding",
            Replacement {
                binding_id: "rb_first",
                ..NEW
            },
            "admin_role_binding_pkey",
        ),
        (
            "op_identity",
            Replacement {
                public_identity: "spki-sha256:first",
                ..NEW
            },
            "admin_credential_public_identity_key",
        ),
        (
            "op_both",
            Replacement {
                credential_id: "crd_first",
                public_identity: "spki-sha256:first",
                ..NEW
            },
            // Both credential keys taken: the ID is named.
            "admin_credential_pkey",
        ),
    ];
    for (index, (id, replacement, constraint)) in cases.into_iter().enumerate() {
        let plan = plan_for(INSTANCE, json!(1), &replacement);
        let audit = format!("aud_issue_{id}");
        issue_on(&pool, &issue_request(id, &audit, &plan))
            .await
            .unwrap();
        let before = pool_snapshot(&pool).await;
        let mut transaction = pool.begin().await.unwrap();
        assert_restore_exists(
            restore_in(&mut transaction, id, &restore_request()).await,
            constraint,
        );
        transaction.commit().await.unwrap();
        assert_eq!(pool_snapshot(&pool).await, before, "{index} {constraint}");
    }
    let before = pool_snapshot(&pool).await;
    let mut transaction = pool.begin().await.unwrap();
    let mut request = restore_request();
    request.audit_event_id = "aud_bootstrap";
    assert_restore_exists(
        restore_in(&mut transaction, "op_1", &request).await,
        "audit_event_pkey",
    );
    transaction.commit().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A stored plan that the issue would refuse (a row written by other
/// means, encoded and signed as the library would) is refused at step 5,
/// at the preview and the restore: a new key equal to the current one is
/// `RecoveryKeyUnchanged`, a reserved admin ID `ReservedActorId`, and a new
/// key that is not a canonical point of large order or not in hexadecimal,
/// a member other than the eight, or an empty public identity an encode
/// error. A time outside the audit years is an encode error before any
/// statement. None leaves anything written, and the transaction stays
/// usable for a good restore.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_refused_restore_leaves_nothing_written() {
    let (db, pool) = issued().await;
    let with = |name: &str, value: Value| {
        let mut plan = good_plan();
        plan.insert(name.into(), value);
        json!(plan)
    };
    let rows = [
        (
            "raw_same",
            json!(plan_for(INSTANCE, json!(1), &other(&KEY))),
        ),
        (
            "raw_reserved",
            with("admin_id", json!("deployment_operator")),
        ),
        (
            "raw_recovery_actor",
            with("admin_id", json!("recovery_key:2")),
        ),
        (
            "raw_small_order",
            json!(plan_for(INSTANCE, json!(1), &other(&IDENTITY))),
        ),
        (
            "raw_non_canonical",
            json!(plan_for(INSTANCE, json!(1), &other(&LARGE_P_PLUS_3))),
        ),
        (
            "raw_undecodable",
            json!(plan_for(INSTANCE, json!(1), &other(&UNDECODABLE))),
        ),
        (
            "raw_upper_key",
            with(
                "new_recovery_public_key",
                json!(hex(&NEW_KEY).to_uppercase()),
            ),
        ),
        (
            "raw_extra",
            with("operation", json!("operator_restoration")),
        ),
        ("raw_empty_identity", with("public_identity", json!(""))),
    ];
    let mut signatures = BTreeMap::new();
    for (id, plan) in rows {
        insert_raw(&pool, id, OPERATOR_RESTORATION, plan, Stored::Library, 1).await;
        signatures.insert(
            id,
            signature_by(&mut pool.acquire().await.unwrap(), id, &SEED).await,
        );
    }
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    let before = snapshot(&mut transaction).await;

    let same = response("raw_same", &signatures["raw_same"]);
    for result in [
        preview_recovery_response(&mut transaction, &same, now())
            .await
            .map(|_| ()),
        restore_operator(&mut transaction, &same, &restore_request())
            .await
            .map(|_| ()),
    ] {
        match result {
            Err(err @ RestoreError::RecoveryKeyUnchanged) => {
                assert_eq!(format!("{err:?}"), "RecoveryKeyUnchanged");
                assert_eq!(
                    err.to_string(),
                    "the new recovery public key is the current one"
                );
            }
            other => panic!("expected RecoveryKeyUnchanged: {other:?}"),
        }
    }
    assert_eq!(snapshot(&mut transaction).await, before);
    for id in ["raw_reserved", "raw_recovery_actor"] {
        let presented = response(id, &signatures[id]);
        for result in [
            preview_recovery_response(&mut transaction, &presented, now())
                .await
                .map(|_| ()),
            restore_operator(&mut transaction, &presented, &restore_request())
                .await
                .map(|_| ()),
        ] {
            match result {
                Err(RestoreError::Store(RegistryError::ReservedActorId)) => {}
                other => panic!("{id}: expected ReservedActorId: {other:?}"),
            }
        }
    }
    for (id, message) in [
        (
            "raw_small_order",
            "recovery public key is a small-order Ed25519 point",
        ),
        (
            "raw_non_canonical",
            "recovery public key is not canonically encoded",
        ),
        (
            "raw_undecodable",
            "recovery public key is not an Ed25519 point",
        ),
        (
            "raw_upper_key",
            "plan new_recovery_public_key is not 64 lowercase hexadecimal digits",
        ),
        (
            "raw_extra",
            "plan has a member other than the eight of an operator restoration",
        ),
        (
            "raw_empty_identity",
            "public identity is empty or over 2048 bytes",
        ),
    ] {
        let presented = response(id, &signatures[id]);
        assert_restore_encode(
            preview_recovery_response(&mut transaction, &presented, now()).await,
            message,
        );
        assert_restore_encode(
            restore_operator(&mut transaction, &presented, &restore_request()).await,
            message,
        );
    }
    let mut request = restore_request();
    request.now = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    assert_restore_encode(
        restore_in(&mut transaction, "op_1", &request).await,
        "audit timestamp outside the years 0000 to 9999",
    );
    assert_eq!(snapshot(&mut transaction).await, before);

    let restored = restore_in(&mut transaction, "op_1", &restore_request())
        .await
        .unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    transaction.commit().await.unwrap();
    drop(connection);
    assert_eq!(
        get_recovery_state(&pool)
            .await
            .unwrap()
            .map(|state| state.recovery_public_key),
        Some(NEW_KEY.to_vec())
    );
    db.drop([pool]).await;
}

/// A restore checks the challenge against the recovery state it locked,
/// in its transaction: a state whose revision moved after the issue is
/// `NotBound`, and one whose `bootstrap_closed` is false (written by other
/// means) is `NoRecoveryState`, at the preview and the restore; nothing is
/// left written. A second restore of the restored operation is `Consumed`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_needs_the_current_closed_recovery_state() {
    let (db, pool) = issued().await;
    let committed = pool_snapshot(&pool).await;
    // The recovery state left open, by other means; the guards that would
    // refuse that write are off only inside the test's transaction.
    let reopen = "ALTER TABLE recovery_state DISABLE TRIGGER USER; \
                  UPDATE recovery_state SET bootstrap_closed = false; \
                  ALTER TABLE recovery_state ENABLE TRIGGER USER";
    for (statement, reason) in [
        (
            "UPDATE recovery_state SET revision = revision + 1",
            NotRestorableReason::NotBound,
        ),
        (reopen, NotRestorableReason::NoRecoveryState),
    ] {
        let mut connection = pool.acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        sqlx::raw_sql(AssertSqlSafe(statement))
            .execute(&mut *transaction)
            .await
            .unwrap();
        let before = snapshot(&mut transaction).await;
        let signature = signature_by(&mut transaction, "op_1", &SEED).await;
        assert_not_restorable(
            preview_recovery_response(&mut transaction, &response("op_1", &signature), now()).await,
            reason,
        );
        assert_not_restorable(
            restore_in(&mut transaction, "op_1", &restore_request()).await,
            reason,
        );
        assert_eq!(snapshot(&mut transaction).await, before, "{reason:?}");
        transaction.rollback().await.unwrap();
    }
    assert_eq!(pool_snapshot(&pool).await, committed);

    // The control, with every value right; then a second restore of the
    // restored operation.
    restore_on(&pool, "op_1", &restore_request()).await.unwrap();
    let restored = pool_snapshot(&pool).await;
    let request = RestoreRequest {
        audit_event_id: "aud_again",
        rotation_audit_event_id: "aud_again_rotate",
        now: now(),
    };
    assert_not_restorable(
        restore_by(&pool, "op_1", &NEW_SEED, &request).await,
        NotRestorableReason::Consumed,
    );
    assert_eq!(pool_snapshot(&pool).await, restored);
    db.drop([pool]).await;
}

/// A restore and an issue wait for each other on the recovery state, in
/// either order, without a deadlock: an issue after a restore sees the new
/// epoch, and a restore after an issue retires the issued challenge's
/// epoch. Of two concurrent restores (of two challenges) the second is
/// `NotBound`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_and_an_issue_wait_for_each_other() {
    // The restore first.
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    let waiting = tokio::spawn(async move {
        let plan = good_plan();
        let mut other = second.begin().await.unwrap();
        let issued =
            issue_recovery_challenge(&mut other, &issue_request("op_2", "aud_issue_2", &plan))
                .await;
        other.rollback().await.unwrap();
        second.close().await.unwrap();
        issued
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_not_issuable(waiting.await.unwrap());
    // The new epoch's plan names a key other than the one now current.
    let plan = plan_for(INSTANCE, json!(2), &other(&THIRD_KEY));
    issue_on(&pool, &issue_request("op_2", "aud_issue_2", &plan))
        .await
        .unwrap();
    db.drop([pool]).await;

    // The issue first.
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let plan = good_plan();
    let mut transaction = first.begin().await.unwrap();
    issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_2", "aud_issue_2", &plan),
    )
    .await
    .unwrap();
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        other.commit().await.unwrap();
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = waiting.await.unwrap().unwrap();
    assert_eq!(
        (
            restored.recovery_key_epoch,
            restored.audit_event.sequence,
            restored.rotation_audit_event.sequence
        ),
        (2, 4, 5)
    );
    assert_refused_signed(&pool, "op_2", now(), NotRestorableReason::NotBound).await;
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );
    db.drop([pool]).await;

    // Two restores.
    let (db, pool) = issued().await;
    let plan = plan_for(INSTANCE, json!(1), &other(&THIRD_KEY));
    issue_on(&pool, &issue_request("op_2", "aud_issue_2", &plan))
        .await
        .unwrap();
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    consume_and_restore(&mut transaction, "op_1").await.unwrap();
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let request = RestoreRequest {
            audit_event_id: "aud_other",
            rotation_audit_event_id: "aud_other_rotate",
            now: now(),
        };
        let restored = restore_in(&mut other, "op_2", &request).await;
        other.rollback().await.unwrap();
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_not_restorable(waiting.await.unwrap(), NotRestorableReason::NotBound);
    assert_eq!(
        get_recovery_state(&pool)
            .await
            .unwrap()
            .map(|state| (state.recovery_public_key, state.recovery_key_epoch)),
        Some((NEW_KEY.to_vec(), 2))
    );
    assert_eq!(pool_operation(&pool, "op_2").await.consumed_us, None);
    db.drop([pool]).await;
}

/// A restoration takes the audit chain head after the recovery state: an
/// issue that has read the recovery state (step 1) while a restoration
/// waits for that row still appends its event and commits, with no
/// deadlock, and the restoration then goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_waiting_for_the_recovery_state_holds_no_audit_head() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    // An issue's step 1, as it holds the row.
    sqlx::query("SELECT instance_id FROM recovery_state FOR SHARE")
        .execute(&mut *transaction)
        .await
        .unwrap();
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let plan = good_plan();
    let challenge = issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_2", "aud_issue_2", &plan),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_eq!(challenge.audit_event.sequence, 3);
    let restored = waiting.await.unwrap().unwrap();
    assert_eq!(
        (
            restored.audit_event.sequence,
            restored.rotation_audit_event.sequence
        ),
        (4, 5)
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );
    db.drop([pool]).await;
}

/// A restoration appends its events after its writes, holding no audit
/// head while it waits for one of them (here for a replacement ID another
/// transaction is inserting): that transaction can still append an event
/// and commit, with no deadlock, and the restoration then finds the ID
/// taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_appends_its_events_after_its_writes() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO admin_identity (id, status, created_at) \
         VALUES ('adm_new', 'enabled', timestamptz 'epoch')",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        other.rollback().await.unwrap();
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let event = registry::test_support::append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: "aud_other_write".into(),
            tenant_id: None,
            timestamp: now(),
            actor: AuditActor::Operator("adm_first".into()),
            action: "admin_identity.create".into(),
            object_id: "adm_new".into(),
            previous_revision: None,
            new_revision: None,
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(event.sequence, 3);
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    assert_restore_exists(restoring.await.unwrap(), "admin_identity_pkey");
    let row = pool_operation(&pool, "op_1").await;
    assert_eq!((row.consumed_us, row.revision), (None, 1));
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:first")
            .await
            .map(|a| a.credential_id),
        Some("crd_first".into())
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 3 }
    );
    db.drop([pool]).await;
}

/// A plan's `instance_id` must be a JSON string, also where its text would
/// match: with a recovery state for the instance `12345` (written by other
/// means), a plan naming the number `12345` is not restorable, and one
/// naming the string is.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_plan_instance_is_a_json_string() {
    let (db, pool) = migrated().await;
    sqlx::raw_sql(
        "INSERT INTO instance_security_policy (instance_id) VALUES ('12345'); \
         INSERT INTO recovery_state (instance_id, bootstrap_closed, recovery_public_key, \
         recovery_key_epoch) VALUES ('12345', true, \
         '\\xc050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let string = plan_for("12345", json!(1), &NEW);
    issue_on(&pool, &issue_request("op_1", "aud_issue_1", &string))
        .await
        .unwrap();
    let mut number = string.clone();
    number.insert("instance_id".into(), json!(12345));
    insert_raw(
        &pool,
        "raw_number",
        OPERATOR_RESTORATION,
        json!(number),
        Stored::Library,
        1,
    )
    .await;

    assert_refused_signed(&pool, "raw_number", now(), NotRestorableReason::NotBound).await;
    restore_on(&pool, "op_1", &restore_request()).await.unwrap();
    db.drop([pool]).await;
}

/// Before bootstrap there is no recovery state, so nothing is restorable,
/// at the preview or the restore.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn nothing_is_restorable_before_bootstrap() {
    let (db, pool) = migrated().await;
    assert_refused(
        &pool,
        "op_1",
        &sign(&SEED, b"any"),
        now(),
        NotRestorableReason::NoRecoveryState,
    )
    .await;
    db.drop([pool]).await;
}

/// A restoration locks the credentials before the recovery state (the
/// `0005` table order): while an operator write holds its credential
/// `FOR SHARE` (`authorize_operator_locked`), the restoration waits for it
/// holding nothing the write needs, so the write can still issue a
/// challenge and commit, with no deadlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_locks_the_credentials_before_the_recovery_state() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    let authorized =
        registry::authorize_operator_locked(&mut transaction, &security_admin("spki-sha256:first"))
            .await
            .unwrap();
    assert_eq!(
        authorized.map(|a| a.credential_id),
        Some("crd_first".into())
    );
    let waiting = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let plan = good_plan();
    issue_recovery_challenge(
        &mut transaction,
        &issue_request("op_2", "aud_issue_2", &plan),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = waiting.await.unwrap().unwrap();
    assert_eq!(restored.revoked_credential_ids, ["crd_first"]);
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 5 }
    );
    db.drop([pool]).await;
}

/// A restoration holds the recovery state from its check to the rotation:
/// an issue that starts while the restoration waits (here on a replacement
/// ID another transaction is inserting) waits for it, and after the
/// restoration commits it sees the new epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_holds_the_recovery_state_until_it_commits() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let mut third = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid, third_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
        backend_pid(&mut third).await,
    );
    let mut transaction = first.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO admin_identity (id, status, created_at) \
         VALUES ('adm_new', 'enabled', timestamptz 'epoch')",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let issuing = tokio::spawn(async move {
        let plan = good_plan();
        let mut other = third.begin().await.unwrap();
        let issued =
            issue_recovery_challenge(&mut other, &issue_request("op_2", "aud_issue_2", &plan))
                .await;
        if issued.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        third.close().await.unwrap();
        issued
    });
    wait_until_blocked(&pool, third_pid, second_pid).await;
    transaction.rollback().await.unwrap();
    first.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    assert_not_issuable(issuing.await.unwrap());
    db.drop([pool]).await;
}

/// The tenant `ten_a` and a disabled instance `auditor` binding `rb_off`
/// of `adm_first`, for the operator writes below.
async fn write_targets(pool: &PgPool) {
    registry::create_tenant(
        pool,
        &NewTenant {
            id: "ten_a".into(),
            name: "Tenant A".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: "rb_off".into(),
            admin_id: "adm_first".into(),
            role: AdminRole::Auditor,
            tenant_id: None,
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
}

/// The four operator writes that can add access, by index: an enabled
/// identity `adm_late`, an enabled credential `crd_late`
/// (`spki-sha256:late`) of `admin`, an enabled tenant `client_admin`
/// binding `rb_late` of `admin`, and `rb_off` re-enabled.
async fn operator_write(
    transaction: &mut Transaction<'_, Postgres>,
    write: usize,
    admin: &str,
) -> Result<(), RegistryError> {
    match write {
        0 => registry::test_support::create_admin_identity(
            &mut **transaction,
            &NewAdminIdentity {
                id: "adm_late".into(),
                status: Status::Enabled,
                created_at: now(),
            },
        )
        .await
        .map(drop),
        1 => registry::test_support::create_admin_credential(
            &mut **transaction,
            &NewAdminCredential {
                id: "crd_late".into(),
                admin_id: admin.into(),
                public_identity: "spki-sha256:late".into(),
                trust_anchor_ref: "deployment/operator-ca".into(),
                status: Status::Enabled,
            },
        )
        .await
        .map(drop),
        2 => registry::test_support::create_admin_role_binding(
            &mut **transaction,
            &NewAdminRoleBinding {
                id: "rb_late".into(),
                admin_id: admin.into(),
                role: AdminRole::ClientAdmin,
                tenant_id: Some("ten_a".into()),
                status: Status::Enabled,
            },
        )
        .await
        .map(drop),
        _ => registry::test_support::update_admin_role_binding(
            &mut **transaction,
            "rb_off",
            1,
            &AdminRoleBindingChanges {
                status: Status::Enabled,
            },
        )
        .await
        .map(drop),
    }
}

/// An enrollment that holds the recovery state (its credential insert)
/// when a restoration starts makes the restoration wait for its commit;
/// the restoration then revokes the enrolled credential with the others,
/// so it does not stay active.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_enrollment_that_commits_while_a_restore_waits_is_revoked() {
    let (db, pool) = issued().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    operator_write(&mut transaction, 1, "adm_first")
        .await
        .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    // The restoration began (its snapshot is older than the enrollment's
    // commit) and waits for the enrollment.
    assert!(waits_for(&pool, second_pid, first_pid, &restoring).await);
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.revoked_credential_ids, ["crd_first", "crd_late"]);
    let late = registry::get_admin_credential(&pool, "crd_late")
        .await
        .unwrap();
    assert_eq!(
        (late.status, late.revoked_at),
        (Status::Disabled, Some(now()))
    );
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:late").await,
        None
    );
    db.drop([pool]).await;
}

/// Each of the four writes that can add operator access waits for a
/// restoration that holds the recovery state, and the writer's lookup
/// after the write, in its transaction, sees the revocation and denies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_operator_write_waits_for_a_restore_and_then_sees_the_revocation() {
    let (db, pool) = issued().await;
    write_targets(&pool).await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    // The restoration holds the recovery state and waits for a replacement
    // ID another transaction is inserting.
    let mut transaction = first.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO admin_identity (id, status, created_at) \
         VALUES ('adm_new', 'enabled', timestamptz 'epoch')",
    )
    .execute(&mut *transaction)
    .await
    .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    let mut writers = Vec::new();
    for write in 0..4 {
        let mut connection = pool.acquire().await.unwrap().detach();
        let pid = backend_pid(&mut connection).await;
        let writer = tokio::spawn(async move {
            let mut writing = connection.begin().await.unwrap();
            let written = operator_write(&mut writing, write, "adm_first").await;
            let authorized =
                registry::authorize_operator(&mut *writing, &security_admin("spki-sha256:first"))
                    .await
                    .unwrap();
            writing.rollback().await.unwrap();
            connection.close().await.unwrap();
            (written, authorized)
        });
        assert!(
            waits_for(&pool, pid, second_pid, &writer).await,
            "write {write} did not wait for the restoration"
        );
        writers.push(writer);
    }
    transaction.rollback().await.unwrap();
    first.close().await.unwrap();
    restoring.await.unwrap().unwrap();
    for (write, writer) in writers.into_iter().enumerate() {
        let (written, authorized) = writer.await.unwrap();
        assert!(written.is_ok(), "{write}: {written:?}");
        assert_eq!(authorized, None, "{write}");
    }
    db.drop([pool]).await;
}

/// The caller's order (a locked authorization, then the writes) and the
/// restoration's (credentials, then the recovery state) do not deadlock:
/// the restoration waits at its credential lock holding no recovery state,
/// the four writes go through and commit, and the restoration then revokes
/// the enrolled credential too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_authorized_enrollment_does_not_deadlock_with_a_restore() {
    let (db, pool) = issued().await;
    write_targets(&pool).await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut transaction = first.begin().await.unwrap();
    assert!(
        registry::authorize_operator_locked(&mut transaction, &security_admin("spki-sha256:first"))
            .await
            .unwrap()
            .is_some()
    );
    let restoring = tokio::spawn(async move {
        let mut other = second.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        second.close().await.unwrap();
        restored
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    for write in 0..4 {
        operator_write(&mut transaction, write, "adm_late")
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
    first.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.revoked_credential_ids, ["crd_first", "crd_late"]);
    assert_eq!(
        registry::get_admin_credential(&pool, "crd_late")
            .await
            .unwrap()
            .revoked_at,
        Some(now())
    );
    assert_eq!(
        registry::get_admin_role_binding(&pool, "rb_off")
            .await
            .unwrap()
            .status,
        Status::Enabled
    );
    assert_eq!(
        verify(&pool).await,
        ChainVerdict::Intact { last_sequence: 4 }
    );
    db.drop([pool]).await;
}

/// The SQLSTATE of a store error.
fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|err| err.code())
        .map(|code| code.into_owned())
        .unwrap_or_default()
}

/// A restore at any isolation level but `READ COMMITTED` is
/// `UnsupportedIsolation`, decided inside its savepoint before its first
/// lock: it does not wait for an enrollment that holds the recovery state,
/// writes nothing, leaves the challenge unconsumed and the transaction
/// usable. The same challenge then restores at `READ COMMITTED`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_runs_only_at_read_committed() {
    let (db, pool) = issued().await;
    let before = pool_snapshot(&pool).await;
    // An uncommitted enrollment holds the recovery state `FOR SHARE`.
    let mut enrolling = pool.begin().await.unwrap();
    operator_write(&mut enrolling, 1, "adm_first")
        .await
        .unwrap();
    for isolation in ["REPEATABLE READ", "SERIALIZABLE", "READ UNCOMMITTED"] {
        let mut connection = pool.acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        sqlx::raw_sql(AssertSqlSafe(format!(
            "SET TRANSACTION ISOLATION LEVEL {isolation}; SET LOCAL lock_timeout = '5s'"
        )))
        .execute(&mut *transaction)
        .await
        .unwrap();
        let inside = snapshot(&mut transaction).await;
        match restore_in(&mut transaction, "op_1", &restore_request()).await {
            Err(err @ RestoreError::UnsupportedIsolation) => {
                assert_eq!(format!("{err:?}"), "UnsupportedIsolation");
                assert_eq!(
                    err.to_string(),
                    "operator restoration runs only at READ COMMITTED"
                );
            }
            other => panic!("{isolation}: expected UnsupportedIsolation: {other:?}"),
        }
        assert_eq!(snapshot(&mut transaction).await, inside, "{isolation}");
        let row = operation(&mut transaction, "op_1").await;
        assert_eq!((row.consumed_us, row.revision), (None, 1), "{isolation}");
        transaction.commit().await.unwrap();
    }
    enrolling.rollback().await.unwrap();
    assert_eq!(pool_snapshot(&pool).await, before);
    let mut connection = pool.acquire().await.unwrap();
    let mut transaction = connection.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await
        .unwrap();
    let restored = consume_and_restore(&mut transaction, "op_1").await.unwrap();
    assert_eq!(restored.recovery_key_epoch, 2);
    transaction.commit().await.unwrap();
    drop(connection);
    db.drop([pool]).await;
}

/// The cycle that remains: a credential enrolled after the restore's
/// credential lock and before its recovery-state lock is not locked by it.
/// A writer that then authorizes on that credential (`FOR SHARE`) and
/// writes, in the documented order, waits for the restore's recovery
/// state, while the restore's revocation waits for that credential.
/// PostgreSQL fails one side with `40P01`, a `Retry`, and the outcome is
/// closed either way: a restore that is the victim leaves nothing and its
/// challenge unconsumed, and its retry revokes the credential; a writer
/// that is the victim writes nothing and the restore revokes the
/// credential. PostgreSQL's deadlock check runs first in the side that
/// started waiting first, which is then the usual victim:
/// `restore_waits_first` picks that side.
async fn documented_order_deadlock(restore_waits_first: bool) {
    let (db, pool) = issued().await;
    let mut enroller = pool.acquire().await.unwrap().detach();
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut gate = pool.acquire().await.unwrap().detach();
    let mut restorer = pool.acquire().await.unwrap().detach();
    let mut writer = pool.acquire().await.unwrap().detach();
    let (enroller_pid, holder_pid, gate_pid, restorer_pid, writer_pid) = (
        backend_pid(&mut enroller).await,
        backend_pid(&mut holder).await,
        backend_pid(&mut gate).await,
        backend_pid(&mut restorer).await,
        backend_pid(&mut writer).await,
    );
    // The enrollment of `crd_late` holds the recovery state.
    let mut enrolling = enroller.begin().await.unwrap();
    operator_write(&mut enrolling, 1, "adm_first")
        .await
        .unwrap();
    // The operation row is held, so the restore stops at its consume.
    let mut holding = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM administrative_operation WHERE id = 'op_1' FOR UPDATE")
        .execute(&mut *holding)
        .await
        .unwrap();
    // The gate holds the writer between its lookup and its write.
    let mut gating = gate.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(81)")
        .execute(&mut *gating)
        .await
        .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = restorer.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        restorer.close().await.unwrap();
        restored
    });
    // Step 1 locked `crd_first` only; step 2 waits for the enrollment,
    // which commits between the two.
    wait_until_blocked(&pool, restorer_pid, enroller_pid).await;
    enrolling.commit().await.unwrap();
    enroller.close().await.unwrap();
    // The restore holds the recovery state and waits at its consume.
    wait_until_blocked(&pool, restorer_pid, holder_pid).await;
    let writing = tokio::spawn(async move {
        let mut transaction = writer.begin().await.unwrap();
        let authorized = registry::authorize_operator_locked(
            &mut transaction,
            &security_admin("spki-sha256:late"),
        )
        .await
        .unwrap();
        assert!(authorized.is_some());
        if restore_waits_first {
            sqlx::query("SELECT pg_advisory_xact_lock(81)")
                .execute(&mut *transaction)
                .await
                .unwrap();
        }
        let written = operator_write(&mut transaction, 0, "adm_first").await;
        if written.is_ok() {
            transaction.commit().await.unwrap();
        } else {
            transaction.rollback().await.unwrap();
        }
        writer.close().await.unwrap();
        written
    });
    if restore_waits_first {
        // The writer holds `crd_late` and waits at the gate; the restore
        // goes on to its revocation and waits for the writer; then the
        // writer writes and waits for the restore.
        wait_until_blocked(&pool, writer_pid, gate_pid).await;
        holding.rollback().await.unwrap();
        wait_until_blocked(&pool, restorer_pid, writer_pid).await;
        gating.rollback().await.unwrap();
    } else {
        // The writer waits for the restore; then the restore goes on to its
        // revocation and waits for the writer.
        assert!(waits_for(&pool, writer_pid, restorer_pid, &writing).await);
        holding.rollback().await.unwrap();
        gating.rollback().await.unwrap();
    }
    holder.close().await.unwrap();
    gate.close().await.unwrap();
    let restored = restoring.await.unwrap();
    let written = writing.await.unwrap();
    let late = registry::get_admin_credential(&pool, "crd_late")
        .await
        .unwrap();
    let late_identity: i64 =
        sqlx::query_scalar("SELECT count(*) FROM admin_identity WHERE id = 'adm_late'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let state = get_recovery_state(&pool).await.unwrap().unwrap();
    let row = pool_operation(&pool, "op_1").await;
    match (restored, written) {
        // The restore was the victim: nothing of it persists.
        (Err(RestoreError::Store(RegistryError::Retry(err))), Ok(())) => {
            assert_eq!(sqlstate(&err), "40P01");
            assert_eq!((row.consumed_us, row.revision), (None, 1));
            assert_eq!(row.outcome, "issued");
            assert_eq!((state.recovery_key_epoch, state.revision), (1, 1));
            assert_eq!(state.recovery_public_key, KEY);
            assert_eq!(late.revoked_at, None);
            assert_eq!(late_identity, 1);
            assert_eq!(
                verify(&pool).await,
                ChainVerdict::Intact { last_sequence: 2 }
            );
            // The retry restores and revokes the enrolled credential.
            let retried = restore_on(&pool, "op_1", &restore_request()).await.unwrap();
            assert_eq!(retried.revoked_credential_ids, ["crd_first", "crd_late"]);
        }
        // The writer was the victim: it wrote nothing, and the restore
        // revoked the enrolled credential.
        (Ok(restored), Err(RegistryError::Retry(err))) => {
            assert_eq!(sqlstate(&err), "40P01");
            assert_eq!(restored.revoked_credential_ids, ["crd_first", "crd_late"]);
            assert_eq!(late.revoked_at, Some(now()));
            assert_eq!(late_identity, 0);
            assert_eq!(row.outcome, "restored");
            assert_eq!(state.recovery_key_epoch, 2);
        }
        other => panic!("expected one 40P01 victim: {other:?}"),
    }
    assert_eq!(
        authorize_security_admin(&pool, "spki-sha256:late").await,
        None
    );
    db.drop([pool]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_restore_waiting_first_on_a_credential_enrolled_during_it_deadlocks_closed() {
    documented_order_deadlock(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_writer_waiting_first_on_a_credential_enrolled_during_a_restore_deadlocks_closed() {
    documented_order_deadlock(false).await;
}

/// A create that collides with the restore's replacement (its operator,
/// credential or binding ID, or its credential's public identity) waits for
/// the restore's recovery-state lock before it inserts, so it holds no key
/// the restore is about to insert: the restore commits, and the create is
/// then `AlreadyExists` with the replacement's constraint, with no
/// deadlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_create_colliding_with_the_replacement_waits_for_the_restore_first() {
    let (db, pool) = issued().await;
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut restorer = pool.acquire().await.unwrap().detach();
    let (holder_pid, restorer_pid) = (
        backend_pid(&mut holder).await,
        backend_pid(&mut restorer).await,
    );
    let mut holding = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM administrative_operation WHERE id = 'op_1' FOR UPDATE")
        .execute(&mut *holding)
        .await
        .unwrap();
    let restoring = tokio::spawn(async move {
        let mut other = restorer.begin().await.unwrap();
        let restored = consume_and_restore(&mut other, "op_1").await;
        if restored.is_ok() {
            other.commit().await.unwrap();
        } else {
            other.rollback().await.unwrap();
        }
        restorer.close().await.unwrap();
        restored
    });
    // The restore holds the recovery state and has inserted nothing yet.
    wait_until_blocked(&pool, restorer_pid, holder_pid).await;
    let mut creates = Vec::new();
    for create in 0..4 {
        let mut connection = pool.acquire().await.unwrap().detach();
        let pid = backend_pid(&mut connection).await;
        let task = tokio::spawn(async move {
            let mut transaction = connection.begin().await.unwrap();
            let created = match create {
                0 => registry::test_support::create_admin_identity(
                    &mut *transaction,
                    &NewAdminIdentity {
                        id: "adm_new".into(),
                        status: Status::Enabled,
                        created_at: now(),
                    },
                )
                .await
                .map(drop),
                1 | 2 => registry::test_support::create_admin_credential(
                    &mut *transaction,
                    &NewAdminCredential {
                        id: if create == 1 {
                            "crd_new"
                        } else {
                            "crd_collide"
                        }
                        .into(),
                        admin_id: "adm_first".into(),
                        public_identity: if create == 1 {
                            "spki-sha256:collide"
                        } else {
                            "spki-sha256:new"
                        }
                        .into(),
                        trust_anchor_ref: "deployment/operator-ca".into(),
                        status: Status::Enabled,
                    },
                )
                .await
                .map(drop),
                _ => registry::test_support::create_admin_role_binding(
                    &mut *transaction,
                    &NewAdminRoleBinding {
                        id: "rb_new".into(),
                        admin_id: "adm_first".into(),
                        role: AdminRole::Auditor,
                        tenant_id: None,
                        status: Status::Enabled,
                    },
                )
                .await
                .map(drop),
            };
            transaction.rollback().await.unwrap();
            connection.close().await.unwrap();
            created
        });
        assert!(
            waits_for(&pool, pid, restorer_pid, &task).await,
            "create {create} did not wait for the restore"
        );
        creates.push(task);
    }
    holding.rollback().await.unwrap();
    holder.close().await.unwrap();
    let restored = restoring.await.unwrap().unwrap();
    assert_eq!(restored.admin_id, "adm_new");
    for (task, constraint) in creates.into_iter().zip([
        "admin_identity_pkey",
        "admin_credential_pkey",
        "admin_credential_public_identity_key",
        "admin_role_binding_pkey",
    ]) {
        match task.await.unwrap() {
            Err(RegistryError::AlreadyExists { constraint: name }) => {
                assert_eq!(name, constraint)
            }
            other => panic!("expected AlreadyExists {constraint}: {other:?}"),
        }
    }
    db.drop([pool]).await;
}
