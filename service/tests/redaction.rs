//! The database password must not appear in connection errors (`Display`
//! or `Debug`) or in logs captured at trace level, on real failure paths.
//! Nor may a value of a gated request (an operation or credential ID, a
//! public identity, the plan, the request digest) appear in the
//! `Display` or `Debug` of an `ApprovalError` that the second-approver flow
//! returns, of the `RegistryError` it wraps, or in the `Debug` of a
//! prepared approval or a digest (`crate::operation`, "Errors and
//! rollback"; proposal section 10). Likewise a value of a recovery
//! response (the operation ID, the signature, the plan, the challenge `M`
//! or its hashes, a key) must not appear in the `Display` or `Debug` of a
//! `RestoreError`, a `SignedRecoveryResponse` or a `RecoveryPreview`
//! (`persistence::registry::recovery`, "Restore";
//! `docs/proposals/recovery-verified-response.md`).
//!
//! The unreachable-host and refused-connection tests need no server. The
//! TLS, wrong-password and approval tests need `SKYOAUTH_IT_DATABASE_URL`
//! and are `#[ignore]`d like the migration tests; run them with
//! `cargo nextest run --run-ignored all` or `cargo test -- --include-ignored`.

mod common;

use std::{
    error::Error as _,
    fmt::Debug,
    io,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use skyoauth_service::{
    jwk::DEFAULT_ALLOWED_ALGORITHMS,
    operation::{
        ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, Gated, PendingOperation,
        PreparedApproval, RequestDigest, Submission, approve_operation, prepare_approval,
        submit_widening_toggle,
    },
    persistence::{
        self, DatabaseConfig, PgPool,
        registry::{
            self, AdminRole, AuditActor, BootstrapRequest, DEFAULT_CHALLENGE_TTL, IssueChallenge,
            NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding, NewAdministrativeOperation,
            NewAuditEvent, NotRestorableReason, OPERATOR_RESTORATION, RecoveryPreview,
            RestoreError, RestoreRequest, SignedRecoveryResponse, Status, bootstrap_instance,
            issue_recovery_challenge, preview_recovery_response, restore_operator,
            test_support::{append_audit_event, insert_administrative_operation},
        },
    },
};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

const SECRET: &str = "s3cr3t-pw-7f2c";

/// Log output captured in memory.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// Connects as the `migrate` command does, with every log level captured,
/// and asserts that the connection fails without the password showing up in
/// the error or the logs.
async fn assert_failure_omits_password(connect: PgConnectOptions) {
    let config =
        DatabaseConfig::new(connect.password(SECRET), None, 2, Duration::from_secs(2)).unwrap();
    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .with_writer(logs.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::info!(database = ?config, "connecting");
    let err = persistence::connect(&config)
        .await
        .expect_err("the connection was expected to fail");
    drop(guard);

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("connecting"), "log capture is not working");
    for (what, text) in [
        ("Display", err.to_string()),
        ("Debug", format!("{err:?}")),
        ("logs", logs),
    ] {
        assert!(!text.contains(SECRET), "password in {what}: {text}");
    }
}

fn it_database_url() -> String {
    std::env::var("SKYOAUTH_IT_DATABASE_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .expect("SKYOAUTH_IT_DATABASE_URL must be set to run this database test")
}

#[tokio::test]
async fn unresolvable_host_failure_omits_the_password() {
    // `.invalid` never resolves (RFC 2606).
    let connect = PgConnectOptions::from_str("postgres://skyoauth@skyoauth-db.invalid/skyoauth");
    assert_failure_omits_password(connect.unwrap()).await;
}

#[tokio::test]
async fn refused_connection_failure_omits_the_password() {
    // Port 1 on loopback refuses connections.
    let connect = PgConnectOptions::from_str("postgres://skyoauth@127.0.0.1:1/skyoauth");
    assert_failure_omits_password(connect.unwrap()).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn tls_failure_omits_the_password() {
    // Fails whether or not the server offers TLS: without TLS, verify-full
    // refuses to continue; with it, the root certificate cannot be read.
    let connect = PgConnectOptions::from_str(&it_database_url())
        .unwrap()
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert("/nonexistent/skyoauth-test-ca.pem");
    assert_failure_omits_password(connect).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn wrong_password_failure_omits_the_password() {
    let connect = PgConnectOptions::from_str(&it_database_url()).unwrap();
    assert_failure_omits_password(connect).await;
}

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;
/// The values of the gated requests below, each one a marker that must not
/// show up in an error or a `Debug`.
const OP: &str = "op_redact_4b7e";
const OP_LONG: &str = "op_redact_long_8c21";
const OP_UNREADABLE: &str = "op_redact_infinite_3a90";
const OP_STALE: &str = "op_redact_stale_57d1";
const OP_MISSING: &str = "op_redact_missing_e6f2";
/// A toggle off without `acknowledge_widening`, and its event.
const OP_UNACKNOWLEDGED: &str = "op_redact_unack_5d09";
const UNACKNOWLEDGED_EVENT: &str = "evt_redact_unack_c4a7";
const REQ_ADMIN: &str = "adm_redact_req_2d4c";
const REQ_CREDENTIAL: &str = "crd_redact_req_62d8";
const REQ_KEY: &str = "spki-sha256:redact-req-91c3";
const SEC_ADMIN: &str = "adm_redact_sec_7e15";
const SEC_KEY: &str = "spki-sha256:redact-sec-0f5a";
const UNKNOWN_KEY: &str = "spki-sha256:redact-unknown-b8e0";
const CREATE_EVENT: &str = "evt_redact_create_19af";
/// The approve event ID that the unlisted check constraint refuses.
const UNLISTED_EVENT: &str = "evt_redact_unlisted_5c3b";

fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

/// A clock fixed at `at(10)`.
struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> SystemTime {
        at(10)
    }
}

/// The forms a leaked digest would take: lowercase and uppercase hex, and
/// the `Debug` of its bytes in decimal and in hex.
fn digest_forms(digest: &[u8]) -> Vec<String> {
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        hex.to_uppercase(),
        hex,
        format!("{digest:?}"),
        format!("{digest:x?}"),
        format!("{digest:02x?}"),
    ]
}

#[track_caller]
fn assert_omits(what: &str, text: &str, markers: &[String]) {
    for marker in markers {
        assert!(
            !text.contains(marker.as_str()),
            "{marker} in {what}: {text}"
        );
    }
}

/// The `Display` and `Debug` (plain and alternate) of `err` and of every
/// error in its source chain down to the `RegistryError`, which documents
/// that its own source, a raw `sqlx::Error`, may quote values.
#[track_caller]
fn assert_error_omits(err: &ApprovalError, markers: &[String]) {
    let mut texts = vec![
        ("Display", err.to_string()),
        ("Debug", format!("{err:?}")),
        ("Debug alternate", format!("{err:#?}")),
    ];
    if let Some(source) = err.source() {
        texts.push(("source Display", source.to_string()));
        texts.push(("source Debug", format!("{source:?}")));
        texts.push(("source Debug alternate", format!("{source:#?}")));
    }
    for (what, text) in texts {
        assert_omits(&format!("{err:?} {what}"), &text, markers);
    }
}

#[track_caller]
fn refused<T: Debug>(result: Result<T, ApprovalError>, expected: &str, markers: &[String]) {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => {
            assert_error_omits(&err, markers);
            assert_eq!(format!("{err:?}"), expected);
        }
    }
}

async fn operator(pool: &PgPool, admin: &str, credential: &str, key: &str, binding: &str) {
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
            id: credential.into(),
            admin_id: admin.into(),
            public_identity: key.into(),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: binding.into(),
            admin_id: admin.into(),
            role: AdminRole::SecurityAdmin,
            tenant_id: None,
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// A pending toggle `id` by [`REQ_KEY`] at policy revision 1.
async fn pending(pool: &PgPool, id: &str, event_id: &str) -> PendingOperation {
    let mut transaction = pool.begin().await.unwrap();
    let gated = submit_widening_toggle(
        &mut transaction,
        &Submission {
            public_identity: REQ_KEY,
            acknowledge_widening: false,
            operation_id: id,
            event_id,
            now: at(0),
        },
        1,
        true,
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    match gated {
        Gated::Pending(pending) => pending,
        other => panic!("not pending: {other:?}"),
    }
}

/// An operation `id` by [`REQ_ADMIN`] written straight to the table, with
/// its `create` event, the toggle's plan and `digest`.
async fn insert_raw(pool: &PgPool, id: &str, digest: Vec<u8>) {
    let mut transaction = pool.begin().await.unwrap();
    let audit_id = format!("evt_{id}");
    append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: audit_id.clone(),
            tenant_id: None,
            timestamp: at(0),
            actor: AuditActor::Operator(REQ_ADMIN.into()),
            action: "administrative_operation.create".into(),
            object_id: id.into(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    let serde_json::Value::Object(plan) = json!({
        "requester_credential_id": REQ_CREDENTIAL,
        "widening_second_approver": true,
    }) else {
        unreachable!()
    };
    insert_administrative_operation(
        &mut transaction,
        &NewAdministrativeOperation {
            id: id.into(),
            tenant_id: None,
            actor_id: REQ_ADMIN.into(),
            kind: "instance_security_policy_update".into(),
            request_digest: digest,
            expected_revision: 1,
            immutable_plan: plan,
            expires_at: Some(at(86_400_000_000)),
            approves_operation_id: None,
            outcome: "pending".into(),
            audit_id,
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}

async fn prepare(key: &str, pool: &PgPool, id: &str) -> Result<PreparedApproval, ApprovalError> {
    prepare_approval(
        pool,
        key,
        ApprovalScope::Instance,
        id,
        DEFAULT_ALLOWED_ALGORITHMS,
        at(1),
    )
    .await
}

/// An approval by [`SEC_KEY`] in a transaction committed either way, with
/// the approve event `approve_event_id`.
async fn approve(
    pool: &PgPool,
    prepared: &PreparedApproval,
    echo: &ApprovalEcho,
    approve_event_id: &str,
    isolation: Option<&str>,
) -> Result<skyoauth_service::operation::Applied, ApprovalError> {
    let mut transaction = pool.begin().await.unwrap();
    if let Some(level) = isolation {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SET TRANSACTION ISOLATION LEVEL {level}"
        )))
        .execute(&mut *transaction)
        .await
        .unwrap();
    }
    let tag = prepared.operation_id().to_owned();
    let approve_operation_id = format!("appr_{tag}");
    let write_event_id = format!("evt_write_{tag}");
    let result = approve_operation(
        &mut transaction,
        SEC_KEY,
        ApprovalScope::Instance,
        prepared,
        echo,
        &ApprovalIds {
            approve_operation_id: &approve_operation_id,
            approve_event_id,
            write_event_id: &write_event_id,
        },
        &Fixed,
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

/// The second-approver flow's refusals on real paths, included: a refusal
/// of the database the registry maps (a taken event ID), one it does not
/// (`RegistryError::Other`, from a check constraint unknown to the registry,
/// whose raw `sqlx::Error` quotes the failing row), and a row the registry
/// cannot read (an infinite expiry, the ID of the row in its
/// `RegistryError`), and a toggle off without `acknowledge_widening`
/// (`WideningNotAcknowledged`). No `Display` or `Debug` of the error or of its
/// `RegistryError` holds an ID, a public identity, the plan or the digest
/// of the request. The
/// `Debug` of a prepared approval holds none of them either, and that of a
/// pending operation or an echo not the digest.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn approval_errors_omit_the_requests_values() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
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
    operator(&pool, REQ_ADMIN, REQ_CREDENTIAL, REQ_KEY, "rb_redact_req").await;
    operator(&pool, SEC_ADMIN, "crd_redact_sec", SEC_KEY, "rb_redact_sec").await;

    let op = pending(&pool, OP, CREATE_EVENT).await;
    let op_stale = pending(&pool, OP_STALE, "evt_redact_stale").await;
    let digest = *op.request_digest.as_bytes();
    let mut wrong = digest;
    wrong[0] ^= 0xff;
    let digests: Vec<String> = [&digest, &wrong, op_stale.request_digest.as_bytes()]
        .into_iter()
        .flat_map(|bytes| digest_forms(bytes))
        .collect();
    let mut markers: Vec<String> = [
        OP,
        OP_LONG,
        OP_UNREADABLE,
        OP_STALE,
        OP_MISSING,
        OP_UNACKNOWLEDGED,
        REQ_ADMIN,
        REQ_CREDENTIAL,
        REQ_KEY,
        SEC_ADMIN,
        SEC_KEY,
        UNKNOWN_KEY,
        CREATE_EVENT,
        UNLISTED_EVENT,
        UNACKNOWLEDGED_EVENT,
        "widening_second_approver",
    ]
    .map(String::from)
    .to_vec();
    markers.extend(digests.iter().cloned());

    // The values a caller holds: their Debug.
    let prepared = prepare(SEC_KEY, &pool, OP).await.unwrap();
    assert_omits("PreparedApproval Debug", &format!("{prepared:?}"), &markers);
    assert_omits(
        "PreparedApproval Debug",
        &format!("{prepared:#?}"),
        &markers,
    );
    let echo = ApprovalEcho {
        request_digest: op.request_digest,
        expected_revision: 1,
    };
    assert_omits("ApprovalEcho Debug", &format!("{echo:#?}"), &markers);
    assert_omits("PendingOperation Debug", &format!("{op:#?}"), &digests);
    let wrong_digest = RequestDigest::from_bytes(wrong);
    assert_omits(
        "RequestDigest Debug",
        &format!("{wrong_digest:?}"),
        &digests,
    );

    // The refusals.
    let unacknowledged = {
        let mut transaction = pool.begin().await.unwrap();
        let result = submit_widening_toggle(
            &mut transaction,
            &Submission {
                public_identity: REQ_KEY,
                acknowledge_widening: false,
                operation_id: OP_UNACKNOWLEDGED,
                event_id: UNACKNOWLEDGED_EVENT,
                now: at(0),
            },
            1,
            false,
        )
        .await;
        transaction.commit().await.unwrap();
        result
    };
    refused(unacknowledged, "WideningNotAcknowledged", &markers);
    refused(
        prepare(UNKNOWN_KEY, &pool, OP).await,
        "Unauthorized",
        &markers,
    );
    refused(
        prepare(SEC_KEY, &pool, OP_MISSING).await,
        "NotFound",
        &markers,
    );
    refused(prepare(REQ_KEY, &pool, OP).await, "SelfApproval", &markers);
    let wrong_echo = ApprovalEcho {
        request_digest: wrong_digest,
        ..echo
    };
    refused(
        approve(&pool, &prepared, &wrong_echo, "evt_redact_a", None).await,
        "EchoMismatch",
        &markers,
    );
    refused(
        approve(
            &pool,
            &prepared,
            &echo,
            "evt_redact_b",
            Some("REPEATABLE READ"),
        )
        .await,
        "UnsupportedIsolation",
        &markers,
    );
    // The database refuses the approve event's ID: it is the create
    // event's, a marker.
    refused(
        approve(&pool, &prepared, &echo, CREATE_EVENT, None).await,
        "Registry(AlreadyExists { constraint: \"audit_event_pkey\" })",
        &markers,
    );
    // A refusal the registry does not map: a check constraint missing from
    // KNOWN_CONSTRAINTS refuses the approve event. The constraint is added
    // in the approval's own transaction, which is rolled back, so it is
    // gone afterwards even when the approval panics (DDL is transactional).
    let unlisted = {
        let mut transaction = pool.begin().await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "ALTER TABLE audit_event ADD CONSTRAINT zz_unlisted CHECK (id <> '{UNLISTED_EVENT}')"
        )))
        .execute(&mut *transaction)
        .await
        .unwrap();
        let result = approve_operation(
            &mut transaction,
            SEC_KEY,
            ApprovalScope::Instance,
            &prepared,
            &echo,
            &ApprovalIds {
                approve_operation_id: "appr_redact_unlisted",
                approve_event_id: UNLISTED_EVENT,
                write_event_id: "evt_write_redact_unlisted",
            },
            &Fixed,
        )
        .await;
        transaction.rollback().await.unwrap();
        result
    };
    let constraints: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_constraint WHERE conname = 'zz_unlisted'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(constraints, 0, "zz_unlisted left behind");
    let err = unlisted.expect_err("the unlisted constraint refuses the approve event");
    assert_error_omits(&err, &markers);
    assert_eq!(
        format!("{err:?}"),
        "Registry(Other { sqlstate: Some(\"23514\"), .. })"
    );
    assert_eq!(
        err.to_string(),
        "operation write failed: registry database error (SQLSTATE 23514)"
    );
    // The raw error under it is the one that quotes the row: the redaction,
    // not the database, keeps the markers out above.
    let registry_err = err
        .source()
        .and_then(|source| source.downcast_ref::<registry::RegistryError>())
        .expect("a RegistryError source");
    let raw = registry_err
        .source()
        .and_then(|source| source.downcast_ref::<sqlx::Error>())
        .and_then(|raw| raw.as_database_error())
        .expect("a database error source");
    assert_eq!(raw.code().as_deref(), Some("23514"));
    assert_eq!(raw.constraint(), Some("zz_unlisted"));
    assert!(
        format!("{:?}", registry_err.source().unwrap()).contains(UNLISTED_EVENT),
        "the raw error does not quote the event ID, so this case proves nothing"
    );

    // A stored digest of another length (33 bytes: the column allows 32 to
    // 64, the flow writes 32).
    insert_raw(&pool, OP_LONG, [&digest[..], &[0]].concat()).await;
    refused(
        prepare(SEC_KEY, &pool, OP_LONG).await,
        "PlanIntegrity",
        &markers,
    );
    // An expiry the registry cannot read, written past its range check and
    // the immutability guard: the RegistryError keeps the row's ID out.
    insert_raw(&pool, OP_UNREADABLE, digest.to_vec()).await;
    let prepared_unreadable = {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "BEGIN; \
             ALTER TABLE administrative_operation \
             DROP CONSTRAINT administrative_operation_expires_at_range_check; \
             ALTER TABLE administrative_operation \
             DISABLE TRIGGER administrative_operation_immutable; \
             UPDATE administrative_operation SET expires_at = 'infinity', \
             revision = revision + 1 WHERE id = '{OP_UNREADABLE}'; \
             ALTER TABLE administrative_operation \
             ENABLE ALWAYS TRIGGER administrative_operation_immutable; \
             COMMIT"
        )))
        .execute(&pool)
        .await
        .unwrap();
        prepare(SEC_KEY, &pool, OP_UNREADABLE).await.unwrap()
    };
    refused(
        approve(&pool, &prepared_unreadable, &echo, "evt_redact_c", None).await,
        "Registry(UnreadableTimestamp { table: \"administrative_operation\", \
         column: \"expires_at\", .. })",
        &markers,
    );

    // Applied once; then consumed, and the other operation stale.
    approve(&pool, &prepared, &echo, "evt_redact_d", None)
        .await
        .unwrap();
    refused(
        approve(&pool, &prepared, &echo, "evt_redact_e", None).await,
        "NotApprovable(Consumed)",
        &markers,
    );
    let prepared_stale = prepare(SEC_KEY, &pool, OP_STALE).await.unwrap();
    let stale_echo = ApprovalEcho {
        request_digest: op_stale.request_digest,
        expected_revision: 1,
    };
    refused(
        approve(&pool, &prepared_stale, &stale_echo, "evt_redact_f", None).await,
        "StaleRevision",
        &markers,
    );
    // The requester's credential revoked.
    registry::revoke_admin_credential(&pool, REQ_CREDENTIAL, at(5))
        .await
        .unwrap();
    refused(
        approve(&pool, &prepared_stale, &stale_echo, "evt_redact_g", None).await,
        "RequesterNotAuthorized",
        &markers,
    );
    db.drop([pool]).await;
}

/// Every reason of `RestoreError::NotRestorable`: its fixed `Display` and
/// a `Debug` that names the variant and the reason only.
const REASONS: [(NotRestorableReason, &str); 10] = [
    (
        NotRestorableReason::NoRecoveryState,
        "there is no closed recovery state",
    ),
    (NotRestorableReason::NotFound, "no such recovery challenge"),
    (
        NotRestorableReason::Consumed,
        "the recovery challenge was already used",
    ),
    (
        NotRestorableReason::Revoked,
        "the recovery challenge was revoked",
    ),
    (
        NotRestorableReason::Expired,
        "the recovery challenge has expired",
    ),
    (
        NotRestorableReason::WrongKind,
        "the operation is not an issued operator restoration challenge",
    ),
    (
        NotRestorableReason::NotBound,
        "the recovery challenge is not bound to the current recovery state",
    ),
    (
        NotRestorableReason::NotLibraryEncoding,
        "the recovery challenge's stored digest or hash is not its encoding",
    ),
    (
        NotRestorableReason::WeakKey,
        "the current recovery public key is not usable",
    ),
    (
        NotRestorableReason::BadSignature,
        "the signature does not verify with the current recovery key",
    ),
];

/// Each reason's `Display` is fixed text and its `Debug` the variant and
/// the reason; equal reasons compare equal and others do not; the error
/// has no source.
#[test]
fn every_not_restorable_reason_is_fixed_text() {
    for (reason, text) in REASONS {
        let err = RestoreError::from(reason);
        assert_eq!(err.to_string(), text);
        assert_eq!(format!("{err:?}"), format!("NotRestorable({reason:?})"));
        assert_eq!(
            format!("{err:#?}"),
            format!("NotRestorable(\n    {reason:?},\n)")
        );
        assert!(err.source().is_none());
        for (other, _) in REASONS {
            assert_eq!(err == RestoreError::from(other), reason == other);
        }
    }
}

/// The `Debug` of a response and of a preview prints none of their values.
#[test]
fn a_recovery_response_and_preview_print_no_values() {
    let response = SignedRecoveryResponse {
        operation_id: RECOVERY_OP,
        signature: &[0xa7; 64],
    };
    let preview = RecoveryPreview {
        admin_id: RECOVERY_ADMIN.into(),
        credential_id: "crd_redact_restore_31f0".into(),
        binding_id: "rb_redact_restore_aa42".into(),
        new_recovery_key_epoch: 7,
        expires_at: at(1),
    };
    let markers = recovery_markers(&[&[0xa7; 64]]);
    for (what, text) in [
        ("response", format!("{response:?}")),
        ("response alternate", format!("{response:#?}")),
        ("preview", format!("{preview:?}")),
        ("preview alternate", format!("{preview:#?}")),
    ] {
        assert_omits(what, &text, &markers);
    }
    assert_eq!(format!("{response:?}"), "SignedRecoveryResponse { .. }");
    assert_eq!(format!("{preview:?}"), "RecoveryPreview { .. }");
}

const RECOVERY_OP: &str = "op_redact_restore_7c19";
const RECOVERY_OTHER_OP: &str = "op_redact_restore_other_0b6d";
const RECOVERY_ADMIN: &str = "adm_redact_restore_e2a8";
const RECOVERY_KEY: &str = "spki-sha256:redact-restore-5f17";
/// The seed of the test recovery key bootstrap enrolls.
const RECOVERY_SEED: [u8; 32] = [0x51; 32];
/// The seed of the key the plan names.
const NEW_RECOVERY_SEED: [u8; 32] = [0x52; 32];

fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// The values a recovery error must not show: the IDs and identity of the
/// plan, and every form of the keys and of `bytes` (signatures, `M`'s
/// hashes).
fn recovery_markers(bytes: &[&[u8]]) -> Vec<String> {
    let mut markers: Vec<String> = [
        RECOVERY_OP,
        RECOVERY_OTHER_OP,
        RECOVERY_ADMIN,
        RECOVERY_KEY,
        "crd_redact_restore_31f0",
        "rb_redact_restore_aa42",
    ]
    .map(String::from)
    .into();
    let keys = [public_key(&RECOVERY_SEED), public_key(&NEW_RECOVERY_SEED)];
    for value in bytes.iter().copied().chain(keys.iter().map(|key| &key[..])) {
        markers.extend(digest_forms(value));
    }
    markers
}

#[track_caller]
fn assert_restore_omits<T: Debug>(
    result: Result<T, RestoreError>,
    reason: NotRestorableReason,
    markers: &[String],
) {
    match result {
        Err(err @ RestoreError::NotRestorable(got)) if got == reason => {
            for (what, text) in [
                ("Display", err.to_string()),
                ("Debug", format!("{err:?}")),
                ("Debug alternate", format!("{err:#?}")),
            ] {
                assert_omits(&format!("{reason:?} {what}"), &text, markers);
            }
        }
        other => panic!("expected NotRestorable({reason:?}): {other:?}"),
    }
}

/// The refusals of a real preview and restore show none of the response's
/// values: an unknown ID, a bad signature, an expired challenge, a
/// consumed one and one the rotation retired.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn recovery_errors_omit_the_responses_values() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
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
            recovery_public_key: &public_key(&RECOVERY_SEED),
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    let new_key: String = public_key(&NEW_RECOVERY_SEED)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let serde_json::Value::Object(plan) = json!({
        "instance_id": INSTANCE_ID,
        "recovery_key_epoch": 1,
        "admin_id": RECOVERY_ADMIN,
        "credential_id": "crd_redact_restore_31f0",
        "binding_id": "rb_redact_restore_aa42",
        "public_identity": RECOVERY_KEY,
        "trust_anchor_ref": "deployment/operator-ca",
        "new_recovery_public_key": new_key,
    }) else {
        unreachable!()
    };
    let mut challenges = Vec::new();
    for (id, event) in [
        (RECOVERY_OP, "evt_redact_issue_1"),
        (RECOVERY_OTHER_OP, "evt_redact_issue_2"),
    ] {
        challenges.push(
            issue_recovery_challenge(
                &mut transaction,
                &IssueChallenge {
                    operation_id: id,
                    kind: OPERATOR_RESTORATION,
                    immutable_plan: &plan,
                    ttl: DEFAULT_CHALLENGE_TTL,
                    now: at(1),
                    audit_event_id: event,
                },
            )
            .await
            .unwrap(),
        );
    }
    transaction.commit().await.unwrap();
    let signer = SigningKey::from_bytes(&RECOVERY_SEED);
    let signature = signer.sign(&challenges[0].challenge).to_bytes();
    let other_signature = signer.sign(&challenges[1].challenge).to_bytes();
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    for challenge in &challenges {
        use sha2::Digest as _;
        hashes.push(sha2::Sha256::digest(&challenge.challenge).into());
    }
    let mut bytes: Vec<&[u8]> = vec![&signature, &other_signature];
    bytes.extend(hashes.iter().map(|hash| &hash[..]));
    let mut markers = recovery_markers(&bytes);
    // `M` itself, and the plan as JSON.
    for challenge in &challenges {
        markers.push(String::from_utf8(challenge.challenge.clone()).unwrap());
    }
    markers.push(json!(plan).to_string());

    let request = |now| RestoreRequest {
        audit_event_id: "evt_redact_restore",
        rotation_audit_event_id: "evt_redact_rotate",
        now,
    };
    let refuse = |id: &'static str, signature: [u8; 64], now, reason| {
        let pool = pool.clone();
        let markers = markers.clone();
        async move {
            let response = SignedRecoveryResponse {
                operation_id: id,
                signature: &signature,
            };
            let mut transaction = pool.begin().await.unwrap();
            assert_restore_omits(
                preview_recovery_response(&mut transaction, &response, now).await,
                reason,
                &markers,
            );
            assert_restore_omits(
                restore_operator(&mut transaction, &response, &request(now)).await,
                reason,
                &markers,
            );
            transaction.rollback().await.unwrap();
        }
    };
    refuse(
        "op_redact_restore_unknown_44c2",
        signature,
        at(2),
        NotRestorableReason::NotFound,
    )
    .await;
    let mut flipped = signature;
    flipped[0] ^= 1;
    refuse(
        RECOVERY_OP,
        flipped,
        at(2),
        NotRestorableReason::BadSignature,
    )
    .await;
    refuse(
        RECOVERY_OP,
        other_signature,
        at(2),
        NotRestorableReason::BadSignature,
    )
    .await;
    refuse(
        RECOVERY_OP,
        signature,
        at(1) + DEFAULT_CHALLENGE_TTL,
        NotRestorableReason::Expired,
    )
    .await;
    let mut transaction = pool.begin().await.unwrap();
    restore_operator(
        &mut transaction,
        &SignedRecoveryResponse {
            operation_id: RECOVERY_OP,
            signature: &signature,
        },
        &request(at(2)),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    refuse(RECOVERY_OP, signature, at(3), NotRestorableReason::Consumed).await;
    refuse(
        RECOVERY_OTHER_OP,
        other_signature,
        at(3),
        NotRestorableReason::NotBound,
    )
    .await;
    db.drop([pool]).await;
}
