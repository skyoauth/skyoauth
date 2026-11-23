//! The database password must not appear in connection errors (`Display`
//! or `Debug`) or in logs captured at trace level, on real failure paths.
//! Nor may a value of a gated request (an operation or credential ID, a
//! public identity, the plan, the request digest) appear in the
//! `Display` or `Debug` of an `ApprovalError` that the second-approver flow
//! returns, of the `RegistryError` it wraps, or in the `Debug` of a
//! prepared approval or a digest (`crate::operation`, "Errors and
//! rollback"; proposal section 10).
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
use serde_json::json;
use skyoauth_service::{
    operation::{
        ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, Gated, PendingOperation,
        PreparedApproval, RequestDigest, Submission, approve_operation, prepare_approval,
        submit_widening_toggle,
    },
    persistence::{
        self, DatabaseConfig, PgPool,
        registry::{
            self, AdminRole, AuditActor, BootstrapRequest, NewAdminCredential, NewAdminIdentity,
            NewAdminRoleBinding, NewAdministrativeOperation, NewAuditEvent, Status,
            append_audit_event, bootstrap_instance, insert_administrative_operation,
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
    registry::create_admin_credential(
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
    registry::create_admin_role_binding(
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
    prepare_approval(pool, key, ApprovalScope::Instance, id, at(1)).await
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
/// `RegistryError`). No `Display` or `Debug` of the error or of its
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
        REQ_ADMIN,
        REQ_CREDENTIAL,
        REQ_KEY,
        SEC_ADMIN,
        SEC_KEY,
        UNKNOWN_KEY,
        CREATE_EVENT,
        UNLISTED_EVENT,
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
