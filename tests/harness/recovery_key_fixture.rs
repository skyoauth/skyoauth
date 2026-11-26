//! The recovery key fixture `tests/conformance/fixtures/_recovery/key.v1.json`
//! against the service's own key checks, so that the workstation's copy
//! (`skyoauth_operator::recovery::RecoveryPublicKey`, which
//! `operator/tests/operator.rs` checks against the same file) and the
//! service's cannot drift apart. They test the fixture file, not a scenario:
//! no name here matches `a\d\d_`, and no stage of
//! `tests/conformance/scenarios.toml` lists them (layout §3).
//!
//! The service's checks (`recovery_key`) are crate-private, so the cases go
//! through the public functions that run them before any statement, each
//! in a transaction of its own that is rolled back:
//!
//! - every `byte_cases` key as the `recovery_public_key` of
//!   [`bootstrap_instance`]: a valid key bootstraps, any other is refused
//!   with the fixture's message for its class;
//! - every `text_cases` text as the plan's `new_recovery_public_key` of
//!   [`issue_recovery_challenge`] on a database without a recovery state: a
//!   valid key passes the checks and the issue is then refused as
//!   [`ChallengeError::NotIssuable`], text that is not 64 lowercase
//!   hexadecimal digits is refused with `service_plan_messages.not_hex`, and
//!   any other with the fixture's message for its class.
//!
//! They need `SKYOAUTH_IT_DATABASE_URL`, like every test of the `pg`
//! target, except [`key_fixture_length_is_the_services`].

use std::time::SystemTime;

use serde_json::{Map, Value, json};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::persistence::registry::{
    BootstrapError, BootstrapRequest, ChallengeError, DEFAULT_CHALLENGE_TTL, IssueChallenge,
    OPERATOR_RESTORATION, PLAN_ADMIN_ID, PLAN_BINDING_ID, PLAN_CREDENTIAL_ID, PLAN_INSTANCE_ID,
    PLAN_NEW_RECOVERY_PUBLIC_KEY, PLAN_PUBLIC_IDENTITY, PLAN_RECOVERY_KEY_EPOCH,
    PLAN_TRUST_ANCHOR_REF, RECOVERY_PUBLIC_KEY_LENGTH, RegistryError, bootstrap_instance,
    issue_recovery_challenge,
};

/// A lowercase hyphenated UUIDv7, for the instance.
const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0000000f1c75";

/// A public identity the bootstrap and the plan accept (the identity
/// fixture's Ed25519 case).
const PUBLIC_IDENTITY: &str =
    "spki-sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/fixtures/_recovery/key.v1.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string in {value}"))
}

fn cases<'a>(fixture: &'a Value, name: &str) -> &'a [Value] {
    let cases = fixture[name]
        .as_array()
        .unwrap_or_else(|| panic!("{name} is not an array"));
    assert!(!cases.is_empty(), "{name} is empty");
    cases
}

/// The bytes of `text`, an even number of lowercase hexadecimal digits.
fn unhex(text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2)
            && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "not lowercase hexadecimal: {text:?}"
    );
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// The message of a refusal through `sqlx::Error::Encode`, the form of
/// every check that runs before a statement.
fn encode_message(err: &RegistryError) -> Option<String> {
    match err {
        RegistryError::Other(sqlx::Error::Encode(err)) => Some(err.to_string()),
        _ => None,
    }
}

/// A restoration plan with `new_recovery_public_key` set to `key`; every
/// other member passes the service's checks.
fn plan(key: &str) -> Map<String, Value> {
    match json!({
        PLAN_INSTANCE_ID: INSTANCE_ID,
        PLAN_RECOVERY_KEY_EPOCH: 1,
        PLAN_ADMIN_ID: "adm_fixture",
        PLAN_CREDENTIAL_ID: "crd_fixture",
        PLAN_BINDING_ID: "rb_fixture",
        PLAN_PUBLIC_IDENTITY: PUBLIC_IDENTITY,
        PLAN_TRUST_ANCHOR_REF: "deployment/operator-ca",
        PLAN_NEW_RECOVERY_PUBLIC_KEY: key,
    }) {
        Value::Object(plan) => plan,
        other => unreachable!("{other}"),
    }
}

#[test]
fn key_fixture_length_is_the_services() {
    let fixture = fixture();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "recovery_public_key");
    assert_eq!(
        fixture["length_bytes"],
        u64::try_from(RECOVERY_PUBLIC_KEY_LENGTH).unwrap()
    );
}

#[tokio::test]
async fn key_byte_cases_through_bootstrap_instance() {
    let fixture = fixture();
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for case in cases(&fixture, "byte_cases") {
        let name = text(case, "case");
        let key = unhex(text(case, "key"));
        let mut transaction = pool.begin().await.unwrap();
        let result = bootstrap_instance(
            &mut transaction,
            &BootstrapRequest {
                instance_id: INSTANCE_ID,
                admin_id: "adm_fixture",
                credential_id: "crd_fixture",
                public_identity: PUBLIC_IDENTITY,
                trust_anchor_ref: "deployment/operator-ca",
                binding_id: "rb_fixture",
                recovery_public_key: &key,
                audit_event_id: "aud_fixture",
                now: SystemTime::now(),
            },
        )
        .await;
        transaction.rollback().await.unwrap();
        match (text(case, "expected"), result) {
            ("valid", Ok(outcome)) => assert_eq!(outcome.instance_id, INSTANCE_ID, "{name}"),
            ("valid", Err(err)) => panic!("{name}: refused: {err:?}"),
            (class, Err(BootstrapError::Store(err))) => assert_eq!(
                encode_message(&err).as_deref(),
                Some(text(&fixture["messages"], class)),
                "{name}: {err:?}"
            ),
            (class, other) => panic!("{name}: expected {class}: {other:?}"),
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn key_text_cases_through_issue_recovery_challenge() {
    let fixture = fixture();
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for case in cases(&fixture, "text_cases") {
        let name = text(case, "case");
        let plan = plan(text(case, "text"));
        let mut transaction = pool.begin().await.unwrap();
        let result = issue_recovery_challenge(
            &mut transaction,
            &IssueChallenge {
                operation_id: "op_fixture",
                kind: OPERATOR_RESTORATION,
                immutable_plan: &plan,
                ttl: DEFAULT_CHALLENGE_TTL,
                now: SystemTime::now(),
                audit_event_id: "aud_fixture",
            },
        )
        .await;
        transaction.rollback().await.unwrap();
        let expected_message = match text(case, "expected") {
            // Past every check: the database has no recovery state.
            "valid" => {
                assert!(
                    matches!(result, Err(ChallengeError::NotIssuable)),
                    "{name}: {result:?}"
                );
                continue;
            }
            "not_hex" => text(&fixture["service_plan_messages"], "not_hex"),
            class => text(&fixture["messages"], class),
        };
        match result {
            Err(ChallengeError::Store(err)) => assert_eq!(
                encode_message(&err).as_deref(),
                Some(expected_message),
                "{name}: {err:?}"
            ),
            other => panic!("{name}: expected {expected_message:?}: {other:?}"),
        }
    }
    db.drop([pool]).await;
}
