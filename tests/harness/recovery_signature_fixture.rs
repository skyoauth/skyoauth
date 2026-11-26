//! The recovery signature fixture
//! `tests/conformance/fixtures/_recovery/signature.v1.json` and its test
//! keys `recovery.test-key.json` against the service, so that the
//! workstation's signer and verifier (`skyoauth_operator::recovery`, which
//! `operator/tests/operator.rs` checks against the same files) and the
//! service's restore agree on every case. They test the fixture files, not
//! a scenario: no name here matches `a\d\d_`, and no stage of
//! `tests/conformance/scenarios.toml` lists them (layout §3).
//!
//! The workstation crate is not a dependency of this package: the fixture
//! is the bridge. The operator's tests pin that its `sign_challenge` of the
//! challenge fixture's op_1 returns the fixture's `valid` signature; here,
//! an independent signer (`ed25519-dalek`'s `SigningKey`) re-makes every
//! real signature of the fixture, and the service, which issued that op_1
//! challenge itself, restores with the `valid` signature and refuses every
//! other case.
//!
//! - The test keys: each seed's public key, and the RFC 8032 test 1 vector
//!   (no database needed).
//! - On a database bootstrapped with the test recovery key: the challenge
//!   [`issue_recovery_challenge`] issues for op_1 is the fixture's `M`; the
//!   independent signer's signature over it is the `valid` case; every case
//!   through [`preview_recovery_response`] and [`restore_operator`] is the
//!   fixture's `service_expected` for its class (`valid` previews and
//!   restores, every other case, the cofactor case `mixed_order_r`
//!   included, is `NotRestorable(BadSignature)` and leaves the challenge
//!   unconsumed); and a replay of the restore is `Consumed`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Map, Value};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    operation::DIGEST_PREFIX,
    persistence::{
        PgPool,
        registry::{
            BootstrapRequest, DEFAULT_CHALLENGE_TTL, IssueChallenge, NotRestorableReason,
            OPERATOR_RESTORATION, PLAN_ADMIN_ID, PLAN_BINDING_ID, PLAN_CREDENTIAL_ID,
            PLAN_INSTANCE_ID, PLAN_NEW_RECOVERY_PUBLIC_KEY, PLAN_RECOVERY_KEY_EPOCH, RestoreError,
            RestoreRequest, SignedRecoveryResponse, bootstrap_instance, issue_recovery_challenge,
            preview_recovery_response, restore_operator,
        },
    },
};

/// A public identity the bootstrap accepts (the identity fixture's Ed25519
/// case).
const PUBLIC_IDENTITY: &str =
    "spki-sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/conformance/fixtures/_recovery/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string in {value}"))
}

fn list<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    let list = value[name]
        .as_array()
        .unwrap_or_else(|| panic!("{name} is not an array in {value}"));
    assert!(!list.is_empty(), "no {name}");
    list
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

/// The signing key `name` of the test-key fixture, with its public key
/// checked against the fixture's.
fn test_key(name: &str) -> SigningKey {
    let keys = fixture("recovery.test-key.json");
    let key = list(&keys, "keys")
        .iter()
        .find(|key| text(key, "name") == name)
        .unwrap_or_else(|| panic!("no test key {name}"));
    let seed: [u8; 32] = unhex(text(key, "seed")).try_into().expect("a 32-byte seed");
    let signing = SigningKey::from_bytes(&seed);
    assert_eq!(
        signing.verifying_key().as_bytes().to_vec(),
        unhex(text(key, "public_key")),
        "{name}"
    );
    signing
}

/// The challenge fixture's vector `case`, and the fixture's prefix.
fn challenge_vector(case: &str) -> (Value, Vec<u8>) {
    let challenge = fixture("challenge.v1.json");
    let vector = list(&challenge, "vectors")
        .iter()
        .find(|vector| vector["case"] == case)
        .unwrap_or_else(|| panic!("no challenge vector {case}"))
        .clone();
    (vector, text(&challenge, "prefix").as_bytes().to_vec())
}

/// The bytes a `signed_over` name stands for, built from the challenge
/// vector and the service's request digest prefix. The two hashes are the
/// vector's, which the database test checks against what the service
/// stored for the issued challenge.
fn signed_over(vector: &Value, prefix: &[u8], name: &str) -> Vec<u8> {
    let canonical = text(vector, "canonical").as_bytes();
    let message = unhex(text(vector, "message_hex"));
    assert_eq!(message, [prefix, canonical].concat());
    match name {
        "message" => message,
        "challenge_hash" => unhex(text(vector, "challenge_hash")),
        "canonical" => canonical.to_vec(),
        "prefix_without_newline" => [&prefix[..prefix.len() - 1], canonical].concat(),
        "request_digest_prefixed" => [DIGEST_PREFIX, canonical].concat(),
        "request_digest" => unhex(text(vector, "request_digest")),
        other => panic!("unknown signed_over {other}"),
    }
}

/// Every key of the test-key fixture is its seed's, and RFC 8032 test 1
/// signs as the RFC says, with `ed25519-dalek` (no database needed).
#[test]
fn signature_fixture_test_keys_and_rfc_vector() {
    let keys = fixture("recovery.test-key.json");
    assert_eq!(keys["fixture_version"], 1);
    assert_eq!(keys["kind"], "recovery_test_key");
    for key in list(&keys, "keys") {
        test_key(text(key, "name"));
    }
    let signature = fixture("signature.v1.json");
    let rfc = &signature["rfc8032_test1"];
    let signing = test_key(text(rfc, "key"));
    assert_eq!(
        signing
            .sign(&unhex(text(rfc, "message_hex")))
            .to_bytes()
            .to_vec(),
        unhex(text(rfc, "signature"))
    );
    // The RFC key is op_1's new key; the signer is not.
    let (vector, _) = challenge_vector(text(&signature, "challenge_case"));
    let new_key = unhex(text(&vector["plan"], PLAN_NEW_RECOVERY_PUBLIC_KEY));
    assert_eq!(signing.verifying_key().as_bytes().to_vec(), new_key);
    assert_ne!(
        test_key(text(&signature, "signer"))
            .verifying_key()
            .as_bytes()
            .to_vec(),
        new_key
    );
}

/// Every real signature of the fixture is its key's over its bytes, made
/// again by `ed25519-dalek`, independently of the workstation crate (no
/// database needed).
#[test]
fn signature_fixture_signatures_are_remade_independently() {
    let signature = fixture("signature.v1.json");
    let (vector, prefix) = challenge_vector(text(&signature, "challenge_case"));
    let mut remade = 0;
    for case in list(&signature, "cases") {
        let name = text(case, "case");
        let (Some(by), Some(over)) = (case.get("signed_by"), case.get("signed_over")) else {
            continue;
        };
        let bytes = signed_over(&vector, &prefix, over.as_str().unwrap());
        assert_eq!(
            test_key(by.as_str().unwrap())
                .sign(&bytes)
                .to_bytes()
                .to_vec(),
            unhex(text(case, "signature")),
            "{name}"
        );
        remade += 1;
    }
    assert!(remade >= 8, "{remade}");
}

/// The outcome of a preview or a restore, as the fixture's
/// `service_expected` names it: `ok` or `bad_signature`.
fn outcome<T: std::fmt::Debug>(result: &Result<T, RestoreError>, name: &str) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(RestoreError::NotRestorable(NotRestorableReason::BadSignature)) => "bad_signature",
        Err(other) => panic!("{name}: {other:?}"),
    }
}

/// Restores `operation_id` with `signature` at `at`, in a transaction of
/// its own (`READ COMMITTED`, the default): commits on `Ok`, rolls back on
/// every `Err`, as the caller of `restore_operator` must.
async fn restore(
    pool: &PgPool,
    operation_id: &str,
    signature: &[u8],
    event: &str,
    at: SystemTime,
) -> Result<skyoauth_service::persistence::registry::Restored, RestoreError> {
    let mut transaction = pool.begin().await.unwrap();
    let rotation = format!("{event}_rotation");
    let restored = restore_operator(
        &mut transaction,
        &SignedRecoveryResponse {
            operation_id,
            signature,
        },
        &RestoreRequest {
            audit_event_id: event,
            rotation_audit_event_id: &rotation,
            now: at,
        },
    )
    .await;
    match restored {
        Ok(_) => transaction.commit().await.unwrap(),
        Err(_) => transaction.rollback().await.unwrap(),
    }
    restored
}

/// The service issues op_1 to an instance whose recovery key is the test
/// key; the independent signer's signature over the issued `M` is the
/// fixture's `valid` case (the one the workstation's `sign_challenge`
/// returns); every case previews and restores as the fixture says; the
/// valid one restores once.
#[tokio::test]
async fn signature_fixture_cases_through_preview_and_restore() {
    let signature = fixture("signature.v1.json");
    let service_expected = signature["service_expected"]
        .as_object()
        .expect("service_expected");
    let (vector, _) = challenge_vector(text(&signature, "challenge_case"));
    let plan: &Map<String, Value> = vector["plan"].as_object().expect("a plan");
    let plan_value = &vector["plan"];
    let signer = test_key(text(&signature, "signer"));
    let expires_at = UNIX_EPOCH
        + Duration::from_micros(u64::try_from(vector["expires_at"].as_i64().unwrap()).unwrap());
    let issued_at: SystemTime = expires_at - DEFAULT_CHALLENGE_TTL;
    let checked_at = expires_at - Duration::from_secs(1);

    let db = TestDb::create().await;
    let pool = db.pool().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: text(&vector["plan"], PLAN_INSTANCE_ID),
            admin_id: "adm_signature_fixture",
            credential_id: "crd_signature_fixture",
            public_identity: PUBLIC_IDENTITY,
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_signature_fixture",
            recovery_public_key: signer.verifying_key().as_bytes(),
            audit_event_id: "aud_signature_fixture_bootstrap",
            now: issued_at,
        },
    )
    .await
    .unwrap();
    assert_eq!(vector["plan"][PLAN_RECOVERY_KEY_EPOCH], 1);
    let issued = issue_recovery_challenge(
        &mut transaction,
        &IssueChallenge {
            operation_id: text(&vector, "id"),
            kind: OPERATOR_RESTORATION,
            immutable_plan: plan,
            ttl: DEFAULT_CHALLENGE_TTL,
            now: issued_at,
            audit_event_id: "aud_signature_fixture_issue",
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(issued.challenge, unhex(text(&vector, "message_hex")));
    assert_eq!(issued.expires_at, expires_at);
    let (request_digest, challenge_hash): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT request_digest, challenge_hash FROM administrative_operation WHERE id = $1",
    )
    .bind(text(&vector, "id"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(request_digest, unhex(text(&vector, "request_digest")));
    assert_eq!(challenge_hash, Some(unhex(text(&vector, "challenge_hash"))));

    // The signer signs what the service issued: the fixture's `valid`.
    let cases = list(&signature, "cases");
    let valid = cases
        .iter()
        .find(|case| text(case, "expected") == "valid")
        .expect("a valid case");
    let signed = signer.sign(&issued.challenge).to_bytes().to_vec();
    assert_eq!(signed, unhex(text(valid, "signature")));

    // Every case, previewed and restored: only `valid` passes, and a
    // refused restore leaves the challenge for the next one.
    let mut refused = Vec::new();
    for (n, case) in cases.iter().enumerate() {
        let name = text(case, "case");
        if text(case, "expected") == "valid" {
            continue;
        }
        let bytes = unhex(text(case, "signature"));
        let expected = service_expected[text(case, "expected")]
            .as_str()
            .expect("a service outcome");
        assert_eq!(expected, "bad_signature", "{name}");
        let mut transaction = pool.begin().await.unwrap();
        let preview = preview_recovery_response(
            &mut transaction,
            &SignedRecoveryResponse {
                operation_id: &issued.operation_id,
                signature: &bytes,
            },
            checked_at,
        )
        .await;
        transaction.rollback().await.unwrap();
        assert_eq!(outcome(&preview, name), expected, "{name}: preview");
        let restored = restore(
            &pool,
            &issued.operation_id,
            &bytes,
            &format!("aud_signature_fixture_refused_{n}"),
            checked_at,
        )
        .await;
        assert_eq!(outcome(&restored, name), expected, "{name}: restore");
        refused.push(name);
    }
    assert!(refused.len() >= 18, "{refused:?}");
    // The lengths, the malleability and the cofactor cases, each refused:
    // `mixed_order_r` (R = rB + T, T of small order) is one a cofactored
    // verifier would accept and ed25519-dalek's `verify` and
    // `verify_strict` both refuse.
    for name in [
        "length_0",
        "length_63",
        "length_65",
        "length_128",
        "s_plus_l",
        "small_order_r",
        "non_canonical_r",
        "mixed_order_r",
    ] {
        assert!(refused.contains(&name), "{name} is not refused");
    }

    let bytes = unhex(text(valid, "signature"));
    let mut transaction = pool.begin().await.unwrap();
    let preview = preview_recovery_response(
        &mut transaction,
        &SignedRecoveryResponse {
            operation_id: &issued.operation_id,
            signature: &bytes,
        },
        checked_at,
    )
    .await;
    transaction.rollback().await.unwrap();
    assert_eq!(
        outcome(&preview, "valid"),
        service_expected["valid"],
        "valid: preview"
    );
    let preview = preview.unwrap();
    assert_eq!(preview.admin_id, text(plan_value, PLAN_ADMIN_ID));
    assert_eq!(preview.credential_id, text(plan_value, PLAN_CREDENTIAL_ID));
    assert_eq!(preview.binding_id, text(plan_value, PLAN_BINDING_ID));
    assert_eq!(preview.new_recovery_key_epoch, 2);

    let restored = restore(
        &pool,
        &issued.operation_id,
        &bytes,
        "aud_signature_fixture_restore",
        checked_at,
    )
    .await;
    assert_eq!(
        outcome(&restored, "valid"),
        service_expected["valid"],
        "valid: restore"
    );
    let restored = restored.unwrap();
    assert_eq!(restored.admin_id, text(plan_value, PLAN_ADMIN_ID));
    assert_eq!(restored.recovery_key_epoch, 2);
    assert_eq!(
        restored.revoked_credential_ids,
        ["crd_signature_fixture".to_owned()]
    );
    // Once: a replay is refused at the consume.
    let replay = restore(
        &pool,
        &issued.operation_id,
        &bytes,
        "aud_signature_fixture_replay",
        checked_at,
    )
    .await;
    assert!(
        matches!(
            replay,
            Err(RestoreError::NotRestorable(NotRestorableReason::Consumed))
        ),
        "{replay:?}"
    );
    db.drop([pool]).await;
}
