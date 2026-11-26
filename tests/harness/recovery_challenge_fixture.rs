//! The recovery challenge fixture
//! `tests/conformance/fixtures/_recovery/challenge.v1.json` against the
//! service, so that the workstation's writer and reader of `C` and `M`
//! (`skyoauth_operator::recovery`, which `operator/tests/operator.rs`
//! checks against the same file) and the service's cannot drift apart.
//! They test the fixture file, not a scenario: no name here matches
//! `a\d\d_`, and no stage of `tests/conformance/scenarios.toml` lists them
//! (layout §3).
//!
//! - The constants: the kind, the actor, the TTL bounds, the plan's member
//!   names and the request digest prefix are the service's public ones.
//! - `C` and `request_digest` of every vector are the service's
//!   [`DigestEnvelope`] over the vector's inputs (no database needed).
//! - `M`, and with it the challenge prefix, which the service keeps
//!   private, are what [`issue_recovery_challenge`] returns for the op_1
//!   vector on a bootstrapped database, and its `challenge_hash` and
//!   `request_digest` what the issue stored in the operation row.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    operation::{DIGEST_PREFIX, DigestEnvelope},
    persistence::registry::{
        BootstrapRequest, DEFAULT_CHALLENGE_TTL, DEPLOYMENT_OPERATOR_ACTOR, IssueChallenge,
        MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL, OPERATOR_RESTORATION, PLAN_ADMIN_ID, PLAN_BINDING_ID,
        PLAN_CREDENTIAL_ID, PLAN_INSTANCE_ID, PLAN_NEW_RECOVERY_PUBLIC_KEY, PLAN_PUBLIC_IDENTITY,
        PLAN_RECOVERY_KEY_EPOCH, PLAN_TRUST_ANCHOR_REF, bootstrap_instance, get_recovery_state,
        issue_recovery_challenge,
    },
};

/// The recovery key the instance is bootstrapped with: valid, and not the
/// op_1 plan's new key (the key fixture's `valid_all_0x11`).
const BOOTSTRAP_RECOVERY_KEY: [u8; 32] = [0x11; 32];

/// A public identity the bootstrap accepts (the identity fixture's Ed25519
/// case).
const PUBLIC_IDENTITY: &str =
    "spki-sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/fixtures/_recovery/challenge.v1.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string in {value}"))
}

fn integer(value: &Value, name: &str) -> i64 {
    value[name]
        .as_i64()
        .unwrap_or_else(|| panic!("{name} is not an i64 in {value}"))
}

fn vectors(fixture: &Value) -> &[Value] {
    let vectors = fixture["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty(), "no vectors");
    vectors
}

fn plan(vector: &Value) -> &Map<String, Value> {
    vector["plan"].as_object().expect("plan is an object")
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

/// The service's envelope of `vector`: the fixed actor and kind, no
/// tenant, and the vector's inputs.
fn envelope<'a>(vector: &'a Value, plan: &'a Map<String, Value>) -> DigestEnvelope<'a> {
    DigestEnvelope {
        id: text(vector, "id"),
        tenant_id: None,
        actor_id: DEPLOYMENT_OPERATOR_ACTOR,
        kind: OPERATOR_RESTORATION,
        expected_revision: integer(vector, "expected_revision"),
        expires_at_us: integer(vector, "expires_at"),
        plan,
    }
}

#[test]
fn challenge_fixture_constants_are_the_services() {
    let fixture = fixture();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "recovery_challenge");
    assert_eq!(fixture["actor_id"], DEPLOYMENT_OPERATOR_ACTOR);
    assert_eq!(fixture["challenge_kind"], OPERATOR_RESTORATION);
    assert_eq!(
        text(&fixture, "request_digest_prefix").as_bytes(),
        DIGEST_PREFIX
    );
    let ttl = &fixture["ttl_seconds"];
    assert_eq!(ttl["min"], MIN_CHALLENGE_TTL.as_secs());
    assert_eq!(ttl["default"], DEFAULT_CHALLENGE_TTL.as_secs());
    assert_eq!(ttl["max"], MAX_CHALLENGE_TTL.as_secs());
    for ttl in [MIN_CHALLENGE_TTL, DEFAULT_CHALLENGE_TTL, MAX_CHALLENGE_TTL] {
        assert_eq!(ttl.subsec_nanos(), 0, "whole seconds");
    }
    let mut members = [
        PLAN_INSTANCE_ID,
        PLAN_RECOVERY_KEY_EPOCH,
        PLAN_ADMIN_ID,
        PLAN_CREDENTIAL_ID,
        PLAN_BINDING_ID,
        PLAN_PUBLIC_IDENTITY,
        PLAN_TRUST_ANCHOR_REF,
        PLAN_NEW_RECOVERY_PUBLIC_KEY,
    ];
    members.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(fixture["plan_members"], serde_json::json!(members));
}

#[test]
fn challenge_fixture_canonical_json_is_the_services() {
    let fixture = fixture();
    for vector in vectors(&fixture) {
        let name = text(vector, "case");
        let plan = plan(vector);
        let envelope = envelope(vector, plan);
        let canonical = envelope.canonical_json().unwrap();
        assert_eq!(canonical, text(vector, "canonical"), "{name}");
        assert_eq!(
            envelope.digest().unwrap().as_bytes().to_vec(),
            unhex(text(vector, "request_digest")),
            "{name}"
        );
        // `M` is the prefix and `C`; the prefix itself is pinned below.
        assert_eq!(
            unhex(text(vector, "message_hex")),
            [text(&fixture, "prefix").as_bytes(), canonical.as_bytes()].concat(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn challenge_fixture_message_through_issue_recovery_challenge() {
    let fixture = fixture();
    let vector = vectors(&fixture)
        .iter()
        .find(|vector| vector["case"] == "op_1")
        .expect("the op_1 vector");
    let plan = plan(vector);
    let expires_at =
        UNIX_EPOCH + Duration::from_micros(u64::try_from(integer(vector, "expires_at")).unwrap());
    let now: SystemTime = expires_at - DEFAULT_CHALLENGE_TTL;

    let db = TestDb::create().await;
    let pool = db.pool().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: text(&vector["plan"], PLAN_INSTANCE_ID),
            admin_id: "adm_fixture",
            credential_id: "crd_fixture",
            public_identity: PUBLIC_IDENTITY,
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_fixture",
            recovery_public_key: &BOOTSTRAP_RECOVERY_KEY,
            audit_event_id: "aud_fixture_bootstrap",
            now,
        },
    )
    .await
    .unwrap();
    // The state the vector is bound to: its instance, epoch and revision.
    let state = get_recovery_state(&mut *transaction)
        .await
        .unwrap()
        .expect("a recovery state");
    assert_eq!(
        (
            &state.instance_id[..],
            state.recovery_key_epoch,
            state.revision
        ),
        (
            text(&vector["plan"], PLAN_INSTANCE_ID),
            integer(&vector["plan"], PLAN_RECOVERY_KEY_EPOCH),
            integer(vector, "expected_revision")
        )
    );
    let issued = issue_recovery_challenge(
        &mut transaction,
        &IssueChallenge {
            operation_id: text(vector, "id"),
            kind: OPERATOR_RESTORATION,
            immutable_plan: plan,
            ttl: DEFAULT_CHALLENGE_TTL,
            now,
            audit_event_id: "aud_fixture_issue",
        },
    )
    .await
    .unwrap();
    assert_eq!(issued.operation_id, text(vector, "id"));
    assert_eq!(issued.expires_at, expires_at);
    assert_eq!(
        issued.expected_revision,
        integer(vector, "expected_revision")
    );
    assert_eq!(issued.challenge, unhex(text(vector, "message_hex")));
    let prefix = text(&fixture, "prefix").as_bytes();
    assert_eq!(&issued.challenge[..prefix.len()], prefix);
    assert_eq!(
        &issued.challenge[prefix.len()..],
        text(vector, "canonical").as_bytes()
    );
    let (request_digest, challenge_hash): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT request_digest, challenge_hash FROM administrative_operation WHERE id = $1",
    )
    .bind(text(vector, "id"))
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(request_digest, unhex(text(vector, "request_digest")));
    assert_eq!(challenge_hash, Some(unhex(text(vector, "challenge_hash"))));
    transaction.rollback().await.unwrap();
    db.drop([pool]).await;
}
