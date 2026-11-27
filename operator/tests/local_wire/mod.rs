//! The deployment-local transport's wire codec (`skyoauth_operator::local`)
//! against the shared fixture
//! `tests/conformance/fixtures/_wire/local_transport.v1.json`, which the
//! `pg` target of `skyoauth-scenarios` checks against the service
//! (`tests/harness/local_transport_wire.rs`): the golden request lines, the
//! golden replies and refusals, the golden exchange's consistency, every
//! reply the client must take as an unknown outcome, the size limits, the
//! escapes against `serde_json`'s, and the redaction of every type.
//!
//! Portable, like the codec: no socket, the codec has no I/O.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use skyoauth_operator::{
    identity::public_identity_of_spki,
    local::{
        BootstrapRequest, Bootstrapped, CallError, EnrolledState, ErrorCode, IssueChallengeRequest,
        Issued, MAX_REPLY_BYTES, MAX_REQUEST_BYTES, MAX_REVOKED_IDS_PER_REPLY, NotSent, Op,
        OperationState, Previewed, Reply, Request, ResponseRequest, Restored, Status,
        StatusRequest, UnknownOutcome, parse_reply,
    },
    recovery::{
        DEFAULT_CHALLENGE_TTL, Expectations, RecoveryPublicKey, check_challenge, parse_challenge,
    },
};

use crate::support::{fixtures_dir, list, text, unhex};

pub const WIRE_FIXTURE: &str = "local_transport.v1.json";

/// Every unknown outcome the codec gives, with its class in the fixture.
const UNKNOWN_CLASSES: [(UnknownOutcome, &str); 6] = [
    (UnknownOutcome::Truncated, "truncated"),
    (UnknownOutcome::TrailingBytes, "trailing_bytes"),
    (UnknownOutcome::TooLarge, "too_large"),
    (UnknownOutcome::NotUtf8, "not_utf8"),
    (UnknownOutcome::Malformed, "malformed"),
    (UnknownOutcome::UnknownCode, "unknown_code"),
];

/// The reply shapes of the fixture, with the operation each answers.
const SHAPES: [(&str, Option<Op>); 6] = [
    ("bootstrapped", Some(Op::Bootstrap)),
    ("issued", Some(Op::IssueChallenge)),
    ("previewed", Some(Op::Preview)),
    ("restored", Some(Op::Restore)),
    ("status", Some(Op::Status)),
    ("error", None),
];

/// The member types of the fixture's reply shapes; each but `code` may
/// also be written `<type>|null`, a member always present whose value is
/// of that type or `null` (the `status` reply's).
const TYPES: [&str; 5] = ["string", "integer", "hex", "string_list", "code"];

/// The fixture file, parsed.
pub fn wire_fixture() -> Value {
    let path = fixtures_dir().join("_wire").join(WIRE_FIXTURE);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn op_named(name: &str) -> Op {
    Op::ALL
        .into_iter()
        .find(|op| op.as_str() == name)
        .unwrap_or_else(|| panic!("no op {name}"))
}

fn integer(value: &Value, name: &str) -> i64 {
    value[name]
        .as_i64()
        .unwrap_or_else(|| panic!("{name} is not an integer in {value}"))
}

fn owned(value: &Value, name: &str) -> String {
    text(value, name).to_owned()
}

fn key(value: &Value, name: &str) -> RecoveryPublicKey {
    RecoveryPublicKey::from_hex(text(value, name)).unwrap()
}

fn signature(value: &Value) -> [u8; 64] {
    unhex(text(value, "signature")).try_into().unwrap()
}

/// The member `name` of `value`, which must be present: `None` for `null`,
/// else `read` of it.
fn nullable<T>(value: &Value, name: &str, read: impl FnOnce(&Value) -> T) -> Option<T> {
    let member = value
        .get(name)
        .unwrap_or_else(|| panic!("no {name} in {value}"));
    (!member.is_null()).then(|| read(member))
}

fn as_text(value: &Value) -> String {
    value.as_str().unwrap().to_owned()
}

fn as_integer(value: &Value) -> i64 {
    value.as_i64().unwrap()
}

fn as_hex(value: &Value) -> Vec<u8> {
    unhex(value.as_str().unwrap())
}

fn as_ids(value: &Value) -> Vec<String> {
    value.as_array().unwrap().iter().map(as_text).collect()
}

fn operation_state(value: &Value) -> OperationState {
    OperationState::ALL
        .into_iter()
        .find(|state| state.as_str() == value.as_str().unwrap())
        .unwrap_or_else(|| panic!("no operation state {value}"))
}

fn enrolled_state(value: &Value) -> EnrolledState {
    EnrolledState::ALL
        .into_iter()
        .find(|state| state.as_str() == value.as_str().unwrap())
        .unwrap_or_else(|| panic!("no enrolled state {value}"))
}

/// The request of a golden request case (also read by `local_exchange`).
pub fn request_of(case: &Value) -> Request {
    let values = &case["values"];
    let response = || ResponseRequest {
        operation_id: owned(values, "operation_id"),
        signature: signature(values),
    };
    match op_named(text(case, "op")) {
        Op::Bootstrap => Request::Bootstrap(BootstrapRequest {
            instance_id: owned(values, "instance_id"),
            credential_spki: unhex(text(values, "credential_spki")),
            trust_anchor_ref: owned(values, "trust_anchor_ref"),
            recovery_public_key: key(values, "recovery_public_key"),
        }),
        Op::IssueChallenge => Request::IssueChallenge(IssueChallengeRequest {
            credential_spki: unhex(text(values, "credential_spki")),
            trust_anchor_ref: owned(values, "trust_anchor_ref"),
            new_recovery_public_key: key(values, "new_recovery_public_key"),
        }),
        Op::Preview => Request::Preview(response()),
        Op::Restore => Request::Restore(response()),
        Op::Status => Request::Status(StatusRequest {
            operation_id: nullable(values, "operation_id", as_text),
            credential_spki: nullable(values, "credential_spki", as_hex),
            revoked_after: nullable(values, "revoked_after", as_text),
        }),
    }
}

/// The success of shape `shape` with `values`.
fn reply_of(shape: &str, values: &Value) -> Reply {
    match shape {
        "bootstrapped" => Reply::Bootstrapped(Bootstrapped {
            instance_id: owned(values, "instance_id"),
            admin_id: owned(values, "admin_id"),
            credential_id: owned(values, "credential_id"),
            binding_id: owned(values, "binding_id"),
            recovery_key_epoch: integer(values, "recovery_key_epoch"),
        }),
        "issued" => Reply::Issued(Issued {
            operation_id: owned(values, "operation_id"),
            expires_at: integer(values, "expires_at"),
            expected_revision: integer(values, "expected_revision"),
            challenge: unhex(text(values, "challenge")),
        }),
        "previewed" => Reply::Previewed(Previewed {
            admin_id: owned(values, "admin_id"),
            credential_id: owned(values, "credential_id"),
            binding_id: owned(values, "binding_id"),
            new_recovery_key_epoch: integer(values, "new_recovery_key_epoch"),
            expires_at: integer(values, "expires_at"),
        }),
        "restored" => Reply::Restored(Restored {
            admin_id: owned(values, "admin_id"),
            credential_id: owned(values, "credential_id"),
            binding_id: owned(values, "binding_id"),
            revoked_credential_count: integer(values, "revoked_credential_count"),
            revoked_credential_ids: list(values, "revoked_credential_ids")
                .iter()
                .map(|id| id.as_str().unwrap().to_owned())
                .collect(),
            recovery_key_epoch: integer(values, "recovery_key_epoch"),
            recovery_state_revision: integer(values, "recovery_state_revision"),
        }),
        "status" => Reply::Status(Box::new(Status {
            server_time: integer(values, "server_time"),
            instance_id: nullable(values, "instance_id", as_text),
            recovery_key_epoch: nullable(values, "recovery_key_epoch", as_integer),
            recovery_state_revision: nullable(values, "recovery_state_revision", as_integer),
            recovery_public_key: nullable(values, "recovery_public_key", as_hex),
            operation_state: nullable(values, "operation_state", operation_state),
            expires_at: nullable(values, "expires_at", as_integer),
            settles_at: nullable(values, "settles_at", as_integer),
            restored_at: nullable(values, "restored_at", as_integer),
            admin_id: nullable(values, "admin_id", as_text),
            credential_id: nullable(values, "credential_id", as_text),
            binding_id: nullable(values, "binding_id", as_text),
            revoked_credential_count: nullable(values, "revoked_credential_count", as_integer),
            revoked_credential_ids: nullable(values, "revoked_credential_ids", as_ids),
            enrolled_state: nullable(values, "enrolled_state", enrolled_state),
            enrolled_admin_id: nullable(values, "enrolled_admin_id", as_text),
            enrolled_credential_id: nullable(values, "enrolled_credential_id", as_text),
            enrolled_trust_anchor_sha256: nullable(values, "enrolled_trust_anchor_sha256", as_hex),
        })),
        other => panic!("no success shape {other}"),
    }
}

/// The operation a reply shape answers (`None` for a refusal).
fn shape_op(shape: &str) -> Option<Op> {
    SHAPES
        .iter()
        .find(|(name, _)| *name == shape)
        .unwrap_or_else(|| panic!("no shape {shape}"))
        .1
}

/// The member names of `names`, a fixture list of strings or of
/// `[name, type]` pairs.
fn names_of(names: &[Value]) -> Vec<&str> {
    names
        .iter()
        .map(|name| match name {
            Value::String(name) => name.as_str(),
            Value::Array(pair) => pair[0].as_str().unwrap(),
            other => panic!("not a member: {other}"),
        })
        .collect()
}

/// A JSON object line, `members` in their order, each value written by
/// `serde_json` (a writer independent of the crate's), and the newline.
fn line_of(members: &[(&str, Value)]) -> String {
    let members: Vec<String> = members
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{}",
                serde_json::to_string(name).unwrap(),
                serde_json::to_string(value).unwrap()
            )
        })
        .collect();
    format!("{{{}}}\n", members.join(","))
}

/// `values`'s members `names`, in that order.
fn ordered<'a>(values: &Value, names: &[&'a str]) -> Vec<(&'a str, Value)> {
    assert_eq!(
        values.as_object().unwrap().len(),
        names.len(),
        "exactly the members {names:?} in {values}"
    );
    names
        .iter()
        .map(|name| {
            let value = values
                .get(*name)
                .unwrap_or_else(|| panic!("no {name} in {values}"));
            (*name, value.clone())
        })
        .collect()
}

/// The bytes of an unknown reply case: its parts, each `text` or `hex`,
/// `repeat` times (once by default).
fn bytes_of(case: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in list(case, "parts") {
        let piece = match (part.get("text"), part.get("hex")) {
            (Some(text), None) => text.as_str().unwrap().as_bytes().to_vec(),
            (None, Some(hex)) => unhex(hex.as_str().unwrap()),
            _ => panic!("a part is text or hex: {part}"),
        };
        let repeat = part.get("repeat").map_or(1, |n| n.as_u64().unwrap());
        for _ in 0..repeat {
            bytes.extend_from_slice(&piece);
        }
    }
    bytes
}

fn unknown_class(class: &str) -> UnknownOutcome {
    UNKNOWN_CLASSES
        .iter()
        .find(|(_, name)| *name == class)
        .unwrap_or_else(|| panic!("no class {class}"))
        .0
}

fn code_named(name: &str) -> ErrorCode {
    ErrorCode::ALL
        .into_iter()
        .find(|code| code.as_str() == name)
        .unwrap_or_else(|| panic!("no code {name}"))
}

/// The case `name` of the list `cases`.
fn case<'a>(cases: &'a [Value], name: &str) -> &'a Value {
    cases
        .iter()
        .find(|case| text(case, "case") == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

#[test]
fn local_wire_fixture_envelope_matches_the_crate() {
    let fixture = wire_fixture();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "local_transport_wire");
    assert_eq!(fixture["status"], "proposed");
    assert!(text(&fixture, "description").contains("Inferred"));
    let framing = &fixture["framing"];
    assert_eq!(text(framing, "line_end"), "\n");
    assert_eq!(
        framing["max_request_bytes"],
        u64::try_from(MAX_REQUEST_BYTES).unwrap()
    );
    assert_eq!(
        framing["max_reply_bytes"],
        u64::try_from(MAX_REPLY_BYTES).unwrap()
    );
    assert_eq!(
        framing["max_revoked_ids_per_reply"],
        u64::try_from(MAX_REVOKED_IDS_PER_REPLY).unwrap()
    );
    assert_eq!(MAX_REVOKED_IDS_PER_REPLY, 1000);
    assert_eq!(text(&fixture, "op_member"), "op");
    let ops: BTreeSet<&str> = fixture["ops"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(ops, Op::ALL.iter().map(|op| op.as_str()).collect());
    // The closed set, in the service's order.
    let codes: Vec<&str> = list(&fixture, "error_codes")
        .iter()
        .map(|entry| text(entry, "code"))
        .collect();
    let crate_codes: Vec<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
    assert_eq!(codes, crate_codes);
    let mut shown = BTreeSet::new();
    for entry in list(&fixture, "error_codes") {
        let applies = list(entry, "applies_when");
        assert!(
            !applies.is_empty()
                && applies
                    .iter()
                    .all(|s| s.as_str().is_some_and(|s| !s.is_empty())),
            "{entry}"
        );
        let code = code_named(text(entry, "code"));
        assert!(code.to_string().starts_with(code.as_str()), "{code:?}");
        shown.insert(code.to_string());
    }
    assert_eq!(shown.len(), ErrorCode::ALL.len());
    // The reply shapes: each success answers its op, in the crate's shapes.
    let replies = fixture["replies"].as_object().unwrap();
    assert_eq!(
        replies.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        SHAPES.iter().map(|(name, _)| *name).collect()
    );
    for (name, op) in SHAPES {
        let shape = &replies[name];
        assert_eq!(
            shape.get("op").and_then(Value::as_str),
            op.map(Op::as_str),
            "{name}"
        );
        let types: BTreeSet<&str> = list(shape, "members")
            .iter()
            .map(|pair| pair[1].as_str().unwrap())
            .collect();
        let known = |kind: &str| {
            TYPES.contains(&kind)
                || kind
                    .strip_suffix("|null")
                    .is_some_and(|base| base != "code" && TYPES.contains(&base))
        };
        assert!(types.iter().all(|kind| known(kind)), "{name}: {types:?}");
        // Only the status reply has nullable members; all of its members
        // but the first are.
        let nullable: Vec<bool> = list(shape, "members")
            .iter()
            .map(|pair| pair[1].as_str().unwrap().ends_with("|null"))
            .collect();
        if op == Some(Op::Status) {
            assert!(!nullable[0] && nullable[1..].iter().all(|n| *n), "{name}");
        } else {
            assert!(nullable.iter().all(|n| !n), "{name}");
        }
    }
}

/// Runs every golden request: its values encode to exactly its line, which
/// is also `serde_json`'s writing of the op and the members in the
/// fixture's order. Returns the names.
fn run_golden_requests(fixture: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for case in list(fixture, "golden_requests") {
        let name = text(case, "case");
        let request = request_of(case);
        let op = op_named(text(case, "op"));
        assert_eq!(request.op(), op, "{name}");
        let line = request
            .encode()
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        let golden = text(case, "line");
        assert_eq!(
            String::from_utf8(line.as_bytes().to_vec()).unwrap(),
            golden,
            "{name}"
        );
        // One line: its newline is its last byte and its only one.
        assert_eq!(line.as_bytes().iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(line.as_bytes().last(), Some(&b'\n'));
        let members = names_of(list(&fixture["ops"], op.as_str()));
        let mut expected = vec![(text(fixture, "op_member"), Value::from(op.as_str()))];
        expected.extend(ordered(&case["values"], &members));
        assert_eq!(line_of(&expected), golden, "{name}");
        names.push(name.to_owned());
    }
    names
}

#[test]
fn golden_requests_encode_to_their_lines() {
    let fixture = wire_fixture();
    let names = run_golden_requests(&fixture);
    // Every op has a golden line.
    let ops: BTreeSet<&str> = list(&fixture, "golden_requests")
        .iter()
        .map(|case| text(case, "op"))
        .collect();
    assert_eq!(ops.len(), Op::ALL.len(), "{names:?}");
}

/// Runs every golden reply: a success parses to its values for its op and
/// is malformed for any other op; a refusal is refused with its code for
/// every op. The line is `serde_json`'s writing of the values in the
/// shape's order. Returns the names.
fn run_golden_replies(fixture: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for case in list(fixture, "golden_replies") {
        let name = text(case, "case");
        let shape = text(case, "reply");
        let line = text(case, "line");
        let members = names_of(list(&fixture["replies"][shape], "members"));
        assert_eq!(line_of(&ordered(&case["values"], &members)), line, "{name}");
        match shape_op(shape) {
            Some(op) => {
                let expected = reply_of(shape, &case["values"]);
                assert_eq!(expected.op(), op, "{name}");
                assert_eq!(parse_reply(op, line.as_bytes()), Ok(expected), "{name}");
                for other in Op::ALL.into_iter().filter(|other| *other != op) {
                    assert_eq!(
                        parse_reply(other, line.as_bytes()),
                        Err(CallError::Unknown(UnknownOutcome::Malformed)),
                        "{name} for {other:?}"
                    );
                }
            }
            None => {
                let code = code_named(text(&case["values"], "error"));
                for op in Op::ALL {
                    assert_eq!(
                        parse_reply(op, line.as_bytes()),
                        Err(CallError::Refused(code)),
                        "{name} for {op:?}"
                    );
                }
            }
        }
        names.push(name.to_owned());
    }
    names
}

#[test]
fn golden_replies_parse_to_their_values() {
    let fixture = wire_fixture();
    run_golden_replies(&fixture);
    // Every shape has a golden line, and every code a golden refusal.
    let cases = list(&fixture, "golden_replies");
    let shapes: BTreeSet<&str> = cases.iter().map(|case| text(case, "reply")).collect();
    assert_eq!(shapes, SHAPES.iter().map(|(name, _)| *name).collect());
    let codes: Vec<ErrorCode> = cases
        .iter()
        .filter(|case| text(case, "reply") == "error")
        .map(|case| code_named(text(&case["values"], "error")))
        .collect();
    assert_eq!(codes, ErrorCode::ALL);
}

/// Runs every unknown reply: the codec classifies it as the fixture says,
/// and it is not a golden line of its op. Returns the names.
fn run_unknown_replies(fixture: &Value) -> Vec<String> {
    let golden: Vec<(Option<Op>, String)> = list(fixture, "golden_replies")
        .iter()
        .map(|case| (shape_op(text(case, "reply")), owned(case, "line")))
        .collect();
    let mut names = Vec::new();
    for case in list(fixture, "unknown_replies") {
        let name = text(case, "case");
        let op = op_named(text(case, "op"));
        let bytes = bytes_of(case);
        for (answers, line) in &golden {
            if answers.is_none_or(|answers| answers == op) {
                assert_ne!(bytes, line.as_bytes(), "{name} is a golden line of {op:?}");
            }
        }
        let expected = unknown_class(text(case, "expected"));
        assert_eq!(
            parse_reply(op, &bytes),
            Err(CallError::Unknown(expected)),
            "{name}"
        );
        names.push(name.to_owned());
    }
    names
}

#[test]
fn unknown_replies_are_unknown() {
    let fixture = wire_fixture();
    run_unknown_replies(&fixture);
    let classes: BTreeSet<&str> = list(&fixture, "unknown_replies")
        .iter()
        .map(|case| text(case, "expected"))
        .collect();
    assert_eq!(
        classes,
        UNKNOWN_CLASSES.iter().map(|(_, name)| *name).collect()
    );
}

/// The golden exchange holds together as the service's: the issued `M` is
/// a challenge `parse_challenge` and `check_challenge` accept for the
/// bootstrapped instance and epoch, the issued replacement and key, at the
/// exchange's time; its reply members are `M`'s; the signature verifies
/// under the bootstrap recovery key; the preview and the restore name the
/// plan's replacement, the next epoch and revision, and revoke the first
/// operator's credential; the replay and the second bootstrap are refused.
/// The `status` steps: before the bootstrap, nothing; after it, the
/// bootstrap's instance, recovery key and mTLS key enrolled with the
/// SHA-256 of its trust anchor reference (the bootstrap reconcile all
/// equal); after the restore, `restored` with the restore's replacement,
/// count and page, then an empty page after its last ID.
#[test]
fn the_golden_exchange_holds_together() {
    let fixture = wire_fixture();
    let requests = list(&fixture, "golden_requests");
    let replies = list(&fixture, "golden_replies");
    let exchange = &fixture["exchange"];
    let now = integer(exchange, "now_micros");
    assert_eq!(
        exchange["challenge_ttl_seconds"],
        DEFAULT_CHALLENGE_TTL.as_secs()
    );
    let ttl = integer(exchange, "challenge_ttl_seconds") * 1_000_000;
    let mut outcomes = Vec::new();
    for step in list(exchange, "steps") {
        let request = case(requests, text(step, "request"));
        let reply = case(replies, text(step, "reply"));
        let op = op_named(text(request, "op"));
        let outcome = parse_reply(op, text(reply, "line").as_bytes());
        outcomes.push((request_of(request), outcome));
    }
    let [
        (Request::Status(asked_nothing), Ok(Reply::Status(nothing))),
        (Request::Bootstrap(bootstrap), Ok(Reply::Bootstrapped(bootstrapped))),
        (Request::Status(asked_key), Ok(Reply::Status(enrolled))),
        (Request::IssueChallenge(issue), Ok(Reply::Issued(issued))),
        (Request::Preview(preview), Ok(Reply::Previewed(previewed))),
        (Request::Restore(restore), Ok(Reply::Restored(restored))),
        (Request::Status(asked_operation), Ok(Reply::Status(after_restore))),
        (Request::Status(asked_next), Ok(Reply::Status(next_page))),
        (Request::Restore(replay), Err(CallError::Refused(ErrorCode::NotRestorable))),
        (Request::Bootstrap(again), Err(CallError::Refused(ErrorCode::Conflict))),
    ] = outcomes.as_slice()
    else {
        panic!("the steps: {outcomes:?}");
    };
    // Before the bootstrap: nothing asked, nothing there.
    assert!(*asked_nothing == StatusRequest::default());
    assert!(
        **nothing
            == Status {
                server_time: now,
                ..empty_status()
            }
    );
    // After it: the bootstrap reconcile's members all equal the request's.
    assert!(
        *asked_key
            == StatusRequest {
                credential_spki: Some(bootstrap.credential_spki.clone()),
                ..StatusRequest::default()
            }
    );
    assert!(
        **enrolled
            == Status {
                server_time: now,
                instance_id: Some(bootstrap.instance_id.clone()),
                recovery_key_epoch: Some(bootstrapped.recovery_key_epoch),
                recovery_state_revision: Some(issued.expected_revision),
                recovery_public_key: Some(bootstrap.recovery_public_key.as_bytes().to_vec()),
                enrolled_state: Some(EnrolledState::Enabled),
                enrolled_admin_id: Some(bootstrapped.admin_id.clone()),
                enrolled_credential_id: Some(bootstrapped.credential_id.clone()),
                enrolled_trust_anchor_sha256: Some(
                    Sha256::digest(bootstrap.trust_anchor_ref.as_bytes()).to_vec()
                ),
                ..empty_status()
            }
    );
    assert_eq!(bootstrapped.instance_id, bootstrap.instance_id);
    let challenge = parse_challenge(&issued.challenge).unwrap();
    assert_eq!(challenge.operation_id(), issued.operation_id);
    assert_eq!(challenge.expires_at_micros(), issued.expires_at);
    assert_eq!(challenge.expected_revision(), issued.expected_revision);
    assert_eq!(issued.expires_at, now + ttl);
    let identity = public_identity_of_spki(&issue.credential_spki).unwrap();
    let verified = check_challenge(
        &challenge,
        &Expectations {
            instance_id: &bootstrap.instance_id,
            now_micros: now,
            recovery_key_epoch: Some(bootstrapped.recovery_key_epoch),
            replacement_public_identity: Some(&identity),
            trust_anchor_ref: Some(&issue.trust_anchor_ref),
            new_recovery_public_key: Some(&issue.new_recovery_public_key),
        },
    )
    .unwrap();
    let plan = challenge.plan();
    assert_eq!(plan.trust_anchor_ref, issue.trust_anchor_ref);
    for response in [preview, restore, replay] {
        assert_eq!(response.operation_id, issued.operation_id);
        let key = VerifyingKey::from_bytes(bootstrap.recovery_public_key.as_bytes()).unwrap();
        key.verify_strict(
            verified.message(),
            &Signature::from_bytes(&response.signature),
        )
        .unwrap();
    }
    assert_eq!(
        (
            &previewed.admin_id,
            &previewed.credential_id,
            &previewed.binding_id
        ),
        (&plan.admin_id, &plan.credential_id, &plan.binding_id)
    );
    assert_eq!(
        previewed.new_recovery_key_epoch,
        bootstrapped.recovery_key_epoch + 1
    );
    assert_eq!(previewed.expires_at, issued.expires_at);
    assert_eq!(
        (
            &restored.admin_id,
            &restored.credential_id,
            &restored.binding_id
        ),
        (&plan.admin_id, &plan.credential_id, &plan.binding_id)
    );
    assert_eq!(
        restored.revoked_credential_ids,
        std::slice::from_ref(&bootstrapped.credential_id)
    );
    assert_eq!(
        restored.recovery_key_epoch,
        previewed.new_recovery_key_epoch
    );
    assert_eq!(
        restored.recovery_state_revision,
        issued.expected_revision + 1
    );
    assert_eq!(restored.revoked_credential_count, 1);
    // After the restore: restored, with what the restore's reply said.
    assert!(
        *asked_operation
            == StatusRequest {
                operation_id: Some(issued.operation_id.clone()),
                ..StatusRequest::default()
            }
    );
    let restored_status = Status {
        server_time: now,
        instance_id: Some(bootstrap.instance_id.clone()),
        recovery_key_epoch: Some(restored.recovery_key_epoch),
        recovery_state_revision: Some(restored.recovery_state_revision),
        recovery_public_key: Some(issue.new_recovery_public_key.as_bytes().to_vec()),
        operation_state: Some(OperationState::Restored),
        expires_at: Some(issued.expires_at),
        restored_at: Some(now),
        admin_id: Some(restored.admin_id.clone()),
        credential_id: Some(restored.credential_id.clone()),
        binding_id: Some(restored.binding_id.clone()),
        revoked_credential_count: Some(restored.revoked_credential_count),
        revoked_credential_ids: Some(restored.revoked_credential_ids.clone()),
        ..empty_status()
    };
    assert!(**after_restore == restored_status);
    // The next page after the last ID held: empty.
    assert!(
        *asked_next
            == StatusRequest {
                operation_id: Some(issued.operation_id.clone()),
                revoked_after: restored.revoked_credential_ids.last().cloned(),
                ..StatusRequest::default()
            }
    );
    assert!(
        **next_page
            == Status {
                revoked_credential_ids: Some(Vec::new()),
                ..restored_status
            }
    );
    assert_eq!(again, bootstrap);
}

/// A `status` reply with every member `null` but `server_time`, which is 0.
fn empty_status() -> Status {
    Status {
        server_time: 0,
        instance_id: None,
        recovery_key_epoch: None,
        recovery_state_revision: None,
        recovery_public_key: None,
        operation_state: None,
        expires_at: None,
        settles_at: None,
        restored_at: None,
        admin_id: None,
        credential_id: None,
        binding_id: None,
        revoked_credential_count: None,
        revoked_credential_ids: None,
        enrolled_state: None,
        enrolled_admin_id: None,
        enrolled_credential_id: None,
        enrolled_trust_anchor_sha256: None,
    }
}

/// A request line of exactly [`MAX_REQUEST_BYTES`] with its newline is
/// encoded; one byte more is [`NotSent::TooLarge`], for every op.
#[test]
fn the_request_limit_is_64_kib_with_the_newline() {
    assert_eq!(MAX_REQUEST_BYTES, 65_536);
    let key = RecoveryPublicKey::from_hex(
        "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
    )
    .unwrap();
    let make: [&dyn Fn(String) -> Request; 7] = [
        &|text| {
            Request::Bootstrap(BootstrapRequest {
                instance_id: text,
                credential_spki: vec![0x30],
                trust_anchor_ref: "t".into(),
                recovery_public_key: key,
            })
        },
        &|text| {
            Request::Bootstrap(BootstrapRequest {
                instance_id: "i".into(),
                credential_spki: vec![0x30],
                trust_anchor_ref: text,
                recovery_public_key: key,
            })
        },
        &|text| {
            Request::IssueChallenge(IssueChallengeRequest {
                credential_spki: vec![0x30],
                trust_anchor_ref: text,
                new_recovery_public_key: key,
            })
        },
        &|text| {
            Request::Preview(ResponseRequest {
                operation_id: text,
                signature: [7; 64],
            })
        },
        &|text| {
            Request::Restore(ResponseRequest {
                operation_id: text,
                signature: [7; 64],
            })
        },
        &|text| {
            Request::Status(StatusRequest {
                operation_id: Some(text),
                ..StatusRequest::default()
            })
        },
        &|text| {
            Request::Status(StatusRequest {
                operation_id: Some("o".into()),
                credential_spki: Some(vec![0x30]),
                revoked_after: Some(text),
            })
        },
    ];
    for make in make {
        let base = make(String::new()).encode().unwrap().as_bytes().len();
        let fill = MAX_REQUEST_BYTES - base;
        let under = make("x".repeat(fill - 1)).encode().unwrap();
        assert_eq!(under.as_bytes().len(), MAX_REQUEST_BYTES - 1);
        let at_limit = make("x".repeat(fill)).encode().unwrap();
        assert_eq!(at_limit.as_bytes().len(), MAX_REQUEST_BYTES);
        let over = make("x".repeat(fill + 1));
        assert_eq!(over.encode(), Err(NotSent::TooLarge), "{over:?}");
        assert_eq!(
            CallError::from(NotSent::TooLarge),
            CallError::NotSent(NotSent::TooLarge)
        );
    }
    // The DER's hexadecimal counts twice its bytes.
    let spki = |length: usize| {
        Request::IssueChallenge(IssueChallengeRequest {
            credential_spki: vec![0xab; length],
            trust_anchor_ref: "t".into(),
            new_recovery_public_key: key,
        })
    };
    let base = spki(0).encode().unwrap().as_bytes().len();
    let bytes = (MAX_REQUEST_BYTES - base) / 2;
    let largest = spki(bytes).encode().unwrap().as_bytes().len();
    assert_eq!(largest, base + 2 * bytes);
    assert_eq!(
        spki(bytes - 1).encode().unwrap().as_bytes().len(),
        largest - 2
    );
    assert!(largest + 1 >= MAX_REQUEST_BYTES, "{largest}");
    assert_eq!(spki(bytes + 1).encode(), Err(NotSent::TooLarge));
}

/// A bootstrap whose credential fills the line to the limit (some 32 KiB
/// of DER, twice that in hexadecimal) is encoded; one byte more of DER is
/// [`NotSent::TooLarge`]. The bootstrap twin of the credential case of
/// `the_request_limit_is_64_kib_with_the_newline`.
#[test]
fn a_bootstrap_credential_up_to_the_request_limit_is_encoded() {
    let key = RecoveryPublicKey::from_hex(
        "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
    )
    .unwrap();
    // The DER's hexadecimal counts twice its bytes.
    let spki = |length: usize| {
        Request::Bootstrap(BootstrapRequest {
            instance_id: "i".into(),
            credential_spki: vec![0xab; length],
            trust_anchor_ref: "t".into(),
            recovery_public_key: key,
        })
    };
    let base = spki(0).encode().unwrap().as_bytes().len();
    let bytes = (MAX_REQUEST_BYTES - base) / 2;
    assert!(bytes > 30_000, "{bytes}");
    let largest = spki(bytes).encode().unwrap().as_bytes().len();
    assert_eq!(largest, base + 2 * bytes);
    assert_eq!(
        spki(bytes - 1).encode().unwrap().as_bytes().len(),
        largest - 2
    );
    assert!(largest + 1 >= MAX_REQUEST_BYTES, "{largest}");
    assert_eq!(spki(bytes + 1).encode(), Err(NotSent::TooLarge));
}

/// A request whose values alone are longer than [`MAX_REQUEST_BYTES`] is
/// [`NotSent::TooLarge`] (the encoder refuses it before building its line;
/// the hexadecimal of the largest credential here would be 32 times the
/// limit), and so is one whose values alone are exactly at the limit,
/// refused by its encoded length. The boundary of a line that fits is
/// `the_request_limit_is_64_kib_with_the_newline`'s.
#[test]
fn oversized_values_are_refused_before_the_line_is_built() {
    const LARGE: usize = 16 * MAX_REQUEST_BYTES;
    let key = RecoveryPublicKey::from_hex(
        "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
    )
    .unwrap();
    let bootstrap = |instance_id: usize, spki: usize, anchor: usize| {
        Request::Bootstrap(BootstrapRequest {
            instance_id: "i".repeat(instance_id),
            credential_spki: vec![0xab; spki],
            trust_anchor_ref: "t".repeat(anchor),
            recovery_public_key: key,
        })
    };
    let issue = |spki: usize, anchor: usize| {
        Request::IssueChallenge(IssueChallengeRequest {
            credential_spki: vec![0xab; spki],
            trust_anchor_ref: "t".repeat(anchor),
            new_recovery_public_key: key,
        })
    };
    let preview = |operation_id: usize| {
        Request::Preview(ResponseRequest {
            operation_id: "o".repeat(operation_id),
            signature: [7; 64],
        })
    };
    let restore = |operation_id: usize| {
        Request::Restore(ResponseRequest {
            operation_id: "o".repeat(operation_id),
            signature: [7; 64],
        })
    };
    let status = |operation_id: usize, spki: usize, after: usize| {
        Request::Status(StatusRequest {
            operation_id: Some("o".repeat(operation_id)),
            credential_spki: Some(vec![0xab; spki]),
            revoked_after: Some("r".repeat(after)),
        })
    };
    let half = MAX_REQUEST_BYTES / 2;
    let early = [
        bootstrap(1, LARGE, 1),
        issue(LARGE, 1),
        bootstrap(LARGE, 1, 1),
        bootstrap(1, 1, LARGE),
        issue(1, LARGE),
        preview(LARGE),
        restore(LARGE),
        status(LARGE, 0, 0),
        status(0, LARGE, 0),
        status(0, 0, LARGE),
        // The values alone one byte over the limit.
        bootstrap(1, half, 0),
        bootstrap(0, half, 1),
        issue(half, 1),
        bootstrap(0, 0, MAX_REQUEST_BYTES + 1),
        issue(0, MAX_REQUEST_BYTES + 1),
        preview(MAX_REQUEST_BYTES + 1),
        restore(MAX_REQUEST_BYTES + 1),
        status(1, half, 0),
        status(0, half, 1),
        status(MAX_REQUEST_BYTES, 0, 1),
    ];
    for request in early {
        assert_eq!(request.encode(), Err(NotSent::TooLarge), "{request:?}");
    }
    // The values alone exactly at the limit: too large once encoded.
    for request in [
        bootstrap(0, half, 0),
        issue(half, 0),
        preview(MAX_REQUEST_BYTES),
        restore(MAX_REQUEST_BYTES),
        status(0, half, 0),
        status(MAX_REQUEST_BYTES, 0, 0),
    ] {
        assert_eq!(request.encode(), Err(NotSent::TooLarge), "{request:?}");
    }
}

/// Every string a request carries is escaped as `serde_json` escapes it,
/// so the line is one line whatever the values hold: every character
/// below U+0080, U+007F and non-ASCII ones included.
#[test]
fn request_strings_are_escaped_as_serde_json_escapes_them() {
    let mut every: String = (0..0x80u8).map(char::from).collect();
    every.push_str("\u{85}\u{a0}\u{e9}\u{2028}\u{1f511}");
    let key = RecoveryPublicKey::from_hex(
        "2012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7",
    )
    .unwrap();
    let requests = [
        Request::Bootstrap(BootstrapRequest {
            instance_id: every.clone(),
            credential_spki: vec![0, 1, 0xfe, 0xff],
            trust_anchor_ref: every.clone(),
            recovery_public_key: key,
        }),
        Request::Restore(ResponseRequest {
            operation_id: every.clone(),
            signature: [0xff; 64],
        }),
        Request::Status(StatusRequest {
            operation_id: Some(every.clone()),
            credential_spki: Some(vec![0, 1, 0xfe, 0xff]),
            revoked_after: Some(every.clone()),
        }),
        Request::Status(StatusRequest::default()),
    ];
    let [bootstrap, restore, status, empty] = &requests;
    let expected = [
        line_of(&[
            ("op", "bootstrap".into()),
            ("instance_id", every.clone().into()),
            ("credential_spki", "0001feff".into()),
            ("trust_anchor_ref", every.clone().into()),
            ("recovery_public_key", key.to_hex().into()),
        ]),
        line_of(&[
            ("op", "restore".into()),
            ("operation_id", every.clone().into()),
            ("signature", "ff".repeat(64).into()),
        ]),
        line_of(&[
            ("op", "status".into()),
            ("operation_id", every.clone().into()),
            ("credential_spki", "0001feff".into()),
            ("revoked_after", every.clone().into()),
        ]),
        line_of(&[
            ("op", "status".into()),
            ("operation_id", Value::Null),
            ("credential_spki", Value::Null),
            ("revoked_after", Value::Null),
        ]),
    ];
    for (request, expected) in [bootstrap, restore, status, empty]
        .into_iter()
        .zip(expected)
    {
        let line = request.encode().unwrap();
        assert_eq!(
            String::from_utf8(line.as_bytes().to_vec()).unwrap(),
            expected
        );
        let body = &line.as_bytes()[..line.as_bytes().len() - 1];
        assert!(body.iter().all(|byte| *byte >= 0x20), "{request:?}");
    }
}

/// Replies with every escape the service's writer uses, non-ASCII text,
/// an empty and a longer list, and the extremes of `i64` parse to their
/// values; the line is `serde_json`'s writing.
#[test]
fn replies_with_escapes_lists_and_extremes_parse() {
    let mut every: String = (0..0x80u8).map(char::from).collect();
    every.push_str("\u{85}\u{e9}\u{2028}\u{1f511}");
    let restored = |count: i64, revoked: &[&str], epoch: i64, revision: i64| {
        let line = line_of(&[
            ("admin_id", every.clone().into()),
            ("credential_id", "c".into()),
            ("binding_id", "".into()),
            ("revoked_credential_count", count.into()),
            ("revoked_credential_ids", revoked.into()),
            ("recovery_key_epoch", epoch.into()),
            ("recovery_state_revision", revision.into()),
        ]);
        let expected = Reply::Restored(Restored {
            admin_id: every.clone(),
            credential_id: "c".into(),
            binding_id: String::new(),
            revoked_credential_count: count,
            revoked_credential_ids: revoked.iter().map(|id| (*id).to_owned()).collect(),
            recovery_key_epoch: epoch,
            recovery_state_revision: revision,
        });
        (line, expected)
    };
    // The IDs in byte order, the only order the parser takes.
    let mut sorted = vec!["a", every.as_str(), "\"", ""];
    sorted.sort_unstable();
    for (line, expected) in [
        restored(i64::MIN, &[], i64::MAX, i64::MIN),
        // The parser does not check the list against the count.
        restored(i64::MAX, &sorted, 0, -1),
    ] {
        assert_eq!(
            parse_reply(Op::Restore, line.as_bytes()),
            Ok(expected),
            "{line}"
        );
    }
    // A status reply: every nullable member with a value at its extreme, or
    // with escapes, then every one null.
    let status = Status {
        server_time: i64::MIN,
        instance_id: Some(every.clone()),
        recovery_key_epoch: Some(i64::MAX),
        recovery_state_revision: Some(-1),
        recovery_public_key: Some(vec![0, 0xff]),
        operation_state: Some(OperationState::Expiring),
        expires_at: Some(0),
        settles_at: Some(i64::MAX),
        restored_at: Some(i64::MIN),
        admin_id: Some(String::new()),
        credential_id: Some("\"".into()),
        binding_id: Some(every.clone()),
        revoked_credential_count: Some(0),
        revoked_credential_ids: Some(sorted.iter().map(|id| (*id).to_owned()).collect()),
        enrolled_state: Some(EnrolledState::Disabled),
        enrolled_admin_id: Some(every.clone()),
        enrolled_credential_id: Some(String::new()),
        enrolled_trust_anchor_sha256: Some(Vec::new()),
    };
    let line = line_of(&[
        ("server_time", i64::MIN.into()),
        ("instance_id", every.clone().into()),
        ("recovery_key_epoch", i64::MAX.into()),
        ("recovery_state_revision", (-1).into()),
        ("recovery_public_key", "00ff".into()),
        ("operation_state", "expiring".into()),
        ("expires_at", 0.into()),
        ("settles_at", i64::MAX.into()),
        ("restored_at", i64::MIN.into()),
        ("admin_id", "".into()),
        ("credential_id", "\"".into()),
        ("binding_id", every.clone().into()),
        ("revoked_credential_count", 0.into()),
        ("revoked_credential_ids", sorted.clone().into()),
        ("enrolled_state", "disabled".into()),
        ("enrolled_admin_id", every.clone().into()),
        ("enrolled_credential_id", "".into()),
        ("enrolled_trust_anchor_sha256", "".into()),
    ]);
    assert_eq!(
        parse_reply(Op::Status, line.as_bytes()),
        Ok(Reply::Status(Box::new(status)))
    );
    let nulls = line_of(&[
        ("server_time", 0.into()),
        ("instance_id", Value::Null),
        ("recovery_key_epoch", Value::Null),
        ("recovery_state_revision", Value::Null),
        ("recovery_public_key", Value::Null),
        ("operation_state", Value::Null),
        ("expires_at", Value::Null),
        ("settles_at", Value::Null),
        ("restored_at", Value::Null),
        ("admin_id", Value::Null),
        ("credential_id", Value::Null),
        ("binding_id", Value::Null),
        ("revoked_credential_count", Value::Null),
        ("revoked_credential_ids", Value::Null),
        ("enrolled_state", Value::Null),
        ("enrolled_admin_id", Value::Null),
        ("enrolled_credential_id", Value::Null),
        ("enrolled_trust_anchor_sha256", Value::Null),
    ]);
    assert_eq!(
        parse_reply(Op::Status, nulls.as_bytes()),
        Ok(Reply::Status(Box::new(empty_status())))
    );
    // Every state value is read.
    for state in OperationState::ALL {
        let line = nulls.replace(
            "\"operation_state\":null",
            &format!("\"operation_state\":\"{}\"", state.as_str()),
        );
        assert!(
            matches!(
                parse_reply(Op::Status, line.as_bytes()),
                Ok(Reply::Status(read)) if read.operation_state == Some(state)
            ),
            "{state:?}"
        );
    }
    for state in EnrolledState::ALL {
        let line = nulls.replace(
            "\"enrolled_state\":null",
            &format!("\"enrolled_state\":\"{}\"", state.as_str()),
        );
        assert!(
            matches!(
                parse_reply(Op::Status, line.as_bytes()),
                Ok(Reply::Status(read)) if read.enrolled_state == Some(state)
            ),
            "{state:?}"
        );
    }
    let issued = line_of(&[
        ("operation_id", "o".into()),
        ("expires_at", i64::MIN.into()),
        ("expected_revision", i64::MAX.into()),
        ("challenge", "".into()),
    ]);
    assert_eq!(
        parse_reply(Op::IssueChallenge, issued.as_bytes()),
        Ok(Reply::Issued(Issued {
            operation_id: "o".into(),
            expires_at: i64::MIN,
            expected_revision: i64::MAX,
            challenge: Vec::new(),
        }))
    );
}

/// A reply line of exactly [`MAX_REPLY_BYTES`] with its newline is read;
/// one over it is [`UnknownOutcome::TooLarge`], however well formed.
#[test]
fn the_reply_cap_is_4_mib_with_the_newline() {
    assert_eq!(MAX_REPLY_BYTES, 4_194_304);
    let issued = |operation_id: &str, digits: usize| {
        line_of(&[
            ("operation_id", operation_id.into()),
            ("expires_at", 1.into()),
            ("expected_revision", 1.into()),
            ("challenge", "ab".repeat(digits / 2).into()),
        ])
    };
    let base = issued("o", 0).len();
    // An even number of digits fills the line to the cap, with an
    // operation ID of the right parity.
    let operation_id = if (MAX_REPLY_BYTES - base).is_multiple_of(2) {
        "o"
    } else {
        "op"
    };
    let digits = MAX_REPLY_BYTES - issued(operation_id, 0).len();
    let at_cap = issued(operation_id, digits);
    assert_eq!(at_cap.len(), MAX_REPLY_BYTES);
    assert!(matches!(
        parse_reply(Op::IssueChallenge, at_cap.as_bytes()),
        Ok(Reply::Issued(issued)) if issued.challenge.len() == digits / 2
    ));
    let over = issued(operation_id, digits + 2);
    assert_eq!(over.len(), MAX_REPLY_BYTES + 2);
    assert_eq!(
        parse_reply(Op::IssueChallenge, over.as_bytes()),
        Err(CallError::Unknown(UnknownOutcome::TooLarge))
    );
    let mut one_over = at_cap.into_bytes();
    one_over.insert(0, b' ');
    assert_eq!(
        parse_reply(Op::IssueChallenge, &one_over),
        Err(CallError::Unknown(UnknownOutcome::TooLarge))
    );
}

/// A restore reply or a `status` page of exactly
/// [`MAX_REVOKED_IDS_PER_REPLY`] revoked IDs, in byte order, is read (the
/// count beyond it: the rest is paged by `status`); one more ID is
/// malformed, an unknown outcome, and so is a reply up to the reply cap of
/// empty strings. The parser checks the bound and the order within the
/// reply only, not the list against the count.
#[test]
fn a_reply_lists_at_most_a_page_of_revoked_ids() {
    let ids = |n: usize| -> Vec<String> {
        (1..=n)
            .map(|n| format!("cred_0000000000000g{n:012}"))
            .collect()
    };
    let restored = |revoked: &[String]| {
        line_of(&[
            ("admin_id", "adm_0000000000000g000000000001".into()),
            ("credential_id", "cred_0000000000000g000000009999".into()),
            ("binding_id", "role_0000000000000g000000000002".into()),
            ("revoked_credential_count", 2001.into()),
            ("revoked_credential_ids", revoked.into()),
            ("recovery_key_epoch", 2.into()),
            ("recovery_state_revision", 3.into()),
        ])
    };
    let page = ids(MAX_REVOKED_IDS_PER_REPLY);
    let line = restored(&page);
    assert!(line.len() < 64 * 1024, "{}", line.len());
    assert_eq!(
        parse_reply(Op::Restore, line.as_bytes()),
        Ok(Reply::Restored(Restored {
            admin_id: "adm_0000000000000g000000000001".into(),
            credential_id: "cred_0000000000000g000000009999".into(),
            binding_id: "role_0000000000000g000000000002".into(),
            revoked_credential_count: 2001,
            revoked_credential_ids: page.clone(),
            recovery_key_epoch: 2,
            recovery_state_revision: 3,
        }))
    );
    let malformed = Err(CallError::Unknown(UnknownOutcome::Malformed));
    let over = ids(MAX_REVOKED_IDS_PER_REPLY + 1);
    assert_eq!(
        parse_reply(Op::Restore, restored(&over).as_bytes()),
        malformed
    );
    // Out of order or repeated anywhere in the page: the last two swapped,
    // the first repeated at the end, the last repeated right after itself.
    let mut swapped = page.clone();
    swapped.swap(998, 999);
    let mut repeated = page[..999].to_vec();
    repeated.push(page[0].clone());
    let mut twice = page[..999].to_vec();
    twice.push(page[998].clone());
    for list in [&swapped, &repeated, &twice] {
        assert_eq!(
            parse_reply(Op::Restore, restored(list).as_bytes()),
            malformed
        );
    }
    // A reply up to the 4 MiB cap of empty strings: repeated from the
    // second, read no further than that.
    let base = restored(&[]).len();
    let empties = vec![String::new(); (MAX_REPLY_BYTES - base + 1) / 3];
    let line = restored(&empties);
    assert!(line.len() <= MAX_REPLY_BYTES && line.len() + 3 > MAX_REPLY_BYTES);
    assert_eq!(parse_reply(Op::Restore, line.as_bytes()), malformed);

    let status = |revoked: &[String]| {
        let mut members = vec![("server_time", Value::from(1))];
        members.extend(
            [
                "instance_id",
                "recovery_key_epoch",
                "recovery_state_revision",
                "recovery_public_key",
                "operation_state",
                "expires_at",
                "settles_at",
                "restored_at",
                "admin_id",
                "credential_id",
                "binding_id",
                "revoked_credential_count",
            ]
            .map(|name| (name, Value::Null)),
        );
        members.push(("revoked_credential_ids", revoked.into()));
        members.extend(
            [
                "enrolled_state",
                "enrolled_admin_id",
                "enrolled_credential_id",
                "enrolled_trust_anchor_sha256",
            ]
            .map(|name| (name, Value::Null)),
        );
        line_of(&members)
    };
    assert!(matches!(
        parse_reply(Op::Status, status(&page).as_bytes()),
        Ok(Reply::Status(read)) if read.revoked_credential_ids.as_ref() == Some(&page)
    ));
    for list in [&over, &swapped, &repeated, &twice] {
        assert_eq!(parse_reply(Op::Status, status(list).as_bytes()), malformed);
    }
}

/// No sentinel value of a request, a reply or a line is shown by `Debug`
/// (plain or alternate) or `Display` of any type of the module: `Debug`
/// names the kind, `Display` is fixed text.
#[test]
fn debug_and_display_show_no_value() {
    const SENTINELS: [&str; 6] = ["SENTINEL", "5a5a", "5A5A", "90, 90", "c7c7", "199, 199"];
    let key = RecoveryPublicKey::from_hex(
        "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a",
    )
    .unwrap();
    let response = ResponseRequest {
        operation_id: "SENTINEL-OPERATION".into(),
        signature: [0x5a; 64],
    };
    let bootstrap = BootstrapRequest {
        instance_id: "SENTINEL-INSTANCE".into(),
        credential_spki: vec![0xc7; 44],
        trust_anchor_ref: "SENTINEL-ANCHOR".into(),
        recovery_public_key: key,
    };
    let issue = IssueChallengeRequest {
        credential_spki: vec![0xc7; 44],
        trust_anchor_ref: "SENTINEL-ANCHOR".into(),
        new_recovery_public_key: key,
    };
    let status_request = StatusRequest {
        operation_id: Some("SENTINEL-OPERATION".into()),
        credential_spki: Some(vec![0xc7; 44]),
        revoked_after: Some("SENTINEL-AFTER".into()),
    };
    let requests = [
        Request::Bootstrap(bootstrap.clone()),
        Request::IssueChallenge(issue.clone()),
        Request::Preview(response.clone()),
        Request::Restore(response.clone()),
        Request::Status(status_request.clone()),
    ];
    let lines: Vec<_> = requests
        .iter()
        .map(|request| request.encode().unwrap())
        .collect();
    let id = || "SENTINEL-ID".to_owned();
    let bootstrapped = Bootstrapped {
        instance_id: id(),
        admin_id: id(),
        credential_id: id(),
        binding_id: id(),
        recovery_key_epoch: 1,
    };
    let issued = Issued {
        operation_id: id(),
        expires_at: 1,
        expected_revision: 1,
        challenge: vec![0x5a; 32],
    };
    let previewed = Previewed {
        admin_id: id(),
        credential_id: id(),
        binding_id: id(),
        new_recovery_key_epoch: 2,
        expires_at: 1,
    };
    let restored = Restored {
        admin_id: id(),
        credential_id: id(),
        binding_id: id(),
        revoked_credential_count: 1,
        revoked_credential_ids: vec![id()],
        recovery_key_epoch: 2,
        recovery_state_revision: 2,
    };
    let status = Status {
        server_time: 1,
        instance_id: Some(id()),
        recovery_key_epoch: Some(1),
        recovery_state_revision: Some(1),
        recovery_public_key: Some(vec![0x5a; 32]),
        operation_state: Some(OperationState::Restored),
        expires_at: Some(1),
        settles_at: Some(1),
        restored_at: Some(1),
        admin_id: Some(id()),
        credential_id: Some(id()),
        binding_id: Some(id()),
        revoked_credential_count: Some(1),
        revoked_credential_ids: Some(vec![id()]),
        enrolled_state: Some(EnrolledState::Enabled),
        enrolled_admin_id: Some(id()),
        enrolled_credential_id: Some(id()),
        enrolled_trust_anchor_sha256: Some(vec![0xc7; 32]),
    };
    let mut shown: Vec<(String, String)> = Vec::new();
    let mut debug = |value: &dyn std::fmt::Debug, expected: &str| {
        assert_eq!(format!("{value:?}"), expected);
        shown.push((format!("{value:?}"), format!("{value:#?}")));
    };
    debug(&bootstrap, "BootstrapRequest(..)");
    debug(&issue, "IssueChallengeRequest(..)");
    debug(&response, "ResponseRequest(..)");
    debug(&status_request, "StatusRequest(..)");
    for (request, expected) in requests.iter().zip([
        "Request::Bootstrap(..)",
        "Request::IssueChallenge(..)",
        "Request::Preview(..)",
        "Request::Restore(..)",
        "Request::Status(..)",
    ]) {
        debug(request, expected);
    }
    for line in &lines {
        debug(line, "RequestLine(..)");
        assert!(line.as_bytes().windows(4).any(|w| w == b"SENT"));
    }
    debug(&bootstrapped, "Bootstrapped(..)");
    debug(&issued, "Issued(..)");
    debug(&previewed, "Previewed(..)");
    debug(&restored, "Restored(..)");
    debug(&status, "Status(..)");
    for (reply, expected) in [
        (Reply::Bootstrapped(bootstrapped), "Reply::Bootstrapped(..)"),
        (Reply::Issued(issued), "Reply::Issued(..)"),
        (Reply::Previewed(previewed), "Reply::Previewed(..)"),
        (Reply::Restored(restored), "Reply::Restored(..)"),
        (Reply::Status(Box::new(status)), "Reply::Status(..)"),
    ] {
        debug(&reply, expected);
    }
    let mut errors: Vec<CallError> = vec![CallError::NotSent(NotSent::TooLarge)];
    errors.extend(ErrorCode::ALL.map(CallError::Refused));
    errors.extend(UNKNOWN_CLASSES.map(|(outcome, _)| CallError::Unknown(outcome)));
    let mut displays = BTreeSet::new();
    for error in &errors {
        shown.push((format!("{error:?}"), error.to_string()));
        shown.push((format!("{error:#?}"), String::new()));
        assert!(displays.insert(error.to_string()), "{error:?}");
        let source: &dyn std::error::Error = error;
        assert!(source.source().is_none());
    }
    for (outcome, _) in UNKNOWN_CLASSES {
        shown.push((format!("{outcome:?}"), outcome.to_string()));
    }
    shown.push((
        format!("{:?}", NotSent::TooLarge),
        NotSent::TooLarge.to_string(),
    ));
    for (plain, other) in &shown {
        for sentinel in SENTINELS {
            assert!(!plain.contains(sentinel), "{plain}");
            assert!(!other.contains(sentinel), "{other}");
        }
    }
}

/// Nothing under `operator/src/local/` names a private key, a signer or
/// the signing of a challenge: the client carries the operation ID and the
/// signature bytes only (key custody outside the pod).
#[test]
fn the_local_module_names_no_signer() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/local");
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let source = std::fs::read_to_string(&path).unwrap();
        for name in [
            "SigningKey",
            "SoftwareSigner",
            "RecoverySigner",
            "sign_challenge",
        ] {
            assert!(!source.contains(name), "{} names {name}", path.display());
        }
        assert!(
            !source.to_ascii_lowercase().contains("seed"),
            "{} names a seed",
            path.display()
        );
        files.push(path.file_name().unwrap().to_str().unwrap().to_owned());
    }
    files.sort();
    assert_eq!(
        files,
        [
            "exchange.rs",
            "mod.rs",
            "path.rs",
            "reconcile.rs",
            "wire.rs"
        ]
    );
}

/// The members of a fixture object.
fn members(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {value}"))
        .keys()
        .map(String::as_str)
        .collect()
}

/// The `case` names of `cases`: unique, and `^[a-z0-9_]+$`.
fn case_names(cases: &[Value]) -> BTreeSet<String> {
    let names: BTreeSet<String> = cases.iter().map(|c| owned(c, "case")).collect();
    assert_eq!(names.len(), cases.len(), "case names are unique");
    for name in &names {
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_')),
            "case name {name:?}"
        );
    }
    names
}

/// The fixture files under `_wire/` and their members are exactly what the
/// tests read: a new file, member or case fails here until a reader is
/// added. `errors.v1.json` is the admin HTTP catalogue, read by the
/// service side only (`tests/harness/wire_errors.rs`); `exchange.id_seed`
/// is the service's ID generator seed, read by
/// `tests/harness/local_transport_wire.rs` only; `default_limits` is read
/// by `local_exchange`. `socket_path.v1.json` is read, member by member,
/// by `local_path`.
#[test]
fn every_wire_fixture_file_and_case_is_covered() {
    let mut files: Vec<String> = std::fs::read_dir(fixtures_dir().join("_wire"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "errors.v1.json",
            WIRE_FIXTURE,
            crate::support::SOCKET_PATH_FIXTURE
        ]
    );

    let fixture = wire_fixture();
    assert_eq!(
        members(&fixture),
        BTreeSet::from([
            "fixture_version",
            "kind",
            "status",
            "description",
            "framing",
            "default_limits",
            "op_member",
            "ops",
            "replies",
            "error_codes",
            "golden_requests",
            "golden_replies",
            "exchange",
            "unknown_replies",
        ])
    );
    assert_eq!(
        members(&fixture["framing"]),
        BTreeSet::from([
            "line_end",
            "max_request_bytes",
            "max_reply_bytes",
            "max_revoked_ids_per_reply"
        ])
    );
    // Read by `local_exchange` (`default_timeouts_are_the_servers_defaults`).
    assert_eq!(
        members(&fixture["default_limits"]),
        BTreeSet::from([
            "deadline_seconds",
            "transaction_timeout_seconds",
            "idle_timeout_seconds",
            "client_total_wait_seconds",
        ])
    );
    for (name, op) in SHAPES {
        let expected: BTreeSet<&str> = if op.is_some() {
            BTreeSet::from(["op", "members"])
        } else {
            BTreeSet::from(["members"])
        };
        assert_eq!(members(&fixture["replies"][name]), expected, "{name}");
    }
    for entry in list(&fixture, "error_codes") {
        assert_eq!(members(entry), BTreeSet::from(["code", "applies_when"]));
    }

    let requests = list(&fixture, "golden_requests");
    assert_eq!(
        run_golden_requests(&fixture)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        case_names(requests)
    );
    for case in requests {
        assert_eq!(
            members(case),
            BTreeSet::from(["case", "op", "values", "line"])
        );
    }
    // A golden request with escapes: `"` and `\` in a string.
    assert!(
        requests
            .iter()
            .any(|case| text(case, "line").contains("\\\"") && text(case, "line").contains("\\\\"))
    );

    let replies = list(&fixture, "golden_replies");
    assert_eq!(
        run_golden_replies(&fixture)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        case_names(replies)
    );
    for case in replies {
        assert_eq!(
            members(case),
            BTreeSet::from(["case", "reply", "values", "line"])
        );
    }

    let unknown = list(&fixture, "unknown_replies");
    assert_eq!(
        run_unknown_replies(&fixture)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        case_names(unknown)
    );
    for case in unknown {
        assert_eq!(
            members(case),
            BTreeSet::from(["case", "op", "parts", "expected"])
        );
        for part in list(case, "parts") {
            let part_members = members(part);
            assert!(
                part_members == BTreeSet::from(["text"])
                    || part_members == BTreeSet::from(["hex"])
                    || part_members == BTreeSet::from(["text", "repeat"]),
                "{part}"
            );
        }
    }

    let exchange = &fixture["exchange"];
    assert_eq!(
        members(exchange),
        BTreeSet::from(["id_seed", "now_micros", "challenge_ttl_seconds", "steps"])
    );
    let request_names = case_names(requests);
    let reply_names = case_names(replies);
    let steps = list(exchange, "steps");
    for step in steps {
        assert_eq!(members(step), BTreeSet::from(["request", "reply"]));
        assert!(request_names.contains(text(step, "request")), "{step}");
        assert!(reply_names.contains(text(step, "reply")), "{step}");
    }
    // Every success shape is in the exchange, so each golden success line
    // is one the service sent.
    let exchanged: BTreeSet<&str> = steps.iter().map(|step| text(step, "reply")).collect();
    for case in replies.iter().filter(|case| text(case, "reply") != "error") {
        assert!(exchanged.contains(text(case, "case")), "{case}");
    }
}
