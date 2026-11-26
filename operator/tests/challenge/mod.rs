//! The recovery challenge: the writer of `C` and `M` and `parse_challenge`
//! against the shared fixture
//! `tests/conformance/fixtures/_recovery/challenge.v1.json`, which the `pg`
//! target of `skyoauth-scenarios` checks against the service
//! (`tests/harness/recovery_challenge_fixture.rs`); the strictness of
//! `parse_challenge`, case by case and by reason; and `check_challenge`
//! with an injected clock.

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use skyoauth_operator::recovery::{
    CHALLENGE_PREFIX, ChallengeError, DEFAULT_CHALLENGE_TTL, DEPLOYMENT_OPERATOR_ACTOR,
    Expectations, KeyError, MAX_CHALLENGE_BYTES, MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL,
    OPERATOR_RESTORATION, PLAN_ADMIN_ID, PLAN_BINDING_ID, PLAN_CREDENTIAL_ID, PLAN_INSTANCE_ID,
    PLAN_NEW_RECOVERY_PUBLIC_KEY, PLAN_PUBLIC_IDENTITY, PLAN_RECOVERY_KEY_EPOCH,
    PLAN_TRUST_ANCHOR_REF, RecoveryPublicKey, Refusal, RestorationPlan, canonical_json,
    challenge_message, check_challenge, parse_challenge,
};

use crate::support::{list, recovery_fixture, text, unhex};

pub const CHALLENGE_FIXTURE: &str = "challenge.v1.json";

/// The members of a vector of the challenge fixture.
pub const VECTOR_MEMBERS: [&str; 10] = [
    "case",
    "note",
    "id",
    "expected_revision",
    "expires_at",
    "plan",
    "canonical",
    "message_hex",
    "challenge_hash",
    "request_digest",
];

/// The plan members, in byte-wise order.
const PLAN_MEMBERS: [&str; 8] = [
    PLAN_ADMIN_ID,
    PLAN_BINDING_ID,
    PLAN_CREDENTIAL_ID,
    PLAN_INSTANCE_ID,
    PLAN_NEW_RECOVERY_PUBLIC_KEY,
    PLAN_PUBLIC_IDENTITY,
    PLAN_RECOVERY_KEY_EPOCH,
    PLAN_TRUST_ANCHOR_REF,
];

/// The RFC 8032 section 7.1 test 1 public key, op_1's new key.
const RFC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// Another valid key.
const OTHER_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// op_1's instance.
const INSTANCE: &str = "01936f4e-8a2b-7c3d-9e4f-0123456789ab";

/// op_1's expiry, in microseconds.
const EXPIRES_AT: i64 = 1_790_000_300_000_000;

fn micros(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap()
}

fn integer(value: &Value, name: &str) -> i64 {
    value[name]
        .as_i64()
        .unwrap_or_else(|| panic!("{name} is not an i64 in {value}"))
}

fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The fixture plan `plan`, which must have exactly the eight members.
fn fixture_plan(plan: &Value) -> RestorationPlan {
    let members: Vec<&str> = plan
        .as_object()
        .expect("a plan is an object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = members.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, PLAN_MEMBERS, "plan members");
    RestorationPlan {
        instance_id: text(plan, PLAN_INSTANCE_ID).to_owned(),
        recovery_key_epoch: integer(plan, PLAN_RECOVERY_KEY_EPOCH),
        admin_id: text(plan, PLAN_ADMIN_ID).to_owned(),
        credential_id: text(plan, PLAN_CREDENTIAL_ID).to_owned(),
        binding_id: text(plan, PLAN_BINDING_ID).to_owned(),
        public_identity: text(plan, PLAN_PUBLIC_IDENTITY).to_owned(),
        trust_anchor_ref: text(plan, PLAN_TRUST_ANCHOR_REF).to_owned(),
        new_recovery_public_key: RecoveryPublicKey::from_hex(text(
            plan,
            PLAN_NEW_RECOVERY_PUBLIC_KEY,
        ))
        .unwrap(),
    }
}

/// op_1's plan, the good plan of the service's tests.
fn good_plan() -> RestorationPlan {
    RestorationPlan {
        instance_id: INSTANCE.into(),
        recovery_key_epoch: 1,
        admin_id: "adm_new".into(),
        credential_id: "crd_new".into(),
        binding_id: "rb_new".into(),
        public_identity: "spki-sha256:new".into(),
        trust_anchor_ref: "deployment/operator-ca".into(),
        new_recovery_public_key: RecoveryPublicKey::from_hex(RFC_KEY).unwrap(),
    }
}

/// `CHALLENGE_PREFIX || c`.
fn message(c: &str) -> Vec<u8> {
    [CHALLENGE_PREFIX, c.as_bytes()].concat()
}

/// `text` with its one occurrence of `from` replaced by `to`.
#[track_caller]
fn with(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from:?} in {text:?}");
    text.replacen(from, to, 1)
}

/// Runs every vector of the challenge fixture through the writer and the
/// reader. Returns the case names.
pub fn run_challenge_vectors(fixture: &Value) -> Vec<String> {
    let prefix = text(fixture, "prefix").as_bytes();
    let digest_prefix = text(fixture, "request_digest_prefix").as_bytes();
    let mut names = Vec::new();
    for vector in list(fixture, "vectors") {
        let name = text(vector, "case");
        assert!(!text(vector, "note").is_empty(), "{name}");
        let id = text(vector, "id");
        let revision = integer(vector, "expected_revision");
        let expires_at = integer(vector, "expires_at");
        let plan = fixture_plan(&vector["plan"]);
        let canonical = text(vector, "canonical");
        let expected_message = unhex(text(vector, "message_hex"));

        assert_eq!(
            canonical_json(id, revision, expires_at, &plan),
            canonical,
            "{name}"
        );
        let written = challenge_message(id, revision, expires_at, &plan);
        assert_eq!(written, expected_message, "{name}");
        assert_eq!(written, [prefix, canonical.as_bytes()].concat(), "{name}");
        assert_eq!(
            sha256_hex(&[&written]),
            text(vector, "challenge_hash"),
            "{name}"
        );
        assert_eq!(
            sha256_hex(&[digest_prefix, canonical.as_bytes()]),
            text(vector, "request_digest"),
            "{name}"
        );

        let parsed =
            parse_challenge(&expected_message).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(parsed.message(), expected_message, "{name}");
        assert_eq!(parsed.operation_id(), id, "{name}");
        assert_eq!(parsed.expected_revision(), revision, "{name}");
        assert_eq!(parsed.expires_at_micros(), expires_at, "{name}");
        assert!(*parsed.plan() == plan, "{name}");
        names.push(name.to_owned());
    }
    names
}

#[test]
fn challenge_fixture_envelope_matches_the_crate() {
    let fixture = recovery_fixture(CHALLENGE_FIXTURE);
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "recovery_challenge");
    assert_eq!(text(&fixture, "prefix").as_bytes(), CHALLENGE_PREFIX);
    assert_eq!(
        text(&fixture, "request_digest_prefix"),
        "skyoauth.administrative_operation.v1\n"
    );
    assert_eq!(fixture["actor_id"], DEPLOYMENT_OPERATOR_ACTOR);
    assert_eq!(fixture["challenge_kind"], OPERATOR_RESTORATION);
    let ttl = &fixture["ttl_seconds"];
    assert_eq!(ttl.as_object().unwrap().len(), 3);
    assert_eq!(ttl["min"], MIN_CHALLENGE_TTL.as_secs());
    assert_eq!(ttl["default"], DEFAULT_CHALLENGE_TTL.as_secs());
    assert_eq!(ttl["max"], MAX_CHALLENGE_TTL.as_secs());
    let members: Vec<&str> = list(&fixture, "plan_members")
        .iter()
        .map(|member| member.as_str().unwrap())
        .collect();
    assert_eq!(members, PLAN_MEMBERS);
    assert!(PLAN_MEMBERS.is_sorted_by(|a, b| a.as_bytes() < b.as_bytes()));
}

#[test]
fn challenge_vectors_match_the_writer_and_the_reader() {
    let fixture = recovery_fixture(CHALLENGE_FIXTURE);
    assert!(!run_challenge_vectors(&fixture).is_empty());
}

/// The canonical text of `vector` in the challenge fixture.
fn fixture_canonical(case: &str) -> String {
    let fixture = recovery_fixture(CHALLENGE_FIXTURE);
    let vector = list(&fixture, "vectors")
        .iter()
        .find(|vector| text(vector, "case") == case)
        .unwrap_or_else(|| panic!("no vector {case}"));
    text(vector, "canonical").to_owned()
}

/// Every input of `M` changes it, and the changed `M` reads back as the
/// changed values.
#[test]
fn every_challenge_input_changes_the_message() {
    let plan = good_plan();
    let base = challenge_message("op_1", 1, EXPIRES_AT, &plan);
    let mut changed = vec![
        ("op_2".to_owned(), 1, EXPIRES_AT, plan.clone()),
        ("op_1".to_owned(), 2, EXPIRES_AT, plan.clone()),
        ("op_1".to_owned(), 1, EXPIRES_AT + 1, plan.clone()),
    ];
    let edits: [fn(&mut RestorationPlan); 8] = [
        |plan| plan.instance_id = "01936f4e-8a2b-7c3d-9e4f-0123456789ac".into(),
        |plan| plan.recovery_key_epoch = 2,
        |plan| plan.admin_id = "adm_other".into(),
        |plan| plan.credential_id = "crd_other".into(),
        |plan| plan.binding_id = "rb_other".into(),
        |plan| plan.public_identity = "spki-sha256:other".into(),
        |plan| plan.trust_anchor_ref = "deployment/other-ca".into(),
        |plan| plan.new_recovery_public_key = RecoveryPublicKey::from_hex(OTHER_KEY).unwrap(),
    ];
    for edit in edits {
        let mut other = plan.clone();
        edit(&mut other);
        assert!(other != plan);
        changed.push(("op_1".to_owned(), 1, EXPIRES_AT, other));
    }
    for (id, revision, expires_at, plan) in changed {
        let message = challenge_message(&id, revision, expires_at, &plan);
        assert_ne!(message, base);
        let parsed = parse_challenge(&message).unwrap();
        assert_eq!(
            (
                parsed.operation_id(),
                parsed.expected_revision(),
                parsed.expires_at_micros()
            ),
            (&id[..], revision, expires_at)
        );
        assert!(*parsed.plan() == plan);
    }
}

/// Each character below U+0020, `"` and `\` get the service's escape, and
/// the rest of ASCII and non-ASCII characters none; each reads back.
#[test]
fn every_string_escape_is_the_services() {
    let mut characters: Vec<char> = ('\0'..='\u{7f}').collect();
    characters.extend([
        '\u{80}',
        '\u{e9}',
        '\u{2028}',
        '\u{fffd}',
        '\u{10348}',
        '\u{10ffff}',
    ]);
    for character in characters {
        let expected = match character {
            '\u{8}' => "\\b".to_owned(),
            '\t' => "\\t".to_owned(),
            '\n' => "\\n".to_owned(),
            '\u{c}' => "\\f".to_owned(),
            '\r' => "\\r".to_owned(),
            '"' => "\\\"".to_owned(),
            '\\' => "\\\\".to_owned(),
            control if u32::from(control) < 0x20 => format!("\\u00{:02x}", u32::from(control)),
            other => other.to_string(),
        };
        let mut plan = good_plan();
        plan.admin_id = format!("a{character}z");
        let c = canonical_json("op_1", 1, EXPIRES_AT, &plan);
        let written = format!("\"admin_id\":\"a{expected}z\",");
        assert!(c.contains(&written), "{character:?}: {c}");
        let parsed = parse_challenge(&message(&c)).unwrap();
        assert_eq!(parsed.plan().admin_id, plan.admin_id, "{character:?}");
    }
}

/// The strictness of `parse_challenge`: each malformed or non-canonical
/// `M`, built from op_1 (or the escapes vector) by one edit, is refused
/// with its reason.
#[test]
fn parse_challenge_refuses_each_malformed_challenge_by_reason() {
    use ChallengeError::*;
    let c = fixture_canonical("op_1");
    let escapes = fixture_canonical("escapes");
    let prefixed = |c: &str| message(c);
    let small_order = "0100000000000000000000000000000000000000000000000000000000000000";
    let not_canonical = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
    let undecodable = "0707070707070707070707070707070707070707070707070707070707070707";
    let anchor = "\"trust_anchor_ref\":\"deployment/operator-ca\"";
    let mut non_utf8 = prefixed(&c);
    let at = non_utf8.len() - 20;
    non_utf8[at] = 0xff;
    let cases: Vec<(&str, Vec<u8>, ChallengeError)> = vec![
        // The prefix.
        ("empty", Vec::new(), Prefix),
        ("no_prefix", c.as_bytes().to_vec(), Prefix),
        (
            "prefix_without_newline",
            [
                &CHALLENGE_PREFIX[..CHALLENGE_PREFIX.len() - 1],
                c.as_bytes(),
            ]
            .concat(),
            Prefix,
        ),
        (
            "prefix_with_crlf",
            [b"skyoauth.recovery_challenge.v1\r\n", c.as_bytes()].concat(),
            Prefix,
        ),
        (
            "prefix_v2",
            [b"skyoauth.recovery_challenge.v2\n", c.as_bytes()].concat(),
            Prefix,
        ),
        (
            "prefix_upper_case",
            [b"SKYOAUTH.recovery_challenge.v1\n", c.as_bytes()].concat(),
            Prefix,
        ),
        (
            "request_digest_prefix",
            [b"skyoauth.administrative_operation.v1\n", c.as_bytes()].concat(),
            Prefix,
        ),
        (
            "prefix_twice",
            prefixed(&String::from_utf8(prefixed(&c)).unwrap()),
            Syntax,
        ),
        // UTF-8 and syntax.
        ("not_utf8", non_utf8, NotUtf8),
        ("prefix_only", prefixed(""), Syntax),
        ("unterminated", prefixed(&c[..c.len() - 1]), Syntax),
        ("trailing_value", prefixed(&format!("{c}{{}}")), Syntax),
        ("trailing_byte", prefixed(&format!("{c}x")), Syntax),
        (
            "missing_comma",
            prefixed(&with(&c, "1,\"expires_at\"", "1 \"expires_at\"")),
            Syntax,
        ),
        (
            "missing_colon",
            prefixed(&with(&c, "\"id\":", "\"id\" ")),
            Syntax,
        ),
        (
            "trailing_comma",
            prefixed(&with(&c, "null}", "null,}")),
            Syntax,
        ),
        (
            "unquoted_name",
            prefixed(&with(&c, "\"id\":", "id:")),
            Syntax,
        ),
        (
            "raw_control",
            prefixed(&with(&c, "op_1", "op_\u{1}")),
            Syntax,
        ),
        ("raw_tab", prefixed(&with(&c, "op_1", "op\t1")), Syntax),
        // The last control character, raw: not read, so not NotCanonical.
        (
            "raw_unit_separator",
            prefixed(&with(&c, "op_1", "op\u{1f}1")),
            Syntax,
        ),
        ("bad_escape", prefixed(&with(&c, "op_1", "op\\x1")), Syntax),
        (
            "short_unicode_escape",
            prefixed(&with(&c, "op_1", "op\\u01")),
            Syntax,
        ),
        (
            "lone_high_surrogate",
            prefixed(&with(&c, "op_1", "op\\ud800")),
            Syntax,
        ),
        (
            "lone_low_surrogate",
            prefixed(&with(&c, "op_1", "op\\udc00")),
            Syntax,
        ),
        (
            "high_surrogate_then_other",
            prefixed(&with(&c, "op_1", "op\\ud800\\u0041")),
            Syntax,
        ),
        (
            "null_misspelled",
            prefixed(&with(&c, ":null}", ":nul}")),
            Syntax,
        ),
        (
            "plus_sign",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":+1",
            )),
            Syntax,
        ),
        (
            "minus_alone",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":-",
            )),
            Syntax,
        ),
        // Numbers.
        (
            "fraction",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":1.0",
            )),
            Number,
        ),
        (
            "exponent",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":1e3",
            )),
            Number,
        ),
        (
            "exponent_upper_case",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":1E3",
            )),
            Number,
        ),
        (
            "leading_zero",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":01",
            )),
            Number,
        ),
        (
            "negative_zero",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":-0",
            )),
            Number,
        ),
        (
            "above_i64_max",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":9223372036854775808",
            )),
            Number,
        ),
        (
            "below_i64_min",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":-9223372036854775809",
            )),
            Number,
        ),
        (
            "expires_at_fraction",
            prefixed(&with(&c, "1790000300000000", "1790000300000000.5")),
            Number,
        ),
        (
            "epoch_fraction",
            prefixed(&with(
                &c,
                "\"recovery_key_epoch\":1",
                "\"recovery_key_epoch\":1.5",
            )),
            Number,
        ),
        (
            "epoch_exponent",
            prefixed(&with(
                &c,
                "\"recovery_key_epoch\":1",
                "\"recovery_key_epoch\":1e0",
            )),
            Number,
        ),
        // Types.
        ("root_array", prefixed("[]"), WrongType),
        ("root_string", prefixed("\"op_1\""), WrongType),
        ("root_null", prefixed("null"), WrongType),
        (
            "revision_string",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":\"1\"",
            )),
            WrongType,
        ),
        (
            "revision_true",
            prefixed(&with(
                &c,
                "\"expected_revision\":1",
                "\"expected_revision\":true",
            )),
            WrongType,
        ),
        (
            "id_integer",
            prefixed(&with(&c, "\"id\":\"op_1\"", "\"id\":1")),
            WrongType,
        ),
        (
            "id_null",
            prefixed(&with(&c, "\"id\":\"op_1\"", "\"id\":null")),
            WrongType,
        ),
        (
            "actor_id_integer",
            prefixed(&with(&c, "\"deployment_operator\"", "7")),
            WrongType,
        ),
        (
            "plan_null",
            prefixed(&format!(
                "{}null,\"tenant_id\":null}}",
                &c[..c.find("{\"admin_id\"").unwrap()]
            )),
            WrongType,
        ),
        (
            "plan_array",
            prefixed(&format!(
                "{}[],\"tenant_id\":null}}",
                &c[..c.find("{\"admin_id\"").unwrap()]
            )),
            WrongType,
        ),
        (
            "plan_string",
            prefixed(&format!(
                "{}\"x\",\"tenant_id\":null}}",
                &c[..c.find("{\"admin_id\"").unwrap()]
            )),
            WrongType,
        ),
        (
            "admin_id_false",
            prefixed(&with(&c, "\"adm_new\"", "false")),
            WrongType,
        ),
        (
            "admin_id_object",
            prefixed(&with(&c, "\"adm_new\"", "{}")),
            WrongType,
        ),
        // Refused at the third level, without reading deeper (10,000
        // levels: deep, and under the size cap).
        (
            "deeply_nested_object",
            prefixed(&with(
                &c,
                "\"adm_new\"",
                &format!("{}{}", "{\"a\":".repeat(10_000), "}".repeat(10_000)),
            )),
            WrongType,
        ),
        (
            "epoch_string",
            prefixed(&with(
                &c,
                "\"recovery_key_epoch\":1",
                "\"recovery_key_epoch\":\"1\"",
            )),
            WrongType,
        ),
        (
            "key_integer",
            prefixed(&with(&c, &format!("\"{RFC_KEY}\""), "1")),
            WrongType,
        ),
        // Order and duplicates.
        (
            "members_unsorted",
            prefixed(&with(
                &c,
                "\"expires_at\":1790000300000000,\"id\":\"op_1\"",
                "\"id\":\"op_1\",\"expires_at\":1790000300000000",
            )),
            UnsortedMembers,
        ),
        (
            "plan_members_unsorted",
            prefixed(&with(
                &c,
                "\"admin_id\":\"adm_new\",\"binding_id\":\"rb_new\"",
                "\"binding_id\":\"rb_new\",\"admin_id\":\"adm_new\"",
            )),
            UnsortedMembers,
        ),
        (
            "tenant_id_first",
            prefixed(&format!(
                "{{\"tenant_id\":null,{}",
                &with(&c, ",\"tenant_id\":null", "")[1..]
            )),
            UnsortedMembers,
        ),
        (
            "duplicate_member",
            prefixed(&with(
                &c,
                "\"id\":\"op_1\"",
                "\"id\":\"op_1\",\"id\":\"op_1\"",
            )),
            DuplicateMember,
        ),
        (
            "duplicate_member_other_value",
            prefixed(&with(
                &c,
                "\"id\":\"op_1\"",
                "\"id\":\"op_1\",\"id\":\"op_2\"",
            )),
            DuplicateMember,
        ),
        (
            "duplicate_plan_member",
            prefixed(&with(
                &c,
                "\"admin_id\":\"adm_new\"",
                "\"admin_id\":\"adm_new\",\"admin_id\":\"adm_new\"",
            )),
            DuplicateMember,
        ),
        (
            "duplicate_member_by_escape",
            prefixed(&with(
                &c,
                "\"admin_id\":\"adm_new\"",
                "\"admin_id\":\"adm_new\",\"\\u0061dmin_id\":\"adm_new\"",
            )),
            DuplicateMember,
        ),
        // U+10348 as is, then as an escaped surrogate pair.
        (
            "duplicate_member_by_surrogate_pair",
            prefixed(&with(
                &c,
                "null}",
                "null,\"\u{10348}\":null,\"\\ud800\\udf48\":null}",
            )),
            DuplicateMember,
        ),
        // U+1F600 as is, then as an escaped surrogate pair whose high half
        // is not D800, so the high half's shift matters.
        (
            "duplicate_member_by_surrogate_pair_high_above_d800",
            prefixed(&with(
                &c,
                "null}",
                "null,\"\u{1f600}\":null,\"\\ud83d\\ude00\":null}",
            )),
            DuplicateMember,
        ),
        // The closed shape.
        (
            "extra_member",
            prefixed(&with(&c, "null}", "null,\"zzz\":null}")),
            UnknownMember,
        ),
        (
            "extra_member_sorted",
            prefixed(&with(&c, "\"kind\"", "\"jti\":\"x\",\"kind\"")),
            UnknownMember,
        ),
        (
            "extra_plan_member",
            prefixed(&with(&c, anchor, &format!("{anchor},\"zzz\":\"x\""))),
            UnknownMember,
        ),
        (
            "extra_plan_nonce",
            prefixed(&with(
                &c,
                "\"public_identity\"",
                "\"nonce\":\"x\",\"public_identity\"",
            )),
            UnknownMember,
        ),
        ("empty_object", prefixed("{}"), MissingMember),
        (
            "missing_kind",
            prefixed(&with(&c, "\"kind\":\"operator_restoration\",", "")),
            MissingMember,
        ),
        (
            "missing_tenant_id",
            prefixed(&with(&c, ",\"tenant_id\":null", "")),
            MissingMember,
        ),
        (
            "missing_actor_id",
            prefixed(&with(&c, "\"actor_id\":\"deployment_operator\",", "")),
            MissingMember,
        ),
        (
            "missing_plan_key",
            prefixed(&with(
                &c,
                &format!("\"new_recovery_public_key\":\"{RFC_KEY}\","),
                "",
            )),
            MissingMember,
        ),
        (
            "empty_plan",
            prefixed(&format!(
                "{}{{}},\"tenant_id\":null}}",
                &c[..c.find("{\"admin_id\"").unwrap()]
            )),
            MissingMember,
        ),
        // Fixed values.
        (
            "tenant_id_string",
            prefixed(&with(&c, "\"tenant_id\":null", "\"tenant_id\":\"tn_1\"")),
            FixedValue,
        ),
        (
            "tenant_id_integer",
            prefixed(&with(&c, "\"tenant_id\":null", "\"tenant_id\":0")),
            FixedValue,
        ),
        (
            "tenant_id_empty",
            prefixed(&with(&c, "\"tenant_id\":null", "\"tenant_id\":\"\"")),
            FixedValue,
        ),
        (
            "actor_id_other",
            prefixed(&with(&c, "\"deployment_operator\"", "\"adm_1\"")),
            FixedValue,
        ),
        (
            "actor_id_upper_case",
            prefixed(&with(
                &c,
                "\"deployment_operator\"",
                "\"Deployment_operator\"",
            )),
            FixedValue,
        ),
        (
            "kind_other",
            prefixed(&with(
                &c,
                "\"operator_restoration\"",
                "\"instance_security_policy_update\"",
            )),
            FixedValue,
        ),
        (
            "kind_extended",
            prefixed(&with(
                &c,
                "\"operator_restoration\"",
                "\"operator_restoration \"",
            )),
            FixedValue,
        ),
        // Plan text bounds and the new key.
        (
            "identity_empty",
            prefixed(&with(&c, "\"spki-sha256:new\"", "\"\"")),
            TextBounds,
        ),
        (
            "anchor_empty",
            prefixed(&with(&c, anchor, "\"trust_anchor_ref\":\"\"")),
            TextBounds,
        ),
        (
            "identity_2049_bytes",
            prefixed(&with(
                &c,
                "\"spki-sha256:new\"",
                &format!("\"{}\"", "i".repeat(2049)),
            )),
            TextBounds,
        ),
        (
            "anchor_2049_bytes",
            prefixed(&with(
                &c,
                anchor,
                &format!("\"trust_anchor_ref\":\"{}\"", "a".repeat(2049)),
            )),
            TextBounds,
        ),
        (
            "key_upper_case",
            prefixed(&with(&c, RFC_KEY, &RFC_KEY.to_ascii_uppercase())),
            NewRecoveryKey(KeyError::NotHex),
        ),
        (
            "key_63_digits",
            prefixed(&with(&c, RFC_KEY, &RFC_KEY[..63])),
            NewRecoveryKey(KeyError::NotHex),
        ),
        (
            "key_31_bytes",
            prefixed(&with(&c, RFC_KEY, &RFC_KEY[..62])),
            NewRecoveryKey(KeyError::NotHex),
        ),
        (
            "key_empty",
            prefixed(&with(&c, RFC_KEY, "")),
            NewRecoveryKey(KeyError::NotHex),
        ),
        (
            "key_small_order",
            prefixed(&with(&c, RFC_KEY, small_order)),
            NewRecoveryKey(KeyError::SmallOrder),
        ),
        (
            "key_not_canonical",
            prefixed(&with(&c, RFC_KEY, not_canonical)),
            NewRecoveryKey(KeyError::NotCanonical),
        ),
        (
            "key_undecodable",
            prefixed(&with(&c, RFC_KEY, undecodable)),
            NewRecoveryKey(KeyError::Undecodable),
        ),
        // Read, but not canonical.
        ("leading_space", prefixed(&format!(" {c}")), NotCanonical),
        (
            "trailing_newline",
            prefixed(&format!("{c}\n")),
            NotCanonical,
        ),
        (
            "space_after_colon",
            prefixed(&with(&c, "\"id\":", "\"id\": ")),
            NotCanonical,
        ),
        (
            "space_after_comma",
            prefixed(&with(&c, ",\"kind\"", ", \"kind\"")),
            NotCanonical,
        ),
        (
            "newline_in_plan",
            prefixed(&with(&c, "{\"admin_id\"", "{\n\"admin_id\"")),
            NotCanonical,
        ),
        (
            "escaped_letter",
            prefixed(&with(&c, "\"adm_new\"", "\"\\u0061dm_new\"")),
            NotCanonical,
        ),
        (
            "escaped_solidus",
            prefixed(&with(
                &c,
                "deployment/operator-ca",
                "deployment\\/operator-ca",
            )),
            NotCanonical,
        ),
        (
            "escaped_name",
            prefixed(&with(&c, "\"kind\"", "\"\\u006bind\"")),
            NotCanonical,
        ),
        (
            "escaped_short_control_long",
            prefixed(&with(&escapes, "rb_\\b", "rb_\\u0008")),
            NotCanonical,
        ),
        (
            "escaped_control_upper_case",
            prefixed(&with(&escapes, "\\u001f", "\\u001F")),
            NotCanonical,
        ),
        (
            "escaped_del",
            prefixed(&with(&escapes, "\u{7f}", "\\u007f")),
            NotCanonical,
        ),
        (
            "escaped_non_ascii",
            prefixed(&with(&escapes, "crd_\u{e9}", "crd_\\u00e9")),
            NotCanonical,
        ),
        (
            "escaped_surrogate_pair",
            prefixed(&with(&escapes, "\u{10348}", "\\ud800\\udf48")),
            NotCanonical,
        ),
        (
            "escaped_line_separator",
            prefixed(&with(&escapes, "\u{2028}", "\\u2028")),
            NotCanonical,
        ),
    ];
    let mut reasons = Vec::new();
    for (name, bytes, expected) in &cases {
        assert_eq!(parse_challenge(bytes).map(|_| ()), Err(*expected), "{name}");
        if !reasons.contains(expected) {
            reasons.push(*expected);
        }
    }
    // Every reason but the size cap (its own test) has a case, with the
    // four key refusals.
    assert_eq!(reasons.len(), 16);
    assert!(!reasons.contains(&TooLarge));
    // The bounds themselves are accepted.
    for (from, to) in [
        (
            "\"spki-sha256:new\"".to_owned(),
            format!("\"{}\"", "i".repeat(2048)),
        ),
        ("\"spki-sha256:new\"".to_owned(), "\"i\"".to_owned()),
        (
            anchor.to_owned(),
            format!("\"trust_anchor_ref\":\"{}\"", "a".repeat(2048)),
        ),
        (anchor.to_owned(), "\"trust_anchor_ref\":\"a\"".to_owned()),
    ] {
        assert!(
            parse_challenge(&prefixed(&with(&c, &from, &to))).is_ok(),
            "{to:.20}"
        );
    }
}

/// `M` of exactly [`MAX_CHALLENGE_BYTES`] bytes is read; one byte more is
/// refused before any reading, even with a good prefix and `C`.
#[test]
fn parse_challenge_reads_at_most_the_size_cap() {
    let base = challenge_message("op_1", 1, EXPIRES_AT, &good_plan());
    let sized = |length: usize| {
        let mut plan = good_plan();
        plan.admin_id.push_str(&"x".repeat(length - base.len()));
        challenge_message("op_1", 1, EXPIRES_AT, &plan)
    };
    let at_cap = sized(MAX_CHALLENGE_BYTES);
    assert_eq!(at_cap.len(), MAX_CHALLENGE_BYTES);
    let parsed = parse_challenge(&at_cap).unwrap();
    assert_eq!(parsed.message(), at_cap);
    let over_cap = sized(MAX_CHALLENGE_BYTES + 1);
    assert_eq!(over_cap.len(), MAX_CHALLENGE_BYTES + 1);
    assert_eq!(
        parse_challenge(&over_cap).map(|_| ()),
        Err(ChallengeError::TooLarge)
    );
    // Before the prefix.
    assert_eq!(
        parse_challenge(&vec![b'x'; MAX_CHALLENGE_BYTES + 1]).map(|_| ()),
        Err(ChallengeError::TooLarge)
    );
    assert_eq!(MAX_CHALLENGE_BYTES, 64 * 1024);
}

/// Every refusal of parsing and checking has its own fixed text, which
/// holds no value of the challenge.
#[test]
fn challenge_errors_and_refusals_show_no_value() {
    use ChallengeError::*;
    let errors = [
        TooLarge,
        Prefix,
        NotUtf8,
        Syntax,
        Number,
        WrongType,
        DuplicateMember,
        UnsortedMembers,
        UnknownMember,
        MissingMember,
        FixedValue,
        TextBounds,
        NewRecoveryKey(KeyError::SmallOrder),
        NotCanonical,
    ];
    let refusals = [
        Refusal::OtherInstance,
        Refusal::Expired,
        Refusal::ExpiresTooLate,
        Refusal::OtherEpoch,
        Refusal::OtherReplacementIdentity,
        Refusal::OtherNewRecoveryKey,
    ];
    let mut texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
    texts.extend(refusals.iter().map(ToString::to_string));
    let count = texts.len();
    texts.sort();
    texts.dedup();
    assert_eq!(texts.len(), count, "every text is its own");
    for shown in texts {
        assert!(
            !shown.contains("op_1") && !shown.contains("d75a") && !shown.contains("adm_"),
            "{shown}"
        );
    }
    assert_eq!(
        std::error::Error::source(&NewRecoveryKey(KeyError::SmallOrder)).map(ToString::to_string),
        Some(KeyError::SmallOrder.to_string())
    );
    assert!(std::error::Error::source(&Prefix).is_none());

    let challenge = parse_challenge(&message(&fixture_canonical("op_1"))).unwrap();
    assert_eq!(format!("{challenge:?}"), "Challenge(..)");
    assert_eq!(format!("{:#?}", challenge.plan()), "RestorationPlan(..)");
    let verified = check_challenge(&challenge, &expectations(EXPIRES_AT - 1)).unwrap();
    assert_eq!(format!("{verified:?}"), "VerifiedChallenge(..)");
}

/// Expectations that op_1 meets at `now`: its instance only.
fn expectations(now_micros: i64) -> Expectations<'static> {
    Expectations {
        instance_id: INSTANCE,
        now_micros,
        recovery_key_epoch: None,
        replacement_public_identity: None,
        new_recovery_public_key: None,
    }
}

/// `check_challenge` on op_1, issued with the default TTL: the instance
/// binding, the expiry at the service's boundary (`now < expires_at`),
/// the horizon of the longest TTL, and the epoch, replacement identity and
/// new key when expected.
#[test]
fn check_challenge_binds_instance_time_epoch_and_replacement() {
    let challenge = parse_challenge(&message(&fixture_canonical("op_1"))).unwrap();
    let issued_at = EXPIRES_AT - micros(DEFAULT_CHALLENGE_TTL);
    let check = |expected: &Expectations<'_>| check_challenge(&challenge, expected).map(|_| ());

    let verified = check_challenge(&challenge, &expectations(issued_at)).unwrap();
    assert!(std::ptr::eq(verified.challenge(), &challenge));
    assert_eq!(verified.message(), challenge.message());

    // Time: refused from expires_at on, accepted up to the longest TTL
    // ahead.
    assert_eq!(check(&expectations(EXPIRES_AT - 1)), Ok(()));
    assert_eq!(check(&expectations(EXPIRES_AT)), Err(Refusal::Expired));
    assert_eq!(check(&expectations(EXPIRES_AT + 1)), Err(Refusal::Expired));
    assert_eq!(check(&expectations(i64::MAX)), Err(Refusal::Expired));
    let horizon = EXPIRES_AT - micros(MAX_CHALLENGE_TTL);
    assert_eq!(check(&expectations(horizon)), Ok(()));
    assert_eq!(
        check(&expectations(horizon - 1)),
        Err(Refusal::ExpiresTooLate)
    );
    assert_eq!(check(&expectations(i64::MIN)), Err(Refusal::ExpiresTooLate));

    // The instance, byte for byte.
    for other in [
        "01936f4e-8a2b-7c3d-9e4f-0123456789ac",
        "01936F4E-8A2B-7C3D-9E4F-0123456789AB",
        "01936f4e-8a2b-7c3d-9e4f-0123456789a",
        "01936f4e-8a2b-7c3d-9e4f-0123456789ab ",
        "",
    ] {
        let expected = Expectations {
            instance_id: other,
            ..expectations(issued_at)
        };
        assert_eq!(check(&expected), Err(Refusal::OtherInstance), "{other:?}");
    }
    // The first refusal wins: another instance, expired as well.
    let expected = Expectations {
        instance_id: "other",
        ..expectations(EXPIRES_AT)
    };
    assert_eq!(check(&expected), Err(Refusal::OtherInstance));

    // The epoch, the replacement identity and the new key, when expected.
    let rfc_key = RecoveryPublicKey::from_hex(RFC_KEY).unwrap();
    let other_key = RecoveryPublicKey::from_hex(OTHER_KEY).unwrap();
    let all = Expectations {
        recovery_key_epoch: Some(1),
        replacement_public_identity: Some("spki-sha256:new"),
        new_recovery_public_key: Some(&rfc_key),
        ..expectations(issued_at)
    };
    assert_eq!(check(&all), Ok(()));
    for (expected, refusal) in [
        (
            Expectations {
                recovery_key_epoch: Some(2),
                ..all
            },
            Refusal::OtherEpoch,
        ),
        (
            Expectations {
                recovery_key_epoch: Some(0),
                ..all
            },
            Refusal::OtherEpoch,
        ),
        (
            Expectations {
                replacement_public_identity: Some("spki-sha256:NEW"),
                ..all
            },
            Refusal::OtherReplacementIdentity,
        ),
        (
            Expectations {
                replacement_public_identity: Some("spki-sha256:ne"),
                ..all
            },
            Refusal::OtherReplacementIdentity,
        ),
        (
            Expectations {
                new_recovery_public_key: Some(&other_key),
                ..all
            },
            Refusal::OtherNewRecoveryKey,
        ),
    ] {
        assert_eq!(check(&expected), Err(refusal), "{refusal:?}");
    }
}

/// `check_challenge` records the replacement as confirmed exactly when it
/// was given both the replacement's identity and the new key, which then
/// matched; the epoch plays no part. A mismatch is still refused.
#[test]
fn check_challenge_records_a_confirmed_replacement() {
    let challenge = parse_challenge(&message(&fixture_canonical("op_1"))).unwrap();
    let rfc_key = RecoveryPublicKey::from_hex(RFC_KEY).unwrap();
    let other_key = RecoveryPublicKey::from_hex(OTHER_KEY).unwrap();
    let base = expectations(EXPIRES_AT - 1);
    let confirmed = |expected: &Expectations<'_>| {
        check_challenge(&challenge, expected).map(|verified| verified.replacement_confirmed())
    };
    for (identity, key, epoch, expected) in [
        (None, None, None, false),
        (Some("spki-sha256:new"), None, None, false),
        (None, Some(&rfc_key), None, false),
        (None, Some(&rfc_key), Some(1), false),
        (Some("spki-sha256:new"), None, Some(1), false),
        (Some("spki-sha256:new"), Some(&rfc_key), None, true),
        (Some("spki-sha256:new"), Some(&rfc_key), Some(1), true),
    ] {
        let expectations = Expectations {
            replacement_public_identity: identity,
            new_recovery_public_key: key,
            recovery_key_epoch: epoch,
            ..base
        };
        assert_eq!(
            confirmed(&expectations),
            Ok(expected),
            "{identity:?} {:?} {epoch:?}",
            key.is_some()
        );
    }
    let mismatched = Expectations {
        replacement_public_identity: Some("spki-sha256:new"),
        new_recovery_public_key: Some(&other_key),
        ..base
    };
    assert_eq!(confirmed(&mismatched), Err(Refusal::OtherNewRecoveryKey));
    assert_eq!(format!("{mismatched:?}"), "Expectations(..)");
}
