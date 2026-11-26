//! Target `operator`: the workstation library against the shared fixture
//! files `tests/conformance/fixtures/_recovery/key.v1.json`,
//! `public_identity.v1.json` and `challenge.v1.json` (in `challenge`, with
//! the strictness of the challenge reader and the challenge checks), whose
//! cases the `pg` target of `skyoauth-scenarios` also checks against the
//! service (`tests/harness/`). Every case of every file is run, and a test
//! fails when a file, a member or a case is not
//! (`every_fixture_file_and_case_is_covered`).
//!
//! Portable: no network, database, socket or clock (a time is always
//! injected); it runs on Linux, macOS and Windows. These are not scenario
//! tests: no name here may match the scenario pattern `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, and the
//! registry (`tests/conformance/scenarios.toml`) does not list them.

mod challenge;
mod support;

use std::collections::BTreeSet;

use challenge::{CHALLENGE_FIXTURE, VECTOR_MEMBERS, run_challenge_vectors};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use skyoauth_operator::{
    identity::{
        IdentityError, MAX_SPKI_DER_BYTES, PUBLIC_IDENTITY_PREFIX, public_identity_of_spki,
    },
    recovery::{KeyError, RECOVERY_PUBLIC_KEY_LENGTH, RecoveryPublicKey},
};
use support::{der_bytes, fixtures_dir, list, recovery_fixture, text, unhex};

const KEY_FIXTURE: &str = "key.v1.json";
const IDENTITY_FIXTURE: &str = "public_identity.v1.json";

/// Every key error, with its class in the key fixture.
const KEY_ERRORS: [(KeyError, &str); 5] = [
    (KeyError::NotHex, "not_hex"),
    (KeyError::Length, "length"),
    (KeyError::Undecodable, "undecodable"),
    (KeyError::NotCanonical, "not_canonical"),
    (KeyError::SmallOrder, "small_order"),
];

/// Every identity error, with its class in the identity fixture.
const IDENTITY_ERRORS: [(IdentityError, &str); 2] = [
    (IdentityError::Empty, "empty"),
    (IdentityError::TooLarge, "too_large"),
];

/// The class of a key result in the key fixture: `valid` or an error's.
fn key_class(result: Result<RecoveryPublicKey, KeyError>) -> &'static str {
    match result {
        Ok(_) => "valid",
        Err(err) => {
            KEY_ERRORS
                .iter()
                .find(|(error, _)| *error == err)
                .expect("every error has a class")
                .1
        }
    }
}

/// Checks one key result against a case's `expected` class: a valid key
/// keeps its bytes, an error gives the fixture's message.
fn check_key(fixture: &Value, case: &Value, result: Result<RecoveryPublicKey, KeyError>) {
    let name = text(case, "case");
    let expected = text(case, "expected");
    assert_eq!(key_class(result), expected, "{name}");
    match result {
        Ok(key) => {
            let hex = key.to_hex();
            assert_eq!(key.as_bytes().to_vec(), unhex(&hex), "{name}");
            assert_eq!(RecoveryPublicKey::from_hex(&hex), Ok(key), "{name}");
            assert_eq!(
                RecoveryPublicKey::from_bytes(key.as_bytes()),
                Ok(key),
                "{name}"
            );
        }
        Err(err) => assert_eq!(
            err.to_string(),
            text(&fixture["messages"], expected),
            "{name}"
        ),
    }
}

/// Runs every `byte_cases` case through [`RecoveryPublicKey::from_bytes`]
/// and, for 32 bytes, its hexadecimal through
/// [`RecoveryPublicKey::from_hex`], which must agree. Returns the names.
fn run_key_byte_cases(fixture: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for case in list(fixture, "byte_cases") {
        let hex = text(case, "key");
        let bytes = unhex(hex);
        let result = RecoveryPublicKey::from_bytes(&bytes);
        check_key(fixture, case, result);
        if let Ok(key) = result {
            assert_eq!(key.to_hex(), hex, "{}", text(case, "case"));
        }
        if bytes.len() == RECOVERY_PUBLIC_KEY_LENGTH {
            assert_eq!(
                RecoveryPublicKey::from_hex(hex),
                result,
                "{}",
                text(case, "case")
            );
        }
        names.push(text(case, "case").to_owned());
    }
    names
}

/// Runs every `text_cases` case through [`RecoveryPublicKey::from_hex`].
/// Returns the names.
fn run_key_text_cases(fixture: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for case in list(fixture, "text_cases") {
        let result = RecoveryPublicKey::from_hex(text(case, "text"));
        check_key(fixture, case, result);
        if let Ok(key) = result {
            assert_eq!(key.to_hex(), text(case, "text"), "{}", text(case, "case"));
        }
        names.push(text(case, "case").to_owned());
    }
    names
}

/// Runs every identity case through [`public_identity_of_spki`]. Returns
/// the names.
fn run_identity_cases(fixture: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for case in list(fixture, "cases") {
        let name = text(case, "case");
        let der = der_bytes(&case["der"]);
        let result = public_identity_of_spki(&der);
        let expected = &case["expected"];
        match (expected.get("identity"), expected.get("error")) {
            (Some(identity), None) => {
                let identity = identity.as_str().expect("identity is a string");
                assert_eq!(result.as_deref(), Ok(identity), "{name}");
                let digest = identity
                    .strip_prefix(PUBLIC_IDENTITY_PREFIX)
                    .unwrap_or_else(|| panic!("{name}: no prefix"));
                assert_eq!(unhex(digest).len(), 32, "{name}");
            }
            (None, Some(class)) => {
                let class = class.as_str().expect("error is a string");
                let err = result.expect_err(name);
                let listed = IDENTITY_ERRORS
                    .iter()
                    .find(|(error, _)| *error == err)
                    .expect("every error has a class")
                    .1;
                assert_eq!(listed, class, "{name}");
                assert_eq!(err.to_string(), text(&fixture["messages"], class), "{name}");
            }
            _ => panic!("{name}: expected is one identity or one error"),
        }
        names.push(name.to_owned());
    }
    names
}

#[test]
fn key_fixture_envelope_matches_the_crate() {
    let fixture = recovery_fixture(KEY_FIXTURE);
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "recovery_public_key");
    assert_eq!(
        fixture["length_bytes"],
        u64::try_from(RECOVERY_PUBLIC_KEY_LENGTH).unwrap()
    );
    assert_eq!(
        fixture["checks"],
        serde_json::json!(["length", "undecodable", "not_canonical", "small_order"])
    );
    let messages = fixture["messages"].as_object().expect("messages");
    assert_eq!(messages.len(), KEY_ERRORS.len());
    for (error, class) in KEY_ERRORS {
        assert_eq!(
            error.to_string(),
            text(&fixture["messages"], class),
            "{class}"
        );
    }
}

#[test]
fn key_byte_cases_match_from_bytes() {
    let fixture = recovery_fixture(KEY_FIXTURE);
    assert!(!run_key_byte_cases(&fixture).is_empty());
}

#[test]
fn key_text_cases_match_from_hex() {
    let fixture = recovery_fixture(KEY_FIXTURE);
    assert!(!run_key_text_cases(&fixture).is_empty());
}

/// The classes of the byte cases hold by `ed25519-dalek` alone, so the
/// fixture tests what it says it tests: an undecodable case does not
/// decode, a non-canonical one decodes to another encoding, a small-order
/// one is canonical and weak, a valid one canonical and not weak. And some
/// non-canonical cases are of small order, so the order of the checks is
/// observable: `not_canonical` comes before `small_order`.
#[test]
fn key_byte_case_classes_hold_independently() {
    let fixture = recovery_fixture(KEY_FIXTURE);
    let mut weak_non_canonical = 0;
    for case in list(&fixture, "byte_cases") {
        let name = text(case, "case");
        let bytes = unhex(text(case, "key"));
        let Ok(bytes) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            assert_eq!(text(case, "expected"), "length", "{name}");
            continue;
        };
        let decoded = VerifyingKey::from_bytes(&bytes);
        let canonical = decoded
            .as_ref()
            .is_ok_and(|key| key.to_edwards().compress().to_bytes() == bytes);
        let weak = decoded.as_ref().is_ok_and(VerifyingKey::is_weak);
        match text(case, "expected") {
            "undecodable" => assert!(decoded.is_err(), "{name}"),
            "not_canonical" => {
                assert!(decoded.is_ok() && !canonical, "{name}");
                weak_non_canonical += usize::from(weak);
            }
            "small_order" => assert!(canonical && weak, "{name}"),
            "valid" => assert!(canonical && !weak, "{name}"),
            other => panic!("{name}: class {other} for 32 bytes"),
        }
    }
    assert!(weak_non_canonical > 0);
}

#[test]
fn key_debug_and_errors_show_no_key_byte() {
    let hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let key = RecoveryPublicKey::from_hex(hex).unwrap();
    assert_eq!(format!("{key:?}"), "RecoveryPublicKey(..)");
    assert_eq!(format!("{key:#?}"), "RecoveryPublicKey(..)");
    for (error, class) in KEY_ERRORS {
        for shown in [
            format!("{error:?}"),
            format!("{error:#?}"),
            error.to_string(),
        ] {
            assert!(
                !shown.contains("d75a") && !shown.contains("D75A"),
                "{class}"
            );
            assert!(
                !shown.contains("0x") && !shown.contains('['),
                "{class}: {shown}"
            );
        }
    }
    // An upper-case key is refused as text, whatever its bytes are.
    assert_eq!(
        RecoveryPublicKey::from_hex(&hex.to_ascii_uppercase()),
        Err(KeyError::NotHex)
    );
}

#[test]
fn identity_fixture_envelope_matches_the_crate() {
    let fixture = recovery_fixture(IDENTITY_FIXTURE);
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "public_identity");
    assert_eq!(fixture["prefix"], PUBLIC_IDENTITY_PREFIX);
    assert_eq!(
        fixture["max_der_bytes"],
        u64::try_from(MAX_SPKI_DER_BYTES).unwrap()
    );
    let messages = fixture["messages"].as_object().expect("messages");
    assert_eq!(messages.len(), IDENTITY_ERRORS.len());
    for (error, class) in IDENTITY_ERRORS {
        assert_eq!(
            error.to_string(),
            text(&fixture["messages"], class),
            "{class}"
        );
        assert!(!format!("{error:?}").contains('['), "{class}");
    }
}

#[test]
fn identity_cases_match_public_identity_of_spki() {
    let fixture = recovery_fixture(IDENTITY_FIXTURE);
    assert!(!run_identity_cases(&fixture).is_empty());
}

/// The bounds, on bytes that are not DER: 1 and [`MAX_SPKI_DER_BYTES`]
/// bytes are hashed, 0 and one more are refused. The identity is the
/// prefix and 64 lowercase digits, and depends on every byte.
#[test]
fn identity_bounds_and_form() {
    for length in [1, 2, MAX_SPKI_DER_BYTES - 1, MAX_SPKI_DER_BYTES] {
        let identity = public_identity_of_spki(&vec![0xff; length]).unwrap();
        let digest = identity.strip_prefix(PUBLIC_IDENTITY_PREFIX).unwrap();
        assert_eq!(digest.len(), 64, "{length}");
        assert_eq!(unhex(digest).len(), 32, "{length}");
    }
    assert_eq!(public_identity_of_spki(&[]), Err(IdentityError::Empty));
    assert_eq!(
        public_identity_of_spki(&vec![0x30; MAX_SPKI_DER_BYTES + 1]),
        Err(IdentityError::TooLarge)
    );
    let mut bytes = vec![0x30; MAX_SPKI_DER_BYTES];
    let first = public_identity_of_spki(&bytes).unwrap();
    bytes[MAX_SPKI_DER_BYTES - 1] = 0x31;
    assert_ne!(public_identity_of_spki(&bytes).unwrap(), first);
}

/// The members of a fixture file, so that a new list of cases cannot be
/// added without a reader.
fn members(fixture: &Value) -> BTreeSet<&str> {
    fixture
        .as_object()
        .expect("a fixture is an object")
        .keys()
        .map(String::as_str)
        .collect()
}

/// The `case` names of `cases`, which must be unique and match
/// `^[a-z0-9_]+$` (conformance layout §1.3).
fn case_names(cases: &[Value]) -> BTreeSet<String> {
    let names: BTreeSet<String> = cases.iter().map(|c| text(c, "case").to_owned()).collect();
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

/// The `expected` classes of the key cases in `cases`.
fn key_classes(cases: &[Value]) -> BTreeSet<&str> {
    cases.iter().map(|c| text(c, "expected")).collect()
}

#[test]
fn every_fixture_file_and_case_is_covered() {
    // Exactly the files this target reads: a new fixture file under
    // `_recovery/` fails here until a reader is added.
    let mut files: Vec<String> = std::fs::read_dir(fixtures_dir().join("_recovery"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(files, [CHALLENGE_FIXTURE, KEY_FIXTURE, IDENTITY_FIXTURE]);

    let challenge = recovery_fixture(CHALLENGE_FIXTURE);
    assert_eq!(
        members(&challenge),
        BTreeSet::from([
            "fixture_version",
            "kind",
            "description",
            "prefix",
            "request_digest_prefix",
            "actor_id",
            "challenge_kind",
            "ttl_seconds",
            "plan_members",
            "vectors",
        ])
    );
    let vectors = list(&challenge, "vectors");
    assert_eq!(
        run_challenge_vectors(&challenge)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        case_names(vectors)
    );
    for vector in vectors {
        assert_eq!(members(vector), BTreeSet::from(VECTOR_MEMBERS), "{vector}");
    }
    // The service's pinned vector, and the escapes and integer extremes.
    for case in ["op_1", "escapes", "integer_extremes"] {
        assert!(case_names(vectors).contains(case), "no vector {case}");
    }

    let key = recovery_fixture(KEY_FIXTURE);
    assert_eq!(
        members(&key),
        BTreeSet::from([
            "fixture_version",
            "kind",
            "description",
            "length_bytes",
            "checks",
            "messages",
            "service_plan_messages",
            "byte_cases",
            "text_cases",
        ])
    );
    let byte_cases = list(&key, "byte_cases");
    let text_cases = list(&key, "text_cases");
    assert_eq!(
        run_key_byte_cases(&key)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        case_names(byte_cases)
    );
    assert_eq!(
        run_key_text_cases(&key)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        case_names(text_cases)
    );
    // Every byte class has a byte case, and the text form has a valid,
    // a not_hex and a byte-check case.
    assert_eq!(
        key_classes(byte_cases),
        BTreeSet::from([
            "valid",
            "length",
            "undecodable",
            "not_canonical",
            "small_order"
        ])
    );
    assert_eq!(
        key_classes(text_cases),
        BTreeSet::from([
            "valid",
            "not_hex",
            "undecodable",
            "not_canonical",
            "small_order"
        ])
    );
    // Nothing is trimmed: padded text is not_hex whether its length is 64
    // bytes (62 digits once trimmed) or more (64 digits once trimmed).
    let trimmed_lengths: BTreeSet<(usize, usize)> = text_cases
        .iter()
        .map(|c| text(c, "text"))
        .filter(|t| t.trim() != *t)
        .map(|t| (t.len(), t.trim().len()))
        .collect();
    assert!(trimmed_lengths.contains(&(64, 62)), "{trimmed_lengths:?}");
    assert!(
        trimmed_lengths
            .iter()
            .any(|&(len, trimmed)| len > 64 && trimmed == 64),
        "{trimmed_lengths:?}"
    );

    let identity = recovery_fixture(IDENTITY_FIXTURE);
    assert_eq!(
        members(&identity),
        BTreeSet::from([
            "fixture_version",
            "kind",
            "description",
            "prefix",
            "max_der_bytes",
            "messages",
            "cases",
        ])
    );
    let cases = list(&identity, "cases");
    assert_eq!(
        run_identity_cases(&identity)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        case_names(cases)
    );
    // Both bounds, both errors and, for each way the service refuses bytes
    // that this crate hashes, a case: truncated, not DER (an indefinite
    // length), trailing bytes and not a SubjectPublicKeyInfo.
    let lengths: BTreeSet<usize> = cases.iter().map(|c| der_bytes(&c["der"]).len()).collect();
    for length in [0, 1, MAX_SPKI_DER_BYTES, MAX_SPKI_DER_BYTES + 1] {
        assert!(lengths.contains(&length), "no case of {length} bytes");
    }
    let errors: BTreeSet<&str> = cases
        .iter()
        .filter_map(|c| c["expected"].get("error").and_then(Value::as_str))
        .collect();
    assert_eq!(errors, BTreeSet::from(["empty", "too_large"]));
    let service_errors: BTreeSet<&str> = cases
        .iter()
        .filter_map(|c| c.get("service_expected"))
        .map(|service| text(service, "error"))
        .collect();
    assert_eq!(
        service_errors,
        BTreeSet::from([
            "the public key encoding is truncated",
            "the public key is not in DER encoding",
            "the public key encoding has trailing bytes",
            "the public key is not a SubjectPublicKeyInfo",
        ])
    );
    for case in cases.iter().filter(|c| c.get("service_expected").is_some()) {
        assert!(case["expected"].get("identity").is_some(), "{case}");
    }
    for case in cases {
        let allowed = ["case", "der", "expected", "service_expected"];
        for member in members(case) {
            assert!(allowed.contains(&member), "{member} in {case}");
        }
    }
}
