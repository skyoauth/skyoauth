//! The public identity fixture
//! `tests/conformance/fixtures/_recovery/public_identity.v1.json` against the
//! service's [`canonical_public_identity`], so that the workstation's copy
//! (`skyoauth_operator::identity::public_identity_of_spki`, which
//! `operator/tests/operator.rs` checks against the same file) and the
//! service's cannot drift apart: the same prefix, the same bound, the same
//! digest for every case and the same message for each error. A case with
//! `service_expected` holds bytes that are not a strict DER
//! `SubjectPublicKeyInfo`, which only the service checks. They test the
//! fixture file, not a scenario: no name here matches `a\d\d_`, and no
//! stage of `tests/conformance/scenarios.toml` lists them (layout §3). They
//! need no server and no database.

use serde_json::Value;
use skyoauth_service::identity::{
    IdentityError, MAX_SPKI_DER_BYTES, PUBLIC_IDENTITY_PREFIX, canonical_public_identity,
};

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/fixtures/_recovery/public_identity.v1.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string in {value}"))
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

/// A case's DER bytes: `hex`, then `fill_count` copies of `fill_byte`.
fn der_bytes(der: &Value) -> Vec<u8> {
    let mut bytes = unhex(text(der, "hex"));
    if let Some(count) = der.get("fill_count") {
        let fill = unhex(text(der, "fill_byte"));
        assert_eq!(fill.len(), 1, "{der}");
        let count = usize::try_from(count.as_u64().expect("fill_count")).unwrap();
        bytes.extend(std::iter::repeat_n(fill[0], count));
    }
    bytes
}

#[test]
fn identity_fixture_prefix_and_bound_are_the_services() {
    let fixture = fixture();
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "public_identity");
    assert_eq!(fixture["prefix"], PUBLIC_IDENTITY_PREFIX);
    assert_eq!(
        fixture["max_der_bytes"],
        u64::try_from(MAX_SPKI_DER_BYTES).unwrap()
    );
}

#[test]
fn identity_cases_through_canonical_public_identity() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = text(case, "case");
        let result = canonical_public_identity(&der_bytes(&case["der"]));
        let service_expected = case.get("service_expected");
        let expected = service_expected.unwrap_or(&case["expected"]);
        // Exactly one member, `identity` or `error`, and it is a string.
        let members: Vec<(&String, &Value)> = expected
            .as_object()
            .unwrap_or_else(|| panic!("{name}: expected is not an object: {expected}"))
            .iter()
            .collect();
        let [(member, Value::String(value))] = members.as_slice() else {
            panic!("{name}: expected is not one string member: {expected}");
        };
        match member.as_str() {
            "identity" => assert_eq!(result.as_deref(), Ok(value.as_str()), "{name}"),
            "error" => {
                let message = match service_expected {
                    Some(_) => value.as_str(),
                    None => text(&fixture["messages"], value),
                };
                let err = result.expect_err(name);
                assert_eq!(err.to_string(), message, "{name}");
            }
            other => panic!("{name}: expected has {other}, not identity or error"),
        }
    }
    // Each way the service refuses bytes that the operator hashes has a
    // `service_expected` case.
    let refused: Vec<&str> = cases
        .iter()
        .filter_map(|case| case.get("service_expected"))
        .map(|service| text(service, "error"))
        .collect();
    for err in [
        IdentityError::Truncated,
        IdentityError::NotDer,
        IdentityError::TrailingBytes,
        IdentityError::NotSpki,
    ] {
        let message = err.to_string();
        assert!(
            refused.contains(&message.as_str()),
            "no case of {message:?}"
        );
    }
}
