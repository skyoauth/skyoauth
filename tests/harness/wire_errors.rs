//! The wire error catalogue `tests/conformance/fixtures/_wire/errors.v1.json`
//! against the codes of the service (`skyoauth_service::admin_http`). They
//! test the catalogue file, not the service's behaviour, so they are not
//! scenario tests: no name here matches `a\d\d_`, and no stage of
//! `tests/conformance/scenarios.toml` lists them (layout §3). They need no
//! server and no database; they run in the `pg` target, the one CI runs.
//!
//! The catalogue is a fixture file for the replaying consumers (layout
//! §1.3: a case refers to `_wire/errors.v1.json#<code>`), and the checks
//! here keep it from drifting from the service: the same set of codes, each
//! with the status the service gives it, the body shape and the one
//! `Retry-After` value. The mapping from a service error to a code is
//! pinned by the service's own unit tests (`admin_http/error.rs`).

use std::collections::BTreeSet;

use serde_json::Value;
use skyoauth_service::admin_http::{ErrorCode, RETRY_AFTER_SECONDS};

fn catalogue() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/fixtures/_wire/errors.v1.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn entries(catalogue: &Value) -> &serde_json::Map<String, Value> {
    catalogue["errors"]
        .as_object()
        .expect("errors is an object")
}

#[test]
fn catalogue_envelope() {
    let catalogue = catalogue();
    assert_eq!(catalogue["fixture_version"], 1);
    assert_eq!(catalogue["kind"], "wire_error_catalogue");
    assert_eq!(catalogue["body"]["content_type"], "application/json");
    assert_eq!(catalogue["body"]["additional_members"], false);
    assert_eq!(
        catalogue["body"]["shape"],
        serde_json::json!({ "error": "<code>" })
    );
    assert_eq!(catalogue["cache_control"], "no-store");
}

#[test]
fn catalogue_has_exactly_the_codes_of_the_service() {
    let catalogue = catalogue();
    let listed: BTreeSet<&str> = entries(&catalogue).keys().map(String::as_str).collect();
    let service: BTreeSet<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
    assert_eq!(listed, service);
}

#[test]
fn catalogue_statuses_and_retry_after_are_the_services() {
    let catalogue = catalogue();
    assert_eq!(
        catalogue["retry_after_seconds_when_present"],
        u64::from(RETRY_AFTER_SECONDS)
    );
    for code in ErrorCode::ALL {
        let entry = &entries(&catalogue)[code.as_str()];
        assert_eq!(
            entry["http_status"],
            u64::from(code.status().as_u16()),
            "{}",
            code.as_str()
        );
        // Only `auth_unavailable` carries `Retry-After`, and only for a
        // retryable cause.
        let retry = if code == ErrorCode::AuthUnavailable {
            "sometimes"
        } else {
            "never"
        };
        assert_eq!(entry["retry_after"], retry, "{}", code.as_str());
        assert!(
            matches!(entry["origin"].as_str(), Some("reused" | "proposed")),
            "{}",
            code.as_str()
        );
        let applies = entry["applies_when"].as_array().expect("applies_when");
        assert!(
            !applies.is_empty()
                && applies
                    .iter()
                    .all(|s| s.as_str().is_some_and(|s| !s.is_empty())),
            "{}",
            code.as_str()
        );
    }
}
