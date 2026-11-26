//! The wire side shared by the A22 and A49 wire tests
//! (`security::a22_wire`, `security::a49_wire`); a helper module of the
//! `pg` target, not a scenario (no test, no name matching `a\d\d_`).
//!
//! Both drive the admin read router of slice S4
//! (`skyoauth_service::admin_http::admin_router`) with
//! `tower::ServiceExt::oneshot` through
//! `admin_http::test_support::with_admin_peer`, the tests' fake acceptor,
//! which hands the router an *already-verified* peer identity. This module
//! holds what they share, with no SQL of its own:
//!
//! - **The wire error catalogue** ([`wire_error`], [`assert_wire_error`]):
//!   the status, `Content-Type`, `Cache-Control`, the absence of
//!   `Retry-After` and the body bytes of an error code are read from
//!   `tests/conformance/fixtures/_wire/errors.v1.json`, as
//!   `tests/harness/wire_errors.rs` reads it, never typed in a test.
//! - **Requests** ([`get_with`], [`Answer`]): one `GET` through the router,
//!   with a verified peer when given and extra headers, and its answer.
//! - **Keys** ([`key`]): canonical public identities (`spki-sha256:<hex>`)
//!   computed from real Ed25519 `SubjectPublicKeyInfo`s with the service's
//!   own `identity::canonical_public_identity`, the form the acceptor will
//!   hand over.
//! - **Time** ([`at`], [`FixedClock`]): seconds after the tests' bootstrap
//!   time, and the router's clock an hour after it.
//! - **Operations** ([`seed_operation`], [`SeededOperation`]): an
//!   administrative operation row, written with the bare operation-row
//!   writer (`registry::test_support::insert_administrative_operation`)
//!   after its `administrative_operation.create` audit event, in one
//!   transaction.
//!
//! Each test module keeps its own fixture: the bootstrap, the tenants, the
//! operators and which operations it seeds.

use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use ed25519_dalek::SigningKey;
use serde_json::{Map, Value};
use skyoauth_service::{
    admin_http::test_support::with_admin_peer,
    identity::canonical_public_identity,
    operation::{Clock, DigestEnvelope},
    persistence::{
        PgPool,
        registry::{self, AuditActor, JsonObject, NewAdministrativeOperation, NewAuditEvent},
    },
};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// The wire error catalogue

/// The catalogue file, read as `tests/harness/wire_errors.rs` reads it.
fn catalogue() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/fixtures/_wire/errors.v1.json"
    );
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{path}: {err}"))
}

/// What a client sees for one error code, as the catalogue gives it.
#[derive(Debug)]
pub(super) struct WireError {
    code: &'static str,
    status: StatusCode,
    content_type: String,
    /// The catalogue's `Cache-Control`, the same for every answer.
    pub(super) cache_control: String,
    /// The body: `body.shape` with its `<code>` placeholder filled in.
    body: Bytes,
    /// The body's members: the shape's, and no other
    /// (`additional_members` is `false`).
    members: BTreeSet<String>,
}

/// The catalogue's entry for `code`. Panics for a code the catalogue does
/// not list, or one that may carry `Retry-After` (the checks here assert
/// its absence, which the catalogue promises only for `never`).
pub(super) fn wire_error(code: &'static str) -> WireError {
    let catalogue = catalogue();
    let entry = &catalogue["errors"][code];
    assert!(entry.is_object(), "{code} is not in the catalogue");
    assert_eq!(
        entry["retry_after"], "never",
        "{code}: these checks assert that Retry-After is absent"
    );
    let status = entry["http_status"]
        .as_u64()
        .and_then(|status| u16::try_from(status).ok())
        .and_then(|status| StatusCode::from_u16(status).ok())
        .unwrap_or_else(|| panic!("{code}: http_status {}", entry["http_status"]));
    let body = &catalogue["body"];
    assert_eq!(body["additional_members"], false, "body.additional_members");
    let shape = body["shape"].as_object().expect("body.shape is an object");
    let filled: Map<String, Value> = shape
        .iter()
        .map(|(member, placeholder)| {
            assert_eq!(placeholder, "<code>", "body.shape.{member}");
            (member.clone(), Value::from(code))
        })
        .collect();
    WireError {
        code,
        status,
        content_type: body["content_type"]
            .as_str()
            .expect("body.content_type")
            .to_owned(),
        cache_control: catalogue["cache_control"]
            .as_str()
            .expect("cache_control")
            .to_owned(),
        body: Bytes::from(serde_json::to_vec(&Value::Object(filled)).unwrap()),
        members: shape.keys().cloned().collect(),
    }
}

/// `answer` is exactly `expected`: status, `Content-Type`,
/// `Cache-Control`, no `Retry-After`, the body bytes, and a body whose
/// members are the shape's and no other.
#[track_caller]
pub(super) fn assert_wire_error(answer: &Answer, expected: &WireError, what: &str) {
    let code = expected.code;
    assert_eq!(
        answer.status, expected.status,
        "{what}: {code}: status ({:?})",
        answer.body
    );
    assert_eq!(
        answer.header(header::CONTENT_TYPE).as_deref(),
        Some(expected.content_type.as_str()),
        "{what}: {code}: Content-Type"
    );
    assert_eq!(
        answer.header(header::CACHE_CONTROL).as_deref(),
        Some(expected.cache_control.as_str()),
        "{what}: {code}: Cache-Control"
    );
    assert!(
        !answer.headers.contains_key(header::RETRY_AFTER),
        "{what}: {code}: Retry-After"
    );
    assert_eq!(answer.body, expected.body, "{what}: {code}: body");
    let body: Map<String, Value> = serde_json::from_slice(&answer.body)
        .unwrap_or_else(|err| panic!("{what}: {code}: body is no JSON object: {err}"));
    let members: BTreeSet<String> = body.keys().cloned().collect();
    assert_eq!(members, expected.members, "{what}: {code}: body members");
    assert_eq!(body["error"], code, "{what}: body error");
}

// ---------------------------------------------------------------------------
// Requests

/// A response: status, headers and body bytes. Two answers are equal when
/// all three are.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Answer {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Bytes,
}

impl Answer {
    pub(super) fn header(&self, name: header::HeaderName) -> Option<String> {
        self.headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    }

    pub(super) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// `GET uri` through `router`, with the verified peer `peer` set by the
/// tests' fake acceptor when given, and `headers`.
///
/// The router answers the same with and without the claim-shaped headers,
/// which is what the A22 tests show, so a request that lost one would pass
/// them unseen: the request is checked to carry every header given, name
/// and value, before it is sent.
pub(super) async fn get_with(
    router: &Router,
    peer: Option<&str>,
    uri: &str,
    headers: &[(&str, String)],
) -> Answer {
    let mut request = Request::get(uri);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let mut request = request.body(Body::empty()).unwrap();
    if let Some(peer) = peer {
        request = with_admin_peer(request, peer);
    }
    for (name, value) in headers {
        assert!(
            request
                .headers()
                .get_all(*name)
                .iter()
                .any(|sent| sent == value.as_str()),
            "{uri}: the request does not carry {name}: {value}"
        );
    }
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    Answer {
        status,
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------
// Keys

/// The canonical public identity of the Ed25519 key with secret `seed`
/// repeated: `identity::canonical_public_identity` of its DER
/// `SubjectPublicKeyInfo` (RFC 8410), the form the acceptor will compute.
pub(super) fn key(seed: u8) -> String {
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let public = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(&public);
    canonical_public_identity(&spki).unwrap()
}

// ---------------------------------------------------------------------------
// Time

/// The tests' bootstrap time, in seconds since the epoch.
const T0: u64 = 1_790_000_000;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;

/// `seconds` after the tests' bootstrap time.
pub(super) fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(T0 + seconds)
}

/// The server's clock for a list's "open at now": an hour after bootstrap,
/// before every seeded pending operation expires.
pub(super) struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        at(HOUR)
    }
}

// ---------------------------------------------------------------------------
// Operations

/// One administrative operation to seed.
pub(super) struct SeededOperation<'a> {
    pub(super) id: &'a str,
    /// `None`: an instance operation.
    pub(super) tenant: Option<&'a str>,
    /// The requester, an operator ID (`adm_<name>`).
    pub(super) actor: &'a str,
    pub(super) kind: &'a str,
    pub(super) plan: JsonObject,
    /// `Some(target)` for an `approve` (and only for one): an approval of
    /// `target`, consumed (`success`) with no expiry and a placeholder
    /// digest. `None`: pending until a day after bootstrap, with the
    /// digest of its envelope at revision 1.
    pub(super) approves: Option<&'a str>,
}

/// Writes `op` after its `administrative_operation.create` event
/// (`evt_<id>`, a second after bootstrap, by its requester), in one
/// transaction.
pub(super) async fn seed_operation(pool: &PgPool, op: &SeededOperation<'_>) {
    assert_eq!(
        op.kind == "approve",
        op.approves.is_some(),
        "{}: an approve, and only an approve, names the operation it approves",
        op.id
    );
    let expires_at_us = i64::try_from((T0 + DAY) * 1_000_000).unwrap();
    let request_digest = if op.approves.is_some() {
        vec![7; 32]
    } else {
        DigestEnvelope {
            id: op.id,
            tenant_id: op.tenant,
            actor_id: op.actor,
            kind: op.kind,
            expected_revision: 1,
            expires_at_us,
            plan: &op.plan,
        }
        .digest()
        .unwrap()
        .as_bytes()
        .to_vec()
    };
    let audit_id = format!("evt_{}", op.id);
    let mut transaction = pool.begin().await.unwrap();
    registry::test_support::append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: audit_id.clone(),
            tenant_id: op.tenant.map(Into::into),
            timestamp: at(1),
            actor: AuditActor::Operator(op.actor.into()),
            action: "administrative_operation.create".into(),
            object_id: op.id.into(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    registry::test_support::insert_administrative_operation(
        &mut transaction,
        &NewAdministrativeOperation {
            id: op.id.into(),
            tenant_id: op.tenant.map(Into::into),
            actor_id: op.actor.into(),
            kind: op.kind.into(),
            request_digest,
            expected_revision: 1,
            immutable_plan: op.plan.clone(),
            expires_at: op.approves.is_none().then(|| at(DAY)),
            approves_operation_id: op.approves.map(Into::into),
            outcome: if op.approves.is_some() {
                "success"
            } else {
                "pending"
            }
            .into(),
            audit_id,
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}
