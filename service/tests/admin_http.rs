//! The admin router of `skyoauth_service::admin_http` on a real database,
//! driven with `tower::ServiceExt::oneshot` through the tests' fake
//! acceptor (`admin_http::test_support::with_admin_peer`, the only way
//! besides the rustls acceptor to set the peer identity): the operation
//! reads of D4 on the instance and tenant paths, who may read what, the
//! one `not_found` for a missing operation and for every operation outside
//! the caller's view (byte for byte), the plan verbatim as canonical text
//! with a digest that recomputes from the response alone, the page bounds
//! and cursors, the error bodies reachable here, and that no header ever
//! stands in for the peer identity.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database. They are
//! registry tests, not conformance scenarios.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use common::TestDb;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use skyoauth_service::{
    admin_http::{AdminState, admin_router, test_support::with_admin_peer},
    operation::{Clock, DigestEnvelope},
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AuditActor, BootstrapRequest, JsonObject, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, NewAdministrativeOperation, NewAuditEvent,
            NewTenant, RegistryError, Status, bootstrap_instance,
            test_support::{
                append_audit_event, consume_administrative_operation,
                insert_administrative_operation,
            },
        },
    },
};
use tower::ServiceExt;

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;
/// 24 hours in microseconds.
const DAY: u64 = 86_400_000_000;
const SEC: AdminRole = AdminRole::SecurityAdmin;
const TRUST: AdminRole = AdminRole::TrustAdmin;
const AUDITOR: AdminRole = AdminRole::Auditor;

/// The instance `security_admin`, requester of the instance operations.
const KEY_SEC: &str = "spki-sha256:sec";
/// `ten_a`'s `trust_admin`, requester of `op_a1`, `op_a3` and `op_a4`.
const KEY_TRUST_A: &str = "spki-sha256:trust_a";
/// Another `trust_admin` of `ten_a`, requester of `op_a2`.
const KEY_TRUST_A2: &str = "spki-sha256:trust_a2";
/// `ten_a`'s `auditor`.
const KEY_AUD_A: &str = "spki-sha256:aud_a";
/// `ten_b`'s `trust_admin`, requester of `op_b1`.
const KEY_TRUST_B: &str = "spki-sha256:trust_b";
/// An instance `auditor`: not a reader of operations.
const KEY_AUD_I: &str = "spki-sha256:aud_i";
/// `ten_a`'s `client_admin`: not a reader.
const KEY_CLIENT_A: &str = "spki-sha256:client_a";
/// An operator whose instance `security_admin` binding is disabled.
const KEY_BIND_OFF: &str = "spki-sha256:bind_off";
/// No credential has it.
const KEY_UNKNOWN: &str = "spki-sha256:unknown";

/// The plan of `op_a1`: an integer above 2^53, a negative one, nested
/// members out of order, an escape and a non-ASCII character.
fn plan_a1() -> JsonObject {
    object(json!({
        "requester_credential_id": "crd_adm_trust_a",
        "z": {"b": [1, -2, null, true], "a": "\u{1}\"\\é"},
        "effective_at_us": 9_007_199_254_740_993_i64,
        "expires_at_us": i64::MAX,
        "B": "",
    }))
}

/// Its canonical text, written out by hand.
const PLAN_A1_TEXT: &str = "{\"B\":\"\",\"effective_at_us\":9007199254740993,\
     \"expires_at_us\":9223372036854775807,\"requester_credential_id\":\"crd_adm_trust_a\",\
     \"z\":{\"a\":\"\\u0001\\\"\\\\\u{e9}\",\"b\":[1,-2,null,true]}}";

fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

fn micros(micros: u64) -> i64 {
    i64::try_from(T0 + micros).unwrap()
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(members) => members,
        other => panic!("not an object: {other}"),
    }
}

/// The server's clock for "open at now": one hour after `T0`.
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        at(3_600_000_000)
    }
}

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// One operator `admin` with the credential `crd_<admin>` of `key` and the
/// bindings `(role, tenant, enabled)`.
async fn operator(
    pool: &PgPool,
    admin: &str,
    key: &str,
    bindings: &[(AdminRole, Option<&str>, bool)],
) {
    registry::test_support::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: admin.into(),
            status: Status::Enabled,
            created_at: at(0),
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_credential(
        pool,
        &NewAdminCredential {
            id: format!("crd_{admin}"),
            admin_id: admin.into(),
            public_identity: key.into(),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (index, &(role, tenant_id, enabled)) in bindings.iter().enumerate() {
        registry::test_support::create_admin_role_binding(
            pool,
            &NewAdminRoleBinding {
                id: format!("rb_{admin}_{index}"),
                admin_id: admin.into(),
                role,
                tenant_id: tenant_id.map(Into::into),
                status: if enabled {
                    Status::Enabled
                } else {
                    Status::Disabled
                },
            },
        )
        .await
        .unwrap();
    }
}

/// A pending operation of the flow as its request stores it: `id` of
/// `tenant_id` by `actor_id`, of `kind`, at expected revision 3, created at
/// `at(0)` and expiring at `at(expires)`, with `plan` and its digest (or
/// `digest` when given, to store a broken one).
fn operation(
    id: &str,
    tenant_id: Option<&str>,
    actor_id: &str,
    kind: &str,
    expires: u64,
    plan: JsonObject,
    digest: Option<Vec<u8>>,
) -> NewAdministrativeOperation {
    let digest = digest.unwrap_or_else(|| {
        DigestEnvelope {
            id,
            tenant_id,
            actor_id,
            kind,
            expected_revision: 3,
            expires_at_us: micros(expires),
            plan: &plan,
        }
        .digest()
        .unwrap()
        .as_bytes()
        .to_vec()
    });
    NewAdministrativeOperation {
        id: id.into(),
        tenant_id: tenant_id.map(Into::into),
        actor_id: actor_id.into(),
        kind: kind.into(),
        request_digest: digest,
        expected_revision: 3,
        immutable_plan: plan,
        expires_at: Some(at(expires)),
        approves_operation_id: None,
        outcome: "pending".into(),
        audit_id: format!("evt_{id}"),
    }
}

fn plan_of(credential: &str) -> JsonObject {
    object(json!({ "requester_credential_id": credential }))
}

/// Appends the operation's `administrative_operation.create` event and
/// inserts it, committed.
async fn insert(pool: &PgPool, new: &NewAdministrativeOperation) {
    let mut transaction = pool.begin().await.unwrap();
    append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: new.audit_id.clone(),
            tenant_id: new.tenant_id.clone(),
            timestamp: at(0),
            actor: AuditActor::Operator(new.actor_id.clone()),
            action: "administrative_operation.create".into(),
            object_id: new.id.clone(),
            previous_revision: None,
            new_revision: Some(1),
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    insert_administrative_operation(&mut transaction, new)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// A bootstrapped instance, the tenants `ten_a` and `ten_b`, the operators
/// of the `KEY_*` constants, and these operations (every expiry a day after
/// `T0` unless said otherwise):
///
/// - `op_a1`: `ten_a`, `trust_source_create` by `adm_trust_a`, plan
///   [`plan_a1`];
/// - `op_a2`: `ten_a`, `trust_keyset_version_create` by `adm_trust_a2`;
/// - `op_a3`: `ten_a`, `trust_source_update` by `adm_trust_a`, expired
///   half an hour after `T0`;
/// - `op_a4`: `ten_a`, `trust_keyset_version_enable` by `adm_trust_a`,
///   consumed (`applied`);
/// - `op_a5`: `ten_a`, an `approve` of `op_a1` by `adm_sec`, no expiry;
/// - `op_b1`: `ten_b`, `trust_source_update` by `adm_trust_b`;
/// - `op_i1`, `op_i2`: instance toggles by `adm_sec`;
/// - `op_ix`: an instance row of a `trust_source_create` kind (a kind of
///   another scope).
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
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
            recovery_public_key: &SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes(),
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    for (id, ns) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::test_support::create_tenant(
            &pool,
            &NewTenant {
                id: id.into(),
                name: format!("Tenant {id}"),
                secret_namespace: ns.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    let a = Some("ten_a");
    let b = Some("ten_b");
    for (admin, key, bindings) in [
        ("adm_sec", KEY_SEC, vec![(SEC, None, true)]),
        ("adm_trust_a", KEY_TRUST_A, vec![(TRUST, a, true)]),
        ("adm_trust_a2", KEY_TRUST_A2, vec![(TRUST, a, true)]),
        ("adm_aud_a", KEY_AUD_A, vec![(AUDITOR, a, true)]),
        ("adm_trust_b", KEY_TRUST_B, vec![(TRUST, b, true)]),
        ("adm_aud_i", KEY_AUD_I, vec![(AUDITOR, None, true)]),
        (
            "adm_client_a",
            KEY_CLIENT_A,
            vec![(AdminRole::ClientAdmin, a, true)],
        ),
        (
            "adm_bind_off",
            KEY_BIND_OFF,
            vec![(SEC, None, false), (TRUST, a, false), (AUDITOR, a, false)],
        ),
    ] {
        operator(&pool, admin, key, &bindings).await;
    }
    let ops = [
        operation(
            "op_a1",
            a,
            "adm_trust_a",
            "trust_source_create",
            DAY,
            plan_a1(),
            None,
        ),
        operation(
            "op_a2",
            a,
            "adm_trust_a2",
            "trust_keyset_version_create",
            DAY,
            plan_of("crd_adm_trust_a2"),
            None,
        ),
        operation(
            "op_a3",
            a,
            "adm_trust_a",
            "trust_source_update",
            1_800_000_000,
            plan_of("crd_adm_trust_a"),
            None,
        ),
        operation(
            "op_a4",
            a,
            "adm_trust_a",
            "trust_keyset_version_enable",
            DAY,
            plan_of("crd_adm_trust_a"),
            None,
        ),
        operation(
            "op_b1",
            b,
            "adm_trust_b",
            "trust_source_update",
            DAY,
            plan_of("crd_adm_trust_b"),
            None,
        ),
        operation(
            "op_i1",
            None,
            "adm_sec",
            "instance_security_policy_update",
            DAY,
            object(
                json!({"requester_credential_id": "crd_adm_sec", "widening_second_approver": true}),
            ),
            None,
        ),
        operation(
            "op_i2",
            None,
            "adm_sec",
            "instance_security_policy_update",
            DAY,
            object(
                json!({"requester_credential_id": "crd_adm_sec", "widening_second_approver": false}),
            ),
            None,
        ),
        operation(
            "op_ix",
            None,
            "adm_sec",
            "trust_source_create",
            DAY,
            plan_of("crd_adm_sec"),
            None,
        ),
    ];
    for op in &ops {
        insert(&pool, op).await;
    }
    let mut approve = operation(
        "op_a5",
        a,
        "adm_sec",
        "approve",
        DAY,
        JsonObject::new(),
        Some(vec![7; 32]),
    );
    approve.expires_at = None;
    approve.approves_operation_id = Some("op_a1".into());
    approve.outcome = "success".into();
    insert(&pool, &approve).await;
    let mut transaction = pool.begin().await.unwrap();
    consume_administrative_operation(&mut transaction, "op_a4", at(1_000), "applied")
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    (db, pool)
}

fn router(pool: &PgPool) -> Router {
    admin_router(AdminState::new(pool.clone(), Arc::new(FixedClock)))
}

/// The response's status, headers and body bytes.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    /// Status, content type, cache control and body: what a client sees.
    fn seen(&self) -> (StatusCode, Option<String>, Option<String>, Bytes) {
        let header = |name| {
            self.headers
                .get(name)
                .map(|value: &header::HeaderValue| value.to_str().unwrap().to_owned())
        };
        (
            self.status,
            header(header::CONTENT_TYPE),
            header(header::RETRY_AFTER),
            self.body.clone(),
        )
    }
}

/// `GET uri` through `router`, with the peer `key` when given and the
/// extra `headers`.
async fn get_with(
    router: &Router,
    key: Option<&str>,
    uri: &str,
    headers: &[(&str, &str)],
) -> Answer {
    let mut request = Request::get(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request.body(Body::empty()).unwrap();
    if let Some(key) = key {
        request = with_admin_peer(request, key);
    }
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{uri}");
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    Answer {
        status,
        headers,
        body,
    }
}

async fn get(router: &Router, key: &str, uri: &str) -> Answer {
    get_with(router, Some(key), uri, &[]).await
}

#[track_caller]
fn assert_error(answer: &Answer, status: StatusCode, code: &str) {
    assert_eq!(answer.status, status, "{:?}", answer.body);
    assert_eq!(answer.headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(answer.body, format!("{{\"error\":\"{code}\"}}"));
}

/// The IDs of a page, and its `next`.
fn page(answer: &Answer) -> (Vec<String>, Option<String>) {
    assert_eq!(answer.status, StatusCode::OK, "{:?}", answer.body);
    let json = answer.json();
    let ids = json["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| op["id"].as_str().unwrap().to_owned())
        .collect();
    (ids, json["next"].as_str().map(str::to_owned))
}

/// Unpadded base64url, for comparing the response's digest.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0_u32, |n, (index, byte)| {
            n | u32::from(*byte) << (16 - 8 * index)
        });
        for index in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[((n >> (18 - 6 * index)) & 63) as usize],
            ));
        }
    }
    out
}

const ROUTES_A: [&str; 4] = [
    "/admin/v1/operations",
    "/admin/v1/operations/op_i1",
    "/admin/v1/tenants/ten_a/operations",
    "/admin/v1/tenants/ten_a/operations/op_a1",
];

/// No peer is 401 on every route; a peer that authorizes nothing there is
/// the one 403 (an unknown credential, a disabled binding, another role,
/// an instance `auditor`, another tenant's `trust_admin`, a tenant role on
/// the instance path); the readers read.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_readers_of_each_path() {
    let (db, pool) = seeded().await;
    let router = router(&pool);
    for uri in ROUTES_A {
        let answer = get_with(&router, None, uri, &[]).await;
        assert_error(&answer, StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    let instance_refused = [
        KEY_UNKNOWN,
        KEY_BIND_OFF,
        KEY_AUD_I,
        KEY_AUD_A,
        KEY_TRUST_A,
        KEY_CLIENT_A,
    ];
    for key in instance_refused {
        for uri in &ROUTES_A[..2] {
            assert_error(
                &get(&router, key, uri).await,
                StatusCode::FORBIDDEN,
                "forbidden",
            );
        }
    }
    let tenant_refused = [
        KEY_UNKNOWN,
        KEY_BIND_OFF,
        KEY_AUD_I,
        KEY_TRUST_B,
        KEY_CLIENT_A,
    ];
    for key in tenant_refused {
        for uri in &ROUTES_A[2..] {
            assert_error(
                &get(&router, key, uri).await,
                StatusCode::FORBIDDEN,
                "forbidden",
            );
        }
    }

    // The instance `security_admin` reads both paths.
    assert_eq!(
        page(&get(&router, KEY_SEC, "/admin/v1/operations").await),
        (vec!["op_i1".into(), "op_i2".into()], None)
    );
    assert_eq!(
        page(&get(&router, KEY_SEC, "/admin/v1/tenants/ten_a/operations").await),
        (vec!["op_a1".into(), "op_a2".into()], None)
    );
    assert_eq!(
        page(&get(&router, KEY_SEC, "/admin/v1/tenants/ten_b/operations").await),
        (vec!["op_b1".into()], None)
    );
    for (uri, id) in [
        ("/admin/v1/operations/op_i2", "op_i2"),
        ("/admin/v1/tenants/ten_a/operations/op_a2", "op_a2"),
        ("/admin/v1/tenants/ten_b/operations/op_b1", "op_b1"),
    ] {
        let answer = get(&router, KEY_SEC, uri).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(answer.json()["id"], id);
    }

    // The tenant's auditor reads every operation of its tenant.
    assert_eq!(
        page(&get(&router, KEY_AUD_A, "/admin/v1/tenants/ten_a/operations").await),
        (vec!["op_a1".into(), "op_a2".into()], None)
    );
    for id in ["op_a1", "op_a2", "op_a3", "op_a4"] {
        let uri = format!("/admin/v1/tenants/ten_a/operations/{id}");
        assert_eq!(get(&router, KEY_AUD_A, &uri).await.status, StatusCode::OK);
    }

    // A `trust_admin` reads and lists its own only.
    assert_eq!(
        page(&get(&router, KEY_TRUST_A, "/admin/v1/tenants/ten_a/operations").await),
        (vec!["op_a1".into()], None)
    );
    assert_eq!(
        page(&get(&router, KEY_TRUST_A2, "/admin/v1/tenants/ten_a/operations").await),
        (vec!["op_a2".into()], None)
    );
    for id in ["op_a1", "op_a3", "op_a4"] {
        let uri = format!("/admin/v1/tenants/ten_a/operations/{id}");
        assert_eq!(get(&router, KEY_TRUST_A, &uri).await.status, StatusCode::OK);
    }
    let other = get(
        &router,
        KEY_TRUST_A,
        "/admin/v1/tenants/ten_a/operations/op_a2",
    )
    .await;
    assert_error(&other, StatusCode::NOT_FOUND, "not_found");
    assert_eq!(
        page(&get(&router, KEY_TRUST_B, "/admin/v1/tenants/ten_b/operations").await),
        (vec!["op_b1".into()], None)
    );
    db.drop([pool]).await;
}

/// A missing operation and every operation outside the caller's view give
/// the same response, byte for byte: another tenant's, the other scope's,
/// a kind of another scope, a row that is not of the flow (an `approve`),
/// another requester's, and an ID no row can hold. A caller refused on a
/// path is refused alike whether the operation exists or not.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn no_existence_oracle() {
    let (db, pool) = seeded().await;
    let router = router(&pool);
    let readers = [
        (KEY_SEC, "ten_a"),
        (KEY_AUD_A, "ten_a"),
        (KEY_TRUST_A, "ten_a"),
        (KEY_TRUST_B, "ten_b"),
    ];
    for (key, tenant) in readers {
        let missing = get(
            &router,
            key,
            &format!("/admin/v1/tenants/{tenant}/operations/op_none"),
        )
        .await;
        assert_error(&missing, StatusCode::NOT_FOUND, "not_found");
        let mut hidden = vec!["op_i1", "op_ix", "op_a5", "op_none%00", "op_a1%00", "%00"];
        hidden.push(if tenant == "ten_a" { "op_b1" } else { "op_a1" });
        if key == KEY_TRUST_A {
            hidden.push("op_a2");
        }
        if key == KEY_TRUST_B {
            hidden.extend(["op_a2", "op_a3"]);
        }
        for id in hidden {
            let uri = format!("/admin/v1/tenants/{tenant}/operations/{id}");
            let answer = get(&router, key, &uri).await;
            assert_eq!(answer.seen(), missing.seen(), "{key} {uri}");
            assert_eq!(answer.headers, missing.headers, "{key} {uri}");
        }
    }
    let missing = get(&router, KEY_SEC, "/admin/v1/operations/op_none").await;
    assert_error(&missing, StatusCode::NOT_FOUND, "not_found");
    for id in ["op_a1", "op_b1", "op_a5", "op_ix", "op_none%00"] {
        let answer = get(&router, KEY_SEC, &format!("/admin/v1/operations/{id}")).await;
        assert_eq!(answer.seen(), missing.seen(), "{id}");
    }
    // An instance row of a tenant kind is listed nowhere.
    let (ids, _) = page(&get(&router, KEY_SEC, "/admin/v1/operations").await);
    assert!(!ids.contains(&"op_ix".to_owned()));

    // Refused callers: the same 403 for an existing, a missing and a
    // foreign operation, and for an unknown tenant.
    for key in [KEY_TRUST_B, KEY_UNKNOWN, KEY_AUD_I] {
        let refused = get(&router, key, "/admin/v1/tenants/ten_a/operations/op_none").await;
        assert_error(&refused, StatusCode::FORBIDDEN, "forbidden");
        for uri in [
            "/admin/v1/tenants/ten_a/operations/op_a1",
            "/admin/v1/tenants/ten_a/operations/op_b1",
            "/admin/v1/tenants/ten_none/operations/op_a1",
            "/admin/v1/tenants/ten%00/operations/op_a1",
            "/admin/v1/tenants/ten_a/operations",
        ] {
            assert_eq!(
                get(&router, key, uri).await.seen(),
                refused.seen(),
                "{key} {uri}"
            );
        }
    }
    // The security admin lists an unknown tenant as empty, like a tenant
    // with no operation.
    assert_eq!(
        page(&get(&router, KEY_SEC, "/admin/v1/tenants/ten_none/operations").await),
        (Vec::new(), None)
    );
    db.drop([pool]).await;
}

/// The response is the whole digest envelope with the plan verbatim as
/// its canonical text, so the digest recomputes from the response alone,
/// an integer above 2^53 included; an expired and a consumed operation are
/// read with their state.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_plan_is_returned_verbatim() {
    let (db, pool) = seeded().await;
    let router = router(&pool);
    let answer = get(
        &router,
        KEY_AUD_A,
        "/admin/v1/tenants/ten_a/operations/op_a1",
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.headers[header::CONTENT_TYPE], "application/json");
    let json = answer.json();
    let members: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        members,
        [
            "actor_id",
            "expected_revision",
            "expires_at",
            "id",
            "kind",
            "outcome",
            "plan",
            "request_digest",
            "revision",
            "tenant_id",
        ]
    );
    assert_eq!(json["id"], "op_a1");
    assert_eq!(json["tenant_id"], "ten_a");
    assert_eq!(json["actor_id"], "adm_trust_a");
    assert_eq!(json["kind"], "trust_source_create");
    assert_eq!(json["expected_revision"], 3);
    assert_eq!(json["expires_at"].as_i64(), Some(micros(DAY)));
    assert_eq!(json["outcome"], "pending");
    assert_eq!(json["revision"], 1);
    assert_eq!(json["plan"], PLAN_A1_TEXT);
    // The integer travels as text inside the string, never as a JSON
    // number a client might round.
    let raw = String::from_utf8(answer.body.to_vec()).unwrap();
    assert!(raw.contains("9007199254740993"), "{raw}");

    let plan: JsonObject = serde_json::from_str(json["plan"].as_str().unwrap()).unwrap();
    let envelope = DigestEnvelope {
        id: json["id"].as_str().unwrap(),
        tenant_id: json["tenant_id"].as_str(),
        actor_id: json["actor_id"].as_str().unwrap(),
        kind: json["kind"].as_str().unwrap(),
        expected_revision: json["expected_revision"].as_i64().unwrap(),
        expires_at_us: json["expires_at"].as_i64().unwrap(),
        plan: &plan,
    };
    let recomputed = envelope.digest().unwrap();
    assert_eq!(json["request_digest"], base64url(recomputed.as_bytes()));
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT request_digest FROM administrative_operation WHERE id = 'op_a1'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, recomputed.as_bytes());
    assert_eq!(base64url(&stored).len(), 43);

    let instance = get(&router, KEY_SEC, "/admin/v1/operations/op_i1")
        .await
        .json();
    assert_eq!(instance["tenant_id"], Value::Null);
    assert_eq!(
        instance["plan"],
        "{\"requester_credential_id\":\"crd_adm_sec\",\"widening_second_approver\":true}"
    );

    let expired = get(
        &router,
        KEY_TRUST_A,
        "/admin/v1/tenants/ten_a/operations/op_a3",
    )
    .await;
    assert_eq!(expired.json()["outcome"], "pending");
    assert_eq!(
        expired.json()["expires_at"].as_i64(),
        Some(micros(1_800_000_000))
    );
    let consumed = get(
        &router,
        KEY_TRUST_A,
        "/admin/v1/tenants/ten_a/operations/op_a4",
    )
    .await;
    assert_eq!(consumed.json()["outcome"], "applied");
    assert_eq!(consumed.json()["revision"], 2);
    db.drop([pool]).await;
}

/// Pages: chained by `next` through every open operation in ID order;
/// `next` is set exactly on a full page; `limit` is clamped to
/// `1..=500`; a cursor past the end is an empty page.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn lists_come_in_bounded_pages() {
    let (db, pool) = seeded().await;
    // 501 more open instance toggles, inserted in one transaction.
    let mut transaction = pool.begin().await.unwrap();
    let mut expected = vec!["op_i1".to_owned(), "op_i2".to_owned()];
    for index in 0..501 {
        let id = format!("op_p{index:03}");
        let new = operation(
            &id,
            None,
            "adm_sec",
            "instance_security_policy_update",
            DAY,
            object(
                json!({"requester_credential_id": "crd_adm_sec", "widening_second_approver": true}),
            ),
            None,
        );
        append_audit_event(
            &mut transaction,
            &NewAuditEvent {
                id: new.audit_id.clone(),
                tenant_id: None,
                timestamp: at(0),
                actor: AuditActor::Operator("adm_sec".into()),
                action: "administrative_operation.create".into(),
                object_id: id.clone(),
                previous_revision: None,
                new_revision: Some(1),
                outcome: "success".into(),
            },
        )
        .await
        .unwrap();
        insert_administrative_operation(&mut transaction, &new)
            .await
            .unwrap();
        expected.push(id);
    }
    transaction.commit().await.unwrap();
    expected.sort();
    let router = router(&pool);

    // Unbounded asks are clamped to 500.
    for uri in [
        "/admin/v1/operations",
        "/admin/v1/operations?limit=500",
        "/admin/v1/operations?limit=501",
        "/admin/v1/operations?limit=4294967295",
    ] {
        let (ids, next) = page(&get(&router, KEY_SEC, uri).await);
        let limit = if uri == "/admin/v1/operations" {
            100
        } else {
            500
        };
        assert_eq!(ids, expected[..limit], "{uri}");
        assert_eq!(next.as_deref(), Some(expected[limit - 1].as_str()), "{uri}");
    }
    // `limit=0` is clamped to 1.
    let (ids, next) = page(&get(&router, KEY_SEC, "/admin/v1/operations?limit=0").await);
    assert_eq!(ids, expected[..1]);
    assert_eq!(next.as_deref(), Some(expected[0].as_str()));

    // Chained pages of 200: 200, 200, 103, and the last one has no next.
    let mut seen = Vec::new();
    let mut uri = "/admin/v1/operations?limit=200".to_owned();
    let mut pages = 0;
    loop {
        let (ids, next) = page(&get(&router, KEY_SEC, &uri).await);
        pages += 1;
        seen.extend(ids);
        let Some(next) = next else { break };
        uri = format!("/admin/v1/operations?after={next}&limit=200");
    }
    assert_eq!(pages, 3);
    assert_eq!(seen, expected);

    // A page that ends exactly at the end: `next` is set, and the page
    // after it is empty with no `next`.
    let (ids, next) = page(
        &get(
            &router,
            KEY_SEC,
            "/admin/v1/tenants/ten_a/operations?limit=2",
        )
        .await,
    );
    assert_eq!(ids, ["op_a1", "op_a2"]);
    assert_eq!(next.as_deref(), Some("op_a2"));
    let (ids, next) = page(
        &get(
            &router,
            KEY_SEC,
            "/admin/v1/tenants/ten_a/operations?after=op_a2&limit=2",
        )
        .await,
    );
    assert!(ids.is_empty());
    assert_eq!(next, None);
    let (ids, next) = page(
        &get(
            &router,
            KEY_SEC,
            "/admin/v1/tenants/ten_a/operations?after=op_a1",
        )
        .await,
    );
    assert_eq!((ids, next), (vec!["op_a2".to_owned()], None));
    let (ids, _) = page(&get(&router, KEY_SEC, "/admin/v1/operations?after=zzz").await);
    assert!(ids.is_empty());
    // A cursor is a byte-wise bound, not an ID that must exist.
    let (ids, _) = page(
        &get(
            &router,
            KEY_SEC,
            "/admin/v1/tenants/ten_a/operations?after=op_a10",
        )
        .await,
    );
    assert_eq!(ids, ["op_a2"]);
    // A requester's pages hold its own operations only.
    let (ids, next) = page(
        &get(
            &router,
            KEY_TRUST_A,
            "/admin/v1/tenants/ten_a/operations?limit=1",
        )
        .await,
    );
    assert_eq!(
        (ids, next.as_deref()),
        (vec!["op_a1".to_owned()], Some("op_a1"))
    );
    let (ids, next) = page(
        &get(
            &router,
            KEY_TRUST_A,
            "/admin/v1/tenants/ten_a/operations?limit=1&after=op_a1",
        )
        .await,
    );
    assert!(ids.is_empty());
    assert_eq!(next, None);
    db.drop([pool]).await;
}

/// The error bodies reachable through these routes, end to end: 400 for a
/// malformed query, 500 for a broken row in the caller's view (and 404 for
/// the same row outside it), 503 for an unavailable store; never a value of
/// the request.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_error_table_end_to_end() {
    let (db, pool) = seeded().await;
    // A row of the flow with a 33-byte digest: no envelope to return.
    insert(
        &pool,
        &operation(
            "op_a9",
            Some("ten_a"),
            "adm_trust_a2",
            "trust_source_create",
            DAY,
            plan_of("crd_adm_trust_a2"),
            Some(vec![1; 33]),
        ),
    )
    .await;
    let router = router(&pool);
    for uri in [
        "/admin/v1/operations?limit=ten",
        "/admin/v1/operations?after=a&after=b",
        "/admin/v1/operations?after=op%00",
        "/admin/v1/tenants/ten_a/operations?tenant=ten_b",
        "/admin/v1/tenants/ten_a/operations?limit=",
        "/admin/v1/operations/%C3%28",
    ] {
        assert_error(
            &get(&router, KEY_SEC, uri).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
    }
    let broken = get(
        &router,
        KEY_AUD_A,
        "/admin/v1/tenants/ten_a/operations/op_a9",
    )
    .await;
    assert_error(&broken, StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    let list = get(&router, KEY_AUD_A, "/admin/v1/tenants/ten_a/operations").await;
    assert_error(&list, StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    // Outside its requester's view the broken row is just not found.
    let hidden = get(
        &router,
        KEY_TRUST_A,
        "/admin/v1/tenants/ten_a/operations/op_a9",
    )
    .await;
    let missing = get(
        &router,
        KEY_TRUST_A,
        "/admin/v1/tenants/ten_a/operations/op_none",
    )
    .await;
    assert_eq!(hidden.seen(), missing.seen());
    let (ids, _) = page(&get(&router, KEY_TRUST_A, "/admin/v1/tenants/ten_a/operations").await);
    assert_eq!(ids, ["op_a1"]);

    // An unavailable store: 503 `auth_unavailable`, no Retry-After.
    let closed = pool.clone();
    closed.close().await;
    for uri in ROUTES_A {
        let answer = get(&router, KEY_SEC, uri).await;
        assert_error(&answer, StatusCode::SERVICE_UNAVAILABLE, "auth_unavailable");
        assert!(answer.headers.get(header::RETRY_AFTER).is_none());
    }
    // Without a peer the closed store is never reached: still 401.
    let answer = get_with(&router, None, ROUTES_A[3], &[]).await;
    assert_error(&answer, StatusCode::UNAUTHORIZED, "unauthenticated");
    db.drop(Vec::new()).await;
}

/// No header stands in for the peer identity: without the extension a
/// request naming an authorized key in any header is 401, and with it the
/// extension's identity is the one used, whatever the headers name.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn spoofed_headers_are_ignored() {
    let (db, pool) = seeded().await;
    let router = router(&pool);
    let spoofed: Vec<(&str, &str)> = [
        "x-client-cert",
        "x-ssl-client-cert",
        "x-forwarded-client-cert",
        "x-client-verify",
        "x-admin-peer",
        "x-spki-sha256",
        "ssl-client-cert",
        "authorization",
        "forwarded",
    ]
    .into_iter()
    .map(|name| (name, KEY_SEC))
    .collect();
    for uri in ROUTES_A {
        let answer = get_with(&router, None, uri, &spoofed).await;
        assert_error(&answer, StatusCode::UNAUTHORIZED, "unauthenticated");
        let answer = get_with(&router, Some(KEY_UNKNOWN), uri, &spoofed).await;
        assert_error(&answer, StatusCode::FORBIDDEN, "forbidden");
        let answer = get_with(
            &router,
            Some(KEY_SEC),
            uri,
            &[("x-client-cert", KEY_UNKNOWN)],
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{uri}");
    }
    // A query parameter is no identity either.
    let answer = get_with(
        &router,
        None,
        "/admin/v1/operations?peer=spki-sha256:sec",
        &[],
    )
    .await;
    assert_error(&answer, StatusCode::UNAUTHORIZED, "unauthenticated");
    db.drop([pool]).await;
}

/// The registry read keys a row by its tenant itself, not only through the
/// read path's scope check behind it: an operation asked for under another
/// tenant, under the instance or under a tenant when it is an instance one
/// is `NotFound`, called directly, with no `record()` in between.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_registry_read_is_keyed_by_the_tenant() {
    let (db, pool) = seeded().await;
    let get = |tenant_id, id| registry::get_administrative_operation(&pool, tenant_id, id);
    for (tenant_id, id) in [
        (Some("ten_a"), "op_a1"),
        (Some("ten_b"), "op_b1"),
        (None, "op_i1"),
    ] {
        let row = get(tenant_id, id).await.unwrap();
        assert_eq!((row.tenant_id.as_deref(), row.id.as_str()), (tenant_id, id));
    }
    for (tenant_id, id) in [
        (Some("ten_b"), "op_a1"),
        (None, "op_a1"),
        (Some("ten_a"), "op_i1"),
        (Some("ten_a"), "op_b1"),
        (Some("ten_none"), "op_a1"),
        (Some("ten_a"), "op_none"),
    ] {
        assert!(
            matches!(get(tenant_id, id).await, Err(RegistryError::NotFound)),
            "{tenant_id:?} {id}"
        );
    }
    db.drop([pool]).await;
}
