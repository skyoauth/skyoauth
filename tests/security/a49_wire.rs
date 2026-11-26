//! A49, the wire half of the cross-tenant probe: the admin read router of
//! slice S4 (`skyoauth_service::admin_http::admin_router`) answers a
//! probe of another tenant's operations exactly as it answers a probe of
//! something that does not exist (tasks §8; T10.2; identity-registry
//! IR-020 to IR-024; D4 of tasks §13).
//!
//! **A49 partial: these tests are no claim, and A49's M1a stage stays
//! `planned`, with no stamp.** They are registered on that planned stage,
//! beside the generated-ID tests of [`super::a49`], so they are no evidence
//! for it: the reporter lists their results as not counted. The stage's
//! export and reapply half (T10.5, T14.8) is not built and stays open, and
//! no write route exists yet (`admin_http`, "Served nowhere"), so only the
//! four operation reads are probed here.
//!
//! **What they prove, and what they do not.** They drive the router with
//! `tower::ServiceExt::oneshot` through
//! `admin_http::test_support::with_admin_peer`, the tests' fake acceptor,
//! which hands the router an *already-verified* peer identity, taken as
//! given. So they prove tenant isolation of the read endpoints by the
//! registry's authorization and the reads' scoping
//! (`operation::read_operation`, `operation::list_operations`), not the
//! mTLS leg: no TLS handshake runs and no certificate chain is verified
//! (slices S5 to S7; the router is served nowhere until S6). The keys are
//! canonical identities (`spki-sha256:<hex>`) that [`key`] computes from
//! real Ed25519 `SubjectPublicKeyInfo`s with the service's own
//! `identity::canonical_public_identity`.
//!
//! **The read rules these tests follow** (module docs of
//! `operation::read` and `admin_http`): an instance `security_admin` reads
//! every operation of a path, a tenant's `auditor` every operation of its
//! tenant's path, and a tenant's `trust_admin` only the operations it
//! requested there. A usable credential without a reading binding for the
//! path is 403 `forbidden`, decided before any operation is read. On a
//! path the caller may read, an operation of another tenant, of the other
//! scope, of a kind outside the flow (an `approve` row), another
//! `trust_admin`'s for a `trust_admin`, and a missing one are the one 404
//! `not_found`. A list shows the open operations of the path only; its
//! cursor `after` is the last ID of the previous page, a plain ID bound to
//! no tenant.
//!
//! **The wire values come from the catalogue.** The status,
//! `Content-Type`, `Cache-Control`, the absence of `Retry-After` and the
//! body bytes of every 403 and 404 are read from
//! `tests/conformance/fixtures/_wire/errors.v1.json` ([`WireError`]), never
//! typed here; the body is also parsed and must hold the shape's members
//! and no other. "The same answer" below means the same status, the same
//! header map and the same body bytes ([`Answer`]'s equality).
//!
//! **The fixture** ([`fixture`]), one fresh database per test: an instance
//! bootstrapped through `registry::bootstrap_instance`, whose first
//! operator `adm_first` is the instance `security_admin`; tenants `ten_a`
//! and `ten_b`; operators written with `registry::test_support`: two
//! `trust_admin`s and an `auditor` of `ten_a`, a `trust_admin` and an
//! `auditor` of `ten_b`; and the operations of [`OPS`], each written with
//! the bare operation-row writer after its `administrative_operation.create`
//! event. Each tenant's plans carry a marker of their tenant, so a body that
//! leaked another tenant's plan would show it.
//!
//! - **Positive** (`a49_pos_each_reader_reads_its_own_tenants_operations`):
//!   every reader reads, single and listed, exactly the operations the
//!   rules give it, with the operation's own ID, tenant, requester, kind and
//!   plan; the instance `security_admin` reads both tenants'.
//! - **Another tenant's path is the 403 of a tenant that does not exist**
//!   (`a49_neg_other_tenants_path_is_the_403_of_a_tenant_that_does_not_exist`):
//!   each of `ten_a`'s readers on `ten_b`'s path (the list, with and
//!   without a query, the single read of `ten_b`'s real operations, of its
//!   own and of a missing one), and on tenant IDs that do not exist (an
//!   unknown one, case variants, padded and near-miss forms of both tenants'
//!   IDs) gets the same 403; `ten_b`'s readers likewise on `ten_a`'s path.
//!   The controls: each reads its own path, and the instance
//!   `security_admin` reads the other tenant's.
//! - **Another tenant's operation on the caller's own path is the 404 of a
//!   missing one**
//!   (`a49_neg_other_tenants_operation_on_own_path_is_the_404_of_a_missing_one`):
//!   on its own tenant's path, each reader (the instance `security_admin`
//!   included) asking for the other tenant's operations, the instance's, an
//!   instance row of a tenant kind, an `approve` row, and case and padded
//!   variants of the other tenant's and its own IDs gets the 404 of a
//!   missing ID; the instance path likewise for tenant operations. The
//!   controls: the same reader reads its own operation on that path, and
//!   the other tenant's readers read theirs on theirs.
//! - **Another `trust_admin`'s operation is the 404 of a missing one**
//!   (`a49_neg_another_trust_admins_operation_is_the_404_of_a_missing_one`):
//!   of `ten_a`'s two `trust_admin`s, neither reads nor lists the other's
//!   operation; `ten_a`'s `auditor` and the instance `security_admin` read
//!   both, the control.
//! - **A list shows nothing of the other tenant**
//!   (`a49_neg_own_list_shows_nothing_of_the_other_tenant`): the lists of
//!   each tenant's readers, whole and paged one by one, hold only their own
//!   tenant's operations, and their bytes hold no ID, tenant ID, requester,
//!   credential or plan marker of the other tenant. The other tenant's
//!   cursor is accepted, as any string is (it is an ID, not a token): the
//!   page after it is the page after a missing ID at the same place, so it
//!   tells nothing of the other tenant.
//!
//! # Not covered here
//!
//! - The mTLS leg (handshake, chain against `trust_anchor_ref`, key
//!   canonicalization by the server): S6 for the handshake and the chain, S7
//!   for the canonicalization, S5 for enrolment and credential state (the
//!   lead's split; tasks §13 does not say).
//! - Writes: the router exposes none, so no cross-tenant write probe goes
//!   over the wire; the typed write probe is [`super::a49`]'s
//!   (`a49_neg_other_tenants_principal_id_is_not_found_as_a_missing_one`).
//! - Export and reapply (T10.5, T14.8): not built.
//! - The exchange rejecting names instead of generated IDs: A49's M2
//!   stage (T21.1).
//! - Timing: the same bytes do not show the same latency; no test measures
//!   it.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    admin_http::{AdminState, admin_router, test_support::with_admin_peer},
    identity::canonical_public_identity,
    operation::{Clock, DigestEnvelope},
    persistence::{
        PgPool,
        registry::{
            self, AdminRole, AuditActor, BootstrapRequest, JsonObject, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, NewAdministrativeOperation, NewAuditEvent,
            NewTenant, Status, bootstrap_instance,
        },
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
struct WireError {
    code: &'static str,
    status: StatusCode,
    content_type: String,
    cache_control: String,
    /// The body: `body.shape` with its `<code>` placeholder filled in.
    body: Bytes,
    /// The body's members: the shape's, and no other
    /// (`additional_members` is `false`).
    members: BTreeSet<String>,
}

/// The catalogue's entry for `code`. Panics for a code the catalogue does
/// not list, or one that may carry `Retry-After` (the checks here assert
/// its absence, which the catalogue promises only for `never`).
fn wire_error(code: &'static str) -> WireError {
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
fn assert_wire_error(answer: &Answer, expected: &WireError, what: &str) {
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
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Answer {
    fn header(&self, name: header::HeaderName) -> Option<String> {
        self.headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// The URI of a tenant's list, with `query` (empty for none).
fn list_uri(tenant: &str, query: &str) -> String {
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    format!("/admin/v1/tenants/{tenant}/operations{query}")
}

/// The URI of one operation on a tenant's path.
fn op_uri(tenant: &str, operation: &str) -> String {
    format!("/admin/v1/tenants/{tenant}/operations/{operation}")
}

/// The URI of one operation on the instance path.
fn instance_op_uri(operation: &str) -> String {
    format!("/admin/v1/operations/{operation}")
}

// ---------------------------------------------------------------------------
// The fixture

const T0: u64 = 1_790_000_000;
const HOUR: u64 = 3_600;
const DAY: u64 = 86_400;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(T0 + seconds)
}

/// The server's clock for a list's "open at now": an hour after bootstrap,
/// before every seeded operation expires.
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        at(HOUR)
    }
}

/// The canonical public identity of the Ed25519 key with secret `seed`
/// repeated: `identity::canonical_public_identity` of its DER
/// `SubjectPublicKeyInfo` (RFC 8410), the form the acceptor will compute.
fn key(seed: u8) -> String {
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

/// `adm_first`, the bootstrapped instance `security_admin`.
const SEC: u8 = 0x41;
/// `adm_trust_a`: `ten_a`'s `trust_admin`, requester of `op_a1`, `op_c1`.
const TRUST_A: u8 = 0x42;
/// `adm_second_a`: `ten_a`'s other `trust_admin`, requester of `op_a2`.
const SECOND_A: u8 = 0x43;
/// `adm_aud_a`: `ten_a`'s `auditor`.
const AUD_A: u8 = 0x44;
/// `adm_trust_b`: `ten_b`'s `trust_admin`, requester of `op_b1`, `op_b2`.
const TRUST_B: u8 = 0x45;
/// `adm_aud_b`: `ten_b`'s `auditor`.
const AUD_B: u8 = 0x46;

/// One seeded operation.
struct Op {
    id: &'static str,
    tenant: Option<&'static str>,
    actor: &'static str,
    kind: &'static str,
}

/// The seeded operations, every one pending and expiring a day after
/// bootstrap, but `op_a9`:
///
/// - `op_i1`: an instance toggle by `adm_first`;
/// - `op_ix`: an instance row of a tenant kind, `trust_source_create` (a
///   kind of the other scope, which no path shows);
/// - `op_a1`, `op_c1`: `ten_a`'s, by `adm_trust_a`; `op_c1` is named to
///   sort after `ten_b`'s IDs, so a cursor of `ten_b`'s falls inside
///   `ten_a`'s list;
/// - `op_a2`: `ten_a`'s, by `adm_second_a`;
/// - `op_a9`: an `approve` of `op_a1` in `ten_a`, by `adm_first`, consumed
///   with no expiry (a kind outside the flow, which no path shows);
/// - `op_b1`, `op_b2`: `ten_b`'s, by `adm_trust_b`.
const OPS: [Op; 8] = [
    Op {
        id: "op_i1",
        tenant: None,
        actor: "adm_first",
        kind: "instance_security_policy_update",
    },
    Op {
        id: "op_ix",
        tenant: None,
        actor: "adm_first",
        kind: "trust_source_create",
    },
    Op {
        id: "op_a1",
        tenant: Some("ten_a"),
        actor: "adm_trust_a",
        kind: "trust_source_create",
    },
    Op {
        id: "op_a2",
        tenant: Some("ten_a"),
        actor: "adm_second_a",
        kind: "trust_keyset_version_create",
    },
    Op {
        id: "op_c1",
        tenant: Some("ten_a"),
        actor: "adm_trust_a",
        kind: "trust_source_update",
    },
    Op {
        id: "op_a9",
        tenant: Some("ten_a"),
        actor: "adm_first",
        kind: "approve",
    },
    Op {
        id: "op_b1",
        tenant: Some("ten_b"),
        actor: "adm_trust_b",
        kind: "trust_source_create",
    },
    Op {
        id: "op_b2",
        tenant: Some("ten_b"),
        actor: "adm_trust_b",
        kind: "trust_keyset_version_create",
    },
];

fn op(id: &str) -> &'static Op {
    OPS.iter()
        .find(|op| op.id == id)
        .unwrap_or_else(|| panic!("no operation {id}"))
}

/// The marker in the plan of every operation of `tenant` (`None`: the
/// instance).
fn plan_marker(tenant: Option<&str>) -> String {
    match tenant {
        Some(tenant) => format!("plan-of-{tenant}-only"),
        None => "plan-of-the-instance-only".to_owned(),
    }
}

/// The plan of `op`: its requester's credential and its tenant's marker.
fn plan(op: &Op) -> JsonObject {
    let Value::Object(plan) = json!({
        "requester_credential_id": op.actor.replace("adm_", "crd_"),
        "note": plan_marker(op.tenant),
    }) else {
        unreachable!()
    };
    plan
}

/// What of `tenant` may not show to anyone outside it: its ID, its name
/// and namespace, its flow operations' IDs, its readers' operator and
/// credential IDs, and its plans' marker. None is a substring of the other tenant's.
fn traces_of(tenant: &str) -> Vec<String> {
    let mut traces = vec![
        tenant.to_owned(),
        format!("Tenant {tenant}"),
        tenant.replace("ten_", "ns_"),
        plan_marker(Some(tenant)),
    ];
    for op in OPS
        .iter()
        .filter(|op| op.tenant == Some(tenant) && op.kind != "approve")
    {
        traces.push(op.id.to_owned());
        traces.push(op.actor.to_owned());
        traces.push(op.actor.replace("adm_", "crd_"));
    }
    match tenant {
        "ten_a" => traces.extend(["adm_aud_a".into(), "crd_aud_a".into()]),
        "ten_b" => traces.extend(["adm_aud_b".into(), "crd_aud_b".into()]),
        other => panic!("no tenant {other}"),
    }
    traces
}

/// `answer`'s bytes hold no trace of `tenant` ([`traces_of`]).
#[track_caller]
fn assert_no_trace_of(answer: &Answer, tenant: &str, what: &str) {
    let body = String::from_utf8(answer.body.to_vec()).unwrap();
    for trace in traces_of(tenant) {
        assert!(
            !body.contains(&trace),
            "{what}: the body shows {trace:?} of {tenant}: {body}"
        );
    }
    for value in answer.headers.values() {
        let value = value.to_str().unwrap();
        for trace in traces_of(tenant) {
            assert!(!value.contains(&trace), "{what}: a header shows {trace:?}");
        }
    }
}

/// One test's database and router.
struct Fixture {
    db: TestDb,
    pool: PgPool,
    router: Router,
    /// The catalogue's `Cache-Control`, for the 200s.
    cache_control: String,
}

impl Fixture {
    /// `GET uri` with the verified peer of `seed`.
    async fn get(&self, seed: u8, uri: &str) -> Answer {
        let request = Request::get(uri).body(Body::empty()).unwrap();
        let request = with_admin_peer(request, &key(seed));
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        Answer {
            status,
            headers,
            body,
        }
    }

    /// `answer` is a 200 JSON body with the catalogue's `Cache-Control`.
    #[track_caller]
    fn assert_ok(&self, answer: &Answer, what: &str) -> Value {
        assert_eq!(answer.status, StatusCode::OK, "{what}: {:?}", answer.body);
        assert_eq!(
            answer.header(header::CONTENT_TYPE).as_deref(),
            Some("application/json"),
            "{what}"
        );
        assert_eq!(
            answer.header(header::CACHE_CONTROL).as_deref(),
            Some(self.cache_control.as_str()),
            "{what}"
        );
        answer.json()
    }

    /// The reader `seed` reads the operation `id` at `uri`: 200, the
    /// operation's own ID, tenant, requester, kind and plan.
    async fn assert_reads(&self, seed: u8, uri: &str, id: &str, what: &str) -> Answer {
        let answer = self.get(seed, uri).await;
        let json = self.assert_ok(&answer, &format!("{what}: GET {uri}"));
        assert_operation(&json, id, &format!("{what}: GET {uri}"));
        answer
    }

    /// The reader `seed` lists `uri`: 200, exactly the operations `ids`,
    /// in that order, and the cursor `next`.
    async fn assert_lists(
        &self,
        seed: u8,
        uri: &str,
        ids: &[&str],
        next: Option<&str>,
        what: &str,
    ) -> Answer {
        let answer = self.get(seed, uri).await;
        let what = format!("{what}: GET {uri}");
        let json = self.assert_ok(&answer, &what);
        let operations = json["operations"].as_array().expect("operations");
        let listed: Vec<&str> = operations
            .iter()
            .map(|operation| operation["id"].as_str().unwrap())
            .collect();
        assert_eq!(listed, ids, "{what}");
        for operation in operations {
            assert_operation(operation, operation["id"].as_str().unwrap(), &what);
        }
        assert_eq!(json["next"], json!(next), "{what}: next");
        answer
    }

    async fn drop(self) {
        self.db.drop([self.pool]).await;
    }
}

/// `json` is the seeded operation `id`, with its own tenant, requester,
/// kind and plan.
#[track_caller]
fn assert_operation(json: &Value, id: &str, what: &str) {
    let op = op(id);
    assert_eq!(json["id"], op.id, "{what}");
    assert_eq!(json["tenant_id"], json!(op.tenant), "{what}");
    assert_eq!(json["actor_id"], op.actor, "{what}");
    assert_eq!(json["kind"], op.kind, "{what}");
    assert_eq!(json["outcome"], "pending", "{what}");
    let shown: Value = serde_json::from_str(json["plan"].as_str().unwrap()).unwrap();
    assert_eq!(shown, Value::Object(plan(op)), "{what}: plan");
}

/// One operator `adm_<name>`: an enabled identity, the enabled credential
/// `crd_<name>` of `key(seed)`, and an enabled binding `rb_<name>` of
/// `role` in `tenant`.
async fn operator(pool: &PgPool, name: &str, seed: u8, role: AdminRole, tenant: &str) {
    let admin_id = format!("adm_{name}");
    registry::test_support::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: admin_id.clone(),
            status: Status::Enabled,
            created_at: at(0),
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_credential(
        pool,
        &NewAdminCredential {
            id: format!("crd_{name}"),
            admin_id: admin_id.clone(),
            public_identity: key(seed),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::test_support::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: format!("rb_{name}"),
            admin_id,
            role,
            tenant_id: Some(tenant.into()),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// Writes `op`, after its `administrative_operation.create` event, in one
/// transaction: pending until a day after bootstrap, or, for an `approve`,
/// an approval of `op_a1` with no expiry and a placeholder digest.
async fn seed_operation(pool: &PgPool, op: &Op) {
    let plan = plan(op);
    let approve = op.kind == "approve";
    let expires_at_us = i64::try_from((T0 + DAY) * 1_000_000).unwrap();
    let request_digest = if approve {
        vec![7; 32]
    } else {
        DigestEnvelope {
            id: op.id,
            tenant_id: op.tenant,
            actor_id: op.actor,
            kind: op.kind,
            expected_revision: 1,
            expires_at_us,
            plan: &plan,
        }
        .digest()
        .unwrap()
        .as_bytes()
        .to_vec()
    };
    let mut transaction = pool.begin().await.unwrap();
    registry::test_support::append_audit_event(
        &mut transaction,
        &NewAuditEvent {
            id: format!("evt_{}", op.id),
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
            immutable_plan: plan,
            expires_at: (!approve).then(|| at(DAY)),
            approves_operation_id: approve.then(|| "op_a1".into()),
            outcome: if approve { "success" } else { "pending" }.into(),
            audit_id: format!("evt_{}", op.id),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}

/// The instance bootstrapped with `adm_first` ([`SEC`]); tenants `ten_a`
/// and `ten_b`; the tenant operators of the seed constants; and [`OPS`].
async fn fixture() -> Fixture {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: "019a9f3c-5b2e-7c41-9d8e-0000000a49e1",
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: &key(SEC),
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &SigningKey::from_bytes(&[0x49; 32])
                .verifying_key()
                .to_bytes(),
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    for tenant in ["ten_a", "ten_b"] {
        registry::test_support::create_tenant(
            &pool,
            &NewTenant {
                id: tenant.into(),
                name: format!("Tenant {tenant}"),
                secret_namespace: tenant.replace("ten_", "ns_"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    let trust = AdminRole::TrustAdmin;
    let auditor = AdminRole::Auditor;
    for (name, seed, role, tenant) in [
        ("trust_a", TRUST_A, trust, "ten_a"),
        ("second_a", SECOND_A, trust, "ten_a"),
        ("aud_a", AUD_A, auditor, "ten_a"),
        ("trust_b", TRUST_B, trust, "ten_b"),
        ("aud_b", AUD_B, auditor, "ten_b"),
    ] {
        operator(&pool, name, seed, role, tenant).await;
    }
    for op in &OPS {
        seed_operation(&pool, op).await;
    }
    let router = admin_router(AdminState::new(pool.clone(), Arc::new(FixedClock)));
    let cache_control = wire_error("not_found").cache_control;
    Fixture {
        db,
        pool,
        router,
        cache_control,
    }
}

/// A tenant reader: who, its key's seed, its tenant, the other tenant, and
/// the open operations of its tenant it reads, by ID byte-wise.
struct Reader {
    who: &'static str,
    seed: u8,
    tenant: &'static str,
    other: &'static str,
    reads: &'static [&'static str],
}

/// Every tenant reader of the fixture.
const READERS: [Reader; 5] = [
    Reader {
        who: "ten_a's trust_admin",
        seed: TRUST_A,
        tenant: "ten_a",
        other: "ten_b",
        reads: &["op_a1", "op_c1"],
    },
    Reader {
        who: "ten_a's second trust_admin",
        seed: SECOND_A,
        tenant: "ten_a",
        other: "ten_b",
        reads: &["op_a2"],
    },
    Reader {
        who: "ten_a's auditor",
        seed: AUD_A,
        tenant: "ten_a",
        other: "ten_b",
        reads: &["op_a1", "op_a2", "op_c1"],
    },
    Reader {
        who: "ten_b's trust_admin",
        seed: TRUST_B,
        tenant: "ten_b",
        other: "ten_a",
        reads: &["op_b1", "op_b2"],
    },
    Reader {
        who: "ten_b's auditor",
        seed: AUD_B,
        tenant: "ten_b",
        other: "ten_a",
        reads: &["op_b1", "op_b2"],
    },
];

/// The open operations of `tenant`'s path that a reader of every
/// operation there reads, by ID byte-wise.
fn all_of(tenant: &str) -> &'static [&'static str] {
    match tenant {
        "ten_a" => &["op_a1", "op_a2", "op_c1"],
        "ten_b" => &["op_b1", "op_b2"],
        other => panic!("no tenant {other}"),
    }
}

// ---------------------------------------------------------------------------
// The tests

/// Every reader reads, single and listed, exactly the operations the read
/// rules give it on its tenant's path, each with its own ID, tenant,
/// requester, kind and plan; the instance `security_admin` reads every
/// open operation of both tenants' paths and the instance's toggle.
#[tokio::test]
async fn a49_pos_each_reader_reads_its_own_tenants_operations() {
    let fixture = fixture().await;
    for reader in &READERS {
        fixture
            .assert_lists(
                reader.seed,
                &list_uri(reader.tenant, ""),
                reader.reads,
                None,
                reader.who,
            )
            .await;
        for id in reader.reads {
            fixture
                .assert_reads(reader.seed, &op_uri(reader.tenant, id), id, reader.who)
                .await;
        }
    }
    for tenant in ["ten_a", "ten_b"] {
        let who = "the instance security_admin";
        fixture
            .assert_lists(SEC, &list_uri(tenant, ""), all_of(tenant), None, who)
            .await;
        for id in all_of(tenant) {
            fixture
                .assert_reads(SEC, &op_uri(tenant, id), id, who)
                .await;
        }
    }
    fixture
        .assert_reads(SEC, &instance_op_uri("op_i1"), "op_i1", "the admin")
        .await;
    fixture
        .assert_lists(SEC, "/admin/v1/operations", &["op_i1"], None, "the admin")
        .await;
    fixture.drop().await;
}

/// A tenant's reader on the other tenant's path gets one 403 `forbidden`,
/// the very answer it gets on a tenant that does not exist: for the list
/// (with and without a query) and the single read of the other tenant's
/// real operations, of its own and of a missing one; and on unknown,
/// case-variant, padded and near-miss tenant IDs of both tenants. The
/// controls: each reads its own path, and the instance `security_admin`
/// reads the other tenant's path.
#[tokio::test]
async fn a49_neg_other_tenants_path_is_the_403_of_a_tenant_that_does_not_exist() {
    let fixture = fixture().await;
    let forbidden = wire_error("forbidden");
    // Tenant IDs no row has: unknown ones, and case variants, padded and
    // near-miss forms of both tenants' IDs (percent-encoded in the path;
    // `%D0%B0` is the Cyrillic `а`, `%00` a NUL no stored ID can hold).
    let not_tenants = [
        "ten_zzz",
        "ten_c",
        "ten_",
        "TEN_B",
        "Ten_b",
        "ten_B",
        "ten_b%20",
        "%20ten_b",
        "ten_b%09",
        "ten_bb",
        "ten_b%00",
        "TEN_A",
        "ten_A",
        "ten_a%20",
        "%20ten_a",
        "ten_%D0%B0",
    ];
    let mut first: Option<Answer> = None;
    for reader in &READERS {
        let what = |uri: &str| format!("{} GET {uri}", reader.who);
        // The reference: an unknown tenant's list.
        let reference_uri = list_uri("ten_zzz", "");
        let reference = fixture.get(reader.seed, &reference_uri).await;
        assert_wire_error(&reference, &forbidden, &what(&reference_uri));
        // One 403 for every reader, too: it names no reader.
        let first = first.get_or_insert_with(|| reference.clone());
        assert_eq!(&reference, first, "{}: not the same 403", reader.who);

        let mut tenants = vec![reader.other];
        tenants.extend(not_tenants);
        // The other tenant's operations, the reader's own, the instance's
        // and a missing one.
        let mut ids = all_of(reader.other).to_vec();
        ids.extend(all_of(reader.tenant));
        ids.extend(["op_i1", "op_missing"]);
        let mut probed = 0;
        for tenant in tenants {
            let mut uris = vec![
                list_uri(tenant, ""),
                list_uri(tenant, "limit=1"),
                list_uri(tenant, "limit=500&after=op_a"),
            ];
            uris.extend(ids.iter().map(|id| op_uri(tenant, id)));
            for uri in uris {
                let answer = fixture.get(reader.seed, &uri).await;
                assert_wire_error(&answer, &forbidden, &what(&uri));
                assert_eq!(
                    answer,
                    reference,
                    "{}: not the 403 of no tenant",
                    what(&uri)
                );
                probed += 1;
            }
        }
        assert!(probed > 100, "{probed}");

        // The controls: the reader reads its own path; the instance
        // `security_admin` reads the other tenant's.
        fixture
            .assert_lists(
                reader.seed,
                &list_uri(reader.tenant, ""),
                reader.reads,
                None,
                reader.who,
            )
            .await;
        fixture
            .assert_reads(
                reader.seed,
                &op_uri(reader.tenant, reader.reads[0]),
                reader.reads[0],
                reader.who,
            )
            .await;
        fixture
            .assert_lists(
                SEC,
                &list_uri(reader.other, ""),
                all_of(reader.other),
                None,
                "the instance security_admin",
            )
            .await;
        for id in all_of(reader.other) {
            fixture
                .assert_reads(SEC, &op_uri(reader.other, id), id, "the admin")
                .await;
        }
    }
    fixture.drop().await;
}

/// On a path the caller reads, an operation outside it is the 404
/// `not_found` of a missing ID, byte for byte: the other tenant's
/// operations, the instance's toggle, an instance row of a tenant kind, an
/// `approve` row (of `ten_a`), and case, padded and near-miss variants of
/// the other tenant's and of the caller's own IDs; for every tenant
/// reader on its own path and the instance `security_admin` on each
/// tenant's path and the instance path. The controls: the same reader
/// reads its own operation on that path, and the other tenant's readers
/// read theirs on their own path.
#[tokio::test]
async fn a49_neg_other_tenants_operation_on_own_path_is_the_404_of_a_missing_one() {
    let fixture = fixture().await;
    let not_found = wire_error("not_found");
    // (who, seed, tenant (None: the instance path), an ID it reads there)
    let mut probes: Vec<(&str, u8, Option<&str>, &str)> = READERS
        .iter()
        .map(|reader| {
            (
                reader.who,
                reader.seed,
                Some(reader.tenant),
                reader.reads[0],
            )
        })
        .collect();
    let admin = "the instance security_admin";
    for tenant in ["ten_a", "ten_b"] {
        probes.push((admin, SEC, Some(tenant), all_of(tenant)[0]));
    }
    probes.push((admin, SEC, None, "op_i1"));

    for (who, seed, tenant, own) in probes {
        let uri_of = |id: &str| match tenant {
            Some(tenant) => op_uri(tenant, id),
            None => instance_op_uri(id),
        };
        let reference_uri = uri_of("op_missing");
        let reference = fixture.get(seed, &reference_uri).await;
        assert_wire_error(
            &reference,
            &not_found,
            &format!("{who} GET {reference_uri}"),
        );
        for id in foreign_ids(tenant, own) {
            let uri = uri_of(&id);
            let what = format!("{who} GET {uri}");
            let answer = fixture.get(seed, &uri).await;
            assert_wire_error(&answer, &not_found, &what);
            assert_eq!(answer, reference, "{what}: not the 404 of a missing ID");
        }
        // The control: the same reader reads its own operation here.
        fixture.assert_reads(seed, &uri_of(own), own, who).await;
    }
    // The controls of the other side: each foreign tenant operation is
    // read on its own path by its tenant's readers.
    for reader in &READERS {
        for id in reader.reads {
            fixture
                .assert_reads(reader.seed, &op_uri(reader.tenant, id), id, reader.who)
                .await;
        }
    }
    fixture.drop().await;
}

/// The IDs that are not operations of `path` (`None`: the instance path),
/// though rows or near-misses of rows exist: the operations of every other
/// path, an instance row of a tenant kind, the `approve` row of `ten_a`,
/// case, padded, NUL-suffixed, extended and truncated variants of a foreign
/// operation's ID and of `own` (an ID the caller reads on `path`), and the
/// IDs of rows of other tables (tenants, operators, an audit event).
fn foreign_ids(path: Option<&str>, own: &str) -> Vec<String> {
    let mut ids: Vec<String> = OPS
        .iter()
        .filter(|op| op.tenant != path || op.id == "op_ix" || op.id == "op_a9")
        .map(|op| op.id.to_owned())
        .collect();
    let foreign = match path {
        Some("ten_a") => "op_b1",
        _ => "op_a1",
    };
    for id in [foreign, own] {
        ids.extend([
            id.to_uppercase(),
            format!("{}{}", id[..1].to_uppercase(), &id[1..]),
            format!("{id}%20"),
            format!("%20{id}"),
            format!("{id}%00"),
            format!("{id}x"),
            id[..id.len() - 1].to_owned(),
        ]);
    }
    ids.extend(["ten_a", "ten_b", "adm_trust_a", "adm_trust_b", "evt_op_b1"].map(String::from));
    ids.sort();
    ids.dedup();
    ids
}

/// Of `ten_a`'s two `trust_admin`s, neither reads nor lists the other's
/// operation: the single read is the 404 of a missing ID, and the list
/// leaves it out. `ten_a`'s `auditor` and the instance `security_admin`
/// read and list both, and each `trust_admin` reads its own: the controls.
#[tokio::test]
async fn a49_neg_another_trust_admins_operation_is_the_404_of_a_missing_one() {
    let fixture = fixture().await;
    let not_found = wire_error("not_found");
    for (who, seed, own, others) in [
        (
            "ten_a's trust_admin",
            TRUST_A,
            &["op_a1", "op_c1"][..],
            &["op_a2"][..],
        ),
        (
            "ten_a's second trust_admin",
            SECOND_A,
            &["op_a2"][..],
            &["op_a1", "op_c1"][..],
        ),
    ] {
        let reference = fixture.get(seed, &op_uri("ten_a", "op_missing")).await;
        assert_wire_error(&reference, &not_found, who);
        for id in others {
            let uri = op_uri("ten_a", id);
            let answer = fixture.get(seed, &uri).await;
            assert_wire_error(&answer, &not_found, &format!("{who} GET {uri}"));
            assert_eq!(
                answer, reference,
                "{who} GET {uri}: not the 404 of a missing ID"
            );
        }
        let list = fixture
            .assert_lists(seed, &list_uri("ten_a", ""), own, None, who)
            .await;
        let body = String::from_utf8(list.body.to_vec()).unwrap();
        for id in others {
            assert!(!body.contains(id), "{who}: the list shows {id}: {body}");
        }
        for id in own {
            fixture
                .assert_reads(seed, &op_uri("ten_a", id), id, who)
                .await;
        }
    }
    for (who, seed) in [
        ("ten_a's auditor", AUD_A),
        ("the instance security_admin", SEC),
    ] {
        fixture
            .assert_lists(seed, &list_uri("ten_a", ""), all_of("ten_a"), None, who)
            .await;
        for id in all_of("ten_a") {
            fixture
                .assert_reads(seed, &op_uri("ten_a", id), id, who)
                .await;
        }
    }
    fixture.drop().await;
}

/// The lists of each tenant's readers, whole and paged one at a time, hold
/// only their own tenant's operations, and no byte of them shows the other
/// tenant ([`traces_of`]). The other tenant's cursor, taken from its own
/// list, is accepted as any ID is: the page after it is the page after a
/// missing ID at the same place, so it tells nothing of the other tenant.
#[tokio::test]
async fn a49_neg_own_list_shows_nothing_of_the_other_tenant() {
    let fixture = fixture().await;
    for reader in &READERS {
        let whole = fixture
            .assert_lists(
                reader.seed,
                &list_uri(reader.tenant, ""),
                reader.reads,
                None,
                reader.who,
            )
            .await;
        assert_no_trace_of(&whole, reader.other, reader.who);
        // Paged one at a time: every page is the reader's own next
        // operation, and every cursor its own ID.
        let mut after: Option<&str> = None;
        for (index, id) in reader.reads.iter().enumerate() {
            let query = match after {
                Some(after) => format!("limit=1&after={after}"),
                None => "limit=1".to_owned(),
            };
            let page = fixture
                .assert_lists(
                    reader.seed,
                    &list_uri(reader.tenant, &query),
                    &[*id],
                    Some(*id),
                    &format!("{} page {index}", reader.who),
                )
                .await;
            assert_no_trace_of(&page, reader.other, reader.who);
            after = Some(id);
        }
        let last = fixture
            .assert_lists(
                reader.seed,
                &list_uri(reader.tenant, &format!("limit=1&after={}", after.unwrap())),
                &[],
                None,
                &format!("{} past the last page", reader.who),
            )
            .await;
        assert_no_trace_of(&last, reader.other, reader.who);
    }

    // `ten_b`'s cursor: its trust_admin's first page of one ends at
    // `op_b1`.
    fixture
        .assert_lists(
            TRUST_B,
            &list_uri("ten_b", "limit=1"),
            &["op_b1"],
            Some("op_b1"),
            "ten_b's trust_admin",
        )
        .await;
    // On `ten_a`'s path, the page after `ten_b`'s cursor (and after its
    // other ID) is the page after a missing ID between `op_b1` and
    // `op_c1`, byte for byte, for every reader of `ten_a`'s path.
    for (who, seed, after_b) in [
        ("ten_a's trust_admin", TRUST_A, &["op_c1"][..]),
        ("ten_a's second trust_admin", SECOND_A, &[][..]),
        ("ten_a's auditor", AUD_A, &["op_c1"][..]),
        ("the instance security_admin", SEC, &["op_c1"][..]),
    ] {
        let reference = fixture
            .assert_lists(seed, &list_uri("ten_a", "after=op_b9"), after_b, None, who)
            .await;
        for cursor in ["op_b1", "op_b2"] {
            let uri = list_uri("ten_a", &format!("after={cursor}"));
            let answer = fixture.get(seed, &uri).await;
            assert_eq!(answer, reference, "{who} GET {uri}");
            assert_no_trace_of(&answer, "ten_b", who);
        }
    }
    // The control: on `ten_b`'s own path the cursor pages on to `op_b2`.
    fixture
        .assert_lists(
            TRUST_B,
            &list_uri("ten_b", "after=op_b1"),
            &["op_b2"],
            None,
            "ten_b's trust_admin",
        )
        .await;
    // And `ten_a`'s cursors on `ten_b`'s path are the page after a missing
    // ID before every `op_b`: the whole list.
    let whole = fixture
        .assert_lists(
            TRUST_B,
            &list_uri("ten_b", ""),
            &["op_b1", "op_b2"],
            None,
            "ten_b's trust_admin",
        )
        .await;
    for cursor in ["op_a1", "op_a2", "op_a0"] {
        let uri = list_uri("ten_b", &format!("after={cursor}"));
        let answer = fixture.get(TRUST_B, &uri).await;
        assert_eq!(answer, whole, "ten_b's trust_admin GET {uri}");
        assert_no_trace_of(&answer, "ten_a", "ten_b's trust_admin");
    }
    fixture.drop().await;
}
