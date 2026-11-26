//! A22, the wire half of the operator scope: the admin read router of
//! slice S4 (`skyoauth_service::admin_http::admin_router`) never takes a
//! claim, a token, a session or a header as operator authority; only the
//! verified peer identity, matched to a registered, usable credential with
//! the needed role, reads (tasks §8; T13.1, T13.6; D5 of tasks §13).
//!
//! **A22 partial: these tests are no claim, and A22's M1a stage stays
//! `planned`, with no stamp.** They are registered on that planned stage,
//! beside the registry-slice tests of [`super::a22`], so they are no
//! evidence for it: the reporter lists their results as not counted.
//!
//! **What they prove, and what they do not.** They drive the router with
//! `tower::ServiceExt::oneshot` through
//! `admin_http::test_support::with_admin_peer`, the tests' fake acceptor,
//! which hands the router an *already-verified* peer identity, taken as
//! given. So they prove that the four read endpoints decide on that typed
//! peer identity and the registry alone, and never on an
//! `Authorization` bearer token, a session cookie, a forwarded client
//! certificate header or an email-, user- or role-shaped header. They do
//! *not* prove that the mTLS leg works: no TLS handshake runs, no client
//! certificate chain is verified against the deployment trust anchor (the
//! credential's `trust_anchor_ref`), and no presented key is canonicalized
//! into `public_identity` by the server. Those legs stay open, with slices
//! S6 (the handshake and the chain against the trust anchor), S7 (the
//! canonicalization of the presented key) and S5 (enrolment and the
//! credential state, as the lead's working split); the admin router is served nowhere until the in-process
//! rustls acceptor of S6 lands (D5), and nothing here serves it. The
//! operator client of the OP harness component, `skyoauth-operator`
//! (T13.10), does not exist either. The fixture's keys are canonical
//! identities (`spki-sha256:<hex>`) that [`key`] computes from real Ed25519
//! `SubjectPublicKeyInfo`s with the service's own
//! `identity::canonical_public_identity`, the form the acceptor will hand
//! over, but no request presents a key.
//!
//! The router is the S4 read router: four `GET`s,
//! `/admin/v1/operations`, `/admin/v1/operations/{operation}`,
//! `/admin/v1/tenants/{tenant}/operations` and
//! `/admin/v1/tenants/{tenant}/operations/{operation}` (`ADMIN_ROUTES`).
//! Every route is driven with an existing target and, for the single reads,
//! a missing one, so a refusal is shown to come before any target is read.
//!
//! **The wire values come from the catalogue.** The status, `Content-Type`,
//! `Cache-Control`, the absence of `Retry-After` and the body bytes of every
//! 401 and 403 (and of the controls' 404) are read from
//! `tests/conformance/fixtures/_wire/errors.v1.json` by the shared
//! [`super::wire_fixture`] ([`WireError`]: the code's `http_status`,
//! `body.shape` filled with the code, `cache_control`, `retry_after`), never
//! typed here; the body is also parsed and must hold the shape's members
//! and no other. Within a test, every refusal of one code is also the same
//! status, header map and bytes as the first one.
//!
//! **The fixture** ([`fixture`]), one fresh database per test: an instance
//! bootstrapped through `registry::bootstrap_instance`, whose first operator
//! `adm_first` ([`ADMIN`]) is the instance `security_admin`; tenants
//! `ten_a` and `ten_b`; operators written with `registry::test_support`,
//! each with one identity, one credential and one binding (see [`fixture`]);
//! and one pending operation per path (`op_i1` on the instance, `op_a1` by
//! `ten_a`'s `trust_admin`, `op_b1` by `ten_b`'s), written with the bare
//! operation-row writer after its audit event. The levers (revoke a
//! credential, disable an identity, disable a binding) are pulled inside the
//! tests, through the registry's own mutators, after a control shows the
//! same key reading.
//!
//! **The headers** ([`claim_headers`], [`key_headers`], [`header_sets`]):
//! an `Authorization: Bearer` ID-token-shaped JWT whose claims name the
//! admin (`sub`, `email`, `roles: ["security_admin"]`), a session cookie,
//! `X-Client-Cert`, `X-SSL-Client-Cert`, `X-Forwarded-Client-Cert`,
//! `X-Email`, `X-Forwarded-Email`, `X-Forwarded-User`, `X-Admin-Role` and
//! others; and the same names each holding the admin's *exact* public
//! identity, so a router that took any of them as the peer identity, or let
//! it stand in for a missing or role-less one, would answer 200. The
//! no-peer, the role-less and the positive tests send each alone, every
//! claim-shaped one at once and every key-valued one at once; the test of
//! the peers naming no usable credential sends the last two sets only.
//!
//! - **No peer** (`a22_neg_no_peer_is_one_401_whatever_the_headers_say`):
//!   on every route, with no header and with every header set, the request
//!   is 401 `unauthenticated`, the same bytes and headers each time. The
//!   control: the same request with the admin's verified peer reads.
//! - **A peer naming no usable credential**
//!   (`a22_neg_a_peer_naming_no_usable_credential_is_the_same_401`): a
//!   never-registered key; the key of an operator whose identity and
//!   `security_admin` binding exist but whose key was never enrolled as a
//!   credential; a revoked credential; a credential created disabled; an
//!   enabled credential of a disabled operator; near-miss forms of the
//!   admin's own key; and the admin's IDs, email, JWT or `Bearer` header
//!   given as the identity. Each is the 401 of a request without a peer,
//!   byte for byte, also with headers naming the admin. Every one of those
//!   operators holds an enabled instance `security_admin` binding, and the
//!   revoked and disabled operators read with that same key before their
//!   lever is pulled: the control.
//! - **The registered credential with the role**
//!   (`a22_pos_a_registered_credential_with_the_role_reads_on_the_wire`):
//!   the instance `security_admin` reads every route of the instance and of
//!   both tenants (200, the seeded operation; 404 `not_found` for a missing
//!   one), `ten_a`'s `trust_admin` its own operation on `ten_a`'s path and
//!   `ten_b`'s `auditor` `ten_b`'s; the same answer, byte for byte, with
//!   every header set attached, so a header neither adds nor removes
//!   anything.
//! - **A usable credential without the role**
//!   (`a22_neg_a_usable_credential_without_the_role_is_one_403_and_no_header_upgrades_it`):
//!   an instance `auditor` (instance and tenant paths), `ten_a`'s
//!   `trust_admin` on the instance path and on `ten_b`'s, `ten_b`'s
//!   `auditor` on the instance path and `ten_a`'s, `ten_a`'s `client_admin`,
//!   and an operator whose instance `security_admin` binding is disabled
//!   (after reading with it as the control) are one 403 `forbidden`, the
//!   same bytes for an existing and a missing target, and stay that 403
//!   with every header set naming the admin attached. The controls: the
//!   admin reads every one of those routes, and `ten_a`'s `trust_admin` and
//!   `ten_b`'s `auditor` still read their own paths, so their credentials
//!   are usable and only the role or scope is missing.
//!
//! # Not covered here
//!
//! - The mTLS legs above (handshake, chain against `trust_anchor_ref`, key
//!   canonicalization by the server): S6 for the handshake and the chain, S7
//!   for the canonicalization, S5 for enrolment and credential state (the
//!   lead's split; tasks §13 does not say).
//! - Any write: the router exposes none yet, so no write endpoint is shown
//!   to ignore a claim (`admin_http`, "Served nowhere").
//! - What a request with the right key but an expired or untrusted
//!   certificate gets: a handshake matter, so the acceptor's.
//! - The router's own unknown-path, method and query answers, the plan and
//!   digest on the wire, and the readers' views of one another's
//!   operations: `service/tests/admin_http.rs`, registry tests, not
//!   scenarios.
//! - A22's M3 stage, "linking", and the registry-lookup half of M1a, which
//!   is [`super::a22`]'s.

use std::sync::Arc;

use axum::{
    Router,
    http::{StatusCode, header},
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    admin_http::{ADMIN_ROUTES, AdminState, admin_router},
    persistence::{
        PgPool,
        registry::{
            self, AdminRole, AdminRoleBindingChanges, BootstrapRequest, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, NewTenant, Status, bootstrap_instance,
        },
    },
};

use super::wire_fixture::{
    Answer, FixedClock, SeededOperation, WireError, assert_wire_error, at, get_with, key,
    seed_operation, wire_error,
};

// ---------------------------------------------------------------------------
// Requests

/// A path of the router: the instance's, or a tenant's.
#[derive(Debug, Clone, Copy)]
enum Path {
    Instance,
    Tenant(&'static str),
}

impl Path {
    /// The seeded operation of the path, its tenant and its requester.
    fn operation(self) -> (&'static str, Option<&'static str>, &'static str) {
        match self {
            Path::Instance => ("op_i1", None, "adm_first"),
            Path::Tenant("ten_a") => ("op_a1", Some("ten_a"), "adm_trust_a"),
            Path::Tenant("ten_b") => ("op_b1", Some("ten_b"), "adm_trust_b"),
            Path::Tenant(other) => panic!("no tenant {other} in the fixture"),
        }
    }
}

/// What a reader of the path gets for a target.
#[derive(Debug, Clone, Copy)]
enum Shows {
    /// A page holding the path's one seeded operation.
    Page,
    /// The path's seeded operation.
    Operation,
    /// 404 `not_found`: the operation does not exist.
    Missing,
}

#[derive(Debug, Clone)]
struct Target {
    path: Path,
    uri: String,
    shows: Shows,
}

/// Every route of `ADMIN_ROUTES` on `path`: each list, and each single read
/// with the seeded operation and with a missing one.
fn targets(path: Path) -> Vec<Target> {
    let mut targets = Vec::new();
    for route in ADMIN_ROUTES {
        let tenant = route.contains("{tenant}");
        let uri = match path {
            Path::Instance if !tenant => route.to_owned(),
            Path::Tenant(id) if tenant => route.replace("{tenant}", id),
            _ => continue,
        };
        if uri.contains("{operation}") {
            let (operation, _, _) = path.operation();
            for (id, shows) in [
                (operation, Shows::Operation),
                ("op_missing", Shows::Missing),
            ] {
                targets.push(Target {
                    path,
                    uri: uri.replace("{operation}", id),
                    shows,
                });
            }
        } else {
            targets.push(Target {
                path,
                uri,
                shows: Shows::Page,
            });
        }
    }
    assert_eq!(targets.len(), 3, "{path:?}: a list and two single reads");
    targets
}

/// Every target of the instance and of both tenants: the four routes.
fn every_target() -> Vec<Target> {
    [Path::Instance, Path::Tenant("ten_a"), Path::Tenant("ten_b")]
        .into_iter()
        .flat_map(targets)
        .collect()
}

// ---------------------------------------------------------------------------
// Headers that claim authority

/// The admin's email, which the JWT and the email headers name; operators
/// have no email, so it names no row.
const ADMIN_EMAIL: &str = "admin@example.test";

/// An unsigned ID-token-shaped JWT (`alg: none`) whose claims name the
/// admin: `{"iss":"https://idp.example.test","sub":"adm_first","email":
/// "admin@example.test","email_verified":true,"roles":["security_admin"],
/// "skyoauth_admin":true}`.
const ADMIN_JWT: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLnRlc3QiLCJzdWIiOiJhZG1fZmlyc3QiLCJlbWFpbCI6ImFkbWluQGV4YW1wbGUudGVzdCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJyb2xlcyI6WyJzZWN1cml0eV9hZG1pbiJdLCJza3lvYXV0aF9hZG1pbiI6dHJ1ZX0.";

/// Claim-, token- and session-shaped headers naming the admin: a bearer
/// ID token, a session cookie, a forwarded client certificate's subject,
/// an email, a user and a role.
fn claim_headers() -> Vec<(&'static str, String)> {
    vec![
        ("authorization", format!("Bearer {ADMIN_JWT}")),
        (
            "cookie",
            "skyoauth_session=s3ss10n-of-adm_first; role=security_admin".into(),
        ),
        (
            "x-forwarded-client-cert",
            "By=spiffe://skyoauth/admin;Subject=\"CN=adm_first\";URI=spiffe://skyoauth/adm_first"
                .into(),
        ),
        ("x-email", ADMIN_EMAIL.into()),
        ("x-forwarded-email", ADMIN_EMAIL.into()),
        ("x-auth-request-email", ADMIN_EMAIL.into()),
        ("x-forwarded-user", "adm_first".into()),
        ("remote-user", "adm_first".into()),
        ("x-admin-role", "security_admin".into()),
        ("x-forwarded-groups", "security_admin".into()),
    ]
}

/// The same kind of headers, each holding the admin's exact public
/// identity (or a bearer of it): a router that read any of them as the
/// peer identity would authorize the admin.
fn key_headers(admin: &str) -> Vec<(&'static str, String)> {
    vec![
        ("authorization", format!("Bearer {admin}")),
        ("cookie", format!("session={admin}")),
        ("x-client-cert", admin.to_owned()),
        ("x-ssl-client-cert", admin.to_owned()),
        ("x-forwarded-client-cert", admin.to_owned()),
        ("x-email", admin.to_owned()),
        ("x-forwarded-email", admin.to_owned()),
        ("x-forwarded-user", admin.to_owned()),
        ("x-admin-peer", admin.to_owned()),
        ("x-public-identity", admin.to_owned()),
    ]
}

/// No header; each claim-shaped and each key-valued header alone, and the
/// bare key as `Authorization`; every claim-shaped one at once; every
/// key-valued one at once. Each with a label.
fn header_sets(admin: &str) -> Vec<(String, Vec<(&'static str, String)>)> {
    let mut sets = vec![("no header".to_owned(), Vec::new())];
    let mut singles = claim_headers();
    singles.extend(key_headers(admin));
    singles.push(("authorization", admin.to_owned()));
    for (name, value) in singles {
        sets.push((format!("{name}: {value}"), vec![(name, value)]));
    }
    sets.push(("every claim-shaped header".to_owned(), claim_headers()));
    sets.push(("every key-valued header".to_owned(), key_headers(admin)));
    sets
}

// ---------------------------------------------------------------------------
// The fixture

/// `adm_first`, the bootstrapped instance `security_admin`.
const ADMIN: u8 = 0x01;
/// `adm_trust_a`: `ten_a`'s `trust_admin`, requester of `op_a1`.
const TRUST_A: u8 = 0x02;
/// `adm_trust_b`: `ten_b`'s `trust_admin`, requester of `op_b1`.
const TRUST_B: u8 = 0x03;
/// `adm_aud_b`: `ten_b`'s `auditor`.
const AUD_B: u8 = 0x04;
/// `adm_aud_i`: an instance `auditor`, not a reader of operations.
const AUD_I: u8 = 0x05;
/// `adm_client_a`: `ten_a`'s `client_admin`, not a reader.
const CLIENT_A: u8 = 0x06;
/// `adm_bind_off`: an instance `security_admin` whose binding a test
/// disables.
const BIND_OFF: u8 = 0x07;
/// `adm_revoked`: an instance `security_admin` whose credential a test
/// revokes.
const REVOKED: u8 = 0x08;
/// `adm_id_off`: an instance `security_admin` whose identity a test
/// disables.
const ID_OFF: u8 = 0x09;
/// `adm_cred_off`: an instance `security_admin` whose credential is
/// created disabled (never revoked).
const CRED_OFF: u8 = 0x0a;
/// `adm_unenrolled`: an enabled identity with an enabled instance
/// `security_admin` binding and no credential; this key was never enrolled.
const UNENROLLED: u8 = 0x0b;
/// A key no row names.
const UNKNOWN: u8 = 0x0c;

/// One test's database and router.
struct Fixture {
    db: TestDb,
    pool: PgPool,
    router: Router,
    /// The catalogue's 404, for the controls' missing targets.
    not_found: WireError,
    /// The catalogue's `Cache-Control`, for the controls' 200s.
    cache_control: String,
}

impl Fixture {
    async fn get(&self, peer: Option<&str>, uri: &str, headers: &[(&str, String)]) -> Answer {
        get_with(&self.router, peer, uri, headers).await
    }

    /// `answer` is what a reader of `target` gets: 200 with the path's
    /// seeded operation (alone on a page), or the catalogue's 404 for a
    /// missing one.
    #[track_caller]
    fn assert_reads(&self, answer: &Answer, target: &Target, who: &str) {
        let what = format!("{} as {who}", target.uri);
        if let Shows::Missing = target.shows {
            assert_wire_error(answer, &self.not_found, &what);
            return;
        }
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
        let json: Value = serde_json::from_slice(&answer.body).unwrap();
        let (id, tenant, actor) = target.path.operation();
        let operation = match target.shows {
            Shows::Page => {
                let operations = json["operations"].as_array().expect("operations");
                assert_eq!(operations.len(), 1, "{what}: {json}");
                assert_eq!(json["next"], Value::Null, "{what}");
                &operations[0]
            }
            _ => &json,
        };
        assert_eq!(operation["id"], id, "{what}");
        assert_eq!(operation["tenant_id"], json!(tenant), "{what}");
        assert_eq!(operation["actor_id"], actor, "{what}");
        assert_eq!(operation["outcome"], "pending", "{what}");
    }

    /// `peer` reads every target of `paths`, with no header.
    async fn assert_reads_all(&self, peer: &str, paths: &[Path], who: &str) {
        for &path in paths {
            for target in targets(path) {
                let answer = self.get(Some(peer), &target.uri, &[]).await;
                self.assert_reads(&answer, &target, who);
            }
        }
    }

    async fn drop(self) {
        self.db.drop([self.pool]).await;
    }
}

/// One operator `adm_<name>`: an enabled identity, the credential
/// `crd_<name>` of `key(seed)` with `credential_status` (no credential when
/// it is `None`), and an enabled binding `rb_<name>` of `role` in `tenant`
/// (`None`: the instance).
async fn operator(
    pool: &PgPool,
    name: &str,
    seed: u8,
    role: AdminRole,
    tenant: Option<&str>,
    credential_status: Option<Status>,
) {
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
    if let Some(status) = credential_status {
        registry::test_support::create_admin_credential(
            pool,
            &NewAdminCredential {
                id: format!("crd_{name}"),
                admin_id: admin_id.clone(),
                public_identity: key(seed),
                trust_anchor_ref: "deployment/operator-ca".into(),
                status,
            },
        )
        .await
        .unwrap();
    }
    registry::test_support::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: format!("rb_{name}"),
            admin_id,
            role,
            tenant_id: tenant.map(Into::into),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// The pending operation of `path` ([`Path::operation`]), expiring a day
/// after bootstrap, written after its `administrative_operation.create`
/// event in one transaction ([`seed_operation`]).
async fn seed_path_operation(pool: &PgPool, path: Path) {
    let (id, tenant, actor) = path.operation();
    let kind = match path {
        Path::Instance => "instance_security_policy_update",
        Path::Tenant(_) => "trust_source_create",
    };
    let Value::Object(plan) = json!({
        "requester_credential_id": actor.replace("adm_", "crd_"),
    }) else {
        unreachable!()
    };
    seed_operation(
        pool,
        &SeededOperation {
            id,
            tenant,
            actor,
            kind,
            plan,
            approves: None,
        },
    )
    .await;
}

/// The instance bootstrapped with `adm_first` ([`ADMIN`], instance
/// `security_admin`); tenants `ten_a` and `ten_b`; the operators of the
/// seed constants above, each with an enabled identity, credential and
/// binding unless its constant says otherwise; and `op_i1`, `op_a1` and
/// `op_b1`.
async fn fixture() -> Fixture {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: "019a9f3c-5b2e-7c41-9d8e-0000000a22e1",
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: &key(ADMIN),
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &SigningKey::from_bytes(&[0x22; 32])
                .verifying_key()
                .to_bytes(),
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    for (tenant, namespace) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::test_support::create_tenant(
            &pool,
            &NewTenant {
                id: tenant.into(),
                name: format!("Tenant {tenant}"),
                secret_namespace: namespace.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    let enabled = Some(Status::Enabled);
    let sec = AdminRole::SecurityAdmin;
    let trust = AdminRole::TrustAdmin;
    let auditor = AdminRole::Auditor;
    let a = Some("ten_a");
    let b = Some("ten_b");
    for (name, seed, role, tenant, credential) in [
        ("trust_a", TRUST_A, trust, a, enabled),
        ("trust_b", TRUST_B, trust, b, enabled),
        ("aud_b", AUD_B, auditor, b, enabled),
        ("aud_i", AUD_I, auditor, None, enabled),
        ("client_a", CLIENT_A, AdminRole::ClientAdmin, a, enabled),
        ("bind_off", BIND_OFF, sec, None, enabled),
        ("revoked", REVOKED, sec, None, enabled),
        ("id_off", ID_OFF, sec, None, enabled),
        ("cred_off", CRED_OFF, sec, None, Some(Status::Disabled)),
        ("unenrolled", UNENROLLED, sec, None, None),
    ] {
        operator(&pool, name, seed, role, tenant, credential).await;
    }
    for path in [Path::Instance, Path::Tenant("ten_a"), Path::Tenant("ten_b")] {
        seed_path_operation(&pool, path).await;
    }
    let router = admin_router(AdminState::new(pool.clone(), Arc::new(FixedClock)));
    let not_found = wire_error("not_found");
    let cache_control = not_found.cache_control.clone();
    Fixture {
        db,
        pool,
        router,
        not_found,
        cache_control,
    }
}

const EVERY_PATH: [Path; 3] = [Path::Instance, Path::Tenant("ten_a"), Path::Tenant("ten_b")];

// ---------------------------------------------------------------------------
// The tests

/// Without a verified peer, every route answers the catalogue's 401
/// `unauthenticated`, the same status, headers and bytes whatever the
/// request's headers claim, the admin's exact key in every header
/// included; the same requests with the admin's verified peer read.
#[tokio::test]
async fn a22_neg_no_peer_is_one_401_whatever_the_headers_say() {
    let fixture = fixture().await;
    let unauthenticated = wire_error("unauthenticated");
    let admin = key(ADMIN);
    let sets = header_sets(&admin);
    let mut first: Option<Answer> = None;
    for target in every_target() {
        for (label, headers) in &sets {
            let what = format!("{} without a peer, {label}", target.uri);
            let answer = fixture.get(None, &target.uri, headers).await;
            assert_wire_error(&answer, &unauthenticated, &what);
            let first = first.get_or_insert_with(|| answer.clone());
            assert_eq!(&answer, first, "{what}: not the same 401");
            // The control: the same request, with the admin as the
            // verified peer, reads.
            let control = fixture.get(Some(&admin), &target.uri, headers).await;
            fixture.assert_reads(&control, &target, "the admin");
        }
    }
    fixture.drop().await;
}

/// A verified peer whose identity names no usable credential is the 401 of
/// a request without a peer, byte for byte, also with headers naming the
/// admin: a never-registered key, a key never enrolled for an operator who
/// holds the role, a revoked credential, a credential created disabled, a
/// disabled operator's credential, near-miss forms of the admin's key, and
/// the admin's IDs, email and tokens given as the identity. Every one of
/// those operators holds an enabled instance `security_admin` binding; the
/// revoked and disabled ones read with the same key before their lever.
#[tokio::test]
async fn a22_neg_a_peer_naming_no_usable_credential_is_the_same_401() {
    let fixture = fixture().await;
    let unauthenticated = wire_error("unauthenticated");
    let admin = key(ADMIN);

    // The controls: before their levers, the revoked and disabled
    // operators read every route with the very keys refused below.
    for seed in [REVOKED, ID_OFF] {
        fixture
            .assert_reads_all(&key(seed), &EVERY_PATH, "its key before the lever")
            .await;
    }
    let revoked = registry::revoke_admin_credential(&fixture.pool, "crd_revoked", at(2))
        .await
        .unwrap();
    assert_eq!(
        (revoked.status, revoked.revoked_at),
        (Status::Disabled, Some(at(2)))
    );
    let disabled = registry::disable_admin_identity(&fixture.pool, "adm_id_off")
        .await
        .unwrap();
    assert_eq!(disabled.status, Status::Disabled);

    let no_peer = fixture
        .get(None, &targets(Path::Instance)[0].uri, &[])
        .await;
    assert_wire_error(&no_peer, &unauthenticated, "without a peer");

    let hex = admin.strip_prefix("spki-sha256:").unwrap().to_owned();
    let peers: Vec<(&str, String)> = vec![
        ("a never-registered key", key(UNKNOWN)),
        (
            "a key never enrolled for an operator with the role",
            key(UNENROLLED),
        ),
        ("a revoked credential", key(REVOKED)),
        ("a credential created disabled", key(CRED_OFF)),
        ("a disabled operator's credential", key(ID_OFF)),
        ("the admin's key in upper case", admin.to_uppercase()),
        ("the admin's key's hex alone", hex.clone()),
        ("the admin's key with a trailing space", format!("{admin} ")),
        (
            "the admin's key with another prefix",
            format!("spki-sha1:{hex}"),
        ),
        ("the admin's admin_id", "adm_first".into()),
        ("the admin's credential_id", "crd_first".into()),
        ("the admin's email", ADMIN_EMAIL.into()),
        ("an ID token naming the admin", ADMIN_JWT.into()),
        (
            "a bearer header of the admin's key",
            format!("Bearer {admin}"),
        ),
        ("a role claim", "roles=security_admin".into()),
    ];
    let header_sets = [
        ("no header", Vec::new()),
        ("every claim-shaped header", claim_headers()),
        ("every key-valued header", key_headers(&admin)),
    ];
    for (who, peer) in &peers {
        for target in every_target() {
            for (label, headers) in &header_sets {
                let what = format!("{} as {who}, {label}", target.uri);
                let answer = fixture.get(Some(peer), &target.uri, headers).await;
                assert_wire_error(&answer, &unauthenticated, &what);
                assert_eq!(answer, no_peer, "{what}: not the 401 of no peer");
            }
        }
    }
    // The control after the levers: the admin, an operator with the same
    // binding and an enabled credential, still reads every route.
    fixture
        .assert_reads_all(&admin, &EVERY_PATH, "the admin")
        .await;
    fixture.drop().await;
}

/// The registered credential with the needed role reads, on every route
/// it may read, and attaching any header set changes nothing in the
/// answer: the instance `security_admin` reads every path, `ten_a`'s
/// `trust_admin` its own operation on `ten_a`'s path, and `ten_b`'s
/// `auditor` and `trust_admin` `ten_b`'s.
#[tokio::test]
async fn a22_pos_a_registered_credential_with_the_role_reads_on_the_wire() {
    let fixture = fixture().await;
    let admin = key(ADMIN);
    assert!(
        admin.starts_with("spki-sha256:") && admin.len() == "spki-sha256:".len() + 64,
        "{admin}"
    );
    let readers = [
        ("the instance security_admin", ADMIN, EVERY_PATH.to_vec()),
        ("ten_a's trust_admin", TRUST_A, vec![Path::Tenant("ten_a")]),
        ("ten_b's auditor", AUD_B, vec![Path::Tenant("ten_b")]),
        ("ten_b's trust_admin", TRUST_B, vec![Path::Tenant("ten_b")]),
    ];
    let sets = header_sets(&admin);
    for (who, seed, paths) in readers {
        let peer = key(seed);
        for path in paths {
            for target in targets(path) {
                let plain = fixture.get(Some(&peer), &target.uri, &[]).await;
                fixture.assert_reads(&plain, &target, who);
                for (label, headers) in &sets {
                    let answer = fixture.get(Some(&peer), &target.uri, headers).await;
                    assert_eq!(
                        answer, plain,
                        "{} as {who}, {label}: a header changed the answer",
                        target.uri
                    );
                }
            }
        }
    }
    fixture.drop().await;
}

/// A usable credential without the role is one 403 `forbidden`, the same
/// bytes for every lacking cause and for an existing and a missing
/// target, and no claim, token, session or key-valued header naming the
/// admin upgrades it. The controls: the admin reads every one of those
/// routes; the disabled binding read before its lever; `ten_a`'s
/// `trust_admin` and `ten_b`'s `auditor` read their own paths.
#[tokio::test]
async fn a22_neg_a_usable_credential_without_the_role_is_one_403_and_no_header_upgrades_it() {
    let fixture = fixture().await;
    let forbidden = wire_error("forbidden");
    let admin = key(ADMIN);

    fixture
        .assert_reads_all(&key(BIND_OFF), &EVERY_PATH, "its key before the lever")
        .await;
    let binding = registry::test_support::update_admin_role_binding(
        &fixture.pool,
        "rb_bind_off",
        1,
        &AdminRoleBindingChanges {
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    assert_eq!((binding.status, binding.revision), (Status::Disabled, 2));

    let a = Path::Tenant("ten_a");
    let b = Path::Tenant("ten_b");
    let lacking: [(&str, u8, Vec<Path>); 6] = [
        ("an instance auditor", AUD_I, EVERY_PATH.to_vec()),
        ("ten_a's trust_admin", TRUST_A, vec![Path::Instance, b]),
        ("ten_b's auditor", AUD_B, vec![Path::Instance, a]),
        ("ten_b's trust_admin", TRUST_B, vec![Path::Instance, a]),
        ("ten_a's client_admin", CLIENT_A, EVERY_PATH.to_vec()),
        (
            "an operator whose security_admin binding is disabled",
            BIND_OFF,
            EVERY_PATH.to_vec(),
        ),
    ];
    let sets = header_sets(&admin);
    let mut first: Option<Answer> = None;
    for (who, seed, paths) in &lacking {
        let peer = key(*seed);
        for &path in paths {
            for target in targets(path) {
                for (label, headers) in &sets {
                    let what = format!("{} as {who}, {label}", target.uri);
                    let answer = fixture.get(Some(&peer), &target.uri, headers).await;
                    assert_wire_error(&answer, &forbidden, &what);
                    let first = first.get_or_insert_with(|| answer.clone());
                    assert_eq!(&answer, first, "{what}: not the same 403");
                }
                // The control: the admin reads this very target.
                let control = fixture.get(Some(&admin), &target.uri, &[]).await;
                fixture.assert_reads(&control, &target, "the admin");
            }
        }
    }
    // The role-less credentials are usable: the tenant roles still read
    // their own paths, so the 403s above are the role's or scope's.
    for (seed, path) in [(TRUST_A, a), (AUD_B, b), (TRUST_B, b)] {
        fixture
            .assert_reads_all(&key(seed), &[path], "own path")
            .await;
    }
    fixture.drop().await;
}
