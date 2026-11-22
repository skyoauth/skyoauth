//! The audited trust source write path with the IR-152 egress check
//! (`skyoauth_service::trust`; T11.2; identity-registry IR-152) against a
//! real PostgreSQL server: a create or a changed destination needs an
//! enabled egress allowlist entry of its purpose with exactly its value; an
//! unchanged one is not checked again; malformed destinations are refused
//! before any statement; only a `trust_admin` of the tenant writes; a
//! concurrent entry disable and a write serialize on the entry row; the
//! audit event comes last; only `READ COMMITTED` runs; and no error names a
//! destination.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. They claim no conformance
//! scenario (A05 belongs to the test session in `tests/security`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    collections::BTreeMap,
    error::Error as _,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use skyoauth_service::{
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AssertionProfile, AuditActor, BindingProfile, ChainVerdict,
            Consumption, InvariantKind, JsonObject, NewAdminCredential, NewAdminIdentity,
            NewAdminRoleBinding, NewAuditEvent, NewConsumedAssertion, NewPrincipal,
            NewPrincipalBinding, NewTenant, NewTrustKeyset, NewTrustSource, PrincipalKind,
            RegistryError, ReplayMode, Status, TrustSource, TrustSourceChanges, TrustSourceKind,
        },
    },
    trust::{
        self, DISCOVERY_URL, SourceAudit, SourceWriteError, TOKEN_REVIEW_ENDPOINT, create_source,
        update_source,
    },
};
use sqlx::{Connection, PgConnection, Postgres, Transaction};

/// An enabled `oidc_discovery` entry.
const DISCOVERY: &str = "https://issuer.example/.well-known/openid-configuration";
/// A second enabled `oidc_discovery` entry.
const DISCOVERY_2: &str = "https://issuer2.example/.well-known/openid-configuration";
/// A disabled `oidc_discovery` entry.
const DISCOVERY_OFF: &str = "https://disabled.example/.well-known/openid-configuration";
/// Only an enabled `jwks` entry has this value.
const JWKS_ONLY: &str = "https://jwks-only.example/.well-known/openid-configuration";
/// Only an enabled `token_review` entry has this value.
const TOKEN_REVIEW_ONLY: &str = "https://tr-only.example/.well-known/openid-configuration";
/// An enabled `token_review` entry.
const TOKEN_REVIEW: &str = "https://k3s.internal.example:6443/";
/// A second enabled `token_review` entry.
const TOKEN_REVIEW_2: &str = "https://k3s-2.internal.example:6443/";
/// A disabled `token_review` entry.
const TOKEN_REVIEW_OFF: &str = "https://k3s-off.internal.example:6443/";
/// Only an enabled `oidc_discovery` entry has this value.
const DISCOVERY_ONLY: &str = "https://k3s-disc.internal.example:6443/";
/// Only an enabled `jwks` entry has this value.
const JWKS_ONLY_TR: &str = "https://k3s-jwks.internal.example:6443/";
/// No entry has this canonical value.
const UNLISTED: &str = "https://unlisted.example/x";

/// Malformed or non-canonical destinations, each of them an enabled entry of
/// both purposes, so only the syntax check refuses them: what each one lacks.
const MALFORMED: [(&str, &str); 27] = [
    (
        "http",
        "http://issuer.example/.well-known/openid-configuration",
    ),
    (
        "upper-case scheme",
        "HTTPS://issuer.example/.well-known/openid-configuration",
    ),
    (
        "no slashes",
        "https:issuer.example/.well-known/openid-configuration",
    ),
    ("no host", "https:///.well-known/openid-configuration"),
    ("userinfo", "https://user@issuer.example/x"),
    ("user and password", "https://user:pw@issuer.example/x"),
    ("empty userinfo", "https://@issuer.example/x"),
    ("fragment", "https://issuer.example/x#frag"),
    ("empty fragment", "https://issuer.example/x#"),
    ("no path", "https://issuer.example"),
    ("query without a path", "https://issuer.example?x=1"),
    (
        "upper-case host",
        "https://ISSUER.example/.well-known/openid-configuration",
    ),
    (
        "default port",
        "https://issuer.example:443/.well-known/openid-configuration",
    ),
    ("port without a path", "https://k3s.internal.example:6443"),
    ("encoded host letter", "https://%69ssuer.example/x"),
    (
        "encoded path character",
        "https://issuer.example/.well-known/openid%2Dconfiguration",
    ),
    ("short IPv4", "https://127.1/x"),
    ("uncompressed IPv6", "https://[0:0:0:0:0:0:0:1]/x"),
    ("dot segment", "https://issuer.example/a/../x"),
    ("backslash", "https://issuer.example\\x"),
    ("U-label", "https://bücher.example/x"),
    ("ideographic dot", "https://issuer。example/x"),
    ("bare % in path", "https://issuer.example/a%b"),
    ("trailing % in path", "https://issuer.example/a%"),
    ("non-hex escape in path", "https://issuer.example/a%zz/b"),
    (
        "incomplete escape in query",
        "https://issuer.example/x?a=%4",
    ),
    ("trailing % in query", "https://issuer.example/x?a=%"),
];

/// A time with sub-microsecond digits, so a write truncates it.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(1_790_000_000_123_456_789)
}

fn audit(event_id: &str) -> SourceAudit<'_> {
    SourceAudit {
        event_id,
        now: now(),
    }
}

/// An `oidc_discovery` source of `ten_a` named after its ID.
fn oidc(id: &str, discovery_url: &str) -> NewTrustSource {
    NewTrustSource {
        id: id.into(),
        tenant_id: "ten_a".into(),
        name: format!("source-{id}"),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: "https://issuer.example".into(),
        discovery_url: Some(discovery_url.into()),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: vec!["https://identity.example.com".into()],
        algorithms: Some(vec!["RS256".into()]),
        proof_bounds: JsonObject::new(),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    }
}

/// A `kubernetes_token_review` source of `ten_a`, with its own cluster.
fn k8s(id: &str, endpoint: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::KubernetesTokenReview,
        exact_issuer: "https://kubernetes.default.svc".into(),
        discovery_url: None,
        cluster_id: Some(format!("cluster_{id}")),
        token_review_endpoint: Some(endpoint.into()),
        ca_bundle_ref: Some("ca_k3s".into()),
        ca_fingerprint: Some("sha256:ca".into()),
        reviewer_credential_ref: Some("reviewer_k3s".into()),
        review_timeout_ms: Some(5000),
        algorithms: None,
        assertion_profile: AssertionProfile::ProjectedServiceAccount,
        replay_mode: ReplayMode::Reusable,
        ..oidc(id, DISCOVERY)
    }
}

/// An `uploaded_jwks` source of `ten_a` on the keyset `ks_1`: no egress
/// destination.
fn uploaded(id: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::UploadedJwks,
        discovery_url: None,
        jwks_keyset_id: Some("ks_1".into()),
        algorithms: Some(vec!["ES256".into()]),
        assertion_profile: AssertionProfile::ReusableJwt,
        replay_mode: ReplayMode::Reusable,
        ..oidc(id, DISCOVERY)
    }
}

/// The mutable columns of `source`, unchanged.
fn changes(source: &TrustSource) -> TrustSourceChanges {
    TrustSourceChanges {
        name: source.name.clone(),
        exact_issuer: source.exact_issuer.clone(),
        discovery_url: source.discovery_url.clone(),
        token_review_endpoint: source.token_review_endpoint.clone(),
        ca_bundle_ref: source.ca_bundle_ref.clone(),
        ca_fingerprint: source.ca_fingerprint.clone(),
        reviewer_credential_ref: source.reviewer_credential_ref.clone(),
        review_timeout_ms: source.review_timeout_ms,
        audiences: source.audiences.clone(),
        algorithms: source.algorithms.clone(),
        proof_bounds: source.proof_bounds.clone(),
        assertion_profile: source.assertion_profile,
        stale_revocation_acknowledged: source.stale_revocation_acknowledged,
        replay_mode: source.replay_mode,
        status: source.status,
    }
}

async fn operator(pool: &PgPool, admin: &str, role: AdminRole, tenant_id: Option<&str>) {
    registry::create_admin_identity(
        pool,
        &NewAdminIdentity {
            id: admin.into(),
            status: Status::Enabled,
            created_at: now(),
        },
    )
    .await
    .unwrap();
    registry::create_admin_credential(
        pool,
        &NewAdminCredential {
            id: format!("crd_{admin}"),
            admin_id: admin.into(),
            public_identity: format!("key_{admin}"),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: format!("rb_{admin}"),
            admin_id: admin.into(),
            role,
            tenant_id: tenant_id.map(Into::into),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// The key of the `trust_admin` of `ten_a`.
const TRUST: &str = "key_adm_trust";
/// The key of the `trust_admin` of `ten_b`.
const TRUST_B: &str = "key_adm_trust_b";

async fn entry(pool: &PgPool, id: &str, purpose: &str, destination: &str, status: &str) {
    sqlx::query(
        "INSERT INTO egress_allowlist_entry (id, purpose, exact_destination, status) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(purpose)
    .bind(destination)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
}

/// Tenants `ten_a` and `ten_b`; keyset `ks_1` of `ten_a`; operators, each
/// with the key `key_<id>`: `adm_trust` (`trust_admin` of `ten_a`),
/// `adm_trust_b` (`trust_admin` of `ten_b`), `adm_sec` (instance
/// `security_admin`), `adm_client` (`client_admin` of `ten_a`) and
/// `adm_audt` (`auditor` of `ten_a`); and the egress entries of the
/// constants above, with every [`MALFORMED`] value enabled for both
/// purposes.
async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    for tenant in ["ten_a", "ten_b"] {
        registry::create_tenant(
            &pool,
            &NewTenant {
                id: tenant.into(),
                name: format!("Tenant {tenant}"),
                secret_namespace: format!("ns_{tenant}"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    registry::create_trust_keyset(
        &pool,
        &NewTrustKeyset {
            id: "ks_1".into(),
            tenant_id: "ten_a".into(),
            name: "keyset-1".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    for (admin, role, tenant) in [
        ("adm_trust", AdminRole::TrustAdmin, Some("ten_a")),
        ("adm_trust_b", AdminRole::TrustAdmin, Some("ten_b")),
        ("adm_sec", AdminRole::SecurityAdmin, None),
        ("adm_client", AdminRole::ClientAdmin, Some("ten_a")),
        ("adm_audt", AdminRole::Auditor, Some("ten_a")),
    ] {
        operator(&pool, admin, role, tenant).await;
    }
    for (id, purpose, destination, status) in [
        ("egr_disc", "oidc_discovery", DISCOVERY, "enabled"),
        ("egr_disc_2", "oidc_discovery", DISCOVERY_2, "enabled"),
        ("egr_disc_off", "oidc_discovery", DISCOVERY_OFF, "disabled"),
        ("egr_jwks", "jwks", JWKS_ONLY, "enabled"),
        ("egr_tr_only", "token_review", TOKEN_REVIEW_ONLY, "enabled"),
        ("egr_tr", "token_review", TOKEN_REVIEW, "enabled"),
        ("egr_tr_2", "token_review", TOKEN_REVIEW_2, "enabled"),
        ("egr_tr_off", "token_review", TOKEN_REVIEW_OFF, "disabled"),
        ("egr_disc_only", "oidc_discovery", DISCOVERY_ONLY, "enabled"),
        ("egr_jwks_tr", "jwks", JWKS_ONLY_TR, "enabled"),
    ] {
        entry(&pool, id, purpose, destination, status).await;
    }
    for (n, (_, destination)) in MALFORMED.into_iter().enumerate() {
        entry(
            &pool,
            &format!("egr_bad_d{n}"),
            "oidc_discovery",
            destination,
            "enabled",
        )
        .await;
        entry(
            &pool,
            &format!("egr_bad_t{n}"),
            "token_review",
            destination,
            "enabled",
        )
        .await;
    }
    (db, pool)
}

/// [`create_source`] in its own transaction, committed on `Ok` and rolled
/// back on `Err`.
async fn create(
    pool: &PgPool,
    key: &str,
    new: &NewTrustSource,
    event_id: &str,
) -> Result<TrustSource, SourceWriteError> {
    let mut tx = pool.begin().await.unwrap();
    let result = create_source(&mut tx, key, new, &audit(event_id)).await;
    finish(tx, &result).await;
    result
}

/// [`update_source`] of a `ten_a` source in its own transaction, committed
/// on `Ok` and rolled back on `Err`.
async fn update(
    pool: &PgPool,
    key: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustSourceChanges,
    event_id: &str,
) -> Result<TrustSource, SourceWriteError> {
    let mut tx = pool.begin().await.unwrap();
    let result = update_source(
        &mut tx,
        key,
        "ten_a",
        id,
        expected_revision,
        changes,
        &audit(event_id),
    )
    .await;
    finish(tx, &result).await;
    result
}

/// Commits on `Ok`; on `Err` first shows that the transaction is still
/// usable (the function rolled its savepoint back), then rolls back.
async fn finish<T>(mut tx: Transaction<'_, Postgres>, result: &Result<T, SourceWriteError>) {
    if result.is_ok() {
        tx.commit().await.unwrap();
    } else {
        sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
}

/// Neither the error's `Display` nor its `Debug` contains `value` or any
/// host of these tests.
fn assert_redacted(err: &SourceWriteError, value: &str) {
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(value.is_empty() || !text.contains(value), "{text}");
        assert!(!text.contains("example"), "{text}");
    }
}

#[track_caller]
fn assert_egress<T: std::fmt::Debug>(
    result: Result<T, SourceWriteError>,
    member: &str,
    value: &str,
) {
    match result {
        Err(err @ SourceWriteError::EgressNotAllowed { member: m }) if m == member => {
            assert_redacted(&err, value);
        }
        other => panic!("{member} {value}: expected EgressNotAllowed, got {other:?}"),
    }
}

#[track_caller]
fn assert_invalid<T: std::fmt::Debug>(
    result: Result<T, SourceWriteError>,
    member: &str,
    value: &str,
) {
    match result {
        Err(err @ SourceWriteError::InvalidDestination { member: m }) if m == member => {
            assert_redacted(&err, value);
        }
        other => panic!("{member} {value}: expected InvalidDestination, got {other:?}"),
    }
}

#[track_caller]
fn assert_unauthorized<T: std::fmt::Debug>(result: Result<T, SourceWriteError>, case: &str) {
    match result {
        Err(err @ SourceWriteError::Unauthorized) => {
            assert_eq!(
                err.to_string(),
                "the operator may not write this tenant's trust sources",
                "{case}"
            );
            assert_eq!(format!("{err:?}"), "Unauthorized", "{case}");
        }
        other => panic!("{case}: expected Unauthorized, got {other:?}"),
    }
}

#[track_caller]
fn assert_registry<T: std::fmt::Debug>(
    result: Result<T, SourceWriteError>,
    expected: fn(&RegistryError) -> bool,
    case: &str,
) {
    match result {
        Err(SourceWriteError::Registry(err)) if expected(&err) => {}
        other => panic!("{case}: got {other:?}"),
    }
}

/// The audit events as `(sequence, action, object_id, tenant_id, actor,
/// previous_revision, new_revision)`.
type EventRow = (
    i64,
    String,
    String,
    Option<String>,
    String,
    Option<i64>,
    Option<i64>,
);

async fn events(pool: &PgPool) -> Vec<EventRow> {
    sqlx::query_as(
        "SELECT sequence, action, object_id, tenant_id, actor, previous_revision, new_revision \
         FROM audit_event ORDER BY sequence",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn assert_chain(pool: &PgPool, last_sequence: i64) {
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        registry::verify_audit_chain(&mut conn).await.unwrap(),
        ChainVerdict::Intact { last_sequence }
    );
}

async fn source_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM trust_source")
        .fetch_one(pool)
        .await
        .unwrap()
}

const DISABLE_ENTRY: &str = "UPDATE egress_allowlist_entry \
     SET status = 'disabled', revision = revision + 1 WHERE id = $1";

async fn disable_entry(pool: &PgPool, id: &str) {
    let done = sqlx::query(DISABLE_ENTRY)
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(done.rows_affected(), 1);
}

fn operator_actor(admin: &str) -> String {
    AuditActor::Operator(admin.into()).canonical_json()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_source_with_an_enabled_matching_entry_is_created_and_audited() {
    let (db, pool) = seeded().await;
    let created = [
        create(&pool, TRUST, &oidc("src_oidc", DISCOVERY), "aud_1").await,
        create(&pool, TRUST, &k8s("src_k8s", TOKEN_REVIEW), "aud_2").await,
        // No destination, so nothing to check.
        create(&pool, TRUST, &uploaded("src_up"), "aud_3").await,
    ];
    for (source, (id, discovery, token_review)) in created.into_iter().zip([
        ("src_oidc", Some(DISCOVERY), None),
        ("src_k8s", None, Some(TOKEN_REVIEW)),
        ("src_up", None, None),
    ]) {
        let source = source.unwrap();
        assert_eq!(
            (
                &source.id[..],
                source.discovery_url.as_deref(),
                source.token_review_endpoint.as_deref(),
                source.revision
            ),
            (id, discovery, token_review, 1)
        );
        assert_eq!(
            registry::get_trust_source(&pool, "ten_a", id)
                .await
                .unwrap(),
            source
        );
    }
    let actor = operator_actor("adm_trust");
    assert_eq!(
        events(&pool).await,
        [(1, "src_oidc"), (2, "src_k8s"), (3, "src_up")].map(|(sequence, id)| (
            sequence,
            "trust_source.create".to_string(),
            id.to_string(),
            Some("ten_a".to_string()),
            actor.clone(),
            None,
            Some(1)
        ))
    );
    assert_chain(&pool, 3).await;

    // Another tenant's trust_admin writes that tenant's sources.
    let mut other = oidc("src_b", DISCOVERY);
    other.tenant_id = "ten_b".into();
    assert_eq!(
        create(&pool, TRUST_B, &other, "aud_4")
            .await
            .unwrap()
            .tenant_id,
        "ten_b"
    );
    // Two sources may use one entry.
    create(&pool, TRUST, &oidc("src_oidc_2", DISCOVERY), "aud_5")
        .await
        .unwrap();
    assert_chain(&pool, 5).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_destination_without_an_enabled_entry_of_its_purpose_is_refused() {
    let (db, pool) = seeded().await;
    for value in [
        // No entry.
        "https://unlisted.example/.well-known/openid-configuration",
        // A disabled entry.
        DISCOVERY_OFF,
        // Only an entry of another purpose.
        JWKS_ONLY,
        TOKEN_REVIEW_ONLY,
    ] {
        let result = create(&pool, TRUST, &oidc("src_1", value), "aud_1").await;
        assert_egress(result, DISCOVERY_URL, value);
    }
    for value in [
        "https://unlisted.example:6443/",
        TOKEN_REVIEW_OFF,
        DISCOVERY_ONLY,
        JWKS_ONLY_TR,
    ] {
        let result = create(&pool, TRUST, &k8s("src_1", value), "aud_1").await;
        assert_egress(result, TOKEN_REVIEW_ENDPOINT, value);
    }
    // Nothing was written, and no event appended.
    assert_eq!(source_count(&pool).await, 0);
    assert!(events(&pool).await.is_empty());
    assert_chain(&pool, 0).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_near_miss_of_an_entry_is_refused() {
    let (db, pool) = seeded().await;
    // Canonical, and matching no entry.
    for value in [
        // Longer than the entry: the entry is a prefix.
        "https://issuer.example/.well-known/openid-configuration/",
        "https://issuer.example/.well-known/openid-configuration?x=1",
        // Shorter: a prefix of the entry.
        "https://issuer.example/.well-known/",
        // Path case.
        "https://issuer.example/.well-known/OpenID-configuration",
        // Another port.
        "https://issuer.example:8443/.well-known/openid-configuration",
        // Spellings the parser keeps.
        "https://issuer.example./.well-known/openid-configuration",
        "https://issuer.example//.well-known/openid-configuration",
        // An encoded reserved character.
        "https://issuer.example/.well-known%2Fopenid-configuration",
    ] {
        let result = create(&pool, TRUST, &oidc("src_1", value), "aud_1").await;
        assert_egress(result, DISCOVERY_URL, value);
    }
    for value in [
        "https://k3s.internal.example:6443/x",
        "https://k3s.internal.example:6443//",
        "https://k3s.internal.example:6444/",
        "https://k3s.internal.example/",
    ] {
        let result = create(&pool, TRUST, &k8s("src_1", value), "aud_1").await;
        assert_egress(result, TOKEN_REVIEW_ENDPOINT, value);
    }
    // Not canonical: refused by the syntax check, before the entry lookup,
    // even where the parser would fetch the entry's own URL.
    for value in [
        "https://ISSUER.example/.well-known/openid-configuration",
        "https://Issuer.Example/.well-known/openid-configuration",
        "https://issuer.example:443/.well-known/openid-configuration",
        "https://issuer.example/.well-known/openid%2Dconfiguration",
        "https://issuer.example/x/../.well-known/openid-configuration",
        "https://%69ssuer.example/.well-known/openid-configuration",
    ] {
        let result = create(&pool, TRUST, &oidc("src_1", value), "aud_1").await;
        assert_invalid(result, DISCOVERY_URL, value);
    }
    for value in [
        "https://K3S.internal.example:6443/",
        "https://k3s.internal.example:6443",
        "https://k3s.internal.example:06443/",
    ] {
        let result = create(&pool, TRUST, &k8s("src_1", value), "aud_1").await;
        assert_invalid(result, TOKEN_REVIEW_ENDPOINT, value);
    }
    assert_eq!(source_count(&pool).await, 0);
    db.drop([pool]).await;
}

/// The `0011` guard (provisional lead pick, 2026-11-22) backs the bare
/// registry writers: a destination this path refuses with
/// `EgressNotAllowed`, its own refusal, which comes first, the database
/// refuses for them with `Invariant { Check }` naming the member's guard,
/// on create and on a changed member, a disable included. It checks no
/// syntax: a malformed destination that an enabled entry lists, which this
/// path refuses with `InvalidDestination`, passes it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_database_guard_refuses_what_the_bare_writers_skip() {
    let (db, pool) = seeded().await;
    let guard = |member: &str| match member {
        DISCOVERY_URL => "trust_source_discovery_url_egress_enabled",
        _ => "trust_source_token_review_endpoint_egress_enabled",
    };
    let assert_guard = |result: Result<TrustSource, RegistryError>, member: &str| match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::Check,
            constraint: Some(constraint),
        }) if constraint == guard(member) => {}
        other => panic!("{member}: expected the guard's Invariant, got {other:?}"),
    };
    let base_oidc = registry::create_trust_source(&pool, &oidc("src_base_o", DISCOVERY))
        .await
        .unwrap();
    let base_k8s = registry::create_trust_source(&pool, &k8s("src_base_k", TOKEN_REVIEW))
        .await
        .unwrap();
    for (member, value) in [
        (DISCOVERY_URL, DISCOVERY_OFF),
        (DISCOVERY_URL, JWKS_ONLY),
        (DISCOVERY_URL, TOKEN_REVIEW_ONLY),
        (DISCOVERY_URL, UNLISTED),
        (TOKEN_REVIEW_ENDPOINT, TOKEN_REVIEW_OFF),
        (TOKEN_REVIEW_ENDPOINT, DISCOVERY_ONLY),
        (TOKEN_REVIEW_ENDPOINT, JWKS_ONLY_TR),
        (TOKEN_REVIEW_ENDPOINT, UNLISTED),
    ] {
        let (new, base, mut changed) = if member == DISCOVERY_URL {
            let mut changed = changes(&base_oidc);
            changed.discovery_url = Some(value.into());
            (oidc("src_1", value), "src_base_o", changed)
        } else {
            let mut changed = changes(&base_k8s);
            changed.token_review_endpoint = Some(value.into());
            (k8s("src_1", value), "src_base_k", changed)
        };
        assert_egress(create(&pool, TRUST, &new, "aud_1").await, member, value);
        assert_egress(
            update(&pool, TRUST, base, 1, &changed, "aud_1").await,
            member,
            value,
        );
        assert_guard(registry::create_trust_source(&pool, &new).await, member);
        assert_guard(
            registry::update_trust_source(&pool, "ten_a", base, 1, &changed).await,
            member,
        );
        changed.status = Status::Disabled;
        assert_guard(
            registry::update_trust_source(&pool, "ten_a", base, 1, &changed).await,
            member,
        );
    }
    for (n, (_, value)) in MALFORMED.into_iter().enumerate() {
        let id = format!("src_bad_{n}");
        assert_invalid(
            create(&pool, TRUST, &oidc(&id, value), "aud_1").await,
            DISCOVERY_URL,
            value,
        );
        registry::create_trust_source(&pool, &oidc(&id, value))
            .await
            .unwrap_or_else(|err| panic!("{value}: {err:?}"));
    }
    assert_eq!(
        source_count(&pool).await,
        2 + i64::try_from(MALFORMED.len()).unwrap()
    );
    assert!(events(&pool).await.is_empty());
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_malformed_destination_is_refused_before_any_statement() {
    let (db, pool) = seeded().await;
    for (case, value) in MALFORMED {
        for (member, new) in [
            (DISCOVERY_URL, oidc("src_1", value)),
            (TOKEN_REVIEW_ENDPOINT, k8s("src_1", value)),
        ] {
            // Refused although an enabled entry of the purpose has it.
            let result = create(&pool, TRUST, &new, "aud_1").await;
            assert!(result.is_err(), "{case}");
            assert_invalid(result, member, value);
            // Before any statement: an aborted transaction would fail the
            // first one with 25P02.
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT 1 / 0")
                .execute(&mut *tx)
                .await
                .expect_err("division by zero");
            let result = create_source(&mut tx, TRUST, &new, &audit("aud_1")).await;
            assert_invalid(result, member, value);
            tx.rollback().await.unwrap();
        }
    }
    // A well-formed one in an aborted transaction reaches the database.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 / 0")
        .execute(&mut *tx)
        .await
        .expect_err("division by zero");
    let result = create_source(&mut tx, TRUST, &oidc("src_1", DISCOVERY), &audit("aud_1")).await;
    assert!(
        matches!(
            &result,
            Err(SourceWriteError::Registry(RegistryError::Other(_)))
        ),
        "{result:?}"
    );
    tx.rollback().await.unwrap();
    assert_eq!(source_count(&pool).await, 0);
    assert!(events(&pool).await.is_empty());
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn only_a_trust_admin_of_the_tenant_may_write() {
    let (db, pool) = seeded().await;
    let refused = [
        ("another tenant's trust_admin", TRUST_B),
        ("an instance security_admin", "key_adm_sec"),
        ("a client_admin of the tenant", "key_adm_client"),
        ("an auditor of the tenant", "key_adm_audt"),
        ("an unknown key", "key_unknown"),
        ("an empty key", ""),
    ];
    for (case, key) in refused {
        assert_unauthorized(
            create(&pool, key, &oidc("src_1", DISCOVERY), "aud_1").await,
            case,
        );
        // Authorization comes before the egress check: an unlisted
        // destination is the same refusal, so nothing is learned about the
        // allowlist.
        assert_unauthorized(
            create(&pool, key, &oidc("src_1", UNLISTED), "aud_1").await,
            case,
        );
        assert_unauthorized(
            create(&pool, key, &k8s("src_1", UNLISTED), "aud_1").await,
            case,
        );
    }
    // The scope is the source's tenant.
    let mut other = oidc("src_b", DISCOVERY);
    other.tenant_id = "ten_b".into();
    assert_unauthorized(create(&pool, TRUST, &other, "aud_1").await, "ten_b");
    assert_eq!(source_count(&pool).await, 0);

    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY), "aud_1")
        .await
        .unwrap();
    let mut renamed = changes(&source);
    renamed.name = "renamed".into();
    let mut unlisted = changes(&source);
    unlisted.discovery_url = Some(UNLISTED.into());
    for (case, key) in refused {
        assert_unauthorized(
            update(&pool, key, "src_1", 1, &renamed, "aud_2").await,
            case,
        );
        assert_unauthorized(
            update(&pool, key, "src_1", 1, &unlisted, "aud_2").await,
            case,
        );
        // A missing source is the same refusal: nothing is learned.
        assert_unauthorized(
            update(&pool, key, "src_missing", 1, &renamed, "aud_2").await,
            case,
        );
    }
    // Another tenant's trust_admin, in its own tenant, does not find it,
    // at any revision: a stale one would tell that it exists.
    for revision in [1, 99] {
        let mut tx = pool.begin().await.unwrap();
        let result = update_source(
            &mut tx,
            TRUST_B,
            "ten_b",
            "src_1",
            revision,
            &unlisted,
            &audit("aud_2"),
        )
        .await;
        finish(tx, &result).await;
        assert_registry(
            result,
            |err| matches!(err, RegistryError::NotFound),
            "ten_b",
        );
    }
    assert_eq!(
        registry::get_trust_source(&pool, "ten_a", "src_1")
            .await
            .unwrap(),
        source
    );
    assert_eq!(events(&pool).await.len(), 1);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_update_rechecks_only_a_changed_destination() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_oidc", DISCOVERY), "aud_1")
        .await
        .unwrap();
    disable_entry(&pool, "egr_disc").await;

    // Unchanged: not checked again, whatever else changes.
    let mut next = changes(&source);
    next.name = "renamed".into();
    let source = update(&pool, TRUST, "src_oidc", 1, &next, "aud_2")
        .await
        .unwrap();
    assert_eq!((source.revision, &source.name[..]), (2, "renamed"));
    next.status = Status::Disabled;
    let source = update(&pool, TRUST, "src_oidc", 2, &next, "aud_3")
        .await
        .unwrap();
    assert_eq!((source.revision, source.status), (3, Status::Disabled));
    next.status = Status::Enabled;
    let source = update(&pool, TRUST, "src_oidc", 3, &next, "aud_4")
        .await
        .unwrap();
    assert_eq!(source.revision, 4);

    // Changed: checked, and refused without an enabled entry.
    for value in [DISCOVERY_OFF, JWKS_ONLY, "https://unlisted.example/x"] {
        let mut changed = changes(&source);
        changed.discovery_url = Some(value.into());
        assert_egress(
            update(&pool, TRUST, "src_oidc", 4, &changed, "aud_5").await,
            DISCOVERY_URL,
            value,
        );
        // A disable that also changes it is checked too.
        changed.status = Status::Disabled;
        assert_egress(
            update(&pool, TRUST, "src_oidc", 4, &changed, "aud_5").await,
            DISCOVERY_URL,
            value,
        );
    }
    for (_, value) in MALFORMED {
        let mut changed = changes(&source);
        changed.discovery_url = Some(value.into());
        assert_invalid(
            update(&pool, TRUST, "src_oidc", 4, &changed, "aud_5").await,
            DISCOVERY_URL,
            value,
        );
    }
    let mut changed = changes(&source);
    changed.discovery_url = Some(DISCOVERY_2.into());
    let source = update(&pool, TRUST, "src_oidc", 4, &changed, "aud_5")
        .await
        .unwrap();
    assert_eq!(
        (source.revision, source.discovery_url.as_deref()),
        (5, Some(DISCOVERY_2))
    );
    // Back to the disabled entry is a change too.
    let mut back = changes(&source);
    back.discovery_url = Some(DISCOVERY.into());
    assert_egress(
        update(&pool, TRUST, "src_oidc", 5, &back, "aud_6").await,
        DISCOVERY_URL,
        DISCOVERY,
    );

    // The same for a TokenReview endpoint.
    let k8s_source = create(&pool, TRUST, &k8s("src_k8s", TOKEN_REVIEW), "aud_6")
        .await
        .unwrap();
    disable_entry(&pool, "egr_tr").await;
    let mut next = changes(&k8s_source);
    next.review_timeout_ms = Some(3000);
    let k8s_source = update(&pool, TRUST, "src_k8s", 1, &next, "aud_7")
        .await
        .unwrap();
    assert_eq!(k8s_source.revision, 2);
    for value in [TOKEN_REVIEW_OFF, DISCOVERY_ONLY, JWKS_ONLY_TR] {
        let mut changed = changes(&k8s_source);
        changed.token_review_endpoint = Some(value.into());
        assert_egress(
            update(&pool, TRUST, "src_k8s", 2, &changed, "aud_8").await,
            TOKEN_REVIEW_ENDPOINT,
            value,
        );
    }
    let mut changed = changes(&k8s_source);
    changed.token_review_endpoint = Some(TOKEN_REVIEW_2.into());
    assert_eq!(
        update(&pool, TRUST, "src_k8s", 2, &changed, "aud_8")
            .await
            .unwrap()
            .revision,
        3
    );

    // A stored value written by other means (the bare registry writer, past
    // the syntax rule, while the `0011` guard found its entry enabled) is not
    // checked while it stays, also once its entry is disabled.
    entry(
        &pool,
        "egr_legacy",
        "oidc_discovery",
        "https://legacy",
        "enabled",
    )
    .await;
    let legacy = registry::create_trust_source(&pool, &oidc("src_legacy", "https://legacy"))
        .await
        .unwrap();
    disable_entry(&pool, "egr_legacy").await;
    let mut next = changes(&legacy);
    next.name = "legacy-renamed".into();
    assert_eq!(
        update(&pool, TRUST, "src_legacy", 1, &next, "aud_9")
            .await
            .unwrap()
            .revision,
        2
    );

    // The registry's own outcomes, before any destination is checked: a
    // stale write that would also be refused for its destination is stale.
    for value in [DISCOVERY, MALFORMED[0].1] {
        let mut stale = changes(&source);
        stale.discovery_url = Some(value.into());
        assert_registry(
            update(&pool, TRUST, "src_oidc", 4, &stale, "aud_10").await,
            |err| matches!(err, RegistryError::StaleRevision),
            "stale",
        );
    }
    assert_registry(
        update(&pool, TRUST, "src_missing", 1, &changes(&source), "aud_10").await,
        |err| matches!(err, RegistryError::NotFound),
        "missing",
    );

    let actor = operator_actor("adm_trust");
    let events = events(&pool).await;
    let updates: Vec<_> = events
        .iter()
        .filter(|event| event.1 == "trust_source.update")
        .map(|event| (&event.2[..], event.5, event.6))
        .collect();
    assert_eq!(
        updates,
        [
            ("src_oidc", Some(1), Some(2)),
            ("src_oidc", Some(2), Some(3)),
            ("src_oidc", Some(3), Some(4)),
            ("src_oidc", Some(4), Some(5)),
            ("src_k8s", Some(1), Some(2)),
            ("src_k8s", Some(2), Some(3)),
            ("src_legacy", Some(1), Some(2)),
        ]
    );
    assert!(events.iter().all(|event| event.4 == actor));
    assert_eq!(events.len(), 9);
    assert_chain(&pool, 9).await;
    db.drop([pool]).await;
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// Waits until the backend `blocked`, which runs `task`, waits for a lock
/// held by `holder`. Fails at once if `task` finished without waiting.
async fn wait_until_blocked<T>(
    pool: &PgPool,
    blocked: i32,
    holder: i32,
    task: &tokio::task::JoinHandle<T>,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                .bind(holder)
                .bind(blocked)
                .fetch_one(pool)
                .await
                .unwrap();
            if waiting {
                return;
            }
            assert!(!task.is_finished(), "finished without waiting for the lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("never waited for the lock");
}

async fn join<T>(task: tokio::task::JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the task never finished")
        .unwrap()
}

/// The SQLSTATE of a raw statement's error.
fn sqlstate(err: &sqlx::Error) -> Option<String> {
    err.as_database_error()
        .and_then(|err| err.code())
        .map(|code| code.into_owned())
}

/// The writes of [`a_write_holding_an_entry_makes_its_disable_wait`].
#[derive(Debug, Clone, Copy)]
enum Write {
    CreateOidc,
    CreateK8s,
    Update,
}

/// A write that checked an entry holds it `FOR SHARE` until it commits: a
/// disable of the entry times out with `55P03` while the write is open,
/// waits for it, and then applies; later writes are refused.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_write_holding_an_entry_makes_its_disable_wait() {
    let (db, pool) = seeded().await;
    let base = create(&pool, TRUST, &oidc("src_base", DISCOVERY_2), "aud_0")
        .await
        .unwrap();
    for (n, (write, entry_id)) in [
        (Write::CreateOidc, "egr_disc"),
        (Write::CreateK8s, "egr_tr"),
        (Write::Update, "egr_disc_only"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut holder = pool.acquire().await.unwrap().detach();
        let mut writer = pool.acquire().await.unwrap().detach();
        let (holder_pid, writer_pid) = (
            backend_pid(&mut holder).await,
            backend_pid(&mut writer).await,
        );
        let mut tx = holder.begin().await.unwrap();
        let event_id = format!("aud_{}", n + 1);
        let id = format!("src_{n}");
        match write {
            Write::CreateOidc => {
                create_source(&mut tx, TRUST, &oidc(&id, DISCOVERY), &audit(&event_id))
                    .await
                    .unwrap();
            }
            Write::CreateK8s => {
                create_source(&mut tx, TRUST, &k8s(&id, TOKEN_REVIEW), &audit(&event_id))
                    .await
                    .unwrap();
            }
            Write::Update => {
                // Changes the base source to the entry's value.
                let mut changed = changes(&base);
                changed.discovery_url = Some(DISCOVERY_ONLY.into());
                update_source(
                    &mut tx,
                    TRUST,
                    "ten_a",
                    "src_base",
                    1,
                    &changed,
                    &audit(&event_id),
                )
                .await
                .unwrap();
            }
        }
        sqlx::query("SET lock_timeout = '100ms'")
            .execute(&mut writer)
            .await
            .unwrap();
        let err = sqlx::query(DISABLE_ENTRY)
            .bind(entry_id)
            .execute(&mut writer)
            .await
            .expect_err("the disable must wait for the write");
        assert_eq!(sqlstate(&err).as_deref(), Some("55P03"), "{entry_id}");
        sqlx::query("SET lock_timeout = 0")
            .execute(&mut writer)
            .await
            .unwrap();
        let target = entry_id.to_string();
        let task = tokio::spawn(async move {
            let done = sqlx::query(DISABLE_ENTRY)
                .bind(&target)
                .execute(&mut writer)
                .await
                .unwrap();
            (done.rows_affected(), writer)
        });
        wait_until_blocked(&pool, writer_pid, holder_pid, &task).await;
        tx.commit().await.unwrap();
        let (rows, writer) = join(task).await;
        assert_eq!(rows, 1, "{entry_id}");
        writer.close().await.unwrap();
        holder.close().await.unwrap();
        let entry = registry::get_egress_allowlist_entry(&pool, entry_id)
            .await
            .unwrap();
        assert_eq!((entry.status, entry.revision), (Status::Disabled, 2));
    }
    // The writes committed; a new one through a disabled entry is refused.
    assert_eq!(source_count(&pool).await, 3);
    assert_egress(
        create(&pool, TRUST, &oidc("src_late", DISCOVERY), "aud_9").await,
        DISCOVERY_URL,
        DISCOVERY,
    );
    assert_egress(
        create(&pool, TRUST, &k8s("src_late", TOKEN_REVIEW), "aud_9").await,
        TOKEN_REVIEW_ENDPOINT,
        TOKEN_REVIEW,
    );
    assert_chain(&pool, 4).await;
    db.drop([pool]).await;
}

/// A write that reaches the entry while a disable holds it waits, and once
/// the disable commits, reads the disabled row and is refused.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_disable_committed_first_refuses_the_write() {
    let (db, pool) = seeded().await;
    for (entry_id, member, new) in [
        ("egr_disc", DISCOVERY_URL, oidc("src_1", DISCOVERY)),
        ("egr_tr", TOKEN_REVIEW_ENDPOINT, k8s("src_1", TOKEN_REVIEW)),
    ] {
        let mut disabler = pool.acquire().await.unwrap().detach();
        let mut writer = pool.acquire().await.unwrap().detach();
        let (disabler_pid, writer_pid) = (
            backend_pid(&mut disabler).await,
            backend_pid(&mut writer).await,
        );
        let mut disable = disabler.begin().await.unwrap();
        sqlx::query(DISABLE_ENTRY)
            .bind(entry_id)
            .execute(&mut *disable)
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            let mut tx = writer.begin().await.unwrap();
            let result = create_source(&mut tx, TRUST, &new, &audit("aud_1")).await;
            tx.rollback().await.unwrap();
            (result, writer)
        });
        wait_until_blocked(&pool, writer_pid, disabler_pid, &task).await;
        disable.commit().await.unwrap();
        let (result, writer) = join(task).await;
        let value = match member {
            DISCOVERY_URL => DISCOVERY,
            _ => TOKEN_REVIEW,
        };
        assert_egress(result, member, value);
        writer.close().await.unwrap();
        disabler.close().await.unwrap();
    }
    assert_eq!(source_count(&pool).await, 0);
    assert!(events(&pool).await.is_empty());
    db.drop([pool]).await;
}

/// The event is appended after the write: while the write waits for a lock
/// (the foreign-key check of its keyset, held `FOR UPDATE` elsewhere), it
/// does not hold the audit head, so another transaction appends meanwhile.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_audit_event_comes_after_the_write() {
    let (db, pool) = seeded().await;
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut writer = pool.acquire().await.unwrap().detach();
    let (holder_pid, writer_pid) = (
        backend_pid(&mut holder).await,
        backend_pid(&mut writer).await,
    );
    let mut hold = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM trust_keyset WHERE id = 'ks_1' FOR UPDATE")
        .execute(&mut *hold)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        let mut tx = writer.begin().await.unwrap();
        let result = create_source(&mut tx, TRUST, &uploaded("src_up"), &audit("aud_w")).await;
        match result {
            Ok(_) => tx.commit().await.unwrap(),
            Err(_) => tx.rollback().await.unwrap(),
        }
        (result, writer)
    });
    wait_until_blocked(&pool, writer_pid, holder_pid, &task).await;
    // The head is free: an append does not wait.
    let mut other = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '1s'")
        .execute(&mut *other)
        .await
        .unwrap();
    registry::append_audit_event(
        &mut other,
        &NewAuditEvent {
            id: "aud_other".into(),
            tenant_id: Some("ten_a".into()),
            timestamp: now(),
            actor: AuditActor::Operator("adm_trust".into()),
            action: "trust_keyset.update".into(),
            object_id: "ks_1".into(),
            previous_revision: Some(1),
            new_revision: Some(2),
            outcome: "success".into(),
        },
    )
    .await
    .expect("the audit head must be free while the write waits");
    other.commit().await.unwrap();
    hold.rollback().await.unwrap();
    let (result, writer) = join(task).await;
    result.unwrap();
    writer.close().await.unwrap();
    holder.close().await.unwrap();
    let events = events(&pool).await;
    assert_eq!(
        events
            .iter()
            .map(|event| (event.0, &event.1[..], &event.2[..]))
            .collect::<Vec<_>>(),
        [
            (1, "trust_keyset.update", "ks_1"),
            (2, "trust_source.create", "src_up"),
        ]
    );
    assert_chain(&pool, 2).await;
    db.drop([pool]).await;
}

/// An audit append that fails after the registry write (here a reused event
/// id) undoes the write: the caller's transaction stays usable and holds
/// neither the new source nor the changed one.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_audit_append_undoes_the_write() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_kept", DISCOVERY), "aud_1")
        .await
        .unwrap();
    let reused = |err: &RegistryError| {
        matches!(
            err,
            RegistryError::AlreadyExists {
                constraint: "audit_event_pkey"
            }
        )
    };

    let mut tx = pool.begin().await.unwrap();
    assert_registry(
        create_source(
            &mut tx,
            TRUST,
            &oidc("src_lost", DISCOVERY),
            &audit("aud_1"),
        )
        .await,
        reused,
        "create",
    );
    let lost: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_source WHERE id = 'src_lost'")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(lost, 0);

    let mut next = changes(&source);
    next.discovery_url = Some(DISCOVERY_2.into());
    assert_registry(
        update_source(
            &mut tx,
            TRUST,
            "ten_a",
            "src_kept",
            1,
            &next,
            &audit("aud_1"),
        )
        .await,
        reused,
        "update",
    );
    let kept: (i64, Option<String>) =
        sqlx::query_as("SELECT revision, discovery_url FROM trust_source WHERE id = 'src_kept'")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(kept, (1, Some(DISCOVERY.into())));
    tx.commit().await.unwrap();

    assert_eq!(source_count(&pool).await, 1);
    assert_eq!(events(&pool).await.len(), 1);
    assert_chain(&pool, 1).await;
    db.drop([pool]).await;
}

/// Step 0 comes before step 1: at a level other than READ COMMITTED, an
/// unknown key gets `UnsupportedIsolation`, not `Unauthorized`, so the
/// isolation is read before the operator is looked up.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_isolation_is_checked_before_the_operator() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY_2), "aud_1")
        .await
        .unwrap();
    let mut changed = changes(&source);
    changed.discovery_url = Some(DISCOVERY.into());
    for write in ["create", "update"] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .unwrap();
        let key = "key_unknown";
        let result = match write {
            "create" => {
                create_source(&mut tx, key, &oidc("src_2", DISCOVERY), &audit("aud_2")).await
            }
            _ => update_source(&mut tx, key, "ten_a", "src_1", 1, &changed, &audit("aud_2")).await,
        };
        assert!(
            matches!(result, Err(SourceWriteError::UnsupportedIsolation)),
            "{write}: {result:?}"
        );
        tx.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn isolation_other_than_read_committed_is_refused_before_any_lock() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY_2), "aud_1")
        .await
        .unwrap();
    let mut changed = changes(&source);
    changed.discovery_url = Some(DISCOVERY.into());
    for level in ["REPEATABLE READ", "SERIALIZABLE", "READ UNCOMMITTED"] {
        for write in ["create", "update"] {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SET TRANSACTION ISOLATION LEVEL {level}"
            )))
            .execute(&mut *tx)
            .await
            .unwrap();
            let result = match write {
                "create" => {
                    create_source(&mut tx, TRUST, &oidc("src_2", DISCOVERY), &audit("aud_2")).await
                }
                _ => {
                    update_source(
                        &mut tx,
                        TRUST,
                        "ten_a",
                        "src_1",
                        1,
                        &changed,
                        &audit("aud_2"),
                    )
                    .await
                }
            };
            match &result {
                Err(err @ SourceWriteError::UnsupportedIsolation) => {
                    assert_eq!(
                        err.to_string(),
                        "trust source writes run only at READ COMMITTED"
                    );
                    assert!(err.source().is_none());
                }
                other => panic!("{level} {write}: {other:?}"),
            }
            // No row is locked: every row the write would lock is free.
            let mut probe = pool.begin().await.unwrap();
            for sql in [
                "SELECT FROM admin_identity WHERE id = 'adm_trust' FOR UPDATE NOWAIT",
                "SELECT FROM admin_credential WHERE id = 'crd_adm_trust' FOR UPDATE NOWAIT",
                "SELECT FROM admin_role_binding WHERE id = 'rb_adm_trust' FOR UPDATE NOWAIT",
                "SELECT FROM trust_source WHERE id = 'src_1' FOR UPDATE NOWAIT",
                "SELECT FROM egress_allowlist_entry WHERE id = 'egr_disc' FOR UPDATE NOWAIT",
                "SELECT FROM audit_chain_head FOR UPDATE NOWAIT",
            ] {
                sqlx::query(sql)
                    .execute(&mut *probe)
                    .await
                    .unwrap_or_else(|err| panic!("{level} {write}: {sql}: {err}"));
            }
            probe.rollback().await.unwrap();
            // The caller's transaction is still usable.
            sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
            tx.rollback().await.unwrap();
        }
    }
    assert_eq!(source_count(&pool).await, 1);
    assert_eq!(
        registry::get_trust_source(&pool, "ten_a", "src_1")
            .await
            .unwrap(),
        source
    );
    assert_chain(&pool, 1).await;
    db.drop([pool]).await;
}

/// A deadlock is a retry of the whole transaction. The cycle is the one the
/// module docs warn about: another transaction holds the entry and then
/// waits for the source row, which the update holds before it locks the
/// entry. The other transaction waits first, past its deadlock check, so
/// the update closes the cycle and is the one PostgreSQL aborts.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_deadlock_is_a_retry() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY), "aud_1")
        .await
        .unwrap();
    let mut writer = pool.acquire().await.unwrap().detach();
    let mut other = pool.acquire().await.unwrap().detach();
    let (writer_pid, other_pid) = (
        backend_pid(&mut writer).await,
        backend_pid(&mut other).await,
    );
    let mut write = writer.begin().await.unwrap();
    // The source row, as the update's step 2 locks it.
    sqlx::query("SELECT FROM trust_source WHERE id = 'src_1' FOR NO KEY UPDATE")
        .execute(&mut *write)
        .await
        .unwrap();
    // A plain BEGIN, so the connection, not a borrow of it, moves to the
    // task.
    for sql in [
        "BEGIN",
        "SELECT FROM egress_allowlist_entry WHERE id = 'egr_disc_2' FOR UPDATE",
    ] {
        sqlx::query(sql).execute(&mut other).await.unwrap();
    }
    let task = tokio::spawn(async move {
        let result = sqlx::query("SELECT FROM trust_source WHERE id = 'src_1' FOR UPDATE")
            .execute(&mut other)
            .await
            .map(|_| ());
        sqlx::query("ROLLBACK").execute(&mut other).await.unwrap();
        (result, other)
    });
    wait_until_blocked(&pool, other_pid, writer_pid, &task).await;
    // Past the server's deadlock_timeout (1 s by default; setting it needs a
    // superuser, which these tests do not use): the other transaction has
    // run its one deadlock check and found no cycle, so the update, which
    // closes the cycle, is the one that fails.
    let deadlock_timeout: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM current_setting('deadlock_timeout')::interval) * 1000)::bigint",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let deadlock_timeout = u64::try_from(deadlock_timeout).unwrap();
    tokio::time::sleep(Duration::from_millis(deadlock_timeout + 500)).await;
    let mut changed = changes(&source);
    changed.discovery_url = Some(DISCOVERY_2.into());
    let result = update_source(
        &mut write,
        TRUST,
        "ten_a",
        "src_1",
        1,
        &changed,
        &audit("aud_2"),
    )
    .await;
    match &result {
        Err(SourceWriteError::Registry(err @ RegistryError::Retry(_))) => {
            assert!(err.to_string().contains("40P01"), "{err}");
        }
        other => panic!("expected a retry, got {other:?}"),
    }
    write.rollback().await.unwrap();
    let (other_result, other) = join(task).await;
    other_result.unwrap();
    other.close().await.unwrap();
    writer.close().await.unwrap();
    assert_eq!(
        registry::get_trust_source(&pool, "ten_a", "src_1")
            .await
            .unwrap(),
        source
    );
    assert_chain(&pool, 1).await;
    db.drop([pool]).await;
}

/// Runs `sql` with `id` in a transaction of its own with a `lock_timeout` of
/// 100 ms and commits it: `Err` holds the SQLSTATE when it had to wait.
async fn without_waiting(pool: &PgPool, sql: &'static str, id: &str) -> Result<(), Option<String>> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout = '100ms'")
        .execute(&mut *tx)
        .await
        .unwrap();
    match sqlx::query(sql).bind(id).execute(&mut *tx).await {
        Ok(_) => {
            tx.commit().await.unwrap();
            Ok(())
        }
        Err(err) => {
            let state = sqlstate(&err);
            tx.rollback().await.unwrap();
            Err(state)
        }
    }
}

/// An update waits for its source row before it locks any egress entry, so
/// while it waits a disable of the entry it would check applies at once;
/// the update then reads the entry disabled. The holder takes only
/// `FOR SHARE`, which the step-2 lock conflicts with but a weaker source
/// lock would not: an update that locked the source more weakly would pass
/// step 2, lock the entry and then wait at its compare-and-set, holding the
/// entry.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_update_waiting_for_its_source_holds_no_entry() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY), "aud_1")
        .await
        .unwrap();
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut writer = pool.acquire().await.unwrap().detach();
    let (holder_pid, writer_pid) = (
        backend_pid(&mut holder).await,
        backend_pid(&mut writer).await,
    );
    let mut hold = holder.begin().await.unwrap();
    sqlx::query("SELECT FROM trust_source WHERE id = 'src_1' FOR SHARE")
        .execute(&mut *hold)
        .await
        .unwrap();
    let mut changed = changes(&source);
    changed.discovery_url = Some(DISCOVERY_2.into());
    let task = tokio::spawn(async move {
        let mut tx = writer.begin().await.unwrap();
        let result = update_source(
            &mut tx,
            TRUST,
            "ten_a",
            "src_1",
            1,
            &changed,
            &audit("aud_2"),
        )
        .await;
        tx.rollback().await.unwrap();
        (result, writer)
    });
    wait_until_blocked(&pool, writer_pid, holder_pid, &task).await;
    without_waiting(&pool, DISABLE_ENTRY, "egr_disc_2")
        .await
        .expect("the waiting update must hold no entry lock");
    hold.rollback().await.unwrap();
    let (result, writer) = join(task).await;
    assert_egress(result, DISCOVERY_URL, DISCOVERY_2);
    writer.close().await.unwrap();
    holder.close().await.unwrap();
    assert_eq!(
        registry::get_trust_source(&pool, "ten_a", "src_1")
            .await
            .unwrap(),
        source
    );
    assert_chain(&pool, 1).await;
    db.drop([pool]).await;
}

/// Two concurrent updates of one source at the same revision: the second
/// waits for the first on the source row and then reads the committed
/// revision, a `StaleRevision`, never a deadlock (`Retry`), whichever
/// entries they check.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_updates_of_one_source_are_stale_not_retry() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY), "aud_1")
        .await
        .unwrap();
    // The first keeps the name, the second also renames.
    for (n, (first_value, second_value, second_name)) in [
        (DISCOVERY_2, DISCOVERY_ONLY, "second"),
        (DISCOVERY_ONLY, DISCOVERY_2, "second-again"),
    ]
    .into_iter()
    .enumerate()
    {
        let revision = i64::try_from(n).unwrap() + 1;
        let stored = registry::get_trust_source(&pool, "ten_a", "src_1")
            .await
            .unwrap();
        let mut first_conn = pool.acquire().await.unwrap().detach();
        let mut second_conn = pool.acquire().await.unwrap().detach();
        let (first_pid, second_pid) = (
            backend_pid(&mut first_conn).await,
            backend_pid(&mut second_conn).await,
        );
        let mut first = first_conn.begin().await.unwrap();
        let mut first_changes = changes(&stored);
        first_changes.discovery_url = Some(first_value.into());
        update_source(
            &mut first,
            TRUST,
            "ten_a",
            "src_1",
            revision,
            &first_changes,
            &audit(&format!("aud_first_{n}")),
        )
        .await
        .unwrap();
        let mut second_changes = changes(&stored);
        second_changes.discovery_url = Some(second_value.into());
        second_changes.name = second_name.into();
        let event_id = format!("aud_second_{n}");
        let task = tokio::spawn(async move {
            let mut tx = second_conn.begin().await.unwrap();
            let result = update_source(
                &mut tx,
                TRUST,
                "ten_a",
                "src_1",
                revision,
                &second_changes,
                &audit(&event_id),
            )
            .await;
            tx.rollback().await.unwrap();
            (result, second_conn)
        });
        wait_until_blocked(&pool, second_pid, first_pid, &task).await;
        first.commit().await.unwrap();
        let (result, second_conn) = join(task).await;
        assert_registry(
            result,
            |err| matches!(err, RegistryError::StaleRevision),
            "second",
        );
        second_conn.close().await.unwrap();
        first_conn.close().await.unwrap();
        let stored = registry::get_trust_source(&pool, "ten_a", "src_1")
            .await
            .unwrap();
        assert_eq!(
            (
                stored.revision,
                stored.discovery_url.as_deref(),
                &stored.name[..]
            ),
            (revision + 1, Some(first_value), &source.name[..])
        );
    }
    assert_eq!(events(&pool).await.len(), 3);
    assert_chain(&pool, 3).await;
    db.drop([pool]).await;
}

/// A refusal after the function took locks releases them with its
/// savepoint: while the caller's transaction is still open, the operator
/// rows, the source row and the checked entry can be locked or changed by
/// another transaction at once.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_refusal_releases_its_locks() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY), "aud_1")
        .await
        .unwrap();
    create(&pool, TRUST, &oidc("src_2", DISCOVERY), "aud_2")
        .await
        .unwrap();
    let duplicate_name = |err: &RegistryError| matches!(err, RegistryError::AlreadyExists { .. });
    let operator_rows = [
        "SELECT FROM admin_identity WHERE id = $1 FOR UPDATE",
        "SELECT FROM admin_credential WHERE admin_id = $1 FOR UPDATE",
        "SELECT FROM admin_role_binding WHERE admin_id = $1 FOR UPDATE",
    ];

    let lock_entry = "SELECT FROM egress_allowlist_entry WHERE id = $1 FOR UPDATE";
    let lock_source = "SELECT FROM trust_source WHERE id = $1 FOR UPDATE";
    let mut tx = pool.begin().await.unwrap();

    // Refusals by this module's own logic, with no database error: the
    // entry was found and locked, and it is disabled.
    let mut off = changes(&source);
    off.discovery_url = Some(DISCOVERY_OFF.into());
    assert_egress(
        update_source(&mut tx, TRUST, "ten_a", "src_1", 1, &off, &audit("aud_3")).await,
        DISCOVERY_URL,
        DISCOVERY_OFF,
    );
    assert_egress(
        create_source(
            &mut tx,
            TRUST,
            &k8s("src_3", TOKEN_REVIEW_OFF),
            &audit("aud_3"),
        )
        .await,
        TOKEN_REVIEW_ENDPOINT,
        TOKEN_REVIEW_OFF,
    );
    for sql in operator_rows {
        assert_eq!(
            without_waiting(&pool, sql, "adm_trust").await,
            Ok(()),
            "{sql}"
        );
    }
    for (sql, id) in [
        (lock_source, "src_1"),
        (lock_entry, "egr_disc_off"),
        (lock_entry, "egr_tr_off"),
    ] {
        assert_eq!(without_waiting(&pool, sql, id).await, Ok(()), "{id}");
    }

    // An update refused at its write, after the operator, source and entry
    // locks: a rename to another source's name.
    let mut clash = changes(&source);
    clash.discovery_url = Some(DISCOVERY_2.into());
    clash.name = "source-src_2".into();
    assert_registry(
        update_source(&mut tx, TRUST, "ten_a", "src_1", 1, &clash, &audit("aud_3")).await,
        duplicate_name,
        "update",
    );
    for sql in operator_rows {
        assert_eq!(
            without_waiting(&pool, sql, "adm_trust").await,
            Ok(()),
            "{sql}"
        );
    }
    assert_eq!(without_waiting(&pool, lock_source, "src_1").await, Ok(()));
    assert_eq!(
        without_waiting(&pool, DISABLE_ENTRY, "egr_disc_2").await,
        Ok(())
    );

    // A create refused at its insert, after the operator and entry locks.
    let mut taken = oidc("src_3", DISCOVERY_ONLY);
    taken.name = "source-src_1".into();
    assert_registry(
        create_source(&mut tx, TRUST, &taken, &audit("aud_3")).await,
        duplicate_name,
        "create",
    );
    for sql in operator_rows {
        assert_eq!(
            without_waiting(&pool, sql, "adm_trust").await,
            Ok(()),
            "{sql}"
        );
    }
    assert_eq!(
        without_waiting(&pool, DISABLE_ENTRY, "egr_disc_only").await,
        Ok(())
    );
    tx.commit().await.unwrap();

    assert_eq!(
        registry::get_trust_source(&pool, "ten_a", "src_1")
            .await
            .unwrap(),
        source
    );
    assert_eq!(source_count(&pool).await, 2);
    assert_chain(&pool, 2).await;
    db.drop([pool]).await;
}

/// The workload principal `wld_1` of `ten_a`, which bindings to `src_1`
/// name.
async fn workload(pool: &PgPool) {
    registry::create_principal(
        pool,
        &NewPrincipal {
            id: "wld_1".into(),
            tenant_id: "ten_a".into(),
            kind: PrincipalKind::Workload,
            name: "principal wld_1".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// A consumed assertion of `src_1`, the `n`th of the test.
fn consumed(n: u8) -> NewConsumedAssertion {
    NewConsumedAssertion {
        tenant_id: "ten_a".into(),
        trust_source_id: "src_1".into(),
        replay_key_digest: vec![n; 32],
        digest_key_version: "dk_1".into(),
        consumed_at: now(),
        retain_until: now() + Duration::from_secs(600),
    }
}

/// The SQLSTATE of a registry error that carries a database error.
fn registry_sqlstate(err: &RegistryError) -> Option<String> {
    match err {
        RegistryError::Other(err) => sqlstate(err),
        other => Some(format!("{other:?}")),
    }
}

/// Commits `tx` on `Ok` and rolls it back on `Err`.
async fn settle(
    tx: Transaction<'_, Postgres>,
    result: Result<(), Option<String>>,
) -> Result<(), Option<String>> {
    if result.is_ok() {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    result
}

/// The two foreign-key references to `src_1`, each in a transaction of its
/// own with a `lock_timeout` of 100 ms, committed when it succeeds: the
/// `n`th `principal_binding` (a binding write) and the `n`th
/// `consumed_assertion` (a token exchange). For each, `Ok` or the SQLSTATE
/// it failed with.
async fn reference_source(pool: &PgPool, n: u8) -> [Result<(), Option<String>>; 2] {
    let set_timeout = "SET LOCAL lock_timeout = '100ms'";
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(set_timeout).execute(&mut *tx).await.unwrap();
    let binding = registry::create_principal_binding(
        &mut *tx,
        &NewPrincipalBinding {
            id: format!("bnd_{n}"),
            tenant_id: "ten_a".into(),
            name: format!("binding-{n}"),
            trust_source_id: "src_1".into(),
            profile: BindingProfile::GithubProduction,
            claim_match_policy: BTreeMap::from(
                [
                    ("repository_owner_id", "123456"),
                    ("repository_id", "456789"),
                    ("event_name", "push"),
                    ("ref", "refs/heads/main"),
                    ("environment", "production"),
                    (
                        "workflow_ref",
                        "acme/platform/.github/workflows/deploy.yml@refs/heads/main",
                    ),
                ]
                .map(|(name, value)| (name.to_string(), value.to_string())),
            ),
            workload_principal_id: "wld_1".into(),
            status: Status::Enabled,
        },
    )
    .await
    .map(|_| ())
    .map_err(|err| registry_sqlstate(&err));
    let binding = settle(tx, binding).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(set_timeout).execute(&mut *tx).await.unwrap();
    let consumption = match registry::consume_assertion(&mut *tx, &consumed(n)).await {
        Ok(Consumption::Consumed) => Ok(()),
        Ok(Consumption::Replay) => panic!("consumed assertion {n} replayed"),
        Err(err) => Err(registry_sqlstate(&err)),
    };
    let consumption = settle(tx, consumption).await;
    [binding, consumption]
}

/// What an update in
/// [`every_source_update_blocks_references_to_the_source_until_commit`]
/// changes.
#[derive(Debug, Clone, Copy)]
enum Change {
    Nothing,
    StatusOnly,
    UrlOnly,
    Rename,
}

/// Every update through `update_source` takes the source row `FOR UPDATE`
/// at its compare-and-set, whatever it changes (the `BEFORE UPDATE` triggers
/// of `trust_source` and the `name` in the `SET` list): until the commit, a
/// `principal_binding` or `consumed_assertion` insert that references the
/// source fails with `55P03` under a short `lock_timeout`; after it, both
/// apply. The locks of the steps before the compare-and-set (the operator
/// rows and the source row `FOR NO KEY UPDATE`) block neither.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_source_update_blocks_references_to_the_source_until_commit() {
    let (db, pool) = seeded().await;
    let mut source = create(&pool, TRUST, &oidc("src_1", DISCOVERY), "aud_1")
        .await
        .unwrap();
    workload(&pool).await;
    let free = [Ok(()), Ok(())];
    let blocked = [Err(Some("55P03".into())), Err(Some("55P03".into()))];
    let mut n = 0;
    assert_eq!(reference_source(&pool, n).await, free, "before any update");
    for change in [
        Change::Nothing,
        Change::StatusOnly,
        Change::UrlOnly,
        Change::Rename,
    ] {
        let mut next = changes(&source);
        match change {
            Change::Nothing => {}
            Change::StatusOnly => next.status = Status::Disabled,
            Change::UrlOnly => next.discovery_url = Some(DISCOVERY_2.into()),
            Change::Rename => next.name = "renamed".into(),
        }
        let mut tx = pool.begin().await.unwrap();
        let updated = update_source(
            &mut tx,
            TRUST,
            "ten_a",
            "src_1",
            source.revision,
            &next,
            &audit(&format!("aud_{change:?}")),
        )
        .await
        .unwrap();
        n += 1;
        assert_eq!(reference_source(&pool, n).await, blocked, "{change:?}");
        tx.commit().await.unwrap();
        n += 1;
        assert_eq!(reference_source(&pool, n).await, free, "{change:?}");
        source = updated;
    }

    // An update that waits at its entry lock holds the operator rows and
    // the source row `FOR NO KEY UPDATE`, and has not reached its
    // compare-and-set: the references do not wait for it.
    let mut blocker_conn = pool.acquire().await.unwrap().detach();
    let mut writer = pool.acquire().await.unwrap().detach();
    let (blocker_pid, writer_pid) = (
        backend_pid(&mut blocker_conn).await,
        backend_pid(&mut writer).await,
    );
    let mut blocker = blocker_conn.begin().await.unwrap();
    sqlx::query("SELECT FROM egress_allowlist_entry WHERE id = 'egr_disc' FOR UPDATE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut back = changes(&source);
    back.discovery_url = Some(DISCOVERY.into());
    let revision = source.revision;
    let task = tokio::spawn(async move {
        let mut tx = writer.begin().await.unwrap();
        let result = update_source(
            &mut tx,
            TRUST,
            "ten_a",
            "src_1",
            revision,
            &back,
            &audit("aud_back"),
        )
        .await;
        tx.rollback().await.unwrap();
        (result, writer)
    });
    wait_until_blocked(&pool, writer_pid, blocker_pid, &task).await;
    n += 1;
    assert_eq!(reference_source(&pool, n).await, free, "before the write");
    blocker.rollback().await.unwrap();
    let (result, writer) = join(task).await;
    result.unwrap();
    writer.close().await.unwrap();
    blocker_conn.close().await.unwrap();
    assert_chain(&pool, 5).await;
    db.drop([pool]).await;
}

/// The audit event comes after the compare-and-set, so an update that waits
/// there for a consumer of its source (a consumed assertion not yet
/// committed, which holds the source `FOR KEY SHARE`) holds no audit head:
/// the consumer appends its own event and commits, and then the update
/// completes. An update that appended first would hold the head while it
/// waited, and the consumer's append would close a deadlock.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_update_waiting_for_a_consumer_holds_no_audit_head() {
    let (db, pool) = seeded().await;
    let source = create(&pool, TRUST, &oidc("src_1", DISCOVERY), "aud_1")
        .await
        .unwrap();
    let mut consumer_conn = pool.acquire().await.unwrap().detach();
    let mut writer = pool.acquire().await.unwrap().detach();
    let (consumer_pid, writer_pid) = (
        backend_pid(&mut consumer_conn).await,
        backend_pid(&mut writer).await,
    );
    let mut consumer = consumer_conn.begin().await.unwrap();
    assert_eq!(
        registry::consume_assertion(&mut *consumer, &consumed(1))
            .await
            .unwrap(),
        Consumption::Consumed
    );
    // An update that changes nothing still reaches the consumer's lock.
    let unchanged = changes(&source);
    let task = tokio::spawn(async move {
        let mut tx = writer.begin().await.unwrap();
        let result = update_source(
            &mut tx,
            TRUST,
            "ten_a",
            "src_1",
            1,
            &unchanged,
            &audit("aud_3"),
        )
        .await;
        match result {
            Ok(_) => tx.commit().await.unwrap(),
            Err(_) => tx.rollback().await.unwrap(),
        }
        (result, writer)
    });
    wait_until_blocked(&pool, writer_pid, consumer_pid, &task).await;
    // The consumer's own event (this action stands in for it).
    registry::append_audit_event(
        &mut consumer,
        &NewAuditEvent {
            id: "aud_2".into(),
            tenant_id: Some("ten_a".into()),
            timestamp: now(),
            actor: AuditActor::Operator("adm_trust".into()),
            action: "trust_keyset.update".into(),
            object_id: "ks_1".into(),
            previous_revision: Some(1),
            new_revision: Some(2),
            outcome: "success".into(),
        },
    )
    .await
    .expect("the audit head must be free while the update waits");
    consumer.commit().await.unwrap();
    let (result, writer) = join(task).await;
    assert_eq!(result.unwrap().revision, 2);
    writer.close().await.unwrap();
    consumer_conn.close().await.unwrap();
    let order: Vec<_> = events(&pool)
        .await
        .into_iter()
        .map(|event| (event.0, event.1))
        .collect();
    assert_eq!(
        order,
        [
            (1, "trust_source.create".to_string()),
            (2, "trust_keyset.update".to_string()),
            (3, "trust_source.update".to_string()),
        ]
    );
    assert_chain(&pool, 3).await;
    db.drop([pool]).await;
}

/// The module is reachable as `skyoauth_service::trust` with its member
/// names.
#[test]
fn the_member_names_are_the_columns() {
    assert_eq!(trust::DISCOVERY_URL, "discovery_url");
    assert_eq!(trust::TOKEN_REVIEW_ENDPOINT, "token_review_endpoint");
}
