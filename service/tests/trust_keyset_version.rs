//! The audited trust keyset version write path
//! (`skyoauth_service::trust::keyset`; T11.3, T11.9) against a real
//! PostgreSQL server: a version stores the validated projection and its
//! fingerprint, never the raw upload; only a `trust_admin` of the tenant
//! writes; the overlap check runs wherever a version becomes enabled, over
//! the stored versions parsed in full, and a rotation passes it; two writes
//! of one keyset serialize on the parent row; the audit event comes last and
//! its failure undoes the write; only `READ COMMITTED` runs; a private
//! member never reaches the database through this path; and no error names
//! a `kid` or key material.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. They claim no conformance
//! scenario (A04 belongs to the test session in `tests/security`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    error::Error as _,
    sync::LazyLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use serde_json::{Value, json};
use skyoauth_service::{
    jwk::{
        DEFAULT_ALLOWED_ALGORITHMS, JwkError, JwkSetError, OverlapError, ValidatedKeyset,
        parse_stored,
    },
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AuditActor, ChainVerdict, InvariantKind, JsonObject,
            NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding, NewAuditEvent, NewTenant,
            NewTrustKeyset, NewTrustKeysetVersion, RegistryError, Status, TrustKeysetVersion,
        },
    },
    trust::{
        self, KeysetAudit, KeysetWriteError, NewKeysetVersion, create_version, disable_version,
        enable_version, validate_upload,
    },
};
use sqlx::{Connection, PgConnection, Postgres, Transaction};

// Key material: the RFC 7517 appendix A.1 P-256 key, a generated P-256
// key, the RFC 8037 Ed25519 key and the RFC 7638 RSA key (see
// `service/tests/jwk.rs`).
const A_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const A_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
const A_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
const B_X: &str = "60KU-t7I0SkALarT8sfRB5iNa5QkWCUlbefzbW7OlQw";
const B_Y: &str = "AB530pP2cpYhadpS5FNwg9m8w4UgWFlJJkxIxFl_MPk";
const ED_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

/// The rotated `kid`: distinctive, so a test can show no error names it.
const KID: &str = "rotation-kid-7f3a";

/// Every value no error may print.
const SECRETS: [&str; 8] = [KID, A_X, A_Y, A_D, B_X, B_Y, ED_X, RSA_N];

/// The key of the `trust_admin` of `ten_a`.
const TRUST: &str = "key_adm_trust";
/// The key of the `trust_admin` of `ten_b`.
const TRUST_B: &str = "key_adm_trust_b";

static PROVENANCE: LazyLock<JsonObject> = LazyLock::new(|| {
    json!({"supplied_by": "operator", "via": "upload"})
        .as_object()
        .unwrap()
        .clone()
});

/// A time with sub-microsecond digits, so a write truncates it.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(1_790_000_000_123_456_789)
}

/// The start of the open-ended windows of these tests.
fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn audit(event_id: &str) -> KeysetAudit<'_> {
    KeysetAudit {
        event_id,
        now: now(),
    }
}

fn p256_a(kid: &str) -> Value {
    json!({"kty": "EC", "kid": kid, "crv": "P-256", "x": A_X, "y": A_Y})
}

fn p256_b(kid: &str) -> Value {
    json!({"kty": "EC", "kid": kid, "crv": "P-256", "x": B_X, "y": B_Y})
}

/// The first key's `x` with the second key's `y`: well formed, below the
/// field prime, and not a point of P-256.
fn p256_off_curve(kid: &str) -> Value {
    json!({"kty": "EC", "kid": kid, "crv": "P-256", "x": A_X, "y": B_Y})
}

fn ed25519(kid: &str) -> Value {
    json!({"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": ED_X})
}

fn rsa(kid: &str, alg: &str) -> Value {
    json!({"kty": "RSA", "kid": kid, "alg": alg, "n": RSA_N, "e": "AQAB"})
}

fn set(keys: Vec<Value>) -> Value {
    json!({ "keys": keys })
}

/// Stage A with the default allowed set.
async fn upload(keys: Vec<Value>) -> ValidatedKeyset {
    validate_upload(set(keys), DEFAULT_ALLOWED_ALGORITHMS)
        .await
        .unwrap()
}

/// A version `id` of `ks_1` of `ten_a` with `keys`, enabled, open-ended
/// from [`t0`].
fn version<'a>(id: &'a str, keys: &'a ValidatedKeyset) -> NewKeysetVersion<'a> {
    NewKeysetVersion {
        id,
        tenant_id: "ten_a",
        keyset_id: "ks_1",
        keys,
        effective_at: t0(),
        expires_at: None,
        status: Status::Enabled,
        provenance: &PROVENANCE,
    }
}

fn disabled<'a>(id: &'a str, keys: &'a ValidatedKeyset) -> NewKeysetVersion<'a> {
    NewKeysetVersion {
        status: Status::Disabled,
        ..version(id, keys)
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

/// Tenants `ten_a` and `ten_b`; keysets `ks_1` and `ks_2` of `ten_a` and
/// `ks_b` of `ten_b`; operators, each with the key `key_<id>`:
/// `adm_trust` (`trust_admin` of `ten_a`), `adm_trust_b` (`trust_admin` of
/// `ten_b`), `adm_sec` (instance `security_admin`), `adm_sec_a`
/// (`security_admin` bound to `ten_a`), `adm_client` (`client_admin` of
/// `ten_a`), `adm_prov` (`provider_admin` of `ten_a`) and `adm_audt`
/// (`auditor` of `ten_a`).
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
    for (id, tenant) in [("ks_1", "ten_a"), ("ks_2", "ten_a"), ("ks_b", "ten_b")] {
        registry::create_trust_keyset(
            &pool,
            &NewTrustKeyset {
                id: id.into(),
                tenant_id: tenant.into(),
                name: format!("keyset-{id}"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    for (admin, role, tenant) in [
        ("adm_trust", AdminRole::TrustAdmin, Some("ten_a")),
        ("adm_trust_b", AdminRole::TrustAdmin, Some("ten_b")),
        ("adm_sec", AdminRole::SecurityAdmin, None),
        ("adm_client", AdminRole::ClientAdmin, Some("ten_a")),
        ("adm_prov", AdminRole::ProviderAdmin, Some("ten_a")),
        ("adm_audt", AdminRole::Auditor, Some("ten_a")),
    ] {
        operator(&pool, admin, role, tenant).await;
    }
    (db, pool)
}

/// Commits on `Ok`; on `Err` first shows that the transaction is still
/// usable (the function rolled its savepoint back), then rolls back.
async fn finish<T>(mut tx: Transaction<'_, Postgres>, result: &Result<T, KeysetWriteError>) {
    if result.is_ok() {
        tx.commit().await.unwrap();
    } else {
        sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
}

/// [`create_version`] in its own transaction, committed on `Ok` and rolled
/// back on `Err`.
async fn create(
    pool: &PgPool,
    key: &str,
    new: &NewKeysetVersion<'_>,
    event_id: &str,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    let mut tx = pool.begin().await.unwrap();
    let result = create_version(&mut tx, key, new, &audit(event_id)).await;
    finish(tx, &result).await;
    result
}

/// [`enable_version`] or [`disable_version`] of a `ten_a` version in its
/// own transaction, committed on `Ok` and rolled back on `Err`.
async fn set_status(
    pool: &PgPool,
    key: &str,
    status: Status,
    id: &str,
    expected_revision: i64,
    event_id: &str,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    let mut tx = pool.begin().await.unwrap();
    let audit = audit(event_id);
    let result = match status {
        Status::Enabled => {
            enable_version(&mut tx, key, "ten_a", id, expected_revision, &audit).await
        }
        Status::Disabled => {
            disable_version(&mut tx, key, "ten_a", id, expected_revision, &audit).await
        }
    };
    finish(tx, &result).await;
    result
}

async fn enable(
    pool: &PgPool,
    id: &str,
    revision: i64,
    event_id: &str,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    set_status(pool, TRUST, Status::Enabled, id, revision, event_id).await
}

async fn disable(
    pool: &PgPool,
    id: &str,
    revision: i64,
    event_id: &str,
) -> Result<TrustKeysetVersion, KeysetWriteError> {
    set_status(pool, TRUST, Status::Disabled, id, revision, event_id).await
}

/// Neither the error's `Display` nor its `Debug` contains a `kid`, key
/// material or a version ID of these tests.
#[track_caller]
fn assert_redacted(err: &KeysetWriteError, ids: &[&str]) {
    for text in [err.to_string(), format!("{err:?}")] {
        for value in SECRETS.iter().chain(ids) {
            assert!(!text.contains(value), "{text} contains {value}");
        }
    }
}

/// The result is an overlap refusal of this kind naming the versions, and
/// prints neither.
#[track_caller]
fn assert_overlap<T: std::fmt::Debug>(
    result: Result<T, KeysetWriteError>,
    kind: &str,
    first_version: &str,
    second_version: &str,
) {
    let err = result.expect_err("an overlap refusal");
    let KeysetWriteError::Overlap(overlap) = &err else {
        panic!("expected Overlap, got {err:?}");
    };
    let (found_kind, first, second) = match overlap {
        OverlapError::KidConflict {
            first_version,
            second_version,
            ..
        } => ("KidConflict", first_version, second_version),
        OverlapError::KeyConflict {
            first_version,
            second_version,
            ..
        } => ("KeyConflict", first_version, second_version),
        OverlapError::AlgorithmConflict {
            first_version,
            second_version,
            ..
        } => ("AlgorithmConflict", first_version, second_version),
    };
    assert_eq!(
        (found_kind, &first[..], &second[..]),
        (kind, first_version, second_version)
    );
    assert!(err.source().is_none());
    assert_redacted(&err, &[first_version, second_version]);
}

#[track_caller]
fn assert_unauthorized<T: std::fmt::Debug>(result: Result<T, KeysetWriteError>, case: &str) {
    match result {
        Err(err @ KeysetWriteError::Unauthorized) => {
            assert_eq!(
                err.to_string(),
                "the operator may not write this tenant's trust keyset versions",
                "{case}"
            );
            assert_eq!(format!("{err:?}"), "Unauthorized", "{case}");
        }
        other => panic!("{case}: expected Unauthorized, got {other:?}"),
    }
}

#[track_caller]
fn assert_registry<T: std::fmt::Debug>(
    result: Result<T, KeysetWriteError>,
    expected: fn(&RegistryError) -> bool,
    case: &str,
) {
    match result {
        Err(KeysetWriteError::Registry(err)) if expected(&err) => {}
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

/// The audit events as `(action, object_id, previous_revision,
/// new_revision)`.
async fn event_summary(pool: &PgPool) -> Vec<(String, String, Option<i64>, Option<i64>)> {
    events(pool)
        .await
        .into_iter()
        .map(|event| (event.1, event.2, event.5, event.6))
        .collect()
}

fn event(
    action: &str,
    id: &str,
    previous: Option<i64>,
    new: i64,
) -> (String, String, Option<i64>, Option<i64>) {
    (
        format!("trust_keyset_version.{action}"),
        id.into(),
        previous,
        Some(new),
    )
}

async fn assert_chain(pool: &PgPool, last_sequence: i64) {
    let mut conn = pool.acquire().await.unwrap();
    assert_eq!(
        registry::verify_audit_chain(&mut conn).await.unwrap(),
        ChainVerdict::Intact { last_sequence }
    );
}

async fn version_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM trust_keyset_version")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// `(status, revision)` of the version `id`.
async fn state(pool: &PgPool, id: &str) -> (Status, i64) {
    let version = registry::get_trust_keyset_version(pool, "ten_a", id)
        .await
        .unwrap();
    (version.status, version.revision)
}

/// The stored `public_jwks` of the version `id`, as PostgreSQL prints it.
async fn stored_text(pool: &PgPool, id: &str) -> String {
    sqlx::query_scalar("SELECT public_jwks::text FROM trust_keyset_version WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A version written through the test-only raw registry writer, the
/// unchecked floor: `public_jwks` is stored as given.
async fn raw_version(
    pool: &PgPool,
    id: &str,
    keyset_id: &str,
    public_jwks: Value,
    status: Status,
    window: (SystemTime, Option<SystemTime>),
) {
    registry::create_trust_keyset_version(
        pool,
        &NewTrustKeysetVersion {
            id: id.into(),
            tenant_id: "ten_a".into(),
            keyset_id: keyset_id.into(),
            public_jwks: public_jwks.as_object().unwrap().clone(),
            fingerprint: "raw".into(),
            effective_at: window.0,
            expires_at: window.1,
            status,
            provenance: PROVENANCE.clone(),
        },
    )
    .await
    .unwrap();
}

fn operator_actor(admin: &str) -> String {
    AuditActor::Operator(admin.into()).canonical_json()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_version_stores_the_projection_and_its_fingerprint_not_the_upload() {
    let (db, pool) = seeded().await;
    let x5t = "AQEBAQEBAQEBAQEBAQEBAQEBAQE";
    let raw = vec![
        // Members outside the projection, in an order the projection does
        // not keep.
        json!({"use": "sig", "key_ops": ["verify"], "x5t": x5t, "y": A_Y, "x": A_X,
               "crv": "P-256", "kid": "k1", "kty": "EC", "alg": "ES256"}),
        json!({"use": "sig", "kty": "OKP", "kid": "k0", "crv": "Ed25519", "x": ED_X}),
    ];
    let keys = validate_upload(set(raw.clone()), DEFAULT_ALLOWED_ALGORITHMS)
        .await
        .unwrap();
    let other = upload(vec![p256_b("k2")]).await;
    let window = Some(t0() + secs(3600));
    let created = [
        create(&pool, TRUST, &version("ver_on", &keys), "aud_1").await,
        create(
            &pool,
            TRUST,
            &NewKeysetVersion {
                expires_at: window,
                ..disabled("ver_off", &other)
            },
            "aud_2",
        )
        .await,
    ];
    for (result, (id, keys, status, expires_at)) in created.into_iter().zip([
        ("ver_on", &keys, Status::Enabled, None),
        ("ver_off", &other, Status::Disabled, window),
    ]) {
        let version = result.unwrap();
        let projection: Value = serde_json::from_str(keys.public_json()).unwrap();
        assert_eq!(
            (
                &version.id[..],
                &version.tenant_id[..],
                &version.keyset_id[..],
                Value::Object(version.public_jwks.clone()),
                &version.fingerprint[..],
                version.effective_at,
                version.expires_at,
                version.status,
                &version.provenance,
                version.revision,
            ),
            (
                id,
                "ten_a",
                "ks_1",
                projection,
                keys.fingerprint().as_str(),
                t0(),
                expires_at,
                status,
                &*PROVENANCE,
                1
            )
        );
        assert_eq!(
            registry::get_trust_keyset_version(&pool, "ten_a", id)
                .await
                .unwrap(),
            version
        );
        // The stored text holds the projection's members only, and reads
        // back to the same projection and fingerprint.
        let text = stored_text(&pool, id).await;
        for absent in ["use", "key_ops", "x5t", "sig", "verify", x5t] {
            assert!(!text.contains(absent), "{text}");
        }
        let stored = parse_stored(&text).unwrap();
        assert_eq!(stored.public_json(), keys.public_json());
        assert_eq!(stored.fingerprint(), keys.fingerprint());
    }
    // The projection is not the upload.
    let upload_value = set(raw);
    assert_ne!(
        Value::Object(
            registry::get_trust_keyset_version(&pool, "ten_a", "ver_on")
                .await
                .unwrap()
                .public_jwks
        ),
        upload_value
    );
    let stored: Value = serde_json::from_str(&stored_text(&pool, "ver_on").await).unwrap();
    let members = |index: usize| {
        let mut names: Vec<String> = stored["keys"][index]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    };
    // Sorted by kid: k0 (Ed25519), then k1 (P-256 with its alg).
    assert_eq!(members(0), ["crv", "kid", "kty", "x"]);
    assert_eq!(members(1), ["alg", "crv", "kid", "kty", "x", "y"]);
    assert_eq!(stored["keys"][0]["kid"], "k0");

    let actor = operator_actor("adm_trust");
    assert_eq!(
        events(&pool).await,
        [(1, "ver_on"), (2, "ver_off")].map(|(sequence, id)| (
            sequence,
            "trust_keyset_version.create".to_string(),
            id.to_string(),
            Some("ten_a".to_string()),
            actor.clone(),
            None,
            Some(1)
        ))
    );
    assert_chain(&pool, 2).await;

    // A status change is its own action, with both revisions.
    disable(&pool, "ver_on", 1, "aud_3").await.unwrap();
    let enabled = enable(&pool, "ver_off", 1, "aud_4").await.unwrap();
    assert_eq!((enabled.status, enabled.revision), (Status::Enabled, 2));
    assert_eq!(state(&pool, "ver_on").await, (Status::Disabled, 2));
    assert_eq!(
        event_summary(&pool).await[2..],
        [
            event("disable", "ver_on", Some(1), 2),
            event("enable", "ver_off", Some(1), 2)
        ]
    );
    assert_chain(&pool, 4).await;

    // Another tenant's trust_admin writes that tenant's keyset.
    let created = create(
        &pool,
        TRUST_B,
        &NewKeysetVersion {
            tenant_id: "ten_b",
            keyset_id: "ks_b",
            ..version("ver_b", &keys)
        },
        "aud_5",
    )
    .await
    .unwrap();
    assert_eq!(created.tenant_id, "ten_b");
    assert_chain(&pool, 5).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn only_a_trust_admin_of_the_tenant_may_write() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &disabled("ver_1", &keys), "aud_1")
        .await
        .unwrap();
    for (key, case) in [
        ("key_unknown", "unknown credential"),
        (TRUST_B, "another tenant's trust_admin"),
        ("key_adm_sec", "instance security_admin"),
        ("key_adm_client", "client_admin of the tenant"),
        ("key_adm_prov", "provider_admin of the tenant"),
        ("key_adm_audt", "auditor of the tenant"),
    ] {
        assert_unauthorized(
            create(&pool, key, &version("ver_2", &keys), "aud_2").await,
            case,
        );
        // Not even whether the keyset exists: a missing keyset, or another
        // tenant's keyset named under the tenant the caller chose, is the
        // same refusal, never NotFound.
        for keyset_id in ["ks_missing", "ks_b"] {
            assert_unauthorized(
                create(
                    &pool,
                    key,
                    &NewKeysetVersion {
                        keyset_id,
                        ..version("ver_2", &keys)
                    },
                    "aud_2",
                )
                .await,
                case,
            );
        }
        for status in [Status::Enabled, Status::Disabled] {
            assert_unauthorized(
                set_status(&pool, key, status, "ver_1", 1, "aud_2").await,
                case,
            );
            // An unauthorized caller learns nothing, not even whether the
            // version exists.
            assert_unauthorized(
                set_status(&pool, key, status, "ver_missing", 1, "aud_2").await,
                case,
            );
        }
    }
    // The tenant's trust_admin may not write another tenant's keyset, even
    // when naming it under its own tenant.
    assert_unauthorized(
        create(
            &pool,
            TRUST,
            &NewKeysetVersion {
                tenant_id: "ten_b",
                keyset_id: "ks_b",
                ..version("ver_2", &keys)
            },
            "aud_2",
        )
        .await,
        "other tenant",
    );
    assert_registry(
        create(
            &pool,
            TRUST,
            &NewKeysetVersion {
                keyset_id: "ks_b",
                ..version("ver_2", &keys)
            },
            "aud_2",
        )
        .await,
        |err| matches!(err, RegistryError::NotFound),
        "keyset of another tenant",
    );
    assert_eq!(version_count(&pool).await, 1);
    assert_eq!(state(&pool, "ver_1").await, (Status::Disabled, 1));
    assert_eq!(events(&pool).await.len(), 1);
    assert_chain(&pool, 1).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn missing_stale_and_invalid_targets_are_registry_errors() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &version("ver_1", &keys), "aud_1")
        .await
        .unwrap();
    create(
        &pool,
        TRUST_B,
        &NewKeysetVersion {
            tenant_id: "ten_b",
            keyset_id: "ks_b",
            ..version("ver_b", &keys)
        },
        "aud_2",
    )
    .await
    .unwrap();
    let not_found = |err: &RegistryError| matches!(err, RegistryError::NotFound);
    for status in [Status::Enabled, Status::Disabled] {
        for (id, revision, case) in [
            ("ver_missing", 1, "missing"),
            ("ver_b", 1, "another tenant's version"),
        ] {
            assert_registry(
                set_status(&pool, TRUST, status, id, revision, "aud_3").await,
                not_found,
                case,
            );
        }
        assert_registry(
            set_status(&pool, TRUST, status, "ver_1", 2, "aud_3").await,
            |err| matches!(err, RegistryError::StaleRevision),
            "stale",
        );
    }
    assert_registry(
        create(
            &pool,
            TRUST,
            &NewKeysetVersion {
                keyset_id: "ks_missing",
                ..version("ver_2", &keys)
            },
            "aud_3",
        )
        .await,
        not_found,
        "missing keyset",
    );
    // The ID is taken (the same keys: no overlap conflict).
    assert_registry(
        create(&pool, TRUST, &version("ver_1", &keys), "aud_3").await,
        |err| {
            matches!(
                err,
                RegistryError::AlreadyExists {
                    constraint: "trust_keyset_version_pkey"
                }
            )
        },
        "duplicate ID",
    );
    // An empty window is the 0004 validity check's, for both statuses.
    for new in [version("ver_2", &keys), disabled("ver_2", &keys)] {
        assert_registry(
            create(
                &pool,
                TRUST,
                &NewKeysetVersion {
                    expires_at: Some(t0()),
                    ..new
                },
                "aud_3",
            )
            .await,
            |err| {
                matches!(
                    err,
                    RegistryError::Invariant {
                        kind: InvariantKind::Check,
                        constraint: Some("trust_keyset_version_validity_check")
                    }
                )
            },
            "empty window",
        );
    }
    assert_eq!(version_count(&pool).await, 2);
    assert_eq!(events(&pool).await.len(), 2);
    assert_chain(&pool, 2).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn overlap_is_refused_wherever_a_version_becomes_enabled() {
    let (db, pool) = seeded().await;
    let old = upload(vec![p256_a(KID), ed25519("ed")]).await;
    let new_key = upload(vec![p256_b(KID)]).await;
    let renamed = upload(vec![p256_a("renamed")]).await;
    let same = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &version("ver_old", &old), "aud_1")
        .await
        .unwrap();

    // Creation as enabled: a kid with another key, a key with another kid.
    assert_overlap(
        create(&pool, TRUST, &version("ver_new", &new_key), "aud_2").await,
        "KidConflict",
        "ver_old",
        "ver_new",
    );
    assert_overlap(
        create(&pool, TRUST, &version("ver_new", &renamed), "aud_2").await,
        "KeyConflict",
        "ver_old",
        "ver_new",
    );
    // Starting later, or starting earlier and ending inside it, still
    // intersects an open window.
    for (start, end) in [
        (t0() + secs(86_400), None),
        (t0() - secs(10), Some(t0() + secs(1))),
    ] {
        assert_overlap(
            create(
                &pool,
                TRUST,
                &NewKeysetVersion {
                    effective_at: start,
                    expires_at: end,
                    ..version("ver_new", &new_key)
                },
                "aud_2",
            )
            .await,
            "KidConflict",
            "ver_old",
            "ver_new",
        );
    }
    // One kid and key with two algorithms (RS256 and PS256).
    let rs = upload(vec![rsa("r1", "RS256")]).await;
    let ps = upload(vec![rsa("r1", "PS256")]).await;
    create(
        &pool,
        TRUST,
        &NewKeysetVersion {
            keyset_id: "ks_2",
            ..version("ver_rs", &rs)
        },
        "aud_2",
    )
    .await
    .unwrap();
    assert_overlap(
        create(
            &pool,
            TRUST,
            &NewKeysetVersion {
                keyset_id: "ks_2",
                ..version("ver_ps", &ps)
            },
            "aud_3",
        )
        .await,
        "AlgorithmConflict",
        "ver_rs",
        "ver_ps",
    );
    // Only the keyset's own versions count: another keyset may reuse both.
    create(
        &pool,
        TRUST,
        &NewKeysetVersion {
            keyset_id: "ks_2",
            ..version("ver_other_ks", &new_key)
        },
        "aud_3",
    )
    .await
    .unwrap();
    assert_eq!(version_count(&pool).await, 3);

    // Allowed: the explicit overlap (same kid, key and algorithm), a window
    // that ends where the old one starts (expiry exclusive), and a disabled
    // create, which runs no check.
    create(&pool, TRUST, &version("ver_same", &same), "aud_4")
        .await
        .unwrap();
    create(
        &pool,
        TRUST,
        &NewKeysetVersion {
            effective_at: t0() - secs(3600),
            expires_at: Some(t0()),
            ..version("ver_before", &new_key)
        },
        "aud_5",
    )
    .await
    .unwrap();
    create(&pool, TRUST, &disabled("ver_new", &new_key), "aud_6")
        .await
        .unwrap();
    // Enabling it is checked.
    assert_overlap(
        enable(&pool, "ver_new", 1, "aud_7").await,
        "KidConflict",
        "ver_old",
        "ver_new",
    );
    assert_eq!(state(&pool, "ver_new").await, (Status::Disabled, 1));
    // A stale revision is refused before the check.
    assert_registry(
        enable(&pool, "ver_new", 2, "aud_7").await,
        |err| matches!(err, RegistryError::StaleRevision),
        "stale before the check",
    );
    // A disable runs no check: the conflicting window is no obstacle.
    disable(&pool, "ver_before", 1, "aud_7").await.unwrap();
    assert_eq!(
        event_summary(&pool).await,
        [
            event("create", "ver_old", None, 1),
            event("create", "ver_rs", None, 1),
            event("create", "ver_other_ks", None, 1),
            event("create", "ver_same", None, 1),
            event("create", "ver_before", None, 1),
            event("create", "ver_new", None, 1),
            event("disable", "ver_before", Some(1), 2),
        ]
    );
    assert_chain(&pool, 7).await;
    db.drop([pool]).await;
}

/// The rotation path: disable the open-ended old version, then create the
/// replacement with the same `kid`; re-enabling the old version is refused
/// while the replacement is enabled, and accepted once it is disabled.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_rotation_disables_the_old_version_first() {
    let (db, pool) = seeded().await;
    let old = upload(vec![p256_a(KID)]).await;
    let replacement = upload(vec![p256_b(KID)]).await;
    create(&pool, TRUST, &version("ver_old", &old), "aud_1")
        .await
        .unwrap();
    // Not before the old version is disabled.
    assert_overlap(
        create(&pool, TRUST, &version("ver_new", &replacement), "aud_2").await,
        "KidConflict",
        "ver_old",
        "ver_new",
    );
    disable(&pool, "ver_old", 1, "aud_2").await.unwrap();
    create(&pool, TRUST, &version("ver_new", &replacement), "aud_3")
        .await
        .unwrap();
    // The old version comes back only once the replacement is disabled.
    assert_overlap(
        enable(&pool, "ver_old", 2, "aud_4").await,
        "KidConflict",
        "ver_new",
        "ver_old",
    );
    disable(&pool, "ver_new", 1, "aud_4").await.unwrap();
    enable(&pool, "ver_old", 2, "aud_5").await.unwrap();
    // And the replacement is now the one refused.
    assert_overlap(
        enable(&pool, "ver_new", 2, "aud_6").await,
        "KidConflict",
        "ver_old",
        "ver_new",
    );
    // Enabling an enabled version is checked and written like any other.
    let again = enable(&pool, "ver_old", 3, "aud_6").await.unwrap();
    assert_eq!((again.status, again.revision), (Status::Enabled, 4));
    assert_eq!(
        event_summary(&pool).await,
        [
            event("create", "ver_old", None, 1),
            event("disable", "ver_old", Some(1), 2),
            event("create", "ver_new", None, 1),
            event("disable", "ver_new", Some(1), 2),
            event("enable", "ver_old", Some(2), 3),
            event("enable", "ver_old", Some(3), 4),
        ]
    );
    assert_chain(&pool, 6).await;
    db.drop([pool]).await;
}

/// A stored version the check compares is parsed in full: one written
/// through the raw floor with a key off its curve (which `parse_stored`
/// accepts) or a nested private member (which the database floor accepts)
/// stops a version from becoming enabled, as a data-integrity error naming
/// the stored version; one the check does not compare does not.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn stored_versions_are_parsed_in_full_before_the_check() {
    let (db, pool) = seeded().await;
    let off_curve = set(vec![p256_off_curve("bad")]);
    let nested = set(vec![
        json!({"kty": "EC", "kid": "nested", "crv": "P-256", "x": A_X, "y": A_Y,
               "privateKey": {"d": A_D}}),
    ]);
    assert!(parse_stored(off_curve.to_string()).is_ok());
    let open = (t0(), None);
    let earlier = (t0() - secs(3600), Some(t0()));
    // In ks_1, intersecting and enabled.
    raw_version(
        &pool,
        "ver_bad",
        "ks_1",
        off_curve.clone(),
        Status::Enabled,
        open,
    )
    .await;
    // In ks_2: enabled but earlier, and disabled.
    raw_version(
        &pool,
        "ver_early",
        "ks_2",
        off_curve.clone(),
        Status::Enabled,
        earlier,
    )
    .await;
    raw_version(
        &pool,
        "ver_off",
        "ks_2",
        nested.clone(),
        Status::Disabled,
        open,
    )
    .await;
    let keys = upload(vec![p256_b(KID)]).await;

    let stored = |result: Result<TrustKeysetVersion, KeysetWriteError>, id: &str, rule: &str| {
        let err = result.expect_err("a stored version error");
        match (&err, rule) {
            (
                KeysetWriteError::StoredVersion {
                    version_id,
                    error: JwkSetError::Key { index: 0, error },
                },
                "point",
            ) if version_id == id && matches!(error, JwkError::PointNotOnCurve) => {}
            (
                KeysetWriteError::StoredVersion {
                    version_id,
                    error:
                        JwkSetError::Key {
                            index: 0,
                            error: JwkError::UnexpectedMember,
                        },
                },
                "member",
            ) if version_id == id => {}
            _ => panic!("{id} {rule}: {err:?}"),
        }
        assert_eq!(
            err.to_string(),
            "a stored version of the keyset breaks the JWK set rules"
        );
        assert_eq!(format!("{err:?}"), "StoredVersion { .. }");
        assert!(err.source().is_none());
        assert_redacted(&err, &[id, "bad", "nested"]);
    };
    stored(
        create(&pool, TRUST, &version("ver_1", &keys), "aud_1").await,
        "ver_bad",
        "point",
    );
    // A disabled create compares nothing.
    create(&pool, TRUST, &disabled("ver_1", &keys), "aud_1")
        .await
        .unwrap();
    stored(enable(&pool, "ver_1", 1, "aud_2").await, "ver_bad", "point");
    // A create reusing a stored version's ID does not compare (or parse)
    // that row: the insert refuses the ID.
    assert_registry(
        create(&pool, TRUST, &version("ver_bad", &keys), "aud_2").await,
        |err| {
            matches!(
                err,
                RegistryError::AlreadyExists {
                    constraint: "trust_keyset_version_pkey"
                }
            )
        },
        "the ID of a stored version",
    );

    // ks_2: neither the earlier nor the disabled version is compared.
    let in_ks_2 = |id| NewKeysetVersion {
        keyset_id: "ks_2",
        ..version(id, &keys)
    };
    create(&pool, TRUST, &in_ks_2("ver_2"), "aud_2")
        .await
        .unwrap();
    // But enabling one parses it in full first.
    stored(
        enable(&pool, "ver_off", 1, "aud_3").await,
        "ver_off",
        "member",
    );
    // A disable parses nothing.
    disable(&pool, "ver_bad", 1, "aud_3").await.unwrap();
    disable(&pool, "ver_early", 1, "aud_4").await.unwrap();
    assert_eq!(
        event_summary(&pool).await,
        [
            event("create", "ver_1", None, 1),
            event("create", "ver_2", None, 1),
            event("disable", "ver_bad", Some(1), 2),
            event("disable", "ver_early", Some(1), 2),
        ]
    );
    // With the bad version disabled, ver_1 becomes enabled.
    enable(&pool, "ver_1", 1, "aud_5").await.unwrap();
    assert_chain(&pool, 5).await;
    db.drop([pool]).await;
}

/// A private member, top-level in a key or nested deeper, is refused in
/// Stage A, so it never reaches a write; the database floor refuses the
/// top-level one written raw and, being a floor, accepts the nested one.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_private_member_never_reaches_the_database_through_this_path() {
    let (db, pool) = seeded().await;
    let top_level = set(vec![
        json!({"kty": "EC", "kid": KID, "crv": "P-256", "x": A_X, "y": A_Y, "d": A_D}),
    ]);
    let nested = set(vec![
        json!({"kty": "EC", "kid": KID, "crv": "P-256", "x": A_X, "y": A_Y,
               "privateKey": {"d": A_D}}),
    ]);
    for (upload, expected) in [
        (&top_level, JwkError::PrivateMember("d")),
        (&nested, JwkError::UnexpectedMember),
    ] {
        let err = validate_upload(upload.clone(), DEFAULT_ALLOWED_ALGORITHMS)
            .await
            .expect_err("a private member");
        match &err {
            KeysetWriteError::Upload(JwkSetError::Key { index: 0, error }) => {
                assert_eq!(*error, expected);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            err.to_string(),
            "the uploaded JWK set breaks the JWK set rules"
        );
        assert_eq!(format!("{err:?}"), "Upload(..)");
        assert!(err.source().is_none());
        assert_redacted(&err, &[]);
    }
    // No ValidatedKeyset exists for either, so no write can take it.
    assert_eq!(version_count(&pool).await, 0);

    let insert = |jwks: &Value| {
        let pool = pool.clone();
        let jwks = jwks.clone();
        async move {
            sqlx::query(
                "INSERT INTO trust_keyset_version (id, tenant_id, keyset_id, public_jwks, \
                 fingerprint, effective_at, status, provenance) VALUES ('ver_raw', 'ten_a', \
                 'ks_1', $1, 'raw', now(), 'enabled', '{}')",
            )
            .bind(sqlx::types::Json(jwks))
            .execute(&pool)
            .await
        }
    };
    // The floor refuses the top-level member written raw.
    let err = insert(&top_level).await.expect_err("the 0004 check");
    let db_err = err.as_database_error().unwrap();
    assert_eq!(
        (db_err.code().as_deref(), db_err.constraint()),
        (
            Some("23514"),
            Some("trust_keyset_version_public_jwks_check")
        )
    );
    // It does not look below a key's own members: the nested one passes it.
    insert(&nested).await.unwrap();
    assert_eq!(version_count(&pool).await, 1);
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

/// Two creates of one `kid` with different keys and intersecting windows,
/// on two connections: the second waits for the parent keyset row the
/// first holds, then reads the first's committed version and is refused.
/// Exactly one succeeds. Then the same race, unstaged.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn two_writes_of_one_keyset_serialize_on_the_parent_row() {
    let (db, pool) = seeded().await;
    let first_keys = upload(vec![p256_a(KID)]).await;
    let second_keys = upload(vec![p256_b(KID)]).await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut tx = first.begin().await.unwrap();
    create_version(
        &mut tx,
        TRUST,
        &version("ver_a", &first_keys),
        &audit("aud_1"),
    )
    .await
    .unwrap();
    let task = tokio::spawn(async move {
        let mut tx = second.begin().await.unwrap();
        let result = create_version(
            &mut tx,
            TRUST,
            &NewKeysetVersion {
                effective_at: t0() + secs(60),
                ..version("ver_b", &second_keys)
            },
            &audit("aud_2"),
        )
        .await;
        finish(tx, &result).await;
        (result, second)
    });
    wait_until_blocked(&pool, second_pid, first_pid, &task).await;
    tx.commit().await.unwrap();
    let (result, second) = join(task).await;
    assert_overlap(result, "KidConflict", "ver_a", "ver_b");
    second.close().await.unwrap();
    first.close().await.unwrap();
    assert_eq!(version_count(&pool).await, 1);

    // Unstaged, in another keyset: exactly one of the two succeeds.
    let race = |id: &'static str, keys: ValidatedKeyset, event_id: &'static str| {
        let pool = pool.clone();
        tokio::spawn(async move {
            let new = NewKeysetVersion {
                keyset_id: "ks_2",
                ..version(id, &keys)
            };
            create(&pool, TRUST, &new, event_id).await
        })
    };
    let (left, right) = (
        race("ver_left", upload(vec![p256_a(KID)]).await, "aud_3"),
        race("ver_right", upload(vec![p256_b(KID)]).await, "aud_4"),
    );
    let results = [join(left).await, join(right).await];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .any(|result| matches!(result, Err(KeysetWriteError::Overlap(_))))
    );
    assert_eq!(version_count(&pool).await, 2);
    assert_chain(&pool, 2).await;
    db.drop([pool]).await;
}

/// The event is appended after the write: while the write waits for a lock
/// (the tenant row its insert's foreign-key check needs, or the version row
/// its update needs, held elsewhere), it does not hold the audit head, so
/// another transaction appends meanwhile.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_audit_event_comes_after_the_write() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &version("ver_1", &keys), "aud_0")
        .await
        .unwrap();
    for (n, (hold_sql, other_tenant)) in [
        ("SELECT FROM tenant WHERE id = 'ten_a' FOR UPDATE", "ten_b"),
        (
            "SELECT FROM trust_keyset_version WHERE id = 'ver_1' FOR UPDATE",
            "ten_a",
        ),
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
        let mut hold = holder.begin().await.unwrap();
        sqlx::query(hold_sql).execute(&mut *hold).await.unwrap();
        let keys = keys.clone();
        let task = tokio::spawn(async move {
            let mut tx = writer.begin().await.unwrap();
            let result = if n == 0 {
                create_version(&mut tx, TRUST, &disabled("ver_2", &keys), &audit("aud_w0")).await
            } else {
                disable_version(&mut tx, TRUST, "ten_a", "ver_1", 1, &audit("aud_w1")).await
            };
            finish(tx, &result).await;
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
                id: format!("aud_other_{n}"),
                tenant_id: Some(other_tenant.into()),
                timestamp: now(),
                actor: AuditActor::Operator("adm_trust".into()),
                action: "trust_keyset.update".into(),
                object_id: "ks_x".into(),
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
    }
    assert_eq!(
        event_summary(&pool)
            .await
            .into_iter()
            .map(|event| (event.0, event.1))
            .collect::<Vec<_>>(),
        [
            ("trust_keyset_version.create", "ver_1"),
            ("trust_keyset.update", "ks_x"),
            ("trust_keyset_version.create", "ver_2"),
            ("trust_keyset.update", "ks_x"),
            ("trust_keyset_version.disable", "ver_1"),
        ]
        .map(|(action, id)| (action.to_string(), id.to_string()))
    );
    assert_chain(&pool, 5).await;
    db.drop([pool]).await;
}

/// An audit append that fails after the registry write (here a reused event
/// id) undoes the write: the caller's transaction stays usable and holds
/// neither the new version nor the changed status.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_failed_audit_append_undoes_the_write() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &version("ver_kept", &keys), "aud_1")
        .await
        .unwrap();
    create(&pool, TRUST, &disabled("ver_off", &keys), "aud_2")
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
    for new in [version("ver_lost", &keys), disabled("ver_lost", &keys)] {
        assert_registry(
            create_version(&mut tx, TRUST, &new, &audit("aud_1")).await,
            reused,
            "create",
        );
    }
    let lost: i64 =
        sqlx::query_scalar("SELECT count(*) FROM trust_keyset_version WHERE id = 'ver_lost'")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(lost, 0);
    assert_registry(
        disable_version(&mut tx, TRUST, "ten_a", "ver_kept", 1, &audit("aud_1")).await,
        reused,
        "disable",
    );
    assert_registry(
        enable_version(&mut tx, TRUST, "ten_a", "ver_off", 1, &audit("aud_1")).await,
        reused,
        "enable",
    );
    let kept: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT id, status, revision FROM trust_keyset_version ORDER BY id")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    assert_eq!(
        kept,
        [("ver_kept", "enabled", 1), ("ver_off", "disabled", 1)].map(|(id, status, revision)| (
            id.to_string(),
            status.to_string(),
            revision
        ))
    );
    tx.commit().await.unwrap();
    assert_eq!(version_count(&pool).await, 2);
    assert_eq!(events(&pool).await.len(), 2);
    assert_chain(&pool, 2).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn isolation_other_than_read_committed_is_refused_before_any_lock() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &version("ver_1", &keys), "aud_1")
        .await
        .unwrap();
    for level in ["REPEATABLE READ", "SERIALIZABLE", "READ UNCOMMITTED"] {
        for write in ["create", "enable", "disable"] {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SET TRANSACTION ISOLATION LEVEL {level}"
            )))
            .execute(&mut *tx)
            .await
            .unwrap();
            let audit = audit("aud_2");
            let result = match write {
                "create" => create_version(&mut tx, TRUST, &version("ver_2", &keys), &audit).await,
                "enable" => enable_version(&mut tx, TRUST, "ten_a", "ver_1", 1, &audit).await,
                _ => disable_version(&mut tx, TRUST, "ten_a", "ver_1", 1, &audit).await,
            };
            match &result {
                Err(err @ KeysetWriteError::UnsupportedIsolation) => {
                    assert_eq!(
                        err.to_string(),
                        "trust keyset version writes run only at READ COMMITTED"
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
                "SELECT FROM trust_keyset WHERE id = 'ks_1' FOR UPDATE NOWAIT",
                "SELECT FROM trust_keyset_version WHERE id = 'ver_1' FOR UPDATE NOWAIT",
                "SELECT FROM tenant WHERE id = 'ten_a' FOR UPDATE NOWAIT",
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
    assert_eq!(version_count(&pool).await, 1);
    assert_eq!(state(&pool, "ver_1").await, (Status::Enabled, 1));
    assert_chain(&pool, 1).await;
    db.drop([pool]).await;
}

/// The write path holds the parent keyset row until the transaction ends:
/// a keyset update times out while it is open.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_write_holds_the_parent_keyset_row() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &version("ver_1", &keys), "aud_0")
        .await
        .unwrap();
    for (n, write) in ["create", "disable", "enable"].into_iter().enumerate() {
        let mut tx = pool.begin().await.unwrap();
        let audit = audit(["aud_1", "aud_2", "aud_3"][n]);
        match write {
            "create" => {
                create_version(&mut tx, TRUST, &disabled("ver_2", &keys), &audit)
                    .await
                    .unwrap();
            }
            "disable" => {
                disable_version(&mut tx, TRUST, "ten_a", "ver_1", 1, &audit)
                    .await
                    .unwrap();
            }
            _ => {
                enable_version(&mut tx, TRUST, "ten_a", "ver_1", 2, &audit)
                    .await
                    .unwrap();
            }
        }
        let mut probe = pool.begin().await.unwrap();
        let err =
            sqlx::query("SELECT FROM trust_keyset WHERE id = 'ks_1' FOR NO KEY UPDATE NOWAIT")
                .execute(&mut *probe)
                .await
                .expect_err("the parent row is held");
        assert_eq!(
            err.as_database_error()
                .and_then(|err| err.code())
                .as_deref(),
            Some("55P03"),
            "{write}"
        );
        probe.rollback().await.unwrap();
        // FOR KEY SHARE (a trust source insert's foreign-key check) is not
        // blocked.
        sqlx::query("SELECT FROM trust_keyset WHERE id = 'ks_1' FOR KEY SHARE NOWAIT")
            .execute(&pool)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    assert_chain(&pool, 4).await;
    db.drop([pool]).await;
}

/// An enable that reaches the parent keyset row while a create of the same
/// keyset holds it waits, then reads the committed version and is refused:
/// the versions are read only after the parent lock is granted.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_enable_waits_for_a_create_of_the_same_keyset() {
    let (db, pool) = seeded().await;
    let old = upload(vec![p256_a(KID)]).await;
    let replacement = upload(vec![p256_b(KID)]).await;
    create(&pool, TRUST, &disabled("ver_old", &old), "aud_1")
        .await
        .unwrap();
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut tx = first.begin().await.unwrap();
    create_version(
        &mut tx,
        TRUST,
        &version("ver_new", &replacement),
        &audit("aud_2"),
    )
    .await
    .unwrap();
    let task = tokio::spawn(async move {
        let mut tx = second.begin().await.unwrap();
        let result = enable_version(&mut tx, TRUST, "ten_a", "ver_old", 1, &audit("aud_3")).await;
        finish(tx, &result).await;
        (result, second)
    });
    wait_until_blocked(&pool, second_pid, first_pid, &task).await;
    tx.commit().await.unwrap();
    let (result, second) = join(task).await;
    assert_overlap(result, "KidConflict", "ver_new", "ver_old");
    second.close().await.unwrap();
    first.close().await.unwrap();
    assert_eq!(state(&pool, "ver_old").await, (Status::Disabled, 1));
    assert_chain(&pool, 2).await;
    db.drop([pool]).await;
}

/// The isolation check comes before the operator lookup: an unknown
/// credential in a `SERIALIZABLE` transaction is refused for its isolation,
/// not for its credential.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_isolation_is_checked_before_the_operator() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    create(&pool, TRUST, &version("ver_1", &keys), "aud_1")
        .await
        .unwrap();
    for write in ["create", "enable", "disable"] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .unwrap();
        let audit = audit("aud_2");
        let key = "key_unknown";
        let result = match write {
            "create" => create_version(&mut tx, key, &version("ver_2", &keys), &audit).await,
            "enable" => enable_version(&mut tx, key, "ten_a", "ver_1", 1, &audit).await,
            _ => disable_version(&mut tx, key, "ten_a", "ver_1", 1, &audit).await,
        };
        assert!(
            matches!(result, Err(KeysetWriteError::UnsupportedIsolation)),
            "{write}: {result:?}"
        );
        tx.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

/// A refusal rolls its savepoint back, which releases the locks it took:
/// while the caller's transaction is still open after an overlap refusal,
/// the parent keyset row and the operator rows are free.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_refusal_releases_the_locks_it_took() {
    let (db, pool) = seeded().await;
    let old = upload(vec![p256_a(KID)]).await;
    let replacement = upload(vec![p256_b(KID)]).await;
    create(&pool, TRUST, &version("ver_old", &old), "aud_1")
        .await
        .unwrap();
    create(&pool, TRUST, &disabled("ver_new", &replacement), "aud_2")
        .await
        .unwrap();
    for write in ["create", "enable"] {
        let mut tx = pool.begin().await.unwrap();
        let audit = audit("aud_3");
        let result = match write {
            "create" => {
                create_version(&mut tx, TRUST, &version("ver_x", &replacement), &audit).await
            }
            _ => enable_version(&mut tx, TRUST, "ten_a", "ver_new", 1, &audit).await,
        };
        assert!(
            matches!(result, Err(KeysetWriteError::Overlap(_))),
            "{write}: {result:?}"
        );
        let mut probe = pool.begin().await.unwrap();
        for sql in [
            "SELECT FROM admin_identity WHERE id = 'adm_trust' FOR UPDATE NOWAIT",
            "SELECT FROM admin_credential WHERE id = 'crd_adm_trust' FOR UPDATE NOWAIT",
            "SELECT FROM admin_role_binding WHERE id = 'rb_adm_trust' FOR UPDATE NOWAIT",
            "SELECT FROM trust_keyset WHERE id = 'ks_1' FOR UPDATE NOWAIT",
        ] {
            sqlx::query(sql)
                .execute(&mut *probe)
                .await
                .unwrap_or_else(|err| panic!("{write}: {sql}: {err}"));
        }
        probe.rollback().await.unwrap();
        tx.rollback().await.unwrap();
    }
    assert_chain(&pool, 2).await;
    db.drop([pool]).await;
}

/// The overlap check sees the window the registry stores, floored to whole
/// microseconds: a window ending 500 ns after an enabled version starts is
/// stored as ending where it starts, and is accepted whether it is created
/// enabled or created disabled and then enabled. A window that is empty
/// once floored is the `0004` validity check's, not an overlap.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_window_is_checked_as_the_registry_stores_it() {
    let (db, pool) = seeded().await;
    let old = upload(vec![p256_a(KID)]).await;
    let replacement = upload(vec![p256_b(KID)]).await;
    let (t1, t2) = (t0() + secs(3600), t0() + secs(7200));
    let half = Duration::from_nanos(500);
    create(
        &pool,
        TRUST,
        &NewKeysetVersion {
            effective_at: t1,
            expires_at: Some(t2),
            ..version("ver_mid", &old)
        },
        "aud_1",
    )
    .await
    .unwrap();
    let before = |id| NewKeysetVersion {
        expires_at: Some(t1 + half),
        ..version(id, &replacement)
    };
    let created = create(&pool, TRUST, &before("ver_enabled"), "aud_2")
        .await
        .unwrap();
    assert_eq!(created.expires_at, Some(t1));
    create(
        &pool,
        TRUST,
        &NewKeysetVersion {
            status: Status::Disabled,
            ..before("ver_later")
        },
        "aud_3",
    )
    .await
    .unwrap();
    enable(&pool, "ver_later", 1, "aud_4").await.unwrap();
    // Unfloored, these windows intersect ver_mid's: the conflict is real
    // one microsecond later.
    assert_overlap(
        create(
            &pool,
            TRUST,
            &NewKeysetVersion {
                expires_at: Some(t1 + Duration::from_micros(1)),
                ..version("ver_late", &replacement)
            },
            "aud_5",
        )
        .await,
        "KidConflict",
        "ver_mid",
        "ver_late",
    );
    // [T, T + 500 ns) inside ver_mid, with a conflicting kid: empty once
    // floored, so the database refuses it, not the overlap check.
    let start = t1 + secs(10);
    for status in [Status::Enabled, Status::Disabled] {
        assert_registry(
            create(
                &pool,
                TRUST,
                &NewKeysetVersion {
                    effective_at: start,
                    expires_at: Some(start + half),
                    status,
                    ..version("ver_empty", &replacement)
                },
                "aud_5",
            )
            .await,
            |err| {
                matches!(
                    err,
                    RegistryError::Invariant {
                        kind: InvariantKind::Check,
                        constraint: Some("trust_keyset_version_validity_check")
                    }
                )
            },
            "empty once floored",
        );
    }
    assert_eq!(version_count(&pool).await, 3);
    assert_chain(&pool, 4).await;
    db.drop([pool]).await;
}

/// A keyset has at most [`trust::MAX_ENABLED_VERSIONS_PER_KEYSET`] enabled
/// versions: the eighth is accepted, a ninth (created enabled or enabled
/// later) is refused before any stored version is parsed, disabled
/// versions and a re-enabled version itself do not count, and a disable
/// makes room.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_keyset_has_at_most_eight_enabled_versions() {
    let (db, pool) = seeded().await;
    assert_eq!(trust::MAX_ENABLED_VERSIONS_PER_KEYSET, 8);
    let keys = upload(vec![p256_a(KID)]).await;
    let ids: Vec<String> = (1..=10).map(|n| format!("ver_{n:02}")).collect();
    for id in &ids[..7] {
        create(&pool, TRUST, &version(id, &keys), &format!("aud_{id}"))
            .await
            .unwrap_or_else(|err| panic!("{id}: {err:?}"));
    }
    // The eighth, written raw with a key off its curve: any parse of it
    // fails, so a refusal that names the bound came before the parse.
    raw_version(
        &pool,
        "ver_08",
        "ks_1",
        set(vec![p256_off_curve("bad")]),
        Status::Enabled,
        (t0(), None),
    )
    .await;
    let too_many = |result: Result<TrustKeysetVersion, KeysetWriteError>, case: &str| {
        let err = result.expect_err(case);
        assert!(
            matches!(err, KeysetWriteError::TooManyEnabledVersions),
            "{case}: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "the keyset already has the most enabled versions allowed"
        );
        assert_eq!(format!("{err:?}"), "TooManyEnabledVersions");
        assert!(err.source().is_none());
    };
    too_many(
        create(&pool, TRUST, &version(&ids[8], &keys), "aud_9").await,
        "a ninth create",
    );
    // A disabled version does not count, and is created.
    create(&pool, TRUST, &disabled(&ids[8], &keys), "aud_9")
        .await
        .unwrap();
    too_many(enable(&pool, &ids[8], 1, "aud_10").await, "a ninth enable");
    // A re-enable does not count itself: it passes the bound and reaches
    // the parse of the stored versions.
    match enable(&pool, &ids[0], 1, "aud_10").await {
        Err(KeysetWriteError::StoredVersion { version_id, .. }) => {
            assert_eq!(version_id, "ver_08");
        }
        other => panic!("re-enable at the bound: {other:?}"),
    }
    // A disable makes room; the eighth enabled version is accepted.
    disable(&pool, "ver_08", 1, "aud_11").await.unwrap();
    enable(&pool, &ids[8], 1, "aud_12").await.unwrap();
    enable(&pool, &ids[0], 1, "aud_13").await.unwrap();
    too_many(
        create(&pool, TRUST, &version(&ids[9], &keys), "aud_14").await,
        "a ninth create, all parseable",
    );
    // A create reusing an enabled version's ID does not count that row: it
    // passes the bound and the insert refuses the ID.
    assert_registry(
        create(&pool, TRUST, &version(&ids[0], &keys), "aud_14").await,
        |err| {
            matches!(
                err,
                RegistryError::AlreadyExists {
                    constraint: "trust_keyset_version_pkey"
                }
            )
        },
        "the ID of an enabled version at the bound",
    );
    // The bound is per keyset.
    create(
        &pool,
        TRUST,
        &NewKeysetVersion {
            keyset_id: "ks_2",
            ..version(&ids[9], &keys)
        },
        "aud_14",
    )
    .await
    .unwrap();
    let enabled: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM trust_keyset_version WHERE keyset_id = 'ks_1' AND status = 'enabled'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(enabled, 8);
    assert_eq!(version_count(&pool).await, 10);
    db.drop([pool]).await;
}

/// Two transactions that each write one keyset and then the other's
/// deadlock: the first holds the audit head when it asks for the second
/// keyset, which the second holds while it waits for the head. PostgreSQL
/// aborts exactly one statement with `40P01`, which is
/// `Registry(Retry)`; that transaction rolls back and the other commits.
/// Which one loses depends on whose deadlock check runs first, so the test
/// accepts either, but exactly one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn two_keysets_in_one_transaction_can_deadlock_into_a_retry() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    let mut first = pool.begin().await.unwrap();
    let mut second = pool.begin().await.unwrap();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let write = |mut tx: Transaction<'static, Postgres>,
                 id: &'static str,
                 keyset_id: &'static str,
                 event_id: &'static str| {
        let keys = keys.clone();
        async move {
            let new = NewKeysetVersion {
                keyset_id,
                ..disabled(id, &keys)
            };
            let result = create_version(&mut tx, TRUST, &new, &audit(event_id)).await;
            (tx, result)
        }
    };
    // The first holds ks_1 and the audit head.
    create_version(
        &mut first,
        TRUST,
        &disabled("ver_1", &keys),
        &audit("aud_1"),
    )
    .await
    .unwrap();
    // The second takes ks_2, then waits for the head.
    let second_task = tokio::spawn(write(second, "ver_2", "ks_2", "aud_2"));
    wait_until_blocked(&pool, second_pid, first_pid, &second_task).await;
    // The first now asks for ks_2.
    let first_task = tokio::spawn(write(first, "ver_3", "ks_2", "aud_3"));
    let mut tasks = [Some(first_task), Some(second_task)];
    let done = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(index) = tasks
                .iter()
                .position(|task| task.as_ref().is_some_and(|task| task.is_finished()))
            {
                return index;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the deadlock was never resolved");
    // Whichever returned first is finished first (a losing first still
    // holds the audit head the second waits for); `finish` shows a loser's
    // transaction is usable and rolls it back whole.
    let (tx, done_result) = join(tasks[done].take().unwrap()).await;
    finish(tx, &done_result).await;
    let (tx, other_result) = join(tasks[1 - done].take().unwrap()).await;
    finish(tx, &other_result).await;
    let (first_result, second_result) = if done == 0 {
        (done_result, other_result)
    } else {
        (other_result, done_result)
    };
    let (err, kept, events) = match (first_result, second_result) {
        (Err(err), Ok(winner)) => (err, vec![winner.id], 1),
        (Ok(winner), Err(err)) => (err, vec!["ver_1".to_string(), winner.id], 2),
        other => panic!("expected exactly one deadlock victim: {other:?}"),
    };
    let KeysetWriteError::Registry(registry_err) = &err else {
        panic!("expected Registry(Retry), got {err:?}");
    };
    assert!(matches!(registry_err, RegistryError::Retry(_)), "{err:?}");
    assert_eq!(
        format!("{err:?}"),
        r#"Registry(Retry { sqlstate: Some("40P01"), .. })"#
    );
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM trust_keyset_version ORDER BY id COLLATE \"C\"")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(ids, kept);
    assert_chain(&pool, events).await;
    db.drop([pool]).await;
}

/// A provenance naming a JWK private member, at any depth, is refused
/// before any statement, and nothing is written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_provenance_naming_a_private_member_is_refused() {
    let (db, pool) = seeded().await;
    let keys = upload(vec![p256_a(KID)]).await;
    for provenance in [
        json!({"supplied_by": "operator", "d": A_D}),
        json!({"supplied_by": "operator", "upload": {"keys": [{"kty": "EC", "d": A_D}]}}),
        json!({"history": [{"jwk": {"kty": "oct", "k": A_X}}]}),
    ] {
        let provenance = provenance.as_object().unwrap().clone();
        for status in [Status::Enabled, Status::Disabled] {
            let new = NewKeysetVersion {
                provenance: &provenance,
                status,
                ..version("ver_1", &keys)
            };
            // Even in a transaction no write may run in: no statement runs.
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *tx)
                .await
                .unwrap();
            let result = create_version(&mut tx, "key_unknown", &new, &audit("aud_1")).await;
            tx.rollback().await.unwrap();
            let err = result.expect_err("a private member in the provenance");
            assert!(
                matches!(err, KeysetWriteError::PrivateMemberInProvenance),
                "{err:?}"
            );
            assert_eq!(
                err.to_string(),
                "the keyset version's provenance names a JWK private member"
            );
            assert_redacted(&err, &[]);
            let err = create(&pool, TRUST, &new, "aud_1").await.unwrap_err();
            assert!(
                matches!(err, KeysetWriteError::PrivateMemberInProvenance),
                "{err:?}"
            );
        }
    }
    // Names only: a value, or a longer name, is no private member.
    let allowed = json!({"supplied_by": "d", "d_source": ["k", "p"]})
        .as_object()
        .unwrap()
        .clone();
    let created = create(
        &pool,
        TRUST,
        &NewKeysetVersion {
            provenance: &allowed,
            ..version("ver_1", &keys)
        },
        "aud_1",
    )
    .await
    .unwrap();
    assert_eq!(created.provenance, allowed);
    assert_eq!(version_count(&pool).await, 1);
    assert_chain(&pool, 1).await;
    db.drop([pool]).await;
}

/// The module is reachable as `skyoauth_service::trust` with its bound.
#[test]
fn the_module_is_reachable() {
    assert_eq!(trust::VALIDATION_WORKERS, 2);
}
