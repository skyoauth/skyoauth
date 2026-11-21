//! The typed registry surface over the `0004` tables
//! (`persistence::registry`) against a real PostgreSQL server: trust
//! keysets and their versions, trust sources of each kind, principal
//! bindings, service identities and service grants with their list rows.
//! Each entity's create, read, list and update; not-found, stale-revision
//! and tenant-isolation outcomes; the mapping of its named constraint
//! errors; the per-kind source rules; the binding-set check of a grant
//! through the registry, at commit and under concurrency; races of updates
//! from one revision; and stored times outside the `0007` range checks.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. They claim no conformance
//! scenario.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    collections::BTreeMap,
    error::Error as _,
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use serde_json::{Value, json};
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, ActivationState, AssertionProfile, BindingProfile, GrantMode, InvariantKind,
        JsonObject, NewAudienceTenantAssignment, NewPrincipal, NewPrincipalBinding,
        NewResourceServer, NewServiceGrant, NewServiceIdentity, NewTenant, NewTrustKeyset,
        NewTrustKeysetVersion, NewTrustSource, Page, PrincipalBindingChanges, PrincipalKind,
        Profile, RegistryError, ReplayMode, ServiceGrant, ServiceGrantChanges,
        ServiceIdentityChanges, Status, TrustKeysetChanges, TrustSource, TrustSourceChanges,
        TrustSourceKind,
    },
};
use sqlx::{Connection, PgConnection};

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// The registry error of a raw statement that must fail.
async fn raw_error(pool: &PgPool, sql: &'static str) -> RegistryError {
    let err = sqlx::raw_sql(sql).execute(pool).await.expect_err(sql);
    RegistryError::from(err)
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn at(micros: i64) -> SystemTime {
    let offset = Duration::from_micros(micros.unsigned_abs());
    if micros >= 0 {
        UNIX_EPOCH + offset
    } else {
        UNIX_EPOCH - offset
    }
}

fn new_tenant(id: &str) -> NewTenant {
    NewTenant {
        id: id.into(),
        name: format!("Tenant {id}"),
        secret_namespace: format!("ns_{id}"),
        status: Status::Enabled,
    }
}

fn new_principal(tenant_id: &str, id: &str, kind: PrincipalKind) -> NewPrincipal {
    NewPrincipal {
        id: id.into(),
        tenant_id: tenant_id.into(),
        kind,
        name: format!("principal {id}"),
        status: Status::Enabled,
    }
}

fn new_server(id: &str) -> NewResourceServer {
    NewResourceServer {
        id: id.into(),
        audience: format!("{id}-api"),
        name: format!("Server {id}"),
        allowed_profiles: vec![Profile::Wif],
        scopes: strings(&["read", "deploy:write"]),
        constraint_versions: vec![],
        status: Status::Enabled,
    }
}

fn new_assignment(
    id: &str,
    resource_server_id: &str,
    tenant_id: &str,
) -> NewAudienceTenantAssignment {
    NewAudienceTenantAssignment {
        id: id.into(),
        resource_server_id: resource_server_id.into(),
        tenant_id: tenant_id.into(),
        allowed_profiles: vec![Profile::Wif],
        allowed_scopes: strings(&["read"]),
        constraint_versions: vec![],
        status: Status::Enabled,
    }
}

fn new_keyset(tenant_id: &str, id: &str, name: &str) -> NewTrustKeyset {
    NewTrustKeyset {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: name.into(),
        status: Status::Enabled,
    }
}

fn new_version(tenant_id: &str, id: &str, keyset_id: &str) -> NewTrustKeysetVersion {
    NewTrustKeysetVersion {
        id: id.into(),
        tenant_id: tenant_id.into(),
        keyset_id: keyset_id.into(),
        public_jwks: object(json!({
            "keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AA", "y": "AA"}]
        })),
        fingerprint: "sha256:01".into(),
        effective_at: at(1_767_323_045_678_901),
        expires_at: Some(at(1_798_859_045_000_001)),
        status: Status::Enabled,
        provenance: object(json!({"uploaded_by": "adm_1"})),
    }
}

/// An `oidc_discovery` source with an on-demand, single-use profile.
fn oidc_source(tenant_id: &str, id: &str, name: &str) -> NewTrustSource {
    NewTrustSource {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: name.into(),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: "https://token.actions.githubusercontent.com".into(),
        discovery_url: Some(
            "https://token.actions.githubusercontent.com/.well-known/openid-configuration".into(),
        ),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: strings(&["https://identity.example.com"]),
        algorithms: Some(strings(&["RS256"])),
        proof_bounds: JsonObject::new(),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    }
}

/// An `uploaded_jwks` source of `keyset_id` with a reusable profile.
fn jwks_source(tenant_id: &str, id: &str, name: &str, keyset_id: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::UploadedJwks,
        exact_issuer: "https://ci.partner.example".into(),
        discovery_url: None,
        jwks_keyset_id: Some(keyset_id.into()),
        algorithms: Some(strings(&["ES256"])),
        proof_bounds: object(json!({"max_age_seconds": 300})),
        assertion_profile: AssertionProfile::ReusableJwt,
        replay_mode: ReplayMode::Reusable,
        ..oidc_source(tenant_id, id, name)
    }
}

/// A `kubernetes_token_review` source of cluster `cluster_id`.
fn token_review_source(tenant_id: &str, id: &str, name: &str, cluster_id: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::KubernetesTokenReview,
        exact_issuer: "https://kubernetes.default.svc".into(),
        discovery_url: None,
        cluster_id: Some(cluster_id.into()),
        token_review_endpoint: Some("https://k3s.internal.example:6443".into()),
        ca_bundle_ref: Some("ca_k3s".into()),
        ca_fingerprint: Some("sha256:ca".into()),
        reviewer_credential_ref: Some("reviewer_k3s".into()),
        review_timeout_ms: Some(5000),
        algorithms: None,
        assertion_profile: AssertionProfile::ProjectedServiceAccount,
        replay_mode: ReplayMode::Reusable,
        ..oidc_source(tenant_id, id, name)
    }
}

/// The mutable columns of `source`, unchanged.
fn source_changes(source: &TrustSource) -> TrustSourceChanges {
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

fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

/// The predicates `github_production` requires (`0008`), with the values
/// of the design section 5.7 example.
fn github_claims() -> BTreeMap<String, String> {
    claims(&[
        ("repository_owner_id", "123456"),
        ("repository_id", "456789"),
        ("event_name", "push"),
        ("ref", "refs/heads/main"),
        ("environment", "production"),
        (
            "workflow_ref",
            "acme/platform/.github/workflows/deploy.yml@refs/heads/main",
        ),
    ])
}

fn new_binding(tenant_id: &str, id: &str, source: &str, principal: &str) -> NewPrincipalBinding {
    NewPrincipalBinding {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: format!("binding-{id}"),
        trust_source_id: source.into(),
        profile: BindingProfile::GithubProduction,
        claim_match_policy: github_claims(),
        workload_principal_id: principal.into(),
        status: Status::Enabled,
    }
}

fn new_service(tenant_id: &str, id: &str, resource_server_ids: &[&str]) -> NewServiceIdentity {
    NewServiceIdentity {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: format!("service-{id}"),
        max_scopes: strings(&["read"]),
        max_resource_constraints: object(json!({"version": 1})),
        resource_server_ids: strings(resource_server_ids),
        status: Status::Enabled,
    }
}

/// A direct grant of `actor` with `bindings` and the audience `rs_1`.
fn direct_grant(tenant_id: &str, id: &str, actor: &str, bindings: &[&str]) -> NewServiceGrant {
    NewServiceGrant {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: format!("grant-{id}"),
        actor_principal_id: actor.into(),
        target_service_id: None,
        mode: GrantMode::Direct,
        scopes: strings(&["read", "deploy:write"]),
        default_scopes: Some(strings(&["read"])),
        resource_constraints: JsonObject::new(),
        max_ttl: 300,
        valid_until: None,
        status: Status::Enabled,
        activation_state: ActivationState::NotRequired,
        allowed_binding_ids: strings(bindings),
        resource_server_ids: if tenant_id == "ten_a" {
            strings(&["rs_1"])
        } else {
            vec![]
        },
    }
}

fn grant_changes(grant: &ServiceGrant) -> ServiceGrantChanges {
    ServiceGrantChanges {
        name: grant.name.clone(),
        scopes: grant.scopes.clone(),
        default_scopes: grant.default_scopes.clone(),
        resource_constraints: grant.resource_constraints.clone(),
        max_ttl: grant.max_ttl,
        valid_until: grant.valid_until,
        status: grant.status,
        activation_state: grant.activation_state,
    }
}

/// Tenants `ten_a` and `ten_b`. In `ten_a`: workloads `wld_1` and `wld_2`,
/// services `svc_1` and `svc_2`, human `usr_1`; resource servers `rs_1` and
/// `rs_3` assigned; keyset `ks_1`; sources `src_gh` (OIDC), `src_up`
/// (uploaded, `ks_1`) and `src_k8s` (TokenReview, `cluster_1`); bindings
/// `bnd_1` and `bnd_2` of `wld_1` on `src_gh` and `bnd_3` of `wld_2` on
/// `src_k8s`; service identity `svc_1` with `rs_1`; grant `grt_1` of
/// `wld_1` with `bnd_1` and `bnd_2`. In `ten_b`: workload `wld_b`, service
/// `svc_b`, `rs_2` assigned, keyset `ks_b`, source `src_b`, binding `bnd_b`,
/// service identity `svc_b` and grant `grt_b`.
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    for tenant in ["ten_a", "ten_b"] {
        registry::create_tenant(&pool, &new_tenant(tenant))
            .await
            .unwrap();
    }
    for (tenant, id, kind) in [
        ("ten_a", "wld_1", PrincipalKind::Workload),
        ("ten_a", "wld_2", PrincipalKind::Workload),
        ("ten_a", "svc_1", PrincipalKind::Service),
        ("ten_a", "svc_2", PrincipalKind::Service),
        ("ten_a", "usr_1", PrincipalKind::Human),
        ("ten_b", "wld_b", PrincipalKind::Workload),
        ("ten_b", "svc_b", PrincipalKind::Service),
    ] {
        registry::create_principal(&pool, &new_principal(tenant, id, kind))
            .await
            .unwrap();
    }
    for id in ["rs_1", "rs_2", "rs_3"] {
        registry::create_resource_server(&pool, &new_server(id))
            .await
            .unwrap();
    }
    for (id, rs, tenant) in [
        ("ata_1", "rs_1", "ten_a"),
        ("ata_2", "rs_2", "ten_b"),
        ("ata_3", "rs_3", "ten_a"),
    ] {
        registry::create_audience_tenant_assignment(&pool, &new_assignment(id, rs, tenant))
            .await
            .unwrap();
    }
    for (tenant, id) in [("ten_a", "ks_1"), ("ten_b", "ks_b")] {
        registry::create_trust_keyset(&pool, &new_keyset(tenant, id, "partner"))
            .await
            .unwrap();
    }
    for source in [
        oidc_source("ten_a", "src_gh", "github"),
        jwks_source("ten_a", "src_up", "partner", "ks_1"),
        token_review_source("ten_a", "src_k8s", "k3s", "cluster_1"),
        oidc_source("ten_b", "src_b", "github"),
    ] {
        registry::create_trust_source(&pool, &source).await.unwrap();
    }
    for (tenant, id, source, principal) in [
        ("ten_a", "bnd_1", "src_gh", "wld_1"),
        ("ten_a", "bnd_2", "src_gh", "wld_1"),
        ("ten_a", "bnd_3", "src_k8s", "wld_2"),
        ("ten_b", "bnd_b", "src_b", "wld_b"),
    ] {
        registry::create_principal_binding(&pool, &new_binding(tenant, id, source, principal))
            .await
            .unwrap();
    }
    registry::create_service_identity(&pool, &new_service("ten_a", "svc_1", &["rs_1"]))
        .await
        .unwrap();
    registry::create_service_identity(&pool, &new_service("ten_b", "svc_b", &["rs_2"]))
        .await
        .unwrap();
    registry::create_service_grant(
        &pool,
        &direct_grant("ten_a", "grt_1", "wld_1", &["bnd_2", "bnd_1"]),
    )
    .await
    .unwrap();
    let mut grant_b = direct_grant("ten_b", "grt_b", "wld_b", &["bnd_b"]);
    grant_b.resource_server_ids = strings(&["rs_2"]);
    registry::create_service_grant(&pool, &grant_b)
        .await
        .unwrap();
    (db, pool)
}

#[track_caller]
fn assert_not_found<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::NotFound)), "{result:?}");
}

#[track_caller]
fn assert_stale<T: Debug>(result: Result<T, RegistryError>) {
    assert!(
        matches!(result, Err(RegistryError::StaleRevision)),
        "{result:?}"
    );
}

#[track_caller]
fn assert_guard<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::Guard)), "{result:?}");
}

#[track_caller]
fn assert_exists<T: Debug>(result: Result<T, RegistryError>, name: &str) {
    match result {
        Err(RegistryError::AlreadyExists { constraint }) => assert_eq!(constraint, name),
        other => panic!("expected AlreadyExists {name}: {other:?}"),
    }
}

#[track_caller]
fn assert_invariant<T: Debug>(result: Result<T, RegistryError>, kind: InvariantKind, name: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: actual,
            constraint: Some(constraint),
        }) => assert_eq!((actual, constraint), (kind, name), "{name}"),
        other => panic!("expected {kind:?} {name}: {other:?}"),
    }
}

#[track_caller]
fn assert_check<T: Debug>(result: Result<T, RegistryError>, name: &str) {
    assert_invariant(result, InvariantKind::Check, name);
}

#[track_caller]
fn assert_foreign_key<T: Debug>(result: Result<T, RegistryError>, name: &str) {
    assert_invariant(result, InvariantKind::ForeignKey, name);
}

async fn grant_of(pool: &PgPool, id: &str) -> ServiceGrant {
    registry::get_service_grant(pool, "ten_a", id)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn keysets_are_tenant_local_and_update_by_revision() {
    let (db, pool) = seeded().await;
    let created = registry::create_trust_keyset(&pool, &new_keyset("ten_a", "ks_2", "rotation"))
        .await
        .unwrap();
    assert_eq!(
        (
            &created.id[..],
            &created.tenant_id[..],
            &created.name[..],
            created.status,
            created.revision
        ),
        ("ks_2", "ten_a", "rotation", Status::Enabled, 1)
    );
    assert_eq!(
        registry::get_trust_keyset(&pool, "ten_a", "ks_2")
            .await
            .unwrap(),
        created
    );
    assert_not_found(registry::get_trust_keyset(&pool, "ten_b", "ks_2").await);
    assert_not_found(registry::get_trust_keyset(&pool, "ten_a", "ks_x").await);
    let listed: Vec<_> = registry::list_trust_keysets(&pool, "ten_a", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect();
    assert_eq!(listed, ["ks_1", "ks_2"]);
    let after: Vec<_> = registry::list_trust_keysets(&pool, "ten_a", Page::after("ks_1", 10))
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect();
    assert_eq!(after, ["ks_2"]);

    let changes = TrustKeysetChanges {
        name: "rotated".into(),
        status: Status::Disabled,
    };
    let updated = registry::update_trust_keyset(&pool, "ten_a", "ks_2", 1, &changes)
        .await
        .unwrap();
    assert_eq!(
        (&updated.name[..], updated.status, updated.revision),
        ("rotated", Status::Disabled, 2)
    );
    for expected in [1, 3, 0, -1] {
        assert_stale(
            registry::update_trust_keyset(&pool, "ten_a", "ks_2", expected, &changes).await,
        );
    }
    assert_not_found(registry::update_trust_keyset(&pool, "ten_b", "ks_2", 2, &changes).await);
    assert_not_found(registry::update_trust_keyset(&pool, "ten_a", "ks_x", 1, &changes).await);
    assert_eq!(
        registry::get_trust_keyset(&pool, "ten_a", "ks_2")
            .await
            .unwrap(),
        updated
    );

    let create = |new: NewTrustKeyset| {
        let pool = pool.clone();
        async move { registry::create_trust_keyset(&pool, &new).await }
    };
    // The same name in another tenant is fine.
    create(new_keyset("ten_b", "ks_3", "rotated"))
        .await
        .unwrap();
    assert_exists(
        create(new_keyset("ten_b", "ks_2", "other")).await,
        "trust_keyset_pkey",
    );
    assert_exists(
        create(new_keyset("ten_a", "ks_4", "partner")).await,
        "trust_keyset_tenant_id_name_key",
    );
    assert_foreign_key(
        create(new_keyset("ten_x", "ks_4", "x")).await,
        "trust_keyset_tenant_id_fkey",
    );
    for (keyset, name) in [
        (new_keyset("ten_a", "ks_4", ""), "trust_keyset_name_check"),
        (
            new_keyset("ten_a", "ks_4", "has space"),
            "trust_keyset_name_no_space_check",
        ),
        (
            new_keyset("ten_a", "ks_4", &"n".repeat(2049)),
            "trust_keyset_name_octet_length_check",
        ),
        (new_keyset("ten_a", "", "x"), "trust_keyset_id_check"),
        (
            new_keyset("ten_a", &"k".repeat(256), "x"),
            "trust_keyset_id_octet_length_check",
        ),
        (
            new_keyset(&"t".repeat(256), "ks_4", "x"),
            "trust_keyset_tenant_id_octet_length_check",
        ),
    ] {
        assert_check(create(keyset).await, name);
    }
    let rename = TrustKeysetChanges {
        name: "partner".into(),
        status: Status::Enabled,
    };
    assert_exists(
        registry::update_trust_keyset(&pool, "ten_a", "ks_2", 2, &rename).await,
        "trust_keyset_tenant_id_name_key",
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn keyset_versions_are_created_read_and_listed_per_keyset() {
    let (db, pool) = seeded().await;
    let created =
        registry::create_trust_keyset_version(&pool, &new_version("ten_a", "kv_2", "ks_1"))
            .await
            .unwrap();
    let expected = new_version("ten_a", "kv_2", "ks_1");
    assert_eq!(
        (
            &created.id[..],
            &created.tenant_id[..],
            &created.keyset_id[..]
        ),
        ("kv_2", "ten_a", "ks_1")
    );
    assert_eq!(created.public_jwks, expected.public_jwks);
    assert_eq!(created.provenance, expected.provenance);
    // Microseconds survive the round trip exactly.
    assert_eq!(created.effective_at, at(1_767_323_045_678_901));
    assert_eq!(created.expires_at, Some(at(1_798_859_045_000_001)));
    assert_eq!(
        registry::get_trust_keyset_version(&pool, "ten_a", "kv_2")
            .await
            .unwrap(),
        created
    );
    assert_not_found(registry::get_trust_keyset_version(&pool, "ten_b", "kv_2").await);

    // Open-ended, before the epoch, and with nanoseconds that truncate.
    let mut open = new_version("ten_a", "kv_1", "ks_1");
    open.expires_at = None;
    open.effective_at = at(-1_000_001) - Duration::from_nanos(1);
    let open = registry::create_trust_keyset_version(&pool, &open)
        .await
        .unwrap();
    assert_eq!((open.effective_at, open.expires_at), (at(-1_000_002), None));
    let mut nanos = new_version("ten_a", "kv_3", "ks_1");
    nanos.effective_at = at(5) + Duration::from_nanos(999);
    nanos.expires_at = Some(at(6));
    let nanos = registry::create_trust_keyset_version(&pool, &nanos)
        .await
        .unwrap();
    assert_eq!(nanos.effective_at, at(5));
    registry::create_trust_keyset(&pool, &new_keyset("ten_a", "ks_2", "other"))
        .await
        .unwrap();
    registry::create_trust_keyset_version(&pool, &new_version("ten_a", "kv_0", "ks_2"))
        .await
        .unwrap();
    registry::create_trust_keyset_version(&pool, &new_version("ten_b", "kv_b", "ks_b"))
        .await
        .unwrap();

    let ids = |versions: Vec<registry::TrustKeysetVersion>| -> Vec<String> {
        versions.into_iter().map(|v| v.id).collect()
    };
    let of_ks_1 =
        ids(
            registry::list_trust_keyset_versions(&pool, "ten_a", "ks_1", Page::first(10))
                .await
                .unwrap(),
        );
    assert_eq!(of_ks_1, ["kv_1", "kv_2", "kv_3"]);
    let page =
        ids(
            registry::list_trust_keyset_versions(&pool, "ten_a", "ks_1", Page::after("kv_1", 1))
                .await
                .unwrap(),
        );
    assert_eq!(page, ["kv_2"]);
    assert_eq!(
        ids(
            registry::list_trust_keyset_versions(&pool, "ten_a", "ks_2", Page::first(10))
                .await
                .unwrap()
        ),
        ["kv_0"]
    );
    // Another tenant's keyset lists nothing.
    assert!(
        registry::list_trust_keyset_versions(&pool, "ten_a", "ks_b", Page::first(10))
            .await
            .unwrap()
            .is_empty()
    );

    let create = |new: NewTrustKeysetVersion| {
        let pool = pool.clone();
        async move { registry::create_trust_keyset_version(&pool, &new).await }
    };
    assert_exists(
        create(new_version("ten_a", "kv_2", "ks_1")).await,
        "trust_keyset_version_pkey",
    );
    for keyset in ["ks_x", "ks_b"] {
        assert_foreign_key(
            create(new_version("ten_a", "kv_9", keyset)).await,
            "trust_keyset_version_keyset_id_fkey",
        );
    }
    let mut empty = new_version("ten_a", "kv_9", "ks_1");
    empty.expires_at = Some(empty.effective_at);
    assert_check(create(empty).await, "trust_keyset_version_validity_check");
    for jwks in [
        json!({"keys": []}),
        json!({"keys": ["not an object"]}),
        json!({"keys": [{"kty": "EC", "d": "private"}]}),
        json!({"keys": [{"kty": "oct", "k": "symmetric"}]}),
        json!({"other": 1}),
    ] {
        let mut private = new_version("ten_a", "kv_9", "ks_1");
        private.public_jwks = object(jwks);
        assert_check(
            create(private).await,
            "trust_keyset_version_public_jwks_check",
        );
    }
    for (fingerprint, name) in [
        ("", "trust_keyset_version_fingerprint_check"),
        (
            "sha256: 01",
            "trust_keyset_version_fingerprint_no_space_check",
        ),
        (
            &"f".repeat(2049),
            "trust_keyset_version_fingerprint_octet_length_check",
        ),
    ] {
        let mut version = new_version("ten_a", "kv_9", "ks_1");
        version.fingerprint = fingerprint.into();
        assert_check(create(version).await, name);
    }
    assert_check(
        create(new_version("ten_a", "", "ks_1")).await,
        "trust_keyset_version_id_check",
    );
    assert_check(
        create(new_version("ten_a", &"v".repeat(256), "ks_1")).await,
        "trust_keyset_version_id_octet_length_check",
    );
    assert_check(
        create(new_version("ten_a", "kv_9", &"k".repeat(256))).await,
        "trust_keyset_version_keyset_id_octet_length_check",
    );
    assert_check(
        create(new_version(&"t".repeat(256), "kv_9", "ks_1")).await,
        "trust_keyset_version_tenant_id_octet_length_check",
    );
    db.drop([pool]).await;
}

/// Each kind stores exactly its own fields, and the database rejects every
/// other combination with the named check.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_source_fields_follow_its_kind() {
    let (db, pool) = seeded().await;
    // All three kinds are listed in their tenant only.
    let listed: Vec<_> = registry::list_trust_sources(&pool, "ten_a", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|source| (source.id, source.kind, source.exact_issuer))
        .collect();
    assert_eq!(
        listed,
        [
            (
                "src_gh".to_string(),
                TrustSourceKind::OidcDiscovery,
                "https://token.actions.githubusercontent.com".to_string()
            ),
            (
                "src_k8s".to_string(),
                TrustSourceKind::KubernetesTokenReview,
                "https://kubernetes.default.svc".to_string()
            ),
            (
                "src_up".to_string(),
                TrustSourceKind::UploadedJwks,
                "https://ci.partner.example".to_string()
            ),
        ]
    );
    for id in ["src_gh", "src_k8s", "src_up"] {
        assert_not_found(registry::get_trust_source(&pool, "ten_b", id).await);
    }
    let oidc = registry::get_trust_source(&pool, "ten_a", "src_gh")
        .await
        .unwrap();
    assert_eq!(oidc.kind, TrustSourceKind::OidcDiscovery);
    assert!(oidc.discovery_url.is_some() && oidc.jwks_keyset_id.is_none());
    assert_eq!(
        (oidc.cluster_id.clone(), oidc.review_timeout_ms),
        (None, None)
    );
    assert_eq!(oidc.algorithms, Some(strings(&["RS256"])));
    assert_eq!(
        (oidc.assertion_profile, oidc.replay_mode, oidc.revision),
        (AssertionProfile::OnDemandJwt, ReplayMode::SingleUse, 1)
    );
    let uploaded = registry::get_trust_source(&pool, "ten_a", "src_up")
        .await
        .unwrap();
    assert_eq!(uploaded.jwks_keyset_id.as_deref(), Some("ks_1"));
    assert_eq!(uploaded.discovery_url, None);
    assert_eq!(
        uploaded.proof_bounds,
        object(json!({"max_age_seconds": 300}))
    );
    let review = registry::get_trust_source(&pool, "ten_a", "src_k8s")
        .await
        .unwrap();
    assert_eq!(
        review,
        TrustSource {
            id: "src_k8s".into(),
            tenant_id: "ten_a".into(),
            name: "k3s".into(),
            kind: TrustSourceKind::KubernetesTokenReview,
            exact_issuer: "https://kubernetes.default.svc".into(),
            discovery_url: None,
            jwks_keyset_id: None,
            cluster_id: Some("cluster_1".into()),
            token_review_endpoint: Some("https://k3s.internal.example:6443".into()),
            ca_bundle_ref: Some("ca_k3s".into()),
            ca_fingerprint: Some("sha256:ca".into()),
            reviewer_credential_ref: Some("reviewer_k3s".into()),
            review_timeout_ms: Some(5000),
            audiences: strings(&["https://identity.example.com"]),
            algorithms: None,
            proof_bounds: JsonObject::new(),
            assertion_profile: AssertionProfile::ProjectedServiceAccount,
            stale_revocation_acknowledged: None,
            replay_mode: ReplayMode::Reusable,
            status: Status::Enabled,
            revision: 1,
        }
    );
    // A locally verified projected token acknowledges stale revocation.
    let mut local = jwks_source("ten_a", "src_local", "k3s-local", "ks_1");
    local.assertion_profile = AssertionProfile::ProjectedServiceAccount;
    local.stale_revocation_acknowledged = Some(true);
    let local = registry::create_trust_source(&pool, &local).await.unwrap();
    assert_eq!(local.stale_revocation_acknowledged, Some(true));

    let create = |new: NewTrustSource| {
        let pool = pool.clone();
        async move { registry::create_trust_source(&pool, &new).await }
    };
    let oidc_new = || oidc_source("ten_a", "src_x", "x");
    let jwks_new = || jwks_source("ten_a", "src_x", "x", "ks_1");
    let review_new = || token_review_source("ten_a", "src_x", "x", "cluster_x");
    let cases: Vec<(NewTrustSource, &str)> = vec![
        (
            NewTrustSource {
                discovery_url: None,
                ..oidc_new()
            },
            "trust_source_discovery_url_kind_check",
        ),
        (
            NewTrustSource {
                discovery_url: Some("https://x.example/.well-known".into()),
                ..jwks_new()
            },
            "trust_source_discovery_url_kind_check",
        ),
        (
            NewTrustSource {
                jwks_keyset_id: Some("ks_1".into()),
                ..oidc_new()
            },
            "trust_source_jwks_keyset_id_kind_check",
        ),
        (
            NewTrustSource {
                jwks_keyset_id: None,
                ..jwks_new()
            },
            "trust_source_jwks_keyset_id_kind_check",
        ),
        (
            NewTrustSource {
                ca_fingerprint: None,
                ..review_new()
            },
            "trust_source_token_review_fields_kind_check",
        ),
        (
            NewTrustSource {
                review_timeout_ms: Some(5000),
                ..oidc_new()
            },
            "trust_source_token_review_fields_kind_check",
        ),
        (
            NewTrustSource {
                cluster_id: Some("cluster_x".into()),
                ..jwks_new()
            },
            "trust_source_token_review_fields_kind_check",
        ),
        (
            NewTrustSource {
                algorithms: Some(strings(&["RS256"])),
                ..review_new()
            },
            "trust_source_algorithms_kind_check",
        ),
        (
            NewTrustSource {
                algorithms: None,
                ..oidc_new()
            },
            "trust_source_algorithms_kind_check",
        ),
        (
            NewTrustSource {
                assertion_profile: AssertionProfile::ReusableJwt,
                ..review_new()
            },
            "trust_source_token_review_profile_check",
        ),
        (
            NewTrustSource {
                assertion_profile: AssertionProfile::ProjectedServiceAccount,
                replay_mode: ReplayMode::Reusable,
                ..oidc_new()
            },
            "trust_source_stale_revocation_kind_check",
        ),
        (
            NewTrustSource {
                stale_revocation_acknowledged: Some(true),
                ..jwks_new()
            },
            "trust_source_stale_revocation_kind_check",
        ),
        (
            NewTrustSource {
                stale_revocation_acknowledged: Some(true),
                ..review_new()
            },
            "trust_source_stale_revocation_kind_check",
        ),
        (
            NewTrustSource {
                assertion_profile: AssertionProfile::ProjectedServiceAccount,
                stale_revocation_acknowledged: Some(false),
                replay_mode: ReplayMode::Reusable,
                ..oidc_new()
            },
            "trust_source_stale_revocation_acknowledged_check",
        ),
        (
            NewTrustSource {
                replay_mode: ReplayMode::SingleUse,
                ..jwks_new()
            },
            "trust_source_single_use_replay_check",
        ),
        (
            NewTrustSource {
                replay_mode: ReplayMode::SingleUse,
                ..review_new()
            },
            "trust_source_single_use_replay_check",
        ),
    ];
    for (source, name) in cases {
        assert_check(create(source).await, name);
    }
    assert!(matches!(
        registry::get_trust_source(&pool, "ten_a", "src_x").await,
        Err(RegistryError::NotFound)
    ));

    // An update keeps the kind; its fields must still match it.
    let mut changes = source_changes(&oidc);
    changes.discovery_url = None;
    assert_check(
        registry::update_trust_source(&pool, "ten_a", "src_gh", 1, &changes).await,
        "trust_source_discovery_url_kind_check",
    );
    let mut changes = source_changes(&oidc);
    changes.token_review_endpoint = Some("https://k.example".into());
    assert_check(
        registry::update_trust_source(&pool, "ten_a", "src_gh", 1, &changes).await,
        "trust_source_token_review_fields_kind_check",
    );
    let mut changes = source_changes(&review);
    changes.review_timeout_ms = None;
    assert_check(
        registry::update_trust_source(&pool, "ten_a", "src_k8s", 1, &changes).await,
        "trust_source_token_review_fields_kind_check",
    );
    let mut changes = source_changes(&review);
    changes.token_review_endpoint = Some("https://k3s-2.internal.example:6443".into());
    changes.ca_fingerprint = Some("sha256:cb".into());
    changes.review_timeout_ms = Some(2500);
    changes.status = Status::Disabled;
    let rotated = registry::update_trust_source(&pool, "ten_a", "src_k8s", 1, &changes)
        .await
        .unwrap();
    assert_eq!(rotated.revision, 2);
    assert_eq!(
        (
            rotated.kind,
            rotated.cluster_id.as_deref(),
            rotated.review_timeout_ms,
            rotated.status
        ),
        (
            TrustSourceKind::KubernetesTokenReview,
            Some("cluster_1"),
            Some(2500),
            Status::Disabled
        )
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_sources_update_by_revision_and_name_their_constraints() {
    let (db, pool) = seeded().await;
    let source = registry::get_trust_source(&pool, "ten_a", "src_up")
        .await
        .unwrap();
    let mut changes = source_changes(&source);
    changes.name = "partner-2".into();
    changes.exact_issuer = "https://ci2.partner.example".into();
    changes.audiences = strings(&["https://a.example", "https://b.example"]);
    changes.algorithms = Some(strings(&["ES256", "ES384"]));
    changes.proof_bounds = object(json!({"max_age_seconds": 60, "clock_skew": 5}));
    let updated = registry::update_trust_source(&pool, "ten_a", "src_up", 1, &changes)
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(
        (&updated.name[..], &updated.exact_issuer[..]),
        ("partner-2", "https://ci2.partner.example")
    );
    assert_eq!(updated.audiences, changes.audiences);
    assert_eq!(updated.algorithms, changes.algorithms);
    assert_eq!(updated.proof_bounds, changes.proof_bounds);
    assert_eq!(updated.jwks_keyset_id.as_deref(), Some("ks_1"));
    assert_eq!(
        registry::get_trust_source(&pool, "ten_a", "src_up")
            .await
            .unwrap(),
        updated
    );
    assert_stale(registry::update_trust_source(&pool, "ten_a", "src_up", 1, &changes).await);
    assert_not_found(registry::update_trust_source(&pool, "ten_b", "src_up", 2, &changes).await);
    assert_not_found(registry::update_trust_source(&pool, "ten_a", "src_x", 1, &changes).await);
    let listed: Vec<_> = registry::list_trust_sources(&pool, "ten_a", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(listed, ["src_gh", "src_k8s", "src_up"]);

    let create = |new: NewTrustSource| {
        let pool = pool.clone();
        async move { registry::create_trust_source(&pool, &new).await }
    };
    assert_exists(
        create(oidc_source("ten_b", "src_gh", "other")).await,
        "trust_source_pkey",
    );
    assert_exists(
        create(oidc_source("ten_a", "src_x", "github")).await,
        "trust_source_tenant_id_name_key",
    );
    assert_exists(
        create(token_review_source("ten_a", "src_x", "x", "cluster_1")).await,
        "trust_source_cluster_id_key",
    );
    assert_foreign_key(
        create(oidc_source("ten_x", "src_x", "x")).await,
        "trust_source_tenant_id_fkey",
    );
    for keyset in ["ks_x", "ks_b"] {
        assert_foreign_key(
            create(jwks_source("ten_a", "src_x", "x", keyset)).await,
            "trust_source_jwks_keyset_id_fkey",
        );
    }
    let oidc_new = || oidc_source("ten_a", "src_x", "x");
    let long = "u".repeat(2049);
    let cases: Vec<(NewTrustSource, &str)> = vec![
        (
            NewTrustSource {
                name: String::new(),
                ..oidc_new()
            },
            "trust_source_name_check",
        ),
        (
            NewTrustSource {
                name: "two words".into(),
                ..oidc_new()
            },
            "trust_source_name_no_space_check",
        ),
        (
            NewTrustSource {
                name: long.clone(),
                ..oidc_new()
            },
            "trust_source_name_octet_length_check",
        ),
        (
            NewTrustSource {
                exact_issuer: String::new(),
                ..oidc_new()
            },
            "trust_source_exact_issuer_check",
        ),
        (
            NewTrustSource {
                exact_issuer: "https://issuer.example\n".into(),
                ..oidc_new()
            },
            "trust_source_exact_issuer_no_space_check",
        ),
        (
            NewTrustSource {
                exact_issuer: long.clone(),
                ..oidc_new()
            },
            "trust_source_exact_issuer_octet_length_check",
        ),
        (
            NewTrustSource {
                discovery_url: Some("https://x.example/ well-known".into()),
                ..oidc_new()
            },
            "trust_source_discovery_url_no_space_check",
        ),
        (
            NewTrustSource {
                discovery_url: Some(String::new()),
                ..oidc_new()
            },
            "trust_source_discovery_url_check",
        ),
        (
            NewTrustSource {
                discovery_url: Some(long.clone()),
                ..oidc_new()
            },
            "trust_source_discovery_url_octet_length_check",
        ),
        (
            NewTrustSource {
                audiences: vec![],
                ..oidc_new()
            },
            "trust_source_audiences_check",
        ),
        (
            NewTrustSource {
                audiences: strings(&[""]),
                ..oidc_new()
            },
            "skyoauth_string_list_check",
        ),
        (
            NewTrustSource {
                algorithms: Some(vec![]),
                ..oidc_new()
            },
            "trust_source_algorithms_check",
        ),
        (
            NewTrustSource {
                review_timeout_ms: Some(0),
                ..token_review_source("ten_a", "src_x", "x", "cluster_x")
            },
            "trust_source_review_timeout_ms_check",
        ),
        (
            NewTrustSource {
                ca_bundle_ref: Some("ca bundle".into()),
                ..token_review_source("ten_a", "src_x", "x", "cluster_x")
            },
            "trust_source_ca_bundle_ref_no_space_check",
        ),
        (
            NewTrustSource {
                reviewer_credential_ref: Some(long.clone()),
                ..token_review_source("ten_a", "src_x", "x", "cluster_x")
            },
            "trust_source_reviewer_credential_ref_octet_length_check",
        ),
        (
            NewTrustSource {
                token_review_endpoint: Some("https://k\t.example".into()),
                ..token_review_source("ten_a", "src_x", "x", "cluster_x")
            },
            "trust_source_token_review_endpoint_no_space_check",
        ),
        (
            token_review_source("ten_a", "src_x", "x", &"c".repeat(256)),
            "trust_source_cluster_id_octet_length_check",
        ),
        (
            NewTrustSource {
                id: "s".repeat(256),
                ..oidc_new()
            },
            "trust_source_id_octet_length_check",
        ),
        (
            jwks_source("ten_a", "src_x", "x", &"k".repeat(256)),
            "trust_source_jwks_keyset_id_octet_length_check",
        ),
    ];
    for (source, name) in cases {
        assert_check(create(source).await, name);
    }
    let mut rename = source_changes(&updated);
    rename.name = "github".into();
    assert_exists(
        registry::update_trust_source(&pool, "ten_a", "src_up", 2, &rename).await,
        "trust_source_tenant_id_name_key",
    );
    assert_eq!(
        registry::get_trust_source(&pool, "ten_a", "src_up")
            .await
            .unwrap()
            .revision,
        2
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn bindings_map_a_same_tenant_source_to_a_workload() {
    let (db, pool) = seeded().await;
    let created = registry::get_principal_binding(&pool, "ten_a", "bnd_3")
        .await
        .unwrap();
    assert_eq!(
        (
            &created.trust_source_id[..],
            &created.workload_principal_id[..],
            created.profile,
            created.revision
        ),
        ("src_k8s", "wld_2", BindingProfile::GithubProduction, 1)
    );
    assert_eq!(created.claim_match_policy, github_claims());
    assert_not_found(registry::get_principal_binding(&pool, "ten_b", "bnd_3").await);

    let changes = PrincipalBindingChanges {
        name: "k3s-ci".into(),
        profile: BindingProfile::KubernetesProduction,
        claim_match_policy: claims(&[
            ("kubernetes.io/serviceaccount/namespace", "ci"),
            (
                "kubernetes.io/serviceaccount/service-account.name",
                "runner",
            ),
            ("kubernetes.io/serviceaccount/service-account.uid", "u-1"),
        ]),
        status: Status::Disabled,
    };
    let updated = registry::update_principal_binding(&pool, "ten_a", "bnd_3", 1, &changes)
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(
        (&updated.name[..], updated.profile, updated.status),
        (
            "k3s-ci",
            BindingProfile::KubernetesProduction,
            Status::Disabled
        )
    );
    assert_eq!(updated.claim_match_policy, changes.claim_match_policy);
    assert_eq!(
        (
            &updated.trust_source_id[..],
            &updated.workload_principal_id[..]
        ),
        ("src_k8s", "wld_2")
    );
    assert_stale(registry::update_principal_binding(&pool, "ten_a", "bnd_3", 1, &changes).await);
    assert_not_found(
        registry::update_principal_binding(&pool, "ten_b", "bnd_3", 2, &changes).await,
    );
    assert_not_found(
        registry::update_principal_binding(&pool, "ten_a", "bnd_x", 1, &changes).await,
    );
    let listed: Vec<_> = registry::list_principal_bindings(&pool, "ten_a", Page::first(2))
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    assert_eq!(listed, ["bnd_1", "bnd_2"]);
    let rest: Vec<_> = registry::list_principal_bindings(&pool, "ten_a", Page::after("bnd_2", 2))
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    assert_eq!(rest, ["bnd_3"]);

    let create = |new: NewPrincipalBinding| {
        let pool = pool.clone();
        async move { registry::create_principal_binding(&pool, &new).await }
    };
    assert_exists(
        create(new_binding("ten_a", "bnd_1", "src_gh", "wld_2")).await,
        "principal_binding_pkey",
    );
    let mut same_name = new_binding("ten_a", "bnd_9", "src_gh", "wld_2");
    same_name.name = "binding-bnd_1".into();
    assert_exists(
        create(same_name).await,
        "principal_binding_tenant_id_name_key",
    );
    // A missing source, or one of another tenant.
    for source in ["src_x", "src_b"] {
        assert_foreign_key(
            create(new_binding("ten_a", "bnd_9", source, "wld_1")).await,
            "principal_binding_trust_source_id_fkey",
        );
    }
    // A service, a human, another tenant's workload, a missing principal.
    for principal in ["svc_1", "usr_1", "wld_b", "prn_x"] {
        assert_foreign_key(
            create(new_binding("ten_a", "bnd_9", "src_gh", principal)).await,
            "principal_binding_workload_principal_id_fkey",
        );
    }
    // No predicate at all lacks the profile's first required one, refused
    // before the statement (registry_predicates.rs has the rest). The 0004
    // check is reached only by raw SQL, an empty object ('{}') and a
    // non-string value ('{"a": 1}'), in
    // trust_guards_and_unreachable_constraints_map_from_raw_statements.
    let mut no_predicate = new_binding("ten_a", "bnd_9", "src_gh", "wld_1");
    no_predicate.claim_match_policy = BTreeMap::new();
    match create(no_predicate).await {
        Err(RegistryError::Other(sqlx::Error::Encode(err))) => assert_eq!(
            err.to_string(),
            "the required predicate repository_owner_id of github_production is missing"
        ),
        other => panic!("expected the encode error: {other:?}"),
    }
    for (binding, name) in [
        (
            NewPrincipalBinding {
                name: String::new(),
                ..new_binding("ten_a", "bnd_9", "src_gh", "wld_1")
            },
            "principal_binding_name_check",
        ),
        (
            NewPrincipalBinding {
                name: "a b".into(),
                ..new_binding("ten_a", "bnd_9", "src_gh", "wld_1")
            },
            "principal_binding_name_no_space_check",
        ),
        (
            new_binding("ten_a", &"b".repeat(256), "src_gh", "wld_1"),
            "principal_binding_id_octet_length_check",
        ),
        (
            new_binding("ten_a", "bnd_9", &"s".repeat(256), "wld_1"),
            "principal_binding_trust_source_id_octet_length_check",
        ),
        (
            new_binding("ten_a", "bnd_9", "src_gh", &"w".repeat(256)),
            "principal_binding_workload_principal_id_octet_length_check",
        ),
    ] {
        assert_check(create(binding).await, name);
    }
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn service_identities_carry_their_assigned_audiences() {
    let (db, pool) = seeded().await;
    let svc = registry::get_service_identity(&pool, "ten_a", "svc_1")
        .await
        .unwrap();
    assert_eq!(svc.resource_server_ids, ["rs_1"]);
    assert_eq!(svc.max_resource_constraints, object(json!({"version": 1})));
    assert_eq!(svc.revision, 1);
    assert_not_found(registry::get_service_identity(&pool, "ten_b", "svc_1").await);

    // Created with several audiences in one statement, listed sorted.
    let created =
        registry::create_service_identity(&pool, &new_service("ten_a", "svc_2", &["rs_3", "rs_1"]))
            .await
            .unwrap();
    assert_eq!(created.resource_server_ids, ["rs_1", "rs_3"]);
    assert_eq!(
        registry::get_service_identity(&pool, "ten_a", "svc_2")
            .await
            .unwrap(),
        created
    );
    let listed: Vec<_> = registry::list_service_identities(&pool, "ten_a", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|s| (s.id, s.resource_server_ids))
        .collect();
    assert_eq!(
        listed,
        [
            ("svc_1".to_string(), strings(&["rs_1"])),
            ("svc_2".to_string(), strings(&["rs_1", "rs_3"]))
        ]
    );

    let changes = ServiceIdentityChanges {
        name: "deployer".into(),
        max_scopes: vec![],
        max_resource_constraints: JsonObject::new(),
        status: Status::Disabled,
    };
    let updated = registry::update_service_identity(&pool, "ten_a", "svc_1", 1, &changes)
        .await
        .unwrap();
    assert_eq!(
        (
            &updated.name[..],
            updated.max_scopes.len(),
            updated.status,
            updated.revision
        ),
        ("deployer", 0, Status::Disabled, 2)
    );
    assert_eq!(updated.resource_server_ids, ["rs_1"]);
    assert_stale(registry::update_service_identity(&pool, "ten_a", "svc_1", 1, &changes).await);
    assert_not_found(registry::update_service_identity(&pool, "ten_b", "svc_1", 2, &changes).await);

    // Audience rows.
    assert_eq!(
        registry::add_service_identity_resource_server(&pool, "ten_a", "svc_1", 2, "rs_3")
            .await
            .unwrap(),
        3
    );
    assert_exists(
        registry::add_service_identity_resource_server(&pool, "ten_a", "svc_1", 3, "rs_3").await,
        "service_identity_resource_server_pkey",
    );
    // rs_2 is assigned to ten_b only; rs_x does not exist.
    for rs in ["rs_2", "rs_x"] {
        assert_foreign_key(
            registry::add_service_identity_resource_server(&pool, "ten_a", "svc_1", 3, rs).await,
            "service_identity_resource_server_assignment_fkey",
        );
    }
    assert_stale(
        registry::add_service_identity_resource_server(&pool, "ten_a", "svc_1", 2, "rs_2").await,
    );
    assert_not_found(
        registry::add_service_identity_resource_server(&pool, "ten_b", "svc_1", 3, "rs_2").await,
    );
    assert_not_found(
        registry::remove_service_identity_resource_server(&pool, "ten_a", "svc_1", 3, "rs_2").await,
    );
    assert_not_found(
        registry::remove_service_identity_resource_server(&pool, "ten_b", "svc_1", 3, "rs_1").await,
    );
    assert_stale(
        registry::remove_service_identity_resource_server(&pool, "ten_a", "svc_1", 2, "rs_1").await,
    );
    for rs in ["rs_1", "rs_3"] {
        let revision = registry::get_service_identity(&pool, "ten_a", "svc_1")
            .await
            .unwrap()
            .revision;
        registry::remove_service_identity_resource_server(&pool, "ten_a", "svc_1", revision, rs)
            .await
            .unwrap();
    }
    // An empty audience set is allowed (it allows nothing).
    let emptied = registry::get_service_identity(&pool, "ten_a", "svc_1")
        .await
        .unwrap();
    assert_eq!(
        (emptied.revision, emptied.resource_server_ids.len()),
        (5, 0)
    );

    let create = |new: NewServiceIdentity| {
        let pool = pool.clone();
        async move { registry::create_service_identity(&pool, &new).await }
    };
    assert_exists(
        create(new_service("ten_a", "svc_2", &[])).await,
        "service_identity_pkey",
    );
    // A workload, a human, another tenant's service principal and a
    // missing principal are not service principals of the tenant.
    registry::create_principal(
        &pool,
        &new_principal("ten_b", "svc_c", PrincipalKind::Service),
    )
    .await
    .unwrap();
    for id in ["wld_1", "usr_1", "svc_c", "svc_x"] {
        assert_foreign_key(
            create(new_service("ten_a", id, &[])).await,
            "service_identity_id_fkey",
        );
    }
    registry::create_principal(
        &pool,
        &new_principal("ten_a", "svc_3", PrincipalKind::Service),
    )
    .await
    .unwrap();
    let mut same_name = new_service("ten_a", "svc_3", &[]);
    same_name.name = "deployer".into();
    assert_exists(
        create(same_name).await,
        "service_identity_tenant_id_name_key",
    );
    // A bad audience fails the whole statement: no identity is left.
    assert_foreign_key(
        create(new_service("ten_a", "svc_3", &["rs_2"])).await,
        "service_identity_resource_server_assignment_fkey",
    );
    assert_exists(
        create(new_service("ten_a", "svc_3", &["rs_1", "rs_1"])).await,
        "service_identity_resource_server_pkey",
    );
    assert_not_found(registry::get_service_identity(&pool, "ten_a", "svc_3").await);
    let mut bad_scope = new_service("ten_a", "svc_3", &[]);
    bad_scope.max_scopes = strings(&["has space"]);
    assert_check(create(bad_scope).await, "skyoauth_scope_list_check");
    let mut nameless = new_service("ten_a", "svc_3", &[]);
    nameless.name = "a\u{85}b".into();
    assert_check(
        create(nameless).await,
        "service_identity_name_no_space_check",
    );
    assert_check(
        create(new_service("ten_a", "svc_3", &[&"r".repeat(256)])).await,
        "service_identity_resource_server_server_id_octet_length_check",
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grants_are_created_with_their_bindings_and_audiences() {
    let (db, pool) = seeded().await;
    let grant = grant_of(&pool, "grt_1").await;
    assert_eq!(grant.allowed_binding_ids, ["bnd_1", "bnd_2"]);
    assert_eq!(grant.resource_server_ids, ["rs_1"]);
    assert_eq!(
        (
            grant.mode,
            grant.target_service_id.as_deref(),
            grant.activation_state,
            grant.max_ttl,
            grant.valid_until,
            grant.revision
        ),
        (
            GrantMode::Direct,
            None,
            ActivationState::NotRequired,
            300,
            None,
            1
        )
    );
    assert_eq!(grant.default_scopes, Some(strings(&["read"])));
    assert_not_found(registry::get_service_grant(&pool, "ten_b", "grt_1").await);

    let delegated = NewServiceGrant {
        target_service_id: Some("svc_1".into()),
        mode: GrantMode::Delegation,
        default_scopes: None,
        resource_constraints: object(json!({"project": ["p-1"]})),
        max_ttl: 60,
        valid_until: Some(at(1_798_761_600_000_000)),
        resource_server_ids: strings(&["rs_3", "rs_1"]),
        ..direct_grant("ten_a", "grt_2", "wld_1", &["bnd_1"])
    };
    let created = registry::create_service_grant(&pool, &delegated)
        .await
        .unwrap();
    assert_eq!(created.target_service_id.as_deref(), Some("svc_1"));
    assert_eq!(created.valid_until, Some(at(1_798_761_600_000_000)));
    assert_eq!(created.resource_server_ids, ["rs_1", "rs_3"]);
    assert_eq!(created.resource_constraints, delegated.resource_constraints);
    assert_eq!(grant_of(&pool, "grt_2").await, created);
    let dormant = NewServiceGrant {
        target_service_id: Some("svc_1".into()),
        mode: GrantMode::Impersonation,
        status: Status::Disabled,
        activation_state: ActivationState::RequiresReapproval,
        resource_server_ids: vec![],
        ..direct_grant("ten_a", "grt_3", "wld_2", &["bnd_3"])
    };
    registry::create_service_grant(&pool, &dormant)
        .await
        .unwrap();
    let listed: Vec<_> = registry::list_service_grants(&pool, "ten_a", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|g| (g.id, g.allowed_binding_ids))
        .collect();
    assert_eq!(
        listed,
        [
            ("grt_1".to_string(), strings(&["bnd_1", "bnd_2"])),
            ("grt_2".to_string(), strings(&["bnd_1"])),
            ("grt_3".to_string(), strings(&["bnd_3"]))
        ]
    );
    let of_b: Vec<_> = registry::list_service_grants(&pool, "ten_b", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(of_b, ["grt_b"]);

    // Update: mutable columns only, bindings and audiences kept.
    let mut changes = grant_changes(&created);
    changes.name = "delegated".into();
    changes.scopes = strings(&["read"]);
    changes.default_scopes = Some(strings(&["read"]));
    changes.max_ttl = 120;
    changes.valid_until = None;
    changes.status = Status::Disabled;
    let updated = registry::update_service_grant(&pool, "ten_a", "grt_2", 1, &changes)
        .await
        .unwrap();
    assert_eq!(
        (
            &updated.name[..],
            updated.max_ttl,
            updated.valid_until,
            updated.status,
            updated.revision
        ),
        ("delegated", 120, None, Status::Disabled, 2)
    );
    assert_eq!(updated.mode, GrantMode::Delegation);
    assert_eq!(updated.allowed_binding_ids, ["bnd_1"]);
    assert_eq!(updated.resource_server_ids, ["rs_1", "rs_3"]);
    assert_eq!(grant_of(&pool, "grt_2").await, updated);
    assert_stale(registry::update_service_grant(&pool, "ten_a", "grt_2", 1, &changes).await);
    assert_not_found(registry::update_service_grant(&pool, "ten_b", "grt_2", 2, &changes).await);
    assert_not_found(registry::update_service_grant(&pool, "ten_a", "grt_x", 1, &changes).await);
    let mut widened = changes.clone();
    widened.default_scopes = Some(strings(&["deploy:write"]));
    assert_check(
        registry::update_service_grant(&pool, "ten_a", "grt_2", 2, &widened).await,
        "service_grant_default_scopes_check",
    );
    // The dormant grant is frozen (0009): enabling it is a guard error,
    // before the 0004 check it would also fail.
    let mut woken = grant_changes(&grant_of(&pool, "grt_3").await);
    woken.status = Status::Enabled;
    let refused = registry::update_service_grant(&pool, "ten_a", "grt_3", 1, &woken).await;
    assert!(matches!(refused, Err(RegistryError::Guard)), "{refused:?}");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_errors_name_their_constraints() {
    let (db, pool) = seeded().await;
    let create = |new: NewServiceGrant| {
        let pool = pool.clone();
        async move { registry::create_service_grant(&pool, &new).await }
    };
    let base = || direct_grant("ten_a", "grt_9", "wld_1", &["bnd_1"]);
    assert_exists(
        create(direct_grant("ten_a", "grt_1", "wld_1", &["bnd_1"])).await,
        "service_grant_pkey",
    );
    assert_exists(
        create(NewServiceGrant {
            name: "grant-grt_1".into(),
            ..base()
        })
        .await,
        "service_grant_tenant_id_name_key",
    );
    // A missing tenant breaks two foreign keys; either may fire first.
    match create(direct_grant("ten_x", "grt_9", "wld_1", &["bnd_1"])).await {
        Err(RegistryError::Invariant {
            kind: InvariantKind::ForeignKey,
            constraint:
                Some("service_grant_tenant_id_fkey" | "service_grant_actor_principal_id_fkey"),
        }) => {}
        other => panic!("{other:?}"),
    }
    // A service, a human, another tenant's workload or a missing principal
    // is no actor. The grant has no binding row, which would also break
    // `service_grant_binding_binding_id_fkey` (a binding row carries the
    // actor); the deferred binding-set check would fail only at commit,
    // after the actor's foreign key fails the statement.
    for actor in ["svc_1", "usr_1", "wld_b", "wld_x"] {
        assert_foreign_key(
            create(direct_grant("ten_a", "grt_9", actor, &[])).await,
            "service_grant_actor_principal_id_fkey",
        );
    }
    for target in ["svc_x", "svc_b", "wld_1"] {
        assert_foreign_key(
            create(NewServiceGrant {
                target_service_id: Some(target.into()),
                mode: GrantMode::Delegation,
                ..base()
            })
            .await,
            "service_grant_target_service_id_fkey",
        );
    }
    // Another actor's binding, another tenant's binding, a missing one.
    for binding in ["bnd_3", "bnd_b", "bnd_x"] {
        assert_foreign_key(
            create(direct_grant("ten_a", "grt_9", "wld_1", &["bnd_1", binding])).await,
            "service_grant_binding_binding_id_fkey",
        );
    }
    assert_exists(
        create(direct_grant("ten_a", "grt_9", "wld_1", &["bnd_1", "bnd_1"])).await,
        "service_grant_binding_pkey",
    );
    // rs_2 is assigned to ten_b only; rs_x does not exist.
    for rs in ["rs_2", "rs_x"] {
        assert_foreign_key(
            create(NewServiceGrant {
                resource_server_ids: strings(&[rs]),
                ..base()
            })
            .await,
            "service_grant_resource_server_assignment_fkey",
        );
    }
    assert_exists(
        create(NewServiceGrant {
            resource_server_ids: strings(&["rs_1", "rs_1"]),
            ..base()
        })
        .await,
        "service_grant_resource_server_pkey",
    );
    let cases: Vec<(NewServiceGrant, &str)> = vec![
        (
            NewServiceGrant {
                target_service_id: Some("svc_1".into()),
                ..base()
            },
            "service_grant_target_mode_check",
        ),
        (
            NewServiceGrant {
                mode: GrantMode::Delegation,
                ..base()
            },
            "service_grant_target_mode_check",
        ),
        (
            NewServiceGrant {
                activation_state: ActivationState::RequiresReapproval,
                ..base()
            },
            "service_grant_activation_mode_check",
        ),
        (
            NewServiceGrant {
                target_service_id: Some("svc_1".into()),
                mode: GrantMode::Impersonation,
                status: Status::Disabled,
                ..base()
            },
            "service_grant_activation_mode_check",
        ),
        (
            NewServiceGrant {
                target_service_id: Some("svc_1".into()),
                mode: GrantMode::Impersonation,
                activation_state: ActivationState::RequiresReapproval,
                ..base()
            },
            "service_grant_impersonation_disabled_check",
        ),
        (
            NewServiceGrant {
                default_scopes: Some(vec![]),
                ..base()
            },
            "service_grant_default_scopes_check",
        ),
        (
            NewServiceGrant {
                default_scopes: Some(strings(&["admin"])),
                ..base()
            },
            "service_grant_default_scopes_check",
        ),
        (
            NewServiceGrant {
                max_ttl: 0,
                ..base()
            },
            "service_grant_max_ttl_check",
        ),
        (
            NewServiceGrant {
                max_ttl: 301,
                ..base()
            },
            "service_grant_max_ttl_check",
        ),
        (
            NewServiceGrant {
                scopes: strings(&["read", ""]),
                ..base()
            },
            "skyoauth_scope_list_check",
        ),
        (
            NewServiceGrant {
                name: "a\tb".into(),
                ..base()
            },
            "service_grant_name_no_space_check",
        ),
        (
            NewServiceGrant {
                id: String::new(),
                ..base()
            },
            "service_grant_id_check",
        ),
        (
            NewServiceGrant {
                actor_principal_id: "w".repeat(256),
                ..base()
            },
            "service_grant_actor_principal_id_octet_length_check",
        ),
        (
            NewServiceGrant {
                allowed_binding_ids: vec!["b".repeat(256)],
                ..base()
            },
            "service_grant_binding_binding_id_octet_length_check",
        ),
        (
            NewServiceGrant {
                resource_server_ids: vec!["r".repeat(256)],
                ..base()
            },
            "service_grant_resource_server_server_id_octet_length_check",
        ),
    ];
    for (grant, name) in cases {
        assert_check(create(grant).await, name);
    }
    assert_not_found(registry::get_service_grant(&pool, "ten_a", "grt_9").await);

    // List rows of a grant: bindings of the actor and assigned audiences.
    assert_eq!(
        registry::add_service_grant_resource_server(&pool, "ten_a", "grt_1", 1, "rs_3")
            .await
            .unwrap(),
        2
    );
    assert_exists(
        registry::add_service_grant_resource_server(&pool, "ten_a", "grt_1", 2, "rs_3").await,
        "service_grant_resource_server_pkey",
    );
    assert_foreign_key(
        registry::add_service_grant_resource_server(&pool, "ten_a", "grt_1", 2, "rs_2").await,
        "service_grant_resource_server_assignment_fkey",
    );
    assert_not_found(
        registry::remove_service_grant_resource_server(&pool, "ten_a", "grt_1", 2, "rs_2").await,
    );
    assert_eq!(
        registry::remove_service_grant_resource_server(&pool, "ten_a", "grt_1", 2, "rs_1")
            .await
            .unwrap(),
        3
    );
    assert_exists(
        registry::add_service_grant_binding(&pool, "ten_a", "grt_1", 3, "bnd_1").await,
        "service_grant_binding_pkey",
    );
    for binding in ["bnd_3", "bnd_b", "bnd_x"] {
        assert_foreign_key(
            registry::add_service_grant_binding(&pool, "ten_a", "grt_1", 3, binding).await,
            "service_grant_binding_binding_id_fkey",
        );
    }
    assert_stale(registry::add_service_grant_binding(&pool, "ten_a", "grt_1", 2, "bnd_x").await);
    assert_not_found(
        registry::add_service_grant_binding(&pool, "ten_b", "grt_1", 3, "bnd_1").await,
    );
    assert_not_found(
        registry::add_service_grant_binding(&pool, "ten_a", "grt_x", 1, "bnd_1").await,
    );
    assert_not_found(
        registry::remove_service_grant_binding(&pool, "ten_a", "grt_1", 3, "bnd_3").await,
    );
    assert_not_found(
        registry::remove_service_grant_binding(&pool, "ten_b", "grt_1", 3, "bnd_1").await,
    );
    let grant = grant_of(&pool, "grt_1").await;
    assert_eq!(grant.revision, 3);
    assert_eq!(grant.resource_server_ids, ["rs_3"]);
    assert_eq!(grant.allowed_binding_ids, ["bnd_1", "bnd_2"]);
    db.drop([pool]).await;
}

/// The binding-set check runs at commit. Outside a transaction a call
/// commits at once, so it fails with `Guard`; inside one the commit does,
/// unless a binding is in place by then.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_grant_keeps_at_least_one_binding_through_the_registry() {
    let (db, pool) = seeded().await;
    // No binding, autocommit.
    assert_guard(
        registry::create_service_grant(&pool, &direct_grant("ten_a", "grt_9", "wld_1", &[])).await,
    );
    assert_not_found(registry::get_service_grant(&pool, "ten_a", "grt_9").await);

    // No binding in a transaction: the statement passes, the commit fails.
    let mut tx = pool.begin().await.unwrap();
    let created =
        registry::create_service_grant(&mut *tx, &direct_grant("ten_a", "grt_9", "wld_1", &[]))
            .await
            .unwrap();
    assert!(created.allowed_binding_ids.is_empty());
    assert_guard(tx.commit().await.map_err(RegistryError::from));
    assert_not_found(registry::get_service_grant(&pool, "ten_a", "grt_9").await);

    // Created empty, then given a binding before the commit.
    let mut tx = pool.begin().await.unwrap();
    registry::create_service_grant(&mut *tx, &direct_grant("ten_a", "grt_9", "wld_1", &[]))
        .await
        .unwrap();
    assert_eq!(
        registry::add_service_grant_binding(&mut *tx, "ten_a", "grt_9", 1, "bnd_2")
            .await
            .unwrap(),
        2
    );
    tx.commit().await.unwrap();
    let grant = grant_of(&pool, "grt_9").await;
    assert_eq!(
        (grant.revision, &grant.allowed_binding_ids[..]),
        (2, &strings(&["bnd_2"])[..])
    );

    // Removing the last binding fails at once outside a transaction, and
    // changes nothing.
    assert_guard(registry::remove_service_grant_binding(&pool, "ten_a", "grt_9", 2, "bnd_2").await);
    let grant = grant_of(&pool, "grt_9").await;
    assert_eq!(
        (grant.revision, &grant.allowed_binding_ids[..]),
        (2, &strings(&["bnd_2"])[..])
    );

    // In a transaction it fails at commit, and rolls back.
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        registry::remove_service_grant_binding(&mut *tx, "ten_a", "grt_9", 2, "bnd_2")
            .await
            .unwrap(),
        3
    );
    assert!(
        registry::get_service_grant(&mut *tx, "ten_a", "grt_9")
            .await
            .unwrap()
            .allowed_binding_ids
            .is_empty()
    );
    assert_guard(tx.commit().await.map_err(RegistryError::from));
    let grant = grant_of(&pool, "grt_9").await;
    assert_eq!(
        (grant.revision, &grant.allowed_binding_ids[..]),
        (2, &strings(&["bnd_2"])[..])
    );

    // Replacing the last binding in one transaction commits.
    let mut tx = pool.begin().await.unwrap();
    registry::remove_service_grant_binding(&mut *tx, "ten_a", "grt_9", 2, "bnd_2")
        .await
        .unwrap();
    registry::add_service_grant_binding(&mut *tx, "ten_a", "grt_9", 3, "bnd_1")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let grant = grant_of(&pool, "grt_9").await;
    assert_eq!(
        (grant.revision, &grant.allowed_binding_ids[..]),
        (4, &strings(&["bnd_1"])[..])
    );

    // One of two bindings goes at once.
    assert_eq!(
        registry::remove_service_grant_binding(&pool, "ten_a", "grt_1", 1, "bnd_1")
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        grant_of(&pool, "grt_1").await.allowed_binding_ids,
        ["bnd_2"]
    );
    db.drop([pool]).await;
}

/// Waits until the backend `blocked` waits for a lock held by `holder`.
async fn wait_until_blocked(pool: &PgPool, blocked: i32, holder: i32) {
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
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the second remover never waited for the grant row");
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// The SQLSTATE of a `Retry` error, from its `source()`, the raw
/// `sqlx::Error`.
fn retry_sqlstate(err: &RegistryError) -> String {
    assert!(matches!(err, RegistryError::Retry(_)), "{err:?}");
    err.source()
        .and_then(|source| source.downcast_ref::<sqlx::Error>())
        .and_then(sqlx::Error::as_database_error)
        .and_then(|source| source.code())
        .unwrap_or_else(|| panic!("no SQLSTATE: {err:?}"))
        .into_owned()
}

/// Two connections at `level` each remove one of `grt_1`'s two bindings
/// through the registry, from the same revision. The second waits for the
/// first's grant row; once the first commits, the second loses, and the
/// grant keeps a binding. Returns the loser's error.
async fn race_binding_removals(level: &str) -> RegistryError {
    let (db, pool) = seeded().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let set_level = match level {
        "READ COMMITTED" => "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
        "REPEATABLE READ" => "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SERIALIZABLE" => "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        other => panic!("{other}"),
    };
    let mut tx = first.begin().await.unwrap();
    sqlx::raw_sql(set_level).execute(&mut *tx).await.unwrap();
    assert_eq!(
        registry::remove_service_grant_binding(&mut *tx, "ten_a", "grt_1", 1, "bnd_1")
            .await
            .unwrap(),
        2
    );
    let waiting = tokio::spawn(async move {
        let mut tx = second.begin().await.unwrap();
        sqlx::raw_sql(set_level).execute(&mut *tx).await.unwrap();
        // The snapshot of a REPEATABLE READ transaction starts here, before
        // the first remover commits.
        let seen = registry::get_service_grant(&mut *tx, "ten_a", "grt_1")
            .await
            .unwrap();
        assert_eq!(seen.allowed_binding_ids, ["bnd_1", "bnd_2"]);
        let result =
            registry::remove_service_grant_binding(&mut *tx, "ten_a", "grt_1", 1, "bnd_2").await;
        tx.rollback().await.unwrap();
        second.close().await.unwrap();
        result
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    assert!(!waiting.is_finished());
    tx.commit().await.unwrap();
    first.close().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(30), waiting)
        .await
        .expect("the second remover never finished")
        .unwrap();
    let err = result.expect_err("both removers succeeded");
    let grant = grant_of(&pool, "grt_1").await;
    assert_eq!(
        (grant.revision, &grant.allowed_binding_ids[..]),
        (2, &strings(&["bnd_2"])[..]),
        "{level}"
    );
    db.drop([pool]).await;
    err
}

/// Under READ COMMITTED the later remover re-reads the grant row, finds
/// the revision moved and is stale.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_binding_removals_through_the_registry_under_read_committed() {
    assert_stale::<()>(Err(race_binding_removals("READ COMMITTED").await));
}

/// Under REPEATABLE READ and SERIALIZABLE PostgreSQL fails the later
/// remover with a serialization failure (`40001`), which is `Retry`, never
/// `StaleRevision`; the grant still keeps one binding. A remover whose snapshot predates the other's
/// commit cannot catch up by passing the new revision: its snapshot shows
/// the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_binding_removals_through_the_registry_under_repeatable_read() {
    for level in ["REPEATABLE READ", "SERIALIZABLE"] {
        let err = race_binding_removals(level).await;
        // The later remover waits for the grant row only (the statement
        // locks it before the binding row), so it cannot deadlock.
        assert_eq!(retry_sqlstate(&err), "40001", "{level}: {err}");
        assert_eq!(
            err.to_string(),
            "registry transaction aborted (SQLSTATE 40001); retry the whole transaction"
        );
    }

    let (db, pool) = seeded().await;
    let mut late = pool.begin().await.unwrap();
    sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *late)
        .await
        .unwrap();
    assert_eq!(
        registry::get_service_grant(&mut *late, "ten_a", "grt_1")
            .await
            .unwrap()
            .revision,
        1
    );
    registry::remove_service_grant_binding(&pool, "ten_a", "grt_1", 1, "bnd_1")
        .await
        .unwrap();
    assert_stale(
        registry::remove_service_grant_binding(&mut *late, "ten_a", "grt_1", 2, "bnd_2").await,
    );
    late.rollback().await.unwrap();
    assert_eq!(
        grant_of(&pool, "grt_1").await.allowed_binding_ids,
        ["bnd_2"]
    );
    db.drop([pool]).await;
}

/// Of four concurrent writes from one revision exactly one succeeds, for
/// every `0004` table with a revision and for every list-set change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_writes_from_one_revision_have_exactly_one_winner() {
    let (db, pool) = seeded().await;
    // Four more bindings of wld_1 and four more audiences of ten_a, so
    // concurrent adds name different rows.
    for n in 0..4 {
        registry::create_principal_binding(
            &pool,
            &new_binding("ten_a", &format!("bnd_c{n}"), "src_gh", "wld_1"),
        )
        .await
        .unwrap();
        registry::create_resource_server(&pool, &new_server(&format!("rs_c{n}")))
            .await
            .unwrap();
        registry::create_audience_tenant_assignment(
            &pool,
            &new_assignment(&format!("ata_c{n}"), &format!("rs_c{n}"), "ten_a"),
        )
        .await
        .unwrap();
    }

    async fn race<F, Fut, T>(attempt: F) -> (usize, usize)
    where
        F: Fn(usize) -> Fut,
        Fut: Future<Output = Result<T, RegistryError>> + Send + 'static,
        T: Send + 'static,
    {
        let tasks: Vec<_> = (0..4).map(|n| tokio::spawn(attempt(n))).collect();
        let (mut won, mut stale) = (0, 0);
        for task in tasks {
            match task.await.unwrap() {
                Ok(_) => won += 1,
                Err(RegistryError::StaleRevision) => stale += 1,
                Err(other) => panic!("{other:?}"),
            }
        }
        (won, stale)
    }

    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            let changes = TrustKeysetChanges {
                name: format!("ks-n{n}"),
                status: Status::Enabled,
            };
            registry::update_trust_keyset(&pool, "ten_a", "ks_1", 1, &changes).await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "trust_keyset");

    let source = registry::get_trust_source(&pool, "ten_a", "src_gh")
        .await
        .unwrap();
    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        let mut changes = source_changes(&source);
        changes.name = format!("src-n{n}");
        async move { registry::update_trust_source(&pool, "ten_a", "src_gh", 1, &changes).await }
    })
    .await;
    assert_eq!(outcome, (1, 3), "trust_source");

    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            let changes = PrincipalBindingChanges {
                name: format!("bnd-n{n}"),
                profile: BindingProfile::GenericProduction,
                claim_match_policy: claims(&[("sub", "x")]),
                status: Status::Enabled,
            };
            registry::update_principal_binding(&pool, "ten_a", "bnd_3", 1, &changes).await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "principal_binding");

    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            let changes = ServiceIdentityChanges {
                name: format!("svc-n{n}"),
                max_scopes: vec![],
                max_resource_constraints: JsonObject::new(),
                status: Status::Enabled,
            };
            registry::update_service_identity(&pool, "ten_a", "svc_1", 1, &changes).await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "service_identity");

    let grant = grant_of(&pool, "grt_1").await;
    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        let mut changes = grant_changes(&grant);
        changes.name = format!("grt-n{n}");
        async move { registry::update_service_grant(&pool, "ten_a", "grt_1", 1, &changes).await }
    })
    .await;
    assert_eq!(outcome, (1, 3), "service_grant");

    // List sets: four adds of different rows, then four removes of the one
    // added, each from one revision.
    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            registry::add_service_identity_resource_server(
                &pool,
                "ten_a",
                "svc_1",
                2,
                &format!("rs_c{n}"),
            )
            .await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "add service audience");
    let svc = registry::get_service_identity(&pool, "ten_a", "svc_1")
        .await
        .unwrap();
    assert_eq!((svc.revision, svc.resource_server_ids.len()), (3, 2));
    let added = svc.resource_server_ids[1].clone();
    let p = pool.clone();
    let outcome = race(move |_| {
        let pool = p.clone();
        let added = added.clone();
        async move {
            registry::remove_service_identity_resource_server(&pool, "ten_a", "svc_1", 3, &added)
                .await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "remove service audience");

    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            registry::add_service_grant_binding(&pool, "ten_a", "grt_1", 2, &format!("bnd_c{n}"))
                .await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "add grant binding");
    let grant = grant_of(&pool, "grt_1").await;
    assert_eq!((grant.revision, grant.allowed_binding_ids.len()), (3, 3));
    let added = grant.allowed_binding_ids[2].clone();
    let p = pool.clone();
    let outcome =
        race(move |_| {
            let pool = p.clone();
            let added = added.clone();
            async move {
                registry::remove_service_grant_binding(&pool, "ten_a", "grt_1", 3, &added).await
            }
        })
        .await;
    assert_eq!(outcome, (1, 3), "remove grant binding");

    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            registry::add_service_grant_resource_server(
                &pool,
                "ten_a",
                "grt_1",
                4,
                &format!("rs_c{n}"),
            )
            .await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "add grant audience");
    let p = pool.clone();
    let outcome = race(move |_| {
        let pool = p.clone();
        async move {
            registry::remove_service_grant_resource_server(&pool, "ten_a", "grt_1", 5, "rs_1").await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "remove grant audience");
    let grant = grant_of(&pool, "grt_1").await;
    assert_eq!(
        (
            grant.revision,
            grant.allowed_binding_ids.len(),
            grant.resource_server_ids.len()
        ),
        (6, 2, 1)
    );

    // Four removals of four different bindings from one revision: one wins,
    // so the grant keeps three.
    registry::create_service_grant(
        &pool,
        &direct_grant(
            "ten_a",
            "grt_4",
            "wld_1",
            &["bnd_c0", "bnd_c1", "bnd_c2", "bnd_c3"],
        ),
    )
    .await
    .unwrap();
    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            registry::remove_service_grant_binding(&pool, "ten_a", "grt_4", 1, &format!("bnd_c{n}"))
                .await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "remove different grant bindings");
    let grant = grant_of(&pool, "grt_4").await;
    assert_eq!((grant.revision, grant.allowed_binding_ids.len()), (2, 3));
    db.drop([pool]).await;
}

/// Every read, update and list-set change names the tenant: another
/// tenant's ID is not found, and lists hold one tenant's rows.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_and_grant_reads_are_scoped_to_their_tenant() {
    let (db, pool) = seeded().await;
    registry::create_trust_keyset_version(&pool, &new_version("ten_b", "kv_b", "ks_b"))
        .await
        .unwrap();
    for (tenant, other) in [("ten_a", "ten_b"), ("ten_b", "ten_a")] {
        let keysets = registry::list_trust_keysets(&pool, tenant, Page::first(10))
            .await
            .unwrap();
        let sources = registry::list_trust_sources(&pool, tenant, Page::first(10))
            .await
            .unwrap();
        let bindings = registry::list_principal_bindings(&pool, tenant, Page::first(10))
            .await
            .unwrap();
        let services = registry::list_service_identities(&pool, tenant, Page::first(10))
            .await
            .unwrap();
        let grants = registry::list_service_grants(&pool, tenant, Page::first(10))
            .await
            .unwrap();
        assert!(keysets.iter().all(|row| row.tenant_id == tenant));
        assert!(sources.iter().all(|row| row.tenant_id == tenant));
        assert!(bindings.iter().all(|row| row.tenant_id == tenant));
        assert!(services.iter().all(|row| row.tenant_id == tenant));
        assert!(grants.iter().all(|row| row.tenant_id == tenant));
        for keyset in &keysets {
            assert_not_found(registry::get_trust_keyset(&pool, other, &keyset.id).await);
            assert!(
                registry::list_trust_keyset_versions(&pool, other, &keyset.id, Page::first(10))
                    .await
                    .unwrap()
                    .is_empty()
            );
            let changes = TrustKeysetChanges {
                name: "x".into(),
                status: Status::Enabled,
            };
            assert_not_found(
                registry::update_trust_keyset(&pool, other, &keyset.id, 1, &changes).await,
            );
        }
        for source in &sources {
            assert_not_found(registry::get_trust_source(&pool, other, &source.id).await);
            assert_not_found(
                registry::update_trust_source(&pool, other, &source.id, 1, &source_changes(source))
                    .await,
            );
        }
        for binding in &bindings {
            assert_not_found(registry::get_principal_binding(&pool, other, &binding.id).await);
        }
        for service in &services {
            assert_not_found(registry::get_service_identity(&pool, other, &service.id).await);
            assert_not_found(
                registry::remove_service_identity_resource_server(
                    &pool,
                    other,
                    &service.id,
                    1,
                    &service.resource_server_ids[0],
                )
                .await,
            );
        }
        for grant in &grants {
            assert_not_found(registry::get_service_grant(&pool, other, &grant.id).await);
            assert_not_found(
                registry::update_service_grant(&pool, other, &grant.id, 1, &grant_changes(grant))
                    .await,
            );
            assert_not_found(
                registry::remove_service_grant_binding(
                    &pool,
                    other,
                    &grant.id,
                    1,
                    &grant.allowed_binding_ids[0],
                )
                .await,
            );
            assert_not_found(
                registry::add_service_grant_resource_server(&pool, other, &grant.id, 1, "rs_1")
                    .await,
            );
        }
    }
    assert_not_found(registry::get_trust_keyset_version(&pool, "ten_a", "kv_b").await);
    assert_eq!(
        registry::get_trust_keyset_version(&pool, "ten_b", "kv_b")
            .await
            .unwrap()
            .keyset_id,
        "ks_b"
    );
    let a: Vec<_> = registry::list_service_grants(&pool, "ten_a", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert_eq!(a, ["grt_1"]);
    assert!(
        registry::list_trust_sources(&pool, "ten_x", Page::first(10))
            .await
            .unwrap()
            .is_empty()
    );
    // Nothing above changed a row.
    assert_eq!(grant_of(&pool, "grt_1").await.revision, 1);
    db.drop([pool]).await;
}

/// Every row of the `0004` tables as text, so a test can show that a
/// failed call changed nothing.
async fn rows_0004(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT concat_ws(E'\\n', \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) FROM trust_keyset t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) FROM trust_keyset_version t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) FROM trust_source t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) FROM principal_binding t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) FROM service_identity t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) \
          FROM service_identity_resource_server t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) FROM service_grant t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) FROM service_grant_binding t), \
         (SELECT string_agg(t::text, E'\\n' ORDER BY t::text) \
          FROM service_grant_resource_server t))",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The expected revision is only compared, never computed with: `i64::MAX`
/// gives `StaleRevision` for an existing row and `NotFound` for a missing
/// row or another tenant's, from every `0004` update and list-set change,
/// not an overflow (`22003`) that would abort a caller transaction.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_expected_revision_of_i64_max_is_stale_or_not_found() {
    const MAX: i64 = i64::MAX;
    let (db, pool) = seeded().await;
    // A second binding of wld_1's grant actor, so it could be added.
    registry::create_principal_binding(&pool, &new_binding("ten_a", "bnd_4", "src_gh", "wld_1"))
        .await
        .unwrap();
    let before = rows_0004(&pool).await;
    let keyset_changes = TrustKeysetChanges {
        name: "renamed".into(),
        status: Status::Disabled,
    };
    let mut source_changes = source_changes(
        &registry::get_trust_source(&pool, "ten_a", "src_gh")
            .await
            .unwrap(),
    );
    source_changes.name = "renamed".into();
    let binding_changes = PrincipalBindingChanges {
        name: "renamed".into(),
        profile: BindingProfile::GithubProduction,
        claim_match_policy: github_claims(),
        status: Status::Disabled,
    };
    let service_changes = ServiceIdentityChanges {
        name: "renamed".into(),
        max_scopes: strings(&["read"]),
        max_resource_constraints: object(json!({"version": 2})),
        status: Status::Disabled,
    };
    let mut grant_changes = grant_changes(&grant_of(&pool, "grt_1").await);
    grant_changes.name = "renamed".into();

    // Each function at i64::MAX: the ten_a row is stale; a missing ID and
    // the ten_b row are not found in ten_a.
    macro_rules! at_max {
        ($function:ident, $id:literal, $other_tenant_id:literal, $argument:expr) => {
            assert_stale(registry::$function(&pool, "ten_a", $id, MAX, $argument).await);
            assert_not_found(registry::$function(&pool, "ten_a", "x_1", MAX, $argument).await);
            assert_not_found(
                registry::$function(&pool, "ten_a", $other_tenant_id, MAX, $argument).await,
            );
        };
    }
    at_max!(update_trust_keyset, "ks_1", "ks_b", &keyset_changes);
    at_max!(update_trust_source, "src_gh", "src_b", &source_changes);
    at_max!(update_principal_binding, "bnd_1", "bnd_b", &binding_changes);
    at_max!(update_service_identity, "svc_1", "svc_b", &service_changes);
    at_max!(update_service_grant, "grt_1", "grt_b", &grant_changes);
    // Each item could be added, or is listed and could be removed, at the
    // owner's revision 1.
    at_max!(
        add_service_identity_resource_server,
        "svc_1",
        "svc_b",
        "rs_3"
    );
    at_max!(
        remove_service_identity_resource_server,
        "svc_1",
        "svc_b",
        "rs_1"
    );
    at_max!(add_service_grant_binding, "grt_1", "grt_b", "bnd_4");
    at_max!(remove_service_grant_binding, "grt_1", "grt_b", "bnd_1");
    at_max!(add_service_grant_resource_server, "grt_1", "grt_b", "rs_3");
    at_max!(
        remove_service_grant_resource_server,
        "grt_1",
        "grt_b",
        "rs_1"
    );

    assert_eq!(rows_0004(&pool).await, before);
    // The same calls at the current revision succeed, so the rows and
    // items above were live targets.
    assert_eq!(
        registry::add_service_grant_binding(&pool, "ten_a", "grt_1", 1, "bnd_4")
            .await
            .unwrap(),
        2
    );
    db.drop([pool]).await;
}

/// A time the registry cannot write so that it reads back exactly is an
/// encode error before any statement runs; the times at the bounds round
/// trip.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn times_at_the_writable_bounds_round_trip_and_beyond_them_write_nothing() {
    const EARLIEST: i64 = -210_866_803_200_000_000;
    const LATEST: i64 = i64::MAX - 1;
    let (db, pool) = seeded().await;
    let mut bounds = new_version("ten_a", "kv_1", "ks_1");
    bounds.effective_at = at(EARLIEST);
    bounds.expires_at = Some(at(LATEST));
    let created = registry::create_trust_keyset_version(&pool, &bounds)
        .await
        .unwrap();
    assert_eq!(
        (created.effective_at, created.expires_at),
        (at(EARLIEST), Some(at(LATEST)))
    );
    assert_eq!(
        registry::get_trust_keyset_version(&pool, "ten_a", "kv_1")
            .await
            .unwrap(),
        created
    );
    let before = rows_0004(&pool).await;

    #[track_caller]
    fn assert_out_of_range<T: Debug>(result: Result<T, RegistryError>) {
        match result {
            Err(RegistryError::Other(sqlx::Error::Encode(err))) => {
                assert_eq!(err.to_string(), "timestamp out of range");
            }
            other => panic!("expected an encode error: {other:?}"),
        }
    }
    let mut early = new_version("ten_a", "kv_2", "ks_1");
    early.effective_at = at(EARLIEST - 1);
    assert_out_of_range(registry::create_trust_keyset_version(&pool, &early).await);
    let mut late = new_version("ten_a", "kv_2", "ks_1");
    late.expires_at = Some(at(i64::MAX));
    assert_out_of_range(registry::create_trust_keyset_version(&pool, &late).await);
    let mut grant = direct_grant("ten_a", "grt_2", "wld_1", &["bnd_1"]);
    grant.valid_until = Some(at(EARLIEST - 1));
    assert_out_of_range(registry::create_service_grant(&pool, &grant).await);
    let mut changes = grant_changes(&grant_of(&pool, "grt_1").await);
    changes.valid_until = Some(at(i64::MAX));
    assert_out_of_range(registry::update_service_grant(&pool, "ten_a", "grt_1", 1, &changes).await);
    assert_eq!(rows_0004(&pool).await, before);

    // A grant's valid_until at either bound round trips too.
    for (expected, valid_until) in [(1, EARLIEST), (2, LATEST)] {
        changes.valid_until = Some(at(valid_until));
        let updated = registry::update_service_grant(&pool, "ten_a", "grt_1", expected, &changes)
            .await
            .unwrap();
        assert_eq!(updated.valid_until, Some(at(valid_until)));
        assert_eq!(grant_of(&pool, "grt_1").await, updated);
    }
    db.drop([pool]).await;
}

/// The guards no registry function reaches (updates never touch an
/// immutable column) and the named constraints the typed inputs cannot
/// violate map from raw statements.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_guards_and_unreachable_constraints_map_from_raw_statements() {
    let (db, pool) = seeded().await;
    registry::create_trust_keyset_version(&pool, &new_version("ten_a", "kv_1", "ks_1"))
        .await
        .unwrap();
    for sql in [
        "UPDATE trust_keyset SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'ks_1'",
        "UPDATE trust_keyset_version SET fingerprint = 'sha256:02', revision = revision + 1 WHERE id = 'kv_1'",
        "UPDATE trust_source SET kind = 'oidc_discovery', revision = revision + 1 WHERE id = 'src_up'",
        "UPDATE trust_source SET cluster_id = 'cluster_2', revision = revision + 1 WHERE id = 'src_k8s'",
        "UPDATE principal_binding SET workload_principal_id = 'wld_2', revision = revision + 1 WHERE id = 'bnd_1'",
        "UPDATE service_grant SET mode = 'delegation', revision = revision + 1 WHERE id = 'grt_1'",
        "UPDATE service_grant SET revision = revision + 2 WHERE id = 'grt_1'",
        "UPDATE service_identity_resource_server SET resource_server_id = 'rs_3'",
        "DELETE FROM service_grant_binding WHERE grant_id = 'grt_1'",
    ] {
        let err = raw_error(&pool, sql).await;
        assert!(matches!(err, RegistryError::Guard), "{sql}: {err:?}");
    }
    for (sql, kind, name) in [
        (
            "INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_3', 'ten_a', 'wld_2')",
            InvariantKind::ForeignKey,
            "service_grant_binding_grant_id_fkey",
        ),
        (
            "INSERT INTO service_grant_resource_server VALUES ('grt_x', 'ten_a', 'rs_1')",
            InvariantKind::ForeignKey,
            "service_grant_resource_server_grant_id_fkey",
        ),
        (
            "INSERT INTO service_identity_resource_server VALUES ('svc_x', 'ten_a', 'rs_1')",
            InvariantKind::ForeignKey,
            "service_identity_resource_server_service_id_fkey",
        ),
        (
            "UPDATE service_grant SET resource_constraints = '[]', revision = revision + 1 WHERE id = 'grt_1'",
            InvariantKind::Check,
            "service_grant_resource_constraints_check",
        ),
        (
            "UPDATE service_identity SET max_resource_constraints = '1', revision = revision + 1 WHERE id = 'svc_1'",
            InvariantKind::Check,
            "service_identity_max_resource_constraints_check",
        ),
        (
            "UPDATE trust_source SET proof_bounds = '[]', revision = revision + 1 WHERE id = 'src_gh'",
            InvariantKind::Check,
            "trust_source_proof_bounds_check",
        ),
        (
            "UPDATE trust_source SET replay_mode = 'once', revision = revision + 1 WHERE id = 'src_gh'",
            InvariantKind::Check,
            "trust_source_replay_mode_check",
        ),
        (
            "UPDATE principal_binding SET profile = 'other', revision = revision + 1 WHERE id = 'bnd_1'",
            InvariantKind::Check,
            "principal_binding_profile_check",
        ),
        // bnd_1 is a github_production binding, so these also fail the
        // 0008 check of its profile; PostgreSQL evaluates a table's checks
        // in name order, and the 0004 check's name sorts first.
        (
            "UPDATE principal_binding SET claim_match_policy = '{}', revision = revision + 1 WHERE id = 'bnd_1'",
            InvariantKind::Check,
            "principal_binding_claim_match_policy_check",
        ),
        (
            "UPDATE principal_binding SET claim_match_policy = '{\"a\": 1}', revision = revision + 1 WHERE id = 'bnd_1'",
            InvariantKind::Check,
            "principal_binding_claim_match_policy_check",
        ),
        (
            "INSERT INTO trust_keyset_version VALUES ('kv_9', 'ten_a', 'ks_1', '{\"keys\": [{}]}', \
             'sha256:09', now(), NULL, 'enabled', '[]')",
            InvariantKind::Check,
            "trust_keyset_version_provenance_check",
        ),
    ] {
        let err = raw_error(&pool, sql).await;
        match err {
            RegistryError::Invariant {
                kind: actual,
                constraint: Some(constraint),
            } => assert_eq!((actual, constraint), (kind, name), "{sql}"),
            other => panic!("{sql}: {other:?}"),
        }
    }
    db.drop([pool]).await;
}

/// Error text never repeats a value from the request.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_errors_do_not_repeat_request_values() {
    let (db, pool) = seeded().await;
    let mut source = token_review_source("ten_a", "src_x", "x", "cluster_1");
    source.reviewer_credential_ref = Some("secret-ref-value".into());
    let err = registry::create_trust_source(&pool, &source)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::AlreadyExists { .. }),
        "{err:?}"
    );
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(
            !text.contains("cluster_1") && !text.contains("secret-ref-value"),
            "{text}"
        );
    }
    let mut binding = new_binding("ten_a", "bnd_9", "src_gh", "wld_1");
    binding.name = "claim value-that-must-not-leak".into();
    let err = registry::create_principal_binding(&pool, &binding)
        .await
        .unwrap_err();
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains("must-not-leak"), "{text}");
    }
    let err = registry::create_service_grant(
        &pool,
        &direct_grant("ten_a", "grt_9", "wld_1", &["bnd-value-not-to-leak"]),
    )
    .await
    .unwrap_err();
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains("not-to-leak"), "{text}");
    }
    db.drop([pool]).await;
}

/// A stored time outside the range the `0007` checks hold (only possible
/// with a check dropped, here inside a rolled-back transaction) is
/// `UnreadableTimestamp` naming the table, the column and the row on every
/// read path, instead of the `0A000` (infinity) or `22003` (a later finite
/// time) the plain projection fails with.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn times_outside_the_range_checks_are_unreadable_timestamps_naming_the_row() {
    let (db, pool) = seeded().await;
    // What the plain projection gives for such times.
    for (sql, code) in [
        (
            "SELECT (extract(epoch FROM timestamptz 'infinity') * 1000000)::bigint",
            "0A000",
        ),
        (
            "SELECT (extract(epoch FROM timestamptz '-infinity') * 1000000)::bigint",
            "0A000",
        ),
        (
            "SELECT (extract(epoch FROM timestamptz '294270-01-01 00:00:00+00') * 1000000)::bigint",
            "22003",
        ),
    ] {
        let err = sqlx::raw_sql(sql).execute(&pool).await.expect_err(sql);
        let actual = err.as_database_error().and_then(|err| err.code());
        assert_eq!(actual.as_deref(), Some(code), "{sql}");
    }

    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(
        "ALTER TABLE tenant DROP CONSTRAINT tenant_created_at_range_check;
         ALTER TABLE principal DROP CONSTRAINT principal_created_at_range_check;
         ALTER TABLE trust_keyset_version
             DROP CONSTRAINT trust_keyset_version_effective_at_range_check,
             DROP CONSTRAINT trust_keyset_version_expires_at_range_check;
         ALTER TABLE service_grant DROP CONSTRAINT service_grant_valid_until_range_check;
         ALTER TABLE instance_security_policy
             DROP CONSTRAINT instance_security_policy_audit_sink_validated_at_range_check;
         INSERT INTO tenant (id, name, secret_namespace, status, created_at) VALUES
             ('ten_far', 'far', 'ns_far', 'enabled', '294270-01-01 00:00:00+00'),
             ('ten_inf', 'inf', 'ns_inf', 'enabled', 'infinity');
         INSERT INTO principal (id, tenant_id, kind, name, status, created_at) VALUES
             ('wld_far', 'ten_b', 'workload', 'far', 'enabled', '294247-01-10 04:00:54.775807+00');
         INSERT INTO trust_keyset_version
             (id, tenant_id, keyset_id, public_jwks, fingerprint, effective_at, expires_at,
              status, provenance) VALUES
             ('kv_early', 'ten_a', 'ks_1',
              '{\"keys\": [{\"kty\": \"EC\", \"crv\": \"P-256\", \"x\": \"AA\", \"y\": \"AA\"}]}',
              'sha256:01', '-infinity', NULL, 'enabled', '{}'),
             ('kv_late', 'ten_a', 'ks_1',
              '{\"keys\": [{\"kty\": \"EC\", \"crv\": \"P-256\", \"x\": \"AA\", \"y\": \"AA\"}]}',
              'sha256:01', '2026-01-01 00:00:00+00', 'infinity', 'enabled', '{}');
         UPDATE service_grant SET valid_until = 'infinity', revision = revision + 1
          WHERE id = 'grt_1';
         INSERT INTO instance_security_policy (instance_id, single_actor_mode,
             audit_sink_config_digest, audit_sink_validated_at)
             VALUES ('inst_1', true, '\\x01', '-infinity');",
    )
    .execute(&mut *tx)
    .await
    .unwrap();

    #[track_caller]
    fn assert_unreadable<T: Debug>(result: Result<T, RegistryError>, expected: (&str, &str, &str)) {
        match &result {
            Err(err @ RegistryError::UnreadableTimestamp { table, column, id }) => {
                assert_eq!((*table, *column, &id[..]), expected);
                for text in [err.to_string(), format!("{err:?}")] {
                    assert!(!text.contains(expected.2), "{text}");
                    assert!(text.contains(expected.0), "{text}");
                }
            }
            other => panic!("expected UnreadableTimestamp {expected:?}: {other:?}"),
        }
    }
    assert_unreadable(
        registry::get_tenant(&mut *tx, "ten_inf").await,
        ("tenant", "created_at", "ten_inf"),
    );
    assert_unreadable(
        registry::get_tenant(&mut *tx, "ten_far").await,
        ("tenant", "created_at", "ten_far"),
    );
    // A list stops at the first unreadable row in its order.
    assert_unreadable(
        registry::list_tenants(&mut *tx, Page::first(10)).await,
        ("tenant", "created_at", "ten_far"),
    );
    assert_eq!(
        registry::list_tenants(&mut *tx, Page::first(2))
            .await
            .unwrap()
            .len(),
        2
    );
    // One microsecond past the latest readable time.
    assert_unreadable(
        registry::get_principal(&mut *tx, "ten_b", "wld_far").await,
        ("principal", "created_at", "wld_far"),
    );
    assert_unreadable(
        registry::list_principals(&mut *tx, "ten_b", Page::first(10)).await,
        ("principal", "created_at", "wld_far"),
    );
    assert_unreadable(
        registry::get_trust_keyset_version(&mut *tx, "ten_a", "kv_early").await,
        ("trust_keyset_version", "effective_at", "kv_early"),
    );
    assert_unreadable(
        registry::get_trust_keyset_version(&mut *tx, "ten_a", "kv_late").await,
        ("trust_keyset_version", "expires_at", "kv_late"),
    );
    assert_unreadable(
        registry::list_trust_keyset_versions(&mut *tx, "ten_a", "ks_1", Page::first(10)).await,
        ("trust_keyset_version", "effective_at", "kv_early"),
    );
    assert_unreadable(
        registry::get_service_grant(&mut *tx, "ten_a", "grt_1").await,
        ("service_grant", "valid_until", "grt_1"),
    );
    assert_unreadable(
        registry::list_service_grants(&mut *tx, "ten_a", Page::first(10)).await,
        ("service_grant", "valid_until", "grt_1"),
    );
    assert_unreadable(
        registry::get_instance_security_policy(&mut *tx).await,
        (
            "instance_security_policy",
            "audit_sink_validated_at",
            "inst_1",
        ),
    );
    // The row an update returns is read the same way. With the check
    // dropped the write applies, and the caller gets the error.
    assert_unreadable(
        registry::update_trust_keyset_version(&mut *tx, "ten_a", "kv_late", 1, Status::Disabled)
            .await,
        ("trust_keyset_version", "expires_at", "kv_late"),
    );
    let written: (String, i64) =
        sqlx::query_as("SELECT status, revision FROM trust_keyset_version WHERE id = 'kv_late'")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(written, ("disabled".into(), 2));
    // With the check in force (here added back NOT VALID, so the row stays)
    // PostgreSQL checks the whole new row: the update fails with 23514 and
    // aborts the transaction.
    sqlx::raw_sql(
        "ALTER TABLE tenant ADD CONSTRAINT tenant_created_at_range_check
             CHECK (created_at >= timestamptz '4714-11-24 00:00:00+00 BC'
                AND created_at <= timestamptz '294247-01-10 04:00:54.775806+00') NOT VALID",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let patch = registry::TenantPatch {
        status: Some(Status::Disabled),
        ..registry::TenantPatch::default()
    };
    assert_check(
        registry::update_tenant(&mut *tx, "ten_inf", 1, &patch).await,
        "tenant_created_at_range_check",
    );
    tx.rollback().await.unwrap();

    // The checks are back and the rows gone.
    assert!(matches!(
        registry::get_tenant(&pool, "ten_inf").await,
        Err(RegistryError::NotFound)
    ));
    assert_eq!(
        registry::get_service_grant(&pool, "ten_a", "grt_1")
            .await
            .unwrap()
            .valid_until,
        None
    );
    db.drop([pool]).await;
}

/// `update_service_grant` replaces `valid_until`, so it repairs a grant
/// holding a time outside the range check even with the check in force,
/// here re-added `NOT VALID` over an `infinity` inside a rolled-back
/// transaction. A grant list-set change writes only the grant's revision:
/// with the check in force it fails with `23514`; with the check dropped it
/// applies without reading `valid_until`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_grant_update_repairs_a_valid_until_outside_a_not_valid_range_check() {
    const RANGE_CHECK: &str = "service_grant_valid_until_range_check";
    let (db, pool) = seeded().await;
    let before = grant_of(&pool, "grt_1").await;
    assert_eq!((before.valid_until, before.revision), (None, 1));

    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(
        "ALTER TABLE service_grant DROP CONSTRAINT service_grant_valid_until_range_check;
         UPDATE service_grant SET valid_until = 'infinity', revision = revision + 1
          WHERE id = 'grt_1'",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let unreadable = registry::get_service_grant(&mut *tx, "ten_a", "grt_1").await;
    assert!(
        matches!(
            &unreadable,
            Err(RegistryError::UnreadableTimestamp {
                table: "service_grant",
                column: "valid_until",
                id,
            }) if id == "grt_1"
        ),
        "{unreadable:?}"
    );
    // With the check dropped, a list-set change applies and returns only the
    // new revision.
    {
        let mut savepoint = tx.begin().await.unwrap();
        assert_eq!(
            registry::add_service_grant_resource_server(
                &mut *savepoint,
                "ten_a",
                "grt_1",
                2,
                "rs_3"
            )
            .await
            .unwrap(),
            3
        );
        savepoint.rollback().await.unwrap();
    }

    sqlx::raw_sql(
        "ALTER TABLE service_grant ADD CONSTRAINT service_grant_valid_until_range_check
             CHECK (valid_until >= timestamptz '4714-11-24 00:00:00+00 BC'
                AND valid_until <= timestamptz '294247-01-10 04:00:54.775806+00') NOT VALID",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let validated: bool = sqlx::query_scalar(
        "SELECT convalidated FROM pg_constraint
         WHERE conrelid = 'service_grant'::regclass AND conname = $1",
    )
    .bind(RANGE_CHECK)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(!validated);

    // A revision-only write of the grant, as every list-set change is, keeps
    // the `infinity` in the new row, so the check rejects it.
    {
        let mut savepoint = tx.begin().await.unwrap();
        assert_check(
            registry::add_service_grant_resource_server(
                &mut *savepoint,
                "ten_a",
                "grt_1",
                2,
                "rs_3",
            )
            .await,
            RANGE_CHECK,
        );
        savepoint.rollback().await.unwrap();
    }
    {
        let mut savepoint = tx.begin().await.unwrap();
        assert_check(
            registry::remove_service_grant_binding(&mut *savepoint, "ten_a", "grt_1", 2, "bnd_2")
                .await,
            RANGE_CHECK,
        );
        savepoint.rollback().await.unwrap();
    }

    // The same revision-checked update with no `valid_until` repairs the row
    // too.
    {
        let mut savepoint = tx.begin().await.unwrap();
        let cleared = registry::update_service_grant(
            &mut *savepoint,
            "ten_a",
            "grt_1",
            2,
            &grant_changes(&before),
        )
        .await
        .unwrap();
        assert_eq!((cleared.valid_until, cleared.revision), (None, 3));
        savepoint.rollback().await.unwrap();
    }
    // Stale is still stale.
    let mut changes = grant_changes(&before);
    changes.valid_until = Some(at(1_798_859_045_000_001));
    assert_stale(registry::update_service_grant(&mut *tx, "ten_a", "grt_1", 1, &changes).await);
    // A finite `valid_until` replaces the `infinity`: the update succeeds and
    // returns a readable row.
    let repaired = registry::update_service_grant(&mut *tx, "ten_a", "grt_1", 2, &changes)
        .await
        .unwrap();
    let mut expected = before.clone();
    expected.valid_until = Some(at(1_798_859_045_000_001));
    expected.revision = 3;
    assert_eq!(repaired, expected);
    assert_eq!(
        registry::get_service_grant(&mut *tx, "ten_a", "grt_1")
            .await
            .unwrap(),
        repaired
    );
    // Every row now passes the check, and list-set changes work again.
    sqlx::raw_sql(
        "ALTER TABLE service_grant VALIDATE CONSTRAINT service_grant_valid_until_range_check",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        registry::add_service_grant_resource_server(&mut *tx, "ten_a", "grt_1", 3, "rs_3")
            .await
            .unwrap(),
        4
    );
    tx.rollback().await.unwrap();

    assert_eq!(grant_of(&pool, "grt_1").await, before);
    db.drop([pool]).await;
}
