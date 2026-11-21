//! A29: tenants share a GitHub issuer or object names; crossed references.
//! Expected: registrations coexist, ownership crossover denied (tasks §8;
//! IR-031, IR-032; ADR-014).
//!
//! Stage M1a, "registry and references": the registry writes of the
//! tenant-owned `0004` records through the typed registry API
//! (`skyoauth_service::persistence::registry`) against a real PostgreSQL.
//!
//! - **Positive.** Two tenants register sources with the same exact issuer
//!   (the GitHub Actions issuer, an uploaded-JWKS issuer and a Kubernetes
//!   issuer) and every tenant-local object under the same names; all
//!   coexist. For trust sources, each tenant reads and lists only its own:
//!   the other tenant's same-issuer sources are not found and not listed.
//!   The other record kinds are read here only through their own tenant;
//!   their per-tenant reads and lists are covered by the service tests
//!   (`service/tests/registry_trust.rs`,
//!   `trust_and_grant_reads_are_scoped_to_their_tenant`: lists of keysets,
//!   sources, bindings, service identities and grants hold one tenant's
//!   rows, their gets from the other tenant are not found, and another
//!   tenant's keyset lists no versions;
//!   `keyset_versions_are_created_read_and_listed_per_keyset`: a keyset
//!   version get from another tenant is not found; and
//!   `service/tests/registry.rs`, `principal_reads_are_scoped_to_their_tenant`
//!   for principals). The keyset, source, binding, service identity and
//!   grant names are unique within one tenant only: a duplicate in the same
//!   tenant is refused by the table's `<table>_tenant_id_name_key`.
//! - **Negative.** Each write-time reference from one tenant's record to
//!   another tenant's record or audience is refused by its composite
//!   foreign key, reported as `Invariant { ForeignKey, <constraint> }`, and
//!   writes nothing; and a write that names another tenant's record finds
//!   nothing. Every case runs in both directions (A into B, B into A).
//!
//! Not covered here: the M2 stage (a proof from one tenant's source with
//! another tenant's grant at exchange); checker tenant sets (instance
//! records, A31/A45); records of later milestones (clients, origins, human
//! policies); authorization and the service rules the database does not
//! enforce (an enabled assignment, scope ceilings; T14.1, T14.2). Principal
//! and tenant names have no uniqueness rule: `0002` has no name key on
//! `principal` (IR-021; `service/migrations/README.md`, "Not done in
//! `0004`") nor on `tenant`, so the shared principal names (`"ci"`, …) and
//! tenant names of `a29_pos_tenants_reuse_object_names` prove nothing about
//! them; a same-tenant duplicate assertion for principals belongs with that
//! key when a migration adds it.
//!
//! The crossings are a closed list, one per composite foreign key of
//! `0004` that a tenant-owned write can name across tenants, so each is
//! enumerated in both directions instead of sampled. Three list-to-parent
//! keys have no foreign-key negative, because no write can name a parent of
//! another tenant through them: `service_identity_resource_server_service_id_fkey`,
//! `service_grant_binding_grant_id_fkey` and
//! `service_grant_resource_server_grant_id_fkey`. The registry inserts a
//! list row in the same statement as its owner and copies `tenant_id` (and
//! the grant's actor) from that owner row: from the row being created in
//! `create_service_identity` and `create_service_grant`, and from the row
//! its tenant-scoped revision update matched in the `add_*` list changes,
//! which find nothing for another tenant's owner
//! (`a29_neg_writes_to_other_tenants_records_find_nothing`).
//!
//! The list covers `0004` only. One tenant-owned crossing of a later
//! migration is covered outside A29: `consumed_assertion_trust_source_id_fkey`
//! (`0005`), a consumed proof naming another tenant's source, is refused in
//! both directions by `a24_neg_consume_names_other_tenants_source` (A24,
//! `tests/security/a24.rs`), not here.

use std::{
    collections::BTreeMap,
    fmt::Debug,
    time::{Duration, UNIX_EPOCH},
};

use serde_json::{Value, json};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, ActivationState, AssertionProfile, BindingProfile, GrantMode, InvariantKind,
        JsonObject, MAX_PAGE_SIZE, NewAudienceTenantAssignment, NewPrincipal, NewPrincipalBinding,
        NewResourceServer, NewServiceGrant, NewServiceIdentity, NewTenant, NewTrustKeyset,
        NewTrustKeysetVersion, NewTrustSource, Page, PrincipalBindingChanges, PrincipalKind,
        Profile, RegistryError, ReplayMode, ServiceGrantChanges, ServiceIdentityChanges, Status,
        TrustKeysetChanges, TrustSourceChanges, TrustSourceKind,
    },
};

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const PARTNER_ISSUER: &str = "https://ci.partner.example";
const KUBERNETES_ISSUER: &str = "https://kubernetes.default.svc";

/// One of the two tenants. Every ID carries the tenant's suffix, because
/// IDs are global; every name is the same in both tenants.
#[derive(Clone, Copy)]
struct Side {
    tenant: &'static str,
    suffix: &'static str,
}

const A: Side = Side {
    tenant: "ten_a",
    suffix: "a",
};
const B: Side = Side {
    tenant: "ten_b",
    suffix: "b",
};

/// (owner, intruder): the intruder's write names the owner's record.
const DIRECTIONS: [(Side, Side); 2] = [(A, B), (B, A)];

impl Side {
    fn id(self, base: &str) -> String {
        format!("{base}_{}", self.suffix)
    }
    /// Workload principal, actor of the grant and of the binding.
    fn workload(self) -> String {
        self.id("wld")
    }
    /// Service principal with a service identity.
    fn service(self) -> String {
        self.id("svc")
    }
    /// Service principal without a service identity.
    fn spare(self) -> String {
        self.id("spare")
    }
    /// Resource server assigned to this tenant only.
    fn audience(self) -> String {
        self.id("rs")
    }
    fn keyset(self) -> String {
        self.id("ks")
    }
    fn version(self) -> String {
        self.id("kv")
    }
    /// Sources: GitHub OIDC, uploaded JWKS, Kubernetes TokenReview.
    fn github(self) -> String {
        self.id("src_gh")
    }
    fn uploaded(self) -> String {
        self.id("src_up")
    }
    fn kubernetes(self) -> String {
        self.id("src_k8s")
    }
    fn binding(self) -> String {
        self.id("bnd")
    }
    fn grant(self) -> String {
        self.id("grt")
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not a JSON object: {other}"),
    }
}

fn principal(side: Side, id: String, kind: PrincipalKind, name: &str) -> NewPrincipal {
    NewPrincipal {
        id,
        tenant_id: side.tenant.into(),
        kind,
        name: name.into(),
        status: Status::Enabled,
    }
}

fn keyset(side: Side, id: String, name: &str) -> NewTrustKeyset {
    NewTrustKeyset {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        status: Status::Enabled,
    }
}

fn version(side: Side, id: String, keyset_id: String) -> NewTrustKeysetVersion {
    NewTrustKeysetVersion {
        id,
        tenant_id: side.tenant.into(),
        keyset_id,
        public_jwks: object(json!({
            "keys": [{"kty": "EC", "crv": "P-256", "kid": "partner-1", "x": "AQ", "y": "AQ"}]
        })),
        fingerprint: "sha256:partner-1".into(),
        effective_at: UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        expires_at: Some(UNIX_EPOCH + Duration::from_secs(1_798_761_600)),
        status: Status::Enabled,
        provenance: object(json!({"uploaded_by": "adm_1"})),
    }
}

/// A GitHub Actions source: `oidc_discovery` on the GitHub issuer.
fn github_source(side: Side, id: String, name: &str) -> NewTrustSource {
    NewTrustSource {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: GITHUB_ISSUER.into(),
        discovery_url: Some(format!("{GITHUB_ISSUER}/.well-known/openid-configuration")),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: strings(&["https://skyoauth.example"]),
        algorithms: Some(strings(&["RS256"])),
        proof_bounds: JsonObject::new(),
        assertion_profile: AssertionProfile::ReusableJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::Reusable,
        status: Status::Enabled,
    }
}

/// An `uploaded_jwks` source of `keyset_id` on the partner issuer.
fn uploaded_source(side: Side, id: String, name: &str, keyset_id: String) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::UploadedJwks,
        exact_issuer: PARTNER_ISSUER.into(),
        discovery_url: None,
        jwks_keyset_id: Some(keyset_id),
        algorithms: Some(strings(&["ES256"])),
        ..github_source(side, id, name)
    }
}

/// A `kubernetes_token_review` source of the tenant's own cluster on the
/// in-cluster issuer, which every cluster shares.
fn kubernetes_source(side: Side, id: String, name: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::KubernetesTokenReview,
        exact_issuer: KUBERNETES_ISSUER.into(),
        discovery_url: None,
        cluster_id: Some(side.id("cluster")),
        token_review_endpoint: Some(format!("https://k8s-{}.example:6443", side.suffix)),
        ca_bundle_ref: Some("cluster-ca".into()),
        ca_fingerprint: Some("sha256:cluster-ca".into()),
        reviewer_credential_ref: Some("token-reviewer".into()),
        review_timeout_ms: Some(5000),
        algorithms: None,
        assertion_profile: AssertionProfile::ProjectedServiceAccount,
        ..github_source(side, id, name)
    }
}

fn binding(
    side: Side,
    id: String,
    name: &str,
    source: String,
    workload: String,
) -> NewPrincipalBinding {
    NewPrincipalBinding {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        trust_source_id: source,
        profile: BindingProfile::GithubProduction,
        claim_match_policy: BTreeMap::from([
            ("repository".to_string(), "example/release".to_string()),
            ("event_name".to_string(), "push".to_string()),
        ]),
        workload_principal_id: workload,
        status: Status::Enabled,
    }
}

fn service_identity(
    side: Side,
    id: String,
    name: &str,
    audiences: Vec<String>,
) -> NewServiceIdentity {
    NewServiceIdentity {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        max_scopes: strings(&["read"]),
        max_resource_constraints: object(json!({"version": 1})),
        resource_server_ids: audiences,
        status: Status::Enabled,
    }
}

/// A direct grant of `actor` with `bindings` and `audiences`.
fn direct_grant(
    side: Side,
    id: String,
    name: &str,
    actor: String,
    bindings: Vec<String>,
    audiences: Vec<String>,
) -> NewServiceGrant {
    NewServiceGrant {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        actor_principal_id: actor,
        target_service_id: None,
        mode: GrantMode::Direct,
        scopes: strings(&["read"]),
        default_scopes: Some(strings(&["read"])),
        resource_constraints: JsonObject::new(),
        max_ttl: 300,
        valid_until: None,
        status: Status::Enabled,
        activation_state: ActivationState::NotRequired,
        allowed_binding_ids: bindings,
        resource_server_ids: audiences,
    }
}

/// Two tenants with the same object graph under the same names, each
/// referring only to its own records: principals, an audience assigned to
/// it alone, a keyset with a version, three sources (one per kind, each on
/// an issuer the other tenant also uses), a binding, a service identity and
/// a grant.
async fn two_tenants() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for side in [A, B] {
        registry::create_tenant(
            &pool,
            &NewTenant {
                id: side.tenant.into(),
                name: "Example".into(),
                secret_namespace: side.id("ns"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        for (id, kind, name) in [
            (side.workload(), PrincipalKind::Workload, "ci"),
            (side.service(), PrincipalKind::Service, "deploy-api"),
            (side.spare(), PrincipalKind::Service, "spare"),
        ] {
            registry::create_principal(&pool, &principal(side, id, kind, name))
                .await
                .unwrap();
        }
        registry::create_resource_server(
            &pool,
            &NewResourceServer {
                id: side.audience(),
                audience: format!("https://api-{}.example", side.suffix),
                name: format!("API {}", side.suffix),
                allowed_profiles: vec![Profile::Wif],
                scopes: strings(&["read"]),
                constraint_versions: vec![],
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        registry::create_audience_tenant_assignment(
            &pool,
            &NewAudienceTenantAssignment {
                id: side.id("ata"),
                resource_server_id: side.audience(),
                tenant_id: side.tenant.into(),
                allowed_profiles: vec![Profile::Wif],
                allowed_scopes: strings(&["read"]),
                constraint_versions: vec![],
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        registry::create_trust_keyset(&pool, &keyset(side, side.keyset(), "partner"))
            .await
            .unwrap();
        registry::create_trust_keyset_version(&pool, &version(side, side.version(), side.keyset()))
            .await
            .unwrap();
        for source in [
            github_source(side, side.github(), "github"),
            uploaded_source(side, side.uploaded(), "partner", side.keyset()),
            kubernetes_source(side, side.kubernetes(), "cluster"),
        ] {
            registry::create_trust_source(&pool, &source).await.unwrap();
        }
        registry::create_principal_binding(
            &pool,
            &binding(
                side,
                side.binding(),
                "release",
                side.github(),
                side.workload(),
            ),
        )
        .await
        .unwrap();
        registry::create_service_identity(
            &pool,
            &service_identity(side, side.service(), "deploy-api", vec![side.audience()]),
        )
        .await
        .unwrap();
        registry::create_service_grant(
            &pool,
            &direct_grant(
                side,
                side.grant(),
                "deploy",
                side.workload(),
                vec![side.binding()],
                vec![side.audience()],
            ),
        )
        .await
        .unwrap();
    }
    (db, pool)
}

/// Everything a tenant can read of its own records, as `Debug` text: every
/// list of the tenant, and the versions of both tenants' keysets as listed
/// under this tenant. Equal snapshots before and after a refused write show
/// that it wrote nothing: no row, no list row and no revision changed.
async fn snapshot(pool: &PgPool, side: Side) -> Vec<String> {
    let all = Page::first(MAX_PAGE_SIZE);
    let mut out = vec![
        format!(
            "{:?}",
            registry::list_principals(pool, side.tenant, all)
                .await
                .unwrap()
        ),
        format!(
            "{:?}",
            registry::list_trust_keysets(pool, side.tenant, all)
                .await
                .unwrap()
        ),
        format!(
            "{:?}",
            registry::list_trust_sources(pool, side.tenant, all)
                .await
                .unwrap()
        ),
        format!(
            "{:?}",
            registry::list_principal_bindings(pool, side.tenant, all)
                .await
                .unwrap()
        ),
        format!(
            "{:?}",
            registry::list_service_identities(pool, side.tenant, all)
                .await
                .unwrap()
        ),
        format!(
            "{:?}",
            registry::list_service_grants(pool, side.tenant, all)
                .await
                .unwrap()
        ),
    ];
    for keyset in [A.keyset(), B.keyset()] {
        out.push(format!(
            "{:?}",
            registry::list_trust_keyset_versions(pool, side.tenant, &keyset, all)
                .await
                .unwrap()
        ));
    }
    out
}

async fn snapshots(pool: &PgPool) -> [Vec<String>; 2] {
    [snapshot(pool, A).await, snapshot(pool, B).await]
}

/// The refusal of a crossed reference: the composite foreign key named
/// `constraint`.
#[track_caller]
fn assert_crossing_refused<T: Debug>(result: Result<T, RegistryError>, constraint: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::ForeignKey,
            constraint: Some(actual),
        }) => assert_eq!(actual, constraint),
        other => panic!("expected Invariant {{ ForeignKey, {constraint} }}: {other:?}"),
    }
}

#[track_caller]
fn assert_not_found<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::NotFound)), "{result:?}");
}

#[track_caller]
fn assert_name_taken<T: Debug>(result: Result<T, RegistryError>, constraint: &str) {
    match result {
        Err(RegistryError::AlreadyExists { constraint: actual }) => assert_eq!(actual, constraint),
        other => panic!("expected AlreadyExists {constraint}: {other:?}"),
    }
}

#[tokio::test]
async fn a29_pos_tenants_share_an_issuer() {
    let (db, pool) = two_tenants().await;
    for (issuer, source) in [
        (GITHUB_ISSUER, Side::github as fn(Side) -> String),
        (PARTNER_ISSUER, Side::uploaded),
        (KUBERNETES_ISSUER, Side::kubernetes),
    ] {
        for side in [A, B] {
            let read = registry::get_trust_source(&pool, side.tenant, &source(side))
                .await
                .unwrap();
            assert_eq!(read.exact_issuer, issuer);
            assert_eq!(read.tenant_id, side.tenant);
        }
        assert_ne!(source(A), source(B));
    }
    for (owner, other) in DIRECTIONS {
        // Each tenant lists its own three sources, not the other's.
        let listed: Vec<String> =
            registry::list_trust_sources(&pool, owner.tenant, Page::first(MAX_PAGE_SIZE))
                .await
                .unwrap()
                .into_iter()
                .map(|source| source.id)
                .collect();
        let mut own = vec![owner.github(), owner.uploaded(), owner.kubernetes()];
        own.sort();
        assert_eq!(listed, own);
        // A same-issuer source is not reachable through the other tenant.
        for id in [owner.github(), owner.uploaded(), owner.kubernetes()] {
            assert_not_found(registry::get_trust_source(&pool, other.tenant, &id).await);
        }
        // The binding and the grant of each tenant hang off its own
        // same-issuer source.
        let bound = registry::get_principal_binding(&pool, owner.tenant, &owner.binding())
            .await
            .unwrap();
        assert_eq!(bound.trust_source_id, owner.github());
        let grant = registry::get_service_grant(&pool, owner.tenant, &owner.grant())
            .await
            .unwrap();
        assert_eq!(grant.allowed_binding_ids, vec![owner.binding()]);
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_pos_tenants_reuse_object_names() {
    let (db, pool) = two_tenants().await;
    for side in [A, B] {
        let t = side.tenant;
        let names = [
            registry::get_trust_keyset(&pool, t, &side.keyset())
                .await
                .unwrap()
                .name,
            registry::get_trust_source(&pool, t, &side.github())
                .await
                .unwrap()
                .name,
            registry::get_trust_source(&pool, t, &side.uploaded())
                .await
                .unwrap()
                .name,
            registry::get_trust_source(&pool, t, &side.kubernetes())
                .await
                .unwrap()
                .name,
            registry::get_principal_binding(&pool, t, &side.binding())
                .await
                .unwrap()
                .name,
            registry::get_service_identity(&pool, t, &side.service())
                .await
                .unwrap()
                .name,
            registry::get_service_grant(&pool, t, &side.grant())
                .await
                .unwrap()
                .name,
            registry::get_principal(&pool, t, &side.workload())
                .await
                .unwrap()
                .name,
        ];
        assert_eq!(
            names,
            [
                "partner",
                "github",
                "partner",
                "cluster",
                "release",
                "deploy-api",
                "deploy",
                "ci"
            ]
        );
    }
    // The names coexist across tenants because they are unique per tenant
    // only: a second record of a taken name in the same tenant is refused.
    for side in [A, B] {
        let dup = |base: &str| side.id(&format!("{base}_dup"));
        assert_name_taken(
            registry::create_trust_keyset(&pool, &keyset(side, dup("ks"), "partner")).await,
            "trust_keyset_tenant_id_name_key",
        );
        assert_name_taken(
            registry::create_trust_source(&pool, &github_source(side, dup("src"), "github")).await,
            "trust_source_tenant_id_name_key",
        );
        assert_name_taken(
            registry::create_principal_binding(
                &pool,
                &binding(side, dup("bnd"), "release", side.github(), side.workload()),
            )
            .await,
            "principal_binding_tenant_id_name_key",
        );
        assert_name_taken(
            registry::create_service_identity(
                &pool,
                &service_identity(side, side.spare(), "deploy-api", vec![]),
            )
            .await,
            "service_identity_tenant_id_name_key",
        );
        assert_name_taken(
            registry::create_service_grant(
                &pool,
                &direct_grant(
                    side,
                    dup("grt"),
                    "deploy",
                    side.workload(),
                    vec![side.binding()],
                    vec![],
                ),
            )
            .await,
            "service_grant_tenant_id_name_key",
        );
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_keyset_version_on_other_tenants_keyset() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        let id = intruder.id("kv_cross");
        assert_crossing_refused(
            registry::create_trust_keyset_version(
                &pool,
                &version(intruder, id.clone(), owner.keyset()),
            )
            .await,
            "trust_keyset_version_keyset_id_fkey",
        );
        for side in [A, B] {
            assert_not_found(registry::get_trust_keyset_version(&pool, side.tenant, &id).await);
        }
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_uploaded_source_on_other_tenants_keyset() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        let id = intruder.id("src_cross");
        assert_crossing_refused(
            registry::create_trust_source(
                &pool,
                &uploaded_source(intruder, id.clone(), "cross", owner.keyset()),
            )
            .await,
            "trust_source_jwks_keyset_id_fkey",
        );
        for side in [A, B] {
            assert_not_found(registry::get_trust_source(&pool, side.tenant, &id).await);
        }
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_binding_on_other_tenants_source() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        // Every kind of the owner's sources, including the one on the
        // issuer the intruder also registered.
        for source in [owner.github(), owner.uploaded(), owner.kubernetes()] {
            let id = intruder.id("bnd_cross");
            assert_crossing_refused(
                registry::create_principal_binding(
                    &pool,
                    &binding(intruder, id.clone(), "cross", source, intruder.workload()),
                )
                .await,
                "principal_binding_trust_source_id_fkey",
            );
            for side in [A, B] {
                assert_not_found(registry::get_principal_binding(&pool, side.tenant, &id).await);
            }
        }
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_binding_of_other_tenants_workload() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        let id = intruder.id("bnd_cross");
        assert_crossing_refused(
            registry::create_principal_binding(
                &pool,
                &binding(
                    intruder,
                    id.clone(),
                    "cross",
                    intruder.github(),
                    owner.workload(),
                ),
            )
            .await,
            "principal_binding_workload_principal_id_fkey",
        );
        for side in [A, B] {
            assert_not_found(registry::get_principal_binding(&pool, side.tenant, &id).await);
        }
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_service_identity_of_other_tenants_principal() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        // The owner's service principal has no identity yet, so only the
        // tenant of the reference is wrong.
        assert_crossing_refused(
            registry::create_service_identity(
                &pool,
                &service_identity(intruder, owner.spare(), "cross", vec![]),
            )
            .await,
            "service_identity_id_fkey",
        );
        for side in [A, B] {
            assert_not_found(
                registry::get_service_identity(&pool, side.tenant, &owner.spare()).await,
            );
        }
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_service_identity_audience_of_other_tenant() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        // On create: the whole statement fails, no identity is left.
        assert_crossing_refused(
            registry::create_service_identity(
                &pool,
                &service_identity(intruder, intruder.spare(), "cross", vec![owner.audience()]),
            )
            .await,
            "service_identity_resource_server_assignment_fkey",
        );
        for side in [A, B] {
            assert_not_found(
                registry::get_service_identity(&pool, side.tenant, &intruder.spare()).await,
            );
        }
        // Added to an existing identity: its revision and audiences stay.
        assert_crossing_refused(
            registry::add_service_identity_resource_server(
                &pool,
                intruder.tenant,
                &intruder.service(),
                1,
                &owner.audience(),
            )
            .await,
            "service_identity_resource_server_assignment_fkey",
        );
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_grant_for_other_tenants_actor() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        // No binding row: a binding row carries the actor and would break
        // its own foreign key too. The deferred one-binding check runs only
        // at commit, after the actor's foreign key has failed the statement.
        let id = intruder.id("grt_cross");
        assert_crossing_refused(
            registry::create_service_grant(
                &pool,
                &direct_grant(
                    intruder,
                    id.clone(),
                    "cross",
                    owner.workload(),
                    vec![],
                    vec![],
                ),
            )
            .await,
            "service_grant_actor_principal_id_fkey",
        );
        for side in [A, B] {
            assert_not_found(registry::get_service_grant(&pool, side.tenant, &id).await);
        }
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_grant_targeting_other_tenants_service() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        let id = intruder.id("grt_cross");
        let grant = NewServiceGrant {
            mode: GrantMode::Delegation,
            target_service_id: Some(owner.service()),
            ..direct_grant(
                intruder,
                id.clone(),
                "cross",
                intruder.workload(),
                vec![intruder.binding()],
                vec![intruder.audience()],
            )
        };
        assert_crossing_refused(
            registry::create_service_grant(&pool, &grant).await,
            "service_grant_target_service_id_fkey",
        );
        for side in [A, B] {
            assert_not_found(registry::get_service_grant(&pool, side.tenant, &id).await);
        }
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_grant_allowing_other_tenants_binding() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        // On create: the binding row fails, so the grant is not created.
        let id = intruder.id("grt_cross");
        assert_crossing_refused(
            registry::create_service_grant(
                &pool,
                &direct_grant(
                    intruder,
                    id.clone(),
                    "cross",
                    intruder.workload(),
                    vec![owner.binding()],
                    vec![intruder.audience()],
                ),
            )
            .await,
            "service_grant_binding_binding_id_fkey",
        );
        for side in [A, B] {
            assert_not_found(registry::get_service_grant(&pool, side.tenant, &id).await);
        }
        // Added to an existing grant: its revision and bindings stay.
        assert_crossing_refused(
            registry::add_service_grant_binding(
                &pool,
                intruder.tenant,
                &intruder.grant(),
                1,
                &owner.binding(),
            )
            .await,
            "service_grant_binding_binding_id_fkey",
        );
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_grant_audience_of_other_tenant() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        let id = intruder.id("grt_cross");
        assert_crossing_refused(
            registry::create_service_grant(
                &pool,
                &direct_grant(
                    intruder,
                    id.clone(),
                    "cross",
                    intruder.workload(),
                    vec![intruder.binding()],
                    vec![owner.audience()],
                ),
            )
            .await,
            "service_grant_resource_server_assignment_fkey",
        );
        for side in [A, B] {
            assert_not_found(registry::get_service_grant(&pool, side.tenant, &id).await);
        }
        assert_crossing_refused(
            registry::add_service_grant_resource_server(
                &pool,
                intruder.tenant,
                &intruder.grant(),
                1,
                &owner.audience(),
            )
            .await,
            "service_grant_resource_server_assignment_fkey",
        );
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

/// Every update and list-set change addressed through the intruder's tenant
/// to a record of the owner finds nothing, whatever it names, and leaves the
/// owner's record as it was. The arguments are otherwise valid, so only the
/// tenant scope refuses them.
#[tokio::test]
async fn a29_neg_writes_to_other_tenants_records_find_nothing() {
    let (db, pool) = two_tenants().await;
    let before = snapshots(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        let t = intruder.tenant;
        let keyset = registry::get_trust_keyset(&pool, owner.tenant, &owner.keyset())
            .await
            .unwrap();
        assert_not_found(
            registry::update_trust_keyset(
                &pool,
                t,
                &keyset.id,
                keyset.revision,
                &TrustKeysetChanges {
                    name: "taken-over".into(),
                    status: Status::Disabled,
                },
            )
            .await,
        );
        let source = registry::get_trust_source(&pool, owner.tenant, &owner.github())
            .await
            .unwrap();
        assert_not_found(
            registry::update_trust_source(
                &pool,
                t,
                &source.id,
                source.revision,
                &TrustSourceChanges {
                    name: "taken-over".into(),
                    exact_issuer: source.exact_issuer.clone(),
                    discovery_url: source.discovery_url.clone(),
                    token_review_endpoint: None,
                    ca_bundle_ref: None,
                    ca_fingerprint: None,
                    reviewer_credential_ref: None,
                    review_timeout_ms: None,
                    audiences: strings(&["https://intruder.example"]),
                    algorithms: source.algorithms.clone(),
                    proof_bounds: source.proof_bounds.clone(),
                    assertion_profile: source.assertion_profile,
                    stale_revocation_acknowledged: None,
                    replay_mode: source.replay_mode,
                    status: Status::Disabled,
                },
            )
            .await,
        );
        let bound = registry::get_principal_binding(&pool, owner.tenant, &owner.binding())
            .await
            .unwrap();
        assert_not_found(
            registry::update_principal_binding(
                &pool,
                t,
                &bound.id,
                bound.revision,
                &PrincipalBindingChanges {
                    name: "taken-over".into(),
                    profile: bound.profile,
                    claim_match_policy: BTreeMap::from([(
                        "repository".to_string(),
                        "intruder/any".to_string(),
                    )]),
                    status: Status::Disabled,
                },
            )
            .await,
        );
        let service = registry::get_service_identity(&pool, owner.tenant, &owner.service())
            .await
            .unwrap();
        assert_not_found(
            registry::update_service_identity(
                &pool,
                t,
                &service.id,
                service.revision,
                &ServiceIdentityChanges {
                    name: "taken-over".into(),
                    max_scopes: strings(&["read"]),
                    max_resource_constraints: JsonObject::new(),
                    status: Status::Disabled,
                },
            )
            .await,
        );
        let grant = registry::get_service_grant(&pool, owner.tenant, &owner.grant())
            .await
            .unwrap();
        assert_not_found(
            registry::update_service_grant(
                &pool,
                t,
                &grant.id,
                grant.revision,
                &ServiceGrantChanges {
                    name: "taken-over".into(),
                    scopes: grant.scopes.clone(),
                    default_scopes: grant.default_scopes.clone(),
                    resource_constraints: grant.resource_constraints.clone(),
                    max_ttl: grant.max_ttl,
                    valid_until: grant.valid_until,
                    status: Status::Disabled,
                    activation_state: grant.activation_state,
                },
            )
            .await,
        );
        // List sets of the owner's records, adding the intruder's items or
        // removing the owner's.
        let (svc, grt) = (owner.service(), owner.grant());
        assert_not_found(
            registry::add_service_identity_resource_server(&pool, t, &svc, 1, &intruder.audience())
                .await,
        );
        assert_not_found(
            registry::remove_service_identity_resource_server(&pool, t, &svc, 1, &owner.audience())
                .await,
        );
        assert_not_found(
            registry::add_service_grant_binding(&pool, t, &grt, 1, &intruder.binding()).await,
        );
        assert_not_found(
            registry::remove_service_grant_binding(&pool, t, &grt, 1, &owner.binding()).await,
        );
        assert_not_found(
            registry::add_service_grant_resource_server(&pool, t, &grt, 1, &intruder.audience())
                .await,
        );
        assert_not_found(
            registry::remove_service_grant_resource_server(&pool, t, &grt, 1, &owner.audience())
                .await,
        );
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}
