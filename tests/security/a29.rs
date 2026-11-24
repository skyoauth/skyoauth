//! A29: tenants share a GitHub issuer or object names; crossed references.
//! Expected: registrations coexist, ownership crossover denied (tasks §8;
//! IR-031, IR-032; ADR-014).
//!
//! Stage M1a, "registry and references": the registry writes of the
//! tenant-owned `0004` records, and the operation inserts (approves among
//! them) and revocation writes of the `0005` operation table, through the
//! typed registry API (`skyoauth_service::persistence::registry`) against a
//! real PostgreSQL.
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
//! - **Negative, operations.** An `approve` that names an operation of
//!   another scope, and a revocation (a cancel) of an operation by a
//!   revoking operation of another scope, are refused by the `0005` guards
//!   `administrative_operation_approves_same_tenant` and
//!   `administrative_operation_revokes_same_tenant`, `check_violation`
//!   (`23514`) reported as `Invariant { SameTenantOperation, <constraint> }`,
//!   and write nothing: no approve, no cancel, no revocation and no audit
//!   event, the chain intact. The guards compare `tenant_id` with
//!   `IS DISTINCT FROM`, so the instance (`tenant_id` `NULL`) is a scope of
//!   its own: each guard runs between the two tenants in both directions
//!   (`a29_neg_approve_of_other_tenants_operation`,
//!   `a29_neg_revocation_by_other_tenants_operation`) and between the
//!   instance and each tenant in both directions
//!   (`a29_neg_approve_across_instance_and_tenant`,
//!   `a29_neg_revocation_across_instance_and_tenant`). The approver is never
//!   the requester, so `administrative_operation_approver_distinct` never
//!   decides; the control, an approve and a cancel within each tenant and
//!   the instance, is written
//!   (`a29_pos_same_scope_approve_and_revocation_are_written`). The registry
//!   inserts no revocation with a new row, so the revocation guard is
//!   reached by its `UPDATE` leg (`revoke_administrative_operation`) only;
//!   its `INSERT` leg has no public writer.
//! - **Negative, operation references.** Since the amendment of `0005` of
//!   2026-11-24 (the user's ruling, relayed by the lead; provisional), two
//!   more references of an operation's insert are refused the same way,
//!   reported as `Invariant { SameTenantOperation, <constraint> }`, writing
//!   nothing, its event included, in the same four directions:
//!   - an operation of any kind whose `audit_id` names an audit event of
//!     another scope, by the audit guard
//!     `administrative_operation_audit_same_tenant` (trigger
//!     `administrative_operation_audit_check`): a pending gated write, an
//!     approve of its own scope's operation, a `route_bundle_approval` of
//!     it, a `cancel` and a `reject`, each otherwise valid
//!     (`a29_neg_operation_names_other_tenants_audit_event`,
//!     `a29_neg_audit_event_across_instance_and_tenant`);
//!   - an operation of a kind other than `approve` whose
//!     `approves_operation_id` names an operation of another scope, by the
//!     approval guard `administrative_operation_approves_same_tenant`
//!     (trigger `administrative_operation_approval_check`, which now runs
//!     for every row that names an operation): a `route_bundle_approval` by
//!     the actor of the operation it names, and a pending gated write
//!     (`a29_neg_other_kind_names_other_tenants_operation`,
//!     `a29_neg_other_kind_names_operation_across_instance_and_tenant`).
//!
//!   A row that crosses both is refused by the approval guard, whose
//!   trigger fires first (PostgreSQL fires same-event triggers in name
//!   order; `0005`, README "Triggers and timing"):
//!   `a29_neg_double_crossing_reports_the_approval_guard`. The controls:
//!   the same writes within each tenant and the instance are written
//!   (`a29_pos_same_scope_audit_event_and_named_operation_are_written`), and
//!   the actor rule stays with kind `approve`: a `route_bundle_approval` by
//!   the actor of the preparation it names is written
//!   (`a29_pos_route_bundle_approval_by_its_preparer_is_written`).
//!
//! Not covered here: the M2 stage (a proof from one tenant's source with
//! another tenant's grant at exchange); checker tenant sets (instance
//! records, A31/A45); records of later milestones (clients, origins, human
//! policies); the second-approver flow above the registry
//! (`skyoauth_service::operation`), whose own scope check refuses another
//! scope's operation as not found before a guard is reached (its service
//! tests); authorization, the enabled-assignment check (since `0010` a
//! database guard at insert, tested in
//! `service/tests/schema_assignment_write_guard.rs`), and the service rules
//! the database does not enforce (scope ceilings; T14.1, T14.2). Principal
//! and tenant names have no uniqueness rule: `0002` has no name key on
//! `principal` (IR-021; `service/migrations/README.md`, "Not done in
//! `0004`") nor on `tenant`, so the shared principal names (`"ci"`, …) and
//! tenant names of `a29_pos_tenants_reuse_object_names` prove nothing about
//! them; a same-tenant duplicate assertion for principals belongs with that
//! key when a migration adds it.
//!
//! The crossings are a closed list, one per composite foreign key of
//! `0004` that a tenant-owned write can name across tenants, and the
//! crossings of `administrative_operation` that the three `0005` guards
//! refuse: the approved operation of an `approve` and of any other kind
//! (`administrative_operation_approves_same_tenant`, trigger
//! `administrative_operation_approval_check`), the audit event
//! (`administrative_operation_audit_same_tenant`, trigger
//! `administrative_operation_audit_check`) and the revoking operation
//! (`administrative_operation_revokes_same_tenant`, trigger
//! `administrative_operation_revocation_check`). Each is enumerated in both
//! directions instead of sampled. The `0005` guards are `AFTER` triggers,
//! not composite foreign keys: `administrative_operation` references an
//! operation by `id` alone and an audit event by `audit_event (id)` alone,
//! and the triggers compare the two rows' tenants. Three list-to-parent
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
//! The list covers `0004` and these `0005` guards only; it does not
//! enumerate every cross-scope reference of `0005`.
//! `consumed_assertion_trust_source_id_fkey` (`0005`), a consumed proof
//! naming another tenant's source, is refused in both directions by
//! `a24_neg_consume_names_other_tenants_source` (A24,
//! `tests/security/a24.rs`), not here. The two references of
//! `administrative_operation` that the approve and revocation guards left
//! open, (a) the audit event and (b) the operation that a kind other than
//! `approve` names, were refused by nothing until the amendment of `0005`
//! of 2026-11-24; both are on the list now, reached through the registry's
//! operation-row insert (`insert_administrative_operation`, crate-private
//! since the second-approver proposal's PR 10 and reached here through
//! `registry::test_support`). Not on the list, and left to the service
//! tests (`service/tests/schema_operation_approval_guard.rs`):
//! `administrative_operation_approver_distinct`, an actor rule and not a
//! crossing; and the revocation guard's `INSERT` leg (above). Not on the
//! list and pinned by no test: the order of the guards across the rows of
//! one statement (`0005`: an earlier row's `23514` before a later row's
//! `23503`). It is unobservable through the public path, since the
//! registry inserts one operation per statement; the behaviour has been
//! probed, but every missing-reference case of the service tests is a
//! single-row statement, so a service test that pins it is a follow-up.

use std::{
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use skyoauth_scenarios::{egress, pg::TestDb};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, ActivationState, AdministrativeOperation, AssertionProfile, AuditActor,
        BindingProfile, ChainVerdict, GrantMode, InvariantKind, JsonObject, MAX_PAGE_SIZE,
        NewAdministrativeOperation, NewAudienceTenantAssignment, NewAuditEvent, NewPrincipal,
        NewPrincipalBinding, NewResourceServer, NewServiceGrant, NewServiceIdentity, NewTenant,
        NewTrustKeyset, NewTrustKeysetVersion, NewTrustSource, Page, PrincipalBindingChanges,
        PrincipalKind, Profile, RegistryError, ReplayMode, ServiceGrantChanges,
        ServiceIdentityChanges, Status, TrustKeysetChanges, TrustSourceChanges, TrustSourceKind,
    },
};
use sqlx::{Postgres, Transaction};

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
        claim_match_policy: super::grant_fixture::github_policy(),
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
        registry::test_support::create_tenant(
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
            registry::test_support::create_principal(&pool, &principal(side, id, kind, name))
                .await
                .unwrap();
        }
        registry::test_support::create_resource_server(
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
        registry::test_support::create_audience_tenant_assignment(
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
        registry::test_support::create_trust_keyset(&pool, &keyset(side, side.keyset(), "partner"))
            .await
            .unwrap();
        registry::test_support::create_trust_keyset_version(
            &pool,
            &version(side, side.version(), side.keyset()),
        )
        .await
        .unwrap();
        for source in [
            github_source(side, side.github(), "github"),
            uploaded_source(side, side.uploaded(), "partner", side.keyset()),
            kubernetes_source(side, side.kubernetes(), "cluster"),
        ] {
            egress::allow_destinations(&pool, &source).await;
            registry::test_support::create_trust_source(&pool, &source)
                .await
                .unwrap();
        }
        registry::test_support::create_principal_binding(
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
        registry::test_support::create_service_identity(
            &pool,
            &service_identity(side, side.service(), "deploy-api", vec![side.audience()]),
        )
        .await
        .unwrap();
        registry::test_support::create_service_grant(
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
            registry::test_support::create_trust_keyset(&pool, &keyset(side, dup("ks"), "partner"))
                .await,
            "trust_keyset_tenant_id_name_key",
        );
        assert_name_taken(
            registry::test_support::create_trust_source(
                &pool,
                &github_source(side, dup("src"), "github"),
            )
            .await,
            "trust_source_tenant_id_name_key",
        );
        assert_name_taken(
            registry::test_support::create_principal_binding(
                &pool,
                &binding(side, dup("bnd"), "release", side.github(), side.workload()),
            )
            .await,
            "principal_binding_tenant_id_name_key",
        );
        assert_name_taken(
            registry::test_support::create_service_identity(
                &pool,
                &service_identity(side, side.spare(), "deploy-api", vec![]),
            )
            .await,
            "service_identity_tenant_id_name_key",
        );
        assert_name_taken(
            registry::test_support::create_service_grant(
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
            registry::test_support::create_trust_keyset_version(
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
            registry::test_support::create_trust_source(
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
                registry::test_support::create_principal_binding(
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
            registry::test_support::create_principal_binding(
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
            registry::test_support::create_service_identity(
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
            registry::test_support::create_service_identity(
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
            registry::test_support::add_service_identity_resource_server(
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
            registry::test_support::create_service_grant(
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
            registry::test_support::create_service_grant(&pool, &grant).await,
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
            registry::test_support::create_service_grant(
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
            registry::test_support::add_service_grant_binding(
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
            registry::test_support::create_service_grant(
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
            registry::test_support::add_service_grant_resource_server(
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
            registry::test_support::update_trust_keyset(
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
            registry::test_support::update_trust_source(
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
            registry::test_support::update_principal_binding(
                &pool,
                t,
                &bound.id,
                bound.revision,
                &PrincipalBindingChanges {
                    name: "taken-over".into(),
                    profile: bound.profile,
                    claim_match_policy: {
                        // Complete, so the statement is reached and finds nothing.
                        let mut policy = super::grant_fixture::github_policy();
                        policy.insert("repository".to_string(), "intruder/any".to_string());
                        policy
                    },
                    status: Status::Disabled,
                },
            )
            .await,
        );
        let service = registry::get_service_identity(&pool, owner.tenant, &owner.service())
            .await
            .unwrap();
        assert_not_found(
            registry::test_support::update_service_identity(
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
            registry::test_support::update_service_grant(
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
            registry::test_support::add_service_identity_resource_server(
                &pool,
                t,
                &svc,
                1,
                &intruder.audience(),
            )
            .await,
        );
        assert_not_found(
            registry::test_support::remove_service_identity_resource_server(
                &pool,
                t,
                &svc,
                1,
                &owner.audience(),
            )
            .await,
        );
        assert_not_found(
            registry::test_support::add_service_grant_binding(
                &pool,
                t,
                &grt,
                1,
                &intruder.binding(),
            )
            .await,
        );
        assert_not_found(
            registry::test_support::remove_service_grant_binding(
                &pool,
                t,
                &grt,
                1,
                &owner.binding(),
            )
            .await,
        );
        assert_not_found(
            registry::test_support::add_service_grant_resource_server(
                &pool,
                t,
                &grt,
                1,
                &intruder.audience(),
            )
            .await,
        );
        assert_not_found(
            registry::test_support::remove_service_grant_resource_server(
                &pool,
                t,
                &grt,
                1,
                &owner.audience(),
            )
            .await,
        );
    }
    assert_eq!(snapshots(&pool).await, before);
    db.drop([pool]).await;
}

// The `0005` approval, audit and revocation guards: the crossings of
// `administrative_operation`.

/// The scope of an operation: a tenant, or the instance (`tenant_id`
/// `NULL`), which the guards compare `IS DISTINCT FROM` as a scope of its
/// own.
#[derive(Clone, Copy, Debug)]
struct Scope {
    tenant: Option<&'static str>,
    suffix: &'static str,
}

const OP_A: Scope = Scope {
    tenant: Some(A.tenant),
    suffix: A.suffix,
};
const OP_B: Scope = Scope {
    tenant: Some(B.tenant),
    suffix: B.suffix,
};
const INSTANCE: Scope = Scope {
    tenant: None,
    suffix: "i",
};

/// (owner, intruder) between the two tenants: the intruder's approve or
/// revocation names the owner's operation.
const TENANT_CROSSINGS: [(Scope, Scope); 2] = [(OP_A, OP_B), (OP_B, OP_A)];

/// (owner, intruder) between the instance and each tenant, both ways.
const INSTANCE_CROSSINGS: [(Scope, Scope); 4] = [
    (OP_A, INSTANCE),
    (INSTANCE, OP_A),
    (OP_B, INSTANCE),
    (INSTANCE, OP_B),
];

/// The actor of every approve: never the actor of the operation it
/// approves, so the `0005` guard `administrative_operation_approver_distinct`
/// never decides here and only the scope is wrong.
const APPROVER: &str = "adm_sec";

/// The kind of a route bundle approval, which names the preparation it
/// approves and may be by that preparation's actor (IR-054; GW-130, GW-131):
/// the approval guard checks its tenant, never its actor.
const ROUTE_BUNDLE_APPROVAL: &str = "route_bundle_approval";

/// The kind of every pending gated write here. The database takes any kind
/// (`0005` lists none), so a pending write may name an operation too, and
/// the approval guard checks its tenant as any other kind's.
const GATED_WRITE: &str = "service_grant.update";

/// A fixed time: the guards read no clock.
fn op_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_790_000_000)
}

impl Scope {
    fn id(self, base: &str) -> String {
        format!("{base}_{}", self.suffix)
    }
    /// The scope's pending operation, the target of every approve and
    /// revocation.
    fn pending(self) -> String {
        self.id("op")
    }
    /// The scope's requester, the actor of its pending operation and of its
    /// cancels.
    fn requester(self) -> String {
        self.id("adm_req")
    }
}

/// A new operation `id` of `kind` in `scope` by `actor`, recorded by the
/// event `evt_<id>`: a pending one (an hour to expiry) unless it is an
/// `approve`, a `cancel`, a `reject` or a `route_bundle_approval`, which
/// has no expiry (proposal section 2; inferred for the
/// `route_bundle_approval`, which no guard reads the expiry of).
fn new_operation(
    scope: Scope,
    id: String,
    actor: String,
    kind: &str,
    approves: Option<String>,
) -> NewAdministrativeOperation {
    let pending = !["approve", "cancel", "reject", ROUTE_BUNDLE_APPROVAL].contains(&kind);
    NewAdministrativeOperation {
        audit_id: format!("evt_{id}"),
        immutable_plan: object(json!({"id": id, "status": "enabled"})),
        id,
        tenant_id: scope.tenant.map(Into::into),
        actor_id: actor,
        kind: kind.into(),
        request_digest: vec![0xd1; 32],
        expected_revision: 1,
        expires_at: pending.then(|| op_time() + Duration::from_secs(3600)),
        approves_operation_id: approves,
        outcome: if pending { "pending" } else { "applied" }.into(),
    }
}

/// Appends the operation's event (in its scope, by its actor, with
/// `action` on `object_id`) and inserts the operation, in the order the
/// migrations README prescribes, in one transaction.
async fn append_and_insert(
    transaction: &mut Transaction<'_, Postgres>,
    new: &NewAdministrativeOperation,
    action: &str,
    object_id: &str,
) -> Result<AdministrativeOperation, RegistryError> {
    let scope = new.tenant_id.clone();
    append_in_and_insert(transaction, new, scope, action, object_id).await
}

/// [`append_and_insert`] with the event appended in the tenant
/// `event_tenant` (`None`: the instance), which may be another scope than
/// the operation's.
async fn append_in_and_insert(
    transaction: &mut Transaction<'_, Postgres>,
    new: &NewAdministrativeOperation,
    event_tenant: Option<String>,
    action: &str,
    object_id: &str,
) -> Result<AdministrativeOperation, RegistryError> {
    registry::test_support::append_audit_event(
        transaction,
        &NewAuditEvent {
            id: new.audit_id.clone(),
            tenant_id: event_tenant,
            timestamp: op_time(),
            actor: AuditActor::Operator(new.actor_id.clone()),
            action: action.into(),
            object_id: object_id.into(),
            previous_revision: None,
            new_revision: None,
            outcome: "success".into(),
        },
    )
    .await
    .unwrap();
    registry::test_support::insert_administrative_operation(transaction, new).await
}

/// `intruder`'s approve `id` by [`APPROVER`] of `owner`'s pending operation,
/// in a transaction committed whatever the insert returned: a refused
/// statement leaves the transaction aborted, so its event goes too.
async fn approve(
    pool: &PgPool,
    owner: Scope,
    intruder: Scope,
    id: &str,
) -> Result<AdministrativeOperation, RegistryError> {
    let new = new_operation(
        intruder,
        id.into(),
        APPROVER.into(),
        "approve",
        Some(owner.pending()),
    );
    let mut transaction = pool.begin().await.unwrap();
    let result = append_and_insert(
        &mut transaction,
        &new,
        "administrative_operation.approve",
        &owner.pending(),
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

/// `intruder`'s cancel of `owner`'s pending operation, as a cancel is
/// written: in one transaction, the cancel's event, its operation `id` by
/// `intruder`'s requester, then the revocation of `owner`'s operation that
/// names it ([`registry::test_support::revoke_administrative_operation`]), committed
/// whatever the revocation returned. The registry inserts no revocation
/// with a new row, so the guard's `UPDATE` leg is the one reached.
async fn cancel(
    pool: &PgPool,
    owner: Scope,
    intruder: Scope,
    id: &str,
) -> Result<i64, RegistryError> {
    let new = new_operation(intruder, id.into(), intruder.requester(), "cancel", None);
    let mut transaction = pool.begin().await.unwrap();
    append_and_insert(
        &mut transaction,
        &new,
        "administrative_operation.cancel",
        &owner.pending(),
    )
    .await
    .unwrap();
    let result = registry::test_support::revoke_administrative_operation(
        &mut transaction,
        &owner.pending(),
        id,
        op_time() + Duration::from_secs(60),
        "cancelled",
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

/// [`two_tenants`] and a pending operation in each tenant and in the
/// instance, each by its scope's requester.
async fn two_tenants_with_operations() -> (TestDb, PgPool) {
    let (db, pool) = two_tenants().await;
    for scope in [OP_A, OP_B, INSTANCE] {
        let new = new_operation(scope, scope.pending(), scope.requester(), GATED_WRITE, None);
        let mut transaction = pool.begin().await.unwrap();
        append_and_insert(
            &mut transaction,
            &new,
            "administrative_operation.create",
            &scope.pending(),
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }
    (db, pool)
}

/// The operation `id`, read under its lock in a transaction rolled back,
/// or `None`.
async fn find_operation(pool: &PgPool, id: &str) -> Option<AdministrativeOperation> {
    let mut transaction = pool.begin().await.unwrap();
    let row = registry::lock_administrative_operation(&mut transaction, id)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();
    row
}

/// Everything a refused approve or revocation could have written: the
/// registry snapshots of both tenants, every operation `ids` names (the
/// pending ones and the refused writes' own), and the audit chain's
/// verdict, whose head sequence counts the events. Equal before and after,
/// nothing was written and the chain is intact.
async fn operation_state(
    pool: &PgPool,
    ids: &[String],
) -> (
    [Vec<String>; 2],
    Vec<Option<AdministrativeOperation>>,
    ChainVerdict,
) {
    let mut operations = Vec::new();
    for id in ids {
        operations.push(find_operation(pool, id).await);
    }
    let mut connection = pool.acquire().await.unwrap();
    let chain = registry::verify_audit_chain(&mut connection).await.unwrap();
    assert!(matches!(chain, ChainVerdict::Intact { .. }), "{chain:?}");
    (snapshots(pool).await, operations, chain)
}

/// The refusal of a crossed operation reference: the `0005` guard named
/// `constraint`, a `check_violation` (`23514`) that the registry maps to
/// `Invariant { SameTenantOperation, <constraint> }` (`SAME_TENANT_OPERATION`).
#[track_caller]
fn assert_scope_refused<T: Debug>(
    result: Result<T, RegistryError>,
    constraint: &str,
    (owner, intruder): (Scope, Scope),
) {
    match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::SameTenantOperation,
            constraint: Some(actual),
        }) => assert_eq!(actual, constraint, "{intruder:?} naming {owner:?}"),
        other => panic!(
            "{intruder:?} naming {owner:?}: expected Invariant {{ SameTenantOperation, {constraint} }}: {other:?}"
        ),
    }
}

/// Approves each crossing's owner operation from the intruder's scope:
/// each is refused by `administrative_operation_approves_same_tenant` and
/// writes nothing, neither the approve nor its event.
async fn assert_approves_refused(crossings: &[(Scope, Scope)]) {
    let (db, pool) = two_tenants_with_operations().await;
    let mut ids: Vec<String> = [OP_A, OP_B, INSTANCE].map(Scope::pending).into();
    let attempts: Vec<String> = crossings
        .iter()
        .map(|(owner, intruder)| format!("op_appr_{}_{}", intruder.suffix, owner.suffix))
        .collect();
    ids.extend(attempts.iter().cloned());
    let before = operation_state(&pool, &ids).await;
    for (&(owner, intruder), id) in crossings.iter().zip(&attempts) {
        assert_scope_refused(
            approve(&pool, owner, intruder, id).await,
            "administrative_operation_approves_same_tenant",
            (owner, intruder),
        );
        assert_eq!(
            find_operation(&pool, id).await,
            None,
            "{owner:?} {intruder:?}"
        );
    }
    assert_eq!(operation_state(&pool, &ids).await, before);
    db.drop([pool]).await;
}

/// Revokes each crossing's owner operation by a cancel of the intruder's
/// scope: each is refused by `administrative_operation_revokes_same_tenant`
/// and writes nothing, neither the revocation, nor the cancel, nor its
/// event.
async fn assert_revocations_refused(crossings: &[(Scope, Scope)]) {
    let (db, pool) = two_tenants_with_operations().await;
    let mut ids: Vec<String> = [OP_A, OP_B, INSTANCE].map(Scope::pending).into();
    let attempts: Vec<String> = crossings
        .iter()
        .map(|(owner, intruder)| format!("op_cncl_{}_{}", intruder.suffix, owner.suffix))
        .collect();
    ids.extend(attempts.iter().cloned());
    let before = operation_state(&pool, &ids).await;
    for (&(owner, intruder), id) in crossings.iter().zip(&attempts) {
        assert_scope_refused(
            cancel(&pool, owner, intruder, id).await,
            "administrative_operation_revokes_same_tenant",
            (owner, intruder),
        );
        assert_eq!(
            find_operation(&pool, id).await,
            None,
            "{owner:?} {intruder:?}"
        );
    }
    assert_eq!(operation_state(&pool, &ids).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_approve_of_other_tenants_operation() {
    assert_approves_refused(&TENANT_CROSSINGS).await;
}

#[tokio::test]
async fn a29_neg_approve_across_instance_and_tenant() {
    assert_approves_refused(&INSTANCE_CROSSINGS).await;
}

#[tokio::test]
async fn a29_neg_revocation_by_other_tenants_operation() {
    assert_revocations_refused(&TENANT_CROSSINGS).await;
}

#[tokio::test]
async fn a29_neg_revocation_across_instance_and_tenant() {
    assert_revocations_refused(&INSTANCE_CROSSINGS).await;
}

/// The control of the four tests above: in each tenant and in the
/// instance, an approve of the scope's own pending operation by another
/// actor, and then a cancel by the scope's requester that revokes it, are
/// written, each with its event, the chain intact. The approve's actor is
/// not the requester, so the result does not depend on
/// `administrative_operation_approver_distinct`.
#[tokio::test]
async fn a29_pos_same_scope_approve_and_revocation_are_written() {
    let (db, pool) = two_tenants_with_operations().await;
    let mut connection = pool.acquire().await.unwrap();
    let ChainVerdict::Intact { last_sequence } =
        registry::verify_audit_chain(&mut connection).await.unwrap()
    else {
        panic!("broken chain");
    };
    drop(connection);
    for scope in [OP_A, OP_B, INSTANCE] {
        let (approval, revoking) = (scope.id("op_appr"), scope.id("op_cncl"));
        let approved = approve(&pool, scope, scope, &approval).await.unwrap();
        assert_eq!(approved.tenant_id.as_deref(), scope.tenant);
        assert_eq!(approved.approves_operation_id, Some(scope.pending()));
        assert_eq!(cancel(&pool, scope, scope, &revoking).await.unwrap(), 2);
        let pending = find_operation(&pool, &scope.pending()).await.unwrap();
        assert_eq!(pending.tenant_id.as_deref(), scope.tenant);
        assert_eq!(pending.revocation_operation_id, Some(revoking.clone()));
        assert_eq!(
            find_operation(&pool, &revoking)
                .await
                .unwrap()
                .tenant_id
                .as_deref(),
            scope.tenant
        );
    }
    let mut connection = pool.acquire().await.unwrap();
    assert_eq!(
        registry::verify_audit_chain(&mut connection).await.unwrap(),
        ChainVerdict::Intact {
            last_sequence: last_sequence + 6
        }
    );
    drop(connection);
    db.drop([pool]).await;
}

// The `0005` crossings of an operation's insert guarded since the
// amendment of 2026-11-24: the audit event an operation names
// (`administrative_operation_audit_same_tenant`) and the operation that a
// kind other than `approve` names
// (`administrative_operation_approves_same_tenant`, whose trigger now runs
// for every row that names an operation).

/// `new`, recorded by an event of `event`'s scope, in a transaction
/// committed whatever the insert returned: a refused statement leaves the
/// transaction aborted, so the event goes too.
async fn insert_recorded_in(
    pool: &PgPool,
    new: &NewAdministrativeOperation,
    event: Scope,
) -> Result<AdministrativeOperation, RegistryError> {
    let object_id = new
        .approves_operation_id
        .clone()
        .unwrap_or_else(|| new.id.clone());
    let mut transaction = pool.begin().await.unwrap();
    let result = append_in_and_insert(
        &mut transaction,
        new,
        event.tenant.map(Into::into),
        "administrative_operation.create",
        &object_id,
    )
    .await;
    transaction.commit().await.unwrap();
    result
}

/// An operation to insert and the scope of the audit event that records it.
type Attempt = (NewAdministrativeOperation, Scope);

/// The ID of `intruder`'s attempt `base` on `owner`.
fn attempt_id(base: &str, owner: Scope, intruder: Scope) -> String {
    format!("op_{base}_{}_{}", intruder.suffix, owner.suffix)
}

/// The audit crossings of `intruder` into `owner`: five operations of
/// `intruder`'s scope that name nothing of another scope, each recorded by
/// an event of `owner`'s: a pending gated write, an approve of `intruder`'s
/// pending operation by [`APPROVER`] (which passes the approval guard), a
/// route bundle approval of it by its requester, and a `cancel` by the
/// requester and a `reject` by [`APPROVER`], inserted as the flow inserts
/// them, without an approved operation or an expiry (the revocation that
/// links them to a revoked row is a later `UPDATE`, not made here).
fn audit_crossings(owner: Scope, intruder: Scope) -> Vec<Attempt> {
    let id = |base| attempt_id(base, owner, intruder);
    [
        new_operation(
            intruder,
            id("evt_gw"),
            intruder.requester(),
            GATED_WRITE,
            None,
        ),
        new_operation(
            intruder,
            id("evt_appr"),
            APPROVER.into(),
            "approve",
            Some(intruder.pending()),
        ),
        new_operation(
            intruder,
            id("evt_rba"),
            intruder.requester(),
            ROUTE_BUNDLE_APPROVAL,
            Some(intruder.pending()),
        ),
        new_operation(
            intruder,
            id("evt_cncl"),
            intruder.requester(),
            "cancel",
            None,
        ),
        new_operation(intruder, id("evt_rjct"), APPROVER.into(), "reject", None),
    ]
    .map(|new| (new, owner))
    .into()
}

/// The named-operation crossings of `intruder` into `owner` by the kinds
/// other than `approve`, each recorded by an event of `intruder`'s own
/// scope: a route bundle approval of `owner`'s pending operation by that
/// operation's own actor (the one a route bundle approval may share, so no
/// actor rule decides), and a pending gated write that names it.
fn named_operation_crossings(owner: Scope, intruder: Scope) -> Vec<Attempt> {
    let id = |base| attempt_id(base, owner, intruder);
    [
        new_operation(
            intruder,
            id("rba"),
            owner.requester(),
            ROUTE_BUNDLE_APPROVAL,
            Some(owner.pending()),
        ),
        new_operation(
            intruder,
            id("gw_named"),
            intruder.requester(),
            GATED_WRITE,
            Some(owner.pending()),
        ),
    ]
    .map(|new| (new, intruder))
    .into()
}

/// Both crossings in one row: `intruder`'s approve (by [`APPROVER`]) and
/// route bundle approval (by the approved operation's actor) of `owner`'s
/// pending operation, each recorded by an event of `owner`'s scope.
fn double_crossings(owner: Scope, intruder: Scope) -> Vec<Attempt> {
    let id = |base| attempt_id(base, owner, intruder);
    [
        new_operation(
            intruder,
            id("both_appr"),
            APPROVER.into(),
            "approve",
            Some(owner.pending()),
        ),
        new_operation(
            intruder,
            id("both_rba"),
            owner.requester(),
            ROUTE_BUNDLE_APPROVAL,
            Some(owner.pending()),
        ),
    ]
    .map(|new| (new, owner))
    .into()
}

/// Inserts every attempt `attempts` makes for each crossing (owner,
/// intruder): each is refused by `constraint` and writes nothing, neither
/// the operation nor its event.
async fn assert_inserts_refused(
    crossings: &[(Scope, Scope)],
    attempts: fn(Scope, Scope) -> Vec<Attempt>,
    constraint: &str,
) {
    let (db, pool) = two_tenants_with_operations().await;
    let attempts: Vec<((Scope, Scope), Attempt)> = crossings
        .iter()
        .flat_map(|&(owner, intruder)| {
            attempts(owner, intruder)
                .into_iter()
                .map(move |attempt| ((owner, intruder), attempt))
        })
        .collect();
    let mut ids: Vec<String> = [OP_A, OP_B, INSTANCE].map(Scope::pending).into();
    ids.extend(attempts.iter().map(|(_, (new, _))| new.id.clone()));
    let before = operation_state(&pool, &ids).await;
    for &((owner, intruder), (ref new, event)) in &attempts {
        assert_scope_refused(
            insert_recorded_in(&pool, new, event).await,
            constraint,
            (owner, intruder),
        );
        assert_eq!(find_operation(&pool, &new.id).await, None, "{}", new.id);
    }
    assert_eq!(operation_state(&pool, &ids).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a29_neg_operation_names_other_tenants_audit_event() {
    assert_inserts_refused(
        &TENANT_CROSSINGS,
        audit_crossings,
        "administrative_operation_audit_same_tenant",
    )
    .await;
}

#[tokio::test]
async fn a29_neg_audit_event_across_instance_and_tenant() {
    assert_inserts_refused(
        &INSTANCE_CROSSINGS,
        audit_crossings,
        "administrative_operation_audit_same_tenant",
    )
    .await;
}

#[tokio::test]
async fn a29_neg_other_kind_names_other_tenants_operation() {
    assert_inserts_refused(
        &TENANT_CROSSINGS,
        named_operation_crossings,
        "administrative_operation_approves_same_tenant",
    )
    .await;
}

#[tokio::test]
async fn a29_neg_other_kind_names_operation_across_instance_and_tenant() {
    assert_inserts_refused(
        &INSTANCE_CROSSINGS,
        named_operation_crossings,
        "administrative_operation_approves_same_tenant",
    )
    .await;
}

/// A row that crosses both references is refused by the approval guard:
/// `administrative_operation_approval_check` fires before
/// `administrative_operation_audit_check` (PostgreSQL fires same-event
/// triggers in name order; `0005`, README "Triggers and timing"), and the
/// first that fails refuses the row. The registry inserts one row per
/// statement, so the order across the rows of one statement is not
/// observable here (see the module documentation).
#[tokio::test]
async fn a29_neg_double_crossing_reports_the_approval_guard() {
    let crossings: Vec<(Scope, Scope)> = TENANT_CROSSINGS
        .into_iter()
        .chain(INSTANCE_CROSSINGS)
        .collect();
    assert_inserts_refused(
        &crossings,
        double_crossings,
        "administrative_operation_approves_same_tenant",
    )
    .await;
}

/// `written` is `new` as given: its ID, scope, actor, kind, audit event and
/// approved operation.
#[track_caller]
fn assert_written(written: &AdministrativeOperation, new: &NewAdministrativeOperation) {
    assert_eq!(written.id, new.id);
    assert_eq!(written.tenant_id, new.tenant_id, "{}", new.id);
    assert_eq!(written.actor_id, new.actor_id, "{}", new.id);
    assert_eq!(written.kind, new.kind, "{}", new.id);
    assert_eq!(written.audit_id, new.audit_id, "{}", new.id);
    assert_eq!(
        written.approves_operation_id, new.approves_operation_id,
        "{}",
        new.id
    );
}

/// The head sequence of the audit chain, which must be intact.
async fn chain_head(pool: &PgPool) -> i64 {
    let mut connection = pool.acquire().await.unwrap();
    match registry::verify_audit_chain(&mut connection).await.unwrap() {
        ChainVerdict::Intact { last_sequence } => last_sequence,
        broken => panic!("broken chain: {broken:?}"),
    }
}

/// The control of the audit and named-operation tests above: in each
/// tenant and in the instance, the seven writes of those tests made within
/// the scope, each recorded by an event of the scope and naming, if
/// anything, the scope's own pending operation (a pending gated write
/// naming nothing, an approve by [`APPROVER`], a route bundle approval by
/// the pending operation's requester, twice, a `cancel` by the requester, a
/// `reject` by [`APPROVER`] and a pending gated write naming the pending
/// operation), are written, each with its event, the chain intact.
#[tokio::test]
async fn a29_pos_same_scope_audit_event_and_named_operation_are_written() {
    let (db, pool) = two_tenants_with_operations().await;
    let head = chain_head(&pool).await;
    let mut written = 0;
    for scope in [OP_A, OP_B, INSTANCE] {
        let attempts = audit_crossings(scope, scope)
            .into_iter()
            .chain(named_operation_crossings(scope, scope));
        for (new, event) in attempts {
            let operation = insert_recorded_in(&pool, &new, event).await.unwrap();
            assert_written(&operation, &new);
            assert_eq!(operation.tenant_id.as_deref(), scope.tenant);
            assert_eq!(find_operation(&pool, &new.id).await, Some(operation));
            written += 1;
        }
    }
    assert_eq!(written, 21);
    assert_eq!(chain_head(&pool).await, head + written);
    db.drop([pool]).await;
}

/// The actor rule of `0005` stays with kind `approve`: in each tenant and
/// in the instance, a route bundle approval of the scope's pending
/// operation by that operation's own actor (one person may prepare and
/// approve a route bundle; IR-054, GW-130, GW-131) is written, with its
/// event, the chain intact. The approval guard, which now runs for this
/// kind, checks its tenant only. (The refusal of an approve by that actor,
/// `administrative_operation_approver_distinct`, is not a crossing and
/// stays with the service tests.)
#[tokio::test]
async fn a29_pos_route_bundle_approval_by_its_preparer_is_written() {
    let (db, pool) = two_tenants_with_operations().await;
    let head = chain_head(&pool).await;
    for scope in [OP_A, OP_B, INSTANCE] {
        let preparer = find_operation(&pool, &scope.pending())
            .await
            .unwrap()
            .actor_id;
        assert_eq!(preparer, scope.requester());
        let new = new_operation(
            scope,
            scope.id("op_rba_self"),
            preparer,
            ROUTE_BUNDLE_APPROVAL,
            Some(scope.pending()),
        );
        let operation = insert_recorded_in(&pool, &new, scope).await.unwrap();
        assert_written(&operation, &new);
        assert_eq!(operation.tenant_id.as_deref(), scope.tenant);
        assert_eq!(find_operation(&pool, &new.id).await, Some(operation));
    }
    assert_eq!(chain_head(&pool).await, head + 3);
    db.drop([pool]).await;
}
