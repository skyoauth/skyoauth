//! A43: tenant B writes, grants or issues on tenant A's audience; RB tenant
//! mismatch. Expected: A uses its own audience, and B's references to A's
//! audience are refused (tasks §8; T14.1, T14.2, T52.6; identity-registry
//! IR-070, IR-071, IR-080, IR-082; ADR-018 items 1, 3 and 4; design §7.1).
//!
//! **A43 partial: the registry-level write slice only; A43 M1a stays
//! planned (scope "write").** These tests are registered on A43's planned
//! M1a stage, so they are no evidence for it: the reporter lists their
//! results as not counted, and they are no claim. They run through the
//! typed registry API (`skyoauth_service::persistence::registry`: the
//! resource server and assignment writes and reads, and the service
//! identity and service grant writes that name an audience) against a real
//! PostgreSQL, one fresh database per test (per round in the replica
//! tests), with no SQL of their own. The fixture is local ([`fixture`]):
//! tenants `ten_a` and `ten_b`, each with a workload, a GitHub source, a
//! binding, a service identity and a direct grant, and four resource
//! servers: `rs_a` and `rs_b`, each assigned to its own tenant only,
//! `rs_shared`, assigned to both tenants by two assignments with different
//! terms, and `rs_free`, registered and assigned to no tenant.
//!
//! - **Positive.** Each tenant references the audiences assigned to it, its
//!   own and the shared one, at every registry write that names an
//!   audience: a service identity and a direct and a delegation grant
//!   created with them, and audiences added to an existing identity and
//!   grant. Every write reads back exactly (the audience set sorted
//!   byte-wise, the revision), each tenant lists only its own records, and
//!   the resource servers and the assignments with their explicit profiles,
//!   scopes and schema versions read back as created
//!   (`a43_pos_tenant_references_its_own_assigned_audiences`).
//! - **Negative, references.** Through each of the four writes that name an
//!   audience (`create_service_identity`, `add_service_identity_resource_server`,
//!   `create_service_grant`, `add_service_grant_resource_server`), a
//!   reference that tenant B may not make is refused with one typed error,
//!   `Invariant { ForeignKey, <write's assignment key> }`, compared by
//!   variant, kind and constraint, never by message text, in each of the
//!   three registry states a name can be in: (1) a resource server assigned
//!   to another tenant only (A's audience); (2) a resource server assigned
//!   to no tenant (`rs_free`); (3) no resource server with that ID. State (3)
//!   is what an unknown ID, every audience string (A's, B's own, the shared
//!   one and the unassigned one) and every assignment ID (A's and B's own,
//!   of their own and of the shared audience) reduce to when used where a
//!   resource server ID is expected. The strings and assignment IDs of
//!   audiences assigned to B are among them, so a write that resolved an
//!   audience string or an assignment ID to its resource server would
//!   accept them: they are what catches it. Named next to B's own audience
//!   in a grant's create, a refused name still fails the whole statement.
//!   Each refusal writes nothing, in both directions
//!   (`a43_neg_reference_outside_own_assignment_is_one_refusal`).
//! - **Negative, competing registrations.** A second resource server with
//!   an audience already registered is refused (`resource_server_audience_key`),
//!   also after the first is disabled, and so is one that reuses a resource
//!   server's ID; a second assignment of an assigned audience to the same
//!   tenant, with wider terms, is refused
//!   (`audience_tenant_assignment_tenant_id_resource_server_id_key`), also
//!   after the first is disabled, and so is one that reuses an assignment's
//!   ID. Nothing changes (`a43_neg_competing_registration_of_an_audience_is_refused`).
//! - **Negative, exactness.** Variants of a registered audience are each
//!   either refused or a resource server of their own: leading, trailing or
//!   ASCII whitespace and control characters are refused
//!   (`resource_server_audience_no_space_check`); case, a trailing slash or
//!   dot, a Cyrillic lookalike letter, a no-break space, a zero-width space
//!   and the NFD spelling of an NFC audience are each registered as a
//!   distinct audience, stored and read back byte for byte, and each is then
//!   unique in its own right; the original stays the only resource server
//!   with its exact bytes (`a43_neg_audience_variants_are_distinct_or_refused`).
//!   All of it is registry behaviour, not the spec's. Known gap: accepting
//!   the no-break space, the zero-width space and the NFD spelling. Its
//!   owner is audience syntax and Unicode normalization (OQ-IR-9, open; a
//!   service rule per migrations README "What 0003 adds"; T14.1), and a
//!   service-layer fix will not turn this test red (see "Known gaps").
//! - **Negative, concurrency.** Of 8 replicas (REP, `skyoauth_scenarios::rep`)
//!   that register one audience at once under 8 resource server IDs,
//!   exactly one succeeds and 7 get `AlreadyExists` with
//!   `resource_server_audience_key`; then of 8 replicas that assign that
//!   audience at once, 4 to each tenant, exactly one per tenant succeeds and
//!   the 6 others get `AlreadyExists` with
//!   `audience_tenant_assignment_tenant_id_resource_server_id_key`. The
//!   state is the winners' only, in 3 fresh databases
//!   (`a43_neg_concurrent_registrations_have_one_winner_per_key`). Four
//!   replicas seen blocked ([`rep::wait_until_blocked`]) behind a holder's
//!   uncommitted registration of the same audience, or assignment of it to
//!   the same tenant, all get `AlreadyExists` after its commit, and exactly
//!   one of them succeeds after its rollback
//!   (`a43_neg_blocked_registrations_follow_the_holder_commit_or_rollback`).
//!
//! # Spec and registry picks
//!
//! The spec's rules these tests pin: one globally unique exact audience per
//! resource server, which tenants cannot register again (IR-070, IR-071;
//! ADR-018 item 1); explicit assignments with their own profiles, scopes and
//! schema versions (ADR-018 item 3; T14.1); a shared audience assigned to
//! several tenants (design §7.1; ADR-018 context, "an audience names an API
//! that may serve several tenants", and item 5, "a shared multi-tenant
//! audience"), so an audience has no single tenant and the concurrency test
//! expects one winner per tenant and audience, not one per audience;
//! references refused without a same-tenant assignment
//! (IR-080); and a matching audience string alone authorizes nothing
//! (IR-082).
//!
//! These are the registry's behaviour, not the spec's, where the spec does
//! not define them: that every refusal of a reference outside the tenant's
//! assignments is the one composite foreign key error, whatever the reason
//! (the spec's non-disclosure rules, API-012 and ERR-020 and ERR-024, are
//! for the exchange, not for writes); the byte-wise comparison of audiences
//! (case, slash, dot and lookalikes distinct; their syntax and comparison
//! rules are open, OQ-IR-9); the refusal of ASCII whitespace and control
//! characters (a lead decision of 2026-11-20 for free-text keys,
//! `service/migrations/README.md`); uniqueness that includes disabled
//! resource servers and assignments; and one assignment per tenant and
//! resource server (inferred in `0003`).
//!
//! Known gaps, asserted with that label: the NFD spelling of an NFC
//! audience, a no-break space and a zero-width space are accepted as new
//! audiences. Audience syntax and Unicode normalization are open (OQ-IR-9)
//! and a service rule per `service/migrations/README.md`, "What 0003 adds"
//! (T14.1), and the registry's character rule refuses ASCII whitespace and
//! C0/C1 controls only. A service-layer fix will not turn this test red:
//! the test calls the registry directly, below any service check, and keeps
//! passing when the service validates or normalizes audiences. Only a
//! change in the registry itself (its schema or its functions normalizing
//! or refusing these values) fails it, and then the assertions and these
//! docs need the update.
//!
//! # Not expressible in the registry, so not tested
//!
//! - **An enabled assignment at write.** IR-080 and T14.2 refuse a
//!   reference "outside an active same-tenant assignment"; the registry's
//!   composite foreign keys prove only that an assignment exists, whatever
//!   its status (`registry::grant`, `add_service_identity_resource_server`;
//!   migrations README, "What 0003 adds": the service must refuse
//!   references outside an enabled assignment). So a write naming an
//!   audience whose assignment is disabled succeeds through the registry,
//!   and "a disabled assignment stops further writes" has no registry test;
//!   no test here asserts the acceptance either: it is an open gap, untested
//!   either way. An assignment cannot be removed (`0006` rejects its
//!   `DELETE`), and the registry has no superseded assignment. The lead
//!   recommends (a recommendation, not a decision) enforcing the check with
//!   a database trigger rather than a check-then-insert above the registry:
//!   the composite foreign key takes a `KEY SHARE` lock, which does not
//!   conflict with the status `UPDATE`, so a check-then-insert races with a
//!   concurrent disable. A trigger reverses the migrations README rule "The
//!   database does not enforce these rules; the service must", so it is a
//!   spec decision that goes to the user.
//! - **Who may assign.** The registry authorizes nobody (`registry` "Not
//!   done here": API-147 and the endpoint roles are T14.1 and T14.2):
//!   creating a resource server or an assignment is an instance write that
//!   only `security_admin` may make (IR-070, API-147). That scoped tenant
//!   admins cannot self-assign or shadow another audience is T14.1's own
//!   tenant-admin clause, enforced by T13.2's scoped roles at the T13.8
//!   endpoints (API-147), not a registry rule. An assignment's tenant and
//!   resource server and a resource server's audience cannot be changed by
//!   any registry update (their change types have no such field), so
//!   re-pointing one has no API to test; the immutability guards behind
//!   them are the service tests'.
//!
//! **Missing, so not a claim.** A43 M1a needs its row end to end at write;
//! these tests reach only the registry. Still needed, with the owner of
//! each part:
//!
//! - The enabled-assignment check at write, the other half of T14.2 above:
//!   not built, and where it lives is open (the lead's recommendation
//!   above).
//! - Audience syntax and Unicode normalization (OQ-IR-9, open; a service
//!   rule per migrations README "What 0003 adds"; T14.1).
//! - The tenant-admin negative at the endpoint: T14.1 (its tenant-admin
//!   clause), enforced by T13.2's scoped roles at the T13.8 endpoints
//!   (API-147). A43's harness is PG and RB, with no operator endpoint, so
//!   that negative cannot be finished in A43 as its row stands. It is
//!   unowned until the maintainer rules between widening A43's harness (a
//!   tasks-row change) and crediting it to A22 M1a.
//!
//! Not A43 M1a's, with their owners:
//!
//! - Issuance and the backend: an exchange for another tenant's audience,
//!   the exact-audience lookup at issuance (`load_scope_ceilings`),
//!   one registered audience per credential and the backends' canonical
//!   tenant mapping (T14.2) are A43's M2 stage, "issuance and backend".
//! - "RB tenant mismatch": the RB harness component, the test-only
//!   reference ConnectRPC backend behind Envoy with its tenant and RBAC
//!   check, which is not built.
//! - The recheck of the assignment at every live authorization (IR-081,
//!   T14.2) has no A43 stage: it is A31's M2 stage (owners T14.3, T26.5),
//!   through the in-process service (UC).
//! - Clients, origins and human policies (IR-080) are M1b records with no
//!   tables yet: a reference from one to another tenant's audience is a
//!   crossing for A29's M1b stage, "human registry references" (T10.8's
//!   closed list), and their assignment-status check is T14.5's and
//!   T14.6's.
//!
//! # Overlap
//!
//! A29 (`tests/security/a29.rs`, implemented) already pins that a service
//! identity or a grant naming the other tenant's audience is refused on
//! create and on add, by `Invariant { ForeignKey, <assignment key> }`, in
//! both directions, and writes nothing. A43 does not repeat that as a claim
//! of its own: it compares that refusal with the refusals in the other two
//! registry states, an audience that no tenant is assigned and an ID that
//! names no resource server, including the audience strings and assignment
//! IDs that reduce to it (one typed refusal for all), uses
//! a shared audience in the positive, and adds the instance-level half that
//! A29 does not touch: audience uniqueness, exactness and concurrency, and
//! competing assignments.
//!
//! The service tests cover, without replicas: duplicate audiences and the
//! space and tab refusals by constraint name
//! (`resource_server_errors_name_their_constraint` in
//! `service/tests/registry.rs`); a duplicate (tenant, resource server)
//! assignment (`assignments_update_by_revision_and_name_their_constraints`);
//! another tenant's and a missing audience giving the same assignment key on
//! a service identity's create and add and a grant's create, and another
//! tenant's on a grant's add (`service_identities_carry_their_assigned_audiences`,
//! `grants_are_created_with_their_bindings_and_audiences` in
//! `service/tests/registry_trust.rs`); and in SQL, byte-wise case and slash
//! distinctness, the whitespace and control refusals, one assignment per
//! pair, a second tenant on one resource server, the immutability guards
//! and the composite keys (`service/tests/schema_resource_servers.rs`).

use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use serde_json::{Value, json};
use skyoauth_scenarios::{
    pg::TestDb,
    rep::{self, Replicas},
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, ActivationState, AssertionProfile, AudienceTenantAssignment,
        AudienceTenantAssignmentChanges, BindingProfile, GrantMode, InvariantKind, JsonObject,
        MAX_PAGE_SIZE, NewAudienceTenantAssignment, NewPrincipal, NewPrincipalBinding,
        NewResourceServer, NewServiceGrant, NewServiceIdentity, NewTenant, NewTrustSource, Page,
        PrincipalKind, Profile, RegistryError, ReplayMode, ResourceServer, ResourceServerChanges,
        Status, TrustSourceKind,
    },
};
use sqlx::{Connection, Postgres, pool::PoolConnection};

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The resource server assigned to both tenants, each by its own
/// assignment.
const SHARED: &str = "rs_shared";
const SHARED_AUDIENCE: &str = "https://shared.example";
/// A registered resource server that no tenant is assigned.
const FREE: &str = "rs_free";
const FREE_AUDIENCE: &str = "https://unassigned.example";
/// An ID that no resource server has.
const MISSING: &str = "rs_missing";

/// The audience the concurrency tests contend for.
const CONTESTED_AUDIENCE: &str = "https://contested.example";

/// One of the two tenants. Every ID carries the tenant's suffix, because
/// IDs are global.
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

/// (owner, intruder): the intruder's write names the owner's audience.
const DIRECTIONS: [(Side, Side); 2] = [(A, B), (B, A)];

impl Side {
    fn id(self, base: &str) -> String {
        format!("{base}_{}", self.suffix)
    }
    fn workload(self) -> String {
        self.id("wld")
    }
    /// Service principal with a service identity in the fixture.
    fn service(self) -> String {
        self.id("svc")
    }
    /// Service principal without a service identity in the fixture.
    fn spare(self) -> String {
        self.id("spare")
    }
    fn source(self) -> String {
        self.id("src")
    }
    fn binding(self) -> String {
        self.id("bnd")
    }
    fn grant(self) -> String {
        self.id("grt")
    }
    /// The resource server assigned to this tenant only.
    fn audience(self) -> String {
        self.id("rs")
    }
    /// The audience string of [`Side::audience`].
    fn audience_string(self) -> String {
        format!("https://api-{}.example", self.suffix)
    }
    /// The assignment of [`Side::audience`] to this tenant.
    fn assignment(self) -> String {
        self.id("ata")
    }
    /// This tenant's assignment of [`SHARED`].
    fn shared_assignment(self) -> String {
        self.id("ata_shared")
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

fn server(id: &str, audience: &str) -> NewResourceServer {
    NewResourceServer {
        id: id.into(),
        audience: audience.into(),
        name: format!("API {id}"),
        allowed_profiles: vec![Profile::Wif, Profile::HumanCli],
        scopes: strings(&["read", "write"]),
        constraint_versions: vec![json!(1), json!(2)],
        status: Status::Enabled,
    }
}

/// The stored row a create of `new` returns, at revision 1.
fn stored_server(new: &NewResourceServer) -> ResourceServer {
    ResourceServer {
        id: new.id.clone(),
        audience: new.audience.clone(),
        name: new.name.clone(),
        allowed_profiles: new.allowed_profiles.clone(),
        scopes: new.scopes.clone(),
        constraint_versions: new.constraint_versions.clone(),
        status: new.status,
        revision: 1,
    }
}

/// An assignment with explicit terms: `wide` lists every profile and scope
/// of the resource server, otherwise only `wif` and `read` with schema
/// version 1.
fn assignment(
    id: &str,
    resource_server_id: &str,
    tenant: &str,
    wide: bool,
) -> NewAudienceTenantAssignment {
    let (allowed_profiles, allowed_scopes, constraint_versions) = if wide {
        (
            vec![Profile::Wif, Profile::HumanCli],
            strings(&["read", "write"]),
            vec![json!(1), json!(2)],
        )
    } else {
        (vec![Profile::Wif], strings(&["read"]), vec![json!(1)])
    };
    NewAudienceTenantAssignment {
        id: id.into(),
        resource_server_id: resource_server_id.into(),
        tenant_id: tenant.into(),
        allowed_profiles,
        allowed_scopes,
        constraint_versions,
        status: Status::Enabled,
    }
}

fn stored_assignment(new: &NewAudienceTenantAssignment) -> AudienceTenantAssignment {
    AudienceTenantAssignment {
        id: new.id.clone(),
        resource_server_id: new.resource_server_id.clone(),
        tenant_id: new.tenant_id.clone(),
        allowed_profiles: new.allowed_profiles.clone(),
        allowed_scopes: new.allowed_scopes.clone(),
        constraint_versions: new.constraint_versions.clone(),
        status: new.status,
        revision: 1,
    }
}

/// The fixture's resource servers, in ID order.
fn servers() -> [NewResourceServer; 4] {
    [
        server(&A.audience(), &A.audience_string()),
        server(&B.audience(), &B.audience_string()),
        server(FREE, FREE_AUDIENCE),
        server(SHARED, SHARED_AUDIENCE),
    ]
}

/// The fixture's assignments, in ID order: each tenant's own audience on
/// narrow terms, and the shared audience on narrow terms for A and wide
/// terms for B.
fn assignments() -> [NewAudienceTenantAssignment; 4] {
    [
        assignment(&A.assignment(), &A.audience(), A.tenant, false),
        assignment(&B.assignment(), &B.audience(), B.tenant, false),
        assignment(&A.shared_assignment(), SHARED, A.tenant, false),
        assignment(&B.shared_assignment(), SHARED, B.tenant, true),
    ]
}

fn tenant(side: Side) -> NewTenant {
    NewTenant {
        id: side.tenant.into(),
        name: "Example".into(),
        secret_namespace: side.id("ns"),
        status: Status::Enabled,
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

fn github_source(side: Side) -> NewTrustSource {
    NewTrustSource {
        id: side.source(),
        tenant_id: side.tenant.into(),
        name: "github".into(),
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

fn service_identity(side: Side, id: String, name: &str, audiences: &[&str]) -> NewServiceIdentity {
    NewServiceIdentity {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        max_scopes: strings(&["read"]),
        max_resource_constraints: object(json!({"version": 1})),
        resource_server_ids: strings(audiences),
        status: Status::Enabled,
    }
}

/// A direct grant of the side's workload, with its binding.
fn direct_grant(side: Side, id: String, name: &str, audiences: &[&str]) -> NewServiceGrant {
    NewServiceGrant {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        actor_principal_id: side.workload(),
        target_service_id: None,
        mode: GrantMode::Direct,
        scopes: strings(&["read"]),
        default_scopes: Some(strings(&["read"])),
        resource_constraints: JsonObject::new(),
        max_ttl: 300,
        valid_until: None,
        status: Status::Enabled,
        activation_state: ActivationState::NotRequired,
        allowed_binding_ids: vec![side.binding()],
        resource_server_ids: strings(audiences),
    }
}

/// Tenants only, for the concurrency tests.
async fn tenants() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for side in [A, B] {
        registry::create_tenant(&pool, &tenant(side)).await.unwrap();
    }
    (db, pool)
}

/// Both tenants with their records (module docs), the four resource
/// servers and the four assignments. Each tenant's service identity and
/// grant name its own audience only.
async fn fixture() -> (TestDb, PgPool) {
    let (db, pool) = tenants().await;
    for new in servers() {
        registry::create_resource_server(&pool, &new).await.unwrap();
    }
    for new in assignments() {
        registry::create_audience_tenant_assignment(&pool, &new)
            .await
            .unwrap();
    }
    for side in [A, B] {
        for (id, kind, name) in [
            (side.workload(), PrincipalKind::Workload, "ci"),
            (side.service(), PrincipalKind::Service, "deploy-api"),
            (side.spare(), PrincipalKind::Service, "spare"),
        ] {
            registry::create_principal(&pool, &principal(side, id, kind, name))
                .await
                .unwrap();
        }
        registry::create_trust_source(&pool, &github_source(side))
            .await
            .unwrap();
        registry::create_principal_binding(
            &pool,
            &NewPrincipalBinding {
                id: side.binding(),
                tenant_id: side.tenant.into(),
                name: "release".into(),
                trust_source_id: side.source(),
                profile: BindingProfile::GithubProduction,
                claim_match_policy: super::grant_fixture::github_policy(),
                workload_principal_id: side.workload(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        let own = side.audience();
        registry::create_service_identity(
            &pool,
            &service_identity(side, side.service(), "deploy-api", &[&own]),
        )
        .await
        .unwrap();
        registry::create_service_grant(&pool, &direct_grant(side, side.grant(), "deploy", &[&own]))
            .await
            .unwrap();
    }
    (db, pool)
}

/// The instance's resource servers and assignments, and each tenant's
/// service identities and grants, as `Debug` text. Equal snapshots before
/// and after a refused write show that it wrote nothing: no row, no
/// audience row and no revision changed.
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let all = Page::first(MAX_PAGE_SIZE);
    let mut out = vec![
        format!(
            "{:?}",
            registry::list_resource_servers(pool, all).await.unwrap()
        ),
        format!(
            "{:?}",
            registry::list_audience_tenant_assignments(pool, all)
                .await
                .unwrap()
        ),
    ];
    for side in [A, B] {
        out.push(format!(
            "{:?}",
            registry::list_service_identities(pool, side.tenant, all)
                .await
                .unwrap()
        ));
        out.push(format!(
            "{:?}",
            registry::list_service_grants(pool, side.tenant, all)
                .await
                .unwrap()
        ));
    }
    out
}

/// A refusal by a constraint, as its typed fields: the variant
/// [`RegistryError::Invariant`] with its kind and constraint name. Two
/// refusals are the same refusal when these are equal; the `Display` text
/// is never compared.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    kind: InvariantKind,
    constraint: &'static str,
}

#[track_caller]
fn refusal<T: Debug>(result: Result<T, RegistryError>) -> Refusal {
    match result {
        Err(RegistryError::Invariant {
            kind,
            constraint: Some(constraint),
        }) => Refusal { kind, constraint },
        other => panic!("expected RegistryError::Invariant with a constraint: {other:?}"),
    }
}

/// The constraint of an `AlreadyExists`, the variant checked by match.
#[track_caller]
fn already_exists<T: Debug>(result: Result<T, RegistryError>) -> &'static str {
    match result {
        Err(RegistryError::AlreadyExists { constraint }) => constraint,
        other => panic!("expected RegistryError::AlreadyExists: {other:?}"),
    }
}

#[track_caller]
fn assert_not_found<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::NotFound)), "{result:?}");
}

const AUDIENCE_KEY: &str = "resource_server_audience_key";
const ASSIGNMENT_PAIR_KEY: &str = "audience_tenant_assignment_tenant_id_resource_server_id_key";
const SERVICE_ASSIGNMENT_KEY: &str = "service_identity_resource_server_assignment_fkey";
const GRANT_ASSIGNMENT_KEY: &str = "service_grant_resource_server_assignment_fkey";
const NO_SPACE_CHECK: &str = "resource_server_audience_no_space_check";

#[tokio::test]
async fn a43_pos_tenant_references_its_own_assigned_audiences() {
    let (db, pool) = fixture().await;
    let all = Page::first(MAX_PAGE_SIZE);
    // The instance registry reads back as created: each audience exact, and
    // each assignment with its own tenant and terms; the shared audience
    // has one assignment per tenant, with different terms.
    let expected_servers: Vec<ResourceServer> = servers().iter().map(stored_server).collect();
    for expected in &expected_servers {
        assert_eq!(
            &registry::get_resource_server(&pool, &expected.id)
                .await
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        registry::list_resource_servers(&pool, all).await.unwrap(),
        expected_servers
    );
    let expected_assignments: Vec<AudienceTenantAssignment> =
        assignments().iter().map(stored_assignment).collect();
    for expected in &expected_assignments {
        assert_eq!(
            &registry::get_audience_tenant_assignment(&pool, &expected.id)
                .await
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        registry::list_audience_tenant_assignments(&pool, all)
            .await
            .unwrap(),
        expected_assignments
    );

    for side in [A, B] {
        let t = side.tenant;
        let own = side.audience();
        let both = vec![own.clone(), SHARED.to_string()];
        // An identity created with both of its audiences, listed in byte
        // order whatever the order given.
        let second = side.id("svc2");
        registry::create_principal(
            &pool,
            &principal(side, second.clone(), PrincipalKind::Service, "billing-api"),
        )
        .await
        .unwrap();
        let created = registry::create_service_identity(
            &pool,
            &service_identity(side, second.clone(), "billing-api", &[SHARED, &own]),
        )
        .await
        .unwrap();
        assert_eq!(created.resource_server_ids, both);
        assert_eq!((created.tenant_id.as_str(), created.revision), (t, 1));
        assert_eq!(
            registry::get_service_identity(&pool, t, &second)
                .await
                .unwrap(),
            created
        );
        // The shared audience added to the fixture's identity and grant,
        // which name the own audience.
        assert_eq!(
            registry::add_service_identity_resource_server(&pool, t, &side.service(), 1, SHARED)
                .await
                .unwrap(),
            2
        );
        let identity = registry::get_service_identity(&pool, t, &side.service())
            .await
            .unwrap();
        assert_eq!(
            (identity.resource_server_ids.clone(), identity.revision),
            (both.clone(), 2)
        );
        assert_eq!(
            registry::add_service_grant_resource_server(&pool, t, &side.grant(), 1, SHARED)
                .await
                .unwrap(),
            2
        );
        let grant = registry::get_service_grant(&pool, t, &side.grant())
            .await
            .unwrap();
        assert_eq!(
            (grant.resource_server_ids.clone(), grant.revision),
            (both.clone(), 2)
        );
        // A delegation grant to the second identity, created with both
        // audiences.
        let delegation = NewServiceGrant {
            mode: GrantMode::Delegation,
            target_service_id: Some(second.clone()),
            ..direct_grant(side, side.id("grt_dlg"), "delegate", &[SHARED, &own])
        };
        let created = registry::create_service_grant(&pool, &delegation)
            .await
            .unwrap();
        assert_eq!(created.resource_server_ids, both);
        assert_eq!(created.target_service_id.as_deref(), Some(second.as_str()));
        assert_eq!(
            registry::get_service_grant(&pool, t, &delegation.id)
                .await
                .unwrap(),
            created
        );
    }
    // Each tenant lists only its own records, each naming only audiences
    // assigned to that tenant.
    for side in [A, B] {
        let t = side.tenant;
        let identities: Vec<(String, Vec<String>)> =
            registry::list_service_identities(&pool, t, all)
                .await
                .unwrap()
                .into_iter()
                .map(|s| (s.id, s.resource_server_ids))
                .collect();
        let both = vec![side.audience(), SHARED.to_string()];
        // In byte order of the IDs: `svc2_a` before `svc_a`.
        assert_eq!(
            identities,
            [
                (side.id("svc2"), both.clone()),
                (side.service(), both.clone())
            ]
        );
        let grants: Vec<(String, Vec<String>)> = registry::list_service_grants(&pool, t, all)
            .await
            .unwrap()
            .into_iter()
            .map(|g| (g.id, g.resource_server_ids))
            .collect();
        assert_eq!(
            grants,
            [(side.grant(), both.clone()), (side.id("grt_dlg"), both)]
        );
    }
    // The instance registry is unchanged by the tenants' references.
    assert_eq!(
        registry::list_resource_servers(&pool, all).await.unwrap(),
        expected_servers
    );
    assert_eq!(
        registry::list_audience_tenant_assignments(&pool, all)
            .await
            .unwrap(),
        expected_assignments
    );
    db.drop([pool]).await;
}

#[tokio::test]
async fn a43_neg_reference_outside_own_assignment_is_one_refusal() {
    let (db, pool) = fixture().await;
    let before = snapshot(&pool).await;
    let service_refusal = Refusal {
        kind: InvariantKind::ForeignKey,
        constraint: SERVICE_ASSIGNMENT_KEY,
    };
    let grant_refusal = Refusal {
        kind: InvariantKind::ForeignKey,
        constraint: GRANT_ASSIGNMENT_KEY,
    };
    for (owner, intruder) in DIRECTIONS {
        let t = intruder.tenant;
        // What the intruder names, by the three registry states a name can
        // be in. (1) A resource server assigned to another tenant only: the
        // owner's. (2) A resource server assigned to no tenant. (3) No
        // resource server has that ID: an unknown ID, and every audience
        // string or assignment ID used where a resource server ID is
        // expected, including the intruder's own audience string, the
        // shared audience's string and the intruder's own assignment IDs,
        // whose resource servers are assigned to the intruder. A write that
        // resolved an audience string or an assignment ID to its resource
        // server would accept those, so they are what catches it.
        let targets = [
            owner.audience(),
            FREE.to_string(),
            MISSING.to_string(),
            owner.audience_string(),
            FREE_AUDIENCE.to_string(),
            intruder.audience_string(),
            SHARED_AUDIENCE.to_string(),
            owner.assignment(),
            owner.shared_assignment(),
            intruder.assignment(),
            intruder.shared_assignment(),
        ];
        let grant_id = intruder.id("grt_cross");
        for target in &targets {
            let named = target.as_str();
            let refusals = [
                (
                    refusal(
                        registry::create_service_identity(
                            &pool,
                            &service_identity(intruder, intruder.spare(), "cross", &[named]),
                        )
                        .await,
                    ),
                    &service_refusal,
                ),
                (
                    refusal(
                        registry::add_service_identity_resource_server(
                            &pool,
                            t,
                            &intruder.service(),
                            1,
                            named,
                        )
                        .await,
                    ),
                    &service_refusal,
                ),
                (
                    refusal(
                        registry::create_service_grant(
                            &pool,
                            &direct_grant(intruder, grant_id.clone(), "cross", &[named]),
                        )
                        .await,
                    ),
                    &grant_refusal,
                ),
                (
                    refusal(
                        registry::add_service_grant_resource_server(
                            &pool,
                            t,
                            &intruder.grant(),
                            1,
                            named,
                        )
                        .await,
                    ),
                    &grant_refusal,
                ),
            ];
            for (index, (actual, expected)) in refusals.iter().enumerate() {
                assert_eq!(
                    actual, *expected,
                    "{} naming {named}, write {index}",
                    intruder.tenant
                );
            }
            // Next to the intruder's own audience, the named one still
            // fails the whole statement.
            let own = intruder.audience();
            assert_eq!(
                refusal(
                    registry::create_service_grant(
                        &pool,
                        &direct_grant(intruder, grant_id.clone(), "cross", &[&own, named]),
                    )
                    .await,
                ),
                grant_refusal,
                "{} naming {own} and {named}",
                intruder.tenant
            );
        }
        for side in [A, B] {
            assert_not_found(
                registry::get_service_identity(&pool, side.tenant, &intruder.spare()).await,
            );
            assert_not_found(registry::get_service_grant(&pool, side.tenant, &grant_id).await);
        }
    }
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a43_neg_competing_registration_of_an_audience_is_refused() {
    let (db, pool) = fixture().await;
    let before = snapshot(&pool).await;
    // A competing resource server for each registered audience, under a new
    // ID and with its own terms, and a reused ID with a new audience.
    for (index, (_, audience)) in [
        (A.audience(), A.audience_string()),
        (B.audience(), B.audience_string()),
        (SHARED.to_string(), SHARED_AUDIENCE.to_string()),
        (FREE.to_string(), FREE_AUDIENCE.to_string()),
    ]
    .into_iter()
    .enumerate()
    {
        let competing = NewResourceServer {
            name: "Competing".into(),
            allowed_profiles: vec![Profile::Wif, Profile::HumanCli, Profile::HumanSession],
            scopes: strings(&["read", "write", "admin"]),
            ..server(&format!("rs_competing_{index}"), &audience)
        };
        assert_eq!(
            already_exists(registry::create_resource_server(&pool, &competing).await),
            AUDIENCE_KEY,
            "{audience}"
        );
    }
    assert_eq!(
        already_exists(
            registry::create_resource_server(&pool, &server(&A.audience(), "https://new.example"))
                .await
        ),
        "resource_server_pkey"
    );
    // A second assignment of an assigned audience to the same tenant, on
    // wider terms, and an assignment that reuses an assignment's ID.
    for (id, resource_server_id, tenant) in [
        ("ata_second_a", A.audience(), A.tenant),
        ("ata_second_b", B.audience(), B.tenant),
        ("ata_second_shared_a", SHARED.to_string(), A.tenant),
        ("ata_second_shared_b", SHARED.to_string(), B.tenant),
    ] {
        assert_eq!(
            already_exists(
                registry::create_audience_tenant_assignment(
                    &pool,
                    &assignment(id, &resource_server_id, tenant, true),
                )
                .await
            ),
            ASSIGNMENT_PAIR_KEY,
            "{id}"
        );
    }
    assert_eq!(
        already_exists(
            registry::create_audience_tenant_assignment(
                &pool,
                &assignment(&A.assignment(), FREE, B.tenant, true),
            )
            .await
        ),
        "audience_tenant_assignment_pkey"
    );
    assert_eq!(snapshot(&pool).await, before);

    // Disabled, the resource server and the assignment still hold their
    // keys (registry behaviour: the unique keys include disabled rows).
    let original = registry::get_resource_server(&pool, &A.audience())
        .await
        .unwrap();
    registry::update_resource_server(
        &pool,
        &original.id,
        original.revision,
        &ResourceServerChanges {
            name: original.name.clone(),
            allowed_profiles: original.allowed_profiles.clone(),
            scopes: original.scopes.clone(),
            constraint_versions: original.constraint_versions.clone(),
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    let held = registry::get_audience_tenant_assignment(&pool, &A.assignment())
        .await
        .unwrap();
    registry::update_audience_tenant_assignment(
        &pool,
        &held.id,
        held.revision,
        &AudienceTenantAssignmentChanges {
            allowed_profiles: held.allowed_profiles.clone(),
            allowed_scopes: held.allowed_scopes.clone(),
            constraint_versions: held.constraint_versions.clone(),
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    let disabled = snapshot(&pool).await;
    assert_eq!(
        already_exists(
            registry::create_resource_server(
                &pool,
                &server("rs_competing_disabled", &A.audience_string())
            )
            .await
        ),
        AUDIENCE_KEY
    );
    assert_eq!(
        already_exists(
            registry::create_audience_tenant_assignment(
                &pool,
                &assignment("ata_second_disabled", &A.audience(), A.tenant, true),
            )
            .await
        ),
        ASSIGNMENT_PAIR_KEY
    );
    assert_eq!(snapshot(&pool).await, disabled);
    for index in 0..4 {
        assert_not_found(
            registry::get_resource_server(&pool, &format!("rs_competing_{index}")).await,
        );
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a43_neg_audience_variants_are_distinct_or_refused() {
    let (db, pool) = fixture().await;
    let original = A.audience_string();
    assert_eq!(original, "https://api-a.example");
    // Refused by the character rule (lead decision, 2026-11-20; registry
    // behaviour, not the spec's): ASCII whitespace and controls anywhere.
    for variant in [
        format!(" {original}"),
        format!("{original} "),
        "https://api-a .example".to_string(),
        format!("{original}\t"),
        format!("{original}\n"),
        format!("{original}\r"),
        format!("{original}\u{7f}"),
        format!("{original}\u{85}"),
    ] {
        assert_eq!(
            refusal(registry::create_resource_server(&pool, &server("rs_variant", &variant)).await),
            Refusal {
                kind: InvariantKind::Check,
                constraint: NO_SPACE_CHECK,
            },
            "{variant:?}"
        );
    }
    assert_not_found(registry::get_resource_server(&pool, "rs_variant").await);
    // Registered as audiences of their own, compared byte for byte:
    // registry behaviour (OQ-IR-9 leaves the comparison rules open), the
    // last three a known gap (no normalization, and only ASCII whitespace
    // refused).
    let nfc = "https://caf\u{e9}.example";
    let variants = [
        ("rs_v_upper", "HTTPS://API-A.EXAMPLE".to_string()),
        ("rs_v_host_case", "https://API-A.example".to_string()),
        ("rs_v_slash", format!("{original}/")),
        ("rs_v_dot", format!("{original}.")),
        // U+0430 CYRILLIC SMALL LETTER A for the first `a`.
        ("rs_v_cyrillic", "https://\u{430}pi-a.example".to_string()),
        ("rs_v_nfc", nfc.to_string()),
        // Known gap: the NFD spelling of the NFC audience above.
        ("rs_v_nfd", "https://cafe\u{301}.example".to_string()),
        // Known gap: U+00A0 NO-BREAK SPACE and U+200B ZERO WIDTH SPACE.
        ("rs_v_nbsp", format!("{original}\u{a0}")),
        ("rs_v_zwsp", "https://api\u{200b}-a.example".to_string()),
    ];
    for (id, variant) in &variants {
        let new = server(id, variant);
        let created = registry::create_resource_server(&pool, &new).await.unwrap();
        assert_eq!(created, stored_server(&new), "{variant:?}");
        let read = registry::get_resource_server(&pool, id).await.unwrap();
        assert_eq!(read.audience.as_bytes(), variant.as_bytes(), "{variant:?}");
    }
    // Each variant is unique in its own right.
    for (index, (_, variant)) in variants.iter().enumerate() {
        assert_eq!(
            already_exists(
                registry::create_resource_server(
                    &pool,
                    &server(&format!("rs_v_again_{index}"), variant)
                )
                .await
            ),
            AUDIENCE_KEY,
            "{variant:?}"
        );
    }
    // Every registered audience is distinct, and the original is still the
    // only resource server with its exact bytes.
    let listed = registry::list_resource_servers(&pool, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap();
    assert_eq!(listed.len(), servers().len() + variants.len());
    let mut audiences: Vec<&str> = listed.iter().map(|rs| rs.audience.as_str()).collect();
    audiences.sort_unstable();
    audiences.dedup();
    assert_eq!(audiences.len(), listed.len());
    let exact: Vec<&str> = listed
        .iter()
        .filter(|rs| rs.audience == original)
        .map(|rs| rs.id.as_str())
        .collect();
    assert_eq!(exact, [A.audience()]);
    db.drop([pool]).await;
}

/// 8 replicas per round, 3 fresh databases (module docs).
#[tokio::test(flavor = "multi_thread")]
async fn a43_neg_concurrent_registrations_have_one_winner_per_key() {
    const REPLICAS: usize = 8;
    const DATABASES: usize = 3;
    let all = Page::first(MAX_PAGE_SIZE);
    for round in 0..DATABASES {
        let (db, pool) = tenants().await;
        let replicas = Replicas::start(&db, REPLICAS).await;

        // One audience, 8 resource server IDs.
        let outcomes = replicas
            .race(|replica, mut conn| async move {
                let new = server(&format!("rs_race_{replica}"), CONTESTED_AUDIENCE);
                registry::create_resource_server(&mut *conn, &new).await
            })
            .await;
        let winners: Vec<usize> = (0..REPLICAS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        let winner = outcomes[winners[0]].as_ref().unwrap().clone();
        assert_eq!(
            winner,
            stored_server(&server(
                &format!("rs_race_{}", winners[0]),
                CONTESTED_AUDIENCE
            ))
        );
        for (replica, outcome) in outcomes.into_iter().enumerate() {
            if replica != winners[0] {
                assert_eq!(already_exists(outcome), AUDIENCE_KEY, "round {round}");
                assert_not_found(
                    registry::get_resource_server(&pool, &format!("rs_race_{replica}")).await,
                );
            }
        }
        assert_eq!(
            registry::list_resource_servers(&pool, all).await.unwrap(),
            std::slice::from_ref(&winner)
        );

        // That audience assigned at once, replica r to tenant A for even r
        // and B for odd r, each on terms of its own: one winner per tenant.
        let contested = winner.id.clone();
        let request = move |replica: usize| {
            let side = [A, B][replica % 2];
            NewAudienceTenantAssignment {
                allowed_scopes: vec![format!("scope{replica}")],
                ..assignment(
                    &format!("ata_race_{replica}"),
                    &contested,
                    side.tenant,
                    false,
                )
            }
        };
        let assign = {
            let request = request.clone();
            move |replica, mut conn: PoolConnection<Postgres>| {
                let new = request(replica);
                async move { registry::create_audience_tenant_assignment(&mut *conn, &new).await }
            }
        };
        let outcomes = replicas.race(assign).await;
        let mut expected = Vec::new();
        for side_index in 0..2 {
            let mine: Vec<usize> = (0..REPLICAS).filter(|r| r % 2 == side_index).collect();
            let won: Vec<usize> = mine
                .iter()
                .copied()
                .filter(|&r| outcomes[r].is_ok())
                .collect();
            assert_eq!(
                won.len(),
                1,
                "round {round}, tenant {side_index}: {outcomes:?}"
            );
            let row = outcomes[won[0]].as_ref().unwrap().clone();
            assert_eq!(row, stored_assignment(&request(won[0])));
            expected.push(row);
        }
        for (replica, outcome) in outcomes.into_iter().enumerate() {
            if outcome.is_err() {
                assert_eq!(
                    already_exists(outcome),
                    ASSIGNMENT_PAIR_KEY,
                    "round {round}"
                );
                assert_not_found(
                    registry::get_audience_tenant_assignment(&pool, &format!("ata_race_{replica}"))
                        .await,
                );
            }
        }
        expected.sort_by(|left, right| left.id.cmp(&right.id));
        assert_eq!(
            registry::list_audience_tenant_assignments(&pool, all)
                .await
                .unwrap(),
            expected
        );
        db.drop(std::iter::once(pool).chain(replicas.into_pools()))
            .await;
    }
}

/// What the holder and the waiters register in
/// `a43_neg_blocked_registrations_follow_the_holder_commit_or_rollback`.
#[derive(Debug, Clone, Copy)]
enum Contested {
    /// A resource server of [`CONTESTED_AUDIENCE`].
    Audience,
    /// An assignment of the committed resource server `rs_contested` to
    /// tenant A.
    Assignment,
}

/// One registration's outcome: the stored row's ID, or the refusal.
type Outcome = Result<String, RegistryError>;

impl Contested {
    /// The registration of `n` (`n` = 100 for the holder): its row's ID.
    fn id(self, n: usize) -> String {
        match self {
            Contested::Audience => format!("rs_blk_{n}"),
            Contested::Assignment => format!("ata_blk_{n}"),
        }
    }

    async fn register(self, conn: &mut sqlx::PgConnection, n: usize) -> Outcome {
        match self {
            Contested::Audience => {
                registry::create_resource_server(conn, &server(&self.id(n), CONTESTED_AUDIENCE))
                    .await
                    .map(|row| row.id)
            }
            Contested::Assignment => registry::create_audience_tenant_assignment(
                conn,
                &assignment(&self.id(n), "rs_contested", A.tenant, n.is_multiple_of(2)),
            )
            .await
            .map(|row| row.id),
        }
    }

    fn key(self) -> &'static str {
        match self {
            Contested::Audience => AUDIENCE_KEY,
            Contested::Assignment => ASSIGNMENT_PAIR_KEY,
        }
    }

    /// The IDs of the rows of this kind, in ID order.
    async fn stored(self, pool: &PgPool) -> Vec<String> {
        let all = Page::first(MAX_PAGE_SIZE);
        match self {
            Contested::Audience => registry::list_resource_servers(pool, all)
                .await
                .unwrap()
                .into_iter()
                .filter(|rs| rs.audience == CONTESTED_AUDIENCE)
                .map(|rs| rs.id)
                .collect(),
            Contested::Assignment => registry::list_audience_tenant_assignments(pool, all)
                .await
                .unwrap()
                .into_iter()
                .map(|a| a.id)
                .collect(),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a43_neg_blocked_registrations_follow_the_holder_commit_or_rollback() {
    const WAITERS: usize = 4;
    const HOLDER: usize = 100;
    for contested in [Contested::Audience, Contested::Assignment] {
        for commit in [true, false] {
            let (db, pool) = tenants().await;
            if let Contested::Assignment = contested {
                registry::create_resource_server(
                    &pool,
                    &server("rs_contested", CONTESTED_AUDIENCE),
                )
                .await
                .unwrap();
            }
            let holder_pool = db.pool_with_max_connections(1).await;
            let mut holder_conn = holder_pool.acquire().await.unwrap();
            let holder_pid = rep::backend_pid(&mut holder_conn).await;
            let waiters = Replicas::start(&db, WAITERS).await;
            let pids = waiters.backend_pids().await;

            let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
            assert_eq!(
                contested.register(&mut tx, HOLDER).await.unwrap(),
                contested.id(HOLDER)
            );
            // Set just before the holder ends: a waiter that finished
            // earlier reads `false`.
            let ending = Arc::new(AtomicBool::new(false));
            let observer = &pool;
            let release = {
                let ending = Arc::clone(&ending);
                async move {
                    rep::wait_until_blocked(observer, &pids, holder_pid).await;
                    ending.store(true, Ordering::SeqCst);
                    if commit {
                        tx.commit().await.unwrap();
                    } else {
                        tx.rollback().await.unwrap();
                    }
                }
            };
            let race = waiters.race({
                let ending = Arc::clone(&ending);
                move |replica, mut conn| {
                    let ending = Arc::clone(&ending);
                    async move {
                        let outcome = contested.register(&mut conn, replica).await;
                        (outcome, ending.load(Ordering::SeqCst))
                    }
                }
            });
            let (results, ()) = tokio::join!(race, release);
            drop(holder_conn);

            let label = format!("{contested:?}, commit {commit}");
            let mut outcomes = Vec::new();
            for (replica, (outcome, after_holder)) in results.into_iter().enumerate() {
                assert!(
                    after_holder,
                    "{label}: replica {replica} finished before the holder ended: {outcome:?}"
                );
                outcomes.push(outcome);
            }
            let winners: Vec<usize> = (0..WAITERS).filter(|&r| outcomes[r].is_ok()).collect();
            let owner = if commit {
                assert_eq!(winners, Vec::<usize>::new(), "{label}: {outcomes:?}");
                contested.id(HOLDER)
            } else {
                assert_eq!(winners.len(), 1, "{label}: {outcomes:?}");
                contested.id(winners[0])
            };
            assert_eq!(contested.stored(&pool).await, [owner], "{label}");
            for (replica, outcome) in outcomes.into_iter().enumerate() {
                if !winners.contains(&replica) {
                    assert_eq!(already_exists(outcome), contested.key(), "{label}");
                }
            }
            let pools = [pool, holder_pool].into_iter().chain(waiters.into_pools());
            db.drop(pools).await;
        }
    }
}
