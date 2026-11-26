//! A49: identical operator labels in two tenants, and create, export and
//! reapply. Expected: distinct generated IDs, a deterministic authorized
//! mapping, no global-name collision or probe; an exchange that names
//! objects instead of their generated IDs is rejected (tasks §8; T10.2,
//! T10.5, T14.8, T21.1; identity-registry IR-020 to IR-024).
//!
//! **A49 partial: the generated-ID half of the M1a scope ("IDs, export,
//! reapply") only; A49's M1a stage stays `planned`, with no stamp.** These
//! tests are registered on A49's planned M1a stage, so they are no
//! evidence for it: the reporter lists their results as not counted, and
//! they are no claim. They run through the audited workload writes of
//! `skyoauth_service::admin` (`create_tenant`, `create_workload_principal`,
//! `update_principal`, `disable_principal`, `create_resource_server`,
//! `create_audience_tenant_assignment`, `create_resource_server_checker`,
//! `create_resource_action`), which take every created ID, and every audit
//! event ID, from the `IdGenerator` the request carries, and read back
//! through the typed registry API (`skyoauth_service::persistence::registry`),
//! against a real PostgreSQL, one fresh database per test, with no SQL of
//! their own. The fixture is local ([`fixture`]): a bootstrapped instance,
//! whose first operator is the instance `security_admin`; two tenants
//! created through `admin::create_tenant`; and one `trust_admin` per tenant
//! (operators written with `registry::test_support`, the setup the
//! scenarios crate may use). Every write takes its IDs from one
//! [`LoggedIds`]: the deterministic `ids::test_support::SequentialIds`
//! (seed [`SEED`]), which records each ID it gives with its kind, so a test
//! can tell an ID the generator gave from one a write made up. No test
//! parses an ID: they compare IDs byte for byte with each other, with the
//! request's labels and with the generator's record (IR-024).
//!
//! - **Positive, identical labels.** A workload principal named
//!   [`LABEL`] in each tenant, each by its own tenant's `trust_admin`: both
//!   are created, with different IDs the generator gave, neither equal to
//!   the label or to a tenant ID; each reads back under its own tenant and
//!   ID only (the other tenant gets `NotFound` for it, as for the label, a
//!   case variant or a padded copy of the ID). A second principal named
//!   [`LABEL`] in either tenant is refused with
//!   `AlreadyExists { constraint: "principal_tenant_id_kind_name_key" }`
//!   and writes nothing, the other tenant's principal included (tenant-local
//!   uniqueness, IR-021); another name in the same tenant is the control
//!   (`a49_pos_identical_labels_in_two_tenants_get_distinct_generated_ids`).
//! - **Positive, every kind.** Through one generator: two tenants, a
//!   principal named [`LABEL`] in each, a resource server, its assignment
//!   to each tenant, a checker and an action. The 9 row IDs and the 9 audit
//!   event IDs are pairwise distinct, none contains another, each is one
//!   the generator gave for that kind, and the generator gave no other;
//!   none equals or contains a caller-supplied value (a tenant name or
//!   secret namespace, the principal name, the audience, the resource
//!   server name, the checker's derived key identity, the action name, an
//!   operator key). The audience, the names, the key identity and the action
//!   name are not IDs: a read by any of them is `NotFound`, a read by the
//!   generated ID returns the row
//!   (`a49_pos_every_created_object_takes_its_id_from_the_generator`).
//! - **Negative, cross-tenant probe.** Tenant A's `trust_admin` naming
//!   tenant B's principal under tenant A (update and disable, at B's
//!   revision and another) gets exactly the `NotFound` of an ID that never
//!   existed. Naming tenant B, or a tenant that does not exist, as A's
//!   credential is the one `Unauthorized`, the same for B's principal, a
//!   missing one and a create. Nothing is written and no ID is generated;
//!   the same calls by each tenant's own `trust_admin` apply, the control
//!   (`a49_neg_other_tenants_principal_id_is_not_found_as_a_missing_one`).
//! - **Negative, no global-name collision or probe.** A name that exists
//!   only in the other tenant never blocks a create, in either order; a
//!   refused same-tenant duplicate of a name the other tenant also holds
//!   is the very error (`Debug` and `Display`) of a duplicate of a name no
//!   other tenant holds, and names no tenant, principal or label
//!   (`a49_neg_a_name_in_another_tenant_neither_collides_nor_shows`).
//! - **Negative, refused creates.** A create refused before it writes (an
//!   instance `security_admin`, the other tenant's `trust_admin` and an
//!   unknown key asking for a principal create; a `trust_admin` asking for
//!   a tenant or resource server create) generates no ID: the generator's
//!   record is unchanged, and the next create gets the IDs a twin generator
//!   gives next (`a49_neg_a_refused_create_consumes_no_id`).
//!
//! # Not covered / tracked
//!
//! - Export and reapply: determinism of the export, the authorized mapping
//!   of an import manifest's references to generated IDs and same-instance
//!   reconciliation (T10.5; T14.8, its import manifest). Neither is built,
//!   so nothing here tests or assumes either; they stay on A49's planned M1a
//!   stage.
//! - The exchange rejecting names instead of generated IDs (T21.1's
//!   generated selectors; A49's M2 stage, "exchange"). Not built.
//! - Tenant-name uniqueness: whether two tenants may share a name is an open
//!   owner question; the tenants here have different names, and no test
//!   depends on the answer.
//! - Service principals and grants: a service principal is created with its
//!   service identity (slice S3b, not built), and grants likewise.
//! - The production generator: it needs an approved CSPRNG dependency
//!   (`skyoauth_service::ids`, "Generators"). These tests use
//!   `SequentialIds`, so distinct IDs here show that the write path takes
//!   every ID from the generator and derives none from a label, not that the
//!   generator's output is random or unguessable. The ID format is the ID
//!   module's own unit tests' to check.
//! - A refused duplicate uses up the ID it generated (`skyoauth_service::admin`,
//!   "Errors and rollback"); no test asserts either way about that.
//! - The request layer (slice S4): no endpoint calls these writes yet, so
//!   the refusals here are typed errors, not wire responses. Only reads
//!   have a route: A49's cross-tenant probe of the four operation reads
//!   through the admin read router, with an already-verified peer (no mTLS
//!   leg), is in [`super::a49_wire`].

use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::{
    admin::{
        self, ActionCreate, AdminRequest, AdminWriteError, AssignmentCreate, Audited,
        CheckerCreate, PrincipalCreate, ResourceServerCreate, TenantCreate,
    },
    ids::{IdError, IdGenerator, IdKind, test_support::SequentialIds},
    persistence::{
        PgPool,
        registry::{
            self, AdminRole, BootstrapRequest, ChainVerdict, MAX_PAGE_SIZE, NewAdminCredential,
            NewAdminIdentity, NewAdminRoleBinding, Page, Principal, PrincipalPatch, Profile,
            RegistryError, Status, Tenant, bootstrap_instance, verify_audit_chain,
        },
    },
};
use sqlx::{Postgres, Transaction};

/// The identical operator label: the name of a workload principal in each
/// tenant.
const LABEL: &str = "deploy-bot";
/// The seed of the generator of every write here.
const SEED: u64 = 49;
/// The key of the bootstrapped first operator, the instance
/// `security_admin` that performs the instance writes.
const SEC_KEY: &str = "spki-sha256:a49-first";
/// The key of tenant A's `trust_admin`.
const TRUST_A_KEY: &str = "spki-sha256:a49-trust-a";
/// The key of tenant B's `trust_admin`.
const TRUST_B_KEY: &str = "spki-sha256:a49-trust-b";
/// No credential has it.
const UNKNOWN_KEY: &str = "spki-sha256:a49-unknown";
/// The expected `Debug` of a same-tenant duplicate name.
const DUPLICATE: &str =
    "Registry(AlreadyExists { constraint: \"principal_tenant_id_kind_name_key\" })";
const T0: u64 = 1_790_000_000_000_000;

fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

/// The generator of every write here: [`SequentialIds`] with [`SEED`],
/// recording each ID it gives with its kind.
struct LoggedIds {
    inner: SequentialIds,
    given: Mutex<Vec<(IdKind, String)>>,
}

impl LoggedIds {
    fn new() -> Self {
        Self {
            inner: SequentialIds::with_seed(SEED),
            given: Mutex::new(Vec::new()),
        }
    }

    /// Every ID given so far, in order, with its kind.
    fn given(&self) -> Vec<(IdKind, String)> {
        self.given.lock().unwrap().clone()
    }

    /// How many IDs of `kind` were given so far.
    fn count(&self, kind: IdKind) -> usize {
        self.given().iter().filter(|(k, _)| *k == kind).count()
    }

    /// Whether `id` is an ID this generator gave for `kind`, compared byte
    /// for byte.
    fn gave(&self, kind: IdKind, id: &str) -> bool {
        self.given()
            .iter()
            .any(|(k, given)| *k == kind && given == id)
    }
}

impl IdGenerator for LoggedIds {
    fn new_id(&self, kind: IdKind) -> Result<String, IdError> {
        let id = self.inner.new_id(kind)?;
        self.given.lock().unwrap().push((kind, id.clone()));
        Ok(id)
    }
}

/// A bootstrapped instance, tenants A and B created through
/// `admin::create_tenant`, and each tenant's `trust_admin`.
struct Fixture {
    db: TestDb,
    pool: PgPool,
    ids: LoggedIds,
    ten_a: Audited<Tenant>,
    ten_b: Audited<Tenant>,
}

impl Fixture {
    fn request<'a>(&'a self, key: &'a str) -> AdminRequest<'a> {
        AdminRequest {
            public_identity: key,
            ids: &self.ids,
            now: at(10),
        }
    }

    fn a(&self) -> &str {
        &self.ten_a.row.id
    }

    fn b(&self) -> &str {
        &self.ten_b.row.id
    }

    /// A workload principal named `name` in `tenant`, created by `key`.
    async fn create_principal(
        &self,
        key: &str,
        tenant: &str,
        name: &str,
    ) -> Result<Audited<Principal>, AdminWriteError> {
        let request = self.request(key);
        let new = PrincipalCreate {
            name: name.into(),
            status: Status::Enabled,
        };
        committed(&self.pool, async |tx| {
            admin::create_workload_principal(tx, &request, tenant, &new).await
        })
        .await
    }

    async fn drop(self) {
        self.db.drop([self.pool]).await;
    }
}

/// Runs `steps` in a transaction of its own and commits it, also after an
/// error, so a refusal shows that the write's savepoint left nothing.
async fn committed<T>(
    pool: &PgPool,
    steps: impl AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<T, AdminWriteError>,
) -> Result<T, AdminWriteError> {
    let mut transaction = pool.begin().await.unwrap();
    let result = steps(&mut transaction).await;
    transaction.commit().await.unwrap();
    result
}

/// One enabled operator `admin` with the credential `crd_<admin>` (`key`)
/// and one enabled binding of `role` in `tenant`.
async fn operator(pool: &PgPool, admin: &str, key: &str, role: AdminRole, tenant: &str) {
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
    registry::test_support::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: format!("rb_{admin}"),
            admin_id: admin.into(),
            role,
            tenant_id: Some(tenant.into()),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// The bootstrapped instance (first operator [`SEC_KEY`], an instance
/// `security_admin`); tenants "Tenant A" and "Tenant B" created through
/// `admin::create_tenant` with the generator's IDs; and the `trust_admin`
/// of each, [`TRUST_A_KEY`] and [`TRUST_B_KEY`], bound to those IDs.
async fn fixture() -> Fixture {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: "019a9f3c-5b2e-7c41-9d8e-0123456789ab",
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: SEC_KEY,
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
    let ids = LoggedIds::new();
    let mut tenants = Vec::new();
    for (name, namespace) in [("Tenant A", "ns_a"), ("Tenant B", "ns_b")] {
        let request = AdminRequest {
            public_identity: SEC_KEY,
            ids: &ids,
            now: at(1),
        };
        let new = TenantCreate {
            name: name.into(),
            status: Status::Enabled,
        };
        let tenant = committed(&pool, async |tx| {
            admin::create_tenant(tx, &request, namespace, &new).await
        })
        .await
        .unwrap();
        tenants.push(tenant);
    }
    let ten_b = tenants.pop().unwrap();
    let ten_a = tenants.pop().unwrap();
    let trust = AdminRole::TrustAdmin;
    operator(&pool, "adm_trust_a", TRUST_A_KEY, trust, &ten_a.row.id).await;
    operator(&pool, "adm_trust_b", TRUST_B_KEY, trust, &ten_b.row.id).await;
    Fixture {
        db,
        pool,
        ids,
        ten_a,
        ten_b,
    }
}

/// Every row the writes here may change, as text, read through the typed
/// registry API: the tenants, each tenant's principals, the resource
/// servers, assignments, checkers and actions, and the audit chain's last
/// sequence (so any appended event shows).
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let all = || Page::first(MAX_PAGE_SIZE);
    let tenants = registry::list_tenants(pool, all()).await.unwrap();
    let mut rows = vec![format!("{tenants:?}")];
    for tenant in &tenants {
        let principals = registry::list_principals(pool, &tenant.id, all())
            .await
            .unwrap();
        rows.push(format!("{principals:?}"));
    }
    rows.push(format!(
        "{:?}",
        registry::list_resource_servers(pool, all()).await.unwrap()
    ));
    rows.push(format!(
        "{:?}",
        registry::list_audience_tenant_assignments(pool, all())
            .await
            .unwrap()
    ));
    rows.push(format!(
        "{:?}",
        registry::list_resource_server_checkers(pool, all())
            .await
            .unwrap()
    ));
    rows.push(format!(
        "{:?}",
        registry::list_resource_actions(pool, all()).await.unwrap()
    ));
    let mut connection = pool.acquire().await.unwrap();
    let verdict = verify_audit_chain(&mut connection).await.unwrap();
    assert!(
        matches!(verdict, ChainVerdict::Intact { .. }),
        "{verdict:?}"
    );
    rows.push(format!("{verdict:?}"));
    rows
}

/// The principals of `tenant`, by ID.
async fn principals(pool: &PgPool, tenant: &str) -> Vec<Principal> {
    registry::list_principals(pool, tenant, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap()
}

#[track_caller]
fn refused<T: std::fmt::Debug>(result: Result<T, AdminWriteError>, expected: &str) -> String {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => {
            assert_eq!(format!("{err:?}"), expected);
            err.to_string()
        }
    }
}

#[track_caller]
fn not_found<T: std::fmt::Debug>(result: Result<T, RegistryError>, what: &str) {
    assert!(
        matches!(result, Err(RegistryError::NotFound)),
        "{what}: {result:?}"
    );
}

/// The DER `SubjectPublicKeyInfo` of the Ed25519 key of `seed` (RFC 8410:
/// the algorithm identifier with parameters absent, then the 32-byte key).
fn ed25519_spki(seed: u8) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(
        &SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    );
    der
}

/// The same label in two tenants: two principals with distinct generated
/// IDs, each found only under its own tenant and ID; a same-tenant
/// duplicate is refused and writes nothing.
#[tokio::test]
async fn a49_pos_identical_labels_in_two_tenants_get_distinct_generated_ids() {
    let f = fixture().await;
    let a = f.create_principal(TRUST_A_KEY, f.a(), LABEL).await.unwrap();
    let b = f.create_principal(TRUST_B_KEY, f.b(), LABEL).await.unwrap();
    for (principal, tenant) in [(&a.row, f.a()), (&b.row, f.b())] {
        assert_eq!(principal.name, LABEL);
        assert_eq!(principal.tenant_id, tenant);
        assert_eq!(principal.revision, 1);
        assert!(
            f.ids.gave(IdKind::WorkloadPrincipal, &principal.id),
            "{principal:?}"
        );
        for label in [LABEL, f.a(), f.b(), "Tenant A", "Tenant B"] {
            assert_ne!(principal.id, label);
        }
    }
    assert_ne!(a.row.id, b.row.id);
    assert_eq!(a.event.object_id, a.row.id);
    assert_eq!(b.event.object_id, b.row.id);

    // Each is found under its own tenant and ID, and nowhere else: not
    // under the other tenant, not by its name, not by a case variant or a
    // padded copy of its ID.
    for (own, other, principal) in [(f.a(), f.b(), &a.row), (f.b(), f.a(), &b.row)] {
        let read = registry::get_principal(&f.pool, own, &principal.id).await;
        assert_eq!(read.unwrap(), *principal);
        not_found(
            registry::get_principal(&f.pool, other, &principal.id).await,
            "the other tenant",
        );
        let upper = principal.id.to_ascii_uppercase();
        assert_ne!(upper, principal.id);
        let variants = [
            LABEL.to_owned(),
            upper,
            format!("{} ", principal.id),
            format!(" {}", principal.id),
        ];
        for variant in variants {
            not_found(
                registry::get_principal(&f.pool, own, &variant).await,
                &variant,
            );
        }
        assert_eq!(
            principals(&f.pool, own).await,
            std::slice::from_ref(principal)
        );
    }

    // A second principal named LABEL in either tenant is refused and writes
    // nothing; the other tenant's principal is untouched.
    let before = snapshot(&f.pool).await;
    for (key, tenant) in [(TRUST_A_KEY, f.a()), (TRUST_B_KEY, f.b())] {
        refused(f.create_principal(key, tenant, LABEL).await, DUPLICATE);
    }
    assert_eq!(snapshot(&f.pool).await, before);
    assert_eq!(
        principals(&f.pool, f.a()).await,
        std::slice::from_ref(&a.row)
    );
    assert_eq!(
        principals(&f.pool, f.b()).await,
        std::slice::from_ref(&b.row)
    );

    // The control: another name in the same tenant is created.
    let other = f
        .create_principal(TRUST_A_KEY, f.a(), "deploy-bot-2")
        .await
        .unwrap();
    assert!(f.ids.gave(IdKind::WorkloadPrincipal, &other.row.id));
    assert_ne!(other.row.id, a.row.id);
    assert_ne!(other.row.id, b.row.id);
    f.drop().await;
}

/// Every kind of object, and every audit event, takes its ID from the
/// generator, and none from a caller-supplied value.
#[tokio::test]
async fn a49_pos_every_created_object_takes_its_id_from_the_generator() {
    let f = fixture().await;
    let sec = f.request(SEC_KEY);
    let audience = "https://api.a49.example";
    let server_name = "A49 API";
    let action_name = "projects.read";
    let principal_a = f.create_principal(TRUST_A_KEY, f.a(), LABEL).await.unwrap();
    let principal_b = f.create_principal(TRUST_B_KEY, f.b(), LABEL).await.unwrap();
    let server = committed(&f.pool, async |tx| {
        let new = ResourceServerCreate {
            audience: audience.into(),
            name: server_name.into(),
            allowed_profiles: vec![Profile::Wif],
            scopes: vec!["projects:read".into()],
            constraint_versions: vec![],
            status: Status::Enabled,
        };
        admin::create_resource_server(tx, &sec, &new).await
    })
    .await
    .unwrap();
    let mut assignments = Vec::new();
    for tenant in [f.a(), f.b()] {
        let new = AssignmentCreate {
            resource_server_id: server.row.id.clone(),
            tenant_id: tenant.into(),
            allowed_profiles: vec![Profile::Wif],
            allowed_scopes: vec!["projects:read".into()],
            constraint_versions: vec![],
            status: Status::Enabled,
        };
        let assignment = committed(&f.pool, async |tx| {
            admin::create_audience_tenant_assignment(tx, &sec, &new).await
        })
        .await
        .unwrap();
        assert_eq!(assignment.row.tenant_id, tenant);
        assignments.push(assignment);
    }
    let checker = committed(&f.pool, async |tx| {
        let new = CheckerCreate {
            resource_server_id: server.row.id.clone(),
            public_key_der: ed25519_spki(0x49),
            status: Status::Enabled,
        };
        admin::create_resource_server_checker(tx, &sec, &new).await
    })
    .await
    .unwrap();
    let action = committed(&f.pool, async |tx| {
        let new = ActionCreate {
            resource_server_id: server.row.id.clone(),
            action_name: action_name.into(),
            required_scopes: vec!["projects:read".into()],
            accepted_profiles: vec![Profile::Wif],
            required_resource_dimensions: vec!["project".into()],
            live_check_required: false,
            status: Status::Enabled,
        };
        admin::create_resource_action(tx, &sec, &new).await
    })
    .await
    .unwrap();

    // (kind, row ID, its event) for each create, the fixture's tenants
    // included.
    let created = [
        (IdKind::Tenant, &f.ten_a.row.id, &f.ten_a.event),
        (IdKind::Tenant, &f.ten_b.row.id, &f.ten_b.event),
        (
            IdKind::WorkloadPrincipal,
            &principal_a.row.id,
            &principal_a.event,
        ),
        (
            IdKind::WorkloadPrincipal,
            &principal_b.row.id,
            &principal_b.event,
        ),
        (IdKind::ResourceServer, &server.row.id, &server.event),
        (
            IdKind::AudienceAssignment,
            &assignments[0].row.id,
            &assignments[0].event,
        ),
        (
            IdKind::AudienceAssignment,
            &assignments[1].row.id,
            &assignments[1].event,
        ),
        (IdKind::Checker, &checker.row.id, &checker.event),
        (IdKind::ResourceAction, &action.row.id, &action.event),
    ];
    let mut used = Vec::new();
    for (kind, id, event) in created {
        assert!(f.ids.gave(kind, id), "{kind:?} {id}");
        assert!(f.ids.gave(IdKind::AuditEvent, &event.id), "{event:?}");
        assert_eq!(event.object_id, *id);
        used.push(id.clone());
        used.push(event.id.clone());
    }
    // Pairwise distinct, none inside another, and exactly the IDs the
    // generator gave: no ID generated and dropped, none from elsewhere.
    let distinct: HashSet<&String> = used.iter().collect();
    assert_eq!(distinct.len(), 18);
    for x in &used {
        for y in &used {
            assert!(x == y || !x.contains(y.as_str()), "{x} contains {y}");
        }
    }
    let given: HashSet<String> = f.ids.given().into_iter().map(|(_, id)| id).collect();
    assert_eq!(given, used.iter().cloned().collect::<HashSet<_>>());

    // No ID equals or contains a caller-supplied value.
    let identity = checker.row.public_mtls_identity.as_str();
    let labels = [
        "Tenant A",
        "Tenant B",
        "ns_a",
        "ns_b",
        LABEL,
        audience,
        server_name,
        identity,
        action_name,
        SEC_KEY,
        TRUST_A_KEY,
        TRUST_B_KEY,
    ];
    for id in &used {
        for label in labels {
            assert!(!id.contains(label), "{id} contains {label}");
        }
    }

    // The values are not IDs: a read by one is `NotFound`; a read by the
    // generated ID returns the row (the control).
    let pool = &f.pool;
    let tenant = registry::get_tenant(pool, f.a()).await;
    assert_eq!(tenant.unwrap(), f.ten_a.row);
    not_found(registry::get_tenant(pool, "Tenant A").await, "tenant name");
    not_found(registry::get_tenant(pool, "ns_a").await, "namespace");
    let read = registry::get_principal(pool, f.a(), &principal_a.row.id).await;
    assert_eq!(read.unwrap(), principal_a.row);
    not_found(registry::get_principal(pool, f.a(), LABEL).await, "name");
    let read = registry::get_resource_server(pool, &server.row.id).await;
    assert_eq!(read.unwrap(), server.row);
    not_found(
        registry::get_resource_server(pool, audience).await,
        "audience",
    );
    not_found(
        registry::get_resource_server(pool, server_name).await,
        "name",
    );
    let read = registry::get_audience_tenant_assignment(pool, &assignments[0].row.id).await;
    assert_eq!(read.unwrap(), assignments[0].row);
    not_found(
        registry::get_audience_tenant_assignment(pool, audience).await,
        "audience",
    );
    let read = registry::get_resource_server_checker(pool, &checker.row.id).await;
    assert_eq!(read.unwrap(), checker.row);
    not_found(
        registry::get_resource_server_checker(pool, identity).await,
        "identity",
    );
    let read = registry::get_resource_action(pool, &action.row.id).await;
    assert_eq!(read.unwrap(), action.row);
    not_found(
        registry::get_resource_action(pool, action_name).await,
        "action name",
    );
    f.drop().await;
}

/// Tenant A's `trust_admin` learns nothing about tenant B's principal: it
/// is `NotFound` under A as a missing ID is, and naming B is the one
/// `Unauthorized` whether the target exists or not.
#[tokio::test]
async fn a49_neg_other_tenants_principal_id_is_not_found_as_a_missing_one() {
    let f = fixture().await;
    let a = f.create_principal(TRUST_A_KEY, f.a(), LABEL).await.unwrap();
    let b = f.create_principal(TRUST_B_KEY, f.b(), LABEL).await.unwrap();
    // An ID that never existed, from a generator of another seed, and a
    // tenant that does not exist.
    let other = SequentialIds::with_seed(SEED + 1);
    let missing = other.new_id(IdKind::WorkloadPrincipal).unwrap();
    let no_tenant = other.new_id(IdKind::Tenant).unwrap();
    for tenant in [f.a(), f.b()] {
        not_found(
            registry::get_principal(&f.pool, tenant, &missing).await,
            "missing",
        );
    }
    not_found(registry::get_tenant(&f.pool, &no_tenant).await, "no tenant");
    let patch = PrincipalPatch {
        name: Some("renamed".into()),
        status: None,
    };
    let request = f.request(TRUST_A_KEY);
    let before = snapshot(&f.pool).await;
    let given = f.ids.given();

    // Under A's own tenant: B's principal, at its revision 1 and at 2, is
    // the `NotFound` of the missing ID; never `StaleRevision`.
    let mut texts = Vec::new();
    for target in [b.row.id.as_str(), missing.as_str()] {
        for revision in [1, 2] {
            let update = committed(&f.pool, async |tx| {
                admin::update_principal(tx, &request, f.a(), target, revision, &patch).await
            })
            .await;
            texts.push(refused(update, "Registry(NotFound)"));
            let disable = committed(&f.pool, async |tx| {
                admin::disable_principal(tx, &request, f.a(), target, revision).await
            })
            .await;
            texts.push(refused(disable, "Registry(NotFound)"));
        }
    }
    assert!(texts.windows(2).all(|w| w[0] == w[1]), "{texts:?}");

    // Naming B, or a tenant that does not exist, is the one `Unauthorized`,
    // for B's principal, a missing one and a create.
    let mut texts = Vec::new();
    for tenant in [f.b(), no_tenant.as_str()] {
        for target in [b.row.id.as_str(), missing.as_str()] {
            let update = committed(&f.pool, async |tx| {
                admin::update_principal(tx, &request, tenant, target, 1, &patch).await
            })
            .await;
            texts.push(refused(update, "Unauthorized"));
            let disable = committed(&f.pool, async |tx| {
                admin::disable_principal(tx, &request, tenant, target, 1).await
            })
            .await;
            texts.push(refused(disable, "Unauthorized"));
        }
        let create = f.create_principal(TRUST_A_KEY, tenant, LABEL).await;
        texts.push(refused(create, "Unauthorized"));
    }
    assert!(texts.windows(2).all(|w| w[0] == w[1]), "{texts:?}");

    // Nothing written, no ID generated.
    assert_eq!(snapshot(&f.pool).await, before);
    assert_eq!(f.ids.given(), given);
    assert_eq!(
        registry::get_principal(&f.pool, f.b(), &b.row.id)
            .await
            .unwrap(),
        b.row
    );

    // The control: each tenant's own trust_admin applies the same calls.
    for (key, tenant, principal) in [(TRUST_A_KEY, f.a(), &a.row), (TRUST_B_KEY, f.b(), &b.row)] {
        let request = f.request(key);
        let updated = committed(&f.pool, async |tx| {
            admin::update_principal(tx, &request, tenant, &principal.id, 1, &patch).await
        })
        .await
        .unwrap();
        assert_eq!(updated.row.name, "renamed");
        assert_eq!(updated.row.revision, 2);
        let disabled = committed(&f.pool, async |tx| {
            admin::disable_principal(tx, &request, tenant, &principal.id, 2).await
        })
        .await
        .unwrap();
        assert_eq!(disabled.row.status, Status::Disabled);
        assert_eq!(disabled.event.tenant_id.as_deref(), Some(tenant));
    }
    f.drop().await;
}

/// A name in the other tenant never blocks a create, and a same-tenant
/// duplicate gives the same error whether or not another tenant holds the
/// name.
#[tokio::test]
async fn a49_neg_a_name_in_another_tenant_neither_collides_nor_shows() {
    let f = fixture().await;
    // "shared-a" first in A, then in B; "shared-b" first in B, then in A:
    // the other tenant's name blocks neither, in either order.
    let mut created = Vec::new();
    for (name, order) in [
        ("shared-a", [(TRUST_A_KEY, f.a()), (TRUST_B_KEY, f.b())]),
        ("shared-b", [(TRUST_B_KEY, f.b()), (TRUST_A_KEY, f.a())]),
    ] {
        for (key, tenant) in order {
            let done = f.create_principal(key, tenant, name).await.unwrap();
            assert_eq!(done.row.tenant_id, tenant);
            assert_eq!(done.row.name, name);
            created.push(done.row);
        }
    }
    // A name each tenant alone holds.
    for (key, tenant, name) in [
        (TRUST_A_KEY, f.a(), "solo-a"),
        (TRUST_B_KEY, f.b(), "solo-b"),
    ] {
        created.push(f.create_principal(key, tenant, name).await.unwrap().row);
    }
    let ids: HashSet<&str> = created.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids.len(), 6);

    // In each tenant: a duplicate of a name the other tenant also holds is
    // the very error of a duplicate of a name only this tenant holds.
    let before = snapshot(&f.pool).await;
    for (key, tenant, solo) in [
        (TRUST_A_KEY, f.a(), "solo-a"),
        (TRUST_B_KEY, f.b(), "solo-b"),
    ] {
        let mut texts = Vec::new();
        for name in ["shared-a", "shared-b", solo] {
            texts.push(refused(
                f.create_principal(key, tenant, name).await,
                DUPLICATE,
            ));
        }
        assert!(texts.windows(2).all(|w| w[0] == w[1]), "{texts:?}");
        // It names no tenant, principal or label.
        let debug = DUPLICATE.to_owned();
        for text in [&texts[0], &debug] {
            for value in [f.a(), f.b(), "shared-a", "shared-b", solo] {
                assert!(!text.contains(value), "{text} names {value}");
            }
            for principal in &created {
                assert!(!text.contains(&principal.id), "{text}");
            }
        }
    }
    assert_eq!(snapshot(&f.pool).await, before);
    f.drop().await;
}

/// A create refused before it writes generates no ID: the next create
/// gets the IDs a twin generator gives next.
#[tokio::test]
async fn a49_neg_a_refused_create_consumes_no_id() {
    let f = fixture().await;
    let before = snapshot(&f.pool).await;
    let given = f.ids.given();
    // A principal create by an instance security_admin, by the other
    // tenant's trust_admin and by an unknown key.
    for key in [SEC_KEY, TRUST_B_KEY, UNKNOWN_KEY] {
        refused(f.create_principal(key, f.a(), LABEL).await, "Unauthorized");
    }
    // A tenant and a resource server create by a trust_admin.
    let request = f.request(TRUST_A_KEY);
    let tenant = committed(&f.pool, async |tx| {
        let new = TenantCreate {
            name: "Tenant C".into(),
            status: Status::Enabled,
        };
        admin::create_tenant(tx, &request, "ns_c", &new).await
    })
    .await;
    refused(tenant, "Unauthorized");
    let server = committed(&f.pool, async |tx| {
        let new = ResourceServerCreate {
            audience: "https://api.a49.example".into(),
            name: "A49 API".into(),
            allowed_profiles: vec![Profile::Wif],
            scopes: vec!["projects:read".into()],
            constraint_versions: vec![],
            status: Status::Enabled,
        };
        admin::create_resource_server(tx, &request, &new).await
    })
    .await;
    refused(server, "Unauthorized");
    assert_eq!(f.ids.given(), given);
    assert_eq!(snapshot(&f.pool).await, before);

    // The next create gets the IDs a twin generator, advanced past the IDs
    // given so far, gives next.
    let twin = SequentialIds::with_seed(SEED);
    for kind in [IdKind::WorkloadPrincipal, IdKind::AuditEvent] {
        for _ in 0..f.ids.count(kind) {
            twin.new_id(kind).unwrap();
        }
    }
    let next = f.create_principal(TRUST_A_KEY, f.a(), LABEL).await.unwrap();
    assert_eq!(next.row.id, twin.new_id(IdKind::WorkloadPrincipal).unwrap());
    assert_eq!(next.event.id, twin.new_id(IdKind::AuditEvent).unwrap());
    f.drop().await;
}
