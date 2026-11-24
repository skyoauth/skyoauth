//! The audited, authorized workload writes of `skyoauth_service::admin` on
//! a real database: for every write, the one role and scope that may
//! perform it and every other that may not (another role, another tenant's
//! role, an instance `auditor`, a revoked credential, a disabled operator,
//! a disabled binding, an unknown credential: no role inherits another),
//! the expected revision, the generated IDs, the audit event (its action,
//! actor, object, tenant and revisions) and the chain, the action of an
//! update, the principal kinds and tenant scope, the isolation level, the
//! locked lookup, and that a refused or failed write, a generator that
//! gives no ID included, leaves nothing behind.
//!
//! Every helper here commits the outer transaction even when the call
//! returned an error, so each refusal also shows that the call's savepoint
//! left nothing behind.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database. They are
//! registry tests, not conformance scenarios.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use ed25519_dalek::SigningKey;
use serde_json::json;
use skyoauth_service::{
    admin::{
        self, ActionCreate, AdminRequest, AdminWriteError, AssignmentCreate, Audited,
        CheckerCreate, PrincipalCreate, ResourceServerCreate, TenantCreate,
    },
    ids::{IdError, IdGenerator, IdKind, test_support::SequentialIds},
    persistence::{
        self, PgPool,
        registry::{
            self, AdminRole, AudienceTenantAssignment, AudienceTenantAssignmentChanges, AuditActor,
            AuditEvent, BootstrapRequest, ChainVerdict, NewAdminCredential, NewAdminIdentity,
            NewAdminRoleBinding, NewAudienceTenantAssignment, NewPrincipal, NewResourceAction,
            NewResourceServer, NewResourceServerChecker, NewTenant, Principal, PrincipalKind,
            PrincipalPatch, Profile, RegistryError, ResourceAction, ResourceActionChanges,
            ResourceServer, ResourceServerChanges, ResourceServerChecker,
            ResourceServerCheckerChanges, Status, Tenant, TenantPatch, bootstrap_instance,
            verify_audit_chain,
        },
    },
};
use sqlx::{AssertSqlSafe, Connection, Postgres, Transaction};

const INSTANCE_ID: &str = "019a9f3c-5b2e-7c41-9d8e-0123456789ab";
const T0: u64 = 1_790_000_000_123_456;
const SEC: AdminRole = AdminRole::SecurityAdmin;
const TRUST: AdminRole = AdminRole::TrustAdmin;

/// `micros` after `T0`, with sub-microsecond digits, so a write truncates
/// it.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros) + Duration::from_nanos(789)
}

fn micros(micros: u64) -> i64 {
    i64::try_from(T0 + micros).unwrap()
}

/// The instance `security_admin` that may perform every instance write.
const KEY_SEC: &str = "key_sec";
/// The `trust_admin` of `ten_a`, who may perform the principal writes of
/// `ten_a`.
const KEY_TRUST_A: &str = "key_trust_a";
/// The `trust_admin` of `ten_b`.
const KEY_TRUST_B: &str = "key_trust_b";
/// No credential has it.
const KEY_UNKNOWN: &str = "key_unknown";

/// Every enrolled key but the two that authorize something here, and the
/// unknown one: an instance `auditor`; `ten_a`'s `auditor`, `client_admin`
/// and `provider_admin`; a revoked credential, a disabled operator and
/// disabled bindings, each of an operator that holds (or held) both
/// instance `security_admin` and `ten_a`'s `trust_admin`.
const NEITHER: [&str; 8] = [
    "key_aud_i",
    "key_aud_a",
    "key_client_a",
    "key_prov_a",
    "key_revoked",
    "key_disabled",
    "key_bind_off",
    KEY_UNKNOWN,
];

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

/// The operator `admin`, enabled, with the credential `crd_<admin>` of
/// `key` and one binding per entry of `bindings`, each `enabled` or not.
async fn operator(
    pool: &PgPool,
    admin: &str,
    key: &str,
    bindings: &[(AdminRole, Option<&str>)],
    bindings_enabled: bool,
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
    for (index, &(role, tenant_id)) in bindings.iter().enumerate() {
        registry::test_support::create_admin_role_binding(
            pool,
            &NewAdminRoleBinding {
                id: format!("rb_{admin}_{index}"),
                admin_id: admin.into(),
                role,
                tenant_id: tenant_id.map(Into::into),
                status: if bindings_enabled {
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

fn server(id: &str, audience: &str) -> NewResourceServer {
    NewResourceServer {
        id: id.into(),
        audience: audience.into(),
        name: format!("Server {id}"),
        allowed_profiles: vec![Profile::Wif],
        scopes: vec!["projects:read".into(), "projects:write".into()],
        constraint_versions: vec![json!(1)],
        status: Status::Enabled,
    }
}

fn assignment(id: &str, resource_server_id: &str, tenant_id: &str) -> NewAudienceTenantAssignment {
    NewAudienceTenantAssignment {
        id: id.into(),
        resource_server_id: resource_server_id.into(),
        tenant_id: tenant_id.into(),
        allowed_profiles: vec![Profile::Wif],
        allowed_scopes: vec!["projects:read".into()],
        constraint_versions: vec![json!(1)],
        status: Status::Enabled,
    }
}

fn action(id: &str, action_name: &str) -> NewResourceAction {
    NewResourceAction {
        id: id.into(),
        resource_server_id: "rs_1".into(),
        action_name: action_name.into(),
        required_scopes: vec!["projects:read".into()],
        accepted_profiles: vec![Profile::Wif],
        required_resource_dimensions: vec!["project".into()],
        live_check_required: true,
        status: Status::Enabled,
    }
}

/// A bootstrapped instance (`adm_first`, key `spki-sha256:first`, an
/// instance `security_admin`), and, written with the bare registry
/// writers:
///
/// - the tenants `ten_a` and `ten_b`;
/// - in `ten_a` the workload principals `wld_a` and `wld_a2`, the service
///   principal `svc_a` and the human principal `usr_a`; in `ten_b` the
///   workload principal `wld_b`;
/// - the resource servers `rs_1`, `rs_2` and `rs_3`; the assignments
///   `asgn_a` (`rs_1`, `ten_a`), `asgn_b` (`rs_1`, `ten_b`) and `asgn_a3`
///   (`rs_3`, `ten_a`); the checkers `chk_1` (`rs_1`, tenant set `ten_a`)
///   and `chk_2` (`rs_1`); the actions `act_1` and `act_2` of `rs_1`;
/// - the operators of [`KEY_SEC`], [`KEY_TRUST_A`], [`KEY_TRUST_B`] and
///   [`NEITHER`].
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
        registry::create_tenant(
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
    for (id, tenant_id, kind) in [
        ("wld_a", "ten_a", PrincipalKind::Workload),
        ("wld_a2", "ten_a", PrincipalKind::Workload),
        ("svc_a", "ten_a", PrincipalKind::Service),
        ("usr_a", "ten_a", PrincipalKind::Human),
        ("wld_b", "ten_b", PrincipalKind::Workload),
    ] {
        registry::create_principal(
            &pool,
            &NewPrincipal {
                id: id.into(),
                tenant_id: tenant_id.into(),
                kind,
                name: format!("principal-{id}"),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    for (id, audience) in [
        ("rs_1", "https://api1.example"),
        ("rs_2", "https://api2.example"),
        ("rs_3", "https://api3.example"),
    ] {
        registry::create_resource_server(&pool, &server(id, audience))
            .await
            .unwrap();
    }
    for (id, rs, tenant) in [
        ("asgn_a", "rs_1", "ten_a"),
        ("asgn_b", "rs_1", "ten_b"),
        ("asgn_a3", "rs_3", "ten_a"),
    ] {
        registry::create_audience_tenant_assignment(&pool, &assignment(id, rs, tenant))
            .await
            .unwrap();
    }
    for (id, identity) in [("chk_1", "spki-sha256:chk1"), ("chk_2", "spki-sha256:chk2")] {
        registry::test_support::create_resource_server_checker(
            &pool,
            &NewResourceServerChecker {
                id: id.into(),
                resource_server_id: "rs_1".into(),
                public_mtls_identity: identity.into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
    }
    registry::test_support::add_resource_server_checker_tenant(&pool, "chk_1", 1, "ten_a")
        .await
        .unwrap();
    for (id, name) in [("act_1", "projects.read"), ("act_2", "projects.list")] {
        registry::test_support::create_resource_action(&pool, &action(id, name))
            .await
            .unwrap();
    }
    let (ten_a, inst) = (Some("ten_a"), None);
    let both = [(SEC, inst), (TRUST, ten_a)];
    operator(&pool, "adm_sec", KEY_SEC, &[(SEC, inst)], true).await;
    operator(&pool, "adm_trust_a", KEY_TRUST_A, &[(TRUST, ten_a)], true).await;
    operator(
        &pool,
        "adm_trust_b",
        KEY_TRUST_B,
        &[(TRUST, Some("ten_b"))],
        true,
    )
    .await;
    operator(
        &pool,
        "adm_aud_i",
        "key_aud_i",
        &[(AdminRole::Auditor, inst)],
        true,
    )
    .await;
    operator(
        &pool,
        "adm_aud_a",
        "key_aud_a",
        &[(AdminRole::Auditor, ten_a)],
        true,
    )
    .await;
    operator(
        &pool,
        "adm_client_a",
        "key_client_a",
        &[(AdminRole::ClientAdmin, ten_a)],
        true,
    )
    .await;
    operator(
        &pool,
        "adm_prov_a",
        "key_prov_a",
        &[(AdminRole::ProviderAdmin, ten_a)],
        true,
    )
    .await;
    operator(&pool, "adm_revoked", "key_revoked", &both, true).await;
    registry::revoke_admin_credential(&pool, "crd_adm_revoked", at(1))
        .await
        .unwrap();
    operator(&pool, "adm_disabled", "key_disabled", &both, true).await;
    registry::disable_admin_identity(&pool, "adm_disabled")
        .await
        .unwrap();
    operator(&pool, "adm_bind_off", "key_bind_off", &both, false).await;
    (db, pool)
}

/// Each write of `skyoauth_service::admin`, with a fixed target and input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Write {
    CreateTenant,
    UpdateTenant,
    DisableTenant,
    CreatePrincipal,
    UpdatePrincipal,
    DisablePrincipal,
    CreateResourceServer,
    UpdateResourceServer,
    DisableResourceServer,
    CreateAssignment,
    UpdateAssignment,
    DisableAssignment,
    CreateChecker,
    UpdateChecker,
    DisableChecker,
    AddCheckerTenant,
    RemoveCheckerTenant,
    CreateAction,
    UpdateAction,
    DisableAction,
}

const WRITES: [Write; 20] = [
    Write::CreateTenant,
    Write::UpdateTenant,
    Write::DisableTenant,
    Write::CreatePrincipal,
    Write::UpdatePrincipal,
    Write::DisablePrincipal,
    Write::CreateResourceServer,
    Write::UpdateResourceServer,
    Write::DisableResourceServer,
    Write::CreateAssignment,
    Write::UpdateAssignment,
    Write::DisableAssignment,
    Write::CreateChecker,
    Write::UpdateChecker,
    Write::DisableChecker,
    Write::AddCheckerTenant,
    Write::RemoveCheckerTenant,
    Write::CreateAction,
    Write::UpdateAction,
    Write::DisableAction,
];

impl Write {
    /// Whether the write is a principal write (a `trust_admin` of `ten_a`)
    /// rather than an instance write (instance `security_admin`).
    fn is_principal(self) -> bool {
        matches!(
            self,
            Self::CreatePrincipal | Self::UpdatePrincipal | Self::DisablePrincipal
        )
    }

    /// The key that authorizes the write.
    fn key(self) -> &'static str {
        if self.is_principal() {
            KEY_TRUST_A
        } else {
            KEY_SEC
        }
    }

    /// The operator of [`Self::key`].
    fn admin(self) -> &'static str {
        if self.is_principal() {
            "adm_trust_a"
        } else {
            "adm_sec"
        }
    }

    /// The other key that a write's role in another scope or another role
    /// holds: `ten_b`'s `trust_admin` and instance `security_admin` for a
    /// principal write, `ten_a`'s `trust_admin` for an instance write.
    fn other_keys(self) -> &'static [&'static str] {
        if self.is_principal() {
            &[KEY_TRUST_B, KEY_SEC, "spki-sha256:first"]
        } else {
            &[KEY_TRUST_A, KEY_TRUST_B]
        }
    }

    /// The ID kind of a create, `None` for any other write.
    fn created_kind(self) -> Option<IdKind> {
        match self {
            Self::CreateTenant => Some(IdKind::Tenant),
            Self::CreatePrincipal => Some(IdKind::WorkloadPrincipal),
            Self::CreateResourceServer => Some(IdKind::ResourceServer),
            Self::CreateAssignment => Some(IdKind::AudienceAssignment),
            Self::CreateChecker => Some(IdKind::Checker),
            Self::CreateAction => Some(IdKind::ResourceAction),
            _ => None,
        }
    }

    /// The fixed target of any other write.
    fn target(self) -> &'static str {
        match self {
            Self::UpdateTenant => "ten_a",
            Self::DisableTenant => "ten_b",
            Self::UpdatePrincipal => "wld_a",
            Self::DisablePrincipal => "wld_a2",
            Self::UpdateResourceServer => "rs_1",
            Self::DisableResourceServer => "rs_3",
            Self::UpdateAssignment => "asgn_a",
            Self::DisableAssignment => "asgn_b",
            Self::UpdateChecker | Self::AddCheckerTenant | Self::RemoveCheckerTenant => "chk_1",
            Self::DisableChecker => "chk_2",
            Self::UpdateAction => "act_1",
            Self::DisableAction => "act_2",
            create => panic!("{create:?} has no target"),
        }
    }

    /// The action of the write's audit event.
    fn action(self) -> &'static str {
        match self {
            Self::CreateTenant => "tenant.create",
            Self::UpdateTenant => "tenant.update",
            Self::DisableTenant => "tenant.disable",
            Self::CreatePrincipal => "principal.create",
            Self::UpdatePrincipal => "principal.update",
            Self::DisablePrincipal => "principal.disable",
            Self::CreateResourceServer => "resource_server.create",
            Self::UpdateResourceServer => "resource_server.update",
            Self::DisableResourceServer => "resource_server.disable",
            Self::CreateAssignment => "audience_tenant_assignment.create",
            Self::UpdateAssignment => "audience_tenant_assignment.update",
            Self::DisableAssignment => "audience_tenant_assignment.disable",
            Self::CreateChecker => "resource_server_checker.create",
            Self::UpdateChecker | Self::AddCheckerTenant | Self::RemoveCheckerTenant => {
                "resource_server_checker.update"
            }
            Self::DisableChecker => "resource_server_checker.disable",
            Self::CreateAction => "resource_action.create",
            Self::UpdateAction => "resource_action.update",
            Self::DisableAction => "resource_action.disable",
        }
    }

    /// The event's tenant: the principal's for a principal write, none for
    /// an instance write.
    fn event_tenant(self) -> Option<&'static str> {
        self.is_principal().then_some("ten_a")
    }
}

/// The ID and revision of a written row.
trait Row {
    fn id(&self) -> &str;
    fn revision(&self) -> i64;
}

macro_rules! row {
    ($($type:ty),+) => {$(
        impl Row for $type {
            fn id(&self) -> &str {
                &self.id
            }
            fn revision(&self) -> i64 {
                self.revision
            }
        }
    )+};
}

row!(
    Tenant,
    Principal,
    ResourceServer,
    AudienceTenantAssignment,
    ResourceServerChecker,
    ResourceAction
);

/// What a successful write returned.
#[derive(Debug)]
struct Done {
    id: String,
    revision: i64,
    event: AuditEvent,
}

fn done<T: Row>(audited: Audited<T>) -> Done {
    Done {
        id: audited.row.id().into(),
        revision: audited.row.revision(),
        event: audited.event,
    }
}

/// The expected revision a call passes: the target's current one, or one
/// that is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Revision {
    Current,
    Stale,
}

/// The current revision of the target of `write`.
async fn current_revision(pool: &PgPool, write: Write) -> i64 {
    let id = write.target();
    match write {
        Write::UpdateTenant | Write::DisableTenant => {
            registry::get_tenant(pool, id).await.unwrap().revision
        }
        Write::UpdatePrincipal | Write::DisablePrincipal => {
            registry::get_principal(pool, "ten_a", id)
                .await
                .unwrap()
                .revision
        }
        Write::UpdateResourceServer | Write::DisableResourceServer => {
            registry::get_resource_server(pool, id)
                .await
                .unwrap()
                .revision
        }
        Write::UpdateAssignment | Write::DisableAssignment => {
            registry::get_audience_tenant_assignment(pool, id)
                .await
                .unwrap()
                .revision
        }
        Write::UpdateChecker
        | Write::DisableChecker
        | Write::AddCheckerTenant
        | Write::RemoveCheckerTenant => {
            registry::get_resource_server_checker(pool, id)
                .await
                .unwrap()
                .revision
        }
        Write::UpdateAction | Write::DisableAction => {
            registry::get_resource_action(pool, id)
                .await
                .unwrap()
                .revision
        }
        create => panic!("{create:?} has no target"),
    }
}

/// Runs `write` by `key` with the generator `ids`, in a transaction it
/// commits either way.
async fn run(
    pool: &PgPool,
    ids: &dyn IdGenerator,
    write: Write,
    key: &str,
    revision: Revision,
) -> Result<Done, AdminWriteError> {
    let expected = if write.created_kind().is_some() {
        0
    } else {
        let current = current_revision(pool, write).await;
        match revision {
            Revision::Current => current,
            Revision::Stale => current - 1,
        }
    };
    let mut transaction = pool.begin().await.unwrap();
    let result = call(&mut transaction, ids, write, key, expected).await;
    transaction.commit().await.unwrap();
    result
}

/// `write` by `key` at `expected` in `transaction`.
async fn call(
    transaction: &mut Transaction<'_, Postgres>,
    ids: &dyn IdGenerator,
    write: Write,
    key: &str,
    expected: i64,
) -> Result<Done, AdminWriteError> {
    let request = AdminRequest {
        public_identity: key,
        ids,
        now: at(5),
    };
    let request = &request;
    let tx = transaction;
    let id = || write.target();
    Ok(match write {
        Write::CreateTenant => done(
            admin::create_tenant(
                tx,
                request,
                "ns_created",
                &TenantCreate {
                    name: "Tenant created".into(),
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::UpdateTenant => done(
            admin::update_tenant(
                tx,
                request,
                id(),
                expected,
                &TenantPatch {
                    name: Some("Tenant A renamed".into()),
                    status: None,
                },
            )
            .await?,
        ),
        Write::DisableTenant => done(admin::disable_tenant(tx, request, id(), expected).await?),
        Write::CreatePrincipal => done(
            admin::create_workload_principal(
                tx,
                request,
                "ten_a",
                &PrincipalCreate {
                    name: "wld-created".into(),
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::UpdatePrincipal => done(
            admin::update_principal(
                tx,
                request,
                "ten_a",
                id(),
                expected,
                &PrincipalPatch {
                    name: Some("wld-renamed".into()),
                    status: None,
                },
            )
            .await?,
        ),
        Write::DisablePrincipal => {
            done(admin::disable_principal(tx, request, "ten_a", id(), expected).await?)
        }
        Write::CreateResourceServer => done(
            admin::create_resource_server(
                tx,
                request,
                &ResourceServerCreate {
                    audience: "https://created.example".into(),
                    name: "Created".into(),
                    allowed_profiles: vec![Profile::Wif],
                    scopes: vec!["projects:read".into()],
                    constraint_versions: vec![],
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::UpdateResourceServer => done(
            admin::update_resource_server(
                tx,
                request,
                id(),
                expected,
                &ResourceServerChanges {
                    name: "Server renamed".into(),
                    allowed_profiles: vec![Profile::Wif],
                    scopes: vec!["projects:read".into(), "projects:write".into()],
                    constraint_versions: vec![json!(1)],
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::DisableResourceServer => {
            done(admin::disable_resource_server(tx, request, id(), expected).await?)
        }
        Write::CreateAssignment => done(
            admin::create_audience_tenant_assignment(
                tx,
                request,
                &AssignmentCreate {
                    resource_server_id: "rs_2".into(),
                    tenant_id: "ten_a".into(),
                    allowed_profiles: vec![Profile::Wif],
                    allowed_scopes: vec!["projects:read".into()],
                    constraint_versions: vec![],
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::UpdateAssignment => done(
            admin::update_audience_tenant_assignment(
                tx,
                request,
                id(),
                expected,
                &AudienceTenantAssignmentChanges {
                    allowed_profiles: vec![Profile::Wif],
                    allowed_scopes: vec!["projects:read".into(), "projects:write".into()],
                    constraint_versions: vec![json!(1)],
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::DisableAssignment => {
            done(admin::disable_audience_tenant_assignment(tx, request, id(), expected).await?)
        }
        Write::CreateChecker => done(
            admin::create_resource_server_checker(
                tx,
                request,
                &CheckerCreate {
                    resource_server_id: "rs_1".into(),
                    public_mtls_identity: "spki-sha256:created".into(),
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::UpdateChecker => done(
            admin::update_resource_server_checker(
                tx,
                request,
                id(),
                expected,
                &ResourceServerCheckerChanges {
                    public_mtls_identity: "spki-sha256:chk1-rotated".into(),
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::DisableChecker => {
            done(admin::disable_resource_server_checker(tx, request, id(), expected).await?)
        }
        Write::AddCheckerTenant => done(
            admin::add_resource_server_checker_tenant(tx, request, id(), expected, "ten_b").await?,
        ),
        Write::RemoveCheckerTenant => done(
            admin::remove_resource_server_checker_tenant(tx, request, id(), expected, "ten_a")
                .await?,
        ),
        Write::CreateAction => done(
            admin::create_resource_action(
                tx,
                request,
                &ActionCreate {
                    resource_server_id: "rs_1".into(),
                    action_name: "projects.create".into(),
                    required_scopes: vec!["projects:write".into()],
                    accepted_profiles: vec![Profile::Wif],
                    required_resource_dimensions: vec!["project".into()],
                    live_check_required: true,
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::UpdateAction => done(
            admin::update_resource_action(
                tx,
                request,
                id(),
                expected,
                &ResourceActionChanges {
                    required_scopes: vec!["projects:read".into()],
                    accepted_profiles: vec![Profile::Wif],
                    required_resource_dimensions: vec!["project".into()],
                    live_check_required: false,
                    status: Status::Enabled,
                },
            )
            .await?,
        ),
        Write::DisableAction => {
            done(admin::disable_resource_action(tx, request, id(), expected).await?)
        }
    })
}

fn request<'a>(key: &'a str, ids: &'a dyn IdGenerator) -> AdminRequest<'a> {
    AdminRequest {
        public_identity: key,
        ids,
        now: at(5),
    }
}

/// A generator that gives the IDs of `inner` but fails its `fail_at`-th
/// call, counted from 1, with `error`.
struct FailingIds<'a> {
    inner: &'a SequentialIds,
    calls: AtomicUsize,
    fail_at: usize,
    error: IdError,
}

impl<'a> FailingIds<'a> {
    fn new(inner: &'a SequentialIds, fail_at: usize, error: IdError) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
            fail_at,
            error,
        }
    }

    /// How many IDs the write asked for, the failed one included.
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl IdGenerator for FailingIds<'_> {
    fn new_id(&self, kind: IdKind) -> Result<String, IdError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_at {
            Err(self.error)
        } else {
            self.inner.new_id(kind)
        }
    }
}

#[track_caller]
fn refused<T: std::fmt::Debug>(result: Result<T, AdminWriteError>, expected: &str) {
    match result {
        Ok(value) => panic!("expected {expected}, got Ok({value:?})"),
        Err(err) => assert_eq!(format!("{err:?}"), expected),
    }
}

/// Every row a write of this module may change, as text.
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let mut rows = Vec::new();
    for table in [
        "tenant",
        "principal",
        "resource_server",
        "audience_tenant_assignment",
        "resource_server_checker",
        "resource_server_checker_tenant",
        "resource_action",
        "audit_event",
        "audit_chain_head",
        "admin_identity",
        "admin_credential",
        "admin_role_binding",
    ] {
        let texts: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT to_jsonb(t)::text FROM {table} AS t ORDER BY to_jsonb(t)::text"
        )))
        .fetch_all(pool)
        .await
        .unwrap();
        rows.extend(texts.into_iter().map(|text| format!("{table} {text}")));
    }
    rows
}

/// A stored event: ID, tenant, actor, action, object, revisions, outcome
/// and time.
type Event = (
    String,
    Option<String>,
    String,
    String,
    String,
    Option<i64>,
    Option<i64>,
    String,
    i64,
);

/// The last event of the chain.
async fn last_event(pool: &PgPool) -> Event {
    sqlx::query_as(
        "SELECT id, tenant_id, actor, action, object_id, previous_revision, new_revision, \
         outcome, (extract(epoch FROM timestamp) * 1000000)::bigint \
         FROM audit_event ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn event_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_event")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn assert_chain_intact(pool: &PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    let verdict = verify_audit_chain(&mut connection).await.unwrap();
    assert!(
        matches!(verdict, ChainVerdict::Intact { .. }),
        "{verdict:?}"
    );
}

/// Every write refuses every role but its own, in every scope but its own,
/// and every credential that is unknown, revoked, of a disabled operator or
/// with only disabled bindings: one `Unauthorized`, nothing written, and no
/// ID generated.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn every_write_refuses_every_other_operator() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(9);
    let before = snapshot(&pool).await;
    for write in WRITES {
        for key in NEITHER.iter().chain(write.other_keys()) {
            let result = run(&pool, &ids, write, key, Revision::Current).await;
            assert!(
                matches!(result, Err(AdminWriteError::Unauthorized)),
                "{write:?} by {key}: {result:?}"
            );
        }
    }
    assert_eq!(snapshot(&pool).await, before);
    // No refused write took an ID.
    let fresh = SequentialIds::with_seed(9);
    for kind in IdKind::ALL {
        assert_eq!(ids.new_id(kind), fresh.new_id(kind), "{kind:?}");
    }
    db.drop([pool]).await;
}

/// Every write succeeds for its own role: the row with a generated ID (a
/// create) and the next revision, and its event, last, with its action,
/// actor, object, tenant, revisions, outcome, generated ID and the
/// request's time; the chain verifies.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn every_write_applies_for_its_role_with_its_event() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(3);
    let expected_ids = SequentialIds::with_seed(3);
    let mut created = Vec::new();
    for write in WRITES {
        let count = event_count(&pool).await;
        let previous = match write.created_kind() {
            Some(_) => None,
            None => Some(current_revision(&pool, write).await),
        };
        let result = run(&pool, &ids, write, write.key(), Revision::Current)
            .await
            .unwrap_or_else(|err| panic!("{write:?}: {err:?}"));
        match write.created_kind() {
            Some(kind) => {
                let expected = expected_ids.new_id(kind).unwrap();
                assert_eq!(result.id, expected, "{write:?}");
                assert_eq!(result.revision, 1, "{write:?}");
                created.push(result.id.clone());
            }
            None => {
                assert_eq!(result.id, write.target(), "{write:?}");
                assert_eq!(Some(result.revision - 1), previous, "{write:?}");
                assert_eq!(current_revision(&pool, write).await, result.revision);
            }
        }
        let event_id = expected_ids.new_id(IdKind::AuditEvent).unwrap();
        let actor = AuditActor::Operator(write.admin().into());
        assert_eq!(event_count(&pool).await, count + 1, "{write:?}");
        assert_eq!(
            last_event(&pool).await,
            (
                event_id.clone(),
                write.event_tenant().map(Into::into),
                actor.canonical_json(),
                write.action().into(),
                result.id.clone(),
                previous,
                Some(result.revision),
                "success".into(),
                micros(5),
            ),
            "{write:?}"
        );
        let event = &result.event;
        assert_eq!(event.id, event_id);
        assert_eq!(event.actor, actor);
        assert_eq!(event.action, write.action());
        assert_eq!(event.object_id, result.id);
        assert_eq!(event.tenant_id.as_deref(), write.event_tenant());
        assert_eq!(event.sequence, count + 1);
    }
    assert_chain_intact(&pool).await;
    // The rows hold the writes.
    let checker = registry::get_resource_server_checker(&pool, "chk_1")
        .await
        .unwrap();
    assert_eq!(checker.allowed_tenant_ids, ["ten_b"]);
    assert_eq!(checker.public_mtls_identity, "spki-sha256:chk1-rotated");
    let tenant = registry::get_tenant(&pool, "ten_b").await.unwrap();
    assert_eq!(tenant.status, Status::Disabled);
    let tenant = registry::get_tenant(&pool, &created[0]).await.unwrap();
    assert_eq!(tenant.secret_namespace, "ns_created");
    assert_eq!(tenant.name, "Tenant created");
    let principal = registry::get_principal(&pool, "ten_a", &created[1])
        .await
        .unwrap();
    assert_eq!(
        (principal.kind, principal.name.as_str()),
        (PrincipalKind::Workload, "wld-created")
    );
    let server = registry::get_resource_server(&pool, "rs_1").await.unwrap();
    assert_eq!(
        (server.name.as_str(), server.status),
        ("Server renamed", Status::Enabled)
    );
    let server = registry::get_resource_server(&pool, "rs_3").await.unwrap();
    assert_eq!(server.status, Status::Disabled);
    assert_eq!(
        (server.name, server.scopes),
        (
            "Server rs_3".into(),
            vec!["projects:read".to_string(), "projects:write".into()]
        )
    );
    db.drop([pool]).await;
}

/// The bootstrapped `security_admin` performs an instance write, and is no
/// `trust_admin`.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn the_bootstrap_operator_performs_instance_writes_only() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let done = run(
        &pool,
        &ids,
        Write::CreateTenant,
        "spki-sha256:first",
        Revision::Current,
    )
    .await
    .unwrap();
    assert_eq!(done.id, "ten_00000000000000000000000001");
    assert_eq!(done.event.actor, AuditActor::Operator("adm_first".into()));
    refused(
        run(
            &pool,
            &ids,
            Write::CreatePrincipal,
            "spki-sha256:first",
            Revision::Current,
        )
        .await,
        "Unauthorized",
    );
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// Every write with an expected revision refuses another one with the
/// registry's `StaleRevision` and writes nothing.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn every_update_refuses_a_stale_revision() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let before = snapshot(&pool).await;
    for write in WRITES {
        if write.created_kind().is_some() {
            continue;
        }
        refused(
            run(&pool, &ids, write, write.key(), Revision::Stale).await,
            "Registry(StaleRevision)",
        );
    }
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// A principal write is scoped to its tenant: `ten_a`'s `trust_admin`
/// asking for `ten_b` is `Unauthorized`; naming `ten_b`'s principal under
/// `ten_a` is `NotFound`, as for a missing one; `ten_b`'s own
/// `trust_admin` writes it.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn principal_writes_stay_in_their_tenant() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let request = |key| request(key, &ids);
    let patch = PrincipalPatch {
        name: Some("renamed".into()),
        status: None,
    };
    let before = snapshot(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    refused(
        admin::update_principal(&mut tx, &request(KEY_TRUST_A), "ten_b", "wld_b", 1, &patch).await,
        "Unauthorized",
    );
    refused(
        admin::update_principal(&mut tx, &request(KEY_TRUST_A), "ten_a", "wld_b", 1, &patch).await,
        "Registry(NotFound)",
    );
    refused(
        admin::disable_principal(&mut tx, &request(KEY_TRUST_A), "ten_a", "wld_b", 1).await,
        "Registry(NotFound)",
    );
    refused(
        admin::update_principal(&mut tx, &request(KEY_TRUST_A), "ten_a", "wld_x", 1, &patch).await,
        "Registry(NotFound)",
    );
    refused(
        admin::create_workload_principal(
            &mut tx,
            &request(KEY_TRUST_A),
            "ten_b",
            &PrincipalCreate {
                name: "x".into(),
                status: Status::Enabled,
            },
        )
        .await,
        "Unauthorized",
    );
    tx.commit().await.unwrap();
    assert_eq!(snapshot(&pool).await, before);
    let mut tx = pool.begin().await.unwrap();
    let done = admin::update_principal(&mut tx, &request(KEY_TRUST_B), "ten_b", "wld_b", 1, &patch)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(done.row.name, "renamed");
    assert_eq!(done.event.tenant_id.as_deref(), Some("ten_b"));
    assert_eq!(done.event.actor, AuditActor::Operator("adm_trust_b".into()));
    db.drop([pool]).await;
}

/// A human principal is neither updated nor disabled here; a service
/// principal is.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn only_workload_and_service_principals_change() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let request = request(KEY_TRUST_A, &ids);
    let before = snapshot(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let patch = PrincipalPatch {
        name: Some("renamed".into()),
        status: None,
    };
    refused(
        admin::update_principal(&mut tx, &request, "ten_a", "usr_a", 1, &patch).await,
        "PrincipalKindNotAllowed",
    );
    refused(
        admin::disable_principal(&mut tx, &request, "ten_a", "usr_a", 1).await,
        "PrincipalKindNotAllowed",
    );
    tx.commit().await.unwrap();
    assert_eq!(snapshot(&pool).await, before);
    let mut tx = pool.begin().await.unwrap();
    let updated = admin::update_principal(&mut tx, &request, "ten_a", "svc_a", 1, &patch)
        .await
        .unwrap();
    let disabled = admin::disable_principal(&mut tx, &request, "ten_a", "svc_a", 2)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(updated.event.action, "principal.update");
    assert_eq!(
        (
            disabled.row.status,
            disabled.row.revision,
            disabled.row.kind
        ),
        (Status::Disabled, 3, PrincipalKind::Service)
    );
    assert_eq!(disabled.event.action, "principal.disable");
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// An update that changes only the status is `.enable` or `.disable`; one
/// that changes anything else, or nothing, is `.update`; a `disable_*` of a
/// disabled row is still `.disable`.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn an_update_names_its_action_from_what_it_changes() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let sec = request(KEY_SEC, &ids);
    let trust = request(KEY_TRUST_A, &ids);
    let mut transaction = pool.begin().await.unwrap();
    let tx = &mut transaction;
    let status = |status| TenantPatch {
        name: None,
        status: Some(status),
    };
    let mut actions = Vec::new();
    // Tenants: a status patch, a status patch with the same name, a no-op
    // name patch, and a repeated disable.
    let t = admin::update_tenant(tx, &sec, "ten_a", 1, &status(Status::Disabled))
        .await
        .unwrap();
    actions.push(t.event.action);
    let same_name = TenantPatch {
        name: Some("Tenant ten_a".into()),
        status: Some(Status::Enabled),
    };
    let t = admin::update_tenant(tx, &sec, "ten_a", 2, &same_name)
        .await
        .unwrap();
    actions.push(t.event.action);
    let no_op = TenantPatch {
        name: Some("Tenant ten_a".into()),
        status: None,
    };
    let t = admin::update_tenant(tx, &sec, "ten_a", 3, &no_op)
        .await
        .unwrap();
    actions.push(t.event.action);
    let t = admin::update_tenant(tx, &sec, "ten_a", 4, &status(Status::Enabled))
        .await
        .unwrap();
    actions.push(t.event.action);
    let t = admin::disable_tenant(tx, &sec, "ten_b", 1).await.unwrap();
    actions.push(t.event.action);
    let t = admin::disable_tenant(tx, &sec, "ten_b", 2).await.unwrap();
    actions.push(t.event.action);
    let rename_and_disable = TenantPatch {
        name: Some("other".into()),
        status: Some(Status::Enabled),
    };
    let t = admin::update_tenant(tx, &sec, "ten_b", 3, &rename_and_disable)
        .await
        .unwrap();
    actions.push(t.event.action);
    // Principals.
    let p = admin::update_principal(
        tx,
        &trust,
        "ten_a",
        "wld_a",
        1,
        &PrincipalPatch {
            name: None,
            status: Some(Status::Disabled),
        },
    )
    .await
    .unwrap();
    actions.push(p.event.action);
    let p = admin::update_principal(
        tx,
        &trust,
        "ten_a",
        "wld_a",
        2,
        &PrincipalPatch {
            name: Some("wld-renamed".into()),
            status: Some(Status::Enabled),
        },
    )
    .await
    .unwrap();
    actions.push(p.event.action);
    // A resource server: status only both ways, then a scope added.
    let rs = registry::get_resource_server(&mut **tx, "rs_2")
        .await
        .unwrap();
    let with = |status, scopes: Vec<String>| ResourceServerChanges {
        name: rs.name.clone(),
        allowed_profiles: rs.allowed_profiles.clone(),
        scopes,
        constraint_versions: rs.constraint_versions.clone(),
        status,
    };
    for (revision, changes) in [
        (1, with(Status::Disabled, rs.scopes.clone())),
        (2, with(Status::Enabled, rs.scopes.clone())),
        (3, with(Status::Enabled, rs.scopes.clone())),
        (4, with(Status::Enabled, vec!["projects:admin".into()])),
        (5, with(Status::Disabled, vec!["projects:read".into()])),
    ] {
        let done = admin::update_resource_server(tx, &sec, "rs_2", revision, &changes)
            .await
            .unwrap();
        actions.push(done.event.action);
    }
    // An assignment, a checker and an action: status only, then another
    // column.
    let a = registry::get_audience_tenant_assignment(&mut **tx, "asgn_a3")
        .await
        .unwrap();
    for (revision, changes) in [
        (
            1,
            AudienceTenantAssignmentChanges {
                allowed_profiles: a.allowed_profiles.clone(),
                allowed_scopes: a.allowed_scopes.clone(),
                constraint_versions: a.constraint_versions.clone(),
                status: Status::Disabled,
            },
        ),
        (
            2,
            AudienceTenantAssignmentChanges {
                allowed_profiles: a.allowed_profiles.clone(),
                allowed_scopes: a.allowed_scopes.clone(),
                constraint_versions: vec![json!(2)],
                status: Status::Disabled,
            },
        ),
    ] {
        let done =
            admin::update_audience_tenant_assignment(tx, &sec, "asgn_a3", revision, &changes)
                .await
                .unwrap();
        actions.push(done.event.action);
    }
    for (revision, changes) in [
        (
            1,
            ResourceServerCheckerChanges {
                public_mtls_identity: "spki-sha256:chk2".into(),
                status: Status::Disabled,
            },
        ),
        (
            2,
            ResourceServerCheckerChanges {
                public_mtls_identity: "spki-sha256:chk2".into(),
                status: Status::Enabled,
            },
        ),
        (
            3,
            ResourceServerCheckerChanges {
                public_mtls_identity: "spki-sha256:chk2b".into(),
                status: Status::Enabled,
            },
        ),
    ] {
        let done = admin::update_resource_server_checker(tx, &sec, "chk_2", revision, &changes)
            .await
            .unwrap();
        actions.push(done.event.action);
    }
    let act = registry::get_resource_action(&mut **tx, "act_2")
        .await
        .unwrap();
    for (revision, live_check_required, status) in
        [(1, true, Status::Disabled), (2, false, Status::Enabled)]
    {
        let changes = ResourceActionChanges {
            required_scopes: act.required_scopes.clone(),
            accepted_profiles: act.accepted_profiles.clone(),
            required_resource_dimensions: act.required_resource_dimensions.clone(),
            live_check_required,
            status,
        };
        let done = admin::update_resource_action(tx, &sec, "act_2", revision, &changes)
            .await
            .unwrap();
        actions.push(done.event.action);
    }
    transaction.commit().await.unwrap();
    assert_chain_intact(&pool).await;
    assert_eq!(
        actions,
        [
            "tenant.disable",
            "tenant.enable",
            "tenant.update",
            "tenant.update",
            "tenant.disable",
            "tenant.disable",
            "tenant.update",
            "principal.disable",
            "principal.update",
            "resource_server.disable",
            "resource_server.enable",
            "resource_server.update",
            "resource_server.update",
            "resource_server.update",
            "audience_tenant_assignment.disable",
            "audience_tenant_assignment.update",
            "resource_server_checker.disable",
            "resource_server_checker.enable",
            "resource_server_checker.update",
            "resource_action.disable",
            "resource_action.update",
        ]
    );
    db.drop([pool]).await;
}

/// A write the registry refuses (a duplicate, a missing row or foreign
/// key, a tenant not in a checker's set, an empty patch) leaves nothing
/// behind, and the caller's transaction stays usable.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_refused_registry_write_leaves_nothing() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let sec = request(KEY_SEC, &ids);
    let before = snapshot(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let tenant = TenantCreate {
        name: "dup".into(),
        status: Status::Enabled,
    };
    refused(
        admin::create_tenant(&mut tx, &sec, "ns_a", &tenant).await,
        "Registry(AlreadyExists { constraint: \"tenant_secret_namespace_key\" })",
    );
    let server = ResourceServerCreate {
        audience: "https://api1.example".into(),
        name: "dup".into(),
        allowed_profiles: vec![Profile::Wif],
        scopes: vec!["projects:read".into()],
        constraint_versions: vec![],
        status: Status::Enabled,
    };
    refused(
        admin::create_resource_server(&mut tx, &sec, &server).await,
        "Registry(AlreadyExists { constraint: \"resource_server_audience_key\" })",
    );
    let missing_server = AssignmentCreate {
        resource_server_id: "rs_missing".into(),
        tenant_id: "ten_a".into(),
        allowed_profiles: vec![Profile::Wif],
        allowed_scopes: vec!["projects:read".into()],
        constraint_versions: vec![],
        status: Status::Enabled,
    };
    let result = admin::create_audience_tenant_assignment(&mut tx, &sec, &missing_server).await;
    assert!(
        matches!(
            result,
            Err(AdminWriteError::Registry(RegistryError::Invariant { .. }))
        ),
        "{result:?}"
    );
    // No tenant `ten_missing`, so no assignment of it; `chk_1` holds no
    // `ten_b` and holds `ten_a`.
    let result =
        admin::add_resource_server_checker_tenant(&mut tx, &sec, "chk_2", 1, "ten_missing").await;
    assert!(
        matches!(
            result,
            Err(AdminWriteError::Registry(RegistryError::Invariant { .. }))
        ),
        "{result:?}"
    );
    refused(
        admin::remove_resource_server_checker_tenant(&mut tx, &sec, "chk_1", 2, "ten_b").await,
        "Registry(NotFound)",
    );
    refused(
        admin::add_resource_server_checker_tenant(&mut tx, &sec, "chk_1", 2, "ten_a").await,
        "Registry(AlreadyExists { constraint: \"resource_server_checker_tenant_pkey\" })",
    );
    refused(
        admin::disable_resource_server(&mut tx, &sec, "rs_missing", 1).await,
        "Registry(NotFound)",
    );
    refused(
        admin::update_tenant(&mut tx, &sec, "ten_missing", 1, &TenantPatch::default()).await,
        "Registry(NotFound)",
    );
    let result = admin::update_tenant(&mut tx, &sec, "ten_a", 1, &TenantPatch::default()).await;
    assert!(
        matches!(
            result,
            Err(AdminWriteError::Registry(RegistryError::Other(_)))
        ),
        "{result:?}"
    );
    let duplicate_name = PrincipalCreate {
        name: "principal-wld_a".into(),
        status: Status::Enabled,
    };
    let trust = request(KEY_TRUST_A, &ids);
    refused(
        admin::create_workload_principal(&mut tx, &trust, "ten_a", &duplicate_name).await,
        "Registry(AlreadyExists { constraint: \"principal_tenant_id_kind_name_key\" })",
    );
    // The transaction is usable: a write after the refusals applies.
    let done = admin::disable_tenant(&mut tx, &sec, "ten_b", 1)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut after = snapshot(&pool).await;
    // Only the disable and its event changed anything.
    assert_eq!(done.row.revision, 2);
    assert_ne!(after, before);
    after.retain(|row| !row.starts_with("tenant ") && !row.starts_with("audit_"));
    let mut expected = before.clone();
    expected.retain(|row| !row.starts_with("tenant ") && !row.starts_with("audit_"));
    assert_eq!(after, expected);
    assert_eq!(event_count(&pool).await, 2);
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// A write runs only under `READ COMMITTED`: under `REPEATABLE READ` or
/// `SERIALIZABLE` it is `UnsupportedIsolation` and writes nothing.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn writes_run_only_at_read_committed() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    let before = snapshot(&pool).await;
    for level in ["REPEATABLE READ", "SERIALIZABLE"] {
        for write in [
            Write::CreateTenant,
            Write::UpdatePrincipal,
            Write::AddCheckerTenant,
        ] {
            let expected = if write.created_kind().is_some() {
                0
            } else {
                current_revision(&pool, write).await
            };
            let mut tx = pool.begin().await.unwrap();
            sqlx::query(AssertSqlSafe(format!(
                "SET TRANSACTION ISOLATION LEVEL {level}"
            )))
            .execute(&mut *tx)
            .await
            .unwrap();
            refused(
                call(&mut tx, &ids, write, write.key(), expected).await,
                "UnsupportedIsolation",
            );
            tx.commit().await.unwrap();
        }
    }
    assert_eq!(snapshot(&pool).await, before);
    db.drop([pool]).await;
}

/// The authorization holds until the write's transaction ends: a
/// revocation of the requester's credential waits for it.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn the_authorization_is_locked_until_the_transaction_ends() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::new();
    for (write, credential) in [
        (Write::CreateTenant, "crd_adm_sec"),
        (Write::CreatePrincipal, "crd_adm_trust_a"),
    ] {
        let mut tx = pool.begin().await.unwrap();
        call(&mut tx, &ids, write, write.key(), 0).await.unwrap();
        let mut other = pool.acquire().await.unwrap();
        let mut revoke = Connection::begin(&mut *other).await.unwrap();
        sqlx::query("SET LOCAL lock_timeout = '200ms'")
            .execute(&mut *revoke)
            .await
            .unwrap();
        let err = registry::revoke_admin_credential(&mut *revoke, credential, at(9))
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("55P03"), "{err:?}");
        revoke.rollback().await.unwrap();
        tx.rollback().await.unwrap();
    }
    db.drop([pool]).await;
}

/// No refusal's `Display` or `Debug` holds a value of the request: a key,
/// an ID, a name, a namespace or an audience.
/// A generator that gives no ID, at any of the calls a write makes (a
/// create's object ID, before the registry write, and every write's event
/// ID, after it), fails the write with `Id` and leaves nothing written,
/// although the outer transaction then commits: the savepoint takes back
/// the row written before the event's ID failed. The write asks for no ID
/// after the failed one, and, with a generator that does not fail, for
/// exactly those IDs.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn a_failing_generator_leaves_nothing() {
    let (db, pool) = seeded().await;
    let shared = SequentialIds::with_seed(7);
    for write in WRITES {
        let calls = if write.created_kind().is_some() { 2 } else { 1 };
        let before = snapshot(&pool).await;
        for fail_at in 1..=calls {
            for error in [IdError::SourceFailed, IdError::Exhausted] {
                let ids = FailingIds::new(&shared, fail_at, error);
                let result = run(&pool, &ids, write, write.key(), Revision::Current).await;
                refused(result, &format!("Id({error:?})"));
                assert_eq!(ids.calls(), fail_at, "{write:?}");
                assert_eq!(snapshot(&pool).await, before, "{write:?} at {fail_at}");
            }
        }
        let ids = FailingIds::new(&shared, usize::MAX, IdError::SourceFailed);
        run(&pool, &ids, write, write.key(), Revision::Current)
            .await
            .unwrap_or_else(|err| panic!("{write:?}: {err:?}"));
        assert_eq!(ids.calls(), calls, "{write:?}");
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

/// `SequentialIds` at the end of a counter is `Exhausted`, and a write
/// that needs an ID of that kind, for its object or its event, writes
/// nothing.
#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn an_exhausted_generator_writes_nothing() {
    let (db, pool) = seeded().await;
    let before = snapshot(&pool).await;
    for (write, kind) in [
        (Write::CreateTenant, IdKind::Tenant),
        (Write::CreateTenant, IdKind::AuditEvent),
        (Write::CreatePrincipal, IdKind::WorkloadPrincipal),
        (Write::CreatePrincipal, IdKind::AuditEvent),
        (Write::CreateChecker, IdKind::Checker),
        (Write::UpdateTenant, IdKind::AuditEvent),
        (Write::DisablePrincipal, IdKind::AuditEvent),
        (Write::AddCheckerTenant, IdKind::AuditEvent),
    ] {
        let ids = SequentialIds::with_last_count(kind, u64::MAX);
        let result = run(&pool, &ids, write, write.key(), Revision::Current).await;
        refused(result, "Id(Exhausted)");
        assert_eq!(snapshot(&pool).await, before, "{write:?} {kind:?}");
    }
    assert_chain_intact(&pool).await;
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "needs SKYOAUTH_IT_DATABASE_URL"]
async fn errors_omit_the_requests_values() {
    let (db, pool) = seeded().await;
    let ids = SequentialIds::with_seed(0x5ec7);
    let markers = [
        KEY_SEC,
        KEY_TRUST_A,
        "key_revoked",
        KEY_UNKNOWN,
        "ten_a",
        "ten_b",
        "wld_a",
        "usr_a",
        "chk_1",
        "rs_1",
        "ns_a",
        "https://api1.example",
        "principal-wld_a",
        "adm_",
        "crd_",
    ];
    let generated = SequentialIds::with_seed(0x5ec7);
    let mut errors = Vec::new();
    for (write, key, revision) in [
        (Write::CreateTenant, KEY_UNKNOWN, Revision::Current),
        (Write::UpdatePrincipal, "key_revoked", Revision::Current),
        (Write::UpdatePrincipal, KEY_TRUST_A, Revision::Stale),
        (Write::RemoveCheckerTenant, KEY_SEC, Revision::Stale),
    ] {
        errors.push(run(&pool, &ids, write, key, revision).await.unwrap_err());
    }
    let failing = FailingIds::new(&ids, 2, IdError::SourceFailed);
    let write = Write::CreateTenant;
    let result = run(&pool, &failing, write, KEY_SEC, Revision::Current).await;
    errors.push(result.unwrap_err());
    let sec = request(KEY_SEC, &ids);
    let trust = request(KEY_TRUST_A, &ids);
    let mut tx = pool.begin().await.unwrap();
    errors.push(
        admin::create_tenant(
            &mut tx,
            &sec,
            "ns_a",
            &TenantCreate {
                name: "ten_a".into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap_err(),
    );
    errors.push(
        admin::create_workload_principal(
            &mut tx,
            &trust,
            "ten_a",
            &PrincipalCreate {
                name: "principal-wld_a".into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap_err(),
    );
    errors.push(
        admin::update_principal(
            &mut tx,
            &trust,
            "ten_a",
            "usr_a",
            1,
            &PrincipalPatch::default(),
        )
        .await
        .unwrap_err(),
    );
    errors.push(
        admin::update_principal(
            &mut tx,
            &trust,
            "ten_a",
            "wld_b",
            1,
            &PrincipalPatch::default(),
        )
        .await
        .unwrap_err(),
    );
    errors.push(
        admin::add_resource_server_checker_tenant(&mut tx, &sec, "chk_1", 2, "ten_a")
            .await
            .unwrap_err(),
    );
    tx.commit().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .unwrap();
    errors.push(
        admin::disable_tenant(&mut tx, &sec, "ten_a", 1)
            .await
            .unwrap_err(),
    );
    tx.rollback().await.unwrap();
    let mut seen = Vec::new();
    for err in &errors {
        seen.push(format!("{err:?}"));
        for text in [format!("{err}"), format!("{err:?}")] {
            for marker in markers
                .iter()
                .map(ToString::to_string)
                .chain([generated.new_id(IdKind::Tenant).unwrap()])
            {
                assert!(!text.contains(&marker), "{text:?} holds {marker:?}");
            }
        }
    }
    assert_eq!(
        seen,
        [
            "Unauthorized",
            "Unauthorized",
            "Registry(StaleRevision)",
            "Registry(StaleRevision)",
            "Id(SourceFailed)",
            "Registry(AlreadyExists { constraint: \"tenant_secret_namespace_key\" })",
            "Registry(AlreadyExists { constraint: \"principal_tenant_id_kind_name_key\" })",
            "PrincipalKindNotAllowed",
            "Registry(NotFound)",
            "Registry(AlreadyExists { constraint: \"resource_server_checker_tenant_pkey\" })",
            "UnsupportedIsolation",
        ]
    );
    db.drop([pool]).await;
}
