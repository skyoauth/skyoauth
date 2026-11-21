//! Operator identities, credentials and role bindings
//! (`persistence::registry::operator`; `0005`; design section 7.2;
//! identity-registry section 5.2; T13.1, T13.2) and the operator
//! authorization lookup `authorize_operator` (public-api API-002 and
//! API-120; ADR-013 OQ-ADR013-3). The database tests create, read and
//! update the rows, check that revocation is one-way in the database and
//! that a revoked key is never registered again, and check that every
//! authorization miss is the same `Ok(None)` while each role and scope
//! shape has its hit. The tests without a database check that reserved
//! actor IDs fail before any statement.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database. They are
//! registry tests, not conformance scenarios (A22, A32 belong to the test
//! session in `tests/security`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    error::Error as _,
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, AdminCredential, AdminRole, AdminRoleBinding, AdminRoleBindingChanges,
        AuthorizedOperator, DEPLOYMENT_OPERATOR_ACTOR, InvariantKind, NewAdminCredential,
        NewAdminIdentity, NewAdminRoleBinding, NewTenant, OperatorRequest, OperatorScope,
        RECOVERY_KEY_ACTOR_PREFIX, RegistryError, Status, authorize_operator, recovery_key_actor,
    },
};
use sqlx::{Connection, postgres::PgPoolOptions};

/// A time with sub-microsecond digits, so a write truncates it.
fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(micros)
}

const T0: u64 = 1_790_000_000_123_456;

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

/// The SQLSTATE of an `Other` error.
fn sqlstate(error: &RegistryError) -> Option<String> {
    error
        .source()?
        .downcast_ref::<sqlx::Error>()?
        .as_database_error()?
        .code()
        .map(|code| code.into_owned())
}

#[track_caller]
fn assert_exists<T: Debug>(result: Result<T, RegistryError>, name: &str) {
    match result {
        Err(error @ RegistryError::AlreadyExists { .. }) => {
            assert!(
                matches!(error, RegistryError::AlreadyExists { constraint } if constraint == name),
                "{error:?}"
            );
            // The colliding value is never in the error's text.
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("key_"), "{text}");
                assert!(!text.contains("adm_"), "{text}");
            }
        }
        other => panic!("expected AlreadyExists {name}: {other:?}"),
    }
}

#[track_caller]
fn assert_invariant<T: Debug>(result: Result<T, RegistryError>, kind: InvariantKind, name: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: actual,
            constraint: Some(constraint),
        }) => assert_eq!((actual, constraint), (kind, name)),
        other => panic!("expected {kind:?} {name}: {other:?}"),
    }
}

#[track_caller]
fn assert_not_found<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::NotFound)), "{result:?}");
}

#[track_caller]
fn assert_guard<T: Debug>(result: Result<T, RegistryError>) {
    assert!(matches!(result, Err(RegistryError::Guard)), "{result:?}");
}

fn identity(id: &str, status: Status) -> NewAdminIdentity {
    NewAdminIdentity {
        id: id.into(),
        status,
        created_at: at(T0),
    }
}

fn credential(id: &str, admin_id: &str, key: &str, status: Status) -> NewAdminCredential {
    NewAdminCredential {
        id: id.into(),
        admin_id: admin_id.into(),
        public_identity: key.into(),
        trust_anchor_ref: "deployment/operator-ca".into(),
        status,
    }
}

fn binding(
    id: &str,
    admin_id: &str,
    role: AdminRole,
    tenant_id: Option<&str>,
    status: Status,
) -> NewAdminRoleBinding {
    NewAdminRoleBinding {
        id: id.into(),
        admin_id: admin_id.into(),
        role,
        tenant_id: tenant_id.map(Into::into),
        status,
    }
}

async fn tenants(pool: &PgPool) {
    for (id, ns) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::create_tenant(
            pool,
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
}

/// One operator `admin` with one credential `key` and one binding.
#[allow(clippy::too_many_arguments)]
async fn operator(
    pool: &PgPool,
    admin: &str,
    admin_status: Status,
    key: &str,
    key_status: Status,
    role: AdminRole,
    tenant_id: Option<&str>,
    binding_status: Status,
) {
    registry::create_admin_identity(pool, &identity(admin, admin_status))
        .await
        .unwrap();
    registry::create_admin_credential(
        pool,
        &credential(&format!("crd_{admin}"), admin, key, key_status),
    )
    .await
    .unwrap();
    registry::create_admin_role_binding(
        pool,
        &binding(
            &format!("rb_{admin}"),
            admin,
            role,
            tenant_id,
            binding_status,
        ),
    )
    .await
    .unwrap();
}

const E: Status = Status::Enabled;
const D: Status = Status::Disabled;

/// Tenants `ten_a` and `ten_b` and these operators, each with one
/// credential `key_<x>` (`crd_adm_<x>`) and one binding (`rb_adm_<x>`),
/// all enabled unless stated:
///
/// - `adm_sec`: `security_admin` of the instance.
/// - `adm_trust`, `adm_client`, `adm_prov`: `trust_admin`, `client_admin`
///   and `provider_admin` of `ten_a`.
/// - `adm_audt`: `auditor` of `ten_a`; `adm_audi`: `auditor` of the
///   instance.
/// - `adm_off`: a disabled identity with an enabled credential and an
///   enabled `trust_admin` binding of `ten_a`.
/// - `adm_cdis`: a disabled (not revoked) credential, `trust_admin` of
///   `ten_a`.
/// - `adm_rev`: a revoked credential, `trust_admin` of `ten_a`.
/// - `adm_bdis`: a disabled `trust_admin` binding of `ten_a`.
/// - `adm_nobind`: an enabled identity and credential with no binding at
///   all, while the other operators hold every role and scope.
/// - `adm_uni`: `security_admin` of the instance, whose key `kéy_uni` has
///   a precomposed `é` (U+00E9).
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    tenants(&pool).await;
    let ten_a = Some("ten_a");
    for (admin, a, key, k, role, tenant, b) in [
        (
            "adm_sec",
            E,
            "key_sec",
            E,
            AdminRole::SecurityAdmin,
            None,
            E,
        ),
        (
            "adm_trust",
            E,
            "key_trust",
            E,
            AdminRole::TrustAdmin,
            ten_a,
            E,
        ),
        (
            "adm_client",
            E,
            "key_client",
            E,
            AdminRole::ClientAdmin,
            ten_a,
            E,
        ),
        (
            "adm_prov",
            E,
            "key_prov",
            E,
            AdminRole::ProviderAdmin,
            ten_a,
            E,
        ),
        ("adm_audt", E, "key_audt", E, AdminRole::Auditor, ten_a, E),
        ("adm_audi", E, "key_audi", E, AdminRole::Auditor, None, E),
        ("adm_off", D, "key_off", E, AdminRole::TrustAdmin, ten_a, E),
        (
            "adm_cdis",
            E,
            "key_cdis",
            D,
            AdminRole::TrustAdmin,
            ten_a,
            E,
        ),
        ("adm_rev", E, "key_rev", E, AdminRole::TrustAdmin, ten_a, E),
        (
            "adm_bdis",
            E,
            "key_bdis",
            E,
            AdminRole::TrustAdmin,
            ten_a,
            D,
        ),
        (
            "adm_uni",
            E,
            "k\u{e9}y_uni",
            E,
            AdminRole::SecurityAdmin,
            None,
            E,
        ),
    ] {
        operator(&pool, admin, a, key, k, role, tenant, b).await;
    }
    registry::revoke_admin_credential(&pool, "crd_adm_rev", at(T0 + 1))
        .await
        .unwrap();
    registry::create_admin_identity(&pool, &identity("adm_nobind", E))
        .await
        .unwrap();
    registry::create_admin_credential(
        &pool,
        &credential("crd_adm_nobind", "adm_nobind", "key_nobind", E),
    )
    .await
    .unwrap();
    (db, pool)
}

fn request<'a>(key: &'a str, role: AdminRole, scope: OperatorScope<'a>) -> OperatorRequest<'a> {
    OperatorRequest {
        public_identity: key,
        scope,
        role,
    }
}

async fn authorize(
    pool: &PgPool,
    key: &str,
    role: AdminRole,
    scope: OperatorScope<'_>,
) -> Result<Option<AuthorizedOperator>, RegistryError> {
    authorize_operator(pool, &request(key, role, scope)).await
}

const INSTANCE: OperatorScope<'static> = OperatorScope::Instance;
const TEN_A: OperatorScope<'static> = OperatorScope::Tenant("ten_a");
const TEN_B: OperatorScope<'static> = OperatorScope::Tenant("ten_b");

fn hit(admin: &str, role: AdminRole) -> AuthorizedOperator {
    AuthorizedOperator {
        admin_id: admin.into(),
        credential_id: format!("crd_{admin}"),
        binding_id: format!("rb_{admin}"),
        role,
    }
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn operator_rows_are_created_read_and_keyed() {
    let (db, pool) = migrated().await;
    tenants(&pool).await;

    let created = registry::create_admin_identity(
        &pool,
        &NewAdminIdentity {
            id: "adm_1".into(),
            status: Status::Enabled,
            // Nanoseconds are truncated to the microsecond.
            created_at: at(T0) + Duration::from_nanos(999),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        (&created.id[..], created.status, created.created_at),
        ("adm_1", Status::Enabled, at(T0))
    );
    assert_eq!(
        registry::get_admin_identity(&pool, "adm_1").await.unwrap(),
        created
    );
    assert_not_found(registry::get_admin_identity(&pool, "adm_x").await);
    assert_exists(
        registry::create_admin_identity(&pool, &identity("adm_1", Status::Disabled)).await,
        "admin_identity_pkey",
    );
    // The time is the caller's, also far from the database's clock.
    let old = registry::create_admin_identity(
        &pool,
        &NewAdminIdentity {
            id: "adm_old".into(),
            status: Status::Disabled,
            created_at: UNIX_EPOCH - Duration::from_secs(86_400),
        },
    )
    .await
    .unwrap();
    assert_eq!(old.created_at, UNIX_EPOCH - Duration::from_secs(86_400));
    assert_eq!(old.status, Status::Disabled);
    // A time outside the 0007 range fails before any statement.
    let far = UNIX_EPOCH + Duration::from_micros(u64::try_from(i64::MAX).unwrap());
    let err = registry::create_admin_identity(
        &pool,
        &NewAdminIdentity {
            id: "adm_far".into(),
            status: Status::Enabled,
            created_at: far,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, RegistryError::Other(sqlx::Error::Encode(_))),
        "{err:?}"
    );
    assert_not_found(registry::get_admin_identity(&pool, "adm_far").await);
    assert_invariant(
        registry::create_admin_identity(&pool, &identity("", Status::Enabled)).await,
        InvariantKind::Check,
        "admin_identity_id_check",
    );
    assert_invariant(
        registry::create_admin_identity(&pool, &identity(&"a".repeat(256), Status::Enabled)).await,
        InvariantKind::Check,
        "admin_identity_id_octet_length_check",
    );

    let key = registry::create_admin_credential(
        &pool,
        &credential("crd_1", "adm_1", "key_1", Status::Enabled),
    )
    .await
    .unwrap();
    assert_eq!(
        key,
        AdminCredential {
            id: "crd_1".into(),
            admin_id: "adm_1".into(),
            public_identity: "key_1".into(),
            trust_anchor_ref: "deployment/operator-ca".into(),
            status: Status::Enabled,
            revoked_at: None,
        }
    );
    assert_eq!(
        registry::get_admin_credential(&pool, "crd_1")
            .await
            .unwrap(),
        key
    );
    assert_not_found(registry::get_admin_credential(&pool, "crd_x").await);
    assert_exists(
        registry::create_admin_credential(
            &pool,
            &credential("crd_1", "adm_1", "key_2", Status::Enabled),
        )
        .await,
        "admin_credential_pkey",
    );
    // The same key for another operator, or for the same one.
    for admin in ["adm_old", "adm_1"] {
        assert_exists(
            registry::create_admin_credential(
                &pool,
                &credential("crd_2", admin, "key_1", Status::Enabled),
            )
            .await,
            "admin_credential_public_identity_key",
        );
    }
    assert_invariant(
        registry::create_admin_credential(
            &pool,
            &credential("crd_2", "adm_x", "key_2", Status::Enabled),
        )
        .await,
        InvariantKind::ForeignKey,
        "admin_credential_admin_id_fkey",
    );
    assert_invariant(
        registry::create_admin_credential(
            &pool,
            &credential("crd_2", "adm_1", "", Status::Enabled),
        )
        .await,
        InvariantKind::Check,
        "admin_credential_public_identity_check",
    );
    assert_invariant(
        registry::create_admin_credential(
            &pool,
            &credential("crd_2", "adm_1", &"k".repeat(2049), Status::Enabled),
        )
        .await,
        InvariantKind::Check,
        "admin_credential_public_identity_octet_length_check",
    );
    let mut spaced = credential("crd_2", "adm_1", "key_2", Status::Enabled);
    spaced.trust_anchor_ref = "operator ca".into();
    assert_invariant(
        registry::create_admin_credential(&pool, &spaced).await,
        InvariantKind::Check,
        "admin_credential_trust_anchor_ref_no_space_check",
    );

    let sec = registry::create_admin_role_binding(
        &pool,
        &binding(
            "rb_1",
            "adm_1",
            AdminRole::SecurityAdmin,
            None,
            Status::Enabled,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        sec,
        AdminRoleBinding {
            id: "rb_1".into(),
            admin_id: "adm_1".into(),
            role: AdminRole::SecurityAdmin,
            tenant_id: None,
            status: Status::Enabled,
            revision: 1,
        }
    );
    assert_eq!(
        registry::get_admin_role_binding(&pool, "rb_1")
            .await
            .unwrap(),
        sec
    );
    assert_not_found(registry::get_admin_role_binding(&pool, "rb_x").await);
    // Every role and scope shape the schema allows.
    for (id, role, tenant) in [
        ("rb_2", AdminRole::TrustAdmin, Some("ten_a")),
        ("rb_3", AdminRole::ClientAdmin, Some("ten_a")),
        ("rb_4", AdminRole::ProviderAdmin, Some("ten_a")),
        ("rb_5", AdminRole::Auditor, Some("ten_a")),
        ("rb_6", AdminRole::Auditor, None),
        ("rb_7", AdminRole::TrustAdmin, Some("ten_b")),
    ] {
        let created = registry::create_admin_role_binding(
            &pool,
            &binding(id, "adm_1", role, tenant, Status::Disabled),
        )
        .await
        .unwrap();
        assert_eq!(
            (created.role, created.tenant_id.as_deref(), created.revision),
            (role, tenant, 1)
        );
    }
    assert_exists(
        registry::create_admin_role_binding(
            &pool,
            &binding("rb_1", "adm_old", AdminRole::Auditor, None, Status::Enabled),
        )
        .await,
        "admin_role_binding_pkey",
    );
    // One binding per operator, role and scope, the instance scope (NULL)
    // included, disabled rows included.
    for (role, tenant) in [
        (AdminRole::SecurityAdmin, None),
        (AdminRole::Auditor, None),
        (AdminRole::TrustAdmin, Some("ten_a")),
    ] {
        assert_exists(
            registry::create_admin_role_binding(
                &pool,
                &binding("rb_9", "adm_1", role, tenant, Status::Enabled),
            )
            .await,
            "admin_role_binding_admin_id_role_tenant_id_key",
        );
    }
    for (role, tenant) in [
        (AdminRole::SecurityAdmin, Some("ten_a")),
        (AdminRole::TrustAdmin, None),
        (AdminRole::ClientAdmin, None),
        (AdminRole::ProviderAdmin, None),
    ] {
        assert_invariant(
            registry::create_admin_role_binding(
                &pool,
                &binding("rb_9", "adm_old", role, tenant, Status::Enabled),
            )
            .await,
            InvariantKind::Check,
            "admin_role_binding_scope_check",
        );
    }
    assert_invariant(
        registry::create_admin_role_binding(
            &pool,
            &binding(
                "rb_9",
                "adm_old",
                AdminRole::TrustAdmin,
                Some("ten_x"),
                Status::Enabled,
            ),
        )
        .await,
        InvariantKind::ForeignKey,
        "admin_role_binding_tenant_id_fkey",
    );
    assert_invariant(
        registry::create_admin_role_binding(
            &pool,
            &binding("rb_9", "adm_x", AdminRole::Auditor, None, Status::Enabled),
        )
        .await,
        InvariantKind::ForeignKey,
        "admin_role_binding_admin_id_fkey",
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn role_binding_updates_are_revision_checked() {
    let (db, pool) = migrated().await;
    tenants(&pool).await;
    operator(
        &pool,
        "adm_1",
        E,
        "key_1",
        E,
        AdminRole::TrustAdmin,
        Some("ten_a"),
        E,
    )
    .await;
    let disable = AdminRoleBindingChanges {
        status: Status::Disabled,
    };
    let enable = AdminRoleBindingChanges {
        status: Status::Enabled,
    };
    let disabled = registry::update_admin_role_binding(&pool, "rb_adm_1", 1, &disable)
        .await
        .unwrap();
    assert_eq!((disabled.status, disabled.revision), (Status::Disabled, 2));
    assert_eq!(
        (
            &disabled.admin_id[..],
            disabled.role,
            disabled.tenant_id.as_deref()
        ),
        ("adm_1", AdminRole::TrustAdmin, Some("ten_a"))
    );
    assert!(matches!(
        registry::update_admin_role_binding(&pool, "rb_adm_1", 1, &enable).await,
        Err(RegistryError::StaleRevision)
    ));
    assert!(matches!(
        registry::update_admin_role_binding(&pool, "rb_adm_1", i64::MAX, &enable).await,
        Err(RegistryError::StaleRevision)
    ));
    assert_not_found(registry::update_admin_role_binding(&pool, "rb_x", 1, &enable).await);
    // A binding is re-enabled rather than assigned twice (0005).
    let enabled = registry::update_admin_role_binding(&pool, "rb_adm_1", 2, &enable)
        .await
        .unwrap();
    assert_eq!((enabled.status, enabled.revision), (Status::Enabled, 3));
    assert_eq!(
        registry::get_admin_role_binding(&pool, "rb_adm_1")
            .await
            .unwrap(),
        enabled
    );
    // The role and scope are immutable in the database too.
    assert_guard(Err::<(), _>(
        raw_error(
            &pool,
            "UPDATE admin_role_binding SET tenant_id = 'ten_b', revision = revision + 1 \
             WHERE id = 'rb_adm_1'",
        )
        .await,
    ));
    assert_guard(Err::<(), _>(
        raw_error(
            &pool,
            "UPDATE admin_role_binding SET role = 'client_admin', revision = revision + 1 \
             WHERE id = 'rb_adm_1'",
        )
        .await,
    ));
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn disabling_an_identity_is_idempotent() {
    let (db, pool) = migrated().await;
    registry::create_admin_identity(&pool, &identity("adm_1", E))
        .await
        .unwrap();
    for _ in 0..2 {
        let disabled = registry::disable_admin_identity(&pool, "adm_1")
            .await
            .unwrap();
        assert_eq!(
            (&disabled.id[..], disabled.status, disabled.created_at),
            ("adm_1", Status::Disabled, at(T0))
        );
    }
    assert_not_found(registry::disable_admin_identity(&pool, "adm_x").await);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn revocation_sets_revoked_at_once_and_disables() {
    let (db, pool) = migrated().await;
    registry::create_admin_identity(&pool, &identity("adm_1", E))
        .await
        .unwrap();
    for (id, key, status) in [("crd_1", "key_1", E), ("crd_2", "key_2", D)] {
        registry::create_admin_credential(&pool, &credential(id, "adm_1", key, status))
            .await
            .unwrap();
    }
    let first = at(T0 + 10) + Duration::from_nanos(999);
    let revoked = registry::revoke_admin_credential(&pool, "crd_1", first)
        .await
        .unwrap();
    assert_eq!(
        (revoked.status, revoked.revoked_at),
        (Status::Disabled, Some(at(T0 + 10)))
    );
    assert_eq!(
        registry::get_admin_credential(&pool, "crd_1")
            .await
            .unwrap(),
        revoked
    );
    // Revoking again keeps the first time; earlier or later alike.
    for again in [at(T0 + 20), at(T0)] {
        assert_eq!(
            registry::revoke_admin_credential(&pool, "crd_1", again)
                .await
                .unwrap(),
            revoked
        );
    }
    // A disabled, unrevoked credential is revoked the same way.
    let revoked = registry::revoke_admin_credential(&pool, "crd_2", at(T0 + 30))
        .await
        .unwrap();
    assert_eq!(
        (revoked.status, revoked.revoked_at),
        (Status::Disabled, Some(at(T0 + 30)))
    );
    assert_not_found(registry::revoke_admin_credential(&pool, "crd_x", at(T0)).await);
    db.drop([pool]).await;
}

/// The database, not only the registry, keeps revocation one-way: the
/// statements below are the ones a caller could write by hand.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn revocation_is_one_way_in_the_database() {
    let (db, pool) = migrated().await;
    registry::create_admin_identity(&pool, &identity("adm_1", E))
        .await
        .unwrap();
    registry::create_admin_credential(&pool, &credential("crd_1", "adm_1", "key_1", E))
        .await
        .unwrap();
    let revoked = registry::revoke_admin_credential(&pool, "crd_1", at(T0))
        .await
        .unwrap();
    // admin_credential_set_once: revoked_at is never cleared or changed.
    for sql in [
        "UPDATE admin_credential SET revoked_at = NULL, status = 'enabled' WHERE id = 'crd_1'",
        "UPDATE admin_credential SET revoked_at = NULL WHERE id = 'crd_1'",
        "UPDATE admin_credential SET revoked_at = revoked_at + interval '1 second' \
         WHERE id = 'crd_1'",
        "UPDATE admin_credential SET revoked_at = revoked_at - interval '1 second' \
         WHERE id = 'crd_1'",
    ] {
        assert_guard(Err::<(), _>(raw_error(&pool, sql).await));
    }
    // admin_credential_revoked_disabled_check: a revoked credential stays
    // disabled.
    assert_invariant(
        Err::<(), _>(
            raw_error(
                &pool,
                "UPDATE admin_credential SET status = 'enabled' WHERE id = 'crd_1'",
            )
            .await,
        ),
        InvariantKind::Check,
        "admin_credential_revoked_disabled_check",
    );
    // An insert cannot create an enabled, revoked credential either.
    assert_invariant(
        Err::<(), _>(
            raw_error(
                &pool,
                "INSERT INTO admin_credential \
                 (id, admin_id, public_identity, trust_anchor_ref, status, revoked_at) \
                 VALUES ('crd_2', 'adm_1', 'key_2', 'ca', 'enabled', now())",
            )
            .await,
        ),
        InvariantKind::Check,
        "admin_credential_revoked_disabled_check",
    );
    // admin_credential_immutable: the key cannot move off the revoked row,
    // nor the row to another ID.
    for sql in [
        "UPDATE admin_credential SET public_identity = 'key_9' WHERE id = 'crd_1'",
        "UPDATE admin_credential SET id = 'crd_9' WHERE id = 'crd_1'",
    ] {
        assert_guard(Err::<(), _>(raw_error(&pool, sql).await));
    }
    // admin_credential_no_delete and _no_truncate (0006): the row stays.
    assert_guard(Err::<(), _>(
        raw_error(&pool, "DELETE FROM admin_credential WHERE id = 'crd_1'").await,
    ));
    assert_guard(Err::<(), _>(
        raw_error(&pool, "TRUNCATE admin_credential").await,
    ));
    assert_eq!(
        registry::get_admin_credential(&pool, "crd_1")
            .await
            .unwrap(),
        revoked
    );
    db.drop([pool]).await;
}

/// A revoked `public_identity` can never be registered again while its row
/// exists, and the row cannot be deleted.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_revoked_public_identity_is_never_registered_again() {
    let (db, pool) = migrated().await;
    tenants(&pool).await;
    operator(
        &pool,
        "adm_1",
        E,
        "key_1",
        E,
        AdminRole::SecurityAdmin,
        None,
        E,
    )
    .await;
    registry::create_admin_identity(&pool, &identity("adm_2", E))
        .await
        .unwrap();
    assert_eq!(
        authorize(&pool, "key_1", AdminRole::SecurityAdmin, INSTANCE)
            .await
            .unwrap(),
        Some(hit("adm_1", AdminRole::SecurityAdmin))
    );
    registry::revoke_admin_credential(&pool, "crd_adm_1", at(T0))
        .await
        .unwrap();
    for _ in 0..2 {
        // For the same operator or another, enabled or disabled.
        for (admin, status) in [("adm_1", E), ("adm_2", E), ("adm_2", D)] {
            assert_exists(
                registry::create_admin_credential(
                    &pool,
                    &credential("crd_new", admin, "key_1", status),
                )
                .await,
                "admin_credential_public_identity_key",
            );
        }
        assert_guard(Err::<(), _>(
            raw_error(&pool, "DELETE FROM admin_credential WHERE id = 'crd_adm_1'").await,
        ));
    }
    assert_not_found(registry::get_admin_credential(&pool, "crd_new").await);
    assert_eq!(
        authorize(&pool, "key_1", AdminRole::SecurityAdmin, INSTANCE)
            .await
            .unwrap(),
        None
    );
    // Only a different key may be registered.
    registry::create_admin_credential(&pool, &credential("crd_new", "adm_1", "key_1b", E))
        .await
        .unwrap();
    db.drop([pool]).await;
}

/// Real operators cannot take the IDs that bootstrap and recovery act
/// under. The check runs before any statement: on a closed pool, where any
/// statement fails with `PoolClosed`, a reserved ID is still
/// `ReservedActorId`.
#[tokio::test]
async fn reserved_actor_ids_fail_before_any_statement() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://registry-test.invalid/none")
        .unwrap();
    pool.close().await;
    assert_eq!(DEPLOYMENT_OPERATOR_ACTOR, "deployment_operator");
    assert_eq!(RECOVERY_KEY_ACTOR_PREFIX, "recovery_key:");
    for id in [
        DEPLOYMENT_OPERATOR_ACTOR.to_owned(),
        "recovery_key:".to_owned(),
        recovery_key_actor(1),
        recovery_key_actor(7),
        "recovery_key:x".to_owned(),
    ] {
        let err = registry::create_admin_identity(&pool, &identity(&id, E))
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::ReservedActorId), "{err:?}");
        // The error names no ID.
        assert!(!err.to_string().contains(&id), "{err}");
        // Also with a time that is out of range: the ID is checked first.
        let mut far = identity(&id, E);
        far.created_at = UNIX_EPOCH + Duration::from_micros(u64::try_from(i64::MAX).unwrap());
        assert!(matches!(
            registry::create_admin_identity(&pool, &far).await,
            Err(RegistryError::ReservedActorId)
        ));
    }
    // A look-alike reaches the pool.
    let err = registry::create_admin_identity(&pool, &identity("Deployment_Operator", E))
        .await
        .unwrap_err();
    assert!(
        matches!(err, RegistryError::Other(sqlx::Error::PoolClosed)),
        "{err:?}"
    );
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn reserved_actor_ids_are_never_written_and_look_alikes_are() {
    let (db, pool) = migrated().await;
    for id in [
        DEPLOYMENT_OPERATOR_ACTOR.to_owned(),
        recovery_key_actor(1),
        "recovery_key:".to_owned(),
    ] {
        assert!(matches!(
            registry::create_admin_identity(&pool, &identity(&id, E)).await,
            Err(RegistryError::ReservedActorId)
        ));
        assert_not_found(registry::get_admin_identity(&pool, &id).await);
    }
    // Exact and byte-wise: these are other IDs.
    for id in [
        "Deployment_Operator",
        "deployment_operator2",
        "recovery_key",
        "recovery-key:1",
        "adm_recovery_key:1",
    ] {
        registry::create_admin_identity(&pool, &identity(id, E))
            .await
            .unwrap();
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_identity \
         WHERE id = 'deployment_operator' OR starts_with(id, 'recovery_key:')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    db.drop([pool]).await;
}

/// One hit for each role and scope shape the schema allows, with the rows
/// that authorized it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn each_role_and_scope_shape_has_its_hit() {
    let (db, pool) = seeded().await;
    for (key, role, scope, admin) in [
        ("key_sec", AdminRole::SecurityAdmin, INSTANCE, "adm_sec"),
        ("key_trust", AdminRole::TrustAdmin, TEN_A, "adm_trust"),
        ("key_client", AdminRole::ClientAdmin, TEN_A, "adm_client"),
        ("key_prov", AdminRole::ProviderAdmin, TEN_A, "adm_prov"),
        ("key_audt", AdminRole::Auditor, TEN_A, "adm_audt"),
        ("key_audi", AdminRole::Auditor, INSTANCE, "adm_audi"),
        (
            "k\u{e9}y_uni",
            AdminRole::SecurityAdmin,
            INSTANCE,
            "adm_uni",
        ),
    ] {
        assert_eq!(
            authorize(&pool, key, role, scope).await.unwrap(),
            Some(hit(admin, role)),
            "{key} {role} {scope:?}"
        );
    }
    db.drop([pool]).await;
}

/// Every miss is the same `Ok(None)`: the same value, the same `Debug`
/// text, whichever check failed.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_miss_is_the_same_none() {
    let (db, pool) = seeded().await;
    let long = "k".repeat(10_000);
    let long_tenant = "t".repeat(10_000);
    let misses: Vec<(&str, &str, AdminRole, OperatorScope<'_>)> = vec![
        // Unknown, empty, over-long and near-miss keys (byte-wise: case,
        // whitespace, Unicode normalization).
        (
            "unknown key",
            "key_unknown",
            AdminRole::SecurityAdmin,
            INSTANCE,
        ),
        ("empty key", "", AdminRole::SecurityAdmin, INSTANCE),
        ("over-long key", &long, AdminRole::SecurityAdmin, INSTANCE),
        ("key case", "KEY_SEC", AdminRole::SecurityAdmin, INSTANCE),
        ("key prefix", "key_se", AdminRole::SecurityAdmin, INSTANCE),
        ("key suffix", "key_sec ", AdminRole::SecurityAdmin, INSTANCE),
        (
            "key leading space",
            " key_sec",
            AdminRole::SecurityAdmin,
            INSTANCE,
        ),
        (
            "key NFD",
            "ke\u{301}y_uni",
            AdminRole::SecurityAdmin,
            INSTANCE,
        ),
        (
            "key upper",
            "K\u{c9}Y_UNI",
            AdminRole::SecurityAdmin,
            INSTANCE,
        ),
        // Disabled identity, disabled credential, revoked credential and
        // disabled binding, each otherwise a hit.
        ("disabled identity", "key_off", AdminRole::TrustAdmin, TEN_A),
        (
            "disabled credential",
            "key_cdis",
            AdminRole::TrustAdmin,
            TEN_A,
        ),
        (
            "revoked credential",
            "key_rev",
            AdminRole::TrustAdmin,
            TEN_A,
        ),
        ("disabled binding", "key_bdis", AdminRole::TrustAdmin, TEN_A),
        // An operator with a credential and no binding, while other
        // operators hold every role and scope.
        (
            "no binding, trust",
            "key_nobind",
            AdminRole::TrustAdmin,
            TEN_A,
        ),
        (
            "no binding, sec",
            "key_nobind",
            AdminRole::SecurityAdmin,
            INSTANCE,
        ),
        (
            "no binding, audi",
            "key_nobind",
            AdminRole::Auditor,
            INSTANCE,
        ),
        ("no binding, audt", "key_nobind", AdminRole::Auditor, TEN_A),
        // Wrong, unknown, empty, over-long and near-miss tenants.
        ("wrong tenant", "key_trust", AdminRole::TrustAdmin, TEN_B),
        (
            "tenant auditor, other tenant",
            "key_audt",
            AdminRole::Auditor,
            TEN_B,
        ),
        (
            "unknown tenant",
            "key_trust",
            AdminRole::TrustAdmin,
            OperatorScope::Tenant("ten_x"),
        ),
        (
            "empty tenant",
            "key_trust",
            AdminRole::TrustAdmin,
            OperatorScope::Tenant(""),
        ),
        (
            "over-long tenant",
            "key_trust",
            AdminRole::TrustAdmin,
            OperatorScope::Tenant(&long_tenant),
        ),
        (
            "tenant case",
            "key_trust",
            AdminRole::TrustAdmin,
            OperatorScope::Tenant("TEN_A"),
        ),
        (
            "tenant space",
            "key_trust",
            AdminRole::TrustAdmin,
            OperatorScope::Tenant("ten_a "),
        ),
        // Wrong role.
        ("wrong role", "key_trust", AdminRole::ClientAdmin, TEN_A),
        (
            "wrong role 2",
            "key_client",
            AdminRole::ProviderAdmin,
            TEN_A,
        ),
        ("wrong role 3", "key_prov", AdminRole::TrustAdmin, TEN_A),
        // No inheritance (API-120): no role implies another.
        ("sec is not trust", "key_sec", AdminRole::TrustAdmin, TEN_A),
        (
            "sec is not client",
            "key_sec",
            AdminRole::ClientAdmin,
            TEN_A,
        ),
        (
            "sec is not provider",
            "key_sec",
            AdminRole::ProviderAdmin,
            TEN_A,
        ),
        (
            "sec is not tenant auditor",
            "key_sec",
            AdminRole::Auditor,
            TEN_A,
        ),
        (
            "sec is not instance auditor",
            "key_sec",
            AdminRole::Auditor,
            INSTANCE,
        ),
        (
            "trust is not auditor",
            "key_trust",
            AdminRole::Auditor,
            TEN_A,
        ),
        (
            "trust is not sec",
            "key_trust",
            AdminRole::SecurityAdmin,
            INSTANCE,
        ),
        (
            "auditor is not trust",
            "key_audt",
            AdminRole::TrustAdmin,
            TEN_A,
        ),
        (
            "instance auditor is not sec",
            "key_audi",
            AdminRole::SecurityAdmin,
            INSTANCE,
        ),
        // Instance against tenant scope, fail-closed both ways.
        (
            "instance auditor, tenant request",
            "key_audi",
            AdminRole::Auditor,
            TEN_A,
        ),
        (
            "tenant auditor, instance request",
            "key_audt",
            AdminRole::Auditor,
            INSTANCE,
        ),
        (
            "security_admin, tenant request",
            "key_sec",
            AdminRole::SecurityAdmin,
            TEN_A,
        ),
        (
            "trust_admin, instance request",
            "key_trust",
            AdminRole::TrustAdmin,
            INSTANCE,
        ),
        (
            "client_admin, instance request",
            "key_client",
            AdminRole::ClientAdmin,
            INSTANCE,
        ),
        (
            "provider_admin, instance request",
            "key_prov",
            AdminRole::ProviderAdmin,
            INSTANCE,
        ),
        // A disabled or revoked key with the wrong scope too.
        (
            "disabled identity, instance",
            "key_off",
            AdminRole::TrustAdmin,
            INSTANCE,
        ),
        (
            "revoked credential, wrong role",
            "key_rev",
            AdminRole::Auditor,
            TEN_A,
        ),
    ];
    for (name, key, role, scope) in misses {
        let result = authorize(&pool, key, role, scope).await;
        assert!(matches!(result, Ok(None)), "{name}: {result:?}");
        assert_eq!(format!("{result:?}"), "Ok(None)", "{name}");
    }
    // Every miss above would be a hit if it named the right key, role and
    // scope; the seed's hits still hold.
    assert!(
        authorize(&pool, "key_trust", AdminRole::TrustAdmin, TEN_A)
            .await
            .unwrap()
            .is_some()
    );
    db.drop([pool]).await;
}

/// A store failure is an `Err`, not a miss; a NUL character is one, as
/// everywhere in the registry.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_nul_character_is_a_store_error_not_a_miss() {
    let (db, pool) = seeded().await;
    for (key, scope) in [
        ("key_sec\0", INSTANCE),
        ("key_trust", OperatorScope::Tenant("ten_a\0")),
    ] {
        let err = authorize(&pool, key, AdminRole::TrustAdmin, scope)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::Other(_)), "{err:?}");
        assert_eq!(sqlstate(&err).as_deref(), Some("22021"));
    }
    db.drop([pool]).await;
}

/// The lookup follows the rows: a disabled binding, a disabled identity and
/// a revoked credential each turn a hit into the same `None`, and the
/// lookup writes nothing (it runs in a read-only transaction and leaves no
/// audit event or administrative operation).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_lookup_follows_the_rows_and_writes_nothing() {
    let (db, pool) = seeded().await;
    let trust = || authorize(&pool, "key_trust", AdminRole::TrustAdmin, TEN_A);
    let expected = Some(hit("adm_trust", AdminRole::TrustAdmin));
    assert_eq!(trust().await.unwrap(), expected);

    let mut conn = pool.acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    sqlx::raw_sql("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        authorize_operator(
            &mut *tx,
            &request("key_trust", AdminRole::TrustAdmin, TEN_A)
        )
        .await
        .unwrap(),
        expected
    );
    assert_eq!(
        authorize_operator(&mut *tx, &request("key_off", AdminRole::TrustAdmin, TEN_A))
            .await
            .unwrap(),
        None
    );
    tx.commit().await.unwrap();
    drop(conn);
    let (events, operations): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM audit_event), \
         (SELECT count(*) FROM administrative_operation)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((events, operations), (0, 0));

    let off = AdminRoleBindingChanges {
        status: Status::Disabled,
    };
    let on = AdminRoleBindingChanges {
        status: Status::Enabled,
    };
    registry::update_admin_role_binding(&pool, "rb_adm_trust", 1, &off)
        .await
        .unwrap();
    assert_eq!(trust().await.unwrap(), None);
    registry::update_admin_role_binding(&pool, "rb_adm_trust", 2, &on)
        .await
        .unwrap();
    assert_eq!(trust().await.unwrap(), expected);
    // A second credential of the same operator authorizes on its own.
    registry::create_admin_credential(
        &pool,
        &credential("crd_trust_2", "adm_trust", "key_trust_2", E),
    )
    .await
    .unwrap();
    registry::revoke_admin_credential(&pool, "crd_adm_trust", at(T0))
        .await
        .unwrap();
    assert_eq!(trust().await.unwrap(), None);
    assert_eq!(
        authorize(&pool, "key_trust_2", AdminRole::TrustAdmin, TEN_A)
            .await
            .unwrap(),
        Some(AuthorizedOperator {
            admin_id: "adm_trust".into(),
            credential_id: "crd_trust_2".into(),
            binding_id: "rb_adm_trust".into(),
            role: AdminRole::TrustAdmin,
        })
    );
    registry::disable_admin_identity(&pool, "adm_trust")
        .await
        .unwrap();
    assert_eq!(
        authorize(&pool, "key_trust_2", AdminRole::TrustAdmin, TEN_A)
            .await
            .unwrap(),
        None
    );
    db.drop([pool]).await;
}

/// An operator with several bindings gets exactly the one it asked for.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_operator_with_several_bindings_gets_the_one_requested() {
    let (db, pool) = migrated().await;
    tenants(&pool).await;
    operator(&pool, "adm_m", E, "key_m", E, AdminRole::Auditor, None, E).await;
    for (id, role, tenant, status) in [
        ("rb_m_ta", AdminRole::TrustAdmin, Some("ten_a"), E),
        ("rb_m_tb", AdminRole::TrustAdmin, Some("ten_b"), D),
        ("rb_m_aa", AdminRole::Auditor, Some("ten_a"), E),
        ("rb_m_sec", AdminRole::SecurityAdmin, None, D),
    ] {
        registry::create_admin_role_binding(&pool, &binding(id, "adm_m", role, tenant, status))
            .await
            .unwrap();
    }
    for (role, scope, binding_id) in [
        (AdminRole::Auditor, INSTANCE, Some("rb_adm_m")),
        (AdminRole::Auditor, TEN_A, Some("rb_m_aa")),
        (AdminRole::TrustAdmin, TEN_A, Some("rb_m_ta")),
        (AdminRole::TrustAdmin, TEN_B, None),
        (AdminRole::SecurityAdmin, INSTANCE, None),
        (AdminRole::Auditor, TEN_B, None),
        (AdminRole::ClientAdmin, TEN_A, None),
    ] {
        let found = authorize(&pool, "key_m", role, scope).await.unwrap();
        assert_eq!(
            found.as_ref().map(|found| &found.binding_id[..]),
            binding_id,
            "{role} {scope:?}"
        );
        if let Some(found) = found {
            assert_eq!(
                (&found.admin_id[..], &found.credential_id[..], found.role),
                ("adm_m", "crd_adm_m", role)
            );
        }
    }
    db.drop([pool]).await;
}

/// `revoked_at IS NULL` is checked on its own, not only through `status`:
/// with `admin_credential_revoked_disabled_check` dropped (as the table
/// owner can), a revoked credential set back to `enabled` still authorizes
/// nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_revoked_credential_is_refused_even_without_the_status_check() {
    let (db, pool) = migrated().await;
    tenants(&pool).await;
    for (admin, key) in [("adm_1", "key_1"), ("adm_2", "key_2")] {
        operator(
            &pool,
            admin,
            E,
            key,
            E,
            AdminRole::TrustAdmin,
            Some("ten_a"),
            E,
        )
        .await;
    }
    registry::revoke_admin_credential(&pool, "crd_adm_1", at(T0))
        .await
        .unwrap();
    sqlx::raw_sql(
        "ALTER TABLE admin_credential DROP CONSTRAINT admin_credential_revoked_disabled_check;
         UPDATE admin_credential SET status = 'enabled' WHERE id = 'crd_adm_1';",
    )
    .execute(&pool)
    .await
    .unwrap();
    let revoked = registry::get_admin_credential(&pool, "crd_adm_1")
        .await
        .unwrap();
    assert_eq!(
        (revoked.status, revoked.revoked_at),
        (Status::Enabled, Some(at(T0)))
    );
    assert_eq!(
        authorize(&pool, "key_1", AdminRole::TrustAdmin, TEN_A)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        authorize(&pool, "key_2", AdminRole::TrustAdmin, TEN_A)
            .await
            .unwrap(),
        Some(hit("adm_2", AdminRole::TrustAdmin))
    );
    db.drop([pool]).await;
}
