//! The compare-and-set updates of tenants, principals and trust keyset
//! versions (`persistence::registry`, on the revisions `0007` adds) against
//! a real PostgreSQL server: patches, stale and missing rows, tenant
//! scoping, the columns an update keeps, empty patches and concurrent
//! updates under `READ COMMITTED`.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database. They claim no
//! conformance scenario.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    error::Error as _,
    fmt::Debug,
    time::{Duration, UNIX_EPOCH},
};

use common::TestDb;
use serde_json::{Value, json};
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, InvariantKind, JsonObject, NewPrincipal, NewTenant, NewTrustKeyset,
        NewTrustKeysetVersion, Page, PrincipalKind, PrincipalPatch, RegistryError, Status,
        TenantPatch, TrustKeysetChanges,
    },
};
use sqlx::{Connection, PgConnection, PgExecutor, postgres::PgPoolOptions};

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
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

fn new_version(tenant_id: &str, id: &str, keyset_id: &str) -> NewTrustKeysetVersion {
    NewTrustKeysetVersion {
        id: id.into(),
        tenant_id: tenant_id.into(),
        keyset_id: keyset_id.into(),
        public_jwks: object(json!({
            "keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AA", "y": "AA"}]
        })),
        fingerprint: "sha256:01".into(),
        effective_at: UNIX_EPOCH + Duration::from_micros(1_767_323_045_678_901),
        expires_at: Some(UNIX_EPOCH + Duration::from_micros(1_798_859_045_000_001)),
        status: Status::Enabled,
        provenance: object(json!({"uploaded_by": "adm_1"})),
    }
}

fn name(name: &str) -> TenantPatch {
    TenantPatch {
        name: Some(name.into()),
        ..TenantPatch::default()
    }
}

fn status(status: Status) -> TenantPatch {
    TenantPatch {
        status: Some(status),
        ..TenantPatch::default()
    }
}

fn principal_patch(patch: TenantPatch) -> PrincipalPatch {
    PrincipalPatch {
        name: patch.name,
        status: patch.status,
    }
}

/// Tenants `ten_a` and `ten_b`; in `ten_a` the workload `wld_1` and the
/// human `usr_1`, in `ten_b` the workload `wld_b`; in each tenant a keyset
/// (`ks_1`, `ks_b`) with one version (`kv_1`, `kv_b`). Every row is at
/// revision 1.
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    for tenant in ["ten_a", "ten_b"] {
        registry::create_tenant(&pool, &new_tenant(tenant))
            .await
            .unwrap();
    }
    for (tenant, id, kind) in [
        ("ten_a", "wld_1", PrincipalKind::Workload),
        ("ten_a", "usr_1", PrincipalKind::Human),
        ("ten_b", "wld_b", PrincipalKind::Workload),
    ] {
        registry::create_principal(&pool, &new_principal(tenant, id, kind))
            .await
            .unwrap();
    }
    for (tenant, keyset, version) in [("ten_a", "ks_1", "kv_1"), ("ten_b", "ks_b", "kv_b")] {
        registry::create_trust_keyset(
            &pool,
            &NewTrustKeyset {
                id: keyset.into(),
                tenant_id: tenant.into(),
                name: "partner".into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        registry::create_trust_keyset_version(&pool, &new_version(tenant, version, keyset))
            .await
            .unwrap();
    }
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
fn assert_check<T: Debug>(result: Result<T, RegistryError>, name: &str) {
    match result {
        Err(RegistryError::Invariant {
            kind: InvariantKind::Check,
            constraint: Some(constraint),
        }) => assert_eq!(constraint, name),
        other => panic!("expected check {name}: {other:?}"),
    }
}

/// An empty patch is the encode error "empty patch", wrapped in `Other`.
#[track_caller]
fn assert_empty_patch<T: Debug>(result: Result<T, RegistryError>) {
    match result {
        Err(RegistryError::Other(sqlx::Error::Encode(err))) => {
            assert_eq!(err.to_string(), "empty patch");
        }
        other => panic!("expected an empty-patch error: {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn tenants_change_the_patched_columns_by_revision_compare_and_set() {
    let (db, pool) = seeded().await;
    let created = registry::get_tenant(&pool, "ten_a").await.unwrap();
    assert_eq!(created.revision, 1);

    let renamed = registry::update_tenant(&pool, "ten_a", 1, &name("Renamed"))
        .await
        .unwrap();
    assert_eq!((&renamed.name[..], renamed.revision), ("Renamed", 2));
    // Columns outside the patch keep their values, the immutable ones too.
    assert_eq!(
        (
            &renamed.id[..],
            &renamed.secret_namespace[..],
            renamed.status,
            renamed.created_at
        ),
        ("ten_a", "ns_ten_a", Status::Enabled, created.created_at)
    );
    let disabled = registry::update_tenant(&pool, "ten_a", 2, &status(Status::Disabled))
        .await
        .unwrap();
    assert_eq!(
        (&disabled.name[..], disabled.status, disabled.revision),
        ("Renamed", Status::Disabled, 3)
    );
    // Re-enabling is a plain status change.
    let both = TenantPatch {
        name: Some("Both".into()),
        status: Some(Status::Enabled),
    };
    let reenabled = registry::update_tenant(&pool, "ten_a", 3, &both)
        .await
        .unwrap();
    assert_eq!(
        (&reenabled.name[..], reenabled.status, reenabled.revision),
        ("Both", Status::Enabled, 4)
    );
    // Setting a column to its current value still advances the revision.
    let same = registry::update_tenant(&pool, "ten_a", 4, &name("Both"))
        .await
        .unwrap();
    assert_eq!(same.revision, 5);
    assert_eq!(registry::get_tenant(&pool, "ten_a").await.unwrap(), same);
    let listed = registry::list_tenants(&pool, Page::first(10))
        .await
        .unwrap();
    assert_eq!(listed[0], same);

    for expected in [1, 4, 6, i64::MAX, i64::MIN] {
        assert_stale(registry::update_tenant(&pool, "ten_a", expected, &name("Stale")).await);
    }
    for expected in [1, 5, i64::MAX] {
        assert_not_found(registry::update_tenant(&pool, "ten_x", expected, &name("X")).await);
    }
    assert_check(
        registry::update_tenant(&pool, "ten_a", 5, &name("")).await,
        "tenant_name_check",
    );
    assert_eq!(registry::get_tenant(&pool, "ten_a").await.unwrap(), same);
    // The other tenant is untouched.
    assert_eq!(
        registry::get_tenant(&pool, "ten_b").await.unwrap().revision,
        1
    );
    // A name-only patch keeps a disabled tenant disabled.
    registry::update_tenant(&pool, "ten_b", 1, &status(Status::Disabled))
        .await
        .unwrap();
    let renamed = registry::update_tenant(&pool, "ten_b", 2, &name("Dormant"))
        .await
        .unwrap();
    assert_eq!(
        (&renamed.name[..], renamed.status, renamed.revision),
        ("Dormant", Status::Disabled, 3)
    );
    db.drop([pool]).await;
}

/// `0002` has no unique constraint on a tenant's or a principal's name, so
/// a rename to a name in use succeeds; constraint errors of an update map by
/// name as for every other write.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn tenant_and_principal_names_need_not_be_unique() {
    let (db, pool) = seeded().await;
    let unique: Vec<String> = sqlx::query_scalar(
        "SELECT conname::text FROM pg_constraint
         WHERE contype IN ('u', 'p') AND conrelid IN ('tenant'::regclass, 'principal'::regclass)
         ORDER BY conname::text COLLATE \"C\"",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        unique,
        [
            "principal_pkey",
            "principal_tenant_id_id_key",
            "principal_tenant_id_id_kind_key",
            "tenant_pkey",
            "tenant_secret_namespace_key"
        ]
    );
    let renamed = registry::update_tenant(&pool, "ten_b", 1, &name("Tenant ten_a"))
        .await
        .unwrap();
    assert_eq!(renamed.name, "Tenant ten_a");
    let renamed = registry::update_principal(
        &pool,
        "ten_a",
        "usr_1",
        1,
        &principal_patch(name("principal wld_1")),
    )
    .await
    .unwrap();
    assert_eq!(renamed.name, "principal wld_1");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn principals_change_within_their_tenant_whatever_their_kind() {
    let (db, pool) = seeded().await;
    let created = registry::get_principal(&pool, "ten_a", "wld_1")
        .await
        .unwrap();
    assert_eq!(created.revision, 1);
    let renamed =
        registry::update_principal(&pool, "ten_a", "wld_1", 1, &principal_patch(name("deploy")))
            .await
            .unwrap();
    assert_eq!(
        (
            &renamed.id[..],
            &renamed.tenant_id[..],
            renamed.kind,
            &renamed.name[..],
            renamed.status,
            renamed.created_at,
            renamed.revision
        ),
        (
            "wld_1",
            "ten_a",
            PrincipalKind::Workload,
            "deploy",
            Status::Enabled,
            created.created_at,
            2
        )
    );
    let disabled = registry::update_principal(
        &pool,
        "ten_a",
        "wld_1",
        2,
        &principal_patch(status(Status::Disabled)),
    )
    .await
    .unwrap();
    assert_eq!(
        (&disabled.name[..], disabled.status, disabled.revision),
        ("deploy", Status::Disabled, 3)
    );
    let reenabled = registry::update_principal(
        &pool,
        "ten_a",
        "wld_1",
        3,
        &principal_patch(status(Status::Enabled)),
    )
    .await
    .unwrap();
    assert_eq!((reenabled.status, reenabled.revision), (Status::Enabled, 4));
    assert_eq!(
        registry::get_principal(&pool, "ten_a", "wld_1")
            .await
            .unwrap(),
        reenabled
    );
    // Kind-agnostic: a human principal changes the same way.
    let human = registry::update_principal(
        &pool,
        "ten_a",
        "usr_1",
        1,
        &PrincipalPatch {
            name: Some("alice".into()),
            status: Some(Status::Disabled),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        (human.kind, &human.name[..], human.status, human.revision),
        (PrincipalKind::Human, "alice", Status::Disabled, 2)
    );

    // Another tenant's principal is not found, whatever the revision: never
    // stale, which would tell the caller it exists.
    for expected in [1, 4, 5, i64::MAX] {
        assert_not_found(
            registry::update_principal(
                &pool,
                "ten_b",
                "wld_1",
                expected,
                &principal_patch(name("x")),
            )
            .await,
        );
        assert_not_found(
            registry::update_principal(
                &pool,
                "ten_a",
                "wld_b",
                expected,
                &principal_patch(name("x")),
            )
            .await,
        );
    }
    assert_not_found(
        registry::update_principal(&pool, "ten_a", "prn_x", 1, &principal_patch(name("x"))).await,
    );
    assert_not_found(
        registry::update_principal(&pool, "ten_x", "wld_1", 4, &principal_patch(name("x"))).await,
    );
    for expected in [1, 3, 5, i64::MAX] {
        assert_stale(
            registry::update_principal(
                &pool,
                "ten_a",
                "wld_1",
                expected,
                &principal_patch(name("x")),
            )
            .await,
        );
    }
    assert_check(
        registry::update_principal(&pool, "ten_a", "wld_1", 4, &principal_patch(name(""))).await,
        "principal_name_check",
    );
    assert_eq!(
        registry::get_principal(&pool, "ten_a", "wld_1")
            .await
            .unwrap(),
        reenabled
    );
    assert_eq!(
        registry::get_principal(&pool, "ten_b", "wld_b")
            .await
            .unwrap()
            .revision,
        1
    );
    // A name-only patch keeps a disabled principal disabled.
    let renamed =
        registry::update_principal(&pool, "ten_a", "usr_1", 2, &principal_patch(name("bob")))
            .await
            .unwrap();
    assert_eq!(
        (&renamed.name[..], renamed.status, renamed.revision),
        ("bob", Status::Disabled, 3)
    );
    // Setting a column to its current value still advances the revision.
    let same =
        registry::update_principal(&pool, "ten_a", "usr_1", 3, &principal_patch(name("bob")))
            .await
            .unwrap();
    let mut expected = renamed.clone();
    expected.revision = 4;
    assert_eq!(same, expected);
    assert_eq!(
        registry::get_principal(&pool, "ten_a", "usr_1")
            .await
            .unwrap(),
        same
    );
    let listed = registry::list_principals(&pool, "ten_a", Page::first(10))
        .await
        .unwrap();
    assert!(listed.contains(&same), "{listed:?}");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn keyset_versions_change_only_status_by_their_own_revision() {
    let (db, pool) = seeded().await;
    let created = registry::get_trust_keyset_version(&pool, "ten_a", "kv_1")
        .await
        .unwrap();
    assert_eq!((created.status, created.revision), (Status::Enabled, 1));

    let disabled =
        registry::update_trust_keyset_version(&pool, "ten_a", "kv_1", 1, Status::Disabled)
            .await
            .unwrap();
    // Every column but status and revision keeps its value.
    let mut expected = created.clone();
    expected.status = Status::Disabled;
    expected.revision = 2;
    assert_eq!(disabled, expected);
    let reenabled =
        registry::update_trust_keyset_version(&pool, "ten_a", "kv_1", 2, Status::Enabled)
            .await
            .unwrap();
    assert_eq!((reenabled.status, reenabled.revision), (Status::Enabled, 3));
    // An unchanged status still advances the revision.
    let same = registry::update_trust_keyset_version(&pool, "ten_a", "kv_1", 3, Status::Enabled)
        .await
        .unwrap();
    assert_eq!(same.revision, 4);
    assert_eq!(
        registry::get_trust_keyset_version(&pool, "ten_a", "kv_1")
            .await
            .unwrap(),
        same
    );
    assert_eq!(
        registry::list_trust_keyset_versions(&pool, "ten_a", "ks_1", Page::first(10))
            .await
            .unwrap(),
        std::slice::from_ref(&same)
    );

    // The keyset's revision is not tied to its versions', either way.
    let keyset = registry::get_trust_keyset(&pool, "ten_a", "ks_1")
        .await
        .unwrap();
    assert_eq!(keyset.revision, 1);
    registry::update_trust_keyset(
        &pool,
        "ten_a",
        "ks_1",
        1,
        &TrustKeysetChanges {
            name: "renamed".into(),
            status: Status::Disabled,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        registry::get_trust_keyset_version(&pool, "ten_a", "kv_1")
            .await
            .unwrap(),
        same
    );
    assert_stale(
        registry::update_trust_keyset_version(&pool, "ten_a", "kv_1", 2, Status::Disabled).await,
    );

    for expected in [1, 4, 5, i64::MAX] {
        assert_not_found(
            registry::update_trust_keyset_version(
                &pool,
                "ten_b",
                "kv_1",
                expected,
                Status::Disabled,
            )
            .await,
        );
        assert_not_found(
            registry::update_trust_keyset_version(
                &pool,
                "ten_a",
                "kv_b",
                expected,
                Status::Disabled,
            )
            .await,
        );
    }
    assert_not_found(
        registry::update_trust_keyset_version(&pool, "ten_a", "kv_x", 1, Status::Disabled).await,
    );
    for expected in [1, 3, 5, i64::MAX, i64::MIN] {
        assert_stale(
            registry::update_trust_keyset_version(
                &pool,
                "ten_a",
                "kv_1",
                expected,
                Status::Disabled,
            )
            .await,
        );
    }
    assert_eq!(
        registry::get_trust_keyset_version(&pool, "ten_a", "kv_1")
            .await
            .unwrap(),
        same
    );
    assert_eq!(
        registry::get_trust_keyset_version(&pool, "ten_b", "kv_b")
            .await
            .unwrap()
            .revision,
        1
    );
    db.drop([pool]).await;
}

/// The marker for an unreadable time cannot collide with a stored one:
/// tenant rows at both bounds of the `0007` range checks, and a principal
/// at the upper one, read back as themselves by a get, a list (tenants
/// only) and the row an update returns, the latest at `i64::MAX - 1`
/// microseconds, one below the marker.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn times_at_the_range_check_bounds_read_back_exactly() {
    const EARLIEST: i64 = -210_866_803_200_000_000;
    const LATEST: i64 = i64::MAX - 1;
    let at = |micros: i64| {
        let offset = Duration::from_micros(micros.unsigned_abs());
        if micros >= 0 {
            UNIX_EPOCH + offset
        } else {
            UNIX_EPOCH - offset
        }
    };
    let (db, pool) = seeded().await;
    sqlx::raw_sql(
        "INSERT INTO tenant (id, name, secret_namespace, status, created_at) VALUES
             ('ten_early', 'early', 'ns_early', 'enabled', '4714-11-24 00:00:00+00 BC'),
             ('ten_late', 'late', 'ns_late', 'enabled', '294247-01-10 04:00:54.775806+00');
         INSERT INTO principal (id, tenant_id, kind, name, status, created_at) VALUES
             ('wld_late', 'ten_late', 'workload', 'late', 'enabled',
              '294247-01-10 04:00:54.775806+00')",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (id, micros) in [("ten_early", EARLIEST), ("ten_late", LATEST)] {
        let tenant = registry::get_tenant(&pool, id).await.unwrap();
        assert_eq!(tenant.created_at, at(micros), "{id}");
        let updated = registry::update_tenant(&pool, id, 1, &name("renamed"))
            .await
            .unwrap();
        assert_eq!(updated.created_at, at(micros), "{id}");
    }
    let listed: Vec<_> = registry::list_tenants(&pool, Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .filter(|tenant| tenant.id == "ten_early" || tenant.id == "ten_late")
        .map(|tenant| tenant.created_at)
        .collect();
    assert_eq!(listed, [at(EARLIEST), at(LATEST)]);
    let principal = registry::get_principal(&pool, "ten_late", "wld_late")
        .await
        .unwrap();
    assert_eq!(principal.created_at, at(LATEST));
    let updated = registry::update_principal(
        &pool,
        "ten_late",
        "wld_late",
        1,
        &principal_patch(name("x")),
    )
    .await
    .unwrap();
    assert_eq!(updated.created_at, at(LATEST));
    db.drop([pool]).await;
}

/// An empty patch fails before any statement: on a closed pool, where any
/// statement would fail with `PoolClosed`, it is still the encode error.
#[tokio::test]
async fn empty_patches_fail_before_any_statement() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://registry-test.invalid/none")
        .unwrap();
    pool.close().await;
    assert_empty_patch(registry::update_tenant(&pool, "ten_a", 1, &TenantPatch::default()).await);
    assert_empty_patch(
        registry::update_principal(&pool, "ten_a", "wld_1", 1, &PrincipalPatch::default()).await,
    );
    // The same calls with a column set do reach the pool.
    for err in [
        registry::update_tenant(&pool, "ten_a", 1, &name("x"))
            .await
            .unwrap_err(),
        registry::update_principal(&pool, "ten_a", "wld_1", 1, &principal_patch(name("x")))
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(err, RegistryError::Other(sqlx::Error::PoolClosed)),
            "{err:?}"
        );
    }
    let err = registry::update_tenant(&pool, "ten_a", 1, &TenantPatch::default())
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "registry database error");
    assert!(err.source().is_some());
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn empty_patches_leave_the_row_and_its_revision_unchanged() {
    let (db, pool) = seeded().await;
    let tenant = registry::get_tenant(&pool, "ten_a").await.unwrap();
    let principal = registry::get_principal(&pool, "ten_a", "wld_1")
        .await
        .unwrap();
    // Also for a missing row: the patch is checked first.
    for id in ["ten_a", "ten_x"] {
        assert_empty_patch(registry::update_tenant(&pool, id, 1, &TenantPatch::default()).await);
    }
    for id in ["wld_1", "prn_x"] {
        assert_empty_patch(
            registry::update_principal(&pool, "ten_a", id, 1, &PrincipalPatch::default()).await,
        );
    }
    assert_eq!(registry::get_tenant(&pool, "ten_a").await.unwrap(), tenant);
    assert_eq!(
        registry::get_principal(&pool, "ten_a", "wld_1")
            .await
            .unwrap(),
        principal
    );
    db.drop([pool]).await;
}

/// The three updates, each from revision 1, setting the status.
#[derive(Debug, Clone, Copy)]
enum Target {
    Tenant,
    Principal,
    Version,
}

const TARGETS: [Target; 3] = [Target::Tenant, Target::Principal, Target::Version];

impl Target {
    /// Updates the target's row from revision 1 and returns its status and
    /// new revision.
    async fn update<'e>(
        self,
        executor: impl PgExecutor<'e>,
        to: Status,
    ) -> Result<(Status, i64), RegistryError> {
        match self {
            Self::Tenant => registry::update_tenant(executor, "ten_a", 1, &status(to))
                .await
                .map(|row| (row.status, row.revision)),
            Self::Principal => registry::update_principal(
                executor,
                "ten_a",
                "wld_1",
                1,
                &principal_patch(status(to)),
            )
            .await
            .map(|row| (row.status, row.revision)),
            Self::Version => {
                registry::update_trust_keyset_version(executor, "ten_a", "kv_1", 1, to)
                    .await
                    .map(|row| (row.status, row.revision))
            }
        }
    }

    /// The target's current status and revision.
    async fn current(self, pool: &PgPool) -> (Status, i64) {
        match self {
            Self::Tenant => {
                let row = registry::get_tenant(pool, "ten_a").await.unwrap();
                (row.status, row.revision)
            }
            Self::Principal => {
                let row = registry::get_principal(pool, "ten_a", "wld_1")
                    .await
                    .unwrap();
                (row.status, row.revision)
            }
            Self::Version => {
                let row = registry::get_trust_keyset_version(pool, "ten_a", "kv_1")
                    .await
                    .unwrap();
                (row.status, row.revision)
            }
        }
    }
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
    .expect("the second updater never waited for the row lock");
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// Under `READ COMMITTED` the second of two updates from one revision waits
/// for the first's row lock and, once the first commits, is stale.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_update_from_one_revision_is_stale_after_the_first_commits() {
    for target in TARGETS {
        let (db, pool) = seeded().await;
        let mut first = pool.acquire().await.unwrap().detach();
        let mut second = pool.acquire().await.unwrap().detach();
        let level: String = sqlx::query_scalar("SHOW transaction_isolation")
            .fetch_one(&mut second)
            .await
            .unwrap();
        assert_eq!(level, "read committed");
        let (first_pid, second_pid) = (
            backend_pid(&mut first).await,
            backend_pid(&mut second).await,
        );
        let mut tx = first.begin().await.unwrap();
        assert_eq!(
            target.update(&mut *tx, Status::Disabled).await.unwrap(),
            (Status::Disabled, 2)
        );
        let waiting = tokio::spawn(async move {
            let outcome = target.update(&mut second, Status::Enabled).await;
            (outcome, second)
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        assert!(!waiting.is_finished(), "{target:?}");
        tx.commit().await.unwrap();
        let (outcome, second) = waiting.await.unwrap();
        assert_stale(outcome);
        assert_eq!(
            target.current(&pool).await,
            (Status::Disabled, 2),
            "{target:?}"
        );
        drop((first, second));
        db.drop([pool]).await;
    }
}

/// Of several concurrent updates from one revision exactly one succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_updates_from_one_revision_have_exactly_one_winner() {
    let (db, pool) = seeded().await;
    for target in TARGETS {
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { target.update(&pool, Status::Disabled).await })
            })
            .collect();
        let (mut won, mut stale) = (0, 0);
        for task in tasks {
            match task.await.unwrap() {
                Ok(outcome) => {
                    assert_eq!(outcome, (Status::Disabled, 2));
                    won += 1;
                }
                Err(RegistryError::StaleRevision) => stale += 1,
                Err(other) => panic!("{target:?}: {other:?}"),
            }
        }
        assert_eq!((won, stale), (1, 3), "{target:?}");
        assert_eq!(target.current(&pool).await, (Status::Disabled, 2));
    }
    db.drop([pool]).await;
}

/// An update composes with other statements in a caller transaction and
/// rolls back with it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn updates_roll_back_with_the_callers_transaction() {
    let (db, pool) = seeded().await;
    let before: Vec<(Status, i64)> = {
        let mut rows = vec![];
        for target in TARGETS {
            rows.push(target.current(&pool).await);
        }
        rows
    };
    let mut tx = pool.begin().await.unwrap();
    for target in TARGETS {
        target.update(&mut *tx, Status::Disabled).await.unwrap();
    }
    tx.rollback().await.unwrap();
    for (target, before) in TARGETS.into_iter().zip(before) {
        assert_eq!(target.current(&pool).await, before);
    }
    db.drop([pool]).await;
}
