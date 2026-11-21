//! The typed registry surface (`persistence::registry`) against a real
//! PostgreSQL server: each function's result, not-found and stale-revision
//! outcomes, the mapping of constraint errors and of serialization
//! failures and deadlocks, tenant-scoped reads, pages, and checker tenant
//! rows.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. They claim no conformance
//! scenario.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    error::Error as _,
    fmt::Debug,
    time::{Duration, SystemTime},
};

use common::TestDb;
use serde_json::json;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, AudienceTenantAssignmentChanges, EgressPurpose, InvariantKind, KNOWN_CONSTRAINTS,
        MAX_PAGE_SIZE, NewAudienceTenantAssignment, NewPrincipal, NewResourceAction,
        NewResourceServer, NewResourceServerChecker, NewTenant, Page, PrincipalKind, Profile,
        RegistryError, ResourceActionChanges, ResourceServerChanges, ResourceServerCheckerChanges,
        Status,
    },
};
use sqlx::{Connection, Executor, PgConnection, Postgres};

async fn migrated() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    (db, pool)
}

async fn run<'c>(executor: impl Executor<'c, Database = Postgres>, sql: &'static str) {
    if let Err(err) = sqlx::raw_sql(sql).execute(executor).await {
        panic!("{sql}: {err}");
    }
}

/// The registry error of a raw statement that must fail.
async fn raw_error(pool: &PgPool, sql: &'static str) -> RegistryError {
    let err = sqlx::raw_sql(sql).execute(pool).await.expect_err(sql);
    RegistryError::from(err)
}

fn new_tenant(id: &str, secret_namespace: &str) -> NewTenant {
    NewTenant {
        id: id.into(),
        name: format!("Tenant {id}"),
        secret_namespace: secret_namespace.into(),
        status: Status::Enabled,
    }
}

fn new_principal(tenant_id: &str, id: &str) -> NewPrincipal {
    NewPrincipal {
        id: id.into(),
        tenant_id: tenant_id.into(),
        kind: PrincipalKind::Workload,
        name: format!("principal {id}"),
        status: Status::Enabled,
    }
}

fn new_server(id: &str, audience: &str) -> NewResourceServer {
    NewResourceServer {
        id: id.into(),
        audience: audience.into(),
        name: format!("Server {id}"),
        allowed_profiles: vec![Profile::Wif, Profile::HumanCli],
        scopes: vec!["projects:read".into(), "projects:write".into()],
        constraint_versions: vec![json!(1)],
        status: Status::Enabled,
    }
}

fn server_changes(name: &str) -> ResourceServerChanges {
    ResourceServerChanges {
        name: name.into(),
        allowed_profiles: vec![Profile::HumanSession],
        scopes: vec!["billing:read".into()],
        constraint_versions: vec![json!("v2"), json!({"major": 2})],
        status: Status::Disabled,
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
        allowed_scopes: vec!["projects:read".into()],
        constraint_versions: vec![json!(1)],
        status: Status::Enabled,
    }
}

fn new_checker(id: &str, resource_server_id: &str, identity: &str) -> NewResourceServerChecker {
    NewResourceServerChecker {
        id: id.into(),
        resource_server_id: resource_server_id.into(),
        public_mtls_identity: identity.into(),
        status: Status::Enabled,
    }
}

fn new_action(id: &str, resource_server_id: &str, action_name: &str) -> NewResourceAction {
    NewResourceAction {
        id: id.into(),
        resource_server_id: resource_server_id.into(),
        action_name: action_name.into(),
        required_scopes: vec!["projects:read".into()],
        accepted_profiles: vec![Profile::Wif],
        required_resource_dimensions: vec!["project".into()],
        live_check_required: true,
        status: Status::Enabled,
    }
}

/// Tenants `ten_a` and `ten_b`, resource servers `rs_1` and `rs_2`, and
/// assignments of `rs_1` to `ten_a` and of `rs_2` to `ten_b`.
async fn seeded() -> (TestDb, PgPool) {
    let (db, pool) = migrated().await;
    for (id, ns) in [("ten_a", "ns_a"), ("ten_b", "ns_b")] {
        registry::create_tenant(&pool, &new_tenant(id, ns))
            .await
            .unwrap();
    }
    for (id, audience) in [("rs_1", "control-plane-api"), ("rs_2", "billing-api")] {
        registry::create_resource_server(&pool, &new_server(id, audience))
            .await
            .unwrap();
    }
    for (id, rs, tenant) in [("ata_1", "rs_1", "ten_a"), ("ata_2", "rs_2", "ten_b")] {
        registry::create_audience_tenant_assignment(&pool, &new_assignment(id, rs, tenant))
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
        }) => assert_eq!((actual, constraint), (kind, name)),
        other => panic!("expected {kind:?} {name}: {other:?}"),
    }
}

/// [`KNOWN_CONSTRAINTS`] is exactly the set of named constraints of the
/// tables the registry writes and of the list domains, so a new constraint
/// in a later migration fails here until the mapping lists it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_constraint_names_match_the_catalog() {
    let (db, pool) = migrated().await;
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT conname::text FROM pg_constraint
         WHERE (contype IN ('c', 'f', 'p', 'u') AND conrelid = ANY(ARRAY[
                   'tenant', 'principal', 'resource_server', 'audience_tenant_assignment',
                   'resource_server_checker', 'resource_server_checker_tenant',
                   'resource_action', 'trust_keyset', 'trust_keyset_version', 'trust_source',
                   'principal_binding', 'service_identity', 'service_identity_resource_server',
                   'service_grant', 'service_grant_binding',
                   'service_grant_resource_server', 'consumed_assertion',
                   'admin_identity', 'admin_credential', 'admin_role_binding']::regclass[]))
            OR contypid = ANY(ARRAY[
                   'skyoauth_scope_list', 'skyoauth_profile_list',
                   'skyoauth_string_list']::regtype[])
         ORDER BY conname::text COLLATE \"C\"",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(names, KNOWN_CONSTRAINTS);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn tenants_are_created_read_listed_and_keyed() {
    let (db, pool) = migrated().await;
    let before = SystemTime::now() - Duration::from_secs(60);
    let created = registry::create_tenant(&pool, &new_tenant("ten_a", "ns_a"))
        .await
        .unwrap();
    assert_eq!(
        (
            &created.id[..],
            &created.name[..],
            &created.secret_namespace[..]
        ),
        ("ten_a", "Tenant ten_a", "ns_a")
    );
    assert_eq!(created.status, Status::Enabled);
    assert!(
        created.created_at > before
            && created.created_at < SystemTime::now() + Duration::from_secs(60)
    );
    assert_eq!(registry::get_tenant(&pool, "ten_a").await.unwrap(), created);
    assert_not_found(registry::get_tenant(&pool, "ten_x").await);
    let mut disabled = new_tenant("ten_b", "ns_b");
    disabled.status = Status::Disabled;
    registry::create_tenant(&pool, &disabled).await.unwrap();
    let listed = registry::list_tenants(&pool, Page::first(10))
        .await
        .unwrap();
    let ids: Vec<_> = listed.iter().map(|t| (&t.id[..], t.status)).collect();
    assert_eq!(
        ids,
        [("ten_a", Status::Enabled), ("ten_b", Status::Disabled)]
    );

    assert_exists(
        registry::create_tenant(&pool, &new_tenant("ten_a", "ns_other")).await,
        "tenant_pkey",
    );
    assert_exists(
        registry::create_tenant(&pool, &new_tenant("ten_c", "ns_a")).await,
        "tenant_secret_namespace_key",
    );
    let mut nameless = new_tenant("ten_c", "ns_c");
    nameless.name.clear();
    assert_invariant(
        registry::create_tenant(&pool, &nameless).await,
        InvariantKind::Check,
        "tenant_name_check",
    );
    assert_invariant(
        registry::create_tenant(&pool, &new_tenant(&"t".repeat(256), "ns_c")).await,
        InvariantKind::Check,
        "tenant_id_octet_length_check",
    );
    assert_invariant(
        registry::create_tenant(&pool, &new_tenant("ten_c", &"n".repeat(256))).await,
        InvariantKind::Check,
        "tenant_secret_namespace_octet_length_check",
    );
    assert_invariant(
        registry::create_tenant(&pool, &new_tenant("", "ns_c")).await,
        InvariantKind::Check,
        "tenant_id_check",
    );
    db.drop([pool]).await;
}

/// `Display` and `Debug` never repeat a value from the request (the
/// `source()` of `Retry` and `Other` may; see the module documentation).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_errors_do_not_repeat_request_values() {
    let (db, pool) = migrated().await;
    let secret = "ns-value-that-must-not-leak";
    registry::create_tenant(&pool, &new_tenant("ten_a", secret))
        .await
        .unwrap();
    let err = registry::create_tenant(&pool, &new_tenant("ten_b", secret))
        .await
        .unwrap_err();
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("ten_b"), "{text}");
    }
    let mut spaced = new_server("rs_1", "has a space-value");
    spaced.name = "name-value".into();
    let err = registry::create_resource_server(&pool, &spaced)
        .await
        .unwrap_err();
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(
            !text.contains("space-value") && !text.contains("name-value"),
            "{text}"
        );
    }
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn principal_reads_are_scoped_to_their_tenant() {
    let (db, pool) = seeded().await;
    let created = registry::create_principal(&pool, &new_principal("ten_a", "prn_1"))
        .await
        .unwrap();
    assert_eq!(created.kind, PrincipalKind::Workload);
    assert_eq!(created.tenant_id, "ten_a");
    let mut human = new_principal("ten_b", "prn_2");
    human.kind = PrincipalKind::Human;
    registry::create_principal(&pool, &human).await.unwrap();

    assert_eq!(
        registry::get_principal(&pool, "ten_a", "prn_1")
            .await
            .unwrap(),
        created
    );
    assert_not_found(registry::get_principal(&pool, "ten_b", "prn_1").await);
    assert_not_found(registry::get_principal(&pool, "ten_x", "prn_1").await);
    assert_not_found(registry::get_principal(&pool, "ten_a", "prn_2").await);
    let a: Vec<_> = registry::list_principals(&pool, "ten_a", Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert_eq!(a, ["prn_1"]);
    let b = registry::list_principals(&pool, "ten_b", Page::first(10))
        .await
        .unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!((&b[0].id[..], b[0].kind), ("prn_2", PrincipalKind::Human));
    assert!(
        registry::list_principals(&pool, "ten_x", Page::first(10))
            .await
            .unwrap()
            .is_empty()
    );

    assert_invariant(
        registry::create_principal(&pool, &new_principal("ten_x", "prn_3")).await,
        InvariantKind::ForeignKey,
        "principal_tenant_id_fkey",
    );
    assert_exists(
        registry::create_principal(&pool, &new_principal("ten_b", "prn_1")).await,
        "principal_pkey",
    );
    assert_invariant(
        registry::create_principal(&pool, &new_principal("ten_a", &"p".repeat(256))).await,
        InvariantKind::Check,
        "principal_id_octet_length_check",
    );
    db.drop([pool]).await;
}

/// Pages follow byte order, not the database collation, start after the
/// cursor (which need not exist) and are bounded.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn list_pages_follow_byte_order_and_are_bounded() {
    let (db, pool) = migrated().await;
    // Byte order: 'B' (0x42) < '_' (0x5F) < 'a' (0x61) < 'b' < 'ä' (0xC3 0xA4).
    for id in ["ä", "b", "a", "_", "B"] {
        registry::create_tenant(&pool, &new_tenant(id, &format!("ns_{id}")))
            .await
            .unwrap();
    }
    let ids = |tenants: Vec<registry::Tenant>| -> Vec<String> {
        tenants.into_iter().map(|t| t.id).collect()
    };
    let all = ids(registry::list_tenants(&pool, Page::first(10))
        .await
        .unwrap());
    assert_eq!(all, ["B", "_", "a", "b", "ä"]);
    let first = ids(registry::list_tenants(&pool, Page::first(2)).await.unwrap());
    assert_eq!(first, ["B", "_"]);
    let next = ids(registry::list_tenants(&pool, Page::after(&first[1], 2))
        .await
        .unwrap());
    assert_eq!(next, ["a", "b"]);
    let last = ids(registry::list_tenants(&pool, Page::after("b", 2))
        .await
        .unwrap());
    assert_eq!(last, ["ä"]);
    assert!(
        registry::list_tenants(&pool, Page::after("ä", 2))
            .await
            .unwrap()
            .is_empty()
    );
    // A cursor that names no row.
    let gap = ids(registry::list_tenants(&pool, Page::after("aa", 10))
        .await
        .unwrap());
    assert_eq!(gap, ["b", "ä"]);
    // A zero limit is one row.
    assert_eq!(
        ids(registry::list_tenants(&pool, Page::first(0)).await.unwrap()),
        ["B"]
    );

    run(
        &pool,
        "INSERT INTO tenant (id, name, secret_namespace, status)
         SELECT 'bulk_' || lpad(n::text, 4, '0'), 'bulk', 'ns_bulk_' || n, 'enabled'
         FROM generate_series(1, 600) AS n",
    )
    .await;
    let page = registry::list_tenants(&pool, Page::first(u32::MAX))
        .await
        .unwrap();
    assert_eq!(page.len(), usize::try_from(MAX_PAGE_SIZE).unwrap());
    let ids: Vec<_> = page.iter().map(|t| &t.id[..]).collect();
    assert_eq!(ids[..5], ["B", "_", "a", "b", "bulk_0001"]);
    assert_eq!(ids[499], "bulk_0496");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn resource_servers_update_by_revision_compare_and_set() {
    let (db, pool) = migrated().await;
    let created = registry::create_resource_server(&pool, &new_server("rs_1", "control-plane-api"))
        .await
        .unwrap();
    assert_eq!(created.revision, 1);
    assert_eq!(created.allowed_profiles, [Profile::Wif, Profile::HumanCli]);
    assert_eq!(created.constraint_versions, [json!(1)]);
    assert_eq!(
        registry::get_resource_server(&pool, "rs_1").await.unwrap(),
        created
    );
    assert_not_found(registry::get_resource_server(&pool, "rs_x").await);

    let updated = registry::update_resource_server(&pool, "rs_1", 1, &server_changes("Renamed"))
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(updated.name, "Renamed");
    assert_eq!(updated.audience, "control-plane-api");
    assert_eq!(updated.allowed_profiles, [Profile::HumanSession]);
    assert_eq!(updated.scopes, ["billing:read"]);
    assert_eq!(
        updated.constraint_versions,
        [json!("v2"), json!({"major": 2})]
    );
    assert_eq!(updated.status, Status::Disabled);
    assert_eq!(
        registry::get_resource_server(&pool, "rs_1").await.unwrap(),
        updated
    );

    // A stale or future revision changes nothing.
    for expected in [1, 3, 0, -1] {
        assert_stale(
            registry::update_resource_server(&pool, "rs_1", expected, &server_changes("Stale"))
                .await,
        );
    }
    assert_eq!(
        registry::get_resource_server(&pool, "rs_1").await.unwrap(),
        updated
    );
    assert_not_found(
        registry::update_resource_server(&pool, "rs_x", 1, &server_changes("x")).await,
    );
    let again = registry::update_resource_server(&pool, "rs_1", 2, &server_changes("Again"))
        .await
        .unwrap();
    assert_eq!((again.revision, &again.name[..]), (3, "Again"));

    registry::create_resource_server(&pool, &new_server("rs_2", "billing-api"))
        .await
        .unwrap();
    let ids: Vec<_> = registry::list_resource_servers(&pool, Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|rs| (rs.id, rs.revision))
        .collect();
    assert_eq!(ids, [("rs_1".into(), 3), ("rs_2".into(), 1)]);
    let after: Vec<_> = registry::list_resource_servers(&pool, Page::after("rs_1", 10))
        .await
        .unwrap()
        .into_iter()
        .map(|rs| rs.id)
        .collect();
    assert_eq!(after, ["rs_2"]);
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn resource_server_errors_name_their_constraint() {
    let (db, pool) = migrated().await;
    registry::create_resource_server(&pool, &new_server("rs_1", "control-plane-api"))
        .await
        .unwrap();
    let create = |server: NewResourceServer| {
        let pool = pool.clone();
        async move { registry::create_resource_server(&pool, &server).await }
    };
    assert_exists(
        create(new_server("rs_1", "other-api")).await,
        "resource_server_pkey",
    );
    assert_exists(
        create(new_server("rs_2", "control-plane-api")).await,
        "resource_server_audience_key",
    );
    for (server, name) in [
        (
            new_server("rs_2", "has space"),
            "resource_server_audience_no_space_check",
        ),
        (
            new_server("rs_2", "tab\tapi"),
            "resource_server_audience_no_space_check",
        ),
        (
            new_server("rs_2", &"a".repeat(2049)),
            "resource_server_audience_octet_length_check",
        ),
        (new_server("rs_2", ""), "resource_server_audience_check"),
        (
            new_server(&"r".repeat(256), "x-api"),
            "resource_server_id_octet_length_check",
        ),
        (new_server("", "x-api"), "resource_server_id_check"),
    ] {
        assert_invariant(create(server).await, InvariantKind::Check, name);
    }
    let mut nameless = new_server("rs_2", "x-api");
    nameless.name.clear();
    assert_invariant(
        create(nameless).await,
        InvariantKind::Check,
        "resource_server_name_check",
    );
    let mut bad_scope = new_server("rs_2", "x-api");
    bad_scope.scopes = vec!["has space".into()];
    assert_invariant(
        create(bad_scope).await,
        InvariantKind::Check,
        "skyoauth_scope_list_check",
    );

    // The same mapping on update; nothing changes.
    let mut changes = server_changes("Renamed");
    changes.scopes = vec!["quote\"d".into()];
    assert_invariant(
        registry::update_resource_server(&pool, "rs_1", 1, &changes).await,
        InvariantKind::Check,
        "skyoauth_scope_list_check",
    );
    changes = server_changes("");
    assert_invariant(
        registry::update_resource_server(&pool, "rs_1", 1, &changes).await,
        InvariantKind::Check,
        "resource_server_name_check",
    );
    assert_eq!(
        registry::get_resource_server(&pool, "rs_1")
            .await
            .unwrap()
            .revision,
        1
    );
    db.drop([pool]).await;
}

/// The expected revision is only compared, never computed with: `i64::MAX`
/// is a stale revision of an existing row and a missing row is not found,
/// for every update and checker tenant-set change, and nothing changes.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_expected_revision_of_i64_max_is_stale_or_not_found() {
    const MAX: i64 = i64::MAX;
    let (db, pool) = seeded().await;
    registry::create_tenant(&pool, &new_tenant("ten_c", "ns_c"))
        .await
        .unwrap();
    registry::create_audience_tenant_assignment(&pool, &new_assignment("ata_3", "rs_1", "ten_c"))
        .await
        .unwrap();
    registry::create_resource_server_checker(&pool, &new_checker("chk_1", "rs_1", "sha256:aa"))
        .await
        .unwrap();
    registry::add_resource_server_checker_tenant(&pool, "chk_1", 1, "ten_a")
        .await
        .unwrap();
    registry::create_resource_action(&pool, &new_action("act_1", "rs_1", "projects.get"))
        .await
        .unwrap();
    let assignment_changes = AudienceTenantAssignmentChanges {
        allowed_profiles: vec![],
        allowed_scopes: vec![],
        constraint_versions: vec![],
        status: Status::Disabled,
    };
    let checker_changes = ResourceServerCheckerChanges {
        public_mtls_identity: "sha256:bb".into(),
        status: Status::Disabled,
    };
    let action_changes = ResourceActionChanges {
        required_scopes: vec![],
        accepted_profiles: vec![Profile::HumanCli],
        required_resource_dimensions: vec![],
        live_check_required: false,
        status: Status::Disabled,
    };

    assert_stale(registry::update_resource_server(&pool, "rs_1", MAX, &server_changes("x")).await);
    assert_not_found(
        registry::update_resource_server(&pool, "rs_x", MAX, &server_changes("x")).await,
    );
    assert_stale(
        registry::update_audience_tenant_assignment(&pool, "ata_1", MAX, &assignment_changes).await,
    );
    assert_not_found(
        registry::update_audience_tenant_assignment(&pool, "ata_x", MAX, &assignment_changes).await,
    );
    assert_stale(
        registry::update_resource_server_checker(&pool, "chk_1", MAX, &checker_changes).await,
    );
    assert_not_found(
        registry::update_resource_server_checker(&pool, "chk_x", MAX, &checker_changes).await,
    );
    assert_stale(registry::update_resource_action(&pool, "act_1", MAX, &action_changes).await);
    assert_not_found(registry::update_resource_action(&pool, "act_x", MAX, &action_changes).await);
    // ten_c could be added and ten_a removed at the checker's revision 2.
    assert_stale(registry::add_resource_server_checker_tenant(&pool, "chk_1", MAX, "ten_c").await);
    assert_not_found(
        registry::add_resource_server_checker_tenant(&pool, "chk_x", MAX, "ten_c").await,
    );
    assert_stale(
        registry::remove_resource_server_checker_tenant(&pool, "chk_1", MAX, "ten_a").await,
    );
    assert_not_found(
        registry::remove_resource_server_checker_tenant(&pool, "chk_x", MAX, "ten_a").await,
    );

    let server = registry::get_resource_server(&pool, "rs_1").await.unwrap();
    assert_eq!((server.revision, &server.name[..]), (1, "Server rs_1"));
    let assignment = registry::get_audience_tenant_assignment(&pool, "ata_1")
        .await
        .unwrap();
    assert_eq!(
        (assignment.revision, assignment.status),
        (1, Status::Enabled)
    );
    let checker = registry::get_resource_server_checker(&pool, "chk_1")
        .await
        .unwrap();
    assert_eq!(
        (
            checker.revision,
            &checker.public_mtls_identity[..],
            &checker.allowed_tenant_ids[..]
        ),
        (2, "sha256:aa", &["ten_a".to_string()][..])
    );
    let action = registry::get_resource_action(&pool, "act_1").await.unwrap();
    assert_eq!((action.revision, action.status), (1, Status::Enabled));
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
    .expect("the second updater never waited for the row lock");
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// The second of two updates from one revision waits for the first's row
/// lock and, once the first commits, finds the revision moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_updater_from_the_same_revision_is_stale_after_the_first_commits() {
    let (db, pool) = seeded().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    let mut tx = first.begin().await.unwrap();
    registry::update_resource_server(&mut *tx, "rs_1", 1, &server_changes("First"))
        .await
        .unwrap();
    let waiting = tokio::spawn(async move {
        registry::update_resource_server(&mut second, "rs_1", 1, &server_changes("Second")).await
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    assert!(!waiting.is_finished());
    tx.commit().await.unwrap();
    assert_stale(waiting.await.unwrap());
    let current = registry::get_resource_server(&pool, "rs_1").await.unwrap();
    assert_eq!((current.revision, &current.name[..]), (2, "First"));
    db.drop([pool]).await;
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

/// In caller transactions at REPEATABLE READ or SERIALIZABLE, the second
/// of two updates from one revision waits for the first's row lock and,
/// once the first commits, fails with `40001` (`serialization_failure`):
/// `Retry`, never `StaleRevision`, although the revision moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_updater_from_the_same_revision_must_retry_under_repeatable_read() {
    for set_level in [
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
    ] {
        let (db, pool) = seeded().await;
        let mut first = pool.begin().await.unwrap();
        let mut second = pool.begin().await.unwrap();
        sqlx::raw_sql(set_level).execute(&mut *first).await.unwrap();
        sqlx::raw_sql(set_level)
            .execute(&mut *second)
            .await
            .unwrap();
        // The second's snapshot starts here, before the first updates.
        let (first_pid, second_pid) = (
            backend_pid(&mut first).await,
            backend_pid(&mut second).await,
        );
        registry::update_resource_server(&mut *first, "rs_1", 1, &server_changes("First"))
            .await
            .unwrap();
        let waiting = tokio::spawn(async move {
            let result = registry::update_resource_server(
                &mut *second,
                "rs_1",
                1,
                &server_changes("Second"),
            )
            .await;
            second.rollback().await.unwrap();
            result
        });
        wait_until_blocked(&pool, second_pid, first_pid).await;
        assert!(!waiting.is_finished());
        first.commit().await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(30), waiting)
            .await
            .expect("the second updater never finished")
            .unwrap()
            .expect_err("both updaters succeeded");
        assert_eq!(retry_sqlstate(&err), "40001", "{set_level}");
        assert_eq!(
            err.to_string(),
            "registry transaction aborted (SQLSTATE 40001); retry the whole transaction"
        );
        assert_eq!(
            format!("{err:?}"),
            r#"Retry { sqlstate: Some("40001"), .. }"#
        );
        let current = registry::get_resource_server(&pool, "rs_1").await.unwrap();
        assert_eq!((current.revision, &current.name[..]), (2, "First"));
        db.drop([pool]).await;
    }
}

/// Two transactions that each update one resource server and then the
/// other's deadlock: the first waits for the second's row lock (checked
/// with `pg_blocking_pids`) before the second asks for the first's.
/// PostgreSQL aborts exactly one of them with `40P01`
/// (`deadlock_detected`), which is `Retry`, and the other goes on. Which one
/// loses depends on whose deadlock check (after `deadlock_timeout`) runs
/// first, and changing `deadlock_timeout` needs a superuser, so the test
/// accepts either, but exactly one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_deadlock_between_two_updaters_must_retry() {
    let (db, pool) = seeded().await;
    let mut first = pool.begin().await.unwrap();
    let mut second = pool.begin().await.unwrap();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    registry::update_resource_server(&mut *first, "rs_1", 1, &server_changes("First"))
        .await
        .unwrap();
    registry::update_resource_server(&mut *second, "rs_2", 1, &server_changes("Second"))
        .await
        .unwrap();
    let first_waits = tokio::spawn(async move {
        let result =
            registry::update_resource_server(&mut *first, "rs_2", 1, &server_changes("First"))
                .await;
        (first, result)
    });
    wait_until_blocked(&pool, first_pid, second_pid).await;
    let second_waits = tokio::spawn(async move {
        let result =
            registry::update_resource_server(&mut *second, "rs_1", 1, &server_changes("Second"))
                .await;
        (second, result)
    });
    let ((first, first_result), (second, second_result)) =
        tokio::time::timeout(Duration::from_secs(30), async {
            (first_waits.await.unwrap(), second_waits.await.unwrap())
        })
        .await
        .expect("the deadlock was never resolved");
    let (winner, err) = match (first_result, second_result) {
        (Ok(server), Err(err)) => {
            assert_eq!(server.revision, 2);
            second.rollback().await.unwrap();
            first.commit().await.unwrap();
            ("First", err)
        }
        (Err(err), Ok(server)) => {
            assert_eq!(server.revision, 2);
            first.rollback().await.unwrap();
            second.commit().await.unwrap();
            ("Second", err)
        }
        other => panic!("expected exactly one deadlock victim: {other:?}"),
    };
    assert_eq!(retry_sqlstate(&err), "40P01");
    assert_eq!(
        err.to_string(),
        "registry transaction aborted (SQLSTATE 40P01); retry the whole transaction"
    );
    assert_eq!(
        format!("{err:?}"),
        r#"Retry { sqlstate: Some("40P01"), .. }"#
    );
    for id in ["rs_1", "rs_2"] {
        let current = registry::get_resource_server(&pool, id).await.unwrap();
        assert_eq!((current.revision, &current.name[..]), (2, winner), "{id}");
    }
    db.drop([pool]).await;
}

/// The same for checker tenant-set changes: a second add or remove from
/// the revision the first moves waits for the first's lock on the checker
/// row and, once the first commits, is stale, although the statement's
/// snapshot still shows the checker at the expected revision (and, for a
/// remove, the tenant listed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_second_checker_tenant_change_from_the_same_revision_is_stale_after_the_first_commits() {
    let (db, pool) = seeded().await;
    registry::create_tenant(&pool, &new_tenant("ten_c", "ns_c"))
        .await
        .unwrap();
    registry::create_audience_tenant_assignment(&pool, &new_assignment("ata_3", "rs_1", "ten_c"))
        .await
        .unwrap();
    registry::create_resource_server_checker(&pool, &new_checker("chk_1", "rs_1", "sha256:aa"))
        .await
        .unwrap();
    let checker = |pool: PgPool| async move {
        let checker = registry::get_resource_server_checker(&pool, "chk_1")
            .await
            .unwrap();
        (checker.revision, checker.allowed_tenant_ids)
    };
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );

    // Two adds of different tenants from revision 1.
    let mut tx = first.begin().await.unwrap();
    assert_eq!(
        registry::add_resource_server_checker_tenant(&mut *tx, "chk_1", 1, "ten_a")
            .await
            .unwrap(),
        2
    );
    let waiting = tokio::spawn(async move {
        let outcome =
            registry::add_resource_server_checker_tenant(&mut second, "chk_1", 1, "ten_c").await;
        (second, outcome)
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    assert!(!waiting.is_finished());
    tx.commit().await.unwrap();
    let (mut second, outcome) = waiting.await.unwrap();
    assert_stale(outcome);
    assert_eq!(checker(pool.clone()).await, (2, vec!["ten_a".to_string()]));

    // Two removes of the listed tenant from revision 2.
    let mut tx = first.begin().await.unwrap();
    assert_eq!(
        registry::remove_resource_server_checker_tenant(&mut *tx, "chk_1", 2, "ten_a")
            .await
            .unwrap(),
        3
    );
    let waiting = tokio::spawn(async move {
        registry::remove_resource_server_checker_tenant(&mut second, "chk_1", 2, "ten_a").await
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    assert!(!waiting.is_finished());
    tx.commit().await.unwrap();
    assert_stale(waiting.await.unwrap());
    assert_eq!(checker(pool.clone()).await, (3, vec![]));
    db.drop([pool]).await;
}

/// Of many concurrent updates from one revision exactly one succeeds, for
/// every revisioned table and for checker tenant-set changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn concurrent_updates_from_one_revision_have_exactly_one_winner() {
    let (db, pool) = seeded().await;
    registry::create_resource_server_checker(&pool, &new_checker("chk_1", "rs_1", "sha256:aa"))
        .await
        .unwrap();
    registry::create_resource_action(&pool, &new_action("act_1", "rs_1", "projects.get"))
        .await
        .unwrap();
    // Assignments of rs_1 to further tenants, so concurrent adds name
    // different tenants.
    for n in 0..4 {
        let tenant = format!("ten_c{n}");
        registry::create_tenant(&pool, &new_tenant(&tenant, &format!("ns_c{n}")))
            .await
            .unwrap();
        registry::create_audience_tenant_assignment(
            &pool,
            &new_assignment(&format!("ata_c{n}"), "rs_1", &tenant),
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
            registry::update_resource_server(&pool, "rs_1", 1, &server_changes(&format!("n{n}")))
                .await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "resource_server");

    let p = pool.clone();
    let outcome = race(move |_| {
        let pool = p.clone();
        async move {
            let changes = AudienceTenantAssignmentChanges {
                allowed_profiles: vec![],
                allowed_scopes: vec![],
                constraint_versions: vec![],
                status: Status::Disabled,
            };
            registry::update_audience_tenant_assignment(&pool, "ata_1", 1, &changes).await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "audience_tenant_assignment");

    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            let changes = ResourceServerCheckerChanges {
                public_mtls_identity: format!("sha256:b{n}"),
                status: Status::Enabled,
            };
            registry::update_resource_server_checker(&pool, "chk_1", 1, &changes).await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "resource_server_checker");

    let p = pool.clone();
    let outcome = race(move |_| {
        let pool = p.clone();
        async move {
            let changes = ResourceActionChanges {
                required_scopes: vec![],
                accepted_profiles: vec![Profile::HumanCli],
                required_resource_dimensions: vec![],
                live_check_required: false,
                status: Status::Enabled,
            };
            registry::update_resource_action(&pool, "act_1", 1, &changes).await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "resource_action");

    // The checker is at revision 2 now; four adds of different tenants.
    let p = pool.clone();
    let outcome = race(move |n| {
        let pool = p.clone();
        async move {
            registry::add_resource_server_checker_tenant(&pool, "chk_1", 2, &format!("ten_c{n}"))
                .await
        }
    })
    .await;
    assert_eq!(outcome, (1, 3), "add checker tenant");
    let checker = registry::get_resource_server_checker(&pool, "chk_1")
        .await
        .unwrap();
    assert_eq!((checker.revision, checker.allowed_tenant_ids.len()), (3, 1));

    // Four removes of the one listed tenant from revision 3.
    let tenant = checker.allowed_tenant_ids[0].clone();
    let p = pool.clone();
    let outcome =
        race(move |_| {
            let pool = p.clone();
            let tenant = tenant.clone();
            async move {
                registry::remove_resource_server_checker_tenant(&pool, "chk_1", 3, &tenant).await
            }
        })
        .await;
    assert_eq!(outcome, (1, 3), "remove checker tenant");
    let checker = registry::get_resource_server_checker(&pool, "chk_1")
        .await
        .unwrap();
    assert_eq!(checker.revision, 4);
    assert!(checker.allowed_tenant_ids.is_empty());
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn assignments_update_by_revision_and_name_their_constraints() {
    let (db, pool) = seeded().await;
    let assignment = registry::get_audience_tenant_assignment(&pool, "ata_1")
        .await
        .unwrap();
    assert_eq!(
        (
            &assignment.resource_server_id[..],
            &assignment.tenant_id[..],
            assignment.revision
        ),
        ("rs_1", "ten_a", 1)
    );
    assert_eq!(assignment.allowed_profiles, [Profile::Wif]);
    assert_eq!(assignment.allowed_scopes, ["projects:read"]);
    assert_not_found(registry::get_audience_tenant_assignment(&pool, "ata_x").await);

    let changes = AudienceTenantAssignmentChanges {
        allowed_profiles: vec![Profile::Wif, Profile::HumanSession],
        allowed_scopes: vec![],
        constraint_versions: vec![json!(1), json!(2)],
        status: Status::Disabled,
    };
    let updated = registry::update_audience_tenant_assignment(&pool, "ata_1", 1, &changes)
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(updated.allowed_profiles, changes.allowed_profiles);
    assert!(updated.allowed_scopes.is_empty());
    assert_eq!(updated.constraint_versions, changes.constraint_versions);
    assert_eq!(updated.status, Status::Disabled);
    assert_eq!(
        (&updated.tenant_id[..], &updated.resource_server_id[..]),
        ("ten_a", "rs_1")
    );
    assert_stale(registry::update_audience_tenant_assignment(&pool, "ata_1", 1, &changes).await);
    assert_not_found(
        registry::update_audience_tenant_assignment(&pool, "ata_x", 1, &changes).await,
    );

    let listed: Vec<_> = registry::list_audience_tenant_assignments(&pool, Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|a| (a.id, a.revision))
        .collect();
    assert_eq!(listed, [("ata_1".into(), 2), ("ata_2".into(), 1)]);

    let create = |new: NewAudienceTenantAssignment| {
        let pool = pool.clone();
        async move { registry::create_audience_tenant_assignment(&pool, &new).await }
    };
    assert_exists(
        create(new_assignment("ata_1", "rs_2", "ten_a")).await,
        "audience_tenant_assignment_pkey",
    );
    assert_exists(
        create(new_assignment("ata_3", "rs_1", "ten_a")).await,
        "audience_tenant_assignment_tenant_id_resource_server_id_key",
    );
    assert_invariant(
        create(new_assignment("ata_3", "rs_1", "ten_x")).await,
        InvariantKind::ForeignKey,
        "audience_tenant_assignment_tenant_id_fkey",
    );
    assert_invariant(
        create(new_assignment("ata_3", "rs_x", "ten_a")).await,
        InvariantKind::ForeignKey,
        "audience_tenant_assignment_resource_server_id_fkey",
    );
    assert_invariant(
        create(new_assignment(&"a".repeat(256), "rs_2", "ten_a")).await,
        InvariantKind::Check,
        "audience_tenant_assignment_id_octet_length_check",
    );
    let mut bad_scope = new_assignment("ata_3", "rs_2", "ten_a");
    bad_scope.allowed_scopes = vec![String::new()];
    assert_invariant(
        create(bad_scope).await,
        InvariantKind::Check,
        "skyoauth_scope_list_check",
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn checkers_update_by_revision_and_keep_their_tenant_set() {
    let (db, pool) = seeded().await;
    let created = registry::create_resource_server_checker(
        &pool,
        &new_checker("chk_1", "rs_1", "CN=checker one"),
    )
    .await
    .unwrap();
    assert_eq!(created.revision, 1);
    assert!(created.allowed_tenant_ids.is_empty());
    assert_eq!(
        registry::get_resource_server_checker(&pool, "chk_1")
            .await
            .unwrap(),
        created
    );
    assert_not_found(registry::get_resource_server_checker(&pool, "chk_x").await);

    assert_eq!(
        registry::add_resource_server_checker_tenant(&pool, "chk_1", 1, "ten_a")
            .await
            .unwrap(),
        2
    );
    let changes = ResourceServerCheckerChanges {
        public_mtls_identity: "sha256:rotated".into(),
        status: Status::Disabled,
    };
    let updated = registry::update_resource_server_checker(&pool, "chk_1", 2, &changes)
        .await
        .unwrap();
    assert_eq!(updated.revision, 3);
    assert_eq!(updated.public_mtls_identity, "sha256:rotated");
    assert_eq!(updated.status, Status::Disabled);
    assert_eq!(updated.allowed_tenant_ids, ["ten_a"]);
    assert_stale(registry::update_resource_server_checker(&pool, "chk_1", 2, &changes).await);
    assert_not_found(registry::update_resource_server_checker(&pool, "chk_x", 1, &changes).await);

    registry::create_resource_server_checker(&pool, &new_checker("chk_2", "rs_2", "sha256:bb"))
        .await
        .unwrap();
    let listed: Vec<_> = registry::list_resource_server_checkers(&pool, Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|c| (c.id, c.allowed_tenant_ids))
        .collect();
    assert_eq!(
        listed,
        [
            ("chk_1".to_string(), vec!["ten_a".to_string()]),
            ("chk_2".to_string(), vec![])
        ]
    );

    let create = |new: NewResourceServerChecker| {
        let pool = pool.clone();
        async move { registry::create_resource_server_checker(&pool, &new).await }
    };
    assert_exists(
        create(new_checker("chk_1", "rs_2", "sha256:cc")).await,
        "resource_server_checker_pkey",
    );
    assert_exists(
        create(new_checker("chk_3", "rs_2", "sha256:rotated")).await,
        "resource_server_checker_public_mtls_identity_key",
    );
    assert_invariant(
        create(new_checker("chk_3", "rs_x", "sha256:cc")).await,
        InvariantKind::ForeignKey,
        "resource_server_checker_resource_server_id_fkey",
    );
    assert_invariant(
        create(new_checker("chk_3", "rs_2", &"i".repeat(2049))).await,
        InvariantKind::Check,
        "resource_server_checker_public_mtls_identity_octet_length_check",
    );
    let changes = ResourceServerCheckerChanges {
        public_mtls_identity: "sha256:bb".into(),
        status: Status::Enabled,
    };
    assert_exists(
        registry::update_resource_server_checker(&pool, "chk_1", 3, &changes).await,
        "resource_server_checker_public_mtls_identity_key",
    );
    db.drop([pool]).await;
}

/// A checker lists only tenants with an assignment of its own resource
/// server; each set change is a compare-and-set on the checker's revision.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn checker_tenant_rows_need_an_assignment_and_advance_the_revision() {
    let (db, pool) = seeded().await;
    registry::create_resource_server_checker(&pool, &new_checker("chk_1", "rs_1", "sha256:aa"))
        .await
        .unwrap();
    let revision = |pool: PgPool| async move {
        registry::get_resource_server_checker(&pool, "chk_1")
            .await
            .unwrap()
            .revision
    };

    // ten_b is assigned only to rs_2, and ten_x does not exist.
    for tenant in ["ten_b", "ten_x"] {
        assert_invariant(
            registry::add_resource_server_checker_tenant(&pool, "chk_1", 1, tenant).await,
            InvariantKind::ForeignKey,
            "resource_server_checker_tenant_assignment_fkey",
        );
    }
    assert_eq!(revision(pool.clone()).await, 1);
    assert_not_found(
        registry::add_resource_server_checker_tenant(&pool, "chk_x", 1, "ten_a").await,
    );
    assert_stale(registry::add_resource_server_checker_tenant(&pool, "chk_1", 2, "ten_a").await);
    assert_eq!(
        registry::add_resource_server_checker_tenant(&pool, "chk_1", 1, "ten_a")
            .await
            .unwrap(),
        2
    );
    assert_exists(
        registry::add_resource_server_checker_tenant(&pool, "chk_1", 2, "ten_a").await,
        "resource_server_checker_tenant_pkey",
    );
    assert_eq!(revision(pool.clone()).await, 2);

    // A disabled assignment still allows the row (the service filters it).
    registry::create_tenant(&pool, &new_tenant("ten_c", "ns_c"))
        .await
        .unwrap();
    let mut disabled = new_assignment("ata_3", "rs_1", "ten_c");
    disabled.status = Status::Disabled;
    registry::create_audience_tenant_assignment(&pool, &disabled)
        .await
        .unwrap();
    assert_eq!(
        registry::add_resource_server_checker_tenant(&pool, "chk_1", 2, "ten_c")
            .await
            .unwrap(),
        3
    );
    let checker = registry::get_resource_server_checker(&pool, "chk_1")
        .await
        .unwrap();
    assert_eq!(checker.allowed_tenant_ids, ["ten_a", "ten_c"]);

    // Removal.
    assert_not_found(
        registry::remove_resource_server_checker_tenant(&pool, "chk_1", 3, "ten_b").await,
    );
    assert_not_found(
        registry::remove_resource_server_checker_tenant(&pool, "chk_x", 3, "ten_a").await,
    );
    assert_stale(registry::remove_resource_server_checker_tenant(&pool, "chk_1", 2, "ten_a").await);
    assert_stale(registry::remove_resource_server_checker_tenant(&pool, "chk_1", 2, "ten_b").await);
    assert_eq!(revision(pool.clone()).await, 3);
    assert_eq!(
        registry::remove_resource_server_checker_tenant(&pool, "chk_1", 3, "ten_a")
            .await
            .unwrap(),
        4
    );
    let checker = registry::get_resource_server_checker(&pool, "chk_1")
        .await
        .unwrap();
    assert_eq!(
        (checker.revision, &checker.allowed_tenant_ids[..]),
        (4, &["ten_c".to_string()][..])
    );
    assert_not_found(
        registry::remove_resource_server_checker_tenant(&pool, "chk_1", 4, "ten_a").await,
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM resource_server_checker_tenant")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    db.drop([pool]).await;
}

/// A checker's tenant set comes back in byte order, whatever order the
/// tenants were added in and whatever the database collation: `ten_B`
/// (0x42) sorts before `ten_a` (0x61) in `C`, after it in `en_US`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn checker_tenant_sets_are_returned_in_byte_order() {
    let (db, pool) = seeded().await;
    // seeded() assigns rs_1 to ten_a.
    for (tenant, ns, assignment) in [("ten_c", "ns_c", "ata_c"), ("ten_B", "ns_B", "ata_B")] {
        registry::create_tenant(&pool, &new_tenant(tenant, ns))
            .await
            .unwrap();
        registry::create_audience_tenant_assignment(
            &pool,
            &new_assignment(assignment, "rs_1", tenant),
        )
        .await
        .unwrap();
    }
    registry::create_resource_server_checker(&pool, &new_checker("chk_1", "rs_1", "sha256:aa"))
        .await
        .unwrap();
    // Neither byte order nor en_US order.
    for (revision, tenant) in [(1, "ten_c"), (2, "ten_a"), (3, "ten_B")] {
        assert_eq!(
            registry::add_resource_server_checker_tenant(&pool, "chk_1", revision, tenant)
                .await
                .unwrap(),
            revision + 1
        );
    }
    let expected = ["ten_B", "ten_a", "ten_c"];

    let read = registry::get_resource_server_checker(&pool, "chk_1")
        .await
        .unwrap();
    assert_eq!(read.allowed_tenant_ids, expected);
    let listed = registry::list_resource_server_checkers(&pool, Page::first(10))
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].allowed_tenant_ids, expected);
    let changes = ResourceServerCheckerChanges {
        public_mtls_identity: "sha256:bb".into(),
        status: Status::Enabled,
    };
    let updated = registry::update_resource_server_checker(&pool, "chk_1", 4, &changes)
        .await
        .unwrap();
    assert_eq!(updated.allowed_tenant_ids, expected);

    // The order is the column's: its collation, which the ORDER BY also
    // names, is "C", so it holds on a cluster whose default is en_US.
    let collation: String = sqlx::query_scalar(
        "SELECT c.collname::text FROM pg_attribute a
         JOIN pg_collation c ON c.oid = a.attcollation
         WHERE a.attrelid = 'resource_server_checker_tenant'::regclass
           AND a.attname = 'tenant_id'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(collation, "C");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn resource_actions_update_by_revision_and_name_their_constraints() {
    let (db, pool) = seeded().await;
    let created =
        registry::create_resource_action(&pool, &new_action("act_1", "rs_1", "projects.get"))
            .await
            .unwrap();
    assert_eq!(created.revision, 1);
    assert_eq!(created.required_resource_dimensions, ["project"]);
    assert!(created.live_check_required);
    assert_eq!(
        registry::get_resource_action(&pool, "act_1").await.unwrap(),
        created
    );
    assert_not_found(registry::get_resource_action(&pool, "act_x").await);

    let changes = ResourceActionChanges {
        required_scopes: vec!["projects:write".into()],
        accepted_profiles: vec![Profile::HumanCli, Profile::HumanSession],
        required_resource_dimensions: vec![],
        live_check_required: false,
        status: Status::Disabled,
    };
    let updated = registry::update_resource_action(&pool, "act_1", 1, &changes)
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(
        (&updated.action_name[..], &updated.resource_server_id[..]),
        ("projects.get", "rs_1")
    );
    assert_eq!(updated.required_scopes, changes.required_scopes);
    assert_eq!(updated.accepted_profiles, changes.accepted_profiles);
    assert!(updated.required_resource_dimensions.is_empty());
    assert!(!updated.live_check_required);
    assert_eq!(updated.status, Status::Disabled);
    assert_stale(registry::update_resource_action(&pool, "act_1", 1, &changes).await);
    assert_not_found(registry::update_resource_action(&pool, "act_x", 1, &changes).await);

    registry::create_resource_action(&pool, &new_action("act_0", "rs_2", "projects.get"))
        .await
        .unwrap();
    let listed: Vec<_> = registry::list_resource_actions(&pool, Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(listed, ["act_0", "act_1"]);

    let create = |new: NewResourceAction| {
        let pool = pool.clone();
        async move { registry::create_resource_action(&pool, &new).await }
    };
    assert_exists(
        create(new_action("act_1", "rs_2", "x")).await,
        "resource_action_pkey",
    );
    assert_exists(
        create(new_action("act_2", "rs_1", "projects.get")).await,
        "resource_action_resource_server_id_action_name_key",
    );
    assert_invariant(
        create(new_action("act_2", "rs_x", "x")).await,
        InvariantKind::ForeignKey,
        "resource_action_resource_server_id_fkey",
    );
    assert_invariant(
        create(new_action("act_2", "rs_1", "projects get")).await,
        InvariantKind::Check,
        "resource_action_action_name_no_space_check",
    );
    assert_invariant(
        create(new_action("act_2", "rs_1", &"x".repeat(2049))).await,
        InvariantKind::Check,
        "resource_action_action_name_octet_length_check",
    );
    let mut bad_dimension = new_action("act_2", "rs_1", "projects.list");
    bad_dimension.required_resource_dimensions = vec![String::new()];
    assert_invariant(
        create(bad_dimension).await,
        InvariantKind::Check,
        "skyoauth_string_list_check",
    );
    db.drop([pool]).await;
}

/// The guard and not-null mappings, which no registry function reaches:
/// updates never touch an immutable column and every column is required.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn guard_not_null_and_unknown_errors_map_from_raw_statements() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        "INSERT INTO resource_server_checker VALUES ('chk_1', 'rs_1', 'sha256:aa', 'enabled')",
    )
    .await;
    for sql in [
        "UPDATE tenant SET secret_namespace = 'ns_z', revision = revision + 1 WHERE id = 'ten_a'",
        "UPDATE resource_server SET audience = 'other', revision = revision + 1 WHERE id = 'rs_1'",
        "UPDATE resource_server SET revision = revision + 2 WHERE id = 'rs_1'",
        "UPDATE audience_tenant_assignment SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'ata_1'",
        "UPDATE resource_server_checker SET resource_server_id = 'rs_2', revision = revision + 1 WHERE id = 'chk_1'",
        "INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', 'https://x/jwks', 'enabled', 2)",
    ] {
        let err = raw_error(&pool, sql).await;
        assert!(matches!(err, RegistryError::Guard), "{sql}: {err:?}");
    }
    let err = raw_error(
        &pool,
        "INSERT INTO tenant (id, name, secret_namespace, status) VALUES ('ten_z', NULL, 'ns_z', 'enabled')",
    )
    .await;
    assert!(
        matches!(
            err,
            RegistryError::Invariant {
                kind: InvariantKind::NotNull,
                constraint: None
            }
        ),
        "{err:?}"
    );
    // A constraint of a table the registry does not write is not mapped.
    let err = raw_error(
        &pool,
        "INSERT INTO egress_allowlist_entry VALUES ('egr_1', 'jwks', 'has space', 'enabled')",
    )
    .await;
    assert!(matches!(err, RegistryError::Other(_)), "{err:?}");
    assert_eq!(err.to_string(), "registry database error (SQLSTATE 23514)");
    db.drop([pool]).await;
}

/// Every function runs inside a caller transaction; an outcome that is not
/// a database error (stale, not found) leaves the transaction usable.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_functions_compose_in_a_caller_transaction() {
    let (db, pool) = seeded().await;
    let mut tx = pool.begin().await.unwrap();
    registry::create_tenant(&mut *tx, &new_tenant("ten_c", "ns_c"))
        .await
        .unwrap();
    registry::create_audience_tenant_assignment(
        &mut *tx,
        &new_assignment("ata_3", "rs_1", "ten_c"),
    )
    .await
    .unwrap();
    registry::create_resource_server_checker(&mut *tx, &new_checker("chk_1", "rs_1", "sha256:aa"))
        .await
        .unwrap();
    assert_stale(registry::add_resource_server_checker_tenant(&mut *tx, "chk_1", 5, "ten_c").await);
    assert_not_found(registry::get_tenant(&mut *tx, "ten_x").await);
    registry::add_resource_server_checker_tenant(&mut *tx, "chk_1", 1, "ten_c")
        .await
        .unwrap();
    assert_eq!(
        registry::get_resource_server_checker(&mut *tx, "chk_1")
            .await
            .unwrap()
            .allowed_tenant_ids,
        ["ten_c"]
    );
    assert_not_found(registry::get_tenant(&pool, "ten_c").await);
    tx.rollback().await.unwrap();
    assert_not_found(registry::get_tenant(&pool, "ten_c").await);
    assert_not_found(registry::get_resource_server_checker(&pool, "chk_1").await);

    let mut tx = pool.begin().await.unwrap();
    registry::update_resource_server(&mut *tx, "rs_1", 1, &server_changes("In tx"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        registry::get_resource_server(&pool, "rs_1")
            .await
            .unwrap()
            .revision,
        2
    );
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn instance_policy_and_egress_entries_are_read() {
    let (db, pool) = migrated().await;
    assert_not_found(registry::get_instance_security_policy(&pool).await);
    run(
        &pool,
        "INSERT INTO instance_security_policy (instance_id, single_actor_mode) VALUES ('inst_1', true)",
    )
    .await;
    let policy = registry::get_instance_security_policy(&pool).await.unwrap();
    assert_eq!(policy.instance_id, "inst_1");
    assert!(policy.single_actor_mode && !policy.widening_second_approver);
    assert_eq!(
        (
            policy.audit_sink_config_digest,
            policy.audit_sink_validated_at,
            policy.revision
        ),
        (None, None, 1)
    );
    run(
        &pool,
        "UPDATE instance_security_policy SET audit_sink_config_digest = '\\x0102',
             audit_sink_validated_at = '2026-01-02T03:04:05.678901Z', revision = 2",
    )
    .await;
    let policy = registry::get_instance_security_policy(&pool).await.unwrap();
    assert_eq!(
        policy.audit_sink_config_digest.as_deref(),
        Some(&[1u8, 2][..])
    );
    let validated = policy
        .audit_sink_validated_at
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    assert_eq!(validated, Duration::from_micros(1_767_323_045_678_901));
    assert_eq!(policy.revision, 2);

    assert_not_found(registry::get_egress_allowlist_entry(&pool, "egr_1").await);
    run(
        &pool,
        "INSERT INTO egress_allowlist_entry VALUES
             ('egr_2', 'jwks', 'https://issuer.example/jwks', 'enabled'),
             ('egr_1', 'token_review', 'https://k8s.example/review', 'disabled')",
    )
    .await;
    let entry = registry::get_egress_allowlist_entry(&pool, "egr_1")
        .await
        .unwrap();
    assert_eq!(
        (
            entry.purpose,
            &entry.exact_destination[..],
            entry.status,
            entry.revision
        ),
        (
            EgressPurpose::TokenReview,
            "https://k8s.example/review",
            Status::Disabled,
            1
        )
    );
    let ids: Vec<_> = registry::list_egress_allowlist_entries(&pool, Page::first(10))
        .await
        .unwrap()
        .into_iter()
        .map(|e| (e.id, e.purpose))
        .collect();
    assert_eq!(
        ids,
        [
            ("egr_1".into(), EgressPurpose::TokenReview),
            ("egr_2".into(), EgressPurpose::Jwks)
        ]
    );
    let after = registry::list_egress_allowlist_entries(&pool, Page::after("egr_1", 10))
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    db.drop([pool]).await;
}
