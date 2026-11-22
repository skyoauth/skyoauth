//! The scope ceilings of an exchange (`persistence::registry`,
//! `load_scope_ceilings`, with `policy::resolve_scopes`; IR-062, IR-063;
//! design section 5.7; T12.8) against a real PostgreSQL server: the loaded values
//! are the registry's rows, the target service is a ceiling exactly for a
//! delegation or impersonation grant (never a direct one, inferred), every miss is the same `None` (including an
//! audience the target service does not list, IR-083), disabled records are
//! loaded and reported by `all_enabled`, and a ceiling that shrinks after
//! the grant was written makes its defaults fail.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! creates and drops its own database. They are registry tests in the shape
//! of A26 (M1a "policy"), not that conformance scenario, which belongs to
//! the test session in `tests/security`.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{self, CeilingRecord, GrantMode, LoadedCeilings, Status, load_scope_ceilings},
};
use skyoauth_service::policy::{ScopeError, ScopeRequest, resolve_scopes};
use sqlx::AssertSqlSafe;

/// Tenants `ten_a` and `ten_b`. Resource servers, by audience:
///
/// - `api-1` (`rs_1`, scopes `read`, `deploy:write`, `admin`), assigned to
///   `ten_a` (`ata_1`: `read`, `deploy:write`) and to `ten_b` (`ata_b1`:
///   `read`, `admin`).
/// - `api-2` (`rs_2`), assigned only to `ten_b`.
/// - `api-3` (`rs_3`), assigned to `ten_a` but in no grant's set.
/// - `api-4` (`rs_4`, scopes `read`), assigned to `ten_a` (`ata_4`) and in
///   the sets of `grt_direct` and `grt_dlg`, but not in `svc_1`'s.
///
/// In `ten_a`: workload `wld_1`, service `svc_1` (`max_scopes` `read`;
/// audience `api-1` only) and grants of `wld_1` with the audience `api-1`:
/// `grt_direct` (scopes `read`, `deploy:write`, `admin`; defaults `read`,
/// `deploy:write`), `grt_dlg`, a delegation to `svc_1` (scopes `read`,
/// `deploy:write`; defaults `read`), and `grt_imp`, the dormant
/// impersonation grant as `svc_1` (scopes `read`, `deploy:write`; disabled
/// and `requires_reapproval`, as the schema requires). In `ten_b`: the
/// direct grant `grt_b` with `api-1`.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO principal VALUES
        ('wld_1', 'ten_a', 'workload', 'deployer', 'enabled'),
        ('svc_1', 'ten_a', 'service', 'deploy-api', 'enabled'),
        ('wld_b', 'ten_b', 'workload', 'deployer', 'enabled');
    INSERT INTO resource_server VALUES
        ('rs_1', 'api-1', 'API 1', '["wif"]', '["read", "deploy:write", "admin"]', '[]', 'enabled'),
        ('rs_2', 'api-2', 'API 2', '["wif"]', '["read"]', '[]', 'enabled'),
        ('rs_3', 'api-3', 'API 3', '["wif"]', '["read"]', '[]', 'enabled'),
        ('rs_4', 'api-4', 'API 4', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["read", "deploy:write"]', '[]', 'enabled'),
        ('ata_3', 'rs_3', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled'),
        ('ata_4', 'rs_4', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled'),
        ('ata_b1', 'rs_1', 'ten_b', '["wif"]', '["read", "admin"]', '[]', 'enabled'),
        ('ata_b2', 'rs_2', 'ten_b', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO service_identity VALUES ('svc_1', 'ten_a', 'deploy-api', '["read"]', '{}', 'enabled');
    INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', 'rs_1');
    INSERT INTO trust_source VALUES
        ('src_1', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled'),
        ('src_b', 'ten_b', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_1', 'ten_a', 'deploy', 'src_1', 'generic_production', '{"sub": "repo:acme/platform"}', 'wld_1', 'enabled'),
        ('bnd_b', 'ten_b', 'deploy', 'src_b', 'generic_production', '{"sub": "repo:acme/platform"}', 'wld_b', 'enabled');
    INSERT INTO service_grant VALUES
        ('grt_direct', 'ten_a', 'direct', 'wld_1', NULL, 'direct', '["read", "deploy:write", "admin"]',
         '["read", "deploy:write"]', '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_dlg', 'ten_a', 'delegated', 'wld_1', 'svc_1', 'delegation', '["read", "deploy:write"]',
         '["read"]', '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_imp', 'ten_a', 'impersonated', 'wld_1', 'svc_1', 'impersonation', '["read", "deploy:write"]',
         NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval'),
        ('grt_b', 'ten_b', 'direct', 'wld_b', NULL, 'direct', '["read", "admin"]', NULL, '{}', 300, NULL,
         'enabled', 'not_required');
    INSERT INTO service_grant_binding VALUES
        ('grt_direct', 'bnd_1', 'ten_a', 'wld_1'), ('grt_dlg', 'bnd_1', 'ten_a', 'wld_1'),
        ('grt_imp', 'bnd_1', 'ten_a', 'wld_1'), ('grt_b', 'bnd_b', 'ten_b', 'wld_b');
    INSERT INTO service_grant_resource_server VALUES
        ('grt_direct', 'ten_a', 'rs_1'), ('grt_dlg', 'ten_a', 'rs_1'), ('grt_imp', 'ten_a', 'rs_1'),
        ('grt_b', 'ten_b', 'rs_1'), ('grt_direct', 'ten_a', 'rs_4'), ('grt_dlg', 'ten_a', 'rs_4');
"#;

async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    sqlx::raw_sql(SEED).execute(&pool).await.unwrap();
    (db, pool)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn explicit(values: &[&str]) -> ScopeRequest {
    ScopeRequest::Explicit(strings(values))
}

async fn load(pool: &PgPool, tenant: &str, grant: &str, audience: &str) -> LoadedCeilings {
    load_scope_ceilings(pool, tenant, grant, audience)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{tenant} {grant} {audience}"))
}

/// The scopes `request` resolves to with the ceilings loaded now.
async fn resolve(
    pool: &PgPool,
    grant: &str,
    request: &ScopeRequest,
) -> Result<Vec<String>, ScopeError> {
    let loaded = load(pool, "ten_a", grant, "api-1").await;
    resolve_scopes(request, loaded.default_scopes(), &loaded.scope_ceilings())
}

/// The loaded values are the registry's rows; the target service is loaded
/// exactly for a grant with a target, the delegation and the dormant
/// impersonation grant; another tenant with the same audience gets its own
/// assignment.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn ceilings_are_the_registry_rows_and_the_target_only_for_a_target_grant() {
    let (db, pool) = seeded().await;
    let grant = registry::get_service_grant(&pool, "ten_a", "grt_direct")
        .await
        .unwrap();
    let server = registry::get_resource_server(&pool, "rs_1").await.unwrap();
    let assignment = registry::get_audience_tenant_assignment(&pool, "ata_1")
        .await
        .unwrap();
    let direct = load(&pool, "ten_a", "grt_direct", "api-1").await;
    assert_eq!(
        direct,
        LoadedCeilings {
            grant: CeilingRecord {
                id: grant.id.clone(),
                status: grant.status,
                revision: grant.revision,
                scopes: grant.scopes.clone(),
            },
            grant_mode: GrantMode::Direct,
            grant_default_scopes: grant.default_scopes.clone(),
            resource_server: CeilingRecord {
                id: server.id.clone(),
                status: server.status,
                revision: server.revision,
                scopes: server.scopes.clone(),
            },
            assignment: CeilingRecord {
                id: assignment.id.clone(),
                status: assignment.status,
                revision: assignment.revision,
                scopes: assignment.allowed_scopes.clone(),
            },
            target_service: None,
        }
    );
    assert_eq!(direct.scope_ceilings().target_service, None);
    assert_eq!(
        direct.default_scopes(),
        Some(&strings(&["read", "deploy:write"])[..])
    );

    let service = registry::get_service_identity(&pool, "ten_a", "svc_1")
        .await
        .unwrap();
    let delegation = load(&pool, "ten_a", "grt_dlg", "api-1").await;
    assert_eq!(delegation.grant_mode, GrantMode::Delegation);
    assert_eq!(delegation.grant.id, "grt_dlg");
    assert_eq!(delegation.assignment.id, "ata_1");
    assert_eq!(
        delegation.target_service,
        Some(CeilingRecord {
            id: service.id.clone(),
            status: service.status,
            revision: service.revision,
            scopes: service.max_scopes.clone(),
        })
    );
    assert_eq!(
        delegation.scope_ceilings().target_service,
        Some(strings(&["read"]))
    );
    assert!(direct.all_enabled() && delegation.all_enabled());

    // The dormant impersonation grant is loaded, disabled, with its target
    // service as a ceiling too.
    let impersonation = load(&pool, "ten_a", "grt_imp", "api-1").await;
    assert_eq!(impersonation.grant_mode, GrantMode::Impersonation);
    assert_eq!(impersonation.grant.status, Status::Disabled);
    assert_eq!(impersonation.target_service, delegation.target_service);
    assert_eq!(
        impersonation.scope_ceilings().target_service,
        Some(strings(&["read"]))
    );
    assert!(!impersonation.all_enabled());
    assert_eq!(
        resolve(&pool, "grt_imp", &explicit(&["deploy:write"])).await,
        Err(ScopeError::Invalid)
    );

    // ten_b's grant on the same audience gets ten_b's assignment.
    let other = load(&pool, "ten_b", "grt_b", "api-1").await;
    assert_eq!(
        (
            other.assignment.id.as_str(),
            other.assignment.scopes.clone()
        ),
        ("ata_b1", strings(&["read", "admin"]))
    );
    assert_eq!(other.grant_default_scopes, None);
    db.drop([pool]).await;
}

/// Every miss is the same `None`: another tenant's grant, an unknown grant
/// or tenant, an unknown audience, one not assigned to the tenant, one
/// assigned but not in the grant's set, and, for a grant with a target
/// service, one in the grant's set but not in the service's (IR-083),
/// including once the service's audience row is removed.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_miss_is_the_same_none() {
    let (db, pool) = seeded().await;
    // api-4 is in the sets of grt_direct and grt_dlg and assigned to ten_a,
    // so only svc_1's set keeps the delegation from it.
    load(&pool, "ten_a", "grt_direct", "api-4").await;
    for (tenant, grant, audience) in [
        ("ten_b", "grt_direct", "api-1"),
        ("ten_a", "grt_b", "api-1"),
        ("ten_a", "grt_none", "api-1"),
        ("ten_none", "grt_direct", "api-1"),
        ("ten_a", "grt_direct", "api-none"),
        ("ten_a", "grt_direct", "API-1"),
        ("ten_a", "grt_direct", "rs_1"),
        ("ten_a", "grt_direct", "api-2"),
        ("ten_a", "grt_direct", "api-3"),
        ("ten_a", "grt_dlg", "api-3"),
        ("ten_b", "grt_b", "api-3"),
        ("ten_a", "grt_dlg", "api-4"),
        ("", "", ""),
    ] {
        assert_eq!(
            load_scope_ceilings(&pool, tenant, grant, audience)
                .await
                .unwrap(),
            None,
            "{tenant} {grant} {audience}"
        );
    }

    // Once svc_1 no longer lists api-1, neither grant with svc_1 as its
    // target loads for it; the direct grant still does.
    load(&pool, "ten_a", "grt_dlg", "api-1").await;
    load(&pool, "ten_a", "grt_imp", "api-1").await;
    let service = registry::get_service_identity(&pool, "ten_a", "svc_1")
        .await
        .unwrap();
    registry::remove_service_identity_resource_server(
        &pool,
        "ten_a",
        "svc_1",
        service.revision,
        "rs_1",
    )
    .await
    .unwrap();
    for grant in ["grt_dlg", "grt_imp"] {
        assert_eq!(
            load_scope_ceilings(&pool, "ten_a", grant, "api-1")
                .await
                .unwrap(),
            None,
            "{grant}"
        );
    }
    load(&pool, "ten_a", "grt_direct", "api-1").await;
    db.drop([pool]).await;
}

/// The `0004` foreign keys keep a grant's audience assigned to its tenant,
/// its target in its tenant and a service's audience row in the service's
/// tenant; the statement checks all three again. With the keys dropped in a
/// rolled-back transaction, an audience only another tenant is assigned,
/// listed by the grant, is still a miss, a target of another tenant is not
/// loaded even with an audience row in the grant's tenant, and a target's
/// audience row of another tenant does not count.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_statement_rechecks_what_the_foreign_keys_guarantee() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::raw_sql(
        r#"BEGIN;
           ALTER TABLE service_grant_resource_server
               DROP CONSTRAINT service_grant_resource_server_assignment_fkey;
           ALTER TABLE service_grant DROP CONSTRAINT service_grant_target_service_id_fkey;
           INSERT INTO service_grant_resource_server VALUES ('grt_direct', 'ten_a', 'rs_2');
           INSERT INTO principal VALUES ('svc_x', 'ten_b', 'service', 'other-api', 'enabled');
           INSERT INTO service_identity VALUES ('svc_x', 'ten_b', 'other-api', '["read", "deploy:write"]', '{}', 'enabled');
           INSERT INTO service_grant VALUES
               ('grt_x', 'ten_a', 'cross', 'wld_1', 'svc_x', 'delegation', '["read"]', NULL, '{}', 300, NULL,
                'enabled', 'not_required');
           INSERT INTO service_grant_binding VALUES ('grt_x', 'bnd_1', 'ten_a', 'wld_1');
           INSERT INTO service_grant_resource_server VALUES ('grt_x', 'ten_a', 'rs_1');
           ALTER TABLE service_identity_resource_server
               DROP CONSTRAINT service_identity_resource_server_service_id_fkey,
               DROP CONSTRAINT service_identity_resource_server_assignment_fkey;
           INSERT INTO service_identity_resource_server VALUES
               ('svc_1', 'ten_b', 'rs_4'),
               ('svc_x', 'ten_a', 'rs_1')"#,
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    for (grant, audience) in [
        ("grt_direct", "api-2"),
        ("grt_x", "api-1"),
        ("grt_dlg", "api-4"),
    ] {
        assert_eq!(
            load_scope_ceilings(&mut *conn, "ten_a", grant, audience)
                .await
                .unwrap(),
            None,
            "{grant} {audience}"
        );
    }
    sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await.unwrap();
    drop(conn);
    db.drop([pool]).await;
}

/// A direct grant loads no target service, whatever its `target_service_id`
/// holds (inferred): the `0004` check `service_grant_target_mode_check`
/// keeps it `NULL`, and the statement keys the target off `mode` rather than
/// rely on it. With the check dropped in a rolled-back transaction, a direct
/// grant naming `svc_1` loads with no target service for an audience `svc_1`
/// lists and for one it does not; the delegation to `svc_1` still loads it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_direct_grant_loads_no_target_service_even_with_a_target_id() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::raw_sql(
        r#"BEGIN;
           ALTER TABLE service_grant DROP CONSTRAINT service_grant_target_mode_check;
           INSERT INTO service_grant VALUES
               ('grt_dt', 'ten_a', 'direct-target', 'wld_1', 'svc_1', 'direct', '["read"]', NULL, '{}', 300,
                NULL, 'enabled', 'not_required');
           INSERT INTO service_grant_binding VALUES ('grt_dt', 'bnd_1', 'ten_a', 'wld_1');
           INSERT INTO service_grant_resource_server VALUES
               ('grt_dt', 'ten_a', 'rs_1'), ('grt_dt', 'ten_a', 'rs_4')"#,
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    // svc_1 lists api-1 but not api-4.
    for audience in ["api-1", "api-4"] {
        let direct = load_scope_ceilings(&mut *conn, "ten_a", "grt_dt", audience)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("grt_dt {audience}"));
        assert_eq!(direct.grant_mode, GrantMode::Direct, "{audience}");
        assert_eq!(direct.target_service, None, "{audience}");
        assert_eq!(direct.scope_ceilings().target_service, None, "{audience}");
    }
    let delegation = load_scope_ceilings(&mut *conn, "ten_a", "grt_dlg", "api-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        delegation.target_service.map(|service| service.id),
        Some("svc_1".to_owned())
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await.unwrap();
    drop(conn);
    db.drop([pool]).await;
}

/// A disabled grant, resource server, assignment or target service is still
/// loaded, with its status, and `all_enabled` is then false; step 5, not
/// the loader, denies it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn disabled_records_are_loaded_and_not_all_enabled() {
    let (db, pool) = seeded().await;
    for (table, id) in [
        ("service_grant", "grt_dlg"),
        ("resource_server", "rs_1"),
        ("audience_tenant_assignment", "ata_1"),
        ("service_identity", "svc_1"),
    ] {
        // The table and ID are this test's constants.
        let set = |status: &str| {
            AssertSqlSafe(format!(
                "UPDATE {table} SET status = '{status}', revision = revision + 1 \
                 WHERE id = '{id}'"
            ))
        };
        sqlx::raw_sql(set("disabled")).execute(&pool).await.unwrap();
        let delegation = load(&pool, "ten_a", "grt_dlg", "api-1").await;
        let statuses = [
            &delegation.grant,
            &delegation.resource_server,
            &delegation.assignment,
            delegation.target_service.as_ref().unwrap(),
        ]
        .map(|record| (record.id.as_str(), record.status));
        assert!(statuses.contains(&(id, Status::Disabled)), "{table}");
        assert!(!delegation.all_enabled(), "{table}");
        // grt_dlg and svc_1 are not records of the direct grant.
        let direct = load(&pool, "ten_a", "grt_direct", "api-1").await;
        assert_eq!(
            direct.all_enabled(),
            matches!(table, "service_grant" | "service_identity"),
            "{table}"
        );
        sqlx::raw_sql(set("enabled")).execute(&pool).await.unwrap();
        assert!(load(&pool, "ten_a", "grt_dlg", "api-1").await.all_enabled());
    }
    db.drop([pool]).await;
}

/// The A26 policy cases on loaded ceilings: omitted scope is exactly the
/// grant's defaults; explicit scopes must lie in every ceiling, the target
/// service's only for the delegation; an explicit empty list is invalid.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn loaded_ceilings_resolve_the_a26_policy_cases() {
    let (db, pool) = seeded().await;
    // Omitted: the defaults, not the ceiling (admin is in the grant and the
    // resource server, deploy:write in every direct ceiling).
    assert_eq!(
        resolve(&pool, "grt_direct", &ScopeRequest::Omitted).await,
        Ok(strings(&["deploy:write", "read"]))
    );
    assert_eq!(
        resolve(&pool, "grt_dlg", &ScopeRequest::Omitted).await,
        Ok(strings(&["read"]))
    );
    // deploy:write is in every ceiling of the direct grant, but not in
    // svc_1's max_scopes.
    assert_eq!(
        resolve(&pool, "grt_direct", &explicit(&["deploy:write"])).await,
        Ok(strings(&["deploy:write"]))
    );
    assert_eq!(
        resolve(&pool, "grt_dlg", &explicit(&["deploy:write"])).await,
        Err(ScopeError::Invalid)
    );
    // admin is in the grant and the resource server but not ten_a's
    // assignment; it is in ten_b's.
    assert_eq!(
        resolve(&pool, "grt_direct", &explicit(&["read", "admin"])).await,
        Err(ScopeError::Invalid)
    );
    let other = load(&pool, "ten_b", "grt_b", "api-1").await;
    assert_eq!(
        resolve_scopes(&explicit(&["admin"]), None, &other.scope_ceilings()),
        Ok(strings(&["admin"]))
    );
    // ten_b's grant has no defaults.
    assert_eq!(
        resolve_scopes(
            &ScopeRequest::Omitted,
            other.default_scopes(),
            &other.scope_ceilings()
        ),
        Err(ScopeError::Invalid)
    );
    assert_eq!(
        resolve(&pool, "grt_direct", &explicit(&[])).await,
        Err(ScopeError::Invalid)
    );
    assert_eq!(
        resolve(&pool, "grt_direct", &explicit(&["unknown"])).await,
        Err(ScopeError::Invalid)
    );
    db.drop([pool]).await;
}

/// A ceiling that shrinks after the grant was written changes the loaded
/// ceilings, and the grant's defaults then fail instead of being trimmed:
/// the assignment's `allowed_scopes`, the resource server's `scopes` and
/// the target service's `max_scopes`, each in turn.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn defaults_fail_once_a_ceiling_shrinks() {
    let (db, pool) = seeded().await;
    for (shrink, restore) in [
        (
            r#"UPDATE audience_tenant_assignment SET allowed_scopes = '["read"]',
                   revision = revision + 1 WHERE id = 'ata_1'"#,
            r#"UPDATE audience_tenant_assignment SET allowed_scopes = '["read", "deploy:write"]',
                   revision = revision + 1 WHERE id = 'ata_1'"#,
        ),
        (
            r#"UPDATE resource_server SET scopes = '["read", "admin"]',
                   revision = revision + 1 WHERE id = 'rs_1'"#,
            r#"UPDATE resource_server SET scopes = '["read", "deploy:write", "admin"]',
                   revision = revision + 1 WHERE id = 'rs_1'"#,
        ),
    ] {
        sqlx::raw_sql(shrink).execute(&pool).await.unwrap();
        let loaded = load(&pool, "ten_a", "grt_direct", "api-1").await;
        let server = registry::get_resource_server(&pool, "rs_1").await.unwrap();
        let assignment = registry::get_audience_tenant_assignment(&pool, "ata_1")
            .await
            .unwrap();
        assert_eq!(
            (
                &loaded.resource_server.scopes,
                loaded.resource_server.revision
            ),
            (&server.scopes, server.revision)
        );
        assert_eq!(
            (&loaded.assignment.scopes, loaded.assignment.revision),
            (&assignment.allowed_scopes, assignment.revision)
        );
        assert_eq!(
            resolve(&pool, "grt_direct", &ScopeRequest::Omitted).await,
            Err(ScopeError::Invalid),
            "{shrink}"
        );
        // What is left of the defaults still resolves when asked for.
        assert_eq!(
            resolve(&pool, "grt_direct", &explicit(&["read"])).await,
            Ok(strings(&["read"]))
        );
        sqlx::raw_sql(restore).execute(&pool).await.unwrap();
        assert_eq!(
            resolve(&pool, "grt_direct", &ScopeRequest::Omitted).await,
            Ok(strings(&["deploy:write", "read"]))
        );
    }
    // The target service's max_scopes.
    sqlx::raw_sql(
        r#"UPDATE service_identity SET max_scopes = '["deploy:write"]', revision = revision + 1
            WHERE id = 'svc_1'"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let loaded = load(&pool, "ten_a", "grt_dlg", "api-1").await;
    let service = registry::get_service_identity(&pool, "ten_a", "svc_1")
        .await
        .unwrap();
    let target = loaded.target_service.as_ref().unwrap();
    assert_eq!(
        (&target.scopes, target.revision),
        (&service.max_scopes, service.revision)
    );
    assert_eq!(
        resolve(&pool, "grt_dlg", &ScopeRequest::Omitted).await,
        Err(ScopeError::Invalid)
    );
    assert_eq!(
        resolve(&pool, "grt_dlg", &explicit(&["deploy:write"])).await,
        Ok(strings(&["deploy:write"]))
    );
    // The direct grant has no target, so svc_1 does not bound it.
    assert_eq!(
        resolve(&pool, "grt_direct", &ScopeRequest::Omitted).await,
        Ok(strings(&["deploy:write", "read"]))
    );
    db.drop([pool]).await;
}
