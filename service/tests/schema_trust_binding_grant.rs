//! Constraints and guards of the `0004_trust_binding_grant` migration against
//! a real PostgreSQL server: trust sources, trust keysets and their versions,
//! principal bindings, service identities and service grants.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database, and the replica-role test needs
//! `SET` on `session_replication_role` (`common/mod.rs`).
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use common::TestDb;
use skyoauth_service::persistence::{self, PgPool};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Postgres};
use std::time::Duration;

/// Two tenants with workload, service and human principals; an audience
/// assigned to each tenant; in `ten_a` a keyset with one version, one source
/// of each kind plus a Kubernetes local-JWT source (`src_local`), bindings
/// for `wld_1` and `wld_2`, a service identity and a direct, a delegated and
/// a dormant impersonation grant; in `ten_b` one of each, with the same
/// names and issuer as in `ten_a`.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO principal VALUES
        ('wld_1', 'ten_a', 'workload', 'w1', 'enabled'),
        ('wld_2', 'ten_a', 'workload', 'w2', 'enabled'),
        ('svc_1', 'ten_a', 'service', 's1', 'enabled'),
        ('svc_2', 'ten_a', 'service', 's2', 'enabled'),
        ('usr_1', 'ten_a', 'human', 'u1', 'enabled'),
        ('wld_b', 'ten_b', 'workload', 'wb', 'enabled'),
        ('svc_b', 'ten_b', 'service', 'sb', 'enabled'),
        ('svc_c', 'ten_b', 'service', 'sc', 'enabled');
    INSERT INTO resource_server VALUES
        ('rs_1', 'api-1', 'API 1', '["wif"]', '["read", "deploy:write"]', '[]', 'enabled'),
        ('rs_2', 'api-2', 'API 2', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled'),
        ('ata_2', 'rs_2', 'ten_b', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO trust_keyset VALUES ('ks_1', 'ten_a', 'partner', 'enabled'), ('ks_b', 'ten_b', 'partner', 'enabled');
    INSERT INTO trust_keyset_version VALUES
        ('kv_1', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AA", "y": "AA"}]}',
         'sha256:01', '2026-01-01Z', NULL, 'enabled', '{"uploaded_by": "adm_1"}');
    INSERT INTO trust_source VALUES
        ('src_gh', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'on_demand_jwt', NULL, 'single_use', 'enabled'),
        ('src_up', 'ten_a', 'partner', 'uploaded_jwks', 'https://ci.partner.example', NULL,
         'ks_1', NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["ES256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled'),
        ('src_k8s', 'ten_a', 'k3s', 'kubernetes_token_review', 'https://kubernetes.default.svc', NULL,
         NULL, 'cluster_1', 'https://k3s.internal.example:6443', 'ca_k3s', 'sha256:ca', 'reviewer_k3s', 5000,
         '["https://identity.example.com"]', NULL, '{}', 'projected_service_account', NULL, 'reusable', 'enabled'),
        ('src_local', 'ten_a', 'k3s-local', 'uploaded_jwks', 'https://kubernetes.default.svc', NULL,
         'ks_1', NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'projected_service_account', true, 'reusable', 'enabled'),
        ('src_b', 'ten_b', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_1', 'ten_a', 'release', 'src_gh', 'github_production', '{"repository_id": "456789", "event_name": "push"}', 'wld_1', 'enabled'),
        ('bnd_2', 'ten_a', 'deploy', 'src_gh', 'github_production', '{"repository_id": "456789", "environment": "production"}', 'wld_1', 'enabled'),
        ('bnd_3', 'ten_a', 'k3s', 'src_k8s', 'kubernetes_production', '{"namespace": "ci", "service_account_uid": "u-1"}', 'wld_2', 'enabled'),
        ('bnd_b', 'ten_b', 'release', 'src_b', 'generic_production', '{"sub": "repo:b"}', 'wld_b', 'enabled');
    INSERT INTO service_identity VALUES
        ('svc_1', 'ten_a', 'deployer', '["read"]', '{"version": 1, "authorization": "allowlist"}', 'enabled'),
        ('svc_b', 'ten_b', 'deployer', '["read"]', '{}', 'enabled');
    INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', 'rs_1'), ('svc_b', 'ten_b', 'rs_2');
    INSERT INTO service_grant VALUES
        ('grt_1', 'ten_a', 'direct', 'wld_1', NULL, 'direct', '["read", "deploy:write"]', '["read"]', '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_2', 'ten_a', 'delegated', 'wld_1', 'svc_1', 'delegation', '["read"]', NULL, '{}', 60, '2027-01-01Z', 'enabled', 'not_required'),
        ('grt_3', 'ten_a', 'dormant', 'wld_2', 'svc_1', 'impersonation', '["read"]', NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval'),
        ('grt_b', 'ten_b', 'direct', 'wld_b', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required');
    INSERT INTO service_grant_binding VALUES
        ('grt_1', 'bnd_1', 'ten_a', 'wld_1'), ('grt_2', 'bnd_1', 'ten_a', 'wld_1'), ('grt_2', 'bnd_2', 'ten_a', 'wld_1'),
        ('grt_3', 'bnd_3', 'ten_a', 'wld_2'), ('grt_b', 'bnd_b', 'ten_b', 'wld_b');
    INSERT INTO service_grant_resource_server VALUES
        ('grt_1', 'ten_a', 'rs_1'), ('grt_2', 'ten_a', 'rs_1'), ('grt_b', 'ten_b', 'rs_2')"#;

/// The revisioned tables.
const TABLES: [&str; 5] = [
    "trust_keyset",
    "trust_source",
    "principal_binding",
    "service_identity",
    "service_grant",
];

/// Every table of 0004.
const ALL_TABLES: [&str; 9] = [
    "trust_keyset",
    "trust_keyset_version",
    "trust_source",
    "principal_binding",
    "service_identity",
    "service_identity_resource_server",
    "service_grant",
    "service_grant_binding",
    "service_grant_resource_server",
];

async fn seeded_on(pool: &PgPool) {
    persistence::migrate(pool).await.unwrap();
    run(pool, SEED).await;
}

async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    seeded_on(&pool).await;
    (db, pool)
}

async fn run<'c>(executor: impl Executor<'c, Database = Postgres>, sql: &'static str) {
    if let Err(err) = sqlx::raw_sql(sql).execute(executor).await {
        panic!("{sql}: {err}");
    }
}

fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
        .unwrap_or_else(|| panic!("not a database error: {err}"))
}

/// Runs each case on its own and checks that it fails with its SQLSTATE.
/// A case is one line, `<SQLSTATE> <statements>`; blank lines are skipped.
/// The statements of a line run in one implicit transaction, so a deferred
/// check fails the line too. SK001 is the guard triggers' state; 23502 is
/// `not_null_violation`, 23503 `foreign_key_violation`, 23505
/// `unique_violation` and 23514 `check_violation` (also raised by a
/// domain's CHECK).
async fn assert_rejected(conn: &mut PgConnection, cases: &'static str) {
    for case in cases.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (code, sql) = case.split_once(' ').unwrap();
        let err = sqlx::raw_sql(sql).execute(&mut *conn).await.expect_err(sql);
        assert_eq!(sqlstate(&err), code, "{sql}: {err}");
    }
}

async fn rejects(pool: &PgPool, cases: &'static str) {
    assert_rejected(&mut pool.acquire().await.unwrap(), cases).await;
}

async fn revision(pool: &PgPool, table: &str) -> Vec<i64> {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT revision FROM {table} ORDER BY id"
    )))
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn rows(pool: &PgPool, sql: &'static str) -> Vec<(String, String)> {
    sqlx::query_as(sql).fetch_all(pool).await.unwrap()
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_migration_is_recorded_once_and_rerun_is_a_no_op() {
    let (db, pool) = seeded().await;
    let recorded = || async {
        sqlx::query_as::<_, (i64, String, bool)>(
            "SELECT version, description, success FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
    };
    let first = recorded().await;
    assert!(
        first.contains(&(4, "trust binding grant".into(), true)),
        "{first:?}"
    );
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(recorded().await, first);
    for table in TABLES {
        assert!(
            revision(&pool, table).await.iter().all(|r| *r == 1),
            "{table}"
        );
    }
    db.drop([pool]).await;
}

/// Catalog properties that behaviour tests cannot see directly.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_catalog_pins_collation_triggers_and_search_path() {
    let (db, pool) = seeded().await;
    let tables: Vec<String> = ALL_TABLES.iter().map(|t| t.to_string()).collect();

    // Every trigger of 0004 is a guard that fires in every
    // session_replication_role and calls a function with a pinned path; the
    // two binding-set checks are deferred to commit.
    let mut triggers: Vec<(String, String, String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname::text, t.tgname::text, t.tgenabled::text,
                coalesce(array_to_string(p.proconfig, ',') ~ '^search_path=pg_catalog, (.*, )?pg_temp$', false),
                t.tgdeferrable AND t.tginitdeferred
         FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND c.relname = ANY($1)",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    triggers.sort();
    let guard = |table: &str, name: &str, deferred: bool| {
        (
            table.to_string(),
            format!("{table}_{name}"),
            "A".to_string(),
            true,
            deferred,
        )
    };
    let mut expected: Vec<_> = ALL_TABLES
        .iter()
        .map(|t| guard(t, "immutable", false))
        .chain(TABLES.iter().map(|t| guard(t, "revision", false)))
        .chain([
            guard("service_grant", "has_binding", true),
            guard("service_grant_binding", "keeps_one", true),
        ])
        .collect();
    expected.sort();
    assert_eq!(triggers, expected);

    // Every function in the schema, other than the frozen 0001 guard that
    // resolves no names, pins search_path with pg_catalog first and pg_temp
    // last (schema_foundation.rs checks the exact paths of 0002).
    let unpinned: Vec<String> = sqlx::query_scalar(
        "SELECT p.proname::text FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname <> 'skyoauth_reject_mutation'
           AND NOT coalesce(array_to_string(p.proconfig, ',') ~ '^search_path=pg_catalog, (.*, )?pg_temp$', false)
         ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(unpinned.is_empty(), "{unpinned:?}");

    // The one new function reads tables: it pins the schema and names both
    // tables with it.
    let (config, source): (Vec<String>, String) = sqlx::query_as(
        "SELECT p.proconfig, p.prosrc FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname = 'skyoauth_service_grant_has_binding'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(config, ["search_path=pg_catalog, public, pg_temp"]);
    for table in ["service_grant", "service_grant_binding"] {
        let names = source.matches(&format!(" {table} ")).count();
        let qualified = source.matches(&format!(" public.{table} ")).count();
        assert!(names == 0 && qualified > 0, "{table}: {source}");
    }

    // IDs, keys, references and enumerations compare byte-wise; only names
    // do not.
    let not_c: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text FROM information_schema.columns
         WHERE table_schema = current_schema() AND table_name = ANY($1)
           AND data_type = 'text' AND collation_name IS DISTINCT FROM 'C'
         ORDER BY 1, 2",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut names: Vec<(String, String)> = TABLES
        .iter()
        .map(|t| (t.to_string(), "name".to_string()))
        .collect();
    names.sort();
    assert_eq!(not_c, names);

    // No foreign key cascades or nulls out a referencing row.
    let actions: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname::text, confupdtype::text || confdeltype::text FROM pg_constraint
         WHERE contype = 'f' AND connamespace = to_regnamespace(quote_ident(current_schema()))
           AND (confupdtype <> 'a' OR confdeltype <> 'a')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(actions.is_empty(), "{actions:?}");

    // Every foreign key of 0004 is named <table>_<description>_fkey, is
    // NO ACTION on update and delete, MATCH SIMPLE and not deferrable.
    let mut fkeys: Vec<(String, String, String, bool, String)> = sqlx::query_as(
        "SELECT c.relname::text, k.conname::text, pg_get_constraintdef(k.oid),
                k.condeferrable OR k.condeferred,
                k.confupdtype::text || k.confdeltype::text || k.confmatchtype::text
         FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
         WHERE k.contype = 'f' AND c.relnamespace = to_regnamespace(quote_ident(current_schema()))
           AND c.relname = ANY($1)",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    fkeys.sort();
    let fkey = |table: &str, name: &str, def: &str| {
        (
            table.to_string(),
            format!("{table}_{name}_fkey"),
            format!("FOREIGN KEY {def}"),
            false,
            "aas".to_string(),
        )
    };
    let tenant = "(tenant_id) REFERENCES tenant(id)";
    let mut expected = vec![
        fkey(
            "principal_binding",
            "source",
            "(tenant_id, trust_source_id) REFERENCES trust_source(tenant_id, id)",
        ),
        fkey("principal_binding", "tenant", tenant),
        fkey(
            "principal_binding",
            "workload",
            "(tenant_id, workload_principal_id, workload_principal_kind) REFERENCES principal(tenant_id, id, kind)",
        ),
        fkey(
            "service_grant",
            "actor",
            "(tenant_id, actor_principal_id, actor_principal_kind) REFERENCES principal(tenant_id, id, kind)",
        ),
        fkey(
            "service_grant",
            "target",
            "(tenant_id, target_service_id) REFERENCES service_identity(tenant_id, id)",
        ),
        fkey("service_grant", "tenant", tenant),
        fkey(
            "service_grant_binding",
            "binding",
            "(tenant_id, binding_id, actor_principal_id) REFERENCES principal_binding(tenant_id, id, workload_principal_id)",
        ),
        fkey(
            "service_grant_binding",
            "grant",
            "(tenant_id, grant_id, actor_principal_id) REFERENCES service_grant(tenant_id, id, actor_principal_id)",
        ),
        fkey(
            "service_grant_resource_server",
            "assignment",
            "(tenant_id, resource_server_id) REFERENCES audience_tenant_assignment(tenant_id, resource_server_id)",
        ),
        fkey(
            "service_grant_resource_server",
            "grant",
            "(tenant_id, grant_id) REFERENCES service_grant(tenant_id, id)",
        ),
        fkey(
            "service_identity",
            "principal",
            "(tenant_id, id, principal_kind) REFERENCES principal(tenant_id, id, kind)",
        ),
        fkey("service_identity", "tenant", tenant),
        fkey(
            "service_identity_resource_server",
            "assignment",
            "(tenant_id, resource_server_id) REFERENCES audience_tenant_assignment(tenant_id, resource_server_id)",
        ),
        fkey(
            "service_identity_resource_server",
            "service",
            "(tenant_id, service_id) REFERENCES service_identity(tenant_id, id)",
        ),
        fkey("trust_keyset", "tenant", tenant),
        fkey(
            "trust_keyset_version",
            "keyset",
            "(tenant_id, keyset_id) REFERENCES trust_keyset(tenant_id, id)",
        ),
        fkey("trust_keyset_version", "tenant", tenant),
        fkey(
            "trust_source",
            "keyset",
            "(tenant_id, jwks_keyset_id) REFERENCES trust_keyset(tenant_id, id)",
        ),
        fkey("trust_source", "tenant", tenant),
    ];
    expected.sort();
    assert_eq!(fkeys, expected);

    // Only the fields the logical model marks optional, and the kind-specific
    // fields of trust sources, may be NULL.
    let nullable: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
         WHERE c.relnamespace = to_regnamespace(quote_ident(current_schema())) AND c.relname = ANY($1)
           AND a.attnum > 0 AND NOT a.attisdropped AND NOT a.attnotnull
         ORDER BY 1, 2",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    let optional = [
        ("service_grant", "default_scopes"),
        ("service_grant", "target_service_id"),
        ("service_grant", "valid_until"),
        ("trust_keyset_version", "expires_at"),
        ("trust_source", "algorithms"),
        ("trust_source", "ca_bundle_ref"),
        ("trust_source", "ca_fingerprint"),
        ("trust_source", "cluster_id"),
        ("trust_source", "discovery_url"),
        ("trust_source", "jwks_keyset_id"),
        ("trust_source", "review_timeout_ms"),
        ("trust_source", "reviewer_credential_ref"),
        ("trust_source", "stale_revocation_acknowledged"),
        ("trust_source", "token_review_endpoint"),
    ];
    let optional: Vec<(String, String)> = optional
        .iter()
        .map(|(t, c)| (t.to_string(), c.to_string()))
        .collect();
    assert_eq!(nullable, optional);

    // Every ID and reference is a skyoauth_id; issuers, URLs, secret
    // references and fingerprints are skyoauth_exact_string. Both domains
    // compare byte-wise and leave NULL to the column.
    let typed: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT c.relname::text, a.attname::text, format_type(a.atttypid, a.atttypmod)
         FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
         WHERE c.relnamespace = to_regnamespace(quote_ident(current_schema())) AND c.relname = ANY($1)
           AND a.attnum > 0 AND NOT a.attisdropped
           AND (a.attname = 'id' OR a.attname LIKE '%\\_id'
                OR format_type(a.atttypid, a.atttypmod) LIKE 'skyoauth\\_%\\_string')
         ORDER BY 1, 2",
    )
    .bind(&tables)
    .fetch_all(&pool)
    .await
    .unwrap();
    let exact = [
        ("trust_keyset_version", "fingerprint"),
        ("trust_source", "ca_bundle_ref"),
        ("trust_source", "ca_fingerprint"),
        ("trust_source", "discovery_url"),
        ("trust_source", "exact_issuer"),
        ("trust_source", "reviewer_credential_ref"),
        ("trust_source", "token_review_endpoint"),
    ];
    let wrong: Vec<&(String, String, String)> = typed
        .iter()
        .filter(|(t, c, ty)| {
            let want = if exact.contains(&(t.as_str(), c.as_str())) {
                "skyoauth_exact_string"
            } else {
                "skyoauth_id"
            };
            ty != want
        })
        .collect();
    assert!(wrong.is_empty(), "{wrong:?}");
    assert_eq!(
        typed
            .iter()
            .filter(|(_, _, ty)| ty == "skyoauth_exact_string")
            .count(),
        exact.len(),
        "{typed:?}"
    );
    let domains: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT t.typname::text, co.collname::text, t.typnotnull FROM pg_type t
         JOIN pg_collation co ON co.oid = t.typcollation
         WHERE t.typnamespace = to_regnamespace(quote_ident(current_schema()))
           AND t.typname IN ('skyoauth_id', 'skyoauth_exact_string')
         ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        domains,
        [
            ("skyoauth_exact_string".to_string(), "C".to_string(), false),
            ("skyoauth_id".to_string(), "C".to_string(), false),
        ]
    );
    db.drop([pool]).await;
}

/// A NULL in any column of a composite reference would make MATCH SIMPLE skip
/// the check, so those columns are NOT NULL; the optional keyset and target
/// references are pinned by CHECKs instead (trust_source_fields_follow_its_kind,
/// grant_mode_fixes_its_target_and_activation_state).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn composite_reference_columns_reject_null() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23502 INSERT INTO trust_keyset VALUES ('ks_2', NULL, 'x', 'enabled')
        23502 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', NULL, 'enabled')
        23502 INSERT INTO trust_keyset_version VALUES ('kv_2', NULL, 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23502 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', NULL, '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23502 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', NULL, '2026-01-01Z', NULL, 'enabled', '{}')
        23502 INSERT INTO trust_source VALUES ('src_x', NULL, 'x', 'uploaded_jwks', 'https://x', NULL, 'ks_1', NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23502 INSERT INTO trust_source VALUES ('src_x', 'ten_a', NULL, 'uploaded_jwks', 'https://x', NULL, 'ks_1', NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23502 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'uploaded_jwks', NULL, NULL, 'ks_1', NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23502 INSERT INTO principal_binding VALUES ('bnd_x', NULL, 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23502 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', NULL, 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23502 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', NULL, 'enabled')
        23502 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled', 1, NULL)
        23502 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', NULL, 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23502 INSERT INTO service_identity VALUES (NULL, 'ten_a', 'x', '[]', '{}', 'enabled')
        23502 INSERT INTO service_identity VALUES ('svc_2', NULL, 'x', '[]', '{}', 'enabled')
        23502 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', 'x', '[]', '{}', 'enabled', 1, NULL)
        23502 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', NULL, '[]', '{}', 'enabled')
        23502 INSERT INTO service_identity_resource_server VALUES (NULL, 'ten_a', 'rs_1')
        23502 INSERT INTO service_identity_resource_server VALUES ('svc_1', NULL, 'rs_1')
        23502 INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', NULL)
        23502 INSERT INTO service_grant VALUES ('grt_x', NULL, 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23502 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', NULL, NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23502 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required', 1, NULL)
        23502 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', NULL, 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23502 INSERT INTO service_grant_binding VALUES (NULL, 'bnd_2', 'ten_a', 'wld_1')
        23502 INSERT INTO service_grant_binding VALUES ('grt_1', NULL, 'ten_a', 'wld_1')
        23502 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_2', NULL, 'wld_1')
        23502 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_2', 'ten_a', NULL)
        23502 INSERT INTO service_grant_resource_server VALUES (NULL, 'ten_a', 'rs_1')
        23502 INSERT INTO service_grant_resource_server VALUES ('grt_3', NULL, 'rs_1')
        23502 INSERT INTO service_grant_resource_server VALUES ('grt_3', 'ten_a', NULL)
    "#).await;
    db.drop([pool]).await;
}

/// IDs and references are at most 255 bytes, names and exact strings at
/// most 2048 bytes, so an over-long value is a check violation (23514) and
/// never a btree size error (54000); IDs, references and exact strings hold
/// no whitespace or control characters, names may hold spaces.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn keys_names_and_exact_strings_are_bounded() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23514 INSERT INTO trust_keyset VALUES (repeat('k', 256), 'ten_a', 'x', 'enabled')
        23514 INSERT INTO trust_keyset VALUES (repeat('é', 128), 'ten_a', 'x', 'enabled')
        23514 INSERT INTO trust_keyset VALUES ('ks 2', 'ten_a', 'x', 'enabled')
        23514 INSERT INTO trust_keyset VALUES (E'ks_2\t', 'ten_a', 'x', 'enabled')
        23514 INSERT INTO trust_keyset VALUES (E'ks_2\n', 'ten_a', 'x', 'enabled')
        23514 INSERT INTO trust_keyset VALUES (E'ks_2\u0085', 'ten_a', 'x', 'enabled')
        23514 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', repeat('n', 2049), 'enabled')
        23514 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', repeat('€', 683), 'enabled')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', repeat('f', 2049), '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'sha256: 02', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', repeat('k', 256), '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'kubernetes_token_review', 'https://x', NULL, NULL, repeat('c', 256), 'https://x:6443', 'ca', 'fp', 'rv', 1, '["aud"]', NULL, '{}', 'projected_service_account', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'kubernetes_token_review', 'https://x', NULL, NULL, 'cluster 2', 'https://x:6443', 'ca', 'fp', 'rv', 1, '["aud"]', NULL, '{}', 'projected_service_account', NULL, 'reusable', 'enabled')
        23514 UPDATE trust_source SET exact_issuer = 'https://x/' || repeat('d', 2039), revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET exact_issuer = 'https://x/ d', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET exact_issuer = E'https://x\r', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET ca_bundle_ref = repeat('c', 2049), revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET ca_bundle_ref = 'ca k3s', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET ca_fingerprint = repeat('c', 2049), revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET ca_fingerprint = 'sha256: ca', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET reviewer_credential_ref = repeat('r', 2049), revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET reviewer_credential_ref = E'reviewer\u0001', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET name = repeat('n', 2049), revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE principal_binding SET name = repeat('n', 2049), revision = revision + 1 WHERE id = 'bnd_1'
        23514 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', repeat('s', 256), 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23514 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld 1', 'enabled')
        23514 UPDATE service_identity SET name = repeat('n', 2049), revision = revision + 1 WHERE id = 'svc_1'
        23514 INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', repeat('r', 256))
        23514 UPDATE service_grant SET name = repeat('n', 2049), revision = revision + 1 WHERE id = 'grt_1'
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', repeat('s', 256), 'delegation', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23514 INSERT INTO service_grant_binding VALUES ('grt_1', repeat('b', 256), 'ten_a', 'wld_1')
        23514 INSERT INTO service_grant_resource_server VALUES ('grt_1', 'ten_a', repeat('r', 256))
    "#).await;
    // The largest values that fit, from data that does not compress: a
    // 255-byte ID and a 2048-byte name of two-byte characters in the
    // (tenant_id, name) index; 2048-byte exact strings; a name with spaces.
    run(
        &pool,
        r#"INSERT INTO trust_keyset VALUES
               (left((SELECT string_agg(md5(i::text), '') FROM generate_series(1, 8) i), 255), 'ten_a',
                (SELECT string_agg(md5(i::text), '') FROM generate_series(1, 32) i) || repeat('é', 512), 'enabled'),
               ('ks_2', 'ten_a', 'release train', 'enabled');
           INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_2', '{"keys": [{"kty": "EC"}]}',
               (SELECT string_agg(md5(i::text), '') FROM generate_series(1, 64) i), '2026-01-01Z', NULL, 'enabled', '{}');
           UPDATE trust_source SET exact_issuer = 'https://x/' || repeat('d', 2038),
               ca_bundle_ref = repeat('c', 2048), ca_fingerprint = repeat('c', 2048), reviewer_credential_ref = repeat('r', 2048),
               revision = revision + 1 WHERE id = 'src_k8s'"#,
    )
    .await;
    let lengths: Vec<(i32, i32)> = sqlx::query_as(
        "SELECT octet_length(id), octet_length(name) FROM trust_keyset ORDER BY 1 DESC, 2 DESC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(lengths[0], (255, 2048), "{lengths:?}");
    db.drop([pool]).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn keyset_names_are_tenant_local_and_versions_change_only_status() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23505 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', 'partner', 'enabled')
        23505 INSERT INTO trust_keyset VALUES ('ks_1', 'ten_b', 'other', 'enabled')
        23503 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_x', 'other', 'enabled')
        23514 INSERT INTO trust_keyset VALUES ('', 'ten_a', 'other', 'enabled')
        23514 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', '', 'enabled')
        23514 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', 'other', 'active')
        SK001 INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', 'other', 'enabled', 2)
        23514 ALTER TABLE trust_keyset DISABLE TRIGGER trust_keyset_revision; INSERT INTO trust_keyset VALUES ('ks_2', 'ten_a', 'other', 'enabled', 0)
        SK001 UPDATE trust_keyset SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'ks_1'
        SK001 UPDATE trust_keyset SET id = 'ks_9', revision = revision + 1 WHERE id = 'ks_1'
        SK001 UPDATE trust_keyset SET status = 'disabled' WHERE id = 'ks_1'
        SK001 UPDATE trust_keyset SET status = 'disabled', revision = revision + 2 WHERE id = 'ks_1'
        23503 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_b', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23503 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_b', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23503 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_x', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23505 INSERT INTO trust_keyset_version VALUES ('kv_1', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', '', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', '2026-01-01Z', 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', '2025-12-31Z', 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'active', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '[]')
        23502 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', NULL, NULL, 'enabled', '{}')
        23502 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'f', '2026-01-01Z', NULL, 'enabled', NULL)
        SK001 UPDATE trust_keyset_version SET id = 'kv_9'
        SK001 UPDATE trust_keyset_version SET tenant_id = 'ten_b'
        SK001 UPDATE trust_keyset_version SET keyset_id = 'ks_b'
        SK001 UPDATE trust_keyset_version SET public_jwks = '{"keys": [{"kty": "RSA"}]}'
        SK001 UPDATE trust_keyset_version SET fingerprint = 'sha256:02'
        SK001 UPDATE trust_keyset_version SET effective_at = '2026-02-01Z'
        SK001 UPDATE trust_keyset_version SET expires_at = '2027-01-01Z'
        SK001 UPDATE trust_keyset_version SET provenance = '{"uploaded_by": "adm_2"}'
    "#).await;
    // Overlapping versions, and a renamed, disabled keyset; a version has no
    // revision, so its status changes on its own.
    run(
        &pool,
        r#"INSERT INTO trust_keyset_version VALUES
               ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}]}', 'sha256:01', '2026-01-01Z', '2026-01-01 00:00:01Z', 'enabled', '{}');
           UPDATE trust_keyset_version SET status = 'disabled' WHERE id = 'kv_1';
           UPDATE trust_keyset_version SET status = 'enabled' WHERE id = 'kv_1';
           UPDATE trust_keyset SET name = 'renamed', status = 'disabled', revision = revision + 1 WHERE id = 'ks_1'"#,
    )
    .await;
    assert_eq!(revision(&pool, "trust_keyset").await, [2, 1]);
    // Referenced keysets hold back deletes.
    rejects(
        &pool,
        "
        23503 DELETE FROM trust_keyset WHERE id = 'ks_1'
        23503 DELETE FROM tenant WHERE id = 'ten_b'
    ",
    )
    .await;
    db.drop([pool]).await;
}

/// A version is a JWK Set of public keys only: no private or symmetric key
/// member on any key (ADR-005 items 2 and 8).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn keyset_version_holds_a_nonempty_set_of_public_keys() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '[]', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '[{"keys": [{"kty": "EC"}]}]', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '"x"', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', 'null', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": []}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": {"kty": "EC"}}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}, 1]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": ["k1"]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [[{"kty": "EC"}]]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "EC"}, {"kty": "EC", "d": "AA"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "RSA", "p": "AA"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "RSA", "q": "AA"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "RSA", "dp": "AA"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "RSA", "dq": "AA"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "RSA", "qi": "AA"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "RSA", "oth": []}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "oct", "k": "AA"}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23514 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', '{"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "AA", "d": null}]}', 'f', '2026-01-01Z', NULL, 'enabled', '{}')
        23502 INSERT INTO trust_keyset_version VALUES ('kv_2', 'ten_a', 'ks_1', NULL, 'f', '2026-01-01Z', NULL, 'enabled', '{}')
    "#).await;
    // Public RSA, EC and OKP keys with their usual optional members; member
    // names are case-sensitive, and other top-level members are kept.
    run(
        &pool,
        r#"INSERT INTO trust_keyset_version VALUES
               ('kv_2', 'ten_a', 'ks_1',
                '{"keys": [{"kty": "RSA", "n": "AQAB", "e": "AQAB", "alg": "RS256", "use": "sig", "kid": "r1", "x5c": ["AA"]},
                           {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA", "D": "AA"},
                           {"kty": "OKP", "crv": "Ed25519", "x": "AA"}],
                  "note": {"d": "not a key"}}',
                'sha256:02', '2026-01-01Z', NULL, 'enabled', '{}')"#,
    )
    .await;
    db.drop([pool]).await;
}

/// Each kind has its own fields, and a field of another kind is rejected
/// (ADR-005 item 1; T11.10). Updates exercise the rules on the seeded
/// sources; inserts cover the immutable cluster and keyset references.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_source_fields_follow_its_kind() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23514 UPDATE trust_source SET discovery_url = NULL, revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET token_review_endpoint = 'https://k3s.internal.example:6443', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET ca_bundle_ref = 'ca_k3s', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET ca_fingerprint = 'sha256:ca', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET reviewer_credential_ref = 'reviewer_k3s', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET review_timeout_ms = 5000, revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET algorithms = NULL, revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET discovery_url = 'https://ci.partner.example/.well-known/openid-configuration', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET token_review_endpoint = 'https://k3s.internal.example:6443', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET ca_bundle_ref = 'ca_k3s', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET ca_fingerprint = 'sha256:ca', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET reviewer_credential_ref = 'reviewer_k3s', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET review_timeout_ms = 5000, revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET algorithms = NULL, revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET token_review_endpoint = NULL, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET ca_bundle_ref = NULL, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET ca_fingerprint = NULL, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET reviewer_credential_ref = NULL, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET review_timeout_ms = NULL, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET review_timeout_ms = 0, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET discovery_url = 'https://kubernetes.default.svc/.well-known/openid-configuration', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET algorithms = '["RS256"]', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET assertion_profile = 'reusable_jwt', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET assertion_profile = 'on_demand_jwt', revision = revision + 1 WHERE id = 'src_k8s'
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'oidc_discovery', 'https://x', 'https://x/d', 'ks_1', NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'oidc_discovery', 'https://x', 'https://x/d', NULL, 'cluster_2', NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'uploaded_jwks', 'https://x', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'uploaded_jwks', 'https://x', NULL, 'ks_1', 'cluster_2', NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'kubernetes_token_review', 'https://x', NULL, NULL, NULL, 'https://x:6443', 'ca', 'fp', 'rv', 1, '["aud"]', NULL, '{}', 'projected_service_account', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'kubernetes_token_review', 'https://x', NULL, 'ks_1', 'cluster_2', 'https://x:6443', 'ca', 'fp', 'rv', 1, '["aud"]', NULL, '{}', 'projected_service_account', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'kubernetes_local', 'https://x', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'projected_service_account', true, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'static_jwks', 'https://x', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23502 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', NULL, 'https://x', 'https://x/d', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
    "#).await;
    // Kind-specific fields may change within the kind.
    run(
        &pool,
        r#"UPDATE trust_source SET discovery_url = 'https://token.actions.githubusercontent.com/other', revision = revision + 1 WHERE id = 'src_gh';
           UPDATE trust_source SET token_review_endpoint = 'https://k3s-2.internal.example:6443', ca_bundle_ref = 'ca_k3s_2',
               ca_fingerprint = 'sha256:cb', reviewer_credential_ref = 'reviewer_k3s_2', review_timeout_ms = 1,
               revision = revision + 1 WHERE id = 'src_k8s'"#,
    )
    .await;
    db.drop([pool]).await;
}

/// stale_revocation_acknowledged is set (true) for projected_service_account
/// on uploaded_jwks or oidc_discovery, and absent on every other source
/// (IR-151).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn stale_revocation_acknowledgment_belongs_to_local_projected_tokens_only() {
    let (db, pool) = seeded().await;
    rejects(&pool, "
        23514 UPDATE trust_source SET stale_revocation_acknowledged = NULL, revision = revision + 1 WHERE id = 'src_local'
        23514 UPDATE trust_source SET stale_revocation_acknowledged = false, revision = revision + 1 WHERE id = 'src_local'
        23514 UPDATE trust_source SET assertion_profile = 'projected_service_account', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET assertion_profile = 'projected_service_account', revision = revision + 1 WHERE id = 'src_b'
        23514 UPDATE trust_source SET stale_revocation_acknowledged = true, revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET stale_revocation_acknowledged = true, revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET stale_revocation_acknowledged = true, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET stale_revocation_acknowledged = false, revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET assertion_profile = 'reusable_jwt', revision = revision + 1 WHERE id = 'src_local'
    ").await;
    run(
        &pool,
        "UPDATE trust_source SET assertion_profile = 'projected_service_account',
             stale_revocation_acknowledged = true, revision = revision + 1 WHERE id = 'src_b';
         UPDATE trust_source SET assertion_profile = 'reusable_jwt',
             stale_revocation_acknowledged = NULL, revision = revision + 1 WHERE id = 'src_local'",
    )
    .await;
    db.drop([pool]).await;
}

/// single_use only with on_demand_jwt on a locally verified source; projected
/// and TokenReview tokens are reusable (OQ-ADR005-2; ADR-016 items 6 and 8).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn single_use_replay_needs_an_on_demand_locally_verified_source() {
    let (db, pool) = seeded().await;
    rejects(&pool, "
        23514 UPDATE trust_source SET assertion_profile = 'reusable_jwt', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET replay_mode = 'single_use', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET replay_mode = 'single_use', revision = revision + 1 WHERE id = 'src_local'
        23514 UPDATE trust_source SET replay_mode = 'single_use', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET replay_mode = 'once', revision = revision + 1 WHERE id = 'src_up'
        23514 UPDATE trust_source SET replay_mode = 'once', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET assertion_profile = 'on_demand', revision = revision + 1 WHERE id = 'src_up'
        23502 UPDATE trust_source SET replay_mode = NULL, revision = revision + 1 WHERE id = 'src_up'
    ").await;
    run(
        &pool,
        "UPDATE trust_source SET assertion_profile = 'on_demand_jwt', replay_mode = 'single_use',
             revision = revision + 1 WHERE id = 'src_up';
         UPDATE trust_source SET replay_mode = 'reusable', revision = revision + 1 WHERE id = 'src_gh'",
    )
    .await;
    db.drop([pool]).await;
}

/// Names are tenant-local and issuers are not unique (IR-021, IR-032); the
/// keyset is the tenant's own; destinations take the egress entry syntax.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_source_names_selectors_and_references() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23505 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'github', 'oidc_discovery', 'https://x', 'https://x/d', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23505 INSERT INTO trust_source VALUES ('src_gh', 'ten_b', 'x', 'oidc_discovery', 'https://x', 'https://x/d', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23503 INSERT INTO trust_source VALUES ('src_x', 'ten_x', 'x', 'oidc_discovery', 'https://x', 'https://x/d', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23503 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'uploaded_jwks', 'https://x', NULL, 'ks_b', NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23503 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'uploaded_jwks', 'https://x', NULL, 'ks_x', NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23505 INSERT INTO trust_source VALUES ('src_x', 'ten_b', 'x', 'kubernetes_token_review', 'https://x', NULL, NULL, 'cluster_1', 'https://x:6443', 'ca', 'fp', 'rv', 1, '["aud"]', NULL, '{}', 'projected_service_account', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'kubernetes_token_review', 'https://x', NULL, NULL, '', 'https://x:6443', 'ca', 'fp', 'rv', 1, '["aud"]', NULL, '{}', 'projected_service_account', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('', 'ten_a', 'x', 'oidc_discovery', 'https://x', 'https://x/d', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        23514 INSERT INTO trust_source VALUES ('src_x', 'ten_a', '', 'oidc_discovery', 'https://x', 'https://x/d', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled')
        SK001 INSERT INTO trust_source VALUES ('src_x', 'ten_a', 'x', 'oidc_discovery', 'https://x', 'https://x/d', NULL, NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled', 2)
        23514 UPDATE trust_source SET exact_issuer = '', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET discovery_url = '', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET discovery_url = 'https://x/ d', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET discovery_url = E'https://x/d\n', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET discovery_url = 'https://x/' || repeat('d', 2039), revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET token_review_endpoint = '', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET token_review_endpoint = 'https://x :6443', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET token_review_endpoint = E'https://x:6443\u0085', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET token_review_endpoint = 'https://x/' || repeat('d', 2039), revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET ca_bundle_ref = '', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET ca_fingerprint = '', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET reviewer_credential_ref = '', revision = revision + 1 WHERE id = 'src_k8s'
        23514 UPDATE trust_source SET audiences = '[]', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET audiences = '[""]', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET audiences = '"aud"', revision = revision + 1 WHERE id = 'src_gh'
        23502 UPDATE trust_source SET audiences = NULL, revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET algorithms = '[]', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET algorithms = '[256]', revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET proof_bounds = '[]', revision = revision + 1 WHERE id = 'src_gh'
        23502 UPDATE trust_source SET proof_bounds = NULL, revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE trust_source SET status = 'degraded', revision = revision + 1 WHERE id = 'src_gh'
        SK001 UPDATE trust_source SET id = 'src_9', revision = revision + 1 WHERE id = 'src_gh'
        SK001 UPDATE trust_source SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'src_gh'
        SK001 UPDATE trust_source SET kind = 'uploaded_jwks', revision = revision + 1 WHERE id = 'src_gh'
        SK001 UPDATE trust_source SET cluster_id = 'cluster_2', revision = revision + 1 WHERE id = 'src_k8s'
        SK001 UPDATE trust_source SET jwks_keyset_id = 'ks_2', revision = revision + 1 WHERE id = 'src_up'
        SK001 UPDATE trust_source SET status = 'disabled' WHERE id = 'src_gh'
        SK001 UPDATE trust_source SET status = 'disabled', revision = 3 WHERE id = 'src_gh'
    "#).await;
    // The same issuer and name in two tenants; 2048-byte destinations; and
    // every non-selector field may change, one revision at a time.
    run(
        &pool,
        r#"INSERT INTO trust_source VALUES ('src_x', 'ten_b', 'partner', 'uploaded_jwks', 'https://ci.partner.example', NULL,
               'ks_b', NULL, NULL, NULL, NULL, NULL, NULL, '["aud"]', '["ES256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
           UPDATE trust_source SET name = 'renamed', exact_issuer = 'https://other.example',
               discovery_url = 'https://x/' || repeat('d', 2038), audiences = '["a", "b"]', algorithms = '["RS256", "ES256"]',
               proof_bounds = '{"max_bytes": 8192}', status = 'disabled', revision = revision + 1
           WHERE id = 'src_gh';
           UPDATE trust_source SET token_review_endpoint = 'https://x/' || repeat('d', 2038), revision = revision + 1
           WHERE id = 'src_k8s'"#,
    )
    .await;
    assert_eq!(revision(&pool, "trust_source").await, [1, 2, 2, 1, 1, 1]);
    rejects(
        &pool,
        "
        23503 DELETE FROM trust_source WHERE id = 'src_gh'
        23503 DELETE FROM trust_keyset WHERE id = 'ks_b'
    ",
    )
    .await;
    db.drop([pool]).await;
}

/// A binding maps evidence of a same-tenant source to a same-tenant workload
/// principal; its predicates are a nonempty object of exact strings.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn binding_maps_a_same_tenant_source_to_a_workload() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23503 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_b', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23503 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_x', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23503 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_b', 'enabled')
        23503 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'svc_1', 'enabled')
        23503 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'usr_1', 'enabled')
        23503 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_x', 'enabled')
        23503 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_x', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23514 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'svc_1', 'enabled', 1, 'service')
        23505 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'release', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23505 INSERT INTO principal_binding VALUES ('bnd_1', 'ten_b', 'x', 'src_b', 'generic_production', '{"sub": "a"}', 'wld_b', 'enabled')
        23514 INSERT INTO principal_binding VALUES ('', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        23514 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', '', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled')
        SK001 INSERT INTO principal_binding VALUES ('bnd_x', 'ten_a', 'x', 'src_gh', 'generic_production', '{"sub": "a"}', 'wld_1', 'enabled', 3)
        23514 UPDATE principal_binding SET profile = 'github_staging', revision = revision + 1 WHERE id = 'bnd_1'
        23502 UPDATE principal_binding SET profile = NULL, revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '{}', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '[]', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '[{"sub": "a"}]', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '"sub"', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '{"sub": "a", "repository_id": 456789}', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '{"sub": ["a", "b"]}', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '{"sub": null}', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET claim_match_policy = '{"sub": {"eq": "a"}}', revision = revision + 1 WHERE id = 'bnd_1'
        23514 UPDATE principal_binding SET status = 'active', revision = revision + 1 WHERE id = 'bnd_1'
        SK001 UPDATE principal_binding SET id = 'bnd_9', revision = revision + 1 WHERE id = 'bnd_3'
        SK001 UPDATE principal_binding SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'bnd_3'
        SK001 UPDATE principal_binding SET trust_source_id = 'src_up', revision = revision + 1 WHERE id = 'bnd_3'
        SK001 UPDATE principal_binding SET workload_principal_id = 'wld_1', revision = revision + 1 WHERE id = 'bnd_3'
        SK001 UPDATE principal_binding SET status = 'disabled' WHERE id = 'bnd_3'
        23503 DELETE FROM principal WHERE id = 'wld_2'
    "#).await;
    // A disabled binding stays referenced by its grants (OQ-ADR022-1).
    run(
        &pool,
        r#"INSERT INTO principal_binding VALUES
               ('bnd_x', 'ten_a', 'x', 'src_up', 'generic_production', '{"sub": ""}', 'wld_2', 'enabled');
           UPDATE principal_binding SET name = 'renamed', profile = 'kubernetes_production',
               claim_match_policy = '{"namespace": "ci", "service_account_name": "runner", "service_account_uid": "u-1"}',
               status = 'disabled', revision = revision + 1
           WHERE id = 'bnd_3'"#,
    )
    .await;
    assert_eq!(revision(&pool, "principal_binding").await, [1, 1, 2, 1, 1]);
    db.drop([pool]).await;
}

/// A service identity is a service principal of its own tenant (tasks
/// section 3 "Ownership"), and lists only audiences assigned to that tenant
/// (IR-080, IR-083).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn service_identity_is_a_service_principal_with_assigned_audiences() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23503 INSERT INTO service_identity VALUES ('wld_1', 'ten_a', 'x', '[]', '{}', 'enabled')
        23503 INSERT INTO service_identity VALUES ('usr_1', 'ten_a', 'x', '[]', '{}', 'enabled')
        23503 INSERT INTO service_identity VALUES ('svc_c', 'ten_a', 'x', '[]', '{}', 'enabled')
        23503 INSERT INTO service_identity VALUES ('svc_9', 'ten_a', 'x', '[]', '{}', 'enabled')
        23514 INSERT INTO service_identity VALUES ('wld_1', 'ten_a', 'x', '[]', '{}', 'enabled', 1, 'workload')
        23505 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', 'deployer', '[]', '{}', 'enabled')
        23514 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', '', '[]', '{}', 'enabled')
        23514 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', 'x', '["a b"]', '{}', 'enabled')
        23514 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', 'x', '[]', '[]', 'enabled')
        23514 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', 'x', '[]', '{}', 'active')
        SK001 INSERT INTO service_identity VALUES ('svc_2', 'ten_a', 'x', '[]', '{}', 'enabled', 0)
        SK001 UPDATE service_identity SET id = 'svc_2', revision = revision + 1 WHERE id = 'svc_1'
        SK001 UPDATE service_identity SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'svc_1'
        SK001 UPDATE service_identity SET status = 'disabled' WHERE id = 'svc_1'
        23503 INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', 'rs_2')
        23503 INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_b', 'rs_2')
        23503 INSERT INTO service_identity_resource_server VALUES ('svc_9', 'ten_a', 'rs_1')
        23505 INSERT INTO service_identity_resource_server VALUES ('svc_1', 'ten_a', 'rs_1')
        23502 INSERT INTO service_identity_resource_server VALUES ('svc_1', NULL, 'rs_1')
        SK001 UPDATE service_identity_resource_server SET resource_server_id = 'rs_1' WHERE service_id = 'svc_b'
        SK001 UPDATE service_identity_resource_server SET service_id = 'svc_2' WHERE service_id = 'svc_1'
        SK001 UPDATE service_identity_resource_server SET tenant_id = 'ten_b' WHERE service_id = 'svc_1'
        23503 DELETE FROM audience_tenant_assignment WHERE id = 'ata_1'
        23503 DELETE FROM principal WHERE id = 'svc_1'
        23503 DELETE FROM service_identity WHERE id = 'svc_1'
    "#).await;
    run(
        &pool,
        r#"INSERT INTO service_identity VALUES ('svc_2', 'ten_a', 'other', '[]', '{}', 'enabled');
           INSERT INTO service_identity_resource_server VALUES ('svc_2', 'ten_a', 'rs_1');
           DELETE FROM service_identity_resource_server WHERE service_id = 'svc_2';
           UPDATE service_identity SET name = 'renamed', max_scopes = '["read", "write"]',
               max_resource_constraints = '{"version": 1}', status = 'disabled', revision = revision + 1
           WHERE id = 'svc_1'"#,
    )
    .await;
    assert_eq!(revision(&pool, "service_identity").await, [2, 1, 1]);
    db.drop([pool]).await;
}

/// Direct grants have no target; delegation and impersonation name a
/// same-tenant service (IR-045; OQ-ADR006-1). Impersonation is stored only
/// disabled and requiring reapproval (design section 5.6; T10.11).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_mode_fixes_its_target_and_activation_state() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', 'svc_1', 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'delegation', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'impersonation', '[]', NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', 'svc_1', 'impersonation', '[]', NULL, '{}', 300, NULL, 'enabled', 'requires_reapproval')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', 'svc_1', 'impersonation', '[]', NULL, '{}', 300, NULL, 'disabled', 'not_required')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', 'svc_1', 'delegation', '[]', NULL, '{}', 300, NULL, 'disabled', 'requires_reapproval')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', 'svc_1', 'device', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'approved')
        23503 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', 'svc_b', 'delegation', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23503 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', 'svc_2', 'delegation', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23503 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_b', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23503 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'svc_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23503 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'usr_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23503 INSERT INTO service_grant VALUES ('grt_x', 'ten_x', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23514 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'svc_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required', 1, 'service')
        23514 UPDATE service_grant SET status = 'enabled', revision = revision + 1 WHERE id = 'grt_3'
        23514 UPDATE service_grant SET activation_state = 'not_required', revision = revision + 1 WHERE id = 'grt_3'
        23514 UPDATE service_grant SET activation_state = 'requires_reapproval', revision = revision + 1 WHERE id = 'grt_2'
        SK001 UPDATE service_grant SET mode = 'delegation', revision = revision + 1 WHERE id = 'grt_3'
        SK001 UPDATE service_grant SET mode = 'delegation', target_service_id = 'svc_1', revision = revision + 1 WHERE id = 'grt_1'
        SK001 UPDATE service_grant SET target_service_id = NULL, revision = revision + 1 WHERE id = 'grt_3'
        SK001 UPDATE service_grant SET actor_principal_id = 'wld_2', revision = revision + 1 WHERE id = 'grt_1'
        SK001 UPDATE service_grant SET tenant_id = 'ten_b', revision = revision + 1 WHERE id = 'grt_1'
        SK001 UPDATE service_grant SET id = 'grt_9', revision = revision + 1 WHERE id = 'grt_1'
    "#).await;
    // The dormant record keeps its desired policy; other fields of a
    // disabled impersonation grant may still be edited.
    run(
        &pool,
        r#"UPDATE service_grant SET name = 'dormant-renamed', scopes = '["read", "deploy:write"]',
               revision = revision + 1 WHERE id = 'grt_3';
           UPDATE service_grant SET status = 'disabled', revision = revision + 1 WHERE id = 'grt_2'"#,
    )
    .await;
    assert_eq!(revision(&pool, "service_grant").await, [1, 2, 2, 1]);
    db.drop([pool]).await;
}

/// default_scopes are explicit, nonempty and within the grant's scopes
/// (IR-063); max_ttl only shortens the 300 s wif maximum.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_scopes_defaults_and_lifetime_are_bounded() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        23514 UPDATE service_grant SET default_scopes = '[]', revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET default_scopes = '["admin"]', revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET default_scopes = '["read", "admin"]', revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET scopes = '["deploy:write"]', revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET default_scopes = '["a b"]', revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET scopes = '["a b"]', revision = revision + 1 WHERE id = 'grt_2'
        23514 UPDATE service_grant SET scopes = '"read"', revision = revision + 1 WHERE id = 'grt_2'
        23502 UPDATE service_grant SET scopes = NULL, revision = revision + 1 WHERE id = 'grt_2'
        23514 UPDATE service_grant SET max_ttl = 0, revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET max_ttl = 301, revision = revision + 1 WHERE id = 'grt_1'
        23502 UPDATE service_grant SET max_ttl = NULL, revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET resource_constraints = '[]', revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET name = '', revision = revision + 1 WHERE id = 'grt_1'
        23505 UPDATE service_grant SET name = 'delegated', revision = revision + 1 WHERE id = 'grt_1'
        23514 UPDATE service_grant SET status = 'active', revision = revision + 1 WHERE id = 'grt_1'
        SK001 UPDATE service_grant SET max_ttl = 60 WHERE id = 'grt_1'
        SK001 UPDATE service_grant SET max_ttl = 60, revision = revision + 2 WHERE id = 'grt_1'
        SK001 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required', 2)
        23514 INSERT INTO service_grant VALUES ('', 'ten_a', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
    "#).await;
    // The same name in another tenant; defaults equal to the scopes; no
    // defaults at all; the shortest lifetime.
    run(
        &pool,
        r#"UPDATE service_grant SET name = 'direct', revision = revision + 1 WHERE id = 'grt_b';
           UPDATE service_grant SET scopes = '["read"]', default_scopes = '["read"]', max_ttl = 1,
               valid_until = '2026-12-31Z', resource_constraints = '{"version": 1, "authorization": "allowlist"}',
               revision = revision + 1 WHERE id = 'grt_1';
           UPDATE service_grant SET default_scopes = NULL, revision = revision + 1 WHERE id = 'grt_1'"#,
    )
    .await;
    assert_eq!(revision(&pool, "service_grant").await, [3, 1, 1, 2]);
    db.drop([pool]).await;
}

/// allowed_binding_ids names only bindings of the grant's own actor in its
/// own tenant: cross-actor and cross-tenant references are rejected
/// (ADR-022 item 13). Audiences need a same-tenant assignment (IR-080).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_references_stay_with_its_actor_and_tenant() {
    let (db, pool) = seeded().await;
    rejects(&pool, "
        23503 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_3', 'ten_a', 'wld_1')
        23503 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_3', 'ten_a', 'wld_2')
        23503 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_b', 'ten_a', 'wld_1')
        23503 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_b', 'ten_b', 'wld_b')
        23503 INSERT INTO service_grant_binding VALUES ('grt_b', 'bnd_1', 'ten_a', 'wld_1')
        23503 INSERT INTO service_grant_binding VALUES ('grt_x', 'bnd_1', 'ten_a', 'wld_1')
        23503 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_x', 'ten_a', 'wld_1')
        23505 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_1', 'ten_a', 'wld_1')
        23502 INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_2', 'ten_a', NULL)
        SK001 UPDATE service_grant_binding SET binding_id = 'bnd_2' WHERE grant_id = 'grt_1'
        SK001 UPDATE service_grant_binding SET grant_id = 'grt_2' WHERE grant_id = 'grt_1'
        SK001 UPDATE service_grant_binding SET tenant_id = 'ten_b' WHERE grant_id = 'grt_1'
        SK001 UPDATE service_grant_binding SET actor_principal_id = 'wld_2' WHERE grant_id = 'grt_1'
        23503 DELETE FROM principal_binding WHERE id = 'bnd_3'
        23503 INSERT INTO service_grant_resource_server VALUES ('grt_1', 'ten_a', 'rs_2')
        23503 INSERT INTO service_grant_resource_server VALUES ('grt_1', 'ten_b', 'rs_2')
        23503 INSERT INTO service_grant_resource_server VALUES ('grt_x', 'ten_a', 'rs_1')
        23505 INSERT INTO service_grant_resource_server VALUES ('grt_1', 'ten_a', 'rs_1')
        SK001 UPDATE service_grant_resource_server SET resource_server_id = 'rs_1' WHERE grant_id = 'grt_b'
        SK001 UPDATE service_grant_resource_server SET grant_id = 'grt_2' WHERE grant_id = 'grt_1'
        SK001 UPDATE service_grant_resource_server SET tenant_id = 'ten_b' WHERE grant_id = 'grt_1'
        23503 DELETE FROM audience_tenant_assignment WHERE id = 'ata_2'
        23503 DELETE FROM service_identity WHERE id = 'svc_1'
        23503 DELETE FROM service_grant WHERE id = 'grt_1'
    ").await;
    run(
        &pool,
        "INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_2', 'ten_a', 'wld_1');
         INSERT INTO service_grant_resource_server VALUES ('grt_3', 'ten_a', 'rs_1')",
    )
    .await;
    let bindings = rows(
        &pool,
        "SELECT grant_id, binding_id FROM service_grant_binding WHERE tenant_id = 'ten_a' ORDER BY 1, 2",
    )
    .await;
    let expected: Vec<(String, String)> = [
        ("grt_1", "bnd_1"),
        ("grt_1", "bnd_2"),
        ("grt_2", "bnd_1"),
        ("grt_2", "bnd_2"),
        ("grt_3", "bnd_3"),
    ]
    .iter()
    .map(|(g, b)| (g.to_string(), b.to_string()))
    .collect();
    assert_eq!(bindings, expected);
    db.drop([pool]).await;
}

/// allowed_binding_ids is nonempty (identity-registry section 10), checked
/// at commit, so a set can be replaced in one transaction.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_keeps_at_least_one_allowed_binding() {
    let (db, pool) = seeded().await;
    rejects(&pool, r#"
        SK001 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        SK001 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'); INSERT INTO service_grant_resource_server VALUES ('grt_x', 'ten_a', 'rs_1')
        SK001 DELETE FROM service_grant_binding WHERE grant_id = 'grt_1'
        SK001 DELETE FROM service_grant_binding WHERE grant_id = 'grt_2'
        SK001 DELETE FROM service_grant_binding WHERE grant_id = 'grt_2' AND binding_id = 'bnd_1'; DELETE FROM service_grant_binding WHERE grant_id = 'grt_2'
        SK001 DELETE FROM service_grant_binding WHERE tenant_id = 'ten_b'
    "#).await;

    // The check runs at commit, not at the statement.
    let mut conn = pool.acquire().await.unwrap();
    run(
        &mut *conn,
        "BEGIN; DELETE FROM service_grant_binding WHERE grant_id = 'grt_1'",
    )
    .await;
    let err = sqlx::raw_sql("COMMIT")
        .execute(&mut *conn)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");
    drop(conn);

    run(
        &pool,
        r#"DELETE FROM service_grant_binding WHERE grant_id = 'grt_2' AND binding_id = 'bnd_2';
           DELETE FROM service_grant_binding WHERE grant_id = 'grt_1';
           INSERT INTO service_grant_binding VALUES ('grt_1', 'bnd_2', 'ten_a', 'wld_1');
           INSERT INTO service_grant VALUES ('grt_4', 'ten_a', 'new', 'wld_2', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required');
           INSERT INTO service_grant_binding VALUES ('grt_4', 'bnd_3', 'ten_a', 'wld_2');
           INSERT INTO service_grant VALUES ('grt_5', 'ten_a', 'gone', 'wld_2', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required');
           DELETE FROM service_grant WHERE id = 'grt_5'"#,
    )
    .await;
    // Hard delete of a disabled, unreferenced grant (ADR-008 item 3): its
    // rows first, then the grant.
    run(
        &pool,
        "DELETE FROM service_grant_binding WHERE grant_id = 'grt_b';
         DELETE FROM service_grant_resource_server WHERE grant_id = 'grt_b';
         DELETE FROM service_grant WHERE id = 'grt_b'",
    )
    .await;
    let bindings = rows(
        &pool,
        "SELECT grant_id, binding_id FROM service_grant_binding ORDER BY 1, 2",
    )
    .await;
    let expected: Vec<(String, String)> = [
        ("grt_1", "bnd_2"),
        ("grt_2", "bnd_1"),
        ("grt_3", "bnd_3"),
        ("grt_4", "bnd_3"),
    ]
    .iter()
    .map(|(g, b)| (g.to_string(), b.to_string()))
    .collect();
    assert_eq!(bindings, expected);
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
    .expect("the second remover never waited for the grant lock");
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// The binding-set check locks the grant row, so of two transactions that
/// each remove one of a grant's last two bindings, the second waits for the
/// first and then sees its delete (READ COMMITTED, the default).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_binding_check_serializes_concurrent_removals() {
    let (db, pool) = seeded().await;
    let mut first = pool.acquire().await.unwrap().detach();
    let mut second = pool.acquire().await.unwrap().detach();
    let (first_pid, second_pid) = (
        backend_pid(&mut first).await,
        backend_pid(&mut second).await,
    );
    run(
        &mut first,
        "BEGIN;
         DELETE FROM service_grant_binding WHERE grant_id = 'grt_2' AND binding_id = 'bnd_1';
         SET CONSTRAINTS service_grant_binding_keeps_one IMMEDIATE",
    )
    .await;
    // The whole second transaction runs in a task, so the test cannot hang
    // whichever statement waits for the lock.
    let commit = tokio::spawn(async move {
        let result = sqlx::raw_sql(
            "BEGIN;
             DELETE FROM service_grant_binding WHERE grant_id = 'grt_2' AND binding_id = 'bnd_2';
             COMMIT",
        )
        .execute(&mut second)
        .await;
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut second)
            .await
            .unwrap();
        (second, result)
    });
    wait_until_blocked(&pool, second_pid, first_pid).await;
    assert!(!commit.is_finished());
    run(&mut first, "COMMIT").await;
    let (second, result) = tokio::time::timeout(Duration::from_secs(30), commit)
        .await
        .expect("the second remover never finished")
        .unwrap();
    let err = result.unwrap_err();
    assert_eq!(sqlstate(&err), "SK001", "{err}");
    let left = rows(
        &pool,
        "SELECT grant_id, binding_id FROM service_grant_binding WHERE grant_id = 'grt_2'",
    )
    .await;
    assert_eq!(left, [("grt_2".to_string(), "bnd_2".to_string())]);
    first.close().await.unwrap();
    second.close().await.unwrap();
    db.drop([pool]).await;
}

/// The binding-set check resolves its tables through a pinned search_path:
/// a role with only DML grants cannot satisfy it with a temporary table, and
/// an empty search_path (logical-replication apply, data-only restore)
/// still works.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_binding_check_ignores_the_callers_search_path() {
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    sqlx::raw_sql(AssertSqlSafe(format!(
        "GRANT SELECT, UPDATE ON service_grant TO {role};
         GRANT SELECT, DELETE ON service_grant_binding TO {role}"
    )))
    .execute(&pool)
    .await
    .unwrap();

    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    run(
        &mut writer,
        "CREATE TEMP TABLE service_grant_binding (grant_id text);
         INSERT INTO pg_temp.service_grant_binding VALUES ('grt_1');
         CREATE TEMP TABLE service_grant (tenant_id text, id text);",
    )
    .await;
    assert_rejected(
        &mut writer,
        "SK001 DELETE FROM public.service_grant_binding WHERE grant_id = 'grt_1'",
    )
    .await;
    writer.close().await.unwrap();

    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    run(
        &mut writer,
        "SET search_path = '';
         DELETE FROM public.service_grant_binding WHERE grant_id = 'grt_2' AND binding_id = 'bnd_2'",
    )
    .await;
    assert_rejected(
        &mut writer,
        "SK001 DELETE FROM public.service_grant_binding WHERE grant_id = 'grt_1'",
    )
    .await;
    writer.close().await.unwrap();
    let left = rows(
        &pool,
        "SELECT grant_id, binding_id FROM service_grant_binding WHERE grant_id IN ('grt_1', 'grt_2') ORDER BY 1, 2",
    )
    .await;
    assert_eq!(
        left,
        [
            ("grt_1".to_string(), "bnd_1".to_string()),
            ("grt_2".to_string(), "bnd_1".to_string())
        ]
    );
    db.drop([pool]).await;
}

/// A schema name with `$$`, upper case and a space must not break the
/// table-reading function: it is created and checks grants there.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn grant_binding_check_works_in_a_schema_named_with_dollar_quotes() {
    let db = TestDb::create().await;
    let admin = db.pool().await;
    run(&admin, r#"CREATE SCHEMA "Trust $$2026""#).await;
    let pool = db.pool_with_search_path(r#""Trust $$2026""#).await;
    seeded_on(&pool).await;
    let config: Vec<String> = sqlx::query_scalar(
        "SELECT p.proconfig FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname = 'skyoauth_service_grant_has_binding'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        config,
        [r#"search_path=pg_catalog, "Trust $$2026", pg_temp"#]
    );
    rejects(
        &pool,
        "SK001 DELETE FROM service_grant_binding WHERE grant_id = 'grt_1'",
    )
    .await;
    run(
        &pool,
        "DELETE FROM service_grant_binding WHERE grant_id = 'grt_2' AND binding_id = 'bnd_2'",
    )
    .await;
    db.drop([admin, pool]).await;
}

/// `ENABLE ALWAYS` keeps the guards, the deferred binding-set check
/// included, firing in replica mode, which would otherwise skip ordinary
/// triggers; CHECKs hold anyway. Foreign keys do not fire there.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn trust_guards_hold_under_replica_role() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    run(&mut *conn, "SET session_replication_role = replica").await;
    assert_rejected(&mut conn, r#"
        SK001 UPDATE trust_keyset SET tenant_id = 'ten_b', revision = revision + 1
        SK001 UPDATE trust_keyset SET status = 'disabled'
        SK001 UPDATE trust_keyset_version SET public_jwks = '{"keys": [{"kty": "RSA"}]}'
        SK001 UPDATE trust_source SET kind = 'uploaded_jwks', revision = revision + 1 WHERE id = 'src_gh'
        SK001 UPDATE trust_source SET status = 'disabled', revision = 5
        SK001 UPDATE principal_binding SET workload_principal_id = 'wld_2', revision = revision + 1 WHERE id = 'bnd_1'
        SK001 UPDATE service_identity SET tenant_id = 'ten_b', revision = revision + 1
        SK001 UPDATE service_identity_resource_server SET resource_server_id = 'rs_2'
        SK001 UPDATE service_grant SET mode = 'delegation', revision = revision + 1 WHERE id = 'grt_1'
        SK001 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required', 2)
        SK001 UPDATE service_grant_binding SET binding_id = 'bnd_2' WHERE grant_id = 'grt_1'
        SK001 UPDATE service_grant_resource_server SET resource_server_id = 'rs_2'
        SK001 DELETE FROM service_grant_binding WHERE grant_id = 'grt_1'
        SK001 INSERT INTO service_grant VALUES ('grt_x', 'ten_a', 'x', 'wld_1', NULL, 'direct', '[]', NULL, '{}', 300, NULL, 'enabled', 'not_required')
        23514 UPDATE trust_source SET discovery_url = NULL, revision = revision + 1 WHERE id = 'src_gh'
        23514 UPDATE service_grant SET status = 'enabled', revision = revision + 1 WHERE id = 'grt_3'
    "#).await;
    conn.close().await.unwrap();
    for table in TABLES {
        assert!(
            revision(&pool, table).await.iter().all(|r| *r == 1),
            "{table}"
        );
    }
    db.drop([pool]).await;
}
