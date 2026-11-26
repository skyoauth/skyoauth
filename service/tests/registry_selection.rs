//! Grant selection and binding matching
//! (`persistence::registry::select_grant` and `policy::match_binding`;
//! ADR-015 item 4 steps 1, 3 and 4; design section 5.7; T12.3). The database tests select grants of one
//! tenant that share an audience but differ in actor, target and mode, check
//! that every miss is the same `NotSelectable`, and match evidence that
//! bindings of two actors both fit. The tests without a database check the
//! matching rules on their own.
//!
//! The database tests need `SKYOAUTH_IT_DATABASE_URL` (see
//! `common/mod.rs`); each creates and drops its own database. These are
//! registry tests in the shape of A25 and A50, not those conformance
//! scenarios, which belong to the test session in `tests/security`.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::collections::BTreeMap;
use std::error::Error as _;
use std::time::Duration;

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, BindingProfile, GrantMode, PrincipalBindingChanges, RegistryError, Selection,
        SelectionError, Status, select_grant,
    },
};
use skyoauth_service::policy::{EligibleBinding, Evidence, match_binding};
use sqlx::postgres::PgPoolOptions;

/// The `sub` every binding of the seed names.
const SUB: &str = "repo:acme/platform:environment:production";

/// Tenants `ten_a` and `ten_b`. In `ten_a`: workloads `wld_a` and `wld_b`,
/// services `svc_1` and `svc_2`, the audience `rs_1`, sources `src_gh`
/// and `src_alt`, and the disabled source `src_off`. Bindings, all
/// `generic_production`:
///
/// - `bnd_a_repo` of `wld_a` on `src_gh`: repo-wide (`sub` and the
///   repository).
/// - `bnd_Z_env` of `wld_a` on `src_gh`: the same plus the environment. Its
///   ID sorts before `bnd_a_repo` byte-wise, after it case-insensitively.
/// - `bnd_a_off` of `wld_a` on `src_gh`: disabled, `sub` only.
/// - `bnd_a_alt` of `wld_a` on `src_alt`: `sub` only.
/// - `bnd_a_free` of `wld_a` on `src_gh`: `sub` only; `grt_a` does not
///   list it.
/// - `bnd_b_deploy` of `wld_b` on `src_gh`: the deployment binding, the
///   same predicates as `bnd_Z_env`.
/// - `bnd_a_srcoff` of `wld_a` on the disabled `src_off`: enabled, `sub`
///   only.
///
/// Grants, all with the audience `rs_1`:
///
/// - `grt_a`: direct, `wld_a`, listing `bnd_a_repo`, `bnd_Z_env`,
///   `bnd_a_off` and `bnd_a_alt`.
/// - `grt_a_svc2`: delegation of `wld_a` to `svc_2`, listing `bnd_a_free`.
/// - `grt_b`: delegation of `wld_b` to `svc_1`, listing `bnd_b_deploy`.
/// - `grt_a_off`: direct, `wld_a`, listing only `bnd_a_off`.
/// - `grt_a_alt`: direct, `wld_a`, listing only `bnd_a_alt`.
/// - `grt_a_srcoff`: direct, `wld_a`, listing only `bnd_a_srcoff`.
/// - `grt_a_dis`: direct, `wld_a`, disabled, listing `bnd_a_repo`.
/// - `grt_a_imp`: the dormant impersonation grant of `wld_a` as `svc_1`
///   (disabled and requiring reapproval, as the schema requires), listing
///   `bnd_a_repo`.
///
/// Each of the last three would be selectable on its own source if its
/// status (or its source's) were not checked.
///
/// In `ten_b`: workload `wld_x`, source `src_x`, binding `bnd_x` and the
/// direct grant `grt_x`.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO principal VALUES
        ('wld_a', 'ten_a', 'workload', 'repo-wide', 'enabled'),
        ('wld_b', 'ten_a', 'workload', 'deployer', 'enabled'),
        ('svc_1', 'ten_a', 'service', 'deploy-api', 'enabled'),
        ('svc_2', 'ten_a', 'service', 'audit-api', 'enabled'),
        ('wld_x', 'ten_b', 'workload', 'other', 'enabled');
    INSERT INTO resource_server VALUES
        ('rs_1', 'api-1', 'API 1', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO audience_tenant_assignment VALUES
        ('ata_1', 'rs_1', 'ten_a', '["wif"]', '["read"]', '[]', 'enabled');
    INSERT INTO service_identity VALUES
        ('svc_1', 'ten_a', 'deploy-api', '["read"]', '{}', 'enabled'),
        ('svc_2', 'ten_a', 'audit-api', '["read"]', '{}', 'enabled');
    -- Enabled egress entries for the seeded destinations (0011 guard).
    INSERT INTO egress_allowlist_entry VALUES
        ('egr_seed_1', 'oidc_discovery', 'https://token.actions.githubusercontent.com/.well-known/openid-configuration', 'enabled'),
        ('egr_seed_2', 'oidc_discovery', 'https://issuer.example.com/.well-known/openid-configuration', 'enabled'),
        ('egr_seed_3', 'oidc_discovery', 'https://retired.example.com/.well-known/openid-configuration', 'enabled');
    INSERT INTO trust_source VALUES
        ('src_gh', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled'),
        ('src_alt', 'ten_a', 'partner', 'oidc_discovery', 'https://issuer.example.com',
         'https://issuer.example.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled'),
        ('src_off', 'ten_a', 'retired', 'oidc_discovery', 'https://retired.example.com',
         'https://retired.example.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'disabled'),
        ('src_x', 'ten_b', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
    INSERT INTO principal_binding VALUES
        ('bnd_a_repo', 'ten_a', 'a-repo', 'src_gh', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production", "repository_id": "456789"}', 'wld_a', 'enabled'),
        ('bnd_Z_env', 'ten_a', 'a-env', 'src_gh', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production", "repository_id": "456789", "environment": "production"}',
         'wld_a', 'enabled'),
        ('bnd_a_off', 'ten_a', 'a-off', 'src_gh', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production"}', 'wld_a', 'disabled'),
        ('bnd_a_alt', 'ten_a', 'a-alt', 'src_alt', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production"}', 'wld_a', 'enabled'),
        ('bnd_a_free', 'ten_a', 'a-free', 'src_gh', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production"}', 'wld_a', 'enabled'),
        ('bnd_b_deploy', 'ten_a', 'b-deploy', 'src_gh', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production", "repository_id": "456789", "environment": "production"}',
         'wld_b', 'enabled'),
        ('bnd_a_srcoff', 'ten_a', 'a-srcoff', 'src_off', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production"}', 'wld_a', 'enabled'),
        ('bnd_x', 'ten_b', 'x', 'src_x', 'generic_production',
         '{"sub": "repo:acme/platform:environment:production"}', 'wld_x', 'enabled');
    INSERT INTO service_grant VALUES
        ('grt_a', 'ten_a', 'a-direct', 'wld_a', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_a_svc2', 'ten_a', 'a-to-svc2', 'wld_a', 'svc_2', 'delegation', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_b', 'ten_a', 'b-to-svc1', 'wld_b', 'svc_1', 'delegation', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_a_off', 'ten_a', 'a-off', 'wld_a', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_a_alt', 'ten_a', 'a-alt', 'wld_a', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_a_srcoff', 'ten_a', 'a-srcoff', 'wld_a', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required'),
        ('grt_a_dis', 'ten_a', 'a-dis', 'wld_a', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'disabled', 'not_required'),
        ('grt_a_imp', 'ten_a', 'a-as-svc1', 'wld_a', 'svc_1', 'impersonation', '["read"]', NULL, '{}', 300, NULL,
         'disabled', 'requires_reapproval'),
        ('grt_x', 'ten_b', 'x', 'wld_x', NULL, 'direct', '["read"]', NULL, '{}', 300, NULL, 'enabled', 'not_required');
    INSERT INTO service_grant_binding VALUES
        ('grt_a', 'bnd_a_repo', 'ten_a', 'wld_a'),
        ('grt_a', 'bnd_Z_env', 'ten_a', 'wld_a'),
        ('grt_a', 'bnd_a_off', 'ten_a', 'wld_a'),
        ('grt_a', 'bnd_a_alt', 'ten_a', 'wld_a'),
        ('grt_a_svc2', 'bnd_a_free', 'ten_a', 'wld_a'),
        ('grt_b', 'bnd_b_deploy', 'ten_a', 'wld_b'),
        ('grt_a_off', 'bnd_a_off', 'ten_a', 'wld_a'),
        ('grt_a_alt', 'bnd_a_alt', 'ten_a', 'wld_a'),
        ('grt_a_srcoff', 'bnd_a_srcoff', 'ten_a', 'wld_a'),
        ('grt_a_dis', 'bnd_a_repo', 'ten_a', 'wld_a'),
        ('grt_a_imp', 'bnd_a_repo', 'ten_a', 'wld_a'),
        ('grt_x', 'bnd_x', 'ten_b', 'wld_x');
    INSERT INTO service_grant_resource_server VALUES
        ('grt_a', 'ten_a', 'rs_1'), ('grt_a_svc2', 'ten_a', 'rs_1'), ('grt_b', 'ten_a', 'rs_1'),
        ('grt_a_off', 'ten_a', 'rs_1'), ('grt_a_alt', 'ten_a', 'rs_1'), ('grt_a_srcoff', 'ten_a', 'rs_1'),
        ('grt_a_dis', 'ten_a', 'rs_1'), ('grt_a_imp', 'ten_a', 'rs_1');
"#;

async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    sqlx::raw_sql(SEED).execute(&pool).await.unwrap();
    (db, pool)
}

fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(claim, value)| (claim.to_string(), value.to_string()))
        .collect()
}

/// Evidence of a push to the production environment of the repository:
/// every predicate of the seed's bindings, plus claims none of them names.
fn production_push() -> Evidence {
    Evidence::new(claims(&[
        ("sub", SUB),
        ("repository_id", "456789"),
        ("environment", "production"),
        ("event_name", "push"),
        ("ref", "refs/heads/main"),
    ]))
}

fn ids(selection: &Selection) -> Vec<&str> {
    selection
        .eligible_bindings
        .iter()
        .map(|binding| binding.id.as_str())
        .collect()
}

async fn select(
    pool: &PgPool,
    tenant_id: &str,
    grant_id: &str,
    source_id: &str,
    mode: GrantMode,
) -> Result<Selection, SelectionError> {
    select_grant(pool, tenant_id, grant_id, source_id, mode).await
}

/// A25 in shape: grants of one tenant with the same audience, for two
/// actors, a direct grant and delegations to two target services. Each
/// selector selects its own grant, with its actor and target, and only the
/// eligible bindings of that actor, sorted byte-wise.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn each_selector_selects_its_own_actor_and_target() {
    let (db, pool) = seeded().await;
    let direct = select(&pool, "ten_a", "grt_a", "src_gh", GrantMode::Direct)
        .await
        .unwrap();
    assert_eq!(
        (
            direct.grant.id.as_str(),
            direct.grant.tenant_id.as_str(),
            direct.grant.actor_principal_id.as_str(),
            direct.grant.target_service_id.as_deref(),
            direct.grant.mode,
            direct.source.id.as_str(),
        ),
        ("grt_a", "ten_a", "wld_a", None, GrantMode::Direct, "src_gh")
    );
    // Byte-wise, "bnd_Z_env" sorts first; the disabled, other-source and
    // unlisted bindings of the actor are not loaded.
    assert_eq!(ids(&direct), ["bnd_Z_env", "bnd_a_repo"]);
    assert_eq!(
        direct.eligible_bindings[1],
        EligibleBinding {
            id: "bnd_a_repo".into(),
            claim_match_policy: claims(&[("sub", SUB), ("repository_id", "456789")]),
            revision: 1,
        }
    );
    // The grant and source are the rows the registry reads.
    assert_eq!(
        direct.grant,
        registry::get_service_grant(&pool, "ten_a", "grt_a")
            .await
            .unwrap()
    );
    assert_eq!(
        direct.source,
        registry::get_trust_source(&pool, "ten_a", "src_gh")
            .await
            .unwrap()
    );

    let to_svc2 = select(
        &pool,
        "ten_a",
        "grt_a_svc2",
        "src_gh",
        GrantMode::Delegation,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            to_svc2.grant.actor_principal_id.as_str(),
            to_svc2.grant.target_service_id.as_deref(),
            to_svc2.grant.mode,
        ),
        ("wld_a", Some("svc_2"), GrantMode::Delegation)
    );
    assert_eq!(ids(&to_svc2), ["bnd_a_free"]);

    let to_svc1 = select(&pool, "ten_a", "grt_b", "src_gh", GrantMode::Delegation)
        .await
        .unwrap();
    assert_eq!(
        (
            to_svc1.grant.actor_principal_id.as_str(),
            to_svc1.grant.target_service_id.as_deref(),
        ),
        ("wld_b", Some("svc_1"))
    );
    assert_eq!(ids(&to_svc1), ["bnd_b_deploy"]);
    for selection in [&direct, &to_svc2, &to_svc1] {
        assert_eq!(selection.grant.resource_server_ids, ["rs_1"]);
    }

    // The same grant on its other source has only that source's binding.
    let alt = select(&pool, "ten_a", "grt_a", "src_alt", GrantMode::Direct)
        .await
        .unwrap();
    assert_eq!(
        (alt.source.id.as_str(), ids(&alt)),
        ("src_alt", vec!["bnd_a_alt"])
    );
    // The other tenant selects its own grant.
    let other = select(&pool, "ten_b", "grt_x", "src_x", GrantMode::Direct)
        .await
        .unwrap();
    assert_eq!(
        (other.grant.tenant_id.as_str(), ids(&other)),
        ("ten_b", vec!["bnd_x"])
    );
    db.drop([pool]).await;
}

/// Every miss gives the same `NotSelectable`, with the same text: a wrong
/// tenant, a mode override, another tenant's source or grant, unknown IDs,
/// a disabled grant, a disabled source, the dormant impersonation grant,
/// and a grant whose actor has no enabled binding listed for the source.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_miss_is_the_same_not_selectable() {
    let (db, pool) = seeded().await;
    let misses = [
        // Another tenant's selector for a grant and source of ten_a.
        ("ten_b", "grt_a", "src_gh", GrantMode::Direct),
        // Mode overrides.
        ("ten_a", "grt_a", "src_gh", GrantMode::Delegation),
        ("ten_a", "grt_b", "src_gh", GrantMode::Direct),
        ("ten_a", "grt_b", "src_gh", GrantMode::Impersonation),
        // Another tenant's source, and another tenant's grant.
        ("ten_a", "grt_a", "src_x", GrantMode::Direct),
        ("ten_a", "grt_x", "src_x", GrantMode::Direct),
        ("ten_a", "grt_x", "src_gh", GrantMode::Direct),
        // Unknown IDs.
        ("ten_a", "grt_none", "src_gh", GrantMode::Direct),
        ("ten_a", "grt_a", "src_none", GrantMode::Direct),
        ("ten_none", "grt_a", "src_gh", GrantMode::Direct),
        ("", "", "", GrantMode::Direct),
        // No eligible binding: only a disabled one, only one on another
        // source, or none of the grant's actor on the source.
        ("ten_a", "grt_a_off", "src_gh", GrantMode::Direct),
        ("ten_a", "grt_a_alt", "src_gh", GrantMode::Direct),
        ("ten_a", "grt_b", "src_alt", GrantMode::Delegation),
        ("ten_a", "grt_a_svc2", "src_alt", GrantMode::Delegation),
        // A disabled grant, and a disabled source, each with an enabled
        // binding of the grant's actor on the source.
        ("ten_a", "grt_a_dis", "src_gh", GrantMode::Direct),
        ("ten_a", "grt_a_srcoff", "src_off", GrantMode::Direct),
        // The dormant impersonation grant, selected in its own mode: the
        // schema keeps it disabled, so the status filter covers it.
        ("ten_a", "grt_a_imp", "src_gh", GrantMode::Impersonation),
    ];
    for (tenant, grant, source, mode) in misses {
        let err = select(&pool, tenant, grant, source, mode)
            .await
            .expect_err(grant);
        let case = format!("{tenant} {grant} {source} {mode}");
        assert_eq!(err, SelectionError::NotSelectable, "{case}");
        assert_eq!(err.to_string(), "no grant can be selected", "{case}");
        assert_eq!(format!("{err:?}"), "NotSelectable", "{case}");
    }
    // The grant whose only binding is on src_alt is selectable there.
    let alt = select(&pool, "ten_a", "grt_a_alt", "src_alt", GrantMode::Direct)
        .await
        .unwrap();
    assert_eq!(ids(&alt), ["bnd_a_alt"]);
    db.drop([pool]).await;
}

/// A50 in shape: the repo-wide binding of `wld_a` and the deployment
/// binding of `wld_b` on one source both fit the same evidence. A grant of
/// `wld_a` matches only bindings of `wld_a`; `wld_b`'s overlap neither
/// matches it nor makes it ambiguous. Of two matching bindings of the same
/// actor, the byte-wise lowest ID is selected, with its own policy and
/// revision only. No match is `None`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_grant_actors_binding_matches_despite_another_actors_overlap() {
    let (db, pool) = seeded().await;
    let of_a = select(&pool, "ten_a", "grt_a", "src_gh", GrantMode::Direct)
        .await
        .unwrap();
    let of_b = select(&pool, "ten_a", "grt_b", "src_gh", GrantMode::Delegation)
        .await
        .unwrap();
    let evidence = production_push();
    let selected = match_binding(&of_a.eligible_bindings, &evidence).unwrap();
    assert_eq!(
        selected,
        &EligibleBinding {
            id: "bnd_Z_env".into(),
            claim_match_policy: claims(&[
                ("sub", SUB),
                ("repository_id", "456789"),
                ("environment", "production"),
            ]),
            revision: 1,
        }
    );
    assert_eq!(
        match_binding(&of_b.eligible_bindings, &evidence).map(|b| b.id.as_str()),
        Some("bnd_b_deploy")
    );

    // Without the environment only the repo-wide binding of wld_a matches;
    // wld_b's grant has no match and does not fall back to wld_a's.
    let no_environment = Evidence::new(claims(&[("sub", SUB), ("repository_id", "456789")]));
    assert_eq!(
        match_binding(&of_a.eligible_bindings, &no_environment).map(|b| b.id.as_str()),
        Some("bnd_a_repo")
    );
    assert_eq!(
        match_binding(&of_b.eligible_bindings, &no_environment),
        None
    );
    // Another repository matches nothing. The sub alone matches nothing
    // either: the bindings that name only the sub are disabled, on another
    // source or not listed.
    let other_repository = Evidence::new(claims(&[
        ("sub", SUB),
        ("repository_id", "999999"),
        ("environment", "production"),
    ]));
    assert_eq!(
        match_binding(&of_a.eligible_bindings, &other_repository),
        None
    );
    let sub_only = Evidence::new(claims(&[("sub", SUB)]));
    assert_eq!(match_binding(&of_a.eligible_bindings, &sub_only), None);

    // The selected binding's revision is the current one.
    registry::test_support::update_principal_binding(
        &pool,
        "ten_a",
        "bnd_Z_env",
        1,
        &PrincipalBindingChanges {
            name: "a-env-renamed".into(),
            profile: BindingProfile::GenericProduction,
            claim_match_policy: claims(&[
                ("sub", SUB),
                ("repository_id", "456789"),
                ("environment", "production"),
            ]),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    let again = select(&pool, "ten_a", "grt_a", "src_gh", GrantMode::Direct)
        .await
        .unwrap();
    let selected = match_binding(&again.eligible_bindings, &evidence).unwrap();
    assert_eq!((selected.id.as_str(), selected.revision), ("bnd_Z_env", 2));
    db.drop([pool]).await;
}

/// The `0004` foreign keys keep a grant's listed binding in its tenant and
/// on its actor, and a binding's source in its tenant; the statement checks
/// the tenant of the grant, the source and the binding, and the actor,
/// again. With the keys dropped in a rolled-back transaction, a listed
/// binding of another actor and one of another tenant, both on the selected
/// source and matching the evidence, are not loaded, and a listed binding
/// on another tenant's source selects nothing for either tenant.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn selection_rechecks_the_tenant_and_actor_the_foreign_keys_guarantee() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::raw_sql(
        r#"BEGIN;
           ALTER TABLE service_grant_binding DROP CONSTRAINT service_grant_binding_binding_id_fkey;
           ALTER TABLE principal_binding
               DROP CONSTRAINT principal_binding_trust_source_id_fkey,
               DROP CONSTRAINT principal_binding_workload_principal_id_fkey;
           INSERT INTO principal_binding VALUES
               ('bnd_0_actor', 'ten_a', 'other-actor', 'src_gh', 'generic_production',
                '{"sub": "repo:acme/platform:environment:production"}', 'wld_b', 'enabled'),
               ('bnd_0_tenant', 'ten_b', 'other-tenant', 'src_gh', 'generic_production',
                '{"sub": "repo:acme/platform:environment:production"}', 'wld_a', 'enabled'),
               ('bnd_0_source', 'ten_a', 'other-source', 'src_x', 'generic_production',
                '{"sub": "repo:acme/platform:environment:production"}', 'wld_a', 'enabled');
           INSERT INTO service_grant_binding VALUES
               ('grt_a', 'bnd_0_actor', 'ten_a', 'wld_a'),
               ('grt_a', 'bnd_0_tenant', 'ten_a', 'wld_a'),
               ('grt_a', 'bnd_0_source', 'ten_a', 'wld_a')"#,
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let selection = select_grant(&mut *conn, "ten_a", "grt_a", "src_gh", GrantMode::Direct)
        .await
        .unwrap();
    assert_eq!(ids(&selection), ["bnd_Z_env", "bnd_a_repo"]);
    let sub_only = Evidence::new(claims(&[("sub", SUB)]));
    assert_eq!(match_binding(&selection.eligible_bindings, &sub_only), None);
    // Neither tenant's selector reaches the binding of ten_a on ten_b's
    // source, nor does ten_b's grant reach ten_a's source.
    for (tenant, grant, source) in [
        ("ten_a", "grt_a", "src_x"),
        ("ten_b", "grt_a", "src_x"),
        ("ten_b", "grt_x", "src_gh"),
    ] {
        assert_eq!(
            select_grant(&mut *conn, tenant, grant, source, GrantMode::Direct)
                .await
                .unwrap_err(),
            SelectionError::NotSelectable,
            "{tenant} {grant} {source}"
        );
    }
    sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await.unwrap();
    drop(conn);
    db.drop([pool]).await;
}

/// The statement's `WHERE EXISTS` gate is required, not only the Rust
/// check that a binding is eligible: it keeps a miss from returning, and so
/// from decoding, a grant row. With the `0007` range check dropped in a
/// rolled-back transaction and `valid_until = 'infinity'` stored on two
/// grants, a hit on one of them is a store failure (the registry cannot
/// read that timestamp), while every miss that finds such a grant row (a
/// grant with no eligible binding, a source of another tenant or an
/// unknown one) is still `NotSelectable`. Without the gate those misses
/// would decode the grant row and be `Store` too.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_miss_decodes_no_grant_row_even_a_corrupt_one() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::raw_sql(
        r#"BEGIN;
           ALTER TABLE service_grant DROP CONSTRAINT service_grant_valid_until_range_check;
           UPDATE service_grant SET valid_until = 'infinity', revision = revision + 1
               WHERE tenant_id = 'ten_a' AND id IN ('grt_a', 'grt_a_off')"#,
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    // Misses first. Each one's grant row matches the tenant, ID and mode,
    // so only the gate keeps it from being returned. (A mode override
    // would not show this: the mode filter already drops the grant row.)
    for (grant, source) in [
        // No eligible binding: its only binding is disabled.
        ("grt_a_off", "src_gh"),
        // A source of another tenant, and an unknown source.
        ("grt_a", "src_x"),
        ("grt_a", "src_none"),
    ] {
        assert_eq!(
            select_grant(&mut *conn, "ten_a", grant, source, GrantMode::Direct)
                .await
                .unwrap_err(),
            SelectionError::NotSelectable,
            "{grant} {source}"
        );
    }
    // A hit on the same corrupt row decodes it: `valid_until` is unreadable,
    // so the hit is a store failure naming the row, never `NotSelectable`.
    let hit = select_grant(&mut *conn, "ten_a", "grt_a", "src_gh", GrantMode::Direct)
        .await
        .unwrap_err();
    assert!(
        matches!(
            &hit,
            SelectionError::Store(RegistryError::UnreadableTimestamp {
                table: "service_grant",
                column: "valid_until",
                id,
            }) if id == "grt_a"
        ),
        "{hit:?}"
    );
    sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await.unwrap();
    drop(conn);
    db.drop([pool]).await;
}

/// Asserts that `err` is a genuine miss: the one `NotSelectable`, with its
/// one text and no source.
fn assert_not_selectable(err: &SelectionError, case: &str) {
    assert_eq!(*err, SelectionError::NotSelectable, "{case}");
    assert_eq!(err.to_string(), "no grant can be selected", "{case}");
    assert_eq!(format!("{err:?}"), "NotSelectable", "{case}");
    assert!(err.source().is_none(), "{case}");
}

/// A store failure is `Store`, never `NotSelectable`, so a caller can tell
/// "retry" from "deny". A selection whose connection the server terminates
/// while the statement waits for the lock another transaction holds is
/// `Store` with the server's `57P01`, not a decode error; on a full pool
/// every selector (a hit and each kind of miss alike) is `Store` with
/// sqlx's `PoolTimedOut`, and on a pool the client closed with its
/// `PoolClosed`. Before any of these, the same misses are each the one
/// `NotSelectable`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_store_failure_is_store_never_not_selectable() {
    let (db, pool) = seeded().await;
    let selectors = [
        // A hit.
        ("ten_a", "grt_a", "src_gh", GrantMode::Direct),
        // An unknown grant, a disabled grant, a wrong tenant, a disabled
        // source and no eligible binding.
        ("ten_a", "grt_none", "src_gh", GrantMode::Direct),
        ("ten_a", "grt_a_dis", "src_gh", GrantMode::Direct),
        ("ten_b", "grt_a", "src_gh", GrantMode::Direct),
        ("ten_a", "grt_a_srcoff", "src_off", GrantMode::Direct),
        ("ten_a", "grt_a_off", "src_gh", GrantMode::Direct),
    ];
    for (index, (tenant, grant, source, mode)) in selectors.into_iter().enumerate() {
        let result = select(&pool, tenant, grant, source, mode).await;
        let case = format!("{tenant} {grant} {source} {mode}");
        if index == 0 {
            assert_eq!(ids(&result.unwrap()), ["bnd_Z_env", "bnd_a_repo"], "{case}");
        } else {
            assert_not_selectable(&result.unwrap_err(), &case);
        }
    }

    // The server ends the connection while the statement waits for a lock.
    // The observer owns the lock holder and always rolls it back before it
    // returns, and gives up when the selection returns first or after
    // `LOCK_WAIT_DEADLINE` without seeing the wait (each with its own
    // failure text); so the selection cannot stay blocked and the join
    // always ends, and a selection that never waited is a prompt failure,
    // not a hang.
    const LOCK_WAIT_DEADLINE: Duration = Duration::from_secs(10);
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE service_grant IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let mut victim = pool.acquire().await.unwrap().detach();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut victim)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let returned = std::cell::Cell::new(false);
    let (result, (blocked_by, terminated)) = tokio::join!(
        async {
            let result =
                select_grant(&mut victim, "ten_a", "grt_a", "src_gh", GrantMode::Direct).await;
            returned.set(true);
            result
        },
        async {
            // The pids that block the selection, once it waits for a lock;
            // or why the observer stopped without seeing it wait.
            let blocked_by = match tokio::time::timeout(LOCK_WAIT_DEADLINE, async {
                loop {
                    if returned.get() {
                        return None;
                    }
                    let blocking: Option<Vec<i32>> = sqlx::query_scalar(
                        "SELECT pg_blocking_pids(pid) FROM pg_stat_activity \
                         WHERE pid = $1 AND wait_event_type = 'Lock'",
                    )
                    .bind(pid)
                    .fetch_optional(&pool)
                    .await
                    .unwrap();
                    if blocking.is_some() {
                        return blocking;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            {
                Ok(Some(pids)) => Ok(pids),
                Ok(None) => Err("returned before it was seen waiting for the lock".to_owned()),
                Err(_) => Err(format!(
                    "was not seen waiting for the lock within {LOCK_WAIT_DEADLINE:?}"
                )),
            };
            let terminated = blocked_by.is_ok()
                && sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
                    .bind(pid)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            blocker.rollback().await.unwrap();
            (blocked_by, terminated)
        }
    );
    let blocked_by = blocked_by.unwrap_or_else(|why| {
        panic!("the selection on backend {pid} {why}; it returned {result:?}")
    });
    assert_eq!(
        blocked_by,
        [blocker_pid],
        "the backends blocking the selection on backend {pid}; it returned {result:?}"
    );
    assert!(terminated, "backend {pid} was not terminated: {result:?}");
    let err = result.unwrap_err();
    match &err {
        SelectionError::Store(RegistryError::Other(sqlx::Error::Database(database))) => {
            assert_eq!(database.code().as_deref(), Some("57P01"), "{err:?}");
        }
        other => panic!("expected a store failure with 57P01: {other:?}"),
    }
    assert!(
        err.to_string().starts_with("grant selection failed: "),
        "{err}"
    );
    assert!(err.source().is_some());
    drop(victim);

    // A full pool: its one connection is held, so every selector times out
    // acquiring one and is the store failure. The short acquire timeout is
    // the point of the leg, but an `acquire` also opens a connection under
    // it, and opening one can take longer on a loaded or slow database; a
    // retry of such an `acquire` cuts each attempt off at the timeout and
    // may never get one. So the pool is built lazily (building it opens
    // nothing) with `min_connections(1)` and no idle timeout or lifetime,
    // so that the pool's own background task opens the one connection
    // under its own long deadline (sqlx's `connect_lazy_with`); the test
    // waits, under its own deadline, until that connection is idle, and
    // only then takes it, which neither opens nor (`test_before_acquire`
    // off) pings one. The six selections then run concurrently, so the leg
    // costs one acquire timeout.
    let full = PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .acquire_timeout(Duration::from_millis(200))
        .test_before_acquire(false)
        .connect_lazy_with((*pool.connect_options()).clone());
    let held = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if full.num_idle() > 0 {
                match full.acquire().await {
                    Ok(connection) => return connection,
                    Err(sqlx::Error::PoolTimedOut) => {}
                    Err(err) => panic!("{err}"),
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the full pool never opened its one connection");
    let select_full =
        |(tenant, grant, source, mode): (&'static str, &'static str, &'static str, GrantMode)| {
            select(&full, tenant, grant, source, mode)
        };
    let (r0, r1, r2, r3, r4, r5) = tokio::join!(
        select_full(selectors[0]),
        select_full(selectors[1]),
        select_full(selectors[2]),
        select_full(selectors[3]),
        select_full(selectors[4]),
        select_full(selectors[5]),
    );
    for ((tenant, grant, source, mode), result) in
        selectors.into_iter().zip([r0, r1, r2, r3, r4, r5])
    {
        let case = format!("{tenant} {grant} {source} {mode}");
        let err = result.expect_err(&case);
        assert!(
            matches!(
                err,
                SelectionError::Store(RegistryError::Other(sqlx::Error::PoolTimedOut))
            ),
            "{case}: {err:?}"
        );
        assert_store_failure(&err, &case);
    }
    drop(held);
    full.close().await;

    // A pool the client closed: every selector is the store failure.
    pool.close().await;
    for (tenant, grant, source, mode) in selectors {
        let err = select(&pool, tenant, grant, source, mode)
            .await
            .unwrap_err();
        let case = format!("{tenant} {grant} {source} {mode}");
        assert!(
            matches!(
                err,
                SelectionError::Store(RegistryError::Other(sqlx::Error::PoolClosed))
            ),
            "{case}: {err:?}"
        );
        assert_store_failure(&err, &case);
    }
    db.drop([pool]).await;
}

/// Asserts that `err`, a pool failure, reads as a store failure: its
/// text, a source, and not equal to `NotSelectable`.
fn assert_store_failure(err: &SelectionError, case: &str) {
    assert_eq!(
        err.to_string(),
        "grant selection failed: registry database error",
        "{case}"
    );
    assert!(err.source().is_some(), "{case}");
    assert_ne!(*err, SelectionError::NotSelectable, "{case}");
}

fn binding(id: &str, policy: &[(&str, &str)]) -> EligibleBinding {
    EligibleBinding {
        id: id.into(),
        claim_match_policy: claims(policy),
        revision: 7,
    }
}

/// Predicates are ANDed exact strings: every one must be in the evidence
/// with the same value. Extra claims of the evidence do not matter; a
/// missing claim, another value, or a value differing only in case or
/// whitespace does not match.
#[test]
fn a_binding_matches_only_when_every_predicate_is_present_and_equal() {
    let deploy = binding("bnd_1", &[("sub", SUB), ("environment", "production")]);
    let eligible = [deploy.clone()];
    let evidence = |pairs: &[(&str, &str)]| Evidence::new(claims(pairs));
    let matched = |pairs: &[(&str, &str)]| match_binding(&eligible, &evidence(pairs)).is_some();
    assert!(matched(&[("sub", SUB), ("environment", "production")]));
    assert!(matched(&[
        ("sub", SUB),
        ("environment", "production"),
        ("ref", "refs/heads/main"),
        ("actor", "octocat"),
    ]));
    // A configured claim absent from the evidence.
    assert!(!matched(&[("sub", SUB)]));
    assert!(!matched(&[("environment", "production")]));
    assert!(!matched(&[]));
    // One predicate equal and the other not.
    assert!(!matched(&[("sub", SUB), ("environment", "staging")]));
    assert!(!matched(&[
        ("sub", "repo:acme/other"),
        ("environment", "production")
    ]));
    // Exact strings: no case folding, trimming or pattern.
    for value in [
        "Production",
        "PRODUCTION",
        "production ",
        " production",
        "prod*",
        ".*",
        "",
    ] {
        assert!(
            !matched(&[("sub", SUB), ("environment", value)]),
            "{value:?}"
        );
    }
    // A claim name differs in case.
    assert!(!matched(&[("sub", SUB), ("Environment", "production")]));
    assert!(deploy.matches(&evidence(&[("sub", SUB), ("environment", "production")])));
}

/// Of several matching bindings, the byte-wise lowest ID is selected in
/// every input order, and it is returned as it is: no other binding's
/// predicates are merged into it. A lower ID that does not match is
/// skipped, not selected.
#[test]
fn the_lowest_matching_id_is_selected_whatever_the_input_order() {
    let narrow = binding("bnd_b", &[("sub", SUB), ("environment", "production")]);
    let wide = binding("bnd_a", &[("sub", SUB)]);
    // Byte-wise "bnd_Z" < "bnd_a" < "bnd_b"; "bnd_0" sorts first of all
    // but does not match.
    let upper = binding("bnd_Z", &[("ref", "refs/heads/main")]);
    let lowest_unmatched = binding("bnd_0", &[("sub", "repo:acme/other")]);
    let evidence = Evidence::new(claims(&[
        ("sub", SUB),
        ("environment", "production"),
        ("ref", "refs/heads/main"),
    ]));
    let all = [narrow, wide, upper, lowest_unmatched];
    let orders: [[usize; 4]; 6] = [
        [0, 1, 2, 3],
        [3, 2, 1, 0],
        [1, 0, 3, 2],
        [2, 3, 0, 1],
        [3, 0, 2, 1],
        [0, 3, 1, 2],
    ];
    for order in orders {
        let eligible: Vec<EligibleBinding> = order.iter().map(|&i| all[i].clone()).collect();
        let selected = match_binding(&eligible, &evidence).unwrap();
        assert_eq!(selected, &all[2], "{order:?}");
        assert!(std::ptr::eq(
            selected,
            eligible.iter().find(|b| b.id == "bnd_Z").unwrap()
        ));
    }
    // Without the ref, bnd_a is the lowest that matches.
    let no_ref = Evidence::new(claims(&[("sub", SUB), ("environment", "production")]));
    for order in orders {
        let eligible: Vec<EligibleBinding> = order.iter().map(|&i| all[i].clone()).collect();
        assert_eq!(
            match_binding(&eligible, &no_ref).map(|b| b.id.as_str()),
            Some("bnd_a"),
            "{order:?}"
        );
    }
}

/// No match is `None`, with no fallback to any binding; an empty policy
/// matches nothing, and no binding matches nothing.
#[test]
fn no_match_selects_nothing() {
    let eligible = [
        binding("bnd_a", &[("sub", SUB)]),
        binding("bnd_b", &[("sub", SUB), ("environment", "production")]),
    ];
    let other = Evidence::new(claims(&[
        ("sub", "repo:acme/other"),
        ("environment", "production"),
    ]));
    assert_eq!(match_binding(&eligible, &other), None);
    assert_eq!(
        match_binding(&[], &Evidence::new(claims(&[("sub", SUB)]))),
        None
    );
    let empty_policy = binding("bnd_empty", &[]);
    assert!(!empty_policy.matches(&Evidence::new(claims(&[("sub", SUB)]))));
    assert!(!empty_policy.matches(&Evidence::default()));
    assert_eq!(match_binding(&[empty_policy], &Evidence::default()), None);
}
