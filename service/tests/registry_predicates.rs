//! Required binding predicates (`0008`; ADR-016 items 2 to 4; T12.2)
//! against a real PostgreSQL server: the registry refuses a binding whose
//! `claim_match_policy` lacks a predicate its profile requires, before its
//! statement; the database refuses the same policies through the three
//! named checks; the checks name every claim of the registry's table; and
//! a `0007` database with such a binding upgrades only once the README's
//! precondition query lists none.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{collections::BTreeMap, fmt::Debug};

use common::TestDb;
use skyoauth_service::persistence::{
    self, MIGRATOR, MigrateError, PgPool,
    registry::{
        self, BindingProfile, GITHUB_JOB_WORKFLOW_REF, InvariantKind, NewPrincipalBinding,
        PredicateProblem, PrincipalBindingChanges, RegistryError, Status, required_claims,
        validate_claim_match_policy,
    },
};
use sqlx::{AssertSqlSafe, Executor, Postgres};

const PROFILES: [BindingProfile; 3] = [
    BindingProfile::GithubProduction,
    BindingProfile::KubernetesProduction,
    BindingProfile::GenericProduction,
];

/// A tenant with a workload and one source, insertable at `0007` and
/// later. The source kind does not matter to the checks: that a template
/// fits its source is the service's rule.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled');
    INSERT INTO principal VALUES ('wld_1', 'ten_a', 'workload', 'w1', 'enabled');
    -- Enabled egress entries for the seeded destinations (0011 guard).
    INSERT INTO egress_allowlist_entry VALUES
        ('egr_seed_1', 'oidc_discovery', 'https://token.actions.githubusercontent.com/.well-known/openid-configuration', 'enabled');
    INSERT INTO trust_source VALUES
        ('src_1', 'ten_a', 'github', 'oidc_discovery', 'https://token.actions.githubusercontent.com',
         'https://token.actions.githubusercontent.com/.well-known/openid-configuration',
         NULL, NULL, NULL, NULL, NULL, NULL, NULL,
         '["https://identity.example.com"]', '["RS256"]', '{}', 'reusable_jwt', NULL, 'reusable', 'enabled');
"#;

async fn seeded() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    persistence::migrate(&pool).await.unwrap();
    run(&pool, SEED).await;
    (db, pool)
}

async fn run<'c>(executor: impl Executor<'c, Database = Postgres>, sql: &str) {
    if let Err(err) = sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(executor)
        .await
    {
        panic!("{sql}: {err}");
    }
}

/// The check of `profile` in `0008`.
fn check_name(profile: BindingProfile) -> String {
    format!("principal_binding_{profile}_predicates_check")
}

/// Exactly the required predicates of `profile`, each with a value.
fn complete(profile: BindingProfile) -> BTreeMap<String, String> {
    required_claims(profile)
        .iter()
        .enumerate()
        .map(|(n, claim)| ((*claim).to_string(), format!("value-{n}")))
        .collect()
}

/// The policy as a JSON object literal for SQL, with `claim` replaced by
/// `value` (a JSON literal) or, for `None`, removed.
fn policy_sql(profile: BindingProfile, claim: &str, value: Option<&str>) -> String {
    let mut object = serde_json::Map::new();
    for (name, v) in complete(profile) {
        object.insert(name, serde_json::Value::String(v));
    }
    object.remove(claim);
    if let Some(value) = value {
        object.insert(claim.into(), serde_json::from_str(value).unwrap());
    }
    serde_json::Value::Object(object)
        .to_string()
        .replace('\'', "''")
}

fn new_binding(
    id: &str,
    profile: BindingProfile,
    policy: BTreeMap<String, String>,
) -> NewPrincipalBinding {
    NewPrincipalBinding {
        id: id.into(),
        tenant_id: "ten_a".into(),
        name: format!("binding-{id}"),
        trust_source_id: "src_1".into(),
        profile,
        claim_match_policy: policy,
        workload_principal_id: "wld_1".into(),
        status: Status::Enabled,
    }
}

/// The typed refusal the registry returns before its statement.
#[track_caller]
fn assert_refused<T: Debug>(
    result: Result<T, RegistryError>,
    claim: &str,
    profile: BindingProfile,
    problem: PredicateProblem,
) {
    match result {
        Err(RegistryError::RequiredPredicate {
            claim: named,
            problem: found,
        }) => assert_eq!((named, found), (claim, problem), "{profile}"),
        other => panic!("expected the refusal of {claim} of {profile}: {other:?}"),
    }
}

/// Every binding row as (id, profile, policy, status, revision), by ID.
async fn bindings(pool: &PgPool) -> Vec<(String, String, String, String, i64)> {
    sqlx::query_as(
        "SELECT id, profile, claim_match_policy::text, status, revision FROM principal_binding
          ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Creating or updating a binding without one of its profile's required
/// predicates, or with one empty, is refused before the statement, for
/// every profile and every claim, and nothing is written.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn registry_refuses_a_missing_or_empty_required_predicate() {
    let (db, pool) = seeded().await;
    // One valid binding per profile, to update.
    for profile in PROFILES {
        registry::test_support::create_principal_binding(
            &pool,
            &new_binding(&format!("bnd_{profile}"), profile, complete(profile)),
        )
        .await
        .unwrap();
    }
    let before = bindings(&pool).await;
    for profile in PROFILES {
        for claim in required_claims(profile) {
            for (problem, value) in [
                (PredicateProblem::Missing, None),
                (PredicateProblem::Empty, Some(String::new())),
            ] {
                let mut policy = complete(profile);
                policy.remove(*claim);
                if let Some(value) = value {
                    policy.insert((*claim).to_string(), value);
                }
                assert_refused(
                    registry::test_support::create_principal_binding(
                        &pool,
                        &new_binding("bnd_new", profile, policy.clone()),
                    )
                    .await,
                    claim,
                    profile,
                    problem,
                );
                // An update of each existing binding to this profile, its
                // own included, whatever profile it had.
                for existing in PROFILES {
                    assert_refused(
                        registry::test_support::update_principal_binding(
                            &pool,
                            "ten_a",
                            &format!("bnd_{existing}"),
                            1,
                            &PrincipalBindingChanges {
                                name: "renamed".into(),
                                profile,
                                claim_match_policy: policy.clone(),
                                status: Status::Disabled,
                            },
                        )
                        .await,
                        claim,
                        profile,
                        problem,
                    );
                }
                // Checked before the statement: also for a binding that
                // does not exist.
                assert_refused(
                    registry::test_support::update_principal_binding(
                        &pool,
                        "ten_a",
                        "bnd_x",
                        1,
                        &PrincipalBindingChanges {
                            name: "renamed".into(),
                            profile,
                            claim_match_policy: policy,
                            status: Status::Enabled,
                        },
                    )
                    .await,
                    claim,
                    profile,
                    problem,
                );
            }
        }
    }
    assert_eq!(bindings(&pool).await, before);
    db.drop([pool]).await;
}

/// The required predicates are enough: optional ones may be added, may be
/// empty and may be removed again (omitted means unconstrained; reviewing
/// a removal as widening stays with the service). A profile change needs
/// the new profile's set.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn optional_predicates_are_free_and_a_profile_change_needs_the_new_set() {
    let (db, pool) = seeded().await;
    for profile in PROFILES {
        let id = format!("bnd_{profile}");
        let created = registry::test_support::create_principal_binding(
            &pool,
            &new_binding(&id, profile, complete(profile)),
        )
        .await
        .unwrap();
        assert_eq!(created.claim_match_policy, complete(profile));
        let mut with_optional = complete(profile);
        with_optional.insert(
            GITHUB_JOB_WORKFLOW_REF.into(),
            "acme/shared/.github/workflows/deploy.yml@refs/tags/v1".into(),
        );
        with_optional.insert("actor".into(), String::new());
        let changes = |policy: BTreeMap<String, String>| PrincipalBindingChanges {
            name: format!("binding-{id}"),
            profile,
            claim_match_policy: policy,
            status: Status::Enabled,
        };
        let updated = registry::test_support::update_principal_binding(
            &pool,
            "ten_a",
            &id,
            1,
            &changes(with_optional.clone()),
        )
        .await
        .unwrap();
        assert_eq!(updated.claim_match_policy, with_optional);
        let narrowed_again = registry::test_support::update_principal_binding(
            &pool,
            "ten_a",
            &id,
            2,
            &changes(complete(profile)),
        )
        .await
        .unwrap();
        assert_eq!(
            (narrowed_again.revision, narrowed_again.claim_match_policy),
            (3, complete(profile))
        );
    }
    // generic_production to github_production: sub alone is not enough;
    // with the GitHub set (and sub kept as an optional predicate) it is.
    let mut github = complete(BindingProfile::GithubProduction);
    assert_refused(
        registry::test_support::update_principal_binding(
            &pool,
            "ten_a",
            "bnd_generic_production",
            3,
            &PrincipalBindingChanges {
                name: "moved".into(),
                profile: BindingProfile::GithubProduction,
                claim_match_policy: complete(BindingProfile::GenericProduction),
                status: Status::Enabled,
            },
        )
        .await,
        "repository_owner_id",
        BindingProfile::GithubProduction,
        PredicateProblem::Missing,
    );
    github.insert(
        "sub".into(),
        "repo:acme/platform:environment:production".into(),
    );
    let moved = registry::test_support::update_principal_binding(
        &pool,
        "ten_a",
        "bnd_generic_production",
        3,
        &PrincipalBindingChanges {
            name: "moved".into(),
            profile: BindingProfile::GithubProduction,
            claim_match_policy: github.clone(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        (moved.profile, moved.claim_match_policy, moved.revision),
        (BindingProfile::GithubProduction, github, 4)
    );
    db.drop([pool]).await;
}

/// A whitespace-only value is a non-empty string: the registry and the
/// database both accept it, for every profile and claim, and store it
/// unchanged; it matches only a token carrying exactly that value (design
/// section 5.3), which is matching's rule, not checked here.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_whitespace_only_value_is_accepted_by_the_registry_and_the_database() {
    let (db, pool) = seeded().await;
    let mut n = 0;
    for profile in PROFILES {
        for claim in required_claims(profile) {
            for value in [" ", "\t", " \n "] {
                let mut policy = complete(profile);
                policy.insert((*claim).to_string(), value.to_string());
                assert!(validate_claim_match_policy(profile, &policy).is_ok());
                n += 1;
                let id = format!("bnd_r{n}");
                let created = registry::test_support::create_principal_binding(
                    &pool,
                    &new_binding(&id, profile, policy),
                )
                .await
                .unwrap();
                assert_eq!(created.claim_match_policy[*claim], value);
                // The same policy by raw SQL, past the registry.
                let json = serde_json::to_string(value).unwrap();
                let id = format!("bnd_s{n}");
                run(
                    &pool,
                    &format!(
                        "INSERT INTO principal_binding VALUES ('{id}', 'ten_a', '{id}', 'src_1',
                         '{profile}', '{}', 'wld_1', 'enabled')",
                        policy_sql(profile, claim, Some(&json)),
                    ),
                )
                .await;
                let stored: String = sqlx::query_scalar(
                    "SELECT claim_match_policy ->> $2 FROM principal_binding WHERE id = $1",
                )
                .bind(&id)
                .bind(*claim)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(stored, value);
            }
        }
    }
    db.drop([pool]).await;
}

/// A profile change that drops predicates is a removal, a widening, that
/// neither the registry nor the database stops: a `github_production`
/// binding moved to `generic_production` with a policy of only `sub` meets
/// the new set. The check that the template fits the source is the only
/// stop on that downgrade, and it is not built (migrations README, "What
/// 0008 adds", "Not checked").
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_profile_change_that_drops_predicates_passes_both_checks() {
    let (db, pool) = seeded().await;
    let github = BindingProfile::GithubProduction;
    let generic = BindingProfile::GenericProduction;
    registry::test_support::create_principal_binding(
        &pool,
        &new_binding("bnd_r", github, complete(github)),
    )
    .await
    .unwrap();
    let downgraded = registry::test_support::update_principal_binding(
        &pool,
        "ten_a",
        "bnd_r",
        1,
        &PrincipalBindingChanges {
            name: "binding-bnd_r".into(),
            profile: generic,
            claim_match_policy: complete(generic),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        (downgraded.profile, downgraded.claim_match_policy),
        (generic, complete(generic))
    );
    run(
        &pool,
        &format!(
            "INSERT INTO principal_binding VALUES ('bnd_s', 'ten_a', 'bnd_s', 'src_1',
             'github_production', '{}', 'wld_1', 'enabled');
             UPDATE principal_binding SET profile = 'generic_production',
                    claim_match_policy = '{{\"sub\": \"value-0\"}}', revision = revision + 1
              WHERE id = 'bnd_s'",
            policy_sql(github, "", None),
        ),
    )
    .await;
    db.drop([pool]).await;
}

/// Bypassing the registry, the database refuses the same policies: for
/// every profile and claim, a policy without it, with it empty, or with a
/// value that is not a string fails `23514` on the profile's check, by
/// INSERT and by UPDATE, and maps to `Invariant { Check, <name> }`. A value
/// that is not a string also fails the `0004` check, which PostgreSQL may
/// report first, so that case runs with the `0004` check dropped in a
/// rolled-back transaction. Exactly the required set is accepted.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn database_checks_refuse_the_same_policies() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for profile in PROFILES {
        let id = format!("bnd_{profile}");
        run(
            &mut *conn,
            &format!(
                "INSERT INTO principal_binding VALUES
                     ('{id}', 'ten_a', '{id}', 'src_1', '{profile}', '{}', 'wld_1', 'enabled')",
                policy_sql(profile, "", None)
            ),
        )
        .await;
    }
    run(
        &mut *conn,
        "BEGIN; ALTER TABLE principal_binding DROP CONSTRAINT principal_binding_claim_match_policy_check",
    )
    .await;
    for profile in PROFILES {
        let id = format!("bnd_{profile}");
        for claim in required_claims(profile) {
            for value in [
                None,
                Some(r#""""#),
                Some("1"),
                Some("null"),
                Some(r#"["a"]"#),
                Some(r#"{"a": "b"}"#),
            ] {
                let policy = policy_sql(profile, claim, value);
                for sql in [
                    format!(
                        "INSERT INTO principal_binding VALUES
                             ('bnd_new', 'ten_a', 'new', 'src_1', '{profile}', '{policy}', 'wld_1', 'enabled')"
                    ),
                    format!(
                        "UPDATE principal_binding SET claim_match_policy = '{policy}', revision = revision + 1
                          WHERE id = '{id}'"
                    ),
                    // Another profile's row moved to this profile.
                    format!(
                        "UPDATE principal_binding SET profile = '{profile}', claim_match_policy = '{policy}',
                                revision = revision + 1
                          WHERE id = 'bnd_{}'",
                        PROFILES.iter().find(|p| **p != profile).unwrap()
                    ),
                ] {
                    run(&mut *conn, "SAVEPOINT attempt").await;
                    let err = sqlx::raw_sql(AssertSqlSafe(sql.clone()))
                        .execute(&mut *conn)
                        .await
                        .expect_err(&sql);
                    run(&mut *conn, "ROLLBACK TO SAVEPOINT attempt").await;
                    let db_err = err.as_database_error().unwrap();
                    assert_eq!(
                        (db_err.code().as_deref(), db_err.constraint()),
                        (Some("23514"), Some(check_name(profile).as_str())),
                        "{sql}"
                    );
                    match RegistryError::from(err) {
                        RegistryError::Invariant {
                            kind: InvariantKind::Check,
                            constraint: Some(name),
                        } => assert_eq!(name, check_name(profile)),
                        other => panic!("{sql}: {other:?}"),
                    }
                }
            }
        }
    }
    run(&mut *conn, "ROLLBACK").await;
    // The 0004 check is back; without it a non-string value fails it, on
    // whichever check PostgreSQL reports first.
    let err = sqlx::raw_sql(AssertSqlSafe(format!(
        "UPDATE principal_binding SET claim_match_policy = '{}', revision = revision + 1
          WHERE id = 'bnd_generic_production'",
        policy_sql(BindingProfile::GenericProduction, "sub", Some("1"))
    )))
    .execute(&mut *conn)
    .await
    .unwrap_err();
    assert_eq!(
        err.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    // Exactly the required set, and the required set with optional keys,
    // one of them empty, are accepted.
    for profile in PROFILES {
        run(
            &mut *conn,
            &format!(
                "UPDATE principal_binding SET claim_match_policy = '{}'::jsonb || '{{\"actor\": \"\"}}',
                        revision = revision + 1
                  WHERE id = 'bnd_{profile}'",
                policy_sql(profile, "", None)
            ),
        )
        .await;
    }
    drop(conn);
    let revisions: Vec<i64> =
        sqlx::query_scalar("SELECT revision FROM principal_binding ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(revisions, [2, 2, 2]);
    db.drop([pool]).await;
}

/// The three checks exist, validated, one per profile, with no other
/// predicate check on the table, and each names every claim of the
/// registry's table for its profile and no claim of another profile's.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_checks_name_the_registry_table() {
    let (db, pool) = seeded().await;
    let checks: Vec<(String, bool, String)> = sqlx::query_as(
        r#"SELECT conname::text, convalidated, pg_get_constraintdef(oid)
             FROM pg_constraint
            WHERE conrelid = 'principal_binding'::regclass AND conname::text LIKE '%\_predicates\_check'
            ORDER BY conname COLLATE "C""#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let names: Vec<&str> = checks.iter().map(|(name, _, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "principal_binding_generic_production_predicates_check",
            "principal_binding_github_production_predicates_check",
            "principal_binding_kubernetes_production_predicates_check",
        ]
    );
    for profile in PROFILES {
        let (_, validated, def) = checks
            .iter()
            .find(|(name, _, _)| *name == check_name(profile))
            .unwrap();
        assert!(validated, "{profile}");
        assert!(
            def.contains(&format!("profile <> '{profile}'::text")),
            "{def}"
        );
        for claim in required_claims(profile) {
            // In the key set and in the string and non-empty checks.
            assert!(
                def.matches(&format!("'{claim}'")).count() >= 3,
                "{claim}: {def}"
            );
        }
        for other in PROFILES.iter().filter(|other| **other != profile) {
            for claim in required_claims(*other) {
                if !required_claims(profile).contains(claim) {
                    assert!(!def.contains(&format!("'{claim}'")), "{claim}: {def}");
                }
            }
        }
    }
    db.drop([pool]).await;
}

/// The upgrade precondition query of the migrations README ("What 0008
/// adds").
fn precondition_sql() -> String {
    let readme = include_str!("../migrations/README.md");
    let mut section = &readme[readme
        .find("## What 0008 adds")
        .expect("README has the 0008 section")..];
    section = &section[section
        .find("- **Upgrade precondition.**")
        .expect("the 0008 section has the upgrade precondition")..];
    let start = section.find("```sql\n").unwrap() + "```sql\n".len();
    let end = start + section[start..].find("  ```").unwrap();
    section[start..end]
        .lines()
        .map(|line| line.strip_prefix("  ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn precondition(pool: &PgPool) -> Vec<(String, String, String, String)> {
    sqlx::query_as(AssertSqlSafe(precondition_sql()))
        .fetch_all(pool)
        .await
        .unwrap()
}

/// On a `0007` database the README query lists the bindings `0008` would
/// reject, a disabled one included, and none of the others; with such a
/// binding `0008` fails with `23514` and leaves the database at `0007`;
/// once the owner adds the predicates or retires the binding, the query
/// lists none and `0008` applies.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn upgrade_precondition_lists_the_bindings_that_would_fail_the_upgrade() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    MIGRATOR.run_to(7, &pool).await.unwrap();
    run(&pool, SEED).await;
    let github = policy_sql(BindingProfile::GithubProduction, "", None);
    let no_workflow = policy_sql(BindingProfile::GithubProduction, "workflow_ref", None);
    let empty_uid = policy_sql(
        BindingProfile::KubernetesProduction,
        "kubernetes.io/serviceaccount/service-account.uid",
        Some(r#""""#),
    );
    run(
        &pool,
        &format!(
            r#"INSERT INTO principal_binding VALUES
                   ('bnd_ok', 'ten_a', 'ok', 'src_1', 'github_production', '{github}', 'wld_1', 'enabled'),
                   ('bnd_gh', 'ten_a', 'gh', 'src_1', 'github_production', '{no_workflow}', 'wld_1', 'enabled'),
                   ('bnd_k8s', 'ten_a', 'k8s', 'src_1', 'kubernetes_production', '{empty_uid}', 'wld_1', 'enabled'),
                   ('bnd_old', 'ten_a', 'old', 'src_1', 'generic_production', '{{"sub": ""}}', 'wld_1', 'disabled'),
                   ('bnd_gen', 'ten_a', 'gen', 'src_1', 'generic_production', '{{"sub": "repo:x"}}', 'wld_1', 'enabled'),
                   ('bnd_sub', 'ten_a', 'sub', 'src_1', 'github_production', '{{"sub": "repo:x"}}', 'wld_1', 'enabled')"#
        ),
    )
    .await;
    let listed = |rows: &[(&str, &str, &str)]| -> Vec<(String, String, String, String)> {
        rows.iter()
            .map(|(id, profile, status)| {
                (
                    "ten_a".into(),
                    (*id).into(),
                    (*profile).into(),
                    (*status).into(),
                )
            })
            .collect()
    };
    assert_eq!(
        precondition(&pool).await,
        listed(&[
            ("bnd_gh", "github_production", "enabled"),
            ("bnd_k8s", "kubernetes_production", "enabled"),
            ("bnd_old", "generic_production", "disabled"),
            ("bnd_sub", "github_production", "enabled"),
        ])
    );

    let err = persistence::migrate(&pool).await.unwrap_err();
    let cause = match &err {
        MigrateError::Execute(cause) | MigrateError::ExecuteMigration(cause, _) => cause,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        cause.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514"),
        "{err}"
    );
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 7);
    // Disabling alone repairs nothing.
    run(
        &pool,
        "UPDATE principal_binding SET status = 'disabled', revision = revision + 1 WHERE id = 'bnd_sub'",
    )
    .await;
    assert_eq!(precondition(&pool).await.len(), 4);

    // The owner's repair, as the README lists it: add the predicates by an
    // ordinary update at the binding's revision, or retire the binding.
    let mut gh = registry::get_principal_binding(&pool, "ten_a", "bnd_gh")
        .await
        .unwrap();
    gh.claim_match_policy.insert(
        "workflow_ref".into(),
        "acme/platform/.github/workflows/deploy.yml@refs/heads/main".into(),
    );
    let mut k8s = registry::get_principal_binding(&pool, "ten_a", "bnd_k8s")
        .await
        .unwrap();
    k8s.claim_match_policy.insert(
        "kubernetes.io/serviceaccount/service-account.uid".into(),
        "0b1c2d3e".into(),
    );
    for binding in [gh, k8s] {
        registry::test_support::update_principal_binding(
            &pool,
            "ten_a",
            &binding.id,
            binding.revision,
            &PrincipalBindingChanges {
                name: binding.name.clone(),
                profile: binding.profile,
                claim_match_policy: binding.claim_match_policy.clone(),
                status: binding.status,
            },
        )
        .await
        .unwrap();
    }
    run(
        &pool,
        "DELETE FROM principal_binding WHERE id IN ('bnd_old', 'bnd_sub')",
    )
    .await;
    assert_eq!(precondition(&pool).await, []);

    // Up to 0008 only, so later migrations do not change what is checked.
    MIGRATOR.run_to(8, &pool).await.unwrap();
    let version: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(version, 8);
    // After the upgrade the query still runs and lists nothing.
    assert_eq!(precondition(&pool).await, []);
    let kept: Vec<(String, i64)> =
        sqlx::query_as("SELECT id, revision FROM principal_binding ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        kept,
        [
            ("bnd_gen".into(), 1),
            ("bnd_gh".into(), 2),
            ("bnd_k8s".into(), 2),
            ("bnd_ok".into(), 1)
        ]
    );
    db.drop([pool]).await;
}
