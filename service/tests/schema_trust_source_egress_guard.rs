//! The `0011_trust_source_egress_guard` migration against a real
//! PostgreSQL server (provisional lead pick, 2026-11-22): the trigger
//! `trust_source_egress_enabled` refuses a `trust_source` write that sets
//! `discovery_url` or `token_review_endpoint` to a destination without an
//! enabled `egress_allowlist_entry` of its purpose with exactly that value,
//! whoever writes it. On `INSERT` a member is checked when it is not
//! `NULL`, on `UPDATE` only when it also changes; the refusal is `23514`
//! naming a per-member constraint, which the registry maps to
//! `Invariant { kind: EgressEntryEnabled, constraint }`; the entry is locked
//! `FOR SHARE`, so a concurrent disable and a write serialize, in either
//! order, raw or through the service, without a deadlock, and writes on one
//! entry do not wait for each other; it is an `AFTER` row trigger, so every
//! `0004` guard and check comes first and the end state of a statement
//! decides; it stays on in replica mode; and existing rows are never
//! revalidated.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. The replica-role test needs
//! `SET` on `session_replication_role` and the table owner, and the
//! privilege test `CREATEROLE`.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::TestDb;
use skyoauth_service::{
    persistence::{
        self, MIGRATOR, PgPool,
        registry::{
            self, AssertionProfile, InvariantKind, JsonObject, KNOWN_CONSTRAINTS, NewTrustSource,
            RegistryError, ReplayMode, Status, TrustSource, TrustSourceChanges, TrustSourceKind,
        },
    },
    trust::{
        DISCOVERY_URL, SourceAudit, SourceWriteError, TOKEN_REVIEW_ENDPOINT, create_source,
        update_source,
    },
};
use sqlx::{
    AssertSqlSafe, Connection, Executor, PgConnection, Postgres, Transaction,
    postgres::PgDatabaseError,
};

/// A placeholder for a destination in a statement template.
const DEST: &str = "@destination@";

/// The function and trigger `0011` adds.
const FUNCTION: &str = "skyoauth_check_trust_source_egress";
const TRIGGER: &str = "trust_source_egress_enabled";

/// An enabled `oidc_discovery` entry.
const DISCOVERY: &str = "https://issuer.example/.well-known/openid-configuration";
/// A second enabled `oidc_discovery` entry.
const DISCOVERY_2: &str = "https://issuer2.example/.well-known/openid-configuration";
/// A disabled `oidc_discovery` entry.
const DISCOVERY_OFF: &str = "https://off.example/.well-known/openid-configuration";
/// Only an enabled `token_review` entry has this value.
const DISCOVERY_AS_TR: &str = "https://cross.example/.well-known/openid-configuration";
/// Only an enabled `jwks` entry has this value.
const DISCOVERY_AS_JWKS: &str = "https://jwks.example/.well-known/openid-configuration";
/// An enabled `token_review` entry.
const TOKEN_REVIEW: &str = "https://k3s.example:6443/";
/// A second enabled `token_review` entry.
const TOKEN_REVIEW_2: &str = "https://k3s-2.example:6443/";
/// A disabled `token_review` entry.
const TOKEN_REVIEW_OFF: &str = "https://k3s-off.example:6443/";
/// Only an enabled `oidc_discovery` entry has this value.
const TOKEN_REVIEW_AS_DISC: &str = "https://cross.example:6443/";
/// Only an enabled `jwks` entry has this value.
const TOKEN_REVIEW_AS_JWKS: &str = "https://jwks.example:6443/";
/// No entry has this value.
const UNLISTED: &str = "https://unlisted.example/d";

/// The key of `adm_trust`, the `trust_admin` of `ten_a`.
const KEY: &str = "key_adm_trust";

/// Tenant `ten_a` with keyset `ks_1`; the operator `adm_trust`, a
/// `trust_admin` of `ten_a` with the key [`KEY`]; and the entries of the
/// constants above.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled');
    INSERT INTO trust_keyset VALUES ('ks_1', 'ten_a', 'partner', 'enabled');
    INSERT INTO admin_identity VALUES ('adm_trust', 'enabled');
    INSERT INTO admin_credential VALUES ('crd_trust', 'adm_trust', 'key_adm_trust', 'ops-ca', 'enabled', NULL);
    INSERT INTO admin_role_binding VALUES ('rb_trust', 'adm_trust', 'trust_admin', 'ten_a', 'enabled');
    INSERT INTO egress_allowlist_entry VALUES
        ('egr_disc', 'oidc_discovery', 'https://issuer.example/.well-known/openid-configuration', 'enabled'),
        ('egr_disc_2', 'oidc_discovery', 'https://issuer2.example/.well-known/openid-configuration', 'enabled'),
        ('egr_disc_off', 'oidc_discovery', 'https://off.example/.well-known/openid-configuration', 'disabled'),
        ('egr_tr_as_disc', 'token_review', 'https://cross.example/.well-known/openid-configuration', 'enabled'),
        ('egr_jwks', 'jwks', 'https://jwks.example/.well-known/openid-configuration', 'enabled'),
        ('egr_tr', 'token_review', 'https://k3s.example:6443/', 'enabled'),
        ('egr_tr_2', 'token_review', 'https://k3s-2.example:6443/', 'enabled'),
        ('egr_tr_off', 'token_review', 'https://k3s-off.example:6443/', 'disabled'),
        ('egr_disc_as_tr', 'oidc_discovery', 'https://cross.example:6443/', 'enabled'),
        ('egr_jwks_tr', 'jwks', 'https://jwks.example:6443/', 'enabled')"#;

/// A destination member of a trust source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Member {
    Discovery,
    TokenReview,
}

impl Member {
    const ALL: [Self; 2] = [Self::Discovery, Self::TokenReview];

    fn column(self) -> &'static str {
        match self {
            Self::Discovery => DISCOVERY_URL,
            Self::TokenReview => TOKEN_REVIEW_ENDPOINT,
        }
    }

    fn purpose(self) -> &'static str {
        match self {
            Self::Discovery => "oidc_discovery",
            Self::TokenReview => "token_review",
        }
    }

    fn constraint(self) -> &'static str {
        match self {
            Self::Discovery => "trust_source_discovery_url_egress_enabled",
            Self::TokenReview => "trust_source_token_review_endpoint_egress_enabled",
        }
    }

    /// The enabled entry of this purpose.
    fn enabled(self) -> &'static str {
        match self {
            Self::Discovery => DISCOVERY,
            Self::TokenReview => TOKEN_REVIEW,
        }
    }

    /// A second enabled entry of this purpose.
    fn enabled_2(self) -> &'static str {
        match self {
            Self::Discovery => DISCOVERY_2,
            Self::TokenReview => TOKEN_REVIEW_2,
        }
    }

    /// The disabled entry of this purpose.
    fn disabled(self) -> &'static str {
        match self {
            Self::Discovery => DISCOVERY_OFF,
            Self::TokenReview => TOKEN_REVIEW_OFF,
        }
    }

    /// The ID of [`Member::enabled`]'s entry.
    fn enabled_id(self) -> &'static str {
        match self {
            Self::Discovery => "egr_disc",
            Self::TokenReview => "egr_tr",
        }
    }

    /// Values that only an enabled entry of another purpose has.
    fn other_purposes(self) -> [&'static str; 2] {
        match self {
            Self::Discovery => [DISCOVERY_AS_TR, DISCOVERY_AS_JWKS],
            Self::TokenReview => [TOKEN_REVIEW_AS_DISC, TOKEN_REVIEW_AS_JWKS],
        }
    }

    fn message(self) -> String {
        format!(
            "trust_source {} matches no enabled egress allowlist entry of purpose {}",
            self.column(),
            self.purpose()
        )
    }

    /// The kind whose sources have this member.
    fn kind(self) -> &'static str {
        match self {
            Self::Discovery => "oidc_discovery",
            Self::TokenReview => "kubernetes_token_review",
        }
    }
}

/// A trust source row of `ten_a` as the values of a raw `INSERT`. `kind`
/// sets the kind-specific columns; `discovery` and `endpoint` are the
/// destination members as given, whatever the kind takes.
fn row(id: &str, kind: &str, discovery: Option<&str>, endpoint: Option<&str>) -> String {
    let lit = |value: Option<&str>| {
        value.map_or_else(
            || "NULL".to_string(),
            |value| format!("'{}'", value.replace('\'', "''")),
        )
    };
    let (discovery, endpoint) = (lit(discovery), lit(endpoint));
    match kind {
        "oidc_discovery" => format!(
            "('{id}', 'ten_a', '{id}', 'oidc_discovery', 'https://issuer.example', {discovery}, \
             NULL, NULL, {endpoint}, NULL, NULL, NULL, NULL, '[\"aud\"]', '[\"RS256\"]', '{{}}', \
             'on_demand_jwt', NULL, 'single_use', 'enabled')"
        ),
        "kubernetes_token_review" => format!(
            "('{id}', 'ten_a', '{id}', 'kubernetes_token_review', 'https://kubernetes.default.svc', \
             {discovery}, NULL, 'cluster_{id}', {endpoint}, 'ca', 'fp', 'rv', 1, '[\"aud\"]', NULL, \
             '{{}}', 'projected_service_account', NULL, 'reusable', 'enabled')"
        ),
        "uploaded_jwks" => format!(
            "('{id}', 'ten_a', '{id}', 'uploaded_jwks', 'https://ci.partner.example', {discovery}, \
             'ks_1', NULL, {endpoint}, NULL, NULL, NULL, NULL, '[\"aud\"]', '[\"ES256\"]', '{{}}', \
             'reusable_jwt', NULL, 'reusable', 'enabled')"
        ),
        _ => unreachable!("{kind}"),
    }
}

/// A raw `INSERT` of a source of `member`'s kind with only `member` set.
fn insert(id: &str, member: Member, value: &str) -> String {
    let (discovery, endpoint) = match member {
        Member::Discovery => (Some(value), None),
        Member::TokenReview => (None, Some(value)),
    };
    format!(
        "INSERT INTO trust_source VALUES {}",
        row(id, member.kind(), discovery, endpoint)
    )
}

/// A raw `UPDATE` of `id` that sets `assignments` and advances the
/// revision.
fn update(id: &str, assignments: &str) -> String {
    format!("UPDATE trust_source SET {assignments}, revision = revision + 1 WHERE id = '{id}'")
}

fn set(member: Member, value: &str) -> String {
    format!("{} = '{value}'", member.column())
}

/// A time with sub-microsecond digits, so a write truncates it.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(1_790_000_000_123_456_789)
}

/// An `oidc_discovery` source of `ten_a`, as the registry writes it.
fn oidc(id: &str, discovery_url: &str) -> NewTrustSource {
    NewTrustSource {
        id: id.into(),
        tenant_id: "ten_a".into(),
        name: format!("source-{id}"),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: "https://issuer.example".into(),
        discovery_url: Some(discovery_url.into()),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: vec!["https://identity.example.com".into()],
        algorithms: Some(vec!["RS256".into()]),
        proof_bounds: JsonObject::new(),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    }
}

/// A `kubernetes_token_review` source of `ten_a`, with its own cluster.
fn k8s(id: &str, endpoint: &str) -> NewTrustSource {
    NewTrustSource {
        kind: TrustSourceKind::KubernetesTokenReview,
        exact_issuer: "https://kubernetes.default.svc".into(),
        discovery_url: None,
        cluster_id: Some(format!("cluster_{id}")),
        token_review_endpoint: Some(endpoint.into()),
        ca_bundle_ref: Some("ca_k3s".into()),
        ca_fingerprint: Some("sha256:ca".into()),
        reviewer_credential_ref: Some("reviewer_k3s".into()),
        review_timeout_ms: Some(5000),
        algorithms: None,
        assertion_profile: AssertionProfile::ProjectedServiceAccount,
        replay_mode: ReplayMode::Reusable,
        ..oidc(id, DISCOVERY)
    }
}

/// A source of `member`'s kind with `member` set to `value`.
fn new_source(member: Member, id: &str, value: &str) -> NewTrustSource {
    match member {
        Member::Discovery => oidc(id, value),
        Member::TokenReview => k8s(id, value),
    }
}

/// The mutable columns of `source`, unchanged.
fn changes(source: &TrustSource) -> TrustSourceChanges {
    TrustSourceChanges {
        name: source.name.clone(),
        exact_issuer: source.exact_issuer.clone(),
        discovery_url: source.discovery_url.clone(),
        token_review_endpoint: source.token_review_endpoint.clone(),
        ca_bundle_ref: source.ca_bundle_ref.clone(),
        ca_fingerprint: source.ca_fingerprint.clone(),
        reviewer_credential_ref: source.reviewer_credential_ref.clone(),
        review_timeout_ms: source.review_timeout_ms,
        audiences: source.audiences.clone(),
        algorithms: source.algorithms.clone(),
        proof_bounds: source.proof_bounds.clone(),
        assertion_profile: source.assertion_profile,
        stale_revocation_acknowledged: source.stale_revocation_acknowledged,
        replay_mode: source.replay_mode,
        status: source.status,
    }
}

/// `changes` with `member` set to `value`.
fn with_member(mut changes: TrustSourceChanges, member: Member, value: &str) -> TrustSourceChanges {
    match member {
        Member::Discovery => changes.discovery_url = Some(value.into()),
        Member::TokenReview => changes.token_review_endpoint = Some(value.into()),
    }
    changes
}

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

async fn try_run<'c>(
    executor: impl Executor<'c, Database = Postgres>,
    sql: &str,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(executor)
        .await
        .map(|_| ())
}

fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
        .unwrap_or_else(|| panic!("not a database error: {err}"))
}

/// `err` is the guard's refusal of `member`: `23514`, the member's
/// constraint name, the table, schema and column, and the message, which
/// names no value.
#[track_caller]
fn assert_guard_error(err: &sqlx::Error, member: Member, case: &str) {
    let database = err
        .as_database_error()
        .unwrap_or_else(|| panic!("{case}: not a database error: {err}"));
    let pg = database.downcast_ref::<PgDatabaseError>();
    assert_eq!(
        (
            pg.code(),
            pg.constraint(),
            pg.schema(),
            pg.table(),
            pg.column(),
            pg.message()
        ),
        (
            "23514",
            Some(member.constraint()),
            Some("public"),
            Some("trust_source"),
            Some(member.column()),
            &member.message()[..]
        ),
        "{case}: {err}"
    );
}

/// Runs `sql` in a transaction that is rolled back and checks that the
/// guard refused `member`.
async fn assert_refused(conn: &mut PgConnection, sql: &str, member: Member) {
    let err = try_run(&mut *conn, &format!("BEGIN; {sql}"))
        .await
        .expect_err(sql);
    assert_guard_error(&err, member, sql);
    run(&mut *conn, "ROLLBACK").await;
}

/// Runs `sql` in a transaction that is rolled back and checks that it
/// passes.
async fn assert_passes(conn: &mut PgConnection, sql: &str) {
    run(&mut *conn, &format!("BEGIN; {sql}")).await;
    run(&mut *conn, "ROLLBACK").await;
}

/// Runs `sql` in a transaction that is rolled back and checks that it
/// fails with `code` naming `constraint` (`None` for a guard or a not-null
/// violation, which name none).
async fn assert_fails(conn: &mut PgConnection, sql: &str, code: &str, constraint: Option<&str>) {
    let err = try_run(&mut *conn, &format!("BEGIN; {sql}"))
        .await
        .expect_err(sql);
    let database = err.as_database_error().unwrap();
    assert_eq!(
        (sqlstate(&err), database.constraint()),
        (code.to_string(), constraint),
        "{sql}: {err}"
    );
    run(&mut *conn, "ROLLBACK").await;
}

/// The registry's mapping of the guard's refusal of `member`.
#[track_caller]
fn assert_registry_refusal<T: std::fmt::Debug>(result: Result<T, RegistryError>, member: Member) {
    match result {
        Err(
            ref err @ RegistryError::Invariant {
                kind: InvariantKind::EgressEntryEnabled,
                constraint: Some(constraint),
            },
        ) if constraint == member.constraint() => {
            assert_eq!(
                err.to_string(),
                format!("registry write violates enabled-egress-entry constraint {constraint}")
            );
        }
        other => panic!("{member:?}: expected the guard's Invariant, got {other:?}"),
    }
}

/// The sources as `(id, discovery_url, token_review_endpoint, revision,
/// status)`.
type SourceRow = (String, Option<String>, Option<String>, i64, String);

async fn sources(pool: &PgPool) -> Vec<SourceRow> {
    sqlx::query_as(
        "SELECT id, discovery_url, token_review_endpoint, revision, status::text \
         FROM trust_source ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Catalog properties that behaviour tests cannot see directly: the
/// migration's record, the trigger (`AFTER INSERT OR UPDATE`, each row,
/// `ENABLE ALWAYS`, not a constraint trigger, so not deferrable, its
/// function) and its place last among the `AFTER` row triggers of
/// `trust_source`, after the foreign-key checks, the function's pinned
/// `search_path`,
/// `SECURITY INVOKER`, schema-qualified table and the two constraint names
/// it raises, which `KNOWN_CONSTRAINTS` lists.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn catalog_pins_the_egress_trigger_and_its_function() {
    let (db, pool) = seeded().await;
    let recorded: Vec<(i64, String, bool)> = sqlx::query_as(
        "SELECT version, description, success FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        recorded.contains(&(11, "trust source egress guard".into(), true)),
        "{recorded:?}"
    );
    persistence::migrate(&pool).await.unwrap();

    // tgtype bits: 1 row, 2 before, 4 insert, 8 delete, 16 update.
    let triggers: Vec<(String, String, i16, String, bool, bool)> = sqlx::query_as(
        "SELECT t.tgname::text, p.proname::text, t.tgtype, t.tgenabled::text,
                t.tgdeferrable, t.tgconstraint <> 0
         FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
         WHERE NOT t.tgisinternal AND t.tgfoid = to_regproc($1)::oid",
    )
    .bind(FUNCTION)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        triggers,
        [(
            TRIGGER.to_string(),
            FUNCTION.to_string(),
            1 | 4 | 16,
            "A".to_string(),
            false,
            false
        )]
    );
    let on_source: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger WHERE tgname = $1 AND tgrelid = 'trust_source'::regclass",
    )
    .bind(TRIGGER)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(on_source, 1);

    // PostgreSQL fires the AFTER row triggers of an event in name order
    // (byte-wise): the internal foreign-key triggers, `RI_ConstraintTrigger_`,
    // come first, and this one is the only other.
    for event in [4_i16, 16] {
        let order: Vec<(String, bool)> = sqlx::query_as(
            r#"SELECT tgname::text, tgisinternal FROM pg_trigger
             WHERE tgrelid = 'trust_source'::regclass AND tgtype & 3 = 1 AND tgtype & $1 <> 0
             ORDER BY tgname COLLATE "C""#,
        )
        .bind(event)
        .fetch_all(&pool)
        .await
        .unwrap();
        let (last, before) = order.split_last().unwrap();
        assert_eq!(last, &(TRIGGER.to_string(), false), "{event}: {order:?}");
        assert!(!before.is_empty(), "{event}: {order:?}");
        assert!(
            before
                .iter()
                .all(|(name, internal)| *internal && name.starts_with("RI_ConstraintTrigger_")),
            "{event}: {order:?}"
        );
    }

    let (config, definer, source): (Vec<String>, bool, String) = sqlx::query_as(
        "SELECT p.proconfig, p.prosecdef, p.prosrc FROM pg_proc p
         WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
           AND p.proname = $1",
    )
    .bind(FUNCTION)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(config, ["search_path=pg_catalog, pg_temp"]);
    assert!(!definer);
    assert_eq!(
        source.matches(" public.egress_allowlist_entry ").count(),
        2,
        "{source}"
    );
    assert!(!source.contains(" egress_allowlist_entry "), "{source}");
    for member in Member::ALL {
        let raise = format!("CONSTRAINT = '{}'", member.constraint());
        assert_eq!(source.matches(&raise[..]).count(), 1, "{source}");
        assert!(KNOWN_CONSTRAINTS.contains(&member.constraint()));
    }
    let catalog: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint WHERE conname LIKE '%egress_enabled'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(catalog, 0, "the names are raised, not catalog constraints");
    db.drop([pool]).await;
}

/// A member without an enabled entry of its purpose with exactly its value
/// is refused on `INSERT`: no entry, a disabled one, one of another
/// purpose (`jwks` included), and near misses of an enabled entry (one
/// byte changed, case, a trailing slash, one byte short). An exact match
/// passes; a `NULL` member is never checked.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_insert_needs_an_enabled_entry_of_its_purpose_with_exactly_its_value() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for member in Member::ALL {
        let enabled = member.enabled();
        let mut refused = vec![
            UNLISTED.to_string(),
            member.disabled().to_string(),
            // One byte changed, the case of one letter, a trailing slash,
            // one byte short.
            format!("{}x", &enabled[..enabled.len() - 1]),
            format!("https://{}{}", enabled[8..9].to_uppercase(), &enabled[9..]),
            format!("{enabled}/"),
            enabled[..enabled.len() - 1].to_string(),
        ];
        refused.extend(member.other_purposes().map(str::to_string));
        for value in &refused {
            assert_ne!(value, enabled);
            assert_refused(&mut conn, &insert("src_x", member, value), member).await;
        }
        assert_passes(&mut conn, &insert("src_x", member, enabled)).await;
        assert_passes(&mut conn, &insert("src_x", member, member.enabled_2())).await;
    }

    // NULL members are not checked: a source with neither, and an
    // `oidc_discovery` source whose (absent) endpoint has no enabled entry
    // at all.
    run(
        &mut *conn,
        "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
         WHERE purpose = 'token_review' AND status = 'enabled'",
    )
    .await;
    assert_passes(
        &mut conn,
        &format!(
            "INSERT INTO trust_source VALUES {}",
            row("src_up", "uploaded_jwks", None, None)
        ),
    )
    .await;
    assert_passes(&mut conn, &insert("src_x", Member::Discovery, DISCOVERY)).await;
    assert_eq!(sources(&pool).await, []);
    drop(conn);
    db.drop([pool]).await;
}

/// The members are checked in a fixed order, `discovery_url` first. No
/// kind has both, and the `0004` kind checks, which run first, refuse a row
/// that sets both whatever its destinations; with those checks dropped (in
/// a transaction that is rolled back) such a row is refused for the first
/// member without an entry.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn discovery_url_is_checked_before_token_review_endpoint() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let no_kind_checks = "ALTER TABLE trust_source \
                          DROP CONSTRAINT trust_source_discovery_url_kind_check, \
                          DROP CONSTRAINT trust_source_token_review_fields_kind_check; ";
    for kind in ["oidc_discovery", "kubernetes_token_review"] {
        let both = |discovery, endpoint| {
            format!(
                "INSERT INTO trust_source VALUES {}",
                row("src_x", kind, Some(discovery), Some(endpoint))
            )
        };
        // The kind check of the member the kind lacks refuses the row first
        // (PostgreSQL checks the constraints in name order).
        let check = if kind == "oidc_discovery" {
            "trust_source_token_review_fields_kind_check"
        } else {
            "trust_source_discovery_url_kind_check"
        };
        for (discovery, endpoint) in [
            (UNLISTED, UNLISTED),
            (UNLISTED, TOKEN_REVIEW),
            (DISCOVERY, UNLISTED),
            (DISCOVERY, TOKEN_REVIEW),
        ] {
            assert_fails(&mut conn, &both(discovery, endpoint), "23514", Some(check)).await;
        }
        let both = |discovery, endpoint| format!("{no_kind_checks}{}", both(discovery, endpoint));
        assert_refused(&mut conn, &both(UNLISTED, UNLISTED), Member::Discovery).await;
        assert_refused(&mut conn, &both(UNLISTED, TOKEN_REVIEW), Member::Discovery).await;
        assert_refused(&mut conn, &both(DISCOVERY, UNLISTED), Member::TokenReview).await;
        assert_passes(&mut conn, &both(DISCOVERY, TOKEN_REVIEW)).await;
    }
    assert_eq!(sources(&pool).await, []);
    drop(conn);
    db.drop([pool]).await;
}

/// A `discovery_url` set on a `kubernetes_token_review` source, which has
/// none, fails the `0004` kind check, not the guard, even when no entry
/// lists the value: the check runs first. The guard does check that
/// member whatever the kind: with the kind check dropped (in a transaction
/// that is rolled back) the same write names the egress constraint.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_discovery_url_on_a_token_review_source_fails_its_kind_check_first() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    run(
        &mut *conn,
        &insert("src_k8s", Member::TokenReview, TOKEN_REVIEW),
    )
    .await;
    let set_discovery = update("src_k8s", &set(Member::Discovery, UNLISTED));
    assert_fails(
        &mut conn,
        &set_discovery,
        "23514",
        Some("trust_source_discovery_url_kind_check"),
    )
    .await;
    assert_refused(
        &mut conn,
        &format!(
            "ALTER TABLE trust_source DROP CONSTRAINT trust_source_discovery_url_kind_check; \
             {set_discovery}"
        ),
        Member::Discovery,
    )
    .await;
    drop(conn);
    db.drop([pool]).await;
}

/// An `UPDATE` checks a member only when it changes: a status-only update,
/// a rename, an assignment of the same value and an unrelated change pass
/// while the stored destination's entry is disabled; a change to
/// another value is checked, also back to the stored one's disabled entry,
/// and also when the update disables the source; clearing a member is not
/// checked (the `0004` kind check refuses it).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_update_checks_only_a_changed_member() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        run(&mut *conn, &insert(&id, member, member.enabled())).await;
    }
    run(
        &mut *conn,
        "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
         WHERE id IN ('egr_disc', 'egr_tr')",
    )
    .await;
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        let column = member.column();
        for unchanged in [
            "status = 'disabled'".to_string(),
            format!("name = '{id}-renamed'"),
            format!("{column} = {column}"),
            set(member, member.enabled()),
            "review_timeout_ms = review_timeout_ms, audiences = '[\"aud\", \"aud-2\"]'".into(),
        ] {
            assert_passes(&mut conn, &update(&id, &unchanged)).await;
        }
        for value in [UNLISTED, member.disabled(), member.other_purposes()[0]] {
            assert_refused(&mut conn, &update(&id, &set(member, value)), member).await;
            let disable = format!("{}, status = 'disabled'", set(member, value));
            assert_refused(&mut conn, &update(&id, &disable), member).await;
        }
        assert_passes(&mut conn, &update(&id, &set(member, member.enabled_2()))).await;
        // Cleared: not checked; the kind check refuses it.
        let kind_check = match member {
            Member::Discovery => "trust_source_discovery_url_kind_check",
            Member::TokenReview => "trust_source_token_review_fields_kind_check",
        };
        assert_fails(
            &mut conn,
            &update(&id, &format!("{column} = NULL")),
            "23514",
            Some(kind_check),
        )
        .await;
    }

    // Through the registry, committed: a status-only update and a rename
    // of a source whose entry is disabled pass; moving it to
    // another enabled entry passes; moving it back is refused.
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        let stored = registry::get_trust_source(&pool, "ten_a", &id)
            .await
            .unwrap();
        let mut next = changes(&stored);
        next.status = Status::Disabled;
        let disabled = registry::update_trust_source(&pool, "ten_a", &id, 1, &next)
            .await
            .unwrap();
        assert_eq!((disabled.revision, disabled.status), (2, Status::Disabled));
        next.name = format!("{id}-renamed");
        next.status = Status::Enabled;
        let stored = registry::update_trust_source(&pool, "ten_a", &id, 2, &next)
            .await
            .unwrap();
        assert_eq!((stored.revision, stored.status), (3, Status::Enabled));
        let moved = with_member(changes(&stored), member, member.enabled_2());
        let stored = registry::update_trust_source(&pool, "ten_a", &id, 3, &moved)
            .await
            .unwrap();
        assert_registry_refusal(
            registry::update_trust_source(
                &pool,
                "ten_a",
                &id,
                4,
                &with_member(changes(&stored), member, member.enabled()),
            )
            .await,
            member,
        );
    }
    let ids: Vec<_> = sources(&pool)
        .await
        .into_iter()
        .map(|(id, discovery, endpoint, revision, _)| (id, discovery, endpoint, revision))
        .collect();
    assert_eq!(
        ids,
        [
            (
                "src_discovery_url".to_string(),
                Some(DISCOVERY_2.to_string()),
                None,
                4
            ),
            (
                "src_token_review_endpoint".to_string(),
                None,
                Some(TOKEN_REVIEW_2.to_string()),
                4
            ),
        ]
    );
    drop(conn);
    db.drop([pool]).await;
}

/// An `UPDATE` that leaves both members unchanged (a status-only update,
/// a rename) takes no lock on any entry, even while the stored
/// destination's entry is disabled: its transaction holds no lock on
/// `egress_allowlist_entry` (`pg_locks`), and another transaction can lock
/// the entry row `FOR UPDATE NOWAIT`. An `UPDATE` that changes a member
/// locks that member's entry row, and only it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_unchanged_destination_takes_no_entry_lock() {
    let (db, pool) = seeded().await;
    let held = "SELECT count(*) FROM pg_locks \
                WHERE pid = pg_backend_pid() AND relation = 'egress_allowlist_entry'::regclass";
    let nowait = |id: &str| {
        format!("BEGIN; SELECT 1 FROM egress_allowlist_entry WHERE id = '{id}' FOR UPDATE NOWAIT")
    };
    let mut other = pool.acquire().await.unwrap();
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        run(&pool, &insert(&id, member, member.enabled())).await;
        run(
            &pool,
            &format!(
                "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
                 WHERE id = '{}'",
                member.enabled_id()
            ),
        )
        .await;
        let column = member.column();
        for unchanged in [
            "status = 'disabled'".to_string(),
            format!("name = '{id}-renamed'"),
            format!("{column} = {column}"),
        ] {
            let mut tx = pool.begin().await.unwrap();
            run(&mut *tx, &update(&id, &unchanged)).await;
            let locks: i64 = sqlx::query_scalar(held).fetch_one(&mut *tx).await.unwrap();
            assert_eq!(locks, 0, "{unchanged}");
            run(&mut *other, &nowait(member.enabled_id())).await;
            run(&mut *other, "ROLLBACK").await;
            tx.rollback().await.unwrap();
        }
        let second = format!("{}_2", member.enabled_id());
        let mut tx = pool.begin().await.unwrap();
        run(&mut *tx, &update(&id, &set(member, member.enabled_2()))).await;
        let locks: i64 = sqlx::query_scalar(held).fetch_one(&mut *tx).await.unwrap();
        assert_ne!(locks, 0, "{member:?}");
        let err = try_run(&mut *other, &nowait(&second))
            .await
            .expect_err("the changed member's entry is locked");
        assert_eq!(sqlstate(&err), "55P03", "{err}");
        run(&mut *other, "ROLLBACK").await;
        run(&mut *other, &nowait(member.enabled_id())).await;
        run(&mut *other, "ROLLBACK").await;
        tx.rollback().await.unwrap();
    }
    drop(other);
    db.drop([pool]).await;
}

/// The registry writers map the refusal to
/// `Invariant { EgressEntryEnabled, name }`, on create and on update, and
/// write nothing.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_registry_writers_get_the_guards_invariant() {
    let (db, pool) = seeded().await;
    for member in Member::ALL {
        for value in [UNLISTED, member.disabled(), member.other_purposes()[1]] {
            assert_registry_refusal(
                registry::create_trust_source(&pool, &new_source(member, "src_x", value)).await,
                member,
            );
        }
        let id = format!("src_{}", member.column());
        let stored =
            registry::create_trust_source(&pool, &new_source(member, &id, member.enabled()))
                .await
                .unwrap();
        assert_registry_refusal(
            registry::update_trust_source(
                &pool,
                "ten_a",
                &id,
                1,
                &with_member(changes(&stored), member, UNLISTED),
            )
            .await,
            member,
        );
    }
    assert_eq!(sources(&pool).await.len(), 2);
    db.drop([pool]).await;
}

/// Every `0004` guard and constraint comes first: a write that also changes
/// an immutable column, does not advance the revision, leaves a `NOT NULL`
/// column empty, repeats a unique key or names a missing tenant fails with
/// its own error, whether its destination has an enabled entry or none. A
/// destination that the `0004` shape checks reject (empty, a space, a
/// control character, over 2048 bytes) fails them, never the guard.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_0004_guard_and_constraint_comes_before_the_egress_refusal() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        run(&mut *conn, &insert(&id, member, member.enabled())).await;
    }
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        let dest = set(member, DEST);
        let fresh = insert("src_new", member, DEST);
        let cases: [(String, &str, Option<&str>); 7] = [
            // An immutable column (`trust_source_immutable`).
            (
                update(&id, &format!("tenant_id = 'ten_z', {dest}")),
                "SK001",
                None,
            ),
            (
                update(&id, &format!("id = 'src_moved', {dest}")),
                "SK001",
                None,
            ),
            // A revision that does not advance (`trust_source_revision`).
            (
                format!("UPDATE trust_source SET {dest} WHERE id = '{id}'"),
                "SK001",
                None,
            ),
            // A NOT NULL column.
            (update(&id, &format!("name = NULL, {dest}")), "23502", None),
            // On INSERT: a revision other than 1, a unique key, a missing
            // tenant (a foreign key, whose internal trigger fires before
            // this one).
            (fresh.replace("'enabled')", "'enabled', 2)"), "SK001", None),
            (
                fresh.replace(
                    "'src_new', 'ten_a', 'src_new'",
                    &format!("'src_new', 'ten_a', '{id}'"),
                ),
                "23505",
                Some("trust_source_tenant_id_name_key"),
            ),
            (
                fresh.replace("'src_new', 'ten_a'", "'src_new', 'ten_z'"),
                "23503",
                Some("trust_source_tenant_id_fkey"),
            ),
        ];
        for (template, code, constraint) in cases {
            assert_ne!(template.matches(DEST).count(), 0, "{template}");
            for value in [UNLISTED, member.disabled(), member.enabled_2()] {
                assert_fails(&mut conn, &template.replace(DEST, value), code, constraint).await;
            }
        }
        let column = format!("trust_source_{}", member.column());
        let long = format!("https://x/{}", "d".repeat(2039));
        for (bad, check) in [
            ("", format!("{column}_check")),
            (" https://x/d", format!("{column}_no_space_check")),
            ("https://x/\u{7f}d", format!("{column}_no_space_check")),
            (&long[..], format!("{column}_octet_length_check")),
        ] {
            for sql in [
                insert("src_new", member, bad),
                update(&id, &set(member, bad)),
            ] {
                assert_fails(&mut conn, &sql, "23514", Some(&check)).await;
            }
        }
    }
    drop(conn);
    db.drop([pool]).await;
}

/// The trigger runs at the end of the statement, so the end state of the
/// statement decides, its `WITH` sub-statements included: a write whose
/// statement also disables its entry is refused, whichever part does
/// which; one whose statement creates or enables the entry passes. A
/// statement that disables the entry of a destination it leaves unchanged
/// passes.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_end_state_of_one_statement_decides() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let entry = |id: &str, status: &str| {
        format!(
            "UPDATE egress_allowlist_entry SET status = '{status}', revision = revision + 1 \
             WHERE id = '{id}'"
        )
    };
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        run(&mut *conn, &insert(&id, member, member.enabled())).await;
        let disable = entry(member.enabled_id(), "disabled");
        let disable_2 = format!(
            "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
             WHERE purpose = '{}' AND exact_destination = '{}'",
            member.purpose(),
            member.enabled_2()
        );
        let enable_off = format!(
            "UPDATE egress_allowlist_entry SET status = 'enabled', revision = revision + 1 \
             WHERE purpose = '{}' AND exact_destination = '{}'",
            member.purpose(),
            member.disabled()
        );
        let add_unlisted = format!(
            "INSERT INTO egress_allowlist_entry VALUES ('egr_new', '{}', '{UNLISTED}', 'enabled')",
            member.purpose()
        );
        // The sub-statement disables the entry the main statement writes.
        for sql in [
            format!(
                "WITH off AS ({disable} RETURNING id) {}",
                insert("src_x", member, member.enabled())
            ),
            format!(
                "WITH off AS ({disable_2} RETURNING id) {}",
                update(&id, &set(member, member.enabled_2()))
            ),
            // The other way round: the sub-statement writes, the main
            // statement disables.
            format!(
                "WITH src AS ({} RETURNING id) {disable}",
                insert("src_x", member, member.enabled())
            ),
        ] {
            assert_refused(&mut conn, &sql, member).await;
        }
        // The statement enables or creates the entry it writes on.
        for sql in [
            format!(
                "WITH on_ AS ({enable_off} RETURNING id) {}",
                insert("src_x", member, member.disabled())
            ),
            format!(
                "WITH added AS ({add_unlisted} RETURNING id) {}",
                update(&id, &set(member, UNLISTED))
            ),
            // Unchanged destination: not checked.
            format!(
                "WITH off AS ({disable} RETURNING id) {}",
                update(&id, "status = 'disabled'")
            ),
        ] {
            assert_passes(&mut conn, &sql).await;
        }
    }
    drop(conn);
    db.drop([pool]).await;
}

/// An upsert of a degraded source, one whose entry was disabled after it
/// was written, that carries its stored destination: `ON CONFLICT (id)
/// DO NOTHING` passes and changes nothing, and `DO UPDATE` that leaves the
/// destination as it is passes, though the proposed row names the disabled
/// entry; a `DO UPDATE` that sets the destination to an unlisted or another
/// disabled value is refused. A `BEFORE` trigger would check the proposed
/// row before the conflict and refuse the first two.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_upsert_of_a_degraded_source_with_its_stored_destination_passes() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        let column = member.column();
        run(&pool, &insert(&id, member, member.enabled())).await;
        run(
            &pool,
            &format!(
                "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
                 WHERE id = '{}'",
                member.enabled_id()
            ),
        )
        .await;
        let upsert = |action: &str| {
            format!(
                "{} ON CONFLICT (id) {action}",
                insert(&id, member, member.enabled())
            )
        };
        let before = sources(&pool).await;
        run(&pool, &upsert("DO NOTHING")).await;
        assert_eq!(sources(&pool).await, before, "{member:?}");
        run(
            &pool,
            &upsert(
                "DO UPDATE SET name = trust_source.id || '-renamed', \
                 revision = trust_source.revision + 1",
            ),
        )
        .await;
        let (name, destination, revision): (String, Option<String>, i64) =
            sqlx::query_as(AssertSqlSafe(format!(
                "SELECT name, {column}, revision FROM trust_source WHERE id = $1"
            )))
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            (name, destination.as_deref(), revision),
            (format!("{id}-renamed"), Some(member.enabled()), 2),
            "{member:?}"
        );
        for value in [UNLISTED, member.disabled()] {
            assert_refused(
                &mut conn,
                &upsert(&format!(
                    "DO UPDATE SET {column} = '{value}', revision = trust_source.revision + 1"
                )),
                member,
            )
            .await;
        }
    }
    drop(conn);
    db.drop([pool]).await;
}

/// `INSERT ... ON CONFLICT`: `DO NOTHING` that inserts no row checks
/// nothing; `DO UPDATE` checks the row as it updates it, so a changed
/// destination is checked and an unchanged one is not, whatever the
/// proposed row holds.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn on_conflict_checks_the_row_it_writes() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    for member in Member::ALL {
        let id = format!("src_{}", member.column());
        run(&mut *conn, &insert(&id, member, member.enabled())).await;
        let column = member.column();
        let upsert = |action: &str| {
            format!(
                "{} ON CONFLICT (id) {action}",
                insert(&id, member, UNLISTED)
            )
        };
        assert_passes(&mut conn, &upsert("DO NOTHING")).await;
        assert_refused(
            &mut conn,
            &upsert(&format!(
                "DO UPDATE SET {column} = EXCLUDED.{column}, revision = trust_source.revision + 1"
            )),
            member,
        )
        .await;
        assert_passes(
            &mut conn,
            &upsert("DO UPDATE SET name = 'renamed', revision = trust_source.revision + 1"),
        )
        .await;
    }
    drop(conn);
    db.drop([pool]).await;
}

/// The trigger is `ENABLE ALWAYS`, so it also fires under
/// `session_replication_role = replica`, where foreign keys do not (a
/// source of a missing tenant is accepted there). What stops it is the
/// documented limit (migrations README, "What 0011 adds"): a role that may
/// switch triggers off, such as the table owner with `DISABLE TRIGGER`;
/// and a re-enable with plain `ENABLE TRIGGER` would leave it off in
/// replica mode.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn replica_mode_keeps_the_guard_and_only_switching_it_off_skips_it() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let replica = "SET LOCAL session_replication_role = replica; ";
    for member in Member::ALL {
        let bad = insert("src_x", member, UNLISTED);
        assert_refused(&mut conn, &format!("{replica}{bad}"), member).await;
        let update_bad = format!(
            "{}; {replica}{}",
            insert("src_y", member, member.enabled()),
            update("src_y", &set(member, member.disabled()))
        );
        assert_refused(&mut conn, &update_bad, member).await;
        // Replica mode is in effect: the foreign key of the tenant is off.
        let missing_tenant = insert("src_x", member, member.enabled())
            .replace("'src_x', 'ten_a'", "'src_x', 'ten_z'");
        assert_passes(&mut conn, &format!("{replica}{missing_tenant}")).await;
        assert_fails(
            &mut conn,
            &missing_tenant,
            "23503",
            Some("trust_source_tenant_id_fkey"),
        )
        .await;

        // The limit: switched off by the table owner, it checks nothing.
        let off = format!("ALTER TABLE trust_source DISABLE TRIGGER {TRIGGER}; ");
        assert_passes(&mut conn, &format!("{off}{bad}")).await;
        assert_passes(&mut conn, &format!("{off}{replica}{bad}")).await;
        // Re-enabled for origin only, it is off in replica mode.
        let origin_only = format!("ALTER TABLE trust_source ENABLE TRIGGER {TRIGGER}; ");
        assert_refused(&mut conn, &format!("{origin_only}{bad}"), member).await;
        assert_passes(&mut conn, &format!("{origin_only}{replica}{bad}")).await;
    }
    assert_eq!(sources(&pool).await, []);
    let enabled: String =
        sqlx::query_scalar("SELECT tgenabled::text FROM pg_trigger WHERE tgname = $1")
            .bind(TRIGGER)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(enabled, "A");
    drop(conn);
    db.drop([pool]).await;
}

/// The function runs with the writer's privileges and locks the entry: a
/// role that writes a destination needs `SELECT` on
/// `egress_allowlist_entry` and `UPDATE` on at least one of its columns
/// (`FOR SHARE` needs it), which a column-level `UPDATE (id)` grants; without
/// either the write fails with `42501`. A write that checks no member needs
/// neither.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn destination_writers_need_select_and_update_on_the_entries() {
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    run(
        &pool,
        &format!("GRANT SELECT, INSERT, UPDATE ON trust_source TO {role}"),
    )
    .await;
    run(&pool, &insert("src_held", Member::Discovery, DISCOVERY)).await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    for (privilege, allowed) in [
        (None, false),
        (Some("SELECT"), false),
        (Some("UPDATE (id)"), false),
        (Some("SELECT, UPDATE (id)"), true),
    ] {
        run(
            &pool,
            &format!("REVOKE ALL ON egress_allowlist_entry FROM {role}"),
        )
        .await;
        if let Some(privilege) = privilege {
            run(
                &pool,
                &format!("GRANT {privilege} ON egress_allowlist_entry TO {role}"),
            )
            .await;
        }
        for sql in [
            insert("src_x", Member::Discovery, DISCOVERY),
            insert("src_x", Member::TokenReview, TOKEN_REVIEW),
            update("src_held", &set(Member::Discovery, DISCOVERY_2)),
        ] {
            if allowed {
                assert_passes(&mut writer, &sql).await;
            } else {
                assert_fails(&mut writer, &sql, "42501", None).await;
            }
        }
        // No member checked: no privilege on the entries needed.
        assert_passes(&mut writer, &update("src_held", "status = 'disabled'")).await;
        assert_passes(
            &mut writer,
            &format!(
                "INSERT INTO trust_source VALUES {}",
                row("src_up", "uploaded_jwks", None, None)
            ),
        )
        .await;
    }
    writer.close().await.unwrap();
    db.drop([pool]).await;
}

/// Why the grant must be column-level: a destination writer that holds
/// table-level `UPDATE` on `egress_allowlist_entry` can enable a disabled
/// entry, and then write a source on it, or disable one; with
/// `UPDATE (id)` it can change no status (`42501`), and `id` itself is
/// immutable (`SK001`).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_table_level_update_lets_a_destination_writer_flip_an_entry() {
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    run(
        &pool,
        &format!("GRANT SELECT, INSERT, UPDATE ON trust_source TO {role}"),
    )
    .await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    let enable_off = format!(
        "UPDATE egress_allowlist_entry SET status = 'enabled', revision = revision + 1 \
         WHERE id = 'egr_disc_off'; {}",
        insert("src_x", Member::Discovery, DISCOVERY_OFF)
    );
    let disable = "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
                   WHERE id = 'egr_disc'";
    run(
        &pool,
        &format!("GRANT SELECT, UPDATE ON egress_allowlist_entry TO {role}"),
    )
    .await;
    assert_passes(&mut writer, &enable_off).await;
    assert_passes(&mut writer, disable).await;
    run(
        &pool,
        &format!("REVOKE ALL ON egress_allowlist_entry FROM {role}"),
    )
    .await;
    run(
        &pool,
        &format!("GRANT SELECT, UPDATE (id) ON egress_allowlist_entry TO {role}"),
    )
    .await;
    assert_fails(&mut writer, &enable_off, "42501", None).await;
    assert_fails(&mut writer, disable, "42501", None).await;
    assert_fails(
        &mut writer,
        "UPDATE egress_allowlist_entry SET id = 'egr_moved' WHERE id = 'egr_disc'",
        "SK001",
        None,
    )
    .await;
    assert_passes(&mut writer, &insert("src_x", Member::Discovery, DISCOVERY)).await;
    writer.close().await.unwrap();
    db.drop([pool]).await;
}

/// Existing rows are never revalidated: an upgrade to `0011` keeps sources
/// whose destination has no entry or a disabled one, and they still take
/// writes that leave the destination as it is; a change is checked.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_upgrade_revalidates_no_existing_row() {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    // Every migration before 0011.
    MIGRATOR.run_to(10, &pool).await.unwrap();
    run(&pool, SEED).await;
    let mut conn = pool.acquire().await.unwrap();
    for (n, member) in Member::ALL.into_iter().enumerate() {
        run(
            &mut *conn,
            &insert(&format!("src_none_{n}"), member, UNLISTED),
        )
        .await;
        run(
            &mut *conn,
            &insert(&format!("src_off_{n}"), member, member.disabled()),
        )
        .await;
    }
    drop(conn);
    let before = sources(&pool).await;
    persistence::migrate(&pool).await.unwrap();
    assert_eq!(sources(&pool).await, before);
    let mut conn = pool.acquire().await.unwrap();
    for (n, member) in Member::ALL.into_iter().enumerate() {
        // Each changed to the other's value: still refused.
        for (id, other) in [
            (format!("src_none_{n}"), member.disabled()),
            (format!("src_off_{n}"), UNLISTED),
        ] {
            run(&mut *conn, &update(&id, "status = 'disabled'")).await;
            run(&mut *conn, &update(&id, "name = name || '-renamed'")).await;
            assert_refused(&mut conn, &update(&id, &set(member, other)), member).await;
            let unlisted = set(member, "https://unlisted.example/e");
            assert_refused(&mut conn, &update(&id, &unlisted), member).await;
        }
    }
    drop(conn);
    db.drop([pool]).await;
}

/// Under `REPEATABLE READ` (and `SERIALIZABLE`) a write whose snapshot
/// predates a disable of its entry fails with `40001`, which the registry
/// maps to `Retry`; it never writes through the disabled entry.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_disable_after_the_snapshot_is_a_retry_under_repeatable_read() {
    let (db, pool) = seeded().await;
    for level in ["REPEATABLE READ", "SERIALIZABLE"] {
        for member in Member::ALL {
            run(
                &pool,
                &format!(
                    "UPDATE egress_allowlist_entry SET status = 'enabled', revision = revision + 1 \
                     WHERE id = '{}' AND status = 'disabled'",
                    member.enabled_id()
                ),
            )
            .await;
            let mut tx = pool.begin().await.unwrap();
            run(
                &mut *tx,
                &format!("SET TRANSACTION ISOLATION LEVEL {level}; SELECT 1"),
            )
            .await;
            run(
                &pool,
                &format!(
                    "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
                     WHERE id = '{}'",
                    member.enabled_id()
                ),
            )
            .await;
            let result = registry::create_trust_source(
                &mut *tx,
                &new_source(member, "src_x", member.enabled()),
            )
            .await;
            match &result {
                Err(err @ RegistryError::Retry(_)) => {
                    assert!(
                        err.to_string().contains("40001"),
                        "{level} {member:?}: {err}"
                    );
                }
                other => panic!("{level} {member:?}: expected a retry, got {other:?}"),
            }
            tx.rollback().await.unwrap();
        }
    }
    assert_eq!(sources(&pool).await, []);
    db.drop([pool]).await;
}

// The race harness: a disable of an entry against a write that checks it,
// raw (the registry writers, where only the trigger checks) and through the
// service (`create_source`, `update_source`, which check first and then
// meet the trigger), creating a source or changing a source to the entry's
// value, in both commit orders.

/// Who writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Path {
    Raw,
    Service,
}

/// What the write does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Create,
    Update,
}

#[derive(Debug, Clone, Copy)]
struct Case {
    path: Path,
    op: Op,
    member: Member,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for path in [Path::Raw, Path::Service] {
        for op in [Op::Create, Op::Update] {
            for member in Member::ALL {
                cases.push(Case { path, op, member });
            }
        }
    }
    cases
}

/// The race entry of round `n`, enabled, and its value.
async fn race_entry(pool: &PgPool, member: Member, n: usize) -> (String, String) {
    let id = format!("egr_race_{n}");
    let value = match member {
        Member::Discovery => format!("https://race-{n}.example/d"),
        Member::TokenReview => format!("https://race-{n}.example:6443/"),
    };
    sqlx::query("INSERT INTO egress_allowlist_entry VALUES ($1, $2, $3, 'enabled')")
        .bind(&id)
        .bind(member.purpose())
        .bind(&value)
        .execute(pool)
        .await
        .unwrap();
    (id, value)
}

/// For an update, creates the source of round `n` on the member's enabled
/// entry, which no race disables.
async fn prepare(pool: &PgPool, case: Case, n: usize) {
    if case.op == Op::Update {
        registry::create_trust_source(
            pool,
            &new_source(case.member, &format!("src_{n}"), case.member.enabled()),
        )
        .await
        .unwrap();
    }
}

/// How a write ended.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Written, not yet committed.
    Written,
    /// Refused for its destination: the trigger's `Invariant` (raw) or
    /// `EgressNotAllowed` (service).
    Refused,
    /// Anything else, a `Retry` included: always a test failure.
    Failed(String),
}

/// The write of round `n` of `case` in `tx`: creates `src_<n>`, or changes
/// it to `value`.
async fn write(tx: &mut Transaction<'_, Postgres>, case: Case, n: usize, value: &str) -> Outcome {
    let id = format!("src_{n}");
    let new = new_source(case.member, &id, value);
    let event_id = format!("aud_{n}");
    let audit = SourceAudit {
        event_id: &event_id,
        now: now(),
    };
    let update = || {
        let stored = new_source(case.member, &id, case.member.enabled());
        let current = TrustSourceChanges {
            name: stored.name,
            exact_issuer: stored.exact_issuer,
            discovery_url: stored.discovery_url,
            token_review_endpoint: stored.token_review_endpoint,
            ca_bundle_ref: stored.ca_bundle_ref,
            ca_fingerprint: stored.ca_fingerprint,
            reviewer_credential_ref: stored.reviewer_credential_ref,
            review_timeout_ms: stored.review_timeout_ms,
            audiences: stored.audiences,
            algorithms: stored.algorithms,
            proof_bounds: stored.proof_bounds,
            assertion_profile: stored.assertion_profile,
            stale_revocation_acknowledged: stored.stale_revocation_acknowledged,
            replay_mode: stored.replay_mode,
            status: stored.status,
        };
        with_member(current, case.member, value)
    };
    let raw = |result: Result<TrustSource, RegistryError>| match result {
        Ok(_) => Outcome::Written,
        Err(RegistryError::Invariant {
            kind: InvariantKind::EgressEntryEnabled,
            constraint: Some(constraint),
        }) if constraint == case.member.constraint() => Outcome::Refused,
        Err(err) => Outcome::Failed(format!("{err:?}: {err}")),
    };
    let service = |result: Result<TrustSource, SourceWriteError>| match result {
        Ok(_) => Outcome::Written,
        Err(SourceWriteError::EgressNotAllowed { member }) if member == case.member.column() => {
            Outcome::Refused
        }
        Err(err) => Outcome::Failed(format!("{err:?}: {err}")),
    };
    match (case.path, case.op) {
        (Path::Raw, Op::Create) => raw(registry::create_trust_source(&mut **tx, &new).await),
        (Path::Raw, Op::Update) => {
            raw(registry::update_trust_source(&mut **tx, "ten_a", &id, 1, &update()).await)
        }
        (Path::Service, Op::Create) => service(create_source(tx, KEY, &new, &audit).await),
        (Path::Service, Op::Update) => {
            service(update_source(tx, KEY, "ten_a", &id, 1, &update(), &audit).await)
        }
    }
}

/// Disables `entry` and lists, after the `UPDATE` and in the same
/// transaction, the sources that have `value` in `member`: under
/// `READ COMMITTED` every write that checked the entry has committed or
/// rolled back by then.
async fn disable_and_list(
    conn: &mut PgConnection,
    entry: &str,
    member: Member,
    value: &str,
) -> Vec<String> {
    let done = sqlx::query(
        "UPDATE egress_allowlist_entry SET status = 'disabled', revision = revision + 1 \
         WHERE id = $1",
    )
    .bind(entry)
    .execute(&mut *conn)
    .await
    .unwrap_or_else(|err| panic!("the disable of {entry}: {err}"));
    assert_eq!(done.rows_affected(), 1);
    listed(conn, member, value).await
}

async fn listed(conn: &mut PgConnection, member: Member, value: &str) -> Vec<String> {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT id FROM trust_source WHERE {} = $1 ORDER BY id",
        member.column()
    )))
    .bind(value)
    .fetch_all(&mut *conn)
    .await
    .unwrap()
}

async fn backend_pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

/// Waits until the backend `blocked`, which runs `task`, waits for a lock
/// held by `holder`. Fails at once if `task` finished without waiting.
async fn wait_until_blocked<T>(
    pool: &PgPool,
    blocked: i32,
    holder: i32,
    task: &tokio::task::JoinHandle<T>,
) {
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
            assert!(!task.is_finished(), "finished without waiting for the lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("never waited for the lock");
}

async fn join<T>(task: tokio::task::JoinHandle<T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .expect("the task never finished")
        .unwrap()
}

/// The source of round `n` after the race: `Some(value)` when the write
/// committed, the stored value of an update that was refused, `None` for a
/// refused create.
async fn stored_value(pool: &PgPool, member: Member, n: usize) -> Option<String> {
    let value: Option<Option<String>> = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT {} FROM trust_source WHERE id = $1",
        member.column()
    )))
    .bind(format!("src_{n}"))
    .fetch_optional(pool)
    .await
    .unwrap();
    value.flatten()
}

/// The write first: it holds the entry `FOR SHARE`, so the disable waits
/// until the write commits, then applies and sees the source. No deadlock,
/// raw or through the service, create or update, for either member.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_disable_waits_for_a_write_that_checked_its_entry() {
    let (db, pool) = seeded().await;
    for (n, case) in cases().into_iter().enumerate() {
        let (entry, value) = race_entry(&pool, case.member, n).await;
        prepare(&pool, case, n).await;
        let mut writer = pool.acquire().await.unwrap().detach();
        let mut disabler = pool.acquire().await.unwrap().detach();
        let (writer_pid, disabler_pid) = (
            backend_pid(&mut writer).await,
            backend_pid(&mut disabler).await,
        );
        let mut tx = writer.begin().await.unwrap();
        assert_eq!(
            write(&mut tx, case, n, &value).await,
            Outcome::Written,
            "{case:?}"
        );
        let (task_entry, task_value) = (entry.clone(), value.clone());
        let task = tokio::spawn(async move {
            let mut disable = disabler.begin().await.unwrap();
            let seen = disable_and_list(&mut disable, &task_entry, case.member, &task_value).await;
            disable.commit().await.unwrap();
            (seen, disabler)
        });
        wait_until_blocked(&pool, disabler_pid, writer_pid, &task).await;
        tx.commit().await.unwrap();
        let (seen, disabler) = join(task).await;
        assert_eq!(seen, [format!("src_{n}")], "{case:?}");
        assert_eq!(
            stored_value(&pool, case.member, n).await,
            Some(value),
            "{case:?}"
        );
        let status: String =
            sqlx::query_scalar("SELECT status::text FROM egress_allowlist_entry WHERE id = $1")
                .bind(&entry)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "disabled", "{case:?}");
        writer.close().await.unwrap();
        disabler.close().await.unwrap();
    }
    db.drop([pool]).await;
}

/// The disable first: the write waits for the entry, then reads it
/// `disabled` and is refused, raw by the trigger and through the service by
/// its own check; nothing is written, and no deadlock.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_write_waits_for_a_disable_of_its_entry_and_is_refused() {
    let (db, pool) = seeded().await;
    for (n, case) in cases().into_iter().enumerate() {
        let (entry, value) = race_entry(&pool, case.member, n).await;
        prepare(&pool, case, n).await;
        let before = sources(&pool).await;
        let mut writer = pool.acquire().await.unwrap().detach();
        let mut disabler = pool.acquire().await.unwrap().detach();
        let (writer_pid, disabler_pid) = (
            backend_pid(&mut writer).await,
            backend_pid(&mut disabler).await,
        );
        let mut disable = disabler.begin().await.unwrap();
        assert_eq!(
            disable_and_list(&mut disable, &entry, case.member, &value).await,
            Vec::<String>::new()
        );
        let task_value = value.clone();
        let task = tokio::spawn(async move {
            let mut tx = writer.begin().await.unwrap();
            let outcome = write(&mut tx, case, n, &task_value).await;
            if outcome == Outcome::Written {
                tx.commit().await.unwrap();
            } else {
                tx.rollback().await.unwrap();
            }
            (outcome, writer)
        });
        wait_until_blocked(&pool, writer_pid, disabler_pid, &task).await;
        disable.commit().await.unwrap();
        let (outcome, writer) = join(task).await;
        assert_eq!(outcome, Outcome::Refused, "{case:?}");
        assert_eq!(sources(&pool).await, before, "{case:?}");
        writer.close().await.unwrap();
        disabler.close().await.unwrap();
    }
    db.drop([pool]).await;
}

/// Unordered races, started together: whatever commits first, no write
/// commits through a disabled entry (the sources the disable lists after
/// its `UPDATE` are exactly the ones that hold the value at the end), and
/// no write fails with anything but the refusal of its member, a deadlock
/// or a serialization failure included.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn unordered_races_never_commit_through_a_disabled_entry() {
    const ROUNDS: usize = 6;
    let (db, pool) = seeded().await;
    let mut outcomes = Vec::new();
    for (c, case) in cases().into_iter().enumerate() {
        for round in 0..ROUNDS {
            let n = c * ROUNDS + round;
            let (entry, value) = race_entry(&pool, case.member, n).await;
            prepare(&pool, case, n).await;
            let mut writer = pool.acquire().await.unwrap().detach();
            let mut disabler = pool.acquire().await.unwrap().detach();
            let start = Arc::new(tokio::sync::Barrier::new(2));
            let (writer_start, writer_value) = (Arc::clone(&start), value.clone());
            let write_task = tokio::spawn(async move {
                let mut tx = writer.begin().await.unwrap();
                writer_start.wait().await;
                let outcome = write(&mut tx, case, n, &writer_value).await;
                if outcome == Outcome::Written {
                    tx.commit().await.unwrap();
                } else {
                    tx.rollback().await.unwrap();
                }
                (outcome, writer)
            });
            let disabler_value = value.clone();
            let disable_task = tokio::spawn(async move {
                let mut disable = disabler.begin().await.unwrap();
                start.wait().await;
                let seen =
                    disable_and_list(&mut disable, &entry, case.member, &disabler_value).await;
                disable.commit().await.unwrap();
                (seen, disabler)
            });
            let (outcome, writer) = join(write_task).await;
            let (seen, disabler) = join(disable_task).await;
            let committed =
                stored_value(&pool, case.member, n).await.as_deref() == Some(&value[..]);
            match outcome {
                Outcome::Written => assert!(committed, "{case:?} {n}"),
                Outcome::Refused => assert!(!committed, "{case:?} {n}"),
                Outcome::Failed(err) => panic!("{case:?} {n}: {err}"),
            }
            let expected: Vec<String> = if committed {
                vec![format!("src_{n}")]
            } else {
                Vec::new()
            };
            assert_eq!(
                seen, expected,
                "{case:?} {n}: committed through a disabled entry"
            );
            outcomes.push(committed);
            writer.close().await.unwrap();
            disabler.close().await.unwrap();
        }
    }
    assert_eq!(outcomes.len(), cases().len() * ROUNDS);
    db.drop([pool]).await;
}

/// Two open transactions that write sources on the same entry do not wait
/// for each other (`FOR SHARE` does not conflict with `FOR SHARE`): raw
/// with raw, and raw with the service in both orders. Each write finishes
/// while the other transaction is open, neither backend is blocked, and
/// both commit. Two service writes are not paired: each appends an audit
/// event, and the audit chain head (`FOR UPDATE`) serializes them by
/// design.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn writes_on_one_entry_do_not_block_each_other() {
    let (db, pool) = seeded().await;
    let mut n = 0;
    for member in Member::ALL {
        for (first, second) in [
            (Path::Raw, Path::Raw),
            (Path::Raw, Path::Service),
            (Path::Service, Path::Raw),
        ] {
            let (entry, value) = race_entry(&pool, member, n).await;
            let mut conns = Vec::new();
            let mut pids = Vec::new();
            let mut txs = Vec::new();
            for _ in 0..2 {
                let mut conn = pool.acquire().await.unwrap().detach();
                pids.push(backend_pid(&mut conn).await);
                conns.push(conn);
            }
            for (conn, path) in conns.iter_mut().zip([first, second]) {
                let mut tx = conn.begin().await.unwrap();
                let case = Case {
                    path,
                    op: Op::Create,
                    member,
                };
                let written =
                    tokio::time::timeout(Duration::from_secs(5), write(&mut tx, case, n, &value))
                        .await
                        .unwrap_or_else(|_| panic!("{case:?} {n}: blocked by the other write"));
                assert_eq!(written, Outcome::Written, "{case:?} {n}");
                txs.push(tx);
                n += 1;
            }
            let blocking: Vec<Vec<i32>> = sqlx::query_scalar(
                "SELECT pg_blocking_pids(pid) FROM unnest($1::int4[]) AS pid ORDER BY pid",
            )
            .bind(&pids)
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(blocking, [Vec::<i32>::new(), Vec::new()], "{entry}");
            for tx in txs {
                tx.commit().await.unwrap();
            }
            for conn in conns {
                conn.close().await.unwrap();
            }
            assert_eq!(listed_in(&pool, member, &value).await.len(), 2, "{entry}");
        }
    }
    db.drop([pool]).await;
}

async fn listed_in(pool: &PgPool, member: Member, value: &str) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    listed(&mut conn, member, value).await
}
