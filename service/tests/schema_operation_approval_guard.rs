//! The approval, audit and revocation guards that `0005_operator` adds
//! since its in-place amendments (`docs/proposals/second-approver-gated-writes.md`
//! section 11; IR-054; D15; the 2026-11-24 ruling on the two cross-scope
//! references) against a real PostgreSQL server: an operation of any kind
//! that names an approved operation names one of its own tenant (`IS NOT
//! DISTINCT FROM`, so the instance names only the instance), and one of
//! kind `approve` never one by its own actor; every operation names an
//! audit event of its own tenant; a revocation, carried by an `INSERT` or
//! written by an `UPDATE`, names a revoking operation of the revoked row's
//! tenant. A refusal is `23514` naming
//! `administrative_operation_approves_same_tenant`,
//! `administrative_operation_approver_distinct`,
//! `administrative_operation_audit_same_tenant` or
//! `administrative_operation_revokes_same_tenant`, which the registry maps to
//! `SameTenantOperation` and `DistinctApprover`. A `route_bundle_approval` by
//! the actor of its preparation stays allowed. The guards are `AFTER` row
//! triggers that fire after the foreign-key checks, are `ENABLE ALWAYS`
//! (replica mode refuses too, and passes a row whose reference is missing),
//! take no row lock, and read with the writer's privileges. The tests also
//! pin the catalog and the privileges README "What 0005 adds" prescribes,
//! the policy row's `FOR SHARE` grant among them.
//!
//! These tests need `SKYOAUTH_IT_DATABASE_URL` (see `common/mod.rs`); each
//! test creates and drops its own database. The replica-mode test needs
//! `SET` on `session_replication_role`, and the privilege tests need
//! `CREATEROLE`. They claim no conformance scenario.
//!
//! No test name here may match the scenario pattern
//! `(^|::)a[0-9]{2}(_[0-9]{2})?_(pos|neg)_`, so `scenarios-pg` never selects them.

mod common;

use std::time::Duration;

use common::TestDb;
use skyoauth_service::persistence::{
    self, PgPool,
    registry::{
        self, DISTINCT_APPROVER, InvariantKind, KNOWN_CONSTRAINTS, RegistryError,
        SAME_TENANT_OPERATION,
    },
};
use sqlx::{
    AssertSqlSafe, Connection, Executor, PgConnection, Postgres, postgres::PgDatabaseError,
};

/// Two tenants, the instance policy row and one audit event per scope
/// (`evt_i`, `evt_a`, `evt_b`); three pending gated writes by `adm_1`, one
/// per scope (`op_i`, `op_a`, `op_b`), and a second pending one of `ten_a`
/// by `adm_2` (`op_a2`); and a `route_bundle_prepare` of `ten_a` by
/// `adm_1` (`op_rp`). Nothing approves or revokes anything yet.
const SEED: &str = r#"
    INSERT INTO tenant VALUES ('ten_a', 'a', 'ns_a', 'enabled'), ('ten_b', 'b', 'ns_b', 'enabled');
    INSERT INTO instance_security_policy (instance_id) VALUES ('inst_1');
    INSERT INTO audit_event VALUES ('evt_i', NULL, 1, NULL, '2026-11-20Z', 'adm_1', 'administrative_operation.create', 'op_i', NULL, NULL, 'pending');
    UPDATE audit_chain_head SET sequence = 1, head_hash = '\x01';
    INSERT INTO audit_event VALUES ('evt_a', 'ten_a', 2, '\x01', '2026-11-20Z', 'adm_1', 'administrative_operation.create', 'op_a', NULL, NULL, 'pending');
    UPDATE audit_chain_head SET sequence = 2, head_hash = '\x02';
    INSERT INTO audit_event VALUES ('evt_b', 'ten_b', 3, '\x02', '2026-11-20Z', 'adm_1', 'administrative_operation.create', 'op_b', NULL, NULL, 'pending');
    UPDATE audit_chain_head SET sequence = 3, head_hash = '\x03';
    INSERT INTO administrative_operation
        (id, tenant_id, actor_id, kind, request_digest, expected_revision, immutable_plan,
         expires_at, outcome, audit_id)
    VALUES
        ('op_i', NULL, 'adm_1', 'instance_security_policy.update', sha256('op_i'), 1, '{}',
         '2026-11-20 01:00Z', 'pending', 'evt_i'),
        ('op_a', 'ten_a', 'adm_1', 'service_grant.update', sha256('op_a'), 1, '{}',
         '2026-11-20 01:00Z', 'pending', 'evt_a'),
        ('op_b', 'ten_b', 'adm_1', 'service_grant.update', sha256('op_b'), 1, '{}',
         '2026-11-20 01:00Z', 'pending', 'evt_b'),
        ('op_a2', 'ten_a', 'adm_2', 'service_grant.update', sha256('op_a2'), 1, '{}',
         '2026-11-20 01:00Z', 'pending', 'evt_a'),
        ('op_rp', 'ten_a', 'adm_1', 'route_bundle_prepare', sha256('op_rp'), 1, '{}',
         '2026-11-20 01:00Z', 'pending', 'evt_a')"#;

const APPROVAL_TRIGGER: &str = "administrative_operation_approval_check";
const AUDIT_TRIGGER: &str = "administrative_operation_audit_check";
const REVOCATION_TRIGGER: &str = "administrative_operation_revocation_check";
const APPROVAL_FUNCTION: &str = "skyoauth_check_operation_approval";
const AUDIT_FUNCTION: &str = "skyoauth_check_operation_audit_event";
const REVOCATION_FUNCTION: &str = "skyoauth_check_operation_revocation";

/// A refusal of the guards: its constraint name, the column it names, its
/// message and the registry's invariant kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    ApprovesOtherTenant,
    SelfApproval,
    AuditOtherTenant,
    RevokesOtherTenant,
}

impl Refusal {
    fn constraint(self) -> &'static str {
        match self {
            Self::ApprovesOtherTenant => "administrative_operation_approves_same_tenant",
            Self::SelfApproval => "administrative_operation_approver_distinct",
            Self::AuditOtherTenant => "administrative_operation_audit_same_tenant",
            Self::RevokesOtherTenant => "administrative_operation_revokes_same_tenant",
        }
    }

    fn column(self) -> &'static str {
        match self {
            Self::ApprovesOtherTenant => "approves_operation_id",
            Self::SelfApproval => "actor_id",
            Self::AuditOtherTenant => "audit_id",
            Self::RevokesOtherTenant => "revocation_operation_id",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::ApprovesOtherTenant => {
                "an operation in administrative_operation approves an operation of another tenant"
            }
            Self::SelfApproval => {
                "an approve in administrative_operation is by the actor of the operation it approves"
            }
            Self::AuditOtherTenant => {
                "an operation in administrative_operation names an audit event of another tenant"
            }
            Self::RevokesOtherTenant => {
                "a revocation in administrative_operation names an operation of another tenant"
            }
        }
    }

    fn kind(self) -> InvariantKind {
        match self {
            Self::SelfApproval => InvariantKind::DistinctApprover,
            _ => InvariantKind::SameTenantOperation,
        }
    }
}

/// The audit event of the seed in `tenant`'s scope.
fn event(tenant: Option<&str>) -> &'static str {
    match tenant {
        None => "evt_i",
        Some("ten_a") => "evt_a",
        Some("ten_b") => "evt_b",
        Some(other) => panic!("{other}"),
    }
}

fn literal(value: Option<&str>) -> String {
    value.map_or_else(|| "NULL".to_string(), |value| format!("'{value}'"))
}

/// The values of a new operation row of the second-approver flow: no
/// expiry for an `approve`, a `cancel` or a `reject`, an hour for any
/// other kind; recorded by the seed's event of its own scope.
fn row(id: &str, tenant: Option<&str>, actor: &str, kind: &str, approves: Option<&str>) -> String {
    row_audited(id, tenant, actor, kind, approves, event(tenant))
}

/// As [`row`], recorded by the audit event `audit`.
fn row_audited(
    id: &str,
    tenant: Option<&str>,
    actor: &str,
    kind: &str,
    approves: Option<&str>,
    audit: &str,
) -> String {
    let expires = if ["approve", "cancel", "reject"].contains(&kind) {
        "NULL"
    } else {
        "'2026-11-20 01:00Z'"
    };
    format!(
        "('{id}', {}, '{actor}', '{kind}', sha256('{id}'), 1, '{{}}', {expires}, {}, 'applied', '{audit}')",
        literal(tenant),
        literal(approves),
    )
}

const COLUMNS: &str = "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, \
                       request_digest, expected_revision, immutable_plan, expires_at, \
                       approves_operation_id, outcome, audit_id) VALUES ";

/// An `INSERT` of one operation.
fn insert(
    id: &str,
    tenant: Option<&str>,
    actor: &str,
    kind: &str,
    approves: Option<&str>,
) -> String {
    format!("{COLUMNS}{}", row(id, tenant, actor, kind, approves))
}

/// An `INSERT` of an `approve` of `approves` in `tenant` by `actor`.
fn approve(id: &str, tenant: Option<&str>, actor: &str, approves: &str) -> String {
    insert(id, tenant, actor, "approve", Some(approves))
}

/// An `INSERT` of an operation recorded by the audit event `audit`.
fn insert_audited(
    id: &str,
    tenant: Option<&str>,
    kind: &str,
    approves: Option<&str>,
    audit: &str,
) -> String {
    format!(
        "{COLUMNS}{}",
        row_audited(id, tenant, "adm_2", kind, approves, audit)
    )
}

/// The statements that append the audit event `id` of `tenant` as the next
/// event of the chain (`sequence`), as a writer does after it locked the
/// head: the event, then the head (`0002`).
fn append_event(id: &str, tenant: Option<&str>, sequence: i64) -> String {
    format!(
        "INSERT INTO audit_event VALUES ('{id}', {}, {sequence}, '\\x{:02x}', '2026-11-20Z', \
         'adm_2', 'administrative_operation.create', '{id}', NULL, NULL, 'pending'); \
         UPDATE audit_chain_head SET sequence = {sequence}, head_hash = '\\x{sequence:02x}'",
        literal(tenant),
        sequence - 1
    )
}

/// An `INSERT` of a revoked operation, revoked by `revoker` when inserted.
fn insert_revoked(id: &str, tenant: Option<&str>, revoker: &str) -> String {
    format!(
        "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, expires_at, revoked_at, revocation_operation_id, \
         outcome, audit_id) VALUES ('{id}', {}, 'adm_1', 'service_grant.update', sha256('{id}'), \
         1, '{{}}', '2026-11-20 01:00Z', '2026-11-20 00:30Z', '{revoker}', 'rejected', '{}')",
        literal(tenant),
        event(tenant)
    )
}

/// The `UPDATE` that revokes `id` by `revoker`, as a revocation writes it.
fn revoke(id: &str, revoker: &str) -> String {
    format!(
        "UPDATE administrative_operation SET revoked_at = '2026-11-20 00:30Z', \
         revocation_operation_id = '{revoker}', outcome = 'rejected', revision = revision + 1 \
         WHERE id = '{id}'"
    )
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

async fn fail<'c>(executor: impl Executor<'c, Database = Postgres>, sql: &str) -> sqlx::Error {
    sqlx::raw_sql(AssertSqlSafe(sql.to_string()))
        .execute(executor)
        .await
        .expect_err(sql)
}

fn sqlstate(err: &sqlx::Error) -> String {
    err.as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
        .unwrap_or_else(|| panic!("not a database error: {err}"))
}

/// `err` is `refusal`: `23514`, its constraint name, the table, schema and
/// column, and the message, which names no value; and the registry maps it
/// to its invariant kind with that name.
#[track_caller]
fn assert_refusal(err: sqlx::Error, refusal: Refusal, case: &str) {
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
            Some(refusal.constraint()),
            Some("public"),
            Some("administrative_operation"),
            Some(refusal.column()),
            refusal.message()
        ),
        "{case}: {err}"
    );
    match RegistryError::from(err) {
        RegistryError::Invariant {
            kind,
            constraint: Some(constraint),
        } => assert_eq!(
            (kind, constraint),
            (refusal.kind(), refusal.constraint()),
            "{case}"
        ),
        other => panic!("{case}: expected {refusal:?}: {other:?}"),
    }
}

/// The stored operation IDs, sorted.
async fn operations(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT id FROM administrative_operation ORDER BY id COLLATE \"C\"")
        .fetch_all(pool)
        .await
        .unwrap()
}

/// The revocation of `id`: its revoking operation and revision.
async fn revocation(pool: &PgPool, id: &str) -> (Option<String>, i64) {
    sqlx::query_as(
        "SELECT revocation_operation_id, revision FROM administrative_operation WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// A trigger as the catalog test reads it: name, function, `tgtype`,
/// deferrable, `tgenabled`, `UPDATE OF` columns and definition.
type TriggerRow = (String, String, i16, bool, String, Vec<String>, String);

const SEEDED: [&str; 5] = ["op_a", "op_a2", "op_b", "op_i", "op_rp"];

/// Catalog properties that behaviour tests cannot see directly: the three
/// triggers (`AFTER`, each row, not deferrable, `ENABLE ALWAYS`, their
/// events, `UPDATE OF` column and `WHEN` clause), their firing order after
/// the immediate foreign-key checks, the functions' pinned `search_path`,
/// `SECURITY INVOKER`, schema-qualified unlocked read and the names they
/// raise, which are in `KNOWN_CONSTRAINTS`, `SAME_TENANT_OPERATION` and
/// `DISTINCT_APPROVER`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn catalog_pins_the_three_triggers_and_their_functions() {
    let (db, pool) = seeded().await;
    // tgtype bits: 1 row, 2 before, 4 insert, 8 delete, 16 update.
    let mut triggers: Vec<TriggerRow> = sqlx::query_as(
        "SELECT t.tgname::text, p.proname::text, t.tgtype, t.tgdeferrable,
                    t.tgenabled::text,
                    ARRAY(SELECT a.attname::text FROM unnest(t.tgattr::int2[]) k
                          JOIN pg_attribute a ON a.attrelid = t.tgrelid AND a.attnum = k),
                    pg_get_triggerdef(t.oid)
             FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
             WHERE NOT t.tgisinternal AND p.proname = ANY($1)
               AND p.pronamespace = to_regnamespace(quote_ident(current_schema()))",
    )
    .bind(
        [APPROVAL_FUNCTION, AUDIT_FUNCTION, REVOCATION_FUNCTION]
            .map(String::from)
            .to_vec(),
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    triggers.sort();
    let def = |rest: &str| format!("CREATE TRIGGER {rest}");
    assert_eq!(
        triggers,
        [
            (
                APPROVAL_TRIGGER.to_string(),
                APPROVAL_FUNCTION.to_string(),
                1 | 4,
                false,
                "A".to_string(),
                vec![],
                def("administrative_operation_approval_check AFTER INSERT ON \
                     public.administrative_operation FOR EACH ROW WHEN \
                     ((new.approves_operation_id IS NOT NULL)) EXECUTE FUNCTION \
                     skyoauth_check_operation_approval()"),
            ),
            (
                AUDIT_TRIGGER.to_string(),
                AUDIT_FUNCTION.to_string(),
                1 | 4,
                false,
                "A".to_string(),
                vec![],
                def("administrative_operation_audit_check AFTER INSERT ON \
                     public.administrative_operation FOR EACH ROW EXECUTE FUNCTION \
                     skyoauth_check_operation_audit_event()"),
            ),
            (
                REVOCATION_TRIGGER.to_string(),
                REVOCATION_FUNCTION.to_string(),
                1 | 4 | 16,
                false,
                "A".to_string(),
                vec!["revocation_operation_id".to_string()],
                def(
                    "administrative_operation_revocation_check AFTER INSERT OR UPDATE OF \
                     revocation_operation_id ON public.administrative_operation FOR EACH ROW \
                     WHEN ((new.revocation_operation_id IS NOT NULL)) EXECUTE FUNCTION \
                     skyoauth_check_operation_revocation()"
                ),
            ),
        ]
    );

    // The AFTER row triggers of the table, in firing (name) order, per
    // event: the foreign-key triggers, none deferrable, then the guards.
    for (event, guards) in [
        (4, vec![APPROVAL_TRIGGER, AUDIT_TRIGGER, REVOCATION_TRIGGER]),
        (16, vec![REVOCATION_TRIGGER]),
    ] {
        let fired: Vec<(String, bool, bool)> = sqlx::query_as(
            "SELECT t.tgname::text, t.tgisinternal, t.tgdeferrable
             FROM pg_trigger t
             WHERE t.tgrelid = to_regclass(quote_ident(current_schema()) || '.administrative_operation')
               AND t.tgtype & (1 | 2 | $1) = (1 | $1)
             ORDER BY t.tgname COLLATE \"C\"",
        )
        .bind(event)
        .fetch_all(&pool)
        .await
        .unwrap();
        let first = fired
            .iter()
            .position(|(name, ..)| name == guards[0])
            .unwrap_or_else(|| panic!("{fired:?}"));
        let (checks, after) = fired.split_at(first);
        assert!(
            !checks.is_empty()
                && checks.iter().all(|(name, internal, deferrable)| {
                    name.starts_with("RI_ConstraintTrigger_") && *internal && !*deferrable
                }),
            "{event}: {fired:?}"
        );
        let after: Vec<&str> = after.iter().map(|(name, ..)| name.as_str()).collect();
        assert_eq!(after, guards, "{event}");
    }
    // The three references the guards read are immediate foreign keys.
    for name in [
        "administrative_operation_approves_operation_id_fkey",
        "administrative_operation_audit_id_fkey",
        "administrative_operation_revocation_operation_id_fkey",
    ] {
        let deferrable: bool = sqlx::query_scalar(
            "SELECT condeferrable FROM pg_constraint
             WHERE conrelid = to_regclass(quote_ident(current_schema()) || '.administrative_operation')
               AND conname = $1",
        )
        .bind(name)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!deferrable, "{name}");
    }

    for (function, raised, read) in [
        (
            APPROVAL_FUNCTION,
            vec![Refusal::ApprovesOtherTenant, Refusal::SelfApproval],
            "administrative_operation o",
        ),
        (
            AUDIT_FUNCTION,
            vec![Refusal::AuditOtherTenant],
            "audit_event e",
        ),
        (
            REVOCATION_FUNCTION,
            vec![Refusal::RevokesOtherTenant],
            "administrative_operation o",
        ),
    ] {
        let (config, definer, source): (Vec<String>, bool, String) = sqlx::query_as(
            "SELECT p.proconfig, p.prosecdef, p.prosrc FROM pg_proc p
             WHERE p.pronamespace = to_regnamespace(quote_ident(current_schema()))
               AND p.proname = $1",
        )
        .bind(function)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(config, ["search_path=pg_catalog, pg_temp"], "{function}");
        assert!(!definer, "{function}: SECURITY INVOKER");
        assert!(
            source.contains(&format!(" public.{read}"))
                && !source.contains(&format!(" {read}"))
                && !source.contains("FOR "),
            "{function}: {source}"
        );
        for refusal in raised {
            assert!(
                source.contains(&format!("CONSTRAINT = '{}'", refusal.constraint())),
                "{function}: {refusal:?}"
            );
            assert!(
                source.contains(&format!("COLUMN = '{}'", refusal.column())),
                "{function}: {refusal:?}"
            );
        }
    }

    for name in SAME_TENANT_OPERATION.iter().chain(&DISTINCT_APPROVER) {
        assert!(KNOWN_CONSTRAINTS.binary_search(name).is_ok(), "{name}");
    }
    assert_eq!(
        SAME_TENANT_OPERATION,
        [
            Refusal::ApprovesOtherTenant.constraint(),
            Refusal::AuditOtherTenant.constraint(),
            Refusal::RevokesOtherTenant.constraint()
        ]
    );
    assert_eq!(DISTINCT_APPROVER, [Refusal::SelfApproval.constraint()]);
    db.drop([pool]).await;
}

/// An `approve` by the actor of the operation it approves is refused in
/// every scope, also when the approve is the second row of one statement;
/// one by another actor is accepted, and the approval of an operation
/// inserted earlier in the same statement is checked against it.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approve_by_the_requesters_actor_is_refused() {
    let (db, pool) = seeded().await;
    for (tenant, approved) in [
        (None, "op_i"),
        (Some("ten_a"), "op_a"),
        (Some("ten_b"), "op_b"),
    ] {
        let err = fail(&pool, &approve("op_x", tenant, "adm_1", approved)).await;
        assert_refusal(err, Refusal::SelfApproval, approved);
    }
    // The comparison is byte-wise: another case is another actor.
    run(&pool, &approve("op_case", Some("ten_a"), "ADM_1", "op_a")).await;
    run(&pool, &approve("op_ok", Some("ten_a"), "adm_2", "op_a")).await;
    // The requester of op_a2 is adm_2; adm_1 may approve it.
    run(&pool, &approve("op_ok2", Some("ten_a"), "adm_1", "op_a2")).await;

    // One statement inserting an operation and its approval.
    let both = |approver: &str| {
        format!(
            "{COLUMNS}{}, {}",
            row(
                "op_new",
                Some("ten_a"),
                "adm_3",
                "service_grant.update",
                None
            ),
            row(
                "op_new_ok",
                Some("ten_a"),
                approver,
                "approve",
                Some("op_new")
            )
        )
    };
    let err = fail(&pool, &both("adm_3")).await;
    assert_refusal(err, Refusal::SelfApproval, "one statement");
    run(&pool, &both("adm_4")).await;

    let mut want: Vec<String> = SEEDED
        .iter()
        .chain(&["op_case", "op_ok", "op_ok2", "op_new", "op_new_ok"])
        .map(ToString::to_string)
        .collect();
    want.sort();
    assert_eq!(operations(&pool).await, want);
    db.drop([pool]).await;
}

/// An `approve` names an operation of its own tenant: a tenant approve of
/// another tenant's operation, an instance approve of a tenant operation
/// and a tenant approve of an instance operation are refused; an instance
/// approve of an instance operation and a tenant approve of its own
/// tenant's are accepted. The tenant is compared before the actor, so an
/// approve that fails both is the tenant refusal.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_approve_names_an_operation_of_its_own_tenant() {
    let (db, pool) = seeded().await;
    for (tenant, approved, case) in [
        (Some("ten_a"), "op_b", "tenant to other tenant"),
        (Some("ten_b"), "op_a", "tenant to other tenant"),
        (None, "op_a", "instance to tenant"),
        (Some("ten_a"), "op_i", "tenant to instance"),
    ] {
        let err = fail(&pool, &approve("op_x", tenant, "adm_2", approved)).await;
        assert_refusal(err, Refusal::ApprovesOtherTenant, case);
        // Also by the approved operation's actor: the tenant comes first.
        let err = fail(&pool, &approve("op_x", tenant, "adm_1", approved)).await;
        assert_refusal(err, Refusal::ApprovesOtherTenant, case);
    }
    run(&pool, &approve("op_x_i", None, "adm_2", "op_i")).await;
    run(&pool, &approve("op_x_a", Some("ten_a"), "adm_2", "op_a")).await;
    run(&pool, &approve("op_x_b", Some("ten_b"), "adm_2", "op_b")).await;
    let approvals: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, tenant_id, approves_operation_id FROM administrative_operation
         WHERE kind = 'approve' ORDER BY id COLLATE \"C\"",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        approvals,
        [
            ("op_x_a".into(), Some("ten_a".into()), "op_a".into()),
            ("op_x_b".into(), Some("ten_b".into()), "op_b".into()),
            ("op_x_i".into(), None, "op_i".into()),
        ]
    );
    db.drop([pool]).await;
}

/// Every kind that names an approved operation names one of its own
/// tenant, not only `approve`: a `route_bundle_approval` naming another
/// tenant's preparation, an instance one naming a tenant's and a tenant one
/// naming an instance operation are refused, as is another kind
/// (`approval`), with the approval guard's name, and write nothing. A
/// `route_bundle_approval` naming its own tenant's preparation is accepted,
/// also by the preparation's actor (IR-054: the actor is checked for kind
/// `approve` only), and so is an instance one naming an instance
/// operation. A missing approved operation is the foreign key's `23503`,
/// not the guard's, whatever the kind.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn every_kind_that_names_an_operation_names_one_of_its_own_tenant() {
    let (db, pool) = seeded().await;
    for (tenant, kind, approved, case) in [
        (
            Some("ten_b"),
            "route_bundle_approval",
            "op_rp",
            "tenant to other tenant",
        ),
        (
            Some("ten_a"),
            "route_bundle_approval",
            "op_b",
            "tenant to other tenant",
        ),
        (None, "route_bundle_approval", "op_rp", "instance to tenant"),
        (
            Some("ten_a"),
            "route_bundle_approval",
            "op_i",
            "tenant to instance",
        ),
        (Some("ten_b"), "approval", "op_a", "another kind"),
        (None, "approval", "op_b", "another kind, instance to tenant"),
    ] {
        // By the approved operation's actor and by another: the actor does
        // not matter for these kinds.
        for actor in ["adm_1", "adm_2"] {
            let err = fail(&pool, &insert("op_x", tenant, actor, kind, Some(approved))).await;
            assert_refusal(err, Refusal::ApprovesOtherTenant, case);
        }
    }
    assert_eq!(operations(&pool).await, SEEDED);

    // The same tenant: accepted, by the preparation's actor too.
    run(
        &pool,
        &insert(
            "op_rba",
            Some("ten_a"),
            "adm_1",
            "route_bundle_approval",
            Some("op_rp"),
        ),
    )
    .await;
    run(
        &pool,
        &insert(
            "op_rba2",
            Some("ten_a"),
            "adm_2",
            "route_bundle_approval",
            Some("op_rp"),
        ),
    )
    .await;
    run(
        &pool,
        &insert("op_ap", None, "adm_1", "approval", Some("op_i")),
    )
    .await;
    let names: Vec<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT o.id, o.tenant_id, o.approves_operation_id FROM administrative_operation o
         JOIN administrative_operation a ON a.id = o.approves_operation_id
         WHERE a.tenant_id IS NOT DISTINCT FROM o.tenant_id
         ORDER BY o.id COLLATE \"C\"",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        names,
        [
            ("op_ap".into(), None, "op_i".into()),
            ("op_rba".into(), Some("ten_a".into()), "op_rp".into()),
            ("op_rba2".into(), Some("ten_a".into()), "op_rp".into()),
        ]
    );

    for kind in ["approve", "route_bundle_approval"] {
        let err = fail(
            &pool,
            &insert("op_x", Some("ten_a"), "adm_2", kind, Some("op_missing")),
        )
        .await;
        assert_eq!(sqlstate(&err), "23503", "{kind}: {err}");
        assert_eq!(
            err.as_database_error().unwrap().constraint(),
            Some("administrative_operation_approves_operation_id_fkey"),
            "{kind}"
        );
    }
    db.drop([pool]).await;
}

/// Every operation names an audit event of its own tenant, compared
/// `IS NOT DISTINCT FROM`: a tenant operation naming another tenant's event
/// or an instance event, and an instance operation naming a tenant's event,
/// are refused with the audit guard's name and write nothing, whatever the
/// kind (a pending gated write, an `approve`, a `route_bundle_approval`, a
/// `cancel`, a recovery challenge). The same scope is accepted in each
/// case: an instance operation with an instance event (`tenant_id` `NULL`)
/// and a tenant operation with one of its tenant. A missing event is the
/// foreign key's `23503`, not the guard's.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn an_operation_names_an_audit_event_of_its_own_tenant() {
    let (db, pool) = seeded().await;
    let cases: [(Option<&str>, &str, Option<&str>); 6] = [
        (Some("ten_a"), "service_grant.update", None),
        (Some("ten_a"), "approve", Some("op_a")),
        (Some("ten_a"), "route_bundle_approval", Some("op_rp")),
        (Some("ten_b"), "cancel", None),
        (None, "instance_security_policy.update", None),
        (None, "approve", Some("op_i")),
    ];
    for (tenant, kind, approves) in cases {
        for (audit, case) in [
            ("evt_a", "event of ten_a"),
            ("evt_b", "event of ten_b"),
            ("evt_i", "instance event"),
        ] {
            if audit == event(tenant) {
                continue;
            }
            let err = fail(
                &pool,
                &insert_audited("op_x", tenant, kind, approves, audit),
            )
            .await;
            assert_refusal(
                err,
                Refusal::AuditOtherTenant,
                &format!("{kind} {tenant:?}: {case}"),
            );
        }
    }
    // A recovery challenge is an instance operation: a tenant's event is
    // refused, the instance event accepted.
    let challenge = |audit: &str| {
        format!(
            "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
             expected_revision, immutable_plan, challenge_hash, expires_at, outcome, audit_id) \
             VALUES ('op_ch', NULL, 'deployment_operator', 'operator_restoration', sha256('ch'), 1, \
             '{{}}', sha256('challenge'), '2026-11-20 00:05Z', 'issued', '{audit}')"
        )
    };
    let err = fail(&pool, &challenge("evt_a")).await;
    assert_refusal(err, Refusal::AuditOtherTenant, "recovery challenge");
    assert_eq!(operations(&pool).await, SEEDED);

    for (i, (tenant, kind, approves)) in cases.into_iter().enumerate() {
        run(
            &pool,
            &insert_audited(&format!("op_ok{i}"), tenant, kind, approves, event(tenant)),
        )
        .await;
    }
    run(&pool, &challenge("evt_i")).await;
    let crossed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM administrative_operation o JOIN audit_event e ON e.id = o.audit_id
         WHERE e.tenant_id IS DISTINCT FROM o.tenant_id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(crossed, 0);
    assert_eq!(
        operations(&pool).await.len(),
        SEEDED.len() + cases.len() + 1
    );

    let err = fail(
        &pool,
        &insert_audited(
            "op_x",
            Some("ten_a"),
            "service_grant.update",
            None,
            "evt_missing",
        ),
    )
    .await;
    assert_eq!(sqlstate(&err), "23503", "{err}");
    assert_eq!(
        err.as_database_error().unwrap().constraint(),
        Some("administrative_operation_audit_id_fkey")
    );
    db.drop([pool]).await;
}

/// The guards fire in name order, approval, audit, revocation, after the
/// foreign keys: a row that crosses its approved operation and its audit
/// event is the approval refusal, and a revoked row inserted with an audit
/// event and a revoking operation of another tenant is the audit refusal.
/// An `approve` that crosses its audit event only, by the approved
/// operation's actor, is the approval guard's self-approval refusal first,
/// since that guard fires first.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_guards_refuse_in_name_order() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        &insert("rev_b", Some("ten_b"), "adm_2", "reject", None),
    )
    .await;
    let err = fail(
        &pool,
        &insert_audited(
            "op_x",
            Some("ten_a"),
            "route_bundle_approval",
            Some("op_b"),
            "evt_b",
        ),
    )
    .await;
    assert_refusal(err, Refusal::ApprovesOtherTenant, "approval and audit");
    let err = fail(
        &pool,
        &format!(
            "{COLUMNS}{}",
            row_audited(
                "op_x",
                Some("ten_a"),
                "adm_1",
                "approve",
                Some("op_a"),
                "evt_b"
            )
        ),
    )
    .await;
    assert_refusal(err, Refusal::SelfApproval, "self-approval and audit");
    let err = fail(
        &pool,
        "INSERT INTO administrative_operation (id, tenant_id, actor_id, kind, request_digest, \
         expected_revision, immutable_plan, expires_at, revoked_at, revocation_operation_id, \
         outcome, audit_id) VALUES ('op_x', 'ten_a', 'adm_1', 'service_grant.update', \
         sha256('op_x'), 1, '{}', '2026-11-20 01:00Z', '2026-11-20 00:30Z', 'rev_b', 'rejected', \
         'evt_b')",
    )
    .await;
    assert_refusal(err, Refusal::AuditOtherTenant, "audit and revocation");
    db.drop([pool]).await;
}

/// In a multi-row `INSERT` the rows are checked in order, each row's
/// foreign-key check and then its guards before the next row's (migrations
/// README, "What 0005 adds", "Triggers and timing"): with a row that
/// crosses its audit event first and a row whose audit event is missing
/// second, the statement is the audit guard's `23514`; with the same two
/// rows the other way round, it is the foreign key's `23503`. Neither
/// writes anything.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn in_a_multi_row_insert_the_earlier_rows_refusal_comes_first() {
    let (db, pool) = seeded().await;
    let crossing = row_audited(
        "op_x",
        Some("ten_a"),
        "adm_2",
        "service_grant.update",
        None,
        "evt_b",
    );
    let missing = row_audited(
        "op_y",
        Some("ten_a"),
        "adm_2",
        "service_grant.update",
        None,
        "evt_missing",
    );

    let err = fail(&pool, &format!("{COLUMNS}{crossing}, {missing}")).await;
    assert_refusal(err, Refusal::AuditOtherTenant, "the crossing row first");

    let err = fail(&pool, &format!("{COLUMNS}{missing}, {crossing}")).await;
    assert_eq!(sqlstate(&err), "23503", "the missing event first: {err}");
    assert_eq!(
        err.as_database_error().unwrap().constraint(),
        Some("administrative_operation_audit_id_fkey"),
        "the missing event first"
    );

    assert_eq!(operations(&pool).await, SEEDED);
    db.drop([pool]).await;
}

/// The audit event is inserted first: `administrative_operation_audit_id_fkey`
/// is immediate, so an operation inserted before its event is the foreign
/// key's `23503`, even under `SET CONSTRAINTS ALL DEFERRED` and when the
/// transaction would insert the event next. An event inserted earlier in
/// the same transaction, uncommitted, or earlier in the same statement (a
/// data-modifying `WITH`), is seen: one of another scope is refused, one of
/// the operation's own accepted.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_audit_event_is_inserted_first_and_seen_uncommitted() {
    let (db, pool) = seeded().await;
    let mut conn = pool.acquire().await.unwrap();
    let op = |tenant: Option<&str>| {
        insert_audited("op_n", tenant, "service_grant.update", None, "evt_n")
    };
    run(&mut *conn, "BEGIN; SET CONSTRAINTS ALL DEFERRED").await;
    let err = fail(&mut *conn, &op(Some("ten_a"))).await;
    assert_eq!(sqlstate(&err), "23503", "{err}");
    assert_eq!(
        err.as_database_error().unwrap().constraint(),
        Some("administrative_operation_audit_id_fkey")
    );
    run(&mut *conn, "ROLLBACK").await;

    for (event_tenant, op_tenant, ok) in [
        (Some("ten_a"), Some("ten_a"), true),
        (None, None, true),
        (Some("ten_a"), Some("ten_b"), false),
        (Some("ten_a"), None, false),
        (None, Some("ten_a"), false),
    ] {
        let case = format!("{event_tenant:?} event, {op_tenant:?} operation");
        // Separate statements of one transaction.
        run(
            &mut *conn,
            &format!(
                "BEGIN; SELECT FROM audit_chain_head FOR UPDATE; {}",
                append_event("evt_n", event_tenant, 4)
            ),
        )
        .await;
        let result = sqlx::raw_sql(AssertSqlSafe(op(op_tenant)))
            .execute(&mut *conn)
            .await;
        match result {
            Ok(_) if ok => {}
            Err(err) if !ok => assert_refusal(err, Refusal::AuditOtherTenant, &case),
            other => panic!("{case}: {other:?}"),
        }
        run(&mut *conn, "ROLLBACK").await;

        // One statement: the event in a WITH, the operation in the main
        // statement; the head is advanced after it.
        let one = format!(
            "WITH e AS (INSERT INTO audit_event VALUES ('evt_n', {}, 4, '\\x03', \
             '2026-11-20Z', 'adm_2', 'administrative_operation.create', 'op_n', NULL, NULL, \
             'pending') RETURNING id) {}",
            literal(event_tenant),
            op(op_tenant)
        );
        run(&mut *conn, "BEGIN").await;
        let result = sqlx::raw_sql(AssertSqlSafe(one)).execute(&mut *conn).await;
        match result {
            Ok(_) if ok => {
                run(
                    &mut *conn,
                    "UPDATE audit_chain_head SET sequence = 4, head_hash = '\\x04'",
                )
                .await;
            }
            Err(err) if !ok => assert_refusal(err, Refusal::AuditOtherTenant, &case),
            other => panic!("{case}, one statement: {other:?}"),
        }
        run(&mut *conn, "ROLLBACK").await;
    }
    drop(conn);
    assert_eq!(operations(&pool).await, SEEDED);
    db.drop([pool]).await;
}

/// A revocation names a revoking operation of the revoked row's tenant,
/// both where an `UPDATE` writes it and where an `INSERT` carries it:
/// other tenant, instance to tenant and tenant to instance are refused
/// and change nothing; the same tenant and the instance by the instance
/// are accepted. The actor and the kind of the revoking operation are not
/// checked (a cancel is by the requester), and a row that also names an
/// approved operation is judged by its revoking one. A missing revoking
/// operation is the foreign key's `23503`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn a_revocation_names_an_operation_of_the_revoked_rows_tenant() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        &format!(
            "{COLUMNS}{}, {}, {}, {}",
            row("rev_i", None, "adm_1", "cancel", None),
            row("rev_a", Some("ten_a"), "adm_1", "cancel", None),
            row("rev_b", Some("ten_b"), "adm_2", "reject", None),
            row(
                "op_rba",
                Some("ten_a"),
                "adm_1",
                "route_bundle_approval",
                Some("op_rp")
            )
        ),
    )
    .await;
    // The guard reads the revoking operation, not the one the revoked row
    // approves (op_rp, of ten_a like op_rba).
    let err = fail(&pool, &revoke("op_rba", "rev_b")).await;
    assert_refusal(err, Refusal::RevokesOtherTenant, "approving row");
    for (revoked, revoker, case) in [
        ("op_a", "rev_b", "tenant by other tenant"),
        ("op_b", "rev_a", "tenant by other tenant"),
        ("op_i", "rev_a", "instance by tenant"),
        ("op_a", "rev_i", "tenant by instance"),
    ] {
        let err = fail(&pool, &revoke(revoked, revoker)).await;
        assert_refusal(err, Refusal::RevokesOtherTenant, case);
        assert_eq!(revocation(&pool, revoked).await, (None, 1), "{case}");

        let tenant = if revoked == "op_i" {
            None
        } else if revoked == "op_a" {
            Some("ten_a")
        } else {
            Some("ten_b")
        };
        let err = fail(&pool, &insert_revoked("op_x", tenant, revoker)).await;
        assert_refusal(err, Refusal::RevokesOtherTenant, case);
    }
    let err = fail(&pool, &revoke("op_a", "op_missing")).await;
    assert_eq!(sqlstate(&err), "23503", "{err}");
    assert_eq!(
        err.as_database_error().unwrap().constraint(),
        Some("administrative_operation_revocation_operation_id_fkey")
    );
    assert_eq!(operations(&pool).await.len(), SEEDED.len() + 4);

    // Accepted: by an operation of the same scope, by its own actor (rev_a
    // and op_a are both adm_1's), and carried by an insert.
    run(&pool, &revoke("op_a", "rev_a")).await;
    run(&pool, &revoke("op_i", "rev_i")).await;
    run(&pool, &revoke("op_b", "rev_b")).await;
    run(&pool, &insert_revoked("op_x_a", Some("ten_a"), "rev_a")).await;
    run(&pool, &insert_revoked("op_x_i", None, "rev_i")).await;
    for (revoked, revoker, revision) in [
        ("op_a", "rev_a", 2),
        ("op_i", "rev_i", 2),
        ("op_b", "rev_b", 2),
        ("op_x_a", "rev_a", 1),
        ("op_x_i", "rev_i", 1),
    ] {
        assert_eq!(
            revocation(&pool, revoked).await,
            (Some(revoker.to_string()), revision),
            "{revoked}"
        );
    }
    db.drop([pool]).await;
}

/// The guards are `ENABLE ALWAYS`, so replica mode does not skip them: a
/// self-approval, an approve or a `route_bundle_approval` of another
/// tenant's operation, an operation naming another tenant's audit event and
/// a revocation by another tenant's operation are still refused. Replica
/// mode skips the foreign keys, so a row whose approved or revoking
/// operation or audit event is missing is accepted (the guard finds no row
/// and passes it): the limit README "What 0005 adds" states.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn replica_mode_refuses_but_passes_a_missing_reference() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        &insert("rev_b", Some("ten_b"), "adm_2", "reject", None),
    )
    .await;
    let mut conn = pool.acquire().await.unwrap();
    for (sql, refusal) in [
        (
            approve("op_x", Some("ten_a"), "adm_1", "op_a"),
            Refusal::SelfApproval,
        ),
        (
            approve("op_x", Some("ten_b"), "adm_2", "op_a"),
            Refusal::ApprovesOtherTenant,
        ),
        (
            insert(
                "op_x",
                Some("ten_b"),
                "adm_2",
                "route_bundle_approval",
                Some("op_rp"),
            ),
            Refusal::ApprovesOtherTenant,
        ),
        (
            insert_audited("op_x", Some("ten_a"), "service_grant.update", None, "evt_b"),
            Refusal::AuditOtherTenant,
        ),
        (
            insert_audited("op_x", None, "service_grant.update", None, "evt_a"),
            Refusal::AuditOtherTenant,
        ),
        (revoke("op_a", "rev_b"), Refusal::RevokesOtherTenant),
        (
            insert_revoked("op_x", Some("ten_a"), "rev_b"),
            Refusal::RevokesOtherTenant,
        ),
    ] {
        run(
            &mut *conn,
            "BEGIN; SET LOCAL session_replication_role = replica",
        )
        .await;
        let err = fail(&mut *conn, &sql).await;
        assert_refusal(err, refusal, &sql);
        run(&mut *conn, "ROLLBACK").await;
    }

    run(
        &mut *conn,
        &format!(
            "BEGIN; SET LOCAL session_replication_role = replica; {}; {}; {}; {}",
            approve("op_x", Some("ten_a"), "adm_2", "op_missing"),
            revoke("op_a", "op_missing"),
            insert_revoked("op_y", Some("ten_a"), "op_missing"),
            insert_audited(
                "op_z",
                Some("ten_a"),
                "service_grant.update",
                None,
                "evt_missing"
            )
        ),
    )
    .await;
    let stored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM administrative_operation
         WHERE approves_operation_id = 'op_missing' OR revocation_operation_id = 'op_missing'
            OR audit_id = 'evt_missing'",
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    assert_eq!(stored, 4);
    run(&mut *conn, "ROLLBACK").await;
    drop(conn);
    db.drop([pool]).await;
}

async fn backend_pid(conn: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(conn)
        .await
        .unwrap()
}

/// Runs `sql`, which must not wait for a lock.
async fn run_promptly(conn: &mut PgConnection, sql: &str) {
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        sqlx::raw_sql(AssertSqlSafe(sql.to_string())).execute(conn),
    )
    .await
    .unwrap_or_else(|_| panic!("{sql}: waited for a lock"));
    if let Err(err) = result {
        panic!("{sql}: {err}");
    }
}

/// The guards take no row lock. An approve, a `route_bundle_approval` and
/// a revocation do not wait for the `FOR NO KEY UPDATE` lock an approver or
/// a canceller holds on the operation they read, nor for one held on the
/// audit event they name (the foreign keys' `FOR KEY SHARE` does not
/// conflict with it), and while they are uncommitted another transaction
/// still takes those rows `FOR NO KEY UPDATE NOWAIT`, which a guard
/// `FOR SHARE` read would block. Neither waits on the other, so no backend
/// is ever blocked. The audit guard does not touch the audit head: an
/// operation naming an existing event is inserted while another
/// transaction holds `audit_chain_head` `FOR UPDATE`, so the guards add no
/// step to the README lock order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_guards_take_no_row_lock() {
    let (db, pool) = seeded().await;
    run(
        &pool,
        &insert("rev_a", Some("ten_a"), "adm_2", "cancel", None),
    )
    .await;
    let mut holder = pool.acquire().await.unwrap().detach();
    let mut writer = pool.acquire().await.unwrap().detach();
    let writer_pid = backend_pid(&mut writer).await;
    let lock = "SELECT FROM administrative_operation WHERE id IN ('op_a', 'op_rp', 'rev_a') \
                FOR NO KEY UPDATE; SELECT FROM audit_event WHERE id = 'evt_a' FOR NO KEY UPDATE";
    run(&mut holder, &format!("BEGIN; {lock}")).await;
    run_promptly(
        &mut writer,
        &format!(
            "BEGIN; {}; {}; {}",
            approve("op_x", Some("ten_a"), "adm_2", "op_a"),
            insert(
                "op_rba",
                Some("ten_a"),
                "adm_2",
                "route_bundle_approval",
                Some("op_rp")
            ),
            revoke("op_a2", "rev_a")
        ),
    )
    .await;
    let blocked: Vec<i32> = sqlx::query_scalar("SELECT unnest(pg_blocking_pids($1))")
        .bind(writer_pid)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(blocked.is_empty(), "{blocked:?}");
    run(&mut holder, "ROLLBACK").await;

    // The writer's transaction is open: its guards hold nothing that
    // conflicts with FOR NO KEY UPDATE on the rows they read.
    run_promptly(
        &mut holder,
        &format!(
            "BEGIN; {}; ROLLBACK",
            lock.replace("UPDATE", "UPDATE NOWAIT")
        ),
    )
    .await;
    run(&mut writer, "COMMIT").await;
    assert_eq!(
        revocation(&pool, "op_a2").await,
        (Some("rev_a".to_string()), 2)
    );

    // The audit head held by another transaction: an operation naming an
    // existing event does not wait for it.
    run(
        &mut holder,
        "BEGIN; SELECT FROM audit_chain_head FOR UPDATE",
    )
    .await;
    run_promptly(
        &mut writer,
        &format!(
            "BEGIN; {}; ROLLBACK",
            insert("op_h", Some("ten_b"), "adm_2", "service_grant.update", None)
        ),
    )
    .await;
    run(&mut holder, "ROLLBACK").await;
    holder.close().await.unwrap();
    writer.close().await.unwrap();
    db.drop([pool]).await;
}

/// The guards read the referenced row with the writer's privileges
/// (`SECURITY INVOKER`): a role that may insert operations needs `SELECT`
/// on `audit_event`'s `id` and `tenant_id` for every insert (the audit
/// guard), on `administrative_operation`'s `id`, `tenant_id` and
/// `actor_id` to insert an `approve`, and on `id` and `tenant_id` only to
/// insert any other kind that names an approved operation (a
/// `route_bundle_approval`, say: the guard reads no `actor_id` for it) or
/// to write a revocation; otherwise `42501`. With `id` and `tenant_id` a
/// crossing by such a kind is the tenant guard's `23514`, not `42501`. An
/// operation that names no other operation needs no `SELECT` on
/// `administrative_operation`.
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_guards_read_with_the_writers_privileges() {
    let (mut db, pool) = seeded().await;
    run(
        &pool,
        &insert("rev_a", Some("ten_a"), "adm_2", "cancel", None),
    )
    .await;
    let (role, connect) = db.create_login_role().await;
    run(
        &pool,
        &format!("GRANT INSERT ON administrative_operation TO {role}"),
    )
    .await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    // Names no other operation: only the audit guard reads, audit_event.
    let plain = insert("op_x", Some("ten_a"), "adm_1", "service_grant.update", None);
    for (select, allowed) in [
        (None, false),
        (Some("SELECT (id)"), false),
        (Some("SELECT (tenant_id)"), false),
        (Some("SELECT (id, tenant_id)"), true),
    ] {
        if let Some(select) = select {
            run(
                &pool,
                &format!(
                    "REVOKE SELECT ON audit_event FROM {role};
                     GRANT {select} ON audit_event TO {role}"
                ),
            )
            .await;
        }
        let result = sqlx::raw_sql(AssertSqlSafe(format!("BEGIN; {plain}")))
            .execute(&mut writer)
            .await;
        if allowed {
            result.unwrap_or_else(|err| panic!("{select:?}: {err}"));
        } else {
            let err = result.expect_err(&plain);
            assert_eq!(sqlstate(&err), "42501", "{select:?}: {err}");
            assert_eq!(
                err.as_database_error().unwrap().message(),
                "permission denied for table audit_event"
            );
        }
        run(&mut writer, "ROLLBACK").await;
    }
    for (select, approve_ok, other_ok) in [
        (None, false, false),
        (Some("SELECT (id)"), false, false),
        (Some("SELECT (tenant_id)"), false, false),
        (Some("SELECT (id, tenant_id)"), false, true),
        (Some("SELECT (id, actor_id)"), false, false),
        (Some("SELECT (id, tenant_id, actor_id)"), true, true),
    ] {
        if let Some(select) = select {
            run(
                &pool,
                &format!(
                    "REVOKE SELECT ON administrative_operation FROM {role};
                     GRANT {select} ON administrative_operation TO {role}"
                ),
            )
            .await;
        }
        for (sql, allowed) in [
            (approve("op_x", Some("ten_a"), "adm_2", "op_a"), approve_ok),
            (
                insert(
                    "op_x",
                    Some("ten_a"),
                    "adm_1",
                    "route_bundle_approval",
                    Some("op_rp"),
                ),
                other_ok,
            ),
            (
                insert("op_x", Some("ten_a"), "adm_2", "approval", Some("op_a")),
                other_ok,
            ),
            (insert_revoked("op_x", Some("ten_a"), "rev_a"), other_ok),
        ] {
            let result = sqlx::raw_sql(AssertSqlSafe(format!("BEGIN; {sql}")))
                .execute(&mut writer)
                .await;
            if allowed {
                result.unwrap_or_else(|err| panic!("{select:?}, {sql}: {err}"));
            } else {
                let err = result.expect_err(&sql);
                assert_eq!(sqlstate(&err), "42501", "{select:?}, {sql}: {err}");
                assert_eq!(
                    err.as_database_error().unwrap().message(),
                    "permission denied for table administrative_operation"
                );
            }
            run(&mut writer, "ROLLBACK").await;
        }
        // A crossing by a kind other than approve: the tenant guard's
        // refusal once the role may read id and tenant_id.
        let crossing = insert(
            "op_x",
            Some("ten_b"),
            "adm_1",
            "route_bundle_approval",
            Some("op_rp"),
        );
        let err = sqlx::raw_sql(AssertSqlSafe(format!("BEGIN; {crossing}")))
            .execute(&mut writer)
            .await
            .expect_err(&crossing);
        if other_ok {
            assert_refusal(err, Refusal::ApprovesOtherTenant, &format!("{select:?}"));
        } else {
            assert_eq!(sqlstate(&err), "42501", "{select:?}: {err}");
        }
        run(&mut writer, "ROLLBACK").await;
    }
    drop(writer);
    db.drop([pool]).await;
}

/// The policy row's `FOR SHARE` lock (a widening trust write) needs
/// `SELECT` on `instance_security_policy` and `UPDATE` on one of its
/// columns; the prescribed grant (README "What 0005 adds", "Privileges")
/// is `UPDATE (instance_id)`, a column the `0002` guard keeps immutable:
/// with it the role takes the lock through the registry but cannot change
/// the row (`42501` for another column, `SK001` for `instance_id`).
#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn the_policy_row_lock_needs_the_prescribed_grant() {
    let (mut db, pool) = seeded().await;
    let (role, connect) = db.create_login_role().await;
    let mut writer = PgConnection::connect_with(&connect).await.unwrap();
    for (privilege, allowed) in [
        (None, false),
        (Some("SELECT"), false),
        (Some("UPDATE (instance_id)"), false),
        (Some("SELECT, UPDATE (instance_id)"), true),
    ] {
        if let Some(privilege) = privilege {
            run(
                &pool,
                &format!(
                    "REVOKE ALL ON instance_security_policy FROM {role};
                     GRANT {privilege} ON instance_security_policy TO {role}"
                ),
            )
            .await;
        }
        let mut transaction = writer.begin().await.unwrap();
        let result = registry::lock_instance_security_policy_shared(&mut transaction).await;
        transaction.rollback().await.unwrap();
        match (allowed, result) {
            (true, Ok(policy)) => assert_eq!(policy.instance_id, "inst_1"),
            (false, Err(RegistryError::Other(err))) => {
                assert_eq!(sqlstate(&err), "42501", "{privilege:?}: {err}");
            }
            (_, other) => panic!("{privilege:?}: {other:?}"),
        }
    }
    for (change, code) in [
        ("widening_second_approver = true", "42501"),
        ("instance_id = 'inst_2'", "SK001"),
    ] {
        let err = fail(
            &mut writer,
            &format!("UPDATE instance_security_policy SET {change}"),
        )
        .await;
        assert_eq!(sqlstate(&err), code, "{change}: {err}");
    }
    drop(writer);
    db.drop([pool]).await;
}
