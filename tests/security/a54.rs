//! A54: a TokenReview or projected service-account token reused before
//! rotation, then rotated; a `single_use` configuration requested.
//! Expected: reusable renewal works both times with fresh validation;
//! `single_use` enrollment or import is denied even with local keys; no
//! verified-`jti` assumption (tasks §8; T11.11, T21.6, T23.1, T23.5,
//! T23.6; ADR-016 "Alternatives considered", "Single-use for projected or
//! TokenReview tokens. Rejected"; OQ-ADR005-2).
//!
//! **A54 partial: the enrollment half of the M1a stage ("single_use
//! rejection") only; the stage stays `planned`, with no stamp.** These
//! tests are registered on A54's planned M1a stage, so they are no
//! evidence for it: the reporter lists their results as not counted, and
//! they are no claim. They run against a real PostgreSQL, one fresh
//! database per test, through two library paths with no SQL of their own;
//! the egress allowlist entries of the sources' destinations are written
//! by the shared egress fixture (`security::egress_fixture`) through the
//! audited egress allowlist writer, as the bootstrapped `adm_first`:
//!
//! - the registry floor, `registry::test_support::create_trust_source` and
//!   `update_trust_source` (crate-private in a normal build; reached here
//!   through the `test-support` feature), where the `0004` check
//!   `trust_source_single_use_replay_check` lives: `single_use` only with
//!   `on_demand_jwt` on `oidc_discovery` or `uploaded_jwks`;
//! - the gated write path of a trust source,
//!   `trust::submit_create_source` and `trust::submit_update_source`, by a
//!   `trust_admin` of the tenant, with `widening_second_approver` off
//!   (applied at once) and on (pending, then approved by a distinct
//!   instance `security_admin` through `operation::prepare_approval` and
//!   `operation::approve_operation`).
//!
//! The sources are the three A54 shapes ([`Shape`]), each a source whose
//! tokens are reused by design: a `kubernetes_token_review` source (which
//! `0004` allows only with the `projected_service_account` profile), and a
//! `projected_service_account` source on each kind that verifies with local
//! keys, `oidc_discovery` and `uploaded_jwks` (the row's "even with local
//! keys"), with `stale_revocation_acknowledged` set as IR-151 requires.
//!
//! - **Positive.** Each shape, `reusable`, is enrolled through the registry
//!   floor and through the gated create with the gate off, and reads back
//!   exactly as written at revision 1; a later update that keeps it
//!   `reusable` (a rename) is accepted at revision 2
//!   (`a54_pos_reusable_token_review_or_projected_source_is_accepted`).
//! - **Negative, create.** Each shape with `single_use`, enabled or
//!   disabled, is refused by the registry floor with
//!   `Invariant { Check, trust_source_single_use_replay_check }`, compared
//!   by variant, kind and constraint, never by message text; nothing is
//!   written (the tenant's sources read back unchanged and the ID is
//!   `NotFound`). As a control, `single_use` with `on_demand_jwt` on
//!   `oidc_discovery` and on `uploaded_jwks` is then accepted in the same
//!   tenant, so the refusal is of the shape, not of `single_use` itself.
//!   A `single_use` TokenReview source with `on_demand_jwt` or
//!   `reusable_jwt` breaks two checks, the replay check and
//!   `trust_source_token_review_profile_check`; it is refused, by either
//!   (which one the database reports is not pinned)
//!   (`a54_neg_single_use_create_on_token_review_or_projected_source_is_refused`).
//! - **Negative, update.** A stored `reusable` source of each shape
//!   updated to `single_use` (alone, and together with a disable) is
//!   refused with the same error, and the stored row keeps its revision
//!   and every column; made `single_use` with a non-projected profile, the
//!   TokenReview source is refused by either check, as on create. A stored `single_use` `on_demand_jwt` source on
//!   `oidc_discovery` or `uploaded_jwks` (the control above) updated to the
//!   `projected_service_account` profile while staying `single_use` is
//!   refused the same way, so the check holds on the profile as well as on
//!   the replay mode
//!   (`a54_neg_single_use_update_on_token_review_or_projected_source_is_refused`).
//! - **Negative, gated write, gate off.** The gated create of each shape
//!   with `single_use` (an enabled source: the gated creates send no
//!   disabled one), and the gated update of a stored `reusable` source
//!   of each shape to `single_use`, return
//!   `SourceWriteError::Registry(Invariant { Check,
//!   trust_source_single_use_replay_check })`; no source is written or
//!   changed and the audit chain has no new event, so the write's savepoint
//!   left nothing behind
//!   (`a54_neg_gated_single_use_write_is_refused_and_writes_nothing`).
//! - **Negative, gated write, gate on.** With `widening_second_approver`
//!   on, the same create (enabled sources only) and update are refused
//!   either at the request with that error, or, if the request is pending,
//!   at the approval, with `ApprovalError::Source(SourceWriteError::Registry(
//!   Invariant { Check, trust_source_single_use_replay_check }))`. Either
//!   way no source is written or changed. A refused request appends no
//!   audit event and writes no operation; a refused approval appends no
//!   event and leaves the operation pending, neither consumed nor revoked
//!   (D14). As controls, the reusable create of each shape and a reusable
//!   update (a rename) of each stored source go pending through the same
//!   flow, change nothing until approved, and are then written as
//!   requested, the update at revision 2
//!   (`a54_neg_gated_single_use_write_is_refused_by_the_second_approver_flow`).
//!   The test accepts both refusal points on purpose. Today the request
//!   pre-validates only the plainly typed checks and leaves the kind,
//!   profile and replay checks to the database (`trust::source`, "The
//!   gate"), so a `single_use` TokenReview request goes pending and is
//!   refused at its approval. That split is D27's explicit pick, accepted
//!   as an implementation choice; a later D27 extension that refuses it at
//!   the request would keep this test green.
//!
//! # Spec and registry picks
//!
//! The rule pinned here is the spec's: projected and TokenReview tokens
//! are reusable by design and are never `single_use` (ADR-016,
//! "Alternatives considered"; design §5.3; OQ-ADR005-2; tasks §8 A54,
//! "single_use enrollment/import denied even with local keys"). The shape
//! of the refusal (one `0004` check, refused by the database, whatever the
//! write path) is the registry's. `reusable_jwt` sources, which the same
//! check also keeps from `single_use`, are not A54's row and are not
//! tested here; the service tests cover them (see "Overlap").
//!
//! # Not tested here, and what stays open
//!
//! - **Import.** The row's "enrollment/import": an import path does not
//!   exist yet and is blocked on T10.5, so a `single_use` TokenReview or
//!   projected source in an import is untested; tracked under T10.5.
//! - **Renewal (A54's M2 stage, "renewal").** A reused projected token
//!   renewing with the same token and then the rotated one, each with a
//!   fresh validation and a new output `jti`, and no verified-`jti`
//!   assumption (T21.6, T23.5, T23.6): it needs the verifiers and the
//!   exchange, the TRm harness with its token-file swap on
//!   `scenarios-pg`, and the envoy-k3s legs
//!   (`scenarios-envoy-k3s/x86_64` and the nightly real kubelet rotation,
//!   `scenarios-envoy-k3s-nightly`).
//! - **Endpoints.** No admin endpoint writes a trust source yet (T13.8);
//!   the gated functions here are the library that one will call.
//! - **The second approver's own refusals** (self-approval, an expired or
//!   cancelled operation, a moved target): the service tests'
//!   (`service/tests/source_approval.rs`).
//!
//! # Overlap
//!
//! The service tests already show the check by name on the registry floor
//! for a `single_use` `uploaded_jwks` source with `reusable_jwt` and a
//! `single_use` TokenReview source (`trust_source_fields_follow_its_kind`
//! in `service/tests/registry_trust.rs`) and in SQL
//! (`service/tests/schema_trust_binding_grant.rs`). A54 adds the projected
//! shapes on both local-key kinds, the update path, the on-demand controls,
//! and the gated write path with the gate off and on.

use std::{
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::json;
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::jwk::DEFAULT_ALLOWED_ALGORITHMS;
use skyoauth_service::operation::{
    ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, Gated, OperationKind,
    PendingOperation, Submission, approve_operation, prepare_approval, submit_widening_toggle,
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, AdminRole, AssertionProfile, BootstrapRequest, ChainVerdict, InvariantKind,
        JsonObject, MAX_PAGE_SIZE, NewAdminCredential, NewAdminIdentity, NewAdminRoleBinding,
        NewTenant, NewTrustKeyset, NewTrustSource, Page, RegistryError, ReplayMode, Status,
        TrustSource, TrustSourceChanges, TrustSourceKind, bootstrap_instance,
        lock_administrative_operation, verify_audit_chain,
    },
};
use skyoauth_service::trust::{SourceWriteError, submit_create_source, submit_update_source};

use super::egress_fixture::Egress;

/// The tenant of every source.
const TENANT: &str = "ten_a";
/// The keyset of the `uploaded_jwks` sources.
const KEYSET: &str = "ks_a";
/// The constraint every refusal here names.
const SINGLE_USE_CHECK: &str = "trust_source_single_use_replay_check";

/// The canonical TokenReview endpoint of the cluster, listed by an enabled
/// `token_review` egress entry.
const TOKEN_REVIEW_ENDPOINT: &str = "https://k8s.cluster-a.example:6443/";
/// The cluster's service-account issuer, published for local verification.
const CLUSTER_ISSUER: &str = "https://oidc.cluster-a.example";
/// The canonical discovery URL of [`CLUSTER_ISSUER`], listed by an enabled
/// `oidc_discovery` egress entry.
const CLUSTER_DISCOVERY: &str = "https://oidc.cluster-a.example/.well-known/openid-configuration";
/// The issuer of the on-demand controls: an external CI.
const CI_ISSUER: &str = "https://ci.example";
/// Its canonical discovery URL.
const CI_DISCOVERY: &str = "https://ci.example/.well-known/openid-configuration";

/// The operators' keys: `adm_first` bootstraps the instance, `adm_sec` is
/// a second instance `security_admin` (the approver) and `adm_trust` the
/// `trust_admin` of [`TENANT`] (the requester).
const FIRST_KEY: &str = "spki-sha256:first";
const SEC_KEY: &str = "spki-sha256:sec";
const TRUST_KEY: &str = "spki-sha256:trust-a";

/// The fixture's clock origin, in microseconds from the Unix epoch.
const T0: u64 = 1_790_000_000_000_000;

fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(T0 + micros)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|&value| value.to_owned()).collect()
}

fn object(value: serde_json::Value) -> JsonObject {
    match value {
        serde_json::Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// The three A54 source shapes: a source whose tokens are reused by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `kubernetes_token_review` (only `projected_service_account` is
    /// allowed with it).
    TokenReview,
    /// `projected_service_account` on `oidc_discovery`: local keys from
    /// the cluster issuer's discovery document.
    ProjectedOidc,
    /// `projected_service_account` on `uploaded_jwks`: local keys from a
    /// tenant-owned keyset.
    ProjectedJwks,
}

const SHAPES: [Shape; 3] = [
    Shape::TokenReview,
    Shape::ProjectedOidc,
    Shape::ProjectedJwks,
];

impl Shape {
    fn label(self) -> &'static str {
        match self {
            Self::TokenReview => "token_review",
            Self::ProjectedOidc => "projected_oidc",
            Self::ProjectedJwks => "projected_jwks",
        }
    }

    /// A `reusable`, enabled source of this shape in [`TENANT`], with ID
    /// `src_<label>_<tag>` and name `<label>-<tag>`. Its destinations are
    /// canonical, so the gated path accepts them too.
    fn source(self, tag: &str) -> NewTrustSource {
        let base = NewTrustSource {
            id: format!("src_{}_{tag}", self.label()),
            tenant_id: TENANT.into(),
            name: format!("{}-{tag}", self.label()),
            kind: TrustSourceKind::OidcDiscovery,
            exact_issuer: CLUSTER_ISSUER.into(),
            discovery_url: None,
            jwks_keyset_id: None,
            cluster_id: None,
            token_review_endpoint: None,
            ca_bundle_ref: None,
            ca_fingerprint: None,
            reviewer_credential_ref: None,
            review_timeout_ms: None,
            audiences: strings(&["https://skyoauth.example"]),
            algorithms: None,
            proof_bounds: object(json!({"max_ttl_s": 3600})),
            assertion_profile: AssertionProfile::ProjectedServiceAccount,
            stale_revocation_acknowledged: None,
            replay_mode: ReplayMode::Reusable,
            status: Status::Enabled,
        };
        match self {
            Self::TokenReview => NewTrustSource {
                kind: TrustSourceKind::KubernetesTokenReview,
                exact_issuer: "https://kubernetes.default.svc.cluster.local".into(),
                cluster_id: Some(format!("cluster_{tag}")),
                token_review_endpoint: Some(TOKEN_REVIEW_ENDPOINT.into()),
                ca_bundle_ref: Some("cluster-a-ca".into()),
                ca_fingerprint: Some("sha256:cluster-a-ca".into()),
                reviewer_credential_ref: Some("cluster-a-reviewer".into()),
                review_timeout_ms: Some(5000),
                ..base
            },
            Self::ProjectedOidc => NewTrustSource {
                discovery_url: Some(CLUSTER_DISCOVERY.into()),
                algorithms: Some(strings(&["RS256"])),
                stale_revocation_acknowledged: Some(true),
                ..base
            },
            Self::ProjectedJwks => NewTrustSource {
                kind: TrustSourceKind::UploadedJwks,
                jwks_keyset_id: Some(KEYSET.into()),
                algorithms: Some(strings(&["ES256"])),
                stale_revocation_acknowledged: Some(true),
                ..base
            },
        }
    }

    /// [`Self::source`] with `single_use`.
    fn single_use(self, tag: &str) -> NewTrustSource {
        NewTrustSource {
            replay_mode: ReplayMode::SingleUse,
            ..self.source(tag)
        }
    }
}

/// A `single_use` `on_demand_jwt` source, the one combination the check
/// allows, on `oidc_discovery` (`uploaded` false) or `uploaded_jwks`.
fn on_demand(uploaded: bool) -> NewTrustSource {
    let base = NewTrustSource {
        id: "src_ci_discovery".into(),
        tenant_id: TENANT.into(),
        name: "ci-discovery".into(),
        kind: TrustSourceKind::OidcDiscovery,
        exact_issuer: CI_ISSUER.into(),
        discovery_url: Some(CI_DISCOVERY.into()),
        jwks_keyset_id: None,
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: strings(&["https://skyoauth.example"]),
        algorithms: Some(strings(&["RS256"])),
        proof_bounds: object(json!({"max_ttl_s": 600})),
        assertion_profile: AssertionProfile::OnDemandJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::SingleUse,
        status: Status::Enabled,
    };
    if uploaded {
        NewTrustSource {
            id: "src_ci_uploaded".into(),
            name: "ci-uploaded".into(),
            kind: TrustSourceKind::UploadedJwks,
            discovery_url: None,
            jwks_keyset_id: Some(KEYSET.into()),
            algorithms: Some(strings(&["ES256"])),
            ..base
        }
    } else {
        base
    }
}

/// `new` as stored at `revision`.
fn stored(new: &NewTrustSource, revision: i64) -> TrustSource {
    TrustSource {
        id: new.id.clone(),
        tenant_id: new.tenant_id.clone(),
        name: new.name.clone(),
        kind: new.kind,
        exact_issuer: new.exact_issuer.clone(),
        discovery_url: new.discovery_url.clone(),
        jwks_keyset_id: new.jwks_keyset_id.clone(),
        cluster_id: new.cluster_id.clone(),
        token_review_endpoint: new.token_review_endpoint.clone(),
        ca_bundle_ref: new.ca_bundle_ref.clone(),
        ca_fingerprint: new.ca_fingerprint.clone(),
        reviewer_credential_ref: new.reviewer_credential_ref.clone(),
        review_timeout_ms: new.review_timeout_ms,
        audiences: new.audiences.clone(),
        algorithms: new.algorithms.clone(),
        proof_bounds: new.proof_bounds.clone(),
        assertion_profile: new.assertion_profile,
        stale_revocation_acknowledged: new.stale_revocation_acknowledged,
        replay_mode: new.replay_mode,
        status: new.status,
        revision,
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

/// The `single_use` updates of a stored `reusable` source: the replay mode
/// alone, and together with a disable.
fn single_use_updates(source: &TrustSource) -> [(&'static str, TrustSourceChanges); 2] {
    [
        (
            "single_use",
            TrustSourceChanges {
                replay_mode: ReplayMode::SingleUse,
                ..changes(source)
            },
        ),
        (
            "single_use and disabled",
            TrustSourceChanges {
                replay_mode: ReplayMode::SingleUse,
                status: Status::Disabled,
                ..changes(source)
            },
        ),
    ]
}

/// The tenant [`TENANT`] with the keyset [`KEYSET`], the instance
/// bootstrapped by `adm_first` (the policy row with both flags off), and an
/// enabled egress entry for every destination a source here sets, written
/// by the egress fixture as `adm_first` while the gate is off.
async fn fixture() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    registry::test_support::create_tenant(
        &pool,
        &NewTenant {
            id: TENANT.into(),
            name: "Example".into(),
            secret_namespace: "ns_a".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    registry::test_support::create_trust_keyset(
        &pool,
        &NewTrustKeyset {
            id: KEYSET.into(),
            tenant_id: TENANT.into(),
            name: "cluster-keys".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    bootstrap_instance(
        &mut transaction,
        &BootstrapRequest {
            instance_id: "019a9f3c-5b2e-7c41-9d8e-0123456789ab",
            admin_id: "adm_first",
            credential_id: "crd_first",
            public_identity: FIRST_KEY,
            trust_anchor_ref: "deployment/operator-ca",
            binding_id: "rb_first",
            recovery_public_key: &[0x11; 32],
            audit_event_id: "aud_bootstrap",
            now: at(0),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    let egress = Egress::adopt(FIRST_KEY);
    for source in [
        Shape::TokenReview.source("x"),
        Shape::ProjectedOidc.source("x"),
        on_demand(false),
    ] {
        egress.allow_destinations(&pool, &source).await;
    }
    (db, pool)
}

/// One enabled operator `admin` with the credential `crd_<admin>` (`key`)
/// and one enabled binding `rb_<admin>`.
async fn operator(pool: &PgPool, admin: &str, key: &str, role: AdminRole, tenant: Option<&str>) {
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
    registry::test_support::create_admin_role_binding(
        pool,
        &NewAdminRoleBinding {
            id: format!("rb_{admin}"),
            admin_id: admin.into(),
            role,
            tenant_id: tenant.map(Into::into),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
}

/// [`fixture`] (the instance bootstrapped by `adm_first`), then `adm_sec`
/// (instance `security_admin`) and `adm_trust` (`trust_admin` of
/// [`TENANT`]). With `gate`, `widening_second_approver` is then turned on
/// through the flow, after the egress entries: `adm_first` requests it and
/// `adm_sec` approves it.
async fn gated_fixture(gate: bool) -> (TestDb, PgPool) {
    let (db, pool) = fixture().await;
    operator(&pool, "adm_sec", SEC_KEY, AdminRole::SecurityAdmin, None).await;
    operator(
        &pool,
        "adm_trust",
        TRUST_KEY,
        AdminRole::TrustAdmin,
        Some(TENANT),
    )
    .await;
    if gate {
        let mut transaction = pool.begin().await.unwrap();
        let toggle = submit_widening_toggle(
            &mut transaction,
            &Submission {
                public_identity: FIRST_KEY,
                acknowledge_widening: true,
                operation_id: "op_gate",
                event_id: "evt_op_gate",
                now: at(1),
            },
            1,
            true,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        let Gated::Pending(toggle) = toggle else {
            panic!("the toggle is not pending: {toggle:?}");
        };
        approve(&pool, ApprovalScope::Instance, &toggle, at(2))
            .await
            .unwrap();
    }
    let policy = registry::get_instance_security_policy(&pool).await.unwrap();
    assert_eq!(
        (policy.widening_second_approver, policy.single_actor_mode),
        (gate, false)
    );
    (db, pool)
}

/// The approve's clock, set by the test.
struct FixedClock(SystemTime);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// Prepares (one microsecond before `now`) and approves `pending` on
/// `scope` by `adm_sec`, with the clock at `now`, and commits the
/// transaction whatever the outcome, so a refusal also shows that the
/// approval's savepoint left nothing behind.
async fn approve(
    pool: &PgPool,
    scope: ApprovalScope<'_>,
    pending: &PendingOperation,
    now: SystemTime,
) -> Result<(), ApprovalError> {
    let op = pending.id.as_str();
    let prepared = prepare_approval(
        pool,
        SEC_KEY,
        scope,
        op,
        DEFAULT_ALLOWED_ALGORITHMS,
        now - Duration::from_micros(1),
    )
    .await?;
    let (approve_operation_id, approve_event_id, write_event_id) = (
        format!("appr_{op}"),
        format!("evt_appr_{op}"),
        format!("evt_write_{op}"),
    );
    let mut transaction = pool.begin().await.unwrap();
    let outcome = approve_operation(
        &mut transaction,
        SEC_KEY,
        scope,
        &prepared,
        &ApprovalEcho {
            request_digest: pending.request_digest,
            expected_revision: pending.expected_revision,
        },
        &ApprovalIds {
            approve_operation_id: &approve_operation_id,
            approve_event_id: &approve_event_id,
            write_event_id: &write_event_id,
        },
        &FixedClock(now),
    )
    .await;
    transaction.commit().await.unwrap();
    outcome.map(drop)
}

/// The submission of `adm_trust` as operation `op` (event `evt_<op>`) at
/// `now`, acknowledged as widening.
fn submission<'a>(op: &'a str, event: &'a str, now: SystemTime) -> Submission<'a> {
    Submission {
        public_identity: TRUST_KEY,
        acknowledge_widening: true,
        operation_id: op,
        event_id: event,
        now,
    }
}

/// The gated create of `new` by `adm_trust`, committed whatever the
/// outcome.
async fn gated_create(
    pool: &PgPool,
    op: &str,
    now: SystemTime,
    new: &NewTrustSource,
) -> Result<Gated<TrustSource>, SourceWriteError> {
    let event = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let outcome = submit_create_source(&mut transaction, &submission(op, &event, now), new).await;
    transaction.commit().await.unwrap();
    outcome
}

/// The gated update of the stored `source` to `changes` by `adm_trust`,
/// committed whatever the outcome.
async fn gated_update(
    pool: &PgPool,
    op: &str,
    now: SystemTime,
    source: &TrustSource,
    changes: &TrustSourceChanges,
) -> Result<Gated<TrustSource>, SourceWriteError> {
    let event = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let outcome = submit_update_source(
        &mut transaction,
        &submission(op, &event, now),
        &source.tenant_id,
        &source.id,
        source.revision,
        changes,
    )
    .await;
    transaction.commit().await.unwrap();
    outcome
}

/// A refusal by a constraint, as its typed fields. The `Display` text is
/// never compared.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    kind: InvariantKind,
    constraint: &'static str,
}

/// The refusal this module expects everywhere.
const SINGLE_USE_REFUSAL: Refusal = Refusal {
    kind: InvariantKind::Check,
    constraint: SINGLE_USE_CHECK,
};

#[track_caller]
fn refusal<T: Debug>(result: Result<T, RegistryError>) -> Refusal {
    match result {
        Err(RegistryError::Invariant {
            kind,
            constraint: Some(constraint),
        }) => Refusal { kind, constraint },
        other => panic!("expected RegistryError::Invariant with a constraint: {other:?}"),
    }
}

/// The `0004` check that keeps a TokenReview source to the
/// `projected_service_account` profile.
const TOKEN_REVIEW_PROFILE_CHECK: &str = "trust_source_token_review_profile_check";

/// Asserts that `refused` is a check refusal by either check that a
/// `single_use` TokenReview source with another profile breaks: the replay
/// check or the TokenReview profile check. Which one the database reports
/// is not pinned.
#[track_caller]
fn assert_single_use_or_profile_refusal(refused: &Refusal, label: &str) {
    assert!(
        refused.kind == InvariantKind::Check
            && [SINGLE_USE_CHECK, TOKEN_REVIEW_PROFILE_CHECK].contains(&refused.constraint),
        "{label}: {refused:?}"
    );
}

/// The profiles a TokenReview source may not have.
const NON_PROJECTED: [AssertionProfile; 2] =
    [AssertionProfile::OnDemandJwt, AssertionProfile::ReusableJwt];

#[track_caller]
fn source_refusal<T: Debug>(result: Result<T, SourceWriteError>) -> Refusal {
    match result {
        Err(SourceWriteError::Registry(err)) => refusal::<()>(Err(err)),
        other => panic!("expected SourceWriteError::Registry: {other:?}"),
    }
}

#[track_caller]
fn assert_not_found<T: Debug>(result: Result<T, RegistryError>) {
    assert!(
        matches!(result, Err(RegistryError::NotFound)),
        "expected NotFound: {result:?}"
    );
}

/// The tenant's trust sources, every column. Equal before and after a
/// refused write shows it wrote no source and changed none.
async fn sources(pool: &PgPool) -> Vec<TrustSource> {
    registry::list_trust_sources(pool, TENANT, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap()
}

/// The sequence of the last audit event of an intact chain.
async fn audit_head(pool: &PgPool) -> i64 {
    let mut connection = pool.acquire().await.unwrap();
    match verify_audit_chain(&mut connection).await.unwrap() {
        ChainVerdict::Intact { last_sequence } => last_sequence,
        broken => panic!("the audit chain is broken: {broken:?}"),
    }
}

/// Whether the operation `op` is still pending: neither consumed nor
/// revoked.
async fn still_pending(pool: &PgPool, op: &str) -> bool {
    let mut transaction = pool.begin().await.unwrap();
    let row = lock_administrative_operation(&mut transaction, op)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no operation {op}"));
    transaction.rollback().await.unwrap();
    row.consumed_at.is_none() && row.revoked_at.is_none()
}

#[tokio::test]
async fn a54_pos_reusable_token_review_or_projected_source_is_accepted() {
    let (db, pool) = gated_fixture(false).await;
    let mut expected = Vec::new();
    for (step, shape) in SHAPES.into_iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        // The registry floor: written and read back exactly, at revision 1.
        let floor = shape.source("floor");
        let written = registry::test_support::create_trust_source(&pool, &floor)
            .await
            .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
        assert_eq!(written, stored(&floor, 1), "{shape:?}");
        assert_eq!(
            registry::get_trust_source(&pool, TENANT, &floor.id)
                .await
                .unwrap(),
            written,
            "{shape:?}"
        );
        // A later update that keeps it reusable: accepted, revision 2.
        let renamed = TrustSourceChanges {
            name: format!("{}-renamed", floor.name),
            ..changes(&written)
        };
        let updated =
            registry::test_support::update_trust_source(&pool, TENANT, &floor.id, 1, &renamed)
                .await
                .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
        let renamed_source = NewTrustSource {
            name: renamed.name.clone(),
            ..floor
        };
        assert_eq!(updated, stored(&renamed_source, 2), "{shape:?}");
        expected.push(updated);

        // The gated create, gate off: applied at once, as requested.
        let gated = shape.source("gated");
        let outcome = gated_create(&pool, &format!("op_pos_{step}"), at(10 + step), &gated)
            .await
            .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
        let Gated::Applied(row) = outcome else {
            panic!("{shape:?}: the create is not applied: {outcome:?}");
        };
        assert_eq!(row, stored(&gated, 1), "{shape:?}");
        assert_eq!(
            registry::get_trust_source(&pool, TENANT, &gated.id)
                .await
                .unwrap(),
            row,
            "{shape:?}"
        );
        expected.push(row);
    }
    expected.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(sources(&pool).await, expected);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a54_neg_single_use_create_on_token_review_or_projected_source_is_refused() {
    let (db, pool) = fixture().await;
    let before = sources(&pool).await;
    for shape in SHAPES {
        for status in [Status::Enabled, Status::Disabled] {
            let new = NewTrustSource {
                status,
                ..shape.single_use("su")
            };
            assert_eq!(
                refusal(registry::test_support::create_trust_source(&pool, &new).await),
                SINGLE_USE_REFUSAL,
                "{shape:?}, {status:?}"
            );
            assert_not_found(registry::get_trust_source(&pool, TENANT, &new.id).await);
            assert_eq!(sources(&pool).await, before, "{shape:?}, {status:?}");
        }
    }

    // A single_use TokenReview source with a profile other than
    // projected_service_account (on_demand_jwt included, the one profile
    // the replay check would allow on a local-key kind): refused, by the
    // replay check or by the TokenReview profile check.
    for profile in NON_PROJECTED {
        let new = NewTrustSource {
            assertion_profile: profile,
            ..Shape::TokenReview.single_use("np")
        };
        let label = format!("TokenReview, {profile:?}");
        assert_single_use_or_profile_refusal(
            &refusal(registry::test_support::create_trust_source(&pool, &new).await),
            &label,
        );
        assert_not_found(registry::get_trust_source(&pool, TENANT, &new.id).await);
        assert_eq!(sources(&pool).await, before, "{label}");
    }

    // The control: `single_use` with `on_demand_jwt` on the two local-key
    // kinds is accepted in the same tenant, so the refusal above is of the
    // shape, not of `single_use`.
    let mut expected = before;
    for uploaded in [false, true] {
        let control = on_demand(uploaded);
        let written = registry::test_support::create_trust_source(&pool, &control)
            .await
            .unwrap_or_else(|err| panic!("uploaded {uploaded}: {err:?}"));
        assert_eq!(written, stored(&control, 1), "uploaded {uploaded}");
        expected.push(written);
    }
    expected.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(sources(&pool).await, expected);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a54_neg_single_use_update_on_token_review_or_projected_source_is_refused() {
    let (db, pool) = fixture().await;
    for shape in SHAPES {
        registry::test_support::create_trust_source(&pool, &shape.source("upd"))
            .await
            .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
    }
    for uploaded in [false, true] {
        registry::test_support::create_trust_source(&pool, &on_demand(uploaded))
            .await
            .unwrap_or_else(|err| panic!("uploaded {uploaded}: {err:?}"));
    }
    let before = sources(&pool).await;

    // A stored reusable source of each shape made single_use.
    for shape in SHAPES {
        let source = stored(&shape.source("upd"), 1);
        for (label, update) in single_use_updates(&source) {
            assert_eq!(
                refusal(
                    registry::test_support::update_trust_source(
                        &pool,
                        TENANT,
                        &source.id,
                        source.revision,
                        &update,
                    )
                    .await
                ),
                SINGLE_USE_REFUSAL,
                "{shape:?}, {label}"
            );
            assert_eq!(sources(&pool).await, before, "{shape:?}, {label}");
        }
    }

    // The stored TokenReview source made single_use with a profile other
    // than projected_service_account: refused by either check.
    let source = stored(&Shape::TokenReview.source("upd"), 1);
    for profile in NON_PROJECTED {
        let update = TrustSourceChanges {
            assertion_profile: profile,
            replay_mode: ReplayMode::SingleUse,
            ..changes(&source)
        };
        let label = format!("TokenReview, {profile:?}");
        assert_single_use_or_profile_refusal(
            &refusal(
                registry::test_support::update_trust_source(
                    &pool,
                    TENANT,
                    &source.id,
                    source.revision,
                    &update,
                )
                .await,
            ),
            &label,
        );
        assert_eq!(sources(&pool).await, before, "{label}");
    }

    // A stored single_use on-demand source made projected while staying
    // single_use.
    for uploaded in [false, true] {
        let source = stored(&on_demand(uploaded), 1);
        let projected = TrustSourceChanges {
            assertion_profile: AssertionProfile::ProjectedServiceAccount,
            stale_revocation_acknowledged: Some(true),
            ..changes(&source)
        };
        assert_eq!(
            refusal(
                registry::test_support::update_trust_source(
                    &pool,
                    TENANT,
                    &source.id,
                    source.revision,
                    &projected,
                )
                .await
            ),
            SINGLE_USE_REFUSAL,
            "uploaded {uploaded}"
        );
        assert_eq!(sources(&pool).await, before, "uploaded {uploaded}");
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a54_neg_gated_single_use_write_is_refused_and_writes_nothing() {
    let (db, pool) = gated_fixture(false).await;
    let mut stored_sources = Vec::new();
    for shape in SHAPES {
        let source = shape.source("stored");
        stored_sources.push((
            shape,
            registry::test_support::create_trust_source(&pool, &source)
                .await
                .unwrap_or_else(|err| panic!("{shape:?}: {err:?}")),
        ));
    }
    let before = sources(&pool).await;
    let head = audit_head(&pool).await;

    for (step, shape) in SHAPES.into_iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        let new = shape.single_use("gated");
        assert_eq!(
            source_refusal(gated_create(&pool, &format!("op_c{step}"), at(10 + step), &new).await),
            SINGLE_USE_REFUSAL,
            "{shape:?}"
        );
        assert_not_found(registry::get_trust_source(&pool, TENANT, &new.id).await);
        assert_eq!(sources(&pool).await, before, "{shape:?}");
        assert_eq!(audit_head(&pool).await, head, "{shape:?}");
    }
    for (step, (shape, source)) in stored_sources.iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        for (label, update) in single_use_updates(source) {
            assert_eq!(
                source_refusal(
                    gated_update(
                        &pool,
                        &format!("op_u{step}"),
                        at(20 + step),
                        source,
                        &update
                    )
                    .await
                ),
                SINGLE_USE_REFUSAL,
                "{shape:?}, {label}"
            );
            assert_eq!(sources(&pool).await, before, "{shape:?}, {label}");
            assert_eq!(audit_head(&pool).await, head, "{shape:?}, {label}");
        }
    }
    db.drop([pool]).await;
}

/// The outcome of a `single_use` write `op` through the gate on, whose
/// request was made when the audit chain's head was `head_before`: refused
/// at the request, or pending and then refused at the approval. Either way
/// it returns the refusal. A refused request must have appended no event
/// and written no operation; a refused approval must have appended no
/// event and left the operation pending (D14).
async fn refused_through_the_gate(
    pool: &PgPool,
    label: &str,
    (op, head_before): (&str, i64),
    outcome: Result<Gated<TrustSource>, SourceWriteError>,
    kind: OperationKind,
    approve_at: SystemTime,
) -> Refusal {
    match outcome {
        Err(err) => {
            assert_eq!(audit_head(pool).await, head_before, "{label}");
            let mut transaction = pool.begin().await.unwrap();
            let row = lock_administrative_operation(&mut transaction, op)
                .await
                .unwrap();
            transaction.rollback().await.unwrap();
            assert!(row.is_none(), "{label}: a refused request wrote {row:?}");
            source_refusal::<()>(Err(err))
        }
        Ok(Gated::Pending(pending)) => {
            assert_eq!(pending.kind, kind, "{label}");
            let head = audit_head(pool).await;
            let refused =
                match approve(pool, ApprovalScope::Tenant(TENANT), &pending, approve_at).await {
                    Err(ApprovalError::Source(err)) => source_refusal::<()>(Err(err)),
                    other => panic!("{label}: expected ApprovalError::Source: {other:?}"),
                };
            assert!(still_pending(pool, &pending.id).await, "{label}");
            assert_eq!(audit_head(pool).await, head, "{label}");
            refused
        }
        Ok(applied) => panic!("{label}: the write was applied: {applied:?}"),
    }
}

#[tokio::test]
async fn a54_neg_gated_single_use_write_is_refused_by_the_second_approver_flow() {
    let (db, pool) = gated_fixture(true).await;
    let mut stored_sources = Vec::new();
    for shape in SHAPES {
        stored_sources.push((
            shape,
            registry::test_support::create_trust_source(&pool, &shape.source("stored"))
                .await
                .unwrap_or_else(|err| panic!("{shape:?}: {err:?}")),
        ));
    }
    let before = sources(&pool).await;

    for (step, shape) in SHAPES.into_iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        let new = shape.single_use("gated");
        let label = format!("{shape:?} create");
        let op = format!("op_c{step}");
        let head_before = audit_head(&pool).await;
        let outcome = gated_create(&pool, &op, at(10 + step), &new).await;
        assert_eq!(
            refused_through_the_gate(
                &pool,
                &label,
                (&op, head_before),
                outcome,
                OperationKind::TrustSourceCreate,
                at(100 + step),
            )
            .await,
            SINGLE_USE_REFUSAL,
            "{label}"
        );
        assert_not_found(registry::get_trust_source(&pool, TENANT, &new.id).await);
        assert_eq!(sources(&pool).await, before, "{label}");
    }
    for (step, (shape, source)) in stored_sources.iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        for (index, (what, update)) in single_use_updates(source).into_iter().enumerate() {
            let index = u64::try_from(index).unwrap();
            let label = format!("{shape:?} update to {what}");
            let n = 2 * step + index;
            let op = format!("op_u{n}");
            let head_before = audit_head(&pool).await;
            let outcome = gated_update(&pool, &op, at(20 + n), source, &update).await;
            assert_eq!(
                refused_through_the_gate(
                    &pool,
                    &label,
                    (&op, head_before),
                    outcome,
                    OperationKind::TrustSourceUpdate,
                    at(200 + n),
                )
                .await,
                SINGLE_USE_REFUSAL,
                "{label}"
            );
            assert_eq!(sources(&pool).await, before, "{label}");
        }
    }

    // The control: the reusable create of each shape goes through the same
    // flow, pending and then approved, and is written as requested.
    let mut expected = before;
    for (step, shape) in SHAPES.into_iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        let new = shape.source("approved");
        let outcome = gated_create(&pool, &format!("op_r{step}"), at(30 + step), &new)
            .await
            .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
        let Gated::Pending(pending) = outcome else {
            panic!("{shape:?}: the reusable create is not pending: {outcome:?}");
        };
        assert_not_found(registry::get_trust_source(&pool, TENANT, &new.id).await);
        approve(
            &pool,
            ApprovalScope::Tenant(TENANT),
            &pending,
            at(300 + step),
        )
        .await
        .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
        let written = registry::get_trust_source(&pool, TENANT, &new.id)
            .await
            .unwrap();
        assert_eq!(written, stored(&new, 1), "{shape:?}");
        expected.push(written);
    }

    // The control of the updates: a reusable update of each stored source
    // (a rename) goes pending, changes nothing until it is approved, and is
    // then written at revision 2.
    for (step, (shape, source)) in stored_sources.iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        let renamed = TrustSourceChanges {
            name: format!("{}-renamed", source.name),
            ..changes(source)
        };
        let outcome = gated_update(
            &pool,
            &format!("op_ru{step}"),
            at(40 + step),
            source,
            &renamed,
        )
        .await
        .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
        let Gated::Pending(pending) = outcome else {
            panic!("{shape:?}: the reusable update is not pending: {outcome:?}");
        };
        assert_eq!(pending.kind, OperationKind::TrustSourceUpdate, "{shape:?}");
        assert_eq!(
            registry::get_trust_source(&pool, TENANT, &source.id)
                .await
                .unwrap(),
            *source,
            "{shape:?}"
        );
        approve(
            &pool,
            ApprovalScope::Tenant(TENANT),
            &pending,
            at(400 + step),
        )
        .await
        .unwrap_or_else(|err| panic!("{shape:?}: {err:?}"));
        let written = registry::get_trust_source(&pool, TENANT, &source.id)
            .await
            .unwrap();
        assert_eq!(
            written,
            TrustSource {
                name: renamed.name.clone(),
                revision: 2,
                ..source.clone()
            },
            "{shape:?}"
        );
        let slot = expected
            .iter_mut()
            .find(|row| row.id == source.id)
            .unwrap_or_else(|| panic!("{shape:?}: not listed"));
        *slot = written;
    }
    expected.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(sources(&pool).await, expected);
    db.drop([pool]).await;
}
