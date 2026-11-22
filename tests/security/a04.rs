//! A04: public keyset overlapping rotation. Expected: parent, source,
//! binding and grant IDs stable; explicit old and new validity windows
//! (tasks §8; T11.3, T11.6, T11.9, T24.2; ADR-005 items 1 and 5; design
//! §5.4; tasks §3 "Verifier union").
//!
//! **A04 partial: the registry-level keyset lifecycle only; A04 M1a stays
//! planned (scope "keyset lifecycle").** These tests are registered on
//! A04's planned M1a stage, so they are no evidence for it: the reporter
//! lists their results as not counted, and they are no claim. They run
//! through the typed registry API (`skyoauth_service::persistence::registry`:
//! the trust keyset and keyset version writes and reads, and the reads of
//! the source, binding and grant that hang off a keyset) against a real
//! PostgreSQL, one fresh database per test (per round in the replica
//! tests), with no SQL of their own. The fixture is local ([`fixture`]):
//! tenants `ten_a` and `ten_b`, each with a workload, a keyset `ks_<t>`
//! with one enabled version `kv_old_<t>` (window `T0` to `T2`), a second
//! keyset `ks_other_<t>` with a version of its own, an `uploaded_jwks`
//! source on `ks_<t>`, a `generic_production` binding on that source, and a
//! direct grant with that binding. A rotation is what the registry offers
//! for it: a new version of the same keyset, uploaded with its own explicit
//! window, and status changes of versions, each a compare-and-set on the
//! version's own revision ([`registry::update_trust_keyset_version`]).
//!
//! - **Positive, overlap.** In each tenant, a new version `kv_new_<t>` is
//!   uploaded disabled with a window from `T1` to `T3` that overlaps the old
//!   one, then enabled; both versions are then enabled at once and listed
//!   per keyset in byte-wise ID order, which here is not the order of their
//!   windows. The old version is then disabled, an open-ended version
//!   `kv_next_<t>` (from `T2`) is uploaded enabled, and the parent keyset
//!   is disabled and re-enabled. Every version reads back exactly as
//!   uploaded (JWK Set, fingerprint, provenance, both window bounds to the
//!   microsecond) but for its status and its own revision, each status
//!   change advances only that version's revision by one, and the parent,
//!   the source (still naming the parent), the binding and the grant keep
//!   their IDs, every column and their revisions; only the parent's own
//!   update moves the parent's revision, and it changes no version. The
//!   other keyset and the other tenant are unchanged
//!   (`a04_pos_rotation_overlaps_versions_and_keeps_every_id`). Eight
//!   replicas (REP, `skyoauth_scenarios::rep`) that each upload a version
//!   with its own overlapping window under one keyset at once all succeed:
//!   a version has no pointer from its parent to contend for, and the
//!   parent and the records on it are unchanged, in 3 fresh databases
//!   (`a04_pos_concurrent_uploads_add_overlapping_versions_under_one_parent`).
//! - **Negative, windows.** A version whose window is empty or inverted is
//!   refused with one typed error, `Invariant { Check,
//!   trust_keyset_version_validity_check }`, compared by variant, kind and
//!   constraint, never by message text: an expiry equal to the start, one
//!   microsecond or more before it, and one 999 nanoseconds after it, which
//!   is empty once both bounds are truncated to whole microseconds; enabled
//!   or disabled, in both tenants. Each refusal writes nothing. The
//!   shortest window, one microsecond, a start with nanoseconds that
//!   truncate onto the same bounds, and an open-ended window are stored, as
//!   truncated (`a04_neg_empty_or_inverted_windows_are_refused`).
//! - **Negative, stale or foreign steps.** A status change at any revision
//!   but the version's current one (the parent's revision included, once
//!   the two differ, and a replay of an applied step) is `StaleRevision`; a
//!   step, read or list by the other tenant is `NotFound` or empty, whatever
//!   the revision, the current one included; a version uploaded under the
//!   other tenant's keyset or a missing one is refused by
//!   `trust_keyset_version_keyset_id_fkey`, and one that reuses an existing
//!   version ID, the other tenant's included, by `trust_keyset_version_pkey`
//!   (`AlreadyExists`). Each refusal writes nothing, in both directions
//!   (`a04_neg_stale_or_foreign_rotation_steps_change_nothing`).
//! - **Negative, concurrency.** Of 8 replicas that change one version's
//!   status at once from its current revision, half to `disabled` and half
//!   to `enabled`, exactly one succeeds and 7 get `StaleRevision`; of 8 that
//!   upload one version ID at once, each with its own window and
//!   fingerprint, exactly one succeeds and 7 get `AlreadyExists` with
//!   `trust_keyset_version_pkey`. The stored version is the winner's, and
//!   the parent, source, binding and grant are unchanged, in 3 fresh
//!   databases (`a04_neg_concurrent_rotation_steps_have_one_winner`). Four
//!   replicas seen blocked ([`rep::wait_until_blocked`]) behind a holder's
//!   uncommitted status change of the same version, or upload of the same
//!   version ID, all get `StaleRevision` or `AlreadyExists` after its
//!   commit, and exactly one of them succeeds after its rollback
//!   (`a04_neg_blocked_rotation_steps_follow_the_holder_commit_or_rollback`).
//!
//! # Spec and registry picks
//!
//! The spec's rules these tests pin at the registry: a stable tenant-owned
//! `TrustKeyset` parent whose `TrustKeysetVersion` rows carry public keys
//! with explicit validity, several of them active at once (ADR-005 items 1
//! and 5; design §5.4; tasks §3 "Verifier union"); rotation and disable
//! keep the parent, source, binding and grant IDs (T11.6, T24.2; ADR-005
//! item 5); versions reference their parent, which holds no
//! current-version pointer, so overlapping versions create no circular
//! reference (T11.9; `0004`); and tenant ownership (T11.9; IR-031). Tasks
//! §3 "Ownership" speaks of "their immutable versions", yet a version's
//! `status` is mutable (`0004` exempts it from the immutability guard);
//! that disable needs a mutable status is inferred from T11.6, not stated.
//!
//! These are the registry's behaviour, not the spec's, where the spec does
//! not define them: that `status` is a version's one mutable column, changed
//! by a compare-and-set on the version's own revision with no tie to the
//! parent's (`0004` "inferred"; `0007` and the lead decision of
//! 2026-11-21); that times are stored truncated to whole microseconds,
//! before the window check (inferred, registry "Timestamps"); that a
//! version list is per keyset, in byte-wise ID order; that re-enabling a
//! version is a plain status change (`persistence::registry` module docs,
//! which name a tenant, a principal or a keyset version: provisional lead
//! pick, 2026-11-21), and the same for a keyset (inferred; at the service
//! layer, re-enabling a version is subject to
//! `skyoauth_service::jwk::check_version_overlap`); and that a disabled
//! parent leaves its versions' rows unchanged. The registry reads no clock:
//! it stores windows as given and compares none with the current time, so
//! these tests use fixed times and pass whatever the date.
//!
//! Also registry picks, not the spec's (T11.6, T24.2 and ADR-005 item 5
//! require stable IDs, not stable revisions): that a version write leaves
//! the parent's revision unchanged (the lineage checks of the rotation, the
//! concurrent uploads, the concurrent steps and the blocked steps), and
//! that concurrent uploads under one parent never contend. The
//! `skyoauth_service::jwk` module docs ("Follow-ups") tell the wiring PR to
//! serialize the writes of one keyset, by locking the parent row or
//! advancing its revision; wiring that advances the parent's revision
//! inside the registry write would turn these checks red, and they should
//! then follow it.
//!
//! **Open, provisional.** Points no spec settles:
//!
//! - The non-empty window rule (`expires_at > effective_at`) exists only as
//!   the `0004` check `trust_keyset_version_validity_check`, in no spec;
//!   the window negative pins that check as it stands.
//! - Whether adding a keyset version is a widening change that needs
//!   review: OQ-ADR008-3's original question names "a new keyset version"
//!   among its examples, and its decision (the server detects widening;
//!   ADR-008 item 12) does not classify it.
//! - Tasks §3 marks `expires_at` optional (`expires_at?`), while T24.2 asks
//!   for "explicit validity windows" and ADR-005 item 5 for "explicit
//!   validity": a tension inside the spec. The registry follows tasks §3
//!   and stores an open-ended window, which the positive uploads.
//!
//! # Not expressible in the registry, so not tested
//!
//! - **Validity in and outside a window.** The row's negative, "each key
//!   outside its window", and the positive's "valid in the overlap" are
//!   decisions of the verifier at a time, with a clock, about the keys of
//!   the enabled versions whose windows contain it. The registry decides
//!   neither: it stores the windows and the statuses, and nothing here
//!   claims a key valid or invalid. Whether a disabled parent, a window not
//!   yet started or one already ended stops verification is untested
//!   either way. The building block exists but is unwired:
//!   `skyoauth_service::jwk::live_keys` and `KeysetVersion::is_live`, with
//!   the half-open window `[effective_at, expires_at)`; nothing calls them.
//! - **Conflicting live kids and key checks.** The registry does not
//!   compare the kids or keys of overlapping versions, nor algorithms,
//!   strength or size (`0004_trust_binding_grant.sql`, the `public_jwks`
//!   comment: "Algorithms, sizes and kid uniqueness are the service's
//!   checks"; the migrations README leaves the service to "check JWK
//!   algorithms, key sizes, `kid` conflicts and fingerprints of an upload
//!   (T11.3)"), so a conflicting live kid has no registry test either way.
//!   The building blocks exist but are unwired:
//!   `skyoauth_service::jwk::parse_jwk_set` and `check_version_overlap`,
//!   to run "wherever a version becomes enabled"; nothing calls them.
//!   Private and symmetric key members are refused by
//!   `trust_keyset_version_public_jwks_check`, which is A05's upload
//!   rejection and the service tests', not A04's lifecycle.
//!
//! **Missing, so not a claim.** A04 M1a needs its keyset lifecycle through
//! the in-process service (UC); these tests reach only the registry. Still
//! needed, and not claimed here, with the owner of each part:
//!
//! - **Not claimed:** the verifier's window decision at token time: each
//!   key valid in its window, the old and the new key both valid in the
//!   overlap, each key refused outside its window and a disabled version's
//!   key refused, against an injected clock (T11.3 "explicit overlap",
//!   T24.2 "explicit validity windows"). Its place in M1a is inferred and
//!   provisional: T24.2 is an M2 task. `skyoauth_service::jwk::live_keys`
//!   is the unwired building block.
//! - **Not claimed:** the live kid conflict: a unique, nonconflicting kid
//!   across overlapping versions, and the algorithm, strength and size
//!   checks of an upload (T11.3; the conflicting kid is also in A05's M2
//!   negative, T24.3). `skyoauth_service::jwk::parse_jwk_set` and
//!   `check_version_overlap` are the unwired building blocks.
//! - **Not claimed:** the audited trust_admin keyset endpoints for rotation
//!   and disable (T13.8 provisioning, T13.2 roles), writing the version and
//!   its audit event atomically, with the expected revision (T11.6;
//!   IR-052), and the server's widening detection with its explicit flag
//!   for a new or re-enabled version (ADR-008 item 12; OQ-ADR008-3, open
//!   for a keyset version, see above). The registry writes no event and
//!   does not tell widening from narrowing.
//!
//! Open owner question, not claimed either: that the rotation is
//! independent of human-provider changes (T11.6's last clause). Human
//! providers are M1b records with no tables yet, and A04 has no M1b stage
//! and a PG+UC harness, so which stage or scenario owns it is undecided.
//!
//! Not A04 M1a's, with their owners: the exchange through the overlap, an
//! issued token from a key of the old and of the new version with the same
//! grant and binding, is A04's M2 stage, "exchange through the overlap"
//! (T24.2 with the exchange of T21.x); the survival of keyset IDs across a
//! migration is A15's (M5; T51.2, T51.6), and contract C05 is covered by
//! A15 and A04 (layout Q11); upload rejection (private members, `jku`,
//! `x5u`) is A05.
//!
//! # Overlap
//!
//! A29 (`tests/security/a29.rs`, implemented) already pins that a version
//! under another tenant's keyset and a source on another tenant's keyset
//! are refused by their composite foreign keys; A04 uses the first only as
//! one of the foreign rotation steps. The service tests cover, without
//! replicas and outside a lifecycle: keyset and version create, read,
//! per-keyset list and their constraints, an empty window by
//! `trust_keyset_version_validity_check`, an open-ended and a pre-epoch
//! window, nanosecond truncation (`keysets_are_tenant_local_and_update_by_revision`,
//! `keyset_versions_are_created_read_and_listed_per_keyset` in
//! `service/tests/registry_trust.rs`); a version's status changing by its
//! own revision, unchanged other columns, stale and other-tenant updates,
//! one blocked updater behind an uncommitted one, a race of status updates
//! from one revision with one winner, and a rollback with the caller's
//! transaction (`keyset_versions_change_only_status_by_their_own_revision`,
//! and the `Target::Version` cases of
//! `concurrent_updates_from_one_revision_have_exactly_one_winner` and
//! `updates_roll_back_with_the_callers_transaction` in
//! `service/tests/registry_updates.rs`); and in SQL, the immutability guard
//! on every column but `status`
//! (`service/tests/schema_trust_binding_grant.rs`).
//! This module adds the lifecycle with its parent, source, binding, grant
//! and sibling keyset, both tenants, the sub-microsecond window, the upload
//! race on one version ID, the blocked steps' holder-rollback branch, and
//! eight replicas with separate pools.

use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use skyoauth_scenarios::{
    pg::TestDb,
    rep::{self, Replicas},
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, ActivationState, AssertionProfile, BindingProfile, GrantMode, InvariantKind,
        JsonObject, MAX_PAGE_SIZE, NewPrincipal, NewPrincipalBinding, NewServiceGrant, NewTenant,
        NewTrustKeyset, NewTrustKeysetVersion, NewTrustSource, Page, PrincipalBinding,
        PrincipalKind, RegistryError, ReplayMode, ServiceGrant, Status, TrustKeyset,
        TrustKeysetChanges, TrustKeysetVersion, TrustSource, TrustSourceKind,
    },
};
use sqlx::{Connection, PgConnection};

/// The issuer of every source: an external CI with uploaded keys.
const PARTNER_ISSUER: &str = "https://ci.partner.example";

/// The window bounds, in microseconds from the Unix epoch, in increasing
/// order. Each has a microsecond part, so a bound that lost its
/// microseconds would show. `T0` to `T2` is the old version's window, `T1`
/// to `T3` the new one's, so the two overlap from `T1` to `T2`.
const T0: u64 = 1_767_225_600_000_001;
const T1: u64 = 1_782_864_000_123_457;
const T2: u64 = 1_798_761_600_000_002;
const T3: u64 = 1_814_400_000_999_999;

fn at(micros: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_micros(micros)
}

/// One of the two tenants. Every ID carries the tenant's suffix, because
/// IDs are global.
#[derive(Clone, Copy, Debug)]
struct Side {
    tenant: &'static str,
    suffix: &'static str,
}

const A: Side = Side {
    tenant: "ten_a",
    suffix: "a",
};
const B: Side = Side {
    tenant: "ten_b",
    suffix: "b",
};

/// (owner, intruder): the intruder's step names the owner's keyset or
/// version.
const DIRECTIONS: [(Side, Side); 2] = [(A, B), (B, A)];

impl Side {
    fn id(self, base: &str) -> String {
        format!("{base}_{}", self.suffix)
    }
    fn workload(self) -> String {
        self.id("wld")
    }
    /// The rotated keyset, the parent of [`Side::source`].
    fn keyset(self) -> String {
        self.id("ks")
    }
    /// A second keyset of the tenant, which no rotation touches.
    fn other_keyset(self) -> String {
        self.id("ks_other")
    }
    fn source(self) -> String {
        self.id("src")
    }
    fn binding(self) -> String {
        self.id("bnd")
    }
    fn grant(self) -> String {
        self.id("grt")
    }
    /// The version the fixture uploads: enabled, window `T0` to `T2`.
    fn old(self) -> NewTrustKeysetVersion {
        version(self, "kv_old", &self.keyset(), "old", T0, Some(at(T2)))
    }
    /// The overlapping version, staged disabled: window `T1` to `T3`. Its
    /// ID sorts before [`Side::old`]'s, its window after.
    fn incoming(self) -> NewTrustKeysetVersion {
        NewTrustKeysetVersion {
            status: Status::Disabled,
            ..version(self, "kv_new", &self.keyset(), "new", T1, Some(at(T3)))
        }
    }
    /// The open-ended version after [`Side::incoming`], enabled: from `T2`.
    fn next(self) -> NewTrustKeysetVersion {
        version(self, "kv_next", &self.keyset(), "next", T2, None)
    }
    /// The version of [`Side::other_keyset`].
    fn other(self) -> NewTrustKeysetVersion {
        version(self, "kv_other", &self.other_keyset(), "other", T0, None)
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not a JSON object: {other}"),
    }
}

/// A P-256 coordinate (`axis` `x` or `y`) of the key with `kid`: 32
/// bytes derived deterministically from both, base64url without padding
/// (43 characters), so each kid has its own key. The bytes are FNV-1a of
/// `<axis>:<kid>` expanded by SplitMix64, with no new dependency. They are
/// well-formed but not a point on the curve: the registry stores a JWK Set
/// without checking its keys (only the `0004`
/// `trust_keyset_version_public_jwks_check` against private members), no
/// curve check exists yet, and no test here verifies a signature.
fn coordinate(axis: &str, kid: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut state = format!("{axis}:{kid}")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    let bytes: Vec<u8> = (0..4)
        .flat_map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (z ^ (z >> 31)).to_be_bytes()
        })
        .collect();
    let mut out = String::with_capacity(43);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// An enabled version `<base>_<t>` of `keyset` holding one public EC key
/// with the kid `<label>-<t>` and coordinates from [`coordinate`], from
/// `effective_micros` to `expires_at`.
fn version(
    side: Side,
    base: &str,
    keyset: &str,
    label: &str,
    effective_micros: u64,
    expires_at: Option<SystemTime>,
) -> NewTrustKeysetVersion {
    let kid = format!("{label}-{}", side.suffix);
    NewTrustKeysetVersion {
        id: side.id(base),
        tenant_id: side.tenant.into(),
        keyset_id: keyset.into(),
        public_jwks: object(json!({
            "keys": [{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
                      "kid": kid, "x": coordinate("x", &kid), "y": coordinate("y", &kid)}]
        })),
        fingerprint: format!("sha256:{kid}"),
        effective_at: at(effective_micros),
        expires_at,
        status: Status::Enabled,
        provenance: object(json!({"uploaded_by": "adm_trust", "file": format!("{kid}.jwks.json")})),
    }
}

/// The stored row of `new` at `status` and `revision`, with its times as
/// given: every time a test compares this with is a whole microsecond.
fn stored(new: &NewTrustKeysetVersion, status: Status, revision: i64) -> TrustKeysetVersion {
    TrustKeysetVersion {
        id: new.id.clone(),
        tenant_id: new.tenant_id.clone(),
        keyset_id: new.keyset_id.clone(),
        public_jwks: new.public_jwks.clone(),
        fingerprint: new.fingerprint.clone(),
        effective_at: new.effective_at,
        expires_at: new.expires_at,
        status,
        provenance: new.provenance.clone(),
        revision,
    }
}

fn tenant(side: Side) -> NewTenant {
    NewTenant {
        id: side.tenant.into(),
        name: "Example".into(),
        secret_namespace: side.id("ns"),
        status: Status::Enabled,
    }
}

fn keyset(side: Side, id: String, name: &str) -> NewTrustKeyset {
    NewTrustKeyset {
        id,
        tenant_id: side.tenant.into(),
        name: name.into(),
        status: Status::Enabled,
    }
}

/// The `uploaded_jwks` source on [`Side::keyset`].
fn uploaded_source(side: Side) -> NewTrustSource {
    NewTrustSource {
        id: side.source(),
        tenant_id: side.tenant.into(),
        name: "partner".into(),
        kind: TrustSourceKind::UploadedJwks,
        exact_issuer: PARTNER_ISSUER.into(),
        discovery_url: None,
        jwks_keyset_id: Some(side.keyset()),
        cluster_id: None,
        token_review_endpoint: None,
        ca_bundle_ref: None,
        ca_fingerprint: None,
        reviewer_credential_ref: None,
        review_timeout_ms: None,
        audiences: strings(&["https://skyoauth.example"]),
        algorithms: Some(strings(&["ES256"])),
        proof_bounds: object(json!({"max_age_seconds": 300})),
        assertion_profile: AssertionProfile::ReusableJwt,
        stale_revocation_acknowledged: None,
        replay_mode: ReplayMode::Reusable,
        status: Status::Enabled,
    }
}

/// Tenants, workloads, keysets with their first versions, sources,
/// bindings and grants (module docs).
async fn fixture() -> (TestDb, PgPool) {
    let db = TestDb::create().await;
    let pool = db.pool().await;
    for side in [A, B] {
        let t = side.tenant;
        registry::create_tenant(&pool, &tenant(side)).await.unwrap();
        registry::create_principal(
            &pool,
            &NewPrincipal {
                id: side.workload(),
                tenant_id: t.into(),
                kind: PrincipalKind::Workload,
                name: "release".into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        for (id, name) in [(side.keyset(), "partner"), (side.other_keyset(), "other")] {
            registry::create_trust_keyset(&pool, &keyset(side, id, name))
                .await
                .unwrap();
        }
        for new in [side.old(), side.other()] {
            registry::create_trust_keyset_version(&pool, &new)
                .await
                .unwrap();
        }
        registry::create_trust_source(&pool, &uploaded_source(side))
            .await
            .unwrap();
        registry::create_principal_binding(
            &pool,
            &NewPrincipalBinding {
                id: side.binding(),
                tenant_id: t.into(),
                name: "release".into(),
                trust_source_id: side.source(),
                profile: BindingProfile::GenericProduction,
                claim_match_policy: [("sub".to_string(), "pipeline:partner/release".to_string())]
                    .into(),
                workload_principal_id: side.workload(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        registry::create_service_grant(
            &pool,
            &NewServiceGrant {
                id: side.grant(),
                tenant_id: t.into(),
                name: "release".into(),
                actor_principal_id: side.workload(),
                target_service_id: None,
                mode: GrantMode::Direct,
                scopes: strings(&["read"]),
                default_scopes: Some(strings(&["read"])),
                resource_constraints: JsonObject::new(),
                max_ttl: 300,
                valid_until: None,
                status: Status::Enabled,
                activation_state: ActivationState::NotRequired,
                allowed_binding_ids: vec![side.binding()],
                resource_server_ids: Vec::new(),
            },
        )
        .await
        .unwrap();
    }
    (db, pool)
}

/// The records a rotation must leave alone: the parent keyset and the
/// source, binding and grant that hang off it, read by ID.
#[derive(Debug, Clone, PartialEq)]
struct Lineage {
    keyset: TrustKeyset,
    source: TrustSource,
    binding: PrincipalBinding,
    grant: ServiceGrant,
}

async fn lineage(pool: &PgPool, side: Side) -> Lineage {
    let t = side.tenant;
    Lineage {
        keyset: registry::get_trust_keyset(pool, t, &side.keyset())
            .await
            .unwrap(),
        source: registry::get_trust_source(pool, t, &side.source())
            .await
            .unwrap(),
        binding: registry::get_principal_binding(pool, t, &side.binding())
            .await
            .unwrap(),
        grant: registry::get_service_grant(pool, t, &side.grant())
            .await
            .unwrap(),
    }
}

/// The versions of `keyset` as `side` lists them.
async fn versions(pool: &PgPool, side: Side, keyset: &str) -> Vec<TrustKeysetVersion> {
    registry::list_trust_keyset_versions(pool, side.tenant, keyset, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap()
}

/// One tenant's keysets with their versions, sources, bindings and grants,
/// as `Debug` text.
async fn tenant_snapshot(pool: &PgPool, side: Side) -> Vec<String> {
    let all = Page::first(MAX_PAGE_SIZE);
    let t = side.tenant;
    let keysets = registry::list_trust_keysets(pool, t, all).await.unwrap();
    let mut out = vec![format!("{keysets:?}")];
    for keyset in &keysets {
        out.push(format!("{:?}", versions(pool, side, &keyset.id).await));
    }
    out.push(format!(
        "{:?}",
        registry::list_trust_sources(pool, t, all).await.unwrap()
    ));
    out.push(format!(
        "{:?}",
        registry::list_principal_bindings(pool, t, all)
            .await
            .unwrap()
    ));
    out.push(format!(
        "{:?}",
        registry::list_service_grants(pool, t, all).await.unwrap()
    ));
    out
}

/// Both tenants' [`tenant_snapshot`]s. Equal snapshots before and after a
/// refused step show that it wrote nothing: no row and no revision changed.
async fn snapshot(pool: &PgPool) -> Vec<String> {
    let mut out = tenant_snapshot(pool, A).await;
    out.extend(tenant_snapshot(pool, B).await);
    out
}

/// A refusal by a constraint, as its typed fields: the variant
/// [`RegistryError::Invariant`] with its kind and constraint name. The
/// `Display` text is never compared.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    kind: InvariantKind,
    constraint: &'static str,
}

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

/// The constraint of an `AlreadyExists`, the variant checked by match.
#[track_caller]
fn already_exists<T: Debug>(result: Result<T, RegistryError>) -> &'static str {
    match result {
        Err(RegistryError::AlreadyExists { constraint }) => constraint,
        other => panic!("expected RegistryError::AlreadyExists: {other:?}"),
    }
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

const VALIDITY_CHECK: Refusal = Refusal {
    kind: InvariantKind::Check,
    constraint: "trust_keyset_version_validity_check",
};
const KEYSET_KEY: Refusal = Refusal {
    kind: InvariantKind::ForeignKey,
    constraint: "trust_keyset_version_keyset_id_fkey",
};
const VERSION_PKEY: &str = "trust_keyset_version_pkey";

/// The status replica `r` sets in the races: `disabled` for even `r`,
/// `enabled` for odd `r`.
fn status_of(replica: usize) -> Status {
    if replica.is_multiple_of(2) {
        Status::Disabled
    } else {
        Status::Enabled
    }
}

#[tokio::test]
async fn a04_pos_rotation_overlaps_versions_and_keeps_every_id() {
    let (db, pool) = fixture().await;
    for (side, other) in DIRECTIONS {
        let t = side.tenant;
        let before = lineage(&pool, side).await;
        let sibling_before = registry::get_trust_keyset(&pool, t, &side.other_keyset())
            .await
            .unwrap();
        let other_before = tenant_snapshot(&pool, other).await;
        // The fixture's lineage: the source names the parent, the binding
        // the source, the grant the binding; all at revision 1.
        assert_eq!(before.keyset.id, side.keyset());
        assert_eq!(before.source.jwks_keyset_id, Some(side.keyset()));
        assert_eq!(before.binding.trust_source_id, side.source());
        assert_eq!(before.grant.allowed_binding_ids, [side.binding()]);
        assert_eq!(
            (
                before.keyset.revision,
                before.source.revision,
                before.binding.revision,
                before.grant.revision
            ),
            (1, 1, 1, 1)
        );
        let old = stored(&side.old(), Status::Enabled, 1);
        assert_eq!(
            versions(&pool, side, &side.keyset()).await,
            std::slice::from_ref(&old)
        );

        // The new version, staged disabled, then enabled: two versions of
        // one parent enabled at once, listed by ID, each exactly as
        // uploaded, windows included.
        let staged = registry::create_trust_keyset_version(&pool, &side.incoming())
            .await
            .unwrap();
        assert_eq!(staged, stored(&side.incoming(), Status::Disabled, 1));
        let new = registry::update_trust_keyset_version(
            &pool,
            t,
            &side.incoming().id,
            1,
            Status::Enabled,
        )
        .await
        .unwrap();
        assert_eq!(new, stored(&side.incoming(), Status::Enabled, 2));
        assert_eq!(
            registry::get_trust_keyset_version(&pool, t, &new.id)
                .await
                .unwrap(),
            new
        );
        let overlap = versions(&pool, side, &side.keyset()).await;
        assert_eq!(overlap, [new.clone(), old.clone()]);
        // The stored windows overlap from T1 to T2, explicitly.
        assert_eq!(
            (overlap[1].effective_at, overlap[0].effective_at),
            (at(T0), at(T1))
        );
        assert_eq!(
            (overlap[1].expires_at, overlap[0].expires_at),
            (Some(at(T2)), Some(at(T3)))
        );
        assert_eq!(lineage(&pool, side).await, before);

        // The old version retired, and an open-ended one after the new.
        let retired = registry::update_trust_keyset_version(&pool, t, &old.id, 1, Status::Disabled)
            .await
            .unwrap();
        assert_eq!(retired, stored(&side.old(), Status::Disabled, 2));
        let next = registry::create_trust_keyset_version(&pool, &side.next())
            .await
            .unwrap();
        assert_eq!(next, stored(&side.next(), Status::Enabled, 1));
        let rotated = [new.clone(), next.clone(), retired.clone()];
        assert_eq!(versions(&pool, side, &side.keyset()).await, rotated);
        assert_eq!(lineage(&pool, side).await, before);

        // The parent disabled and re-enabled: its own revision moves, its
        // ID and name do not, and no version changes.
        let changes = |status| TrustKeysetChanges {
            name: before.keyset.name.clone(),
            status,
        };
        let disabled =
            registry::update_trust_keyset(&pool, t, &side.keyset(), 1, &changes(Status::Disabled))
                .await
                .unwrap();
        assert_eq!(
            disabled,
            TrustKeyset {
                status: Status::Disabled,
                revision: 2,
                ..before.keyset.clone()
            }
        );
        assert_eq!(versions(&pool, side, &side.keyset()).await, rotated);
        let reenabled =
            registry::update_trust_keyset(&pool, t, &side.keyset(), 2, &changes(Status::Enabled))
                .await
                .unwrap();
        assert_eq!(
            reenabled,
            TrustKeyset {
                revision: 3,
                ..before.keyset.clone()
            }
        );
        assert_eq!(versions(&pool, side, &side.keyset()).await, rotated);
        assert_eq!(
            lineage(&pool, side).await,
            Lineage {
                keyset: reenabled,
                ..before.clone()
            }
        );

        // The tenant's other keyset (every column, its revision included)
        // and its version, and the other tenant, are untouched.
        assert_eq!(
            registry::get_trust_keyset(&pool, t, &side.other_keyset())
                .await
                .unwrap(),
            sibling_before
        );
        assert_eq!(
            (sibling_before.status, sibling_before.revision),
            (Status::Enabled, 1)
        );
        assert_eq!(
            versions(&pool, side, &side.other_keyset()).await,
            [stored(&side.other(), Status::Enabled, 1)]
        );
        assert_eq!(tenant_snapshot(&pool, other).await, other_before);
    }
    db.drop([pool]).await;
}

/// 8 replicas per round, 3 fresh databases (module docs).
#[tokio::test(flavor = "multi_thread")]
async fn a04_pos_concurrent_uploads_add_overlapping_versions_under_one_parent() {
    const REPLICAS: usize = 8;
    const DATABASES: usize = 3;
    // Replica r's version: its own window, each starting r microseconds
    // after T1 and overlapping the old version's and every other one's.
    let request = |replica: usize| {
        version(
            A,
            &format!("kv_r{replica}"),
            &A.keyset(),
            &format!("r{replica}"),
            T1 + replica as u64,
            Some(at(T3)),
        )
    };
    for round in 0..DATABASES {
        let (db, pool) = fixture().await;
        let before = lineage(&pool, A).await;
        let other_before = tenant_snapshot(&pool, B).await;
        let replicas = Replicas::start(&db, REPLICAS).await;
        let outcomes = replicas
            .race(move |replica, mut conn| async move {
                registry::create_trust_keyset_version(&mut *conn, &request(replica)).await
            })
            .await;
        let mut expected = vec![stored(&A.old(), Status::Enabled, 1)];
        for (replica, outcome) in outcomes.into_iter().enumerate() {
            let row =
                outcome.unwrap_or_else(|err| panic!("round {round}, replica {replica}: {err:?}"));
            assert_eq!(
                row,
                stored(&request(replica), Status::Enabled, 1),
                "round {round}"
            );
            expected.push(row);
        }
        // `kv_old_a` sorts before `kv_r0_a`; the replicas' IDs in order.
        assert_eq!(
            versions(&pool, A, &A.keyset()).await,
            expected,
            "round {round}"
        );
        assert_eq!(lineage(&pool, A).await, before, "round {round}");
        assert_eq!(
            tenant_snapshot(&pool, B).await,
            other_before,
            "round {round}"
        );
        db.drop(std::iter::once(pool).chain(replicas.into_pools()))
            .await;
    }
}

#[tokio::test]
async fn a04_neg_empty_or_inverted_windows_are_refused() {
    let (db, pool) = fixture().await;
    let sub_micro = Duration::from_nanos(999);
    for side in [A, B] {
        let refused: [(&str, SystemTime, Option<SystemTime>); 4] = [
            ("an expiry equal to the start", at(T1), Some(at(T1))),
            (
                "an expiry one microsecond before the start",
                at(T1),
                Some(at(T1 - 1)),
            ),
            ("an expiry before the start", at(T2), Some(at(T1))),
            (
                "an expiry 999 ns after the start, empty in whole microseconds",
                at(T1),
                Some(at(T1) + sub_micro),
            ),
        ];
        for (label, effective_at, expires_at) in refused {
            for status in [Status::Enabled, Status::Disabled] {
                let before = snapshot(&pool).await;
                let new = NewTrustKeysetVersion {
                    effective_at,
                    expires_at,
                    status,
                    ..side.incoming()
                };
                assert_eq!(
                    refusal(registry::create_trust_keyset_version(&pool, &new).await),
                    VALIDITY_CHECK,
                    "{side:?}, {label}, {status:?}"
                );
                assert_not_found(
                    registry::get_trust_keyset_version(&pool, side.tenant, &new.id).await,
                );
                assert_eq!(
                    snapshot(&pool).await,
                    before,
                    "{side:?}, {label}, {status:?}"
                );
            }
        }

        // The boundaries the check lets through, stored as truncated.
        let accepted: [(&str, SystemTime, Option<SystemTime>, SystemTime); 3] = [
            ("one microsecond", at(T1), Some(at(T1 + 1)), at(T1)),
            (
                "a start whose nanoseconds truncate",
                at(T1) + sub_micro,
                Some(at(T1 + 1)),
                at(T1),
            ),
            ("open-ended", at(T1), None, at(T1)),
        ];
        for (n, (label, effective_at, expires_at, stored_start)) in accepted.into_iter().enumerate()
        {
            let new = NewTrustKeysetVersion {
                id: side.id(&format!("kv_edge{n}")),
                effective_at,
                expires_at,
                ..side.incoming()
            };
            let row = registry::create_trust_keyset_version(&pool, &new)
                .await
                .unwrap_or_else(|err| panic!("{side:?}, {label}: {err:?}"));
            let expected = NewTrustKeysetVersion {
                effective_at: stored_start,
                ..new
            };
            assert_eq!(
                row,
                stored(&expected, Status::Disabled, 1),
                "{side:?}, {label}"
            );
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a04_neg_stale_or_foreign_rotation_steps_change_nothing() {
    let (db, pool) = fixture().await;
    let before = snapshot(&pool).await;
    for (owner, intruder) in DIRECTIONS {
        let old = owner.old().id;
        let label = format!("{owner:?} by {intruder:?}");
        // Any revision but the current one, 1, is stale, in either
        // direction of status.
        for expected in [0, 2, -1, i64::MIN, i64::MAX] {
            for status in [Status::Disabled, Status::Enabled] {
                assert_stale(
                    registry::update_trust_keyset_version(
                        &pool,
                        owner.tenant,
                        &old,
                        expected,
                        status,
                    )
                    .await,
                );
            }
        }
        // The other tenant finds nothing, whatever the revision, the
        // current one included.
        for expected in [1, 2, i64::MAX] {
            assert_not_found(
                registry::update_trust_keyset_version(
                    &pool,
                    intruder.tenant,
                    &old,
                    expected,
                    Status::Disabled,
                )
                .await,
            );
        }
        assert_not_found(registry::get_trust_keyset_version(&pool, intruder.tenant, &old).await);
        assert!(
            versions(&pool, intruder, &owner.keyset()).await.is_empty(),
            "{label}"
        );
        assert_not_found(
            registry::update_trust_keyset_version(
                &pool,
                owner.tenant,
                &owner.id("kv_missing"),
                1,
                Status::Disabled,
            )
            .await,
        );

        // An upload into the other tenant's keyset, or into none.
        for keyset_id in [owner.keyset(), intruder.id("ks_missing")] {
            let foreign = NewTrustKeysetVersion {
                keyset_id,
                ..intruder.incoming()
            };
            assert_eq!(
                refusal(registry::create_trust_keyset_version(&pool, &foreign).await),
                KEYSET_KEY,
                "{label}"
            );
        }
        // An upload that reuses a version ID, the other tenant's included:
        // IDs are global, so neither shadows the existing version.
        for uploader in [owner, intruder] {
            let reuse = NewTrustKeysetVersion {
                id: old.clone(),
                ..uploader.incoming()
            };
            assert_eq!(
                already_exists(registry::create_trust_keyset_version(&pool, &reuse).await),
                VERSION_PKEY,
                "{label}"
            );
        }
        assert_eq!(snapshot(&pool).await, before, "{label}");
    }

    // The version's revision is its own: once the parent is at revision 2,
    // a step at the parent's revision is stale, one at the version's
    // applies and moves only the version's, and its replay is stale.
    for side in [A, B] {
        let t = side.tenant;
        let parent = registry::update_trust_keyset(
            &pool,
            t,
            &side.keyset(),
            1,
            &TrustKeysetChanges {
                name: "partner".into(),
                status: Status::Enabled,
            },
        )
        .await
        .unwrap();
        assert_eq!(parent.revision, 2);
        let old = side.old().id;
        assert_stale(
            registry::update_trust_keyset_version(&pool, t, &old, 2, Status::Disabled).await,
        );
        let step = registry::update_trust_keyset_version(&pool, t, &old, 1, Status::Disabled)
            .await
            .unwrap();
        assert_eq!(step, stored(&side.old(), Status::Disabled, 2));
        for status in [Status::Disabled, Status::Enabled] {
            assert_stale(registry::update_trust_keyset_version(&pool, t, &old, 1, status).await);
        }
        assert_eq!(
            registry::get_trust_keyset_version(&pool, t, &old)
                .await
                .unwrap(),
            step
        );
        assert_eq!(lineage(&pool, side).await.keyset, parent);
    }
    db.drop([pool]).await;
}

/// 8 replicas per round, 3 fresh databases (module docs).
#[tokio::test(flavor = "multi_thread")]
async fn a04_neg_concurrent_rotation_steps_have_one_winner() {
    const REPLICAS: usize = 8;
    const DATABASES: usize = 3;
    for round in 0..DATABASES {
        let (db, pool) = fixture().await;
        let before = lineage(&pool, A).await;
        let other_before = tenant_snapshot(&pool, B).await;
        let replicas = Replicas::start(&db, REPLICAS).await;

        // One version's status from its current revision: half disable it,
        // half (re-)enable it.
        let outcomes = replicas
            .race(|replica, mut conn| async move {
                registry::update_trust_keyset_version(
                    &mut *conn,
                    A.tenant,
                    &A.old().id,
                    1,
                    status_of(replica),
                )
                .await
            })
            .await;
        let winners: Vec<usize> = (0..REPLICAS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        let winner = outcomes[winners[0]].as_ref().unwrap().clone();
        assert_eq!(winner, stored(&A.old(), status_of(winners[0]), 2));
        for (replica, outcome) in outcomes.into_iter().enumerate() {
            if replica != winners[0] {
                assert_stale(outcome);
            }
        }
        assert_eq!(
            registry::get_trust_keyset_version(&pool, A.tenant, &A.old().id)
                .await
                .unwrap(),
            winner,
            "round {round}"
        );

        // One version ID uploaded at once, each with its own window and
        // fingerprint.
        let request = |replica: usize| {
            version(
                A,
                "kv_race",
                &A.keyset(),
                &format!("r{replica}"),
                T1 + replica as u64,
                Some(at(T3)),
            )
        };
        let outcomes = replicas
            .race(move |replica, mut conn| async move {
                registry::create_trust_keyset_version(&mut *conn, &request(replica)).await
            })
            .await;
        let winners: Vec<usize> = (0..REPLICAS).filter(|&r| outcomes[r].is_ok()).collect();
        assert_eq!(winners.len(), 1, "round {round}: {outcomes:?}");
        let uploaded = outcomes[winners[0]].as_ref().unwrap().clone();
        assert_eq!(uploaded, stored(&request(winners[0]), Status::Enabled, 1));
        for (replica, outcome) in outcomes.into_iter().enumerate() {
            if replica != winners[0] {
                assert_eq!(already_exists(outcome), VERSION_PKEY, "round {round}");
            }
        }
        // `kv_old_a` sorts before `kv_race_a`.
        assert_eq!(
            versions(&pool, A, &A.keyset()).await,
            [winner, uploaded],
            "round {round}"
        );
        assert_eq!(lineage(&pool, A).await, before, "round {round}");
        assert_eq!(
            tenant_snapshot(&pool, B).await,
            other_before,
            "round {round}"
        );
        db.drop(std::iter::once(pool).chain(replicas.into_pools()))
            .await;
    }
}

/// What the holder and the waiters write in
/// `a04_neg_blocked_rotation_steps_follow_the_holder_commit_or_rollback`.
#[derive(Debug, Clone, Copy)]
enum Contested {
    /// A status change of `kv_old_a` from revision 1: [`status_of`] for a
    /// waiter, `disabled` for the holder.
    Step,
    /// An upload of the version ID `kv_blk_a`, with a window of its own.
    Upload,
}

/// The holder's number in [`Contested::write`].
const HOLDER: usize = 100;

impl Contested {
    fn upload(n: usize) -> NewTrustKeysetVersion {
        version(
            A,
            "kv_blk",
            &A.keyset(),
            &format!("w{n}"),
            T1 + n as u64,
            Some(at(T3)),
        )
    }

    /// The write of waiter `n`, or of the holder when `n` is [`HOLDER`].
    async fn write(
        self,
        conn: &mut PgConnection,
        n: usize,
    ) -> Result<TrustKeysetVersion, RegistryError> {
        match self {
            Contested::Step => {
                let status = if n == HOLDER {
                    Status::Disabled
                } else {
                    status_of(n)
                };
                registry::update_trust_keyset_version(conn, A.tenant, &A.old().id, 1, status).await
            }
            Contested::Upload => {
                registry::create_trust_keyset_version(conn, &Self::upload(n)).await
            }
        }
    }

    /// The row the write of `n` stores when it wins.
    fn row(self, n: usize) -> TrustKeysetVersion {
        match self {
            Contested::Step => {
                let status = if n == HOLDER {
                    Status::Disabled
                } else {
                    status_of(n)
                };
                stored(&A.old(), status, 2)
            }
            Contested::Upload => stored(&Self::upload(n), Status::Enabled, 1),
        }
    }

    fn id(self) -> String {
        match self {
            Contested::Step => A.old().id,
            Contested::Upload => Self::upload(0).id,
        }
    }

    /// Asserts that `outcome` is this write's refusal when it loses.
    #[track_caller]
    fn assert_lost(self, outcome: Result<TrustKeysetVersion, RegistryError>, label: &str) {
        match self {
            Contested::Step => assert!(
                matches!(outcome, Err(RegistryError::StaleRevision)),
                "{label}: {outcome:?}"
            ),
            Contested::Upload => assert_eq!(already_exists(outcome), VERSION_PKEY, "{label}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a04_neg_blocked_rotation_steps_follow_the_holder_commit_or_rollback() {
    const WAITERS: usize = 4;
    for contested in [Contested::Step, Contested::Upload] {
        for commit in [true, false] {
            let (db, pool) = fixture().await;
            let before = lineage(&pool, A).await;
            let holder_pool = db.pool_with_max_connections(1).await;
            let mut holder_conn = holder_pool.acquire().await.unwrap();
            let holder_pid = rep::backend_pid(&mut holder_conn).await;
            let waiters = Replicas::start(&db, WAITERS).await;
            let pids = waiters.backend_pids().await;

            let mut tx = Connection::begin(&mut *holder_conn).await.unwrap();
            assert_eq!(
                contested.write(&mut tx, HOLDER).await.unwrap(),
                contested.row(HOLDER)
            );
            // Set just before the holder ends: a waiter that finished
            // earlier reads `false`.
            let ending = Arc::new(AtomicBool::new(false));
            let observer = &pool;
            let release = {
                let ending = Arc::clone(&ending);
                async move {
                    rep::wait_until_blocked(observer, &pids, holder_pid).await;
                    ending.store(true, Ordering::SeqCst);
                    if commit {
                        tx.commit().await.unwrap();
                    } else {
                        tx.rollback().await.unwrap();
                    }
                }
            };
            let race = waiters.race({
                let ending = Arc::clone(&ending);
                move |replica, mut conn| {
                    let ending = Arc::clone(&ending);
                    async move {
                        let outcome = contested.write(&mut conn, replica).await;
                        (outcome, ending.load(Ordering::SeqCst))
                    }
                }
            });
            let (results, ()) = tokio::join!(race, release);
            drop(holder_conn);

            let label = format!("{contested:?}, commit {commit}");
            let mut outcomes = Vec::new();
            for (replica, (outcome, after_holder)) in results.into_iter().enumerate() {
                assert!(
                    after_holder,
                    "{label}: replica {replica} finished before the holder ended: {outcome:?}"
                );
                outcomes.push(outcome);
            }
            let winners: Vec<usize> = (0..WAITERS).filter(|&r| outcomes[r].is_ok()).collect();
            let owner = if commit {
                assert_eq!(winners, Vec::<usize>::new(), "{label}: {outcomes:?}");
                HOLDER
            } else {
                assert_eq!(winners.len(), 1, "{label}: {outcomes:?}");
                winners[0]
            };
            for (replica, outcome) in outcomes.into_iter().enumerate() {
                if winners.contains(&replica) {
                    assert_eq!(outcome.unwrap(), contested.row(owner), "{label}");
                } else {
                    contested.assert_lost(outcome, &label);
                }
            }
            assert_eq!(
                registry::get_trust_keyset_version(&pool, A.tenant, &contested.id())
                    .await
                    .unwrap(),
                contested.row(owner),
                "{label}"
            );
            assert_eq!(lineage(&pool, A).await, before, "{label}");
            let pools = [pool, holder_pool].into_iter().chain(waiters.into_pools());
            db.drop(pools).await;
        }
    }
}
