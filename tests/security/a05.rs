//! A05: unsafe JWKS and token-header inputs; egress allowlist checks.
//! Expected: a public-only JWK is accepted; private members, `jku`, `x5u`,
//! an embedded `jwk` and an unsafe key URL are rejected; a `discovery_url`
//! or `token_review_endpoint` with no enabled matching egress allowlist
//! entry is rejected on create or change, a discovered `jwks_uri` with no
//! enabled `jwks` entry is not fetched, and no new discovery or JWKS fetch
//! goes through a disabled entry (tasks §8; T11.2, T11.3, T11.5, T11.8,
//! T24.3, T52.1; ADR-005 item 8; design §5.4; identity-registry IR-152).
//!
//! **A05 partial: the upload rejection and the write-time egress rejection
//! of the M1a stage ("upload, token-header and egress-allowlist
//! rejection") only, on `scenarios-pg/x86_64`; the stage stays `planned`,
//! with no stamp, and cannot be implemented until a `scenarios-hermetic`
//! job exists for its hermetic legs.** These tests are registered on A05's
//! planned M1a stage, so they are no evidence for it: the reporter lists
//! their results as not counted, and they are no claim. They run against a
//! real PostgreSQL, one fresh database per test, through these library
//! paths:
//!
//! - the keyset version upload: Stage A, `trust::validate_upload`, which
//!   runs `jwk::validate_keyset` on the parsed upload, and Stage B, the
//!   gated create `trust::submit_create_version` by a `trust_admin` of the
//!   tenant with `widening_second_approver` off (applied at once);
//! - the registry floor of a keyset version,
//!   `registry::test_support::create_trust_keyset_version` (crate-private
//!   in a normal build; reached through the `test-support` feature), where
//!   the `0004` check `trust_keyset_version_public_jwks_check` lives;
//! - the registry floor of a trust source,
//!   `registry::test_support::create_trust_source` and
//!   `update_trust_source`, where the `0011` guard
//!   (`trust_source_egress_enabled`) refuses a destination with no enabled
//!   matching entry, with `Invariant { EgressEntryEnabled,
//!   trust_source_discovery_url_egress_enabled }` or `Invariant {
//!   EgressEntryEnabled, trust_source_token_review_endpoint_egress_enabled
//!   }`;
//! - the gated write path of a trust source, `trust::submit_create_source`
//!   and `trust::submit_update_source`, by `adm_trust` with
//!   `widening_second_approver` off (applied at once), whose own checks
//!   refuse first, with `SourceWriteError::InvalidDestination` or
//!   `EgressNotAllowed` naming the member; and with the gate on, the
//!   approval of a pending create by a distinct instance `security_admin`
//!   (`operation::prepare_approval` and `operation::approve_operation`).
//!
//! Every refusal is compared by its typed fields (variant, member, key
//! index, invariant kind, constraint), never by message text.
//!
//! - **Positive, upload.** A one-key set (the RFC 7517 appendix A.1 P-256
//!   public key) and a three-key set (the RFC 7638 RSA key, a P-256 key and
//!   the RFC 8037 Ed25519 key, with `use` and `key_ops`) are validated and
//!   written as enabled versions through the gated create. The expected
//!   projection and fingerprint of each are written out here from the
//!   input keys, never taken from the validator: every key, with its `kid`,
//!   its type's public members and their input values, `alg` where the
//!   upload had it, and nothing else (`use` and `key_ops` dropped). Stage
//!   A's output and the stored row must both equal them
//!   (`a05_pos_public_only_jwks_upload_is_accepted`).
//! - **Negative, private members.** A key with one of the eight private or
//!   symmetric members `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k` (RFC 7518
//!   section 6, RFC 8037 section 2; the list is written out here, not taken
//!   from `jwk::PRIVATE_MEMBERS`), alone in the set or next to one good key
//!   before or after it, is refused by `validate_upload` as
//!   `Upload(Key { index, PrivateMember(member) })`, the index that of the
//!   bad key: the whole upload is refused, its good key included. So are
//!   the RFC 7517 appendix A.2 EC and RFC 8037 appendix A.1 Ed25519
//!   private keys and an `oct` key. The same sets written through the
//!   registry floor are refused by `trust_keyset_version_public_jwks_check`.
//!   A good upload whose `provenance` names a private member, nested in an
//!   array, and no other one, is refused by `submit_create_version` with
//!   `PrivateMemberInProvenance` (an inferred rule of `trust::keyset`).
//!   After each refusal the keyset has no version and the audit chain no
//!   new event; a good upload is then written, as the control
//!   (`a05_neg_upload_with_private_members_is_refused`).
//! - **Negative, key references.** A key with `x5u`, `x5c` or `jku`, placed
//!   the same three ways, is refused as `Upload(Key { index,
//!   KeyReference(member) })` and nothing is written
//!   (`a05_neg_upload_with_key_reference_members_is_refused`). The `0004`
//!   floor does not check these members, so only the service refuses them;
//!   no floor case is asserted for them.
//! - **Positive, egress.** An `oidc_discovery` source and a
//!   `kubernetes_token_review` source whose destination an enabled entry
//!   of the member's purpose lists byte for byte are created at revision 1
//!   and moved to a second such destination at revision 2. Once that
//!   entry is disabled, a rename, a disable and a re-enable that leave the
//!   member unchanged are accepted, at revisions 3, 4 and 5 (IR-152:
//!   rejected "on create or change" only)
//!   (`a05_pos_destination_with_an_enabled_matching_egress_entry_is_accepted`).
//! - **Negative, egress create.** For each member, a create, enabled or
//!   disabled, whose destination has no enabled matching entry is refused
//!   with the member's constraint and writes nothing: no entry at all; an
//!   enabled entry of the member's purpose for another destination
//!   (another host, port or path, a prefix of the listed URL, the listed
//!   URL extended, another letter case); enabled entries of both other
//!   purposes for exactly that destination; and a disabled entry of the
//!   member's purpose for exactly that destination
//!   (`a05_neg_source_create_without_an_enabled_matching_egress_entry_is_refused`).
//! - **Negative, egress change.** A stored source of each kind updated to
//!   each of those destinations (alone, with a disable, with a rename) is
//!   refused the same way, and the stored row keeps its revision and every
//!   column
//!   (`a05_neg_source_change_without_an_enabled_matching_egress_entry_is_refused`).
//! - **Negative, gated write.** The same table through the gated create
//!   (enabled or disabled) and the gated update (alone, with a disable,
//!   with a rename), gate off: each is refused with `EgressNotAllowed`
//!   naming the member, except the near misses that are not in canonical
//!   form, another letter case for both members and the TokenReview URL
//!   without its path, which the syntax rule refuses first with
//!   `InvalidDestination` naming the member. No source is written or
//!   changed and the audit chain has no new event. As a control, a gated
//!   create to a listed destination is applied
//!   (`a05_neg_gated_source_write_without_an_enabled_matching_egress_entry_is_refused`).
//! - **Negative, approval.** With the gate on, a create on a listed
//!   destination goes pending; its entry is then disabled through the
//!   egress allowlist writer, and the approval is refused with
//!   `ApprovalError::Source`
//!   (`EgressNotAllowed` naming the member): no source is written, the
//!   operation stays pending and the audit chain has no new event. As a
//!   control, a create on a destination whose entry stays enabled is
//!   approved and written as requested
//!   (`a05_neg_approval_after_its_egress_entry_is_disabled_is_refused`).
//!
//! # Egress allowlist entries
//!
//! Every entry here is written through the audited egress allowlist writer
//! (`skyoauth_service::admin::egress`; IR-152) by the instance
//! `security_admin` `adm_first`, which [`egress_fixture`] bootstraps first:
//! [`seed_entry`] creates the enabled entries of the member's own purpose
//! and of the other purposes and the disabled entries (created as
//! `disabled`), and [`disable_entry`] disables an entry, at its current
//! revision, after a source was written on it or a request went pending on
//! it. A create, enabled or disabled, is widening (IR-052, IR-152), so
//! [`seed_entry`] acknowledges it and runs while `widening_second_approver`
//! is still off (outcome `success_widening`), before a gated fixture turns
//! it on; a disable is not widening and needs neither. No entry is SQL-seeded, so A05 no longer uses the shared fixture
//! `skyoauth_scenarios::egress` (conformance layout §1.3). The writer has no
//! endpoint yet; its library call is what one will make.
//!
//! # Spec and registry picks
//!
//! The spec's rules pinned here: private-key uploads are rejected (ADR-005
//! items 1 and 8; design §5.4; T11.3), and a destination with no enabled
//! entry that exactly matches it is rejected on create or change, a write
//! that leaves it unchanged is not (IR-152). The registry's, not the
//! spec's: that a set with one bad key is refused whole and the error
//! names the bad key's index; that `x5u`, `x5c` and `jku` are refused in an
//! uploaded key (inferred in `jwk` from ADR-005 item 8); that a
//! `provenance` naming a private member is refused (inferred in
//! `trust::keyset`); that "exactly match" is byte equality with no
//! normalization of case, port or trailing slash (inferred in
//! `trust::source`); that a disable that also moves the member to a
//! destination with no enabled entry is refused (the "with a disable"
//! updates; inferred in `trust::source`, "When": IR-152 says a disable
//! must not be rejected and exempts "a disable" and a write that leaves
//! both members unchanged, and such a write is neither alone, so a ruling
//! the other way turns those cases red); that a re-enable that leaves both
//! members unchanged is accepted through a disabled entry (IR-152's
//! unchanged-write rule, applied by the `0011` guard and `trust::source` to
//! every update); that the gated path refuses a non-canonical destination
//! before its entry check (`trust::source`, "Syntax"); and the error
//! shapes. Egress entries are instance-global (`0002`: no tenant column;
//! the instance `security_admin` owns them, identity-registry §2), so an
//! entry "of another tenant" does not exist and is not tested: any enabled
//! entry of the purpose with exactly that destination allows a source of
//! any tenant.
//!
//! # Not tested here, and what stays open
//!
//! None of these has a library path at M1a; each needs code that does not
//! exist (no fetcher, no token verifier, no JWS header parsing), and none
//! has a completion criterion yet:
//!
//! - **Token headers.** A token whose header carries `jku`, `x5u` or an
//!   embedded `jwk` is not trusted (T11.5, T11.7, T24.3); the verifier
//!   does not exist.
//! - **Unsafe key URL.** A key URL that is not a safe `https` destination
//!   (T11.2, T11.8); no fetcher exists. The write-time syntax rule of
//!   `trust::source` is reached here only by the two non-canonical near
//!   misses of the gated table; its own cases are the service tests'.
//! - **Discovered `jwks_uri`.** A `jwks_uri` from a discovery document with
//!   no enabled `jwks` entry is not fetched (IR-152; T11.2, T11.8).
//! - **Disabled entry at fetch.** No new discovery or JWKS fetch through an
//!   entry disabled after the source was written (IR-152; the degraded
//!   health signal).
//! - **The hermetic legs** (`scenarios-hermetic/x86_64`,
//!   `scenarios-hermetic/aarch64`): the job does not exist.
//! - **A05's M2 stage** ("generic issuer keysets"): disallowed issuer or
//!   algorithm, conflicting `kid`, cross-tenant keyset.
//! - **Endpoints.** No admin endpoint writes a keyset version or a trust
//!   source yet (T13.8); the gated functions here are the library that one
//!   will call.
//!
//! # Overlap
//!
//! The service tests already pin each refusal of `jwk` on single keys
//! (`service/tests/jwk.rs`), the upload and provenance refusals of the
//! keyset write path (`service/tests/trust_keyset_version.rs`) and the
//! `0011` guard in SQL (`service/tests/schema_trust_source_egress_guard.rs`),
//! the egress check through the registry and the gated path
//! (`service/tests/trust_source_egress.rs`) and the approval refused after
//! its entry is disabled (`service/tests/source_approval.rs`). A05 adds the
//! scenario's view: every member of each family through the upload path,
//! inside a set with a good key, the floor's refusal of the same sets, and
//! the create and change refusals of each missing-entry shape through both
//! the `0011` guard and the gated path.

use std::{
    fmt::Debug,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use skyoauth_scenarios::pg::TestDb;
use skyoauth_service::admin::{self, AdminRequest, EgressEntryCreate};
use skyoauth_service::ids::test_support::SequentialIds;
use skyoauth_service::jwk::{DEFAULT_ALLOWED_ALGORITHMS, JwkError, JwkSetError, ValidatedKeyset};
use skyoauth_service::operation::{
    ApprovalEcho, ApprovalError, ApprovalIds, ApprovalScope, Clock, Gated, OperationKind,
    PendingOperation, Submission, approve_operation, prepare_approval, submit_widening_toggle,
};
use skyoauth_service::persistence::{
    PgPool,
    registry::{
        self, AdminRole, AssertionProfile, BootstrapRequest, ChainVerdict, EgressPurpose,
        InvariantKind, JsonObject, MAX_PAGE_SIZE, NewAdminCredential, NewAdminIdentity,
        NewAdminRoleBinding, NewTenant, NewTrustKeyset, NewTrustKeysetVersion, NewTrustSource,
        Page, RegistryError, ReplayMode, Status, TrustKeysetVersion, TrustSource,
        TrustSourceChanges, TrustSourceKind, bootstrap_instance, lock_administrative_operation,
        verify_audit_chain,
    },
};
use skyoauth_service::trust::{
    KeysetWriteError, NewKeysetVersion, SourceWriteError, submit_create_source,
    submit_create_version, submit_update_source, validate_upload,
};

/// The tenant of every row.
const TENANT: &str = "ten_a";
/// The keyset every upload goes to.
const KEYSET: &str = "ks_a";

/// The operators' keys: `adm_first` bootstraps the instance, `adm_sec` is a
/// second instance `security_admin` (the approver) and `adm_trust` the
/// `trust_admin` of [`TENANT`] (the uploader and requester).
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

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

// Key vectors. RFC 7517 appendix A.1 / RFC 7638 section 3.1 (the RSA key,
// kid "2011-04-29"); RFC 7517 appendices A.1 and A.2 (the P-256 key and its
// private `d`); RFC 8037 appendices A.1 and A.2 (the Ed25519 key and its
// private `d`); the P-256 points 1G and 2G (as in `tests/security/a04.rs`,
// computed and cross-checked in Python there). The same values as
// `service/tests/jwk.rs`.
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const P256_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const P256_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
const P256_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
const ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const ED25519_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const P256_1G: (&str, &str) = (
    "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
    "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
);
const P256_2G: (&str, &str) = (
    "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg",
    "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
);

fn p256(kid: &str, (x, y): (&str, &str)) -> Value {
    json!({"kty": "EC", "crv": "P-256", "kid": kid, "x": x, "y": y})
}

fn rsa(kid: &str) -> Value {
    json!({"kty": "RSA", "alg": "RS256", "kid": kid, "n": RSA_N, "e": "AQAB"})
}

fn ed25519(kid: &str) -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": ED25519_X})
}

/// `key` with `member` set to `value`.
fn with(mut key: Value, member: &str, value: Value) -> Value {
    key.as_object_mut()
        .expect("a key is an object")
        .insert(member.to_owned(), value);
    key
}

fn set(keys: Vec<Value>) -> Value {
    json!({ "keys": keys })
}

/// The good key every negative set is built around: the RFC 7517 appendix
/// A.1 P-256 public key.
fn good_key() -> Value {
    p256("good", (P256_X, P256_Y))
}

/// The private and symmetric key members (RFC 7518 section 6: `d`, `p`,
/// `q`, `dp`, `dq`, `qi`, `oth`, `k`; RFC 8037 section 2: `d`), written out
/// here so that a member dropped from the library's list fails a case.
const PRIVATE: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The members referring to keys or certificates outside the upload
/// (RFC 7517 sections 4.6 and 4.7; RFC 7515 section 4.1.2).
const KEY_REFERENCE: [&str; 3] = ["x5u", "x5c", "jku"];

/// A plausible value of `member`: the shape it has in a real private key or
/// a real header, never one the check could depend on. It names no private
/// member itself, so `member` is the only one in a key or provenance built
/// with it: the `oth` entries keep `r` and `t` and leave out their `d`
/// (RFC 7518 section 6.3.2.7), which the recursive provenance check would
/// otherwise refuse in place of `oth`.
fn member_value(member: &str) -> Value {
    match member {
        "oth" => json!([{"r": P256_D, "t": P256_D}]),
        "x5u" => json!("https://keys.a.example/cert.pem"),
        "jku" => json!("https://keys.a.example/jwks.json"),
        "x5c" => json!(["MIIBszCCAVmgAwIBAgIUQ2VydGlmaWNhdGU"]),
        _ => json!(P256_D),
    }
}

/// The three placements of a bad key: alone, after the good key, before
/// it. Each is the set and the index of the bad key in it.
fn placements(bad: &Value) -> [(&'static str, Value, usize); 3] {
    [
        ("alone", set(vec![bad.clone()]), 0),
        ("after a good key", set(vec![good_key(), bad.clone()]), 1),
        ("before a good key", set(vec![bad.clone(), good_key()]), 0),
    ]
}

/// The tenant [`TENANT`] and its keyset [`KEYSET`].
async fn base_fixture() -> (TestDb, PgPool) {
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
            name: "uploaded-keys".into(),
            status: Status::Enabled,
        },
    )
    .await
    .unwrap();
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

/// The instance bootstrapped by `adm_first` (the policy row with both
/// flags off), then [`enrolled`].
async fn operators(pool: &PgPool, gate: bool) {
    bootstrap(pool).await;
    enrolled(pool, gate).await;
}

/// The instance bootstrapped by `adm_first`, an instance `security_admin`
/// (the policy row with both flags off).
async fn bootstrap(pool: &PgPool) {
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
}

/// On a bootstrapped instance: `adm_sec` (a second instance
/// `security_admin`, the approver) and `adm_trust` (the `trust_admin` of
/// [`TENANT`], the requester). With `gate`, `widening_second_approver` is
/// then turned on through the flow: `adm_first` requests it and `adm_sec`
/// approves it. Without it, a gated write is applied at once.
async fn enrolled(pool: &PgPool, gate: bool) {
    operator(pool, "adm_sec", SEC_KEY, AdminRole::SecurityAdmin, None).await;
    operator(
        pool,
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
        approve(pool, ApprovalScope::Instance, &toggle, at(2))
            .await
            .unwrap();
    }
    let policy = registry::get_instance_security_policy(pool).await.unwrap();
    assert_eq!(
        (policy.widening_second_approver, policy.single_actor_mode),
        (gate, false)
    );
}

/// [`base_fixture`] and [`operators`] with the gate off.
async fn upload_fixture() -> (TestDb, PgPool) {
    let (db, pool) = base_fixture().await;
    operators(&pool, false).await;
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

/// The keyset's versions, every column.
async fn versions(pool: &PgPool) -> Vec<TrustKeysetVersion> {
    registry::list_trust_keyset_versions(pool, TENANT, KEYSET, Page::first(MAX_PAGE_SIZE))
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

/// The provenance of an upload: who and from where, no key content.
fn provenance() -> JsonObject {
    object(json!({"uploaded_by": "adm_trust", "file": "keys.jwks.json"}))
}

/// Stage A, as the wiring will run it: the upload validated against the
/// default allowed algorithms; the refusal, if any, as its upload error.
async fn upload(value: Value) -> Result<ValidatedKeyset, JwkSetError> {
    match validate_upload(value, DEFAULT_ALLOWED_ALGORITHMS).await {
        Ok(keys) => Ok(keys),
        Err(KeysetWriteError::Upload(err)) => Err(err),
        Err(other) => panic!("expected KeysetWriteError::Upload: {other:?}"),
    }
}

/// Stage B: the gated create of version `id` with `keys` and `provenance`
/// by `adm_trust` as operation `op` at `now`, committed whatever the
/// outcome.
async fn create_version(
    pool: &PgPool,
    id: &str,
    op: &str,
    now: SystemTime,
    keys: &ValidatedKeyset,
    provenance: &JsonObject,
) -> Result<Gated<TrustKeysetVersion>, KeysetWriteError> {
    let event = format!("evt_{op}");
    let mut transaction = pool.begin().await.unwrap();
    let outcome = submit_create_version(
        &mut transaction,
        &Submission {
            public_identity: TRUST_KEY,
            acknowledge_widening: true,
            operation_id: op,
            event_id: &event,
            now,
        },
        &NewKeysetVersion {
            id,
            tenant_id: TENANT,
            keyset_id: KEYSET,
            keys,
            effective_at: at(0),
            expires_at: None,
            status: Status::Enabled,
            provenance,
        },
        DEFAULT_ALLOWED_ALGORITHMS,
    )
    .await;
    transaction.commit().await.unwrap();
    outcome
}

/// The raw set `public_jwks` as version `id` through the registry floor.
fn floor_version(id: &str, public_jwks: &Value) -> NewTrustKeysetVersion {
    NewTrustKeysetVersion {
        id: id.into(),
        tenant_id: TENANT.into(),
        keyset_id: KEYSET.into(),
        public_jwks: object(public_jwks.clone()),
        fingerprint: format!("sha256:{id}"),
        effective_at: at(0),
        expires_at: None,
        status: Status::Enabled,
        provenance: provenance(),
    }
}

/// A refusal by a constraint, as its typed fields. The `Display` text is
/// never compared.
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

#[track_caller]
fn assert_not_found<T: Debug>(result: Result<T, RegistryError>) {
    assert!(
        matches!(result, Err(RegistryError::NotFound)),
        "expected NotFound: {result:?}"
    );
}

/// The `0004` floor's refusal of a set with a private member.
const PUBLIC_JWKS_REFUSAL: Refusal = Refusal {
    kind: InvariantKind::Check,
    constraint: "trust_keyset_version_public_jwks_check",
};

/// An accepted upload and what it must be stored as, written out from the
/// input keys: its keys' `kid`s, its canonical public projection and that
/// projection's fingerprint.
struct Accepted {
    id: &'static str,
    upload: Value,
    kids: &'static [&'static str],
    projection: String,
    fingerprint: &'static str,
}

/// The two accepted uploads. Each projection is the input keys written out
/// in `jwk::projection`'s canonical form: `{"keys":[…]}`, the keys sorted
/// by `kid` (the input order of the three-key set is `rsa`, `ec`, `ed`),
/// each key's members in lexicographic order, no whitespace; the members
/// `kid`, `kty`, the type's public members with their input values, and
/// `alg` only where the upload had it (`use` and `key_ops` dropped). Each
/// fingerprint is the unpadded base64url SHA-256 of that text, computed
/// outside the library (Python `hashlib.sha256` and
/// `base64.urlsafe_b64encode`, `=` stripped) and pinned here.
fn accepted_uploads() -> [Accepted; 2] {
    let (ec_x, ec_y) = P256_1G;
    [
        Accepted {
            id: "kv_one",
            upload: set(vec![good_key()]),
            kids: &["good"],
            projection: format!(
                r#"{{"keys":[{{"crv":"P-256","kid":"good","kty":"EC","x":"{P256_X}","y":"{P256_Y}"}}]}}"#
            ),
            fingerprint: "QaEpbe93pWl7PXKJD4lsM55i9Xh0IzQquiGvQYGrsRo",
        },
        Accepted {
            id: "kv_three",
            upload: set(vec![
                with(
                    with(rsa("rsa"), "use", json!("sig")),
                    "key_ops",
                    json!(["verify"]),
                ),
                with(p256("ec", P256_1G), "alg", json!("ES256")),
                with(ed25519("ed"), "use", json!("sig")),
            ]),
            kids: &["ec", "ed", "rsa"],
            projection: format!(
                concat!(
                    r#"{{"keys":["#,
                    r#"{{"alg":"ES256","crv":"P-256","kid":"ec","kty":"EC","x":"{ec_x}","y":"{ec_y}"}},"#,
                    r#"{{"crv":"Ed25519","kid":"ed","kty":"OKP","x":"{ed_x}"}},"#,
                    r#"{{"alg":"RS256","e":"AQAB","kid":"rsa","kty":"RSA","n":"{rsa_n}"}}"#,
                    r#"]}}"#,
                ),
                ec_x = ec_x,
                ec_y = ec_y,
                ed_x = ED25519_X,
                rsa_n = RSA_N,
            ),
            fingerprint: "2uCIdszkdVr_uAuweJyNtxnWIgVdhYmC6AZKS5bMJXs",
        },
    ]
}

#[tokio::test]
async fn a05_pos_public_only_jwks_upload_is_accepted() {
    let (db, pool) = upload_fixture().await;
    let mut expected = Vec::new();
    for (step, accepted) in accepted_uploads().into_iter().enumerate() {
        let Accepted {
            id,
            upload: value,
            kids,
            projection,
            fingerprint,
        } = accepted;
        let step = u64::try_from(step).unwrap();
        let keys = upload(value)
            .await
            .unwrap_or_else(|err| panic!("{id}: {err:?}"));
        // Stage A's output is the written-out projection, byte for byte,
        // and its fingerprint.
        assert_eq!(keys.public_json(), projection, "{id}");
        assert_eq!(keys.fingerprint().as_str(), fingerprint, "{id}");
        let outcome = create_version(
            &pool,
            id,
            &format!("op_pos_{step}"),
            at(10 + step),
            &keys,
            &provenance(),
        )
        .await
        .unwrap_or_else(|err| panic!("{id}: {err:?}"));
        let Gated::Applied(row) = outcome else {
            panic!("{id}: the create is not applied: {outcome:?}");
        };
        // Stored as the written-out projection and fingerprint: every key,
        // each with exactly its expected members and values.
        let stored_kids: Vec<&str> = row.public_jwks["keys"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: no keys array"))
            .iter()
            .map(|key| {
                key["kid"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{id}: a key without kid"))
            })
            .collect();
        assert_eq!(stored_kids, kids, "{id}");
        assert_eq!(
            row,
            TrustKeysetVersion {
                id: id.into(),
                tenant_id: TENANT.into(),
                keyset_id: KEYSET.into(),
                public_jwks: object(serde_json::from_str(&projection).unwrap()),
                fingerprint: fingerprint.into(),
                effective_at: at(0),
                expires_at: None,
                status: Status::Enabled,
                provenance: provenance(),
                revision: 1,
            },
            "{id}"
        );
        assert_eq!(
            registry::get_trust_keyset_version(&pool, TENANT, id)
                .await
                .unwrap(),
            row,
            "{id}"
        );
        expected.push(row);
    }
    assert_eq!(versions(&pool).await, expected);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a05_neg_upload_with_private_members_is_refused() {
    let (db, pool) = upload_fixture().await;
    let head = audit_head(&pool).await;

    // Each member alone on an otherwise public key, in each placement:
    // refused by Stage A, naming the member and the bad key's index, and by
    // the registry floor.
    let mut cases = Vec::new();
    for member in PRIVATE {
        let bad = with(p256("bad", P256_2G), member, member_value(member));
        for (placement, value, index) in placements(&bad) {
            cases.push((format!("{member}, {placement}"), value, index, member));
        }
    }
    // Real private keys: the RFC 7517 appendix A.2 EC key, the RFC 8037
    // appendix A.1 Ed25519 key, and a symmetric key.
    for (label, bad, member) in [
        (
            "RFC 7517 EC private key",
            with(p256("bad", (P256_X, P256_Y)), "d", json!(P256_D)),
            "d",
        ),
        (
            "RFC 8037 Ed25519 private key",
            with(ed25519("bad"), "d", json!(ED25519_D)),
            "d",
        ),
        (
            "oct key",
            json!({"kty": "oct", "kid": "bad", "k": P256_D}),
            "k",
        ),
    ] {
        for (placement, value, index) in placements(&bad) {
            cases.push((format!("{label}, {placement}"), value, index, member));
        }
    }

    for (n, (label, value, index, member)) in cases.into_iter().enumerate() {
        assert_eq!(
            upload(value.clone()).await.map(drop),
            Err(JwkSetError::Key {
                index,
                error: JwkError::PrivateMember(member),
            }),
            "{label}"
        );
        let id = format!("kv_floor_{n}");
        assert_eq!(
            refusal(
                registry::test_support::create_trust_keyset_version(
                    &pool,
                    &floor_version(&id, &value)
                )
                .await
            ),
            PUBLIC_JWKS_REFUSAL,
            "{label}"
        );
        assert_not_found(registry::get_trust_keyset_version(&pool, TENANT, &id).await);
        assert_eq!(versions(&pool).await, [], "{label}");
        assert_eq!(audit_head(&pool).await, head, "{label}");
    }

    // A good upload whose provenance carries a private member, nested in an
    // array: refused by Stage B before any statement.
    let keys = upload(set(vec![good_key()])).await.unwrap();
    for (step, member) in PRIVATE.into_iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        let jwk = with(json!({"kty": "EC"}), member, member_value(member));
        let carried = object(json!({
            "uploaded_by": "adm_trust",
            "files": [{"name": "keys.jwks.json", "jwk": jwk}],
        }));
        let outcome = create_version(
            &pool,
            "kv_provenance",
            &format!("op_prov_{step}"),
            at(10 + step),
            &keys,
            &carried,
        )
        .await;
        assert!(
            matches!(outcome, Err(KeysetWriteError::PrivateMemberInProvenance)),
            "{member}: {outcome:?}"
        );
        assert_not_found(registry::get_trust_keyset_version(&pool, TENANT, "kv_provenance").await);
        assert_eq!(versions(&pool).await, [], "{member}");
        assert_eq!(audit_head(&pool).await, head, "{member}");
    }

    // The control: the good key alone, with a clean provenance, is written.
    let outcome = create_version(&pool, "kv_good", "op_good", at(100), &keys, &provenance())
        .await
        .unwrap();
    let Gated::Applied(row) = outcome else {
        panic!("the control is not applied: {outcome:?}");
    };
    assert_eq!(versions(&pool).await, [row]);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a05_neg_upload_with_key_reference_members_is_refused() {
    let (db, pool) = upload_fixture().await;
    let head = audit_head(&pool).await;
    for member in KEY_REFERENCE {
        let bad = with(p256("bad", P256_2G), member, member_value(member));
        for (placement, value, index) in placements(&bad) {
            assert_eq!(
                upload(value).await.map(drop),
                Err(JwkSetError::Key {
                    index,
                    error: JwkError::KeyReference(member),
                }),
                "{member}, {placement}"
            );
            assert_eq!(versions(&pool).await, [], "{member}, {placement}");
            assert_eq!(audit_head(&pool).await, head, "{member}, {placement}");
        }
    }
    db.drop([pool]).await;
}

// Egress.

/// The discovery URL an enabled `oidc_discovery` entry lists.
const DISCOVERY: &str = "https://idp.a.example/.well-known/openid-configuration";
/// A second one, the target of the accepted change.
const DISCOVERY_NEXT: &str = "https://idp-next.a.example/.well-known/openid-configuration";
/// The TokenReview endpoint an enabled `token_review` entry lists.
const REVIEW: &str = "https://k8s.a.example:6443/";
/// A second one, the target of the accepted change.
const REVIEW_NEXT: &str = "https://k8s-next.a.example:6443/";

const PURPOSES: [&str; 3] = ["oidc_discovery", "jwks", "token_review"];

/// The two destination members of a trust source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Member {
    /// `discovery_url` of an `oidc_discovery` source.
    Discovery,
    /// `token_review_endpoint` of a `kubernetes_token_review` source.
    TokenReview,
}

const MEMBERS: [Member; 2] = [Member::Discovery, Member::TokenReview];

/// How a missing-entry case's destination is seeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seed {
    /// No entry for it (the member's own entry, for another destination,
    /// may exist).
    Nothing,
    /// Enabled entries of both other purposes, for exactly it.
    OtherPurposes,
    /// A disabled entry of the member's purpose, for exactly it.
    Disabled,
}

impl Member {
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

    fn refusal(self) -> Refusal {
        Refusal {
            kind: InvariantKind::EgressEntryEnabled,
            constraint: self.constraint(),
        }
    }

    /// The destination an enabled entry lists, and the second one.
    fn allowed(self) -> (&'static str, &'static str) {
        match self {
            Self::Discovery => (DISCOVERY, DISCOVERY_NEXT),
            Self::TokenReview => (REVIEW, REVIEW_NEXT),
        }
    }

    /// The destinations with no enabled matching entry. Every one but the
    /// last two is a near miss of the listed destination.
    fn missing(self) -> &'static [(&'static str, &'static str, Seed)] {
        match self {
            Self::Discovery => &[
                (
                    "no entry",
                    "https://none.a.example/.well-known/openid-configuration",
                    Seed::Nothing,
                ),
                (
                    "another host",
                    "https://idp.b.example/.well-known/openid-configuration",
                    Seed::Nothing,
                ),
                (
                    "another port",
                    "https://idp.a.example:8443/.well-known/openid-configuration",
                    Seed::Nothing,
                ),
                (
                    "another path",
                    "https://idp.a.example/.well-known/oauth-authorization-server",
                    Seed::Nothing,
                ),
                ("a prefix", "https://idp.a.example/", Seed::Nothing),
                (
                    "extended",
                    "https://idp.a.example/.well-known/openid-configuration/",
                    Seed::Nothing,
                ),
                (
                    "another case",
                    "https://IDP.a.example/.well-known/openid-configuration",
                    Seed::Nothing,
                ),
                (
                    "another purpose",
                    "https://purpose.a.example/.well-known/openid-configuration",
                    Seed::OtherPurposes,
                ),
                (
                    "a disabled entry",
                    "https://disabled.a.example/.well-known/openid-configuration",
                    Seed::Disabled,
                ),
            ],
            Self::TokenReview => &[
                ("no entry", "https://none.a.example:6443/", Seed::Nothing),
                ("another host", "https://k8s.b.example:6443/", Seed::Nothing),
                ("another port", "https://k8s.a.example:6444/", Seed::Nothing),
                ("a prefix", "https://k8s.a.example:6443", Seed::Nothing),
                ("extended", "https://k8s.a.example:6443/api", Seed::Nothing),
                ("another case", "https://K8S.a.example:6443/", Seed::Nothing),
                (
                    "another purpose",
                    "https://purpose.a.example:6443/",
                    Seed::OtherPurposes,
                ),
                (
                    "a disabled entry",
                    "https://disabled.a.example:6443/",
                    Seed::Disabled,
                ),
            ],
        }
    }

    /// An enabled source of this member's kind in [`TENANT`] with ID
    /// `src_<tag>` and its member set to `destination`.
    fn source(self, tag: &str, destination: &str) -> NewTrustSource {
        let base = NewTrustSource {
            id: format!("src_{tag}"),
            tenant_id: TENANT.into(),
            name: format!("source-{tag}"),
            kind: TrustSourceKind::OidcDiscovery,
            exact_issuer: "https://idp.a.example".into(),
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
            proof_bounds: object(json!({"max_ttl_s": 600})),
            assertion_profile: AssertionProfile::OnDemandJwt,
            stale_revocation_acknowledged: None,
            replay_mode: ReplayMode::SingleUse,
            status: Status::Enabled,
        };
        match self {
            Self::Discovery => NewTrustSource {
                discovery_url: Some(destination.into()),
                algorithms: Some(strings(&["RS256"])),
                ..base
            },
            Self::TokenReview => NewTrustSource {
                kind: TrustSourceKind::KubernetesTokenReview,
                exact_issuer: "https://kubernetes.default.svc.cluster.local".into(),
                cluster_id: Some(format!("cluster_{tag}")),
                token_review_endpoint: Some(destination.into()),
                ca_bundle_ref: Some("cluster-a-ca".into()),
                ca_fingerprint: Some("sha256:cluster-a-ca".into()),
                reviewer_credential_ref: Some("cluster-a-reviewer".into()),
                review_timeout_ms: Some(5000),
                proof_bounds: object(json!({"max_ttl_s": 3600})),
                assertion_profile: AssertionProfile::ProjectedServiceAccount,
                replay_mode: ReplayMode::Reusable,
                ..base
            },
        }
    }

    /// `source` with this member set to `destination`, at `revision`.
    fn moved(self, source: &TrustSource, destination: &str, revision: i64) -> TrustSource {
        let source = TrustSource {
            revision,
            ..source.clone()
        };
        match self {
            Self::Discovery => TrustSource {
                discovery_url: Some(destination.into()),
                ..source
            },
            Self::TokenReview => TrustSource {
                token_review_endpoint: Some(destination.into()),
                ..source
            },
        }
    }

    /// `changes` with this member set to `destination`.
    fn pointed(self, changes: TrustSourceChanges, destination: &str) -> TrustSourceChanges {
        match self {
            Self::Discovery => TrustSourceChanges {
                discovery_url: Some(destination.into()),
                ..changes
            },
            Self::TokenReview => TrustSourceChanges {
                token_review_endpoint: Some(destination.into()),
                ..changes
            },
        }
    }
}

/// The seed of the next egress writer call's [`SequentialIds`], so that no
/// two calls give the same entry or event ID.
static NEXT_SEED: AtomicU64 = AtomicU64::new(0x0a05_0000);

/// An egress writer call's request by `adm_first`, with IDs of their own.
fn writer_request(ids: &SequentialIds) -> AdminRequest<'_> {
    AdminRequest {
        public_identity: FIRST_KEY,
        ids,
        now: at(3),
    }
}

fn writer_ids() -> SequentialIds {
    SequentialIds::with_seed(NEXT_SEED.fetch_add(1, Ordering::Relaxed))
}

/// Creates the egress allowlist entry of `purpose` for `destination` with
/// `status` through the writer, acknowledged as widening, with the toggle
/// off (see "Egress allowlist entries" in the module docs); it fails on a
/// duplicate or with the toggle on.
async fn seed_entry(pool: &PgPool, purpose: &str, destination: &str, status: Status) {
    let ids = writer_ids();
    let new = EgressEntryCreate {
        purpose: purpose.parse::<EgressPurpose>().unwrap(),
        exact_destination: destination.into(),
        status,
    };
    let mut transaction = pool.begin().await.unwrap();
    admin::create_egress_entry(&mut transaction, &writer_request(&ids), &new, true)
        .await
        .unwrap_or_else(|err| panic!("{status:?} {purpose} entry: {err:?}"));
    transaction.commit().await.unwrap();
}

/// Disables the enabled entry of `purpose` for `destination` through the
/// writer, at its current revision (see "Egress allowlist entries").
async fn disable_entry(pool: &PgPool, purpose: &str, destination: &str) {
    let entries = registry::list_egress_allowlist_entries(pool, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap();
    assert!(entries.len() < usize::try_from(MAX_PAGE_SIZE).unwrap());
    let entry = entries
        .into_iter()
        .find(|entry| entry.purpose.as_str() == purpose && entry.exact_destination == destination)
        .unwrap_or_else(|| panic!("no {purpose} entry"));
    assert_eq!(entry.status, Status::Enabled, "the {purpose} entry");
    let ids = writer_ids();
    let mut transaction = pool.begin().await.unwrap();
    admin::disable_egress_entry(
        &mut transaction,
        &writer_request(&ids),
        &entry.id,
        entry.revision,
    )
    .await
    .unwrap_or_else(|err| panic!("disable the {purpose} entry: {err:?}"));
    transaction.commit().await.unwrap();
}

/// [`base_fixture`], the instance [`bootstrap`]ped, then the egress
/// entries through the writer: enabled entries of each member's purpose for
/// both its allowed destinations, and for each missing-entry case its seed.
async fn egress_fixture() -> (TestDb, PgPool) {
    let (db, pool) = base_fixture().await;
    bootstrap(&pool).await;
    for member in MEMBERS {
        let (allowed, next) = member.allowed();
        for destination in [allowed, next] {
            seed_entry(&pool, member.purpose(), destination, Status::Enabled).await;
        }
        for &(_, destination, seed) in member.missing() {
            match seed {
                Seed::Nothing => {}
                Seed::OtherPurposes => {
                    for purpose in PURPOSES.into_iter().filter(|&p| p != member.purpose()) {
                        seed_entry(&pool, purpose, destination, Status::Enabled).await;
                    }
                }
                Seed::Disabled => {
                    seed_entry(&pool, member.purpose(), destination, Status::Disabled).await;
                }
            }
        }
    }
    (db, pool)
}

/// [`egress_fixture`] and [`enrolled`]: the gated source writes of
/// `adm_trust`, applied at once (`gate` off) or pending until `adm_sec`
/// approves them (`gate` on).
async fn gated_egress_fixture(gate: bool) -> (TestDb, PgPool) {
    let (db, pool) = egress_fixture().await;
    enrolled(&pool, gate).await;
    (db, pool)
}

/// A refusal of the gated source write path, as its typed fields.
#[derive(Debug, PartialEq, Eq)]
enum GatedRefusal {
    /// `SourceWriteError::InvalidDestination { member }`.
    InvalidDestination(&'static str),
    /// `SourceWriteError::EgressNotAllowed { member }`.
    EgressNotAllowed(&'static str),
}

#[track_caller]
fn gated_refusal(err: SourceWriteError) -> GatedRefusal {
    match err {
        SourceWriteError::InvalidDestination { member } => GatedRefusal::InvalidDestination(member),
        SourceWriteError::EgressNotAllowed { member } => GatedRefusal::EgressNotAllowed(member),
        other => panic!("expected InvalidDestination or EgressNotAllowed: {other:?}"),
    }
}

impl Member {
    /// The member's name in the gated path's errors, written out here.
    fn name(self) -> &'static str {
        match self {
            Self::Discovery => "discovery_url",
            Self::TokenReview => "token_review_endpoint",
        }
    }

    /// The gated path's refusal of the missing-entry case `label`. Its
    /// syntax rule refuses a destination that is not in canonical form
    /// first (`trust::source`, "Syntax"): another letter case of the host
    /// (the parser lowercases it) and a TokenReview URL without its path
    /// (the parser adds `/`). Every other case is canonical and has no
    /// enabled matching entry.
    fn gated_refusal(self, label: &str) -> GatedRefusal {
        match (self, label) {
            (_, "another case") | (Self::TokenReview, "a prefix") => {
                GatedRefusal::InvalidDestination(self.name())
            }
            _ => GatedRefusal::EgressNotAllowed(self.name()),
        }
    }
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

/// The tenant's trust sources, every column.
async fn sources(pool: &PgPool) -> Vec<TrustSource> {
    registry::list_trust_sources(pool, TENANT, Page::first(MAX_PAGE_SIZE))
        .await
        .unwrap()
}

/// `source` updated through the registry floor from its revision.
async fn update(
    pool: &PgPool,
    source: &TrustSource,
    changes: &TrustSourceChanges,
) -> Result<TrustSource, RegistryError> {
    registry::test_support::update_trust_source(pool, TENANT, &source.id, source.revision, changes)
        .await
}

#[tokio::test]
async fn a05_pos_destination_with_an_enabled_matching_egress_entry_is_accepted() {
    let (db, pool) = egress_fixture().await;
    let mut expected = Vec::new();
    for member in MEMBERS {
        let (allowed, next) = member.allowed();
        // Create: written and read back exactly, at revision 1.
        let new = member.source(&format!("{member:?}").to_lowercase(), allowed);
        let written = registry::test_support::create_trust_source(&pool, &new)
            .await
            .unwrap_or_else(|err| panic!("{member:?}: {err:?}"));
        assert_eq!(written, stored(&new, 1), "{member:?}");
        assert_eq!(
            registry::get_trust_source(&pool, TENANT, &new.id)
                .await
                .unwrap(),
            written,
            "{member:?}"
        );

        // Change to another listed destination: revision 2.
        let moved = update(&pool, &written, &member.pointed(changes(&written), next))
            .await
            .unwrap_or_else(|err| panic!("{member:?}: {err:?}"));
        assert_eq!(moved, member.moved(&written, next, 2), "{member:?}");

        // Its entry disabled: writes that leave the member unchanged are
        // still accepted (IR-152), a rename, a disable and a re-enable.
        disable_entry(&pool, member.purpose(), next).await;
        let renamed = update(
            &pool,
            &moved,
            &TrustSourceChanges {
                name: format!("{}-renamed", moved.name),
                ..changes(&moved)
            },
        )
        .await
        .unwrap_or_else(|err| panic!("{member:?} rename: {err:?}"));
        assert_eq!(
            renamed,
            TrustSource {
                name: format!("{}-renamed", moved.name),
                revision: 3,
                ..moved.clone()
            },
            "{member:?}"
        );
        let disabled = update(
            &pool,
            &renamed,
            &TrustSourceChanges {
                status: Status::Disabled,
                ..changes(&renamed)
            },
        )
        .await
        .unwrap_or_else(|err| panic!("{member:?} disable: {err:?}"));
        assert_eq!(
            disabled,
            TrustSource {
                status: Status::Disabled,
                revision: 4,
                ..renamed.clone()
            },
            "{member:?}"
        );
        let enabled = update(
            &pool,
            &disabled,
            &TrustSourceChanges {
                status: Status::Enabled,
                ..changes(&disabled)
            },
        )
        .await
        .unwrap_or_else(|err| panic!("{member:?} re-enable: {err:?}"));
        assert_eq!(
            enabled,
            TrustSource {
                revision: 5,
                ..renamed.clone()
            },
            "{member:?}"
        );
        expected.push(enabled);
    }
    expected.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(sources(&pool).await, expected);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a05_neg_source_create_without_an_enabled_matching_egress_entry_is_refused() {
    let (db, pool) = egress_fixture().await;
    let before = sources(&pool).await;
    for member in MEMBERS {
        for (n, &(label, destination, _)) in member.missing().iter().enumerate() {
            for status in [Status::Enabled, Status::Disabled] {
                let new = NewTrustSource {
                    status,
                    ..member.source(&format!("{member:?}_{n}").to_lowercase(), destination)
                };
                assert_eq!(
                    refusal(registry::test_support::create_trust_source(&pool, &new).await),
                    member.refusal(),
                    "{member:?}, {label}, {status:?}"
                );
                assert_not_found(registry::get_trust_source(&pool, TENANT, &new.id).await);
                assert_eq!(
                    sources(&pool).await,
                    before,
                    "{member:?}, {label}, {status:?}"
                );
            }
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a05_neg_source_change_without_an_enabled_matching_egress_entry_is_refused() {
    let (db, pool) = egress_fixture().await;
    let mut stored_sources = Vec::new();
    for member in MEMBERS {
        let new = member.source(&format!("{member:?}").to_lowercase(), member.allowed().0);
        stored_sources.push((
            member,
            registry::test_support::create_trust_source(&pool, &new)
                .await
                .unwrap_or_else(|err| panic!("{member:?}: {err:?}")),
        ));
    }
    let before = sources(&pool).await;
    for (member, source) in &stored_sources {
        for &(label, destination, _) in member.missing() {
            let pointed = member.pointed(changes(source), destination);
            for (what, update_to) in [
                ("alone", pointed.clone()),
                (
                    "with a disable",
                    TrustSourceChanges {
                        status: Status::Disabled,
                        ..pointed.clone()
                    },
                ),
                (
                    "with a rename",
                    TrustSourceChanges {
                        name: format!("{}-moved", source.name),
                        ..pointed
                    },
                ),
            ] {
                assert_eq!(
                    refusal(update(&pool, source, &update_to).await),
                    member.refusal(),
                    "{member:?}, {label}, {what}"
                );
                assert_eq!(sources(&pool).await, before, "{member:?}, {label}, {what}");
            }
        }
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a05_neg_gated_source_write_without_an_enabled_matching_egress_entry_is_refused() {
    let (db, pool) = gated_egress_fixture(false).await;
    let mut stored_sources = Vec::new();
    for member in MEMBERS {
        let new = member.source(&format!("{member:?}").to_lowercase(), member.allowed().0);
        stored_sources.push((
            member,
            registry::test_support::create_trust_source(&pool, &new)
                .await
                .unwrap_or_else(|err| panic!("{member:?}: {err:?}")),
        ));
    }
    let before = sources(&pool).await;
    let head = audit_head(&pool).await;
    let mut step = 0_u64;

    // The gated create, enabled or disabled.
    for member in MEMBERS {
        for (n, &(label, destination, _)) in member.missing().iter().enumerate() {
            for status in [Status::Enabled, Status::Disabled] {
                step += 1;
                let new = NewTrustSource {
                    status,
                    ..member.source(&format!("gated_{member:?}_{n}").to_lowercase(), destination)
                };
                let outcome =
                    gated_create(&pool, &format!("op_c{step}"), at(10 + step), &new).await;
                let err = outcome
                    .map(drop)
                    .expect_err(&format!("{member:?}, {label}, {status:?}: accepted"));
                assert_eq!(
                    gated_refusal(err),
                    member.gated_refusal(label),
                    "{member:?}, {label}, {status:?}"
                );
                assert_not_found(registry::get_trust_source(&pool, TENANT, &new.id).await);
                assert_eq!(
                    sources(&pool).await,
                    before,
                    "{member:?}, {label}, {status:?}"
                );
                assert_eq!(
                    audit_head(&pool).await,
                    head,
                    "{member:?}, {label}, {status:?}"
                );
            }
        }
    }

    // The gated update of a stored source: alone, with a disable, with a
    // rename.
    for (member, source) in &stored_sources {
        for &(label, destination, _) in member.missing() {
            let pointed = member.pointed(changes(source), destination);
            for (what, update_to) in [
                ("alone", pointed.clone()),
                (
                    "with a disable",
                    TrustSourceChanges {
                        status: Status::Disabled,
                        ..pointed.clone()
                    },
                ),
                (
                    "with a rename",
                    TrustSourceChanges {
                        name: format!("{}-moved", source.name),
                        ..pointed
                    },
                ),
            ] {
                step += 1;
                let outcome = gated_update(
                    &pool,
                    &format!("op_u{step}"),
                    at(10 + step),
                    source,
                    &update_to,
                )
                .await;
                let err = outcome
                    .map(drop)
                    .expect_err(&format!("{member:?}, {label}, {what}: accepted"));
                assert_eq!(
                    gated_refusal(err),
                    member.gated_refusal(label),
                    "{member:?}, {label}, {what}"
                );
                assert_eq!(sources(&pool).await, before, "{member:?}, {label}, {what}");
                assert_eq!(audit_head(&pool).await, head, "{member:?}, {label}, {what}");
            }
        }
    }

    // The control: the gated create to a listed destination is applied.
    for member in MEMBERS {
        step += 1;
        let new = member.source(
            &format!("gated_{member:?}_ok").to_lowercase(),
            member.allowed().1,
        );
        let outcome = gated_create(&pool, &format!("op_ok{step}"), at(10 + step), &new)
            .await
            .unwrap_or_else(|err| panic!("{member:?}: {err:?}"));
        let Gated::Applied(row) = outcome else {
            panic!("{member:?}: the create is not applied: {outcome:?}");
        };
        assert_eq!(row, stored(&new, 1), "{member:?}");
    }
    db.drop([pool]).await;
}

#[tokio::test]
async fn a05_neg_approval_after_its_egress_entry_is_disabled_is_refused() {
    let (db, pool) = gated_egress_fixture(true).await;
    let before = sources(&pool).await;
    let mut expected = before.clone();
    for (step, member) in MEMBERS.into_iter().enumerate() {
        let step = u64::try_from(step).unwrap();
        let (allowed, next) = member.allowed();

        // A create on `next` goes pending while its entry is enabled; the
        // entry is then disabled; the approval is refused.
        let refused = member.source(&format!("{member:?}_refused").to_lowercase(), next);
        let op = format!("op_refused_{step}");
        let outcome = gated_create(&pool, &op, at(10 + step), &refused)
            .await
            .unwrap_or_else(|err| panic!("{member:?}: {err:?}"));
        let Gated::Pending(pending) = outcome else {
            panic!("{member:?}: the create is not pending: {outcome:?}");
        };
        assert_eq!(pending.kind, OperationKind::TrustSourceCreate, "{member:?}");
        disable_entry(&pool, member.purpose(), next).await;
        let head = audit_head(&pool).await;
        match approve(
            &pool,
            ApprovalScope::Tenant(TENANT),
            &pending,
            at(100 + step),
        )
        .await
        {
            Err(ApprovalError::Source(err)) => assert_eq!(
                gated_refusal(err),
                GatedRefusal::EgressNotAllowed(member.name()),
                "{member:?}"
            ),
            other => panic!("{member:?}: expected ApprovalError::Source: {other:?}"),
        }
        assert!(still_pending(&pool, &op).await, "{member:?}");
        assert_eq!(audit_head(&pool).await, head, "{member:?}");
        assert_not_found(registry::get_trust_source(&pool, TENANT, &refused.id).await);
        assert_eq!(sources(&pool).await, expected, "{member:?}");

        // The control: the same flow on `allowed`, whose entry stays
        // enabled, is approved and written as requested.
        let approved = member.source(&format!("{member:?}_approved").to_lowercase(), allowed);
        let outcome = gated_create(
            &pool,
            &format!("op_approved_{step}"),
            at(20 + step),
            &approved,
        )
        .await
        .unwrap_or_else(|err| panic!("{member:?}: {err:?}"));
        let Gated::Pending(pending) = outcome else {
            panic!("{member:?}: the control is not pending: {outcome:?}");
        };
        approve(
            &pool,
            ApprovalScope::Tenant(TENANT),
            &pending,
            at(200 + step),
        )
        .await
        .unwrap_or_else(|err| panic!("{member:?}: {err:?}"));
        let written = registry::get_trust_source(&pool, TENANT, &approved.id)
            .await
            .unwrap();
        assert_eq!(written, stored(&approved, 1), "{member:?}");
        expected.push(written);
        expected.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(sources(&pool).await, expected, "{member:?}");
    }
    db.drop([pool]).await;
}
