//! The plans of the two trust source kinds (proposal section 2, "The
//! plan"): what a pending `trust_source_create` or `trust_source_update`
//! stores, written by [`crate::trust::source`]'s `submit_*` from typed
//! input and read back by the approve. Each plan holds exactly its members,
//! with their JSON types; a stored plan of any other shape is
//! [`super::ApprovalError::PlanIntegrity`] at the approve.
//!
//! The members are named as the fields of [`NewTrustSource`] and
//! [`TrustSourceChanges`] (inferred). `proof_bounds`, free-form operator
//! JSON, is stored as its JSON text (`serde_json`'s compact form, members
//! sorted byte-wise since its map is ordered; inferred, as a keyset create's
//! provenance), so the `jsonb` column returns it exactly, whatever numbers
//! it holds. An optional member that is not set is JSON `null`;
//! `review_timeout_ms` is an integer in the `i32` range.
//!
//! No member holds a secret: `ca_bundle_ref` and `reviewer_credential_ref`
//! are references that resolve in the tenant's secret namespace (IR-034),
//! not the secrets (migrations README, the `0005` service rules).

use serde_json::Value;

use super::PLAN_REQUESTER_CREDENTIAL_ID;
use crate::persistence::registry::{
    AssertionProfile, JsonObject, NewTrustSource, ReplayMode, Status, TrustSource,
    TrustSourceChanges, TrustSourceKind,
};

const ID: &str = "id";
const TENANT_ID: &str = "tenant_id";
const KIND: &str = "kind";
const JWKS_KEYSET_ID: &str = "jwks_keyset_id";
const CLUSTER_ID: &str = "cluster_id";
const SOURCE_ID: &str = "source_id";
const CHANGED: &str = "changed";

const NAME: &str = "name";
const EXACT_ISSUER: &str = "exact_issuer";
const DISCOVERY_URL: &str = "discovery_url";
const TOKEN_REVIEW_ENDPOINT: &str = "token_review_endpoint";
const CA_BUNDLE_REF: &str = "ca_bundle_ref";
const CA_FINGERPRINT: &str = "ca_fingerprint";
const REVIEWER_CREDENTIAL_REF: &str = "reviewer_credential_ref";
const REVIEW_TIMEOUT_MS: &str = "review_timeout_ms";
const AUDIENCES: &str = "audiences";
const ALGORITHMS: &str = "algorithms";
const PROOF_BOUNDS: &str = "proof_bounds";
const ASSERTION_PROFILE: &str = "assertion_profile";
const STALE_REVOCATION_ACKNOWLEDGED: &str = "stale_revocation_acknowledged";
const REPLAY_MODE: &str = "replay_mode";
const STATUS: &str = "status";

/// The fifteen members of [`TrustSourceChanges`], sorted byte-wise: the
/// names a plan's `changed` may hold.
pub(crate) const CHANGE_MEMBERS: [&str; 15] = [
    ALGORITHMS,
    ASSERTION_PROFILE,
    AUDIENCES,
    CA_BUNDLE_REF,
    CA_FINGERPRINT,
    DISCOVERY_URL,
    EXACT_ISSUER,
    NAME,
    PROOF_BOUNDS,
    REPLAY_MODE,
    REVIEW_TIMEOUT_MS,
    REVIEWER_CREDENTIAL_REF,
    STALE_REVOCATION_ACKNOWLEDGED,
    STATUS,
    TOKEN_REVIEW_ENDPOINT,
];

/// The members of `changes` whose value differs from `stored`'s, sorted
/// byte-wise: an update plan's `changed` (section 2). `proof_bounds` is
/// compared as JSON values (`serde_json`'s equality: a key order does not
/// count, a number spelled as an integer and as a float does).
pub(crate) fn changed_members(
    stored: &TrustSource,
    changes: &TrustSourceChanges,
) -> Vec<&'static str> {
    let differs = [
        (ALGORITHMS, stored.algorithms != changes.algorithms),
        (
            ASSERTION_PROFILE,
            stored.assertion_profile != changes.assertion_profile,
        ),
        (AUDIENCES, stored.audiences != changes.audiences),
        (CA_BUNDLE_REF, stored.ca_bundle_ref != changes.ca_bundle_ref),
        (
            CA_FINGERPRINT,
            stored.ca_fingerprint != changes.ca_fingerprint,
        ),
        (DISCOVERY_URL, stored.discovery_url != changes.discovery_url),
        (EXACT_ISSUER, stored.exact_issuer != changes.exact_issuer),
        (NAME, stored.name != changes.name),
        (PROOF_BOUNDS, stored.proof_bounds != changes.proof_bounds),
        (REPLAY_MODE, stored.replay_mode != changes.replay_mode),
        (
            REVIEW_TIMEOUT_MS,
            stored.review_timeout_ms != changes.review_timeout_ms,
        ),
        (
            REVIEWER_CREDENTIAL_REF,
            stored.reviewer_credential_ref != changes.reviewer_credential_ref,
        ),
        (
            STALE_REVOCATION_ACKNOWLEDGED,
            stored.stale_revocation_acknowledged != changes.stale_revocation_acknowledged,
        ),
        (STATUS, stored.status != changes.status),
        (
            TOKEN_REVIEW_ENDPOINT,
            stored.token_review_endpoint != changes.token_review_endpoint,
        ),
    ];
    differs
        .into_iter()
        .filter_map(|(name, differs)| differs.then_some(name))
        .collect()
}

/// The plan of a `trust_source_create` (section 2): the requester's
/// credential and the twenty members of [`NewTrustSource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreateSourcePlan {
    pub(crate) requester_credential_id: String,
    /// Every member but `proof_bounds`, which is [`Self::proof_bounds`].
    source: SourceFields,
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) kind: TrustSourceKind,
    pub(crate) jwks_keyset_id: Option<String>,
    pub(crate) cluster_id: Option<String>,
}

/// The plan of a `trust_source_update` (section 2): the requester's
/// credential, the source's ID, the fifteen members of
/// [`TrustSourceChanges`], and `changed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateSourcePlan {
    pub(crate) requester_credential_id: String,
    pub(crate) source_id: String,
    source: SourceFields,
    /// The members that differed from the stored row at the request,
    /// sorted byte-wise, without repeats (for the reviewer).
    pub(crate) changed: Vec<String>,
}

/// The fifteen members a create and an update share, the mutable columns.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFields {
    name: String,
    exact_issuer: String,
    discovery_url: Option<String>,
    token_review_endpoint: Option<String>,
    ca_bundle_ref: Option<String>,
    ca_fingerprint: Option<String>,
    reviewer_credential_ref: Option<String>,
    review_timeout_ms: Option<i32>,
    audiences: Vec<String>,
    algorithms: Option<Vec<String>>,
    /// The JSON text of the object (see the module docs).
    proof_bounds: String,
    assertion_profile: AssertionProfile,
    stale_revocation_acknowledged: Option<bool>,
    replay_mode: ReplayMode,
    status: Status,
}

/// An optional text as JSON: a string or `null`.
fn optional_text(value: Option<&String>) -> Value {
    value.map_or(Value::Null, |text| Value::String(text.clone()))
}

/// A list of texts as a JSON array of strings.
fn texts(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

/// A JSON array of strings, or `None`.
fn read_texts(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// A string or `null`, or `None` (another type) wrapped in the outer
/// `Option`.
fn read_optional_text(value: &Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        Value::String(text) => Some(Some(text.clone())),
        _ => None,
    }
}

impl SourceFields {
    fn insert_into(&self, plan: &mut JsonObject) {
        let members = [
            (NAME, Value::String(self.name.clone())),
            (EXACT_ISSUER, Value::String(self.exact_issuer.clone())),
            (DISCOVERY_URL, optional_text(self.discovery_url.as_ref())),
            (
                TOKEN_REVIEW_ENDPOINT,
                optional_text(self.token_review_endpoint.as_ref()),
            ),
            (CA_BUNDLE_REF, optional_text(self.ca_bundle_ref.as_ref())),
            (CA_FINGERPRINT, optional_text(self.ca_fingerprint.as_ref())),
            (
                REVIEWER_CREDENTIAL_REF,
                optional_text(self.reviewer_credential_ref.as_ref()),
            ),
            (
                REVIEW_TIMEOUT_MS,
                self.review_timeout_ms.map_or(Value::Null, Value::from),
            ),
            (AUDIENCES, texts(&self.audiences)),
            (
                ALGORITHMS,
                self.algorithms.as_deref().map_or(Value::Null, texts),
            ),
            (PROOF_BOUNDS, Value::String(self.proof_bounds.clone())),
            (
                ASSERTION_PROFILE,
                Value::String(self.assertion_profile.as_str().into()),
            ),
            (
                STALE_REVOCATION_ACKNOWLEDGED,
                self.stale_revocation_acknowledged
                    .map_or(Value::Null, Value::Bool),
            ),
            (REPLAY_MODE, Value::String(self.replay_mode.as_str().into())),
            (STATUS, Value::String(self.status.as_str().into())),
        ];
        for (name, value) in members {
            plan.insert(name.into(), value);
        }
    }

    /// The fifteen members of a stored plan, with their types, or `None`.
    fn from_plan(plan: &JsonObject) -> Option<Self> {
        let text = |name: &str| plan.get(name)?.as_str().map(str::to_owned);
        let optional = |name: &str| read_optional_text(plan.get(name)?);
        let review_timeout_ms = match plan.get(REVIEW_TIMEOUT_MS)? {
            Value::Null => None,
            value => Some(i32::try_from(value.as_i64()?).ok()?),
        };
        let algorithms = match plan.get(ALGORITHMS)? {
            Value::Null => None,
            value => Some(read_texts(value)?),
        };
        let stale_revocation_acknowledged = match plan.get(STALE_REVOCATION_ACKNOWLEDGED)? {
            Value::Null => None,
            value => Some(value.as_bool()?),
        };
        let proof_bounds = text(PROOF_BOUNDS)?;
        serde_json::from_str::<JsonObject>(&proof_bounds).ok()?;
        Some(Self {
            name: text(NAME)?,
            exact_issuer: text(EXACT_ISSUER)?,
            discovery_url: optional(DISCOVERY_URL)?,
            token_review_endpoint: optional(TOKEN_REVIEW_ENDPOINT)?,
            ca_bundle_ref: optional(CA_BUNDLE_REF)?,
            ca_fingerprint: optional(CA_FINGERPRINT)?,
            reviewer_credential_ref: optional(REVIEWER_CREDENTIAL_REF)?,
            review_timeout_ms,
            audiences: read_texts(plan.get(AUDIENCES)?)?,
            algorithms,
            proof_bounds,
            assertion_profile: text(ASSERTION_PROFILE)?.parse().ok()?,
            stale_revocation_acknowledged,
            replay_mode: text(REPLAY_MODE)?.parse().ok()?,
            status: text(STATUS)?.parse().ok()?,
        })
    }

    /// The proof bounds object; a plan from [`Self::from_plan`] always has
    /// one.
    fn proof_bounds(&self) -> Option<JsonObject> {
        serde_json::from_str(&self.proof_bounds).ok()
    }
}

impl CreateSourcePlan {
    /// The plan of a create of `new` by the credential
    /// `requester_credential_id`.
    pub(crate) fn new(requester_credential_id: &str, new: &NewTrustSource) -> Self {
        Self {
            requester_credential_id: requester_credential_id.into(),
            source: SourceFields {
                name: new.name.clone(),
                exact_issuer: new.exact_issuer.clone(),
                discovery_url: new.discovery_url.clone(),
                token_review_endpoint: new.token_review_endpoint.clone(),
                ca_bundle_ref: new.ca_bundle_ref.clone(),
                ca_fingerprint: new.ca_fingerprint.clone(),
                reviewer_credential_ref: new.reviewer_credential_ref.clone(),
                review_timeout_ms: new.review_timeout_ms,
                audiences: new.audiences.clone(),
                algorithms: new.algorithms.clone(),
                proof_bounds: Value::Object(new.proof_bounds.clone()).to_string(),
                assertion_profile: new.assertion_profile,
                stale_revocation_acknowledged: new.stale_revocation_acknowledged,
                replay_mode: new.replay_mode,
                status: new.status,
            },
            id: new.id.clone(),
            tenant_id: new.tenant_id.clone(),
            kind: new.kind,
            jwks_keyset_id: new.jwks_keyset_id.clone(),
            cluster_id: new.cluster_id.clone(),
        }
    }

    pub(crate) fn to_plan(&self) -> JsonObject {
        let mut plan = JsonObject::from_iter([
            (
                PLAN_REQUESTER_CREDENTIAL_ID.into(),
                Value::String(self.requester_credential_id.clone()),
            ),
            (ID.into(), Value::String(self.id.clone())),
            (TENANT_ID.into(), Value::String(self.tenant_id.clone())),
            (KIND.into(), Value::String(self.kind.as_str().into())),
            (
                JWKS_KEYSET_ID.into(),
                optional_text(self.jwks_keyset_id.as_ref()),
            ),
            (CLUSTER_ID.into(), optional_text(self.cluster_id.as_ref())),
        ]);
        self.source.insert_into(&mut plan);
        plan
    }

    /// The plan of a stored create, or `None` when it is not exactly the
    /// twenty-one members with their types: the enumerations their values,
    /// `review_timeout_ms` in the `i32` range, `proof_bounds` the text of a
    /// JSON object.
    pub(crate) fn from_plan(plan: &JsonObject) -> Option<Self> {
        if plan.len() != 21 {
            return None;
        }
        let text = |name: &str| plan.get(name)?.as_str().map(str::to_owned);
        Some(Self {
            requester_credential_id: text(PLAN_REQUESTER_CREDENTIAL_ID)?,
            source: SourceFields::from_plan(plan)?,
            id: text(ID)?,
            tenant_id: text(TENANT_ID)?,
            kind: text(KIND)?.parse().ok()?,
            jwks_keyset_id: read_optional_text(plan.get(JWKS_KEYSET_ID)?)?,
            cluster_id: read_optional_text(plan.get(CLUSTER_ID)?)?,
        })
    }

    /// The source to create; `None` only for a plan whose `proof_bounds` is
    /// not an object, which [`Self::from_plan`] never returns.
    pub(crate) fn to_new(&self) -> Option<NewTrustSource> {
        let source = &self.source;
        Some(NewTrustSource {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            name: source.name.clone(),
            kind: self.kind,
            exact_issuer: source.exact_issuer.clone(),
            discovery_url: source.discovery_url.clone(),
            jwks_keyset_id: self.jwks_keyset_id.clone(),
            cluster_id: self.cluster_id.clone(),
            token_review_endpoint: source.token_review_endpoint.clone(),
            ca_bundle_ref: source.ca_bundle_ref.clone(),
            ca_fingerprint: source.ca_fingerprint.clone(),
            reviewer_credential_ref: source.reviewer_credential_ref.clone(),
            review_timeout_ms: source.review_timeout_ms,
            audiences: source.audiences.clone(),
            algorithms: source.algorithms.clone(),
            proof_bounds: source.proof_bounds()?,
            assertion_profile: source.assertion_profile,
            stale_revocation_acknowledged: source.stale_revocation_acknowledged,
            replay_mode: source.replay_mode,
            status: source.status,
        })
    }
}

impl UpdateSourcePlan {
    /// The plan of an update of the source `source_id`, whose stored row is
    /// `stored`, to `changes`, by the credential `requester_credential_id`.
    pub(crate) fn new(
        requester_credential_id: &str,
        stored: &TrustSource,
        changes: &TrustSourceChanges,
    ) -> Self {
        Self {
            requester_credential_id: requester_credential_id.into(),
            source_id: stored.id.clone(),
            source: SourceFields {
                name: changes.name.clone(),
                exact_issuer: changes.exact_issuer.clone(),
                discovery_url: changes.discovery_url.clone(),
                token_review_endpoint: changes.token_review_endpoint.clone(),
                ca_bundle_ref: changes.ca_bundle_ref.clone(),
                ca_fingerprint: changes.ca_fingerprint.clone(),
                reviewer_credential_ref: changes.reviewer_credential_ref.clone(),
                review_timeout_ms: changes.review_timeout_ms,
                audiences: changes.audiences.clone(),
                algorithms: changes.algorithms.clone(),
                proof_bounds: Value::Object(changes.proof_bounds.clone()).to_string(),
                assertion_profile: changes.assertion_profile,
                stale_revocation_acknowledged: changes.stale_revocation_acknowledged,
                replay_mode: changes.replay_mode,
                status: changes.status,
            },
            changed: changed_members(stored, changes)
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    pub(crate) fn to_plan(&self) -> JsonObject {
        let mut plan = JsonObject::from_iter([
            (
                PLAN_REQUESTER_CREDENTIAL_ID.into(),
                Value::String(self.requester_credential_id.clone()),
            ),
            (SOURCE_ID.into(), Value::String(self.source_id.clone())),
            (CHANGED.into(), texts(&self.changed)),
        ]);
        self.source.insert_into(&mut plan);
        plan
    }

    /// The plan of a stored update, or `None` when it is not exactly the
    /// eighteen members with their types: as a create's, and `changed`
    /// names of [`CHANGE_MEMBERS`], sorted byte-wise without repeats.
    pub(crate) fn from_plan(plan: &JsonObject) -> Option<Self> {
        if plan.len() != 18 {
            return None;
        }
        let text = |name: &str| plan.get(name)?.as_str().map(str::to_owned);
        let changed = read_texts(plan.get(CHANGED)?)?;
        let known = changed
            .iter()
            .all(|name| CHANGE_MEMBERS.contains(&name.as_str()));
        let sorted = changed
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes());
        if !known || !sorted {
            return None;
        }
        Some(Self {
            requester_credential_id: text(PLAN_REQUESTER_CREDENTIAL_ID)?,
            source_id: text(SOURCE_ID)?,
            source: SourceFields::from_plan(plan)?,
            changed,
        })
    }

    /// The changes to write; `None` only for a plan whose `proof_bounds` is
    /// not an object, which [`Self::from_plan`] never returns.
    pub(crate) fn to_changes(&self) -> Option<TrustSourceChanges> {
        let source = &self.source;
        Some(TrustSourceChanges {
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
            proof_bounds: source.proof_bounds()?,
            assertion_profile: source.assertion_profile,
            stale_revocation_acknowledged: source.stale_revocation_acknowledged,
            replay_mode: source.replay_mode,
            status: source.status,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn object(value: Value) -> JsonObject {
        match value {
            Value::Object(members) => members,
            other => panic!("not an object: {other}"),
        }
    }

    fn k8s() -> NewTrustSource {
        NewTrustSource {
            id: "src_1".into(),
            tenant_id: "ten_a".into(),
            name: "source-1".into(),
            kind: TrustSourceKind::KubernetesTokenReview,
            exact_issuer: "https://kubernetes.default.svc".into(),
            discovery_url: None,
            jwks_keyset_id: None,
            cluster_id: Some("cluster_1".into()),
            token_review_endpoint: Some("https://k3s.internal.example:6443/".into()),
            ca_bundle_ref: Some("ca_k3s".into()),
            ca_fingerprint: Some("sha256:ca".into()),
            reviewer_credential_ref: Some("reviewer_k3s".into()),
            review_timeout_ms: Some(5000),
            audiences: vec!["aud_b".into(), "aud_a".into()],
            algorithms: None,
            proof_bounds: object(json!({"z": 1, "a": {"n": 1.5}})),
            assertion_profile: AssertionProfile::ProjectedServiceAccount,
            stale_revocation_acknowledged: None,
            replay_mode: ReplayMode::Reusable,
            status: Status::Enabled,
        }
    }

    fn stored(new: &NewTrustSource) -> TrustSource {
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
            revision: 3,
        }
    }

    fn unchanged(stored: &TrustSource) -> TrustSourceChanges {
        TrustSourceChanges {
            name: stored.name.clone(),
            exact_issuer: stored.exact_issuer.clone(),
            discovery_url: stored.discovery_url.clone(),
            token_review_endpoint: stored.token_review_endpoint.clone(),
            ca_bundle_ref: stored.ca_bundle_ref.clone(),
            ca_fingerprint: stored.ca_fingerprint.clone(),
            reviewer_credential_ref: stored.reviewer_credential_ref.clone(),
            review_timeout_ms: stored.review_timeout_ms,
            audiences: stored.audiences.clone(),
            algorithms: stored.algorithms.clone(),
            proof_bounds: stored.proof_bounds.clone(),
            assertion_profile: stored.assertion_profile,
            stale_revocation_acknowledged: stored.stale_revocation_acknowledged,
            replay_mode: stored.replay_mode,
            status: stored.status,
        }
    }

    /// A create's plan is the requester's credential and every member of
    /// the source, `proof_bounds` as sorted compact text, unset members
    /// `null`; it reads back to the same source.
    #[test]
    fn a_create_plan_holds_every_member_of_the_source() {
        let new = k8s();
        let plan = CreateSourcePlan::new("crd_1", &new);
        let stored = plan.to_plan();
        assert_eq!(
            Value::Object(stored.clone()),
            json!({
                "requester_credential_id": "crd_1",
                "id": "src_1",
                "tenant_id": "ten_a",
                "name": "source-1",
                "kind": "kubernetes_token_review",
                "exact_issuer": "https://kubernetes.default.svc",
                "discovery_url": null,
                "jwks_keyset_id": null,
                "cluster_id": "cluster_1",
                "token_review_endpoint": "https://k3s.internal.example:6443/",
                "ca_bundle_ref": "ca_k3s",
                "ca_fingerprint": "sha256:ca",
                "reviewer_credential_ref": "reviewer_k3s",
                "review_timeout_ms": 5000,
                "audiences": ["aud_b", "aud_a"],
                "algorithms": null,
                "proof_bounds": r#"{"a":{"n":1.5},"z":1}"#,
                "assertion_profile": "projected_service_account",
                "stale_revocation_acknowledged": null,
                "replay_mode": "reusable",
                "status": "enabled",
            })
        );
        assert_eq!(CreateSourcePlan::from_plan(&stored), Some(plan.clone()));
        assert_eq!(plan.to_new(), Some(new));
    }

    #[test]
    fn a_stored_create_plan_of_another_shape_is_refused() {
        let good = CreateSourcePlan::new("crd_1", &k8s()).to_plan();
        let changed = |name: &str, value: Value| {
            let mut plan = good.clone();
            plan.insert(name.into(), value);
            plan
        };
        let mut missing = good.clone();
        missing.remove("cluster_id");
        for bad in [
            missing,
            changed("x", json!(1)),
            changed("id", json!(null)),
            changed("tenant_id", json!(1)),
            changed("kind", json!("oidc")),
            changed("cluster_id", json!(1)),
            changed("review_timeout_ms", json!(1.5)),
            changed("review_timeout_ms", json!(2_147_483_648_i64)),
            changed("review_timeout_ms", json!("5000")),
            changed("audiences", json!("aud")),
            changed("audiences", json!([1])),
            changed("algorithms", json!([null])),
            changed("proof_bounds", json!({})),
            changed("proof_bounds", json!("[1]")),
            changed("proof_bounds", json!("not json")),
            changed("assertion_profile", json!("jwt")),
            changed("stale_revocation_acknowledged", json!("true")),
            changed("replay_mode", json!(null)),
            changed("status", json!("Enabled")),
            changed("requester_credential_id", json!(null)),
        ] {
            assert_eq!(CreateSourcePlan::from_plan(&bad), None, "{bad:?}");
        }
    }

    /// An update's plan is the requester's credential, the source, the
    /// fifteen members of the changes and the sorted names of those that
    /// differ from the stored row; it reads back to the same changes.
    #[test]
    fn an_update_plan_holds_the_changes_and_what_changed() {
        let stored = stored(&k8s());
        let mut changes = unchanged(&stored);
        changes.status = Status::Disabled;
        changes.name = "renamed".into();
        changes.proof_bounds = object(json!({"a": {"n": 1.5}, "z": 2}));
        let plan = UpdateSourcePlan::new("crd_1", &stored, &changes);
        assert_eq!(plan.changed, ["name", "proof_bounds", "status"]);
        let written = plan.to_plan();
        assert_eq!(written.len(), 18);
        assert_eq!(written["source_id"], json!("src_1"));
        assert_eq!(
            written["changed"],
            json!(["name", "proof_bounds", "status"])
        );
        assert_eq!(written["proof_bounds"], json!(r#"{"a":{"n":1.5},"z":2}"#));
        assert_eq!(written["status"], json!("disabled"));
        assert!(!written.contains_key("id"));
        assert!(!written.contains_key("kind"));
        assert!(!written.contains_key("cluster_id"));
        assert_eq!(UpdateSourcePlan::from_plan(&written), Some(plan.clone()));
        assert_eq!(plan.to_changes(), Some(changes));
        for bad in [
            json!(["status", "name"]),
            json!(["name", "name"]),
            json!(["id"]),
            json!("name"),
        ] {
            let mut plan = written.clone();
            plan.insert("changed".into(), bad.clone());
            assert_eq!(UpdateSourcePlan::from_plan(&plan), None, "{bad}");
        }
        let mut extra = written.clone();
        extra.insert("id".into(), json!("src_1"));
        assert_eq!(UpdateSourcePlan::from_plan(&extra), None);
    }

    /// Every member of the changes counts, each under its own name, and the
    /// names are sorted byte-wise.
    #[test]
    fn every_changed_member_is_named() {
        let stored = stored(&k8s());
        assert!(changed_members(&stored, &unchanged(&stored)).is_empty());
        let mut sorted = CHANGE_MEMBERS;
        sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(sorted, CHANGE_MEMBERS);
        type Change = fn(&mut TrustSourceChanges);
        let cases: [(&str, Change); 15] = [
            ("algorithms", |c| c.algorithms = Some(vec!["ES256".into()])),
            ("assertion_profile", |c| {
                c.assertion_profile = AssertionProfile::ReusableJwt;
            }),
            ("audiences", |c| c.audiences.pop().map_or((), drop)),
            ("ca_bundle_ref", |c| c.ca_bundle_ref = None),
            ("ca_fingerprint", |c| c.ca_fingerprint = Some("x".into())),
            ("discovery_url", |c| c.discovery_url = Some("x".into())),
            ("exact_issuer", |c| c.exact_issuer.push('x')),
            ("name", |c| c.name.push('x')),
            ("proof_bounds", |c| c.proof_bounds = JsonObject::new()),
            ("replay_mode", |c| c.replay_mode = ReplayMode::SingleUse),
            ("review_timeout_ms", |c| c.review_timeout_ms = Some(1)),
            ("reviewer_credential_ref", |c| {
                c.reviewer_credential_ref = None;
            }),
            ("stale_revocation_acknowledged", |c| {
                c.stale_revocation_acknowledged = Some(true);
            }),
            ("status", |c| c.status = Status::Disabled),
            ("token_review_endpoint", |c| c.token_review_endpoint = None),
        ];
        for (name, change) in cases {
            let mut changes = unchanged(&stored);
            change(&mut changes);
            assert_eq!(changed_members(&stored, &changes), [name], "{name}");
        }
        // Key order does not count; a number's spelling does.
        let mut changes = unchanged(&stored);
        changes.proof_bounds = object(json!({"a": {"n": 1.5}, "z": 1}));
        assert!(changed_members(&stored, &changes).is_empty());
        changes.proof_bounds = object(json!({"a": {"n": 1.5}, "z": 1.0}));
        assert_eq!(changed_members(&stored, &changes), ["proof_bounds"]);
    }
}
