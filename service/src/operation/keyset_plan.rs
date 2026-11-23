//! The plans of the two keyset kinds (proposal section 2, "The plan"):
//! what a pending `trust_keyset_version_create` or
//! `trust_keyset_version_enable` stores, written by
//! [`crate::trust::keyset`]'s `submit_*` from typed input and read back by
//! the approve. Each plan holds exactly its members, with their JSON types;
//! a stored plan of any other shape is [`super::ApprovalError::PlanIntegrity`]
//! at the approve.
//!
//! No member holds a secret: `public_jwks` is the canonical public
//! projection ([`ValidatedKeyset::public_json`]), never the raw upload, and
//! `provenance` naming a JWK private member is refused before the plan is
//! built.

use serde_json::Value;

use super::{PLAN_REQUESTER_CREDENTIAL_ID, digest::microseconds_since_epoch};
use crate::jwk::{Algorithm, ValidatedKeyset};
use crate::persistence::registry::{JsonObject, Status};

const VERSION_ID: &str = "version_id";
const KEYSET_ID: &str = "keyset_id";
const PUBLIC_JWKS: &str = "public_jwks";
const FINGERPRINT: &str = "fingerprint";
const ALLOWED_ALGORITHMS: &str = "allowed_algorithms";
const EFFECTIVE_AT_US: &str = "effective_at_us";
const EXPIRES_AT_US: &str = "expires_at_us";
const STATUS: &str = "status";
const PROVENANCE: &str = "provenance";

/// The plan of a `trust_keyset_version_create` (section 2): ten members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CreatePlan {
    pub(crate) requester_credential_id: String,
    pub(crate) version_id: String,
    pub(crate) keyset_id: String,
    /// The text of [`ValidatedKeyset::public_json`].
    pub(crate) public_jwks: String,
    /// [`crate::jwk::KeysetFingerprint::as_str`] of the projection.
    pub(crate) fingerprint: String,
    /// The `allowed` set the upload was validated against, sorted by name
    /// byte-wise, without repeats (D25). Never empty.
    pub(crate) allowed_algorithms: Vec<Algorithm>,
    /// Whole microseconds since the epoch, floored as the writer floors.
    pub(crate) effective_at_us: i64,
    /// As `effective_at_us`; `None` (JSON `null`) for no expiry.
    pub(crate) expires_at_us: Option<i64>,
    pub(crate) status: Status,
    /// The provenance object as JSON text (inferred: `serde_json`'s compact
    /// form, members sorted byte-wise since its map is ordered), so the
    /// `jsonb` column returns it exactly, whatever numbers it holds.
    pub(crate) provenance: String,
}

/// The input of [`CreatePlan::new`].
pub(crate) struct CreateRequest<'a> {
    pub(crate) requester_credential_id: &'a str,
    pub(crate) version_id: &'a str,
    pub(crate) keyset_id: &'a str,
    pub(crate) keys: &'a ValidatedKeyset,
    pub(crate) allowed: &'a [Algorithm],
    pub(crate) effective_at: std::time::SystemTime,
    pub(crate) expires_at: Option<std::time::SystemTime>,
    pub(crate) status: Status,
    pub(crate) provenance: &'a JsonObject,
}

/// A time outside the `i64` microsecond range, so no plan can hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutOfRange;

impl CreatePlan {
    /// The plan of `request`; [`OutOfRange`] when a time is outside the
    /// `i64` microsecond range (the `0007` range refuses it anyway).
    pub(crate) fn new(request: &CreateRequest<'_>) -> Result<Self, OutOfRange> {
        let mut allowed_algorithms = request.allowed.to_vec();
        allowed_algorithms.sort_unstable_by(|a, b| a.name().as_bytes().cmp(b.name().as_bytes()));
        allowed_algorithms.dedup();
        let expires_at_us = match request.expires_at {
            Some(at) => Some(microseconds_since_epoch(at).ok_or(OutOfRange)?),
            None => None,
        };
        Ok(Self {
            requester_credential_id: request.requester_credential_id.into(),
            version_id: request.version_id.into(),
            keyset_id: request.keyset_id.into(),
            public_jwks: request.keys.public_json().into(),
            fingerprint: request.keys.fingerprint().as_str().into(),
            allowed_algorithms,
            effective_at_us: microseconds_since_epoch(request.effective_at).ok_or(OutOfRange)?,
            expires_at_us,
            status: request.status,
            provenance: Value::Object(request.provenance.clone()).to_string(),
        })
    }

    pub(crate) fn to_plan(&self) -> JsonObject {
        let allowed = self
            .allowed_algorithms
            .iter()
            .map(|alg| Value::String(alg.name().into()))
            .collect();
        JsonObject::from_iter([
            (
                PLAN_REQUESTER_CREDENTIAL_ID.into(),
                Value::String(self.requester_credential_id.clone()),
            ),
            (VERSION_ID.into(), Value::String(self.version_id.clone())),
            (KEYSET_ID.into(), Value::String(self.keyset_id.clone())),
            (PUBLIC_JWKS.into(), Value::String(self.public_jwks.clone())),
            (FINGERPRINT.into(), Value::String(self.fingerprint.clone())),
            (ALLOWED_ALGORITHMS.into(), Value::Array(allowed)),
            (EFFECTIVE_AT_US.into(), Value::from(self.effective_at_us)),
            (
                EXPIRES_AT_US.into(),
                self.expires_at_us.map_or(Value::Null, Value::from),
            ),
            (STATUS.into(), Value::String(self.status.as_str().into())),
            (PROVENANCE.into(), Value::String(self.provenance.clone())),
        ])
    }

    /// The plan of a stored create, or `None` when it is not exactly the
    /// ten members with their types: the algorithms known, sorted and
    /// without repeats, the status a status, the provenance the text of a
    /// JSON object.
    pub(crate) fn from_plan(plan: &JsonObject) -> Option<Self> {
        if plan.len() != 10 {
            return None;
        }
        let text = |name: &str| plan.get(name)?.as_str().map(str::to_owned);
        let mut allowed_algorithms: Vec<Algorithm> = Vec::new();
        for name in plan.get(ALLOWED_ALGORITHMS)?.as_array()? {
            let alg = Algorithm::from_name(name.as_str()?)?;
            if let Some(last) = allowed_algorithms.last().copied()
                && last.name().as_bytes() >= alg.name().as_bytes()
            {
                return None;
            }
            allowed_algorithms.push(alg);
        }
        if allowed_algorithms.is_empty() {
            return None;
        }
        let expires_at_us = match plan.get(EXPIRES_AT_US)? {
            Value::Null => None,
            value => Some(value.as_i64()?),
        };
        let provenance = text(PROVENANCE)?;
        serde_json::from_str::<JsonObject>(&provenance).ok()?;
        Some(Self {
            requester_credential_id: text(PLAN_REQUESTER_CREDENTIAL_ID)?,
            version_id: text(VERSION_ID)?,
            keyset_id: text(KEYSET_ID)?,
            public_jwks: text(PUBLIC_JWKS)?,
            fingerprint: text(FINGERPRINT)?,
            allowed_algorithms,
            effective_at_us: plan.get(EFFECTIVE_AT_US)?.as_i64()?,
            expires_at_us,
            status: text(STATUS)?.parse().ok()?,
            provenance,
        })
    }

    /// The provenance object; a plan from [`Self::from_plan`] always has
    /// one.
    pub(crate) fn provenance(&self) -> Option<JsonObject> {
        serde_json::from_str(&self.provenance).ok()
    }
}

/// The plan of a `trust_keyset_version_enable` (section 2): the version,
/// its keyset and its stored fingerprint, read at the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnablePlan {
    pub(crate) requester_credential_id: String,
    pub(crate) version_id: String,
    pub(crate) keyset_id: String,
    pub(crate) fingerprint: String,
}

impl EnablePlan {
    pub(crate) fn to_plan(&self) -> JsonObject {
        JsonObject::from_iter([
            (
                PLAN_REQUESTER_CREDENTIAL_ID.into(),
                Value::String(self.requester_credential_id.clone()),
            ),
            (VERSION_ID.into(), Value::String(self.version_id.clone())),
            (KEYSET_ID.into(), Value::String(self.keyset_id.clone())),
            (FINGERPRINT.into(), Value::String(self.fingerprint.clone())),
        ])
    }

    /// The plan of a stored enable, or `None` when it is not exactly the
    /// four string members.
    pub(crate) fn from_plan(plan: &JsonObject) -> Option<Self> {
        if plan.len() != 4 {
            return None;
        }
        let text = |name: &str| plan.get(name)?.as_str().map(str::to_owned);
        Some(Self {
            requester_credential_id: text(PLAN_REQUESTER_CREDENTIAL_ID)?,
            version_id: text(VERSION_ID)?,
            keyset_id: text(KEYSET_ID)?,
            fingerprint: text(FINGERPRINT)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::*;
    use crate::jwk::{DEFAULT_ALLOWED_ALGORITHMS, validate_keyset};

    fn object(value: Value) -> JsonObject {
        match value {
            Value::Object(members) => members,
            other => panic!("not an object: {other}"),
        }
    }

    fn keys() -> ValidatedKeyset {
        validate_keyset(
            &json!({"keys": [{
                "kty": "EC", "kid": "k", "crv": "P-256",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                // A member outside the projection: never in a plan.
                "use": "sig",
            }]}),
            DEFAULT_ALLOWED_ALGORITHMS,
        )
        .unwrap()
    }

    fn create(expires_at: Option<SystemTime>) -> CreatePlan {
        let keys = keys();
        let provenance = object(json!({"via": "upload", "n": 1.5, "a": [true]}));
        CreatePlan::new(&CreateRequest {
            requester_credential_id: "crd_1",
            version_id: "ver_1",
            keyset_id: "ks_1",
            keys: &keys,
            allowed: &[Algorithm::Es256, Algorithm::EdDsa, Algorithm::Es256],
            effective_at: UNIX_EPOCH + Duration::from_nanos(1_790_000_000_123_456_789),
            expires_at,
            status: Status::Disabled,
            provenance: &provenance,
        })
        .unwrap()
    }

    /// A create's plan is its ten members: the projection and fingerprint,
    /// never the raw upload; the allowed set sorted by name without
    /// repeats; the window in floored microseconds; provenance as text.
    #[test]
    fn a_create_plan_holds_the_projection_and_its_members() {
        let keys = keys();
        let plan = create(Some(
            UNIX_EPOCH + Duration::from_micros(1_790_000_100_000_000),
        ));
        let stored = plan.to_plan();
        assert_eq!(
            Value::Object(stored.clone()),
            json!({
                "requester_credential_id": "crd_1",
                "version_id": "ver_1",
                "keyset_id": "ks_1",
                "public_jwks": keys.public_json(),
                "fingerprint": keys.fingerprint().as_str(),
                "allowed_algorithms": ["ES256", "EdDSA"],
                "effective_at_us": 1_790_000_000_123_456_i64,
                "expires_at_us": 1_790_000_100_000_000_i64,
                "status": "disabled",
                "provenance": r#"{"a":[true],"n":1.5,"via":"upload"}"#,
            })
        );
        assert!(!keys.public_json().contains("use"));
        assert_eq!(CreatePlan::from_plan(&stored), Some(plan.clone()));
        assert_eq!(
            plan.provenance(),
            Some(object(json!({"via": "upload", "n": 1.5, "a": [true]})))
        );
        let open = create(None);
        assert_eq!(open.to_plan()["expires_at_us"], Value::Null);
        assert_eq!(CreatePlan::from_plan(&open.to_plan()), Some(open));
    }

    #[test]
    fn a_stored_create_plan_of_another_shape_is_refused() {
        let good = create(None).to_plan();
        let changed = |name: &str, value: Value| {
            let mut plan = good.clone();
            plan.insert(name.into(), value);
            plan
        };
        let mut missing = good.clone();
        missing.remove("provenance");
        for bad in [
            missing,
            changed("x", json!(1)),
            changed("version_id", json!(1)),
            changed("public_jwks", json!({"keys": []})),
            changed("allowed_algorithms", json!([])),
            changed("allowed_algorithms", json!(["EdDSA", "ES256"])),
            changed("allowed_algorithms", json!(["ES256", "ES256"])),
            changed("allowed_algorithms", json!(["ES256", "HS256"])),
            changed("allowed_algorithms", json!("ES256")),
            changed("effective_at_us", json!(1.5)),
            changed("effective_at_us", json!(null)),
            changed("expires_at_us", json!("1")),
            changed("status", json!("Enabled")),
            changed("provenance", json!("[1]")),
            changed("provenance", json!("not json")),
            changed("provenance", json!({})),
        ] {
            assert_eq!(CreatePlan::from_plan(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn an_enable_plan_is_exactly_its_four_members() {
        let plan = EnablePlan {
            requester_credential_id: "crd_1".into(),
            version_id: "ver_1".into(),
            keyset_id: "ks_1".into(),
            fingerprint: "fp".into(),
        };
        let stored = plan.to_plan();
        assert_eq!(
            Value::Object(stored.clone()),
            json!({
                "requester_credential_id": "crd_1",
                "version_id": "ver_1",
                "keyset_id": "ks_1",
                "fingerprint": "fp",
            })
        );
        assert_eq!(EnablePlan::from_plan(&stored), Some(plan));
        for bad in [
            json!({"requester_credential_id": "crd_1", "version_id": "ver_1", "keyset_id": "ks_1"}),
            json!({"requester_credential_id": "crd_1", "version_id": "ver_1",
                   "keyset_id": "ks_1", "fingerprint": 1}),
            json!({"requester_credential_id": "crd_1", "version_id": "ver_1",
                   "keyset_id": "ks_1", "fp": "fp"}),
            json!({"requester_credential_id": "crd_1", "version_id": "ver_1",
                   "keyset_id": "ks_1", "fingerprint": "fp", "x": null}),
        ] {
            assert_eq!(EnablePlan::from_plan(&object(bad.clone())), None, "{bad}");
        }
    }
}
