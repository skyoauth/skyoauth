//! The request digest of a pending operation
//! (`docs/proposals/second-approver-gated-writes.md` section 2, "The
//! digest"; D6, D29).
//!
//! ```text
//! request_digest = SHA-256("skyoauth.administrative_operation.v1\n" || C)
//! C = canonical JSON of {"actor_id": <id>, "expected_revision": <i64>,
//!                        "expires_at": <i64>, "id": <id>, "kind": <kind>,
//!                        "plan": <plan>, "tenant_id": <id> | null}
//! ```
//!
//! `C` has its members sorted byte-wise at every level, the nested plan
//! included, no insignificant whitespace, strings escaped as the IR-056
//! event hash escapes them (the registry's `push_string`), and integers in
//! decimal. `expires_at` is whole microseconds since the Unix epoch
//! (inferred). The plan may hold only strings, integers (`i64`), booleans,
//! `null`, arrays and objects of those: a number that is not an `i64` has
//! no canonical form here and is [`NotCanonical`], so a plan read back from
//! the `jsonb` column recomputes to the digest it was stored with.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::persistence::registry::{JsonObject, floor_to_microsecond, push_string};

/// The domain-separation prefix of the request digest, with its newline.
pub const DIGEST_PREFIX: &[u8] = b"skyoauth.administrative_operation.v1\n";

/// SHA-256 of the canonical request (see the module docs). `Debug` prints
/// `RequestDigest(..)`, never the bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestDigest([u8; 32]);

impl RequestDigest {
    /// The digest with these 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes of the digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestDigest(..)")
    }
}

/// A byte string that is not 32 bytes long, so not a [`RequestDigest`]
/// (an echo of another length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestLengthError;

impl fmt::Display for DigestLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a request digest is 32 bytes")
    }
}

impl std::error::Error for DigestLengthError {}

impl TryFrom<&[u8]> for RequestDigest {
    type Error = DigestLengthError;

    fn try_from(bytes: &[u8]) -> Result<Self, DigestLengthError> {
        Ok(Self(bytes.try_into().map_err(|_| DigestLengthError)?))
    }
}

/// A plan value the canonical form does not write: a number that is not an
/// integer in the `i64` range (a fraction, an exponent form `jsonb` keeps,
/// or an integer above `i64::MAX`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotCanonical;

impl fmt::Display for NotCanonical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the plan holds a number that is not a 64-bit integer")
    }
}

impl std::error::Error for NotCanonical {}

/// Every input of the request digest: the operation's ID, tenant, actor,
/// kind, expected revision, expiry and plan, as the
/// `administrative_operation` row stores them (D29: the read response
/// returns exactly these, so a client recomputes the digest from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestEnvelope<'a> {
    pub id: &'a str,
    /// `None` for an instance operation.
    pub tenant_id: Option<&'a str>,
    /// The requester's `admin_id`.
    pub actor_id: &'a str,
    /// The stored kind name.
    pub kind: &'a str,
    pub expected_revision: i64,
    /// `expires_at` as whole microseconds since the Unix epoch.
    pub expires_at_us: i64,
    pub plan: &'a JsonObject,
}

impl DigestEnvelope<'_> {
    /// `C`, the canonical JSON the digest covers (see the module docs).
    pub fn canonical_json(&self) -> Result<String, NotCanonical> {
        let mut out = String::with_capacity(256);
        out.push_str("{\"actor_id\":");
        push_string(&mut out, self.actor_id);
        out.push_str(",\"expected_revision\":");
        out.push_str(&self.expected_revision.to_string());
        out.push_str(",\"expires_at\":");
        out.push_str(&self.expires_at_us.to_string());
        out.push_str(",\"id\":");
        push_string(&mut out, self.id);
        out.push_str(",\"kind\":");
        push_string(&mut out, self.kind);
        out.push_str(",\"plan\":");
        push_object(&mut out, self.plan)?;
        out.push_str(",\"tenant_id\":");
        match self.tenant_id {
            Some(tenant_id) => push_string(&mut out, tenant_id),
            None => out.push_str("null"),
        }
        out.push('}');
        Ok(out)
    }

    /// The request digest: SHA-256 of [`DIGEST_PREFIX`] and
    /// [`canonical_json`](Self::canonical_json).
    pub fn digest(&self) -> Result<RequestDigest, NotCanonical> {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_PREFIX);
        hasher.update(self.canonical_json()?.as_bytes());
        Ok(RequestDigest(hasher.finalize().into()))
    }
}

/// The plan's canonical text: exactly the bytes the preimage `C` embeds as
/// its `plan` member (see the module docs), so a client that splices it
/// into the envelope recomputes the digest without parsing a number of the
/// plan (D29; the operation reads of [`crate::admin_http`] return it
/// verbatim). A plan with no canonical form is [`NotCanonical`].
pub fn canonical_plan(plan: &JsonObject) -> Result<String, NotCanonical> {
    let mut out = String::with_capacity(128);
    push_object(&mut out, plan)?;
    Ok(out)
}

/// Appends `members` with their names sorted byte-wise.
fn push_object(out: &mut String, members: &JsonObject) -> Result<(), NotCanonical> {
    let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
    sorted.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
    out.push('{');
    for (index, (name, value)) in sorted.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_string(out, name);
        out.push(':');
        push_value(out, value)?;
    }
    out.push('}');
    Ok(())
}

fn push_value(out: &mut String, value: &Value) -> Result<(), NotCanonical> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.as_i64().ok_or(NotCanonical)?.to_string()),
        Value::String(text) => push_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                push_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(members) => push_object(out, members)?,
    }
    Ok(())
}

/// `time` floored to a whole microsecond, as the registry stores it, in
/// microseconds since the Unix epoch; `None` outside the `i64` range.
pub(crate) fn microseconds_since_epoch(time: SystemTime) -> Option<i64> {
    match floor_to_microsecond(time).duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_micros()).ok(),
        Err(before) => i64::try_from(before.duration().as_micros())
            .ok()
            .map(|micros| -micros),
    }
}

/// The time `microseconds` after the Unix epoch (before it when negative):
/// the inverse of [`microseconds_since_epoch`] on whole microseconds.
/// `None` when `SystemTime` cannot hold it.
pub(crate) fn from_microseconds(microseconds: i64) -> Option<SystemTime> {
    let magnitude = std::time::Duration::from_micros(microseconds.unsigned_abs());
    if microseconds >= 0 {
        UNIX_EPOCH.checked_add(magnitude)
    } else {
        UNIX_EPOCH.checked_sub(magnitude)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    fn object(value: Value) -> JsonObject {
        match value {
            Value::Object(members) => members,
            other => panic!("not an object: {other}"),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// A pending toggle, the envelope the golden vectors use.
    fn toggle_plan() -> JsonObject {
        object(json!({
            "widening_second_approver": true,
            "requester_credential_id": "crd_1",
        }))
    }

    fn envelope(plan: &JsonObject) -> DigestEnvelope<'_> {
        DigestEnvelope {
            id: "op_1",
            tenant_id: None,
            actor_id: "adm_1",
            kind: "instance_security_policy_update",
            expected_revision: 3,
            expires_at_us: 1_790_086_400_123_456,
            plan,
        }
    }

    /// The preimage of the golden vectors, member for member, and the
    /// digests computed independently of this code (Python's `hashlib`
    /// over the same bytes).
    #[test]
    fn golden_vectors() {
        let plan = toggle_plan();
        let instance = envelope(&plan);
        assert_eq!(
            instance.canonical_json().unwrap(),
            r#"{"actor_id":"adm_1","expected_revision":3,"expires_at":1790086400123456,"id":"op_1","kind":"instance_security_policy_update","plan":{"requester_credential_id":"crd_1","widening_second_approver":true},"tenant_id":null}"#
        );
        assert_eq!(
            hex(instance.digest().unwrap().as_bytes()),
            "29d86502fae51ee777623a165f09a04381f742e79761f6d0d14d25786d773d92"
        );
        let nested = object(json!({
            "z": [1, -2, null, false, {"b": "\u{1}\"\\", "a": "é"}],
            "B": {"y": 9_223_372_036_854_775_807_i64, "x": "\n"},
            "a": "",
        }));
        let tenant = DigestEnvelope {
            id: "op_2",
            tenant_id: Some("ten_a"),
            actor_id: "adm_2",
            kind: "trust_source_update",
            expected_revision: 0,
            expires_at_us: -1,
            plan: &nested,
        };
        assert_eq!(
            tenant.canonical_json().unwrap(),
            "{\"actor_id\":\"adm_2\",\"expected_revision\":0,\"expires_at\":-1,\"id\":\"op_2\",\
             \"kind\":\"trust_source_update\",\"plan\":{\"B\":{\"x\":\"\\n\",\
             \"y\":9223372036854775807},\"a\":\"\",\"z\":[1,-2,null,false,\
             {\"a\":\"\u{e9}\",\"b\":\"\\u0001\\\"\\\\\"}]},\"tenant_id\":\"ten_a\"}"
        );
        assert_eq!(
            hex(tenant.digest().unwrap().as_bytes()),
            "adf18319a76355511f56dc2a21422b1a80a21631aa00c05be720108bff99dda3"
        );
    }

    /// The plan's canonical text is the very substring the preimage embeds
    /// as `plan`, so splicing it back reproduces `C` byte for byte.
    #[test]
    fn the_canonical_plan_is_the_preimages_plan_member() {
        let nested = object(json!({
            "z": [1, -2, null, false, {"b": "\u{1}\"\\", "a": "é"}],
            "B": {"y": 9_223_372_036_854_775_807_i64, "x": "\n"},
            "a": "",
        }));
        for plan in [toggle_plan(), nested, JsonObject::new()] {
            let text = canonical_plan(&plan).unwrap();
            let whole = envelope(&plan).canonical_json().unwrap();
            assert!(
                whole.contains(&format!(",\"plan\":{text},\"tenant_id\":")),
                "{whole}"
            );
        }
        assert_eq!(
            canonical_plan(&toggle_plan()).unwrap(),
            r#"{"requester_credential_id":"crd_1","widening_second_approver":true}"#
        );
        assert_eq!(canonical_plan(&JsonObject::new()).unwrap(), "{}");
        let float = object(json!({ "deep": [{ "n": 1.5 }] }));
        assert_eq!(canonical_plan(&float), Err(NotCanonical));
    }

    /// The envelope's members are in byte-wise order, and so are a plan's
    /// at every depth, whatever order the map holds them in.
    #[test]
    fn members_are_sorted_byte_wise_at_every_level() {
        let plan = object(json!({"b": 1, "B": 2, "a": {"z": 1, "Z": 2, "_": 3}, "~": 0}));
        let text = envelope(&plan).canonical_json().unwrap();
        let names = [
            "\"actor_id\"",
            "\"expected_revision\"",
            "\"expires_at\"",
            "\"id\"",
            "\"kind\"",
            "\"plan\"",
            "\"tenant_id\"",
        ];
        let positions: Vec<usize> = names.iter().map(|name| text.find(name).unwrap()).collect();
        assert!(positions.is_sorted(), "{text}");
        let mut sorted = names;
        sorted.sort_unstable();
        assert_eq!(sorted, names);
        assert!(
            text.contains(r#""plan":{"B":2,"a":{"Z":2,"_":3,"z":1},"b":1,"~":0}"#),
            "{text}"
        );
    }

    /// Strings are escaped as the IR-056 event hash escapes them.
    #[test]
    fn strings_are_escaped_as_the_event_hash_escapes_them() {
        let value = "\u{8}\t\n\u{c}\r\"\\\u{0}\u{1f}/\u{7f}\u{2028}\u{1f600}";
        let mut expected = String::new();
        push_string(&mut expected, value);
        assert_eq!(
            expected,
            "\"\\b\\t\\n\\f\\r\\\"\\\\\\u0000\\u001f/\u{7f}\u{2028}\u{1f600}\""
        );
        let plan = object(json!({ value: value }));
        let text = DigestEnvelope {
            id: value,
            tenant_id: Some(value),
            actor_id: value,
            kind: value,
            ..envelope(&plan)
        }
        .canonical_json()
        .unwrap();
        assert_eq!(text.matches(&expected).count(), 6, "{text}");
    }

    /// Integers are written in decimal across the whole `i64` range; any
    /// other number has no canonical form.
    #[test]
    fn only_64_bit_integers_are_canonical() {
        for (number, text) in [
            (json!(0), "0"),
            (json!(-1), "-1"),
            (json!(i64::MAX), "9223372036854775807"),
            (json!(i64::MIN), "-9223372036854775808"),
            (json!(1_u64 << 53), "9007199254740992"),
        ] {
            let plan = object(json!({ "n": number }));
            let canonical = envelope(&plan).canonical_json().unwrap();
            assert!(canonical.contains(&format!("\"n\":{text}")), "{canonical}");
        }
        for number in [json!(1.5), json!(1.0), json!(u64::MAX), json!(-0.0)] {
            let plan = object(json!({ "deep": [{ "n": number }] }));
            assert_eq!(envelope(&plan).canonical_json(), Err(NotCanonical));
            assert_eq!(envelope(&plan).digest(), Err(NotCanonical));
        }
        let plan = toggle_plan();
        let out = DigestEnvelope {
            expected_revision: i64::MIN,
            expires_at_us: i64::MAX,
            ..envelope(&plan)
        }
        .canonical_json()
        .unwrap();
        assert!(out.contains("\"expected_revision\":-9223372036854775808,"));
        assert!(out.contains("\"expires_at\":9223372036854775807,"));
    }

    /// Every member of the envelope, and every member of the plan, changes
    /// the digest; so does `null` against a present tenant.
    #[test]
    fn every_field_affects_the_digest() {
        let plan = toggle_plan();
        let base = envelope(&plan);
        let other_plan = object(json!({
            "widening_second_approver": false,
            "requester_credential_id": "crd_1",
        }));
        let other_credential = object(json!({
            "widening_second_approver": true,
            "requester_credential_id": "crd_2",
        }));
        let extra_member = object(json!({
            "widening_second_approver": true,
            "requester_credential_id": "crd_1",
            "x": null,
        }));
        let variants = [
            DigestEnvelope { id: "op_2", ..base },
            DigestEnvelope {
                tenant_id: Some("ten_a"),
                ..base
            },
            DigestEnvelope {
                actor_id: "adm_2",
                ..base
            },
            DigestEnvelope {
                kind: "approve",
                ..base
            },
            DigestEnvelope {
                expected_revision: 4,
                ..base
            },
            DigestEnvelope {
                expires_at_us: base.expires_at_us + 1,
                ..base
            },
            DigestEnvelope {
                plan: &other_plan,
                ..base
            },
            DigestEnvelope {
                plan: &other_credential,
                ..base
            },
            DigestEnvelope {
                plan: &extra_member,
                ..base
            },
        ];
        let digest = base.digest().unwrap();
        let mut seen = vec![digest];
        for variant in variants {
            let other = variant.digest().unwrap();
            assert!(!seen.contains(&other), "{variant:?}");
            seen.push(other);
        }
        // The digest is SHA-256 over the prefix and C, nothing else.
        let mut hasher = Sha256::new();
        hasher.update(b"skyoauth.administrative_operation.v1\n");
        hasher.update(base.canonical_json().unwrap());
        assert_eq!(digest.as_bytes(), &<[u8; 32]>::from(hasher.finalize()));
    }

    #[test]
    fn a_digest_is_32_bytes_and_debug_prints_no_byte() {
        let digest = RequestDigest::from_bytes([0xab; 32]);
        assert_eq!(digest.as_bytes(), &[0xab; 32]);
        assert_eq!(RequestDigest::try_from(&[0xab_u8; 32][..]), Ok(digest));
        for length in [0, 31, 33, 64] {
            assert_eq!(
                RequestDigest::try_from(&vec![0xab_u8; length][..]),
                Err(DigestLengthError)
            );
        }
        assert_eq!(format!("{digest:?}"), "RequestDigest(..)");
        assert_eq!(
            DigestLengthError.to_string(),
            "a request digest is 32 bytes"
        );
    }

    #[test]
    fn expiries_are_floored_microseconds() {
        let at = UNIX_EPOCH + Duration::new(1_790_086_400, 123_456_789);
        assert_eq!(microseconds_since_epoch(at), Some(1_790_086_400_123_456));
        assert_eq!(microseconds_since_epoch(UNIX_EPOCH), Some(0));
        let before = UNIX_EPOCH - Duration::from_nanos(1);
        assert_eq!(microseconds_since_epoch(before), Some(-1));
        let before = UNIX_EPOCH - Duration::from_nanos(1_001);
        assert_eq!(microseconds_since_epoch(before), Some(-2));
        for micros in [0, 1, -1, 1_790_086_400_123_456, -62_135_596_800_000_000] {
            let time = from_microseconds(micros).unwrap();
            assert_eq!(microseconds_since_epoch(time), Some(micros));
        }
        assert_eq!(
            from_microseconds(1_790_086_400_123_456),
            Some(UNIX_EPOCH + Duration::from_micros(1_790_086_400_123_456))
        );
    }
}
