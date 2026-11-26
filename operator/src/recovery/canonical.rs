//! The writer of `C` and `M` (see the [module documentation](super),
//! "What is signed").
//!
//! It writes only the closed shape of a recovery challenge: the seven
//! members of `C` and the eight of the plan, in byte-wise order, with no
//! whitespace, integers in decimal and strings escaped as the service's
//! canonical writer escapes them. It is the reference [`parse_challenge`]
//! compares its input with, byte for byte.
//!
//! [`parse_challenge`]: super::parse_challenge

use super::{
    CHALLENGE_PREFIX, DEPLOYMENT_OPERATOR_ACTOR, OPERATOR_RESTORATION, PLAN_ADMIN_ID,
    PLAN_BINDING_ID, PLAN_CREDENTIAL_ID, PLAN_INSTANCE_ID, PLAN_NEW_RECOVERY_PUBLIC_KEY,
    PLAN_PUBLIC_IDENTITY, PLAN_RECOVERY_KEY_EPOCH, PLAN_TRUST_ANCHOR_REF, RestorationPlan,
};

/// `C`, the canonical JSON of the challenge with this operation ID,
/// expected revision, expiry (whole microseconds since the Unix epoch) and
/// plan.
///
/// Every value is written as given: the writer checks nothing, so it can
/// write a challenge [`parse_challenge`](super::parse_challenge) refuses
/// (an empty `public_identity`, say).
pub fn canonical_json(
    operation_id: &str,
    expected_revision: i64,
    expires_at_micros: i64,
    plan: &RestorationPlan,
) -> String {
    let mut out = String::with_capacity(512);
    out.push('{');
    push_name(&mut out, "actor_id");
    push_string(&mut out, DEPLOYMENT_OPERATOR_ACTOR);
    out.push(',');
    push_name(&mut out, "expected_revision");
    out.push_str(&expected_revision.to_string());
    out.push(',');
    push_name(&mut out, "expires_at");
    out.push_str(&expires_at_micros.to_string());
    out.push(',');
    push_name(&mut out, "id");
    push_string(&mut out, operation_id);
    out.push(',');
    push_name(&mut out, "kind");
    push_string(&mut out, OPERATOR_RESTORATION);
    out.push(',');
    push_name(&mut out, "plan");
    push_plan(&mut out, plan);
    out.push(',');
    push_name(&mut out, "tenant_id");
    out.push_str("null");
    out.push('}');
    out
}

/// `M`, the bytes the recovery key signs: [`CHALLENGE_PREFIX`] followed by
/// [`canonical_json`] of the same values.
pub fn challenge_message(
    operation_id: &str,
    expected_revision: i64,
    expires_at_micros: i64,
    plan: &RestorationPlan,
) -> Vec<u8> {
    let canonical = canonical_json(operation_id, expected_revision, expires_at_micros, plan);
    let mut message = Vec::with_capacity(CHALLENGE_PREFIX.len() + canonical.len());
    message.extend_from_slice(CHALLENGE_PREFIX);
    message.extend_from_slice(canonical.as_bytes());
    message
}

/// Appends the plan, its eight members in byte-wise order.
fn push_plan(out: &mut String, plan: &RestorationPlan) {
    out.push('{');
    push_name(out, PLAN_ADMIN_ID);
    push_string(out, &plan.admin_id);
    out.push(',');
    push_name(out, PLAN_BINDING_ID);
    push_string(out, &plan.binding_id);
    out.push(',');
    push_name(out, PLAN_CREDENTIAL_ID);
    push_string(out, &plan.credential_id);
    out.push(',');
    push_name(out, PLAN_INSTANCE_ID);
    push_string(out, &plan.instance_id);
    out.push(',');
    push_name(out, PLAN_NEW_RECOVERY_PUBLIC_KEY);
    push_string(out, &plan.new_recovery_public_key.to_hex());
    out.push(',');
    push_name(out, PLAN_PUBLIC_IDENTITY);
    push_string(out, &plan.public_identity);
    out.push(',');
    push_name(out, PLAN_RECOVERY_KEY_EPOCH);
    out.push_str(&plan.recovery_key_epoch.to_string());
    out.push(',');
    push_name(out, PLAN_TRUST_ANCHOR_REF);
    push_string(out, &plan.trust_anchor_ref);
    out.push('}');
}

/// Appends a member name and its colon.
fn push_name(out: &mut String, name: &str) {
    push_string(out, name);
    out.push(':');
}

/// Appends `value` as a JSON string with the service's escapes (its
/// registry's `push_string`, RFC 8785 section 3.2.2.2): `"` and `\` after a
/// reverse solidus, the five short control escapes, any other character
/// below U+0020 as `\u` and four lowercase hexadecimal digits, and every
/// other character as is.
fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if control < '\u{20}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}
