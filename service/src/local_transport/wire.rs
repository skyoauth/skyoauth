//! The wire format: one request line in, one response line out (see the
//! module docs of [`crate::local_transport`], "Protocol").

use serde::{Deserialize, Serialize};

/// A request, by its `op` member. Each variant's members are closed
/// (`deny_unknown_fields`); serde refuses a missing, repeated or unknown
/// member, a repeated `op` and an unknown `op`.
///
/// No `Debug`: a request holds key material in hexadecimal.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(super) enum Request {
    Bootstrap(BootstrapWire),
    IssueChallenge(IssueWire),
    Preview(ResponseWire),
    Restore(ResponseWire),
}

impl Request {
    /// The operation's name, as the `op` member spells it.
    #[cfg(test)]
    pub(super) const fn op(&self) -> &'static str {
        match self {
            Self::Bootstrap(_) => "bootstrap",
            Self::IssueChallenge(_) => "issue_challenge",
            Self::Preview(_) => "preview",
            Self::Restore(_) => "restore",
        }
    }
}

/// `bootstrap`: the input of `bootstrap_instance` that the deployment
/// operator supplies; the transport generates the IDs and takes the time.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BootstrapWire {
    /// A lowercase hyphenated UUIDv7 (IR-057).
    pub(super) instance_id: String,
    /// The DER `SubjectPublicKeyInfo` of the first operator's mTLS key, in
    /// lowercase hexadecimal; the transport derives its canonical public
    /// identity.
    pub(super) credential_spki: String,
    pub(super) trust_anchor_ref: String,
    /// The raw 32-byte Ed25519 recovery public key, 64 lowercase
    /// hexadecimal digits.
    pub(super) recovery_public_key: String,
}

/// `issue_challenge`: the replacement the restoration plan names; the
/// transport reads the instance and the key epoch from the recovery state
/// and generates the IDs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssueWire {
    /// As [`BootstrapWire::credential_spki`], for the replacement.
    pub(super) credential_spki: String,
    pub(super) trust_anchor_ref: String,
    /// The recovery public key the restore rotates to, 64 lowercase
    /// hexadecimal digits (the plan's own form).
    pub(super) new_recovery_public_key: String,
}

/// `preview` and `restore`: the signed response, carried as bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResponseWire {
    pub(super) operation_id: String,
    /// The signature over the challenge's `M`, lowercase hexadecimal, of
    /// any even length: the restore refuses one that is not 64 bytes.
    pub(super) signature: String,
}

/// A response line. Every success has its own members; every refusal is
/// `{"error":"<code>"}` and nothing else.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(super) enum Reply {
    Bootstrapped {
        instance_id: String,
        admin_id: String,
        credential_id: String,
        binding_id: String,
        recovery_key_epoch: i64,
    },
    Issued {
        operation_id: String,
        /// Whole microseconds since the Unix epoch, as stored.
        expires_at: i64,
        expected_revision: i64,
        /// `M`, in lowercase hexadecimal.
        challenge: String,
    },
    Previewed {
        admin_id: String,
        credential_id: String,
        binding_id: String,
        new_recovery_key_epoch: i64,
        expires_at: i64,
    },
    Restored {
        admin_id: String,
        credential_id: String,
        binding_id: String,
        revoked_credential_ids: Vec<String>,
        recovery_key_epoch: i64,
        recovery_state_revision: i64,
    },
    Error {
        error: &'static str,
    },
}

impl Reply {
    /// The response line: the JSON text and its newline.
    pub(super) fn line(&self) -> Vec<u8> {
        // Strings, integers and a list of strings: serializing cannot fail.
        let mut line =
            serde_json::to_vec(self).unwrap_or_else(|_| br#"{"error":"server_error"}"#.to_vec());
        line.push(b'\n');
        line
    }
}

/// `bytes` in lowercase hexadecimal.
pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// The bytes of `text`, an even number of lowercase hexadecimal digits;
/// `None` for anything else (upper case included).
pub(super) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digit = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[high, low]| Some((digit(*high)? << 4) | digit(*low)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Request, serde_json::Error> {
        serde_json::from_str(text)
    }

    #[test]
    fn hex_is_lowercase_and_even() {
        assert_eq!(encode_hex(&[0x00, 0x9f, 0xa0, 0xff]), "009fa0ff");
        assert_eq!(decode_hex("009fa0ff"), Some(vec![0x00, 0x9f, 0xa0, 0xff]));
        assert_eq!(decode_hex(""), Some(Vec::new()));
        for bad in ["0", "009FA0ff", "0g", "zz", " 00", "00 ", "0x00", "\u{e9}0"] {
            assert_eq!(decode_hex(bad), None, "{bad}");
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode_hex(&encode_hex(&all)), Some(all));
    }

    #[test]
    fn each_op_parses_with_exactly_its_members() {
        for (text, op) in [
            (
                r#"{"op":"bootstrap","instance_id":"i","credential_spki":"00","trust_anchor_ref":"t","recovery_public_key":"00"}"#,
                "bootstrap",
            ),
            (
                r#"{"credential_spki":"00","op":"issue_challenge","trust_anchor_ref":"t","new_recovery_public_key":"00"}"#,
                "issue_challenge",
            ),
            (
                r#" {"op":"preview","operation_id":"o","signature":"00"} "#,
                "preview",
            ),
            (
                r#"{"op":"restore","operation_id":"o","signature":"00"}"#,
                "restore",
            ),
        ] {
            assert_eq!(parse(text).unwrap().op(), op, "{text}");
        }
    }

    #[test]
    fn unknown_missing_repeated_and_mistyped_members_are_refused() {
        for text in [
            // Unknown op, missing op, wrong case.
            r#"{"op":"approve","operation_id":"o","signature":"00"}"#,
            r#"{"operation_id":"o","signature":"00"}"#,
            r#"{"op":"Restore","operation_id":"o","signature":"00"}"#,
            r#"{"op":"issue-challenge","credential_spki":"00","trust_anchor_ref":"t","new_recovery_public_key":"00"}"#,
            // Unknown member.
            r#"{"op":"restore","operation_id":"o","signature":"00","now":1}"#,
            r#"{"op":"bootstrap","instance_id":"i","credential_spki":"00","trust_anchor_ref":"t","recovery_public_key":"00","admin_id":"adm_x"}"#,
            r#"{"op":"issue_challenge","credential_spki":"00","trust_anchor_ref":"t","new_recovery_public_key":"00","ttl":900}"#,
            // Missing member.
            r#"{"op":"restore","operation_id":"o"}"#,
            r#"{"op":"bootstrap","instance_id":"i","credential_spki":"00","trust_anchor_ref":"t"}"#,
            // Repeated member, repeated op.
            r#"{"op":"restore","operation_id":"o","operation_id":"p","signature":"00"}"#,
            r#"{"op":"restore","op":"preview","operation_id":"o","signature":"00"}"#,
            // Mistyped member.
            r#"{"op":"restore","operation_id":1,"signature":"00"}"#,
            r#"{"op":"restore","operation_id":"o","signature":null}"#,
            r#"{"op":"restore","operation_id":"o","signature":["00"]}"#,
            // Not one object.
            r#"[{"op":"restore","operation_id":"o","signature":"00"}]"#,
            r#"{"op":"restore","operation_id":"o","signature":"00"}{}"#,
            "",
            "null",
            "{",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_reply_is_one_line_of_its_members() {
        assert_eq!(
            Reply::Error { error: "forbidden" }.line(),
            b"{\"error\":\"forbidden\"}\n"
        );
        let issued = Reply::Issued {
            operation_id: "oper_1".into(),
            expires_at: 9_007_199_254_740_993,
            expected_revision: 1,
            challenge: "00".into(),
        };
        assert_eq!(
            String::from_utf8(issued.line()).unwrap(),
            "{\"operation_id\":\"oper_1\",\"expires_at\":9007199254740993,\
             \"expected_revision\":1,\"challenge\":\"00\"}\n"
        );
    }
}
