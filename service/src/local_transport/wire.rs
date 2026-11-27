//! The wire format: one request line in, one response line out (see the
//! module docs of [`crate::local_transport`], "Protocol").

use serde::{Deserialize, Deserializer, Serialize};

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
    Status(StatusWire),
}

impl Request {
    /// The request in `line`, which must be one JSON object: serde's
    /// internally tagged enum would also take a positional array (`["restore",
    /// "oper_1", "00"]`), so a root that is not an object (an array, a
    /// string, a number, `true`, `false`, `null`) is refused before serde
    /// sees it. JSON whitespace may precede the object; serde refuses
    /// anything but whitespace after it.
    pub(super) fn parse(line: &[u8]) -> Option<Self> {
        let first = line
            .iter()
            .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))?;
        if *first != b'{' {
            return None;
        }
        serde_json::from_slice(line).ok()
    }

    /// The operation's name, as the `op` member spells it.
    #[cfg(test)]
    pub(super) const fn op(&self) -> &'static str {
        match self {
            Self::Bootstrap(_) => "bootstrap",
            Self::IssueChallenge(_) => "issue_challenge",
            Self::Preview(_) => "preview",
            Self::Restore(_) => "restore",
            Self::Status(_) => "status",
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

/// `status`: what to report. Every member is required, `null` when not
/// asked: a missing member is refused like any other.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StatusWire {
    /// The recovery challenge to report.
    #[serde(deserialize_with = "nullable")]
    pub(super) operation_id: Option<String>,
    /// As [`BootstrapWire::credential_spki`]: the mTLS key to report.
    #[serde(deserialize_with = "nullable")]
    pub(super) credential_spki: Option<String>,
    /// The last revoked credential ID the client holds; only with an
    /// `operation_id`.
    #[serde(deserialize_with = "nullable")]
    pub(super) revoked_after: Option<String>,
}

/// A member that may be `null` but must be present: with
/// `deserialize_with`, serde refuses a missing member instead of taking
/// `None`.
fn nullable<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(deserializer)
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
        /// How many credentials the restore revoked.
        revoked_credential_count: i64,
        /// The first of them, at most `MAX_REVOKED_IDS_PER_REPLY`, in byte
        /// order.
        revoked_credential_ids: Vec<String>,
        recovery_key_epoch: i64,
        recovery_state_revision: i64,
    },
    Status(Box<StatusReply>),
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

/// The `status` reply: every member, in this order, `null` where it has
/// nothing to say (see the module docs of [`crate::local_transport`],
/// "Operations").
#[derive(Debug, Serialize, PartialEq, Eq, Default)]
pub(super) struct StatusReply {
    /// Whole microseconds since the Unix epoch, as every time here.
    pub(super) server_time: i64,
    pub(super) instance_id: Option<String>,
    pub(super) recovery_key_epoch: Option<i64>,
    pub(super) recovery_state_revision: Option<i64>,
    /// Lowercase hexadecimal.
    pub(super) recovery_public_key: Option<String>,
    pub(super) operation_state: Option<&'static str>,
    pub(super) expires_at: Option<i64>,
    pub(super) settles_at: Option<i64>,
    pub(super) restored_at: Option<i64>,
    pub(super) admin_id: Option<String>,
    pub(super) credential_id: Option<String>,
    pub(super) binding_id: Option<String>,
    pub(super) revoked_credential_count: Option<i64>,
    pub(super) revoked_credential_ids: Option<Vec<String>>,
    pub(super) enrolled_state: Option<&'static str>,
    pub(super) enrolled_admin_id: Option<String>,
    pub(super) enrolled_credential_id: Option<String>,
    /// Lowercase hexadecimal.
    pub(super) enrolled_trust_anchor_sha256: Option<String>,
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

    fn parse(text: &str) -> Result<Request, ()> {
        Request::parse(text.as_bytes()).ok_or(())
    }

    /// Serde's internally tagged enum takes a positional array too; the
    /// transport takes only an object.
    #[test]
    fn the_root_must_be_an_object() {
        let positional = r#"["restore","oper_1","00"]"#;
        assert!(serde_json::from_str::<Request>(positional).is_ok());
        for text in [
            positional,
            r#" ["preview","oper_1","00"]"#,
            r#"["bootstrap","i","00","t","00"]"#,
            r#"["issue_challenge","00","t","00"]"#,
            "null",
            "true",
            "1",
            r#""restore""#,
            "",
            " ",
            "\u{feff}{}",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(
            parse("\t\r {\"op\":\"restore\",\"operation_id\":\"o\",\"signature\":\"\"}").is_ok()
        );
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
            (
                r#"{"op":"status","operation_id":null,"credential_spki":null,"revoked_after":null}"#,
                "status",
            ),
            (
                r#"{"revoked_after":"c","credential_spki":"00","operation_id":"o","op":"status"}"#,
                "status",
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
            // A status member missing, mistyped, unknown or repeated: null
            // is a value, absence is not.
            r#"{"op":"status","credential_spki":null,"revoked_after":null}"#,
            r#"{"op":"status","operation_id":null,"revoked_after":null}"#,
            r#"{"op":"status","operation_id":null,"credential_spki":null}"#,
            r#"{"op":"status"}"#,
            r#"{"op":"status","operation_id":1,"credential_spki":null,"revoked_after":null}"#,
            r#"{"op":"status","operation_id":null,"credential_spki":[],"revoked_after":null}"#,
            r#"{"op":"status","operation_id":null,"credential_spki":null,"revoked_after":false}"#,
            r#"{"op":"status","operation_id":null,"credential_spki":null,"revoked_after":null,"signature":null}"#,
            r#"{"op":"status","operation_id":null,"operation_id":null,"credential_spki":null,"revoked_after":null}"#,
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
    fn a_status_member_is_null_or_a_string() {
        let Ok(Request::Status(empty)) = parse(
            r#"{"op":"status","operation_id":null,"credential_spki":null,"revoked_after":null}"#,
        ) else {
            panic!("not a status request");
        };
        assert_eq!(
            (
                empty.operation_id,
                empty.credential_spki,
                empty.revoked_after
            ),
            (None, None, None)
        );
        let Ok(Request::Status(full)) = parse(
            r#"{"op":"status","operation_id":"o","credential_spki":"00","revoked_after":""}"#,
        ) else {
            panic!("not a status request");
        };
        assert_eq!(
            (full.operation_id, full.credential_spki, full.revoked_after),
            (Some("o".into()), Some("00".into()), Some(String::new()))
        );
    }

    #[test]
    fn a_status_reply_has_every_member_in_order() {
        let nothing = Reply::Status(Box::new(StatusReply {
            server_time: 1,
            ..StatusReply::default()
        }));
        assert_eq!(
            String::from_utf8(nothing.line()).unwrap(),
            "{\"server_time\":1,\"instance_id\":null,\"recovery_key_epoch\":null,\
             \"recovery_state_revision\":null,\"recovery_public_key\":null,\
             \"operation_state\":null,\"expires_at\":null,\"settles_at\":null,\
             \"restored_at\":null,\"admin_id\":null,\"credential_id\":null,\
             \"binding_id\":null,\"revoked_credential_count\":null,\
             \"revoked_credential_ids\":null,\"enrolled_state\":null,\
             \"enrolled_admin_id\":null,\"enrolled_credential_id\":null,\
             \"enrolled_trust_anchor_sha256\":null}\n"
        );
    }

    /// The worst `restore` reply: a full page of the longest IDs the
    /// database allows (255 characters), each a control character that
    /// serializes as a six-byte escape, with the other members at their
    /// longest, stays far under the operator client's 4 MiB.
    #[test]
    fn a_full_page_of_the_worst_ids_is_under_the_clients_reply_limit() {
        let worst = "\u{1}".repeat(255);
        let ids = vec![worst.clone(); crate::local_transport::MAX_REVOKED_IDS_PER_REPLY];
        let restored = Reply::Restored {
            admin_id: worst.clone(),
            credential_id: worst.clone(),
            binding_id: worst.clone(),
            revoked_credential_count: i64::MAX,
            revoked_credential_ids: ids.clone(),
            recovery_key_epoch: i64::MAX,
            recovery_state_revision: i64::MAX,
        };
        let line = restored.line();
        assert!(line.len() > 1000 * 6 * 255, "{}", line.len());
        assert!(line.len() < 4 << 20, "{}", line.len());
        let status = Reply::Status(Box::new(StatusReply {
            server_time: i64::MIN,
            instance_id: Some(worst.clone()),
            recovery_key_epoch: Some(i64::MIN),
            recovery_state_revision: Some(i64::MIN),
            // The database allows a recovery key of 8192 bytes.
            recovery_public_key: Some("ff".repeat(8192)),
            operation_state: Some("not_found"),
            expires_at: Some(i64::MIN),
            settles_at: Some(i64::MIN),
            restored_at: Some(i64::MIN),
            admin_id: Some(worst.clone()),
            credential_id: Some(worst.clone()),
            binding_id: Some(worst.clone()),
            revoked_credential_count: Some(i64::MIN),
            revoked_credential_ids: Some(ids),
            enrolled_state: Some("disabled"),
            enrolled_admin_id: Some(worst.clone()),
            enrolled_credential_id: Some(worst),
            enrolled_trust_anchor_sha256: Some("ff".repeat(32)),
        }));
        let line = status.line();
        assert!(line.len() < 1_600_000, "{}", line.len());
        assert!(line.len() < 4 << 20, "{}", line.len());
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
