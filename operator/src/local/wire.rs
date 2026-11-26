//! The request line encoder ([`Request::encode`]) and the reply line
//! parser ([`parse_reply`]); see the [module documentation](super).
//!
//! Both sides of the wire are closed shapes, so neither needs a general
//! JSON library. The encoder writes the one form the golden lines fix: the
//! `op` member first, then the operation's members in the service's order,
//! no whitespace, strings escaped as the service's JSON writer escapes
//! them. The parser reads the one form the service writes (its replies are
//! `serde_json`'s compact output of fixed shapes): the members of the
//! request's own success in their order, or the single `error` member, with
//! no whitespace, only the escapes that writer uses and integers in their
//! shortest form. Anything else is [`UnknownOutcome::Malformed`]: a reply
//! the client cannot read exactly is never taken as a success or a refusal.

use super::{
    Bootstrapped, CallError, ErrorCode, Issued, MAX_REPLY_BYTES, MAX_REQUEST_BYTES, NotSent, Op,
    Previewed, Reply, Request, RequestLine, Restored, UnknownOutcome,
};
use crate::text::{decode_hex, encode_hex};

/// The member that names the operation, first in every request.
const OP_MEMBER: &str = "op";

/// The one member of a refusal.
const ERROR_MEMBER: &str = "error";

impl Request {
    /// The request line: one JSON object, the `op` member first and then
    /// the operation's members in the service's order (as the fixture's
    /// golden lines fix them), with no whitespace, and the newline. Byte
    /// values are lowercase hexadecimal; strings are escaped as the
    /// service's JSON writer escapes them, so the line never holds a raw
    /// newline before its end. The values are not checked: the server
    /// decides, and refuses a bad one with `invalid_request`.
    ///
    /// # Errors
    ///
    /// [`NotSent::TooLarge`] when the line, its newline included, is longer
    /// than [`MAX_REQUEST_BYTES`]: such a request must not be written, and
    /// no connection is made for it.
    pub fn encode(&self) -> Result<RequestLine, NotSent> {
        let mut line = String::with_capacity(256);
        line.push('{');
        push_name(&mut line, OP_MEMBER);
        push_string(&mut line, self.op().as_str());
        match self {
            Self::Bootstrap(request) => {
                push_member(&mut line, "instance_id", &request.instance_id);
                push_member(
                    &mut line,
                    "credential_spki",
                    &encode_hex(&request.credential_spki),
                );
                push_member(&mut line, "trust_anchor_ref", &request.trust_anchor_ref);
                push_member(
                    &mut line,
                    "recovery_public_key",
                    &request.recovery_public_key.to_hex(),
                );
            }
            Self::IssueChallenge(request) => {
                push_member(
                    &mut line,
                    "credential_spki",
                    &encode_hex(&request.credential_spki),
                );
                push_member(&mut line, "trust_anchor_ref", &request.trust_anchor_ref);
                push_member(
                    &mut line,
                    "new_recovery_public_key",
                    &request.new_recovery_public_key.to_hex(),
                );
            }
            Self::Preview(request) | Self::Restore(request) => {
                push_member(&mut line, "operation_id", &request.operation_id);
                push_member(&mut line, "signature", &encode_hex(&request.signature));
            }
        }
        line.push_str("}\n");
        if line.len() > MAX_REQUEST_BYTES {
            return Err(NotSent::TooLarge);
        }
        Ok(RequestLine(line.into_bytes()))
    }
}

/// Appends `,"name":` and `value` as a JSON string.
fn push_member(out: &mut String, name: &str, value: &str) {
    out.push(',');
    push_name(out, name);
    push_string(out, value);
}

/// Appends a member name and its colon.
fn push_name(out: &mut String, name: &str) {
    push_string(out, name);
    out.push(':');
}

/// Appends `value` as a JSON string, escaped as `serde_json` escapes it:
/// `"` and `\` after a reverse solidus, the five short control escapes,
/// any other character below U+0020 as `\u` and four lowercase
/// hexadecimal digits, and every other character as is. (The same escapes
/// as the recovery challenge's canonical writer.)
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

/// The reply line in `line`, everything the client read on the
/// connection, for a request of `op`.
///
/// It must be one line, at most [`MAX_REPLY_BYTES`] with its newline, and
/// nothing after the newline; the line must be UTF-8 and exactly what the
/// service writes for either `op`'s success (its members in their order,
/// [`Reply`]) or a refusal, `{"error":"<code>"}`.
///
/// # Errors
///
/// - [`CallError::Refused`] with the code of a refusal of the closed set;
/// - [`CallError::Unknown`] for everything else, checked in this order:
///   [`UnknownOutcome::TooLarge`], [`UnknownOutcome::Truncated`] (no
///   newline, no byte at all included), [`UnknownOutcome::TrailingBytes`],
///   [`UnknownOutcome::NotUtf8`], then [`UnknownOutcome::Malformed`] or
///   [`UnknownOutcome::UnknownCode`].
///
/// Never [`CallError::NotSent`]: a reply means the request was written.
pub fn parse_reply(op: Op, line: &[u8]) -> Result<Reply, CallError> {
    if line.len() > MAX_REPLY_BYTES {
        return Err(CallError::Unknown(UnknownOutcome::TooLarge));
    }
    let Some(newline) = line.iter().position(|byte| *byte == b'\n') else {
        return Err(CallError::Unknown(UnknownOutcome::Truncated));
    };
    if newline + 1 != line.len() {
        return Err(CallError::Unknown(UnknownOutcome::TrailingBytes));
    }
    let body = std::str::from_utf8(&line[..newline])
        .map_err(|_| CallError::Unknown(UnknownOutcome::NotUtf8))?;
    let mut reader = Reader { text: body, at: 0 };
    reader.token("{")?;
    if reader.member(ERROR_MEMBER, true).is_ok() {
        let code = reader.string()?;
        reader.close()?;
        return Err(ErrorCode::ALL
            .into_iter()
            .find(|known| known.as_str() == code)
            .map_or(
                CallError::Unknown(UnknownOutcome::UnknownCode),
                CallError::Refused,
            ));
    }
    // The members in the service's order: a struct expression's fields are
    // evaluated in the order they are written.
    let reply = match op {
        Op::Bootstrap => Reply::Bootstrapped(Bootstrapped {
            instance_id: reader.text("instance_id", true)?,
            admin_id: reader.text("admin_id", false)?,
            credential_id: reader.text("credential_id", false)?,
            binding_id: reader.text("binding_id", false)?,
            recovery_key_epoch: reader.integer_member("recovery_key_epoch")?,
        }),
        Op::IssueChallenge => Reply::Issued(Issued {
            operation_id: reader.text("operation_id", true)?,
            expires_at: reader.integer_member("expires_at")?,
            expected_revision: reader.integer_member("expected_revision")?,
            challenge: decode_hex(&reader.text("challenge", false)?).ok_or(Malformed)?,
        }),
        Op::Preview => Reply::Previewed(Previewed {
            admin_id: reader.text("admin_id", true)?,
            credential_id: reader.text("credential_id", false)?,
            binding_id: reader.text("binding_id", false)?,
            new_recovery_key_epoch: reader.integer_member("new_recovery_key_epoch")?,
            expires_at: reader.integer_member("expires_at")?,
        }),
        Op::Restore => Reply::Restored(Restored {
            admin_id: reader.text("admin_id", true)?,
            credential_id: reader.text("credential_id", false)?,
            binding_id: reader.text("binding_id", false)?,
            revoked_credential_ids: {
                reader.member("revoked_credential_ids", false)?;
                reader.strings()?
            },
            recovery_key_epoch: reader.integer_member("recovery_key_epoch")?,
            recovery_state_revision: reader.integer_member("recovery_state_revision")?,
        }),
    };
    reader.close()?;
    Ok(reply)
}

/// The reply line is not what the service writes.
struct Malformed;

impl From<Malformed> for CallError {
    fn from(_: Malformed) -> Self {
        Self::Unknown(UnknownOutcome::Malformed)
    }
}

/// Reads the service's compact JSON, byte by byte: no whitespace anywhere.
struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    /// Consumes `token`, which must come next.
    fn token(&mut self, token: &str) -> Result<(), Malformed> {
        if self.text.as_bytes()[self.at..].starts_with(token.as_bytes()) {
            self.at += token.len();
            Ok(())
        } else {
            Err(Malformed)
        }
    }

    /// Consumes the name of the member `name` and its colon, after a comma
    /// unless it is the `first` member. Consumes nothing when they do not
    /// come next.
    fn member(&mut self, name: &str, first: bool) -> Result<(), Malformed> {
        let start = self.at;
        let read = (|| {
            if !first {
                self.token(",")?;
            }
            self.token("\"")?;
            self.token(name)?;
            self.token("\":")
        })();
        if read.is_err() {
            self.at = start;
        }
        read
    }

    /// The end of the object, which must be the end of the line.
    fn close(&mut self) -> Result<(), Malformed> {
        self.token("}")?;
        if self.at == self.text.len() {
            Ok(())
        } else {
            Err(Malformed)
        }
    }

    /// The string member `name`.
    fn text(&mut self, name: &str, first: bool) -> Result<String, Malformed> {
        self.member(name, first)?;
        self.string()
    }

    /// The integer member `name`, never the first.
    fn integer_member(&mut self, name: &str) -> Result<i64, Malformed> {
        self.member(name, false)?;
        self.integer()
    }

    /// A string, its escapes decoded. Only the escapes the service's
    /// writer uses are read (see `push_string`): `\/`, a `\u` escape of a
    /// character that is not a control character or has a short escape,
    /// and upper-case digits are refused, as is a raw control character.
    fn string(&mut self) -> Result<String, Malformed> {
        self.token("\"")?;
        let mut out = String::new();
        let mut run = self.at;
        loop {
            match self.peek() {
                Some(b'"') => {
                    out.push_str(&self.text[run..self.at]);
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    out.push_str(&self.text[run..self.at]);
                    self.at += 1;
                    out.push(self.escape()?);
                    run = self.at;
                }
                Some(0x20..) => self.at += 1,
                // A raw control character, or the end of the line.
                _ => return Err(Malformed),
            }
        }
    }

    /// The character of the escape after a reverse solidus.
    fn escape(&mut self) -> Result<char, Malformed> {
        Ok(match self.next() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let mut unit = 0;
                for _ in 0..4 {
                    let digit = match self.next() {
                        Some(digit @ b'0'..=b'9') => digit - b'0',
                        Some(digit @ b'a'..=b'f') => digit - b'a' + 10,
                        _ => return Err(Malformed),
                    };
                    unit = (unit << 4) | u32::from(digit);
                }
                match char::from_u32(unit) {
                    Some(control @ ('\0'..='\u{7}' | '\u{b}' | '\u{e}'..='\u{1f}')) => control,
                    _ => return Err(Malformed),
                }
            }
            _ => return Err(Malformed),
        })
    }

    /// An integer in its shortest decimal form (an optional minus, then `0`
    /// or a nonzero digit and more digits; not `-0`) in the `i64` range. A
    /// fraction or an exponent is refused by what must follow.
    fn integer(&mut self) -> Result<i64, Malformed> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.next() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.at += 1;
                }
            }
            _ => return Err(Malformed),
        }
        let digits = &self.text[start..self.at];
        if digits == "-0" {
            return Err(Malformed);
        }
        digits.parse().map_err(|_| Malformed)
    }

    /// An array of strings, maybe empty.
    fn strings(&mut self) -> Result<Vec<String>, Malformed> {
        self.token("[")?;
        let mut strings = Vec::new();
        if self.token("]").is_ok() {
            return Ok(strings);
        }
        loop {
            strings.push(self.string()?);
            match self.next() {
                Some(b',') => {}
                Some(b']') => return Ok(strings),
                _ => return Err(Malformed),
            }
        }
    }
}
