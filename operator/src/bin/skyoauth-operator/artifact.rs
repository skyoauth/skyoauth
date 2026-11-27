//! The two artifacts (`docs/proposals/operator-cli-artifacts.md`).
//!
//! - The challenge artifact is the `issue_challenge` reply line exactly as
//!   the deployment-local transport sent it, read with the transport's own
//!   codec ([`parse_reply`]); its `challenge` is `M`, read with
//!   [`parse_challenge`], and its `operation_id`, `expires_at` and
//!   `expected_revision` must be `M`'s.
//! - The response artifact is one line, `{"operation_id":"…","signature":"…"}`
//!   and its newline: the two members in that order, no whitespace, the
//!   operation ID escaped as the transport's codec escapes a string and
//!   the signature in lowercase hexadecimal.
//!
//! Every refusal is fixed text: no value of an artifact is repeated.

use skyoauth_operator::{
    local::{CallError, Op, Reply, UnknownOutcome, parse_reply},
    recovery::{Challenge, parse_challenge},
};

use crate::Failure;

/// The challenge of a challenge artifact.
///
/// # Errors
///
/// [`Failure::Refused`] when the artifact is not an `issue_challenge` reply
/// (a refusal of the transport included), its challenge is refused, or its
/// members are not its challenge's.
pub fn challenge(artifact: &[u8]) -> Result<Challenge, Failure> {
    let issued = match parse_reply(Op::IssueChallenge, artifact) {
        Ok(Reply::Issued(issued)) => issued,
        Ok(_) => {
            return Err(Failure::Refused(
                "the challenge artifact is not an issue_challenge reply".to_owned(),
            ));
        }
        Err(CallError::Refused(code)) => {
            return Err(Failure::Refused(format!(
                "the challenge artifact is a refusal of the local transport, not a challenge \
                 ({code})"
            )));
        }
        Err(CallError::Unknown(why)) => {
            return Err(Failure::Refused(format!(
                "the challenge artifact is not an issue_challenge reply: {why}"
            )));
        }
        Err(CallError::NotSent(_)) => {
            return Err(Failure::Refused(
                "the challenge artifact is not an issue_challenge reply".to_owned(),
            ));
        }
    };
    let challenge = parse_challenge(&issued.challenge).map_err(|err| {
        Failure::Refused(format!(
            "the challenge artifact's challenge is refused ({err:?}): {err}"
        ))
    })?;
    if challenge.operation_id() != issued.operation_id
        || challenge.expires_at_micros() != issued.expires_at
        || challenge.expected_revision() != issued.expected_revision
    {
        return Err(Failure::Refused(format!(
            "the challenge artifact is refused: {}",
            UnknownOutcome::ChallengeMismatch
        )));
    }
    Ok(challenge)
}

/// A response artifact: the operation ID and the signature's bytes, of
/// any length (the length is [`verify_response`]'s to refuse).
///
/// No `Debug`: the signature is not shown.
///
/// [`verify_response`]: skyoauth_operator::recovery::verify_response
pub struct Response {
    pub operation_id: String,
    pub signature: Vec<u8>,
}

/// The response of a response artifact.
///
/// # Errors
///
/// [`Failure::Refused`] when it is not one line of exactly the artifact's
/// form.
pub fn response(artifact: &[u8]) -> Result<Response, Failure> {
    let malformed =
        |why: &str| Failure::Refused(format!("the response artifact is malformed: {why}"));
    let line = artifact
        .strip_suffix(b"\n")
        .ok_or_else(|| malformed("it does not end with a newline"))?;
    if line.contains(&b'\n') {
        return Err(malformed("it is more than one line"));
    }
    let line = std::str::from_utf8(line).map_err(|_| malformed("it is not UTF-8"))?;
    let mut reader = Reader { text: line, at: 0 };
    let read = (|| {
        reader.token("{\"operation_id\":")?;
        let operation_id = reader.string()?;
        reader.token(",\"signature\":")?;
        let signature = reader.string()?;
        reader.token("}")?;
        if reader.at == reader.text.len() {
            Some((operation_id, signature))
        } else {
            None
        }
    })();
    let (operation_id, signature) = read
        .ok_or_else(|| malformed("it is not {\"operation_id\":\"...\",\"signature\":\"...\"}"))?;
    let signature = decode_hex(&signature)
        .ok_or_else(|| malformed("the signature is not lowercase hexadecimal"))?;
    Ok(Response {
        operation_id,
        signature,
    })
}

/// Reads the artifact's compact JSON: no whitespace, and only the escapes
/// the transport's codec writes (those of `serde_json`).
struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl Reader<'_> {
    fn next(&mut self) -> Option<u8> {
        let byte = *self.text.as_bytes().get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn token(&mut self, token: &str) -> Option<()> {
        if self.text.as_bytes()[self.at..].starts_with(token.as_bytes()) {
            self.at += token.len();
            Some(())
        } else {
            None
        }
    }

    /// A string, its escapes decoded: `\"`, `\\`, the five short control
    /// escapes, and `\u` with four lowercase digits for a control
    /// character that has no short escape. A raw control character, `\/`
    /// and any other escape are refused.
    fn string(&mut self) -> Option<String> {
        self.token("\"")?;
        let mut out = String::new();
        let mut run = self.at;
        loop {
            match self.text.as_bytes().get(self.at)? {
                b'"' => {
                    out.push_str(&self.text[run..self.at]);
                    self.at += 1;
                    return Some(out);
                }
                b'\\' => {
                    out.push_str(&self.text[run..self.at]);
                    self.at += 1;
                    out.push(self.escape()?);
                    run = self.at;
                }
                0x20.. => self.at += 1,
                _ => return None,
            }
        }
    }

    fn escape(&mut self) -> Option<char> {
        Some(match self.next()? {
            b'"' => '"',
            b'\\' => '\\',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let mut unit = 0;
                for _ in 0..4 {
                    unit = (unit << 4) | u32::from(hex_digit(self.next()?)?);
                }
                match char::from_u32(unit)? {
                    control @ ('\0'..='\u{7}' | '\u{b}' | '\u{e}'..='\u{1f}') => control,
                    _ => return None,
                }
            }
            _ => return None,
        })
    }
}

/// The value of one lowercase hexadecimal digit.
const fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The bytes of an even number of lowercase hexadecimal digits.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[high, low]| Some((hex_digit(*high)? << 4) | hex_digit(*low)?))
        .collect()
}
