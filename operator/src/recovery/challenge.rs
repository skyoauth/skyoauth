//! [`parse_challenge`], which reads `M`, and [`check_challenge`], which
//! checks what it read against the operator's expectations.
//!
//! The reader is a small JSON reader limited to what `C` can hold: objects
//! two levels deep, strings, `i64` integers and `null`. It accepts JSON's
//! insignificant whitespace and every string escape, so that the final
//! byte comparison with the canonical re-encoding, not the reader, is what
//! refuses them; the closed shape (members, types, fixed values, order and
//! duplicates) is checked while reading, each with a reason of its own.

use std::{fmt, time::Duration};

use super::{
    CHALLENGE_PREFIX, DEPLOYMENT_OPERATOR_ACTOR, KeyError, MAX_CHALLENGE_TTL, OPERATOR_RESTORATION,
    PLAN_ADMIN_ID, PLAN_BINDING_ID, PLAN_CREDENTIAL_ID, PLAN_INSTANCE_ID,
    PLAN_NEW_RECOVERY_PUBLIC_KEY, PLAN_PUBLIC_IDENTITY, PLAN_RECOVERY_KEY_EPOCH,
    PLAN_TRUST_ANCHOR_REF, RecoveryPublicKey, canonical_json,
};

/// The members of `C`, in byte-wise order.
const CHALLENGE_MEMBERS: [&str; 7] = [
    "actor_id",
    "expected_revision",
    "expires_at",
    "id",
    "kind",
    "plan",
    "tenant_id",
];

/// The members of the plan, in byte-wise order.
const PLAN_MEMBERS: [&str; 8] = [
    PLAN_ADMIN_ID,
    PLAN_BINDING_ID,
    PLAN_CREDENTIAL_ID,
    PLAN_INSTANCE_ID,
    PLAN_NEW_RECOVERY_PUBLIC_KEY,
    PLAN_PUBLIC_IDENTITY,
    PLAN_RECOVERY_KEY_EPOCH,
    PLAN_TRUST_ANCHOR_REF,
];

/// The longest `public_identity` and `trust_anchor_ref`, in bytes (the
/// service's bound).
const MAX_EXACT_STRING: usize = 2048;

/// The deepest object nesting of `C`: `C` itself and its plan.
const MAX_DEPTH: usize = 2;

/// How far after the operator's time [`check_challenge`] accepts an
/// `expires_at`: the longest TTL the service gives a challenge.
///
/// Inferred, an interim pick: `M` carries no issue time, so the TTL cannot
/// be checked against the issue, and this bounds the expiry from the
/// operator's clock instead. By design, an operator clock that lags the
/// service's by more than the longest TTL less the challenge's own TTL
/// refuses the challenge. The check uses only this constant, so it can be
/// dropped or changed here alone.
const EXPIRY_HORIZON: Duration = MAX_CHALLENGE_TTL;

/// Why bytes are not a challenge [`parse_challenge`] accepts. Carries no
/// input byte: `Debug` names the reason only, `Display` is fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    /// The bytes do not begin with [`CHALLENGE_PREFIX`], its newline
    /// included.
    Prefix,
    /// `C` is not UTF-8.
    NotUtf8,
    /// `C` is not one JSON value (a bad token, string or escape, a raw
    /// control character in a string, or bytes after the value).
    Syntax,
    /// A number that is not an `i64` integer in JSON's form: a fraction, an
    /// exponent, a leading zero, `-0`, or a value outside the `i64` range.
    Number,
    /// `C` or one of its members is not of its type: `C` or the plan not an
    /// object, a string member not a string, an integer member not an
    /// integer, a boolean, an array, or an object below the plan.
    WrongType,
    /// An object names one member twice.
    DuplicateMember,
    /// An object's members are not in byte-wise order of their names.
    UnsortedMembers,
    /// `C` or the plan has a member other than its seven or eight.
    UnknownMember,
    /// `C` or the plan lacks one of its seven or eight members.
    MissingMember,
    /// `actor_id` is not [`DEPLOYMENT_OPERATOR_ACTOR`], `kind` not
    /// [`OPERATOR_RESTORATION`], or `tenant_id` not `null`.
    FixedValue,
    /// The plan's `public_identity` or `trust_anchor_ref` is empty or over
    /// 2048 bytes.
    TextBounds,
    /// The plan's `new_recovery_public_key` is refused by
    /// [`RecoveryPublicKey::from_hex`].
    NewRecoveryKey(KeyError),
    /// `C` is not the canonical encoding of what it holds (whitespace, an
    /// escape the canonical form does not use, ...).
    NotCanonical,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Prefix => "the challenge does not begin with the recovery challenge prefix",
            Self::NotUtf8 => "the challenge is not UTF-8",
            Self::Syntax => "the challenge is not one JSON value",
            Self::Number => "the challenge holds a number that is not a 64-bit integer",
            Self::WrongType => "the challenge holds a value of the wrong type",
            Self::DuplicateMember => "the challenge names a member twice",
            Self::UnsortedMembers => "the challenge's members are not in byte-wise order",
            Self::UnknownMember => "the challenge holds an unknown member",
            Self::MissingMember => "the challenge lacks a member",
            Self::FixedValue => {
                "the challenge is not an operator restoration by the deployment operator \
                 without a tenant"
            }
            Self::TextBounds => {
                "the plan's public identity or trust anchor reference is empty or over 2048 bytes"
            }
            Self::NewRecoveryKey(_) => "the plan's new recovery public key is refused",
            Self::NotCanonical => "the challenge is not canonically encoded",
        })
    }
}

impl std::error::Error for ChallengeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NewRecoveryKey(err) => Some(err),
            _ => None,
        }
    }
}

/// The plan of an operator restoration: the instance and the key epoch the
/// challenge is bound to, and the replacement operator it enrolls.
///
/// The operator does not copy the service's refusal of a reserved
/// `admin_id` (`deployment_operator`, or one beginning with
/// `recovery_key:`): the service stays authoritative and refuses such a
/// plan at the issue and again at the restore.
///
/// `Debug` prints `RestorationPlan(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct RestorationPlan {
    pub instance_id: String,
    pub recovery_key_epoch: i64,
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    pub public_identity: String,
    pub trust_anchor_ref: String,
    pub new_recovery_public_key: RecoveryPublicKey,
}

impl fmt::Debug for RestorationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RestorationPlan(..)")
    }
}

/// A challenge [`parse_challenge`] accepted: `M`, exactly as received, and
/// what it holds. Not yet checked against anything the operator expects
/// (see [`check_challenge`]).
///
/// `Debug` prints `Challenge(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct Challenge {
    message: Vec<u8>,
    operation_id: String,
    expected_revision: i64,
    expires_at_micros: i64,
    plan: RestorationPlan,
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenge(..)")
    }
}

impl Challenge {
    /// `M`, the bytes [`parse_challenge`] accepted.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// `C`'s `id`, the operation ID of the challenge.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// `C`'s `expected_revision`, the recovery state revision the challenge
    /// is bound to.
    pub const fn expected_revision(&self) -> i64 {
        self.expected_revision
    }

    /// `C`'s `expires_at`, in whole microseconds since the Unix epoch.
    pub const fn expires_at_micros(&self) -> i64 {
        self.expires_at_micros
    }

    /// `C`'s plan.
    pub const fn plan(&self) -> &RestorationPlan {
        &self.plan
    }
}

/// A JSON value of the shapes `C` can hold.
enum Value {
    Null,
    Integer(i64),
    Text(String),
    Object(Vec<(String, Value)>),
}

/// Reads JSON from text, byte by byte; see the module documentation.
struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Reader<'a> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.at += 1;
        Some(byte)
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ChallengeError> {
        if self.next() == Some(byte) {
            Ok(())
        } else {
            Err(ChallengeError::Syntax)
        }
    }

    /// A value at object depth `depth` (0 for `C`).
    fn value(&mut self, depth: usize) -> Result<Value, ChallengeError> {
        match self.peek() {
            Some(b'"') => Ok(Value::Text(self.string()?)),
            Some(b'{') if depth < MAX_DEPTH => Ok(Value::Object(self.object(depth + 1)?)),
            Some(b'-' | b'0'..=b'9') => Ok(Value::Integer(self.integer()?)),
            Some(b'n') => {
                if self.text[self.at..].starts_with("null") {
                    self.at += 4;
                    Ok(Value::Null)
                } else {
                    Err(ChallengeError::Syntax)
                }
            }
            // `true`, `false`, an array or an object below the plan: JSON,
            // but nothing `C` holds.
            Some(b't' | b'f' | b'[' | b'{') => Err(ChallengeError::WrongType),
            _ => Err(ChallengeError::Syntax),
        }
    }

    /// An object whose values are at depth `depth`; refuses a repeated
    /// name and names out of byte-wise order as they come.
    fn object(&mut self, depth: usize) -> Result<Vec<(String, Value)>, ChallengeError> {
        self.expect(b'{')?;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(members);
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(ChallengeError::Syntax);
            }
            let name = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value(depth)?;
            if members.iter().any(|(seen, _)| *seen == name) {
                return Err(ChallengeError::DuplicateMember);
            }
            if members
                .last()
                .is_some_and(|(last, _)| last.as_bytes() > name.as_bytes())
            {
                return Err(ChallengeError::UnsortedMembers);
            }
            members.push((name, value));
            self.skip_whitespace();
            match self.next() {
                Some(b',') => {}
                Some(b'}') => return Ok(members),
                _ => return Err(ChallengeError::Syntax),
            }
        }
    }

    /// A string, its escapes decoded.
    fn string(&mut self) -> Result<String, ChallengeError> {
        self.expect(b'"')?;
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
                // A raw control character, or the end of the text.
                _ => return Err(ChallengeError::Syntax),
            }
        }
    }

    /// The character of the escape after a reverse solidus.
    fn escape(&mut self) -> Result<char, ChallengeError> {
        Ok(match self.next() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let unit = self.code_unit()?;
                let code = match unit {
                    0xd800..=0xdbff => {
                        self.expect(b'\\')?;
                        self.expect(b'u')?;
                        let low = self.code_unit()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err(ChallengeError::Syntax);
                        }
                        0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
                    }
                    other => other,
                };
                // `None` for a lone low surrogate.
                char::from_u32(code).ok_or(ChallengeError::Syntax)?
            }
            _ => return Err(ChallengeError::Syntax),
        })
    }

    /// The four hexadecimal digits of a `\u` escape, in either case.
    fn code_unit(&mut self) -> Result<u32, ChallengeError> {
        let mut unit = 0;
        for _ in 0..4 {
            let digit = self
                .next()
                .and_then(|byte| char::from(byte).to_digit(16))
                .ok_or(ChallengeError::Syntax)?;
            unit = (unit << 4) | digit;
        }
        Ok(unit)
    }

    /// An integer in JSON's form (an optional minus, then `0` or a nonzero
    /// digit and more digits) in the `i64` range, other than `-0`.
    fn integer(&mut self) -> Result<i64, ChallengeError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.next() {
            Some(b'0') => {
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(ChallengeError::Number);
                }
            }
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.at += 1;
                }
            }
            _ => return Err(ChallengeError::Syntax),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(ChallengeError::Number);
        }
        let digits = &self.text[start..self.at];
        if digits == "-0" {
            return Err(ChallengeError::Number);
        }
        digits.parse().map_err(|_| ChallengeError::Number)
    }
}

/// The members of an object that must have exactly `names`: refuses any
/// other name. A missing one is refused when it is taken.
fn closed(
    members: Vec<(String, Value)>,
    names: &[&str],
) -> Result<Vec<(String, Value)>, ChallengeError> {
    if members
        .iter()
        .any(|(name, _)| !names.contains(&name.as_str()))
    {
        return Err(ChallengeError::UnknownMember);
    }
    Ok(members)
}

/// Takes the member `name` out of `members`.
fn take(members: &mut Vec<(String, Value)>, name: &str) -> Result<Value, ChallengeError> {
    let index = members
        .iter()
        .position(|(member, _)| member == name)
        .ok_or(ChallengeError::MissingMember)?;
    Ok(members.swap_remove(index).1)
}

fn text(value: Value) -> Result<String, ChallengeError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(ChallengeError::WrongType),
    }
}

fn integer(value: Value) -> Result<i64, ChallengeError> {
    match value {
        Value::Integer(integer) => Ok(integer),
        _ => Err(ChallengeError::WrongType),
    }
}

/// A string member that must be `expected`.
fn fixed(value: Value, expected: &str) -> Result<(), ChallengeError> {
    if text(value)? == expected {
        Ok(())
    } else {
        Err(ChallengeError::FixedValue)
    }
}

/// A plan string that must be 1 to 2048 bytes long.
fn bounded(value: Value) -> Result<String, ChallengeError> {
    let text = text(value)?;
    if (1..=MAX_EXACT_STRING).contains(&text.len()) {
        Ok(text)
    } else {
        Err(ChallengeError::TextBounds)
    }
}

/// The plan, from the members of its object.
fn plan(members: Vec<(String, Value)>) -> Result<RestorationPlan, ChallengeError> {
    let mut members = closed(members, &PLAN_MEMBERS)?;
    let mut member = |name| take(&mut members, name);
    Ok(RestorationPlan {
        admin_id: text(member(PLAN_ADMIN_ID)?)?,
        binding_id: text(member(PLAN_BINDING_ID)?)?,
        credential_id: text(member(PLAN_CREDENTIAL_ID)?)?,
        instance_id: text(member(PLAN_INSTANCE_ID)?)?,
        new_recovery_public_key: RecoveryPublicKey::from_hex(&text(member(
            PLAN_NEW_RECOVERY_PUBLIC_KEY,
        )?)?)
        .map_err(ChallengeError::NewRecoveryKey)?,
        public_identity: bounded(member(PLAN_PUBLIC_IDENTITY)?)?,
        recovery_key_epoch: integer(member(PLAN_RECOVERY_KEY_EPOCH)?)?,
        trust_anchor_ref: bounded(member(PLAN_TRUST_ANCHOR_REF)?)?,
    })
}

/// Reads the challenge `M` the service issued, strictly: `M` must be
/// [`CHALLENGE_PREFIX`] followed by `C`, the UTF-8 text of one JSON object
/// with exactly the seven members of a challenge, its `actor_id`, `kind`
/// and `tenant_id` the fixed values, and a plan with exactly its eight
/// members; and `C` must be the byte-for-byte canonical encoding
/// ([`canonical_json`]) of what it holds.
///
/// It checks nothing against the operator's expectations or clock: see
/// [`check_challenge`].
///
/// # Errors
///
/// The first [`ChallengeError`] met, in this order: the prefix, UTF-8, the
/// JSON reading (syntax, numbers, value types, duplicate and unsorted
/// members, as they come), then the members of `C` in byte-wise order (an
/// unknown or missing member, a type, a fixed value, the plan's members
/// likewise, the plan's text bounds and new key), and last the canonical
/// comparison.
pub fn parse_challenge(message: &[u8]) -> Result<Challenge, ChallengeError> {
    let canonical = message
        .strip_prefix(CHALLENGE_PREFIX)
        .ok_or(ChallengeError::Prefix)?;
    let text_of_c = std::str::from_utf8(canonical).map_err(|_| ChallengeError::NotUtf8)?;
    let mut reader = Reader {
        text: text_of_c,
        at: 0,
    };
    reader.skip_whitespace();
    let root = reader.value(0)?;
    reader.skip_whitespace();
    if reader.at != text_of_c.len() {
        return Err(ChallengeError::Syntax);
    }
    let Value::Object(members) = root else {
        return Err(ChallengeError::WrongType);
    };
    let mut members = closed(members, &CHALLENGE_MEMBERS)?;
    let mut member = |name| take(&mut members, name);
    fixed(member("actor_id")?, DEPLOYMENT_OPERATOR_ACTOR)?;
    let expected_revision = integer(member("expected_revision")?)?;
    let expires_at_micros = integer(member("expires_at")?)?;
    let operation_id = text(member("id")?)?;
    fixed(member("kind")?, OPERATOR_RESTORATION)?;
    let Value::Object(plan_members) = member("plan")? else {
        return Err(ChallengeError::WrongType);
    };
    let plan = plan(plan_members)?;
    if !matches!(member("tenant_id")?, Value::Null) {
        return Err(ChallengeError::FixedValue);
    }
    let encoded = canonical_json(&operation_id, expected_revision, expires_at_micros, &plan);
    if encoded.as_bytes() != canonical {
        return Err(ChallengeError::NotCanonical);
    }
    Ok(Challenge {
        message: message.to_vec(),
        operation_id,
        expected_revision,
        expires_at_micros,
        plan,
    })
}

/// What the operator expects of a challenge, and the operator's clock.
#[derive(Debug, Clone, Copy)]
pub struct Expectations<'a> {
    /// The instance the operator means to restore, compared byte-wise with
    /// the plan's `instance_id`.
    pub instance_id: &'a str,
    /// The operator's time, in whole microseconds since the Unix epoch.
    /// The library reads no clock.
    pub now_micros: i64,
    /// The epoch of the recovery key the operator holds, when known.
    pub recovery_key_epoch: Option<i64>,
    /// The public identity of the replacement credential the operator
    /// approves, when known.
    pub replacement_public_identity: Option<&'a str>,
    /// The new recovery public key the operator approves, when known.
    pub new_recovery_public_key: Option<&'a RecoveryPublicKey>,
}

/// Why [`check_challenge`] refused a challenge. `Debug` names the reason
/// only, `Display` is fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The plan names another instance.
    OtherInstance,
    /// The challenge has expired: the operator's time is at or after
    /// `expires_at`.
    Expired,
    /// `expires_at` is more than [`MAX_CHALLENGE_TTL`] after the operator's
    /// time (an inferred horizon; see [`check_challenge`]).
    ExpiresTooLate,
    /// The plan names another recovery key epoch.
    OtherEpoch,
    /// The plan's replacement has another public identity.
    OtherReplacementIdentity,
    /// The plan's new recovery public key is another one.
    OtherNewRecoveryKey,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OtherInstance => "the challenge is for another instance",
            Self::Expired => "the challenge has expired",
            Self::ExpiresTooLate => {
                "the challenge expires later than the longest challenge TTL from now"
            }
            Self::OtherEpoch => "the challenge is for another recovery key epoch",
            Self::OtherReplacementIdentity => {
                "the challenge enrolls a replacement with another public identity"
            }
            Self::OtherNewRecoveryKey => "the challenge sets another new recovery public key",
        })
    }
}

impl std::error::Error for Refusal {}

/// A challenge that passed [`check_challenge`]. Only that function makes
/// one, so a value of this type is a challenge checked against the
/// operator's expectations; it is what the operator signs.
///
/// `Debug` prints `VerifiedChallenge(..)`, none of the values.
pub struct VerifiedChallenge<'c> {
    challenge: &'c Challenge,
}

impl fmt::Debug for VerifiedChallenge<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedChallenge(..)")
    }
}

impl<'c> VerifiedChallenge<'c> {
    /// The challenge that was checked.
    pub const fn challenge(&self) -> &'c Challenge {
        self.challenge
    }

    /// `M`, the bytes to sign.
    pub fn message(&self) -> &'c [u8] {
        &self.challenge.message
    }
}

/// Checks `challenge` against what the operator expects, in this order:
///
/// 1. the plan's `instance_id` is `expected.instance_id`, byte for byte;
/// 2. `expected.now_micros < expires_at`, as the service checks it at the
///    restore: a challenge is refused from its `expires_at` on;
/// 3. `expires_at` is at most [`MAX_CHALLENGE_TTL`] after
///    `expected.now_micros`. This horizon is inferred, an interim pick:
///    the service issues no challenge with a longer TTL, but `M` carries no
///    issue time, so the expiry is bounded from the operator's clock
///    instead. By design, an operator clock that lags the service's by more
///    than the longest TTL less the challenge's own TTL refuses it;
/// 4. the plan's `recovery_key_epoch`, `public_identity` and
///    `new_recovery_public_key` are the expected ones, for each that
///    `expected` gives.
///
/// The new recovery public key itself already passed the service's key
/// checks in [`parse_challenge`].
///
/// # Errors
///
/// The [`Refusal`] of the first check that fails.
pub fn check_challenge<'c>(
    challenge: &'c Challenge,
    expected: &Expectations<'_>,
) -> Result<VerifiedChallenge<'c>, Refusal> {
    let plan = &challenge.plan;
    if plan.instance_id.as_bytes() != expected.instance_id.as_bytes() {
        return Err(Refusal::OtherInstance);
    }
    if expected.now_micros >= challenge.expires_at_micros {
        return Err(Refusal::Expired);
    }
    // The inferred horizon (see `EXPIRY_HORIZON`).
    let ahead = i128::from(challenge.expires_at_micros) - i128::from(expected.now_micros);
    if u128::try_from(ahead).is_ok_and(|ahead| ahead > EXPIRY_HORIZON.as_micros()) {
        return Err(Refusal::ExpiresTooLate);
    }
    if expected
        .recovery_key_epoch
        .is_some_and(|epoch| epoch != plan.recovery_key_epoch)
    {
        return Err(Refusal::OtherEpoch);
    }
    if expected
        .replacement_public_identity
        .is_some_and(|identity| identity.as_bytes() != plan.public_identity.as_bytes())
    {
        return Err(Refusal::OtherReplacementIdentity);
    }
    if expected
        .new_recovery_public_key
        .is_some_and(|key| *key != plan.new_recovery_public_key)
    {
        return Err(Refusal::OtherNewRecoveryKey);
    }
    Ok(VerifiedChallenge { challenge })
}
