//! [`parse_challenge`], which reads `M`, and [`check_challenge`], which
//! checks what it read against the operator's expectations.
//!
//! The reader is a small JSON reader limited to what `C` can hold: objects
//! two levels deep, strings, `i64` integers and `null`. It accepts JSON's
//! insignificant whitespace and every string escape, so that the final
//! byte comparison with the canonical re-encoding, not the reader, is what
//! refuses them; the closed shape (members, types, fixed values, order and
//! duplicates) is checked while reading, each with a reason of its own.

use std::{cmp::Ordering, fmt, time::Duration};

use super::{
    CHALLENGE_PREFIX, DEPLOYMENT_OPERATOR_ACTOR, KeyError, MAX_CHALLENGE_BYTES, MAX_CHALLENGE_TTL,
    OPERATOR_RESTORATION, PLAN_ADMIN_ID, PLAN_BINDING_ID, PLAN_CREDENTIAL_ID, PLAN_INSTANCE_ID,
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
    /// More than [`MAX_CHALLENGE_BYTES`] bytes; nothing of them is read.
    TooLarge,
    /// The bytes do not begin with [`CHALLENGE_PREFIX`], its newline
    /// included.
    Prefix,
    /// `C` is not UTF-8.
    NotUtf8,
    /// `C` is not one JSON value as the reader reads it: a bad token,
    /// string or escape, a raw control character in a string, or bytes
    /// after the value. A `t`, `f` or `[` where a value starts is
    /// [`ChallengeError::WrongType`] instead, whatever follows it.
    Syntax,
    /// A number that is not an `i64` integer in JSON's form: a fraction, an
    /// exponent, a leading zero, `-0`, or a value outside the `i64` range.
    Number,
    /// `C` or one of its members is not of its type: `C` or the plan not an
    /// object, a string member not a string, an integer member not an
    /// integer, or an object below the plan. A `t`, `f` or `[` where a
    /// value starts (a boolean or an array in JSON) is refused here at once,
    /// without reading further, so even when the rest is not JSON.
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
            Self::TooLarge => "the challenge is larger than 64 KiB",
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
            // The names so far are strictly increasing, so a name above the
            // last one is new and in order: one comparison per member. Only
            // a name that is not above the last one is compared with the
            // earlier names, once, and the object is refused.
            if let Some((last, _)) = members.last() {
                match last.as_bytes().cmp(name.as_bytes()) {
                    Ordering::Less => {}
                    Ordering::Equal => return Err(ChallengeError::DuplicateMember),
                    Ordering::Greater => {
                        return Err(if members.iter().any(|(seen, _)| *seen == name) {
                            ChallengeError::DuplicateMember
                        } else {
                            ChallengeError::UnsortedMembers
                        });
                    }
                }
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
/// `M` is read only when it is at most [`MAX_CHALLENGE_BYTES`] long, and
/// then in time linear in its length.
///
/// # Errors
///
/// The first [`ChallengeError`] met, in this order:
///
/// 1. [`ChallengeError::TooLarge`], then [`ChallengeError::Prefix`], then
///    [`ChallengeError::NotUtf8`];
/// 2. one pass of the reader over `C`, which stops at the first error in
///    the text: syntax, a number, a value of a type `C` never holds (a
///    `t`, `f` or `[` where a value starts is
///    [`ChallengeError::WrongType`] at once, even if the rest is not JSON),
///    a repeated or out-of-order member name, each where it occurs;
/// 3. `C` not an object, or a member of `C` other than its seven;
/// 4. the members of `C` taken one by one in byte-wise order, each checked
///    in full when taken: missing, of the wrong type, not its fixed value.
///    The plan, when taken, is checked the same way: a member other than
///    its eight, then its members one by one in byte-wise order, each with
///    its own type, text bound or key check, so a refused new key is
///    reported before a missing `trust_anchor_ref`. `tenant_id` comes
///    after the plan;
/// 5. the canonical comparison, [`ChallengeError::NotCanonical`].
pub fn parse_challenge(message: &[u8]) -> Result<Challenge, ChallengeError> {
    if message.len() > MAX_CHALLENGE_BYTES {
        return Err(ChallengeError::TooLarge);
    }
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
///
/// [`sign_challenge`](super::sign_challenge) signs only a challenge checked
/// with both [`Expectations::replacement_public_identity`] and
/// [`Expectations::new_recovery_public_key`] given (see
/// [`VerifiedChallenge::replacement_confirmed`]).
///
/// `Debug` prints `Expectations(..)`, none of the values: the instance and
/// the identity are not secret, but they are kept out of logs like the
/// challenge's own values.
#[derive(Clone, Copy)]
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

impl fmt::Debug for Expectations<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Expectations(..)")
    }
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
    replacement_confirmed: bool,
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

    /// Whether the operator confirmed the replacement: the check was given
    /// both the replacement's public identity and the new recovery public
    /// key, and both are the plan's. [`sign_challenge`](super::sign_challenge)
    /// refuses a challenge without it (interim pick: the replacement is
    /// what the signature authorizes, so the operator must have compared
    /// it, not only read it).
    pub const fn replacement_confirmed(&self) -> bool {
        self.replacement_confirmed
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
/// The result records whether `expected` gave both the replacement's
/// public identity and the new recovery public key
/// ([`VerifiedChallenge::replacement_confirmed`]): a challenge checked
/// without either passes, but is not signed.
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
    Ok(VerifiedChallenge {
        challenge,
        replacement_confirmed: expected.replacement_public_identity.is_some()
            && expected.new_recovery_public_key.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Duration};

    use super::*;

    /// The text of an object of `count` members `"m0000000":null`, ...,
    /// all different and in byte-wise order, then `tail` before its `}`.
    fn many_members(count: usize, tail: &str) -> String {
        let members: Vec<String> = (0..count).map(|i| format!("\"m{i:07}\":null")).collect();
        format!("{{{}{tail}}}", members.join(","))
    }

    fn read_object(text: &str) -> (Result<usize, ChallengeError>, bool) {
        let mut reader = Reader { text, at: 0 };
        let members = reader.object(1).map(|members| members.len());
        (members, reader.at == text.len())
    }

    /// The reader compares each member name with the last one only, so a
    /// large object is read in linear time. Not a timing measurement: the
    /// 300,000 members take some 300,000 name comparisons, where comparing
    /// each name with every earlier one takes some 4.5e10, so the bound of
    /// 5 seconds separates the two by orders of magnitude on any runner.
    /// (`parse_challenge` refuses such an input as too large before reading
    /// it, so the reader is called directly.)
    #[test]
    fn many_members_are_read_in_linear_time() {
        const MEMBERS: usize = 300_000;
        let text = many_members(MEMBERS, "");
        assert!(text.len() > 4_000_000);
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            let _ = done.send(read_object(&text));
        });
        let read = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("300,000 members are read within 5 seconds");
        assert_eq!(read, (Ok(MEMBERS), true));
    }

    /// After many members, a repeated name is still found among the earlier
    /// ones, and a new name out of order is unsorted.
    #[test]
    fn a_late_repeated_or_unsorted_name_is_found() {
        for (tail, expected) in [
            (",\"m0000000\":null", ChallengeError::DuplicateMember),
            (",\"m0000500\":null", ChallengeError::DuplicateMember),
            (",\"m0000999\":null", ChallengeError::DuplicateMember),
            (",\"\\u006d0000500\":null", ChallengeError::DuplicateMember),
            (",\"m0000500a\":null", ChallengeError::UnsortedMembers),
            (",\"a\":null", ChallengeError::UnsortedMembers),
        ] {
            assert_eq!(
                read_object(&many_members(1000, tail)).0,
                Err(expected),
                "{tail}"
            );
        }
        assert_eq!(read_object(&many_members(1000, ",\"n\":null")).0, Ok(1001));
    }
}
