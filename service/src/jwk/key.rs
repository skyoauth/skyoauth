//! One uploaded JWK: its members, key material, strength and algorithm
//! (see the module docs of [`crate::jwk`] for the rules and their sources).

use std::fmt;

use serde_json::{Map, Value};

use super::base64url::{self, Base64urlError};
use super::thumbprint::{Thumbprint, thumbprint};

/// The private and symmetric key members (RFC 7518 section 6: `d`, `p`,
/// `q`, `dp`, `dq`, `qi`, `oth`, `k`; RFC 8037 section 2: `d`), the set the
/// `0004` `CHECK` rejects too. Matched case-sensitively, as JSON member
/// names are.
pub const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The members that refer to keys or certificates outside the upload
/// (RFC 7517 section 4.6 `x5u`, 4.7 `x5c`; `jku` is a JWS header parameter,
/// RFC 7515 section 4.1.2). Rejecting them in an upload is inferred from
/// ADR-005 item 8 (see the module docs of [`crate::jwk`]).
pub const KEY_REFERENCE_MEMBERS: [&str; 3] = ["x5u", "x5c", "jku"];

/// The members every accepted key may carry besides its key type's own
/// (inferred allowlist): `kty`, `kid`, `use`, `key_ops`, `alg`, `x5t`
/// and `x5t#S256`. Any other member is refused, unknown ones included.
pub const COMMON_MEMBERS: [&str; 7] = ["kty", "kid", "use", "key_ops", "alg", "x5t", "x5t#S256"];

/// The key members of `kty` `RSA` (RFC 7518 section 6.3.1).
pub const RSA_MEMBERS: [&str; 2] = ["n", "e"];
/// The key members of `kty` `EC` (RFC 7518 section 6.2.1).
pub const EC_MEMBERS: [&str; 3] = ["crv", "x", "y"];
/// The key members of `kty` `OKP` (RFC 8037 section 2).
pub const OKP_MEMBERS: [&str; 2] = ["crv", "x"];

/// The smallest RSA modulus, in bits (lead pick, inferred).
pub const RSA_MIN_MODULUS_BITS: usize = 2048;
/// The largest RSA modulus, in bits (inferred: a bound on verification
/// cost).
pub const RSA_MAX_MODULUS_BITS: usize = 8192;
/// The smallest RSA public exponent (lead pick, inferred; FIPS 186-4
/// appendix B.3.1 requires `2^16 < e < 2^256`, odd).
pub const RSA_MIN_EXPONENT: u32 = 65537;
/// The longest RSA public exponent, in octets: `e < 2^256` (inferred, FIPS
/// 186-4 appendix B.3.1).
pub const RSA_MAX_EXPONENT_OCTETS: usize = 32;
/// The longest `kid`, in bytes (inferred).
pub const KID_MAX_BYTES: usize = 128;

/// A JWS algorithm a key may verify. Only the asymmetric algorithms this
/// module knows are representable: `none` and `HS*` never are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// RSASSA-PSS with SHA-256.
    Ps256,
    /// ECDSA on P-256 with SHA-256.
    Es256,
    /// ECDSA on P-384 with SHA-384.
    Es384,
    /// ECDSA on P-521 with SHA-512.
    Es512,
    /// EdDSA (RFC 8037), here only on Ed25519.
    EdDsa,
}

/// Every algorithm this module knows, the list [`Algorithm::from_name`]
/// parses, kept apart from the allowed set so that changing the allowed
/// set never changes how a name parses.
pub const KNOWN_ALGORITHMS: [Algorithm; 6] = [
    Algorithm::Rs256,
    Algorithm::Ps256,
    Algorithm::Es256,
    Algorithm::Es384,
    Algorithm::Es512,
    Algorithm::EdDsa,
];

/// The provisional default allowed algorithm set (lead decision,
/// 2026-11-21, provisional; the set itself is OQ-TP-3, open).
pub const DEFAULT_ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Rs256,
    Algorithm::Ps256,
    Algorithm::Es256,
    Algorithm::Es384,
    Algorithm::Es512,
    Algorithm::EdDsa,
];

impl Algorithm {
    /// The JWA name (RFC 7518 section 3.1, RFC 8037 section 3.1).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }

    /// The algorithm named exactly `name`, if this module knows it (one of
    /// [`KNOWN_ALGORITHMS`], whatever the allowed set).
    pub fn from_name(name: &str) -> Option<Self> {
        KNOWN_ALGORITHMS.into_iter().find(|alg| alg.name() == name)
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An accepted `EC` curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    /// The `crv` name (RFC 7518 section 6.2.1.1).
    pub const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }

    /// The exact length of `x` and `y` in octets (RFC 7518 sections
    /// 6.2.1.2 and 6.2.1.3: "the full size of a coordinate for the curve").
    pub const fn coordinate_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// The one algorithm of the curve (RFC 7518 section 3.4).
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Self::P256 => Algorithm::Es256,
            Self::P384 => Algorithm::Es384,
            Self::P521 => Algorithm::Es512,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Self::P256, Self::P384, Self::P521]
            .into_iter()
            .find(|curve| curve.name() == name)
    }
}

/// An accepted `OKP` curve: only Ed25519 (RFC 8037).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OkpCurve {
    Ed25519,
}

impl OkpCurve {
    /// The `crv` name (RFC 8037 section 2).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
        }
    }

    /// The exact length of `x` in octets (RFC 8032 section 5.1.5).
    pub const fn key_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
        }
    }
}

/// The validated key material of one JWK. `Debug` prints the key type,
/// curve and modulus size, never the octets.
#[derive(Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// `kty` `RSA`: the modulus and exponent, big-endian, without leading
    /// zero octets.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// `kty` `EC`: the coordinates, each exactly
    /// [`EcCurve::coordinate_len`] octets.
    Ec {
        curve: EcCurve,
        x: Vec<u8>,
        y: Vec<u8>,
    },
    /// `kty` `OKP`: the public key, exactly [`OkpCurve::key_len`] octets.
    Okp { curve: OkpCurve, x: Vec<u8> },
}

impl PublicKey {
    /// The `kty` value.
    pub const fn kty(&self) -> &'static str {
        match self {
            Self::Rsa { .. } => "RSA",
            Self::Ec { .. } => "EC",
            Self::Okp { .. } => "OKP",
        }
    }

    /// The algorithms this key type and curve admit, whatever the allowed
    /// set.
    pub fn compatible_algorithms(&self) -> &'static [Algorithm] {
        match self {
            Self::Rsa { .. } => &[Algorithm::Rs256, Algorithm::Ps256],
            Self::Ec { curve, .. } => match curve {
                EcCurve::P256 => &[Algorithm::Es256],
                EcCurve::P384 => &[Algorithm::Es384],
                EcCurve::P521 => &[Algorithm::Es512],
            },
            Self::Okp {
                curve: OkpCurve::Ed25519,
                ..
            } => &[Algorithm::EdDsa],
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa { n, .. } => f
                .debug_struct("Rsa")
                .field("modulus_bits", &modulus_bits(n))
                .finish_non_exhaustive(),
            Self::Ec { curve, .. } => f
                .debug_struct("Ec")
                .field("curve", curve)
                .finish_non_exhaustive(),
            Self::Okp { curve, .. } => f
                .debug_struct("Okp")
                .field("curve", curve)
                .finish_non_exhaustive(),
        }
    }
}

/// A validated `kid`: 1 to [`KID_MAX_BYTES`] bytes of `A`-`Z`, `a`-`z`,
/// `0`-`9` and `-._~:+/=` (inferred; see the module docs of
/// [`crate::jwk`]). It is an identifier, not key material, and holds no
/// quote, space or control character, so errors may print it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid(String);

impl Kid {
    /// The `kid` text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(text: &str) -> Result<Self, JwkError> {
        if text.is_empty() || text.len() > KID_MAX_BYTES {
            return Err(JwkError::KidLength { bytes: text.len() });
        }
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~:+/=".contains(&byte))
        {
            return Err(JwkError::KidCharacter);
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated public JWK: built only by
/// [`parse_jwk_set`](super::parse_jwk_set). `Debug` prints the `kid`, key
/// type, curve or modulus size, algorithm and thumbprint, never the key
/// octets.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicJwk {
    kid: Kid,
    key: PublicKey,
    alg: Option<Algorithm>,
    algorithm: Algorithm,
    thumbprint: Thumbprint,
}

impl PublicJwk {
    /// The `kid`.
    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    /// The key material.
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The uploaded `alg` member, when present.
    pub fn alg(&self) -> Option<Algorithm> {
        self.alg
    }

    /// The one algorithm this key verifies with (inferred: one algorithm
    /// per key, RFC 8725 section 3.1): its `alg` member, or, for a key
    /// without one, the single algorithm its curve admits (an RSA key
    /// always has `alg`). It does not depend on the allowed set. The
    /// overlap checks compare keys by this algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The RFC 7638 SHA-256 thumbprint.
    pub fn thumbprint(&self) -> &Thumbprint {
        &self.thumbprint
    }
}

impl fmt::Debug for PublicJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicJwk")
            .field("kid", &self.kid)
            .field("key", &self.key)
            .field("alg", &self.alg)
            .field("algorithm", &self.algorithm)
            .field("thumbprint", &self.thumbprint)
            .finish()
    }
}

/// Why one JWK is refused. No variant holds key material or text copied
/// from the key, so neither `Display` nor `Debug` can print any; a member
/// is named by its fixed name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkError {
    /// A private or symmetric key member is present (one of
    /// [`PRIVATE_MEMBERS`]).
    PrivateMember(&'static str),
    /// A member referring to keys or certificates outside the upload is
    /// present (one of [`KEY_REFERENCE_MEMBERS`]).
    KeyReference(&'static str),
    /// A member outside the allowlist of the key type is present
    /// ([`COMMON_MEMBERS`] plus [`RSA_MEMBERS`], [`EC_MEMBERS`] or
    /// [`OKP_MEMBERS`]). The member is not named: its name is uploaded
    /// text and may hold anything, key material included.
    UnexpectedMember,
    /// A required member is absent.
    MissingMember(&'static str),
    /// A member has the wrong JSON type.
    WrongType(&'static str),
    /// `kty` is `oct`, a symmetric key.
    SymmetricKeyType,
    /// `kty` is not `RSA`, `EC`, `OKP` or `oct`.
    UnsupportedKeyType,
    /// A key material member is not canonical unpadded base64url.
    Encoding {
        member: &'static str,
        reason: Base64urlError,
    },
    /// `crv` is not an accepted curve of the key type.
    UnsupportedCurve,
    /// An `EC` coordinate or `OKP` key is not exactly the curve's length,
    /// or an `x5t` or `x5t#S256` is not exactly 20 or 32 octets.
    KeyLength {
        member: &'static str,
        expected: usize,
        actual: usize,
    },
    /// The RSA modulus has a leading zero octet.
    RsaModulusLeadingZero,
    /// The RSA modulus is shorter than [`RSA_MIN_MODULUS_BITS`].
    RsaModulusTooSmall { bits: usize },
    /// The RSA modulus is longer than [`RSA_MAX_MODULUS_BITS`].
    RsaModulusTooLarge { bits: usize },
    /// The RSA modulus is even.
    RsaModulusEven,
    /// The RSA exponent has a leading zero octet.
    RsaExponentLeadingZero,
    /// The RSA exponent is longer than [`RSA_MAX_EXPONENT_OCTETS`].
    RsaExponentTooLong,
    /// The RSA exponent is below [`RSA_MIN_EXPONENT`].
    RsaExponentTooSmall,
    /// The RSA exponent is even.
    RsaExponentEven,
    /// `kid` is empty or longer than [`KID_MAX_BYTES`].
    KidLength { bytes: usize },
    /// `kid` has a character outside the accepted set.
    KidCharacter,
    /// `use` is present and not `sig`.
    Use,
    /// `key_ops` is present and not exactly `["verify"]`.
    KeyOps,
    /// `alg` is `none` or an `HS*` (symmetric) algorithm.
    ForbiddenAlgorithm,
    /// `alg` is another algorithm this module does not know.
    UnsupportedAlgorithm,
    /// `alg` is known but not in the allowed set.
    AlgorithmNotAllowed(Algorithm),
    /// `alg` does not fit the key type or curve.
    AlgorithmMismatch(Algorithm),
    /// No `alg`, and the one algorithm the curve admits is not allowed.
    NoAllowedAlgorithm,
    /// No `alg` on a key whose type admits more than one algorithm (every
    /// RSA key), whatever the allowed set (inferred: one algorithm per key,
    /// RFC 8725 section 3.1).
    AlgorithmRequired,
}

impl fmt::Display for JwkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateMember(member) => write!(
                f,
                "member \"{member}\" is a private or symmetric key parameter"
            ),
            Self::KeyReference(member) => write!(
                f,
                "member \"{member}\" refers to keys or certificates outside the upload"
            ),
            Self::UnexpectedMember => f.write_str("a member outside the allowlist is present"),
            Self::MissingMember(member) => write!(f, "member \"{member}\" is missing"),
            Self::WrongType(member) => write!(f, "member \"{member}\" has the wrong JSON type"),
            Self::SymmetricKeyType => f.write_str("kty \"oct\" (a symmetric key) is not accepted"),
            Self::UnsupportedKeyType => f.write_str("kty is not RSA, EC or OKP"),
            Self::Encoding { member, reason } => write!(
                f,
                "member \"{member}\" is not canonical unpadded base64url: {reason}"
            ),
            Self::UnsupportedCurve => f.write_str("crv is not an accepted curve of the key type"),
            Self::KeyLength {
                member,
                expected,
                actual,
            } => write!(
                f,
                "member \"{member}\" is {actual} octets, expected {expected}"
            ),
            Self::RsaModulusLeadingZero => f.write_str("the RSA modulus has a leading zero octet"),
            Self::RsaModulusTooSmall { bits } => write!(
                f,
                "the RSA modulus is {bits} bits, under {RSA_MIN_MODULUS_BITS}"
            ),
            Self::RsaModulusTooLarge { bits } => write!(
                f,
                "the RSA modulus is {bits} bits, over {RSA_MAX_MODULUS_BITS}"
            ),
            Self::RsaModulusEven => f.write_str("the RSA modulus is even"),
            Self::RsaExponentLeadingZero => {
                f.write_str("the RSA exponent has a leading zero octet")
            }
            Self::RsaExponentTooLong => write!(
                f,
                "the RSA exponent is longer than {RSA_MAX_EXPONENT_OCTETS} octets"
            ),
            Self::RsaExponentTooSmall => {
                write!(f, "the RSA exponent is under {RSA_MIN_EXPONENT}")
            }
            Self::RsaExponentEven => f.write_str("the RSA exponent is even"),
            Self::KidLength { bytes } => {
                write!(f, "kid is {bytes} bytes, not 1 to {KID_MAX_BYTES}")
            }
            Self::KidCharacter => f.write_str("kid has a character outside the accepted set"),
            Self::Use => f.write_str("use is not \"sig\""),
            Self::KeyOps => f.write_str("key_ops is not exactly [\"verify\"]"),
            Self::ForbiddenAlgorithm => f.write_str("alg is none or a symmetric algorithm"),
            Self::UnsupportedAlgorithm => f.write_str("alg is not a supported algorithm"),
            Self::AlgorithmNotAllowed(alg) => write!(f, "alg {alg} is not allowed"),
            Self::AlgorithmMismatch(alg) => {
                write!(f, "alg {alg} does not fit the key type or curve")
            }
            Self::NoAllowedAlgorithm => f.write_str("the curve's one algorithm is not allowed"),
            Self::AlgorithmRequired => {
                f.write_str("alg is required: the key type admits several algorithms")
            }
        }
    }
}

impl std::error::Error for JwkError {}

/// The string value of `member`, if present.
fn string<'a>(
    jwk: &'a Map<String, Value>,
    member: &'static str,
) -> Result<Option<&'a str>, JwkError> {
    match jwk.get(member) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(JwkError::WrongType(member)),
    }
}

/// The string value of the required `member`.
fn required<'a>(jwk: &'a Map<String, Value>, member: &'static str) -> Result<&'a str, JwkError> {
    string(jwk, member)?.ok_or(JwkError::MissingMember(member))
}

/// The octets of the required base64url `member`.
fn octets(jwk: &Map<String, Value>, member: &'static str) -> Result<Vec<u8>, JwkError> {
    base64url::decode(required(jwk, member)?)
        .map_err(|reason| JwkError::Encoding { member, reason })
}

/// The bit length of a big-endian integer without leading zero octets.
pub(crate) fn modulus_bits(n: &[u8]) -> usize {
    match n.first() {
        Some(&first) => n.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    }
}

fn rsa(jwk: &Map<String, Value>) -> Result<PublicKey, JwkError> {
    let n = octets(jwk, "n")?;
    let e = octets(jwk, "e")?;
    // RFC 7518 section 6.3.1.1: the minimum number of octets.
    if n.first() == Some(&0) {
        return Err(JwkError::RsaModulusLeadingZero);
    }
    let bits = modulus_bits(&n);
    if bits < RSA_MIN_MODULUS_BITS {
        return Err(JwkError::RsaModulusTooSmall { bits });
    }
    if bits > RSA_MAX_MODULUS_BITS {
        return Err(JwkError::RsaModulusTooLarge { bits });
    }
    if n.last().is_some_and(|last| last & 1 == 0) {
        return Err(JwkError::RsaModulusEven);
    }
    // RFC 7518 section 6.3.1.2: the minimum number of octets.
    if e.first() == Some(&0) {
        return Err(JwkError::RsaExponentLeadingZero);
    }
    if e.len() > RSA_MAX_EXPONENT_OCTETS {
        return Err(JwkError::RsaExponentTooLong);
    }
    // Without leading zeros, more octets is a larger value, so the
    // comparison with the minimum is by length, then octet by octet.
    let min = RSA_MIN_EXPONENT.to_be_bytes();
    let min = &min[min.iter().take_while(|&&byte| byte == 0).count()..];
    if (e.len(), e.as_slice()) < (min.len(), min) {
        return Err(JwkError::RsaExponentTooSmall);
    }
    if e.last().is_some_and(|last| last & 1 == 0) {
        return Err(JwkError::RsaExponentEven);
    }
    Ok(PublicKey::Rsa { n, e })
}

/// `member`'s octets, which must be exactly `expected` long.
fn exact(
    jwk: &Map<String, Value>,
    member: &'static str,
    expected: usize,
) -> Result<Vec<u8>, JwkError> {
    let bytes = octets(jwk, member)?;
    if bytes.len() != expected {
        return Err(JwkError::KeyLength {
            member,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn ec(jwk: &Map<String, Value>) -> Result<PublicKey, JwkError> {
    let curve = EcCurve::from_name(required(jwk, "crv")?).ok_or(JwkError::UnsupportedCurve)?;
    let x = exact(jwk, "x", curve.coordinate_len())?;
    let y = exact(jwk, "y", curve.coordinate_len())?;
    Ok(PublicKey::Ec { curve, x, y })
}

fn okp(jwk: &Map<String, Value>) -> Result<PublicKey, JwkError> {
    let curve = match required(jwk, "crv")? {
        "Ed25519" => OkpCurve::Ed25519,
        _ => return Err(JwkError::UnsupportedCurve),
    };
    let x = exact(jwk, "x", curve.key_len())?;
    Ok(PublicKey::Okp { curve, x })
}

/// Whether `alg` names `none` or a symmetric (`HS*`) algorithm.
fn forbidden(alg: &str) -> bool {
    alg == "none" || alg.starts_with("HS")
}

/// An accepted `kty`.
enum Kty {
    Rsa,
    Ec,
    Okp,
}

/// Validates one JWK of a set; `allowed` is the allowed algorithm set.
pub(crate) fn parse_jwk(
    jwk: &Map<String, Value>,
    allowed: &[Algorithm],
) -> Result<PublicJwk, JwkError> {
    if let Some(member) = PRIVATE_MEMBERS
        .into_iter()
        .find(|member| jwk.contains_key(*member))
    {
        return Err(JwkError::PrivateMember(member));
    }
    if let Some(member) = KEY_REFERENCE_MEMBERS
        .into_iter()
        .find(|member| jwk.contains_key(*member))
    {
        return Err(JwkError::KeyReference(member));
    }
    let kty = match required(jwk, "kty")? {
        "RSA" => Kty::Rsa,
        "EC" => Kty::Ec,
        "OKP" => Kty::Okp,
        "oct" => return Err(JwkError::SymmetricKeyType),
        _ => return Err(JwkError::UnsupportedKeyType),
    };
    let own: &[&str] = match kty {
        Kty::Rsa => &RSA_MEMBERS,
        Kty::Ec => &EC_MEMBERS,
        Kty::Okp => &OKP_MEMBERS,
    };
    if jwk
        .keys()
        .any(|member| !COMMON_MEMBERS.contains(&member.as_str()) && !own.contains(&member.as_str()))
    {
        return Err(JwkError::UnexpectedMember);
    }
    let kid = Kid::parse(required(jwk, "kid")?)?;
    if string(jwk, "use")?.is_some_and(|value| value != "sig") {
        return Err(JwkError::Use);
    }
    if let Some(ops) = jwk.get("key_ops") {
        let verify_only = matches!(ops, Value::Array(ops)
            if matches!(ops.as_slice(), [Value::String(op)] if op == "verify"));
        if !verify_only {
            return Err(JwkError::KeyOps);
        }
    }
    // x5t and x5t#S256 are certificate thumbprints (RFC 7517 sections 4.8
    // and 4.9): checked as such so they cannot carry anything else
    // (inferred); otherwise unused.
    for (member, len) in [("x5t", 20), ("x5t#S256", 32)] {
        if jwk.contains_key(member) {
            exact(jwk, member, len)?;
        }
    }
    let key = match kty {
        Kty::Rsa => rsa(jwk)?,
        Kty::Ec => ec(jwk)?,
        Kty::Okp => okp(jwk)?,
    };
    let compatible = key.compatible_algorithms();
    let alg = match string(jwk, "alg")? {
        Some(name) => {
            let alg = match Algorithm::from_name(name) {
                Some(alg) => alg,
                None if forbidden(name) => return Err(JwkError::ForbiddenAlgorithm),
                None => return Err(JwkError::UnsupportedAlgorithm),
            };
            if !compatible.contains(&alg) {
                return Err(JwkError::AlgorithmMismatch(alg));
            }
            if !allowed.contains(&alg) {
                return Err(JwkError::AlgorithmNotAllowed(alg));
            }
            Some(alg)
        }
        None => None,
    };
    let algorithm = match (alg, compatible) {
        (Some(alg), _) => alg,
        // The curve fixes the algorithm.
        (None, &[only]) => {
            if !allowed.contains(&only) {
                return Err(JwkError::NoAllowedAlgorithm);
            }
            only
        }
        // The key type admits several algorithms (every RSA key), whatever
        // the allowed set: `alg` is required.
        (None, _) => return Err(JwkError::AlgorithmRequired),
    };
    let thumbprint = thumbprint(&key);
    Ok(PublicJwk {
        kid,
        key,
        alg,
        algorithm,
        thumbprint,
    })
}
