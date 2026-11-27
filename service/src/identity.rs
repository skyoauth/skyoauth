//! The canonical public identity of an mTLS public key: the value of
//! `AdminCredential.public_identity` (design section 7.2; tasks T13.1;
//! identity-registry section 5.2) and
//! `ResourceServerChecker.public_mtls_identity` (identity-registry section
//! 7.3, IR-090), which the checker writers of [`crate::admin`] derive with
//! it. The format and the rules below are a lead decision,
//! 2026-11-24.
//!
//! # Format
//!
//! The canonical public identity of a key is [`PUBLIC_IDENTITY_PREFIX`]
//! (`spki-sha256:`) followed by the 64 lowercase hexadecimal digits of the
//! SHA-256 digest of the key's DER `SubjectPublicKeyInfo` (RFC 5280 section
//! 4.1.2.7), 76 ASCII bytes in all, inside the 2048-byte bound of the
//! `public_identity` and `public_mtls_identity` columns (`0005`, `0003`).
//!
//! The service computes it, with [`canonical_public_identity`], from the
//! DER bytes of the key it is given (at enrollment) or that the client
//! presents (at mTLS authentication), and never accepts a precomputed
//! identity string from a client. At bootstrap and enrollment the operator
//! tooling only supplies the DER key; the service derives its identity.
//!
//! # One form per accepted algorithm
//!
//! The digest covers the exact bytes, so an identity names one DER encoding
//! of a key. A key has more than one valid DER `SubjectPublicKeyInfo` (an EC
//! point compressed or not, named or explicit curve parameters, `NULL` or
//! absent parameters, several algorithm identifiers for one RSA key, RFC
//! 4055 section 1.2), so [`canonical_public_identity`] accepts exactly one
//! form for each accepted algorithm and refuses every other, after the
//! structural checks below and before the hash
//! ([`IdentityError::UnsupportedKey`]). The accepted algorithms are exactly
//! these two (the user, 2026-11-27, relayed by the lead; identity-registry
//! section 7.3):
//!
//! - Ed25519 (RFC 8410): the `AlgorithmIdentifier` holds only the
//!   `OBJECT IDENTIFIER` `id-Ed25519` (1.3.101.112, `2b 65 70`), its
//!   parameters absent, and the `BIT STRING` holds the 32-octet key: the
//!   44-byte form `30 2a 30 05 06 03 2b 65 70 03 21 00` followed by the key;
//! - ECDSA P-256 (RFC 5480): the `OBJECT IDENTIFIER` `id-ecPublicKey`
//!   (1.2.840.10045.2.1, `2a 86 48 ce 3d 02 01`) with the named curve
//!   `prime256v1` (1.2.840.10045.3.1.7, `2a 86 48 ce 3d 03 01 07`) as its
//!   parameters, an `OBJECT IDENTIFIER` (not `NULL`, not explicit
//!   `specifiedCurve` parameters, no other curve), and the `BIT STRING`
//!   holds the 65-octet uncompressed point (`04`, then the two
//!   coordinates; neither compressed, `02` or `03`, nor hybrid, `06` or
//!   `07`): the 91-byte form `30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08
//!   2a 86 48 ce 3d 03 01 07 03 42 00 04` followed by the coordinates.
//!
//! Every other algorithm (RSA under any identifier, Ed448, X25519, X448,
//! another curve, any other `OBJECT IDENTIFIER`) and every other form of
//! these two (Ed25519 with `NULL` or any parameters, a key or point of
//! another length, a P-256 point that is not uncompressed) is refused, and
//! so is a key of an accepted form that fails the key check of "Key
//! validity" below. With the strict DER framing below, the two forms are
//! fixed byte layouts; the key check refuses a coordinate at or above the
//! field prime, the one other way to spell the same point in those layouts
//! (an Ed25519 `y + p`, a P-256 `x + p` or `y + p` that fits in 32 octets),
//! and an Ed25519 `x = 0` with its sign bit set. So a key has one identity,
//! and the `0005` unique key on
//! `admin_credential.public_identity`, which keeps an identity registered at
//! most once, revoked credentials included, holds per key for every
//! identity derived here. Enrollment and authentication agree on that single
//! representation as long as both derive the identity with this function
//! (the callers below).
//!
//! The checker writers call this: [`crate::admin`]'s
//! `create_resource_server_checker` and a key rotation through its
//! `update_resource_server_checker` take the key's DER and store the
//! identity this function derives (lead decision, 2026-11-25); so do the
//! deployment-local transport ([`crate::local_transport`]) for the operator
//! key of a bootstrap or a recovery, and the admin peer of a verified client
//! certificate (`admin_http`'s `AdminPeer`, whose acceptor is a later
//! slice, S6). `bootstrap_instance` and the operator writers still take the
//! identity string from their caller.
//!
//! # Key validity
//!
//! Weak, non-canonical and undecodable keys are refused at every enrollment
//! point (ADR-013 item 7; the user, 2026-11-24), and this function is the
//! enrollment and handshake check of an mTLS key (the lead, 2026-11-27). A
//! key of an accepted form is then checked as below, and refused as
//! [`IdentityError::UnsupportedKey`]:
//!
//! - Ed25519: the recovery key check (`recovery_key` of
//!   `crate::persistence::registry`, through `ed25519-dalek`): decoding,
//!   the canonical re-encoding and `is_weak`. So a `y` at or above
//!   `p = 2^255 - 19`, a `y` that does not decode to a point and `x = 0`
//!   with the sign bit set are refused, and so are the eight points of
//!   small order (the identity, the point of order 2 and those of order 4
//!   and 8): some verifiers accept a fixed signature for any message under
//!   such a key, so it would prove no possession. A point with a torsion
//!   component (a prime-order point plus a small-order one) is accepted.
//!   About 10 microseconds a key in a release build, where the hand-written
//!   RFC 8032 section 5.1.3 decoding of `crate::jwk::point`
//!   (`check_ed25519`, the JWK check) takes about 9 milliseconds; the tests
//!   check that the two accept and refuse the same keys.
//! - P-256 (`check_ec` of `crate::jwk::point`, hand-written arithmetic, no
//!   elliptic-curve dependency, about 20 microseconds a key in a release
//!   build): each coordinate below the field prime and
//!   `y^2 = x^3 - 3x + b (mod p)`. The curve has cofactor 1, so a point on
//!   it is in the prime-order group; the point at infinity has no
//!   uncompressed form (its `00` encoding is refused by the form check).
//!
//! # What is checked
//!
//! The input must be one well-formed DER `SubjectPublicKeyInfo` and nothing
//! else, checked structurally first, in this order; only bytes that pass
//! every structural check reach the algorithm check of "One form per
//! accepted algorithm" and the key check of "Key validity" above
//! ([`IdentityError::UnsupportedKey`]):
//!
//! - 1 to [`MAX_SPKI_DER_BYTES`] (4096) bytes, before any parsing
//!   ([`IdentityError::Empty`], [`IdentityError::TooLarge`]);
//! - one `SEQUENCE` that spans the input exactly
//!   ([`IdentityError::TrailingBytes`]), holding exactly an
//!   `AlgorithmIdentifier` `SEQUENCE` (an `OBJECT IDENTIFIER`, then at most
//!   one parameters element) and a primitive `BIT STRING` whose unused-bits
//!   octet is 0 and which holds at least one key octet
//!   ([`IdentityError::NotSpki`], also when one of these elements is
//!   missing);
//! - every element is DER-framed ([`IdentityError::NotDer`]): a tag in one
//!   octet (no high-tag-number form); in the universal class, a tag number
//!   and form from an explicit table of the pairs DER allows (X.690, the
//!   BER rules and the DER restrictions): the primitive form only for `BOOLEAN`, `INTEGER`, `BIT
//!   STRING`, `OCTET STRING`, `NULL`, `OBJECT IDENTIFIER`,
//!   `ObjectDescriptor`, `REAL`, `ENUMERATED`, `RELATIVE-OID`, the
//!   restricted character strings, `UTCTime` and `GeneralizedTime`; the
//!   constructed form only for `EXTERNAL`, `EMBEDDED PDV`, `SEQUENCE`,
//!   `SET` and `CHARACTER STRING`; neither for end-of-contents (`0x00`),
//!   tag 14 (`TIME` in X.680, not accepted in SPKI parameters) or 15
//!   (reserved); in the other classes, either form; a
//!   definite length (no indefinite length `0x80`) in its shortest form (the
//!   short form below 128; in the long form no leading zero octet, and at
//!   most two length octets, enough for the size bound), and contents
//!   within its parent ([`IdentityError::Truncated`]); a `NULL` is empty; an
//!   `OBJECT IDENTIFIER` or `RELATIVE-OID` is not empty and every
//!   subidentifier is minimal and terminated. Constructed parameters are
//!   checked the same way, recursively, to a depth of
//!   [`MAX_PARAMETERS_DEPTH`] (8): the parameters element is at depth 1,
//!   and each element inside a constructed element is one deeper; an
//!   element deeper than 8 is [`IdentityError::NotSpki`].
//!
//! DER is a canonical encoding of a structure, and these rules refuse every
//! other framing of the same structure: PEM text, a long-form or
//! zero-padded length, an indefinite length, a constructed string, trailing
//! bytes. So one structure has one identity; the form and key checks
//! above make one key one structure.
//!
//! # What is not checked
//!
//! - The key's strength beyond "Key validity": an Ed25519 key with a
//!   torsion component is accepted (cofactor handling belongs to the
//!   verifier), and no key is checked against a list of known or
//!   compromised keys.
//! - DER rules inside primitive elements other than `NULL`, `OBJECT
//!   IDENTIFIER` and `RELATIVE-OID`: for example the minimal encoding of an
//!   `INTEGER` or the `BOOLEAN` values in explicit curve parameters, or the
//!   order of a `SET OF`. The structural check passes such parameters, and
//!   the algorithm check then refuses them, since neither accepted form has
//!   parameters other than the P-256 curve's `OBJECT IDENTIFIER`.
//! - The identity is a name, not a proof: authentication still needs the
//!   TLS handshake's proof of possession and the credential and role check
//!   on every call (design section 7.2).
//!
//! Errors carry no input byte: `Debug` names the variant only and `Display`
//! is fixed text (as `NotRestorableReason`), so an error can be logged.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::jwk::EcCurve;
use crate::jwk::point::check_ec;
use crate::persistence::registry::recovery_key;

/// The largest accepted DER `SubjectPublicKeyInfo`: 4 KiB covers RSA keys
/// up to 16384 bits (about 2.1 KB) and ML-DSA-87 keys (about 2.6 KB)
/// (lead decision, 2026-11-24).
pub const MAX_SPKI_DER_BYTES: usize = 4096;

/// The deepest element the `AlgorithmIdentifier` parameters may hold: the
/// parameters element is at depth 1 and each element inside a constructed
/// element is one deeper, so eight nested `SEQUENCE`s pass and nine do not.
/// It bounds the recursion of the check; explicit EC parameters reach
/// depth 3 over a prime field and 5 over a binary one.
pub const MAX_PARAMETERS_DEPTH: usize = 8;

/// The prefix of a canonical public identity.
pub const PUBLIC_IDENTITY_PREFIX: &str = "spki-sha256:";

/// Why bytes are not a DER `SubjectPublicKeyInfo`. Carries no input byte;
/// `Debug` names the variant only, `Display` is fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    /// No bytes.
    Empty,
    /// More than [`MAX_SPKI_DER_BYTES`] bytes.
    TooLarge,
    /// An element's header or contents run past the end of its parent. An
    /// element that is missing altogether is [`IdentityError::NotSpki`].
    Truncated,
    /// A length is indefinite or not in its shortest form, or a tag is in
    /// the high-tag-number form or one DER does not allow: BER, not DER.
    NotDer,
    /// Bytes follow the outer `SEQUENCE`.
    TrailingBytes,
    /// Well-formed DER, but not the shape of a `SubjectPublicKeyInfo`: a
    /// wrong tag, a missing or extra element, a `BIT STRING` with unused
    /// bits or no key octet, or parameters deeper than
    /// [`MAX_PARAMETERS_DEPTH`].
    NotSpki,
    /// A well-formed DER `SubjectPublicKeyInfo`, but not the one accepted
    /// form of Ed25519 or of ECDSA P-256 (see the module documentation,
    /// "One form per accepted algorithm"): another algorithm, parameters,
    /// curve, point form or key length; or a key of that form that is not
    /// a valid point ("Key validity"): non-canonical, undecodable, off the
    /// curve or of small order. Checked only after every structural check
    /// has passed.
    UnsupportedKey,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the public key is empty",
            Self::TooLarge => "the public key is too large",
            Self::Truncated => "the public key encoding is truncated",
            Self::NotDer => "the public key is not in DER encoding",
            Self::TrailingBytes => "the public key encoding has trailing bytes",
            Self::NotSpki => "the public key is not a SubjectPublicKeyInfo",
            Self::UnsupportedKey => "the public key is not an accepted Ed25519 or P-256 key",
        })
    }
}

impl std::error::Error for IdentityError {}

const SEQUENCE: u8 = 0x30;
const BIT_STRING: u8 = 0x03;
const OBJECT_IDENTIFIER: u8 = 0x06;
const NULL: u8 = 0x05;
const RELATIVE_OID: u8 = 0x0d;
const CONSTRUCTED: u8 = 0x20;
/// The class bits of a tag octet; 0 is the universal class.
const CLASS: u8 = 0xc0;

/// The contents of the `OBJECT IDENTIFIER` `id-Ed25519`, 1.3.101.112
/// (RFC 8410 section 3).
const ID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// The octets of an Ed25519 public key (RFC 8410 section 4).
const ED25519_KEY_OCTETS: usize = 32;
/// The contents of the `OBJECT IDENTIFIER` `id-ecPublicKey`,
/// 1.2.840.10045.2.1 (RFC 5480 section 2.1.1).
const ID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// The contents of the `OBJECT IDENTIFIER` `secp256r1` (`prime256v1`),
/// 1.2.840.10045.3.1.7, the P-256 named curve (RFC 5480 section 2.1.1.1).
const SECP256R1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// The octets of an uncompressed P-256 point: the `04` tag, then the two
/// 32-octet coordinates (SEC 1 section 2.3.3; RFC 5480 section 2.2).
const P256_POINT_OCTETS: usize = 65;
/// The first octet of an uncompressed EC point.
const UNCOMPRESSED_POINT: u8 = 0x04;

/// The canonical public identity of the key whose DER
/// `SubjectPublicKeyInfo` is `spki_der` (see the module documentation).
pub fn canonical_public_identity(spki_der: &[u8]) -> Result<String, IdentityError> {
    if spki_der.is_empty() {
        return Err(IdentityError::Empty);
    }
    if spki_der.len() > MAX_SPKI_DER_BYTES {
        return Err(IdentityError::TooLarge);
    }
    check_accepted_key(&check_spki(spki_der)?)?;
    let digest = Sha256::digest(spki_der);
    let mut identity = String::with_capacity(PUBLIC_IDENTITY_PREFIX.len() + 64);
    identity.push_str(PUBLIC_IDENTITY_PREFIX);
    for byte in digest.iter() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        identity.push(char::from(HEX[usize::from(byte >> 4)]));
        identity.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(identity)
}

/// The parts of a structurally valid `SubjectPublicKeyInfo` that
/// [`check_accepted_key`] reads.
struct Spki<'a> {
    /// The contents of the algorithm `OBJECT IDENTIFIER`.
    algorithm: &'a [u8],
    /// The `AlgorithmIdentifier` parameters element, if there is one.
    parameters: Option<Element<'a>>,
    /// The key octets: the `BIT STRING` contents after the unused-bits
    /// octet.
    key: &'a [u8],
}

/// One DER element: its tag octet and contents.
struct Element<'a> {
    tag: u8,
    contents: &'a [u8],
}

/// The encoding form of an element: bit 6 of its tag octet (X.690).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    Primitive,
    Constructed,
}

/// The one form DER allows for the universal tag `number` (0 to 30), or
/// `None` when this module refuses the tag in both forms. The encoding
/// rules are those of X.690 (BER, with the DER restrictions); the tag numbers
/// those of X.680.
///
/// No clause numbers are cited: they were not checked against the
/// recommendation text. No universal tag has both forms in DER: BER leaves
/// the form to the sender only for `BIT STRING`, `OCTET STRING` and the
/// restricted character strings, and DER makes those primitive.
///
/// Only the tag and the framing are checked. For `EXTERNAL`, `EMBEDDED PDV`
/// and `CHARACTER STRING` (`08`, `0b` and `1d`, constructed) the contents
/// must be well-framed DER elements ([`check_elements`]), but they are not
/// checked against the components of the `SEQUENCE` each is encoded as.
fn der_universal_form(number: u8) -> Option<Form> {
    use Form::{Constructed, Primitive};
    match number {
        // End-of-contents: only closes an indefinite length which DER does not use.
        0x00 => None,
        // BOOLEAN, INTEGER: primitive.
        0x01 | 0x02 => Some(Primitive),
        // BIT STRING, OCTET STRING (BER allows either form): primitive in DER.
        0x03 | 0x04 => Some(Primitive),
        // NULL, OBJECT IDENTIFIER: primitive.
        0x05 | 0x06 => Some(Primitive),
        // ObjectDescriptor: a useful type, `[UNIVERSAL 7] IMPLICIT
        // GraphicString` (X.680), encoded as that restricted character
        // string, so primitive in DER.
        0x07 => Some(Primitive),
        // EXTERNAL and INSTANCE OF: encoded as a SEQUENCE, so
        // constructed.
        0x08 => Some(Constructed),
        // REAL: primitive; ENUMERATED: encoded as an INTEGER, so
        // primitive.
        0x09 | 0x0a => Some(Primitive),
        // EMBEDDED PDV: encoded as a SEQUENCE, so constructed.
        0x0b => Some(Constructed),
        // UTF8String: a restricted character string, primitive in DER.
        0x0c => Some(Primitive),
        // RELATIVE-OID: primitive.
        0x0d => Some(Primitive),
        // 14 is TIME since the 2008 editions of X.680 (reserved before) and 15
        // is reserved: no structure a SubjectPublicKeyInfo holds uses either,
        // so neither is accepted in its parameters.
        0x0e | 0x0f => None,
        // SEQUENCE and SEQUENCE OF, SET and SET OF: constructed.
        0x10 | 0x11 => Some(Constructed),
        // NumericString, PrintableString, TeletexString (T61String),
        // VideotexString, IA5String: restricted character strings, primitive
        // in DER.
        0x12..=0x16 => Some(Primitive),
        // UTCTime, GeneralizedTime: useful types, `IMPLICIT VisibleString`
        // (X.680), encoded as that restricted character string, so primitive in DER
        // (DER also restricts their contents, which are not checked here).
        0x17 | 0x18 => Some(Primitive),
        // GraphicString, VisibleString (ISO646String), GeneralString,
        // UniversalString: restricted character strings, primitive
        // in DER.
        0x19..=0x1c => Some(Primitive),
        // CHARACTER STRING (unrestricted): encoded as a SEQUENCE, so
        // constructed.
        0x1d => Some(Constructed),
        // BMPString: a restricted character string, primitive in DER.
        0x1e => Some(Primitive),
        // 31: the high-tag-number form, refused by `check_tag` first; and
        // no other number fits in five bits.
        _ => None,
    }
}

/// Refuses a tag octet DER does not allow, or this module does not
/// accept: the high-tag-number form in any class (a tag number of 31 or
/// more, which no element of a `SubjectPublicKeyInfo` needs; below 31 it is
/// not DER), and in the universal class every tag and form that
/// [`der_universal_form`] does not permit. A tag of another class
/// (application, context-specific, private) is accepted in either form: its
/// form follows the type it tags, which only the schema knows.
fn check_tag(tag: u8) -> Result<(), IdentityError> {
    let number = tag & 0x1f;
    if number == 0x1f {
        return Err(IdentityError::NotDer);
    }
    if tag & CLASS != 0 {
        return Ok(());
    }
    let form = if tag & CONSTRUCTED == 0 {
        Form::Primitive
    } else {
        Form::Constructed
    };
    match der_universal_form(number) {
        Some(permitted) if permitted == form => Ok(()),
        _ => Err(IdentityError::NotDer),
    }
}

/// Reads one element from the front of `input`; returns it and the rest.
fn element(input: &[u8]) -> Result<(Element<'_>, &[u8]), IdentityError> {
    let (&tag, rest) = input.split_first().ok_or(IdentityError::Truncated)?;
    check_tag(tag)?;
    let (&first, mut rest) = rest.split_first().ok_or(IdentityError::Truncated)?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        // 0x80 is the indefinite length; a length that needs more than two
        // octets exceeds MAX_SPKI_DER_BYTES anyway.
        let octets = usize::from(first & 0x7f);
        if octets == 0 || octets > 2 {
            return Err(IdentityError::NotDer);
        }
        if rest.len() < octets {
            return Err(IdentityError::Truncated);
        }
        let (bytes, after) = rest.split_at(octets);
        rest = after;
        if bytes[0] == 0 {
            return Err(IdentityError::NotDer);
        }
        let length = bytes
            .iter()
            .fold(0usize, |length, &b| (length << 8) | usize::from(b));
        if length < 0x80 {
            return Err(IdentityError::NotDer);
        }
        length
    };
    if rest.len() < length {
        return Err(IdentityError::Truncated);
    }
    let (contents, rest) = rest.split_at(length);
    Ok((Element { tag, contents }, rest))
}

/// Reads an element the `SubjectPublicKeyInfo` shape requires from the
/// front of `input`: when there is none at all the shape is wrong
/// ([`IdentityError::NotSpki`]), which is not a truncation.
fn required_element(input: &[u8]) -> Result<(Element<'_>, &[u8]), IdentityError> {
    if input.is_empty() {
        return Err(IdentityError::NotSpki);
    }
    element(input)
}

/// Checks that `contents` is a sequence of well-formed DER elements at
/// `depth`, recursing into constructed ones.
fn check_elements(mut contents: &[u8], depth: usize) -> Result<(), IdentityError> {
    while !contents.is_empty() {
        let (element, rest) = element(contents)?;
        check_element(&element, depth)?;
        contents = rest;
    }
    Ok(())
}

/// Checks one element at `depth` (see [`MAX_PARAMETERS_DEPTH`]).
fn check_element(element: &Element<'_>, depth: usize) -> Result<(), IdentityError> {
    if depth > MAX_PARAMETERS_DEPTH {
        return Err(IdentityError::NotSpki);
    }
    match element.tag {
        NULL if !element.contents.is_empty() => Err(IdentityError::NotDer),
        OBJECT_IDENTIFIER | RELATIVE_OID => check_oid(element.contents),
        tag if tag & CONSTRUCTED != 0 => check_elements(element.contents, depth + 1),
        _ => Ok(()),
    }
}

/// Not empty; each subidentifier minimal (no leading 0x80 octet) and
/// terminated (the last octet has its high bit clear). The contents of an
/// `OBJECT IDENTIFIER` and of a `RELATIVE-OID` (which has at least one
/// component, X.680) follow the same rules at the octet level; they differ only in what the first subidentifier means.
fn check_oid(contents: &[u8]) -> Result<(), IdentityError> {
    let Some(&last) = contents.last() else {
        return Err(IdentityError::NotDer);
    };
    if last & 0x80 != 0 {
        return Err(IdentityError::NotDer);
    }
    let mut start = true;
    for &byte in contents {
        if start && byte == 0x80 {
            return Err(IdentityError::NotDer);
        }
        start = byte & 0x80 == 0;
    }
    Ok(())
}

/// The structural check of "What is checked" in the module documentation;
/// returns the parts the algorithm check reads.
fn check_spki(der: &[u8]) -> Result<Spki<'_>, IdentityError> {
    let (spki, rest) = element(der)?;
    if spki.tag != SEQUENCE {
        return Err(IdentityError::NotSpki);
    }
    if !rest.is_empty() {
        return Err(IdentityError::TrailingBytes);
    }
    let (algorithm, rest) = required_element(spki.contents)?;
    let (key, rest) = required_element(rest)?;
    if algorithm.tag != SEQUENCE || key.tag != BIT_STRING || !rest.is_empty() {
        return Err(IdentityError::NotSpki);
    }
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
    // parameters ANY OPTIONAL }.
    let (oid, parameters) = required_element(algorithm.contents)?;
    if oid.tag != OBJECT_IDENTIFIER {
        return Err(IdentityError::NotSpki);
    }
    check_oid(oid.contents)?;
    let parameters = if parameters.is_empty() {
        None
    } else {
        let (parameters, rest) = element(parameters)?;
        if !rest.is_empty() {
            return Err(IdentityError::NotSpki);
        }
        check_element(&parameters, 1)?;
        Some(parameters)
    };
    // subjectPublicKey BIT STRING: an unused-bits octet, 0 for a key
    // (inferred: every public key encoding is whole octets), then the key.
    match key.contents {
        [0, key @ ..] if !key.is_empty() => Ok(Spki {
            algorithm: oid.contents,
            parameters,
            key,
        }),
        _ => Err(IdentityError::NotSpki),
    }
}

/// Accepts exactly the one form of each accepted algorithm (see "One form
/// per accepted algorithm" in the module documentation): Ed25519 with no
/// parameters and a 32-octet key, or `id-ecPublicKey` with the P-256 named
/// curve and a 65-octet uncompressed point. The DER framing that
/// [`check_spki`] has checked fixes every other byte, so each is one byte
/// layout (44 and 91 bytes). Then the key itself (see "Key validity"):
/// [`recovery_key`] for Ed25519 and [`check_ec`] for P-256, whose refusals
/// are all [`IdentityError::UnsupportedKey`].
fn check_accepted_key(spki: &Spki<'_>) -> Result<(), IdentityError> {
    let accepted = match spki.algorithm {
        ID_ED25519 => {
            spki.parameters.is_none()
                && spki.key.len() == ED25519_KEY_OCTETS
                && recovery_key(spki.key).is_ok()
        }
        ID_EC_PUBLIC_KEY => {
            matches!(
                spki.parameters,
                Some(Element {
                    tag: OBJECT_IDENTIFIER,
                    contents: SECP256R1
                })
            ) && spki.key.len() == P256_POINT_OCTETS
                && spki.key[0] == UNCOMPRESSED_POINT
                && check_ec(EcCurve::P256, &spki.key[1..33], &spki.key[33..]).is_ok()
        }
        _ => false,
    };
    if accepted {
        Ok(())
    } else {
        Err(IdentityError::UnsupportedKey)
    }
}

/// The structural tests build most of their inputs on the RFC 8410 key with
/// other parameters, OIDs or key lengths: such bytes "pass" the structural
/// check when the result is [`IdentityError::UnsupportedKey`] (`UNSUPPORTED`),
/// which only bytes that pass every structural check can have.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::point::check_ed25519;

    /// The Ed25519 public key of RFC 8410 section 10.1, as DER
    /// (`MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=`).
    const ED25519: [u8; 44] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x19, 0xbf, 0x44,
        0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b, 0x96, 0xc8, 0x50,
        0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31, 0x66, 0xe1,
    ];

    /// The P-256 public key of RFC 6979 appendix A.2.5, as the DER
    /// `SubjectPublicKeyInfo` OpenSSL exports for it (`openssl pkey -pubin
    /// -text` reads it as `prime256v1` and exports the same bytes): the
    /// named curve and the uncompressed point, 91 bytes.
    const P256: [u8; 91] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x60, 0xfe, 0xd4,
        0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49,
        0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79,
        0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
        0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22,
        0x99,
    ];

    /// The `AlgorithmIdentifier` contents of the accepted Ed25519 form: the
    /// OID, no parameters.
    const ED25519_ALGORITHM: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

    /// The `AlgorithmIdentifier` contents of the accepted P-256 form:
    /// `id-ecPublicKey`, then the `prime256v1` OID.
    const P256_ALGORITHM: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x03, 0x01, 0x07,
    ];

    /// The result of a structurally valid `SubjectPublicKeyInfo` that is
    /// not an accepted form.
    const UNSUPPORTED: Result<String, IdentityError> = Err(IdentityError::UnsupportedKey);

    /// An SPKI whose `AlgorithmIdentifier` holds `algorithm` and whose
    /// `BIT STRING` holds the unused-bits octet 0 and `key`, with DER
    /// lengths.
    fn spki(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
        let mut contents = vec![0x30];
        push_length(&mut contents, algorithm.len());
        contents.extend_from_slice(algorithm);
        contents.push(0x03);
        push_length(&mut contents, key.len() + 1);
        contents.push(0x00);
        contents.extend_from_slice(key);
        let mut der = vec![0x30];
        push_length(&mut der, contents.len());
        der.extend(contents);
        der
    }

    /// `algorithm` with the `OBJECT IDENTIFIER` whose contents are `oid`
    /// in front.
    fn oid_then(oid: &[u8], parameters: &[u8]) -> Vec<u8> {
        let mut algorithm = vec![0x06, u8::try_from(oid.len()).unwrap()];
        algorithm.extend_from_slice(oid);
        algorithm.extend_from_slice(parameters);
        algorithm
    }

    /// The bytes of the lowercase hexadecimal `text`.
    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    /// The same with `05 00` (NULL) parameters, as RSA has: 46 bytes.
    fn with_null_parameters() -> Vec<u8> {
        let mut der = vec![
            0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00,
        ];
        der.extend_from_slice(&ED25519[9..]);
        der
    }

    /// An SPKI with the RFC 8410 key whose `AlgorithmIdentifier` holds
    /// `algorithm` (an OID and any parameters), with DER lengths.
    fn with_algorithm(algorithm: &[u8]) -> Vec<u8> {
        let mut contents = vec![0x30];
        push_length(&mut contents, algorithm.len());
        contents.extend_from_slice(algorithm);
        contents.extend_from_slice(&ED25519[9..]);
        let mut der = vec![0x30];
        push_length(&mut der, contents.len());
        der.extend(contents);
        der
    }

    /// The RFC 8410 key with `parameters` after its OID.
    fn with_parameters(parameters: &[u8]) -> Vec<u8> {
        let mut algorithm = vec![0x06, 0x03, 0x2b, 0x65, 0x70];
        algorithm.extend_from_slice(parameters);
        with_algorithm(&algorithm)
    }

    /// `inner` wrapped in `levels` SEQUENCEs.
    fn nested(levels: usize, inner: &[u8]) -> Vec<u8> {
        let mut element = inner.to_vec();
        for _ in 0..levels {
            let mut outer = vec![0x30];
            push_length(&mut outer, element.len());
            outer.extend(element);
            element = outer;
        }
        element
    }

    /// A syntactically valid SPKI whose BIT STRING is `len` bytes long
    /// (unused-bits octet included), its length encoded as `length`.
    fn with_key_length(len: usize, length: &[u8]) -> Vec<u8> {
        let mut key = vec![0u8; len];
        key[1] = 1;
        let mut contents = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03];
        contents.extend_from_slice(length);
        contents.extend(key);
        let mut der = vec![0x30];
        push_length(&mut der, contents.len());
        der.extend(contents);
        der
    }

    /// The same with a DER length, long-form from 128.
    fn large(len: usize) -> Vec<u8> {
        let mut length = Vec::new();
        push_length(&mut length, len);
        with_key_length(len, &length)
    }

    fn push_length(out: &mut Vec<u8>, len: usize) {
        match len {
            0..0x80 => out.push(len as u8),
            0x80..0x100 => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
    }

    #[test]
    fn the_helpers_build_der() {
        assert_eq!(with_parameters(&[]), ED25519);
        assert_eq!(spki(ED25519_ALGORITHM, &ED25519[12..]), ED25519);
        assert_eq!(spki(P256_ALGORITHM, &P256[26..]), P256);
        assert_eq!(oid_then(&[0x2b, 0x65, 0x70], &[]), ED25519_ALGORITHM);
        assert_eq!(unhex("00ff7a"), [0x00, 0xff, 0x7a]);
        assert_eq!(with_parameters(&[0x05, 0x00]), with_null_parameters());
        assert_eq!(
            nested(2, &[0x05, 0x00]),
            [0x30, 0x04, 0x30, 0x02, 0x05, 0x00]
        );
        assert_eq!(&large(0x90)[..3], [0x30, 0x81, 0x9a]);
        assert_eq!(&large(0x90)[10..13], [0x03, 0x81, 0x90]);
    }

    /// Known answer: `sha256sum` of the RFC 8410 key's DER (computed with
    /// OpenSSL and Python's hashlib).
    #[test]
    fn known_answer_for_an_ed25519_key() {
        assert_eq!(
            canonical_public_identity(&ED25519).unwrap(),
            "spki-sha256:a1e9156054e04fac899ae9f275132cdc07a5dbc4ea2c2ad3a1ffc6e0d253681f"
        );
        // Not SHA-1 (3a04967761a552db7e9e18c6dba4bd4aae119908) nor any
        // other digest: the length pins 64 hex digits too.
        assert_eq!(canonical_public_identity(&ED25519).unwrap().len(), 76);
    }

    /// Known answer: `sha256sum` of the RFC 6979 P-256 key's DER (computed
    /// with OpenSSL's export of it and `sha256sum`; the same answer as the
    /// `p256_rfc6979_uncompressed` case of
    /// `tests/conformance/fixtures/_recovery/public_identity.v1.json`).
    #[test]
    fn known_answer_for_a_p256_key() {
        assert_eq!(
            canonical_public_identity(&P256).unwrap(),
            "spki-sha256:5a7a78cca4a0f420d9bc62bb669c3c2759e39f723d3ae10dcbe0f0815a07ecd4"
        );
    }

    /// The two accepted forms are the fixed 44-byte and 91-byte layouts of
    /// the module documentation: another Ed25519 key (RFC 8032's) and another
    /// P-256 point (one OpenSSL generated) pass, with an identity each.
    #[test]
    fn the_two_accepted_forms() {
        let ed25519_prefix = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let p256_prefix = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        assert_eq!(ED25519[..12], ed25519_prefix);
        assert_eq!(P256[..27], p256_prefix);
        // The Ed25519 key of RFC 8032 section 7.1, test 1.
        let rfc8032 = unhex(
            "302a300506032b6570032100\
             d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );
        assert_eq!(rfc8032[..12], ed25519_prefix);
        let generated = unhex(
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004\
             26b98d241d13ab59f39f2f2a64971b5f5f0fc1a7fb2f98c946ab93dbf5f31677\
             3da55d98f4e40188b207932165a2b6624aa44f1ef18d6072d1cb3d857986c9be",
        );
        assert_eq!(generated[..27], p256_prefix);
        for (der, len) in [(rfc8032, 44), (generated, 91)] {
            assert_eq!(der.len(), len);
            let identity = canonical_public_identity(&der).unwrap();
            assert!(identity.starts_with(PUBLIC_IDENTITY_PREFIX));
            assert_eq!(identity.len(), 76);
        }
        assert_ne!(
            canonical_public_identity(&ED25519),
            canonical_public_identity(&P256)
        );
    }

    /// Every other algorithm, and every other form of the two accepted
    /// ones, is [`IdentityError::UnsupportedKey`]: each case is a
    /// structurally valid `SubjectPublicKeyInfo` that differs from an
    /// accepted form in one rule where it can. The real keys are OpenSSL's
    /// exports (`openssl genpkey`, `openssl pkey -pubout`, and for the
    /// RFC 6979 point `-ec_conv_form` and `-ec_param_enc explicit`).
    #[test]
    fn every_other_algorithm_and_form_is_refused() {
        let ed25519_key = &ED25519[12..];
        let point = &P256[26..];
        let x_coordinate = &P256[27..59];
        let ed25519_oid: &[u8] = &[0x2b, 0x65, 0x70];
        let ec_oid: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        let p256_curve: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let with_tag = |tag: u8, rest: &[u8]| {
            let mut key = vec![tag];
            key.extend_from_slice(rest);
            key
        };
        let cases: Vec<(&str, Vec<u8>)> = vec![
            // Ed25519 with parameters: NULL, an OID, an empty SEQUENCE, an
            // empty OCTET STRING.
            ("ed25519 NULL parameters", with_null_parameters()),
            (
                "ed25519 curve OID parameters",
                spki(&oid_then(ed25519_oid, p256_curve), ed25519_key),
            ),
            (
                "ed25519 SEQUENCE parameters",
                spki(&oid_then(ed25519_oid, &[0x30, 0x00]), ed25519_key),
            ),
            (
                "ed25519 OCTET STRING parameters",
                spki(&oid_then(ed25519_oid, &[0x04, 0x00]), ed25519_key),
            ),
            // The other RFC 8410 algorithms, real keys, and with a 32-octet
            // key.
            (
                "ed448",
                unhex(
                    "3043300506032b6571033a0082493eb1804fde456ad9187beef678838fb3519fdd\
                     8296c50f929802ef6fb403900c31212ad1a63ca0fd775d38a440a349734f2182\
                     6316b780",
                ),
            ),
            (
                "ed448 OID, 32-octet key",
                spki(&oid_then(&[0x2b, 0x65, 0x71], &[]), ed25519_key),
            ),
            (
                "x25519",
                unhex(
                    "302a300506032b656e032100e809b2be0313477f55a6895a766ff528092cc68c\
                     3c6ad8d14d8af59fdb6e8b73",
                ),
            ),
            (
                "x448 OID, 32-octet key",
                spki(&oid_then(&[0x2b, 0x65, 0x6f], &[]), ed25519_key),
            ),
            // OIDs one arc from id-Ed25519: 1.3.101 and 1.3.101.112.0.
            ("1.3.101", spki(&oid_then(&[0x2b, 0x65], &[]), ed25519_key)),
            (
                "1.3.101.112.0",
                spki(&oid_then(&[0x2b, 0x65, 0x70, 0x00], &[]), ed25519_key),
            ),
            // RSA: rsaEncryption with NULL parameters, and id-RSASSA-PSS
            // with none (1024-bit keys).
            (
                "rsaEncryption",
                unhex(
                    "30819f300d06092a864886f70d010101050003818d0030818902818100c0a0738f\
                     54294d8703d7a16446e70c5ea05c34102bae574a8581665560ac0cccccd57a70bb\
                     e5c42395bcca654fa8759892e357dc97cd09ef379c4387b2b05861fbfd62a1ef06\
                     fd3618ec22e3d717d4893ee72b2b87d100676348497552a8b8e8d056bb6d783509\
                     94b74ea17be6b8858ef29597b5e111baea4931741254199b930203010001",
                ),
            ),
            (
                "id-RSASSA-PSS",
                unhex(
                    "30819d300b06092a864886f70d01010a03818d0030818902818100cae03004d709\
                     efbfcba5cdda2a69fb04103838fbeb260b0b5567d77fef23ecb19f068c2c532485\
                     1e24d86ba3a58ebb2158cc66d3c9b6115063931e9c3ff34e3ff2335303dd4a7f7f\
                     8d5424be26b6fa9cf51bc69808b2007836f2ec070cd7b2a93de94ceb3a7221fc72\
                     76f20644f62e4a53fc30afe86660a5241ab6f19bbacd370203010001",
                ),
            ),
            // Other curves: P-384 and secp256k1 (real keys), and their
            // OIDs with a 65-octet uncompressed point, so that only the
            // curve differs.
            (
                "P-384",
                unhex(
                    "3076301006072a8648ce3d020106052b8104002203620004d9e8ea2657081b4f83\
                     c3167ffdbbdc9e2e0a10a06f40e4ea33e221b2417f88dff150eadaeb9a767699a2\
                     3513e965059e4f50d045029b7a0b3b8cf4e33c312a792b50c089a863f26f5cff43\
                     15b92b5cac2b2ce14b072ba278aef72554980994ec",
                ),
            ),
            (
                "secp256k1",
                unhex(
                    "3056301006072a8648ce3d020106052b8104000a034200045b7cafa7df10c6f4cb\
                     b83dc610682c2d843ac9a9e9592aa31d27609ecaa30ff56d36072dee84a9b38002\
                     b07c08c2cc69b027399a746fae68780a969956070f81",
                ),
            ),
            (
                "P-384 OID, 65-octet point",
                spki(
                    &oid_then(ec_oid, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
                    point,
                ),
            ),
            (
                "secp256k1 OID, 65-octet point",
                spki(
                    &oid_then(ec_oid, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a]),
                    point,
                ),
            ),
            // Curve OIDs one arc from prime256v1: 1.2.840.10045.3.1.6
            // (another curve of the same arc), 1.2.840.10045.3.1 and
            // 1.2.840.10045.3.1.7.0.
            (
                "1.2.840.10045.3.1.6",
                spki(
                    &oid_then(
                        ec_oid,
                        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x06],
                    ),
                    point,
                ),
            ),
            (
                "1.2.840.10045.3.1",
                spki(
                    &oid_then(
                        ec_oid,
                        &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01],
                    ),
                    point,
                ),
            ),
            (
                "1.2.840.10045.3.1.7.0",
                spki(
                    &oid_then(
                        ec_oid,
                        &[
                            0x06, 0x09, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x00,
                        ],
                    ),
                    point,
                ),
            ),
            // The P-256 point with other parameters: none, NULL, explicit
            // (OpenSSL's `specifiedCurve` export of the RFC 6979 key), the
            // curve OID's contents under another tag (RELATIVE-OID, `[0]`
            // primitive) or inside a SEQUENCE.
            ("P-256 no parameters", spki(&oid_then(ec_oid, &[]), point)),
            (
                "P-256 NULL parameters",
                spki(&oid_then(ec_oid, &[0x05, 0x00]), point),
            ),
            (
                "P-256 explicit parameters",
                unhex(
                    "3082014b3082010306072a8648ce3d02013081f7020101302c06072a8648ce3d01\
                     01022100ffffffff00000001000000000000000000000000ffffffffffffffffff\
                     ffffff305b0420ffffffff00000001000000000000000000000000ffffffffffff\
                     fffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63b\
                     ce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b\
                     17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe3\
                     42e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100\
                     ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255102\
                     01010342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce66962\
                     2e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294\
                     d4462299",
                ),
            ),
            (
                "P-256 curve as RELATIVE-OID",
                spki(&oid_then(ec_oid, &with_tag(0x0d, &p256_curve[1..])), point),
            ),
            (
                "P-256 curve as [0]",
                spki(&oid_then(ec_oid, &with_tag(0x80, &p256_curve[1..])), point),
            ),
            (
                "P-256 curve in a SEQUENCE",
                spki(&oid_then(ec_oid, &nested(1, p256_curve)), point),
            ),
            // The P-256 point in other forms: compressed and hybrid
            // (OpenSSL's exports of the RFC 6979 point), compressed with
            // either tag, and a 65-octet point with each other tag, so that
            // only the tag differs; the point at infinity (`00`).
            (
                "P-256 compressed",
                unhex(
                    "3039301306072a8648ce3d020106082a8648ce3d0301070322000360fed4ba255a\
                     9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
                ),
            ),
            (
                "P-256 compressed 02",
                spki(P256_ALGORITHM, &with_tag(0x02, x_coordinate)),
            ),
            (
                "P-256 hybrid",
                unhex(
                    "3059301306072a8648ce3d020106082a8648ce3d0301070342000760fed4ba255a\
                     9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc\
                     99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
                ),
            ),
            (
                "P-256 65 octets, tag 02",
                spki(P256_ALGORITHM, &with_tag(0x02, &point[1..])),
            ),
            (
                "P-256 65 octets, tag 03",
                spki(P256_ALGORITHM, &with_tag(0x03, &point[1..])),
            ),
            (
                "P-256 65 octets, tag 06",
                spki(P256_ALGORITHM, &with_tag(0x06, &point[1..])),
            ),
            (
                "P-256 65 octets, tag 05",
                spki(P256_ALGORITHM, &with_tag(0x05, &point[1..])),
            ),
            (
                "P-256 65 octets, tag 00",
                spki(P256_ALGORITHM, &with_tag(0x00, &point[1..])),
            ),
            ("P-256 point at infinity", spki(P256_ALGORITHM, &[0x00])),
            // OIDs one arc from id-ecPublicKey with the P-256 curve and
            // point: 1.2.840.10045.2 and 1.2.840.10045.2.1.0; and two real
            // EC algorithms that are not id-ecPublicKey, id-ecDH
            // (1.3.132.1.12) and id-ecMQV (1.3.132.1.13).
            (
                "1.2.840.10045.2",
                spki(
                    &oid_then(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02], p256_curve),
                    point,
                ),
            ),
            (
                "1.2.840.10045.2.1.0",
                spki(
                    &oid_then(
                        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x00],
                        p256_curve,
                    ),
                    point,
                ),
            ),
            (
                "id-ecDH",
                spki(
                    &oid_then(&[0x2b, 0x81, 0x04, 0x01, 0x0c], p256_curve),
                    point,
                ),
            ),
            (
                "id-ecMQV",
                spki(
                    &oid_then(&[0x2b, 0x81, 0x04, 0x01, 0x0d], p256_curve),
                    point,
                ),
            ),
            // The two algorithms crossed: the Ed25519 OID with the P-256
            // parameters and point, or with only its point; id-ecPublicKey
            // and the curve with the Ed25519 key.
            (
                "ed25519 OID, P-256 parameters and point",
                spki(&oid_then(ed25519_oid, p256_curve), point),
            ),
            ("ed25519 OID, P-256 point", spki(ED25519_ALGORITHM, point)),
            (
                "P-256 algorithm, Ed25519 key",
                spki(P256_ALGORITHM, ed25519_key),
            ),
            // The curve OID as the algorithm.
            ("prime256v1 as the algorithm", spki(p256_curve, point)),
        ];
        for (name, der) in cases {
            assert_eq!(canonical_public_identity(&der), UNSUPPORTED, "{name}");
        }
    }

    /// The key lengths one octet either side of the accepted ones, and
    /// further out: 32 octets for Ed25519, 65 for P-256 (with the `04`
    /// tag); and zero padding that keeps the key's value.
    #[test]
    fn key_lengths_either_side_are_refused() {
        for len in [0usize, 1, 31, 33, 64, 65] {
            let mut key = ED25519[12..].to_vec();
            key.resize(len, 0x5a);
            let der = spki(ED25519_ALGORITHM, &key);
            if len == 0 {
                // No key octet at all is a structural error, first.
                assert_eq!(canonical_public_identity(&der), Err(IdentityError::NotSpki));
            } else {
                assert_eq!(canonical_public_identity(&der), UNSUPPORTED, "{len}");
            }
        }
        assert!(canonical_public_identity(&spki(ED25519_ALGORITHM, &ED25519[12..])).is_ok());
        for len in [1usize, 33, 64, 66, 97, 129] {
            let mut point = P256[26..].to_vec();
            point.resize(len, 0x5a);
            assert_eq!(point[0], 0x04);
            let der = spki(P256_ALGORITHM, &point);
            assert_eq!(canonical_public_identity(&der), UNSUPPORTED, "{len}");
        }
        assert!(canonical_public_identity(&spki(P256_ALGORITHM, &P256[26..])).is_ok());
        // A valid key padded with zero octets that leave its value
        // unchanged: an Ed25519 `y` (little-endian) with zeros after it, a
        // P-256 coordinate (big-endian) with a zero before it. Each would be
        // a second spelling of an accepted key, so only the length refuses
        // it.
        let mut y3 = vec![0u8; 32];
        y3[0] = 3;
        assert!(canonical_public_identity(&spki(ED25519_ALGORITHM, &y3)).is_ok());
        for len in [33usize, 64] {
            let mut key = y3.clone();
            key.resize(len, 0);
            let der = spki(ED25519_ALGORITHM, &key);
            assert_eq!(canonical_public_identity(&der), UNSUPPORTED, "{len}");
        }
        let point = &P256[26..];
        for padded in [
            [&point[..33], &[0], &point[33..]].concat(),
            [&point[..1], &[0], &point[1..33], &[0], &point[33..]].concat(),
        ] {
            let der = spki(P256_ALGORITHM, &padded);
            assert_eq!(
                canonical_public_identity(&der),
                UNSUPPORTED,
                "{padded:02x?}"
            );
        }
    }

    /// The Ed25519 key checks of "Key validity", each probe a 32-octet key in
    /// the accepted form: accepted, or refused as
    /// [`IdentityError::UnsupportedKey`]. Little-endian `y`, sign of `x` in
    /// the top bit; `p = 2^255 - 19`.
    const ED25519_PROBES: [(&str, &str, bool); 18] = [
        // Accepted: RFC 8410's key; y = 3 and 32 octets 01, points with a
        // torsion component (computed in Python: 8P is not the identity,
        // LP is not either).
        (
            "RFC 8410",
            "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1",
            true,
        ),
        (
            "y = 3",
            "0300000000000000000000000000000000000000000000000000000000000000",
            true,
        ),
        (
            "01 x 32",
            "0101010101010101010101010101010101010101010101010101010101010101",
            true,
        ),
        // One key, one identity: y = 3 + p spells the y = 3 point again.
        (
            "y = 3 + p",
            "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            false,
        ),
        // The eight small-order points: y = 0 (order 4, both signs of x),
        // the identity y = 1, y = p - 1 (order 2), the order-8 y and p - y.
        (
            "all zero (order 4)",
            "0000000000000000000000000000000000000000000000000000000000000000",
            false,
        ),
        (
            "y = 0, sign set (order 4)",
            "0000000000000000000000000000000000000000000000000000000000000080",
            false,
        ),
        (
            "identity",
            "0100000000000000000000000000000000000000000000000000000000000000",
            false,
        ),
        (
            "y = p - 1 (order 2)",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            false,
        ),
        (
            "order 8",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            false,
        ),
        (
            "order 8, p - y",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            false,
        ),
        (
            "order 8, sign set",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            false,
        ),
        // Non-canonical: y = p + 1 (the identity again), x = 0 with the
        // sign bit set (y = 1 and y = p - 1), y = 2^255 - 1.
        (
            "y = p + 1",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            false,
        ),
        (
            "identity, sign set",
            "0100000000000000000000000000000000000000000000000000000000000080",
            false,
        ),
        (
            "y = p - 1, sign set",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            false,
        ),
        (
            "all ff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            false,
        ),
        // Undecodable: (y^2 - 1) / (d y^2 + 1) is not a square.
        (
            "07 x 32",
            "0707070707070707070707070707070707070707070707070707070707070707",
            false,
        ),
        (
            "02 x 32",
            "0202020202020202020202020202020202020202020202020202020202020202",
            false,
        ),
        (
            "y = 2",
            "0200000000000000000000000000000000000000000000000000000000000000",
            false,
        ),
    ];

    #[test]
    fn ed25519_keys_are_validated() {
        for (name, key, accepted) in ED25519_PROBES {
            let key = unhex(key);
            assert_eq!(key.len(), 32, "{name}");
            let result = canonical_public_identity(&spki(ED25519_ALGORITHM, &key));
            if accepted {
                assert!(result.is_ok(), "{name}");
            } else {
                assert_eq!(result, UNSUPPORTED, "{name}");
            }
        }
    }

    /// The Ed25519 check here (the recovery key check, through
    /// `ed25519-dalek`: decoding, re-encoding, `is_weak`) and the
    /// hand-written RFC 8032 decoding of the JWK check
    /// ([`check_ed25519`], the oracle) accept and refuse the same keys: the
    /// probes above, the keys of 32 equal octets 00 to 1f, and `y` from 0
    /// to 15 with either sign. (Few, since the hand-written arithmetic is
    /// slow in a debug build.)
    #[test]
    fn the_ed25519_check_agrees_with_the_hand_written_decoding() {
        let mut keys: Vec<Vec<u8>> = ED25519_PROBES
            .iter()
            .map(|(_, key, _)| unhex(key))
            .collect();
        keys.extend((0..0x20).map(|byte| vec![byte; 32]));
        for y in 0..16u8 {
            for sign in [0x00, 0x80] {
                let mut key = vec![0; 32];
                key[0] = y;
                key[31] = sign;
                keys.push(key);
            }
        }
        let mut accepted = 0;
        for key in &keys {
            let here = canonical_public_identity(&spki(ED25519_ALGORITHM, key)).is_ok();
            let oracle = check_ed25519(key).is_ok();
            assert_eq!(here, oracle, "{key:02x?}");
            accepted += usize::from(here);
        }
        // Both outcomes occur.
        assert!(accepted > 0 && accepted < keys.len(), "{accepted}");
    }

    /// The P-256 key checks of "Key validity", each probe the two 32-octet
    /// big-endian coordinates after `04`: accepted, or refused as
    /// [`IdentityError::UnsupportedKey`]. The two accepted points with a
    /// small coordinate were found in Python (a square root, and the roots
    /// of a cubic, mod `p`) and pass `openssl pkey -pubcheck`.
    const P256_PROBES: [(&str, &str, bool); 9] = [
        (
            "RFC 6979",
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
             7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            true,
        ),
        (
            "x = 0",
            "0000000000000000000000000000000000000000000000000000000000000000\
             66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
            true,
        ),
        (
            "y = 1",
            "8d0177ebab9c6e9e10db6dd095dbac0d6375e8a97b70f611875d877f0069d2c7\
             0000000000000000000000000000000000000000000000000000000000000001",
            true,
        ),
        // One key, one identity: x + p and y + p spell the two points
        // above again (each fits in 32 octets).
        (
            "x = 0 + p",
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\
             66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
            false,
        ),
        (
            "y = 1 + p",
            "8d0177ebab9c6e9e10db6dd095dbac0d6375e8a97b70f611875d877f0069d2c7\
             ffffffff00000001000000000000000000000001000000000000000000000000",
            false,
        ),
        // Off the curve: the RFC 6979 point with y's last bit flipped.
        (
            "off the curve",
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
             7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462298",
            false,
        ),
        (
            "(0, 0)",
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000",
            false,
        ),
        (
            "all ff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            false,
        ),
        (
            "(p, p)",
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\
             ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            false,
        ),
    ];

    #[test]
    fn p256_points_are_validated() {
        for (name, coordinates, accepted) in P256_PROBES {
            let mut point = vec![0x04];
            point.extend(unhex(coordinates));
            assert_eq!(point.len(), 65, "{name}");
            let result = canonical_public_identity(&spki(P256_ALGORITHM, &point));
            if accepted {
                assert!(result.is_ok(), "{name}");
            } else {
                assert_eq!(result, UNSUPPORTED, "{name}");
            }
        }
    }

    /// The structural errors come first, in their own order: bytes with a
    /// structural problem have that error whether or not their algorithm
    /// is accepted, and only bytes that pass every structural check can
    /// be [`IdentityError::UnsupportedKey`].
    #[test]
    fn structural_errors_come_before_the_algorithm() {
        let rsa = unhex(
            "30819f300d06092a864886f70d010101050003818d0030818902818100c0a0738f\
             54294d8703d7a16446e70c5ea05c34102bae574a8581665560ac0cccccd57a70bb\
             e5c42395bcca654fa8759892e357dc97cd09ef379c4387b2b05861fbfd62a1ef06\
             fd3618ec22e3d717d4893ee72b2b87d100676348497552a8b8e8d056bb6d783509\
             94b74ea17be6b8858ef29597b5e111baea4931741254199b930203010001",
        );
        assert_eq!(canonical_public_identity(&rsa), UNSUPPORTED);
        for der in [ED25519.to_vec(), P256.to_vec(), rsa] {
            // Truncated, trailing bytes, a non-minimal outer length.
            assert_eq!(
                canonical_public_identity(&der[..der.len() - 1]),
                Err(IdentityError::Truncated)
            );
            let mut trailing = der.clone();
            trailing.push(0x00);
            assert_eq!(
                canonical_public_identity(&trailing),
                Err(IdentityError::TrailingBytes)
            );
            // The outer length with a leading zero octet: 30 82 00 2a, 30
            // 82 00 59 or 30 82 00 9f.
            let header = if der[1] == 0x81 { 3 } else { 2 };
            let mut long_outer = vec![0x30, 0x82, 0x00, der[header - 1]];
            long_outer.extend_from_slice(&der[header..]);
            assert_eq!(
                canonical_public_identity(&long_outer),
                Err(IdentityError::NotDer)
            );
        }
        // An Ed25519 and a P-256 key whose BIT STRING is an OCTET STRING,
        // or has unused bits.
        for (der, at) in [(ED25519.to_vec(), 9), (P256.to_vec(), 23)] {
            let mut octet_string = der.clone();
            octet_string[at] = 0x04;
            assert_eq!(
                canonical_public_identity(&octet_string),
                Err(IdentityError::NotSpki)
            );
            let mut unused_bits = der.clone();
            unused_bits[at + 2] = 0x01;
            assert_eq!(
                canonical_public_identity(&unused_bits),
                Err(IdentityError::NotSpki)
            );
        }
        // Unaccepted parameters with a structural fault: a non-empty NULL
        // after the Ed25519 OID is NotDer, not UnsupportedKey.
        let mut der = with_null_parameters();
        der[1] += 1;
        der[3] += 1;
        der[10] = 0x01;
        der.insert(11, 0x00);
        assert_eq!(canonical_public_identity(&der), Err(IdentityError::NotDer));
    }

    #[test]
    fn empty_and_oversize_are_refused() {
        assert_eq!(canonical_public_identity(&[]), Err(IdentityError::Empty));
        // The largest structure within the bound passes the structural
        // check (the Ed25519 OID with a key of thousands of octets, then
        // UnsupportedKey); one byte more is
        // TooLarge before any parsing.
        let mut len = 2;
        while large(len + 1).len() <= MAX_SPKI_DER_BYTES {
            len += 1;
        }
        assert_eq!(large(len).len(), MAX_SPKI_DER_BYTES);
        assert_eq!(canonical_public_identity(&large(len)), UNSUPPORTED);
        assert_eq!(large(len + 1).len(), MAX_SPKI_DER_BYTES + 1);
        assert_eq!(
            canonical_public_identity(&large(len + 1)),
            Err(IdentityError::TooLarge)
        );
        let mut trailing = ED25519.to_vec();
        trailing.resize(MAX_SPKI_DER_BYTES + 1, 0);
        assert_eq!(
            canonical_public_identity(&trailing),
            Err(IdentityError::TooLarge)
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        for extra in [&[0x00][..], &[0x30, 0x00], &ED25519[..]] {
            let mut der = ED25519.to_vec();
            der.extend_from_slice(extra);
            assert_eq!(
                canonical_public_identity(&der),
                Err(IdentityError::TrailingBytes)
            );
        }
    }

    /// Another framing of the same structure is no identity: BER lengths
    /// are refused.
    #[test]
    fn non_minimal_lengths_are_refused() {
        // Outer length in long form: 30 81 2a.
        let mut long_outer = vec![0x30, 0x81, 0x2a];
        long_outer.extend_from_slice(&ED25519[2..]);
        // Inner AlgorithmIdentifier length in long form.
        let mut long_inner = vec![0x30, 0x2b, 0x30, 0x81, 0x05];
        long_inner.extend_from_slice(&ED25519[4..]);
        // A leading zero length octet: 30 82 00 2a.
        let mut leading_zero = vec![0x30, 0x82, 0x00, 0x2a];
        leading_zero.extend_from_slice(&ED25519[2..]);
        // Indefinite length.
        let mut indefinite = vec![0x30, 0x80];
        indefinite.extend_from_slice(&ED25519[2..]);
        indefinite.extend([0x00, 0x00]);
        // A BIT STRING length in long form.
        let mut long_key = vec![0x30, 0x2b];
        long_key.extend_from_slice(&ED25519[2..9]);
        long_key.extend([0x03, 0x81, 0x21]);
        long_key.extend_from_slice(&ED25519[11..]);
        for der in [long_outer, long_inner, leading_zero, indefinite, long_key] {
            assert_eq!(
                canonical_public_identity(&der),
                Err(IdentityError::NotDer),
                "{der:02x?}"
            );
        }
        // A length of 128 or more with a leading zero octet: the 144-byte
        // BIT STRING of `large(144)` as 03 82 00 90 instead of 03 81 90.
        let valid = large(0x90);
        assert_eq!(canonical_public_identity(&valid), UNSUPPORTED);
        assert_eq!(&valid[..3], [0x30, 0x81, 0x9a]);
        assert_eq!(&valid[10..13], [0x03, 0x81, 0x90]);
        let mut padded = vec![0x30, 0x81, 0x9b];
        padded.extend_from_slice(&valid[3..10]);
        padded.extend([0x03, 0x82, 0x00, 0x90]);
        padded.extend_from_slice(&valid[13..]);
        assert_eq!(
            canonical_public_identity(&padded),
            Err(IdentityError::NotDer)
        );
        // A non-minimal OID subidentifier (0x80 padding) and a non-empty
        // NULL.
        let mut der = vec![0x30, 0x2b, 0x30, 0x06, 0x06, 0x04, 0x80, 0x2b, 0x65, 0x70];
        der.extend_from_slice(&ED25519[9..]);
        assert_eq!(canonical_public_identity(&der), Err(IdentityError::NotDer));
        let mut der = with_null_parameters();
        der[1] += 1;
        der[3] += 1;
        der[10] = 0x01;
        der.insert(11, 0x00);
        assert_eq!(canonical_public_identity(&der), Err(IdentityError::NotDer));
        // The input ends inside the length octets, or just after them: the
        // length is still checked before the missing contents.
        let cases: [(&[u8], IdentityError); 5] = [
            (&[0x30, 0x81], IdentityError::Truncated),
            (&[0x30, 0x82, 0x01], IdentityError::Truncated),
            (&[0x30, 0x82, 0x01, 0x00], IdentityError::Truncated),
            (&[0x30, 0x81, 0x7f], IdentityError::NotDer),
            (&[0x30, 0x82, 0x00, 0x90], IdentityError::NotDer),
        ];
        for (der, expected) in cases {
            assert_eq!(canonical_public_identity(der), Err(expected), "{der:02x?}");
        }
    }

    /// The edges of the long form: a length below 128 in it (`81 7f`) or
    /// with a leading zero octet (`82 00 ff`) is refused, the shortest long
    /// form of 128 (`81 80`) and of 256 (`82 01 00`) is accepted, and more
    /// than two length octets are refused. An accepted framing passes the
    /// structural check and then is [`IdentityError::UnsupportedKey`], since
    /// no key of these lengths is an accepted form.
    #[test]
    fn long_form_length_edges() {
        const UNSUPPORTED_KEY: Result<(), IdentityError> = Err(IdentityError::UnsupportedKey);
        let cases: [(usize, &[u8], Result<(), IdentityError>); 10] = [
            (0x7f, &[0x7f], UNSUPPORTED_KEY),
            (0x7f, &[0x81, 0x7f], Err(IdentityError::NotDer)),
            (0x80, &[0x81, 0x80], UNSUPPORTED_KEY),
            (0x80, &[0x82, 0x00, 0x80], Err(IdentityError::NotDer)),
            (0xff, &[0x81, 0xff], UNSUPPORTED_KEY),
            (0xff, &[0x82, 0x00, 0xff], Err(IdentityError::NotDer)),
            (0x100, &[0x82, 0x01, 0x00], UNSUPPORTED_KEY),
            (0x100, &[0x83, 0x00, 0x01, 0x00], Err(IdentityError::NotDer)),
            // Three length octets with no leading zero: 65536 bytes, which
            // would be a truncation; the octet count is refused first.
            (0x10, &[0x83, 0x01, 0x00, 0x00], Err(IdentityError::NotDer)),
            // The count is the low seven bits: c1 is 65 octets, not one.
            (0x80, &[0xc1, 0x80], Err(IdentityError::NotDer)),
        ];
        for (len, length, expected) in cases {
            let der = with_key_length(len, length);
            assert_eq!(
                canonical_public_identity(&der).map(|_| ()),
                expected,
                "{length:02x?}"
            );
        }
    }

    /// Every OID, the algorithm's and one in the parameters at any depth:
    /// not empty, each subidentifier minimal and terminated.
    #[test]
    fn malformed_oids_are_refused() {
        let bad: [&[u8]; 5] = [
            // Empty.
            &[0x06, 0x00],
            // The first subidentifier padded (80 2b).
            &[0x06, 0x04, 0x80, 0x2b, 0x65, 0x70],
            // A later subidentifier padded (2b 80 65).
            &[0x06, 0x04, 0x2b, 0x80, 0x65, 0x70],
            // Unterminated: the last octet has its high bit set.
            &[0x06, 0x03, 0x2b, 0x65, 0xf0],
            // A lone continuation octet.
            &[0x06, 0x01, 0x81],
        ];
        for oid in bad {
            let as_algorithm = with_algorithm(oid);
            let mut as_parameters = vec![0x06, 0x03, 0x2b, 0x65, 0x70];
            as_parameters.extend_from_slice(oid);
            let as_parameters = with_algorithm(&as_parameters);
            let mut second = vec![0x05, 0x00];
            second.extend_from_slice(oid);
            let in_sequence = with_parameters(&nested(1, &second));
            for der in [as_algorithm, as_parameters, in_sequence] {
                assert_eq!(
                    canonical_public_identity(&der),
                    Err(IdentityError::NotDer),
                    "{der:02x?}"
                );
            }
        }
        // Multi-octet subidentifiers (81 00, 128; 81 80 00, 16384: an 80
        // octet that does not start one) are minimal and pass, as does the
        // well-formed OID.
        for oid in [
            &[0x06, 0x04, 0x2b, 0x81, 0x00, 0x70][..],
            &[0x06, 0x05, 0x2b, 0x81, 0x80, 0x00, 0x70],
            &[0x06, 0x03, 0x2b, 0x65, 0x70],
        ] {
            let expected = if oid == ED25519_ALGORITHM {
                Ok(canonical_public_identity(&ED25519).unwrap())
            } else {
                UNSUPPORTED
            };
            assert_eq!(canonical_public_identity(&with_algorithm(oid)), expected);
            assert_eq!(
                canonical_public_identity(&with_parameters(oid)),
                UNSUPPORTED
            );
        }
    }

    /// A RELATIVE-OID in the parameters, and nested in them, follows the
    /// same contents rules as an OID.
    #[test]
    fn malformed_relative_oids_are_refused() {
        let bad: [&[u8]; 5] = [
            // Empty: a RELATIVE-OID has at least one component.
            &[0x0d, 0x00],
            // The first arc padded (80 01).
            &[0x0d, 0x02, 0x80, 0x01],
            // A later arc padded (01 80 7f).
            &[0x0d, 0x03, 0x01, 0x80, 0x7f],
            // Unterminated: the last octet has its high bit set.
            &[0x0d, 0x02, 0x01, 0x81],
            // A lone continuation octet.
            &[0x0d, 0x01, 0x81],
        ];
        for relative_oid in bad {
            for der in [
                with_parameters(relative_oid),
                with_parameters(&nested(1, relative_oid)),
            ] {
                assert_eq!(
                    canonical_public_identity(&der),
                    Err(IdentityError::NotDer),
                    "{der:02x?}"
                );
            }
        }
        // One arc, a multi-octet arc (81 00, 128) and arc 0 pass.
        for relative_oid in [
            &[0x0d, 0x01, 0x01][..],
            &[0x0d, 0x03, 0x01, 0x81, 0x00],
            &[0x0d, 0x02, 0x00, 0x00],
        ] {
            assert_eq!(
                canonical_public_identity(&with_parameters(relative_oid)),
                UNSUPPORTED
            );
            assert_eq!(
                canonical_public_identity(&with_parameters(&nested(1, relative_oid))),
                UNSUPPORTED
            );
        }
    }

    /// Constructed parameters, a SEQUENCE, a SET or a context-specific
    /// `[0]`, are checked element by element, the second child as well as
    /// the first.
    #[test]
    fn constructed_parameters_are_checked_throughout() {
        for tag in [0x30, 0x31, 0xa0] {
            let wrap = |children: &[u8]| {
                let mut parameters = vec![tag, children.len() as u8];
                parameters.extend_from_slice(children);
                with_parameters(&parameters)
            };
            assert_eq!(
                canonical_public_identity(&wrap(&[0x05, 0x00, 0x05, 0x00])),
                UNSUPPORTED
            );
            assert_eq!(
                canonical_public_identity(&wrap(&[0x05, 0x00, 0x04, 0x01, 0x00])),
                UNSUPPORTED
            );
            for children in [
                // A non-empty NULL, first and second.
                &[0x05, 0x01, 0x00, 0x05, 0x00][..],
                &[0x05, 0x00, 0x05, 0x01, 0x00],
                // A long-form length below 128, first and second.
                &[0x04, 0x81, 0x01, 0x00, 0x05, 0x00],
                &[0x05, 0x00, 0x04, 0x81, 0x01, 0x00],
                // A leading zero length octet in the second.
                &[0x05, 0x00, 0x04, 0x82, 0x00, 0x01, 0x00],
                // An indefinite length in the second.
                &[0x05, 0x00, 0x30, 0x80, 0x00, 0x00],
            ] {
                assert_eq!(
                    canonical_public_identity(&wrap(children)),
                    Err(IdentityError::NotDer),
                    "{tag:02x} {children:02x?}"
                );
            }
            // A second child that runs past the end of its parent.
            assert_eq!(
                canonical_public_identity(&wrap(&[0x05, 0x00, 0x04, 0x02, 0x00])),
                Err(IdentityError::Truncated)
            );
        }
    }

    /// The universal tag octets DER allows, written out from X.690
    /// and the tag numbers of X.680 rather
    /// than taken from the implementation: every one of the 64 universal
    /// octets `0x00` to `0x3f`, both forms, is listed exactly once, accepted
    /// or refused, and asserted on [`check_tag`]. Through
    /// [`canonical_public_identity`], in the parameters and nested in them,
    /// each accepted tag carries a representative valid value and each
    /// refused one an empty element.
    #[test]
    fn tags_der_does_not_allow_are_refused() {
        // Each accepted octet with a representative valid DER value.
        const ACCEPTED: [(u8, &[u8]); 28] = [
            // Primitive: BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL,
            // OBJECT IDENTIFIER, ObjectDescriptor.
            (0x01, &[0x01, 0x01, 0xff]),
            (0x02, &[0x02, 0x01, 0x00]),
            (0x03, &[0x03, 0x01, 0x00]),
            (0x04, &[0x04, 0x01, 0x00]),
            (0x05, &[0x05, 0x00]),
            (0x06, &[0x06, 0x01, 0x2b]),
            (0x07, b"\x07\x01a"),
            // Primitive: REAL (zero, no contents), ENUMERATED, UTF8String,
            // RELATIVE-OID.
            (0x09, &[0x09, 0x00]),
            (0x0a, &[0x0a, 0x01, 0x00]),
            (0x0c, b"\x0c\x01a"),
            (0x0d, &[0x0d, 0x01, 0x01]),
            // Primitive: NumericString, PrintableString, TeletexString,
            // VideotexString, IA5String, UTCTime, GeneralizedTime,
            // GraphicString, VisibleString, GeneralString, UniversalString,
            // BMPString.
            (0x12, b"\x12\x011"),
            (0x13, b"\x13\x01a"),
            (0x14, b"\x14\x01a"),
            (0x15, b"\x15\x01a"),
            (0x16, b"\x16\x01a"),
            (0x17, b"\x17\x0d250101000000Z"),
            (0x18, b"\x18\x0f20250101000000Z"),
            (0x19, b"\x19\x01a"),
            (0x1a, b"\x1a\x01a"),
            (0x1b, b"\x1b\x01a"),
            (0x1c, &[0x1c, 0x04, 0x00, 0x00, 0x00, 0x61]),
            (0x1e, &[0x1e, 0x02, 0x00, 0x61]),
            // Constructed: EXTERNAL (and INSTANCE OF) with a direct
            // reference and octet-aligned data, EMBEDDED PDV and CHARACTER
            // STRING with the `fixed` identification and empty data,
            // SEQUENCE (OF), SET (OF). Only the framing of `08`, `0b` and
            // `1d` is checked (see `der_universal_form`).
            (0x28, &[0x28, 0x05, 0x06, 0x01, 0x2b, 0x81, 0x00]),
            (0x2b, &[0x2b, 0x06, 0xa0, 0x02, 0x85, 0x00, 0x82, 0x00]),
            (0x30, &[0x30, 0x03, 0x02, 0x01, 0x00]),
            (0x31, &[0x31, 0x03, 0x02, 0x01, 0x00]),
            (0x3d, &[0x3d, 0x06, 0xa0, 0x02, 0x85, 0x00, 0x82, 0x00]),
        ];
        const REFUSED: [u8; 36] = [
            // Primitive: end-of-contents, EXTERNAL, EMBEDDED PDV, TIME,
            // reserved 15, SEQUENCE, SET, CHARACTER STRING, the
            // high-tag-number form.
            0x00, 0x08, 0x0b, 0x0e, 0x0f, 0x10, 0x11, 0x1d, 0x1f,
            // Constructed: end-of-contents, BOOLEAN, INTEGER, BIT STRING,
            // OCTET STRING, NULL, OBJECT IDENTIFIER, ObjectDescriptor.
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            // Constructed: REAL, ENUMERATED, UTF8String, RELATIVE-OID,
            // TIME, reserved 15.
            0x29, 0x2a, 0x2c, 0x2d, 0x2e, 0x2f,
            // Constructed: the restricted character strings and times
            // (0x32 to 0x3c, 0x3e), and the high-tag-number form.
            0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3e, 0x3f,
        ];
        // The two lists partition the 64 universal octets.
        let mut all: Vec<u8> = ACCEPTED
            .iter()
            .map(|(tag, _)| *tag)
            .chain(REFUSED)
            .collect();
        all.sort_unstable();
        assert_eq!(all, (0x00..=0x3f).collect::<Vec<u8>>());
        for (tag, value) in ACCEPTED {
            assert_eq!(check_tag(tag), Ok(()), "{tag:02x}");
            assert_eq!(value[0], tag);
            assert_eq!(usize::from(value[1]), value.len() - 2, "{tag:02x}");
            for der in [with_parameters(value), with_parameters(&nested(1, value))] {
                assert_eq!(
                    canonical_public_identity(&der),
                    UNSUPPORTED,
                    "{tag:02x} {der:02x?}"
                );
            }
        }
        for tag in REFUSED {
            assert_eq!(check_tag(tag), Err(IdentityError::NotDer), "{tag:02x}");
            for der in [
                with_parameters(&[tag, 0x00]),
                with_parameters(&nested(1, &[tag, 0x00])),
            ] {
                assert_eq!(
                    canonical_public_identity(&der),
                    Err(IdentityError::NotDer),
                    "{tag:02x} {der:02x?}"
                );
            }
        }
        // Constructed and primitive tags of the other classes pass.
        for tag in [0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0xa3, 0x83] {
            assert_eq!(check_tag(tag), Ok(()), "{tag:02x}");
            assert_eq!(
                canonical_public_identity(&with_parameters(&[tag, 0x00])),
                UNSUPPORTED,
                "{tag:02x}"
            );
        }
        // The high-tag-number form, in each class.
        for tag in [0x1f, 0x3f, 0x5f, 0x7f, 0x9f, 0xbf, 0xdf, 0xff] {
            assert_eq!(check_tag(tag), Err(IdentityError::NotDer), "{tag:02x}");
            assert_eq!(
                canonical_public_identity(&with_parameters(&[tag, 0x01, 0x00])),
                Err(IdentityError::NotDer),
                "{tag:02x}"
            );
        }
        // As the outer tag, and as the BIT STRING's.
        for tag in [0x00, 0x10, 0x11, 0x20, 0x23, 0x24] {
            let mut der = ED25519.to_vec();
            der[0] = tag;
            assert_eq!(
                canonical_public_identity(&der),
                Err(IdentityError::NotDer),
                "{tag:02x}"
            );
            let mut der = ED25519.to_vec();
            der[9] = tag;
            assert_eq!(
                canonical_public_identity(&der),
                Err(IdentityError::NotDer),
                "{tag:02x}"
            );
        }
    }

    /// The parameters element is at depth 1 and each element inside a
    /// constructed element is one deeper: depth 8 passes and depth 9 is
    /// refused, whether the deepest element is constructed or primitive.
    #[test]
    fn parameters_nest_at_most_eight_deep() {
        assert_eq!(MAX_PARAMETERS_DEPTH, 8);
        // Eight SEQUENCEs, the innermost empty, at depths 1 to 8.
        assert_eq!(
            canonical_public_identity(&with_parameters(&nested(8, &[]))),
            UNSUPPORTED
        );
        assert_eq!(
            canonical_public_identity(&with_parameters(&nested(9, &[]))),
            Err(IdentityError::NotSpki)
        );
        // A NULL at depth 8, then 9.
        assert_eq!(
            canonical_public_identity(&with_parameters(&nested(7, &[0x05, 0x00]))),
            UNSUPPORTED
        );
        assert_eq!(
            canonical_public_identity(&with_parameters(&nested(8, &[0x05, 0x00]))),
            Err(IdentityError::NotSpki)
        );
        // A primitive parameters element is at depth 1.
        assert_eq!(
            canonical_public_identity(&with_parameters(&[0x04, 0x00])),
            UNSUPPORTED
        );
        // A deep second child: the depth does not grow along a sequence.
        let mut children = nested(6, &[]);
        children.extend(nested(6, &[]));
        assert_eq!(
            canonical_public_identity(&with_parameters(&nested(1, &children))),
            UNSUPPORTED
        );
        // Far deeper, within the size bound: refused, no stack overflow.
        let deep = with_parameters(&nested(1000, &[]));
        assert!(deep.len() <= MAX_SPKI_DER_BYTES);
        assert_eq!(
            canonical_public_identity(&deep),
            Err(IdentityError::NotSpki)
        );
    }

    #[test]
    fn malformed_and_other_structures_are_refused() {
        // PEM text: '-' is 0x2d, a constructed universal tag.
        let pem = b"-----BEGIN PUBLIC KEY-----\n\
            MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
            -----END PUBLIC KEY-----\n";
        assert_eq!(canonical_public_identity(pem), Err(IdentityError::NotDer));
        // Every truncation of the key.
        for end in 1..ED25519.len() {
            assert_eq!(
                canonical_public_identity(&ED25519[..end]),
                Err(IdentityError::Truncated),
                "{end}"
            );
        }
        let cases: [(&[u8], IdentityError); 11] = [
            // The raw 32-byte key, no SPKI around it: its first octets
            // read as a tag and a 63-octet long-form length.
            (&ED25519[12..], IdentityError::NotDer),
            // A SET instead of a SEQUENCE.
            (&[0x31, 0x00], IdentityError::NotSpki),
            // An empty SEQUENCE: no AlgorithmIdentifier.
            (&[0x30, 0x00], IdentityError::NotSpki),
            // An AlgorithmIdentifier and no BIT STRING.
            (
                &[0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70],
                IdentityError::NotSpki,
            ),
            // An empty AlgorithmIdentifier.
            (
                &[0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x00, 0x01],
                IdentityError::NotSpki,
            ),
            // A high tag number form.
            (&[0x1f, 0x01, 0x00], IdentityError::NotDer),
            // A length past the end.
            (&[0x30, 0x2b, 0x30], IdentityError::Truncated),
            // Algorithm without an OID: SEQUENCE { NULL }.
            (
                &[0x30, 0x08, 0x30, 0x02, 0x05, 0x00, 0x03, 0x02, 0x00, 0x01],
                IdentityError::NotSpki,
            ),
            // A BIT STRING with unused bits.
            (
                &[
                    0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x02, 0x01, 0x02,
                ],
                IdentityError::NotSpki,
            ),
            // An empty key.
            (
                &[
                    0x30, 0x0a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x01, 0x00,
                ],
                IdentityError::NotSpki,
            ),
            // A BIT STRING with no octet at all.
            (
                &[
                    0x30, 0x09, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x00,
                ],
                IdentityError::NotSpki,
            ),
        ];
        for (der, expected) in cases {
            assert_eq!(canonical_public_identity(der), Err(expected), "{der:02x?}");
        }
        // A SET, an OCTET STRING or a `[0]` around the whole, a SET as the
        // AlgorithmIdentifier, an OCTET STRING as the key.
        for (offset, tag) in [(0, 0x31), (0, 0x04), (0, 0xa0), (2, 0x31), (9, 0x04)] {
            let mut der = ED25519.to_vec();
            der[offset] = tag;
            assert_eq!(
                canonical_public_identity(&der),
                Err(IdentityError::NotSpki),
                "{offset} {tag:02x}"
            );
        }
        // A third element in the SPKI, and two parameters.
        let mut der = vec![0x30, 0x2c];
        der.extend_from_slice(&ED25519[2..]);
        der.extend([0x05, 0x00]);
        assert_eq!(canonical_public_identity(&der), Err(IdentityError::NotSpki));
        let mut der = vec![0x30, 0x2e, 0x30, 0x09, 0x06, 0x03, 0x2b, 0x65, 0x70];
        der.extend([0x05, 0x00, 0x05, 0x00]);
        der.extend_from_slice(&ED25519[9..]);
        assert_eq!(canonical_public_identity(&der), Err(IdentityError::NotSpki));
    }

    #[test]
    fn errors_print_fixed_text_and_no_bytes() {
        for error in [
            IdentityError::Empty,
            IdentityError::TooLarge,
            IdentityError::Truncated,
            IdentityError::NotDer,
            IdentityError::TrailingBytes,
            IdentityError::NotSpki,
            IdentityError::UnsupportedKey,
        ] {
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("0x") && !text.contains("19bf"), "{text}");
            }
        }
        assert_eq!(
            IdentityError::NotDer.to_string(),
            "the public key is not in DER encoding"
        );
        assert_eq!(
            IdentityError::UnsupportedKey.to_string(),
            "the public key is not an accepted Ed25519 or P-256 key"
        );
        assert_eq!(
            format!("{:?}", IdentityError::UnsupportedKey),
            "UnsupportedKey"
        );
    }
}
