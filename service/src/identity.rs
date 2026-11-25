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
//! # One identity per encoding, not per key
//!
//! The digest covers the exact bytes, so an identity names one DER encoding
//! of a key, not the key. A key has more than one valid DER
//! `SubjectPublicKeyInfo`, and this module accepts each of them, with an
//! identity of its own:
//!
//! - an EC key (P-256 and the other curves) with its point uncompressed
//!   (`04`), compressed (`02`, `03`) or hybrid (`06`, `07`), and with
//!   named-curve parameters (an `OBJECT IDENTIFIER`) or explicit ones
//!   (`specifiedCurve`);
//! - an RSA key with `NULL` parameters or with none, with a BER length
//!   (long-form or zero-padded) inside the `RSAPublicKey` that the `BIT
//!   STRING` holds, which is not decoded, and under another algorithm
//!   `OBJECT IDENTIFIER` for the same modulus and exponent: `rsaEncryption`
//!   (1.2.840.113549.1.1.1), `id-RSASSA-PSS` (1.2.840.113549.1.1.10, with
//!   its parameters absent) or `id-RSAES-OAEP` (1.2.840.113549.1.1.7, with
//!   its `RSAES-OAEP-params` `SEQUENCE` as the parameters, of which only the
//!   DER framing is checked, as for any parameters: the hash and mask
//!   functions it names are not read);
//! - an Ed25519 or Ed448 key with its parameters absent or `NULL`
//!   (`05 00`).
//!
//! So the `0005` unique key on `admin_credential.public_identity`, which
//! keeps an identity registered at most once, revoked credentials included,
//! holds per encoding only: a revoked RSA key enrolled again with its
//! parameters absent instead of `NULL` has a new identity, and the unique
//! key does not fire.
//!
//! **A hard requirement on the callers (S3, S5 and S7).** Before a slice
//! computes an identity with this function, it must accept exactly one
//! `SubjectPublicKeyInfo` form for each algorithm it accepts, and refuse
//! every other form of that algorithm:
//!
//! - EC: the algorithm `id-ecPublicKey` (1.2.840.10045.2.1), the named
//!   curve (the curve's `OBJECT IDENTIFIER` as the parameters) and the
//!   uncompressed point (`04`) only;
//! - RSA: the algorithm `rsaEncryption` (1.2.840.113549.1.1.1) with `NULL`
//!   parameters, and a DER `RSAPublicKey` inside the `BIT STRING`;
//!   `id-RSASSA-PSS` and `id-RSAES-OAEP` are refused, or one of them is the
//!   only RSA form, never several;
//! - Ed25519 and Ed448: the parameters absent.
//!
//! Enrollment and authentication must agree on the same single
//! representation of a key across all the profiles they support, since
//! several algorithm identifiers can describe the same underlying public
//! key (RFC 4055 section 1.2: `rsaEncryption`, `id-RSASSA-PSS` and
//! `id-RSAES-OAEP` for one RSA key).
//!
//! Only then does a key have one identity and the `0005` unique key hold
//! per key. This module stays algorithm-agnostic and does not enforce it.
//!
//! The checker writer calls this: [`crate::admin`]'s
//! `create_resource_server_checker` and a key rotation through its
//! `update_resource_server_checker` take the key's DER and store the
//! identity this function derives (lead decision, 2026-11-25). The
//! per-algorithm form rule above is still outstanding, so the checker
//! writers must not be exposed on any HTTP surface until it lands. Nothing
//! else calls this module yet: `bootstrap_instance` and the operator
//! writers still take the identity string from their caller, and the
//! slices that wire enrollment and authentication (S5, S7) call it.
//!
//! # What is checked
//!
//! The input must be one well-formed DER `SubjectPublicKeyInfo` and nothing
//! else; the check is structural:
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
//! bytes. So one structure has one identity. They do not make one key one
//! structure: see "One identity per encoding, not per key" above.
//!
//! # What is not checked
//!
//! - The algorithm. There is no algorithm list here: any `OBJECT
//!   IDENTIFIER` passes, and the key bytes are not decoded, so neither the
//!   key's validity (a point on its curve, an RSA modulus) nor its strength
//!   is checked. A caller that needs a particular algorithm or strength (for
//!   example the operator's mTLS key policy, T13.1) must check the key
//!   itself; this module only names it.
//! - DER rules inside primitive elements other than `NULL`, `OBJECT
//!   IDENTIFIER` and `RELATIVE-OID`, and inside the key bytes: for example
//!   the minimal encoding of an `INTEGER` or the `BOOLEAN` values in
//!   explicit curve parameters, or the order of a `SET OF`. Such a key with
//!   a non-DER parameter is accepted and its identity is that of its exact
//!   bytes, so the same key spelled two ways there would have two
//!   identities; the requirement on the callers above refuses such
//!   parameters for the algorithms it names.
//! - The identity is a name, not a proof: authentication still needs the
//!   TLS handshake's proof of possession and the credential and role check
//!   on every call (design section 7.2).
//!
//! Errors carry no input byte: `Debug` names the variant only and `Display`
//! is fixed text (as `NotRestorableReason`), so an error can be logged.

use std::fmt;

use sha2::{Digest as _, Sha256};

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

/// The canonical public identity of the key whose DER
/// `SubjectPublicKeyInfo` is `spki_der` (see the module documentation).
pub fn canonical_public_identity(spki_der: &[u8]) -> Result<String, IdentityError> {
    if spki_der.is_empty() {
        return Err(IdentityError::Empty);
    }
    if spki_der.len() > MAX_SPKI_DER_BYTES {
        return Err(IdentityError::TooLarge);
    }
    check_spki(spki_der)?;
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

fn check_spki(der: &[u8]) -> Result<(), IdentityError> {
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
    if !parameters.is_empty() {
        let (parameters, rest) = element(parameters)?;
        if !rest.is_empty() {
            return Err(IdentityError::NotSpki);
        }
        check_element(&parameters, 1)?;
    }
    // subjectPublicKey BIT STRING: an unused-bits octet, 0 for a key
    // (inferred: every public key encoding is whole octets), then the key.
    match key.contents {
        [0, _, ..] => Ok(()),
        _ => Err(IdentityError::NotSpki),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Ed25519 public key of RFC 8410 section 10.1, as DER
    /// (`MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=`).
    const ED25519: [u8; 44] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x19, 0xbf, 0x44,
        0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b, 0x96, 0xc8, 0x50,
        0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31, 0x66, 0xe1,
    ];

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

    /// The identity is per encoding: the same key with `NULL` parameters
    /// and without has two (the requirement on the callers in the module
    /// documentation).
    #[test]
    fn parameters_are_structure_only() {
        let identity = canonical_public_identity(&with_null_parameters()).unwrap();
        assert!(identity.starts_with(PUBLIC_IDENTITY_PREFIX));
        assert_ne!(identity, canonical_public_identity(&ED25519).unwrap());
        // An OID parameter (as for EC keys), and a constructed one.
        let mut der = vec![0x30, 0x2f, 0x30, 0x0a, 0x06, 0x03, 0x2b, 0x65, 0x70];
        der.extend([0x06, 0x03, 0x2b, 0x65, 0x71]);
        der.extend_from_slice(&ED25519[9..]);
        assert!(canonical_public_identity(&der).is_ok());
        let mut der = vec![0x30, 0x2e, 0x30, 0x09, 0x06, 0x03, 0x2b, 0x65, 0x70];
        der.extend([0x30, 0x02, 0x05, 0x00]);
        der.extend_from_slice(&ED25519[9..]);
        assert!(canonical_public_identity(&der).is_ok());
    }

    #[test]
    fn empty_and_oversize_are_refused() {
        assert_eq!(canonical_public_identity(&[]), Err(IdentityError::Empty));
        // The largest structure within the bound passes; one byte more is
        // TooLarge before any parsing.
        let mut len = 2;
        while large(len + 1).len() <= MAX_SPKI_DER_BYTES {
            len += 1;
        }
        assert_eq!(large(len).len(), MAX_SPKI_DER_BYTES);
        assert!(canonical_public_identity(&large(len)).is_ok());
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
        assert!(canonical_public_identity(&valid).is_ok());
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
    /// than two length octets are refused.
    #[test]
    fn long_form_length_edges() {
        let cases: [(usize, &[u8], Result<(), IdentityError>); 10] = [
            (0x7f, &[0x7f], Ok(())),
            (0x7f, &[0x81, 0x7f], Err(IdentityError::NotDer)),
            (0x80, &[0x81, 0x80], Ok(())),
            (0x80, &[0x82, 0x00, 0x80], Err(IdentityError::NotDer)),
            (0xff, &[0x81, 0xff], Ok(())),
            (0xff, &[0x82, 0x00, 0xff], Err(IdentityError::NotDer)),
            (0x100, &[0x82, 0x01, 0x00], Ok(())),
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
            assert!(canonical_public_identity(&with_algorithm(oid)).is_ok());
            assert!(canonical_public_identity(&with_parameters(oid)).is_ok());
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
            assert!(canonical_public_identity(&with_parameters(relative_oid)).is_ok());
            assert!(canonical_public_identity(&with_parameters(&nested(1, relative_oid))).is_ok());
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
            assert!(canonical_public_identity(&wrap(&[0x05, 0x00, 0x05, 0x00])).is_ok());
            assert!(canonical_public_identity(&wrap(&[0x05, 0x00, 0x04, 0x01, 0x00])).is_ok());
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
    /// or refused, and checked in the parameters and nested in them.
    #[test]
    fn tags_der_does_not_allow_are_refused() {
        const ACCEPTED: [u8; 28] = [
            // Primitive: BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL,
            // OBJECT IDENTIFIER, ObjectDescriptor.
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            // Primitive: REAL, ENUMERATED, UTF8String, RELATIVE-OID.
            0x09, 0x0a, 0x0c, 0x0d,
            // Primitive: NumericString, PrintableString, TeletexString,
            // VideotexString, IA5String, UTCTime, GeneralizedTime,
            // GraphicString, VisibleString, GeneralString, UniversalString,
            // BMPString.
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1e,
            // Constructed: EXTERNAL (and INSTANCE OF), EMBEDDED PDV,
            // SEQUENCE (OF), SET (OF), CHARACTER STRING.
            0x28, 0x2b, 0x30, 0x31, 0x3d,
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
        let mut all: Vec<u8> = ACCEPTED.iter().chain(&REFUSED).copied().collect();
        all.sort_unstable();
        assert_eq!(all, (0x00..=0x3f).collect::<Vec<u8>>());
        for tag in 0x00..=0x3f_u8 {
            // A minimal valid element of each tag: an OID and a
            // RELATIVE-OID need contents.
            let element: &[u8] = match tag {
                0x06 | 0x0d => &[tag, 0x01, 0x2b],
                _ => &[tag, 0x00],
            };
            let expected = if ACCEPTED.contains(&tag) {
                Ok(())
            } else {
                Err(IdentityError::NotDer)
            };
            for der in [
                with_parameters(element),
                with_parameters(&nested(1, element)),
            ] {
                assert_eq!(
                    canonical_public_identity(&der).map(|_| ()),
                    expected,
                    "{tag:02x} {der:02x?}"
                );
            }
        }
        // Constructed and primitive tags of the other classes pass.
        for tag in [0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0xa3, 0x83] {
            assert!(
                canonical_public_identity(&with_parameters(&[tag, 0x00])).is_ok(),
                "{tag:02x}"
            );
        }
        // The high-tag-number form, in each class.
        for tag in [0x1f, 0x3f, 0x5f, 0x7f, 0x9f, 0xbf, 0xdf, 0xff] {
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
        assert!(canonical_public_identity(&with_parameters(&nested(8, &[]))).is_ok());
        assert_eq!(
            canonical_public_identity(&with_parameters(&nested(9, &[]))),
            Err(IdentityError::NotSpki)
        );
        // A NULL at depth 8, then 9.
        assert!(canonical_public_identity(&with_parameters(&nested(7, &[0x05, 0x00]))).is_ok());
        assert_eq!(
            canonical_public_identity(&with_parameters(&nested(8, &[0x05, 0x00]))),
            Err(IdentityError::NotSpki)
        );
        // A primitive parameters element is at depth 1.
        assert!(canonical_public_identity(&with_parameters(&[0x04, 0x00])).is_ok());
        // A deep second child: the depth does not grow along a sequence.
        let mut children = nested(6, &[]);
        children.extend(nested(6, &[]));
        assert!(canonical_public_identity(&with_parameters(&nested(1, &children))).is_ok());
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
        ] {
            for text in [error.to_string(), format!("{error:?}")] {
                assert!(!text.contains("0x") && !text.contains("19bf"), "{text}");
            }
        }
        assert_eq!(
            IdentityError::NotDer.to_string(),
            "the public key is not in DER encoding"
        );
    }
}
