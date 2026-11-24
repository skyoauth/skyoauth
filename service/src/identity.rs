//! The canonical public identity of an mTLS public key: the value of
//! `AdminCredential.public_identity` (design section 7.2; tasks T13.1;
//! identity-registry section 5.2) and, when its writer lands,
//! `ResourceServerChecker.public_mtls_identity` (identity-registry section
//! 7.3, IR-090). The format and the rules below are a lead decision,
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
//! identity string from a client. So the `0005` unique key on
//! `admin_credential.public_identity`, which keeps a key registered at most
//! once, revoked credentials included, holds per key: a revoked key cannot
//! be registered again under another spelling of its identity.
//!
//! Nothing calls this module yet: `bootstrap_instance` and the operator
//! writers still take the identity string from their caller, and the slices
//! that wire enrollment and authentication (S5, S7) call it.
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
//!   ([`IdentityError::NotSpki`]);
//! - every element is DER-framed ([`IdentityError::NotDer`]): a tag in one
//!   octet (no high-tag-number form), a definite length (no indefinite
//!   length `0x80`) in its shortest form (the short form below 128; in the
//!   long form no leading zero octet, and at most two length octets, enough
//!   for the size bound), and contents within its parent
//!   ([`IdentityError::Truncated`]); a `NULL` is empty; an `OBJECT
//!   IDENTIFIER` is not empty and every subidentifier is minimal and
//!   terminated. Constructed parameters are checked the same way,
//!   recursively.
//!
//! DER is a canonical encoding, and these rules reject every other framing
//! of the same structure: PEM text, a long-form or zero-padded length, an
//! indefinite length, trailing bytes. So the usual other spellings of one
//! key give an error, not a second identity.
//!
//! # What is not checked
//!
//! - The algorithm. There is no algorithm list here: any `OBJECT
//!   IDENTIFIER` passes, and the key bytes are not decoded, so neither the
//!   key's validity (a point on its curve, an RSA modulus) nor its strength
//!   is checked. A caller that needs a particular algorithm or strength (for
//!   example the operator's mTLS key policy, T13.1) must check the key
//!   itself; this module only names it.
//! - DER rules inside primitive elements other than `NULL` and `OBJECT
//!   IDENTIFIER`, and inside the key bytes: for example the minimal
//!   encoding of an `INTEGER` or the `BOOLEAN` values in explicit curve
//!   parameters, or the order of a `SET OF`. Such a key with a non-DER
//!   parameter is accepted and its identity is that of its exact bytes, so
//!   the same key spelled two ways there would have two identities; a caller
//!   that accepts explicit parameters at all should restrict them by
//!   algorithm.
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
    /// An element's header or contents run past the end of its parent.
    Truncated,
    /// A length is indefinite or not in its shortest form, or a tag is in
    /// the high-tag-number form: BER, not DER.
    NotDer,
    /// Bytes follow the outer `SEQUENCE`.
    TrailingBytes,
    /// Well-formed DER, but not the shape of a `SubjectPublicKeyInfo`.
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
const CONSTRUCTED: u8 = 0x20;

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

/// Reads one element from the front of `input`; returns it and the rest.
fn element(input: &[u8]) -> Result<(Element<'_>, &[u8]), IdentityError> {
    let (&tag, rest) = input.split_first().ok_or(IdentityError::Truncated)?;
    if tag & 0x1f == 0x1f {
        return Err(IdentityError::NotDer);
    }
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

/// Checks that `contents` is a sequence of well-formed DER elements,
/// recursing into constructed ones.
fn check_elements(mut contents: &[u8]) -> Result<(), IdentityError> {
    while !contents.is_empty() {
        let (element, rest) = element(contents)?;
        check_element(&element)?;
        contents = rest;
    }
    Ok(())
}

fn check_element(element: &Element<'_>) -> Result<(), IdentityError> {
    match element.tag {
        NULL if !element.contents.is_empty() => Err(IdentityError::NotDer),
        OBJECT_IDENTIFIER => check_oid(element.contents),
        tag if tag & CONSTRUCTED != 0 => check_elements(element.contents),
        _ => Ok(()),
    }
}

/// Not empty; each subidentifier minimal (no leading 0x80 octet) and
/// terminated (the last octet has its high bit clear).
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
    let (algorithm, rest) = element(spki.contents)?;
    let (key, rest) = element(rest)?;
    if algorithm.tag != SEQUENCE || key.tag != BIT_STRING || !rest.is_empty() {
        return Err(IdentityError::NotSpki);
    }
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
    // parameters ANY OPTIONAL }.
    let (oid, parameters) = element(algorithm.contents)?;
    if oid.tag != OBJECT_IDENTIFIER {
        return Err(IdentityError::NotSpki);
    }
    check_oid(oid.contents)?;
    if !parameters.is_empty() {
        let (parameters, rest) = element(parameters)?;
        if !rest.is_empty() {
            return Err(IdentityError::NotSpki);
        }
        check_element(&parameters)?;
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

    /// A syntactically valid SPKI whose BIT STRING is `len` bytes long
    /// (unused-bits octet included), with long-form lengths.
    fn large(len: usize) -> Vec<u8> {
        let mut key = vec![0u8; len];
        key[1] = 1;
        let mut bit_string = vec![0x03];
        push_length(&mut bit_string, len);
        bit_string.extend(key);
        let mut contents = vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        contents.extend(bit_string);
        let mut der = vec![0x30];
        push_length(&mut der, contents.len());
        der.extend(contents);
        der
    }

    fn push_length(out: &mut Vec<u8>, len: usize) {
        match len {
            0..0x80 => out.push(len as u8),
            0x80..0x100 => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
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

    /// Another encoding of the same key is no identity: BER lengths are
    /// refused, so one key has one identity.
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
    }

    #[test]
    fn malformed_and_other_structures_are_refused() {
        let pem = b"-----BEGIN PUBLIC KEY-----\n\
            MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
            -----END PUBLIC KEY-----\n";
        assert_eq!(canonical_public_identity(pem), Err(IdentityError::NotSpki));
        // Every truncation of the key.
        for end in 1..ED25519.len() {
            assert_eq!(
                canonical_public_identity(&ED25519[..end]),
                Err(IdentityError::Truncated),
                "{end}"
            );
        }
        let cases: [(&[u8], IdentityError); 8] = [
            // The raw 32-byte key, no SPKI around it: its first octets
            // read as a tag and a 63-octet long-form length.
            (&ED25519[12..], IdentityError::NotDer),
            // A SET instead of a SEQUENCE.
            (&[0x31, 0x00], IdentityError::NotSpki),
            // An empty SEQUENCE.
            (&[0x30, 0x00], IdentityError::Truncated),
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
        ];
        for (der, expected) in cases {
            assert_eq!(canonical_public_identity(der), Err(expected), "{der:02x?}");
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
