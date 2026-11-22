//! Uploaded JWK Set validation, thumbprints and live-key overlap
//! (`skyoauth_service::jwk`, T11.3). Pure: no database.
//!
//! The thumbprints expected here come from the RFCs (RFC 7638 section 3.1,
//! RFC 8037 appendix A.3) or were computed independently with Python's
//! `hashlib`, never from this crate's output. The P-384 and P-521 keys were
//! generated with Python's `cryptography`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use skyoauth_service::jwk::{
    Algorithm, Base64urlError, DEFAULT_ALLOWED_ALGORITHMS, JwkError, JwkSet, JwkSetError,
    KEY_REFERENCE_MEMBERS, KeysetVersion, MAX_KEYS, MAX_SET_BYTES, OverlapError, PRIVATE_MEMBERS,
    PublicKey, VersionStatus, check_version_overlap, live_keys, parse_jwk_set,
};

// RFC 7517 appendix A.1 / RFC 7638 section 3.1 (kid "2011-04-29").
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const RSA_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
// RFC 7517 appendix A.1 (kid "1"); thumbprint computed with Python.
const P256_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
const P256_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
const P256_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";
const P256_THUMBPRINT: &str = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s";
// RFC 8037 appendix A.2, A.1 (d) and A.3 (thumbprint).
const ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const ED25519_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const ED25519_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
// Generated with Python's `cryptography`; thumbprints computed with Python.
const P384_X: &str = "qRllRbpjs0WpZzN326wyeDdyd_DuNSPjIaEW9aq7zWDKVCK37k6MmXTi1S9lLigq";
const P384_Y: &str = "D9xVNK0DDLKUOB3ebm0L3nDrUEr2EP05s6TGcOsgNNkZjQPBEOgjbWsCT-WWX0A3";
const P384_THUMBPRINT: &str = "GmrgaIDP2Tdtw86SpYsQRSseaUet9UMiq6kjVR5KOuk";
const P521_X: &str =
    "ACZcq9r597gtjnSV4d4WBjMUaPF9ywO2R0MvC2vA2xTBOJ2D6SO7x6XIp1pV_hREE01OEgCbh95eah8S6-PEEiuK";
const P521_Y: &str =
    "AZupTVy2snFxihMve6JA6-3G5VHhoDDZiGLQibc6EqQTFhsZqlN7SUsc-5NHRahHPDnLMGa-R2m_5laWIh7PH4Y0";
const P521_THUMBPRINT: &str = "3F6jLbdPuIfWTyAalTYo3hPNvtu7-GvwpBnEMxXBjsE";

/// A test-local unpadded base64url encoder, independent of the crate's.
fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        acc = acc << 8 | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(ALPHABET[(acc >> bits & 63) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(acc << (6 - bits) & 63) as usize] as char);
    }
    out
}

/// The RFC 7638 RSA key with `alg` `RS256`: under the default allowed
/// set an RSA key needs `alg`, since both RS256 and PS256 fit it.
fn rsa_key(kid: &str) -> Value {
    json!({"kty": "RSA", "kid": kid, "alg": "RS256", "n": RSA_N, "e": "AQAB"})
}

fn p256_key(kid: &str) -> Value {
    json!({"kty": "EC", "kid": kid, "crv": "P-256", "x": P256_X, "y": P256_Y})
}

fn p384_key(kid: &str) -> Value {
    json!({"kty": "EC", "kid": kid, "crv": "P-384", "x": P384_X, "y": P384_Y})
}

fn p521_key(kid: &str) -> Value {
    json!({"kty": "EC", "kid": kid, "crv": "P-521", "x": P521_X, "y": P521_Y})
}

fn ed25519_key(kid: &str) -> Value {
    json!({"kty": "OKP", "kid": kid, "crv": "Ed25519", "x": ED25519_X})
}

/// A synthetic RSA key with the given modulus and exponent octets.
fn rsa_with(kid: &str, n: &[u8], e: &[u8]) -> Value {
    json!({"kty": "RSA", "kid": kid, "alg": "RS256", "n": b64(n), "e": b64(e)})
}

/// An odd modulus of `len` octets whose first octet is `first`; `seed`
/// varies the middle so distinct seeds give distinct keys.
fn modulus(len: usize, first: u8, seed: u8) -> Vec<u8> {
    let mut n = vec![0xa5; len];
    n[0] = first;
    n[len / 2] = seed;
    n[len - 1] = 0x01;
    n
}

fn with(mut jwk: Value, member: &str, value: Value) -> Value {
    jwk.as_object_mut()
        .unwrap()
        .insert(member.to_owned(), value);
    jwk
}

fn without(mut jwk: Value, member: &str) -> Value {
    jwk.as_object_mut().unwrap().remove(member);
    jwk
}

fn set_of(keys: Vec<Value>) -> Value {
    json!({ "keys": keys })
}

fn parse(set: &Value) -> Result<JwkSet, JwkSetError> {
    parse_jwk_set(set, DEFAULT_ALLOWED_ALGORITHMS)
}

fn accept(jwk: Value) -> JwkSet {
    parse(&set_of(vec![jwk])).expect("accepted")
}

fn reject_with(jwk: Value, allowed: &[Algorithm]) -> JwkError {
    match parse_jwk_set(&set_of(vec![jwk]), allowed) {
        Err(JwkSetError::Key { index: 0, error }) => error,
        other => panic!("expected a key error, got {other:?}"),
    }
}

fn reject(jwk: Value) -> JwkError {
    reject_with(jwk, DEFAULT_ALLOWED_ALGORITHMS)
}

// ---------------------------------------------------------------------------
// Accepted keys and thumbprints

#[test]
fn rfc_7638_example_key_has_the_rfc_thumbprint() {
    // The RFC 7638 section 3.1 key, with its "alg" and "kid": members
    // outside the required set do not enter the thumbprint.
    let set = accept(json!({
        "kty": "RSA", "n": RSA_N, "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"
    }));
    let key = &set.keys()[0];
    assert_eq!(key.thumbprint().as_str(), RSA_THUMBPRINT);
    assert_eq!(key.thumbprint().to_string(), RSA_THUMBPRINT);
    assert_eq!(key.kid().as_str(), "2011-04-29");
    assert_eq!(key.alg(), Some(Algorithm::Rs256));
    assert_eq!(key.algorithm(), Algorithm::Rs256);
    assert!(matches!(key.key(), PublicKey::Rsa { n, e } if n.len() == 256 && e == &[1, 0, 1]));
    assert_eq!(set.get("2011-04-29"), Some(key));
    assert_eq!(set.get("2011-04-2"), None);
}

#[test]
fn ec_and_okp_keys_have_independently_computed_thumbprints() {
    for (jwk, expected) in [
        (p256_key("p256"), P256_THUMBPRINT),
        (p384_key("p384"), P384_THUMBPRINT),
        (p521_key("p521"), P521_THUMBPRINT),
        (ed25519_key("ed"), ED25519_THUMBPRINT),
    ] {
        let set = accept(jwk);
        assert_eq!(set.keys()[0].thumbprint().as_str(), expected);
    }
}

#[test]
fn thumbprint_ignores_optional_members() {
    let plain = accept(p256_key("a"));
    let decorated = accept(with(
        with(
            with(p256_key("b"), "alg", json!("ES256")),
            "use",
            json!("sig"),
        ),
        "key_ops",
        json!(["verify"]),
    ));
    assert_eq!(
        plain.keys()[0].thumbprint(),
        decorated.keys()[0].thumbprint()
    );
}

#[test]
fn rfc_7517_appendix_a1_ec_key_is_refused_for_use_enc() {
    // The RFC's own example is an encryption key.
    let jwk =
        json!({"kty": "EC", "crv": "P-256", "x": P256_X, "y": P256_Y, "use": "enc", "kid": "1"});
    assert_eq!(reject(jwk.clone()), JwkError::Use);
    assert_eq!(
        accept(without(jwk, "use")).keys()[0].thumbprint().as_str(),
        P256_THUMBPRINT
    );
}

#[test]
fn rfc_private_key_examples_are_refused() {
    // RFC 7517 appendix A.2 (EC) and RFC 8037 appendix A.1 (Ed25519).
    let ec = with(p256_key("1"), "d", json!(P256_D));
    assert_eq!(reject(ec), JwkError::PrivateMember("d"));
    let ed = with(ed25519_key("ed"), "d", json!(ED25519_D));
    assert_eq!(reject(ed), JwkError::PrivateMember("d"));
}

#[test]
fn allowlisted_members_are_accepted() {
    // Every common member on every key type: kty, kid, use, key_ops, alg,
    // x5t (20 octets) and x5t#S256 (32 octets).
    let decorate = |jwk: Value, alg: &str| {
        let jwk = with(jwk, "use", json!("sig"));
        let jwk = with(jwk, "key_ops", json!(["verify"]));
        let jwk = with(jwk, "alg", json!(alg));
        let jwk = with(jwk, "x5t", json!(b64(&[0x11; 20])));
        with(jwk, "x5t#S256", json!(b64(&[0x22; 32])))
    };
    for (jwk, alg) in [
        (rsa_key("k"), "RS256"),
        (p256_key("k"), "ES256"),
        (p384_key("k"), "ES384"),
        (p521_key("k"), "ES512"),
        (ed25519_key("k"), "EdDSA"),
    ] {
        accept(decorate(jwk, alg));
    }
    for member in ["x5t", "x5t#S256"] {
        accept(with(
            rsa_key("k"),
            member,
            json!(b64(&vec![0x33; if member == "x5t" { 20 } else { 32 }])),
        ));
    }
}

#[test]
fn certificate_thumbprints_are_checked() {
    for (member, len) in [("x5t", 20), ("x5t#S256", 32)] {
        for actual in [len - 1, len + 1, 0x40] {
            assert_eq!(
                reject(with(rsa_key("k"), member, json!(b64(&vec![1; actual])))),
                JwkError::KeyLength {
                    member,
                    expected: len,
                    actual
                }
            );
        }
        assert_eq!(
            reject(with(
                rsa_key("k"),
                member,
                json!("-----BEGIN CERTIFICATE-----")
            )),
            JwkError::Encoding {
                member,
                reason: Base64urlError::Alphabet
            }
        );
        assert_eq!(
            reject(with(rsa_key("k"), member, json!(1))),
            JwkError::WrongType(member)
        );
    }
}

#[test]
fn members_outside_the_allowlist_are_refused() {
    let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----";
    for jwk in [
        // Nested private members.
        with(rsa_key("k"), "privateKey", json!({"d": P256_D})),
        with(
            ed25519_key("k"),
            "private",
            json!({"kty": "OKP", "d": ED25519_D}),
        ),
        // A PEM string.
        with(rsa_key("k"), "pem", json!(pem)),
        with(p256_key("k"), "privateKeyPem", json!(pem)),
        // Members of another key type.
        with(
            with(
                with(rsa_key("k"), "crv", json!("P-256")),
                "x",
                json!(P256_X),
            ),
            "y",
            json!(P256_Y),
        ),
        with(rsa_key("k"), "crv", json!("P-256")),
        with(rsa_key("k"), "x", json!(P256_X)),
        with(rsa_key("k"), "y", json!(P256_Y)),
        with(with(p256_key("k"), "n", json!(RSA_N)), "e", json!("AQAB")),
        with(p256_key("k"), "n", json!(RSA_N)),
        with(p256_key("k"), "e", json!("AQAB")),
        with(ed25519_key("k"), "y", json!(P256_Y)),
        with(ed25519_key("k"), "n", json!(RSA_N)),
        with(ed25519_key("k"), "e", json!("AQAB")),
        // Unknown, extension and differently cased members.
        with(rsa_key("k"), "ext", json!(true)),
        with(rsa_key("k"), "Kid", json!("k")),
        with(rsa_key("k"), "", json!("")),
        with(rsa_key("k"), "x5t#S512", json!(b64(&[1; 64]))),
        with(rsa_key("k"), "jwk", json!(rsa_key("k"))),
    ] {
        assert_eq!(reject(jwk.clone()), JwkError::UnexpectedMember, "{jwk}");
    }
}

#[test]
fn set_members_other_than_keys_are_refused() {
    for extra in [
        json!({"kty": "oct", "k": "AQAB"}),
        json!(1),
        json!("-----BEGIN PRIVATE KEY-----"),
        json!(null),
    ] {
        for name in ["private_jwk", "extra", "Keys", ""] {
            let mut set = set_of(vec![rsa_key("k")]);
            set[name] = extra.clone();
            assert_eq!(parse(&set), Err(JwkSetError::UnexpectedMember), "{name}");
        }
    }
}

// ---------------------------------------------------------------------------
// Private members and key references

#[test]
fn each_private_member_is_refused_with_a_valid_public_part() {
    assert_eq!(
        PRIVATE_MEMBERS,
        ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
    );
    for member in PRIVATE_MEMBERS {
        for jwk in [rsa_key("k"), p256_key("k"), ed25519_key("k")] {
            assert_eq!(
                reject(with(jwk, member, json!("AQAB"))),
                JwkError::PrivateMember(member),
                "{member}"
            );
        }
    }
}

#[test]
fn each_private_member_is_refused_without_a_valid_public_part() {
    for member in PRIVATE_MEMBERS {
        for jwk in [
            json!({ member: "AQAB" }),
            json!({ "kty": "oct", member: "AQAB" }),
            json!({ "kty": "nope", member: ["not", "a", "string"] }),
        ] {
            assert_eq!(reject(jwk), JwkError::PrivateMember(member), "{member}");
        }
    }
}

#[test]
fn private_members_are_case_sensitive() {
    // Other cases are not the private members, but they are outside the
    // allowlist.
    for member in ["D", "P", "Q", "DP", "Dq", "QI", "OTH", "K"] {
        assert_eq!(
            reject(with(rsa_key("k"), member, json!("AQAB"))),
            JwkError::UnexpectedMember
        );
    }
}

#[test]
fn private_members_are_refused_whatever_their_value() {
    for member in PRIVATE_MEMBERS {
        for value in [
            json!(null),
            json!(0),
            json!(1.5),
            json!({}),
            json!({"d": "AQAB"}),
            json!([]),
            json!(true),
            json!(""),
        ] {
            for jwk in [rsa_key("k"), p256_key("k"), ed25519_key("k"), json!({})] {
                assert_eq!(
                    reject(with(jwk, member, value.clone())),
                    JwkError::PrivateMember(member),
                    "{member}: {value}"
                );
            }
        }
    }
}

#[test]
fn key_references_are_refused() {
    assert_eq!(KEY_REFERENCE_MEMBERS, ["x5u", "x5c", "jku"]);
    for (member, value) in [
        ("x5u", json!("https://example.com/cert.pem")),
        (
            "x5c",
            json!(["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"]),
        ),
        ("jku", json!("https://example.com/jwks.json")),
    ] {
        for jwk in [rsa_key("k"), p256_key("k"), json!({})] {
            assert_eq!(
                reject(with(jwk, member, value.clone())),
                JwkError::KeyReference(member),
                "{member}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Key types

#[test]
fn only_rsa_ec_and_okp_key_types_are_accepted() {
    assert_eq!(
        reject(json!({"kty": "oct", "kid": "k"})),
        JwkError::SymmetricKeyType
    );
    for kty in ["rsa", "ec", "okp", "OCT", "AKP", "ML-DSA", ""] {
        assert_eq!(
            reject(with(rsa_key("k"), "kty", json!(kty))),
            JwkError::UnsupportedKeyType,
            "{kty}"
        );
    }
    assert_eq!(
        reject(without(rsa_key("k"), "kty")),
        JwkError::MissingMember("kty")
    );
    assert_eq!(
        reject(with(rsa_key("k"), "kty", json!(1))),
        JwkError::WrongType("kty")
    );
}

#[test]
fn required_key_members_must_be_present_strings() {
    for (jwk, member) in [
        (rsa_key("k"), "n"),
        (rsa_key("k"), "e"),
        (p256_key("k"), "crv"),
        (p256_key("k"), "x"),
        (p256_key("k"), "y"),
        (ed25519_key("k"), "crv"),
        (ed25519_key("k"), "x"),
    ] {
        assert_eq!(
            reject(without(jwk.clone(), member)),
            JwkError::MissingMember(member)
        );
        assert_eq!(
            reject(with(jwk.clone(), member, json!(null))),
            JwkError::WrongType(member)
        );
        assert_eq!(
            reject(with(jwk, member, json!([1]))),
            JwkError::WrongType(member)
        );
    }
}

// ---------------------------------------------------------------------------
// RSA strength

#[test]
fn rsa_modulus_bounds() {
    let e = [1, 0, 1];
    // Exactly 2048 bits: 256 octets, top bit set.
    accept(rsa_with("k", &modulus(256, 0x80, 0), &e));
    // 2047 bits: 256 octets, top bit clear.
    assert_eq!(
        reject(rsa_with("k", &modulus(256, 0x7f, 0), &e)),
        JwkError::RsaModulusTooSmall { bits: 2047 }
    );
    assert_eq!(
        reject(rsa_with("k", &modulus(256, 0x01, 0), &e)),
        JwkError::RsaModulusTooSmall { bits: 2041 }
    );
    assert_eq!(
        reject(rsa_with("k", &modulus(255, 0xff, 0), &e)),
        JwkError::RsaModulusTooSmall { bits: 2040 }
    );
    // 2049 bits.
    accept(rsa_with("k", &modulus(257, 0x01, 0), &e));
    // Exactly 8192 bits, then 8193.
    accept(rsa_with("k", &modulus(1024, 0xff, 0), &e));
    assert_eq!(
        reject(rsa_with("k", &modulus(1025, 0x01, 0), &e)),
        JwkError::RsaModulusTooLarge { bits: 8193 }
    );
}

#[test]
fn rsa_modulus_has_no_leading_zero_and_is_odd() {
    let e = [1, 0, 1];
    let mut padded = vec![0];
    padded.extend(modulus(256, 0x80, 0));
    assert_eq!(
        reject(rsa_with("k", &padded, &e)),
        JwkError::RsaModulusLeadingZero
    );
    let mut even = modulus(256, 0x80, 0);
    *even.last_mut().unwrap() = 0x02;
    assert_eq!(reject(rsa_with("k", &even, &e)), JwkError::RsaModulusEven);
}

#[test]
fn rsa_exponent_bounds() {
    let n = modulus(256, 0x80, 0);
    for e in [
        &[1, 0, 1][..],
        &[1, 0, 3],
        &[0xff, 0xff, 0xff],
        &[1, 0, 0, 1],
        &[0xff; 32],
    ] {
        accept(rsa_with("k", &n, e));
    }
    for e in [&[3][..], &[0xff, 0xff], &[1, 0, 0], &[0x01], &[0, 1]] {
        let error = reject(rsa_with("k", &n, e));
        assert!(
            matches!(
                error,
                JwkError::RsaExponentTooSmall | JwkError::RsaExponentLeadingZero
            ),
            "{e:?}: {error:?}"
        );
    }
    // 65535 is odd and too small; 65536 is too small.
    assert_eq!(
        reject(rsa_with("k", &n, &[0xff, 0xff])),
        JwkError::RsaExponentTooSmall
    );
    assert_eq!(
        reject(rsa_with("k", &n, &[1, 0, 0])),
        JwkError::RsaExponentTooSmall
    );
    // Even values at or above the minimum.
    assert_eq!(
        reject(rsa_with("k", &n, &[1, 0, 2])),
        JwkError::RsaExponentEven
    );
    assert_eq!(
        reject(rsa_with("k", &n, &[1, 0, 0, 0])),
        JwkError::RsaExponentEven
    );
    assert_eq!(
        reject(rsa_with("k", &n, &[0, 1, 0, 1])),
        JwkError::RsaExponentLeadingZero
    );
    // At most 32 octets.
    let mut long = vec![0xff; 33];
    long[0] = 0x01;
    assert_eq!(
        reject(rsa_with("k", &n, &long)),
        JwkError::RsaExponentTooLong
    );
}

// ---------------------------------------------------------------------------
// Curves

#[test]
fn ec_coordinates_have_the_exact_curve_length() {
    for (crv, len) in [("P-256", 32), ("P-384", 48), ("P-521", 66)] {
        // These points are not on the curve: only lengths are checked
        // until the on-curve check lands (module follow-ups), and these
        // fixtures will change then.
        let key = |x: usize, y: usize| json!({"kty": "EC", "kid": "k", "crv": crv, "x": b64(&vec![7; x]), "y": b64(&vec![9; y])});
        accept(key(len, len));
        for (member, x, y) in [
            ("x", len - 1, len),
            ("x", len + 1, len),
            ("y", len, len - 1),
            ("y", len, len + 1),
        ] {
            let actual = if member == "x" { x } else { y };
            assert_eq!(
                reject(key(x, y)),
                JwkError::KeyLength {
                    member,
                    expected: len,
                    actual
                },
                "{crv} {member}"
            );
        }
    }
}

#[test]
fn only_nist_curves_are_accepted_for_ec() {
    for crv in [
        "secp256k1",
        "P-192",
        "P-224",
        "p-256",
        "Ed25519",
        "X25519",
        "",
    ] {
        assert_eq!(
            reject(with(p256_key("k"), "crv", json!(crv))),
            JwkError::UnsupportedCurve,
            "{crv}"
        );
    }
}

#[test]
fn only_ed25519_is_accepted_for_okp() {
    for crv in ["Ed448", "X25519", "X448", "ed25519", "P-256", ""] {
        assert_eq!(
            reject(with(ed25519_key("k"), "crv", json!(crv))),
            JwkError::UnsupportedCurve,
            "{crv}"
        );
    }
    for len in [31, 33, 57] {
        assert_eq!(
            reject(with(ed25519_key("k"), "x", json!(b64(&vec![5; len])))),
            JwkError::KeyLength {
                member: "x",
                expected: 32,
                actual: len
            }
        );
    }
}

// ---------------------------------------------------------------------------
// Canonical base64url

#[test]
fn key_members_must_be_canonical_unpadded_base64url() {
    let x = P256_X;
    let cases = [
        (format!("{x}="), Base64urlError::Padding),
        (String::new(), Base64urlError::Empty),
        (format!("+{}", &x[1..]), Base64urlError::Alphabet),
        (format!("/{}", &x[1..]), Base64urlError::Alphabet),
        (format!("{} ", x), Base64urlError::Alphabet),
        (format!(" {}", x), Base64urlError::Alphabet),
        (
            format!("{}\n{}", &x[..20], &x[20..]),
            Base64urlError::Alphabet,
        ),
        (format!("{x}AA"), Base64urlError::Length),
    ];
    for (text, reason) in cases {
        assert_eq!(
            reject(with(p256_key("k"), "x", json!(text))),
            JwkError::Encoding {
                member: "x",
                reason
            },
            "{text:?}"
        );
    }
    // P256_X ends in "D4": 43 characters, the last one with 2 unused bits.
    // "D5" encodes the same octets with a nonzero unused bit.
    let noncanonical = format!("{}5", &x[..42]);
    assert_eq!(
        reject(with(p256_key("k"), "x", json!(noncanonical))),
        JwkError::Encoding {
            member: "x",
            reason: Base64urlError::TrailingBits
        }
    );
    // "AQAB" padded and with "+": e is checked the same way.
    assert_eq!(
        reject(with(rsa_key("k"), "e", json!("AQAB=="))),
        JwkError::Encoding {
            member: "e",
            reason: Base64urlError::Padding
        }
    );
    assert_eq!(
        reject(with(rsa_key("k"), "n", json!(RSA_N.replace('-', "+")))),
        JwkError::Encoding {
            member: "n",
            reason: Base64urlError::Alphabet
        }
    );
    // "AQB" would decode to [1, 0] with a nonzero unused bit.
    assert_eq!(
        reject(with(rsa_key("k"), "e", json!("AQB"))),
        JwkError::Encoding {
            member: "e",
            reason: Base64urlError::TrailingBits
        }
    );
}

// ---------------------------------------------------------------------------
// kid, use and key_ops

#[test]
fn kid_is_required_and_bounded() {
    assert_eq!(
        reject(without(rsa_key("k"), "kid")),
        JwkError::MissingMember("kid")
    );
    assert_eq!(
        reject(with(rsa_key("k"), "kid", json!(7))),
        JwkError::WrongType("kid")
    );
    assert_eq!(reject(rsa_key("")), JwkError::KidLength { bytes: 0 });
    accept(rsa_key("a"));
    accept(rsa_key(&"a".repeat(128)));
    assert_eq!(
        reject(rsa_key(&"a".repeat(129))),
        JwkError::KidLength { bytes: 129 }
    );
    accept(rsa_key("ABCXYZabcxyz0189-._~:+/="));
    for kid in [
        "a b", "a\"b", "a\\b", "a\nb", "a@b", "é", "a\u{0}b", "a,b", "{}",
    ] {
        assert_eq!(reject(rsa_key(kid)), JwkError::KidCharacter, "{kid:?}");
    }
}

#[test]
fn duplicate_kid_in_a_set_is_refused() {
    let error = parse(&set_of(vec![
        rsa_key("same"),
        p256_key("other"),
        p256_key("same"),
    ]))
    .unwrap_err();
    match error {
        JwkSetError::DuplicateKid { kid, first, second } => {
            assert_eq!((kid.as_str(), first, second), ("same", 0, 2));
        }
        other => panic!("{other:?}"),
    }
    // kids are compared exactly.
    parse(&set_of(vec![rsa_key("Same"), p256_key("same")])).unwrap();
}

#[test]
fn one_key_under_two_kids_in_a_set_is_refused() {
    let error = parse(&set_of(vec![p256_key("a"), p256_key("b")])).unwrap_err();
    match error {
        JwkSetError::DuplicateKey {
            first_kid,
            second_kid,
        } => assert_eq!((first_kid.as_str(), second_kid.as_str()), ("a", "b")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn use_is_absent_or_sig() {
    accept(with(rsa_key("k"), "use", json!("sig")));
    for value in ["enc", "SIG", "sig ", ""] {
        assert_eq!(
            reject(with(rsa_key("k"), "use", json!(value))),
            JwkError::Use
        );
    }
    assert_eq!(
        reject(with(rsa_key("k"), "use", json!(["sig"]))),
        JwkError::WrongType("use")
    );
}

#[test]
fn key_ops_is_absent_or_exactly_verify() {
    accept(with(rsa_key("k"), "key_ops", json!(["verify"])));
    accept(with(
        with(rsa_key("k"), "key_ops", json!(["verify"])),
        "use",
        json!("sig"),
    ));
    for value in [
        json!(["sign"]),
        json!(["verify", "verify"]),
        json!(["verify", "sign"]),
        json!(["sign", "verify"]),
        json!([]),
        json!("verify"),
        json!([1]),
        json!(["VERIFY"]),
        json!(null),
    ] {
        assert_eq!(
            reject(with(rsa_key("k"), "key_ops", value.clone())),
            JwkError::KeyOps,
            "{value}"
        );
    }
}

// ---------------------------------------------------------------------------
// Algorithms

#[test]
fn alg_must_fit_the_key_type_and_curve() {
    let all = DEFAULT_ALLOWED_ALGORITHMS;
    let keys = [
        (rsa_key("k"), &[Algorithm::Rs256, Algorithm::Ps256][..]),
        (p256_key("k"), &[Algorithm::Es256]),
        (p384_key("k"), &[Algorithm::Es384]),
        (p521_key("k"), &[Algorithm::Es512]),
        (ed25519_key("k"), &[Algorithm::EdDsa]),
    ];
    for (jwk, fits) in keys {
        for &alg in all {
            let jwk = with(jwk.clone(), "alg", json!(alg.name()));
            if fits.contains(&alg) {
                let set = accept(jwk);
                assert_eq!(set.keys()[0].alg(), Some(alg));
                assert_eq!(set.keys()[0].algorithm(), alg);
            } else {
                assert_eq!(reject(jwk), JwkError::AlgorithmMismatch(alg), "{alg}");
            }
        }
    }
}

#[test]
fn algorithm_names() {
    let names: Vec<&str> = DEFAULT_ALLOWED_ALGORITHMS
        .iter()
        .map(|alg| alg.name())
        .collect();
    assert_eq!(
        names,
        ["RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"]
    );
    for alg in DEFAULT_ALLOWED_ALGORITHMS {
        assert_eq!(Algorithm::from_name(alg.name()), Some(*alg));
        assert_eq!(alg.to_string(), alg.name());
    }
    assert_eq!(Algorithm::from_name("rs256"), None);
}

#[test]
fn none_and_symmetric_algorithms_are_forbidden() {
    for alg in ["none", "HS256", "HS384", "HS512"] {
        for jwk in [rsa_key("k"), p256_key("k"), ed25519_key("k")] {
            assert_eq!(
                reject(with(jwk, "alg", json!(alg))),
                JwkError::ForbiddenAlgorithm,
                "{alg}"
            );
        }
    }
}

#[test]
fn unknown_algorithms_are_unsupported() {
    for alg in [
        "RS384", "RS512", "PS384", "PS512", "ES256K", "Ed25519", "rs256", "None", "",
    ] {
        assert_eq!(
            reject(with(rsa_key("k"), "alg", json!(alg))),
            JwkError::UnsupportedAlgorithm,
            "{alg}"
        );
    }
    assert_eq!(
        reject(with(rsa_key("k"), "alg", json!(256))),
        JwkError::WrongType("alg")
    );
}

#[test]
fn alg_must_be_in_the_allowed_set() {
    let only_es256 = &[Algorithm::Es256][..];
    assert_eq!(
        reject_with(with(rsa_key("k"), "alg", json!("RS256")), only_es256),
        JwkError::AlgorithmNotAllowed(Algorithm::Rs256)
    );
    parse_jwk_set(
        &set_of(vec![with(p256_key("k"), "alg", json!("ES256"))]),
        only_es256,
    )
    .unwrap();
    // A misfit is reported as such even when the algorithm is not allowed.
    assert_eq!(
        reject_with(
            with(rsa_key("k"), "alg", json!("ES256")),
            &[Algorithm::Rs256]
        ),
        JwkError::AlgorithmMismatch(Algorithm::Es256)
    );
}

#[test]
fn a_key_without_alg_needs_its_curve_algorithm_allowed() {
    let only_es256 = &[Algorithm::Es256][..];
    let set = parse_jwk_set(&set_of(vec![p256_key("k")]), only_es256).unwrap();
    assert_eq!(set.keys()[0].alg(), None);
    assert_eq!(set.keys()[0].algorithm(), Algorithm::Es256);
    for jwk in [p384_key("k"), p521_key("k"), ed25519_key("k")] {
        assert_eq!(reject_with(jwk, only_es256), JwkError::NoAllowedAlgorithm);
    }
    for jwk in [p256_key("k"), ed25519_key("k")] {
        assert_eq!(reject_with(jwk, &[]), JwkError::NoAllowedAlgorithm);
    }
}

#[test]
fn rsa_keys_require_alg_whatever_the_allowed_set() {
    let rsa = without(rsa_key("k"), "alg");
    // RS256 and PS256 both fit an RSA key, so alg is required even when
    // the allowed set holds one of them, or none.
    for allowed in [
        DEFAULT_ALLOWED_ALGORITHMS,
        &[Algorithm::Rs256, Algorithm::Ps256][..],
        &[Algorithm::Rs256][..],
        &[Algorithm::Ps256][..],
        &[Algorithm::Rs256, Algorithm::Es256][..],
        &[Algorithm::Es256][..],
        &[][..],
    ] {
        assert_eq!(
            reject_with(rsa.clone(), allowed),
            JwkError::AlgorithmRequired,
            "{allowed:?}"
        );
    }
    for alg in [Algorithm::Rs256, Algorithm::Ps256] {
        let set = accept(with(rsa.clone(), "alg", json!(alg.name())));
        assert_eq!(set.keys()[0].alg(), Some(alg));
        assert_eq!(set.keys()[0].algorithm(), alg);
    }
    // The curve fixes the algorithm of EC and Ed25519 keys.
    for (jwk, alg) in [
        (p256_key("k"), Algorithm::Es256),
        (p384_key("k"), Algorithm::Es384),
        (p521_key("k"), Algorithm::Es512),
        (ed25519_key("k"), Algorithm::EdDsa),
    ] {
        let set = accept(jwk);
        assert_eq!(set.keys()[0].alg(), None);
        assert_eq!(set.keys()[0].algorithm(), alg);
    }
}

// ---------------------------------------------------------------------------
// Set shape and bounds

#[test]
fn set_shape() {
    assert_eq!(parse(&json!([rsa_key("k")])), Err(JwkSetError::NotAnObject));
    assert_eq!(parse(&json!({})), Err(JwkSetError::MissingKeys));
    assert_eq!(parse(&json!({"keys": {}})), Err(JwkSetError::KeysNotArray));
    assert_eq!(
        parse(&json!({"keys": null})),
        Err(JwkSetError::KeysNotArray)
    );
    assert_eq!(parse(&json!({"keys": []})), Err(JwkSetError::NoKeys));
    assert_eq!(
        parse(&json!({"keys": [rsa_key("k"), "AQAB"]})),
        Err(JwkSetError::KeyNotObject { index: 1 })
    );
    assert_eq!(
        parse(&json!({"keys": [rsa_key("k"), with(p256_key("e"), "use", json!("enc"))]})),
        Err(JwkSetError::Key {
            index: 1,
            error: JwkError::Use
        })
    );
}

fn distinct_rsa_keys(count: usize) -> Vec<Value> {
    (0..count)
        .map(|i| rsa_with(&format!("k{i}"), &modulus(256, 0x80, i as u8), &[1, 0, 1]))
        .collect()
}

#[test]
fn key_count_bound() {
    assert_eq!(MAX_KEYS, 20);
    assert_eq!(
        parse(&set_of(distinct_rsa_keys(20))).unwrap().keys().len(),
        20
    );
    assert_eq!(
        parse(&set_of(distinct_rsa_keys(21))),
        Err(JwkSetError::TooManyKeys { count: 21 })
    );
}

/// A set whose compact JSON is exactly `size` bytes, padded with a
/// top-level member. The member makes the set invalid (no set within the
/// allowlist and the key bounds reaches 64 KiB), so the bound shows as
/// `TooLarge` above it and as another error at it.
fn set_of_size(size: usize) -> Value {
    let mut set = json!({"keys": [rsa_key("k")], "pad": ""});
    let base = serde_json::to_string(&set).unwrap().len();
    set["pad"] = json!("a".repeat(size - base));
    assert_eq!(serde_json::to_string(&set).unwrap().len(), size);
    set
}

#[test]
fn the_largest_valid_set_is_well_under_the_size_bound() {
    // 20 RSA keys of 8192 bits, a 32-octet e, a 128-byte kid and every
    // allowlisted member: the bound the module docs state.
    let keys: Vec<Value> = (0..20u8)
        .map(|i| {
            let jwk = rsa_with(
                &format!("{i:02}{}", "k".repeat(126)),
                &modulus(1024, 0xff, i),
                &[0xff; 32],
            );
            let jwk = with(jwk, "use", json!("sig"));
            let jwk = with(jwk, "key_ops", json!(["verify"]));
            let jwk = with(jwk, "x5t", json!(b64(&[0x11; 20])));
            with(jwk, "x5t#S256", json!(b64(&[0x22; 32])))
        })
        .collect();
    let set = set_of(keys);
    assert_eq!(serde_json::to_string(&set).unwrap().len(), 34_290);
    assert_eq!(parse(&set).unwrap().keys().len(), 20);
}

#[test]
fn serialized_size_bound() {
    assert_eq!(MAX_SET_BYTES, 65536);
    assert_eq!(
        parse(&set_of_size(MAX_SET_BYTES)),
        Err(JwkSetError::UnexpectedMember)
    );
    assert_eq!(
        parse(&set_of_size(MAX_SET_BYTES + 1)),
        Err(JwkSetError::TooLarge)
    );
    // Checked before the shape.
    assert_eq!(
        parse(&json!(vec!["a".repeat(MAX_SET_BYTES)])),
        Err(JwkSetError::TooLarge)
    );
}

// ---------------------------------------------------------------------------
// Overlap across versions

fn t(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000 + seconds)
}

fn version<'a>(
    id: &'a str,
    keys: &'a JwkSet,
    effective_at: SystemTime,
    expires_at: Option<SystemTime>,
) -> KeysetVersion<'a> {
    KeysetVersion {
        id,
        effective_at,
        expires_at,
        status: VersionStatus::Enabled,
        keys,
    }
}

fn kids(live: &[skyoauth_service::jwk::LiveKey<'_>]) -> Vec<(String, Vec<String>)> {
    live.iter()
        .map(|key| {
            (
                key.key.kid().to_string(),
                key.version_ids.iter().map(|id| id.to_string()).collect(),
            )
        })
        .collect()
}

#[test]
fn version_window_is_start_inclusive_and_expiry_exclusive() {
    let keys = accept(rsa_key("a"));
    let v = version("v1", &keys, t(100), Some(t(200)));
    let nanosecond = Duration::from_nanos(1);
    assert!(!v.is_live(t(100) - nanosecond));
    assert!(v.is_live(t(100)));
    assert!(v.is_live(t(200) - nanosecond));
    assert!(!v.is_live(t(200)));
    assert!(version("v1", &keys, t(100), None).is_live(t(1_000_000)));
    assert_eq!(live_keys(&[v], t(100)).unwrap().len(), 1);
    assert!(live_keys(&[v], t(200)).unwrap().is_empty());
    assert!(live_keys(&[v], t(99)).unwrap().is_empty());
}

#[test]
fn disabled_versions_are_not_live() {
    let keys = accept(rsa_key("a"));
    let mut v = version("v1", &keys, t(0), None);
    v.status = VersionStatus::Disabled;
    assert!(!v.is_live(t(10)));
    assert!(live_keys(&[v], t(10)).unwrap().is_empty());
}

#[test]
fn identical_overlap_is_merged() {
    let old = parse(&set_of(vec![rsa_key("a"), p256_key("b")])).unwrap();
    let new = parse(&set_of(vec![p256_key("b"), ed25519_key("c")])).unwrap();
    let versions = [
        version("v-new", &new, t(100), None),
        version("v-old", &old, t(0), Some(t(200))),
    ];
    let live = live_keys(&versions, t(150)).unwrap();
    assert_eq!(
        kids(&live),
        [
            ("a".into(), vec!["v-old".into()]),
            ("b".into(), vec!["v-new".into(), "v-old".into()]),
            ("c".into(), vec!["v-new".into()]),
        ]
    );
    assert_eq!(live[1].key.thumbprint().as_str(), P256_THUMBPRINT);
    // Before the new version and after the old one.
    assert_eq!(kids(&live_keys(&versions, t(50)).unwrap()).len(), 2);
    assert_eq!(
        kids(&live_keys(&versions, t(200)).unwrap()),
        [
            ("b".into(), vec!["v-new".into()]),
            ("c".into(), vec!["v-new".into()]),
        ]
    );
}

#[test]
fn one_kid_with_two_keys_in_live_versions_conflicts() {
    let first = accept(p256_key("a"));
    let second = accept(p384_key("a"));
    let versions = [
        version("v1", &first, t(0), None),
        version("v2", &second, t(100), None),
    ];
    assert_eq!(
        live_keys(&versions, t(100)).unwrap_err(),
        OverlapError::KidConflict {
            kid: first.keys()[0].kid().clone(),
            first_version: "v1".into(),
            second_version: "v2".into(),
        }
    );
    // Not live together: no conflict.
    assert_eq!(live_keys(&versions, t(99)).unwrap().len(), 1);
    let mut disabled = versions;
    disabled[1].status = VersionStatus::Disabled;
    assert_eq!(live_keys(&disabled, t(100)).unwrap().len(), 1);
    let ended = [
        version("v1", &first, t(0), Some(t(100))),
        version("v2", &second, t(100), None),
    ];
    assert_eq!(live_keys(&ended, t(100)).unwrap().len(), 1);
}

#[test]
fn one_key_under_two_kids_in_live_versions_conflicts() {
    let first = accept(rsa_key("a"));
    let second = parse(&set_of(vec![p256_key("x"), rsa_key("b")])).unwrap();
    let versions = [
        version("v1", &first, t(0), None),
        version("v2", &second, t(0), None),
    ];
    match live_keys(&versions, t(1)).unwrap_err() {
        OverlapError::KeyConflict {
            first_kid,
            second_kid,
            first_version,
            second_version,
        } => assert_eq!(
            (
                first_kid.as_str(),
                second_kid.as_str(),
                first_version.as_str(),
                second_version.as_str()
            ),
            ("a", "b", "v1", "v2")
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn one_kid_and_key_with_two_algorithms_conflicts() {
    let rs = accept(with(rsa_key("a"), "alg", json!("RS256")));
    let ps = accept(with(rsa_key("a"), "alg", json!("PS256")));
    let versions = [
        version("v1", &rs, t(0), None),
        version("v2", &ps, t(0), None),
    ];
    let conflict = OverlapError::AlgorithmConflict {
        kid: rs.keys()[0].kid().clone(),
        first_version: "v1".into(),
        second_version: "v2".into(),
    };
    assert_eq!(live_keys(&versions, t(0)).unwrap_err(), conflict);
    assert_eq!(
        check_version_overlap(&versions[1], &versions[..1]),
        Err(conflict)
    );
}

#[test]
fn a_curve_key_without_alg_matches_the_same_key_with_its_alg() {
    // The algorithm is compared, not the presence of the alg member.
    let bare = accept(p256_key("a"));
    let explicit = accept(with(p256_key("a"), "alg", json!("ES256")));
    assert_eq!(bare.keys()[0].algorithm(), explicit.keys()[0].algorithm());
    let versions = [
        version("v1", &bare, t(0), None),
        version("v2", &explicit, t(0), None),
    ];
    assert_eq!(
        kids(&live_keys(&versions, t(0)).unwrap()),
        [("a".into(), vec!["v1".into(), "v2".into()])]
    );
    assert_eq!(check_version_overlap(&versions[1], &versions[..1]), Ok(()));
    assert_eq!(check_version_overlap(&versions[0], &versions[1..]), Ok(()));
}

#[test]
fn no_versions_give_no_live_keys() {
    assert!(live_keys(&[], t(0)).unwrap().is_empty());
}

#[test]
fn a_version_given_twice_is_listed_once() {
    let keys = accept(p256_key("a"));
    let v = version("v1", &keys, t(0), None);
    let live = live_keys(&[v, v], t(0)).unwrap();
    assert_eq!(kids(&live), [("a".into(), vec!["v1".into()])]);
}

#[test]
fn empty_and_inverted_windows_are_never_live() {
    let keys = accept(p256_key("a"));
    let empty = version("v1", &keys, t(100), Some(t(100)));
    let inverted = version("v2", &keys, t(100), Some(t(50)));
    for at in [t(49), t(50), t(75), t(99), t(100), t(101)] {
        assert!(!empty.is_live(at));
        assert!(!inverted.is_live(at));
    }
    let open = version("v3", &keys, t(0), None);
    for v in [empty, inverted] {
        assert!(!v.windows_intersect(&open));
        assert!(!open.windows_intersect(&v));
        assert!(!v.windows_intersect(&v));
    }
}

fn kid_conflict(kid: &str, first: &str, second: &str) -> OverlapError {
    let kid = accept(p256_key(kid)).keys()[0].kid().clone();
    OverlapError::KidConflict {
        kid,
        first_version: first.into(),
        second_version: second.into(),
    }
}

#[test]
fn windows_intersect_is_half_open_and_symmetric() {
    let keys = accept(p256_key("a"));
    let window = |start: u64, end: Option<u64>| version("v", &keys, t(start), end.map(t));
    let cases = [
        // (a, b, intersect)
        ((0, Some(100)), (100, None), false),
        ((0, Some(100)), (99, None), true),
        ((0, Some(100)), (100, Some(200)), false),
        ((0, Some(100)), (50, Some(60)), true),
        ((0, None), (1_000_000, None), true),
        ((100, None), (100, Some(200)), true),
        ((100, Some(101)), (100, Some(101)), true),
        ((0, Some(100)), (200, Some(300)), false),
    ];
    for ((a0, a1), (b0, b1), expected) in cases {
        let (a, b) = (window(a0, a1), window(b0, b1));
        assert_eq!(
            a.windows_intersect(&b),
            expected,
            "{a0} {a1:?} / {b0} {b1:?}"
        );
        assert_eq!(
            b.windows_intersect(&a),
            expected,
            "{b0} {b1:?} / {a0} {a1:?}"
        );
    }
    // Statuses play no part.
    let (mut a, mut b) = (window(0, None), window(0, None));
    a.status = VersionStatus::Disabled;
    b.status = VersionStatus::Disabled;
    assert!(a.windows_intersect(&b));
}

#[test]
fn write_check_catches_a_future_conflict() {
    let first = accept(p256_key("a"));
    let second = accept(p384_key("a"));
    let existing = [version("v1", &first, t(0), None)];
    let new = version("v2", &second, t(1000), None);
    // Nothing is live together yet, so the live check sees no conflict...
    assert_eq!(live_keys(&[existing[0], new], t(0)).unwrap().len(), 1);
    // ...but the write check refuses the version that will conflict.
    assert_eq!(
        check_version_overlap(&new, &existing),
        Err(kid_conflict("a", "v1", "v2"))
    );
}

#[test]
fn write_check_catches_a_conflict_on_re_enable() {
    let first = accept(p256_key("a"));
    let second = accept(p384_key("a"));
    let v1 = version("v1", &first, t(0), None);
    let mut v2 = version("v2", &second, t(0), None);
    v2.status = VersionStatus::Disabled;
    // While v2 is disabled, the live set has no conflict.
    assert_eq!(live_keys(&[v1, v2], t(10)).unwrap().len(), 1);
    // Re-enabling v2 is checked against the enabled v1; v2's own status
    // (disabled before, enabled after) is not read.
    assert_eq!(
        check_version_overlap(&v2, &[v1]),
        Err(kid_conflict("a", "v1", "v2"))
    );
    v2.status = VersionStatus::Enabled;
    assert_eq!(
        check_version_overlap(&v2, &[v1]),
        Err(kid_conflict("a", "v1", "v2"))
    );
    // A disabled existing version is retired and does not count.
    let mut v1_disabled = v1;
    v1_disabled.status = VersionStatus::Disabled;
    assert_eq!(check_version_overlap(&v2, &[v1_disabled]), Ok(()));
}

#[test]
fn rotation_replaces_a_disabled_open_ended_version() {
    let old_keys = accept(p256_key("a"));
    let new_keys = accept(p384_key("a"));
    let mut old = version("v-old", &old_keys, t(0), None);
    let mut new = version("v-new", &new_keys, t(1000), None);
    // An enabled intersecting version still conflicts at write.
    assert_eq!(
        check_version_overlap(&new, &[old]),
        Err(kid_conflict("a", "v-old", "v-new"))
    );
    // Disable the old open-ended version; the same-kid replacement is
    // then accepted.
    old.status = VersionStatus::Disabled;
    assert_eq!(check_version_overlap(&new, &[old]), Ok(()));
    // Re-enabling the old version is refused while the replacement is
    // enabled...
    assert_eq!(
        check_version_overlap(&old, &[old, new]),
        Err(kid_conflict("a", "v-new", "v-old"))
    );
    // ...and accepted once the replacement is disabled.
    new.status = VersionStatus::Disabled;
    assert_eq!(check_version_overlap(&old, &[old, new]), Ok(()));
}

#[test]
fn a_replacement_created_disabled_waits_for_the_old_version() {
    let old_keys = accept(p256_key("a"));
    let new_keys = accept(p384_key("a"));
    let mut old = version("v-old", &old_keys, t(0), None);
    let mut new = version("v-new", &new_keys, t(0), None);
    new.status = VersionStatus::Disabled;
    // Creating it disabled may skip the check; enabling it may not, and is
    // refused while the old version is enabled...
    assert_eq!(
        check_version_overlap(&new, &[old, new]),
        Err(kid_conflict("a", "v-old", "v-new"))
    );
    // ...and accepted once the old version is disabled.
    old.status = VersionStatus::Disabled;
    assert_eq!(check_version_overlap(&new, &[old, new]), Ok(()));
}

#[test]
fn the_checked_version_is_excluded_by_id() {
    // The keyset's full list may be passed: the version itself (same ID,
    // here with a different key, as a stale copy would be) is skipped.
    let keys = accept(p256_key("a"));
    let stale = accept(p384_key("a"));
    let v = version("v1", &keys, t(0), None);
    let same_id = version("v1", &stale, t(0), None);
    assert_eq!(check_version_overlap(&v, &[same_id]), Ok(()));
    let other_id = version("v2", &stale, t(0), None);
    assert_eq!(
        check_version_overlap(&v, &[same_id, other_id]),
        Err(kid_conflict("a", "v2", "v1"))
    );
}

#[test]
fn write_check_passes_windows_that_do_not_intersect() {
    let first = accept(p256_key("a"));
    let second = accept(p384_key("a"));
    let v1 = version("v1", &first, t(0), Some(t(100)));
    // Starts exactly when v1 expires.
    let v2 = version("v2", &second, t(100), None);
    assert_eq!(check_version_overlap(&v2, &[v1]), Ok(()));
    assert_eq!(check_version_overlap(&v1, &[v2]), Ok(()));
    // One instant of overlap is enough.
    let v3 = version("v3", &second, t(99), None);
    assert_eq!(
        check_version_overlap(&v3, &[v1]),
        Err(kid_conflict("a", "v1", "v3"))
    );
    // Empty and inverted windows conflict with nothing.
    for end in [t(0), t(50)] {
        let empty = version("v4", &second, t(50), Some(end));
        assert!(end <= t(50));
        assert_eq!(check_version_overlap(&empty, &[v1]), Ok(()));
        assert_eq!(check_version_overlap(&v1, &[empty]), Ok(()));
    }
}

#[test]
fn write_check_with_equal_starts() {
    let first = accept(p256_key("a"));
    let second = accept(p384_key("a"));
    let v1 = version("v1", &first, t(100), None);
    let v2 = version("v2", &second, t(100), Some(t(200)));
    assert_eq!(
        check_version_overlap(&v2, &[v1]),
        Err(kid_conflict("a", "v1", "v2"))
    );
    // An equal start and expiry is an empty window.
    let v3 = version("v3", &second, t(100), Some(t(100)));
    assert_eq!(check_version_overlap(&v3, &[v1]), Ok(()));
}

#[test]
fn write_check_applies_the_key_and_alg_rules() {
    let rsa_a = accept(rsa_key("a"));
    let rsa_b = accept(rsa_key("b"));
    let rsa_a_ps = accept(with(rsa_key("a"), "alg", json!("PS256")));
    let other = parse(&set_of(vec![p256_key("c"), ed25519_key("d")])).unwrap();
    let v1 = version("v1", &rsa_a, t(0), None);
    // One key under two kids.
    match check_version_overlap(&version("v2", &rsa_b, t(0), None), &[v1]) {
        Err(OverlapError::KeyConflict {
            first_kid,
            second_kid,
            first_version,
            second_version,
        }) => assert_eq!(
            (
                first_kid.as_str(),
                second_kid.as_str(),
                &*first_version,
                &*second_version
            ),
            ("a", "b", "v1", "v2")
        ),
        other => panic!("{other:?}"),
    }
    // One kid and key with two algs.
    assert_eq!(
        check_version_overlap(&version("v2", &rsa_a_ps, t(0), None), &[v1]),
        Err(OverlapError::AlgorithmConflict {
            kid: rsa_a.keys()[0].kid().clone(),
            first_version: "v1".into(),
            second_version: "v2".into(),
        })
    );
    // The same kid, key and alg (explicit overlap) and unrelated keys pass.
    let v_same = version("v2", &rsa_a, t(0), None);
    let v_other = version("v3", &other, t(0), None);
    assert_eq!(check_version_overlap(&v_same, &[v1, v_other]), Ok(()));
    assert_eq!(check_version_overlap(&v_other, &[v1, v_same]), Ok(()));
    assert_eq!(check_version_overlap(&v1, &[]), Ok(()));
    // Existing versions are compared with the new one, not each other.
    let v_conflicting = version("v4", &rsa_b, t(0), None);
    assert_eq!(
        check_version_overlap(&v_other, &[v1, v_conflicting]),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Known gaps until the on-curve check (module follow-ups)

#[test]
fn invalid_points_pass_until_the_on_curve_check_lands() {
    // These assertions record today's gap and must flip when the on-curve
    // and canonical-point checks land; the write path must not rely on
    // this module alone until then.
    // P-256 (0, 0) is not on the curve.
    accept(
        json!({"kty": "EC", "kid": "k", "crv": "P-256", "x": b64(&[0; 32]), "y": b64(&[0; 32])}),
    );
    // A P-521 coordinate equal to p = 2^521 - 1 is out of the field.
    let mut p = vec![0xff; 66];
    p[0] = 0x01;
    accept(json!({"kty": "EC", "kid": "k", "crv": "P-521", "x": b64(&p), "y": b64(&p)}));
    // The Ed25519 identity point (y = 1), a small-order point.
    let mut identity = [0; 32];
    identity[0] = 1;
    accept(json!({"kty": "OKP", "kid": "k", "crv": "Ed25519", "x": b64(&identity)}));
}

// ---------------------------------------------------------------------------
// No key material in errors

const MARKER: &str = "LEAKMARKER";

/// A 258-octet odd "modulus" whose base64url text starts with the marker.
fn marked_n() -> String {
    format!("{MARKER}{}B", "A".repeat(333))
}

/// A 32-octet Ed25519 "key" whose base64url text starts with the marker.
fn marked_x() -> String {
    format!("{MARKER}{}", "A".repeat(33))
}

/// The decoded leading octets of the marker as `Debug` would print them in
/// a byte list.
fn marker_byte_lists() -> Vec<String> {
    // "LEAKMARKER" decodes to these leading octets (computed with
    // Python's base64 module).
    let octets = [0x2c, 0x40, 0x0a, 0x30, 0x04, 0x4a, 0x11, 0x14];
    vec![
        format!("{}, {}, {}", octets[0], octets[1], octets[2]),
        format!("{:#x}, {:#x}", octets[0], octets[1]),
        format!("{:02x}{:02x}{:02x}", octets[0], octets[1], octets[2]),
    ]
}

fn assert_clean(text: &str) {
    assert!(!text.contains(MARKER), "leaked the marker: {text}");
    for list in marker_byte_lists() {
        assert!(!text.contains(&list), "leaked key octets: {text}");
    }
}

#[test]
fn marker_octets_are_what_the_leak_check_looks_for() {
    // Ties the hand-computed octets to the test-local encoder.
    assert_eq!(
        b64(&[0x2c, 0x40, 0x0a, 0x30, 0x04, 0x4a, 0x11, 0x14, 0x44]),
        "LEAKMARKERRE"
    );
}

#[test]
fn errors_and_debug_output_never_contain_key_material() {
    let rsa = json!({"kty": "RSA", "kid": "m", "alg": "RS256", "n": marked_n(), "e": "AQAB"});
    let ed = json!({"kty": "OKP", "kid": "m", "crv": "Ed25519", "x": marked_x()});
    let ec = json!({"kty": "EC", "kid": "m", "crv": "P-256", "x": marked_x(), "y": marked_x()});
    // The marked keys pass this module's checks today. They are not real
    // keys (the EC and Ed25519 points are not on their curves), and these
    // fixtures will change when the on-curve check lands.
    let rsa_set = accept(rsa.clone());
    let ed_set = accept(ed.clone());
    let ec_set = accept(ec.clone());
    let mut outputs = vec![
        format!("{rsa_set:?}"),
        format!("{ed_set:?}"),
        format!("{ec_set:?}"),
        format!("{:?}", rsa_set.keys()[0].key()),
        format!("{:#?}", rsa_set.keys()[0]),
    ];
    let failing_sets = vec![
        set_of(vec![with(rsa.clone(), "e", json!("Aw"))]),
        set_of(vec![with(rsa.clone(), "e", json!("AQAC"))]),
        set_of(vec![with(rsa.clone(), "alg", json!("ES256"))]),
        set_of(vec![with(rsa.clone(), "alg", json!("none"))]),
        set_of(vec![with(rsa.clone(), "alg", json!(MARKER))]),
        set_of(vec![with(rsa.clone(), "d", json!(marked_n()))]),
        set_of(vec![with(rsa.clone(), MARKER, json!(marked_n()))]),
        set_of(vec![with(rsa.clone(), &marked_n(), json!(1))]),
        set_of(vec![with(
            rsa.clone(),
            "privateKey",
            json!({"d": marked_n()}),
        )]),
        set_of(vec![with(rsa.clone(), "x5t", json!(marked_x()))]),
        set_of(vec![without(rsa.clone(), "alg")]),
        with(
            set_of(vec![rsa.clone()]),
            MARKER,
            json!({"kty": "oct", "k": marked_n()}),
        ),
        set_of(vec![with(rsa.clone(), "x5c", json!([marked_n()]))]),
        set_of(vec![with(rsa.clone(), "use", json!(MARKER))]),
        set_of(vec![with(rsa.clone(), "key_ops", json!([MARKER]))]),
        set_of(vec![with(rsa.clone(), "kty", json!(MARKER))]),
        set_of(vec![with(rsa.clone(), "kid", json!(format!("{MARKER} ")))]),
        set_of(vec![with(
            rsa.clone(),
            "n",
            json!(format!("{}=", marked_n())),
        )]),
        set_of(vec![with(
            rsa.clone(),
            "n",
            json!(format!("A{}", marked_n())),
        )]),
        set_of(vec![with(
            rsa.clone(),
            "n",
            json!(format!("AA{}", &marked_n()[..340])),
        )]),
        set_of(vec![with(
            ed.clone(),
            "x",
            json!(format!("{}AAAA", marked_x())),
        )]),
        set_of(vec![with(ed.clone(), "crv", json!(MARKER))]),
        set_of(vec![with(
            ec.clone(),
            "y",
            json!(format!("{}AAAA", marked_x())),
        )]),
        set_of(vec![with(ec.clone(), "alg", json!("ES384"))]),
        set_of(vec![rsa.clone(), with(rsa.clone(), "kid", json!("other"))]),
        set_of(vec![rsa.clone(), ed.clone()]),
    ];
    let mut failures = 0;
    for set in &failing_sets {
        if let Err(error) = parse(set) {
            failures += 1;
            outputs.push(error.to_string());
            outputs.push(format!("{error:?}"));
            outputs.push(format!("{error:#?}"));
        }
    }
    // Every set above fails.
    assert_eq!(failures, failing_sets.len());
    // Overlap conflicts between the marked keys.
    let ed_other = accept(with(ed.clone(), "kid", json!("other")));
    for (first, second) in [(&ed_set, &ed_other), (&rsa_set, &ed_set)] {
        let versions = [
            version("v1", first, t(0), None),
            version("v2", second, t(0), None),
        ];
        let error = live_keys(&versions, t(0)).unwrap_err();
        outputs.push(error.to_string());
        outputs.push(format!("{error:?}"));
        let error = check_version_overlap(&versions[1], &versions[..1]).unwrap_err();
        outputs.push(error.to_string());
        outputs.push(format!("{error:?}"));
    }
    let live = [
        version("v1", &rsa_set, t(0), None),
        version("v2", &ed_other, t(0), None),
    ];
    outputs.push(format!("{:?}", live_keys(&live, t(0)).unwrap()));
    outputs.push(format!("{live:?}"));
    for output in &outputs {
        assert_clean(output);
    }
}

#[test]
fn error_text_names_the_member_and_kid() {
    assert_eq!(
        reject(with(rsa_key("k"), "dq", json!("AQAB"))).to_string(),
        "member \"dq\" is a private or symmetric key parameter"
    );
    let error = parse(&set_of(vec![
        rsa_key("k"),
        with(rsa_key("k2"), "x5u", json!("u")),
    ]))
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "JWK set key 1: member \"x5u\" refers to keys or certificates outside the upload"
    );
    let error = parse(&set_of(vec![rsa_key("dup"), p256_key("dup")])).unwrap_err();
    assert_eq!(error.to_string(), "JWK set keys 0 and 1 share kid \"dup\"");
    let map: Map<String, Value> = Map::new();
    assert_eq!(
        parse(&Value::Object(map)).unwrap_err().to_string(),
        "JWK set has no \"keys\" member"
    );
}
