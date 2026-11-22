//! Uploaded JWK Set validation, thumbprints and live-key overlap
//! (`skyoauth_service::jwk`, T11.3). Pure: no database.
//!
//! The thumbprints expected here come from the RFCs (RFC 7638 section 3.1,
//! RFC 8037 appendix A.3) or were computed independently with Python's
//! `hashlib`, never from this crate's output. The P-384 and P-521 keys and
//! the `GENERATED_*` keys were generated with Python's `cryptography`.
//! Every EC and Ed25519 point here, valid or not, was classified in Python
//! (integer arithmetic for the curve equations, OpenSSL through
//! `cryptography` for the valid NIST points), never with this crate.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use skyoauth_service::jwk::{
    Algorithm, Base64urlError, DEFAULT_ALLOWED_ALGORITHMS, JwkError, JwkSet, JwkSetError,
    KEY_REFERENCE_MEMBERS, KeysetVersion, MAX_KEYS, MAX_SET_BYTES, MAX_STORED_BYTES, OverlapError,
    PRIVATE_MEMBERS, PublicKey, ValidatedKeyset, VersionStatus, check_version_overlap, live_keys,
    parse_jwk_set, parse_stored, validate_keyset,
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
// Generated with Python's `cryptography`; thumbprints computed with Python.
// Each entry: crv, x, y (empty for Ed25519), thumbprint.
const GENERATED_KEYS: [(&str, &str, &str, &str); 5] = [
    (
        "P-256",
        "60KU-t7I0SkALarT8sfRB5iNa5QkWCUlbefzbW7OlQw",
        "AB530pP2cpYhadpS5FNwg9m8w4UgWFlJJkxIxFl_MPk",
        "ReTyQj2cWmZjeGr2ceSTROSYokqG3coaxsX6fyD0GBM",
    ),
    (
        "P-384",
        "grHJzJDGmltQdKpdbWc8J6K8CQ9rcHdzq_1P8ranPnKnldwj6Va8pNUE8udBOPuu",
        "-4CGkS9nzqSHR1MZZVBXiZezNmfhj7KSiKVD_8_auTMJ0YEppjlymjZiZ-Mc5nMX",
        "6GkdwWJbxzM_ZGgM_7uKVDrIZ6EgnPtWEXt8IDXdpB0",
    ),
    (
        "P-521",
        "AVdcynxoDq-dnnl3A1dRx1E8ZdkcEcer9dMMH99ywTsYyqS3rPlrG3eQfnwn9uliJ5Xz-f9rXsmwP_W_F0hR4z3O",
        "AWtej0Hf_sO1cXSV4wGCTZsol5liNHVe6TN45mIHVjjhuNjYTb1h-eZfhWFpK8cIV7n-HBEk2_aCYJ9kv2Q_NpVO",
        "HvLzGXbwC4jm7UXDfsm0P9IV7FjLWpoyxyIEaUTElQU",
    ),
    (
        "Ed25519",
        "ncaI80H8hcEwcD8clmapyTEcC448Pq3zYu1UbNiTA1o",
        "",
        "OsWI4tpuT2QevRsi1-CTroBg5C6C5DoQTx8g7Wm2LRY",
    ),
    (
        "Ed25519",
        "IXHSjlZri83ERxwDrU3eUUWKZl2n6f6gIZ9LmQCc3CE",
        "",
        "UEsnB7Cybc4vyBolClBjy0YqbPF6VMtUoIPE3KEkeSM",
    ),
];

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

/// A test-local base64url decoder (canonical unpadded input only),
/// independent of the crate's.
fn unb64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for char in text.bytes() {
        let value = ALPHABET.iter().position(|&a| a == char).expect("base64url") as u32;
        acc = acc << 6 | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits & 0xff) as u8);
        }
    }
    out
}

/// The octets of hexadecimal `text`.
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// An `EC` key of `crv` with these coordinate octets.
fn ec_key(crv: &str, x: &[u8], y: &[u8]) -> Value {
    json!({"kty": "EC", "kid": "k", "crv": crv, "x": b64(x), "y": b64(y)})
}

/// An Ed25519 key with these octets.
fn ed_key(x: &[u8]) -> Value {
    json!({"kty": "OKP", "kid": "k", "crv": "Ed25519", "x": b64(x)})
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
    for (crv, len, x, y) in [
        ("P-256", 32, P256_X, P256_Y),
        ("P-384", 48, P384_X, P384_Y),
        ("P-521", 66, P521_X, P521_Y),
    ] {
        // Real points, cut or extended: the length is checked before the
        // point.
        let (x, y) = (unb64(x), unb64(y));
        let resized = |octets: &[u8], len: usize| {
            let mut octets = octets.to_vec();
            octets.resize(len, 0x5a);
            octets
        };
        let key =
            |x_len: usize, y_len: usize| ec_key(crv, &resized(&x, x_len), &resized(&y, y_len));
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

/// 20 RSA keys of 8192 bits, a 32-octet e, a 128-byte kid and every
/// allowlisted member: the largest valid set, the bound the module docs
/// state.
fn largest_valid_set() -> Value {
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
    set_of(keys)
}

#[test]
fn the_largest_valid_set_is_well_under_the_size_bound() {
    let set = largest_valid_set();
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
// Points: EC on-curve and range, Ed25519 canonical and not small-order.
// Every vector below was classified in Python, not with this crate.

/// The field primes, big-endian hex (FIPS 186-4 appendix D.1.2; the same
/// values as 2^256 - 2^224 + 2^192 + 2^96 - 1, 2^384 - 2^128 - 2^96 + 2^32
/// - 1 and 2^521 - 1, checked in Python).
const NIST_PRIMES: [(&str, &str); 3] = [
    (
        "P-256",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    ),
    (
        "P-384",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    ),
    (
        "P-521",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
];

/// The valid EC keys of this file: crv, x, y.
fn valid_ec_keys() -> Vec<(&'static str, &'static str, &'static str)> {
    let mut keys = vec![
        ("P-256", P256_X, P256_Y),
        ("P-384", P384_X, P384_Y),
        ("P-521", P521_X, P521_Y),
    ];
    keys.extend(
        GENERATED_KEYS
            .iter()
            .filter(|(crv, ..)| *crv != "Ed25519")
            .map(|&(crv, x, y, _)| (crv, x, y)),
    );
    keys
}

/// The big-endian octets of `p - value` for `value < p` (schoolbook
/// subtraction, test-local).
fn negate(p: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = vec![0; p.len()];
    let mut borrow = 0i16;
    for i in (0..p.len()).rev() {
        let mut digit = i16::from(p[i]) - i16::from(value[i]) - borrow;
        borrow = i16::from(digit < 0);
        if digit < 0 {
            digit += 256;
        }
        out[i] = digit as u8;
    }
    assert_eq!(borrow, 0);
    out
}

/// `value` with bit `bit` flipped, counted from the least significant bit
/// of the last octet (big-endian) or of the first octet (little-endian).
fn flip(value: &[u8], bit: usize, big_endian: bool) -> Vec<u8> {
    let mut out = value.to_vec();
    let index = if big_endian {
        value.len() - 1 - bit / 8
    } else {
        bit / 8
    };
    out[index] ^= 1 << (bit % 8);
    out
}

#[test]
fn generated_keys_are_accepted_with_their_thumbprints() {
    for (crv, x, y, expected) in GENERATED_KEYS {
        let jwk = if crv == "Ed25519" {
            json!({"kty": "OKP", "kid": "k", "crv": crv, "x": x})
        } else {
            json!({"kty": "EC", "kid": "k", "crv": crv, "x": x, "y": y})
        };
        assert_eq!(
            accept(jwk).keys()[0].thumbprint().as_str(),
            expected,
            "{crv} {x}"
        );
    }
}

#[test]
fn one_flipped_coordinate_bit_takes_an_ec_point_off_the_curve() {
    for (crv, x, y) in valid_ec_keys() {
        let (x, y) = (unb64(x), unb64(y));
        accept(ec_key(crv, &x, &y));
        // The lowest bit of x, then of y (both stay below p).
        assert_eq!(
            reject(ec_key(crv, &flip(&x, 0, true), &y)),
            JwkError::PointNotOnCurve,
            "{crv} x"
        );
        assert_eq!(
            reject(ec_key(crv, &x, &flip(&y, 0, true))),
            JwkError::PointNotOnCurve,
            "{crv} y"
        );
    }
}

#[test]
fn the_negated_ec_point_is_accepted() {
    // (x, p - y) is the point's negative, on the curve too.
    for (crv, x, y) in valid_ec_keys() {
        let p = unhex(NIST_PRIMES.iter().find(|(name, _)| *name == crv).unwrap().1);
        let (x, y) = (unb64(x), unb64(y));
        accept(ec_key(crv, &x, &negate(&p, &y)));
    }
}

#[test]
fn ec_coordinates_must_be_below_p() {
    for (crv, p) in NIST_PRIMES {
        let p = unhex(p);
        let (_, x, y) = valid_ec_keys()
            .into_iter()
            .find(|(name, ..)| *name == crv)
            .unwrap();
        let (x, y) = (unb64(x), unb64(y));
        let all_ff = vec![0xff; p.len()];
        for (key, member) in [
            (ec_key(crv, &p, &y), "x"),
            (ec_key(crv, &x, &p), "y"),
            (ec_key(crv, &p, &p), "x"),
            (ec_key(crv, &all_ff, &all_ff), "x"),
            (ec_key(crv, &x, &all_ff), "y"),
        ] {
            assert_eq!(
                reject(key),
                JwkError::CoordinateOutOfRange { member },
                "{crv} {member}"
            );
        }
    }
    // A P-521 coordinate of 66 octets may exceed p by a valid value: x + p
    // and y + p (computed in Python) are refused, not reduced.
    let y = unb64(P521_Y);
    let x_plus_p = unb64(
        "AiZcq9r597gtjnSV4d4WBjMUaPF9ywO2R0MvC2vA2xTBOJ2D6SO7x6XIp1pV_hREE01OEgCbh95eah8S6-PEEiuJ",
    );
    assert_eq!(
        reject(ec_key("P-521", &x_plus_p, &y)),
        JwkError::CoordinateOutOfRange { member: "x" }
    );
    let y_plus_p = unb64(
        "A5upTVy2snFxihMve6JA6-3G5VHhoDDZiGLQibc6EqQTFhsZqlN7SUsc-5NHRahHPDnLMGa-R2m_5laWIh7PH4Yz",
    );
    assert_eq!(
        reject(ec_key("P-521", &unb64(P521_X), &y_plus_p)),
        JwkError::CoordinateOutOfRange { member: "y" }
    );
}

#[test]
fn ec_points_at_the_ends_of_the_field() {
    // Points with x = 0 or x = p - 1, where they exist (found in Python;
    // OpenSSL accepts each), are accepted: the bound is strict at p only.
    for (crv, x, y) in [
        (
            "P-256",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ZkhceA4vg9ckM71dhKBrtlQcKvMdrocXKL-FahdPk_Q",
        ),
        (
            "P-384",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffe",
            "jN6tu9BJEaPBkx4m3z-mQ53KnH6yhvvUb8MZ8OK7eAIyuvV4JfwMGRKtov7-hAJM",
        ),
        (
            "P-384",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "wwZhD7CuWhWc9FwGBp8ipsXrNkHGAtQt6ixLT3VVB5NAbYDSuRrVT5BIvUh68a3h",
        ),
        (
            "P-521",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
            "ANklT9-ABJasszeQsQPF7p-sEoMv5UbGMiJbD3_OPaRXSxqHm2I9ci-o_DTV_CqHMarWkamou4tVTJWgUdaqUFrP",
        ),
        (
            "P-521",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "AS3xNgFZSog-8tk15Eu5C_TWYZt05Sr3VS-XdpARwHGetDnPqyqI1A_lmivtH0NVcWmi0KLM0oDGB7krv1H_4LB4",
        ),
    ] {
        accept(ec_key(crv, &unhex(x), &unb64(y)));
    }
    // (0, 0), (p - 1, 0) and (p - 1, 1) are on no curve here.
    for (crv, p) in NIST_PRIMES {
        let p = unhex(p);
        let zero = vec![0; p.len()];
        let mut one = zero.clone();
        *one.last_mut().unwrap() = 1;
        let p_minus_1 = negate(&p, &one);
        for (x, y) in [(&zero, &zero), (&p_minus_1, &zero), (&p_minus_1, &one)] {
            assert_eq!(
                reject(ec_key(crv, x, y)),
                JwkError::PointNotOnCurve,
                "{crv}"
            );
        }
    }
}

/// The eight Ed25519 points of order dividing 8, little-endian hex (found
/// in Python by multiplying random points by the group order, each checked
/// with `8P` the identity): y = 1 (order 1), y = p - 1 (order 2), y = 0
/// with both signs (order 4) and y = y8, p - y8 with both signs (order 8).
const ED25519_SMALL_ORDER: [&str; 8] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
];

#[test]
fn each_small_order_ed25519_point_is_refused() {
    for encoded in ED25519_SMALL_ORDER {
        assert_eq!(
            reject(ed_key(&unhex(encoded))),
            JwkError::Ed25519SmallOrder,
            "{encoded}"
        );
    }
}

#[test]
fn noncanonical_ed25519_encodings_are_refused() {
    for encoded in [
        // x = 0 with the sign bit set: y = 1 and y = p - 1.
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        // y = p, p + 1 (with either sign), 2^255 - 1 (with either sign).
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        assert_eq!(
            reject(ed_key(&unhex(encoded))),
            JwkError::Ed25519NotCanonical,
            "{encoded}"
        );
    }
}

#[test]
fn ed25519_bit_flips_and_negation() {
    // For each valid key, the lowest bit whose flip leaves a y with no x
    // (x^2 not a square; found in Python). Flipping the sign bit gives the
    // negated point, which is valid.
    for (x, bit) in [
        (ED25519_X, 0),
        (GENERATED_KEYS[3].1, 1),
        (GENERATED_KEYS[4].1, 0),
    ] {
        let x = unb64(x);
        accept(ed_key(&x));
        assert_eq!(
            reject(ed_key(&flip(&x, bit, false))),
            JwkError::PointNotOnCurve,
            "bit {bit}"
        );
        accept(ed_key(&flip(&x, 255, false)));
    }
}

#[test]
fn ed25519_points_with_a_torsion_component_are_accepted() {
    // The RFC 8037 key plus an order-8 point (computed in Python): not
    // small-order, so accepted. Cofactor handling is the verifier's
    // (T11.7, strict verification), and such a key is not claimed safe.
    accept(json!({
        "kty": "OKP", "kid": "k", "crv": "Ed25519",
        "x": "kVgxKpqNbjs0yJHW1hRE-LghHFEX660VvbC9aLB-AkU"
    }));
}

#[test]
fn invalid_points_are_refused() {
    // The points the length-only checks used to accept.
    // P-256 (0, 0) is not on the curve.
    assert_eq!(
        reject(ec_key("P-256", &[0; 32], &[0; 32])),
        JwkError::PointNotOnCurve
    );
    // A P-521 coordinate equal to p = 2^521 - 1 is out of the field.
    let mut p = vec![0xff; 66];
    p[0] = 0x01;
    assert_eq!(
        reject(ec_key("P-521", &p, &p)),
        JwkError::CoordinateOutOfRange { member: "x" }
    );
    // The Ed25519 identity point (y = 1), a small-order point.
    let mut identity = [0; 32];
    identity[0] = 1;
    assert_eq!(reject(ed_key(&identity)), JwkError::Ed25519SmallOrder);
}

// ---------------------------------------------------------------------------
// No key material in errors

const MARKER: &str = "LEAKMARKER";

/// A 258-octet odd "modulus" whose base64url text starts with the marker.
fn marked_n() -> String {
    format!("{MARKER}{}B", "A".repeat(333))
}

/// A 32-octet Ed25519 key whose base64url text starts with the marker: a
/// valid point, not small-order (checked in Python).
fn marked_x() -> String {
    format!("{MARKER}{}", "A".repeat(33))
}

/// A marked 32-octet Ed25519 encoding that decodes to no point (checked in
/// Python).
fn marked_undecodable_x() -> String {
    format!("{MARKER}{}Q", "A".repeat(32))
}

/// A P-256 `x` whose base64url text starts with the marker, and the `y`
/// that makes it a point (found in Python; OpenSSL accepts the point).
fn marked_ec_x() -> String {
    format!("{MARKER}{}U", "A".repeat(32))
}
const MARKED_EC_Y: &str = "ut94dV84kk2hQ-8EJDYxIGDXqke9cfnKTmiISCnlUkw";

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
    let ec = json!({"kty": "EC", "kid": "m", "crv": "P-256", "x": marked_ec_x(), "y": MARKED_EC_Y});
    // The marked keys pass every check: the EC and Ed25519 keys are points
    // of their curves. The RSA key is not a real modulus (unchecked).
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
    // The point checks, with marked input where the refused value can hold
    // the marker.
    let point_failures = [
        (
            with(ec.clone(), "y", json!(marked_ec_x())),
            JwkError::PointNotOnCurve,
        ),
        (
            with(ed.clone(), "x", json!(marked_undecodable_x())),
            JwkError::PointNotOnCurve,
        ),
        (
            json!({"kty": "EC", "kid": "m", "crv": "P-521",
                "x": format!("{MARKER}{}", "A".repeat(78)), "y": P521_Y}),
            JwkError::CoordinateOutOfRange { member: "x" },
        ),
    ];
    for (jwk, expected) in &point_failures {
        assert_eq!(&reject(jwk.clone()), expected);
    }
    let failing_sets: Vec<Value> = failing_sets
        .into_iter()
        .chain(point_failures.into_iter().map(|(jwk, _)| set_of(vec![jwk])))
        .collect();
    // A noncanonical or small-order Ed25519 key cannot hold the marker (its
    // octets are fixed): the error text must not hold its base64url or hex
    // text instead.
    for (encoded, expected) in [
        (
            "0100000000000000000000000000000000000000000000000000000000000080",
            JwkError::Ed25519NotCanonical,
        ),
        (
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            JwkError::Ed25519NotCanonical,
        ),
        (
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            JwkError::Ed25519SmallOrder,
        ),
    ] {
        let octets = unhex(encoded);
        let jwk = with(ed.clone(), "x", json!(b64(&octets)));
        assert_eq!(reject(jwk.clone()), expected);
        let error = parse(&set_of(vec![jwk])).unwrap_err();
        for text in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert_clean(&text);
            assert!(!text.contains(&b64(&octets)), "{text}");
            assert!(!text.contains(&encoded[..6]), "{text}");
            assert!(
                !text.contains(&format!("{}, {}, {}", octets[0], octets[1], octets[2])),
                "{text}"
            );
        }
    }
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
    assert_eq!(
        reject(ec_key("P-256", &[0; 32], &[0; 32])).to_string(),
        "the key is not a point of its curve"
    );
    assert_eq!(
        reject(ec_key("P-256", &[0xff; 32], &[0; 32])).to_string(),
        "member \"x\" is not below the curve's field prime"
    );
    assert_eq!(
        reject(ed_key(&[0xff; 32])).to_string(),
        "the Ed25519 key is not canonically encoded"
    );
    assert_eq!(
        reject(ed_key(&[0; 32])).to_string(),
        "the Ed25519 key is a small-order point"
    );
    let error = parse(&set_of(vec![rsa_key("dup"), p256_key("dup")])).unwrap_err();
    assert_eq!(error.to_string(), "JWK set keys 0 and 1 share kid \"dup\"");
    let map: Map<String, Value> = Map::new();
    assert_eq!(
        parse(&Value::Object(map)).unwrap_err().to_string(),
        "JWK set has no \"keys\" member"
    );
}

// ---------------------------------------------------------------------------
// Projection, fingerprint and stored sets

/// The set whose projection and fingerprint are pinned: the RFC 7638 RSA
/// key with `alg`, the RFC 7517 P-256 key without `alg` and the RFC 8037
/// Ed25519 key with `alg`, the first two with members the projection drops.
fn fixed_set() -> Value {
    set_of(vec![
        with(
            with(rsa_key("rsa"), "use", json!("sig")),
            "key_ops",
            json!(["verify"]),
        ),
        with(
            with(p256_key("ec"), "x5t", json!(b64(&[0x11; 20]))),
            "x5t#S256",
            json!(b64(&[0x22; 32])),
        ),
        with(ed25519_key("ed"), "alg", json!("EdDSA")),
    ])
}

/// The projection of [`fixed_set`], written by hand: keys sorted by `kid`
/// (`ec`, `ed`, `rsa`), members sorted.
fn fixed_projection() -> String {
    format!(
        concat!(
            r#"{{"keys":[{{"crv":"P-256","kid":"ec","kty":"EC","x":"{}","y":"{}"}},"#,
            r#"{{"alg":"EdDSA","crv":"Ed25519","kid":"ed","kty":"OKP","x":"{}"}},"#,
            r#"{{"alg":"RS256","e":"AQAB","kid":"rsa","kty":"RSA","n":"{}"}}]}}"#,
        ),
        P256_X, P256_Y, ED25519_X, RSA_N
    )
}

/// The fingerprint of [`fixed_projection`], computed with Python
/// (`json.dumps` with `sort_keys=True` and `separators=(",", ":")` over the
/// keys sorted by `kid`, then `hashlib.sha256` and unpadded
/// `base64.urlsafe_b64encode`), never from this crate.
const FIXED_FINGERPRINT: &str = "kmw_flxprrqx5hAs8p0vEVuCoTPn9KA9a_dZ9kH1Tfk";

/// The members a projected key may have.
const PROJECTION_MEMBERS: [&str; 8] = ["alg", "crv", "e", "kid", "kty", "n", "x", "y"];

fn validate(set: &Value) -> ValidatedKeyset {
    validate_keyset(set, DEFAULT_ALLOWED_ALGORITHMS).expect("accepted")
}

/// `value` as JSON text the way `jsonb` might give it back: every object's
/// members in reverse order, with spaces after `:` and `,`.
fn jsonb_like(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let members: Vec<String> = map
                .iter()
                .rev()
                .map(|(name, value)| format!("{}: {}", json!(name), jsonb_like(value)))
                .collect();
            format!("{{{}}}", members.join(", "))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(jsonb_like).collect();
            format!("[{}]", items.join(", "))
        }
        other => other.to_string(),
    }
}

#[test]
fn projection_and_fingerprint_of_a_fixed_set_are_pinned() {
    let validated = validate(&fixed_set());
    assert_eq!(validated.public_json(), fixed_projection());
    assert_eq!(validated.set().to_public_json(), fixed_projection());
    assert_eq!(validated.fingerprint().as_str(), FIXED_FINGERPRINT);
    assert_eq!(validated.fingerprint().to_string(), FIXED_FINGERPRINT);
    // The same set and keys as the plain parse.
    let set = parse(&fixed_set()).unwrap();
    assert_eq!(validated.set(), &set);
    assert_eq!(validated.keys(), set.keys());
    // Stable: the same upload gives the same projection and fingerprint.
    assert_eq!(validate(&fixed_set()), validated);
    let stored = parse_stored(fixed_projection()).unwrap();
    assert_eq!(stored.fingerprint().as_str(), FIXED_FINGERPRINT);
    assert_eq!(stored.public_json(), fixed_projection());
}

fn round_trip_sets() -> Vec<Value> {
    let generated: Vec<Value> = GENERATED_KEYS
        .iter()
        .enumerate()
        .map(|(i, (crv, x, y, _))| {
            if y.is_empty() {
                json!({"kty": "OKP", "kid": format!("g{i}"), "crv": crv, "x": x})
            } else {
                json!({"kty": "EC", "kid": format!("g{i}"), "crv": crv, "x": x, "y": y})
            }
        })
        .collect();
    vec![
        fixed_set(),
        set_of(vec![rsa_key("k")]),
        set_of(vec![p384_key("a:b/c+d=e~f"), p521_key("b")]),
        set_of(vec![
            with(p256_key("a"), "alg", json!("ES256")),
            with(rsa_key("b"), "alg", json!("PS256")),
            with(p384_key("c"), "alg", json!("ES384")),
            with(p521_key("d"), "alg", json!("ES512")),
        ]),
        set_of(generated),
        set_of(distinct_rsa_keys(MAX_KEYS)),
        largest_valid_set(),
    ]
}

#[test]
fn full_parse_projection_and_stored_parse_round_trip() {
    for set in round_trip_sets() {
        let validated = validate(&set);
        let projection = validated.public_json();
        let stored = parse_stored(projection).expect("stored projection accepted");
        // Same keys in the same order (sorted by kid), same projection,
        // same fingerprint.
        assert_eq!(stored.keys(), validated.keys());
        assert!(
            validated
                .keys()
                .windows(2)
                .all(|pair| pair[0].kid() < pair[1].kid())
        );
        assert_eq!(stored.public_json(), projection);
        assert_eq!(stored.fingerprint(), validated.fingerprint());
        for key in validated.keys() {
            assert_eq!(stored.get(key.kid().as_str()), Some(key));
        }
        // As bytes, an owned string or owned bytes.
        assert_eq!(parse_stored(projection.as_bytes()).unwrap(), stored);
        let owned: (String, Vec<u8>) = (projection.into(), projection.into());
        assert_eq!(parse_stored(owned.0).unwrap(), stored);
        assert_eq!(parse_stored(owned.1).unwrap(), stored);
        // As jsonb might give it back: reordered and spaced, the same.
        let value: Value = serde_json::from_str(projection).unwrap();
        let reordered = jsonb_like(&value);
        assert_ne!(reordered, projection);
        assert_eq!(parse_stored(&reordered).unwrap(), stored);
        // A projection is itself an accepted upload, with the same result.
        assert_eq!(validate(&value), validated);
        // No whitespace, only the projection's members, sorted.
        assert!(!projection.contains(char::is_whitespace));
        for key in value["keys"].as_array().unwrap() {
            let members: Vec<&str> = key
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert!(
                members.iter().all(|m| PROJECTION_MEMBERS.contains(m)),
                "{members:?}"
            );
        }
        assert!(projection.len() <= serde_json::to_string(&set).unwrap().len());
    }
}

#[test]
fn projection_member_order_is_lexicographic() {
    // The member names of each key, in the order they appear in the text.
    let projection = validate(&fixed_set()).public_json().to_owned();
    for key in projection
        .trim_start_matches(r#"{"keys":[{"#)
        .trim_end_matches("}]}")
        .split("},{")
    {
        let names: Vec<&str> = key
            .split(',')
            .map(|member| member.split(':').next().unwrap().trim_matches('"'))
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }
}

#[test]
fn fingerprint_changes_when_any_member_changes() {
    let base = validate(&fixed_set());
    let keys = fixed_set()["keys"].as_array().unwrap().clone();
    let (rsa, ec, ed) = (keys[0].clone(), keys[1].clone(), keys[2].clone());
    let three = |rsa: Value, ec: Value, ed: Value| set_of(vec![rsa, ec, ed]);
    let variants = vec![
        three(
            with(rsa.clone(), "kid", json!("rsa2")),
            ec.clone(),
            ed.clone(),
        ),
        three(
            rsa.clone(),
            with(ec.clone(), "kid", json!("ec2")),
            ed.clone(),
        ),
        three(
            rsa.clone(),
            ec.clone(),
            with(ed.clone(), "kid", json!("ed2")),
        ),
        three(
            with(rsa.clone(), "alg", json!("PS256")),
            ec.clone(),
            ed.clone(),
        ),
        // 65539, another valid exponent.
        three(
            with(rsa.clone(), "e", json!("AQAD")),
            ec.clone(),
            ed.clone(),
        ),
        three(
            with(rsa.clone(), "n", json!(b64(&modulus(256, 0x80, 1)))),
            ec.clone(),
            ed.clone(),
        ),
        three(
            rsa.clone(),
            with(ec.clone(), "alg", json!("ES256")),
            ed.clone(),
        ),
        three(
            rsa.clone(),
            with(
                with(ec.clone(), "x", json!(GENERATED_KEYS[0].1)),
                "y",
                json!(GENERATED_KEYS[0].2),
            ),
            ed.clone(),
        ),
        three(rsa.clone(), ec.clone(), without(ed.clone(), "alg")),
        three(
            rsa.clone(),
            ec.clone(),
            with(ed.clone(), "x", json!(GENERATED_KEYS[3].1)),
        ),
        // One key fewer, one key more.
        set_of(vec![rsa.clone(), ec.clone()]),
        set_of(vec![rsa.clone(), ec.clone(), ed.clone(), p384_key("p384")]),
    ];
    let mut seen = HashSet::from([base.fingerprint().clone()]);
    for variant in &variants {
        let validated = validate(variant);
        assert_eq!(validated.fingerprint().as_str().len(), 43);
        assert!(
            seen.insert(validated.fingerprint().clone()),
            "fingerprint unchanged or repeated: {variant}"
        );
        assert_eq!(validate(variant).fingerprint(), validated.fingerprint());
    }
    // The same keys in another order give the same bytes and fingerprint.
    let reordered = validate(&set_of(vec![ec.clone(), rsa.clone(), ed.clone()]));
    assert_eq!(reordered.public_json(), base.public_json());
    assert_eq!(reordered.fingerprint(), base.fingerprint());
    // The members the projection drops do not change it.
    for (index, member) in [(0, "use"), (0, "key_ops"), (1, "x5t"), (1, "x5t#S256")] {
        let mut set = fixed_set();
        set["keys"][index].as_object_mut().unwrap().remove(member);
        assert_eq!(validate(&set).fingerprint(), base.fingerprint(), "{member}");
    }
}

#[test]
fn stored_parse_refuses_what_the_full_parse_refuses_for_shape_size_and_members() {
    let mut cases: Vec<Value> = PRIVATE_MEMBERS
        .iter()
        .map(|member| set_of(vec![with(p256_key("k"), member, json!(P256_D))]))
        .collect();
    cases.extend(
        KEY_REFERENCE_MEMBERS
            .iter()
            .map(|member| set_of(vec![with(rsa_key("k"), member, json!("u"))])),
    );
    cases.extend([
        // Unexpected members, in a key and in the set.
        set_of(vec![with(rsa_key("k"), "foo", json!("x"))]),
        set_of(vec![with(p256_key("k"), "n", json!(RSA_N))]),
        set_of(vec![with(ed25519_key("k"), "y", json!(P256_Y))]),
        with(set_of(vec![rsa_key("k")]), "pad", json!("")),
        // Size and shape.
        set_of_size(MAX_SET_BYTES + 1),
        json!([rsa_key("k")]),
        json!({}),
        json!({"keys": {}}),
        json!({"keys": []}),
        json!({"keys": [rsa_key("k"), "AQAB"]}),
        set_of(distinct_rsa_keys(MAX_KEYS + 1)),
        // Missing alg for RSA, and the other alg rules.
        set_of(vec![without(rsa_key("k"), "alg")]),
        set_of(vec![with(rsa_key("k"), "alg", json!("ES256"))]),
        set_of(vec![with(rsa_key("k"), "alg", json!("none"))]),
        set_of(vec![with(rsa_key("k"), "alg", json!("HS256"))]),
        set_of(vec![with(rsa_key("k"), "alg", json!("RS384"))]),
        set_of(vec![with(p256_key("k"), "alg", json!("ES384"))]),
        // Duplicate kid, one key under two kids.
        set_of(vec![rsa_key("dup"), p256_key("dup")]),
        set_of(vec![p256_key("a"), p256_key("b")]),
        // Lengths, encodings and RSA bounds.
        set_of(vec![ec_key("P-256", &[1; 31], &[1; 32])]),
        set_of(vec![ed_key(&[1; 33])]),
        set_of(vec![with(p256_key("k"), "x5t", json!(b64(&[0x11; 19])))]),
        set_of(vec![with(rsa_key("k"), "n", json!(format!("{RSA_N}=")))]),
        set_of(vec![rsa_with("k", &modulus(255, 0x80, 0), &[1, 0, 1])]),
        set_of(vec![rsa_with("k", &modulus(256, 0x80, 0), &[3])]),
        // Members: kid, use, key_ops, kty, crv.
        set_of(vec![without(rsa_key("k"), "kid")]),
        set_of(vec![with(rsa_key("k"), "kid", json!("a b"))]),
        set_of(vec![with(rsa_key("k"), "use", json!("enc"))]),
        set_of(vec![with(rsa_key("k"), "key_ops", json!(["sign"]))]),
        set_of(vec![json!({"kty": "oct", "kid": "k"})]),
        set_of(vec![with(p256_key("k"), "crv", json!("secp256k1"))]),
    ]);
    for set in &cases {
        let full = parse(set).expect_err("the full parse refuses it");
        assert_eq!(parse_stored(set.to_string()), Err(full.clone()), "{full}");
        assert_eq!(parse_stored(jsonb_like(set)), Err(full), "jsonb-like");
    }
    // Text that is not JSON.
    for text in [
        &b""[..],
        b"{",
        b"{\"keys\":[}",
        b"\xef\xbb\xbf{\"keys\":[]}",
        b"\xff\xfe",
    ] {
        assert_eq!(parse_stored(text), Err(JwkSetError::NotJson));
    }
    assert_eq!(
        JwkSetError::NotJson.to_string(),
        "stored JWK set is not JSON"
    );
}

#[test]
fn stored_size_is_measured_on_the_parsed_value() {
    // Whitespace past the bound does not count, as for an upload.
    let set = set_of(vec![rsa_key("k")]);
    let text = format!(
        "{}{}",
        serde_json::to_string(&set).unwrap(),
        " ".repeat(MAX_SET_BYTES)
    );
    assert_eq!(
        parse_stored(&text).unwrap().public_json(),
        validate(&set).public_json()
    );
}

#[test]
fn stored_parse_ignores_the_allowed_set() {
    // Stored under a wider allowed set, read whatever the allowed set now
    // is: the allowed set is applied at write and at verification.
    let set = set_of(vec![rsa_key("r"), p256_key("e")]);
    assert_eq!(
        parse_jwk_set(&set, &[Algorithm::Es256]),
        Err(JwkSetError::Key {
            index: 0,
            error: JwkError::AlgorithmNotAllowed(Algorithm::Rs256)
        })
    );
    let projection = validate(&set).public_json().to_owned();
    assert_eq!(parse_stored(&projection).unwrap().keys().len(), 2);
}

#[test]
fn point_invalid_keys_are_accepted_by_the_stored_parse_only() {
    // The documented difference: parse_stored runs no point arithmetic.
    let mut p521 = vec![0xff; 66];
    p521[0] = 0x01;
    let mut identity = [0; 32];
    identity[0] = 1;
    let (p256_x, p256_y) = (unb64(P256_X), unb64(P256_Y));
    let cases = [
        (
            ec_key("P-256", &[0; 32], &[0; 32]),
            JwkError::PointNotOnCurve,
        ),
        (
            ec_key("P-256", &flip(&p256_x, 0, true), &p256_y),
            JwkError::PointNotOnCurve,
        ),
        (
            ec_key("P-521", &p521, &p521),
            JwkError::CoordinateOutOfRange { member: "x" },
        ),
        (
            ed_key(&flip(&unb64(ED25519_X), 0, false)),
            JwkError::PointNotOnCurve,
        ),
        (ed_key(&[0xff; 32]), JwkError::Ed25519NotCanonical),
        (ed_key(&identity), JwkError::Ed25519SmallOrder),
    ];
    for (jwk, error) in cases {
        let set = set_of(vec![jwk]);
        assert_eq!(
            validate_keyset(&set, DEFAULT_ALLOWED_ALGORITHMS),
            Err(JwkSetError::Key { index: 0, error })
        );
        let stored = parse_stored(set.to_string()).expect("no point checks");
        assert_eq!(stored.keys().len(), 1);
        assert!(stored.get("k").is_some());
        assert!(stored.get("K").is_none());
        // Its projection reads back the same.
        assert_eq!(parse_stored(stored.public_json()).unwrap(), stored);
    }
}

#[test]
fn projection_never_holds_private_members() {
    // An upload with a private member is refused, so it has no projection.
    for member in PRIVATE_MEMBERS {
        for jwk in [p256_key("k"), ed25519_key("k"), rsa_key("k")] {
            assert_eq!(
                validate_keyset(
                    &set_of(vec![with(jwk, member, json!(P256_D))]),
                    DEFAULT_ALLOWED_ALGORITHMS
                ),
                Err(JwkSetError::Key {
                    index: 0,
                    error: JwkError::PrivateMember(member)
                })
            );
        }
    }
    assert_eq!(
        validate_keyset(
            &set_of(vec![with(ed25519_key("k"), "d", json!(ED25519_D))]),
            DEFAULT_ALLOWED_ALGORITHMS
        ),
        Err(JwkSetError::Key {
            index: 0,
            error: JwkError::PrivateMember("d")
        })
    );
    // An accepted projection holds only the projection's members, and
    // none of the dropped ones even when uploaded.
    for set in round_trip_sets() {
        let value: Value = serde_json::from_str(validate(&set).public_json()).unwrap();
        for key in value["keys"].as_array().unwrap() {
            for member in key.as_object().unwrap().keys() {
                assert!(!PRIVATE_MEMBERS.contains(&member.as_str()), "{member}");
                assert!(PROJECTION_MEMBERS.contains(&member.as_str()), "{member}");
            }
        }
    }
}

#[test]
fn projection_types_and_stored_errors_never_print_key_material() {
    let rsa = json!({"kty": "RSA", "kid": "r", "alg": "RS256", "n": marked_n(), "e": "AQAB"});
    let ed = json!({"kty": "OKP", "kid": "o", "crv": "Ed25519", "x": marked_x()});
    let ec = json!({"kty": "EC", "kid": "e", "crv": "P-256", "x": marked_ec_x(), "y": MARKED_EC_Y});
    let validated = validate(&set_of(vec![rsa.clone(), ed.clone(), ec.clone()]));
    // The projection does hold the key material; the Debug output does not.
    assert!(validated.public_json().contains(MARKER));
    let stored = parse_stored(validated.public_json()).unwrap();
    let mut outputs = vec![
        format!("{validated:?}"),
        format!("{validated:#?}"),
        format!("{stored:?}"),
        format!("{stored:#?}"),
        format!("{:?}", validated.fingerprint()),
    ];
    let failing = [
        set_of(vec![with(rsa.clone(), "d", json!(marked_n()))]),
        set_of(vec![with(rsa.clone(), MARKER, json!(marked_n()))]),
        set_of(vec![with(rsa.clone(), "alg", json!(MARKER))]),
        set_of(vec![with(ed.clone(), "crv", json!(MARKER))]),
        set_of(vec![with(
            ed.clone(),
            "x",
            json!(format!("{}AAAA", marked_x())),
        )]),
        with(set_of(vec![ec.clone()]), MARKER, json!(1)),
    ];
    for set in &failing {
        let error = parse_stored(set.to_string()).unwrap_err();
        outputs.push(error.to_string());
        outputs.push(format!("{error:?}"));
    }
    let error = parse_stored(format!("{{\"keys\":[\"{MARKER}")).unwrap_err();
    assert_eq!(error, JwkSetError::NotJson);
    outputs.push(error.to_string());
    outputs.push(format!("{error:?}"));
    for output in &outputs {
        assert_clean(output);
    }
}

fn kids_of(keys: &[skyoauth_service::jwk::PublicJwk]) -> Vec<&str> {
    keys.iter().map(|key| key.kid().as_str()).collect()
}

#[test]
fn keys_are_sorted_by_kid_whatever_the_input_order() {
    let keys = fixed_set()["keys"].as_array().unwrap().clone();
    let base = validate(&fixed_set());
    assert_eq!(kids_of(base.keys()), ["ec", "ed", "rsa"]);
    // Every permutation of the three keys: the same bytes, fingerprint and
    // key order, in JwkSet, ValidatedKeyset and StoredKeyset alike.
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let set = set_of(order.iter().map(|&i| keys[i].clone()).collect());
        let validated = validate(&set);
        assert_eq!(validated.public_json(), fixed_projection(), "{order:?}");
        assert_eq!(validated.fingerprint().as_str(), FIXED_FINGERPRINT);
        assert_eq!(validated, base);
        assert_eq!(kids_of(parse(&set).unwrap().keys()), ["ec", "ed", "rsa"]);
        // A stored value in that order reads back sorted.
        let stored = parse_stored(set.to_string()).unwrap();
        assert_eq!(kids_of(stored.keys()), ["ec", "ed", "rsa"]);
        assert_eq!(stored.keys(), base.keys());
        assert_eq!(stored.public_json(), fixed_projection());
        assert_eq!(stored.fingerprint().as_str(), FIXED_FINGERPRINT);
    }
    // Byte order, not case-insensitive or numeric: "B" < "a" and
    // "k10" < "k9".
    let set = set_of(vec![
        p256_key("a"),
        p384_key("k9"),
        ed25519_key("B"),
        p521_key("k10"),
    ]);
    assert_eq!(kids_of(validate(&set).keys()), ["B", "a", "k10", "k9"]);
}

#[test]
fn stored_input_is_bounded_before_parsing() {
    assert_eq!(MAX_STORED_BYTES, 4 * MAX_SET_BYTES);
    let set = set_of(vec![rsa_key("k")]);
    let compact = serde_json::to_string(&set).unwrap();
    let padded = |len: usize| format!("{compact}{}", " ".repeat(len - compact.len()));
    // At the limit: parsed, and valid.
    let at_limit = padded(MAX_STORED_BYTES);
    assert_eq!(at_limit.len(), MAX_STORED_BYTES);
    assert_eq!(
        parse_stored(&at_limit).unwrap().public_json(),
        validate(&set).public_json()
    );
    // One byte over: refused.
    let over = padded(MAX_STORED_BYTES + 1);
    assert_eq!(parse_stored(&over), Err(JwkSetError::TooLarge));
    // Refused before the parse: text that is not JSON is TooLarge, not
    // NotJson, once over the limit.
    assert_eq!(
        parse_stored("{".repeat(MAX_STORED_BYTES)),
        Err(JwkSetError::NotJson)
    );
    assert_eq!(
        parse_stored("{".repeat(MAX_STORED_BYTES + 1)),
        Err(JwkSetError::TooLarge)
    );
}
