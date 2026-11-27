//! Known answers for `security::wire_fixture::key`, the canonical public
//! identities of the A22 and A49 wire tests. They test a helper of the
//! tests, not the service, so they are not scenario tests: no name here
//! matches `a\d\d_`, and no stage of `tests/conformance/scenarios.toml`
//! lists them (layout §3). They need no server and no database; they run
//! in the `pg` target, the one CI runs.
//!
//! `identity::canonical_public_identity` refuses a DER
//! `SubjectPublicKeyInfo` that is malformed, not the one form of Ed25519 or
//! P-256, or not a valid key, but a helper that ignored its seed, or derived
//! another valid key from it, would still hand the tests valid identities.
//! The literals below were computed once from the
//! helper; they are also the SHA-256 of the DER `SubjectPublicKeyInfo`
//! that OpenSSL exports for the Ed25519 key with the same secret.

use skyoauth_service::identity::PUBLIC_IDENTITY_PREFIX;

use crate::security::wire_fixture::key;

/// `key(1)`: the Ed25519 key with secret `[1; 32]`.
const KEY_1: &str = "spki-sha256:fd110d301d2f077de1414b8f99f441b1403fab207b2052fbd2c065e4ee8e7dc2";
/// `key(2)`: the Ed25519 key with secret `[2; 32]`.
const KEY_2: &str = "spki-sha256:47dea58ea00fae9417ee19d76755bfef690899021132effb04fe1f9e4f0c8059";

#[test]
fn wire_fixture_key_known_answers() {
    assert_eq!(key(1), KEY_1);
    assert_eq!(key(2), KEY_2);
    assert_ne!(key(1), key(2));
}

/// The pinned identities are canonical (the prefix, then 64 lowercase hex
/// digits), and no other spelling of the same digest is the helper's
/// output.
#[test]
fn wire_fixture_key_answers_are_canonical() {
    for (seed, pin) in [(1, KEY_1), (2, KEY_2)] {
        let hex = pin
            .strip_prefix(PUBLIC_IDENTITY_PREFIX)
            .unwrap_or_else(|| panic!("{pin}: no {PUBLIC_IDENTITY_PREFIX} prefix"));
        assert_eq!(hex.len(), 64, "{pin}");
        assert!(
            hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{pin}: not lowercase hex"
        );
        let answer = key(seed);
        for other in [
            format!("{PUBLIC_IDENTITY_PREFIX}{}", hex.to_uppercase()),
            pin.to_uppercase(),
            hex.to_owned(),
            format!("spki-sha256-{hex}"),
        ] {
            assert_ne!(answer, other, "key({seed})");
        }
    }
}
