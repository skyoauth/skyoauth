//! Signing and verifying: `SoftwareSigner`, `sign_challenge` and
//! `verify_response` against the shared fixtures
//! `tests/conformance/fixtures/_recovery/recovery.test-key.json` and
//! `signature.v1.json`, which the `pg` target of `skyoauth-scenarios`
//! checks against the service (`tests/harness/recovery_signature_fixture.rs`);
//! the refusals of `sign_challenge`, with signers that misbehave; and the
//! replacement confirmation `check_challenge` records.

use std::cell::{Cell, RefCell};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use skyoauth_operator::recovery::{
    CHALLENGE_PREFIX, Challenge, Expectations, RecoveryPublicKey, RecoverySigner, Refusal,
    SIGNATURE_LENGTH, SignError, SignerError, SigningRequest, SoftwareSigner, VerifyError,
    check_challenge, parse_challenge, sign_challenge, verify_response,
};

use crate::support::{list, recovery_fixture, text, unhex};

pub const TEST_KEY_FIXTURE: &str = "recovery.test-key.json";
pub const SIGNATURE_FIXTURE: &str = "signature.v1.json";

/// The members of a key of the test-key fixture.
pub const KEY_MEMBERS: [&str; 3] = ["name", "seed", "public_key"];

/// The members a case of the signature fixture may have; `lax_verify` and
/// `cofactored_verify` exactly for 64 bytes, `signed_by` and `signed_over`
/// together.
pub const CASE_MEMBERS: [&str; 8] = [
    "case",
    "note",
    "signed_by",
    "signed_over",
    "signature",
    "expected",
    "lax_verify",
    "cofactored_verify",
];

/// The class of a `verify_response` result in the signature fixture.
fn class(result: Result<(), VerifyError>) -> &'static str {
    match result {
        Ok(()) => "valid",
        Err(VerifyError::Length) => "length",
        Err(VerifyError::NotVerified) => "not_verified",
    }
}

/// op_1's expiry, in microseconds.
const EXPIRES_AT: i64 = 1_790_000_300_000_000;

/// The seed of the key `name` of the test-key fixture.
pub fn seed(name: &str) -> [u8; 32] {
    let fixture = recovery_fixture(TEST_KEY_FIXTURE);
    let key = list(&fixture, "keys")
        .iter()
        .find(|key| text(key, "name") == name)
        .unwrap_or_else(|| panic!("no test key {name}"));
    unhex(text(key, "seed")).try_into().expect("a 32-byte seed")
}

/// The signer of the key `name` of the test-key fixture.
pub fn signer(name: &str) -> SoftwareSigner {
    SoftwareSigner::from_seed(seed(name)).expect("a test key is valid")
}

/// The signature of the key `name` of the test-key fixture over any bytes,
/// made with `ed25519-dalek` directly: a `SoftwareSigner` signs only what
/// `sign_challenge` asks of it.
pub fn raw_sign(name: &str, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
    SigningKey::from_bytes(&seed(name)).sign(message).to_bytes()
}

/// The vector `case` of the challenge fixture.
fn challenge_vector(case: &str) -> Value {
    let fixture = recovery_fixture(crate::challenge::CHALLENGE_FIXTURE);
    list(&fixture, "vectors")
        .iter()
        .find(|vector| text(vector, "case") == case)
        .unwrap_or_else(|| panic!("no challenge vector {case}"))
        .clone()
}

/// The challenge of the vector `case` of the challenge fixture, parsed.
fn challenge(case: &str) -> Challenge {
    parse_challenge(&unhex(text(&challenge_vector(case), "message_hex"))).unwrap()
}

/// The bytes a `signed_over` name of the signature fixture stands for,
/// built from the challenge vector `case`.
fn signed_over(case: &str, name: &str) -> Vec<u8> {
    let challenge_fixture = recovery_fixture(crate::challenge::CHALLENGE_FIXTURE);
    let vector = challenge_vector(case);
    let canonical = text(&vector, "canonical").as_bytes();
    let message = unhex(text(&vector, "message_hex"));
    let digest_prefixed = [
        text(&challenge_fixture, "request_digest_prefix").as_bytes(),
        canonical,
    ]
    .concat();
    match name {
        "message" => message,
        "challenge_hash" => Sha256::digest(&message).to_vec(),
        "canonical" => canonical.to_vec(),
        "prefix_without_newline" => {
            [&CHALLENGE_PREFIX[..CHALLENGE_PREFIX.len() - 1], canonical].concat()
        }
        "request_digest_prefixed" => digest_prefixed,
        "request_digest" => Sha256::digest(&digest_prefixed).to_vec(),
        other => panic!("unknown signed_over {other}"),
    }
}

/// Expectations that op_1 meets at `now`, with the replacement confirmed:
/// its instance, epoch, replacement identity, trust anchor and new key.
fn confirmed(new_key: &RecoveryPublicKey) -> Expectations<'_> {
    Expectations {
        instance_id: "01936f4e-8a2b-7c3d-9e4f-0123456789ab",
        now_micros: EXPIRES_AT - 1,
        recovery_key_epoch: Some(1),
        replacement_public_identity: Some("spki-sha256:new"),
        trust_anchor_ref: Some("deployment/operator-ca"),
        new_recovery_public_key: Some(new_key),
    }
}

/// The new recovery key of op_1's plan.
fn op_1_new_key() -> RecoveryPublicKey {
    challenge("op_1").plan().new_recovery_public_key
}

/// Runs every key of the test-key fixture through
/// [`SoftwareSigner::from_seed`]. Returns the names.
pub fn run_test_keys(fixture: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for key in list(fixture, "keys") {
        let name = text(key, "name");
        let seed: [u8; 32] = unhex(text(key, "seed")).try_into().expect("32 bytes");
        let signer = SoftwareSigner::from_seed(seed).unwrap();
        assert_eq!(
            signer.public_key().to_hex(),
            text(key, "public_key"),
            "{name}"
        );
        // Independently of the crate: ed25519-dalek's own derivation.
        assert_eq!(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            unhex(text(key, "public_key")),
            "{name}"
        );
        names.push(name.to_owned());
    }
    names
}

/// Runs every case of the signature fixture through [`verify_response`]
/// with the signer's key over the challenge's `M`, and re-makes each real
/// signature with `ed25519-dalek` ([`raw_sign`]). Returns the names.
pub fn run_signature_cases(fixture: &Value) -> Vec<String> {
    let challenge_case = text(fixture, "challenge_case");
    let challenge = challenge(challenge_case);
    let key = signer(text(fixture, "signer")).public_key();
    let lax = VerifyingKey::from_bytes(key.as_bytes()).unwrap();
    let mut names = Vec::new();
    for case in list(fixture, "cases") {
        let name = text(case, "case");
        assert!(!text(case, "note").is_empty(), "{name}");
        let signature = unhex(text(case, "signature"));
        let result = verify_response(&key, &challenge, &signature);
        assert_eq!(class(result), text(case, "expected"), "{name}");
        // The class holds independently: `length` exactly for another
        // length, and `lax_verify` is what a verify without the strict
        // checks says.
        assert_eq!(
            signature.len() != SIGNATURE_LENGTH,
            text(case, "expected") == "length",
            "{name}"
        );
        match <[u8; SIGNATURE_LENGTH]>::try_from(signature.as_slice()) {
            Ok(bytes) => {
                let lax_verify = case["lax_verify"].as_bool().expect("lax_verify");
                assert_eq!(
                    lax.verify(challenge.message(), &Signature::from_bytes(&bytes))
                        .is_ok(),
                    lax_verify,
                    "{name}"
                );
                // Recorded from the fixture's independent computation; no
                // verifier here is cofactored.
                case["cofactored_verify"]
                    .as_bool()
                    .expect("cofactored_verify");
            }
            Err(_) => {
                assert!(case.get("lax_verify").is_none(), "{name}");
                assert!(case.get("cofactored_verify").is_none(), "{name}");
            }
        }
        // A real signature: its key signs its bytes to exactly it.
        match (case.get("signed_by"), case.get("signed_over")) {
            (None, None) => {}
            (Some(by), Some(over)) => {
                let by = by.as_str().expect("signed_by");
                let over = signed_over(challenge_case, over.as_str().expect("signed_over"));
                assert_eq!(raw_sign(by, &over).to_vec(), signature, "{name}");
            }
            _ => panic!("{name}: signed_by and signed_over go together"),
        }
        names.push(name.to_owned());
    }
    names
}

#[test]
fn signature_fixture_envelope_matches_the_crate() {
    let fixture = recovery_fixture(SIGNATURE_FIXTURE);
    assert_eq!(fixture["fixture_version"], 1);
    assert_eq!(fixture["kind"], "recovery_signature");
    assert_eq!(
        fixture["signature_length_bytes"],
        u64::try_from(SIGNATURE_LENGTH).unwrap()
    );
    assert_eq!(SIGNATURE_LENGTH, 64);
    // The service's outcome per class: only `valid` restores.
    assert_eq!(
        fixture["service_expected"],
        serde_json::json!({
            "valid": "ok",
            "length": "bad_signature",
            "not_verified": "bad_signature",
        })
    );
    let keys = recovery_fixture(TEST_KEY_FIXTURE);
    assert_eq!(keys["fixture_version"], 1);
    assert_eq!(keys["kind"], "recovery_test_key");
    // The signer is not op_1's new key; the RFC 8032 key is.
    let new_key = op_1_new_key();
    assert_ne!(signer(text(&fixture, "signer")).public_key(), new_key);
    assert_eq!(signer("rfc8032_test1").public_key(), new_key);
    assert_ne!(signer("other").public_key(), new_key);
}

#[test]
fn test_keys_match_software_signer() {
    let fixture = recovery_fixture(TEST_KEY_FIXTURE);
    assert_eq!(run_test_keys(&fixture).len(), 3);
}

#[test]
fn signature_cases_match_verify_response() {
    let fixture = recovery_fixture(SIGNATURE_FIXTURE);
    assert!(!run_signature_cases(&fixture).is_empty());
}

/// RFC 8032 section 7.1, test 1: the key's seed gives the RFC's public key
/// through [`SoftwareSigner`], and its signature of the empty message
/// (`ed25519-dalek`, since a `SoftwareSigner` signs only a challenge) is
/// the RFC's.
#[test]
fn rfc8032_test1_through_software_signer() {
    let fixture = recovery_fixture(SIGNATURE_FIXTURE);
    let vector = &fixture["rfc8032_test1"];
    let name = text(vector, "key");
    assert_eq!(
        signer(name).public_key().as_bytes(),
        SigningKey::from_bytes(&seed(name))
            .verifying_key()
            .as_bytes()
    );
    let signature = raw_sign(name, &unhex(text(vector, "message_hex")));
    assert_eq!(signature.to_vec(), unhex(text(vector, "signature")));
    assert_ne!(raw_sign(name, b"x"), signature);
}

/// The signature `sign_challenge` returns for op_1 is the fixture's
/// `valid` case, every time, and verifies.
#[test]
fn sign_challenge_returns_the_fixture_signature() {
    let fixture = recovery_fixture(SIGNATURE_FIXTURE);
    let valid = list(&fixture, "cases")
        .iter()
        .find(|case| text(case, "case") == "valid")
        .expect("a valid case");
    let challenge = challenge(text(&fixture, "challenge_case"));
    let new_key = op_1_new_key();
    let verified = check_challenge(&challenge, &confirmed(&new_key)).unwrap();
    let signer = signer(text(&fixture, "signer"));
    let response = sign_challenge(&verified, &signer).unwrap();
    assert_eq!(response.operation_id(), "op_1");
    assert_eq!(
        response.signature().to_vec(),
        unhex(text(valid, "signature"))
    );
    assert_eq!(sign_challenge(&verified, &signer).unwrap(), response);
    assert_eq!(
        verify_response(&signer.public_key(), &challenge, response.signature()),
        Ok(())
    );
    assert_eq!(
        verify_response(&new_key, &challenge, response.signature()),
        Err(VerifyError::NotVerified)
    );
}

/// A signer that answers with what it was given, counts its calls and
/// keeps the bytes it was asked to sign.
struct StubSigner {
    public_key: RecoveryPublicKey,
    answer: Result<[u8; SIGNATURE_LENGTH], SignerError>,
    public_key_calls: Cell<usize>,
    signed: Cell<usize>,
    asked: RefCell<Vec<Vec<u8>>>,
}

impl StubSigner {
    fn new(public_key: RecoveryPublicKey, answer: Result<[u8; 64], SignerError>) -> Self {
        Self {
            public_key,
            answer,
            public_key_calls: Cell::new(0),
            signed: Cell::new(0),
            asked: RefCell::new(Vec::new()),
        }
    }
}

impl RecoverySigner for StubSigner {
    fn public_key(&self) -> RecoveryPublicKey {
        self.public_key_calls.set(self.public_key_calls.get() + 1);
        self.public_key
    }

    fn sign(&self, request: &SigningRequest<'_>) -> Result<[u8; SIGNATURE_LENGTH], SignerError> {
        self.signed.set(self.signed.get() + 1);
        self.asked.borrow_mut().push(request.message().to_vec());
        self.answer
    }
}

/// A signer that passes the request it is given on to the signer it wraps:
/// a signer of another crate can do so, and signs only what
/// `sign_challenge` asked.
struct Wrapping<'s> {
    inner: &'s SoftwareSigner,
    asked: RefCell<Vec<Vec<u8>>>,
}

impl RecoverySigner for Wrapping<'_> {
    fn public_key(&self) -> RecoveryPublicKey {
        self.inner.public_key()
    }

    fn sign(&self, request: &SigningRequest<'_>) -> Result<[u8; SIGNATURE_LENGTH], SignerError> {
        assert_eq!(format!("{request:?}"), "SigningRequest(..)");
        self.asked.borrow_mut().push(request.message().to_vec());
        self.inner.sign(request)
    }
}

/// The signer is asked for exactly `M`, once, and a wrapping signer of
/// another crate can pass the request on.
#[test]
fn the_signer_is_asked_for_exactly_m() {
    let challenge = challenge("op_1");
    let new_key = op_1_new_key();
    let verified = check_challenge(&challenge, &confirmed(&new_key)).unwrap();
    let stub = StubSigner::new(
        signer("recovery").public_key(),
        Ok(raw_sign("recovery", challenge.message())),
    );
    sign_challenge(&verified, &stub).unwrap();
    assert_eq!(*stub.asked.borrow(), [challenge.message().to_vec()]);
    let inner = signer("recovery");
    let wrapping = Wrapping {
        inner: &inner,
        asked: RefCell::new(Vec::new()),
    };
    let response = sign_challenge(&verified, &wrapping).unwrap();
    assert_eq!(*wrapping.asked.borrow(), [challenge.message().to_vec()]);
    assert_eq!(response, sign_challenge(&verified, &inner).unwrap());
}

/// A signer whose signature does not verify with its own public key over
/// `M` is refused, whatever it returned: every 64-byte refusal of the
/// fixture (malleable, small-order or non-canonical `R`, another key, the
/// plan's new key, another message), garbage, and the right signature
/// under another public key. The signature is never returned.
#[test]
fn sign_challenge_refuses_a_signature_that_does_not_verify() {
    let fixture = recovery_fixture(SIGNATURE_FIXTURE);
    let challenge = challenge(text(&fixture, "challenge_case"));
    let new_key = op_1_new_key();
    let verified = check_challenge(&challenge, &confirmed(&new_key)).unwrap();
    let key = signer(text(&fixture, "signer")).public_key();
    let mut refused = 0;
    for case in list(&fixture, "cases") {
        let name = text(case, "case");
        let Ok(signature) = <[u8; 64]>::try_from(unhex(text(case, "signature")).as_slice()) else {
            continue;
        };
        let stub = StubSigner::new(key, Ok(signature));
        let result = sign_challenge(&verified, &stub);
        if text(case, "expected") == "valid" {
            assert_eq!(result.unwrap().signature(), &signature, "{name}");
        } else {
            assert_eq!(result, Err(SignError::NotVerified), "{name}");
            refused += 1;
        }
        assert_eq!(
            (stub.public_key_calls.get(), stub.signed.get()),
            (1, 1),
            "{name}"
        );
    }
    assert!(refused >= 12, "{refused}");

    // Garbage, and a weak key's universal signature (R the identity, S
    // zero), under the signer's key.
    let mut identity_r = [0; 64];
    identity_r[0] = 1;
    for garbage in [[0xff; 64], [0; 64], identity_r] {
        let stub = StubSigner::new(key, Ok(garbage));
        assert_eq!(
            sign_challenge(&verified, &stub),
            Err(SignError::NotVerified)
        );
    }
    // The right signature, presented under another key.
    let right = raw_sign(text(&fixture, "signer"), challenge.message());
    let stub = StubSigner::new(signer("other").public_key(), Ok(right));
    assert_eq!(
        sign_challenge(&verified, &stub),
        Err(SignError::NotVerified)
    );
}

/// A signer that does not sign is `Signer`, with its error as the source.
#[test]
fn sign_challenge_passes_on_a_signer_failure() {
    let challenge = challenge("op_1");
    let new_key = op_1_new_key();
    let verified = check_challenge(&challenge, &confirmed(&new_key)).unwrap();
    let stub = StubSigner::new(signer("recovery").public_key(), Err(SignerError::Failed));
    let err = sign_challenge(&verified, &stub).unwrap_err();
    assert_eq!(err, SignError::Signer(SignerError::Failed));
    assert_eq!(
        std::error::Error::source(&err).map(ToString::to_string),
        Some(SignerError::Failed.to_string())
    );
    assert_eq!(stub.signed.get(), 1);
}

/// The plan's new key is never the signer's: the service would refuse the
/// restore (`RecoveryKeyUnchanged`) and the issue (`NotIssuable`). Nothing
/// is signed.
#[test]
fn sign_challenge_refuses_the_plans_new_key_as_signer() {
    let challenge = challenge("op_1");
    let new_key = op_1_new_key();
    let verified = check_challenge(&challenge, &confirmed(&new_key)).unwrap();
    // The RFC 8032 key is op_1's new key.
    assert_eq!(
        sign_challenge(&verified, &signer("rfc8032_test1")),
        Err(SignError::RecoveryKeyUnchanged)
    );
    let right = raw_sign("rfc8032_test1", challenge.message());
    let stub = StubSigner::new(new_key, Ok(right));
    assert_eq!(
        sign_challenge(&verified, &stub),
        Err(SignError::RecoveryKeyUnchanged)
    );
    assert_eq!((stub.public_key_calls.get(), stub.signed.get()), (1, 0));
}

/// Only a challenge checked with the replacement's identity, its trust
/// anchor and the new key is signed; without any of them, nothing is asked
/// of the signer. A challenge whose trust anchor is another one is refused
/// by the check, so it never reaches the signer.
#[test]
fn sign_challenge_requires_a_confirmed_replacement() {
    let challenge = challenge("op_1");
    let new_key = op_1_new_key();
    let all = confirmed(&new_key);
    let stub = StubSigner::new(
        signer("recovery").public_key(),
        Ok(raw_sign("recovery", challenge.message())),
    );
    for (expected, confirmed) in [
        (all, true),
        (
            Expectations {
                recovery_key_epoch: None,
                ..all
            },
            true,
        ),
        (
            Expectations {
                replacement_public_identity: None,
                ..all
            },
            false,
        ),
        (
            Expectations {
                trust_anchor_ref: None,
                ..all
            },
            false,
        ),
        (
            Expectations {
                new_recovery_public_key: None,
                ..all
            },
            false,
        ),
        (
            Expectations {
                replacement_public_identity: None,
                new_recovery_public_key: None,
                ..all
            },
            false,
        ),
        (
            Expectations {
                replacement_public_identity: None,
                trust_anchor_ref: None,
                new_recovery_public_key: None,
                ..all
            },
            false,
        ),
    ] {
        let verified = check_challenge(&challenge, &expected).unwrap();
        assert_eq!(verified.replacement_confirmed(), confirmed);
        let before = (stub.public_key_calls.get(), stub.signed.get());
        let result = sign_challenge(&verified, &stub);
        let after = (stub.public_key_calls.get(), stub.signed.get());
        if confirmed {
            assert!(result.is_ok());
            assert_eq!(after, (before.0 + 1, before.1 + 1));
        } else {
            assert_eq!(result, Err(SignError::ReplacementNotConfirmed));
            assert_eq!(after, before);
        }
    }
    // The two confirmed ones only were signed.
    assert_eq!((stub.public_key_calls.get(), stub.signed.get()), (2, 2));
    // Another trust anchor: refused by the check, before any signer.
    for anchor in ["deployment/other-ca", "deployment/operator-c", ""] {
        let other = Expectations {
            trust_anchor_ref: Some(anchor),
            ..all
        };
        assert_eq!(
            check_challenge(&challenge, &other).map(|_| ()),
            Err(Refusal::OtherTrustAnchor),
            "{anchor:?}"
        );
    }
    assert_eq!((stub.public_key_calls.get(), stub.signed.get()), (2, 2));
}

/// A signer can present only a key that passed the service's checks: every
/// refused 32-byte case of the key fixture is refused as a
/// `RecoveryPublicKey`, the one type `RecoverySigner::public_key` returns.
/// A seed's key always passes.
#[test]
fn a_signer_cannot_present_a_weak_key() {
    let fixture = recovery_fixture("key.v1.json");
    let mut refused = 0;
    for case in list(&fixture, "byte_cases") {
        let bytes = unhex(text(case, "key"));
        if bytes.len() == 32 && text(case, "expected") != "valid" {
            assert!(RecoveryPublicKey::from_bytes(&bytes).is_err(), "{case}");
            refused += 1;
        }
    }
    assert!(refused >= 14, "{refused}");
    for first in 0..=u8::MAX {
        let mut seed = [first; 32];
        seed[31] = first.wrapping_mul(7);
        let signer = SoftwareSigner::from_seed(seed).unwrap();
        assert_eq!(
            RecoveryPublicKey::from_bytes(signer.public_key().as_bytes()),
            Ok(signer.public_key())
        );
    }
}

/// `verify_response` checks the length first: a valid signature cut short
/// or extended is `Length`, never verified.
#[test]
fn verify_response_refuses_other_lengths() {
    let challenge = challenge("op_1");
    let key = signer("recovery").public_key();
    let signature = raw_sign("recovery", challenge.message());
    assert_eq!(verify_response(&key, &challenge, &signature), Ok(()));
    let extended = [&signature[..], &[0]].concat();
    let doubled = [signature, signature].concat();
    for wrong in [
        &[][..],
        &[5][..],
        &signature[..32],
        &signature[..63],
        &extended[..],
        &doubled[..],
    ] {
        assert_eq!(
            verify_response(&key, &challenge, wrong),
            Err(VerifyError::Length),
            "{}",
            wrong.len()
        );
    }
}

/// A signature binds its challenge: over every challenge vector, the
/// signature of one challenge verifies for it alone, and with its signer's
/// key alone.
#[test]
fn a_signature_verifies_for_its_challenge_and_key_alone() {
    let fixture = recovery_fixture(crate::challenge::CHALLENGE_FIXTURE);
    let challenges: Vec<Challenge> = list(&fixture, "vectors")
        .iter()
        .map(|vector| parse_challenge(&unhex(text(vector, "message_hex"))).unwrap())
        .collect();
    let names = ["recovery", "other"];
    let keys = names.map(signer);
    for (i, signed) in challenges.iter().enumerate() {
        for (k, by) in names.iter().enumerate() {
            let signature = raw_sign(by, signed.message());
            for (j, checked) in challenges.iter().enumerate() {
                for (l, key) in keys.iter().enumerate() {
                    let expected = if i == j && k == l {
                        Ok(())
                    } else {
                        Err(VerifyError::NotVerified)
                    };
                    assert_eq!(
                        verify_response(&key.public_key(), checked, &signature),
                        expected,
                        "{i} {k} {j} {l}"
                    );
                }
            }
        }
    }
}

/// Every refusal of signing and verifying has its own fixed text.
#[test]
fn sign_and_verify_errors_are_fixed_text() {
    let texts = [
        SignError::ReplacementNotConfirmed.to_string(),
        SignError::RecoveryKeyUnchanged.to_string(),
        SignError::Signer(SignerError::Failed).to_string(),
        SignError::NotVerified.to_string(),
        VerifyError::Length.to_string(),
        VerifyError::NotVerified.to_string(),
    ];
    let mut unique = texts.to_vec();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), texts.len());
    assert_eq!(
        SignerError::Failed.to_string(),
        SignError::Signer(SignerError::Failed).to_string()
    );
    assert!(std::error::Error::source(&SignError::NotVerified).is_none());
    assert!(std::error::Error::source(&VerifyError::Length).is_none());
    assert!(std::error::Error::source(&SignerError::Failed).is_none());
}
