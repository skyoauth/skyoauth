//! No key material, signature or challenge value in what the crate shows:
//! a sentinel test over the `Debug` and `Display` of every type that holds
//! one and of every error; the traits `SoftwareSigner` must not have; and
//! source checks that nothing under `operator/src` writes a file, and that
//! the deployment-local client, once it exists, never names the signer.

use std::{
    fmt::Debug,
    marker::PhantomData,
    path::{Path, PathBuf},
};

use skyoauth_operator::{
    identity::IdentityError,
    recovery::{
        ChallengeError, Expectations, KeyError, RecoveryPublicKey, RecoverySigner, Refusal,
        RestorationPlan, SignError, SignerError, SoftwareSigner, VerifyError, challenge_message,
        check_challenge, parse_challenge, sign_challenge,
    },
};

/// 32 distinctive bytes: the signer's seed.
const SEED: [u8; 32] = *b"SENTINEL-seed-0123456789-abcdef!";

/// 32 distinctive bytes: the seed of the plan's new key.
const NEW_KEY_SEED: [u8; 32] = *b"SENTINEL-newkey-0123456789abcdef";

const INSTANCE: &str = "SENTINEL-instance-7f3a";
const OPERATION: &str = "op_SENTINEL_id_7f3a";
const IDENTITY: &str = "spki-sha256:SENTINELidentity7f3a";
const ANCHOR: &str = "SENTINEL/anchor/7f3a";
const EXPIRES_AT: i64 = 1_790_000_300_000_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The ways `bytes` could be shown: lowercase and uppercase hexadecimal
/// (whole, and the first 8 bytes), the bytes as text when they are, and
/// the start of the `Debug` of the byte array (decimal and hexadecimal).
fn needles_of(bytes: &[u8]) -> Vec<String> {
    let whole = hex(bytes);
    let mut needles = vec![
        whole.clone(),
        whole.to_ascii_uppercase(),
        whole[..16].to_owned(),
        whole[..16].to_ascii_uppercase(),
        format!("{:?}", &bytes[..4])
            .trim_end_matches(']')
            .to_owned(),
        format!("{:x?}", &bytes[..4])
            .trim_end_matches(']')
            .to_owned(),
    ];
    if let Ok(text) = std::str::from_utf8(bytes) {
        needles.push(text.to_owned());
    }
    needles
}

/// The `Debug` (plain and alternate) of `value`.
fn debugs(value: &dyn Debug) -> Vec<String> {
    vec![format!("{value:?}"), format!("{value:#?}")]
}

/// The `Debug` and `Display` of `error`.
fn shown_error<E: std::error::Error>(error: &E) -> Vec<String> {
    let mut shown = debugs(error);
    shown.push(error.to_string());
    shown
}

/// Every `Debug` and `Display` of the crate's types, built from sentinel
/// values, contains none of them in any form.
#[test]
fn no_sentinel_value_is_shown() {
    let signer = SoftwareSigner::from_seed(SEED).unwrap();
    let new_key_signer = SoftwareSigner::from_seed(NEW_KEY_SEED).unwrap();
    let new_key = new_key_signer.public_key();
    let plan = RestorationPlan {
        instance_id: INSTANCE.into(),
        recovery_key_epoch: 7_310_411,
        admin_id: "adm_SENTINEL_admin".into(),
        credential_id: "crd_SENTINEL_credential".into(),
        binding_id: "rb_SENTINEL_binding".into(),
        public_identity: IDENTITY.into(),
        trust_anchor_ref: ANCHOR.into(),
        new_recovery_public_key: new_key,
    };
    let message = challenge_message(OPERATION, 7_310_412, EXPIRES_AT, &plan);
    let challenge = parse_challenge(&message).unwrap();
    let expectations = Expectations {
        instance_id: INSTANCE,
        now_micros: EXPIRES_AT - 1,
        recovery_key_epoch: Some(7_310_411),
        replacement_public_identity: Some(IDENTITY),
        new_recovery_public_key: Some(&new_key),
    };
    let verified = check_challenge(&challenge, &expectations).unwrap();
    let response = sign_challenge(&verified, &signer).unwrap();

    let mut needles: Vec<String> = Vec::new();
    for bytes in [
        &SEED[..],
        &NEW_KEY_SEED[..],
        signer.public_key().as_bytes(),
        new_key.as_bytes(),
        response.signature(),
    ] {
        needles.extend(needles_of(bytes));
    }
    needles.extend(
        [
            "SENTINEL",
            "7f3a",
            "7310411",
            "7310412",
            "1790000300000000",
            INSTANCE,
            OPERATION,
            IDENTITY,
            ANCHOR,
        ]
        .map(String::from),
    );

    let mut shown: Vec<(&str, String)> = Vec::new();
    let mut add = |what: &'static str, texts: Vec<String>| {
        shown.extend(texts.into_iter().map(|text| (what, text)));
    };
    add("SoftwareSigner", debugs(&signer));
    add("RecoveryPublicKey", debugs(&signer.public_key()));
    add("new key", debugs(&new_key));
    add("SignedResponse", debugs(&response));
    add("Challenge", debugs(&challenge));
    add("RestorationPlan", debugs(&plan));
    add("RestorationPlan of the challenge", debugs(challenge.plan()));
    add("VerifiedChallenge", debugs(&verified));
    add("Expectations", debugs(&expectations));
    add(
        "Result<SignedResponse>",
        debugs(&sign_challenge(&verified, &signer)),
    );
    for error in [
        SignError::ReplacementNotConfirmed,
        SignError::RecoveryKeyUnchanged,
        SignError::Signer(SignerError::Failed),
        SignError::NotVerified,
    ] {
        add("SignError", shown_error(&error));
    }
    add("SignerError", shown_error(&SignerError::Failed));
    for error in [VerifyError::Length, VerifyError::NotVerified] {
        add("VerifyError", shown_error(&error));
    }
    for error in [
        KeyError::NotHex,
        KeyError::Length,
        KeyError::Undecodable,
        KeyError::NotCanonical,
        KeyError::SmallOrder,
    ] {
        add("KeyError", shown_error(&error));
    }
    for error in [
        ChallengeError::TooLarge,
        ChallengeError::Prefix,
        ChallengeError::NotUtf8,
        ChallengeError::Syntax,
        ChallengeError::Number,
        ChallengeError::WrongType,
        ChallengeError::DuplicateMember,
        ChallengeError::UnsortedMembers,
        ChallengeError::UnknownMember,
        ChallengeError::MissingMember,
        ChallengeError::FixedValue,
        ChallengeError::TextBounds,
        ChallengeError::NewRecoveryKey(KeyError::SmallOrder),
        ChallengeError::NotCanonical,
    ] {
        add("ChallengeError", shown_error(&error));
    }
    for refusal in [
        Refusal::OtherInstance,
        Refusal::Expired,
        Refusal::ExpiresTooLate,
        Refusal::OtherEpoch,
        Refusal::OtherReplacementIdentity,
        Refusal::OtherNewRecoveryKey,
    ] {
        add("Refusal", shown_error(&refusal));
    }
    for error in [IdentityError::Empty, IdentityError::TooLarge] {
        add("IdentityError", shown_error(&error));
    }

    for (what, text) in &shown {
        for needle in &needles {
            assert!(
                !text.contains(needle.as_str()),
                "{what} shows {needle:?}: {text}"
            );
        }
    }
    // The values themselves: `Debug` is the kind only.
    let kinds: Vec<&str> = [
        "SoftwareSigner",
        "RecoveryPublicKey",
        "SignedResponse",
        "Challenge",
        "RestorationPlan",
        "VerifiedChallenge",
        "Expectations",
    ]
    .to_vec();
    for kind in kinds {
        let expected = format!("{kind}(..)");
        assert!(
            shown
                .iter()
                .any(|(what, text)| what == &kind && *text == expected),
            "{kind}"
        );
    }
}

/// A probe for a trait, by method resolution: the inherent method of
/// `Probe<T>` exists only when `T` has the trait, and takes precedence over
/// the fallback trait's, which answers `false`.
macro_rules! probe {
    ($name:ident, $($bound:tt)+) => {
        mod $name {
            use super::*;
            pub struct Probe<T>(pub PhantomData<T>);
            impl<T: $($bound)+> Probe<T> {
                pub fn has(&self) -> bool {
                    true
                }
            }
            pub trait Fallback {
                fn has(&self) -> bool {
                    false
                }
            }
            impl<T> Fallback for Probe<T> {}
        }
    };
}

probe!(clone, Clone);
probe!(copy, Copy);
probe!(display, std::fmt::Display);
probe!(default, Default);
probe!(deref, std::ops::Deref);
probe!(as_bytes, AsRef<[u8]>);
probe!(as_array, AsRef<[u8; 32]>);
probe!(into_array, Into<[u8; 32]>);
probe!(partial_eq, PartialEq);

// The fallbacks, for the probes of a type without the trait.
use as_array::Fallback as _;
use as_bytes::Fallback as _;
use clone::Fallback as _;
use copy::Fallback as _;
use default::Fallback as _;
use deref::Fallback as _;
use display::Fallback as _;
use into_array::Fallback as _;
use partial_eq::Fallback as _;

/// The traits that could copy or show a seed, by probe.
macro_rules! traits_of {
    ($type:ty) => {{
        [
            ("Clone", clone::Probe::<$type>(PhantomData).has()),
            ("Copy", copy::Probe::<$type>(PhantomData).has()),
            ("Display", display::Probe::<$type>(PhantomData).has()),
            ("Default", default::Probe::<$type>(PhantomData).has()),
            ("Deref", deref::Probe::<$type>(PhantomData).has()),
            ("AsRef<[u8]>", as_bytes::Probe::<$type>(PhantomData).has()),
            (
                "AsRef<[u8; 32]>",
                as_array::Probe::<$type>(PhantomData).has(),
            ),
            (
                "Into<[u8; 32]>",
                into_array::Probe::<$type>(PhantomData).has(),
            ),
            ("PartialEq", partial_eq::Probe::<$type>(PhantomData).has()),
        ]
    }};
}

/// `SoftwareSigner` has none of the traits that copy, compare or show its
/// seed. The probe itself is checked on types that have them.
#[test]
fn software_signer_has_no_trait_that_copies_or_shows_the_seed() {
    for (name, has) in traits_of!(SoftwareSigner) {
        assert!(!has, "SoftwareSigner implements {name}");
    }
    let key: Vec<(&str, bool)> = traits_of!(RecoveryPublicKey).to_vec();
    for name in ["Clone", "Copy", "PartialEq"] {
        assert!(key.contains(&(name, true)), "the probe misses {name}");
    }
    assert!(key.contains(&("Display", false)));
    let array: Vec<(&str, bool)> = traits_of!([u8; 32]).to_vec();
    for name in ["Default", "AsRef<[u8]>", "Into<[u8; 32]>"] {
        assert!(array.contains(&(name, true)), "the probe misses {name}");
    }
    let boxed: Vec<(&str, bool)> = traits_of!(Box<[u8; 32]>).to_vec();
    assert!(boxed.contains(&("Deref", true)), "the probe misses Deref");
    assert!(boxed.contains(&("AsRef<[u8; 32]>", true)));
    let text: Vec<(&str, bool)> = traits_of!(String).to_vec();
    assert!(
        text.contains(&("Display", true)),
        "the probe misses Display"
    );
}

/// The crate's source directory.
fn source_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(dir.is_dir(), "no source directory at {}", dir.display());
    dir
}

/// Every `.rs` file under `dir`, recursively, with its text.
fn sources(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            found.push((path, text));
        }
    }
    found
}

/// The code of `text`: every line but comment lines.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(index, line)| (index + 1, line))
}

/// Nothing under `operator/src` touches a file or a writer: no `std::fs`,
/// `File`, `OpenOptions` or `std::io`, and every `write` is a formatter's
/// `f.write_str(`. So no function of the crate writes a private key
/// anywhere.
#[test]
fn no_source_writes_a_file() {
    // Only `recovery/`: the deployment-local client (`local/`) legitimately
    // uses `std::io` to talk to a socket, and is held to its own check below.
    let sources = sources(&source_dir().join("recovery"));
    assert!(
        sources
            .iter()
            .any(|(path, _)| path.ends_with("recovery/sign.rs")),
        "sign.rs is read"
    );
    for (path, text) in &sources {
        for (number, line) in code_lines(text) {
            let place = format!("{}:{number}: {line}", path.display());
            for token in ["std::fs", "fs::", "File", "OpenOptions", "std::io", "io::"] {
                assert!(!line.contains(token), "{token} at {place}");
            }
            let writes = line.matches("write").count();
            let formatter_writes = line.matches("f.write_str(").count();
            assert_eq!(writes, formatter_writes, "a write at {place}");
        }
    }
}

/// The deployment-local client (`operator/src/local/`, a later part of the
/// crate) carries a signed response only: no source there may name the
/// signer, its key or its seed. The directory does not exist yet, so the
/// check passes vacuously until it does; it then checks every file there.
#[test]
fn the_local_client_never_names_the_signer() {
    let local = source_dir().join("local");
    if !local.exists() {
        // Vacuous: no local client yet.
        return;
    }
    for (path, text) in sources(&local) {
        for name in [
            "SigningKey",
            "SoftwareSigner",
            "RecoverySigner",
            "seed",
            "sign_challenge",
        ] {
            assert!(!text.contains(name), "{name} in {}", path.display());
        }
    }
}

/// `SoftwareSigner` derives nothing and implements only `Debug` (by hand)
/// and `RecoverySigner`; no function in `sign.rs` returns a seed or a
/// signing key, and nothing there names a secret key type.
#[test]
fn software_signer_source_has_no_way_out_for_the_seed() {
    let path = source_dir().join("recovery").join("sign.rs");
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.starts_with("pub struct SoftwareSigner"))
        .expect("the struct");
    let attributes: Vec<&str> = lines[..at]
        .iter()
        .rev()
        .take_while(|line| line.starts_with("///") || line.starts_with("#["))
        .copied()
        .filter(|line| line.starts_with("#["))
        .collect();
    assert!(attributes.is_empty(), "{attributes:?}");
    let mut impls: Vec<&str> = lines
        .iter()
        .filter(|line| line.starts_with("impl") && line.contains("SoftwareSigner"))
        .map(|line| line.trim_end_matches(" {"))
        .collect();
    impls.sort_unstable();
    assert_eq!(
        impls,
        [
            "impl RecoverySigner for SoftwareSigner",
            "impl SoftwareSigner",
            "impl fmt::Debug for SoftwareSigner",
        ]
    );
    for (number, line) in code_lines(&text) {
        for token in [
            "-> [u8; 32]",
            "-> &[u8; 32]",
            "SigningKey {",
            "-> SigningKey",
            "-> &SigningKey",
            "SecretKey",
            "to_bytes()",
            "as_bytes()",
            "to_keypair",
            "unsafe",
        ] {
            // A signature's `to_bytes()` is the one allowed.
            if token == "to_bytes()" && line.contains("signature.to_bytes()") {
                continue;
            }
            // The verifying key's bytes are public.
            if token == "as_bytes()"
                && (line.contains("verifying_key().as_bytes()") || line.contains("key.as_bytes()"))
            {
                continue;
            }
            assert!(!line.contains(token), "{token} at sign.rs:{number}: {line}");
        }
    }
    // The fields stay private.
    assert!(!text.contains("pub signing_key"));
    assert!(!text.contains("pub(crate) signing_key"));
    // A signer is usable as a trait object.
    let signer = SoftwareSigner::from_seed(SEED).unwrap();
    let object: &dyn RecoverySigner = &signer;
    assert_eq!(object.public_key(), signer.public_key());
}
