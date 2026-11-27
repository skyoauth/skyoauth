//! No key material, signature or challenge value in what the crate shows:
//! a sentinel test over the `Debug` and `Display` of every type that holds
//! one and of every error; the traits `SoftwareSigner` and `SigningRequest`
//! must not have; and source checks that every top-level module is
//! classified, that nothing under `operator/src` but the deployment-local
//! client and the binary writes a file or prints, that the signer's key and
//! request have no way out, that the deployment-local client, once it
//! exists, never names the signer, and that the binary signs and writes a
//! file only where `sign` does, never overwriting one.

use std::{
    collections::BTreeSet,
    fmt::Debug,
    marker::PhantomData,
    path::{Path, PathBuf},
};

use skyoauth_operator::{
    identity::IdentityError,
    recovery::{
        ChallengeError, Expectations, KeyError, RecoveryPublicKey, RecoverySigner, Refusal,
        RestorationPlan, SignError, SignerError, SigningRequest, SoftwareSigner, VerifyError,
        challenge_message, check_challenge, parse_challenge, sign_challenge,
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
        trust_anchor_ref: Some(ANCHOR),
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
        Refusal::OtherTrustAnchor,
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

/// Whether `path` is the deployment-local client: `src/local.rs` or a file
/// under `src/local/`.
fn is_local(path: &Path) -> bool {
    let src = source_dir();
    path == src.join("local.rs") || path.starts_with(src.join("local"))
}

/// The directory of the package's binaries, `src/bin/`.
const BIN_DIR: &str = "bin";

/// The one binary, `skyoauth-operator`: a directory under [`BIN_DIR`].
const BINARY: &str = "skyoauth-operator";

/// Whether `path` is a source of a binary: a file under `src/bin/`.
fn is_bin(path: &Path) -> bool {
    path.starts_with(source_dir().join(BIN_DIR))
}

/// The code of `text`: every line but comment lines.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(index, line)| (index + 1, line))
}

/// The code of `text` with no comment line and no whitespace, so that a
/// pattern cannot hide behind a line break.
fn joined_code(text: &str) -> String {
    code_lines(text)
        .flat_map(|(_, line)| line.chars())
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// The top-level modules of the crate other than the deployment-local
/// client, all held to [`no_source_writes_a_file`].
const FORMAT_MODULES: [&str; 3] = ["identity", "recovery", "text"];

/// The deployment-local client's module (a later part of the crate), held
/// to [`the_local_client_never_names_the_signer`] instead.
const LOCAL_MODULE: &str = "local";

/// The modules `lib.rs` declares (`mod x;`, with or without a visibility
/// or an attribute on the line).
fn declared_modules() -> BTreeSet<String> {
    let lib = std::fs::read_to_string(source_dir().join("lib.rs")).unwrap();
    code_lines(&lib)
        .filter_map(|(_, line)| {
            let line = line.trim();
            let at = line.find("mod ")?;
            let rest = line[at + 4..].trim();
            let name = rest.strip_suffix(';')?;
            let before = line[..at].trim();
            let prefix_ok = before.is_empty()
                || before.starts_with("pub")
                || (before.starts_with("#[") && before.contains(']'));
            (prefix_ok && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
                .then(|| name.to_owned())
        })
        .collect()
}

/// Every top-level module is classified: each is a format module or the
/// local client, every format module is declared, and every file or
/// directory in `src/` is `lib.rs`, `bin/` or names a declared module (a
/// `local.rs` or `local/` is checked as the local client whether declared
/// or not). `bin/` holds the one binary's directory and nothing else. So a
/// new module, the local client in either layout, or a new binary, cannot
/// escape the source checks below.
#[test]
fn every_top_level_module_is_classified() {
    let declared = declared_modules();
    for module in FORMAT_MODULES {
        assert!(
            declared.contains(module),
            "lib.rs does not declare {module}"
        );
    }
    for module in &declared {
        assert!(
            FORMAT_MODULES.contains(&module.as_str()) || module == LOCAL_MODULE,
            "module {module} is not classified"
        );
    }
    for entry in std::fs::read_dir(source_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if name == "lib.rs" {
            continue;
        }
        if name == BIN_DIR {
            let binaries: Vec<String> = std::fs::read_dir(&path)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
            assert_eq!(binaries, [BINARY], "src/bin/ holds the one binary");
            assert!(
                path.join(BINARY).is_dir(),
                "src/bin/{BINARY} is a directory"
            );
            continue;
        }
        let module = name.strip_suffix(".rs").unwrap_or(&name);
        assert!(
            declared.contains(module),
            "src/{name} is not a module lib.rs declares"
        );
    }
}

/// Nothing under `operator/src` but the deployment-local client
/// (`src/local.rs` or `src/local/`, which talks to a socket and is held to
/// its own check below) and the binary (`src/bin/`, which reads files and
/// prints, and writes and signs in `sign` only, held to
/// [`the_binary_signs_and_writes_only_in_sign`])
/// touches a file, a writer, the console, the process or its environment,
/// or the secret scalar: no `std::fs`, `File`, `OpenOptions`, `std::io`,
/// `print!`, `println!`, `eprint`, `dbg!`, `std::process`, `std::env` or
/// `to_scalar`, and every `write` is a formatter's `f.write_str(`. So no
/// function of the formats or the signer writes or prints a private key
/// anywhere.
#[test]
fn no_source_writes_a_file() {
    let src = source_dir();
    let sources: Vec<(PathBuf, String)> = sources(&src)
        .into_iter()
        .filter(|(path, _)| !is_local(path) && !is_bin(path))
        .collect();
    for read in [
        "lib.rs",
        "identity.rs",
        "text.rs",
        "recovery/mod.rs",
        "recovery/sign.rs",
    ] {
        assert!(
            sources.iter().any(|(path, _)| *path == src.join(read)),
            "{read} is read"
        );
    }
    for (path, text) in &sources {
        for (number, line) in code_lines(text) {
            let place = format!("{}:{number}: {line}", path.display());
            for token in [
                "std::fs",
                "fs::",
                "File",
                "OpenOptions",
                "std::io",
                "io::",
                "print!",
                "println!",
                "eprint",
                "dbg!",
                "std::process",
                "process::",
                "std::env",
                "env::",
                "to_scalar",
            ] {
                assert!(!line.contains(token), "{token} at {place}");
            }
            let writes = line.matches("write").count();
            let formatter_writes = line.matches("f.write_str(").count();
            assert_eq!(writes, formatter_writes, "a write at {place}");
        }
    }
}

/// The deployment-local client (`src/local.rs` or `src/local/`, a later
/// part of the crate) carries a signed response only: no source there may
/// name the signer, its request, its key or its seed. Without a local
/// client the check has nothing to read and passes; with one, in either
/// layout, it checks every file.
#[test]
fn the_local_client_never_names_the_signer() {
    for (path, text) in sources(&source_dir())
        .into_iter()
        .filter(|(path, _)| is_local(path))
    {
        for name in [
            "SigningKey",
            "SoftwareSigner",
            "RecoverySigner",
            "SigningRequest",
            "signing_key",
            "seed",
            "sign_challenge",
            "to_scalar",
        ] {
            assert!(!text.contains(name), "{name} in {}", path.display());
        }
    }
}

/// The binary's file that signs (`sign`), the one place in it that may
/// name the signer or `sign_challenge`.
const BIN_SIGNING_FILE: &str = "cmd_sign.rs";

/// The binary's file that reads the seed file.
const BIN_SEED_FILE: &str = "seed_file.rs";

/// The binary's file that writes `sign`'s `--out`, the one place in it
/// that may open a file for writing.
const BIN_OUT_FILE: &str = "out_file.rs";

/// The binary's files that may name a seed: the flag and its help
/// (`args.rs`), the documentation of the exit codes (`main.rs`), the
/// signing and the reading of the seed file.
const BIN_SEED_NAMING_FILES: [&str; 4] = ["args.rs", "main.rs", BIN_SIGNING_FILE, BIN_SEED_FILE];

/// The binary (`src/bin/`) checks artifacts, and signs in one place only
/// (relaxed for `sign`, deliberately and narrowly):
///
/// - only [`BIN_SIGNING_FILE`] names `SoftwareSigner` or `sign_challenge`,
///   and only [`BIN_SEED_NAMING_FILES`] name a seed; no source names a
///   signing key, the `RecoverySigner` trait, its request or the secret
///   scalar;
/// - only [`BIN_OUT_FILE`] opens a file to write it (`OpenOptions`), and
///   only with `create_new(true)`: never `create(true)`, `truncate` or
///   `append`, so no existing file is overwritten, and synchronizes it
///   (`sync_all`, which no test can observe); no source writes a file
///   otherwise (`fs::write`, `File::create`), creates a directory, removes
///   or renames anything or changes a permission;
/// - [`BIN_SEED_FILE`] derives nothing and formats nothing with `Debug`,
///   so the seed's bytes have no way into a message, and it checks the
///   path without following a link and the opened file again, as the same
///   file (a swap between the two cannot be tested without a race);
/// - none reads the environment (its only input from the process is its
///   arguments), none uses `unsafe`, which its `main.rs` forbids, and none
///   prints with a macro that panics when the output is closed (`print!`,
///   `println!`, `eprint!`, `eprintln!`, `dbg!`).
///
/// The check fails if it does not read the binary's `main.rs` and each of
/// the files named above.
#[test]
fn the_binary_signs_and_writes_only_in_sign() {
    let sources: Vec<(PathBuf, String)> = sources(&source_dir())
        .into_iter()
        .filter(|(path, _)| is_bin(path))
        .collect();
    let file_name = |path: &Path| path.file_name().unwrap().to_str().unwrap().to_owned();
    for read in [
        "main.rs",
        "args.rs",
        BIN_SIGNING_FILE,
        BIN_SEED_FILE,
        BIN_OUT_FILE,
    ] {
        assert!(
            sources
                .iter()
                .any(|(path, _)| path.ends_with(Path::new(BINARY).join(read))),
            "the binary's {read} is read"
        );
    }
    assert!(
        sources.iter().any(|(path, text)| path.ends_with("main.rs")
            && text.lines().any(|line| line == "#![forbid(unsafe_code)]")),
        "the binary forbids unsafe code"
    );
    for (path, text) in &sources {
        let name = file_name(path);
        let mut forbidden = vec![
            "SigningKey",
            "RecoverySigner",
            "SigningRequest",
            "signing_key",
            "to_scalar",
        ];
        if name != BIN_SIGNING_FILE {
            forbidden.extend(["SoftwareSigner", "sign_challenge"]);
        }
        if !BIN_SEED_NAMING_FILES.contains(&name.as_str()) {
            forbidden.push("seed");
        }
        for word in forbidden {
            assert!(!text.contains(word), "{word} in {}", path.display());
        }
        for (number, line) in code_lines(text) {
            let place = format!("{}:{number}: {line}", path.display());
            let mut tokens = vec![
                "fs::write",
                "File::create",
                "create_dir",
                "remove_",
                "rename",
                "set_permissions",
                "env::var",
                "env::set",
                "env::current",
                "unsafe ",
                "unsafe{",
                "print!",
                "println!",
                "eprint",
                "dbg!",
            ];
            if name != BIN_OUT_FILE {
                tokens.push("OpenOptions");
            }
            if name == BIN_SEED_FILE {
                tokens.extend(["derive", ":?"]);
            }
            for token in tokens {
                assert!(!line.contains(token), "{token} at {place}");
            }
        }
        if name == BIN_SEED_FILE {
            // The link check, the recheck of the opened file and its Unix
            // comparison by device and inode, which no test can reach
            // without a race.
            let code = joined_code(text);
            for token in [
                "fs::symlink_metadata(path)",
                "check(&opened,&owner)?;",
                "same_file(&checked,&opened)",
                "checked.dev()==opened.dev()&&checked.ino()==opened.ino()",
            ] {
                assert!(code.contains(token), "{token} not in {}", path.display());
            }
        }
        if name == BIN_OUT_FILE {
            let code = joined_code(text);
            assert!(
                code.contains(".create_new(true)"),
                "{} creates its file new",
                path.display()
            );
            assert!(
                code.contains(".and_then(|()|file.sync_all())"),
                "{} synchronizes its file before success",
                path.display()
            );
            for token in [".create(true)", "truncate", "append"] {
                assert!(!code.contains(token), "{token} in {}", path.display());
            }
        }
    }
}

/// The attributes right above the line of `item` in `lines`.
fn attributes_above<'a>(lines: &[&'a str], item: &str) -> Vec<&'a str> {
    let at = lines
        .iter()
        .position(|line| line.starts_with(item))
        .unwrap_or_else(|| panic!("no {item}"));
    lines[..at]
        .iter()
        .rev()
        .take_while(|line| line.starts_with("///") || line.starts_with("#["))
        .copied()
        .filter(|line| line.starts_with("#["))
        .collect()
}

/// The `impl` lines of `sign.rs` that name `name`, sorted.
fn impls_of<'a>(lines: &[&'a str], name: &str) -> Vec<&'a str> {
    let mut impls: Vec<&str> = lines
        .iter()
        .filter(|line| line.starts_with("impl") && line.contains(name))
        .map(|line| line.trim_end_matches(" {"))
        .collect();
    impls.sort_unstable();
    impls
}

/// `SoftwareSigner` derives nothing, implements only `Debug` (by hand) and
/// `RecoverySigner`, and its fields have no visibility; its signing key is
/// named only where it is declared, made, stored, signs and gives its
/// public key; no function in `sign.rs` returns a seed or a signing key.
/// A `SigningRequest` is made in one place, `sign_challenge`, has a
/// private field, derives nothing and has only `Debug` and its `message`
/// accessor.
#[test]
fn software_signer_source_has_no_way_out_for_the_seed() {
    let path = source_dir().join("recovery").join("sign.rs");
    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let code = joined_code(&text);

    assert_eq!(
        attributes_above(&lines, "pub struct SoftwareSigner"),
        Vec::<&str>::new()
    );
    assert_eq!(
        impls_of(&lines, "SoftwareSigner"),
        [
            "impl RecoverySigner for SoftwareSigner",
            "impl SoftwareSigner",
            "impl fmt::Debug for SoftwareSigner",
        ]
    );
    // The fields, with no visibility at all.
    assert!(
        code.contains(
            "pubstructSoftwareSigner{signing_key:SigningKey,public_key:RecoveryPublicKey,}"
        ),
        "SoftwareSigner's fields changed or gained a visibility"
    );
    // Every use of the signing key, each exactly once.
    let uses = [
        "pubstructSoftwareSigner{signing_key:SigningKey,",
        "letsigning_key=SigningKey::from_bytes(&seed);",
        "RecoveryPublicKey::from_bytes(signing_key.verifying_key().as_bytes())?;",
        "Ok(Self{signing_key,public_key,})",
        "self.signing_key.try_sign(request.message())",
    ];
    for allowed in uses {
        assert_eq!(code.matches(allowed).count(), 1, "{allowed}");
    }
    assert_eq!(
        code.matches("signing_key").count(),
        uses.len(),
        "the signing key is used other than to be made, stored, sign and give its public key"
    );

    assert_eq!(
        attributes_above(&lines, "pub struct SigningRequest"),
        Vec::<&str>::new()
    );
    assert_eq!(
        impls_of(&lines, "SigningRequest"),
        [
            "impl fmt::Debug for SigningRequest<'_>",
            "impl<'a> SigningRequest<'a>",
        ]
    );
    assert!(
        code.contains("pubstructSigningRequest<'a>{message:&'a[u8],}"),
        "SigningRequest's field changed or gained a visibility"
    );
    assert!(
        code.contains(
            "impl<'a>SigningRequest<'a>{pubconstfnmessage(&self)->&'a[u8]{self.message}}"
        )
    );
    assert_eq!(
        code.matches("SigningRequest{").count(),
        1,
        "a SigningRequest is made elsewhere than in sign_challenge"
    );
    assert!(code.contains(
        "letrequest=SigningRequest{message:checked.message(),};letsignature=signer.sign(&request)"
    ));
    assert!(!code.contains("->SigningRequest"));

    for (number, line) in code_lines(&text) {
        for token in [
            "-> [u8; 32]",
            "-> &[u8; 32]",
            "-> SigningKey",
            "-> &SigningKey",
            "SecretKey",
            "to_bytes()",
            "as_bytes()",
            "to_scalar",
            "to_keypair",
            "unsafe",
        ] {
            // A signature's `to_bytes()` is the one allowed.
            if token == "to_bytes()" && line.contains("signature.to_bytes()") {
                continue;
            }
            // Public key bytes: the verifying key's, and a recovery public
            // key's when it is decoded.
            if token == "as_bytes()"
                && (line.contains("verifying_key().as_bytes()")
                    || line.contains("VerifyingKey::from_bytes(key.as_bytes())"))
            {
                continue;
            }
            assert!(!line.contains(token), "{token} at sign.rs:{number}: {line}");
        }
    }
    // A signer is usable as a trait object.
    let signer = SoftwareSigner::from_seed(SEED).unwrap();
    let object: &dyn RecoverySigner = &signer;
    assert_eq!(object.public_key(), signer.public_key());
}

/// `SigningRequest` has none of the traits that would let a caller copy,
/// make or show one.
#[test]
fn signing_request_has_no_trait_to_copy_or_make_it() {
    for (name, has) in traits_of!(SigningRequest<'static>) {
        assert!(!has, "SigningRequest implements {name}");
    }
}
