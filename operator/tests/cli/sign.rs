//! `skyoauth-operator sign`: the round trip of every challenge vector with
//! the recovery test key's seed file (the response byte for byte the
//! library's, verified by `verify-response`), every refusal, the required
//! expectations, the seed file's checks (its content on every platform,
//! its protection on Unix) and the output file, which is created new or
//! not at all (docs/proposals/operator-cli-artifacts.md).
//!
//! Every run is checked for what it must never do ([`run_sign`]): print a
//! seed or a signature in any form (the response goes to `--out` only),
//! print anything on standard output when it fails, or end in another exit
//! code than 0 to 3.

use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde_json::Value;
use skyoauth_operator::recovery::{
    Expectations, RecoveryPublicKey, Refusal, check_challenge, parse_challenge, sign_challenge,
};

use super::{
    BINARY, HINT, NEW_KEY, NOW, Run, TempDir, challenge_artifact, confirming_flags,
    fixture_signature, integer, refusal_flags, response_artifact, test_public_key, vector,
    verify_response,
};
use crate::{
    challenge::CHALLENGE_FIXTURE,
    signature::{SIGNATURE_FIXTURE, TEST_KEY_FIXTURE, signer},
    support::{list, recovery_fixture, text, unhex},
};

/// The seed (hexadecimal) of the test key `name`.
fn seed_hex(name: &str) -> String {
    list(&recovery_fixture(TEST_KEY_FIXTURE), "keys")
        .iter()
        .find(|key| text(key, "name") == name)
        .map(|key| text(key, "seed").to_owned())
        .unwrap_or_else(|| panic!("no test key {name}"))
}

/// `text` as the binary shows a string of an artifact: quoted, printable
/// ASCII as is but `"` and `\` after a backslash, every other character
/// as `\u{X}`. Written here again, so a fault in the binary's cannot hide.
fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for character in text.chars() {
        match character {
            '"' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            ' '..='~' => out.push(character),
            other => out.push_str(&format!("\\u{{{:x}}}", u32::from(other))),
        }
    }
    out.push('"');
    out
}

/// Lowercase hexadecimal of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `hex` and its uppercase, whole and its first 16 digits.
fn forms(hex: &str) -> Vec<String> {
    vec![
        hex.to_owned(),
        hex.to_ascii_uppercase(),
        hex[..16].to_owned(),
        hex[..16].to_ascii_uppercase(),
    ]
}

/// Every test key's seed, in every form: never printed.
fn seed_needles() -> Vec<String> {
    list(&recovery_fixture(TEST_KEY_FIXTURE), "keys")
        .iter()
        .flat_map(|key| forms(text(key, "seed")))
        .collect()
}

/// Every signature of the signature fixture, and every test key's
/// signature over every challenge vector, in every form: never printed.
fn signature_needles() -> Vec<String> {
    let mut hexes: Vec<String> = list(&recovery_fixture(SIGNATURE_FIXTURE), "cases")
        .iter()
        .map(|case| text(case, "signature").to_owned())
        .filter(|signature| signature.len() >= 16)
        .collect();
    for vector in list(&recovery_fixture(CHALLENGE_FIXTURE), "vectors") {
        for name in ["recovery", "other"] {
            hexes.push(library_signature(vector, name));
        }
    }
    hexes.iter().flat_map(|hex| forms(hex)).collect()
}

/// The library's signature over `vector`'s challenge, its replacement
/// confirmed, by the test key `name`, in hexadecimal.
fn library_signature(vector: &Value, name: &str) -> String {
    let plan = &vector["plan"];
    let challenge = parse_challenge(&unhex(text(vector, "message_hex"))).unwrap();
    let new_key = RecoveryPublicKey::from_hex(text(plan, "new_recovery_public_key")).unwrap();
    let verified = check_challenge(
        &challenge,
        &Expectations {
            instance_id: text(plan, "instance_id"),
            now_micros: integer(vector, "expires_at") - 1,
            recovery_key_epoch: Some(integer(plan, "recovery_key_epoch")),
            replacement_public_identity: Some(text(plan, "public_identity")),
            trust_anchor_ref: Some(text(plan, "trust_anchor_ref")),
            new_recovery_public_key: Some(&new_key),
        },
    )
    .unwrap();
    hex(sign_challenge(&verified, &signer(name))
        .unwrap()
        .signature())
}

/// Runs the binary with `arguments` and no input, and checks what every
/// `sign` run must hold: an exit code from 0 to 3 (a panic is 101), output
/// in printable ASCII and newlines only, an error message on standard
/// error exactly when the code is not 0 and nothing on standard output
/// then, and no seed and no signature anywhere.
fn run_sign<S: AsRef<OsStr>>(arguments: &[S]) -> Run {
    let output = Command::new(BINARY)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .expect("the binary runs");
    let code = output.status.code().expect("the binary exits with a code");
    assert!((0..=3).contains(&code), "exit code {code}: {output:?}");
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            stream
                .iter()
                .all(|byte| matches!(byte, b' '..=b'~' | b'\n')),
            "a byte that is not printable ASCII: {output:?}"
        );
    }
    let run = Run {
        code,
        stdout: String::from_utf8(output.stdout).unwrap(),
        stderr: String::from_utf8(output.stderr).unwrap(),
    };
    assert_eq!(run.code == 0, run.stderr.is_empty(), "{run:?}");
    if run.code != 0 {
        assert!(run.stderr.starts_with("skyoauth-operator: "), "{run:?}");
        assert_eq!(run.stdout, "", "a failed sign prints nothing: {run:?}");
    }
    for needle in seed_needles().into_iter().chain(signature_needles()) {
        assert!(
            !run.stdout.contains(&needle) && !run.stderr.contains(&needle),
            "a seed or a signature is printed: {run:?}"
        );
    }
    run
}

/// Writes `bytes` to the seed file `name` in `dir`, of mode 0600 on Unix
/// (set explicitly, whatever the umask).
fn seed_file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.file(name, bytes);
    set_mode(&path, 0o600);
    path
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// The arguments of `sign` with `challenge`, `seed`, `out` and `flags`
/// (a vector's confirming flags).
fn sign_arguments(challenge: &Path, seed: &Path, flags: &[String], out: &Path) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = vec![
        "sign".into(),
        "--challenge".into(),
        challenge.into(),
        "--seed-file".into(),
        seed.into(),
        "--out".into(),
        out.into(),
    ];
    arguments.extend(flags.iter().map(OsString::from));
    arguments
}

/// `arguments` without the flag `flag` and its value.
fn without(mut arguments: Vec<OsString>, flag: &str) -> Vec<OsString> {
    let at = arguments.iter().position(|given| given == flag).unwrap();
    arguments.drain(at..at + 2);
    arguments
}

/// The end of a successful `sign --out`, after its clock line.
fn written(operation_id: &str) -> String {
    format!(
        "operation_id: {operation_id}\nreplacement_confirmed: yes\nresult: ok; the challenge is \
         signed, the response artifact is written to --out\n"
    )
}

/// op_1 and the recovery test key: a fresh directory, the challenge
/// artifact and the seed file.
struct Op1 {
    dir: TempDir,
    challenge: PathBuf,
    seed: PathBuf,
}

impl Op1 {
    fn new() -> Self {
        let dir = TempDir::new();
        let challenge = dir.file("challenge", &challenge_artifact(&vector("op_1")));
        let seed = seed_file(
            &dir,
            "seed",
            format!("{}\n", seed_hex("recovery")).as_bytes(),
        );
        Self {
            dir,
            challenge,
            seed,
        }
    }

    /// `sign` of op_1 with `seed`, the confirming flags changed by
    /// `change`, writing to `out`.
    fn sign_with(&self, seed: &Path, change: impl FnOnce(&mut Vec<String>), out: &Path) -> Run {
        let mut flags = confirming_flags(&vector("op_1"), NOW);
        change(&mut flags);
        run_sign(&sign_arguments(&self.challenge, seed, &flags, out))
    }

    /// The path `name` in the directory, which does not exist.
    fn out(&self, name: &str) -> PathBuf {
        let path = self.dir.0.join(name);
        assert!(fs::symlink_metadata(&path).is_err());
        path
    }
}

/// Every vector of the challenge fixture, its escapes and integer extremes
/// included, signed with the recovery test key's seed file: the response
/// artifact in the new `--out` file is byte for byte the library's response
/// ([`sign_challenge`], deterministic Ed25519) in the artifact's form, and
/// the file is of mode 0600 at most (Unix; the umask may remove bits);
/// op_1's is the signature fixture's `valid`. Each verifies with
/// `verify-response` and the recovery key, and not with another. The same
/// run gives the same artifact.
#[test]
fn sign_round_trip_of_every_challenge_vector() {
    let dir = TempDir::new();
    let seed = seed_file(&dir, "seed", seed_hex("recovery").as_bytes());
    let recovery_key = test_public_key("recovery");
    let vectors = list(&recovery_fixture(CHALLENGE_FIXTURE), "vectors").to_vec();
    assert!(vectors.len() >= 3);
    for vector in &vectors {
        let case = text(vector, "case");
        let now = integer(vector, "expires_at") - 1;
        let challenge = dir.file(&format!("{case}.challenge"), &challenge_artifact(vector));
        let flags = confirming_flags(vector, now);
        let expected =
            response_artifact(text(vector, "id"), &library_signature(vector, "recovery"));
        let expected = String::from_utf8(expected).unwrap();

        let operation_id = quoted(text(vector, "id"));
        let out = dir.0.join(format!("{case}.response"));
        for path in [&out, &dir.0.join(format!("{case}.again"))] {
            let run = run_sign(&sign_arguments(&challenge, &seed, &flags, path));
            assert_eq!(
                run,
                Run {
                    code: 0,
                    stdout: format!("clock: --now {now}\n{}", written(&operation_id)),
                    stderr: String::new(),
                },
                "{case}"
            );
            assert_eq!(fs::read_to_string(path).unwrap(), expected, "{case}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = fs::metadata(path).unwrap().permissions().mode() & 0o7777;
                assert_eq!(mode & !0o600, 0, "{case}: {mode:o}");
            }
        }

        let run = verify_response(&challenge, &out, &recovery_key);
        assert_eq!(run.code, 0, "{case}: {run:?}");
        let run = verify_response(&challenge, &out, &test_public_key("other"));
        assert_eq!(run.code, 1, "{case}: {run:?}");
    }
    let op_1 = dir.0.join("op_1.response");
    assert_eq!(
        fs::read(op_1).unwrap(),
        response_artifact("op_1", &fixture_signature("valid"))
    );
}

/// Every refusal of the challenge's check, `RecoveryKeyUnchanged` (the
/// seed of op_1's new recovery key), a challenge artifact that is not one
/// and one that cannot be read: the exit code and the fixed message,
/// nothing on standard output, and no `--out` file. The challenge is
/// checked before the seed file is read: a refused challenge is refused
/// as such even with a seed file of the wrong mode (Unix) or content.
#[test]
fn every_refusal_writes_nothing() {
    let op = Op1::new();
    for refusal in [
        Refusal::OtherInstance,
        Refusal::Expired,
        Refusal::ExpiresTooLate,
        Refusal::OtherEpoch,
        Refusal::OtherReplacementIdentity,
        Refusal::OtherTrustAnchor,
        Refusal::OtherNewRecoveryKey,
    ] {
        let (flag, value) = refusal_flags(refusal);
        let change = |flags: &mut Vec<String>| {
            let at = flags.iter().position(|given| given == flag).unwrap();
            flags[at + 1] = value.clone();
        };
        let expected = Run {
            code: 1,
            stdout: String::new(),
            stderr: format!("skyoauth-operator: refused ({refusal:?}): {refusal}\n"),
        };
        let out = op.out("response");
        assert_eq!(
            op.sign_with(&op.seed, change, &out),
            expected,
            "{refusal:?}"
        );
        assert!(fs::symlink_metadata(&out).is_err(), "{refusal:?}");
        // The seed file is not read for a refused challenge.
        let bad_seed = op.dir.file("bad_seed", b"not a seed");
        set_mode(&bad_seed, 0o644);
        assert_eq!(
            op.sign_with(&bad_seed, change, &out),
            expected,
            "{refusal:?}"
        );
        assert!(fs::symlink_metadata(&out).is_err(), "{refusal:?}");
        fs::remove_file(bad_seed).unwrap();
    }

    // The signer's key is the plan's new recovery key.
    let unchanged = seed_file(&op.dir, "unchanged", seed_hex("rfc8032_test1").as_bytes());
    assert_eq!(test_public_key("rfc8032_test1"), NEW_KEY);
    let out = op.out("response");
    assert_eq!(
        op.sign_with(&unchanged, |_| {}, &out),
        Run {
            code: 1,
            stdout: String::new(),
            stderr: "skyoauth-operator: refused (RecoveryKeyUnchanged): the challenge's new \
                     recovery public key is the signer's own key\n"
                .into(),
        }
    );
    assert!(fs::symlink_metadata(&out).is_err());

    // A challenge artifact that is not one, and one that is missing.
    let refusal = op.dir.file("refusal", b"{\"error\":\"conflict\"}\n");
    let missing = op.dir.0.join("missing");
    for (challenge, code, message) in [
        (
            &refusal,
            1,
            "the challenge artifact is a refusal of the local transport, not a challenge \
             (conflict: the stored state refuses the request)",
        ),
        (
            &missing,
            3,
            &*format!(
                "--challenge: the file cannot be read ({})",
                std::io::ErrorKind::NotFound
            ),
        ),
    ] {
        let flags = confirming_flags(&vector("op_1"), NOW);
        let run = run_sign(&sign_arguments(challenge, &op.seed, &flags, &out));
        assert_eq!(
            run,
            Run {
                code,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: {message}\n"),
            }
        );
        assert!(fs::symlink_metadata(&out).is_err());
    }
}

/// `sign` requires every expectation: the instance, the epoch and the
/// replacement's identity, trust anchor and new recovery key, with the
/// challenge, the seed file and the output file. One left out is a usage
/// error (exit 2), decided before any file is read: the challenge and the
/// seed file named here do not exist, and no output file is created.
#[test]
fn sign_requires_every_expectation() {
    let op = Op1::new();
    let all = sign_arguments(
        &op.dir.0.join("missing-challenge"),
        &op.dir.0.join("missing-seed"),
        &confirming_flags(&vector("op_1"), NOW),
        &op.out("response"),
    );
    for flag in [
        "--challenge",
        "--seed-file",
        "--out",
        "--instance-id",
        "--epoch",
        "--replacement-identity",
        "--trust-anchor",
        "--new-recovery-key",
    ] {
        assert_eq!(
            run_sign(&without(all.clone(), flag)),
            Run {
                code: 2,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: {flag} is required\n{HINT}"),
            },
            "{flag}"
        );
        assert!(fs::symlink_metadata(op.dir.0.join("response")).is_err());
    }
}

/// No flag takes the seed: a flag that would (`--seed`, `--key` and the
/// like) is unknown to `sign`, a seed given as an argument is not a flag,
/// and the value of `--seed-file` is a path (a seed there names a file
/// that does not exist). The environment is not read: a seed in it does
/// not replace `--seed-file`. No message repeats the seed (`run_sign`).
#[test]
fn no_flag_and_no_variable_takes_the_seed() {
    let op = Op1::new();
    let seed = seed_hex("recovery");
    let flags = confirming_flags(&vector("op_1"), NOW);
    let out = op.out("response");
    for flag in [
        "--seed",
        "--seed-hex",
        "--key",
        "--private-key",
        "--secret",
        "--response",
    ] {
        let mut arguments = sign_arguments(&op.challenge, &op.seed, &flags, &out);
        arguments.push(flag.into());
        arguments.push(seed.clone().into());
        assert_eq!(
            run_sign(&arguments),
            Run {
                code: 2,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: sign has no flag {flag}\n{HINT}"),
            },
            "{flag}"
        );
    }
    let mut arguments = sign_arguments(&op.challenge, &op.seed, &flags, &out);
    arguments.push(seed.clone().into());
    let position = arguments.len();
    assert_eq!(
        run_sign(&arguments),
        Run {
            code: 2,
            stdout: String::new(),
            stderr: format!("skyoauth-operator: argument {position} is not a flag of sign\n{HINT}"),
        }
    );
    assert_eq!(
        run_sign(&sign_arguments(
            &op.challenge,
            Path::new(&seed),
            &flags,
            &out
        )),
        Run {
            code: 3,
            stdout: String::new(),
            stderr: format!(
                "skyoauth-operator: --seed-file: the file cannot be read ({})\n",
                std::io::ErrorKind::NotFound
            ),
        }
    );
    let arguments = without(
        sign_arguments(&op.challenge, &op.seed, &flags, &out),
        "--seed-file",
    );
    for variable in [
        "SKYOAUTH_SEED",
        "SKYOAUTH_OPERATOR_SEED",
        "SKYOAUTH_SEED_FILE",
        "SEED",
    ] {
        let value: &OsStr = if variable.ends_with("_FILE") {
            op.seed.as_os_str()
        } else {
            OsStr::new(&seed)
        };
        let output = Command::new(BINARY)
            .args(&arguments)
            .env(variable, value)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{variable}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("skyoauth-operator: --seed-file is required\n{HINT}"),
            "{variable}"
        );
        assert!(output.stdout.is_empty());
    }
    assert!(fs::symlink_metadata(&out).is_err());
}

/// The other usage errors of `sign`, and its help.
#[test]
fn sign_usage_errors_and_help() {
    let op = Op1::new();
    let flags = confirming_flags(&vector("op_1"), NOW);
    let out = op.out("response");
    // Without `--out`, so that each case can give it.
    let base = without(
        sign_arguments(&op.challenge, &op.seed, &flags, &out),
        "--out",
    );
    let with = |extra: &[&str]| {
        let mut arguments = base.clone();
        arguments.extend(extra.iter().map(OsString::from));
        arguments
    };
    for (arguments, message) in [
        (
            with(&["--seed-file", "other"]),
            "--seed-file is given more than once",
        ),
        (with(&["--out"]), "--out needs a value"),
        (with(&["--out", ""]), "--out has an empty value"),
        (with(&["--out", "--now"]), "--out needs a value"),
        (
            with(&["--out", "x", "--out", "y"]),
            "--out is given more than once",
        ),
        (with(&["help"]), "argument 18 is not a flag of sign"),
    ] {
        assert_eq!(
            run_sign(&arguments),
            Run {
                code: 2,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: {message}\n{HINT}"),
            },
            "{arguments:?}"
        );
    }
    assert!(fs::symlink_metadata(&out).is_err());
    let help = run_sign(&["--help"]);
    assert_eq!(help.code, 0);
    assert!(
        help.stdout
            .contains("skyoauth-operator sign --challenge FILE --seed-file FILE --out FILE")
            && help.stdout.contains("On Windows its protection is NOT")
            && help
                .stdout
                .contains("never\ninstall this binary setuid or setgid"),
        "{help:?}"
    );
    for arguments in [vec!["sign", "--help"], vec!["sign", "-h"]] {
        assert_eq!(run_sign(&arguments), help, "{arguments:?}");
    }
    assert_eq!(run_sign(&with(&["-h"])), help);
}

/// The content of the seed file, on every platform: 64 lowercase
/// hexadecimal digits and at most one newline. Any other content of at
/// most 128 bytes is one refusal, exit 1, "not a seed"; a larger file is
/// exit 3, too large. Each message is fixed and repeats no byte of the
/// file, and nothing is written.
#[test]
fn seed_file_content() {
    let op = Op1::new();
    let seed = seed_hex("recovery");
    let not_a_seed = "skyoauth-operator: --seed-file: the file is not a seed: 64 lowercase \
                      hexadecimal digits, optionally followed by one newline\n";
    let too_large = "skyoauth-operator: --seed-file: the file is larger than 128 bytes\n";
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("empty", Vec::new(), not_a_seed),
        ("newline", b"\n".to_vec(), not_a_seed),
        ("short", seed.as_bytes()[..62].to_vec(), not_a_seed),
        ("odd", seed.as_bytes()[..63].to_vec(), not_a_seed),
        (
            "odd_newline",
            format!("{}\n", &seed[..63]).into_bytes(),
            not_a_seed,
        ),
        ("long", format!("{seed}0").into_bytes(), not_a_seed),
        ("longer", format!("{seed}00").into_bytes(), not_a_seed),
        ("twice", format!("{seed}\n{seed}").into_bytes(), too_large),
        ("doubled", format!("{seed}{seed}").into_bytes(), not_a_seed),
        ("at_cap", vec![b'0'; 128], not_a_seed),
        ("over_cap", vec![b'0'; 129], too_large),
        ("bom", format!("\u{feff}{seed}").into_bytes(), not_a_seed),
        (
            "bom_newline",
            format!("\u{feff}{seed}\n").into_bytes(),
            not_a_seed,
        ),
        (
            "uppercase",
            seed.to_ascii_uppercase().into_bytes(),
            not_a_seed,
        ),
        (
            "one_uppercase",
            format!("{}A{}", &seed[..10], &seed[11..]).into_bytes(),
            not_a_seed,
        ),
        (
            "non_hex",
            format!("{}g{}", &seed[..10], &seed[11..]).into_bytes(),
            not_a_seed,
        ),
        (
            "trailing_garbage",
            format!("{seed}x").into_bytes(),
            not_a_seed,
        ),
        (
            "trailing_space",
            format!("{seed} ").into_bytes(),
            not_a_seed,
        ),
        ("leading_space", format!(" {seed}").into_bytes(), not_a_seed),
        (
            "two_newlines",
            format!("{seed}\n\n").into_bytes(),
            not_a_seed,
        ),
        ("crlf", format!("{seed}\r\n").into_bytes(), not_a_seed),
        ("cr", format!("{seed}\r").into_bytes(), not_a_seed),
        ("raw", unhex(&seed), not_a_seed),
        (
            "prefixed",
            format!("0x{}", &seed[2..]).into_bytes(),
            not_a_seed,
        ),
        (
            "sentinel",
            b"SENTINEL-not-a-seed-SENTINEL-not-a-seed-SENTINEL-not-a-seed-SENT".to_vec(),
            not_a_seed,
        ),
        ("big", vec![b'0'; 4096], too_large),
    ];
    for (name, bytes, message) in cases {
        let path = seed_file(&op.dir, name, &bytes);
        let out = op.out("response");
        let run = op.sign_with(&path, |_| {}, &out);
        let code = if message == too_large { 3 } else { 1 };
        assert_eq!(
            run,
            Run {
                code,
                stdout: String::new(),
                stderr: message.to_owned(),
            },
            "{name}"
        );
        assert!(!run.stderr.contains("SENTINEL"), "{name}");
        assert!(fs::symlink_metadata(&out).is_err(), "{name}");
    }
    // Accepted: with and without its newline.
    for (name, bytes) in [
        ("plain", seed.clone().into_bytes()),
        ("with_newline", format!("{seed}\n").into_bytes()),
    ] {
        let path = seed_file(&op.dir, name, &bytes);
        let out = op.out(&format!("{name}.response"));
        let run = op.sign_with(&path, |_| {}, &out);
        assert_eq!(run.code, 0, "{name}: {run:?}");
        assert_eq!(
            fs::read(&out).unwrap(),
            response_artifact("op_1", &fixture_signature("valid"))
        );
    }
}

/// The seed file's checks on Unix: a regular file (not a directory, a
/// named pipe or a device, refused without being opened), not a symbolic
/// link (even to a good seed file), of mode 0600 exactly, owned by the
/// effective user (tried only as root, which can give the file another
/// owner; a NOTICE otherwise). Each is exit 3 with a fixed message, and
/// nothing is written. Runs as root and as another user.
#[cfg(unix)]
#[test]
fn seed_file_protection_on_unix() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let op = Op1::new();
    let io = |path: &Path, message: &str| {
        let out = op.out("response");
        assert_eq!(
            op.sign_with(path, |_| {}, &out),
            Run {
                code: 3,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: --seed-file: {message}\n"),
            },
            "{}",
            path.display()
        );
        assert!(fs::symlink_metadata(&out).is_err());
    };
    let seed = format!("{}\n", seed_hex("recovery"));

    for mode in [
        0o644, 0o640, 0o604, 0o660, 0o666, 0o400, 0o200, 0o700, 0o610, 0o601, 0o000,
    ] {
        let path = seed_file(&op.dir, &format!("mode{mode:o}"), seed.as_bytes());
        set_mode(&path, mode);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            mode
        );
        io(&path, "the file's mode is not exactly 0600");
    }

    let link = op.dir.0.join("link");
    std::os::unix::fs::symlink(&op.seed, &link).unwrap();
    io(&link, "a symbolic link, not the file itself");
    let dangling = op.dir.0.join("dangling");
    std::os::unix::fs::symlink(op.dir.0.join("nowhere"), &dangling).unwrap();
    io(&dangling, "a symbolic link, not the file itself");

    let directory = op.dir.0.join("directory");
    fs::create_dir(&directory).unwrap();
    set_mode(&directory, 0o600);
    io(&directory, "not a regular file");
    set_mode(&directory, 0o700);

    io(Path::new("/dev/null"), "not a regular file");

    let pipe = op.dir.0.join("pipe");
    match Command::new("mkfifo").arg(&pipe).status() {
        Ok(status) if status.success() => {
            set_mode(&pipe, 0o600);
            // `run_sign` waits for the binary: a binary that opened the
            // pipe would block here, and the test would time out.
            io(&pipe, "not a regular file");
        }
        _ => eprintln!("NOTICE: no mkfifo: the named pipe case was NOT tried"),
    }

    // Another owner: only root can make one.
    let owned = seed_file(&op.dir, "owned", seed.as_bytes());
    if fs::metadata(&owned).unwrap().uid() == 0 {
        std::os::unix::fs::lchown(&owned, Some(65_534), None).unwrap();
        io(&owned, "the file is not owned by the effective user");
        // A link owned by root to that file is a link still.
        let to_owned = op.dir.0.join("to_owned");
        std::os::unix::fs::symlink(&owned, &to_owned).unwrap();
        io(&to_owned, "a symbolic link, not the file itself");
    } else {
        eprintln!("NOTICE: not root: the other-owner case was NOT tried");
    }

    // The good seed file is still accepted.
    assert_eq!(op.sign_with(&op.seed, |_| {}, &op.out("response")).code, 0);
}

/// `--out` is created new: an existing file (left unchanged), a symbolic
/// link and a directory (Unix; a dangling link's target is not created)
/// are refused, exit 3, and so is a path in a directory that does not
/// exist; the signature is not printed instead.
#[test]
fn out_is_created_new_or_not_at_all() {
    let op = Op1::new();
    let exists = op.dir.file("exists", b"keep me\n");
    let exists_message = "--out: the file already exists; it is never overwritten";
    let io = |out: &Path, message: &str| {
        assert_eq!(
            op.sign_with(&op.seed, |_| {}, out),
            Run {
                code: 3,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: {message}\n"),
            },
            "{}",
            out.display()
        );
    };
    io(&exists, exists_message);
    assert_eq!(fs::read(&exists).unwrap(), b"keep me\n");
    io(&op.challenge, exists_message);
    assert_eq!(
        fs::read(&op.challenge).unwrap(),
        challenge_artifact(&vector("op_1"))
    );
    io(
        &op.dir.0.join("no-such-directory").join("response"),
        &format!(
            "--out: the file cannot be created ({})",
            std::io::ErrorKind::NotFound
        ),
    );
    #[cfg(unix)]
    {
        io(&op.dir.0, exists_message);
        let target = op.dir.0.join("target");
        let dangling = op.dir.0.join("dangling");
        std::os::unix::fs::symlink(&target, &dangling).unwrap();
        io(&dangling, exists_message);
        assert!(fs::symlink_metadata(&target).is_err());
        let link = op.dir.0.join("link");
        std::os::unix::fs::symlink(&exists, &link).unwrap();
        io(&link, exists_message);
        assert_eq!(fs::read(&exists).unwrap(), b"keep me\n");
    }
    // A new path is written.
    let out = op.out("response");
    assert_eq!(op.sign_with(&op.seed, |_| {}, &out).code, 0);
    assert_eq!(
        fs::read(&out).unwrap(),
        response_artifact("op_1", &fixture_signature("valid"))
    );
}

/// A summary that cannot be written to standard output (a pipe whose
/// reading end is closed) is exit 3, never 0, after the response was
/// written to `--out`; the signature is not shown on standard error.
#[test]
fn a_summary_that_cannot_be_written_is_exit_3() {
    let op = Op1::new();
    let flags = confirming_flags(&vector("op_1"), NOW);
    let out = op.out("response");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = Command::new(BINARY)
        .args(sign_arguments(&op.challenge, &op.seed, &flags, &out))
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.starts_with("skyoauth-operator: the output cannot be written (")
            && stderr.lines().count() == 1,
        "{stderr}"
    );
    for needle in signature_needles().into_iter().chain(seed_needles()) {
        assert!(!stderr.contains(&needle), "{stderr}");
    }
    assert_eq!(
        fs::read(&out).unwrap(),
        response_artifact("op_1", &fixture_signature("valid"))
    );
}

/// A write to `--out` that fails is exit 3 with its message, and leaves an
/// empty file (Unix: the binary runs under `ulimit -f 0`, with `SIGXFSZ`
/// ignored, so its write of the response fails with `EFBIG`). Nothing is
/// printed on standard output and no signature anywhere. Without `sh`, the
/// test says so and passes.
#[cfg(unix)]
#[test]
fn an_out_write_that_fails_is_exit_3() {
    let op = Op1::new();
    let flags = confirming_flags(&vector("op_1"), NOW);
    let out = op.out("response");
    let script = r#"trap "" XFSZ; ulimit -f 0 || exit 99; exec "$0" "$@""#;
    let Ok(output) = Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(BINARY)
        .args(sign_arguments(&op.challenge, &op.seed, &flags, &out))
        .stdin(Stdio::null())
        .output()
    else {
        eprintln!("NOTICE: no sh: the failing --out write was NOT tried");
        return;
    };
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(3), "{stdout}{stderr}");
    assert_eq!(stdout, "");
    assert_eq!(
        stderr,
        format!(
            "skyoauth-operator: --out: the file cannot be written ({})\n",
            std::io::ErrorKind::FileTooLarge
        )
    );
    for needle in signature_needles().into_iter().chain(seed_needles()) {
        assert!(!stderr.contains(&needle), "{stderr}");
    }
    assert_eq!(fs::read(&out).unwrap(), b"");
}
