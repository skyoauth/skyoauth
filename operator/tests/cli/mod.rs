//! The `skyoauth-operator` binary (`operator/src/bin/skyoauth-operator/`),
//! run as a process on files in a fresh temporary directory: the challenge
//! artifact (the `issue_challenge` reply line) of every vector of
//! `tests/conformance/fixtures/_recovery/challenge.v1.json`, the response
//! artifact of every case of `signature.v1.json`, every refusal, every
//! usage error, the file errors and their size limits, and malformed
//! artifacts that must be refused without a panic
//! (docs/proposals/operator-cli-artifacts.md). `sign` is in [`sign`].
//!
//! Every run is checked for what it must never do: end in another exit
//! code than 0 to 4 (a panic is 101), print a byte that is not printable
//! ASCII or a newline (an artifact's control character must not reach the
//! terminal), or print a signature or a seed.
//!
//! Portable: the Unix-only cases are gated.

mod sign;

use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use skyoauth_operator::{
    local::{MAX_REPLY_BYTES, MAX_REQUEST_BYTES, Op, Reply, parse_reply},
    recovery::{
        Expectations, MAX_CHALLENGE_TTL, RecoveryPublicKey, Refusal, check_challenge,
        parse_challenge, sign_challenge,
    },
};

use crate::{
    challenge::CHALLENGE_FIXTURE,
    signature::{SIGNATURE_FIXTURE, TEST_KEY_FIXTURE, signer},
    support::{list, recovery_fixture, text, unhex},
};

/// The binary under test, built by cargo for this target.
const BINARY: &str = env!("CARGO_BIN_EXE_skyoauth-operator");

/// op_1's instance, expiry and new recovery key.
const INSTANCE: &str = "01936f4e-8a2b-7c3d-9e4f-0123456789ab";
const EXPIRES_AT: i64 = 1_790_000_300_000_000;
const NEW_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// A valid key that is none of the plan's or the test keys'.
const OTHER_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// A time at which op_1 is live: 5 minutes before its expiry.
const NOW: i64 = EXPIRES_AT - 300_000_000;

/// The usage hint after every usage error.
const HINT: &str = "Run `skyoauth-operator --help` for the usage.\n";

/// A fresh directory under the system's temporary directory, removed when
/// dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "skyoauth-operator-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    /// Writes `bytes` to the file `name` in the directory, and returns its
    /// path.
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A finished run of the binary.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Bytes the binary must never print: the test keys' seeds and every
/// signature of the signature fixture, in lowercase and uppercase
/// hexadecimal, whole and their first 8 bytes.
fn secrets() -> Vec<String> {
    let mut hexes: Vec<String> = list(&recovery_fixture(TEST_KEY_FIXTURE), "keys")
        .iter()
        .map(|key| text(key, "seed").to_owned())
        .collect();
    hexes.extend(
        list(&recovery_fixture(SIGNATURE_FIXTURE), "cases")
            .iter()
            .map(|case| text(case, "signature").to_owned())
            .filter(|signature| signature.len() >= 16),
    );
    let mut needles = Vec::new();
    for hex in hexes {
        needles.push(hex[..16].to_owned());
        needles.push(hex[..16].to_ascii_uppercase());
        needles.push(hex.to_ascii_uppercase());
        needles.push(hex);
    }
    needles
}

/// Runs the binary with `arguments` and no input, and checks what every
/// run must hold: an exit code from 0 to 4, output in printable ASCII and
/// newlines only, an error message on standard error exactly when the
/// code is not 0, and no secret.
fn run<S: AsRef<OsStr>>(arguments: &[S]) -> Run {
    run_in(None, arguments)
}

/// [`run`] in the working directory `dir`, when given.
fn run_in<S: AsRef<OsStr>>(dir: Option<&Path>, arguments: &[S]) -> Run {
    let mut command = Command::new(BINARY);
    command.args(arguments).stdin(Stdio::null());
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let output = command.output().expect("the binary runs");
    let code = output.status.code().expect("the binary exits with a code");
    assert!((0..=4).contains(&code), "exit code {code}: {output:?}");
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
    }
    for needle in secrets() {
        assert!(
            !run.stdout.contains(&needle) && !run.stderr.contains(&needle),
            "a secret or a signature is printed: {run:?}"
        );
    }
    run
}

/// Runs the binary with `arguments`, a path among them.
fn run_with(arguments: &[&dyn AsRef<OsStr>]) -> Run {
    let arguments: Vec<&OsStr> = arguments.iter().map(|argument| argument.as_ref()).collect();
    run(&arguments)
}

/// The vector `case` of the challenge fixture.
fn vector(case: &str) -> Value {
    list(&recovery_fixture(CHALLENGE_FIXTURE), "vectors")
        .iter()
        .find(|vector| text(vector, "case") == case)
        .unwrap_or_else(|| panic!("no vector {case}"))
        .clone()
}

fn integer(value: &Value, name: &str) -> i64 {
    value[name].as_i64().unwrap()
}

/// The challenge artifact of a vector: the `issue_challenge` reply line
/// the service sends for it (members in the service's order, the
/// operation ID escaped by `serde_json` as the service escapes it).
fn challenge_artifact(vector: &Value) -> Vec<u8> {
    format!(
        "{{\"operation_id\":{},\"expires_at\":{},\"expected_revision\":{},\"challenge\":\"{}\"}}\n",
        serde_json::to_string(text(vector, "id")).unwrap(),
        integer(vector, "expires_at"),
        integer(vector, "expected_revision"),
        text(vector, "message_hex"),
    )
    .into_bytes()
}

/// A response artifact of `operation_id` and the signature `hex`.
fn response_artifact(operation_id: &str, hex: &str) -> Vec<u8> {
    format!(
        "{{\"operation_id\":{},\"signature\":\"{hex}\"}}\n",
        serde_json::to_string(operation_id).unwrap()
    )
    .into_bytes()
}

/// The public key of the test key `name`.
fn test_public_key(name: &str) -> String {
    list(&recovery_fixture(TEST_KEY_FIXTURE), "keys")
        .iter()
        .find(|key| text(key, "name") == name)
        .map(|key| text(key, "public_key").to_owned())
        .unwrap_or_else(|| panic!("no test key {name}"))
}

/// The signature of the signature fixture's case `name`.
fn fixture_signature(name: &str) -> String {
    list(&recovery_fixture(SIGNATURE_FIXTURE), "cases")
        .iter()
        .find(|case| text(case, "case") == name)
        .map(|case| text(case, "signature").to_owned())
        .unwrap_or_else(|| panic!("no signature case {name}"))
}

/// The `verify-challenge` flags of a vector's plan, all of them.
fn confirming_flags(vector: &Value, now: i64) -> Vec<String> {
    let plan = &vector["plan"];
    [
        "--instance-id",
        text(plan, "instance_id"),
        "--epoch",
        &integer(plan, "recovery_key_epoch").to_string(),
        "--replacement-identity",
        text(plan, "public_identity"),
        "--trust-anchor",
        text(plan, "trust_anchor_ref"),
        "--new-recovery-key",
        text(plan, "new_recovery_public_key"),
        "--now",
        &now.to_string(),
    ]
    .map(String::from)
    .to_vec()
}

/// `verify-challenge --challenge <path>` and `flags`.
fn verify_challenge<S: AsRef<str>>(path: &Path, flags: &[S]) -> Run {
    let mut arguments: Vec<OsString> = vec!["verify-challenge".into(), "--challenge".into()];
    arguments.push(path.into());
    arguments.extend(flags.iter().map(|flag| OsString::from(flag.as_ref())));
    run(&arguments)
}

/// `verify-response` of the files at `challenge` and `response` with
/// `key`.
fn verify_response(challenge: &Path, response: &Path, key: &str) -> Run {
    run_with(&[
        &"verify-response",
        &"--challenge",
        &challenge,
        &"--response",
        &response,
        &"--key",
        &key,
    ])
}

/// op_1's plan lines, as the binary prints them after its clock line.
const OP_1_PLAN: &str = "\
operation_id: \"op_1\"
expected_revision: 1
expires_at: 1790000300000000
instance_id: \"01936f4e-8a2b-7c3d-9e4f-0123456789ab\"
recovery_key_epoch: 1
admin_id: \"adm_new\"
credential_id: \"crd_new\"
binding_id: \"rb_new\"
public_identity: \"spki-sha256:new\"
trust_anchor_ref: \"deployment/operator-ca\"
new_recovery_public_key: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
";

/// The end of a confirmed `verify-challenge`.
const CONFIRMED: &str =
    "replacement_confirmed: yes\nresult: ok; every check passed, the replacement is confirmed\n";

const NOT_CHECKED: &str =
    "not checked (generated by the service): admin_id, credential_id, binding_id\n";

/// op_1 checked with every flag: the whole output, the replacement
/// confirmed, exit 0. With the instance and the epoch alone, or any one of
/// the replacement's three values left out: every given check passed, but
/// the replacement is not confirmed, exit 4, and the output names what was
/// not given. Each time the clock given by `--now` is printed.
#[test]
fn verify_challenge_prints_the_plan_and_the_confirmation() {
    let dir = TempDir::new();
    let path = dir.file("challenge", &challenge_artifact(&vector("op_1")));

    let confirmed = verify_challenge(&path, &confirming_flags(&vector("op_1"), NOW));
    assert_eq!(
        confirmed,
        Run {
            code: 0,
            stdout: format!(
                "clock: --now {NOW}\n{OP_1_PLAN}given: instance_id, expires_at, \
                 recovery_key_epoch, public_identity, trust_anchor_ref, \
                 new_recovery_public_key\n{NOT_CHECKED}{CONFIRMED}"
            ),
            stderr: String::new(),
        }
    );

    let partial = verify_challenge(
        &path,
        &[
            "--instance-id",
            INSTANCE,
            "--epoch",
            "1",
            "--now",
            &NOW.to_string(),
        ],
    );
    let not_given = "--replacement-identity, --trust-anchor, --new-recovery-key";
    assert_eq!(
        partial,
        Run {
            code: 4,
            stdout: format!(
                "clock: --now {NOW}\n{OP_1_PLAN}given: instance_id, expires_at, \
                 recovery_key_epoch\n{NOT_CHECKED}replacement_confirmed: no (not given: \
                 {not_given})\nresult: not confirmed; every given check passed, but the \
                 replacement is not confirmed\n"
            ),
            stderr: format!(
                "skyoauth-operator: not confirmed: the replacement is not confirmed (not given: \
                 {not_given})\n"
            ),
        }
    );

    // Any two of the three are not a confirmation.
    let all = confirming_flags(&vector("op_1"), NOW);
    for left_out in [
        "--replacement-identity",
        "--trust-anchor",
        "--new-recovery-key",
    ] {
        let at = all.iter().position(|flag| flag == left_out).unwrap();
        let mut flags = all.clone();
        flags.drain(at..at + 2);
        let run = verify_challenge(&path, &flags);
        assert_eq!(run.code, 4, "{left_out}: {run:?}");
        assert!(
            run.stdout.contains(&format!(
                "\nreplacement_confirmed: no (not given: {left_out})\n"
            )) && !run.stdout.contains("replacement_confirmed: yes"),
            "{left_out}: {run:?}"
        );
        assert_eq!(
            run.stderr,
            format!(
                "skyoauth-operator: not confirmed: the replacement is not confirmed (not given: \
                 {left_out})\n"
            ),
            "{left_out}"
        );
    }

    // The same run gives the same output.
    assert_eq!(
        verify_challenge(&path, &confirming_flags(&vector("op_1"), NOW)),
        confirmed
    );
}

/// The refusal `refusal` of op_1 and the flags that cause it: one value
/// changed from the confirming flags. The match is exhaustive, so a new
/// refusal does not compile until it has a case.
fn refusal_flags(refusal: Refusal) -> (&'static str, String) {
    match refusal {
        Refusal::OtherInstance => (
            "--instance-id",
            "01936f4e-8a2b-7c3d-9e4f-0123456789ac".into(),
        ),
        Refusal::Expired => ("--now", EXPIRES_AT.to_string()),
        Refusal::ExpiresTooLate => (
            "--now",
            (EXPIRES_AT - i64::try_from(MAX_CHALLENGE_TTL.as_micros()).unwrap() - 1).to_string(),
        ),
        Refusal::OtherEpoch => ("--epoch", "2".into()),
        Refusal::OtherReplacementIdentity => ("--replacement-identity", "spki-sha256:old".into()),
        Refusal::OtherTrustAnchor => ("--trust-anchor", "deployment/other-ca".into()),
        Refusal::OtherNewRecoveryKey => ("--new-recovery-key", OTHER_KEY.into()),
    }
}

/// Every refusal of `check_challenge`, reached through the binary: exit 1,
/// the plan and `result: refused (<name>)` on standard output, and the
/// fixed message on standard error. A value one step inside each bound is
/// accepted.
#[test]
fn every_refusal_is_exit_1_with_its_message() {
    let dir = TempDir::new();
    let path = dir.file("challenge", &challenge_artifact(&vector("op_1")));
    let all = confirming_flags(&vector("op_1"), NOW);
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
        let mut flags = all.clone();
        let at = flags.iter().position(|given| given == flag).unwrap();
        flags[at + 1] = value;
        let run = verify_challenge(&path, &flags);
        assert_eq!(run.code, 1, "{refusal:?}: {run:?}");
        assert!(
            run.stdout.contains(OP_1_PLAN)
                && run
                    .stdout
                    .ends_with(&format!("result: refused ({refusal:?})\n"))
                && !run.stdout.contains("replacement_confirmed"),
            "{refusal:?}: {run:?}"
        );
        assert_eq!(
            run.stderr,
            format!("skyoauth-operator: refused ({refusal:?}): {refusal}\n"),
            "{refusal:?}"
        );
    }
    // One step inside the clock's bounds.
    let ttl = i64::try_from(MAX_CHALLENGE_TTL.as_micros()).unwrap();
    for now in [EXPIRES_AT - 1, EXPIRES_AT - ttl] {
        let run = verify_challenge(&path, &confirming_flags(&vector("op_1"), now));
        assert_eq!(run.code, 0, "{now}: {run:?}");
        assert!(run.stdout.starts_with(&format!("clock: --now {now}\n")));
    }
}

/// Without `--now`, the system clock is used and printed, and decides the
/// result as `check_challenge` does at that time.
#[test]
fn without_now_the_system_clock_is_used_and_printed() {
    let dir = TempDir::new();
    let path = dir.file("challenge", &challenge_artifact(&vector("op_1")));
    let micros = || {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros(),
        )
        .unwrap()
    };
    let before = micros();
    let run = verify_challenge(&path, &["--instance-id", INSTANCE, "--epoch", "1"]);
    let after = micros();
    let clock: i64 = run
        .stdout
        .strip_prefix("clock: system ")
        .and_then(|rest| rest.split_once('\n'))
        .and_then(|(micros, _)| micros.parse().ok())
        .unwrap_or_else(|| panic!("no system clock line: {run:?}"));
    assert!(
        before <= clock && clock <= after,
        "{before} {clock} {after}"
    );
    let challenge = parse_challenge(&unhex(text(&vector("op_1"), "message_hex"))).unwrap();
    let expected = check_challenge(
        &challenge,
        &Expectations {
            instance_id: INSTANCE,
            now_micros: clock,
            recovery_key_epoch: Some(1),
            replacement_public_identity: None,
            trust_anchor_ref: None,
            new_recovery_public_key: None,
        },
    );
    match expected {
        // Checked, but not confirmed: the replacement's values are not given.
        Ok(_) => assert_eq!(run.code, 4, "{run:?}"),
        Err(refusal) => {
            assert_eq!(run.code, 1, "{run:?}");
            assert_eq!(
                run.stderr,
                format!("skyoauth-operator: refused ({refusal:?}): {refusal}\n")
            );
        }
    }
}

/// Every vector of the challenge fixture, its escapes and integer extremes
/// included, as a challenge artifact: checked with all its plan's values,
/// signed by the recovery test key (through the library), and its response
/// artifact verified with that key, and refused with another.
#[test]
fn round_trip_of_every_challenge_vector() {
    let dir = TempDir::new();
    let recovery_key = test_public_key("recovery");
    let other_key = test_public_key("other");
    let vectors = list(&recovery_fixture(CHALLENGE_FIXTURE), "vectors").to_vec();
    assert!(vectors.len() >= 3);
    for vector in &vectors {
        let case = text(vector, "case");
        let now = integer(vector, "expires_at") - 1;
        let challenge_path = dir.file(&format!("{case}.challenge"), &challenge_artifact(vector));
        let run = verify_challenge(&challenge_path, &confirming_flags(vector, now));
        assert_eq!(run.code, 0, "{case}: {run:?}");
        assert!(run.stdout.ends_with(CONFIRMED), "{case}: {run:?}");

        let challenge = parse_challenge(&unhex(text(vector, "message_hex"))).unwrap();
        let new_key =
            RecoveryPublicKey::from_hex(text(&vector["plan"], "new_recovery_public_key")).unwrap();
        let verified = check_challenge(
            &challenge,
            &Expectations {
                instance_id: text(&vector["plan"], "instance_id"),
                now_micros: now,
                recovery_key_epoch: None,
                replacement_public_identity: Some(text(&vector["plan"], "public_identity")),
                trust_anchor_ref: Some(text(&vector["plan"], "trust_anchor_ref")),
                new_recovery_public_key: Some(&new_key),
            },
        )
        .unwrap();
        let response = sign_challenge(&verified, &signer("recovery")).unwrap();
        let hex: String = response
            .signature()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let response_path = dir.file(
            &format!("{case}.response"),
            &response_artifact(response.operation_id(), &hex),
        );
        let run = verify_response(&challenge_path, &response_path, &recovery_key);
        assert_eq!(run.code, 0, "{case}: {run:?}");
        assert!(
            run.stdout.ends_with(
                "\nresult: ok; the signature verifies with the given recovery public key over \
                 the challenge (verify_strict)\n"
            ) && !run.stdout.contains(&hex),
            "{case}: {run:?}"
        );
        let refused = verify_response(&challenge_path, &response_path, &other_key);
        assert_eq!(
            refused,
            Run {
                code: 1,
                stdout: String::new(),
                stderr: "skyoauth-operator: refused (NotVerified): the signature does not \
                         verify with the recovery public key over the challenge\n"
                    .into(),
            },
            "{case}"
        );
    }
}

/// The escapes vector's strings reach the terminal quoted, every
/// character outside printable ASCII escaped (`run` checks that no other
/// byte is printed).
#[test]
fn artifact_strings_are_shown_escaped() {
    let dir = TempDir::new();
    let escapes = vector("escapes");
    let path = dir.file("challenge", &challenge_artifact(&escapes));
    let run = verify_challenge(
        &path,
        &confirming_flags(&escapes, integer(&escapes, "expires_at") - 1),
    );
    assert_eq!(run.code, 0, "{run:?}");
    assert!(
        run.stdout
            .contains("operation_id: \"op_\\\"\\\\\\u{e9}\"\n"),
        "{run:?}"
    );
    assert!(
        run.stdout.contains(
            "binding_id: \"rb_\\u{8}\\u{9}\\u{a}\\u{c}\\u{d}\\u{0}\\u{1}\\u{1f}\\u{7f}/\"\n"
        ),
        "{run:?}"
    );
}

/// Every case of the signature fixture as a response artifact over op_1,
/// verified with the recovery test key: exit 0 for `valid`, else exit 1
/// with the class's refusal, and no signature printed either way (`run`).
/// The valid signature with any other key is refused, and so is a response
/// for another operation.
#[test]
fn verify_response_of_every_signature_case() {
    let dir = TempDir::new();
    let challenge = dir.file("challenge", &challenge_artifact(&vector("op_1")));
    let recovery_key = test_public_key("recovery");
    let not_verified = "skyoauth-operator: refused (NotVerified): the signature does not verify \
                        with the recovery public key over the challenge\n";
    for case in list(&recovery_fixture(SIGNATURE_FIXTURE), "cases") {
        let name = text(case, "case");
        let response = dir.file(name, &response_artifact("op_1", text(case, "signature")));
        let run = verify_response(&challenge, &response, &recovery_key);
        let expected = match text(case, "expected") {
            "valid" => (0, ""),
            "length" => (
                1,
                "skyoauth-operator: refused (Length): the signature is not 64 bytes\n",
            ),
            "not_verified" => (1, not_verified),
            other => panic!("{name}: class {other}"),
        };
        assert_eq!((run.code, run.stderr.as_str()), expected, "{name}: {run:?}");
        if run.code != 0 {
            assert_eq!(run.stdout, "", "{name}");
        }
    }

    let valid = dir.file(
        "valid",
        &response_artifact("op_1", &fixture_signature("valid")),
    );
    for key in [test_public_key("other"), NEW_KEY.into(), OTHER_KEY.into()] {
        let run = verify_response(&challenge, &valid, &key);
        assert_eq!((run.code, run.stderr.as_str()), (1, not_verified), "{key}");
    }
    let other_operation = dir.file(
        "other_operation",
        &response_artifact("op_2", &fixture_signature("valid")),
    );
    assert_eq!(
        verify_response(&challenge, &other_operation, &recovery_key),
        Run {
            code: 1,
            stdout: String::new(),
            stderr: "skyoauth-operator: refused (OtherOperation): the response is for another \
                     operation than the challenge\n"
                .into(),
        }
    );
}

/// The command line's refusals: exit 2, a fixed message that repeats no
/// value, and the usage hint. Nothing is read: the challenge path does not
/// exist, so a run that reads it would end in exit 3.
#[test]
fn usage_errors_are_exit_2() {
    let missing = "no-such-challenge";
    let key = test_public_key("recovery");
    let key = key.as_str();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec![], "no command given"),
        (vec!["verify"], "unknown command (argument 1)"),
        (vec!["VERIFY-CHALLENGE"], "unknown command (argument 1)"),
        (vec!["sign"], "--challenge is required"),
        (
            vec!["sign", "--challenge", missing],
            "--seed-file is required",
        ),
        (vec!["verify-challenge"], "--challenge is required"),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
            ],
            "--epoch is required",
        ),
        // Help is never read as a value, and only a known command takes it
        // after its name.
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                "--help",
            ],
            "--instance-id needs a value",
        ),
        // `help` is a command only.
        (
            vec!["verify-challenge", "help"],
            "argument 2 is not a flag of verify-challenge",
        ),
        (
            vec!["verify-response", "--challenge", missing, "help"],
            "argument 4 is not a flag of verify-response",
        ),
        (vec!["sign", "help"], "argument 2 is not a flag of sign"),
        (vec!["bogus", "-h"], "unknown command (argument 1)"),
        (vec!["bogus", "--help"], "unknown command (argument 1)"),
        (
            vec!["--help", "verify-challenge"],
            "the help takes no other argument",
        ),
        (vec!["help", "-h"], "the help takes no other argument"),
        (
            vec!["verify-challenge", "--bogus", "--help"],
            "verify-challenge has no flag --bogus",
        ),
        (
            vec!["verify-challenge", "--challenge", missing],
            "--instance-id is required",
        ),
        (
            vec!["verify-challenge", "--instance-id", INSTANCE],
            "--challenge is required",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--challenge",
                missing,
            ],
            "--challenge is given more than once",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                "1",
                "--epoch",
                "1",
            ],
            "--epoch is given more than once",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--seed-file",
                "x",
            ],
            "verify-challenge has no flag --seed-file",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--key",
                key,
            ],
            "verify-challenge has no flag --key",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                key,
            ],
            "argument 6 is not a flag of verify-challenge",
        ),
        (
            vec!["verify-challenge", "--challenge", missing, "--instance-id"],
            "--instance-id needs a value",
        ),
        (
            vec!["verify-challenge", "--challenge", "--instance-id", INSTANCE],
            "--challenge needs a value",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                "",
            ],
            "--instance-id has an empty value",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                "01",
            ],
            "--epoch is not an integer in its shortest decimal form",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                "+1",
            ],
            "--epoch is not an integer in its shortest decimal form",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                "-0",
            ],
            "--epoch is not an integer in its shortest decimal form",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                " 1",
            ],
            "--epoch is not an integer in its shortest decimal form",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                "1",
                "--now",
                "9223372036854775808",
            ],
            "--now is not an integer in its shortest decimal form",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                "1",
                "--now",
                "1.5",
            ],
            "--now is not an integer in its shortest decimal form",
        ),
        (
            vec![
                "verify-challenge",
                "--challenge",
                missing,
                "--instance-id",
                INSTANCE,
                "--epoch",
                "1",
                "--new-recovery-key",
                &NEW_KEY[..62],
            ],
            "--new-recovery-key is refused: recovery public key is not 64 lowercase hexadecimal \
             digits",
        ),
        (
            vec![
                "verify-response",
                "--challenge",
                missing,
                "--response",
                missing,
            ],
            "--key is required",
        ),
        (
            vec!["verify-response", "--challenge", missing, "--key", key],
            "--response is required",
        ),
        (
            vec![
                "verify-response",
                "--challenge",
                missing,
                "--response",
                missing,
                "--key",
                key,
                "--now",
                "1",
            ],
            "verify-response has no flag --now",
        ),
    ];
    for (arguments, message) in cases {
        let run = run(&arguments);
        assert_eq!(
            run,
            Run {
                code: 2,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: {message}\n{HINT}"),
            },
            "{arguments:?}"
        );
    }
    // Every class of key refusal, with the library's message.
    let key_fixture = recovery_fixture("key.v1.json");
    for case in list(&key_fixture, "text_cases") {
        let class = text(case, "expected");
        // An empty value is refused before it is read as a key.
        if class == "valid" || text(case, "text").is_empty() {
            continue;
        }
        let run = run(&[
            "verify-response",
            "--challenge",
            missing,
            "--response",
            missing,
            "--key",
            text(case, "text"),
        ]);
        assert_eq!(run.code, 2, "{}: {run:?}", text(case, "case"));
        assert_eq!(
            run.stderr,
            format!(
                "skyoauth-operator: --key is refused: {}\n{HINT}",
                text(&key_fixture["messages"], class)
            )
        );
    }
}

/// A value that is not UTF-8 is a usage error; a path that is not UTF-8
/// is only a path.
#[test]
fn non_utf8_arguments() {
    #[cfg(unix)]
    let bad = {
        use std::os::unix::ffi::OsStringExt as _;
        OsString::from_vec(vec![b'x', 0xff])
    };
    #[cfg(windows)]
    let bad = {
        use std::os::windows::ffi::OsStringExt as _;
        OsString::from_wide(&[u16::from(b'x'), 0xd800])
    };
    #[cfg(any(unix, windows))]
    {
        let run = run_with(&[
            &"verify-challenge",
            &"--challenge",
            &"missing",
            &"--instance-id",
            &bad,
        ]);
        assert_eq!(
            run,
            Run {
                code: 2,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: --instance-id is not UTF-8\n{HINT}"),
            }
        );
        let run = run_with(&[
            &"verify-challenge",
            &"--challenge",
            &bad,
            &"--instance-id",
            &INSTANCE,
            &"--epoch",
            &"1",
        ]);
        assert_eq!(run.code, 3, "{run:?}");
        let run = run_with(&[&bad]);
        assert_eq!(
            run.stderr,
            format!("skyoauth-operator: unknown command (argument 1)\n{HINT}")
        );
    }
}

/// `--help`, `-h` or `help` alone, and `--help` or `-h` where a flag of a
/// command is expected: the usage on standard output, exit 0, always the
/// same text (`help` is a command only: see [`usage_errors_are_exit_2`]).
#[test]
fn help_is_exit_0() {
    let help = run(&["--help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.starts_with("skyoauth-operator: "), "{help:?}");
    for command in [
        "verify-challenge --challenge",
        "sign --challenge",
        "verify-response --challenge",
        "Exit codes: 0",
    ] {
        assert!(help.stdout.contains(command), "{command}: {help:?}");
    }
    for arguments in [
        vec!["-h"],
        vec!["help"],
        vec!["verify-challenge", "--help"],
        vec!["verify-challenge", "--challenge", "x", "-h"],
        vec!["verify-response", "--challenge", "x", "-h"],
        vec!["verify-response", "--help", "--bogus"],
        vec!["sign", "--help"],
        vec!["sign", "--challenge", "x", "-h"],
    ] {
        assert_eq!(run(&arguments), help, "{arguments:?}");
    }
}

/// `-h` and `--help` are values where a value is expected: a challenge
/// file named `-h` is read, and an instance named `-h` is compared (a value
/// may not begin with `--`, so `--help` there is a missing value, exit 2:
/// see [`usage_errors_are_exit_2`]).
#[test]
fn help_as_a_value_is_a_value() {
    let dir = TempDir::new();
    dir.file("-h", &challenge_artifact(&vector("op_1")));
    let mut arguments = vec![
        "verify-challenge".to_owned(),
        "--challenge".into(),
        "-h".into(),
    ];
    arguments.extend(confirming_flags(&vector("op_1"), NOW));
    let run = run_in(Some(&dir.0), &arguments);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.stdout.ends_with(CONFIRMED), "{run:?}");

    let at = arguments.iter().position(|a| a == "--instance-id").unwrap();
    arguments[at + 1] = "-h".into();
    let run = run_in(Some(&dir.0), &arguments);
    assert_eq!(run.code, 1, "{run:?}");
    assert_eq!(
        run.stderr,
        "skyoauth-operator: refused (OtherInstance): the challenge is for another instance\n"
    );
}

/// Output that cannot be written is exit 3 with a message on standard
/// error, whatever the command's result: the result was not delivered.
/// Standard output is a pipe whose reading end is closed before the
/// binary runs.
#[test]
fn an_output_that_cannot_be_written_is_exit_3() {
    let dir = TempDir::new();
    let path = dir.file("challenge", &challenge_artifact(&vector("op_1")));
    let mut confirmed: Vec<OsString> = vec!["verify-challenge".into(), "--challenge".into()];
    confirmed.push(path.clone().into());
    confirmed.extend(
        confirming_flags(&vector("op_1"), NOW)
            .into_iter()
            .map(OsString::from),
    );
    let mut refused = confirmed.clone();
    let at = refused.iter().position(|a| a == "--epoch").unwrap();
    refused[at + 1] = "2".into();
    for (arguments, first) in [
        (vec![OsString::from("--help")], String::new()),
        (confirmed, String::new()),
        (
            refused,
            "skyoauth-operator: refused (OtherEpoch): the challenge is for another recovery key \
             epoch\n"
                .to_owned(),
        ),
    ] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = Command::new(BINARY)
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(output.status.code(), Some(3), "{arguments:?}: {stderr}");
        let rest = stderr
            .strip_prefix(&first)
            .unwrap_or_else(|| panic!("{arguments:?}: {stderr}"));
        assert!(
            rest.starts_with("skyoauth-operator: the output cannot be written (")
                && rest.ends_with(")\n")
                && rest.lines().count() == 1,
            "{arguments:?}: {stderr}"
        );
    }
}

/// Standard error that cannot be written (a pipe without a reader): a
/// result that needs a message there (refused, not confirmed, a usage
/// error) exits 3, its standard output printed in full; a result that
/// needs none is not affected.
#[test]
fn an_error_output_that_cannot_be_written_is_exit_3() {
    let dir = TempDir::new();
    let path = dir.file("challenge", &challenge_artifact(&vector("op_1")));
    let mut confirmed: Vec<OsString> = vec!["verify-challenge".into(), "--challenge".into()];
    confirmed.push(path.clone().into());
    confirmed.extend(
        confirming_flags(&vector("op_1"), NOW)
            .into_iter()
            .map(OsString::from),
    );
    let mut refused = confirmed.clone();
    let at = refused.iter().position(|a| a == "--epoch").unwrap();
    refused[at + 1] = "2".into();
    let mut not_confirmed = confirmed.clone();
    let at = not_confirmed
        .iter()
        .position(|a| a == "--new-recovery-key")
        .unwrap();
    not_confirmed.drain(at..at + 2);
    for (arguments, code) in [
        (confirmed, 0),
        (vec![OsString::from("--help")], 0),
        (refused, 3),
        (not_confirmed, 3),
        (vec![OsString::from("sign")], 3),
    ] {
        let expected_stdout = run(&arguments).stdout;
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let output = Command::new(BINARY)
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(writer)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{arguments:?}");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            expected_stdout,
            "{arguments:?}"
        );
    }
}

/// The file errors: exit 3 with the flag and the kind of the failure. A
/// missing file, a directory, and a file one byte over its limit (4 MiB
/// for the challenge artifact, 64 KiB for the response artifact) are
/// refused before anything is parsed; a file of exactly the limit is read
/// and refused as an artifact (exit 1).
#[test]
fn file_errors_are_exit_3() {
    let dir = TempDir::new();
    let challenge = dir.file("challenge", &challenge_artifact(&vector("op_1")));
    let response = dir.file(
        "response",
        &response_artifact("op_1", &fixture_signature("valid")),
    );
    let key = test_public_key("recovery");
    let missing = dir.0.join("missing");
    let not_found = format!("({})", std::io::ErrorKind::NotFound);
    let io = |run: Run, message: &str| {
        assert_eq!(
            run,
            Run {
                code: 3,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: {message}\n"),
            }
        );
    };

    io(
        verify_challenge(&missing, &["--instance-id", INSTANCE, "--epoch", "1"]),
        &format!("--challenge: the file cannot be read {not_found}"),
    );
    io(
        verify_challenge(&dir.0, &["--instance-id", INSTANCE, "--epoch", "1"]),
        "--challenge: not a regular file",
    );
    io(
        verify_response(&missing, &response, &key),
        &format!("--challenge: the file cannot be read {not_found}"),
    );
    io(
        verify_response(&challenge, &missing, &key),
        &format!("--response: the file cannot be read {not_found}"),
    );
    io(
        verify_response(&challenge, &dir.0, &key),
        "--response: not a regular file",
    );

    // The challenge artifact's limit, MAX_REPLY_BYTES.
    let at_limit = dir.file("at_limit", &vec![b'{'; MAX_REPLY_BYTES]);
    let over_limit = dir.file("over_limit", &vec![b'{'; MAX_REPLY_BYTES + 1]);
    let run = verify_challenge(&at_limit, &["--instance-id", INSTANCE, "--epoch", "1"]);
    assert_eq!(run.code, 1, "{run:?}");
    io(
        verify_challenge(&over_limit, &["--instance-id", INSTANCE, "--epoch", "1"]),
        "--challenge: the file is larger than 4194304 bytes",
    );
    io(
        verify_response(&over_limit, &response, &key),
        "--challenge: the file is larger than 4194304 bytes",
    );
    // A valid artifact padded past the limit is refused as too large, not
    // read.
    let mut padded = challenge_artifact(&vector("op_1"));
    padded.resize(MAX_REPLY_BYTES + 1, b' ');
    let padded = dir.file("padded", &padded);
    io(
        verify_challenge(&padded, &confirming_flags(&vector("op_1"), NOW)),
        "--challenge: the file is larger than 4194304 bytes",
    );

    // The response artifact's limit, MAX_REQUEST_BYTES.
    let at_limit = dir.file("response_at_limit", &vec![b'{'; MAX_REQUEST_BYTES]);
    let over_limit = dir.file("response_over_limit", &vec![b'{'; MAX_REQUEST_BYTES + 1]);
    let run = verify_response(&challenge, &at_limit, &key);
    assert_eq!(run.code, 1, "{run:?}");
    io(
        verify_response(&challenge, &over_limit, &key),
        "--response: the file is larger than 65536 bytes",
    );
}

/// A device is not a regular file (Unix: `/dev/null`).
#[cfg(unix)]
#[test]
fn a_device_is_not_a_regular_file() {
    let run = verify_challenge(
        Path::new("/dev/null"),
        &["--instance-id", INSTANCE, "--epoch", "1"],
    );
    assert_eq!(run.code, 3, "{run:?}");
    assert_eq!(
        run.stderr,
        "skyoauth-operator: --challenge: not a regular file\n"
    );
}

/// A named pipe is refused without being opened: opening one for reading
/// blocks until a writer comes, so a binary that opened it first would
/// hang. The binary must end within 20 seconds (it ends at once). The pipe
/// is made with the system's `mkfifo`; without one, the test says so and
/// passes.
#[cfg(unix)]
#[test]
fn a_named_pipe_is_refused_without_being_opened() {
    use std::time::{Duration, Instant};

    let dir = TempDir::new();
    let pipe = dir.0.join("pipe");
    match Command::new("mkfifo").arg(&pipe).status() {
        Ok(status) if status.success() => {}
        _ => {
            eprintln!("NOTICE: no mkfifo: the named pipe case was NOT tried");
            return;
        }
    }
    let mut child = Command::new(BINARY)
        .args([
            "verify-challenge",
            "--instance-id",
            INSTANCE,
            "--epoch",
            "1",
            "--challenge",
        ])
        .arg(&pipe)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the binary blocked on a named pipe");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert_eq!(
        output.stderr,
        b"skyoauth-operator: --challenge: not a regular file\n"
    );
}

/// The refusals of a challenge artifact that is not an issued challenge:
/// exit 1 and a fixed message, for each way it can fail.
#[test]
fn malformed_challenge_artifacts_are_exit_1() {
    let dir = TempDir::new();
    let op_1 = vector("op_1");
    let good = String::from_utf8(challenge_artifact(&op_1)).unwrap();
    let not_reply = |why: &str| {
        format!(
            "skyoauth-operator: the challenge artifact is not an issue_challenge reply: {why}\n"
        )
    };
    let malformed = not_reply("the reply is not a reply of the request's operation");
    let mismatch = "skyoauth-operator: the challenge artifact is refused: the issued reply does \
                    not match its challenge\n";
    let cases: Vec<(Vec<u8>, String)> =
        vec![
        (Vec::new(), not_reply("the reply does not end with a newline")),
        (
            good.trim_end().into(),
            not_reply("the reply does not end with a newline"),
        ),
        (
            format!("{good}\n").into(),
            not_reply("the reply has bytes after its newline"),
        ),
        (good.replace('\n', "\r\n").into(), malformed.clone()),
        (format!("\u{feff}{good}").into(), malformed.clone()),
        (good.replace(':', ": ").into(), malformed.clone()),
        (
            b"{\"operation_id\":\"\xff\"}\n".to_vec(),
            not_reply("the reply is not UTF-8"),
        ),
        (
            b"{\"error\":\"conflict\"}\n".to_vec(),
            "skyoauth-operator: the challenge artifact is a refusal of the local transport, not \
             a challenge (conflict: the stored state refuses the request)\n"
                .into(),
        ),
        (
            b"{\"error\":\"nope\"}\n".to_vec(),
            not_reply("the reply refuses with an unknown code"),
        ),
        (
            good.replace("\"expires_at\":1790000300000000", "\"expires_at\":1790000300000001")
                .into(),
            mismatch.into(),
        ),
        (
            good.replace("\"expected_revision\":1", "\"expected_revision\":2")
                .into(),
            mismatch.into(),
        ),
        (
            good.replace("\"operation_id\":\"op_1\"", "\"operation_id\":\"op_2\"")
                .into(),
            mismatch.into(),
        ),
        (
            good.replace("\"challenge\":\"736b", "\"challenge\":\"746b")
                .into(),
            "skyoauth-operator: the challenge artifact's challenge is refused (Prefix): the \
             challenge does not begin with the recovery challenge prefix\n"
                .into(),
        ),
        (
            good.replace("\"challenge\":\"736b", "\"challenge\":\"736B")
                .into(),
            malformed.clone(),
        ),
    ];
    for (index, (artifact, message)) in cases.into_iter().enumerate() {
        let path = dir.file(&format!("case{index}"), &artifact);
        for run in [
            verify_challenge(&path, &confirming_flags(&op_1, NOW)),
            verify_response(&path, &path, &test_public_key("recovery")),
        ] {
            assert_eq!(
                run,
                Run {
                    code: 1,
                    stdout: String::new(),
                    stderr: message.clone()
                },
                "case {index}"
            );
        }
    }
}

/// The refusals of a response artifact that is not one: exit 1 and a
/// fixed message.
#[test]
fn malformed_response_artifacts_are_exit_1() {
    let dir = TempDir::new();
    let challenge = dir.file("challenge", &challenge_artifact(&vector("op_1")));
    let signature = fixture_signature("valid");
    let good = String::from_utf8(response_artifact("op_1", &signature)).unwrap();
    let malformed = "skyoauth-operator: the response artifact is malformed: ";
    let shape =
        format!("{malformed}it is not {{\"operation_id\":\"...\",\"signature\":\"...\"}}\n");
    let cases: Vec<(Vec<u8>, String)> = vec![
        (
            Vec::new(),
            format!("{malformed}it does not end with a newline\n"),
        ),
        (
            good.trim_end().into(),
            format!("{malformed}it does not end with a newline\n"),
        ),
        (
            format!("{good}{good}").into(),
            format!("{malformed}it is more than one line\n"),
        ),
        (
            b"{\"operation_id\":\"\xff\"}\n".to_vec(),
            format!("{malformed}it is not UTF-8\n"),
        ),
        (good.replace('\n', "\r\n").into(), shape.clone()),
        (good.replace(':', ": ").into(), shape.clone()),
        (format!("\u{feff}{good}").into(), shape.clone()),
        (
            format!("{{\"signature\":\"{signature}\",\"operation_id\":\"op_1\"}}\n").into(),
            shape.clone(),
        ),
        (
            format!("{{\"operation_id\":\"op_1\",\"signature\":\"{signature}\",\"x\":1}}\n").into(),
            shape.clone(),
        ),
        (
            format!("{{\"operation_id\":\"op\\/1\",\"signature\":\"{signature}\"}}\n").into(),
            shape.clone(),
        ),
        (
            format!("{{\"operation_id\":\"op\\u0041\",\"signature\":\"{signature}\"}}\n").into(),
            shape.clone(),
        ),
        (
            format!("{{\"operation_id\":\"op\\u001F\",\"signature\":\"{signature}\"}}\n").into(),
            shape.clone(),
        ),
        (
            format!("{{\"operation_id\":\"op\u{1}\",\"signature\":\"{signature}\"}}\n").into(),
            shape.clone(),
        ),
        (
            format!("{{\"operation_id\":op_1,\"signature\":\"{signature}\"}}\n").into(),
            shape.clone(),
        ),
        (
            format!(
                "{{\"operation_id\":\"op_1\",\"signature\":\"{}\"}}\n",
                signature.to_ascii_uppercase()
            )
            .into(),
            format!("{malformed}the signature is not lowercase hexadecimal\n"),
        ),
        (
            format!(
                "{{\"operation_id\":\"op_1\",\"signature\":\"{}\"}}\n",
                &signature[1..]
            )
            .into(),
            format!("{malformed}the signature is not lowercase hexadecimal\n"),
        ),
        (
            format!(
                "{{\"operation_id\":\"op_1\",\"signature\":\"0x{}\"}}\n",
                &signature[2..]
            )
            .into(),
            format!("{malformed}the signature is not lowercase hexadecimal\n"),
        ),
    ];
    for (index, (artifact, message)) in cases.into_iter().enumerate() {
        let path = dir.file(&format!("case{index}"), &artifact);
        let run = verify_response(&challenge, &path, &test_public_key("recovery"));
        assert_eq!(
            run,
            Run {
                code: 1,
                stdout: String::new(),
                stderr: message
            },
            "case {index}"
        );
    }
    // The escapes the codec writes are read: an operation ID with every
    // short escape and a `\u` control is another operation, not malformed.
    let escaped = dir.file(
        "escaped",
        format!(
            "{{\"operation_id\":\"{}\",\"signature\":\"{signature}\"}}\n",
            r#"\"\\\b\f\n\r\t\u0000\u001f"#
        )
        .as_bytes(),
    );
    let run = verify_response(&challenge, &escaped, &test_public_key("recovery"));
    assert!(run.stderr.contains("(OtherOperation)"), "{run:?}");
}

/// A small deterministic generator (an LCG), so the mutations are the
/// same on every run and every platform.
struct Lcg(u64);

impl Lcg {
    fn below(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(self.0 >> 33).unwrap() % bound
    }
}

/// Whether the library reads `artifact` as op_1's issued challenge, or
/// one whose changes are only in what is not checked (an `admin_id`
/// letter, say), and confirms it with op_1's values: the oracle of the
/// mutated challenges.
fn library_confirms(artifact: &[u8]) -> bool {
    let Ok(Reply::Issued(issued)) = parse_reply(Op::IssueChallenge, artifact) else {
        return false;
    };
    let Ok(challenge) = parse_challenge(&issued.challenge) else {
        return false;
    };
    if challenge.operation_id() != issued.operation_id
        || challenge.expires_at_micros() != issued.expires_at
        || challenge.expected_revision() != issued.expected_revision
    {
        return false;
    }
    let new_key = RecoveryPublicKey::from_hex(NEW_KEY).unwrap();
    check_challenge(
        &challenge,
        &Expectations {
            instance_id: INSTANCE,
            now_micros: NOW,
            recovery_key_epoch: Some(1),
            replacement_public_identity: Some("spki-sha256:new"),
            trust_anchor_ref: Some("deployment/operator-ca"),
            new_recovery_public_key: Some(&new_key),
        },
    )
    .is_ok_and(|verified| verified.replacement_confirmed())
}

/// Mutations of the good artifacts (a byte replaced, removed or inserted,
/// the line cut short), each run through both commands: never a panic,
/// never a byte that is not printable ASCII (`run`), a changed challenge
/// confirmed exactly when the library confirms it, and a changed artifact
/// never verifies.
#[test]
fn mutated_artifacts_never_panic() {
    let dir = TempDir::new();
    let op_1 = vector("op_1");
    let challenge = challenge_artifact(&op_1);
    let response = response_artifact("op_1", &fixture_signature("valid"));
    let good_challenge = dir.file("challenge", &challenge);
    let good_response = dir.file("response", &response);
    let key = test_public_key("recovery");
    let flags = confirming_flags(&op_1, NOW);
    let interesting = [
        0u8, b'\n', b'\r', b'"', b'\\', b'{', b'}', b',', b':', b'0', b'f', 0x1b, 0x80, 0xff,
    ];
    let mut lcg = Lcg(0x5eed);
    for round in 0..120 {
        let (original, is_challenge) = if round % 2 == 0 {
            (&challenge, true)
        } else {
            (&response, false)
        };
        let mut mutated = original.clone();
        match lcg.below(4) {
            0 => {
                let at = lcg.below(mutated.len());
                mutated[at] = interesting[lcg.below(interesting.len())];
            }
            1 => {
                mutated.remove(lcg.below(mutated.len()));
            }
            2 => {
                let byte = interesting[lcg.below(interesting.len())];
                mutated.insert(lcg.below(mutated.len() + 1), byte);
            }
            _ => mutated.truncate(lcg.below(mutated.len())),
        }
        if mutated == *original {
            continue;
        }
        let path = dir.file(&format!("mutated{round}"), &mutated);
        if is_challenge {
            let run = verify_challenge(&path, &flags);
            let expected = if library_confirms(&mutated) { 0 } else { 1 };
            assert_eq!(run.code, expected, "round {round}: {run:?}");
            // A changed artifact that is still read is another `M`, which
            // the signature does not cover.
            let run = verify_response(&path, &good_response, &key);
            assert_eq!(run.code, 1, "round {round}: {run:?}");
        } else {
            let run = verify_response(&good_challenge, &path, &key);
            assert_eq!(run.code, 1, "round {round}: {run:?}");
        }
    }
}
