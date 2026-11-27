//! The online commands of the binary, `bootstrap`, `issue-challenge`,
//! `preview`, `restore` and `status` (docs/proposals/operator-cli-online.md),
//! run as a process.
//!
//! Portable: the usage errors of the socket flags and of each command's
//! flags (exit 2, decided before any file is read, on every platform), the
//! help; off Unix, each online command exits 2 with its fixed text, reads
//! no file and creates no `--out`.
//!
//! Unix (`unix`): a fake service, a `UnixListener` at a socket of mode 0600
//! in a private 0700 directory, `--service-uid` the directory's owner read
//! from its metadata (so the socket path checks pass for any user, root
//! included), serving the golden reply lines of
//! `tests/conformance/fixtures/_wire/local_transport.v1.json` (the bytes
//! the real service sent) and checking that each request line received is
//! the fixture's golden request, byte for byte, and how many connections
//! were made. Every outcome: each command's output, every member of a
//! `status` reply, the challenge artifact `--out` (the reply line verbatim,
//! created before the request, left empty on every other outcome), a
//! restore's `revoked_credential_ids_complete`, each outcome of a write
//! (exit 1, 5 with the fixed text of what to run, 6, and 3 when its output
//! fails after it committed), the walk over the pages of revoked IDs (its restart on
//! the documented tie, and a page mismatch), each refusal code (exit 1),
//! each unknown reply of the fixture for `preview` and `status` and a
//! timeout of each wait (exit 6, never 5: they change nothing), each
//! refused socket path and a connection refused (exit 6, nothing
//! received), a signature of 63 or 65 bytes and a request too large
//! (exit 1, no connection), the file errors (exit 3, no connection), and
//! every verdict of both reconciles with its `next:` line.
//!
//! Every run is checked as `super::run` checks one (exit codes 0 to 6
//! here), and for what it must never print: the response's signature, the
//! key's DER in hexadecimal, the socket's path or its directory's.

use std::ffi::OsString;

use super::{HINT, Run, run_up_to};

/// The golden signature of the fixture's `preview` and `restore`
/// requests: never printed.
const SIGNATURE: &str = "a14dbaf5fda40acbc5a8c292e681cd41dc270dc39da5b152b4b9fed08bb95e267185dd263986c9c88dd99ad6c3e897be2d419ef19bf4f8f28b11a2a26f2e5807";

/// The DER of the fixture's `status_credential` key, in hexadecimal: never
/// printed.
const SPKI_HEX: &str =
    "302a300506032b65700321000101010101010101010101010101010101010101010101010101010101010101";

/// The line after the message of exit 6.
const UNCHANGED_NEXT: &str = "Nothing was changed by this command: it may be run again.\n";

/// Runs the binary with `arguments`, checks it as [`super::run`] does
/// with the exit codes 0 to 6, and that it prints none of `hidden`, the
/// signature or the key's DER, and the line that ends each kind of
/// failure.
fn online<S: AsRef<std::ffi::OsStr>>(arguments: &[S], hidden: &[String]) -> Run {
    let run = run_up_to(None, arguments, 6);
    let mut needles = vec![
        SIGNATURE.to_owned(),
        SIGNATURE[..16].to_owned(),
        SIGNATURE.to_ascii_uppercase(),
        SPKI_HEX.to_owned(),
    ];
    needles.extend(hidden.iter().cloned());
    for needle in &needles {
        assert!(
            !run.stdout.contains(needle.as_str()) && !run.stderr.contains(needle.as_str()),
            "{needle} is printed: {run:?}"
        );
    }
    match run.code {
        2 => assert!(run.stderr.ends_with(HINT), "{run:?}"),
        6 => assert!(
            run.stderr.ends_with(UNCHANGED_NEXT) && run.stdout.is_empty(),
            "{run:?}"
        ),
        // The cause, then what to run instead of repeating the write.
        5 => assert!(
            run.stderr.lines().count() >= 2
                && run.stdout.is_empty()
                && !run.stderr.contains(UNCHANGED_NEXT),
            "{run:?}"
        ),
        _ => assert!(!run.stderr.contains(UNCHANGED_NEXT), "{run:?}"),
    }
    run
}

/// `arguments` as owned strings.
fn strings(arguments: &[&str]) -> Vec<OsString> {
    arguments.iter().map(OsString::from).collect()
}

/// The usage errors of the online commands: exit 2, the fixed message and
/// the hint, nothing read (the files named do not exist, so a run that
/// read one would end in exit 3, and no socket exists, which would be exit
/// 6). No message repeats a value given.
#[test]
fn online_usage_errors_are_exit_2() {
    let socket = ["--socket", "no-such-socket", "--service-uid", "1000"];
    let with_socket = |rest: &[&'static str]| -> Vec<&'static str> {
        let mut arguments = vec![rest[0]];
        arguments.extend(socket);
        arguments.extend(&rest[1..]);
        arguments
    };
    let key = "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a";
    let bootstrap_flags = [
        "--instance-id",
        "SENTINEL-INSTANCE",
        "--credential-spki",
        "no-such-spki",
        "--trust-anchor",
        "SENTINEL-ANCHOR",
        "--recovery-key",
        key,
    ];
    let mut cases: Vec<(Vec<&str>, String)> = vec![
        (vec!["preview"], "--socket is required".into()),
        (
            vec!["preview", "--socket", "no-such-socket"],
            "--service-uid is required".into(),
        ),
        (
            vec!["status", "--service-uid", "1000"],
            "--socket is required".into(),
        ),
        (with_socket(&["preview"]), "--response is required".into()),
        (
            with_socket(&["preview", "--challenge", "no-such-challenge"]),
            "preview has no flag --challenge".into(),
        ),
        (
            with_socket(&["preview", "--response", "x", "--response", "y"]),
            "--response is given more than once".into(),
        ),
        (
            with_socket(&["status", "--socket", "again"]),
            "--socket is given more than once".into(),
        ),
        (
            with_socket(&["status", "--out", "x"]),
            "status has no flag --out".into(),
        ),
        (
            with_socket(&["status", "--challenge", "x", "--response", "y"]),
            "--challenge and --response cannot both be given".into(),
        ),
        (
            with_socket(&["status", "--reconcile", "SENTINEL-RECONCILE"]),
            "--reconcile is not restore or bootstrap".into(),
        ),
        (
            with_socket(&["status", "--reconcile", "restore"]),
            "--reconcile restore needs --challenge or --response".into(),
        ),
        (
            with_socket(&[
                "status",
                "--reconcile",
                "restore",
                "--response",
                "x",
                "--credential-spki",
                "y",
            ]),
            "--credential-spki is not for --reconcile restore".into(),
        ),
        (
            with_socket(&[
                "status",
                "--reconcile",
                "restore",
                "--response",
                "x",
                "--recovery-key",
                key,
            ]),
            "--recovery-key is only for --reconcile bootstrap".into(),
        ),
        (
            with_socket(&["status", "--instance-id", "SENTINEL-INSTANCE"]),
            "--instance-id is only for --reconcile bootstrap".into(),
        ),
        (
            with_socket(&["status", "--trust-anchor", "SENTINEL-ANCHOR"]),
            "--trust-anchor is only for --reconcile bootstrap".into(),
        ),
        (
            with_socket(&["status", "--reconcile", "bootstrap", "--response", "x"]),
            "--challenge and --response are not for --reconcile bootstrap".into(),
        ),
        (
            with_socket(&[
                "status",
                "--reconcile",
                "bootstrap",
                "--instance-id",
                "SENTINEL-INSTANCE",
                "--credential-spki",
                "no-such-spki",
                "--trust-anchor",
                "SENTINEL-ANCHOR",
                "--recovery-key",
                &key[..62],
            ]),
            "--recovery-key is refused: recovery public key is not 64 lowercase hexadecimal \
             digits"
                .into(),
        ),
        (
            with_socket(&["status", "--trust-ancestors", "SENTINEL-TRUST"]),
            "--trust-ancestors is not service-or-root or root-only".into(),
        ),
        (
            with_socket(&["status", "--trust-ancestors", "Root-Only"]),
            "--trust-ancestors is not service-or-root or root-only".into(),
        ),
    ];
    // Each of the four flags of `--reconcile bootstrap` is required.
    for left_out in [
        "--instance-id",
        "--credential-spki",
        "--trust-anchor",
        "--recovery-key",
    ] {
        let mut arguments = with_socket(&["status", "--reconcile", "bootstrap"]);
        let at = bootstrap_flags
            .iter()
            .position(|flag| *flag == left_out)
            .unwrap();
        for (index, argument) in bootstrap_flags.iter().enumerate() {
            if index != at && index != at + 1 {
                arguments.push(argument);
            }
        }
        cases.push((arguments, format!("{left_out} is required")));
    }
    let uid_message = "--service-uid is not a UID: an integer from 0 to 4294967295 in its \
                       shortest decimal form";
    for uid in [
        "-1",
        "4294967296",
        "01",
        "+1",
        "1.0",
        "SENTINEL-UID",
        "0x10",
    ] {
        cases.push((
            vec!["status", "--socket", "s", "--service-uid", uid],
            uid_message.into(),
        ));
    }
    for flag in ["--total-wait", "--idle-wait"] {
        for seconds in ["0", "-1", "01", "1.5", "+1", "SENTINEL-WAIT"] {
            let mut arguments = with_socket(&["status"]);
            arguments.extend([flag, seconds]);
            cases.push((
                arguments,
                format!(
                    "{flag} is not a whole number of seconds over zero in its shortest decimal \
                     form"
                ),
            ));
        }
    }
    // The writes: every flag of each is required, and each refuses the
    // flags of the others; a key that does not parse is named by its flag.
    let issue_flags = [
        "--credential-spki",
        "no-such-spki",
        "--trust-anchor",
        "SENTINEL-ANCHOR",
        "--new-recovery-key",
        key,
        "--out",
        "SENTINEL-OUT",
    ];
    let restore_flags = ["--response", "no-such-response"];
    for (command, flags) in [
        ("bootstrap", &bootstrap_flags[..]),
        ("issue-challenge", &issue_flags[..]),
        ("restore", &restore_flags[..]),
    ] {
        for at in (0..flags.len()).step_by(2) {
            let mut arguments = with_socket(&[command]);
            for (index, argument) in flags.iter().enumerate() {
                if index != at && index != at + 1 {
                    arguments.push(argument);
                }
            }
            cases.push((arguments, format!("{} is required", flags[at])));
        }
        let mut arguments = vec![command];
        arguments.extend(flags);
        cases.push((arguments, "--socket is required".into()));
        let mut arguments = vec![command, "--socket", "no-such-socket"];
        arguments.extend(flags);
        cases.push((arguments, "--service-uid is required".into()));
        let mut arguments = with_socket(&[command]);
        arguments.extend(flags);
        arguments.extend(["--total-wait", "0"]);
        cases.push((
            arguments,
            "--total-wait is not a whole number of seconds over zero in its shortest decimal form"
                .into(),
        ));
    }
    for (command, flag) in [
        ("bootstrap", "--out"),
        ("bootstrap", "--new-recovery-key"),
        ("bootstrap", "--response"),
        ("bootstrap", "--reconcile"),
        ("issue-challenge", "--instance-id"),
        ("issue-challenge", "--recovery-key"),
        ("issue-challenge", "--response"),
        ("issue-challenge", "--challenge"),
        ("restore", "--challenge"),
        ("restore", "--out"),
        ("restore", "--credential-spki"),
        ("restore", "--instance-id"),
    ] {
        cases.push((
            with_socket(&[command, flag, "SENTINEL-VALUE"]),
            format!("{command} has no flag {flag}"),
        ));
    }
    let mut arguments = with_socket(&["bootstrap"]);
    arguments.extend(&bootstrap_flags[..7]);
    arguments.push(&key[1..]);
    cases.push((
        arguments,
        "--recovery-key is refused: recovery public key is not 64 lowercase hexadecimal digits"
            .into(),
    ));
    let mut arguments = with_socket(&["issue-challenge"]);
    arguments.extend(&issue_flags[..5]);
    arguments.push("C050C5637A44FA8629FFF3CCCCE2300CB362A63D99D95FC54145266F4332445A");
    arguments.extend(&issue_flags[6..]);
    cases.push((
        arguments,
        "--new-recovery-key is refused: recovery public key is not 64 lowercase hexadecimal \
         digits"
            .into(),
    ));
    let mut arguments = with_socket(&["restore"]);
    arguments.extend(restore_flags);
    arguments.extend(restore_flags);
    cases.push((arguments, "--response is given more than once".into()));
    let hidden: Vec<String> = ["SENTINEL", "no-such-socket", "C050C5637A44FA86"]
        .map(String::from)
        .to_vec();
    for (arguments, message) in cases {
        let run = online(&arguments, &hidden);
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
    // The largest UID and wait are accepted: the run goes on, to the
    // missing response file (exit 3) on Unix.
    let run = online(
        &strings(&[
            "preview",
            "--socket",
            "no-such-socket",
            "--service-uid",
            "4294967295",
            "--total-wait",
            "9223372036854775807",
            "--idle-wait",
            "1",
            "--trust-ancestors",
            "root-only",
            "--response",
            "no-such-response",
        ]),
        &hidden,
    );
    assert_ne!(run.code, 0, "{run:?}");
    assert!(!run.stderr.contains("--service-uid") && !run.stderr.contains("-wait"));
}

/// The help names the five online commands, Unix only, their socket flags
/// and the exit codes 5 and 6; it is printed for `--help` or `-h` where a
/// flag of any is expected (never as a value).
#[test]
fn the_help_names_the_online_commands() {
    let help = online(&["--help"], &[]);
    assert_eq!(help.code, 0);
    assert!(!help.stdout.contains("not implemented"), "{help:?}");
    for text in [
        "skyoauth-operator bootstrap SOCKET --instance-id ID --credential-spki FILE\n      \
         --trust-anchor REF --recovery-key HEX",
        "skyoauth-operator issue-challenge SOCKET --credential-spki FILE\n      \
         --trust-anchor REF --new-recovery-key HEX --out FILE",
        "skyoauth-operator restore SOCKET --response FILE",
        "skyoauth-operator preview SOCKET --response FILE",
        "skyoauth-operator status SOCKET [--challenge FILE | --response FILE]",
        "skyoauth-operator status SOCKET --reconcile restore",
        "skyoauth-operator status SOCKET --reconcile bootstrap --instance-id ID",
        "SOCKET is: --socket PATH --service-uid UID",
        "[--trust-ancestors service-or-root|root-only]",
        "[--total-wait SECONDS] [--idle-wait SECONDS]",
        "(Unix only)",
        "--total-wait (default 100) and --idle-wait (default 10)",
        "issue-challenge creates --out, a new\nfile",
        "revoked_credential_ids_complete: yes or no",
        "On a\nplatform without Unix sockets, the online commands exit 2.",
        "; 5 the outcome of a write (bootstrap,\nissue-challenge, restore) is unknown",
        "; 6 nothing was changed",
    ] {
        assert!(help.stdout.contains(text), "{text}: {help:?}");
    }
    for arguments in [
        vec!["preview", "--help"],
        vec!["preview", "--socket", "x", "-h"],
        vec!["status", "-h"],
        vec!["status", "--reconcile", "restore", "--help"],
        vec!["bootstrap", "--help"],
        vec!["bootstrap", "--instance-id", "x", "-h"],
        vec!["issue-challenge", "-h"],
        vec!["issue-challenge", "--out", "x", "--help"],
        vec!["restore", "--help"],
        vec!["restore", "--socket", "x", "--service-uid", "1", "-h"],
    ] {
        assert_eq!(online(&arguments, &[]), help, "{arguments:?}");
    }
    // `-h` as a value is a value: here a socket path, refused later.
    let run = online(&["restore", "--socket", "-h"], &[]);
    assert_eq!(run.code, 2, "{run:?}");
    assert_ne!(run.stdout, help.stdout);
}

/// Off Unix, an online command is parsed with its flags, as everywhere,
/// and then refused with exit 2 and its fixed text, before any file is
/// read (the files named do not exist: a read would be exit 3) and before
/// `issue-challenge` creates its `--out`.
#[cfg(not(unix))]
#[test]
fn online_commands_exit_2_without_unix_sockets() {
    let socket = ["--socket", "no-such-socket", "--service-uid", "1000"];
    let key = "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a";
    let dir = super::TempDir::new();
    let out = dir.0.join("challenge");
    let out = out.to_str().unwrap();
    for (command, rest) in [
        (
            "bootstrap",
            vec![
                "--instance-id",
                "019a9f3c-5b2e-7c41-9d8e-0000000c1001",
                "--credential-spki",
                "no-such-spki",
                "--trust-anchor",
                "deployment/operator-ca",
                "--recovery-key",
                key,
            ],
        ),
        (
            "issue-challenge",
            vec![
                "--credential-spki",
                "no-such-spki",
                "--trust-anchor",
                "deployment/operator-ca",
                "--new-recovery-key",
                key,
                "--out",
                out,
            ],
        ),
        ("restore", vec!["--response", "no-such-response"]),
        ("preview", vec!["--response", "no-such-response"]),
        ("status", vec![]),
        (
            "status",
            vec![
                "--challenge",
                "no-such-challenge",
                "--credential-spki",
                "no-such-spki",
            ],
        ),
        (
            "status",
            vec!["--reconcile", "restore", "--response", "no-such-response"],
        ),
    ] {
        let mut arguments = vec![command];
        arguments.extend(socket);
        arguments.extend(rest);
        let run = online(&arguments, &[]);
        assert_eq!(
            run,
            Run {
                code: 2,
                stdout: String::new(),
                stderr: format!(
                    "skyoauth-operator: {command} needs the deployment-local Unix socket, which \
                     this platform does not have\n{HINT}"
                ),
            },
            "{arguments:?}"
        );
    }
    assert!(!std::path::Path::new(out).exists(), "--out was created");
}

#[cfg(unix)]
mod unix;
