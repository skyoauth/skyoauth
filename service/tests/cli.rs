//! Command-line behavior that needs no database.

use std::process::{Command, Output};

fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_skyoauth-service"));
    command
        .args(args)
        .env_remove("SKYOAUTH_DATABASE_URL")
        .env("NO_COLOR", "1")
        .env("RUST_LOG", "info");
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn all_output(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

#[test]
fn unknown_command_prints_usage_and_exits_2() {
    for args in [&["serve-now"][..], &["migrate", "extra"][..]] {
        let output = run(args, &[]);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("usage:"));
    }
}

#[test]
fn help_prints_usage() {
    let output = run(&["--help"], &[]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("migrate"));
}

#[test]
fn migrate_without_database_url_fails_clearly() {
    let output = run(&["migrate"], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(all_output(&output).contains("SKYOAUTH_DATABASE_URL is not set"));
}

#[test]
fn migrate_connection_failure_does_not_log_the_password() {
    // Port 1 on loopback refuses connections, so this fails fast.
    let output = run(
        &["migrate"],
        &[
            (
                "SKYOAUTH_DATABASE_URL",
                "postgres://skyoauth:s3cr3t-pw@127.0.0.1:1/skyoauth",
            ),
            ("SKYOAUTH_DATABASE_ACQUIRE_TIMEOUT_SECS", "1"),
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let text = all_output(&output);
    assert!(text.contains("cannot connect to the database"), "{text}");
    assert!(text.contains("127.0.0.1"), "{text}");
    assert!(!text.contains("s3cr3t-pw"), "{text}");
}

/// A password with an unencoded `?`, `/` or `#` ends the URL authority
/// early, so the rest of it would reach sqlx's "unrecognized connect
/// parameter" WARN or the database name in the `connecting` log line. Such a
/// URL is rejected before sqlx parses it, and nothing of the password is
/// printed, even at trace level.
#[test]
fn migrate_rejects_an_unencoded_password_character_without_printing_the_password() {
    // The head is numeric so that, unchecked, it would parse as a port and
    // the URL would be accepted.
    const HEAD: &str = "40417";
    const TAIL: &str = "t4il-k9zq";
    for url in [
        format!("postgres://skyoauth:{HEAD}?{TAIL}@127.0.0.1:1/skyoauth"),
        format!("postgres://skyoauth:{HEAD}/{TAIL}@127.0.0.1:1/skyoauth"),
        format!("postgres://skyoauth:/{TAIL}@127.0.0.1:1/skyoauth"),
        format!("postgres://skyoauth:{HEAD}#{TAIL}@127.0.0.1:1/skyoauth"),
        format!("postgres://skyoauth:{HEAD}@{TAIL}@127.0.0.1:1/skyoauth"),
    ] {
        let output = run(
            &["migrate"],
            &[
                ("SKYOAUTH_DATABASE_URL", &url),
                ("SKYOAUTH_DATABASE_ACQUIRE_TIMEOUT_SECS", "1"),
                ("RUST_LOG", "trace"),
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{url}");
        let text = all_output(&output);
        assert!(text.contains("must be percent-encoded"), "{url}: {text}");
        for fragment in [HEAD, TAIL] {
            assert!(!text.contains(fragment), "{url}: {fragment} in {text}");
        }
    }
}
