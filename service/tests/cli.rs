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

/// [`all_output`] without each log line's leading timestamp, whose
/// microsecond digits could contain a numeric secret by chance.
fn output_without_timestamps(output: &Output) -> String {
    strip_timestamps(&all_output(output))
}

fn strip_timestamps(text: &str) -> String {
    text.lines()
        .map(|line| match line.split_once(' ') {
            Some((first, rest)) if is_timestamp(first) => rest,
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `word` looks like the RFC 3339 UTC timestamp `tracing` prints,
/// such as `2026-11-20T06:08:05.572788Z`.
fn is_timestamp(word: &str) -> bool {
    word.ends_with('Z')
        && word.contains('T')
        && word
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | 'Z'))
}

#[test]
fn timestamps_are_stripped_before_searching_the_output() {
    let text = "2026-11-20T06:08:05.404170Z ERROR x: 40417 gone\nplain 2026 40417Z\n";
    assert_eq!(
        strip_timestamps(text),
        "ERROR x: 40417 gone\nplain 2026 40417Z"
    );
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
        let text = output_without_timestamps(&output);
        assert!(text.contains("must be percent-encoded"), "{url}: {text}");
        for fragment in [HEAD, TAIL] {
            assert!(!text.contains(fragment), "{url}: {fragment} in {text}");
        }
    }
}

/// Runs `migrate` on `url` at trace level and asserts that it is rejected
/// with `message`, before any connection attempt, and that none of
/// `secrets` is printed.
fn assert_rejected_at_trace(url: &str, message: &str, secrets: &[&str]) {
    let output = run(
        &["migrate"],
        &[
            ("SKYOAUTH_DATABASE_URL", url),
            ("SKYOAUTH_DATABASE_ACQUIRE_TIMEOUT_SECS", "1"),
            ("RUST_LOG", "trace"),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{url}");
    let text = output_without_timestamps(&output);
    assert!(text.contains(message), "{url}: {text}");
    assert!(!text.contains("connecting"), "{url}: {text}");
    assert!(!text.contains("unrecognized"), "{url}: {text}");
    for secret in secrets {
        assert!(!text.contains(secret), "{url}: {secret} in {text}");
    }
}

const UNSUPPORTED: &str = "has a query parameter that is not supported";

/// sqlx logs a query key it does not act on, with its value, at WARN. Such
/// a key is rejected before sqlx sees the URL, and the error names neither
/// the key nor the value.
#[test]
fn migrate_rejects_an_unsupported_query_key_without_printing_it() {
    // Letters keep these from matching timestamp digits or a port.
    const KEY: &str = "Kx-qvzt";
    const VALUE: &str = "Vy-wpjr";
    for (url, secrets) in [
        (
            format!("postgres://skyoauth@127.0.0.1:1/skyoauth?sslpassword={VALUE}"),
            &[VALUE][..],
        ),
        // A query password with an unencoded `&`: the tail becomes a key.
        (
            format!("postgres://skyoauth@127.0.0.1:1/skyoauth?password={KEY}&{VALUE}"),
            &[KEY, VALUE][..],
        ),
        (
            format!("postgres://skyoauth@127.0.0.1:1/skyoauth?password={KEY}&{VALUE}=x"),
            &[KEY, VALUE][..],
        ),
        // An unknown key carrying a secret, including a libpq parameter.
        (
            format!("postgres://skyoauth@127.0.0.1:1/skyoauth?sslmode=disable&{KEY}={VALUE}"),
            &[KEY, VALUE][..],
        ),
        (
            format!("postgres://skyoauth@127.0.0.1:1/skyoauth?connect_timeout=5&x={VALUE}"),
            &[VALUE][..],
        ),
        // An unencoded `?` in the database name starts the query.
        (
            format!("postgres://skyoauth@127.0.0.1:1/sky{KEY}?{VALUE}"),
            &[VALUE][..],
        ),
    ] {
        assert_rejected_at_trace(&url, UNSUPPORTED, secrets);
    }
}

/// A `?` typed for `&` would make the rest of the query part of the user or
/// database name, which the `connecting` line prints.
#[test]
fn migrate_rejects_a_second_question_mark_without_printing_the_query() {
    const SECRET: &str = "Sz-hqkwm";
    for url in [
        format!("postgres://127.0.0.1:1/skyoauth?user=bob?password={SECRET}"),
        format!("postgres://skyoauth@127.0.0.1:1/?dbname=x?password={SECRET}"),
    ] {
        assert_rejected_at_trace(&url, "must be percent-encoded", &[SECRET, "bob?"]);
    }
    let url = format!("postgres://127.0.0.1:1/skyoauth?user=bob%3Fpassword%3D{SECRET}");
    assert_rejected_at_trace(&url, "user or database name containing '?'", &[SECRET]);
}

/// A fragment silently drops the query parameters after it, `sslmode`
/// included.
#[test]
fn migrate_rejects_a_fragment_without_printing_it() {
    const HEAD: &str = "Hw-rmcx";
    const TAIL: &str = "Tq-zvbn";
    let url = format!(
        "postgres://skyoauth@127.0.0.1:1/skyoauth?password={HEAD}#{TAIL}&sslmode=verify-full"
    );
    assert_rejected_at_trace(&url, "has a '#' fragment", &[HEAD, TAIL]);
}
