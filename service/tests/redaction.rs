//! The database password must not appear in connection errors (`Display`
//! or `Debug`) or in logs captured at trace level, on real failure paths.
//!
//! The unreachable-host and refused-connection tests need no server. The TLS
//! and wrong-password tests need `SKYOAUTH_IT_DATABASE_URL` and are
//! `#[ignore]`d like the migration tests; run them with
//! `cargo nextest run --run-ignored all` or `cargo test -- --include-ignored`.

use std::{
    io,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use skyoauth_service::persistence::{self, DatabaseConfig};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

const SECRET: &str = "s3cr3t-pw-7f2c";

/// Log output captured in memory.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// Connects as the `migrate` command does, with every log level captured,
/// and asserts that the connection fails without the password showing up in
/// the error or the logs.
async fn assert_failure_omits_password(connect: PgConnectOptions) {
    let config =
        DatabaseConfig::new(connect.password(SECRET), None, 2, Duration::from_secs(2)).unwrap();
    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .with_writer(logs.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::info!(database = ?config, "connecting");
    let err = persistence::connect(&config)
        .await
        .expect_err("the connection was expected to fail");
    drop(guard);

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("connecting"), "log capture is not working");
    for (what, text) in [
        ("Display", err.to_string()),
        ("Debug", format!("{err:?}")),
        ("logs", logs),
    ] {
        assert!(!text.contains(SECRET), "password in {what}: {text}");
    }
}

fn it_database_url() -> String {
    std::env::var("SKYOAUTH_IT_DATABASE_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .expect("SKYOAUTH_IT_DATABASE_URL must be set to run this database test")
}

#[tokio::test]
async fn unresolvable_host_failure_omits_the_password() {
    // `.invalid` never resolves (RFC 2606).
    let connect = PgConnectOptions::from_str("postgres://skyoauth@skyoauth-db.invalid/skyoauth");
    assert_failure_omits_password(connect.unwrap()).await;
}

#[tokio::test]
async fn refused_connection_failure_omits_the_password() {
    // Port 1 on loopback refuses connections.
    let connect = PgConnectOptions::from_str("postgres://skyoauth@127.0.0.1:1/skyoauth");
    assert_failure_omits_password(connect.unwrap()).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn tls_failure_omits_the_password() {
    // Fails whether or not the server offers TLS: without TLS, verify-full
    // refuses to continue; with it, the root certificate cannot be read.
    let connect = PgConnectOptions::from_str(&it_database_url())
        .unwrap()
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert("/nonexistent/skyoauth-test-ca.pem");
    assert_failure_omits_password(connect).await;
}

#[tokio::test]
#[ignore = "requires SKYOAUTH_IT_DATABASE_URL"]
async fn wrong_password_failure_omits_the_password() {
    let connect = PgConnectOptions::from_str(&it_database_url()).unwrap();
    assert_failure_omits_password(connect).await;
}
