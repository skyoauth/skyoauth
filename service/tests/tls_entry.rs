//! The database TLS default, proven at the real entry point.
//!
//! These tests run the built `skyoauth-service migrate` binary as a child
//! process, with `PGSSLMODE` set on the child only, against a fake server
//! that answers sqlx's `SSLRequest` with "no TLS". What the client does next
//! shows the SSL mode it ended up with:
//!
//! - `verify-full` (and `require`) give up; no startup message follows;
//! - `prefer` falls back to plaintext and sends the startup message;
//! - `disable` never sends an `SSLRequest` at all.
//!
//! No database is needed. The fake server listens on `127.0.0.1`; the URL
//! reaches it as `0.0.0.0`, which counts as a remote host (it is not
//! loopback) but connects to the local machine on Linux and macOS.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// The first eight bytes of a PostgreSQL `SSLRequest`.
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
const SECRET: &str = "s3cr3t-pw-tls";

/// What one client connection did.
#[derive(Debug, Clone, Copy)]
struct Connection {
    /// The first packet was an `SSLRequest`.
    ssl_request: bool,
    /// More bytes (the startup message) arrived after the "no TLS" answer.
    startup_after_refusal: bool,
}

/// A fake PostgreSQL server that refuses TLS and records client behavior.
struct FakeServer {
    port: u16,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Connection>>>,
    handle: thread::JoinHandle<()>,
}

impl FakeServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handle = {
            let (stop, seen) = (stop.clone(), seen.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let outcome = serve(stream);
                            seen.lock().unwrap().push(outcome);
                        }
                        Err(_) => thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        };
        Self {
            port,
            stop,
            seen,
            handle,
        }
    }

    fn finish(self) -> Vec<Connection> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap();
        self.seen.lock().unwrap().clone()
    }
}

fn serve(mut stream: TcpStream) -> Connection {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut first = [0u8; 8];
    if stream.read_exact(&mut first).is_err() {
        return Connection {
            ssl_request: false,
            startup_after_refusal: false,
        };
    }
    let ssl_request = first == SSL_REQUEST;
    let mut startup_after_refusal = false;
    if ssl_request {
        stream.write_all(b"N").unwrap();
        let mut more = [0u8; 16];
        startup_after_refusal = matches!(stream.read(&mut more), Ok(n) if n > 0);
    }
    Connection {
        ssl_request,
        startup_after_refusal,
    }
}

/// Runs `skyoauth-service migrate` against `url`, with `pgsslmode` set on
/// the child only, and returns the fake server's observations and the output.
fn migrate_against_fake_server(
    url_for: impl Fn(u16) -> String,
    pgsslmode: Option<&str>,
) -> (Vec<Connection>, Output) {
    let server = FakeServer::start();
    let mut command = Command::new(env!("CARGO_BIN_EXE_skyoauth-service"));
    command
        .arg("migrate")
        .env("SKYOAUTH_DATABASE_URL", url_for(server.port))
        .env("SKYOAUTH_DATABASE_ACQUIRE_TIMEOUT_SECS", "1")
        .env("NO_COLOR", "1")
        .env("RUST_LOG", "info")
        .env_remove("PGSSLMODE");
    if let Some(mode) = pgsslmode {
        command.env("PGSSLMODE", mode);
    }
    let started = Instant::now();
    let output = command.output().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "migrate took too long"
    );
    (server.finish(), output)
}

fn all_output(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

#[test]
fn a_remote_host_without_sslmode_ignores_pgsslmode_and_refuses_plaintext() {
    for pgsslmode in [None, Some("disable"), Some("allow"), Some("prefer")] {
        let (seen, output) = migrate_against_fake_server(
            |port| format!("postgres://skyoauth:{SECRET}@0.0.0.0:{port}/skyoauth"),
            pgsslmode,
        );
        assert_eq!(output.status.code(), Some(1), "{pgsslmode:?}");
        assert!(!seen.is_empty(), "{pgsslmode:?}: no connection was made");
        for connection in &seen {
            assert!(
                connection.ssl_request,
                "{pgsslmode:?}: the client skipped TLS: {connection:?}"
            );
            assert!(
                !connection.startup_after_refusal,
                "{pgsslmode:?}: the client fell back to plaintext: {connection:?}"
            );
        }
        let text = all_output(&output);
        assert!(!text.contains(SECRET), "{pgsslmode:?}: {text}");
        assert!(!text.contains("weaker than verify-full"), "{text}");
    }
}

#[test]
fn an_explicit_weaker_mode_for_a_remote_host_is_honored_with_a_warning() {
    let (seen, output) = migrate_against_fake_server(
        |port| format!("postgres://skyoauth:{SECRET}@0.0.0.0:{port}/skyoauth?sslmode=prefer"),
        Some("verify-full"),
    );
    assert!(
        seen.iter()
            .any(|c| c.ssl_request && c.startup_after_refusal),
        "the explicit prefer should fall back to plaintext: {seen:?}"
    );
    let text = all_output(&output);
    assert!(text.contains("weaker than verify-full"), "{text}");
    assert!(text.contains("0.0.0.0"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
}

#[test]
fn a_loopback_host_without_sslmode_uses_prefer_whatever_pgsslmode_says() {
    for pgsslmode in [None, Some("disable"), Some("verify-full")] {
        let (seen, output) = migrate_against_fake_server(
            |port| format!("postgres://skyoauth:{SECRET}@127.0.0.1:{port}/skyoauth"),
            pgsslmode,
        );
        assert!(
            seen.iter()
                .any(|c| c.ssl_request && c.startup_after_refusal),
            "{pgsslmode:?}: expected an SSLRequest followed by plaintext: {seen:?}"
        );
        let text = all_output(&output);
        assert!(!text.contains("weaker than verify-full"), "{text}");
        assert!(!text.contains(SECRET), "{text}");
    }
}
