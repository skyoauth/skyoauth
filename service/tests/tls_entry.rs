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
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// How long one `migrate` run may take before it is killed. Each run fails
/// within the 1-second acquire timeout; the margin is for slow CI machines.
const DEADLINE: Duration = Duration::from_secs(30);

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
    migrate_with_env(url_for, pgsslmode, None)
}

/// As [`migrate_against_fake_server`], also setting `PGHOSTADDR` on the child.
fn migrate_with_env(
    url_for: impl Fn(u16) -> String,
    pgsslmode: Option<&str>,
    pghostaddr: Option<&str>,
) -> (Vec<Connection>, Output) {
    let server = FakeServer::start();
    let mut command = Command::new(env!("CARGO_BIN_EXE_skyoauth-service"));
    command
        .arg("migrate")
        .env("SKYOAUTH_DATABASE_URL", url_for(server.port))
        .env("SKYOAUTH_DATABASE_ACQUIRE_TIMEOUT_SECS", "1")
        .env("NO_COLOR", "1")
        .env("RUST_LOG", "info")
        .env_remove("PGSSLMODE")
        .env_remove("PGHOSTADDR");
    if let Some(mode) = pgsslmode {
        command.env("PGSSLMODE", mode);
    }
    if let Some(address) = pghostaddr {
        command.env("PGHOSTADDR", address);
    }
    let output = output_within(&mut command, DEADLINE);
    (server.finish(), output)
}

/// Runs `command` to completion and collects its output, killing it if it
/// is still running after `deadline`. stdout and stderr are drained on their
/// own threads, so a chatty child cannot block on a full pipe.
fn output_within(command: &mut Command, deadline: Duration) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let drain = |mut pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).unwrap();
            bytes
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            let (stdout, stderr) = (stdout.join().unwrap(), stderr.join().unwrap());
            panic!(
                "migrate did not finish within {deadline:?}:\n{}{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        thread::sleep(Duration::from_millis(20));
    };
    Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

fn all_output(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

/// The log lines carrying the weak-TLS WARN.
fn weak_tls_warnings(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| line.contains("weaker than verify-full"))
        .collect()
}

#[test]
fn a_remote_host_without_sslmode_ignores_pgsslmode_and_refuses_plaintext() {
    for pgsslmode in [
        None,
        Some("disable"),
        Some("allow"),
        Some("prefer"),
        Some("require"),
        Some("verify-ca"),
    ] {
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
    let warnings = weak_tls_warnings(&text);
    assert_eq!(warnings.len(), 1, "{text}");
    assert!(warnings[0].contains("WARN"), "{text}");
    assert!(warnings[0].contains("host=\"0.0.0.0\""), "{text}");
    assert!(!text.contains(SECRET), "{text}");
}

/// The WARN names the dialed `hostaddr` as well as the host name.
#[test]
fn the_warning_for_a_remote_hostaddr_names_the_address() {
    let (seen, output) = migrate_against_fake_server(
        |port| {
            format!(
                "postgres://skyoauth:{SECRET}@localhost:{port}/skyoauth?hostaddr=0.0.0.0&sslmode=prefer"
            )
        },
        None,
    );
    assert!(
        seen.iter()
            .any(|c| c.ssl_request && c.startup_after_refusal),
        "the explicit prefer should fall back to plaintext: {seen:?}"
    );
    let text = all_output(&output);
    let warnings = weak_tls_warnings(&text);
    assert_eq!(warnings.len(), 1, "{text}");
    assert!(warnings[0].contains("host=\"localhost\""), "{text}");
    assert!(warnings[0].contains("hostaddr=0.0.0.0"), "{text}");
    assert!(text.contains("hostaddr: Some(0.0.0.0)"), "{text}");
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

/// sqlx dials `hostaddr` in preference to the host name, so the TLS default
/// follows the address: a loopback name with a non-loopback address is remote.
#[test]
fn a_loopback_name_with_a_remote_hostaddr_still_refuses_plaintext() {
    let by_url = |port: u16| {
        format!("postgres://skyoauth:{SECRET}@localhost:{port}/skyoauth?hostaddr=0.0.0.0")
    };
    let by_env = |port: u16| format!("postgres://skyoauth:{SECRET}@localhost:{port}/skyoauth");
    for (what, (seen, output)) in [
        ("hostaddr in the URL", migrate_with_env(by_url, None, None)),
        (
            "PGHOSTADDR in the environment",
            migrate_with_env(by_env, Some("disable"), Some("0.0.0.0")),
        ),
    ] {
        assert!(!seen.is_empty(), "{what}: the fixture was not dialed");
        for connection in &seen {
            assert!(connection.ssl_request, "{what}: {connection:?}");
            assert!(!connection.startup_after_refusal, "{what}: {connection:?}");
        }
        assert!(!all_output(&output).contains(SECRET), "{what}");
    }
}

/// The reverse: a remote-looking name whose address is loopback is local.
#[test]
fn a_remote_name_with_a_loopback_hostaddr_uses_prefer() {
    let (seen, output) = migrate_against_fake_server(
        |port| {
            format!("postgres://skyoauth:{SECRET}@db.example:{port}/skyoauth?hostaddr=127.0.0.1")
        },
        None,
    );
    assert!(
        seen.iter()
            .any(|c| c.ssl_request && c.startup_after_refusal),
        "{seen:?}"
    );
    let text = all_output(&output);
    assert!(!text.contains("weaker than verify-full"), "{text}");
    assert!(!text.contains(SECRET), "{text}");
}

/// An encoded `sslmode` key is still an explicit mode.
#[test]
fn an_encoded_sslmode_key_is_honored_on_a_loopback_host() {
    let (seen, _) = migrate_against_fake_server(
        |port| {
            format!("postgres://skyoauth:{SECRET}@127.0.0.1:{port}/skyoauth?ssl%6Dode=verify-full")
        },
        Some("disable"),
    );
    assert!(!seen.is_empty());
    for connection in &seen {
        assert!(connection.ssl_request, "{connection:?}");
        assert!(!connection.startup_after_refusal, "{connection:?}");
    }
}
