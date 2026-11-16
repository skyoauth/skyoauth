#![cfg(unix)]

use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

#[test]
fn sigterm_shuts_the_service_down_gracefully() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_skyoauth-service"))
        .env("SKYOAUTH_ADDR", "127.0.0.1:0")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // The signal handlers are installed before the listening line is logged.
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while !line.contains("listening") {
        line.clear();
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0, "exited early");
    }

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    // Success (rather than death by signal) means the graceful path ran.
    assert!(child.wait().unwrap().success());
}
