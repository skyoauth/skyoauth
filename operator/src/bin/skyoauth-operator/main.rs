//! `skyoauth-operator`: the operator command line (T13.10; the artifact
//! formats and exit codes are in `docs/proposals/operator-cli-artifacts.md`,
//! the online commands in `docs/proposals/operator-cli-online.md`).
//!
//! Three commands offline:
//!
//! - `verify-challenge` reads a challenge artifact (the `issue_challenge`
//!   reply line, verbatim), checks it with
//!   [`parse_challenge`](skyoauth_operator::recovery::parse_challenge) and
//!   [`check_challenge`](skyoauth_operator::recovery::check_challenge)
//!   against the flags given, and prints the restoration plan for the
//!   operator to compare, with whether the replacement was confirmed;
//! - `sign` checks a challenge artifact as `verify-challenge` does, every
//!   expectation required, signs it with the key of a seed file (the
//!   library's signing, in `cmd_sign.rs` only) and writes the response
//!   artifact to a new file (`--out`, required);
//! - `verify-response` checks a response artifact's signature over the
//!   challenge with a recovery public key, as the service's restore checks
//!   it ([`verify_response`](skyoauth_operator::recovery::verify_response)).
//!
//!
//! The offline commands read no socket. Five more are online: they talk to
//! the service over its deployment-local Unix socket, on the service's host
//! (Unix only: elsewhere they are parsed, then refused with exit 2). Three
//! write, each with one request, never repeated:
//!
//! - `bootstrap` sends the first operator and the recovery key of a new
//!   instance and prints what the service wrote;
//! - `issue-challenge` asks for a recovery challenge and writes the reply
//!   line, verbatim, to a new file (`--out`, created before the request is
//!   sent): the challenge artifact;
//! - `restore` sends a response artifact and prints the replacement it
//!   enrolled and the credential IDs it revoked;
//!
//! and two read and change nothing there:
//!
//! - `preview` sends a response artifact and prints what its restore would
//!   enroll;
//! - `status` prints the recovery state, an operation's state (every
//!   credential ID a restore revoked, page by page) and a key's
//!   enrollment, and, to reconcile a restore or a bootstrap of unknown
//!   outcome, the verdict and the next step.
//!
//! Results go to standard output, errors to standard error, both
//! deterministic for the same arguments and files (the system clock aside,
//! which `--now` replaces, and the service's answers). Nothing reads the
//! environment. The only files written are the `--out` of `sign` and of
//! `issue-challenge`, each created new; the only private key is the seed of
//! `sign`'s `--seed-file`, read from that file only, never shown. No
//! signature is shown: `sign` writes it to `--out` only, and `preview` and
//! `restore` send it to the socket only. No message names a path, the
//! socket's included.
//!
//! Exit codes: [`EXIT_OK`], [`EXIT_REFUSED`], [`EXIT_USAGE`], [`EXIT_IO`],
//! [`EXIT_NOT_CONFIRMED`], [`EXIT_UNKNOWN`], [`EXIT_UNCHANGED`].

#![forbid(unsafe_code)]

mod args;
mod artifact;
#[cfg(unix)]
mod cmd_bootstrap;
#[cfg(unix)]
mod cmd_issue_challenge;
#[cfg(unix)]
mod cmd_preview;
#[cfg(unix)]
mod cmd_restore;
mod cmd_sign;
#[cfg(unix)]
mod cmd_status;
mod cmd_verify_challenge;
mod cmd_verify_response;
mod input;
#[cfg(unix)]
mod online;
mod out_file;
mod seed_file;
mod show;

use std::{
    io::{self, Write},
    process::ExitCode,
};

use args::Command;

/// Every check passed (for `verify-challenge`, the replacement is
/// confirmed; for `sign`, the response is written), or the help was
/// printed.
const EXIT_OK: u8 = 0;

/// An artifact was refused: a check failed, an artifact is not what it
/// must be, `sign` refused to sign, or a seed file's bytes are not a seed.
const EXIT_REFUSED: u8 = 1;

/// The command line is wrong: an unknown command or flag, a flag missing,
/// repeated or without a value, a value that does not parse; an online
/// command on a platform without Unix sockets.
const EXIT_USAGE: u8 = 2;

/// A file could not be read (missing, not a regular file, too large,
/// unreadable; for a seed file also a symbolic link, or on Unix not owned
/// by the effective user or not of mode 0600), the system clock could not
/// be read, `--out` exists or could not be created or written, or the
/// output could not be written (whatever the command's result was; after a
/// write that succeeded, the message says what was committed).
const EXIT_IO: u8 = 3;

/// `verify-challenge`: every given check passed, but the replacement is not
/// confirmed, since its identity, trust anchor or new recovery key was not
/// given. Never 0: an omitted value is not a passed check.
const EXIT_NOT_CONFIRMED: u8 = 4;

/// The outcome of an online write is unknown: the service may have
/// committed it (`bootstrap`, `issue-challenge`, `restore`). Do not repeat
/// it: the message's next line says what to run first. `preview` and
/// `status` never exit 5.
const EXIT_UNKNOWN: u8 = 5;

/// Nothing was changed by this command: the request was not sent, or the
/// reply of a `preview` or a `status` cannot be believed (they change no
/// row). The same command may be run again.
const EXIT_UNCHANGED: u8 = 6;

/// The line after the message of [`EXIT_UNCHANGED`]: what to do next.
const UNCHANGED_NEXT: &str = "Nothing was changed by this command: it may be run again.\n";

/// Why a command did not succeed, with its fixed message. The message
/// never holds a signature, a seed, a key given on the command line, a
/// file's bytes or a value of an artifact.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// [`EXIT_REFUSED`].
    Refused(String),
    /// [`EXIT_USAGE`].
    Usage(String),
    /// [`EXIT_IO`].
    Io(String),
    /// [`EXIT_NOT_CONFIRMED`].
    NotConfirmed(String),
    /// [`EXIT_UNKNOWN`].
    #[cfg_attr(not(unix), allow(dead_code))]
    Unknown(String),
    /// [`EXIT_UNCHANGED`].
    #[cfg_attr(not(unix), allow(dead_code))]
    Unchanged(String),
}

impl Failure {
    const fn code(&self) -> u8 {
        match self {
            Self::Refused(_) => EXIT_REFUSED,
            Self::Usage(_) => EXIT_USAGE,
            Self::Io(_) => EXIT_IO,
            Self::NotConfirmed(_) => EXIT_NOT_CONFIRMED,
            Self::Unknown(_) => EXIT_UNKNOWN,
            Self::Unchanged(_) => EXIT_UNCHANGED,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Refused(message)
            | Self::Usage(message)
            | Self::Io(message)
            | Self::NotConfirmed(message)
            | Self::Unknown(message)
            | Self::Unchanged(message) => message,
        }
    }

    /// The same failure, `line` added to its message on a line of its own.
    #[cfg(unix)]
    fn with_line(mut self, line: &str) -> Self {
        let (Self::Refused(message)
        | Self::Usage(message)
        | Self::Io(message)
        | Self::NotConfirmed(message)
        | Self::Unknown(message)
        | Self::Unchanged(message)) = &mut self;
        message.push('\n');
        message.push_str(line);
        self
    }
}

/// What a command prints on standard output, and how it ended. The output
/// is printed in both cases: a refused challenge still shows its plan.
struct Outcome {
    output: String,
    result: Result<(), Failure>,
}

impl From<Failure> for Outcome {
    fn from(failure: Failure) -> Self {
        Self {
            output: String::new(),
            result: Err(failure),
        }
    }
}

fn run(command: Command) -> Outcome {
    match command {
        Command::Help => Outcome {
            output: args::HELP.to_owned(),
            result: Ok(()),
        },
        Command::VerifyChallenge(flags) => cmd_verify_challenge::run(&flags),
        Command::Sign(flags) => cmd_sign::run(&flags),
        Command::VerifyResponse(flags) => cmd_verify_response::run(&flags),
        #[cfg(unix)]
        Command::Bootstrap(flags) => cmd_bootstrap::run(&flags),
        #[cfg(unix)]
        Command::IssueChallenge(flags) => cmd_issue_challenge::run(&flags),
        #[cfg(unix)]
        Command::Preview(flags) => cmd_preview::run(&flags),
        #[cfg(unix)]
        Command::Restore(flags) => cmd_restore::run(&flags),
        #[cfg(unix)]
        Command::Status(flags) => cmd_status::run(&flags),
        #[cfg(not(unix))]
        online @ (Command::Bootstrap(_)
        | Command::IssueChallenge(_)
        | Command::Preview(_)
        | Command::Restore(_)
        | Command::Status(_)) => no_socket(&online),
    }
}

/// What a write that succeeded committed, said after its output could not
/// be written, so the operator does not repeat it
/// (`docs/proposals/operator-cli-online.md`, "Output and redaction").
const fn committed(command: &Command) -> Option<&'static str> {
    match command {
        Command::Bootstrap(_) => Some(
            "the bootstrap committed, but its output cannot be written: run status --reconcile \
             bootstrap",
        ),
        Command::IssueChallenge(_) => {
            Some("the challenge was issued and --out is complete, but its output cannot be written")
        }
        Command::Restore(_) => Some(
            "the restore committed, but its output cannot be written: run status --reconcile \
             restore",
        ),
        Command::Help
        | Command::VerifyChallenge(_)
        | Command::Sign(_)
        | Command::VerifyResponse(_)
        | Command::Preview(_)
        | Command::Status(_) => None,
    }
}

/// An online command on a platform without Unix sockets: parsed, then
/// refused with a fixed text before any file is read
/// (`docs/proposals/operator-cli-online.md`, Q7).
#[cfg(not(unix))]
fn no_socket(command: &Command) -> Outcome {
    let name = command.online_name().unwrap_or("this command");
    Failure::Usage(format!(
        "{name} needs the deployment-local Unix socket, which this platform does not have"
    ))
    .into()
}

/// Writes `output` to standard output, flushed.
fn write_output(output: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    stdout.flush()
}

fn main() -> ExitCode {
    let (outcome, committed) = match args::parse(std::env::args_os().skip(1)) {
        Ok(command) => {
            let committed = committed(&command);
            (run(command), committed)
        }
        Err(failure) => (failure.into(), None),
    };
    let mut code = match &outcome.result {
        Ok(()) => EXIT_OK,
        Err(failure) => failure.code(),
    };
    let mut errors = String::new();
    if let Err(failure) = &outcome.result {
        errors.push_str(&format!("skyoauth-operator: {}\n", failure.message()));
        match failure {
            Failure::Usage(_) => errors.push_str("Run `skyoauth-operator --help` for the usage.\n"),
            Failure::Unchanged(_) => errors.push_str(UNCHANGED_NEXT),
            _ => {}
        }
    }
    // The result was not delivered: exit 3, whatever it was, and say why.
    if let Err(err) = write_output(&outcome.output) {
        code = EXIT_IO;
        errors.push_str(&format!(
            "skyoauth-operator: the output cannot be written ({})\n",
            err.kind()
        ));
        if let (Ok(()), Some(committed)) = (&outcome.result, committed) {
            errors.push_str(committed);
            errors.push('\n');
        }
    }
    if !errors.is_empty() {
        let mut stderr = io::stderr().lock();
        // Standard error is the last channel: its failure is reported by the
        // exit code alone.
        if stderr
            .write_all(errors.as_bytes())
            .and_then(|()| stderr.flush())
            .is_err()
        {
            code = EXIT_IO;
        }
    }
    ExitCode::from(code)
}
