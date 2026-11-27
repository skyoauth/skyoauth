//! What the online commands share (Unix only, like the library's client):
//! the client of the socket flags, the exit code and message of a call that
//! did not succeed, the files they read, and how a reply's values are
//! printed (`docs/proposals/operator-cli-online.md`, "Exit codes" and
//! "Output and redaction").
//!
//! No message names a path, the socket's included, or repeats a value given
//! on the command line or read from a file: a failure is named by its flag
//! and its kind, with the library's fixed texts.

use std::fmt::Write as _;

use skyoauth_operator::{
    identity::MAX_SPKI_DER_BYTES,
    local::{
        AncestorTrust, CallError, CheckedSocketPath, LocalClient, MAX_REPLY_BYTES, NotSent, Op,
        PathProblem, Retry, SocketExpectations, Timeouts,
    },
};

use crate::{
    Failure,
    args::{OperationArtifact, SocketFlags, TrustAncestors},
    artifact,
    cmd_verify_response::MAX_RESPONSE_BYTES,
    input,
    show::quoted,
};

/// The client of the socket the flags name, its path checked before every
/// connect (`LocalClient::new`, never `unchecked`).
pub fn client(flags: &SocketFlags) -> LocalClient<CheckedSocketPath> {
    let ancestors = match flags.trust_ancestors {
        TrustAncestors::ServiceOrRoot => AncestorTrust::ServiceOrRoot,
        TrustAncestors::RootOnly => AncestorTrust::RootOnly,
    };
    LocalClient::new(
        &flags.socket,
        SocketExpectations {
            owner_uid: flags.service_uid,
            ancestors,
        },
        Timeouts {
            total: flags.total_wait,
            idle: flags.idle_wait,
        },
    )
}

/// The failure of a call of `op` that did not succeed, by the proposal's
/// table: refused by the service, or a request too large to send, is 1;
/// not sent is 6; an unknown outcome is 6 after an operation that changes
/// no row (`Retry::Safe`: `preview`, `status`) and 5 after a write
/// (`Retry::ReconcileFirst`).
pub fn failure(op: Op, err: CallError) -> Failure {
    match err {
        CallError::NotSent(NotSent::TooLarge) => Failure::Refused(format!(
            "refused (TooLarge): the request was not sent: {}",
            NotSent::TooLarge
        )),
        CallError::NotSent(why) => {
            Failure::Unchanged(format!("the request was not sent: {}", not_sent(why)))
        }
        CallError::Refused(code) => Failure::Refused(format!("refused ({}): {err}", code.as_str())),
        CallError::Unknown(why) => match op.retry() {
            Retry::Safe => Failure::Unchanged(format!(
                "the reply cannot be believed ({why}); {} changes nothing",
                op.as_str()
            )),
            Retry::ReconcileFirst => Failure::Unknown(err.to_string()),
        },
    }
}

/// Why a request was not sent: the library's fixed text, a refused socket
/// path named by its flag and its problem, an error by its kind.
fn not_sent(why: NotSent) -> String {
    match why {
        NotSent::Path(problem @ PathProblem::Lookup(kind)) => {
            format!("--socket: {problem} ({kind})")
        }
        NotSent::Path(problem) => format!("--socket: {problem}"),
        NotSent::Connect(kind) | NotSent::Setup(kind) => format!("{why} ({kind})"),
        other => other.to_string(),
    }
}

/// The operation ID of the artifact `--challenge` or `--response` names,
/// read and checked as D1 reads it (any signature length: only the ID is
/// used).
pub fn operation_id(artifact: &OperationArtifact) -> Result<String, Failure> {
    match artifact {
        OperationArtifact::Challenge(path) => {
            let bytes = input::read_file("--challenge", path, MAX_REPLY_BYTES)?;
            Ok(artifact::challenge(&bytes)?.operation_id().to_owned())
        }
        OperationArtifact::Response(path) => {
            let bytes = input::read_file("--response", path, MAX_RESPONSE_BYTES)?;
            Ok(artifact::response(&bytes)?.operation_id)
        }
    }
}

/// The DER `SubjectPublicKeyInfo` of the file `--credential-spki` names:
/// 1 to [`MAX_SPKI_DER_BYTES`] bytes, sent as they are (no PEM).
pub fn credential_spki(path: &std::path::Path) -> Result<Vec<u8>, Failure> {
    let bytes = input::read_file("--credential-spki", path, MAX_SPKI_DER_BYTES)?;
    if bytes.is_empty() {
        return Err(Failure::Io(
            "--credential-spki: the file is empty".to_owned(),
        ));
    }
    Ok(bytes)
}

/// Bytes in lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A string of the service, quoted, or `null`.
pub fn text_or_null(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), quoted)
}

/// An integer in decimal, or `null`.
pub fn integer_or_null(value: Option<i64>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| value.to_string())
}

/// Bytes in lowercase hexadecimal, or `null`.
pub fn hex_or_null(value: Option<&[u8]>) -> String {
    value.map_or_else(|| "null".to_owned(), hex)
}
