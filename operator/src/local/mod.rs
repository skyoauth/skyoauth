//! The wire codec of the service's deployment-local bootstrap and recovery
//! transport (T13.4, T13.5; the service's `local_transport` module, whose
//! wire format is this module's contract): the request line the client
//! writes and the reply line it reads, for the four operations
//! `bootstrap`, `issue_challenge`, `preview` and `restore`.
//!
//! The codec turns a [`Request`] into the exact bytes to write
//! ([`Request::encode`]) and the bytes read back into a [`Reply`], a
//! refusal or an unknown outcome ([`parse_reply`]); [`LocalClient`]
//! exchanges one request for its reply over a connection, with its time
//! limits and the classification of its outcome (see its documentation).
//! The socket's path, owner, mode and directories are checked before
//! every connect by [`LocalClient::with_checked_socket`]
//! ([`CheckedSocketPath`], [`check_socket`]: the service's rules for its
//! socket file, pinned by
//! `tests/conformance/fixtures/_wire/socket_path.v1.json`), the client a
//! real caller uses; [`LocalClient::new`] ([`SocketPath`]) connects
//! unchecked.
//!
//! # Framing
//!
//! One request per connection: the client writes **one JSON object on one
//! line, then the newline, then closes its write half**
//! (`shutdown(SHUT_WR)`); the server dispatches the request only once it
//! has read that end of the stream, so a well-formed line whose client
//! keeps its write half open is never dispatched or answered (the server's
//! idle timeout or deadline closes the connection). A request line is at
//! most [`MAX_REQUEST_BYTES`] (64 KiB) with its newline;
//! [`Request::encode`] refuses a longer one ([`NotSent::TooLarge`]), so it
//! is never written and no connection is made for it. The server answers
//! with one JSON object on one line and its newline, then closes the
//! connection.
//!
//! The server may answer before it has read the whole request: a peer it
//! refuses gets `forbidden` at once, before any read, and a line over
//! 64 KiB or a byte after the newline gets `invalid_request` as soon as it
//! is read. So the exchange ([`LocalClient`]) still reads the reply after
//! its write fails (`EPIPE`: the server answered and closed first), and
//! keeps the bytes it read before an `ECONNRESET` (the server closed with
//! request bytes unread).
//!
//! The wire format is inferred: the service's module docs say no contract
//! text fixes it. The fixture
//! `tests/conformance/fixtures/_wire/local_transport.v1.json` holds its
//! golden lines; this crate's `operator` test target and the service's side
//! (`tests/harness/local_transport_wire.rs` in `skyoauth-scenarios`) check
//! the same file.
//!
//! # Outcomes
//!
//! Every call ends in exactly one of four outcomes, a success or one of the
//! three kinds of [`CallError`]:
//!
//! - **a success**, the reply of the operation's own shape ([`Reply`]);
//! - **refused**, `{"error":"<code>"}` with a code of the closed set
//!   [`ErrorCode::ALL`] ([`CallError::Refused`]): the server answered, and
//!   its transaction was rolled back. One exception, from the service's
//!   docs ("Transactions"): a `COMMIT` that fails, or whose
//!   acknowledgement is lost, is answered as a store failure,
//!   [`ErrorCode::AuthUnavailable`] (a lost connection) or
//!   [`ErrorCode::ServerError`], and its outcome is then unknown, for each
//!   of the three operations that write: `bootstrap`, `issue_challenge`
//!   and `restore`. A rollback after which a repeat could still succeed
//!   can never be confirmed through this socket. The codec reports what
//!   the server sent: [`parse_reply`] returns `Refused(AuthUnavailable)`
//!   or `Refused(ServerError)` for these, for every operation. The
//!   client's call ([`LocalClient`]) reports these two codes as
//!   an unknown outcome ([`CallError::Unknown`], carrying the wire code)
//!   for `bootstrap`, `issue_challenge` and `restore`, and as
//!   [`CallError::Refused`] only for `preview`, which writes nothing:
//!   after a write, reconcile first;
//! - **not sent** ([`CallError::NotSent`]): nothing was written to the
//!   server, so nothing happened there;
//! - **unknown** ([`CallError::Unknown`]): anything else. A missing,
//!   truncated, oversized or malformed reply, bytes after its newline, a
//!   second line, a refusal with a code outside the closed set: the
//!   request may or may not have been served, and a bootstrap, an issue or
//!   a restore may have committed. **Do not proceed: reconcile first** (read the
//!   recovery state and the operator through another channel), then decide.
//!
//! **The client never retries on its own**, after any outcome. Once a
//! first bootstrap committed, a repeat of it is answered `conflict`; once
//! a first restore of a challenge committed, a repeat of it is answered
//! `not_restorable` (the service's docs, "Transactions"): the repeat's
//! answer looks like a refusal and hides the first call's success. Once a
//! first issue committed, a repeat of it makes a second live challenge
//! (the first expires unused). No write is safe to repeat without
//! reconciling first, `issue_challenge` included.
//!
//! # Key material
//!
//! A `preview` or `restore` request carries only the operation ID and the
//! 64 signature bytes ([`ResponseRequest`]); nothing here holds or names a
//! private key. `Debug` of every request, reply and error type names its
//! kind only, and `Display` of every error is fixed text: no ID, key,
//! signature or challenge byte is shown.
//!
//! Unix only, like the service's transport (`cfg(unix)` in `lib.rs`).

mod exchange;
mod path;
mod wire;

use std::{fmt, io};

pub use exchange::{
    Connector, DEFAULT_IDLE_WAIT, DEFAULT_TOTAL_WAIT, HalfClose, LocalClient, Retry, SocketPath,
    Timeouts,
};
pub use path::{
    AncestorTrust, CheckedSocket, CheckedSocketPath, MAX_SOCKET_PATH_BYTES, MAX_SYMLINKS,
    PathError, PathProblem, SOCKET_MODE, SocketExpectations, check_socket,
};
pub use wire::parse_reply;

use crate::recovery::RecoveryPublicKey;

/// The largest request line, its newline included: 64 KiB (the service's
/// `local_transport::MAX_REQUEST_BYTES`).
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// The largest reply line [`parse_reply`] reads, its newline included:
/// 4 MiB. Inferred: the service sets no bound on its replies, and one of
/// them has none of its own: a restore's `revoked_credential_ids` lists
/// every credential the restore revoked (all of them), some 34 bytes per
/// ID, so a reply over 64 KiB takes fewer than 2000 credentials. The cap
/// is not a limit of the protocol: it only bounds what the client holds
/// (it reads the whole reply before parsing it) when the peer misbehaves,
/// and 4 MiB holds some 120,000 revoked IDs. A reply over it is
/// [`UnknownOutcome::TooLarge`]: the request may have been served, a
/// restore may have committed, so reconcile first. A request line stays
/// at most [`MAX_REQUEST_BYTES`].
///
/// Open question for the service and the design, not settled here: a
/// reply with no bound of its own. The 4 MiB figure is arbitrary; a
/// bounded reply format (a count, or the revoked IDs read some other way)
/// would need a change to the service.
pub const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// An operation of the transport, by its request's `op` member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// `bootstrap`: the first operator and the recovery key of a new
    /// instance.
    Bootstrap,
    /// `issue_challenge`: a recovery challenge for a replacement operator.
    IssueChallenge,
    /// `preview`: what a signed response would restore; writes nothing.
    Preview,
    /// `restore`: the restoration a signed response authorizes.
    Restore,
}

impl Op {
    /// Every operation.
    pub const ALL: [Self; 4] = [
        Self::Bootstrap,
        Self::IssueChallenge,
        Self::Preview,
        Self::Restore,
    ];

    /// The value of the request's `op` member.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::IssueChallenge => "issue_challenge",
            Self::Preview => "preview",
            Self::Restore => "restore",
        }
    }
}

/// The value of a refusal's one member, `error`: the closed set of the
/// service's `local_transport::ErrorCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The peer's UID is neither the service UID nor root.
    Forbidden,
    /// The request, or one of its values, is malformed.
    InvalidRequest,
    /// The stored state refuses the request: bootstrap is closed, the
    /// instance ID is not the stored one, no challenge can be issued, a
    /// value is already registered.
    Conflict,
    /// The signed response does not authorize a restoration.
    NotRestorable,
    /// The store was unavailable or the transaction was aborted
    /// (serialization failure, timeout); nothing was written, unless a
    /// failed `COMMIT` was answered this way: its outcome is then unknown,
    /// so reconcile before retrying a bootstrap, an issue or a restore (see
    /// the [module documentation](self), "Outcomes").
    AuthUnavailable,
    /// A server or data-integrity error; nothing was written, unless a
    /// failed `COMMIT` was answered this way: its outcome is then unknown,
    /// so reconcile first after a bootstrap, an issue or a restore (see the
    /// [module documentation](self), "Outcomes").
    ServerError,
}

impl ErrorCode {
    /// Every code, in the service's order.
    pub const ALL: [Self; 6] = [
        Self::Forbidden,
        Self::InvalidRequest,
        Self::Conflict,
        Self::NotRestorable,
        Self::AuthUnavailable,
        Self::ServerError,
    ];

    /// The wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::InvalidRequest => "invalid_request",
            Self::Conflict => "conflict",
            Self::NotRestorable => "not_restorable",
            Self::AuthUnavailable => "auth_unavailable",
            Self::ServerError => "server_error",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Forbidden => "forbidden: the caller's UID may not use the local transport",
            Self::InvalidRequest => {
                "invalid_request: the request or one of its values is malformed"
            }
            Self::Conflict => "conflict: the stored state refuses the request",
            Self::NotRestorable => {
                "not_restorable: the signed response does not authorize a restoration"
            }
            Self::AuthUnavailable => {
                "auth_unavailable: the store was unavailable or the transaction was aborted \
                 (serialization failure, timeout); reconcile before retrying a bootstrap, an \
                 issue or a restore"
            }
            Self::ServerError => "server_error: a server or data-integrity error",
        })
    }
}

/// Why a request was not sent: nothing was written to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotSent {
    /// The request line is longer than [`MAX_REQUEST_BYTES`].
    TooLarge,
    /// [`Timeouts::total`] or [`Timeouts::idle`] is zero; nothing was
    /// connected.
    InvalidTimeouts,
    /// No connection was made, with the error's kind (a missing path, a
    /// path that is not a listening socket, a permission refused, ...), or
    /// the call's thread could not start.
    Connect(io::ErrorKind),
    /// [`Timeouts::total`] ran out before anything was written: while
    /// connecting (a connection made later is dropped before anything is
    /// written to it), or between the connect and the first write.
    TimedOut,
    /// The connection refused the wait of the first write, with the error's
    /// kind ([`HalfClose::set_write_wait`]); nothing was written to it.
    Setup(io::ErrorKind),
    /// [`CheckedSocketPath`] refused the socket path, by its problem: before
    /// the connect, or after it when the path no longer held the checked
    /// socket ([`PathProblem::Changed`]; the connection is dropped before
    /// anything is written to it).
    Path(PathProblem),
}

impl fmt::Display for NotSent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "the request line is larger than 64 KiB",
            Self::InvalidTimeouts => "a timeout of the client is zero",
            Self::Connect(_) => "no connection to the local transport could be made",
            Self::TimedOut => "the total wait ran out before anything was written",
            Self::Setup(_) => "the connection refused the time limit of the first write",
            Self::Path(_) => "the local socket's path, owner or mode was refused",
        })
    }
}

/// Why the outcome of a request is unknown: the server may or may not have
/// served it. Do not proceed; reconcile first (see the [module
/// documentation](self), "Outcomes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnknownOutcome {
    /// The reply does not end with a newline: no byte at all, or a line cut
    /// short.
    Truncated,
    /// Bytes after the reply's first newline: a second line, or anything
    /// else.
    TrailingBytes,
    /// The reply is longer than [`MAX_REPLY_BYTES`].
    TooLarge,
    /// The reply line is not UTF-8.
    NotUtf8,
    /// The reply line is neither the success of the request's operation,
    /// exactly as the service writes it, nor a refusal: not a JSON object,
    /// an unknown, missing, repeated, reordered or mistyped member,
    /// whitespace, an escape the service does not write, a number that is
    /// not a 64-bit integer in its shortest form, or another operation's
    /// success.
    Malformed,
    /// A refusal whose code is not in [`ErrorCode::ALL`].
    UnknownCode,
    /// [`Timeouts::total`] or [`Timeouts::idle`] ran out once the request
    /// may have been written, before the end of the reply.
    TimedOut,
    /// The connection failed, with the error's kind: a write or a reset
    /// after which what was read is not a refusal (the server did not read
    /// the whole request), or any other failed read (see [`LocalClient`]).
    ConnectionLost(io::ErrorKind),
    /// A write refused with a store failure, the code carried
    /// ([`ErrorCode::AuthUnavailable`] or [`ErrorCode::ServerError`]),
    /// which a failed `COMMIT` is also answered with (see [`LocalClient`]).
    UncertainCommit(ErrorCode),
    /// An issue's reply whose challenge
    /// [`parse_challenge`](crate::recovery::parse_challenge) refuses, or
    /// whose `operation_id`, `expires_at` or `expected_revision` is not its
    /// challenge's.
    ChallengeMismatch,
}

impl fmt::Display for UnknownOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "the reply does not end with a newline",
            Self::TrailingBytes => "the reply has bytes after its newline",
            Self::TooLarge => "the reply is larger than 4 MiB",
            Self::NotUtf8 => "the reply is not UTF-8",
            Self::Malformed => "the reply is not a reply of the request's operation",
            Self::UnknownCode => "the reply refuses with an unknown code",
            Self::TimedOut => "the wait for the reply ran out",
            Self::ConnectionLost(_) => "the connection failed before a reply could be believed",
            Self::UncertainCommit(_) => "a write failed in the store, maybe in its commit",
            Self::ChallengeMismatch => "the issued reply does not match its challenge",
        })
    }
}

/// A call that did not succeed: not sent, refused or of unknown outcome
/// (see the [module documentation](self), "Outcomes"). `Debug` names the
/// kind only, `Display` is fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    /// Nothing was written to the server.
    NotSent(NotSent),
    /// The server refused the request with a code of the closed set; its
    /// transaction was rolled back. [`parse_reply`] gives this for every
    /// code and every operation, [`ErrorCode::AuthUnavailable`] and
    /// [`ErrorCode::ServerError`] included. Since a failed `COMMIT` is
    /// answered with one of these two, the client's call ([`LocalClient`])
    /// reports them as [`CallError::Unknown`], carrying the
    /// wire code, for `bootstrap`, `issue_challenge` and `restore`, and as
    /// a refusal only for `preview`: after a write, reconcile first (see
    /// the [module documentation](self), "Outcomes").
    Refused(ErrorCode),
    /// The request may or may not have been served: do not proceed;
    /// reconcile first. Never repeated by the client.
    Unknown(UnknownOutcome),
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSent(why) => write!(f, "the request was not sent: {why}"),
            Self::Refused(code) => write!(f, "the local transport refused the request: {code}"),
            Self::Unknown(why) => write!(
                f,
                "the outcome of the request is unknown ({why}): do not proceed; reconcile first"
            ),
        }
    }
}

impl std::error::Error for CallError {}

impl From<NotSent> for CallError {
    fn from(why: NotSent) -> Self {
        Self::NotSent(why)
    }
}

/// The values of a `bootstrap` request. The transport generates every ID
/// but the instance's and takes the time itself.
///
/// `Debug` prints `BootstrapRequest(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapRequest {
    /// The instance ID, a lowercase hyphenated UUIDv7 (the server checks
    /// it).
    pub instance_id: String,
    /// The DER `SubjectPublicKeyInfo` of the first operator's mTLS key,
    /// sent in lowercase hexadecimal.
    pub credential_spki: Vec<u8>,
    /// The first operator's trust anchor reference.
    pub trust_anchor_ref: String,
    /// The recovery public key, sent as 64 lowercase hexadecimal digits.
    pub recovery_public_key: RecoveryPublicKey,
}

impl fmt::Debug for BootstrapRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootstrapRequest(..)")
    }
}

/// The values of an `issue_challenge` request: the replacement operator a
/// restoration would enroll and the key it rotates to. The transport reads
/// the instance and the key epoch from its recovery state.
///
/// `Debug` prints `IssueChallengeRequest(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct IssueChallengeRequest {
    /// The DER `SubjectPublicKeyInfo` of the replacement's mTLS key, sent
    /// in lowercase hexadecimal.
    pub credential_spki: Vec<u8>,
    /// The replacement's trust anchor reference.
    pub trust_anchor_ref: String,
    /// The recovery public key a restoration rotates to.
    pub new_recovery_public_key: RecoveryPublicKey,
}

impl fmt::Debug for IssueChallengeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssueChallengeRequest(..)")
    }
}

/// The values of a `preview` or `restore` request, the signed response:
/// the challenge's operation ID and the 64-byte signature over its `M`.
/// Nothing else: no key, and nothing that signs.
///
/// `Debug` prints `ResponseRequest(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseRequest {
    /// The challenge's operation ID.
    pub operation_id: String,
    /// The signature, sent as 128 lowercase hexadecimal digits.
    pub signature: [u8; 64],
}

impl fmt::Debug for ResponseRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponseRequest(..)")
    }
}

/// A request, by operation.
///
/// `Debug` names the operation only, `Request::Restore(..)` say.
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    /// `bootstrap`.
    Bootstrap(BootstrapRequest),
    /// `issue_challenge`.
    IssueChallenge(IssueChallengeRequest),
    /// `preview`.
    Preview(ResponseRequest),
    /// `restore`.
    Restore(ResponseRequest),
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bootstrap(_) => "Request::Bootstrap(..)",
            Self::IssueChallenge(_) => "Request::IssueChallenge(..)",
            Self::Preview(_) => "Request::Preview(..)",
            Self::Restore(_) => "Request::Restore(..)",
        })
    }
}

impl Request {
    /// The request's operation.
    pub const fn op(&self) -> Op {
        match self {
            Self::Bootstrap(_) => Op::Bootstrap,
            Self::IssueChallenge(_) => Op::IssueChallenge,
            Self::Preview(_) => Op::Preview,
            Self::Restore(_) => Op::Restore,
        }
    }
}

/// The bytes of one request line, its newline included: what
/// [`Request::encode`] gives, to be written as is, followed by the end of
/// the client's write half.
///
/// `Debug` prints `RequestLine(..)`: the line holds the request's values.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestLine(Vec<u8>);

impl fmt::Debug for RequestLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestLine(..)")
    }
}

impl RequestLine {
    /// The bytes to write.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The success of a `bootstrap`: what it wrote.
///
/// `Debug` prints `Bootstrapped(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct Bootstrapped {
    pub instance_id: String,
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    pub recovery_key_epoch: i64,
}

impl fmt::Debug for Bootstrapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Bootstrapped(..)")
    }
}

/// The success of an `issue_challenge`: the challenge to check and sign.
/// The codec checks the reply's shape only; `challenge` is still to be
/// read with [`parse_challenge`](crate::recovery::parse_challenge) and
/// checked against the other members and the operator's expectations.
///
/// `Debug` prints `Issued(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct Issued {
    pub operation_id: String,
    /// Whole microseconds since the Unix epoch.
    pub expires_at: i64,
    pub expected_revision: i64,
    /// `M`, the bytes the recovery key signs (sent in lowercase
    /// hexadecimal).
    pub challenge: Vec<u8>,
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Issued(..)")
    }
}

/// The success of a `preview`: what the signed response would restore.
///
/// `Debug` prints `Previewed(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct Previewed {
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    pub new_recovery_key_epoch: i64,
    /// Whole microseconds since the Unix epoch.
    pub expires_at: i64,
}

impl fmt::Debug for Previewed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Previewed(..)")
    }
}

/// The success of a `restore`: the replacement it enrolled and what it
/// revoked.
///
/// `Debug` prints `Restored(..)`, none of the values.
#[derive(Clone, PartialEq, Eq)]
pub struct Restored {
    pub admin_id: String,
    pub credential_id: String,
    pub binding_id: String,
    pub revoked_credential_ids: Vec<String>,
    pub recovery_key_epoch: i64,
    pub recovery_state_revision: i64,
}

impl fmt::Debug for Restored {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Restored(..)")
    }
}

/// A success, by operation: [`parse_reply`] gives only the request's own.
///
/// `Debug` names the operation only, `Reply::Restored(..)` say.
#[derive(Clone, PartialEq, Eq)]
pub enum Reply {
    /// The success of a `bootstrap`.
    Bootstrapped(Bootstrapped),
    /// The success of an `issue_challenge`.
    Issued(Issued),
    /// The success of a `preview`.
    Previewed(Previewed),
    /// The success of a `restore`.
    Restored(Restored),
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bootstrapped(_) => "Reply::Bootstrapped(..)",
            Self::Issued(_) => "Reply::Issued(..)",
            Self::Previewed(_) => "Reply::Previewed(..)",
            Self::Restored(_) => "Reply::Restored(..)",
        })
    }
}

impl Reply {
    /// The operation this is the success of.
    pub const fn op(&self) -> Op {
        match self {
            Self::Bootstrapped(_) => Op::Bootstrap,
            Self::Issued(_) => Op::IssueChallenge,
            Self::Previewed(_) => Op::Preview,
            Self::Restored(_) => Op::Restore,
        }
    }
}
