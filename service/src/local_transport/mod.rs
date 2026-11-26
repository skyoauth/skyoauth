//! The deployment-local bootstrap and recovery transport (T13.3 to T13.5;
//! design section 7.2; ADR-013 items 5 and 7; OQ-TM-9): a Unix-domain
//! socket owned by the service UID with mode 0600 that carries one request
//! per connection to the registry's [`bootstrap_instance`],
//! [`issue_recovery_challenge`], [`preview_recovery_response`] and
//! [`restore_operator`], each in a transaction of its own.
//!
//! It is the binary's transport of the recovery module's "Flow"
//! (`persistence::registry::recovery`) and of
//! `docs/proposals/recovery-verified-response.md`, section 7: it holds no
//! private key and verifies no signature. **The recovery signature is
//! verified inside [`restore_operator`]**, against the recovery state and
//! the challenge row it has locked; the transport only carries the
//! signature's bytes to it.
//!
//! [`bootstrap_instance`]: crate::persistence::registry::bootstrap_instance
//! [`issue_recovery_challenge`]: crate::persistence::registry::issue_recovery_challenge
//! [`preview_recovery_response`]: crate::persistence::registry::preview_recovery_response
//! [`restore_operator`]: crate::persistence::registry::restore_operator
//!
//! # Not done here
//!
//! - **Served nowhere.** Like `crate::admin_http`'s router, nothing starts
//!   it: `main` neither names this module nor has a socket path setting,
//!   and [`crate::app`] knows nothing of it. A source check
//!   (`service/tests/local_transport_private.rs`) keeps it so. The
//!   subcommand or startup path that binds it is a later slice.
//! - **No client.** The workstation side, which checks and signs `M` with
//!   the offline recovery key, is the operator crate (`skyoauth-operator`,
//!   slice S9, T13.10); it must not depend on this crate (tasks section 13,
//!   "Plan splits"), so the wire format below is its contract.
//! - **No HTTP and no TLS.** One JSON line each way over the socket; the
//!   peer is authenticated by its UID alone (see "Security").
//! - **The one key form per algorithm.** The transport derives the
//!   operator's `public_identity` from the DER key it is given with
//!   [`canonical_public_identity`](crate::identity::canonical_public_identity),
//!   never from a client-supplied identity string, but the rule that S3, S5
//!   and S7 accept one `SubjectPublicKeyInfo` form per algorithm
//!   ([`crate::identity`], "A hard requirement on the callers") is not
//!   enforced yet; it must land before the transport is served.
//! - **No provider transition.** M1b's recovery-signed switch and rollback
//!   (OQ-ADR012-4) are not operations here; nor is any WIF, audience or
//!   token operation (T13.5).
//!
//! # Use
//!
//! [`LocalTransport::new`] takes the pool, the clock, the ID generator and
//! the service UID (`None`: the process's effective UID);
//! [`LocalTransport::bind`] creates the socket and returns a
//! [`LocalListener`], whose [`LocalListener::serve`] accepts connections
//! until its shutdown future resolves, waits for the open connections and
//! removes the socket. Time and IDs come only from the injected [`Clock`]
//! and [`IdGenerator`] (D1: no other source of randomness; tests use
//! `ids::test_support::SequentialIds`).
//!
//! # The socket file
//!
//! The socket is owned by the service UID with mode 0600 (T13.4, OQ-TM-9),
//! and no other UID can reach it before it is. The umask is process-wide,
//! shared by every thread, and the standard library has no call to change
//! it (the crate forbids `unsafe`), so the transport does not change it:
//!
//! 1. it creates a fresh directory, mode 0700, next to the socket path
//!    (`.<name>.<pid>.<n>.bind`; `mkdir` never reuses an entry, so a name
//!    already taken, a symbolic link included, is skipped). Its owner is
//!    the process's effective UID, the default service UID;
//! 2. it refuses to start ([`BindError::PathOccupied`]) when the socket
//!    path holds anything but a socket owned by the service UID (a file, a
//!    directory, a symbolic link, another UID's socket), and
//!    ([`BindError::InUse`]) when a process accepts a connection on it. A
//!    socket of the service UID that refuses the connection is stale and is
//!    removed (only while it is still the same inode);
//! 3. it binds the socket inside the private directory, gives it to the
//!    service UID when that is not the effective UID (`chown`, which needs
//!    the privilege; a refusal is [`BindError::Io`]) and sets mode 0600;
//! 4. it hard-links the socket to the socket path: `link` never replaces an
//!    entry, so one that appeared since step 2 is left in place
//!    ([`BindError::PathOccupied`]); then it removes the private directory;
//! 5. it checks the path again: the same inode, a socket, owned by the
//!    service UID, permission bits exactly 0600, else
//!    [`BindError::NotVerified`].
//!
//! The socket's directory must be writable only by the service UID (or
//! root): whoever may write it may replace the socket, which no check here
//! can prevent. On shutdown, and when the [`LocalListener`] is dropped, the
//! path is removed only while it is still the transport's socket.
//!
//! # Protocol
//!
//! One request per connection. Before reading, the peer's credentials are
//! checked (see "Security"); a refused peer gets `{"error":"forbidden"}`
//! and its request is not read. The request is one JSON object on one
//! line, at most [`MAX_REQUEST_BYTES`] (64 KiB) with its `\n`, which is the
//! last byte the client sends; the server never holds more than that limit
//! and answers a longer line, bytes after the newline, an end of stream
//! before it, invalid UTF-8 or JSON, an unknown `op`, and a missing,
//! repeated, unknown or mistyped member with `invalid_request`. The
//! response is one JSON object on one line, and the server closes the
//! connection. Byte values are lowercase hexadecimal; times are whole
//! microseconds since the Unix epoch, as `crate::admin_http`'s operation
//! reads give them. Inferred throughout: no contract text fixes the wire
//! format.
//!
//! # Operations
//!
//! | `op` | Members | Registry call | Success members |
//! | ---- | ------- | ------------- | --------------- |
//! | `bootstrap` | `instance_id`, `credential_spki`, `trust_anchor_ref`, `recovery_public_key` | [`bootstrap_instance`] | `instance_id`, `admin_id`, `credential_id`, `binding_id`, `recovery_key_epoch` |
//! | `issue_challenge` | `credential_spki`, `trust_anchor_ref`, `new_recovery_public_key` | [`get_recovery_state`](crate::persistence::registry::get_recovery_state), then [`issue_recovery_challenge`] | `operation_id`, `expires_at`, `expected_revision`, `challenge` (`M`) |
//! | `preview` | `operation_id`, `signature` | [`preview_recovery_response`] | `admin_id`, `credential_id`, `binding_id`, `new_recovery_key_epoch`, `expires_at` |
//! | `restore` | `operation_id`, `signature` | [`restore_operator`] | `admin_id`, `credential_id`, `binding_id`, `revoked_credential_ids`, `recovery_key_epoch`, `recovery_state_revision` |
//!
//! - The transport generates every ID with the [`IdGenerator`] (the
//!   operator, credential, binding and event IDs of a bootstrap; the
//!   operation, event and replacement IDs of an issue; the two event IDs of
//!   a restore) and takes `now` from the [`Clock`] immediately before the
//!   registry call. No request names an ID the transport creates.
//! - `instance_id` is the one ID a request supplies: it is a UUIDv7
//!   (IR-057), not an [`IdKind`](crate::ids::IdKind), and the crate has no
//!   UUIDv7 generator (the contracts are silent on who generates it; the
//!   deployment operator's tooling does, and bootstrap checks it, or its
//!   equality with an adopted policy row).
//! - `credential_spki` is the DER `SubjectPublicKeyInfo` of the operator's
//!   mTLS key; the transport derives `public_identity` from it (see "Not
//!   done here").
//! - `issue_challenge` builds the closed eight-member plan: the instance
//!   and the key epoch from the recovery state read in the same
//!   transaction (the issue reads it again `FOR SHARE` and refuses a plan
//!   that no longer matches), the generated replacement IDs, the derived
//!   identity, the trust anchor and the new key. The TTL is the
//!   transport's setting ([`Settings::challenge_ttl`], default 5 minutes,
//!   1 second to 15 minutes, OQ-LT-17), not the request's.
//! - `M` is returned only by `issue_challenge`: the workstation checks
//!   it (the instance, the replacement, the expiry) and signs it. A
//!   `restore` sends back the operation ID and the signature; the
//!   replacement it enrolls is the challenge's plan, never the request's.
//! - `trust_anchor_ref` is checked against the `0005` constraints (1 to
//!   2048 bytes, no ASCII whitespace or control character) before the
//!   issue too, whose plan only the restore stores in a credential, so no
//!   challenge is issued that no restore could use.
//!
//! # Transactions
//!
//! Each request is exactly one transaction, begun with `BEGIN ISOLATION
//! LEVEL READ COMMITTED` (the one level [`restore_operator`] runs at,
//! whatever the database's default) and with `lock_timeout` and
//! `statement_timeout` set for it alone ([`Settings::statement_timeout`]),
//! as the recovery module asks of a caller (its "Time"). The registry
//! functions run in a savepoint of their own and never commit; the
//! transport commits only on `Ok` and rolls back on every refusal, so a
//! refusal, a store failure or a failed audit append writes nothing. A
//! `preview` writes nothing and is always rolled back. A commit that fails
//! is mapped as a store failure (`auth_unavailable` for a lost connection,
//! see "Errors"); its outcome may be unknown, and the uncertain-commit rule
//! of the registry applies (reconcile, then retry).
//!
//! # Serialization
//!
//! Requests are serialized per transport: one in-process mutex is held from
//! after the request is parsed to after its transaction ends, so one
//! process runs one bootstrap, issue, preview or restore at a time and
//! holds one database connection for it. It is not what makes bootstrap
//! and a challenge one-shot: the database is (`bootstrap_instance`'s
//! "Closure": the policy row lock and the `recovery_state` unique keys;
//! `restore_operator`'s locks and its single consume, which the
//! `administrative_operation` guards back), so two transports, or a
//! transport and another writer, on one database stay safe. The mutex adds
//! a fixed order within the process (no `40001` or `40P01` between the
//! transport's own requests, and no issue that a concurrent restore of the
//! same process turns into a `conflict`).
//!
//! # Time limits
//!
//! Each read of the request must return within [`Settings::idle_timeout`];
//! the whole connection, from accept to the last byte of the response,
//! within [`Settings::deadline`]. Past either the connection is closed
//! without a response. Past the deadline the request is cancelled where it
//! is: a transaction not yet committed is rolled back (the connection
//! drops it, or the server aborts it); a cancellation that falls during
//! `COMMIT` leaves its outcome unknown to the client, as a crash does (see
//! "Crashes"). The database side is bounded by the transaction's
//! `lock_timeout` and `statement_timeout`, which end in `auth_unavailable`.
//!
//! # Crashes
//!
//! The transport keeps no state that matters across a crash or a restart:
//! the mutex, and nothing else. A challenge is a stored, expiring,
//! single-use `administrative_operation` row, inserted with its audit event
//! in one transaction. A crash before that transaction commits leaves
//! nothing (the database rolls it back). After it commits, the row stays
//! unconsumed until its `expires_at` (the TTL: 5 minutes by default, 15 at
//! most, LT-107, OQ-LT-17), and a `restore` after a restart can still
//! consume it until then, from a new [`LocalTransport`] on the same
//! database: the restore reads the row, not the transport. If the
//! `issue_challenge` response was lost, the client never received `M` and
//! the operation ID; no operation reads them back, so the row simply
//! expires unconsumed, and the client issues a new challenge (several open
//! challenges may exist; a restore of any one advances the key epoch and
//! the recovery state revision, which retires the others: their restore is
//! `not_restorable`). An expired row is never removed; it stays as the
//! record of the issue. A restore is one transaction: after a crash either
//! everything of it committed (the challenge consumed, the replacement
//! enrolled, every credential revoked, the key rotated, both events) or
//! nothing did (the challenge is still unconsumed and can be used until it
//! expires). Bootstrap likewise either closed for good or left bootstrap
//! open.
//!
//! # Errors
//!
//! A refusal is `{"error":"<code>"}` and nothing else: no description, no
//! value of the request or of a row, no constraint name, no SQL text, no
//! key byte. A success carries only the members of "Operations"; `M` holds
//! the plan, which the workstation must see. The codes ([`ErrorCode`]) are
//! a closed set; `forbidden`, `invalid_request`, `conflict`,
//! `auth_unavailable` and `server_error` are `crate::admin_http`'s codes
//! with their meaning, and `not_restorable` is this transport's (proposed
//! here, as `not_approvable` is for an operation):
//!
//! | Cause | Code |
//! | ----- | ---- |
//! | the peer's UID is neither the service UID nor 0, or has no credentials | `forbidden` |
//! | a malformed or oversized request (see "Protocol") | `invalid_request` |
//! | a value the transport's checks refuse: not lowercase hexadecimal, an `instance_id` that is not a lowercase UUIDv7, a key that is not a canonical Ed25519 point of large order, a DER that is not one `SubjectPublicKeyInfo`, a bad `trust_anchor_ref`, an operation ID with a NUL | `invalid_request` |
//! | idle or deadline timeout | (closed, no response) |
//! | [`BootstrapError`](crate::persistence::registry::BootstrapError) `AlreadyClosed`, `InstanceIdMismatch` | `conflict` |
//! | [`ChallengeError`](crate::persistence::registry::ChallengeError) `NotIssuable`; no closed recovery state at the issue | `conflict` |
//! | [`RestoreError`](crate::persistence::registry::RestoreError) `NotRestorable(_)` (every reason, a bad signature included), `RecoveryKeyUnchanged` | `not_restorable` |
//! | `RestoreError::UnsupportedIsolation` (unreachable: every transaction is `READ COMMITTED`) | `server_error` |
//! | [`IdError`](crate::ids::IdError) (D1: nothing written) | `server_error` |
//! | [`RegistryError`](crate::persistence::registry::RegistryError) `NotFound`, `StaleRevision`, `AlreadyExists` (a registered key, say), `Guard`, `Invariant` `ForeignKey`, `AssignmentActive`, `EgressEntryEnabled` | `conflict` |
//! | `Invariant` `Check`, `NotNull`; `ReservedActorId`, `RequiredPredicate` | `invalid_request` |
//! | `Invariant` `SameTenantOperation`, `DistinctApprover`; `UnreadableTimestamp` | `server_error` |
//! | `Retry` (`40001`, `40P01`); `Other`: `Io`, `Tls`, `PoolTimedOut`, `PoolClosed`, SQLSTATE class `08`, `53`, `57P0x`, `55P03`, `57014`; a failed `BEGIN` or `COMMIT` of those | `auth_unavailable` |
//! | `Other`: anything else, an encode error included (the transport checks every value it submits first, so the registry's own checks refuse only the server's: its clock, the audit chain's sequence) | `server_error` |
//!
//! Every reason of `NotRestorable` is one code: the local client learns
//! that the response does not restore, not which check refused it.
//!
//! # Security
//!
//! The peer check is the control: on each accepted connection the server
//! reads the peer's credentials from the kernel (`SO_PEERCRED` on Linux,
//! through [`tokio::net::UnixStream::peer_cred`]) and serves only the
//! service UID and root (UID 0); any other UID, or a connection whose
//! credentials cannot be read, is `forbidden` before a byte is read. The
//! socket file's owner and mode 0600 are defence in depth: they stop other
//! UIDs at `connect`, and the peer check still holds if the mode is
//! loosened. Root is accepted because root can reach the service UID's
//! files and processes anyway.
//!
//! Who reaches the socket reaches bootstrap and recovery: `pods/exec` on
//! the SkyOAuth namespace equals channel access and stays limited to
//! already-trusted infrastructure administrators (OQ-TM-9, decided). The
//! channel gives no authority of its own beyond what the registry allows:
//! bootstrap once (the database closes it for good), and a restoration
//! only with a signature by the current offline recovery key over a
//! challenge the registry issued (single use, expiring, bound to the
//! instance, the key epoch and the recovery state revision).
//!
//! The module is compiled on Unix only (`cfg(unix)` in `lib.rs`): the CI
//! builds and tests the service on Linux (x86_64 and aarch64), and the
//! service is a Linux server; the portable operator crate does not depend
//! on it.

mod connection;
mod error;
mod ops;
mod socket;
mod wire;

use std::{fmt, path::Path, sync::Arc, time::Duration};

use tokio::{net::UnixListener, sync::Mutex, task::JoinSet};

pub use connection::MAX_REQUEST_BYTES;
pub use error::ErrorCode;
pub use socket::BindError;

use crate::ids::IdGenerator;
use crate::operation::Clock;
use crate::persistence::{
    PgPool,
    registry::{DEFAULT_CHALLENGE_TTL, MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL},
};

/// The transport's time limits and challenge TTL (see the module docs,
/// "Time limits").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The longest wait for each read of the request; default 10 seconds.
    pub idle_timeout: Duration,
    /// The longest a connection lasts, from accept to the response's last
    /// byte; default 30 seconds.
    pub deadline: Duration,
    /// The transaction's `lock_timeout` and `statement_timeout`, at least 1
    /// millisecond; default 5 seconds.
    pub statement_timeout: Duration,
    /// The TTL of an issued challenge, [`MIN_CHALLENGE_TTL`] to
    /// [`MAX_CHALLENGE_TTL`]; default [`DEFAULT_CHALLENGE_TTL`] (5 minutes).
    pub challenge_ttl: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(10),
            deadline: Duration::from_secs(30),
            statement_timeout: Duration::from_secs(5),
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
        }
    }
}

/// [`Settings`] out of their bounds: a zero timeout or deadline, a
/// statement timeout under 1 millisecond, or a TTL outside 1 second to 15
/// minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSettings;

impl fmt::Display for InvalidSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the local transport settings are out of bounds")
    }
}

impl std::error::Error for InvalidSettings {}

impl Settings {
    fn check(&self) -> Result<(), InvalidSettings> {
        let ttl = MIN_CHALLENGE_TTL..=MAX_CHALLENGE_TTL;
        if self.idle_timeout.is_zero()
            || self.deadline.is_zero()
            || self.statement_timeout < Duration::from_millis(1)
            || !ttl.contains(&self.challenge_ttl)
        {
            return Err(InvalidSettings);
        }
        Ok(())
    }
}

/// What every connection of one transport shares.
struct Shared {
    pool: PgPool,
    clock: Arc<dyn Clock + Send>,
    ids: Arc<dyn IdGenerator>,
    settings: Settings,
    service_uid: u32,
    /// Held for each request (see the module docs, "Serialization").
    serial: Mutex<()>,
}

/// The transport before it is bound (see the module docs, "Use").
pub struct LocalTransport {
    pool: PgPool,
    clock: Arc<dyn Clock + Send>,
    ids: Arc<dyn IdGenerator>,
    service_uid: Option<u32>,
    settings: Settings,
}

impl fmt::Debug for LocalTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalTransport")
            .field("service_uid", &self.service_uid)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl LocalTransport {
    /// A transport with the default [`Settings`]. `service_uid` is the UID
    /// that owns the socket and that the peer check accepts besides root;
    /// `None` is the process's effective UID.
    pub fn new(
        pool: PgPool,
        clock: Arc<dyn Clock + Send>,
        ids: Arc<dyn IdGenerator>,
        service_uid: Option<u32>,
    ) -> Self {
        Self {
            pool,
            clock,
            ids,
            service_uid,
            settings: Settings::default(),
        }
    }

    /// This transport with `settings`.
    ///
    /// # Errors
    ///
    /// [`InvalidSettings`] when one is out of its bounds.
    pub fn with_settings(mut self, settings: Settings) -> Result<Self, InvalidSettings> {
        settings.check()?;
        self.settings = settings;
        Ok(self)
    }

    /// Creates the socket at `path` (see the module docs, "The socket
    /// file") and returns the listener, which serves nothing until
    /// [`LocalListener::serve`].
    ///
    /// # Errors
    ///
    /// [`BindError`]; nothing is then left at `path`.
    pub async fn bind(self, path: &Path) -> Result<LocalListener, BindError> {
        let (listener, socket, service_uid) = socket::bind(path, self.service_uid).await?;
        Ok(LocalListener {
            listener,
            socket,
            shared: Arc::new(Shared {
                pool: self.pool,
                clock: self.clock,
                ids: self.ids,
                settings: self.settings,
                service_uid,
                serial: Mutex::new(()),
            }),
        })
    }
}

/// The bound transport. Dropping it closes the socket and removes the
/// socket path while it is still this socket.
pub struct LocalListener {
    // Declared before `socket`: the listener is closed before the path is
    // removed.
    listener: UnixListener,
    socket: socket::SocketFile,
    shared: Arc<Shared>,
}

impl fmt::Debug for LocalListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalListener")
            .field("path", &self.socket.path())
            .field("service_uid", &self.shared.service_uid)
            .finish_non_exhaustive()
    }
}

impl LocalListener {
    /// The socket path.
    pub fn path(&self) -> &Path {
        self.socket.path()
    }

    /// The UID that owns the socket and that the peer check accepts
    /// besides root.
    pub fn service_uid(&self) -> u32 {
        self.shared.service_uid
    }

    /// Accepts connections, each served on a task of its own, until
    /// `shutdown` resolves; then stops accepting, removes the socket and
    /// waits for the open connections, each bounded by the deadline.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let shared = Arc::clone(&self.shared);
                        connections.spawn(async move {
                            connection::serve(stream, &shared).await;
                        });
                    }
                    Err(err) => {
                        // Out of file descriptors, say: back off and go on.
                        tracing::warn!(kind = ?err.kind(), "local transport accept failed");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                },
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
        drop(self.listener);
        drop(self.socket);
        while connections.join_next().await.is_some() {}
    }
}

/// The pause after a failed accept.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_bounded() {
        assert_eq!(Settings::default().check(), Ok(()));
        assert_eq!(Settings::default().challenge_ttl, DEFAULT_CHALLENGE_TTL);
        let with = |change: fn(&mut Settings)| {
            let mut settings = Settings::default();
            change(&mut settings);
            settings.check()
        };
        for change in [
            (|s: &mut Settings| s.idle_timeout = Duration::ZERO) as fn(&mut Settings),
            |s| s.deadline = Duration::ZERO,
            |s| s.statement_timeout = Duration::from_micros(999),
            |s| s.challenge_ttl = Duration::from_millis(999),
            |s| s.challenge_ttl = MAX_CHALLENGE_TTL + Duration::from_nanos(1),
        ] {
            assert_eq!(with(change), Err(InvalidSettings));
        }
        for change in [
            (|s: &mut Settings| s.statement_timeout = Duration::from_millis(1))
                as fn(&mut Settings),
            |s| s.challenge_ttl = MIN_CHALLENGE_TTL,
            |s| s.challenge_ttl = MAX_CHALLENGE_TTL,
        ] {
            assert_eq!(with(change), Ok(()));
        }
        assert_eq!(
            InvalidSettings.to_string(),
            "the local transport settings are out of bounds"
        );
    }
}
