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
//! - **No logging and no alert.** A refused peer, a `server_error`, and a
//!   successful bootstrap or restore are neither logged nor alerted on here
//!   (TM-15, design section 7.2); only a failed `accept` is logged. The
//!   audit chain records what the registry writes.
//!
//! # Use
//!
//! [`LocalTransport::new`] takes the pool, the clock, the ID generator and
//! the service UID (`None`: the process's effective UID);
//! [`LocalTransport::bind`] creates the socket and returns a
//! [`LocalListener`], whose [`LocalListener::serve`] accepts connections
//! until its shutdown future resolves, removes the socket and waits for
//! the open connections (at most [`SHUTDOWN_GRACE`]). Time and IDs come only from the injected [`Clock`]
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
//! 1. it refuses a socket path that does not fit a Unix socket address
//!    ([`BindError::PathTooLong`]: over [`MAX_SOCKET_PATH_BYTES`], 107
//!    bytes on Linux, 103 on the BSDs and macOS), which no client could
//!    connect to;
//! 2. it reads the process's effective UID from the kernel (the peer
//!    credentials of a socket pair it creates), the default service UID,
//!    and refuses the socket's directory ([`BindError::UnsafeDirectory`])
//!    unless it is a directory, not a symbolic link, not writable by group
//!    or others, or sticky (as `/tmp`), and owned by the service UID or
//!    root; when the service UID is not the effective UID (root binding for
//!    another UID), it must be owned by the effective UID itself, so the
//!    service UID cannot rename what the bind creates there while the bind
//!    gives it away. Then it walks the lookup of the directory from the
//!    root directory, following symbolic links as the kernel does, and
//!    refuses it ([`BindError::UnsafeAncestor`], naming the depth, not the
//!    path) unless every directory looked up on the way, the root
//!    directory included, is owned by root or the service UID (or the
//!    effective UID: the binding process itself) and not writable by group
//!    or others, or sticky: another UID could otherwise
//!    rename the socket's directory, or a directory above it, and redirect
//!    the paths used below. This is a precondition the operator's client
//!    (T13.10) checks too before it connects;
//! 3. it opens the lock file `<name>.lock` next to the socket, or, when
//!    there is none, creates it as a private inode first: a new file, mode
//!    0600, `l` in a fresh private directory (as in step 4), given to the
//!    service UID on its open descriptor (`fchown`) and only then
//!    hard-linked to `<name>.lock` (`link` never replaces an entry: a lock
//!    file another bind published meanwhile is opened instead), so the lock
//!    path never holds a file of the wrong owner, also when the process is
//!    killed in between. It is opened with `O_NOFOLLOW` (a symbolic link
//!    at the path fails, and is never followed) and `O_NONBLOCK` (a FIFO or
//!    a device never blocks the open), and the open file must be a regular
//!    file owned by the service UID with mode 0600, checked with `fstat`
//!    against the path (also after publishing it), so a symbolic link or
//!    another file is [`BindError::PathOccupied`]. The crate does not
//!    depend on `libc`, so the two flags are Linux's values for x86_64,
//!    aarch64 and riscv64; elsewhere the bind refuses to start
//!    ([`BindError::Io`] of kind [`std::io::ErrorKind::Unsupported`]). It
//!    is locked exclusively without waiting
//!    (`flock`, [`std::fs::File::try_lock`]): a lock another transport holds
//!    is [`BindError::InUse`]. The lock is held for the listener's life, so
//!    steps 4 to 8 and the removal at shutdown run in one transport at a
//!    time across processes: two transports never replace or remove each
//!    other's socket. The lock file is never removed (removing it while
//!    another process holds it open would let two processes lock two files
//!    of the same name);
//! 4. under the lock it clears the private directories a killed bind of the
//!    same name left (`.<name>.<pid>.<n>.bind`, owned by the process's UID,
//!    never a symbolic link): it unlinks only what a bind puts there, the
//!    staged socket `s` (a socket) and the staged lock `l` (a regular file),
//!    each owned by the service UID or the process's UID, and removes the
//!    directory only when it is then empty (`rmdir`, never recursively);
//!    anything else in it is left, and so is the directory. A directory the
//!    process may write but not list (a sticky directory with mode 01733,
//!    say) is not scanned: its leftovers stay. Then it creates a fresh
//!    private directory, mode 0700 (`mkdir` never reuses an entry), opens
//!    it, and checks the open directory: the one at the path, owned by the
//!    process's UID, no group or other bits, else
//!    [`BindError::NotVerified`];
//! 5. it refuses to start ([`BindError::PathOccupied`]) when the socket path
//!    holds anything but a socket owned by the service UID (a file, a
//!    directory, a symbolic link, another UID's socket), and
//!    ([`BindError::InUse`]) when a process accepts a connection on it (one
//!    that takes no lock file). A socket of the service UID that refuses the
//!    connection is stale and is removed, only while it is still the same
//!    inode;
//! 6. it computes the staged socket's address once, through the open
//!    directory (`/proc/self/fd/<fd>/s`), and uses it for every call on the
//!    staged socket: the bind, the change of owner, the mode, the check and
//!    the link of step 7 (the staged lock `l` of step 3 is reached the same
//!    way), so a rename of the private directory's path, and a directory
//!    with a symbolic link put in its place, redirect none of them; the
//!    address is also short whatever the path's length. Where
//!    `/proc/self/fd` is missing (not Linux, or no `/proc`) it uses the full
//!    staging path, and one that does not fit a socket address is
//!    [`BindError::StagingPathTooLong`]; that path is safe as well, because
//!    of step 2: only the effective UID (or root) can rename entries in the
//!    socket's directory and in the directories above it. It binds the
//!    socket there, gives it to the service UID when that is not the
//!    effective UID (`lchown`, which needs the privilege; a refusal is
//!    [`BindError::Io`]) and sets mode 0600;
//! 7. it hard-links the staged socket, through the same address, to the
//!    socket path: `link` never replaces an entry, so one that appeared
//!    since step 5 is left in place ([`BindError::PathOccupied`]); then it
//!    clears the private directory as in step 4 (its entries through the
//!    open directory);
//! 8. it checks the path again: the same inode, a socket, owned by the
//!    service UID, permission bits exactly 0600, else
//!    [`BindError::NotVerified`].
//!
//! On shutdown, and when the [`LocalListener`] is dropped, the path is
//! removed, still under the lock, only while it is the transport's socket;
//! then the lock is released. A transport killed mid-bind leaves its
//! private directory, which the next bind of the name clears (step 4); one
//! killed while creating the lock file leaves at most its private
//! directory and `l` in it, never a lock file, and the next bind creates
//! the lock file and clears the directory; one killed while serving leaves
//! a stale socket, which the next bind replaces (step 5).
//!
//! # Protocol
//!
//! One request per connection. Before reading, the peer's credentials are
//! checked (see "Security"); a refused peer gets `{"error":"forbidden"}` at
//! once and its request is not read.
//!
//! The request is one JSON object on one line, at most
//! [`MAX_REQUEST_BYTES`] (64 KiB) with its `\n`, **and then the end of the
//! stream: the client closes its write half** (`shutdown(SHUT_WR)`) after
//! the newline. The server dispatches the request only once it has read
//! that end of the stream, within the same limit, idle timeout and deadline,
//! so the answer does not depend on how the bytes are split across reads. A
//! client that never closes its write half is never answered (the idle
//! timeout or the deadline closes it, and nothing is dispatched). Any byte
//! after the newline, however and whenever it arrives, is `invalid_request`
//! and nothing is dispatched: no request is pipelined. This framing is a
//! lead pick (no contract text fixes it); the operator's client (T13.10)
//! must close its write half after the line.
//!
//! The server never holds more than the limit and answers a longer line,
//! bytes after the newline, an end of stream before it, invalid UTF-8 or
//! JSON, a root that is not a JSON object (an array, the positional form
//! serde would otherwise take, a string, a number, `true`, `false`,
//! `null`), an unknown `op`, and a missing, repeated, unknown or mistyped
//! member with `invalid_request`. The response is one JSON object on one
//! line, and the server closes the connection. Byte values are lowercase
//! hexadecimal; times are whole microseconds since the Unix epoch, as
//! `crate::admin_http`'s operation reads give them. Inferred throughout: no
//! contract text fixes the wire format.
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
//!   2048 bytes; no space and no control character, U+0000 to U+001F and
//!   U+007F to U+009F, the C1 controls included: exactly what
//!   `admin_credential_trust_anchor_ref_no_space_check` refuses under the
//!   `C` collation) before the issue too, whose plan only the restore
//!   stores in a credential, so no challenge is issued that no restore
//!   could use.
//! - For the same reason an issue whose replacement key a credential
//!   already has, live or revoked (`admin_credential.public_identity` is
//!   unique), is `conflict` before anything is written: the issue looks the
//!   identity up in its transaction (a lead pick: the local channel is the
//!   service UID's and root's only, so the lookup tells it nothing it could
//!   not read).
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
//! see "Errors"); a commit that does not end within the transaction
//! timeout, or that shutdown cuts, gets no response (see "Time limits").
//! Either outcome may be unknown, and the uncertain-commit rule of the
//! registry applies (reconcile, then retry).
//!
//! A response lost after its transaction committed (the client crashed or
//! timed out, the write failed or timed out, the transaction timeout or
//! shutdown cut the request during its commit) cannot be told apart, by the
//! client, from a request that was not served: it must reconcile before it
//! retries. A retried bootstrap is `conflict` once the first one committed
//! (read the recovery state and the operator); a retried restore of the
//! same challenge is `not_restorable` once it committed (the operator's
//! credential and the key epoch show it); a retried issue makes a second
//! challenge, and the first expires unused.
//!
//! # Serialization
//!
//! Requests are serialized per transport: one in-process mutex is taken
//! only after the request is read and parsed (a silent client never holds
//! it) and held until its transaction has ended, committed or rolled back,
//! or was cut by the transaction timeout or at shutdown (its connection
//! discarded), also past the connection's deadline (see "Time limits"), so
//! one process runs one bootstrap, issue, preview or restore at a time and
//! holds one
//! database connection for it. It is not what makes bootstrap and a
//! challenge one-shot: the database is (`bootstrap_instance`'s "Closure":
//! the policy row lock and the `recovery_state` unique keys;
//! `restore_operator`'s locks and its single consume, which the
//! `administrative_operation` guards back), so two transports, or a
//! transport and another writer, on one database stay safe. The mutex adds
//! a fixed order within the process (no `40001` or `40P01` between the
//! transport's own requests, and no issue that a concurrent restore of the
//! same process turns into a `conflict`).
//!
//! # Time limits
//!
//! At most [`Settings::max_connections`] connections (default 32) are
//! served at once: the transport takes a permit before it accepts a
//! connection and holds it until the connection ends, so past the limit a
//! new client waits in the socket's listen queue, unaccepted, until a
//! connection ends (it is not refused; its own timeout bounds its wait).
//!
//! Each read of the request must return within [`Settings::idle_timeout`].
//! [`Settings::deadline`], from the accept, bounds only the read of the
//! request, the wait for the mutex and the pool's acquire and `BEGIN`; past
//! it the connection is closed without a response, and nothing was written
//! (a `BEGIN` cut short discards its connection, as below). Once the
//! transaction has begun, the deadline no longer applies:
//! [`Settings::transaction_timeout`] (default 60 seconds) bounds everything
//! after `BEGIN`, setting the timeouts, the operation's statements and the
//! commit or rollback, with the mutex held. Within it, the server's
//! `lock_timeout` and `statement_timeout` ([`Settings::statement_timeout`])
//! end a slow statement or lock wait (`auth_unavailable`), but only while
//! the server answers: a stalled server or network, or a client library
//! waiting on a socket, is ended by the transaction timeout alone. Past
//! it the request's database connection is discarded, detached from the
//! pool and closed at once, so it is never reused or tested mid-transaction
//! and the server rolls back what it holds; the mutex is released, and the
//! connection is closed **without a response**. Nothing was written,
//! unless the commit had been sent: its outcome is then unknown, and the
//! uncertain-commit rule applies (see "Transactions": reconcile, then
//! retry). No response is the one answer that is true in every case.
//!
//! The response is then written within the idle timeout. If it cannot be
//! written in time, the connection is closed: the transaction's outcome is
//! then unknown to the client (see "Transactions", the lost response).
//!
//! So a connection lasts at most its deadline, the transaction timeout and
//! the idle timeout: by default 30, 60 and 10 seconds, 100 seconds in all.
//! That is the longest the operator's client (T13.10) must wait for a
//! response before it treats the request as one whose outcome is unknown
//! and reconciles; a response never comes later. On shutdown
//! [`LocalListener::serve`] waits for the open connections at most
//! [`SHUTDOWN_GRACE`] (10 seconds) and then cuts the rest, as the
//! transaction timeout does (no response, the connection discarded, a
//! commit's outcome unknown), so serving ends within the grace whatever
//! the database does.
//!
//! [`Settings`] bound every value: each timeout at most [`MAX_TIMEOUT`]
//! (`i32::MAX` milliseconds, PostgreSQL's limit), the statement timeout
//! under the deadline and at most the transaction timeout, the TTL 1
//! second to 15 minutes, and [`Settings::max_connections`] 1 to
//! [`MAX_CONNECTIONS`] ([`InvalidSettings`] names the value out of bounds);
//! no timer overflows.
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
//! open. A transport killed while binding or serving leaves files that the
//! next bind cleans up (see "The socket file").
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
//! | idle timeout, deadline before the transaction began, no end of stream after the line | (closed, no response, nothing written) |
//! | the transaction not ended within the transaction timeout, or cut at shutdown (the database connection is discarded; nothing written unless the commit was sent, whose outcome is then unknown) | (closed, no response) |
//! | an issue whose replacement key a credential (live or revoked) already has | `conflict` |
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

use tokio::{
    net::UnixListener,
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

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
    /// The longest wait for each read of the request, up to the end of the
    /// stream; over zero, at most [`MAX_TIMEOUT`]; default 10 seconds.
    pub idle_timeout: Duration,
    /// The connection's deadline, from the accept: it bounds the read of the
    /// request, the wait for the transport's mutex and the pool's acquire
    /// and `BEGIN`, and nothing after `BEGIN` (that is
    /// [`Settings::transaction_timeout`]'s); over zero, at most
    /// [`MAX_TIMEOUT`]; default 30 seconds.
    pub deadline: Duration,
    /// The transaction's `lock_timeout` and `statement_timeout`, in whole
    /// milliseconds: 1 millisecond to [`MAX_TIMEOUT`], under `deadline`;
    /// default 5 seconds. The server enforces them, while it answers.
    pub statement_timeout: Duration,
    /// The longest time from the end of `BEGIN` to the end of the commit or
    /// rollback, everything on the transaction's connection included: the
    /// backstop for a database or network that stopped answering, which
    /// `statement_timeout` cannot end. Past it the connection is discarded
    /// and closed without a response (a commit's outcome is then unknown;
    /// see the module docs, "Time limits"). At least `statement_timeout`,
    /// at most [`MAX_TIMEOUT`]; default 60 seconds.
    pub transaction_timeout: Duration,
    /// The TTL of an issued challenge, [`MIN_CHALLENGE_TTL`] to
    /// [`MAX_CHALLENGE_TTL`]; default [`DEFAULT_CHALLENGE_TTL`] (5 minutes).
    pub challenge_ttl: Duration,
    /// The most connections served at once, 1 to [`MAX_CONNECTIONS`];
    /// default 32. Past it, the transport accepts no connection until one
    /// ends: a new client waits in the socket's listen queue (see the module
    /// docs, "Time limits").
    pub max_connections: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(10),
            deadline: Duration::from_secs(30),
            statement_timeout: Duration::from_secs(5),
            transaction_timeout: Duration::from_secs(60),
            challenge_ttl: DEFAULT_CHALLENGE_TTL,
            max_connections: 32,
        }
    }
}

/// The longest `idle_timeout`, `deadline`, `statement_timeout` and
/// `transaction_timeout`:
/// `i32::MAX` milliseconds (about 24.8 days), PostgreSQL's limit for
/// `lock_timeout` and `statement_timeout`. It also keeps the connection's
/// deadline, `now` plus [`Settings::deadline`], far from the end of the
/// clock's range.
pub const MAX_TIMEOUT: Duration = Duration::from_millis(2_147_483_647);

/// The largest [`Settings::max_connections`].
pub const MAX_CONNECTIONS: usize = 1024;

/// The longest socket path, in bytes: one under the size of
/// `sockaddr_un.sun_path`, which also holds the path's terminating NUL (107
/// bytes on Linux, 103 on the BSDs and macOS). A longer one is
/// [`BindError::PathTooLong`].
pub const MAX_SOCKET_PATH_BYTES: usize = socket::SUN_PATH_BYTES - 1;

/// How long [`LocalListener::serve`] waits for the open connections once
/// its shutdown future resolves; past it the remaining connections are cut
/// (see the module docs, "Time limits").
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// A [`Settings`] value out of its bounds, by field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidSettings {
    /// `idle_timeout` is zero or over [`MAX_TIMEOUT`].
    IdleTimeout,
    /// `deadline` is zero or over [`MAX_TIMEOUT`].
    Deadline,
    /// `statement_timeout` is under 1 millisecond, over [`MAX_TIMEOUT`], or
    /// not under `deadline`.
    StatementTimeout,
    /// `transaction_timeout` is under `statement_timeout` or over
    /// [`MAX_TIMEOUT`].
    TransactionTimeout,
    /// `challenge_ttl` is outside 1 second to 15 minutes.
    ChallengeTtl,
    /// `max_connections` is outside 1 to [`MAX_CONNECTIONS`].
    MaxConnections,
}

impl fmt::Display for InvalidSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::IdleTimeout => {
                "the local transport's idle_timeout must be over zero and at most \
                 2147483647 milliseconds"
            }
            Self::Deadline => {
                "the local transport's deadline must be over zero and at most 2147483647 \
                 milliseconds"
            }
            Self::StatementTimeout => {
                "the local transport's statement_timeout must be 1 to 2147483647 milliseconds \
                 and under its deadline"
            }
            Self::TransactionTimeout => {
                "the local transport's transaction_timeout must be at least its \
                 statement_timeout and at most 2147483647 milliseconds"
            }
            Self::ChallengeTtl => {
                "the local transport's challenge_ttl must be 1 second to 15 minutes"
            }
            Self::MaxConnections => "the local transport's max_connections must be 1 to 1024",
        })
    }
}

impl std::error::Error for InvalidSettings {}

impl Settings {
    fn check(&self) -> Result<(), InvalidSettings> {
        let timeout = Duration::from_nanos(1)..=MAX_TIMEOUT;
        if !timeout.contains(&self.idle_timeout) {
            return Err(InvalidSettings::IdleTimeout);
        }
        if !timeout.contains(&self.deadline) {
            return Err(InvalidSettings::Deadline);
        }
        if !(Duration::from_millis(1)..=MAX_TIMEOUT).contains(&self.statement_timeout)
            || self.statement_timeout >= self.deadline
        {
            return Err(InvalidSettings::StatementTimeout);
        }
        if !(self.statement_timeout..=MAX_TIMEOUT).contains(&self.transaction_timeout) {
            return Err(InvalidSettings::TransactionTimeout);
        }
        if !(MIN_CHALLENGE_TTL..=MAX_CHALLENGE_TTL).contains(&self.challenge_ttl) {
            return Err(InvalidSettings::ChallengeTtl);
        }
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err(InvalidSettings::MaxConnections);
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
    /// [`BindError`]; nothing is then left at `path` (the lock file next
    /// to it may be).
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
    /// waits for the open connections, at most [`SHUTDOWN_GRACE`]: the
    /// connections still open then are cut (closed without a response,
    /// their database connections discarded, a commit in flight left with
    /// an unknown outcome; see the module docs, "Time limits"), so serving
    /// ends within the grace whatever the database does.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        let mut connections = JoinSet::new();
        // A permit per connection, taken before its accept and held until it
        // ends: past `max_connections`, new clients wait unaccepted.
        let permits = Arc::new(Semaphore::new(self.shared.settings.max_connections));
        tokio::pin!(shutdown);
        loop {
            let next = async {
                let permit = Arc::clone(&permits).acquire_owned().await;
                (permit, self.listener.accept().await)
            };
            tokio::select! {
                () = &mut shutdown => break,
                (permit, accepted) = next => match accepted {
                    Ok((stream, _)) => {
                        let shared = Arc::clone(&self.shared);
                        connections.spawn(async move {
                            let _permit = permit;
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
        let drained = async { while connections.join_next().await.is_some() {} };
        if tokio::time::timeout(SHUTDOWN_GRACE, drained).await.is_err() {
            // Aborted: each task's request future is dropped, which discards
            // its database connection and releases the mutex.
            connections.shutdown().await;
        }
    }
}

/// The pause after a failed accept.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_bounded() {
        assert_eq!(
            MAX_TIMEOUT,
            Duration::from_millis(u64::try_from(i32::MAX).unwrap())
        );
        assert_eq!(Settings::default().check(), Ok(()));
        assert_eq!(Settings::default().challenge_ttl, DEFAULT_CHALLENGE_TTL);
        assert_eq!(
            Settings::default().transaction_timeout,
            Duration::from_secs(60)
        );
        let with = |change: fn(&mut Settings)| {
            let mut settings = Settings::default();
            change(&mut settings);
            settings.check()
        };
        for (change, refusal) in [
            (
                (|s: &mut Settings| s.idle_timeout = Duration::ZERO) as fn(&mut Settings),
                InvalidSettings::IdleTimeout,
            ),
            (
                |s| s.idle_timeout = MAX_TIMEOUT + Duration::from_nanos(1),
                InvalidSettings::IdleTimeout,
            ),
            (|s| s.deadline = Duration::ZERO, InvalidSettings::Deadline),
            (
                |s| s.deadline = MAX_TIMEOUT + Duration::from_nanos(1),
                InvalidSettings::Deadline,
            ),
            (|s| s.deadline = Duration::MAX, InvalidSettings::Deadline),
            (
                |s| s.statement_timeout = Duration::from_micros(999),
                InvalidSettings::StatementTimeout,
            ),
            (
                |s| s.statement_timeout = MAX_TIMEOUT + Duration::from_nanos(1),
                InvalidSettings::StatementTimeout,
            ),
            (
                |s| s.challenge_ttl = Duration::from_millis(999),
                InvalidSettings::ChallengeTtl,
            ),
            (
                |s| s.challenge_ttl = MAX_CHALLENGE_TTL + Duration::from_nanos(1),
                InvalidSettings::ChallengeTtl,
            ),
            (
                |s| s.statement_timeout = s.deadline,
                InvalidSettings::StatementTimeout,
            ),
            (
                |s| s.transaction_timeout = s.statement_timeout - Duration::from_nanos(1),
                InvalidSettings::TransactionTimeout,
            ),
            (
                |s| s.transaction_timeout = MAX_TIMEOUT + Duration::from_nanos(1),
                InvalidSettings::TransactionTimeout,
            ),
            (
                |s| s.transaction_timeout = Duration::ZERO,
                InvalidSettings::TransactionTimeout,
            ),
            (|s| s.max_connections = 0, InvalidSettings::MaxConnections),
            (
                |s| s.max_connections = MAX_CONNECTIONS + 1,
                InvalidSettings::MaxConnections,
            ),
        ] {
            assert_eq!(with(change), Err(refusal));
        }
        for change in [
            (|s: &mut Settings| s.statement_timeout = Duration::from_millis(1))
                as fn(&mut Settings),
            |s| s.statement_timeout = s.deadline - Duration::from_nanos(1),
            |s| s.idle_timeout = Duration::from_nanos(1),
            |s| s.idle_timeout = MAX_TIMEOUT,
            |s| {
                s.deadline = Duration::from_millis(2);
                s.statement_timeout = Duration::from_millis(1);
            },
            |s| s.deadline = MAX_TIMEOUT,
            |s| s.max_connections = 1,
            |s| s.max_connections = MAX_CONNECTIONS,
            |s| s.transaction_timeout = s.statement_timeout,
            |s| s.transaction_timeout = MAX_TIMEOUT,
            |s| {
                s.statement_timeout = MAX_TIMEOUT - Duration::from_nanos(1);
                s.deadline = MAX_TIMEOUT;
                s.transaction_timeout = MAX_TIMEOUT;
            },
            |s| s.challenge_ttl = MIN_CHALLENGE_TTL,
            |s| s.challenge_ttl = MAX_CHALLENGE_TTL,
        ] {
            assert_eq!(with(change), Ok(()));
        }
        assert_eq!(
            InvalidSettings::StatementTimeout.to_string(),
            "the local transport's statement_timeout must be 1 to 2147483647 milliseconds and \
             under its deadline"
        );
        assert_eq!(
            InvalidSettings::TransactionTimeout.to_string(),
            "the local transport's transaction_timeout must be at least its statement_timeout \
             and at most 2147483647 milliseconds"
        );
    }

    /// The largest deadline still makes a connection deadline, and the
    /// largest statement timeout is PostgreSQL's limit in its own unit.
    #[test]
    fn the_largest_timeouts_are_usable() {
        assert!(
            tokio::time::Instant::now()
                .checked_add(MAX_TIMEOUT)
                .is_some()
        );
        assert_eq!(MAX_TIMEOUT.as_millis(), 2_147_483_647);
    }
}
