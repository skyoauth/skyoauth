# Proposal: the online operator commands over the deployment-local socket (D2)

Status: Ruled by the lead 2026-11-27 (all eight recommendations accepted);
slice 1: status and preview implemented. This document changes no contract under `docs/contracts/` and no code. It
extends [the offline command line](operator-cli-artifacts.md) (D1) with the
commands that talk to the service's deployment-local transport. "D2" here
names this slice of the operator command line, not the entry "D2 names" of
[tasks §13](../skyoauth-tasks.md#13-m1a-lead-decisions-2026-11-24).
It builds on C4 (`LocalClient::status`, `RestoreVerdict`,
`BootstrapVerdict`, `StatusRequest::reconciling_*`,
`LocalClient::revoked_credential_ids` and the "Reconciling" section of
`operator/src/local/mod.rs`), merged to `main` with pull request #211.

## Who decided what

- **User rulings** (2026-11-27, relayed by the lead; tasks §13, "Other
  rulings of the user, 2026-11-27"): the challenge artifact is the
  `issue_challenge` reply, verbatim, and the response artifact is
  `{operation_id, signature}` with `signature` hex-encoded ("Recovery
  artifacts"); a read-only operation is added to the local socket
  ("Read-only socket operation", now `status`); how a client reaches a
  socket inside a pod stays open ("Pod access to the local socket");
  `skyoauth-operator` stays `publish = false`.
- **Lead picks and rulings, from the repository:** the D1 exit codes 0 to
  4, flags only, help only where a command or a flag is expected, exit 4
  for `verify-challenge` only, and `--out` required with no response on
  standard output ([D1](operator-cli-artifacts.md#who-decided-what)); a
  store failure after a write is an unknown outcome, after `preview` or
  `status` a refusal (`operator/src/local/exchange.rs`, `refusal`); an
  `issue_challenge` of unknown outcome is not reconciled but issued again,
  and `status` is `Retry::Safe` (Q5); after a retry, a `conflict` or a
  `not_restorable` sends the operator back to the **original** operation
  ID (c); the bootstrap reconcile by the instance, the recovery key, the
  mTLS key and the trust anchor's SHA-256 (F4 and (b)): all in
  [the status proposal](local-read-operation.md#rulings).
- **The lead's D2 scope statement** (relayed with this task, not recorded
  in the repository): the five subcommands on `LocalClient`, the D1
  artifacts reused, unknown outcomes as exit codes, and that a
  dev-dependency of `skyoauth-scenarios` on `skyoauth-operator` is approved
  for the C4 follow-up; it landed with #214 ([demo
  walkthroughs](demo-walkthroughs.md), "Extra dependencies").
- **Everything else is proposed here**, marked "(proposed)" where it is a
  pick; the eight that most need a ruling are under
  [Rulings](#rulings).

## Where the commands run

The transport answers only a peer whose UID is the service UID or root
(the service's `local_transport` docs, "Errors": `forbidden`), over a
socket owned by the service UID with mode 0600 (T13.4, OQ-TM-9; ADR-013
item 8). So the online commands run on the service's host, as the service
UID or root, while `sign` runs on the offline workstation that holds the
recovery seed. The artifacts carry the recovery between the two:

1. host: `issue-challenge --out challenge` writes the reply line, verbatim;
2. workstation: `verify-challenge`, then `sign --out response` (D1);
3. host: `preview --response response` (optional), then `restore
   --response response`;
4. host, after exit 5: `status --reconcile restore --response response`.

No online command reads a seed file or takes a private key (proposed): the
recovery private key never reaches the host. How the binary reaches a
socket inside a pod is the user's open question; D2 assumes a shell where
the socket path is visible (`pods/exec`, OQ-TM-9). Nothing binds the socket
yet: the service's `local_transport` is "served nowhere" (its module docs,
"Not done here"), so D2 is testable against the harness only until the
binding slice lands.

## Commands

```text
skyoauth-operator bootstrap SOCKET --instance-id ID --credential-spki FILE
    --trust-anchor REF --recovery-key HEX
skyoauth-operator issue-challenge SOCKET --credential-spki FILE
    --trust-anchor REF --new-recovery-key HEX --out FILE
skyoauth-operator preview SOCKET --response FILE
skyoauth-operator restore SOCKET --response FILE
skyoauth-operator status SOCKET [--challenge FILE | --response FILE]
    [--credential-spki FILE]
skyoauth-operator status SOCKET --reconcile restore
    (--challenge FILE | --response FILE)
skyoauth-operator status SOCKET --reconcile bootstrap --instance-id ID
    --credential-spki FILE --trust-anchor REF --recovery-key HEX

SOCKET is: --socket PATH --service-uid UID
    [--trust-ancestors service-or-root|root-only]
    [--total-wait SECONDS] [--idle-wait SECONDS]
```

D1's rules hold unchanged: flags only, each `--flag VALUE` once, no
configuration file, no environment, help recognised only where a command
or a flag is expected. A key (`--recovery-key`, `--new-recovery-key`) is
read as D1 reads one (`RecoveryPublicKey::from_hex`, a usage error when
refused). `--credential-spki FILE` is a file of the DER
`SubjectPublicKeyInfo` itself, 1 to 4096 bytes (`MAX_SPKI_DER_BYTES`),
read as D1 reads an artifact (a regular file, size checked first); no PEM
(proposed). The wire's members fix the inputs: `preview` and `restore`
both take `operation_id` and `signature`, so both take the response
artifact (fixture `ops`).

### The socket flags

All proposed; the library takes `LocalClient::new(path,
SocketExpectations, Timeouts)` and checks the path before every connect
(C3, `operator/src/local/path.rs`, `check_socket`):

- `--socket PATH`, **required, no default**: the service has no socket
  path setting yet (above), so there is no path to default to. Checked
  with the client's rules: at most 107 bytes on Linux and 103 on macOS
  (`MAX_SOCKET_PATH_BYTES`), a relative path joined to the working
  directory once, every directory on the way owned by a trusted UID and
  not writable by others, the socket's own directory private (not even
  sticky, `SharedDirectory`), the socket owned by `--service-uid` with
  mode exactly 0600, and compared again after the connect (`Changed`).
- `--service-uid UID`, **required**: `SocketExpectations::owner_uid`. The
  standard library cannot read the process's UID, and a default of the
  effective UID is wrong when the command runs as root (the usual
  `pods/exec` case).
- `--trust-ancestors`, default `service-or-root` (`AncestorTrust::
  ServiceOrRoot`, the library's own inferred pick), or `root-only` for a
  socket that root binds for the service UID.
- `--total-wait SECONDS` and `--idle-wait SECONDS`, whole seconds over
  zero, defaults 100 and 10 (`DEFAULT_TOTAL_WAIT`, `DEFAULT_IDLE_WAIT`;
  the fixture's `default_limits`: deadline 30, transaction timeout 60,
  idle 10). They fit a server with the default settings only; a server
  tuned otherwise needs both set to match, since the transport cannot
  report its settings. Both limits apply to each request, not to the
  command: `preview` sends one request; `status` sends one, and for a
  restored operation also the walk of its revoked IDs, `1 + ceil(N/1000)`
  requests in all (at least 2) for `N` revoked IDs, with the pages walked
  once more if `N` changes during the walk (the documented tie). A command
  can therefore block for a multiple of `--total-wait`, 100 seconds by
  default.

### `bootstrap`

Sends `BootstrapRequest` with the four values given. `--instance-id` is
given, not generated (proposed: no randomness or clock in the binary, and
a rerun with the same flags is the same request, which the reconcile
needs). On success it prints `instance_id`, `admin_id`, `credential_id`,
`binding_id` and `recovery_key_epoch`. Keep this output: the instance ID
and the epoch are what `verify-challenge --instance-id --epoch` must later
be given from the operator's own records.

### `issue-challenge`

Sends `IssueChallengeRequest` (the replacement's DER, its trust anchor,
the new recovery key). `--out` is required, as for `sign`, and created new
(`create_new`, mode 0600 on Unix) **before** the request is sent, so an
existing `--out` is exit 3 with nothing sent (proposed). On success the
reply line is written to `--out` exactly as the transport sent it, its
newline included (the user's ruling), and synchronized; then standard
output shows `operation_id`, `expires_at`, `expected_revision`,
`replacement_identity` (`public_identity_of_spki` of `--credential-spki`,
to pass to `verify-challenge --replacement-identity`; the service stays
the authority for it) and `result: ok; …; check it on the workstation with
verify-challenge`. On any other outcome nothing is written to `--out`,
which is left empty, and the message says to remove it (D1's precedent:
the binary removes no file by path).

`LocalClient::issue_challenge` returns the parsed `Challenge`, not the
reply's bytes, so the verbatim artifact needs a small library addition
that returns the reply line with the challenge (Q6).

### `preview` and `restore`

Both read `--response` as D1 reads it (at most 64 KiB, the one-line form)
and send `ResponseRequest`. A signature that is not 64 bytes is refused
before any connection (exit 1, `refused (Length)`, as `verify_response`
names it; proposed). `preview` prints `admin_id`, `credential_id`,
`binding_id`, `new_recovery_key_epoch` and `expires_at`, and writes
nothing on the service. `restore` prints `admin_id`, `credential_id`,
`binding_id`, `recovery_key_epoch`, `recovery_state_revision`,
`revoked_credential_count`, the reply's revoked IDs one per line, and
`revoked_credential_ids_complete: yes|no` (complete exactly when the list's
length equals the count). When it is `no`, it names the command that lists
the rest (`status --response FILE`); `restore` itself sends one request
only (proposed).

### `status`

One read (`Retry::Safe`), plus the page walk below. Without a selector it
prints the recovery state (`server_time`, `instance_id`,
`recovery_key_epoch`, `recovery_state_revision`, `recovery_public_key`).
`--challenge` or `--response` (one of them) adds the operation's state and
its members, the operation ID read from the artifact so nothing is retyped;
for a `restored` operation every revoked ID is listed, walked with
`LocalClient::revoked_credential_ids(operation_id, None)`. `--credential-spki`
adds the key's `enrolled_*` members. Every member of the reply is printed,
`null` where the service wrote `null`.

`--reconcile restore` and `--reconcile bootstrap` build the request with
`StatusRequest::reconciling_restore` or `reconciling_bootstrap` and add two
lines: `verdict:` and `next:` (below).

## Exit codes

D1's table, its meanings for 0 to 4 kept exactly, extended (proposed: Q2).

| Code | Meaning |
| ---- | ------- |
| 0 | As D1. Online: the request succeeded: the bootstrap or the restore committed, the challenge was issued and `--out` written, the preview or the status was answered (whatever the reconcile verdict, Q3). |
| 1 | As D1: refused. Online also: the service refused with a code of the closed set (`refused (<code>): …`): `forbidden`, `invalid_request`, `conflict`, `not_restorable`; after `preview` and `status`, `auth_unavailable` and `server_error` too. Its transaction was rolled back. And an input refused before anything was sent: a response artifact that is malformed or whose signature is not 64 bytes, a request over 64 KiB (`NotSent::TooLarge`). |
| 2 | As D1: usage. Online also: a missing socket flag, a `--trust-ancestors` or wait out of its set, and an online command on a platform without Unix sockets (Q7). |
| 3 | As D1: I/O. Online also: `--credential-spki`, `--challenge` or `--response` missing, unreadable or over its limit; `--out` that exists or cannot be created, written or synchronized. After a success the message says what succeeded (below). |
| 4 | Unchanged: `verify-challenge` only; no online command exits 4. |
| 5 | New. The outcome of a write is unknown (`CallError::Unknown` after `bootstrap`, `issue-challenge` or `restore`, `UncertainCommit` included): the service may have committed it. Do not repeat it: reconcile first (`Retry::ReconcileFirst`). |
| 6 | New. Nothing was changed by this command: the request was not sent (`CallError::NotSent`: the socket path refused, no connection, the total wait ran out before a byte was written), for every command; or `preview` or `status` got no reply that can be believed (`CallError::Unknown`, `PageMismatch` included), which change no row. The same command may be run again. |

So 5 is `Retry::ReconcileFirst` and 6 is "nothing happened or nothing
could have been written", which makes a script's rule simple: 6 may be
retried, 5 never without the reconcile.

## Unknown outcomes and reconciling

The library's rule stands: **the client never retries on its own**
(`operator/src/local/mod.rs`, "Outcomes"). The CLI keeps it at the level of
the command: one write per invocation, never repeated.

**Recommendation: print what to run, do not reconcile automatically**
(proposed; Q1). After exit 5 the CLI prints, on standard error, the fixed
text of the cause and the next command, by flag names only:

- `bootstrap`: `run skyoauth-operator status --reconcile bootstrap with
  the same flags`; the bootstrap's own four flags are what
  `BootstrapVerdict::of` compares, so the operator repeats the line with
  `bootstrap` replaced.
- `restore`: `run skyoauth-operator status --reconcile restore --response
  FILE with the same socket flags`.
- `issue-challenge`: `no reconcile is possible: issue again; the first
  challenge, if it was issued, expires unused` (Q5). An `--out` left empty
  is named.

Why not reconcile automatically: an unknown outcome is mostly a timeout or
a failed store, and a `status` sent at once meets the same service and
cannot see the listen queue, where the request may still wait; its first
answer is then the least final one (`issued`, no recovery state), which
the procedure turns into "repeat the same write". Run by the operator, the
read comes when the operator chooses, after the service is back, and each
invocation's exit code is one request's outcome. The alternative, one
automatic `status` read after exit 5 that prints the verdict and never
repeats the write, stays within the library's rule (a read is not a
retry); it would add a second outcome to one exit code.

`status --reconcile restore` prints `RestoreVerdict::of`, as the C4
procedure decides it:

| State | `verdict:` | `next:` |
| ----- | ---------- | ------- |
| `restored` | `committed` | the replacement's IDs and every revoked ID are listed; do not repeat |
| `retired`, `revoked` | `never_commits` | issue a new challenge |
| `issued` | `repeat_restore` | run the same `restore`; it restores or is `not_restorable`; then reconcile again |
| `expiring` | `ask_again_after` | run `status` again after `settles_at` (printed with `server_time`; the CLI does not wait) |
| `expired` | `expired` | issue a new challenge; not final |
| `not_found`, none | `unknown` | do not proceed |

After any retry (lead ruling (c)), a `not_restorable` from `restore` or a
`conflict` from `issue-challenge` adds to its exit-1 message: `if an
earlier restore of this challenge may have committed, run status
--reconcile restore on the original response`.

`status --reconcile bootstrap` prints `BootstrapVerdict::of`: `matches
(enabled: yes|no)` with `next: do not repeat; the credential is usable
only when enabled`; `repeat_bootstrap` with `next: run the same
bootstrap`; `does_not_match` with `next: do not claim the bootstrap
committed; stop`. Both reconciles exit 0 whatever the verdict (Q3).

## Output and redaction

As D1 (proposed where D1 did not decide it):

- Results on standard output, one `name: value` per line in the reply's
  member order, then `result:` (and `verdict:` and `next:` for a
  reconcile); errors on standard error as one line `skyoauth-operator:
  <message>`, plus the next command for exits 5 and 6.
- Strings from the service (IDs, the operation ID) printed quoted with
  D1's `quoted`: printable ASCII as is, every other character escaped.
  Integers in decimal, byte values (`recovery_public_key`,
  `enrolled_trust_anchor_sha256`) in lowercase hexadecimal, `null` as
  `null`. Everything printed is printable ASCII and newlines.
- Never printed: a signature (not even on refusal), the request or reply
  line, the `M` bytes, the DER of `--credential-spki`, the socket path or
  any path, a value given on the command line. Messages name a flag and
  the kind of a failure; the library's `Display` texts are fixed and name
  no value (`PathError` names the problem, never the path).
- Success of a write whose output then fails: exit 3 as D1, and standard
  error says what succeeded, so the operator does not repeat a committed
  write: `the restore committed, but its output cannot be written: run
  status --reconcile restore`; `the challenge was issued, but --out cannot
  be written: issue again`.

## Idempotence

- `bootstrap`: a repeat after a commit is `conflict` (exit 1), which hides
  the first success; after exit 5, reconcile; `repeat_bootstrap` is the
  only verdict that repeats it (the database closes it once).
- `issue-challenge`: each run issues a new challenge; a repeat is harmless
  (a stray challenge expires unused and a restore retires the others) but
  writes a row and an audit event.
- `restore`: single use; a repeat after a commit is `not_restorable`,
  which hides the first success; after exit 5, reconcile.
- `preview`, `status`: change no row; repeat freely. A `status` walk that
  meets the documented tie restarts once inside the library.
- A process killed after it may have written its request (`SIGINT`,
  `SIGKILL`) leaves an unknown outcome with no exit code of its own:
  reconcile as for exit 5. The call's thread never writes once the caller
  has given up (`exchange.rs`, the `phase` handshake), and the process's
  exit ends a connect still blocked.

## Not in D2

- The D3 provisioning client: the remote private mTLS client (S9), TLS to
  the admin listener (D5), any admin API call.
- Generating or provisioning keys: no mTLS key, CSR or certificate, no
  recovery key pair; deriving the recovery public key from a seed file is
  not a command in D1 or D2.
- The binding subcommand and any service-side change: the service's
  socket path setting and its startup or subcommand path.
- The syslog-over-TLS forwarder (tasks §13, D6).
- A bridge to a socket inside a pod (`Connector` allows one later; the
  user's question stays open), and non-Unix transports (named pipes).
- Automatic retry, automatic reconcile (Q1), waiting for `settles_at`.
- M1b's recovery-signed provider transitions (OQ-ADR012-4).
- JSON output, a configuration file, the environment.

## Platforms

The binary builds on Linux, macOS and Windows (ADR-017 item 15, T13.10).
The client is Unix only (`#[cfg(unix)]`), so on Windows the online
commands are parsed with their flags, as everywhere, and then end with exit
2 and the fixed text `<command> needs the deployment-local Unix socket,
which this platform does not have`, before any file is read (proposed:
Q7). The help lists them on every platform, marked "Unix only". macOS runs
them (the client is Unix), with the access-control-list residual of
`check_socket` ("Access control lists"); the service binds on Linux only.

## Testing plan

- **The `operator` target, a fake server** (`operator/tests/cli/`, a new
  `online.rs`; Linux and macOS legs): a `UnixListener` of mode 0600 in a
  private 0700 directory, `--service-uid` the test's own UID (the owner of
  a file it creates), serving the fixture's golden lines (the bytes the
  real service sent, `exchange`). Required cases: each command's output;
  the request line received equals the fixture's golden request, byte for
  byte; `--out` equals the served reply line exactly and
  `verify-challenge` accepts it; each refusal code (exit 1); a store
  failure after each write (5) and after `preview` and `status` (1); every
  `UnknownOutcome` kind after a write (5) and after a read (6), a timeout
  with a small `--total-wait`; each refused socket path (wrong mode, wrong
  owner, shared directory, missing) as exit 6 with no byte received;
  exactly one connection per write, whatever the outcome; a signature of
  63 bytes refused with no connection; the `status` walk over several
  pages, its tie restart, and `PageMismatch` (6); every verdict's lines;
  stdout and stderr printable ASCII, no signature hex, no socket path, and
  every exit code within 0 to 6 (D1's harness asserts 0 to 4 today).
- **Windows leg:** each online command exits 2 with its fixed text and
  reads no file.
- **The real service** (`skyoauth-scenarios`, the `pg` target): Cargo sets
  `CARGO_BIN_EXE_<name>` only for the integration tests of the binary's
  own package (not verified by running), so the scenarios cannot run the
  binary through the approved dev-dependency alone. Proposed: the
  dev-dependency serves the C4 library round trip (`LocalClient` against
  `LocalTransport` on a socket in a private directory: bootstrap, its
  reconcile `matches`, issue, a test-key signature, preview, restore, the
  repeat `not_restorable`, the restore reconcile `committed` with every
  revoked ID), and the binary meets the real service's bytes through the
  fixture above. A binary-level journey in `pg` needs the binary's path
  from the job, failing loudly when missing (conformance layout: never
  pass vacuously): a CI change, Q8.
- **Mutants** (by hand, each must turn a test red): a store failure after
  a write as 1; an unknown read as 5, or an unknown write as 6; not sent
  as 5; `--out` re-encoded from the parsed reply (a missing newline, say);
  `--out` written before the challenge check (a `ChallengeMismatch` reply
  saved); a second connection after an unknown write; a verdict printed
  for the wrong state; a signature or the socket path in a message; a
  signature padded or cut to 64 bytes instead of refused;
  `LocalClient::unchecked` in place of `new` (a socket of mode 0666
  connected); `--total-wait` ignored; exit 0 after a success whose output
  failed.

The implementation PR also amends D1's proposal ("it reads no socket"),
the binary's module docs and help, and the README's operator paragraph.

## Rulings

All by the lead, 2026-11-27, on review of this proposal; each accepts the
recommendation that was made with the question.

1. **Reconcile:** the command prints what to run; no automatic reconcile.
   One write per invocation, no read on its heels.
2. **Exit codes 5 and 6** as defined (5: a write's outcome is unknown; 6:
   nothing was changed).
3. **`status` exit code:** 0 for every answered read, with the stable
   `verdict:` line.
4. **`--service-uid` required; `--trust-ancestors` defaults to
   `service-or-root`.**
5. **`--socket` required, no default**, until the binding slice fixes a
   path.
6. **The verbatim reply for `--out`:** a small addition to `LocalClient`
   that returns the reply line verbatim together with the parsed
   `Challenge`, in the D2 implementation.
7. **Online commands on Windows:** parsed, then exit 2 with fixed text.
8. **Tests:** the fake server with the fixture's real bytes in D2; the
   library journey with the approved `skyoauth-scenarios` dev-dependency
   (a separate PR); the binary journey in `pg` is a CI follow-up, the job
   passing the binary's path and failing loudly when it is missing.

Everything else in the proposal stands, including `--out` created new
before the request is sent, and the output rules.

## Not verified

- Nothing was built or run for this proposal but the docs check.
- C4's API was read from pull request #211 at `4ef4fa0`, before it
  merged; the commands of slice 1 are built against the merged API.
- That `CARGO_BIN_EXE_<name>` is set only for the binary's own package:
  from Cargo's documentation as remembered, not tried.
- That the reply parser accepts exactly one byte form per reply (Q6): from
  its module docs, not tested by re-encoding.
