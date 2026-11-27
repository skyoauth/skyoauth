# Proposal: the offline operator command line and its artifacts (T13.10)

Status: Interim, until the contracts define the artifacts; this document
changes no contract under `docs/contracts/`. Implemented: `verify-challenge`
and `verify-response` (D1a), `sign` and its seed file (D1b).

## Who decided what

- **User ruling** (2026-11-27, relayed by the lead; tasks §13, "Other rulings
  of the user, 2026-11-27", entry "Recovery artifacts (interim, until the
  contracts define them)"): the challenge artifact is the `issue_challenge`
  reply, verbatim; the response artifact is `{operation_id, signature}`, with
  `signature` hex-encoded. A change to it goes back to the user.
- **Lead picks** (2026-11-27, D1a and its review): the binary's name and that
  it is a target of the `skyoauth-operator` package; flags only, no
  configuration file; `--now` with the system clock as its default, the
  clock printed; `--epoch` required; the exit codes 0 to 4, and that help is
  recognised only where a command or a flag is expected (`help` only as a
  command); the seed file as 64 lowercase hexadecimal digits; the Windows
  residual documented, with no protection claimed.
- **Lead rulings on the seed file** (2026-11-27, D1b): 64 lowercase
  hexadecimal digits with at most one trailing newline; a regular file, not
  a symbolic link (checked with `symlink_metadata`, and the opened file
  checked again as the same device and inode); on Unix owned by the
  effective user and of mode 0600 exactly; never an argument, never the
  environment; read into a fixed buffer with a size cap, never echoed, never
  shown with `Debug`; on Windows no protection checked, the residual
  documented and the help warning of it; the seed not wiped
  (`SoftwareSigner` has no `zeroize`), documented (since then wiped, by
  the `zeroize` PR that the user ruled,
  [tasks §13](../skyoauth-tasks.md#13-m1a-lead-decisions-2026-11-24),
  "Other rulings of the user": see [the seed file](#the-seed-file)).
  Also lead: every
  expectation is required for `sign`, and exit 4 is `verify-challenge`'s
  only. D1b review: `--out` required (no response on standard output), the
  file synchronized before success, the seed file read up to 128 bytes with
  every content error one refusal, the setuid and `sudo` guidance.
- **Implementation picks** (D1a and D1b, open to review): the byte form of
  each artifact (one line, its newline, member order, no whitespace, the
  escapes, lowercase hexadecimal), the size limits, the output lines and
  messages, `sign`'s exit codes within the lead's table (which failure is 1,
  2 or 3), the order of `sign`'s steps, its output, and how the effective
  user is read. Each is marked
  "(implementation pick)" below.

The workstation side of offline recovery (ADR-013 items 7 and 8; the
`recovery-offline` chain of [the conformance layout](../testing/conformance-layout.md))
carries a recovery challenge from the service's host to the workstation that
holds the recovery key, and the signed response back. The carrier is two
files, the artifacts. The binary `skyoauth-operator`, in the
`skyoauth-operator` package (`operator/src/bin/skyoauth-operator/`), checks
and signs them offline: the commands of D1 read no socket, no environment
and no configuration file, and write no file but the one `sign --out` names,
which `sign` creates new. The online commands of D2, in
[the online commands proposal](operator-cli-online.md), do read a socket: the
service's deployment-local one.

## Commands

```text
skyoauth-operator verify-challenge --challenge FILE --instance-id ID --epoch N
    [--replacement-identity ID] [--trust-anchor REF] [--new-recovery-key HEX]
    [--now MICROS]
skyoauth-operator sign --challenge FILE --seed-file FILE --out FILE
    --instance-id ID --epoch N --replacement-identity ID --trust-anchor REF
    --new-recovery-key HEX [--now MICROS]
skyoauth-operator verify-response --challenge FILE --response FILE --key HEX
skyoauth-operator --help
```

Flags only, each `--flag VALUE` with the value as the next argument, each
given at most once; a value may not be empty or begin with `--`. Integers
(`--epoch`, `--now`) are 64-bit, in their shortest decimal form. A key
(`--new-recovery-key`, `--key`) is a recovery public key, 64 lowercase
hexadecimal digits, refused as the service refuses it (not canonical, of
small order, undecodable).

Help is recognised only where a command or a flag is expected, never as a
value: `help` only as the command (alone), `--help` and `-h` as the command
or where a flag of a command is expected. There it prints the help and exits
0. Anywhere else it is a usage error: `verify-challenge help` (`help` is not
a flag), `bogus -h`, `--help verify-challenge`, and `--instance-id --help`
(a value may not begin with `--`); `--challenge -h` reads the file named
`-h`.

`verify-challenge` reads the challenge artifact, then the clock, checks the
challenge with `parse_challenge` and `check_challenge` against the given
values and the clock, and prints, one per line: the clock used, the
challenge's `operation_id`, `expected_revision` and `expires_at`, the plan's
`instance_id`, `recovery_key_epoch`, `admin_id`, `credential_id`,
`binding_id`, `public_identity` (the replacement's identity),
`trust_anchor_ref` and `new_recovery_public_key`, then `given:` and the plan
values given to compare, and the plan values that are not checked:
`admin_id`, `credential_id` and `binding_id` are generated by the service.
`--instance-id` and `--epoch` are required, so the instance and the
recovery key epoch are always checked, and `expires_at` is checked against
the clock.

The replacement is confirmed only when `--replacement-identity`,
`--trust-anchor` and `--new-recovery-key` are all given and match the plan:
then the command prints `replacement_confirmed: yes` and exits 0. When one
of them is not given and every given check passed, it prints
`replacement_confirmed: no (not given: <flags>)`, names the flags on
standard error and exits 4: an expectation left out is never skipped
silently. Signing (`sign`, `sign_challenge`) needs a confirmed replacement
and also the signer's key to differ from the plan's new recovery key
(`RecoveryKeyUnchanged`), which this command cannot check, as it holds no
private key. A refused challenge still prints its plan and the `given:`
line (the check stops at the first refusal, so not every value given was
compared), then `result: refused (<Refusal>)`. (Output lines: implementation
pick.)

Strings from an artifact are printed in double quotes, with only printable
ASCII as is: `"` and `\` after a backslash, every other character as
`\u{X}` (its code point in lowercase hexadecimal). So a control character or
a bidirectional override in a plan cannot change what the terminal shows.
(Implementation pick.)

`--now MICROS` is the time to check against, in microseconds since the Unix
epoch. Without it the system clock is used, read after the artifact. The
first line of the output names the clock: `clock: --now <micros>` or
`clock: system <micros>`.

`verify-response` checks the response artifact's operation ID against the
challenge's, then its signature over the challenge's `M` with the recovery
public key `--key`, as the service's restore checks it (`verify_response`:
64 bytes, then `verify_strict`). It prints the operation ID and the result;
it never prints the signature, whatever the result.

### `sign`

`sign` takes the flags of `verify-challenge`, all of the replacement's
values required (lead pick: it signs only a confirmed replacement), the
seed file (`--seed-file`, see [the seed file](#the-seed-file)) and the
output file (`--out`, required; lead ruling). In this order
(implementation pick):

1. the command line: a flag left out is a usage error (exit 2), decided
   before any file is read. An unconfirmed replacement cannot reach the
   signing: a missing expectation is known from the command line alone, so
   it is a usage error, not a refusal (exit 1, which is for what an
   artifact or a check refuses) and not exit 4 (`verify-challenge`'s only;
   lead pick);
2. the challenge artifact, read and checked as `verify-challenge` reads and
   checks it, with the same clock (`--now`, or the system clock read after
   the artifact): any refusal is exit 1, `refused (<Refusal>): …`;
3. only then the seed file, read and checked (exit 3 for the file, exit 1
   for its bytes), and the signer `SoftwareSigner::from_seed`: a refused
   challenge never reads the seed;
4. `sign_challenge`, which refuses a plan whose new recovery key is the
   signer's own (`refused (RecoveryKeyUnchanged): …`, exit 1) and checks
   its own signature (`refused (NotVerified)`, `refused (Signer(Failed))`,
   exit 1; not expected with this signer);
5. the response artifact, written last to the new `--out` file (below);
   standard output then shows `clock:`, `operation_id:`,
   `replacement_confirmed: yes` and `result: ok; …`, never the signature.

The response never goes to standard output (lead ruling): a standard
output that was closed when the command started is reopened on
`/dev/null` by the Rust runtime on Unix, so a response written there would
be lost with exit 0, and a shell redirection would bypass the checks of
`--out` (a new file, mode 0600). So `sign` never prints a signature, and a
`sign` that fails prints nothing on standard output. The
artifact is built with the transport's codec
(the `restore` request line without its `op` member), so it is byte for
byte what a `restore` request carries. Ed25519 signing is deterministic: the
same challenge and seed give the same artifact. (Implementation pick.)

`--out FILE` is created new (`create_new`: `O_CREAT | O_EXCL` on Unix,
`CREATE_NEW` on Windows), of mode 0600 on Unix (the umask may only remove
bits): an existing file, a directory or a symbolic link, even a dangling
one, is never followed or overwritten, and is refused with exit 3 (`--out:
the file already exists; it is never overwritten`). The response is written
and synchronized to the disk (`sync_all`) before success is reported. A
write or synchronization that fails after the file was created is exit 3
(`--out: the file cannot be written (<kind>)`) and may leave a partial or
empty file, which is not a response artifact and is refused as one; remove
it before signing again. (Implementation pick.)

What a `sign` that does not succeed leaves (implementation pick; the help
says the same):

- A refused `sign` (exit 1), and one stopped by a usage error (exit 2) or
  by an I/O error before `--out` is created (exit 3: the challenge, the
  clock, the seed file, an `--out` that exists or cannot be created),
  creates no file.
- A write or synchronization of `--out` that fails (exit 3) may leave a
  partial or empty file: remove it.
- Under a file-size limit (`RLIMIT_FSIZE`, `ulimit -f`) the process may
  instead be killed by `SIGXFSZ`, whose default action ends it with no
  exit code of its own; the file is then partial or empty too, and must be
  removed. The binary handles no signal (no `unsafe` call, no dependency);
  exit 3 for a write over the limit holds only where `SIGXFSZ` is ignored,
  as the test that pins it arranges (`trap "" XFSZ`).
- When only the summary on standard output cannot be written (exit 3,
  `the output cannot be written (<kind>)`), the response was written and
  synchronized first, so `--out` is complete: check it with
  `verify-response` before signing again, since a retry at the same path
  fails while the file exists (`--out: the file already exists`).
- On macOS an access control list inherited from the `--out` directory can
  let other users read the new file whatever its mode shows (see
  [the seed file](#the-seed-file)): remove the directory's ACLs first.

Results go to standard output, errors to standard error as one line
`skyoauth-operator: <message>` (a usage error adds a line that points to
`--help`). No message repeats a value given on the command line or read from
an artifact; a file is named by its flag, a failure by its kind. The output
is the same for the same arguments and files, the system clock aside. A
write to standard output that fails makes the command exit 3, whatever its
result, and say so on standard error (`the output cannot be written
(<kind>)`); a write to standard error that fails makes it exit 3 too. Only a
write that fails does: a standard output or error that was closed when the
command started is reopened on `/dev/null` by the Rust runtime on Unix (on
Windows, the standard library takes the writes to a missing handle as
done), so its writes succeed and the command keeps its own exit code: it
never turns a failure into 0, and no result of `sign` is lost, since its
response is written to `--out` only. (Messages: implementation pick.)

## Exit codes

Lead pick; which of `sign`'s failures is 1, 2 or 3 is an implementation
pick within it (D1b).

| Code | Meaning |
| ---- | ------- |
| 0 | Every check passed: for `verify-challenge`, every expectation was given and passed, so the replacement is confirmed (`replacement_confirmed: yes`); for `sign`, the challenge is signed and the response artifact written; for `verify-response`, the signature verifies. Or the help was printed. |
| 1 | Refused: a check failed (`refused (<Name>): …`, the name of the `Refusal`, `SignError` or `VerifyError`, or `OtherOperation` for a response to another operation), or an artifact is not what it must be. For `sign` also: a seed file of at most 128 bytes that is not a seed (`--seed-file: the file is not a seed: …`, one message for every content error), and the seed's public key refused (not expected). |
| 2 | Usage: no or an unknown command, an unknown, repeated or missing flag (`--epoch` included; for `sign` every flag but `--now`), a flag without a value, a value that does not parse, help where it is not recognised. |
| 3 | I/O: a file is missing, not a regular file, larger than its limit or unreadable; the system clock cannot be read; a write to the output fails. For `sign` also: a seed file that is a symbolic link, larger than 128 bytes, changed between its check and its opening, or on Unix owned by another user than the effective user or not of mode 0600 exactly, or whose effective user cannot be read; an `--out` that exists or cannot be created, written or synchronized. |
| 4 | `verify-challenge` only: every given check passed, but the replacement is not confirmed, because `--replacement-identity`, `--trust-anchor` or `--new-recovery-key` was not given (`replacement_confirmed: no (not given: …)`). Not a pass. |

## The challenge artifact

User ruling: the `issue_challenge` reply, verbatim. Implementation pick:
the reply line exactly as the deployment-local transport sent it, its
newline included, and nothing else:

```text
{"operation_id":"…","expires_at":…,"expected_revision":…,"challenge":"<hex of M>"}
```

It is read with the transport's codec (`skyoauth_operator::local::parse_reply`,
pinned by `tests/conformance/fixtures/_wire/local_transport.v1.json`), which
is built on every platform for this reason; its `challenge` is read with
`parse_challenge`, and its `operation_id`, `expires_at` and
`expected_revision` must be `M`'s. A refusal line (`{"error":"…"}`) is
refused as such. At most 4 MiB (`MAX_REPLY_BYTES`, the transport client's
own limit). The bytes are kept as they are: a carrier that converts line
endings or adds a byte order mark makes the artifact refused.

## The response artifact

User ruling: `{operation_id, signature}`, with `signature` hex-encoded.
Implementation pick: one line, its newline included, and nothing else:

```text
{"operation_id":"…","signature":"<128 lowercase hex digits>"}
```

The two members in that order, no whitespace; the operation ID is the
challenge's, escaped as the transport's codec escapes a string (`\"`, `\\`,
the five short control escapes, `\u` and four lowercase digits for another
control character; nothing else is escaped); the signature is the 64-byte
Ed25519 signature over `M` in lowercase hexadecimal. It is the `restore`
request's values without its `op` member. At most 64 KiB
(`MAX_REQUEST_BYTES`: a response that cannot be sent as a `restore` request
is of no use). A signature of another length is read, and refused by
`verify_response` (`refused (Length)`).

## The seed file

Lead rulings (D1b), implemented in `operator/src/bin/skyoauth-operator/seed_file.rs`:

- The private key is never an argument and never read from the
  environment: no flag takes it (`--seed-file` takes a path), and the binary
  reads no variable. It is a file given with `--seed-file`.
- Its content: 64 lowercase hexadecimal digits (the 32-byte RFC 8032 seed),
  optionally followed by one newline, and nothing else (at most 65 bytes:
  a decoding rule). Uppercase digits, a carriage return (CRLF), a byte
  order mark, a second newline, whitespace, a `0x` prefix, raw bytes and
  any trailing byte are refused. The file is read up to a cap of 128 bytes
  (lead ruling), so every such content error is one refusal, exit 1, `the
  file is not a seed`; a file larger than 128 bytes is exit 3 (`the file is
  larger than 128 bytes`), as an artifact over its limit is (implementation
  pick: the size is a file check, made before the file is read).
- A regular file, not a symbolic link: the path is checked with
  `symlink_metadata` before it is opened, so a link (even to a good seed
  file), a directory, a device or a named pipe is refused without being
  opened; the opened file is checked again, and on Unix must be the same
  file (device and inode) as the path checked.
- On Unix, owned by the effective user and of mode 0600 exactly (no other
  permission bit, no special bit), on the path and on the opened file. The
  effective user is the owner the kernel gives a pipe the process creates
  (implementation pick: `std` has no `geteuid`, and the binary makes no
  `unsafe` call and adds no dependency; on Linux it is the file-system UID,
  which follows the effective UID). Run `sign` as the seed file's owner:
  under `sudo` the effective user is root, and a seed file of the operator
  is refused as another user's.
- The owner and mode check reads no access control list (`std` cannot),
  as the client's socket path check does not
  (`skyoauth_operator::local::check_socket`, "Access control lists"). On
  Linux a POSIX ACL's grants show in the group bits (the ACL's mask), so a
  seed file an ACL lets others read is not of mode 0600 and is refused.
  macOS does not show them: an ACL there can let other users read the
  seed file whatever its mode bits show, and an ACL inherited from the
  `--out` directory can do the same for the new response file. On macOS
  remove the ACLs of the seed file and of the `--out` directory
  (`ls -le` shows them, `chmod -N` removes them).
- Never install the binary setuid or setgid. It checks the seed file
  against its effective user, so a setuid copy is a confused deputy: a
  setuid-root copy run by any user signs with a root-owned seed file
  (verified in the D1b review). The binary does not detect it (`std` reads
  no real user ID).
- Read into a fixed buffer of 129 bytes (the cap and one byte to detect a
  file that grew), never echoed: every message names the flag and the kind
  of the failure, never the path, the bytes or the seed; nothing in the
  seed file's reader derives or formats with `Debug`.
- The seed is wiped from memory with `zeroize` (volatile writes kept in
  order by a compiler fence), on every return, refusals and errors
  included (the `zeroize` PR is the user's ruling; how it is done below is
  an implementation pick):
  - the binary reads the file into a fixed buffer that is wiped on drop
    (`Zeroizing`) (implementation pick);
  - it decodes the seed in place into a `[u8; 32]` that is wiped on drop,
    never returned, moved or copied by value (implementation pick);
  - `SoftwareSigner::from_seed` borrows that array mutably and wipes it in
    place once the signing key is made, so the caller sees all zeros
    after (implementation pick), and the binary keeps the signer in its
    `Result`, borrowed, never moved (implementation pick);
  - the `SigningKey` inside `SoftwareSigner` is wiped when the signer is
    dropped: the operator crate builds `ed25519-dalek` with its `zeroize`
    feature, which adds no crate to the lock file. The service's manifest
    is unchanged, and a build of the service alone
    (`-p skyoauth-service`) has `ed25519-dalek` without `zeroize`; a
    `--workspace` build unifies the feature, so there the service's
    `ed25519-dalek` is built with `zeroize` too (no change to its set of
    dependencies: `zeroize` is already in its graph, through `rustls`);
  - compile-time checks fail the build if the buffer, the seed or
    `SigningKey` is not wiped on drop (the library's own check for
    `SigningKey`, the binary's for its buffer and seed), and source checks
    of the `operator` target pin each wipe (implementation pick).

  What is not covered is listed under [Residuals](#residuals).

## Residuals

- **Windows:** no protection of the seed file is checked: the permission
  bits of Unix have no equivalent that `std` reads, and access control lists
  and the owner are not checked, nor is the opened file compared with the
  path checked (only that both are regular files and the path is not a
  symbolic link). The operator must protect the file by other means; the
  help says so. The binary claims no protection there.
- **macOS access control lists:** the owner and mode check does not see
  them (see [the seed file](#the-seed-file)); remove the ACLs of the seed
  file and of the `--out` directory.
- **The seed in memory:** wiped once used (see
  [the seed file](#the-seed-file)), as a best effort. Not covered: copies
  the system makes (the kernel's page cache of the seed file, swap, a core
  dump or a hibernation image taken while the seed is held); a bitwise
  copy the compiler leaves when it moves a value (a move does not wipe
  its old place, and Rust gives no control over it; the binary moves
  neither the seed nor the signer); registers, spilled temporaries and
  intermediate values of the decoding and the signing: in
  `ed25519-dalek` 3.0.0, `ExpandedSecretKey::from` (run when the signing
  key is made and for each signature) leaves the 64-byte SHA-512 digest
  of the seed, which is the expanded key itself, and the `scalar_bytes`
  copy of its first half on the stack unwiped, and the SHA-512 state
  over the seed is not wiped; other copies of the seed that a caller of
  the library made before `SoftwareSigner::from_seed` (the binary makes
  none); and a process that is killed or aborts before the wipes run.
  So disable
  core dumps (`ulimit -c 0`) and use encrypted or no swap on the
  workstation that signs. The seed never comes from the command line, the
  environment or standard input.
- **Named pipes and devices:** a path that is replaced by a named pipe or a
  device between its check and its opening can block the read or have
  side effects (no non-blocking open without a platform dependency); for
  the seed file the opened file is refused afterwards (not a regular file,
  not the same file), but the open has happened. The artifacts and the seed
  file are the operator's own files.
- **Setuid or `sudo`:** see [the seed file](#the-seed-file): run as the
  seed file's owner, never install the binary setuid or setgid.
- **Shell redirection:** a shell that re-encodes text (Windows PowerShell
  5.1's `>` writes UTF-16) makes an artifact refused; write artifacts as
  bytes.
