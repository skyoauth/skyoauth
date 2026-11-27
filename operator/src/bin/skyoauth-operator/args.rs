//! The command line, parsed by hand: a command, then its flags, each flag
//! followed by its value as the next argument (`--flag VALUE`). A flag is
//! given at most once, every required flag must be given, and a value may
//! not be empty or begin with `--`. No flag takes a private key: `sign`
//! takes the path of a seed file (`--seed-file`), never the seed. Nothing
//! is read from the environment or a configuration file.
//!
//! A refused argument is named by its flag, or by its position when it is
//! not a flag: no message repeats a value given on the command line.
//!
//! The online commands (`bootstrap`, `issue-challenge`, `preview`,
//! `restore` and `status`) take the socket flags ([`SocketFlags`]) and are
//! parsed on every platform; only a Unix system runs them
//! (`docs/proposals/operator-cli-online.md`, "Platforms").

use std::{ffi::OsString, path::PathBuf, time::Duration};

use skyoauth_operator::recovery::RecoveryPublicKey;

use crate::Failure;

/// The text of `--help`.
pub const HELP: &str = "\
skyoauth-operator: checks and signs a recovery challenge offline, and checks
its signed response; on the service's host, bootstraps the instance, issues
the challenge, restores with its signed response and reads the recovery
state over the service's deployment-local socket

Usage:
  skyoauth-operator verify-challenge --challenge FILE --instance-id ID --epoch N
      [--replacement-identity ID] [--trust-anchor REF] [--new-recovery-key HEX]
      [--now MICROS]
  skyoauth-operator sign --challenge FILE --seed-file FILE --out FILE
      --instance-id ID --epoch N --replacement-identity ID --trust-anchor REF
      --new-recovery-key HEX [--now MICROS]
  skyoauth-operator verify-response --challenge FILE --response FILE --key HEX
  skyoauth-operator bootstrap SOCKET --instance-id ID --credential-spki FILE
      --trust-anchor REF --recovery-key HEX                        (Unix only)
  skyoauth-operator issue-challenge SOCKET --credential-spki FILE
      --trust-anchor REF --new-recovery-key HEX --out FILE         (Unix only)
  skyoauth-operator preview SOCKET --response FILE                 (Unix only)
  skyoauth-operator restore SOCKET --response FILE                 (Unix only)
  skyoauth-operator status SOCKET [--challenge FILE | --response FILE]
      [--credential-spki FILE]                                     (Unix only)
  skyoauth-operator status SOCKET --reconcile restore
      (--challenge FILE | --response FILE)                         (Unix only)
  skyoauth-operator status SOCKET --reconcile bootstrap --instance-id ID
      --credential-spki FILE --trust-anchor REF --recovery-key HEX (Unix only)
  skyoauth-operator --help

  SOCKET is: --socket PATH --service-uid UID
      [--trust-ancestors service-or-root|root-only]
      [--total-wait SECONDS] [--idle-wait SECONDS]

verify-challenge reads the challenge artifact (the issue_challenge reply
line, verbatim), checks it against the given values and the clock, and
prints the restoration plan to compare. The replacement is confirmed
(replacement_confirmed: yes, exit 0) only when --replacement-identity,
--trust-anchor and --new-recovery-key are all given and match; when one of
them is not given, the output names it and the exit code is 4. Signing
also needs the signer's key to differ from the plan's new recovery key,
which this command cannot check.

sign checks the challenge as verify-challenge does, with every value
required, then signs it with the recovery private key of the seed file and
writes the response artifact to --out, a new file (mode 0600 on Unix; an
existing file is never overwritten). The seed file holds the 32-byte seed
as 64 lowercase hex digits and at most one newline. On Unix it must be a
regular file, not a symbolic link, owned by the effective user, of mode
0600 exactly: run sign as the seed file's owner (not with sudo), and never
install this binary setuid or setgid. That check reads no access control
list: on macOS an ACL can let others read the seed file or a new --out file
(inherited from its directory) whatever the mode shows, so remove ACLs from
the seed file and from the --out directory (ls -le, chmod -N).
On Windows its protection is NOT checked: keep it where only you can read
it. The seed is never taken from the command line or the environment,
never printed, and wiped from this process's memory once used. That is a
best effort; not wiped are copies the system makes (swap, a core dump),
copies the compiler leaves when it moves a value, and the signing
library's intermediate values: ed25519-dalek 3.0.0 leaves the 64-byte
SHA-512 digest of the seed (the expanded key) and a copy of its first
half on the stack. Disable core dumps and use encrypted or no swap.

A refused sign creates no file. A write to --out that fails (exit 3) may
leave a partial or empty file: remove it. Under a file-size limit
(ulimit -f) the process may instead be killed by SIGXFSZ, without exiting
3; the file is then partial or empty too. When only the summary on standard
output fails (exit 3), --out is complete: check it with verify-response
before signing again, since a retry at the same path fails while the file
exists.

verify-response checks the response artifact's signature over the
challenge with the recovery public key --key (64 lowercase hex digits).

--now MICROS is the time to check against, in microseconds since the Unix
epoch; without it the system clock is used. The clock used is printed.

The online commands talk to the service's deployment-local Unix socket, on
the service's host, as the service UID or root; none takes a private key,
and each sends one request (status: and the pages of revoked IDs), never
repeated. --socket is the socket's path (required, no default). It is
checked before the connect: every directory on the way owned by a trusted
UID and not writable by others, the socket's own directory private, the
socket owned by --service-uid (required) with mode 0600 exactly.
--trust-ancestors names the trusted UIDs: service-or-root (the default:
root and --service-uid) or root-only.
--total-wait (default 100) and --idle-wait (default 10) are whole seconds
over zero; the defaults fit a service with its default settings. Both
apply to each request, not to the command: preview sends one request;
status sends one, or for a restored operation with N revoked IDs
1 + ceil(N/1000) (at least 2), the pages read once more if N changes
while they are read. A command may so wait a multiple of --total-wait.

bootstrap sends the first operator's key (--credential-spki, a file of the
DER SubjectPublicKeyInfo, 1 to 4096 bytes), its trust anchor and the
recovery public key, for the instance --instance-id (given, never
generated), and prints what the service wrote: keep it, verify-challenge
needs the instance ID and the epoch. issue-challenge creates --out, a new
file (mode 0600 on Unix; an existing file is never overwritten), before it
sends the replacement's key file, trust anchor and new recovery key; it
writes the reply line to --out exactly as the service sent it, and prints
the operation, its expiry and the replacement's identity (to give
verify-challenge as --replacement-identity). On any other outcome --out is
left empty: remove it. restore sends the response artifact (--response)
and prints the replacement and the revoked credential IDs of its reply,
with revoked_credential_ids_complete: yes or no (no: status --response
lists every one).

preview sends the response artifact (--response) and prints what its
restore would enroll; preview and status change nothing on the service.
status prints the recovery state, and every member of the reply (null
where the service wrote null): with --challenge or --response also the
state of that operation (for a restored one, every revoked credential ID,
read page by page: revoked_credential_ids: N is followed by N
revoked_credential_id lines), with --credential-spki also that key's
enrollment. status --reconcile restore or --reconcile bootstrap adds a
verdict: line and a next: line, the step to take after a restore or a
bootstrap whose outcome is unknown; it exits 0 whatever the verdict. On a
platform without Unix sockets, the online commands exit 2.

Exit codes: 0 every check passed (verify-challenge: the replacement is
confirmed; sign: the response is written; bootstrap, restore: committed;
issue-challenge: issued and --out written; preview, status: the service
answered), or the help was printed; 1 refused (sign: also a seed file of at
most 128 bytes that is not a seed; online: also refused by the service, or
a response whose signature is not 64 bytes or a request over 64 KiB,
before anything is sent); 2 usage error; 3 a file, the clock or the output
could not be read or written (sign: also a seed file that is not protected
as above or is larger than 128 bytes; sign, issue-challenge: also an --out
that exists; after a write that succeeded, the message says what was
committed); 4 (verify-challenge) every given check passed, but the
replacement is not confirmed; 5 the outcome of a write (bootstrap,
issue-challenge, restore) is unknown: do not repeat it, reconcile first as
the message says; 6 nothing was changed: the request was not sent, or the
reply of preview or status cannot be believed; the same command may be run
again.
";

/// A command and its flags.
pub enum Command {
    /// `--help`, `-h` or `help` alone, or `--help` or `-h` where a flag of
    /// a command is expected.
    Help,
    /// `verify-challenge`.
    VerifyChallenge(VerifyChallenge),
    /// `sign`.
    Sign(Sign),
    /// `verify-response`.
    VerifyResponse(VerifyResponse),
    /// `bootstrap` (its flags are read on Unix only).
    #[cfg_attr(not(unix), allow(dead_code))]
    Bootstrap(Bootstrap),
    /// `issue-challenge` (its flags are read on Unix only).
    #[cfg_attr(not(unix), allow(dead_code))]
    IssueChallenge(IssueChallenge),
    /// `preview` (its flags are read on Unix only).
    #[cfg_attr(not(unix), allow(dead_code))]
    Preview(Preview),
    /// `restore` (its flags are read on Unix only).
    #[cfg_attr(not(unix), allow(dead_code))]
    Restore(Restore),
    /// `status` (its flags are read on Unix only).
    #[cfg_attr(not(unix), allow(dead_code))]
    Status(Status),
}

/// The flags of `verify-challenge`.
pub struct VerifyChallenge {
    pub challenge: PathBuf,
    pub instance_id: String,
    pub epoch: i64,
    pub replacement_identity: Option<String>,
    pub trust_anchor: Option<String>,
    pub new_recovery_key: Option<RecoveryPublicKey>,
    pub now: Option<i64>,
}

/// The flags of `sign`: those of `verify-challenge`, the replacement's
/// three values required, the seed file and the output file (required:
/// the response is never written to standard output, where a closed or
/// redirected descriptor would lose it or bypass the new file's checks).
pub struct Sign {
    pub challenge: PathBuf,
    pub seed_file: PathBuf,
    pub instance_id: String,
    pub epoch: i64,
    pub replacement_identity: String,
    pub trust_anchor: String,
    pub new_recovery_key: RecoveryPublicKey,
    pub now: Option<i64>,
    pub out: PathBuf,
}

/// The flags of `verify-response`.
pub struct VerifyResponse {
    pub challenge: PathBuf,
    pub response: PathBuf,
    pub key: RecoveryPublicKey,
}

/// Whom the client trusts with the directories on the way to the socket
/// (`--trust-ancestors`; the library's `AncestorTrust`, which is Unix
/// only).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustAncestors {
    /// `service-or-root`, the default.
    ServiceOrRoot,
    /// `root-only`.
    RootOnly,
}

/// The socket flags of every online command (unread off Unix, where the
/// command ends once they are parsed).
#[cfg_attr(not(unix), allow(dead_code))]
pub struct SocketFlags {
    /// `--socket`, required.
    pub socket: PathBuf,
    /// `--service-uid`, required: the socket's expected owner.
    pub service_uid: u32,
    /// `--trust-ancestors`, default `service-or-root`.
    pub trust_ancestors: TrustAncestors,
    /// `--total-wait`, whole seconds over zero, default 100: the total
    /// limit of each request, not of the command.
    pub total_wait: Duration,
    /// `--idle-wait`, whole seconds over zero, default 10, of each request.
    pub idle_wait: Duration,
}

/// The flags of `bootstrap`: the four values of its request, each given
/// (the instance ID too: never generated, so a rerun with the same flags
/// is the same request, which `status --reconcile bootstrap` compares).
#[cfg_attr(not(unix), allow(dead_code))]
pub struct Bootstrap {
    pub socket: SocketFlags,
    pub instance_id: String,
    pub credential_spki: PathBuf,
    pub trust_anchor: String,
    pub recovery_key: RecoveryPublicKey,
}

/// The flags of `issue-challenge`: the three values of its request and the
/// output file (required: the challenge artifact is written to a new file
/// only).
#[cfg_attr(not(unix), allow(dead_code))]
pub struct IssueChallenge {
    pub socket: SocketFlags,
    pub credential_spki: PathBuf,
    pub trust_anchor: String,
    pub new_recovery_key: RecoveryPublicKey,
    pub out: PathBuf,
}

/// The flags of `preview`.
#[cfg_attr(not(unix), allow(dead_code))]
pub struct Preview {
    pub socket: SocketFlags,
    pub response: PathBuf,
}

/// The flags of `restore`.
#[cfg_attr(not(unix), allow(dead_code))]
pub struct Restore {
    pub socket: SocketFlags,
    pub response: PathBuf,
}

/// The artifact that names an operation for `status`: `--challenge` or
/// `--response`, its operation ID read from it.
#[cfg_attr(not(unix), allow(dead_code))]
pub enum OperationArtifact {
    Challenge(PathBuf),
    Response(PathBuf),
}

/// What `status` asks.
#[cfg_attr(not(unix), allow(dead_code))]
pub enum StatusQuery {
    /// `status`, with an operation, a key, both or neither.
    Read {
        operation: Option<OperationArtifact>,
        credential_spki: Option<PathBuf>,
    },
    /// `status --reconcile restore`: the operation alone.
    ReconcileRestore(OperationArtifact),
    /// `status --reconcile bootstrap`: the bootstrap's four values.
    ReconcileBootstrap {
        instance_id: String,
        credential_spki: PathBuf,
        trust_anchor: String,
        recovery_key: RecoveryPublicKey,
    },
}

/// The flags of `status`.
#[cfg_attr(not(unix), allow(dead_code))]
pub struct Status {
    pub socket: SocketFlags,
    pub query: StatusQuery,
}

impl Command {
    /// The name of an online command, which needs the Unix socket.
    #[cfg_attr(unix, allow(dead_code))]
    pub const fn online_name(&self) -> Option<&'static str> {
        match self {
            Self::Bootstrap(_) => Some(BOOTSTRAP),
            Self::IssueChallenge(_) => Some(ISSUE_CHALLENGE),
            Self::Preview(_) => Some(PREVIEW),
            Self::Restore(_) => Some(RESTORE),
            Self::Status(_) => Some(STATUS),
            Self::Help | Self::VerifyChallenge(_) | Self::Sign(_) | Self::VerifyResponse(_) => None,
        }
    }
}

const VERIFY_CHALLENGE: &str = "verify-challenge";
const VERIFY_RESPONSE: &str = "verify-response";
const SIGN: &str = "sign";
const BOOTSTRAP: &str = "bootstrap";
const ISSUE_CHALLENGE: &str = "issue-challenge";
const PREVIEW: &str = "preview";
const RESTORE: &str = "restore";
const STATUS: &str = "status";

const CHALLENGE: &str = "--challenge";
const INSTANCE_ID: &str = "--instance-id";
const EPOCH: &str = "--epoch";
const REPLACEMENT_IDENTITY: &str = "--replacement-identity";
const TRUST_ANCHOR: &str = "--trust-anchor";
const NEW_RECOVERY_KEY: &str = "--new-recovery-key";
const NOW: &str = "--now";
const RESPONSE: &str = "--response";
const KEY: &str = "--key";
const SEED_FILE: &str = "--seed-file";
const OUT: &str = "--out";
const SOCKET: &str = "--socket";
const SERVICE_UID: &str = "--service-uid";
const TRUST_ANCESTORS: &str = "--trust-ancestors";
const TOTAL_WAIT: &str = "--total-wait";
const IDLE_WAIT: &str = "--idle-wait";
const CREDENTIAL_SPKI: &str = "--credential-spki";
const RECONCILE: &str = "--reconcile";
const RECOVERY_KEY: &str = "--recovery-key";

/// The defaults of `--total-wait` and `--idle-wait`, in seconds: the
/// library's `DEFAULT_TOTAL_WAIT` and `DEFAULT_IDLE_WAIT`, which are Unix
/// only, so repeated here; on Unix the assertions below fail the build when
/// they disagree, and `the_default_waits_are_the_librarys`
/// (`operator/tests/cli/online/unix.rs`) checks the help states the
/// library's.
const DEFAULT_TOTAL_WAIT_SECONDS: u64 = 100;
const DEFAULT_IDLE_WAIT_SECONDS: u64 = 10;
#[cfg(unix)]
const _: () =
    assert!(DEFAULT_TOTAL_WAIT_SECONDS == skyoauth_operator::local::DEFAULT_TOTAL_WAIT.as_secs());
#[cfg(unix)]
const _: () =
    assert!(DEFAULT_IDLE_WAIT_SECONDS == skyoauth_operator::local::DEFAULT_IDLE_WAIT.as_secs());

/// The flags of each command.
const VERIFY_CHALLENGE_FLAGS: [&str; 7] = [
    CHALLENGE,
    INSTANCE_ID,
    EPOCH,
    REPLACEMENT_IDENTITY,
    TRUST_ANCHOR,
    NEW_RECOVERY_KEY,
    NOW,
];
const SIGN_FLAGS: [&str; 9] = [
    CHALLENGE,
    SEED_FILE,
    OUT,
    INSTANCE_ID,
    EPOCH,
    REPLACEMENT_IDENTITY,
    TRUST_ANCHOR,
    NEW_RECOVERY_KEY,
    NOW,
];
const VERIFY_RESPONSE_FLAGS: [&str; 3] = [CHALLENGE, RESPONSE, KEY];
const BOOTSTRAP_FLAGS: [&str; 9] = [
    SOCKET,
    SERVICE_UID,
    TRUST_ANCESTORS,
    TOTAL_WAIT,
    IDLE_WAIT,
    INSTANCE_ID,
    CREDENTIAL_SPKI,
    TRUST_ANCHOR,
    RECOVERY_KEY,
];
const ISSUE_CHALLENGE_FLAGS: [&str; 9] = [
    SOCKET,
    SERVICE_UID,
    TRUST_ANCESTORS,
    TOTAL_WAIT,
    IDLE_WAIT,
    CREDENTIAL_SPKI,
    TRUST_ANCHOR,
    NEW_RECOVERY_KEY,
    OUT,
];
/// The flags of `preview` and of `restore`.
const RESPONSE_FLAGS: [&str; 6] = [
    SOCKET,
    SERVICE_UID,
    TRUST_ANCESTORS,
    TOTAL_WAIT,
    IDLE_WAIT,
    RESPONSE,
];
const STATUS_FLAGS: [&str; 12] = [
    SOCKET,
    SERVICE_UID,
    TRUST_ANCESTORS,
    TOTAL_WAIT,
    IDLE_WAIT,
    CHALLENGE,
    RESPONSE,
    CREDENTIAL_SPKI,
    RECONCILE,
    INSTANCE_ID,
    TRUST_ANCHOR,
    RECOVERY_KEY,
];

fn usage(message: impl Into<String>) -> Failure {
    Failure::Usage(message.into())
}

/// Whether `argument` asks for the help.
fn is_help(argument: &OsString) -> bool {
    argument == "--help" || argument == "-h"
}

/// The command line after the program name.
///
/// # Errors
///
/// [`Failure::Usage`] for anything but a known command with valid flags.
pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, Failure> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    let Some((command, flags)) = arguments.split_first() else {
        return Err(usage("no command given"));
    };
    if is_help(command) || command == "help" {
        return if flags.is_empty() {
            Ok(Command::Help)
        } else {
            Err(usage("the help takes no other argument"))
        };
    }
    match command.to_str() {
        Some(VERIFY_CHALLENGE) => {
            let Some(mut given) = Given::read(VERIFY_CHALLENGE, &VERIFY_CHALLENGE_FLAGS, flags)?
            else {
                return Ok(Command::Help);
            };
            Ok(Command::VerifyChallenge(VerifyChallenge {
                challenge: given.required_path(CHALLENGE)?,
                instance_id: given.required_text(INSTANCE_ID)?,
                epoch: given
                    .integer(EPOCH)?
                    .ok_or_else(|| usage(format!("{EPOCH} is required")))?,
                replacement_identity: given.text(REPLACEMENT_IDENTITY)?,
                trust_anchor: given.text(TRUST_ANCHOR)?,
                new_recovery_key: given.key(NEW_RECOVERY_KEY)?,
                now: given.integer(NOW)?,
            }))
        }
        Some(VERIFY_RESPONSE) => {
            let Some(mut given) = Given::read(VERIFY_RESPONSE, &VERIFY_RESPONSE_FLAGS, flags)?
            else {
                return Ok(Command::Help);
            };
            Ok(Command::VerifyResponse(VerifyResponse {
                challenge: given.required_path(CHALLENGE)?,
                response: given.required_path(RESPONSE)?,
                key: given
                    .key(KEY)?
                    .ok_or_else(|| usage(format!("{KEY} is required")))?,
            }))
        }
        Some(SIGN) => {
            let Some(mut given) = Given::read(SIGN, &SIGN_FLAGS, flags)? else {
                return Ok(Command::Help);
            };
            // Every expectation is required: `sign` signs only a confirmed
            // replacement, and which value is missing is known from the
            // command line alone, before anything is read.
            Ok(Command::Sign(Sign {
                challenge: given.required_path(CHALLENGE)?,
                seed_file: given.required_path(SEED_FILE)?,
                out: given.required_path(OUT)?,
                instance_id: given.required_text(INSTANCE_ID)?,
                epoch: given
                    .integer(EPOCH)?
                    .ok_or_else(|| usage(format!("{EPOCH} is required")))?,
                replacement_identity: given.required_text(REPLACEMENT_IDENTITY)?,
                trust_anchor: given.required_text(TRUST_ANCHOR)?,
                new_recovery_key: given
                    .key(NEW_RECOVERY_KEY)?
                    .ok_or_else(|| usage(format!("{NEW_RECOVERY_KEY} is required")))?,
                now: given.integer(NOW)?,
            }))
        }
        Some(BOOTSTRAP) => {
            let Some(mut given) = Given::read(BOOTSTRAP, &BOOTSTRAP_FLAGS, flags)? else {
                return Ok(Command::Help);
            };
            Ok(Command::Bootstrap(Bootstrap {
                socket: given.socket_flags()?,
                instance_id: given.required_text(INSTANCE_ID)?,
                credential_spki: given.required_path(CREDENTIAL_SPKI)?,
                trust_anchor: given.required_text(TRUST_ANCHOR)?,
                recovery_key: given
                    .key(RECOVERY_KEY)?
                    .ok_or_else(|| usage(format!("{RECOVERY_KEY} is required")))?,
            }))
        }
        Some(ISSUE_CHALLENGE) => {
            let Some(mut given) = Given::read(ISSUE_CHALLENGE, &ISSUE_CHALLENGE_FLAGS, flags)?
            else {
                return Ok(Command::Help);
            };
            Ok(Command::IssueChallenge(IssueChallenge {
                socket: given.socket_flags()?,
                credential_spki: given.required_path(CREDENTIAL_SPKI)?,
                trust_anchor: given.required_text(TRUST_ANCHOR)?,
                new_recovery_key: given
                    .key(NEW_RECOVERY_KEY)?
                    .ok_or_else(|| usage(format!("{NEW_RECOVERY_KEY} is required")))?,
                out: given.required_path(OUT)?,
            }))
        }
        Some(PREVIEW) => {
            let Some(mut given) = Given::read(PREVIEW, &RESPONSE_FLAGS, flags)? else {
                return Ok(Command::Help);
            };
            Ok(Command::Preview(Preview {
                socket: given.socket_flags()?,
                response: given.required_path(RESPONSE)?,
            }))
        }
        Some(RESTORE) => {
            let Some(mut given) = Given::read(RESTORE, &RESPONSE_FLAGS, flags)? else {
                return Ok(Command::Help);
            };
            Ok(Command::Restore(Restore {
                socket: given.socket_flags()?,
                response: given.required_path(RESPONSE)?,
            }))
        }
        Some(STATUS) => {
            let Some(mut given) = Given::read(STATUS, &STATUS_FLAGS, flags)? else {
                return Ok(Command::Help);
            };
            let socket = given.socket_flags()?;
            let query = status_query(&mut given)?;
            Ok(Command::Status(Status { socket, query }))
        }
        _ => Err(usage("unknown command (argument 1)")),
    }
}

/// What `status` asks, from its flags but the socket's: a selector
/// (`--challenge` or `--response`, at most one), a key, or a reconcile
/// with exactly the flags it takes.
fn status_query(given: &mut Given) -> Result<StatusQuery, Failure> {
    let reconcile = given.text(RECONCILE)?;
    let challenge = given.take(CHALLENGE).map(PathBuf::from);
    let response = given.take(RESPONSE).map(PathBuf::from);
    let operation = match (challenge, response) {
        (Some(_), Some(_)) => {
            return Err(usage(format!(
                "{CHALLENGE} and {RESPONSE} cannot both be given"
            )));
        }
        (Some(path), None) => Some(OperationArtifact::Challenge(path)),
        (None, Some(path)) => Some(OperationArtifact::Response(path)),
        (None, None) => None,
    };
    match reconcile.as_deref() {
        None => {
            given.refuse(&[INSTANCE_ID, TRUST_ANCHOR, RECOVERY_KEY], |flag| {
                format!("{flag} is only for {RECONCILE} bootstrap")
            })?;
            Ok(StatusQuery::Read {
                operation,
                credential_spki: given.take(CREDENTIAL_SPKI).map(PathBuf::from),
            })
        }
        Some("restore") => {
            given.refuse(&[CREDENTIAL_SPKI], |flag| {
                format!("{flag} is not for {RECONCILE} restore")
            })?;
            given.refuse(&[INSTANCE_ID, TRUST_ANCHOR, RECOVERY_KEY], |flag| {
                format!("{flag} is only for {RECONCILE} bootstrap")
            })?;
            let operation = operation.ok_or_else(|| {
                usage(format!(
                    "{RECONCILE} restore needs {CHALLENGE} or {RESPONSE}"
                ))
            })?;
            Ok(StatusQuery::ReconcileRestore(operation))
        }
        Some("bootstrap") => {
            if operation.is_some() {
                return Err(usage(format!(
                    "{CHALLENGE} and {RESPONSE} are not for {RECONCILE} bootstrap"
                )));
            }
            Ok(StatusQuery::ReconcileBootstrap {
                instance_id: given.required_text(INSTANCE_ID)?,
                credential_spki: given.required_path(CREDENTIAL_SPKI)?,
                trust_anchor: given.required_text(TRUST_ANCHOR)?,
                recovery_key: given
                    .key(RECOVERY_KEY)?
                    .ok_or_else(|| usage(format!("{RECOVERY_KEY} is required")))?,
            })
        }
        Some(_) => Err(usage(format!("{RECONCILE} is not restore or bootstrap"))),
    }
}

/// The flags given to a command, by name, each once.
struct Given {
    values: Vec<(&'static str, OsString)>,
}

impl Given {
    /// Reads `arguments` as pairs of a flag of `allowed` and its value.
    /// `None` when `--help` or `-h` comes where a flag is expected (never
    /// as a value: `--challenge -h` names a file `-h`).
    fn read(
        command: &str,
        allowed: &[&'static str],
        arguments: &[OsString],
    ) -> Result<Option<Self>, Failure> {
        let mut values: Vec<(&'static str, OsString)> = Vec::new();
        let mut rest = arguments.iter().enumerate();
        while let Some((index, argument)) = rest.next() {
            // Positions count from 1 at the command.
            let position = index + 2;
            if is_help(argument) {
                return Ok(None);
            }
            let Some(flag) = allowed.iter().copied().find(|flag| argument == *flag) else {
                return Err(usage(match argument.to_str() {
                    Some(text) if text.starts_with("--") && is_flag_shaped(text) => {
                        format!("{command} has no flag {text}")
                    }
                    _ => format!("argument {position} is not a flag of {command}"),
                }));
            };
            if values.iter().any(|(given, _)| *given == flag) {
                return Err(usage(format!("{flag} is given more than once")));
            }
            let value = match rest.next() {
                None => return Err(usage(format!("{flag} needs a value"))),
                Some((_, value)) if value.is_empty() => {
                    return Err(usage(format!("{flag} has an empty value")));
                }
                // The argument's own bytes (the platform's encoding, of
                // which ASCII is a subset), before any conversion to
                // UTF-8: a value that is not UTF-8 is refused too.
                Some((_, value)) if value.as_encoded_bytes().starts_with(b"--") => {
                    return Err(usage(format!("{flag} needs a value")));
                }
                Some((_, value)) => value.clone(),
            };
            values.push((flag, value));
        }
        Ok(Some(Self { values }))
    }

    /// The value of `flag`, taken out, if given.
    fn take(&mut self, flag: &str) -> Option<OsString> {
        let at = self.values.iter().position(|(given, _)| *given == flag)?;
        Some(self.values.swap_remove(at).1)
    }

    fn required_path(&mut self, flag: &str) -> Result<PathBuf, Failure> {
        self.take(flag)
            .map(PathBuf::from)
            .ok_or_else(|| usage(format!("{flag} is required")))
    }

    fn text(&mut self, flag: &str) -> Result<Option<String>, Failure> {
        self.take(flag)
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| usage(format!("{flag} is not UTF-8")))
            })
            .transpose()
    }

    fn required_text(&mut self, flag: &str) -> Result<String, Failure> {
        self.text(flag)?
            .ok_or_else(|| usage(format!("{flag} is required")))
    }

    fn integer(&mut self, flag: &str) -> Result<Option<i64>, Failure> {
        self.text(flag)?
            .map(|text| {
                decimal(&text).ok_or_else(|| {
                    usage(format!(
                        "{flag} is not an integer in its shortest decimal form"
                    ))
                })
            })
            .transpose()
    }

    /// Refuses the first of `flags` that was given, with `message` of it.
    fn refuse(&self, flags: &[&str], message: impl Fn(&str) -> String) -> Result<(), Failure> {
        match flags
            .iter()
            .find(|flag| self.values.iter().any(|(given, _)| given == *flag))
        {
            Some(flag) => Err(usage(message(flag))),
            None => Ok(()),
        }
    }

    /// The socket flags, `--socket` and `--service-uid` required.
    fn socket_flags(&mut self) -> Result<SocketFlags, Failure> {
        let socket = self.required_path(SOCKET)?;
        let service_uid = self
            .text(SERVICE_UID)?
            .ok_or_else(|| usage(format!("{SERVICE_UID} is required")))?;
        let service_uid = decimal(&service_uid)
            .and_then(|uid| u32::try_from(uid).ok())
            .ok_or_else(|| {
                usage(format!(
                    "{SERVICE_UID} is not a UID: an integer from 0 to 4294967295 in its shortest \
                     decimal form"
                ))
            })?;
        let trust_ancestors = match self.text(TRUST_ANCESTORS)?.as_deref() {
            None | Some("service-or-root") => TrustAncestors::ServiceOrRoot,
            Some("root-only") => TrustAncestors::RootOnly,
            Some(_) => {
                return Err(usage(format!(
                    "{TRUST_ANCESTORS} is not service-or-root or root-only"
                )));
            }
        };
        Ok(SocketFlags {
            socket,
            service_uid,
            trust_ancestors,
            total_wait: self.seconds(TOTAL_WAIT, DEFAULT_TOTAL_WAIT_SECONDS)?,
            idle_wait: self.seconds(IDLE_WAIT, DEFAULT_IDLE_WAIT_SECONDS)?,
        })
    }

    /// A wait of whole seconds over zero, `default` when not given.
    fn seconds(&mut self, flag: &str, default: u64) -> Result<Duration, Failure> {
        let Some(text) = self.text(flag)? else {
            return Ok(Duration::from_secs(default));
        };
        decimal(&text)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs)
            .ok_or_else(|| {
                usage(format!(
                    "{flag} is not a whole number of seconds over zero in its shortest decimal \
                     form"
                ))
            })
    }

    fn key(&mut self, flag: &str) -> Result<Option<RecoveryPublicKey>, Failure> {
        self.text(flag)?
            .map(|text| {
                RecoveryPublicKey::from_hex(&text)
                    .map_err(|err| usage(format!("{flag} is refused: {err}")))
            })
            .transpose()
    }
}

/// Whether `text` looks like a flag name, `--` and lowercase letters,
/// digits and hyphens, short enough to repeat in a message.
fn is_flag_shaped(text: &str) -> bool {
    text.len() <= 40
        && text[2..]
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// A 64-bit integer in its shortest decimal form: an optional minus, then
/// `0` or a nonzero digit and more digits; not `-0`, no plus, no
/// whitespace.
fn decimal(text: &str) -> Option<i64> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let shortest = match digits.as_bytes() {
        [b'0'] => text == "0",
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if shortest { text.parse().ok() } else { None }
}
