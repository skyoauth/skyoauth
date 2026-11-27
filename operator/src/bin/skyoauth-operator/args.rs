//! The command line, parsed by hand: a command, then its flags, each flag
//! followed by its value as the next argument (`--flag VALUE`). A flag is
//! given at most once, every required flag must be given, and a value may
//! not be empty or begin with `--`. No flag takes a private key, and
//! nothing is read from the environment or a configuration file.
//!
//! A refused argument is named by its flag, or by its position when it is
//! not a flag: no message repeats a value given on the command line.

use std::{ffi::OsString, path::PathBuf};

use skyoauth_operator::recovery::RecoveryPublicKey;

use crate::Failure;

/// The text of `--help`.
pub const HELP: &str = "\
skyoauth-operator: offline checks of a recovery challenge and its signed response

Usage:
  skyoauth-operator verify-challenge --challenge FILE --instance-id ID
      [--epoch N] [--replacement-identity ID] [--trust-anchor REF]
      [--new-recovery-key HEX] [--now MICROS]
  skyoauth-operator verify-response --challenge FILE --response FILE --key HEX
  skyoauth-operator --help

verify-challenge reads the challenge artifact (the issue_challenge reply
line, verbatim), checks it against the given values and the clock, and
prints the restoration plan to compare. A signature is allowed only when
--replacement-identity, --trust-anchor and --new-recovery-key are all given
and match (replacement_confirmed: yes).

verify-response checks the response artifact's signature over the
challenge with the recovery public key --key (64 lowercase hex digits).

--now MICROS is the time to check against, in microseconds since the Unix
epoch; without it the system clock is used. The clock used is printed.

Exit codes: 0 every check passed; 1 refused; 2 usage error; 3 a file, the
clock or the output could not be read or written.
";

/// A command and its flags.
pub enum Command {
    /// `--help`, `-h` or `help`, alone or after a command.
    Help,
    /// `verify-challenge`.
    VerifyChallenge(VerifyChallenge),
    /// `verify-response`.
    VerifyResponse(VerifyResponse),
}

/// The flags of `verify-challenge`.
pub struct VerifyChallenge {
    pub challenge: PathBuf,
    pub instance_id: String,
    pub epoch: Option<i64>,
    pub replacement_identity: Option<String>,
    pub trust_anchor: Option<String>,
    pub new_recovery_key: Option<RecoveryPublicKey>,
    pub now: Option<i64>,
}

/// The flags of `verify-response`.
pub struct VerifyResponse {
    pub challenge: PathBuf,
    pub response: PathBuf,
    pub key: RecoveryPublicKey,
}

const VERIFY_CHALLENGE: &str = "verify-challenge";
const VERIFY_RESPONSE: &str = "verify-response";
const SIGN: &str = "sign";

const CHALLENGE: &str = "--challenge";
const INSTANCE_ID: &str = "--instance-id";
const EPOCH: &str = "--epoch";
const REPLACEMENT_IDENTITY: &str = "--replacement-identity";
const TRUST_ANCHOR: &str = "--trust-anchor";
const NEW_RECOVERY_KEY: &str = "--new-recovery-key";
const NOW: &str = "--now";
const RESPONSE: &str = "--response";
const KEY: &str = "--key";

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
const VERIFY_RESPONSE_FLAGS: [&str; 3] = [CHALLENGE, RESPONSE, KEY];

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
        return Ok(Command::Help);
    }
    if flags.iter().any(is_help) {
        return Ok(Command::Help);
    }
    match command.to_str() {
        Some(VERIFY_CHALLENGE) => {
            let mut given = Given::read(VERIFY_CHALLENGE, &VERIFY_CHALLENGE_FLAGS, flags)?;
            Ok(Command::VerifyChallenge(VerifyChallenge {
                challenge: given.required_path(CHALLENGE)?,
                instance_id: given.required_text(INSTANCE_ID)?,
                epoch: given.integer(EPOCH)?,
                replacement_identity: given.text(REPLACEMENT_IDENTITY)?,
                trust_anchor: given.text(TRUST_ANCHOR)?,
                new_recovery_key: given.key(NEW_RECOVERY_KEY)?,
                now: given.integer(NOW)?,
            }))
        }
        Some(VERIFY_RESPONSE) => {
            let mut given = Given::read(VERIFY_RESPONSE, &VERIFY_RESPONSE_FLAGS, flags)?;
            Ok(Command::VerifyResponse(VerifyResponse {
                challenge: given.required_path(CHALLENGE)?,
                response: given.required_path(RESPONSE)?,
                key: given
                    .key(KEY)?
                    .ok_or_else(|| usage(format!("{KEY} is required")))?,
            }))
        }
        Some(SIGN) => Err(usage("the sign command is not implemented yet")),
        _ => Err(usage("unknown command (argument 1)")),
    }
}

/// The flags given to a command, by name, each once.
struct Given {
    values: Vec<(&'static str, OsString)>,
}

impl Given {
    /// Reads `arguments` as pairs of a flag of `allowed` and its value.
    fn read(
        command: &str,
        allowed: &[&'static str],
        arguments: &[OsString],
    ) -> Result<Self, Failure> {
        let mut values: Vec<(&'static str, OsString)> = Vec::new();
        let mut rest = arguments.iter().enumerate();
        while let Some((index, argument)) = rest.next() {
            // Positions count from 1 at the command.
            let position = index + 2;
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
                Some((_, value)) if value.to_str().is_some_and(|v| v.starts_with("--")) => {
                    return Err(usage(format!("{flag} needs a value")));
                }
                Some((_, value)) => value.clone(),
            };
            values.push((flag, value));
        }
        Ok(Self { values })
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
