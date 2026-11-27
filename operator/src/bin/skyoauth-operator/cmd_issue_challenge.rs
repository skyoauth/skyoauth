//! `issue-challenge`: asks the service's deployment-local socket, once, for
//! a recovery challenge for a replacement operator, and writes the reply
//! line, exactly as the service sent it, to a new file, `--out`: the
//! challenge artifact (`docs/proposals/operator-cli-online.md`,
//! "`issue-challenge`"; the user's ruling: the reply, verbatim).
//!
//! In this order: the key file (`--credential-spki`) is read (exit 3) and
//! the request encoded (exit 1 when it is over 64 KiB); then `--out` is
//! created new (exit 3 when it exists or cannot be created, with nothing
//! sent); only then is the socket's path checked and the one request sent.
//! The reply line is written to `--out` only once the library has parsed
//! it as an issue's reply and checked its challenge
//! ([`LocalClient::issue_challenge_verbatim`]), and synchronized; then the
//! summary is printed, with the replacement's public identity derived from
//! the key file (the service stays its authority: `verify-challenge`
//! checks the challenge's against it).
//!
//! On any other outcome nothing is written to `--out`, which is left empty,
//! and the message says so: the binary removes no file by path. An issue of
//! unknown outcome (exit 5) cannot be reconciled: issue again (lead ruling
//! Q5).
//!
//! [`LocalClient::issue_challenge_verbatim`]: skyoauth_operator::local::LocalClient::issue_challenge_verbatim

use std::fmt::Write as _;

use skyoauth_operator::{
    identity::public_identity_of_spki,
    local::{CallError, ErrorCode, IssueChallengeRequest, Op, Request},
};

use crate::{Failure, Outcome, args::IssueChallenge, online, out_file, show::quoted};

/// What to do after an issue whose outcome is unknown.
const REISSUE: &str =
    "no reconcile is possible: issue again; the first challenge, if it was issued, expires unused";

/// What a `conflict` adds to its message (lead ruling (c)): the conflict
/// may come from a restore, already committed, of an earlier challenge for
/// the same replacement key.
const AFTER_A_RETRY: &str = "if a restore of an earlier challenge for this replacement key may \
                             have committed, run status --reconcile restore on the original \
                             response";

/// The last line of the message of every failure once `--out` was created.
const LEFT_EMPTY: &str = "--out was created and is left empty: remove it";

pub fn run(flags: &IssueChallenge) -> Outcome {
    match issue(flags) {
        Ok(output) => Outcome {
            output,
            result: Ok(()),
        },
        Err(failure) => failure.into(),
    }
}

fn issue(flags: &IssueChallenge) -> Result<String, Failure> {
    let credential_spki = online::credential_spki(&flags.credential_spki)?;
    let replacement_identity = public_identity_of_spki(&credential_spki)
        .map_err(|err| Failure::Io(format!("--credential-spki: {err}")))?;
    let request = IssueChallengeRequest {
        credential_spki,
        trust_anchor_ref: flags.trust_anchor.clone(),
        new_recovery_public_key: flags.new_recovery_key,
    };
    // A request too large to send is refused before `--out` is created.
    Request::IssueChallenge(request.clone())
        .encode()
        .map_err(|why| online::failure(Op::IssueChallenge, CallError::NotSent(why)))?;
    let mut out = out_file::create_new(&flags.out)?;
    let issued = online::client(&flags.socket)
        .issue_challenge_verbatim(&request)
        .map_err(|err| {
            let conflict = err == CallError::Refused(ErrorCode::Conflict);
            let failure = online::write_failure(Op::IssueChallenge, err, REISSUE);
            let failure = if conflict {
                online::after_a_retry(failure, AFTER_A_RETRY)
            } else {
                failure
            };
            failure.with_line(LEFT_EMPTY)
        })?;
    out_file::write(&mut out, &issued.line).map_err(|kind| {
        Failure::Io(format!(
            "--out: the file cannot be written ({kind})\nthe challenge was issued, but --out \
             cannot be written: issue again; --out may hold part of the challenge: remove it"
        ))
    })?;
    let mut output = String::new();
    // Writing to a `String` cannot fail.
    let _ = write!(
        output,
        "operation_id: {}\n\
         expires_at: {}\n\
         expected_revision: {}\n\
         replacement_identity: {}\n\
         result: ok; the challenge was issued and written to --out; check it on the \
         workstation with verify-challenge\n",
        quoted(issued.challenge.operation_id()),
        issued.challenge.expires_at_micros(),
        issued.challenge.expected_revision(),
        quoted(&replacement_identity),
    );
    Ok(output)
}
