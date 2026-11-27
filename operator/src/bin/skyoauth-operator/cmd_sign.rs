//! `sign`: checks a challenge artifact as `verify-challenge` does, with
//! every expectation required, then signs it with the seed file's key
//! ([`sign_challenge`] with a [`SoftwareSigner`]) and writes the response
//! artifact to `--out` or standard output.
//!
//! In this order: the challenge artifact is read, then the clock, and the
//! challenge is checked; only a challenge that passed is followed by the
//! seed file, the signer and [`sign_challenge`] (which refuses an
//! unconfirmed replacement and a new recovery key that is the signer's
//! own); the response is written last. So nothing is written, and the seed
//! is not read, for a challenge that is refused; and nothing is written but
//! the whole response. The signature is never printed but as the artifact
//! on standard output, without `--out`, after every check passed.

use std::fmt::Write as _;

use skyoauth_operator::{
    local::{MAX_REPLY_BYTES, Op, Request, ResponseRequest},
    recovery::{Expectations, SignedResponse, SoftwareSigner, check_challenge, sign_challenge},
};

use crate::{
    Failure, Outcome, args::Sign, artifact, cmd_verify_challenge::clock, input, out_file,
    seed_file, show::quoted,
};

pub fn run(flags: &Sign) -> Outcome {
    match sign(flags) {
        Ok(output) => Outcome {
            output,
            result: Ok(()),
        },
        Err(failure) => failure.into(),
    }
}

fn sign(flags: &Sign) -> Result<String, Failure> {
    let bytes = input::read_file("--challenge", &flags.challenge, MAX_REPLY_BYTES)?;
    let challenge = artifact::challenge(&bytes)?;
    // The clock is read last, just before the check.
    let clock = clock(flags.now)?;
    let expectations = Expectations {
        instance_id: &flags.instance_id,
        now_micros: clock.now_micros,
        recovery_key_epoch: Some(flags.epoch),
        replacement_public_identity: Some(&flags.replacement_identity),
        trust_anchor_ref: Some(&flags.trust_anchor),
        new_recovery_public_key: Some(&flags.new_recovery_key),
    };
    let verified = check_challenge(&challenge, &expectations)
        .map_err(|refusal| Failure::Refused(format!("refused ({refusal:?}): {refusal}")))?;
    // The signer lives in this block only: it is not wiped, but not kept
    // either.
    let signed = {
        let signer =
            SoftwareSigner::from_seed(seed_file::read(&flags.seed_file)?).map_err(|err| {
                Failure::Refused(format!(
                    "--seed-file: the seed's public key is refused ({err:?}): {err}"
                ))
            })?;
        sign_challenge(&verified, &signer)
            .map_err(|err| Failure::Refused(format!("refused ({err:?}): {err}")))?
    };
    let response = response_artifact(&signed)?;
    let Some(out) = &flags.out else {
        return Ok(response);
    };
    out_file::write_new(out, response.as_bytes())?;
    let mut output = String::new();
    // Writing to a `String` cannot fail.
    let _ = write!(
        output,
        "clock: {} {}\n\
         operation_id: {}\n\
         replacement_confirmed: yes\n\
         result: ok; the challenge is signed, the response artifact is written to --out\n",
        clock.source,
        clock.now_micros,
        quoted(signed.operation_id()),
    );
    Ok(output)
}

/// The response artifact of `signed`: the `restore` request line of the
/// transport's codec without its `op` member, so the operation ID is
/// escaped and the signature written exactly as a `restore` request
/// carries them.
fn response_artifact(signed: &SignedResponse) -> Result<String, Failure> {
    let cannot =
        || Failure::Refused("the response cannot be written as a restore request".to_owned());
    let line = Request::Restore(ResponseRequest {
        operation_id: signed.operation_id().to_owned(),
        signature: *signed.signature(),
    })
    .encode()
    .map_err(|_| cannot())?;
    let op_member = format!("{{\"op\":\"{}\",", Op::Restore.as_str());
    let line = std::str::from_utf8(line.as_bytes()).map_err(|_| cannot())?;
    let members = line.strip_prefix(&op_member).ok_or_else(cannot)?;
    Ok(format!("{{{members}"))
}
