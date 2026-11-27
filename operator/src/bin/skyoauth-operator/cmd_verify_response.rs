//! `verify-response`: checks a response artifact's signature over a
//! challenge with a recovery public key, as the service's restore does.
//! Neither the signature nor any part of it is printed, whatever the
//! result.

use skyoauth_operator::{
    local::{MAX_REPLY_BYTES, MAX_REQUEST_BYTES},
    recovery::verify_response,
};

use crate::{Failure, Outcome, args::VerifyResponse, artifact, input, show::quoted};

/// The largest response artifact: a response is sent as a `restore`
/// request, whose line is at most [`MAX_REQUEST_BYTES`] and holds more than
/// the artifact.
const MAX_RESPONSE_BYTES: usize = MAX_REQUEST_BYTES;

pub fn run(flags: &VerifyResponse) -> Outcome {
    match check(flags) {
        Ok(output) => Outcome {
            output,
            result: Ok(()),
        },
        Err(failure) => failure.into(),
    }
}

fn check(flags: &VerifyResponse) -> Result<String, Failure> {
    let challenge_bytes = input::read_file("--challenge", &flags.challenge, MAX_REPLY_BYTES)?;
    let response_bytes = input::read_file("--response", &flags.response, MAX_RESPONSE_BYTES)?;
    let challenge = artifact::challenge(&challenge_bytes)?;
    let response = artifact::response(&response_bytes)?;
    if response.operation_id != challenge.operation_id() {
        return Err(Failure::Refused(
            "refused (OtherOperation): the response is for another operation than the challenge"
                .to_owned(),
        ));
    }
    verify_response(&flags.key, &challenge, &response.signature)
        .map_err(|err| Failure::Refused(format!("refused ({err:?}): {err}")))?;
    Ok(format!(
        "operation_id: {}\n\
         result: ok; the signature verifies with the given recovery public key over the \
         challenge (verify_strict)\n",
        quoted(challenge.operation_id())
    ))
}
