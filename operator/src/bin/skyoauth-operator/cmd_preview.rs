//! `preview`: sends the response artifact (`--response`) to the service's
//! deployment-local socket and prints what its restore would enroll. It
//! changes nothing on the service (`Retry::Safe`), so a reply that cannot be
//! believed is exit 6, never 5.
//!
//! In this order: the response artifact is read and checked (exit 3 for
//! the file, exit 1 for its bytes, and a signature that is not 64 bytes is
//! refused, `refused (Length)`), and only then is the socket's path checked
//! and the one request sent. The signature is never printed.

use std::fmt::Write as _;

use skyoauth_operator::{
    local::{Op, ResponseRequest},
    recovery::VerifyError,
};

use crate::{
    Failure, Outcome, args::Preview, artifact, cmd_verify_response::MAX_RESPONSE_BYTES, input,
    online, show::quoted,
};

pub fn run(flags: &Preview) -> Outcome {
    match preview(flags) {
        Ok(output) => Outcome {
            output,
            result: Ok(()),
        },
        Err(failure) => failure.into(),
    }
}

fn preview(flags: &Preview) -> Result<String, Failure> {
    let bytes = input::read_file("--response", &flags.response, MAX_RESPONSE_BYTES)?;
    let response = artifact::response(&bytes)?;
    // Refused here, before any connection: never padded or cut to 64.
    let signature = <[u8; 64]>::try_from(response.signature.as_slice())
        .map_err(|_| Failure::Refused(format!("refused (Length): {}", VerifyError::Length)))?;
    let request = ResponseRequest {
        operation_id: response.operation_id,
        signature,
    };
    let previewed = online::client(&flags.socket)
        .preview(&request)
        .map_err(|err| online::failure(Op::Preview, err))?;
    let mut output = String::new();
    // Writing to a `String` cannot fail.
    let _ = write!(
        output,
        "admin_id: {}\n\
         credential_id: {}\n\
         binding_id: {}\n\
         new_recovery_key_epoch: {}\n\
         expires_at: {}\n\
         result: ok; the service previewed the restore of this response; nothing was written\n",
        quoted(&previewed.admin_id),
        quoted(&previewed.credential_id),
        quoted(&previewed.binding_id),
        previewed.new_recovery_key_epoch,
        previewed.expires_at,
    );
    Ok(output)
}
