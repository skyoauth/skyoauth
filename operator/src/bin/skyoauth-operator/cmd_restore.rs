//! `restore`: sends the response artifact (`--response`) to the service's
//! deployment-local socket, once, and prints the replacement the restore
//! enrolled and the credential IDs it revoked
//! (`docs/proposals/operator-cli-online.md`, "`preview` and `restore`").
//!
//! In this order: the response artifact is read and checked (exit 3 for
//! the file, exit 1 for its bytes, and a signature that is not 64 bytes is
//! refused, `refused (Length)`, never padded or cut), and only then is the
//! socket's path checked and the one request sent. The signature is never
//! printed.
//!
//! One request only: the reply lists at most 1000 revoked IDs with their
//! count, and `revoked_credential_ids_complete: yes|no` says whether the
//! list is all of them (exactly when its length equals the count); when it
//! is not, the result line names the command that lists every one
//! (`status --response`), which is not run here. A restore whose outcome
//! is unknown is exit 5, with the command that reconciles it; it is never
//! repeated here. A `not_restorable` may hide an earlier restore of the
//! same challenge that committed, so its message says how to find out
//! (lead ruling (c)).

use std::fmt::Write as _;

use skyoauth_operator::{
    local::{CallError, ErrorCode, Op, ResponseRequest},
    recovery::VerifyError,
};

use crate::{
    Failure, Outcome, args::Restore, artifact, cmd_verify_response::MAX_RESPONSE_BYTES, input,
    online, show::quoted,
};

/// What to run after a restore whose outcome is unknown.
const RECONCILE: &str = "run skyoauth-operator status --reconcile restore --response FILE with \
                         the same socket flags";

/// What a `not_restorable` adds to its message (lead ruling (c)).
const AFTER_A_RETRY: &str = "if an earlier restore of this challenge may have committed, run \
                             status --reconcile restore on the original response";

pub fn run(flags: &Restore) -> Outcome {
    match restore(flags) {
        Ok(output) => Outcome {
            output,
            result: Ok(()),
        },
        Err(failure) => failure.into(),
    }
}

fn restore(flags: &Restore) -> Result<String, Failure> {
    let bytes = input::read_file("--response", &flags.response, MAX_RESPONSE_BYTES)?;
    let response = artifact::response(&bytes)?;
    // Refused here, before any connection: never padded or cut to 64.
    let signature = <[u8; 64]>::try_from(response.signature.as_slice())
        .map_err(|_| Failure::Refused(format!("refused (Length): {}", VerifyError::Length)))?;
    let request = ResponseRequest {
        operation_id: response.operation_id,
        signature,
    };
    let restored = online::client(&flags.socket)
        .restore(&request)
        .map_err(|err| {
            let not_restorable = err == CallError::Refused(ErrorCode::NotRestorable);
            let failure = online::write_failure(Op::Restore, err, RECONCILE);
            if not_restorable {
                online::after_a_retry(failure, AFTER_A_RETRY)
            } else {
                failure
            }
        })?;
    let listed = restored.revoked_credential_ids.len();
    let complete =
        i64::try_from(listed).is_ok_and(|listed| listed == restored.revoked_credential_count);
    let mut output = String::new();
    // Writing to a `String` cannot fail.
    let _ = write!(
        output,
        "admin_id: {}\n\
         credential_id: {}\n\
         binding_id: {}\n\
         revoked_credential_count: {}\n\
         revoked_credential_ids: {listed}\n",
        quoted(&restored.admin_id),
        quoted(&restored.credential_id),
        quoted(&restored.binding_id),
        restored.revoked_credential_count,
    );
    for id in &restored.revoked_credential_ids {
        let _ = writeln!(output, "revoked_credential_id: {}", quoted(id));
    }
    let _ = write!(
        output,
        "revoked_credential_ids_complete: {}\n\
         recovery_key_epoch: {}\n\
         recovery_state_revision: {}\n\
         result: ok; the restore committed; do not repeat it{}\n",
        if complete { "yes" } else { "no" },
        restored.recovery_key_epoch,
        restored.recovery_state_revision,
        if complete {
            ""
        } else {
            "; not every revoked ID is listed: skyoauth-operator status --response FILE with \
             the same socket flags lists every one"
        },
    );
    Ok(output)
}
