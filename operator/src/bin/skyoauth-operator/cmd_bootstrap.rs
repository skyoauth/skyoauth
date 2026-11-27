//! `bootstrap`: sends the first operator and the recovery key of a new
//! instance to the service's deployment-local socket, once, and prints
//! what the service wrote (`docs/proposals/operator-cli-online.md`,
//! "`bootstrap`").
//!
//! In this order: the key file (`--credential-spki`) is read (exit 3), and
//! only then is the socket's path checked and the one request sent. The
//! instance ID is the one given: no randomness or clock here, so a rerun
//! with the same flags is the same request, which `status --reconcile
//! bootstrap` compares. A bootstrap whose outcome is unknown is exit 5,
//! with the command that reconciles it; it is never repeated here. A
//! `conflict` may hide an earlier bootstrap that committed, so its message
//! says how to find out.

use std::fmt::Write as _;

use skyoauth_operator::local::{BootstrapRequest, CallError, ErrorCode, Op};

use crate::{Failure, Outcome, args::Bootstrap, online, show::quoted};

/// What to run after a bootstrap whose outcome is unknown.
const RECONCILE: &str = "run skyoauth-operator status --reconcile bootstrap with the same flags";

/// What a `conflict` adds to its message.
const AFTER_A_RETRY: &str = "if an earlier bootstrap may have committed, run status \
                             --reconcile bootstrap with the same flags";

pub fn run(flags: &Bootstrap) -> Outcome {
    match bootstrap(flags) {
        Ok(output) => Outcome {
            output,
            result: Ok(()),
        },
        Err(failure) => failure.into(),
    }
}

fn bootstrap(flags: &Bootstrap) -> Result<String, Failure> {
    let request = BootstrapRequest {
        instance_id: flags.instance_id.clone(),
        credential_spki: online::credential_spki(&flags.credential_spki)?,
        trust_anchor_ref: flags.trust_anchor.clone(),
        recovery_public_key: flags.recovery_key,
    };
    let bootstrapped = online::client(&flags.socket)
        .bootstrap(&request)
        .map_err(|err| {
            let conflict = err == CallError::Refused(ErrorCode::Conflict);
            let failure = online::write_failure(Op::Bootstrap, err, RECONCILE);
            if conflict {
                online::after_a_retry(failure, AFTER_A_RETRY)
            } else {
                failure
            }
        })?;
    let mut output = String::new();
    // Writing to a `String` cannot fail.
    let _ = write!(
        output,
        "instance_id: {}\n\
         admin_id: {}\n\
         credential_id: {}\n\
         binding_id: {}\n\
         recovery_key_epoch: {}\n\
         result: ok; the bootstrap committed; keep this output: verify-challenge needs the \
         instance ID and the epoch\n",
        quoted(&bootstrapped.instance_id),
        quoted(&bootstrapped.admin_id),
        quoted(&bootstrapped.credential_id),
        quoted(&bootstrapped.binding_id),
        bootstrapped.recovery_key_epoch,
    );
    Ok(output)
}
