//! `status`: one read of the service's state over its deployment-local
//! socket (`Retry::Safe`: it changes no row), plus, for a restored
//! operation, the walk over every credential ID its restore revoked
//! (`LocalClient::revoked_credential_ids` from `status` alone, page by
//! page). With `--reconcile restore` or `--reconcile bootstrap` it also
//! prints the verdict of the reconcile procedure (`RestoreVerdict::of`,
//! `BootstrapVerdict::of`) and the next step, and exits 0 whatever the
//! verdict (lead ruling Q3).
//!
//! The output: every member of the reply in its order, one `name: value`
//! per line (`null` where the service wrote `null`; strings quoted, byte
//! values in lowercase hexadecimal, states as their wire values), the list
//! of revoked IDs as `revoked_credential_ids: N` and then N lines
//! `revoked_credential_id: "…"`, then `verdict:` and `next:` for a
//! reconcile, then `result:`. A call or a walk that does not succeed
//! prints nothing on standard output.
//!
//! The files are read and checked first (exit 3 for a file, exit 1 for an
//! artifact's bytes); only then is the socket's path checked and the first
//! request sent.

use std::fmt::Write as _;

use skyoauth_operator::local::{
    BootstrapRequest, BootstrapVerdict, Op, OperationState, RestoreVerdict, Status, StatusRequest,
};

use crate::{
    Failure, Outcome,
    args::{self, StatusQuery},
    online::{self, hex_or_null, integer_or_null, text_or_null},
    show::quoted,
};

/// Which reconcile the command prints the verdict of.
enum Reconcile {
    Restore,
    Bootstrap(BootstrapRequest),
}

pub fn run(flags: &args::Status) -> Outcome {
    match status(flags) {
        Ok(output) => Outcome {
            output,
            result: Ok(()),
        },
        Err(failure) => failure.into(),
    }
}

fn status(flags: &args::Status) -> Result<String, Failure> {
    let (request, reconcile) = match &flags.query {
        StatusQuery::Read {
            operation,
            credential_spki,
        } => {
            let operation_id = operation.as_ref().map(online::operation_id).transpose()?;
            let credential_spki = credential_spki
                .as_deref()
                .map(online::credential_spki)
                .transpose()?;
            let request = StatusRequest {
                operation_id,
                credential_spki,
                revoked_after: None,
            };
            (request, None)
        }
        // `StatusRequest::reconciling_restore`'s request, the operation ID
        // alone: that function takes the whole signed response, and a
        // `status` never sends a signature, so a challenge artifact names
        // the operation as well as a response artifact.
        StatusQuery::ReconcileRestore(operation) => {
            let request = StatusRequest {
                operation_id: Some(online::operation_id(operation)?),
                credential_spki: None,
                revoked_after: None,
            };
            (request, Some(Reconcile::Restore))
        }
        StatusQuery::ReconcileBootstrap {
            instance_id,
            credential_spki,
            trust_anchor,
            recovery_key,
        } => {
            let bootstrap = BootstrapRequest {
                instance_id: instance_id.clone(),
                credential_spki: online::credential_spki(credential_spki)?,
                trust_anchor_ref: trust_anchor.clone(),
                recovery_public_key: *recovery_key,
            };
            let request = StatusRequest::reconciling_bootstrap(&bootstrap);
            (request, Some(Reconcile::Bootstrap(bootstrap)))
        }
    };
    let failed = |err| online::failure(Op::Status, err);
    let client = online::client(&flags.socket);
    let reply = client.status(&request).map_err(failed)?;
    // Every revoked ID of a restored operation, walked from `status` alone.
    let walked = match (&request.operation_id, reply.operation_state) {
        (Some(operation_id), Some(OperationState::Restored)) => Some(
            client
                .revoked_credential_ids(operation_id, None)
                .map_err(failed)?,
        ),
        _ => None,
    };
    let mut output = members(&reply, walked.as_deref());
    let verdict = match &reconcile {
        None => None,
        Some(Reconcile::Restore) => Some(restore_verdict(RestoreVerdict::of(&reply))),
        Some(Reconcile::Bootstrap(bootstrap)) => {
            Some(bootstrap_verdict(BootstrapVerdict::of(bootstrap, &reply)))
        }
    };
    if let Some((verdict, next)) = verdict {
        // Writing to a `String` cannot fail.
        let _ = write!(output, "verdict: {verdict}\nnext: {next}\n");
    }
    output.push_str("result: ok; the service answered; status changes nothing\n");
    Ok(output)
}

/// The `verdict:` and `next:` of a restore reconcile
/// (`docs/proposals/operator-cli-online.md`, "Unknown outcomes and
/// reconciling").
fn restore_verdict(verdict: RestoreVerdict) -> (&'static str, &'static str) {
    match verdict {
        RestoreVerdict::Committed => (
            "committed",
            "the replacement's IDs and every revoked ID are listed; do not repeat",
        ),
        RestoreVerdict::NeverCommits => ("never_commits", "issue a new challenge"),
        RestoreVerdict::RepeatRestore => (
            "repeat_restore",
            "run the same restore; it restores or is not_restorable; then reconcile again",
        ),
        RestoreVerdict::AskAgainAfter(_) => (
            "ask_again_after",
            "run status again after settles_at (printed with server_time); the CLI does not \
             wait",
        ),
        RestoreVerdict::Expired => ("expired", "issue a new challenge; not final"),
        RestoreVerdict::Unknown => ("unknown", "do not proceed"),
    }
}

/// The `verdict:` and `next:` of a bootstrap reconcile.
fn bootstrap_verdict(verdict: BootstrapVerdict) -> (&'static str, &'static str) {
    match verdict {
        BootstrapVerdict::Matches { enabled: true } => (
            "matches (enabled: yes)",
            "do not repeat; the credential is usable only when enabled",
        ),
        BootstrapVerdict::Matches { enabled: false } => (
            "matches (enabled: no)",
            "do not repeat; the credential is usable only when enabled",
        ),
        BootstrapVerdict::RepeatBootstrap => ("repeat_bootstrap", "run the same bootstrap"),
        BootstrapVerdict::DoesNotMatch => (
            "does_not_match",
            "do not claim the bootstrap committed; stop",
        ),
    }
}

/// Every member of `status`, in the reply's order. The revoked IDs are
/// `walked` when given (every ID of a restored operation), else the
/// reply's own page.
fn members(status: &Status, walked: Option<&[String]>) -> String {
    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = write!(
        out,
        "server_time: {}\n\
         instance_id: {}\n\
         recovery_key_epoch: {}\n\
         recovery_state_revision: {}\n\
         recovery_public_key: {}\n\
         operation_state: {}\n\
         expires_at: {}\n\
         settles_at: {}\n\
         restored_at: {}\n\
         admin_id: {}\n\
         credential_id: {}\n\
         binding_id: {}\n\
         revoked_credential_count: {}\n",
        status.server_time,
        text_or_null(status.instance_id.as_deref()),
        integer_or_null(status.recovery_key_epoch),
        integer_or_null(status.recovery_state_revision),
        hex_or_null(status.recovery_public_key.as_deref()),
        status
            .operation_state
            .map_or("null", |state| state.as_str()),
        integer_or_null(status.expires_at),
        integer_or_null(status.settles_at),
        integer_or_null(status.restored_at),
        text_or_null(status.admin_id.as_deref()),
        text_or_null(status.credential_id.as_deref()),
        text_or_null(status.binding_id.as_deref()),
        integer_or_null(status.revoked_credential_count),
    );
    match walked.or(status.revoked_credential_ids.as_deref()) {
        None => out.push_str("revoked_credential_ids: null\n"),
        Some(ids) => {
            let _ = writeln!(out, "revoked_credential_ids: {}", ids.len());
            for id in ids {
                let _ = writeln!(out, "revoked_credential_id: {}", quoted(id));
            }
        }
    }
    let _ = write!(
        out,
        "enrolled_state: {}\n\
         enrolled_admin_id: {}\n\
         enrolled_credential_id: {}\n\
         enrolled_trust_anchor_sha256: {}\n",
        status.enrolled_state.map_or("null", |state| state.as_str()),
        text_or_null(status.enrolled_admin_id.as_deref()),
        text_or_null(status.enrolled_credential_id.as_deref()),
        hex_or_null(status.enrolled_trust_anchor_sha256.as_deref()),
    );
    out
}
