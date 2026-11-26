//! The four operations: each checks its wire values, generates its IDs,
//! runs one `READ COMMITTED` transaction around one registry call, and
//! commits only on success (see the module docs of
//! [`crate::local_transport`], "Operations" and "Transactions").

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sqlx::{Postgres, Transaction};

use super::{
    Shared,
    connection::refusal,
    error::{
        ErrorCode, from_bootstrap, from_challenge, from_id, from_registry, from_restore,
        from_store_failure,
    },
    wire::{BootstrapWire, IssueWire, Reply, Request, ResponseWire, decode_hex, encode_hex},
};
use crate::identity::canonical_public_identity;
use crate::ids::IdKind;
use crate::persistence::registry::{
    BootstrapRequest, IssueChallenge, JsonObject, OPERATOR_RESTORATION, PLAN_ADMIN_ID,
    PLAN_BINDING_ID, PLAN_CREDENTIAL_ID, PLAN_INSTANCE_ID, PLAN_NEW_RECOVERY_PUBLIC_KEY,
    PLAN_PUBLIC_IDENTITY, PLAN_RECOVERY_KEY_EPOCH, PLAN_TRUST_ANCHOR_REF, RestoreRequest,
    SignedRecoveryResponse, bootstrap_instance, get_recovery_state, is_lowercase_uuid_v7,
    issue_recovery_challenge, preview_recovery_response, recovery_key, restore_operator,
};

/// Every transaction of the transport: `restore_operator` runs only at
/// `READ COMMITTED`, so the level is stated rather than taken from the
/// database's default.
const BEGIN: &str = "BEGIN ISOLATION LEVEL READ COMMITTED";

/// The transaction's `lock_timeout` and `statement_timeout`, both `$1`.
const SET_TIMEOUTS: &str = "SELECT set_config('lock_timeout', $1, true), \
     set_config('statement_timeout', $1, true)";

/// The longest `trust_anchor_ref`, in bytes (`0005`).
const MAX_TRUST_ANCHOR_REF: usize = 2048;

/// Runs `request` (see the module docs, "Operations").
pub(super) async fn execute(shared: &Shared, request: Request) -> Reply {
    let result = match request {
        Request::Bootstrap(wire) => bootstrap(shared, wire).await,
        Request::IssueChallenge(wire) => issue(shared, wire).await,
        Request::Preview(wire) => preview(shared, wire).await,
        Request::Restore(wire) => restore(shared, wire).await,
    };
    result.unwrap_or_else(refusal)
}

/// The canonical public identity of the DER `SubjectPublicKeyInfo` in
/// `hex`, computed here, never taken from the request.
fn credential_identity(hex: &str) -> Result<String, ErrorCode> {
    let der = decode_hex(hex).ok_or(ErrorCode::InvalidRequest)?;
    canonical_public_identity(&der).map_err(|_| ErrorCode::InvalidRequest)
}

/// The `0005` checks of `admin_credential.trust_anchor_ref`: 1 to 2048
/// bytes, no ASCII whitespace or control character. Checked here for the
/// issue too, whose plan the restore stores later, so a challenge is never
/// issued for a replacement the restore could not enroll.
fn check_trust_anchor_ref(value: &str) -> Result<(), ErrorCode> {
    let bounded = (1..=MAX_TRUST_ANCHOR_REF).contains(&value.len());
    if bounded
        && !value
            .bytes()
            .any(|byte| byte == b' ' || byte.is_ascii_control())
    {
        Ok(())
    } else {
        Err(ErrorCode::InvalidRequest)
    }
}

/// A recovery public key in `hex` that passes the registry's checks: 32
/// bytes, a canonically encoded Ed25519 point not of small order.
fn checked_recovery_key(hex: &str) -> Result<Vec<u8>, ErrorCode> {
    let key = decode_hex(hex).ok_or(ErrorCode::InvalidRequest)?;
    recovery_key(&key).map_err(|_| ErrorCode::InvalidRequest)?;
    Ok(key)
}

/// An operation ID the database can bind: no NUL character.
fn check_operation_id(id: &str) -> Result<(), ErrorCode> {
    if id.contains('\0') {
        Err(ErrorCode::InvalidRequest)
    } else {
        Ok(())
    }
}

/// A new ID of `kind`.
fn new_id(shared: &Shared, kind: IdKind) -> Result<String, ErrorCode> {
    shared.ids.new_id(kind).map_err(|err| from_id(&err))
}

/// `time` in whole microseconds since the Unix epoch (negative before it),
/// as the stored times are.
fn micros(time: SystemTime) -> Result<i64, ErrorCode> {
    let micros = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_micros()),
        Err(before) => i64::try_from(before.duration().as_micros()).map(|micros| -micros),
    };
    micros.map_err(|_| ErrorCode::ServerError)
}

/// Begins the request's transaction: `READ COMMITTED`, with the transport's
/// lock and statement timeouts set for this transaction only.
async fn begin(shared: &Shared) -> Result<Transaction<'static, Postgres>, ErrorCode> {
    let store = |err: sqlx::Error| from_store_failure(&err);
    let mut transaction = shared.pool.begin_with(BEGIN).await.map_err(store)?;
    let timeout = format!("{}ms", shared.settings.statement_timeout.as_millis());
    sqlx::query(SET_TIMEOUTS)
        .bind(timeout)
        .execute(&mut *transaction)
        .await
        .map_err(store)?;
    Ok(transaction)
}

/// Commits `transaction` when `result` is `Ok`, else rolls it back: a
/// refusal writes nothing.
async fn finish<T>(
    transaction: Transaction<'static, Postgres>,
    result: Result<T, ErrorCode>,
) -> Result<T, ErrorCode> {
    match result {
        Ok(value) => {
            transaction
                .commit()
                .await
                .map_err(|err| from_store_failure(&err))?;
            Ok(value)
        }
        Err(code) => {
            // A failed rollback leaves nothing either: the connection is
            // closed or the server aborts the transaction.
            let _ = transaction.rollback().await;
            Err(code)
        }
    }
}

/// `bootstrap`: [`bootstrap_instance`].
async fn bootstrap(shared: &Shared, wire: BootstrapWire) -> Result<Reply, ErrorCode> {
    if !is_lowercase_uuid_v7(&wire.instance_id) {
        return Err(ErrorCode::InvalidRequest);
    }
    let public_identity = credential_identity(&wire.credential_spki)?;
    check_trust_anchor_ref(&wire.trust_anchor_ref)?;
    let recovery_public_key = checked_recovery_key(&wire.recovery_public_key)?;
    let admin_id = new_id(shared, IdKind::AdminIdentity)?;
    let credential_id = new_id(shared, IdKind::AdminCredential)?;
    let binding_id = new_id(shared, IdKind::AdminRoleBinding)?;
    let audit_event_id = new_id(shared, IdKind::AuditEvent)?;

    let mut transaction = begin(shared).await?;
    let request = BootstrapRequest {
        instance_id: &wire.instance_id,
        admin_id: &admin_id,
        credential_id: &credential_id,
        public_identity: &public_identity,
        trust_anchor_ref: &wire.trust_anchor_ref,
        binding_id: &binding_id,
        recovery_public_key: &recovery_public_key,
        audit_event_id: &audit_event_id,
        now: shared.clock.now(),
    };
    let result = bootstrap_instance(&mut transaction, &request)
        .await
        .map_err(|err| from_bootstrap(&err));
    let outcome = finish(transaction, result).await?;
    Ok(Reply::Bootstrapped {
        instance_id: outcome.instance_id,
        admin_id: outcome.admin_id,
        credential_id: outcome.credential_id,
        binding_id: outcome.binding_id,
        recovery_key_epoch: outcome.recovery_key_epoch,
    })
}

/// The restoration plan: the instance and the key epoch of the recovery
/// state read in the transaction, and the replacement.
struct Replacement<'a> {
    admin_id: &'a str,
    credential_id: &'a str,
    binding_id: &'a str,
    public_identity: &'a str,
    trust_anchor_ref: &'a str,
    new_recovery_public_key: &'a str,
}

fn plan(instance_id: &str, recovery_key_epoch: i64, replacement: &Replacement<'_>) -> JsonObject {
    let text = |value: &str| Value::String(value.to_owned());
    JsonObject::from_iter([
        (PLAN_INSTANCE_ID.to_owned(), text(instance_id)),
        (
            PLAN_RECOVERY_KEY_EPOCH.to_owned(),
            Value::from(recovery_key_epoch),
        ),
        (PLAN_ADMIN_ID.to_owned(), text(replacement.admin_id)),
        (
            PLAN_CREDENTIAL_ID.to_owned(),
            text(replacement.credential_id),
        ),
        (PLAN_BINDING_ID.to_owned(), text(replacement.binding_id)),
        (
            PLAN_PUBLIC_IDENTITY.to_owned(),
            text(replacement.public_identity),
        ),
        (
            PLAN_TRUST_ANCHOR_REF.to_owned(),
            text(replacement.trust_anchor_ref),
        ),
        (
            PLAN_NEW_RECOVERY_PUBLIC_KEY.to_owned(),
            text(replacement.new_recovery_public_key),
        ),
    ])
}

/// `issue_challenge`: [`issue_recovery_challenge`] for the plan built from
/// the recovery state and the replacement.
async fn issue(shared: &Shared, wire: IssueWire) -> Result<Reply, ErrorCode> {
    let public_identity = credential_identity(&wire.credential_spki)?;
    check_trust_anchor_ref(&wire.trust_anchor_ref)?;
    // Checked as the registry checks it; the plan carries the hex text.
    checked_recovery_key(&wire.new_recovery_public_key)?;
    let operation_id = new_id(shared, IdKind::AdministrativeOperation)?;
    let audit_event_id = new_id(shared, IdKind::AuditEvent)?;
    let admin_id = new_id(shared, IdKind::AdminIdentity)?;
    let credential_id = new_id(shared, IdKind::AdminCredential)?;
    let binding_id = new_id(shared, IdKind::AdminRoleBinding)?;
    let replacement = Replacement {
        admin_id: &admin_id,
        credential_id: &credential_id,
        binding_id: &binding_id,
        public_identity: &public_identity,
        trust_anchor_ref: &wire.trust_anchor_ref,
        new_recovery_public_key: &wire.new_recovery_public_key,
    };

    let mut transaction = begin(shared).await?;
    let result = async {
        // The issue reads the row again `FOR SHARE` and refuses a plan
        // whose instance or epoch it no longer holds.
        let state = get_recovery_state(&mut *transaction)
            .await
            .map_err(|err| from_registry(&err))?
            .filter(|state| state.bootstrap_closed)
            .ok_or(ErrorCode::Conflict)?;
        let plan = plan(&state.instance_id, state.recovery_key_epoch, &replacement);
        issue_recovery_challenge(
            &mut transaction,
            &IssueChallenge {
                operation_id: &operation_id,
                kind: OPERATOR_RESTORATION,
                immutable_plan: &plan,
                ttl: shared.settings.challenge_ttl,
                now: shared.clock.now(),
                audit_event_id: &audit_event_id,
            },
        )
        .await
        .map_err(|err| from_challenge(&err))
    }
    .await;
    let challenge = finish(transaction, result).await?;
    Ok(Reply::Issued {
        operation_id: challenge.operation_id,
        expires_at: micros(challenge.expires_at)?,
        expected_revision: challenge.expected_revision,
        challenge: encode_hex(&challenge.challenge),
    })
}

/// The signed response of a `preview` or `restore`, decoded.
fn signature(wire: &ResponseWire) -> Result<Vec<u8>, ErrorCode> {
    check_operation_id(&wire.operation_id)?;
    decode_hex(&wire.signature).ok_or(ErrorCode::InvalidRequest)
}

/// `preview`: [`preview_recovery_response`], in a transaction that is
/// always rolled back (it writes nothing).
async fn preview(shared: &Shared, wire: ResponseWire) -> Result<Reply, ErrorCode> {
    let signature = signature(&wire)?;
    let response = SignedRecoveryResponse {
        operation_id: &wire.operation_id,
        signature: &signature,
    };
    let mut transaction = begin(shared).await?;
    let result = preview_recovery_response(&mut transaction, &response, shared.clock.now())
        .await
        .map_err(|err| from_restore(&err));
    let _ = transaction.rollback().await;
    let preview = result?;
    Ok(Reply::Previewed {
        admin_id: preview.admin_id,
        credential_id: preview.credential_id,
        binding_id: preview.binding_id,
        new_recovery_key_epoch: preview.new_recovery_key_epoch,
        expires_at: micros(preview.expires_at)?,
    })
}

/// `restore`: [`restore_operator`], which verifies the signature itself.
async fn restore(shared: &Shared, wire: ResponseWire) -> Result<Reply, ErrorCode> {
    let signature = signature(&wire)?;
    let audit_event_id = new_id(shared, IdKind::AuditEvent)?;
    let rotation_audit_event_id = new_id(shared, IdKind::AuditEvent)?;
    let response = SignedRecoveryResponse {
        operation_id: &wire.operation_id,
        signature: &signature,
    };
    let mut transaction = begin(shared).await?;
    // `now` immediately before the call (the recovery module, "Time").
    let request = RestoreRequest {
        audit_event_id: &audit_event_id,
        rotation_audit_event_id: &rotation_audit_event_id,
        now: shared.clock.now(),
    };
    let result = restore_operator(&mut transaction, &response, &request)
        .await
        .map_err(|err| from_restore(&err));
    let restored = finish(transaction, result).await?;
    Ok(Reply::Restored {
        admin_id: restored.admin_id,
        credential_id: restored.credential_id,
        binding_id: restored.binding_id,
        revoked_credential_ids: restored.revoked_credential_ids,
        recovery_key_epoch: restored.recovery_key_epoch,
        recovery_state_revision: restored.recovery_state_revision,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_trust_anchor_ref_is_bounded_and_has_no_space_or_control() {
        for good in [
            "a",
            "deployment/operator-ca",
            "caf\u{e9}",
            &"k".repeat(2048),
        ] {
            assert_eq!(check_trust_anchor_ref(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            " a",
            "a b",
            "a\tb",
            "a\nb",
            "a\u{7f}",
            "a\0",
            "a\u{b}",
            &"k".repeat(2049),
        ] {
            assert_eq!(
                check_trust_anchor_ref(bad),
                Err(ErrorCode::InvalidRequest),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_recovery_key_passes_the_registry_checks() {
        // The public key of the seed `[0x51; 32]` (`registry_recovery.rs`).
        let good = "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a";
        assert_eq!(checked_recovery_key(good), Ok(decode_hex(good).unwrap()));
        let mut identity = [0; 32];
        identity[0] = 1;
        for bad in [
            String::new(),
            encode_hex(&[0x11; 31]),
            encode_hex(&[0x11; 33]),
            encode_hex(&[7; 32]),
            encode_hex(&identity),
            good.to_uppercase(),
            format!("{good}00"),
        ] {
            assert_eq!(
                checked_recovery_key(&bad),
                Err(ErrorCode::InvalidRequest),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_credential_is_a_der_spki() {
        // The Ed25519 key of `crate::admin_http`'s peer tests.
        let spki = "302a300506032b657003210051f4589a4cc78fa1b0b8b62c23eb539068974c29ee0c6a\
                    229440518d9163f0e4";
        assert_eq!(
            credential_identity(spki).unwrap(),
            "spki-sha256:280292eab9838fde657039d990410c3525af3bcf2882b2cbee438d905d6e877f"
        );
        for bad in [
            "",
            "zz",
            "spki-sha256:280292eab9838fde657039d990410c3525af3bcf2882b2cbee438d905d6e877f",
            &spki.to_uppercase(),
            &spki[..spki.len() - 2],
        ] {
            assert_eq!(
                credential_identity(bad),
                Err(ErrorCode::InvalidRequest),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_operation_id_has_no_nul() {
        assert_eq!(check_operation_id("oper_1"), Ok(()));
        assert_eq!(check_operation_id(""), Ok(()));
        assert_eq!(
            check_operation_id("oper\0_1"),
            Err(ErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn times_are_whole_microseconds() {
        assert_eq!(micros(UNIX_EPOCH), Ok(0));
        assert_eq!(micros(UNIX_EPOCH + Duration::from_nanos(1_999)), Ok(1));
        assert_eq!(micros(UNIX_EPOCH - Duration::from_micros(5)), Ok(-5));
    }

    #[test]
    fn the_plan_has_the_eight_members() {
        let replacement = Replacement {
            admin_id: "adm_1",
            credential_id: "cred_1",
            binding_id: "role_1",
            public_identity: "spki-sha256:x",
            trust_anchor_ref: "anchor",
            new_recovery_public_key: "ab",
        };
        let plan = plan("i", 7, &replacement);
        assert_eq!(
            Value::Object(plan),
            serde_json::json!({
                "instance_id": "i",
                "recovery_key_epoch": 7,
                "admin_id": "adm_1",
                "credential_id": "cred_1",
                "binding_id": "role_1",
                "public_identity": "spki-sha256:x",
                "trust_anchor_ref": "anchor",
                "new_recovery_public_key": "ab",
            })
        );
    }

    #[test]
    fn the_transaction_is_read_committed_with_local_timeouts() {
        assert_eq!(BEGIN, "BEGIN ISOLATION LEVEL READ COMMITTED");
        assert!(SET_TIMEOUTS.contains("set_config('lock_timeout', $1, true)"));
        assert!(SET_TIMEOUTS.contains("set_config('statement_timeout', $1, true)"));
    }
}
