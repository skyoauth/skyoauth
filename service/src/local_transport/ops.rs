//! The four operations: each checks its wire values, generates its IDs,
//! runs one `READ COMMITTED` transaction around one registry call, and
//! commits only on success (see the module docs of
//! [`crate::local_transport`], "Operations" and "Transactions").

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sqlx::{Connection as _, PgConnection, Postgres, Transaction, pool::PoolConnection};
use tokio::time::{Instant, timeout, timeout_at};

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
    PLAN_PUBLIC_IDENTITY, PLAN_RECOVERY_KEY_EPOCH, PLAN_TRUST_ANCHOR_REF, RecoveryChallenge,
    RestoreRequest, SignedRecoveryResponse, bootstrap_instance, get_recovery_state,
    is_lowercase_uuid_v7, issue_recovery_challenge, preview_recovery_response, recovery_key,
    restore_operator,
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

/// Whether an issue's replacement key is already registered: a credential
/// with that `public_identity`, revoked or not (the key is unique across
/// every credential, so the restore could not enroll it).
const CREDENTIAL_REGISTERED: &str =
    "SELECT EXISTS (SELECT FROM admin_credential WHERE public_identity = $1)";

/// Why an operation stopped without its result.
pub(super) enum Stop {
    /// Refused with this code; nothing was written.
    Refused(ErrorCode),
    /// Closed without a response: the connection's deadline passed before
    /// the transaction began (while a pooled connection was acquired or
    /// `BEGIN` ran), and nothing was written; or the transaction did not end
    /// within the transaction timeout ([`Settings::transaction_timeout`]),
    /// and nothing was written unless the commit had been sent, whose
    /// outcome is then unknown (see the module docs, "Transactions"). A
    /// connection cut mid-exchange is discarded ([`Link`]).
    ///
    /// [`Settings::transaction_timeout`]: super::Settings::transaction_timeout
    Expired,
}

impl From<ErrorCode> for Stop {
    fn from(code: ErrorCode) -> Self {
        Self::Refused(code)
    }
}

/// Runs `request` (see the module docs, "Operations"); `None` when the
/// `deadline` passed before its transaction began, or the transaction did
/// not end within the transaction timeout, which bounds everything after
/// `BEGIN` (the deadline does not; the module docs, "Time limits").
pub(super) async fn execute(shared: &Shared, request: Request, deadline: Instant) -> Option<Reply> {
    let result = match request {
        Request::Bootstrap(wire) => bootstrap(shared, wire, deadline).await,
        Request::IssueChallenge(wire) => issue(shared, wire, deadline).await,
        Request::Preview(wire) => preview(shared, wire, deadline).await,
        Request::Restore(wire) => restore(shared, wire, deadline).await,
    };
    match result {
        Ok(reply) => Some(reply),
        Err(Stop::Refused(code)) => Some(refusal(code)),
        Err(Stop::Expired) => None,
    }
}

/// The canonical public identity of the DER `SubjectPublicKeyInfo` in
/// `hex`, computed here, never taken from the request.
fn credential_identity(hex: &str) -> Result<String, ErrorCode> {
    let der = decode_hex(hex).ok_or(ErrorCode::InvalidRequest)?;
    canonical_public_identity(&der).map_err(|_| ErrorCode::InvalidRequest)
}

/// The `0005` checks of `admin_credential.trust_anchor_ref`: 1 to 2048
/// bytes, and none of the characters that `(trust_anchor_ref COLLATE "C")
/// !~ '[[:space:][:cntrl:]]'` refuses. Under the `C` collation PostgreSQL's
/// `[:space:]` is the ASCII space and U+0009 to U+000D, and `[:cntrl:]` is
/// U+0000 to U+001F and U+007F to U+009F (the C1 controls included, U+0085
/// say): together, the space and Unicode's `Cc` category, which is
/// [`char::is_control`]. Other Unicode spaces (U+00A0, U+2028, U+3000) pass
/// the database's check and this one. Checked here for the issue too, whose
/// plan the restore stores later, so a challenge is never issued for a
/// replacement the restore could not enroll.
fn check_trust_anchor_ref(value: &str) -> Result<(), ErrorCode> {
    let bounded = (1..=MAX_TRUST_ANCHOR_REF).contains(&value.len());
    if bounded && !value.chars().any(|c| c == ' ' || c.is_control()) {
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

/// The request's pooled connection. Dropped before [`Link::release`] (its
/// transaction cut by the transaction timeout, its `BEGIN` by the
/// deadline, or the request's task aborted at shutdown), it is discarded:
/// detached from the pool, which may open a replacement, and closed at
/// once, never reused or tested mid-exchange; the server rolls back its
/// open transaction, if any, when it sees the connection end.
struct Link(Option<PoolConnection<Postgres>>);

impl Link {
    /// The connection (always there until [`Link::release`] or the drop).
    fn connection(&mut self) -> Result<&mut PgConnection, Stop> {
        self.0
            .as_deref_mut()
            .ok_or(Stop::Refused(ErrorCode::ServerError))
    }

    /// Returns the connection to the pool: the request's use of it ended
    /// without being cut ([`settle`]).
    fn release(mut self) {
        drop(self.0.take());
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        if let Some(connection) = self.0.take() {
            drop(connection.detach());
        }
    }
}

/// Ends the request's use of `link` after `outcome`: returned to the pool,
/// unless the request was cut ([`Stop::Expired`]), when it is discarded.
fn settle<T>(link: Link, outcome: &Result<T, Stop>) {
    if !matches!(outcome, Err(Stop::Expired)) {
        link.release();
    }
}

/// A pooled connection for the request; the pool's acquire must end
/// before `deadline` ([`Stop::Expired`]).
async fn acquire(shared: &Shared, deadline: Instant) -> Result<Link, Stop> {
    let connection = timeout_at(deadline, shared.pool.acquire())
        .await
        .map_err(|_| Stop::Expired)?
        .map_err(|err| from_store_failure(&err))?;
    Ok(Link(Some(connection)))
}

/// Begins the request's transaction on `link`: `READ COMMITTED`. The
/// `BEGIN` must end before `deadline` ([`Stop::Expired`]; the connection,
/// cut mid-exchange, is then discarded).
async fn begin(link: &mut Link, deadline: Instant) -> Result<Transaction<'_, Postgres>, Stop> {
    let begin = link.connection()?.begin_with(BEGIN);
    timeout_at(deadline, begin)
        .await
        .map_err(|_| Stop::Expired)?
        .map_err(|err| Stop::from(from_store_failure(&err)))
}

/// Runs `work`, everything after `BEGIN` (setting the timeouts, the
/// operation's statements, the commit or the rollback), within the
/// transaction timeout: the backstop for a database that stopped answering,
/// which the server's own timeouts cannot end. On expiry `work` is dropped
/// mid-exchange and the request stops with [`Stop::Expired`] (no response;
/// the caller discards the connection).
async fn within<T>(
    shared: &Shared,
    work: impl Future<Output = Result<T, Stop>>,
) -> Result<T, Stop> {
    timeout(shared.settings.transaction_timeout, work)
        .await
        .unwrap_or(Err(Stop::Expired))
}

/// Sets the transport's lock and statement timeouts for `transaction` only.
async fn set_timeouts(
    shared: &Shared,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), Stop> {
    let timeout = format!("{}ms", shared.settings.statement_timeout.as_millis());
    sqlx::query(SET_TIMEOUTS)
        .bind(timeout)
        .execute(&mut **transaction)
        .await
        .map_err(|err| from_store_failure(&err))?;
    Ok(())
}

/// Commits `transaction` when `result` is `Ok`, else rolls it back: a
/// refusal writes nothing (a failed rollback too: the connection is closed
/// or the server aborts the transaction).
async fn finish<T>(
    transaction: Transaction<'_, Postgres>,
    result: Result<T, ErrorCode>,
) -> Result<T, Stop> {
    match result {
        Ok(value) => {
            transaction
                .commit()
                .await
                .map_err(|err| from_store_failure(&err))?;
            Ok(value)
        }
        Err(code) => {
            let _ = transaction.rollback().await;
            Err(code.into())
        }
    }
}

/// `bootstrap`: [`bootstrap_instance`].
async fn bootstrap(shared: &Shared, wire: BootstrapWire, deadline: Instant) -> Result<Reply, Stop> {
    if !is_lowercase_uuid_v7(&wire.instance_id) {
        return Err(ErrorCode::InvalidRequest.into());
    }
    let public_identity = credential_identity(&wire.credential_spki)?;
    check_trust_anchor_ref(&wire.trust_anchor_ref)?;
    let recovery_public_key = checked_recovery_key(&wire.recovery_public_key)?;
    let admin_id = new_id(shared, IdKind::AdminIdentity)?;
    let credential_id = new_id(shared, IdKind::AdminCredential)?;
    let binding_id = new_id(shared, IdKind::AdminRoleBinding)?;
    let audit_event_id = new_id(shared, IdKind::AuditEvent)?;

    let mut link = acquire(shared, deadline).await?;
    let outcome = async {
        let mut transaction = begin(&mut link, deadline).await?;
        within(shared, async {
            set_timeouts(shared, &mut transaction).await?;
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
            finish(transaction, result).await
        })
        .await
    }
    .await;
    settle(link, &outcome);
    let outcome = outcome?;
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
async fn issue(shared: &Shared, wire: IssueWire, deadline: Instant) -> Result<Reply, Stop> {
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

    let mut link = acquire(shared, deadline).await?;
    let challenge = async {
        let mut transaction = begin(&mut link, deadline).await?;
        within(shared, async {
            set_timeouts(shared, &mut transaction).await?;
            let result = issue_step(
                shared,
                &mut transaction,
                &public_identity,
                &replacement,
                &operation_id,
                &audit_event_id,
            )
            .await;
            finish(transaction, result).await
        })
        .await
    }
    .await;
    settle(link, &challenge);
    let challenge = challenge?;
    Ok(Reply::Issued {
        operation_id: challenge.operation_id,
        expires_at: micros(challenge.expires_at)?,
        expected_revision: challenge.expected_revision,
        challenge: encode_hex(&challenge.challenge),
    })
}

/// The statements of an issue in `transaction`: the recovery state, the
/// lookup of the replacement key, and [`issue_recovery_challenge`].
async fn issue_step(
    shared: &Shared,
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    replacement: &Replacement<'_>,
    operation_id: &str,
    audit_event_id: &str,
) -> Result<RecoveryChallenge, ErrorCode> {
    // The issue reads the row again `FOR SHARE` and refuses a plan
    // whose instance or epoch it no longer holds.
    let state = get_recovery_state(&mut **transaction)
        .await
        .map_err(|err| from_registry(&err))?
        .filter(|state| state.bootstrap_closed)
        .ok_or(ErrorCode::Conflict)?;
    // A key already registered, by a live or a revoked credential,
    // would make a challenge that previews but never restores
    // (`admin_credential`'s unique `public_identity`): refused before
    // the issue writes anything.
    let registered: bool = sqlx::query_scalar(CREDENTIAL_REGISTERED)
        .bind(public_identity)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|err| from_store_failure(&err))?;
    if registered {
        return Err(ErrorCode::Conflict);
    }
    let plan = plan(&state.instance_id, state.recovery_key_epoch, replacement);
    issue_recovery_challenge(
        transaction,
        &IssueChallenge {
            operation_id,
            kind: OPERATOR_RESTORATION,
            immutable_plan: &plan,
            ttl: shared.settings.challenge_ttl,
            now: shared.clock.now(),
            audit_event_id,
        },
    )
    .await
    .map_err(|err| from_challenge(&err))
}

/// The signed response of a `preview` or `restore`, decoded.
fn signature(wire: &ResponseWire) -> Result<Vec<u8>, ErrorCode> {
    check_operation_id(&wire.operation_id)?;
    decode_hex(&wire.signature).ok_or(ErrorCode::InvalidRequest)
}

/// `preview`: [`preview_recovery_response`], in a transaction that is
/// always rolled back (it writes nothing).
async fn preview(shared: &Shared, wire: ResponseWire, deadline: Instant) -> Result<Reply, Stop> {
    let signature = signature(&wire)?;
    let response = SignedRecoveryResponse {
        operation_id: &wire.operation_id,
        signature: &signature,
    };
    let mut link = acquire(shared, deadline).await?;
    let preview = async {
        let mut transaction = begin(&mut link, deadline).await?;
        within(shared, async {
            set_timeouts(shared, &mut transaction).await?;
            let result =
                preview_recovery_response(&mut transaction, &response, shared.clock.now()).await;
            // Written nothing to keep: a failed rollback changes no answer.
            let _ = transaction.rollback().await;
            result.map_err(|err| Stop::from(from_restore(&err)))
        })
        .await
    }
    .await;
    settle(link, &preview);
    let preview = preview?;
    Ok(Reply::Previewed {
        admin_id: preview.admin_id,
        credential_id: preview.credential_id,
        binding_id: preview.binding_id,
        new_recovery_key_epoch: preview.new_recovery_key_epoch,
        expires_at: micros(preview.expires_at)?,
    })
}

/// `restore`: [`restore_operator`], which verifies the signature itself.
async fn restore(shared: &Shared, wire: ResponseWire, deadline: Instant) -> Result<Reply, Stop> {
    let signature = signature(&wire)?;
    let audit_event_id = new_id(shared, IdKind::AuditEvent)?;
    let rotation_audit_event_id = new_id(shared, IdKind::AuditEvent)?;
    let response = SignedRecoveryResponse {
        operation_id: &wire.operation_id,
        signature: &signature,
    };
    let mut link = acquire(shared, deadline).await?;
    let restored = async {
        let mut transaction = begin(&mut link, deadline).await?;
        within(shared, async {
            set_timeouts(shared, &mut transaction).await?;
            // `now` immediately before the call (the recovery module, "Time").
            let request = RestoreRequest {
                audit_event_id: &audit_event_id,
                rotation_audit_event_id: &rotation_audit_event_id,
                now: shared.clock.now(),
            };
            let result = restore_operator(&mut transaction, &response, &request)
                .await
                .map_err(|err| from_restore(&err));
            finish(transaction, result).await
        })
        .await
    }
    .await;
    settle(link, &restored);
    let restored = restored?;
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
            "a\u{a0}b",
            "a\u{2028}b",
            "a\u{3000}b",
            "a\u{1680}b",
            &"k".repeat(2048),
            &"\u{e9}".repeat(1024),
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
            "a\u{1f}",
            "a\u{80}",
            "a\u{85}",
            "a\u{9f}",
            &"k".repeat(2049),
            &"\u{e9}".repeat(1025),
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
