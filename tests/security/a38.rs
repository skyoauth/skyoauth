//! A38: device/impersonation not shipped. Expected: not advertised or
//! accepted for issuance; dormant impersonation API storage allowed only
//! disabled; capability gain does not activate (tasks §8; T10.11, T12.5,
//! T20.1).
//!
//! Stage M1a, "dormant impersonation record stored and not enableable or
//! approvable; a delegation grant's re-enable moves its revision forward,
//! never back (registry API)": the storage half of the row, through the
//! typed registry API (`skyoauth_service::persistence::registry`) against a
//! real PostgreSQL, one fresh database per test.
//!
//! - **Positive.** An impersonation grant created disabled and requiring
//!   reapproval (with its target service) is stored exactly as given at
//!   revision 1, read back and listed
//!   (`a38_pos_dormant_impersonation_grant_stored`).
//! - **Negative.** The dormant record cannot be enabled
//!   (`service_grant_impersonation_disabled_check`) nor lose its
//!   reapproval marker (`service_grant_activation_mode_check`), by update or
//!   on create, and a refused write changes nothing
//!   (`a38_neg_dormant_grant_enable_refused`,
//!   `a38_neg_dormant_grant_reapproval_marker_kept`). A disable/re-enable
//!   cycle of a delegation grant moves its revision forward (1, 2, 3), and
//!   writes at the earlier revisions are stale
//!   (`a38_neg_reenable_does_not_restore_prior_revision`).
//!
//! The re-enable case shows only that the registry API moves a revision
//! forward and refuses writes at older ones: every update sets
//! `revision = revision + 1` under a compare-and-set, so the API cannot
//! write a revision back. A direct SQL write that sets an older revision is
//! refused by the `SK001` revision trigger, which is not exercised here.
//! The "or evidence" half of the row's negative, the tasks §3 **Policy
//! revisions** rule that a disable/re-enable cycle cannot revive old
//! evidence (issuance-time `dependency_revisions`), needs issuance and
//! belongs with the M2 stage.
//!
//! Not covered here: the M2 stage (device or impersonation not advertised
//! in metadata, issuance rejected, a capability gain that does not
//! activate); export, import and startup of a dormant record (A53); a
//! direct or delegation grant created `requires_reapproval`, refused by the
//! same `service_grant_activation_mode_check` (not part of this row).

use skyoauth_service::persistence::registry::{
    self, ActivationState, GrantMode, RegistryError, Status,
};

use super::grant_fixture::{
    CREATE_REFUSALS, TENANT, UPDATE_REFUSALS, assert_create_refused, assert_stored,
    assert_unchanged, assert_update_refused, changes, dormant, grant, tenant,
};

#[tokio::test]
async fn a38_pos_dormant_impersonation_grant_stored() {
    let (db, pool) = tenant().await;
    let stored = assert_stored(&pool, &dormant("grt_imp")).await;
    assert_eq!(stored.mode, GrantMode::Impersonation);
    assert_eq!(stored.target_service_id.as_deref(), Some("svc_a"));
    assert_eq!(stored.status, Status::Disabled);
    assert_eq!(stored.activation_state, ActivationState::RequiresReapproval);
    db.drop([pool]).await;
}

#[tokio::test]
async fn a38_neg_dormant_grant_enable_refused() {
    let (db, pool) = tenant().await;
    let stored = assert_stored(&pool, &dormant("grt_imp")).await;
    let [(status, activation_state, constraint), ..] = UPDATE_REFUSALS;
    assert_eq!(
        (status, activation_state),
        (Status::Enabled, ActivationState::RequiresReapproval)
    );
    assert_update_refused(&pool, &stored, status, activation_state, constraint).await;
    db.drop([pool]).await;
}

/// The reapproval marker stays: clearing it, alone or while enabling, is
/// refused on update, and a create without it (or enabled) stores nothing.
#[tokio::test]
async fn a38_neg_dormant_grant_reapproval_marker_kept() {
    let (db, pool) = tenant().await;
    let stored = assert_stored(&pool, &dormant("grt_imp")).await;
    // The enabling update alone is a38_neg_dormant_grant_enable_refused.
    let [_, clearing, both] = UPDATE_REFUSALS;
    for (status, activation_state, constraint) in [clearing, both] {
        assert_update_refused(&pool, &stored, status, activation_state, constraint).await;
    }
    for (status, activation_state, constraint) in CREATE_REFUSALS {
        let new = grant(
            "grt_imp_new",
            GrantMode::Impersonation,
            status,
            activation_state,
        );
        assert_create_refused(&pool, &new, constraint).await;
    }
    assert_unchanged(&pool, &stored).await;
    db.drop([pool]).await;
}

/// Disabling and re-enabling a delegation grant restores its content, not
/// its revision: the re-enabled record is at revision 3, and updates
/// expecting revision 1 or 2 are stale and change nothing.
#[tokio::test]
async fn a38_neg_reenable_does_not_restore_prior_revision() {
    let (db, pool) = tenant().await;
    let id = "grt_del";
    let first = assert_stored(
        &pool,
        &grant(
            id,
            GrantMode::Delegation,
            Status::Enabled,
            ActivationState::NotRequired,
        ),
    )
    .await;
    let update = |revision, status| {
        let pool = &pool;
        let changes = changes(&first, status, ActivationState::NotRequired);
        async move { registry::update_service_grant(pool, TENANT, id, revision, &changes).await }
    };
    let disabled = update(1, Status::Disabled).await.unwrap();
    assert_eq!((disabled.status, disabled.revision), (Status::Disabled, 2));
    assert_unchanged(&pool, &disabled).await;
    let enabled = update(2, Status::Enabled).await.unwrap();
    assert_eq!((enabled.status, enabled.revision), (Status::Enabled, 3));
    // The same content as at revision 1, at a new revision.
    assert_eq!(
        enabled,
        registry::ServiceGrant {
            revision: 3,
            ..first.clone()
        }
    );
    assert_unchanged(&pool, &enabled).await;
    // Writes at the earlier revisions, each restoring that revision's
    // status, are stale.
    for (revision, status) in [(1, Status::Enabled), (2, Status::Disabled)] {
        let stale = update(revision, status).await;
        assert!(
            matches!(stale, Err(RegistryError::StaleRevision)),
            "{stale:?}"
        );
        assert_unchanged(&pool, &enabled).await;
    }
    db.drop([pool]).await;
}
