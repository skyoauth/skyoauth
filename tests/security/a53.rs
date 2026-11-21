//! A53: unsupported impersonation create/import, then capability upgrade
//! and activation attempts. Expected: a disabled/reapproval record
//! round-trips normally; enabled unsupported input rejects;
//! upgrade/PATCH/import cannot activate (tasks §8; T10.11, T12.10).
//!
//! **A53 partial: the create and PATCH refusal half only; A53 M1a stays
//! planned, export/import, startup and restore-fixture parts have no
//! code.** These tests are registered on A53's planned M1a stage, so they
//! are no evidence for it: the reporter lists their results as not counted.
//! They run through the typed registry API
//! (`skyoauth_service::persistence::registry`) against a real PostgreSQL,
//! one fresh database per test; the record is the dormant impersonation
//! grant (disabled, `requires_reapproval`).
//!
//! - **Positive.** `a53_pos_disabled_record_round_trips_through_registry`:
//!   the disabled, `requires_reapproval` record is created, read and listed
//!   unchanged. This is a round trip through the registry API only, **not**
//!   the export/import round trip of the row, and nothing restarts.
//! - **Negative.** An impersonation grant created enabled
//!   (`a53_neg_enabled_create_refused`), approved
//!   (`a53_neg_approved_create_refused`) or both
//!   (`a53_neg_enabled_and_approved_create_refused`) is refused by its
//!   `0004` check and not stored; an update that enables the stored record
//!   (`a53_neg_enabling_patch_refused`) is refused and changes nothing.
//!   "Approved" is read as `status = disabled` with `activation_state =
//!   not_required`, the only stored form of a cleared reapproval marker:
//!   that reading is an inference, the spec does not define the word for
//!   this record. "PATCH" is `update_service_grant`; no HTTP API exists
//!   yet.
//!
//! The same storage rules are A38's M1a evidence (`security::a38`); both
//! modules take the cases and assertions from `security::grant_fixture`, so
//! each refusal is stated once.
//!
//! Not covered here: export and import (rejecting an enabled or approved
//! record on import), startup with an active unsupported record seeded by
//! the restore fixture, rewriting nothing on that refusal, and the M1b
//! forward-migration stage.

use skyoauth_service::persistence::registry::{ActivationState, GrantMode, Status};

use super::grant_fixture::{
    CREATE_REFUSALS, UPDATE_REFUSALS, assert_create_refused, assert_stored, assert_update_refused,
    dormant, grant, tenant,
};

/// Creates the impersonation grant of one [`CREATE_REFUSALS`] case and
/// checks its refusal.
async fn create_refused(case: (Status, ActivationState, &str)) {
    let (db, pool) = tenant().await;
    let (status, activation_state, constraint) = case;
    let new = grant(
        "grt_imp",
        GrantMode::Impersonation,
        status,
        activation_state,
    );
    assert_create_refused(&pool, &new, constraint).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a53_pos_disabled_record_round_trips_through_registry() {
    let (db, pool) = tenant().await;
    assert_stored(&pool, &dormant("grt_imp")).await;
    db.drop([pool]).await;
}

#[tokio::test]
async fn a53_neg_enabled_create_refused() {
    let [enabled, _, _] = CREATE_REFUSALS;
    assert_eq!(
        (enabled.0, enabled.1),
        (Status::Enabled, ActivationState::RequiresReapproval)
    );
    create_refused(enabled).await;
}

#[tokio::test]
async fn a53_neg_approved_create_refused() {
    let [_, approved, _] = CREATE_REFUSALS;
    assert_eq!(
        (approved.0, approved.1),
        (Status::Disabled, ActivationState::NotRequired)
    );
    create_refused(approved).await;
}

#[tokio::test]
async fn a53_neg_enabled_and_approved_create_refused() {
    let [_, _, both] = CREATE_REFUSALS;
    assert_eq!(
        (both.0, both.1),
        (Status::Enabled, ActivationState::NotRequired)
    );
    create_refused(both).await;
}

/// Both enabling updates: with the reapproval marker kept, and cleared.
#[tokio::test]
async fn a53_neg_enabling_patch_refused() {
    let (db, pool) = tenant().await;
    let stored = assert_stored(&pool, &dormant("grt_imp")).await;
    let [enabling, _, enabling_and_approving] = UPDATE_REFUSALS;
    for (status, activation_state, constraint) in [enabling, enabling_and_approving] {
        assert_eq!(status, Status::Enabled);
        assert_update_refused(&pool, &stored, status, activation_state, constraint).await;
    }
    db.drop([pool]).await;
}
