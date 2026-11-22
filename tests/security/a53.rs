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
//! - **Positive.** `a53_pos_dormant_record_stored_and_read_back`: the
//!   disabled, `requires_reapproval` record is created, read and listed
//!   unchanged. This is a round trip through the registry API only, **not**
//!   the export/import round trip of the row, and nothing restarts.
//! - **Negative.** An impersonation grant created enabled
//!   (`a53_neg_enabled_create_refused`), with its reapproval marker cleared
//!   (`activation_state = not_required`;
//!   `a53_neg_reapproval_cleared_create_refused`) or both
//!   (`a53_neg_enabled_reapproval_cleared_create_refused`) is refused by its
//!   `0004` check and not stored; an update that enables the stored record
//!   (`a53_neg_enabling_patch_refused`) is refused, by the `0009` guard
//!   that freezes a stored impersonation grant (`Guard`), and changes
//!   nothing.
//!   "PATCH" is `update_service_grant`; no HTTP API exists yet. The tests
//!   are named after the values they write: they do not claim to settle what
//!   the row's "approved" means for this record, which the spec does not
//!   define.
//!
//! The same storage rules are A38's M1a evidence (`security::a38`); both
//! modules take the cases and assertions from `security::grant_fixture`, so
//! each refusal is stated once.
//!
//! Not covered here: export and import (rejecting an enabled or
//! reapproval-cleared record on import), startup with an active
//! unsupported record seeded by the restore fixture, rewriting nothing on
//! that refusal, and the M1b forward-migration stage. The database bounds
//! that fixture (docs/testing/conformance-layout.md, "Restore-state
//! cases"): the `0004` checks refuse an active impersonation row on every
//! insert, so it cannot be seeded as stored rows; a seeded grant and its
//! list rows are written in one transaction, since `0009` lets only the
//! creating transaction write them; and since `0009` a stored
//! impersonation grant cannot be rewritten (`Guard`), though the refusal
//! must still be shown to rewrite nothing.

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
async fn a53_pos_dormant_record_stored_and_read_back() {
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
async fn a53_neg_reapproval_cleared_create_refused() {
    let [_, cleared, _] = CREATE_REFUSALS;
    assert_eq!(
        (cleared.0, cleared.1),
        (Status::Disabled, ActivationState::NotRequired)
    );
    create_refused(cleared).await;
}

#[tokio::test]
async fn a53_neg_enabled_reapproval_cleared_create_refused() {
    let [_, _, both] = CREATE_REFUSALS;
    assert_eq!(
        (both.0, both.1),
        (Status::Enabled, ActivationState::NotRequired)
    );
    create_refused(both).await;
}

/// Both enabling updates, with the reapproval marker kept and cleared, are
/// refused by the `0009` guard (`Guard`) before any `0004` check.
#[tokio::test]
async fn a53_neg_enabling_patch_refused() {
    let (db, pool) = tenant().await;
    let stored = assert_stored(&pool, &dormant("grt_imp")).await;
    let [enabling, _, enabling_and_clearing] = UPDATE_REFUSALS;
    for (status, activation_state) in [enabling, enabling_and_clearing] {
        assert_eq!(status, Status::Enabled);
        assert_update_refused(&pool, &stored, status, activation_state).await;
    }
    db.drop([pool]).await;
}
