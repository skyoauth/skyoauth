//! The audited, authorized writes of the instance-global egress allowlist
//! (identity-registry IR-152; public-api section 7.1, the
//! `/admin/v1/egress-allowlist` row; tasks section 3 "Egress and secret
//! namespaces", T11.2): [`create_egress_entry`], [`enable_egress_entry`] and
//! [`disable_egress_entry`]. See the [module docs](super) for the steps,
//! the lock order, the errors and the D3 seams; this module's own rules are
//! under "Egress allowlist" there.
//!
//! An entry is immutable but for its `status` and has no delete (IR-152;
//! `0002`): a create takes [`EgressEntryCreate`], without an ID, and the
//! other two writes set only `status` at the expected revision. A disabled
//! entry is enabled again with [`enable_egress_entry`].

use sqlx::{Postgres, Transaction};

use super::workload::security_admin;
use super::{AdminRequest, AdminWriteError, Audited};
use crate::ids::IdKind;
use crate::operation::{OUTCOME_SUCCESS, Requester};
use crate::persistence::registry::{
    self, AuditActor, AuditEvent, EgressAllowlistEntry, EgressPurpose, NewAuditEvent,
    NewEgressAllowlistEntry, Status, append_audit_event,
};
use crate::trust::source::is_canonical_destination;
use crate::trust::write::in_savepoint;

/// The audit action of a create (identity-registry IR-059; the names of
/// [`AUDIT_ACTIONS`](crate::persistence::registry::AUDIT_ACTIONS)).
const CREATE: &str = "egress_allowlist_entry.create";
/// The audit action of [`enable_egress_entry`] (IR-059's own example).
const ENABLE: &str = "egress_allowlist_entry.enable";
/// The audit action of [`disable_egress_entry`].
const DISABLE: &str = "egress_allowlist_entry.disable";

/// The longest `exact_destination`, in bytes: the `0002` column check
/// (lead decision), checked here first so that a longer one is
/// [`AdminWriteError::InvalidDestination`] before any ID is generated.
pub const MAX_DESTINATION_BYTES: usize = 2048;

/// The input of [`create_egress_entry`]: an entry without its ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressEntryCreate {
    pub purpose: EgressPurpose,
    /// The exact URL a source's destination must equal byte for byte. It
    /// must pass [`is_valid_destination`].
    pub exact_destination: String,
    pub status: Status,
}

/// Whether `destination` may be an entry's `exact_destination` (see the
/// module docs, "Egress allowlist"): at most [`MAX_DESTINATION_BYTES`]
/// bytes, no `*`, and the canonical-form `https` rule that a trust source's
/// destination must pass ([`crate::trust::source`], "Syntax"): no ASCII
/// whitespace, control character or backslash; the text the URL parser
/// serializes; no incomplete escape and no escape of an unreserved
/// character; scheme `https`, a non-empty host, no userinfo and no
/// fragment. A query is allowed, as for a source.
pub fn is_valid_destination(destination: &str) -> bool {
    destination.len() <= MAX_DESTINATION_BYTES
        && !destination.contains('*')
        && is_canonical_destination(destination)
}

/// Step 6: the write's event, last, with a generated ID: an instance event
/// (no tenant) with the entry as its object.
async fn append_egress_event(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    requester: &Requester,
    action: &'static str,
    previous_revision: Option<i64>,
    row: &EgressAllowlistEntry,
) -> Result<AuditEvent, AdminWriteError> {
    let event = NewAuditEvent {
        id: request.ids.new_id(IdKind::AuditEvent)?,
        tenant_id: None,
        timestamp: request.now,
        actor: AuditActor::Operator(requester.admin_id.clone()),
        action: action.into(),
        object_id: row.id.clone(),
        previous_revision,
        new_revision: Some(row.revision),
        outcome: OUTCOME_SUCCESS.into(),
    };
    Ok(append_audit_event(transaction, &event).await?)
}

/// Creates an egress allowlist entry with a generated ID
/// ([`IdKind::EgressEntry`]), enabled or disabled as `new.status` says, and
/// appends `egress_allowlist_entry.create`. A destination that is not
/// valid ([`is_valid_destination`]) is
/// [`AdminWriteError::InvalidDestination`], after the authorization and
/// before any ID is generated; a `(purpose, exact_destination)` pair another
/// entry has, enabled or disabled, is [`RegistryError::AlreadyExists`]
/// naming `egress_allowlist_entry_purpose_exact_destination_key`.
///
/// Not gated: an enabled create is widening-class (IR-152) and is one of
/// the D3 seams (see the module docs, "Not gated: the D3 seams").
///
/// [`RegistryError::AlreadyExists`]: crate::persistence::registry::RegistryError::AlreadyExists
pub async fn create_egress_entry(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    new: &EgressEntryCreate,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        if !is_valid_destination(&new.exact_destination) {
            return Err(AdminWriteError::InvalidDestination);
        }
        let new = NewEgressAllowlistEntry {
            id: request.ids.new_id(IdKind::EgressEntry)?,
            purpose: new.purpose,
            exact_destination: new.exact_destination.clone(),
            status: new.status,
        };
        let row = registry::create_egress_allowlist_entry(&mut **transaction, &new).await?;
        let event =
            append_egress_event(transaction, request, &requester, CREATE, None, &row).await?;
        Ok(Audited { row, event })
    })
    .await
}

/// Steps 3 to 6 of a status write: sets the status of the entry `id` at
/// `expected_revision` with the registry's compare-and-set, which is the
/// revision check (a missing entry is `NotFound`, another revision
/// `StaleRevision`), and appends `action`.
async fn write_egress_status(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    requester: &Requester,
    (id, expected_revision): (&str, i64),
    status: Status,
    action: &'static str,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    let row =
        registry::update_egress_allowlist_entry(&mut **transaction, id, expected_revision, status)
            .await?;
    let previous = Some(expected_revision);
    let event =
        append_egress_event(transaction, request, requester, action, previous, &row).await?;
    Ok(Audited { row, event })
}

/// Enables the egress allowlist entry `id` at `expected_revision` and
/// appends `egress_allowlist_entry.enable`, also when it is already
/// enabled. A disabled entry's re-enable is this write: no destination is
/// checked again (it is immutable and was checked at its create).
///
/// Not gated: re-enabling is widening-class (IR-152) and is one of the D3
/// seams (see the module docs, "Not gated: the D3 seams").
pub async fn enable_egress_entry(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let target = (id, expected_revision);
        write_egress_status(
            transaction,
            request,
            &requester,
            target,
            Status::Enabled,
            ENABLE,
        )
        .await
    })
    .await
}

/// Disables the egress allowlist entry `id` at `expected_revision` and
/// appends `egress_allowlist_entry.disable`, also when it is already
/// disabled. From its commit, a trust source write that sets a destination
/// to it is refused, at the write or at its approval (IR-152; see the
/// module docs, "Egress allowlist"); sources that already use it are left
/// as they are.
pub async fn disable_egress_entry(
    transaction: &mut Transaction<'_, Postgres>,
    request: &AdminRequest<'_>,
    id: &str,
    expected_revision: i64,
) -> Result<Audited<EgressAllowlistEntry>, AdminWriteError> {
    in_savepoint(transaction, async |transaction| {
        let requester = security_admin(transaction, request).await?;
        let target = (id, expected_revision);
        write_egress_status(
            transaction,
            request,
            &requester,
            target,
            Status::Disabled,
            DISABLE,
        )
        .await
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::registry::is_audit_action;

    #[test]
    fn every_action_is_in_the_table() {
        for action in [CREATE, ENABLE, DISABLE] {
            assert!(is_audit_action(action), "{action}");
        }
    }

    #[test]
    fn the_bound_is_the_columns() {
        assert_eq!(MAX_DESTINATION_BYTES, 2048);
    }

    /// The writer's own bounds on top of the shared rule: the length, at
    /// the column's limit and one byte over it, and `*` anywhere.
    #[test]
    fn a_destination_has_the_writers_bounds() {
        let base = "https://idp.example/";
        let at_limit = format!("{base}{}", "a".repeat(MAX_DESTINATION_BYTES - base.len()));
        assert_eq!(at_limit.len(), MAX_DESTINATION_BYTES);
        assert!(is_canonical_destination(&at_limit));
        assert!(is_valid_destination(&at_limit));
        let over = format!("{at_limit}a");
        assert!(is_canonical_destination(&over));
        assert!(!is_valid_destination(&over));
        for wildcard in [
            "https://*.idp.example/",
            "https://idp.example/*",
            "https://idp.example/keys?kid=*",
        ] {
            assert!(!is_valid_destination(wildcard), "{wildcard}");
        }
        // The shared rule alone takes these, so only the writer's bound
        // refuses them.
        assert!(is_canonical_destination("https://*.idp.example/"));
        assert!(is_canonical_destination("https://idp.example/*"));
        assert!(is_canonical_destination("https://idp.example/keys?kid=*"));
    }
}
