//! The audited write path of a trust source with the IR-152 egress check
//! (T11.2; identity-registry IR-152; public-api section 7.1, the
//! `/admin/v1/tenants/{tenant}/trust-sources` row; migrations README, "What
//! 0004 adds", the service rules).
//!
//! [`create_source`] and [`update_source`] wrap the registry's bare
//! [`create_trust_source`] and [`update_trust_source`], which check nothing
//! the database does not. They run in the caller's
//! transaction and neither commit nor roll it back. The picks below are
//! the lead's (provisional lead pick, 2026-11-22) unless marked (inferred);
//! all are provisional until the maintainer ratifies the ADRs (T00.8 to
//! T00.17, Gate M0).
//!
//! # Rules
//!
//! - **Who.** The operator must be a `trust_admin` of the source's tenant:
//!   [`authorize_operator_locked`] with the presented `public_identity`,
//!   [`OperatorScope::Tenant`] of the tenant and [`AdminRole::TrustAdmin`]
//!   (public-api section 7.1: tenant `trust_admin`). The function builds that
//!   request itself, so a caller cannot ask for another role or scope
//!   (inferred). Roles do not inherit (API-120): a `security_admin`, another
//!   tenant's `trust_admin` or a `client_admin` of the tenant is refused.
//!   Every miss is the one [`SourceWriteError::Unauthorized`], whatever its
//!   cause, and an unauthorized update learns nothing about the source, not
//!   even whether it exists.
//! - **What.** `discovery_url` must match an `oidc_discovery` entry and
//!   `token_review_endpoint` a `token_review` entry (IR-152). Only a member
//!   that is set is checked; the `0004` kind checks decide which members a
//!   kind has (`discovery_url` for `oidc_discovery`, `token_review_endpoint`
//!   for `kubernetes_token_review`, neither for `uploaded_jwks`), and they
//!   still reject a member of the wrong kind at the write.
//! - **Match.** Exact byte equality of the member with the entry's
//!   `exact_destination`, with no normalization of case, port, trailing
//!   slash or percent-encoding (inferred: IR-152 says "exactly match"; the
//!   column is `COLLATE "C"`, so `=` compares bytes). A `jwks` entry, or an
//!   entry of the other purpose, never satisfies a member. The entry must be
//!   `enabled`: a missing or disabled entry is
//!   [`SourceWriteError::EgressNotAllowed`] naming the member.
//! - **When.** A create checks every member that is set. An update checks
//!   only a member whose new value differs, byte-wise, from the stored row's
//!   (IR-152: "on create or change"). An update that leaves both unchanged,
//!   a disable included, is never refused for a missing or disabled entry,
//!   so a source whose entry was disabled after its last change can still be
//!   renamed or disabled; such a source is degraded and fails closed at
//!   fetch (IR-152), not here. An update that disables a source and changes
//!   a member in the same write is checked like any other change (inferred:
//!   IR-152 exempts "a disable" and "a write that leaves both fields
//!   unchanged", and this write is neither alone).
//! - **Syntax.** A checked member must be an `https` URL with a host, a
//!   path and no userinfo or fragment (the lead's list), read as follows
//!   (inferred): the `url` crate parses it, and its raw text is `https://`
//!   followed by a non-empty authority with no `@`, which ends at a `/` (not
//!   at `?`, `#`, `\` or the end), and it has no fragment, not even an
//!   empty `#`. The raw text is checked as well as the parsed URL because
//!   the parser is lenient: it reads `https:///x` as the host `x`, drops the
//!   empty userinfo of `https://@host/`, and gives `https://host` the path
//!   `/`. A query is allowed (no rule names it), and the minimal path is
//!   `/`, so a TokenReview endpoint is written `https://host:6443/`.
//!   Otherwise the write is [`SourceWriteError::InvalidDestination`] naming
//!   the member. A create checks the syntax before any statement; an update
//!   checks only a changed member, like the entry check, so it checks after
//!   it has read the stored row and before any egress entry lock (inferred:
//!   an unchanged member is never refused, also not by a syntax rule that
//!   tightened after it was stored).
//!
//! No error's `Display` or `Debug` contains a destination: errors name the
//! member, never its value.
//!
//! # Order and locks
//!
//! Each function, after the pure checks, runs these steps in a savepoint of
//! its own:
//!
//! 0. reads `transaction_isolation` and refuses any value but
//!    `read committed` with [`SourceWriteError::UnsupportedIsolation`],
//!    before any other statement and any lock (see "Isolation");
//! 1. [`authorize_operator_locked`]: the operator's `admin_identity`,
//!    `admin_credential` and `admin_role_binding` rows `FOR SHARE`, in the
//!    `0005` order;
//! 2. an update only: the `trust_source` row by tenant and ID
//!    `FOR NO KEY UPDATE`, the lock its compare-and-set takes anyway, and
//!    reads the stored destinations and revision. A missing row is
//!    [`RegistryError::NotFound`] and another revision
//!    [`RegistryError::StaleRevision`], both before any entry lock;
//! 3. for each member to check, in the fixed order `discovery_url`, then
//!    `token_review_endpoint`, the matching `egress_allowlist_entry` row
//!    `FOR SHARE`, by `purpose` and `exact_destination` (unique together, so
//!    at most one row each). No kind has both members, so a valid write
//!    locks at most one entry; the fixed order covers a write that sets
//!    both, which the kind checks then reject;
//! 4. the registry write: the insert (whose foreign-key checks take
//!    `FOR KEY SHARE` on the tenant and, for `uploaded_jwks`, the keyset) or
//!    the compare-and-set update;
//! 5. [`append_audit_event`] last, which locks the tenant row
//!    `FOR KEY SHARE` and then the chain head (migrations README, "append
//!    audit events in this order").
//!
//! So the lock order is: operator rows, then the source row
//! (`FOR NO KEY UPDATE`, update only), then the egress entry rows
//! (`FOR SHARE`, discovery before TokenReview), then the write's own locks,
//! then the audit head. This differs from step 1 of "What 0005 adds" in the
//! migrations README, which orders the `0002` to `0004` tables by name
//! (`egress_allowlist_entry` before `trust_source`): that order is for a
//! write that creates an `administrative_operation`, which this one does
//! not, and an update must read the stored row before it knows which entry
//! to lock. An egress entry writer that locked a trust source row after an
//! entry row would deadlock with an update here; PostgreSQL fails one of
//! them with `40P01` ([`RegistryError::Retry`]), a refusal for this write.
//! No egress entry writer exists yet; one must not lock trust sources after
//! the entry.
//!
//! `FOR SHARE` on the entry conflicts with the `UPDATE` that disables it,
//! which takes a `FOR NO KEY UPDATE` row lock, and not with another
//! `FOR SHARE`, so concurrent source writes that use one entry do not wait
//! for each other. A disable that starts while a write holds the entry waits
//! until that write commits or rolls back, so the source is never written
//! against an entry that a disable committed before it: either the write
//! commits first and the source is then degraded by the disable at fetch,
//! or the disable commits first and the write sees it. A write that reaches
//! the entry while a disable holds it waits for that disable; under
//! `READ COMMITTED` the lock then returns the row as the disable committed
//! it, `disabled`, and the write is refused.
//!
//! # Isolation
//!
//! The functions run only under `READ COMMITTED`, as
//! [`restore_operator`](crate::persistence::registry::restore_operator)
//! does: step 0 compares `transaction_isolation` by name and refuses any
//! other level, `READ UNCOMMITTED` included, with
//! [`SourceWriteError::UnsupportedIsolation`]. The refusal takes no lock,
//! writes nothing and leaves the caller's transaction usable; the caller
//! retries in a `READ COMMITTED` transaction. The argument of "Order and
//! locks" is written for `READ COMMITTED`, where a lock that waited returns
//! the row as committed. Under `REPEATABLE READ` or `SERIALIZABLE` a lock on
//! a row changed after the snapshot would fail with `40001` instead, and
//! the authorization lookup and the stored-row comparison would read the
//! snapshot; one level keeps one argument. A `40001` or `40P01` from any
//! step is [`RegistryError::Retry`] in [`SourceWriteError::Registry`]:
//! retry the whole transaction.
//!
//! # Audit event
//!
//! One event, last, in the source's tenant: actor the authorized operator
//! (`{"type": "operator", "id": <admin_id>}`), `object_id` the source's ID,
//! outcome `success` (inferred, as for bootstrap and restore). A create is
//! `trust_source.create` with no previous revision and the new row's
//! revision; an update is `trust_source.update` with the stored and the new
//! revision, for every update, a status-only one included (provisional
//! lead pick, 2026-11-22; the action table's convention would name a
//! status-only write `trust_source.enable` or `trust_source.disable`). The
//! event envelope has no member for the checked members or the matched
//! entry IDs (no `audit_event` detail column; migrations README, "Not done
//! in `0002`"), so the event records neither (inferred: kept minimal), and
//! never a destination.
//!
//! # Errors and rollback
//!
//! Each function runs its steps in a savepoint (`Transaction::begin` on the
//! caller's transaction), releases it on `Ok` and rolls it back on every
//! `Err`, as bootstrap and restore do: a caller that commits after an `Err`
//! commits none of the function's rows, and its transaction stays usable.
//! Rolling the savepoint back releases the locks taken in it. The caller
//! still rolls back on `Err`, since a failed savepoint rollback leaves the
//! rows in place. A refusal before step 0 (the syntax of a create) runs no
//! statement and takes no savepoint.
//!
//! # Not done here
//!
//! - No endpoint and no HTTP: nothing calls these functions yet. They must
//!   not be wired to a request path before the request layer of T14.1 and
//!   T14.2 exists (generated IDs, NUL rejection, the role of each endpoint)
//!   and the widening question below is decided, since a wired write would
//!   apply a widening source write without the approval IR-052 may require.
//! - Widening: whether a source write is widening and needs an IR-054
//!   approval while `widening_second_approver` is on (IR-052) is not decided
//!   here; no write waits for an approval.
//! - The fetch-time match of a discovered `jwks_uri` against an enabled
//!   `jwks` entry, the degraded health signal and the fetches themselves
//!   (IR-152; T11.2, T11.8).
//! - `ca_bundle_ref` and `reviewer_credential_ref` resolution within the
//!   tenant's secret namespace (IR-034), tenant status (the operator lookup
//!   does not read it), and the other source rules of T11.1 and T11.8.
//! - A database backstop, such as a trigger that checks the entry: the
//!   migrations are frozen, and that alternative waits for the maintainer's
//!   ruling on a proposal. The bare registry functions still write any
//!   destination the `0004` checks allow.

use std::{fmt, time::SystemTime};

use sqlx::{Connection, Postgres, Row, Transaction};
use url::Url;

use crate::persistence::registry::{
    AdminRole, AuditActor, EgressPurpose, NewAuditEvent, NewTrustSource, OperatorRequest,
    OperatorScope, RegistryError, Status, TrustSource, TrustSourceChanges, append_audit_event,
    authorize_operator_locked, create_trust_source, update_trust_source,
};

/// The member name of a trust source's discovery URL, as errors name it.
pub const DISCOVERY_URL: &str = "discovery_url";

/// The member name of a trust source's TokenReview endpoint, as errors name
/// it.
pub const TOKEN_REVIEW_ENDPOINT: &str = "token_review_endpoint";

/// The audit action of [`create_source`] (identity-registry IR-059).
const CREATE_ACTION: &str = "trust_source.create";

/// The audit action of [`update_source`] (identity-registry IR-059).
const UPDATE_ACTION: &str = "trust_source.update";

/// The outcome of the event (inferred, as for bootstrap).
const SUCCESS: &str = "success";

/// Step 0: the transaction's isolation level.
const TRANSACTION_ISOLATION: &str = "SELECT current_setting('transaction_isolation')";

/// The one isolation level the writes run at, as `transaction_isolation`
/// names it.
const READ_COMMITTED: &str = "read committed";

/// Step 2 of an update: the stored row, locked as its update locks it.
const LOCK_SOURCE: &str = "SELECT discovery_url, token_review_endpoint, revision \
     FROM trust_source WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE";

/// Step 3: the entry of one purpose with exactly this destination.
const LOCK_ENTRY: &str = "SELECT id, status FROM egress_allowlist_entry \
     WHERE purpose = $1 AND exact_destination = $2 FOR SHARE";

/// The scheme and the two slashes a destination starts with.
const HTTPS_PREFIX: &str = "https://";

/// What the write's audit event takes from the caller: its ID
/// (caller-generated, T10.2) and the caller's `now`, never the database's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAudit<'a> {
    pub event_id: &'a str,
    pub now: SystemTime,
}

/// Why [`create_source`] or [`update_source`] did not write. On every
/// variant the function's savepoint is rolled back; the caller rolls back
/// too. `Display` and `Debug` never contain a destination or another value
/// of the request.
///
/// The enum is `#[non_exhaustive]`: a later task may add a variant.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceWriteError {
    /// The presented credential does not authorize a `trust_admin` of the
    /// source's tenant. Every cause is this one value, with no detail.
    Unauthorized,
    /// The member, [`DISCOVERY_URL`] or [`TOKEN_REVIEW_ENDPOINT`], is not a
    /// destination the syntax rules accept (see the module docs, "Rules").
    InvalidDestination {
        /// The member's name, never its value.
        member: &'static str,
    },
    /// No enabled egress allowlist entry of the member's purpose has exactly
    /// the member's value: no entry, a disabled one, or only one of another
    /// purpose.
    EgressNotAllowed {
        /// The member's name, never its value.
        member: &'static str,
    },
    /// The caller's transaction does not run at `READ COMMITTED` (see the
    /// module docs, "Isolation"). Not retryable as is: the caller retries
    /// in a `READ COMMITTED` transaction.
    UnsupportedIsolation,
    /// A registry error: a store failure, [`RegistryError::Retry`] (retry
    /// the whole transaction), or the write's own outcome, such as
    /// [`RegistryError::NotFound`], [`RegistryError::StaleRevision`] or a
    /// constraint of the `0004` kind checks.
    Registry(RegistryError),
}

impl fmt::Display for SourceWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => {
                f.write_str("the operator may not write this tenant's trust sources")
            }
            Self::InvalidDestination { member } => write!(
                f,
                "trust source {member} is not an https URL with a host, a path and no userinfo \
                 or fragment"
            ),
            Self::EgressNotAllowed { member } => write!(
                f,
                "trust source {member} matches no enabled egress allowlist entry of its purpose"
            ),
            Self::UnsupportedIsolation => {
                f.write_str("trust source writes run only at READ COMMITTED")
            }
            Self::Registry(err) => write!(f, "trust source write failed: {err}"),
        }
    }
}

impl std::error::Error for SourceWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(err) => Some(err),
            _ => None,
        }
    }
}

impl From<RegistryError> for SourceWriteError {
    fn from(err: RegistryError) -> Self {
        Self::Registry(err)
    }
}

impl From<sqlx::Error> for SourceWriteError {
    fn from(err: sqlx::Error) -> Self {
        Self::Registry(err.into())
    }
}

/// A member to check: its name, the purpose of the entries that may match
/// it, and its value.
#[derive(Clone, Copy)]
struct Destination<'a> {
    member: &'static str,
    purpose: EgressPurpose,
    value: &'a str,
}

/// The members that are set, in the fixed check order: `discovery_url`,
/// then `token_review_endpoint`.
fn destinations<'a>(
    discovery_url: Option<&'a str>,
    token_review_endpoint: Option<&'a str>,
) -> Vec<Destination<'a>> {
    [
        (DISCOVERY_URL, EgressPurpose::OidcDiscovery, discovery_url),
        (
            TOKEN_REVIEW_ENDPOINT,
            EgressPurpose::TokenReview,
            token_review_endpoint,
        ),
    ]
    .into_iter()
    .filter_map(|(member, purpose, value)| {
        value.map(|value| Destination {
            member,
            purpose,
            value,
        })
    })
    .collect()
}

/// Checks the syntax of `destination` (see the module docs, "Rules").
fn check_syntax(destination: Destination<'_>) -> Result<(), SourceWriteError> {
    let invalid = || SourceWriteError::InvalidDestination {
        member: destination.member,
    };
    let raw = destination.value;
    let url = Url::parse(raw).map_err(|_| invalid())?;
    // https only, written as such.
    let Some(rest) = raw.strip_prefix(HTTPS_PREFIX) else {
        return Err(invalid());
    };
    if url.scheme() != "https" {
        return Err(invalid());
    }
    // The authority ends where the parser ends it for a special scheme.
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let (authority, after) = rest.split_at(end);
    // A host.
    if authority.is_empty() {
        return Err(invalid());
    }
    // No userinfo, not even an empty one.
    if authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
        return Err(invalid());
    }
    // No fragment, not even an empty one.
    if url.fragment().is_some() {
        return Err(invalid());
    }
    // A path.
    if !after.starts_with('/') {
        return Err(invalid());
    }
    Ok(())
}

/// The new value of a member, when it differs byte-wise from the stored one.
fn changed<'a>(new: &'a Option<String>, stored: Option<&str>) -> Option<&'a str> {
    new.as_deref().filter(|new| Some(*new) != stored)
}

/// Step 0: `READ COMMITTED` only.
async fn require_read_committed(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), SourceWriteError> {
    let isolation: String = sqlx::query_scalar(TRANSACTION_ISOLATION)
        .fetch_one(&mut **transaction)
        .await?;
    if isolation != READ_COMMITTED {
        return Err(SourceWriteError::UnsupportedIsolation);
    }
    Ok(())
}

/// Step 1: a `trust_admin` of `tenant_id`, locked until the transaction
/// ends; the operator's ID.
async fn authorize(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
) -> Result<String, SourceWriteError> {
    let request = OperatorRequest {
        public_identity,
        scope: OperatorScope::Tenant(tenant_id),
        role: AdminRole::TrustAdmin,
    };
    match authorize_operator_locked(transaction, &request).await? {
        Some(operator) => Ok(operator.admin_id),
        None => Err(SourceWriteError::Unauthorized),
    }
}

/// Step 3: each destination's entry `FOR SHARE`, in order; each must be
/// enabled.
async fn check_egress(
    transaction: &mut Transaction<'_, Postgres>,
    destinations: &[Destination<'_>],
) -> Result<(), SourceWriteError> {
    for destination in destinations {
        let entry = sqlx::query(LOCK_ENTRY)
            .bind(destination.purpose.as_str())
            .bind(destination.value)
            .fetch_optional(&mut **transaction)
            .await?;
        let enabled = match entry {
            Some(row) => row.try_get::<&str, _>("status")? == Status::Enabled.as_str(),
            None => false,
        };
        if !enabled {
            return Err(SourceWriteError::EgressNotAllowed {
                member: destination.member,
            });
        }
    }
    Ok(())
}

/// Creates the trust source `new` at revision 1 for the operator whose
/// credential has `public_identity`, after the IR-152 egress check of its
/// `discovery_url` and `token_review_endpoint`, and appends its
/// `trust_source.create` event last, in `transaction` (see the module docs
/// for the rules, the order and the locks). Runs only under
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`.
pub async fn create_source(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewTrustSource,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    let destinations = destinations(
        new.discovery_url.as_deref(),
        new.token_review_endpoint.as_deref(),
    );
    for destination in &destinations {
        check_syntax(*destination)?;
    }
    let mut savepoint = transaction.begin().await?;
    match create_steps(&mut savepoint, public_identity, new, &destinations, audit).await {
        Ok(source) => {
            savepoint.commit().await?;
            Ok(source)
        }
        Err(err) => {
            // The step's error says more than a failed savepoint rollback.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}

/// Steps 0 to 5 of [`create_source`], in its savepoint.
async fn create_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewTrustSource,
    destinations: &[Destination<'_>],
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    require_read_committed(transaction).await?;
    let admin_id = authorize(transaction, public_identity, &new.tenant_id).await?;
    check_egress(transaction, destinations).await?;
    let source = create_trust_source(&mut **transaction, new).await?;
    append_audit_event(
        transaction,
        &NewAuditEvent {
            id: audit.event_id.into(),
            tenant_id: Some(source.tenant_id.clone()),
            timestamp: audit.now,
            actor: AuditActor::Operator(admin_id),
            action: CREATE_ACTION.into(),
            object_id: source.id.clone(),
            previous_revision: None,
            new_revision: Some(source.revision),
            outcome: SUCCESS.into(),
        },
    )
    .await?;
    Ok(source)
}

/// Replaces the mutable columns of the trust source `id` of `tenant_id` at
/// `expected_revision` with `changes` for the operator whose credential has
/// `public_identity`, after the IR-152 egress check of each of
/// `discovery_url` and `token_review_endpoint` that changes, and appends
/// its `trust_source.update` event last, in `transaction` (see the module
/// docs). A member left unchanged is not checked. Runs only under
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`.
pub async fn update_source(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustSourceChanges,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    let target = (tenant_id, id, expected_revision);
    let mut savepoint = transaction.begin().await?;
    match update_steps(&mut savepoint, public_identity, target, changes, audit).await {
        Ok(source) => {
            savepoint.commit().await?;
            Ok(source)
        }
        Err(err) => {
            // The step's error says more than a failed savepoint rollback.
            let _ = savepoint.rollback().await;
            Err(err)
        }
    }
}

/// Steps 0 to 5 of [`update_source`], in its savepoint. `target` is the
/// tenant, the ID and the expected revision.
async fn update_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    (tenant_id, id, expected_revision): (&str, &str, i64),
    changes: &TrustSourceChanges,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    require_read_committed(transaction).await?;
    let admin_id = authorize(transaction, public_identity, tenant_id).await?;
    let Some(stored) = sqlx::query(LOCK_SOURCE)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?
    else {
        return Err(RegistryError::NotFound.into());
    };
    let stored_revision: i64 = stored.try_get("revision")?;
    if stored_revision != expected_revision {
        return Err(RegistryError::StaleRevision.into());
    }
    let stored_discovery: Option<&str> = stored.try_get("discovery_url")?;
    let stored_token_review: Option<&str> = stored.try_get("token_review_endpoint")?;
    let destinations = destinations(
        changed(&changes.discovery_url, stored_discovery),
        changed(&changes.token_review_endpoint, stored_token_review),
    );
    for destination in &destinations {
        check_syntax(*destination)?;
    }
    check_egress(transaction, &destinations).await?;
    let source = update_trust_source(
        &mut **transaction,
        tenant_id,
        id,
        expected_revision,
        changes,
    )
    .await?;
    append_audit_event(
        transaction,
        &NewAuditEvent {
            id: audit.event_id.into(),
            tenant_id: Some(source.tenant_id.clone()),
            timestamp: audit.now,
            actor: AuditActor::Operator(admin_id),
            action: UPDATE_ACTION.into(),
            object_id: source.id.clone(),
            previous_revision: Some(stored_revision),
            new_revision: Some(source.revision),
            outcome: SUCCESS.into(),
        },
    )
    .await?;
    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(member: &'static str, value: &str) -> Result<(), SourceWriteError> {
        let purpose = EgressPurpose::OidcDiscovery;
        check_syntax(Destination {
            member,
            purpose,
            value,
        })
    }

    #[test]
    fn https_urls_with_a_host_and_a_path_pass() {
        for value in [
            "https://issuer.example/.well-known/openid-configuration",
            "https://issuer.example/",
            "https://k3s.internal.example:6443/",
            "https://[::1]:8443/x",
            "https://192.0.2.1/x",
            "https://issuer.example/x?y=1",
            "https://ISSUER.example/X",
        ] {
            assert!(check(DISCOVERY_URL, value).is_ok(), "{value}");
        }
    }

    #[test]
    fn other_destinations_are_refused_naming_only_the_member() {
        for value in [
            "",
            "not a url",
            "issuer.example/x",
            "http://issuer.example/x",
            "ftp://issuer.example/x",
            "HTTPS://issuer.example/x",
            "https:issuer.example/x",
            "https:/issuer.example/x",
            "https:\\\\issuer.example\\x",
            "https:///x",
            "https://:443/x",
            "https://user@issuer.example/x",
            "https://user:pw@issuer.example/x",
            "https://@issuer.example/x",
            "https://:@issuer.example/x",
            "https://issuer.example/x#frag",
            "https://issuer.example/x#",
            "https://issuer.example",
            "https://issuer.example:443",
            "https://issuer.example?x",
            "https://issuer.example#x",
            "https://issuer.example\\x",
            "https://iss uer.example/x",
        ] {
            for member in [DISCOVERY_URL, TOKEN_REVIEW_ENDPOINT] {
                let err = check(member, value).expect_err(value);
                assert!(
                    matches!(err, SourceWriteError::InvalidDestination { member: m } if m == member),
                    "{value}: {err:?}"
                );
                for text in [err.to_string(), format!("{err:?}")] {
                    assert!(text.contains(member), "{text}");
                    assert!(value.is_empty() || !text.contains(value), "{text}");
                    assert!(!text.contains("issuer.example"), "{text}");
                }
            }
        }
    }

    #[test]
    fn destinations_keep_the_fixed_order_and_skip_unset_members() {
        fn names(d: Vec<Destination<'_>>) -> Vec<(&'static str, EgressPurpose, &str)> {
            d.iter().map(|d| (d.member, d.purpose, d.value)).collect()
        }
        assert_eq!(
            names(destinations(Some("a"), Some("b"))),
            [
                (DISCOVERY_URL, EgressPurpose::OidcDiscovery, "a"),
                (TOKEN_REVIEW_ENDPOINT, EgressPurpose::TokenReview, "b"),
            ]
        );
        assert_eq!(
            names(destinations(None, Some("b"))),
            [(TOKEN_REVIEW_ENDPOINT, EgressPurpose::TokenReview, "b")]
        );
        assert!(destinations(None, None).is_empty());
    }

    #[test]
    fn the_locks_name_their_rows_exactly() {
        assert_eq!(
            LOCK_ENTRY,
            "SELECT id, status FROM egress_allowlist_entry \
             WHERE purpose = $1 AND exact_destination = $2 FOR SHARE"
        );
        assert!(LOCK_SOURCE.ends_with("WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE"));
    }

    #[test]
    fn errors_print_fixed_text() {
        for (err, text) in [
            (
                SourceWriteError::Unauthorized,
                "the operator may not write this tenant's trust sources",
            ),
            (
                SourceWriteError::EgressNotAllowed {
                    member: TOKEN_REVIEW_ENDPOINT,
                },
                "trust source token_review_endpoint matches no enabled egress allowlist entry \
                 of its purpose",
            ),
            (
                SourceWriteError::UnsupportedIsolation,
                "trust source writes run only at READ COMMITTED",
            ),
            (
                SourceWriteError::Registry(RegistryError::StaleRevision),
                "trust source write failed: registry row is not at the expected revision; \
                 read it again",
            ),
        ] {
            assert_eq!(err.to_string(), text);
        }
    }
}
