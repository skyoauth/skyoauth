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
//! T00.17, Gate M0). Three rulings below are the user's (2026-11-22,
//! relayed by the lead), not provisional picks: canonical-form
//! destinations as the convention (end of "Rules"), source writes as
//! widening, and the database backstop (both under "Not done here").
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
//!   column is `COLLATE "C"`, so `=` compares bytes). The member is in
//!   canonical form (see "Syntax"), so only an entry in canonical form can
//!   match it. A `jwks` entry, or an entry of the other purpose, never
//!   satisfies a member. The entry must be `enabled`: a missing or disabled
//!   entry is [`SourceWriteError::EgressNotAllowed`] naming the member.
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
//! - **Syntax.** A checked member must be an `https` URL in canonical form
//!   with a host and no userinfo or fragment (lead ruling, 2026-11-22;
//!   inferred). In order:
//!   - its text has no ASCII whitespace, no control character (NUL
//!     included) and no backslash, which the parser would strip, drop or
//!     read as `/`;
//!   - the `url` crate parses it, and the parsed URL serializes to exactly
//!     the same text (`Url::as_str() == raw`);
//!   - every `%` starts an escape of two hex digits, and no escape encodes
//!     an unreserved character (a letter, a digit, `-`, `.`, `_` or `~`).
//!     The parser keeps both an incomplete or non-hex escape (`%`, `%4`,
//!     `%zz`, reported only as a syntax violation) and an escaped unreserved
//!     character in a path or query as they are, so the round trip alone
//!     does not refuse them (inferred);
//!   - its scheme is `https`, it has a non-empty host, no userinfo and no
//!     fragment, not even an empty `@` or `#`.
//!
//!   Canonical form makes the text an operator approves name the host,
//!   port and path that are fetched. Otherwise the parser would fetch
//!   `good.example` for `%67ood.example`, `127.0.0.1` for `0x7f.1`,
//!   `0177.0.0.1` or `127.1`, an `xn--` A-label for a U-label, or
//!   `example.com` for a fullwidth or ideographic-dot spelling. It would
//!   also lowercase the host and scheme, compress an IPv6 address, drop a
//!   default or empty port, a zero-width character, a soft hyphen or a dot
//!   segment, and read `a\b` as `a/b`.
//!
//!   A path of at least `/` follows from canonical form (`https://h:6443`
//!   is not canonical, `https://h:6443/` is); IR-152 does not require it.
//!   IR-152 names scheme, host, port and path as the parts of an exact URL,
//!   but it does not require a port to be written: canonical form leaves a
//!   default port out. A query is allowed (no rule names it).
//!
//!   This check is about spelling, not about where an address points. A
//!   canonical loopback, link-local, private or cloud-metadata address
//!   (`https://127.0.0.1/`, `https://169.254.169.254/`) or an IPv4-mapped
//!   IPv6 address passes it when an entry lists it. A policy on such
//!   addresses, and on what a host name resolves to, belongs to the
//!   fetcher (T11.2, T11.8) or the egress entry writer, not here
//!   (inferred).
//!
//!   A refused member is [`SourceWriteError::InvalidDestination`] naming
//!   the member. A create checks the syntax before any statement. An update
//!   checks only a changed member, like the entry check: after it has read
//!   the stored row and before any egress entry lock (inferred: an
//!   unchanged member is never refused, also not by a syntax rule that
//!   tightened after it was stored).
//!
//!   Canonical-form egress destinations are the convention (ruled by the
//!   user, 2026-11-22, relayed by the lead): an egress entry writer must
//!   enforce this same rule on `exact_destination`, and an importer (C05)
//!   must rewrite a path-less, kubeconfig-style server URL
//!   (`https://host:6443`, the export's `api_server`, OQ-IR-6), which this
//!   check refuses, to canonical form. Neither exists yet: nothing checks
//!   today that an entry's `exact_destination` is canonical, and entries
//!   are matched byte for byte, so a non-canonical entry matches no source.
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
//!    `FOR NO KEY UPDATE`, and reads the stored destinations and revision.
//!    A missing row is [`RegistryError::NotFound`] and another revision
//!    [`RegistryError::StaleRevision`], both before any entry lock. A
//!    concurrent update of the same source waits here, holding no entry
//!    lock, and then reads the committed revision: `StaleRevision`, not a
//!    deadlock;
//! 3. for each member to check, in the fixed order `discovery_url`, then
//!    `token_review_endpoint`, the matching `egress_allowlist_entry` row
//!    `FOR SHARE`, by `purpose` and `exact_destination` (unique together, so
//!    at most one row each). No kind has both members, so a valid write
//!    locks at most one entry; the fixed order covers a write that sets
//!    both, which the kind checks then reject;
//! 4. the registry write: the insert (whose foreign-key checks take
//!    `FOR KEY SHARE` on the tenant and, for `uploaded_jwks`, the keyset) or
//!    the compare-and-set update. Every compare-and-set takes the source
//!    row `FOR UPDATE` until the transaction ends, whatever it changes, a
//!    status-only write or one that changes nothing included.
//!    [`update_trust_source`] always sets `name`, a column of the unique key
//!    `(tenant_id, name)`. With the `BEFORE UPDATE` row triggers of
//!    `trust_source` (`trust_source_immutable`, `trust_source_revision`),
//!    PostgreSQL chooses the row lock from the columns in the `SET` list,
//!    not from the values that change. `FOR UPDATE` conflicts with the
//!    `FOR KEY SHARE` of a foreign-key check. So, from the compare-and-set
//!    until the commit, every `principal_binding` and `consumed_assertion`
//!    insert that references the source waits, or fails with `55P03` under
//!    a `lock_timeout`; that is, binding writes and token exchanges through
//!    the source. The steps before it (the `FOR NO KEY UPDATE` of step 2
//!    and the operator locks) do not block those inserts. Callers must
//!    commit promptly after an update;
//! 5. [`append_audit_event`] last, which locks the tenant row
//!    `FOR KEY SHARE` and then the chain head (migrations README, "append
//!    audit events in this order"). It must stay after the compare-and-set.
//!    An update that held the head while its compare-and-set waited for a
//!    consumer's `FOR KEY SHARE` would deadlock with that consumer's own
//!    audit append;
//!
//! So the lock order is: operator rows, then the source row
//! (`FOR NO KEY UPDATE`, update only; `FOR UPDATE` from step 4 on), then
//! the egress entry rows
//! (`FOR SHARE`, discovery before TokenReview), then the write's own locks,
//! then the audit head. This differs from step 1 of "What 0005 adds" in the
//! migrations README, which orders the `0002` to `0004` tables by name
//! (`egress_allowlist_entry` before `trust_source`): that order is for a
//! write that creates an `administrative_operation`, which this one does
//! not, and an update must read the stored row before it knows which entry
//! to lock. An egress entry writer that locked a trust source row after an
//! entry row would deadlock with an update here; PostgreSQL fails one of
//! them with `40P01` ([`RegistryError::Retry`]), a refusal for this write.
//! No egress entry writer exists yet. One that creates an operation must
//! lock no `trust_source` row at all. It may list the affected source IDs
//! without a lock only after its entry `UPDATE`, under `READ COMMITTED`:
//! a source write that checked the entry has committed by then, since the
//! `UPDATE` waited for its `FOR SHARE`, and a later one sees the new status.
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
//! lead pick, 2026-11-22, open; the action table's convention would name a
//! status-only write `trust_source.enable` or `trust_source.disable`, which
//! have no writer yet; see `persistence::registry::event_actions`). The
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
//!   and before the T14.1 and T14.2 design of the second-approver flow,
//!   since a wired write would apply a widening source write without the
//!   approval IR-052 requires.
//! - Widening: a trust source write counts as widening and needs an IR-054
//!   approval by a second approver while `widening_second_approver` is on
//!   (ruled by the user, 2026-11-22, relayed by the lead; this decides the
//!   IR-052 widening question for this write). What remains is the design
//!   of the second-approver flow (T14.1, T14.2); no write here waits for an
//!   approval.
//! - The fetch-time match of a discovered `jwks_uri` against an enabled
//!   `jwks` entry, the degraded health signal and the fetches themselves
//!   (IR-152; T11.2, T11.8).
//! - `ca_bundle_ref` and `reviewer_credential_ref` resolution within the
//!   tenant's secret namespace (IR-034), tenant status (the operator lookup
//!   does not read it), and the other source rules of T11.1 and T11.8.
//! - A database backstop for the egress check. The trigger of
//!   `docs/proposals/ir-080-assignment-write-guard.md` (IR-080 assignment
//!   references) is accepted and, for that table family, is migration
//!   `0010`; the same trigger pattern is to guard this check too: a
//!   `trust_source` destination against `egress_allowlist_entry` (ruled by
//!   the user, 2026-11-22, relayed by the lead). Accepted; implementation
//!   pending: the migrations `0001` to `0009` are frozen, and no migration
//!   adds the egress guard yet. Until it exists, the bare registry functions
//!   still write any destination the `0004` checks allow.
//!
//! [`authorize_operator_locked`]: crate::persistence::registry::authorize_operator_locked
//! [`OperatorScope::Tenant`]: crate::persistence::registry::OperatorScope::Tenant
//! [`AdminRole::TrustAdmin`]: crate::persistence::registry::AdminRole::TrustAdmin

use std::{fmt, time::SystemTime};

use sqlx::{Postgres, Row, Transaction};
use url::Url;

use super::write::{WriteError, authorize_trust_admin, in_savepoint, require_read_committed};
use crate::persistence::registry::{
    AuditActor, EgressPurpose, NewAuditEvent, NewTrustSource, RegistryError, Status, TrustSource,
    TrustSourceChanges, append_audit_event, create_trust_source, update_trust_source,
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

/// Step 2 of an update: the stored row, locked before any entry so that a
/// concurrent update of the source waits here and holds no entry lock. Its
/// compare-and-set (step 4) then takes the row `FOR UPDATE`, which blocks
/// foreign-key inserts that reference the source until the commit (see the
/// module docs, "Order and locks").
const LOCK_SOURCE: &str = "SELECT discovery_url, token_review_endpoint, revision \
     FROM trust_source WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE";

/// Step 3: the entry of one purpose with exactly this destination.
const LOCK_ENTRY: &str = "SELECT id, status FROM egress_allowlist_entry \
     WHERE purpose = $1 AND exact_destination = $2 FOR SHARE";

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
                "trust source {member} is not a canonical https URL with a host and no userinfo \
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

impl WriteError for SourceWriteError {
    const UNSUPPORTED_ISOLATION: Self = Self::UnsupportedIsolation;
    const UNAUTHORIZED: Self = Self::Unauthorized;
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
    // Characters the parser strips, drops or reads as `/`.
    if raw
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control() || c == '\\')
    {
        return Err(invalid());
    }
    let url = Url::parse(raw).map_err(|_| invalid())?;
    // Canonical form: the text is what the parser serializes, so it names
    // the host, port and path that are fetched.
    if url.as_str() != raw || bad_escape(raw) {
        return Err(invalid());
    }
    if url.scheme() != "https" || url.host_str().is_none_or(str::is_empty) {
        return Err(invalid());
    }
    // No userinfo and no fragment, not even an empty one.
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid());
    }
    Ok(())
}

/// Whether `raw` has a `%` that is not a valid escape of a character that
/// must stay encoded. That is either an incomplete or non-hex escape (`%`,
/// `%4`, `%zz`), which the parser keeps as it is while it reports only a
/// syntax violation, or an escape of an unreserved character (RFC 3986
/// section 2.3: a letter, a digit, `-`, `.`, `_` or `~`), which the parser
/// leaves encoded in a path or a query.
fn bad_escape(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.iter().enumerate().any(|(at, &byte)| {
        if byte != b'%' {
            return false;
        }
        let Some(&[high, low]) = bytes.get(at + 1..at + 3) else {
            return true;
        };
        let (Some(high), Some(low)) = (hex(high), hex(low)) else {
            return true;
        };
        let decoded = high << 4 | low;
        decoded.is_ascii_alphanumeric() || matches!(decoded, b'-' | b'.' | b'_' | b'~')
    })
}

/// The value of one hex digit.
fn hex(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// The new value of a member, when it differs byte-wise from the stored one.
fn changed<'a>(new: &'a Option<String>, stored: Option<&str>) -> Option<&'a str> {
    new.as_deref().filter(|new| Some(*new) != stored)
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
    in_savepoint(transaction, async |savepoint| {
        create_steps(savepoint, public_identity, new, &destinations, audit).await
    })
    .await
}

/// Steps 0 to 5 of [`create_source`], in its savepoint.
async fn create_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewTrustSource,
    destinations: &[Destination<'_>],
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    require_read_committed::<SourceWriteError>(transaction).await?;
    let admin_id =
        authorize_trust_admin::<SourceWriteError>(transaction, public_identity, &new.tenant_id)
            .await?;
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
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`,
/// promptly: until then the source row is locked `FOR UPDATE`, and every
/// `principal_binding` or `consumed_assertion` insert that references the
/// source waits.
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
    in_savepoint(transaction, async |savepoint| {
        update_steps(savepoint, public_identity, target, changes, audit).await
    })
    .await
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
    require_read_committed::<SourceWriteError>(transaction).await?;
    let admin_id =
        authorize_trust_admin::<SourceWriteError>(transaction, public_identity, tenant_id).await?;
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
    fn canonical_https_urls_with_a_host_pass() {
        for value in [
            "https://issuer.example/.well-known/openid-configuration",
            "https://issuer.example/",
            "https://k3s.internal.example:6443/",
            "https://[::1]:8443/x",
            "https://[2001:db8::1]/x",
            "https://192.0.2.1/x",
            "https://issuer.example/x?y=1",
            "https://issuer.example/X/Y",
            "https://xn--bcher-kva.example/",
            "https://issuer.example/a%2Fb",
            "https://issuer.example/a%2fb",
            "https://issuer.example/a%20b",
            "https://issuer.example./x",
        ] {
            assert!(check(DISCOVERY_URL, value).is_ok(), "{value}");
            assert!(check(TOKEN_REVIEW_ENDPOINT, value).is_ok(), "{value}");
        }
    }

    /// Spellings that the parser would fetch as another text: each is
    /// refused, naming only the member.
    #[test]
    fn non_canonical_spellings_are_refused() {
        for (case, value) in [
            ("fullwidth letter", "https://ｉssuer.example/x"),
            ("fullwidth dot", "https://issuer．example/x"),
            ("ideographic dot", "https://issuer。example/x"),
            ("halfwidth ideographic dot", "https://issuer｡example/x"),
            ("zero-width space", "https://iss\u{200B}uer.example/x"),
            ("zero-width joiner", "https://iss\u{200D}uer.example/x"),
            ("soft hyphen", "https://iss\u{AD}uer.example/x"),
            ("U-label", "https://bücher.example/x"),
            ("upper-case U-label", "https://BÜCHER.example/x"),
            ("hex IPv4", "https://0x7f.0.0.1/x"),
            ("hex IPv4 number", "https://0x7f000001/x"),
            ("octal IPv4", "https://0177.0.0.1/x"),
            ("short IPv4", "https://127.1/x"),
            ("decimal IPv4 number", "https://2130706433/x"),
            ("uncompressed IPv6", "https://[0:0:0:0:0:0:0:1]/x"),
            ("leading-zero IPv6", "https://[2001:0db8::1]/x"),
            ("upper-case IPv6", "https://[2001:DB8::1]/x"),
            ("mapped IPv4 in IPv6", "https://[::ffff:127.0.0.1]/x"),
            ("empty port", "https://issuer.example:/x"),
            ("zero-padded port", "https://issuer.example:06443/x"),
            ("default port", "https://issuer.example:443/x"),
            ("no path", "https://h.example:6443"),
            ("no path, default port", "https://issuer.example:443"),
            ("dot-dot segment", "https://issuer.example/a/../b"),
            ("dot segment", "https://issuer.example/./x"),
            ("encoded dot segment", "https://issuer.example/a/%2e%2e/b"),
            ("encoded host letter", "https://%67ood.example/x"),
            ("encoded path letter", "https://issuer.example/%67"),
            (
                "encoded hyphen",
                "https://issuer.example/openid%2Dconfiguration",
            ),
            ("encoded tilde", "https://issuer.example/%7Euser"),
            ("encoded digit", "https://issuer.example/v%31"),
            ("encoded query letter", "https://issuer.example/x?a=%62"),
            ("upper-case host", "https://ISSUER.example/x"),
            ("mixed-case host", "https://Issuer.Example/x"),
            ("upper-case scheme", "HTTPS://issuer.example/x"),
            ("mixed-case scheme", "Https://issuer.example/x"),
            ("unencoded path character", "https://issuer.example/ü"),
            ("unencoded quote in query", "https://issuer.example/x?a='b'"),
            ("trailing space", "https://issuer.example/x "),
            ("leading space", " https://issuer.example/x"),
            ("trailing tab", "https://issuer.example/x\t"),
            ("inner tab", "https://issuer.example/a\tb"),
            ("trailing newline", "https://issuer.example/x\n"),
            ("inner newline", "https://issuer.ex\nample/x"),
            ("carriage return", "https://issuer.example/x\r"),
            ("trailing NUL", "https://issuer.example/x\0"),
            ("inner NUL", "https://issuer.example\0/x"),
            ("C1 control", "https://issuer.example/x\u{85}"),
            ("backslash", "https://a\\b"),
            ("backslash path", "https://issuer.example\\x"),
            ("backslash in path", "https://issuer.example/a\\b"),
            // The parser keeps this one: only the character check refuses
            // it.
            ("backslash in query", "https://issuer.example/x?a\\b"),
            // Incomplete or non-hex escapes, which the parser keeps.
            ("bare % in path", "https://issuer.example/a%b"),
            ("trailing % in path", "https://issuer.example/a%"),
            ("incomplete escape in path", "https://issuer.example/a%4"),
            (
                "incomplete escape mid-segment",
                "https://issuer.example/a%4/b",
            ),
            ("non-hex escape in path", "https://issuer.example/a%zzb"),
            ("half-hex escape in path", "https://issuer.example/a%4g"),
            ("bare % in query", "https://issuer.example/x?a=%&b"),
            ("trailing % in query", "https://issuer.example/x?a=%"),
            (
                "incomplete escape in query",
                "https://issuer.example/x?a=%4",
            ),
            ("non-hex escape in query", "https://issuer.example/x?a=%zz"),
            ("non-hex letters g-z in path", "https://issuer.example/a%gg"),
            (
                "non-hex letters g-z in query",
                "https://issuer.example/x?a=%gg",
            ),
            (
                "bad escape after a valid one",
                "https://issuer.example/%2F%zz",
            ),
            (
                "trailing % after a valid escape",
                "https://issuer.example/a%20b%",
            ),
        ] {
            for member in [DISCOVERY_URL, TOKEN_REVIEW_ENDPOINT] {
                let err = check(member, value).expect_err(case);
                assert!(
                    matches!(err, SourceWriteError::InvalidDestination { member: m } if m == member),
                    "{case}: {err:?}"
                );
                for text in [err.to_string(), format!("{err:?}")] {
                    assert!(!text.contains(value), "{case}: {text}");
                    assert!(!text.contains("example"), "{case}: {text}");
                }
            }
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
            "https://ISSUER.example/X",
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
