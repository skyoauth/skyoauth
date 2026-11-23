//! The second-approver flow of gated writes
//! (`docs/proposals/second-approver-gated-writes.md`, PR 3; IR-052 to
//! IR-054; tasks section 2, the approve endpoints): the request digest, the
//! operation kinds, the approval ([`prepare_approval`], then
//! [`approve_operation`]), its cancel and reject ([`cancel_operation`],
//! [`reject_operation`]), and the first gated kind, the toggle of
//! `widening_second_approver` ([`submit_widening_toggle`]; D16).
//!
//! Every pick below is the proposal's (a provisional lead pick, 2026-11-23,
//! D1 to D29) unless marked (inferred); all of them stay provisional until
//! the maintainer ratifies the ADRs (T00.8 to T00.17, Gate M0).
//!
//! # Not wired
//!
//! Nothing calls these functions yet: no endpoint, and nothing at startup.
//! No endpoint lands before the request layer exists (generated IDs, T10.2;
//! the raw body bound; NUL rejection; the role of each endpoint; T13.3).
//! The trust kinds (`trust_keyset_version_create`, `_enable`,
//! `trust_source_create`, `_update`) and their `submit_*` writes come with
//! PRs 4 and 5 of the proposal: until then [`OperationKind`] has the toggle
//! only, and any other stored kind is [`NotApprovableReason::WrongKind`]
//! (inferred).
//!
//! # The pending operation
//!
//! A pending gated write is one `administrative_operation` row (section 2):
//! the requester as `actor_id`, the kind, the request digest ([`DigestEnvelope`]), the
//! target's revision as `expected_revision`, the plan, `expires_at` the
//! request's `now` plus [`PENDING_OPERATION_TTL`] floored to a whole
//! microsecond (D5), outcome `pending`, and as `audit_id` the
//! `administrative_operation.create` event, appended first. Its outcome
//! becomes `applied`, `cancelled` or `rejected`, and stays `pending` after
//! expiry (D22). Every plan holds `requester_credential_id`, the
//! credential the request was authorized with (D21); the toggle's plan holds
//! `widening_second_approver` too, and nothing else (inferred: no version
//! member, since the digest prefix carries the version). No plan holds a
//! secret.
//!
//! # Approve
//!
//! [`prepare_approval`] runs outside any transaction: it authorizes first
//! (the approver's lookup, an instance `security_admin`, a miss is
//! [`ApprovalError::Unauthorized`]), then reads the operation's immutable
//! columns and state without a lock (another scope is
//! [`ApprovalError::NotFound`], the approver's own operation
//! [`ApprovalError::SelfApproval`], then the kind, consumed, revoked and
//! expired, [`ApprovalError::NotApprovable`]), and only then reads the
//! digest and the plan and parses it (D20). A toggle's plan that is not
//! exactly its two members is [`ApprovalError::PlanIntegrity`].
//!
//! [`approve_operation`] runs in a savepoint of the caller's transaction,
//! only under `READ COMMITTED` (section 3, approve steps 2 to 7):
//!
//! 1. the transaction's isolation ([`ApprovalError::UnsupportedIsolation`]);
//! 2. without a lock: the approver's lookup, then the operation's immutable
//!    `tenant_id`, `actor_id` and `kind` (the scope, self-approval and the
//!    kind, as above), then its plan's `requester_credential_id` (a plan
//!    without it is [`ApprovalError::PlanIntegrity`]). The kind is checked
//!    here, not under the row lock: the requester's role, which the next
//!    step locks, depends on it, and the kind and the plan are immutable
//!    (section 3, approve step 2);
//! 3. both operators' rows `FOR SHARE` in the `0005` order
//!    ([`authorize_approval_locked`]): the approver, the requester's
//!    submitting credential, identity and role (Q5; D21; a refusal is
//!    [`ApprovalError::Unauthorized`], [`ApprovalError::SelfApproval`] or
//!    [`ApprovalError::RequesterNotAuthorized`]);
//! 4. the operation row `FOR NO KEY UPDATE`: consumed or revoked is
//!    [`ApprovalError::NotApprovable`]; a stored digest or expected
//!    revision unequal to the echo, or a digest unequal to the one
//!    [`prepare_approval`] read, is [`ApprovalError::EchoMismatch`]; a
//!    digest recomputed from the stored row unequal to the stored one, or a
//!    locked plan unequal to the one [`prepare_approval`] parsed (D24 for
//!    the toggle, inferred), is [`ApprovalError::PlanIntegrity`];
//! 5. the kind's post-authorization step (D26). The toggle: the policy row
//!    `FOR NO KEY UPDATE` (missing: [`ApprovalError::PolicyUnavailable`],
//!    D18), its revision against `expected_revision`
//!    ([`ApprovalError::StaleRevision`], D19), and its compare-and-set. It
//!    returns the row and its domain event, unstamped;
//! 6. **the clock** (D28): the injected [`Clock`] is sampled once, after
//!    the registry write and before the first append, and floored to a
//!    whole microsecond. `now >= expires_at` is
//!    [`NotApprovableReason::Expired`], and the savepoint rollback undoes
//!    the write, so nothing is written. Every lock wait comes before the
//!    sample; only the append's own waits (the tenant row
//!    `FOR KEY SHARE` and the audit head) come after it (Limits);
//! 7. through [`append_audit_event`]: `administrative_operation.approve`
//!    (the approver as actor, the pending operation as `object_id`, its
//!    revision and the next), the `approve` operation (the approver, the
//!    pending operation as `approves_operation_id`, its tenant, digest and
//!    expected revision copied, plan `{}`, no expiry, outcome `success`),
//!    the domain event (the requester as actor, outcome `success`), then
//!    the pending row consumed at the sample with outcome `applied`.
//!
//! One clock sample is the time of both events and the `consumed_at`.
//!
//! # Cancel and reject
//!
//! Both run in a savepoint, only under `READ COMMITTED`: the actor's lookup
//! without a lock, the operation's immutable columns (the scope check as in
//! the approve), the actor's rows `FOR SHARE`
//! ([`authorize_operator_locked`]), the operation row `FOR NO KEY UPDATE`
//! (consumed or already revoked is [`ApprovalError::NotApprovable`]; an
//! expired operation may still be revoked), then the audit head: the event
//! (`administrative_operation.cancel` or `.reject`, the actor, the pending
//! operation as `object_id`, its revision and the next), the revoking
//! operation (kind `cancel` or `reject`, its digest and expected revision
//! copied, plan `{}`, no expiry, outcome `success`, inferred as for the
//! approve), and the pending row revoked with outcome `cancelled` or
//! `rejected`.
//!
//! - **Cancel** is by the requester: the presented credential's operator
//!   must be the operation's `actor_id` and still hold the kind's role,
//!   through any enabled, unrevoked credential of that identity (section
//!   3). The role is looked up from the path before the operation is read
//!   (inferred: every kind of the flow on the instance path is an instance
//!   `security_admin` write, the toggle, and on a tenant path a tenant
//!   `trust_admin` write, section 6), so a caller without it learns
//!   nothing about the operation. Another operator, a `security_admin`
//!   included, is [`ApprovalError::Unauthorized`] (inferred).
//! - **Reject** is by an instance `security_admin` who is not the
//!   requester: the requester is [`ApprovalError::SelfApproval`]
//!   (inferred: the approve's refusal, since a reject is the approver's
//!   decision).
//!
//! # The toggle
//!
//! [`submit_widening_toggle`] requests a change of
//! `widening_second_approver` (section 3, "The toggle"; D16, D19): in a
//! savepoint, only under `READ COMMITTED`, the requester's instance
//! `security_admin` rows `FOR SHARE`, then the policy row
//! `FOR NO KEY UPDATE`, never `FOR SHARE`, in both branches (a missing row
//! is [`ApprovalError::PolicyUnavailable`]), and its revision against the
//! request's `expected_revision` ([`ApprovalError::StaleRevision`]). With
//! `single_actor_mode` on it applies at once: the compare-and-set and
//! `instance_security_policy.update` with outcome `success_single_actor`.
//! Otherwise it goes pending, whatever the current or the requested value,
//! for a distinct `security_admin` to approve on the instance path: turning
//! the setting on or off needs that approver (IR-052,
//! `docs/contracts/identity-registry.md:423-427`; tasks:147;
//! ADR-008:100-103). A request for the current value (a no-op) is accepted
//! like any other (inferred): applied at once it writes the same value at
//! the next revision; pending, its approval only advances the revision, so
//! every other pending toggle goes stale at its approval. The
//! `acknowledge_widening` flag of the [`Submission`] is ignored: whether
//! the toggle needs it is not decided (proposal, "Not decided here";
//! inferred). The authorization is the toggle's own, instance
//! `security_admin` through [`authorize_operator_locked`] (tasks:147), not
//! the trust writes' `authorize_trust_admin` of PR 4.
//!
//! # Lock order
//!
//! As the proposal declares ("Lock order"): the operator rows `FOR SHARE`
//! in the `0005` order; the pending operation row `FOR NO KEY UPDATE`
//! (approve, cancel, reject); the policy row `FOR NO KEY UPDATE` (the
//! toggle, request and approve); the registry write; the audit head last.
//! One operation is applied per transaction (D17). A `40001` or `40P01` is
//! [`RegistryError::Retry`] in [`ApprovalError::Registry`].
//!
//! # Errors and rollback
//!
//! Every function but [`prepare_approval`] runs in a savepoint of the
//! caller's transaction, releases it on `Ok` and rolls it back on `Err`: an
//! `Err` leaves no operation, no event and no target change, and the
//! caller's transaction usable. Refusals are not audited. No error's
//! `Display` or `Debug` holds a digest, an ID, a revision or another value
//! of the request (section 10).
//!
//! [`authorize_approval_locked`]: crate::persistence::registry::authorize_approval_locked
//! [`authorize_operator_locked`]: crate::persistence::registry::authorize_operator_locked
//! [`append_audit_event`]: crate::persistence::registry::append_audit_event
//! [`RegistryError::Retry`]: crate::persistence::registry::RegistryError::Retry

mod approval;
mod digest;
mod toggle;

use std::{
    fmt,
    time::{Duration, SystemTime},
};

pub use approval::{
    PreparedApproval, approve_operation, cancel_operation, prepare_approval, reject_operation,
};
pub use digest::{DIGEST_PREFIX, DigestEnvelope, DigestLengthError, NotCanonical, RequestDigest};
pub use toggle::submit_widening_toggle;

use crate::persistence::registry::{
    AdminRole, AuditActor, InstanceSecurityPolicy, NewAuditEvent, OperatorScope, RegistryError,
};
use crate::trust::write::WriteError;

/// How long a pending operation stays approvable (D5; Q1, ruled by the
/// user, 2026-11-23).
pub const PENDING_OPERATION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The plan member that names the requester's submitting credential (D21).
pub const PLAN_REQUESTER_CREDENTIAL_ID: &str = "requester_credential_id";

/// The toggle's plan member: the requested value.
pub const PLAN_WIDENING_SECOND_APPROVER: &str = "widening_second_approver";

/// The outcome of a pending operation (inferred values, section 2).
pub const OUTCOME_PENDING: &str = "pending";
/// The outcome of an approved operation.
pub const OUTCOME_APPLIED: &str = "applied";
/// The outcome of an operation its requester cancelled.
pub const OUTCOME_CANCELLED: &str = "cancelled";
/// The outcome of an operation an approver rejected.
pub const OUTCOME_REJECTED: &str = "rejected";
/// The outcome of an event, and of an `approve`, `cancel` or `reject`
/// operation.
pub const OUTCOME_SUCCESS: &str = "success";
/// The outcome of the event of a write applied at once under
/// `single_actor_mode` (section 7; Q4; inferred value, as section 7's whole
/// value set).
pub const OUTCOME_SUCCESS_SINGLE_ACTOR: &str = "success_single_actor";

/// A kind of gated write (section 2; inferred names). `#[non_exhaustive]`:
/// the trust kinds come with PRs 4 and 5.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// A change of `widening_second_approver` (the toggle).
    InstanceSecurityPolicyUpdate,
}

impl OperationKind {
    /// Every kind.
    pub const ALL: &[Self] = &[Self::InstanceSecurityPolicyUpdate];

    /// The `kind` column's value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstanceSecurityPolicyUpdate => "instance_security_policy_update",
        }
    }

    /// The kind whose name is exactly `name` (byte-wise), if any.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|kind| kind.as_str() == name)
    }

    /// The scope and role the requester of an operation of this kind in
    /// `tenant_id` holds (section 6), or `None` when the kind does not
    /// belong to that scope (a toggle names no tenant).
    fn requester_role(self, tenant_id: Option<&str>) -> Option<(OperatorScope<'_>, AdminRole)> {
        match (self, tenant_id) {
            (Self::InstanceSecurityPolicyUpdate, None) => {
                Some((OperatorScope::Instance, AdminRole::SecurityAdmin))
            }
            (Self::InstanceSecurityPolicyUpdate, Some(_)) => None,
        }
    }
}

/// What a gated write returns: the write, or the pending operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gated<T> {
    Applied(T),
    Pending(PendingOperation),
}

/// A pending operation as its request stored it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOperation {
    pub id: String,
    pub kind: OperationKind,
    pub request_digest: RequestDigest,
    pub expected_revision: i64,
    /// Floored to a whole microsecond, as stored.
    pub expires_at: SystemTime,
}

/// The request's common input. `event_id` is the one event a request
/// appends (the domain event, or `administrative_operation.create`);
/// `operation_id` is used only when the write goes pending (T10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submission<'a> {
    /// The canonical public identity of the presented credential.
    pub public_identity: &'a str,
    /// Ignored by the toggle (see the module docs, "The toggle").
    pub acknowledge_widening: bool,
    pub operation_id: &'a str,
    pub event_id: &'a str,
    pub now: SystemTime,
}

/// The path an approve, cancel or reject is called on: an instance
/// operation is found only on the instance path and a tenant's only on its
/// tenant's path (section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalScope<'a> {
    Instance,
    Tenant(&'a str),
}

impl ApprovalScope<'_> {
    /// Whether an operation of `tenant_id` is in this scope (byte-wise).
    fn holds(self, tenant_id: Option<&str>) -> bool {
        match self {
            Self::Instance => tenant_id.is_none(),
            Self::Tenant(scope) => tenant_id == Some(scope),
        }
    }
}

/// What the approver echoes (tasks:149).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalEcho {
    pub request_digest: RequestDigest,
    pub expected_revision: i64,
}

/// The IDs an approve writes (T10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalIds<'a> {
    pub approve_operation_id: &'a str,
    pub approve_event_id: &'a str,
    pub write_event_id: &'a str,
}

/// The IDs a cancel or reject writes (T10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeIds<'a> {
    pub revoking_operation_id: &'a str,
    pub event_id: &'a str,
}

/// The server clock, sampled by the approve after its registry write and
/// before its first append (D28). Production uses [`SystemClock`]; tests
/// inject their own.
pub trait Clock: Sync {
    fn now(&self) -> SystemTime;
}

/// [`SystemTime::now`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// The requester as the request authorized it, or as the approve's locked
/// lookup checked the plan's credential; the post-authorization step
/// functions take it (D26).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Requester {
    pub(crate) admin_id: String,
    pub(crate) credential_id: String,
}

/// A step function's domain event, without its ID, time and outcome; the
/// caller stamps and appends it (the request with its `now`, the approve
/// with its one clock sample; D26, D28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnstampedEvent {
    pub(crate) tenant_id: Option<String>,
    pub(crate) actor: AuditActor,
    pub(crate) action: &'static str,
    pub(crate) object_id: String,
    pub(crate) previous_revision: Option<i64>,
    pub(crate) new_revision: Option<i64>,
}

impl UnstampedEvent {
    /// The event with its ID, time and outcome.
    pub(crate) fn stamp(self, id: &str, timestamp: SystemTime, outcome: &str) -> NewAuditEvent {
        NewAuditEvent {
            id: id.into(),
            tenant_id: self.tenant_id,
            timestamp,
            actor: self.actor,
            action: self.action.into(),
            object_id: self.object_id,
            previous_revision: self.previous_revision,
            new_revision: self.new_revision,
            outcome: outcome.into(),
        }
    }
}

/// The row an approval wrote. `#[non_exhaustive]`: the trust kinds come
/// with PRs 4 and 5.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    InstanceSecurityPolicy(InstanceSecurityPolicy),
}

/// Why an operation cannot be approved, cancelled or rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotApprovableReason {
    Consumed,
    Revoked,
    /// `now >= expires_at` (approve only: an expired operation may be
    /// cancelled or rejected).
    Expired,
    /// Not a kind of the flow, or not of the path's scope.
    WrongKind,
}

/// Why a function of this module did not succeed (section 10). On every
/// variant from a function with a savepoint, it is rolled back.
///
/// `Display` is fixed text per variant and `Debug` names the variant (and
/// the reason of [`Self::NotApprovable`]); neither holds a digest, an ID, a
/// revision or another value of the request. `source()` returns the inner
/// [`RegistryError`] only. `#[non_exhaustive]`: PRs 4 and 5 add the trust
/// writes' errors.
#[non_exhaustive]
pub enum ApprovalError {
    /// The presented credential does not authorize this call: no instance
    /// `security_admin` (approve, reject, the toggle), or not the
    /// operation's requester holding its role (cancel).
    Unauthorized,
    /// No such operation, or not in the path's scope.
    NotFound,
    /// The operation is consumed, revoked, expired (approve only) or of a
    /// kind outside the flow.
    NotApprovable(NotApprovableReason),
    /// The approver or rejecter is the requester (IR-054).
    SelfApproval,
    /// The echoed digest or expected revision does not equal the stored
    /// one, or the stored digest is not the one the preparation read.
    EchoMismatch,
    /// The requester's identity is disabled, its submitting credential is
    /// disabled or revoked, or it no longer holds the kind's role (Q5; D21).
    RequesterNotAuthorized,
    /// The stored operation does not recompute to its digest, or its plan
    /// is not the kind's: a data-integrity error, not a client error.
    PlanIntegrity,
    /// There is no instance security policy row (D18).
    PolicyUnavailable,
    /// The policy row is not at the expected revision (D19).
    StaleRevision,
    /// The caller's transaction does not run at `READ COMMITTED`.
    UnsupportedIsolation,
    /// A registry error: a store failure, [`RegistryError::Retry`] (retry
    /// the whole transaction), or a database refusal.
    Registry(RegistryError),
}

impl NotApprovableReason {
    const fn name(self) -> &'static str {
        match self {
            Self::Consumed => "Consumed",
            Self::Revoked => "Revoked",
            Self::Expired => "Expired",
            Self::WrongKind => "WrongKind",
        }
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("the operator may not act on this operation"),
            Self::NotFound => f.write_str("no such operation in this scope"),
            Self::NotApprovable(reason) => f.write_str(match reason {
                NotApprovableReason::Consumed => "the operation was already applied",
                NotApprovableReason::Revoked => "the operation was cancelled or rejected",
                NotApprovableReason::Expired => "the operation has expired",
                NotApprovableReason::WrongKind => "the operation is not of an approvable kind",
            }),
            Self::SelfApproval => {
                f.write_str("the requester of an operation may not approve or reject it")
            }
            Self::EchoMismatch => f.write_str(
                "the echoed request digest or expected revision does not match the operation",
            ),
            Self::RequesterNotAuthorized => {
                f.write_str("the requester of the operation is no longer authorized")
            }
            Self::PlanIntegrity => {
                f.write_str("the stored operation does not match its request digest or kind")
            }
            Self::PolicyUnavailable => f.write_str("the instance security policy is unavailable"),
            Self::StaleRevision => {
                f.write_str("the instance security policy changed since the request")
            }
            Self::UnsupportedIsolation => {
                f.write_str("operation writes run only at READ COMMITTED")
            }
            Self::Registry(err) => write!(f, "operation write failed: {err}"),
        }
    }
}

impl fmt::Debug for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("Unauthorized"),
            Self::NotFound => f.write_str("NotFound"),
            Self::NotApprovable(reason) => write!(f, "NotApprovable({})", reason.name()),
            Self::SelfApproval => f.write_str("SelfApproval"),
            Self::EchoMismatch => f.write_str("EchoMismatch"),
            Self::RequesterNotAuthorized => f.write_str("RequesterNotAuthorized"),
            Self::PlanIntegrity => f.write_str("PlanIntegrity"),
            Self::PolicyUnavailable => f.write_str("PolicyUnavailable"),
            Self::StaleRevision => f.write_str("StaleRevision"),
            Self::UnsupportedIsolation => f.write_str("UnsupportedIsolation"),
            Self::Registry(err) => f.debug_tuple("Registry").field(err).finish(),
        }
    }
}

impl std::error::Error for ApprovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(err) => Some(err),
            _ => None,
        }
    }
}

impl From<RegistryError> for ApprovalError {
    fn from(err: RegistryError) -> Self {
        Self::Registry(err)
    }
}

impl From<sqlx::Error> for ApprovalError {
    fn from(err: sqlx::Error) -> Self {
        Self::Registry(err.into())
    }
}

impl WriteError for ApprovalError {
    const UNSUPPORTED_ISOLATION: Self = Self::UnsupportedIsolation;
    const UNAUTHORIZED: Self = Self::Unauthorized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_have_their_names() {
        for &kind in OperationKind::ALL {
            assert_eq!(OperationKind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(
            OperationKind::InstanceSecurityPolicyUpdate.as_str(),
            "instance_security_policy_update"
        );
        for name in [
            "approve",
            "cancel",
            "reject",
            "operator_restoration",
            "Instance_security_policy_update",
            "instance_security_policy_update ",
            "",
        ] {
            assert_eq!(OperationKind::from_name(name), None, "{name}");
        }
        assert_eq!(
            OperationKind::InstanceSecurityPolicyUpdate.requester_role(None),
            Some((OperatorScope::Instance, AdminRole::SecurityAdmin))
        );
        assert_eq!(
            OperationKind::InstanceSecurityPolicyUpdate.requester_role(Some("ten_a")),
            None
        );
    }

    #[test]
    fn scopes_hold_their_own_operations_only() {
        assert!(ApprovalScope::Instance.holds(None));
        assert!(!ApprovalScope::Instance.holds(Some("ten_a")));
        assert!(ApprovalScope::Tenant("ten_a").holds(Some("ten_a")));
        assert!(!ApprovalScope::Tenant("ten_a").holds(Some("ten_b")));
        assert!(!ApprovalScope::Tenant("ten_a").holds(Some("TEN_A")));
        assert!(!ApprovalScope::Tenant("ten_a").holds(None));
        assert!(!ApprovalScope::Tenant("").holds(None));
    }

    #[test]
    fn the_ttl_is_24_hours() {
        assert_eq!(PENDING_OPERATION_TTL, Duration::from_secs(86_400));
    }

    /// `Display` and `Debug` hold no value of the request.
    #[test]
    fn errors_print_fixed_text_without_values() {
        let cases = [
            (
                ApprovalError::Unauthorized,
                "Unauthorized",
                "the operator may not act on this operation",
            ),
            (
                ApprovalError::NotFound,
                "NotFound",
                "no such operation in this scope",
            ),
            (
                ApprovalError::NotApprovable(NotApprovableReason::Consumed),
                "NotApprovable(Consumed)",
                "the operation was already applied",
            ),
            (
                ApprovalError::NotApprovable(NotApprovableReason::Revoked),
                "NotApprovable(Revoked)",
                "the operation was cancelled or rejected",
            ),
            (
                ApprovalError::NotApprovable(NotApprovableReason::Expired),
                "NotApprovable(Expired)",
                "the operation has expired",
            ),
            (
                ApprovalError::NotApprovable(NotApprovableReason::WrongKind),
                "NotApprovable(WrongKind)",
                "the operation is not of an approvable kind",
            ),
            (
                ApprovalError::SelfApproval,
                "SelfApproval",
                "the requester of an operation may not approve or reject it",
            ),
            (
                ApprovalError::EchoMismatch,
                "EchoMismatch",
                "the echoed request digest or expected revision does not match the operation",
            ),
            (
                ApprovalError::RequesterNotAuthorized,
                "RequesterNotAuthorized",
                "the requester of the operation is no longer authorized",
            ),
            (
                ApprovalError::PlanIntegrity,
                "PlanIntegrity",
                "the stored operation does not match its request digest or kind",
            ),
            (
                ApprovalError::PolicyUnavailable,
                "PolicyUnavailable",
                "the instance security policy is unavailable",
            ),
            (
                ApprovalError::StaleRevision,
                "StaleRevision",
                "the instance security policy changed since the request",
            ),
            (
                ApprovalError::UnsupportedIsolation,
                "UnsupportedIsolation",
                "operation writes run only at READ COMMITTED",
            ),
        ];
        for (err, debug, display) in cases {
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(err.to_string(), display);
            assert!(std::error::Error::source(&err).is_none());
        }
        let err = ApprovalError::Registry(RegistryError::StaleRevision);
        assert_eq!(format!("{err:?}"), "Registry(StaleRevision)");
        assert!(err.to_string().starts_with("operation write failed: "));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn an_unstamped_event_takes_its_id_time_and_outcome() {
        let event = UnstampedEvent {
            tenant_id: None,
            actor: AuditActor::Operator("adm_1".into()),
            action: "instance_security_policy.update",
            object_id: "inst".into(),
            previous_revision: Some(1),
            new_revision: Some(2),
        };
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(5);
        assert_eq!(
            event.stamp("evt_1", at, OUTCOME_SUCCESS),
            NewAuditEvent {
                id: "evt_1".into(),
                tenant_id: None,
                timestamp: at,
                actor: AuditActor::Operator("adm_1".into()),
                action: "instance_security_policy.update".into(),
                object_id: "inst".into(),
                previous_revision: Some(1),
                new_revision: Some(2),
                outcome: "success".into(),
            }
        );
    }
}
