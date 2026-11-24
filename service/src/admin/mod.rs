//! Audited, authorized operator writes (T13.2, T13.3; design section 7.2;
//! identity-registry sections 1 and 5.2; public-api section 7.1).
//!
//! The registry's bare writers ([`crate::persistence::registry`]) check
//! nothing the database does not, authorize no one and append no audit
//! event. This module is the write path above them for the workload
//! provisioning objects of M1a ([`workload`]): tenants, workload and service
//! principals, resource servers, audience tenant assignments, checkers with
//! their tenant sets, and resource actions. Each write, in the caller's
//! transaction:
//!
//! 1. runs only under `READ COMMITTED`
//!    ([`AdminWriteError::UnsupportedIsolation`] otherwise), as the trust
//!    writes do ([`crate::trust`]);
//! 2. authorizes the presented credential for the one role and scope the
//!    write needs (see "Who"), locked until the transaction ends;
//! 3. for an update, reads the stored row and checks the caller's expected
//!    revision (IR-022), and the registry's compare-and-set checks it
//!    again;
//! 4. for a create, takes the new object's ID from the [`IdGenerator`]
//!    the request carries (IR-020, IR-022; T10.2), never from the caller;
//! 5. calls the registry writer;
//! 6. appends the write's audit event, whose ID the generator gives too,
//!    and returns the row with the stored event ([`Audited`]).
//!
//! The functions are library-level only: no endpoint calls them yet
//! (slice S4 of M1a wires the router), and nothing wires them at startup.
//!
//! # Who
//!
//! The function builds the operator request itself, so a caller cannot ask
//! for another role or scope. Roles do not inherit one another (public-api
//! API-120), and a scope is satisfied only by a binding of exactly that
//! scope (identity-registry section 5.2, "Fail-closed scope").
//!
//! - **Instance `security_admin`**: a tenant create, update or disable
//!   (public-api section 7.1, `/admin/v1/tenants`; identity-registry
//!   sections 1 and 5.2; design section 7.2); a resource server create,
//!   update or disable (`/admin/v1/resource-servers`; IR-070); an audience
//!   tenant assignment create, update or disable (`/tenant-assignments`;
//!   identity-registry section 1; T14.1 and IR-071: no tenant
//!   self-assignment); a checker create, update or disable and a change of
//!   its tenant set (`/checker-identities`; IR-090; identity-registry
//!   section 10, `ResourceServerChecker.allowed_tenant_ids`); a resource
//!   action create, update or disable (`/actions`; IR-100).
//! - **`trust_admin` of the principal's tenant**: a workload principal
//!   create, and a workload or service principal update or disable
//!   (public-api section 7.1, `/admin/v1/tenants/{tenant}/principals`;
//!   identity-registry section 5.1 and IR-043; the lead ruling of
//!   2026-11-21 that only workload and service principals change through
//!   this path).
//!
//! Every miss is the one [`AdminWriteError::Unauthorized`]: an unknown
//! credential, a revoked or disabled one, a disabled operator, no binding
//! or a disabled one, a binding of another role (an `auditor`, a
//! `client_admin`, a `trust_admin` asking for an instance write, a
//! `security_admin` asking for a principal write) or of another scope
//! (another tenant's `trust_admin`, an instance `auditor` for a tenant).
//! The authorization comes before any read of the target, so a refused
//! caller learns nothing about it, not even whether it exists. A principal
//! is read by its tenant and ID, so an authorized `trust_admin` that names
//! another tenant's principal under its own tenant gets
//! [`RegistryError::NotFound`], as for a missing one.
//!
//! The lookup is [`authorize_operator_locked`]: the operator's identity,
//! credential and role binding `FOR SHARE`, in the `0005` order, until the
//! transaction ends, so a revocation, a disable or a binding change waits
//! for the write's commit or rollback (identity-registry section 5.2,
//! "Point in time or locked"). Tenant status is not part of it: a write in
//! a disabled tenant is not refused here (identity-registry section 5.2
//! leaves that check to where a write needs it; none of these writes names
//! it, so none checks it; inferred).
//!
//! # Audit events
//!
//! One event per write, last, with outcome `success`, the authorized
//! operator as actor (`{"type": "operator", "id": <admin_id>}`) and the
//! written object's ID as `object_id`, with no previous revision and the
//! new row's revision for a create, and the expected and the new revision
//! for every other write. The action is the table's verb of
//! [`AUDIT_ACTIONS`] (identity-registry IR-059): `<resource>.create` for a
//! create; for an update, `<resource>.enable` or `<resource>.disable` when
//! the write changes the stored row's `status` and nothing else, and
//! `<resource>.update` otherwise, a write that changes nothing included;
//! `<resource>.disable` for every `disable_*` write, also of a row already
//! disabled; `resource_server_checker.update` for a change of a checker's
//! tenant set, which advances the checker's revision (inferred: the
//! classification, the verb of a no-op write and of a repeated disable).
//! Principal events carry the principal's tenant as `tenant_id`; the events
//! of the instance-owned objects (tenants, resource servers, assignments,
//! checkers, actions) are instance events, with no tenant (inferred: they
//! are writes of instance `security_admin`, whose events a tenant
//! `auditor` does not read, tasks section 2, `/admin/v1/tenants/{tenant}/audit`).
//! The event has no member for the changed values (no `audit_event` detail
//! column), so it records none.
//!
//! # Order and locks
//!
//! In a savepoint of the caller's transaction: the isolation check, the
//! operator rows `FOR SHARE` (`0005` order), the stored row without a lock
//! (an update), the registry write with its own locks (the target row's
//! compare-and-set; a create's or a tenant set addition's foreign-key
//! checks take `FOR KEY SHARE` on the rows they reference), then the audit
//! append, which locks a principal's tenant row `FOR KEY SHARE` and then
//! the chain head, last (migrations README, "append audit events in this
//! order"; for an assignment update, "What 0010 adds", "Lock order"). The
//! stored row an update reads first is read without a lock: the
//! compare-and-set then succeeds only on the row at the revision read, and
//! every change advances the revision, so the event's classification holds
//! for the row it replaced.
//!
//! # Errors and rollback
//!
//! Every function runs its steps in a savepoint, releases it on `Ok` and
//! rolls it back on every `Err`, so an `Err` leaves no row and no event
//! behind and the caller's transaction usable; the caller still rolls back
//! on `Err`, since a failed savepoint rollback leaves the rows in place. A
//! generated ID is used up even when the write then fails. Refusals are not
//! audited. A `40001` or `40P01` is [`RegistryError::Retry`] inside
//! [`AdminWriteError::Registry`]: retry the whole transaction.
//! `Display` and `Debug` of an [`AdminWriteError`] never contain an ID, a
//! public identity, a name or another value of the request.
//!
//! # Not gated: the D3 seams
//!
//! Every write here applies at once on one operator's authority. None goes
//! through the second-approver gate ([`crate::operation`]), none takes
//! `acknowledge_widening`, and none reads `widening_second_approver`:
//! which of these writes are widening (D3 of the M1a plan) awaits a ruling
//! of the user (slice S3b), so this module decides nothing about it. The
//! writes a ruling may move behind the gate are the ones that can widen
//! what a credential, a checker or an operator can reach:
//!
//! - an audience tenant assignment create (enabled), its enable or
//!   re-enable, and an update that adds a profile, a scope or a constraint
//!   version to its ceiling ([`workload::create_audience_tenant_assignment`],
//!   [`workload::update_audience_tenant_assignment`]);
//! - a checker tenant set addition
//!   ([`workload::add_resource_server_checker_tenant`]), a checker create
//!   (enabled), its re-enable and a change of its `public_mtls_identity`
//!   ([`workload::create_resource_server_checker`],
//!   [`workload::update_resource_server_checker`]);
//! - a principal re-enable and a tenant re-enable
//!   ([`workload::update_principal`], [`workload::update_tenant`]), and a
//!   workload principal create (enabled,
//!   [`workload::create_workload_principal`]);
//! - a resource server create (enabled), its re-enable and an update that
//!   adds a profile, a scope or a constraint version
//!   ([`workload::create_resource_server`],
//!   [`workload::update_resource_server`]);
//! - a resource action create (enabled), its re-enable and an update that
//!   drops a required scope or a required resource dimension, adds an
//!   accepted profile or turns `live_check_required` off
//!   ([`workload::create_resource_action`],
//!   [`workload::update_resource_action`]);
//! - a tenant create ([`workload::create_tenant`]).
//!
//! The `disable_*` writes and a checker tenant set removal only narrow; the
//! design's rule that a soft disable is fail-safe and not widening
//! (ADR-008 item 3, for bindings and grants) suggests they stay ungated,
//! but that too is for the ruling. A gated write would keep this module's
//! authorization and audit and add the gate's steps between them, as
//! [`crate::trust`] does.
//!
//! # Not done here
//!
//! - No endpoint, no router and no request parsing (slice S4): the request
//!   layer must reject a NUL character, an unknown or read-only field (a
//!   tenant's `secret_namespace`, every ID) and check that a path's parent
//!   (a resource server's ID in `/resource-servers/{id}/actions`, say)
//!   matches the row; this module reads an instance object by its own ID.
//! - `Tenant.secret_namespace` generation: IR-034 requires a
//!   server-generated opaque value, and [`crate::ids`] has no kind for it
//!   yet (its character set awaits a ruling), so [`workload::create_tenant`]
//!   takes it from its caller, which must generate it, never accept it from
//!   a request.
//! - A service principal create: a service principal is created
//!   atomically with its service identity (identity-registry section 5.1),
//!   a write of the service identity path, not of this module.
//! - The scope, profile and constraint vocabulary of a resource server, an
//!   assignment or an action, and the T14.4 range rules of an action
//!   (IR-101); leaving a disabled assignment's tenant out of a checker's
//!   effective set (OQ-ADR018-1).
//!
//! [`authorize_operator_locked`]: crate::persistence::registry::authorize_operator_locked
//! [`AUDIT_ACTIONS`]: crate::persistence::registry::AUDIT_ACTIONS
//! [`RegistryError::NotFound`]: crate::persistence::registry::RegistryError::NotFound
//! [`RegistryError::Retry`]: crate::persistence::registry::RegistryError::Retry

pub mod workload;

use std::{fmt, time::SystemTime};

use crate::ids::IdGenerator;
use crate::persistence::registry::{AuditEvent, RegistryError};
use crate::trust::write::WriteError;

pub use workload::{
    ActionCreate, AssignmentCreate, CheckerCreate, PrincipalCreate, ResourceServerCreate,
    TenantCreate, add_resource_server_checker_tenant, create_audience_tenant_assignment,
    create_resource_action, create_resource_server, create_resource_server_checker, create_tenant,
    create_workload_principal, disable_audience_tenant_assignment, disable_principal,
    disable_resource_action, disable_resource_server, disable_resource_server_checker,
    disable_tenant, remove_resource_server_checker_tenant, update_audience_tenant_assignment,
    update_principal, update_resource_action, update_resource_server,
    update_resource_server_checker, update_tenant,
};

/// What every write takes from its caller besides the target: the
/// presented credential, the ID generator and the time of its audit event.
#[derive(Clone, Copy)]
pub struct AdminRequest<'a> {
    /// The canonical public identity of the presented mTLS credential,
    /// compared byte-wise with `admin_credential.public_identity`.
    pub public_identity: &'a str,
    /// The generator of the new object's ID and of the audit event's ID.
    pub ids: &'a dyn IdGenerator,
    /// The audit event's time, truncated to a whole microsecond; the
    /// caller's, never the database's.
    pub now: SystemTime,
}

impl fmt::Debug for AdminRequest<'_> {
    /// Leaves out the public identity and the generator.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminRequest")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// A written row and the audit event appended with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Audited<T> {
    /// The row as the write left it: a create's generated ID, every row's
    /// new revision.
    pub row: T,
    /// The stored event, with its generated ID, its sequence and its hash.
    pub event: AuditEvent,
}

/// Why a write of this module did not write. On every variant its
/// savepoint is rolled back: no row, no event.
///
/// `Display` is fixed text per variant and `Debug` names the variant; the
/// [`RegistryError`] inside [`Self::Registry`] prints only constraint,
/// table and column names and a SQLSTATE. Neither holds an ID, a public
/// identity, a name or another value of the request. `source()` returns
/// the inner [`RegistryError`] only, whose own source may quote values, so
/// logging must not walk the chain. `#[non_exhaustive]`: a later write may
/// add a variant.
#[derive(Debug)]
#[non_exhaustive]
pub enum AdminWriteError {
    /// The presented credential does not authorize the write: every cause
    /// is this one value (see the module docs, "Who").
    Unauthorized,
    /// The caller's transaction does not run at `READ COMMITTED`. Not
    /// retryable as is: retry in a `READ COMMITTED` transaction.
    UnsupportedIsolation,
    /// A principal update or disable names a principal of a kind this path
    /// does not change: a human principal (IR-043; the lead ruling of
    /// 2026-11-21 that only workload and service principals change here).
    PrincipalKindNotAllowed,
    /// A registry error: the target's outcome
    /// ([`RegistryError::NotFound`], [`RegistryError::StaleRevision`],
    /// [`RegistryError::AlreadyExists`], a constraint), a store failure, or
    /// [`RegistryError::Retry`] (retry the whole transaction).
    Registry(RegistryError),
}

impl fmt::Display for AdminWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("the operator may not perform this write"),
            Self::UnsupportedIsolation => f.write_str("operator writes run only at READ COMMITTED"),
            Self::PrincipalKindNotAllowed => {
                f.write_str("this write may not change a principal of this kind")
            }
            Self::Registry(err) => write!(f, "operator write failed: {err}"),
        }
    }
}

impl std::error::Error for AdminWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registry(err) => Some(err),
            _ => None,
        }
    }
}

impl From<RegistryError> for AdminWriteError {
    fn from(err: RegistryError) -> Self {
        Self::Registry(err)
    }
}

impl From<sqlx::Error> for AdminWriteError {
    fn from(err: sqlx::Error) -> Self {
        Self::Registry(err.into())
    }
}

impl WriteError for AdminWriteError {
    const UNSUPPORTED_ISOLATION: Self = Self::UnsupportedIsolation;
    const UNAUTHORIZED: Self = Self::Unauthorized;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Display` and `Debug` are fixed text, with no value.
    #[test]
    fn errors_print_fixed_text() {
        let cases = [
            (
                AdminWriteError::Unauthorized,
                "Unauthorized",
                "the operator may not perform this write",
            ),
            (
                AdminWriteError::UnsupportedIsolation,
                "UnsupportedIsolation",
                "operator writes run only at READ COMMITTED",
            ),
            (
                AdminWriteError::PrincipalKindNotAllowed,
                "PrincipalKindNotAllowed",
                "this write may not change a principal of this kind",
            ),
        ];
        for (err, debug, display) in cases {
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(err.to_string(), display);
            assert!(std::error::Error::source(&err).is_none());
        }
        let err = AdminWriteError::from(RegistryError::StaleRevision);
        assert_eq!(format!("{err:?}"), "Registry(StaleRevision)");
        assert!(err.to_string().starts_with("operator write failed: "));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn a_request_prints_no_public_identity() {
        struct NoIds;
        impl IdGenerator for NoIds {
            fn new_id(&self, _: crate::ids::IdKind) -> String {
                unreachable!()
            }
        }
        let request = AdminRequest {
            public_identity: "spki-sha256:secret-marker",
            ids: &NoIds,
            now: SystemTime::UNIX_EPOCH,
        };
        let text = format!("{request:?}");
        assert!(!text.contains("secret-marker"), "{text}");
        assert!(text.starts_with("AdminRequest { now: "), "{text}");
    }
}
