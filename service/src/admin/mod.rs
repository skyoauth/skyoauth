//! Audited, authorized operator writes (T13.2, T13.3; design section 7.2;
//! identity-registry sections 1 and 5.2; public-api section 7.1).
//!
//! The registry's bare writers ([`crate::persistence::registry`]) check
//! nothing the database does not, authorize no one and append no audit
//! event. This module is the write path above them for the workload
//! provisioning objects of M1a ([`workload`]): tenants, workload and service
//! principals, resource servers, audience tenant assignments, checkers with
//! their tenant sets, and resource actions; and for the instance-global
//! egress allowlist ([`egress`]; see "Egress allowlist"). Each write, in the
//! caller's transaction:
//!
//! 1. runs only under `READ COMMITTED`
//!    ([`AdminWriteError::UnsupportedIsolation`] otherwise), as the trust
//!    writes do ([`crate::trust`]);
//! 2. authorizes the presented credential for the one role and scope the
//!    write needs (see "Who"), locked until the transaction ends once the
//!    write succeeds (see "Errors and rollback" for an `Err`); an egress
//!    entry create or enable, which is widening, then passes the gate's
//!    acknowledgement and policy steps (see "Egress allowlist");
//! 3. for an update, reads the stored row and checks the caller's expected
//!    revision (IR-022), and the compare-and-set of the write checks it
//!    again; [`workload::disable_tenant`] and the checker tenant set
//!    changes ([`workload::add_resource_server_checker_tenant`],
//!    [`workload::remove_resource_server_checker_tenant`]) read no stored
//!    row and rely on that compare-and-set alone, and so do
//!    [`egress::enable_egress_entry`] and [`egress::disable_egress_entry`],
//!    which change only `status` and need no stored column before it (an
//!    enable checks the destination of the row it returns, see "Egress
//!    allowlist");
//! 4. for a create, takes the new object's ID from the [`IdGenerator`]
//!    the request carries (IR-020, IR-022; T10.2), never from the caller,
//!    after every check of the request's input (a checker's key is derived
//!    into its identity first, see "Not done here"; an egress entry's
//!    destination is checked first, see "Egress allowlist");
//! 5. calls the registry writer, or, for [`workload::disable_resource_server`]
//!    and [`workload::disable_audience_tenant_assignment`], one statement
//!    of its own that sets only `status` and `revision`, so the other
//!    columns are not read into Rust and written back (a `jsonb` number an
//!    `f64` cannot hold is kept as stored); the egress entry writers'
//!    registry status update sets only those two columns too;
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
//!   action create, update or disable (`/actions`; IR-100); an egress
//!   allowlist entry create, enable or disable (`/admin/v1/egress-allowlist`;
//!   IR-152: owned by instance `security_admin`, tenant operators only choose
//!   from it, so a tenant `trust_admin` is refused like any other role).
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
//! credential and role binding `FOR SHARE`, in the `0005` order, in the
//! write's savepoint, so once the write succeeds a revocation, a disable or
//! a binding change waits for the caller's commit or rollback
//! (identity-registry section 5.2, "Point in time or locked"); a write that
//! returns `Err` rolls the savepoint back, which releases them. Tenant
//! status is not part of it: the writes check it themselves, after the
//! authorization (see "Disabled tenants").
//!
//! # Disabled tenants
//!
//! The contracts do not say which operator writes a disabled tenant
//! refuses: ADR-014 item 11 (OQ-ADR014-1) lists issuance, live checks,
//! admission and refresh as what it denies, and identity-registry
//! section 5.2 ("Fail-closed scope") notes that it does not name operator
//! writes and leaves the check to T14 "where an operator write needs it".
//! The rule here is the lead decision, 2026-11-24: in a disabled tenant
//! every write that is not disable-only is
//! [`AdminWriteError::TenantDisabled`] and writes nothing. A write is
//! disable-only when its new `status` is `disabled` and every other
//! mutable column keeps the stored value (the effect, as for the
//! disable-only trust source update of ADR-008's OQ-ADR008-3, Q2), a
//! repeated disable included. The writes in a tenant:
//!
//! | Write | Its tenant | In a disabled tenant |
//! | ----- | ---------- | -------------------- |
//! | [`workload::update_tenant`] | the tenant itself | only a status-only change (an enable or a disable; the name kept) |
//! | [`workload::disable_tenant`] | the tenant itself | allowed |
//! | [`workload::create_workload_principal`] | the principal's | refused |
//! | [`workload::update_principal`] | the principal's | only disable-only |
//! | [`workload::disable_principal`] | the principal's | allowed |
//! | [`workload::create_audience_tenant_assignment`] | the assignment's `tenant_id` | refused, a disabled assignment too |
//! | [`workload::update_audience_tenant_assignment`] | the assignment's `tenant_id` | only disable-only |
//! | [`workload::disable_audience_tenant_assignment`] | the assignment's `tenant_id` | allowed |
//! | [`workload::add_resource_server_checker_tenant`] | the tenant added | refused: adding it widens the checker |
//! | [`workload::remove_resource_server_checker_tenant`] | the tenant removed | allowed: removing it narrows |
//!
//! The resource server, checker (create, update, disable), action and
//! egress entry writes are in no tenant and do not check one. The tenant
//! itself is enabled again only by a status-only update, which stays
//! allowed. The check comes after the authorization, so it tells nothing
//! to an operator the write refuses: a principal write's `trust_admin` holds
//! that very tenant, and an instance `security_admin` reads every tenant
//! anyway. For a write in a tenant other than the tenant itself (every
//! write of the table but the first two, the removal from a checker
//! included, which is allowed in either status), the tenant row is locked
//! `FOR SHARE` in the write's savepoint, so once the write succeeds a
//! tenant disable waits for its commit, and the write for the disable's;
//! for the tenant itself, its compare-and-set holds the status it read. The
//! check also needs the tenant to exist: for every write of the table, a
//! tenant that does not exist is [`RegistryError::NotFound`], before any ID
//! is generated.
//!
//! An assignment update is disable-only when its `status` is `disabled`
//! and its profiles, scopes and constraint versions equal the stored ones
//! under PostgreSQL's `jsonb` equality, the stored columns' own, so a
//! constraint version `1` submitted for a stored `1.0` is the same value;
//! the event's action uses the same comparison.
//!
//! # Audit events
//!
//! One event per write, last, with outcome `success` (a widening egress
//! write's is the gate's, see "Egress allowlist"), the authorized
//! operator as actor (`{"type": "operator", "id": <admin_id>}`) and the
//! written object's ID as `object_id`, with no previous revision and the
//! new row's revision for a create, and the expected and the new revision
//! for every other write. The action is the table's verb of
//! [`AUDIT_ACTIONS`] (identity-registry IR-059): `<resource>.create` for a
//! create; for an update, `<resource>.enable` or `<resource>.disable` when
//! the write changes the stored row's `status` and nothing else (an
//! assignment's columns compared as under "Disabled tenants", and a
//! resource server's name, profiles, scopes and constraint versions the
//! same way, so the two classify the same constraint versions alike), and
//! `<resource>.update` otherwise, a write that changes nothing included;
//! `<resource>.disable` for every `disable_*` write, also of a row already
//! disabled; `resource_server_checker.update` for a change of a checker's
//! tenant set, which advances the checker's revision (inferred: the
//! classification, the verb of a no-op write and of a repeated disable).
//! Principal events carry the principal's tenant as `tenant_id`; the events
//! of the instance-owned objects (tenants, resource servers, assignments,
//! checkers, actions, egress entries) are instance events, with no tenant
//! (lead decision, 2026-11-24: they are writes of instance
//! `security_admin`, whose events a tenant `auditor` does not read, tasks
//! section 2, `/admin/v1/tenants/{tenant}/audit`). The event has no member for the
//! changed values (no `audit_event` detail column), so it records none.
//!
//! The actions these writes append, all of [`AUDIT_ACTIONS`], for the
//! audit event catalogue ("status-only" is a write whose only changed
//! column is `status`; a write that changes nothing is `update`):
//!
//! | Write | Action | Event `tenant_id` |
//! | ----- | ------ | ----------------- |
//! | [`workload::create_tenant`] | `tenant.create` | none |
//! | [`workload::update_tenant`] | `tenant.enable` or `tenant.disable` when status-only, else `tenant.update` | none |
//! | [`workload::disable_tenant`] | `tenant.disable`, also when already disabled | none |
//! | [`workload::create_workload_principal`] | `principal.create` | the principal's |
//! | [`workload::update_principal`] | `principal.enable` or `principal.disable` when status-only, else `principal.update` | the principal's |
//! | [`workload::disable_principal`] | `principal.disable`, also when already disabled | the principal's |
//! | [`workload::create_resource_server`] | `resource_server.create` | none |
//! | [`workload::update_resource_server`] | `resource_server.enable` or `resource_server.disable` when status-only, else `resource_server.update` | none |
//! | [`workload::disable_resource_server`] | `resource_server.disable`, also when already disabled | none |
//! | [`workload::create_audience_tenant_assignment`] | `audience_tenant_assignment.create` | none |
//! | [`workload::update_audience_tenant_assignment`] | `audience_tenant_assignment.enable` or `audience_tenant_assignment.disable` when status-only, else `audience_tenant_assignment.update` | none |
//! | [`workload::disable_audience_tenant_assignment`] | `audience_tenant_assignment.disable`, also when already disabled | none |
//! | [`workload::create_resource_server_checker`] | `resource_server_checker.create` | none |
//! | [`workload::update_resource_server_checker`] | `resource_server_checker.enable` or `resource_server_checker.disable` when status-only, else `resource_server_checker.update` | none |
//! | [`workload::disable_resource_server_checker`] | `resource_server_checker.disable`, also when already disabled | none |
//! | [`workload::add_resource_server_checker_tenant`] | `resource_server_checker.update` | none |
//! | [`workload::remove_resource_server_checker_tenant`] | `resource_server_checker.update` | none |
//! | [`workload::create_resource_action`] | `resource_action.create` | none |
//! | [`workload::update_resource_action`] | `resource_action.enable` or `resource_action.disable` when status-only, else `resource_action.update` | none |
//! | [`workload::disable_resource_action`] | `resource_action.disable`, also when already disabled | none |
//! | [`egress::create_egress_entry`] | `egress_allowlist_entry.create`, enabled or disabled | none |
//! | [`egress::enable_egress_entry`] | `egress_allowlist_entry.enable`, also when already enabled | none |
//! | [`egress::disable_egress_entry`] | `egress_allowlist_entry.disable`, also when already disabled | none |
//!
//! # Egress allowlist
//!
//! An `EgressAllowlistEntry` (IR-152) is an instance-global exact
//! destination of one purpose (`oidc_discovery`, `jwks`, `token_review`):
//! `(purpose, exact_destination)` is unique and both are immutable, a
//! PATCH changes only `status`, and entries are not deleted. So
//! [`egress::create_egress_entry`] inserts one, and
//! [`egress::enable_egress_entry`] and [`egress::disable_egress_entry`] set
//! its `status`, nothing else; there is no update and no delete. A taken
//! pair, whatever the other entry's status, is
//! [`RegistryError::AlreadyExists`] naming
//! `egress_allowlist_entry_purpose_exact_destination_key`, a typed error
//! whose text names the constraint only.
//!
//! **The destination rule.** IR-152 calls `exact_destination` "an exact
//! URL (scheme, host, port and path)" and states no syntax; the `0002`
//! comment leaves the URL rule to the service (inferred there), and the
//! user ruled canonical-form destinations the convention: "an egress entry
//! writer must enforce this same rule on `exact_destination`" (2026-11-22,
//! relayed by the lead; [`crate::trust::source`], "Syntax"). So
//! [`egress::is_valid_destination`] is that rule, the one function a trust
//! source's destination passes too, plus two bounds of the writer's own. In
//! full, a destination:
//!
//! - has no ASCII whitespace, no control character (NUL included) and no
//!   backslash;
//! - is the text the URL parser serializes it to, byte for byte, with no
//!   incomplete or non-hex escape and no escape of an unreserved
//!   character (so the host is lowercase, an IPv4 address is dotted
//!   decimal, a default port is left out and the path is at least `/`);
//! - has the scheme `https`, a non-empty host, no userinfo and no fragment,
//!   not even an empty `@` or `#`, for every purpose, `token_review`
//!   included: the design asks for a "fixed HTTPS API endpoint" for a
//!   TokenReview source (design section 5.4) and T11.2 for "approved HTTPS
//!   egress", and no source allows `http`;
//! - may have a query, as a source's destination may (the shared rule
//!   allows it; inferred: no source names a query, and refusing it here
//!   would leave a source with one, which the source rule takes, with no
//!   entry to match);
//! - is at most [`egress::MAX_DESTINATION_BYTES`] (2048) bytes, the `0002`
//!   column bound, checked here so that a longer one is this error, not a
//!   database check (inferred: the bound is the lead's, the place of the
//!   check this module's);
//! - has no `*` in its host (lead decision, 2026-11-25, replacing the
//!   earlier inferred "no `*` anywhere"): the URL parser takes
//!   `https://*.example/` as a host, and an entry whose host reads like a
//!   pattern while it matches one exact text is refused rather than
//!   misread. A literal `*` in the path or the query is allowed, as the
//!   source rule allows it: matching is byte equality, so it is never a
//!   wildcard there, and refusing it would leave a source that has one with
//!   no entry to match.
//!
//! The rule is about spelling, not about where an address points, as for a
//! source: a canonical loopback, private or link-local address passes. A
//! policy on such addresses belongs to the fetcher (T11.2, T11.8), not to
//! this writer or the source writes. A refused destination is
//! [`AdminWriteError::InvalidDestination`], fixed text that never quotes it,
//! after the authorization and the gate and before any ID is generated, so a
//! refusal uses up no ID.
//!
//! **An enable checks the stored destination again** (lead decision,
//! 2026-11-25). An entry written another way (raw SQL, a fixture, the tests'
//! bare registry writer) may fail the rule, a pathless URL say, which no
//! source destination can match. After the authorization and the gate,
//! [`egress::enable_egress_entry`] checks the immutable destination of the
//! row its revision-checked update returns, before the event: one that
//! fails is [`AdminWriteError::InvalidDestination`], and the savepoint
//! takes the update back, so nothing is written, no event appended and no
//! ID taken, and a refused operator learns nothing of the destination. A
//! disable checks no destination, so such an entry can always be disabled.
//!
//! **Disabling fails closed.** A trust source write that sets
//! `discovery_url` or `token_review_endpoint` to a disabled entry's
//! destination is refused, at the write and at the approval of a pending
//! one, by the source path's entry check under `FOR SHARE` and by the
//! `0011` guard; the disable's `UPDATE` takes the entry `FOR NO KEY
//! UPDATE`, which waits for those `FOR SHARE` locks and they for it (see
//! [`crate::trust::source`], "Order and locks"). These writers lock no
//! `trust_source` row, so they add no deadlock with a source update. A
//! write that leaves both members unchanged is still accepted (IR-152), and
//! sources that already use the entry are not changed: IR-152 makes them
//! degraded, a derived signal of the fetcher, which does not exist yet.
//!
//! **Widening writes fail closed.** A create, enabled or disabled, and an
//! enable or re-enable are widening-class: IR-052 lists "adding or
//! re-enabling an `EgressAllowlistEntry`" with the gated trust writes, and
//! IR-152 and OQ-IR-12 repeat it; a disabled create is widening as a
//! disabled keyset or source create is (the user's ruling Q3 of the
//! second-approver proposal; ADR-008; [`crate::trust::source`] and
//! [`crate::trust::keyset`] gate theirs). IR-052 decides this, so D3 does
//! not (lead decision, 2026-11-25). The two writes take the gate's request
//! steps 3 and 4 after the authorization, as a gated trust write does
//! ([`crate::trust`]):
//!
//! - without `acknowledge_widening`,
//!   [`AdminWriteError::WideningNotAcknowledged`];
//! - the `instance_security_policy` row `FOR SHARE`, after the operator
//!   rows (the source path's order); none is
//!   [`AdminWriteError::PolicyUnavailable`];
//! - the mode table: `widening_second_approver` off applies the write with
//!   outcome `success_widening` (D23); on, under `single_actor_mode`,
//!   with `success_single_actor`, since the requester always holds instance
//!   `security_admin` (Q4; IR-052: "or one actor when `single_actor_mode`
//!   is on"); otherwise the write would be a pending operation, and an
//!   egress write has no operation kind yet, so it is
//!   [`AdminWriteError::SecondApproverRequired`]: nothing written, no ID
//!   taken, until an `egress_allowlist_entry_*` kind adds the pending path.
//!
//! The expected revision IR-052 asks for is the entry's, which an enable
//! carries; a create has none, and neither carries the policy row's
//! revision, as no gated trust write does (inferred). A disable is not
//! widening (IR-152) and passes no gate step: no acknowledgement, no policy
//! row, outcome `success`.
//!
//! # Order and locks
//!
//! In a savepoint of the caller's transaction: the isolation check, the
//! operator rows `FOR SHARE` (`0005` order), the stored row without a lock
//! (an update), the tenant row `FOR SHARE` (a write in a tenant other than
//! the tenant itself, "Disabled tenants"; it is taken before the domain
//! rows and the head stays last, so the order of the audit append
//! holds: the migrations README declares this step under "append audit
//! events in this order"), the write with its own locks (the target row's
//! compare-and-set; a create's or a tenant set addition's foreign-key
//! checks take `FOR KEY SHARE` on the rows they reference), then the audit
//! append, which locks a principal's tenant row `FOR KEY SHARE` and then
//! the chain head, last (migrations README, "append audit events in this
//! order"; for an assignment update, "What 0010 adds", "Lock order"). The
//! stored row an update reads first is read without a lock: the
//! compare-and-set then succeeds only on the row at the revision read, and
//! every change advances the revision, so the event's classification holds
//! for the row it replaced. An egress entry write takes, after the operator
//! rows, the policy row `FOR SHARE` (a create or an enable, "Egress
//! allowlist"), then only its own: the insert's unique index entry, or the
//! entry row `FOR NO KEY UPDATE` by its compare-and-set, then the audit
//! head.
//!
//! # Errors and rollback
//!
//! Every function runs its steps in a savepoint, releases it on `Ok` and
//! rolls it back on every `Err`, so an `Err` leaves no row and no event
//! behind and the caller's transaction usable; the caller still rolls back
//! on `Err`, since a failed savepoint rollback leaves the rows in place. A
//! generated ID is used up even when the write then fails. A generator that
//! gives no ID, for the new object (before the registry write) or for the
//! event (after it, inside the savepoint), is [`AdminWriteError::Id`], and
//! the savepoint's rollback takes back the row written before it (a server
//! error: "Generators" in [`crate::ids`]; lead decision, 2026-11-24).
//! Refusals are not audited. A `40001` or `40P01` is [`RegistryError::Retry`] inside
//! [`AdminWriteError::Registry`]: retry the whole transaction. The locks a
//! write takes in its savepoint (the operator rows, the tenant row, the
//! target row) are released by that rollback on `Err`, and held until the
//! caller's transaction ends on `Ok`.
//! `Display` and `Debug` of an [`AdminWriteError`] never contain an ID, a
//! public identity, a name or another value of the request.
//!
//! # Not gated: the D3 seams
//!
//! Every workload write here ([`workload`]) applies at once on one
//! operator's authority. None goes through the second-approver gate
//! ([`crate::operation`]), none takes `acknowledge_widening`, and none
//! reads `widening_second_approver`: which of these writes are widening
//! (D3 of the M1a plan) awaits a ruling of the user (slice S3b), so this
//! module decides nothing about it. The egress entry writes are not among
//! them: IR-052 already gates them (see "Egress allowlist"). The writes a
//! ruling may move behind the gate are the ones that can widen what a
//! credential, a checker or an operator can reach:
//!
//! - an audience tenant assignment create (enabled), its enable or
//!   re-enable, and an update that adds a profile, a scope or a constraint
//!   version to its ceiling ([`workload::create_audience_tenant_assignment`],
//!   [`workload::update_audience_tenant_assignment`]);
//! - a checker tenant set addition
//!   ([`workload::add_resource_server_checker_tenant`]), a checker create
//!   (enabled), its re-enable and a key rotation, which changes its
//!   `public_mtls_identity` ([`workload::create_resource_server_checker`],
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
//! [`crate::trust`] does, and as the egress create and enable do.
//!
//! Such a write creates an `administrative_operation`, so it must take its
//! locks as steps 1 to 3 of "What 0005 adds" in the migrations README
//! prescribe: every row the operation references or the write updates
//! `FOR NO KEY UPDATE`, the tables in that section's fixed order (the
//! `0005` tables, then the `0002` to `0004` tables by name, so
//! `audience_tenant_assignment`, `principal` and `resource_server_checker`
//! before `tenant`), before the audit head. The tenant step of this module
//! is not in that order: it locks the tenant row `FOR SHARE`, before the
//! domain rows. Moving a write in a tenant behind the gate must reconcile
//! the two (inferred: take the tenant row once, in its place in the `0005`
//! order and in the mode that order asks for, not `FOR SHARE` first and
//! stronger later, since two writes that each hold it `FOR SHARE` and then
//! ask for more deadlock, `40P01`), and the migrations README's lock order
//! with it. An egress entry write that creates an operation must also lock
//! no `trust_source` row (the `0011` README notes and
//! [`crate::trust::source`], "Order and locks": a source update holds its
//! row and then takes the entry `FOR SHARE`); it may list the affected
//! sources without a lock after its entry `UPDATE`.
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
//!   a request. This is interim (lead decision, 2026-11-24):
//!   [`workload::create_tenant`] must not be exposed on any HTTP surface
//!   until an IR-034 generator or ID kind is ruled.
//! - The checker's key form: [`workload::create_resource_server_checker`]
//!   and a rotation through [`workload::update_resource_server_checker`]
//!   take the key's DER `SubjectPublicKeyInfo` and derive
//!   `public_mtls_identity` with
//!   [`crate::identity::canonical_public_identity`] (bytes it refuses are
//!   [`AdminWriteError::PublicKey`]; a status-only write keeps the stored
//!   identity), never taking an identity string from their caller (lead
//!   decision, 2026-11-25). The per-algorithm form rule of
//!   [`crate::identity`] ("A hard requirement on the callers": one
//!   `SubjectPublicKeyInfo` form per accepted algorithm) is still
//!   outstanding, so one key can have several identities, and the checker
//!   writers must not be exposed on any HTTP surface until it lands.
//! - A service principal create: a service principal is created
//!   atomically with its service identity (identity-registry section 5.1),
//!   a write of the service identity path, not of this module (lead
//!   decision, 2026-11-24: it lands with the service identity in slice
//!   S3b).
//! - The scope, profile and constraint vocabulary of a resource server, an
//!   assignment or an action, and the T14.4 range rules of an action
//!   (IR-101); leaving a disabled assignment's tenant out of a checker's
//!   effective set (OQ-ADR018-1).
//! - The affected source IDs in an egress entry write's event: decided, not
//!   implemented. IR-152 and OQ-IR-12 (decided, 2026-11-20) say "the audit
//!   event of the entry write lists the affected source IDs", but an event
//!   has no detail member (no `audit_event` column for it), and an envelope
//!   member is an ADR-level change to the IR-056 hash input (as ruled for
//!   the fingerprint, Q6 of the second-approver proposal), so the event
//!   records only the entry until that change lands. The degraded health
//!   signal of dependent sources and the fail-closed fetch are the
//!   fetcher's (T11.2, T11.8).
//! - The deployment-policy mirror of the egress allowlist, which is slice
//!   S8, not these writers; nothing here bumps a revision for it.
//!
//! [`authorize_operator_locked`]: crate::persistence::registry::authorize_operator_locked
//! [`AUDIT_ACTIONS`]: crate::persistence::registry::AUDIT_ACTIONS
//! [`RegistryError::AlreadyExists`]: crate::persistence::registry::RegistryError::AlreadyExists
//! [`RegistryError::NotFound`]: crate::persistence::registry::RegistryError::NotFound
//! [`RegistryError::Retry`]: crate::persistence::registry::RegistryError::Retry

pub mod egress;
pub mod workload;

use std::{fmt, time::SystemTime};

use crate::identity::IdentityError;
use crate::ids::{IdError, IdGenerator};
use crate::persistence::registry::{AuditEvent, RegistryError};
use crate::trust::write::{GatedWriteError, WriteError};

pub use egress::{
    EgressEntryCreate, MAX_DESTINATION_BYTES, create_egress_entry, disable_egress_entry,
    enable_egress_entry, is_valid_destination,
};
pub use workload::{
    ActionCreate, AssignmentCreate, CheckerChanges, CheckerCreate, PrincipalCreate,
    ResourceServerCreate, TenantCreate, add_resource_server_checker_tenant,
    create_audience_tenant_assignment, create_resource_action, create_resource_server,
    create_resource_server_checker, create_tenant, create_workload_principal,
    disable_audience_tenant_assignment, disable_principal, disable_resource_action,
    disable_resource_server, disable_resource_server_checker, disable_tenant,
    remove_resource_server_checker_tenant, update_audience_tenant_assignment, update_principal,
    update_resource_action, update_resource_server, update_resource_server_checker, update_tenant,
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
/// [`IdError`] inside [`Self::Id`] and the [`IdentityError`] inside
/// [`Self::PublicKey`] are only their variant's name, and their text is left
/// out of `Display`; the [`RegistryError`] inside [`Self::Registry`] prints
/// only constraint, table and column names and a SQLSTATE. None holds an
/// ID, a public identity, a key byte, a name or another value of the
/// request. `source()` returns the inner [`IdError`], [`IdentityError`] or
/// [`RegistryError`] only; a registry error's own source may quote values,
/// so logging must not walk the chain. `#[non_exhaustive]`: a later write may
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
    /// The write's tenant is disabled and the write is not disable-only
    /// (see the module docs, "Disabled tenants"; lead decision,
    /// 2026-11-24). Checked after the authorization.
    TenantDisabled,
    /// A checker create or key rotation gave bytes that are not one
    /// well-formed DER `SubjectPublicKeyInfo`, so no canonical public
    /// identity ([`crate::identity::canonical_public_identity`]); checked
    /// after the authorization and before any ID is generated.
    PublicKey(IdentityError),
    /// An egress entry create gave an `exact_destination`, or an enable
    /// found a stored one, that is not an exact `https` URL in canonical
    /// form within the writer's bounds ([`egress::is_valid_destination`];
    /// see the module docs, "Egress allowlist"); checked after the
    /// authorization and the gate and before any ID is generated. The text
    /// never quotes the destination.
    InvalidDestination,
    /// A widening egress write (a create, enabled or disabled, or an enable;
    /// IR-052, IR-152) was submitted without `acknowledge_widening`, as a
    /// gated trust write's `WideningNotAcknowledged` (see the module docs,
    /// "Egress allowlist"). Checked after the authorization.
    WideningNotAcknowledged,
    /// A widening egress write found no `instance_security_policy` row
    /// (before bootstrap; D18), as a gated trust write's
    /// `PolicyUnavailable`.
    PolicyUnavailable,
    /// A widening egress write while `widening_second_approver` is on and
    /// the write is not single-actor: IR-052 says it must not take effect
    /// until an approval applies it, and an egress write has no pending
    /// operation yet, so it is refused, writing nothing (fails closed; see
    /// the module docs, "Egress allowlist").
    SecondApproverRequired,
    /// The generator gave no ID, for the new object or for the audit
    /// event: a server error, not retried with another source (see
    /// "Generators" in [`crate::ids`]; lead decision, 2026-11-24).
    Id(IdError),
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
            Self::TenantDisabled => {
                f.write_str("this write is refused while its tenant is disabled")
            }
            Self::PublicKey(_) => {
                f.write_str("the checker's public key is not a DER SubjectPublicKeyInfo")
            }
            Self::InvalidDestination => {
                f.write_str("the egress destination is not an exact https URL in canonical form")
            }
            Self::WideningNotAcknowledged => {
                f.write_str("the egress allowlist write is widening and was not acknowledged")
            }
            Self::PolicyUnavailable => f.write_str("the instance security policy is unavailable"),
            Self::SecondApproverRequired => f.write_str(
                "the egress allowlist write is widening and needs a second approver, \
                 which egress writes cannot request yet",
            ),
            Self::Id(_) => f.write_str("operator write could not generate an ID"),
            Self::Registry(err) => write!(f, "operator write failed: {err}"),
        }
    }
}

impl std::error::Error for AdminWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Id(err) => Some(err),
            Self::PublicKey(err) => Some(err),
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

impl From<IdError> for AdminWriteError {
    fn from(err: IdError) -> Self {
        Self::Id(err)
    }
}

impl From<IdentityError> for AdminWriteError {
    fn from(err: IdentityError) -> Self {
        Self::PublicKey(err)
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

impl GatedWriteError for AdminWriteError {
    const WIDENING_NOT_ACKNOWLEDGED: Self = Self::WideningNotAcknowledged;
    const POLICY_UNAVAILABLE: Self = Self::PolicyUnavailable;
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
            (
                AdminWriteError::TenantDisabled,
                "TenantDisabled",
                "this write is refused while its tenant is disabled",
            ),
            (
                AdminWriteError::InvalidDestination,
                "InvalidDestination",
                "the egress destination is not an exact https URL in canonical form",
            ),
            (
                AdminWriteError::WideningNotAcknowledged,
                "WideningNotAcknowledged",
                "the egress allowlist write is widening and was not acknowledged",
            ),
            (
                AdminWriteError::PolicyUnavailable,
                "PolicyUnavailable",
                "the instance security policy is unavailable",
            ),
            (
                AdminWriteError::SecondApproverRequired,
                "SecondApproverRequired",
                "the egress allowlist write is widening and needs a second approver, which \
                 egress writes cannot request yet",
            ),
        ];
        for (err, debug, display) in cases {
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(err.to_string(), display);
            assert!(std::error::Error::source(&err).is_none());
        }
        for (id, debug) in [
            (IdError::SourceFailed, "Id(SourceFailed)"),
            (IdError::Exhausted, "Id(Exhausted)"),
        ] {
            let err = AdminWriteError::from(id);
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(err.to_string(), "operator write could not generate an ID");
            let source = std::error::Error::source(&err).map(ToString::to_string);
            assert_eq!(source, Some(id.to_string()));
        }
        for (key, debug) in [
            (IdentityError::Empty, "PublicKey(Empty)"),
            (IdentityError::NotDer, "PublicKey(NotDer)"),
            (IdentityError::NotSpki, "PublicKey(NotSpki)"),
        ] {
            let err = AdminWriteError::from(key);
            assert_eq!(format!("{err:?}"), debug);
            assert_eq!(
                err.to_string(),
                "the checker's public key is not a DER SubjectPublicKeyInfo"
            );
            let source = std::error::Error::source(&err).map(ToString::to_string);
            assert_eq!(source, Some(key.to_string()));
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
            fn new_id(&self, _: crate::ids::IdKind) -> Result<String, IdError> {
                Err(IdError::SourceFailed)
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
