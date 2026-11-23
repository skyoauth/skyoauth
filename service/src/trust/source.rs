//! The audited write path of a trust source with the IR-152 egress check
//! (T11.2; identity-registry IR-152; public-api section 7.1, the
//! `/admin/v1/tenants/{tenant}/trust-sources` row; migrations README, "What
//! 0004 adds", the service rules).
//!
//! `create_source` and `update_source` (both `pub(super)`) wrap the
//! registry's bare, crate-private `create_trust_source` and
//! `update_trust_source` (the proposal's PR 9), which check nothing the
//! database does not. [`submit_create_source`] and
//! [`submit_update_source`] are the gated create and update of the
//! second-approver flow (`docs/proposals/second-approver-gated-writes.md`,
//! PR 5; see "The gate"). They run in the caller's transaction and neither
//! commit nor roll it back. The picks below are the lead's (provisional
//! lead pick, 2026-11-22; the gate's, 2026-11-23) unless marked (inferred);
//! all are provisional until the maintainer ratifies the ADRs (T00.8 to
//! T00.17, Gate M0). Four rulings below are the user's, not provisional
//! picks: canonical-form destinations as the convention (end of "Rules"),
//! source writes as widening and the database backstop (both under "Not
//! done here"; 2026-11-22, relayed by the lead), and the class of an update
//! (Q2, 2026-11-23; "The gate").
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
//! # The gate
//!
//! [`submit_create_source`] and [`submit_update_source`] (proposal sections
//! 1 to 3). The server decides the class of a write from the stored row,
//! never the caller (Q2, ruled by the user, 2026-11-23):
//!
//! - every create, enabled or disabled, is widening;
//! - an update is disable-only when it sets `status` to `disabled` and its
//!   other fourteen members equal the stored row's. `proof_bounds` is
//!   compared by the database's `jsonb` equality on the locked row
//!   (`proof_bounds_equal`): key order does not count, numbers compare by
//!   value (`1` equals `1.0`), and a stored number beyond `f64` precision
//!   (only a row written outside the service, by raw SQL or a future
//!   importer, can hold one) is compared exactly, so a caller's echo of the
//!   row, which rounds it, is a change and widening (inferred). A disabled
//!   source written with its stored members is disable-only too (inferred:
//!   it widens nothing).
//!   A disable-only update is not widening: it is applied at once with
//!   outcome `success`, without the acknowledgement, whatever the policy,
//!   and never goes pending;
//! - every other update is widening: an enable, a re-enable, a disable that
//!   also changes another member, any other change, and a write that
//!   changes nothing on an enabled source.
//!
//! Before any statement a request refuses what D27 pre-validates: the
//! syntax of a create's destinations, then the plainly typed `CHECK`s of
//! `0003` and `0004` (a non-empty `id`, `name`, `exact_issuer`,
//! `cluster_id`, `ca_bundle_ref`, `ca_fingerprint` and
//! `reviewer_credential_ref`; non-empty `audiences` and `algorithms` of
//! non-empty strings; a positive `review_timeout_ms`;
//! `stale_revocation_acknowledged` true when set), each with the
//! [`RegistryError::Invariant`] the database gives, the
//! `skyoauth_string_list` domain first and then the checks by name
//! (inferred: this scope and order). So an unauthorized caller gets these
//! refusals too; they name a constraint, never a value. The kind, profile,
//! replay, length, character, unique and foreign-key checks stay the
//! database's. A source parses nothing in the transaction, so no request
//! waits for a validation permit and none is `ValidationBusy`.
//!
//! Then, in its savepoint:
//!
//! 0. `READ COMMITTED` only;
//! 1. the requester, a `trust_admin` of the source's tenant: its identity,
//!    its credential, its `trust_admin` binding and its instance
//!    `security_admin` binding, if any, `FOR SHARE` in one lookup (Q4). A
//!    `security_admin` without the tenant role is
//!    [`SourceWriteError::Unauthorized`] like any other miss, and learns
//!    nothing of the source;
//! 2. a create: `acknowledge_widening`
//!    ([`SourceWriteError::WideningNotAcknowledged`]), then the policy row
//!    `FOR SHARE`, which must exist ([`SourceWriteError::PolicyUnavailable`]
//!    before bootstrap, D18). An update: the policy row `FOR SHARE`, if
//!    any, then the stored row `FOR NO KEY UPDATE` (`NotFound`,
//!    `StaleRevision`) and its class; a widening update then needs the
//!    acknowledgement and the policy row, in that order, and a disable-only
//!    one needs neither (inferred: the policy row is locked before the
//!    source row for every update, a disable-only one included, so one lock
//!    order holds whatever the class the stored row later gives);
//! 3. the mode. Disable-only: applied at once, outcome `success`.
//!    `widening_second_approver` off: applied at once, outcome
//!    `success_widening` (D23). `single_actor_mode` on and the requester
//!    also an instance `security_admin`: applied at once, outcome
//!    `success_single_actor` (Q4). Otherwise the write's own checks run
//!    under its locks (D7: the syntax and the enabled entry `FOR SHARE` of
//!    each destination a create sets or an update changes), and a pending
//!    operation is written with its `administrative_operation.create`
//!    event; no source is written.
//!
//! A create's plan (`trust_source_create`, expected revision 0) holds every
//! member of the new source; an update's (`trust_source_update`, at the
//! stored revision) holds the source's ID, its fifteen mutable members as
//! the request gave them and `changed`, the sorted names of the members that
//! differ from the stored row. Both hold the requester's credential ID.
//! Every member is public: the CA bundle and the reviewer credential are
//! named by reference (`ca_bundle_ref`, `reviewer_credential_ref`), never
//! held, and a plan holds no secret. Destinations are in canonical form, as
//! the syntax rules require. `proof_bounds` is held as its compact JSON
//! text (inferred).
//!
//! The approval ([`crate::operation::approve_operation`]) reruns the write
//! from the locked plan under the approval's locks: for a create, the
//! syntax, the entries and the insert; for an update, the stored row
//! `FOR NO KEY UPDATE` at the operation's expected revision, then the
//! changed destinations, their entries and the compare-and-set. It refuses
//! with `PlanIntegrity` a create plan whose tenant is not the operation's,
//! and an update plan whose `changed` is not what its changes change on the
//! stored row (both inferred). It does not classify again: the expected
//! revision pins the stored row the class was read from (inferred). The
//! steps are split for it (D26): `apply_create_source` and
//! `apply_locked_update` return the row and its event unstamped, and the
//! caller stamps and appends it. The approval samples the clock once, after
//! the registry write (D28), so a compare-and-set that waited for a token
//! exchange's `FOR KEY SHARE` is judged at the time it finished.
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
//!    `update_trust_source` always sets `name`, a column of the unique key
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
//! So the lock order is: operator rows, then the policy row (`FOR SHARE`,
//! a gated request only), then the source row (`FOR NO KEY UPDATE`, update
//! only; `FOR UPDATE` from step 4 on), then the egress entry rows
//! (`FOR SHARE`, discovery before TokenReview), then the write's own locks,
//! then the audit head. A pending request writes no source: after its
//! entries it appends its `administrative_operation.create` event (the
//! audit head) and then inserts the operation. An approval takes its
//! operator rows, then the operation row `FOR NO KEY UPDATE`, then the
//! source row, the entries and the write as above, then samples the clock,
//! then takes the audit head; it takes no policy row. This differs from
//! step 1 of "What 0005 adds" in the migrations README, which orders the
//! `0002` to `0004` tables by name (`egress_allowlist_entry` before
//! `instance_security_policy` and `trust_source`) for a write that creates
//! an `administrative_operation`: an update must read the stored row before
//! it knows which entry to lock, and the policy row, which every gated
//! request reads first, comes before both (inferred). An egress entry writer that locked a trust source row after an
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
//! outcome `success` (inferred, as for bootstrap and restore; a gated
//! write applied at once has `success_widening` or `success_single_actor`,
//! a disable-only update `success`, and an approved write `success` with
//! the requester as actor, after the approval's own event, at the
//! approval's clock sample: see "The gate"). A create is
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
//! rows in place. A refusal before step 0 (the syntax of a create, or D27
//! of a gated request) runs no statement and takes no savepoint.
//!
//! # Not done here
//!
//! - No endpoint and no HTTP: nothing calls these functions yet. They must
//!   not be wired to a request path before the request layer exists
//!   (generated IDs, T10.2; NUL rejection; the role of each endpoint,
//!   T13.2, T13.3). An endpoint calls [`submit_create_source`] and
//!   [`submit_update_source`], never the ungated writes.
//! - Widening: a trust source write counts as widening and needs an IR-054
//!   approval by a second approver while `widening_second_approver` is on
//!   (ruled by the user, 2026-11-22, relayed by the lead; this decides the
//!   IR-052 widening question for this write), except a disable-only update
//!   (Q2, ruled by the user, 2026-11-23). The second-approver flow is
//!   designed in that proposal (accepted, 2026-11-23); no task ID names it
//!   (the nearest owners are T13.3, T13.2, T13.8, T11.6, T10.4 and T10.2).
//!   The gated writes put source writes through it (see "The gate").
//!   `create_source` and `update_source` stay ungated: they apply a create
//!   or an update, a widening one or not, on one operator's authority
//!   without the gate, so with `widening_second_approver` on a widening
//!   one would skip its approval. They are visible only within `trust`
//!   (`pub(super)`, the proposal's PR 7), so no other module of the crate
//!   can call them, and nothing in `trust` calls them outside tests; this
//!   package's integration tests reach them through the `#[doc(hidden)]`
//!   `trust::test_support`, compiled only with the `test-support` feature,
//!   which a normal build leaves off
//!   (`service/tests/ungated_writes_private.rs` checks that such a build
//!   exposes neither and calls neither).
//! - The fetch-time match of a discovered `jwks_uri` against an enabled
//!   `jwks` entry, the degraded health signal and the fetches themselves
//!   (IR-152; T11.2, T11.8).
//! - `ca_bundle_ref` and `reviewer_credential_ref` resolution within the
//!   tenant's secret namespace (IR-034), tenant status (the operator lookup
//!   does not read it), and the other source rules of T11.1 and T11.8.
//! - A database backstop of the syntax rules. The egress check has one.
//!   The trigger pattern of `docs/proposals/ir-080-assignment-write-guard.md`
//!   is accepted (ruled by the user, 2026-11-22, relayed by the lead): for
//!   the IR-080 assignment references it is migration `0010`, and for this
//!   check it is migration `0011` (provisional lead pick, 2026-11-22;
//!   migrations README, "What 0011 adds"). Its trigger
//!   `trust_source_egress_enabled`, an `AFTER INSERT OR UPDATE` row
//!   trigger, applies the "What", "Match" and "When" rules above to every
//!   writer at the end of the statement, after the row is written and
//!   every `0004` check has run, locking the entry `FOR SHARE`, and refuses
//!   with `23514` naming `trust_source_discovery_url_egress_enabled` or
//!   `trust_source_token_review_endpoint_egress_enabled`, which the
//!   registry maps to [`RegistryError::Invariant`] of kind
//!   [`InvariantKind::EgressEntryEnabled`]. This path checks first, so it
//!   still refuses with [`SourceWriteError::EgressNotAllowed`]; at step 4
//!   the trigger finds the entry this path holds, so the lock order above
//!   is unchanged. The bare registry functions now get the `Invariant`,
//!   but they still write a non-canonical destination that an enabled
//!   entry lists with exactly that value.
//!
//! [`authorize_operator_locked`]: crate::persistence::registry::authorize_operator_locked
//! [`InvariantKind::EgressEntryEnabled`]: crate::persistence::registry::InvariantKind::EgressEntryEnabled
//! [`OperatorScope::Tenant`]: crate::persistence::registry::OperatorScope::Tenant
//! [`AdminRole::TrustAdmin`]: crate::persistence::registry::AdminRole::TrustAdmin

use std::{fmt, time::SystemTime};

use sqlx::{Postgres, Row, Transaction, types::Json};
use url::Url;

use super::write::{
    GatedWriteError, Mode, WriteError, authorize_gated_requester, authorize_trust_admin,
    authorize_widening_write, in_savepoint, lock_policy_shared, require_acknowledged,
    require_read_committed, widening_mode,
};
use crate::operation::{
    Gated, OUTCOME_SUCCESS, OperationKind, PendingRequest, Requester, Submission, UnstampedEvent,
    insert_pending,
    source_plan::{CreateSourcePlan, UpdateSourcePlan, changed_members},
};
use crate::persistence::registry::{
    AuditActor, EgressPurpose, InvariantKind, JsonObject, NewTrustSource, RegistryError, Status,
    TrustSource, TrustSourceChanges, append_audit_event, create_trust_source, update_trust_source,
};

/// The member name of a trust source's discovery URL, as errors name it.
pub const DISCOVERY_URL: &str = "discovery_url";

/// The member name of a trust source's TokenReview endpoint, as errors name
/// it.
pub const TOKEN_REVIEW_ENDPOINT: &str = "token_review_endpoint";

/// The audit action of `create_source` (identity-registry IR-059).
const CREATE_ACTION: &str = "trust_source.create";

/// The audit action of `update_source` (identity-registry IR-059).
const UPDATE_ACTION: &str = "trust_source.update";

/// The outcome of the event of an ungated write (inferred, as for
/// bootstrap).
const SUCCESS: &str = "success";

/// The member name of a source's status, as an update plan's `changed`
/// names it.
const STATUS_MEMBER: &str = "status";

/// The `0003` domain check of a list of names: a JSON array of non-empty
/// strings.
const STRING_LIST_CHECK: &str = "skyoauth_string_list_check";

/// Step 2 of an update: the stored row, every column, locked before any
/// entry so that a concurrent update of the source waits here and holds no
/// entry lock. Its compare-and-set (step 4) then takes the row
/// `FOR UPDATE`, which blocks foreign-key inserts that reference the source
/// until the commit (see the module docs, "Order and locks"). The gate
/// reads the whole row: the class of an update (Q2) and its plan's
/// `changed` compare every mutable member.
const LOCK_SOURCE: &str = "SELECT id, tenant_id, name, kind, exact_issuer, discovery_url, \
     jwks_keyset_id, cluster_id, token_review_endpoint, ca_bundle_ref, ca_fingerprint, \
     reviewer_credential_ref, review_timeout_ms, audiences, algorithms, proof_bounds, \
     assertion_profile, stale_revocation_acknowledged, replay_mode, status, revision \
     FROM trust_source WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE";

/// The `jsonb` equality of a locked source's `proof_bounds` with the
/// changes' (Q2; see [`proof_bounds_equal`]).
const PROOF_BOUNDS_EQUAL: &str =
    "SELECT proof_bounds = $3 FROM trust_source WHERE tenant_id = $1 AND id = $2";

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

/// Why a trust source write ([`submit_create_source`],
/// [`submit_update_source`]) or its approval did not write. On every
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
    /// A gated write that is widening was submitted without
    /// `acknowledge_widening` (proposal section 3, request step 3). Whether
    /// a write is widening is the server's decision (see the module docs,
    /// "The gate").
    WideningNotAcknowledged,
    /// A gated widening write found no `instance_security_policy` row
    /// (before bootstrap; D18).
    PolicyUnavailable,
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
            Self::WideningNotAcknowledged => {
                f.write_str("the trust source write is widening and was not acknowledged")
            }
            Self::PolicyUnavailable => f.write_str("the instance security policy is unavailable"),
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

impl GatedWriteError for SourceWriteError {
    const WIDENING_NOT_ACKNOWLEDGED: Self = Self::WideningNotAcknowledged;
    const POLICY_UNAVAILABLE: Self = Self::PolicyUnavailable;
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

/// A step function's event of a write by `requester` of `source`,
/// unstamped (D26): the caller stamps it with its ID, time and outcome.
fn unstamped(
    requester: &Requester,
    action: &'static str,
    previous_revision: Option<i64>,
    source: &TrustSource,
) -> UnstampedEvent {
    UnstampedEvent {
        tenant_id: Some(source.tenant_id.clone()),
        actor: AuditActor::Operator(requester.admin_id.clone()),
        action,
        object_id: source.id.clone(),
        previous_revision,
        new_revision: Some(source.revision),
    }
}

/// Step 5: `event` stamped with the caller's ID, `now` and `outcome`,
/// through the audit head.
async fn append_stamped(
    transaction: &mut Transaction<'_, Postgres>,
    event: UnstampedEvent,
    event_id: &str,
    now: SystemTime,
    outcome: &str,
) -> Result<(), SourceWriteError> {
    append_audit_event(transaction, &event.stamp(event_id, now, outcome)).await?;
    Ok(())
}

/// The syntax of each member of a create that is set (see the module docs,
/// "Rules"), before any statement.
fn check_create_syntax(new: &NewTrustSource) -> Result<(), SourceWriteError> {
    let destinations = destinations(
        new.discovery_url.as_deref(),
        new.token_review_endpoint.as_deref(),
    );
    for destination in &destinations {
        check_syntax(*destination)?;
    }
    Ok(())
}

/// A refusal of the `0003`/`0004` `CHECK` named `constraint`, as the
/// registry maps the database's.
fn check_violation(constraint: &'static str) -> SourceWriteError {
    RegistryError::Invariant {
        kind: InvariantKind::Check,
        constraint: Some(constraint),
    }
    .into()
}

/// The members of a write that D27 pre-validates (see the module docs,
/// "The gate"), as a create and an update share them.
struct TypedMembers<'a> {
    id: Option<&'a str>,
    name: &'a str,
    exact_issuer: &'a str,
    cluster_id: Option<&'a str>,
    ca_bundle_ref: Option<&'a str>,
    ca_fingerprint: Option<&'a str>,
    reviewer_credential_ref: Option<&'a str>,
    review_timeout_ms: Option<i32>,
    audiences: &'a [String],
    algorithms: Option<&'a [String]>,
    stale_revocation_acknowledged: Option<bool>,
}

/// D27: the plainly typed `CHECK`s of a source, with the refusal the
/// database gives (inferred order: the `skyoauth_string_list` domain
/// first, as PostgreSQL coerces a value to the column's domain before it
/// runs the table's checks, then the table's checks by name, as PostgreSQL
/// runs them). The kind, replay, profile, length, character, unique and
/// foreign-key checks stay the database's.
fn check_typed(members: &TypedMembers<'_>) -> Result<(), SourceWriteError> {
    let empty = |value: Option<&str>| value.is_some_and(str::is_empty);
    let lists = std::iter::once(members.audiences).chain(members.algorithms);
    if lists.flatten().any(String::is_empty) {
        return Err(check_violation(STRING_LIST_CHECK));
    }
    let checks = [
        (
            members.algorithms.is_some_and(<[String]>::is_empty),
            "trust_source_algorithms_check",
        ),
        (members.audiences.is_empty(), "trust_source_audiences_check"),
        (
            empty(members.ca_bundle_ref),
            "trust_source_ca_bundle_ref_check",
        ),
        (
            empty(members.ca_fingerprint),
            "trust_source_ca_fingerprint_check",
        ),
        (empty(members.cluster_id), "trust_source_cluster_id_check"),
        (
            members.exact_issuer.is_empty(),
            "trust_source_exact_issuer_check",
        ),
        (empty(members.id), "trust_source_id_check"),
        (members.name.is_empty(), "trust_source_name_check"),
        (
            members.review_timeout_ms.is_some_and(|ms| ms <= 0),
            "trust_source_review_timeout_ms_check",
        ),
        (
            empty(members.reviewer_credential_ref),
            "trust_source_reviewer_credential_ref_check",
        ),
        (
            members.stale_revocation_acknowledged == Some(false),
            "trust_source_stale_revocation_acknowledged_check",
        ),
    ];
    match checks.into_iter().find(|(fails, _)| *fails) {
        Some((_, constraint)) => Err(check_violation(constraint)),
        None => Ok(()),
    }
}

/// The pure checks of a gated create, before any statement: the syntax of
/// its destinations, then D27 ([`check_typed`]). A destination is left to
/// the syntax rules, which refuse an empty one (inferred).
fn check_create_request(new: &NewTrustSource) -> Result<(), SourceWriteError> {
    check_create_syntax(new)?;
    check_typed(&TypedMembers {
        id: Some(&new.id),
        name: &new.name,
        exact_issuer: &new.exact_issuer,
        cluster_id: new.cluster_id.as_deref(),
        ca_bundle_ref: new.ca_bundle_ref.as_deref(),
        ca_fingerprint: new.ca_fingerprint.as_deref(),
        reviewer_credential_ref: new.reviewer_credential_ref.as_deref(),
        review_timeout_ms: new.review_timeout_ms,
        audiences: &new.audiences,
        algorithms: new.algorithms.as_deref(),
        stale_revocation_acknowledged: new.stale_revocation_acknowledged,
    })
}

/// The pure checks of a gated update, before any statement: D27
/// ([`check_typed`]) on its changes. The destinations are checked once the
/// stored row says which changed (see the module docs, "Rules").
fn check_update_request(changes: &TrustSourceChanges) -> Result<(), SourceWriteError> {
    check_typed(&TypedMembers {
        id: None,
        name: &changes.name,
        exact_issuer: &changes.exact_issuer,
        cluster_id: None,
        ca_bundle_ref: changes.ca_bundle_ref.as_deref(),
        ca_fingerprint: changes.ca_fingerprint.as_deref(),
        reviewer_credential_ref: changes.reviewer_credential_ref.as_deref(),
        review_timeout_ms: changes.review_timeout_ms,
        audiences: &changes.audiences,
        algorithms: changes.algorithms.as_deref(),
        stale_revocation_acknowledged: changes.stale_revocation_acknowledged,
    })
}

/// The post-authorization steps of a create (D26): steps 3 and 4, by
/// `requester`, whom the caller authorized: the syntax of the destinations
/// (again, for the approve, whose plan no request checked in this
/// transaction), each entry `FOR SHARE` and the insert. Returns the row and
/// its `trust_source.create` event, unstamped; the caller appends it.
pub(crate) async fn apply_create_source(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    new: &NewTrustSource,
) -> Result<(TrustSource, UnstampedEvent), SourceWriteError> {
    check_create_syntax(new)?;
    let destinations = destinations(
        new.discovery_url.as_deref(),
        new.token_review_endpoint.as_deref(),
    );
    check_egress(transaction, &destinations).await?;
    let source = create_trust_source(&mut **transaction, new).await?;
    let event = unstamped(requester, CREATE_ACTION, None, &source);
    Ok((source, event))
}

/// Creates the trust source `new` at revision 1 for the operator whose
/// credential has `public_identity`, after the IR-152 egress check of its
/// `discovery_url` and `token_review_endpoint`, and appends its
/// `trust_source.create` event last, in `transaction` (see the module docs
/// for the rules, the order and the locks). Runs only under
/// `READ COMMITTED`. The caller commits on `Ok` and rolls back on `Err`.
///
/// Ungated: it applies a widening write on one operator's authority, so it
/// is visible only within `trust` (see the module docs, "Not done here");
/// [`submit_create_source`] is the gated write. Nothing in the crate calls
/// it outside tests: the integration tests reach it through
/// `trust::test_support` (the `test-support` feature).
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn create_source(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewTrustSource,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    check_create_syntax(new)?;
    in_savepoint(transaction, async |savepoint| {
        create_steps(savepoint, public_identity, new, audit).await
    })
    .await
}

/// Steps 0 to 5 of `create_source`, in its savepoint.
async fn create_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    new: &NewTrustSource,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    require_read_committed::<SourceWriteError>(transaction).await?;
    let requester =
        authorize_trust_admin::<SourceWriteError>(transaction, public_identity, &new.tenant_id)
            .await?;
    let (source, event) = apply_create_source(transaction, &requester, new).await?;
    append_stamped(transaction, event, audit.event_id, audit.now, SUCCESS).await?;
    Ok(source)
}

/// Requests the create of the trust source `new` (proposal section 3,
/// "Request"): a widening write, enabled or disabled, for the `trust_admin`
/// of `new.tenant_id` whose credential has `submission.public_identity`.
///
/// Before any statement: the syntax of its destinations and D27. Then, in
/// a savepoint, only under `READ COMMITTED`: the requester's rows
/// `FOR SHARE` (with its instance `security_admin` binding, if any; Q4),
/// `acknowledge_widening` ([`SourceWriteError::WideningNotAcknowledged`]),
/// the policy row `FOR SHARE` ([`SourceWriteError::PolicyUnavailable`]),
/// and the mode:
///
/// - `widening_second_approver` off: applied at once, as
///   `create_source`, with the event's outcome `success_widening` (D23);
/// - on, `single_actor_mode` on and the requester also an instance
///   `security_admin`: applied at once, outcome `success_single_actor`
///   (Q4);
/// - otherwise the create's checks (each destination's entry `FOR SHARE`,
///   enabled), then a pending `trust_source_create` operation at expected
///   revision 0, whose plan holds the source's members. No source is
///   written.
///
/// The caller commits on `Ok` and rolls back on `Err`.
pub async fn submit_create_source(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    new: &NewTrustSource,
) -> Result<Gated<TrustSource>, SourceWriteError> {
    check_create_request(new)?;
    in_savepoint(transaction, async |savepoint| {
        submit_create_steps(savepoint, submission, new).await
    })
    .await
}

/// Request steps 0 to 8 of [`submit_create_source`], in its savepoint.
async fn submit_create_steps(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    new: &NewTrustSource,
) -> Result<Gated<TrustSource>, SourceWriteError> {
    require_read_committed::<SourceWriteError>(transaction).await?;
    let (requester, mode) =
        authorize_widening_write::<SourceWriteError>(transaction, submission, &new.tenant_id)
            .await?;
    match mode {
        Mode::Apply(outcome) => {
            let (source, event) = apply_create_source(transaction, &requester, new).await?;
            append_stamped(
                transaction,
                event,
                submission.event_id,
                submission.now,
                outcome,
            )
            .await?;
            Ok(Gated::Applied(source))
        }
        Mode::Pending => {
            let destinations = destinations(
                new.discovery_url.as_deref(),
                new.token_review_endpoint.as_deref(),
            );
            check_egress(transaction, &destinations).await?;
            let plan = CreateSourcePlan::new(&requester.credential_id, new);
            let request = PendingRequest {
                kind: OperationKind::TrustSourceCreate,
                tenant_id: Some(&new.tenant_id),
                // A create has no target revision (README:946).
                expected_revision: 0,
                plan: plan.to_plan(),
            };
            let pending =
                insert_pending::<SourceWriteError>(transaction, submission, &requester, request)
                    .await?;
            Ok(Gated::Pending(pending))
        }
    }
}

/// Step 2 of an update: the stored row of the source `id` of `tenant_id`,
/// every column, `FOR NO KEY UPDATE`, before any entry lock, so that a
/// concurrent update of the source waits here and holds no entry lock. A
/// missing row is [`RegistryError::NotFound`] and another revision than
/// `expected_revision` [`RegistryError::StaleRevision`].
pub(crate) async fn lock_source(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
) -> Result<TrustSource, SourceWriteError> {
    let stored: TrustSource = sqlx::query_as(LOCK_SOURCE)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(RegistryError::NotFound)?;
    if stored.revision != expected_revision {
        return Err(RegistryError::StaleRevision.into());
    }
    Ok(stored)
}

/// Step 3 of an update of `stored`: each destination of `changes` that
/// differs byte-wise from the stored one, its syntax and then its entry
/// `FOR SHARE`, enabled. A gated update's pending request runs exactly
/// this (D7).
async fn check_update(
    transaction: &mut Transaction<'_, Postgres>,
    stored: &TrustSource,
    changes: &TrustSourceChanges,
) -> Result<(), SourceWriteError> {
    let destinations = destinations(
        changed(&changes.discovery_url, stored.discovery_url.as_deref()),
        changed(
            &changes.token_review_endpoint,
            stored.token_review_endpoint.as_deref(),
        ),
    );
    for destination in &destinations {
        check_syntax(*destination)?;
    }
    check_egress(transaction, &destinations).await
}

/// Steps 3 and 4 of an update of `stored`, the row [`lock_source`]
/// locked, by `requester`: [`check_update`], then the compare-and-set at
/// the stored revision. Returns the row and its `trust_source.update`
/// event, unstamped (D26).
pub(crate) async fn apply_locked_update(
    transaction: &mut Transaction<'_, Postgres>,
    requester: &Requester,
    stored: &TrustSource,
    changes: &TrustSourceChanges,
) -> Result<(TrustSource, UnstampedEvent), SourceWriteError> {
    check_update(transaction, stored, changes).await?;
    let source = update_trust_source(
        &mut **transaction,
        &stored.tenant_id,
        &stored.id,
        stored.revision,
        changes,
    )
    .await?;
    let event = unstamped(requester, UPDATE_ACTION, Some(stored.revision), &source);
    Ok((source, event))
}

/// What a source update is (Q2, ruled by the user, 2026-11-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateClass {
    /// `status` set to `disabled` and every other member equal to the
    /// stored one: not widening, so it lands at once with outcome
    /// `success`, whatever the policy.
    DisableOnly,
    /// Anything else: an enable or re-enable, a disable that also changes
    /// another member, any other change, and a write that changes nothing
    /// on an enabled source.
    Widening,
}

/// Whether the `proof_bounds` of the source `stored`, which this
/// transaction has locked, equals `proof_bounds` under the database's
/// `jsonb` equality: exact for every stored number, also one beyond `f64`
/// precision that the row read into [`TrustSource`] has rounded; key order
/// does not count, and numbers compare by value (`1` equals `1.0`).
pub(crate) async fn proof_bounds_equal(
    transaction: &mut Transaction<'_, Postgres>,
    stored: &TrustSource,
    proof_bounds: &JsonObject,
) -> Result<bool, SourceWriteError> {
    let equal = sqlx::query_scalar(PROOF_BOUNDS_EQUAL)
        .bind(&stored.tenant_id)
        .bind(&stored.id)
        .bind(Json(proof_bounds))
        .fetch_one(&mut **transaction)
        .await?;
    Ok(equal)
}

/// The class of an update of `stored` to `changes` (Q2), decided by the
/// server from the stored row, never by the caller: disable-only when
/// `changes.status` is `disabled` and [`changed_members`] names no other
/// member, `proof_bounds_equal` being [`proof_bounds_equal`]'s answer. A
/// source already disabled and written with the same members is
/// disable-only too (inferred: it widens nothing).
pub(crate) fn classify_source_update(
    stored: &TrustSource,
    changes: &TrustSourceChanges,
    proof_bounds_equal: bool,
) -> UpdateClass {
    let others_unchanged = changed_members(stored, changes, proof_bounds_equal)
        .into_iter()
        .all(|member| member == STATUS_MEMBER);
    if changes.status == Status::Disabled && others_unchanged {
        UpdateClass::DisableOnly
    } else {
        UpdateClass::Widening
    }
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
///
/// Ungated (an update, a widening one or not, without the gate) and
/// `pub(super)`, as `create_source`;
/// [`submit_update_source`] is the gated write.
#[cfg_attr(
    not(feature = "test-support"),
    expect(dead_code, reason = "ungated: tests only, through test_support")
)]
pub(super) async fn update_source(
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

/// Steps 0 to 5 of `update_source`, in its savepoint. `target` is the
/// tenant, the ID and the expected revision.
async fn update_steps(
    transaction: &mut Transaction<'_, Postgres>,
    public_identity: &str,
    (tenant_id, id, expected_revision): (&str, &str, i64),
    changes: &TrustSourceChanges,
    audit: &SourceAudit<'_>,
) -> Result<TrustSource, SourceWriteError> {
    require_read_committed::<SourceWriteError>(transaction).await?;
    let requester =
        authorize_trust_admin::<SourceWriteError>(transaction, public_identity, tenant_id).await?;
    let stored = lock_source(transaction, tenant_id, id, expected_revision).await?;
    let (source, event) = apply_locked_update(transaction, &requester, &stored, changes).await?;
    append_stamped(transaction, event, audit.event_id, audit.now, SUCCESS).await?;
    Ok(source)
}

/// Requests the update of the trust source `id` of `tenant_id` at
/// `expected_revision` to `changes` (proposal section 3, "Request"), for
/// the `trust_admin` whose credential has `submission.public_identity`.
///
/// Before any statement: D27 on `changes`. Then, in a savepoint, only
/// under `READ COMMITTED`: the requester's rows `FOR SHARE` (with its
/// instance `security_admin` binding, if any; Q4), the policy row
/// `FOR SHARE`, the stored row ([`RegistryError::NotFound`],
/// [`RegistryError::StaleRevision`]), and the class (Q2):
///
/// - disable-only: applied at once, as `update_source`, outcome
///   `success`, whatever the policy and the flag;
/// - widening: without `acknowledge_widening`,
///   [`SourceWriteError::WideningNotAcknowledged`]; with no policy row,
///   [`SourceWriteError::PolicyUnavailable`]; then the mode, as
///   [`submit_create_source`]'s: applied at once with `success_widening` or
///   `success_single_actor`, or the update's checks (each changed
///   destination's syntax and entry) and a pending `trust_source_update`
///   operation at the stored revision, whose plan holds the changes and
///   the names of the members they change. The source is not written.
///
/// The caller commits on `Ok` and rolls back on `Err`.
pub async fn submit_update_source(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    tenant_id: &str,
    id: &str,
    expected_revision: i64,
    changes: &TrustSourceChanges,
) -> Result<Gated<TrustSource>, SourceWriteError> {
    check_update_request(changes)?;
    let target = (tenant_id, id, expected_revision);
    in_savepoint(transaction, async |savepoint| {
        submit_update_steps(savepoint, submission, target, changes).await
    })
    .await
}

/// Request steps 0 to 8 of [`submit_update_source`], in its savepoint.
async fn submit_update_steps(
    transaction: &mut Transaction<'_, Postgres>,
    submission: &Submission<'_>,
    (tenant_id, id, expected_revision): (&str, &str, i64),
    changes: &TrustSourceChanges,
) -> Result<Gated<TrustSource>, SourceWriteError> {
    require_read_committed::<SourceWriteError>(transaction).await?;
    let gated =
        authorize_gated_requester::<SourceWriteError>(transaction, submission, tenant_id).await?;
    // The policy row before the source row, in the lock order, for every
    // update, a disable-only one included (inferred: one lock order
    // whatever the class, which only the stored row decides).
    let policy = lock_policy_shared::<SourceWriteError>(transaction).await?;
    let stored = lock_source(transaction, tenant_id, id, expected_revision).await?;
    let equal = proof_bounds_equal(transaction, &stored, &changes.proof_bounds).await?;
    let mode = match classify_source_update(&stored, changes, equal) {
        UpdateClass::DisableOnly => Mode::Apply(OUTCOME_SUCCESS),
        UpdateClass::Widening => {
            require_acknowledged::<SourceWriteError>(submission)?;
            widening_mode::<SourceWriteError>(&gated, policy.as_ref())?
        }
    };
    let requester = gated.requester;
    match mode {
        Mode::Apply(outcome) => {
            let (source, event) =
                apply_locked_update(transaction, &requester, &stored, changes).await?;
            append_stamped(
                transaction,
                event,
                submission.event_id,
                submission.now,
                outcome,
            )
            .await?;
            Ok(Gated::Applied(source))
        }
        Mode::Pending => {
            check_update(transaction, &stored, changes).await?;
            let plan = UpdateSourcePlan::new(&requester.credential_id, &stored, changes, equal);
            let request = PendingRequest {
                kind: OperationKind::TrustSourceUpdate,
                tenant_id: Some(tenant_id),
                expected_revision: stored.revision,
                plan: plan.to_plan(),
            };
            let pending =
                insert_pending::<SourceWriteError>(transaction, submission, &requester, request)
                    .await?;
            Ok(Gated::Pending(pending))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::registry::{AssertionProfile, ReplayMode, TrustSourceKind};

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
        // The full stored row: every column `TrustSource` reads.
        assert!(LOCK_SOURCE.starts_with(
            "SELECT id, tenant_id, name, kind, exact_issuer, discovery_url, jwks_keyset_id, \
             cluster_id, token_review_endpoint, ca_bundle_ref, ca_fingerprint, \
             reviewer_credential_ref, review_timeout_ms, audiences, algorithms, proof_bounds, \
             assertion_profile, stale_revocation_acknowledged, replay_mode, status, revision \
             FROM trust_source "
        ));
    }

    fn object(value: serde_json::Value) -> crate::persistence::registry::JsonObject {
        match value {
            serde_json::Value::Object(members) => members,
            other => panic!("not an object: {other}"),
        }
    }

    fn stored(status: Status) -> TrustSource {
        TrustSource {
            id: "src_1".into(),
            tenant_id: "ten_a".into(),
            name: "source-1".into(),
            kind: TrustSourceKind::OidcDiscovery,
            exact_issuer: "https://issuer.example".into(),
            discovery_url: Some("https://issuer.example/.well-known/openid-configuration".into()),
            jwks_keyset_id: None,
            cluster_id: None,
            token_review_endpoint: None,
            ca_bundle_ref: None,
            ca_fingerprint: None,
            reviewer_credential_ref: None,
            review_timeout_ms: None,
            audiences: vec!["aud_a".into()],
            algorithms: Some(vec!["ES256".into()]),
            proof_bounds: object(serde_json::json!({"a": 1, "b": [true]})),
            assertion_profile: AssertionProfile::OnDemandJwt,
            stale_revocation_acknowledged: None,
            replay_mode: ReplayMode::Reusable,
            status,
            revision: 4,
        }
    }

    fn same(stored: &TrustSource) -> TrustSourceChanges {
        TrustSourceChanges {
            name: stored.name.clone(),
            exact_issuer: stored.exact_issuer.clone(),
            discovery_url: stored.discovery_url.clone(),
            token_review_endpoint: stored.token_review_endpoint.clone(),
            ca_bundle_ref: stored.ca_bundle_ref.clone(),
            ca_fingerprint: stored.ca_fingerprint.clone(),
            reviewer_credential_ref: stored.reviewer_credential_ref.clone(),
            review_timeout_ms: stored.review_timeout_ms,
            audiences: stored.audiences.clone(),
            algorithms: stored.algorithms.clone(),
            proof_bounds: stored.proof_bounds.clone(),
            assertion_profile: stored.assertion_profile,
            stale_revocation_acknowledged: stored.stale_revocation_acknowledged,
            replay_mode: stored.replay_mode,
            status: stored.status,
        }
    }

    /// [`classify_source_update`] with `serde_json`'s equality of the proof
    /// bounds standing in for the database's `jsonb` equality, which agrees
    /// with it on every value here.
    fn classify(stored: &TrustSource, changes: &TrustSourceChanges) -> UpdateClass {
        classify_source_update(stored, changes, stored.proof_bounds == changes.proof_bounds)
    }

    /// Q2: a disable that changes nothing else is not widening; an enable,
    /// a re-enable, a write that changes nothing on an enabled source and a
    /// disable that changes any other member are.
    #[test]
    fn only_a_disable_that_changes_nothing_else_is_disable_only() {
        let enabled = stored(Status::Enabled);
        let disabled = stored(Status::Disabled);
        let mut disable = same(&enabled);
        disable.status = Status::Disabled;
        assert_eq!(classify(&enabled, &disable), UpdateClass::DisableOnly);
        assert_eq!(
            classify(&disabled, &same(&disabled)),
            UpdateClass::DisableOnly
        );
        // The key order of the proof bounds is no change.
        let mut reordered = disable.clone();
        reordered.proof_bounds = object(serde_json::json!({"b": [true], "a": 1}));
        assert_eq!(classify(&enabled, &reordered), UpdateClass::DisableOnly);
        assert_eq!(classify(&enabled, &same(&enabled)), UpdateClass::Widening);
        let mut enable = same(&disabled);
        enable.status = Status::Enabled;
        assert_eq!(classify(&disabled, &enable), UpdateClass::Widening);
        type Change = fn(&mut TrustSourceChanges);
        let others: [Change; 14] = [
            |c| c.name.push('x'),
            |c| c.exact_issuer.push('x'),
            |c| c.discovery_url = Some("https://other.example/".into()),
            |c| c.token_review_endpoint = Some("https://other.example/".into()),
            |c| c.ca_bundle_ref = Some("ca".into()),
            |c| c.ca_fingerprint = Some("sha256:ca".into()),
            |c| c.reviewer_credential_ref = Some("reviewer".into()),
            |c| c.review_timeout_ms = Some(1000),
            |c| c.audiences.push("aud_b".into()),
            |c| c.algorithms = None,
            |c| c.proof_bounds = object(serde_json::json!({"a": 2, "b": [true]})),
            |c| c.assertion_profile = AssertionProfile::ReusableJwt,
            |c| c.stale_revocation_acknowledged = Some(true),
            |c| c.replay_mode = ReplayMode::SingleUse,
        ];
        for (index, change) in others.into_iter().enumerate() {
            for (row, base) in [(&enabled, &disable), (&disabled, &same(&disabled))] {
                let mut changes = base.clone();
                change(&mut changes);
                assert_eq!(
                    classify(row, &changes),
                    UpdateClass::Widening,
                    "change {index} of a {:?} source",
                    row.status
                );
            }
        }
    }

    fn constraint(result: Result<(), SourceWriteError>) -> Option<&'static str> {
        match result {
            Ok(()) => None,
            Err(SourceWriteError::Registry(RegistryError::Invariant {
                kind: InvariantKind::Check,
                constraint,
            })) => constraint,
            Err(other) => panic!("not a check: {other:?}"),
        }
    }

    fn k8s_new() -> NewTrustSource {
        NewTrustSource {
            id: "src_2".into(),
            tenant_id: "ten_a".into(),
            name: "k8s".into(),
            kind: TrustSourceKind::KubernetesTokenReview,
            exact_issuer: "https://kubernetes.default.svc".into(),
            discovery_url: None,
            jwks_keyset_id: None,
            cluster_id: Some("cluster_1".into()),
            token_review_endpoint: Some("https://k3s.internal.example:6443/".into()),
            ca_bundle_ref: Some("ca".into()),
            ca_fingerprint: Some("sha256:ca".into()),
            reviewer_credential_ref: Some("reviewer".into()),
            review_timeout_ms: Some(5000),
            audiences: vec!["aud_a".into()],
            algorithms: None,
            proof_bounds: object(serde_json::json!({})),
            assertion_profile: AssertionProfile::ProjectedServiceAccount,
            stale_revocation_acknowledged: None,
            replay_mode: ReplayMode::Reusable,
            status: Status::Enabled,
        }
    }

    /// D27: each plainly typed check is refused as the database refuses
    /// it, the domain first and then the table's checks by name; the
    /// destinations are the syntax rules'.
    #[test]
    fn the_typed_checks_refuse_as_the_database_does() {
        assert_eq!(constraint(check_create_request(&k8s_new())), None);
        type Change = fn(&mut NewTrustSource);
        let cases: [(Change, &str); 14] = [
            (|n| n.id.clear(), "trust_source_id_check"),
            (|n| n.name.clear(), "trust_source_name_check"),
            (
                |n| n.exact_issuer.clear(),
                "trust_source_exact_issuer_check",
            ),
            (
                |n| n.cluster_id = Some(String::new()),
                "trust_source_cluster_id_check",
            ),
            (
                |n| n.ca_bundle_ref = Some(String::new()),
                "trust_source_ca_bundle_ref_check",
            ),
            (
                |n| n.ca_fingerprint = Some(String::new()),
                "trust_source_ca_fingerprint_check",
            ),
            (
                |n| n.reviewer_credential_ref = Some(String::new()),
                "trust_source_reviewer_credential_ref_check",
            ),
            (
                |n| n.review_timeout_ms = Some(0),
                "trust_source_review_timeout_ms_check",
            ),
            (
                |n| n.review_timeout_ms = Some(-1),
                "trust_source_review_timeout_ms_check",
            ),
            (|n| n.audiences.clear(), "trust_source_audiences_check"),
            (|n| n.audiences.push(String::new()), STRING_LIST_CHECK),
            (
                |n| n.algorithms = Some(Vec::new()),
                "trust_source_algorithms_check",
            ),
            (
                |n| n.algorithms = Some(vec!["ES256".into(), String::new()]),
                STRING_LIST_CHECK,
            ),
            (
                |n| n.stale_revocation_acknowledged = Some(false),
                "trust_source_stale_revocation_acknowledged_check",
            ),
        ];
        for (change, expected) in cases {
            let mut new = k8s_new();
            change(&mut new);
            assert_eq!(constraint(check_create_request(&new)), Some(expected));
        }
        // Values the checks accept.
        let mut fine = k8s_new();
        fine.review_timeout_ms = Some(1);
        fine.stale_revocation_acknowledged = Some(true);
        fine.algorithms = Some(vec!["ES256".into()]);
        assert_eq!(constraint(check_create_request(&fine)), None);
        // Several at once: the domain, then by name.
        let mut several = k8s_new();
        several.name.clear();
        several.audiences.clear();
        several.algorithms = Some(vec![String::new()]);
        assert_eq!(
            constraint(check_create_request(&several)),
            Some(STRING_LIST_CHECK)
        );
        several.algorithms = None;
        assert_eq!(
            constraint(check_create_request(&several)),
            Some("trust_source_audiences_check")
        );
        // A destination is the syntax rules', first.
        let mut empty_destination = k8s_new();
        empty_destination.token_review_endpoint = Some(String::new());
        empty_destination.name.clear();
        assert!(matches!(
            check_create_request(&empty_destination),
            Err(SourceWriteError::InvalidDestination {
                member: TOKEN_REVIEW_ENDPOINT
            })
        ));
        // An update checks its changes, never an ID.
        let source = stored(Status::Enabled);
        assert_eq!(constraint(check_update_request(&same(&source))), None);
        let mut changes = same(&source);
        changes.exact_issuer.clear();
        assert_eq!(
            constraint(check_update_request(&changes)),
            Some("trust_source_exact_issuer_check")
        );
        changes = same(&source);
        changes.stale_revocation_acknowledged = Some(false);
        assert_eq!(
            constraint(check_update_request(&changes)),
            Some("trust_source_stale_revocation_acknowledged_check")
        );
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
                SourceWriteError::WideningNotAcknowledged,
                "the trust source write is widening and was not acknowledged",
            ),
            (
                SourceWriteError::PolicyUnavailable,
                "the instance security policy is unavailable",
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
