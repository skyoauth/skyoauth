//! A normal build of the workspace, without the `test-support` feature,
//! neither exposes nor calls the ungated trust writes, and exposes none of
//! the bare registry trust writers, operator writers, audit append or
//! operation-row writers (second-approver proposal,
//! `docs/proposals/second-approver-gated-writes.md`, PRs 7, 9 and 10), nor
//! the checker, action, tenant and principal writers that only the audited
//! writes of `crate::admin` call (the proposal's survey under "Still open
//! after PRs 7, 9 and 10").
//!
//! `create_version`, `enable_version`, `create_source` and `update_source`
//! apply a write without the second-approver gate, so they are visible only
//! within `trust` (`pub(super)`, PR 7). The registry's
//! `create_trust_keyset_version`, `update_trust_keyset_version`,
//! `create_trust_source` and `update_trust_source` write a keyset version
//! or a trust source with no authorization, no gate and no audit event, so
//! they are crate-private (`pub(crate)`, PR 9): the trust write path in
//! `crate::trust` calls them, gated paths included, so they cannot be
//! narrower. PR 10 does the same for the registry's operator writers, audit
//! append and operation-row writers: `create_admin_identity`,
//! `create_admin_credential` and `create_admin_role_binding` are visible
//! only within the registry (`pub(super)`), whose `bootstrap_instance` and
//! `restore_operator` (once it has verified the recovery signature itself,
//! `docs/proposals/recovery-verified-response.md`) call them;
//! `update_admin_role_binding` is `pub(super)` too and has no caller in the
//! crate, so it carries PR 7's `expect(dead_code)`; `append_audit_event`
//! and the operation-row writers `insert_administrative_operation`,
//! `consume_administrative_operation` and `revoke_administrative_operation`
//! are `pub(crate)`, called by `crate::operation` and `crate::trust` as
//! well. The checker writers, the action writers, `update_tenant` and
//! `update_principal` of the registry are `pub(crate)` too: the audited,
//! authorized writes of `crate::admin` call them, and nothing else in the
//! crate does.
//! Only the `#[doc(hidden)]` modules `trust::test_support` and
//! `persistence::registry::test_support`, compiled with the feature, expose
//! them to tests. The same feature gates `ids::test_support`, whose
//! `SequentialIds` generates predictable IDs: the probes below require it
//! to be unreachable too, next to a control that the public `ids` items
//! resolve. Every test target of this package is built with the
//! feature (the package's dev-dependency on itself), and so is every test
//! target of `skyoauth-scenarios` (its dev-dependency on this package), so
//! a test cannot simply name the writers and expect a compile error. This
//! test therefore checks the library without the feature, as a dependent
//! crate would see it: it runs `cargo check` on the workspace's libraries
//! and binaries (a build that turns no dev-dependency feature on, and that
//! a workspace member enabling the feature through a normal or build
//! dependency would change), in a target directory of its own, and then:
//!
//! - asserts that `skyoauth-service`'s library was built with no feature;
//! - asserts that the library emitted no warning. Without the feature each
//!   `trust` writer and the registry writer of [`REGISTRY_DEAD`] carry
//!   `expect(dead_code)`, so a caller in their visibility, a public
//!   forwarder included, makes the expectation unfulfilled, which is a
//!   warning (a caller outside it is a privacy error in every build);
//! - compiles small probe crates against the library's metadata with
//!   `rustc`. A probe that names an ungated writer, a bare registry writer,
//!   a registry writer that PR 10 or the hardening after it made
//!   crate-private, one of the crate-private steps below or one of their
//!   callers at any of its paths must fail as a private
//!   (E0603) or unresolved (E0432) path, and a probe that names the public
//!   writes and registry items, the registry writers that deliberately stay
//!   public included, must compile, so a probe that fails for an unrelated
//!   reason (a toolchain mismatch, a missing crate) or a narrowing of what
//!   must stay public fails this test instead of passing it.
//!
//! The registry writers but the one of [`REGISTRY_DEAD`] are called in every
//! build, and so are the six crate-private steps of `trust` that apply a
//! write without authorizing, gating or auditing it themselves
//! (`insert_create_version`, `apply_create_version`,
//! `apply_enable_version`, `apply_status`, `apply_create_source`,
//! `apply_locked_update`; PR 7's `expect(dead_code)` covers only the four
//! `pub(super)` writers, not these), so no dead-code guard fits them. A
//! source check stands in for it: outside comments and string and character
//! literals, the library names each writer and each step only at the places
//! a table lists (the definition, the crate-private re-export, the
//! test-support wrapper, the `use`s, and the callers in `trust::keyset`,
//! `trust::source`, `crate::operation`, `crate::admin` and the registry's
//! bootstrap and recovery), and, one level up, each of those callers
//! ([`CALLERS`]: `bootstrap_steps`, `insert_pending`, each `append_stamped`,
//! `crate::admin`'s `append_event` and `write_*` helpers and the rest, and
//! `trust::keyset`'s `set_status`, the one caller of a caller that is not
//! public or itself guarded; `set_status` and the `crate::admin` helpers
//! are counted in their own module only ([`SCOPED`]: they are private
//! there)), each keyed by the item that holds it
//! (a top-level item, or an `impl` block at any depth) with that item's
//! visibility and counted. So a forwarder of another name, a new caller, a
//! widened definition or caller and a public method of an `impl` nested in
//! a function body each change a key or a count. The check also refuses
//! source that could hide an item from those keys (`rustfmt::skip`,
//! `#[path]`, `include!`, and a level set for `non_local_definitions`, the
//! warning a nested `impl` draws, or for `warnings`, in the source, the
//! manifests or the workspace's cargo configuration) and a writer or step
//! imported or cast under another name (`<name> as`; inferred). The probes
//! also require each step and each caller to be unreachable from outside
//! the crate, and each writer of [`REGISTRY_PRIVATE`]'s path through its
//! defining module to be private (E0603), not missing. The source check
//! reads text, not the compiled crate, and does not see everything: the
//! second-approver proposal, "PR 10 as implemented", records the mutants it
//! was run against and what still escapes it.
//!
//! It needs no database, so it is not `#[ignore]`d (inferred), and runs
//! offline from the crates the outer build has already fetched. The first
//! run checks every dependency (about 40 s on four cores); later runs
//! reuse the target directory under `CARGO_TARGET_TMPDIR`.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

/// The ungated writers, by the module that defines them.
const UNGATED: [(&str, &str); 4] = [
    ("keyset", "create_version"),
    ("keyset", "enable_version"),
    ("source", "create_source"),
    ("source", "update_source"),
];

/// The writes a normal build must keep public: the gated ones, and the
/// keyset disable, which is not widening and never gated.
const PUBLIC: [&str; 6] = [
    "keyset::submit_create_version",
    "keyset::submit_enable_version",
    "keyset::disable_version",
    "source::submit_create_source",
    "source::submit_update_source",
    "disable_version",
];

/// The bare registry trust writers (PR 9), defined in
/// `persistence/registry/trust.rs`.
const REGISTRY_UNGATED: [&str; 4] = [
    "create_trust_keyset_version",
    "update_trust_keyset_version",
    "create_trust_source",
    "update_trust_source",
];

/// The registry writers that PR 10 and the checker, action, tenant and
/// principal hardening after it made crate-private, by the private module
/// of `persistence::registry` that defines them: the operator writers
/// (`pub(super)`: the three creates are called only by the registry's
/// `bootstrap` and `recovery`, the update by nothing in the crate), the
/// audit append and the operation-row writers (`pub(crate)`:
/// `crate::operation`, `crate::trust` and `crate::admin` call the append,
/// the first the operation-row writers), and the checker, action, tenant
/// and principal writers (`pub(crate)`: the audited, authorized writes of
/// `crate::admin` call them).
const REGISTRY_PRIVATE: [(&str, &str); 16] = [
    ("operator", "create_admin_identity"),
    ("operator", "create_admin_credential"),
    ("operator", "create_admin_role_binding"),
    ("operator", "update_admin_role_binding"),
    ("events", "append_audit_event"),
    ("operation", "insert_administrative_operation"),
    ("operation", "consume_administrative_operation"),
    ("operation", "revoke_administrative_operation"),
    ("audience", "create_resource_server_checker"),
    ("audience", "update_resource_server_checker"),
    ("audience", "add_resource_server_checker_tenant"),
    ("audience", "remove_resource_server_checker_tenant"),
    ("audience", "create_resource_action"),
    ("audience", "update_resource_action"),
    ("tenant", "update_tenant"),
    ("tenant", "update_principal"),
];

/// The registry writer of [`REGISTRY_PRIVATE`] that nothing in the crate
/// calls, so that it carries the `expect(dead_code)` guard, by its file
/// under `src`. The checker, action, tenant and principal writers left this
/// table when `crate::admin` became their caller.
const REGISTRY_DEAD: [(&str, &str); 1] = [(
    "persistence/registry/operator.rs",
    "update_admin_role_binding",
)];

/// The crate-private steps of the trust write path that apply a write
/// without authorizing, gating or auditing it themselves: the four that
/// call a bare registry writer (`insert_create_version`, `apply_status`,
/// `apply_create_source`, `apply_locked_update`) and the two that call
/// those (`apply_create_version`, `apply_enable_version`), by module. Their
/// callers authorize, gate and audit; `crate::operation`'s approval calls
/// four of them, so they are `pub(crate)` (but `apply_status`, which is
/// private to `trust::keyset`). None may be reachable from outside the
/// crate.
const STEPS: [(&str, &str); 6] = [
    ("keyset", "insert_create_version"),
    ("keyset", "apply_create_version"),
    ("keyset", "apply_enable_version"),
    ("keyset", "apply_status"),
    ("source", "apply_create_source"),
    ("source", "apply_locked_update"),
];

/// The callers one level up: each function of the library, other than the
/// [`STEPS`], that names a bare registry writer, a writer of
/// [`REGISTRY_PRIVATE`] or a step, by the module that defines it (from the
/// crate root) and the module that re-exports it, if any. Each authorizes,
/// gates, verifies or audits for its own public caller (the registry's
/// `bootstrap_steps`, `issue_steps` and `restore_steps`; `crate::trust`'s
/// `append_stamped` and `*_steps`; `crate::operation`'s approval steps,
/// `toggle_steps` and `insert_pending`, the pending branch of every gated
/// `submit_*`; `crate::admin`'s `append_event` and the `write_*` helpers of
/// its updates, whose public writes authorize first), so a public forwarder of one of them, under another name,
/// would reach an ungated write as surely as a forwarder of the writer: the
/// source check counts where each is named too, and the probes require each
/// to be unreachable from outside the crate.
const CALLERS: [(&str, &str, &str); 27] = [
    ("admin::workload", "admin", "append_event"),
    ("admin::workload", "admin", "write_resource_server"),
    ("admin::workload", "admin", "write_assignment"),
    ("admin::workload", "admin", "write_checker"),
    ("admin::workload", "admin", "write_action"),
    (
        "persistence::registry::bootstrap",
        "persistence::registry",
        "bootstrap_steps",
    ),
    (
        "persistence::registry::recovery",
        "persistence::registry",
        "issue_steps",
    ),
    (
        "persistence::registry::recovery",
        "persistence::registry",
        "restore_steps",
    ),
    ("operation::toggle", "operation", "insert_pending"),
    ("operation::toggle", "operation", "toggle_steps"),
    ("operation::approval", "operation", "approve_steps"),
    ("operation::approval", "operation", "revoke_steps"),
    ("operation::approval", "operation", "apply_create"),
    ("operation::approval", "operation", "apply_enable"),
    ("operation::approval", "operation", "apply_source_create"),
    ("operation::approval", "operation", "apply_source_update"),
    ("trust::keyset", "trust", "append_stamped"),
    ("trust::keyset", "trust", "create_steps"),
    ("trust::keyset", "trust", "submit_create_steps"),
    ("trust::keyset", "trust", "status_steps"),
    ("trust::keyset", "trust", "submit_enable_steps"),
    ("trust::keyset", "trust", "set_status"),
    ("trust::source", "trust", "append_stamped"),
    ("trust::source", "trust", "create_steps"),
    ("trust::source", "trust", "submit_create_steps"),
    ("trust::source", "trust", "update_steps"),
    ("trust::source", "trust", "submit_update_steps"),
];

/// Names the source check counts only in the files of the module that
/// defines them (its file, and the files of its submodules), as a path
/// under `src/` without `.rs`. `trust::keyset`'s `set_status` and
/// `crate::admin::workload`'s helpers are private, so only that module and
/// its descendants can name them: the same name elsewhere is another item
/// (a method of another type, say), not a forwarder. Widening one changes
/// the key of its definition, which the count still catches, and a new
/// caller can only be in these files.
const SCOPED: [(&str, &str); 6] = [
    ("set_status", "trust/keyset"),
    ("append_event", "admin/workload"),
    ("write_resource_server", "admin/workload"),
    ("write_assignment", "admin/workload"),
    ("write_checker", "admin/workload"),
    ("write_action", "admin/workload"),
];

/// The registry items of the same tables that stay public: the readers,
/// and the row and input types the test-support wrappers take and return.
const REGISTRY_PUBLIC: [&str; 43] = [
    "get_trust_keyset_version",
    "list_trust_keyset_versions",
    "get_trust_source",
    "list_trust_sources",
    "NewTrustKeysetVersion",
    "TrustKeysetVersion",
    "NewTrustSource",
    "TrustSourceChanges",
    "TrustSource",
    "get_admin_identity",
    "get_admin_credential",
    "get_admin_role_binding",
    "NewAdminIdentity",
    "AdminIdentity",
    "NewAdminCredential",
    "AdminCredential",
    "NewAdminRoleBinding",
    "AdminRoleBindingChanges",
    "AdminRoleBinding",
    "NewAuditEvent",
    "AuditEvent",
    "verify_audit_chain",
    "NewAdministrativeOperation",
    "AdministrativeOperation",
    "lock_administrative_operation",
    "get_resource_server_checker",
    "list_resource_server_checkers",
    "NewResourceServerChecker",
    "ResourceServerCheckerChanges",
    "ResourceServerChecker",
    "get_resource_action",
    "list_resource_actions",
    "NewResourceAction",
    "ResourceActionChanges",
    "ResourceAction",
    "get_tenant",
    "list_tenants",
    "TenantPatch",
    "Tenant",
    "get_principal",
    "list_principals",
    "PrincipalPatch",
    "Principal",
];

/// The registry writers that deliberately stay public (the proposal's
/// "Still open after PRs 7, 9 and 10"): bootstrap, a separate decision, and
/// the two operator writers that only narrow. A change that made one of
/// them crate-private would be a decision this test does not take; the
/// control probe fails on it.
const REGISTRY_KEPT_PUBLIC: [&str; 3] = [
    "bootstrap_instance",
    "disable_admin_identity",
    "revoke_admin_credential",
];

/// The public surface of break-glass restoration
/// (`docs/proposals/recovery-verified-response.md`, section 8): the
/// restore verifies the recovery signature inside, the preview is
/// read-only and grants nothing, and an issue alone enrolls no one, so
/// they are public writes, not ungated ones. The control probe resolves
/// each.
const RECOVERY_PUBLIC: [&str; 12] = [
    "restore_operator",
    "SignedRecoveryResponse",
    "RestoreRequest",
    "Restored",
    "RestoreError",
    "NotRestorableReason",
    "preview_recovery_response",
    "RecoveryPreview",
    "issue_recovery_challenge",
    "IssueChallenge",
    "RecoveryChallenge",
    "get_recovery_state",
];

/// Registry items that no longer exist: `ChallengeBinding`, the
/// caller-supplied digest and hash a restore presented before it verified
/// the signature itself (section 8 of the same proposal).
const REGISTRY_REMOVED: [&str; 1] = ["ChallengeBinding"];

/// The ID items a normal build keeps public (`crate::ids`), compiled by the
/// control probe, so that the probe of [`IDS_TEST_ONLY`] fails for the
/// feature gate, not for a missing or renamed `ids` module.
const IDS_PUBLIC: [&str; 4] = ["IdGenerator", "IdError", "IdKind", "encode_id"];

/// The deterministic ID generator of tests and its module, compiled only
/// with the feature (`ids::test_support`): a normal build has no
/// predictable ID generator for a write path to take.
const IDS_TEST_ONLY: [&str; 2] = ["test_support::SequentialIds", "test_support"];

/// Where the library's source, comments and literals aside, names a bare
/// registry writer, a writer of [`REGISTRY_PRIVATE`], a step of [`STEPS`]
/// or a caller of [`CALLERS`], one entry per line: the file under `src`,
/// the first line of the item that holds the mention (the top-level item,
/// or an `impl` block at any depth that follows it: the `seed` of
/// `trust::keyset`'s tests comes after their `impl Drop for Db`), the name,
/// and how many times, separated by ` | `. The trust writers are defined
/// and re-exported `pub(crate)`, each wrapper is compiled only with
/// `test-support`, and the callers are the trust write path's own steps and
/// `crate::operation`'s approval, none of them public. Of PR 10's writers,
/// the operator writers are defined `pub(super)` and the three creates
/// re-exported privately, to `bootstrap_steps` and `restore_steps` (and the
/// `seed` of a database unit test in `trust::keyset`, through
/// `test_support`); `update_admin_role_binding` is named only by its
/// definition and its wrapper; the audit append and the operation-row
/// writers are defined and re-exported `pub(crate)`, and called by the
/// audited steps of the registry (`bootstrap_steps`, `issue_steps`,
/// `restore_steps`), of `crate::trust` (each module's private
/// `append_stamped`) and of `crate::operation` (the approval's
/// `approve_steps` and `revoke_steps`, the toggle's `toggle_steps`, and
/// `insert_pending`, which the gated `submit_*` writes call). The
/// checker, action, tenant and principal writers are defined and
/// re-exported `pub(crate)`, named by their wrapper, and called only by
/// `crate::admin`: by its private `write_checker` and `write_action` and
/// by its public writes, which authorize first and then append their event
/// through its private `append_event` (a caller of the audit append, like
/// `append_stamped`); those public writes share the writers' names, so
/// `crate::admin`'s own re-export of them is listed too. The last rows list
/// where each caller of [`CALLERS`] is named: its definition, the `use`s
/// and the crate-private re-export of `insert_pending`, the other callers,
/// and the public entry points that call it (`bootstrap_instance`,
/// `issue_recovery_challenge`, `restore_operator`, `approve_operation`,
/// `cancel_operation`, `reject_operation`, `submit_widening_toggle`, the
/// gated `submit_*` of `crate::trust`, the narrowing `disable_version` and
/// the public writes of `crate::admin`), and the ungated `pub(super)` writers of `crate::trust`, which their
/// `expect(dead_code)` guards.
const MENTIONS: &str = "
persistence/registry/mod.rs | pub(crate) use trust::{ | create_trust_keyset_version | 1
persistence/registry/mod.rs | pub(crate) use trust::{ | update_trust_keyset_version | 1
persistence/registry/mod.rs | pub(crate) use trust::{ | create_trust_source | 1
persistence/registry/mod.rs | pub(crate) use trust::{ | update_trust_source | 1
persistence/registry/test_support.rs | pub async fn create_trust_keyset_version<'e>( | create_trust_keyset_version | 2
persistence/registry/test_support.rs | pub async fn update_trust_keyset_version<'e>( | update_trust_keyset_version | 2
persistence/registry/test_support.rs | pub async fn create_trust_source<'e>( | create_trust_source | 2
persistence/registry/test_support.rs | pub async fn update_trust_source<'e>( | update_trust_source | 2
persistence/registry/trust.rs | pub(crate) async fn create_trust_keyset_version<'e>( | create_trust_keyset_version | 1
persistence/registry/trust.rs | pub(crate) async fn update_trust_keyset_version<'e>( | update_trust_keyset_version | 1
persistence/registry/trust.rs | pub(crate) async fn create_trust_source<'e>( | create_trust_source | 1
persistence/registry/trust.rs | pub(crate) async fn update_trust_source<'e>( | update_trust_source | 1
trust/keyset.rs | use crate::persistence::registry::{ | create_trust_keyset_version | 1
trust/keyset.rs | use crate::persistence::registry::{ | update_trust_keyset_version | 1
trust/keyset.rs | pub(crate) async fn insert_create_version( | insert_create_version | 1
trust/keyset.rs | pub(crate) async fn insert_create_version( | create_trust_keyset_version | 1
trust/keyset.rs | pub(crate) async fn apply_create_version( | apply_create_version | 1
trust/keyset.rs | pub(crate) async fn apply_create_version( | insert_create_version | 1
trust/keyset.rs | async fn create_steps( | apply_create_version | 1
trust/keyset.rs | async fn submit_create_steps( | apply_create_version | 1
trust/keyset.rs | async fn status_steps( | apply_status | 1
trust/keyset.rs | async fn apply_status( | apply_status | 1
trust/keyset.rs | async fn apply_status( | update_trust_keyset_version | 1
trust/keyset.rs | pub(crate) async fn apply_enable_version( | apply_enable_version | 1
trust/keyset.rs | pub(crate) async fn apply_enable_version( | apply_status | 1
trust/keyset.rs | async fn submit_enable_steps( | apply_status | 1
trust/source.rs | use crate::persistence::registry::{ | create_trust_source | 1
trust/source.rs | use crate::persistence::registry::{ | update_trust_source | 1
trust/source.rs | pub(crate) async fn apply_create_source( | apply_create_source | 1
trust/source.rs | pub(crate) async fn apply_create_source( | create_trust_source | 1
trust/source.rs | async fn create_steps( | apply_create_source | 1
trust/source.rs | async fn submit_create_steps( | apply_create_source | 1
trust/source.rs | pub(crate) async fn apply_locked_update( | apply_locked_update | 1
trust/source.rs | pub(crate) async fn apply_locked_update( | update_trust_source | 1
trust/source.rs | async fn update_steps( | apply_locked_update | 1
trust/source.rs | async fn submit_update_steps( | apply_locked_update | 1
operation/approval.rs | use crate::trust::{ | apply_create_version | 1
operation/approval.rs | use crate::trust::{ | apply_enable_version | 1
operation/approval.rs | use crate::trust::{ | apply_create_source | 1
operation/approval.rs | use crate::trust::{ | apply_locked_update | 1
operation/approval.rs | async fn apply_create( | apply_create_version | 1
operation/approval.rs | async fn apply_enable( | apply_enable_version | 1
operation/approval.rs | async fn apply_source_create( | apply_create_source | 1
operation/approval.rs | async fn apply_source_update( | apply_locked_update | 1
persistence/registry/mod.rs | pub(crate) use events::{append_audit_event, push_string}; | append_audit_event | 1
persistence/registry/mod.rs | pub(crate) use operation::{ | insert_administrative_operation | 1
persistence/registry/mod.rs | pub(crate) use operation::{ | consume_administrative_operation | 1
persistence/registry/mod.rs | pub(crate) use operation::{ | revoke_administrative_operation | 1
persistence/registry/mod.rs | use operator::{create_admin_credential, create_admin_identity, create_admin_role_binding}; | create_admin_identity | 1
persistence/registry/mod.rs | use operator::{create_admin_credential, create_admin_identity, create_admin_role_binding}; | create_admin_credential | 1
persistence/registry/mod.rs | use operator::{create_admin_credential, create_admin_identity, create_admin_role_binding}; | create_admin_role_binding | 1
persistence/registry/events.rs | pub(crate) async fn append_audit_event( | append_audit_event | 1
persistence/registry/operation.rs | pub(crate) async fn insert_administrative_operation( | insert_administrative_operation | 1
persistence/registry/operation.rs | pub(crate) async fn consume_administrative_operation( | consume_administrative_operation | 1
persistence/registry/operation.rs | pub(crate) async fn revoke_administrative_operation( | revoke_administrative_operation | 1
persistence/registry/operator.rs | pub(super) async fn create_admin_identity<'e>( | create_admin_identity | 1
persistence/registry/operator.rs | pub(super) async fn create_admin_credential<'e>( | create_admin_credential | 1
persistence/registry/operator.rs | pub(super) async fn create_admin_role_binding<'e>( | create_admin_role_binding | 1
persistence/registry/operator.rs | pub(super) async fn update_admin_role_binding<'e>( | update_admin_role_binding | 1
persistence/registry/test_support.rs | pub async fn create_admin_identity<'e>( | create_admin_identity | 2
persistence/registry/test_support.rs | pub async fn create_admin_credential<'e>( | create_admin_credential | 2
persistence/registry/test_support.rs | pub async fn create_admin_role_binding<'e>( | create_admin_role_binding | 2
persistence/registry/test_support.rs | pub async fn update_admin_role_binding<'e>( | update_admin_role_binding | 2
persistence/registry/test_support.rs | pub async fn append_audit_event( | append_audit_event | 2
persistence/registry/test_support.rs | pub async fn insert_administrative_operation( | insert_administrative_operation | 2
persistence/registry/test_support.rs | pub async fn consume_administrative_operation( | consume_administrative_operation | 2
persistence/registry/test_support.rs | pub async fn revoke_administrative_operation( | revoke_administrative_operation | 2
persistence/registry/bootstrap.rs | use super::{ | create_admin_identity | 1
persistence/registry/bootstrap.rs | use super::{ | create_admin_credential | 1
persistence/registry/bootstrap.rs | use super::{ | create_admin_role_binding | 1
persistence/registry/bootstrap.rs | use super::{ | append_audit_event | 1
persistence/registry/bootstrap.rs | async fn bootstrap_steps( | create_admin_identity | 1
persistence/registry/bootstrap.rs | async fn bootstrap_steps( | create_admin_credential | 1
persistence/registry/bootstrap.rs | async fn bootstrap_steps( | create_admin_role_binding | 1
persistence/registry/bootstrap.rs | async fn bootstrap_steps( | append_audit_event | 1
persistence/registry/recovery.rs | use super::{ | create_admin_identity | 1
persistence/registry/recovery.rs | use super::{ | create_admin_credential | 1
persistence/registry/recovery.rs | use super::{ | append_audit_event | 1
persistence/registry/recovery.rs | use super::{ | create_admin_role_binding | 1
persistence/registry/recovery.rs | async fn issue_steps( | append_audit_event | 1
persistence/registry/recovery.rs | async fn restore_steps( | create_admin_identity | 1
persistence/registry/recovery.rs | async fn restore_steps( | create_admin_credential | 1
persistence/registry/recovery.rs | async fn restore_steps( | create_admin_role_binding | 1
persistence/registry/recovery.rs | async fn restore_steps( | append_audit_event | 2
operation/approval.rs | use crate::persistence::registry::{ | append_audit_event | 1
operation/approval.rs | use crate::persistence::registry::{ | consume_administrative_operation | 1
operation/approval.rs | use crate::persistence::registry::{ | insert_administrative_operation | 1
operation/approval.rs | use crate::persistence::registry::{ | revoke_administrative_operation | 1
operation/approval.rs | async fn approve_steps( | append_audit_event | 2
operation/approval.rs | async fn approve_steps( | insert_administrative_operation | 1
operation/approval.rs | async fn approve_steps( | consume_administrative_operation | 1
operation/approval.rs | async fn revoke_steps( | append_audit_event | 1
operation/approval.rs | async fn revoke_steps( | insert_administrative_operation | 1
operation/approval.rs | async fn revoke_steps( | revoke_administrative_operation | 1
operation/toggle.rs | use crate::persistence::registry::{ | append_audit_event | 1
operation/toggle.rs | use crate::persistence::registry::{ | insert_administrative_operation | 1
operation/toggle.rs | pub(crate) async fn insert_pending<E: From<RegistryError>>( | append_audit_event | 1
operation/toggle.rs | pub(crate) async fn insert_pending<E: From<RegistryError>>( | insert_administrative_operation | 1
operation/toggle.rs | async fn toggle_steps( | append_audit_event | 1
trust/keyset.rs | use crate::persistence::registry::{ | append_audit_event | 1
trust/keyset.rs | async fn append_stamped( | append_audit_event | 1
trust/keyset.rs |         impl Drop for Db { | create_admin_identity | 1
trust/keyset.rs |         impl Drop for Db { | create_admin_credential | 1
trust/keyset.rs |         impl Drop for Db { | create_admin_role_binding | 1
trust/source.rs | use crate::persistence::registry::{ | append_audit_event | 1
trust/source.rs | async fn append_stamped( | append_audit_event | 1
persistence/registry/audience.rs | pub(crate) async fn create_resource_server_checker<'e>( | create_resource_server_checker | 1
persistence/registry/audience.rs | pub(crate) async fn update_resource_server_checker<'e>( | update_resource_server_checker | 1
persistence/registry/audience.rs | pub(crate) async fn add_resource_server_checker_tenant<'e>( | add_resource_server_checker_tenant | 1
persistence/registry/audience.rs | pub(crate) async fn remove_resource_server_checker_tenant<'e>( | remove_resource_server_checker_tenant | 1
persistence/registry/audience.rs | pub(crate) async fn create_resource_action<'e>( | create_resource_action | 1
persistence/registry/audience.rs | pub(crate) async fn update_resource_action<'e>( | update_resource_action | 1
persistence/registry/tenant.rs | pub(crate) async fn update_tenant<'e>( | update_tenant | 1
persistence/registry/tenant.rs | pub(crate) async fn update_principal<'e>( | update_principal | 1
persistence/registry/test_support.rs | pub async fn create_resource_server_checker<'e>( | create_resource_server_checker | 2
persistence/registry/test_support.rs | pub async fn update_resource_server_checker<'e>( | update_resource_server_checker | 2
persistence/registry/test_support.rs | pub async fn add_resource_server_checker_tenant<'e>( | add_resource_server_checker_tenant | 2
persistence/registry/test_support.rs | pub async fn remove_resource_server_checker_tenant<'e>( | remove_resource_server_checker_tenant | 2
persistence/registry/test_support.rs | pub async fn create_resource_action<'e>( | create_resource_action | 2
persistence/registry/test_support.rs | pub async fn update_resource_action<'e>( | update_resource_action | 2
persistence/registry/test_support.rs | pub async fn update_tenant<'e>( | update_tenant | 2
persistence/registry/test_support.rs | pub async fn update_principal<'e>( | update_principal | 2
persistence/registry/mod.rs | pub(crate) use audience::{ | add_resource_server_checker_tenant | 1
persistence/registry/mod.rs | pub(crate) use audience::{ | create_resource_action | 1
persistence/registry/mod.rs | pub(crate) use audience::{ | create_resource_server_checker | 1
persistence/registry/mod.rs | pub(crate) use audience::{ | remove_resource_server_checker_tenant | 1
persistence/registry/mod.rs | pub(crate) use audience::{ | update_resource_action | 1
persistence/registry/mod.rs | pub(crate) use audience::{ | update_resource_server_checker | 1
persistence/registry/mod.rs | pub(crate) use tenant::{update_principal, update_tenant}; | update_principal | 1
persistence/registry/mod.rs | pub(crate) use tenant::{update_principal, update_tenant}; | update_tenant | 1
admin/mod.rs | pub use workload::{ | add_resource_server_checker_tenant | 1
admin/mod.rs | pub use workload::{ | create_resource_action | 1
admin/mod.rs | pub use workload::{ | create_resource_server_checker | 1
admin/mod.rs | pub use workload::{ | remove_resource_server_checker_tenant | 1
admin/mod.rs | pub use workload::{ | update_principal | 1
admin/mod.rs | pub use workload::{ | update_resource_action | 1
admin/mod.rs | pub use workload::{ | update_resource_server_checker | 1
admin/mod.rs | pub use workload::{ | update_tenant | 1
admin/workload.rs | async fn append_event( | append_audit_event | 1
admin/workload.rs | async fn append_event( | append_event | 1
admin/workload.rs | async fn write_action( | append_event | 1
admin/workload.rs | async fn write_action( | update_resource_action | 1
admin/workload.rs | async fn write_action( | write_action | 1
admin/workload.rs | async fn write_assignment( | append_event | 1
admin/workload.rs | async fn write_assignment( | write_assignment | 1
admin/workload.rs | async fn write_checker( | append_event | 1
admin/workload.rs | async fn write_checker( | update_resource_server_checker | 1
admin/workload.rs | async fn write_checker( | write_checker | 1
admin/workload.rs | async fn write_resource_server( | append_event | 1
admin/workload.rs | async fn write_resource_server( | write_resource_server | 1
admin/workload.rs | pub async fn add_resource_server_checker_tenant( | add_resource_server_checker_tenant | 2
admin/workload.rs | pub async fn add_resource_server_checker_tenant( | append_event | 1
admin/workload.rs | pub async fn create_audience_tenant_assignment( | append_event | 1
admin/workload.rs | pub async fn create_resource_action( | append_event | 1
admin/workload.rs | pub async fn create_resource_action( | create_resource_action | 2
admin/workload.rs | pub async fn create_resource_server( | append_event | 1
admin/workload.rs | pub async fn create_resource_server_checker( | append_event | 1
admin/workload.rs | pub async fn create_resource_server_checker( | create_resource_server_checker | 2
admin/workload.rs | pub async fn create_tenant( | append_event | 1
admin/workload.rs | pub async fn create_workload_principal( | append_event | 1
admin/workload.rs | pub async fn disable_audience_tenant_assignment( | write_assignment | 1
admin/workload.rs | pub async fn disable_principal( | append_event | 1
admin/workload.rs | pub async fn disable_principal( | update_principal | 1
admin/workload.rs | pub async fn disable_resource_action( | write_action | 1
admin/workload.rs | pub async fn disable_resource_server( | write_resource_server | 1
admin/workload.rs | pub async fn disable_resource_server_checker( | write_checker | 1
admin/workload.rs | pub async fn disable_tenant( | append_event | 1
admin/workload.rs | pub async fn disable_tenant( | update_tenant | 1
admin/workload.rs | pub async fn remove_resource_server_checker_tenant( | append_event | 1
admin/workload.rs | pub async fn remove_resource_server_checker_tenant( | remove_resource_server_checker_tenant | 2
admin/workload.rs | pub async fn update_audience_tenant_assignment( | write_assignment | 1
admin/workload.rs | pub async fn update_principal( | append_event | 1
admin/workload.rs | pub async fn update_principal( | update_principal | 2
admin/workload.rs | pub async fn update_resource_action( | update_resource_action | 1
admin/workload.rs | pub async fn update_resource_action( | write_action | 1
admin/workload.rs | pub async fn update_resource_server( | write_resource_server | 1
admin/workload.rs | pub async fn update_resource_server_checker( | update_resource_server_checker | 1
admin/workload.rs | pub async fn update_resource_server_checker( | write_checker | 1
admin/workload.rs | pub async fn update_tenant( | append_event | 1
admin/workload.rs | pub async fn update_tenant( | update_tenant | 2
admin/workload.rs | use crate::persistence::registry::{ | append_audit_event | 1
operation/approval.rs | async fn apply_create( | apply_create | 1
operation/approval.rs | async fn apply_enable( | apply_enable | 1
operation/approval.rs | async fn apply_source_create( | apply_source_create | 1
operation/approval.rs | async fn apply_source_update( | apply_source_update | 1
operation/approval.rs | async fn approve_steps( | apply_create | 1
operation/approval.rs | async fn approve_steps( | apply_enable | 1
operation/approval.rs | async fn approve_steps( | apply_source_create | 1
operation/approval.rs | async fn approve_steps( | apply_source_update | 1
operation/approval.rs | async fn approve_steps( | approve_steps | 1
operation/approval.rs | async fn revoke_steps( | revoke_steps | 1
operation/approval.rs | pub async fn approve_operation( | approve_steps | 1
operation/approval.rs | pub async fn cancel_operation( | revoke_steps | 1
operation/approval.rs | pub async fn reject_operation( | revoke_steps | 1
operation/mod.rs | pub(crate) use toggle::{PendingRequest, encode_error, insert_pending}; | insert_pending | 1
operation/toggle.rs | async fn toggle_steps( | insert_pending | 1
operation/toggle.rs | async fn toggle_steps( | toggle_steps | 1
operation/toggle.rs | pub async fn submit_widening_toggle( | toggle_steps | 1
operation/toggle.rs | pub(crate) async fn insert_pending<E: From<RegistryError>>( | insert_pending | 1
persistence/registry/bootstrap.rs | async fn bootstrap_steps( | bootstrap_steps | 1
persistence/registry/bootstrap.rs | pub async fn bootstrap_instance( | bootstrap_steps | 1
persistence/registry/recovery.rs | async fn issue_steps( | issue_steps | 1
persistence/registry/recovery.rs | async fn restore_steps( | restore_steps | 1
persistence/registry/recovery.rs | pub async fn issue_recovery_challenge( | issue_steps | 1
persistence/registry/recovery.rs | pub async fn restore_operator( | restore_steps | 1
trust/keyset.rs | async fn append_stamped( | append_stamped | 1
trust/keyset.rs | async fn create_steps( | append_stamped | 1
trust/keyset.rs | async fn create_steps( | create_steps | 1
trust/keyset.rs | async fn set_status( | set_status | 1
trust/keyset.rs | async fn set_status( | status_steps | 1
trust/keyset.rs | async fn status_steps( | append_stamped | 1
trust/keyset.rs | async fn status_steps( | status_steps | 1
trust/keyset.rs | async fn submit_create_steps( | append_stamped | 1
trust/keyset.rs | async fn submit_create_steps( | insert_pending | 1
trust/keyset.rs | async fn submit_create_steps( | submit_create_steps | 1
trust/keyset.rs | async fn submit_enable_steps( | append_stamped | 1
trust/keyset.rs | async fn submit_enable_steps( | insert_pending | 1
trust/keyset.rs | async fn submit_enable_steps( | submit_enable_steps | 1
trust/keyset.rs | pub async fn disable_version( | set_status | 1
trust/keyset.rs | pub async fn submit_create_version( | submit_create_steps | 1
trust/keyset.rs | pub async fn submit_enable_version( | submit_enable_steps | 1
trust/keyset.rs | pub(super) async fn create_version( | create_steps | 1
trust/keyset.rs | pub(super) async fn enable_version( | set_status | 1
trust/keyset.rs | use crate::operation::{ | insert_pending | 1
trust/source.rs | async fn append_stamped( | append_stamped | 1
trust/source.rs | async fn create_steps( | append_stamped | 1
trust/source.rs | async fn create_steps( | create_steps | 1
trust/source.rs | async fn submit_create_steps( | append_stamped | 1
trust/source.rs | async fn submit_create_steps( | insert_pending | 1
trust/source.rs | async fn submit_create_steps( | submit_create_steps | 1
trust/source.rs | async fn submit_update_steps( | append_stamped | 1
trust/source.rs | async fn submit_update_steps( | insert_pending | 1
trust/source.rs | async fn submit_update_steps( | submit_update_steps | 1
trust/source.rs | async fn update_steps( | append_stamped | 1
trust/source.rs | async fn update_steps( | update_steps | 1
trust/source.rs | pub async fn submit_create_source( | submit_create_steps | 1
trust/source.rs | pub async fn submit_update_source( | submit_update_steps | 1
trust/source.rs | pub(super) async fn create_source( | create_steps | 1
trust/source.rs | pub(super) async fn update_source( | update_steps | 1
trust/source.rs | use crate::operation::{ | insert_pending | 1
";

/// Text that would let source escape the item keys of [`MENTIONS`], none of
/// which the library uses: a `rustfmt::skip` keeps an indented item that
/// would then count under the item before it; `#[path]`, a `path` in a
/// `cfg_attr` and `include!` read source from a file this check does not
/// key by its own name. Matched with all whitespace removed.
const LAYOUT_ESCAPES: [&str; 4] = ["rustfmt::skip", "#[path", "path=\"", "include!("];

/// The lints whose level, set in the source, would silence the warning
/// that an `impl` nested in a function body draws (`non_local_definitions`,
/// warned by default and in no group but `warnings`). A macro can expand
/// such an `impl` from a name passed to it, where the `impl`'s own line
/// names nothing; that warning, which the plain check refuses, is then what
/// catches it. None of them is named in the library's code (matched as
/// identifiers outside comments and literals), nor, outside comments, in
/// the package's or the workspace's manifest or the workspace's cargo
/// configuration, where a `[lints]` table or `rustflags` (`-A`, or
/// `--cap-lints`, also refused there) would set it for the whole build.
const LINT_ESCAPES: [&str; 2] = ["non_local_definitions", "warnings"];

/// The environment a nested `cargo` or `rustc` must not inherit: this
/// test's own build settings (`cargo test` and `cargo llvm-cov` set
/// `CARGO_*`, `RUSTFLAGS` and the coverage profile file), which would
/// change the nested build or write coverage data from it.
fn is_inherited_build_setting(key: &OsString) -> bool {
    let key = key.to_string_lossy();
    let keep = ["CARGO_HOME", "CARGO_NET_", "CARGO_HTTP_", "CARGO_REGISTR"];
    if key.starts_with("CARGO") || key.starts_with("__CARGO") {
        return !keep.iter().any(|prefix| key.starts_with(prefix));
    }
    matches!(
        key.as_ref(),
        "RUSTFLAGS"
            | "RUSTDOCFLAGS"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "LLVM_PROFILE_FILE"
            | "MAKEFLAGS"
            | "MFLAGS"
    )
}

fn clean_command(program: impl Into<OsString>) -> Command {
    let mut command = Command::new(program.into());
    for (key, _) in env::vars_os() {
        if is_inherited_build_setting(&key) {
            command.env_remove(key);
        }
    }
    command
}

fn text(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text
}

/// The library checked without features: the path of its `.rmeta` and the
/// directories of every artifact of the build (one `deps` directory, or one
/// directory per unit, depending on the cargo version: 1.100 uses the
/// latter).
struct PlainLibrary {
    rmeta: PathBuf,
    deps: BTreeSet<PathBuf>,
}

/// Whether a cargo JSON message is about `skyoauth-service`'s library
/// target (not its binary, whose target name is `skyoauth-service`).
fn is_service_library(message: &Value) -> bool {
    let kinds = message["target"]["kind"].as_array();
    message["target"]["name"] == "skyoauth_service"
        && kinds.is_some_and(|kinds| kinds.iter().any(|kind| kind == "lib"))
}

fn check_plain_library(target_dir: &Path) -> PlainLibrary {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| env!("CARGO").into());
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = clean_command(cargo)
        .arg("check")
        .args(["--locked", "--offline", "--quiet"])
        .arg("--manifest-path")
        .arg(&manifest)
        .args(["--workspace", "--lib", "--bins"])
        .arg("--target-dir")
        .arg(target_dir)
        .args(["--message-format", "json"])
        .output()
        .expect("cargo runs");
    assert!(
        output.status.success(),
        "cargo check of the plain workspace failed:\n{}",
        text(&output)
    );
    let mut found = None;
    let mut deps = BTreeSet::new();
    let mut diagnostics = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] == "compiler-message" && is_service_library(&message) {
            // Cargo replays a fresh unit's cached diagnostics, so a warm run
            // sees them too.
            let rendered = message["message"]["rendered"].as_str().unwrap_or("?");
            diagnostics.push(rendered.to_owned());
            continue;
        }
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let filenames = message["filenames"].as_array().into_iter().flatten();
        for file in filenames.filter_map(Value::as_str) {
            if let Some(dir) = Path::new(file).parent() {
                deps.insert(dir.to_path_buf());
            }
        }
        if !is_service_library(&message) {
            continue;
        }
        // The build this test relies on: no feature, so no `test-support`,
        // whichever workspace member asks for it.
        assert_eq!(
            message["features"],
            Value::Array(Vec::new()),
            "the plain library was built with features"
        );
        let rmeta = message["filenames"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .find(|name| name.ends_with(".rmeta"))
            .expect("the library's metadata");
        found = Some(PathBuf::from(rmeta));
    }
    assert!(
        diagnostics.is_empty(),
        "the library without `test-support` emitted diagnostics (an unfulfilled \
         `expect(dead_code)` means an ungated writer is public or called):\n{}",
        diagnostics.join("\n")
    );
    let rmeta = found.expect("cargo reported the library's artifact");
    PlainLibrary { rmeta, deps }
}

/// Compiles `source` as a library crate that depends on the plain
/// library, metadata only.
fn compile_probe(library: &PlainLibrary, dir: &Path, name: &str, source: &str) -> Output {
    let file = dir.join(format!("{name}.rs"));
    fs::write(&file, source).unwrap();
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let mut command = clean_command(rustc);
    command
        .args(["--edition", "2024", "--crate-type", "lib"])
        .args([
            "--emit",
            "metadata",
            "--color",
            "never",
            "--crate-name",
            name,
        ]);
    for dir in &library.deps {
        command
            .arg("-L")
            .arg(format!("dependency={}", dir.display()));
    }
    command
        .arg("--extern")
        .arg(format!("skyoauth_service={}", library.rmeta.display()))
        .arg("--out-dir")
        .arg(dir)
        .arg(&file)
        .output()
        .expect("rustc runs")
}

/// Asserts that `skyoauth_service::{path}` does not resolve in a probe
/// crate: private (E0603) or missing (E0432), and nothing else, so that a
/// probe that fails for another reason does not count.
fn assert_unreachable(library: &PlainLibrary, probes: &Path, name: &str, path: &str) {
    let output_text = probe_unreachable(library, probes, name, path);
    assert!(
        output_text.contains("error[E0603]") || output_text.contains("error[E0432]"),
        "`skyoauth_service::{path}` failed to compile, but not as a path that \
         does not resolve:\n{output_text}"
    );
}

/// Asserts that `skyoauth_service::{path}` exists and is private (E0603)
/// in a probe crate: for the path of a writer's defining module, so that a
/// renamed module or a stale table, which leaves the path missing (E0432),
/// fails this test instead of passing it.
fn assert_private(library: &PlainLibrary, probes: &Path, name: &str, path: &str) {
    let output_text = probe_unreachable(library, probes, name, path);
    assert!(
        output_text.contains("error[E0603]"),
        "`skyoauth_service::{path}` failed to compile, but not as a private path \
         (E0603), so the probe names nothing:\n{output_text}"
    );
}

/// Compiles a probe that re-exports `skyoauth_service::{path}`, asserts
/// that it fails, and returns its output.
fn probe_unreachable(library: &PlainLibrary, probes: &Path, name: &str, path: &str) -> String {
    let source = format!("pub use skyoauth_service::{path};\n");
    let output = compile_probe(library, probes, name, &source);
    assert!(
        !output.status.success(),
        "`skyoauth_service::{path}` is reachable without `test-support`"
    );
    text(&output)
}

/// The guard that makes a caller visible to the check above: each writer
/// is `pub(super)` and carries, right before it, the `expect(dead_code)`
/// that a build without the feature turns into a warning once anything
/// calls the writer. Without this, removing the attribute and adding a
/// public forwarder of another name in the same change would pass. The
/// four ungated trust writers (PR 7) and the registry writers of
/// [`REGISTRY_DEAD`], by their file under `src` and the start of their
/// item.
#[test]
fn each_ungated_writer_keeps_its_visibility_and_dead_code_guard() {
    const GUARD: &str = "#[cfg_attr(
    not(feature = \"test-support\"),
    expect(dead_code, reason = \"ungated: tests only, through test_support\")
)]
";
    let trust =
        UNGATED.map(|(module, writer)| (format!("trust/{module}.rs"), format!("{writer}(")));
    let registry = REGISTRY_DEAD.map(|(file, writer)| (file.to_owned(), format!("{writer}<'e>(")));
    for (file, writer) in trust.into_iter().chain(registry) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
        let source = fs::read_to_string(&path).unwrap();
        let item = format!("async fn {writer}");
        assert_eq!(
            source.matches(&item).count(),
            1,
            "`{item}` is defined once in {}",
            path.display()
        );
        let guarded = format!("{GUARD}pub(super) {item}");
        assert!(
            source.contains(&guarded),
            "`{item}` must be `pub(super)` right after its `expect(dead_code)` guard"
        );
    }
}

/// How many times `line` names `word` as a whole identifier.
fn identifier_count(line: &str, word: &str) -> usize {
    let is_identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(word)
        .filter(|(start, _)| {
            let before = line[..*start].chars().next_back();
            let after = line[start + word.len()..].chars().next();
            !before.is_some_and(is_identifier) && !after.is_some_and(is_identifier)
        })
        .count()
}

/// `source` with every comment and every string, byte string, raw string
/// and character literal replaced by spaces, newlines kept, so that a name
/// in a comment or a literal is not a mention and lines stay in place.
/// Block comments nest, as in Rust; a `'` that does not open a character
/// literal is a lifetime or a label and is kept.
fn strip_comments_and_literals(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let blank = |out: &mut String, run: &[char]| {
        for c in run {
            out.push(if *c == '\n' { '\n' } else { ' ' });
        }
    };
    let is_identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut i = 0;
    while i < chars.len() {
        let rest = &chars[i..];
        let end = if rest.starts_with(&['/', '/']) {
            rest.iter().position(|c| *c == '\n').unwrap_or(rest.len())
        } else if rest.starts_with(&['/', '*']) {
            let (mut depth, mut j) = (0_usize, 0);
            while j < rest.len() {
                if rest[j..].starts_with(&['/', '*']) {
                    depth += 1;
                    j += 2;
                } else if rest[j..].starts_with(&['*', '/']) {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            j
        } else if rest[0] == 'r'
            && !(i > 0 && is_identifier(chars[i - 1]) && !matches!(chars[i - 1], 'b' | 'c'))
            && {
                let hashes = rest[1..].iter().take_while(|c| **c == '#').count();
                rest.get(1 + hashes) == Some(&'"')
            }
        {
            let hashes = rest[1..].iter().take_while(|c| **c == '#').count();
            let close: Vec<char> = std::iter::once('"')
                .chain(std::iter::repeat_n('#', hashes))
                .collect();
            let body = 2 + hashes;
            body + rest[body..]
                .windows(close.len())
                .position(|window| window == close.as_slice())
                .map_or(rest.len() - body, |at| at + close.len())
        } else if rest[0] == '"' {
            let mut j = 1;
            while j < rest.len() && rest[j] != '"' {
                j += if rest[j] == '\\' { 2 } else { 1 };
            }
            (j + 1).min(rest.len())
        } else if rest[0] == '\'' && rest.get(1) == Some(&'\\') {
            2 + rest[2..]
                .iter()
                .skip(1)
                .position(|c| *c == '\'')
                .map_or(rest.len() - 2, |at| at + 2)
        } else if rest[0] == '\'' && rest.get(2) == Some(&'\'') {
            3
        } else {
            0
        };
        if end == 0 {
            out.push(chars[i]);
            i += 1;
        } else {
            blank(&mut out, &rest[..end]);
            i += end;
        }
    }
    out
}

/// Whether `line` (comments and literals stripped) starts an `impl` block,
/// at any depth: an `impl` nested in a function body still adds methods to
/// its type, public ones included, so it is keyed as an item of its own.
fn is_nested_impl(line: &str) -> bool {
    let line = line.trim_start();
    ["impl ", "impl<", "unsafe impl "]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

/// The stripping the source check counts on: code stays, comments and
/// literals go, a lifetime is not a character literal, and lines stay in
/// place.
#[test]
fn stripping_keeps_code_and_blanks_comments_and_literals() {
    let source = "f(\"a // b\", r#\"c \"x\" d\"#, '\\'', '\"', b'x');\n\
                  g::<'e>(); // h\n/* i /* j */ k */ l\n\"m\n n\" o\n";
    let stripped = strip_comments_and_literals(source);
    let words: Vec<&str> = stripped
        .split(|c: char| !c.is_ascii_alphanumeric())
        .collect();
    let words: Vec<&str> = words.into_iter().filter(|word| !word.is_empty()).collect();
    assert_eq!(words, ["f", "b", "g", "e", "l", "o"]);
    assert_eq!(stripped.lines().count(), source.lines().count());
}

/// Whether the source check counts `name` in `file` (under `src/`,
/// `/`-separated): everywhere, but a name of [`SCOPED`] only in the files
/// of its module.
fn counted_in(name: &str, file: &str) -> bool {
    SCOPED
        .iter()
        .filter(|(scoped, _)| *scoped == name)
        .all(|(_, module)| {
            file == format!("{module}.rs") || file.starts_with(&format!("{module}/"))
        })
}

/// A mention's key: the file, the first line of the item that holds it, and
/// the name.
type MentionKey = (String, String, String);

/// Adds to `found` the mentions of `names` in `source`, the file `relative`
/// (under `src/`), outside comments and literals, keyed by the item that
/// holds each (see
/// [`each_writer_and_step_is_crate_private_and_named_only_where_expected`]);
/// a name of [`SCOPED`] only in its module's files.
fn count_mentions(
    relative: &str,
    source: &str,
    names: &BTreeSet<&str>,
    found: &mut BTreeMap<MentionKey, usize>,
) {
    let stripped = strip_comments_and_literals(source);
    let names: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| counted_in(name, relative))
        .collect();
    let mut item = String::from("<the file's start>");
    for (line, stripped_line) in source.lines().zip(stripped.lines()) {
        let continues = ["/", "#", "}", ")", "]", "{", "where"];
        let starts_item = stripped_line
            .chars()
            .next()
            .is_some_and(|c| !c.is_whitespace())
            && !continues
                .iter()
                .any(|prefix| stripped_line.starts_with(prefix));
        let starts_item = starts_item || is_nested_impl(stripped_line);
        if starts_item {
            item = line.to_owned();
        }
        for name in &names {
            let count = identifier_count(stripped_line, name);
            if count > 0 {
                *found
                    .entry((relative.to_owned(), item.clone(), (*name).to_owned()))
                    .or_insert(0) += count;
            }
        }
    }
}

#[test]
fn a_scoped_name_is_counted_only_in_its_module() {
    let names = BTreeSet::from(["set_status", "append_stamped"]);
    let lamp = "struct Lamp;\n\nimpl Lamp {\n    pub fn set_status(&self) {}\n}\n";
    let mut found = BTreeMap::new();
    // An unrelated method of the same name, in another module or a module
    // whose name only starts with `keyset`, is not a mention.
    count_mentions("operation/lamp.rs", lamp, &names, &mut found);
    count_mentions("trust/keyset_lamp.rs", lamp, &names, &mut found);
    assert!(found.is_empty(), "{found:?}");
    // In the module's file or a submodule's, it is.
    count_mentions("trust/keyset.rs", lamp, &names, &mut found);
    count_mentions("trust/keyset/lamp.rs", lamp, &names, &mut found);
    // A name that is not scoped is counted everywhere.
    count_mentions(
        "operation/lamp.rs",
        "fn f() {\n    append_stamped();\n}\n",
        &names,
        &mut found,
    );
    let key =
        |file: &str, item: &str, name: &str| (file.to_owned(), item.to_owned(), name.to_owned());
    let expected = BTreeMap::from([
        (key("operation/lamp.rs", "fn f() {", "append_stamped"), 1),
        (key("trust/keyset.rs", "impl Lamp {", "set_status"), 1),
        (key("trust/keyset/lamp.rs", "impl Lamp {", "set_status"), 1),
    ]);
    assert_eq!(found, expected);
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

/// The stand-in for `expect(dead_code)` where the writers and steps are
/// called in every build: outside comments and string and character
/// literals, the library names each bare registry writer, each writer of
/// [`REGISTRY_PRIVATE`], each step of [`STEPS`] and each caller of
/// [`CALLERS`] exactly as [`MENTIONS`] lists. A mention is keyed by the
/// first line of the item that holds it: the top-level item (a line that
/// starts in column 0 and is not an attribute or the rest of an item), or
/// the `impl` block, at any depth, that follows it, so a definition or a
/// caller made `pub` changes the key, a forwarder or a caller of any other
/// name, a public method of an `impl` nested in a function body included,
/// adds one or a mention to a key, and a name moved into a comment or a
/// literal to keep a count is not counted. `rustfmt` puts every top-level
/// item in column 0, so the check also refuses the [`LAYOUT_ESCAPES`] that
/// could keep one out of it and the [`LINT_ESCAPES`] that could silence a
/// nested `impl` a macro expands, and it refuses `<name> as` (whitespace
/// removed, outside comments and literals), an import or a cast under
/// another name, which no count can follow.
#[test]
fn each_writer_and_step_is_crate_private_and_named_only_where_expected() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    // A set: `append_stamped`, `create_steps` and `submit_create_steps` each
    // name a function of `trust::keyset` and one of `trust::source`, and a
    // name listed twice would be counted twice.
    let names: BTreeSet<&str> = REGISTRY_UNGATED
        .into_iter()
        .chain(REGISTRY_PRIVATE.iter().map(|(_, writer)| *writer))
        .chain(STEPS.iter().map(|(_, step)| *step))
        .chain(CALLERS.iter().map(|(_, _, caller)| *caller))
        .collect();
    let mut escapes = Vec::new();
    let mut aliases = Vec::new();
    let mut found = BTreeMap::new();
    for file in files {
        let relative = file.strip_prefix(&src).unwrap();
        let relative = relative.to_string_lossy().replace('\\', "/");
        let source = fs::read_to_string(&file).unwrap();
        let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        for escape in LAYOUT_ESCAPES {
            if compact.contains(escape) {
                escapes.push(format!("{relative}: `{escape}`"));
            }
        }
        let stripped = strip_comments_and_literals(&source);
        for lint in LINT_ESCAPES {
            if identifier_count(&stripped, lint) > 0 {
                escapes.push(format!("{relative}: `{lint}`"));
            }
        }
        let code: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
        for name in names.iter().filter(|name| counted_in(name, &relative)) {
            if code.contains(&format!("{name}as")) {
                aliases.push(format!("{relative}: `{name} as`"));
            }
        }
        count_mentions(&relative, &source, &names, &mut found);
    }
    // The same lint levels set for the whole build: in a `[lints]` table of
    // the package or the workspace, or as `rustflags` (`-A`,
    // `--cap-lints`) in the workspace's cargo configuration.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for settings in ["Cargo.toml", "../Cargo.toml", "../.cargo/config.toml"] {
        let Ok(text) = fs::read_to_string(manifest_dir.join(settings)) else {
            continue;
        };
        let lines = text
            .lines()
            .map(|line| line.split('#').next().unwrap_or(""));
        let normalized = lines.collect::<Vec<_>>().join("\n").replace('-', "_");
        for lint in LINT_ESCAPES.iter().chain(&["cap_lints"]) {
            if normalized.contains(lint) {
                escapes.push(format!("service/{settings}: `{lint}`"));
            }
        }
    }
    assert!(
        escapes.is_empty(),
        "the library uses text that this source check cannot see through:\n{}",
        escapes.join("\n")
    );
    assert!(
        aliases.is_empty(),
        "the library imports or casts a crate-private registry writer, a step or a caller under \
         another name, which this source check cannot follow:\n{}",
        aliases.join("\n")
    );
    let mut expected = BTreeMap::new();
    for line in MENTIONS.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<&str> = line.split(" | ").collect();
        let [file, item, name, count] = fields[..] else {
            panic!("a malformed line of MENTIONS: {line}");
        };
        let key = (file.to_owned(), item.to_owned(), name.to_owned());
        let previous = expected.insert(key, count.parse::<usize>().unwrap());
        assert!(previous.is_none(), "a duplicate line of MENTIONS: {line}");
    }
    let show = |(file, item, name): &(String, String, String), count: usize| {
        format!("{file} | {item} | {name} | {count}")
    };
    let unexpected: Vec<String> = found
        .iter()
        .filter(|(key, count)| expected.get(*key) != Some(*count))
        .map(|(key, count)| show(key, *count))
        .collect();
    let missing: Vec<String> = expected
        .iter()
        .filter(|(key, count)| found.get(*key) != Some(*count))
        .map(|(key, count)| show(key, *count))
        .collect();
    assert!(
        unexpected.is_empty() && missing.is_empty(),
        "a crate-private registry writer, a step or a caller is named where it should not be, under \
         another visibility, or a different number of times (file | item | name | \
         count). Update MENTIONS only if this is a deliberate narrowing or rename; \
         a new caller or a wider visibility is what this test exists to refuse.\n\
         In the source, not in MENTIONS:\n{}\nIn MENTIONS, not in the source:\n{}",
        unexpected.join("\n"),
        missing.join("\n")
    );
}

#[test]
fn a_build_without_test_support_exposes_no_ungated_write() {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ungated-writes-private");
    let library = check_plain_library(&base.join("target"));
    let probes = base.join("probes");
    fs::create_dir_all(&probes).unwrap();

    // The control: the public writes and registry items resolve, so the
    // probes below fail for the path they name, not for the setup, and the
    // registry writers that deliberately stay public are still public.
    let trust_uses = PUBLIC.iter().enumerate().map(|(index, path)| {
        format!("pub use skyoauth_service::trust::{path} as public_{index};\n")
    });
    let registry_items = REGISTRY_PUBLIC
        .iter()
        .chain(&REGISTRY_KEPT_PUBLIC)
        .chain(&RECOVERY_PUBLIC);
    let registry_uses = registry_items.enumerate().map(|(index, item)| {
        format!("pub use skyoauth_service::persistence::registry::{item} as registry_{index};\n")
    });
    let ids_uses = IDS_PUBLIC
        .iter()
        .enumerate()
        .map(|(index, item)| format!("pub use skyoauth_service::ids::{item} as ids_{index};\n"));
    let uses: String = trust_uses.chain(registry_uses).chain(ids_uses).collect();
    let control = compile_probe(&library, &probes, "control", &uses);
    assert!(
        control.status.success(),
        "the control probe must compile:\n{}",
        text(&control)
    );

    for (module, writer) in UNGATED {
        // The defining module, the re-export of `trust` and the test-support
        // module.
        let paths = [
            format!("trust::{module}::{writer}"),
            format!("trust::{writer}"),
            format!("trust::test_support::{writer}"),
        ];
        for (index, path) in paths.iter().enumerate() {
            let name = format!("probe_{writer}_{index}");
            assert_unreachable(&library, &probes, &name, path);
        }
    }

    for writer in REGISTRY_UNGATED {
        // The re-export of `registry`, the defining module (private), the
        // registry's test-support module, and `trust`'s.
        let paths = [
            format!("persistence::registry::{writer}"),
            format!("persistence::registry::trust::{writer}"),
            format!("persistence::registry::test_support::{writer}"),
            format!("trust::test_support::{writer}"),
        ];
        for (index, path) in paths.iter().enumerate() {
            let name = format!("probe_registry_{writer}_{index}");
            assert_unreachable(&library, &probes, &name, path);
        }
    }

    for (module, writer) in REGISTRY_PRIVATE {
        // The re-export of `registry` (crate-private or private), the
        // defining module (private, so E0603 only) and the registry's
        // test-support module.
        let paths = [
            format!("persistence::registry::{writer}"),
            format!("persistence::registry::{module}::{writer}"),
            format!("persistence::registry::test_support::{writer}"),
        ];
        for (index, path) in paths.iter().enumerate() {
            let name = format!("probe_private_{writer}_{index}");
            if index == 1 {
                assert_private(&library, &probes, &name, path);
            } else {
                assert_unreachable(&library, &probes, &name, path);
            }
        }
    }

    for (module, step) in STEPS {
        let paths = [format!("trust::{module}::{step}"), format!("trust::{step}")];
        for (index, path) in paths.iter().enumerate() {
            let name = format!("probe_step_{step}_{index}");
            assert_unreachable(&library, &probes, &name, path);
        }
    }

    for (module, parent, caller) in CALLERS {
        // The defining module and the parent's re-export.
        let paths = [format!("{module}::{caller}"), format!("{parent}::{caller}")];
        for (index, path) in paths.iter().enumerate() {
            let name = format!(
                "probe_caller_{}_{caller}_{index}",
                module.replace("::", "_")
            );
            assert_unreachable(&library, &probes, &name, path);
        }
    }

    for item in REGISTRY_REMOVED {
        let name = format!("probe_removed_{item}");
        assert_unreachable(
            &library,
            &probes,
            &name,
            &format!("persistence::registry::{item}"),
        );
    }

    for (index, item) in IDS_TEST_ONLY.iter().enumerate() {
        let name = format!("probe_ids_{index}");
        assert_unreachable(&library, &probes, &name, &format!("ids::{item}"));
    }
}
