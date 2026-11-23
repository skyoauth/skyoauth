//! A normal build of the workspace, without the `test-support` feature,
//! neither exposes nor calls the ungated trust writes, and exposes none of
//! the bare registry trust writers, operator writers, audit append or
//! operation-row writers (second-approver proposal,
//! `docs/proposals/second-approver-gated-writes.md`, PRs 7, 9 and 10).
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
//! `restore_operator` call them; `update_admin_role_binding` is
//! `pub(super)` too and has no caller in the crate, so it carries PR 7's
//! `expect(dead_code)`; `append_audit_event` and the operation-row writers
//! `insert_administrative_operation`, `consume_administrative_operation`
//! and `revoke_administrative_operation` are `pub(crate)`, called by
//! `crate::operation` and `crate::trust` as well. Only the `#[doc(hidden)]`
//! modules `trust::test_support` and `persistence::registry::test_support`,
//! compiled with the feature, expose them to tests. Every test target of
//! this package is built with the feature (the package's dev-dependency on
//! itself), and so is every test target of `skyoauth-scenarios` (its
//! dev-dependency on this package), so a test cannot simply name the
//! writers and expect a compile error. This test therefore checks the
//! library without the feature, as a dependent crate would see it: it runs
//! `cargo check` on the workspace's libraries and binaries (a build that
//! turns no dev-dependency feature on, and that a workspace member enabling
//! the feature through a normal or build dependency would change), in a
//! target directory of its own, and then:
//!
//! - asserts that `skyoauth-service`'s library was built with no feature;
//! - asserts that the library emitted no warning. Without the feature each
//!   `trust` writer and `update_admin_role_binding` carry
//!   `expect(dead_code)`, so a caller in their visibility, a public
//!   forwarder included, makes the expectation unfulfilled, which is a
//!   warning (a caller outside it is a privacy error in every build);
//! - compiles small probe crates against the library's metadata with
//!   `rustc`. A probe that names an ungated writer, a bare registry writer,
//!   a registry writer that PR 10 made crate-private or one of the
//!   crate-private steps below at any of its paths must fail as a private
//!   (E0603) or unresolved (E0432) path, and a probe that names the public
//!   writes and registry items, the registry writers that deliberately stay
//!   public included, must compile, so a probe that fails for an unrelated
//!   reason (a toolchain mismatch, a missing crate) or a narrowing of what
//!   must stay public fails this test instead of passing it.
//!
//! The registry writers but `update_admin_role_binding` are called in every
//! build, and so are the six crate-private steps of `trust` that apply a
//! write without authorizing, gating or auditing it themselves
//! (`insert_create_version`, `apply_create_version`,
//! `apply_enable_version`, `apply_status`, `apply_create_source`,
//! `apply_locked_update`; PR 7's `expect(dead_code)` covers only the four
//! `pub(super)` writers, not these), so no dead-code guard fits them. A
//! source check stands in for it: outside comments, the library names each
//! writer and each step only at the places a table lists (the definition,
//! the crate-private re-export, the test-support wrapper, the `use`s, and
//! the callers in `trust::keyset`, `trust::source`, `crate::operation` and
//! the registry's bootstrap and recovery), each keyed by the item that
//! holds it with that item's visibility and counted, so a forwarder of
//! another name, a new caller and a widened definition or caller each fail
//! it, and so does source that could hide an item from those keys
//! (`rustfmt::skip`, `#[path]`, `include!`; inferred). The probes also
//! require each step to be unreachable from outside the crate.
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

/// The registry writers that PR 10 made crate-private, by the private
/// module of `persistence::registry` that defines them: the operator
/// writers (`pub(super)`: the three creates are called only by the
/// registry's `bootstrap` and `recovery`, the update by nothing in the
/// crate), the audit append and the operation-row writers (`pub(crate)`:
/// `crate::operation` and `crate::trust` call them too).
const REGISTRY_PRIVATE: [(&str, &str); 8] = [
    ("operator", "create_admin_identity"),
    ("operator", "create_admin_credential"),
    ("operator", "create_admin_role_binding"),
    ("operator", "update_admin_role_binding"),
    ("events", "append_audit_event"),
    ("operation", "insert_administrative_operation"),
    ("operation", "consume_administrative_operation"),
    ("operation", "revoke_administrative_operation"),
];

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

/// The registry items of the same tables that stay public: the readers,
/// and the row and input types the test-support wrappers take and return.
const REGISTRY_PUBLIC: [&str; 25] = [
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
];

/// The registry writers that deliberately stay public (the proposal's
/// "Still open after PRs 7, 9 and 10"): break-glass restoration and bootstrap,
/// whose verifier is the open decision, and the two operator writers that
/// only narrow. A change that made one of them crate-private would be a
/// decision this test does not take; the control probe fails on it.
const REGISTRY_KEPT_PUBLIC: [&str; 5] = [
    "restore_operator",
    "issue_recovery_challenge",
    "bootstrap_instance",
    "disable_admin_identity",
    "revoke_admin_credential",
];

/// Where the library's source, comment lines aside, names a bare registry
/// writer, a writer of [`REGISTRY_PRIVATE`] or a step of [`STEPS`], one
/// entry per line: the file under `src`, the first line of the top-level
/// item that holds the mention, the name, and how many times, separated by
/// ` | `. The trust writers are defined and re-exported `pub(crate)`, each
/// wrapper is compiled only with `test-support`, and the callers are the
/// trust write path's own steps and `crate::operation`'s approval, none of
/// them public. Of PR 10's writers, the operator writers are defined
/// `pub(super)` and the three creates re-exported privately, to
/// `bootstrap_steps` and `restore_steps` (and the `seed` of a database
/// unit test in `trust::keyset`, through `test_support`);
/// `update_admin_role_binding` is named only by its definition and its
/// wrapper; the audit append and the operation-row writers are defined and
/// re-exported `pub(crate)`, and called by the audited steps of the
/// registry (`bootstrap_steps`, `issue_steps`, `restore_steps`), of
/// `crate::trust` (each module's private `append_stamped`) and of
/// `crate::operation` (the approval's `approve_steps` and `revoke_steps`,
/// the toggle's `toggle_steps`, and `insert_pending`, which the gated
/// `submit_*` writes call).
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
trust/keyset.rs | mod tests { | create_admin_identity | 1
trust/keyset.rs | mod tests { | create_admin_credential | 1
trust/keyset.rs | mod tests { | create_admin_role_binding | 1
trust/source.rs | use crate::persistence::registry::{ | append_audit_event | 1
trust/source.rs | async fn append_stamped( | append_audit_event | 1
";

/// Text that would let source escape the item keys of [`MENTIONS`], none of
/// which the library uses: a `rustfmt::skip` keeps an indented item that
/// would then count under the item before it, and `#[path]`, a `path` in a
/// `cfg_attr` and `include!` read source from a file this check does not
/// key by its own name. Matched with all whitespace removed.
const LAYOUT_ESCAPES: [&str; 4] = ["rustfmt::skip", "#[path", "path=\"", "include!("];

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
    let source = format!("pub use skyoauth_service::{path};\n");
    let output = compile_probe(library, probes, name, &source);
    let output_text = text(&output);
    assert!(
        !output.status.success(),
        "`skyoauth_service::{path}` is reachable without `test-support`"
    );
    assert!(
        output_text.contains("error[E0603]") || output_text.contains("error[E0432]"),
        "`skyoauth_service::{path}` failed to compile, but not as a path that \
         does not resolve:\n{output_text}"
    );
}

/// The guard that makes a caller visible to the check above: each writer
/// is `pub(super)` and carries, right before it, the `expect(dead_code)`
/// that a build without the feature turns into a warning once anything
/// calls the writer. Without this, removing the attribute and adding a
/// public forwarder of another name in the same change would pass. The
/// four ungated trust writers (PR 7) and `update_admin_role_binding`
/// (PR 10), by their file under `src` and the start of their item.
#[test]
fn each_ungated_writer_keeps_its_visibility_and_dead_code_guard() {
    const GUARD: &str = "#[cfg_attr(
    not(feature = \"test-support\"),
    expect(dead_code, reason = \"ungated: tests only, through test_support\")
)]
";
    let trust =
        UNGATED.map(|(module, writer)| (format!("trust/{module}.rs"), format!("{writer}(")));
    let operator = (
        "persistence/registry/operator.rs".to_owned(),
        "update_admin_role_binding<'e>(".to_owned(),
    );
    for (file, writer) in trust.into_iter().chain([operator]) {
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
/// called in every build: outside comment lines, the library names each
/// bare registry writer and each step of [`STEPS`] exactly as
/// [`MENTIONS`] lists. A mention is keyed by the first line of the
/// top-level item that holds it (a line that starts in column 0 and is not
/// a comment, an attribute or the rest of an item), so a definition or a
/// caller made `pub` changes the key, and a forwarder or a caller of any
/// other name adds one, or a mention to a key. `rustfmt` puts every
/// top-level item in column 0, so the check also refuses the
/// [`LAYOUT_ESCAPES`] that could keep one out of it.
#[test]
fn each_writer_and_step_is_crate_private_and_named_only_where_expected() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let names: Vec<&str> = REGISTRY_UNGATED
        .into_iter()
        .chain(REGISTRY_PRIVATE.iter().map(|(_, writer)| *writer))
        .chain(STEPS.iter().map(|(_, step)| *step))
        .collect();
    let mut escapes = Vec::new();
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
        let mut item = String::from("<the file's start>");
        for line in source.lines() {
            let continues = ["/", "#", "}", ")", "]", "{", "where"];
            let starts_item = line.chars().next().is_some_and(|c| !c.is_whitespace())
                && !continues.iter().any(|prefix| line.starts_with(prefix));
            if starts_item {
                item = line.to_owned();
            }
            if line.trim_start().starts_with("//") {
                continue;
            }
            for name in &names {
                let count = identifier_count(line, name);
                if count > 0 {
                    *found
                        .entry((relative.clone(), item.clone(), (*name).to_owned()))
                        .or_insert(0) += count;
                }
            }
        }
    }
    assert!(
        escapes.is_empty(),
        "the library uses text that this source check cannot see through:\n{}",
        escapes.join("\n")
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
        "a crate-private registry writer or a step is named where it should not be, under \
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
    let registry_items = REGISTRY_PUBLIC.iter().chain(&REGISTRY_KEPT_PUBLIC);
    let registry_uses = registry_items.enumerate().map(|(index, item)| {
        format!("pub use skyoauth_service::persistence::registry::{item} as registry_{index};\n")
    });
    let uses: String = trust_uses.chain(registry_uses).collect();
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
        // defining module (private) and the registry's test-support module.
        let paths = [
            format!("persistence::registry::{writer}"),
            format!("persistence::registry::{module}::{writer}"),
            format!("persistence::registry::test_support::{writer}"),
        ];
        for (index, path) in paths.iter().enumerate() {
            let name = format!("probe_private_{writer}_{index}");
            assert_unreachable(&library, &probes, &name, path);
        }
    }

    for (module, step) in STEPS {
        let paths = [format!("trust::{module}::{step}"), format!("trust::{step}")];
        for (index, path) in paths.iter().enumerate() {
            let name = format!("probe_step_{step}_{index}");
            assert_unreachable(&library, &probes, &name, path);
        }
    }
}
