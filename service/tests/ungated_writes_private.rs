//! A normal build of the workspace, without the `test-support` feature,
//! neither exposes nor calls the ungated trust writes (second-approver
//! proposal, `docs/proposals/second-approver-gated-writes.md`, PR 7).
//!
//! `create_version`, `enable_version`, `create_source` and `update_source`
//! apply a write without the second-approver gate, so they are visible
//! only within `trust` (`pub(super)`), and only `trust::test_support`,
//! compiled with the feature, exposes them to this package's tests. Every
//! test target of this package is built with the feature (the package's
//! dev-dependency on itself), so a test cannot simply name the writers and
//! expect a compile error. This test therefore checks the library without
//! the feature, as a dependent crate would see it: it runs `cargo check`
//! on the workspace's libraries and binaries (a build that turns no
//! dev-dependency feature on, and that a workspace member enabling the
//! feature through a normal or build dependency would change), in a target
//! directory of its own, and then:
//!
//! - asserts that `skyoauth-service`'s library was built with no feature;
//! - asserts that the library emitted no warning. Without the feature each
//!   writer carries `expect(dead_code)`, so a caller in `trust`, a public
//!   forwarder included, makes the expectation unfulfilled, which is a
//!   warning (a caller outside `trust` is a privacy error in every build);
//! - compiles small probe crates against the library's metadata with
//!   `rustc`. A probe that names an ungated writer at any of its paths must
//!   fail as a private (E0603) or unresolved (E0432) path, and a probe that
//!   names the public writes must compile, so a probe that fails for an
//!   unrelated reason (a toolchain mismatch, a missing crate) fails this
//!   test instead of passing it.
//!
//! It needs no database, so it is not `#[ignore]`d (inferred), and runs
//! offline from the crates the outer build has already fetched. The first
//! run checks every dependency (about 40 s on four cores); later runs
//! reuse the target directory under `CARGO_TARGET_TMPDIR`.

use std::{
    collections::BTreeSet,
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

/// The guard that makes a caller visible to the check above: each writer
/// is `pub(super)` and carries, right before it, the `expect(dead_code)`
/// that a build without the feature turns into a warning once anything
/// calls the writer. Without this, removing the attribute and adding a
/// public forwarder of another name in the same change would pass.
#[test]
fn each_ungated_writer_keeps_its_visibility_and_dead_code_guard() {
    const GUARD: &str = "#[cfg_attr(
    not(feature = \"test-support\"),
    expect(dead_code, reason = \"ungated: tests only, through test_support\")
)]
";
    for (module, writer) in UNGATED {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/trust")
            .join(format!("{module}.rs"));
        let source = fs::read_to_string(&path).unwrap();
        let item = format!("async fn {writer}(");
        assert_eq!(
            source.matches(&item).count(),
            1,
            "`{writer}` is defined once in {}",
            path.display()
        );
        let guarded = format!("{GUARD}pub(super) {item}");
        assert!(
            source.contains(&guarded),
            "`{writer}` must be `pub(super)` right after its `expect(dead_code)` guard"
        );
    }
}

#[test]
fn a_build_without_test_support_exposes_no_ungated_write() {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ungated-writes-private");
    let library = check_plain_library(&base.join("target"));
    let probes = base.join("probes");
    fs::create_dir_all(&probes).unwrap();

    // The control: the public writes resolve, so the probes below fail for
    // the path they name, not for the setup.
    let uses: String = PUBLIC
        .iter()
        .enumerate()
        .map(|(index, path)| {
            format!("pub use skyoauth_service::trust::{path} as public_{index};\n")
        })
        .collect();
    let control = compile_probe(&library, &probes, "control", &uses);
    assert!(
        control.status.success(),
        "the control probe must compile:\n{}",
        text(&control)
    );

    for (module, writer) in UNGATED {
        // The defining module, the re-export of `trust` and the test-support
        // module. Each must fail to resolve: private (E0603) or missing
        // (E0432), and nothing else, so that a probe that fails for another
        // reason does not count.
        let paths = [
            format!("trust::{module}::{writer}"),
            format!("trust::{writer}"),
            format!("trust::test_support::{writer}"),
        ];
        for (index, path) in paths.iter().enumerate() {
            let name = format!("probe_{writer}_{index}");
            let source = format!("pub use skyoauth_service::{path};\n");
            let output = compile_probe(&library, &probes, &name, &source);
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
    }
}
