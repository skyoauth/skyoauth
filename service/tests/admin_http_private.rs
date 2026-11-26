//! The admin router is served nowhere, and nothing but the rustls acceptor
//! (a later slice) and, under `test-support`, the tests' fake acceptor can
//! make the peer identity it trusts (`crate::admin_http`, D5).
//!
//! The source checks read the library's code, comments and string and
//! character literals blanked:
//!
//! - `admin_router` is named only under `src/admin_http/`, in the service
//!   and in the scenario crate's library; `lib.rs` names `admin_http` only
//!   in its `pub mod`, `main.rs` names neither, and `app()` merges, nests
//!   and falls back to nothing (the plaintext `app()` answering 404 on every
//!   `/admin` path is the unit test
//!   `the_plaintext_app_answers_404_for_every_admin_path`);
//! - `AdminPeer` is built in `peer.rs` only, in exactly two places (the
//!   acceptor's `from_peer_spki` and the `test-support` `with_admin_peer`);
//!   its one derive is `Clone`, its `impl`s are the three of `peer.rs` (no
//!   `Default`, `From`, `FromStr` or `Deserialize`); `from_peer_spki` is
//!   `pub(in crate::admin_http)` and carries the `expect(dead_code)` that a
//!   build without `cfg(test)` turns into a warning once anything calls it;
//!   `with_admin_peer` sits in the `cfg(feature = "test-support")` module;
//!   and no file of `admin_http` reads a request header or uses `#[path]`
//!   or `include!`.
//!
//! The compile probes check the library as a dependent crate sees it,
//! without features, as `ungated_writes_private.rs` does (and in its target
//! directory, to build the workspace once): the build emits no diagnostic
//! (so `from_peer_spki` has no caller outside tests), the public items of
//! `admin_http` resolve, `admin_http::test_support` does not, and naming the
//! private field (E0451), calling `from_peer_spki` (E0624) or asking for a
//! `Default`, a `From` or a `FromStr` (E0277) fails to compile.
//!
//! It needs no database, so it is not `#[ignore]`d (inferred), and runs
//! offline from the crates the outer build has already fetched.

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

fn service_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

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

/// `source` with comments and literals blanked: as
/// `ungated_writes_private.rs`'s function of the same name.
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

fn identifier_count(text: &str, word: &str) -> usize {
    let is_identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word)
        .filter(|(start, _)| {
            let before = text[..*start].chars().next_back();
            let after = text[start + word.len()..].chars().next();
            !before.is_some_and(is_identifier) && !after.is_some_and(is_identifier)
        })
        .count()
}

/// Every library source file of the workspace (the service's `src` and the
/// scenario crate's `src`), relative to the workspace, with its stripped
/// text.
fn library_sources() -> Vec<(String, String)> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    rust_files(&service_src(), &mut files);
    rust_files(&workspace.join("tests/src"), &mut files);
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let name = file
                .strip_prefix(workspace)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let source = strip_comments_and_literals(&fs::read_to_string(&file).unwrap());
            (name, without_unit_tests(source))
        })
        .collect()
}

/// The code before the file's `#[cfg(test)] mod tests`: unit tests are in
/// no build but `cfg(test)`, where `from_peer_spki` may be called (its
/// `expect(dead_code)` holds only outside `cfg(test)`).
fn without_unit_tests(mut code: String) -> String {
    if let Some(at) = code.find("\n#[cfg(test)]\nmod tests") {
        code.truncate(at);
    }
    code
}

fn read_stripped(relative: &str) -> String {
    strip_comments_and_literals(&fs::read_to_string(service_src().join(relative)).unwrap())
}

/// The text with all whitespace removed.
fn squeezed(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn the_admin_router_is_wired_nowhere() {
    let sources = library_sources();
    for (name, code) in &sources {
        let in_admin_http = name.starts_with("service/src/admin_http/");
        for word in ["admin_router", "AdminState", "ADMIN_ROUTES"] {
            assert!(
                in_admin_http || identifier_count(code, word) == 0,
                "{name} names `{word}`: the admin router is served nowhere until the \
                 rustls acceptor lands (D5)"
            );
        }
        if !in_admin_http && name != "service/src/lib.rs" {
            assert_eq!(
                identifier_count(code, "admin_http"),
                0,
                "{name} names `admin_http`"
            );
        }
    }
    let lib = read_stripped("lib.rs");
    assert_eq!(identifier_count(&lib, "admin_http"), 1);
    assert!(squeezed(&lib).contains("pubmodadmin_http;"));
    let main = read_stripped("main.rs");
    assert!(
        squeezed(&main).contains("skyoauth_service::app()"),
        "{main}"
    );
    for word in ["admin_http", "admin_router", "AdminState", "AdminPeer"] {
        assert_eq!(identifier_count(&main, word), 0, "main.rs names `{word}`");
    }

    // `app()` routes `/healthz` only: no merge, nest or fallback service
    // could pull another router in.
    let start = lib.find("pub fn app()").expect("lib.rs defines `app()`");
    let body = &lib[start..start + lib[start..].find("\n}").unwrap()];
    for word in [
        "merge",
        "nest",
        "nest_service",
        "fallback",
        "fallback_service",
        "route_service",
        "layer",
    ] {
        assert_eq!(
            identifier_count(body, word),
            0,
            "`app()` calls `{word}`: {body}"
        );
    }
    assert_eq!(identifier_count(body, "route"), 1, "{body}");
}

/// Whether a stripped line starts an `impl` block or the struct's
/// definition rather than building a value.
fn is_item_header(line: &str) -> bool {
    let line = line.trim_start();
    ["impl ", "impl<", "pub struct ", "struct "]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

#[test]
fn the_admin_peer_is_built_only_by_the_acceptor_and_the_fake_one() {
    let sources = library_sources();
    for (name, code) in &sources {
        let squeezed = squeezed(code);
        if name == "service/src/admin_http/peer.rs" {
            continue;
        }
        assert!(
            !squeezed.contains("AdminPeer{"),
            "{name} builds or implements `AdminPeer`"
        );
        assert_eq!(identifier_count(code, "from_peer_spki"), 0, "{name}");
        assert_eq!(identifier_count(code, "with_admin_peer"), 0, "{name}");
        assert!(
            !code
                .lines()
                .any(|line| is_item_header(line) && identifier_count(line, "AdminPeer") > 0),
            "{name} implements a trait for `AdminPeer`"
        );
    }
    for (name, code) in &sources {
        if !name.starts_with("service/src/admin_http/") {
            continue;
        }
        let squeezed = squeezed(code);
        for escape in ["#[path", "path=", "include!(", "include_str!("] {
            assert!(!squeezed.contains(escape), "{name} uses `{escape}`");
        }
        for word in ["HeaderMap", "TypedHeader", "remote_addr", "ConnectInfo"] {
            assert_eq!(identifier_count(code, word), 0, "{name} names `{word}`");
        }
    }
    // The request side (the extractor, the handlers, the router) reads no
    // header and no URI: only the response side writes headers
    // (`headers_mut`, in `error.rs` and the `no-store` layer).
    for file in ["peer.rs", "operations.rs", "mod.rs"] {
        let code = read_stripped(&format!("admin_http/{file}"));
        let code = &code[..code.find("#[cfg(test)]").unwrap_or(code.len())];
        for word in ["headers", "uri", "Uri", "OriginalUri", "Host"] {
            assert_eq!(identifier_count(code, word), 0, "{file} names `{word}`");
        }
    }

    let peer = read_stripped("admin_http/peer.rs");
    // The unit tests at the end build peers through `from_peer_spki` only;
    // they are left out of the counts below.
    let code = &peer[..peer.find("#[cfg(test)]").expect("peer.rs has unit tests")];
    let lines: Vec<&str> = code.lines().collect();

    let headers: Vec<String> = lines
        .iter()
        .filter(|line| is_item_header(line) && identifier_count(line, "AdminPeer") > 0)
        .map(|line| line.trim().to_owned())
        .collect();
    assert_eq!(
        headers,
        [
            "pub struct AdminPeer {",
            "impl AdminPeer {",
            "impl fmt::Debug for AdminPeer {",
            "impl<S: Send + Sync> FromRequestParts<S> for AdminPeer {",
        ],
        "the definition and the impls of `AdminPeer`"
    );
    let definition = lines
        .iter()
        .position(|line| line.trim() == "pub struct AdminPeer {")
        .unwrap();
    let attributes: Vec<&str> = lines[..definition]
        .iter()
        .rev()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .take_while(|line| line.starts_with("#["))
        .collect();
    assert_eq!(
        attributes,
        ["#[derive(Clone)]"],
        "the attributes of `AdminPeer`"
    );
    assert_eq!(
        lines[definition + 1..definition + 3]
            .iter()
            .map(|line| line.trim())
            .collect::<Vec<_>>(),
        ["public_identity: String,", "}"],
        "one private field"
    );

    // Exactly two values are built: `Self { .. }` in `from_peer_spki` and
    // `AdminPeer { .. }` in `with_admin_peer`.
    let squeezed_code = squeezed(code);
    assert_eq!(squeezed_code.matches("Self{").count(), 1);
    let builds: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !is_item_header(line) && squeezed(line).contains("AdminPeer{"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        builds.len(),
        1,
        "one `AdminPeer {{ .. }}` outside item headers"
    );
    let test_support = squeezed_code
        .find("#[cfg(feature=)]#[doc(hidden)]pubmodtest_support{")
        .expect("`test_support` is gated on the feature and hidden");
    let build_at = squeezed(&lines[..builds[0]].join("\n")).len();
    assert!(build_at > test_support, "the literal is in `test_support`");
    assert!(
        squeezed_code.contains(
            "#[cfg_attr(not(test),expect(dead_code,reason=))]\
             pub(incrate::admin_http)fnfrom_peer_spki("
        ),
        "`from_peer_spki` keeps its visibility and its dead-code guard"
    );
    let spki = squeezed_code.find("fnfrom_peer_spki(").unwrap();
    let self_at = squeezed_code.find("Self{").unwrap();
    assert!(
        spki < self_at && self_at < test_support,
        "`Self {{ .. }}` is the acceptor's"
    );
    // The feature gate of the re-export.
    let module = read_stripped("admin_http/mod.rs");
    let module = squeezed(&module[..module.find("#[cfg(test)]\nmod tests").unwrap()]);
    assert!(module.contains("#[cfg(feature=)]#[doc(hidden)]pubusepeer::test_support;"));
    assert_eq!(module.matches("test_support").count(), 1);
}

/// The environment a nested `cargo` or `rustc` must not inherit (as in
/// `ungated_writes_private.rs`).
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

/// The library checked without features: its `.rmeta` and the directories
/// of every artifact of the build.
struct PlainLibrary {
    rmeta: PathBuf,
    deps: BTreeSet<PathBuf>,
}

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
         `expect(dead_code)` means `from_peer_spki` has a caller):\n{}",
        diagnostics.join("\n")
    );
    let rmeta = found.expect("cargo reported the library's artifact");
    PlainLibrary { rmeta, deps }
}

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

/// Asserts that `source` fails to compile with `code` (and so not for an
/// unrelated reason).
#[track_caller]
fn assert_refused(library: &PlainLibrary, probes: &Path, name: &str, source: &str, code: &str) {
    let output = compile_probe(library, probes, name, source);
    let output_text = text(&output);
    assert!(
        !output.status.success(),
        "probe `{name}` compiles:\n{source}"
    );
    assert!(
        output_text.contains(&format!("error[{code}]")),
        "probe `{name}` failed, but not with {code}:\n{output_text}"
    );
}

#[test]
fn a_dependent_crate_cannot_make_an_admin_peer() {
    // The target directory of `ungated_writes_private.rs`: the same build,
    // checked once (cargo's lock serializes the two tests).
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let library = check_plain_library(&base.join("ungated-writes-private").join("target"));
    let probes = base.join("admin-http-private").join("probes");
    fs::create_dir_all(&probes).unwrap();

    // The control: the public items resolve and a peer is usable.
    let control = compile_probe(
        &library,
        &probes,
        "admin_http_control",
        "pub use skyoauth_service::admin_http::{\n\
             ADMIN_ROUTES, AdminHttpError, AdminPeer, AdminState, DEFAULT_PAGE_SIZE, ErrorCode,\n\
             RETRY_AFTER_SECONDS, admin_router, from_admin_write, from_approval, from_id,\n\
             from_identity, from_keyset_write, from_operation_read, from_registry,\n\
             from_source_write,\n\
         };\n\
         pub fn identity(peer: &AdminPeer) -> &str { peer.public_identity() }\n\
         pub fn copy(peer: &AdminPeer) -> AdminPeer { peer.clone() }\n",
    );
    assert!(
        control.status.success(),
        "the control probe must compile:\n{}",
        text(&control)
    );

    let peer = "skyoauth_service::admin_http::AdminPeer";
    assert_refused(
        &library,
        &probes,
        "admin_http_literal",
        &format!("pub fn f() -> {peer} {{ {peer} {{ public_identity: String::new() }} }}\n"),
        "E0451",
    );
    assert_refused(
        &library,
        &probes,
        "admin_http_acceptor",
        &format!("pub fn f() {{ let _ = {peer}::from_peer_spki(&[]); }}\n"),
        "E0624",
    );
    for (name, source) in [
        (
            "admin_http_default",
            format!("pub fn f() -> {peer} {{ Default::default() }}\n"),
        ),
        (
            "admin_http_from_string",
            format!("pub fn f() -> {peer} {{ <{peer} as From<String>>::from(String::new()) }}\n"),
        ),
        (
            "admin_http_from_str",
            format!("pub fn f() -> {peer} {{ <{peer} as From<&str>>::from(\"\") }}\n"),
        ),
        (
            "admin_http_parse",
            format!("pub fn f() -> {peer} {{ \"\".parse::<{peer}>().unwrap() }}\n"),
        ),
        (
            "admin_http_try_from",
            format!(
                "pub fn f() -> {peer} {{ <{peer} as TryFrom<String>>::try_from(String::new()).unwrap() }}\n"
            ),
        ),
    ] {
        assert_refused(&library, &probes, name, &source, "E0277");
    }
    for (name, path) in [
        ("admin_http_test_support", "admin_http::test_support"),
        (
            "admin_http_with_peer",
            "admin_http::test_support::with_admin_peer",
        ),
    ] {
        let output = compile_probe(
            &library,
            &probes,
            name,
            &format!("pub use skyoauth_service::{path};\n"),
        );
        assert!(
            !output.status.success(),
            "`{path}` resolves without `test-support`"
        );
        let output_text = text(&output);
        assert!(
            output_text.contains("error[E0432]") || output_text.contains("error[E0433]"),
            "`{path}` failed, but not as a missing path:\n{output_text}"
        );
    }
    // The defining module is private, not missing.
    let output = compile_probe(
        &library,
        &probes,
        "admin_http_peer_module",
        "pub use skyoauth_service::admin_http::peer::AdminPeer;\n",
    );
    assert!(text(&output).contains("error[E0603]"), "{}", text(&output));
}
