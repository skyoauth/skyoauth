//! The local bootstrap and recovery transport is served nowhere
//! (`crate::local_transport`, "Not done here"): until a deployment step
//! starts it, the service binds no Unix socket.
//!
//! The source check reads the library's code, comments and string and
//! character literals blanked, as `admin_http_private.rs` does:
//! `LocalTransport`, `LocalListener` and `local_transport` are named only
//! under `src/local_transport/`, in the service and in the scenario crate's
//! library, and in `lib.rs`'s one `#[cfg(unix)] pub mod`; `main.rs` names
//! none of them nor a Unix socket; and `app()` merges, nests and falls back
//! to nothing.
//!
//! It needs no database, so it is not `#[ignore]`d (inferred).

use std::{
    env, fs,
    path::{Path, PathBuf},
};

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
/// `ungated_writes_private.rs`'s and `admin_http_private.rs`'s function of
/// the same name.
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
/// no build but `cfg(test)`.
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

/// The names that would start or reach the transport.
const TRANSPORT_NAMES: [&str; 3] = ["local_transport", "LocalTransport", "LocalListener"];

#[test]
fn the_local_transport_is_wired_nowhere() {
    let sources = library_sources();
    assert!(
        sources
            .iter()
            .any(|(name, _)| name == "service/src/local_transport/mod.rs"),
        "the transport's module moved: update this test"
    );
    for (name, code) in &sources {
        if name.starts_with("service/src/local_transport/") || name == "service/src/lib.rs" {
            continue;
        }
        for word in TRANSPORT_NAMES {
            assert_eq!(
                identifier_count(code, word),
                0,
                "{name} names `{word}`: the local transport is started nowhere \
                 (see its module docs, \"Not done here\")"
            );
        }
    }
    let lib = read_stripped("lib.rs");
    assert_eq!(identifier_count(&lib, "local_transport"), 1);
    assert!(squeezed(&lib).contains("#[cfg(unix)]pubmodlocal_transport;"));
    for word in ["LocalTransport", "LocalListener"] {
        assert_eq!(identifier_count(&lib, word), 0, "lib.rs names `{word}`");
    }

    let main = read_stripped("main.rs");
    assert!(
        squeezed(&main).contains("skyoauth_service::app()"),
        "{main}"
    );
    for word in TRANSPORT_NAMES
        .into_iter()
        .chain(["UnixListener", "UnixStream", "peer_cred"])
    {
        assert_eq!(identifier_count(&main, word), 0, "main.rs names `{word}`");
    }

    // `app()` routes `/healthz` only: no merge, nest or fallback service
    // could pull a transport in.
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
