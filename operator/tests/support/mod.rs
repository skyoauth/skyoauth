//! Helpers of the `operator` target: the shared fixture files and their
//! hexadecimal.

use std::path::PathBuf;

use serde_json::Value;

/// The shared fixture directory, `tests/conformance/fixtures` at the
/// repository root (conformance layout §1.3). Panics when it does not exist,
/// so a moved directory fails every test instead of reading nothing.
pub fn fixtures_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tests")
        .join("conformance")
        .join("fixtures");
    assert!(dir.is_dir(), "no fixture directory at {}", dir.display());
    dir
}

/// The socket path fixture under `_wire/`, read by `local_path` (Unix
/// only) and listed by `local_wire`.
pub const SOCKET_PATH_FIXTURE: &str = "socket_path.v1.json";

/// The fixture file `name` under `_recovery/`, parsed.
pub fn recovery_fixture(name: &str) -> Value {
    let path = fixtures_dir().join("_recovery").join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// The bytes of `text`, an even number of lowercase hexadecimal digits.
/// Independent of the crate's own codec, so a fault there cannot hide here.
pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hexadecimal: {text:?}");
    assert!(
        text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "not lowercase hexadecimal: {text:?}"
    );
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// The string member `name` of `value`.
pub fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} is not a string in {value}"))
}

/// The array member `name` of `value`.
pub fn list<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    value[name]
        .as_array()
        .unwrap_or_else(|| panic!("{name} is not an array in {value}"))
}

/// The bytes of a public identity case's `der`: `hex`, then `fill_count`
/// copies of `fill_byte` when the case has them.
pub fn der_bytes(der: &Value) -> Vec<u8> {
    let mut bytes = unhex(text(der, "hex"));
    match (der.get("fill_byte"), der.get("fill_count")) {
        (None, None) => {}
        (Some(byte), Some(count)) => {
            let byte = unhex(byte.as_str().expect("fill_byte is a string"));
            assert_eq!(byte.len(), 1, "fill_byte is one byte");
            let count = count.as_u64().expect("fill_count is an integer");
            bytes.extend(std::iter::repeat_n(
                byte[0],
                usize::try_from(count).unwrap(),
            ));
        }
        _ => panic!("fill_byte and fill_count go together: {der}"),
    }
    bytes
}
