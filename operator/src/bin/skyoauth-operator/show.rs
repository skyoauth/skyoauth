//! Text from an artifact, made safe to print to a terminal.
//!
//! An artifact's strings are the issuer's, and the operator reads them to
//! decide whether to sign: a control character (an ANSI escape that moves
//! the cursor or clears a line, a carriage return) or a bidirectional
//! override could make one value look like another. So a string is printed
//! quoted, with only printable ASCII as is and every other character
//! escaped.

use std::fmt::Write as _;

/// `text` in double quotes: printable ASCII but `"` and `\` as is, those
/// two after a backslash, and every other character as `\u{X}` with its
/// code point in lowercase hexadecimal.
pub fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(character),
            other => {
                // Writing to a `String` cannot fail.
                let _ = write!(out, "\\u{{{:x}}}", u32::from(other));
            }
        }
    }
    out.push('"');
    out
}
