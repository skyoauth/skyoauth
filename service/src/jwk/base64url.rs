//! Canonical unpadded base64url (RFC 4648 section 5, without padding as
//! RFC 7515 section 2 and RFC 7518 section 6 require for JWK members),
//! hand-written like the audit module's JCS serializer (no new dependency).
//!
//! The decoder accepts exactly one text per octet sequence: the output of
//! [`encode`]. It rejects an empty text, `=` padding, any character outside
//! `A`-`Z`, `a`-`z`, `0`-`9`, `-` and `_` (so whitespace, `+` and `/`), a
//! length of 1 modulo 4, and nonzero unused bits in the last character (a
//! noncanonical encoding of the same octets).

use std::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Why a member is not canonical unpadded base64url. It names no position
/// and no character of the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64urlError {
    /// The text is empty.
    Empty,
    /// The text contains `=` padding.
    Padding,
    /// The text contains a character outside the base64url alphabet, such
    /// as whitespace, `+` or `/`.
    Alphabet,
    /// The length is 1 modulo 4, which no octet sequence encodes to.
    Length,
    /// The last character has nonzero unused bits.
    TrailingBits,
}

impl fmt::Display for Base64urlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty",
            Self::Padding => "padded",
            Self::Alphabet => "a character outside the base64url alphabet",
            Self::Length => "an impossible length",
            Self::TrailingBits => "nonzero trailing bits",
        })
    }
}

impl std::error::Error for Base64urlError {}

/// The 6-bit value of a base64url character.
fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes canonical unpadded base64url (see the module docs).
pub(crate) fn decode(text: &str) -> Result<Vec<u8>, Base64urlError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(Base64urlError::Empty);
    }
    if bytes.contains(&b'=') {
        return Err(Base64urlError::Padding);
    }
    let sextets = bytes
        .iter()
        .map(|&byte| sextet(byte).ok_or(Base64urlError::Alphabet))
        .collect::<Result<Vec<u8>, _>>()?;
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        match *chunk {
            [a, b, c, d] => {
                out.push(a << 2 | b >> 4);
                out.push(b << 4 | c >> 2);
                out.push(c << 6 | d);
            }
            [a, b, c] => {
                if c & 0b11 != 0 {
                    return Err(Base64urlError::TrailingBits);
                }
                out.push(a << 2 | b >> 4);
                out.push(b << 4 | c >> 2);
            }
            [a, b] => {
                if b & 0b1111 != 0 {
                    return Err(Base64urlError::TrailingBits);
                }
                out.push(a << 2 | b >> 4);
            }
            // A last chunk of one character: a length of 1 modulo 4.
            _ => return Err(Base64urlError::Length),
        }
    }
    Ok(out)
}

/// Encodes `bytes` as unpadded base64url.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let char_at = |index: u8| char::from(ALPHABET[usize::from(index & 0x3f)]);
    for chunk in bytes.chunks(3) {
        match *chunk {
            [a, b, c] => {
                out.push(char_at(a >> 2));
                out.push(char_at(a << 4 | b >> 4));
                out.push(char_at(b << 2 | c >> 6));
                out.push(char_at(c));
            }
            [a, b] => {
                out.push(char_at(a >> 2));
                out.push(char_at(a << 4 | b >> 4));
                out.push(char_at(b << 2));
            }
            [a] => {
                out.push(char_at(a >> 2));
                out.push(char_at(a << 4));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rfc_4648_vectors_without_padding() {
        // RFC 4648 section 10, padding removed.
        for (text, bytes) in [
            ("Zg", &b"f"[..]),
            ("Zm8", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg", b"foob"),
            ("Zm9vYmE", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
        ] {
            assert_eq!(decode(text).unwrap(), bytes, "{text}");
            assert_eq!(encode(bytes), text);
        }
    }

    #[test]
    fn uses_the_url_safe_alphabet() {
        assert_eq!(decode("-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("AQAB").unwrap(), [1, 0, 1]);
    }

    #[test]
    fn round_trips_every_byte_value_and_length() {
        let bytes: Vec<u8> = (0..=255).collect();
        for len in 1..bytes.len() {
            assert_eq!(decode(&encode(&bytes[..len])).unwrap(), &bytes[..len]);
        }
    }

    #[test]
    fn rejects_noncanonical_forms() {
        assert_eq!(decode(""), Err(Base64urlError::Empty));
        assert_eq!(decode("Zg=="), Err(Base64urlError::Padding));
        assert_eq!(decode("Zm8="), Err(Base64urlError::Padding));
        assert_eq!(decode("+_8"), Err(Base64urlError::Alphabet));
        assert_eq!(decode("-/8"), Err(Base64urlError::Alphabet));
        assert_eq!(decode("Zm 9v"), Err(Base64urlError::Alphabet));
        assert_eq!(decode("Zm9v\n"), Err(Base64urlError::Alphabet));
        assert_eq!(decode("Zm9vY"), Err(Base64urlError::Length));
        assert_eq!(decode("Z"), Err(Base64urlError::Length));
        // "Zh" and "Zm9" would decode to "f" and "fo", whose canonical
        // forms are "Zg" and "Zm8", with nonzero unused bits.
        assert_eq!(decode("Zh"), Err(Base64urlError::TrailingBits));
        assert_eq!(decode("Zm9"), Err(Base64urlError::TrailingBits));
        assert_eq!(decode("Zm-"), Err(Base64urlError::TrailingBits));
        assert_eq!(decode("Zm_"), Err(Base64urlError::TrailingBits));
    }
}
