//! Lowercase hexadecimal, the text form of keys and digests on the wire.
//!
//! The service's own codec (`local_transport` and the restoration plan)
//! takes an even number of lowercase digits and refuses everything else,
//! upper case included, so this one does the same. A general-purpose
//! hexadecimal crate would accept upper case.

/// The digits, by value.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// `bytes` in lowercase hexadecimal.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// The value of one lowercase hexadecimal digit.
fn digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// The bytes of `text`, an even number of lowercase hexadecimal digits;
/// `None` for anything else (upper case included).
pub(crate) fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[high, low]| Some((digit(*high)? << 4) | digit(*low)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_round_trips() {
        let bytes: Vec<u8> = (0..=u8::MAX).collect();
        let text = encode_hex(&bytes);
        assert_eq!(text.len(), 512);
        assert!(text.bytes().all(|b| DIGITS.contains(&b)));
        assert_eq!(&text[..8], "00010203");
        assert_eq!(&text[504..], "fcfdfeff");
        assert_eq!(decode_hex(&text), Some(bytes));
        assert_eq!(encode_hex(&[]), "");
        assert_eq!(decode_hex(""), Some(Vec::new()));
    }

    #[test]
    fn only_even_lowercase_digits_decode() {
        for text in [
            "0", "abc", "A0", "0A", "aF", "0g", "g0", " 0", "0 ", "0x00", "+1", "\u{e9}", "-0",
        ] {
            assert_eq!(decode_hex(text), None, "{text:?}");
        }
        assert_eq!(decode_hex("09af"), Some(vec![0x09, 0xaf]));
    }
}
