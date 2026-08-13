//! Dependency-free base-85 encoding with a DNS-safe alphabet.
//!
//! Base 85 encodes four bytes into five printable ASCII characters, a 20%
//! expansion instead of base64's 33%. This keeps a public-key DNS TXT
//! record small enough to fit the practical 4096-byte limit: the
//! ML-KEM-768 + ML-DSA-65 public keys (3136 bytes) become 3920 characters.
//!
//! # DNS-safe alphabet
//!
//! The 85 symbols are `!`..`z` (ASCII 33–122) with the five characters
//! that are hostile in a quoted DNS zone-file string removed:
//! `"` (the string quote itself), `\` (escape character), `;` (comment
//! start), and `(` / `)` (multi-line grouping). The output therefore never
//! needs escaping when each TXT character-string is pasted between double
//! quotes — unlike the classic Adobe ASCII85 alphabet, which includes `"`.
//!
//! There is no zero-run `z` shortcut (the whole `!`..`z` range is used for
//! digits): every full group is five characters. Whitespace is ignored on
//! decode, and a trailing partial group of `n` characters decodes to `n-1`
//! bytes per the classic rules.
//!
//! This is implemented locally rather than pulling in the unmaintained
//! `ascii85` crate (2017 vintage, decoder-only, incorrect on `z`, and not
//! DNS-safe). [`decode`] rejects characters outside the symbol set and
//! group values that overflow 32 bits, so it is safe to feed untrusted
//! input such as a DNS record.

use std::sync::OnceLock;
use thiserror::Error;

/// The 85 base-85 symbols, in digit order.
///
/// `!`..`z` (33..=122) minus `"` (34), `(`, `)`, `;` (59), and `\` (92).
/// This is exactly 85 characters and contains none of the characters that
/// must be escaped inside a quoted DNS TXT string.
const ALPHABET: [u8; 85] =
    *b"!#$%&'*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz";

/// Errors produced by [`decode`].
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Ascii85Error {
    /// The input contains a character outside the 85-symbol set.
    #[error("invalid base-85 character {0:?}")]
    InvalidChar(u8),
    /// A five-character group decodes to a value larger than 2^32-1.
    #[error("base-85 group value out of range")]
    ValueOverflow,
}

/// Encode `data` into a base-85 string.
///
/// Every four-byte group is encoded as five characters; a trailing partial
/// group of `r` bytes is encoded as `r+1` characters per the classic rules.
/// The output contains only the DNS-safe symbols above.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(4) * 5);
    for chunk in data.chunks_exact(4) {
        push_value(
            &mut out,
            u32::from_be_bytes(chunk.try_into().expect("4 bytes per chunk")),
        );
    }
    let remainder = data.chunks_exact(4).remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; 4];
        buf[..remainder.len()].copy_from_slice(remainder);
        let mut tmp = String::with_capacity(5);
        push_value(&mut tmp, u32::from_be_bytes(buf));
        out.push_str(&tmp[..remainder.len() + 1]);
    }
    out
}

/// Append the five-symbol base-85 encoding of `value` to `out`.
fn push_value(out: &mut String, mut value: u32) {
    let mut buf = [0u8; 5];
    for slot in buf.iter_mut().rev() {
        *slot = ALPHABET[(value % 85) as usize];
        value /= 85;
    }
    out.push_str(std::str::from_utf8(&buf).expect("base-85 digits are ASCII"));
}

/// Map a byte to its base-85 digit value, or `None` if it is not a symbol.
fn digit_value(byte: u8) -> Option<u8> {
    static TABLE: OnceLock<[i16; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut table = [-1i16; 256];
        for (digit, &symbol) in ALPHABET.iter().enumerate() {
            table[symbol as usize] = digit as i16;
        }
        table
    });
    let value = table[byte as usize];
    (value >= 0).then_some(value as u8)
}

/// Decode a base-85 string back into bytes.
///
/// Whitespace (including line breaks inserted by DNS TXT chunking) is
/// ignored. Returns an error for characters outside the symbol set and for
/// groups whose value overflows 32 bits.
pub fn decode(input: &str) -> Result<Vec<u8>, Ascii85Error> {
    let mut out = Vec::with_capacity(input.len() / 5 * 4 + 8);
    let mut chunk: u64 = 0;
    let mut count = 0usize;

    for byte in input.bytes().filter(|b| !b.is_ascii_whitespace()) {
        match digit_value(byte) {
            Some(digit) => {
                chunk = chunk * 85 + u64::from(digit);
                count += 1;
                if count == 5 {
                    out.extend_from_slice(&to_u32(chunk)?.to_be_bytes());
                    chunk = 0;
                    count = 0;
                }
            }
            None => return Err(Ascii85Error::InvalidChar(byte)),
        }
    }

    if count > 0 {
        for _ in count..5 {
            chunk = chunk * 85 + 84;
        }
        let keep = count - 1;
        out.extend_from_slice(&to_u32(chunk)?.to_be_bytes()[..keep]);
    }
    Ok(out)
}

/// Reject group values that cannot be represented in 32 bits.
fn to_u32(chunk: u64) -> Result<u32, Ascii85Error> {
    u32::try_from(chunk).map_err(|_| Ascii85Error::ValueOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_remainder_lengths() {
        for len in 0..=33usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = encode(&data);
            assert_eq!(decode(&encoded).unwrap(), data, "len {}", len);
        }
    }

    #[test]
    fn round_trips_random_distributed_bytes() {
        let data: Vec<u8> = (0..4096u16).map(|i| i as u8).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn encode_is_20_percent_overhead() {
        let data = vec![0x5au8; 3136];
        let encoded = encode(&data);
        assert_eq!(encoded.len(), 3920, "3136 bytes -> 3920 chars");
    }

    #[test]
    fn encode_contains_no_zone_file_hostile_characters() {
        let mut data: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
        data.extend_from_slice(&[0; 64]);
        let encoded = encode(&data);
        let hostile = [b'"', b'\\', b';', b'(', b')', b' '];
        assert!(
            encoded.bytes().all(|b| !hostile.contains(&b)),
            "output must be paste-safe inside DNS quotes: {}",
            encoded
        );
        assert!(encoded.bytes().all(|b| ALPHABET.contains(&b)));
    }

    #[test]
    fn decode_ignores_whitespace() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7];
        let encoded = encode(&data);
        let split: String = encoded
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == 3 {
                    format!(" {} ", c)
                } else {
                    c.to_string()
                }
            })
            .collect();
        assert_eq!(decode(&split).unwrap(), data);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert_eq!(decode("abcd~"), Err(Ascii85Error::InvalidChar(b'~')));
        let overflow = "zzzzz";
        assert_eq!(decode(overflow), Err(Ascii85Error::ValueOverflow));
    }
}
