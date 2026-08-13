//! Dependency-free ASCII85 (a.k.a. Base85) encoding.
//!
//! ASCII85 encodes four bytes into five ASCII characters chosen from the
//! printable range `!` (33) to `u` (117), giving a 20% expansion instead of
//! base64's 33%. This keeps a public-key DNS TXT record small enough to fit
//! the practical 4096-byte limit: the ML-KEM-768 + ML-DSA-65 public keys
//! (3136 bytes) become 3920 characters.
//!
//! The alphabet and partial-group rules follow the classic Adobe
//! specification: a run of four zero bytes is encoded as the single
//! character `z`, whitespace is ignored on decode, and a trailing partial
//! group of `n` characters (<5) decodes to `n-1` bytes. The encoder always
//! emits five characters per full group, so `z` never appears inside a
//! partial group.
//!
//! This is implemented locally rather than pulling in the unmaintained
//! `ascii85` crate (2017 vintage, decoder-only, and incorrect when the
//! input contains `z`). [`decode`] rejects characters outside the ASCII85
//! alphabet and group values that overflow 32 bits, so it is safe to feed
//! untrusted input such as a DNS record.

use thiserror::Error;

/// Errors produced by [`decode`].
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Ascii85Error {
    /// The input contains a character outside the ASCII85 alphabet (`!`..`u`).
    #[error("invalid ASCII85 character {0:?}")]
    InvalidChar(u8),
    /// A `z` appears inside an unfinished group.
    #[error("misplaced ASCII85 'z'")]
    MisplacedZ,
    /// A five-character group decodes to a value larger than 2^32-1.
    #[error("ASCII85 group value out of range")]
    ValueOverflow,
}

/// Encode `data` into an ASCII85 string.
///
/// Full four-byte groups are encoded as five characters (or a single `z`
/// when they are all zero); a trailing partial group of `r` bytes is
/// encoded as `r+1` characters per the classic spec.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(4) * 5);
    let chunks = data.chunks_exact(4);
    for chunk in chunks {
        let value = u32::from_be_bytes(chunk.try_into().expect("chunks_exact yields 4 bytes"));
        if value == 0 {
            out.push('z');
        } else {
            push_value(&mut out, value);
        }
    }
    let remainder = data.chunks_exact(4).remainder();
    if !remainder.is_empty() {
        let mut buf = [0u8; 4];
        buf[..remainder.len()].copy_from_slice(remainder);
        let mut tmp = String::with_capacity(5);
        push_value(&mut tmp, u32::from_be_bytes(buf));
        let keep = remainder.len() + 1;
        out.push_str(&tmp[..keep]);
    }
    out
}

/// Append the five-character ASCII85 encoding of `value` to `out`.
fn push_value(out: &mut String, mut value: u32) {
    let mut buf = [0u8; 5];
    for slot in buf.iter_mut().rev() {
        *slot = (value % 85) as u8 + b'!';
        value /= 85;
    }
    out.push_str(std::str::from_utf8(&buf).expect("ascii85 digits are ASCII"));
}

/// Decode an ASCII85 string back into bytes.
///
/// Whitespace (including line breaks inserted by DNS TXT chunking) is
/// ignored. Returns an error for characters outside the ASCII85 alphabet,
/// misplaced `z`, and groups whose value overflows 32 bits.
pub fn decode(input: &str) -> Result<Vec<u8>, Ascii85Error> {
    let mut out = Vec::with_capacity(input.len() / 5 * 4 + 8);
    let mut chunk: u64 = 0;
    let mut count = 0usize;

    for byte in input.bytes().filter(|b| !b.is_ascii_whitespace()) {
        match byte {
            b'z' if count == 0 => out.extend_from_slice(&[0, 0, 0, 0]),
            b'z' => return Err(Ascii85Error::MisplacedZ),
            b'!'..=b'u' => {
                chunk = chunk * 85 + u64::from(byte - b'!');
                count += 1;
                if count == 5 {
                    out.extend_from_slice(&to_u32(chunk)?.to_be_bytes());
                    chunk = 0;
                    count = 0;
                }
            }
            other => return Err(Ascii85Error::InvalidChar(other)),
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
    fn encodes_known_vector() {
        assert_eq!(encode(b"Man sure."), "9jqo^F*2M7/c");
        assert_eq!(decode("9jqo^F*2M7/c").unwrap(), b"Man sure.");
    }

    #[test]
    fn round_trips_all_remainder_lengths() {
        for len in 0..=33usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = encode(&data);
            assert_eq!(decode(&encoded).unwrap(), data, "len {}", len);
        }
    }

    #[test]
    fn zero_runs_compress_to_z() {
        let zeros = [0u8; 12];
        assert_eq!(encode(&zeros), "zzz");
        assert_eq!(decode("zzz").unwrap(), zeros);
    }

    #[test]
    fn encode_is_20_percent_overhead() {
        let data = vec![0x5au8; 3136];
        let encoded = encode(&data);
        assert_eq!(encoded.len(), 3920, "3136 bytes -> 3920 ascii85 chars");
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
        assert_eq!(
            decode("9jqo^F*2M7/c~"),
            Err(Ascii85Error::InvalidChar(b'~'))
        );
        assert_eq!(decode("abzcd"), Err(Ascii85Error::MisplacedZ));
        let overflow = "uuuuu";
        assert_eq!(decode(overflow), Err(Ascii85Error::ValueOverflow));
    }
}
