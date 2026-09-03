extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

// --- shared varint (Snappy uses little-endian base-128 for the preamble) ---

#[cfg(feature = "enc")]
fn put_uvarint(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[cfg(feature = "dec")]
fn read_uvarint(input: &[u8]) -> Result<(u32, usize), Error> {
    let mut value: u32 = 0;
    for (i, &b) in input.iter().enumerate() {
        if i == 5 {
            return Err(Error::Corrupt);
        }
        value |= u32::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(Error::Truncated)
}

// --- encoder: hash-based greedy match finder over the Snappy block format ---

#[cfg(feature = "enc")]
const MAX_OFFSET: usize = 1 << 16; // we emit 2-byte-offset copies only (simplest valid subset)

#[cfg(feature = "enc")]
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 8);
    put_uvarint(&mut out, input.len() as u32);

    let n = input.len();
    if n == 0 {
        return out;
    }

    // Hash table of 4-byte sequences -> position.
    let table_bits = 14;
    let table_size = 1usize << table_bits;
    let mut table = alloc::vec![usize::MAX; table_size];

    let hash = |bytes: &[u8]| -> usize {
        let x = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        (x.wrapping_mul(0x1e35a7bd) >> (32 - table_bits)) as usize
    };

    let mut lit_start = 0usize;
    let mut i = 0usize;
    while i + 4 <= n {
        let h = hash(&input[i..]);
        let cand = table[h];
        table[h] = i;
        let in_range = cand != usize::MAX && i - cand < MAX_OFFSET;
        if in_range && input[cand..cand + 4] == input[i..i + 4] {
            emit_literals(&mut out, &input[lit_start..i]);
            let offset = i - cand;
            // Extend the match.
            let mut len = 4;
            while i + len < n && input[cand + len] == input[i + len] {
                len += 1;
            }
            emit_copy(&mut out, offset, len);
            i += len;
            lit_start = i;
        } else {
            i += 1;
        }
    }
    emit_literals(&mut out, &input[lit_start..]);
    out
}

#[cfg(feature = "enc")]
fn emit_literals(out: &mut Vec<u8>, lit: &[u8]) {
    if lit.is_empty() {
        return;
    }
    let n = lit.len() - 1;
    if n < 60 {
        out.push((n as u8) << 2); // tag 00, length-1 in upper 6 bits
    } else {
        // length-1 stored in following bytes; count how many bytes needed.
        let mut bytes = [0u8; 4];
        let mut count = 0;
        let mut v = n as u32;
        while v > 0 {
            bytes[count] = v as u8;
            v >>= 8;
            count += 1;
        }
        out.push((59 + count as u8) << 2); // tag 00, 60..=63 => 1..=4 extra bytes
        out.extend_from_slice(&bytes[..count]);
    }
    out.extend_from_slice(lit);
}

#[cfg(feature = "enc")]
fn emit_copy(out: &mut Vec<u8>, offset: usize, mut len: usize) {
    // Emit as repeated 2-byte-offset copies (tag 10), max length 64 each.
    while len > 0 {
        let chunk = len.min(64);
        out.push((0b10) | (((chunk - 1) as u8) << 2)); // tag 10, len-1 in bits 2..8
        out.push((offset & 0xff) as u8);
        out.push(((offset >> 8) & 0xff) as u8);
        len -= chunk;
    }
}

// --- decoder: full Snappy block format (handles all copy tag widths) ---

#[cfg(feature = "dec")]
pub fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    let (declared, mut pos) = read_uvarint(input)?;
    if declared as usize != orig_len {
        return Err(Error::Corrupt);
    }
    let mut out: Vec<u8> = Vec::with_capacity(orig_len);

    while pos < input.len() {
        let tag = input[pos];
        pos += 1;
        match tag & 0b11 {
            0 => {
                // literal
                let mut len = (tag >> 2) as usize;
                if len >= 60 {
                    let extra = len - 59;
                    if pos + extra > input.len() {
                        return Err(Error::Truncated);
                    }
                    let mut v = 0usize;
                    for k in 0..extra {
                        v |= (input[pos + k] as usize) << (8 * k);
                    }
                    pos += extra;
                    len = v;
                }
                len += 1;
                if pos + len > input.len() {
                    return Err(Error::Truncated);
                }
                out.extend_from_slice(&input[pos..pos + len]);
                pos += len;
            }
            1 => {
                // copy, 1-byte offset (len 4..=11, 3-bit len, 11-bit offset)
                let len = 4 + ((tag >> 2) & 0x7) as usize;
                if pos >= input.len() {
                    return Err(Error::Truncated);
                }
                let offset = (((tag >> 5) as usize) << 8) | input[pos] as usize;
                pos += 1;
                copy_match(&mut out, offset, len)?;
            }
            2 => {
                // copy, 2-byte offset
                let len = 1 + (tag >> 2) as usize;
                if pos + 2 > input.len() {
                    return Err(Error::Truncated);
                }
                let offset = input[pos] as usize | ((input[pos + 1] as usize) << 8);
                pos += 2;
                copy_match(&mut out, offset, len)?;
            }
            _ => {
                // copy, 4-byte offset
                let len = 1 + (tag >> 2) as usize;
                if pos + 4 > input.len() {
                    return Err(Error::Truncated);
                }
                let offset = input[pos] as usize
                    | ((input[pos + 1] as usize) << 8)
                    | ((input[pos + 2] as usize) << 16)
                    | ((input[pos + 3] as usize) << 24);
                pos += 4;
                copy_match(&mut out, offset, len)?;
            }
        }

        if out.len() > orig_len {
            return Err(Error::Corrupt);
        }
    }

    if out.len() != orig_len {
        return Err(Error::Corrupt);
    }
    Ok(out)
}

#[cfg(feature = "dec")]
fn copy_match(out: &mut Vec<u8>, offset: usize, len: usize) -> Result<(), Error> {
    if offset == 0 || offset > out.len() {
        return Err(Error::Corrupt);
    }
    let start = out.len() - offset;
    for k in 0..len {
        let byte = out[start + k];
        out.push(byte);
    }
    Ok(())
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let c = compress(data);
        assert_eq!(
            decompress(&c, data.len()).unwrap(),
            data,
            "roundtrip mismatch"
        );
    }

    #[test]
    fn roundtrip_cases() {
        rt(b"");
        rt(b"a");
        rt(b"hello hello hello hello world world world");
        rt(&b"The quick brown fox jumps over the lazy dog. ".repeat(30));
        rt(&(0u8..=255).collect::<alloc::vec::Vec<u8>>());
    }

    #[test]
    fn preamble_encodes_length() {
        // 300 bytes -> varint preamble 0xAC 0x02 at the front.
        let c = compress(&[7u8; 300]);
        assert_eq!(&c[..2], &[0xAC, 0x02]);
    }

    #[test]
    fn truncated_is_error() {
        assert!(decompress(&[0x04, 0xff], 4).is_err());
    }

    #[test]
    fn overgrowth_is_rejected() {
        // Preamble declares orig_len = 4, then a 4-byte literal ("AAAA") fills
        // it exactly, followed by a 2-byte-offset copy tag that would append
        // 64 more bytes (offset 1, len 64) -- output would balloon to 68
        // bytes despite the declared length of 4. Must be rejected before
        // that growth completes, not just via the final length check.
        let body: &[u8] = &[
            0x04, // preamble: orig_len = 4
            0x0C, // literal tag: len - 1 = 3 -> 4 literal bytes
            b'A', b'A', b'A', b'A', // the literal
            0xFE, // copy tag: 2-byte offset, len - 1 = 63 -> len = 64
            0x01, 0x00, // offset = 1
        ];
        assert!(decompress(body, 4).is_err());
    }
}
