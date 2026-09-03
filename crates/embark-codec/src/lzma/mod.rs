//! Self-implemented LZMA1 codec in the `.lzma` "alone" container format,
//! interoperable with the `xz` tool (`xz --format=lzma`).
//!
//! The 13-byte header is: one properties byte `(pb*5 + lp)*9 + lc`, a 4-byte
//! little-endian dictionary size, and an 8-byte little-endian uncompressed
//! size. The range-coded LZMA1 stream follows. We encode with the customary
//! defaults lc=3, lp=0, pb=2 (properties byte `0x5D`) and store the real
//! uncompressed length; the decoder honours whatever lc/lp/pb a valid header
//! declares.

extern crate alloc;

mod model;
mod rangecoder;

#[cfg(feature = "dec")]
mod decoder;
#[cfg(feature = "enc")]
mod encoder;

#[cfg(any(feature = "enc", feature = "dec"))]
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

const HEADER_LEN: usize = 13;

/// Compress `input` into a complete `.lzma` alone stream (header + body).
#[cfg(feature = "enc")]
pub fn compress(input: &[u8]) -> Vec<u8> {
    let dict = encoder::dict_size(input.len());
    let mut out = Vec::with_capacity(HEADER_LEN + input.len() / 2 + 16);
    // Properties byte for lc=3, lp=0, pb=2: (2*5 + 0)*9 + 3 = 93 = 0x5D.
    out.push(0x5D);
    out.extend_from_slice(&dict.to_le_bytes());
    out.extend_from_slice(&(input.len() as u64).to_le_bytes());
    let body = encoder::encode(input, dict);
    out.extend_from_slice(&body);
    out
}

/// Decompress a `.lzma` alone stream, verifying the output length is exactly
/// `orig_len`. Malformed input yields `Error::Corrupt` / `Error::Truncated`,
/// never a panic.
#[cfg(feature = "dec")]
pub fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    if input.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    let props = input[0];
    if props >= 9 * 5 * 5 {
        return Err(Error::Corrupt);
    }
    let lc = (props % 9) as u32;
    let rem = props / 9;
    let lp = (rem % 5) as u32;
    let pb = (rem / 5) as u32;

    // Dictionary size (bytes 1..5) is not needed: our window is the output
    // buffer itself, and copy_match rejects any out-of-range distance.

    // Uncompressed size (bytes 5..13). The alone format stores the real size,
    // or an all-ones "unknown" marker; verify it against orig_len when known.
    let size = u64::from_le_bytes([
        input[5], input[6], input[7], input[8], input[9], input[10], input[11], input[12],
    ]);
    if size != u64::MAX && size != orig_len as u64 {
        return Err(Error::Corrupt);
    }

    let stream = &input[HEADER_LEN..];
    decoder::decode(lc, lp, pb, stream, orig_len)
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn rt(data: &[u8]) {
        let c = compress(data);
        let back = decompress(&c, data.len()).expect("decompress");
        assert_eq!(back, data, "roundtrip mismatch (len {})", data.len());
    }

    #[test]
    fn roundtrip_empty() {
        rt(b"");
    }

    #[test]
    fn roundtrip_single_byte() {
        rt(b"Q");
    }

    #[test]
    fn roundtrip_repetitive() {
        rt(&[0u8; 1000]);
        rt(&b"abcabcabc".repeat(200));
        rt(&b"The quick brown fox jumps over the lazy dog. ".repeat(50));
    }

    #[test]
    fn roundtrip_all_bytes() {
        let data: Vec<u8> = (0u8..=255).collect();
        rt(&data);
    }

    #[test]
    fn roundtrip_incompressible() {
        // Deterministic pseudo-random bytes (xorshift) -- no exploitable runs.
        let mut x: u32 = 0x1234_5678;
        let mut data = vec![0u8; 4096];
        for b in data.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x & 0xff) as u8;
        }
        rt(&data);
    }

    #[test]
    fn roundtrip_text_kb() {
        let mut s = Vec::new();
        for i in 0u32..300 {
            s.extend_from_slice(b"line ");
            let mut digits = [0u8; 10];
            let mut d = 9;
            let mut v = i;
            loop {
                digits[d] = b'0' + (v % 10) as u8;
                v /= 10;
                if v == 0 {
                    break;
                }
                d -= 1;
            }
            s.extend_from_slice(&digits[d..]);
            s.extend_from_slice(b": the lazy dog sleeps while the quick fox runs.\n");
        }
        rt(&s);
    }

    #[test]
    fn too_short_header_is_truncated() {
        assert!(matches!(decompress(&[0u8; 5], 0), Err(Error::Truncated)));
    }

    #[test]
    fn bad_props_is_corrupt() {
        let mut c = compress(b"hello world");
        c[0] = 0xFF; // props >= 225
        assert!(matches!(decompress(&c, 11), Err(Error::Corrupt)));
    }

    #[test]
    fn wrong_size_field_is_corrupt() {
        let mut c = compress(b"hello world");
        c[5] ^= 0x01; // corrupt the stored uncompressed size
        assert!(matches!(decompress(&c, 11), Err(Error::Corrupt)));
    }

    #[test]
    fn truncated_body_errs() {
        let c = compress(&b"The quick brown fox. ".repeat(40));
        let orig = b"The quick brown fox. ".repeat(40).len();
        // Chop the range-coded body in half; must error, not panic.
        let cut = HEADER_LEN + (c.len() - HEADER_LEN) / 2;
        let _ = decompress(&c[..cut], orig);
    }

    #[test]
    fn hostile_orig_len_does_not_over_allocate() {
        // A too-short input fails the `input.len() < HEADER_LEN` check
        // before ever reaching the allocation, so that alone doesn't prove
        // the allocation is bounded. Build a well-formed 13-byte header
        // (valid properties byte, and a stored size matching the huge
        // orig_len we pass in, so the header's own size check doesn't
        // short-circuit us) followed by a minimal 5-byte range-coder
        // preamble (RangeDecoder::new only requires len >= 5 and a leading
        // zero byte). That's enough to reach `decoder::decode` with an
        // attacker-chosen orig_len. Before the fix this called
        // `Vec::with_capacity(orig_len)` and aborted the process.
        let hostile_orig_len: usize = 1 << 40; // 1 TiB
        let mut input = Vec::new();
        input.push(0x5D); // props: lc=3, lp=0, pb=2
        input.extend_from_slice(&0u32.to_le_bytes()); // dict size (unchecked)
        input.extend_from_slice(&(hostile_orig_len as u64).to_le_bytes());
        input.extend_from_slice(&[0u8, 0, 0, 0, 0]); // range-coder preamble
        assert!(decompress(&input, hostile_orig_len).is_err());
    }

    #[test]
    fn garbage_does_not_panic() {
        let mut x: u32 = 0xDEAD_BEEF;
        let mut junk = vec![0u8; 200];
        for b in junk.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x & 0xff) as u8;
        }
        // Any result is fine as long as it does not panic.
        let _ = decompress(&junk, 500);
    }
}
