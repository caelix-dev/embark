extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "enc")]
pub(crate) fn compress(input: &[u8]) -> Vec<u8> {
    // "Fastest" is the only implemented level in ruzstd 0.9 (Default/Better/Best
    // panic with `unimplemented!()`); it still produces a valid, portable zstd
    // frame that any conformant decoder (including this one) can read.
    ruzstd::encoding::compress_to_vec(input, ruzstd::encoding::CompressionLevel::Fastest)
}

#[cfg(feature = "dec")]
pub(crate) fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    use ruzstd::io::Read as _;

    if orig_len == 0 {
        return Ok(Vec::new());
    }
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(input).map_err(|_| Error::Corrupt)?;
    // `orig_len` comes straight from the (attacker-controllable) entry header,
    // so size the buffer through a fallible reservation: a claim like 1 TiB
    // becomes a returned `Error::Corrupt` instead of an eager allocation that
    // aborts the process on failure.
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(orig_len)
        .map_err(|_| Error::Corrupt)?;
    out.resize(orig_len, 0u8);
    decoder.read_exact(&mut out).map_err(|_| Error::Corrupt)?;
    Ok(out)
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let c = compress(b"");
        assert_eq!(decompress(&c, 0).unwrap(), b"");
    }

    #[test]
    fn roundtrip_single_byte() {
        let data = b"x";
        let c = compress(data);
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_repetitive() {
        let data = b"ababababababababababababababababab".repeat(50);
        let c = compress(&data);
        assert!(c.len() < data.len(), "repetitive data should shrink");
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_incompressible_random() {
        // A small xorshift PRNG keeps this test dependency-free.
        let mut state: u32 = 0x1234_5678;
        let mut data = Vec::with_capacity(2048);
        for _ in 0..2048 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            data.push((state & 0xff) as u8);
        }
        let c = compress(&data);
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_all_byte_values() {
        let data: Vec<u8> = (0..=255u8).collect();
        let c = compress(&data);
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_text() {
        let data = b"The quick brown fox jumps over the lazy dog. \
            Pack my box with five dozen liquor jugs. \
            How vexingly quick daft zebras jump! \
            The five boxing wizards jump quickly. \
            Sphinx of black quartz, judge my vow. \
            Waltz, bad nymph, for quick jigs vex."
            .repeat(4);
        let c = compress(&data);
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn garbage_is_corrupt() {
        assert!(decompress(&[0xff, 0xff, 0xff, 0xff], 10).is_err());
    }

    #[test]
    fn roundtrip_large_real_data() {
        // A legitimate large payload must still round-trip through the
        // fallible-reservation path -- a bound that rejects real data would
        // be worse than the bug it fixes.
        let data = b"the quick brown fox jumps over the lazy dog ".repeat(200_000);
        let c = compress(&data);
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn hostile_orig_len_does_not_over_allocate() {
        // A tiny input claiming an impossible orig_len fails during frame
        // parsing before ever reaching the allocation -- that alone doesn't
        // prove the allocation is bounded. Use a *valid* zstd frame for a
        // small plaintext, paired with a huge caller-supplied orig_len, so
        // the frame header check is passed and the fallible reservation is
        // the thing actually under test. Before the fix this called
        // `vec![0u8; orig_len]` and aborted the process.
        let c = compress(b"tiny");
        let hostile_orig_len = 1usize << 40; // 1 TiB
        assert!(decompress(&c, hostile_orig_len).is_err());
    }
}
