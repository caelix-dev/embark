extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "enc")]
pub fn compress(input: &[u8]) -> Vec<u8> {
    // "Fastest" is the only implemented level in ruzstd 0.9 (Default/Better/Best
    // panic with `unimplemented!()`); it still produces a valid, portable zstd
    // frame that any conformant decoder (including this one) can read.
    ruzstd::encoding::compress_to_vec(input, ruzstd::encoding::CompressionLevel::Fastest)
}

#[cfg(feature = "dec")]
pub fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    use ruzstd::io::Read as _;

    if orig_len == 0 {
        return Ok(Vec::new());
    }
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(input).map_err(|_| Error::Corrupt)?;
    let mut out = alloc::vec![0u8; orig_len];
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
}
