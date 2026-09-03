extern crate alloc;
#[cfg(any(feature = "enc", feature = "dec"))]
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "enc")]
pub(crate) fn compress(input: &[u8]) -> Vec<u8> {
    lz4_flex::block::compress(input)
}

#[cfg(feature = "dec")]
pub(crate) fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    // `lz4_flex::block::decompress` preallocates `orig_len` internally via
    // `vec![0u8; orig_len]`, and `orig_len` comes straight from the
    // (attacker-controllable) entry header. We size the output buffer
    // ourselves through a fallible reservation, then decompress into it with
    // `decompress_into` (which writes through a bounds-checked slice sink and
    // performs no allocation of its own), so a hostile length becomes a
    // returned `Error::Corrupt` instead of an eager allocation that aborts
    // the process on failure.
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(orig_len)
        .map_err(|_| Error::Corrupt)?;
    out.resize(orig_len, 0u8);
    let written = lz4_flex::block::decompress_into(input, &mut out).map_err(|_| Error::Corrupt)?;
    out.truncate(written);
    Ok(out)
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"lz4 lz4 lz4 lz4 lz4 lz4 lz4 lz4 lz4 lz4".repeat(20);
        let c = compress(&data);
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty() {
        let c = compress(b"");
        assert_eq!(decompress(&c, 0).unwrap(), b"");
    }

    #[test]
    fn wrong_len_is_corrupt() {
        let c = compress(b"hello world");
        assert!(decompress(&c, 3).is_err());
    }

    #[test]
    fn hostile_orig_len_does_not_over_allocate() {
        // The old `lz4_flex::block::decompress(input, orig_len)` call
        // preallocated `orig_len` before looking at `input` at all, so even
        // 4 bytes of garbage with a huge claimed length aborted the process.
        let hostile_orig_len = 1usize << 40; // 1 TiB
        assert!(decompress(&[0u8, 0, 0, 0], hostile_orig_len).is_err());
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
}
