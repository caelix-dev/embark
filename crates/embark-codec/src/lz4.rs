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
    // (attacker-controllable) entry header. `decompress_into` allocates
    // nothing and writes through a bounds-checked slice sink, so the buffer
    // is ours to size -- but it has to exist in full before decoding starts,
    // since a match copies from earlier output.
    //
    // A fallible reservation is not enough on its own. An operating system
    // that overcommits grants a mapping for a claim of any size and only
    // kills the process once it is written to, which is exactly what filling
    // the buffer does next. So the claim is checked against what this payload
    // could possibly expand to before any of it is believed.
    //
    // The bound is the format's: the cheapest way to emit bytes is one match,
    // costing a token and a two-byte offset for the first 19 and one more
    // byte per further 255. Anything past that is not a length this input can
    // decode to, whoever wrote the header.
    let ceiling = input.len().saturating_mul(255).saturating_add(64);
    if orig_len > ceiling {
        return Err(Error::Corrupt);
    }
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve_exact(orig_len)
        .map_err(|_| Error::Corrupt)?;
    out.resize(orig_len, 0u8);
    let written = lz4_flex::block::decompress_into(input, &mut out).map_err(|_| Error::Corrupt)?;
    // The sink is exactly `orig_len` wide, so a block that wants more than
    // that fails inside `decompress_into`. One that wants less returns
    // early with the count, and is just as much of a length disagreement.
    if written != orig_len {
        return Err(Error::Corrupt);
    }
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

    // Both directions. A claim smaller than the block fails inside the
    // decoder when the sink runs out; a claim larger than it used to come
    // back as `Ok` with the shorter output, which the fuzzer found within
    // its first few inputs.
    #[test]
    fn wrong_len_is_corrupt() {
        let c = compress(b"hello world");
        assert_eq!(decompress(&c, 3), Err(Error::Corrupt));
        assert_eq!(decompress(&c, 12), Err(Error::Corrupt));
        assert_eq!(decompress(&c, 100), Err(Error::Corrupt));
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
