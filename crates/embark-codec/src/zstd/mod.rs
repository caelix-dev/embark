//! Zstandard encoder written against RFC 8478, with `ruzstd` kept for
//! decoding.
//!
//! The asymmetry is deliberate. Compression runs once per asset inside the
//! build-time proc macro, while decompression runs in every consumer binary
//! that reads the asset, so effort spent on ratio is paid for once and
//! effort spent on decode speed is paid for forever. That is why the encoder
//! here is a lazy hash-chain parser with repeat offsets rather than the
//! single-probe finder `ruzstd` offers, and why the decoder is left alone.
//!
//! The encoder emits a single frame with an explicit window of at most
//! 8 MiB, blocks of at most 128 KiB, Huffman-coded literals, and sequences
//! entropy-coded against the format's predefined FSE distributions. Blocks that would not shrink are stored instead, so an
//! incompressible input grows by only three bytes per block.

extern crate alloc;

#[cfg(feature = "enc")]
mod bitstream;
#[cfg(feature = "enc")]
mod block;
#[cfg(feature = "enc")]
mod frame;
#[cfg(feature = "enc")]
mod fse;
#[cfg(feature = "enc")]
mod huffman;
#[cfg(feature = "enc")]
mod matcher;
#[cfg(feature = "enc")]
mod sequences;

#[cfg(any(feature = "enc", feature = "dec"))]
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

/// Compress `input` into one Zstandard frame.
#[cfg(feature = "enc")]
pub(crate) fn compress(input: &[u8]) -> Vec<u8> {
    frame::encode(input)
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
    use alloc::string::String;

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

    /// A deterministic xorshift, so the random-shaped tests stay reproducible
    /// and dependency-free.
    fn pseudo_random(seed: u32, len: usize) -> Vec<u8> {
        let mut state = seed | 1;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.push((state & 0xff) as u8);
        }
        out
    }

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let packed = compress(data);
        assert_eq!(&packed[..4], &[0x28, 0xb5, 0x2f, 0xfd], "frame magic");
        let back = decompress(&packed, data.len()).expect("our own decoder must accept the frame");
        assert_eq!(back, data);
        packed
    }

    #[test]
    fn roundtrip_json_like() {
        let mut data = String::from("[");
        for i in 0..2000 {
            data.push_str("{\"id\":");
            data.push_str(&alloc::format!("{i}"));
            data.push_str(",\"name\":\"item\",\"tags\":[\"a\",\"b\"],\"ok\":true},");
        }
        data.push(']');
        let bytes = data.into_bytes();
        let packed = roundtrip(&bytes);
        assert!(
            packed.len() * 8 < bytes.len(),
            "structured text should shrink hard"
        );
    }

    #[test]
    fn roundtrip_sizes_around_the_block_boundary() {
        // 128 KiB is the largest block, so the interesting sizes are the ones
        // that force a second block to exist and to be nearly empty.
        for len in [131_071usize, 131_072, 131_073, 131_074, 262_144, 262_145] {
            let mut data = pseudo_random(len as u32, len);
            // Half random, half repetitive, so both block types get exercised.
            for i in len / 2..len {
                data[i] = data[i % 97];
            }
            roundtrip(&data);
        }
    }

    #[test]
    fn roundtrip_sizes_around_the_window_boundary() {
        // The window descriptor and the single-segment form change over at
        // 256 bytes, and the content-size field widens at 65792.
        for len in [
            1usize, 2, 3, 4, 5, 255, 256, 257, 1023, 1024, 1025, 65_791, 65_792,
        ] {
            roundtrip(&pseudo_random(len as u32, len));
            roundtrip(&b"ab".repeat(len.div_ceil(2))[..len]);
        }
    }

    #[test]
    fn incompressible_input_barely_grows() {
        let data = pseudo_random(7, 300_000);
        let packed = compress(&data);
        // Three bytes of block header per 128 KiB block, plus the frame header.
        assert!(packed.len() < data.len() + 32, "grew to {}", packed.len());
        assert_eq!(decompress(&packed, data.len()).unwrap(), data);
    }

    #[test]
    fn fuzz_roundtrip_over_random_shapes() {
        let mut seed = 0x9e37_79b9u32;
        for round in 0..400u32 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let len = (seed as usize) % 9_000;
            let mut data = pseudo_random(seed, len);
            match round % 4 {
                // Low entropy.
                0 => data.iter_mut().for_each(|b| *b &= 0x03),
                // A repeated prefix, which drives the repeat-offset codes.
                1 if len > 8 => {
                    let head = data[..len / 8].to_vec();
                    data.truncate(len / 8);
                    while data.len() < len {
                        data.extend_from_slice(&head);
                    }
                    data.truncate(len);
                }
                // One byte throughout, which must fall out as RLE blocks.
                2 => data.iter_mut().for_each(|b| *b = 0x5a),
                _ => {}
            }
            let packed = compress(&data);
            assert_eq!(
                decompress(&packed, data.len()).unwrap(),
                data,
                "round {round}, len {len}"
            );
        }
    }

    #[test]
    fn truncated_frames_are_rejected_not_panics() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(64);
        let packed = compress(&data);
        for cut in 0..packed.len() {
            // Any prefix must either decode to the right bytes or error out.
            if let Ok(back) = decompress(&packed[..cut], data.len()) {
                assert_eq!(back, data);
            }
        }
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
