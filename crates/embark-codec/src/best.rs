extern crate alloc;
#[cfg(feature = "enc")]
use alloc::vec::Vec;
#[cfg(feature = "enc")]
use embark_format::CodecId;

#[cfg(feature = "enc")]
pub fn compress_best(input: &[u8]) -> (CodecId, Vec<u8>) {
    // Store is the baseline; a codec wins only if strictly smaller.
    let mut best_id = CodecId::Store;
    let mut best = input.to_vec();

    let consider = |id: CodecId, bytes: Vec<u8>, best_id: &mut CodecId, best: &mut Vec<u8>| {
        if bytes.len() < best.len() {
            *best_id = id;
            *best = bytes;
        }
    };

    #[cfg(feature = "deflate")]
    consider(
        CodecId::Deflate,
        crate::deflate::compress(input),
        &mut best_id,
        &mut best,
    );
    #[cfg(feature = "lz4")]
    consider(
        CodecId::Lz4,
        crate::lz4::compress(input),
        &mut best_id,
        &mut best,
    );
    #[cfg(feature = "snappy")]
    consider(
        CodecId::Snappy,
        crate::snappy::compress(input),
        &mut best_id,
        &mut best,
    );
    #[cfg(feature = "zstd")]
    consider(
        CodecId::Zstd,
        crate::zstd::compress(input),
        &mut best_id,
        &mut best,
    );

    let _ = &consider; // silence unused warning when no codec feature is on
    (best_id, best)
}
