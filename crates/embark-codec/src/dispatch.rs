//! Runtime dispatch from an on-binary [`CodecId`] to a codec implementation.
//!
//! The tables below list exactly the codecs compiled into this build, in
//! `CodecId` order; a codec whose cargo feature is off is simply absent.

extern crate alloc;
#[cfg(any(feature = "enc", feature = "dec"))]
use alloc::vec::Vec;
#[cfg(any(feature = "enc", feature = "dec"))]
use embark_format::CodecId;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "enc")]
type CompressFn = fn(&[u8]) -> Vec<u8>;

#[cfg(feature = "dec")]
type DecompressFn = fn(&[u8], usize) -> Result<Vec<u8>, Error>;

#[cfg(feature = "enc")]
pub(crate) const ENCODERS: &[(CodecId, CompressFn)] = &[
    (CodecId::Store, crate::store::compress),
    #[cfg(feature = "deflate")]
    (CodecId::Deflate, crate::deflate::compress),
    #[cfg(feature = "lz4")]
    (CodecId::Lz4, crate::lz4::compress),
    #[cfg(feature = "snappy")]
    (CodecId::Snappy, crate::snappy::compress),
    #[cfg(feature = "zstd")]
    (CodecId::Zstd, crate::zstd::compress),
    #[cfg(feature = "lzma")]
    (CodecId::Lzma, crate::lzma::compress),
];

#[cfg(feature = "dec")]
const DECODERS: &[(CodecId, DecompressFn)] = &[
    (CodecId::Store, crate::store::decompress),
    #[cfg(feature = "deflate")]
    (CodecId::Deflate, crate::deflate::decompress),
    #[cfg(feature = "lz4")]
    (CodecId::Lz4, crate::lz4::decompress),
    #[cfg(feature = "snappy")]
    (CodecId::Snappy, crate::snappy::decompress),
    #[cfg(feature = "zstd")]
    (CodecId::Zstd, crate::zstd::decompress),
    #[cfg(feature = "lzma")]
    (CodecId::Lzma, crate::lzma::decompress),
];

#[cfg(any(feature = "enc", feature = "dec"))]
fn lookup<F: Copy>(table: &[(CodecId, F)], id: CodecId) -> Option<F> {
    table
        .iter()
        .find_map(|&(entry, f)| (entry == id).then_some(f))
}

/// Compress with `id`, falling back to [`CodecId::Store`] when that codec's
/// feature is off, so encoding never fails.
#[cfg(feature = "enc")]
pub fn compress(id: CodecId, input: &[u8]) -> Vec<u8> {
    let compress = lookup(ENCODERS, id).unwrap_or(crate::store::compress);
    compress(input)
}

/// Decompress with `id`, which must name a codec compiled into this build.
#[cfg(feature = "dec")]
pub fn decompress(id: CodecId, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    let Some(decompress) = lookup(DECODERS, id) else {
        return Err(Error::UnknownCodec(id.as_u8()));
    };
    decompress(input, orig_len)
}
