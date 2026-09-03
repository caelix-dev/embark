extern crate alloc;
use alloc::vec::Vec;
use embark_format::CodecId;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "enc")]
pub fn compress(id: CodecId, input: &[u8]) -> Vec<u8> {
    match id {
        CodecId::Store => crate::store::compress(input),
        #[cfg(feature = "deflate")]
        CodecId::Deflate => crate::deflate::compress(input),
        #[cfg(feature = "lz4")]
        CodecId::Lz4 => crate::lz4::compress(input),
        #[cfg(feature = "snappy")]
        CodecId::Snappy => crate::snappy::compress(input),
        #[cfg(feature = "zstd")]
        CodecId::Zstd => crate::zstd::compress(input),
        #[cfg(feature = "lzma")]
        CodecId::Lzma => crate::lzma::compress(input),
        // Codecs whose feature is off fall back to Store so encoding never fails.
        // (Unreachable only when every codec feature is enabled at once.)
        #[allow(unreachable_patterns)]
        _ => crate::store::compress(input),
    }
}

#[cfg(feature = "dec")]
pub fn decompress(id: CodecId, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    match id {
        CodecId::Store => crate::store::decompress(input, orig_len),
        #[cfg(feature = "deflate")]
        CodecId::Deflate => crate::deflate::decompress(input, orig_len),
        #[cfg(feature = "lz4")]
        CodecId::Lz4 => crate::lz4::decompress(input, orig_len),
        #[cfg(feature = "snappy")]
        CodecId::Snappy => crate::snappy::decompress(input, orig_len),
        #[cfg(feature = "zstd")]
        CodecId::Zstd => crate::zstd::decompress(input, orig_len),
        #[cfg(feature = "lzma")]
        CodecId::Lzma => crate::lzma::decompress(input, orig_len),
        // Reached when an entry names a codec whose feature is disabled;
        // unreachable only when every codec feature is enabled at once.
        #[allow(unreachable_patterns)]
        other => Err(Error::UnknownCodec(other.as_u8())),
    }
}
