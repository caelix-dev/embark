extern crate alloc;
use alloc::vec::Vec;
use embark_format::{CodecId, Error};

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
        // Codecs whose feature is off fall back to Store so encoding never fails.
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
        other => Err(Error::UnknownCodec(other.as_u8())),
    }
}
