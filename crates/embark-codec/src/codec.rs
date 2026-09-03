//! The [`Codec`] trait abstracts over compression codecs.
//!
//! Each built-in codec (gated by its own cargo feature) is a zero-sized unit
//! struct implementing [`Codec`] on top of the same code the derive macros
//! and [`crate::compress`]/[`crate::decompress`] dispatch use — this is a
//! manual, direct-call entry point into that machinery, not a new
//! implementation. Advanced users who want to call a specific codec without
//! going through `CodecId` dispatch can use these directly; they can also
//! implement `Codec` for their own type to reuse embark-codec's function
//! signatures manually. `#[derive(Embed)]` and `embed_bytes!` only ever
//! select among the built-in codecs by [`embark_format::CodecId`] — a
//! proc-macro cannot call into a user's own codec implementation at compile
//! time, so custom codecs are usable only through this manual trait, never
//! through the derive/macro path.

extern crate alloc;
use alloc::vec::Vec;
use embark_format::CodecId;
#[cfg(feature = "dec")]
use embark_format::Error;

/// A compression codec: turns bytes into a smaller (ideally) representation
/// and back.
///
/// Built-in codecs are zero-sized unit structs ([`Store`], [`Deflate`],
/// [`Lz4`], [`Snappy`], [`Zstd`], [`Lzma`]) implementing this trait, each
/// gated by its own cargo feature. Implement `Codec` for your own type to
/// use embark-codec's function signatures with a custom codec — this only
/// works for manual, direct calls; `#[derive(Embed)]` and `embed_bytes!`
/// cannot pick up a user-defined codec.
pub trait Codec {
    /// The on-binary [`CodecId`] this codec corresponds to.
    const ID: CodecId;

    /// Compress `input`.
    #[cfg(feature = "enc")]
    fn compress(&self, input: &[u8]) -> Vec<u8>;

    /// Decompress `input`, which must expand to exactly `orig_len` bytes.
    #[cfg(feature = "dec")]
    fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error>;
}

/// The identity codec: stores bytes unchanged.
pub struct Store;

impl Codec for Store {
    const ID: CodecId = CodecId::Store;

    #[cfg(feature = "enc")]
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::store::compress(input)
    }

    #[cfg(feature = "dec")]
    fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::store::decompress(input, orig_len)
    }
}

/// The DEFLATE codec (via `miniz_oxide`).
#[cfg(feature = "deflate")]
pub struct Deflate;

#[cfg(feature = "deflate")]
impl Codec for Deflate {
    const ID: CodecId = CodecId::Deflate;

    #[cfg(feature = "enc")]
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::deflate::compress(input)
    }

    #[cfg(feature = "dec")]
    fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::deflate::decompress(input, orig_len)
    }
}

/// The LZ4 codec (via `lz4_flex`).
#[cfg(feature = "lz4")]
pub struct Lz4;

#[cfg(feature = "lz4")]
impl Codec for Lz4 {
    const ID: CodecId = CodecId::Lz4;

    #[cfg(feature = "enc")]
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::lz4::compress(input)
    }

    #[cfg(feature = "dec")]
    fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::lz4::decompress(input, orig_len)
    }
}

/// The Snappy codec (self-implemented).
#[cfg(feature = "snappy")]
pub struct Snappy;

#[cfg(feature = "snappy")]
impl Codec for Snappy {
    const ID: CodecId = CodecId::Snappy;

    #[cfg(feature = "enc")]
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::snappy::compress(input)
    }

    #[cfg(feature = "dec")]
    fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::snappy::decompress(input, orig_len)
    }
}

/// The Zstd codec (via `ruzstd`).
#[cfg(feature = "zstd")]
pub struct Zstd;

#[cfg(feature = "zstd")]
impl Codec for Zstd {
    const ID: CodecId = CodecId::Zstd;

    #[cfg(feature = "enc")]
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::zstd::compress(input)
    }

    #[cfg(feature = "dec")]
    fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::zstd::decompress(input, orig_len)
    }
}

/// The LZMA1 codec (self-implemented `.lzma` alone format).
#[cfg(feature = "lzma")]
pub struct Lzma;

#[cfg(feature = "lzma")]
impl Codec for Lzma {
    const ID: CodecId = CodecId::Lzma;

    #[cfg(feature = "enc")]
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::lzma::compress(input)
    }

    #[cfg(feature = "dec")]
    fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::lzma::decompress(input, orig_len)
    }
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrips_via_trait() {
        let data = b"trait roundtrip via Store";
        let c = Store.compress(data);
        assert_eq!(Store.decompress(&c, data.len()).unwrap(), data);
        assert_eq!(Store::ID, CodecId::Store);
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn deflate_roundtrips_via_trait() {
        let data = b"trait roundtrip via Deflate trait roundtrip via Deflate".repeat(4);
        let c = Deflate.compress(&data);
        assert_eq!(Deflate.decompress(&c, data.len()).unwrap(), data);
        assert_eq!(Deflate::ID, CodecId::Deflate);
    }
}
