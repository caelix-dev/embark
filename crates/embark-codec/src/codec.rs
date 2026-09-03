//! Named, zero-sized handles for the built-in codecs.
//!
//! Each codec compiled into the build (gated by its own cargo feature) has a
//! unit struct here — [`Store`], [`Deflate`], [`Lz4`], [`Snappy`], [`Zstd`],
//! [`Lzma`] — carrying inherent `compress`/`decompress` methods and an
//! [`Codec::ID`] naming its on-binary [`CodecId`]. They are a direct-call
//! entry point into the same code [`crate::compress`] and
//! [`crate::decompress`] reach through `CodecId` dispatch, for callers who
//! already know which codec they want.
//!
//! [`Codec`] is sealed: it exists to associate a type with its on-binary id,
//! not as an extension point. The on-binary format spends four bits on the
//! codec id and `embark-format` assigns every accepted value to a built-in,
//! so a third-party codec has no id it could occupy, nothing would ever
//! decode it, and `#[derive(Embed)]` / `embed_bytes!` select a codec by
//! `CodecId` at compile time and so can never name one.

extern crate alloc;
#[cfg(any(feature = "enc", feature = "dec"))]
use alloc::vec::Vec;
use embark_format::CodecId;
#[cfg(feature = "dec")]
use embark_format::Error;

mod sealed {
    pub trait Sealed {}
}

/// Associates a built-in codec type with its on-binary [`CodecId`].
///
/// This trait is sealed and cannot be implemented outside this crate. The
/// codec id is a fixed four-bit field of the embedded entry header with no
/// values left over, so there is no id a downstream codec could claim and no
/// path by which the derive macros or [`crate::decompress`] could reach one.
/// Compression itself lives on inherent methods of each codec type, so
/// calling `Deflate.compress(..)` does not require this trait in scope.
pub trait Codec: sealed::Sealed {
    /// The on-binary [`CodecId`] this codec corresponds to.
    const ID: CodecId;
}

/// The identity codec: stores bytes unchanged.
#[derive(Debug)]
pub struct Store;

impl sealed::Sealed for Store {}

impl Codec for Store {
    const ID: CodecId = CodecId::Store;
}

impl Store {
    /// Compress `input`.
    #[cfg(feature = "enc")]
    #[must_use]
    pub fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::store::compress(input)
    }

    /// Decompress `input`, which must expand to exactly `orig_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if `input` is not exactly `orig_len`
    /// bytes long. Nothing else can go wrong: there is no encoding to
    /// misparse.
    #[cfg(feature = "dec")]
    pub fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::store::decompress(input, orig_len)
    }
}

/// The DEFLATE codec (via `miniz_oxide`).
#[cfg(feature = "deflate")]
#[derive(Debug)]
pub struct Deflate;

#[cfg(feature = "deflate")]
impl sealed::Sealed for Deflate {}

#[cfg(feature = "deflate")]
impl Codec for Deflate {
    const ID: CodecId = CodecId::Deflate;
}

#[cfg(feature = "deflate")]
impl Deflate {
    /// Compress `input`.
    #[cfg(feature = "enc")]
    #[must_use]
    pub fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::deflate::compress(input)
    }

    /// Decompress `input`, which must expand to exactly `orig_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if `input` is not a valid raw DEFLATE
    /// stream, if it expands to a length other than `orig_len`, or if
    /// `orig_len` is more than this target can allocate.
    #[cfg(feature = "dec")]
    pub fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::deflate::decompress(input, orig_len)
    }
}

/// The LZ4 codec (via `lz4_flex`).
#[cfg(feature = "lz4")]
#[derive(Debug)]
pub struct Lz4;

#[cfg(feature = "lz4")]
impl sealed::Sealed for Lz4 {}

#[cfg(feature = "lz4")]
impl Codec for Lz4 {
    const ID: CodecId = CodecId::Lz4;
}

#[cfg(feature = "lz4")]
impl Lz4 {
    /// Compress `input`.
    #[cfg(feature = "enc")]
    #[must_use]
    pub fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::lz4::compress(input)
    }

    /// Decompress `input`, which must expand to exactly `orig_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if `input` is not a valid LZ4 block, if it
    /// expands to a length other than `orig_len`, or if `orig_len` is more
    /// than this target can allocate.
    #[cfg(feature = "dec")]
    pub fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::lz4::decompress(input, orig_len)
    }
}

/// The Snappy codec (self-implemented).
#[cfg(feature = "snappy")]
#[derive(Debug)]
pub struct Snappy;

#[cfg(feature = "snappy")]
impl sealed::Sealed for Snappy {}

#[cfg(feature = "snappy")]
impl Codec for Snappy {
    const ID: CodecId = CodecId::Snappy;
}

#[cfg(feature = "snappy")]
impl Snappy {
    /// Compress `input`.
    #[cfg(feature = "enc")]
    #[must_use]
    pub fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::snappy::compress(input)
    }

    /// Decompress `input`, which must expand to exactly `orig_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the block ends mid-tag, and
    /// [`Error::Corrupt`] if a tag is malformed, if the length preamble or
    /// the decoded output disagrees with `orig_len`, or if `orig_len` is
    /// more than this target can allocate.
    #[cfg(feature = "dec")]
    pub fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::snappy::decompress(input, orig_len)
    }
}

/// The Zstd codec: a self-written encoder, decoding via `ruzstd`.
#[cfg(feature = "zstd")]
#[derive(Debug)]
pub struct Zstd;

#[cfg(feature = "zstd")]
impl sealed::Sealed for Zstd {}

#[cfg(feature = "zstd")]
impl Codec for Zstd {
    const ID: CodecId = CodecId::Zstd;
}

#[cfg(feature = "zstd")]
impl Zstd {
    /// Compress `input`.
    #[cfg(feature = "enc")]
    #[must_use]
    pub fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::zstd::compress(input)
    }

    /// Decompress `input`, which must expand to exactly `orig_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if `input` is not a valid zstd frame, if it
    /// yields fewer than `orig_len` bytes, or if `orig_len` is more than this
    /// target can allocate.
    #[cfg(feature = "dec")]
    pub fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::zstd::decompress(input, orig_len)
    }
}

/// The LZMA1 codec (self-implemented `.lzma` alone format).
#[cfg(feature = "lzma")]
#[derive(Debug)]
pub struct Lzma;

#[cfg(feature = "lzma")]
impl sealed::Sealed for Lzma {}

#[cfg(feature = "lzma")]
impl Codec for Lzma {
    const ID: CodecId = CodecId::Lzma;
}

#[cfg(feature = "lzma")]
impl Lzma {
    /// Compress `input`.
    #[cfg(feature = "enc")]
    #[must_use]
    pub fn compress(&self, input: &[u8]) -> Vec<u8> {
        crate::lzma::compress(input)
    }

    /// Decompress `input`, which must expand to exactly `orig_len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the stream ends mid-symbol, and
    /// [`Error::Corrupt`] if the `.lzma` header is malformed, if the size it
    /// records or the decoded output disagrees with `orig_len`, or if
    /// `orig_len` is more than this target can allocate.
    #[cfg(feature = "dec")]
    pub fn decompress(&self, input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
        crate::lzma::decompress(input, orig_len)
    }
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrips_via_handle() {
        let data = b"handle roundtrip via Store";
        let c = Store.compress(data);
        assert_eq!(Store.decompress(&c, data.len()).unwrap(), data);
        assert_eq!(Store::ID, CodecId::Store);
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn deflate_roundtrips_via_handle() {
        let data = b"handle roundtrip via Deflate handle roundtrip via Deflate".repeat(4);
        let c = Deflate.compress(&data);
        assert_eq!(Deflate.decompress(&c, data.len()).unwrap(), data);
        assert_eq!(Deflate::ID, CodecId::Deflate);
    }
}
