//! The compression layer of the `embark` toolkit: one interface over
//! DEFLATE, LZ4, Snappy, Zstandard and LZMA1, keyed by the
//! [`CodecId`](embark_format::CodecId) that `embark-format` writes into
//! every entry header.
//!
//! There are two ways in. [`compress`] and [`decompress`] take a `CodecId`
//! and dispatch at runtime, which is what a decoder reading an untrusted
//! entry needs. The unit structs — [`Store`], [`Deflate`], [`Lz4`],
//! [`Snappy`], [`Zstd`], [`Lzma`] — are the direct-call form for a caller
//! that already knows its codec, and [`compress_best`] tries every codec
//! compiled in and keeps the smallest output.
//!
//! Every codec is pure Rust with no C dependency, so the whole crate builds
//! for `no_std` targets with only `alloc`.
//!
//! # Features
//!
//! Each codec has its own feature and none are on by default, so a build
//! links only the formats it names. `enc` compiles the compressing half and
//! `dec` the decompressing half; a consumer that only reads embedded files
//! needs `dec` plus the codecs its entries actually use.
//!
//! A codec that was not compiled in is not an error at the format level:
//! [`decompress`] reports [`Error::UnknownCodec`](embark_format::Error::UnknownCodec)
//! for it, and [`compress`] falls back to [`CodecId::Store`](embark_format::CodecId::Store)
//! so encoding never fails.
//!
//! # Example
//!
//! ```
//! # #[cfg(all(feature = "enc", feature = "dec", feature = "deflate"))] {
//! use embark_format::CodecId;
//!
//! let data = b"embark embark embark embark".repeat(8);
//! let packed = embark_codec::compress(CodecId::Deflate, &data);
//! assert!(packed.len() < data.len());
//!
//! let back = embark_codec::decompress(CodecId::Deflate, &packed, data.len())?;
//! assert_eq!(back, data);
//! # }
//! # Ok::<(), embark_format::Error>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

// A codec's implementation is only reachable through `enc` or `dec`. With
// neither, the module would compile to dead code, so it is not compiled at
// all; the `Codec` handle it names stays available either way.
mod best;
mod codec;
#[cfg(all(feature = "deflate", any(feature = "enc", feature = "dec")))]
mod deflate;
mod dispatch;
#[cfg(all(feature = "lz4", any(feature = "enc", feature = "dec")))]
mod lz4;
#[cfg(all(feature = "lzma", any(feature = "enc", feature = "dec")))]
mod lzma;
#[cfg(all(feature = "snappy", any(feature = "enc", feature = "dec")))]
mod snappy;
mod store;
#[cfg(all(feature = "zstd", any(feature = "enc", feature = "dec")))]
mod zstd;

#[cfg(feature = "deflate")]
pub use codec::Deflate;
#[cfg(feature = "lz4")]
pub use codec::Lz4;
#[cfg(feature = "lzma")]
pub use codec::Lzma;
#[cfg(feature = "snappy")]
pub use codec::Snappy;
#[cfg(feature = "zstd")]
pub use codec::Zstd;
pub use codec::{Codec, Store};

#[cfg(feature = "enc")]
pub use best::compress_best;
#[cfg(feature = "enc")]
pub use dispatch::compress;
#[cfg(feature = "dec")]
pub use dispatch::decompress;
