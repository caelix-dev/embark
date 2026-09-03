#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod best;
mod codec;
#[cfg(feature = "deflate")]
mod deflate;
mod dispatch;
#[cfg(feature = "lz4")]
mod lz4;
#[cfg(feature = "lzma")]
mod lzma;
#[cfg(feature = "snappy")]
mod snappy;
mod store;
#[cfg(feature = "zstd")]
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
