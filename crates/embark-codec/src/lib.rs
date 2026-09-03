#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod best;
mod dispatch;
mod store;
#[cfg(feature = "deflate")]
mod deflate;
#[cfg(feature = "lz4")]
mod lz4;
#[cfg(feature = "snappy")]
mod snappy;

#[cfg(feature = "enc")]
pub use best::compress_best;
#[cfg(feature = "enc")]
pub use dispatch::compress;
#[cfg(feature = "dec")]
pub use dispatch::decompress;
