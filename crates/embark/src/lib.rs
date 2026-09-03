#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod bytes;
mod decode;

pub use bytes::EmbeddedBytes;
pub use embark_format::Error;
