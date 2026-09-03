#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod ids;
mod varint;

pub use error::Error;
pub use ids::{CodecId, CryptoId};
#[cfg(feature = "alloc")]
pub use varint::write_varint;
pub use varint::read_varint;
