#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod entry;
mod error;
mod ids;
mod varint;

pub use error::Error;
#[cfg(feature = "enc")]
pub use entry::write_entry;
#[cfg(feature = "dec")]
pub use entry::read_header;
pub use entry::Header;
pub use ids::{CodecId, CryptoId};
#[cfg(feature = "alloc")]
pub use varint::write_varint;
pub use varint::read_varint;
