#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod entry;
mod error;
mod ids;
mod varint;

pub use entry::Header;
#[cfg(feature = "dec")]
pub use entry::read_header;
#[cfg(feature = "enc")]
pub use entry::write_entry;
pub use error::{Error, Result};
pub use ids::{CodecId, CryptoId};
pub use varint::read_varint;
#[cfg(feature = "alloc")]
pub use varint::write_varint;
