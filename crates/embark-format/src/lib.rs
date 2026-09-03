//! The on-binary layout shared by every crate in the `embark` toolkit.
//!
//! An *entry* is one embedded file as it appears in the compiled binary: a
//! header naming how the bytes were transformed, followed by the transformed
//! bytes themselves. [`write_entry`] produces one at build time and
//! [`read_header`] parses one back at runtime; the payload starts at
//! [`Header::payload_offset`].
//!
//! # Entry layout
//!
//! | bytes | meaning |
//! |---|---|
//! | 1 | tag: [`CodecId`] in the low nibble, [`CryptoId`] in the high nibble |
//! | 1..=10 | original (pre-compression) length, LEB128 varint |
//! | 12 | AEAD nonce, present only when the crypto id is not [`CryptoId::None`] |
//! | 16 | AEAD tag, present under the same condition |
//! | rest | payload: compressed, then encrypted, in that order |
//!
//! Nothing here compresses or encrypts anything. This crate only decides
//! where the bytes go and what the ids mean, so that `embark-codec`,
//! `embark-crypt`, `embark-macros` and `embark` all agree on it without
//! depending on each other.
//!
//! # Features
//!
//! `enc` compiles the build-time writing half, `dec` the runtime reading
//! half. A consumer that only reads embedded files (the common case) needs
//! `dec` alone. Both imply `alloc`; `std` is the default and additionally
//! implies `alloc`.

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
