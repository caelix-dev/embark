#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod bytes;
mod decode;
mod embed;
#[cfg(feature = "encryption")]
mod encrypted;
#[cfg(feature = "metadata")]
mod meta;

pub use bytes::EmbeddedBytes;
pub use embark_format::Error;
#[cfg(feature = "encryption")]
pub use embed::lookup_encrypted;
pub use embed::{entries, lookup, Embed, EmbeddedFile, Entries, Manifest};
#[cfg(feature = "encryption")]
pub use encrypted::EncryptedFile;

// NOTE: the `derive` feature's macro re-export (`pub use embark_macros::{embed_bytes,
// embed_crypt, Embed};`) is intentionally deferred to `feat/macros`, which implements
// those proc-macros. Adding it here before they exist breaks the build.

#[cfg(feature = "metadata")]
#[doc(hidden)]
pub fn __sha256_for_test(d: &[u8]) -> [u8; 32] {
    meta::sha256(d)
}
