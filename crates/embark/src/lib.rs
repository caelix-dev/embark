//! `embark` embeds files into your binary at build time, with optional
//! compression, encryption, and metadata — a
//! unified embedding layer across raw, compressed, and encrypted content.
//!
//! Two front-end styles are provided:
//!
//! - [`embed_bytes!`] — an `include_bytes!`-style single-file macro,
//!   optionally compressed with a chosen codec (see [`EmbeddedBytes`]).
//! - [`Embed`] (via `#[derive(Embed)]`) — a whole-directory
//!   embed, giving [`Embed::get`]-by-path and [`Embed::iter`] access to
//!   every file under a folder.
//!
//! Encrypted content ([`embed_crypt!`], `#[embark(encrypt)]`) is handled by
//! [`EncryptedFile`], generic over a type-state marker
//! ([`EmbeddedKey`] or [`RuntimeKey`]) that determines which decrypt
//! methods exist on it. **Read its docs before using build-time
//! encryption**: the default mode is obfuscation, not real confidentiality
//! — see [`EncryptedFile`] for the distinction and how to get real
//! confidentiality with a runtime key.
//!
//! # Feature flags
//!
//! - `std` / `alloc` — runtime support; `alloc` alone keeps the crate
//!   `no_std`.
//! - `derive` — the `embed_bytes!`, `embed_crypt!`, and `#[derive(Embed)]`
//!   macros (via `embark-macros`).
//! - `deflate`, `lz4`, `snappy` — compression codecs (opt-in, pay for what
//!   you use).
//! - `encryption` — ChaCha20-Poly1305 AEAD support ([`EncryptedFile`]).
//! - `metadata` — per-file [`EmbeddedFile::hash`] and [`EmbeddedFile::mime`].
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
#[cfg(feature = "std")]
pub use embed::__dev_file;
#[cfg(feature = "encryption")]
pub use embed::lookup_encrypted;
pub use embed::{entries, lookup, Embed, EmbeddedFile, Entries, Manifest};
#[cfg(feature = "encryption")]
pub use encrypted::{EmbeddedKey, EncryptedFile, RuntimeKey};

// Re-exported for advanced users who want to call a codec or cipher
// directly, or implement one of these traits for manual (non-macro) use.
// `#[derive(Embed)]` and the `embed_*!` macros only ever pick a built-in
// codec/cipher by on-binary id — they cannot use a custom implementation.
pub use embark_codec::Codec;
#[cfg(feature = "deflate")]
pub use embark_codec::Deflate;
#[cfg(feature = "lz4")]
pub use embark_codec::Lz4;
#[cfg(feature = "lzma")]
pub use embark_codec::Lzma;
#[cfg(feature = "snappy")]
pub use embark_codec::Snappy;
#[cfg(feature = "zstd")]
pub use embark_codec::Zstd;
#[cfg(feature = "encryption")]
pub use embark_crypt::{Aead, ChaCha20Poly1305};

#[cfg(feature = "derive")]
pub use embark_macros::{embed_bytes, embed_crypt, Embed};

#[cfg(feature = "metadata")]
#[doc(hidden)]
pub fn __sha256_for_test(d: &[u8]) -> [u8; 32] {
    meta::sha256(d)
}
