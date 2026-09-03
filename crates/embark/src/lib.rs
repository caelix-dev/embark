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
//! # Example
//!
//! The examples throughout these docs embed this crate's own
//! `examples/assets` folder, so they run as written. Paths are resolved
//! relative to your crate's `CARGO_MANIFEST_DIR`.
//!
//! ```
//! # #[cfg(all(feature = "derive", feature = "deflate", feature = "std"))] {
//! use embark::Embed as _;
//!
//! // A single file, verbatim -- exactly `include_bytes!`.
//! static HELLO: &[u8] = embark::embed_bytes!("examples/assets/hello.txt");
//! assert_eq!(HELLO, b"hello embark");
//!
//! // A single file, compressed at build time and decompressed on access.
//! static TEXT: embark::EmbeddedBytes =
//!     embark::embed_bytes!("examples/assets/lipsum.txt", codec = deflate);
//! assert!(TEXT.data().starts_with(b"Embark packs your files"));
//!
//! // A whole folder, addressable by path.
//! #[derive(embark::Embed)]
//! #[embark(folder = "examples/assets/docs", codec = "auto")]
//! struct Docs;
//!
//! assert_eq!(Docs::iter().count(), 2);
//! assert!(Docs::get("about.txt").unwrap().data().starts_with(b"Embark"));
//! # }
//! ```
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
//! - `aes` — adds AES-256-GCM as a second AEAD cipher, selected per entry
//!   with `embed_crypt!(..., cipher = aes)` or `#[embark(encrypt, cipher =
//!   "aes")]` (implies `encryption`).
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
pub use embed::{Embed, EmbeddedFile, Entries, Manifest, entries, lookup};
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
#[cfg(feature = "aes")]
pub use embark_crypt::Aes256Gcm;
#[cfg(feature = "encryption")]
pub use embark_crypt::{Aead, ChaCha20Poly1305};

#[cfg(feature = "derive")]
pub use embark_macros::{Embed, embed_bytes, embed_crypt};

#[cfg(feature = "metadata")]
#[doc(hidden)]
pub fn __sha256_for_test(d: &[u8]) -> [u8; 32] {
    meta::sha256(d)
}
