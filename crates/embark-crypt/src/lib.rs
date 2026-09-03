//! The encryption layer of the `embark` toolkit: AEAD sealing and opening
//! for embedded entries, keyed by the [`CryptoId`](embark_format::CryptoId)
//! that `embark-format` writes into every entry header.
//!
//! [`seal`] and [`open`] dispatch on that id at runtime; [`ChaCha20Poly1305`]
//! and, behind the `aes` feature, [`Aes256Gcm`] are the same two ciphers
//! named as types, through the sealed [`Aead`] trait. Both take a 32-byte
//! key and a 12-byte nonce and produce a detached 16-byte tag, and both are
//! always used with empty associated data.
//!
//! [`gen_key_nonce`] draws a fresh key and nonce for one entry from the
//! operating system generator, and [`xor32`] is the masking primitive behind
//! the build-time key obfuscation that `embark-macros` emits.
//!
//! # What this crate does not promise
//!
//! Nothing here decides *where the key lives*, and that is what determines
//! whether an embedded file is actually confidential. `embark`'s default
//! mode reconstructs the key from material compiled into the binary, which
//! is obfuscation against a casual reader and not security against anyone
//! willing to reverse the binary. Real confidentiality needs a key supplied
//! at runtime. See `embark::EncryptedFile` for that distinction.
//!
//! # Features
//!
//! `enc` compiles the build-time sealing half (and the OS key generator with
//! it), `dec` the runtime opening half. `aes` adds AES-256-GCM alongside the
//! always-present ChaCha20-Poly1305.

// docs.rs builds with `--cfg docsrs` (see each manifest's
// `[package.metadata.docs.rs]`), which turns this on and makes rustdoc label
// every item with the feature that gates it. Nearly all of this API is
// behind one, so without the label the rendered docs read as though it were
// all unconditional. Inert on stable, where `docsrs` is never set.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

// Every cipher body sits behind `enc` or `dec`. With neither, these modules
// would be dead code, so they are not compiled at all.
#[cfg(any(feature = "enc", feature = "dec"))]
mod aead;

#[cfg(all(feature = "aes", any(feature = "enc", feature = "dec")))]
mod aes;

mod aead_trait;
#[cfg(feature = "aes")]
pub use aead_trait::Aes256Gcm;
pub use aead_trait::{Aead, ChaCha20Poly1305};

#[cfg(any(feature = "enc", feature = "dec"))]
mod dispatch;
#[cfg(feature = "dec")]
pub use dispatch::open;
#[cfg(feature = "enc")]
pub use dispatch::seal;

mod keygen;
#[cfg(feature = "enc")]
pub use keygen::gen_key_nonce;
pub use keygen::xor32;
