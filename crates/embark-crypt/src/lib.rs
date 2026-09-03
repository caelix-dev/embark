#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aead;

#[cfg(feature = "aes")]
mod aes;

mod aead_trait;
#[cfg(feature = "aes")]
pub use aead_trait::Aes256Gcm;
pub use aead_trait::{Aead, ChaCha20Poly1305};

mod dispatch;
#[cfg(feature = "dec")]
pub use dispatch::open;
#[cfg(feature = "enc")]
pub use dispatch::seal;

mod keygen;
#[cfg(feature = "enc")]
pub use keygen::gen_key_nonce;
pub use keygen::xor32;
