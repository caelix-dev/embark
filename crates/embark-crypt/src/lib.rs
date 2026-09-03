#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aead;
#[cfg(feature = "dec")]
pub use aead::open;
#[cfg(feature = "enc")]
pub use aead::seal;

mod keygen;
#[cfg(feature = "enc")]
pub use keygen::gen_key_nonce;
pub use keygen::xor32;
