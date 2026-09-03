#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aead;
#[cfg(feature = "enc")]
pub use aead::seal;
#[cfg(feature = "dec")]
pub use aead::open;

mod keygen;
pub use keygen::xor32;
#[cfg(feature = "enc")]
pub use keygen::gen_key_nonce;
