//! The [`Aead`] trait abstracts over AEAD ciphers.
//!
//! [`ChaCha20Poly1305`] is the built-in cipher, implementing [`Aead`] on top
//! of the same code the derive macros and the runtime decrypt path use —
//! this is a manual, direct-call entry point into that machinery, not a new
//! implementation. Implement `Aead` for your own cipher to reuse
//! embark-crypt's function signatures manually. The on-binary `CryptoId`
//! and the `embark_crypt` macro/runtime pipeline always use the built-in
//! cipher; a proc-macro cannot call into a user's own cipher implementation
//! at compile time, so a custom `Aead` impl is usable only through this
//! manual trait, never through the derive/macro path.

extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

/// An AEAD (authenticated encryption with associated data) cipher, with no
/// associated data (embark never needs any).
///
/// [`ChaCha20Poly1305`] is the built-in implementation. Implement `Aead` for
/// your own cipher to use embark-crypt's function signatures with a custom
/// cipher — this only works for manual, direct calls; the on-binary format
/// and the `embark_crypt`/`#[embark(encrypt)]` macro path always use the
/// built-in cipher.
pub trait Aead {
    /// Encrypt `plain` in place, returning the ciphertext and detached tag.
    #[cfg(feature = "enc")]
    fn seal(&self, key: &[u8; 32], nonce: &[u8; 12], plain: &[u8]) -> (Vec<u8>, [u8; 16]);

    /// Decrypt `ct`, verifying it against the detached `tag`.
    #[cfg(feature = "dec")]
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ct: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Error>;
}

/// The built-in ChaCha20-Poly1305 AEAD cipher.
pub struct ChaCha20Poly1305;

impl Aead for ChaCha20Poly1305 {
    #[cfg(feature = "enc")]
    fn seal(&self, key: &[u8; 32], nonce: &[u8; 12], plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
        crate::aead::seal(key, nonce, plain)
    }

    #[cfg(feature = "dec")]
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ct: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Error> {
        crate::aead::open(key, nonce, ct, tag)
    }
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_via_trait() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let plain = b"trait roundtrip via ChaCha20Poly1305";
        let (ct, tag) = ChaCha20Poly1305.seal(&key, &nonce, plain);
        assert_ne!(&ct[..], &plain[..]);
        let got = ChaCha20Poly1305.open(&key, &nonce, &ct, &tag).unwrap();
        assert_eq!(got, plain);
    }
}
