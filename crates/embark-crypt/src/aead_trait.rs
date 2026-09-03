//! Naming and dispatch for the two built-in AEAD ciphers.

extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

mod sealed {
    pub trait Sealed {}
}

/// An AEAD (authenticated encryption with associated data) cipher, always
/// used with empty associated data — embark never needs any.
///
/// This trait is **sealed**: [`ChaCha20Poly1305`] and, behind the `aes`
/// feature, `Aes256Gcm` are its only implementations, and downstream crates
/// cannot add another. It exists so the built-in ciphers can be named as
/// types and dispatched over uniformly, not as an extension point.
///
/// A third-party cipher would be unusable here even if the trait were open.
/// An embedded entry names its cipher with a one-byte `CryptoId` in its
/// header, and that set of ids is closed, so a custom cipher has no id to
/// write and nothing could produce an entry it would later be asked to open.
/// The proc macros pick from the same ids at compile time and have no way to
/// call into user code.
pub trait Aead: sealed::Sealed {
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

impl sealed::Sealed for ChaCha20Poly1305 {}

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

/// The AES-256-GCM AEAD cipher, gated behind the `aes` feature. Same key
/// (32B), nonce (12B), and tag (16B) shape as [`ChaCha20Poly1305`].
#[cfg(feature = "aes")]
pub struct Aes256Gcm;

#[cfg(feature = "aes")]
impl sealed::Sealed for Aes256Gcm {}

#[cfg(feature = "aes")]
impl Aead for Aes256Gcm {
    #[cfg(feature = "enc")]
    fn seal(&self, key: &[u8; 32], nonce: &[u8; 12], plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
        crate::aes::seal(key, nonce, plain)
    }

    #[cfg(feature = "dec")]
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ct: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Error> {
        crate::aes::open(key, nonce, ct, tag)
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

    #[cfg(feature = "aes")]
    #[test]
    fn roundtrips_via_trait_aes() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let plain = b"trait roundtrip via Aes256Gcm";
        let (ct, tag) = Aes256Gcm.seal(&key, &nonce, plain);
        assert_ne!(&ct[..], &plain[..]);
        let got = Aes256Gcm.open(&key, &nonce, &ct, &tag).unwrap();
        assert_eq!(got, plain);
    }
}
