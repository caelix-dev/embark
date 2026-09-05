//! Naming and dispatch for the two built-in AEAD ciphers.

extern crate alloc;
#[cfg(any(feature = "enc", feature = "dec"))]
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

mod sealed {
    pub trait Sealed {}
}

/// An AEAD (authenticated encryption with associated data) cipher.
///
/// The associated data is the entry header -- the codec, the cipher and the
/// claimed length -- so that none of those can be rewritten under a tag
/// that still verifies. The caller passes the exact bytes; an entry's
/// [`Header::aad_len`](embark_format::Header::aad_len) says how many.
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
    /// Encrypt `plain`, binding `aad` into the tag, and return the
    /// ciphertext and detached tag.
    ///
    /// # Panics
    ///
    /// Panics if `plain` is longer than the cipher can encrypt under one key
    /// and nonce: 256 GiB for ChaCha20-Poly1305, 64 GiB for AES-256-GCM. An
    /// entry that large cannot be embedded in a binary in any case.
    #[cfg(feature = "enc")]
    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plain: &[u8],
    ) -> (Vec<u8>, [u8; 16]);

    /// Decrypt `ct`, verifying it and `aad` against the detached `tag`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Auth`] if the tag does not authenticate `ct` and
    /// `aad` under this key and nonce.
    #[cfg(feature = "dec")]
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Error>;
}

/// The built-in ChaCha20-Poly1305 AEAD cipher.
#[derive(Debug)]
pub struct ChaCha20Poly1305;

impl sealed::Sealed for ChaCha20Poly1305 {}

impl Aead for ChaCha20Poly1305 {
    #[cfg(feature = "enc")]
    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plain: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        crate::aead::seal(key, nonce, aad, plain)
    }

    #[cfg(feature = "dec")]
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Error> {
        crate::aead::open(key, nonce, aad, ct, tag)
    }
}

/// The AES-256-GCM AEAD cipher, gated behind the `aes` feature. Same key
/// (32B), nonce (12B), and tag (16B) shape as [`ChaCha20Poly1305`].
#[cfg(feature = "aes")]
#[derive(Debug)]
pub struct Aes256Gcm;

#[cfg(feature = "aes")]
impl sealed::Sealed for Aes256Gcm {}

#[cfg(feature = "aes")]
impl Aead for Aes256Gcm {
    #[cfg(feature = "enc")]
    fn seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plain: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        crate::aes::seal(key, nonce, aad, plain)
    }

    #[cfg(feature = "dec")]
    fn open(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, Error> {
        crate::aes::open(key, nonce, aad, ct, tag)
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
        let (ct, tag) = ChaCha20Poly1305.seal(&key, &nonce, b"hdr", plain);
        assert_ne!(&ct[..], &plain[..]);
        let got = ChaCha20Poly1305
            .open(&key, &nonce, b"hdr", &ct, &tag)
            .unwrap();
        assert_eq!(got, plain);
        // The tag stands for the associated data too.
        assert_eq!(
            ChaCha20Poly1305.open(&key, &nonce, b"HDR", &ct, &tag),
            Err(Error::Auth)
        );
    }

    #[cfg(feature = "aes")]
    #[test]
    fn roundtrips_via_trait_aes() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let plain = b"trait roundtrip via Aes256Gcm";
        let (ct, tag) = Aes256Gcm.seal(&key, &nonce, b"hdr", plain);
        assert_ne!(&ct[..], &plain[..]);
        let got = Aes256Gcm.open(&key, &nonce, b"hdr", &ct, &tag).unwrap();
        assert_eq!(got, plain);
        assert_eq!(
            Aes256Gcm.open(&key, &nonce, b"HDR", &ct, &tag),
            Err(Error::Auth)
        );
    }
}
