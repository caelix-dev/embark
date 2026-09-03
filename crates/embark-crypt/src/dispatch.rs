//! Dispatch by [`CryptoId`] to the built-in [`Aead`](crate::Aead)
//! implementation it names. Mirrors `embark-codec`'s codec dispatch.

extern crate alloc;
use alloc::vec::Vec;
use embark_format::CryptoId;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "aes")]
use crate::Aes256Gcm;
use crate::ChaCha20Poly1305;

/// Seal `plain` under the AEAD cipher named by `crypto`.
///
/// # Panics
///
/// Panics if `crypto` does not name a cipher this build can seal with: that
/// is `CryptoId::None`, `CryptoId::Aes256Gcm` without the `aes` feature, or
/// a cipher added to the format since this build was compiled.
/// The only caller today is `embark-macros`, which always resolves a
/// `cipher = ...` argument to a supported cipher before calling here, so
/// any of these is a caller bug rather than a runtime condition to recover
/// from.
///
/// Also panics if `plain` exceeds the chosen cipher's maximum message
/// length; see [`Aead::seal`](crate::Aead::seal).
#[cfg(feature = "enc")]
#[must_use]
pub fn seal(
    crypto: CryptoId,
    key: &[u8; 32],
    nonce: &[u8; 12],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    use crate::Aead;
    match crypto {
        CryptoId::ChaCha20Poly1305 => ChaCha20Poly1305.seal(key, nonce, plain),
        #[cfg(feature = "aes")]
        CryptoId::Aes256Gcm => Aes256Gcm.seal(key, nonce, plain),
        other => panic!(
            "embark-crypt: seal requires a real AEAD cipher, got crypto id {}",
            other.as_u8()
        ),
    }
}

/// Open `ct` (with detached `tag`) under the AEAD cipher named by `crypto`.
///
/// Unlike [`seal`], this is reachable with an arbitrary on-binary
/// `CryptoId` (untrusted entry data), so an unknown or feature-disabled
/// cipher is a normal `Err`, never a panic.
///
/// # Errors
///
/// Returns `Error::UnknownCrypto` if `crypto` names no cipher this build can
/// open with, and `Error::Auth` if the tag does not authenticate `ct` under
/// this key and nonce.
#[cfg(feature = "dec")]
pub fn open(
    crypto: CryptoId,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    use crate::Aead;
    match crypto {
        CryptoId::ChaCha20Poly1305 => ChaCha20Poly1305.open(key, nonce, ct, tag),
        #[cfg(feature = "aes")]
        CryptoId::Aes256Gcm => Aes256Gcm.open(key, nonce, ct, tag),
        // Reached for `CryptoId::None` (never sealed, so never a valid
        // `open` target), for `Aes256Gcm` when the `aes` feature is off, and
        // for any cipher `CryptoId` gained after this build was compiled.
        other => Err(Error::UnknownCrypto(other.as_u8())),
    }
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn chacha_dispatch_roundtrip() {
        let key = [7u8; 32];
        let nonce = [8u8; 12];
        let (ct, tag) = seal(CryptoId::ChaCha20Poly1305, &key, &nonce, b"dispatch");
        let got = open(CryptoId::ChaCha20Poly1305, &key, &nonce, &ct, &tag).unwrap();
        assert_eq!(got, b"dispatch");
    }

    #[cfg(feature = "aes")]
    #[test]
    fn aes_dispatch_roundtrip() {
        let key = [7u8; 32];
        let nonce = [8u8; 12];
        let (ct, tag) = seal(CryptoId::Aes256Gcm, &key, &nonce, b"dispatch-aes");
        let got = open(CryptoId::Aes256Gcm, &key, &nonce, &ct, &tag).unwrap();
        assert_eq!(got, b"dispatch-aes");
    }

    #[test]
    fn open_unknown_crypto_errors() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let (ct, tag) = seal(CryptoId::ChaCha20Poly1305, &key, &nonce, b"x");
        assert_eq!(
            open(CryptoId::None, &key, &nonce, &ct, &tag),
            Err(embark_format::Error::UnknownCrypto(0))
        );
    }
}
