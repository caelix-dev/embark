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
/// `crypto` is expected to name a real cipher (`ChaCha20Poly1305` or, with
/// the `aes` feature, `Aes256Gcm`) -- the only caller today is
/// `embark-macros`, which always resolves a `cipher = ...` argument to one
/// of those before calling here. `CryptoId::None`, or `Aes256Gcm` with the
/// `aes` feature disabled, is a caller bug, not a runtime condition to
/// recover from.
#[cfg(feature = "enc")]
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
        #[allow(unreachable_patterns)]
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
        // `open` target) and for `Aes256Gcm` when the `aes` feature is off.
        #[allow(unreachable_patterns)]
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
