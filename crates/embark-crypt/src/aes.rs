#[cfg(feature = "dec")]
use embark_format::Error;
extern crate alloc;
use alloc::vec::Vec;

#[cfg(feature = "dec")]
use aes_gcm::Tag;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

#[cfg(feature = "enc")]
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut buf = plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), b"", &mut buf)
        .expect("embark-crypt: plaintext exceeds the 64 GiB AES-256-GCM message limit");
    (buf, tag.into())
}

#[cfg(feature = "dec")]
pub fn open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            b"",
            &mut buf,
            Tag::from_slice(tag),
        )
        .map_err(|_| Error::Auth)?;
    Ok(buf)
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plain = b"embark encrypted payload";
        let (ct, tag) = seal(&key, &nonce, plain);
        assert_ne!(&ct[..], &plain[..]);
        let got = open(&key, &nonce, &ct, &tag).unwrap();
        assert_eq!(got, plain);
    }

    #[test]
    fn wrong_key_is_auth_error() {
        let (ct, tag) = seal(&[1u8; 32], &[2u8; 12], b"secret");
        assert_eq!(
            open(&[9u8; 32], &[2u8; 12], &ct, &tag),
            Err(embark_format::Error::Auth)
        );
    }

    #[test]
    fn tampered_ciphertext_is_auth_error() {
        let (mut ct, tag) = seal(&[1u8; 32], &[2u8; 12], b"secret");
        ct[0] ^= 0xff;
        assert_eq!(
            open(&[1u8; 32], &[2u8; 12], &ct, &tag),
            Err(embark_format::Error::Auth)
        );
    }
}
