#[cfg(feature = "dec")]
use embark_format::Error;
extern crate alloc;
use alloc::vec::Vec;

#[cfg(feature = "dec")]
use chacha20poly1305::Tag;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

#[cfg(feature = "enc")]
pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut buf = plain.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(*nonce), aad, buf.as_mut_slice().into())
        .expect("embark-crypt: plaintext exceeds the 256 GiB ChaCha20-Poly1305 message limit");
    (buf, tag.into())
}

#[cfg(feature = "dec")]
pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    let mut buf = ct.to_vec();
    cipher
        .decrypt_inout_detached(
            &Nonce::from(*nonce),
            aad,
            buf.as_mut_slice().into(),
            &Tag::from(*tag),
        )
        .map_err(|_| Error::Auth)?;
    Ok(buf)
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    // Captured from this crate on the previous release of the AEAD stack.
    // The interface underneath has been rewritten twice now, and each time
    // the only thing that matters is that the bytes did not move: a binary
    // built against an older `embark` has to keep decrypting under a newer
    // one, and nothing about a round trip would notice if it stopped.
    #[test]
    fn matches_the_bytes_this_crate_has_always_produced() {
        let (ct, tag) = seal(
            &[0x42u8; 32],
            &[0x24u8; 12],
            b"",
            b"embark encrypted payload",
        );
        let hex = |b: &[u8]| {
            b.iter()
                .map(|x| alloc::format!("{x:02x}"))
                .collect::<alloc::string::String>()
        };
        assert_eq!(
            hex(&ct),
            "816ae76f99b578cdeb08faf2946378fcdfb928c8ca4c3553",
            "ChaCha20-Poly1305 ciphertext moved"
        );
        // Associated data goes into the tag and nowhere else: the
        // ciphertext is the same bytes whatever the header says.
        let (ct_aad, tag_aad) = seal(
            &[0x42u8; 32],
            &[0x24u8; 12],
            b"hdr",
            b"embark encrypted payload",
        );
        assert_eq!(ct_aad, ct);
        assert_ne!(tag_aad, tag);
        assert_eq!(
            hex(&tag),
            "4ef9e4a2427db48368c59a9b67a2907d",
            "ChaCha20-Poly1305 tag moved"
        );
    }

    #[test]
    fn roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plain = b"embark encrypted payload";
        let (ct, tag) = seal(&key, &nonce, b"", plain);
        assert_ne!(&ct[..], &plain[..]);
        let got = open(&key, &nonce, b"", &ct, &tag).unwrap();
        assert_eq!(got, plain);
    }

    #[test]
    fn wrong_key_is_auth_error() {
        let (ct, tag) = seal(&[1u8; 32], &[2u8; 12], b"", b"secret");
        assert_eq!(
            open(&[9u8; 32], &[2u8; 12], b"", &ct, &tag),
            Err(embark_format::Error::Auth)
        );
    }

    #[test]
    fn tampered_ciphertext_is_auth_error() {
        let (mut ct, tag) = seal(&[1u8; 32], &[2u8; 12], b"", b"secret");
        ct[0] ^= 0xff;
        assert_eq!(
            open(&[1u8; 32], &[2u8; 12], b"", &ct, &tag),
            Err(embark_format::Error::Auth)
        );
    }
}
