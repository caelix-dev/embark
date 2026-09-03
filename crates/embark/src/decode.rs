use alloc::borrow::Cow;
use alloc::vec::Vec;
use embark_format::{read_header, CodecId, CryptoId, Error};

pub(crate) fn decode(
    entry: &'static [u8],
    key: Option<[u8; 32]>,
) -> Result<Cow<'static, [u8]>, Error> {
    let header = read_header(entry)?;
    let payload = &entry[header.payload_offset..];

    // Decryption stage (only when the entry is encrypted).
    let plaintext: Cow<'static, [u8]> = match header.crypto {
        CryptoId::None => Cow::Borrowed(payload),
        CryptoId::ChaCha20Poly1305 => {
            #[cfg(feature = "encryption")]
            {
                let key = key.ok_or(Error::Auth)?;
                let nonce = header.nonce.ok_or(Error::Corrupt)?;
                let tag = header.tag.ok_or(Error::Corrupt)?;
                Cow::Owned(embark_crypt::open(&key, &nonce, payload, &tag)?)
            }
            #[cfg(not(feature = "encryption"))]
            {
                let _ = key;
                return Err(Error::UnknownCrypto(CryptoId::ChaCha20Poly1305.as_u8()));
            }
        }
    };

    // Decompression stage. For Store the plaintext is already the final bytes,
    // so we return it as-is (Borrowed for Store+plaintext, keeping the zero-copy
    // path; Owned if it was decrypted above).
    if header.codec == CodecId::Store {
        return Ok(plaintext);
    }
    let orig = header.orig_len as usize;
    let out: Vec<u8> = embark_codec::decompress(header.codec, &plaintext, orig)?;
    Ok(Cow::Owned(out))
}
