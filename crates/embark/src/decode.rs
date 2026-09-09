use alloc::borrow::Cow;
use alloc::vec::Vec;
use embark_format::{CodecId, CryptoId, Error, Result, read_header};

pub(crate) fn decode(entry: &'static [u8], key: Option<[u8; 32]>) -> Result<Cow<'static, [u8]>> {
    let header = read_header(entry)?;
    let payload = &entry[header.payload_offset..];

    // Decryption stage (only when the entry is encrypted). Both AEAD
    // ciphers dispatch through the same `embark_crypt::open`, keyed by
    // `header.crypto`; a cipher whose feature isn't enabled on `embark`
    // (e.g. `Aes256Gcm` without the `aes` feature) surfaces as
    // `Error::UnknownCrypto` from that dispatch, not a compile-time branch
    // here.
    let plaintext: Cow<'static, [u8]> = match header.crypto {
        CryptoId::None => Cow::Borrowed(payload),
        CryptoId::ChaCha20Poly1305 | CryptoId::Aes256Gcm => {
            #[cfg(feature = "encryption")]
            {
                let key = key.ok_or(Error::Auth)?;
                let nonce = header.nonce.ok_or(Error::Corrupt)?;
                let tag = header.tag.ok_or(Error::Corrupt)?;
                // The header rides along as associated data, so a codec, a
                // cipher or a length rewritten under this tag fails here as
                // `Auth` rather than reaching a decoder it was never meant
                // for.
                Cow::Owned(embark_crypt::open(
                    header.crypto,
                    &key,
                    &nonce,
                    &entry[..header.aad_len],
                    payload,
                    &tag,
                )?)
            }
            #[cfg(not(feature = "encryption"))]
            {
                let _ = key;
                return Err(Error::UnknownCrypto(header.crypto.as_u8()));
            }
        }
        // `CryptoId` is `#[non_exhaustive]`. A cipher added to the format
        // after this crate was compiled parses fine in the header but is one
        // this build cannot open, so say so; treating it as plaintext would
        // hand the caller ciphertext and call it the file.
        _ => return Err(Error::UnknownCrypto(header.crypto.as_u8())),
    };

    // The claim is a `u64` because the format is; on a 32-bit target a claim
    // above `usize::MAX` would wrap under `as`, and a wrapped claim is one a
    // decoder could accidentally satisfy.
    let orig = usize::try_from(header.orig_len).map_err(|_| Error::Corrupt)?;

    // Decompression stage. For Store the plaintext is already the final
    // bytes, so it is returned as-is (Borrowed for Store+plaintext, keeping
    // the zero-copy path; Owned if it was decrypted above). The claim is
    // still held to: it is what `size()` reports, and every other codec
    // treats a payload that disagrees with it as a damaged entry.
    if header.codec == CodecId::Store {
        if plaintext.len() != orig {
            return Err(Error::Corrupt);
        }
        return Ok(plaintext);
    }
    let out: Vec<u8> = embark_codec::decompress(header.codec, &plaintext, orig)?;
    Ok(Cow::Owned(out))
}
