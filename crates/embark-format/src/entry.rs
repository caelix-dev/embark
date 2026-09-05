#[cfg(feature = "dec")]
use crate::Result;
use crate::{CodecId, CryptoId};
#[cfg(feature = "enc")]
use alloc::vec::Vec;

/// The decoded header of one on-binary entry, as returned by
/// [`read_header`].
///
/// `#[non_exhaustive]`: the on-binary layout is expected to grow (a
/// content hash, per-entry flags), so fields get added over time. Read the
/// fields you need; do not build one by hand or match it exhaustively.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The compression applied to the payload.
    pub codec: CodecId,
    /// The AEAD cipher the payload was sealed with, if any.
    pub crypto: CryptoId,
    /// Length of the file *before* compression and encryption, in bytes.
    ///
    /// Decoders use it to size the output buffer, so it comes from
    /// untrusted bytes and must be treated as a claim rather than a fact:
    /// reserve fallibly, and check the decoded length against it.
    pub orig_len: u64,
    /// The AEAD nonce, present exactly when `crypto` is not
    /// [`CryptoId::None`]. Stored in the clear, and unique per entry.
    pub nonce: Option<[u8; 12]>,
    /// The detached AEAD authentication tag, present under the same
    /// condition as `nonce`.
    pub tag: Option<[u8; 16]>,
    /// Offset into the entry at which the payload begins, that is the
    /// length of the header this `Header` was parsed from.
    pub payload_offset: usize,
    /// Length of the leading bytes -- the tag byte and the length varint --
    /// that a sealed entry's AEAD tag covers as associated data, so that the
    /// codec, cipher and claimed length cannot be rewritten under a tag that
    /// still verifies. `entry[..aad_len]` is what to hand the cipher.
    pub aad_len: usize,
}

/// Appends the part of the header every entry has -- the tag byte and the
/// length varint -- to `out`.
///
/// These are also the bytes a sealed entry's AEAD tag covers as associated
/// data, which is why they are reachable on their own: whoever seals a
/// payload writes them first, hands them to the cipher, and then writes the
/// entry with [`write_entry`], which produces the same bytes again.
#[cfg(feature = "enc")]
pub fn write_header(out: &mut Vec<u8>, codec: CodecId, crypto: CryptoId, orig_len: u64) {
    out.push(codec.as_u8() | (crypto.as_u8() << 4));
    crate::write_varint(out, orig_len);
}

/// Appends one complete entry -- header followed by `payload` -- to `out`.
///
/// `orig_len` is the length of the file before compression, and `nonce_tag`
/// carries the AEAD nonce and tag when the payload was sealed. Pass `None`
/// for a plaintext entry; `crypto` and `nonce_tag` have to agree, since
/// [`read_header`] decides whether to expect the 28 nonce-and-tag bytes from
/// `crypto` alone.
#[cfg(feature = "enc")]
pub fn write_entry(
    out: &mut Vec<u8>,
    codec: CodecId,
    crypto: CryptoId,
    orig_len: u64,
    nonce_tag: Option<([u8; 12], [u8; 16])>,
    payload: &[u8],
) {
    write_header(out, codec, crypto, orig_len);
    if let Some((nonce, tag)) = nonce_tag {
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
    }
    out.extend_from_slice(payload);
}

/// Parses the header at the front of `entry`.
///
/// Only the header is examined; the payload is left to the caller, which
/// finds it at [`Header::payload_offset`]. Nothing is copied out of the
/// payload and no allocation happens here, so this is cheap enough to call
/// just to read [`Header::orig_len`].
///
/// # Errors
///
/// Returns [`Error::Truncated`](crate::Error::Truncated) if `entry` is
/// shorter than the header it declares, [`Error::Corrupt`](crate::Error::Corrupt)
/// if the length varint is malformed, and
/// [`Error::UnknownCodec`](crate::Error::UnknownCodec) or
/// [`Error::UnknownCrypto`](crate::Error::UnknownCrypto) if the tag byte
/// names an unassigned id.
#[cfg(feature = "dec")]
pub fn read_header(entry: &[u8]) -> Result<Header> {
    let tag_byte = *entry.first().ok_or(crate::Error::Truncated)?;
    let codec = CodecId::from_u8(tag_byte & 0x0f)?;
    let crypto = CryptoId::from_u8(tag_byte >> 4)?;
    let (orig_len, used) = crate::read_varint(&entry[1..])?;
    let mut offset = 1 + used;

    let (nonce, tag) = match crypto {
        CryptoId::None => (None, None),
        // Both AEAD ciphers share the same 12-byte nonce / 16-byte tag shape.
        CryptoId::ChaCha20Poly1305 | CryptoId::Aes256Gcm => {
            let end = offset + 28;
            if entry.len() < end {
                return Err(crate::Error::Truncated);
            }
            let mut nonce = [0u8; 12];
            let mut tag = [0u8; 16];
            nonce.copy_from_slice(&entry[offset..offset + 12]);
            tag.copy_from_slice(&entry[offset + 12..end]);
            offset = end;
            (Some(nonce), Some(tag))
        }
    };

    Ok(Header {
        codec,
        crypto,
        orig_len,
        nonce,
        tag,
        payload_offset: offset,
        aad_len: 1 + used,
    })
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn plain_entry_roundtrip() {
        let mut buf = Vec::new();
        write_entry(
            &mut buf,
            CodecId::Store,
            CryptoId::None,
            3,
            None,
            &[1, 2, 3],
        );
        let h = read_header(&buf).unwrap();
        assert_eq!(h.codec, CodecId::Store);
        assert_eq!(h.crypto, CryptoId::None);
        assert_eq!(h.orig_len, 3);
        assert!(h.nonce.is_none());
        assert_eq!(&buf[h.payload_offset..], &[1, 2, 3]);
    }

    #[test]
    fn encrypted_entry_roundtrip() {
        let nonce = [9u8; 12];
        let tag = [7u8; 16];
        let mut buf = Vec::new();
        write_entry(
            &mut buf,
            CodecId::Deflate,
            CryptoId::ChaCha20Poly1305,
            100,
            Some((nonce, tag)),
            &[0xAA, 0xBB],
        );
        let h = read_header(&buf).unwrap();
        assert_eq!(h.codec, CodecId::Deflate);
        assert_eq!(h.crypto, CryptoId::ChaCha20Poly1305);
        assert_eq!(h.orig_len, 100);
        assert_eq!(h.nonce, Some(nonce));
        assert_eq!(h.tag, Some(tag));
        assert_eq!(&buf[h.payload_offset..], &[0xAA, 0xBB]);
    }

    #[test]
    fn aes_encrypted_entry_roundtrip() {
        let nonce = [3u8; 12];
        let tag = [4u8; 16];
        let mut buf = Vec::new();
        write_entry(
            &mut buf,
            CodecId::Store,
            CryptoId::Aes256Gcm,
            5,
            Some((nonce, tag)),
            &[0xCC, 0xDD],
        );
        let h = read_header(&buf).unwrap();
        assert_eq!(h.crypto, CryptoId::Aes256Gcm);
        assert_eq!(h.nonce, Some(nonce));
        assert_eq!(h.tag, Some(tag));
        assert_eq!(&buf[h.payload_offset..], &[0xCC, 0xDD]);
    }

    #[test]
    fn truncated_header_errors() {
        assert!(read_header(&[]).is_err());
    }
}
