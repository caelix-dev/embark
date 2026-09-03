use crate::{CodecId, CryptoId, Error};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub struct Header {
    pub codec: CodecId,
    pub crypto: CryptoId,
    pub orig_len: u64,
    pub nonce: Option<[u8; 12]>,
    pub tag: Option<[u8; 16]>,
    pub payload_offset: usize,
}

#[cfg(feature = "enc")]
pub fn write_entry(
    out: &mut Vec<u8>,
    codec: CodecId,
    crypto: CryptoId,
    orig_len: u64,
    nonce_tag: Option<([u8; 12], [u8; 16])>,
    payload: &[u8],
) {
    out.push(codec.as_u8() | (crypto.as_u8() << 4));
    crate::write_varint(out, orig_len);
    if let Some((nonce, tag)) = nonce_tag {
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
    }
    out.extend_from_slice(payload);
}

#[cfg(feature = "dec")]
pub fn read_header(entry: &[u8]) -> Result<Header, Error> {
    let tag_byte = *entry.first().ok_or(Error::Truncated)?;
    let codec = CodecId::from_u8(tag_byte & 0x0f)?;
    let crypto = CryptoId::from_u8(tag_byte >> 4)?;
    let (orig_len, used) = crate::read_varint(&entry[1..])?;
    let mut offset = 1 + used;

    let (nonce, tag) = match crypto {
        CryptoId::None => (None, None),
        CryptoId::ChaCha20Poly1305 => {
            let end = offset + 28;
            if entry.len() < end {
                return Err(Error::Truncated);
            }
            let mut nonce = [0u8; 12];
            let mut tag = [0u8; 16];
            nonce.copy_from_slice(&entry[offset..offset + 12]);
            tag.copy_from_slice(&entry[offset + 12..end]);
            offset = end;
            (Some(nonce), Some(tag))
        }
    };

    Ok(Header { codec, crypto, orig_len, nonce, tag, payload_offset: offset })
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn plain_entry_roundtrip() {
        let mut buf = Vec::new();
        write_entry(&mut buf, CodecId::Store, CryptoId::None, 3, None, &[1, 2, 3]);
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
        write_entry(&mut buf, CodecId::Deflate, CryptoId::ChaCha20Poly1305, 100,
                    Some((nonce, tag)), &[0xAA, 0xBB]);
        let h = read_header(&buf).unwrap();
        assert_eq!(h.codec, CodecId::Deflate);
        assert_eq!(h.crypto, CryptoId::ChaCha20Poly1305);
        assert_eq!(h.orig_len, 100);
        assert_eq!(h.nonce, Some(nonce));
        assert_eq!(h.tag, Some(tag));
        assert_eq!(&buf[h.payload_offset..], &[0xAA, 0xBB]);
    }

    #[test]
    fn truncated_header_errors() {
        assert!(read_header(&[]).is_err());
    }
}
