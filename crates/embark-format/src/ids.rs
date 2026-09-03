use crate::{Error, Result};

/// Names the compression applied to an entry's payload.
///
/// Stored in the low nibble of an entry's first byte, so the format admits
/// at most sixteen codecs and every id below is permanently assigned. Which
/// of them a given build can actually *use* is a separate question, decided
/// by `embark-codec`'s cargo features: an id naming a codec that was not
/// compiled in parses fine here and fails at decompression time with
/// [`Error::UnknownCodec`].
///
/// `#[non_exhaustive]`: this list has already grown from two variants to
/// six and the format has room for ten more, so match it with a wildcard
/// arm that reports [`Error::UnknownCodec`] rather than one that silently
/// picks a default.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecId {
    /// No compression: the payload is the original bytes verbatim.
    ///
    /// Also the fallback the build-time encoders pick whenever the chosen
    /// codec would have made the file larger.
    Store = 0,
    /// Raw DEFLATE (RFC 1951), with no zlib or gzip wrapper.
    Deflate = 1,
    /// LZ4 block format, without the frame header.
    Lz4 = 2,
    /// Snappy block format, including its length preamble.
    Snappy = 3,
    /// Zstandard, as a complete single-frame stream.
    Zstd = 4,
    /// LZMA1 in the `.lzma` "alone" container, header included.
    Lzma = 5,
}

impl CodecId {
    /// The byte written to the low nibble of an entry's tag byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Reads a codec id back out of an entry's tag byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownCodec`] if `v` is not an assigned id. Entry
    /// bytes are untrusted input, so this is an ordinary runtime outcome
    /// rather than a sign of a bug.
    pub fn from_u8(v: u8) -> Result<CodecId> {
        match v {
            0 => Ok(CodecId::Store),
            1 => Ok(CodecId::Deflate),
            2 => Ok(CodecId::Lz4),
            3 => Ok(CodecId::Snappy),
            4 => Ok(CodecId::Zstd),
            5 => Ok(CodecId::Lzma),
            other => Err(Error::UnknownCodec(other)),
        }
    }
}

/// Names the AEAD cipher an entry's payload was sealed with, if any.
///
/// Stored in the high nibble of an entry's first byte. Any id other than
/// [`None`](CryptoId::None) also means the header carries a 12-byte nonce
/// and a 16-byte authentication tag between the length varint and the
/// payload; both built-in ciphers share that shape.
///
/// `#[non_exhaustive]`: this list has already grown from two variants to
/// three, so match it with a wildcard arm that reports
/// [`Error::UnknownCrypto`] rather than one that treats an unrecognized
/// cipher as no cipher at all.
#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoId {
    /// The payload is not encrypted, and the header carries no nonce or tag.
    None = 0,
    /// ChaCha20-Poly1305 (RFC 8439), the default cipher.
    ChaCha20Poly1305 = 1,
    /// AES-256-GCM, available where hardware acceleration makes it the
    /// faster choice.
    Aes256Gcm = 2,
}

impl CryptoId {
    /// The byte written to the high nibble of an entry's tag byte.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Reads a crypto id back out of an entry's tag byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownCrypto`] if `v` is not an assigned id. Entry
    /// bytes are untrusted input, so this is an ordinary runtime outcome
    /// rather than a sign of a bug.
    pub fn from_u8(v: u8) -> Result<CryptoId> {
        match v {
            0 => Ok(CryptoId::None),
            1 => Ok(CryptoId::ChaCha20Poly1305),
            2 => Ok(CryptoId::Aes256Gcm),
            other => Err(Error::UnknownCrypto(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrip() {
        for id in [
            CodecId::Store,
            CodecId::Deflate,
            CodecId::Lz4,
            CodecId::Snappy,
            CodecId::Zstd,
            CodecId::Lzma,
        ] {
            assert_eq!(CodecId::from_u8(id.as_u8()).unwrap(), id);
        }
        assert!(matches!(
            CodecId::from_u8(9),
            Err(crate::Error::UnknownCodec(9))
        ));
    }

    #[test]
    fn crypto_roundtrip() {
        assert_eq!(CryptoId::from_u8(1).unwrap(), CryptoId::ChaCha20Poly1305);
        assert_eq!(CryptoId::from_u8(2).unwrap(), CryptoId::Aes256Gcm);
        assert!(matches!(
            CryptoId::from_u8(7),
            Err(crate::Error::UnknownCrypto(7))
        ));
    }
}
