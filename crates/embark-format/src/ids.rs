use crate::Error;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecId {
    Store = 0,
    Deflate = 1,
    Lz4 = 2,
    Snappy = 3,
    Zstd = 4,
    Lzma = 5,
}

impl CodecId {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Result<CodecId, Error> {
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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoId {
    None = 0,
    ChaCha20Poly1305 = 1,
}

impl CryptoId {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Result<CryptoId, Error> {
        match v {
            0 => Ok(CryptoId::None),
            1 => Ok(CryptoId::ChaCha20Poly1305),
            other => Err(Error::UnknownCrypto(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrip() {
        for id in [CodecId::Store, CodecId::Deflate, CodecId::Lz4, CodecId::Snappy, CodecId::Zstd, CodecId::Lzma] {
            assert_eq!(CodecId::from_u8(id.as_u8()).unwrap(), id);
        }
        assert!(matches!(CodecId::from_u8(9), Err(crate::Error::UnknownCodec(9))));
    }

    #[test]
    fn crypto_roundtrip() {
        assert_eq!(CryptoId::from_u8(1).unwrap(), CryptoId::ChaCha20Poly1305);
        assert!(matches!(CryptoId::from_u8(7), Err(crate::Error::UnknownCrypto(7))));
    }
}
