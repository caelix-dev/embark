#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    UnknownCodec(u8),
    UnknownCrypto(u8),
    Corrupt,
    Auth,
    Utf8,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => f.write_str("input ended before a complete entry"),
            Error::UnknownCodec(v) => write!(f, "unknown codec id {v}"),
            Error::UnknownCrypto(v) => write!(f, "unknown crypto id {v}"),
            Error::Corrupt => f.write_str("malformed compressed or encoded data"),
            Error::Auth => f.write_str("authentication tag mismatch"),
            Error::Utf8 => f.write_str("decoded bytes are not valid UTF-8"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
