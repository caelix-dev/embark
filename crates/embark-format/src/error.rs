/// Everything that can go wrong decoding an entry, shared by every crate in
/// the toolkit.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    UnknownCodec(u8),
    UnknownCrypto(u8),
    Corrupt,
    Auth,
    Utf8 {
        /// How many leading bytes were valid UTF-8 before the bad sequence,
        /// as reported by `core::str::Utf8Error::valid_up_to`.
        valid_up_to: usize,
    },
}

/// The toolkit's `Result`, defaulting its error type to [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated => f.write_str("input ended before a complete entry"),
            Error::UnknownCodec(v) => write!(f, "unknown codec id {v}"),
            Error::UnknownCrypto(v) => write!(f, "unknown crypto id {v}"),
            Error::Corrupt => f.write_str("malformed compressed or encoded data"),
            Error::Auth => f.write_str("authentication tag mismatch"),
            Error::Utf8 { valid_up_to } => {
                write!(f, "decoded bytes are not valid UTF-8 at byte {valid_up_to}")
            }
        }
    }
}

// `core::error::Error` is `std::error::Error` -- std re-exports it -- so this
// one impl covers both, no_std builds included.
impl core::error::Error for Error {}
