/// Everything that can go wrong decoding an entry, shared by every crate in
/// the toolkit.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input ended in the middle of a header or payload. Distinct from
    /// [`Corrupt`](Error::Corrupt): the bytes present were well formed,
    /// there were simply not enough of them.
    Truncated,
    /// The entry's tag byte names a codec id that is either unassigned or
    /// not compiled into this build. Carries the id as read.
    UnknownCodec(u8),
    /// The entry's tag byte names a cipher id that is either unassigned or
    /// not compiled into this build. Carries the id as read.
    ///
    /// Also returned for [`CryptoId::None`](crate::CryptoId::None) where a
    /// real cipher was required, since nothing is ever sealed under it.
    UnknownCrypto(u8),
    /// The bytes are structurally invalid: a payload the named codec cannot
    /// decode, a varint longer than ten bytes, or output whose length
    /// disagrees with the length the header declared.
    ///
    /// A decoder also reports this rather than aborting when the header
    /// claims a length too large to allocate, so a hostile entry costs a
    /// failed reservation rather than the process.
    Corrupt,
    /// The AEAD tag does not authenticate the payload under the key and
    /// nonce supplied: a wrong key, a tampered entry, or both. The
    /// plaintext is never returned in this case, even partially.
    Auth,
    /// The decoded bytes were requested as a string but are not valid
    /// UTF-8.
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
