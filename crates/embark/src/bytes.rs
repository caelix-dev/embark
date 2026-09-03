use alloc::borrow::Cow;
use embark_format::{Result, read_header};

/// A single, unencrypted embedded file, produced by
/// [`embed_bytes!`](crate::embed_bytes) with a `codec = ...` argument.
///
/// Wraps a compiled-in, possibly compressed entry and decompresses it lazily
/// on first access via [`data`](EmbeddedBytes::data). For an `embed_bytes!`
/// call with no `codec` argument, the macro instead expands to a plain
/// `include_bytes!` (a `&'static [u8]`), not this type — `EmbeddedBytes` only
/// shows up once compression is in play.
///
/// # Example
///
/// Both forms, against this crate's own `examples/assets`:
///
/// ```
/// # #[cfg(all(feature = "derive", feature = "deflate", feature = "std"))] {
/// // No codec: a zero-cost `include_bytes!`, so the type is `&[u8]`.
/// static RAW: &[u8] = embark::embed_bytes!("examples/assets/hello.txt");
/// assert_eq!(RAW, b"hello embark");
///
/// // With a codec: an `EmbeddedBytes`, decompressed lazily on first access.
/// static TEXT: embark::EmbeddedBytes =
///     embark::embed_bytes!("examples/assets/lipsum.txt", codec = deflate);
/// let data = TEXT.data();
/// assert!(data.starts_with(b"Embark packs your files"));
///
/// // `codec` takes a bare identifier, never a string. `auto` keeps the
/// // smallest output among the codecs enabled on `embark`.
/// static BEST: embark::EmbeddedBytes =
///     embark::embed_bytes!("examples/assets/lipsum.txt", codec = auto);
/// assert_eq!(BEST.data(), data);
/// # }
/// ```
pub struct EmbeddedBytes {
    entry: &'static [u8],
}

// An embedded file is routinely megabytes; a derived `Debug` would print
// every byte of it. Report the decoded size instead.
impl core::fmt::Debug for EmbeddedBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EmbeddedBytes")
            .field("size", &self.size())
            .finish_non_exhaustive()
    }
}

impl EmbeddedBytes {
    /// Wraps a raw, already-encoded entry (header + payload) as produced by
    /// the build-time entry writer. Normally emitted by the `embed_bytes!`
    /// macro, not called directly.
    #[must_use]
    pub const fn from_entry(entry: &'static [u8]) -> EmbeddedBytes {
        EmbeddedBytes { entry }
    }

    /// Returns the decompressed file contents.
    ///
    /// Infallible by construction: the entry was built and validated at
    /// compile time by the macro that produced this `EmbeddedBytes`, so
    /// decoding it back out cannot fail in a correctly built binary.
    ///
    /// # Panics
    ///
    /// Panics only on internal corruption of the compiled-in entry (a
    /// build-time bug, not something a caller can trigger at runtime). Use
    /// [`try_data`](EmbeddedBytes::try_data) for the fallible form.
    #[must_use]
    pub fn data(&self) -> Cow<'static, [u8]> {
        self.try_data()
            .expect("embark: embedded entry is malformed (this is a build-time bug)")
    }

    /// The fallible form of [`data`](EmbeddedBytes::data): decodes and
    /// returns the file contents, or an error if the compiled-in entry is
    /// malformed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`](crate::Error::Truncated) or
    /// [`Error::Corrupt`](crate::Error::Corrupt) if the compiled-in header or
    /// payload is damaged, and
    /// [`Error::UnknownCodec`](crate::Error::UnknownCodec) if the entry names
    /// a codec this build did not compile in. Neither is reachable from a
    /// binary these macros built, which is why [`data`](EmbeddedBytes::data)
    /// exists.
    pub fn try_data(&self) -> Result<Cow<'static, [u8]>> {
        crate::decode::decode(self.entry, None)
    }

    /// The original (decompressed) size of the file, in bytes.
    ///
    /// Reads the size out of the entry header without decompressing the
    /// payload. `None` means the header could not be read, or records a
    /// length this platform's `usize` cannot hold — distinct from
    /// `Some(0)`, which is a genuinely empty file.
    #[must_use]
    pub fn size(&self) -> Option<usize> {
        let header = read_header(self.entry).ok()?;
        usize::try_from(header.orig_len).ok()
    }
}
