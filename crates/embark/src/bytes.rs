use alloc::borrow::Cow;
use embark_format::read_header;

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
/// # }
/// ```
pub struct EmbeddedBytes {
    entry: &'static [u8],
}

impl EmbeddedBytes {
    /// Wraps a raw, already-encoded entry (header + payload) as produced by
    /// the build-time entry writer. Normally emitted by the `embed_bytes!`
    /// macro, not called directly.
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
    pub fn data(&self) -> Cow<'static, [u8]> {
        self.try_data()
            .expect("embark: embedded entry is malformed (this is a build-time bug)")
    }

    /// The fallible form of [`data`](EmbeddedBytes::data): decodes and
    /// returns the file contents, or an error if the compiled-in entry is
    /// malformed.
    pub fn try_data(&self) -> Result<Cow<'static, [u8]>, embark_format::Error> {
        crate::decode::decode(self.entry, None)
    }

    /// The original (decompressed) size of the file, in bytes.
    ///
    /// Reads the size out of the entry header without decompressing the
    /// payload; returns `0` if the header cannot be read.
    pub fn size(&self) -> usize {
        read_header(self.entry)
            .map(|h| h.orig_len as usize)
            .unwrap_or(0)
    }
}
