use alloc::borrow::Cow;
use embark_format::Result;

/// One compiled-in `(path, entry)` pair in a `#[derive(Embed)]` manifest.
///
/// Built entirely by the derive macro at build time; not constructed by
/// hand. `path` is the file's path relative to the folder given in
/// `#[embark(folder = "...")]`, and `entry` is the encoded (header +
/// payload) bytes for the file.
///
/// `#[non_exhaustive]`: fields are expected to be added (a content hash, a
/// per-file codec override), so build one with [`Manifest::new`] rather
/// than a struct literal. Reading the fields you need stays fine.
#[non_exhaustive]
pub struct Manifest {
    /// The file's path relative to the embedded folder, always with `/`
    /// separators regardless of the platform the build ran on.
    pub path: &'static str,
    /// The encoded entry -- header followed by the compressed and possibly
    /// encrypted payload -- exactly as `embark-format` wrote it at build
    /// time.
    pub entry: &'static [u8],
}

// A manifest holds every embedded file, so a derived `Debug` would print the
// whole asset folder byte by byte. Report the entry's size instead.
impl core::fmt::Debug for Manifest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Manifest")
            .field("path", &self.path)
            .field("entry_len", &self.entry.len())
            .finish()
    }
}

impl Manifest {
    /// Builds one manifest entry. `const`, so it can be used in the `static`
    /// manifest the derive macro emits.
    ///
    /// The only way to build one: `Manifest` is `#[non_exhaustive]`, so a
    /// struct literal will not compile from another crate. Fields added
    /// later take a default here rather than breaking every caller.
    #[must_use]
    pub const fn new(path: &'static str, entry: &'static [u8]) -> Manifest {
        Manifest { path, entry }
    }
}

/// Implemented by types produced with `#[derive(Embed)]`, giving directory
/// access to the files embedded from `#[embark(folder = "...")]`.
///
/// # Example
///
/// Embedding this crate's own `examples/assets/docs` folder, which holds
/// `about.txt` and `license.txt`:
///
/// ```
/// # #[cfg(all(feature = "derive", feature = "std"))] {
/// use embark::Embed as _;
///
/// #[derive(embark::Embed)]
/// #[embark(folder = "examples/assets/docs")]
/// struct Docs;
///
/// let file = Docs::get("license.txt").unwrap();
/// assert!(file.data().starts_with(b"MIT"));
/// assert_eq!(file.path(), "license.txt");
///
/// let paths: Vec<_> = Docs::iter().collect();
/// assert_eq!(paths, ["about.txt", "license.txt"]);
///
/// assert!(Docs::get("nope.txt").is_none());
/// # }
/// ```
pub trait Embed {
    /// Looks up a single file by its path relative to the embedded folder.
    /// Returns `None` if no embedded file has that path.
    fn get(path: &str) -> Option<EmbeddedFile>;
    /// Iterates the paths of every embedded file, in sorted order.
    fn iter() -> Entries;
}

enum Source {
    Static(&'static [u8]),
    #[cfg(feature = "std")]
    Owned(alloc::vec::Vec<u8>),
}

/// A single file looked up from a `#[derive(Embed)]` type via
/// [`Embed::get`], obtained via [`lookup`] / [`lookup_encrypted`], or (in
/// debug builds, with `#[embark(dev)]`) read live from disk.
pub struct EmbeddedFile {
    source: Source,
    path: Cow<'static, str>,
    // For an encrypted entry, the per-build-randomized reconstruction function
    // that rebuilds the shared build-time key; `None` for plain entries.
    recon: Option<fn() -> [u8; 32]>,
}

// Neither the file's bytes nor the address of the key-reconstruction routine
// belongs in a debug line, so this reports the shape of the handle only.
impl core::fmt::Debug for EmbeddedFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EmbeddedFile")
            .field("path", &self.path())
            .field("size", &self.size())
            .finish_non_exhaustive()
    }
}

impl EmbeddedFile {
    /// Returns the file's decompressed (and, if applicable, decrypted)
    /// contents.
    ///
    /// Infallible by construction for the compiled-in case: the entry was
    /// built and validated at compile time, so decoding it back out cannot
    /// fail in a correctly built binary. In debug builds under
    /// `#[embark(dev)]`, the file is instead read straight off disk each
    /// time and returned as-is.
    ///
    /// # Panics
    ///
    /// Panics only on internal corruption of a compiled-in entry (a
    /// build-time bug, not something a caller can trigger at runtime). Use
    /// [`try_data`](EmbeddedFile::try_data) for the fallible form.
    #[must_use]
    pub fn data(&self) -> Cow<'static, [u8]> {
        self.try_data()
            .expect("embark: embedded entry is malformed (build-time bug)")
    }

    /// The fallible form of [`data`](EmbeddedFile::data): decodes and
    /// returns the file contents, or an error if the compiled-in entry is
    /// malformed.
    ///
    /// # Errors
    ///
    /// Returns whatever the decode path reports for a malformed entry:
    /// [`Error::Truncated`](crate::Error::Truncated) or
    /// [`Error::Corrupt`](crate::Error::Corrupt) for a damaged header or
    /// payload, [`Error::UnknownCodec`](crate::Error::UnknownCodec) or
    /// [`Error::UnknownCrypto`](crate::Error::UnknownCrypto) when the entry
    /// names a codec or cipher this build did not compile in, and
    /// [`Error::Auth`](crate::Error::Auth) if an encrypted entry fails to
    /// authenticate. In a binary built by these macros none of these can
    /// happen, which is why [`data`](EmbeddedFile::data) exists.
    pub fn try_data(&self) -> Result<Cow<'static, [u8]>> {
        match &self.source {
            Source::Static(entry) => {
                let key = self.recon.map(|recon| recon());
                crate::decode::decode(entry, key)
            }
            #[cfg(feature = "std")]
            Source::Owned(bytes) => Ok(Cow::Owned(bytes.clone())),
        }
    }

    /// The original (decompressed) size of the file, in bytes.
    ///
    /// Reads the size out of the entry header without decompressing the
    /// payload. `None` means the header could not be read, or records a
    /// length this platform's `usize` cannot hold — distinct from
    /// `Some(0)`, which is a genuinely empty file. For a `#[embark(dev)]`
    /// file read live from disk, this is the size of the bytes actually
    /// read.
    #[must_use]
    pub fn size(&self) -> Option<usize> {
        match &self.source {
            Source::Static(entry) => {
                let header = embark_format::read_header(entry).ok()?;
                usize::try_from(header.orig_len).ok()
            }
            #[cfg(feature = "std")]
            Source::Owned(bytes) => Some(bytes.len()),
        }
    }

    /// The file's path, relative to the folder given in
    /// `#[embark(folder = "...")]`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Iterator over the paths of every file embedded in a `#[derive(Embed)]`
/// manifest, in sorted order. Returned by [`Embed::iter`] / [`entries`].
///
/// Yields `&'static str`: the paths are compiled into the binary, so they
/// outlive the iterator and never need to be owned.
pub struct Entries {
    inner: core::slice::Iter<'static, Manifest>,
}

// The inner slice iterator would print every remaining `Manifest`; a count
// is what a debug line actually wants here.
impl core::fmt::Debug for Entries {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entries")
            .field("remaining", &self.inner.len())
            .finish()
    }
}

impl Iterator for Entries {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|m| m.path)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for Entries {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|m| m.path)
    }
}

impl ExactSizeIterator for Entries {
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for Entries {}

/// Looks up an unencrypted, compiled-in file by path (binary search) in a
/// `#[derive(Embed)]` manifest. Used internally by the derive's generated
/// `get()`; not normally called directly.
#[must_use]
pub fn lookup(manifest: &'static [Manifest], path: &str) -> Option<EmbeddedFile> {
    let idx = manifest.binary_search_by(|m| m.path.cmp(path)).ok()?;
    let m = &manifest[idx];
    Some(EmbeddedFile {
        source: Source::Static(m.entry),
        path: Cow::Borrowed(m.path),
        recon: None,
    })
}

/// Iterates every path in a `#[derive(Embed)]` manifest, in sorted order.
/// Used internally by the derive's generated `iter()`; not normally called
/// directly.
#[must_use]
pub fn entries(manifest: &'static [Manifest]) -> Entries {
    Entries {
        inner: manifest.iter(),
    }
}

/// Looks up a build-time-encrypted, compiled-in file by path (binary
/// search) in a `#[derive(Embed)]` manifest, attaching its per-build
/// key-reconstruction function. Used internally by the derive's generated
/// `get()` when `#[embark(encrypt)]` is set; not normally called directly.
/// See [`EncryptedFile`](crate::EncryptedFile) for why the build-time key is
/// obfuscation, not security.
#[cfg(feature = "encryption")]
pub fn lookup_encrypted(
    manifest: &'static [Manifest],
    path: &str,
    recon: fn() -> [u8; 32],
) -> Option<EmbeddedFile> {
    let idx = manifest.binary_search_by(|m| m.path.cmp(path)).ok()?;
    let m = &manifest[idx];
    Some(EmbeddedFile {
        source: Source::Static(m.entry),
        path: Cow::Borrowed(m.path),
        recon: Some(recon),
    })
}

/// Dev-mode escape hatch used by `#[embark(dev)]`: read the file straight off
/// disk (relative to the folder the derive was pointed at) instead of the
/// embedded, compiled-in copy. Only ever called from a `#[cfg(debug_assertions)]`
/// branch the derive emits, so release builds never reference it.
#[cfg(feature = "std")]
#[doc(hidden)]
#[must_use]
pub fn __dev_file(folder_abs: &str, path: &str) -> Option<EmbeddedFile> {
    let full = std::path::Path::new(folder_abs).join(path);
    let bytes = std::fs::read(full).ok()?;
    Some(EmbeddedFile {
        source: Source::Owned(bytes),
        path: Cow::Owned(path.to_string()),
        recon: None,
    })
}
