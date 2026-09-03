use alloc::borrow::Cow;

/// One compiled-in `(path, entry)` pair in a `#[derive(Embed)]` manifest.
///
/// Built entirely by the derive macro at build time; not constructed by
/// hand. `path` is the file's path relative to the folder given in
/// `#[embark(folder = "...")]`, and `entry` is the encoded (header +
/// payload) bytes for the file.
pub struct Manifest {
    pub path: &'static str,
    pub entry: &'static [u8],
}

/// Implemented by types produced with `#[derive(Embed)]`, giving directory
/// access to the files embedded from `#[embark(folder = "...")]`.
///
/// # Example
///
/// ```ignore
/// #[derive(embark::Embed)]
/// #[embark(folder = "assets")]
/// struct Assets;
///
/// let file = Assets::get("logo.png").unwrap();
/// let data = file.data();
/// for path in Assets::iter() { /* ... */ }
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
    pub fn data(&self) -> Cow<'static, [u8]> {
        self.try_data()
            .expect("embark: embedded entry is malformed (build-time bug)")
    }

    /// The fallible form of [`data`](EmbeddedFile::data): decodes and
    /// returns the file contents, or an error if the compiled-in entry is
    /// malformed.
    pub fn try_data(&self) -> Result<Cow<'static, [u8]>, embark_format::Error> {
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
    /// payload; returns `0` if the header cannot be read. For a
    /// `#[embark(dev)]` file read live from disk, this is the size of the
    /// bytes actually read.
    pub fn size(&self) -> usize {
        match &self.source {
            Source::Static(entry) => embark_format::read_header(entry)
                .map(|h| h.orig_len as usize)
                .unwrap_or(0),
            #[cfg(feature = "std")]
            Source::Owned(bytes) => bytes.len(),
        }
    }

    /// The file's path, relative to the folder given in
    /// `#[embark(folder = "...")]`.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Iterator over the paths of every file embedded in a `#[derive(Embed)]`
/// manifest, in sorted order. Returned by [`Embed::iter`] / [`entries`].
pub struct Entries {
    inner: core::slice::Iter<'static, Manifest>,
}

impl Iterator for Entries {
    type Item = Cow<'static, str>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|m| Cow::Borrowed(m.path))
    }
}

/// Looks up an unencrypted, compiled-in file by path (binary search) in a
/// `#[derive(Embed)]` manifest. Used internally by the derive's generated
/// `get()`; not normally called directly.
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
pub fn __dev_file(folder_abs: &str, path: &str) -> Option<EmbeddedFile> {
    let full = std::path::Path::new(folder_abs).join(path);
    let bytes = std::fs::read(full).ok()?;
    Some(EmbeddedFile {
        source: Source::Owned(bytes),
        path: Cow::Owned(path.to_string()),
        recon: None,
    })
}
