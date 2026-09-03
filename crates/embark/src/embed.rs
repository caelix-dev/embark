use alloc::borrow::Cow;

pub struct Manifest {
    pub path: &'static str,
    pub entry: &'static [u8],
}

pub trait Embed {
    fn get(path: &str) -> Option<EmbeddedFile>;
    fn iter() -> Entries;
}

pub struct EmbeddedFile {
    entry: &'static [u8],
    path: &'static str,
    key: Option<([u8; 32], [u8; 32])>,
}

impl EmbeddedFile {
    pub fn data(&self) -> Cow<'static, [u8]> {
        self.try_data()
            .expect("embark: embedded entry is malformed (build-time bug)")
    }

    pub fn try_data(&self) -> Result<Cow<'static, [u8]>, embark_format::Error> {
        let key = self
            .key
            .map(|(masked, mask)| embark_crypt_xor(masked, mask));
        crate::decode::decode(self.entry, key)
    }

    pub fn size(&self) -> usize {
        embark_format::read_header(self.entry)
            .map(|h| h.orig_len as usize)
            .unwrap_or(0)
    }

    pub fn path(&self) -> &'static str {
        self.path
    }
}

#[cfg(feature = "encryption")]
fn embark_crypt_xor(masked: [u8; 32], mask: [u8; 32]) -> [u8; 32] {
    embark_crypt::xor32(&masked, &mask)
}

#[cfg(not(feature = "encryption"))]
fn embark_crypt_xor(_masked: [u8; 32], _mask: [u8; 32]) -> [u8; 32] {
    // Unreachable without the encryption feature; the derive never sets a key.
    [0u8; 32]
}

pub struct Entries {
    inner: core::slice::Iter<'static, Manifest>,
}

impl Iterator for Entries {
    type Item = Cow<'static, str>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|m| Cow::Borrowed(m.path))
    }
}

pub fn lookup(manifest: &'static [Manifest], path: &str) -> Option<EmbeddedFile> {
    let idx = manifest.binary_search_by(|m| m.path.cmp(path)).ok()?;
    let m = &manifest[idx];
    Some(EmbeddedFile {
        entry: m.entry,
        path: m.path,
        key: None,
    })
}

pub fn entries(manifest: &'static [Manifest]) -> Entries {
    Entries {
        inner: manifest.iter(),
    }
}

#[cfg(feature = "encryption")]
pub fn lookup_encrypted(
    manifest: &'static [Manifest],
    path: &str,
    masked: [u8; 32],
    mask: [u8; 32],
) -> Option<EmbeddedFile> {
    let idx = manifest.binary_search_by(|m| m.path.cmp(path)).ok()?;
    let m = &manifest[idx];
    Some(EmbeddedFile {
        entry: m.entry,
        path: m.path,
        key: Some((masked, mask)),
    })
}
