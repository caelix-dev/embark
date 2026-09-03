use alloc::borrow::Cow;
use embark_format::read_header;

pub struct EmbeddedBytes {
    entry: &'static [u8],
}

impl EmbeddedBytes {
    pub const fn from_entry(entry: &'static [u8]) -> EmbeddedBytes {
        EmbeddedBytes { entry }
    }

    pub fn data(&self) -> Cow<'static, [u8]> {
        self.try_data()
            .expect("embark: embedded entry is malformed (this is a build-time bug)")
    }

    pub fn try_data(&self) -> Result<Cow<'static, [u8]>, embark_format::Error> {
        crate::decode::decode(self.entry, None)
    }

    pub fn size(&self) -> usize {
        read_header(self.entry)
            .map(|h| h.orig_len as usize)
            .unwrap_or(0)
    }
}
