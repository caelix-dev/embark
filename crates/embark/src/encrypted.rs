#![cfg(feature = "encryption")]
use alloc::string::String;
use alloc::vec::Vec;
use embark_format::Error;

enum EmbeddedKey {
    Masked([u8; 32], [u8; 32]),
    Runtime,
}

pub struct EncryptedFile {
    entry: &'static [u8],
    key: EmbeddedKey,
}

impl EncryptedFile {
    pub const fn with_embedded_key(
        entry: &'static [u8],
        masked: [u8; 32],
        mask: [u8; 32],
    ) -> EncryptedFile {
        EncryptedFile {
            entry,
            key: EmbeddedKey::Masked(masked, mask),
        }
    }

    pub const fn with_runtime_key(entry: &'static [u8]) -> EncryptedFile {
        EncryptedFile {
            entry,
            key: EmbeddedKey::Runtime,
        }
    }

    pub fn decrypt(&self) -> Vec<u8> {
        self.try_decrypt()
            .expect("embark: embedded key decrypt failed (build-time bug)")
    }

    pub fn decrypt_str(&self) -> Result<String, Error> {
        String::from_utf8(self.try_decrypt()?).map_err(|_| Error::Utf8)
    }

    pub fn decrypt_with(&self, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        Ok(crate::decode::decode(self.entry, Some(*key))?.into_owned())
    }

    fn try_decrypt(&self) -> Result<Vec<u8>, Error> {
        let key = match self.key {
            EmbeddedKey::Masked(masked, mask) => embark_crypt::xor32(&masked, &mask),
            EmbeddedKey::Runtime => return Err(Error::Auth),
        };
        Ok(crate::decode::decode(self.entry, Some(key))?.into_owned())
    }
}
