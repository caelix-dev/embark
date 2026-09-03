use crate::build;
use embark_crypt::{gen_key_nonce, seal};
use embark_format::{CodecId, CryptoId, write_entry};
use proc_macro2::Span;

pub(crate) enum KeyMode {
    BuildTime,
    /// Carries the span of the `key = runtime` argument that asked for this
    /// mode, so a missing or malformed `EMBARK_KEY` points the caret there
    /// rather than at the path literal.
    Runtime(Span),
}

pub(crate) struct Sealed {
    pub entry: Vec<u8>,
    // The build-time key for embedded-key mode, from which the caller emits a
    // randomized reconstruction function; `None` in runtime-key mode.
    pub key: Option<[u8; 32]>,
}

// Hand-written rather than derived: `key` is live key material, and a derived
// `Debug` would print it into the build log of anyone who ever formats this
// while debugging the macro.
impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("entry_len", &self.entry.len())
            .field("key", &self.key.map(|_| "[redacted]"))
            .finish()
    }
}

/// Seals `data`, which `shown` names and `span` points at for diagnostics.
///
/// # Errors
///
/// Fails if the compressed payload does not decode back to `data` (see
/// [`build::compress_verified`]), or, in [`KeyMode::Runtime`] only, if
/// `EMBARK_KEY` is missing or malformed.
pub(crate) fn seal_file(
    data: &[u8],
    codec: CodecId,
    crypto: CryptoId,
    mode: KeyMode,
    shown: &str,
    span: Span,
) -> syn::Result<Sealed> {
    // Compress first (never grow, and check it decodes), then encrypt the
    // compressed payload. Only the compression stage is verified: a
    // decrypt-then-decompress round trip would test the AEAD crates instead,
    // and there is no key to decrypt with in `KeyMode::Runtime` anyway.
    let (codec, compressed) = build::compress_verified(codec, data, shown, span)?;

    let (key, nonce, embedded_key) = match mode {
        KeyMode::BuildTime => {
            let (key, nonce) = gen_key_nonce();
            (key, nonce, Some(key))
        }
        KeyMode::Runtime(key_span) => {
            let key = env_key().map_err(|msg| syn::Error::new(key_span, msg))?;
            let (_, nonce) = gen_key_nonce();
            (key, nonce, None)
        }
    };

    let (ct, tag) = seal(crypto, &key, &nonce, &compressed);
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        codec,
        crypto,
        data.len() as u64,
        Some((nonce, tag)),
        &ct,
    );
    Ok(Sealed {
        entry,
        key: embedded_key,
    })
}

fn env_key() -> Result<[u8; 32], String> {
    let raw = std::env::var("EMBARK_KEY").map_err(|_| {
        "embark: `key = runtime` needs the EMBARK_KEY environment variable (64 hex characters, a 32-byte key) set at build time"
            .to_string()
    })?;
    let hex = raw.trim();
    // Checking for ASCII hex up front also keeps the byte-pair slicing below
    // off a multi-byte char boundary.
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "embark: EMBARK_KEY must be exactly 64 hex characters (a 32-byte key), got {} characters",
            hex.chars().count()
        ));
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("embark: EMBARK_KEY is not valid hex: {e}"))?;
    }
    Ok(key)
}

// Used by derive(Embed) with #[embark(encrypt)]: every file in the folder is
// sealed under one shared build-time key (obfuscated via a per-build
// reconstruction function the derive emits). Returns just the entry bytes.
pub(crate) fn seal_with_key(
    data: &[u8],
    codec: CodecId,
    crypto: CryptoId,
    key: [u8; 32],
    shown: &str,
    span: Span,
) -> syn::Result<Vec<u8>> {
    let (codec, compressed) = build::compress_verified(codec, data, shown, span)?;
    let (_, nonce) = gen_key_nonce(); // fresh per-file nonce
    let (ct, tag) = seal(crypto, &key, &nonce, &compressed);
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        codec,
        crypto,
        data.len() as u64,
        Some((nonce, tag)),
        &ct,
    );
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_print_the_key() {
        let key = [0x7Fu8; 32];
        let sealed = Sealed {
            entry: vec![1, 2, 3],
            key: Some(key),
        };
        let shown = format!("{sealed:?}");
        assert!(shown.contains("[redacted]"), "{shown}");
        assert!(
            !shown.contains("127"),
            "key material reached Debug: {shown}"
        );
    }
}
