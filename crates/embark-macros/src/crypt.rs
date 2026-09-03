use embark_crypt::{gen_key_nonce, seal};
use embark_format::{write_entry, CodecId, CryptoId};

pub(crate) enum KeyMode {
    BuildTime,
    Runtime,
}

pub(crate) struct Sealed {
    pub entry: Vec<u8>,
    // The build-time key for embedded-key mode, from which the caller emits a
    // randomized reconstruction function; `None` in runtime-key mode.
    pub key: Option<[u8; 32]>,
}

pub(crate) fn seal_file(data: &[u8], codec: CodecId, crypto: CryptoId, mode: KeyMode) -> Sealed {
    // Compress first (never grow), then encrypt the compressed payload.
    let compressed = embark_codec::compress(codec, data);
    let (codec, compressed) = if compressed.len() < data.len() {
        (codec, compressed)
    } else {
        (CodecId::Store, data.to_vec())
    };

    let (key, nonce, embedded_key) = match mode {
        KeyMode::BuildTime => {
            let (key, nonce) = gen_key_nonce();
            (key, nonce, Some(key))
        }
        KeyMode::Runtime => {
            let key = env_key();
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
    Sealed {
        entry,
        key: embedded_key,
    }
}

fn env_key() -> [u8; 32] {
    let hex = std::env::var("EMBARK_KEY").expect(
        "embark: key = runtime requires the EMBARK_KEY env var (64 hex chars) at build time",
    );
    let hex = hex.trim();
    assert_eq!(
        hex.len(),
        64,
        "embark: EMBARK_KEY must be 64 hex chars (32 bytes)"
    );
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .expect("embark: EMBARK_KEY must be valid hex");
    }
    key
}

// Used by derive(Embed) with #[embark(encrypt)]: every file in the folder is
// sealed under one shared build-time key (obfuscated via a per-build
// reconstruction function the derive emits). Returns just the entry bytes.
pub(crate) fn seal_with_key(
    data: &[u8],
    codec: CodecId,
    crypto: CryptoId,
    key: [u8; 32],
) -> Vec<u8> {
    let compressed = embark_codec::compress(codec, data);
    let (codec, compressed) = if compressed.len() < data.len() {
        (codec, compressed)
    } else {
        (CodecId::Store, data.to_vec())
    };
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
    entry
}
