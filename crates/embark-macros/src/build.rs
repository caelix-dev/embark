use embark_format::{write_entry, CodecId, CryptoId};
use std::path::PathBuf;

pub(crate) fn manifest_dir() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"))
}

pub(crate) fn resolve(rel: &str) -> PathBuf {
    manifest_dir().join(rel)
}

pub(crate) fn read(rel: &str) -> Vec<u8> {
    let path = resolve(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("embark: cannot read {}: {e}", path.display()))
}

// Build a plaintext (optionally compressed) entry as raw bytes.
pub(crate) fn build_entry(codec: CodecId, data: &[u8]) -> Vec<u8> {
    let payload = embark_codec::compress(codec, data);
    // Never grow: fall back to Store if the codec did not help.
    let (codec, payload) = if payload.len() < data.len() {
        (codec, payload)
    } else {
        (CodecId::Store, data.to_vec())
    };
    let mut entry = Vec::new();
    write_entry(&mut entry, codec, CryptoId::None, data.len() as u64, None, &payload);
    entry
}

pub(crate) fn build_entry_best(data: &[u8]) -> Vec<u8> {
    let (codec, payload) = embark_codec::compress_best(data);
    let mut entry = Vec::new();
    write_entry(&mut entry, codec, CryptoId::None, data.len() as u64, None, &payload);
    entry
}

// Emit a byte slice as a token literal: &[0u8, 1u8, ...].
pub(crate) fn bytes_literal(bytes: &[u8]) -> proc_macro2::TokenStream {
    use quote::quote;
    let elems = bytes.iter().map(|b| quote!(#b));
    quote!(&[#(#elems),*])
}
