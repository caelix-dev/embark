use embark_format::{write_entry, CodecId, CryptoId};
use quote::quote;
use std::path::{Path, PathBuf};

pub(crate) fn manifest_dir() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"))
}

pub(crate) fn resolve(rel: &str) -> PathBuf {
    manifest_dir().join(rel)
}

pub(crate) fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("embark: cannot read {}: {e}", path.display()))
}

// Reading an asset with `std::fs` is invisible to cargo, so an edited asset
// would not trigger a rebuild. Emitting `include_bytes!` on the same path
// registers it as a build input; `const _` keeps the value unnamed and
// discardable, and repeats never collide.
pub(crate) fn track_file(path: &Path) -> proc_macro2::TokenStream {
    let abs = path.to_str().expect("embark: non-UTF-8 path");
    quote!(
        const _: &[::core::primitive::u8] = ::core::include_bytes!(#abs);
    )
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
    write_entry(
        &mut entry,
        codec,
        CryptoId::None,
        data.len() as u64,
        None,
        &payload,
    );
    entry
}

pub(crate) fn build_entry_best(data: &[u8]) -> Vec<u8> {
    let (codec, payload) = embark_codec::compress_best(data);
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        codec,
        CryptoId::None,
        data.len() as u64,
        None,
        &payload,
    );
    entry
}

// Emit a byte slice as a single byte-string literal. One token instead of one
// per byte keeps rustc's parsing and const-evaluation cost flat in asset size.
// The result is typed `&'static [u8; N]`, so call sites relying on a
// `&'static [u8]` need an unsizing coercion site.
pub(crate) fn bytes_literal(bytes: &[u8]) -> proc_macro2::Literal {
    proc_macro2::Literal::byte_string(bytes)
}
