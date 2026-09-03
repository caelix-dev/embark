use embark_format::{CodecId, CryptoId, write_entry};
use proc_macro2::Span;
use quote::quote;
use std::path::{Path, PathBuf};
use syn::LitStr;

pub(crate) fn manifest_dir() -> PathBuf {
    PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"))
}

pub(crate) fn resolve(rel: &LitStr) -> PathBuf {
    manifest_dir().join(rel.value())
}

// `shown` is the path as the user wrote it. The resolved absolute path is
// deliberately kept out of the message: it embeds the build machine's
// CARGO_MANIFEST_DIR, and a not-found `io::Error` renders in the build
// machine's locale, so neither reproduces across machines.
fn read_error(err: &std::io::Error, shown: &str, span: Span) -> syn::Error {
    let msg = if err.kind() == std::io::ErrorKind::NotFound {
        format!("embark: file not found: `{shown}` (resolved relative to CARGO_MANIFEST_DIR)")
    } else {
        format!("embark: cannot read `{shown}`: {err}")
    };
    syn::Error::new(span, msg)
}

pub(crate) fn read(path: &Path, shown: &str, span: Span) -> syn::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| read_error(&e, shown, span))
}

// The raw `embed_bytes!` mode never reads the file itself -- it defers to
// `include_bytes!` -- but rustc spans that failure at the whole macro call.
// Opening the file here buys the same caret-on-the-path-literal diagnostic
// as every other failure, without reading the contents twice.
pub(crate) fn ensure_readable(path: &Path, shown: &str, span: Span) -> syn::Result<()> {
    std::fs::File::open(path)
        .map(drop)
        .map_err(|e| read_error(&e, shown, span))
}

pub(crate) fn path_str(path: &Path, span: Span) -> syn::Result<&str> {
    path.to_str().ok_or_else(|| {
        syn::Error::new(
            span,
            format!("embark: path is not valid UTF-8: {}", path.display()),
        )
    })
}

// Reading an asset with `std::fs` is invisible to cargo, so an edited asset
// would not trigger a rebuild. Emitting `include_bytes!` on the same path
// registers it as a build input; `const _` keeps the value unnamed and
// discardable, and repeats never collide.
pub(crate) fn track_file(path: &Path, span: Span) -> syn::Result<proc_macro2::TokenStream> {
    let abs = path_str(path, span)?;
    Ok(quote!(
        const _: &[::core::primitive::u8] = ::core::include_bytes!(#abs);
    ))
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
