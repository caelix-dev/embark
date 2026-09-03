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

// How the macro's own `codec = ...` argument spells this codec, so a
// diagnostic names the thing the user would edit.
fn codec_name(codec: CodecId) -> String {
    match codec {
        CodecId::Store => "store".to_string(),
        CodecId::Deflate => "deflate".to_string(),
        CodecId::Lz4 => "lz4".to_string(),
        CodecId::Snappy => "snappy".to_string(),
        CodecId::Zstd => "zstd".to_string(),
        CodecId::Lzma => "lzma".to_string(),
        // `CodecId` is #[non_exhaustive]: a codec added to the format but not
        // yet to this table still has to name itself in a diagnostic.
        other => format!("codec id {}", other.as_u8()),
    }
}

/// Checks that the decoder can read back what the encoder just produced,
/// and fails the build if it cannot.
///
/// The encoders run here, on the build machine; the decoder that reads their
/// output is a separate implementation compiled into the consumer's binary.
/// Nothing else checks the two agree, so an encoder emitting something our
/// decoder refuses -- a frame parameter it does not support, say -- would
/// otherwise surface as a runtime error in a binary that already shipped.
/// Decoding costs a fraction of what the encoding above cost.
///
/// A mismatch is never routed into the `Store` fallback. That fallback is a
/// size decision, and reusing it here would make an encoder bug look exactly
/// like an incompressible file, discarding the only signal this check exists
/// to produce.
fn verify_decode(
    codec: CodecId,
    data: &[u8],
    payload: &[u8],
    shown: &str,
    span: Span,
) -> syn::Result<()> {
    let fail = |detail: &str| {
        let name = codec_name(codec);
        let msg = format!(
            "embark: `{shown}`: the {name} encoder produced a payload this build's \
             decoder cannot read back ({detail}). This is a bug in embark, not in \
             the asset; please report it."
        );
        syn::Error::new(span, msg)
    };

    let decoded = embark_codec::decompress(codec, payload, data.len())
        .map_err(|e| fail(&format!("decoding failed: {e}")))?;
    // Most decoders reject a length disagreement themselves, above. Saying it
    // in the message anyway keeps "decoded the wrong amount" distinguishable
    // from "decoded the wrong bytes", which point at different encoder bugs.
    if decoded.len() != data.len() {
        return Err(fail(&format!(
            "decoded to {} bytes, expected {}",
            decoded.len(),
            data.len()
        )));
    }
    if let Some(at) = decoded.iter().zip(data).position(|(a, b)| a != b) {
        return Err(fail(&format!(
            "decoded output first differs at byte {at}: expected {:#04x}, got {:#04x}",
            data[at], decoded[at]
        )));
    }
    Ok(())
}

// Compress, pick between the result and the original, and prove the winner
// decodes. Shared by the plaintext and the encrypted paths, which make the
// same two decisions in the same order.
pub(crate) fn compress_verified(
    codec: CodecId,
    data: &[u8],
    shown: &str,
    span: Span,
) -> syn::Result<(CodecId, Vec<u8>)> {
    let payload = embark_codec::compress(codec, data);
    // Never grow: fall back to Store if the codec did not help.
    let (codec, payload) = if payload.len() < data.len() {
        (codec, payload)
    } else {
        (CodecId::Store, data.to_vec())
    };
    verify_decode(codec, data, &payload, shown, span)?;
    Ok((codec, payload))
}

// Build a plaintext (optionally compressed) entry as raw bytes.
pub(crate) fn build_entry(
    codec: CodecId,
    data: &[u8],
    shown: &str,
    span: Span,
) -> syn::Result<Vec<u8>> {
    let (codec, payload) = compress_verified(codec, data, shown, span)?;
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        codec,
        CryptoId::None,
        data.len() as u64,
        None,
        &payload,
    );
    Ok(entry)
}

pub(crate) fn build_entry_best(data: &[u8], shown: &str, span: Span) -> syn::Result<Vec<u8>> {
    let (codec, payload) = embark_codec::compress_best(data);
    // Only the winner is verified. Every other candidate's output is thrown
    // away unread, so checking it would cost a decode per compiled-in codec
    // to protect bytes that never reach the binary.
    verify_decode(codec, data, &payload, shown, span)?;
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        codec,
        CryptoId::None,
        data.len() as u64,
        None,
        &payload,
    );
    Ok(entry)
}

// Emit a byte slice as a single byte-string literal. One token instead of one
// per byte keeps rustc's parsing and const-evaluation cost flat in asset size.
// The result is typed `&'static [u8; N]`, so call sites relying on a
// `&'static [u8]` need an unsizing coercion site.
pub(crate) fn bytes_literal(bytes: &[u8]) -> proc_macro2::Literal {
    proc_macro2::Literal::byte_string(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"embark verifies that the decoder can read the encoder";

    // Store's payload is the input verbatim, so a flipped byte lands at an
    // offset known in advance -- the one the diagnostic has to name.
    #[test]
    fn a_corrupted_payload_names_the_path_the_codec_and_the_offset() {
        let mut payload = DATA.to_vec();
        payload[12] ^= 0x01;
        let err = verify_decode(
            CodecId::Store,
            DATA,
            &payload,
            "assets/logo.png",
            Span::call_site(),
        )
        .expect_err("a flipped byte must not verify");

        let msg = err.to_string();
        assert!(msg.contains("assets/logo.png"), "{msg}");
        assert!(msg.contains("store"), "{msg}");
        assert!(msg.contains("byte 12"), "{msg}");
    }

    // A length disagreement is caught by the decoder itself rather than by
    // the comparison below it, so this lands on the "decoding failed" arm.
    #[test]
    fn a_truncated_payload_is_reported_as_a_decoder_rejection() {
        let err = verify_decode(
            CodecId::Store,
            DATA,
            &DATA[..DATA.len() - 1],
            "assets/logo.png",
            Span::call_site(),
        )
        .expect_err("a truncated payload must not verify");

        let msg = err.to_string();
        assert!(msg.contains("assets/logo.png"), "{msg}");
        assert!(msg.contains("decoding failed"), "{msg}");
    }

    #[test]
    fn an_untouched_payload_verifies() {
        let (codec, payload) =
            compress_verified(CodecId::Store, DATA, "assets/logo.png", Span::call_site())
                .expect("store must round-trip");
        assert_eq!(codec, CodecId::Store);
        assert_eq!(payload, DATA);
    }
}
