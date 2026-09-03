use crate::args::CodecArg;
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
fn read_error(err: &std::io::Error, shown: &str) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        format!("embark: file not found: `{shown}` (resolved relative to CARGO_MANIFEST_DIR)")
    } else {
        format!("embark: cannot read `{shown}`: {err}")
    }
}

/// Give a message from one of the span-free steps below its caret.
///
/// Those steps run on worker threads when `parallel-encode` is on, and a
/// `proc_macro2::Span` is not something a thread can hand to another, so
/// they carry their diagnostics as plain text and meet a span here.
pub(crate) fn at(span: Span) -> impl Fn(String) -> syn::Error {
    move |message| syn::Error::new(span, message)
}

pub(crate) fn read(path: &Path, shown: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| read_error(&e, shown))
}

// The raw `embed_bytes!` mode never reads the file itself -- it defers to
// `include_bytes!` -- but rustc spans that failure at the whole macro call.
// Opening the file here buys the same caret-on-the-path-literal diagnostic
// as every other failure, without reading the contents twice.
pub(crate) fn ensure_readable(path: &Path, shown: &str, span: Span) -> syn::Result<()> {
    std::fs::File::open(path)
        .map(drop)
        .map_err(|e| syn::Error::new(span, read_error(&e, shown)))
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
fn verify_decode(codec: CodecId, data: &[u8], payload: &[u8], shown: &str) -> Result<(), String> {
    let fail = |detail: &str| {
        let name = codec_name(codec);
        format!(
            "embark: `{shown}`: the {name} encoder produced a payload this build's \
             decoder cannot read back ({detail}). This is a bug in embark, not in \
             the asset; please report it."
        )
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

// Compress, settle on a codec, and prove the winner decodes. Every encoded
// payload in the crate goes through here: the plaintext and the encrypted
// paths make the same decisions in the same order, and an `auto` tier is a
// choice of candidates, not a different pipeline.
pub(crate) fn compress_verified(
    codec: CodecArg,
    data: &[u8],
    shown: &str,
) -> Result<(CodecId, Vec<u8>), String> {
    let (codec, payload) = match codec {
        // Already never larger than the input, and already Store when
        // nothing in the tier helped. Only the winner is verified: every
        // other candidate's output is thrown away unread, so checking it
        // would cost a decode per candidate to protect bytes that never
        // reach the binary.
        CodecArg::Auto(tier) => embark_codec::compress_best_in(tier, data),
        CodecArg::Fixed(id) => {
            let payload = embark_codec::compress(id, data);
            // Never grow: fall back to Store if the codec did not help.
            if payload.len() < data.len() {
                (id, payload)
            } else {
                (CodecId::Store, data.to_vec())
            }
        }
    };
    verify_decode(codec, data, &payload, shown)?;
    Ok((codec, payload))
}

// Build a plaintext (optionally compressed) entry as raw bytes.
pub(crate) fn build_entry(codec: CodecArg, data: &[u8], shown: &str) -> Result<Vec<u8>, String> {
    let (codec, payload) = compress_verified(codec, data, shown)?;
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
        let msg = verify_decode(CodecId::Store, DATA, &payload, "assets/logo.png")
            .expect_err("a flipped byte must not verify");

        assert!(msg.contains("assets/logo.png"), "{msg}");
        assert!(msg.contains("store"), "{msg}");
        assert!(msg.contains("byte 12"), "{msg}");
    }

    // A length disagreement is caught by the decoder itself rather than by
    // the comparison below it, so this lands on the "decoding failed" arm.
    #[test]
    fn a_truncated_payload_is_reported_as_a_decoder_rejection() {
        let msg = verify_decode(
            CodecId::Store,
            DATA,
            &DATA[..DATA.len() - 1],
            "assets/logo.png",
        )
        .expect_err("a truncated payload must not verify");

        assert!(msg.contains("assets/logo.png"), "{msg}");
        assert!(msg.contains("decoding failed"), "{msg}");
    }

    #[test]
    fn an_untouched_payload_verifies() {
        let (codec, payload) =
            compress_verified(CodecArg::Fixed(CodecId::Store), DATA, "assets/logo.png")
                .expect("store must round-trip");
        assert_eq!(codec, CodecId::Store);
        assert_eq!(payload, DATA);
    }
}
