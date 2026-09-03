//! `embed_bytes!` with a `codec` argument, one test per codec that has to be
//! selectable by name. Each compresses at build time and must decode back to
//! the original file at runtime.
#![cfg(all(feature = "std", feature = "derive"))]

#[cfg(feature = "deflate")]
static LOGO: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = deflate);
#[cfg(feature = "deflate")]
static AUTO: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = auto);
// The other two policies of the `auto` family. Under `--features deflate`
// alone the fast tier holds no enabled codec, so this also exercises the
// widening that keeps it from emitting an uncompressed entry.
#[cfg(feature = "deflate")]
static AUTO_FAST: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = auto_fast);
#[cfg(feature = "deflate")]
static AUTO_SMALL: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = auto_small);

#[cfg(feature = "deflate")]
#[test]
fn transformed_decodes() {
    let expected = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/repetitive.txt"
    ))
    .unwrap();
    assert_eq!(&*LOGO.data(), &expected[..]);
    assert_eq!(&*AUTO.data(), &expected[..]);
    assert_eq!(&*AUTO_FAST.data(), &expected[..]);
    assert_eq!(&*AUTO_SMALL.data(), &expected[..]);
    assert_eq!(LOGO.size(), Some(expected.len()));
}

#[cfg(feature = "zstd")]
static ZSTD: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = zstd);

#[cfg(feature = "zstd")]
#[test]
fn explicit_zstd_roundtrips() {
    let expected = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/repetitive.txt"
    ))
    .unwrap();
    assert_eq!(&*ZSTD.data(), &expected[..]);
    assert_eq!(ZSTD.size(), Some(expected.len()));
}

#[cfg(feature = "lzma")]
static LZMA: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = lzma);

#[cfg(feature = "lzma")]
#[test]
fn explicit_lzma_roundtrips() {
    let expected = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/repetitive.txt"
    ))
    .unwrap();
    assert_eq!(&*LZMA.data(), &expected[..]);
    assert_eq!(LZMA.size(), Some(expected.len()));
}
