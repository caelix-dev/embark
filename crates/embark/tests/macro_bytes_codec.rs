#![cfg(all(feature = "std", feature = "derive"))]

#[cfg(feature = "deflate")]
static LOGO: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = deflate);
#[cfg(feature = "deflate")]
static AUTO: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = auto);

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
