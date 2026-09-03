#![cfg(all(feature = "std", feature = "derive", feature = "deflate"))]

static LOGO: embark::EmbeddedBytes = embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = deflate);
static AUTO: embark::EmbeddedBytes = embark::embed_bytes!("tests/fixtures/repetitive.txt", codec = auto);

#[test]
fn transformed_decodes() {
    let expected = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/repetitive.txt")).unwrap();
    assert_eq!(&*LOGO.data(), &expected[..]);
    assert_eq!(&*AUTO.data(), &expected[..]);
    assert_eq!(LOGO.size(), expected.len());
}
