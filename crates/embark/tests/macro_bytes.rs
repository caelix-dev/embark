#![cfg(all(feature = "std", feature = "derive"))]

static RAW: &[u8] = embark::embed_bytes!("tests/fixtures/hello.txt");

#[test]
fn raw_is_static_slice() {
    assert_eq!(RAW, b"hello embark\n");
}
