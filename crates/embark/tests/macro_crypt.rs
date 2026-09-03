#![cfg(all(feature = "std", feature = "derive", feature = "encryption"))]

static SECRET: embark::EncryptedFile = embark::embed_crypt!("tests/fixtures/secret.txt");

#[test]
fn build_time_key_roundtrips() {
    let expected = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/secret.txt"
    ))
    .unwrap();
    assert_eq!(SECRET.decrypt(), expected);
}
