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

#[cfg(feature = "aes")]
static SECRET_AES: embark::EncryptedFile =
    embark::embed_crypt!("tests/fixtures/secret.txt", cipher = aes);

#[cfg(feature = "aes")]
#[test]
fn build_time_key_roundtrips_aes() {
    let expected = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/secret.txt"
    ))
    .unwrap();
    assert_eq!(SECRET_AES.decrypt(), expected);
}
