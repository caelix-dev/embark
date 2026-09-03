//! `embed_crypt!` in its default build-time-key mode, under both ciphers:
//! the macro seals the file at build time and the emitted reconstruction
//! function has to recover the key at runtime.
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

// `embed_crypt!` runs the same codec selection every other path does; the
// selection reads the plaintext, before sealing, so the sealed entry still
// has to decrypt to the file verbatim.
static SECRET_AUTO: embark::EncryptedFile =
    embark::embed_crypt!("tests/fixtures/repetitive.txt", codec = auto);

#[test]
fn an_auto_selected_codec_roundtrips_through_the_cipher() {
    let expected = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/repetitive.txt"
    ))
    .unwrap();
    assert_eq!(SECRET_AUTO.decrypt(), expected);
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
