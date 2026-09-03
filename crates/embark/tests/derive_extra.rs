//! The two `#[derive(Embed)]` attributes with runtime consequences:
//! `#[embark(encrypt)]`, which seals every file in the folder under one
//! shared build-time key, and `#[embark(dev)]`, which reads from disk in
//! debug builds instead of the compiled-in copy.
#![cfg(all(
    feature = "std",
    feature = "derive",
    feature = "deflate",
    feature = "encryption"
))]
use embark::Embed;

#[derive(Embed)]
#[embark(folder = "tests/assets/")]
#[embark(encrypt)]
struct EncryptedAssets;

#[test]
fn derive_encrypt_roundtrips() {
    let f = EncryptedAssets::get("one.txt").unwrap();
    assert_eq!(&*f.data(), b"one\n");
}

// `encrypt` used to skip the codec-selection pass entirely and hard-code
// Deflate. It runs the selection now, on the plaintext, before sealing.
#[derive(Embed)]
#[embark(folder = "tests/assets/")]
#[embark(encrypt, codec = "auto_small")]
struct EncryptedAutoAssets;

#[test]
fn derive_encrypt_with_an_auto_policy_roundtrips() {
    let f = EncryptedAutoAssets::get("one.txt").unwrap();
    assert_eq!(
        &*f.data(),
        b"one
"
    );
}

#[derive(Embed)]
#[embark(folder = "tests/assets/")]
#[embark(dev)]
struct DevAssets;

#[test]
fn derive_dev_reads_from_disk() {
    // debug_assertions is on in `cargo test` by default, so this exercises
    // the __dev_file branch, not the embedded manifest.
    let f = DevAssets::get("one.txt").unwrap();
    assert_eq!(&*f.data(), b"one\n");
}
