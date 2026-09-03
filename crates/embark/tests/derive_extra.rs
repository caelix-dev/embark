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
