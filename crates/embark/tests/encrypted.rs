#![cfg(all(feature = "std", feature = "encryption"))]
use embark::EncryptedFile;
use embark_crypt::seal;
use embark_format::{write_entry, CodecId, CryptoId};

fn encrypted_entry(plain: &[u8], key: [u8; 32], nonce: [u8; 12]) -> Vec<u8> {
    encrypted_entry_with(CryptoId::ChaCha20Poly1305, plain, key, nonce)
}

fn encrypted_entry_with(crypto: CryptoId, plain: &[u8], key: [u8; 32], nonce: [u8; 12]) -> Vec<u8> {
    let (ct, tag) = seal(crypto, &key, &nonce, plain);
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        CodecId::Store,
        crypto,
        plain.len() as u64,
        Some((nonce, tag)),
        &ct,
    );
    entry
}

// Stand-in for the macro-generated key-reconstruction fn: a plain `fn`
// pointer that returns the fixed key used to seal the entry below.
fn recon_33() -> [u8; 32] {
    [0x33u8; 32]
}

#[test]
fn embedded_key_decrypts() {
    let key = [0x33u8; 32];
    let entry: &'static [u8] =
        Box::leak(encrypted_entry(b"top secret", key, [1u8; 12]).into_boxed_slice());
    let f = EncryptedFile::with_embedded_key(entry, recon_33);
    assert_eq!(f.decrypt(), b"top secret");
    assert_eq!(f.decrypt_str().unwrap(), "top secret");
}

#[test]
fn runtime_key_decrypts_and_rejects_wrong() {
    let key = [0x55u8; 32];
    let entry: &'static [u8] =
        Box::leak(encrypted_entry(b"cfg", key, [2u8; 12]).into_boxed_slice());
    let f: EncryptedFile<embark::RuntimeKey> = EncryptedFile::with_runtime_key(entry);
    assert_eq!(f.decrypt_with(&key).unwrap(), b"cfg");
    assert!(f.decrypt_with(&[0u8; 32]).is_err());
}

// `EncryptedFile<RuntimeKey>` has no `decrypt()` method at all -- calling it
// on a runtime-key handle is a compile error, not a runtime panic. See the
// `compile_fail` doctest on `EncryptedFile::<RuntimeKey>::with_runtime_key`
// in `crates/embark/src/encrypted.rs` for a checked demonstration of that.

#[cfg(feature = "aes")]
fn recon_77() -> [u8; 32] {
    [0x77u8; 32]
}

#[cfg(feature = "aes")]
#[test]
fn aes_embedded_key_decrypts() {
    let key = [0x77u8; 32];
    let entry: &'static [u8] = Box::leak(
        encrypted_entry_with(CryptoId::Aes256Gcm, b"aes secret", key, [4u8; 12]).into_boxed_slice(),
    );
    let f = EncryptedFile::with_embedded_key(entry, recon_77);
    assert_eq!(f.decrypt(), b"aes secret");
}
