//! `EncryptedFile` in both key modes, over hand-sealed entries.
//!
//! Covers decryption under an embedded build-time key and under a
//! caller-supplied runtime key, rejection of a wrong runtime key, the UTF-8
//! error position `decrypt_str` reports, and the type-level guarantee that a
//! `RuntimeKey` handle is no larger than the entry reference it holds and so
//! carries no key material.
#![cfg(all(feature = "std", feature = "encryption"))]
use embark::EncryptedFile;
use embark_crypt::seal;
use embark_format::{CodecId, CryptoId, write_entry, write_header};

fn encrypted_entry(plain: &[u8], key: [u8; 32], nonce: [u8; 12]) -> Vec<u8> {
    encrypted_entry_with(CryptoId::ChaCha20Poly1305, plain, key, nonce)
}

fn encrypted_entry_with(crypto: CryptoId, plain: &[u8], key: [u8; 32], nonce: [u8; 12]) -> Vec<u8> {
    // The header is sealed in as associated data, so it is written first
    // and handed to the cipher before the entry is assembled.
    let mut header = Vec::new();
    write_header(&mut header, CodecId::Store, crypto, plain.len() as u64);
    let (ct, tag) = seal(crypto, &key, &nonce, &header, plain);
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
    assert_eq!(f.decrypt_str_with(&key).unwrap(), "cfg");
    assert_eq!(f.decrypt_with(&[0u8; 32]), Err(embark::Error::Auth));
    assert_eq!(f.decrypt_str_with(&[0u8; 32]), Err(embark::Error::Auth));
}

// The length sits in the clear header, so both modes can report it without
// a key, and an unreadable header is `None` rather than a panic.
#[test]
fn size_needs_no_key_in_either_mode() {
    let key = [0x44u8; 32];
    let entry: &'static [u8] =
        Box::leak(encrypted_entry(b"sized", key, [3u8; 12]).into_boxed_slice());
    assert_eq!(EncryptedFile::with_runtime_key(entry).size(), Some(5));
    assert_eq!(
        EncryptedFile::with_embedded_key(entry, recon_33).size(),
        Some(5)
    );
    assert_eq!(EncryptedFile::with_runtime_key(&[]).size(), None);
}

// The tag covers the header, not just the payload. An entry whose codec
// nibble or claimed length was rewritten after sealing must fail as `Auth`
// -- the tag no longer stands for what is in front of it -- and never reach
// a decoder with a plaintext it was not meant for.
#[test]
fn a_rewritten_header_fails_authentication() {
    let key = [0x66u8; 32];
    let sealed = encrypted_entry(b"header-bound", key, [6u8; 12]);
    let open = |entry: Vec<u8>| {
        let entry: &'static [u8] = Box::leak(entry.into_boxed_slice());
        EncryptedFile::with_runtime_key(entry).decrypt_with(&key)
    };
    assert_eq!(open(sealed.clone()).unwrap(), b"header-bound");

    // Store -> Deflate, keeping the cipher id in the high nibble.
    let mut codec_swapped = sealed.clone();
    codec_swapped[0] = (codec_swapped[0] & 0xf0) | CodecId::Deflate.as_u8();
    assert_eq!(open(codec_swapped), Err(embark::Error::Auth));

    // The claimed length is the second byte for a payload this short.
    let mut length_changed = sealed;
    length_changed[1] ^= 0x01;
    assert_eq!(open(length_changed), Err(embark::Error::Auth));
}

// `EncryptedFile<RuntimeKey>` has no `decrypt()` method at all -- calling it
// on a runtime-key handle is a compile error, not a runtime panic. See the
// `compile_fail` doctest on `EncryptedFile::<RuntimeKey>::with_runtime_key`
// in `crates/embark/src/encrypted.rs` for a checked demonstration of that.

// A runtime-key handle is exactly its sealed entry: the mode-specific payload
// is `()`, so there is no field for key material to sit in -- not even a
// zeroed placeholder for a later refactor to hand out.
#[test]
fn runtime_key_handle_carries_no_key_material() {
    assert_eq!(
        size_of::<EncryptedFile<embark::RuntimeKey>>(),
        size_of::<&'static [u8]>()
    );
    assert_eq!(
        size_of::<EncryptedFile<embark::EmbeddedKey>>(),
        size_of::<&'static [u8]>() + size_of::<fn() -> [u8; 32]>()
    );
}

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

fn recon_11() -> [u8; 32] {
    [0x11u8; 32]
}

#[test]
fn decrypt_str_reports_where_utf8_broke() {
    let key = [0x11u8; 32];
    let entry: &'static [u8] =
        Box::leak(encrypted_entry(b"ok\xFF!", key, [5u8; 12]).into_boxed_slice());
    let f = EncryptedFile::with_embedded_key(entry, recon_11);
    assert_eq!(f.decrypt_str(), Err(embark::Error::Utf8 { valid_up_to: 2 }));
}
