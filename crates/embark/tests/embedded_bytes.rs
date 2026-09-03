#![cfg(all(feature = "std", feature = "deflate"))]
use embark::EmbeddedBytes;
use embark_codec::compress;
use embark_format::{CodecId, CryptoId, write_entry};
use std::borrow::Cow;

fn make_entry(codec: CodecId, data: &[u8]) -> Vec<u8> {
    let payload = compress(codec, data);
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        codec,
        CryptoId::None,
        data.len() as u64,
        None,
        &payload,
    );
    entry
}

#[test]
fn store_entry_borrows() {
    let entry: &'static [u8] = Box::leak(make_entry(CodecId::Store, b"plain").into_boxed_slice());
    let eb = EmbeddedBytes::from_entry(entry);
    assert!(matches!(eb.data(), Cow::Borrowed(_)));
    assert_eq!(&*eb.data(), b"plain");
    assert_eq!(eb.size(), Some(5));
}

#[test]
fn deflate_entry_owns_and_decodes() {
    let data = b"compress me compress me compress me".repeat(10);
    let entry: &'static [u8] = Box::leak(make_entry(CodecId::Deflate, &data).into_boxed_slice());
    let eb = EmbeddedBytes::from_entry(entry);
    assert!(matches!(eb.data(), Cow::Owned(_)));
    assert_eq!(&*eb.data(), &data[..]);
}

#[test]
fn size_is_none_for_an_unreadable_header() {
    let eb = EmbeddedBytes::from_entry(&[]);
    assert_eq!(eb.size(), None);
}
