//! The `metadata` feature as a downstream crate sees it: `hash()` over a
//! looked-up file against the FIPS 180-4 `"abc"` vector, and `mime()` from
//! the path's extension.
#![cfg(all(feature = "std", feature = "metadata"))]
use embark::Manifest;
use embark_format::{CodecId, CryptoId, write_entry};

fn store(data: &[u8]) -> &'static [u8] {
    let mut entry = Vec::new();
    write_entry(
        &mut entry,
        CodecId::Store,
        CryptoId::None,
        data.len() as u64,
        None,
        data,
    );
    Box::leak(entry.into_boxed_slice())
}

fn manifest() -> &'static [Manifest] {
    static M: std::sync::OnceLock<Vec<Manifest>> = std::sync::OnceLock::new();
    M.get_or_init(|| {
        vec![
            Manifest::new("abc.txt", store(b"abc")),
            Manifest::new("blob", store(b"")),
            Manifest::new("style.css", store(b"")),
        ]
    })
}

#[test]
fn hash_is_sha256_of_the_contents() {
    let file = embark::lookup(manifest(), "abc.txt").unwrap();
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(file.hash(), expected);
}

#[test]
fn mime_comes_from_the_extension() {
    let get = |path| embark::lookup(manifest(), path).unwrap().mime();
    assert_eq!(get("abc.txt"), "text/plain");
    assert_eq!(get("style.css"), "text/css");
    assert_eq!(get("blob"), "application/octet-stream");
}
