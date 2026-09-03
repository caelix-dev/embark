#![cfg(all(feature = "enc", feature = "dec"))]
use embark_codec::{compress, compress_best, decompress};
use embark_format::CodecId;

const CODECS: &[CodecId] = &[
    CodecId::Store,
    #[cfg(feature = "deflate")]
    CodecId::Deflate,
    #[cfg(feature = "lz4")]
    CodecId::Lz4,
    #[cfg(feature = "snappy")]
    CodecId::Snappy,
    #[cfg(feature = "zstd")]
    CodecId::Zstd,
];

#[test]
fn all_codecs_roundtrip() {
    let corpus: &[&[u8]] = &[
        b"",
        b"x",
        b"The quick brown fox jumps over the lazy dog.",
        &[0u8; 1000],
    ];
    for &data in corpus {
        for &id in CODECS {
            let c = compress(id, data);
            let back = decompress(id, &c, data.len()).unwrap();
            assert_eq!(back, data, "codec {:?} failed", id);
        }
    }
}

#[test]
fn best_never_larger_than_store() {
    let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let (id, bytes) = compress_best(data);
    assert!(bytes.len() <= data.len());
    assert_eq!(decompress(id, &bytes, data.len()).unwrap(), data);
}
