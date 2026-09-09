//! Every encoder's output has to read back through its decoder, byte for
//! byte, for any input at all. The `store` fallback in the macros only
//! covers the case where compression did not help, not the case where it
//! produced something the decoder refuses.
#![no_main]

use embark_format::CodecId;
use libfuzzer_sys::fuzz_target;

const CODECS: [CodecId; 6] = [
    CodecId::Store,
    CodecId::Deflate,
    CodecId::Lz4,
    CodecId::Snappy,
    CodecId::Zstd,
    CodecId::Lzma,
];

fuzz_target!(|data: &[u8]| {
    for codec in CODECS {
        let packed = embark_codec::compress(codec, data);
        let back = embark_codec::decompress(codec, &packed, data.len())
            .unwrap_or_else(|e| panic!("{codec:?}: our own output was refused: {e}"));
        assert!(back == data, "{codec:?}: round trip changed the bytes");
    }

    let (codec, packed) = embark_codec::compress_best(data);
    assert!(packed.len() <= data.len(), "compress_best grew the input");
    let back = embark_codec::decompress(codec, &packed, data.len()).expect("compress_best output");
    assert!(back == data, "compress_best round trip changed the bytes");
});
