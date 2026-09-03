extern crate alloc;
use alloc::vec::Vec;
use embark_format::Error;

#[cfg(feature = "enc")]
pub fn compress(input: &[u8]) -> Vec<u8> {
    input.to_vec()
}

#[cfg(feature = "dec")]
pub fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    if input.len() != orig_len {
        return Err(Error::Corrupt);
    }
    Ok(input.to_vec())
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::super::{compress, decompress};
    use embark_format::CodecId;

    #[test]
    fn store_roundtrip() {
        let data = b"identity bytes";
        let stored = compress(CodecId::Store, data);
        assert_eq!(stored, data);
        let back = decompress(CodecId::Store, &stored, data.len()).unwrap();
        assert_eq!(back, data);
    }
}
