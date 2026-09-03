extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "enc")]
pub fn compress(input: &[u8]) -> Vec<u8> {
    lz4_flex::block::compress(input)
}

#[cfg(feature = "dec")]
pub fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    lz4_flex::block::decompress(input, orig_len).map_err(|_| Error::Corrupt)
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"lz4 lz4 lz4 lz4 lz4 lz4 lz4 lz4 lz4 lz4".repeat(20);
        let c = compress(&data);
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty() {
        let c = compress(b"");
        assert_eq!(decompress(&c, 0).unwrap(), b"");
    }

    #[test]
    fn wrong_len_is_corrupt() {
        let c = compress(b"hello world");
        assert!(decompress(&c, 3).is_err());
    }
}
