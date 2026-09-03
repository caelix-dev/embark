extern crate alloc;
use alloc::vec::Vec;
#[cfg(feature = "dec")]
use embark_format::Error;

#[cfg(feature = "enc")]
pub fn compress(input: &[u8]) -> Vec<u8> {
    // Level 9: maximum ratio. Raw DEFLATE (no zlib header) to keep the entry
    // header the single source of framing.
    miniz_oxide::deflate::compress_to_vec(input, 9)
}

#[cfg(feature = "dec")]
pub fn decompress(input: &[u8], orig_len: usize) -> Result<Vec<u8>, Error> {
    if orig_len == 0 {
        return Ok(Vec::new());
    }
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(input, orig_len)
        .map_err(|_| Error::Corrupt)?;
    if out.len() != orig_len {
        return Err(Error::Corrupt);
    }
    Ok(out)
}

#[cfg(all(test, feature = "enc", feature = "dec"))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_repetitive() {
        let data = b"ababababababababababababababababab".repeat(50);
        let c = compress(&data);
        assert!(c.len() < data.len(), "repetitive data should shrink");
        assert_eq!(decompress(&c, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty() {
        let c = compress(b"");
        assert_eq!(decompress(&c, 0).unwrap(), b"");
    }

    #[test]
    fn garbage_is_corrupt() {
        assert!(decompress(&[0xff, 0xff, 0xff, 0xff], 10).is_err());
    }
}
