#[cfg(feature = "alloc")]
pub fn write_varint(out: &mut alloc::vec::Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub fn read_varint(input: &[u8]) -> crate::Result<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &byte) in input.iter().enumerate() {
        if i == 10 {
            return Err(crate::Error::Corrupt);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(crate::Error::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn roundtrip_boundaries() {
        for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (got, n) = read_varint(&buf).unwrap();
            assert_eq!(got, v);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn known_encoding() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 300);
        assert_eq!(buf, [0xAC, 0x02]); // canonical LEB128 for 300
    }

    #[test]
    fn truncated_is_error() {
        assert!(matches!(read_varint(&[0x80]), Err(crate::Error::Truncated)));
    }
}
