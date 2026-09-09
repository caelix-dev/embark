/// Appends `value` to `out` as an unsigned LEB128 varint: seven bits of
/// payload per byte, little-endian, with the high bit set on every byte but
/// the last.
///
/// Costs one byte for values under 128 and at most ten for `u64::MAX`,
/// which is why entry lengths are stored this way rather than as a fixed
/// eight bytes.
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

/// Reads one unsigned LEB128 varint from the front of `input`, returning
/// the value and how many bytes it occupied.
///
/// Trailing bytes are ignored, so the caller advances by the returned
/// count to reach whatever follows.
///
/// # Errors
///
/// Returns [`Error::Truncated`](crate::Error::Truncated) if the
/// continuation bit is still set when `input` runs out, and
/// [`Error::Corrupt`](crate::Error::Corrupt) if the encoding runs past the
/// ten bytes a `u64` can need, which would otherwise let a hostile entry
/// shift bits off the end.
pub fn read_varint(input: &[u8]) -> crate::Result<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &byte) in input.iter().enumerate() {
        // Nine bytes carry 63 bits; the tenth has room for one more, and
        // anything above it would be shifted off the end. A byte that sets
        // those bits is not an encoding of any `u64`.
        if i == 10 || (i == 9 && byte & 0x7e != 0) {
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

    // Ten bytes is the most a `u64` takes, and the tenth holds one bit. A
    // tenth byte with more set, or an eleventh byte at all, describes a
    // value wider than the type, not a `u64` written the long way.
    #[test]
    fn bits_past_the_sixty_fourth_are_corrupt() {
        let mut max = [0xffu8; 10];
        max[9] = 0x01;
        assert_eq!(read_varint(&max), Ok((u64::MAX, 10)));

        let mut over = max;
        over[9] = 0x02;
        assert!(matches!(read_varint(&over), Err(crate::Error::Corrupt)));

        let mut long = [0xffu8; 11];
        long[10] = 0x00;
        assert!(matches!(read_varint(&long), Err(crate::Error::Corrupt)));
    }
}
