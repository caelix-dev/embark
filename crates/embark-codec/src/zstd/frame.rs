//! Frame header and window sizing (RFC 8478, section 3.1.1.1).

use alloc::vec::Vec;

use super::block;

const MAGIC: u32 = 0xfd2f_b528;

/// Largest window this encoder advertises, as a base-2 logarithm.
///
/// Eight mebibytes is the size the format recommends every decoder support,
/// and it is far under the ceiling our own decoder enforces, so a frame from
/// here can never be one our own reader refuses.
const MAX_WINDOW_LOG: u32 = 23;

/// Encode `input` as one Zstandard frame.
pub(super) fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + 32);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    write_header(&mut out, input.len());

    if input.is_empty() {
        // A frame must carry at least one block.
        out.extend_from_slice(&[0x01, 0x00, 0x00]);
        return out;
    }
    block::write_all(&mut out, input);
    out
}

/// Write the frame header.
///
/// Inputs below 256 bytes take the `Single_Segment_Flag`: the window
/// descriptor is dropped and the content size fits in one byte, which is two
/// bytes of header in total. Larger inputs carry an explicit window and the
/// narrowest content-size field that can hold their length.
fn write_header(out: &mut Vec<u8>, len: usize) {
    if len < 256 {
        out.push(0x20);
        out.push(len as u8);
        return;
    }
    let log = ceil_log2(len).min(MAX_WINDOW_LOG);
    let descriptor = if len <= 65791 {
        0x40
    } else if len <= u32::MAX as usize {
        0x80
    } else {
        0xc0
    };
    out.push(descriptor);
    out.push(((log - 10) << 3) as u8);
    if len <= 65791 {
        out.extend_from_slice(&((len - 256) as u16).to_le_bytes());
    } else if len <= u32::MAX as usize {
        out.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        out.extend_from_slice(&(len as u64).to_le_bytes());
    }
}

/// Smallest window log that covers `n` bytes, never below the format's
/// 1 KiB floor.
fn ceil_log2(n: usize) -> u32 {
    (usize::BITS - (n - 1).leading_zeros()).max(10)
}
