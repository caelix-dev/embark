//! Frame header and window sizing (RFC 8478, section 3.1.1.1).

use alloc::vec::Vec;

use super::block;
use super::matcher::{self, Params};

const MAGIC: u32 = 0xfd2f_b528;

/// Longest input the match finder will parse. Its tables address positions
/// as `u32`; anything larger is stored rather than searched, which costs
/// three bytes per block and never happens for a real embedded asset.
const MAX_PARSED: usize = u32::MAX as usize;

/// Largest window this encoder advertises, as a base-2 logarithm.
///
/// Eight mebibytes is the size the format recommends every decoder support,
/// and it is far under the ceiling our own decoder enforces, so a frame from
/// here can never be one our own reader refuses.
const MAX_WINDOW_LOG: u32 = 23;

/// Encode `input` as one Zstandard frame.
pub(super) fn encode(input: &[u8]) -> Vec<u8> {
    let len = input.len();
    let mut out = Vec::with_capacity(len / 3 + 32);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    let window = write_header(&mut out, len);

    if len == 0 {
        // A frame must carry at least one block.
        out.extend_from_slice(&[0x01, 0x00, 0x00]);
        return out;
    }
    let matches = if len <= MAX_PARSED {
        matcher::parse(input, window - 1, &Params::for_input(len))
    } else {
        Vec::new()
    };
    block::write_all(&mut out, input, &matches);
    out
}

/// Write the frame header and return the window size in bytes.
///
/// Inputs below 256 bytes take the `Single_Segment_Flag`: the window
/// descriptor is dropped and the content size fits in one byte, which is two
/// bytes of header in total. Larger inputs carry an explicit window and the
/// narrowest content-size field that can hold their length.
fn write_header(out: &mut Vec<u8>, len: usize) -> usize {
    if len < 256 {
        out.push(0x20);
        out.push(len as u8);
        return len.max(1);
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
    1usize << log
}

/// Smallest window log that covers `n` bytes, never below the format's
/// 1 KiB floor.
fn ceil_log2(n: usize) -> u32 {
    (usize::BITS - (n - 1).leading_zeros()).max(10)
}
