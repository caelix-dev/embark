//! Block segmentation and serialization (RFC 8478, sections 3.1.1.2 and
//! 3.1.1.3).

use alloc::vec::Vec;

/// Largest decompressed size of one block.
pub(super) const MAX_BLOCK: usize = 128 * 1024;

const RAW: u8 = 0;
const RLE: u8 = 1;

/// Write every block of the frame, marking the last one.
pub(super) fn write_all(out: &mut Vec<u8>, input: &[u8]) {
    let mut at = 0usize;
    while at < input.len() {
        let end = (at + MAX_BLOCK).min(input.len());
        write_one(out, &input[at..end], end == input.len());
        at = end;
    }
}

fn write_one(out: &mut Vec<u8>, raw: &[u8], last: bool) {
    // One repeated byte costs a single byte as an RLE block, which nothing
    // else can beat.
    if raw.iter().all(|&b| b == raw[0]) {
        write_header(out, raw.len(), RLE, last);
        out.push(raw[0]);
    } else {
        write_header(out, raw.len(), RAW, last);
        out.extend_from_slice(raw);
    }
}

fn write_header(out: &mut Vec<u8>, size: usize, kind: u8, last: bool) {
    let word = (size as u32) << 3 | u32::from(kind) << 1 | u32::from(last);
    out.extend_from_slice(&word.to_le_bytes()[..3]);
}
