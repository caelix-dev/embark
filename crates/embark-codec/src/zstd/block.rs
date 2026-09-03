//! Block serialization (RFC 8478, sections 3.1.1.2 and 3.1.1.3).

use alloc::vec::Vec;

use super::huffman;
use super::matcher::{History, Match};
use super::sequences::{self, Coded};

/// Largest decompressed size of one block.
pub(super) const MAX_BLOCK: usize = 128 * 1024;

const RAW: u8 = 0;
const RLE: u8 = 1;
const COMPRESSED: u8 = 2;

const RAW_LITERALS: u8 = 0;
const RLE_LITERALS: u8 = 1;
const COMPRESSED_LITERALS: u8 = 2;

/// Write `input[start..end]` as one block.
///
/// `parses` holds one or more ways of encoding the same range; each is
/// serialized and the smallest kept, which is what lets the parser try
/// several price models without any of them being able to make things worse.
pub(super) fn write_one(
    out: &mut Vec<u8>,
    input: &[u8],
    start: usize,
    end: usize,
    parses: &[Vec<Match>],
    history: &mut History,
    last: bool,
) {
    let raw = &input[start..end];
    // One repeated byte costs a single byte as an RLE block, which nothing
    // else can beat, so that case never needs the sequence encoder.
    if !raw.is_empty() && raw.iter().all(|&b| b == raw[0]) {
        write_header(out, raw.len(), RLE, last);
        out.push(raw[0]);
        return;
    }

    let mut best: Option<(Vec<u8>, History)> = None;
    for parse in parses {
        let mut trial = *history;
        let body = compressed_body(input, start, end, parse, &mut trial);
        if best
            .as_ref()
            .is_none_or(|(kept, _)| body.len() < kept.len())
        {
            best = Some((body, trial));
        }
    }

    // A `Compressed_Block` is only legal when it is strictly smaller than
    // what it stands for, which is also the only case in which it is worth
    // using. Blocks that are not compressed leave the offset history alone.
    match best {
        Some((body, trial)) if body.len() < raw.len() => {
            write_header(out, body.len(), COMPRESSED, last);
            out.extend_from_slice(&body);
            *history = trial;
        }
        _ => {
            write_header(out, raw.len(), RAW, last);
            out.extend_from_slice(raw);
        }
    }
}

fn write_header(out: &mut Vec<u8>, size: usize, kind: u8, last: bool) {
    let word = (size as u32) << 3 | u32::from(kind) << 1 | u32::from(last);
    out.extend_from_slice(&word.to_le_bytes()[..3]);
}

/// Build a `Compressed_Block` body: the literals section, then the sequences.
fn compressed_body(
    input: &[u8],
    start: usize,
    end: usize,
    parse: &[Match],
    history: &mut History,
) -> Vec<u8> {
    let mut literals = Vec::new();
    let mut coded = Vec::with_capacity(parse.len());
    let mut at = start;
    for seq in parse {
        literals.extend_from_slice(&input[at..at + seq.literal_len]);
        at += seq.literal_len + seq.match_len;
        let offset = history.encode(seq.offset, seq.literal_len);
        coded.push(Coded::new(
            seq.literal_len as u32,
            seq.match_len as u32,
            offset,
        ));
    }
    literals.extend_from_slice(&input[at..end]);

    let mut body = Vec::with_capacity(literals.len() + coded.len() * 4 + 8);
    write_literals(&mut body, &literals);
    sequences::write_section(&mut body, &coded);
    body
}

/// Write the literals section, taking whichever of the three forms is
/// smallest: one repeated byte, Huffman-coded, or stored.
fn write_literals(out: &mut Vec<u8>, literals: &[u8]) {
    if !literals.is_empty() && literals.iter().all(|&b| b == literals[0]) {
        write_literals_header(out, RLE_LITERALS, literals.len(), None);
        out.push(literals[0]);
        return;
    }
    if let Some(content) = huffman::compress(literals) {
        let coded = header_len(literals.len(), Some(content.len())) + content.len();
        if coded < header_len(literals.len(), None) + literals.len() {
            write_literals_header(
                out,
                COMPRESSED_LITERALS,
                literals.len(),
                Some(content.len()),
            );
            out.extend_from_slice(&content);
            return;
        }
    }
    write_literals_header(out, RAW_LITERALS, literals.len(), None);
    out.extend_from_slice(literals);
}

/// Shape of a `Literals_Section_Header`: the size format, how many bits it
/// occupies, how many bits each size field occupies, and the total length
/// in bytes (RFC 8478, section 3.1.1.3.1.1).
fn header_shape(regenerated: usize, compressed: Option<usize>) -> (u8, u32, u32, usize) {
    match compressed {
        // Stored and run-length literals carry one size field.
        None if regenerated < 32 => (0, 1, 5, 1),
        None if regenerated < 4096 => (1, 2, 12, 2),
        None => (3, 2, 20, 3),
        // Huffman-coded literals carry two equal size fields, and this
        // encoder always writes four streams, so the one-stream format 00 is
        // never used.
        Some(size) if regenerated < 1024 && size < 1024 => (1, 2, 10, 3),
        Some(size) if regenerated < 16384 && size < 16384 => (2, 2, 14, 4),
        _ => (3, 2, 18, 5),
    }
}

fn header_len(regenerated: usize, compressed: Option<usize>) -> usize {
    header_shape(regenerated, compressed).3
}

/// Write the header as one little-endian bit field, lowest field first.
fn write_literals_header(
    out: &mut Vec<u8>,
    kind: u8,
    regenerated: usize,
    compressed: Option<usize>,
) {
    let (format, format_bits, size_bits, bytes) = header_shape(regenerated, compressed);
    let mut word =
        u64::from(kind) | u64::from(format) << 2 | (regenerated as u64) << (2 + format_bits);
    if let Some(size) = compressed {
        word |= (size as u64) << (2 + format_bits + size_bits);
    }
    out.extend_from_slice(&word.to_le_bytes()[..bytes]);
}
