//! Block segmentation and serialization (RFC 8478, sections 3.1.1.2 and
//! 3.1.1.3).

use alloc::vec::Vec;

use super::matcher::Match;
use super::sequences::{self, Coded, Tables};

/// Largest decompressed size of one block.
pub(super) const MAX_BLOCK: usize = 128 * 1024;

const RAW: u8 = 0;
const RLE: u8 = 1;
const COMPRESSED: u8 = 2;

/// One block: an input range and the sequences that reconstruct it.
struct Chunk {
    start: usize,
    end: usize,
    seqs: Vec<Match>,
}

/// Write every block of the frame, marking the last one.
pub(super) fn write_all(out: &mut Vec<u8>, input: &[u8], matches: &[Match]) {
    let chunks = plan(input.len(), matches);
    let tables = Tables::new();
    for (i, chunk) in chunks.iter().enumerate() {
        write_one(out, input, chunk, &tables, i + 1 == chunks.len());
    }
}

/// Cut the sequence stream into blocks of at most [`MAX_BLOCK`] bytes.
///
/// A block boundary can only fall between sequences or inside a run of
/// literals, so a literal run longer than a block is split and its tail
/// carried into the next one. Matches are already capped short enough to
/// always fit in a fresh block.
fn plan(len: usize, matches: &[Match]) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut cursor = 0usize;
    let mut next = 0usize;
    let mut carried: Option<usize> = None;
    while cursor < len {
        let start = cursor;
        let mut budget = MAX_BLOCK;
        let mut seqs = Vec::new();
        loop {
            let Some(m) = matches.get(next) else {
                let take = budget.min(len - cursor);
                cursor += take;
                break;
            };
            let literal_len = carried.unwrap_or(m.literal_len);
            if literal_len + m.match_len <= budget {
                budget -= literal_len + m.match_len;
                cursor += literal_len + m.match_len;
                seqs.push(Match {
                    literal_len,
                    match_len: m.match_len,
                    offset: m.offset,
                });
                next += 1;
                carried = None;
                if budget == 0 {
                    break;
                }
            } else {
                let take = budget.min(literal_len);
                cursor += take;
                carried = Some(literal_len - take);
                break;
            }
        }
        chunks.push(Chunk {
            start,
            end: cursor,
            seqs,
        });
    }
    chunks
}

fn write_one(out: &mut Vec<u8>, input: &[u8], chunk: &Chunk, tables: &Tables, last: bool) {
    let raw = &input[chunk.start..chunk.end];
    // One repeated byte costs a single byte as an RLE block, which nothing
    // else can beat, so that case never needs the sequence encoder.
    if !raw.is_empty() && raw.iter().all(|&b| b == raw[0]) {
        write_header(out, raw.len(), RLE, last);
        out.push(raw[0]);
        return;
    }
    let body = compressed_body(input, chunk, tables);
    // A `Compressed_Block` is only legal when it is strictly smaller than what
    // it stands for, which is also the only case in which it is worth using.
    if body.len() < raw.len() {
        write_header(out, body.len(), COMPRESSED, last);
        out.extend_from_slice(&body);
    } else {
        write_header(out, raw.len(), RAW, last);
        out.extend_from_slice(raw);
    }
}

fn write_header(out: &mut Vec<u8>, size: usize, kind: u8, last: bool) {
    let word = (size as u32) << 3 | u32::from(kind) << 1 | u32::from(last);
    out.extend_from_slice(&word.to_le_bytes()[..3]);
}

/// Build a `Compressed_Block` body: the literals section, then the sequences.
fn compressed_body(input: &[u8], chunk: &Chunk, tables: &Tables) -> Vec<u8> {
    let mut literals = Vec::new();
    let mut coded = Vec::with_capacity(chunk.seqs.len());
    let mut at = chunk.start;
    for seq in &chunk.seqs {
        literals.extend_from_slice(&input[at..at + seq.literal_len]);
        at += seq.literal_len + seq.match_len;
        // Offset values 1 to 3 name repeat offsets, so a literal distance is
        // written three higher (RFC 8478, section 3.1.1.3.2.1.1).
        coded.push(Coded::new(
            seq.literal_len as u32,
            seq.match_len as u32,
            seq.offset as u32 + 3,
        ));
    }
    literals.extend_from_slice(&input[at..chunk.end]);

    let mut body = Vec::with_capacity(literals.len() + coded.len() * 4 + 8);
    write_literals(&mut body, &literals);
    sequences::write_section(&mut body, &coded, tables);
    body
}

/// Write a `Raw_Literals_Block`, or an RLE one when every literal is the same
/// byte (RFC 8478, section 3.1.1.3.1.1).
fn write_literals(out: &mut Vec<u8>, literals: &[u8]) {
    let regenerated = literals.len();
    let uniform = !literals.is_empty() && literals.iter().all(|&b| b == literals[0]);
    let kind = if uniform { 1u8 } else { 0u8 };
    if regenerated < 32 {
        out.push((regenerated as u8) << 3 | kind);
    } else if regenerated < 4096 {
        out.push(((regenerated as u8) & 0xf) << 4 | 1 << 2 | kind);
        out.push((regenerated >> 4) as u8);
    } else {
        out.push(((regenerated as u8) & 0xf) << 4 | 3 << 2 | kind);
        out.push((regenerated >> 4) as u8);
        out.push((regenerated >> 12) as u8);
    }
    if uniform {
        out.push(literals[0]);
    } else {
        out.extend_from_slice(literals);
    }
}
