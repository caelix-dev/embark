//! Greedy match finder over a single-slot hash table.

use alloc::vec;
use alloc::vec::Vec;

/// Shortest match worth emitting, and the number of bytes the table hashes.
const MIN_MATCH: usize = 4;
/// Longest match emitted, so that one sequence always fits in one block.
const MAX_MATCH: usize = 1 << 16;
/// Empty slot in the hash table.
const NONE: u32 = u32::MAX;

/// One parsed sequence: literals to copy out, then a match to copy back.
pub(super) struct Match {
    pub(super) literal_len: usize,
    pub(super) match_len: usize,
    /// Distance back from the end of the literals, in bytes.
    pub(super) offset: usize,
}

/// Search effort, derived from the input size in [`Params::for_input`].
pub(super) struct Params {
    hash_bits: u32,
}

impl Params {
    pub(super) fn for_input(len: usize) -> Self {
        Self {
            hash_bits: ceil_log2(len).clamp(10, 18),
        }
    }
}

fn ceil_log2(n: usize) -> u32 {
    if n <= 1 {
        0
    } else {
        usize::BITS - (n - 1).leading_zeros()
    }
}

fn hash(input: &[u8], pos: usize, bits: u32) -> usize {
    let word = u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
    (word.wrapping_mul(2_654_435_761) >> (32 - bits)) as usize
}

fn common_prefix(input: &[u8], a: usize, b: usize, limit: usize) -> usize {
    let mut len = 0usize;
    while len + 8 <= limit {
        let x = u64::from_le_bytes(input[a + len..a + len + 8].try_into().unwrap_or_default());
        let y = u64::from_le_bytes(input[b + len..b + len + 8].try_into().unwrap_or_default());
        if x != y {
            return len + ((x ^ y).trailing_zeros() / 8) as usize;
        }
        len += 8;
    }
    while len < limit && input[a + len] == input[b + len] {
        len += 1;
    }
    len
}

/// Parse `input` into sequences, taking matches no further back than
/// `max_offset` bytes.
pub(super) fn parse(input: &[u8], max_offset: usize, params: &Params) -> Vec<Match> {
    let len = input.len();
    let mut out = Vec::new();
    if len < MIN_MATCH {
        return out;
    }
    let last_hashable = len - MIN_MATCH + 1;
    let mut table = vec![NONE; 1usize << params.hash_bits];
    let mut anchor = 0usize;
    let mut pos = 0usize;

    while pos < last_hashable {
        let slot = hash(input, pos, params.hash_bits);
        let candidate = table[slot];
        table[slot] = pos as u32;
        if candidate != NONE {
            let at = candidate as usize;
            let match_len = if pos - at <= max_offset {
                common_prefix(input, at, pos, (len - pos).min(MAX_MATCH))
            } else {
                0
            };
            if match_len >= MIN_MATCH {
                out.push(Match {
                    literal_len: pos - anchor,
                    match_len,
                    offset: pos - at,
                });
                // Positions covered by the match still have to reach the
                // table, or every match hides the text it just matched.
                for inside in pos + 1..(pos + match_len).min(last_hashable) {
                    table[hash(input, inside, params.hash_bits)] = inside as u32;
                }
                pos += match_len;
                anchor = pos;
                continue;
            }
        }
        pos += 1;
    }
    out
}
