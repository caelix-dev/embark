//! Hash-chain match finder with lazy evaluation and repeat offsets.

use alloc::vec;
use alloc::vec::Vec;

/// Shortest match the hash chain will report. The format allows three, but
/// the chain is indexed on four bytes; three-byte matches are only taken at
/// a repeat offset, where naming the offset is nearly free.
const MIN_MATCH: usize = 4;
/// Shortest match accepted at the most recent repeat offset.
const MIN_REPEAT_MATCH: usize = 3;
/// Longest match emitted, so that one sequence always fits in one block.
const MAX_MATCH: usize = 1 << 16;
/// Empty slot in the hash tables.
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
    depth: u32,
    nice_len: usize,
    lazy: u32,
}

impl Params {
    pub(super) fn for_input(len: usize) -> Self {
        Self {
            hash_bits: ceil_log2(len).clamp(10, 18),
            depth: 32,
            nice_len: 128,
            lazy: 2,
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

struct HashChain {
    head: Vec<u32>,
    chain: Vec<u32>,
    hash_bits: u32,
    chain_mask: usize,
}

impl HashChain {
    fn new(len: usize, window: usize, hash_bits: u32) -> Self {
        // The chain only has to remember one window of positions: a slot can
        // be reused once the position that holds it has dropped out of
        // reach, which is exactly when the window has moved past it.
        let chain_size = window.min(len).max(1).next_power_of_two();
        Self {
            head: vec![NONE; 1usize << hash_bits],
            chain: vec![NONE; chain_size],
            hash_bits,
            chain_mask: chain_size - 1,
        }
    }

    fn hash(&self, input: &[u8], pos: usize) -> usize {
        let word = u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
        (word.wrapping_mul(2_654_435_761) >> (32 - self.hash_bits)) as usize
    }

    fn insert(&mut self, input: &[u8], pos: usize) {
        let slot = self.hash(input, pos);
        self.chain[pos & self.chain_mask] = self.head[slot];
        self.head[slot] = pos as u32;
    }

    /// Walk the chain for the longest match at `pos`, reaching no further
    /// back than `floor` and no more than `depth` candidates deep.
    fn find(
        &self,
        input: &[u8],
        pos: usize,
        floor: usize,
        params: &Params,
    ) -> Option<(usize, usize)> {
        let limit = (input.len() - pos).min(MAX_MATCH);
        let mut best_len = 0usize;
        let mut best_pos = 0usize;
        let mut candidate = self.head[self.hash(input, pos)];
        for _ in 0..params.depth {
            if candidate == NONE {
                break;
            }
            let at = candidate as usize;
            if at < floor {
                break;
            }
            // Testing the byte that would have to extend the current best
            // rejects most candidates without a full comparison.
            if best_len == 0 || input[at + best_len] == input[pos + best_len] {
                let len = common_prefix(input, at, pos, limit);
                if len > best_len {
                    best_len = len;
                    best_pos = at;
                    if len >= params.nice_len || len >= limit {
                        break;
                    }
                }
            }
            candidate = self.chain[at & self.chain_mask];
        }
        (best_len >= MIN_MATCH).then(|| (best_len, pos - best_pos))
    }
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

#[derive(Clone, Copy)]
struct Candidate {
    len: usize,
    offset: usize,
    /// Rough bit cost of naming this offset, used only to rank candidates.
    offset_bits: u32,
}

impl Candidate {
    fn score(self) -> i64 {
        self.len as i64 * 4 - i64::from(self.offset_bits)
    }
}

/// Parse `input` into sequences, taking matches no further back than
/// `max_offset` bytes.
pub(super) fn parse(input: &[u8], max_offset: usize, params: &Params) -> Vec<Match> {
    let len = input.len();
    let mut out = Vec::new();
    if len < MIN_MATCH {
        return out;
    }
    let mut chain = HashChain::new(len, max_offset, params.hash_bits);
    let mut inserted = 0usize;
    let mut anchor = 0usize;
    let mut pos = 0usize;
    // Offset history as the decoder will rebuild it (RFC 8478, section
    // 3.1.1.5). The parser keeps it only to know which offsets are cheap.
    let mut repeats = [1usize, 4, 8];

    while pos + MIN_MATCH <= len {
        insert_upto(&mut chain, input, &mut inserted, pos);
        let Some(mut best) = best_at(input, &chain, pos, max_offset, &repeats, params) else {
            pos += 1;
            continue;
        };
        // Lazy evaluation: a match one or two bytes further on is worth
        // waiting for if it more than pays for the literals left behind.
        let mut at = pos;
        for _ in 0..params.lazy {
            if at + 1 + MIN_MATCH > len {
                break;
            }
            insert_upto(&mut chain, input, &mut inserted, at + 1);
            let Some(next) = best_at(input, &chain, at + 1, max_offset, &repeats, params) else {
                break;
            };
            if next.score() <= best.score() + 4 {
                break;
            }
            best = next;
            at += 1;
        }

        let (start, match_len) = extend_back(input, at, anchor, &best, &repeats);
        let literal_len = start - anchor;
        out.push(Match {
            literal_len,
            match_len,
            offset: best.offset,
        });
        encode_offset(&mut repeats, best.offset, literal_len);
        anchor = start + match_len;
        pos = anchor;
    }
    out
}

/// Grow a match backwards over literals it already matches.
///
/// Absorbing literals is free but for one case: a match at the most recent
/// repeat offset loses its one-bit offset code once no literals precede it,
/// because with a literals length of zero that code names the *second*
/// repeat offset instead. There, one literal is held back.
fn extend_back(
    input: &[u8],
    at: usize,
    anchor: usize,
    best: &Candidate,
    repeats: &[usize; 3],
) -> (usize, usize) {
    let floor = if best.offset == repeats[0] {
        anchor + 1
    } else {
        anchor
    };
    let mut start = at;
    let mut len = best.len;
    while start > floor
        && start > best.offset
        && len < MAX_MATCH
        && input[start - 1] == input[start - 1 - best.offset]
    {
        start -= 1;
        len += 1;
    }
    (start, len)
}

fn insert_upto(chain: &mut HashChain, input: &[u8], inserted: &mut usize, upto: usize) {
    let end = upto.min(input.len() - MIN_MATCH + 1);
    while *inserted < end {
        chain.insert(input, *inserted);
        *inserted += 1;
    }
}

fn best_at(
    input: &[u8],
    chain: &HashChain,
    pos: usize,
    max_offset: usize,
    repeats: &[usize; 3],
    params: &Params,
) -> Option<Candidate> {
    let limit = (input.len() - pos).min(MAX_MATCH);
    let mut best: Option<Candidate> = None;

    let repeat = repeats[0];
    if repeat <= pos {
        let len = common_prefix(input, pos - repeat, pos, limit);
        if len >= MIN_REPEAT_MATCH {
            best = Some(Candidate {
                len,
                offset: repeat,
                offset_bits: 2,
            });
        }
    }

    let floor = pos.saturating_sub(max_offset);
    if let Some((len, offset)) = chain.find(input, pos, floor, params) {
        let candidate = Candidate {
            len,
            offset,
            offset_bits: u32::BITS - (offset as u32 + 3).leading_zeros(),
        };
        if best.is_none_or(|b| candidate.score() > b.score()) {
            best = Some(candidate);
        }
    }
    best
}

/// Pick the cheapest encoding of `offset` and advance the repeat history the
/// way the decoder will for that encoding (RFC 8478, section 3.1.1.5).
///
/// The two halves have to stay together: which of the three repeat codes
/// fits depends on whether any literals precede the match, and each code
/// reorders the history differently, so choosing a code and then updating
/// the history under a different assumption would silently desynchronize the
/// encoder from the decoder.
pub(super) fn encode_offset(repeats: &mut [usize; 3], offset: usize, literal_len: usize) -> u32 {
    let value = if literal_len > 0 {
        match offset {
            o if o == repeats[0] => 1,
            o if o == repeats[1] => 2,
            o if o == repeats[2] => 3,
            o => o + 3,
        }
    } else {
        match offset {
            o if o == repeats[1] => 1,
            o if o == repeats[2] => 2,
            o if repeats[0] > 1 && o == repeats[0] - 1 => 3,
            o => o + 3,
        }
    };
    match (literal_len > 0, value) {
        // The most recent offset, reused: the history is already in order.
        (true, 1) => {}
        // The second most recent, which trades places with the first.
        (true, 2) | (false, 1) => repeats.swap(0, 1),
        // Anything else takes the lead and pushes the rest back.
        _ => *repeats = [offset, repeats[0], repeats[1]],
    }
    value as u32
}
