//! Hash-chain match finder and the repeat-offset rules the parser needs.

use alloc::vec;
use alloc::vec::Vec;

/// Shortest match worth reporting, and the number of bytes the chain hashes.
pub(super) const MIN_MATCH: usize = 4;
/// Shortest match the parser will consider at all. Three-byte matches come
/// from their own table, and at a repeat offset the offset is nearly free.
pub(super) const MIN_SHORT_MATCH: usize = 3;
/// Shortest match the parser will take at a repeat offset, where naming the
/// offset costs almost nothing.
pub(super) const MIN_REPEAT_MATCH: usize = MIN_SHORT_MATCH;
/// Longest match emitted, so that one sequence always fits in one block.
pub(super) const MAX_MATCH: usize = 1 << 16;
/// Empty slot in the hash tables.
const NONE: u32 = u32::MAX;

/// One parsed sequence: literals to copy out, then a match to copy back.
#[derive(Clone, Copy)]
pub(super) struct Match {
    pub(super) literal_len: usize,
    pub(super) match_len: usize,
    /// Distance back from the end of the literals, in bytes.
    pub(super) offset: usize,
}

/// Search effort, derived from the searchable span in [`Params::for_input`].
pub(super) struct Params {
    pub(super) hash_bits: u32,
    pub(super) depth: u32,
    /// A match at least this long is taken without looking for a better
    /// parse through the middle of it.
    pub(super) nice_len: usize,
}

impl Params {
    /// `window` is the match window; positions older than that are out of
    /// reach, so it, not the whole input, bounds how many keys the table has
    /// to keep apart.
    pub(super) fn for_input(len: usize, window: usize) -> Self {
        // One bucket per live position. Undersizing this is expensive
        // in a way that is invisible in the output: the buckets still hold
        // every candidate, the chains behind them just get longer, so the
        // encoder walks more entries to reach the same matches. Measured on
        // 4 MiB of poorly compressible data, raising the ceiling from 18 to
        // 22 cut encode time by half and changed the output by zero bytes.
        //
        // The ceiling is a memory bound: the table is `4 << hash_bits`
        // bytes, so 22 costs 16 MiB. It only exists at build time, next to a
        // chain array that is already window-sized.
        let searchable = len.min(window);
        Self {
            hash_bits: ceil_log2(searchable).clamp(10, 22),
            depth: 64,
            nice_len: 192,
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

pub(super) struct HashChain {
    head: Vec<u32>,
    chain: Vec<u32>,
    /// Most recent position for each three-byte key, with no chain behind
    /// it. Short matches are only worth taking when they are close, so the
    /// latest one is the only one worth remembering.
    short: Vec<u32>,
    hash_bits: u32,
    short_bits: u32,
    chain_mask: usize,
    /// Positions below this have been inserted.
    filled: usize,
}

impl HashChain {
    pub(super) fn new(len: usize, window: usize, hash_bits: u32) -> Self {
        // The chain only has to remember one window of positions: a slot can
        // be reused once the position that holds it has dropped out of
        // reach, which is exactly when the window has moved past it.
        let chain_size = window.min(len).max(1).next_power_of_two();
        let short_bits = hash_bits.min(17);
        Self {
            head: vec![NONE; 1usize << hash_bits],
            chain: vec![NONE; chain_size],
            short: vec![NONE; 1usize << short_bits],
            hash_bits,
            short_bits,
            chain_mask: chain_size - 1,
            filled: 0,
        }
    }

    fn hash(&self, input: &[u8], pos: usize) -> usize {
        let word = u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
        (word.wrapping_mul(2_654_435_761) >> (32 - self.hash_bits)) as usize
    }

    /// Same key, three bytes wide. A whole four-byte word is always readable
    /// where this is called, so the fourth byte is simply masked away.
    fn short_hash(&self, input: &[u8], pos: usize) -> usize {
        let word = u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
        ((word & 0x00ff_ffff).wrapping_mul(2_654_435_761) >> (32 - self.short_bits)) as usize
    }

    /// Insert every position below `upto` that is not in yet.
    pub(super) fn fill_to(&mut self, input: &[u8], upto: usize) {
        // A position is only hashable while a whole key still follows it.
        let end = upto.min((input.len() + 1).saturating_sub(MIN_MATCH));
        while self.filled < end {
            let slot = self.hash(input, self.filled);
            self.chain[self.filled & self.chain_mask] = self.head[slot];
            self.head[slot] = self.filled as u32;
            let short = self.short_hash(input, self.filled);
            self.short[short] = self.filled as u32;
            self.filled += 1;
        }
    }

    /// Collect the longest match at each distance the chain offers, nearest
    /// first, as `(length, offset)` pairs of strictly increasing length.
    ///
    /// The chain runs from the most recent position backwards, so the first
    /// candidate to reach a given length is also the cheapest offset that
    /// reaches it, and a shorter match can always be had from the same
    /// offset by truncation. That makes this list everything the parser
    /// needs to price every length available here.
    pub(super) fn candidates(
        &self,
        input: &[u8],
        pos: usize,
        floor: usize,
        limit: usize,
        params: &Params,
        out: &mut Vec<(u32, u32)>,
    ) {
        if limit < MIN_SHORT_MATCH || pos + MIN_MATCH > input.len() {
            return;
        }
        // The three-byte table first, capped at three so it only ever claims
        // the length the chain cannot reach. On data whose literals barely
        // compress, a match this short still pays for itself.
        let short = self.short[self.short_hash(input, pos)];
        if short != NONE {
            let at = short as usize;
            if at >= floor && at < pos && common_prefix(input, at, pos, limit) >= MIN_SHORT_MATCH {
                out.push((MIN_SHORT_MATCH as u32, (pos - at) as u32));
            }
        }
        if limit < MIN_MATCH {
            return;
        }
        let mut best_len = 0usize;
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
                if len > best_len && len >= MIN_MATCH {
                    best_len = len;
                    out.push((len as u32, (pos - at) as u32));
                    if len >= limit || len >= params.nice_len {
                        break;
                    }
                }
            }
            candidate = self.chain[at & self.chain_mask];
        }
    }
}

pub(super) fn common_prefix(input: &[u8], a: usize, b: usize, limit: usize) -> usize {
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

/// Pick the cheapest encoding of `offset` and return it with the repeat
/// history the decoder will hold afterwards (RFC 8478, section 3.1.1.5).
///
/// The two halves have to stay together: which of the three repeat codes
/// fits depends on whether any literals precede the match, and each code
/// reorders the history differently, so choosing a code and then updating
/// the history under a different assumption would silently desynchronize the
/// encoder from the decoder.
pub(super) fn encode_offset(
    repeats: [usize; 3],
    offset: usize,
    literal_len: usize,
) -> (u32, [usize; 3]) {
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
    let advanced = match (literal_len > 0, value) {
        // The most recent offset, reused: the history is already in order.
        (true, 1) => repeats,
        // The second most recent, which trades places with the first.
        (true, 2) | (false, 1) => [repeats[1], repeats[0], repeats[2]],
        // Anything else takes the lead and pushes the rest back.
        _ => [offset, repeats[0], repeats[1]],
    };
    (value as u32, advanced)
}

/// The offsets that a repeat code can name from this history, cheapest
/// first. With no literals in front the codes shift by one, and the third
/// names one byte less than the most recent offset.
pub(super) fn repeat_candidates(repeats: [usize; 3], literal_len: usize) -> [usize; 3] {
    if literal_len > 0 {
        repeats
    } else {
        [repeats[1], repeats[2], repeats[0].saturating_sub(1)]
    }
}
