//! LZMA1 encoder: a greedy hash-chain match finder feeding the probability
//! model and range encoder. It emits only literals and *new* matches (never
//! rep matches), which is a valid subset of LZMA1 -- correctness and
//! `xz`-decodable output are the goal here, not maximal ratio.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::model::{LzmaModel, MATCH_MAX_LEN, MATCH_MIN_LEN};
use super::rangecoder::RangeEncoder;

const HASH_BITS: u32 = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NONE: u32 = u32::MAX;
/// Longest hash chain we walk when looking for a match. Bounds worst-case time
/// on highly repetitive input while still finding good matches.
const MAX_CHAIN: u32 = 128;
/// Shortest match we are willing to emit. Two literals are cheaper than a
/// short far match, and the 4-byte hash naturally surfaces matches this long.
const MIN_MATCH: usize = 3;

/// Dictionary size we advertise in the `.lzma` header and cap match distances
/// to: the next power of two at least as large as the input (min 4 KiB), so a
/// decoder with this dictionary can resolve every distance we emit.
pub(crate) fn dict_size(n: usize) -> u32 {
    let base = (n as u32).clamp(1 << 12, 1 << 27);
    base.next_power_of_two()
}

#[inline]
fn hash4(b: &[u8]) -> usize {
    let x = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (x.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

/// Encode `input` into a raw LZMA1 range-coded stream (no `.lzma` header).
pub(crate) fn encode(input: &[u8], dict: u32) -> Vec<u8> {
    let n = input.len();
    let mut rc = RangeEncoder::new();
    let mut model = LzmaModel::new(3, 0, 2);

    let mut state = 0usize;
    let (mut rep0, mut rep1, mut rep2, mut rep3) = (0u32, 0u32, 0u32, 0u32);

    // Hash-chain match finder: `head[h]` is the most recent position with hash
    // `h`; `prev[p]` links to the previous position sharing p's hash.
    let mut head = vec![NONE; HASH_SIZE];
    let mut prev = vec![NONE; n];
    let window = dict as usize;

    let mut i = 0usize;
    while i < n {
        let (mlen, moff) = find_match(input, i, &head, &prev, window);
        let pos_state = model.pos_state(i);

        if mlen >= MIN_MATCH {
            // New match.
            model.encode_is_match(&mut rc, state, pos_state, 1);
            model.encode_is_rep(&mut rc, state, 0);
            rep3 = rep2;
            rep2 = rep1;
            rep1 = rep0;
            let len_sym = mlen - MATCH_MIN_LEN;
            model.encode_new_len(&mut rc, len_sym, pos_state);
            state = if state < 7 { 7 } else { 10 };
            let dist = (moff - 1) as u32;
            model.encode_distance(&mut rc, dist, len_sym);
            rep0 = dist;

            insert_range(input, &mut head, &mut prev, i, i + mlen, n);
            i += mlen;
        } else {
            // Literal.
            model.encode_is_match(&mut rc, state, pos_state, 0);
            let prev_byte = if i == 0 { 0 } else { input[i - 1] };
            let match_byte = if state >= 7 {
                input[i - rep0 as usize - 1]
            } else {
                0
            };
            model.encode_literal(&mut rc, i, prev_byte, state, input[i], match_byte);
            state = if state < 4 {
                0
            } else if state < 10 {
                state - 3
            } else {
                state - 6
            };
            insert(input, &mut head, &mut prev, i, n);
            i += 1;
        }
    }

    // Silence unused-assignment warnings on the trailing rep shuffle.
    let _ = (rep1, rep2, rep3);
    rc.flush();
    rc.out
}

/// Find the longest match for the data at `pos` among earlier positions, using
/// the hash chain. Returns `(len, offset)`; `len < MIN_MATCH` means no usable
/// match. Only positions inside the dictionary `window` are considered.
fn find_match(
    input: &[u8],
    pos: usize,
    head: &[u32],
    prev: &[u32],
    window: usize,
) -> (usize, usize) {
    let n = input.len();
    if pos + 4 > n {
        return (0, 0);
    }
    let max_len = (n - pos).min(MATCH_MAX_LEN);
    let h = hash4(&input[pos..]);
    let mut cand = head[h];
    let mut best_len = 0usize;
    let mut best_off = 0usize;
    let mut chain = MAX_CHAIN;

    while cand != NONE && chain > 0 {
        let c = cand as usize;
        if pos - c > window {
            break;
        }
        // Cheap rejection: only bother comparing if we can beat the best.
        if best_len == 0 || input[c + best_len] == input[pos + best_len] {
            let mut l = 0usize;
            while l < max_len && input[c + l] == input[pos + l] {
                l += 1;
            }
            if l > best_len {
                best_len = l;
                best_off = pos - c;
                if l == max_len {
                    break;
                }
            }
        }
        cand = prev[c];
        chain -= 1;
    }
    (best_len, best_off)
}

#[inline]
fn insert(input: &[u8], head: &mut [u32], prev: &mut [u32], pos: usize, n: usize) {
    if pos + 4 <= n {
        let h = hash4(&input[pos..]);
        prev[pos] = head[h];
        head[h] = pos as u32;
    }
}

fn insert_range(
    input: &[u8],
    head: &mut [u32],
    prev: &mut [u32],
    start: usize,
    end: usize,
    n: usize,
) {
    for p in start..end {
        insert(input, head, prev, p, n);
    }
}
