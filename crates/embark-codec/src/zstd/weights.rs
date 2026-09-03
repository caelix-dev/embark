//! FSE-compressed Huffman weight header (RFC 8478, section 4.2.1.2).
//!
//! The direct header packs one weight per nibble and tops out at 128
//! symbols, so any literal above 128 forces this form. The weights are coded
//! against a distribution built for them, written out as a table
//! description, and then entropy-coded by two states sharing that one table:
//! the first takes the even-indexed weights and the second the odd ones.

use alloc::vec::Vec;

use super::bitstream::BitWriter;
use super::fse::Encoder;

/// Accuracy log for the weight distribution. Six is the format's maximum
/// here, and the series is short enough that the table description it costs
/// is repaid by the tighter coding.
const LOG: u32 = 6;

/// Number of distinct weight values, since a weight is at most 11.
const ALPHABET: usize = 12;

/// The header byte states the compressed size in seven bits, so a series
/// that does not fit in 127 bytes cannot use this form at all.
const MAX_SIZE: usize = 127;

/// Compress `weights` into a header body, or `None` if it will not fit.
pub(super) fn compress(weights: &[u8]) -> Option<Vec<u8>> {
    if weights.len() < 2 {
        return None;
    }
    let mut counts = [0u32; ALPHABET];
    for &weight in weights {
        *counts.get_mut(weight as usize)? += 1;
    }
    // A distribution needs two or more symbols with a non-zero probability.
    if counts.iter().filter(|&&c| c > 0).count() < 2 {
        return None;
    }
    let distribution = normalize(&counts);

    let mut description = BitWriter::new();
    write_distribution(&mut description, &distribution);
    let mut out = description.finish_forward();
    out.extend_from_slice(&write_stream(weights, &Encoder::new(&distribution, LOG)));
    (out.len() <= MAX_SIZE).then_some(out)
}

/// Scale `counts` onto `1 << LOG` points, giving every present symbol at
/// least one, then settle the rounding error on the busiest symbols.
fn normalize(counts: &[u32; ALPHABET]) -> [i16; ALPHABET] {
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    let target = 1i32 << LOG;
    let mut normalized = [0i16; ALPHABET];
    let mut used = 0i32;
    for (symbol, &count) in counts.iter().enumerate() {
        if count == 0 {
            continue;
        }
        let scaled = (u64::from(count) * (target as u64) * 2 / total).div_ceil(2);
        let points = (scaled as i32).max(1);
        normalized[symbol] = points as i16;
        used += points;
    }
    // Take from, or give to, whichever symbol currently holds the most
    // points: that is where a one-point change costs the least.
    while used != target {
        let pick = (0..ALPHABET)
            .filter(|&s| normalized[s] > if used > target { 1 } else { 0 })
            .max_by_key(|&s| normalized[s]);
        let Some(symbol) = pick else { break };
        if used > target {
            normalized[symbol] -= 1;
            used -= 1;
        } else {
            normalized[symbol] += 1;
            used += 1;
        }
    }
    normalized
}

/// Write the table description: the accuracy log, then each probability in a
/// field whose width shrinks as the remaining points run out (RFC 8478,
/// section 4.1.1).
fn write_distribution(bw: &mut BitWriter, distribution: &[i16; ALPHABET]) {
    bw.push(LOG - 5, 4);
    let last = distribution
        .iter()
        .rposition(|&points| points != 0)
        .unwrap_or(0);
    let mut remaining = 1i32 << LOG;
    let mut symbol = 0usize;
    while symbol <= last {
        let ceiling = (remaining + 1) as u32;
        let bits = u32::BITS - ceiling.leading_zeros();
        // Values below the threshold are one bit shorter, which is what lets
        // the field width fall between powers of two.
        let threshold = (1u32 << bits) - 1 - ceiling;
        let value = (distribution[symbol] + 1) as u32;
        if value < threshold {
            bw.push(value, bits - 1);
        } else if value < 1 << (bits - 1) {
            bw.push(value, bits);
        } else {
            bw.push(value + threshold, bits);
        }
        remaining -= i32::from(distribution[symbol]);

        if distribution[symbol] == 0 {
            // A zero is followed by a repeat count of further zeroes, in
            // two-bit groups, where a full group means another one follows.
            let mut run = 0usize;
            while symbol + 1 + run <= last && distribution[symbol + 1 + run] == 0 {
                run += 1;
            }
            symbol += run;
            loop {
                if run >= 3 {
                    bw.push(3, 2);
                    run -= 3;
                } else {
                    bw.push(run as u32, 2);
                    break;
                }
            }
        }
        symbol += 1;
    }
}

/// Entropy-code the weight series with two interleaved states.
///
/// The decoder reads backwards, so this walks the series from the end: the
/// two states start on the last two weights and no bits are written for
/// them, and the initial states go in last so they come out first.
fn write_stream(weights: &[u8], encoder: &Encoder) -> Vec<u8> {
    let count = weights.len();
    let mut bw = BitWriter::new();
    let mut state = [0u16; 2];
    state[(count - 1) % 2] = encoder.initial_state(u32::from(weights[count - 1]));
    state[(count - 2) % 2] = encoder.initial_state(u32::from(weights[count - 2]));
    for (index, &weight) in weights[..count - 2].iter().enumerate().rev() {
        let slot = index % 2;
        let step = encoder.step(u32::from(weight), state[slot]);
        bw.push(u32::from(state[slot] - step.baseline), step.bits);
        state[slot] = step.state;
    }
    bw.push(u32::from(state[1]), LOG);
    bw.push(u32::from(state[0]), LOG);
    bw.finish()
}
