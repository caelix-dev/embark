//! FSE-compressed Huffman weight header (RFC 8478, section 4.2.1.2).
//!
//! The direct header packs one weight per nibble and tops out at 128
//! symbols, so any literal above 128 forces this form. The weights are coded
//! against a distribution built for them, written out as a table
//! description, and then entropy-coded by two states sharing that one table:
//! the first takes the even-indexed weights and the second the odd ones.

use alloc::vec::Vec;

use super::bitstream::BitWriter;
use super::distribution;
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
    let normalized = distribution::normalize(&counts, LOG);

    let mut out = distribution::describe(&normalized, LOG);
    out.extend_from_slice(&write_stream(weights, &Encoder::new(&normalized, LOG)));
    (out.len() <= MAX_SIZE).then_some(out)
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
