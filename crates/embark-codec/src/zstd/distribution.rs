//! Normalized FSE distributions and the table descriptions that carry them
//! (RFC 8478, section 4.1.1).

use alloc::vec;
use alloc::vec::Vec;

use super::bitstream::BitWriter;

/// Scale `counts` onto `1 << log` points, giving every symbol that occurs at
/// least one point, then settle the rounding error on the busiest symbols.
///
/// Every present symbol keeps a real probability, so the "less than one"
/// encoding is never needed. That costs a little precision on rare symbols
/// and needs `1 << log` to be at least the number of present symbols, which
/// callers pick `log` to guarantee.
pub(super) fn normalize(counts: &[u32], log: u32) -> Vec<i16> {
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    let target = 1i32 << log;
    let mut normalized = vec![0i16; counts.len()];
    let mut used = 0i32;
    for (symbol, &count) in counts.iter().enumerate() {
        if count == 0 {
            continue;
        }
        let scaled = (u64::from(count) * target as u64 * 2 / total).div_ceil(2);
        let points = (scaled as i32).max(1);
        normalized[symbol] = points as i16;
        used += points;
    }
    // Take from, or give to, whichever symbol currently holds the most
    // points: that is where a one-point change costs the least.
    while used != target {
        let floor = i16::from(used > target);
        let Some(symbol) = (0..counts.len())
            .filter(|&s| normalized[s] > floor)
            .max_by_key(|&s| normalized[s])
        else {
            break;
        };
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

/// Write a table description: the accuracy log, then each probability in a
/// field whose width shrinks as the remaining points run out.
pub(super) fn write_description(bw: &mut BitWriter, distribution: &[i16], log: u32) {
    bw.push(log - 5, 4);
    let last = distribution
        .iter()
        .rposition(|&points| points != 0)
        .unwrap_or(0);
    let mut remaining = 1i32 << log;
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

/// Serialize a table description on its own.
pub(super) fn describe(distribution: &[i16], log: u32) -> Vec<u8> {
    let mut bw = BitWriter::new();
    write_description(&mut bw, distribution, log);
    bw.finish_forward()
}

/// Base-2 logarithm in 1/256ths, interpolated linearly inside each octave.
///
/// Only used to compare two candidate tables, where an error of a
/// hundredth of a bit cannot change the answer.
pub(super) fn log2_fixed(value: u32) -> u32 {
    debug_assert!(value > 0);
    let msb = u32::BITS - 1 - value.leading_zeros();
    let fraction = if msb >= 8 {
        value >> (msb - 8)
    } else {
        value << (8 - msb)
    };
    msb * 256 + (fraction & 0xff)
}
