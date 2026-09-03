//! Finite State Entropy encoding against a fixed normalized distribution.
//!
//! The format defines FSE from the decoder's side (RFC 8478, section 4.1): a
//! table of `1 << accuracy_log` cells, each holding a symbol, a bit count
//! and a baseline, with `next_state = baseline + read(bits)`. Encoding is
//! that relation run backwards. The cells carrying one symbol have
//! `[baseline, baseline + 2^bits)` ranges that partition the whole state
//! space, so for any state the decoder should move *to* there is exactly one
//! cell it can have come *from*, and the bits to write are the distance from
//! that cell's baseline.
//!
//! Only the three predefined distributions of section 3.1.1.3.2.2 are built
//! here, so no table description is ever written into a block.

use alloc::vec;
use alloc::vec::Vec;

/// Literals-length default distribution (RFC 8478, section 3.1.1.3.2.2.1).
pub(super) const LL_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
/// Accuracy log of the predefined literals-length table.
pub(super) const LL_LOG: u32 = 6;

/// Match-length default distribution (RFC 8478, section 3.1.1.3.2.2.2).
pub(super) const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
/// Accuracy log of the predefined match-length table.
pub(super) const ML_LOG: u32 = 6;

/// Offset-code default distribution (RFC 8478, section 3.1.1.3.2.2.3).
pub(super) const OF_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
/// Accuracy log of the predefined offset-code table.
pub(super) const OF_LOG: u32 = 5;

/// Largest offset code the predefined offset table can represent.
pub(super) const OF_MAX_CODE: u32 = OF_DEFAULT.len() as u32 - 1;

/// One cell of the decoding table.
#[derive(Clone, Copy, Default)]
struct Cell {
    symbol: u16,
    bits: u32,
    baseline: u16,
}

/// One step of the encoder: where the decoder came from, and how to say so.
#[derive(Clone, Copy, Default)]
pub(super) struct Step {
    /// State the decoder must hold to emit this symbol.
    pub(super) state: u16,
    /// Baseline to subtract from the target state to get the bits to write.
    pub(super) baseline: u16,
    /// How many bits that difference occupies.
    pub(super) bits: u32,
}

/// Encoding tables derived from one normalized distribution.
pub(super) struct Encoder {
    size: usize,
    /// `size` steps per symbol, indexed `symbol * size + target_state`.
    steps: Vec<Step>,
    /// State each symbol is encoded from when it is the last of a stream.
    initial: Vec<u16>,
}

impl Encoder {
    /// Build the tables for `dist`, normalized to `1 << log`.
    ///
    /// `dist` uses the format's convention: a positive entry is a cell count,
    /// and -1 means "less than one", a symbol that still gets one cell but
    /// whose cell resets the state completely.
    pub(super) fn new(dist: &[i16], log: u32) -> Self {
        let size = 1usize << log;
        let table = build_table(dist, log);

        let mut cells_of: Vec<Vec<u16>> = vec![Vec::new(); dist.len()];
        for (state, cell) in table.iter().enumerate() {
            cells_of[cell.symbol as usize].push(state as u16);
        }

        let mut steps = vec![Step::default(); dist.len() * size];
        let mut initial = vec![0u16; dist.len()];
        for (symbol, states) in cells_of.iter().enumerate() {
            let Some(&first) = states.first() else {
                continue;
            };
            initial[symbol] = first;
            for &state in states {
                let cell = table[state as usize];
                let width = 1usize << cell.bits;
                let base = cell.baseline as usize;
                let step = Step {
                    state,
                    baseline: cell.baseline,
                    bits: cell.bits,
                };
                steps[symbol * size + base..symbol * size + base + width].fill(step);
            }
        }

        Self {
            size,
            steps,
            initial,
        }
    }

    /// The step that leaves the decoder in `target` after emitting `symbol`.
    pub(super) fn step(&self, symbol: u32, target: u16) -> Step {
        self.steps[symbol as usize * self.size + target as usize]
    }

    /// State to start from when `symbol` is the last one in the stream.
    pub(super) fn initial_state(&self, symbol: u32) -> u16 {
        self.initial[symbol as usize]
    }
}

/// Construct the decoding table `dist` describes (RFC 8478, section 4.1.1).
fn build_table(dist: &[i16], log: u32) -> Vec<Cell> {
    let size = 1usize << log;
    let mask = size - 1;
    let mut symbol_of = vec![0u16; size];

    // "Less than one" symbols take one cell each from the end of the table,
    // retreating. Those cells are then skipped by the spread below.
    let mut reserved = size;
    for (symbol, &p) in dist.iter().enumerate() {
        if p < 0 {
            reserved -= 1;
            symbol_of[reserved] = symbol as u16;
        }
    }

    let stride = (size >> 1) + (size >> 3) + 3;
    let mut pos = 0usize;
    for (symbol, &p) in dist.iter().enumerate() {
        for _ in 0..p.max(0) {
            symbol_of[pos] = symbol as u16;
            loop {
                pos = (pos + stride) & mask;
                if pos < reserved {
                    break;
                }
            }
        }
    }

    let mut cells_of: Vec<Vec<u16>> = vec![Vec::new(); dist.len()];
    for (state, &symbol) in symbol_of.iter().enumerate() {
        cells_of[symbol as usize].push(state as u16);
    }

    let mut table = vec![Cell::default(); size];
    for (symbol, states) in cells_of.iter().enumerate() {
        if states.is_empty() {
            continue;
        }
        // A symbol holding `count` cells is given `count.next_power_of_two()`
        // equal shares of the state space; the lowest cells absorb the
        // shortfall by taking two shares each, hence one extra bit.
        let count = states.len();
        let shares = count.next_power_of_two();
        let wide = shares - count;
        let narrow_bits = log - shares.trailing_zeros();
        // Baselines run upwards from the first narrow cell and wrap, which
        // is what puts the widest ranges on the lowest states.
        let mut base = 0usize;
        for k in 0..count {
            let index = (wide + k) % count;
            let bits = if index < wide {
                narrow_bits + 1
            } else {
                narrow_bits
            };
            table[states[index] as usize] = Cell {
                symbol: symbol as u16,
                bits,
                baseline: base as u16,
            };
            base += 1usize << bits;
        }
        debug_assert_eq!(base, size);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected decoding tables from RFC 8478, Appendix A, as
    /// `(symbol, number_of_bits, baseline)` indexed by state.
    #[rustfmt::skip]
    const LITERAL_LENGTH_TABLE: [(u16, u32, u16); 64] = [
        (0, 4, 0), (0, 4, 16), (1, 5, 32), (3, 5, 0), (4, 5, 0), (6, 5, 0), (7, 5,
        0), (9, 5, 0), (10, 5, 0), (12, 5, 0), (14, 6, 0), (16, 5, 0), (18, 5, 0),
        (19, 5, 0), (21, 5, 0), (22, 5, 0), (24, 5, 0), (25, 5, 32), (26, 5, 0),
        (27, 6, 0), (29, 6, 0), (31, 6, 0), (0, 4, 32), (1, 4, 0), (2, 5, 0), (4, 5,
        32), (5, 5, 0), (7, 5, 32), (8, 5, 0), (10, 5, 32), (11, 5, 0), (13, 6, 0),
        (16, 5, 32), (17, 5, 0), (19, 5, 32), (20, 5, 0), (22, 5, 32), (23, 5, 0),
        (25, 4, 0), (25, 4, 16), (26, 5, 32), (28, 6, 0), (30, 6, 0), (0, 4, 48),
        (1, 4, 16), (2, 5, 32), (3, 5, 32), (5, 5, 32), (6, 5, 32), (8, 5, 32), (9,
        5, 32), (11, 5, 32), (12, 5, 32), (15, 6, 0), (17, 5, 32), (18, 5, 32), (20,
        5, 32), (21, 5, 32), (23, 5, 32), (24, 5, 32), (35, 6, 0), (34, 6, 0), (33,
        6, 0), (32, 6, 0)
    ];

    #[rustfmt::skip]
    const MATCH_LENGTH_TABLE: [(u16, u32, u16); 64] = [
        (0, 6, 0), (1, 4, 0), (2, 5, 32), (3, 5, 0), (5, 5, 0), (6, 5, 0), (8, 5,
        0), (10, 6, 0), (13, 6, 0), (16, 6, 0), (19, 6, 0), (22, 6, 0), (25, 6, 0),
        (28, 6, 0), (31, 6, 0), (33, 6, 0), (35, 6, 0), (37, 6, 0), (39, 6, 0), (41,
        6, 0), (43, 6, 0), (45, 6, 0), (1, 4, 16), (2, 4, 0), (3, 5, 32), (4, 5, 0),
        (6, 5, 32), (7, 5, 0), (9, 6, 0), (12, 6, 0), (15, 6, 0), (18, 6, 0), (21,
        6, 0), (24, 6, 0), (27, 6, 0), (30, 6, 0), (32, 6, 0), (34, 6, 0), (36, 6,
        0), (38, 6, 0), (40, 6, 0), (42, 6, 0), (44, 6, 0), (1, 4, 32), (1, 4, 48),
        (2, 4, 16), (4, 5, 32), (5, 5, 32), (7, 5, 32), (8, 5, 32), (11, 6, 0), (14,
        6, 0), (17, 6, 0), (20, 6, 0), (23, 6, 0), (26, 6, 0), (29, 6, 0), (52, 6,
        0), (51, 6, 0), (50, 6, 0), (49, 6, 0), (48, 6, 0), (47, 6, 0), (46, 6, 0)
    ];

    #[rustfmt::skip]
    const OFFSET_TABLE: [(u16, u32, u16); 32] = [
        (0, 5, 0), (6, 4, 0), (9, 5, 0), (15, 5, 0), (21, 5, 0), (3, 5, 0), (7, 4,
        0), (12, 5, 0), (18, 5, 0), (23, 5, 0), (5, 5, 0), (8, 4, 0), (14, 5, 0),
        (20, 5, 0), (2, 5, 0), (7, 4, 16), (11, 5, 0), (17, 5, 0), (22, 5, 0), (4,
        5, 0), (8, 4, 16), (13, 5, 0), (19, 5, 0), (1, 5, 0), (6, 4, 16), (10, 5,
        0), (16, 5, 0), (28, 5, 0), (27, 5, 0), (26, 5, 0), (25, 5, 0), (24, 5, 0)
    ];

    fn check(dist: &[i16], log: u32, expected: &[(u16, u32, u16)]) {
        let table = build_table(dist, log);
        for (state, (cell, want)) in table.iter().zip(expected).enumerate() {
            assert_eq!(
                (cell.symbol, cell.bits, cell.baseline),
                *want,
                "state {state}"
            );
        }
        assert_eq!(table.len(), expected.len());
    }

    #[test]
    fn predefined_tables_match_the_rfc() {
        check(&LL_DEFAULT, LL_LOG, &LITERAL_LENGTH_TABLE);
        check(&ML_DEFAULT, ML_LOG, &MATCH_LENGTH_TABLE);
        check(&OF_DEFAULT, OF_LOG, &OFFSET_TABLE);
    }

    /// Every step must name a cell that really does decode to that symbol
    /// and really does cover the target state.
    #[test]
    fn steps_invert_the_tables() {
        for (dist, log) in [
            (&LL_DEFAULT[..], LL_LOG),
            (&ML_DEFAULT[..], ML_LOG),
            (&OF_DEFAULT[..], OF_LOG),
        ] {
            let table = build_table(dist, log);
            let encoder = Encoder::new(dist, log);
            let size = 1u16 << log;
            for (symbol, &p) in dist.iter().enumerate() {
                if p == 0 {
                    continue;
                }
                for target in 0..size {
                    let step = encoder.step(symbol as u32, target);
                    let cell = table[step.state as usize];
                    assert_eq!(cell.symbol as usize, symbol);
                    assert_eq!(cell.baseline, step.baseline);
                    assert_eq!(cell.bits, step.bits);
                    assert!(target >= step.baseline);
                    assert!(u32::from(target - step.baseline) < 1 << step.bits);
                }
                assert_eq!(
                    table[encoder.initial_state(symbol as u32) as usize].symbol as usize,
                    symbol
                );
            }
        }
    }
}
