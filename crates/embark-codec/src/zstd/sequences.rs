//! Sequence codes and the interleaved FSE bitstream of a compressed block.

use alloc::vec;
use alloc::vec::Vec;

use super::bitstream::BitWriter;
use super::distribution;
use super::fse::{self, Encoder, Step};

/// Literals-length baselines (RFC 8478, section 3.1.1.3.2.1.1).
const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
/// Extra bits carried by each literals-length code.
const LL_EXTRA: [u32; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// Match-length baselines (RFC 8478, section 3.1.1.3.2.1.1).
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
/// Extra bits carried by each match-length code.
const ML_EXTRA: [u32; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// Largest accuracy log the format allows for each symbol type.
const LL_MAX_LOG: u32 = 9;
const ML_MAX_LOG: u32 = 9;
const OF_MAX_LOG: u32 = 8;
/// Smallest accuracy log a table description can express.
const MIN_LOG: u32 = 5;

const PREDEFINED: u8 = 0;
const RLE: u8 = 1;
const FSE_COMPRESSED: u8 = 2;

/// One sequence, already reduced to codes and the raw bits that go with them.
pub(super) struct Coded {
    ll_code: u32,
    ll_extra: u32,
    ml_code: u32,
    ml_extra: u32,
    of_code: u32,
    of_extra: u32,
}

impl Coded {
    /// Reduce a literals length, a match length and an offset value.
    ///
    /// `offset_value` is the format's encoding of the offset: 1, 2 and 3
    /// name repeat offsets, and anything larger is a literal distance plus
    /// three (RFC 8478, section 3.1.1.3.2.1.1).
    pub(super) fn new(literal_len: u32, match_len: u32, offset_value: u32) -> Self {
        let ll_code = code_of(&LL_BASE, literal_len);
        let ml_code = code_of(&ML_BASE, match_len);
        let of_code = 31 - offset_value.leading_zeros();
        // The frame's window is capped well below what the predefined
        // offset table covers, so every offset stays representable.
        debug_assert!(of_code <= fse::OF_MAX_CODE);
        Self {
            ll_code,
            ll_extra: literal_len - LL_BASE[ll_code as usize],
            ml_code,
            ml_extra: match_len - ML_BASE[ml_code as usize],
            of_code,
            of_extra: offset_value - (1 << of_code),
        }
    }
}

/// Index of the largest baseline not above `value`.
fn code_of(bases: &[u32], value: u32) -> u32 {
    (bases.partition_point(|&b| b <= value) - 1) as u32
}

/// How one symbol type is entropy-coded in this block.
struct Coder {
    mode: u8,
    /// Absent for RLE mode, which spends no bits: with a single-cell table
    /// the initial state and every update are zero bits wide.
    table: Option<Encoder>,
    log: u32,
    /// The table description, empty unless the mode is `FSE_Compressed`.
    description: Vec<u8>,
}

impl Coder {
    fn initial_state(&self, symbol: u32) -> u16 {
        self.table
            .as_ref()
            .map_or(0, |table| table.initial_state(symbol))
    }

    fn step(&self, symbol: u32, target: u16) -> Step {
        self.table
            .as_ref()
            .map_or_else(Step::default, |table| table.step(symbol, target))
    }

    /// Pick the cheapest of the three modes for a symbol type.
    ///
    /// A single symbol goes RLE, which costs one byte and no bits at all.
    /// Otherwise a table built for this block competes with the predefined
    /// one, paying for its own description.
    fn choose(counts: &[u32], predefined: &[i16], predefined_log: u32, max_log: u32) -> Self {
        let present = counts.iter().filter(|&&c| c > 0).count();
        if present == 1 {
            let symbol = counts.iter().position(|&c| c > 0).unwrap_or(0);
            return Self {
                mode: RLE,
                table: None,
                log: 0,
                description: vec![symbol as u8],
            };
        }

        let last = counts.iter().rposition(|&c| c > 0).unwrap_or(0);
        let mut best: Option<(u64, Self)> = None;
        if last < predefined.len() {
            let cost = estimate(counts, predefined, predefined_log);
            best = Some((
                cost,
                Self {
                    mode: PREDEFINED,
                    table: Some(Encoder::new(predefined, predefined_log)),
                    log: predefined_log,
                    description: Vec::new(),
                },
            ));
        }

        // The table needs at least one cell per present symbol, and a wider
        // table describes the distribution more finely but costs more to
        // describe, so every legal width is tried.
        let floor = ceil_log2(present).max(MIN_LOG);
        for log in floor..=max_log {
            let normalized = distribution::normalize(&counts[..=last], log);
            let description = distribution::describe(&normalized, log);
            let cost = estimate(counts, &normalized, log) + description.len() as u64 * 8 * 256;
            if best.as_ref().is_none_or(|(best_cost, _)| cost < *best_cost) {
                best = Some((
                    cost,
                    Self {
                        mode: FSE_COMPRESSED,
                        table: Some(Encoder::new(&normalized, log)),
                        log,
                        description,
                    },
                ));
            }
        }
        // Every alphabet here has at least two symbols and at most 512
        // cells, so some width always fits.
        best.map_or_else(
            || Self {
                mode: PREDEFINED,
                table: Some(Encoder::new(predefined, predefined_log)),
                log: predefined_log,
                description: Vec::new(),
            },
            |(_, coder)| coder,
        )
    }
}

/// Cost of coding `counts` against `distribution`, in 1/256ths of a bit.
///
/// An FSE symbol holding `p` of the `1 << log` cells costs about
/// `log - log2(p)` bits, which is close enough to rank two tables.
fn estimate(counts: &[u32], distribution: &[i16], log: u32) -> u64 {
    let mut total = 0u64;
    for (symbol, &count) in counts.iter().enumerate() {
        if count == 0 {
            continue;
        }
        // A "less than one" cell is a full state reset, so it costs the
        // whole accuracy log, the same as a single-cell symbol.
        let points = distribution[symbol].max(1) as u32;
        let bits = log * 256 - distribution::log2_fixed(points);
        total += u64::from(count) * u64::from(bits);
    }
    total
}

fn ceil_log2(n: usize) -> u32 {
    if n <= 1 {
        0
    } else {
        usize::BITS - (n - 1).leading_zeros()
    }
}

fn counts_of(seqs: &[Coded], alphabet: usize, pick: fn(&Coded) -> u32) -> Vec<u32> {
    let mut counts = vec![0u32; alphabet];
    for seq in seqs {
        counts[pick(seq) as usize] += 1;
    }
    counts
}

/// Serialize the sequences section of one block.
pub(super) fn write_section(out: &mut Vec<u8>, seqs: &[Coded]) {
    let count = seqs.len();
    if count == 0 {
        out.push(0);
        return;
    }
    if count < 128 {
        out.push(count as u8);
    } else if count < 0x7f00 {
        out.push((count >> 8) as u8 + 128);
        out.push(count as u8);
    } else {
        let rest = count - 0x7f00;
        out.push(255);
        out.push(rest as u8);
        out.push((rest >> 8) as u8);
    }

    let literal_len = Coder::choose(
        &counts_of(seqs, LL_BASE.len(), |s| s.ll_code),
        &fse::LL_DEFAULT,
        fse::LL_LOG,
        LL_MAX_LOG,
    );
    let offset = Coder::choose(
        &counts_of(seqs, fse::OF_DEFAULT.len(), |s| s.of_code),
        &fse::OF_DEFAULT,
        fse::OF_LOG,
        OF_MAX_LOG,
    );
    let match_len = Coder::choose(
        &counts_of(seqs, ML_BASE.len(), |s| s.ml_code),
        &fse::ML_DEFAULT,
        fse::ML_LOG,
        ML_MAX_LOG,
    );

    // Modes, then the tables in the order the decoder expects them, then
    // the bitstream (RFC 8478, section 3.1.1.3.2).
    out.push(literal_len.mode << 6 | offset.mode << 4 | match_len.mode << 2);
    out.extend_from_slice(&literal_len.description);
    out.extend_from_slice(&offset.description);
    out.extend_from_slice(&match_len.description);
    out.extend_from_slice(&write_bitstream(seqs, &literal_len, &offset, &match_len));
}

/// Build the interleaved FSE bitstream.
///
/// The decoder reads, backwards from the end: the three initial states, then
/// for each sequence its offset, match-length and literals-length extra
/// bits, then (except after the last sequence) the state updates. Writing is
/// that list reversed, which is why this walks the sequences from the back.
fn write_bitstream(seqs: &[Coded], ll: &Coder, of: &Coder, ml: &Coder) -> Vec<u8> {
    let mut bw = BitWriter::new();
    let last = &seqs[seqs.len() - 1];
    let mut ll_state = ll.initial_state(last.ll_code);
    let mut ml_state = ml.initial_state(last.ml_code);
    let mut of_state = of.initial_state(last.of_code);
    push_extra(&mut bw, last);

    for seq in seqs[..seqs.len() - 1].iter().rev() {
        let of_step = of.step(seq.of_code, of_state);
        let ml_step = ml.step(seq.ml_code, ml_state);
        let ll_step = ll.step(seq.ll_code, ll_state);
        bw.push(u32::from(of_state - of_step.baseline), of_step.bits);
        bw.push(u32::from(ml_state - ml_step.baseline), ml_step.bits);
        bw.push(u32::from(ll_state - ll_step.baseline), ll_step.bits);
        of_state = of_step.state;
        ml_state = ml_step.state;
        ll_state = ll_step.state;
        push_extra(&mut bw, seq);
    }

    bw.push(u32::from(ml_state), ml.log);
    bw.push(u32::from(of_state), of.log);
    bw.push(u32::from(ll_state), ll.log);
    bw.finish()
}

fn push_extra(bw: &mut BitWriter, seq: &Coded) {
    bw.push(seq.ll_extra, LL_EXTRA[seq.ll_code as usize]);
    bw.push(seq.ml_extra, ML_EXTRA[seq.ml_code as usize]);
    bw.push(seq.of_extra, seq.of_code);
}
