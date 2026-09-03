//! Sequence codes and the interleaved FSE bitstream of a compressed block.

use alloc::vec::Vec;

use super::bitstream::BitWriter;
use super::fse::{self, Encoder};

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

/// The three predefined tables, built once per frame.
pub(super) struct Tables {
    literal_len: Encoder,
    match_len: Encoder,
    offset: Encoder,
}

impl Tables {
    pub(super) fn new() -> Self {
        Self {
            literal_len: Encoder::new(&fse::LL_DEFAULT, fse::LL_LOG),
            match_len: Encoder::new(&fse::ML_DEFAULT, fse::ML_LOG),
            offset: Encoder::new(&fse::OF_DEFAULT, fse::OF_LOG),
        }
    }
}

/// Serialize the sequences section of one block.
///
/// All three symbol types use `Predefined_Mode`, so the section is just the
/// sequence count, the mode byte and the bitstream.
pub(super) fn write_section(out: &mut Vec<u8>, seqs: &[Coded], tables: &Tables) {
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
    // Literal lengths, offsets and match lengths all in Predefined_Mode,
    // reserved bits zero (RFC 8478, section 3.1.1.3.2.1).
    out.push(0);
    out.extend_from_slice(&write_bitstream(seqs, tables));
}

/// Build the interleaved FSE bitstream.
///
/// The decoder reads, backwards from the end: the three initial states, then
/// for each sequence its offset, match-length and literals-length extra
/// bits, then (except after the last sequence) the state updates. Writing is
/// that list reversed, which is why this walks the sequences from the back.
fn write_bitstream(seqs: &[Coded], tables: &Tables) -> Vec<u8> {
    let mut bw = BitWriter::new();
    let last = &seqs[seqs.len() - 1];
    let mut ll_state = tables.literal_len.initial_state(last.ll_code);
    let mut ml_state = tables.match_len.initial_state(last.ml_code);
    let mut of_state = tables.offset.initial_state(last.of_code);
    push_extra(&mut bw, last);

    for seq in seqs[..seqs.len() - 1].iter().rev() {
        let of_step = tables.offset.step(seq.of_code, of_state);
        let ml_step = tables.match_len.step(seq.ml_code, ml_state);
        let ll_step = tables.literal_len.step(seq.ll_code, ll_state);
        bw.push(u32::from(of_state - of_step.baseline), of_step.bits);
        bw.push(u32::from(ml_state - ml_step.baseline), ml_step.bits);
        bw.push(u32::from(ll_state - ll_step.baseline), ll_step.bits);
        of_state = of_step.state;
        ml_state = ml_step.state;
        ll_state = ll_step.state;
        push_extra(&mut bw, seq);
    }

    bw.push(u32::from(ml_state), fse::ML_LOG);
    bw.push(u32::from(of_state), fse::OF_LOG);
    bw.push(u32::from(ll_state), fse::LL_LOG);
    bw.finish()
}

fn push_extra(bw: &mut BitWriter, seq: &Coded) {
    bw.push(seq.ll_extra, LL_EXTRA[seq.ll_code as usize]);
    bw.push(seq.ml_extra, ML_EXTRA[seq.ml_code as usize]);
    bw.push(seq.of_extra, seq.of_code);
}
