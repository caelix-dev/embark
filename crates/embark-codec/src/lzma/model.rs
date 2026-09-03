//! The full set of LZMA1 adaptive probabilities plus the length sub-coder,
//! driven by the decoder.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::rangecoder::RangeDecoder;

/// Initial probability: `kBitModelTotal / 2 = 2048 / 2`.
const INIT_PROB: u16 = 1024;

pub(crate) const NUM_STATES: usize = 12;
/// Second dimension of the pos-state-indexed arrays: `1 << kNumPosBitsMax`.
const POS_STATES_MAX: usize = 1 << 4;
pub(crate) const NUM_LEN_TO_POS: usize = 4;
pub(crate) const NUM_ALIGN_BITS: u32 = 4;
pub(crate) const END_POS_MODEL_INDEX: u32 = 14;
/// `1 << (kEndPosModelIndex >> 1)` = 128.
const NUM_FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX >> 1);
/// `1 + kNumFullDistances - kEndPosModelIndex` = 115.
const SPEC_POS_LEN: usize = 1 + NUM_FULL_DISTANCES - END_POS_MODEL_INDEX as usize;
pub(crate) const MATCH_MIN_LEN: usize = 2;

/// The length sub-coder (used both for new matches and rep matches). Returns
/// a raw length symbol in `0..=271`; the true match length is that plus
/// `MATCH_MIN_LEN`.
struct LenCoder {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; POS_STATES_MAX],
    mid: [[u16; 8]; POS_STATES_MAX],
    high: [u16; 256],
}

impl LenCoder {
    fn new() -> Self {
        Self {
            choice: INIT_PROB,
            choice2: INIT_PROB,
            low: [[INIT_PROB; 8]; POS_STATES_MAX],
            mid: [[INIT_PROB; 8]; POS_STATES_MAX],
            high: [INIT_PROB; 256],
        }
    }

    fn decode(&mut self, rc: &mut RangeDecoder<'_>, pos_state: usize) -> usize {
        if rc.decode_bit(&mut self.choice) == 0 {
            rc.decode_bittree(&mut self.low[pos_state], 3) as usize
        } else if rc.decode_bit(&mut self.choice2) == 0 {
            8 + rc.decode_bittree(&mut self.mid[pos_state], 3) as usize
        } else {
            16 + rc.decode_bittree(&mut self.high, 8) as usize
        }
    }
}

/// Every adaptive probability in an LZMA1 stream. `lc`/`lp`/`pb` are taken
/// from the `.lzma` header.
pub(crate) struct LzmaModel {
    lc: u32,
    lp_mask: u32,
    pb_mask: usize,
    lit: Vec<u16>,
    pos_slot: [[u16; 64]; NUM_LEN_TO_POS],
    spec_pos: [u16; SPEC_POS_LEN],
    align: [u16; 1 << NUM_ALIGN_BITS],
    is_match: [[u16; POS_STATES_MAX]; NUM_STATES],
    is_rep: [u16; NUM_STATES],
    len_coder: LenCoder,
    is_rep_g0: [u16; NUM_STATES],
    is_rep_g1: [u16; NUM_STATES],
    is_rep_g2: [u16; NUM_STATES],
    is_rep0_long: [[u16; POS_STATES_MAX]; NUM_STATES],
    rep_len_coder: LenCoder,
}

impl LzmaModel {
    pub(crate) fn new(lc: u32, lp: u32, pb: u32) -> Self {
        let lit_size = 0x300usize << (lc + lp);
        Self {
            lc,
            lp_mask: (1u32 << lp) - 1,
            pb_mask: (1usize << pb) - 1,
            lit: vec![INIT_PROB; lit_size],
            pos_slot: [[INIT_PROB; 64]; NUM_LEN_TO_POS],
            spec_pos: [INIT_PROB; SPEC_POS_LEN],
            align: [INIT_PROB; 1 << NUM_ALIGN_BITS],
            is_match: [[INIT_PROB; POS_STATES_MAX]; NUM_STATES],
            is_rep: [INIT_PROB; NUM_STATES],
            len_coder: LenCoder::new(),
            is_rep_g0: [INIT_PROB; NUM_STATES],
            is_rep_g1: [INIT_PROB; NUM_STATES],
            is_rep_g2: [INIT_PROB; NUM_STATES],
            is_rep0_long: [[INIT_PROB; POS_STATES_MAX]; NUM_STATES],
            rep_len_coder: LenCoder::new(),
        }
    }

    #[inline]
    pub(crate) fn pos_state(&self, total_pos: usize) -> usize {
        total_pos & self.pb_mask
    }

    /// Literal probability context index: `((pos & lpMask) << lc) + (prev >> (8 - lc))`.
    #[inline]
    fn lit_state(&self, total_pos: usize, prev_byte: u8) -> usize {
        let a = (total_pos as u32 & self.lp_mask) << self.lc;
        let b = (prev_byte as u32) >> (8 - self.lc);
        (a + b) as usize
    }
}

impl LzmaModel {
    #[inline]
    pub(crate) fn decode_is_match(
        &mut self,
        rc: &mut RangeDecoder<'_>,
        st: usize,
        ps: usize,
    ) -> u32 {
        rc.decode_bit(&mut self.is_match[st][ps])
    }

    #[inline]
    pub(crate) fn decode_is_rep(&mut self, rc: &mut RangeDecoder<'_>, st: usize) -> u32 {
        rc.decode_bit(&mut self.is_rep[st])
    }

    #[inline]
    pub(crate) fn decode_is_rep_g0(&mut self, rc: &mut RangeDecoder<'_>, st: usize) -> u32 {
        rc.decode_bit(&mut self.is_rep_g0[st])
    }

    #[inline]
    pub(crate) fn decode_is_rep_g1(&mut self, rc: &mut RangeDecoder<'_>, st: usize) -> u32 {
        rc.decode_bit(&mut self.is_rep_g1[st])
    }

    #[inline]
    pub(crate) fn decode_is_rep_g2(&mut self, rc: &mut RangeDecoder<'_>, st: usize) -> u32 {
        rc.decode_bit(&mut self.is_rep_g2[st])
    }

    #[inline]
    pub(crate) fn decode_is_rep0_long(
        &mut self,
        rc: &mut RangeDecoder<'_>,
        st: usize,
        ps: usize,
    ) -> u32 {
        rc.decode_bit(&mut self.is_rep0_long[st][ps])
    }

    #[inline]
    pub(crate) fn decode_rep_len(&mut self, rc: &mut RangeDecoder<'_>, ps: usize) -> usize {
        self.rep_len_coder.decode(rc, ps)
    }

    #[inline]
    pub(crate) fn decode_new_len(&mut self, rc: &mut RangeDecoder<'_>, ps: usize) -> usize {
        self.len_coder.decode(rc, ps)
    }

    /// Decode one literal byte. `prev_byte` is the previously output byte (0 at
    /// the start); `match_byte` is the byte `rep0 + 1` back, needed only for the
    /// "matched" literal coder used right after a match (`state >= 7`).
    pub(crate) fn decode_literal(
        &mut self,
        rc: &mut RangeDecoder<'_>,
        total_pos: usize,
        prev_byte: u8,
        state: usize,
        match_byte: u8,
    ) -> u8 {
        let ls = self.lit_state(total_pos, prev_byte);
        let probs = &mut self.lit[ls * 0x300..ls * 0x300 + 0x300];
        let mut symbol = 1u32;
        if state < 7 {
            while symbol < 0x100 {
                symbol = (symbol << 1) | rc.decode_bit(&mut probs[symbol as usize]);
            }
        } else {
            let mut mb = match_byte as u32;
            while symbol < 0x100 {
                mb <<= 1;
                let match_bit = (mb >> 8) & 1;
                let idx = (((1 + match_bit) << 8) + symbol) as usize;
                let bit = rc.decode_bit(&mut probs[idx]);
                symbol = (symbol << 1) | bit;
                if match_bit != bit {
                    while symbol < 0x100 {
                        symbol = (symbol << 1) | rc.decode_bit(&mut probs[symbol as usize]);
                    }
                    break;
                }
            }
        }
        (symbol & 0xff) as u8
    }

    /// Decode the raw distance for a new match, given the raw length symbol.
    /// Returns the distance value `dist` (the true back-offset is `dist + 1`);
    /// `0xFFFF_FFFF` is the end-of-stream marker.
    pub(crate) fn decode_distance(&mut self, rc: &mut RangeDecoder<'_>, len_sym: usize) -> u32 {
        let len_state = len_sym.min(NUM_LEN_TO_POS - 1);
        let pos_slot = rc.decode_bittree(&mut self.pos_slot[len_state], 6);
        if pos_slot < 4 {
            return pos_slot;
        }
        let num_direct = (pos_slot >> 1) - 1;
        let mut dist = (2 | (pos_slot & 1)) << num_direct;
        if pos_slot < END_POS_MODEL_INDEX {
            let base = (dist - pos_slot) as usize;
            dist += rc.decode_bittree_reverse(&mut self.spec_pos[base..], num_direct);
        } else {
            dist += rc.decode_direct_bits(num_direct - NUM_ALIGN_BITS) << NUM_ALIGN_BITS;
            dist += rc.decode_bittree_reverse(&mut self.align, NUM_ALIGN_BITS);
        }
        dist
    }
}
