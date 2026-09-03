//! LZMA range decoder: the normalized 11-bit-probability arithmetic coder
//! that sits underneath every LZMA symbol. It is the exact mirror of the
//! range encoder in any LZMA1 producer, so it consumes streams from `xz` and
//! from `lzma-rust2` alike.

/// `kTopValue` -- the range is renormalized whenever it drops below this.
const TOP: u32 = 1 << 24;
/// Number of bits in a probability; `kBitModelTotal = 1 << 11 = 2048`.
const MOVE_BITS: u32 = 5;

pub(crate) struct RangeDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
    /// Count of bytes requested past the end of `input`. A well-formed,
    /// complete stream never needs them; a truncated one does.
    pub(crate) read_past: usize,
}

impl<'a> RangeDecoder<'a> {
    /// Initialize from the raw range-coded stream. The first byte must be 0
    /// (LZMA encoders always emit a leading zero from the range coder's cache);
    /// the next four are the initial `code`, big-endian.
    pub(crate) fn new(input: &'a [u8]) -> Option<Self> {
        if input.len() < 5 || input[0] != 0 {
            return None;
        }
        let code = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        Some(Self {
            input,
            pos: 5,
            range: 0xFFFF_FFFF,
            code,
            read_past: 0,
        })
    }

    #[inline]
    fn next_byte(&mut self) -> u32 {
        if self.pos < self.input.len() {
            let b = self.input[self.pos] as u32;
            self.pos += 1;
            b
        } else {
            self.read_past += 1;
            0
        }
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < TOP {
            self.range <<= 8;
            self.code = (self.code << 8) | self.next_byte();
        }
    }

    /// Decode one bit under the given adaptive probability, updating it.
    #[inline]
    pub(crate) fn decode_bit(&mut self, prob: &mut u16) -> u32 {
        let bound = (self.range >> 11) * (*prob as u32);
        let bit = if self.code < bound {
            self.range = bound;
            *prob += ((2048 - *prob as u32) >> MOVE_BITS) as u16;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= *prob >> MOVE_BITS;
            1
        };
        self.normalize();
        bit
    }

    /// Decode `num` bits with a fixed (0.5) probability -- used for the high
    /// bits of large distances.
    pub(crate) fn decode_direct_bits(&mut self, num: u32) -> u32 {
        let mut res = 0u32;
        for _ in 0..num {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            self.normalize();
            res = (res << 1).wrapping_add(t.wrapping_add(1));
        }
        res
    }

    /// Decode a most-significant-bit-first bit tree of `num_bits` bits.
    /// `probs` must hold at least `1 << num_bits` entries.
    pub(crate) fn decode_bittree(&mut self, probs: &mut [u16], num_bits: u32) -> u32 {
        let mut m = 1u32;
        for _ in 0..num_bits {
            m = (m << 1) | self.decode_bit(&mut probs[m as usize]);
        }
        m - (1 << num_bits)
    }

    /// Decode a least-significant-bit-first ("reverse") bit tree.
    pub(crate) fn decode_bittree_reverse(&mut self, probs: &mut [u16], num_bits: u32) -> u32 {
        let mut m = 1usize;
        let mut sym = 0u32;
        for i in 0..num_bits {
            let bit = self.decode_bit(&mut probs[m]);
            m = (m << 1) | bit as usize;
            sym |= bit << i;
        }
        sym
    }
}
