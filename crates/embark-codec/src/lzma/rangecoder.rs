//! LZMA range coder: the normalized 11-bit-probability arithmetic coder that
//! sits underneath every LZMA symbol. The decoder and encoder are exact
//! mirrors of each other so a stream produced by one is consumed by the other
//! (and, more importantly, by the reference `xz` implementation).

/// `kTopValue` -- the range is renormalized whenever it drops below this.
const TOP: u32 = 1 << 24;
/// Number of bits in a probability; `kBitModelTotal = 1 << 11 = 2048`.
pub(crate) const MOVE_BITS: u32 = 5;

// --- decoder ---

#[cfg(feature = "dec")]
pub(crate) struct RangeDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
    /// Count of bytes requested past the end of `input`. A well-formed,
    /// complete stream never needs them; a truncated one does.
    pub(crate) read_past: usize,
}

#[cfg(feature = "dec")]
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

// --- encoder ---

#[cfg(feature = "enc")]
pub(crate) struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    pub(crate) out: alloc::vec::Vec<u8>,
}

#[cfg(feature = "enc")]
impl RangeEncoder {
    pub(crate) fn new() -> Self {
        Self {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_size: 1,
            out: alloc::vec::Vec::new(),
        }
    }

    #[inline]
    fn shift_low(&mut self) {
        if self.low < 0xFF00_0000 || (self.low >> 32) != 0 {
            let mut temp = self.cache;
            loop {
                self.out.push((temp as u64 + (self.low >> 32)) as u8);
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low << 8) & 0xFFFF_FFFF;
    }

    #[inline]
    fn normalize(&mut self) {
        while self.range < TOP {
            self.range <<= 8;
            self.shift_low();
        }
    }

    #[inline]
    pub(crate) fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
        let bound = (self.range >> 11) * (*prob as u32);
        if bit == 0 {
            self.range = bound;
            *prob += ((2048 - *prob as u32) >> MOVE_BITS) as u16;
        } else {
            self.low += bound as u64;
            self.range -= bound;
            *prob -= *prob >> MOVE_BITS;
        }
        self.normalize();
    }

    pub(crate) fn encode_direct_bits(&mut self, v: u32, num: u32) {
        for i in (0..num).rev() {
            self.range >>= 1;
            if ((v >> i) & 1) == 1 {
                self.low += self.range as u64;
            }
            self.normalize();
        }
    }

    pub(crate) fn encode_bittree(&mut self, probs: &mut [u16], symbol: u32, num_bits: u32) {
        let mut m = 1usize;
        for i in (0..num_bits).rev() {
            let bit = (symbol >> i) & 1;
            self.encode_bit(&mut probs[m], bit);
            m = (m << 1) | bit as usize;
        }
    }

    pub(crate) fn encode_bittree_reverse(&mut self, probs: &mut [u16], symbol: u32, num_bits: u32) {
        let mut m = 1usize;
        for i in 0..num_bits {
            let bit = (symbol >> i) & 1;
            self.encode_bit(&mut probs[m], bit);
            m = (m << 1) | bit as usize;
        }
    }

    /// Flush the five remaining bytes of the range coder's state.
    pub(crate) fn flush(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }
}
