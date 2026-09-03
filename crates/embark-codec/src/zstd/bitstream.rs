//! Forward bit writer for the backward-read bitstreams of RFC 8478.
//!
//! Zstandard's FSE and Huffman bitstreams are written low bit first, in
//! increasing byte order, but read from the last byte backwards. A decoder
//! finds its starting point by skipping the padding zeroes and the single
//! set bit that the encoder appends after the final payload bit (RFC 8478,
//! section 3.1.1.3.2.1.2), so a field written last is read first. Callers
//! therefore push fields in the reverse of the order the decoder consumes
//! them.

use alloc::vec::Vec;

/// Accumulates bits into a byte stream, least significant bit first.
pub(super) struct BitWriter {
    out: Vec<u8>,
    container: u64,
    bits: u32,
}

impl BitWriter {
    pub(super) fn new() -> Self {
        Self {
            out: Vec::new(),
            container: 0,
            bits: 0,
        }
    }

    /// Append the low `nbits` of `value`.
    ///
    /// `nbits` never exceeds 28 here (the widest field is an offset code's
    /// extra bits), so the accumulator can always take a whole field on top
    /// of the up to 7 bits left over from the previous flush.
    pub(super) fn push(&mut self, value: u32, nbits: u32) {
        debug_assert!(nbits <= 28);
        debug_assert!(nbits == 0 || u64::from(value) < (1u64 << nbits));
        self.container |= u64::from(value) << self.bits;
        self.bits += nbits;
        while self.bits >= 8 {
            self.out.push(self.container as u8);
            self.container >>= 8;
            self.bits -= 8;
        }
    }

    /// Flush any partial byte and return the stream with no end marker.
    ///
    /// The FSE table description is read forwards and reports its own
    /// length, so it needs no marker and simply leaves the last byte's spare
    /// bits unused (RFC 8478, section 4.1.1).
    pub(super) fn finish_forward(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.out.push(self.container as u8);
        }
        self.out
    }

    /// Append the end marker and return the finished stream.
    ///
    /// The marker is a single set bit followed by zero padding to the next
    /// byte boundary; it is what tells the decoder where the payload ends.
    pub(super) fn finish(mut self) -> Vec<u8> {
        self.push(1, 1);
        if self.bits > 0 {
            self.out.push(self.container as u8);
        }
        self.out
    }
}
