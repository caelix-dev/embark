//! LZMA1 decode loop: drives the range decoder and probability model through
//! the literal / match / rep-match state machine, writing into an output
//! window. Every read is bounds-checked; hostile input yields `Error`, never a
//! panic or an over-long output.

extern crate alloc;
use alloc::vec::Vec;
use embark_format::Error;

use super::model::{LzmaModel, MATCH_MIN_LEN};
use super::rangecoder::RangeDecoder;

/// Decode `orig_len` output bytes from the range-coded `stream`.
pub(crate) fn decode(
    lc: u32,
    lp: u32,
    pb: u32,
    stream: &[u8],
    orig_len: usize,
) -> Result<Vec<u8>, Error> {
    let mut rc = RangeDecoder::new(stream).ok_or(Error::Corrupt)?;
    let mut model = LzmaModel::new(lc, lp, pb);

    // `orig_len` is the caller-supplied, attacker-controllable uncompressed
    // size from the entry header; `RangeDecoder::new` above only requires 5
    // bytes of well-formed range-coder preamble, so a 13-byte header plus a
    // handful of stream bytes is enough to reach this point with an
    // arbitrarily large `orig_len`.
    // Reserve for what is plausible rather than for what is claimed. The
    // claim is the attacker's; the buffer grows as real output arrives, and a
    // claim the payload cannot honour ends as a decode failure below.
    const EAGER: usize = 64 * 1024;
    let mut out: Vec<u8> = Vec::new();
    out.try_reserve(orig_len.min(EAGER))
        .map_err(|_| Error::Corrupt)?;
    let mut state = 0usize;
    let (mut rep0, mut rep1, mut rep2, mut rep3) = (0u32, 0u32, 0u32, 0u32);

    while out.len() < orig_len {
        // A complete stream never asks for a byte it does not have, so the
        // moment it does, it is over. Checking here rather than only after
        // the loop is what bounds the work by the input: `orig_len` is the
        // caller's claim, and the range decoder happily keeps decoding zeros
        // once the real bytes run out, so without this a fourteen-byte stream
        // claiming a terabyte decodes a terabyte of nonsense before anyone
        // objects.
        if rc.read_past > 0 {
            return Err(Error::Truncated);
        }
        let pos_state = model.pos_state(out.len());
        if model.decode_is_match(&mut rc, state, pos_state) == 0 {
            // Literal.
            let prev = out.last().copied().unwrap_or(0);
            let match_byte = if state >= 7 {
                let idx = out
                    .len()
                    .checked_sub(rep0 as usize + 1)
                    .ok_or(Error::Corrupt)?;
                out[idx]
            } else {
                0
            };
            let byte = model.decode_literal(&mut rc, out.len(), prev, state, match_byte);
            out.push(byte);
            state = if state < 4 {
                0
            } else if state < 10 {
                state - 3
            } else {
                state - 6
            };
            continue;
        }

        // Match of some kind.
        let len;
        if model.decode_is_rep(&mut rc, state) != 0 {
            // Rep match: reuse one of the last four distances.
            if model.decode_is_rep_g0(&mut rc, state) == 0 {
                if model.decode_is_rep0_long(&mut rc, state, pos_state) == 0 {
                    // Short rep: a single byte at distance rep0 + 1.
                    state = if state < 7 { 9 } else { 11 };
                    let idx = out
                        .len()
                        .checked_sub(rep0 as usize + 1)
                        .ok_or(Error::Corrupt)?;
                    let b = out[idx];
                    out.push(b);
                    continue;
                }
            } else {
                let dist;
                if model.decode_is_rep_g1(&mut rc, state) == 0 {
                    dist = rep1;
                } else {
                    if model.decode_is_rep_g2(&mut rc, state) == 0 {
                        dist = rep2;
                    } else {
                        dist = rep3;
                        rep3 = rep2;
                    }
                    rep2 = rep1;
                }
                rep1 = rep0;
                rep0 = dist;
            }
            len = model.decode_rep_len(&mut rc, pos_state) + MATCH_MIN_LEN;
            state = if state < 7 { 8 } else { 11 };
        } else {
            // New match: length is coded first, then the distance.
            rep3 = rep2;
            rep2 = rep1;
            rep1 = rep0;
            let len_sym = model.decode_new_len(&mut rc, pos_state);
            state = if state < 7 { 7 } else { 10 };
            rep0 = model.decode_distance(&mut rc, len_sym);
            if rep0 == 0xFFFF_FFFF {
                // End-of-stream marker: never expected in a known-size .lzma.
                return Err(Error::Corrupt);
            }
            len = len_sym + MATCH_MIN_LEN;
        }

        copy_match(&mut out, rep0, len, orig_len)?;
    }

    if rc.read_past > 0 {
        return Err(Error::Truncated);
    }
    Ok(out)
}

/// Copy a match of `len` bytes at back-distance `rep0 + 1` (byte-by-byte so
/// overlapping run-length copies work), rejecting distances past the window
/// start and any output that would exceed `orig_len`.
fn copy_match(out: &mut Vec<u8>, rep0: u32, len: usize, orig_len: usize) -> Result<(), Error> {
    let dist = rep0 as usize + 1;
    if dist > out.len() {
        return Err(Error::Corrupt);
    }
    if out.len() + len > orig_len {
        return Err(Error::Corrupt);
    }
    let start = out.len() - dist;
    for k in 0..len {
        let b = out[start + k];
        out.push(b);
    }
    Ok(())
}
