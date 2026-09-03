//! Frame header, window sizing and the block loop (RFC 8478, section
//! 3.1.1.1).

use alloc::vec;
use alloc::vec::Vec;

use super::block;
use super::matcher::{HashChain, Match, Params};
use super::optimal::{self, Prices};

const MAGIC: u32 = 0xfd2f_b528;

/// Largest window this encoder advertises, as a base-2 logarithm.
///
/// Eight mebibytes is the size the format recommends every decoder support,
/// and it is far under the ceiling our own decoder enforces, so a frame from
/// here can never be one our own reader refuses.
const MAX_WINDOW_LOG: u32 = 23;

/// Longest input the match finder will parse. Its tables address positions
/// as `u32`; anything larger is coded as literals alone, which still shrinks
/// but finds no matches, and never happens for a real embedded asset.
const MAX_PARSED: usize = u32::MAX as usize;

/// How many times a block is parsed. Each pass reprices from the parse
/// before it, and the smallest result is kept, so passes cannot make a block
/// worse — only slower to encode, which is a build-time cost.
const PASSES: usize = 4;

/// Encode `input` as one Zstandard frame.
pub(super) fn encode(input: &[u8]) -> Vec<u8> {
    let len = input.len();
    let mut out = Vec::with_capacity(len / 3 + 32);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    let window = write_header(&mut out, len);

    if len == 0 {
        // A frame must carry at least one block.
        out.extend_from_slice(&[0x01, 0x00, 0x00]);
        return out;
    }

    let params = Params::for_input(len);
    let mut chain = HashChain::new(len, window, params.hash_bits);
    let mut repeats = [1usize, 4, 8];
    let mut at = 0usize;
    while at < len {
        let end = (at + block::MAX_BLOCK).min(len);
        let parses = if len <= MAX_PARSED {
            parse_block(input, at, end, &mut chain, &params, window - 1, repeats)
        } else {
            vec![Vec::new()]
        };
        block::write_one(&mut out, input, at, end, &parses, &mut repeats, end == len);
        at = end;
    }
    out
}

/// Parse one block once per price model.
///
/// The match candidates are collected once and shared, so the passes differ
/// only in what they think each choice costs.
fn parse_block(
    input: &[u8],
    start: usize,
    end: usize,
    chain: &mut HashChain,
    params: &Params,
    max_offset: usize,
    repeats: [usize; 3],
) -> Vec<Vec<Match>> {
    let candidates = optimal::collect(input, start, end, chain, params, max_offset);
    let block = &input[start..end];
    let mut prices = Prices::seed(block);
    let mut parses = Vec::with_capacity(PASSES);
    for pass in 0..PASSES {
        let parse = optimal::parse(input, start, end, &candidates, repeats, &prices);
        if pass + 1 < PASSES {
            prices = Prices::fit(block, &parse, repeats);
        }
        parses.push(parse);
    }
    parses
}

/// Write the frame header and return the window size in bytes.
///
/// Inputs below 256 bytes take the `Single_Segment_Flag`: the window
/// descriptor is dropped and the content size fits in one byte, which is two
/// bytes of header in total. Larger inputs carry an explicit window and the
/// narrowest content-size field that can hold their length.
fn write_header(out: &mut Vec<u8>, len: usize) -> usize {
    if len < 256 {
        out.push(0x20);
        out.push(len as u8);
        return len.max(1);
    }
    let log = ceil_log2(len).min(MAX_WINDOW_LOG);
    let descriptor = if len <= 65791 {
        0x40
    } else if len <= u32::MAX as usize {
        0x80
    } else {
        0xc0
    };
    out.push(descriptor);
    out.push(((log - 10) << 3) as u8);
    if len <= 65791 {
        out.extend_from_slice(&((len - 256) as u16).to_le_bytes());
    } else if len <= u32::MAX as usize {
        out.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        out.extend_from_slice(&(len as u64).to_le_bytes());
    }
    1usize << log
}

/// Smallest window log that covers `n` bytes, never below the format's
/// 1 KiB floor.
fn ceil_log2(n: usize) -> u32 {
    (usize::BITS - (n - 1).leading_zeros()).max(10)
}
