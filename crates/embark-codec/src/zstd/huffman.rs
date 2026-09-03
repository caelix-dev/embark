//! Huffman coding of the literals section (RFC 8478, section 4.2).

use alloc::vec;
use alloc::vec::Vec;

use super::bitstream::BitWriter;
use super::weights;

/// Longest code the format allows.
const MAX_BITS: u32 = 11;

/// Most weights a direct header can carry.
///
/// The header states `Number_of_Symbols = headerByte - 127`, so it holds at
/// most 128 weights, covering literals 0 to 128 once the last weight is
/// deduced. A wider alphabet has to take the FSE-compressed header.
const MAX_DIRECT_WEIGHTS: usize = 128;

/// Below this many literals the tree description cannot pay for itself.
const MIN_LITERALS: usize = 256;

/// Huffman-code `literals` into a `Literals_Section_Content`: the tree
/// description, the jump table and the four streams.
///
/// Returns `None` when the input cannot or should not be coded this way.
pub(super) fn compress(literals: &[u8]) -> Option<Vec<u8>> {
    if literals.len() < MIN_LITERALS {
        return None;
    }
    let mut counts = [0u32; 256];
    for &byte in literals {
        counts[byte as usize] += 1;
    }
    let last = counts.iter().rposition(|&c| c > 0)?;
    if counts.iter().filter(|&&c| c > 0).count() < 2 {
        return None;
    }

    let lengths = code_lengths(&counts);
    let codes = assign_codes(&lengths);
    let max_bits = u32::from(*lengths.iter().max()?);
    // Weights run to one before the highest present symbol; the decoder
    // deduces the last one by completing the tree to the next power of two.
    let series: Vec<u8> = lengths[..last]
        .iter()
        .map(|&len| weight(len, max_bits))
        .collect();

    let mut out = Vec::with_capacity(literals.len() / 2 + last / 2 + 8);
    write_tree(&mut out, &series)?;

    // Four streams, each a quarter of the literals rounded up except the
    // last (RFC 8478, section 3.1.1.3.1.6). The jump table gives the
    // compressed size of the first three; the fourth is what is left.
    let quarter = literals.len().div_ceil(4);
    let jump_table = out.len();
    out.extend_from_slice(&[0u8; 6]);
    let mut sizes = [0usize; 3];
    for (i, part) in literals.chunks(quarter).enumerate() {
        let before = out.len();
        write_stream(&mut out, part, &lengths, &codes);
        if i < 3 {
            sizes[i] = out.len() - before;
        }
    }
    for (i, size) in sizes.iter().enumerate() {
        out[jump_table + i * 2..jump_table + i * 2 + 2]
            .copy_from_slice(&(u16::try_from(*size).ok()?).to_le_bytes());
    }
    Some(out)
}

/// Code lengths for `counts`, none longer than [`MAX_BITS`].
///
/// A plain Huffman tree can be deeper than the format allows. Halving the
/// counts and rebuilding flattens it, and always terminates: once every
/// present symbol has the same count the tree is balanced, and 256 symbols
/// balance to eight bits.
fn code_lengths(counts: &[u32; 256]) -> [u8; 256] {
    let mut freqs = *counts;
    loop {
        let lengths = huffman(&freqs);
        if lengths.iter().all(|&len| u32::from(len) <= MAX_BITS) {
            return lengths;
        }
        for freq in &mut freqs {
            *freq = (*freq).div_ceil(2);
        }
    }
}

/// Plain Huffman code lengths, built by merging the two lightest nodes.
///
/// Leaves are pre-sorted by weight and every internal node is heavier than
/// the one before it, so the two lightest nodes are always at the front of
/// one of the two runs and no priority queue is needed.
fn huffman(freqs: &[u32; 256]) -> [u8; 256] {
    let mut leaves: Vec<(u64, usize)> = (0..256)
        .filter(|&s| freqs[s] > 0)
        .map(|s| (u64::from(freqs[s]), s))
        .collect();
    leaves.sort_unstable();
    let leaf_count = leaves.len();

    let mut lengths = [0u8; 256];
    if leaf_count < 2 {
        if let Some(&(_, symbol)) = leaves.first() {
            lengths[symbol] = 1;
        }
        return lengths;
    }

    // Node ids below `leaf_count` are leaves, in sorted order; the rest are
    // internal nodes in creation order, so a parent always outranks its
    // children.
    let mut internal_freq: Vec<u64> = Vec::with_capacity(leaf_count - 1);
    let mut children: Vec<(usize, usize)> = Vec::with_capacity(leaf_count - 1);
    let mut next_leaf = 0usize;
    let mut next_internal = 0usize;
    let mut picked = [(0u64, 0usize); 2];
    while (leaf_count - next_leaf) + (internal_freq.len() - next_internal) > 1 {
        for slot in &mut picked {
            let leaf = leaves.get(next_leaf).map(|&(freq, _)| freq);
            let internal = internal_freq.get(next_internal).copied();
            // Ties go to the leaf, which keeps the tree shallower.
            let take_internal = match (leaf, internal) {
                (Some(l), Some(i)) => i < l,
                (None, Some(_)) => true,
                _ => false,
            };
            *slot = if take_internal {
                next_internal += 1;
                (internal.unwrap_or_default(), leaf_count + next_internal - 1)
            } else {
                next_leaf += 1;
                (leaf.unwrap_or_default(), next_leaf - 1)
            };
        }
        internal_freq.push(picked[0].0 + picked[1].0);
        children.push((picked[0].1, picked[1].1));
    }

    let mut depth = vec![0u32; leaf_count + children.len()];
    for (index, &(left, right)) in children.iter().enumerate().rev() {
        let parent = depth[leaf_count + index] + 1;
        depth[left] = parent;
        depth[right] = parent;
    }
    for (index, &(_, symbol)) in leaves.iter().enumerate() {
        lengths[symbol] = depth[index] as u8;
    }
    lengths
}

/// Canonical prefix codes: longest first, symbols in natural order within a
/// length, codes running upwards (RFC 8478, section 4.2.1.3).
fn assign_codes(lengths: &[u8; 256]) -> [u16; 256] {
    let mut codes = [0u16; 256];
    let mut code = 0u32;
    for bits in (1..=MAX_BITS as u8).rev() {
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == bits {
                codes[symbol] = code as u16;
                code += 1;
            }
        }
        code >>= 1;
    }
    codes
}

/// Write the tree description, in whichever of the two forms is smaller.
fn write_tree(out: &mut Vec<u8>, series: &[u8]) -> Option<()> {
    let direct = (series.len() <= MAX_DIRECT_WEIGHTS).then(|| 1 + series.len().div_ceil(2));
    let coded = weights::compress(series);
    match (direct, coded) {
        (Some(size), Some(body)) if size <= body.len() + 1 => write_direct(out, series),
        (_, Some(body)) => {
            out.push(body.len() as u8);
            out.extend_from_slice(&body);
        }
        (Some(_), None) => write_direct(out, series),
        (None, None) => return None,
    }
    Some(())
}

/// The direct representation: one weight per nibble, high nibble first.
fn write_direct(out: &mut Vec<u8>, series: &[u8]) {
    out.push((127 + series.len()) as u8);
    for pair in series.chunks(2) {
        out.push(pair[0] << 4 | pair.get(1).copied().unwrap_or(0));
    }
}

fn weight(len: u8, max_bits: u32) -> u8 {
    if len == 0 {
        0
    } else {
        (max_bits + 1) as u8 - len
    }
}

/// Code one stream. Like every backward-read bitstream in the format, the
/// symbols go in last first.
fn write_stream(out: &mut Vec<u8>, part: &[u8], lengths: &[u8; 256], codes: &[u16; 256]) {
    let mut bw = BitWriter::new();
    for &byte in part.iter().rev() {
        bw.push(
            u32::from(codes[byte as usize]),
            u32::from(lengths[byte as usize]),
        );
    }
    out.extend_from_slice(&bw.finish());
}
