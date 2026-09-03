//! Price-based optimal parsing.
//!
//! A lazy parser takes the best match it can see from where it stands. This
//! one asks a different question: what is the cheapest way to encode the
//! whole block? Positions in the block are nodes, an edge is either one
//! literal or one match, and an edge weighs what that choice will actually
//! cost in bits once it is entropy-coded. The cheapest path wins.
//!
//! Prices come from the block itself, which is circular: what a symbol costs
//! depends on how often the parse ends up using it. The way out is to
//! iterate. The first pass prices literals by their frequency in the block
//! and sequences by the format's predefined distributions; each later pass
//! reprices from the parse the one before it produced. The caller serializes
//! every pass and keeps the smallest, so a pass that guesses badly costs
//! build time and nothing else.
//!
//! One approximation is worth naming. A sequence's literals-length code
//! depends on how many literals precede it, and its offset code on the
//! repeat history, so an edge's true weight depends on the path that reached
//! it. Rather than track every combination, each node carries the literal
//! run and the repeat history of the best path into it, and edges are priced
//! against those. That is what makes this a good parse rather than a
//! provably optimal one.

use alloc::vec;
use alloc::vec::Vec;

use super::distribution::log2_fixed;
use super::fse;
use super::matcher::{
    self, HashChain, MAX_MATCH, MIN_MATCH, MIN_REPEAT_MATCH, Match, Params, common_prefix,
};
use super::sequences;

/// Lengths above this are only priced at their full extent, not at every
/// shorter truncation, which keeps a long match from costing time
/// proportional to its length at every position it covers.
const RELAX_LIMIT: usize = 32;

/// Price of a literal is clamped into what a Huffman code can really charge:
/// no code is shorter than one bit, and none is longer than eleven.
const MIN_LITERAL_PRICE: u32 = 256;
const MAX_LITERAL_PRICE: u32 = 11 * 256;
/// An FSE symbol can cost well under a bit, but not nothing.
const MIN_SYMBOL_PRICE: u32 = 32;
/// What an unseen symbol is charged: the cost of the rarest thing seen, plus
/// a penalty, since taking it will widen the table that has to describe it.
const UNSEEN_PENALTY: u32 = 2 * 256;

/// Every match the chain can offer inside one block, collected once.
///
/// The candidates at a position depend only on the input, not on the
/// prices, so they are found once and read by every pass. That takes the
/// match search out of the repricing loop entirely, which is where nearly
/// all of the time was going.
pub(super) struct Candidates {
    items: Vec<(u32, u32)>,
    /// Where each position's run of candidates begins, with one extra entry
    /// so the last run has an end.
    starts: Vec<u32>,
    /// Whether this position was searched at all. Positions swallowed by a
    /// long match are not, and the parser leaves them alone too.
    searched: Vec<bool>,
}

impl Candidates {
    fn at(&self, index: usize) -> &[(u32, u32)] {
        let from = self.starts[index] as usize;
        let to = self.starts[index + 1] as usize;
        &self.items[from..to]
    }

    fn searched(&self, index: usize) -> bool {
        self.searched[index]
    }
}

/// Sweep the block once, filling the hash chain and recording what it finds.
pub(super) fn collect(
    input: &[u8],
    start: usize,
    end: usize,
    chain: &mut HashChain,
    params: &Params,
    max_offset: usize,
) -> Candidates {
    let span = end - start;
    let mut items = Vec::new();
    let mut starts = Vec::with_capacity(span + 1);
    let mut searched = Vec::with_capacity(span);
    let mut skip_until = 0usize;
    for index in 0..span {
        let pos = start + index;
        chain.fill_to(input, pos);
        starts.push(items.len() as u32);
        searched.push(index >= skip_until);
        if index < skip_until {
            continue;
        }
        let before = items.len();
        chain.candidates(
            input,
            pos,
            pos.saturating_sub(max_offset),
            (span - index).min(MAX_MATCH),
            params,
            &mut items,
        );
        // Once a match this long turns up it is taken whole, so there is no
        // point searching for a better way through the middle of it.
        if items.len() > before {
            let longest = items[items.len() - 1].0 as usize;
            if longest >= params.nice_len {
                skip_until = index + longest;
            }
        }
    }
    starts.push(items.len() as u32);
    Candidates {
        items,
        starts,
        searched,
    }
}

/// What each symbol costs, in 1/256ths of a bit.
pub(super) struct Prices {
    literal: [u32; 256],
    literal_len: [u32; 36],
    match_len: [u32; 53],
    offset: [u32; 32],
}

impl Prices {
    /// Prices for the first pass, before any parse exists: literals by their
    /// frequency in this block, sequences by the predefined distributions.
    pub(super) fn seed(block: &[u8]) -> Self {
        let mut literals = [0u32; 256];
        for &byte in block {
            literals[byte as usize] += 1;
        }
        let mut prices = Self {
            literal: [0; 256],
            literal_len: [0; 36],
            match_len: [0; 53],
            offset: [0; 32],
        };
        prices.set_literals(&literals);
        for (code, price) in prices.literal_len.iter_mut().enumerate() {
            *price = predefined(&fse::LL_DEFAULT, fse::LL_LOG, code)
                + sequences::literal_len_extra(code as u32) * 256;
        }
        for (code, price) in prices.match_len.iter_mut().enumerate() {
            *price = predefined(&fse::ML_DEFAULT, fse::ML_LOG, code)
                + sequences::match_len_extra(code as u32) * 256;
        }
        for (code, price) in prices.offset.iter_mut().enumerate() {
            *price = predefined(&fse::OF_DEFAULT, fse::OF_LOG, code) + code as u32 * 256;
        }
        prices
    }

    /// Reprice from a parse of the same block.
    pub(super) fn fit(block: &[u8], matches: &[Match], repeats: [usize; 3]) -> Self {
        let mut literals = [0u32; 256];
        let mut literal_len = [0u32; 36];
        let mut match_len = [0u32; 53];
        let mut offset = [0u32; 32];
        let mut history = repeats;
        let mut at = 0usize;
        for seq in matches {
            for &byte in &block[at..at + seq.literal_len] {
                literals[byte as usize] += 1;
            }
            at += seq.literal_len + seq.match_len;
            literal_len[sequences::literal_len_code(seq.literal_len as u32) as usize] += 1;
            match_len[sequences::match_len_code(seq.match_len as u32) as usize] += 1;
            let (value, advanced) = matcher::encode_offset(history, seq.offset, seq.literal_len);
            history = advanced;
            offset[(31 - value.leading_zeros()) as usize] += 1;
        }
        for &byte in &block[at..] {
            literals[byte as usize] += 1;
        }

        let mut prices = Self {
            literal: [0; 256],
            literal_len: [0; 36],
            match_len: [0; 53],
            offset: [0; 32],
        };
        prices.set_literals(&literals);
        let sequences_total: u32 = literal_len.iter().sum();
        for (code, price) in prices.literal_len.iter_mut().enumerate() {
            *price = entropy(literal_len[code], sequences_total).max(MIN_SYMBOL_PRICE)
                + sequences::literal_len_extra(code as u32) * 256;
        }
        for (code, price) in prices.match_len.iter_mut().enumerate() {
            *price = entropy(match_len[code], sequences_total).max(MIN_SYMBOL_PRICE)
                + sequences::match_len_extra(code as u32) * 256;
        }
        for (code, price) in prices.offset.iter_mut().enumerate() {
            *price =
                entropy(offset[code], sequences_total).max(MIN_SYMBOL_PRICE) + code as u32 * 256;
        }
        prices
    }

    fn set_literals(&mut self, counts: &[u32; 256]) {
        let total: u32 = counts.iter().sum();
        for (byte, price) in self.literal.iter_mut().enumerate() {
            *price = entropy(counts[byte], total).clamp(MIN_LITERAL_PRICE, MAX_LITERAL_PRICE);
        }
    }

    fn literal_run(&self, len: usize) -> i64 {
        i64::from(self.literal_len[sequences::literal_len_code(len as u32) as usize])
    }

    fn match_run(&self, len: usize) -> i64 {
        i64::from(self.match_len[sequences::match_len_code(len as u32) as usize])
    }

    fn offset_value(&self, value: u32) -> i64 {
        i64::from(self.offset[(31 - value.leading_zeros()) as usize])
    }
}

/// Bits to name one occurrence out of `total`, in 1/256ths.
fn entropy(count: u32, total: u32) -> u32 {
    if total == 0 {
        return 8 * 256;
    }
    if count == 0 {
        return log2_fixed(total) + UNSEEN_PENALTY;
    }
    log2_fixed(total).saturating_sub(log2_fixed(count))
}

/// Bits a symbol costs under one of the format's predefined distributions.
fn predefined(dist: &[i16], log: u32, code: usize) -> u32 {
    let points = dist.get(code).map_or(1, |&p| p.unsigned_abs().max(1));
    (log * 256).saturating_sub(log2_fixed(u32::from(points)))
}

/// One position in the block, holding the best path found to it.
#[derive(Clone, Copy)]
struct Node {
    /// Total price of the path, including the literals-length code of the
    /// run still open at this position.
    price: i64,
    /// Literals immediately before this position on that path.
    literal_len: u32,
    /// Match that arrived here, or zero if a literal did.
    match_len: u32,
    offset: u32,
    repeats: [u32; 3],
}

const UNREACHABLE: Node = Node {
    price: i64::MAX,
    literal_len: 0,
    match_len: 0,
    offset: 0,
    repeats: [0; 3],
};

/// Parse `input[start..end]` into sequences under `prices`.
///
/// Matches may reach back before `start`, as far as the chain sweep allowed,
/// but never produce output past `end`: a block stands on its own.
pub(super) fn parse(
    input: &[u8],
    start: usize,
    end: usize,
    candidates: &Candidates,
    repeats: [usize; 3],
    prices: &Prices,
) -> Vec<Match> {
    let span = end - start;
    let mut nodes = vec![UNREACHABLE; span + 1];
    nodes[0] = Node {
        price: prices.literal_run(0),
        literal_len: 0,
        match_len: 0,
        offset: 0,
        repeats: repeats.map(|r| r as u32),
    };

    for index in 0..span {
        let pos = start + index;
        let here = nodes[index];
        debug_assert!(here.price != i64::MAX);

        // One more literal. Extending an open run can change its length
        // code, so the difference between the two codes is part of the step.
        let run = here.literal_len as usize;
        let step = i64::from(prices.literal[input[pos] as usize]) + prices.literal_run(run + 1)
            - prices.literal_run(run);
        relax(
            &mut nodes[index + 1],
            Node {
                price: here.price + step,
                literal_len: here.literal_len + 1,
                match_len: 0,
                offset: 0,
                repeats: here.repeats,
            },
        );

        let limit = (span - index).min(MAX_MATCH);
        if limit < MIN_REPEAT_MATCH || !candidates.searched(index) {
            continue;
        }
        let history = here.repeats.map(|r| r as usize);
        let cursor = Cursor {
            prices,
            index,
            node: here,
        };

        // A match at a repeat offset is priced with a one- or two-bit code,
        // so it is worth testing even when it is shorter than the chain
        // reports. They come cheapest first, so once one covers a length the
        // dearer ones have nothing to add there.
        let mut covered = MIN_REPEAT_MATCH - 1;
        for offset in matcher::repeat_candidates(history, run) {
            if offset == 0 || offset > pos {
                continue;
            }
            let len = common_prefix(input, pos - offset, pos, limit);
            if len > covered {
                cursor.offer(&mut nodes, offset, len, covered);
                covered = len.min(RELAX_LIMIT).max(covered);
            }
        }

        // Chain candidates arrive nearest first and so also longest-last: a
        // later one is further away, so it can only pay for lengths the
        // nearer ones could not reach.
        let mut covered = MIN_MATCH - 1;
        for &(len, offset) in candidates.at(index) {
            let (len, offset) = (len as usize, offset as usize);
            if len > covered {
                cursor.offer(&mut nodes, offset, len, covered);
                covered = len.min(RELAX_LIMIT).max(covered);
            }
        }
    }

    backtrack(&nodes)
}

/// The position the parser is standing on, and everything an edge leaving
/// it is priced against.
struct Cursor<'a> {
    prices: &'a Prices,
    index: usize,
    node: Node,
}

impl Cursor<'_> {
    /// Price a match of every length in `covered + 1 ..= len` at this
    /// offset, and relax the nodes it can reach.
    ///
    /// Every truncation of a match is a legal sequence of its own, but
    /// pricing all of them would cost time proportional to the match at
    /// every position it covers, so past [`RELAX_LIMIT`] only the full
    /// length is offered.
    fn offer(&self, nodes: &mut [Node], offset: usize, len: usize, covered: usize) {
        let run = self.node.literal_len as usize;
        let history = self.node.repeats.map(|r| r as usize);
        let (value, advanced) = matcher::encode_offset(history, offset, run);
        let base = self.node.price + self.prices.offset_value(value) + self.prices.literal_run(0);
        let advanced = advanced.map(|r| r as u32);
        let mut put = |taken: usize| {
            relax(
                &mut nodes[self.index + taken],
                Node {
                    price: base + self.prices.match_run(taken),
                    literal_len: 0,
                    match_len: taken as u32,
                    offset: offset as u32,
                    repeats: advanced,
                },
            );
        };
        for taken in covered + 1..=len.min(RELAX_LIMIT) {
            put(taken);
        }
        if len > RELAX_LIMIT {
            put(len);
        }
    }
}

fn relax(slot: &mut Node, candidate: Node) {
    if candidate.price < slot.price {
        *slot = candidate;
    }
}

/// Walk the chosen path back from the end of the block and turn it into
/// sequences, in order.
fn backtrack(nodes: &[Node]) -> Vec<Match> {
    let mut ends: Vec<(usize, usize, usize)> = Vec::new();
    let mut index = nodes.len() - 1;
    while index > 0 {
        let node = nodes[index];
        if node.match_len == 0 {
            index -= 1;
            continue;
        }
        let match_len = node.match_len as usize;
        index -= match_len;
        ends.push((index, match_len, node.offset as usize));
    }
    ends.reverse();

    let mut out = Vec::with_capacity(ends.len());
    let mut at = 0usize;
    for (position, match_len, offset) in ends {
        out.push(Match {
            literal_len: position - at,
            match_len,
            offset,
        });
        at = position + match_len;
    }
    out
}
