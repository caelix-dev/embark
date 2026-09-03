//! Codec selection for the `auto` family: compress with a tier of candidate
//! codecs and keep the smallest result.

extern crate alloc;
#[cfg(feature = "enc")]
use alloc::vec::Vec;
#[cfg(feature = "enc")]
use embark_format::CodecId;

/// Which codecs a selection pass is allowed to try.
///
/// Compression runs once, in the proc macro; decompression runs in every
/// consumer's shipped binary on every access. The two are not
/// interchangeable costs, so the tiers cut the codec set by decode speed and
/// each keeps the smallest output *within its own candidates*. Measured on a
/// 125,976-byte executable, with the decoders this crate actually ships:
///
/// | tier | wins with | payload | decode |
/// |---|---|---:|---:|
/// | [`Fast`](AutoTier::Fast) | LZ4 | 81,798 B | 2,775 MB/s |
/// | [`Balanced`](AutoTier::Balanced) | Zstd | 56,140 B | 112 MB/s |
/// | [`Small`](AutoTier::Small) | LZMA | 52,512 B | 41 MB/s |
///
/// The tiers are nested, so a wider one never picks a *larger* payload than
/// a narrower one. They are fixed membership rather than a cost function:
/// which codec a build selects has to be predictable from the asset and the
/// enabled features alone, never from how fast the build machine is.
///
/// The tier is a build-time policy. An entry header records the one
/// [`CodecId`] that won, so nothing about it reaches the decode side.
#[cfg(feature = "enc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoTier {
    /// `Store`, `Lz4`, `Snappy` — the codecs that decode at GB/s.
    ///
    /// Selected by `codec = auto_fast`. Also by far the cheapest to
    /// *encode*: it runs neither the LZMA nor the Zstd encoder, both of
    /// which search hard enough to cost minutes on a large, poorly
    /// compressible asset. Measured on 32 MiB of such data: this tier took
    /// 0.2 s where [`Balanced`](AutoTier::Balanced) took 180 s.
    Fast,
    /// [`Fast`](AutoTier::Fast) plus `Deflate` and `Zstd`.
    ///
    /// Selected by `codec = auto`, and the balance point the `auto` family
    /// is named for: roughly a third off the payload `Fast` picks, and
    /// still read back around three times quicker than LZMA's.
    ///
    /// The balance is in *decode* speed, which the consumer's binary pays on
    /// every access. It is not cheap to encode: Zstd parses each block by
    /// price over several passes, so a large asset costs this tier minutes
    /// at build time. See the README's note on build times.
    Balanced,
    /// [`Balanced`](AutoTier::Balanced) plus `Lzma` — every compressing
    /// codec there is.
    ///
    /// Selected by `codec = auto_small`. The smallest binary available, at
    /// the slowest decode. Its build cost is close to
    /// [`Balanced`](AutoTier::Balanced)'s rather than far above it, since
    /// both tiers run a codec that searches hard: 226 s against 180 s on
    /// the same 32 MiB asset.
    Small,
}

/// Whether `id` is one of `tier`'s candidates.
///
/// [`CodecId::Store`] is deliberately absent: it is the baseline every tier
/// falls back to when nothing shrinks the input, not a codec a tier chooses
/// between.
#[cfg(feature = "enc")]
fn contains(tier: AutoTier, id: CodecId) -> bool {
    match id {
        CodecId::Lz4 | CodecId::Snappy => true,
        CodecId::Deflate | CodecId::Zstd => matches!(tier, AutoTier::Balanced | AutoTier::Small),
        CodecId::Lzma => matches!(tier, AutoTier::Small),
        // `Store`, plus -- `CodecId` being `#[non_exhaustive]` -- any codec
        // added to the format and not yet placed in a tier.
        _ => false,
    }
}

/// Whether this build compiled in any of `tier`'s candidates.
#[cfg(feature = "enc")]
fn is_populated(tier: AutoTier) -> bool {
    crate::dispatch::ENCODERS
        .iter()
        .any(|&(id, _)| contains(tier, id))
}

/// The tier a request for `tier` actually runs, after widening.
///
/// A tier whose candidates are all switched off at feature level would
/// otherwise emit `Store` and leave the asset uncompressed, which is the
/// worst outcome on both axes at once. The tiers nest, so widening is
/// well-defined: take the narrowest tier at or above the requested one that
/// this build has a candidate for. A build with only `lzma` on therefore
/// serves `auto_fast` with LZMA -- the fast codecs it asked for do not
/// exist here, and LZMA is strictly better than not compressing.
///
/// This depends only on the enabled features, never on the asset or the
/// build machine.
#[cfg(feature = "enc")]
fn effective(tier: AutoTier) -> AutoTier {
    let wider: &[AutoTier] = match tier {
        AutoTier::Fast => &[AutoTier::Fast, AutoTier::Balanced, AutoTier::Small],
        AutoTier::Balanced => &[AutoTier::Balanced, AutoTier::Small],
        AutoTier::Small => &[AutoTier::Small],
    };
    // With no compressing codec compiled in at all there is nothing to widen
    // to; the caller falls through to `Store` either way.
    wider
        .iter()
        .copied()
        .find(|&t| is_populated(t))
        .unwrap_or(tier)
}

/// Compress `input` with each of `tier`'s candidates compiled into this
/// build and return the smallest result.
///
/// Only the tier's own candidates are encoded, so `AutoTier::Fast` does not
/// pay LZMA's encode time to then discard its output.
///
/// [`CodecId::Store`] is the baseline: a codec wins only if it is strictly
/// smaller than the input, and among codecs the earliest entry of the codec
/// table wins a tie, which is what `min_by_key` yields.
///
/// If none of `tier`'s candidates were compiled in, the selection widens to
/// the next tier rather than giving up and storing the input verbatim.
#[cfg(feature = "enc")]
#[must_use]
pub fn compress_best_in(tier: AutoTier, input: &[u8]) -> (CodecId, Vec<u8>) {
    let tier = effective(tier);
    // The candidates are independent: each reads the same input and writes
    // its own output, and none of them looks at what another produced. With
    // `parallel-encode` on they run concurrently, which matters most for the
    // tiers that include a codec searching as hard as Zstd or LZMA.
    //
    // `map` preserves the table's order, so the tie-break below is the one
    // the table spells out rather than whichever encoder happened to finish
    // first.
    let candidates: Vec<(CodecId, crate::dispatch::CompressFn)> = crate::dispatch::ENCODERS
        .iter()
        .copied()
        .filter(|&(id, _)| contains(tier, id))
        .collect();
    crate::threads::map(&candidates, |&(id, compress)| (id, compress(input)))
        .into_iter()
        .min_by_key(|(_, out)| out.len())
        .filter(|(_, out)| out.len() < input.len())
        .unwrap_or_else(|| (CodecId::Store, crate::store::compress(input)))
}

/// Compress `input` with every codec compiled into this build and return the
/// smallest result.
///
/// The smallest-output end of the family, equivalent to
/// [`compress_best_in`] with [`AutoTier::Small`].
#[cfg(feature = "enc")]
#[must_use]
pub fn compress_best(input: &[u8]) -> (CodecId, Vec<u8>) {
    compress_best_in(AutoTier::Small, input)
}
