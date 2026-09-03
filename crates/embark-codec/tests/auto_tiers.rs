//! The `auto` family of selection policies: that each tier picks only from
//! its own candidates, that widening keeps an unpopulated tier from shipping
//! uncompressed bytes, and that the widest tier still behaves exactly as
//! `compress_best` always has.
//!
//! Every assertion here is written against the *enabled* codecs rather than
//! against a fixed expectation, so the file says something under any feature
//! combination -- including the single-codec builds where widening is the
//! only thing keeping compression alive.
#![cfg(all(feature = "enc", feature = "dec"))]
use embark_codec::{AutoTier, compress_best, compress_best_in, decompress};
use embark_format::CodecId;

const TIERS: &[AutoTier] = &[AutoTier::Fast, AutoTier::Balanced, AutoTier::Small];

/// The codecs this build compiled in, excluding `Store`.
const ENABLED: &[CodecId] = &[
    #[cfg(feature = "deflate")]
    CodecId::Deflate,
    #[cfg(feature = "lz4")]
    CodecId::Lz4,
    #[cfg(feature = "snappy")]
    CodecId::Snappy,
    #[cfg(feature = "zstd")]
    CodecId::Zstd,
    #[cfg(feature = "lzma")]
    CodecId::Lzma,
];

/// The tier table from the documentation, restated independently of the
/// implementation.
fn membership(tier: AutoTier, id: CodecId) -> bool {
    match id {
        CodecId::Lz4 | CodecId::Snappy => true,
        CodecId::Deflate | CodecId::Zstd => tier != AutoTier::Fast,
        CodecId::Lzma => tier == AutoTier::Small,
        _ => false,
    }
}

/// The candidates `tier` may pick from in this build, after widening to the
/// narrowest populated tier at or above it.
fn candidates(tier: AutoTier) -> Vec<CodecId> {
    let wider = match tier {
        AutoTier::Fast => TIERS,
        AutoTier::Balanced => &TIERS[1..],
        AutoTier::Small => &TIERS[2..],
    };
    for &t in wider {
        let found: Vec<CodecId> = ENABLED
            .iter()
            .copied()
            .filter(|&id| membership(t, id))
            .collect();
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

fn corpus() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"x".to_vec(),
        b"The quick brown fox jumps over the lazy dog.".to_vec(),
        vec![0u8; 4096],
        b"embark embeds files into your binary. ".repeat(64),
        // Pseudo-random, so no codec shrinks it and every tier has to fall
        // back to `Store`.
        (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect(),
    ]
}

#[test]
fn every_tier_roundtrips() {
    for data in corpus() {
        for &tier in TIERS {
            let (id, packed) = compress_best_in(tier, &data);
            let back = decompress(id, &packed, data.len()).unwrap();
            assert_eq!(back, data, "tier {tier:?} picked {id:?}");
        }
    }
}

#[test]
fn a_tier_picks_only_its_own_candidates() {
    let allowed = |tier| candidates(tier);
    for data in corpus() {
        for &tier in TIERS {
            let (id, _) = compress_best_in(tier, &data);
            assert!(
                id == CodecId::Store || allowed(tier).contains(&id),
                "tier {tier:?} picked {id:?}, which is not among {:?}",
                allowed(tier)
            );
        }
    }
}

/// A tier with no enabled candidate widens instead of storing the input
/// verbatim. With only `lzma` compiled in, this is what makes `auto_fast`
/// compress at all.
#[test]
fn a_tier_with_no_enabled_candidate_widens_rather_than_storing() {
    // Nothing to widen to in a build with no compressing codec at all.
    if candidates(AutoTier::Small).is_empty() {
        return;
    }
    let data = b"embark embeds files into your binary. ".repeat(64);
    for &tier in TIERS {
        let (id, packed) = compress_best_in(tier, &data);
        assert_ne!(
            id,
            CodecId::Store,
            "tier {tier:?} stored compressible data with {ENABLED:?} enabled"
        );
        assert!(packed.len() < data.len());
    }
}

#[test]
fn no_tier_returns_more_bytes_than_storing() {
    for data in corpus() {
        for &tier in TIERS {
            let (_, packed) = compress_best_in(tier, &data);
            assert!(packed.len() <= data.len(), "tier {tier:?} grew the input");
        }
    }
}

/// The tiers nest, so a wider one can never be talked into a larger payload
/// than a narrower one. This is the property that makes `auto_small` the
/// size floor and `auto` a bounded concession, not a gamble.
#[test]
fn a_wider_tier_never_produces_a_larger_payload() {
    for data in corpus() {
        let fast = compress_best_in(AutoTier::Fast, &data).1.len();
        let balanced = compress_best_in(AutoTier::Balanced, &data).1.len();
        let small = compress_best_in(AutoTier::Small, &data).1.len();
        assert!(balanced <= fast, "{balanced} > {fast}");
        assert!(small <= balanced, "{small} > {balanced}");
    }
}

/// `auto_small` is the old `auto`: the same candidates, the same tie rule,
/// the same bytes.
#[test]
fn the_small_tier_is_exactly_compress_best() {
    for data in corpus() {
        let (small_id, small) = compress_best_in(AutoTier::Small, &data);
        let (best_id, best) = compress_best(&data);
        assert_eq!(small_id, best_id);
        assert_eq!(small, best);
    }
}
