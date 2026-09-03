extern crate alloc;
#[cfg(feature = "enc")]
use alloc::vec::Vec;
#[cfg(feature = "enc")]
use embark_format::CodecId;

/// Compress `input` with every codec compiled into this build and return the
/// smallest result.
///
/// [`CodecId::Store`] is the baseline: a codec wins only if it is strictly
/// smaller than the input, and among codecs the earliest entry of the codec
/// table wins a tie, which is what `min_by_key` yields.
#[cfg(feature = "enc")]
pub fn compress_best(input: &[u8]) -> (CodecId, Vec<u8>) {
    crate::dispatch::ENCODERS
        .iter()
        .filter(|&&(id, _)| id != CodecId::Store)
        .map(|&(id, compress)| (id, compress(input)))
        .min_by_key(|(_, out)| out.len())
        .filter(|(_, out)| out.len() < input.len())
        .unwrap_or_else(|| (CodecId::Store, crate::store::compress(input)))
}
