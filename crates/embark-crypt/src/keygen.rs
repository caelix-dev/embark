pub fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Draws a fresh key and nonce for one embedded entry from the operating
/// system CSPRNG.
///
/// The key and the nonce come from two independent calls, because the nonce is
/// stored in cleartext in the entry header and must therefore carry no
/// information about the key. Taking both from a single userspace generator
/// lets an attacker invert its output function on the published nonce, recover
/// the generator state and replay the key.
///
/// # Panics
///
/// Panics if the operating system generator is unavailable. This runs at build
/// time inside a proc macro, where there is no safe fallback: substituting a
/// weaker source would silently produce a guessable key.
#[cfg(feature = "enc")]
pub fn gen_key_nonce() -> ([u8; 32], [u8; 12]) {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    fill_from_os(&mut key);
    fill_from_os(&mut nonce);
    (key, nonce)
}

#[cfg(feature = "enc")]
fn fill_from_os(out: &mut [u8]) {
    if let Err(err) = getrandom::fill(out) {
        panic!("embark-crypt: operating system random generator unavailable: {err}");
    }
}

#[cfg(all(test, feature = "enc"))]
mod tests {
    use super::*;

    const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;
    const MIX_A: u64 = 0xBF58_476D_1CE4_E5B9;
    const MIX_B: u64 = 0x94D0_49BB_1331_11EB;

    /// The generator `gen_key_nonce` used to draw both the key and the nonce
    /// from. Kept here so the tests can demonstrate that the recovery attack it
    /// enabled is real, and that the current implementation defeats it.
    struct SplitMix64 {
        state: u64,
    }

    impl SplitMix64 {
        fn fill(&mut self, out: &mut [u8]) {
            for chunk in out.chunks_mut(8) {
                self.state = self.state.wrapping_add(GOLDEN_GAMMA);
                let bytes = finalize(self.state).to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    fn finalize(state: u64) -> u64 {
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(MIX_A);
        z = (z ^ (z >> 27)).wrapping_mul(MIX_B);
        z ^ (z >> 31)
    }

    fn modular_inverse(a: u64) -> u64 {
        let mut inv = a;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv)));
        }
        inv
    }

    fn undo_xor_shift_right(x: u64, shift: u32) -> u64 {
        let mut y = x;
        let mut known = shift;
        while known < 64 {
            y = x ^ (y >> shift);
            known += shift;
        }
        y
    }

    fn invert_finalize(output: u64) -> u64 {
        let mut z = undo_xor_shift_right(output, 31);
        z = z.wrapping_mul(modular_inverse(MIX_B));
        z = undo_xor_shift_right(z, 27);
        z = z.wrapping_mul(modular_inverse(MIX_A));
        undo_xor_shift_right(z, 30)
    }

    /// The attack: given only the cleartext nonce, invert the finalizer to
    /// recover the generator state, step the counter back over the four words
    /// that made up the key, and replay them.
    fn key_from_nonce(nonce: &[u8; 12]) -> [u8; 32] {
        let mut leading = [0u8; 8];
        leading.copy_from_slice(&nonce[..8]);
        let nonce_state = invert_finalize(u64::from_le_bytes(leading));

        let mut key = [0u8; 32];
        for (index, word) in key.chunks_mut(8).enumerate() {
            let steps_back = 4 - index as u64;
            let state = nonce_state.wrapping_sub(GOLDEN_GAMMA.wrapping_mul(steps_back));
            word.copy_from_slice(&finalize(state).to_le_bytes());
        }
        key
    }

    #[test]
    fn finalizer_inverse_is_exact() {
        for state in [0u64, 1, u64::MAX, 0x0123_4567_89AB_CDEF, GOLDEN_GAMMA] {
            assert_eq!(invert_finalize(finalize(state)), state);
        }
        assert_eq!(MIX_A.wrapping_mul(modular_inverse(MIX_A)), 1);
        assert_eq!(MIX_B.wrapping_mul(modular_inverse(MIX_B)), 1);
    }

    #[test]
    fn attack_recovers_the_key_from_a_shared_splitmix64_stream() {
        for seed in 0..256u64 {
            let mut prng = SplitMix64 {
                state: seed.wrapping_mul(GOLDEN_GAMMA) ^ 0xDEAD_BEEF_CAFE_F00D,
            };
            let mut key = [0u8; 32];
            let mut nonce = [0u8; 12];
            prng.fill(&mut key);
            prng.fill(&mut nonce);

            assert_eq!(
                key_from_nonce(&nonce),
                key,
                "the attack must work against the old construction, \
                 otherwise the regression test below proves nothing"
            );
        }
    }

    #[test]
    fn nonce_never_reveals_the_key() {
        for _ in 0..1000 {
            let (key, nonce) = gen_key_nonce();
            assert_ne!(
                key_from_nonce(&nonce),
                key,
                "the key must not be derivable from the cleartext nonce"
            );
        }
    }

    #[test]
    fn key_and_nonce_are_not_trivially_related() {
        for _ in 0..1000 {
            let (key, nonce) = gen_key_nonce();
            assert_ne!(key, [0u8; 32]);
            assert_ne!(nonce, [0u8; 12]);
            assert_ne!(&key[..12], &nonce[..]);
            assert!(
                !key.windows(12).any(|window| window == nonce),
                "the nonce must not appear anywhere inside the key"
            );
        }
    }

    #[test]
    fn keys_differ_between_calls() {
        let (k1, n1) = gen_key_nonce();
        let (k2, n2) = gen_key_nonce();
        assert_ne!(k1, k2);
        assert_ne!(n1, n2);
    }

    #[test]
    fn xor_is_involutive() {
        let key = [0x11u8; 32];
        let mask = [0xA5u8; 32];
        let masked = xor32(&key, &mask);
        assert_ne!(masked, key);
        assert_eq!(xor32(&masked, &mask), key);
    }
}
