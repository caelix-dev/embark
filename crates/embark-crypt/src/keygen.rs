pub fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

#[cfg(feature = "enc")]
pub fn gen_key_nonce() -> ([u8; 32], [u8; 12]) {
    let mut prng = SplitMix64::from_entropy();
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    prng.fill(&mut key);
    prng.fill(&mut nonce);
    (key, nonce)
}

#[cfg(feature = "enc")]
struct SplitMix64 {
    state: u64,
}

#[cfg(feature = "enc")]
impl SplitMix64 {
    fn from_entropy() -> Self {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut seed = RandomState::new().build_hasher().finish();
        if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
            seed ^= dur.as_nanos() as u64;
        }
        seed ^= std::process::id() as u64;
        seed = seed.rotate_left(17).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        SplitMix64 { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[cfg(all(test, feature = "enc"))]
mod tests {
    use super::*;

    #[test]
    fn keys_differ_between_calls() {
        let (k1, n1) = gen_key_nonce();
        let (k2, n2) = gen_key_nonce();
        assert!(k1 != k2 || n1 != n2, "two draws should not collide");
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
