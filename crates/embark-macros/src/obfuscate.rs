//! Build-time "obfuscation compiler" for embedded keys.
//!
//! The embedded-key mode of `embed_crypt!` / `#[embark(encrypt)]` bakes the
//! 32-byte key into the binary. To keep the reconstruction from being
//! trivially generic across every `embark` binary (embark is open source, so
//! the *scheme* is public), we generate — fresh for every build, from the
//! build-time CSPRNG — a randomized, straight-line function that reassembles
//! the key. No two builds emit the same function: the op count, op types,
//! their order, all constants, permutations and rotation amounts are random,
//! so no single generic extractor works across binaries; each must be
//! reversed individually.
//!
//! This is **obfuscation, not security**: the key still ships in the binary
//! and a determined reverser can recover it. See `EncryptedFile`'s docs.
//!
//! ## How it works
//!
//! We operate on a 32-byte accumulator with a handful of *invertible* ops
//! (see [`Op`]). For a given key we:
//!
//! 1. pick a random forward program `F = [op_1 .. op_M]` (M in `8..=20`);
//! 2. compute the seed `S0 = F^{-1}(key)` by applying each op's inverse in
//!    reverse order ([`seed_of`]);
//! 3. split `S0` into 2–3 random shares that XOR back to `S0` (so `S0` is
//!    never a single literal), plus optional canceling decoy no-ops;
//! 4. emit a `fn` that XOR-assembles the shares and then applies `op_1..op_M`
//!    as inline straight-line Rust with all constants baked in as literals.
//!
//! Running `F` on `S0` yields the key: `F(F^{-1}(key)) == key`. The share
//! literals are fed through [`core::hint::black_box`] in the emitted code so
//! the optimizer cannot constant-fold the whole function back down to a bare
//! key literal (which would defeat the obfuscation).

use embark_crypt::gen_key_nonce;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// A small `SplitMix64` PRNG, seeded from `embark_crypt::gen_key_nonce` (the
/// same build-time CSPRNG the key itself is drawn from). Used only to pick
/// the shape of the obfuscation program; it never touches key material.
struct Rng {
    state: u64,
}

impl Rng {
    fn new() -> Self {
        let (key, nonce) = gen_key_nonce();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut mix = |bytes: &[u8]| {
            for chunk in bytes.chunks(8) {
                let mut b = [0u8; 8];
                b[..chunk.len()].copy_from_slice(chunk);
                state ^= u64::from_le_bytes(b);
                state = state.rotate_left(13).wrapping_mul(0x2545_F491_4F6C_DD1D);
            }
        };
        mix(&key);
        mix(&nonce);
        Rng { state }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish value in `0..n` (n > 0).
    fn below(&mut self, n: u32) -> u32 {
        (self.next_u64() % n as u64) as u32
    }

    /// Uniform-ish value in `lo..=hi`.
    fn range_incl(&mut self, lo: u32, hi: u32) -> u32 {
        lo + self.below(hi - lo + 1)
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    fn arr32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for x in a.iter_mut() {
            *x = self.byte();
        }
        a
    }

    /// A uniformly random permutation of `0..32` (Fisher–Yates).
    fn perm(&mut self) -> [u8; 32] {
        let mut p = [0u8; 32];
        for (i, slot) in p.iter_mut().enumerate() {
            *slot = i as u8;
        }
        for i in (1..32).rev() {
            let j = self.below(i as u32 + 1) as usize;
            p.swap(i, j);
        }
        p
    }
}

/// One invertible operation on the 32-byte accumulator.
///
/// Every variant has an exact inverse (see [`apply_inverse`]), which is what
/// makes `F(F^{-1}(key)) == key` hold:
///
/// - [`Op::Xor`] `a[i] ^= c[i]` — self-inverse.
/// - [`Op::Add`] `a[i] = a[i].wrapping_add(c[i])` — inverse is `wrapping_sub`.
/// - [`Op::Rotl`] `a[i] = a[i].rotate_left(k)` (k in `1..=7`) — inverse is
///   `rotate_right(k)`.
/// - [`Op::Perm`] `out[i] = a[p[i]]` for a permutation `p` — inverse applies
///   the same shape with `inv_p` (`inv_p[p[i]] = i`).
/// - [`Op::Reverse`] `a[i] = a[31 - i]` — self-inverse.
#[derive(Clone)]
enum Op {
    Xor([u8; 32]),
    Add([u8; 32]),
    Rotl(u32),
    Perm([u8; 32]),
    Reverse,
}

impl Op {
    fn random(rng: &mut Rng) -> Op {
        match rng.below(5) {
            0 => Op::Xor(rng.arr32()),
            1 => Op::Add(rng.arr32()),
            2 => Op::Rotl(rng.range_incl(1, 7)),
            3 => Op::Perm(rng.perm()),
            _ => Op::Reverse,
        }
    }
}

/// `inv_p[p[i]] = i`; the permutation that undoes `p`.
fn inverse_perm(p: &[u8; 32]) -> [u8; 32] {
    let mut inv = [0u8; 32];
    for (i, &pi) in p.iter().enumerate() {
        inv[pi as usize] = i as u8;
    }
    inv
}

/// Applies `op` forward to the accumulator — the exact semantics the emitted
/// code reproduces. Only used by the correctness tests; the build path emits
/// tokens ([`emit_forward`]) and computes seeds via inverses ([`seed_of`]).
#[cfg(test)]
fn apply_forward(op: &Op, a: &mut [u8; 32]) {
    match op {
        Op::Xor(c) => {
            for i in 0..32 {
                a[i] ^= c[i];
            }
        }
        Op::Add(c) => {
            for i in 0..32 {
                a[i] = a[i].wrapping_add(c[i]);
            }
        }
        Op::Rotl(k) => {
            for x in a.iter_mut() {
                *x = x.rotate_left(*k);
            }
        }
        Op::Perm(p) => {
            let t = *a;
            for i in 0..32 {
                a[i] = t[p[i] as usize];
            }
        }
        Op::Reverse => {
            let t = *a;
            for i in 0..32 {
                a[i] = t[31 - i];
            }
        }
    }
}

/// Applies the inverse of `op`. Used only at build time to derive the seed;
/// never emitted.
fn apply_inverse(op: &Op, a: &mut [u8; 32]) {
    match op {
        Op::Xor(c) => {
            for i in 0..32 {
                a[i] ^= c[i];
            }
        }
        Op::Add(c) => {
            for i in 0..32 {
                a[i] = a[i].wrapping_sub(c[i]);
            }
        }
        Op::Rotl(k) => {
            for x in a.iter_mut() {
                *x = x.rotate_right(*k);
            }
        }
        Op::Perm(p) => {
            let inv = inverse_perm(p);
            let t = *a;
            for i in 0..32 {
                a[i] = t[inv[i] as usize];
            }
        }
        Op::Reverse => {
            let t = *a;
            for i in 0..32 {
                a[i] = t[31 - i];
            }
        }
    }
}

/// `S0 = F^{-1}(key)`: apply each op's inverse in reverse order, so that
/// replaying the forward program on `S0` reproduces `key`.
fn seed_of(key: [u8; 32], program: &[Op]) -> [u8; 32] {
    let mut a = key;
    for op in program.iter().rev() {
        apply_inverse(op, &mut a);
    }
    a
}

/// A `u8` literal token (`0xNN_u8`), for baking constants into the emitted
/// straight-line code.
fn byte_lit(b: u8) -> TokenStream {
    quote!(#b)
}

/// A `usize` literal token, for baked-in array indices.
fn idx_lit(i: usize) -> TokenStream {
    let lit = proc_macro2::Literal::usize_unsuffixed(i);
    quote!(#lit)
}

/// Emits the statements for one forward op, operating on the local `a`.
/// `slot` disambiguates the temporary binding used by `Perm`/`Reverse`.
fn emit_forward(op: &Op, slot: usize, out: &mut Vec<TokenStream>) {
    match op {
        Op::Xor(c) => {
            for (i, &ci) in c.iter().enumerate() {
                let (i, ci) = (idx_lit(i), byte_lit(ci));
                out.push(quote!(a[#i] ^= #ci;));
            }
        }
        Op::Add(c) => {
            for (i, &ci) in c.iter().enumerate() {
                let (i, ci) = (idx_lit(i), byte_lit(ci));
                out.push(quote!(a[#i] = a[#i].wrapping_add(#ci);));
            }
        }
        Op::Rotl(k) => {
            for i in 0..32 {
                let i = idx_lit(i);
                out.push(quote!(a[#i] = a[#i].rotate_left(#k);));
            }
        }
        Op::Perm(p) => {
            let t = format_ident!("t{}", slot);
            out.push(quote!(let #t = a;));
            for (i, &pi) in p.iter().enumerate() {
                let (i, pi) = (idx_lit(i), idx_lit(pi as usize));
                out.push(quote!(a[#i] = #t[#pi];));
            }
        }
        Op::Reverse => {
            let t = format_ident!("t{}", slot);
            out.push(quote!(let #t = a;));
            for i in 0..32 {
                let (i, r) = (idx_lit(i), idx_lit(31 - i));
                out.push(quote!(a[#i] = #t[#r];));
            }
        }
    }
}

/// Builds the random forward program and the shares of `S0` for `key`.
struct Plan {
    program: Vec<Op>,
    shares: Vec<[u8; 32]>,
    decoys: Vec<[u8; 32]>,
}

fn plan(rng: &mut Rng, key: [u8; 32]) -> Plan {
    let m = rng.range_incl(8, 20);
    let program: Vec<Op> = (0..m).map(|_| Op::random(rng)).collect();
    let s0 = seed_of(key, &program);

    // 2–3 shares that XOR to S0: fill all but the last at random, then set
    // the last so the XOR of every share reproduces S0.
    let nshares = rng.range_incl(2, 3) as usize;
    let mut shares: Vec<[u8; 32]> = (0..nshares - 1).map(|_| rng.arr32()).collect();
    let mut last = s0;
    for sh in &shares {
        for i in 0..32 {
            last[i] ^= sh[i];
        }
    }
    shares.push(last);

    // A couple of canceling decoy constants (each XORed in and back out, so a
    // provable no-op) — pure source-level noise, distinct every build.
    let ndecoys = rng.range_incl(0, 2) as usize;
    let decoys: Vec<[u8; 32]> = (0..ndecoys).map(|_| rng.arr32()).collect();

    Plan {
        program,
        shares,
        decoys,
    }
}

/// Generates a per-build-unique key-reconstruction function for `key`.
///
/// Returns the `fn` item (to be spliced into the caller's crate) and its
/// (also random) name. Calling that function at runtime returns exactly
/// `key`. See the module docs for the guarantees and caveats.
pub(crate) fn emit_key_recon(key: &[u8; 32]) -> (TokenStream, syn::Ident) {
    let mut rng = Rng::new();
    let Plan {
        program,
        shares,
        decoys,
    } = plan(&mut rng, *key);

    let name = format_ident!("__embark_recon_{:016x}", rng.next_u64());

    let mut stmts: Vec<TokenStream> = Vec::new();

    // Assemble `a` from the black-boxed shares. black_box keeps the optimizer
    // from folding the share literals (and the whole function) back into a
    // bare key literal, so the reconstruction actually runs at runtime.
    let share_idents: Vec<syn::Ident> =
        (0..shares.len()).map(|j| format_ident!("s{}", j)).collect();
    for (ident, share) in share_idents.iter().zip(&shares) {
        let lits = share.iter().map(|&b| byte_lit(b));
        stmts.push(quote! {
            let #ident: [u8; 32] = ::core::hint::black_box([#(#lits),*]);
        });
    }
    stmts.push(quote!(let mut a: [u8; 32] = [0u8; 32];));
    for i in 0..32 {
        let i = idx_lit(i);
        let terms = share_idents.iter().map(|s| quote!(#s[#i]));
        stmts.push(quote!(a[#i] = #(#terms)^*;));
    }

    // Canceling decoys: xor each in, then straight back out (net identity).
    for d in &decoys {
        for pass in 0..2 {
            let _ = pass;
            for (i, &di) in d.iter().enumerate() {
                let (i, di) = (idx_lit(i), byte_lit(di));
                stmts.push(quote!(a[#i] ^= #di;));
            }
        }
    }

    // The forward program, fully inlined as straight-line Rust.
    for (slot, op) in program.iter().enumerate() {
        emit_forward(op, slot, &mut stmts);
    }

    let item = quote! {
        #[allow(clippy::all)]
        fn #name() -> [u8; 32] {
            #(#stmts)*
            a
        }
    };
    (item, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fresh RNG for tests (deterministic per process is not needed; we want
    // wide coverage, so we just draw from the same source many times).
    fn rng() -> Rng {
        Rng::new()
    }

    #[test]
    fn inverse_perm_is_correct() {
        let mut r = rng();
        for _ in 0..1000 {
            let p = r.perm();
            let inv = inverse_perm(&p);
            // p is a permutation of 0..32.
            let mut seen = [false; 32];
            for &pi in &p {
                assert!(!seen[pi as usize], "p is not a permutation");
                seen[pi as usize] = true;
            }
            // Applying Perm(p) then Perm(inv_p) is the identity.
            let a = r.arr32();
            let mut b = a;
            apply_forward(&Op::Perm(p), &mut b);
            apply_forward(&Op::Perm(inv), &mut b);
            assert_eq!(a, b, "Perm(p) then Perm(inv_p) must be identity");
        }
    }

    #[test]
    fn each_op_forward_then_inverse_is_identity() {
        let mut r = rng();
        for _ in 0..2000 {
            let ops = [
                Op::Xor(r.arr32()),
                Op::Add(r.arr32()),
                Op::Rotl(r.range_incl(1, 7)),
                Op::Perm(r.perm()),
                Op::Reverse,
            ];
            for op in &ops {
                let a = r.arr32();
                // forward then inverse
                let mut b = a;
                apply_forward(op, &mut b);
                apply_inverse(op, &mut b);
                assert_eq!(a, b, "forward then inverse must be identity");
                // inverse then forward
                let mut c = a;
                apply_inverse(op, &mut c);
                apply_forward(op, &mut c);
                assert_eq!(a, c, "inverse then forward must be identity");
            }
        }
    }

    #[test]
    fn forward_of_seed_recovers_key() {
        let mut r = rng();
        for _ in 0..5000 {
            let key = r.arr32();
            let m = r.range_incl(8, 20);
            let program: Vec<Op> = (0..m).map(|_| Op::random(&mut r)).collect();

            let s0 = seed_of(key, &program);
            // Replay the forward program on the seed.
            let mut a = s0;
            for op in &program {
                apply_forward(op, &mut a);
            }
            assert_eq!(a, key, "F(F^-1(key)) must equal key");
        }
    }

    #[test]
    fn shares_xor_to_seed() {
        let mut r = rng();
        for _ in 0..2000 {
            let key = r.arr32();
            let p = plan(&mut r, key);
            let s0 = seed_of(key, &p.program);
            let mut acc = [0u8; 32];
            for sh in &p.shares {
                for i in 0..32 {
                    acc[i] ^= sh[i];
                }
            }
            assert_eq!(acc, s0, "shares must XOR to S0");
            assert!(
                p.shares.len() >= 2 && p.shares.len() <= 3,
                "expected 2–3 shares"
            );
        }
    }

    #[test]
    fn emitted_reconstructions_vary_per_build() {
        let key = [0x42u8; 32];
        let (a_tokens, a_name) = emit_key_recon(&key);
        let (b_tokens, b_name) = emit_key_recon(&key);
        assert_ne!(
            a_name.to_string(),
            b_name.to_string(),
            "fn names must differ per build"
        );
        assert_ne!(
            a_tokens.to_string(),
            b_tokens.to_string(),
            "emitted reconstructions for the same key must differ per build"
        );
    }
}
