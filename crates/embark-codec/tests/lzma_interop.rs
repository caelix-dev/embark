//! Interoperability of our self-implemented LZMA1 `.lzma` codec with the
//! reference `xz` tool. Gated behind `EMBARK_LZMA_INTEROP=1` so environments
//! without `xz` skip it. Both directions are checked:
//!   * ours -> xz  proves our encoder emits valid LZMA1.
//!   * xz  -> ours proves our decoder is spec-correct.
#![cfg(all(feature = "enc", feature = "dec", feature = "lzma"))]
use std::io::Write;
use std::process::{Command, Stdio};

fn samples() -> Vec<Vec<u8>> {
    // Deterministic pseudo-random (incompressible) data.
    let mut x: u32 = 0x9E37_79B1;
    let mut r = vec![0u8; 8192];
    for b in r.iter_mut() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = (x & 0xff) as u8;
    }
    vec![
        Vec::new(),
        b"Q".to_vec(),
        vec![0u8; 5000],
        b"The quick brown fox jumps over the lazy dog. ".repeat(80),
        b"abcabcabcabcabc".repeat(300),
        (0u8..=255).cycle().take(4096).collect(),
        r,
    ]
}

fn run_xz(args: &[&str], input: &[u8]) -> Vec<u8> {
    let mut child = Command::new("xz")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xz");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("write to xz");
    let out = child.wait_with_output().expect("wait xz");
    assert!(
        out.status.success(),
        "xz {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn ours_decodes_by_xz() {
    if std::env::var("EMBARK_LZMA_INTEROP").is_err() {
        eprintln!("skipping lzma interop (set EMBARK_LZMA_INTEROP=1)");
        return;
    }
    for data in samples() {
        let compressed = embark_codec::compress(embark_format::CodecId::Lzma, &data);
        // xz decodes our .lzma back to the original.
        let got = run_xz(&["-d", "--format=lzma", "--stdout"], &compressed);
        assert_eq!(got, data, "ours->xz mismatch (len {})", data.len());
    }
}

#[test]
fn xz_output_decodes_by_ours() {
    if std::env::var("EMBARK_LZMA_INTEROP").is_err() {
        eprintln!("skipping lzma interop (set EMBARK_LZMA_INTEROP=1)");
        return;
    }
    for data in samples() {
        // xz produces a .lzma alone stream; our decoder must reproduce data.
        let compressed = run_xz(&["-z", "--format=lzma", "--stdout", "-6"], &data);
        let got = embark_codec::decompress(embark_format::CodecId::Lzma, &compressed, data.len())
            .expect("our decompress of xz output");
        assert_eq!(got, data, "xz->ours mismatch (len {})", data.len());
    }
}
