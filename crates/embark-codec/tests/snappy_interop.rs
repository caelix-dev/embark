//! Interoperability of our self-implemented Snappy encoder with the
//! reference implementation: the output is handed to `python-snappy` and
//! must decode back to the original bytes. Opt-in via `EMBARK_SNAPPY_INTEROP=1`
//! so the suite stays runnable without Python installed.
#![cfg(all(feature = "enc", feature = "snappy"))]
use std::process::Command;

// Confirms our Snappy output is decodable by the reference `python-snappy`.
#[test]
fn our_snappy_is_standard() {
    if std::env::var("EMBARK_SNAPPY_INTEROP").is_err() {
        eprintln!("skipping snappy interop (set EMBARK_SNAPPY_INTEROP=1)");
        return;
    }
    let data = b"The quick brown fox jumps over the lazy dog. ".repeat(40);
    let compressed = embark_codec::compress(embark_format::CodecId::Snappy, &data);
    // CARGO_TARGET_TMPDIR is set by cargo for test binaries and is guaranteed
    // to exist; a plain relative path is not safe here since cargo runs test
    // binaries with the package directory as cwd, not the workspace root.
    let out_path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("snap_out.bin");
    std::fs::write(&out_path, &compressed).unwrap();

    // python-snappy uses the framed format by default; use raw decompress.
    let py = format!(
        r#"
import sys, snappy
d = open({out_path:?}, 'rb').read()
sys.stdout.buffer.write(snappy.decompress(d))
"#
    );
    let out = Command::new("python3").arg("-c").arg(py).output().unwrap();
    assert!(
        out.status.success(),
        "python-snappy failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, data);
}
