#![cfg(all(feature = "std", feature = "deflate"))]
use embark::{Embed, EmbeddedFile, Manifest};
use embark_codec::compress;
use embark_format::{CodecId, CryptoId, write_entry};

fn entry(codec: CodecId, data: &[u8]) -> &'static [u8] {
    let payload = compress(codec, data);
    let mut e = Vec::new();
    write_entry(
        &mut e,
        codec,
        CryptoId::None,
        data.len() as u64,
        None,
        &payload,
    );
    Box::leak(e.into_boxed_slice())
}

struct Assets;

// Hand-built manifest standing in for the derive output; entries sorted by path.
fn manifest() -> &'static [Manifest] {
    static M: std::sync::OnceLock<Vec<Manifest>> = std::sync::OnceLock::new();
    M.get_or_init(|| {
        let mut v = vec![
            Manifest {
                path: "a.txt",
                entry: entry(CodecId::Store, b"alpha"),
            },
            Manifest {
                path: "b.txt",
                entry: entry(CodecId::Deflate, &b"beta".repeat(50)),
            },
        ];
        v.sort_by_key(|m| m.path);
        v
    })
}

impl Embed for Assets {
    fn get(path: &str) -> Option<EmbeddedFile> {
        embark::lookup(manifest(), path)
    }
    fn iter() -> embark::Entries {
        embark::entries(manifest())
    }
}

#[test]
fn get_and_iter() {
    assert_eq!(&*Assets::get("a.txt").unwrap().data(), b"alpha");
    assert_eq!(
        &*Assets::get("b.txt").unwrap().data(),
        &b"beta".repeat(50)[..]
    );
    assert!(Assets::get("missing").is_none());
    let paths: Vec<_> = Assets::iter().map(|p| p.into_owned()).collect();
    assert_eq!(paths, vec!["a.txt".to_string(), "b.txt".to_string()]);
}
