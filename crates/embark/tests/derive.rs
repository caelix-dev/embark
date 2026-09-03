#![cfg(all(feature = "std", feature = "derive", feature = "deflate"))]
use embark::Embed;

#[derive(Embed)]
#[embark(folder = "tests/assets/")]
#[embark(codec = "auto")]
#[embark(exclude = "*.skip")]
struct Assets;

#[test]
fn derive_get_iter() {
    assert_eq!(&*Assets::get("one.txt").unwrap().data(), b"one\n");
    assert!(Assets::get("ignore.skip").is_none());
    let mut paths: Vec<&str> = Assets::iter().collect();
    paths.sort();
    assert_eq!(paths, ["one.txt", "sub/two.txt"]);
}
