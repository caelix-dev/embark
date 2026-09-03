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
    let mut paths: Vec<_> = Assets::iter().map(|p| p.into_owned()).collect();
    paths.sort();
    assert_eq!(
        paths,
        vec!["one.txt".to_string(), "sub/two.txt".to_string()]
    );
}
