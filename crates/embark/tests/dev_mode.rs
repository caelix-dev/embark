//! `#[embark(dev)]` reads off disk in debug builds, from a path the caller
//! supplies. That path must be able to name an embedded file and nothing
//! else: not a file outside the folder, and not the same file under a name
//! the manifest would not know.
#![cfg(all(
    feature = "std",
    feature = "derive",
    feature = "deflate",
    debug_assertions
))]
use embark::Embed;

#[derive(Embed)]
#[embark(folder = "tests/assets/", dev, exclude = "*.skip")]
struct Assets;

#[test]
fn dev_mode_serves_the_manifest_names_and_only_those() {
    assert_eq!(&*Assets::get("one.txt").unwrap().data(), b"one\n");
    assert!(Assets::get("sub/two.txt").is_some());

    for request in [
        // Out of the folder, in every spelling.
        "../Cargo.toml",
        r"..\Cargo.toml",
        "sub/../../Cargo.toml",
        "/etc/passwd",
        r"C:\Windows\win.ini",
        r"\Windows\win.ini",
        // The right file under a name the manifest does not hold.
        "./one.txt",
        "sub/../one.txt",
        "ONE.TXT",
        "one.txt.",
        "one.txt ",
        r"sub\two.txt",
        "",
        // Excluded on disk is excluded here too.
        "ignore.skip",
    ] {
        assert!(
            Assets::get(request).is_none(),
            "{request:?} resolved in dev mode; release would say None"
        );
    }
}
