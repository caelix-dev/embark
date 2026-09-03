//! The codec and encrypted macro paths expand to a block expression carrying
//! rebuild-tracking items. These lock in that the block still behaves like a
//! plain expression everywhere it is used, and that several expansions
//! coexist in one module without colliding.
#![cfg(all(feature = "std", feature = "derive", feature = "deflate"))]

static FIRST: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/hello.txt", codec = deflate);
static SECOND: embark::EmbeddedBytes =
    embark::embed_bytes!("tests/fixtures/hello.txt", codec = deflate);

#[test]
fn repeated_expansions_in_one_module() {
    assert_eq!(FIRST.data(), SECOND.data());
}

#[test]
fn usable_as_a_local_and_a_receiver() {
    let local = embark::embed_bytes!("tests/fixtures/hello.txt", codec = deflate);
    assert_eq!(
        local.data(),
        embark::embed_bytes!("tests/fixtures/hello.txt", codec = deflate).data()
    );
}

#[cfg(feature = "encryption")]
#[test]
fn encrypted_expansion_is_an_expression() {
    let sealed = embark::embed_crypt!("tests/fixtures/secret.txt");
    assert_eq!(
        sealed.decrypt(),
        embark::embed_crypt!("tests/fixtures/secret.txt").decrypt()
    );
}
