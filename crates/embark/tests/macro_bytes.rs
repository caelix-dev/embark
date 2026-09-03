//! `embed_bytes!` with no `codec` argument expands to a plain
//! `include_bytes!`, so the result is a `&'static [u8]` usable in a `static`
//! and not a wrapper type.
#![cfg(all(feature = "std", feature = "derive"))]

static RAW: &[u8] = embark::embed_bytes!("tests/fixtures/hello.txt");

#[test]
fn raw_is_static_slice() {
    assert_eq!(RAW, b"hello embark\n");
}
