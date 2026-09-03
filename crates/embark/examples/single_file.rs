//! `embed_bytes!` with no `codec` argument is a zero-cost `include_bytes!`:
//! the file is embedded verbatim, uncompressed, with no runtime decode step.

static RAW: &[u8] = embark::embed_bytes!("examples/assets/hello.txt");

fn main() {
    println!("raw {} bytes: {:?}", RAW.len(), core::str::from_utf8(RAW));
}
