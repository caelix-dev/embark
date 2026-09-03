//! `embed_bytes!` with `codec = auto` compresses the file at build time with
//! whichever enabled codec shrinks it most, and decompresses on first access.

static DOC: embark::EmbeddedBytes =
    embark::embed_bytes!("examples/assets/lipsum.txt", codec = auto);

fn main() {
    let bytes = DOC.data();
    match DOC.size() {
        Some(size) => println!("decoded {} bytes (original size {size})", bytes.len()),
        None => println!("decoded {} bytes (header unreadable)", bytes.len()),
    }
}
