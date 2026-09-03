fn main() {
    let _ = embark::embed_bytes!("assets/data.bin", format = deflate);
}
