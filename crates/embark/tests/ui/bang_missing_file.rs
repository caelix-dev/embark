fn main() {
    let _ = embark::embed_bytes!("assets/does_not_exist.bin", codec = deflate);
}
