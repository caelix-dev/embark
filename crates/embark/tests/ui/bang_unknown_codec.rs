fn main() {
    let _ = embark::embed_bytes!("assets/data.bin", codec = bogus);
}
