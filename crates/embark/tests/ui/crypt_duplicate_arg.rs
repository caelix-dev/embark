fn main() {
    let _ = embark::embed_crypt!("assets/data.bin", cipher = chacha, cipher = chacha);
}
