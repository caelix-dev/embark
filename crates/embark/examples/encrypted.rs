//! `embed_crypt!` seals the file with ChaCha20-Poly1305 at build time.
//!
//! SECURITY NOTE: with no `key = runtime` argument, the key is generated at
//! build time and masked into the binary alongside the ciphertext. That
//! stops casual inspection (e.g. `strings`) but NOT a determined reverser --
//! anyone who can run the binary's own unmasking code can recover the key.
//! For real confidentiality, use `key = runtime` and supply the key at
//! runtime via `EncryptedFile::decrypt_with`.

static SECRET: embark::EncryptedFile = embark::embed_crypt!("examples/assets/secret.txt");

fn main() {
    println!("decrypted: {}", SECRET.decrypt_str().unwrap());
}
