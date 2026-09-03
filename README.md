# embark

`embark` is a unified embedding layer for Rust: it packs files into your
binary at compile time and gives you one consistent API to read them back,
whichever combination of compression and encryption you chose per file. It's
built as a Cargo workspace of focused crates
(`embark-format`, `embark-codec`, `embark-crypt`, `embark-macros`) behind the
single `embark` facade, so you only pay (in dependencies and binary size)
for the features you actually enable.

## Quick start

Add `embark` to `Cargo.toml`:

```toml
[dependencies]
embark = "0.1"
```

### `#[derive(Embed)]` — embed a whole folder

```rust
use embark::Embed;

#[derive(Embed)]
#[embark(folder = "assets/")]
#[embark(codec = "auto")] // picks the smallest of the codecs you've enabled
struct Assets;

fn main() {
    for path in Assets::iter() {
        let file = Assets::get(&path).unwrap();
        println!("{} -> {} bytes", path, file.data().len());
    }
}
```

### `embed_bytes!` — embed a single file

```rust
// No `codec` argument: a zero-cost `include_bytes!`, embedded verbatim.
static RAW: &[u8] = embark::embed_bytes!("assets/hello.txt");

// With a codec: compressed at build time, decompressed on first access.
static DOC: embark::EmbeddedBytes = embark::embed_bytes!("assets/lipsum.txt", codec = auto);
```

### `embed_crypt!` — embed an encrypted file

`embed_crypt!` compresses a file, then seals it with an AEAD cipher, in one
build-time step:

```rust
// Default: compressed (Deflate) then encrypted (ChaCha20-Poly1305),
// with a build-time key obfuscated into the binary.
static SECRET: embark::EncryptedFile = embark::embed_crypt!("assets/secret.txt");

// Choose the cipher (needs the `aes` feature) and the compression codec;
// arguments can appear in any order.
static CONFIG: embark::EncryptedFile =
    embark::embed_crypt!("assets/config.bin", cipher = aes, codec = zstd);

// Runtime key — no key compiled in; you supply it at run time. Note the
// EncryptedFile<RuntimeKey> type annotation.
static LICENSE: embark::EncryptedFile<embark::RuntimeKey> =
    embark::embed_crypt!("assets/license.key", key = runtime);

fn main() {
    println!("{}", SECRET.decrypt_str().unwrap());     // build-time key: infallible
    let cfg = CONFIG.decrypt();                          // Vec<u8>
    let lic = LICENSE.decrypt_with(&runtime_key()).unwrap(); // runtime key: Result
}
```

- `cipher = <ident>` — `chacha` (ChaCha20-Poly1305, the default) or `aes`
  (AES-256-GCM; needs the `aes` feature).
- `codec = <ident>` — `store`, `deflate` (the default), `lz4`, `snappy`,
  `zstd`, `lzma`, or `auto`; compression always happens before encryption.
- `key = runtime` — switches the binding's type to
  `EncryptedFile<RuntimeKey>`: no key material is compiled in, and (enforced
  at compile time, not just by convention) that type has no `decrypt()`
  method at all — only `decrypt_with(&key)`, which returns a `Result` since
  the wrong key fails to authenticate. Omitted by default, which embeds a
  build-time key and gives you the infallible `decrypt()` / `decrypt_str()`
  instead.

Runnable versions of all four patterns live in
[`crates/embark/examples/`](crates/embark/examples/) — try
`cargo run -p embark --example basic_derive`, `--example single_file`,
`--example compressed`, or `--example encrypted --features encryption`.

## Security note

**A build-time encryption key is obfuscation, not encryption, against a
determined reverser.** `embed_crypt!` (with no `key = runtime` argument)
generates a key at compile time — ChaCha20-Poly1305 by default, or
AES-256-GCM with `cipher = aes` — and masks it into the binary next to the
ciphertext, so the secret never appears as a plaintext string a `strings`
scan would find. That's enough to stop casual inspection, but anyone who
can run (or disassemble) the binary's own unmasking code can recover the
key — the key and the means to unmask it ship in the same artifact. This
distinction is about the key's provenance, not the cipher: it applies
identically to both ciphers, `cipher = aes` included.

For real confidentiality — a secret the binary itself should not be able to
reveal without external input — use `key = runtime`:

```rust
static SECRET: embark::EncryptedFile<embark::RuntimeKey> =
    embark::embed_crypt!("assets/secret.txt", key = runtime);

fn main() {
    let key: [u8; 32] = load_key_from_somewhere_else();
    let data = SECRET.decrypt_with(&key).unwrap();
}
```

With `key = runtime` the ciphertext is embedded but no key material at all
is compiled in; the caller supplies the key at run time (e.g. from an
environment variable, a secrets manager, or a hardware token), and without
it the embedded data is unrecoverable.

## Feature flags

| Feature      | Default | Enables |
|--------------|:-------:|---------|
| `std`        | yes     | `std`-dependent APIs (dev-mode file reads, etc.) |
| `alloc`      | yes     | `alloc`-only APIs; use with `--no-default-features` for `no_std` |
| `derive`     | yes     | `#[derive(Embed)]`, `embed_bytes!`, `embed_crypt!` proc macros |
| `deflate`    | yes     | the Deflate codec |
| `lz4`        | no      | the LZ4 codec |
| `snappy`     | no      | the Snappy codec (self-implemented, no dependency) |
| `zstd`       | no      | the Zstd codec |
| `lzma`       | no      | the LZMA codec (self-implemented, no dependency) |
| `encryption` | no      | `embed_crypt!`, `EncryptedFile` (ChaCha20-Poly1305) |
| `aes`        | no      | AES-256-GCM cipher for `embed_crypt!(cipher = aes)` |
| `metadata`   | no      | per-entry metadata helpers (e.g. content hashing) |

For `no_std` targets, build with `--no-default-features` and select `alloc`
plus whichever codec features you need; see the `no_std` job in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a worked example
against `thumbv7em-none-eabihf`.

## Similar projects

- [rust-embed](https://crates.io/crates/rust-embed)
- [include_dir](https://github.com/Michael-F-Bryan/include_dir)
- [include-flate](https://github.com/SOF3/include-flate)
- [include-crypt-bytes](https://github.com/breakpointninja/include-crypt-bytes)

## License

Licensed under the [MIT license](LICENSE-MIT).
