# embark

[![CI](https://github.com/caelix-dev/embark/actions/workflows/ci.yml/badge.svg)](https://github.com/caelix-dev/embark/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.87-blue.svg)](Cargo.toml)

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
#[embark(codec = "auto")] // best size/decode-speed trade of the enabled codecs
struct Assets;

fn main() {
    for path in Assets::iter() {
        let file = Assets::get(&path).unwrap();
        println!("{} -> {} bytes", path, file.data().len());
    }
}
```

#### Picking which files go in

`include` and `exclude` filter the folder walk. Both are globs over each
file's path relative to `folder`, both may be repeated, and `exclude` wins:

```rust
#[derive(Embed)]
#[embark(folder = "assets", include = "**/*.png", include = "**/*.svg", exclude = "**/tmp/**")]
struct Icons;
```

`?` is one character and `*` any run of them, neither crossing `/`. `**`
does cross it, and as a whole segment stands for any number of segments —
zero among them, so `**/*.png` finds a `.png` at the top level as well as
further down. With no `include`, everything not excluded is embedded.

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
// EncryptedFile<RuntimeKey> type annotation. Building this needs
// EMBARK_KEY=<64 hex chars> in the environment; see below.
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
  `zstd`, `lzma`, or one of the `auto_fast` / `auto` / `auto_small`
  policies below. Compression always happens before encryption, so a
  policy selects on the plaintext and the cipher sees no difference.
- `key = runtime` — switches the binding's type to
  `EncryptedFile<RuntimeKey>`: no key material is compiled in, and (enforced
  at compile time, not just by convention) that type has no `decrypt()`
  method at all — only `decrypt_with(&key)`, which returns a `Result` since
  the wrong key fails to authenticate. Omitted by default, which embeds a
  build-time key and gives you the infallible `decrypt()` / `decrypt_str()`
  instead.

  **This mode needs `EMBARK_KEY` set at build time**, as 64 hex characters
  (a 32-byte key):

  ```sh
  EMBARK_KEY=$(openssl rand -hex 32) cargo build --release
  ```

  The macro seals the file with that key while compiling, then throws it
  away — nothing about it is written into the binary. Keep it: it is the
  same key you must hand `decrypt_with` at run time, and without it the
  embedded bytes are unrecoverable. Building without the variable set is a
  compile error pointing at the `runtime` argument.

Runnable versions of all four patterns live in
[`crates/embark/examples/`](crates/embark/examples/) — try
`cargo run -p embark --example basic_derive`, `--example single_file`,
`--example compressed`, or `--example encrypted --features encryption`.

## Choosing a codec: the `auto` policies

You compress once, while building. Everyone who runs your binary
decompresses on every access. Those are not the same cost, so `codec = auto`
does not mean "smallest": it names a **tier** of candidate codecs, compresses
with each of them, and keeps the smallest output *within that tier*.

| policy | candidates |
|---|---|
| `auto_fast` | `store`, `lz4`, `snappy` |
| `auto` | those, plus `deflate` and `zstd` |
| `auto_small` | those, plus `lzma` |

On a 468 KiB executable, decoded with the pure-Rust decoders `embark`
actually ships:

| policy | picks | payload | ratio | decode |
|---|---|---:|---:|---:|
| `auto_fast` | LZ4 | 312,340 B | 1.54x | 1,744 MB/s |
| `auto` | DEFLATE | 228,157 B | 2.10x | 305 MB/s |
| `auto_small` | LZMA | 191,493 B | 2.51x | 45 MB/s |

`auto` gives up 19% of the size `auto_small` reaches and decodes nearly
seven times faster for it. `auto_small` is the right answer when the binary
is read once at startup and size is what you are paying for; `auto_fast` is
for assets read in a hot path. Reach for a policy, not a codec — naming a
codec directly still works and still overrides everything here.

Three things worth knowing:

- **A policy only encodes with its own candidates.** `auto_fast` never runs
  the LZMA encoder, so it does not pay for output it would discard. See the
  build-time note below.
- **A tier with nothing enabled widens rather than giving up.** If none of a
  policy's candidates are enabled as features on `embark`, it moves to the
  next tier out; the tiers nest, so this is always well defined. A build
  with only `lzma` on still compresses under `auto_fast`.
- **The tier is a build-time policy.** An entry header records the one codec
  that won, so nothing about the choice reaches the decode side and no
  reader needs to know a policy existed.

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

Build it with the key in the environment, and keep that key — it is the one
`load_key_from_somewhere_else` has to return:

```sh
EMBARK_KEY=$(openssl rand -hex 32) cargo build --release
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
| `deflate`    | yes     | the Deflate codec (a candidate from `auto` out) |
| `lz4`        | no      | the LZ4 codec (a candidate in every `auto` policy) |
| `snappy`     | no      | the Snappy codec, self-implemented, no dependency (every `auto` policy) |
| `zstd`       | no      | the Zstd codec, self-written encoder, decodes via `ruzstd` (a candidate from `auto` out) |
| `lzma`       | no      | the LZMA codec, via `lzma-rust2` (`auto_small` only; see the build-time note) |
| `encryption` | no      | `embed_crypt!`, `EncryptedFile` (ChaCha20-Poly1305) |
| `aes`        | no      | AES-256-GCM cipher for `embed_crypt!(cipher = aes)` |
| `metadata`   | no      | per-entry metadata helpers (e.g. content hashing) |
| `parallel-encode` | yes | lets the build-time encoder use every core; adds nothing to your binary |

For `no_std` targets, build with `--no-default-features` and select `alloc`
plus whichever codec features you need; see the `no_std` job in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for a worked example
against `thumbv7em-none-eabihf`.

### A note on `lzma`, `zstd` and build times

LZMA gives the best ratio of the six codecs, and `zstd` is now close behind
it; both cost real time to encode. Encoding happens in the proc macro, so
you pay it while compiling, not at run time.

The part that surprises people: the macro re-runs whenever the crate holding
the `embed_bytes!` or `#[derive(Embed)]` call recompiles. Editing **any**
source file in that crate re-encodes the asset. Only a genuine no-op build
is free. Measured here on a 4.7 MB JSON asset, rebuilding after touching an
unrelated source file in the same crate:

| codec | default `dev` profile | with the override below |
|---|---:|---:|
| `deflate` | 0.8 s | 0.8 s |
| `lzma` | 24.6 s | 5.1 s |

Proc macros build under the `dev` profile, so the encoder itself runs
unoptimized. Optimizing build-time code recovers most of the difference —
put this in the manifest of the crate that does the embedding:

```toml
[profile.dev.build-override]
opt-level = 3
```

`zstd` sits in the same bracket. Its encoder parses each block by price and
reprices four times over, which buys a payload within 1% of what real
`zstd -19` achieves. What that costs depends on how much searching the asset
gives it: with the override in place and one thread, a redundant asset runs
at about 0.14 s per MiB and a large binary one at about 1.6 s per MiB, and a
machine with cores to spare cuts both to well under half. Without the
override, multiply by roughly ten.

Rules of thumb: under a few MB, `lzma` or `zstd` costs a few seconds per
rebuild with that override in place and is usually worth it. Past roughly
16 MB per asset, reach for `deflate`, `lz4` or `snappy` instead, or accept
a slow build.

Two of the three `auto` policies now run an encoder that searches hard:
`auto_small` runs LZMA and `auto` runs Zstd. Only `auto_fast` stops short of
both. What that costs depends far more on the asset than on the policy.
Encoding 32 MB with each, optimized:

| policy | redundant asset | poorly compressible asset |
|---|---|---|
| `auto_fast` | 0.0 s, LZ4 131,735 B | 0.2 s, Store 33,554,432 B |
| `auto` | 4.5 s, Zstd 3,482 B | 56 s, Zstd 24,339,163 B |
| `auto_small` | 7.1 s, Zstd 3,482 B | 96 s, LZMA 22,417,485 B |

Those are single-threaded figures, which is what you get with
`EMBARK_ENCODE_THREADS=1`. With `parallel-encode` on — it is a default
feature — the same 16-core machine cuts the right-hand column to 13 s and
46 s, the second of those held up by LZMA, which stays single-threaded. A
`#[derive(Embed)]` over a folder falls further still, since whole files then
compress side by side. See below.

The left column is an asset that compresses almost to nothing, so the search
finds its matches immediately. The right one barely compresses, so both
encoders search the whole window and find little — the worst case for build
time, and the case where compression buys you least. `auto_fast` gives up on
it in a fifth of a second and stores it verbatim, which for that asset is the
honest answer.

So the rule of thumb is about the asset, not the policy: a large asset that
does not compress well is the one to keep away from `auto` and `auto_small`.
Name `deflate`, `lz4` or `snappy` for it explicitly, or accept the build cost
once and rely on the rebuild note above.

### Build-time threads

Compression runs once, in the proc macro, on the machine doing the build.
Decompression runs in every binary you ship. The `parallel-encode` feature
spends the first of those on whatever cores the build machine has, and it is
on by default; nothing it does reaches your binary, which gains neither a
thread nor `std`.

Three kinds of work overlap, from outermost in:

- a `#[derive(Embed)]` compresses the folder's files side by side
- an `auto` policy runs its candidate codecs side by side
- the Zstd encoder cuts an asset over a mebibyte into segments and encodes
  those side by side

They draw on one shared budget, so the three together never ask for more
threads than the machine has. Measured on a 16-core machine, a derive over
56 files totalling 5.8 MB under `codec = "auto"`:

| `EMBARK_ENCODE_THREADS` | build |
|---|---:|
| `1` | 11.3 s |
| `4` | 4.3 s |
| unset (16 here) | 2.9 s |

And one large asset on its own, `codec = "zstd"`, 32 MB that barely
compresses:

| `EMBARK_ENCODE_THREADS` | encode |
|---|---:|
| `1` | 52 s |
| unset (16 here) | 13 s |

Set `EMBARK_ENCODE_THREADS` to cap it, or to `1` to turn it off for one
build. That matters under a job server: cargo already runs several rustc
processes at once, and each of them expanding a macro that grabs every core
is how a build machine ends up thrashing.

The output does not depend on any of this. The same assets produce the same
bytes at one thread or at thirty-two, so a build stays reproducible across
machines that do not have the same core count. Zstd's segments are cut by
input size for that reason, not by core count, which costs a single-threaded
encode about a tenth of its time and, on the most repetitive assets, a
handful of bytes in a few tens of thousands.

## Similar projects

- [rust-embed](https://crates.io/crates/rust-embed)
- [include_dir](https://github.com/Michael-F-Bryan/include_dir)
- [include-flate](https://github.com/SOF3/include-flate)
- [include-crypt-bytes](https://github.com/breakpointninja/include-crypt-bytes)

## License

Licensed under the [MIT license](LICENSE-MIT).
