# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `parallel-encode`, a default feature that lets the build-time encoder use
  every core the build machine has. Three kinds of work overlap: a
  `#[derive(Embed)]` compresses the folder's files side by side, an `auto`
  policy runs its candidate codecs side by side, and the Zstd encoder cuts
  an asset over a mebibyte into segments it encodes side by side. All three
  draw on one shared budget, so they never oversubscribe together. Measured
  on 16 cores: a derive over 56 files totalling 5.8 MB under `codec = "auto"`
  goes from 11.3 s to 2.9 s, and 32 MB of poorly compressible data under
  `codec = "zstd"` from 52 s to 13 s.

  Compression runs in the proc macro, so this is build-machine work only:
  the feature is not forwarded to the copy of `embark-codec` compiled for
  your target, and a `no_std` binary gains neither a thread nor `std`. CI
  builds that combination against `thumbv7em-none-eabihf` to keep it that
  way.

  Output does not depend on the core count. The same assets produce the same
  bytes at one thread or thirty-two. `EMBARK_ENCODE_THREADS` caps the budget
  for one build, or turns it off with `1`, which is what a build under an
  external job server wants.

  Keeping that true has a price, since Zstd's segments have to be cut by
  input size rather than by how many cores are going to work on them: a
  single-threaded encode is about a tenth slower than before, and the most
  repetitive assets grow by a few bytes in a few tens of thousands. Assets of
  a mebibyte or less are one segment and are unchanged.
- CI now builds and tests with `--all-features`, so the LZMA codec and the
  AES-256-GCM cipher are covered rather than a hand-maintained subset, and
  the LZMA interop test runs against the `xz` binary alongside the existing
  Snappy interop test.
- Publish metadata on all five crates: `keywords`, `categories`, `readme`,
  `documentation`, `homepage`, and `[package.metadata.docs.rs]` with
  `all-features = true` so docs.rs renders the encryption and
  zstd/LZMA/AES surface instead of only the default features.
- `include` on every crate, so a published `.crate` no longer ships the
  test assets and fixtures. Each one carries a copy of `LICENSE-MIT`:
  `license = "MIT"` tells crates.io what the terms are, but the terms
  themselves say the notice travels with the copy, and a `.crate` is a copy.
- `#![cfg_attr(docsrs, feature(doc_cfg))]` on all five crates, so docs.rs
  labels each item with the feature that gates it. The manifests already
  asked for `--cfg docsrs`; nothing read it, and almost every item here is
  behind a feature, so the rendered docs read as though none of them were.

### Changed

- Dependencies moved to their current majors: `syn` 2 → 3, `chacha20poly1305`
  0.10 → 0.11 with `aes-gcm` 0.10 → 0.11 and `aes` 0.8 → 0.9 alongside it,
  `getrandom` 0.3 → 0.4, `lz4_flex` 0.11 → 0.14, `miniz_oxide` 0.8 → 0.9, and
  `actions/checkout` v4 → v7.

  Two needed work. The AEAD crates moved to `aead` 0.6, where `AeadInPlace`
  became `AeadInOut` and the in-place methods take an `InOutBuf`. `lz4_flex`
  split `alloc` out into its own feature, and without it the entry points
  that return a `Vec` are compiled out, which is a compile error rather than
  a silent one.

  Both ciphers produce the same bytes they did before, which is now a test
  rather than an assumption: a fixed key, nonce and plaintext, and the
  ciphertext and tag written out. A binary built against an older `embark`
  has to keep decrypting under a newer one, and a round trip would not notice
  if that stopped being true.
- `BSD-3-Clause` is gone from `deny.toml`'s allow-list. It was there for
  `subtle`, which the new AEAD stack no longer pulls in, and `cargo deny`
  reports an allowance nothing matches.

- **`codec = auto` changes meaning.** It used to try every enabled codec and
  keep the smallest output, which since the `lzma-rust2` encoder landed has
  meant "always LZMA" — the slowest codec to decode, chosen on a
  size-only criterion, in a binary that pays the decode cost on every
  access. `auto` now names the balance point instead, and the family has
  three members, each keeping the smallest output among its own candidates:

  | policy | candidates |
  |---|---|
  | `auto_fast` | `store`, `lz4`, `snappy` |
  | `auto` | those, plus `deflate` and `zstd` |
  | `auto_small` | those, plus `lzma` |

  **`auto_small` is the old `auto`**, byte for byte, so the previous
  behaviour is one word away. On a 468 KiB executable, `auto` picks DEFLATE
  at 228,157 bytes and 305 MB/s where `auto_small` picks LZMA at 191,493
  bytes and 45 MB/s: 19% larger, nearly seven times quicker to read back.
  The crate is unpublished, so this breaks no released build.

  A policy only encodes with its own candidates, which also cuts build time:
  `auto_fast` never runs the LZMA encoder. And a policy whose candidates are
  all disabled at feature level widens to the next tier instead of emitting
  an uncompressed entry, so a build with only `lzma` on still compresses
  under `auto_fast`.

  The tier is a build-time policy only. An entry header still records the
  single codec that won, so the on-binary format and the decode path are
  unchanged. The names are `auto_fast` / `auto` / `auto_small` as bare
  idents for `embed_bytes!` and `embed_crypt!`, and the same three as
  strings for `#[derive(Embed)]`.
- `embed_crypt!` and `#[derive(Embed)]`'s `encrypt` mode now run the codec
  selection like every other path. Both used to map an `auto` argument to
  Deflate and skip the selection entirely, on the argument that the size
  delta mattered less under encryption. `auto` names a policy rather than a
  codec now, so silently substituting one codec for it was no longer
  defensible. Compression happens before sealing, so the selection reads the
  plaintext and nothing about the cryptography changes.
- Zstd now compresses with a self-written encoder rather than `ruzstd`'s.
  `ruzstd` implements only its `Fastest` level, which is well short of what
  the format allows: the frames it writes advertise a 128 KiB window, so on
  anything larger no match can reach across the file. The new encoder writes
  windows up to 8 MiB, parses each block by shortest path over a price model
  fitted to that block, uses the repeat offsets, Huffman-codes the literals
  and fits FSE tables per block. On a four-file corpus it lands 21% to 33%
  below what `ruzstd` produced, and within 1% of what real `zstd -19`
  produces. Decoding is unchanged and still goes through `ruzstd`, since that
  is the half that ships in a consumer's binary. Encoding costs roughly 5 to
  70 times what `ruzstd` charged, which is a build-time cost only.
- Minimum supported Rust version raised from 1.74 to **1.87**. The 1.74
  claim was never true: the dependency graph has required a newer compiler
  since before it was written, and CI never caught it. 1.87 is the measured
  floor for `--all-features`, set by `ruzstd 0.9`.
- The workspace moved to **edition 2024** and the MSRV-aware
  `resolver = "3"`. No semantic source change was required.

### Fixed

- **A hostile `orig_len` could still take the process down, on any operating
  system that overcommits.** Every decoder sized its output buffer from the
  length in the entry header, and turned a refused reservation into
  `Error::Corrupt`. A refusal is what Windows gives, and what Linux's
  heuristic gives for an obviously impossible claim; macOS hands back a
  mapping of any size and lets the process die when it is written to. Zstd
  and LZ4 then wrote to it, and LZMA decoded zeros toward the claimed length
  until it had produced a terabyte of them.

  None of them size from the claim any more. Zstd grows its buffer as the
  frame actually produces output, and rejects a frame that produces more than
  was claimed rather than silently truncating it, which also closes a hole.
  LZ4 has to have its whole buffer up front, since a match copies from
  earlier output, so it bounds the claim by what the payload could expand to
  under the format's own limits. LZMA now stops the moment its range decoder
  reads past the end of the input, which a complete stream never does; the
  check existed but only ran after the decode loop it was supposed to bound.

  The first CI run on a macOS runner found this. It is reachable only from an
  entry that was not written by this crate's own encoder.
- Line endings are pinned by `.gitattributes`. The embedded fixtures are
  compared byte for byte, and a Windows checkout was turning their LFs into
  CRLFs, so two derive tests asserted on content the repository never held.

- Build-time key and nonce generation now draws from the OS CSPRNG. The
  previous SplitMix64 generator produced a key recoverable from the
  cleartext nonce that ships in every encrypted entry header, which
  defeated the build-time key obfuscation outright.
- The decoders for Zstd, LZ4, LZMA and Snappy no longer size their output
  buffer from the caller-supplied `orig_len` with an infallible
  allocation. A hostile or corrupted entry claiming a huge length aborted
  the process, unrecoverably, even through the fallible `try_data()` API.
  All four now reserve fallibly and return `Error::Corrupt`.
- Every file a macro reads is now registered with cargo's dependency
  tracking, so editing an embedded asset triggers a rebuild. Previously
  only `embed_bytes!` without a codec was tracked, which made rebuild
  behaviour depend on whether a `codec` argument was present. Adding a
  *new* file to a `#[derive(Embed)]` folder still does not trigger a
  rebuild; this is documented on the derive.

### Performance

- Embedded bytes are emitted as a single byte-string literal instead of one
  numeric token per byte. Building a crate that embeds a 2 MB asset through
  `embed_bytes!(codec = deflate)` drops from 13.3 s to 1.0 s.
- LZMA now encodes through `lzma-rust2` instead of the hand-written greedy
  encoder, which never emitted rep-matches. Output reaches parity with
  `xz -9`: a 272 KB JSON asset drops from 31,143 to 22,690 bytes and a 4 MB
  one from 424,672 to 303,700. The decoder is unchanged and still ours, and
  interop with `xz` is verified in both directions.

  Encoding is correspondingly slower, roughly 4x from 16 MB up, and the
  proc macro re-encodes whenever the calling crate recompiles. See the
  README's note on `lzma` and build times for the
  `[profile.dev.build-override]` mitigation. `lzma-rust2` is Apache-2.0 and
  is a build-time dependency only; it is never linked into a consumer's
  binary, and embark's own crates stay MIT.

## [0.1.0]

### Added

- Initial workspace scaffolding with five crates: `embark`, `embark-format`,
  `embark-codec`, `embark-crypt`, and `embark-macros`.
- Raw, compressed, and encrypted file embedding through a single
  `EmbeddedFile` / `EmbeddedBytes` / `EncryptedFile` API surface.
- `#[derive(Embed)]` to embed a whole folder, with `folder`, `codec`,
  `encrypt`, `dev`, `include`, and `exclude` attributes.
- `embed_bytes!` for single-file embedding, with an optional `codec`
  argument (`store`, `deflate`, `lz4`, `snappy`, `zstd`, `lzma`, or
  `auto`).
- `embed_crypt!` for single-file authenticated encryption, with build-time
  (obfuscated) or `key = runtime` key modes, an optional `codec` argument
  that compresses before sealing, and a `cipher` argument selecting
  `chacha` or `aes`.
- Codecs: Store, Deflate, LZ4, Zstd, and self-implemented Snappy and LZMA
  encoder/decoder pairs.
- AEAD ciphers: ChaCha20-Poly1305 by default and AES-256-GCM under the
  `aes` feature, behind a shared `Aead` trait with dispatch by `CryptoId`.
- Build-time key obfuscation: each build emits a randomized
  key-reconstruction function rather than storing the key as a contiguous
  literal.
- `#[embark(dev)]` dev-mode: reads files straight off disk in debug builds
  instead of the compiled-in copy, for fast edit/reload loops.
- `no_std` (`alloc`-only) support for `embark-format`, `embark-codec`,
  `embark-crypt`, and `embark`.
