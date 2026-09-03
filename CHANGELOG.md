# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI now builds and tests with `--all-features`, so the LZMA codec and the
  AES-256-GCM cipher are covered rather than a hand-maintained subset, and
  the LZMA interop test runs against the `xz` binary alongside the existing
  Snappy interop test.
- Publish metadata on all five crates: `keywords`, `categories`, `readme`,
  `documentation`, `homepage`, and `[package.metadata.docs.rs]` with
  `all-features = true` so docs.rs renders the encryption and
  zstd/LZMA/AES surface instead of only the default features.
- `include` on every crate, so a published `.crate` no longer ships the
  test assets and fixtures.

### Changed

- Minimum supported Rust version raised from 1.74 to **1.87**. The 1.74
  claim was never true: the dependency graph has required a newer compiler
  since before it was written, and CI never caught it. 1.87 is the measured
  floor for `--all-features`, set by `ruzstd 0.9`.
- The workspace moved to **edition 2024** and the MSRV-aware
  `resolver = "3"`. No semantic source change was required.

### Fixed

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
