# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- Initial workspace scaffolding with five crates: `embark`, `embark-format`,
  `embark-codec`, `embark-crypt`, and `embark-macros`.
- Raw, compressed, and encrypted file embedding through a single
  `EmbeddedFile` / `EmbeddedBytes` / `EncryptedFile` API surface.
- `#[derive(Embed)]` to embed a whole folder, with `folder`, `codec`,
  `encrypt`, `dev`, `include`, and `exclude` attributes.
- `embed_bytes!` for single-file embedding, with an optional `codec`
  argument (`store`, `deflate`, `lz4`, `snappy`, or `auto`).
- `embed_crypt!` for single-file ChaCha20-Poly1305 encryption, with
  build-time (obfuscated) or `key = runtime` key modes.
- Codecs: Store, Deflate, LZ4, and a self-implemented Snappy
  encoder/decoder.
- ChaCha20-Poly1305 AEAD encryption via `embark-crypt`.
- `#[embark(dev)]` dev-mode: reads files straight off disk in debug builds
  instead of the compiled-in copy, for fast edit/reload loops.
- `no_std` (`alloc`-only) support for `embark-format`, `embark-codec`,
  `embark-crypt`, and `embark`.
