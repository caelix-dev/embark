# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A pass over every crate at once, rather than over one concern: what each
decoder accepts, where key material sits, and what the macros do with an
argument they were not expecting.

### Added

- `EncryptedFile::size()`, in both key modes. The claimed length sits in
  the clear header, so it needs no key; `EmbeddedBytes` and `EmbeddedFile`
  already had it.
- `EncryptedFile<RuntimeKey>::decrypt_str_with`, the UTF-8 form that
  `decrypt_str` already gave the embedded-key mode.
- `embark_crypt::Zeroizing`, re-exported from `zeroize`, for a caller that
  holds a key only as long as one `open` call.
- `EncryptedFile<EmbeddedKey>::try_decrypt`, the fallible form of
  `decrypt`, matching `try_data` on the other handles. `Debug` on an
  encrypted handle now reports the file's size, as the plain ones do.
- Fuzz targets under `fuzz/`, for every decoder against arbitrary
  entries, every encoder's round trip, and the glob matcher. CI runs each
  for a minute; the two fixes below are what the first minutes found.

### Fixed

- **An LZ4 block that decoded to fewer bytes than the header claimed was
  accepted.** `decompress_into` reports how much it wrote and the decoder
  truncated to that, so `size()` and `data().len()` could disagree for a
  damaged entry. The count is held to the claim now, like every other
  codec's output.
- **A run of wildcards could hang a build.** The glob matcher backtracked,
  which is exponential on patterns like `*********x` against a name that
  does not match; a fuzzer found a five-second input on its first attempt.
  The matcher is a table now, and costs pattern length times name length
  whatever the pattern.
- **The AEAD ciphers were handed a copy of the key.** `Key::from(*key)`
  put a third copy of it on the stack, one that neither the caller's
  wiped array nor the cipher's wiped schedule reached. The cipher borrows
  the caller's key now.
- **A `Store` entry was never held to its claimed length.** Every
  compressed codec rejects a payload that disagrees with the header, but
  `Store` had no decoder to notice, so `size()` could report one number and
  `data()` return another. It is `Corrupt` now, like the rest.
- **The rebuilt embedded key was left on the stack after decrypting.** The
  reconstruction function hands back a plain `[u8; 32]`, and the decode
  path took it by value, so a copy stayed behind in dead stack frames. The
  key is borrowed now, and the one copy lives in a wrapper wiped when the
  call returns. The build side does the same with the key it draws and
  with the one it reads from `EMBARK_KEY`.
- **A glob `?` matched one byte, not one character.** `?.png` missed
  `é.png`, and `*` could leave a match attempt in the middle of a
  multi-byte character.
- **A macro argument given twice silently kept the last one.** `codec =
  lz4, codec = zstd` compressed with zstd and said nothing. It is an error
  at the repeated argument now, for `embed_crypt!` and for every
  `#[embark(...)]` key that names one value; `include` and `exclude` still
  repeat, as documented.
- **Over-long varints were read with their high bits dropped.** A tenth
  byte with more than one bit set is not an encoding of any `u64`, and
  `read_varint` accepted it. Snappy's length preamble had the same gap past
  the thirty-second bit. Both are `Corrupt` now.
- **The LZMA decoder sized its literal tables from the header, infallibly.**
  `lc + lp` can be twelve under the format, which is six mebibytes of
  probabilities, allocated with a plain `vec!` on whatever target is
  decoding. The allocation is fallible now, and a refusal is `Corrupt`.
- **`parallel::map` kept borrowed workers if the encoder panicked and the
  panic was caught.** They go back to the budget on every way out.

### Changed

- `EmbeddedFile::hash()` hashes the decoded bytes in place instead of
  copying them into a padded buffer first, which halves its peak memory
  on a large asset.

### Removed

- The hidden `embark::__sha256_for_test`. The hash is exercised through
  `EmbeddedFile::hash()` and by known-answer tests inside the crate, so
  the public API no longer carries a test hook.

### Documentation

- The `embark` feature list names `zstd`, `lzma` and `parallel-encode`.
- What `#[embark(dev)]` does under `encrypt`: a debug build serves the
  file as it is on disk, in the clear.
- The cipher docs on `embed_crypt!` and the derive point at
  `EncryptedFile`, where the threat model is actually written down; they
  used to point at a note that does not exist.
- `embark-crypt` no longer says the ciphers run with empty associated
  data. The entry header has been associated data since 0.2.0.

## [0.2.1] - 2026-09-07

A second pass over the cryptography's surroundings: not the ciphers, but
what happens to keys around them and what a build does when a key changes.

### Fixed

- **The ChaCha20-Poly1305 cipher kept its copy of the key until the memory
  was reused.** `chacha20poly1305` 0.11 made wiping on drop an optional
  feature, and the manifest enabled only `alloc`. It is on now, which holds
  ChaCha to the guarantee `aes-gcm` and `aes` already had.

### Documentation

- **Rotating `EMBARK_KEY` does not rebuild anything on its own.** Cargo does
  not know the build reads the variable: change it, build again with no
  source change, and cargo reports the crate up to date and hands back the
  binary sealed under the old key, with no warning. Reproduced, then fixed
  with the standard remedy -- `cargo:rerun-if-env-changed=EMBARK_KEY` from a
  `build.rs` in the embedding crate, which a proc macro cannot emit for you
  on stable Rust. The README's runtime-key section and `embed_crypt!`'s docs
  now say so.
- **An encrypted bundle still reveals its file names and plaintext sizes.**
  The manifest's paths are plain strings in the binary and each header
  carries the original length in the clear; only the contents are
  ciphertext. Verified against a release binary. Documented in the README's
  security note, with the advice that follows from it.

Checked and found sound: `metadata`'s `hash()` is computed at runtime from
the decrypted bytes, not embedded, so it exposes nothing about an encrypted
file; `Debug` for `EncryptedFile` prints neither the key routine nor the
entry; `aes-gcm`'s `zeroize` covers its key and the GHASH key.

## [0.2.0] - 2026-09-05

A hardening release. Each item was found by trying the attack rather than
by reading the code, and each is now a test.

### Fixed

- **`#[embark(dev)]` served any file the process could read.** In a debug
  build, `get()` joined the request onto the folder and read the result,
  with nothing checked: `../outside.txt`, `..\outside.txt`, `/etc/passwd`
  and `C:\Windows\win.ini` all came back, the last two because a join with
  an absolute path drops the base outright. The mode exists so a development
  server can hand out assets by request path, which makes that a
  network-reachable file read during development. Release builds were never
  affected.

  Dev mode now serves exactly the files the derive embedded, re-read from
  disk, and nothing else: a request has to be a name the manifest holds or
  it is `None`, as it would be in release. That one rule also stops it
  serving files `exclude` left out, and stops Windows from answering
  `INDEX.HTML` or `index.html.` for an `index.html` the manifest knows under
  one spelling. A file added to the folder since the last build is no longer
  served until the crate rebuilds; it never appeared in `iter()` either.
- **A symbolic link inside the folder was followed and its target embedded.**
  One pointing at `~/.ssh/id_rsa` or a credential file put that file into
  the binary, on the release build on CI. A link is now a build error that
  names it and the way out: `#[embark(follow_links)]`, or replace it with
  the file. With links followed, each real directory is walked once, so a
  link back to an ancestor ends the walk instead of never ending it.
  Reproduced with a directory junction on Windows, which counts as a link.
- **A sealed entry's tag covered the payload and not the header.** The
  codec, cipher and claimed length in front of it could be rewritten under a
  tag that still verified, and the plaintext handed to a decoder it was
  never sealed for. Not a confidentiality break, since none of that helps
  without the key, but not what an AEAD format is supposed to say either.
  The header bytes are now the associated data.
- `orig_len` is checked to fit in `usize` before use, rather than truncated
  by `as` on a 32-bit target.

### Changed

- **Every `seal` and `open` in `embark-crypt` takes the associated data
  explicitly**, and `Header` gained `aad_len` saying how many leading bytes
  to pass. There is no empty default, since an empty default is the mistake
  above. This is the API break behind the version.
- **Encrypted entries from 0.1.x no longer open.** Every entry is produced by
  the same build that reads it, so this only reaches a caller that kept
  sealed bytes from `embark-crypt` or `embark-format` directly across the
  upgrade. Re-seal them.
- `#[derive(Embed)]` accepts `follow_links`.

Verified not to be a problem, for the record: 48,000 mutated entries across
every codec and both ciphers produced no panic, only `Err`; release-mode
lookup is a binary search over a static table and cannot reach the
filesystem; `key = runtime` embeds no key material; nonces come from the
OS CSPRNG per file.

## [0.1.1] - 2026-09-04

### Fixed

- **`**` in an `include` or `exclude` pattern now crosses `/`.** It used to
  be two `*`s in a row, and a `*` stops at a separator, so `**/*.png` meant
  exactly one directory deep -- it found `sub/logo.png` and missed both
  `logo.png` and `a/b/logo.png`. As a whole segment it now stands for any
  number of segments, zero among them, which is what it means in
  `.gitignore` and in every other crate that filters a folder. `sub/**`
  takes everything under `sub/` at any depth, and a bare `**` takes
  everything.

  A pattern containing `**` therefore matches more files than it did in
  0.1.0. One without `**` is unaffected: `*` and `?` still stay inside a
  segment.
- The README documents `include` and `exclude` at all, which it did not.
  They existed only in the derive's API docs, so the depth rule was
  something you found out by having a file quietly not embedded.

## [0.1.0] - 2026-09-04

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
