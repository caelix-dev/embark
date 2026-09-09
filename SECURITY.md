# Security Policy

## Supported versions

`embark` is pre-1.0. Until a `1.0` release, only the most recently
published version on crates.io is supported with security fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, rather than in a public
GitHub issue, to:

**me@caelix.dev**

Include as much detail as you can: affected crate(s) and version(s), a
minimal reproduction, and what you believe the impact is. This is a
one-maintainer project, so response times are best-effort, not
contractual — expect an initial acknowledgement within a few days. There is
currently no bug-bounty program.

## Security model — what's in scope

`embark` embeds files into a binary at build time, with optional
compression and AEAD encryption (`embark-crypt`). The
[README's security note](README.md#security-note) spells out the threat
model for the encryption feature; the short version:

- **`embed_crypt!` with a build-time key (the default, no `key = runtime`
  argument) is obfuscation, not confidentiality.** The key is masked into
  the binary next to the ciphertext, and anyone who can run or disassemble
  that binary's own unmasking code can recover it. **This is by design and
  documented behavior, not a vulnerability** — please don't report "the
  build-time key can be extracted from the binary" as a security issue.
- **`key = runtime` (`EncryptedFile<RuntimeKey>`) is the mode intended for
  real secrets.** No key material is compiled in; the caller supplies the
  key at run time, and the type has no infallible `decrypt()` at all, only
  the keyed `decrypt_with(&key)` and `decrypt_str_with(&key)`.

What **is** in scope for a security report:

- Anything that breaks the confidentiality or integrity guarantees of
  `key = runtime` — e.g. a way to recover plaintext or forge/tamper with
  ciphertext without the runtime key.
- Misuse of the AEAD primitives themselves: nonce reuse, key/nonce
  derivation bugs, timing side channels in comparison paths, or any gap
  between `embark-crypt` and the security properties ChaCha20-Poly1305 /
  AES-256-GCM are supposed to provide.
- Memory safety issues in the decoders (`embark-codec`, `embark-format`)
  when parsing untrusted or malformed embedded data — every crate in this
  workspace is `#![forbid(unsafe_code)]`, so a memory-safety report
  ordinarily means either a soundness hole in a dependency or a logic bug
  that lets safe code violate an invariant (e.g. an out-of-bounds slice
  panic reachable from crafted input, which we'd still like to know about
  even though it's "just" a panic, not UB).
- Anything that breaks the `no_std` build's guarantees (e.g. an
  accidental panic-as-abort or allocation path where one shouldn't exist).
- Supply-chain concerns in the dependency tree (this repo runs
  `cargo deny` in CI for advisories and licensing, but a report about a
  gap in that coverage is still welcome).

If you're unsure whether something qualifies, err on the side of emailing
rather than filing a public issue — worst case we ask you to reopen it as
a normal issue.
