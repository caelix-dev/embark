//! Proc-macros for `embark`: [`embed_bytes!`], [`embed_crypt!`], and the
//! [`Embed`](macro@Embed) derive. Re-exported from the `embark` crate under
//! its `derive` feature; use them via `embark::embed_bytes!` etc. rather
//! than depending on this crate directly.
#![forbid(unsafe_code)]

mod args;
mod build;
mod crypt;
mod crypt_args;
mod derive;
mod glob;
mod obfuscate;

use embark_format::CodecId;
use proc_macro::TokenStream;
use quote::quote;

/// Embeds a single file's bytes at build time, expanding to an
/// [`EmbeddedBytes`](https://docs.rs/embark/*/embark/struct.EmbeddedBytes.html)
/// (or, with no `codec` argument, a plain `include_bytes!`-style
/// `&'static [u8]`).
///
/// ```ignore
/// // Zero-cost, uncompressed -- identical to include_bytes!.
/// static RAW: &[u8] = embark::embed_bytes!("assets/logo.png");
///
/// // Compressed with a specific codec.
/// static GZ: embark::EmbeddedBytes = embark::embed_bytes!("assets/data.json", codec = deflate);
///
/// // Compressed with whichever enabled codec shrinks it the most.
/// static BEST: embark::EmbeddedBytes = embark::embed_bytes!("assets/data.json", codec = "auto");
/// ```
///
/// `path` is resolved relative to the crate's `CARGO_MANIFEST_DIR`. The
/// optional `codec = <ident>` argument selects the compressor: `store`,
/// `deflate`, `lz4`, `snappy`, or `auto` (tries every codec enabled on the
/// `embark` crate and keeps the smallest output, falling back to `store` if
/// none of them help).
///
/// **`codec = "auto"` and enabled features:** the codec ident you name here
/// (explicit, or the winner `auto` picks) must correspond to a codec
/// feature enabled on the `embark` crate you decode with. If it isn't
/// enabled, encoding does not fail -- the entry silently degrades to
/// `store` (uncompressed) instead, since encoding never fails and correct
/// but uncompressed output is still correct. Enable the matching feature
/// (`deflate`, `lz4`, `snappy`) if you expect compression to actually
/// happen.
#[proc_macro]
pub fn embed_bytes(input: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(input as args::Args);
    match args.codec {
        None => {
            // Raw mode: zero-cost include_bytes! with an absolute path.
            let abs = build::resolve(&args.path);
            let abs = abs.to_str().expect("embark: non-UTF-8 path");
            quote!(include_bytes!(#abs)).into()
        }
        Some(codec) => {
            let data = build::read(&args.path);
            let entry = match codec {
                args::CodecArg::Auto => build::build_entry_best(&data),
                args::CodecArg::Store => build::build_entry(CodecId::Store, &data),
                args::CodecArg::Deflate => build::build_entry(CodecId::Deflate, &data),
                args::CodecArg::Lz4 => build::build_entry(CodecId::Lz4, &data),
                args::CodecArg::Snappy => build::build_entry(CodecId::Snappy, &data),
            };
            let lit = build::bytes_literal(&entry);
            quote!(::embark::EmbeddedBytes::from_entry(#lit)).into()
        }
    }
}

/// Embeds a single file, encrypted at build time with ChaCha20-Poly1305 (or,
/// with `cipher = aes`, AES-256-GCM), expanding to an
/// [`EncryptedFile`](https://docs.rs/embark/*/embark/struct.EncryptedFile.html),
/// generic over a type-state marker
/// ([`EmbeddedKey`](https://docs.rs/embark/*/embark/struct.EmbeddedKey.html)
/// or
/// [`RuntimeKey`](https://docs.rs/embark/*/embark/struct.RuntimeKey.html))
/// that determines which decrypt methods the resulting handle has.
///
/// ```ignore
/// // Build-time embedded key (the default): obfuscation, not security --
/// // see EncryptedFile's docs. Type is EncryptedFile<EmbeddedKey>.
/// static SECRET: embark::EncryptedFile = embark::embed_crypt!("assets/config.enc");
/// let plaintext = SECRET.decrypt();
///
/// // Runtime key: real confidentiality. No key is embedded in the binary.
/// // Type is EncryptedFile<RuntimeKey> -- note the explicit annotation.
/// static SEALED: embark::EncryptedFile<embark::RuntimeKey> =
///     embark::embed_crypt!("assets/config.enc", key = runtime);
/// let plaintext = SEALED.decrypt_with(&my_key).unwrap();
/// ```
///
/// `path` is resolved relative to `CARGO_MANIFEST_DIR`, as in
/// [`embed_bytes!`]. Independent, comma-separated arguments may follow
/// the path, in any order:
///
/// - `codec = <ident>` — compress before sealing (`store`, `deflate`,
///   `lz4`, `snappy`, or `auto`). Defaults to `deflate` when omitted;
///   `auto` also simplifies to `deflate` here rather than running the full
///   codec-selection pass `embed_bytes!` does, since the entry is encrypted
///   regardless. The same feature-enablement caveat as `embed_bytes!`
///   applies: if the named codec's feature isn't enabled on `embark`, the
///   entry silently degrades to `store` instead of failing to build.
/// - `cipher = <ident>` — the AEAD cipher to seal with: `chacha`
///   (ChaCha20-Poly1305, the default) or `aes` (AES-256-GCM). Both share
///   the same key/nonce/tag shape and threat model — see the module docs'
///   security note. `cipher = aes` requires the `aes` feature enabled on
///   `embark`; naming it without that feature is a build error, not a
///   silent fallback (unlike an unavailable codec).
/// - `key = runtime` — opt into the runtime-key mode: no key material is
///   embedded, and the resulting handle (an `EncryptedFile<RuntimeKey>`)
///   must be decrypted with `decrypt_with(&key)` -- it has no `decrypt()`
///   method at all, so a binding must be explicitly typed
///   `EncryptedFile<RuntimeKey>` (plain `EncryptedFile` defaults to
///   `EncryptedFile<EmbeddedKey>` and will not accept it). Omitted by
///   default, which uses the build-time embedded-key mode
///   (**obfuscation, not security** — see `EncryptedFile`'s docs for what
///   that means and why).
#[proc_macro]
pub fn embed_crypt(input: TokenStream) -> TokenStream {
    let parsed = syn::parse_macro_input!(input as crypt_args::CryptArgs);
    let data = build::read(&parsed.path);
    let codec = parsed.codec_id();
    let crypto = parsed.crypto_id();
    let mode = if parsed.runtime_key {
        crypt::KeyMode::Runtime
    } else {
        crypt::KeyMode::BuildTime
    };
    let sealed = crypt::seal_file(&data, codec, crypto, mode);
    let entry_lit = build::bytes_literal(&sealed.entry);
    match sealed.key {
        Some(key) => {
            // Emit a per-build-randomized key-reconstruction fn and hand its
            // pointer to `with_embedded_key`. The whole thing is a block
            // expression valid in a `static` initializer: an inner `fn` item
            // plus a const-constructible tail call.
            let (recon_fn, recon_name) = obfuscate::emit_key_recon(key);
            quote! {
                {
                    #recon_fn
                    ::embark::EncryptedFile::with_embedded_key(#entry_lit, #recon_name)
                }
            }
            .into()
        }
        None => quote!(::embark::EncryptedFile::with_runtime_key(#entry_lit)).into(),
    }
}

/// Derives [`Embed`](https://docs.rs/embark/*/embark/trait.Embed.html) for
/// a unit struct, embedding every file under a folder at build time.
///
/// ```ignore
/// #[derive(embark::Embed)]
/// #[embark(folder = "assets", codec = "auto", include = "*.png", exclude = "*.tmp")]
/// struct Assets;
///
/// let logo = Assets::get("logo.png").unwrap();
/// for path in Assets::iter() { /* ... */ }
/// ```
///
/// Configured with a single `#[embark(...)]` attribute, whose keys are:
///
/// - `folder = "..."` (required) — the directory to embed, relative to
///   `CARGO_MANIFEST_DIR`. Walked recursively; every file found becomes a
///   manifest entry, keyed by its path relative to this folder (with `/`
///   separators, even on Windows).
/// - `codec = "..."` — compression for every embedded file: `"store"`,
///   `"deflate"` (the default), `"lz4"`, `"snappy"`, or `"auto"` (picks
///   the smallest per-file output among the codecs enabled on `embark`).
///   As with `embed_bytes!`, naming a codec whose feature isn't enabled on
///   `embark` does not fail the build -- affected entries silently degrade
///   to `store` (correct, just uncompressed).
/// - `encrypt` — seal every embedded file with a single build-time
///   embedded key shared by the whole derive
///   (**obfuscation, not security** -- see `EncryptedFile`'s docs).
///   `Embed::get` then returns files decryptable with the infallible
///   `EncryptedFile::decrypt()`. There is currently no per-derive
///   `key = runtime` option; use `embed_crypt!` directly for runtime-key
///   files.
/// - `cipher = "..."` — the AEAD cipher `encrypt` seals with: `"chacha"`
///   (ChaCha20-Poly1305, the default) or `"aes"` (AES-256-GCM). Ignored
///   without `encrypt`. Both share the same threat model -- see the
///   module docs' security note. `cipher = "aes"` requires the `aes`
///   feature enabled on `embark`; naming it without that feature is a
///   build error.
/// - `dev` — in debug builds only, `get()` reads the file live from disk
///   (relative to `folder`) instead of returning the compiled-in copy, for
///   fast iteration without rebuilding. Has no effect in release builds.
/// - `include = "..."` / `exclude = "..."` — glob filters over each file's
///   path relative to `folder`; repeatable (each occurrence adds one
///   pattern). A file is embedded when it matches no `exclude` pattern and
///   (`include` is empty, or it matches at least one `include` pattern).
///   `exclude` takes priority over `include`.
///
///   **Glob matching does not cross `/`.** `*` and `?` match any run of
///   characters *except* `/` -- they do not recurse into
///   subdirectories on their own, even though the folder walk itself is
///   recursive. So `include = "*.png"` matches `logo.png` but **not**
///   `sub/logo.png`; matching against a nested file needs an explicit
///   path, e.g. `include = "sub/*.png"` (still only one level) or use
///   `include = "*"`, which matches any top-level file (a relative path
///   containing no `/`) but still not `sub/logo.png`. There is no
///   `**`-style multi-segment wildcard.
#[proc_macro_derive(Embed, attributes(embark))]
pub fn derive_embed(input: TokenStream) -> TokenStream {
    let parsed = syn::parse_macro_input!(input as syn::DeriveInput);
    derive::expand(parsed).into()
}
