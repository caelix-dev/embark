//! Proc-macros for `embark`: [`embed_bytes!`], [`embed_crypt!`], and the
//! [`Embed`](macro@Embed) derive. Re-exported from the `embark` crate under
//! its `derive` feature; use them via `embark::embed_bytes!` etc. rather
//! than depending on this crate directly.

// docs.rs builds with `--cfg docsrs` (see each manifest's
// `[package.metadata.docs.rs]`), which turns this on and makes rustdoc label
// every item with the feature that gates it. Nearly all of this API is
// behind one, so without the label the rendered docs read as though it were
// all unconditional. Inert on stable, where `docsrs` is never set.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod args;
mod build;
mod crypt;
mod crypt_args;
mod derive;
mod glob;
mod obfuscate;

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
/// // Compressed with the best size/decode-speed trade among the enabled
/// // codecs; `auto_fast` and `auto_small` move that balance either way.
/// static BEST: embark::EmbeddedBytes = embark::embed_bytes!("assets/data.json", codec = auto);
/// ```
///
/// <div class="warning">Not run as a doctest: expanding this macro needs
/// the `embark` crate, and `embark-macros` cannot depend on it without a
/// dependency cycle. A runnable version, embedding real files, is on
/// [`EmbeddedBytes`](https://docs.rs/embark/*/embark/struct.EmbeddedBytes.html).</div>
///
/// `path` is resolved relative to the crate's `CARGO_MANIFEST_DIR`. The
/// optional `codec = <ident>` argument names either one codec -- `store`,
/// `deflate`, `lz4`, `snappy`, `zstd` or `lzma` -- or one of the three
/// `auto` policies, which compress with a tier of candidates at build time
/// and keep the smallest output among that tier:
///
/// | policy | candidates |
/// |---|---|
/// | `auto_fast` | `store`, `lz4`, `snappy` |
/// | `auto` | those, plus `deflate` and `zstd` |
/// | `auto_small` | those, plus `lzma` |
///
/// Compression runs once, here; decompression runs in the shipped binary on
/// every access. The tiers are cut along that second axis. On a 468 KiB
/// executable, `auto_fast` picks LZ4 at 312,340 bytes and 1,744 MB/s,
/// `auto` picks DEFLATE at 228,157 bytes and 305 MB/s, and `auto_small`
/// picks LZMA at 191,493 bytes and 45 MB/s. All three fall back to `store`
/// when nothing shrinks the file.
///
/// A policy encodes only with its own candidates, so `auto_fast` never pays
/// LZMA's build-time encode cost to then throw the result away.
///
/// **Codecs and enabled features:** the codec ident you name here must
/// correspond to a codec feature enabled on the `embark` crate you decode
/// with. If it isn't enabled, encoding does not fail -- the entry silently
/// degrades to `store` (uncompressed) instead, since encoding never fails
/// and correct but uncompressed output is still correct. Enable the
/// matching feature (`deflate`, `lz4`, `snappy`, `zstd`, `lzma`) if you
/// expect compression to actually happen. The `auto` policies can only pick
/// an enabled codec by construction, and a policy whose whole tier is
/// disabled widens to the next one rather than degrading to `store`: with
/// only `lzma` on, `auto_fast` still compresses.
#[proc_macro]
pub fn embed_bytes(input: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(input as args::Args);
    expand_bytes(args)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_bytes(args: args::Args) -> syn::Result<proc_macro2::TokenStream> {
    let span = args.path.span();
    let shown = args.path.value();
    let path = build::resolve(&args.path);
    match args.codec {
        None => {
            // Raw mode: zero-cost include_bytes! with an absolute path.
            build::ensure_readable(&path, &shown, span)?;
            let abs = build::path_str(&path, span)?;
            Ok(quote!(::core::include_bytes!(#abs)))
        }
        Some(codec) => {
            let data = build::read(&path, &shown).map_err(build::at(span))?;
            let entry = build::build_entry(codec, &data, &shown).map_err(build::at(span))?;
            let lit = build::bytes_literal(&entry);
            let track = build::track_file(&path, span)?;
            Ok(quote! {
                {
                    #track
                    ::embark::EmbeddedBytes::from_entry(#lit)
                }
            })
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
/// <div class="warning">Not run as a doctest: expanding this macro needs
/// the `embark` crate, and `embark-macros` cannot depend on it without a
/// dependency cycle. A runnable version of the embedded-key half is on
/// [`EncryptedFile`](https://docs.rs/embark/*/embark/struct.EncryptedFile.html).
/// The runtime-key half cannot be a doctest anywhere: `key = runtime`
/// reads `EMBARK_KEY` from the environment at build time.</div>
///
/// `path` is resolved relative to `CARGO_MANIFEST_DIR`, as in
/// [`embed_bytes!`]. Independent, comma-separated arguments may follow
/// the path, in any order:
///
/// - `codec = <ident>` — compress before sealing (`store`, `deflate`,
///   `lz4`, `snappy`, `zstd`, `lzma`, or one of `auto_fast` / `auto` /
///   `auto_small`). Defaults to `deflate` when omitted. The `auto` policies
///   run the same selection pass as in [`embed_bytes!`]; compression
///   happens before sealing, so the pass reads the plaintext and the cipher
///   sees no difference. The same feature-enablement caveat as
///   [`embed_bytes!`] applies: if the named codec's feature isn't enabled
///   on `embark`, the entry silently degrades to `store` instead of failing
///   to build.
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
    expand_crypt(parsed)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_crypt(parsed: crypt_args::CryptArgs) -> syn::Result<proc_macro2::TokenStream> {
    let span = parsed.path.span();
    let shown = parsed.path.value();
    let path = build::resolve(&parsed.path);
    let data = build::read(&path, &shown).map_err(build::at(span))?;
    let track = build::track_file(&path, span)?;
    let codec = parsed.codec();
    let crypto = parsed.crypto_id();
    let mode = match parsed.runtime_key {
        // `KeyMode::Runtime` carries its own span, so an EMBARK_KEY failure
        // lands on the `key = runtime` argument that asked for it rather
        // than on the path literal every other diagnostic points at.
        Some(key_span) => crypt::KeyMode::Runtime(key_span),
        None => crypt::KeyMode::BuildTime,
    };
    let sealed = crypt::seal_file(&data, codec, crypto, mode, &shown, span)?;
    let entry_lit = build::bytes_literal(&sealed.entry);
    Ok(match sealed.key {
        Some(key) => {
            // Emit a per-build-randomized key-reconstruction fn and hand its
            // pointer to `with_embedded_key`. The whole thing is a block
            // expression valid in a `static` initializer: an inner `fn` item
            // plus a const-constructible tail call.
            let (recon_fn, recon_name) = obfuscate::emit_key_recon(key);
            quote! {
                {
                    #track
                    #recon_fn
                    ::embark::EncryptedFile::with_embedded_key(#entry_lit, #recon_name)
                }
            }
        }
        None => quote! {
            {
                #track
                ::embark::EncryptedFile::with_runtime_key(#entry_lit)
            }
        },
    })
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
/// <div class="warning">Not run as a doctest: expanding this macro needs
/// the `embark` crate, and `embark-macros` cannot depend on it without a
/// dependency cycle. A runnable version, embedding a real folder, is on
/// [`Embed`](https://docs.rs/embark/*/embark/trait.Embed.html).</div>
///
/// Configured with a single `#[embark(...)]` attribute, whose keys are:
///
/// - `folder = "..."` (required) — the directory to embed, relative to
///   `CARGO_MANIFEST_DIR`. Walked recursively; every file found becomes a
///   manifest entry, keyed by its path relative to this folder (with `/`
///   separators, even on Windows).
/// - `codec = "..."` — compression for every embedded file: `"store"`,
///   `"deflate"` (the default), `"lz4"`, `"snappy"`, `"zstd"`, `"lzma"`, or
///   one of the three selection policies `"auto_fast"`, `"auto"` and
///   `"auto_small"`, described on [`embed_bytes!`]. A policy is applied per
///   file, so one folder can end up with a different codec per entry. It
///   applies under `encrypt` too, on each file's plaintext.
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
///
///   It serves the files the derive embedded and nothing else: a path has
///   to be one the manifest holds, exactly, or `get()` returns `None` just
///   as the release build would. A file added to the folder since the last
///   build is not served until the crate rebuilds, and one that `exclude`
///   left out is never served. This is what keeps a development server
///   that hands out assets by request path from handing out `../.env`.
/// - `follow_links` — follow symbolic links (and, on Windows, junctions)
///   found inside the folder. Off by default, and a link met without it is
///   a build error rather than a skipped file: a link can point anywhere
///   on the build machine, and following one that points at a key or a
///   credential file embeds that file into the binary. That is a plausible
///   shape for an accident and a very plausible shape for a hostile pull
///   request. With it on, each real directory is walked once, so a link
///   back to an ancestor ends the walk instead of never ending it.
/// - `include = "..."` / `exclude = "..."` — glob filters over each file's
///   path relative to `folder`; repeatable (each occurrence adds one
///   pattern). A file is embedded when it matches no `exclude` pattern and
///   (`include` is empty, or it matches at least one `include` pattern).
///   `exclude` takes priority over `include`.
///
///   `?` matches one character other than `/`, and `*` any run of them, so
///   a single `*` stays inside one path segment: `include = "*.png"`
///   matches `logo.png` but not `sub/logo.png`.
///
///   `**` crosses `/`. As a whole segment it stands for any number of
///   segments, zero included, which is what makes `**/*.png` the way to say
///   "a `.png` anywhere":
///
///   | pattern | matches |
///   |---|---|
///   | `*.png` | `logo.png` |
///   | `sub/*.png` | `sub/logo.png` |
///   | `**/*.png` | `logo.png`, `sub/logo.png`, `a/b/logo.png` |
///   | `sub/**` | everything under `sub/`, at any depth |
///   | `**` | everything |
///
/// # Rebuilds
///
/// Every embedded file is registered as a build input, so editing or
/// deleting one of them triggers a rebuild. **Adding a new file to the
/// folder does not.** Only the files that existed when the derive last
/// expanded are tracked, and a file that has never been seen cannot be
/// among them. After adding a file, force the crate to rebuild -- touch
/// any of its `.rs` files, or run `cargo clean -p <crate>`.
#[proc_macro_derive(Embed, attributes(embark))]
pub fn derive_embed(input: TokenStream) -> TokenStream {
    let parsed = syn::parse_macro_input!(input as syn::DeriveInput);
    derive::expand(&parsed)
        .unwrap_or_else(|e| derive::error_with_stub(&parsed, &e))
        .into()
}
