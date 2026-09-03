use crate::args::{CodecArg, parse_codec};
use crate::{build, crypt, glob};
use embark_format::{CodecId, CryptoId};
use quote::quote;
use std::path::Path;
use syn::LitStr;
use syn::spanned::Spanned;

struct Config {
    // The literal, not its value: every folder-related diagnostic below is
    // spanned at it, so the caret lands on the path the user wrote.
    folder: LitStr,
    codec: CodecArg,
    cipher: CryptoId,
    encrypt: bool,
    dev: bool,
    include: Vec<String>,
    exclude: Vec<String>,
}

pub(crate) fn expand(input: &syn::DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    check_shape(input)?;
    let name = &input.ident;
    let cfg = parse_config(input)?;
    let folder_span = cfg.folder.span();

    let folder_abs = build::resolve(&cfg.folder);
    let folder_abs_str = build::path_str(&folder_abs, folder_span)?.to_string();

    // Walk the folder, collect (relative_path, absolute_path), apply globs.
    let mut files = Vec::new();
    walk(&folder_abs, &folder_abs, &cfg, &mut files)?;
    files.sort();

    // One build-time key per derive when encrypting.
    let key_material = if cfg.encrypt {
        Some(embark_crypt::gen_key_nonce().0)
    } else {
        None
    };

    let mut manifest_items = Vec::new();
    let mut tracked = Vec::new();
    for (rel, abs) in &files {
        let shown = shown_child(&cfg, rel);
        let data = build::read(abs, &shown, folder_span)?;
        let entry = if let Some(key) = key_material {
            // As in `embed_crypt!`: the encrypted path does not run the
            // selection pass, and an `auto` policy simplifies to Deflate.
            let codec = match cfg.codec {
                CodecArg::Auto(_) => CodecArg::Fixed(CodecId::Deflate),
                fixed => fixed,
            };
            crypt::seal_with_key(&data, codec, cfg.cipher, key, &shown, folder_span)?
        } else {
            build::build_entry(cfg.codec, &data, &shown, folder_span)?
        };
        let lit = build::bytes_literal(&entry);
        manifest_items.push(quote! {
            ::embark::Manifest::new(#rel, #lit)
        });
        tracked.push(build::track_file(abs, folder_span)?);
    }

    // get()/iter() bodies. Dev-mode overrides get() in debug builds.
    let dev = cfg.dev;
    // When encrypting, emit ONE per-build-randomized key-reconstruction fn for
    // the whole derive (all files share the key) and hand its pointer to
    // `lookup_encrypted`. The fn item is spliced into the `const _` block below.
    let (recon_fn, get_body) = if let Some(key) = key_material {
        let (recon_fn, recon_name) = crate::obfuscate::emit_key_recon(key);
        (
            recon_fn,
            quote!(::embark::lookup_encrypted(MANIFEST, path, #recon_name)),
        )
    } else {
        (quote!(), quote!(::embark::lookup(MANIFEST, path)))
    };

    // With #[embark(dev)] the #[cfg(debug_assertions)] branch below always
    // returns in a debug build, which makes `get_body` provably unreachable
    // from rustc's point of view even though it is very much live in a
    // release build. Scoped to the dev case only, so a real unreachable-code
    // bug in a non-dev derive still gets flagged.
    let (dev_branch, unreachable_allow) = if dev {
        (
            quote! {
                #[cfg(debug_assertions)]
                {
                    return ::embark::__dev_file(#folder_abs_str, path);
                }
            },
            quote!(#[allow(unreachable_code)]),
        )
    } else {
        (quote!(), quote!())
    };

    Ok(quote! {
        const _: () = {
            #(#tracked)*
            static MANIFEST: &[::embark::Manifest] = &[ #(#manifest_items),* ];
            #recon_fn
            impl ::embark::Embed for #name {
                #unreachable_allow
                fn get(path: &str) -> ::core::option::Option<::embark::EmbeddedFile> {
                    #dev_branch
                    #get_body
                }
                fn iter() -> ::embark::Entries {
                    ::embark::entries(MANIFEST)
                }
            }
        };
    })
}

/// The failure form of [`expand`]: the real diagnostic, plus an `Embed` impl
/// that does nothing.
///
/// Without the stub, every downstream `Assets::get(..)` raises its own
/// "no function or associated item named `get`" on top of the actual error,
/// burying it. The stub makes those calls resolve, leaving the message that
/// explains what to fix as the only one reported.
pub(crate) fn error_with_stub(
    input: &syn::DeriveInput,
    err: &syn::Error,
) -> proc_macro2::TokenStream {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let diagnostic = err.to_compile_error();
    quote! {
        #diagnostic
        const _: () = {
            impl #impl_generics ::embark::Embed for #name #ty_generics #where_clause {
                fn get(_path: &str) -> ::core::option::Option<::embark::EmbeddedFile> {
                    ::core::option::Option::None
                }
                fn iter() -> ::embark::Entries {
                    ::embark::entries(&[])
                }
            }
        };
    }
}

/// `#[derive(Embed)]` ties a folder to a type name, so the type itself has
/// nothing to carry: the documented contract is a non-generic unit struct.
/// Anything else expands to an impl that does not mean what it says.
fn check_shape(input: &syn::DeriveInput) -> syn::Result<()> {
    const EXPECTED: &str = "#[derive(Embed)] expects a unit struct, e.g. `struct Assets;`";

    if !input.generics.params.is_empty() {
        // Spanned at the `<` rather than at the parameter list as a whole:
        // covering the list means joining several token spans, which only
        // some compilers can do, so the caret would change width from one
        // toolchain to the next.
        let at = input
            .generics
            .lt_token
            .map_or_else(|| input.ident.span(), |lt| lt.span());
        return Err(syn::Error::new(
            at,
            format!("{EXPECTED}; generic parameters are not supported"),
        ));
    }
    match &input.data {
        syn::Data::Struct(s) => match &s.fields {
            syn::Fields::Unit => Ok(()),
            fields => Err(syn::Error::new(
                fields.span(),
                format!("{EXPECTED}; this struct has fields"),
            )),
        },
        syn::Data::Enum(e) => Err(syn::Error::new(
            e.enum_token.span,
            format!("{EXPECTED}; enums are not supported"),
        )),
        syn::Data::Union(u) => Err(syn::Error::new(
            u.union_token.span,
            format!("{EXPECTED}; unions are not supported"),
        )),
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    cfg: &Config,
    out: &mut Vec<(String, std::path::PathBuf)>,
) -> syn::Result<()> {
    // A directory that cannot be listed would otherwise drop every file under
    // it from the manifest without a word, so report it instead.
    let rd = std::fs::read_dir(dir).map_err(|e| {
        let shown = if dir == root {
            cfg.folder.value()
        } else {
            shown_child(cfg, &relative_to(root, dir))
        };
        let msg = if e.kind() == std::io::ErrorKind::NotFound {
            format!("embark: folder not found: `{shown}` (resolved relative to CARGO_MANIFEST_DIR)")
        } else {
            format!("embark: cannot read folder `{shown}`: {e}")
        };
        syn::Error::new(cfg.folder.span(), msg)
    })?;
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, cfg, out)?;
        } else {
            let rel = relative_to(root, &path);
            if included(cfg, &rel) {
                out.push((rel, path));
            }
        }
    }
    Ok(())
}

/// How a path under the embedded folder is named in diagnostics: as the user
/// wrote the folder, plus the entry's path relative to it. The resolved
/// absolute path is deliberately left out -- see `build::read`.
fn shown_child(cfg: &Config, rel: &str) -> String {
    format!("{}/{rel}", cfg.folder.value().trim_end_matches('/'))
}

/// `path` relative to `root`, with `/` separators on every platform. Every
/// caller passes a `path` produced by walking `root`, so the prefix is there.
fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn included(cfg: &Config, rel: &str) -> bool {
    if cfg.exclude.iter().any(|p| glob::matches(p, rel)) {
        return false;
    }
    if cfg.include.is_empty() {
        return true;
    }
    cfg.include.iter().any(|p| glob::matches(p, rel))
}

fn parse_config(input: &syn::DeriveInput) -> syn::Result<Config> {
    let mut folder: Option<LitStr> = None;
    let mut codec = CodecArg::Fixed(CodecId::Deflate);
    let mut cipher = CryptoId::ChaCha20Poly1305;
    let mut encrypt = false;
    let mut dev = false;
    let mut include = Vec::new();
    let mut exclude = Vec::new();

    for attr in &input.attrs {
        if !attr.path().is_ident("embark") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("folder") {
                folder = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("codec") {
                let s: syn::LitStr = meta.value()?.parse()?;
                let name = s.value();
                codec = parse_codec(&name)
                    .ok_or_else(|| meta.error(format!("unknown codec `{name}`")))?;
            } else if meta.path.is_ident("cipher") {
                let s: syn::LitStr = meta.value()?.parse()?;
                match s.value().as_str() {
                    "chacha" => cipher = CryptoId::ChaCha20Poly1305,
                    "aes" => {
                        if !cfg!(feature = "aes") {
                            return Err(meta.error(
                                "cipher = \"aes\" requires the `aes` feature enabled on `embark`",
                            ));
                        }
                        cipher = CryptoId::Aes256Gcm;
                    }
                    other => return Err(meta.error(format!("unknown cipher `{other}`"))),
                }
            } else if meta.path.is_ident("encrypt") {
                encrypt = true;
            } else if meta.path.is_ident("dev") {
                dev = true;
            } else if meta.path.is_ident("include") {
                let s: syn::LitStr = meta.value()?.parse()?;
                include.push(s.value());
            } else if meta.path.is_ident("exclude") {
                let s: syn::LitStr = meta.value()?.parse()?;
                exclude.push(s.value());
            } else {
                return Err(meta.error("unknown `#[embark(...)]` attribute"));
            }
            Ok(())
        })?;
    }

    let folder = folder.ok_or_else(|| {
        syn::Error::new(
            input.ident.span(),
            "#[derive(Embed)] requires #[embark(folder = \"...\")]",
        )
    })?;

    Ok(Config {
        folder,
        codec,
        cipher,
        encrypt,
        dev,
        include,
        exclude,
    })
}
