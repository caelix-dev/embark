use crate::{build, crypt, glob};
use embark_format::{CodecId, CryptoId};
use quote::quote;
use std::path::Path;

struct Config {
    folder: String,
    codec: CodecId,
    cipher: CryptoId,
    auto: bool,
    encrypt: bool,
    dev: bool,
    include: Vec<String>,
    exclude: Vec<String>,
}

pub fn expand(input: syn::DeriveInput) -> proc_macro2::TokenStream {
    let name = &input.ident;
    let cfg = parse_config(&input);

    let folder_abs = build::resolve(&cfg.folder);
    let folder_abs_str = folder_abs
        .to_str()
        .expect("embark: non-UTF-8 folder path")
        .to_string();

    // Walk the folder, collect (relative_path, absolute_path), apply globs.
    let mut files = Vec::new();
    walk(&folder_abs, &folder_abs, &cfg, &mut files);
    files.sort();

    // One build-time key per derive when encrypting.
    let key_material = if cfg.encrypt {
        Some(embark_crypt::gen_key_nonce().0)
    } else {
        None
    };

    let mut manifest_items = Vec::new();
    for (rel, abs) in &files {
        let data = std::fs::read(abs).expect("embark: read file during derive");
        let entry = if let Some(key) = key_material {
            crypt::seal_with_key(&data, cfg.codec, cfg.cipher, key)
        } else if cfg.auto {
            build::build_entry_best(&data)
        } else {
            build::build_entry(cfg.codec, &data)
        };
        let lit = build::bytes_literal(&entry);
        manifest_items.push(quote! {
            ::embark::Manifest { path: #rel, entry: #lit }
        });
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

    quote! {
        const _: () = {
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
    }
}

fn walk(root: &Path, dir: &Path, cfg: &Config, out: &mut Vec<(String, std::path::PathBuf)>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, cfg, out);
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if included(cfg, &rel) {
                out.push((rel, path));
            }
        }
    }
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

fn parse_config(input: &syn::DeriveInput) -> Config {
    let mut folder: Option<String> = None;
    let mut codec = CodecId::Deflate;
    let mut cipher = CryptoId::ChaCha20Poly1305;
    let mut auto = false;
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
                let s: syn::LitStr = meta.value()?.parse()?;
                folder = Some(s.value());
            } else if meta.path.is_ident("codec") {
                let s: syn::LitStr = meta.value()?.parse()?;
                match s.value().as_str() {
                    "auto" => auto = true,
                    "store" => codec = CodecId::Store,
                    "deflate" => codec = CodecId::Deflate,
                    "lz4" => codec = CodecId::Lz4,
                    "snappy" => codec = CodecId::Snappy,
                    other => return Err(meta.error(format!("unknown codec `{other}`"))),
                }
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
        })
        .expect("embark: invalid #[embark(...)] attribute");
    }

    Config {
        folder: folder.expect("embark: #[derive(Embed)] requires #[embark(folder = \"...\")]"),
        codec,
        cipher,
        auto,
        encrypt,
        dev,
        include,
        exclude,
    }
}
