use crate::args::{CodecArg, parse_codec};
use crate::{build, crypt, glob};
use embark_crypt::Zeroizing;
use embark_format::{CodecId, CryptoId};
use quote::quote;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
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
    // Off unless asked for. A link inside the folder can point anywhere on
    // the build machine, and following it embeds whatever is there.
    follow_links: bool,
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
    walk(
        &folder_abs,
        &folder_abs,
        &cfg,
        &mut HashSet::new(),
        &mut files,
    )?;
    files.sort();

    // One build-time key per derive when encrypting. It is only ever lent
    // out from here, and wiped when the expansion is done with it.
    let key_material = cfg
        .encrypt
        .then(|| Zeroizing::new(embark_crypt::gen_key_nonce().0));

    // One folder is many files, and a file is read, compressed and sealed
    // without reference to any other: the shared key was drawn above, before
    // any of this starts, and each entry's bytes stand alone. That makes the
    // folder the outermost place there is to spend the encoder's threads,
    // and the most valuable, since a derive over an asset folder is what
    // most builds actually run.
    //
    // Only plain data crosses into the workers. A `proc_macro2::Span` is not
    // `Send`, so the steps below report failures as text and the loop after
    // this one gives them their caret back -- at `folder_span`, which is
    // where every one of these diagnostics pointed before as well.
    let jobs: Vec<(String, PathBuf)> = files
        .iter()
        .map(|(rel, abs)| (shown_child(&cfg, rel), abs.clone()))
        .collect();
    let (codec, cipher) = (cfg.codec, cfg.cipher);
    let built = embark_codec::parallel::map(&jobs, |(shown, abs)| {
        let data = build::read(abs, shown)?;
        match &key_material {
            Some(key) => crypt::seal_with_key(&data, codec, cipher, key, shown),
            None => build::build_entry(codec, &data, shown),
        }
    });

    let mut manifest_items = Vec::new();
    let mut tracked = Vec::new();
    for ((rel, abs), entry) in files.iter().zip(built) {
        let entry = entry.map_err(build::at(folder_span))?;
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
    let (recon_fn, get_body) = if let Some(key) = &key_material {
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
                    return ::embark::__dev_file(MANIFEST, #folder_abs_str, path);
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
    seen: &mut HashSet<PathBuf>,
    out: &mut Vec<(String, std::path::PathBuf)>,
) -> syn::Result<()> {
    // A followed link can lead back to a directory already walked, and one
    // pointing at an ancestor would do so without end. Each real directory
    // is walked once, the root included, so a link back to it is simply a
    // directory already seen.
    if cfg.follow_links {
        let real = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        if !seen.insert(real) {
            return Ok(());
        }
    }
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
        // What the entry *is*, from the listing, before anything follows it
        // to what it points at.
        let is_link = entry.file_type().is_ok_and(|kind| kind.is_symlink());
        if is_link && !cfg.follow_links {
            let shown = shown_child(cfg, &relative_to(root, &path));
            return Err(syn::Error::new(
                cfg.folder.span(),
                format!(
                    "embark: `{shown}` is a symbolic link, and links are not followed: one \
                     pointing outside the folder would embed its target -- a key, a \
                     credential file -- into the binary. Add `follow_links` to \
                     `#[embark(...)]` to follow links, or replace it with the file itself."
                ),
            ));
        }
        if path.is_dir() {
            walk(root, &path, cfg, seen, out)?;
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
    let mut codec: Option<CodecArg> = None;
    let mut cipher: Option<CryptoId> = None;
    let mut encrypt = false;
    let mut dev = false;
    let mut follow_links = false;
    let mut include = Vec::new();
    let mut exclude = Vec::new();

    // `include` and `exclude` are lists, so they repeat. Everything else
    // names one value, and a second one would silently replace the first.
    let once = |seen: bool, meta: &syn::meta::ParseNestedMeta<'_>| {
        if seen {
            let key = meta
                .path
                .get_ident()
                .map_or_else(String::new, |k| k.to_string());
            return Err(meta.error(format!("`{key}` given more than once")));
        }
        Ok(())
    };

    for attr in &input.attrs {
        if !attr.path().is_ident("embark") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("folder") {
                once(folder.is_some(), &meta)?;
                folder = Some(meta.value()?.parse()?);
            } else if meta.path.is_ident("codec") {
                once(codec.is_some(), &meta)?;
                let s: syn::LitStr = meta.value()?.parse()?;
                let name = s.value();
                codec = Some(
                    parse_codec(&name)
                        .ok_or_else(|| meta.error(format!("unknown codec `{name}`")))?,
                );
            } else if meta.path.is_ident("cipher") {
                once(cipher.is_some(), &meta)?;
                let s: syn::LitStr = meta.value()?.parse()?;
                cipher = Some(match s.value().as_str() {
                    "chacha" => CryptoId::ChaCha20Poly1305,
                    "aes" => {
                        if !cfg!(feature = "aes") {
                            return Err(meta.error(
                                "cipher = \"aes\" requires the `aes` feature enabled on `embark`",
                            ));
                        }
                        CryptoId::Aes256Gcm
                    }
                    other => return Err(meta.error(format!("unknown cipher `{other}`"))),
                });
            } else if meta.path.is_ident("encrypt") {
                once(encrypt, &meta)?;
                encrypt = true;
            } else if meta.path.is_ident("dev") {
                once(dev, &meta)?;
                dev = true;
            } else if meta.path.is_ident("follow_links") {
                once(follow_links, &meta)?;
                follow_links = true;
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
        codec: codec.unwrap_or(CodecArg::Fixed(CodecId::Deflate)),
        cipher: cipher.unwrap_or(CryptoId::ChaCha20Poly1305),
        encrypt,
        dev,
        follow_links,
        include,
        exclude,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn config(follow_links: bool) -> Config {
        Config {
            folder: LitStr::new("assets", proc_macro2::Span::call_site()),
            codec: CodecArg::Fixed(CodecId::Store),
            cipher: CryptoId::ChaCha20Poly1305,
            encrypt: false,
            dev: false,
            follow_links,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }

    /// A fresh scratch tree: `assets/ok.txt`, and `outside.txt` next to the
    /// folder so a link can point out of it.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("embark-walk-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("assets")).unwrap();
        fs::write(dir.join("assets/ok.txt"), b"ok").unwrap();
        fs::write(dir.join("outside.txt"), b"not an asset").unwrap();
        dir
    }

    /// Creating a link needs a privilege on Windows that a plain user does
    /// not have. `None` means the test cannot run here, not that it failed.
    fn link(target: &Path, at: &Path, is_dir: bool) -> Option<()> {
        #[cfg(unix)]
        {
            let _ = is_dir;
            std::os::unix::fs::symlink(target, at).ok()
        }
        #[cfg(windows)]
        {
            if is_dir {
                std::os::windows::fs::symlink_dir(target, at).ok()
            } else {
                std::os::windows::fs::symlink_file(target, at).ok()
            }
        }
    }

    fn names(dir: &Path, follow_links: bool) -> syn::Result<Vec<String>> {
        let root = dir.join("assets");
        let mut out = Vec::new();
        walk(
            &root,
            &root,
            &config(follow_links),
            &mut HashSet::new(),
            &mut out,
        )?;
        Ok(out.into_iter().map(|(rel, _)| rel).collect())
    }

    #[test]
    fn a_link_out_of_the_folder_is_refused_unless_asked_for() {
        let dir = scratch("out");
        if link(
            &dir.join("outside.txt"),
            &dir.join("assets/leak.txt"),
            false,
        )
        .is_none()
        {
            return;
        }
        let err = names(&dir, false).expect_err("a link must not be followed by default");
        let msg = err.to_string();
        assert!(msg.contains("leak.txt"), "{msg}");
        assert!(msg.contains("follow_links"), "{msg}");

        let followed = names(&dir, true).unwrap();
        assert!(followed.contains(&"leak.txt".to_string()), "{followed:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_back_to_an_ancestor_ends_the_walk_instead_of_never_ending_it() {
        let dir = scratch("loop");
        if link(&dir.join("assets"), &dir.join("assets/again"), true).is_none() {
            return;
        }
        let followed = names(&dir, true).unwrap();
        // The real directory is walked once, so its one file appears once,
        // under the name it was reached by first.
        assert_eq!(
            followed.iter().filter(|n| n.ends_with("ok.txt")).count(),
            1,
            "{followed:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
