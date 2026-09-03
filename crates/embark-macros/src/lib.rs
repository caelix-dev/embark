#![forbid(unsafe_code)]

mod args;
mod build;
mod crypt;
mod crypt_args;

use embark_format::CodecId;
use proc_macro::TokenStream;
use quote::quote;

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

#[proc_macro]
pub fn embed_crypt(input: TokenStream) -> TokenStream {
    let parsed = syn::parse_macro_input!(input as crypt_args::CryptArgs);
    let data = build::read(&parsed.path);
    let codec = parsed.codec_id();
    let mode = if parsed.runtime_key {
        crypt::KeyMode::Runtime
    } else {
        crypt::KeyMode::BuildTime
    };
    let sealed = crypt::seal_file(&data, codec, mode);
    let entry_lit = build::bytes_literal(&sealed.entry);
    match sealed.masked_mask {
        Some((masked, mask)) => {
            let masked_arr = array32(&masked);
            let mask_arr = array32(&mask);
            quote!(::embark::EncryptedFile::with_embedded_key(#entry_lit, #masked_arr, #mask_arr)).into()
        }
        None => quote!(::embark::EncryptedFile::with_runtime_key(#entry_lit)).into(),
    }
}

fn array32(bytes: &[u8; 32]) -> proc_macro2::TokenStream {
    let elems = bytes.iter().map(|b| quote::quote!(#b));
    quote::quote!([#(#elems),*])
}
