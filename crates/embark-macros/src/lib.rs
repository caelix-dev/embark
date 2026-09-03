#![forbid(unsafe_code)]

mod args;
mod build;

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
