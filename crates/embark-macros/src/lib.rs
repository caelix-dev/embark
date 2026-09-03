#![forbid(unsafe_code)]

mod args;
mod build;

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
        Some(_) => {
            // Transformed mode is added in Task 14.
            quote!(compile_error!("codec-transformed embed_bytes! not yet implemented")).into()
        }
    }
}
