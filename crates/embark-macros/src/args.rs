use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token};

pub enum CodecArg {
    Store,
    Deflate,
    Lz4,
    Snappy,
    Auto,
}

pub struct Args {
    pub path: String,
    pub codec: Option<CodecArg>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path: LitStr = input.parse()?;
        let mut codec = None;
        if input.peek(Token![,]) {
            let _: Token![,] = input.parse()?;
            let key: syn::Ident = input.parse()?;
            if key != "codec" {
                return Err(syn::Error::new(key.span(), "expected `codec`"));
            }
            let _: Token![=] = input.parse()?;
            let val: syn::Ident = input.parse()?;
            codec = Some(match val.to_string().as_str() {
                "store" => CodecArg::Store,
                "deflate" => CodecArg::Deflate,
                "lz4" => CodecArg::Lz4,
                "snappy" => CodecArg::Snappy,
                "auto" => CodecArg::Auto,
                other => {
                    return Err(syn::Error::new(
                        val.span(),
                        format!("unknown codec `{other}`"),
                    ))
                }
            });
        }
        Ok(Args {
            path: path.value(),
            codec,
        })
    }
}
