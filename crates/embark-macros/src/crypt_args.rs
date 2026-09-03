use embark_format::CodecId;
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token};

/// Parses `embed_crypt!` arguments: a path literal, optionally followed by
/// `, codec = <ident>` and/or `, key = runtime`, in either order. Modeled on
/// `args::Args`, with the addition of the `key = runtime` flag.
pub struct CryptArgs {
    pub path: String,
    pub codec: Option<crate::args::CodecArg>,
    pub runtime_key: bool,
}

impl CryptArgs {
    /// The codec to compress with before sealing. Defaults to `Deflate` when
    /// unspecified. `codec = auto` is accepted but, for `embed_crypt!`,
    /// simplifies to `Deflate` too rather than running the full
    /// codec-selection pass `embed_bytes!` does for its `auto` mode -- the
    /// entry is encrypted either way, so the size delta between codecs
    /// matters less here.
    pub fn codec_id(&self) -> CodecId {
        match self.codec {
            None | Some(crate::args::CodecArg::Auto) => CodecId::Deflate,
            Some(crate::args::CodecArg::Store) => CodecId::Store,
            Some(crate::args::CodecArg::Deflate) => CodecId::Deflate,
            Some(crate::args::CodecArg::Lz4) => CodecId::Lz4,
            Some(crate::args::CodecArg::Snappy) => CodecId::Snappy,
        }
    }
}

impl Parse for CryptArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path: LitStr = input.parse()?;
        let mut codec = None;
        let mut runtime_key = false;

        while input.peek(Token![,]) {
            let _: Token![,] = input.parse()?;
            let key: syn::Ident = input.parse()?;
            let _: Token![=] = input.parse()?;
            if key == "codec" {
                let val: syn::Ident = input.parse()?;
                codec = Some(match val.to_string().as_str() {
                    "store" => crate::args::CodecArg::Store,
                    "deflate" => crate::args::CodecArg::Deflate,
                    "lz4" => crate::args::CodecArg::Lz4,
                    "snappy" => crate::args::CodecArg::Snappy,
                    "auto" => crate::args::CodecArg::Auto,
                    other => {
                        return Err(syn::Error::new(
                            val.span(),
                            format!("unknown codec `{other}`"),
                        ))
                    }
                });
            } else if key == "key" {
                let val: syn::Ident = input.parse()?;
                if val != "runtime" {
                    return Err(syn::Error::new(val.span(), "expected `runtime`"));
                }
                runtime_key = true;
            } else {
                return Err(syn::Error::new(key.span(), "expected `codec` or `key`"));
            }
        }

        Ok(CryptArgs {
            path: path.value(),
            codec,
            runtime_key,
        })
    }
}
