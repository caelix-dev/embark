use embark_codec::AutoTier;
use embark_format::CodecId;
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token};

/// The `codec = ...` argument: either one named codec, or one of the `auto`
/// policies, which names a tier of candidates to pick the smallest output
/// from rather than a codec.
#[derive(Clone, Copy)]
pub(crate) enum CodecArg {
    Fixed(CodecId),
    Auto(AutoTier),
}

/// Parses the value of a `codec = ...` argument, or `None` if it names no
/// codec this build knows.
///
/// All three macros share this vocabulary. `embed_bytes!` and
/// `embed_crypt!` spell the value as a bare ident and `#[derive(Embed)]` as
/// a string, but the accepted names are the same set.
pub(crate) fn parse_codec(name: &str) -> Option<CodecArg> {
    Some(match name {
        "store" => CodecArg::Fixed(CodecId::Store),
        "deflate" => CodecArg::Fixed(CodecId::Deflate),
        "lz4" => CodecArg::Fixed(CodecId::Lz4),
        "snappy" => CodecArg::Fixed(CodecId::Snappy),
        "zstd" => CodecArg::Fixed(CodecId::Zstd),
        "lzma" => CodecArg::Fixed(CodecId::Lzma),
        "auto_fast" => CodecArg::Auto(AutoTier::Fast),
        "auto" => CodecArg::Auto(AutoTier::Balanced),
        "auto_small" => CodecArg::Auto(AutoTier::Small),
        _ => return None,
    })
}

pub(crate) struct Args {
    // Kept as the literal, not its value: downstream errors (a missing file,
    // say) are spanned at it so the caret lands on the path the user wrote.
    pub path: LitStr,
    pub codec: Option<CodecArg>,
}

impl Parse for Args {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
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
            let name = val.to_string();
            codec =
                Some(parse_codec(&name).ok_or_else(|| {
                    syn::Error::new(val.span(), format!("unknown codec `{name}`"))
                })?);
        }
        Ok(Args { path, codec })
    }
}
