use crate::args::{CodecArg, parse_codec};
use embark_format::{CodecId, CryptoId};
use proc_macro2::Span;
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token};

/// The `cipher = ...` argument: which AEAD cipher to seal with.
pub(crate) enum CipherArg {
    ChaCha,
    Aes,
}

/// Parses `embed_crypt!` arguments: a path literal, optionally followed by
/// `, codec = <ident>`, `, cipher = <ident>`, and/or `, key = runtime`, in
/// any order. Modeled on `args::Args`, with the addition of the `cipher`
/// and `key = runtime` options.
pub(crate) struct CryptArgs {
    // Kept as the literal, not its value, so a failure to read the file is
    // spanned at the path the user wrote. Same for `runtime_key`: it carries
    // the span of `runtime`, which a bad `EMBARK_KEY` is reported at.
    pub path: LitStr,
    pub codec: Option<CodecArg>,
    pub cipher: Option<CipherArg>,
    pub runtime_key: Option<Span>,
}

impl CryptArgs {
    /// The codec to compress with before sealing. Defaults to `Deflate` when
    /// unspecified.
    ///
    /// The `auto` policies run the same selection pass here as anywhere
    /// else. Compression happens before sealing, so the pass reads the
    /// plaintext and the cipher never sees the difference.
    pub(crate) fn codec(&self) -> CodecArg {
        self.codec.unwrap_or(CodecArg::Fixed(CodecId::Deflate))
    }

    /// The AEAD cipher to seal with. Defaults to `ChaCha20Poly1305` when
    /// unspecified.
    pub(crate) fn crypto_id(&self) -> CryptoId {
        match self.cipher {
            None | Some(CipherArg::ChaCha) => CryptoId::ChaCha20Poly1305,
            Some(CipherArg::Aes) => CryptoId::Aes256Gcm,
        }
    }
}

impl Parse for CryptArgs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let path: LitStr = input.parse()?;
        let mut codec = None;
        let mut cipher = None;
        let mut runtime_key = None;

        while input.peek(Token![,]) {
            let _: Token![,] = input.parse()?;
            let key: syn::Ident = input.parse()?;
            let _: Token![=] = input.parse()?;
            if key == "codec" {
                let val: syn::Ident = input.parse()?;
                let name = val.to_string();
                codec = Some(parse_codec(&name).ok_or_else(|| {
                    syn::Error::new(val.span(), format!("unknown codec `{name}`"))
                })?);
            } else if key == "cipher" {
                let val: syn::Ident = input.parse()?;
                cipher = Some(match val.to_string().as_str() {
                    "chacha" => CipherArg::ChaCha,
                    "aes" => {
                        if !cfg!(feature = "aes") {
                            return Err(syn::Error::new(
                                val.span(),
                                "cipher = aes requires the `aes` feature enabled on `embark`",
                            ));
                        }
                        CipherArg::Aes
                    }
                    other => {
                        return Err(syn::Error::new(
                            val.span(),
                            format!("unknown cipher `{other}`"),
                        ));
                    }
                });
            } else if key == "key" {
                let val: syn::Ident = input.parse()?;
                if val != "runtime" {
                    return Err(syn::Error::new(val.span(), "expected `runtime`"));
                }
                runtime_key = Some(val.span());
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "expected `codec`, `cipher`, or `key`",
                ));
            }
        }

        Ok(CryptArgs {
            path,
            codec,
            cipher,
            runtime_key,
        })
    }
}
