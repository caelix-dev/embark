use embark_format::{CodecId, CryptoId};
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token};

/// The `cipher = ...` argument: which AEAD cipher to seal with.
pub enum CipherArg {
    ChaCha,
    Aes,
}

/// Parses `embed_crypt!` arguments: a path literal, optionally followed by
/// `, codec = <ident>`, `, cipher = <ident>`, and/or `, key = runtime`, in
/// any order. Modeled on `args::Args`, with the addition of the `cipher`
/// and `key = runtime` options.
pub struct CryptArgs {
    pub path: String,
    pub codec: Option<crate::args::CodecArg>,
    pub cipher: Option<CipherArg>,
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
            Some(crate::args::CodecArg::Zstd) => CodecId::Zstd,
            Some(crate::args::CodecArg::Lzma) => CodecId::Lzma,
        }
    }

    /// The AEAD cipher to seal with. Defaults to `ChaCha20Poly1305` when
    /// unspecified.
    pub fn crypto_id(&self) -> CryptoId {
        match self.cipher {
            None | Some(CipherArg::ChaCha) => CryptoId::ChaCha20Poly1305,
            Some(CipherArg::Aes) => CryptoId::Aes256Gcm,
        }
    }
}

impl Parse for CryptArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let path: LitStr = input.parse()?;
        let mut codec = None;
        let mut cipher = None;
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
                    "zstd" => crate::args::CodecArg::Zstd,
                    "lzma" => crate::args::CodecArg::Lzma,
                    "auto" => crate::args::CodecArg::Auto,
                    other => {
                        return Err(syn::Error::new(
                            val.span(),
                            format!("unknown codec `{other}`"),
                        ));
                    }
                });
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
                runtime_key = true;
            } else {
                return Err(syn::Error::new(
                    key.span(),
                    "expected `codec`, `cipher`, or `key`",
                ));
            }
        }

        Ok(CryptArgs {
            path: path.value(),
            codec,
            cipher,
            runtime_key,
        })
    }
}
