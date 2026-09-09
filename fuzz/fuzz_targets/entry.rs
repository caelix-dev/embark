//! An arbitrary byte string presented as an on-binary entry: the header
//! parser, the AEAD opener and every decoder must reject or accept it
//! without panicking, and whatever a decoder accepts must be exactly as
//! long as the header claimed.
#![no_main]

use embark_format::{CryptoId, read_header};
use libfuzzer_sys::fuzz_target;
use std::borrow::Cow;

const KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    let Ok(header) = read_header(data) else {
        return;
    };
    let payload = &data[header.payload_offset..];

    let plain: Cow<'_, [u8]> = match header.crypto {
        CryptoId::None => Cow::Borrowed(payload),
        _ => {
            let (Some(nonce), Some(tag)) = (header.nonce, header.tag) else {
                panic!("a sealed entry parsed without its nonce or tag");
            };
            match embark_crypt::open(
                header.crypto,
                &KEY,
                &nonce,
                &data[..header.aad_len],
                payload,
                &tag,
            ) {
                Ok(plain) => Cow::Owned(plain),
                Err(_) => return,
            }
        }
    };

    let Ok(orig_len) = usize::try_from(header.orig_len) else {
        return;
    };
    if let Ok(out) = embark_codec::decompress(header.codec, &plain, orig_len) {
        assert_eq!(out.len(), orig_len, "{:?} accepted the wrong length", header.codec);
    }
});
