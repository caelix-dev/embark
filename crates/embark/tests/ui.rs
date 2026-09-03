//! Compile-fail tests over the macro diagnostics: every case here asserts
//! the exact text, span and caret placement of an error, which is the part
//! of `embark-macros` no other test can reach.
//!
//! Each case is expected to fail with nothing but `compile_error!` output
//! from the macros themselves. That is deliberate: proc-macro diagnostics
//! render the same way across compiler versions, whereas rustc's own type
//! and resolution errors do not, and a `.stderr` snapshot of those would
//! break on a toolchain upgrade rather than on a real regression. The
//! derive cases call `get()` for exactly this reason -- their `.stderr`
//! records that the stub `Embed` impl kept rustc from adding a cascading
//! error of its own.
#![cfg(feature = "derive")]

#[test]
fn ui() {
    let t = trybuild::TestCases::new();

    t.compile_fail("tests/ui/bang_unknown_codec.rs");
    t.compile_fail("tests/ui/bang_unknown_key.rs");
    t.compile_fail("tests/ui/bang_missing_file.rs");

    t.compile_fail("tests/ui/crypt_unknown_cipher.rs");
    t.compile_fail("tests/ui/crypt_bad_key_mode.rs");
    // Only an error while the feature is off; with `aes` enabled the same
    // call is accepted and fails later, on the missing asset.
    #[cfg(not(feature = "aes"))]
    t.compile_fail("tests/ui/crypt_aes_without_feature.rs");

    t.compile_fail("tests/ui/derive_missing_folder.rs");
    t.compile_fail("tests/ui/derive_unknown_codec.rs");
    t.compile_fail("tests/ui/derive_unknown_key.rs");
    t.compile_fail("tests/ui/derive_on_enum.rs");
    t.compile_fail("tests/ui/derive_with_fields.rs");
    t.compile_fail("tests/ui/derive_generic_struct.rs");
}
