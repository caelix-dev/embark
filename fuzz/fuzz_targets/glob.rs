//! The `include`/`exclude` glob matcher over arbitrary patterns and names.
//! It runs at build time on patterns a developer wrote, so the properties
//! are: no panic on any input, and no input that takes it exponentially
//! long -- a pattern of a dozen stars must not stall a build.
#![no_main]

// The matcher is private to `embark-macros`, which a proc-macro crate
// cannot export as a plain function, so the source is compiled in here.
#[path = "../../crates/embark-macros/src/glob.rs"]
#[allow(dead_code)]
mod glob;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, &str)| {
    let (pattern, name) = input;
    let _ = glob::matches(pattern, name);
});
