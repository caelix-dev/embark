#![allow(dead_code)]

use embark::Embed;

#[derive(embark::Embed)]
#[embark(folder = "assets")]
enum Assets {
    One,
}

fn main() {
    let _ = Assets::get("one.txt");
}
