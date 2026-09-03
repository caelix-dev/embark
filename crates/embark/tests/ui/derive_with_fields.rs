#![allow(dead_code)]

use embark::Embed;

#[derive(embark::Embed)]
#[embark(folder = "assets")]
struct Assets {
    name: String,
}

fn main() {
    let _ = Assets::get("one.txt");
}
