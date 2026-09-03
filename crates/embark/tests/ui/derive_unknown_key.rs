use embark::Embed;

#[derive(embark::Embed)]
#[embark(folder = "assets", compression = "deflate")]
struct Assets;

fn main() {
    let _ = Assets::get("one.txt");
}
