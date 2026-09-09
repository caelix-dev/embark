use embark::Embed;

#[derive(embark::Embed)]
#[embark(folder = "assets", codec = "deflate")]
#[embark(codec = "store")]
struct Assets;

fn main() {
    let _ = Assets::get("one.txt");
}
