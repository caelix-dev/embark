use embark::Embed;

#[derive(embark::Embed)]
#[embark(folder = "assets", codec = "bogus")]
struct Assets;

fn main() {
    let _ = Assets::get("one.txt");
}
