use embark::Embed;

#[derive(embark::Embed)]
struct Assets;

fn main() {
    let _ = Assets::get("one.txt");
}
