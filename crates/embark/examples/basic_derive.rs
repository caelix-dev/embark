//! `#[derive(Embed)]` embeds every file under a folder, picking the best
//! codec per file automatically (`codec = "auto"`).

use embark::Embed;

#[derive(Embed)]
#[embark(folder = "examples/assets/")]
#[embark(codec = "auto")]
struct Assets;

fn main() {
    for path in Assets::iter() {
        let file = Assets::get(&path).unwrap();
        println!("{} -> {} bytes", path, file.data().len());
    }
}
