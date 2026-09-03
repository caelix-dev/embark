#![allow(dead_code)]

use core::marker::PhantomData;
use embark::Embed;

#[derive(embark::Embed)]
#[embark(folder = "assets")]
struct Assets<T>(PhantomData<T>);

fn main() {
    let _ = Assets::<u8>::get("one.txt");
}
