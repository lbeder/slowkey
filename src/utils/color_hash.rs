use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt};
use crossterm::style::Color;

pub fn color_hash(data: &[u8; 32]) -> Color {
    let v = Cursor::new(data).read_u32::<BigEndian>().expect("Hash is too small") as usize;

    let b = (v & 0xFF) as u8;
    let g = ((v >> 8) & 0xFF) as u8;
    let r = ((v >> 16) & 0xFF) as u8;

    Color::Rgb { r, g, b }
}
