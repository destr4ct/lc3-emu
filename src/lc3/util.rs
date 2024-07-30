use std::fs::File;
use std::os::unix::fs::FileExt;
use crate::lc3::hardware::{Fault, LC3Result};

pub fn extend_sign(v: u16, bits_count: usize) -> u16 {
    if ((v >> (bits_count-1)) & 1) == 1 {
        v | (0xffff << bits_count) // fill with ones if number is negative
    } else {
        v
    }
}

pub fn get_file(path: &str) -> LC3Result<File> {
    if let Ok(fd) = File::open(path) {
        Ok(fd)
    } else {
        Fault::construct_default("failed to open binary")
    }
}

pub fn read_short_at(f: &mut File, offset: u64) -> LC3Result<u16> {
    let mut tmp = [0u8; 2];
    if let Err(_) = f.read_exact_at(&mut tmp, offset) {
        return Fault::construct_default("failed to read origin");
    }
    Ok(u16::from_be_bytes(tmp))
}

pub fn print_crash(f: &Fault) {
    println!("lc3 got fault: {}", f.reason);

    println!("Machine registers:");
    for (i, &reg_v) in f.regs_dump.iter().enumerate() {
        print!("R{:03}=0x{:04x} ", i, reg_v);
        if (i+1) % 3 == 0 && i > 0 {
            println!()
        }
    }
}

pub fn u16_to_char(c: u16) -> char {
    if let Some(ch) = char::from_u32(c as u32) {
        return ch
    } else {
        return '\u{FFFD}';
    }
}