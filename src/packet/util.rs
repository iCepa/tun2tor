use std::iter;
use std::slice;

#[inline]
pub fn be_u16(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8 | (buf[1] as u16))
}

#[inline]
pub fn be_u32(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 24 | (buf[1] as u32) << 16 | (buf[2] as u32) << 8 | (buf[3] as u32))
}

#[inline]
pub fn set_be_u16(buf: &mut [u8], val: u16) {
    buf[0] = (val >> 8) as u8;
    buf[1] = val as u8;
}

#[inline]
pub fn set_be_u32(buf: &mut [u8], val: u32) {
    buf[0] = (val >> 24) as u8;
    buf[1] = (val >> 16) as u8;
    buf[2] = (val >> 8) as u8;
    buf[3] = val as u8;
}

pub trait Pair {
    fn pair_iter<'b>(&'b self) -> iter::Map<slice::Chunks<'b, u8>, fn(&[u8]) -> u16>;
}

impl Pair for [u8] {
    fn pair_iter<'b>(&'b self) -> iter::Map<slice::Chunks<'b, u8>, fn(&[u8]) -> u16> {
        fn combine(c: &[u8]) -> u16 {
            match c.len() {
                1 => (c[0] as u16) << 8,
                2 => ((c[0] as u16) << 8 | c[1] as u16),
                _ => unreachable!(),
            }
        }
        self.chunks(2).map(combine)
    }
}

pub trait Checksum {
    fn checksum(&mut self) -> u16;
}

impl<T> Checksum for T
    where T: Iterator<Item = u16>
{
    fn checksum(&mut self) -> u16 {
        !self.fold(0, |a, b| {
            let mut folded = (a as u32) + (b as u32);
            while folded > 0xFFFF {
                folded = (folded >> 16) + (folded & 0xFFFF);
            }
            (folded as u16)
        })
    }
}
