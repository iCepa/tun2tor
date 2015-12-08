use std::iter;
use std::slice;
use std::io::{Cursor, Read, Write};

pub trait PktBuf {
    fn cursor<'a>(&'a self) -> Cursor<&'a [u8]>;
    fn read_slice(&self, pos: usize, dst: &mut [u8]) -> usize {
        let mut cursor = self.cursor();
        cursor.set_position(pos as u64);
        match cursor.read(dst) {
            Ok(bytes) => bytes,
            _ => 0,
        }
    }
}

pub trait MutPktBuf {
    fn cursor_mut<'a>(&'a mut self) -> Cursor<&'a mut [u8]>;
    fn write_slice(&mut self, pos: usize, src: &[u8]) -> usize {
        let mut cursor = self.cursor_mut();
        cursor.set_position(pos as u64);
        match cursor.write(src) {
            Ok(bytes) => bytes,
            _ => 0,
        }
    }
}

impl<'a> PktBuf for &'a [u8] {
    fn cursor(&self) -> Cursor<&[u8]> {
        Cursor::new(self)
    }
}

impl<'a> PktBuf for &'a mut [u8] {
    fn cursor(&self) -> Cursor<&[u8]> {
        Cursor::new(self)
    }
}

impl<'a> MutPktBuf for &'a mut [u8] {
    fn cursor_mut(&mut self) -> Cursor<&mut [u8]> {
        Cursor::new(self)
    }
}

impl PktBuf for Vec<u8> {
    fn cursor(&self) -> Cursor<&[u8]> {
        Cursor::new(&self[..])
    }
}

impl MutPktBuf for Vec<u8> {
    fn cursor_mut(&mut self) -> Cursor<&mut [u8]> {
        Cursor::new(&mut self[..])
    }
}

pub trait Header<T> where T: PktBuf {
    fn with_buf(buf: T) -> Self;
    fn into_buf(self) -> T;

    // TODO: Convert to associated constant when stable
    fn max_len() -> usize;

    fn len(&self) -> usize;
}

pub trait Pair<'a> {
    fn pair_iter(&self) -> iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16>;
}

impl<'a> Pair<'a> for &'a [u8] {
    fn pair_iter(&self) -> iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16> {
        fn combine(c: &[u8]) -> u16 {
            match c.len() {
                1 => (c[0] as u16) << 8,
                2 => ((c[0] as u16) << 8 | c[1] as u16),
                _ => 0,
            }
        }
        self.chunks(2).map(combine)
    }
}

pub trait Checksum {
    fn checksum(&mut self) -> u16;
}

impl<T> Checksum for T where T: Iterator<Item=u16> {
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
