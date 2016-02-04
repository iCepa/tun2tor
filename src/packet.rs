use std::iter;
use std::slice;
use std::io::{Cursor, Read, Write};
use std::borrow::{Borrow, BorrowMut};

pub trait PktBuf: Borrow<[u8]> {
    fn read_slice(&self, pos: usize, dst: &mut [u8]) -> bool {
        let mut cursor = Cursor::new(self.borrow());
        cursor.set_position(pos as u64);
        match cursor.read_exact(dst) {
            Ok(()) => true,
            _ => false,
        }
    }

    fn read_u8(&self, pos: usize) -> u8 {
        let mut buf = [0; 1];
        self.read_slice(pos, &mut buf);
        buf[0]
    }

    fn read_u16(&self, pos: usize) -> u16 {
        let mut buf = [0; 2];
        self.read_slice(pos, &mut buf);
        ((buf[0] as u16) << 8 | buf[1] as u16)
    }

    fn read_u32(&self, pos: usize) -> u32 {
        let mut buf = [0; 4];
        self.read_slice(pos, &mut buf);
        ((buf[0] as u32) << 24 | (buf[1] as u32) << 16 | (buf[2] as u32) << 8 | buf[3] as u32)
    }
}

pub trait MutPktBuf: BorrowMut<[u8]> {
    fn write_slice(&mut self, pos: usize, src: &[u8]) -> bool {
        let mut cursor = Cursor::new(self.borrow_mut());
        cursor.set_position(pos as u64);
        match cursor.write_all(src) {
            Ok(_v) => true,
            Err(_e) => false,
        }
    }

    fn write_u8(&mut self, pos: usize, val: u8) -> bool {
        self.write_slice(pos, &[val])
    }

    fn write_u16(&mut self, pos: usize, val: u16) -> bool {
        self.write_slice(pos, &[(val >> 8) as u8, val as u8])
    }
}

impl<T> PktBuf for T where T: Borrow<[u8]> { }
impl<T> MutPktBuf for T where T: BorrowMut<[u8]> { }

pub trait Header<T> where T: PktBuf {
    fn with_buf(buf: T) -> Self;
    fn into_buf(self) -> T;

    // TODO: Convert to associated constant when stable
    fn max_len() -> usize;

    fn len(&self) -> usize;
}

pub trait Pair: Borrow<[u8]> {
    fn pair_iter<'b>(&'b self) -> iter::Map<slice::Chunks<'b, u8>, fn(&[u8]) -> u16> {
        fn combine(c: &[u8]) -> u16 {
            match c.len() {
                1 => (c[0] as u16) << 8,
                2 => ((c[0] as u16) << 8 | c[1] as u16),
                _ => 0,
            }
        }
        self.borrow().chunks(2).map(combine)
    }
}

impl<T: ?Sized> Pair for T where T: Borrow<[u8]> { }

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
