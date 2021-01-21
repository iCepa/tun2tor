#![allow(dead_code)]

use std::io;
use std::rc::Rc;
use std::cell::{RefCell, Ref, RefMut};

use byteorder::{ReadBytesExt, WriteBytesExt, ByteOrder};
use tokio_io::io::Window;

#[derive(Clone, Debug)]
pub struct Bytes {
    bytes: Rc<RefCell<Box<[u8]>>>,
    off: usize,
    len: usize,
    cap: usize,
}

impl Bytes {
    pub fn try_unwrap(this: Bytes) -> Result<Window<Box<[u8]>>, Bytes> {
        let (off, len, cap) = (this.off, this.len, this.cap);
        Rc::try_unwrap(this.bytes)
            .map(|c| {
                let mut window = Window::new(c.into_inner());
                window.set_start(off);
                window.set_end(off + len);
                window
            })
            .map_err(|b| {
                Bytes {
                    bytes: b,
                    off: off,
                    len: len,
                    cap: cap,
                }
            })
    }

    pub fn new(bytes: Box<[u8]>) -> Bytes {
        let len = bytes.len();
        Bytes {
            bytes: Rc::new(RefCell::new(bytes)),
            off: 0,
            len: len,
            cap: len,
        }
    }

    fn set_start(&mut self, at: usize) {
        let end = self.off + self.len;
        assert!(at <= end);
        self.off = at;
        self.len = end - at;
    }

    fn set_end(&mut self, at: usize) {
        assert!(at >= self.off && at <= self.cap);
        self.len = at - self.off;
    }

    pub fn slice(&self, start: usize, end: usize) -> Bytes {
        let mut ret = self.clone();
        ret.set_end(self.off + end);
        ret.set_start(self.off + start);
        ret
    }

    pub fn split_off(&mut self, at: usize) -> Bytes {
        let at = self.off + at;
        let mut other = self.clone();
        other.set_start(at);
        self.set_end(at);
        other
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> Ref<[u8]> {
        Ref::map(self.bytes.borrow(), |s| &s[self.off..self.off + self.len])
    }

    pub fn as_mut(&mut self) -> RefMut<[u8]> {
        RefMut::map(self.bytes.borrow_mut(), |s| {
            &mut s[self.off..self.off + self.len]
        })
    }

    pub fn read_u8(&self, pos: usize) -> io::Result<u8> {
        (&self.as_slice()[pos..]).read_u8()
    }

    pub fn read_u16<B: ByteOrder>(&self, pos: usize) -> io::Result<u16> {
        (&self.as_slice()[pos..]).read_u16::<B>()
    }

    pub fn read_u32<B: ByteOrder>(&self, pos: usize) -> io::Result<u32> {
        (&self.as_slice()[pos..]).read_u32::<B>()
    }

    pub fn write_u8(&mut self, pos: usize, value: u8) -> io::Result<()> {
        (&mut self.as_mut()[pos..]).write_u8(value)
    }

    pub fn write_u16<B: ByteOrder>(&mut self, pos: usize, value: u16) -> io::Result<()> {
        (&mut self.as_mut()[pos..]).write_u16::<B>(value)
    }

    pub fn write_u32<B: ByteOrder>(&mut self, pos: usize, value: u32) -> io::Result<()> {
        (&mut self.as_mut()[pos..]).write_u32::<B>(value)
    }

    pub fn pair_iter(&self) -> PairIter {
        PairIter {
            bytes: self.clone(),
            index: 0,
        }
    }
}

pub struct PairIter {
    bytes: Bytes,
    index: usize,
}

impl Iterator for PairIter {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        let index = self.index;
        if index >= self.bytes.len() {
            return None;
        }

        self.index += 2;
        let slice = &self.bytes.as_slice()[index..];
        Some(match slice.len() {
            0 => unreachable!(),
            1 => (slice[0] as u16) << 8,
            _ => ((slice[0] as u16) << 8 | slice[1] as u16),
        })
    }
}

pub trait Checksum {
    fn checksum(&mut self) -> u16;
}

impl<T> Checksum for T
where
    T: Iterator<Item = u16>,
{
    fn checksum(&mut self) -> u16 {
        !self.fold(0, |a, b| {
            let mut folded = (a as u32) + (b as u32);
            while folded > 0xFFFF {
                folded = (folded >> 16) + (folded & 0xFFFF);
            }
            folded as u16
        })
    }
}

#[macro_export]
macro_rules! try_split {
    ($bytes:expr, $len:expr) => ({
        if $bytes.len() < $len {
            return Err(::std::io::Error::new(::std::io::ErrorKind::UnexpectedEof, "").into());
        }
        $bytes.split_off($len)
    })
}
