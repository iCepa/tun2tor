#![allow(dead_code)]

use std::fmt;
use std::io;

use byteorder::NetworkEndian;

use packet::bytes::{Bytes, Checksum};
use packet::ip::IpHeader;

pub struct TcpHeader(Bytes);

impl TcpHeader {
    pub fn with_bytes(bytes: Bytes) -> io::Result<(TcpHeader, Bytes)> {
        let mut header = TcpHeader(bytes);
        let len = header.len();
        let remaining = try_split!(header.0, len);
        Ok((header, remaining))
    }

    pub fn max_len() -> usize {
        60
    }

    pub fn len(&self) -> usize {
        ((self.0.read_u8(12).unwrap() >> 4) * 4) as usize
    }

    pub fn src(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(0).unwrap()
    }

    pub fn dest(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(2).unwrap()
    }

    pub fn seq_num(&self) -> u32 {
        self.0.read_u32::<NetworkEndian>(4).unwrap()
    }

    pub fn ack_num(&self) -> u32 {
        self.0.read_u32::<NetworkEndian>(8).unwrap()
    }

    fn options(&self) -> u8 {
        self.0.read_u8(13).unwrap()
    }

    pub fn is_syn(&self) -> bool {
        (self.options() & 0x2) == 0x2
    }

    pub fn is_ack(&self) -> bool {
        (self.options() & 0x10) == 0x10
    }

    pub fn is_fin(&self) -> bool {
        (self.options() & 0x1) == 0x1
    }

    fn checksum(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(16).unwrap()
    }

    pub fn checksum_valid<V: Iterator<Item = u16>>(&self, header: &IpHeader, data: V) -> bool {
        self.checksum() == self.calculated_checksum(header, data)
    }

    pub fn calculated_checksum<V: Iterator<Item = u16>>(&self, header: &IpHeader, data: V) -> u16 {
        let pseudo = header.pseudo_iter(header.total_len().unwrap() - header.len());
        self.0
            .slice(0, 16)
            .pair_iter()
            .chain(self.0.slice(18, self.len()).pair_iter())
            .chain(pseudo)
            .chain(data)
            .checksum()
    }
}

impl fmt::Debug for TcpHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TcpHeader")
            .field("src", &self.src())
            .field("dest", &self.dest())
            .field("len", &self.len())
            .field("seq_num", &self.seq_num())
            .field("ack_num", &self.ack_num())
            .field("options", &self.options())
            .finish()
    }
}
