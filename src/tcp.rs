#![allow(dead_code)]

use packet::{PktBuf, MutPktBuf, Header, Pair, Checksum};
use ip::IpHeader;

#[derive(Debug)]
pub struct TcpHeader<T: PktBuf> {
    buf: T,
}

impl<T> Header<T> for TcpHeader<T>
    where T: PktBuf
{
    fn with_buf(buf: T) -> TcpHeader<T> {
        TcpHeader { buf: buf }
    }

    fn into_buf(self) -> T {
        self.buf
    }

    fn max_len() -> usize {
        60
    }

    fn len(&self) -> usize {
        ((self.buf.read_u8(12) >> 4) * 4) as usize
    }
}

impl<T> TcpHeader<T>
    where T: PktBuf
{
    pub fn src(&self) -> u16 {
        self.buf.read_u16(0)
    }

    pub fn dest(&self) -> u16 {
        self.buf.read_u16(2)
    }

    pub fn seq_num(&self) -> u32 {
        self.buf.read_u32(4)
    }

    pub fn ack_num(&self) -> u32 {
        self.buf.read_u32(8)
    }

    fn options(&self) -> u8 {
        self.buf.read_u8(9)
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
        self.buf.read_u16(16)
    }

    pub fn checksum_valid<U: PktBuf, V: Iterator<Item = u16>>(&self,
                                                              header: &IpHeader<U>,
                                                              data: V)
                                                              -> bool {
        (self.checksum() == self.calculate_checksum(header, data))
    }

    pub fn calculate_checksum<U: PktBuf, V: Iterator<Item = u16>>(&self,
                                                                  header: &IpHeader<U>,
                                                                  data: V)
                                                                  -> u16 {
        let bytes = self.buf.borrow();
        let pseudo = header.pseudo_iter(header.total_len() - header.len());
        bytes[..16]
            .pair_iter()
            .chain(bytes[18..self.len()].pair_iter())
            .chain(pseudo)
            .chain(data)
            .checksum()
    }
}

impl<T> TcpHeader<T>
    where T: MutPktBuf,
          T: PktBuf
{
    pub fn set_src(&mut self, src: u16) {
        self.buf.write_u16(0, src);
    }

    pub fn set_dest(&mut self, dest: u16) {
        self.buf.write_u16(2, dest);
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.buf.write_u16(16, checksum);
    }
}
