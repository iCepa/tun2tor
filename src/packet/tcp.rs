use std::net::IpAddr;

use packet::ip::IpHeader;
use packet::util::{be_u16, be_u32, set_be_u16, set_be_u32, Pair, Checksum};

#[derive(Debug)]
pub struct TcpHeader<'a> {
    buf: &'a [u8],
}

impl<'a> TcpHeader<'a> {
    pub fn with_buf(buf: &[u8]) -> TcpHeader {
        TcpHeader { buf: buf }
    }

    pub fn max_len() -> usize {
        60
    }

    pub fn len(&self) -> usize {
        ((self.buf[12] >> 4) * 4) as usize
    }

    pub fn src(&self) -> u16 {
        be_u16(&self.buf[..])
    }

    pub fn dest(&self) -> u16 {
        be_u16(&self.buf[2..])
    }

    pub fn seq_num(&self) -> u32 {
        be_u32(&self.buf[4..])
    }

    pub fn ack_num(&self) -> u32 {
        be_u32(&self.buf[8..])
    }

    fn options(&self) -> u8 {
        self.buf[13]
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
        be_u16(&self.buf[16..])
    }

    pub fn checksum_valid<V: Iterator<Item = u16>>(&self, header: &IpHeader<'a>, data: V) -> bool {
        (self.checksum() == self.calculate_checksum(header, data))
    }

    pub fn calculate_checksum<V: Iterator<Item = u16>>(&self,
                                                       header: &IpHeader<'a>,
                                                       data: V)
                                                       -> u16 {
        let pseudo = header.pseudo_iter(header.total_len() - header.len());
        self.buf[..16]
            .pair_iter()
            .chain(self.buf[18..self.len()].pair_iter())
            .chain(pseudo)
            .chain(data)
            .checksum()
    }
}

#[derive(Debug)]
pub struct TcpHeaderMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> TcpHeaderMut<'a> {
    pub fn with_buf(buf: &mut [u8]) -> TcpHeaderMut {
        TcpHeaderMut { buf: buf }
    }

    pub fn new(buf: &mut [u8]) -> TcpHeaderMut {
        buf[12] = 5 << 4;
        TcpHeaderMut::with_buf(buf)
    }

    pub fn set_src(&mut self, src: u16) {
        set_be_u16(&mut self.buf[..], src)
    }

    pub fn set_dest(&mut self, dest: u16) {
        set_be_u16(&mut self.buf[2..], dest)
    }

    pub fn set_seq_num(&mut self, seq_num: u32) {
        set_be_u32(&mut self.buf[4..], seq_num);
    }

    pub fn set_ack_num(&mut self, ack_num: u32) {
        set_be_u32(&mut self.buf[8..], ack_num);
    }

    fn set_option(&mut self, mask: u8, opt: bool) {
        self.buf[13] = if opt {
            self.buf[13] | mask
        } else {
            self.buf[13] & !mask
        };
    }

    pub fn set_syn(&mut self, syn: bool) {
        self.set_option(0x2, syn)
    }

    pub fn set_ack(&mut self, ack: bool) {
        self.set_option(0x10, ack)
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        set_be_u16(&mut self.buf[16..], checksum)
    }
}
