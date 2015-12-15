#![allow(dead_code)]

use packet::{PktBuf, MutPktBuf, Header, Pair, Checksum};
use ip::IpHeader;

#[derive(Debug)]
pub struct TcpHeader<T: PktBuf> {
    buf: T,
}

impl<T> Header<T> for TcpHeader<T> where T: PktBuf {
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
        let mut len = [0; 1];
        self.buf.read_slice(12, &mut len);
        ((len[0] >> 4) * 4) as usize
    }
}

impl<T> TcpHeader<T> where T: PktBuf {
    pub fn src(&self) -> u16 {
        let mut src = [0; 2];
        self.buf.read_slice(0, &mut src);
        ((src[0] as u16) << 8 | src[1] as u16)
    }

    pub fn dest(&self) -> u16 {
        let mut dest = [0; 2];
        self.buf.read_slice(2, &mut dest);
        ((dest[0] as u16) << 8 | dest[1] as u16)
    }

    fn checksum(&self) -> u16 {
        let mut checksum = [0; 2];
        self.buf.read_slice(16, &mut checksum);
        ((checksum[0] as u16) << 8 | checksum[1] as u16)
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

impl<T> TcpHeader<T> where T: MutPktBuf, T: PktBuf {
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
