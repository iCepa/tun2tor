use packet::{PktBuf, MutPktBuf, Header, Pair, Checksum};
use ip::IpHeader;

#[derive(Debug)]
pub struct UdpHeader<T: PktBuf> {
    buf: T,
}

impl<T> Header<T> for UdpHeader<T> where T: PktBuf {
    fn with_buf(buf: T) -> UdpHeader<T> {
        UdpHeader { buf: buf }
    }

    fn into_buf(self) -> T {
        self.buf
    }

    fn max_len() -> usize {
        8
    }

    fn len(&self) -> usize {
        UdpHeader::<T>::max_len()
    }
}

impl<T> UdpHeader<T> where T: PktBuf {
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

    pub fn udp_len(&self) -> usize {
        let mut len = [0; 2];
        self.buf.read_slice(4, &mut len);
        ((len[0] as u16) << 8 | len[1] as u16) as usize
    }

    pub fn data_len(&self) -> usize {
        self.udp_len() - self.len()
    }

    fn checksum(&self) -> u16 {
        let mut checksum = [0; 2];
        self.buf.read_slice(6, &mut checksum);
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
        let pseudo = header.pseudo_iter(self.udp_len());
        bytes[..6]
            .pair_iter()
            .chain(pseudo)
            .chain(data)
            .checksum()
    }
}

impl<T> UdpHeader<T> where T: MutPktBuf, T: PktBuf {
    pub fn set_src(&mut self, src: u16) {
        self.buf.write_u16(0, src);
    }

    pub fn set_dest(&mut self, dest: u16) {
        self.buf.write_u16(2, dest);
    }

    pub fn set_udp_len(&mut self, len: usize) {
        self.buf.write_u16(4, len as u16);
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        self.buf.write_u16(6, checksum);
    }
}
