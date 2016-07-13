use packet::{PktBuf, MutPktBuf, Header, Pair, Checksum};
use ip::IpHeader;

#[derive(Debug)]
pub struct UdpHeader<T: AsRef<[u8]>> {
    buf: T,
}

impl<T> Header<T> for UdpHeader<T>
    where T: AsRef<[u8]>
{
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

impl<T> UdpHeader<T>
    where T: AsRef<[u8]>
{
    pub fn src(&self) -> u16 {
        self.buf.read_u16(0)
    }

    pub fn dest(&self) -> u16 {
        self.buf.read_u16(2)
    }

    pub fn udp_len(&self) -> usize {
        self.buf.read_u16(4) as usize
    }

    pub fn data_len(&self) -> usize {
        self.udp_len() - self.len()
    }

    fn checksum(&self) -> u16 {
        self.buf.read_u16(6)
    }

    pub fn checksum_valid<U: AsRef<[u8]>, V: Iterator<Item = u16>>(&self,
                                                                   header: &IpHeader<U>,
                                                                   data: V)
                                                                   -> bool {
        (self.checksum() == self.calculate_checksum(header, data))
    }

    pub fn calculate_checksum<U: AsRef<[u8]>, V: Iterator<Item = u16>>(&self,
                                                                       header: &IpHeader<U>,
                                                                       data: V)
                                                                       -> u16 {
        let bytes = self.buf.as_ref();
        let pseudo = header.pseudo_iter(self.udp_len());
        bytes[..6]
            .pair_iter()
            .chain(pseudo)
            .chain(data)
            .checksum()
    }
}


impl<T> UdpHeader<T>
    where T: AsRef<[u8]>,
          T: AsMut<[u8]>
{
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
