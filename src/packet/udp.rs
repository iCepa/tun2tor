use packet::ip::IpHeader;
use packet::util::{be_u16, set_be_u16, Pair, Checksum};

#[derive(Debug)]
pub struct UdpHeader<'a> {
    buf: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    pub fn with_buf(buf: &'a [u8]) -> UdpHeader<'a> {
        UdpHeader { buf: buf }
    }

    pub fn len() -> usize {
        8
    }

    pub fn src(&self) -> u16 {
        be_u16(&self.buf[..])
    }

    pub fn dest(&self) -> u16 {
        be_u16(&self.buf[2..])
    }

    pub fn udp_len(&self) -> usize {
        be_u16(&self.buf[4..]) as usize
    }

    pub fn data_len(&self) -> usize {
        self.udp_len() - UdpHeader::len()
    }

    fn checksum(&self) -> u16 {
        be_u16(&self.buf[6..])
    }

    pub fn checksum_valid<V: Iterator<Item = u16>>(&self, header: &IpHeader<'a>, data: V) -> bool {
        (self.checksum() == self.calculate_checksum(header, data))
    }

    pub fn calculate_checksum<V: Iterator<Item = u16>>(&self,
                                                       header: &IpHeader<'a>,
                                                       data: V)
                                                       -> u16 {
        let pseudo = header.pseudo_iter(self.udp_len());
        self.buf[..6]
            .pair_iter()
            .chain(pseudo)
            .chain(data)
            .checksum()
    }
}

#[derive(Debug)]
pub struct UdpHeaderMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> UdpHeaderMut<'a> {
    pub fn with_buf(buf: &mut [u8]) -> UdpHeaderMut {
        UdpHeaderMut { buf: buf }
    }

    pub fn set_src(&mut self, src: u16) {
        set_be_u16(&mut self.buf[..], src)
    }

    pub fn set_dest(&mut self, dest: u16) {
        set_be_u16(&mut self.buf[2..], dest)
    }

    pub fn set_udp_len(&mut self, len: usize) {
        set_be_u16(&mut self.buf[4..], len as u16)
    }

    pub fn set_checksum(&mut self, checksum: u16) {
        set_be_u16(&mut self.buf[16..], checksum)
    }
}
