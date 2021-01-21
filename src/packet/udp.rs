use std::fmt;
use std::io;

use byteorder::NetworkEndian;

use packet::bytes::{Bytes, Checksum};
use packet::ip::IpHeader;

pub struct UdpHeader(Bytes);

impl UdpHeader {
    pub fn with_bytes(bytes: Bytes) -> io::Result<(UdpHeader, Bytes)> {
        let mut header = UdpHeader(bytes);
        let mut payload = try_split!(header.0, UdpHeader::len());
        if let Some(data_len) = header.data_len() {
            try_split!(payload, data_len);
        }
        Ok((header, payload))
    }

    pub fn len() -> usize {
        8
    }

    pub fn src(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(0).unwrap()
    }

    pub fn dest(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(2).unwrap()
    }

    pub fn udp_len(&self) -> usize {
        self.0.read_u16::<NetworkEndian>(4).unwrap() as usize
    }

    pub fn data_len(&self) -> Option<usize> {
        let udp_len = self.udp_len();
        if udp_len > UdpHeader::len() {
            Some(udp_len - UdpHeader::len())
        } else {
            None
        }
    }

    fn checksum(&self) -> u16 {
        self.0.read_u16::<NetworkEndian>(6).unwrap()
    }

    pub fn checksum_valid<V: Iterator<Item = u16>>(&self, header: &IpHeader, data: V) -> bool {
        self.checksum() == self.calculated_checksum(header, data)
    }

    pub fn calculated_checksum<V: Iterator<Item = u16>>(&self, header: &IpHeader, data: V) -> u16 {
        let pseudo = header.pseudo_iter(self.udp_len());
        self.0
            .slice(0, 6)
            .pair_iter()
            .chain(pseudo)
            .chain(data)
            .checksum()
    }

    pub fn set_src(&mut self, src: u16) {
        self.0.write_u16::<NetworkEndian>(0, src).unwrap();
    }

    pub fn set_dest(&mut self, dest: u16) {
        self.0.write_u16::<NetworkEndian>(2, dest).unwrap();
    }

    pub fn set_udp_len(&mut self, len: usize) {
        self.0.write_u16::<NetworkEndian>(4, len as u16).unwrap();
    }

    pub fn set_data_len(&mut self, len: usize) {
        self.set_udp_len(len + UdpHeader::len());
    }

    fn set_checksum(&mut self, checksum: u16) {
        self.0.write_u16::<NetworkEndian>(6, checksum).unwrap();
    }

    pub fn calculate_checksum<V: Iterator<Item = u16>>(&mut self, header: &IpHeader, data: V) {
        let checksum = self.calculated_checksum(header, data);
        self.set_checksum(checksum);
    }
}

impl fmt::Debug for UdpHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("UdpHeader")
            .field("src", &self.src())
            .field("dest", &self.dest())
            .field("udp_len", &self.udp_len())
            .finish()
    }
}

#[derive(Default, Debug, Clone)]
pub struct UdpHeaderBuilder {
    src: Option<u16>,
    dest: Option<u16>,
}

impl UdpHeaderBuilder {
    pub fn len() -> usize {
        UdpHeader::len()
    }

    pub fn src(mut self, src: u16) -> UdpHeaderBuilder {
        self.src = Some(src);
        self
    }

    pub fn dest(mut self, dest: u16) -> UdpHeaderBuilder {
        self.dest = Some(dest);
        self
    }

    pub fn build(self, bytes: Bytes) -> (UdpHeader, Bytes) {
        let src = self.src.unwrap_or_else(|| unimplemented!());
        let dest = self.dest.unwrap_or_else(|| unimplemented!());

        let (mut header, remaining) = UdpHeader::with_bytes(bytes).unwrap();
        header.set_src(src);
        header.set_dest(dest);
        (header, remaining)
    }
}
