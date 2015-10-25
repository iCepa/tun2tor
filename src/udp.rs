use std::io::Cursor;
use std::net::SocketAddr;
use byteorder::{BigEndian, ReadBytesExt};

use ip::{IpHeader, FromBytes, Pair};

pub use ip::Result;

#[derive(Debug)]
pub struct UdpHeader {
    pub src: u16,
    pub dest: u16,
    pub plen: usize,
    chksum: u16,
}

impl FromBytes for UdpHeader {
    fn from_bytes(packet: &[u8]) -> Result<UdpHeader> {
        let mut rdr = Cursor::new(packet);
        let src = try!(rdr.read_u16::<BigEndian>());
        let dest = try!(rdr.read_u16::<BigEndian>());
        let plen = try!(rdr.read_u16::<BigEndian>()) as usize;
        let chksum = try!(rdr.read_u16::<BigEndian>());

        Ok(UdpHeader {
            src: src,
            dest: dest,
            plen: plen,
            chksum: chksum,
        })
    }
}

impl UdpHeader {
    pub fn len(&self) -> usize {
        8
    }

    pub fn checksum_valid(&self, data: &[u8], ip_hdr: &IpHeader) -> bool {
        if self.chksum == 0 {
            true
        } else {
            let udp_bytes = [(self.src >> 8) as u8,
                             self.src as u8,
                             (self.dest >> 8) as u8,
                             self.dest as u8,
                             (self.plen >> 8) as u8,
                             self.plen as u8];
            let data_iter = data.pair_iter().chain(udp_bytes.pair_iter());
            let calculated = ip_hdr.pseudo_checksum(self.plen as u16, data_iter);

            (self.chksum == calculated)
        }
    }
}

#[derive(Debug)]
pub struct UdpPcb {
    local: SocketAddr,
    remote: SocketAddr,
}
