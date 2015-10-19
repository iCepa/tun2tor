use std::io::Cursor;
use std::net::SocketAddr;
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

use ip::{IpHeader, FromBytes, Pair};

pub use ip::Result;

pub struct UdpHeader {
    pub src: u16,
    pub dest: u16,
    pub len: usize,
    chksum: u16,
}

impl FromBytes for UdpHeader {
    fn from_bytes(packet: &[u8]) -> Result<UdpHeader> {
        let mut rdr = Cursor::new(packet);
        let src = try!(rdr.read_u16::<BigEndian>());
        let dest = try!(rdr.read_u16::<BigEndian>());
        let len = try!(rdr.read_u16::<BigEndian>()) as usize;
        let chksum = try!(rdr.read_u16::<BigEndian>());

        Ok(UdpHeader {
            src: src,
            dest: dest,
            len: len,
            chksum: chksum,
        })
    }
}

impl UdpHeader {
    pub fn checksum_valid(&self, data: &[u8], ip_hdr: &IpHeader) -> bool {
        if self.chksum == 0 {
            true
        } else {
            let udp_bytes = [(self.src >> 8) as u8, self.src as u8,
                 (self.dest >> 8) as u8, self.dest as u8,
                 (self.len >> 8) as u8, self.len as u8];
            let data_iter = data.pair_iter().chain(udp_bytes.pair_iter());

            (self.chksum == match ip_hdr {
                &IpHeader::V4(ref ipv4_hdr) => {
                    ipv4_hdr.pseudo_checksum(data.len() as u16 + 8, data_iter)
                },
                &IpHeader::V6(ref ipv6_hdr) => {
                    0
                }
            })
        }
    }
}

#[derive(Debug)]
pub struct UdpPcb {
    local: SocketAddr,
    remote: SocketAddr,
}
