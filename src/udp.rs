use std::io::Cursor;
use std::net::SocketAddr;
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

use ip::{IpHeader, FromBytes, Pair, Checksum};

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
            let pseudo_sum = match ip_hdr {
                &IpHeader::V4(ref ipv4_hdr) => {
                    ipv4_hdr.pseudo_sum(data.len() as u16 + 8)
                },
                &IpHeader::V6(ref ipv6_hdr) => {
                    0
                }
            };

            let udp_bytes = [(self.src >> 8) as u8, self.src as u8,
                             (self.dest >> 8) as u8, self.dest as u8,
                             (self.len >> 8) as u8, self.len as u8];

            let calculated = !(data.pair_iter()
                                   .chain(udp_bytes.pair_iter())
                                   .checksum() + pseudo_sum);

            println!("Calculated {:?}, Actual {:?}", calculated, self.chksum);
            
            (self.chksum == calculated)
        }
    }
}

#[derive(Debug)]
pub struct UdpPcb {
    local: SocketAddr,
    remote: SocketAddr,
}
