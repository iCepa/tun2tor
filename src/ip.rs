use std::fmt;
use std::iter;
use std::slice;
use std::vec;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::iter::Iterator;
use mio::IpAddr;

use result::{Result, Error};
use packet::{PktBuf, MutPktBuf, Header, Pair, Checksum};

pub enum IpProto {
    Icmp,
    Igmp,
    Udp,
    UdpLite,
    Tcp,
    Unknown(u8),
}

impl IpProto {
    fn new(value: u8) -> Self {
        match value {
            1 => IpProto::Icmp,
            2 => IpProto::Igmp,
            17 => IpProto::Udp,
            136 => IpProto::UdpLite,
            6 => IpProto::Tcp,
            _ => IpProto::Unknown(value),
        }
    }
    pub fn value(&self) -> u8 {
        match *self {
            IpProto::Icmp => 1,
            IpProto::Igmp => 2,
            IpProto::Udp => 17,
            IpProto::UdpLite => 136,
            IpProto::Tcp => 6,
            IpProto::Unknown(value) => value,
        }
    }
}

impl fmt::Debug for IpProto {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IpProto::Icmp => write!(f, "ICMP"),
            IpProto::Igmp => write!(f, "IGMP"),
            IpProto::Udp => write!(f, "UDP"),
            IpProto::UdpLite => write!(f, "UDPLite"),
            IpProto::Tcp => write!(f, "TCP"),
            IpProto::Unknown(value) => write!(f, "Unknown ({})", value),
        }
    }
}

#[derive(Debug)]
pub struct Ipv4Header<T: PktBuf> {
    buf: T,
}

impl<T> Header<T> for Ipv4Header<T> where T: PktBuf {
    fn with_buf(buf: T) -> Ipv4Header<T> {
        Ipv4Header { buf: buf }
    }

    fn into_buf(self) -> T {
        self.buf
    }

    fn max_len() -> usize {
        60
    }

    fn len(&self) -> usize {
        let mut len = [0; 1];
        self.buf.read_slice(0, &mut len);
        ((len[0] & 0xF) * 4) as usize
    }
}

impl<T> Ipv4Header<T> where T: PktBuf {
    pub fn src(&self) -> Ipv4Addr {
        let mut src = [0; 4];
        self.buf.read_slice(12, &mut src);
        Ipv4Addr::new(src[0], src[1], src[2], src[3])
    }

    pub fn dest(&self) -> Ipv4Addr {
        let mut dest = [0; 4];
        self.buf.read_slice(16, &mut dest);
        Ipv4Addr::new(dest[0], dest[1], dest[2], dest[3])
    }

    pub fn total_len(&self) -> usize {
        let mut len = [0; 2];
        self.buf.read_slice(2, &mut len);
        ((len[0] as u16) << 8 | len[1] as u16) as usize
    }

    pub fn proto(&self) -> IpProto {
        let mut proto = [0; 1];
        self.buf.read_slice(9, &mut proto);
        IpProto::new(proto[0])
    }

    pub fn pseudo_iter<'a>
                           (&'a self,
                            len: usize)
                            -> iter::Chain<iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16>, vec::IntoIter<u16>> {
        let bytes = self.buf.cursor().into_inner();
        let pseudo = vec![self.proto().value() as u16, len as u16];
        (&bytes[12..20]).pair_iter().chain(pseudo.into_iter())
    }

    fn checksum(&self) -> u16 {
        let mut checksum = [0; 2];
        self.buf.read_slice(10, &mut checksum);
        ((checksum[0] as u16) << 8 | checksum[1] as u16)
    }

    pub fn checksum_valid(&self) -> bool {
        let bytes = self.buf.cursor().into_inner();
        let pre = &bytes[..10];
        let post = &bytes[12..self.len()];
        (self.checksum() == pre.pair_iter().chain(post.pair_iter()).checksum())
    }
}

impl<T> Ipv4Header<T> where T: MutPktBuf, T: PktBuf {
    pub fn initialize(&mut self) {
        self.buf.write_slice(0, &[(4 << 4 | 5)]); // IP Version and default length
        self.buf.write_slice(8, &[64]); // TTL
    }

    pub fn set_src(&mut self, addr: &Ipv4Addr) {
        self.buf.write_slice(12, &addr.octets()[..]);
    }

    pub fn set_dest(&mut self, addr: &Ipv4Addr) {
        self.buf.write_slice(16, &addr.octets()[..]);
    }

    pub fn set_total_len(&mut self, len: usize) {
        self.buf.write_slice(2, &[((len as u16) >> 8) as u8, len as u8]);
    }

    pub fn set_proto(&mut self, proto: &IpProto) {
        self.buf.write_slice(9, &[proto.value()]);
    }

    fn set_checksum(&mut self, checksum: u16) {
        self.buf.write_slice(10, &[(checksum >> 8) as u8, checksum as u8]);
    }

    pub fn calculate_checksum(&mut self) {
        let checksum = {
            let bytes = self.buf.cursor().into_inner();
            let pre = &bytes[..10];
            let post = &bytes[12..self.len()];
            pre.pair_iter().chain(post.pair_iter()).checksum()
        };
        self.set_checksum(checksum);
    }
}

#[derive(Debug)]
pub struct Ipv6Header<T: PktBuf> {
    buf: T,
}

impl<T> Header<T> for Ipv6Header<T> where T: PktBuf {
    fn with_buf(buf: T) -> Ipv6Header<T> {
        Ipv6Header { buf: buf }
    }

    fn into_buf(self) -> T {
        self.buf
    }

    fn max_len() -> usize {
        40
    }

    fn len(&self) -> usize {
        Ipv6Header::<T>::max_len()
    }
}

impl<T> Ipv6Header<T> where T: PktBuf {
    pub fn src(&self) -> Ipv6Addr {
        unimplemented!();
    }

    pub fn dest(&self) -> Ipv6Addr {
        unimplemented!();
    }

    pub fn total_len(&self) -> usize {
        unimplemented!();
    }

    pub fn proto(&self) -> IpProto {
        unimplemented!();
    }

    fn pseudo_iter<'a>
                       (&'a self,
                        len: usize)
                        -> iter::Chain<iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16>, vec::IntoIter<u16>> {
        let bytes = self.buf.cursor().into_inner();
        let pseudo = vec![self.proto().value() as u16, len as u16];
        (&bytes[8..40]).pair_iter().chain(pseudo.into_iter())
    }
}

impl<T> Ipv6Header<T> where T: MutPktBuf, T: PktBuf {
    pub fn initialize(&mut self) {
        unimplemented!();
    }

    pub fn set_src(&mut self, _addr: &Ipv6Addr) {
        unimplemented!();
    }

    pub fn set_dest(&mut self, _addr: &Ipv6Addr) {
        unimplemented!();
    }

    pub fn set_total_len(&mut self, _len: usize) {
        unimplemented!();
    }

    pub fn set_proto(&mut self, _proto: &IpProto) {
        unimplemented!();
    }
}

#[derive(Debug)]
pub enum IpHeader<T: PktBuf> {
    V4(Ipv4Header<T>),
    V6(Ipv6Header<T>),
}

impl<T> IpHeader<T> where T: PktBuf {
    pub fn with_buf(buf: T) -> Result<IpHeader<T>> {
        let mut version = [0; 1];
        buf.read_slice(0, &mut version);
        match version[0] >> 4 {
            4 => Ok(IpHeader::V4(Ipv4Header::with_buf(buf))),
            6 => Ok(IpHeader::V6(Ipv6Header::with_buf(buf))),
            v => Err(Error::IPVersionNotSupported(v)),
        }
    }

    pub fn version(&self) -> u8 {
        match *self {
            IpHeader::V4(ref _h) => 4,
            IpHeader::V6(ref _h) => 6,
        }
    }

    pub fn src(&self) -> IpAddr {
        match *self {
            IpHeader::V4(ref h) => IpAddr::V4(h.src()),
            IpHeader::V6(ref h) => IpAddr::V6(h.src()),
        }
    }

    pub fn dest(&self) -> IpAddr {
        match *self {
            IpHeader::V4(ref h) => IpAddr::V4(h.dest()),
            IpHeader::V6(ref h) => IpAddr::V6(h.dest()),
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            IpHeader::V4(ref h) => h.len(),
            IpHeader::V6(ref h) => h.len(),
        }
    }

    pub fn total_len(&self) -> usize {
        match *self {
            IpHeader::V4(ref h) => h.total_len(),
            IpHeader::V6(ref h) => h.total_len(),
        }
    }

    pub fn pseudo_iter<'a>
                           (&'a self,
                            len: usize)
                            -> iter::Chain<iter::Map<slice::Chunks<'a, u8>, fn(&[u8]) -> u16>, vec::IntoIter<u16>> {
        match *self {
            IpHeader::V4(ref h) => h.pseudo_iter(len),
            IpHeader::V6(ref h) => h.pseudo_iter(len),
        }
    }

    pub fn checksum_valid(&self) -> bool {
        match *self {
            IpHeader::V4(ref h) => h.checksum_valid(),
            IpHeader::V6(ref _h) => true,
        }
    }

    pub fn proto(&self) -> IpProto {
        match *self {
            IpHeader::V4(ref h) => h.proto(),
            IpHeader::V6(ref h) => h.proto(),
        }
    }
}

impl<T> IpHeader<T> where T: MutPktBuf, T: PktBuf {
    pub fn with_buf_hint(buf: T, addr: &IpAddr) -> IpHeader<T> {
        match *addr {
            IpAddr::V4(ref _a) => IpHeader::V4(Ipv4Header::with_buf(buf)),
            IpAddr::V6(ref _a) => IpHeader::V6(Ipv6Header::with_buf(buf)),
        }
    }

    pub fn initialize(&mut self) {
        match *self {
            IpHeader::V4(ref mut h) => h.initialize(),
            IpHeader::V6(ref mut h) => h.initialize(),
        }
    }

    pub fn set_src(&mut self, addr: &IpAddr) {
        match *self {
            IpHeader::V4(ref mut h) => {
                match addr {
                    &IpAddr::V4(ref a) => h.set_src(a),
                    &IpAddr::V6(ref _a) => panic!("Cannot set an IPv6 address on an IPv4 header"),
                }
            }
            IpHeader::V6(ref mut h) => {
                match addr {
                    &IpAddr::V4(ref _a) => panic!("Cannot set an IPv4 address on an IPv6 header"),
                    &IpAddr::V6(ref a) => h.set_src(a),
                }
            }
        }
    }

    pub fn set_dest(&mut self, addr: &IpAddr) {
        match *self {
            IpHeader::V4(ref mut h) => {
                match addr {
                    &IpAddr::V4(ref a) => h.set_dest(a),
                    &IpAddr::V6(ref _a) => panic!("Cannot set an IPv6 address on an IPv4 header"),
                }
            }
            IpHeader::V6(ref mut h) => {
                match addr {
                    &IpAddr::V4(ref _a) => panic!("Cannot set an IPv4 address on an IPv6 header"),
                    &IpAddr::V6(ref a) => h.set_dest(a),
                }
            }
        }
    }

    pub fn set_total_len(&mut self, len: usize) {
        match *self {
            IpHeader::V4(ref mut h) => h.set_total_len(len),
            IpHeader::V6(ref mut h) => h.set_total_len(len),
        }
    }

    pub fn calculate_checksum(&mut self) {
        match *self {
            IpHeader::V4(ref mut h) => h.calculate_checksum(),
            IpHeader::V6(ref mut _h) => (),
        }
    }

    pub fn set_proto(&mut self, proto: &IpProto) {
        match *self {
            IpHeader::V4(ref mut h) => h.set_proto(proto),
            IpHeader::V6(ref mut h) => h.set_proto(proto),
        }
    }
}
